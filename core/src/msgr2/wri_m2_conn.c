/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_conn.c - one msgr2 client connection: lifecycle, the deadline, the step loop and failure
 * handling. The handshake frames are in wri_m2_conn_hs.c, the READY-state flow and the byte plumbing (rx window, tx peek and consume) in wri_m2_conn_msg.c;
 * see wri_m2_conn.h for the contract and docs/design/core-architecture.md 8.1 for the states.
 *
 * The step loop is a thin dispatcher over the events of the receive parser. Two rules keep it simple:
 *
 *   - one event is "held" until its handler resolved it: a handler returns WR_E_BUSY (no room to
 *     answer yet, or the upper layer has no sink yet) without having changed anything, the loop
 *     stops, and the same event is handed to the same handler again at the next step. The parser is
 *     not stepped while an event is held (a second step would run past the SEG0 sink choice);
 *   - every other error is final: the handler (or the loop) calls wri_m2c_fail(), which records the
 *     first cause, wipes what a handshake leaves behind, drops the unsent bytes and tells the upper
 *     layer once.
 */
#include "wri_m2_conn.h"
#include "wri_m2_sec.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/* ---- small helpers ------------------------------------------------------------------------ */

static int is_handshake_state(unsigned s) { return s >= WRI_M2_BANNER && s <= WRI_M2_IDENT; }
static int is_live_state(unsigned s) { return wri_m2c_state_live(s); }

/* Transcript taps. Local wrappers, so that no code takes the address of a function of another object
 * (in position independent code that goes through the GOT, which the libc-free link check rejects). */
static void log_rx(void *pa, const uint8_t *b, size_t n) { wri_m2_preauth_rx(pa, b, n); }
static void log_tx(void *pa, const uint8_t *b, size_t n) { wri_m2_preauth_tx(pa, b, n); }

static void report_closed(wri_m2_conn *c)
{
	if (c->close_reported)
		return;
	c->close_reported = 1;
	if (c->up != NULL && c->up->closed != NULL)
		c->up->closed(c->up_ctx, c, &c->err);
}

/* Drop everything a finished or failed connection must not keep: transcripts, the expected
 * signature, staged bytes (they may hold ticket data), unsent output. */
static void release(wri_m2_conn *c)
{
	wri_secure_zero(c->sig_want, sizeof(c->sig_want));
	wri_ring_reset_wipe(&c->ring);
	if (c->ctl_buf != NULL)
		wri_secure_zero(c->ctl_buf, c->ctl_cap);
	if (c->tx.buf != NULL)
		wri_secure_zero(c->tx.buf, c->tx.used);
	wri_m2_txq_reset(&c->tx); /* forgets an active secure stream: before the seam is taken away below */
	/* The secure life ends with every connection: key schedule, nonces, staging and bounce buffer erased, the slot zero, the seam cleared.
	 * While the handshake slot is still ours (c->pa), the auth layer is told to drop its copy of the secret as well. */
	wri_m2c_sec_end(c);
	if (c->pa != NULL) {
		wri_m2_preauth_wipe(c->pa);
		c->pa = NULL; /* the client sees NULL and returns the handshake slot to its pool */
	}
	c->held_ev = WRI_RXE_NONE;
	c->stalled = 0;
	c->deadline_ms = WR_DEADLINE_NONE;
}

/* Record the failure and drop everything (state FAILED); the report to the upper layer is the caller's to make (now, or at the next step). */
static int fail_record(const wri_ctx *x, wri_m2_conn *c, wr_status st, unsigned line, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	unsigned was;

	if (c == NULL || c->state == WRI_M2_FAILED || c->state == WRI_M2_CLOSING || c->state == WRI_M2_FREE)
		return 0;
	was = c->state;
	wri_errinfo_set(&c->err, st, WR_MOD_M2, line, what, a0, a1, a2);
	c->err.conn = c->id;
	c->state = WRI_M2_FAILED;
	release(c);
	if (x != NULL)
		WRI_LOG(x, WR_LOG_WARN, WR_MOD_M2, c->id, st, "msgr2 connection failed", was, a0, a1, a2);
	return 1;
}

void wri_m2c_fail(const wri_ctx *x, wri_m2_conn *c, wr_status st, unsigned line, const char *what, uint64_t a0,
		  uint64_t a1, uint64_t a2)
{
	if (fail_record(x, c, st, line, what, a0, a1, a2))
		report_closed(c);
}

void wri_m2c_fail_deferred(const wri_ctx *x, wri_m2_conn *c, wr_status st, unsigned line, const char *what, uint64_t a0,
			   uint64_t a1, uint64_t a2)
{
	(void)fail_record(x, c, st, line, what, a0, a1, a2); /* up->closed follows at the next step (wri_m2_conn_step reports a failure nobody reported) */
}

/* ---- transmit helpers (shared with the other two files) ----------------------------------- */

int wri_m2c_tx_room(const wri_m2_conn *c, uint32_t bytes)
{
	return c->tx.buf != NULL && c->tx.cap - c->tx.used >= bytes && c->tx.niov + 2u <= WRI_M2_TXQ_IOV;
}

wr_status wri_m2c_need_room(const wri_ctx *x, wri_m2_conn *c, uint32_t bytes)
{
	if (wri_m2c_tx_room(c, bytes))
		return WR_OK;
	if (c->tx.buf == NULL || bytes > c->tx.cap) { /* waiting cannot help: say so now, not after a timeout (or never) */
		WRI_M2C_FAIL(x, c, WR_E_TOOBIG, "transmit buffer too small for a protocol frame", c->tx.cap, bytes, 0);
		return WR_E_TOOBIG;
	}
	return WR_E_BUSY;
}

wr_status wri_m2c_send(const wri_ctx *x, wri_m2_conn *c, uint8_t tag, const uint8_t *p, uint32_t n)
{
	wri_m2_seg_src seg;
	wr_status st;
	int logging = c->pa != NULL;

	seg.p = p;
	seg.len = n;
	seg.ref = 0;
	st = wri_m2_tx_frame(&c->tx, x->host.prim, tag, &seg, 1, logging ? log_tx : NULL, c->pa);
	if (st == WR_OK) {
		c->last_tx_ms = x->now.mono_ms;
		if (logging && c->pa->err != WR_OK)
			return c->pa->err; /* the frame overflowed the sent transcript: no valid signature can follow */
	}
	return st;
}

/* ---- lifecycle ---------------------------------------------------------------------------- */

/* What bind() was given; open() re-applies it so a connection slot can be reused without the client binding again. */
typedef struct bound {
	uint8_t *ring_buf, *ctl_buf, *tx_buf;
	uint32_t ring_cap, ctl_cap, tx_cap, seg_cap_max, pa_slot;
	uint16_t gen, slot;
} bound;

static void bound_save(const wri_m2_conn *c, bound *b)
{
	b->ring_buf = c->ring.buf;
	b->ring_cap = c->ring.cap;
	b->ctl_buf = c->ctl_buf;
	b->ctl_cap = c->ctl_cap;
	b->tx_buf = c->tx.buf;
	b->tx_cap = c->tx.cap;
	b->seg_cap_max = c->seg_cap_max;
	b->pa_slot = c->pa_slot;
	b->gen = c->gen; /* the client owns the generation counter */
	b->slot = c->slot;
}

/* Zero the connection and set it up empty with the given buffers: state FREE. */
static void bound_apply(wri_m2_conn *c, const bound *b)
{
	WR_MEMSET(c, 0, sizeof(*c));
	c->gen = b->gen;
	c->slot = b->slot;
	c->pa_slot = b->pa_slot;
	c->deadline_ms = WR_DEADLINE_NONE;
	c->ctl_buf = b->ctl_buf;
	c->ctl_cap = b->ctl_buf != NULL ? b->ctl_cap : 0;
	c->seg_cap_max = b->seg_cap_max;
	wri_ring_init(&c->ring, b->ring_buf, b->ring_cap);
	wri_m2_rx_init(&c->rx, b->ctl_buf, c->ctl_cap, b->seg_cap_max);
	wri_m2_txq_init(&c->tx, b->tx_buf, b->tx_cap);
	c->state = WRI_M2_FREE;
}

void wri_m2_conn_bind(wri_m2_conn *c, uint16_t slot, uint8_t *ring_buf, uint32_t ring_cap, uint8_t *ctl_buf,
		      uint32_t ctl_cap, uint8_t *tx_buf, uint32_t tx_cap, uint32_t seg_cap_max)
{
	bound b;

	if (c == NULL)
		return;
	b.ring_buf = ring_buf, b.ring_cap = ring_cap;
	b.ctl_buf = ctl_buf, b.ctl_cap = ctl_cap;
	b.tx_buf = tx_buf, b.tx_cap = tx_cap;
	b.seg_cap_max = seg_cap_max;
	b.pa_slot = WRI_NIL;
	b.gen = c->gen;
	b.slot = slot;
	bound_apply(c, &b);
}

static int auth_ops_ok(const wri_auth_ops *a)
{
	return a != NULL && a->begin != NULL && a->more != NULL && a->done != NULL && a->session_key != NULL &&
	       a->ident_gid != NULL;
}

static int upper_ok(const wri_m2_upper *u)
{
	return u != NULL && u->plan != NULL && u->message != NULL && u->ready != NULL && u->closed != NULL;
}

void wri_m2_conn_open(wri_m2_conn *c, wr_conn_id id, uint8_t role, const wri_eaddr *target, const wr_addr *dial,
		      const wri_auth_ops *auth, void *auth_ctx, const wri_m2_upper *up, void *up_ctx, wri_m2_preauth *pa,
		      uint32_t my_nonce, uint64_t global_seq)
{
	bound b;
	int ok;

	if (c == NULL)
		return;
	bound_save(c, &b); /* keep what bind() gave us, reset everything else */
	if (c->sec != NULL) /* a slot reused without the previous life having ended through close / on_closed: no key survives into the new one */
		wri_m2_secure_off(&c->rx, &c->tx, c->sec);
	bound_apply(c, &b);
	c->id = id;
	c->role = role;
	c->up = up;
	c->up_ctx = up_ctx;
	c->auth = auth;
	c->auth_ctx = auth_ctx;
	c->my_nonce = my_nonce;
	c->global_seq = global_seq;
	c->peer_gid = -1;
	if (target != NULL)
		c->target = *target;
	if (dial != NULL)
		c->dial = *dial;
	ok = (role == WRI_ENTITY_MON || role == WRI_ENTITY_OSD) && target != NULL && auth_ops_ok(auth) && upper_ok(up);
	ok = ok && pa != NULL && pa->rx_buf != NULL && pa->tx_buf != NULL && pa->cap != 0;
	ok = ok && c->ctl_buf != NULL && c->tx.buf != NULL && c->ring.buf != NULL;
	if (!ok) {
		/* a programming error of the owner: reported by the first step, like any other failure */
		wri_errinfo_set(&c->err, WR_E_INVAL, WR_MOD_M2, (unsigned)__LINE__, "bad arguments to open", 0, 0, 0);
		c->err.conn = id;
		c->state = WRI_M2_FAILED;
		return;
	}
	wri_m2_preauth_init(pa, pa->rx_buf, pa->tx_buf, pa->cap); /* a reused slot starts empty */
	c->pa = pa;
	c->state = WRI_M2_CONNECTING;
}

void wri_m2_conn_on_connected(const wri_ctx *x, wri_m2_conn *c)
{
	wr_status st;

	if (x == NULL || c == NULL || c->state != WRI_M2_CONNECTING)
		return;
	c->state = WRI_M2_BANNER;
	c->last_rx_ms = c->last_tx_ms = x->now.mono_ms;
	c->deadline_ms = x->cfg.handshake_timeout_ms != 0 ? x->now.mono_ms + x->cfg.handshake_timeout_ms
							  : WR_DEADLINE_NONE;
	st = wri_m2_tx_banner(&c->tx, log_tx, c->pa);
	if (st != WR_OK)
		WRI_M2C_FAIL(x, c, st, "banner does not fit the transmit buffer", c->tx.cap, 0, 0);
}

void wri_m2_conn_on_closed(const wri_ctx *x, wri_m2_conn *c, int host_errno)
{
	wr_status st;

	if (c == NULL || c->state == WRI_M2_FREE)
		return;
	if (!c->close_reported) {
		st = c->state == WRI_M2_CONNECTING ? WR_E_NET_CONNECT : WR_E_NET_CLOSED;
		wri_errinfo_set(&c->err, st, WR_MOD_M2, (unsigned)__LINE__,
				c->state == WRI_M2_CONNECTING ? "connect failed" : "closed by the peer or the host",
				(uint64_t)(int64_t)host_errno, c->state, 0);
		c->err.conn = c->id;
		if (x != NULL)
			WRI_LOG(x, WR_LOG_INFO, WR_MOD_M2, c->id, st, "msgr2 connection closed by the transport", c->state,
				(int64_t)host_errno, 0, 0);
	}
	release(c);
	c->state = WRI_M2_FAILED; /* so that report_closed() below runs once; the slot is FREE after */
	report_closed(c);
	c->state = WRI_M2_FREE;
}

void wri_m2_conn_close(const wri_ctx *x, wri_m2_conn *c, wr_status why)
{
	if (c == NULL || c->state == WRI_M2_FREE || c->state == WRI_M2_FAILED || c->state == WRI_M2_CLOSING)
		return;
	if (why != WR_OK) {
		wri_errinfo_set(&c->err, why, WR_MOD_M2, (unsigned)__LINE__, "close requested", c->state, 0, 0);
		c->err.conn = c->id;
	}
	if (x != NULL)
		WRI_LOG(x, WR_LOG_DEBUG, WR_MOD_M2, c->id, why, "msgr2 close requested", c->state, 0, 0, 0);
	release(c);
	c->state = WRI_M2_CLOSING;
	report_closed(c);
}

void wri_m2_conn_wipe(wri_m2_conn *c)
{
	if (c == NULL)
		return;
	release(c); /* transcripts, expected signature, staged bytes, control buffer, unsent output, the secure slot and its bounce buffer */
	if (c->tx.buf != NULL)
		wri_secure_zero(c->tx.buf, c->tx.cap); /* the whole encode buffer, not only what is queued: earlier frames (a sealed signature, an authorizer) are gone too */
	c->state = WRI_M2_FREE;
	c->close_reported = 1; /* nobody is told: the engine is going away */
}

uint64_t wri_m2_conn_deadline(const wri_m2_conn *c)
{
	uint64_t d = WR_DEADLINE_NONE;

	if (c == NULL)
		return d;
	if (c->state == WRI_M2_FAILED && !c->close_reported)
		return 0; /* a failure that happened inside a send call: the next step reports it to the upper layer */
	if (is_handshake_state(c->state))
		d = c->deadline_ms;
	if (c->stalled && is_live_state(c->state) && c->retry_ms < d)
		d = c->retry_ms;
	return d;
}

/* ---- the step loop ------------------------------------------------------------------------ */

static int tag_allowed(unsigned state, unsigned tag)
{
	switch (state) {
	case WRI_M2_HELLO:
		return tag == WRI_M2_TAG_HELLO;
	case WRI_M2_AUTH:
		return tag == WRI_M2_TAG_AUTH_REPLY_MORE || tag == WRI_M2_TAG_AUTH_BAD_METHOD ||
		       tag == WRI_M2_TAG_AUTH_DONE;
	case WRI_M2_SIG:
		return tag == WRI_M2_TAG_AUTH_SIGNATURE;
	case WRI_M2_IDENT:
		return tag == WRI_M2_TAG_SERVER_IDENT || tag == WRI_M2_TAG_IDENT_MISSING_FEATURES ||
		       tag == WRI_M2_TAG_WAIT;
	case WRI_M2_READY:
		return tag == WRI_M2_TAG_MESSAGE || tag == WRI_M2_TAG_KEEPALIVE2 || tag == WRI_M2_TAG_KEEPALIVE2_ACK ||
		       tag == WRI_M2_TAG_ACK;
	default:
		return 0;
	}
}

/* SEG0: segment 0 is verified. Decide whether the frame is acceptable here at all. */
static wr_status on_seg0(const wri_ctx *x, wri_m2_conn *c)
{
	const wri_m2_desc *d = &c->rx.desc;

	if (!tag_allowed(c->state, d->tag)) {
		WRI_M2C_FAIL(x, c, WR_E_M2_STATE, "frame not allowed in this state", c->state, d->tag, 0);
		return WR_E_M2_STATE;
	}
	if (d->tag == WRI_M2_TAG_MESSAGE)
		return wri_m2c_msg_seg0(x, c);
	if (d->nseg != 1u) { /* every control frame is a single segment */
		WRI_M2C_FAIL(x, c, WR_E_M2_FRAME_FORM, "control frame with more than one segment", d->tag, d->nseg, 0);
		return WR_E_M2_FRAME_FORM;
	}
	return WR_OK;
}

static wr_status on_frame(const wri_ctx *x, wri_m2_conn *c)
{
	if (c->state == WRI_M2_READY)
		return wri_m2c_ready_frame(x, c);
	return wri_m2c_hs_frame(x, c);
}

static wr_status on_aborted(const wri_ctx *x, wri_m2_conn *c)
{
	/* only a multi-segment frame can be aborted, and in READY that is a MESSAGE: drop it */
	if (c->state != WRI_M2_READY || c->rx.desc.tag != WRI_M2_TAG_MESSAGE) {
		WRI_M2C_FAIL(x, c, WR_E_M2_ABORTED_FRAME, "aborted frame outside a message", c->state, c->rx.desc.tag, 0);
		return WR_E_M2_ABORTED_FRAME;
	}
	c->n_msg_dropped++;
	return WR_OK;
}

static int work_left(const wri_m2_conn *c, const uint32_t *budget)
{
	return budget != NULL && *budget == 0 && (c->ring.len != 0 || c->rx.direct != 0);
}

/* A transcript that overflowed makes a valid signature impossible: fail now. 1 if the connection failed. */
static int pa_overflowed(const wri_ctx *x, wri_m2_conn *c)
{
	wr_status st;

	if (c->pa == NULL || c->pa->err == WR_OK)
		return 0;
	st = c->pa->err;
	WRI_M2C_FAIL(x, c, st, "pre-auth transcript too large", c->pa->cap, c->pa->rx_len, c->pa->tx_len);
	return 1;
}

/* The parser died: its own detail (line, what, values) is the first cause. */
static void rx_died(const wri_ctx *x, wri_m2_conn *c)
{
	const wr_errinfo *re = wri_m2_rx_error(&c->rx);
	wr_status st = re->status != WR_OK ? re->status : WR_E_M2_FRAME_FORM;

	c->err = *re;
	WRI_M2C_FAIL(x, c, st, "receive parser error", 0, 0, 0);
}

/* Handle one event; WR_OK = resolved, WR_E_BUSY = held, anything else = failed already. */
static wr_status dispatch(const wri_ctx *x, wri_m2_conn *c, unsigned ev)
{
	wr_status st = WR_OK;

	switch (ev) {
	case WRI_RXE_BANNER:
		c->held_ev = (uint8_t)ev;
		return wri_m2c_hs_banner(x, c);
	case WRI_RXE_SEG0:
		c->held_ev = (uint8_t)ev;
		return on_seg0(x, c);
	case WRI_RXE_FRAME:
		c->held_ev = (uint8_t)ev;
		c->last_rx_ms = x->now.mono_ms;
		st = on_frame(x, c);
		break;
	case WRI_RXE_ABORTED:
		st = on_aborted(x, c);
		break;
	default: /* WRI_RXE_ERROR */
		rx_died(x, c);
		return WR_E_M2_FRAME_FORM;
	}
	if (st == WR_OK)
		wri_m2_rx_next_frame(&c->rx);
	return st;
}

int wri_m2_conn_step(const wri_ctx *x, wri_m2_conn *c, uint32_t *budget)
{
	if (x == NULL || c == NULL)
		return 0;
	if (c->state == WRI_M2_FAILED) { /* an open() that was refused, or a failure nobody reported yet */
		report_closed(c);
		return 0;
	}
	if (!is_live_state(c->state))
		return 0;
	c->stalled = 0;
	if (is_handshake_state(c->state) && c->deadline_ms != WR_DEADLINE_NONE && x->now.mono_ms >= c->deadline_ms) {
		WRI_M2C_FAIL(x, c, WR_E_M2_HANDSHAKE_TIMEOUT, "handshake did not finish in time", c->state,
			     x->cfg.handshake_timeout_ms, 0);
		return 0;
	}
	for (;;) {
		unsigned ev;
		wr_status st;

		if (c->held_ev != WRI_RXE_NONE) {
			ev = c->held_ev;
		} else {
			ev = (unsigned)wri_m2_rx_step(&c->rx, &c->ring, x->host.prim, budget,
						      c->pa != NULL ? log_rx : NULL, c->pa);
			if (pa_overflowed(x, c))
				return 0;
		}
		if (ev == WRI_RXE_NONE)
			return work_left(c, budget);
		st = dispatch(x, c, ev);
		/* Checked before BUSY: a handler can fail the connection with a status that happens to be BUSY (an
		 * authentication callback that answers it), and a dead connection must not be marked stalled. */
		if (!is_live_state(c->state))
			return 0; /* failed (already recorded), or the owner closed the connection from a callback */
		if (st == WR_E_BUSY) { /* backpressure: nothing changed, the held event comes back */
			c->stalled = 1;
			c->retry_ms = x->now.mono_ms + WRI_M2C_STALL_RETRY_MS;
			return 0;
		}
		if (st != WR_OK)
			return 0; /* cannot happen: every error path fails the connection first */
		c->held_ev = WRI_RXE_NONE;
	}
}
