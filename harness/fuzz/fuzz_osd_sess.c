/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the OSD session table (core/src/osd/wri_osd_sess*.c): hostile frames delivered to READY sessions through the upper-layer callbacks the
 * way wri_m2_conn calls them (plan(), the bytes copied into the sinks the table named but never beyond their caps, then message(); or plan() alone for an
 * aborted frame), mixed with everything the engine and the request layer do to a table: acquire, the connection reaching READY, being lost, time, in-flight
 * counts, resets, sends, the engine's gates and its refusals, callbacks of stale connections. The table runs against a fake link.
 *
 * Input layout:
 *
 *   byte 0   bits 0-1 sessions (2 / 3 / 4 / 6), bit 2 the link has a features hook, bit 3 osd_idle_ms = 3000, bits 4-5 backoff slots (1 / 2 / 4 / 8),
 *            bit 6 the engine has exactly as many connection slots as sessions (else two more), bit 7 a closed connection keeps its engine slot until
 *            the engine frees it (op 11)
 *   rest     a stream of operations, each an opcode byte (mod 12) followed by its arguments:
 *              0 acquire   osd (low 3 bits), address variant
 *              1 ready     session, feature word selector
 *              2 closed    session, status selector (the engine reports the connection's end)
 *              3 frame     session, type selector, version, compat, tid selector, sink policy, mode (complete / aborted), u16 front length and bytes,
 *                          u8 middle length (zero bytes), u16 data length and bytes
 *              4 time      u16 ms, then the table's periodic step
 *              5 inflight  session, signed delta
 *              6 reset     session, status selector
 *              7 send      session
 *              8 blocked   session, pool, pg seed, hash, name length and bytes
 *              9 stale     the callbacks (plan / message / ready / closed) with a connection that is not the session's
 *             10 link      knob selector: ticket, handshake slot, open refusal, transmit queue idle, send refusal
 *             11 engine    the engine frees the slots of closed connections
 *
 * Properties (a violated one traps): no crash or undefined behaviour (ASan / UBSan); the table never writes into a data sink and never writes the front
 * buffer beyond its cap (heap buffers of exactly their size); plan answers OK, BUSY (only a backoff frame while the queue is busy) or WR_E_OSD_PROTO;
 * a frame that decodes is delivered with a data length equal to the sum of the echoed payload lengths and an operation count equal to the one named
 * by the sink callback, and reply() is never called with more stored bytes than the destination holds; bad_reply is followed by the end of the session;
 * lost is called exactly once per connection, with the session no longer live; at most osd_sessions entries are live and at most one entry per OSD;
 * every live entry has its own valid connection slot, every other entry has none, no operations in flight and no backoffs; the backoff table is
 * consistent (counts, lengths, coarse entries' id lists); rx_tid is 0 after every completed frame; hiwater never exceeds osd_sessions; a callback of
 * a connection the session does not own changes nothing.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_osd_sess.h"
#include "wri_le.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAX_INPUT 70000u
#define MAX_OPS 300u
#define NSLOT 8u
#define BUF_SMALL 48u
#define BUF_BIG 2048u

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

typedef struct slot {
	int used, closing;
	wri_m2_conn conn;
} slot;

typedef struct fz {
	wri_ctx x;
	uint8_t *mem;
	wri_arena arena;
	wri_osd_sess_tab t;
	slot sl[NSLOT];
	unsigned n_slots, n_sess;
	int have_ticket, hs_free, tx_idle, closing_holds, hook;
	wr_status open_st, send_st;
	uint64_t feat;
	/* the request layer's side */
	uint8_t *sb_small, *sb_big;          /* destinations of exactly BUF_SMALL / BUF_BIG bytes */
	uint8_t sink_policy;                  /* 0 none, 1 small, 2 big */
	uint8_t sink_nops;
	uint8_t *sink_given;
	uint32_t sink_cap_given;
	int in_frame, frame_completed;
	int bad_pending;                      /* bad_reply was called: the session must end before the frame returns */
	uint32_t bad_s;
	uint32_t frame_data_len, frame_sum_expected;
	unsigned n_reply_cb, n_opened, n_lost;
} fz;

/* ---- the fake link ------------------------------------------------------------------------------------------------------- */

static wr_status l_open(void *ctx, const wri_eaddr *addr, const wri_m2_upper *up, void *up_ctx, uint16_t *out)
{
	fz *f = (fz *)ctx;
	unsigned i;

	(void)addr;
	if (f->open_st != WR_OK)
		return f->open_st;
	check(up == wri_osd_sess_upper() && up_ctx != NULL);
	for (i = 0; i < f->n_slots; i++) {
		if (!f->sl[i].used) {
			memset(&f->sl[i], 0, sizeof(f->sl[i]));
			f->sl[i].used = 1;
			f->n_opened++;
			f->sl[i].conn.slot = (uint16_t)i;
			f->sl[i].conn.state = WRI_M2_CONNECTING;
			*out = (uint16_t)i;
			return WR_OK;
		}
	}
	return WR_E_BUSY;
}

static void l_close(void *ctx, uint16_t s, wr_status why)
{
	fz *f = (fz *)ctx;

	(void)why;
	check(s < f->n_slots && f->sl[s].used && !f->sl[s].closing); /* closes only a connection it opened, once */
	f->sl[s].closing = 1;
	f->sl[s].conn.state = WRI_M2_CLOSING;
	if (!f->closing_holds)
		f->sl[s].used = 0;
}

static wr_status l_send(void *ctx, uint16_t s, const wri_m2_msg_out *m)
{
	fz *f = (fz *)ctx;

	check(m != NULL && s < f->n_slots && f->sl[s].used && !f->sl[s].closing);
	check(m->front_len == 0 || m->front != NULL);
	return f->send_st;
}

static int l_tx_idle(void *ctx, uint16_t s)
{
	fz *f = (fz *)ctx;

	check(s < f->n_slots && f->sl[s].used);
	return f->tx_idle;
}

static uint64_t l_features(void *ctx, uint16_t s)
{
	fz *f = (fz *)ctx;

	check(s < f->n_slots);
	return f->feat;
}

static int l_ticket(void *ctx) { return ((fz *)ctx)->have_ticket; }
static int l_hs(void *ctx) { return ((fz *)ctx)->hs_free; }

/* ---- the request layer's callbacks -------------------------------------------------------------------------------------------- */

static void u_sink(void *ctx, uint32_t s, uint64_t tid, uint8_t **dst, uint32_t *cap, uint32_t *n_ops)
{
	fz *f = (fz *)ctx;

	check(f->in_frame && s < f->n_sess && *dst == NULL && *cap == 0u && *n_ops == 0u);
	(void)tid;
	f->sink_given = NULL;
	f->sink_cap_given = 0;
	if (f->sink_policy == 1u) {
		*dst = f->sb_small;
		*cap = BUF_SMALL;
	} else if (f->sink_policy == 2u) {
		*dst = f->sb_big;
		*cap = BUF_BIG;
	}
	f->sink_given = *dst;
	f->sink_cap_given = *cap;
	*n_ops = f->sink_nops;
}

static void u_reply(void *ctx, uint32_t s, uint64_t tid, const wri_mosdopreply *rep, uint32_t stored)
{
	fz *f = (fz *)ctx;
	const wri_osd_sess *p = &f->t.s[s];
	uint32_t i;
	uint64_t sum = 0;

	(void)tid;
	check(f->in_frame && s < f->n_sess && p->state == WRI_OS_READY);
	check(stored <= f->sink_cap_given && (f->sink_given != NULL || stored == 0u));
	check(rep->n_ops <= WRI_OSD_OPS_MAX);
	check(rep->oid_len == 0u || (rep->oid >= p->front && rep->oid + rep->oid_len <= p->front + f->x.cfg.osd_front_cap));
	for (i = 0; i < rep->n_ops; i++)
		sum += rep->out_len[i];
	check(sum == rep->out_total && sum == f->frame_data_len); /* the data segment is exactly what the operations echo */
	if (f->sink_nops != 0u)
		check(rep->n_ops == f->sink_nops);
	check(stored == 0u || stored == f->frame_data_len);
	f->n_reply_cb++;
}

static void u_bad(void *ctx, uint32_t s, uint64_t tid, const wr_errinfo *why)
{
	fz *f = (fz *)ctx;

	(void)tid;
	check(f->in_frame && s < f->n_sess && why != NULL && why->status != WR_OK);
	check(f->t.s[s].state == WRI_OS_READY); /* the session ends after this call, not before */
	f->bad_pending = 1;
	f->bad_s = s;
}

static void u_ready(void *ctx, uint32_t s)
{
	fz *f = (fz *)ctx;

	check(s < f->n_sess && f->t.s[s].state == WRI_OS_READY && f->t.s[s].msg_version >= 8u && f->t.s[s].msg_version <= 9u);
	check((f->t.s[s].features & WRI_OSDFEAT_NEED) == WRI_OSDFEAT_NEED);
}

static void u_lost(void *ctx, uint32_t s, const wr_errinfo *why)
{
	fz *f = (fz *)ctx;
	const wri_osd_sess *p;

	check(s < f->n_sess && why != NULL);
	p = &f->t.s[s];
	check(p->state != WRI_OS_OPENING && p->state != WRI_OS_READY && p->conn_slot == WRI_OS_NOSLOT);
	check(p->n_inflight == 0u && p->n_backoff == 0u && p->rx_tid == 0u);
	if (f->bad_pending && f->bad_s == s)
		f->bad_pending = 0;
	f->n_lost++;
}

static void u_unblock(void *ctx, uint32_t s, int64_t pool, uint32_t pg)
{
	fz *f = (fz *)ctx;

	(void)pool, (void)pg;
	check(s < f->n_sess);
}

/* ---- invariants --------------------------------------------------------------------------------------------------------- */

static void check_tables(fz *f)
{
	uint32_t i, j, k, live = 0, alive_slots = 0;
	unsigned slots = f->x.cfg.backoff_slots;

	for (i = 0; i < f->n_sess; i++) {
		const wri_osd_sess *a = &f->t.s[i];
		unsigned used = 0;

		check(a->state <= WRI_OS_READY); /* CLOSING is never visible between calls */
		check(a->tab == &f->t && a->front != NULL && a->bo != NULL);
		if (a->state == WRI_OS_OPENING || a->state == WRI_OS_READY) {
			live++;
			check(a->conn_slot < f->n_slots && f->sl[a->conn_slot].used && !f->sl[a->conn_slot].closing);
			check(a->osd >= 0);
		} else {
			check(a->conn_slot == WRI_OS_NOSLOT && a->n_inflight == 0u && a->n_backoff == 0u && a->rx_tid == 0u);
		}
		if (a->state == WRI_OS_FREE)
			check(a->osd == -1);
		if (a->state == WRI_OS_COOLDOWN)
			check(a->osd >= 0);
		for (j = i + 1u; j < f->n_sess; j++) {
			const wri_osd_sess *b = &f->t.s[j];

			if (a->state != WRI_OS_FREE && b->state != WRI_OS_FREE)
				check(a->osd != b->osd);
			if (a->conn_slot != WRI_OS_NOSLOT && b->conn_slot != WRI_OS_NOSLOT)
				check(a->conn_slot != b->conn_slot);
		}
		/* the backoff table */
		for (k = 0; k < slots; k++) {
			const wri_backoff *e = &a->bo[k];

			if (!e->used)
				continue;
			used++;
			check(e->coarse <= 1u);
			if (e->coarse)
				check(e->begin_len <= WRI_OSD_OID_MAX / 8u);
			else
				check(e->begin_len <= WRI_OSD_OID_MAX && e->end_len <= WRI_OSD_OID_MAX);
		}
		check(used == a->n_backoff && used <= slots);
		if (a->state != WRI_OS_READY)
			check(a->n_backoff == 0u);
		if (a->bo_lost)
			check(a->state == WRI_OS_READY || a->state == WRI_OS_OPENING);
	}
	check(live <= f->n_sess && f->t.hiwater <= f->n_sess);
	for (i = 0; i < f->n_slots; i++)
		alive_slots += (f->sl[i].used && !f->sl[i].closing) ? 1u : 0u;
	check(alive_slots == live);
	check(f->n_opened == f->n_lost + live); /* every connection that was opened is reported lost exactly once, and only when the session is gone */
}

/* ---- the program ------------------------------------------------------------------------------------------------------- */

typedef struct rd {
	const uint8_t *p;
	size_t n, pos;
} rd;

static uint8_t rd8(rd *r)
{
	return r->pos < r->n ? r->p[r->pos++] : 0u;
}

static uint16_t rd16(rd *r)
{
	uint16_t lo = rd8(r);

	return (uint16_t)(lo | ((uint16_t)rd8(r) << 8));
}

static const uint8_t *rdbytes(rd *r, size_t len, size_t *got)
{
	size_t left = r->n - r->pos;
	const uint8_t *p = r->p + r->pos;

	*got = len < left ? len : left;
	r->pos += *got;
	return p;
}

static wr_addr addr_of(unsigned osd, unsigned variant)
{
	wr_addr a;

	memset(&a, 0, sizeof(a));
	a.family = WR_AF_IPV4;
	a.ip[0] = 10, a.ip[1] = 77, a.ip[2] = 0, a.ip[3] = (uint8_t)(30u + osd);
	a.port = (uint16_t)(6800u + osd + (variant & 3u));
	a.nonce = 9000u + osd;
	if (variant & 4u) {
		a.family = WR_AF_IPV6;
		a.ip[15] = (uint8_t)osd;
	}
	return a;
}

static uint64_t feat_of(unsigned sel)
{
	uint64_t all = 0x3f07fffffffdffffull;

	switch (sel & 7u) {
	case 0:
	case 1:
	case 2:
		return all;
	case 3:
		return all & ~(1ull << 49); /* v8 */
	case 4:
		return all & ~(1ull << 8);
	case 5:
		return all & ~(1ull << 57);
	case 6:
		return all & ~(1ull << 58);
	default:
		return 0;
	}
}

static wr_status status_of(unsigned sel)
{
	static const wr_status st[] = {WR_E_NET_CLOSED, WR_E_M2_HANDSHAKE_TIMEOUT, WR_E_M2_BAD_METHOD, WR_OK, WR_E_OSD_PROTO, WR_E_BUSY};

	return st[sel % (sizeof(st) / sizeof(st[0]))];
}

static void op_frame(fz *f, rd *r)
{
	uint32_t idx = rd8(r) % f->n_sess;
	uint8_t tsel = rd8(r) % 8u, ver = rd8(r), compat = rd8(r), tidsel = rd8(r), pol = rd8(r), mode = rd8(r);
	size_t flen_want = rd16(r), flen, mlen_want, dlen_want, dlen;
	const uint8_t *front, *data;
	wri_osd_sess *s = &f->t.s[idx];
	wri_m2_conn *c;
	wri_m2_hdr2 h;
	uint32_t seglen[3], stored[3];
	wri_m2_sink sink[3];
	wr_status st;
	static const uint16_t types[8] = {43, 43, 43, 61, 61, 41, 42, 7};

	front = rdbytes(r, flen_want, &flen);
	mlen_want = rd8(r);
	dlen_want = rd16(r);
	data = rdbytes(r, dlen_want, &dlen);
	if (s->conn_slot == WRI_OS_NOSLOT)
		return; /* a frame needs a connection */
	c = &f->sl[s->conn_slot].conn;
	memset(&h, 0, sizeof(h));
	h.seq = ++c->in_seq;
	h.tid = tidsel < 4u ? (uint64_t)tidsel : (uint64_t)tidsel << 16;
	h.type = types[tsel];
	h.version = ver & 0xfu;
	h.compat_version = compat & 0xfu;
	if (tsel == 0u || tsel == 3u) {
		h.version = 8, h.compat_version = 2; /* the versions the decoders take, so the front is read */
		if (tsel == 3u)
			h.version = 1, h.compat_version = 1;
	}
	seglen[0] = (uint32_t)flen_want <= 0x4000u ? (uint32_t)flen_want : 0x4000u; /* the announced length may exceed the bytes the input has */
	seglen[1] = (uint32_t)(mlen_want & 3u);
	seglen[2] = (uint32_t)dlen_want <= 0x4000u ? (uint32_t)dlen_want : 0x4000u;
	if (seglen[0] > flen)
		seglen[0] = (uint32_t)flen; /* the bytes of the input are all there are */
	if (seglen[2] > dlen)
		seglen[2] = (uint32_t)dlen;
	f->sink_policy = (uint8_t)(pol % 3u);
	f->sink_nops = (uint8_t)((pol >> 2) % 3u);
	f->frame_data_len = seglen[2];
	memset(sink, 0, sizeof(sink));
	f->in_frame = 1;
	f->frame_completed = 0;
	st = wri_osd_sess_upper()->plan(s, c, &h, seglen, sink);
	check(st == WR_OK || st == WR_E_BUSY || st == WR_E_OSD_PROTO);
	if (st == WR_E_BUSY) {
		check(h.type == 61u && !f->tx_idle); /* held only for a backoff frame while the queue has bytes */
		c->in_seq--;
		f->in_frame = 0;
		return;
	}
	if (st != WR_OK) { /* the connection fails: its closed callback comes with the status */
		wr_errinfo e;

		memset(&e, 0, sizeof(e));
		e.status = st;
		e.what = "refused";
		c->state = WRI_M2_FAILED;
		f->sl[s->conn_slot].used = 0;
		wri_osd_sess_upper()->closed(s, c, &e);
		f->in_frame = 0;
		return;
	}
	/* the parser's part: bytes into the sinks, never beyond their caps; an aborted frame stops here */
	stored[0] = stored[1] = stored[2] = 0;
	if (sink[0].dst != NULL) {
		stored[0] = seglen[0] < sink[0].cap ? seglen[0] : sink[0].cap;
		if (stored[0] != 0)
			memcpy(sink[0].dst, front, stored[0]);
	}
	check(sink[1].dst == NULL); /* the table never names a middle sink */
	if (sink[2].dst != NULL) {
		check(sink[2].dst == f->sink_given && seglen[2] <= sink[2].cap && sink[2].cap == f->sink_cap_given);
		stored[2] = seglen[2];
		if (stored[2] != 0)
			memcpy(sink[2].dst, data, stored[2]);
	}
	if (sink[0].dst != NULL)
		check(sink[0].dst == s->front && sink[0].cap == f->x.cfg.osd_front_cap && seglen[0] <= sink[0].cap);
	if (mode & 1u) { /* aborted by the sender: no message() call */
		f->in_frame = 0;
		return;
	}
	f->frame_completed = 1;
	wri_osd_sess_upper()->message(s, c, &h, stored);
	f->in_frame = 0;
	check(!f->bad_pending);
	if (s->state == WRI_OS_READY)
		check(s->rx_tid == 0u);
}

static void op_stale(fz *f, rd *r)
{
	uint32_t idx = rd8(r) % f->n_sess;
	wri_osd_sess *s = &f->t.s[idx];
	wri_m2_conn stale;
	wri_m2_hdr2 h;
	uint32_t seglen[3] = {20, 0, 0}, stored[3] = {0, 0, 0};
	wri_m2_sink sink[3];
	wr_errinfo e;
	uint8_t op = rd8(r);
	wri_osd_sess before = *s;

	memset(&stale, 0, sizeof(stale));
	stale.slot = (uint16_t)((s->conn_slot == 0u ? 1u : 0u) + (op >> 4)); /* never the session's own slot */
	if (s->conn_slot != WRI_OS_NOSLOT && stale.slot == s->conn_slot)
		stale.slot = (uint16_t)(stale.slot + 1u);
	memset(&h, 0, sizeof(h));
	h.type = 43;
	h.version = 8;
	h.compat_version = 2;
	memset(sink, 0, sizeof(sink));
	memset(&e, 0, sizeof(e));
	e.status = WR_E_NET_CLOSED;
	switch (op & 3u) {
	case 0:
		check(wri_osd_sess_upper()->plan(s, &stale, &h, seglen, sink) == WR_OK);
		check(sink[0].dst == NULL && sink[1].dst == NULL && sink[2].dst == NULL);
		break;
	case 1:
		wri_osd_sess_upper()->message(s, &stale, &h, stored);
		break;
	case 2:
		wri_osd_sess_upper()->ready(s, &stale);
		break;
	default:
		wri_osd_sess_upper()->closed(s, &stale, &e);
		break;
	}
	check(memcmp(&before, s, sizeof(before)) == 0); /* nothing of the session changed */
}

static int run(const uint8_t *data, size_t size)
{
	fz *f;
	rd r;
	uint8_t b0;
	unsigned nsel[4] = {2, 3, 4, 6}, bsel[4] = {1, 2, 4, 8}, ops = 0;
	size_t need = 0;
	wri_osd_link l;
	wri_osd_sess_up u;

	if (size < 2u || size > MAX_INPUT)
		return 0;
	f = (fz *)calloc(1, sizeof(*f));
	if (f == NULL)
		return 0;
	b0 = data[0];
	f->n_sess = nsel[b0 & 3u];
	f->hook = (b0 >> 2) & 1u;
	wr_config_profile_harness(&f->x.cfg);
	f->x.cfg.osd_sessions = (uint16_t)f->n_sess;
	f->x.cfg.osd_front_cap = 1024;
	f->x.cfg.backoff_slots = (uint16_t)bsel[(b0 >> 4) & 3u];
	f->x.cfg.osd_connect_timeout_ms = 2000;
	f->x.cfg.osd_idle_ms = (b0 & 8u) ? 3000u : 0u;
	f->x.now.mono_ms = 1000;
	f->n_slots = (b0 & 0x40u) ? f->n_sess : f->n_sess + 2u;
	f->closing_holds = (b0 >> 7) & 1u;
	f->have_ticket = f->hs_free = f->tx_idle = 1;
	f->feat = feat_of(0);
	f->sb_small = (uint8_t *)malloc(BUF_SMALL);
	f->sb_big = (uint8_t *)malloc(BUF_BIG);
	if (wri_osd_sess_mem(&f->x.cfg, &need) != WR_OK || f->sb_small == NULL || f->sb_big == NULL)
		goto out;
	f->mem = (uint8_t *)malloc(need + 64u);
	if (f->mem == NULL)
		goto out;
	memset(f->mem, 0xA5, need + 64u); /* the table is zeroed by the arena, whatever the memory held */
	wri_arena_init(&f->arena, (uint8_t *)(((uintptr_t)f->mem + 63u) & ~(uintptr_t)63u), need);
	memset(&l, 0, sizeof(l));
	l.ctx = f;
	l.open = l_open;
	l.close = l_close;
	l.send = l_send;
	l.tx_idle = l_tx_idle;
	l.features = f->hook ? l_features : NULL;
	l.have_ticket = l_ticket;
	l.handshake_free = l_hs;
	memset(&u, 0, sizeof(u));
	u.ctx = f;
	u.sink = u_sink;
	u.reply = u_reply;
	u.bad_reply = u_bad;
	u.ready = u_ready;
	u.lost = u_lost;
	u.unblock = u_unblock;
	check(wri_osd_sess_init(&f->t, &f->x, &f->arena, &l, &u) == WR_OK);
	r.p = data;
	r.n = size;
	r.pos = 1;
	while (r.pos < r.n && ops++ < MAX_OPS) {
		uint8_t op = (uint8_t)(rd8(&r) % 12u);

		switch (op) {
		case 0: {
			unsigned osd = rd8(&r) & 7u;
			wr_addr a = addr_of(osd, rd8(&r));
			uint32_t s = WRI_NIL;
			wr_status st = wri_osd_sess_acquire(&f->t, (int32_t)osd, &a, &s);

			check(st == WR_OK || st == WR_E_BUSY || st == f->open_st); /* the link may refuse with its own status */
			if (st == WR_OK)
				check(s < f->n_sess && (f->t.s[s].state == WRI_OS_OPENING || f->t.s[s].state == WRI_OS_READY) && f->t.s[s].osd == (int32_t)osd);
			break;
		}
		case 1: {
			uint32_t idx = rd8(&r) % f->n_sess;
			wri_osd_sess *s = &f->t.s[idx];

			f->feat = feat_of(rd8(&r));
			if (s->state == WRI_OS_OPENING) {
				f->sl[s->conn_slot].conn.features = f->hook ? 0u : f->feat;
				f->sl[s->conn_slot].conn.state = WRI_M2_READY;
				wri_osd_sess_upper()->ready(s, &f->sl[s->conn_slot].conn);
				check(s->state == WRI_OS_READY || s->state == WRI_OS_COOLDOWN);
				check(s->state == WRI_OS_COOLDOWN || (f->feat & WRI_OSDFEAT_NEED) == WRI_OSDFEAT_NEED);
			}
			break;
		}
		case 2: {
			uint32_t idx = rd8(&r) % f->n_sess;
			wri_osd_sess *s = &f->t.s[idx];
			wr_errinfo e;

			memset(&e, 0, sizeof(e));
			e.status = status_of(rd8(&r));
			if (s->conn_slot != WRI_OS_NOSLOT) {
				slot *sl = &f->sl[s->conn_slot];

				sl->conn.state = WRI_M2_FAILED;
				wri_osd_sess_upper()->closed(s, &sl->conn, &e);
				sl->used = 0;
			}
			break;
		}
		case 3:
			op_frame(f, &r);
			break;
		case 4:
			f->x.now.mono_ms += rd16(&r);
			(void)wri_osd_sess_step(&f->t);
			break;
		case 5: {
			uint32_t idx = rd8(&r) % f->n_sess;
			int d = (int)(int8_t)rd8(&r);

			wri_osd_sess_inflight(&f->t, idx, d);
			break;
		}
		case 6: {
			uint32_t idx = rd8(&r) % f->n_sess;
			wr_errinfo e;
			uint8_t sel = rd8(&r);

			memset(&e, 0, sizeof(e));
			e.status = status_of(sel);
			wri_osd_sess_reset(&f->t, idx, (sel & 0x80u) ? NULL : &e);
			break;
		}
		case 7: {
			uint32_t idx = rd8(&r) % f->n_sess;
			wri_m2_msg_out m;
			wr_status st;

			memset(&m, 0, sizeof(m));
			m.type = 42;
			st = wri_osd_sess_send(&f->t, idx, &m);
			check(f->t.s[idx].state == WRI_OS_READY ? (st == WR_OK || st == f->send_st) : st == WR_E_STATE);
			break;
		}
		case 8: {
			uint32_t idx = rd8(&r) % f->n_sess;
			int64_t pool = (int64_t)(rd8(&r) & 3u);
			uint32_t pg = rd8(&r), hash = (uint32_t)rd16(&r) * 65537u;
			size_t n, nl = rd8(&r);
			const uint8_t *name = rdbytes(&r, nl, &n);

			(void)wri_osd_sess_blocked(&f->t, idx, pool, pg, hash, name, (uint32_t)n);
			break;
		}
		case 9:
			op_stale(f, &r);
			break;
		case 10: {
			uint8_t sel = rd8(&r);

			switch (sel % 7u) {
			case 0: f->have_ticket = !f->have_ticket; break;
			case 1: f->hs_free = !f->hs_free; break;
			case 2: f->open_st = f->open_st == WR_OK ? WR_E_BUSY : WR_OK; break;
			case 3: f->tx_idle = !f->tx_idle; break;
			case 4: f->send_st = f->send_st == WR_OK ? WR_E_BUSY : WR_OK; break;
			case 5: f->open_st = f->open_st == WR_OK ? WR_E_INVAL : WR_OK; break;
			default: f->send_st = f->send_st == WR_OK ? WR_E_STATE : WR_OK; break;
			}
			break;
		}
		default: {
			unsigned i;

			for (i = 0; i < f->n_slots; i++)
				if (f->sl[i].used && f->sl[i].closing)
					f->sl[i].used = 0;
			break;
		}
		}
		check_tables(f);
	}
	/* the destinations were never written by the table: the harness wrote them only through the sinks it was handed (checked in op_frame) */
out:
	free(f->sb_small);
	free(f->sb_big);
	free(f->mem);
	free(f);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	return run(data, size);
}
