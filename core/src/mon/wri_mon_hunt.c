/* SPDX-License-Identifier: MIT */
/*
 * wri_mon_hunt.c - the monitor session lifecycle: wri_mon_step(), hunting with exponential
 * back-off, session set-up after READY, keepalive (docs/spec/mon-client.md 3.2, 3.3, 3.6, 3.7,
 * architecture 8.3).
 *
 * Hunting: one session at a time. The ranks are tried in order (the literal addresses of the
 * cluster spec, replaced by the monmap's msgr2 addresses once one arrives). The first attempt of a
 * process starts at once; after every failed attempt the machine waits a time that doubles from
 * hunt_backoff_min_ms up to hunt_backoff_max_ms, reduced by a random jitter of up to a quarter (never
 * below the minimum). The base only goes back to the minimum once a session has been ACTIVE for
 * keepalive_ms ("stable"), so a monitor that accepts and drops us at once still gets the growing
 * back-off. A full round of monitors that failed before reaching READY raises
 * WR_EV_CLUSTER_UNREACHABLE and the machine keeps trying; a cephx refusal raises WR_EV_AUTH_FAILED
 * and backs off the same way (and forgets the tickets, so the next try is a clean login); no
 * failure ever retries without a wait.
 *
 * Deviation from architecture 8.3: a failed ticket renewal closes the session first and opens the
 * new one after the minimum wait, instead of opening the new one before closing the old (the task
 * keeps exactly one monitor session at a time).
 */
#include "wri_mon.h"

#include "wri_le.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define KA_MS_PER_S 1000u

uint64_t wri_mon_add_ms(uint64_t now, uint64_t d)
{
	if (d >= WR_DEADLINE_NONE - 1u - now || now >= WR_DEADLINE_NONE - 1u)
		return WR_DEADLINE_NONE - 1u;
	return now + d;
}

static uint64_t mon_min_u64(uint64_t a, uint64_t b)
{
	return a < b ? a : b;
}

/* now - since, 0 if the clock stepped back (a host with a bad clock must not make every timer fire at once). */
static uint64_t mon_elapsed(uint64_t now, uint64_t since)
{
	return now > since ? now - since : 0;
}

/* AUTH_BAD_METHOD, a signature or mode refusal, and every cephx failure: the cluster is there but refuses us. */
static int is_auth_failure(wr_status st)
{
	return st == WR_E_M2_BAD_METHOD || st == WR_E_M2_SIGNATURE || st == WR_E_M2_MODE ||
	       (st <= WR_E_AUTH_DENIED && st >= WR_E_AUTH_RESULT);
}

static void mon_raise(const wri_mon_link *link, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *e)
{
	if (link->event != NULL)
		link->event(link->ctx, kind, epoch, e);
}

/* ---- back-off ------------------------------------------------------------------------------------------ */

/* The wait before the next attempt; also doubles the base for the one after. */
static uint32_t next_wait(const wri_ctx *x, wri_mon *m, int planned)
{
	uint32_t base = m->backoff_ms, jitter = 0, w;
	uint8_t r[4];

	if (planned)
		return m->min_wait_ms;
	if (base < m->min_wait_ms)
		base = m->min_wait_ms;
	if (base > m->max_wait_ms)
		base = m->max_wait_ms;
	if (wri_random(x, r, sizeof(r)) == WR_OK) /* a jitter is no secret: without a source the wait is just the base */
		jitter = wri_le32_get(r) % (base / 4u + 1u);
	w = base - jitter;
	if (w < m->min_wait_ms)
		w = m->min_wait_ms;
	m->backoff_ms = base > m->max_wait_ms / 2u ? m->max_wait_ms : base * 2u;
	return w;
}

/* ---- losing a session ------------------------------------------------------------------------------------ */

void wri_mon_fail(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link, wr_status st, unsigned line,
		  const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	wr_errinfo e;

	WR_MEMSET(&e, 0, sizeof(e));
	wri_errinfo_set(&e, st, WR_MOD_MON, line, what, a0, a1, a2);
	wri_mon_lose(x, m, cx, link, &e, 0);
}

/* Per-session state back to "no session". */
static void lose_reset(wri_mon *m)
{
	m->ev_ready = m->ev_closed = 0;
	m->need_getmap = m->need_sub = m->resub = 0;
	m->up = m->got_monmap = m->stable = m->retry = 0;
	m->ping_out = 0;
	m->fsid_bad = m->fsid_fail = 0; /* the count is per session: a wrong-cluster session must not poison the next monitor */
	m->renew_rounds = 0;
	m->renew_deadline_ms = WR_DEADLINE_NONE;
	m->conn_deadline_ms = WR_DEADLINE_NONE;
	wri_mon_slots_reset_session(m);
}

/* A monitor that never got to READY is one more failed rank in this round; a full round raises UNREACHABLE. */
static void lose_count_failure(wri_mon *m, const wri_mon_link *link, wr_status cause)
{
	wr_errinfo u;

	if (++m->failed_in_round < m->n_addrs)
		return;
	WR_MEMSET(&u, 0, sizeof(u));
	wri_errinfo_set(&u, WR_E_MON_UNREACHABLE, WR_MOD_MON, __LINE__, "a full round of monitors failed", m->n_addrs,
			(uint64_t)(-(int64_t)cause), 0);
	mon_raise(link, WR_EV_CLUSTER_UNREACHABLE, 0, &u);
	m->failed_in_round = 0;
}

void wri_mon_lose(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link, const wr_errinfo *why,
		  unsigned flags)
{
	uint16_t slot = m->conn_slot;
	uint8_t was_up = m->up, was_stable = m->stable;
	int planned = why->status == WR_OK;
	uint32_t wait;

	/* Forget the connection BEFORE asking for the close: whatever it reports meanwhile is not ours any more. */
	m->conn_slot = WRI_MON_NO_SLOT;
	if (!(flags & WRI_MON_LOSE_CONN_DONE) && slot != WRI_MON_NO_SLOT && link->close != NULL)
		link->close(link->ctx, slot, why->status);
	lose_reset(m);
	m->err = *why; /* from here on the event argument is m->err, so the caller's copy may be a temporary */
	if (was_up)
		mon_raise(link, WR_EV_MON_SESSION_DOWN, m->monmap_epoch, &m->err);
	if (is_auth_failure(m->err.status)) {
		mon_raise(link, WR_EV_AUTH_FAILED, m->monmap_epoch, &m->err);
		if (cx != NULL)
			wri_cx_forget(cx); /* never reuse a ticket the monitor just refused: the next try is a clean login */
	} else if (!was_up && !planned) {
		lose_count_failure(m, link, m->err.status);
	}
	if (was_stable && !planned)
		m->backoff_ms = m->min_wait_ms; /* a session that lived: the next failure starts the back-off over */
	if (m->err.status == WR_E_MON_FSID)
		m->backoff_ms = m->max_wait_ms; /* the wrong cluster does not get better by asking again soon */
	wait = next_wait(x, m, planned);
	m->hunt_at_ms = wri_mon_add_ms(x->now.mono_ms, wait);
	m->st = WRI_MON_HUNT_WAIT;
	WRI_LOG(x, WR_LOG_INFO, WR_MOD_MON, 0, m->err.status, "monitor session ended, hunting", wait, m->n_addrs, was_up, was_stable);
}

/* ---- opening a session ------------------------------------------------------------------------------------- */

static void open_started(const wri_ctx *x, wri_mon *m, uint16_t slot)
{
	m->n_opens++;
	m->conn_slot = slot;
	m->cur_rank = m->rank;
	m->cur_addr = m->addrs[m->rank];
	m->rank = (uint8_t)((m->rank + 1u) % m->n_addrs);
	m->st = WRI_MON_CONNECTING;
	wri_mon_slots_reset_session(m);
	m->ev_ready = m->ev_closed = 0;
	/* Guard against a host that never reports the connection: connect + handshake + a second of grace. */
	if (x->cfg.connect_timeout_ms != 0 && x->cfg.handshake_timeout_ms != 0)
		m->conn_deadline_ms = wri_mon_add_ms(x->now.mono_ms, (uint64_t)x->cfg.connect_timeout_ms +
									     x->cfg.handshake_timeout_ms + 1000u);
	else
		m->conn_deadline_ms = WR_DEADLINE_NONE;
}

static void open_session(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	uint16_t slot = WRI_MON_NO_SLOT;
	wr_status st;

	if (m->rank >= m->n_addrs)
		m->rank = 0;
	st = link->open(link->ctx, &m->addrs[m->rank], &slot);
	if (st == WR_E_BUSY) { /* no free connection slot (an old one is still closing): not a failed monitor */
		m->hunt_at_ms = wri_mon_add_ms(x->now.mono_ms, m->min_wait_ms);
		return;
	}
	if (st == WR_OK && slot != WRI_MON_NO_SLOT) {
		open_started(x, m, slot);
		return;
	}
	m->cur_rank = m->rank;
	m->rank = (uint8_t)((m->rank + 1u) % m->n_addrs);
	WRI_MON_FAIL(x, m, cx, link, st != WR_OK ? st : WR_E_STATE, "the monitor connection could not be opened", slot, 0, 0);
}

/* ---- keepalive ------------------------------------------------------------------------------------------------ */

/* Look at the ACK count; returns 1 if the ack timeout ended the session. */
static int ka_check(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	uint64_t now = x->now.mono_ms;
	uint32_t acks;

	if (link->keepalive_acks == NULL)
		return 0;
	acks = link->keepalive_acks(link->ctx, m->conn_slot);
	if (acks != m->ka_seen) {
		m->ka_seen = acks; /* an ACK came in: nothing is outstanding */
		m->ping_out = 0;
	}
	if (!m->ping_out || x->cfg.keepalive_timeout_ms == 0)
		return 0;
	if (m->stalled) { /* the connection is held by backpressure of ours: it cannot read the ACK */
		m->ping_since_ms = now;
		return 0;
	}
	if (mon_elapsed(now, m->ping_since_ms) < x->cfg.keepalive_timeout_ms)
		return 0;
	WRI_MON_FAIL(x, m, cx, link, WR_E_TIMEOUT, "no keepalive acknowledgement from the monitor", mon_elapsed(now, m->ping_since_ms),
		     x->cfg.keepalive_timeout_ms, 0);
	return 1;
}

/* The stamp of a KEEPALIVE2: the wall clock when the host has one, else the monotonic clock. */
static void ka_stamp(const wri_ctx *x, uint32_t *sec, uint32_t *nsec)
{
	uint64_t wall = x->now.wall_ms != 0 ? x->now.wall_ms : x->now.mono_ms;
	uint32_t s = (uint32_t)wri_div_s64_u32((int64_t)(wall & 0x7fffffffffffffffull), KA_MS_PER_S);

	*sec = s;
	*nsec = (uint32_t)(wall - (uint64_t)s * KA_MS_PER_S) * 1000000u;
}

static void sess_keepalive(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	uint64_t now = x->now.mono_ms;
	uint32_t sec, nsec;
	wr_status st;

	if (link->keepalive == NULL || x->cfg.keepalive_ms == 0)
		return;
	if (ka_check(x, m, cx, link))
		return;
	if (now < m->next_ping_ms)
		return;
	ka_stamp(x, &sec, &nsec);
	st = link->keepalive(link->ctx, m->conn_slot, sec, nsec);
	if (st == WR_E_BUSY) {
		m->retry = 1;
		m->next_ping_ms = wri_mon_add_ms(now, WRI_MON_RETRY_MS); /* a moment later, not a period later */
		return;
	}
	if (st != WR_OK) {
		WRI_MON_FAIL(x, m, cx, link, st, "keepalive could not be sent", 0, 0, 0);
		return;
	}
	m->next_ping_ms = wri_mon_add_ms(now, x->cfg.keepalive_ms);
	if (!m->ping_out) {
		m->ping_out = 1;
		m->ping_since_ms = now;
	}
}

/* ---- READY and the session proper -------------------------------------------------------------------------------- */

static void sync_sends(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	wr_status st;

	if (m->need_getmap) {
		st = wri_mon_send_getmap(link, m->conn_slot);
		if (st == WR_E_BUSY) {
			m->retry = 1;
			return;
		}
		if (st != WR_OK) {
			WRI_MON_FAIL(x, m, cx, link, st, "MMonGetMap could not be sent", 0, 0, 0);
			return;
		}
		m->need_getmap = 0;
	}
	if (m->need_sub || m->resub) {
		st = wri_mon_send_subscribe(m, link, m->conn_slot);
		if (st == WR_E_BUSY) {
			m->retry = 1;
			return;
		}
		if (st != WR_OK) {
			WRI_MON_FAIL(x, m, cx, link, st, "MMonSubscribe could not be sent", 0, 0, 0);
			return;
		}
		m->need_sub = m->resub = 0;
		if (!m->up) {
			m->up = 1;
			m->n_sessions++;
			m->failed_in_round = 0; /* a monitor answered: the round is over */
			mon_raise(link, WR_EV_MON_SESSION_UP, m->monmap_epoch, NULL);
		}
	}
}

static void sess_connecting(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	uint64_t now = x->now.mono_ms;

	if (m->ev_ready) {
		m->ev_ready = 0;
		m->st = WRI_MON_SYNC;
		m->need_getmap = m->need_sub = 1;
		m->conn_deadline_ms = x->cfg.keepalive_timeout_ms != 0 ? wri_mon_add_ms(now, x->cfg.keepalive_timeout_ms)
								       : WR_DEADLINE_NONE;
		m->next_ping_ms = wri_mon_add_ms(now, x->cfg.keepalive_ms);
		m->ping_out = 0;
		m->ka_seen = link->keepalive_acks != NULL ? link->keepalive_acks(link->ctx, m->conn_slot) : 0;
		return;
	}
	if (now >= m->conn_deadline_ms)
		WRI_MON_FAIL(x, m, cx, link, WR_E_TIMEOUT, "monitor connection never became ready", 0, 0, 0);
}

/* SYNC to ACTIVE, the guards of SYNC and the stability timer. Returns 1 if the session ended. */
static int sess_progress(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	uint64_t now = x->now.mono_ms;

	if (m->fsid_fail) {
		WRI_MON_FAIL(x, m, cx, link, WR_E_MON_FSID, "map messages keep coming from another cluster", m->n_fsid_drop,
			     0, 0);
		return 1;
	}
	if (m->st == WRI_MON_SYNC && m->got_monmap && !m->need_sub) {
		m->st = WRI_MON_ACTIVE;
		m->active_since_ms = now;
		m->conn_deadline_ms = WR_DEADLINE_NONE;
	}
	if (m->st == WRI_MON_SYNC && m->stalled && x->cfg.keepalive_timeout_ms != 0) /* held up by our own consumer */
		m->conn_deadline_ms = wri_mon_add_ms(now, x->cfg.keepalive_timeout_ms);
	if (m->st == WRI_MON_SYNC && now >= m->conn_deadline_ms) {
		WRI_MON_FAIL(x, m, cx, link, WR_E_TIMEOUT, "no monitor map after subscribing", 0, 0, 0);
		return 1;
	}
	if (m->st >= WRI_MON_ACTIVE && !m->stable && mon_elapsed(now, m->active_since_ms) >= x->cfg.keepalive_ms) {
		m->stable = 1; /* lived long enough to count as a success: the back-off starts over */
		m->backoff_ms = m->min_wait_ms;
		m->failed_in_round = 0;
		WR_MEMSET(&m->err, 0, sizeof(m->err));
	}
	return 0;
}

static void sess_run(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	sync_sends(x, m, cx, link);
	if (m->conn_slot == WRI_MON_NO_SLOT || sess_progress(x, m, cx, link))
		return;
	sess_keepalive(x, m, cx, link);
	if (m->conn_slot == WRI_MON_NO_SLOT)
		return;
	wri_mon_renew_step(x, m, cx, link);
}

/* Keepalive and renewal times of a live session. */
static uint64_t deadline_timers(const wri_ctx *x, const wri_mon *m, uint64_t d)
{
	if (m->ka_on)
		d = mon_min_u64(d, m->next_ping_ms);
	if (m->ka_on && m->ping_out && x->cfg.keepalive_timeout_ms != 0)
		d = mon_min_u64(d, wri_mon_add_ms(m->ping_since_ms, x->cfg.keepalive_timeout_ms));
	if (m->st == WRI_MON_RENEW)
		d = mon_min_u64(d, m->renew_deadline_ms);
	else if (m->st == WRI_MON_ACTIVE && m->renew_at_ms != WR_DEADLINE_NONE)
		d = mon_min_u64(d, m->renew_at_ms > m->renew_hold_ms ? m->renew_at_ms : m->renew_hold_ms);
	return d;
}

/* The earliest time something here wants to run again. */
static uint64_t next_deadline(const wri_ctx *x, const wri_mon *m)
{
	uint64_t d = WR_DEADLINE_NONE;

	if (m->st == WRI_MON_IDLE)
		return 0;
	if (m->st == WRI_MON_HUNT_WAIT)
		return m->hunt_at_ms;
	if (m->st == WRI_MON_CONNECTING)
		return m->conn_deadline_ms;
	if (m->retry || m->need_getmap || m->need_sub || m->resub)
		d = wri_mon_add_ms(x->now.mono_ms, WRI_MON_RETRY_MS);
	if (m->st == WRI_MON_SYNC)
		d = mon_min_u64(d, m->conn_deadline_ms);
	if (m->st >= WRI_MON_ACTIVE && !m->stable)
		d = mon_min_u64(d, wri_mon_add_ms(m->active_since_ms, x->cfg.keepalive_ms));
	return deadline_timers(x, m, d);
}

void wri_mon_step(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	uint64_t now;

	if (x == NULL || m == NULL || link == NULL || link->open == NULL || link->send == NULL)
		return;
	m->x = x;
	now = x->now.mono_ms;
	m->retry = 0;
	m->ka_on = link->keepalive != NULL && x->cfg.keepalive_ms != 0;
	if (m->st == WRI_MON_IDLE) {
		m->rank = 0;
		m->st = WRI_MON_HUNT_WAIT;
		m->hunt_at_ms = now; /* the first attempt of a process starts at once */
	}
	if (m->ev_closed) { /* the connection ended: hunt on */
		wr_errinfo e = m->close_err;

		wri_mon_lose(x, m, cx, link, &e, WRI_MON_LOSE_CONN_DONE);
	}
	wri_mon_notify_maps(m, link);
	if (m->st == WRI_MON_HUNT_WAIT && now >= m->hunt_at_ms)
		open_session(x, m, cx, link);
	if (m->st == WRI_MON_CONNECTING)
		sess_connecting(x, m, cx, link);
	if (m->st >= WRI_MON_SYNC)
		sess_run(x, m, cx, link);
	wri_mon_notify_maps(m, link);
	m->deadline_ms = next_deadline(x, m);
}
