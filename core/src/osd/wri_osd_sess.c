/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_sess.c - the table of OSD sessions (design 21.1 to 21.3): which connection slot belongs to which OSD, acquire with eviction
 * and cool-down, the idle reaper, send and reset. The wri_m2_upper table is in wri_osd_sess_up.c, the backoff table in
 * wri_osd_sess_bo.c.
 *
 * A session entry is in one of four states: FREE (nothing), COOLDOWN (no connection; remembers the OSD, its address and its fail streak
 * so the next attempt waits and the wait grows), OPENING (connection open, handshake running), READY. CLOSING exists only while the
 * table's own close call is running. Entries are only ever changed by this file and by the upper-layer callbacks of their own
 * connection; every change that ends a connection goes through settle() so that backoffs, counters and the lost callback cannot be
 * forgotten on one of the paths.
 */
#include "wri_osd_sess.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/* A call that carries a large local (an errinfo, an address) is kept out of its caller's frame: the sanitizer builds count every local with a red zone
 * against the 1024 byte frame limit. */
#if defined(__GNUC__) || defined(__clang__)
#define OS_NOINLINE __attribute__((noinline))
#else
#define OS_NOINLINE
#endif

static uint64_t now_ms(const wri_osd_sess_tab *t)
{
	return t->x->now.mono_ms;
}

void wri_os_err(wr_errinfo *e, wr_status st, unsigned line, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	WR_MEMSET(e, 0, sizeof(*e));
	wri_errinfo_set(e, st, WR_MOD_OSD, line, what, a0, a1, a2);
}

/* ---- memory ----------------------------------------------------------------------------------------------------------- */

static wr_status plan_all(const wr_config *cfg, size_t *used)
{
	size_t n = cfg->osd_sessions, nbo, fronts;
	wr_status st = wri_mul_sz(n, cfg->backoff_slots, &nbo);

	if (st != WR_OK)
		return st;
	st = wri_mul_sz(n, cfg->osd_front_cap, &fronts);
	if (st != WR_OK)
		return st;
	st = wri_arena_plan_array(used, n, sizeof(wri_osd_sess), 16u);
	if (st == WR_OK)
		st = wri_arena_plan(used, fronts, 16u);
	if (st == WR_OK)
		st = wri_arena_plan_array(used, nbo, sizeof(wri_backoff), 16u);
	return st;
}

wr_status wri_osd_sess_mem(const wr_config *cfg, size_t *arena_bytes)
{
	size_t used = 0;
	wr_status st;

	if (cfg == NULL || arena_bytes == NULL)
		return WR_E_INVAL;
	*arena_bytes = 0;
	if (cfg->osd_sessions == 0)
		return WR_OK;
	if (cfg->osd_front_cap < WRI_OSD_FRONT_MIN || cfg->backoff_slots == 0)
		return WR_E_INVAL;
	st = plan_all(cfg, &used);
	if (st != WR_OK)
		return st;
	*arena_bytes = used;
	return WR_OK;
}

wr_status wri_osd_sess_init(wri_osd_sess_tab *t, const wri_ctx *x, wri_arena *arena, const wri_osd_link *link,
			    const wri_osd_sess_up *up)
{
	uint8_t *fronts;
	wri_backoff *bos;
	size_t need = 0, nbo;
	uint32_t i, n;
	wr_status st;

	if (t == NULL)
		return WR_E_INVAL;
	WR_MEMSET(t, 0, sizeof(*t));
	if (x == NULL || arena == NULL || link == NULL || up == NULL)
		return WR_E_INVAL;
	if (link->open == NULL || link->close == NULL || link->send == NULL || link->tx_idle == NULL || link->have_ticket == NULL ||
	    link->handshake_free == NULL || up->sink == NULL || up->reply == NULL || up->bad_reply == NULL || up->ready == NULL ||
	    up->lost == NULL || up->unblock == NULL)
		return WR_E_INVAL;
	st = wri_osd_sess_mem(&x->cfg, &need);
	if (st != WR_OK)
		return st;
	n = x->cfg.osd_sessions;
	if (n == 0)
		return WR_E_INVAL; /* the OSD client is off: there is no table to make */
	nbo = (size_t)n * x->cfg.backoff_slots; /* checked by wri_osd_sess_mem */
	t->s = (wri_osd_sess *)wri_arena_take_array(arena, n, sizeof(wri_osd_sess), 16u);
	fronts = (uint8_t *)wri_arena_take_array(arena, n, x->cfg.osd_front_cap, 16u);
	bos = (wri_backoff *)wri_arena_take_array(arena, nbo, sizeof(wri_backoff), 16u);
	if (t->s == NULL || fronts == NULL || bos == NULL) {
		WR_MEMSET(t, 0, sizeof(*t));
		return WR_E_BUDGET;
	}
	t->x = x;
	t->link = *link;
	t->up = *up;
	t->n = n;
	for (i = 0; i < n; i++) {
		wri_osd_sess *s = &t->s[i];

		s->tab = t;
		s->state = WRI_OS_FREE;
		s->osd = -1;
		s->conn_slot = WRI_OS_NOSLOT;
		s->front = fronts + (size_t)i * x->cfg.osd_front_cap;
		s->bo = bos + (size_t)i * x->cfg.backoff_slots;
	}
	return WR_OK;
}

/* ---- accessors -------------------------------------------------------------------------------------------------------- */

const wri_osd_sess *wri_osd_sess_at(const wri_osd_sess_tab *t, uint32_t s)
{
	if (t == NULL || t->s == NULL || s >= t->n)
		return NULL;
	return &t->s[s];
}

uint32_t wri_osd_sess_index(const wri_osd_sess_tab *t, const wri_osd_sess *sess)
{
	if (t == NULL || sess == NULL || t->s == NULL || sess < t->s || sess >= t->s + t->n)
		return WRI_NIL;
	return (uint32_t)(sess - t->s);
}

int wri_osd_sess_ready(const wri_osd_sess_tab *t, uint32_t s)
{
	const wri_osd_sess *p = wri_osd_sess_at(t, s);

	return p != NULL && p->state == WRI_OS_READY;
}

static int has_conn(const wri_osd_sess *s)
{
	return s->state == WRI_OS_OPENING || s->state == WRI_OS_READY;
}

static uint32_t count_live(const wri_osd_sess_tab *t)
{
	uint32_t i, n = 0;

	for (i = 0; i < t->n; i++)
		n += has_conn(&t->s[i]) ? 1u : 0u;
	return n;
}

static int addr_equal(const wr_addr *a, const wr_addr *b)
{
	unsigned i, n;

	if (a->family != b->family || a->port != b->port || a->nonce != b->nonce)
		return 0;
	n = a->family == WR_AF_IPV4 ? 4u : 16u;
	for (i = 0; i < n; i++)
		if (a->ip[i] != b->ip[i])
			return 0;
	return 1;
}

/* ---- the end of a connection ------------------------------------------------------------------------------------------ */

/* The cool-down after the failure that makes the streak `streak`: osd_connect_timeout_ms doubled once per earlier failure, capped. */
static uint64_t cooldown_ms(const wri_osd_sess_tab *t, uint32_t streak)
{
	uint64_t base = t->x->cfg.osd_connect_timeout_ms;
	uint64_t cap = base > WRI_OSD_COOLDOWN_MAX_MS ? base : WRI_OSD_COOLDOWN_MAX_MS;
	uint64_t v = base;

	while (streak != 0 && v != 0 && v < cap) { /* a zero base stays zero: do not spin once per earlier failure */
		v <<= 1;
		streak--;
	}
	return v > cap ? cap : v;
}

/* Everything a finished connection leaves behind, in one place. */
static void settle(wri_osd_sess_tab *t, wri_osd_sess *s, const wr_errinfo *why, int orderly)
{
	wr_errinfo e;

	if (why != NULL)
		e = *why;
	else
		WR_MEMSET(&e, 0, sizeof(e));
	if (e.status == WR_OK)
		orderly = 1;
	wri_os_bo_clear(s);
	s->conn_slot = WRI_OS_NOSLOT;
	s->n_inflight = 0;
	s->rx_tid = 0;
	s->rx_flags = 0;
	s->rx_n_ops = 0;
	s->rx_data_len = 0;
	s->front_len = 0;
	s->features = 0;
	s->msg_version = 0;
	s->err = e;
	if (orderly) {
		s->state = WRI_OS_FREE;
		s->osd = -1;
		s->fail_streak = 0;
		WR_MEMSET(&s->addr, 0, sizeof(s->addr));
	} else {
		if (s->replied)
			s->fail_streak = 0; /* it was healthy: this is one failure, not a streak */
		s->cooldown_until_ms = now_ms(t) + cooldown_ms(t, s->fail_streak);
		if (s->fail_streak != UINT32_MAX)
			s->fail_streak++;
		s->state = WRI_OS_COOLDOWN;
		t->n_resets++;
	}
	s->replied = 0;
	t->up.lost(t->up.ctx, (uint32_t)(s - t->s), &s->err);
}

void wri_os_lost(wri_osd_sess_tab *t, wri_osd_sess *s, const wr_errinfo *why)
{
	if (!has_conn(s))
		return;
	settle(t, s, why, 0);
}

void wri_os_end(wri_osd_sess_tab *t, wri_osd_sess *s, const wr_errinfo *why, int orderly)
{
	uint16_t slot;
	wr_status cs = why != NULL ? why->status : WR_OK;

	if (!has_conn(s))
		return;
	slot = s->conn_slot;
	s->state = WRI_OS_CLOSING;
	s->conn_slot = WRI_OS_NOSLOT; /* its closed callback is ignored from here on */
	t->link.close(t->link.ctx, slot, cs);
	settle(t, s, why, orderly);
}

void wri_osd_sess_reset(wri_osd_sess_tab *t, uint32_t idx, const wr_errinfo *why)
{
	wri_osd_sess *s;
	wr_errinfo ok;

	s = t != NULL && t->s != NULL && idx < t->n ? &t->s[idx] : NULL;
	if (s == NULL || !has_conn(s))
		return;
	if (why == NULL) {
		WR_MEMSET(&ok, 0, sizeof(ok));
		why = &ok;
	}
	wri_os_end(t, s, why, why->status == WR_OK);
}

/* ---- acquire ---------------------------------------------------------------------------------------------------------- */

/* The entry of this OSD that is not FREE, or NULL. At most one exists (acquire keeps it so). */
static wri_osd_sess *find_osd(wri_osd_sess_tab *t, int32_t osd)
{
	uint32_t i;

	for (i = 0; i < t->n; i++)
		if (t->s[i].state != WRI_OS_FREE && t->s[i].osd == osd)
			return &t->s[i];
	return NULL;
}

static wri_osd_sess *find_free(wri_osd_sess_tab *t)
{
	uint32_t i;

	for (i = 0; i < t->n; i++)
		if (t->s[i].state == WRI_OS_FREE)
			return &t->s[i];
	return NULL;
}

/* A cool-down entry of another OSD whose time has passed (then it is only memory): the one that was tried last. An entry that is still cooling down is
 * never taken: it is the table's only record that the OSD just failed, so taking it for another OSD would let the next operation for the failed OSD dial it
 * again at once, evict a working session to do so, and repeat that for ever without time passing (found by fuzz_client_osd: two sessions, three OSDs, one
 * of them refusing connections). */
static wri_osd_sess *find_cooldown(wri_osd_sess_tab *t)
{
	wri_osd_sess *best = NULL;
	uint64_t now = now_ms(t);
	uint32_t i;

	for (i = 0; i < t->n; i++) {
		wri_osd_sess *s = &t->s[i];

		if (s->state == WRI_OS_COOLDOWN && s->cooldown_until_ms <= now && (best == NULL || s->cooldown_until_ms < best->cooldown_until_ms))
			best = s;
	}
	return best;
}

/* The READY session with nothing in flight that was used longest ago. */
static wri_osd_sess *find_lru(wri_osd_sess_tab *t)
{
	wri_osd_sess *best = NULL;
	uint32_t i;

	for (i = 0; i < t->n; i++) {
		wri_osd_sess *s = &t->s[i];

		if (s->state == WRI_OS_READY && s->n_inflight == 0 && (best == NULL || s->last_used_ms < best->last_used_ms))
			best = s;
	}
	return best;
}

/* Close a session on the table's own account (eviction, a moved OSD, the idle reaper): status WR_OK, no penalty. */
OS_NOINLINE static void close_orderly(wri_osd_sess_tab *t, wri_osd_sess *s)
{
	wr_errinfo ok;

	WR_MEMSET(&ok, 0, sizeof(ok));
	wri_os_end(t, s, &ok, 1);
}

/* Open the connection of entry s to `addr` and make the entry its session. WR_E_BUSY and the link's other statuses leave the entry as it was. */
OS_NOINLINE static wr_status open_entry(wri_osd_sess_tab *t, wri_osd_sess *s, int32_t osd, const wr_addr *addr, uint32_t keep_streak)
{
	wri_eaddr ea;
	uint16_t slot = WRI_OS_NOSLOT;
	wr_status st;

	wri_eaddr_from_wr(&ea, addr, WRI_EADDR_TYPE_MSGR2);
	st = t->link.open(t->link.ctx, &ea, wri_osd_sess_upper(), s, &slot);
	if (st != WR_OK)
		return st; /* BUSY: no connection or handshake slot yet; the entry keeps what it was (FREE or a cool-down) */
	if (slot == WRI_OS_NOSLOT)
		return WR_E_INVAL; /* a link that opens a connection must name a slot below 0xffff */
	WR_MEMSET(&s->err, 0, sizeof(s->err));
	s->osd = osd;
	s->addr = *addr;
	s->conn_slot = slot;
	s->state = WRI_OS_OPENING;
	s->replied = 0;
	s->bo_lost = 0;
	s->n_inflight = 0;
	s->fail_streak = keep_streak;
	s->last_used_ms = now_ms(t);
	s->rx_tid = 0;
	s->rx_flags = 0;
	s->rx_n_ops = 0;
	s->rx_data_len = 0;
	s->front_len = 0;
	s->features = 0;
	s->msg_version = 0;
	wri_os_bo_clear(s);
	t->n_opened++;
	return WR_OK;
}

wr_status wri_osd_sess_acquire(wri_osd_sess_tab *t, int32_t osd, const wr_addr *addr, uint32_t *out)
{
	wri_osd_sess *s, *same;
	uint32_t keep_streak = 0, live;
	wr_status st;

	if (t == NULL || t->s == NULL || addr == NULL || out == NULL || osd < 0 || addr->family == 0)
		return WR_E_INVAL;
	same = find_osd(t, osd);
	if (same != NULL) {
		if (has_conn(same) && addr_equal(&same->addr, addr)) {
			same->last_used_ms = now_ms(t);
			*out = (uint32_t)(same - t->s);
			return WR_OK;
		}
		if (has_conn(same)) { /* the map moved the OSD: this connection goes nowhere any more */
			close_orderly(t, same);
		} else if (addr_equal(&same->addr, addr)) { /* COOLDOWN at the same address */
			if (now_ms(t) < same->cooldown_until_ms)
				return WR_E_BUSY;
			keep_streak = same->fail_streak;
		}
		/* a cool-down at another address is void: the new address gets its attempt at once with a fresh streak */
	}
	/* the gates, before anything is evicted for a connection that cannot be opened now */
	if (!t->link.have_ticket(t->link.ctx) || !t->link.handshake_free(t->link.ctx))
		return WR_E_BUSY;
	s = same;
	if (s == NULL)
		s = find_free(t);
	if (s == NULL)
		s = find_cooldown(t);
	if (s == NULL) {
		s = find_lru(t);
		if (s == NULL)
			return WR_E_BUSY; /* every session has operations in flight or is cooling down after a failure */
		close_orderly(t, s); /* the engine frees the slot when the host has closed the socket: open() may say BUSY once */
		t->n_evicted++;
	}
	st = open_entry(t, s, osd, addr, keep_streak);
	if (st != WR_OK)
		return st;
	live = count_live(t);
	if (live > t->hiwater)
		t->hiwater = live;
	*out = (uint32_t)(s - t->s);
	return WR_OK;
}

/* ---- using a session -------------------------------------------------------------------------------------------------- */

wr_status wri_osd_sess_send(wri_osd_sess_tab *t, uint32_t idx, const wri_m2_msg_out *m)
{
	wri_osd_sess *s;
	wr_status st;

	if (t == NULL || t->s == NULL || m == NULL || idx >= t->n)
		return WR_E_INVAL;
	s = &t->s[idx];
	if (s->state != WRI_OS_READY)
		return WR_E_STATE;
	st = t->link.send(t->link.ctx, s->conn_slot, m);
	if (st == WR_OK)
		s->last_used_ms = now_ms(t);
	return st;
}

void wri_osd_sess_inflight(wri_osd_sess_tab *t, uint32_t idx, int delta)
{
	wri_osd_sess *s;

	if (t == NULL || t->s == NULL || idx >= t->n)
		return;
	s = &t->s[idx];
	if (!has_conn(s))
		return; /* nothing can be in flight on a session without a connection (the count was zeroed when it ended) */
	if (delta > 0) {
		if (s->n_inflight > UINT32_MAX - (uint32_t)delta)
			s->n_inflight = UINT32_MAX;
		else
			s->n_inflight += (uint32_t)delta;
		s->last_used_ms = now_ms(t);
	} else if (delta < 0) {
		uint32_t d = (uint32_t)(-(delta + 1)) + 1u; /* |delta| without overflowing at INT_MIN */

		s->n_inflight = s->n_inflight > d ? s->n_inflight - d : 0u;
	}
}

int wri_osd_sess_tx_idle(const wri_osd_sess_tab *t, uint32_t idx)
{
	const wri_osd_sess *s = wri_osd_sess_at(t, idx);

	if (s == NULL || !has_conn(s))
		return 1; /* no connection, no queue, nothing of ours is referenced */
	return t->link.tx_idle(t->link.ctx, s->conn_slot) != 0;
}

/* ---- periodic work ---------------------------------------------------------------------------------------------------- */

uint64_t wri_osd_sess_step(wri_osd_sess_tab *t)
{
	uint64_t next = WR_DEADLINE_NONE, now, idle;
	uint32_t i;

	if (t == NULL || t->s == NULL)
		return WR_DEADLINE_NONE;
	now = now_ms(t);
	idle = t->x->cfg.osd_idle_ms;
	for (i = 0; i < t->n; i++) {
		wri_osd_sess *s = &t->s[i];

		if (s->state == WRI_OS_CLOSING) { /* cannot be seen between calls; never leave an entry in a state nothing leaves */
			s->state = WRI_OS_FREE;
			s->osd = -1;
			s->conn_slot = WRI_OS_NOSLOT;
		} else if (s->state == WRI_OS_COOLDOWN) {
			if (s->cooldown_until_ms > now && s->cooldown_until_ms < next)
				next = s->cooldown_until_ms;
		} else if (s->state == WRI_OS_READY && idle != 0 && s->n_inflight == 0) {
			uint64_t due = s->last_used_ms + idle;

			if (now >= due) {
				close_orderly(t, s);
				t->n_idle_closed++;
			} else if (due < next) {
				next = due;
			}
		}
	}
	return next;
}
