/* SPDX-License-Identifier: MIT */
/*
 * wr_client.c - the public client API: create / destroy, the scheduler wr_client_run, events, map
 * messages, state and diagnostics. The connection table and the host-facing wr_conn_* calls are in
 * wri_client_conn.c, the memory layout in wri_client_mem.c; see wri_client.h for the overview and
 * docs/design/core-architecture.md 8.4 for the order of one run.
 *
 * One run, fixed order, nothing waits:
 *   1. set the clock (never backwards); re-base the handshake deadline of fresh connects;
 *   2. step every connection (parse, CRC, handshake, dispatch to the monitor client and cephx), with
 *      one shared work budget; the next run starts behind the connection that used it up, so a busy
 *      connection cannot starve the others;
 *   3. housekeeping: connect backstop, handshake slots, connections that ended unseen;
 *   4. the monitor client (hunting, subscriptions, keepalive, renewal, map slots);
 *   5. fatal check, state, first-failure bookkeeping; return the earliest deadline.
 * The host then drains actions and moves bytes.
 */
#include "wri_client.h"

#include "wri_le.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define CLIENT_PREFIX_LEN 7u /* strlen("client.") */

static int engine_ok(const wr_client *c)
{
	return c != NULL && c->magic == WRI_CLIENT_MAGIC;
}

/* ---- create / destroy ---------------------------------------------------------------------------------- */

/* The cluster description, checked before anything is written to the host's regions. */
static wr_status check_spec(const wr_cluster_spec *sp)
{
	wr_key tmp;
	size_t n = 0, skip = 0;
	unsigned i, have_mon = 0;
	wr_status st;

	while (n < WR_ENTITY_MAX && sp->user[n] != '\0')
		n++;
	if (n == WR_ENTITY_MAX)
		return WR_E_INVAL; /* not terminated inside the field */
	if (n >= CLIENT_PREFIX_LEN && sp->user[0] == 'c' && sp->user[1] == 'l' && sp->user[2] == 'i' && sp->user[3] == 'e' &&
	    sp->user[4] == 'n' && sp->user[5] == 't' && sp->user[6] == '.')
		skip = CLIENT_PREFIX_LEN;
	if (n - skip == 0u)
		return WR_E_INVAL;
	st = wr_key_from_raw(&tmp, sp->key.type, sp->key.secret, sp->key.len); /* type and length of the key */
	wr_key_wipe(&tmp);
	if (st != WR_OK)
		return st;
	if (sp->n_mons > WR_MAX_MONS)
		return WR_E_INVAL;
	for (i = 0; i < sp->n_mons; i++)
		have_mon |= sp->mons[i].family == WR_AF_IPV4 || sp->mons[i].family == WR_AF_IPV6;
	return have_mon ? WR_OK : WR_E_MON_NO_V2_ADDR;
}

static int regions_ok(wr_mem_region a, wr_mem_region b)
{
	uintptr_t a0 = (uintptr_t)a.base, b0 = (uintptr_t)b.base;

	if (a.base == NULL || b.base == NULL || (a0 & 15u) != 0u || (b0 & 15u) != 0u)
		return 0;
	if (a.size > (size_t)-1 - a0 || b.size > (size_t)-1 - b0) /* a region that wraps the address space */
		return 0;
	return a0 + a.size <= b0 || b0 + b.size <= a0; /* disjoint */
}

wr_status wr_client_create(const wr_config *cfg, const wr_host_ops *host, const wr_cluster_spec *cluster,
			   wr_mem_region arena, wr_mem_region bulk, wr_client **out)
{
	wri_layout lay;
	wri_arena a, b;
	uint8_t nb[4];
	wr_client *c = NULL;
	wr_status st;

	if (out == NULL)
		return WR_E_INVAL;
	*out = NULL;
	if (cfg == NULL || host == NULL || cluster == NULL)
		return WR_E_INVAL;
	st = wri_client_layout(cfg, &lay);
	if (st != WR_OK)
		return st;
	if (host->size != (uint32_t)sizeof(wr_host_ops))
		return WR_E_ABI;
	if (host->random == NULL)
		return WR_E_INVAL;
	if (arena.size < lay.arena || bulk.size < lay.bulk)
		return WR_E_BUDGET;
	if (!regions_ok(arena, bulk))
		return WR_E_INVAL;
	st = check_spec(cluster);
	if (st != WR_OK)
		return st;
	/* The entity nonce is drawn before anything is written: a host without randomness never gets a client. */
	if (host->random(host->ctx, nb, sizeof(nb)) != WR_OK) {
		wri_secure_zero(nb, sizeof(nb));
		return WR_E_HOST_RANDOM;
	}

	wri_arena_init(&a, arena.base, arena.size);
	wri_arena_init(&b, bulk.base, bulk.size);
	st = wri_client_carve(&a, &b, cfg, &lay, host, cluster, wri_le32_get(nb), &c);
	wri_secure_zero(nb, sizeof(nb));
	if (st != WR_OK) {
		wri_secure_zero(arena.base, a.used); /* nothing partly initialised, no key left behind */
		wri_secure_zero(bulk.base, b.used);
		return st;
	}
	*out = c;
	return WR_OK;
}

void wr_client_destroy(wr_client *c)
{
	uint8_t *base;
	size_t used;

	if (!engine_ok(c))
		return;
	base = c->arena_base;
	used = c->arena_used;
	wri_cx_client_wipe(&c->cx); /* principal, session keys, tickets, scratch */
	if (c->mon.abuf != NULL) /* the renewal buffers (bulk) carry sealed cephx payloads */
		wri_secure_zero(c->mon.abuf, c->mon.abuf_cap);
	if (c->mon.fbuf != NULL)
		wri_secure_zero(c->mon.fbuf, c->mon.abuf_cap);
	wri_secure_zero(base, used); /* the engine itself, rings, transcripts, ticket blobs: the whole arena part in use */
}

/* ---- events ------------------------------------------------------------------------------------------------ */

static int is_failure_kind(wr_ev_kind k)
{
	return k == WR_EV_MON_SESSION_DOWN || k == WR_EV_AUTH_FAILED || k == WR_EV_CLUSTER_UNREACHABLE || k == WR_EV_FATAL;
}

static int errinfo_same(const wr_errinfo *a, const wr_errinfo *b)
{
	return a->status == b->status && a->module == b->module && a->line == b->line && a->peer_result == b->peer_result &&
	       a->conn == b->conn && a->a0 == b->a0 && a->a1 == b->a1 && a->a2 == b->a2 && a->what == b->what;
}

/* First failure since the last success wins. */
static void note_failure(wr_client *c, const wr_errinfo *e)
{
	if (c->last_err.status == WR_OK && e->status != WR_OK)
		c->last_err = *e;
}

/* The monitor client reports why its last session ended in mon.err (also when no event is raised for it). */
static void sync_mon_err(wr_client *c)
{
	if (c->mon.err.status == WR_OK) {
		WR_MEMSET(&c->mon_err_seen, 0, sizeof(c->mon_err_seen));
		return;
	}
	if (!errinfo_same(&c->mon.err, &c->mon_err_seen)) {
		c->mon_err_seen = c->mon.err;
		note_failure(c, &c->mon.err);
	}
}

void wri_client_push_event(wr_client *c, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *err)
{
	wr_event e;
	unsigned i, j;

	if (!engine_ok(c))
		return;
	WR_MEMSET(&e, 0, sizeof(e));
	e.kind = kind;
	e.epoch = epoch;
	if (err != NULL)
		e.err = *err;
	if (kind == WR_EV_MON_SESSION_UP) { /* a success: the next failure is a new first failure */
		WR_MEMSET(&c->last_err, 0, sizeof(c->last_err));
		c->mon_err_seen = c->mon.err;
	} else if (is_failure_kind(kind)) {
		sync_mon_err(c); /* mon.err is set before the event is raised: it names the root cause, the event may be a summary of it */
		if (err != NULL)
			note_failure(c, err);
	}
	if (c->ev_len == WRI_EVENT_RING) { /* full: drop the oldest informational event, never a fatal one */
		for (i = 0; i < c->ev_len; i++)
			if (c->ev[(c->ev_head + i) % WRI_EVENT_RING].kind != WR_EV_FATAL)
				break;
		c->ev_dropped++;
		if (i == c->ev_len) { /* only fatal events queued (cannot happen: one per engine) */
			if (kind != WR_EV_FATAL)
				return; /* the new informational event is the one that is lost */
			i = 0;
		}
		for (j = i; j + 1u < c->ev_len; j++)
			c->ev[(c->ev_head + j) % WRI_EVENT_RING] = c->ev[(c->ev_head + j + 1u) % WRI_EVENT_RING];
		c->ev_len--;
	}
	c->ev[(c->ev_head + c->ev_len) % WRI_EVENT_RING] = e;
	c->ev_len++;
}

int wr_client_next_event(wr_client *c, wr_event *out)
{
	if (out == NULL)
		return 0;
	WR_MEMSET(out, 0, sizeof(*out));
	if (!engine_ok(c) || c->ev_len == 0u)
		return 0;
	*out = c->ev[c->ev_head];
	c->ev_head = (uint8_t)((c->ev_head + 1u) % WRI_EVENT_RING);
	c->ev_len--;
	return 1;
}

/* ---- the scheduler ------------------------------------------------------------------------------------------- */

/* No randomness is unrecoverable: the core never falls back to a weak source (wr_host.h). */
static void check_fatal(wr_client *c)
{
	wr_errinfo why;

	if (c->state == WR_CS_FAILED || c->mon.err.status != WR_E_HOST_RANDOM)
		return;
	why = c->mon.err;
	c->state = WR_CS_FAILED;
	WRI_LOG(&c->x, WR_LOG_ERR, WR_MOD_CLIENT, 0, why.status, "host random source failed, client stopped", 0, 0, 0, 0);
	wri_client_push_event(c, WR_EV_FATAL, 0, &why);
	wri_client_conn_close_all(c, why.status);
}

static uint64_t earliest_deadline(const wr_client *c)
{
	uint64_t d = wri_client_conn_deadline(c), t, now = c->x.now.mono_ms;

	if (c->state == WR_CS_FAILED)
		return d;
	t = wri_mon_deadline(&c->mon);
	if (t < d)
		d = t;
	t = wri_cx_next_renew_ms(&c->cx); /* only a future time: one already due is the monitor client's to act on */
	if (t != WR_DEADLINE_NONE && t > now && t < d)
		d = t;
	return d;
}

wr_run_result wr_client_run(wr_client *c, const wr_clock *now, uint32_t work_budget)
{
	wr_run_result r;
	uint32_t budget;

	r.next_deadline_ms = WR_DEADLINE_NONE;
	r.more_work = 0;
	if (!engine_ok(c) || now == NULL)
		return r;
	if (now->mono_ms > c->x.now.mono_ms) /* the clock is monotonic: a host that steps back is held at the last value */
		c->x.now.mono_ms = now->mono_ms;
	c->x.now.wall_ms = now->wall_ms;
	budget = work_budget != 0u ? work_budget : WRI_CLIENT_DEFAULT_BUDGET;
	if (c->state == WR_CS_CREATED)
		c->state = WR_CS_HUNTING;

	wri_client_conn_rebase(c);
	r.more_work = (uint32_t)wri_client_conn_step_all(c, &budget);
	wri_client_conn_housekeeping(c);
	if (c->state != WR_CS_FAILED)
		wri_mon_step(&c->x, &c->mon, &c->cx, &c->link);
	sync_mon_err(c);
	check_fatal(c);
	wri_client_conn_housekeeping(c);
	if (c->state != WR_CS_FAILED)
		c->state = c->mon.up ? WR_CS_ACTIVE : WR_CS_HUNTING;
	r.next_deadline_ms = earliest_deadline(c);
	return r;
}

/* ---- map messages --------------------------------------------------------------------------------------------- */

int wr_client_mapmsg_peek(wr_client *c, wr_mapmsg *out)
{
	if (out == NULL)
		return 0;
	WR_MEMSET(out, 0, sizeof(*out));
	if (!engine_ok(c))
		return 0;
	return wri_mon_mapmsg_peek(&c->mon, out);
}

void wr_client_mapmsg_release(wr_client *c)
{
	if (engine_ok(c))
		wri_mon_mapmsg_release(&c->mon);
}

/* ---- state and diagnostics --------------------------------------------------------------------------------------- */

wr_client_state wr_client_get_state(const wr_client *c)
{
	return engine_ok(c) ? c->state : WR_CS_FAILED;
}

const wr_errinfo *wr_client_last_error(const wr_client *c)
{
	static const wr_errinfo none = {0, 0, 0, 0, 0, 0, 0, 0, 0, NULL};

	return engine_ok(c) ? &c->last_err : &none;
}

void wr_client_get_stats(const wr_client *c, wr_stats *out)
{
	if (out == NULL)
		return;
	WR_MEMSET(out, 0, sizeof(*out));
	if (!engine_ok(c))
		return;
	wri_client_conn_stats(c, out);
	wri_mon_mapmsg_stats(&c->mon, &out->mapmsg_in_use, &out->mapmsg_hiwater);
	out->arena_used = c->stats.arena_used;
	out->bulk_used = c->stats.bulk_used;
}
