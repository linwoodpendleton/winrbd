/* SPDX-License-Identifier: MIT */
/*
 * wri_client_osd.c - the OSD client and the image layer inside the engine (design 26 and 27): the memory plan and the create-time carve of the
 * whole layer, the three-line adapters that give the object engine the map and the events (over wr_map.h and the event ring), the stage of
 * wr_client_run, the engine's side of a fatal error, and the counters.
 *
 * Memory. wri_client_osd_mem computes, with the same walk wri_client_osd_init takes, the arena and bulk bytes of: the glue block (struct wri_cosd:
 * the object engine and the image layer embedded), the per-connection-slot cephx contexts, the image handles, the object engine's tables and the
 * session table (wri_osdc_mem), the image layer's tables (wri_rbd_mem), and the zombie area (bulk). The walk is the plan / take pair of
 * wri_client_mem.c: wr_client_mem_required adds this plan to the engine's, create adds what init takes, and test_client_osd_mem asserts that the two
 * are the same number for the three profiles and random configurations.
 */
#include "wri_client_osd.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define OSD_MSGS_MAX 64u    /* object messages encoded / extents cut in one pass of the stage (an upper bound however large the work budget) */
#if defined(__GNUC__) || defined(__clang__)
#define OSD_NOINLINE __attribute__((noinline))
#else
#define OSD_NOINLINE
#endif
#define OSD_TX_SLACK 256u   /* bytes of an OSD request's frame around its front: preamble, header, checksums, epilogue (with room to spare) */

/* ---- configuration and memory ---------------------------------------------------------------------------------------------- */

static wr_status check_osd_cfg(const wr_config *cfg)
{
	if (cfg->map_slot_bytes == 0u)
		return WR_E_INVAL; /* the image layer places objects with the map module */
	if (cfg->max_conns < (uint32_t)cfg->osd_sessions + 2u)
		return WR_E_INVAL; /* the monitor session and the one that replaces it during a renewal keep their two slots */
	if (cfg->ctl_ops == 0u || cfg->max_ops <= cfg->ctl_ops)
		return WR_E_INVAL; /* data operations need slots besides the control reserve, and an open needs a reserve to be sure of one */
	if (cfg->max_images == 0u || cfg->max_reqs == 0u || cfg->osd_front_cap == 0u || cfg->op_bytes_max == 0u || cfg->inflight_bytes_max == 0u ||
	    cfg->op_timeout_ms == 0u || cfg->osd_connect_timeout_ms == 0u || cfg->img_ctl_bytes == 0u || cfg->backoff_slots == 0u)
		return WR_E_INVAL;
	if (cfg->op_bytes_max > wri_client_seg_cap(cfg) || cfg->op_bytes_max > cfg->inflight_bytes_max)
		return WR_E_INVAL; /* a reply's data segment must fit a connection, and one operation must fit the bytes on the wire */
	if ((uint64_t)cfg->tx_buf_bytes < (uint64_t)cfg->osd_front_cap + OSD_TX_SLACK)
		return WR_E_INVAL; /* a request front is encoded into the connection's encode buffer */
	return WR_OK;
}

/* The plan / take walk of the glue's own pieces (the same idea as wri_client_mem.c: one routine, two modes). */
typedef struct osd_take {
	wri_arena *a; /* NULL = plan mode */
	size_t used;
	wr_status st;
} osd_take;

static void *otk(osd_take *t, size_t count, size_t elem)
{
	void *p;

	if (t->st != WR_OK)
		return NULL;
	if (t->a == NULL) {
		t->st = wri_arena_plan_array(&t->used, count, elem, 16u);
		return NULL;
	}
	p = wri_arena_take_array(t->a, count, elem, 16u);
	if (p == NULL)
		t->st = WR_E_BUDGET;
	return p;
}

wr_status wri_client_osd_mem(const wr_config *cfg, size_t *arena_bytes, size_t *bulk_bytes)
{
	osd_take t;
	size_t oa = 0, ob = 0, ra = 0;
	wr_status st;

	if (cfg == NULL || arena_bytes == NULL || bulk_bytes == NULL)
		return WR_E_INVAL;
	*arena_bytes = 0;
	*bulk_bytes = 0;
	if (cfg->osd_sessions == 0u)
		return WR_OK;
	st = check_osd_cfg(cfg);
	if (st != WR_OK)
		return st;
	st = wri_osdc_mem(cfg, &oa, &ob);
	if (st == WR_OK)
		st = wri_rbd_mem(cfg, &ra);
	if (st != WR_OK)
		return st;
	WR_MEMSET(&t, 0, sizeof(t));
	(void)otk(&t, 1u, sizeof(struct wri_cosd));
	(void)otk(&t, cfg->max_conns, sizeof(wri_cx_hs));
	(void)otk(&t, cfg->max_images, sizeof(struct wr_image));
	if (t.st == WR_OK)
		t.st = wri_arena_plan(&t.used, oa, 16u);
	if (t.st == WR_OK)
		t.st = wri_arena_plan(&t.used, ra, 16u);
	if (t.st != WR_OK)
		return t.st;
	*arena_bytes = t.used;
	*bulk_bytes = ob;
	return WR_OK;
}

/* ---- what the object engine and the image layer see of the engine ---------------------------------------------------------- */

static const wri_osdmap *held(const wr_client *c)
{
	return wri_mapstore_map(&c->map);
}

static uint32_t m_epoch(void *ctx)
{
	const wri_osdmap *m = held((const wr_client *)ctx);

	return m != NULL ? m->epoch : 0u;
}

static uint32_t m_flags(void *ctx)
{
	const wri_osdmap *m = held((const wr_client *)ctx);

	return m != NULL ? m->flags : 0u;
}

static wr_status m_pool_info(void *ctx, wr_pool_h h, wr_pool_info *out)
{
	return wr_client_pool_info((const wr_client *)ctx, h, out);
}

static wr_status m_target(void *ctx, wr_pool_h h, const wr_object_id *oid, wr_target *out)
{
	return wr_client_map_target((wr_client *)ctx, h, oid, out);
}

static wr_status p_track(void *ctx, const char *name, wr_pool_h *h)
{
	return wr_client_pool_track((wr_client *)ctx, name, h);
}

static uint32_t p_n_full(void *ctx)
{
	wr_map_stats ms;

	wr_client_map_stats((const wr_client *)ctx, &ms);
	return ms.n_full;
}

/* An image event: arg is the slot, the engine's ring carries it as the event's epoch field (WR_EV_IMAGE: the image slot). */
static void rbd_event(void *ctx, wr_ev_kind kind, uint32_t arg, const wr_errinfo *err)
{
	wri_client_push_event((wr_client *)ctx, kind, arg, err);
}

/* A stall or a resume: the event says why in err (a0 = the OSD), the epoch field stays 0 (wr_client.h). */
static void osdc_event(void *ctx, wr_ev_kind kind, uint32_t arg, const wr_errinfo *err)
{
	(void)arg;
	wri_client_push_event((wr_client *)ctx, kind, 0u, err);
}

/* ---- create -------------------------------------------------------------------------------------------------------------- */

/* The object engine: the map ops and the link are carved into the engine's own tables by the init. Kept out of the caller's frame: the sanitizer builds at -O0 give every
 * temporary its own slot and the frame limit is 1 KiB. */
OSD_NOINLINE static wr_status init_osdc(wr_client *c, struct wri_cosd *og, wri_arena *arena, wri_arena *bulk)
{
	wri_osd_map_ops mops;
	wri_osd_link link;
	wr_status st;

	WR_MEMSET(&mops, 0, sizeof(mops));
	mops.ctx = c;
	mops.epoch = m_epoch;
	mops.flags = m_flags;
	mops.pool_info = m_pool_info;
	mops.target = m_target;
	wri_client_osd_link(c, &link);
	st = wri_osdc_init(&og->osd, &c->x, arena, bulk, &mops, &link);
	if (st == WR_OK)
		wri_osdc_set_event(&og->osd, osdc_event, c);
	return st;
}

/* The glue block, the per-slot cephx contexts and the image handles. */
OSD_NOINLINE static wr_status carve_glue(wr_client *c, wri_arena *arena, struct wri_cosd **out)
{
	osd_take t;
	struct wri_cosd *og;
	uint32_t i;

	WR_MEMSET(&t, 0, sizeof(t));
	t.a = arena;
	og = (struct wri_cosd *)otk(&t, 1u, sizeof(*og));
	if (t.st != WR_OK)
		return t.st;
	if (og == NULL)
		return WR_E_INVAL; /* no arena: the walk would be a plan, which takes nothing (only a caller that passes NULL gets here) */
	og->hs = (wri_cx_hs *)otk(&t, c->x.cfg.max_conns, sizeof(wri_cx_hs));
	og->h = (struct wr_image *)otk(&t, c->x.cfg.max_images, sizeof(struct wr_image));
	if (t.st != WR_OK)
		return t.st;
	og->n_hs = c->x.cfg.max_conns;
	og->n_h = c->x.cfg.max_images;
	og->rbd_deadline = WR_DEADLINE_NONE;
	for (i = 0; i < og->n_h; i++) {
		og->h[i].c = c;
		og->h[i].slot = (uint16_t)i;
		og->h[i].magic = WRI_IMG_MAGIC;
	}
	*out = og;
	return WR_OK;
}

/* The image layer: its hooks (the layer keeps what is bound before its init), the pool table it opens images through. */
OSD_NOINLINE static wr_status init_rbd(wr_client *c, struct wri_cosd *og, wri_arena *arena)
{
	og->pools.ctx = c;
	og->pools.track = p_track;
	og->pools.n_full = p_n_full;
	og->rbd.event = rbd_event;
	og->rbd.event_ctx = c;
	og->rbd.pools = &og->pools;
	return wri_rbd_init(&og->rbd, &c->x, arena, &og->osd);
}

wr_status wri_client_osd_init(wr_client *c, wri_arena *arena, wri_arena *bulk)
{
	struct wri_cosd *og = NULL;
	size_t oa = 0, ob = 0;
	wr_status st;

	if (c->x.cfg.osd_sessions == 0u)
		return WR_OK; /* the OSD client is off: three NULL pointers, nothing taken */
	st = wri_client_osd_mem(&c->x.cfg, &oa, &ob);
	if (st == WR_OK)
		st = carve_glue(c, arena, &og);
	if (st != WR_OK)
		return st;
	c->og = og; /* the connection hooks read it from the first open on */
	st = init_osdc(c, og, arena, bulk);
	if (st == WR_OK)
		st = init_rbd(c, og, arena);
	if (st != WR_OK)
		return st;
	c->osd = &og->osd;
	c->rbd = &og->rbd;
	return WR_OK;
}

/* ---- the stage of a run ---------------------------------------------------------------------------------------------------- */

/* Messages one pass may encode and extents it may cut: the engine's work budget scaled down to a count, never zero (a budget used up by the connections
 * must not stop the layer), never above OSD_MSGS_MAX. */
static uint32_t pass_budget(uint32_t budget)
{
	uint32_t n = budget >> 8;

	if (n == 0u)
		n = 1u;
	return n > OSD_MSGS_MAX ? OSD_MSGS_MAX : n;
}

/* Deadlines taken against a clock that was old (wri_client_osd.h): an image still OPENING, and the requests the glue marked. */
static void rebase_images(wr_client *c, uint64_t delta)
{
	uint32_t i;

	for (i = 0; i < c->og->n_h; i++) {
		struct wr_image *h = &c->og->h[i];
		wri_rbd_img *m = &c->og->rbd.img[i];

		if (!h->fresh)
			continue;
		h->fresh = 0;
		if (m->state != (uint8_t)WR_IMG_OPENING)
			continue;
		if (m->open_deadline_ms != WR_DEADLINE_NONE)
			m->open_deadline_ms = wri_mon_add_ms(m->open_deadline_ms, delta);
		m->refresh_start_ms = wri_mon_add_ms(m->refresh_start_ms, delta);
	}
}

static void rebase_requests(wr_client *c, uint64_t delta)
{
	wri_rbd *r = &c->og->rbd;
	uint32_t i;

	for (i = 0; i < r->n_rq; i++) {
		wri_rbd_rq *q = &r->rq[i];
		wri_rbd_rqpriv pv;

		/* only a request the host still owes a pull for holds a pointer that is good (a finished one may be gone, a zombie has none) */
		if (q->req == NULL || (q->state != (uint8_t)WRI_RQ_WAIT && q->state != (uint8_t)WRI_RQ_RUN))
			continue;
		WR_MEMCPY(&pv, q->req->priv, sizeof(pv));
		if (pv.used != WRI_RBD_PRIV_MAGIC || !pv.fresh)
			continue;
		pv.fresh = 0;
		WR_MEMCPY(q->req->priv, &pv, sizeof(pv));
		if (q->deadline_ms != WR_DEADLINE_NONE)
			q->deadline_ms = wri_mon_add_ms(q->deadline_ms, delta);
	}
}

void wri_client_osd_rebase(wr_client *c, uint64_t delta_ms)
{
	struct wri_cosd *og = c->og;

	if (og == NULL)
		return;
	if (og->fresh_img) {
		og->fresh_img = 0;
		rebase_images(c, delta_ms);
	}
	if (og->fresh_req) {
		og->fresh_req = 0;
		rebase_requests(c, delta_ms);
	}
}

void wri_client_osd_note_open(wr_client *c, uint32_t slot)
{
	if (c->og == NULL || slot >= c->og->n_h)
		return;
	c->og->h[slot].fresh = 1;
	c->og->fresh_img = 1;
}

void wri_client_osd_note_request(wr_client *c, wr_io_req *req)
{
	wri_rbd_rqpriv pv;

	if (c->og == NULL || req == NULL || req->timeout_ms == 0u)
		return;
	WR_MEMCPY(&pv, req->priv, sizeof(pv));
	if (pv.used != WRI_RBD_PRIV_MAGIC)
		return;
	pv.fresh = 1;
	WR_MEMCPY(req->priv, &pv, sizeof(pv));
	c->og->fresh_req = 1;
}

uint32_t wri_client_osd_begin(wr_client *c, uint32_t budget, int *more)
{
	struct wri_cosd *og = c->og;
	uint32_t n = pass_budget(budget);

	if (og == NULL || c->state == WR_CS_FAILED)
		return 0;
	*more |= wri_osdc_step(&og->osd, n);
	return n;
}

void wri_client_osd_end(wr_client *c, uint64_t rbd_deadline, int *more)
{
	struct wri_cosd *og = c->og;

	og->rbd_deadline = rbd_deadline;
	if (wri_osdc_deadline(&og->osd) <= c->x.now.mono_ms)
		*more = 1;
}

uint64_t wri_client_osd_deadline(const wr_client *c)
{
	uint64_t d, t;

	if (c->og == NULL || c->state == WR_CS_FAILED)
		return WR_DEADLINE_NONE;
	d = wri_osdc_deadline(&c->og->osd);
	t = c->og->rbd_deadline;
	return t < d ? t : d;
}

void wri_client_osd_on_fatal(wr_client *c)
{
	struct wri_cosd *og = c->og;
	wr_errinfo why;
	uint32_t i;

	if (og == NULL || og->failed || c->state != WR_CS_FAILED)
		return;
	og->failed = 1;
	why = og->fatal.status != WR_OK ? og->fatal : c->last_err;
	if (why.status == WR_OK)
		WRI_ERRINFO(&why, WR_E_STATE, WR_MOD_CLIENT, "the client has failed", 0, 0, 0);
	for (i = 0; i < og->rbd.n_img; i++)
		wri_rbd_img_fail(&og->rbd, i, &why); /* ignores a free or failed slot; completes the requests of the others */
}

void wri_client_osd_wipe(wr_client *c)
{
	if (c->og != NULL && c->og->osd.zbuf != NULL)
		wri_secure_zero(c->og->osd.zbuf, c->og->osd.zcap);
}

/* ---- counters ------------------------------------------------------------------------------------------------------------- */

/* The session table's counters (a function of its own: the sanitizer builds at -O0 give every local a slot with red zones and the frame limit is 1 KiB). */
OSD_NOINLINE static void stats_sessions(const wri_osd_sess_tab *t, wr_osd_stats *out)
{
	uint32_t i, open = 0;

	for (i = 0; i < t->n; i++)
		open += t->s[i].state == (uint8_t)WRI_OS_OPENING || t->s[i].state == (uint8_t)WRI_OS_READY;
	out->sessions_open = open;
	out->sessions_hiwater = t->hiwater;
	out->n_session_resets = t->n_resets;
	out->n_backoff_blocks = t->n_backoff_blocks;
	out->n_backoff_overflow = t->n_backoff_overflow;
	out->n_osdmap_discarded = t->n_osdmap_discarded;
}

void wri_client_osd_stats(const wr_client *c, wr_osd_stats *out)
{
	const struct wri_cosd *og = c->og;

	WR_MEMSET(out, 0, sizeof(*out));
	if (og == NULL)
		return;
	stats_sessions(&og->osd.sess, out);
	out->ops_inflight = og->osd.n_inflight;
	out->ops_hiwater = og->osd.hiwater;
	out->reqs_inflight = og->rbd.reqs_inflight;
	out->reqs_hiwater = og->rbd.reqs_hiwater;
	out->ops_done = og->osd.n_done;
	out->ops_resent = og->osd.n_resent;
	out->ops_failed = og->osd.n_failed;
	out->zombie_bytes_used = og->osd.zused;
	out->zombie_bytes_max = og->osd.zmax;
}
