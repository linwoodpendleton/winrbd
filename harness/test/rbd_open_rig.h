/* SPDX-License-Identifier: MIT */
/*
 * rbd_open_rig.h - the rig of the rbd-open tests: the image layer (wri_rbd, the open and refresh machine of wri_rbd_open.c and the I/O half's
 * collect / cut) over the REAL request engine, real sessions and sim_osd (osd_req_rig.h) with the sim_osd image fixtures (sim_rbd_image_create). The
 * OSD map is the scripted one of the request rig; the pool names of the open parameters go through a scripted wri_rbd_pools:
 *   "meta"  -> handle 0 (pool id W_POOL)
 *   "data"  -> handle 1 (pool id W_POOL + 1)
 *   "ghost" -> handle 1 too (a name the tests make absent by clearing mapw.pool[1].present)
 *   "bad"   -> the track call fails (WR_E_TOOBIG)
 * The tests move time (orig_tick), the map and the full-map counter by hand, exactly as the engine glue will. Test code: libc allowed, everything
 * static inline so every test executable carries its own copy.
 */
#ifndef RBD_OPEN_RIG_H
#define RBD_OPEN_RIG_H

#include "osd_req_rig.h"
#include "wri_rbd_io.h"
#include "wri_rbd_open.h"

#define OR_META "meta"
#define OR_DATA "data"
#define OR_GHOST "ghost"

typedef struct oev {
	wr_ev_kind kind;
	uint32_t arg;
	wr_status st;
	uint64_t a0;
} oev;

typedef struct orig {
	rig r;
	wri_rbd L;
	wri_rbd_pools pools;
	uint8_t *mem;
	wri_arena a;
	uint32_t n_full;        /* what the host says about the full maps adopted */
	unsigned n_track;       /* wr_client_pool_track calls */
	oev ev[64];
	unsigned n_ev;
	unsigned n_img_ev;      /* WR_EV_IMAGE events */
	int use_n_full;         /* 0: the pools table has no n_full hook */
} orig;

static orig *g_orig;        /* the tweak of rig_open needs the rig it is making */

static inline wr_status orig_track(void *ctx, const char *name, wr_pool_h *h)
{
	orig *o = (orig *)ctx;

	o->n_track++;
	if (strcmp(name, OR_META) == 0)
		*h = 0;
	else if (strcmp(name, OR_DATA) == 0 || strcmp(name, OR_GHOST) == 0)
		*h = 1;
	else
		return WR_E_TOOBIG;
	return WR_OK;
}

static inline uint32_t orig_nfull(void *ctx) { return ((orig *)ctx)->n_full; }

static inline void orig_event(void *ctx, wr_ev_kind kind, uint32_t arg, const wr_errinfo *err)
{
	orig *o = (orig *)ctx;

	if (o->n_ev < 64u) {
		o->ev[o->n_ev].kind = kind;
		o->ev[o->n_ev].arg = arg;
		o->ev[o->n_ev].st = err != NULL ? err->status : WR_OK;
		o->ev[o->n_ev].a0 = err != NULL ? err->a0 : 0;
		o->n_ev++;
	}
	if (kind == WR_EV_IMAGE)
		o->n_img_ev++;
}

/* The configuration the open tests use (on top of the request rig's defaults). */
typedef struct orig_cfg {
	uint16_t max_images, max_reqs, max_snaps, ctl_ops;
	uint32_t hdr_refresh_ms, img_ctl_bytes;
	unsigned first_map_epoch;   /* 0: no map yet */
} orig_cfg;

static inline orig_cfg orig_cfg_default(void)
{
	orig_cfg c;

	memset(&c, 0, sizeof(c));
	c.max_images = 4;
	c.max_reqs = 16;
	c.max_snaps = 8;
	c.ctl_ops = 4;
	c.hdr_refresh_ms = 1000;
	c.img_ctl_bytes = 4096;
	c.first_map_epoch = 10;
	return c;
}

static orig_cfg g_cfg;

static inline void orig_tweak(rig *r)
{
	wr_config *c = &r->w.e.x.cfg;

	c->max_images = g_cfg.max_images;
	c->max_reqs = g_cfg.max_reqs;
	c->max_snaps = g_cfg.max_snaps;
	c->ctl_ops = g_cfg.ctl_ops;
	c->hdr_refresh_ms = g_cfg.hdr_refresh_ms;
	c->img_ctl_bytes = g_cfg.img_ctl_bytes;
	r->m.epoch = g_cfg.first_map_epoch;
	r->m.pool[1].present = 1; /* the data pool exists unless a test removes it */
}

/* 0 = ok. n_osd OSDs, one session each. */
static inline int orig_open(orig *o, const orig_cfg *cfg)
{
	size_t need = 0;

	memset(o, 0, sizeof(*o));
	g_cfg = cfg != NULL ? *cfg : orig_cfg_default();
	g_orig = o;
	o->use_n_full = 1;
	if (rig_open(&o->r, 1, 2, orig_tweak) != 0)
		return -1;
	if (wri_rbd_mem(&o->r.w.e.x.cfg, &need) != WR_OK)
		return -2;
	o->mem = (uint8_t *)calloc(1, need + 128u);
	if (o->mem == NULL)
		return -3;
	wri_arena_init(&o->a, (uint8_t *)(((uintptr_t)o->mem + 63u) & ~(uintptr_t)63u), need + 64u);
	o->L.event = orig_event; /* bound before the carve: wri_rbd_init keeps it */
	o->L.event_ctx = o;
	if (wri_rbd_init(&o->L, &o->r.w.e.x, &o->a, &o->r.o) != WR_OK)
		return -4;
	o->pools.ctx = o;
	o->pools.track = orig_track;
	o->pools.n_full = orig_nfull;
	o->n_full = g_cfg.first_map_epoch != 0 ? 1u : 0u;
	return 0;
}

static inline void orig_close(orig *o)
{
	rig_close(&o->r);
	free(o->mem);
	o->mem = NULL;
}

static inline uint64_t orig_now(const orig *o) { return o->r.w.e.x.now.mono_ms; }

/* One pass of what the engine glue's wri_rbd_step will do, and the fatal answers of the I/O half. Returns 1 if anything moved. */
static inline int orig_pass(orig *o)
{
	uint64_t dl = WR_DEADLINE_NONE;
	uint32_t img;
	wr_status st;
	int p = w_pump(&o->r.w);
	int more = wri_osdc_step(&o->r.o, 64);

	more |= wri_rbd_open_step(&o->L, &dl);
	more |= wri_rbd_io_collect(&o->L) != 0;
	while (wri_rbd_io_take_fatal(&o->L, &img, &st)) {
		wr_errinfo why;

		memset(&why, 0, sizeof(why));
		why.status = st;
		why.module = WR_MOD_RBD;
		wri_rbd_img_fail(&o->L, img, &why);
		more = 1;
	}
	more |= wri_rbd_io_cut(&o->L, 64);
	wri_rbd_io_timeouts(&o->L, &dl);
	if (wri_osdc_deadline(&o->r.o) <= orig_now(o))
		more = 1; /* the engine has an operation to target or send: the host's loop would run it again at once */
	return p != 0 || more != 0;
}

static inline int orig_settle(orig *o)
{
	int i;

	for (i = 0; i < 600; i++) {
		if (!orig_pass(o) && w_pump(&o->r.w) == 0)
			break;
	}
	return i;
}

/* Advance the clock by ms in steps of at most 100 ms, settling after each. */
static inline void orig_tick(orig *o, uint64_t ms)
{
	while (ms != 0) {
		uint64_t d = ms < 100 ? ms : 100;

		o->r.w.e.x.now.mono_ms += d;
		ms -= d;
		(void)orig_settle(o);
	}
}

/* ---- images --------------------------------------------------------------------------------------------------------------------- */

/* A plain image the open accepts as reader and writer (features 0x21: layering + deep-flatten), 4 MiB objects, 64 MiB. */
static inline sim_rbd_image_cfg oimg_cfg(const char *name, const char *id)
{
	sim_rbd_image_cfg c;

	memset(&c, 0, sizeof(c));
	c.pool = W_POOL;
	c.name = name;
	c.id = id;
	c.size = 64ull << 20;
	c.order = 22;
	c.features = 0x21;
	c.data_pool = -1;
	return c;
}

static inline void oimg_make(orig *o, const sim_rbd_image_cfg *c)
{
	wr_status st = sim_rbd_image_create(o->r.w.store, c);

	WRT_CHECK_STATUS(WR_OK, st);
}

static inline wr_image_params oparams(const char *pool, const char *name, const char *id, int want_write)
{
	wr_image_params p;

	memset(&p, 0, sizeof(p));
	p.size = (uint32_t)sizeof(p);
	p.pool = pool;
	p.name = name;
	p.id = id;
	p.snap_id = WR_SNAP_HEAD;
	p.want_write = (uint8_t)want_write;
	return p;
}

/* Open and return the slot (WRI_NIL if the start refused: the status is checked against `want`). */
static inline uint32_t orig_start(orig *o, const wr_image_params *p, wr_status want)
{
	uint32_t slot = WRI_NIL;
	wr_status st = wri_rbd_open_start(&o->L, &o->pools, p, &slot);

	WRT_CHECK_STATUS(want, st);
	return st == WR_OK ? slot : WRI_NIL;
}

static inline wri_rbd_img *oimg(orig *o, uint32_t slot) { return &o->L.img[slot]; }

/* Messages the OSD recorded with this object name. */
static inline unsigned orig_nrec_oid(orig *o, const char *oid)
{
	uint32_t i, n = rig_nrec(&o->r, 0), c = 0;

	for (i = 0; i < n; i++) {
		const sim_osd_rec *rec = rig_rec(&o->r, 0, i);

		if (rec != NULL && strcmp(rec->oid, oid) == 0)
			c++;
	}
	return c;
}

/* The slot of the engine is back where it belongs: no control operation in use, none in the done ring. */
static inline int orig_ctl_idle(const orig *o)
{
	return o->r.o.n_ctl_used == 0 && o->r.o.done_len == 0;
}

static inline unsigned orig_count_ev(const orig *o, wr_ev_kind kind, uint32_t arg)
{
	unsigned i, n = 0;

	for (i = 0; i < o->n_ev; i++)
		if (o->ev[i].kind == kind && o->ev[i].arg == arg)
			n++;
	return n;
}

#endif /* RBD_OPEN_RIG_H */
