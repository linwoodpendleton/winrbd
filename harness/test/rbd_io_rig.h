/* SPDX-License-Identifier: MIT */
/*
 * rbd_io_rig.h - the rig of the rbd-io tests: the image layer (wri_rbd) over the object engine of osd_req_rig.h (real sessions and connections, sim_osd
 * servers over one store, a scripted map). The images are built OPEN directly from a sim_rbd_image_cfg: no header read, no dependency on the open
 * machine. What `wri_rbd_step` will be in the engine (client-glue-osd) is `rio_step` here: engine step, collect, cut, timeouts.
 * Test code: libc allowed, everything static inline so every test executable carries its own copy.
 */
#ifndef RBD_IO_RIG_H
#define RBD_IO_RIG_H

#include "osd_req_rig.h"
#include "wri_rbd_io.h"

/* ---- parameters ------------------------------------------------------------------------------------------------------------- */

typedef struct rio_params {
	unsigned n_osd, n_sess;
	uint32_t max_ops, ctl_ops, max_reqs, max_images, max_snaps;
	uint32_t op_bytes_max, inflight_bytes_max, zombie_bytes, op_timeout_ms, hdr_refresh_ms;
	rig_tweak tweak;                       /* the test's own change of the rig (map, simulators, config), after the parameters */
} rio_params;

static inline rio_params rio_defaults(void)
{
	rio_params p;

	memset(&p, 0, sizeof(p));
	p.n_osd = 1;
	p.n_sess = 2;
	p.max_ops = 32;
	p.ctl_ops = 2;
	p.max_reqs = 32;
	p.max_images = 2;
	p.max_snaps = 16;
	p.op_bytes_max = 1u << 20;
	p.inflight_bytes_max = 64u << 20;
	p.zombie_bytes = 1u << 20;
	p.op_timeout_ms = 5000;
	p.hdr_refresh_ms = 0;
	return p;
}

static const rio_params *rio_cur_params;

static inline void rio_apply_params(rig *g)
{
	wr_config *c = &g->w.e.x.cfg;
	const rio_params *p = rio_cur_params;

	c->max_ops = (uint16_t)p->max_ops;
	c->ctl_ops = (uint16_t)p->ctl_ops;
	c->max_reqs = (uint16_t)p->max_reqs;
	c->max_images = (uint16_t)p->max_images;
	c->max_snaps = (uint16_t)p->max_snaps;
	c->op_bytes_max = p->op_bytes_max;
	c->inflight_bytes_max = p->inflight_bytes_max;
	c->zombie_bytes = p->zombie_bytes;
	c->op_timeout_ms = p->op_timeout_ms;
	c->hdr_refresh_ms = p->hdr_refresh_ms;
	c->img_ctl_bytes = 4096;
	if (p->tweak != NULL)
		p->tweak(g);
}

/* ---- the rig ---------------------------------------------------------------------------------------------------------------- */

typedef struct rio_rq {                        /* a host request: the core's wr_io_req first, the test's bookkeeping after it */
	wr_io_req q;
	int done;                              /* the completion was pulled */
	wr_status st;
	unsigned order;                        /* completion order number */
	uint8_t *expect;                       /* READ: what the bytes must be (malloc'd, owned by the test) */
	uint64_t sub_no;                       /* submission number */
} rio_rq;

typedef struct rbio {
	rig g;
	wri_rbd r;
	uint8_t *mem;
	wri_arena a;
	unsigned n_done;                       /* completions pulled so far */
	uint64_t sub_count;
	size_t arena_planned;
} rbio;

static inline int rio_open(rbio *b, const rio_params *p)
{
	size_t need = 0;
	wri_arena *a;

	memset(b, 0, sizeof(*b));
	rio_cur_params = p;
	if (rig_open(&b->g, p->n_osd, p->n_sess, rio_apply_params) != 0)
		return -1;
	if (wri_rbd_mem(&b->g.w.e.x.cfg, &need) != WR_OK)
		return -2;
	b->arena_planned = need;
	b->mem = (uint8_t *)calloc(1, need + 256u);
	if (b->mem == NULL)
		return -3;
	a = &b->a;
	wri_arena_init(a, (uint8_t *)(((uintptr_t)b->mem + 63u) & ~(uintptr_t)63u), need + 64u);
	if (wri_rbd_init(&b->r, &b->g.w.e.x, a, &b->g.o) != WR_OK)
		return -4;
	return 0;
}

static inline void rio_close(rbio *b)
{
	rig_close(&b->g);
	free(b->mem);
	b->mem = NULL;
}

static inline uint64_t rio_now(const rbio *b) { return b->g.w.e.x.now.mono_ms; }

/* ---- images ----------------------------------------------------------------------------------------------------------------- */

/* Image `slot`: created in the store like the lab's (rbd_id / rbd_header), and made OPEN in the layer from the same description. */
static inline wri_rbd_img *rio_image(rbio *b, unsigned slot, const char *name, uint64_t size, uint8_t order, int writable)
{
	sim_rbd_image_cfg cfg;
	char id[16];
	wri_rbd_img *im = &b->r.img[slot];

	memset(&cfg, 0, sizeof(cfg));
	snprintf(id, sizeof(id), "id%02u", slot);
	cfg.pool = W_POOL;
	cfg.name = name;
	cfg.id = id;
	cfg.size = size;
	cfg.order = order;
	cfg.features = 1;
	cfg.data_pool = -1;
	if (sim_rbd_image_create(b->g.w.store, &cfg) != WR_OK)
		return NULL;
	im->state = (uint8_t)WR_IMG_OPEN;
	im->ros = (uint8_t)WRI_ROS_READY;
	im->want_write = (uint8_t)(writable != 0);
	im->writable = (uint8_t)(writable != 0);
	im->was_open = 1;
	im->order = order;
	im->size = size;
	im->features = cfg.features;
	im->pool_h = 0;
	im->data_pool_h = 0;
	im->pool_id = W_POOL;
	im->data_pool_id = W_POOL;
	snprintf(im->name, sizeof(im->name), "%s", name);
	snprintf(im->id, sizeof(im->id), "%s", id);
	snprintf(im->prefix, sizeof(im->prefix), "rbd_data.%s", id);
	im->snapc.seq = 0;
	im->snapc.n = 0;
	im->refreshed_ms = rio_now(b);
	im->next_refresh_ms = WR_DEADLINE_NONE;
	return im;
}

/* The name of data object n of image `slot`. */
static inline void rio_oname(const rbio *b, unsigned slot, uint64_t n, char out[WRI_RBD_OBJNAME_MAX])
{
	(void)wri_rbd_obj_name(out, WRI_RBD_OBJNAME_MAX, b->r.img[slot].prefix, n);
}

/* ---- the step and time ------------------------------------------------------------------------------------------------------ */

/* Pull every finished request into its rio_rq. Returns how many. */
static inline unsigned rio_collect_done(rbio *b)
{
	unsigned n = 0;
	wr_io_req *p;

	while ((p = wri_rbd_next_done(&b->r)) != NULL) {
		rio_rq *x = (rio_rq *)(void *)p;

		WRT_CHECK(!x->done);
		x->done = 1;
		x->st = p->status;
		x->order = b->n_done++;
		n++;
	}
	return n;
}

/* Everything that changes when the layer, the engine or a server does something: two equal readings in a row mean nothing moves. */
static inline uint64_t rio_fp(const rbio *b)
{
	uint64_t f = b->g.o.next_tid + b->g.o.n_done * 7u + b->g.o.n_resent * 13u + b->r.n_completed * 17u + b->r.n_submitted * 19u +
		     (uint64_t)b->g.o.n_inflight * 23u + (uint64_t)b->r.done_len * 37u + (uint64_t)b->g.o.done_len * 41u;
	unsigned k;

	for (k = 0; k < b->g.w.n_osd; k++)
		f += (uint64_t)sim_osd_n_requests(b->g.w.osd[k]) * 29u + (uint64_t)sim_osd_n_conns_accepted(b->g.w.osd[k]) * 31u;
	return f;
}

/* One pass of what the engine's step will do for the layer: bytes, engine, collect, cut, timeouts. Returns the pump's rounds. */
static inline int rio_step_once(rbio *b)
{
	uint64_t dl = WR_DEADLINE_NONE;
	int rounds = w_pump(&b->g.w);

	(void)wri_osdc_step(&b->g.o, 64);
	(void)wri_rbd_io_collect(&b->r);
	(void)wri_rbd_io_cut(&b->r, 64);
	wri_rbd_io_timeouts(&b->r, &dl);
	return rounds;
}

/* Settle: step until nothing moves (bounded). Completions stay in the ring (the test pulls them with rio_collect_done). */
static inline int rio_settle(rbio *b)
{
	uint64_t last = rio_fp(b);
	int i, same = 0;

	for (i = 0; i < 20000; i++) {
		uint64_t f;

		(void)rio_step_once(b);
		f = rio_fp(b);
		if (f == last) {
			if (++same >= 3)
				break;
		} else {
			same = 0;
			last = f;
		}
	}
	return i;
}

/* Settle and pull. */
static inline unsigned rio_run(rbio *b)
{
	unsigned n = 0;
	int i;

	for (i = 0; i < 64; i++) {
		unsigned k;

		(void)rio_settle(b);
		k = rio_collect_done(b);
		n += k;
		if (k == 0)
			break;
	}
	return n;
}

/* Advance the clock by ms in steps of at most 100 ms, running the layer after each. */
static inline void rio_tick(rbio *b, uint64_t ms)
{
	while (ms != 0) {
		uint64_t d = ms < 100 ? ms : 100;

		b->g.w.e.x.now.mono_ms += d;
		ms -= d;
		(void)rio_run(b);
	}
}

/* Run (letting time pass in 100 ms steps up to max_ms) until the request is done. 1 = done. */
static inline int rio_until(rbio *b, rio_rq *x, uint64_t max_ms)
{
	uint64_t spent = 0;

	(void)rio_run(b);
	while (!x->done && spent < max_ms) {
		rio_tick(b, 100);
		spent += 100;
	}
	return x->done;
}

/* ---- requests --------------------------------------------------------------------------------------------------------------- */

static inline void rio_fill_req(rio_rq *x, wr_io_kind kind, uint64_t off, uint64_t len, void *buf, uint32_t timeout_ms)
{
	memset(x, 0, sizeof(*x));
	x->q.kind = kind;
	x->q.offset = off;
	x->q.length = len;
	x->q.buf = buf;
	x->q.timeout_ms = timeout_ms;
	x->q.user = x;
}

static inline wr_status rio_submit(rbio *b, unsigned img, rio_rq *x)
{
	wr_status st = wri_rbd_submit(&b->r, img, &x->q);

	if (st == WR_OK)
		x->sub_no = ++b->sub_count;
	return st;
}

/* Fill, submit, expect success at submit. */
static inline int rio_go(rbio *b, unsigned img, rio_rq *x, wr_io_kind kind, uint64_t off, uint64_t len, void *buf, uint32_t timeout_ms)
{
	rio_fill_req(x, kind, off, len, buf, timeout_ms);
	WRT_CHECK_STATUS(WR_OK, rio_submit(b, img, x));
	return x->sub_no != 0;
}

/* Deterministic bytes: a function of (seed, position), so a test can name what a region holds. */
static inline void rio_pattern(uint8_t *p, size_t n, uint32_t seed)
{
	uint32_t s = seed * 2654435761u + 12345u;
	size_t i;

	for (i = 0; i < n; i++) {
		s = s * 1664525u + 1013904223u;
		p[i] = (uint8_t)(s >> 24);
	}
}

/* ---- checks against the store ------------------------------------------------------------------------------------------------- */

/* The bytes [off, off + n) of image `slot` as the store holds them (a missing object and a hole are zeros), through the object names. */
static inline int rio_store_read(rbio *b, unsigned slot, uint64_t off, uint8_t *out, size_t n)
{
	const wri_rbd_img *im = &b->r.img[slot];
	size_t done = 0;

	while (done < n) {
		uint64_t pos = off + done, objno = pos >> im->order, in_obj = pos & ((1ull << im->order) - 1u);
		size_t run = (size_t)((1ull << im->order) - in_obj);
		char name[WRI_RBD_OBJNAME_MAX];
		int exists = 0;

		if (run > n - done)
			run = n - done;
		rio_oname(b, slot, objno, name);
		if (sim_store_read(b->g.w.store, W_POOL, name, in_obj, out + done, run, &exists) != WR_OK)
			return 0;
		done += run;
	}
	return 1;
}

/* Every slot and byte the layer accounts for is back: no request in the table, no operation in the engine, the ring empty. */
static inline int rio_idle(const rbio *b)
{
	uint32_t i, n_free = 0;

	for (i = b->r.rq_free; i != WRI_NIL && n_free <= b->r.n_rq; i = b->r.rq[i].link)
		n_free++;
	return b->r.reqs_inflight == 0 && b->r.done_len == 0 && n_free == b->r.n_rq && rig_idle(&b->g);
}

#endif /* RBD_IO_RIG_H */
