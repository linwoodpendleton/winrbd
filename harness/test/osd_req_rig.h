/* SPDX-License-Identifier: MIT */
/*
 * osd_req_rig.h - the rig of the osd-req tests: the request engine (wri_osdc) over REAL sessions and connections. Everything below the engine is the
 * product's own (wri_osd_sess, wri_m2_conn, the cephx machine, one handshake per connection) talking through the in-test byte pump of osd_sess_world.h to
 * sim_osd servers over one store; everything above it is the test. The OSD map is scripted (mapw): the tests move primaries, epochs, flags and pools
 * by hand and the engine sees them through wri_osd_map_ops exactly as the glue will give them. Test code: libc allowed, everything static inline so every
 * test executable carries its own copy.
 */
#ifndef OSD_REQ_RIG_H
#define OSD_REQ_RIG_H

#include "osd_sess_world.h"
#include "wri_osd_req.h"

/* ---- the scripted map ------------------------------------------------------------------------------------------------------- */

#define MW_PG_MAX 64u
#define MW_POOLS 2u

typedef struct mapw {
	uint32_t epoch, flags, pg_num;        /* pg_num: a power of two, so a split is `pg_num *= 2` */
	struct {
		int present;
		wr_status status;
		uint64_t flags;
		uint32_t last_force;
		int64_t id;
	} pool[MW_POOLS];
	int prim[MW_PG_MAX];                  /* acting primary of each PG, -1 = nobody */
	int unmappable[MW_PG_MAX];            /* the map says WR_E_PLACE_UNMAPPABLE */
	int addr_of[W_OSD];                   /* which address of the world an OSD id has; -1 = the map has none */
	wr_status target_status;              /* != WR_OK: the placement of an object fails with this (the pool itself is fine) */
	const wr_addr *addrs;
	unsigned n_target, n_pool_info;
} mapw;

static inline uint32_t mw_hash(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	uint32_t h = 2166136261u;
	size_t i;

	for (i = 0; i < n; i++)
		h = (h ^ b[i]) * 16777619u;
	return h;
}

static inline uint32_t mw_pg(const mapw *m, const char *oid)
{
	return mw_hash(oid, strlen(oid)) & (m->pg_num - 1u);
}

static inline uint32_t mw_epoch(void *c) { return ((mapw *)c)->epoch; }
static inline uint32_t mw_flags(void *c) { return ((mapw *)c)->flags; }

static inline wr_status mw_pool_info(void *c, wr_pool_h h, wr_pool_info *out)
{
	mapw *m = (mapw *)c;

	memset(out, 0, sizeof(*out));
	m->n_pool_info++;
	if (m->epoch == 0)
		return WR_E_MAP_NONE;
	if (h >= MW_POOLS || !m->pool[h].present)
		return WR_E_POOL_NOT_FOUND;
	out->id = m->pool[h].id;
	out->flags = m->pool[h].flags;
	out->size = 3;
	out->min_size = 2;
	out->pg_num = out->pgp_num = m->pg_num;
	out->last_force_op_resend = m->pool[h].last_force;
	out->status = m->pool[h].status;
	return WR_OK;
}

static inline wr_status mw_target(void *c, wr_pool_h h, const wr_object_id *oid, wr_target *out)
{
	mapw *m = (mapw *)c;
	uint32_t hash, pg;
	int osd;

	memset(out, 0, sizeof(*out));
	m->n_target++;
	if (m->epoch == 0)
		return WR_E_MAP_NONE;
	if (h >= MW_POOLS || !m->pool[h].present)
		return WR_E_POOL_NOT_FOUND;
	if (m->pool[h].status != WR_OK)
		return m->pool[h].status;
	if (m->target_status != WR_OK)
		return m->target_status;
	hash = mw_hash(oid->name, oid->name_len);
	pg = hash & (m->pg_num - 1u);
	out->epoch = m->epoch;
	out->pool_id = m->pool[h].id;
	out->ps = hash;
	out->pg_seed = pg;
	osd = m->prim[pg];
	if (m->unmappable[pg] || osd < 0)
		return WR_E_PLACE_UNMAPPABLE;
	out->n_up = out->n_acting = 1;
	out->up[0] = out->acting[0] = osd;
	out->up_primary = out->acting_primary = osd;
	if (m->addr_of[osd] >= 0)
		out->primary_addr = m->addrs[m->addr_of[osd]];
	return WR_OK;
}

static inline wri_osd_map_ops mw_ops(mapw *m)
{
	wri_osd_map_ops o;

	memset(&o, 0, sizeof(o));
	o.ctx = m;
	o.epoch = mw_epoch;
	o.flags = mw_flags;
	o.pool_info = mw_pool_info;
	o.target = mw_target;
	return o;
}

/* Every PG of the map is served by `osd`. */
static inline void mw_all(mapw *m, int osd)
{
	unsigned i;

	for (i = 0; i < MW_PG_MAX; i++)
		m->prim[i] = osd;
}

/* ---- the rig ---------------------------------------------------------------------------------------------------------------- */

typedef struct rig_ev {
	wr_ev_kind kind;
	uint32_t arg;
	wr_status st;
	uint64_t a0;
} rig_ev;

typedef struct rig {
	world w;
	mapw m;
	wri_osdc o;
	uint8_t *mem, *bulk;
	wri_arena a, b;
	rig_ev ev[64];
	unsigned n_ev, n_stall, n_resume;
	uint64_t t_start;
} rig;

typedef void (*rig_tweak)(rig *);

static inline void rig_event(void *ctx, wr_ev_kind kind, uint32_t arg, const wr_errinfo *err)
{
	rig *r = (rig *)ctx;

	if (r->n_ev < 64u) {
		r->ev[r->n_ev].kind = kind;
		r->ev[r->n_ev].arg = arg;
		r->ev[r->n_ev].st = err != NULL ? err->status : WR_OK;
		r->ev[r->n_ev].a0 = err != NULL ? err->a0 : 0;
		r->n_ev++;
	}
	if (kind == WR_EV_IO_STALL)
		r->n_stall++;
	if (kind == WR_EV_IO_RESUME)
		r->n_resume++;
}

/*
 * A world of n_osd OSDs (all on one store), a table of n_sess sessions and an engine with the default budgets below; `tweak` runs after the defaults,
 * before anything is created: it may change r->w.e.x.cfg, the simulators' configuration (r->w.ocfg[]) and the scripted map. 0 = ok.
 */
static inline int rig_open(rig *r, unsigned n_osd, unsigned n_sess, rig_tweak tweak)
{
	wri_osd_link l;
	wri_osd_map_ops mo;
	size_t need_a = 0, need_b = 0;
	unsigned i;
	int rc;

	memset(r, 0, sizeof(*r));
	rc = w_open_world(&r->w, n_osd, n_sess, 2048, 8, WR_KEY_TYPE_AES256K);
	if (rc != 0) {
		fprintf(stderr, "w_open_world failed: %d\n", rc);
		return -1;
	}
	{
		wr_config *c = &r->w.e.x.cfg;

		c->max_ops = 32;
		c->ctl_ops = 2;
		c->max_snaps = 16;
		c->op_timeout_ms = 5000;
		c->osd_connect_timeout_ms = 2000;
		c->inflight_bytes_max = 64u << 20;
		c->op_bytes_max = 4u << 20;
		c->zombie_bytes = 65536;
		c->map_stale_ms = 30000;
		c->osd_idle_ms = 0;
		c->osd_flags = WR_OSDF_FULL_TRY | WR_OSDF_HONOR_PAUSE;
	}
	r->m.epoch = 10;
	r->m.pg_num = 8;
	for (i = 0; i < MW_POOLS; i++) {
		r->m.pool[i].present = i == 0;
		r->m.pool[i].id = (int64_t)(W_POOL + (int)i);
		r->m.pool[i].status = WR_OK;
	}
	r->m.addrs = r->w.addr;
	for (i = 0; i < W_OSD; i++)
		r->m.addr_of[i] = i < n_osd ? (int)i : -1;
	mw_all(&r->m, 0);
	if (tweak != NULL)
		tweak(r);
	for (i = 0; i < n_osd; i++) {
		r->w.osd[i] = sim_osd_new(&r->w.ocfg[i]);
		if (r->w.osd[i] == NULL)
			return -2;
	}
	if (wri_osdc_mem(&r->w.e.x.cfg, &need_a, &need_b) != WR_OK)
		return -3;
	r->mem = (uint8_t *)calloc(1, need_a + 128u);
	r->bulk = (uint8_t *)calloc(1, need_b + 128u);
	if (r->mem == NULL || r->bulk == NULL)
		return -4;
	wri_arena_init(&r->a, (uint8_t *)(((uintptr_t)r->mem + 63u) & ~(uintptr_t)63u), need_a + 64u);
	wri_arena_init(&r->b, (uint8_t *)(((uintptr_t)r->bulk + 63u) & ~(uintptr_t)63u), need_b + 64u);
	memset(&l, 0, sizeof(l));
	l.ctx = &r->w;
	l.open = w_open;
	l.close = w_close;
	l.send = w_send;
	l.tx_idle = w_tx_idle;
	l.features = NULL;
	l.have_ticket = w_have_ticket;
	l.handshake_free = w_handshake_free;
	mo = mw_ops(&r->m);
	if (wri_osdc_init(&r->o, &r->w.e.x, &r->a, &r->b, &mo, &l) != WR_OK)
		return -5;
	wri_osdc_set_event(&r->o, rig_event, r);
	r->t_start = r->w.e.x.now.mono_ms;
	return 0;
}

static inline void rig_close(rig *r)
{
	w_free(&r->w);
	free(r->mem);
	free(r->bulk);
	r->mem = r->bulk = NULL;
}

static inline uint64_t rig_now(const rig *r) { return r->w.e.x.now.mono_ms; }

/* Pump the connections and step the engine until nothing moves (bounded). Returns the rounds it took. */
static inline int rig_settle(rig *r)
{
	int i;

	for (i = 0; i < 600; i++) {
		int p = w_pump(&r->w);
		int more = wri_osdc_step(&r->o, 64);

		if (p == 0 && !more && w_pump(&r->w) == 0)
			break;
	}
	return i;
}

/* Advance the clock by ms (in steps of at most 100 ms, settling after each, so the engine meets every deadline in order). */
static inline void rig_tick(rig *r, uint64_t ms)
{
	while (ms != 0) {
		uint64_t d = ms < 100 ? ms : 100;

		r->w.e.x.now.mono_ms += d;
		ms -= d;
		(void)rig_settle(r);
	}
}

/* ---- building and collecting operations ------------------------------------------------------------------------------------------ */

static inline uint32_t rq_alloc(rig *r, unsigned kind, const char *oid, uint32_t owner, int control)
{
	uint32_t i = wri_osdc_alloc(&r->o, control);
	wri_osd_op *op;

	if (i == WRI_NIL)
		return WRI_NIL;
	op = wri_osdc_at(&r->o, i);
	op->kind = (uint8_t)kind;
	op->pool = 0;
	op->oid_len = (uint8_t)strlen(oid);
	memcpy(op->oid, oid, strlen(oid));
	op->owner = owner;
	op->n_ops = 1;
	return i;
}

/* Submit a filled slot; a failure is a test failure unless `want` says otherwise. Returns the slot, or WRI_NIL (the slot is released). */
static inline uint32_t rq_submit_expect(rig *r, uint32_t i, wr_status want)
{
	wr_status st;

	if (i == WRI_NIL) {
		WRT_CHECK(i != WRI_NIL);
		return WRI_NIL;
	}
	st = wri_osdc_submit(&r->o, i);
	WRT_CHECK_STATUS(want, st);
	if (st != WR_OK) {
		wri_osdc_release(&r->o, i);
		return WRI_NIL;
	}
	return i;
}

static inline uint32_t rq_submit(rig *r, uint32_t i)
{
	return rq_submit_expect(r, i, WR_OK);
}

static inline uint32_t rq_read(rig *r, const char *oid, uint64_t off, uint32_t len, uint8_t *out, uint32_t owner)
{
	uint32_t i = rq_alloc(r, WRI_OPK_READ, oid, owner, 0);
	wri_osd_op *op;

	if (i == WRI_NIL)
		return WRI_NIL;
	op = wri_osdc_at(&r->o, i);
	op->ops[0].code = WRI_OSD_OP_READ;
	op->ops[0].off = off;
	op->ops[0].len = len;
	op->out = out;
	op->out_cap = len;
	return rq_submit(r, i);
}

static inline uint32_t rq_write(rig *r, const char *oid, uint64_t off, const uint8_t *data, uint32_t len, const wri_snapc *sc, uint32_t owner)
{
	uint32_t i = rq_alloc(r, WRI_OPK_WRITE, oid, owner, 0);
	wri_osd_op *op;

	if (i == WRI_NIL)
		return WRI_NIL;
	op = wri_osdc_at(&r->o, i);
	op->ops[0].code = WRI_OSD_OP_WRITE;
	op->ops[0].off = off;
	op->ops[0].len = len;
	op->ops[0].in_len = len;
	op->data = data;
	op->data_len = len;
	op->snapc = sc;
	return rq_submit(r, i);
}

/* ZERO, TRUNCATE (off = the new size) or DELETE: one operation, no data. */
static inline uint32_t rq_plain(rig *r, const char *oid, uint16_t code, uint64_t off, uint64_t len, uint32_t owner)
{
	uint32_t i = rq_alloc(r, WRI_OPK_WRITE, oid, owner, 0);
	wri_osd_op *op;

	if (i == WRI_NIL)
		return WRI_NIL;
	op = wri_osdc_at(&r->o, i);
	op->ops[0].code = code;
	op->ops[0].off = off;
	op->ops[0].len = len;
	return rq_submit(r, i);
}

static inline wri_osd_op *rq_at(rig *r, uint32_t i)
{
	return wri_osdc_at(&r->o, i);
}

static inline int rq_done(rig *r, uint32_t i)
{
	return rq_at(r, i)->state == WRI_OP_DONE;
}

/* The ops the OSD k has seen, and its n-th record (NULL beyond). */
static inline const sim_osd_rec *rig_rec(rig *r, unsigned k, uint32_t n)
{
	uint32_t cnt = 0;
	const sim_osd_rec *rec = sim_osd_recs(r->w.osd[k], &cnt);

	return n < cnt ? &rec[n] : NULL;
}

static inline uint32_t rig_nrec(rig *r, unsigned k)
{
	uint32_t cnt = 0;

	(void)sim_osd_recs(r->w.osd[k], &cnt);
	return cnt;
}

/* Settle (and, while an op is not done, let `ms` of time pass in 100 ms steps up to `max_ms`) until op i is done. 1 = done. */
static inline int rig_until_done(rig *r, uint32_t i, uint64_t max_ms)
{
	uint64_t spent = 0;

	(void)rig_settle(r);
	while (!rq_done(r, i) && spent < max_ms) {
		rig_tick(r, 100);
		spent += 100;
	}
	return rq_done(r, i);
}

/* Pop every completion and release it; returns how many. */
static inline unsigned rig_drain(rig *r)
{
	unsigned n = 0;
	uint32_t i;

	while ((i = wri_osdc_pop_done(&r->o)) != WRI_NIL) {
		wri_osdc_release(&r->o, i);
		n++;
	}
	return n;
}

/* Pop one completion that must be op i (the oldest), release it, return its status. */
static inline wr_status rig_take(rig *r, uint32_t i)
{
	uint32_t got = wri_osdc_pop_done(&r->o);
	wr_status st = WR_E_STATE;

	WRT_CHECK(got == i);
	if (got != WRI_NIL) {
		st = rq_at(r, got)->status;
		wri_osdc_release(&r->o, got);
	}
	return st;
}

/* The simulator's end of the connection of engine session s, and a message it sends to the engine on it (pumped through at once). */
static inline sim_osd_conn *rig_srv(rig *r, uint32_t s)
{
	const wri_osd_sess *p = wri_osd_sess_at(&r->o.sess, s);

	return p != NULL && p->conn_slot < W_EC ? r->w.ec[p->conn_slot].sc : NULL;
}

static inline wr_status rig_inject(rig *r, uint32_t s, uint16_t type, uint64_t tid, uint16_t ver, const uint8_t *front, uint32_t flen,
				   const uint8_t *data, uint32_t dlen)
{
	sim_osd_conn *c = rig_srv(r, s);
	wr_status st;

	if (c == NULL)
		return WR_E_STATE;
	st = sim_m2_send_message(sim_osd_conn_m2(c), type, tid, ver, front, flen, NULL, 0, data, dlen);
	if (st == WR_OK)
		(void)w_pump(&r->w);
	return st;
}

/* Bytes the store holds for an object, as a flat copy; 1 if it exists. */
static inline int rig_store_read(rig *r, const char *oid, uint64_t off, uint8_t *out, size_t n)
{
	int exists = 0;

	if (sim_store_read(r->w.store, W_POOL, oid, off, out, n, &exists) != WR_OK)
		return 0;
	return exists;
}

/* Every slot and byte the engine accounts for is back: nothing live, nothing queued, nothing on the wire, the free list whole. */
static inline int rig_idle(const rig *r)
{
	return r->o.n_inflight == 0 && r->o.inflight_bytes == 0 && r->o.head == WRI_NIL && r->o.tail == WRI_NIL && r->o.done_len == 0 &&
	       r->o.n_free == r->o.n_op && r->o.n_ctl_used == 0 && r->o.zused == 0;
}

#endif /* OSD_REQ_RIG_H */
