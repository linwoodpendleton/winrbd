/* SPDX-License-Identifier: MIT */
/*
 * osd_sess_rig.h - the rig of the osd-sess tests that needs no network: a scripted engine link (connection slots, knobs for the gates and for
 * a busy engine, a log of what the table asked), a recorder for what the table tells the request layer, and builders of the frames an OSD
 * sends (a MOSDOpReply front written from osd-ops.md 2.9, a MOSDBackoff front). A frame is handed to the table the way the msgr2 parser hands
 * it to the upper layer: plan() names the sinks, the bytes are copied into them, message() follows. Test code: libc allowed, everything
 * static inline so every test executable carries its own copy.
 */
#ifndef OSD_SESS_RIG_H
#define OSD_SESS_RIG_H

#include <stdlib.h>
#include <string.h>

#include "wrt.h"

#include "wri_le.h"
#include "wri_osd_sess.h"

#define FK_SLOTS 12u
#define FK_LOG 64u

/* ---- the recorder: what the table tells the request layer ------------------------------------------------------------- */

typedef struct orec {
	unsigned seq;            /* callbacks so far: the order of bad_reply and lost */
	/* sink policy: the destination handed out for sink_tid (0 = every tid) */
	uint64_t sink_tid;
	uint8_t *sink_dst;
	uint32_t sink_cap, sink_n_ops;
	unsigned n_sink;
	uint64_t sink_last_tid;
	uint32_t sink_last_s;
	/* logs */
	unsigned n_ready, n_lost, n_unblock, n_reply, n_bad;
	uint32_t ready_s[FK_LOG];
	struct {
		uint32_t s;
		wr_status st;
		uint64_t a0, a1;
		const char *what;
		unsigned seq;
	} lost[FK_LOG];
	struct {
		uint32_t s;
		int64_t pool;
		uint32_t pg;
	} unblock[FK_LOG];
	struct {
		uint32_t s;
		uint64_t tid;
		uint32_t stored;
		wri_mosdopreply rep;
		uint8_t oid[64];
	} reply[FK_LOG];
	struct {
		uint32_t s;
		uint64_t tid;
		wr_status st;
		const char *what;
		unsigned seq;
	} bad[FK_LOG];
} orec;

static inline void orec_sink(void *ctx, uint32_t s, uint64_t tid, uint8_t **dst, uint32_t *cap, uint32_t *n_ops)
{
	orec *r = (orec *)ctx;

	r->n_sink++;
	r->sink_last_tid = tid;
	r->sink_last_s = s;
	if (r->sink_dst != NULL && (r->sink_tid == 0 || r->sink_tid == tid)) {
		*dst = r->sink_dst;
		*cap = r->sink_cap;
		*n_ops = r->sink_n_ops;
	}
}

static inline void orec_reply(void *ctx, uint32_t s, uint64_t tid, const wri_mosdopreply *rep, uint32_t stored)
{
	orec *r = (orec *)ctx;
	unsigned i = r->n_reply++;

	if (i < FK_LOG) {
		r->reply[i].s = s;
		r->reply[i].tid = tid;
		r->reply[i].stored = stored;
		r->reply[i].rep = *rep;
		memset(r->reply[i].oid, 0, sizeof(r->reply[i].oid));
		memcpy(r->reply[i].oid, rep->oid, rep->oid_len < sizeof(r->reply[i].oid) ? rep->oid_len : sizeof(r->reply[i].oid));
		r->reply[i].rep.oid = r->reply[i].oid; /* the front buffer is not ours to keep */
	}
}

static inline void orec_bad(void *ctx, uint32_t s, uint64_t tid, const wr_errinfo *why)
{
	orec *r = (orec *)ctx;
	unsigned i = r->n_bad++;

	if (i < FK_LOG) {
		r->bad[i].s = s;
		r->bad[i].tid = tid;
		r->bad[i].st = why->status;
		r->bad[i].what = why->what;
		r->bad[i].seq = ++r->seq;
	}
}

static inline void orec_ready(void *ctx, uint32_t s)
{
	orec *r = (orec *)ctx;
	unsigned i = r->n_ready++;

	if (i < FK_LOG)
		r->ready_s[i] = s;
}

static inline void orec_lost(void *ctx, uint32_t s, const wr_errinfo *why)
{
	orec *r = (orec *)ctx;
	unsigned i = r->n_lost++;

	if (i < FK_LOG) {
		r->lost[i].s = s;
		r->lost[i].st = why->status;
		r->lost[i].a0 = why->a0;
		r->lost[i].a1 = why->a1;
		r->lost[i].what = why->what;
		r->lost[i].seq = ++r->seq;
	}
}

static inline void orec_unblock(void *ctx, uint32_t s, int64_t pool, uint32_t pg)
{
	orec *r = (orec *)ctx;
	unsigned i = r->n_unblock++;

	if (i < FK_LOG) {
		r->unblock[i].s = s;
		r->unblock[i].pool = pool;
		r->unblock[i].pg = pg;
	}
}

static inline wri_osd_sess_up orec_up(orec *r)
{
	wri_osd_sess_up u;

	memset(&u, 0, sizeof(u));
	u.ctx = r;
	u.sink = orec_sink;
	u.reply = orec_reply;
	u.bad_reply = orec_bad;
	u.ready = orec_ready;
	u.lost = orec_lost;
	u.unblock = orec_unblock;
	return u;
}

/* ---- the scripted engine link ------------------------------------------------------------------------------------------ */

typedef struct fk_sent {
	uint16_t slot;
	wri_m2_msg_out m;
	uint8_t front[1024];
	uint32_t front_len;
} fk_sent;

typedef struct fk {
	/* knobs */
	int have_ticket, handshake_free, tx_idle;
	wr_status open_st;       /* != OK: open answers it (BUSY) */
	wr_status send_st;       /* != OK: send answers it */
	int closing_holds_slot;  /* 1: a closed slot stays used until fk_free_slot (an engine that frees it a run later) */
	int features_hook;       /* 1: link.features answers feat; 0: no hook (NULL) */
	uint64_t feat;
	/* the engine's slots */
	struct {
		int used, closing;
		wri_m2_conn conn;
		const wri_m2_upper *up;
		void *up_ctx;
		wri_eaddr addr;
		unsigned n_close;
		wr_status close_why;
	} slot[FK_SLOTS];
	unsigned n_slots;        /* slots the engine has (<= FK_SLOTS) */
	unsigned n_open, n_close, n_send, n_tx_idle_calls;
	unsigned max_live_seen;
	fk_sent sent[16];
	unsigned n_sent;
	uint16_t last_open_slot;
	wri_eaddr last_open_addr;
} fk;

static inline unsigned fk_live(const fk *f)
{
	unsigned i, n = 0;

	for (i = 0; i < f->n_slots; i++)
		n += f->slot[i].used ? 1u : 0u;
	return n;
}

static inline wr_status fk_open(void *ctx, const wri_eaddr *addr, const wri_m2_upper *up, void *up_ctx, uint16_t *slot)
{
	fk *f = (fk *)ctx;
	unsigned i;

	if (f->open_st != WR_OK)
		return f->open_st;
	for (i = 0; i < f->n_slots; i++) {
		if (!f->slot[i].used) {
			memset(&f->slot[i].conn, 0, sizeof(f->slot[i].conn));
			f->slot[i].used = 1;
			f->slot[i].closing = 0;
			f->slot[i].n_close = 0;
			f->slot[i].up = up;
			f->slot[i].up_ctx = up_ctx;
			f->slot[i].addr = *addr;
			f->slot[i].conn.slot = (uint16_t)i;
			f->slot[i].conn.role = WRI_ENTITY_OSD;
			f->slot[i].conn.state = WRI_M2_CONNECTING;
			f->n_open++;
			f->last_open_slot = (uint16_t)i;
			f->last_open_addr = *addr;
			if (fk_live(f) > f->max_live_seen)
				f->max_live_seen = fk_live(f);
			*slot = (uint16_t)i;
			return WR_OK;
		}
	}
	return WR_E_BUSY;
}

static inline void fk_close(void *ctx, uint16_t slot, wr_status why)
{
	fk *f = (fk *)ctx;

	if (slot >= f->n_slots || !f->slot[slot].used)
		return;
	f->n_close++;
	f->slot[slot].n_close++;
	f->slot[slot].close_why = why;
	f->slot[slot].closing = 1;
	f->slot[slot].conn.state = WRI_M2_CLOSING;
	if (!f->closing_holds_slot)
		f->slot[slot].used = 0;
}

static inline void fk_free_slot(fk *f, unsigned slot)
{
	f->slot[slot].used = 0;
}

static inline wr_status fk_send(void *ctx, uint16_t slot, const wri_m2_msg_out *m)
{
	fk *f = (fk *)ctx;

	if (f->send_st != WR_OK)
		return f->send_st;
	if (slot >= f->n_slots || !f->slot[slot].used)
		return WR_E_STATE;
	f->n_send++;
	if (f->n_sent < 16u) {
		fk_sent *s = &f->sent[f->n_sent++];

		s->slot = slot;
		s->m = *m;
		s->front_len = m->front_len < sizeof(s->front) ? m->front_len : (uint32_t)sizeof(s->front);
		if (m->front != NULL)
			memcpy(s->front, m->front, s->front_len);
		s->m.front = s->front;
	}
	return WR_OK;
}

static inline int fk_tx_idle(void *ctx, uint16_t slot)
{
	fk *f = (fk *)ctx;

	(void)slot;
	f->n_tx_idle_calls++;
	return f->tx_idle;
}

static inline uint64_t fk_features(void *ctx, uint16_t slot)
{
	fk *f = (fk *)ctx;

	(void)slot;
	return f->feat;
}

static inline int fk_have_ticket(void *ctx) { return ((fk *)ctx)->have_ticket; }
static inline int fk_handshake_free(void *ctx) { return ((fk *)ctx)->handshake_free; }

static inline wri_osd_link fk_link(fk *f)
{
	wri_osd_link l;

	memset(&l, 0, sizeof(l));
	l.ctx = f;
	l.open = fk_open;
	l.close = fk_close;
	l.send = fk_send;
	l.tx_idle = fk_tx_idle;
	l.features = f->features_hook ? fk_features : NULL;
	l.have_ticket = fk_have_ticket;
	l.handshake_free = fk_handshake_free;
	return l;
}

/* ---- the rig: a table over the scripted link ---------------------------------------------------------------------------- */

#define ALL_FEATURES 0x3f07fffffffdffffull /* what a v20.2.5 OSD and this client negotiate */

typedef struct osr {
	wri_ctx x;
	uint8_t *raw;
	size_t raw_bytes;
	wri_arena arena;
	wri_osd_sess_tab t;
	fk f;
	orec r;
} osr;

static inline void osr_cfg(wri_ctx *x, unsigned n_sess, unsigned front_cap, unsigned bo_slots)
{
	memset(x, 0, sizeof(*x));
	wr_config_profile_harness(&x->cfg);
	x->cfg.osd_sessions = (uint16_t)n_sess;
	x->cfg.osd_front_cap = (uint16_t)front_cap;
	x->cfg.backoff_slots = (uint16_t)bo_slots;
	x->cfg.osd_connect_timeout_ms = 2000;
	x->cfg.osd_idle_ms = 0;
}

/* The table needs `n_sess` sessions; the scripted engine has `n_sess + 2` connection slots. 0 = ok. */
static inline int osr_init(osr *o, unsigned n_sess, unsigned front_cap, unsigned bo_slots)
{
	size_t need = 0;
	wri_osd_link l;
	wri_osd_sess_up u;

	memset(o, 0, sizeof(*o));
	osr_cfg(&o->x, n_sess, front_cap, bo_slots);
	o->x.now.mono_ms = 100000;
	o->f.have_ticket = 1;
	o->f.handshake_free = 1;
	o->f.tx_idle = 1;
	o->f.n_slots = n_sess + 2u > FK_SLOTS ? FK_SLOTS : n_sess + 2u;
	o->f.feat = ALL_FEATURES;
	if (wri_osd_sess_mem(&o->x.cfg, &need) != WR_OK)
		return -1;
	o->raw_bytes = need + 128u;
	o->raw = (uint8_t *)calloc(1, o->raw_bytes);
	if (o->raw == NULL)
		return -1;
	wri_arena_init(&o->arena, (uint8_t *)(((uintptr_t)o->raw + 63u) & ~(uintptr_t)63u), need + 64u);
	l = fk_link(&o->f);
	u = orec_up(&o->r);
	if (wri_osd_sess_init(&o->t, &o->x, &o->arena, &l, &u) != WR_OK)
		return -1;
	return 0;
}

static inline void osr_free(osr *o)
{
	free(o->raw);
	o->raw = NULL;
}

static inline wr_addr osr_addr(unsigned n)
{
	wr_addr a;

	memset(&a, 0, sizeof(a));
	a.family = WR_AF_IPV4;
	a.ip[0] = 10, a.ip[1] = 77, a.ip[2] = 0, a.ip[3] = (uint8_t)(30u + n);
	a.port = (uint16_t)(6800u + n);
	a.nonce = 5000u + n;
	return a;
}

/* The scripted connection of session s reaches READY with the given feature word. */
static inline void osr_ready(osr *o, uint32_t s, uint64_t feats)
{
	const wri_osd_sess *p = wri_osd_sess_at(&o->t, s);
	uint16_t slot = p->conn_slot;

	o->f.feat = feats;
	o->f.slot[slot].conn.features = feats;
	o->f.slot[slot].conn.state = WRI_M2_READY;
	o->f.slot[slot].up->ready(o->f.slot[slot].up_ctx, &o->f.slot[slot].conn);
}

/* The engine reports the connection of session s lost (what the connection's closed callback carries). */
static inline void osr_closed(osr *o, uint32_t s, wr_status st)
{
	const wri_osd_sess *p = wri_osd_sess_at(&o->t, s);
	uint16_t slot = p->conn_slot;
	wr_errinfo e;

	memset(&e, 0, sizeof(e));
	e.status = st;
	e.module = WR_MOD_M2;
	e.what = "scripted loss";
	o->f.slot[slot].conn.state = WRI_M2_FAILED;
	o->f.slot[slot].up->closed(o->f.slot[slot].up_ctx, &o->f.slot[slot].conn, &e);
	o->f.slot[slot].used = 0;
}

static inline uint32_t osr_get(osr *o, int32_t osd, uint64_t feats_if_ready)
{
	wr_addr a = osr_addr((unsigned)osd);
	uint32_t s = WRI_NIL;

	if (wri_osd_sess_acquire(&o->t, osd, &a, &s) != WR_OK)
		return WRI_NIL;
	if (feats_if_ready != 0 && !wri_osd_sess_ready(&o->t, s))
		osr_ready(o, s, feats_if_ready);
	return s;
}

/* ---- frames an OSD sends ----------------------------------------------------------------------------------------------- */

typedef struct rframe {
	uint8_t b[4096];
	uint32_t n;
} rframe;

static inline void rf_u8(rframe *f, uint8_t v)
{
	uint32_t n = f->n < (uint32_t)sizeof(f->b) - 1u ? f->n : (uint32_t)sizeof(f->b) - 1u; /* a frame never gets this long: the last byte is reused */

	f->b[n] = v;
	if (f->n < (uint32_t)sizeof(f->b))
		f->n++;
}
static inline void rf_le(rframe *f, uint64_t v, unsigned bytes)
{
	unsigned i;

	for (i = 0; i < bytes; i++)
		rf_u8(f, (uint8_t)(v >> (8u * i)));
}
static inline void rf_zero(rframe *f, unsigned n) { while (n--) rf_u8(f, 0); }
static inline void rf_mem(rframe *f, const void *p, size_t n)
{
	const uint8_t *q = (const uint8_t *)p;

	while (n--)
		rf_u8(f, *q++);
}

/* A MOSDOpReply v8 front (osd-ops.md 2.9) echoing `n_ops` READ records with the given output lengths. */
static inline void rf_reply(rframe *f, const char *oid, uint32_t n_ops, const uint32_t *plen, int32_t result, int32_t retry)
{
	uint32_t i;

	f->n = 0;
	rf_le(f, strlen(oid), 4);
	rf_mem(f, oid, strlen(oid));
	rf_u8(f, 1);                 /* pg_t */
	rf_le(f, 2, 8);              /* pool 2 */
	rf_le(f, 3, 4);              /* seed 3 */
	rf_le(f, 0xFFFFFFFFu, 4);    /* preferred -1 */
	rf_le(f, 0x08400015u, 8);    /* flags */
	rf_le(f, (uint32_t)result, 4);
	rf_le(f, 7, 8);              /* bad_replay_version */
	rf_le(f, 9, 4);
	rf_le(f, 42, 4);             /* epoch */
	rf_le(f, n_ops, 4);
	for (i = 0; i < n_ops; i++) {
		rf_le(f, WRI_OSD_OP_READ, 2);
		rf_zero(f, 32);
		rf_le(f, plen != NULL ? plen[i] : 0u, 4);
	}
	rf_le(f, (uint32_t)retry, 4);
	for (i = 0; i < n_ops; i++)
		rf_le(f, 0, 4);          /* rval */
	rf_le(f, 11, 8);             /* replay_version */
	rf_le(f, 12, 4);
	rf_le(f, 99, 8);             /* user_version */
	rf_u8(f, 0);                 /* no redirect */
	rf_zero(f, 24);              /* trace */
}

/* A MOSDBackoff front: BLOCK / ACK_BLOCK / UNBLOCK of [begin, end) in pg (pool, seed), the shape the product's own encoder writes (it is
 * the encoder of the ACK_BLOCK: the op byte is patched, offset 28 = spg_t 24 + epoch 4). `m` is filled by the caller. */
static inline uint32_t rf_backoff(uint8_t *out, size_t cap, wri_mbackoff *m, uint8_t op)
{
	wri_wr w;

	wri_wr_init(&w, out, cap);
	m->op = WRI_BACKOFF_BLOCK;
	if (wri_mbackoff_encode_ack(&w, m) != WR_OK)
		return 0;
	out[28] = op;
	return (uint32_t)wri_wr_len(&w);
}

/* ---- handing a frame to the table the way the msgr2 parser does ----------------------------------------------------------- */

typedef struct fr_out {
	wr_status plan_st;     /* what plan() answered */
	uint32_t stored[3];
	wri_m2_sink sink[3];
} fr_out;

/*
 * One MESSAGE on session s: plan(), the bytes copied into the sinks (never beyond their cap, as the parser does), message(). A plan() that
 * fails fails the connection: the closed callback is called with that status, as wri_m2_conn does. WR_E_BUSY from plan() leaves the frame
 * undelivered (the caller retries). Returns plan()'s answer.
 */
static inline wr_status osr_frame(osr *o, uint32_t s, uint16_t type, uint64_t tid, uint16_t ver, uint16_t compat, const uint8_t *front,
				  uint32_t flen, const uint8_t *middle, uint32_t mlen, const uint8_t *data, uint32_t dlen, fr_out *out)
{
	const wri_osd_sess *p = wri_osd_sess_at(&o->t, s);
	uint16_t slot = p->conn_slot;
	wri_m2_conn *c = &o->f.slot[slot].conn;
	const wri_m2_upper *up = wri_osd_sess_upper();
	wri_m2_hdr2 h;
	uint32_t seglen[3], stored[3];
	wri_m2_sink sink[3];
	wr_status st;
	fr_out dummy;

	if (out == NULL)
		out = &dummy;
	memset(&h, 0, sizeof(h));
	h.seq = ++c->in_seq;
	h.tid = tid;
	h.type = type;
	h.priority = 127;
	h.version = ver;
	h.compat_version = compat;
	h.flags = 3;
	seglen[0] = flen, seglen[1] = mlen, seglen[2] = dlen;
	memset(sink, 0, sizeof(sink));
	st = up->plan(o->f.slot[slot].up_ctx, c, &h, seglen, sink);
	out->plan_st = st;
	out->sink[0] = sink[0], out->sink[1] = sink[1], out->sink[2] = sink[2];
	if (st == WR_E_BUSY) {
		c->in_seq--;
		return st;
	}
	if (st != WR_OK) {
		wr_errinfo e;

		memset(&e, 0, sizeof(e));
		e.status = st;
		e.module = WR_MOD_M2;
		e.what = "upper layer refused the message";
		c->state = WRI_M2_FAILED;
		up->closed(o->f.slot[slot].up_ctx, c, &e);
		o->f.slot[slot].used = 0;
		return st;
	}
	stored[0] = stored[1] = stored[2] = 0;
	if (sink[0].dst != NULL) {
		stored[0] = flen < sink[0].cap ? flen : sink[0].cap;
		if (stored[0] != 0)
			memcpy(sink[0].dst, front, stored[0]);
	}
	if (sink[1].dst != NULL) {
		stored[1] = mlen < sink[1].cap ? mlen : sink[1].cap;
		if (stored[1] != 0)
			memcpy(sink[1].dst, middle, stored[1]);
	}
	if (sink[2].dst != NULL) {
		stored[2] = dlen < sink[2].cap ? dlen : sink[2].cap;
		if (stored[2] != 0)
			memcpy(sink[2].dst, data, stored[2]);
	}
	out->stored[0] = stored[0], out->stored[1] = stored[1], out->stored[2] = stored[2];
	up->message(o->f.slot[slot].up_ctx, c, &h, stored);
	return WR_OK;
}

#endif /* OSD_SESS_RIG_H */
