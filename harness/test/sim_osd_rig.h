/* SPDX-License-Identifier: MIT */
/*
 * sim_osd_rig.h - the hand-driven test client of the sim_osd tests (test_sim_osd*.c), written from docs/spec/osd-ops.md 2.3 to 2.10 and
 * cephx.md 3.3 and sharing nothing with the product's client modules: its own MOSDOp v9 / v8 encoder, its own MOSDOpReply decoder, its own
 * authorizer builder for the OSD handshake (over the scripted client pieces of sim_m2_tc.h / sim_mon_tc.h), and a few op builders.
 * One `ore` is a cluster (monitor, store, OSD, the tickets a login on the monitor gave); one `orc` is one connection to an OSD of it. Everything
 * is static inline, so each test executable carries its own copy.
 */
#ifndef SIM_OSD_RIG_H
#define SIM_OSD_RIG_H

#include "sim_mon_tc.h"
#include "sim_osd.h"

#define OR_OSD_SLOT 2u
#define OR_MAXOPS 8u
#define OR_MAXSNAPS 160u
#define OR_POOL 2

/* ---- the cluster ------------------------------------------------------------------------------------------------------ */

typedef struct ore {
	sim_mon *mon;
	sim_store *store;
	sim_osd *osd;
	sim_osd_cfg cfg;
	mc login;               /* a login on the monitor that asked for the OSD ticket */
	wr_key okey;            /* the OSD session key */
	uint8_t blob[SIM_MON_BLOB_MAX];
	uint32_t blob_len;
	uint64_t secret_id, gid;
	wri_ctx x;
	uint64_t rng;
} ore;

static inline wr_status ore_random(void *ctx, uint8_t *out, size_t n)
{
	ore *e = (ore *)ctx;
	size_t i;

	for (i = 0; i < n; i++) {
		e->rng ^= e->rng >> 12;
		e->rng ^= e->rng << 25;
		e->rng ^= e->rng >> 27;
		out[i] = (uint8_t)((e->rng * 0x2545f4914f6cdd1dull) >> 56);
	}
	return WR_OK;
}

/* Monitor, store, a login that holds an OSD ticket, and the OSD configuration (e->cfg) to adjust before ore_start. */
static inline void ore_prep_gid(ore *e, unsigned key_type, uint64_t first_gid)
{
	sim_mon_cfg mc_cfg;

	memset(e, 0, sizeof(*e));
	e->rng = 0x0123456789abcdefull;
	e->x.host.size = (uint32_t)sizeof(e->x.host);
	e->x.host.ctx = e;
	e->x.host.random = ore_random;
	mt_cfg(&mc_cfg, key_type);
	if (first_gid != 0)
		mc_cfg.first_global_id = first_gid;
	e->mon = sim_mon_new(&mc_cfg);
	e->store = sim_store_new();
	if (e->mon == NULL || e->store == NULL || mc_init(&e->login, e->mon, &mc_cfg.key, "winrbd") != 0 || mc_login(&e->login, 0x24) != MC_OK) {
		fprintf(stderr, "ore_prep failed\n");
		abort();
	}
	e->okey = e->login.svc[OR_OSD_SLOT].key;
	memcpy(e->blob, e->login.svc[OR_OSD_SLOT].blob, e->login.svc[OR_OSD_SLOT].blob_len);
	e->blob_len = e->login.svc[OR_OSD_SLOT].blob_len;
	e->secret_id = e->login.svc[OR_OSD_SLOT].secret_id;
	e->gid = e->login.gid;
	sim_osd_cfg_default(&e->cfg);
	e->cfg.mon = e->mon;
	e->cfg.store = e->store;
	e->cfg.id = 0;
	e->cfg.seed = 7;
}

static inline void ore_prep(ore *e, unsigned key_type) { ore_prep_gid(e, key_type, 0); }

static inline void ore_start(ore *e)
{
	e->osd = sim_osd_new(&e->cfg);
	if (e->osd == NULL) {
		fprintf(stderr, "sim_osd_new failed\n");
		abort();
	}
}

static inline void ore_free(ore *e)
{
	sim_osd_free(e->osd);
	mc_free(&e->login);
	sim_mon_free(e->mon);
	sim_store_free(e->store);
}

/* ---- operations --------------------------------------------------------------------------------------------------------- */

typedef struct or_op {
	uint8_t rec[38];
	uint8_t pay[600];
	uint32_t pay_len;
	const uint8_t *ext; /* the input bytes when they are not in pay (a data write) */
} or_op;

static inline const uint8_t *or_op_in(const or_op *o) { return o->ext != NULL ? o->ext : o->pay; }

static inline void or_op_init(or_op *o, uint16_t code, uint32_t flags)
{
	memset(o, 0, sizeof(*o));
	wri_le16_put(o->rec, code);
	wri_le32_put(o->rec + 2, flags);
}

static inline void or_op_extent(or_op *o, uint64_t off, uint64_t len)
{
	wri_le64_put(o->rec + 6, off);
	wri_le64_put(o->rec + 14, len);
}

static inline void or_op_setpay(or_op *o, const void *p, uint32_t n)
{
	if (n > sizeof(o->pay)) {
		fprintf(stderr, "or_op payload too big\n");
		abort();
	}
	memcpy(o->pay, p, n);
	o->pay_len = n;
	wri_le32_put(o->rec + 34, n);
}

static inline or_op or_read(uint64_t off, uint64_t len)
{
	or_op o;
	or_op_init(&o, 0x1201, 0);
	or_op_extent(&o, off, len);
	return o;
}

static inline or_op or_sparse(uint64_t off, uint64_t len)
{
	or_op o;
	or_op_init(&o, 0x1205, 0);
	or_op_extent(&o, off, len);
	return o;
}

static inline or_op or_stat(void)
{
	or_op o;
	or_op_init(&o, 0x1202, 0);
	return o;
}

static inline or_op or_write(uint64_t off, const void *data, uint32_t n)
{
	or_op o;
	or_op_init(&o, 0x2201, 0);
	or_op_extent(&o, off, n);
	o.ext = (const uint8_t *)data;
	o.pay_len = n;
	wri_le32_put(o.rec + 34, n);
	return o;
}

static inline or_op or_writefull(const void *data, uint32_t n)
{
	or_op o = or_write(0, data, n);
	wri_le16_put(o.rec, 0x2202);
	return o;
}

static inline or_op or_zero(uint64_t off, uint64_t len)
{
	or_op o;
	or_op_init(&o, 0x2204, 0);
	or_op_extent(&o, off, len);
	return o;
}

static inline or_op or_truncate(uint64_t off)
{
	or_op o;
	or_op_init(&o, 0x2203, 0);
	or_op_extent(&o, off, 0);
	return o;
}

static inline or_op or_delete(void)
{
	or_op o;
	or_op_init(&o, 0x2205, 0);
	return o;
}

static inline or_op or_create(int excl)
{
	or_op o;
	or_op_init(&o, 0x220d, excl ? 1u : 0u);
	return o;
}

static inline or_op or_allochint(void)
{
	or_op o;
	or_op_init(&o, 0x2223, 2); /* FAILOK, as librbd sends it */
	wri_le64_put(o.rec + 6, 4194304);
	wri_le64_put(o.rec + 14, 4194304);
	return o;
}

static inline or_op or_getxattr(const char *name)
{
	or_op o;
	or_op_init(&o, 0x1301, 0);
	wri_le32_put(o.rec + 6, (uint32_t)strlen(name));
	or_op_setpay(&o, name, (uint32_t)strlen(name));
	return o;
}

static inline or_op or_omap_vals(const char *after, uint64_t max, const char *prefix)
{
	or_op o;
	tb t;

	or_op_init(&o, 0x1212, 0);
	t.n = 0;
	tb_u32(&t, (uint32_t)strlen(after));
	tb_bytes(&t, after, strlen(after));
	tb_u64(&t, max);
	tb_u32(&t, (uint32_t)strlen(prefix));
	tb_bytes(&t, prefix, strlen(prefix));
	or_op_extent(&o, 0, t.n); /* as the stock client does: length = input length */
	or_op_setpay(&o, t.b, (uint32_t)t.n);
	return o;
}

static inline or_op or_omap_keys(const char *after, uint64_t max)
{
	or_op o;
	tb t;

	or_op_init(&o, 0x1211, 0);
	t.n = 0;
	tb_u32(&t, (uint32_t)strlen(after));
	tb_bytes(&t, after, strlen(after));
	tb_u64(&t, max);
	or_op_extent(&o, 0, t.n);
	or_op_setpay(&o, t.b, (uint32_t)t.n);
	return o;
}

static inline or_op or_omap_bykeys(const char *const *keys, uint32_t n)
{
	or_op o;
	tb t;
	uint32_t i;

	or_op_init(&o, 0x1214, 0);
	t.n = 0;
	tb_u32(&t, n);
	for (i = 0; i < n; i++) {
		tb_u32(&t, (uint32_t)strlen(keys[i]));
		tb_bytes(&t, keys[i], strlen(keys[i]));
	}
	or_op_extent(&o, 0, t.n);
	or_op_setpay(&o, t.b, (uint32_t)t.n);
	return o;
}

static inline or_op or_call(const char *cls, const char *method, const void *in, uint32_t n)
{
	or_op o;
	uint8_t buf[600];
	size_t cl = strlen(cls), ml = strlen(method);

	or_op_init(&o, 0x1401, 0);
	o.rec[6] = (uint8_t)cl;
	o.rec[7] = (uint8_t)ml;
	wri_le32_put(o.rec + 9, n);
	memcpy(buf, cls, cl);
	memcpy(buf + cl, method, ml);
	if (n != 0)
		memcpy(buf + cl + ml, in, n);
	or_op_setpay(&o, buf, (uint32_t)(cl + ml + n));
	return o;
}

/* ---- the request --------------------------------------------------------------------------------------------------------- */

typedef struct or_req {
	int64_t pool;
	const char *oid;
	uint32_t oid_len;       /* 0 = strlen(oid) */
	const char *nspace;
	uint32_t hash, epoch, flags, mtime_s;
	uint64_t snapid, snap_seq;
	uint64_t snaps[OR_MAXSNAPS];
	uint32_t n_snaps;
	int32_t retry;
	or_op ops[OR_MAXOPS];
	uint32_t n_ops;
	uint8_t reqid_inc_bad;  /* reqid.inc != client_inc (a request the real OSD would assert on) */
	uint8_t no_otel;        /* encode as v8 whatever the connection says */
} or_req;

static inline void or_req_init(or_req *r, int64_t pool, const char *oid)
{
	memset(r, 0, sizeof(*r));
	r->pool = pool;
	r->oid = oid;
	r->epoch = 42;
	r->snapid = 0xfffffffffffffffeull;
	r->hash = 0x12345678u;
}

static inline or_req *or_req_add(or_req *r, or_op op)
{
	r->ops[r->n_ops++] = op;
	return r;
}

static inline int or_code_writes(uint16_t c)
{
	return c == 0x2201 || c == 0x2202 || c == 0x2203 || c == 0x2204 || c == 0x2205 || c == 0x220d || c == 0x2223;
}

/* The flag word librbd would send: READ or WRITE by the ops (class methods: the caller sets `flags`), ONDISK, KNOWN_REDIR, SUPPORTSPOOLEIO. */
static inline uint32_t or_default_flags(const or_req *r)
{
	uint32_t i;

	for (i = 0; i < r->n_ops; i++)
		if (or_code_writes(wri_le16_get(r->ops[i].rec)))
			return r->retry != 0 ? 0x0840002cu : 0x08400024u;
	return r->retry != 0 ? 0x0840001cu : 0x08400014u;
}

/* Encode the front of MOSDOp v9 / v8 (osd-ops.md 2.3) and concatenate the input data; returns the front length. */
static inline uint32_t or_encode(const or_req *r, uint8_t version, uint8_t *front, size_t fcap, uint8_t *data, size_t dcap, uint32_t *dlen)
{
	wri_wr w;
	uint32_t i, oid_len = r->oid_len != 0 ? r->oid_len : (uint32_t)strlen(r->oid), ns_len = r->nspace != NULL ? (uint32_t)strlen(r->nspace) : 0u;
	uint32_t flags = r->flags != 0 ? r->flags : or_default_flags(r), seed = r->hash % 32u;
	size_t m;
	uint32_t dl = 0;

	wri_wr_init(&w, front, fcap);
	wri_wr_u8(&w, 1); /* spg_t */
	wri_wr_u8(&w, 1);
	wri_wr_u32(&w, 18);
	wri_wr_u8(&w, 1);
	wri_wr_u64(&w, (uint64_t)r->pool);
	wri_wr_u32(&w, seed);
	wri_wr_i32(&w, -1);
	wri_wr_u8(&w, 0xff);
	wri_wr_u32(&w, r->hash);
	wri_wr_u32(&w, r->epoch);
	wri_wr_u32(&w, flags);
	wri_wr_u8(&w, 2); /* reqid: v2 compat 2, name (0, 0), tid 0, inc */
	wri_wr_u8(&w, 2);
	wri_wr_u32(&w, 21);
	wri_wr_u8(&w, 0);
	wri_wr_i64(&w, 0);
	wri_wr_u64(&w, 0);
	wri_wr_i32(&w, r->reqid_inc_bad ? 5 : 0);
	wri_wr_zero(&w, 24); /* blkin */
	if (version == 9u) { /* otel */
		wri_wr_u8(&w, 1);
		wri_wr_u8(&w, 1);
		wri_wr_u32(&w, 1);
		wri_wr_u8(&w, 0);
	}
	wri_wr_u32(&w, 0); /* client_inc */
	wri_wr_u32(&w, r->mtime_s);
	wri_wr_u32(&w, 0);
	wri_wr_u8(&w, 6); /* object_locator_t v6 compat 3 */
	wri_wr_u8(&w, 3);
	m = wri_wr_len(&w);
	wri_wr_u32(&w, 0);
	wri_wr_i64(&w, r->pool);
	wri_wr_i32(&w, -1);
	wri_wr_u32(&w, 0); /* key */
	wri_wr_u32(&w, ns_len);
	if (ns_len != 0)
		wri_wr_bytes(&w, (const uint8_t *)r->nspace, ns_len);
	wri_wr_i64(&w, -1);
	wri_wr_patch_u32(&w, m, (uint32_t)(wri_wr_len(&w) - m - 4u));
	wri_wr_u32(&w, oid_len);
	wri_wr_bytes(&w, (const uint8_t *)r->oid, oid_len);
	wri_wr_u16(&w, (uint16_t)r->n_ops);
	for (i = 0; i < r->n_ops; i++)
		wri_wr_bytes(&w, r->ops[i].rec, 38);
	wri_wr_u64(&w, r->snapid);
	wri_wr_u64(&w, r->snap_seq);
	wri_wr_u32(&w, r->n_snaps);
	for (i = 0; i < r->n_snaps; i++)
		wri_wr_u64(&w, r->snaps[i]);
	wri_wr_i32(&w, r->retry);
	wri_wr_u64(&w, 0x3f07fffffffdffffull);
	if (!wri_wr_ok(&w)) {
		fprintf(stderr, "or_encode overflow\n");
		abort();
	}
	for (i = 0; i < r->n_ops; i++) {
		if (dl + r->ops[i].pay_len > dcap) {
			fprintf(stderr, "or_encode data overflow\n");
			abort();
		}
		memcpy(data + dl, or_op_in(&r->ops[i]), r->ops[i].pay_len);
		dl += r->ops[i].pay_len;
	}
	*dlen = dl;
	return (uint32_t)wri_wr_len(&w);
}

/* ---- the reply ----------------------------------------------------------------------------------------------------------- */

typedef struct or_reply {
	int ok;                 /* the front decoded exactly */
	uint64_t tid, seq;
	uint16_t version, compat, priority;
	char oid[80];
	int64_t pool;
	uint32_t seed;
	int64_t flags;
	int32_t result;
	uint64_t bad_ver;
	uint32_t bad_epoch, epoch, n_ops;
	uint16_t code[32];
	uint32_t payload_len[32];
	uint8_t rec[32][38];
	int32_t rval[32];
	int32_t retry;
	uint64_t replay_ver, user_version;
	uint32_t replay_epoch;
	uint8_t do_redirect;
	int64_t redirect_pool;
	const uint8_t *data;    /* the data segment (owned by the message list) */
	uint32_t dlen;
	uint32_t sum_payload;   /* of the op records */
	const uint8_t *out[32]; /* each op's output inside data (NULL when outside) */
} or_reply;

typedef struct or_msg {
	uint16_t type, version, compat, priority;
	uint64_t tid, seq;
	uint8_t *front, *data;
	uint32_t flen, dlen;
	uint8_t nseg;
} or_msg;

static inline int or_decode_reply(const or_msg *m, or_reply *r)
{
	wri_rd rd;
	uint32_t i, ol, off = 0;
	const uint8_t *p;

	memset(r, 0, sizeof(*r));
	r->tid = m->tid;
	r->version = m->version;
	r->compat = m->compat;
	r->priority = m->priority;
	wri_rd_init(&rd, m->front, m->flen);
	p = wri_denc_blob(&rd, &ol, 4096);
	if (p != NULL)
		memcpy(r->oid, p, ol < sizeof(r->oid) - 1u ? ol : sizeof(r->oid) - 1u);
	if (wri_rd_u8(&rd) != 1u)
		return 0;
	r->pool = (int64_t)wri_rd_u64(&rd);
	r->seed = wri_rd_u32(&rd);
	(void)wri_rd_i32(&rd);
	r->flags = wri_rd_i64(&rd);
	r->result = wri_rd_i32(&rd);
	r->bad_ver = wri_rd_u64(&rd);
	r->bad_epoch = wri_rd_u32(&rd);
	r->epoch = wri_rd_u32(&rd);
	r->n_ops = wri_rd_u32(&rd);
	if (r->n_ops > 32u)
		return 0;
	for (i = 0; i < r->n_ops; i++) {
		const uint8_t *q = wri_rd_bytes(&rd, 38);

		if (q == NULL)
			return 0;
		memcpy(r->rec[i], q, 38);
		r->code[i] = wri_le16_get(q);
		r->payload_len[i] = wri_le32_get(q + 34);
		r->sum_payload += r->payload_len[i];
	}
	r->retry = wri_rd_i32(&rd);
	for (i = 0; i < r->n_ops; i++)
		r->rval[i] = wri_rd_i32(&rd);
	r->replay_ver = wri_rd_u64(&rd);
	r->replay_epoch = wri_rd_u32(&rd);
	r->user_version = wri_rd_u64(&rd);
	r->do_redirect = wri_rd_u8(&rd);
	if (r->do_redirect) {
		wri_env e, o;

		if (wri_env_open(&rd, 1, &e) != WR_OK || wri_env_open(&e.body, 6, &o) != WR_OK)
			return 0;
		r->redirect_pool = wri_rd_i64(&o.body);
	}
	wri_rd_skip(&rd, 24);
	if (!wri_rd_ok(&rd) || wri_rd_left(&rd) != 0)
		return 0;
	r->data = m->data;
	r->dlen = m->dlen;
	for (i = 0; i < r->n_ops; i++) {
		r->out[i] = m->data != NULL && off + r->payload_len[i] <= m->dlen ? m->data + off : NULL;
		off += r->payload_len[i];
	}
	r->ok = 1;
	return 1;
}

/* ---- one connection ------------------------------------------------------------------------------------------------------ */

enum { /* orc_open outcomes */
	OR_OK = 1,
	OR_BAD_METHOD,  /* AUTH_BAD_METHOD (c->bm) */
	OR_CLOSED,      /* the connection ended without the frame the step needs */
	OR_ERR          /* a reply that does not parse (c->err) */
};

enum { /* what the client does wrong in orc_open */
	OR_T_NONE = 0,
	OR_T_FOREIGN_TICKET,    /* one byte of the ticket blob changed */
	OR_T_WRONG_GID,         /* an authorizer for another global id */
	OR_T_WRONG_PLUS_ONE,    /* the challenge answered wrongly */
	OR_T_NO_CHALLENGE_STEP, /* the first authorizer already claims to answer a challenge */
	OR_T_METHOD,            /* method 1 instead of cephx */
	OR_T_WRONG_KEY,         /* the proof sealed with a key that is not the ticket's */
	OR_T_CHANGED_NONCE      /* the second authorizer carries another nonce */
};

typedef struct orc {
	ore *e;
	sim_osd *osd;
	sim_osd_conn *conn;
	tc t;
	uint64_t seq, next_tid;
	uint8_t version;        /* MOSDOp version this client sends (9, or 8 against an OSD without SERVER_SQUID) */
	uint64_t srv_supported; /* SERVER_IDENT supported */
	uint64_t nonce, challenge;
	unsigned tamper;
	wri_m2_bad_method bm;
	wr_status err;
	int sig_ok, ready;
	or_msg *msg;            /* every MESSAGE received so far */
	uint32_t n_msg, cap_msg;
	uint32_t n_ctl;         /* control frames dropped by orc_pull */
	uint8_t ident_ip[4];    /* the address CLIENT_IDENT tells the OSD (default 10.77.0.20) */
	uint32_t ident_nonce;   /* and its nonce (default 0x1234) */
	or_reply last;
} orc;

static inline void orc_clear_frames(orc *c)
{
	size_t i, j;

	for (i = 0; i < c->t.nfr; i++)
		for (j = 0; j < 4; j++) {
			free(c->t.fr[i].seg[j]);
			c->t.fr[i].seg[j] = NULL;
		}
	c->t.nfr = 0;
}

/* Reads what the OSD has for us; MESSAGE frames become entries of c->msg, the other frames are counted and dropped. */
static inline void orc_pull(orc *c)
{
	size_t i;

	tc_pull(&c->t, sim_osd_conn_m2(c->conn));
	for (i = 0; i < c->t.nfr; i++) {
		tc_frame *f = &c->t.fr[i];
		or_msg *m;

		if (f->tag != WRI_M2_TAG_MESSAGE || f->len[0] < 41u) {
			c->n_ctl++;
			continue;
		}
		if (c->n_msg == c->cap_msg) {
			c->cap_msg = c->cap_msg != 0 ? c->cap_msg * 2u : 32u;
			c->msg = (or_msg *)realloc(c->msg, (size_t)c->cap_msg * sizeof(*c->msg));
		}
		m = &c->msg[c->n_msg++];
		memset(m, 0, sizeof(*m));
		m->seq = wri_le64_get(f->seg[0]);
		m->tid = wri_le64_get(f->seg[0] + 8);
		m->type = wri_le16_get(f->seg[0] + 16);
		m->priority = wri_le16_get(f->seg[0] + 18);
		m->version = wri_le16_get(f->seg[0] + 20);
		m->compat = wri_le16_get(f->seg[0] + 37);
		m->nseg = f->nseg;
		m->front = f->seg[1];
		m->flen = f->nseg > 1 ? f->len[1] : 0;
		m->data = f->seg[3];
		m->dlen = f->nseg > 3 ? f->len[3] : 0;
		f->seg[1] = f->seg[3] = NULL; /* the message owns them now */
	}
	orc_clear_frames(c);
}

/* the biggest segment the client side takes (a test that sends only small messages lowers it to make connections cheap) */
static uint32_t or_client_seg_cap = 5u << 20;

static inline void orc_init(orc *c, ore *e, sim_osd *osd)
{
	memset(c, 0, sizeof(*c));
	c->e = e;
	c->osd = osd;
	c->conn = sim_osd_accept(osd);
	if (c->conn == NULL) {
		fprintf(stderr, "sim_osd_accept failed\n");
		abort();
	}
	tc_init(&c->t, or_client_seg_cap); /* the default holds a 4 MiB object read in one segment */
	free(c->t.sent);
	c->t.sent = (uint8_t *)malloc(or_client_seg_cap); /* only the handshake needs the log of what was sent (orc_send_raw restarts it); one message must fit */
	c->next_tid = 1;
	c->version = 9;
	memcpy(c->ident_ip, TC_CLIENT_IP, 4);
	c->ident_nonce = 0x1234;
	c->nonce = 0x1111222233334444ull;
}

static inline void orc_free(orc *c)
{
	uint32_t i;

	for (i = 0; i < c->n_msg; i++) {
		free(c->msg[i].front);
		free(c->msg[i].data);
	}
	free(c->msg);
	tc_free(&c->t);
	sim_osd_conn_free(c->conn);
}

/* The authorizer (cephx.md 2.7): v 1, global id, service 4, the ticket blob, the proof sealed under the ticket's session key. */
static inline size_t or_authorizer(orc *c, uint8_t *out, size_t cap, int have_chal, uint64_t plus_one, uint64_t nonce)
{
	ore *e = c->e;
	wri_wr w;
	uint8_t item[18], ct[256], blob[SIM_MON_BLOB_MAX];
	size_t n = 0;
	wr_key k = e->okey;

	memcpy(blob, e->blob, e->blob_len);
	if (c->tamper == OR_T_FOREIGN_TICKET)
		blob[5] ^= 0x40;
	if (c->tamper == OR_T_WRONG_KEY)
		k.secret[0] ^= 0x55;
	item[0] = 2;
	wri_le64_put(item + 1, nonce);
	item[9] = (uint8_t)(have_chal ? 1 : 0);
	wri_le64_put(item + 10, plus_one);
	if (wri_cx_seal(&e->x, &k, WRI_CX_USAGE_AUTHORIZE, item, sizeof(item), ct, sizeof(ct), &n) != WR_OK)
		abort();
	wri_wr_init(&w, out, cap);
	wri_wr_u8(&w, 1);
	wri_wr_u64(&w, c->tamper == OR_T_WRONG_GID ? e->gid + 1u : e->gid);
	wri_wr_u32(&w, 4);
	wri_wr_u8(&w, 1);
	wri_wr_u64(&w, e->secret_id);
	wri_wr_u32(&w, e->blob_len);
	wri_wr_bytes(&w, blob, e->blob_len);
	wri_wr_u32(&w, (uint32_t)n);
	wri_wr_bytes(&w, ct, n);
	wri_secure_zero(&k, sizeof(k));
	return wri_wr_len(&w);
}

static inline int or_bad_method(orc *c, const tc_frame *f)
{
	wri_rd r;

	wri_rd_init(&r, f->seg[0], f->len[0]);
	c->err = wri_m2_bad_method_decode(&r, &c->bm);
	return c->err == WR_OK ? OR_BAD_METHOD : OR_ERR;
}

/* Banner, HELLO, the authorizer round trip, both AUTH_SIGNATUREs and the session handshake (cephx.md 3.3). `upto_challenge` stops at the server's
 * challenge. */
static inline int orc_open_ex(orc *c, int upto_challenge)
{
	sim_m2 *s = sim_osd_conn_m2(c->conn);
	ore *e = c->e;
	tc *t = &c->t;
	tb p;
	size_t before, sent_before;
	const tc_frame *f;
	uint8_t az[1500], sig[32], plain[256];
	size_t aln;
	const uint8_t *item = NULL;
	size_t ilen = 0;
	uint32_t blen;
	wri_rd r;

	tc_pull(t, s);
	if (!t->got_banner)
		return OR_CLOSED;
	(void)tc_send_banner(t, s, 1, 0);
	tc_pay_hello(&p, SIM_M2_ENT_CLIENT, 6800);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_HELLO, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (before == t->nfr || t->fr[before].tag != WRI_M2_TAG_HELLO)
		return OR_CLOSED;
	if (c->tamper == OR_T_NO_CHALLENGE_STEP)
		aln = or_authorizer(c, az, sizeof(az), 1, c->challenge + 1u, c->nonce);
	else
		aln = or_authorizer(c, az, sizeof(az), 0, 0, c->nonce);
	p.n = 0;
	tb_u32(&p, c->tamper == OR_T_METHOD ? 1u : 2u);
	tb_u32(&p, 1);
	tb_u32(&p, 1);
	tb_u32(&p, (uint32_t)aln);
	tb_bytes(&p, az, aln);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_AUTH_REQUEST, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (t->nfr == before)
		return OR_CLOSED;
	f = &t->fr[before];
	if (f->tag == WRI_M2_TAG_AUTH_BAD_METHOD)
		return or_bad_method(c, f);
	if (f->tag != WRI_M2_TAG_AUTH_REPLY_MORE)
		return OR_ERR;
	/* the challenge: the raw sealed envelope behind the u32 length of the frame (no length prefix of its own) */
	wri_rd_init(&r, f->seg[0], f->len[0]);
	blen = wri_rd_u32(&r);
	if (!wri_rd_ok(&r) || blen != f->len[0] - 4u)
		return OR_ERR;
	c->err = wri_cx_open(&e->x, &e->okey, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, f->seg[0] + 4, blen, plain, sizeof(plain), &item, &ilen);
	if (c->err != WR_OK || ilen < 9u)
		return OR_ERR;
	c->challenge = wri_le64_get(item + 1);
	if (upto_challenge)
		return OR_OK;
	aln = or_authorizer(c, az, sizeof(az), 1, c->tamper == OR_T_WRONG_PLUS_ONE ? c->challenge + 2u : c->challenge + 1u,
			    c->tamper == OR_T_CHANGED_NONCE ? c->nonce + 1u : c->nonce);
	p.n = 0;
	tb_u32(&p, (uint32_t)aln);
	tb_bytes(&p, az, aln);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_AUTH_REQUEST_MORE, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (t->nfr == before)
		return OR_CLOSED;
	f = &t->fr[before];
	if (f->tag == WRI_M2_TAG_AUTH_BAD_METHOD)
		return or_bad_method(c, f);
	if (f->tag != WRI_M2_TAG_AUTH_DONE || f->len[0] < 16u)
		return OR_ERR;
	if (wri_le64_get(f->seg[0]) != e->gid || wri_le32_get(f->seg[0] + 8) != 1u) /* the OSD echoes our global id, crc mode */
		return OR_ERR;
	blen = wri_le32_get(f->seg[0] + 12);
	if (blen != f->len[0] - 16u || blen < 4u || wri_le32_get(f->seg[0] + 16) != blen - 4u)
		return OR_ERR;
	c->err = wri_cx_open(&e->x, &e->okey, WRI_CX_USAGE_AUTHORIZE_REPLY, f->seg[0] + 20, blen - 4u, plain, sizeof(plain), &item, &ilen);
	if (c->err != WR_OK || ilen != 9u || item[0] != 1u || wri_le64_get(item + 1) != c->nonce + 1u) /* nonce + 1, no connection secret in crc mode */
		return OR_ERR;
	/* AUTH_SIGNATURE under the OSD session key */
	tc_hmac(e->okey.secret, e->okey.len, t->log, t->log_len, sig);
	sent_before = t->sent_len;
	p.n = 0;
	tb_bytes(&p, sig, 32);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
	before = t->nfr;
	tc_pull(t, s);
	f = NULL;
	{
		size_t i;

		for (i = before; i < t->nfr; i++)
			if (t->fr[i].tag == WRI_M2_TAG_AUTH_SIGNATURE)
				f = &t->fr[i];
	}
	if (f == NULL || f->len[0] != 32u)
		return OR_CLOSED;
	tc_hmac(e->okey.secret, e->okey.len, t->sent, sent_before, sig);
	c->sig_ok = memcmp(sig, f->seg[0], 32) == 0;
	if (!c->sig_ok)
		return OR_ERR;
	{ /* CLIENT_IDENT as tc_pay_ident builds it, with the address of this client */
		uint8_t me[SIM_M2_ADDR4_LEN], target[SIM_M2_ADDR4_LEN];

		p.n = 0;
		sim_m2_put_addr4(me, 3, c->ident_nonce, c->ident_ip, 0);
		sim_m2_put_addr4(target, 2, 0, TC_SERVER_IP, 6800);
		tb_u8(&p, 2);
		tb_u32(&p, 1);
		tb_bytes(&p, me, sizeof(me));
		tb_bytes(&p, target, sizeof(target));
		tb_u64(&p, e->gid);
		tb_u64(&p, 1);
		tb_u64(&p, 0x3f07fffffffdffffull);
		tb_u64(&p, 0x0800000000000000ull);
		tb_u64(&p, 1);
		tb_u64(&p, 0);
	}
	(void)tc_send_ctl(t, s, WRI_M2_TAG_CLIENT_IDENT, &p);
	before = t->nfr;
	tc_pull(t, s);
	f = NULL;
	{
		size_t i;

		for (i = before; i < t->nfr; i++)
			if (t->fr[i].tag == WRI_M2_TAG_SERVER_IDENT)
				f = &t->fr[i];
	}
	if (f == NULL || f->len[0] < 5u + 70u + 8u * 6u)
		return OR_CLOSED;
	/* SERVER_IDENT: addrvec (u8 2, u32 n, n x 35), gid, global_seq, supported, required, flags, cookie */
	c->srv_supported = wri_le64_get(f->seg[0] + 5u + 35u * wri_le32_get(f->seg[0] + 1) + 16u);
	c->version = ((c->srv_supported >> 49) & 1u) != 0 ? 9u : 8u; /* SERVER_SQUID: bit 49 with the incarnation bit 57 */
	c->ready = 1;
	orc_clear_frames(c);
	return OR_OK;
}

static inline int orc_open(orc *c) { return orc_open_ex(c, 0); }

/* A cluster with one OSD and one ready connection. */
static inline void orc_up(orc *c, ore *e)
{
	orc_init(c, e, e->osd);
	if (orc_open(c) != OR_OK) {
		fprintf(stderr, "orc_up: handshake failed\n");
		abort();
	}
}

/* ---- sending and answers -------------------------------------------------------------------------------------------------- */

/* MESSAGE with a proper header (type, version, compat 3) at the next sequence number; seq_override != 0 sends that number instead. */
static inline void orc_send_raw(orc *c, uint16_t type, uint16_t version, uint16_t compat, uint64_t tid, const uint8_t *front, uint32_t flen,
				const uint8_t *mid, uint32_t mlen, const uint8_t *data, uint32_t dlen, uint64_t seq_override)
{
	uint8_t h[SIM_M2_HDR2_LEN];
	wri_m2_seg_src seg[4];
	unsigned nseg = dlen != 0 ? 4u : mlen != 0 ? 3u : flen != 0 ? 2u : 1u;
	uint64_t seq = seq_override != 0 ? seq_override : ++c->seq;

	c->t.sent_len = 0; /* the log of sent bytes is for the signature of the handshake only */
	tc_pay_hdr2(h, seq, tid, type, 0);
	wri_le16_put(h + 18, 63);
	wri_le16_put(h + 20, version);
	wri_le16_put(h + 37, compat);
	seg[0].p = h, seg[0].len = sizeof(h);
	seg[1].p = front, seg[1].len = flen;
	seg[2].p = mid, seg[2].len = mlen;
	seg[3].p = data, seg[3].len = dlen;
	seg[0].ref = seg[1].ref = seg[2].ref = seg[3].ref = 0;
	(void)tc_send(&c->t, sim_osd_conn_m2(c->conn), WRI_M2_TAG_MESSAGE, seg, nseg);
}

/* Sends the request with the given tid (0 = the next one); returns the tid. */
static inline uint64_t orc_send(orc *c, const or_req *r, uint64_t tid)
{
	size_t need = 16, i;
	uint8_t *front = (uint8_t *)malloc(16384), *data;
	uint32_t dlen = 0, flen;
	uint8_t v = r->no_otel ? 8u : c->version;

	for (i = 0; i < r->n_ops; i++)
		need += r->ops[i].pay_len;
	data = (uint8_t *)malloc(need);
	if (tid == 0)
		tid = c->next_tid++;
	flen = or_encode(r, v, front, 16384, data, need, &dlen);
	orc_send_raw(c, 42, v, 3, tid, front, flen, NULL, 0, data, dlen, 0);
	free(front);
	free(data);
	return tid;
}

static inline const or_msg *orc_find(const orc *c, uint64_t tid, uint16_t type)
{
	uint32_t i;

	for (i = 0; i < c->n_msg; i++)
		if (c->msg[i].tid == tid && c->msg[i].type == type)
			return &c->msg[i];
	return NULL;
}

/* The decoded reply of `tid`, or NULL when there is none (c->last holds it until the next call). */
static inline const or_reply *orc_reply(orc *c, uint64_t tid)
{
	const or_msg *m;

	orc_pull(c);
	m = orc_find(c, tid, 43);
	if (m == NULL)
		return NULL;
	if (!or_decode_reply(m, &c->last)) {
		memset(&c->last, 0, sizeof(c->last));
		c->last.tid = tid;
	}
	return &c->last;
}

static inline const or_reply *orc_call(orc *c, const or_req *r)
{
	uint64_t tid = orc_send(c, r, 0);

	return orc_reply(c, tid);
}

/* Number of MESSAGEs of this type received. */
static inline uint32_t orc_count(const orc *c, uint16_t type)
{
	uint32_t i, n = 0;

	for (i = 0; i < c->n_msg; i++)
		n += c->msg[i].type == type;
	return n;
}

/* Drops the messages received so far (the frames are gone already). */
static inline void orc_forget(orc *c)
{
	uint32_t i;

	for (i = 0; i < c->n_msg; i++) {
		free(c->msg[i].front);
		free(c->msg[i].data);
	}
	c->n_msg = 0;
}

/* ---- short cuts for the tests --------------------------------------------------------------------------------------------- */

static inline or_req or_one(const char *oid, or_op op)
{
	or_req r;

	or_req_init(&r, OR_POOL, oid);
	or_req_add(&r, op);
	return r;
}

/* result, or INT32_MIN when no reply came */
static inline int32_t orc_result(orc *c, const or_req *r)
{
	const or_reply *p = orc_call(c, r);

	return p != NULL && p->ok ? p->result : INT32_MIN;
}

#endif /* SIM_OSD_RIG_H */
