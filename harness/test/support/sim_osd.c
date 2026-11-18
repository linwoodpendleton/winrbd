/* SPDX-License-Identifier: MIT */
/*
 * sim_osd.c - the fake OSD of the harness (see sim_osd.h): configuration, lifecycle, the connection table, sending with the OSD's header
 * conventions, held replies, restarts, the scripted server-initiated messages (MOSDBackoff, MOSDMap) and the recorded operations. The cephx
 * server side is in sim_osd_auth.c, the MOSDOp decoder / executor / reply encoder in sim_osd_ops.c, the object classes and the RBD fixtures in
 * sim_osd_cls.c and the shared store in sim_osd_store.c. Test code: libc allowed.
 */
#include "sim_osd_int.h"

/* ---- configuration ------------------------------------------------------------------------------------------------------- */

void sim_osd_cfg_default(sim_osd_cfg *c)
{
	memset(c, 0, sizeof(*c));
	sim_m2_cfg_default(&c->m2);
	c->m2.entity_type = SIM_M2_ENT_OSD;
	c->m2.preauth_cap = 64u << 10;  /* an OSD handshake is a few hundred bytes */
	c->m2.seg_cap = 8u << 20;       /* the biggest data segment of one message a test sends or reads: 4 MiB objects with room to spare */
	c->m2.max_msgs = 32;            /* the recorded ops are in sim_osd_recs(); the msgr2 copies are only for the odd message type */
	c->m2.msg_bytes_cap = 16u << 20;
	c->m2.modes[0] = SIM_M2_MODE_CRC;
	c->m2.n_modes = 1;
	c->m2.server_port = 6800;
	c->max_write_bytes = 90u * 1024u * 1024u;
	c->max_object_bytes = 128u * 1024u * 1024u;
}

/* ---- generator and cipher context ------------------------------------------------------------------------------------------ */

uint64_t so_rand64(sim_osd *o)
{
	uint64_t x = o->rng;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	o->rng = x;
	return x * 0x2545f4914f6cdd1dull;
}

void so_rand(sim_osd *o, uint8_t *out, size_t n)
{
	size_t i = 0;

	while (i < n) {
		uint64_t v = so_rand64(o);
		unsigned k;

		for (k = 0; k < 8 && i < n; k++, i++)
			out[i] = (uint8_t)(v >> (8u * k));
	}
}

static wr_status host_random(void *ctx, uint8_t *out, size_t n)
{
	so_rand((sim_osd *)ctx, out, n);
	return WR_OK;
}

const wri_ctx *so_ctx(const sim_osd *o) { return o->x; }

/* ---- lifecycle ----------------------------------------------------------------------------------------------------------- */

sim_osd *sim_osd_new(const sim_osd_cfg *cfg)
{
	sim_osd *o;

	if (cfg == NULL || cfg->mon == NULL || cfg->store == NULL || cfg->m2.ctl_cap == 0 || cfg->m2.seg_cap == 0 ||
	    cfg->m2.n_methods > SIM_M2_LIST_MAX || cfg->m2.n_modes > SIM_M2_LIST_MAX || cfg->max_object_bytes == 0)
		return NULL;
	o = (sim_osd *)calloc(1, sizeof(*o));
	if (o == NULL)
		return NULL;
	o->x = (wri_ctx *)calloc(1, sizeof(*o->x));
	o->recs = (sim_osd_rec *)calloc(SIM_OSD_REC_MAX, sizeof(*o->recs));
	if (o->x == NULL || o->recs == NULL) {
		free(o->x);
		free(o->recs);
		free(o);
		return NULL;
	}
	o->cfg = *cfg;
	o->epoch = cfg->epoch;
	o->rng = cfg->seed != 0 ? cfg->seed ^ 0x9e3779b97f4a7c15ull : 0x5eed0ed05eed0ed0ull;
	o->x->host.size = (uint32_t)sizeof(o->x->host);
	o->x->host.ctx = o;
	o->x->host.random = host_random;
	return o;
}

static void held_free(so_held *h)
{
	free(h->front);
	free(h->data);
	memset(h, 0, sizeof(*h));
}

static void parked_free(so_parked *p)
{
	free(p->front);
	free(p->data);
	memset(p, 0, sizeof(*p));
}

static void drop_conn_state(sim_osd *o, const sim_osd_conn *c)
{
	uint32_t i;

	for (i = 0; i < o->n_held;) {
		if (c == NULL || o->held[i].c == c) {
			held_free(&o->held[i]);
			memmove(&o->held[i], &o->held[i + 1], (size_t)(o->n_held - i - 1u) * sizeof(o->held[0]));
			o->n_held--;
			memset(&o->held[o->n_held], 0, sizeof(o->held[0]));
		} else {
			i++;
		}
	}
	for (i = 0; i < o->n_parked;) {
		if (c == NULL || o->parked[i].c == c) {
			parked_free(&o->parked[i]);
			memmove(&o->parked[i], &o->parked[i + 1], (size_t)(o->n_parked - i - 1u) * sizeof(o->parked[0]));
			o->n_parked--;
			memset(&o->parked[o->n_parked], 0, sizeof(o->parked[0]));
		} else {
			i++;
		}
	}
}

void sim_osd_free(sim_osd *o)
{
	uint32_t i;

	if (o == NULL)
		return;
	for (i = 0; i < SIM_OSD_MAX_CONNS; i++)
		if (o->conns[i] != NULL)
			sim_osd_conn_free(o->conns[i]);
	drop_conn_state(o, NULL);
	free(o->recs);
	free(o->x);
	free(o);
}

sim_osd_fault *sim_osd_faults(sim_osd *o) { return &o->cfg.fault; }

sim_osd_conn *sim_osd_accept(sim_osd *o)
{
	sim_osd_conn *c;
	sim_m2_cfg cfg;
	sim_m2_auth_ops ops;
	uint32_t slot;

	for (slot = 0; slot < SIM_OSD_MAX_CONNS && o->conns[slot] != NULL; slot++)
		;
	if (slot == SIM_OSD_MAX_CONNS)
		return NULL;
	c = (sim_osd_conn *)calloc(1, sizeof(*c));
	if (c == NULL)
		return NULL;
	c->osd = o;
	c->index = o->n_accepted;
	cfg = o->cfg.m2;
	cfg.entity_type = SIM_M2_ENT_OSD;
	if (o->cfg.v8_only)
		cfg.ident_supported &= ~(1ull << 49); /* SERVER_SQUID: the client falls back to MOSDOp v8 or refuses */
	memset(&ops, 0, sizeof(ops));
	ops.ctx = c;
	ops.request = so_auth_request;
	ops.more = so_auth_more;
	c->m2 = sim_m2_new(&cfg, &ops);
	if (c->m2 == NULL) {
		free(c);
		return NULL;
	}
	c->m2->on_message = so_on_message;
	c->m2->on_message_ctx = c;
	o->conns[slot] = c;
	o->n_accepted++;
	return c;
}

void sim_osd_conn_free(sim_osd_conn *c)
{
	uint32_t i;

	if (c == NULL)
		return;
	for (i = 0; i < SIM_OSD_MAX_CONNS; i++)
		if (c->osd->conns[i] == c)
			c->osd->conns[i] = NULL;
	drop_conn_state(c->osd, c);
	wr_key_wipe(&c->key);
	sim_m2_free(c->m2);
	free(c);
}

size_t sim_osd_feed(sim_osd_conn *c, const uint8_t *p, size_t n) { return sim_m2_feed(c->m2, p, n); }
size_t sim_osd_drain(sim_osd_conn *c, uint8_t *out, size_t cap) { return sim_m2_drain(c->m2, out, cap); }
int sim_osd_closed(const sim_osd_conn *c) { return sim_m2_closed(c->m2); }
sim_m2 *sim_osd_conn_m2(sim_osd_conn *c) { return c->m2; }

/* ---- sending ----------------------------------------------------------------------------------------------------------------- */

/* One MESSAGE with the header of a daemon (priority 127, flags 3). Empty trailing segments are not sent. */
wr_status so_send_msg(sim_osd_conn *c, uint16_t type, uint64_t tid, uint16_t version, uint16_t compat, const uint8_t *front, uint32_t flen,
		      const uint8_t *data, uint32_t dlen)
{
	sim_m2 *s = c->m2;
	uint8_t h[WRI_M2_HDR2_LEN];
	wri_m2_hdr2 hd;
	wri_m2_seg_src seg[4];
	unsigned nseg = dlen != 0 ? 4u : flen != 0 ? 2u : 1u;
	wr_status st;

	if (c->killed || s->state != SIM_M2_ST_READY)
		return WR_E_STATE;
	memset(&hd, 0, sizeof(hd));
	hd.seq = s->out_seq + 1u;
	hd.tid = tid;
	hd.type = type;
	hd.priority = 127;
	hd.version = version;
	hd.ack_seq = s->in_seq;
	hd.flags = WRI_M2_MSGF_COMPLETE_NOCRC;
	hd.compat_version = compat;
	wri_m2_hdr2_encode(h, &hd);
	memset(seg, 0, sizeof(seg));
	seg[0].p = h, seg[0].len = sizeof(h);
	seg[1].p = front, seg[1].len = flen;
	seg[3].p = data, seg[3].len = dlen;
	st = sim_m2_send_frame(s, WRI_M2_TAG_MESSAGE, seg, nseg);
	if (st == WR_OK)
		s->out_seq++;
	return st;
}

/* An abrupt end: the bytes queued for the client are never delivered and it reads EOF. */
static void conn_cut(sim_osd_conn *c)
{
	sim_m2 *s = c->m2;

	if (c->killed)
		return;
	c->killed = 1;
	s->cfg.f.out_limit = (int64_t)s->delivered;
	s->cfg.f.out_limit_close = 1;
	sim_m2_close(s);
}

void so_cut_all(sim_osd *o)
{
	uint32_t i;

	for (i = 0; i < SIM_OSD_MAX_CONNS; i++)
		if (o->conns[i] != NULL)
			conn_cut(o->conns[i]);
}

void sim_osd_restart(sim_osd *o)
{
	uint32_t i;

	so_cut_all(o);
	drop_conn_state(o, NULL); /* held replies and parked requests are lost; the duplicate log is in the store and stays */
	for (i = 0; i < SIM_OSD_MAX_CONNS; i++)
		if (o->conns[i] != NULL)
			memset(o->conns[i]->bo, 0, sizeof(o->conns[i]->bo));
}

uint32_t sim_osd_release(sim_osd *o, uint32_t n)
{
	uint32_t done = 0;

	while (o->n_held != 0 && (n == 0 || done < n)) {
		uint32_t at = o->cfg.fault.reverse_release ? o->n_held - 1u : 0u;
		so_held h = o->held[at];
		wr_status st;

		memmove(&o->held[at], &o->held[at + 1], (size_t)(o->n_held - at - 1u) * sizeof(o->held[0]));
		o->n_held--;
		memset(&o->held[o->n_held], 0, sizeof(o->held[0]));
		st = so_send_msg(h.c, SO_MSG_OSD_OPREPLY, h.tid, 8, 2, h.front, h.flen, h.data, h.dlen);
		free(h.front);
		free(h.data);
		if (st == WR_OK)
			done++;
		else if (h.c->send_err == WR_OK)
			h.c->send_err = st;
	}
	return done;
}

/* ---- the epoch and parked requests ------------------------------------------------------------------------------------------------ */

void sim_osd_set_epoch(sim_osd *o, uint32_t epoch)
{
	uint32_t i;

	o->epoch = epoch;
	if (o->reentry)
		return;
	o->reentry = 1;
	for (i = 0; i < o->n_parked;) { /* arrival order */
		so_parked p = o->parked[i];

		if (epoch != 0 && p.front != NULL && wri_le32_get(p.front + 24u + 4u) > epoch) { /* hash, then epoch, after the 24 byte spg_t */
			i++;
			continue;
		}
		memmove(&o->parked[i], &o->parked[i + 1], (size_t)(o->n_parked - i - 1u) * sizeof(o->parked[0]));
		o->n_parked--;
		memset(&o->parked[o->n_parked], 0, sizeof(o->parked[0]));
		if (p.front != NULL && !p.c->killed)
			so_handle_osdop(p.c, p.version, p.tid, p.front, p.flen, p.data, p.dlen, 1);
		free(p.front);
		free(p.data);
	}
	o->reentry = 0;
}

uint32_t sim_osd_n_parked(const sim_osd *o) { return o->n_parked; }
uint32_t sim_osd_n_held(const sim_osd *o) { return o->n_held; }
uint32_t sim_osd_epoch(const sim_osd *o) { return o->epoch; }

void sim_osd_set_class_hook(sim_osd *o, int (*fn)(void *ctx, sim_osd_cls_call *call, int run), void *ctx)
{
	o->cls_hook = fn;
	o->cls_hook_ctx = ctx;
}

/* ---- server-initiated messages ----------------------------------------------------------------------------------------------------- */

static int is_max(const char *oid) { return oid != NULL && strcmp(oid, SIM_OSD_BO_MAX) == 0; }

static void put_hobject(so_buf *b, const char *oid, uint32_t hash, int64_t pool)
{
	size_t m = b->len;
	int mx = is_max(oid);
	size_t l = oid != NULL && !mx ? strlen(oid) : 0;

	so_buf_u8(b, 4); /* hobject_t: struct v4/3 { string key, string oid, u64 snap, u32 hash, bool max, string nspace, i64 pool } */
	so_buf_u8(b, 3);
	so_buf_u32(b, 0);
	so_buf_str(b, "", 0);
	so_buf_str(b, mx ? "" : oid != NULL ? oid : "", l);
	so_buf_u64(b, l != 0 ? SO_SNAP_NOSNAP : 0u); /* a real object is the head; an empty name is a boundary of the PG */
	so_buf_u32(b, mx ? 0u : hash);
	so_buf_u8(b, mx ? 1u : 0u); /* the "max" position the end of the last PG of a pool has: a default hobject_t with the max flag (pool INT64_MIN) */
	so_buf_str(b, "", 0);
	so_buf_u64(b, mx ? (uint64_t)INT64_MIN : (uint64_t)pool);
	if (!b->oom)
		wri_le32_put(b->p + m + 2, (uint32_t)(b->len - m - 6u));
}

wr_status sim_osd_send_backoff(sim_osd_conn *c, uint8_t op, uint64_t id, int64_t pool, uint32_t pg_seed, uint32_t map_epoch,
			       const char *begin_oid, uint32_t begin_hash, const char *end_oid, uint32_t end_hash)
{
	so_buf b;
	wr_status st;
	uint32_t i;

	memset(&b, 0, sizeof(b));
	so_buf_u8(&b, 1); /* spg_t: struct v1/1 { pg_t, i8 shard } */
	so_buf_u8(&b, 1);
	so_buf_u32(&b, 18);
	so_buf_u8(&b, 1);
	so_buf_u64(&b, (uint64_t)pool);
	so_buf_u32(&b, pg_seed);
	so_buf_u32(&b, 0xffffffffu);
	so_buf_u8(&b, 0xff);
	so_buf_u32(&b, map_epoch);
	so_buf_u8(&b, op);
	so_buf_u64(&b, id);
	put_hobject(&b, begin_oid, begin_hash, pool);
	put_hobject(&b, end_oid, end_hash, pool);
	if (b.oom) {
		so_buf_free(&b);
		return WR_E_BUDGET;
	}
	if (op == 1u) { /* BLOCK: the entry covers requests once the client acknowledged it */
		for (i = 0; i < SO_BACKOFFS && c->bo[i].used; i++)
			;
		if (i < SO_BACKOFFS) {
			so_backoff *e = &c->bo[i];

			memset(e, 0, sizeof(*e));
			e->used = 1;
			e->id = id;
			e->pool = pool;
			e->pg_seed = pg_seed;
			e->begin_max = (uint8_t)is_max(begin_oid);
			e->end_max = (uint8_t)is_max(end_oid);
			snprintf(e->begin, sizeof(e->begin), "%s", begin_oid != NULL && !e->begin_max ? begin_oid : "");
			snprintf(e->end, sizeof(e->end), "%s", end_oid != NULL && !e->end_max ? end_oid : "");
			e->begin_hash = e->begin_max ? 0u : begin_hash;
			e->end_hash = e->end_max ? 0u : end_hash;
		}
	} else if (op == 3u) { /* UNBLOCK */
		for (i = 0; i < SO_BACKOFFS; i++)
			if (c->bo[i].used && c->bo[i].id == id)
				memset(&c->bo[i], 0, sizeof(c->bo[i]));
	}
	st = so_send_msg(c, SO_MSG_OSD_BACKOFF, 0, 1, 1, b.p, (uint32_t)b.len, NULL, 0);
	so_buf_free(&b);
	return st;
}

wr_status sim_osd_send_map_push(sim_osd_conn *c, const uint8_t *front, uint32_t n)
{
	return so_send_msg(c, SO_MSG_OSD_MAP, 0, 4, 3, front, n, NULL, 0);
}

/* ---- what the OSD recorded ------------------------------------------------------------------------------------------------------ */

const sim_osd_rec *sim_osd_recs(const sim_osd *o, uint32_t *n)
{
	*n = o->n_recs;
	return o->recs;
}

void sim_osd_recs_clear(sim_osd *o) { o->n_recs = 0; }
uint32_t sim_osd_n_conns_accepted(const sim_osd *o) { return o->n_accepted; }
uint32_t sim_osd_n_acks(const sim_osd *o) { return o->n_acks; }
uint32_t sim_osd_n_violations(const sim_osd *o) { return o->n_violations; }
uint32_t sim_osd_n_backoff_drops(const sim_osd *o) { return o->n_backoff_drops; }
uint32_t sim_osd_n_requests(const sim_osd *o) { return o->n_requests; }
uint32_t sim_osd_n_other(const sim_osd *o) { return o->n_other; }
