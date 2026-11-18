/* SPDX-License-Identifier: MIT */
/*
 * sim_osd_ops.c - the MOSDOp side of the fake OSD, written from docs/spec/osd-ops.md and rbd-format2.md from the SERVER's point of view and
 * sharing no code with the client modules (R9): its own decoder of MOSDOp v9 / v8 (2.3, 2.5), the checks of the primary-log path in the order
 * the note gives them (silence, epoch parking, backoff, full pool, EAGAIN, redirect, name limits, snapshot context, message size, class
 * lookup, forced errors, duplicate detection), the execution of the operations in order against the shared store with the rules of 2.7, and
 * its own encoder of MOSDOpReply v8 (2.9). Snapshot semantics: a clone is made by the first write whose context is newer than the object's
 * last-seen one, a delete with clones leaves a whiteout (3.9). Test code: libc allowed.
 */
#include "sim_osd_int.h"

/* ---- violations ------------------------------------------------------------------------------------------------------ */

void so_violation(sim_osd_conn *c, const char *what, uint64_t a0, uint64_t a1)
{
	sim_m2 *s = c->m2;

	c->osd->n_violations++;
	if (s->err.status == WR_OK) {
		s->err.status = WR_E_OSD_PROTO;
		s->err.module = WR_MOD_OSD;
		s->err.what = what;
		s->err.a0 = a0;
		s->err.a1 = a1;
	}
	sim_m2_close(s);
}

/* ---- decoding ---------------------------------------------------------------------------------------------------------- */

/* NULL when the request decodes, else a short reason. The identity of the request is (client.<global id>, inc, tid): with the usual empty
 * reqid it comes from the connection and the message header (osd-ops.md 2.3). */
static const char *decode_req(const sim_osd_conn *c, uint8_t version, uint64_t msg_tid, const uint8_t *front, uint32_t flen,
			      const uint8_t *data, uint32_t dlen, so_req *rq)
{
	wri_rd r;
	wri_env sp, rid, ot, ol;
	uint8_t pgv, rtype;
	int64_t rnum;
	uint64_t rtid;
	int32_t rinc, pref;
	uint32_t i, nops, nsn, total = 0;

	memset(rq, 0, sizeof(*rq));
	rq->version = version;
	wri_rd_init(&r, front, flen);
	if (wri_env_open(&r, 1, &sp) != WR_OK) /* spg_t: struct { pg_t, shard } */
		return "spg_t does not decode";
	pgv = wri_rd_u8(&sp.body);
	rq->pool = (int64_t)wri_rd_u64(&sp.body);
	rq->pg_seed = wri_rd_u32(&sp.body);
	pref = wri_rd_i32(&sp.body);
	(void)wri_rd_u8(&sp.body); /* the shard: -1 for a replicated pool */
	if (!wri_rd_ok(&sp.body) || pgv != 1u || pref != -1)
		return "pg_t is not the 17 byte form";
	rq->hash = wri_rd_u32(&r);
	rq->epoch = wri_rd_u32(&r);
	rq->flags = wri_rd_u32(&r);
	if (wri_env_open(&r, 2, &rid) != WR_OK)
		return "osd_reqid_t does not decode";
	rtype = wri_rd_u8(&rid.body);
	rnum = wri_rd_i64(&rid.body);
	rtid = wri_rd_u64(&rid.body);
	rinc = wri_rd_i32(&rid.body);
	if (!wri_rd_ok(&rid.body))
		return "osd_reqid_t is short";
	wri_rd_skip(&r, 24); /* the blkin trace */
	if (version == 9u && wri_env_open(&r, 1, &ot) != WR_OK) /* the otel trace */
		return "otel trace does not decode";
	rq->client_inc = wri_rd_u32(&r);
	rq->mtime_s = wri_rd_u32(&r);
	rq->mtime_ns = wri_rd_u32(&r);
	if (wri_env_open(&r, 6, &ol) != WR_OK) /* object_locator_t */
		return "object_locator_t does not decode";
	(void)wri_rd_i64(&ol.body); /* the pool of the locator: the pgid's counts */
	(void)wri_rd_i32(&ol.body);
	rq->key = wri_denc_blob(&ol.body, &rq->key_len, SO_NAME_DECODE_MAX);
	rq->nspace = wri_denc_blob(&ol.body, &rq->nspace_len, SO_NAME_DECODE_MAX);
	if (!wri_rd_ok(&ol.body))
		return "object_locator_t is short";
	rq->oid = wri_denc_blob(&r, &rq->oid_len, SO_NAME_DECODE_MAX);
	nops = wri_rd_u16(&r);
	if (!wri_rd_ok(&r) || nops > SO_OPS_CAP || nops == 0u)
		return "object name or operation count";
	rq->n_ops = nops;
	for (i = 0; i < nops; i++) {
		const uint8_t *p = wri_rd_bytes(&r, SO_OPREC);
		so_opd *op = &rq->ops[i];

		if (p == NULL)
			return "operation record is short";
		memcpy(op->raw, p, SO_OPREC);
		op->code = wri_le16_get(p);
		op->flags = wri_le32_get(p + 2);
		op->payload_len = wri_le32_get(p + 34);
		if (total + op->payload_len < total)
			return "payload lengths overflow";
		total += op->payload_len;
	}
	rq->snapid = wri_rd_u64(&r);
	rq->snap_seq = wri_rd_u64(&r);
	nsn = wri_rd_count(&r, SO_SNAPS_CAP, 8);
	rq->n_snaps = nsn;
	for (i = 0; i < nsn; i++)
		rq->snaps[i] = wri_rd_u64(&r);
	rq->retry_attempt = wri_rd_i32(&r);
	(void)wri_rd_u64(&r); /* the feature word */
	if (!wri_rd_ok(&r))
		return "front is short";
	if (wri_rd_left(&r) != 0)
		return "bytes after the last field of the front";
	if (total != dlen)
		return "payload lengths do not add up to the data segment";
	{
		const uint8_t *q = data;

		for (i = 0; i < nops; i++) {
			rq->ops[i].in = q;
			q += rq->ops[i].payload_len;
		}
	}
	rq->data = data;
	rq->data_len = dlen;
	if (rtype == 0u && rnum == 0 && rtid == 0u) {
		if ((uint32_t)rinc != rq->client_inc) /* the OSD asserts it */
			return "reqid.inc differs from client_inc";
		rq->gid = c->gid;
		rq->tid = msg_tid;
	} else {
		rq->gid = (uint64_t)rnum;
		rq->tid = rtid;
	}
	return NULL;
}

/* ---- backoff: the ordering of hobject_t (osd-ops.md 2.10) and what the OSD does with a covered request ------------------------- */

static uint32_t rev32(uint32_t x)
{
	x = (x >> 16) | (x << 16);
	x = ((x & 0xff00ff00u) >> 8) | ((x & 0x00ff00ffu) << 8);
	x = ((x & 0xf0f0f0f0u) >> 4) | ((x & 0x0f0f0f0fu) << 4);
	x = ((x & 0xccccccccu) >> 2) | ((x & 0x33333333u) << 2);
	x = ((x & 0xaaaaaaaau) >> 1) | ((x & 0x55555555u) << 1);
	return x;
}

static int pos_cmp(int ma, int64_t pa, uint32_t ha, const uint8_t *oa, uint32_t la, int mb, int64_t pb, uint32_t hb, const uint8_t *ob,
		   uint32_t lb)
{
	uint32_t ra, rb, m;
	int c;

	if (ma != mb) /* the max flag first: a max position sorts above everything */
		return ma ? 1 : -1;
	if (ma)
		return 0;
	if (pa != pb)
		return pa < pb ? -1 : 1;
	ra = rev32(ha);
	rb = rev32(hb);
	if (ra != rb)
		return ra < rb ? -1 : 1;
	m = la < lb ? la : lb;
	c = m != 0 ? memcmp(oa, ob, m) : 0;
	if (c != 0)
		return c;
	return la < lb ? -1 : la > lb ? 1 : 0;
}

int so_backoff_covers(const sim_osd_conn *c, const so_req *rq)
{
	uint32_t i;

	for (i = 0; i < SO_BACKOFFS; i++) {
		const so_backoff *b = &c->bo[i];
		size_t bl = strlen(b->begin), el = strlen(b->end);
		int cb, ce;

		if (!b->used || !b->acked || b->pool != rq->pool || b->pg_seed != rq->pg_seed)
			continue;
		cb = pos_cmp(0, rq->pool, rq->hash, rq->oid, rq->oid_len, b->begin_max, b->pool, b->begin_hash, (const uint8_t *)b->begin, (uint32_t)bl);
		ce = pos_cmp(0, rq->pool, rq->hash, rq->oid, rq->oid_len, b->end_max, b->pool, b->end_hash, (const uint8_t *)b->end, (uint32_t)el);
		if (b->begin_max == b->end_max && b->begin_hash == b->end_hash && bl == el && memcmp(b->begin, b->end, bl) == 0) {
			if (cb == 0)
				return 1;
		} else if (cb >= 0 && ce < 0) {
			return 1;
		}
	}
	return 0;
}

/* a MOSDBackoff from the client: ACK_BLOCK marks the entry (spg_t, u32 epoch, u8 op, u64 id, ...) */
void so_backoff_note(sim_osd_conn *c, const uint8_t *front, uint32_t flen)
{
	wri_rd r;
	wri_env sp;
	uint8_t op;
	uint64_t id;
	uint32_t i;

	wri_rd_init(&r, front, flen);
	if (wri_env_open(&r, 1, &sp) != WR_OK)
		return;
	(void)wri_rd_u32(&r);
	op = wri_rd_u8(&r);
	id = wri_rd_u64(&r);
	if (!wri_rd_ok(&r) || op != 2u)
		return;
	c->osd->n_acks++;
	for (i = 0; i < SO_BACKOFFS; i++)
		if (c->bo[i].used && c->bo[i].id == id)
			c->bo[i].acked = 1;
}

/* ---- classification of the operations -------------------------------------------------------------------------------------- */

typedef struct so_opinfo {
	so_cls_fn fn;
	uint8_t writes, hook;
	char cls[256], method[256];
	const uint8_t *args;
	uint32_t args_len;
} so_opinfo;

static int op_writes(uint16_t code)
{
	switch (code) {
	case SO_OP_WRITE:
	case SO_OP_WRITEFULL:
	case SO_OP_TRUNCATE:
	case SO_OP_ZERO:
	case SO_OP_DELETE:
	case SO_OP_CREATE:
	case SO_OP_SETALLOCHINT:
		return 1;
	default: /* the known readers and any op code the simulator does not run: the mode bit decides */
		return code != SO_OP_CALL && (code & 0x2000u) != 0u;
	}
}

/* 0, or the errno of the whole message (the class loader's answers happen before anything runs); *mutating says whether anything can write */
static int32_t classify(const sim_osd *o, const so_req *rq, so_opinfo *oi, int *mutating)
{
	uint32_t i;

	*mutating = 0;
	for (i = 0; i < rq->n_ops; i++) {
		const so_opd *op = &rq->ops[i];
		so_opinfo *x = &oi[i];
		uint32_t cl, ml, il;
		int rc;

		memset(x, 0, sizeof(*x));
		if (op->code != SO_OP_CALL) {
			*mutating |= op_writes(op->code);
			continue;
		}
		cl = op->raw[6];
		ml = op->raw[7];
		il = wri_le32_get(op->raw + 9);
		if ((uint64_t)cl + ml + il != op->payload_len)
			return -SO_EINVAL;
		memcpy(x->cls, op->in, cl);
		memcpy(x->method, op->in + cl, ml);
		x->args = op->in + cl + ml;
		x->args_len = il;
		rc = so_cls_lookup(x->cls, cl, x->method, ml, &x->fn, &x->writes);
		if (rc == -1 && o->cls_hook != NULL) {
			sim_osd_cls_call call;

			memset(&call, 0, sizeof(call));
			call.cls = x->cls;
			call.method = x->method;
			call.in = x->args;
			call.in_len = il;
			if (o->cls_hook(o->cls_hook_ctx, &call, 0) == 1) {
				x->hook = 1;
				x->writes = call.writes;
				rc = 0;
			}
		}
		if (rc == -1)
			return -SO_EPERM; /* an unknown class (the capture: -EPERM, not -EOPNOTSUPP) */
		if (rc == -2)
			return -SO_EOPNOTSUPP;
		*mutating |= x->writes;
	}
	return 0;
}

/* ---- the answer -------------------------------------------------------------------------------------------------------------- */

static void rep_init(so_rep *rep, const so_req *rq)
{
	uint32_t i;

	memset(rep, 0, sizeof(*rep));
	for (i = 0; i < rq->n_ops; i++) {
		memcpy(rep->rec[i], rq->ops[i].raw, SO_OPREC);
		wri_le32_put(rep->rec[i] + 34, 0);
	}
}

static void put_redirect(so_buf *f, int64_t pool)
{
	size_t m1 = f->len, m2;

	so_buf_u8(f, 1); /* request_redirect_t: struct v1/1 { object_locator_t, string redirect_object, u32 0 } */
	so_buf_u8(f, 1);
	so_buf_u32(f, 0);
	m2 = f->len;
	so_buf_u8(f, 6); /* object_locator_t: struct v6/3 { i64 pool, i32 -1, string key, string nspace, i64 hash } */
	so_buf_u8(f, 3);
	so_buf_u32(f, 0);
	so_buf_u64(f, (uint64_t)pool);
	so_buf_u32(f, 0xffffffffu);
	so_buf_str(f, "", 0);
	so_buf_str(f, "", 0);
	so_buf_u64(f, UINT64_MAX);
	if (!f->oom)
		wri_le32_put(f->p + m2 + 2, (uint32_t)(f->len - m2 - 6u));
	so_buf_str(f, "", 0);
	so_buf_u32(f, 0);
	if (!f->oom)
		wri_le32_put(f->p + m1 + 2, (uint32_t)(f->len - m1 - 6u));
}

/* Builds, records and sends (or drops or holds) the MOSDOpReply of `rq`. The reply data segment is the outputs in op order. */
static void deliver(sim_osd_conn *c, uint64_t msg_tid, const so_req *rq, so_rep *rep, sim_osd_rec *rec, uint32_t rec_index)
{
	sim_osd *o = c->osd;
	so_buf f;
	uint32_t i, epoch = o->epoch != 0 ? o->epoch : rq->epoch, dlen = (uint32_t)rep->out.len;
	uint64_t flags = rq->flags;
	uint32_t pl0 = 0;

	memset(&f, 0, sizeof(f));
	if (rep->executed)
		flags |= SO_F_ACK | SO_F_ONDISK;
	if (o->cfg.fault.bad_reply_len) {
		if (dlen != 0)
			dlen--;
		else
			pl0 = 1; /* nothing to cut: the first record claims one byte that is not there */
	}
	for (i = 0; i < rq->n_ops; i++) {
		wri_le32_put(rep->rec[i] + 34, rep->outlen[i] + (i == 0 ? pl0 : 0u));
		if (i < SIM_OSD_OPS_MAX) {
			rec->op_rval[i] = rep->rval[i];
			rec->op_out[i] = rep->outlen[i];
		}
	}
	so_buf_str(&f, rq->oid, rq->oid_len);
	so_buf_u8(&f, 1); /* pg_t */
	so_buf_u64(&f, (uint64_t)rq->pool);
	so_buf_u32(&f, rq->pg_seed);
	so_buf_u32(&f, 0xffffffffu);
	so_buf_u64(&f, flags);
	so_buf_u32(&f, (uint32_t)rep->result);
	so_buf_u64(&f, rep->user_version); /* bad_replay_version: (user version, epoch) */
	so_buf_u32(&f, rep->replay_epoch != 0 ? rep->replay_epoch : epoch);
	so_buf_u32(&f, epoch);
	so_buf_u32(&f, rq->n_ops);
	for (i = 0; i < rq->n_ops; i++)
		so_buf_put(&f, rep->rec[i], SO_OPREC);
	so_buf_u32(&f, (uint32_t)rq->retry_attempt);
	for (i = 0; i < rq->n_ops; i++)
		so_buf_u32(&f, (uint32_t)rep->rval[i]);
	so_buf_u64(&f, rep->replay_ver);
	so_buf_u32(&f, rep->replay_ver != 0 ? rep->replay_epoch : 0u);
	so_buf_u64(&f, rep->user_version);
	so_buf_u8(&f, rep->do_redirect);
	if (rep->do_redirect)
		put_redirect(&f, rep->redirect_pool);
	{
		uint8_t z[24];

		memset(z, 0, sizeof(z));
		so_buf_put(&f, z, sizeof(z)); /* blkin trace */
	}
	rec->result = rep->result;
	if (f.oom || rep->out.oom) {
		so_buf_free(&f);
		c->send_err = WR_E_BUDGET;
		return;
	}
	if (o->cfg.fault.drop_replies != 0) { /* executed, answer lost */
		o->cfg.fault.drop_replies--;
		rec->dropped_reply = 1;
		rec->result = 0;
		so_buf_free(&f);
		return;
	}
	if (o->cfg.fault.hold_replies) {
		so_held *h;

		if (o->n_held == SIM_OSD_HELD_MAX) {
			c->send_err = WR_E_BUDGET;
			so_buf_free(&f);
			return;
		}
		h = &o->held[o->n_held];
		h->c = c;
		h->tid = msg_tid;
		h->flen = (uint32_t)f.len;
		h->dlen = dlen;
		h->front = f.p; /* the held reply owns the front buffer */
		h->data = NULL;
		h->rec = rec_index;
		if (dlen != 0) {
			h->data = (uint8_t *)malloc(dlen);
			if (h->data == NULL) {
				free(f.p);
				c->send_err = WR_E_BUDGET;
				return;
			}
			memcpy(h->data, rep->out.p, dlen);
		}
		o->n_held++;
		rec->held = 1;
		return;
	}
	{
		wr_status st = so_send_msg(c, SO_MSG_OSD_OPREPLY, msg_tid, 8, 2, f.p, (uint32_t)f.len, rep->out.p, dlen);

		if (st != WR_OK && c->send_err == WR_OK)
			c->send_err = st;
	}
	so_buf_free(&f);
}

/* a reply produced before anything ran: the request's flags are echoed unchanged, no output, every rval 0 */
static void reply_error(sim_osd_conn *c, uint64_t msg_tid, const so_req *rq, sim_osd_rec *rec, uint32_t ri, int32_t result)
{
	so_rep rep;

	rep_init(&rep, rq);
	rep.result = result;
	deliver(c, msg_tid, rq, &rep, rec, ri);
	so_buf_free(&rep.out);
}

/* ---- execution --------------------------------------------------------------------------------------------------------------- */

typedef struct so_xc {
	sim_osd_conn *c;
	sim_osd *o;
	const so_req *rq;
	so_rep *rep;
	const so_opinfo *oi;
	so_obj *obj;
	const so_body *rb;      /* what a read-only message reads (the head or a clone) */
	int mutating;
	uint8_t dirty;
	char oid[SO_NAME_MAX + 1];
} so_xc;

static const so_body *body_now(const so_xc *x)
{
	if (x->mutating)
		return x->obj != NULL && x->obj->exists ? &x->obj->head : NULL;
	return x->rb;
}

static int range_bad(uint64_t max, uint64_t off, uint64_t len) { return off >= max || len > max || off + len > max; }

static int32_t ensure_exists(so_xc *x)
{
	if (!x->obj->exists) {
		x->obj->exists = 1;
		x->obj->whiteout = 0;
		so_body_free(&x->obj->head);
		x->dirty = 1;
	}
	return 0;
}

static void set_ext_len(so_xc *x, uint32_t i, uint64_t v) { wri_le64_put(x->rep->rec[i] + 14, v); }

static int32_t op_read(so_xc *x, uint32_t i, int sparse, so_buf *out)
{
	const so_body *b = body_now(x);
	const so_opd *op = &x->rq->ops[i];
	uint64_t off = wri_le64_get(op->raw + 6), len = wri_le64_get(op->raw + 14), l;

	if (b == NULL)
		return -SO_ENOENT;
	if (!sparse) {
		uint8_t *d;

		if (off >= b->size) {
			set_ext_len(x, i, 0);
			return 0;
		}
		l = len == 0 ? b->size - off : (len < b->size - off ? len : b->size - off); /* length 0 = to the end */
		d = so_buf_grow(out, (size_t)l);
		if (d == NULL)
			return -SO_EIO;
		so_body_read(b, off, d, l);
		set_ext_len(x, i, l);
		return 0;
	} else {
		uint32_t n = 0, k;
		uint64_t *ex = NULL, total = 0;
		uint8_t *d;

		l = off >= b->size || len == 0 ? 0 : (len < b->size - off ? len : b->size - off);
		if (l != 0) {
			ex = so_body_extents(b, off, l, &n);
			if (ex == NULL)
				return -SO_EIO;
		}
		for (k = 0; k < n; k++)
			total += ex[2u * k + 1u];
		so_buf_u32(out, n);
		for (k = 0; k < n; k++) {
			so_buf_u64(out, ex[2u * k]);
			so_buf_u64(out, ex[2u * k + 1u]);
		}
		so_buf_u32(out, (uint32_t)total);
		for (k = 0; k < n; k++) {
			d = so_buf_grow(out, (size_t)ex[2u * k + 1u]);
			if (d == NULL) {
				free(ex);
				return -SO_EIO;
			}
			so_body_read(b, ex[2u * k], d, ex[2u * k + 1u]);
		}
		free(ex);
		set_ext_len(x, i, total);
		return 0;
	}
}

static int32_t op_write(so_xc *x, uint32_t i, int full)
{
	const so_opd *op = &x->rq->ops[i];
	uint64_t off = full ? 0 : wri_le64_get(op->raw + 6), len = wri_le64_get(op->raw + 14);
	uint64_t max = x->o->cfg.max_object_bytes;

	if (len != op->payload_len)
		return -SO_EINVAL;
	if (full ? len > max : range_bad(max, off, len))
		return -SO_EFBIG;
	(void)ensure_exists(x);
	x->dirty = 1;
	if (full)
		so_body_clear_data(&x->obj->head);
	if (len == 0) {
		if (off > x->obj->head.size)
			x->obj->head.size = off; /* a write of nothing past the end extends the object */
		return 0;
	}
	return so_body_write(&x->obj->head, off, op->in, len) == 0 ? 0 : -SO_EFBIG;
}

static int32_t op_zero(so_xc *x, uint32_t i)
{
	so_body *b = x->obj != NULL && x->obj->exists ? &x->obj->head : NULL;
	const so_opd *op = &x->rq->ops[i];
	uint64_t off = wri_le64_get(op->raw + 6), len = wri_le64_get(op->raw + 14);
	uint64_t max = x->o->cfg.max_object_bytes;

	/* The order of the real OSD (checked on the lab): an existing object whose end the range reaches is turned into a TRUNCATE first, and
	 * the TRUNCATE still checks the ORIGINAL length (off + len > max is -EFBIG even though only the offset is used); every other ZERO checks
	 * the range before it looks at the object, so an absent object or a length of 0 does not hide -EFBIG. */
	if (b != NULL && off < max && len >= 1u && len <= max && off + len >= b->size) {
		if (off >= b->size)
			return 0; /* nothing to do */
		wri_le16_put(x->rep->rec[i], SO_OP_TRUNCATE);
		if (range_bad(max, off, len))
			return -SO_EFBIG;
		x->dirty = 1;
		return so_body_truncate(b, off) == 0 ? 0 : -SO_EIO;
	}
	if (range_bad(max, off, len))
		return -SO_EFBIG;
	if (b == NULL || len == 0)
		return 0; /* an absent object or an empty range: a no-op */
	x->dirty = 1;
	return so_body_zero(b, off, len) == 0 ? 0 : -SO_EIO;
}

static int32_t op_truncate(so_xc *x, uint32_t i)
{
	so_body *b = x->obj != NULL && x->obj->exists ? &x->obj->head : NULL;
	uint64_t off = wri_le64_get(x->rq->ops[i].raw + 6), len = wri_le64_get(x->rq->ops[i].raw + 14);

	if (b == NULL)
		return 0; /* absent: a no-op, before any range check (lab) */
	if (range_bad(x->o->cfg.max_object_bytes, off, len)) /* the length field is checked too, a stock client sends 0 */
		return -SO_EFBIG;
	x->dirty = 1;
	return so_body_truncate(b, off) == 0 ? 0 : -SO_EIO;
}

static int32_t op_delete(so_xc *x)
{
	if (x->obj == NULL || !x->obj->exists)
		return -SO_ENOENT;
	so_body_free(&x->obj->head);
	x->obj->exists = 0;
	x->obj->whiteout = x->obj->nclones != 0;
	x->dirty = 1;
	return 0;
}

static int32_t op_create(so_xc *x, uint32_t i)
{
	const so_opd *op = &x->rq->ops[i];

	if (op->payload_len != 0) { /* a retired category string: u32 length + bytes */
		wri_rd r;
		uint32_t l;

		wri_rd_init(&r, op->in, op->payload_len);
		(void)wri_denc_blob(&r, &l, 1u << 16);
		if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0)
			return -SO_EINVAL;
	}
	if (x->obj->exists)
		return (op->flags & SO_OPF_EXCL) != 0u ? -SO_EEXIST : 0;
	return ensure_exists(x);
}

static int32_t op_getxattr(so_xc *x, uint32_t i, so_buf *out)
{
	const so_body *b = body_now(x);
	const so_opd *op = &x->rq->ops[i];
	uint32_t nl = wri_le32_get(op->raw + 6);
	const so_kv *kv;

	if (b == NULL)
		return -SO_ENOENT;
	if (nl != op->payload_len)
		return -SO_EINVAL;
	kv = so_kv_get(&b->xattr, op->in, nl);
	if (kv == NULL)
		return -SO_ENODATA;
	so_buf_put(out, kv->v, kv->vl);
	wri_le32_put(x->rep->rec[i] + 10, kv->vl);
	return 0;
}

static int32_t op_omap(so_xc *x, uint32_t i, uint16_t code, so_buf *out)
{
	const so_body *b = body_now(x);
	const so_opd *op = &x->rq->ops[i];
	wri_rd r;
	uint32_t j, cnt = 0, sl, pl = 0, nreq, k;
	const uint8_t *start, *prefix = NULL;
	uint64_t maxe = 0, limit;
	uint8_t truncated = 0;
	size_t cnt_at;

	if (b == NULL)
		return -SO_ENOENT;
	wri_rd_init(&r, op->in, op->payload_len);
	if (code == SO_OP_OMAPGETVALSBYKEYS) {
		uint32_t kl[64];
		const uint8_t *kp[64];

		nreq = wri_rd_count(&r, 64, 4);
		for (k = 0; k < nreq; k++)
			kp[k] = wri_denc_blob(&r, &kl[k], 1u << 16);
		if (!wri_rd_ok(&r))
			return -SO_EINVAL;
		cnt_at = out->len;
		so_buf_u32(out, 0);
		for (j = 0; j < b->omap.n; j++) {
			for (k = 0; k < nreq; k++)
				if (kl[k] == b->omap.a[j].kl && (kl[k] == 0 || memcmp(kp[k], b->omap.a[j].k, kl[k]) == 0))
					break;
			if (k == nreq)
				continue;
			so_buf_str(out, b->omap.a[j].k, b->omap.a[j].kl);
			so_buf_str(out, b->omap.a[j].v, b->omap.a[j].vl);
			cnt++;
		}
		if (!out->oom)
			wri_le32_put(out->p + cnt_at, cnt);
		return 0;
	}
	start = wri_denc_blob(&r, &sl, 1u << 16);
	maxe = wri_rd_u64(&r);
	if (code == SO_OP_OMAPGETVALS)
		prefix = wri_denc_blob(&r, &pl, 1u << 16);
	if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0)
		return -SO_EINVAL;
	limit = maxe < SO_OMAP_MAX_ENTRIES ? maxe : SO_OMAP_MAX_ENTRIES;
	cnt_at = out->len;
	so_buf_u32(out, 0);
	{
		int found = 0;
		uint32_t first = so_kv_lower(&b->omap, start, sl, &found);

		if (found)
			first++; /* strictly after start_after */
		for (j = first; j < b->omap.n; j++) {
			const so_kv *kv = &b->omap.a[j];

			if (prefix != NULL && (kv->kl < pl || (pl != 0 && memcmp(kv->k, prefix, pl) != 0)))
				continue;
			if (cnt == limit) { /* one more matching key after the limit: the listing is cut */
				truncated = 1;
				break;
			}
			so_buf_str(out, kv->k, kv->kl);
			if (code == SO_OP_OMAPGETVALS)
				so_buf_str(out, kv->v, kv->vl);
			cnt++;
		}
	}
	so_buf_u8(out, truncated);
	if (!out->oom)
		wri_le32_put(out->p + cnt_at, cnt);
	return 0;
}

static int32_t op_call(so_xc *x, uint32_t i, so_buf *out)
{
	const so_opinfo *oi = &x->oi[i];
	so_cctx cx;
	so_body empty;
	int32_t rc;
	size_t before = out->len;

	if (oi->hook) {
		sim_osd_cls_call call;
		uint8_t *buf = (uint8_t *)malloc(65536u);

		if (buf == NULL)
			return -SO_EIO;
		memset(&call, 0, sizeof(call));
		call.cls = oi->cls;
		call.method = oi->method;
		call.in = oi->args;
		call.in_len = oi->args_len;
		call.out = buf;
		call.out_cap = 65536u;
		if (x->o->cls_hook == NULL || x->o->cls_hook(x->o->cls_hook_ctx, &call, 1) != 1) {
			free(buf);
			return -SO_EOPNOTSUPP;
		}
		if (call.out_len > call.out_cap)
			call.out_len = call.out_cap;
		so_buf_put(out, buf, call.out_len);
		free(buf);
		if (call.writes && x->mutating)
			x->dirty = 1;
		set_ext_len(x, i, call.out_len);
		return call.rval;
	}
	memset(&cx, 0, sizeof(cx));
	memset(&empty, 0, sizeof(empty));
	cx.store = x->o->cfg.store;
	if (oi->writes && x->mutating)
		(void)ensure_exists(x);
	cx.exists = body_now(x) != NULL;
	cx.body = cx.exists ? (so_body *)(void *)body_now(x) : &empty;
	cx.gid = x->c->gid;
	cx.now_s = cx.store->now_s;
	cx.oid = x->oid;
	cx.oid_len = x->rq->oid_len;
	{
		const sim_m2_ident *id = &x->c->m2->ident;

		if (id->addrs_len >= 35u && id->addrs[0] == 1u) {
			memcpy(cx.addr, id->addrs, 35);
			wri_le32_put(cx.addr + 7, 1); /* the lock record keeps the address with type legacy */
		} else {
			static const uint8_t ip[4] = {10, 77, 0, 20};

			sim_m2_put_addr4(cx.addr, 1, 0, ip, 0);
		}
	}
	rc = oi->fn(&cx, oi->args, oi->args_len, out);
	if (out->oom)
		return -SO_EIO;
	if (rc < 0) {
		out->len = before; /* the failing call has no output */
		return rc;
	}
	if (cx.dirty && x->mutating)
		x->dirty = 1;
	set_ext_len(x, i, out->len - before);
	return rc;
}

static int32_t exec_op(so_xc *x, uint32_t i, so_buf *out)
{
	const so_opd *op = &x->rq->ops[i];

	switch (op->code) {
	case SO_OP_READ: return op_read(x, i, 0, out);
	case SO_OP_SPARSE_READ: return op_read(x, i, 1, out);
	case SO_OP_STAT: {
		const so_body *b = body_now(x);

		if (b == NULL)
			return -SO_ENOENT;
		so_buf_u64(out, b->size);
		so_buf_u32(out, b->mtime_s);
		so_buf_u32(out, b->mtime_ns);
		return 0;
	}
	case SO_OP_WRITE: return op_write(x, i, 0);
	case SO_OP_WRITEFULL: return op_write(x, i, 1);
	case SO_OP_ZERO: return op_zero(x, i);
	case SO_OP_TRUNCATE: return op_truncate(x, i);
	case SO_OP_DELETE: return op_delete(x);
	case SO_OP_CREATE: return op_create(x, i);
	case SO_OP_SETALLOCHINT: return ensure_exists(x);
	case SO_OP_GETXATTR: return op_getxattr(x, i, out);
	case SO_OP_OMAPGETKEYS:
	case SO_OP_OMAPGETVALS:
	case SO_OP_OMAPGETVALSBYKEYS: return op_omap(x, i, op->code, out);
	case SO_OP_CALL: return op_call(x, i, out);
	default: return -SO_EOPNOTSUPP;
	}
}

/* A write whose snapshot context is newer than the object's last-seen one preserves the head as a clone of the snapshots taken since. */
static int make_writeable(so_xc *x)
{
	so_obj *ob = x->obj;
	const so_req *rq = x->rq;
	uint64_t snaps[SO_SNAPS_CAP];
	uint32_t n = 0, k;

	if (rq->snap_seq <= ob->snapseq)
		return 0;
	if (ob->exists)
		for (k = 0; k < rq->n_snaps; k++)
			if (rq->snaps[k] > ob->snapseq)
				snaps[n++] = rq->snaps[k];
	if (n != 0 && so_obj_add_clone(ob, rq->snap_seq, snaps, n, &ob->head) != 0)
		return -1;
	ob->snapseq = rq->snap_seq;
	return 0;
}

/* Did the message make the object (or its data) grow, against the saved state? What the full-pool check of the OSD looks at. */
static int grew(const so_obj *before, const so_obj *now)
{
	if (!now->exists)
		return 0;
	return !before->exists || now->head.size > before->head.size;
}

static void execute(sim_osd_conn *c, uint64_t msg_tid, const so_req *rq, const so_opinfo *oi, int mutating, sim_osd_rec *rec, uint32_t ri)
{
	sim_osd *o = c->osd;
	sim_store *st = o->cfg.store;
	so_xc x;
	so_rep rep;
	so_obj bk;
	uint8_t key[SO_NAME_MAX + SO_NSPACE_MAX + 2u];
	uint32_t klen, i;
	int32_t result = 0;
	int failed = 0;
	so_dedup dd;

	memset(&x, 0, sizeof(x));
	memset(&bk, 0, sizeof(bk));
	rep_init(&rep, rq);
	x.c = c;
	x.o = o;
	x.rq = rq;
	x.rep = &rep;
	x.oi = oi;
	x.mutating = mutating;
	memcpy(x.oid, rq->oid, rq->oid_len);
	so_key_build(key, &klen, rq->nspace, rq->nspace_len, rq->oid, rq->oid_len);
	x.obj = mutating ? so_obj_get(st, rq->pool, key, klen) : so_obj_find(st, rq->pool, key, klen);
	if (mutating && x.obj == NULL) {
		reply_error(c, msg_tid, rq, rec, ri, -SO_EIO);
		return;
	}
	if (!mutating) {
		x.rb = x.obj != NULL ? so_obj_at(x.obj, rq->snapid) : NULL;
		if (x.rb == NULL) { /* every op reads: a missing object (or a whiteout) fails the whole message before anything runs */
			reply_error(c, msg_tid, rq, rec, ri, -SO_ENOENT);
			return;
		}
	} else {
		if ((rq->flags & SO_F_ORDERSNAP) != 0u && rq->snap_seq < x.obj->snapseq) {
			if (!x.obj->exists && !x.obj->whiteout && x.obj->nclones == 0)
				so_obj_purge(st, x.obj);
			reply_error(c, msg_tid, rq, rec, ri, -SO_EOLDSNAPC);
			return;
		}
		if (so_obj_copy_state(&bk, x.obj) != 0 || make_writeable(&x) != 0) {
			so_obj_wipe(&bk);
			reply_error(c, msg_tid, rq, rec, ri, -SO_EIO);
			return;
		}
	}
	rep.executed = 1;
	rec->executed = 1;
	for (i = 0; i < rq->n_ops; i++) {
		size_t before = rep.out.len;
		int32_t r = exec_op(&x, i, &rep.out);

		if (r < 0) {
			rep.out.len = before;
			rep.rval[i] = r;
			rep.outlen[i] = 0;
			if ((rq->ops[i].flags & SO_OPF_FAILOK) != 0u) {
				result = 0;
				continue;
			}
			result = r;
			failed = 1;
			break;
		}
		rep.rval[i] = r;
		rep.outlen[i] = (uint32_t)(rep.out.len - before);
		result = r;
	}
	rep.result = result;
	{
		const so_body *rb = mutating ? (x.obj->exists ? &x.obj->head : NULL) : x.rb;

		rep.user_version = rb != NULL ? rb->user_version : x.obj != NULL ? x.obj->head.user_version : 0;
	}
	if (mutating && !failed && x.dirty && o->cfg.fault.pool_full_drop && (rq->flags & SO_F_FULL_FORCE) == 0u && grew(&bk, x.obj)) {
		/* A full pool refuses what makes data or objects grow, and finds out by running the operations (the real check comes after the dry
		 * run: an overwrite in place, a ZERO, a TRUNCATE down and a DELETE go through): with FULL_TRY the answer is -ENOSPC, without it
		 * the request is dropped and nothing is sent. Nothing is applied either way. */
		so_obj_move_state(x.obj, &bk);
		so_obj_wipe(&bk);
		if (!x.obj->exists && !x.obj->whiteout && x.obj->nclones == 0)
			so_obj_purge(st, x.obj);
		so_buf_free(&rep.out);
		rec->executed = 0;
		if ((rq->flags & SO_F_FULL_TRY) != 0u)
			reply_error(c, msg_tid, rq, rec, ri, -SO_ENOSPC);
		return;
	}
	if (mutating) {
		if (failed || !x.dirty) { /* nothing is applied: the object goes back to what it was */
			so_obj_move_state(x.obj, &bk);
			rep.user_version = x.obj->exists ? x.obj->head.user_version : 0;
		} else {
			if (x.obj->exists) {
				x.obj->head.user_version++;
				x.obj->head.mtime_s = rq->mtime_s;
				x.obj->head.mtime_ns = rq->mtime_ns;
			}
			rep.user_version = x.obj->head.user_version;
			rep.replay_ver = ++st->pg_version;
			rep.replay_epoch = o->epoch != 0 ? o->epoch : rq->epoch;
			if ((rq->flags & 0x4000000u) == 0u) { /* no RETURNVEC: the output of a changed object is not returned, the rvals stay */
				rep.out.len = 0;
				for (i = 0; i < rq->n_ops; i++)
					rep.outlen[i] = 0;
				if (rep.result >= 0)
					rep.result = 0;
			}
			memset(&dd, 0, sizeof(dd));
			dd.gid = rq->gid;
			dd.tid = rq->tid;
			dd.inc = rq->client_inc;
			dd.result = rep.result;
			dd.user_version = rep.user_version;
			dd.replay_ver = rep.replay_ver;
			dd.replay_epoch = rep.replay_epoch;
			so_dedup_add(st, &dd);
		}
		so_obj_wipe(&bk); /* empty after a rollback, the saved copy after a commit */
		if (!x.obj->exists && !x.obj->whiteout && x.obj->nclones == 0) {
			so_obj_purge(st, x.obj);
			x.obj = NULL;
		}
	}
	deliver(c, msg_tid, rq, &rep, rec, ri);
	so_buf_free(&rep.out);
}

/* ---- one request ------------------------------------------------------------------------------------------------------------ */

static void park(sim_osd_conn *c, uint8_t version, uint64_t tid, const uint8_t *front, uint32_t flen, const uint8_t *data, uint32_t dlen)
{
	sim_osd *o = c->osd;
	so_parked *p;

	if (o->n_parked == SIM_OSD_HELD_MAX)
		return; /* more than the simulator waits for: dropped */
	p = &o->parked[o->n_parked];
	p->front = (uint8_t *)malloc(flen != 0 ? flen : 1u);
	p->data = (uint8_t *)malloc(dlen != 0 ? dlen : 1u);
	if (p->front == NULL || p->data == NULL) {
		free(p->front);
		free(p->data);
		return;
	}
	memcpy(p->front, front, flen);
	memcpy(p->data, data, dlen);
	p->c = c;
	p->version = version;
	p->tid = tid;
	p->flen = flen;
	p->dlen = dlen;
	o->n_parked++;
}

static void fill_rec(sim_osd_rec *rec, const sim_osd_conn *c, const so_req *rq)
{
	uint32_t i, l = rq->oid_len < SIM_OSD_NAME_MAX - 1u ? rq->oid_len : SIM_OSD_NAME_MAX - 1u;

	memset(rec, 0, sizeof(*rec));
	rec->conn = c->index;
	rec->tid = rq->tid;
	rec->global_id = rq->gid;
	rec->epoch = rq->epoch;
	rec->flags = rq->flags;
	rec->hash = rq->hash;
	rec->pg_seed = rq->pg_seed;
	rec->retry_attempt = (uint32_t)rq->retry_attempt;
	rec->pool = rq->pool;
	memcpy(rec->oid, rq->oid, l);
	rec->snapid = rq->snapid;
	rec->snap_seq = rq->snap_seq;
	rec->n_snaps = rq->n_snaps;
	rec->version = rq->version;
	rec->n_ops = rq->n_ops;
	rec->data_len = rq->data_len;
	for (i = 0; i < rq->n_ops && i < SIM_OSD_OPS_MAX; i++) {
		rec->op_code[i] = rq->ops[i].code;
		rec->op_off[i] = wri_le64_get(rq->ops[i].raw + 6);
		rec->op_len[i] = wri_le64_get(rq->ops[i].raw + 14);
	}
	rec->result = INT32_MIN;
}

static int snapc_valid(const so_req *rq)
{
	uint32_t i;

	if (rq->snap_seq > SO_SNAP_MAX)
		return 0;
	if (rq->n_snaps != 0 && rq->snaps[0] > rq->snap_seq)
		return 0;
	for (i = 1; i < rq->n_snaps; i++)
		if (rq->snaps[i] >= rq->snaps[i - 1u] || rq->snaps[i - 1u] == 0)
			return 0;
	return 1;
}

void so_handle_osdop(sim_osd_conn *c, uint8_t version, uint64_t msg_tid, const uint8_t *front, uint32_t flen, const uint8_t *data,
		     uint32_t dlen, int parked)
{
	sim_osd *o = c->osd;
	sim_osd_fault *f = &o->cfg.fault;
	so_req *rq = (so_req *)malloc(sizeof(*rq));
	so_opinfo *oi = (so_opinfo *)malloc(sizeof(*oi) * SO_OPS_CAP);
	sim_osd_rec dummy, *rec;
	uint32_t ri = UINT32_MAX;
	const char *why;
	int mutating = 0, i_cut = 0;
	int32_t cerr;

	if (rq == NULL || oi == NULL) {
		free(rq);
		free(oi);
		return;
	}
	why = decode_req(c, version, msg_tid, front, flen, data, dlen, rq);
	if (why != NULL) {
		so_violation(c, why, flen, dlen);
		goto out;
	}
	o->n_requests++;
	if (o->n_recs < SIM_OSD_REC_MAX) {
		ri = o->n_recs++;
		rec = &o->recs[ri];
	} else {
		rec = &dummy;
	}
	fill_rec(rec, c, rq);
	rec->parked = (uint8_t)parked;
	cerr = classify(o, rq, oi, &mutating);
	rec->mutating = (uint8_t)mutating;
	i_cut = f->cut_after_ops != 0;

	if (f->silent)
		goto handled;
	if (f->min_epoch != 0 && rq->epoch < f->min_epoch)
		goto handled;
	if (o->cfg.check_primary && o->cfg.is_primary != NULL &&
	    !o->cfg.is_primary(o->cfg.is_primary_ctx, o->cfg.id, rq->pool, rq->pg_seed, rq->hash, rq->epoch))
		goto handled;
	if (o->epoch != 0 && rq->epoch > o->epoch) { /* the OSD must first get the newer map */
		park(c, version, msg_tid, front, flen, data, dlen);
		rec->parked = 1;
		goto handled;
	}
	if (so_backoff_covers(c, rq)) {
		o->n_backoff_drops++;
		rec->backoff_drop = 1;
		goto handled;
	}
	if (f->eagain_ops != 0) {
		f->eagain_ops--;
		reply_error(c, msg_tid, rq, rec, ri, -SO_EAGAIN);
		goto handled;
	}
	if (f->redirect) {
		so_rep rep;

		rep_init(&rep, rq);
		rep.result = -SO_ENOENT;
		rep.do_redirect = 1;
		rep.redirect_pool = rq->pool + 1;
		deliver(c, msg_tid, rq, &rep, rec, ri);
		so_buf_free(&rep.out);
		goto handled;
	}
	if (rq->oid_len == 0) {
		reply_error(c, msg_tid, rq, rec, ri, -SO_EINVAL);
		goto handled;
	}
	if (rq->oid_len > SO_NAME_MAX || rq->key_len > SO_NAME_MAX || rq->nspace_len > SO_NSPACE_MAX) {
		reply_error(c, msg_tid, rq, rec, ri, -SO_ENAMETOOLONG);
		goto handled;
	}
	if ((rq->flags & SO_F_PARALLELEXEC) != 0u) {
		reply_error(c, msg_tid, rq, rec, ri, -SO_EINVAL);
		goto handled;
	}
	if (mutating && (rq->snapid != SO_SNAP_NOSNAP || !snapc_valid(rq))) {
		reply_error(c, msg_tid, rq, rec, ri, -SO_EINVAL);
		goto handled;
	}
	if (mutating && rq->data_len > o->cfg.max_write_bytes) {
		reply_error(c, msg_tid, rq, rec, ri, -SO_EMSGSIZE);
		goto handled;
	}
	if (cerr != 0) {
		reply_error(c, msg_tid, rq, rec, ri, cerr);
		goto handled;
	}
	if (f->force_errno_op != 0) {
		uint32_t i;

		for (i = 0; i < rq->n_ops; i++)
			if (rq->ops[i].code == (uint16_t)f->force_errno_op) {
				reply_error(c, msg_tid, rq, rec, ri, f->force_errno);
				goto handled;
			}
	}
	if (mutating && !f->no_dedup) {
		const so_dedup *d = so_dedup_find(o->cfg.store, rq->gid, rq->tid, rq->client_inc);

		if (d != NULL) { /* a resent write: the stored result, nothing is applied again (the PG log, osd-ops.md 3.6) */
			so_rep rep;

			rep_init(&rep, rq);
			rep.result = d->result;
			rep.executed = 1;
			rep.replay_ver = d->replay_ver;
			rep.replay_epoch = d->replay_epoch;
			rep.user_version = d->user_version;
			rec->duplicate = 1;
			deliver(c, msg_tid, rq, &rep, rec, ri);
			so_buf_free(&rep.out);
			goto handled;
		}
	}
	execute(c, msg_tid, rq, oi, mutating, rec, ri);
handled:
	if (i_cut && o->cfg.fault.cut_after_ops != 0 && ++o->cut_count >= o->cfg.fault.cut_after_ops) {
		o->cfg.fault.cut_after_ops = 0;
		o->cut_count = 0;
		so_cut_all(o);
	}
out:
	free(rq);
	free(oi);
}

void so_on_message(void *ctx, sim_m2 *s, const sim_m2_msg *m)
{
	sim_osd_conn *c = (sim_osd_conn *)ctx;
	const uint8_t *front = m->seg[0] != NULL ? m->seg[0] : (const uint8_t *)"";
	uint32_t flen = m->seg_len[0];

	(void)s;
	if (c->killed)
		return;
	c->n_msgs++;
	if (m->type == SO_MSG_OSD_OP) {
		if (m->seg_len[1] != 0u) {
			so_violation(c, "MOSDOp has a middle segment", m->seg_len[1], 0);
			return;
		}
		if (m->version != 9u && m->version != 8u) {
			so_violation(c, "MOSDOp version is neither 9 nor 8", m->version, 0);
			return;
		}
		if (m->version == 9u && c->osd->cfg.v8_only) {
			so_violation(c, "MOSDOp v9 to an OSD that only decodes v8", 9, 0);
			return;
		}
		so_handle_osdop(c, (uint8_t)m->version, m->tid, front, flen, m->seg[2] != NULL ? m->seg[2] : (const uint8_t *)"", m->seg_len[2], 0);
	} else if (m->type == SO_MSG_OSD_BACKOFF) {
		so_backoff_note(c, front, flen);
	} else {
		c->osd->n_other++;
	}
}
