/* SPDX-License-Identifier: MIT */
/*
 * sim_osd_cls.c - the object classes of the fake OSD and the RBD image fixtures. Written from docs/spec/rbd-format2.md 2.1 to 2.8 (the header
 * objects, the omap keys of 2.4, the read methods of 2.3, the lock class of 2.7, the feature masks of 2.8) and checked against the vectors in
 * harness/vectors/rbd. The header state is real omap data of `rbd_header.<id>` in the shared store, encoded as the note says, so an omap read
 * and a class call see the same bytes; the lock record is the xattr `lock.<name>`. The class methods are plain functions over one object body.
 * Test code: libc allowed.
 */
#include "sim_osd_int.h"

#define F_LAYERING 0x1u
#define F_STRIPINGV2 0x2u
#define F_RO_INCOMPAT 0x883u  /* layering | striping | data pool | dirty cache (rbd-format2.md 2.8) */
#define F_RW_INCOMPAT 0xfffu  /* every bit the OSD knows */
#define F_ALL 0xfffu

/* ---- small decoding helpers ----------------------------------------------------------------------------------------- */

static int32_t finish_rd(const wri_rd *r) { return wri_rd_ok(r) ? 0 : -SO_EINVAL; }

/* a string read into a bounded NUL terminated buffer; 0 or -EINVAL */
static const uint8_t *rd_str(wri_rd *r, uint32_t *len)
{
	const uint8_t *p = wri_denc_blob(r, len, 1u << 16);

	return wri_rd_ok(r) ? p : NULL;
}

static void put_utime(so_buf *b, uint32_t s, uint32_t ns)
{
	so_buf_u32(b, s);
	so_buf_u32(b, ns);
}

/* ---- the rbd class: header state ------------------------------------------------------------------------------------ */

static int32_t kv_u64(const so_cctx *cx, const char *k, uint64_t *v, int32_t missing)
{
	const so_kv *kv = so_kv_get(&cx->body->omap, k, (uint32_t)strlen(k));

	if (kv == NULL)
		return missing;
	if (kv->vl != 8u)
		return -SO_EIO;
	*v = wri_le64_get(kv->v);
	return 0;
}

static void snap_key(char out[26], uint64_t id) { snprintf(out, 26, "snapshot_%016llx", (unsigned long long)id); }

typedef struct so_snaprec {
	uint64_t id, image_size, flags, overlap;
	uint8_t has_overlap;
} so_snaprec;

static int32_t snap_get(const so_cctx *cx, uint64_t id, so_snaprec *sr)
{
	char k[26];
	const so_kv *kv;
	wri_rd r;
	wri_env e;
	uint32_t nl;

	snap_key(k, id);
	kv = so_kv_get(&cx->body->omap, k, (uint32_t)strlen(k));
	if (kv == NULL)
		return -SO_ENOENT;
	wri_rd_init(&r, kv->v, kv->vl);
	if (wri_env_open(&r, 8, &e) != WR_OK)
		return -SO_EIO;
	memset(sr, 0, sizeof(*sr));
	sr->id = wri_rd_u64(&e.body);
	(void)rd_str(&e.body, &nl);
	sr->image_size = wri_rd_u64(&e.body);
	sr->flags = wri_rd_u64(&e.body);
	sr->has_overlap = wri_rd_u8(&e.body);
	sr->overlap = wri_rd_u64(&e.body);
	return wri_rd_ok(&e.body) ? 0 : -SO_EIO;
}

static int32_t m_get_size(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	uint64_t snap, size = 0;
	const so_kv *ord;
	int32_t rc;

	wri_rd_init(&r, in, n);
	snap = wri_rd_u64(&r);
	if (finish_rd(&r) != 0)
		return -SO_EINVAL;
	ord = so_kv_get(&cx->body->omap, "order", 5);
	if (!cx->exists || ord == NULL)
		return -SO_ENOENT; /* the order key is read before the size */
	if (ord->vl != 1u)
		return -SO_EIO;
	if (snap == SO_SNAP_NOSNAP) {
		rc = kv_u64(cx, "size", &size, -SO_ENOENT);
		if (rc != 0)
			return rc;
	} else {
		so_snaprec sr;

		rc = snap_get(cx, snap, &sr);
		if (rc != 0)
			return rc;
		size = sr.image_size;
	}
	so_buf_u8(out, ord->v[0]);
	so_buf_u64(out, size);
	return 0;
}

static int32_t m_get_features(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	uint64_t f = 0;
	uint8_t ro = 0;
	int32_t rc;

	wri_rd_init(&r, in, n);
	(void)wri_rd_u64(&r); /* the snapshot id: read and ignored */
	if (!wri_rd_ok(&r))
		return -SO_EINVAL;
	if (wri_rd_left(&r) != 0)
		ro = wri_rd_u8(&r); /* optional; any value, any trailing bytes accepted */
	rc = kv_u64(cx, "features", &f, -SO_ENOENT);
	if (rc != 0)
		return rc;
	so_buf_u64(out, f);
	so_buf_u64(out, f & (ro != 0 ? F_RO_INCOMPAT : F_RW_INCOMPAT));
	return 0;
}

static int32_t m_get_object_prefix(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	const so_kv *kv = so_kv_get(&cx->body->omap, "object_prefix", 13);
	wri_rd r;
	uint32_t l;

	(void)in, (void)n;
	if (kv == NULL)
		return -SO_ENOENT;
	wri_rd_init(&r, kv->v, kv->vl);
	(void)rd_str(&r, &l);
	if (!wri_rd_ok(&r))
		return -SO_EIO;
	so_buf_put(out, kv->v, 4u + l);
	return 0;
}

static int32_t m_get_snapcontext(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	uint64_t seq = 0, *ids;
	uint32_t i, cnt = 0, int_i;
	int32_t rc;

	(void)in, (void)n;
	rc = kv_u64(cx, "snap_seq", &seq, -SO_ENOENT);
	if (rc != 0)
		return rc;
	ids = (uint64_t *)calloc(cx->body->omap.n + 1u, sizeof(uint64_t));
	if (ids == NULL)
		return -SO_EIO;
	for (i = 0; i < cx->body->omap.n; i++) {
		const so_kv *kv = &cx->body->omap.a[i];
		uint64_t v = 0;
		uint32_t k;

		if (kv->kl != 25u || memcmp(kv->k, "snapshot_", 9) != 0)
			continue;
		for (k = 9; k < 25u; k++) {
			uint8_t ch = kv->k[k];

			v = v * 16u + (uint64_t)(ch >= 'a' ? ch - 'a' + 10 : ch - '0');
		}
		ids[cnt++] = v;
	}
	so_buf_u64(out, seq);
	so_buf_u32(out, cnt);
	for (int_i = cnt; int_i > 0; int_i--) /* descending: the keys come in ascending order */
		so_buf_u64(out, ids[int_i - 1u]);
	free(ids);
	return 0;
}

static int32_t m_get_data_pool(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	uint64_t v = 0;
	int32_t rc = kv_u64(cx, "data_pool_id", &v, 1);

	(void)in, (void)n;
	if (rc < 0)
		return rc;
	so_buf_u64(out, rc == 1 ? UINT64_MAX : v); /* -1 when absent */
	return 0;
}

static int32_t m_get_stripe_unit_count(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	uint64_t f = 0, su = 0, sc = 0;
	const so_kv *ord = so_kv_get(&cx->body->omap, "order", 5);
	int32_t rc;

	(void)in, (void)n;
	rc = kv_u64(cx, "features", &f, -SO_ENOENT);
	if (rc != 0)
		return rc;
	if ((f & F_STRIPINGV2) == 0)
		return -SO_ENOEXEC;
	rc = kv_u64(cx, "stripe_unit", &su, 1); /* each key has its own default, as the class reads them one by one */
	if (rc < 0)
		return rc;
	if (rc == 1) {
		if (ord == NULL || ord->vl != 1u)
			return -SO_EIO; /* the order is read for the default and must be there */
		su = 1ull << ord->v[0];
	}
	rc = kv_u64(cx, "stripe_count", &sc, 1);
	if (rc < 0)
		return rc;
	if (rc == 1)
		sc = 1;
	so_buf_u64(out, su);
	so_buf_u64(out, sc);
	return 0;
}

static int32_t m_get_flags(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	uint64_t snap, v = 0;
	int32_t rc;

	wri_rd_init(&r, in, n);
	snap = wri_rd_u64(&r);
	if (finish_rd(&r) != 0)
		return -SO_EINVAL;
	if (snap == SO_SNAP_NOSNAP) {
		rc = kv_u64(cx, "flags", &v, 1);
		if (rc < 0)
			return rc;
		if (rc == 1)
			v = 0;
	} else {
		so_snaprec sr;

		rc = snap_get(cx, snap, &sr);
		if (rc != 0)
			return rc;
		v = sr.flags;
	}
	so_buf_u64(out, v);
	return 0;
}

static int32_t m_op_features_get(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	uint64_t v = 0;
	int32_t rc = kv_u64(cx, "op_features", &v, 1);

	(void)in, (void)n;
	if (rc < 0)
		return rc;
	so_buf_u64(out, rc == 1 ? 0 : v);
	return 0;
}

static int32_t m_get_all_features(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	(void)cx, (void)in, (void)n;
	so_buf_u64(out, F_ALL);
	return 0;
}

static int32_t m_get_timestamp(so_cctx *cx, so_buf *out, const char *key)
{
	const so_kv *kv = so_kv_get(&cx->body->omap, key, (uint32_t)strlen(key));

	if (kv == NULL)
		return -SO_ENOENT;
	if (kv->vl != 8u)
		return -SO_EIO;
	so_buf_put(out, kv->v, 8);
	return 0;
}

static int32_t m_get_create_timestamp(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	(void)in, (void)n;
	return m_get_timestamp(cx, out, "create_timestamp");
}

static int32_t m_get_access_timestamp(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	(void)in, (void)n;
	return m_get_timestamp(cx, out, "access_timestamp");
}

static int32_t m_get_modify_timestamp(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	(void)in, (void)n;
	return m_get_timestamp(cx, out, "modify_timestamp");
}

/* the parent record of the header: struct v2/2 { i64 pool, string ns, string image id, u64 snap id, u8 present, u64 overlap } */
typedef struct so_parentrec {
	int64_t pool;
	const uint8_t *ns, *id;
	uint32_t nsl, idl;
	uint64_t snap_id, overlap;
	uint8_t has_overlap;
} so_parentrec;

static int32_t parent_get_rec(const so_cctx *cx, so_parentrec *p, int *have)
{
	const so_kv *kv = so_kv_get(&cx->body->omap, "parent", 6);
	wri_rd r;
	wri_env e;

	*have = 0;
	memset(p, 0, sizeof(*p));
	if (kv == NULL)
		return 0;
	wri_rd_init(&r, kv->v, kv->vl);
	if (wri_env_open(&r, 2, &e) != WR_OK)
		return -SO_EIO;
	p->pool = wri_rd_i64(&e.body);
	p->ns = rd_str(&e.body, &p->nsl);
	p->id = rd_str(&e.body, &p->idl);
	p->snap_id = wri_rd_u64(&e.body);
	p->has_overlap = wri_rd_u8(&e.body);
	p->overlap = wri_rd_u64(&e.body);
	if (!wri_rd_ok(&e.body))
		return -SO_EIO;
	*have = 1;
	return 0;
}

static int32_t m_parent_get(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	uint64_t f = 0;
	so_parentrec p;
	int have = 0;
	int32_t rc = kv_u64(cx, "features", &f, -SO_ENOENT);
	uint8_t tmp[256];
	wri_wr w;

	(void)in, (void)n;
	if (rc != 0)
		return rc;
	if ((f & F_LAYERING) != 0u) {
		rc = parent_get_rec(cx, &p, &have);
		if (rc != 0)
			return rc;
	}
	wri_wr_init(&w, tmp, sizeof(tmp)); /* ParentImageSpec: struct v1/1 { i64 pool, string ns, string image id, u64 snap id } */
	{
		size_t mark = wri_env_begin(&w, 1, 1);

		if (have && p.pool >= 0 && p.idl != 0 && p.snap_id != SO_SNAP_NOSNAP) {
			wri_wr_i64(&w, p.pool);
			wri_denc_put_str(&w, p.ns, p.nsl);
			wri_denc_put_str(&w, p.id, p.idl);
			wri_wr_u64(&w, p.snap_id);
		} else {
			wri_wr_i64(&w, -1);
			wri_denc_put_str(&w, (const uint8_t *)"", 0);
			wri_denc_put_str(&w, (const uint8_t *)"", 0);
			wri_wr_u64(&w, SO_SNAP_NOSNAP);
		}
		wri_env_end(&w, mark);
	}
	if (!wri_wr_ok(&w))
		return -SO_EIO;
	so_buf_put(out, tmp, wri_wr_len(&w));
	return 0;
}

static int32_t m_parent_overlap_get(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	uint64_t snap, f = 0, ov = 0;
	uint8_t has = 0;
	int32_t rc;

	wri_rd_init(&r, in, n);
	snap = wri_rd_u64(&r);
	if (finish_rd(&r) != 0)
		return -SO_EINVAL;
	rc = kv_u64(cx, "features", &f, -SO_ENOENT);
	if (rc != 0)
		return rc;
	if ((f & F_LAYERING) != 0u) {
		if (snap == SO_SNAP_NOSNAP) {
			so_parentrec p;
			int have = 0;

			rc = parent_get_rec(cx, &p, &have);
			if (rc != 0)
				return rc;
			if (have && p.has_overlap) {
				has = 1;
				ov = p.overlap;
			}
		} else {
			so_snaprec sr;

			rc = snap_get(cx, snap, &sr);
			if (rc != 0)
				return rc;
			has = sr.has_overlap;
			ov = sr.overlap;
		}
	}
	so_buf_u8(out, has);
	if (has)
		so_buf_u64(out, ov);
	return 0;
}

/* get_parent (legacy, still served for old clients): i64 pool, string image id, u64 snap id, u64 overlap */
static int32_t m_get_parent(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	uint64_t snap, f = 0, ov = 0;
	so_parentrec p;
	int have = 0;
	int32_t rc;

	wri_rd_init(&r, in, n);
	snap = wri_rd_u64(&r);
	if (finish_rd(&r) != 0)
		return -SO_EINVAL;
	rc = kv_u64(cx, "features", &f, -SO_ENOENT);
	if (rc != 0)
		return rc;
	if ((f & F_LAYERING) != 0u) {
		rc = parent_get_rec(cx, &p, &have);
		if (rc != 0)
			return rc;
		if (have && snap != SO_SNAP_NOSNAP) {
			so_snaprec sr;

			rc = snap_get(cx, snap, &sr);
			if (rc != 0)
				return rc;
			ov = sr.has_overlap ? sr.overlap : 0;
		} else if (have) {
			ov = p.has_overlap ? p.overlap : 0;
		}
	}
	if (have && p.pool >= 0 && p.idl != 0 && p.snap_id != SO_SNAP_NOSNAP) {
		so_buf_u64(out, (uint64_t)p.pool);
		so_buf_str(out, p.id, p.idl);
		so_buf_u64(out, p.snap_id);
		so_buf_u64(out, ov);
	} else {
		so_buf_u64(out, UINT64_MAX);
		so_buf_str(out, "", 0);
		so_buf_u64(out, SO_SNAP_NOSNAP);
		so_buf_u64(out, 0);
	}
	return 0;
}

/* get_id: the id object holds one encoded string */
static int32_t m_get_id(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	uint8_t *tmp;
	wri_rd r;
	uint32_t l;

	(void)in, (void)n;
	if (!cx->exists || cx->body->size == 0)
		return -SO_ENOENT;
	if (cx->body->size > (1u << 16))
		return -SO_EIO;
	tmp = (uint8_t *)malloc((size_t)cx->body->size);
	if (tmp == NULL)
		return -SO_EIO;
	so_body_read(cx->body, 0, tmp, cx->body->size);
	wri_rd_init(&r, tmp, (size_t)cx->body->size);
	(void)rd_str(&r, &l);
	if (!wri_rd_ok(&r)) {
		free(tmp);
		return -SO_EIO;
	}
	so_buf_put(out, tmp, 4u + l);
	free(tmp);
	return 0;
}

static int32_t dir_lookup(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out, const char *prefix)
{
	wri_rd r;
	uint32_t l;
	const uint8_t *s;
	uint8_t *k;
	const so_kv *kv;
	size_t pl = strlen(prefix);

	wri_rd_init(&r, in, n);
	s = rd_str(&r, &l);
	if (s == NULL)
		return -SO_EINVAL;
	k = (uint8_t *)malloc(pl + l + 1u);
	if (k == NULL)
		return -SO_EIO;
	memcpy(k, prefix, pl);
	memcpy(k + pl, s, l);
	kv = so_kv_get(&cx->body->omap, k, (uint32_t)(pl + l));
	free(k);
	if (kv == NULL)
		return -SO_ENOENT;
	so_buf_put(out, kv->v, kv->vl);
	return 0;
}

static int32_t m_dir_get_id(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out) { return dir_lookup(cx, in, n, out, "name_"); }
static int32_t m_dir_get_name(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out) { return dir_lookup(cx, in, n, out, "id_"); }

/* set_size: a method that WRITES, to show up as a mutating class call */
static int32_t m_set_size(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	uint64_t size;
	uint8_t t[8];

	(void)out;
	wri_rd_init(&r, in, n);
	size = wri_rd_u64(&r);
	if (finish_rd(&r) != 0)
		return -SO_EINVAL;
	if (!cx->exists || so_kv_get(&cx->body->omap, "size", 4) == NULL)
		return -SO_ENOENT;
	wri_le64_put(t, size);
	if (so_kv_set(&cx->body->omap, "size", 4, t, 8) != 0)
		return -SO_EIO;
	cx->dirty = 1;
	return 0;
}

/* ---- the lock class ------------------------------------------------------------------------------------------------- */

#define SO_LOCKERS 32u
#define LOCK_NONE 0u
#define LOCK_EXCLUSIVE 1u
#define LOCK_SHARED 2u
#define LOCK_EPHEMERAL 3u
#define LOCK_MAY_RENEW 0x1u
#define LOCK_MUST_RENEW 0x2u

typedef struct so_locker {
	uint8_t etype;
	int64_t num;
	const uint8_t *cookie, *desc;
	uint32_t cl, dl;
	uint32_t exp_s, exp_ns;
	uint8_t addr[35];
} so_locker;

typedef struct so_lockrec {
	so_locker l[SO_LOCKERS];
	uint32_t n;
	uint8_t type;
	const uint8_t *tag;
	uint32_t tl;
} so_lockrec;

static int lock_name_key(char *out, size_t cap, const uint8_t *name, uint32_t nl)
{
	if (nl == 0 || nl + 6u > cap)
		return -1;
	memcpy(out, "lock.", 5);
	memcpy(out + 5, name, nl);
	out[5 + nl] = '\0';
	return 0;
}

/* Decodes a stored record (the get_info reply form); pointers point into `raw`. */
static int32_t lockrec_decode(so_lockrec *rec, const uint8_t *raw, uint32_t rl)
{
	wri_rd r;
	wri_env e;
	uint32_t cnt, i;

	memset(rec, 0, sizeof(*rec));
	wri_rd_init(&r, raw, rl);
	if (wri_env_open(&r, 1, &e) != WR_OK)
		return -SO_EIO;
	cnt = wri_rd_count(&e.body, SO_LOCKERS, 12);
	for (i = 0; i < cnt && wri_rd_ok(&e.body); i++) {
		wri_env id, info;
		so_locker *l = &rec->l[i];
		const uint8_t *a;

		if (wri_env_open(&e.body, 1, &id) != WR_OK || wri_env_open(&e.body, 1, &info) != WR_OK)
			return -SO_EIO;
		l->etype = wri_rd_u8(&id.body);
		l->num = wri_rd_i64(&id.body);
		l->cookie = rd_str(&id.body, &l->cl);
		l->exp_s = wri_rd_u32(&info.body);
		l->exp_ns = wri_rd_u32(&info.body);
		a = wri_rd_bytes(&info.body, 35);
		if (a != NULL)
			memcpy(l->addr, a, 35);
		l->desc = rd_str(&info.body, &l->dl);
		if (!wri_rd_ok(&id.body) || !wri_rd_ok(&info.body))
			return -SO_EIO;
	}
	rec->n = cnt;
	rec->type = wri_rd_u8(&e.body);
	rec->tag = rd_str(&e.body, &rec->tl);
	return wri_rd_ok(&e.body) ? 0 : -SO_EIO;
}

static void lockrec_encode(const so_lockrec *rec, so_buf *b)
{
	size_t mark = b->len;
	uint32_t i;

	so_buf_u8(b, 1);
	so_buf_u8(b, 1);
	so_buf_u32(b, 0);
	so_buf_u32(b, rec->n);
	for (i = 0; i < rec->n; i++) {
		const so_locker *l = &rec->l[i];
		size_t m1 = b->len, m2;

		so_buf_u8(b, 1);
		so_buf_u8(b, 1);
		so_buf_u32(b, 0);
		so_buf_u8(b, l->etype);
		so_buf_u64(b, (uint64_t)l->num);
		so_buf_str(b, l->cookie, l->cl);
		if (!b->oom)
			wri_le32_put(b->p + m1 + 2, (uint32_t)(b->len - m1 - 6u));
		m2 = b->len;
		so_buf_u8(b, 1);
		so_buf_u8(b, 1);
		so_buf_u32(b, 0);
		put_utime(b, l->exp_s, l->exp_ns);
		so_buf_put(b, l->addr, 35);
		so_buf_str(b, l->desc, l->dl);
		if (!b->oom)
			wri_le32_put(b->p + m2 + 2, (uint32_t)(b->len - m2 - 6u));
	}
	so_buf_u8(b, rec->type);
	so_buf_str(b, rec->tag, rec->tl);
	if (!b->oom)
		wri_le32_put(b->p + mark + 2, (uint32_t)(b->len - mark - 6u));
}

/* Loads lock `name` from the object (`raw` receives a private copy the pointers of the record refer to). 0 = a record (or none: empty), <0 = error. */
static int32_t lock_load(const so_cctx *cx, const uint8_t *name, uint32_t nl, so_lockrec *rec, so_buf *raw, int *have)
{
	char key[96];
	const so_kv *kv;
	uint32_t i, j;
	int32_t rc;

	*have = 0;
	memset(rec, 0, sizeof(*rec));
	if (lock_name_key(key, sizeof(key), name, nl) != 0)
		return -SO_EINVAL;
	kv = so_kv_get(&cx->body->xattr, key, (uint32_t)strlen(key));
	if (kv == NULL)
		return 0;
	so_buf_put(raw, kv->v, kv->vl);
	if (raw->oom)
		return -SO_EIO;
	rc = lockrec_decode(rec, raw->p, (uint32_t)raw->len);
	if (rc != 0)
		return rc;
	*have = 1;
	for (i = j = 0; i < rec->n; i++) { /* expired lockers are not there */
		if (rec->l[i].exp_s != 0u || rec->l[i].exp_ns != 0u) {
			if ((uint64_t)rec->l[i].exp_s <= cx->now_s)
				continue;
		}
		if (i != j)
			rec->l[j] = rec->l[i];
		j++;
	}
	rec->n = j;
	return 0;
}

static int32_t lock_store(so_cctx *cx, const uint8_t *name, uint32_t nl, const so_lockrec *rec)
{
	char key[96];
	so_buf b;
	int rc;

	if (lock_name_key(key, sizeof(key), name, nl) != 0)
		return -SO_EINVAL;
	memset(&b, 0, sizeof(b));
	lockrec_encode(rec, &b);
	if (b.oom) {
		so_buf_free(&b);
		return -SO_EIO;
	}
	rc = so_kv_set(&cx->body->xattr, key, (uint32_t)strlen(key), b.p, (uint32_t)b.len);
	so_buf_free(&b);
	if (rc != 0)
		return -SO_EIO;
	cx->dirty = 1;
	return 0;
}

static int lock_find(const so_lockrec *rec, uint8_t etype, int64_t num, const uint8_t *cookie, uint32_t cl)
{
	uint32_t i;

	for (i = 0; i < rec->n; i++)
		if (rec->l[i].etype == etype && rec->l[i].num == num && rec->l[i].cl == cl && (cl == 0 || memcmp(rec->l[i].cookie, cookie, cl) == 0))
			return (int)i;
	return -1;
}

static int32_t m_lock_get_info(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	wri_env e;
	const uint8_t *name;
	uint32_t nl;
	so_lockrec rec;
	so_buf raw;
	int have;
	int32_t rc;

	wri_rd_init(&r, in, n);
	if (wri_env_open(&r, 1, &e) != WR_OK)
		return -SO_EINVAL;
	name = rd_str(&e.body, &nl);
	if (name == NULL)
		return -SO_EINVAL;
	if (!cx->exists)
		return -SO_ENOENT;
	memset(&raw, 0, sizeof(raw));
	rc = lock_load(cx, name, nl, &rec, &raw, &have);
	if (rc == 0)
		lockrec_encode(&rec, out); /* none: an empty map, type 0, empty tag */
	so_buf_free(&raw);
	return rc;
}

static int32_t m_lock_lock(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	wri_env e;
	const uint8_t *name, *cookie, *tag, *desc;
	uint32_t nl, cl, tl, dl, dur_s, dur_ns, i;
	uint8_t type, flags;
	so_lockrec rec;
	so_buf raw;
	int have, at;
	int32_t rc;

	(void)out;
	wri_rd_init(&r, in, n);
	if (wri_env_open(&r, 1, &e) != WR_OK)
		return -SO_EINVAL;
	name = rd_str(&e.body, &nl);
	type = wri_rd_u8(&e.body);
	cookie = rd_str(&e.body, &cl);
	tag = rd_str(&e.body, &tl);
	desc = rd_str(&e.body, &dl);
	dur_s = wri_rd_u32(&e.body);
	dur_ns = wri_rd_u32(&e.body);
	flags = wri_rd_u8(&e.body);
	if (!wri_rd_ok(&e.body))
		return -SO_EINVAL;
	if ((type != LOCK_EXCLUSIVE && type != LOCK_SHARED && type != LOCK_EPHEMERAL) || nl == 0 ||
	    (flags & (LOCK_MAY_RENEW | LOCK_MUST_RENEW)) == (LOCK_MAY_RENEW | LOCK_MUST_RENEW))
		return -SO_EINVAL;
	memset(&raw, 0, sizeof(raw));
	rc = lock_load(cx, name, nl, &rec, &raw, &have);
	if (rc != 0)
		goto done;
	rc = -SO_EBUSY;
	if (rec.n != 0 && (rec.tl != tl || (tl != 0 && memcmp(rec.tag, tag, tl) != 0)))
		goto done;
	at = lock_find(&rec, 8, (int64_t)cx->gid, cookie, cl);
	if (at >= 0 && (flags & LOCK_MAY_RENEW) == 0u) {
		rc = -SO_EEXIST;
		goto done;
	}
	if (at < 0 && (flags & LOCK_MUST_RENEW) != 0u) {
		rc = -SO_ENOENT;
		goto done;
	}
	if (type == LOCK_EXCLUSIVE && rec.n != 0 && !(at >= 0 && rec.n == 1u))
		goto done;
	if (rec.n != 0 && rec.type != type)
		goto done;
	if (at < 0) {
		if (rec.n == SO_LOCKERS)
			goto done;
		at = (int)rec.n++;
	}
	{
		so_locker *l = &rec.l[at];

		l->etype = 8;
		l->num = (int64_t)cx->gid;
		l->cookie = cookie;
		l->cl = cl;
		l->desc = desc;
		l->dl = dl;
		memcpy(l->addr, cx->addr, 35);
		if (dur_s != 0u || dur_ns != 0u) {
			l->exp_s = (uint32_t)(cx->now_s + dur_s);
			l->exp_ns = dur_ns;
		} else {
			l->exp_s = l->exp_ns = 0;
		}
	}
	rec.type = type;
	rec.tag = tag;
	rec.tl = tl;
	(void)i;
	rc = lock_store(cx, name, nl, &rec);
done:
	so_buf_free(&raw);
	return rc;
}

static int32_t m_lock_unlock(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	wri_env e;
	const uint8_t *name, *cookie;
	uint32_t nl, cl;
	so_lockrec rec;
	so_buf raw;
	int have, at;
	int32_t rc;

	(void)out;
	wri_rd_init(&r, in, n);
	if (wri_env_open(&r, 1, &e) != WR_OK)
		return -SO_EINVAL;
	name = rd_str(&e.body, &nl);
	cookie = rd_str(&e.body, &cl);
	if (!wri_rd_ok(&e.body))
		return -SO_EINVAL;
	memset(&raw, 0, sizeof(raw));
	rc = lock_load(cx, name, nl, &rec, &raw, &have);
	if (rc == 0) {
		at = have ? lock_find(&rec, 8, (int64_t)cx->gid, cookie, cl) : -1;
		if (at < 0) {
			rc = -SO_ENOENT;
		} else {
			memmove(&rec.l[at], &rec.l[at + 1], (size_t)(rec.n - (uint32_t)at - 1u) * sizeof(rec.l[0]));
			rec.n--;
			rc = lock_store(cx, name, nl, &rec); /* the record stays, with an empty map */
		}
	}
	so_buf_free(&raw);
	return rc;
}

static int32_t m_lock_break(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	wri_env e;
	const uint8_t *name, *cookie;
	uint32_t nl, cl;
	uint8_t etype;
	int64_t num;
	so_lockrec rec;
	so_buf raw;
	int have, at;
	int32_t rc;

	(void)out;
	wri_rd_init(&r, in, n);
	if (wri_env_open(&r, 1, &e) != WR_OK)
		return -SO_EINVAL;
	name = rd_str(&e.body, &nl);
	etype = wri_rd_u8(&e.body);
	num = wri_rd_i64(&e.body);
	cookie = rd_str(&e.body, &cl);
	if (!wri_rd_ok(&e.body))
		return -SO_EINVAL;
	memset(&raw, 0, sizeof(raw));
	rc = lock_load(cx, name, nl, &rec, &raw, &have);
	if (rc == 0) {
		at = have ? lock_find(&rec, etype, num, cookie, cl) : -1;
		if (at < 0) {
			rc = -SO_ENOENT;
		} else {
			memmove(&rec.l[at], &rec.l[at + 1], (size_t)(rec.n - (uint32_t)at - 1u) * sizeof(rec.l[0]));
			rec.n--;
			rc = lock_store(cx, name, nl, &rec);
		}
	}
	so_buf_free(&raw);
	return rc;
}

static int32_t m_lock_assert(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	wri_env e;
	const uint8_t *name, *cookie, *tag;
	uint32_t nl, cl, tl;
	uint8_t type;
	so_lockrec rec;
	so_buf raw;
	int have;
	int32_t rc;

	(void)out;
	wri_rd_init(&r, in, n);
	if (wri_env_open(&r, 1, &e) != WR_OK)
		return -SO_EINVAL;
	name = rd_str(&e.body, &nl);
	type = wri_rd_u8(&e.body);
	cookie = rd_str(&e.body, &cl);
	tag = rd_str(&e.body, &tl);
	if (!wri_rd_ok(&e.body))
		return -SO_EINVAL;
	if (!cx->exists)
		return -SO_ENOENT;
	memset(&raw, 0, sizeof(raw));
	rc = lock_load(cx, name, nl, &rec, &raw, &have);
	if (rc == 0 && (!have || lock_find(&rec, 8, (int64_t)cx->gid, cookie, cl) < 0 || rec.type != type || rec.tl != tl ||
			(tl != 0 && memcmp(rec.tag, tag, tl) != 0)))
		rc = -SO_EBUSY;
	so_buf_free(&raw);
	return rc;
}

static int32_t m_lock_set_cookie(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	wri_rd r;
	wri_env e;
	const uint8_t *name, *cookie, *tag, *ncookie;
	uint32_t nl, cl, tl, ncl;
	uint8_t type;
	so_lockrec rec;
	so_buf raw;
	int have, at;
	int32_t rc;

	(void)out;
	wri_rd_init(&r, in, n);
	if (wri_env_open(&r, 1, &e) != WR_OK)
		return -SO_EINVAL;
	name = rd_str(&e.body, &nl);
	type = wri_rd_u8(&e.body);
	cookie = rd_str(&e.body, &cl);
	tag = rd_str(&e.body, &tl);
	ncookie = rd_str(&e.body, &ncl);
	if (!wri_rd_ok(&e.body))
		return -SO_EINVAL;
	memset(&raw, 0, sizeof(raw));
	rc = lock_load(cx, name, nl, &rec, &raw, &have);
	if (rc == 0) {
		at = have ? lock_find(&rec, 8, (int64_t)cx->gid, cookie, cl) : -1;
		if (at < 0)
			rc = -SO_ENOENT;
		else if (rec.type != type || rec.tl != tl || (tl != 0 && memcmp(rec.tag, tag, tl) != 0) ||
			 lock_find(&rec, 8, (int64_t)cx->gid, ncookie, ncl) >= 0)
			rc = -SO_EBUSY;
		else {
			rec.l[at].cookie = ncookie;
			rec.l[at].cl = ncl;
			rc = lock_store(cx, name, nl, &rec);
		}
	}
	so_buf_free(&raw);
	return rc;
}

static int32_t m_lock_list_locks(so_cctx *cx, const uint8_t *in, uint32_t n, so_buf *out)
{
	uint32_t i, cnt = 0;
	size_t mark;

	(void)in, (void)n;
	if (!cx->exists)
		return -SO_ENOENT;
	mark = out->len;
	so_buf_u8(out, 1);
	so_buf_u8(out, 1);
	so_buf_u32(out, 0);
	so_buf_u32(out, 0);
	for (i = 0; i < cx->body->xattr.n; i++) {
		const so_kv *kv = &cx->body->xattr.a[i];

		if (kv->kl > 5u && memcmp(kv->k, "lock.", 5) == 0) {
			so_buf_str(out, kv->k + 5, kv->kl - 5u);
			cnt++;
		}
	}
	if (!out->oom) {
		wri_le32_put(out->p + mark + 6, cnt);
		wri_le32_put(out->p + mark + 2, (uint32_t)(out->len - mark - 6u));
	}
	return 0;
}

/* ---- the method tables ---------------------------------------------------------------------------------------------- */

typedef struct so_cls_ent {
	const char *name;
	so_cls_fn fn;
	uint8_t writes;
} so_cls_ent;

static const so_cls_ent k_rbd[] = {
	{"get_id", m_get_id, 0},
	{"dir_get_id", m_dir_get_id, 0},
	{"dir_get_name", m_dir_get_name, 0},
	{"get_size", m_get_size, 0},
	{"get_features", m_get_features, 0},
	{"get_all_features", m_get_all_features, 0},
	{"get_object_prefix", m_get_object_prefix, 0},
	{"get_snapcontext", m_get_snapcontext, 0},
	{"get_data_pool", m_get_data_pool, 0},
	{"get_stripe_unit_count", m_get_stripe_unit_count, 0},
	{"get_flags", m_get_flags, 0},
	{"op_features_get", m_op_features_get, 0},
	{"parent_get", m_parent_get, 0},
	{"parent_overlap_get", m_parent_overlap_get, 0},
	{"get_parent", m_get_parent, 0},
	{"get_create_timestamp", m_get_create_timestamp, 0},
	{"get_access_timestamp", m_get_access_timestamp, 0},
	{"get_modify_timestamp", m_get_modify_timestamp, 0},
	{"set_size", m_set_size, 1},
};

static const so_cls_ent k_lock[] = {
	{"lock", m_lock_lock, 1},
	{"unlock", m_lock_unlock, 1},
	{"break_lock", m_lock_break, 1},
	{"set_cookie", m_lock_set_cookie, 1},
	{"get_info", m_lock_get_info, 0},
	{"list_locks", m_lock_list_locks, 0},
	{"assert_locked", m_lock_assert, 0},
};

static int name_is(const char *a, uint32_t al, const char *lit)
{
	return strlen(lit) == al && memcmp(a, lit, al) == 0;
}

int so_cls_lookup(const char *cls, uint32_t cl, const char *method, uint32_t ml, so_cls_fn *fn, uint8_t *writes)
{
	const so_cls_ent *t;
	size_t n, i;

	if (name_is(cls, cl, "rbd")) {
		t = k_rbd;
		n = sizeof(k_rbd) / sizeof(k_rbd[0]);
	} else if (name_is(cls, cl, "lock")) {
		t = k_lock;
		n = sizeof(k_lock) / sizeof(k_lock[0]);
	} else {
		return -1;
	}
	for (i = 0; i < n; i++)
		if (name_is(method, ml, t[i].name)) {
			*fn = t[i].fn;
			*writes = t[i].writes;
			return 0;
		}
	return -2;
}

/* ---- the RBD image fixtures ------------------------------------------------------------------------------------------ */

static void put_u64(so_buf *b, uint64_t v) { so_buf_u64(b, v); }

static wr_status omap_put(so_obj *o, const char *key, const so_buf *v)
{
	if (v->oom || so_kv_set(&o->head.omap, key, (uint32_t)strlen(key), v->p, (uint32_t)v->len) != 0)
		return WR_E_BUDGET;
	return WR_OK;
}

static wr_status omap_u64(so_obj *o, const char *key, uint64_t v)
{
	so_buf b;
	wr_status st;

	memset(&b, 0, sizeof(b));
	put_u64(&b, v);
	st = omap_put(o, key, &b);
	so_buf_free(&b);
	return st;
}

static wr_status omap_str(so_obj *o, const char *key, const char *s)
{
	so_buf b;
	wr_status st;

	memset(&b, 0, sizeof(b));
	so_buf_str(&b, s, strlen(s));
	st = omap_put(o, key, &b);
	so_buf_free(&b);
	return st;
}

static so_obj *live_obj(sim_store *s, int64_t pool, const char *name)
{
	so_obj *o = so_obj_get(s, pool, (const uint8_t *)name, (uint32_t)strlen(name));

	if (o != NULL && !o->exists) {
		o->exists = 1;
		o->whiteout = 0;
	}
	return o;
}

/* snapshot_<id>: struct v8/8 { u64 id, string name, u64 image size, u64 flags, u8 has overlap, u64 overlap } (the stock record carries more fields after these) */
static wr_status put_snap(so_obj *h, uint64_t id, uint64_t size, uint8_t has_overlap, uint64_t overlap)
{
	char key[26], nm[32];
	so_buf b;
	wr_status st;

	memset(&b, 0, sizeof(b));
	snap_key(key, id);
	snprintf(nm, sizeof(nm), "snap%llu", (unsigned long long)id);
	so_buf_u8(&b, 8);
	so_buf_u8(&b, 8);
	so_buf_u32(&b, 0);
	so_buf_u64(&b, id);
	so_buf_str(&b, nm, strlen(nm));
	so_buf_u64(&b, size);
	so_buf_u64(&b, 0);
	so_buf_u8(&b, has_overlap);
	so_buf_u64(&b, overlap);
	if (!b.oom)
		wri_le32_put(b.p + 2, (uint32_t)(b.len - 6u));
	st = omap_put(h, key, &b);
	so_buf_free(&b);
	return st;
}

static void default_addr(uint8_t out[35]) /* 10.77.0.99:0, nonce 1234, type legacy */
{
	static const uint8_t ip[4] = {10, 77, 0, 99};

	sim_m2_put_addr4(out, 1, 1234, ip, 0);
}

wr_status sim_rbd_image_create(sim_store *s, const sim_rbd_image_cfg *c)
{
	char hname[200], iname[200], prefix[200], dkey[300];
	so_obj *h, *idobj, *dir;
	wr_status st;
	uint32_t i;
	uint8_t order;
	so_buf b;
	uint8_t tbuf[64];

	if (s == NULL || c == NULL || c->name == NULL || c->id == NULL || c->name[0] == '\0' || c->id[0] == '\0' || strlen(c->name) > 100 ||
	    strlen(c->id) > 100 || c->n_snaps > 16u || (c->prefix != NULL && strlen(c->prefix) > 150))
		return WR_E_INVAL;
	order = c->order != 0 ? c->order : 22u;
	snprintf(hname, sizeof(hname), "rbd_header.%s", c->id);
	snprintf(iname, sizeof(iname), "rbd_id.%s", c->name);
	if (c->prefix != NULL)
		snprintf(prefix, sizeof(prefix), "%s", c->prefix);
	else if (c->data_pool >= 0)
		snprintf(prefix, sizeof(prefix), "rbd_data.%lld.%s", (long long)c->pool, c->id);
	else
		snprintf(prefix, sizeof(prefix), "rbd_data.%s", c->id);

	/* the id object: one encoded string */
	idobj = live_obj(s, c->pool, iname);
	h = live_obj(s, c->pool, hname);
	dir = live_obj(s, c->pool, "rbd_directory");
	if (idobj == NULL || h == NULL || dir == NULL)
		return WR_E_BUDGET;
	memset(&b, 0, sizeof(b));
	so_buf_str(&b, c->id, strlen(c->id));
	so_body_clear_data(&idobj->head);
	if (b.oom || so_body_write(&idobj->head, 0, b.p, b.len) != 0) {
		so_buf_free(&b);
		return WR_E_BUDGET;
	}
	so_buf_free(&b);

	/* the header omap (rbd-format2.md 2.4) */
	st = omap_u64(h, "size", c->size);
	tbuf[0] = order;
	if (st == WR_OK && so_kv_set(&h->head.omap, "order", 5, tbuf, 1) != 0)
		st = WR_E_BUDGET;
	if (st == WR_OK)
		st = omap_u64(h, "features", c->features);
	if (st == WR_OK)
		st = omap_str(h, "object_prefix", prefix);
	if (st == WR_OK)
		st = omap_u64(h, "snap_seq", c->snap_seq);
	for (i = 0; st == WR_OK && i < 3u; i++) {
		static const char *const ts[3] = {"create_timestamp", "access_timestamp", "modify_timestamp"};

		wri_le32_put(tbuf, 1700000000u);
		wri_le32_put(tbuf + 4, 0);
		if (so_kv_set(&h->head.omap, ts[i], (uint32_t)strlen(ts[i]), tbuf, 8) != 0)
			st = WR_E_BUDGET;
	}
	if (st == WR_OK && c->data_pool >= 0)
		st = omap_u64(h, "data_pool_id", (uint64_t)c->data_pool);
	if (st == WR_OK && (c->stripe_unit != 0 || c->stripe_count != 0)) {
		st = omap_u64(h, "stripe_unit", c->stripe_unit);
		if (st == WR_OK)
			st = omap_u64(h, "stripe_count", c->stripe_count);
	}
	if (st == WR_OK && c->flags != 0)
		st = omap_u64(h, "flags", c->flags);
	if (st == WR_OK && c->op_features != 0)
		st = omap_u64(h, "op_features", c->op_features);
	if (st == WR_OK && c->has_parent) { /* struct v2/2 { pool 1, "", image "parent", snap 2, overlap = size } */
		so_buf pb;

		memset(&pb, 0, sizeof(pb));
		so_buf_u8(&pb, 2);
		so_buf_u8(&pb, 2);
		so_buf_u32(&pb, 0);
		so_buf_u64(&pb, 1);
		so_buf_str(&pb, "", 0);
		so_buf_str(&pb, "parent", 6);
		so_buf_u64(&pb, 2);
		so_buf_u8(&pb, 1);
		so_buf_u64(&pb, c->size);
		if (!pb.oom)
			wri_le32_put(pb.p + 2, (uint32_t)(pb.len - 6u));
		st = omap_put(h, "parent", &pb);
		so_buf_free(&pb);
	}
	for (i = 0; st == WR_OK && i < c->n_snaps; i++)
		st = put_snap(h, c->snaps[i], c->size, c->has_parent ? 1u : 0u, c->size);

	/* the directory */
	if (st == WR_OK) {
		snprintf(dkey, sizeof(dkey), "name_%s", c->name);
		st = omap_str(dir, dkey, c->id);
	}
	if (st == WR_OK) {
		snprintf(dkey, sizeof(dkey), "id_%s", c->id);
		st = omap_str(dir, dkey, c->name);
	}

	/* a foreign exclusive locker */
	if (st == WR_OK && c->lock_held) {
		so_lockrec rec;
		so_buf lb;
		static const uint8_t cookie[] = "auto 140737";
		static const uint8_t tag[] = "internal";

		memset(&rec, 0, sizeof(rec));
		rec.n = 1;
		rec.type = LOCK_EXCLUSIVE;
		rec.tag = tag;
		rec.tl = 8;
		rec.l[0].etype = 8;
		rec.l[0].num = 77777;
		rec.l[0].cookie = cookie;
		rec.l[0].cl = 11;
		rec.l[0].desc = (const uint8_t *)"";
		default_addr(rec.l[0].addr);
		memset(&lb, 0, sizeof(lb));
		lockrec_encode(&rec, &lb);
		if (lb.oom || so_kv_set(&h->head.xattr, "lock.rbd_lock", 13, lb.p, (uint32_t)lb.len) != 0)
			st = WR_E_BUDGET;
		so_buf_free(&lb);
	}
	h->head.user_version++;
	idobj->head.user_version++;
	dir->head.user_version++;
	return st;
}

static so_obj *header_of(sim_store *s, int64_t pool, const char *id)
{
	char hname[200];
	so_obj *o;

	if (id == NULL || strlen(id) > 100)
		return NULL;
	snprintf(hname, sizeof(hname), "rbd_header.%s", id);
	o = so_obj_find(s, pool, (const uint8_t *)hname, (uint32_t)strlen(hname));
	return o != NULL && o->exists ? o : NULL;
}

wr_status sim_rbd_image_set_snapc(sim_store *s, int64_t pool, const char *id, uint64_t seq, const uint64_t *snaps, uint32_t n)
{
	so_obj *h = header_of(s, pool, id);
	const so_kv *sz;
	uint64_t size = 0;
	uint32_t i;
	wr_status st;

	if (h == NULL)
		return WR_E_RANGE;
	if (n > 1024u)
		return WR_E_INVAL;
	sz = so_kv_get(&h->head.omap, "size", 4);
	if (sz != NULL && sz->vl == 8u)
		size = wri_le64_get(sz->v);
	for (i = 0; i < h->head.omap.n;) { /* drop the old snapshot records */
		const so_kv *kv = &h->head.omap.a[i];

		if (kv->kl == 25u && memcmp(kv->k, "snapshot_", 9) == 0) {
			uint8_t key[25];

			memcpy(key, kv->k, 25);
			(void)so_kv_del(&h->head.omap, key, 25);
		} else {
			i++;
		}
	}
	st = omap_u64(h, "snap_seq", seq);
	for (i = 0; st == WR_OK && i < n; i++)
		st = put_snap(h, snaps[i], size, 0, 0);
	h->head.user_version++;
	return st;
}

wr_status sim_rbd_image_set_size(sim_store *s, int64_t pool, const char *id, uint64_t size)
{
	so_obj *h = header_of(s, pool, id);
	wr_status st;

	if (h == NULL)
		return WR_E_RANGE;
	st = omap_u64(h, "size", size);
	h->head.user_version++;
	return st;
}

wr_status sim_rbd_image_set_features(sim_store *s, int64_t pool, const char *id, uint64_t features)
{
	so_obj *h = header_of(s, pool, id);
	wr_status st;

	if (h == NULL)
		return WR_E_RANGE;
	st = omap_u64(h, "features", features);
	h->head.user_version++;
	return st;
}
