/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_cls_dec.c - decoders of the outputs of the object-class calls (see wri_rbd_cls.h; spec rbd-format2.md 2.3, 2.5, 2.7).
 *
 * Each decoder takes the bytes of one operation's output and must consume them exactly: a short output, trailing bytes, an envelope
 * that claims more than is there are all WR_E_RBD_PROTO. What the bytes say is judged separately, with its own status: an image id or
 * prefix that cannot name objects (WR_E_RBD_BAD_ID), a snapshot context that is not valid or does not fit (WR_E_RBD_SNAPC). A decoder
 * that fails leaves every output cleared; nothing is read from the input twice and nothing is kept (no pointer into it).
 */
#include "wri_rbd_cls.h"

#include "wri_denc.h"

WR_FILE_LICENCE_MIT

#define RBD_LOCKERS_MAX 64u        /* lockers a lock record may list before the reply is refused */
#define RBD_LOCKER_MIN 25u         /* smallest locker entry: two struct headers (6 + 6), the entity (9), the cookie length (4) */
#define RBD_PARENT_STR_MAX 4096u   /* longest namespace or image id inside parent_get that is read at all (the output is smaller anyway) */

/* The whole output was read and nothing is left. */
static wr_status rd_done(const wri_rd *r)
{
	return (wri_rd_ok(r) && r->pos == r->len) ? WR_OK : WR_E_RBD_PROTO;
}

/* ASCII letters and digits: what `isalnum` means for an image id (rbd-format2.md 3.1). */
static int is_alnum(uint8_t c)
{
	return (c >= (uint8_t)'0' && c <= (uint8_t)'9') || (c >= (uint8_t)'a' && c <= (uint8_t)'z') || (c >= (uint8_t)'A' && c <= (uint8_t)'Z');
}

/* ---- strings: the id and the object prefix ------------------------------------------------------------------------ */

/* Visible ASCII, no space: what a prefix of generated object names is made of (rbd_data.<id> or rbd_data.<pool>.<id>). */
static int is_name_byte(uint8_t c)
{
	return c >= 0x21u && c <= 0x7eu;
}

/*
 * u32 length + bytes, exactly the output. A length outside 1 .. max_len is a bad id however many bytes follow; so is a byte that is not
 * a letter or digit (alnum_only: an image id) or not visible ASCII (a prefix). *dst gets the bytes and a NUL.
 */
static wr_status dec_name(const uint8_t *out, uint32_t n, char *dst, size_t dst_cap, uint32_t max_len, int alnum_only)
{
	wri_rd r;
	const uint8_t *p;
	uint32_t len, i;

	WR_MEMSET(dst, 0, dst_cap);
	wri_rd_init(&r, out, n);
	len = wri_rd_u32(&r);
	if (!wri_rd_ok(&r))
		return WR_E_RBD_PROTO;
	if (len == 0 || len > max_len)
		return WR_E_RBD_BAD_ID;
	p = wri_rd_bytes(&r, len);
	if (p == NULL || rd_done(&r) != WR_OK)
		return WR_E_RBD_PROTO;
	for (i = 0; i < len; i++)
		if (!(alnum_only ? is_alnum(p[i]) : is_name_byte(p[i])))
			return WR_E_RBD_BAD_ID;
	WR_MEMCPY(dst, p, len);
	dst[len] = '\0';
	return WR_OK;
}

wr_status wri_rbd_dec_id(const uint8_t *out, uint32_t n, char id[WRI_RBD_ID_MAX])
{
	if (id == NULL)
		return WR_E_INVAL;
	return dec_name(out, n, id, WRI_RBD_ID_MAX, WRI_RBD_ID_MAX - 1u, 1);
}

wr_status wri_rbd_dec_prefix(const uint8_t *out, uint32_t n, char prefix[WRI_RBD_PREFIX_MAX])
{
	if (prefix == NULL)
		return WR_E_INVAL;
	return dec_name(out, n, prefix, WRI_RBD_PREFIX_MAX, WRI_RBD_PREFIX_LEN_MAX, 0);
}

/* ---- fixed layouts ------------------------------------------------------------------------------------------------ */

wr_status wri_rbd_dec_size(const uint8_t *out, uint32_t n, uint8_t *order, uint64_t *size)
{
	wri_rd r;
	uint8_t o;
	uint64_t s;

	if (order == NULL || size == NULL)
		return WR_E_INVAL;
	*order = 0;
	*size = 0;
	wri_rd_init(&r, out, n);
	o = wri_rd_u8(&r);
	s = wri_rd_u64(&r);
	if (rd_done(&r) != WR_OK)
		return WR_E_RBD_PROTO;
	*order = o;
	*size = s;
	return WR_OK;
}

wr_status wri_rbd_dec_features(const uint8_t *out, uint32_t n, uint64_t *features, uint64_t *incompatible)
{
	wri_rd r;
	uint64_t f, i;

	if (features == NULL || incompatible == NULL)
		return WR_E_INVAL;
	*features = 0;
	*incompatible = 0;
	wri_rd_init(&r, out, n);
	f = wri_rd_u64(&r);
	i = wri_rd_u64(&r);
	if (rd_done(&r) != WR_OK)
		return WR_E_RBD_PROTO;
	*features = f;
	*incompatible = i;
	return WR_OK;
}

wr_status wri_rbd_dec_u64(const uint8_t *out, uint32_t n, uint64_t *v)
{
	wri_rd r;
	uint64_t x;

	if (v == NULL)
		return WR_E_INVAL;
	*v = 0;
	wri_rd_init(&r, out, n);
	x = wri_rd_u64(&r);
	if (rd_done(&r) != WR_OK)
		return WR_E_RBD_PROTO;
	*v = x;
	return WR_OK;
}

wr_status wri_rbd_dec_i64(const uint8_t *out, uint32_t n, int64_t *v)
{
	wri_rd r;
	int64_t x;

	if (v == NULL)
		return WR_E_INVAL;
	*v = 0;
	wri_rd_init(&r, out, n);
	x = wri_rd_i64(&r);
	if (rd_done(&r) != WR_OK)
		return WR_E_RBD_PROTO;
	*v = x;
	return WR_OK;
}

wr_status wri_rbd_dec_stripe(const uint8_t *out, uint32_t n, uint64_t *unit, uint64_t *count)
{
	wri_rd r;
	uint64_t u, c;

	if (unit == NULL || count == NULL)
		return WR_E_INVAL;
	*unit = 0;
	*count = 0;
	wri_rd_init(&r, out, n);
	u = wri_rd_u64(&r);
	c = wri_rd_u64(&r);
	if (rd_done(&r) != WR_OK)
		return WR_E_RBD_PROTO;
	*unit = u;
	*count = c;
	return WR_OK;
}

/* ---- the snapshot context (rbd-format2.md 2.5) --------------------------------------------------------------------- */

/*
 * u64 seq, u32 count, count x u64. The count is checked against the bytes that are there before anything is stored, so a hostile count
 * costs nothing; a context with more ids than s->cap is WR_E_RBD_SNAPC with the count in *n_total and nothing stored. The rules are the
 * ones of wri_snapc_valid (kept here as well so this module stands alone): seq at most WRI_SNAP_MAX, the first id at most seq, every
 * following id strictly smaller than the one before (an id 0 can therefore not be followed by another).
 */
wr_status wri_rbd_dec_snapcontext(const uint8_t *out, uint32_t n, wri_snapc *s, uint32_t *n_total)
{
	wri_rd r;
	uint64_t seq, prev = 0, v;
	uint32_t cnt, i;

	if (n_total != NULL)
		*n_total = 0;
	if (s == NULL || (s->cap != 0 && s->snaps == NULL))
		return WR_E_INVAL;
	s->seq = 0;
	s->n = 0;
	wri_rd_init(&r, out, n);
	seq = wri_rd_u64(&r);
	cnt = wri_rd_u32(&r);
	if (!wri_rd_ok(&r))
		return WR_E_RBD_PROTO;
	/* the ids are the rest of the output, exactly: cnt * 8 == left, compared without a multiplication that could wrap */
	if ((uint64_t)cnt > (uint64_t)wri_rd_left(&r) / 8u || (uint64_t)cnt * 8u != (uint64_t)wri_rd_left(&r))
		return WR_E_RBD_PROTO;
	if (n_total != NULL)
		*n_total = cnt;
	if (cnt > s->cap || seq > WRI_SNAP_MAX)
		return WR_E_RBD_SNAPC;
	for (i = 0; i < cnt; i++) {
		v = wri_rd_u64(&r);
		if (i == 0 ? v > seq : v >= prev) {
			if (i != 0)
				WR_MEMSET(s->snaps, 0, (size_t)i * sizeof(s->snaps[0]));
			return WR_E_RBD_SNAPC;
		}
		s->snaps[i] = v;
		prev = v;
	}
	if (rd_done(&r) != WR_OK) /* cannot happen after the length check; kept so a future edit cannot lose it */
		return WR_E_RBD_PROTO;
	s->seq = seq;
	s->n = cnt;
	return WR_OK;
}

/* ---- parent and overlap (rbd-format2.md 2.3) ------------------------------------------------------------------------ */

wr_status wri_rbd_dec_parent(const uint8_t *out, uint32_t n, uint8_t *has_parent)
{
	wri_rd r;
	wri_env e;
	int64_t pool;
	uint64_t snap;
	uint32_t ns_len = 0, id_len = 0;
	const uint8_t *ns, *id;

	if (has_parent == NULL)
		return WR_E_INVAL;
	*has_parent = 0;
	wri_rd_init(&r, out, n);
	/* version 1 is what the server of the lab sends; a later version that keeps compat 1 only appends fields, which the envelope skips */
	if (wri_env_open(&r, 1u, &e) != WR_OK)
		return WR_E_RBD_PROTO;
	pool = wri_rd_i64(&e.body);
	ns = wri_denc_str(&e.body, &ns_len, RBD_PARENT_STR_MAX);
	id = wri_denc_str(&e.body, &id_len, RBD_PARENT_STR_MAX);
	snap = wri_rd_u64(&e.body);
	(void)ns; /* the namespace and the id are not kept: only whether a parent exists (every one of the three conditions) */
	(void)id;
	if (!wri_rd_ok(&e.body) || rd_done(&r) != WR_OK)
		return WR_E_RBD_PROTO;
	*has_parent = (pool >= 0 && id_len != 0 && snap != WRI_SNAP_NOSNAP) ? 1u : 0u;
	return WR_OK;
}

wr_status wri_rbd_dec_overlap(const uint8_t *out, uint32_t n, uint8_t *present, uint64_t *overlap)
{
	wri_rd r;
	uint8_t p;
	uint64_t o = 0;

	if (present == NULL || overlap == NULL)
		return WR_E_INVAL;
	*present = 0;
	*overlap = 0;
	wri_rd_init(&r, out, n);
	p = wri_rd_u8(&r);
	if (wri_rd_ok(&r) && p > 1u)
		return WR_E_RBD_PROTO;
	if (p == 1u)
		o = wri_rd_u64(&r);
	if (rd_done(&r) != WR_OK)
		return WR_E_RBD_PROTO;
	*present = p;
	*overlap = o;
	return WR_OK;
}

/* ---- the lock record (rbd-format2.md 2.7) --------------------------------------------------------------------------- */

/* One locker: the id structure (entity, cookie) is read to its end, the info structure (expiry, address, description) is skipped whole. */
static wr_status skip_locker(wri_rd *r)
{
	wri_env id, info;
	uint32_t cookie_len = 0;

	if (wri_env_open(r, 1u, &id) != WR_OK)
		return WR_E_RBD_PROTO;
	(void)wri_rd_u8(&id.body);  /* entity type */
	(void)wri_rd_i64(&id.body); /* entity number */
	(void)wri_denc_str(&id.body, &cookie_len, 0xffffffffu);
	if (!wri_rd_ok(&id.body))
		return WR_E_RBD_PROTO;
	if (wri_env_open(r, 1u, &info) != WR_OK)
		return WR_E_RBD_PROTO;
	return WR_OK;
}

wr_status wri_rbd_dec_lock_info(const uint8_t *out, uint32_t n, uint32_t *n_lockers, uint8_t *type, char *tag, size_t tag_cap)
{
	wri_rd r;
	wri_env e;
	uint32_t cnt, i, tag_len = 0;
	uint8_t t;
	const uint8_t *tp;

	if (n_lockers == NULL || type == NULL || (tag == NULL && tag_cap != 0))
		return WR_E_INVAL;
	*n_lockers = 0;
	*type = 0;
	if (tag_cap != 0)
		WR_MEMSET(tag, 0, tag_cap);
	wri_rd_init(&r, out, n);
	if (wri_env_open(&r, 1u, &e) != WR_OK)
		return WR_E_RBD_PROTO;
	cnt = wri_rd_count(&e.body, RBD_LOCKERS_MAX, RBD_LOCKER_MIN);
	if (!wri_rd_ok(&e.body))
		return WR_E_RBD_PROTO;
	for (i = 0; i < cnt; i++)
		if (skip_locker(&e.body) != WR_OK)
			return WR_E_RBD_PROTO;
	t = wri_rd_u8(&e.body);
	tp = wri_denc_str(&e.body, &tag_len, 0xffffffffu);
	if (!wri_rd_ok(&e.body) || rd_done(&r) != WR_OK || t > 3u)
		return WR_E_RBD_PROTO;
	*n_lockers = cnt;
	*type = t;
	if (tag_cap != 0) {
		size_t keep = tag_len < tag_cap - 1u ? (size_t)tag_len : tag_cap - 1u;

		if (keep != 0)
			WR_MEMCPY(tag, tp, keep);
		tag[keep] = '\0';
	}
	return WR_OK;
}
