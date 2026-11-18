/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_bo.c - MOSDBackoff (osd-ops.md 2.10, 3.7): the decoder of the OSD's BLOCK / UNBLOCK, the encoder of our ACK_BLOCK, and the
 * order of hobject_t positions that decides whether a request lies inside a blocked range. Pure functions over cursors and
 * borrowed byte strings; nothing is stored here (the table is the session's, module osd-sess).
 */
#include "wri_osd_msg.h"

#include "wri_denc.h"

WR_FILE_LICENCE_MIT

#define NS_LIMIT 256u          /* longest namespace a backoff position may carry */
#define HOBJ_STRUCT_V 4u       /* the hobject_t encoding this decoder implements: it reads any struct whose compat is at most 4 */
#define HOBJ_STRUCT_COMPAT 3u  /* the compat byte we write (the oldest reader that understands version 4) */

/* ---- hobject_t, full encoding (osd-ops.md 2.2) -------------------------------------------------------------------------------- */

static const uint8_t *read_str(wri_rd *r, uint32_t *len, uint32_t max)
{
	const uint8_t *p = wri_denc_blob(r, len, max);

	if (p == NULL) {
		*len = 0;
		wri_rd_fail(r, WR_E_OSD_PROTO); /* a no-op when the cursor already holds an error */
	}
	return p;
}

/* struct header (v4 compat 3), string key, string oid, u64 snap, u32 hash, bool max, string nspace, i64 pool. */
static wr_status read_hobj(wri_rd *r, wri_hobj *h)
{
	wri_env e;
	wr_status st;

	WR_MEMSET(h, 0, sizeof(*h));
	st = wri_env_open(r, HOBJ_STRUCT_V, &e);
	if (st == WR_E_UNSUPPORTED)
		return WR_E_OSD_VERSION; /* a newer, incompatible hobject_t */
	if (st != WR_OK)
		return WR_E_OSD_PROTO;
	if (e.v < HOBJ_STRUCT_V) /* the older layouts have no namespace or pool: never sent by a release that has backoffs with ours */
		return WR_E_OSD_VERSION;
	h->key = read_str(&e.body, &h->key_len, WRI_OSD_NAME_LIMIT);
	h->oid = read_str(&e.body, &h->oid_len, WRI_OSD_NAME_LIMIT);
	h->snap = wri_rd_u64(&e.body);
	h->hash = wri_rd_u32(&e.body);
	h->max = wri_rd_u8(&e.body) != 0u ? 1u : 0u;
	h->nspace = read_str(&e.body, &h->nspace_len, NS_LIMIT);
	h->pool = wri_rd_i64(&e.body);
	if (!wri_rd_ok(&e.body)) {
		WR_MEMSET(h, 0, sizeof(*h));
		return WR_E_OSD_PROTO;
	}
	return WR_OK;
}

static void put_hobj(wri_wr *w, const wri_hobj *h)
{
	size_t mark = wri_env_begin(w, (uint8_t)HOBJ_STRUCT_V, (uint8_t)HOBJ_STRUCT_COMPAT);

	wri_denc_put_blob(w, h->key, h->key_len);
	wri_denc_put_blob(w, h->oid, h->oid_len);
	wri_wr_u64(w, h->snap);
	wri_wr_u32(w, h->hash);
	wri_wr_u8(w, h->max != 0u ? 1u : 0u);
	wri_denc_put_blob(w, h->nspace, h->nspace_len);
	wri_wr_i64(w, h->pool);
	wri_env_end(w, mark);
}

/* ---- the message ---------------------------------------------------------------------------------------------------------------- */

wr_status wri_mbackoff_decode(const uint8_t *front, size_t n, uint16_t msg_version, uint16_t msg_compat, wri_mbackoff *out)
{
	wri_rd r;
	wri_env spg;
	uint8_t pg_ver;
	int8_t shard;
	wr_status st;

	if (out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	if (front == NULL && n != 0)
		return WR_E_INVAL;
	/* No struct header of its own: the message header carries the version. A newer minor version only appends fields. */
	if (msg_version < WRI_MOSDBACKOFF_VERSION || msg_compat > WRI_MOSDBACKOFF_VERSION)
		return WR_E_OSD_VERSION;

	wri_rd_init(&r, front, n);
	st = wri_env_open(&r, 1, &spg); /* spg_t: struct v1 */
	if (st == WR_E_UNSUPPORTED)
		return WR_E_OSD_VERSION;
	if (st != WR_OK)
		return WR_E_OSD_PROTO;
	pg_ver = wri_rd_u8(&spg.body);
	out->pool = (int64_t)wri_rd_u64(&spg.body);
	out->pg_seed = wri_rd_u32(&spg.body);
	wri_rd_skip(&spg.body, 4); /* retired preferred field */
	shard = (int8_t)wri_rd_u8(&spg.body);
	/* Only replicated pools exist for this client: the ACK we write carries shard -1, so a shard here would not be echoed. */
	if (!wri_rd_ok(&spg.body) || pg_ver != 1u || shard != -1) {
		WR_MEMSET(out, 0, sizeof(*out));
		return WR_E_OSD_PROTO;
	}
	out->map_epoch = wri_rd_u32(&r);
	out->op = wri_rd_u8(&r);
	out->id = wri_rd_u64(&r);
	if (!wri_rd_ok(&r) || out->op < WRI_BACKOFF_BLOCK || out->op > WRI_BACKOFF_UNBLOCK) {
		WR_MEMSET(out, 0, sizeof(*out));
		return WR_E_OSD_PROTO;
	}
	st = read_hobj(&r, &out->begin);
	if (st == WR_OK)
		st = read_hobj(&r, &out->end);
	if (st != WR_OK) {
		WR_MEMSET(out, 0, sizeof(*out));
		return st;
	}
	/* A message of the version we implement ends here; a later minor version may add fields after the positions. */
	if (msg_version == WRI_MOSDBACKOFF_VERSION && wri_rd_left(&r) != 0) {
		WR_MEMSET(out, 0, sizeof(*out));
		return WR_E_OSD_PROTO;
	}
	return WR_OK;
}

size_t wri_mbackoff_ack_len(const wri_mbackoff *b)
{
	uint64_t n;

	if (b == NULL)
		return 0;
	/* 64-bit sum: six u32 lengths of a hand-made block cannot wrap it (a decoded block holds at most 4 * 2048 + 2 * 256 string bytes);
	 * on a 32-bit host an absurd total saturates, and wri_mbackoff_encode_ack refuses such a block anyway. */
	n = (uint64_t)WRI_MBACKOFF_FIXED_LEN + (uint64_t)b->begin.key_len + b->begin.oid_len + b->begin.nspace_len + b->end.key_len +
		     b->end.oid_len + b->end.nspace_len;

	if (n > (uint64_t)(size_t)-1)
		return (size_t)-1;
	return (size_t)n;
}

static int hobj_ok(const wri_hobj *h)
{
	if (h->key_len > WRI_OSD_NAME_LIMIT || h->oid_len > WRI_OSD_NAME_LIMIT || h->nspace_len > NS_LIMIT)
		return 0;
	return 1;
}

wr_status wri_mbackoff_encode_ack(wri_wr *w, const wri_mbackoff *block)
{
	size_t mark;

	if (w == NULL || block == NULL)
		return WR_E_INVAL;
	if (block->op != WRI_BACKOFF_BLOCK)
		return WR_E_INVAL; /* only a BLOCK is acknowledged */
	if ((block->begin.key == NULL && block->begin.key_len != 0) || (block->begin.oid == NULL && block->begin.oid_len != 0) ||
	    (block->begin.nspace == NULL && block->begin.nspace_len != 0) || (block->end.key == NULL && block->end.key_len != 0) ||
	    (block->end.oid == NULL && block->end.oid_len != 0) || (block->end.nspace == NULL && block->end.nspace_len != 0))
		return WR_E_INVAL;
	if (!hobj_ok(&block->begin) || !hobj_ok(&block->end))
		return WR_E_RANGE;

	mark = wri_env_begin(w, 1, 1); /* spg_t */
	wri_wr_u8(w, 1);
	wri_wr_u64(w, (uint64_t)block->pool);
	wri_wr_u32(w, block->pg_seed);
	wri_wr_i32(w, -1);
	wri_wr_u8(w, 0xFFu);
	wri_env_end(w, mark);
	wri_wr_u32(w, block->map_epoch); /* the BLOCK's epoch: the OSD drops an ACK whose epoch a split has outdated */
	wri_wr_u8(w, WRI_BACKOFF_ACK_BLOCK);
	wri_wr_u64(w, block->id);
	put_hobj(w, &block->begin);
	put_hobj(w, &block->end);
	return w->err;
}

/* ---- the order of positions (osd-ops.md 2.10) ----------------------------------------------------------------------------------- */

static uint32_t bit_reverse32(uint32_t v)
{
	v = ((v >> 1) & 0x55555555u) | ((v & 0x55555555u) << 1);
	v = ((v >> 2) & 0x33333333u) | ((v & 0x33333333u) << 2);
	v = ((v >> 4) & 0x0F0F0F0Fu) | ((v & 0x0F0F0F0Fu) << 4);
	v = ((v >> 8) & 0x00FF00FFu) | ((v & 0x00FF00FFu) << 8);
	return (v >> 16) | (v << 16);
}

/* Byte-wise (unsigned) order of two strings, a proper prefix sorting first. */
static int str_cmp(const uint8_t *a, uint32_t alen, const uint8_t *b, uint32_t blen)
{
	uint32_t n = alen < blen ? alen : blen;
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (a[i] != b[i])
			return a[i] < b[i] ? -1 : 1;
	}
	if (alen != blen)
		return alen < blen ? -1 : 1;
	return 0;
}

/* The key an object is ordered by: the locator key, or the object name when the key is empty. */
static const uint8_t *eff_key(const wri_hobj *h, uint32_t *len)
{
	if (h->key_len != 0) {
		*len = h->key_len;
		return h->key;
	}
	*len = h->oid_len;
	return h->oid;
}

int wri_hobj_cmp(const wri_hobj *a, const wri_hobj *b)
{
	uint32_t ha, hb;
	uint32_t ka_len, kb_len;
	const uint8_t *ka, *kb;
	int c;

	if (a->max != b->max)
		return a->max != 0u ? 1 : -1;
	if (a->pool != b->pool)
		return a->pool < b->pool ? -1 : 1;
	if (a->max == 0u) { /* two max positions sort equal by hash: their hash field is not part of the order */
		ha = bit_reverse32(a->hash);
		hb = bit_reverse32(b->hash);
		if (ha != hb)
			return ha < hb ? -1 : 1;
	}
	c = str_cmp(a->nspace, a->nspace_len, b->nspace, b->nspace_len);
	if (c != 0)
		return c;
	ka = eff_key(a, &ka_len);
	kb = eff_key(b, &kb_len);
	c = str_cmp(ka, ka_len, kb, kb_len);
	if (c != 0)
		return c;
	c = str_cmp(a->oid, a->oid_len, b->oid, b->oid_len);
	if (c != 0)
		return c;
	if (a->snap != b->snap)
		return a->snap < b->snap ? -1 : 1;
	return 0;
}

void wri_hobj_of_request(wri_hobj *h, int64_t pool, uint32_t hash, const uint8_t *nspace, uint32_t nspace_len, const uint8_t *oid,
			 uint32_t oid_len)
{
	if (h == NULL)
		return;
	WR_MEMSET(h, 0, sizeof(*h));
	h->pool = pool;
	h->hash = hash;
	h->nspace = nspace;
	h->nspace_len = nspace_len;
	h->oid = oid;
	h->oid_len = oid_len;
	h->snap = WRI_SNAP_NOSNAP;
}

int wri_mbackoff_covers(const wri_mbackoff *b, const wri_hobj *pos)
{
	if (b == NULL || pos == NULL)
		return 0;
	if (wri_hobj_cmp(&b->begin, &b->end) == 0) /* begin == end: that one object */
		return wri_hobj_cmp(pos, &b->begin) == 0;
	return wri_hobj_cmp(&b->begin, pos) <= 0 && wri_hobj_cmp(pos, &b->end) < 0;
}
