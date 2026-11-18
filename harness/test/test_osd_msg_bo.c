/* SPDX-License-Identifier: MIT */
/*
 * test_osd_msg_bo.c - module osd-msg, MOSDBackoff and the hobject order (core/src/osd/wri_osd_bo.c): wri_mbackoff_decode,
 * wri_mbackoff_encode_ack, wri_hobj_cmp, wri_hobj_of_request, wri_mbackoff_covers.
 *
 * Oracles: a test-local BLOCK writer built from osd-ops.md 2.2 and 2.10 (independent of the core cursors) and an independent
 * implementation of the order of 2.10 (bit reversal by a per-bit loop, memcmp for the strings) compared on random pairs.
 */
#include "wrt.h"
#include "wri_osd_msg.h"

/* ---- a writer for backoff messages --------------------------------------------------------------------------------------------- */

typedef struct buf {
	uint8_t *p;
	size_t n, cap;
} buf;

static void b_u8(buf *b, uint8_t v)
{
	if (b->n < b->cap)
		b->p[b->n] = v;
	b->n++;
}

static void b_le(buf *b, uint64_t v, unsigned bytes)
{
	unsigned i;

	for (i = 0; i < bytes; i++)
		b_u8(b, (uint8_t)(v >> (8 * i)));
}

static void b_mem(buf *b, const void *p, size_t n)
{
	const uint8_t *q = (const uint8_t *)p;

	while (n--)
		b_u8(b, *q++);
}

static void b_str(buf *b, const char *s, size_t n)
{
	b_le(b, n, 4);
	b_mem(b, s, n);
}

typedef struct th { /* a hobject as the test writes it */
	const char *key, *oid, *ns;
	size_t key_len, oid_len, ns_len;
	uint64_t snap;
	uint32_t hash;
	uint8_t max;
	int64_t pool;
	uint8_t v, compat; /* struct header; 0 = 4 / 3 */
	size_t extra;      /* bytes appended inside the struct (a later revision) */
	int64_t body_lie;  /* >= 0: struct_len written instead of the true one */
	int64_t oid_lie;   /* >= 0: the length prefix written for the name instead of its true length */
} th;

static th th_make(const char *key, const char *oid, const char *ns, uint64_t snap, uint32_t hash, int64_t pool)
{
	th h;

	memset(&h, 0, sizeof(h));
	h.key = key;
	h.key_len = strlen(key);
	h.oid = oid;
	h.oid_len = strlen(oid);
	h.ns = ns;
	h.ns_len = strlen(ns);
	h.snap = snap;
	h.hash = hash;
	h.pool = pool;
	h.body_lie = -1;
	h.oid_lie = -1;
	return h;
}

static void put_th(buf *b, const th *h)
{
	uint8_t body[8192];
	buf s;

	s.p = body;
	s.n = 0;
	s.cap = sizeof(body);
	b_str(&s, h->key, h->key_len);
	b_le(&s, h->oid_lie >= 0 ? (uint64_t)h->oid_lie : h->oid_len, 4);
	b_mem(&s, h->oid, h->oid_len);
	b_le(&s, h->snap, 8);
	b_le(&s, h->hash, 4);
	b_u8(&s, h->max);
	b_str(&s, h->ns, h->ns_len);
	b_le(&s, (uint64_t)h->pool, 8);
	{
		size_t k;

		for (k = 0; k < h->extra; k++)
			b_u8(&s, 0x6B);
	}
	b_u8(b, h->v ? h->v : 4);
	b_u8(b, h->compat ? h->compat : 3);
	b_le(b, h->body_lie >= 0 ? (uint64_t)h->body_lie : s.n, 4);
	b_mem(b, body, s.n);
}

typedef struct tb {
	int64_t pool;
	uint32_t seed;
	uint8_t pg_ver, shard;
	uint8_t spg_v, spg_compat;
	size_t spg_extra;
	uint32_t epoch;
	uint8_t op;
	uint64_t id;
	th begin, end;
	size_t tail;      /* bytes after the second position */
} tb;

static tb tb_make(void)
{
	tb t;

	memset(&t, 0, sizeof(t));
	t.pool = 5;
	t.seed = 0x1a;
	t.pg_ver = 1;
	t.shard = 0xFF;
	t.spg_v = 1;
	t.spg_compat = 1;
	t.epoch = 77;
	t.op = WRI_BACKOFF_BLOCK;
	t.id = 0x0102030405060708ull;
	t.begin = th_make("", "rbd_data.1234.0000000000000007", "", WRI_SNAP_NOSNAP - 1u, 0x12345678u, 5);
	t.end = th_make("", "rbd_data.1234.0000000000000009", "", 0, 0x12345679u, 5);
	return t;
}

static size_t tb_build(const tb *t, uint8_t *dst, size_t cap)
{
	buf b;
	size_t i;

	b.p = dst;
	b.n = 0;
	b.cap = cap;
	b_u8(&b, t->spg_v);
	b_u8(&b, t->spg_compat);
	b_le(&b, 18 + t->spg_extra, 4);
	b_u8(&b, t->pg_ver);
	b_le(&b, (uint64_t)t->pool, 8);
	b_le(&b, t->seed, 4);
	b_le(&b, 0xFFFFFFFFu, 4);
	b_u8(&b, t->shard);
	for (i = 0; i < t->spg_extra; i++)
		b_u8(&b, 0x6B);
	b_le(&b, t->epoch, 4);
	b_u8(&b, t->op);
	b_le(&b, t->id, 8);
	put_th(&b, &t->begin);
	put_th(&b, &t->end);
	for (i = 0; i < t->tail; i++)
		b_u8(&b, 0x6B);
	return b.n;
}

static int all_zero(const void *p, size_t n)
{
	const uint8_t *q = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (q[i] != 0)
			return 0;
	return 1;
}

static uint8_t *bo_copy; /* the exact-size copy the last decode borrowed from: alive until the next decode */

static wr_status bdec(const uint8_t *front, size_t n, uint16_t ver, uint16_t compat, wri_mbackoff *out)
{
	uint8_t *c = (uint8_t *)malloc(n ? n : 1);

	free(bo_copy);
	bo_copy = c;
	if (n)
		memcpy(c, front, n);
	memset(out, 0xEE, sizeof(*out));
	return wri_mbackoff_decode(c, n, ver, compat, out);
}

static int hobj_eq_th(const wri_hobj *h, const th *t)
{
	return h->key_len == t->key_len && h->oid_len == t->oid_len && h->nspace_len == t->ns_len &&
	       memcmp(h->key, t->key, t->key_len) == 0 && memcmp(h->oid, t->oid, t->oid_len) == 0 &&
	       memcmp(h->nspace, t->ns, t->ns_len) == 0 && h->snap == t->snap && h->hash == t->hash && h->max == (t->max != 0) &&
	       h->pool == t->pool;
}

/* ---- decode ---------------------------------------------------------------------------------------------------------------------- */

static void test_decode(void)
{
	tb t = tb_make();
	uint8_t b[4096];
	size_t n, cut;
	wri_mbackoff m;
	uint8_t op;

	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 1, &m));
	WRT_CHECK(m.pool == 5 && m.pg_seed == 0x1a && m.map_epoch == 77 && m.op == WRI_BACKOFF_BLOCK && m.id == 0x0102030405060708ull);
	WRT_CHECK(hobj_eq_th(&m.begin, &t.begin) && hobj_eq_th(&m.end, &t.end));
	/* the strings borrow from the input */
	WRT_CHECK(m.begin.oid >= bo_copy && m.begin.oid + m.begin.oid_len <= bo_copy + n);
	WRT_CHECK(m.end.oid >= bo_copy && m.end.oid + m.end.oid_len <= bo_copy + n);

	/* all three operations are decoded (an ACK_BLOCK from the OSD is ignored later, by the session) */
	for (op = 0; op < 6; op++) {
		t.op = op;
		n = tb_build(&t, b, sizeof(b));
		if (op >= WRI_BACKOFF_BLOCK && op <= WRI_BACKOFF_UNBLOCK) {
			WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 1, &m));
			WRT_CHECK(m.op == op);
		} else {
			WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
			WRT_CHECK(all_zero(&m, sizeof(m)));
		}
	}
	t.op = WRI_BACKOFF_UNBLOCK;

	/* a negative pool, key and namespace, the max flag */
	t = tb_make();
	t.pool = -1;
	t.begin = th_make("loc-key", "name", "ns1", 12, 0xFFFFFFFFu, -1);
	t.end = th_make("", "", "", 0xFFFFFFFFFFFFFFFFull, 0, 0x123456789ll);
	t.end.max = 1;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 1, &m));
	WRT_CHECK(m.pool == -1 && hobj_eq_th(&m.begin, &t.begin) && hobj_eq_th(&m.end, &t.end) && m.end.max == 1);
	/* max is a boolean byte: any non-zero value reads as 1 */
	{
		uint8_t *q;

		t.end.max = 1;
		n = tb_build(&t, b, sizeof(b));
		/* the max byte of the end position (empty strings, the last 39 bytes): envelope 6, key length 4, name length 4, snap 8, hash 4 */
		q = b + n - 39 + (6 + 4 + 4 + 8 + 4);
		WRT_CHECK(*q == 1);
		*q = 0x7F;
		WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 1, &m));
		WRT_CHECK(m.end.max == 1);
	}

	/* versions: the message header's pair */
	t = tb_make();
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_VERSION, bdec(b, n, 0, 1, &m));
	WRT_CHECK_STATUS(WR_E_OSD_VERSION, bdec(b, n, 1, 2, &m));
	WRT_CHECK_STATUS(WR_E_OSD_VERSION, bdec(b, n, 0xFFFF, 0xFFFF, &m));
	WRT_CHECK(all_zero(&m, sizeof(m)));
	WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 0, &m));
	/* a later revision of the message (version 2, still compat 1) may append fields after the positions */
	t.tail = 9;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, bdec(b, n, 2, 1, &m));
	WRT_CHECK_STATUS(WR_OK, bdec(b, n, 9, 1, &m));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m)); /* but not in the version we implement */
	t.tail = 0;

	/* the pg_t and spg_t */
	t.pg_ver = 0;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
	t.pg_ver = 2;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
	t.pg_ver = 1;
	t.shard = 0; /* an erasure shard: not echoed by our ACK, so not accepted */
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
	t.shard = 0xFE;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
	t.shard = 0xFF;
	t.spg_extra = 5; /* a later spg_t revision: the tail is skipped by its length */
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 1, &m));
	WRT_CHECK(m.pool == 5 && m.pg_seed == 0x1a && m.map_epoch == 77);
	t.spg_extra = 0;
	t.spg_compat = 2; /* a newer incompatible spg_t */
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_VERSION, bdec(b, n, 1, 1, &m));
	t.spg_compat = 1;

	/* the hobject_t struct header: older layouts and newer incompatible ones are refused, a newer compatible one is read */
	t.begin.v = 3;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_VERSION, bdec(b, n, 1, 1, &m));
	t.begin.v = 5;
	t.begin.extra = 12;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 1, &m));
	WRT_CHECK(hobj_eq_th(&m.begin, &t.begin) && hobj_eq_th(&m.end, &t.end));
	t.begin.compat = 5;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_VERSION, bdec(b, n, 1, 1, &m));
	t.begin.compat = 4; /* compat 4 is still readable by a reader of version 4 */
	t.begin.v = 5;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 1, &m));
	t.begin.extra = 0;
	t.begin.compat = 3;
	t.begin.v = 4;
	t.end.v = 2;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_VERSION, bdec(b, n, 1, 1, &m));
	t.end.v = 0;
	/* struct_len that lies: too long for the message, too short for the fields */
	t.begin.body_lie = 0x7FFFFFFF;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
	t.begin.body_lie = 20;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
	t.begin.body_lie = 0;
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
	t.begin.body_lie = -1;

	/* the string caps: key and name 2048, namespace 256 */
	{
		static char big[3000];

		memset(big, 'z', sizeof(big));
		t = tb_make();
		t.begin = th_make("", "", "", 0, 1, 5);
		t.begin.oid = big;
		t.begin.oid_len = 2048;
		n = tb_build(&t, b, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 1, &m));
		WRT_CHECK(m.begin.oid_len == 2048);
		t.begin.oid_len = 2049;
		n = tb_build(&t, b, sizeof(b));
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
		WRT_CHECK(all_zero(&m, sizeof(m)));
		t.begin.oid_len = 3;
		t.begin.key = big;
		t.begin.key_len = 2048;
		n = tb_build(&t, b, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 1, &m));
		t.begin.key_len = 2049;
		n = tb_build(&t, b, sizeof(b));
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
		t.begin.key_len = 0;
		t.begin.ns = big;
		t.begin.ns_len = 256;
		n = tb_build(&t, b, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 1, &m));
		WRT_CHECK(m.begin.nspace_len == 256);
		t.begin.ns_len = 257;
		n = tb_build(&t, b, sizeof(b));
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
		/* a name length that claims more than the message holds, in either position */
		{
			static const int64_t lies[] = {4, 100, 2048, 2049, 0x7FFFFFFF, 0xFFFFFFFFll};
			unsigned k;

			for (k = 0; k < sizeof(lies) / sizeof(lies[0]); k++) {
				t = tb_make();
				t.begin = th_make("", "abc", "", 0, 1, 5);
				t.begin.oid_lie = lies[k];
				n = tb_build(&t, b, sizeof(b));
				WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
				WRT_CHECK(all_zero(&m, sizeof(m)));
				t = tb_make();
				t.end = th_make("", "abc", "", 0, 1, 5);
				t.end.oid_lie = lies[k];
				n = tb_build(&t, b, sizeof(b));
				WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n, 1, 1, &m));
			}
		}
	}

	/* truncation at every offset (the whole front is needed: the version 1 message has no trailing part) */
	t = tb_make();
	t.begin = th_make("kk", "object-name", "ns", 9, 0xA5A5A5A5u, 5);
	t.end = th_make("", "object-nome", "ns", 0, 0x5A5A5A5Au, 5);
	n = tb_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, bdec(b, n, 1, 1, &m));
	for (cut = 0; cut < n; cut++) {
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, cut, 1, 1, &m));
		WRT_CHECK(all_zero(&m, sizeof(m)));
	}
	/* one byte too many in version 1 */
	b[n] = 0;
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, bdec(b, n + 1, 1, 1, &m));

	/* arguments */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mbackoff_decode(b, n, 1, 1, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mbackoff_decode(NULL, 5, 1, 1, &m));
	WRT_CHECK(all_zero(&m, sizeof(m)));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_mbackoff_decode(NULL, 0, 1, 1, &m));
}

/* ---- the acknowledgement ----------------------------------------------------------------------------------------------------------- */

static void test_ack(void)
{
	tb t = tb_make();
	tb want;
	static uint8_t blk[16384], ack[16384], exp[16384];
	uint8_t *mcopy;
	size_t n, an, en, cap;
	wri_mbackoff m, m2;
	wri_wr w;
	uint32_t i;

	t.begin = th_make("lk", "object-1", "nspc", 33, 0xCAFEF00Du, 5);
	t.end = th_make("", "object-1", "", 33, 0xCAFEF00Du, 5); /* begin != end here; a single-object backoff is tested below */
	n = tb_build(&t, blk, sizeof(blk));
	mcopy = (uint8_t *)malloc(n); /* `m` borrows from this copy for the whole function (bdec's copy is replaced by every later decode) */
	memcpy(mcopy, blk, n);
	WRT_CHECK_STATUS(WR_OK, wri_mbackoff_decode(mcopy, n, 1, 1, &m));

	/* the answer: same pgid, id, begin, end, the BLOCK's epoch, op ACK_BLOCK; byte for byte what the writer builds */
	want = t;
	want.op = WRI_BACKOFF_ACK_BLOCK;
	en = tb_build(&want, exp, sizeof(exp));
	wri_wr_init(&w, ack, sizeof(ack));
	WRT_CHECK_STATUS(WR_OK, wri_mbackoff_encode_ack(&w, &m));
	an = wri_wr_len(&w);
	WRT_CHECK(an == en && an == wri_mbackoff_ack_len(&m));
	if (an == en)
		WRT_CHECK_MEM(ack, exp, en);
	/* and it reads back as an ACK_BLOCK with the same fields (the decoder accepts the op) */
	WRT_CHECK_STATUS(WR_OK, wri_mbackoff_decode(ack, an, 1, 1, &m2));
	WRT_CHECK(m2.op == WRI_BACKOFF_ACK_BLOCK && m2.id == m.id && m2.map_epoch == m.map_epoch && m2.pool == m.pool && m2.pg_seed == m.pg_seed);
	WRT_CHECK(wri_hobj_cmp(&m2.begin, &m.begin) == 0 && wri_hobj_cmp(&m2.end, &m.end) == 0);
	WRT_CHECK(m2.begin.key_len == 2 && m2.begin.nspace_len == 4 && m2.end.key_len == 0);

	/* the size formula: fixed 115 + the six strings */
	WRT_CHECK(WRI_MBACKOFF_FIXED_LEN == 115u);
	{
		tb e = tb_make();
		wri_mbackoff z;

		e.begin = th_make("", "", "", 0, 0, 0);
		e.end = th_make("", "", "", 0, 0, 0);
		n = tb_build(&e, blk, sizeof(blk));
		WRT_CHECK(n == WRI_MBACKOFF_FIXED_LEN);
		WRT_CHECK_STATUS(WR_OK, bdec(blk, n, 1, 1, &z));
		WRT_CHECK(wri_mbackoff_ack_len(&z) == WRI_MBACKOFF_FIXED_LEN);
	}
	WRT_CHECK(wri_mbackoff_ack_len(NULL) == 0);
	{
		/* a hand-made block with absurd lengths: the sum is taken in 64 bits (saturating on a 32-bit host), never wrapped, and the
		 * encoder refuses it */
		wri_mbackoff big;
		uint64_t sum = (uint64_t)WRI_MBACKOFF_FIXED_LEN + 6u * (uint64_t)0xFFFFFFFFu;
		uint8_t dummy[1] = {0};

		memset(&big, 0, sizeof(big));
		big.op = WRI_BACKOFF_BLOCK;
		big.begin.key = big.begin.oid = big.begin.nspace = dummy;
		big.end.key = big.end.oid = big.end.nspace = dummy;
		big.begin.key_len = big.begin.oid_len = big.begin.nspace_len = 0xFFFFFFFFu;
		big.end.key_len = big.end.oid_len = big.end.nspace_len = 0xFFFFFFFFu;
		WRT_CHECK(wri_mbackoff_ack_len(&big) == (sum > (uint64_t)(size_t)-1 ? (size_t)-1 : (size_t)sum));
		wri_wr_init(&w, ack, sizeof(ack));
		WRT_CHECK_STATUS(WR_E_RANGE, wri_mbackoff_encode_ack(&w, &big));
		WRT_CHECK(w.pos == 0);
	}

	/* every smaller buffer: TOOBIG, never a byte past the cap */
	for (cap = 0; cap < an; cap++) {
		uint8_t *g = (uint8_t *)malloc(cap + 16u);
		size_t k;

		memset(g, 0xA5, cap + 16u);
		wri_wr_init(&w, g, cap);
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_mbackoff_encode_ack(&w, &m));
		for (k = 0; k < 16; k++)
			WRT_CHECK(g[cap + k] == 0xA5);
		free(g);
	}

	/* only a BLOCK is acknowledged */
	for (i = 0; i < 6; i++) {
		wri_mbackoff x = m;

		x.op = (uint8_t)i;
		wri_wr_init(&w, ack, sizeof(ack));
		WRT_CHECK_STATUS(i == WRI_BACKOFF_BLOCK ? WR_OK : WR_E_INVAL, wri_mbackoff_encode_ack(&w, &x));
	}
	/* a position that does not fit the limits, a NULL string with a length, NULL arguments */
	{
		wri_mbackoff x = m;
		static const uint8_t z[1] = {0};

		x.begin.oid_len = WRI_OSD_NAME_LIMIT + 1u;
		wri_wr_init(&w, ack, sizeof(ack));
		WRT_CHECK_STATUS(WR_E_RANGE, wri_mbackoff_encode_ack(&w, &x));
		x = m;
		x.end.nspace_len = 257;
		WRT_CHECK_STATUS(WR_E_RANGE, wri_mbackoff_encode_ack(&w, &x));
		x = m;
		x.end.key_len = 2049;
		WRT_CHECK_STATUS(WR_E_RANGE, wri_mbackoff_encode_ack(&w, &x));
		x = m;
		x.begin.oid = NULL;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mbackoff_encode_ack(&w, &x));
		x = m;
		x.end.nspace = NULL;
		x.end.nspace_len = 0;
		x.end.key = NULL;
		x.end.key_len = 0;
		x.end.oid = z;
		x.end.oid_len = 0;
		WRT_CHECK_STATUS(WR_OK, wri_mbackoff_encode_ack(&w, &x)); /* empty strings need no memory */
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mbackoff_encode_ack(NULL, &m));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mbackoff_encode_ack(&w, NULL));
	}

	/* a single-object backoff (begin == end) and the extremes: a max position, the largest strings, negative pool */
	{
		static char big[2048];
		tb e = tb_make();
		wri_mbackoff z;

		memset(big, 'k', sizeof(big));
		e.pool = -1;
		e.begin = th_make("", "x", "", 1, 2, -1);
		e.begin.key = big;
		e.begin.key_len = 2048;
		e.begin.oid = big;
		e.begin.oid_len = 2048;
		e.begin.ns = big;
		e.begin.ns_len = 256;
		e.end = e.begin;
		e.end.max = 1;
		n = tb_build(&e, blk, sizeof(blk));
		WRT_CHECK_STATUS(WR_OK, bdec(blk, n, 1, 1, &z));
		e.op = WRI_BACKOFF_ACK_BLOCK;
		en = tb_build(&e, exp, sizeof(exp));
		wri_wr_init(&w, ack, sizeof(ack));
		WRT_CHECK_STATUS(WR_OK, wri_mbackoff_encode_ack(&w, &z));
		WRT_CHECK(wri_wr_len(&w) == en && en == wri_mbackoff_ack_len(&z));
		if (wri_wr_len(&w) == en)
			WRT_CHECK_MEM(ack, exp, en);
		WRT_CHECK(en == WRI_MBACKOFF_FIXED_LEN + 2u * (2048u + 2048u + 256u));
	}
	free(mcopy);
}

/* ---- the order of hobject positions: an independent implementation --------------------------------------------------------------- */

typedef struct oh { /* the same object, with owned strings, for the oracle */
	char key[8], oid[8], ns[8];
	uint32_t key_len, oid_len, ns_len;
	uint64_t snap;
	uint32_t hash;
	uint8_t max;
	int64_t pool;
} oh;

static uint32_t rev_bits_loop(uint32_t v)
{
	uint32_t r = 0;
	int i;

	for (i = 0; i < 32; i++)
		if ((v >> i) & 1u)
			r |= 1u << (31 - i);
	return r;
}

static int memcmp_len(const char *a, uint32_t al, const char *b, uint32_t bl)
{
	int c = memcmp(a, b, al < bl ? al : bl);

	if (c != 0)
		return c < 0 ? -1 : 1;
	return al < bl ? -1 : al > bl ? 1 : 0;
}

/* osd-ops.md 2.10, field by field: max, pool, bit-reversed hash, namespace, effective key (skipped if both keys are empty), name, snap */
static int oracle_cmp(const oh *a, const oh *b)
{
	int c;

	if (a->max != b->max)
		return a->max < b->max ? -1 : 1;
	if (a->pool != b->pool)
		return a->pool < b->pool ? -1 : 1;
	if (!a->max) { /* "max sorts above everything" and a max position has no hash of its own */
		uint32_t ra = rev_bits_loop(a->hash), rb = rev_bits_loop(b->hash);

		if (ra != rb)
			return ra < rb ? -1 : 1;
	}
	c = memcmp_len(a->ns, a->ns_len, b->ns, b->ns_len);
	if (c != 0)
		return c;
	if (!(a->key_len == 0 && b->key_len == 0)) {
		const char *ka = a->key_len ? a->key : a->oid;
		uint32_t kal = a->key_len ? a->key_len : a->oid_len;
		const char *kb = b->key_len ? b->key : b->oid;
		uint32_t kbl = b->key_len ? b->key_len : b->oid_len;

		c = memcmp_len(ka, kal, kb, kbl);
		if (c != 0)
			return c;
	}
	c = memcmp_len(a->oid, a->oid_len, b->oid, b->oid_len);
	if (c != 0)
		return c;
	if (a->snap != b->snap)
		return a->snap < b->snap ? -1 : 1;
	return 0;
}

static void to_hobj(wri_hobj *h, const oh *o)
{
	memset(h, 0, sizeof(*h));
	h->key = (const uint8_t *)o->key;
	h->key_len = o->key_len;
	h->oid = (const uint8_t *)o->oid;
	h->oid_len = o->oid_len;
	h->nspace = (const uint8_t *)o->ns;
	h->nspace_len = o->ns_len;
	h->snap = o->snap;
	h->hash = o->hash;
	h->max = o->max;
	h->pool = o->pool;
}

static uint64_t rng_s = 0x0DDBA11CAFEF00D5ull;

static uint64_t rnd(void)
{
	rng_s ^= rng_s >> 12;
	rng_s ^= rng_s << 25;
	rng_s ^= rng_s >> 27;
	return rng_s * 0x2545F4914F6CDD1Dull;
}

static uint32_t pick(uint32_t n)
{
	return (uint32_t)(rnd() % n);
}

/* A random position from small palettes so that equal fields (and equal prefixes) are common. */
static void rand_oh(oh *o)
{
	static const char *const strs[] = {"", "a", "ab", "abc", "b", "\xff", "\x80z", "a\xff", "\x01"};
	static const uint32_t hashes[] = {0, 1, 2, 0x80000000u, 0x40000000u, 0xFFFFFFFFu, 0x12345678u, 0x1e6a2c48u, 3};
	static const uint64_t snaps[] = {0, 1, 5, 0xfffffffffffffffdull, 0xfffffffffffffffeull, 0xFFFFFFFFFFFFFFFFull};
	const char *s;

	memset(o, 0, sizeof(*o));
	s = strs[pick(9)];
	o->key_len = (uint32_t)strlen(s);
	memcpy(o->key, s, o->key_len);
	s = strs[pick(9)];
	o->oid_len = (uint32_t)strlen(s);
	memcpy(o->oid, s, o->oid_len);
	s = strs[pick(9)];
	o->ns_len = (uint32_t)strlen(s);
	memcpy(o->ns, s, o->ns_len);
	/* make the equal-effective-key case common: copy the name into the key */
	if (pick(5) == 0) {
		o->key_len = o->oid_len;
		memcpy(o->key, o->oid, o->oid_len);
	}
	o->snap = snaps[pick(6)];
	o->hash = pick(3) == 0 ? (uint32_t)rnd() : hashes[pick(9)];
	o->max = pick(8) == 0;
	o->pool = pick(6) == 0 ? (int64_t)rnd() : (int64_t)pick(4) - 1;
}

static int sgn(int v)
{
	return v < 0 ? -1 : v > 0 ? 1 : 0;
}

static void test_order_random(void)
{
	unsigned it;
	unsigned eq = 0, lt = 0, gt = 0;

	for (it = 0; it < 300000; it++) {
		oh a, b;
		wri_hobj ha, hb;
		int got, want;

		rand_oh(&a);
		if (pick(3) == 0) { /* b close to a: change one field */
			b = a;
			switch (pick(7)) {
			case 0: b.max ^= 1; break;
			case 1: b.pool += 1; break;
			case 2: b.hash ^= 1u << pick(32); break;
			case 3: b.ns[0] ^= 1; if (!b.ns_len) { b.ns_len = 1; } break;
			case 4: b.oid[0] ^= 1; if (!b.oid_len) { b.oid_len = 1; } break;
			case 5: b.snap += 1; break;
			default: b.key[0] ^= 1; if (!b.key_len) { b.key_len = 1; } break;
			}
		} else if (pick(6) == 0) { /* the same position, written two ways: a key equal to the name, or no key */
			b = a;
			if (a.key_len == 0) {
				b.key_len = a.oid_len;
				memcpy(b.key, a.oid, a.oid_len);
			} else if (a.key_len == a.oid_len && memcmp(a.key, a.oid, a.key_len) == 0) {
				b.key_len = 0;
			}
		} else {
			rand_oh(&b);
		}
		to_hobj(&ha, &a);
		to_hobj(&hb, &b);
		got = wri_hobj_cmp(&ha, &hb);
		want = oracle_cmp(&a, &b);
		if (sgn(got) != want) {
			fprintf(stderr, "order mismatch at %u: got %d want %d\n", it, got, want);
			WRT_CHECK(0);
			return;
		}
		wrt_checks++;
		/* antisymmetry and reflexivity */
		WRT_CHECK(sgn(wri_hobj_cmp(&hb, &ha)) == -want);
		WRT_CHECK(wri_hobj_cmp(&ha, &ha) == 0);
		if (want < 0)
			lt++;
		else if (want > 0)
			gt++;
		else
			eq++;
	}
	/* the random pairs reached every outcome, equal ones included */
	WRT_CHECK(eq > 100 && lt > 1000 && gt > 1000);
}

static void test_order_transitive(void)
{
	enum { N = 60 };
	oh o[N];
	unsigned i, j, k;

	for (i = 0; i < N; i++)
		rand_oh(&o[i]);
	for (i = 0; i < N; i++)
		for (j = 0; j < N; j++)
			for (k = 0; k < N; k++) {
				wri_hobj a, b, c;

				to_hobj(&a, &o[i]);
				to_hobj(&b, &o[j]);
				to_hobj(&c, &o[k]);
				if (wri_hobj_cmp(&a, &b) <= 0 && wri_hobj_cmp(&b, &c) <= 0 && wri_hobj_cmp(&a, &c) > 0) {
					WRT_CHECK(0);
					return;
				}
			}
	wrt_checks++;
}

static void test_order_known(void)
{
	wri_hobj a, b;
	static const uint8_t n1[] = "n";
	static const uint8_t k1[] = "k";
	static const uint8_t z1[] = "z";
	static const uint8_t a1[] = "a";

	wri_hobj_of_request(&a, 3, 0x80000000u, NULL, 0, n1, 1);
	wri_hobj_of_request(&b, 3, 0x00000001u, NULL, 0, n1, 1);
	WRT_CHECK(wri_hobj_cmp(&a, &b) < 0); /* bit reversed: 0x80000000 reverses to 1, 1 reverses to 0x80000000 */
	wri_hobj_of_request(&a, 3, 0x2, NULL, 0, n1, 1);
	wri_hobj_of_request(&b, 3, 0x1, NULL, 0, n1, 1);
	WRT_CHECK(wri_hobj_cmp(&a, &b) < 0 && wri_hobj_cmp(&b, &a) > 0);
	wri_hobj_of_request(&a, 3, 0x0, NULL, 0, n1, 1);
	wri_hobj_of_request(&b, 3, 0x1, NULL, 0, n1, 1);
	WRT_CHECK(wri_hobj_cmp(&a, &b) < 0);
	/* the pool dominates the hash, the max flag dominates the pool */
	wri_hobj_of_request(&a, 2, 0xFFFFFFFFu, NULL, 0, n1, 1);
	wri_hobj_of_request(&b, 3, 0x0, NULL, 0, n1, 1);
	WRT_CHECK(wri_hobj_cmp(&a, &b) < 0);
	b.max = 1;
	a.pool = 100;
	WRT_CHECK(wri_hobj_cmp(&a, &b) < 0 && wri_hobj_cmp(&b, &a) > 0);
	/* two max positions are equal whatever their hashes (the hash does not take part) */
	a.max = 1;
	a.pool = b.pool;
	a.hash = 5;
	b.hash = 9;
	WRT_CHECK(wri_hobj_cmp(&a, &b) == 0);
	/* the key replaces the name in the order, an empty key means the name; the name then breaks ties */
	wri_hobj_of_request(&a, 3, 7, NULL, 0, z1, 1);
	a.key = k1;
	a.key_len = 1;                              /* effective key "k", name "z" */
	wri_hobj_of_request(&b, 3, 7, NULL, 0, a1, 1); /* effective key "a" (its name) */
	WRT_CHECK(wri_hobj_cmp(&a, &b) > 0);
	b.oid = k1;                                 /* effective key "k", name "k": ties on the key, "z" > "k" */
	WRT_CHECK(wri_hobj_cmp(&a, &b) > 0);
	b.key = k1;
	b.key_len = 1;
	WRT_CHECK(wri_hobj_cmp(&a, &b) > 0);
	a.oid = k1;
	WRT_CHECK(wri_hobj_cmp(&a, &b) == 0);       /* key "k" name "k" equals key "k" name "k" */
	b.key = NULL;
	b.key_len = 0;                              /* key empty: effective key is the name "k" */
	WRT_CHECK(wri_hobj_cmp(&a, &b) == 0);       /* the same position, as the OSD stores a key equal to the name */
	/* the namespace comes before the key and the name */
	wri_hobj_of_request(&a, 3, 7, k1, 1, a1, 1);
	wri_hobj_of_request(&b, 3, 7, NULL, 0, z1, 1);
	WRT_CHECK(wri_hobj_cmp(&a, &b) > 0);
	/* strings compare as unsigned bytes, a proper prefix first */
	{
		static const uint8_t hi[] = {0xFF};
		static const uint8_t lo[] = {0x7F};
		static const uint8_t ab[] = "ab";
		static const uint8_t abc[] = "abc";

		wri_hobj_of_request(&a, 3, 7, NULL, 0, hi, 1);
		wri_hobj_of_request(&b, 3, 7, NULL, 0, lo, 1);
		WRT_CHECK(wri_hobj_cmp(&a, &b) > 0);
		wri_hobj_of_request(&a, 3, 7, NULL, 0, ab, 2);
		wri_hobj_of_request(&b, 3, 7, NULL, 0, abc, 3);
		WRT_CHECK(wri_hobj_cmp(&a, &b) < 0);
	}
	/* snapshot ids last */
	wri_hobj_of_request(&a, 3, 7, NULL, 0, n1, 1);
	b = a;
	b.snap = 4;
	WRT_CHECK(wri_hobj_cmp(&b, &a) < 0);
	b.snap = 0xFFFFFFFFFFFFFFFFull;
	WRT_CHECK(wri_hobj_cmp(&b, &a) > 0);
}

static void test_of_request(void)
{
	wri_hobj h;
	static const uint8_t ns[] = "tenant";
	static const uint8_t nm[] = "rbd_data.1.2";

	memset(&h, 0xEE, sizeof(h));
	wri_hobj_of_request(&h, 12, 0xABCD1234u, ns, 6, nm, 12);
	WRT_CHECK(h.pool == 12 && h.hash == 0xABCD1234u && h.snap == WRI_SNAP_NOSNAP && h.max == 0);
	WRT_CHECK(h.key_len == 0 && h.oid == nm && h.oid_len == 12 && h.nspace == ns && h.nspace_len == 6);
	wri_hobj_of_request(&h, 1, 2, NULL, 0, nm, 12);
	WRT_CHECK(h.nspace_len == 0 && h.key_len == 0 && h.max == 0);
	wri_hobj_of_request(NULL, 1, 2, NULL, 0, nm, 12); /* must not crash */
}

/* ---- coverage -------------------------------------------------------------------------------------------------------------------------- */

static wri_mbackoff mb_of(const wri_hobj *b, const wri_hobj *e)
{
	wri_mbackoff m;

	memset(&m, 0, sizeof(m));
	m.pool = b->pool;
	m.begin = *b;
	m.end = *e;
	return m;
}

static void test_covers(void)
{
	static const uint8_t n_a[] = "a", n_b[] = "b", n_c[] = "c", n_d[] = "d", n_e[] = "e";
	wri_hobj ha, hb, hc, hd, he, pos;
	wri_mbackoff m;

	wri_hobj_of_request(&ha, 4, 100, NULL, 0, n_a, 1);
	wri_hobj_of_request(&hb, 4, 100, NULL, 0, n_b, 1);
	wri_hobj_of_request(&hc, 4, 100, NULL, 0, n_c, 1);
	wri_hobj_of_request(&hd, 4, 100, NULL, 0, n_d, 1);
	wri_hobj_of_request(&he, 4, 100, NULL, 0, n_e, 1);

	/* begin == end: that one object only */
	m = mb_of(&hc, &hc);
	WRT_CHECK(wri_mbackoff_covers(&m, &hc) == 1);
	WRT_CHECK(wri_mbackoff_covers(&m, &hb) == 0 && wri_mbackoff_covers(&m, &hd) == 0);
	pos = hc;
	pos.snap = 9; /* the same name at another snapshot is another position */
	WRT_CHECK(wri_mbackoff_covers(&m, &pos) == 0);
	pos = hc;
	pos.hash ^= 1;
	WRT_CHECK(wri_mbackoff_covers(&m, &pos) == 0);
	pos = hc;
	pos.pool = 5;
	WRT_CHECK(wri_mbackoff_covers(&m, &pos) == 0);
	/* a request of that very object: its snap is NOSNAP, so a backoff of the head object is begin == end with NOSNAP */
	{
		wri_hobj r;

		wri_hobj_of_request(&r, 4, 100, NULL, 0, n_c, 1);
		WRT_CHECK(wri_mbackoff_covers(&m, &r) == 1);
	}

	/* [begin, end): begin in, end out, the middle in, outside out */
	m = mb_of(&hb, &hd);
	WRT_CHECK(wri_mbackoff_covers(&m, &ha) == 0);
	WRT_CHECK(wri_mbackoff_covers(&m, &hb) == 1);
	WRT_CHECK(wri_mbackoff_covers(&m, &hc) == 1);
	WRT_CHECK(wri_mbackoff_covers(&m, &hd) == 0);
	WRT_CHECK(wri_mbackoff_covers(&m, &he) == 0);
	/* the snapshot ids of an object at the edges: (b, snap 0) < (b, NOSNAP); (d, 0) < (d, NOSNAP) = end if end carries NOSNAP */
	pos = hb;
	pos.snap = 0;
	WRT_CHECK(wri_mbackoff_covers(&m, &pos) == 0); /* sorts below begin (b, NOSNAP) */
	pos = hd;
	pos.snap = 0;
	WRT_CHECK(wri_mbackoff_covers(&m, &pos) == 1); /* sorts below end (d, NOSNAP) */

	/* reversed bounds cover nothing; an empty-looking range [x, x) is the single-object case, not nothing */
	m = mb_of(&hd, &hb);
	WRT_CHECK(wri_mbackoff_covers(&m, &hc) == 0 && wri_mbackoff_covers(&m, &hb) == 0 && wri_mbackoff_covers(&m, &hd) == 0);

	/* a range that ends at the max position (the tail of the PG space) covers everything above begin */
	{
		wri_hobj mx;

		memset(&mx, 0, sizeof(mx));
		mx.max = 1;
		mx.pool = 4;
		m = mb_of(&hb, &mx);
		WRT_CHECK(wri_mbackoff_covers(&m, &hb) == 1 && wri_mbackoff_covers(&m, &he) == 1 && wri_mbackoff_covers(&m, &ha) == 0);
		wri_hobj_of_request(&pos, 4, 0xFFFFFFFFu, NULL, 0, n_e, 1);
		WRT_CHECK(wri_mbackoff_covers(&m, &pos) == 1); /* the highest hash of the pool is still below the max position */
		WRT_CHECK(wri_mbackoff_covers(&m, &mx) == 0);  /* the end itself is out */
		/* the PG-wide case: begin = lowest hash of the PG, end = lowest hash of the next one (bit reversed order) */
		{
			wri_hobj lo, hi, in_pg, out_pg;
			uint32_t pg_lo = 0x00000001u, pg_hi = 0x80000001u; /* hash bits are reversed: these two reverse to 0x80000000 and 0x80000001 */

			wri_hobj_of_request(&lo, 4, pg_lo, NULL, 0, n_a, 0);
			lo.snap = 0;
			wri_hobj_of_request(&hi, 4, pg_hi, NULL, 0, n_a, 0);
			hi.snap = 0;
			m = mb_of(&lo, &hi);
			wri_hobj_of_request(&in_pg, 4, pg_lo, NULL, 0, n_a, 1);
			wri_hobj_of_request(&out_pg, 4, pg_hi, NULL, 0, n_a, 1);
			WRT_CHECK(wri_mbackoff_covers(&m, &in_pg) == 1);
			WRT_CHECK(wri_mbackoff_covers(&m, &out_pg) == 0);
			wri_hobj_of_request(&out_pg, 4, 0x2, NULL, 0, n_a, 1); /* reverses to 0x40000000: below the begin */
			WRT_CHECK(wri_mbackoff_covers(&m, &out_pg) == 0);
		}
	}
	WRT_CHECK(wri_mbackoff_covers(NULL, &ha) == 0);
	WRT_CHECK(wri_mbackoff_covers(&m, NULL) == 0);
}

/* Coverage against the oracle order on random ranges and positions. */
static void test_covers_random(void)
{
	unsigned it, hit = 0, miss = 0;

	for (it = 0; it < 100000; it++) {
		oh b, e, p;
		wri_hobj hb, he, hp;
		wri_mbackoff m;
		int want, got;

		rand_oh(&b);
		if (pick(4) == 0)
			e = b;
		else
			rand_oh(&e);
		if (pick(2) == 0) { /* a position near the range */
			p = pick(2) ? b : e;
			p.snap += pick(3) - 1u;
			p.hash ^= pick(3) == 0 ? 1u << pick(32) : 0u;
		} else {
			rand_oh(&p);
		}
		to_hobj(&hb, &b);
		to_hobj(&he, &e);
		to_hobj(&hp, &p);
		m = mb_of(&hb, &he);
		if (oracle_cmp(&b, &e) == 0)
			want = oracle_cmp(&p, &b) == 0;
		else
			want = oracle_cmp(&b, &p) <= 0 && oracle_cmp(&p, &e) < 0;
		got = wri_mbackoff_covers(&m, &hp);
		if (got != want) {
			fprintf(stderr, "covers mismatch at %u: got %d want %d\n", it, got, want);
			WRT_CHECK(0);
			return;
		}
		wrt_checks++;
		if (want)
			hit++;
		else
			miss++;
	}
	WRT_CHECK(hit > 1000 && miss > 1000);
}

int main(void)
{
	test_decode();
	free(bo_copy);
	bo_copy = NULL;
	test_ack();
	test_order_random();
	test_order_transitive();
	test_order_known();
	test_of_request();
	test_covers();
	test_covers_random();
	return wrt_finish();
}
