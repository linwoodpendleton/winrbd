/* SPDX-License-Identifier: MIT */
/*
 * test_osd_msg_enc.c - module osd-msg, the request side (core/src/osd/wri_osd_msg.c): wri_mosdop_encode, wri_osd_op_put,
 * wri_mosdop_front_max, wri_snapc_valid, wri_osd_errno_status.
 *
 * The oracle is the set of captured requests of harness/vectors/osdop/ (written by the stock client of a v20.2.5 cluster): every one is
 * rebuilt from its summary and must come out byte for byte, as v9 and, minus the 7 otel bytes, as v8. The rest checks every refusal,
 * the RETRY rule, the front size bound over random headers and the behaviour on a buffer that is too small.
 */
#include "osd_msg_rig.h"

/* ---- a small PRNG (xorshift64*), deterministic ---------------------------------------------------------------------------------- */

static uint64_t rng_s = 0x9E3779B97F4A7C15ull;

static uint64_t rnd(void)
{
	rng_s ^= rng_s >> 12;
	rng_s ^= rng_s << 25;
	rng_s ^= rng_s >> 27;
	return rng_s * 0x2545F4914F6CDD1Dull;
}

static uint32_t rnd_to(uint32_t n) /* 0 .. n-1 */
{
	return (uint32_t)(rnd() % n);
}

/* ---- helpers ---------------------------------------------------------------------------------------------------------------- */

/* Encode into a buffer of exactly cap bytes surrounded by guard bytes; returns the status and the length written. */
static wr_status enc_guard(const wri_mosdop_hdr *h, const wri_osd_opd *ops, unsigned n, uint8_t *dst, size_t cap, size_t *len)
{
	uint8_t *buf = (uint8_t *)malloc(cap + 32u);
	wri_wr w;
	wr_status st;
	size_t i;

	memset(buf, 0xA5, cap + 32u);
	wri_wr_init(&w, buf + 16, cap);
	st = wri_mosdop_encode(&w, h, ops, n);
	for (i = 0; i < 16; i++)
		WRT_CHECK(buf[i] == 0xA5 && buf[16 + cap + i] == 0xA5); /* never a byte outside the buffer */
	*len = w.pos;
	if (dst != NULL && cap != 0)
		memcpy(dst, buf + 16, cap);
	free(buf);
	return st;
}

static wri_mosdop_hdr base_hdr(const uint8_t *oid, uint32_t oid_len)
{
	wri_mosdop_hdr h;

	memset(&h, 0, sizeof(h));
	h.version = WRI_MOSDOP_VERSION;
	h.pool = 7;
	h.pg_seed = 0x1a;
	h.hash = 0xdeadbeefu;
	h.map_epoch = 42;
	h.flags = WRI_OSDF_BASE_READ;
	h.oid = oid;
	h.oid_len = oid_len;
	h.snapid = WRI_SNAP_NOSNAP;
	h.features = 0x3f07fffffffdffffull;
	return h;
}

static wri_osd_opd read_op(uint64_t off, uint64_t len)
{
	wri_osd_opd o;

	memset(&o, 0, sizeof(o));
	o.code = WRI_OSD_OP_READ;
	o.off = off;
	o.len = len;
	return o;
}

static wri_osd_opd write_op(uint64_t off, uint32_t len)
{
	wri_osd_opd o;

	memset(&o, 0, sizeof(o));
	o.code = WRI_OSD_OP_WRITE;
	o.off = off;
	o.len = len;
	o.in_len = len;
	return o;
}

/* ---- the captured vectors ------------------------------------------------------------------------------------------------------- */

static void test_vectors(void)
{
	unsigned k;

	for (k = 0; k < RIG_NVEC; k++) {
		rig_vec v;
		rig_req q;
		size_t front_max, len;
		uint8_t *buf;
		wri_wr w;
		uint8_t *v8;

		if (rig_vec_load(&v, rig_vec_name[k]) != 0 || rig_req_build(&q, &v) != 0) {
			fprintf(stderr, "cannot load vector %s\n", rig_vec_name[k]);
			WRT_CHECK(0);
			continue;
		}
		/* v9 */
		front_max = wri_mosdop_front_max(q.h.oid_len, 0, q.n_ops, q.snapc.n);
		buf = (uint8_t *)malloc(front_max);
		wri_wr_init(&w, buf, front_max);
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &q.h, q.ops, q.n_ops));
		len = wri_wr_len(&w);
		if (len != v.req_len)
			fprintf(stderr, "%s: encoded %zu bytes, captured %zu\n", rig_vec_name[k], len, v.req_len);
		WRT_CHECK(len == v.req_len);
		if (len == v.req_len)
			WRT_CHECK_MEM(buf, v.req_front, len);
		WRT_CHECK(len == front_max); /* the bound is exact for a v9 message */

		/* a write-flagged message with an empty context reads back as seq 0 and no ids, as the capture has it */
		/* v8: the same bytes without the 7 otel bytes */
		q.h.version = WRI_MOSDOP_VERSION_V8;
		wri_wr_init(&w, buf, front_max);
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &q.h, q.ops, q.n_ops));
		WRT_CHECK(wri_wr_len(&w) == v.req_len - RIG_OTEL_LEN);
		v8 = (uint8_t *)malloc(v.req_len);
		memcpy(v8, v.req_front, RIG_OTEL_AT);
		memcpy(v8 + RIG_OTEL_AT, v.req_front + RIG_OTEL_AT + RIG_OTEL_LEN, v.req_len - RIG_OTEL_AT - RIG_OTEL_LEN);
		if (wri_wr_len(&w) == v.req_len - RIG_OTEL_LEN)
			WRT_CHECK_MEM(buf, v8, v.req_len - RIG_OTEL_LEN);
		free(v8);
		free(buf);
		rig_req_free(&q);
		rig_vec_free(&v);
	}
}

/* The 217 byte worked example of osd-ops.md 5.1, spelled out here as well (vector 19 holds the same bytes). */
static void test_note_example(void)
{
	static const uint8_t oid[1] = {'a'};
	wri_mosdop_hdr h = base_hdr(oid, 1);
	wri_osd_opd op = read_op(0, 4096);
	uint8_t buf[300];
	wri_wr w;

	h.pool = 1;
	h.pg_seed = 0x38;
	h.hash = 0x12345678u;
	h.map_epoch = 5;
	h.features = 0;
	wri_wr_init(&w, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, &op, 1));
	WRT_CHECK(wri_wr_len(&w) == 217u);
	WRT_CHECK(wri_mosdop_front_max(1, 0, 1, 0) == 217u);
	/* spg_t, hash, epoch, flags: hand-checked bytes */
	{
		static const uint8_t head[] = {0x01, 0x01, 0x12, 0, 0, 0, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x38, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff,
					       0x78, 0x56, 0x34, 0x12, 0x05, 0, 0, 0, 0x14, 0x00, 0x40, 0x08};
		WRT_CHECK_MEM(buf, head, sizeof(head));
	}
	/* the tail: snapid NOSNAP, seq 0, no ids, retry 0, features 0 */
	{
		static const uint8_t tail[32] = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; /* then 24 zero bytes */
		WRT_CHECK_MEM(buf + 217 - sizeof(tail), tail, sizeof(tail));
	}
}

/* ---- the operation record ---------------------------------------------------------------------------------------------------- */

static void test_op_put(void)
{
	uint8_t b[64];
	wri_wr w;
	wri_osd_opd o;
	size_t i;

	/* extent operations: offset @6, length @14, truncate_size and truncate_seq zero, payload_len @34 */
	memset(&o, 0, sizeof(o));
	o.code = WRI_OSD_OP_WRITE;
	o.flags = 0x0102;
	o.in_len = 0xAABBCCDDu;
	o.off = 0x1122334455667788ull;
	o.len = 0x99AABBCCDDEEFF00ull;
	memset(b, 0xEE, sizeof(b));
	wri_wr_init(&w, b, WRI_OSD_OPREC_LEN);
	wri_osd_op_put(&w, &o);
	WRT_CHECK(wri_wr_ok(&w) && wri_wr_len(&w) == 38u);
	{
		static const uint8_t want[38] = {0x01, 0x22, 0x02, 0x01, 0, 0, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC,
						 0xBB, 0xAA, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xDD, 0xCC, 0xBB, 0xAA};
		WRT_CHECK_MEM(b, want, 38);
	}

	/* CALL: class_len @6, method_len @7, argc @8 = 0, indata_len @9 = in_len - names, zeros to @34, payload_len @34 = in_len */
	memset(&o, 0, sizeof(o));
	o.code = WRI_OSD_OP_CALL;
	o.cls_class_len = 3;
	o.cls_method_len = 8;
	o.in_len = 19;
	memset(b, 0xEE, sizeof(b));
	wri_wr_init(&w, b, WRI_OSD_OPREC_LEN);
	wri_osd_op_put(&w, &o);
	WRT_CHECK(wri_wr_ok(&w) && wri_wr_len(&w) == 38u);
	WRT_CHECK(b[0] == 0x01 && b[1] == 0x14 && b[6] == 3 && b[7] == 8 && b[8] == 0 && b[9] == 8 && b[10] == 0 && b[11] == 0 && b[12] == 0);
	for (i = 13; i < 34; i++)
		WRT_CHECK(b[i] == 0);
	WRT_CHECK(b[34] == 19 && b[35] == 0 && b[36] == 0 && b[37] == 0);

	/* too small: TOOBIG, nothing past the cap */
	memset(b, 0xEE, sizeof(b));
	wri_wr_init(&w, b, 37);
	wri_osd_op_put(&w, &o);
	WRT_CHECK(w.err == WR_E_TOOBIG);
	WRT_CHECK(b[37] == 0xEE);
	wri_wr_init(&w, b, 64);
	wri_osd_op_put(&w, NULL);
	WRT_CHECK(w.err == WR_E_INVAL);
}

/* ---- a write with a snapshot context ---------------------------------------------------------------------------------------- */

static void test_write_snapc(void)
{
	static const uint8_t oid[] = "rbd_data.1234.0000000000000001";
	static uint64_t snaps[3] = {20, 12, 5};
	wri_snapc sc;
	wri_mosdop_hdr h = base_hdr(oid, 30);
	wri_osd_opd op = write_op(4096, 512);
	uint8_t buf[512], *tail;
	size_t len;
	wr_status st;

	sc.seq = 20;
	sc.n = 3;
	sc.cap = 3;
	sc.snaps = snaps;
	h.flags = WRI_OSDF_BASE_WRITE;
	h.snapc = &sc;
	h.mtime_sec = 1700000000u;
	h.mtime_nsec = 123456789u;
	st = enc_guard(&h, &op, 1, buf, sizeof(buf), &len);
	WRT_CHECK_STATUS(WR_OK, st);
	WRT_CHECK(len == wri_mosdop_front_max(30, 0, 1, 3));
	/* snapid, seq, count, the ids, retry, features */
	tail = buf + len - (8 + 8 + 4 + 24 + 4 + 8);
	WRT_CHECK_U64(rig_le64(tail), WRI_SNAP_NOSNAP);
	WRT_CHECK_U64(rig_le64(tail + 8), 20);
	WRT_CHECK_U64(rig_le32(tail + 16), 3);
	WRT_CHECK_U64(rig_le64(tail + 20), 20);
	WRT_CHECK_U64(rig_le64(tail + 28), 12);
	WRT_CHECK_U64(rig_le64(tail + 36), 5);
	WRT_CHECK_U64(rig_le32(tail + 44), 0);
	WRT_CHECK_U64(rig_le64(tail + 48), h.features);
	WRT_CHECK_U64(rig_le32(buf + RIG_MTIME_AT), 1700000000u);
	WRT_CHECK_U64(rig_le32(buf + RIG_MTIME_AT + 4), 123456789u);

	/* a read message ignores the context: seq 0, no ids, and an invalid one is not refused */
	h.flags = WRI_OSDF_BASE_READ;
	op = read_op(0, 4096);
	sc.seq = 3; /* snaps[0] > seq: invalid for a write */
	st = enc_guard(&h, &op, 1, buf, sizeof(buf), &len);
	WRT_CHECK_STATUS(WR_OK, st);
	WRT_CHECK(len == wri_mosdop_front_max(30, 0, 1, 0));
	tail = buf + len - (8 + 8 + 4 + 4 + 8);
	WRT_CHECK_U64(rig_le64(tail + 8), 0);
	WRT_CHECK_U64(rig_le32(tail + 16), 0);

	/* a read of a snapshot: snapid goes out as given */
	h.snapid = 17;
	st = enc_guard(&h, &op, 1, buf, sizeof(buf), &len);
	WRT_CHECK_STATUS(WR_OK, st);
	WRT_CHECK_U64(rig_le64(buf + len - (8 + 8 + 4 + 4 + 8)), 17);
}

/* ---- a namespace ------------------------------------------------------------------------------------------------------------- */

static void test_namespace(void)
{
	static const uint8_t oid[] = "obj";
	static const uint8_t ns[] = "tenant7";
	wri_mosdop_hdr h = base_hdr(oid, 3);
	wri_osd_opd op = read_op(0, 1);
	uint8_t buf[300];
	size_t len;
	const uint8_t *ol;

	h.nspace = ns;
	h.nspace_len = 7;
	WRT_CHECK_STATUS(WR_OK, enc_guard(&h, &op, 1, buf, sizeof(buf), &len));
	WRT_CHECK(len == wri_mosdop_front_max(3, 7, 1, 0));
	ol = buf + 106; /* the locator: v6 compat 3, len, pool, -1, key "", nspace, hash -1 */
	WRT_CHECK(ol[0] == 6 && ol[1] == 3);
	WRT_CHECK_U64(rig_le32(ol + 2), 8 + 4 + 4 + 4 + 7 + 8);
	WRT_CHECK_U64(rig_le64(ol + 6), 7);
	WRT_CHECK_U64(rig_le32(ol + 14), 0xFFFFFFFFu);
	WRT_CHECK_U64(rig_le32(ol + 18), 0);
	WRT_CHECK_U64(rig_le32(ol + 22), 7);
	WRT_CHECK_MEM(ol + 26, ns, 7);
	WRT_CHECK_U64(rig_le64(ol + 33), 0xFFFFFFFFFFFFFFFFull);
	/* the name follows the locator */
	WRT_CHECK_U64(rig_le32(ol + 41), 3);
	WRT_CHECK_MEM(ol + 45, oid, 3);
}

/* ---- the refusals -------------------------------------------------------------------------------------------------------------- */

static void check_refused(const wri_mosdop_hdr *h, const wri_osd_opd *ops, unsigned n, wr_status want, int line)
{
	uint8_t buf[2400];
	wri_wr w;
	wr_status st;

	memset(buf, 0x77, sizeof(buf));
	wri_wr_init(&w, buf, sizeof(buf));
	st = wri_mosdop_encode(&w, h, ops, n);
	wrt_checks++;
	if (st != want) {
		wrt_failures++;
		fprintf(stderr, "%s:%d: refusal returned %d (%s), want %d (%s)\n", __FILE__, line, (int)st, wrt_status_name_(st), (int)want,
			wrt_status_name_(want));
	}
	/* a refusal writes nothing and leaves the writer clean */
	WRT_CHECK(w.pos == 0 && w.err == WR_OK && buf[0] == 0x77);
}

#define REFUSED(h, ops, n, want) check_refused((h), (ops), (n), (want), __LINE__)

static void test_refusals(void)
{
	static const uint8_t oid[] = "o";
	static uint8_t longname[3000];
	static uint64_t good[3] = {9, 6, 2};
	static uint64_t bad_order[3] = {9, 9, 2};
	static uint64_t bad_asc[2] = {2, 9};
	static uint64_t bad_top[2] = {11, 6};
	static uint64_t zero_then[3] = {5, 0, 0};
	wri_mosdop_hdr h = base_hdr(oid, 1);
	wri_osd_opd r = read_op(0, 10);
	wri_osd_opd w1 = write_op(0, 10);
	wri_osd_opd ops9[9];
	wri_snapc sc;
	unsigned i;

	memset(longname, 'x', sizeof(longname));

	/* versions */
	h.version = 7;
	REFUSED(&h, &r, 1, WR_E_UNSUPPORTED);
	h.version = 10;
	REFUSED(&h, &r, 1, WR_E_UNSUPPORTED);
	h.version = 0;
	REFUSED(&h, &r, 1, WR_E_UNSUPPORTED);
	h.version = 8;
	{
		uint8_t buf[300];
		wri_wr w;

		wri_wr_init(&w, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, &r, 1)); /* 8 is accepted */
	}
	h.version = 9;

	/* operation count */
	REFUSED(&h, &r, 0, WR_E_RANGE);
	for (i = 0; i < 9; i++)
		ops9[i] = r;
	REFUSED(&h, ops9, 9, WR_E_RANGE);
	{
		uint8_t buf[600];
		wri_wr w;

		wri_wr_init(&w, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, ops9, 8));
		WRT_CHECK(wri_wr_len(&w) == wri_mosdop_front_max(1, 0, 8, 0));
	}

	/* names */
	h.oid_len = 0;
	REFUSED(&h, &r, 1, WR_E_RANGE);
	h.oid = longname;
	h.oid_len = 2049;
	REFUSED(&h, &r, 1, WR_E_RANGE);
	h.oid_len = 0xFFFFFFFFu;
	REFUSED(&h, &r, 1, WR_E_RANGE);
	h.oid_len = 2048;
	{
		uint8_t buf[2400];
		wri_wr w;

		wri_wr_init(&w, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, &r, 1)); /* the limit itself is fine */
		WRT_CHECK(wri_wr_len(&w) == wri_mosdop_front_max(2048, 0, 1, 0));
	}
	h.oid = NULL;
	h.oid_len = 1;
	REFUSED(&h, &r, 1, WR_E_INVAL);
	h.oid = oid;
	h.oid_len = 1;
	h.nspace = longname;
	h.nspace_len = 257;
	REFUSED(&h, &r, 1, WR_E_RANGE);
	h.nspace_len = 256;
	{
		uint8_t buf[600];
		wri_wr w;

		wri_wr_init(&w, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, &r, 1));
		WRT_CHECK(wri_wr_len(&w) == wri_mosdop_front_max(1, 256, 1, 0));
	}
	h.nspace = NULL;
	REFUSED(&h, &r, 1, WR_E_INVAL);
	h.nspace_len = 0;

	/* a negative pool, a negative retry attempt */
	h.pool = -1;
	REFUSED(&h, &r, 1, WR_E_RANGE);
	h.pool = 7;
	h.retry_attempt = -1;
	REFUSED(&h, &r, 1, WR_E_INVAL);
	h.retry_attempt = 0;

	/* write-capable messages: snapid must be NOSNAP */
	h.flags = WRI_OSDF_BASE_WRITE;
	h.snapid = 5;
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	h.snapid = WRI_SNAP_NOSNAP - 1u; /* NOSNAP - 1 = the highest snapshot id */
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	/* ... also when only an operation code says "mutating" (the WRITE flag is missing) ... */
	h.flags = WRI_OSDF_BASE_READ;
	h.snapid = 5;
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	{
		wri_osd_opd z = w1;
		wri_osd_opd cases[5];
		static const uint16_t wr[5] = {WRI_OSD_OP_ZERO, WRI_OSD_OP_TRUNCATE, WRI_OSD_OP_DELETE, WRI_OSD_OP_CREATE, WRI_OSD_OP_SETALLOCHINT};

		for (i = 0; i < 5; i++) {
			memset(&cases[i], 0, sizeof(cases[i]));
			cases[i].code = wr[i];
			REFUSED(&h, &cases[i], 1, WR_E_INVAL);
		}
		z.code = WRI_OSD_OP_WRITEFULL;
		REFUSED(&h, &z, 1, WR_E_INVAL);
	}
	/* ... and the WRITE flag alone (a CALL of a mutating method) is enough */
	{
		wri_osd_opd c;

		memset(&c, 0, sizeof(c));
		c.code = WRI_OSD_OP_CALL;
		c.cls_class_len = 4;
		c.cls_method_len = 4;
		c.in_len = 8;
		h.flags = WRI_OSDF_BASE_WRITE;
		REFUSED(&h, &c, 1, WR_E_INVAL);
		h.flags = WRI_OSDF_BASE_READ; /* a read CALL of a snapshot is fine */
		{
			uint8_t buf[300];
			wri_wr w;

			wri_wr_init(&w, buf, sizeof(buf));
			WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, &c, 1));
		}
	}
	h.snapid = WRI_SNAP_NOSNAP;

	/* snapshot contexts of a write */
	h.flags = WRI_OSDF_BASE_WRITE;
	h.snapc = &sc;
	sc.cap = 3;
	sc.snaps = good;
	sc.n = 3;
	sc.seq = 9;
	{
		uint8_t buf[300];
		wri_wr w;

		wri_wr_init(&w, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, &w1, 1));
	}
	sc.seq = WRI_SNAP_MAX + 1u;
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	sc.seq = 9;
	sc.snaps = bad_order;
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	sc.snaps = bad_asc;
	sc.n = 2;
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	sc.snaps = bad_top;
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	sc.snaps = zero_then;
	sc.n = 3;
	sc.seq = 5;
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	sc.snaps = NULL;
	sc.n = 1;
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	h.snapc = NULL; /* NULL is the empty context */
	{
		uint8_t buf[300];
		wri_wr w;

		wri_wr_init(&w, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, &w1, 1));
	}
	h.flags = WRI_OSDF_BASE_READ;

	/* CALL lengths */
	{
		wri_osd_opd c;
		uint8_t buf[300];
		wri_wr w;

		memset(&c, 0, sizeof(c));
		c.code = WRI_OSD_OP_CALL;
		c.cls_class_len = 3;
		c.cls_method_len = 8;
		c.in_len = 10;
		REFUSED(&h, &c, 1, WR_E_INVAL);
		c.in_len = 11; /* names only, no argument */
		wri_wr_init(&w, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, &c, 1));
		c.cls_class_len = 255;
		c.cls_method_len = 255;
		c.in_len = 509;
		REFUSED(&h, &c, 1, WR_E_INVAL);
		c.in_len = 510;
		wri_wr_init(&w, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, &c, 1));
		/* the second operation is checked too */
		{
			wri_osd_opd two[2];

			two[0] = r;
			two[1] = c;
			two[1].in_len = 100;
			REFUSED(&h, two, 2, WR_E_INVAL);
		}
	}

	/* a WRITE whose length differs from its data */
	w1.len = 11;
	h.flags = WRI_OSDF_BASE_WRITE;
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	w1.len = 10;
	w1.code = WRI_OSD_OP_WRITEFULL;
	w1.len = 9;
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	w1.len = 0x100000000ull + 10u; /* a 64 bit length that truncates to in_len is still a mismatch */
	REFUSED(&h, &w1, 1, WR_E_INVAL);
	w1 = write_op(0, 10);
	h.flags = WRI_OSDF_BASE_READ;

	/* operations the client does not send */
	{
		static const uint16_t bad[] = {0x1208 /* ASSERT_VER */, 0x1220 /* CMPEXT */, 0x2226 /* WRITESAME */, 0x2227, 0x1206, 0x1207, 0x1209,
					       0x220F, 0x0000, 0xFFFF, 0x3201, 0x1211 /* OMAPGETKEYS */, 0x1213 /* OMAPGETHEADER */};
		wri_osd_opd o;

		memset(&o, 0, sizeof(o));
		for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			o.code = bad[i];
			h.flags = WRI_OSDF_BASE_READ;
			REFUSED(&h, &o, 1, WR_E_UNSUPPORTED);
		}
		o.code = WRI_OSD_OP_READ;
		{
			wri_osd_opd two[2];

			two[0] = r;
			two[1] = o;
			two[1].code = 0x1208;
			REFUSED(&h, two, 2, WR_E_UNSUPPORTED);
		}
	}

	/* a data segment beyond what the frame can carry */
	{
		wri_osd_opd big[2];

		big[0] = write_op(0, 0x80000000u);
		big[1] = write_op(0, 0x80000000u);
		h.flags = WRI_OSDF_BASE_WRITE;
		REFUSED(&h, big, 2, WR_E_RANGE);
		big[1] = write_op(0, 0x7FFFFFFFu); /* 0xFFFFFFFF in total: allowed */
		{
			uint8_t buf[600];
			wri_wr w;

			wri_wr_init(&w, buf, sizeof(buf));
			WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, big, 2));
		}
	}

	/* NULL arguments */
	{
		uint8_t buf[300];
		wri_wr w;

		wri_wr_init(&w, buf, sizeof(buf));
		h.flags = WRI_OSDF_BASE_READ;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mosdop_encode(NULL, &h, &r, 1));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mosdop_encode(&w, NULL, &r, 1));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mosdop_encode(&w, &h, NULL, 1));
		WRT_CHECK(w.pos == 0);
	}
}

/* ---- RETRY is derived ------------------------------------------------------------------------------------------------------- */

static void test_retry(void)
{
	static const uint8_t oid[] = "o";
	wri_mosdop_hdr h = base_hdr(oid, 1);
	wri_osd_opd r = read_op(0, 10);
	wri_osd_opd w1 = write_op(0, 10);
	uint8_t buf[300];
	size_t len;
	static const int32_t attempts[] = {0, 1, 2, 7, 100000, 0x7FFFFFFF};
	unsigned i, k;

	for (k = 0; k < 2; k++) {
		for (i = 0; i < sizeof(attempts) / sizeof(attempts[0]); i++) {
			uint32_t base = k ? WRI_OSDF_BASE_WRITE : WRI_OSDF_BASE_READ;
			uint32_t flags_out;

			h.flags = base;
			h.retry_attempt = attempts[i];
			WRT_CHECK_STATUS(WR_OK, enc_guard(&h, k ? &w1 : &r, 1, buf, sizeof(buf), &len));
			flags_out = rig_le32(buf + 32);
			WRT_CHECK_U64(flags_out, attempts[i] != 0 ? (base | WRI_OSDF_RETRY) : base);
			WRT_CHECK_U64(rig_le32(buf + len - 12), (uint32_t)attempts[i]); /* retry_attempt just before the features */
			/* a RETRY set by the caller is not trusted on a first transmission */
			h.flags = base | WRI_OSDF_RETRY;
			WRT_CHECK_STATUS(WR_OK, enc_guard(&h, k ? &w1 : &r, 1, buf, sizeof(buf), &len));
			flags_out = rig_le32(buf + 32);
			WRT_CHECK_U64(flags_out, attempts[i] != 0 ? (base | WRI_OSDF_RETRY) : base);
		}
	}
	/* everything else the caller put in the flags travels unchanged */
	h.retry_attempt = 3;
	h.flags = WRI_OSDF_BASE_WRITE | WRI_OSDF_FULL_TRY | WRI_OSDF_ORDERSNAP;
	WRT_CHECK_STATUS(WR_OK, enc_guard(&h, &w1, 1, buf, sizeof(buf), &len));
	WRT_CHECK_U64(rig_le32(buf + 32), WRI_OSDF_BASE_WRITE | WRI_OSDF_FULL_TRY | WRI_OSDF_ORDERSNAP | WRI_OSDF_RETRY);
	/* reqid.inc and client_inc are both 0, the name and tid empty, whatever the attempt */
	{
		size_t j;

		for (j = 36; j < 36 + 27 + 24; j++) /* reqid (27) and the blkin trace (24): the zero bytes after the two struct headers */
			if (j != 36 && j != 37 && j != 38)
				WRT_CHECK(buf[j] == 0);
		WRT_CHECK(buf[36] == 2 && buf[37] == 2 && rig_le32(buf + 38) == 21);
		WRT_CHECK_U64(rig_le32(buf + 94), 0); /* client_inc */
	}
}

/* ---- sizes --------------------------------------------------------------------------------------------------------------------- */

static void test_front_max_random(void)
{
	static uint8_t name[2048];
	static uint8_t ns[256];
	static uint64_t snaps[300];
	unsigned it;

	memset(name, 'n', sizeof(name));
	memset(ns, 's', sizeof(ns));
	{
		unsigned i;

		for (i = 0; i < 300; i++)
			snaps[i] = 1000u - i; /* strictly descending */
	}
	for (it = 0; it < 400; it++) {
		wri_mosdop_hdr h = base_hdr(name, 1 + rnd_to(2048));
		wri_osd_opd ops[WRI_OSD_OPS_MAX];
		wri_snapc sc;
		unsigned n_ops = 1 + rnd_to(8), i;
		int writes = (int)rnd_to(2);
		size_t len, fm;
		uint8_t *buf;
		wri_wr w;

		h.version = rnd_to(2) ? WRI_MOSDOP_VERSION : WRI_MOSDOP_VERSION_V8;
		h.nspace = ns;
		h.nspace_len = rnd_to(257);
		h.pool = (int64_t)(rnd() >> 2);
		h.pg_seed = (uint32_t)rnd();
		h.hash = (uint32_t)rnd();
		h.map_epoch = (uint32_t)rnd();
		h.retry_attempt = (int32_t)rnd_to(5);
		h.features = rnd();
		h.mtime_sec = (uint32_t)rnd();
		h.mtime_nsec = rnd_to(1000000000u);
		h.flags = writes ? WRI_OSDF_BASE_WRITE : WRI_OSDF_BASE_READ;
		sc.seq = 1000;
		sc.n = rnd_to(301);
		sc.cap = 300;
		sc.snaps = snaps;
		h.snapc = &sc;
		for (i = 0; i < n_ops; i++) {
			uint32_t k = rnd_to(4);

			memset(&ops[i], 0, sizeof(ops[i]));
			if (k == 0) {
				ops[i].code = WRI_OSD_OP_CALL;
				ops[i].cls_class_len = (uint8_t)rnd_to(256);
				ops[i].cls_method_len = (uint8_t)rnd_to(256);
				ops[i].in_len = (uint32_t)ops[i].cls_class_len + ops[i].cls_method_len + rnd_to(100);
			} else if (k == 1) {
				ops[i] = write_op(rnd(), rnd_to(1u << 20));
			} else if (k == 2) {
				ops[i] = read_op(rnd(), rnd());
			} else {
				ops[i].code = WRI_OSD_OP_ZERO;
				ops[i].off = rnd();
				ops[i].len = rnd();
			}
			if (ops[i].code == WRI_OSD_OP_ZERO || ops[i].code == WRI_OSD_OP_WRITE)
				h.flags |= WRI_OSDF_WRITE; /* keep READ/WRITE flags and op modes consistent */
		}
		fm = wri_mosdop_front_max(h.oid_len, h.nspace_len, n_ops, sc.n);
		buf = (uint8_t *)malloc(fm);
		wri_wr_init(&w, buf, fm);
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, ops, n_ops));
		len = wri_wr_len(&w);
		WRT_CHECK(len <= fm);
		/* exact for v9; v8 is 7 less; a read message carries no snapshot ids, so it is shorter by their bytes */
		{
			int mutates = (h.flags & WRI_OSDF_WRITE) != 0;
			size_t want = fm - (h.version == WRI_MOSDOP_VERSION_V8 ? 7u : 0u) - (mutates ? 0u : 8u * sc.n);

			WRT_CHECK(len == want);
		}
		free(buf);
	}
	/* the bound itself: monotone and saturating, no wrap for absurd arguments */
	WRT_CHECK(wri_mosdop_front_max(1, 0, 1, 0) == 217u);
	WRT_CHECK(wri_mosdop_front_max(2, 0, 1, 0) == 218u);
	WRT_CHECK(wri_mosdop_front_max(1, 1, 1, 0) == 218u);
	WRT_CHECK(wri_mosdop_front_max(1, 0, 2, 0) == 255u);
	WRT_CHECK(wri_mosdop_front_max(1, 0, 1, 1) == 225u);
	WRT_CHECK(wri_mosdop_front_max(0xFFFFFFFFu, 0xFFFFFFFFu, 255, 0xFFFFFFFFu) >= wri_mosdop_front_max(2048, 256, 8, 256));
}

static void test_small_buffer(void)
{
	static const uint8_t oid[] = "rbd_data.abcdef.0000000000000000";
	static uint64_t snaps[2] = {9, 4};
	wri_snapc sc;
	wri_mosdop_hdr h = base_hdr(oid, 32);
	wri_osd_opd ops[2];
	size_t full, cap, len;
	uint8_t *ref;

	sc.seq = 9;
	sc.n = 2;
	sc.cap = 2;
	sc.snaps = snaps;
	h.flags = WRI_OSDF_BASE_WRITE;
	h.snapc = &sc;
	h.mtime_sec = 5;
	ops[0] = write_op(0, 100);
	ops[1] = write_op(100, 100);
	full = wri_mosdop_front_max(32, 0, 2, 2);
	ref = (uint8_t *)malloc(full);
	WRT_CHECK_STATUS(WR_OK, enc_guard(&h, ops, 2, ref, full, &len));
	WRT_CHECK(len == full);
	/* every shorter capacity fails with TOOBIG and writes nothing outside, the exact one succeeds */
	for (cap = 0; cap < full; cap++) {
		wr_status st = enc_guard(&h, ops, 2, NULL, cap, &len);

		WRT_CHECK_STATUS(WR_E_TOOBIG, st);
		WRT_CHECK(len <= cap);
	}
	/* a writer that is already failed stays failed and writes nothing */
	{
		uint8_t buf[600];
		wri_wr w;

		wri_wr_init(&w, buf, sizeof(buf));
		wri_wr_fail(&w, WR_E_STATE);
		WRT_CHECK_STATUS(WR_E_STATE, wri_mosdop_encode(&w, &h, ops, 2));
		WRT_CHECK(w.pos == 0);
	}
	/* a writer with no memory */
	{
		wri_wr w;

		wri_wr_init(&w, NULL, 0);
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_mosdop_encode(&w, &h, ops, 2));
	}
	free(ref);
}

/* ---- snapshot context rule and errno table ------------------------------------------------------------------------------------- */

static void test_snapc_valid(void)
{
	static uint64_t d3[3] = {9, 6, 2};
	static uint64_t d_zero_last[3] = {9, 6, 0};
	static uint64_t d_equal[3] = {9, 9, 2};
	static uint64_t d_up[3] = {2, 6, 9};
	static uint64_t d_top[1] = {10};
	static uint64_t d_zero_more[2] = {0, 0};
	static uint64_t d_max[2] = {0xfffffffffffffffdull, 0xfffffffffffffffcull};
	static uint64_t d_big[1] = {0xfffffffffffffffeull};
	wri_snapc s;

	WRT_CHECK(wri_snapc_valid(NULL) == 1);
	memset(&s, 0, sizeof(s));
	WRT_CHECK(wri_snapc_valid(&s) == 1);          /* seq 0, no ids */
	s.seq = 5;
	WRT_CHECK(wri_snapc_valid(&s) == 1);          /* a seq without ids (all snapshots gone) */
	s.seq = WRI_SNAP_MAX;
	WRT_CHECK(wri_snapc_valid(&s) == 1);
	s.seq = WRI_SNAP_MAX + 1u;
	WRT_CHECK(wri_snapc_valid(&s) == 0);
	s.seq = 0xFFFFFFFFFFFFFFFFull;
	WRT_CHECK(wri_snapc_valid(&s) == 0);
	s.seq = 9;
	s.snaps = d3;
	s.n = 3;
	s.cap = 3;
	WRT_CHECK(wri_snapc_valid(&s) == 1);
	s.seq = 10;
	WRT_CHECK(wri_snapc_valid(&s) == 1);
	s.seq = 8;
	WRT_CHECK(wri_snapc_valid(&s) == 0);          /* snaps[0] above seq */
	s.seq = 9;
	s.snaps = d_zero_last;
	WRT_CHECK(wri_snapc_valid(&s) == 1);          /* 0 as the last id */
	s.snaps = d_equal;
	WRT_CHECK(wri_snapc_valid(&s) == 0);
	s.snaps = d_up;
	WRT_CHECK(wri_snapc_valid(&s) == 0);
	s.snaps = d_top;
	s.n = 1;
	s.seq = 10;
	WRT_CHECK(wri_snapc_valid(&s) == 1);
	s.seq = 9;
	WRT_CHECK(wri_snapc_valid(&s) == 0);
	s.snaps = d_zero_more;
	s.n = 2;
	s.seq = 5;
	WRT_CHECK(wri_snapc_valid(&s) == 0);          /* an id 0 followed by another */
	s.snaps = d_max;
	s.seq = WRI_SNAP_MAX;
	WRT_CHECK(wri_snapc_valid(&s) == 1);
	s.snaps = d_big;
	s.n = 1;
	WRT_CHECK(wri_snapc_valid(&s) == 0);          /* the id of the head is not a snapshot */
	s.snaps = NULL;
	WRT_CHECK(wri_snapc_valid(&s) == 0);
}

static void test_errno_table(void)
{
	WRT_CHECK_STATUS(WR_OK, wri_osd_errno_status(0));
	WRT_CHECK_STATUS(WR_OK, wri_osd_errno_status(1));
	WRT_CHECK_STATUS(WR_OK, wri_osd_errno_status(4096));
	WRT_CHECK_STATUS(WR_OK, wri_osd_errno_status(0x7FFFFFFF));
	WRT_CHECK_STATUS(WR_E_OSD_NOENT, wri_osd_errno_status(-2));
	WRT_CHECK_STATUS(WR_E_OSD_NOENT, wri_osd_errno_status(-95));
	WRT_CHECK_STATUS(WR_E_OSD_PERM, wri_osd_errno_status(-1));
	WRT_CHECK_STATUS(WR_E_OSD_IO, wri_osd_errno_status(-5));
	WRT_CHECK_STATUS(WR_E_OSD_NOSPC, wri_osd_errno_status(-28));
	WRT_CHECK_STATUS(WR_E_OSD_NOSPC, wri_osd_errno_status(-122));
	WRT_CHECK_STATUS(WR_E_OSD_BLOCKLISTED, wri_osd_errno_status(-108));
	/* everything else negative is a plain errno: EAGAIN, EEXIST, EINVAL, EFBIG, ENAMETOOLONG, EMSGSIZE, EOLDSNAPC, ENODATA, ... */
	{
		static const int32_t other[] = {-11, -17, -22, -27, -36, -90, -85, -61, -23, -3, -4, -13, -100, -121, -123, -1000, (int32_t)0x80000000u,
						-0x7FFFFFFF};
		unsigned i;

		for (i = 0; i < sizeof(other) / sizeof(other[0]); i++)
			WRT_CHECK_STATUS(WR_E_OSD_ERRNO, wri_osd_errno_status(other[i]));
	}
	/* the constants of the header are the Linux numbers */
	WRT_CHECK(WRI_ERRNO_ENOENT == 2 && WRI_ERRNO_EBLOCKLISTED == 108 && WRI_ERRNO_EDQUOT == 122 && WRI_ERRNO_EOLDSNAPC == 85);
}

int main(void)
{
	test_vectors();
	test_note_example();
	test_op_put();
	test_write_snapc();
	test_namespace();
	test_refusals();
	test_retry();
	test_front_max_random();
	test_small_buffer();
	test_snapc_valid();
	test_errno_table();
	return wrt_finish();
}
