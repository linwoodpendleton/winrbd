/* SPDX-License-Identifier: MIT */
/*
 * test_osd_msg_cap.c - module osd-msg, the request side, second oracle: requests the stock Rados client of a v20.2.5 lab cluster sent that
 * the first capture round of harness/vectors/osdop/ does not contain: a namespace, GETXATTR, TRUNCATE, ZERO (with a zero mtime on a
 * write, which the OSD accepted), a write with a one-snapshot context, TRUNCATE and DELETE under a context, a read of a snapshot and a
 * DELETE after the last snapshot was removed (seq 17, no snapshot ids). Each front is rebuilt by wri_mosdop_encode from the fields
 * below (as v9 byte for byte, and as v8 without the 7 otel bytes) and must equal the captured bytes.
 *
 * The capture: a throw-away cephx user (osd caps on the lab pool only, deleted afterwards), the stock python binding with the client in
 * crc mode, tcpdump on the loopback of the lab VM, the frames cut out of the streams with the checker of harness/tools. Nothing but the
 * bodies of the requests is kept: object names are lab names (wrtest-osdmsg-*, rbd_data.<lab image id>.<n>), the data segments are not
 * kept. A body holds no key or ticket (osd-ops.md 2.3).
 */
#include "osd_msg_rig.h"

typedef struct cap_op {
	uint16_t code;
	uint16_t flags;
	uint32_t in_len;
	uint64_t off, len;
} cap_op;

typedef struct cap_case {
	const char *name;
	const char *oid;
	const char *nspace;
	int64_t pool;
	uint32_t seed, hash, epoch, flags, mtime_sec, mtime_nsec;
	uint64_t snapid, snap_seq, features;
	unsigned n_snaps;
	uint64_t snaps[2];
	unsigned n_ops;
	cap_op ops[2];
	const char *front_hex;
} cap_case;

static const cap_case cases[] = {
	{"write_full in a namespace",
	 "wrtest-osdmsg-o1", "wrtest-osdmsg", 2, 9u, 3974993673u, 3114u, 0x08400024u, 1794929933u, 133009914u,
	 0xfffffffffffffffeull, 0ull, 0x3f07fffffffdffffull, 0, {0}, 1, {{0x2202, 0, 16, 0u, 16u}},
	 "01011200000001020000000000000009000000ffffffffff0997edec2a0c00002400400802021500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010100000000000000000d75fc6afa91ed070603290000000200000000000000ffffffff000000000d0000007772746573742d6f73646d7367ffffffffffffffff100000007772746573742d6f73646d73672d6f3101000222000000000000000000000000100000000000000000000000000000000000000010000000feffffffffffffff00000000000000000000000000000000fffffdffffff073f"},
	{"getxattr",
	 "wrtest-osdmsg-o1", "wrtest-osdmsg", 2, 9u, 3974993673u, 3114u, 0x08400014u, 0u, 0u,
	 0xfffffffffffffffeull, 0ull, 0x3f07fffffffdffffull, 0, {0}, 1, {{0x1301, 0, 6, 0u, 0u}},
	 "01011200000001020000000000000009000000ffffffffff0997edec2a0c000014004008020215000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010101000000000000000000000000000000000603290000000200000000000000ffffffff000000000d0000007772746573742d6f73646d7367ffffffffffffffff100000007772746573742d6f73646d73672d6f3101000113000000000600000000000000000000000000000000000000000000000000000006000000feffffffffffffff00000000000000000000000000000000fffffdffffff073f"},
	{"truncate",
	 "wrtest-osdmsg-o1", "wrtest-osdmsg", 2, 9u, 3974993673u, 3114u, 0x08400024u, 1794929934u, 349432549u,
	 0xfffffffffffffffeull, 0ull, 0x3f07fffffffdffffull, 0, {0}, 1, {{0x2203, 0, 0, 6u, 0u}},
	 "01011200000001020000000000000009000000ffffffffff0997edec2a0c00002400400802021500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010100000000000000000e75fc6ae5ead3140603290000000200000000000000ffffffff000000000d0000007772746573742d6f73646d7367ffffffffffffffff100000007772746573742d6f73646d73672d6f3101000322000000000600000000000000000000000000000000000000000000000000000000000000feffffffffffffff00000000000000000000000000000000fffffdffffff073f"},
	{"zero, mtime 0",
	 "wrtest-osdmsg-o1", "wrtest-osdmsg", 2, 9u, 3974993673u, 3114u, 0x08400024u, 0u, 0u,
	 0xfffffffffffffffeull, 0ull, 0x3f07fffffffdffffull, 0, {0}, 1, {{0x2204, 0, 0, 3u, 1u}},
	 "01011200000001020000000000000009000000ffffffffff0997edec2a0c000024004008020215000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010101000000000000000000000000000000000603290000000200000000000000ffffffff000000000d0000007772746573742d6f73646d7367ffffffffffffffff100000007772746573742d6f73646d73672d6f3101000422000000000300000000000000010000000000000000000000000000000000000000000000feffffffffffffff00000000000000000000000000000000fffffdffffff073f"},
	{"write with snapshot context and alloc hint",
	 "rbd_data.16d4d152ca5cd.0000000000000000", "", 2, 18u, 2889139346u, 3115u, 0x08400024u, 1794929938u, 528746448u,
	 0xfffffffffffffffeull, 17ull, 0x3f07fffffffdffffull, 1, {17ull}, 2, {{0x2223, 2, 0, 4194304u, 4194304u}, {0x2201, 0, 4096, 8192u, 4096u}},
	 "01011200000001020000000000000012000000ffffffffff92c434ac2b0c00002400400802021500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010100000000000000001275fc6ad007841f06031c0000000200000000000000ffffffff0000000000000000ffffffffffffffff270000007262645f646174612e313664346431353263613563642e30303030303030303030303030303030020023220200000000004000000000000000400000000000000000000000000000000000000000000122000000000020000000000000001000000000000000000000000000000000000000100000feffffffffffffff110000000000000001000000110000000000000000000000fffffdffffff073f"},
	{"truncate with snapshot context",
	 "rbd_data.16d4d152ca5cd.0000000000000001", "", 2, 12u, 2754142348u, 3115u, 0x08400024u, 1794929939u, 755015339u,
	 0xfffffffffffffffeull, 17ull, 0x3f07fffffffdffffull, 1, {17ull}, 1, {{0x2203, 0, 0, 65536u, 0u}},
	 "0101120000000102000000000000000c000000ffffffffff8ce028a42b0c00002400400802021500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010100000000000000001375fc6aab9e002d06031c0000000200000000000000ffffffff0000000000000000ffffffffffffffff270000007262645f646174612e313664346431353263613563642e3030303030303030303030303030303101000322000000000000010000000000000000000000000000000000000000000000000000000000feffffffffffffff110000000000000001000000110000000000000000000000fffffdffffff073f"},
	{"delete with snapshot context",
	 "rbd_data.16d4d152ca5cd.0000000000000002", "", 2, 26u, 3128949882u, 3115u, 0x08400024u, 1794929940u, 165125586u,
	 0xfffffffffffffffeull, 17ull, 0x3f07fffffffdffffull, 1, {17ull}, 1, {{0x2205, 0, 0, 0u, 0u}},
	 "0101120000000102000000000000001a000000ffffffffff7afc7fba2b0c00002400400802021500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010100000000000000001475fc6ad29dd70906031c0000000200000000000000ffffffff0000000000000000ffffffffffffffff270000007262645f646174612e313664346431353263613563642e3030303030303030303030303030303201000522000000000000000000000000000000000000000000000000000000000000000000000000feffffffffffffff110000000000000001000000110000000000000000000000fffffdffffff073f"},
	{"read of a snapshot",
	 "rbd_data.16d4d152ca5cd.0000000000000000", "", 2, 18u, 2889139346u, 3115u, 0x08400014u, 0u, 0u,
	 0x11ull, 0ull, 0x3f07fffffffdffffull, 0, {0}, 1, {{0x1201, 0, 0, 0u, 4096u}},
	 "01011200000001020000000000000012000000ffffffffff92c434ac2b0c0000140040080202150000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101010000000000000000000000000000000006031c0000000200000000000000ffffffff0000000000000000ffffffffffffffff270000007262645f646174612e313664346431353263613563642e3030303030303030303030303030303001000112000000000000000000000000001000000000000000000000000000000000000000000000110000000000000000000000000000000000000000000000fffffdffffff073f"},
	{"delete, seq 17 and no snapshots",
	 "rbd_data.16d4d152ca5cd.0000000000000000", "", 2, 18u, 2889139346u, 3116u, 0x08400024u, 1794929941u, 780722178u,
	 0xfffffffffffffffeull, 17ull, 0x3f07fffffffdffffull, 0, {0}, 1, {{0x2205, 0, 0, 0u, 0u}},
	 "01011200000001020000000000000012000000ffffffffff92c434ac2c0c00002400400802021500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010100000000000000001575fc6a02e0882e06031c0000000200000000000000ffffffff0000000000000000ffffffffffffffff270000007262645f646174612e313664346431353263613563642e3030303030303030303030303030303001000522000000000000000000000000000000000000000000000000000000000000000000000000feffffffffffffff11000000000000000000000000000000fffffdffffff073f"},
};

static size_t from_hex(const char *s, uint8_t *dst, size_t cap)
{
	size_t n = strlen(s) / 2u, i;

	if (n > cap)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned v;

		if (sscanf(s + 2u * i, "%2x", &v) != 1)
			return 0;
		dst[i] = (uint8_t)v;
	}
	return n;
}

#define N_CASES (sizeof(cases) / sizeof(cases[0]))

/* The header and the operations of a case as the encoder takes them. */
static void build(const cap_case *c, wri_mosdop_hdr *h, wri_osd_opd *ops, wri_snapc *sc)
{
	unsigned i;

	memset(h, 0, sizeof(*h));
	h->version = WRI_MOSDOP_VERSION;
	h->pool = c->pool;
	h->pg_seed = c->seed;
	h->hash = c->hash;
	h->map_epoch = c->epoch;
	h->flags = c->flags;
	h->mtime_sec = c->mtime_sec;
	h->mtime_nsec = c->mtime_nsec;
	h->oid = (const uint8_t *)c->oid;
	h->oid_len = (uint32_t)strlen(c->oid);
	h->nspace = (const uint8_t *)c->nspace;
	h->nspace_len = (uint32_t)strlen(c->nspace);
	h->snapid = c->snapid;
	h->features = c->features;
	sc->seq = c->snap_seq;
	sc->n = c->n_snaps;
	sc->cap = c->n_snaps;
	sc->snaps = (uint64_t *)(uintptr_t)c->snaps;
	h->snapc = sc;
	for (i = 0; i < c->n_ops; i++) {
		memset(&ops[i], 0, sizeof(ops[i]));
		ops[i].code = c->ops[i].code;
		ops[i].flags = c->ops[i].flags;
		ops[i].in_len = c->ops[i].in_len;
		ops[i].off = c->ops[i].off;
		ops[i].len = c->ops[i].len;
	}
}

static void test_captured(void)
{
	unsigned k;

	for (k = 0; k < N_CASES; k++) {
		const cap_case *c = &cases[k];
		uint8_t want[512], got[512];
		size_t n = from_hex(c->front_hex, want, sizeof(want)), len;
		wri_mosdop_hdr h;
		wri_osd_opd ops[2];
		wri_snapc sc;
		wri_wr w;

		if (n == 0) {
			fprintf(stderr, "case %s: bad hex\n", c->name);
			WRT_CHECK(0);
			continue;
		}
		build(c, &h, ops, &sc);
		wri_wr_init(&w, got, sizeof(got));
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, ops, c->n_ops));
		len = wri_wr_len(&w);
		if (len != n)
			fprintf(stderr, "case %s: encoded %zu bytes, captured %zu\n", c->name, len, n);
		WRT_CHECK(len == n);
		WRT_CHECK(len == wri_mosdop_front_max(h.oid_len, h.nspace_len, c->n_ops, c->n_snaps));
		if (len == n) {
			if (memcmp(got, want, n) != 0)
				fprintf(stderr, "case %s: bytes differ\n", c->name);
			WRT_CHECK_MEM(got, want, n);
		}
		/* v8 = v9 without the 7 otel bytes; and an exact-size writer works, one byte less does not */
		h.version = WRI_MOSDOP_VERSION_V8;
		wri_wr_init(&w, got, sizeof(got));
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w, &h, ops, c->n_ops));
		WRT_CHECK(wri_wr_len(&w) == n - RIG_OTEL_LEN);
		if (wri_wr_len(&w) == n - RIG_OTEL_LEN) {
			WRT_CHECK_MEM(got, want, RIG_OTEL_AT);
			WRT_CHECK_MEM(got + RIG_OTEL_AT, want + RIG_OTEL_AT + RIG_OTEL_LEN, n - RIG_OTEL_AT - RIG_OTEL_LEN);
		}
		h.version = WRI_MOSDOP_VERSION;
		wri_wr_init(&w, got, n - 1u);
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_mosdop_encode(&w, &h, ops, c->n_ops));
	}
}

/* The union of GETXATTR is the xattr variant (name_len = the input length) and that of the omap reads is (0, input length), whatever the
 * owner left in off and len: the OSD cuts the attribute name out of the input by name_len, so an extent-shaped record would ask for the
 * attribute "" (captured: name_len 6 for a six byte name). */
static void test_derived_union(void)
{
	wri_osd_opd o;
	uint8_t a[WRI_OSD_OPREC_LEN], b[WRI_OSD_OPREC_LEN];
	wri_wr w;
	unsigned k;
	static const uint16_t codes[3] = {WRI_OSD_OP_GETXATTR, WRI_OSD_OP_OMAPGETVALS, WRI_OSD_OP_OMAPGETVALSBYKEYS};

	for (k = 0; k < 3; k++) {
		memset(&o, 0, sizeof(o));
		o.code = codes[k];
		o.in_len = 6;
		wri_wr_init(&w, a, sizeof(a));
		wri_osd_op_put(&w, &o);
		WRT_CHECK(wri_wr_ok(&w) && wri_wr_len(&w) == WRI_OSD_OPREC_LEN);
		o.off = 0x1111111111111111ull;
		o.len = 0x2222222222222222ull;
		wri_wr_init(&w, b, sizeof(b));
		wri_osd_op_put(&w, &o);
		WRT_CHECK_MEM(a, b, WRI_OSD_OPREC_LEN);
		if (codes[k] == WRI_OSD_OP_GETXATTR) {
			WRT_CHECK_U64(rig_le32(a + 6), 6); /* name_len */
			WRT_CHECK_U64(rig_le32(a + 10), 0); /* value_len */
			WRT_CHECK_U64(rig_le64(a + 14), 0); /* cmp_op, cmp_mode and the rest */
		} else {
			WRT_CHECK_U64(rig_le64(a + 6), 0);
			WRT_CHECK_U64(rig_le64(a + 14), 6);
		}
		WRT_CHECK_U64(rig_le64(a + 22), 0);
		WRT_CHECK_U64(rig_le32(a + 30), 0);
		WRT_CHECK_U64(rig_le32(a + 34), 6);
	}
}


/* ---- replies of the same capture round (the second one: reads of an image with holes and a short object) ---------------------------- */

typedef struct cap_rep {
	const char *name, *oid, *front_hex, *map_hex, *pats; /* map_hex: the extent table of a SPARSE_READ output (n, pairs, data_len) */
	uint16_t ver, compat;
	uint32_t pg_seed, epoch, dlen;
	int64_t pool, flags;
	int32_t result, retry;
	uint64_t user_version, req_off, req_len;
	unsigned n_ops, n_ext;
	uint32_t out_len[2];
	uint16_t op_code[2];
	int32_t rval[2];
	uint64_t ext[2][2];
} cap_rep;

static const cap_rep reps[] = {
	{"sparse read, two extents",
	 "rbd_data.17ff0525e3405.0000000000000000",
	 "270000007262645f646174612e313766663035323565333430352e3030303030303030303030303030303001020000000000000004000000ffffffff1500400800000000000000004000000000000000000000002d0c00000100000005120000000000000000000000000020000000000000000000000000000000000000282000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000",
	 "02000000000000000000000000100000000000000002100000000000001000000000000000200000", "AB",
	 8, 2, 4u, 3117u, 8232u, 2, 138412053, 0, 0, 64ull, 0ull, 4194304ull, 1, 2,
	 {8232u}, {0x1205}, {0}, {{0ull, 4096ull}, {1049088ull, 4096ull}}},
	{"sparse read over a hole",
	 "rbd_data.17ff0525e3405.0000000000000000",
	 "270000007262645f646174612e313766663035323565333430352e3030303030303030303030303030303001020000000000000004000000ffffffff1500400800000000000000004000000000000000000000002d0c00000100000005120000000000002000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000",
	 "0000000000000000", "",
	 8, 2, 4u, 3117u, 8u, 2, 138412053, 0, 0, 64ull, 2097152ull, 65536ull, 1, 0,
	 {8u}, {0x1205}, {0}, {{0, 0}}},
	{"sparse read, extent inside the request",
	 "rbd_data.17ff0525e3405.0000000000000000",
	 "270000007262645f646174612e313766663035323565333430352e3030303030303030303030303030303001020000000000000004000000ffffffff1500400800000000000000004000000000000000000000002d0c00000100000005120000000000001000000000000010000000000000000000000000000000000000181000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000",
	 "010000000002100000000000001000000000000000100000", "B",
	 8, 2, 4u, 3117u, 4120u, 2, 138412053, 0, 0, 64ull, 1048576ull, 131072ull, 1, 1,
	 {4120u}, {0x1205}, {0}, {{1049088ull, 4096ull}}},
	{"sparse read, short object",
	 "rbd_data.17ff0525e3405.0000000000000001",
	 "270000007262645f646174612e313766663035323565333430352e3030303030303030303030303030303101020000000000000008000000ffffffff1500400800000000000000005100000000000000000000002d0c000001000000051200000000000000000000000064000000000000000000000000000000000000007c0000000000000000000000000000000000000000000000510000000000000000000000000000000000000000000000000000000000000000",
	 "010000000300000000000000640000000000000064000000", "C",
	 8, 2, 8u, 3117u, 124u, 2, 138412053, 0, 0, 81ull, 0ull, 4194304ull, 1, 1,
	 {124u}, {0x1205}, {0}, {{3ull, 100ull}}},
	{"read, short object",
	 "rbd_data.17ff0525e3405.0000000000000001",
	 "270000007262645f646174612e313766663035323565333430352e3030303030303030303030303030303101020000000000000008000000ffffffff1500400800000000000000005100000000000000000000002d0c00000100000001120000000000000000000000006700000000000000000000000000000000000000670000000000000000000000000000000000000000000000510000000000000000000000000000000000000000000000000000000000000000",
	 "", "",
	 8, 2, 8u, 3117u, 103u, 2, 138412053, 0, 0, 81ull, 0ull, 1000ull, 1, 0,
	 {103u}, {0x1201}, {0}, {{0, 0}}},
	{"read past the end of the object",
	 "rbd_data.17ff0525e3405.0000000000000001",
	 "270000007262645f646174612e313766663035323565333430352e3030303030303030303030303030303101020000000000000008000000ffffffff1500400800000000000000005100000000000000000000002d0c000001000000011200000000c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000510000000000000000000000000000000000000000000000000000000000000000",
	 "", "",
	 8, 2, 8u, 3117u, 0u, 2, 138412053, 0, 0, 81ull, 200ull, 1000ull, 1, 0,
	 {0u}, {0x1201}, {0}, {{0, 0}}},
	{"sparse read, missing object",
	 "rbd_data.17ff0525e3405.0000000000000002",
	 "270000007262645f646174612e313766663035323565333430352e3030303030303030303030303030303201020000000000000010000000ffffffff1400400800000000feffffff0000000000000000000000002d0c00000100000005120000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	 "", "",
	 8, 2, 16u, 3117u, 0u, 2, 138412052, -2, 0, 0ull, 0ull, 4194304ull, 1, 0,
	 {0u}, {0x1205}, {0}, {{0, 0}}},
	{"truncate",
	 "rbd_data.17ff0525e3405.0000000000000003",
	 "270000007262645f646174612e313766663035323565333430352e3030303030303030303030303030303301020000000000000008000000ffffffff25004008000000000000000053000000000000002d0c00002d0c0000010000000322000000000000010000000000000000000000000000000000000000000000000000000000000000000000000053000000000000002d0c0000530000000000000000000000000000000000000000000000000000000000000000",
	 "", "",
	 8, 2, 8u, 3117u, 0u, 2, 138412069, 0, 0, 83ull, 65536ull, 0ull, 1, 0,
	 {0u}, {0x2203}, {0}, {{0, 0}}},
	{"write with alloc hint",
	 "rbd_data.17ff0525e3405.0000000000000000",
	 "270000007262645f646174612e313766663035323565333430352e3030303030303030303030303030303001020000000000000004000000ffffffff2500400800000000000000003f000000000000002d0c00002d0c000002000000232202000000000040000000000000004000000000000000000000000000000000000000000001220000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000003f000000000000002d0c00003f0000000000000000000000000000000000000000000000000000000000000000",
	 "", "",
	 8, 2, 4u, 3117u, 0u, 2, 138412069, 0, 0, 63ull, 0ull, 4096ull, 2, 0,
	 {0u, 0u}, {0x2223, 0x2201}, {0, 0}, {{0, 0}}},
};

static uint8_t pat_byte(char k, unsigned i)
{
	switch (k) {
	case 'A':
		return (uint8_t)((i * 7u + 3u) % 251u);
	case 'B':
		return (uint8_t)((i * 11u + 5u) % 251u);
	default:
		return (uint8_t)((i * 13u + 1u) % 251u);
	}
}

/* The data of a SPARSE_READ reply: the captured extent table, then the bytes the lab image held (known test patterns, 4096 bytes of
 * A and B, 100 of C); the first part of the output is the capture, the rest is regenerated and its length is the captured one. */
static size_t sparse_output(const cap_rep *r, uint8_t *dst, size_t cap)
{
	size_t n = from_hex(r->map_hex, dst, cap), k, i;
	const char *p;

	for (p = r->pats; *p != '\0'; p++) {
		size_t cnt = *p == 'C' ? 100u : 4096u;

		if (n + cnt > cap)
			return 0;
		for (i = 0, k = n; i < cnt; i++)
			dst[k + i] = pat_byte(*p, (unsigned)i);
		n += cnt;
	}
	return n;
}

static void test_captured_replies(void)
{
	unsigned k;

	for (k = 0; k < sizeof(reps) / sizeof(reps[0]); k++) {
		const cap_rep *r = &reps[k];
		uint8_t front[512];
		size_t n = from_hex(r->front_hex, front, sizeof(front)), cut;
		wri_mosdopreply p;
		unsigned i;

		WRT_CHECK(n != 0);
		if (n == 0)
			continue;
		WRT_CHECK_STATUS(WR_OK, wri_mosdopreply_decode(front, n, r->ver, r->compat, &p));
		WRT_CHECK(p.oid_len == strlen(r->oid) && memcmp(p.oid, r->oid, p.oid_len) == 0);
		WRT_CHECK(p.pool == r->pool && p.pg_seed == r->pg_seed && p.flags == r->flags && p.result == r->result && p.map_epoch == r->epoch);
		WRT_CHECK(p.retry_attempt == r->retry && p.user_version == r->user_version && p.do_redirect == 0);
		WRT_CHECK(p.n_ops == r->n_ops);
		for (i = 0; i < r->n_ops && i < 2u; i++)
			WRT_CHECK(p.op_code[i] == r->op_code[i] && p.out_len[i] == r->out_len[i] && p.rval[i] == r->rval[i]);
		WRT_CHECK(p.out_total == r->dlen); /* what the data segment of the reply held */
		/* a front cut anywhere is a protocol error; the version pair of the header decides the rest */
		for (cut = 0; cut < n; cut++)
			WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_mosdopreply_decode(front, cut, r->ver, r->compat, &p));
		WRT_CHECK_STATUS(WR_E_OSD_VERSION, wri_mosdopreply_decode(front, n, 7, r->compat, &p));

		if (r->n_ops == 1 && r->op_code[0] == WRI_OSD_OP_SPARSE_READ && r->result == 0) {
			uint8_t out[8300];
			size_t on = sparse_output(r, out, sizeof(out));
			wri_osd_extent ext[WRI_OSD_SPARSE_EXT_MAX];
			uint32_t ne = 99, doff = 0, dlen = 0, e;

			WRT_CHECK(on == r->dlen);
			WRT_CHECK_STATUS(WR_OK, wri_osd_sparse_decode(out, (uint32_t)on, r->req_off, r->req_len, ext, WRI_OSD_SPARSE_EXT_MAX, &ne, &doff, &dlen));
			WRT_CHECK(ne == r->n_ext && doff == 8u + 16u * r->n_ext && doff + dlen == on);
			for (e = 0; e < ne && e < 2u; e++)
				WRT_CHECK(ext[e].off == r->ext[e][0] && ext[e].len == r->ext[e][1]);
			if (r->n_ext != 0) {
				/* a request that does not contain the first extent is a protocol error: the capture is judged against its own range */
				WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_osd_sparse_decode(out, (uint32_t)on, r->ext[0][0] + 1u, r->req_len, ext, WRI_OSD_SPARSE_EXT_MAX,
										       &ne, &doff, &dlen));
				WRT_CHECK(ne == 0 && doff == 0 && dlen == 0);
			}
		}
	}
}

int main(void)
{
	test_captured();
	test_derived_union();
	test_captured_replies();
	return wrt_finish();
}
