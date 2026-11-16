/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of the monitor message codecs (core/src/mon/wri_mon_msgs.c, wri_monmap.c,
 * wri_mosdmap_hdr.c; docs/spec/mon-client.md 2.3 to 2.6, 3.8 and cephx.md 2.11).
 *
 *  - MMonSubscribe: every harness/vectors/monclient/mmonsubscribe-*.json is re-encoded from its
 *    decoded fields and must equal the captured front byte for byte (hostname included); writer
 *    error paths (bad arguments, no room, caps);
 *  - MMonGetMap: the empty front, and the message type constants against the vectors' type fields;
 *  - MMonMap: the front wrapper and the MonMap of mmonmap-e3.json decode to the documented fields;
 *    hand-built maps (rank order, versions 6 to 11, v1-only and legacy monitors, IPv6, more than
 *    eight ranks, wire caps, refusals) and a cut at every offset;
 *  - MOSDMap: the captured full-map front and the synthetic incremental front (epochs, bounds,
 *    newest_map), hand-built fronts for header versions 2 to 5, refusals, caps, every cut;
 *  - MAuth / MAuthReply: the scrubbed renewal vectors (byte-exact encode, structural decode), every
 *    cut, bad lengths.
 *
 * Inputs handed to the decoders are exact-size heap buffers so ASan sees any over-read.
 */
#include "wrt.h"

#include "wri_mon.h"

/* ---- helpers ------------------------------------------------------------------------------ */

static uint8_t *dup_bytes(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n ? n : 1);

	if (!q) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	if (n)
		memcpy(q, p, n);
	return q;
}

/* A growing byte builder, independent of the cursors under test. */
typedef struct bld {
	uint8_t d[16384];
	size_t n;
} bld;

static void b_u8(bld *b, uint32_t v)
{
	b->d[b->n++] = (uint8_t)v;
}
static void b_u16(bld *b, uint32_t v)
{
	b_u8(b, v);
	b_u8(b, v >> 8);
}
static void b_u32(bld *b, uint32_t v)
{
	b_u16(b, v);
	b_u16(b, v >> 16);
}
static void b_u64(bld *b, uint64_t v)
{
	b_u32(b, (uint32_t)v);
	b_u32(b, (uint32_t)(v >> 32));
}
static void b_bytes(bld *b, const void *p, size_t n)
{
	if (n)
		memcpy(b->d + b->n, p, n);
	b->n += n;
}
static void b_zero(bld *b, size_t n)
{
	memset(b->d + b->n, 0, n);
	b->n += n;
}
static void b_str(bld *b, const char *s)
{
	b_u32(b, (uint32_t)strlen(s));
	b_bytes(b, s, strlen(s));
}
static size_t b_env(bld *b, uint32_t v, uint32_t compat)
{
	size_t mark = b->n;

	b_u8(b, v);
	b_u8(b, compat);
	b_u32(b, 0);
	return mark;
}
static void b_env_end(bld *b, size_t mark)
{
	uint32_t len = (uint32_t)(b->n - mark - 6);

	b->d[mark + 2] = (uint8_t)len;
	b->d[mark + 3] = (uint8_t)(len >> 8);
	b->d[mark + 4] = (uint8_t)(len >> 16);
	b->d[mark + 5] = (uint8_t)(len >> 24);
}

/* ---- vectors ------------------------------------------------------------------------------ */

/* Load a vector and one of its hex members; *buf is exact-size heap memory. Returns 0 on success. */
static int load_hex(wrt_json *j, const char *rel, const char *member, uint8_t **buf, size_t *n)
{
	uint8_t *tmp = NULL;
	size_t tn = 0;

	*buf = NULL;
	*n = 0;
	if (wrt_json_load_vec(j, rel) != 0)
		return -1;
	if (wrt_json_get_hex(j, wrt_json_root(j), member, &tmp, &tn) != 0)
		return -1;
	*buf = dup_bytes(tmp, tn);
	*n = tn;
	free(tmp);
	return 0;
}

static wrt_tok expect_of(const wrt_json *j)
{
	return wrt_json_get(j, wrt_json_root(j), "expect");
}

static int64_t jint(const wrt_json *j, wrt_tok obj, const char *key)
{
	int ok = 0;
	int64_t v = wrt_json_int(j, wrt_json_get(j, obj, key), &ok);

	WRT_CHECK(ok);
	return v;
}

/* ---- MMonSubscribe ------------------------------------------------------------------------- */

#define SUB_MAX_ITEMS 8

static void sub_vector(const char *rel)
{
	wrt_json j;
	uint8_t *front = NULL;
	size_t front_n = 0, i, n;
	wrt_tok ex, what;
	wri_sub_item items[SUB_MAX_ITEMS];
	char *names[SUB_MAX_ITEMS];
	char *host;
	uint8_t out[256];
	wri_wr w;

	if (load_hex(&j, rel, "front_hex", &front, &front_n) != 0) {
		fprintf(stderr, "cannot load %s\n", rel);
		WRT_CHECK(0 && "vector load");
		return;
	}
	ex = expect_of(&j);
	what = wrt_json_get(&j, ex, "what");
	n = wrt_json_count(&j, what);
	WRT_CHECK(n >= 1 && n <= SUB_MAX_ITEMS);
	if (n > SUB_MAX_ITEMS)
		n = SUB_MAX_ITEMS;
	for (i = 0; i < n; i++) {
		wrt_tok it = wrt_json_at(&j, what, i);
		int ok = 0;

		names[i] = wrt_json_strdup(&j, wrt_json_at(&j, it, 0));
		items[i].what = names[i];
		items[i].start = (uint64_t)wrt_json_int(&j, wrt_json_at(&j, it, 1), &ok);
		items[i].flags = (uint8_t)wrt_json_int(&j, wrt_json_at(&j, it, 2), &ok);
	}
	host = wrt_json_strdup(&j, wrt_json_get(&j, ex, "hostname"));
	WRT_CHECK(host != NULL);

	wri_wr_init(&w, out, sizeof(out));
	wri_mmonsubscribe_encode(&w, items, n, host);
	WRT_CHECK_STATUS(WR_OK, w.err);
	WRT_CHECK_U64(wri_wr_len(&w), front_n);
	WRT_CHECK_U64(wri_wr_len(&w), jint(&j, ex, "front_len"));
	if (wri_wr_len(&w) == front_n)
		WRT_CHECK_MEM(out, front, front_n);

	/* exactly-sized buffer works, one byte less is TOOBIG and writes nothing past the end */
	{
		uint8_t *small = (uint8_t *)malloc(front_n);

		if (small) {
			wri_wr_init(&w, small, front_n);
			wri_mmonsubscribe_encode(&w, items, n, host);
			WRT_CHECK_STATUS(WR_OK, w.err);
			wri_wr_init(&w, small, front_n - 1);
			wri_mmonsubscribe_encode(&w, items, n, host);
			WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
			free(small);
		}
	}
	for (i = 0; i < n; i++)
		free(names[i]);
	free(host);
	free(front);
	wrt_json_free(&j);
}

static void test_subscribe(void)
{
	static const char *const vecs[] = {
		"monclient/mmonsubscribe-config-monmap.json",
		"monclient/mmonsubscribe-derived-monmap-only.json",
		"monclient/mmonsubscribe-mgrmap.json",
		"monclient/mmonsubscribe-osdmap-start0-onetime.json",
		"monclient/mmonsubscribe-reconnect.json",
	};
	size_t i;
	uint8_t out[128];
	wri_wr w;
	wri_sub_item it[2];
	static const uint8_t want_none[] = {0, 0, 0, 0, 0, 0, 0, 0};

	for (i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++)
		sub_vector(vecs[i]);

	/* no items, NULL host name: count 0 and an empty string */
	wri_wr_init(&w, out, sizeof(out));
	wri_mmonsubscribe_encode(&w, NULL, 0, NULL);
	WRT_CHECK_STATUS(WR_OK, w.err);
	WRT_CHECK_U64(wri_wr_len(&w), 8);
	WRT_CHECK_MEM(out, want_none, 8);

	/* items go out in the order given, not sorted */
	it[0].what = "osdmap", it[0].start = 5, it[0].flags = 1;
	it[1].what = "monmap", it[1].start = 0x0102030405060708ull, it[1].flags = 0;
	wri_wr_init(&w, out, sizeof(out));
	wri_mmonsubscribe_encode(&w, it, 2, "h");
	WRT_CHECK_STATUS(WR_OK, w.err);
	{
		static const uint8_t want[] = {2,   0,   0,   0,   6,   0,   0,   0,   'o', 's', 'd', 'm', 'a',
					       'p', 5,   0,   0,   0,   0,   0,   0,   0,   1,   6,   0,   0,
					       0,   'm', 'o', 'n', 'm', 'a', 'p', 8,   7,   6,   5,   4,   3,
					       2,   1,   0,   1,   0,   0,   0,   'h'};

		WRT_CHECK_U64(wri_wr_len(&w), sizeof(want));
		if (wri_wr_len(&w) == sizeof(want))
			WRT_CHECK_MEM(out, want, sizeof(want));
	}

	/* argument errors are sticky writer errors */
	wri_wr_init(&w, out, sizeof(out));
	wri_mmonsubscribe_encode(&w, NULL, 1, "h");
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	it[0].what = NULL;
	wri_wr_init(&w, out, sizeof(out));
	wri_mmonsubscribe_encode(&w, it, 1, "h");
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	it[0].what = "monmap";
	{
		char longname[300];

		memset(longname, 'x', sizeof(longname) - 1);
		longname[sizeof(longname) - 1] = '\0';
		it[0].what = longname;
		wri_wr_init(&w, out, sizeof(out));
		wri_mmonsubscribe_encode(&w, it, 1, "h");
		WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
		it[0].what = "monmap";
		wri_wr_init(&w, out, sizeof(out));
		wri_mmonsubscribe_encode(&w, it, 1, longname);
		WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
		memset(longname, 'x', 255);
		longname[255] = '\0'; /* exactly at the cap is fine, with room for it */
		{
			uint8_t big[512];

			wri_wr_init(&w, big, sizeof(big));
			wri_mmonsubscribe_encode(&w, it, 1, longname);
			WRT_CHECK_STATUS(WR_OK, w.err);
			WRT_CHECK_U64(wri_wr_len(&w), 4 + 4 + 6 + 9 + 4 + 255);
		}
	}
	{
		wri_sub_item many[40];
		size_t k;

		for (k = 0; k < 40; k++)
			many[k] = it[0];
		wri_wr_init(&w, out, sizeof(out));
		wri_mmonsubscribe_encode(&w, many, 40, "h");
		WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	}
	/* a repeated name would collapse into one entry on the monitor: refused, nothing half-written is sent */
	{
		wri_sub_item dup[3];

		dup[0].what = "monmap", dup[0].start = 0, dup[0].flags = 0;
		dup[1].what = "osdmap", dup[1].start = 0, dup[1].flags = 0;
		dup[2].what = "monmap", dup[2].start = 9, dup[2].flags = 1;
		wri_wr_init(&w, out, sizeof(out));
		wri_mmonsubscribe_encode(&w, dup, 3, "h");
		WRT_CHECK_STATUS(WR_E_INVAL, w.err);
		WRT_CHECK_U64(wri_wr_len(&w), 0);
		/* names that only share a prefix are different names */
		dup[2].what = "monmap2";
		wri_wr_init(&w, out, sizeof(out));
		wri_mmonsubscribe_encode(&w, dup, 3, "h");
		WRT_CHECK_STATUS(WR_OK, w.err);
		dup[2].what = "mon";
		wri_wr_init(&w, out, sizeof(out));
		wri_mmonsubscribe_encode(&w, dup, 3, "h");
		WRT_CHECK_STATUS(WR_OK, w.err);
	}
	wri_mmonsubscribe_encode(NULL, it, 1, "h"); /* must not crash */
}

/* ---- MMonGetMap and the type constants -------------------------------------------------------- */

static void test_getmap_and_types(void)
{
	static const struct {
		const char *rel;
		uint32_t type;
	} v[] = {
		{"monclient/mmongetmap.json", WRI_MSG_MON_GET_MAP},
		{"monclient/mmonmap-e3.json", WRI_MSG_MON_MAP},
		{"monclient/mmonsubscribe-mgrmap.json", WRI_MSG_MON_SUBSCRIBE},
		{"monclient/mosdmap-v4-full-e42.json", WRI_MSG_OSD_MAP},
		{"monclient/mauth-renewal-scrubbed.json", WRI_MSG_AUTH},
		{"monclient/mauthreply-renewal-scrubbed.json", WRI_MSG_AUTH_REPLY},
	};
	size_t i;

	for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
		wrt_json j;

		if (wrt_json_load_vec(&j, v[i].rel) != 0) {
			WRT_CHECK(0 && "vector load");
			continue;
		}
		WRT_CHECK_U64(jint(&j, expect_of(&j), "type"), v[i].type);
		wrt_json_free(&j);
	}
	WRT_CHECK_U64(WRI_MSG_MON_SUBSCRIBE_ACK, 16);
	/* MMonGetMap has an empty body: nothing to encode, and the captured front is empty */
	{
		wrt_json j;
		uint8_t *front = NULL;
		size_t n = 99;

		WRT_CHECK(load_hex(&j, "monclient/mmongetmap.json", "front_hex", &front, &n) == 0);
		WRT_CHECK_U64(n, 0);
		free(front);
		wrt_json_free(&j);
	}
}

/* ---- MonMap ------------------------------------------------------------------------------- */

static void v4_addr(bld *b, uint32_t type, uint32_t nonce, const uint8_t ip[4], uint16_t port)
{
	b_u8(b, 1);
	b_u8(b, 1);
	b_u8(b, 1);
	b_u32(b, 28);
	b_u32(b, type);
	b_u32(b, nonce);
	b_u32(b, 16);
	b_u16(b, 2);
	b_u8(b, port >> 8);
	b_u8(b, port);
	b_bytes(b, ip, 4);
	b_zero(b, 8);
}

static void v6_addr(bld *b, uint32_t type, const uint8_t ip[16], uint16_t port)
{
	b_u8(b, 1);
	b_u8(b, 1);
	b_u8(b, 1);
	b_u32(b, 40);
	b_u32(b, type);
	b_u32(b, 0);
	b_u32(b, 28);
	b_u16(b, 10);
	b_u8(b, port >> 8);
	b_u8(b, port);
	b_zero(b, 4);
	b_bytes(b, ip, 16);
	b_zero(b, 4);
}

/* One monitor of a hand-built map. kind selects the address vector. */
enum { K_V2V1, K_V1V2, K_V1ONLY, K_V2V6, K_LEGACY0, K_NONE_FAMILY, K_V2_PORT_7000, K_V2_PORT_0, K_V2_PORT_0_THEN_OK };

typedef struct mon_spec {
	const char *name;
	int kind;
	uint8_t last_octet; /* IPv4 10.0.0.<last_octet> */
	uint32_t info_compat;
} mon_spec;

static void put_addrvec(bld *b, int kind, uint8_t last)
{
	uint8_t ip[4], ip6[16];

	ip[0] = 10, ip[1] = 0, ip[2] = 0, ip[3] = last;
	memset(ip6, 0, sizeof(ip6));
	ip6[0] = 0xfd, ip6[15] = last;
	switch (kind) {
	case K_V2V1:
		b_u8(b, 2), b_u32(b, 2);
		v4_addr(b, 2, 0, ip, 3300);
		v4_addr(b, 1, 0, ip, 6789);
		break;
	case K_V1V2:
		b_u8(b, 2), b_u32(b, 2);
		v4_addr(b, 1, 0, ip, 6789);
		v4_addr(b, 2, 7, ip, 3301);
		break;
	case K_V1ONLY:
		b_u8(b, 2), b_u32(b, 1);
		v4_addr(b, 1, 0, ip, 6789);
		break;
	case K_V2V6:
		b_u8(b, 2), b_u32(b, 2);
		v6_addr(b, 2, ip6, 3300);
		v4_addr(b, 1, 0, ip, 6789);
		break;
	case K_LEGACY0:
		b_u8(b, 0); /* legacy sockaddr form: marker, u8, u16, nonce, sockaddr_storage */
		b_u8(b, 0), b_u16(b, 0), b_u32(b, 0), b_zero(b, 128);
		break;
	case K_NONE_FAMILY:
		b_u8(b, 2), b_u32(b, 1);
		b_u8(b, 1), b_u8(b, 1), b_u8(b, 1), b_u32(b, 12), b_u32(b, 2), b_u32(b, 0), b_u32(b, 0);
		break; /* type msgr2 but elen 0: blank, not usable */
	case K_V2_PORT_0:
		b_u8(b, 2), b_u32(b, 1);
		v4_addr(b, 2, 0, ip, 0);
		break;
	case K_V2_PORT_0_THEN_OK:
		b_u8(b, 2), b_u32(b, 2);
		v4_addr(b, 2, 0, ip, 0);
		v4_addr(b, 2, 0, ip, 3300);
		break;
	default:
		b_u8(b, 2), b_u32(b, 1);
		v4_addr(b, 2, 0, ip, 7000);
		break;
	}
}

/*
 * A MonMap: v/compat envelope, the fields before mon_info, mon_info (given order), ranks, then
 * optional trailing bytes inside the envelope (stand-in for later fields).
 */
static size_t build_monmap(bld *b, uint32_t v, uint32_t compat, const mon_spec *mons, size_t n_mons,
			   const char *const *ranks, size_t n_ranks, size_t trailing)
{
	size_t env = b_env(b, v, compat), i, m;
	static const uint8_t fsid[16] = {0xa0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xaf};

	b_bytes(b, fsid, 16);
	b_u32(b, 7); /* epoch */
	b_u32(b, 1), b_u32(b, 2); /* last_changed */
	b_u32(b, 3), b_u32(b, 4); /* created */
	for (i = 0; i < 2; i++) { /* persistent / optional features */
		size_t f = b_env(b, 1, 1);

		b_u64(b, 0x1234);
		b_env_end(b, f);
	}
	b_u32(b, (uint32_t)n_mons);
	for (i = 0; i < n_mons; i++) {
		b_str(b, mons[i].name);
		m = b_env(b, 6, mons[i].info_compat ? mons[i].info_compat : 1);
		b_str(b, mons[i].name);
		put_addrvec(b, mons[i].kind, mons[i].last_octet);
		b_u16(b, 0), b_u16(b, 0); /* priority, weight */
		b_u32(b, 0);              /* crush_loc */
		b_u32(b, 0), b_u32(b, 0); /* time_added */
		b_env_end(b, m);
	}
	b_u32(b, (uint32_t)n_ranks);
	for (i = 0; i < n_ranks; i++)
		b_str(b, ranks[i]);
	b_zero(b, trailing);
	b_env_end(b, env);
	return b->n;
}

static wr_status decode_monmap_copy(const uint8_t *p, size_t n, wri_monmap *out)
{
	uint8_t *q = dup_bytes(p, n);
	wr_status st = wri_monmap_decode(q, n, out);

	free(q);
	return st;
}

static int map_is_zero(const wri_monmap *m)
{
	wri_monmap z;

	memset(&z, 0, sizeof(z));
	return memcmp(m, &z, sizeof(z)) == 0;
}

static void check_v4(const wri_eaddr *a, uint8_t last, uint16_t port, uint32_t nonce)
{
	WRT_CHECK_U64(a->type, WRI_EADDR_TYPE_MSGR2);
	WRT_CHECK_U64(a->family, WR_AF_IPV4);
	WRT_CHECK_U64(a->ip[0], 10);
	WRT_CHECK_U64(a->ip[3], last);
	WRT_CHECK_U64(a->port, port);
	WRT_CHECK_U64(a->nonce, nonce);
}

static void test_monmap_vector(void)
{
	wrt_json j;
	uint8_t *front = NULL, *map = NULL, *map_json = NULL, *want_fsid = NULL;
	size_t front_n = 0, map_n = 0, fsid_n = 0, i;
	const uint8_t *blob = NULL;
	size_t blob_n = 0;
	wri_monmap m;
	wrt_tok mm;

	if (load_hex(&j, "monclient/mmonmap-e3.json", "front_hex", &front, &front_n) != 0) {
		WRT_CHECK(0 && "vector load");
		return;
	}
	WRT_CHECK(wrt_json_get_hex(&j, wrt_json_root(&j), "monmap_hex", &map_json, &map_n) == 0);
	map = dup_bytes(map_json, map_n); /* exact-size heap copy for ASan */
	free(map_json);
	WRT_CHECK_U64(front_n, jint(&j, expect_of(&j), "front_len"));

	/* the MMonMap front is u32 length + the MonMap blob */
	WRT_CHECK_STATUS(WR_OK, wri_mmonmap_front(front, front_n, &blob, &blob_n));
	WRT_CHECK_U64(blob_n, map_n);
	WRT_CHECK(blob == front + 4);
	if (blob_n == map_n)
		WRT_CHECK_MEM(blob, map, map_n);

	mm = wrt_json_get(&j, expect_of(&j), "monmap");
	memset(&m, 0xAA, sizeof(m));
	WRT_CHECK_STATUS(WR_OK, wri_monmap_decode(map, map_n, &m));
	WRT_CHECK_U64(m.epoch, jint(&j, mm, "epoch"));
	WRT_CHECK_U64(m.n_mons, 1);
	WRT_CHECK_U64(m.rank_valid[0], 1);
	WRT_CHECK_U64(m.rank_valid[1], 0);
	WRT_CHECK(wrt_json_hex(&j, wrt_json_get(&j, mm, "fsid"), &want_fsid, &fsid_n) == 0);
	WRT_CHECK_U64(fsid_n, 16);
	if (fsid_n == 16)
		WRT_CHECK_MEM(m.fsid, want_fsid, 16);
	check_v4(&m.addr[0], 10, 3300, 0);
	WRT_CHECK_U64(m.addr[0].ip[1], 77);
	WRT_CHECK_U64(m.addr[0].ip[2], 0);
	/* the kept address is the canonical wire form of the monitor's v2 address, untouched */
	WRT_CHECK_U64(m.addr[0].raw_len, 35);

	/* every cut of the blob is refused, and the output is left zeroed */
	for (i = 0; i < map_n; i++) {
		wri_monmap t;

		memset(&t, 0x55, sizeof(t));
		WRT_CHECK(decode_monmap_copy(map, i, &t) != WR_OK);
		WRT_CHECK(map_is_zero(&t));
	}
	/* a cut MMonMap front */
	for (i = 0; i < front_n && i < 4 + map_n; i++) {
		const uint8_t *b2 = NULL;
		size_t n2 = 5;
		uint8_t *f = dup_bytes(front, i);
		wr_status st = wri_mmonmap_front(f, i, &b2, &n2);

		if (i < 4 + map_n) {
			WRT_CHECK(st != WR_OK);
			WRT_CHECK(b2 == NULL && n2 == 0);
		}
		free(f);
	}
	free(map);
	free(want_fsid);
	free(front);
	wrt_json_free(&j);
}

static void test_monmap_built(void)
{
	static const mon_spec three[] = {
		{"a", K_V2V1, 1, 0},
		{"b", K_V2V1, 2, 0},
		{"c", K_V2V1, 3, 0},
	};
	static const char *const rank_cab[] = {"c", "a", "b"};
	static const char *const rank_a[] = {"a"};
	bld b;
	wri_monmap m;
	uint32_t v;

	/* rank order follows the ranks vector, not the (name-sorted) map */
	b.n = 0;
	build_monmap(&b, 10, 6, three, 3, rank_cab, 3, 0);
	WRT_CHECK_STATUS(WR_OK, decode_monmap_copy(b.d, b.n, &m));
	WRT_CHECK_U64(m.epoch, 7);
	WRT_CHECK_U64(m.n_mons, 3);
	check_v4(&m.addr[0], 3, 3300, 0);
	check_v4(&m.addr[1], 1, 3300, 0);
	check_v4(&m.addr[2], 2, 3300, 0);
	WRT_CHECK_U64(m.rank_valid[0] & m.rank_valid[1] & m.rank_valid[2], 1);
	WRT_CHECK_U64(m.fsid[0], 0xa0);
	WRT_CHECK_U64(m.fsid[15], 0xaf);

	/* a map listing its monitors in some other order decodes the same */
	{
		static const mon_spec rev[] = {{"c", K_V2V1, 3, 0}, {"b", K_V2V1, 2, 0}, {"a", K_V2V1, 1, 0}};
		wri_monmap m2;

		b.n = 0;
		build_monmap(&b, 10, 6, rev, 3, rank_cab, 3, 0);
		WRT_CHECK_STATUS(WR_OK, decode_monmap_copy(b.d, b.n, &m2));
		WRT_CHECK_MEM(&m2, &m, sizeof(m));
	}

	/* struct_v 6 to 9 share the prefix, a later version just carries more bytes: skipped by struct_len */
	for (v = 6; v <= 12; v++) {
		b.n = 0;
		build_monmap(&b, v, 6, three, 3, rank_cab, 3, v >= 10 ? 40 : 0);
		WRT_CHECK_STATUS(WR_OK, decode_monmap_copy(b.d, b.n, &m));
		WRT_CHECK_U64(m.n_mons, 3);
	}
	/* envelope-level extra bytes with a compat up to 10 are accepted; compat 11 is not */
	b.n = 0;
	build_monmap(&b, 11, 10, three, 3, rank_cab, 3, 9);
	WRT_CHECK_STATUS(WR_OK, decode_monmap_copy(b.d, b.n, &m));
	b.n = 0;
	build_monmap(&b, 11, 11, three, 3, rank_cab, 3, 9);
	WRT_CHECK_STATUS(WR_E_MON_MAP_VERSION, decode_monmap_copy(b.d, b.n, &m));
	WRT_CHECK(map_is_zero(&m));
	b.n = 0;
	build_monmap(&b, 10, 255, three, 3, rank_cab, 3, 0);
	WRT_CHECK_STATUS(WR_E_MON_MAP_VERSION, decode_monmap_copy(b.d, b.n, &m));

	/* versions below 6, including the legacy 16-bit forms */
	for (v = 0; v <= 5; v++) {
		b.n = 0;
		build_monmap(&b, v, 1, three, 3, rank_cab, 3, 0);
		WRT_CHECK_STATUS(WR_E_MON_MAP_VERSION, decode_monmap_copy(b.d, b.n, &m));
		WRT_CHECK(map_is_zero(&m));
	}
	/* a version byte alone is enough to refuse an old map */
	{
		uint8_t one = 3;

		WRT_CHECK_STATUS(WR_E_MON_MAP_VERSION, decode_monmap_copy(&one, 1, &m));
	}
	WRT_CHECK_STATUS(WR_E_TRUNCATED, decode_monmap_copy(b.d, 0, &m));

	/* the v2 address is the second entry, after a v1 one */
	{
		static const mon_spec s[] = {{"a", K_V1V2, 9, 0}};

		b.n = 0;
		build_monmap(&b, 10, 6, s, 1, rank_a, 1, 0);
		WRT_CHECK_STATUS(WR_OK, decode_monmap_copy(b.d, b.n, &m));
		check_v4(&m.addr[0], 9, 3301, 7);
	}
	/* a v1-only monitor is kept as an invalid rank while another has a v2 address */
	{
		static const mon_spec s[] = {{"a", K_V1ONLY, 1, 0}, {"b", K_V2V1, 2, 0}, {"c", K_LEGACY0, 3, 0}};
		static const char *const r[] = {"a", "b", "c"};

		b.n = 0;
		build_monmap(&b, 10, 6, s, 3, r, 3, 0);
		WRT_CHECK_STATUS(WR_OK, decode_monmap_copy(b.d, b.n, &m));
		WRT_CHECK_U64(m.n_mons, 3);
		WRT_CHECK_U64(m.rank_valid[0], 0);
		WRT_CHECK_U64(m.rank_valid[1], 1);
		WRT_CHECK_U64(m.rank_valid[2], 0);
		check_v4(&m.addr[1], 2, 3300, 0);
	}
	/* no monitor has a msgr2 address: v1 only, legacy marker 0, a blank msgr2 entry */
	{
		static const mon_spec v1[] = {{"a", K_V1ONLY, 1, 0}};
		static const mon_spec leg[] = {{"a", K_LEGACY0, 1, 0}};
		static const mon_spec blank[] = {{"a", K_NONE_FAMILY, 1, 0}};

		b.n = 0;
		build_monmap(&b, 10, 6, v1, 1, rank_a, 1, 0);
		WRT_CHECK_STATUS(WR_E_MON_NO_V2_ADDR, decode_monmap_copy(b.d, b.n, &m));
		WRT_CHECK(map_is_zero(&m));
		b.n = 0;
		build_monmap(&b, 10, 6, leg, 1, rank_a, 1, 0);
		WRT_CHECK_STATUS(WR_E_MON_NO_V2_ADDR, decode_monmap_copy(b.d, b.n, &m));
		b.n = 0;
		build_monmap(&b, 10, 6, blank, 1, rank_a, 1, 0);
		WRT_CHECK_STATUS(WR_E_MON_NO_V2_ADDR, decode_monmap_copy(b.d, b.n, &m));
		/* a msgr2 address with port 0 cannot be dialled: not usable, and the next entry is looked at */
		{
			static const mon_spec p0[] = {{"a", K_V2_PORT_0, 1, 0}};
			static const mon_spec p0ok[] = {{"a", K_V2_PORT_0_THEN_OK, 1, 0}};

			b.n = 0;
			build_monmap(&b, 10, 6, p0, 1, rank_a, 1, 0);
			WRT_CHECK_STATUS(WR_E_MON_NO_V2_ADDR, decode_monmap_copy(b.d, b.n, &m));
			WRT_CHECK(map_is_zero(&m));
			b.n = 0;
			build_monmap(&b, 10, 6, p0ok, 1, rank_a, 1, 0);
			WRT_CHECK_STATUS(WR_OK, decode_monmap_copy(b.d, b.n, &m));
			WRT_CHECK_U64(m.rank_valid[0], 1);
			check_v4(&m.addr[0], 1, 3300, 0);
		}
		/* no monitors at all */
		b.n = 0;
		build_monmap(&b, 10, 6, NULL, 0, NULL, 0, 0);
		WRT_CHECK_STATUS(WR_E_MON_NO_V2_ADDR, decode_monmap_copy(b.d, b.n, &m));
	}
	/* IPv6 first, and a non-standard port */
	{
		static const mon_spec s[] = {{"a", K_V2V6, 5, 0}, {"b", K_V2_PORT_7000, 6, 0}};
		static const char *const r[] = {"a", "b"};

		b.n = 0;
		build_monmap(&b, 10, 6, s, 2, r, 2, 0);
		WRT_CHECK_STATUS(WR_OK, decode_monmap_copy(b.d, b.n, &m));
		WRT_CHECK_U64(m.addr[0].family, WR_AF_IPV6);
		WRT_CHECK_U64(m.addr[0].ip[0], 0xfd);
		WRT_CHECK_U64(m.addr[0].ip[15], 5);
		WRT_CHECK_U64(m.addr[0].port, 3300);
		WRT_CHECK_U64(m.addr[0].raw_len, 47);
		check_v4(&m.addr[1], 6, 7000, 0);
	}
	/* a rank whose name is not in mon_info is an invalid rank, not an error */
	{
		static const mon_spec s[] = {{"a", K_V2V1, 1, 0}};
		static const char *const r[] = {"ghost", "a"};

		b.n = 0;
		build_monmap(&b, 10, 6, s, 1, r, 2, 0);
		WRT_CHECK_STATUS(WR_OK, decode_monmap_copy(b.d, b.n, &m));
		WRT_CHECK_U64(m.n_mons, 2);
		WRT_CHECK_U64(m.rank_valid[0], 0);
		WRT_CHECK_U64(m.rank_valid[1], 1);
	}
	/* more than eight ranks: the first eight are kept, the rest read and ignored */
	{
		mon_spec s[12];
		char names[12][4];
		const char *r[12];
		size_t i;

		for (i = 0; i < 12; i++) {
			names[i][0] = 'm';
			names[i][1] = (char)('a' + i);
			names[i][2] = '\0';
			s[i].name = names[i];
			s[i].kind = K_V2V1;
			s[i].last_octet = (uint8_t)(i + 1);
			s[i].info_compat = 0;
			r[i] = names[i];
		}
		b.n = 0;
		build_monmap(&b, 10, 6, s, 12, r, 12, 0);
		WRT_CHECK_STATUS(WR_OK, decode_monmap_copy(b.d, b.n, &m));
		WRT_CHECK_U64(m.n_mons, WRI_MON_MAXMONS);
		for (i = 0; i < WRI_MON_MAXMONS; i++)
			check_v4(&m.addr[i], (uint8_t)(i + 1), 3300, 0);
	}
	/* a mon_info_t with a compat this client does not know is a version problem */
	{
		static const mon_spec s[] = {{"a", K_V2V1, 1, 2}};

		b.n = 0;
		build_monmap(&b, 10, 6, s, 1, rank_a, 1, 0);
		WRT_CHECK_STATUS(WR_E_MON_MAP_VERSION, decode_monmap_copy(b.d, b.n, &m));
	}
	/* hostile counts: every list count is capped and bounded by the bytes left */
	{
		static const mon_spec s[] = {{"a", K_V2V1, 1, 0}};
		size_t off = 6 + 16 + 4 + 16 + 2 * (6 + 8); /* the mon_info count */

		b.n = 0;
		build_monmap(&b, 10, 6, s, 1, rank_a, 1, 0);
		b.d[off] = 0xff, b.d[off + 1] = 0xff, b.d[off + 2] = 0xff, b.d[off + 3] = 0xff;
		WRT_CHECK_STATUS(WR_E_TOOBIG, decode_monmap_copy(b.d, b.n, &m));
		WRT_CHECK(map_is_zero(&m));
		b.d[off] = 65, b.d[off + 1] = 0, b.d[off + 2] = 0, b.d[off + 3] = 0; /* above the cap of 64 */
		WRT_CHECK_STATUS(WR_E_TOOBIG, decode_monmap_copy(b.d, b.n, &m));
	}
	/* NULL arguments */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_monmap_decode(b.d, b.n, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_monmap_decode(NULL, 5, &m));
	WRT_CHECK(map_is_zero(&m));
}

/* every cut of a larger hand-built map fails cleanly (not only the captured one) */
static void test_monmap_cuts(void)
{
	static const mon_spec s[] = {{"a", K_V2V1, 1, 0}, {"b", K_V1V2, 2, 0}, {"c", K_V2V6, 3, 0}};
	static const char *const r[] = {"b", "c", "a"};
	bld b;
	size_t i;

	b.n = 0;
	build_monmap(&b, 10, 6, s, 3, r, 3, 12);
	for (i = 0; i < b.n; i++) {
		wri_monmap m;

		memset(&m, 0x33, sizeof(m));
		WRT_CHECK(decode_monmap_copy(b.d, i, &m) != WR_OK);
		WRT_CHECK(map_is_zero(&m));
	}
}

/* ---- MOSDMap header -------------------------------------------------------------------------- */

static const uint8_t k_fsid[16] = {0x52, 0x76, 0x27, 0x25, 0xe1, 0x9a, 0x11, 0xf1,
				   0x88, 0x6d, 0x52, 0x54, 0x00, 0x77, 0x00, 0x01};

typedef struct osd_spec {
	uint32_t ver;
	const uint32_t *inc;   /* epochs, blob length = inc_len[i] */
	const uint32_t *inc_len;
	uint32_t n_inc;
	const uint32_t *full;
	const uint32_t *full_len;
	uint32_t n_full;
	uint32_t oldest, newest, gap;
	size_t trailing;
} osd_spec;

static void build_osdmap(bld *b, const osd_spec *s)
{
	uint32_t i;

	b->n = 0;
	b_bytes(b, k_fsid, 16);
	b_u32(b, s->n_inc);
	for (i = 0; i < s->n_inc; i++) {
		b_u32(b, s->inc[i]);
		b_u32(b, s->inc_len[i]);
		memset(b->d + b->n, 0xC3, s->inc_len[i]);
		b->n += s->inc_len[i];
	}
	b_u32(b, s->n_full);
	for (i = 0; i < s->n_full; i++) {
		b_u32(b, s->full[i]);
		b_u32(b, s->full_len[i]);
		memset(b->d + b->n, 0x3C, s->full_len[i]);
		b->n += s->full_len[i];
	}
	if (s->ver >= 2) {
		b_u32(b, s->oldest);
		b_u32(b, s->newest);
	}
	if (s->ver >= 4)
		b_u32(b, s->gap);
	b_zero(b, s->trailing);
}

static wr_status decode_osd_copy(const uint8_t *p, size_t n, uint16_t ver, wri_mosdmap_info *out)
{
	uint8_t *q = dup_bytes(p, n);
	wr_status st = wri_mosdmap_info_decode(q, n, ver, out);

	free(q);
	return st;
}

static int osd_is_zero(const wri_mosdmap_info *o)
{
	wri_mosdmap_info z;

	memset(&z, 0, sizeof(z));
	return memcmp(o, &z, sizeof(z)) == 0;
}

static void osd_vector(const char *rel, const char *hex_name, uint32_t n_inc, uint32_t n_full, uint32_t first,
		       uint32_t last)
{
	wrt_json j;
	uint8_t *front = NULL;
	size_t n = 0, i;
	wri_mosdmap_info o;
	wrt_tok ex;
	uint8_t *want_fsid = NULL;
	size_t fsid_n = 0;

	if (load_hex(&j, rel, hex_name, &front, &n) != 0) {
		WRT_CHECK(0 && "vector load");
		return;
	}
	ex = expect_of(&j);
	memset(&o, 0xAA, sizeof(o));
	WRT_CHECK_STATUS(WR_OK, wri_mosdmap_info_decode(front, n, (uint16_t)jint(&j, ex, "version"), &o));
	WRT_CHECK_U64(o.n_incremental, n_inc);
	WRT_CHECK_U64(o.n_full, n_full);
	WRT_CHECK_U64(o.first_epoch, first);
	WRT_CHECK_U64(o.last_epoch, last);
	WRT_CHECK_U64(o.oldest_map, jint(&j, ex, "cluster_osdmap_trim_lower_bound"));
	WRT_CHECK_U64(o.newest_map, jint(&j, ex, "newest_map"));
	WRT_CHECK_U64(wrt_json_count(&j, wrt_json_get(&j, ex, "incremental_epochs")), n_inc);
	WRT_CHECK_U64(wrt_json_count(&j, wrt_json_get(&j, ex, "full_epochs")), n_full);
	WRT_CHECK_U64(jint(&j, ex, "removed_snaps_gap_count"), 0);
	WRT_CHECK(wrt_json_hex(&j, wrt_json_get(&j, ex, "fsid"), &want_fsid, &fsid_n) == 0);
	WRT_CHECK_U64(fsid_n, 16);
	if (fsid_n == 16)
		WRT_CHECK_MEM(o.fsid, want_fsid, 16);

	/* the same body under a version that is not 4 changes the reading, never overruns */
	WRT_CHECK(decode_osd_copy(front, n, 2, &o) != WR_OK); /* v2 has no removed-snaps block: trailing bytes */
	WRT_CHECK_STATUS(WR_E_MON_PROTO, decode_osd_copy(front, n, 1, &o));
	WRT_CHECK(osd_is_zero(&o));

	/* every cut fails and leaves the output zeroed */
	for (i = 0; i < n; i++) {
		memset(&o, 0x77, sizeof(o));
		WRT_CHECK(decode_osd_copy(front, i, 4, &o) != WR_OK);
		WRT_CHECK(osd_is_zero(&o));
	}
	free(want_fsid);
	free(front);
	wrt_json_free(&j);
}

static void test_osdmap_vectors(void)
{
	/* one full map of epoch 42, trim bound 1, newest 42 */
	osd_vector("monclient/mosdmap-v4-full-e42.json", "front_hex", 0, 1, 42, 42);
	/* two incrementals 42, 43 with blob lengths 268 and 273; newest 43 sits behind them */
	osd_vector("monclient/mosdmap-v4-inc-e42-e43-synthetic.json", "front_hex", 2, 0, 42, 43);
}

static void test_osdmap_built(void)
{
	static const uint32_t inc[] = {40, 41, 39}, inc_len[] = {0, 17, 5000};
	static const uint32_t full[] = {30, 50}, full_len[] = {1, 0};
	osd_spec s;
	bld b;
	wri_mosdmap_info o;
	uint16_t ver;

	memset(&s, 0, sizeof(s));
	s.ver = 4, s.inc = inc, s.inc_len = inc_len, s.n_inc = 3;
	s.full = full, s.full_len = full_len, s.n_full = 2;
	s.oldest = 11, s.newest = 77;

	/* epochs are the min and max over both lists, whatever their order; lengths 0 and 5000 are skipped */
	build_osdmap(&b, &s);
	WRT_CHECK_STATUS(WR_OK, decode_osd_copy(b.d, b.n, 4, &o));
	WRT_CHECK_U64(o.n_incremental, 3);
	WRT_CHECK_U64(o.n_full, 2);
	WRT_CHECK_U64(o.first_epoch, 30);
	WRT_CHECK_U64(o.last_epoch, 50);
	WRT_CHECK_U64(o.oldest_map, 11);
	WRT_CHECK_U64(o.newest_map, 77);
	WRT_CHECK_MEM(o.fsid, k_fsid, 16);

	/* empty lists: bounds 0, header values still read */
	s.n_inc = 0, s.n_full = 0;
	build_osdmap(&b, &s);
	WRT_CHECK_STATUS(WR_OK, decode_osd_copy(b.d, b.n, 4, &o));
	WRT_CHECK_U64(o.first_epoch, 0);
	WRT_CHECK_U64(o.last_epoch, 0);
	WRT_CHECK_U64(o.newest_map, 77);

	/* epoch 0 is a real key, not "none" */
	{
		static const uint32_t z[] = {0}, zl[] = {3};

		s.full = z, s.full_len = zl, s.n_full = 1;
		build_osdmap(&b, &s);
		WRT_CHECK_STATUS(WR_OK, decode_osd_copy(b.d, b.n, 4, &o));
		WRT_CHECK_U64(o.n_full, 1);
		WRT_CHECK_U64(o.first_epoch, 0);
		WRT_CHECK_U64(o.last_epoch, 0);
		s.full = full, s.full_len = full_len, s.n_full = 2;
	}

	/* header versions: 2 and 3 end after newest_map, 4 has the removed-snaps count, 5+ may append more */
	s.n_inc = 3, s.n_full = 2;
	for (ver = 2; ver <= 6; ver++) {
		s.ver = ver;
		s.trailing = 0;
		build_osdmap(&b, &s);
		WRT_CHECK_STATUS(WR_OK, decode_osd_copy(b.d, b.n, ver, &o));
		WRT_CHECK_U64(o.newest_map, 77);
		s.trailing = 6;
		build_osdmap(&b, &s);
		if (ver <= 4)
			WRT_CHECK_STATUS(WR_E_ENCODING, decode_osd_copy(b.d, b.n, ver, &o));
		else
			WRT_CHECK_STATUS(WR_OK, decode_osd_copy(b.d, b.n, ver, &o));
		WRT_CHECK(ver <= 4 ? osd_is_zero(&o) : o.newest_map == 77);
	}
	s.trailing = 0;

	/* version 0 and 1 are refused, whatever the bytes */
	s.ver = 4;
	build_osdmap(&b, &s);
	WRT_CHECK_STATUS(WR_E_MON_PROTO, decode_osd_copy(b.d, b.n, 0, &o));
	WRT_CHECK_STATUS(WR_E_MON_PROTO, decode_osd_copy(b.d, b.n, 1, &o));
	WRT_CHECK(osd_is_zero(&o));
	WRT_CHECK_STATUS(WR_E_MON_PROTO, wri_mosdmap_info_decode(NULL, 0, 1, &o));

	/* a non-empty removed-snaps block is refused (v4), and ignored below v4 where it is not there */
	s.gap = 1;
	build_osdmap(&b, &s);
	WRT_CHECK_STATUS(WR_E_MON_PROTO, decode_osd_copy(b.d, b.n, 4, &o));
	WRT_CHECK(osd_is_zero(&o));
	s.gap = 0xFFFFFFFFu;
	build_osdmap(&b, &s);
	WRT_CHECK_STATUS(WR_E_MON_PROTO, decode_osd_copy(b.d, b.n, 4, &o));
	s.gap = 0;

	/* a blob length running past the front */
	s.ver = 4;
	build_osdmap(&b, &s);
	{
		size_t len_off = 16 + 4 + 4; /* first incremental's length */

		b.d[len_off] = 0xff, b.d[len_off + 1] = 0xff, b.d[len_off + 2] = 0xff, b.d[len_off + 3] = 0xff;
		WRT_CHECK_STATUS(WR_E_TRUNCATED, decode_osd_copy(b.d, b.n, 4, &o));
		WRT_CHECK(osd_is_zero(&o));
	}
	/* hostile counts */
	build_osdmap(&b, &s);
	b.d[16] = 0xff, b.d[17] = 0xff, b.d[18] = 0xff, b.d[19] = 0xff;
	WRT_CHECK_STATUS(WR_E_TOOBIG, decode_osd_copy(b.d, b.n, 4, &o));
	{
		static const uint32_t none = 0;
		osd_spec e;

		memset(&e, 0, sizeof(e));
		e.ver = 4, e.inc = &none, e.inc_len = &none, e.n_inc = 0, e.full = &none, e.full_len = &none;
		e.n_full = 0;
		build_osdmap(&b, &e);
		WRT_CHECK_STATUS(WR_OK, decode_osd_copy(b.d, b.n, 4, &o));
		/* 1025 entries of 8 bytes each: one above the cap of 1024, even though the bytes would fit */
		b.n = 16;
		b_u32(&b, 1025);
		b_zero(&b, 1025 * 8);
		b_u32(&b, 0), b_u32(&b, 1), b_u32(&b, 2), b_u32(&b, 0);
		WRT_CHECK_STATUS(WR_E_TOOBIG, decode_osd_copy(b.d, b.n, 4, &o));
	}

	/* NULL */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mosdmap_info_decode(b.d, b.n, 4, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mosdmap_info_decode(NULL, 5, 4, &o));
}

/* ---- MAuth / MAuthReply ---------------------------------------------------------------------- */

static void test_mauth(void)
{
	wrt_json j;
	uint8_t *front = NULL;
	size_t front_n = 0, i;
	uint8_t out[512];
	wri_wr w;
	uint32_t plen;

	/* encode: the scrubbed renewal request reproduced byte for byte from its parts */
	if (load_hex(&j, "monclient/mauth-renewal-scrubbed.json", "front_hex", &front, &front_n) != 0) {
		WRT_CHECK(0 && "vector load");
		return;
	}
	WRT_CHECK_U64(front_n, jint(&j, expect_of(&j), "front_len"));
	plen = (uint32_t)(front[22] | (front[23] << 8) | (front[24] << 16) | ((uint32_t)front[25] << 24));
	WRT_CHECK_U64(plen, 255);
	WRT_CHECK_U64(front_n, 8 + 2 + 8 + 4 + 4 + plen + 4);
	WRT_CHECK_U64(front[26] | (front[27] << 8), jint(&j, expect_of(&j), "request_type")); /* 0x0200 */
	WRT_CHECK_U64(front[front_n - 1] | front[front_n - 2] | front[front_n - 3] | front[front_n - 4], 0);
	wri_wr_init(&w, out, sizeof(out));
	wri_mauth_encode(&w, (uint32_t)jint(&j, expect_of(&j), "protocol"), front + 26, plen,
			 (uint32_t)jint(&j, expect_of(&j), "monmap_epoch"));
	WRT_CHECK_STATUS(WR_OK, w.err);
	WRT_CHECK_U64(wri_wr_len(&w), front_n);
	if (wri_wr_len(&w) == front_n)
		WRT_CHECK_MEM(out, front, front_n);
	/* the paxos prefix is version 0, session_mon -1, tid 0 */
	WRT_CHECK_U64(out[8], 0xff);
	WRT_CHECK_U64(out[9], 0xff);
	WRT_CHECK_U64(out[0] | out[1] | out[2] | out[3] | out[4] | out[5] | out[6] | out[7] | out[10] | out[17], 0);

	/* no room: TOOBIG at every size, and a small buffer is never overrun (ASan sees the exact malloc) */
	for (i = 0; i < front_n; i += 29) {
		uint8_t *small = (uint8_t *)malloc(i ? i : 1);

		if (small) {
			wri_wr_init(&w, small, i);
			wri_mauth_encode(&w, 2, front + 26, plen, 0);
			WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
			free(small);
		}
	}
	/* other arguments */
	wri_wr_init(&w, out, sizeof(out));
	wri_mauth_encode(&w, 9, NULL, 0, 4);
	WRT_CHECK_STATUS(WR_OK, w.err);
	WRT_CHECK_U64(wri_wr_len(&w), 8 + 2 + 8 + 4 + 4 + 4); /* prefix, protocol, empty blob, epoch */
	WRT_CHECK_U64(out[18], 9);
	WRT_CHECK_U64(out[26], 4);
	wri_wr_init(&w, out, sizeof(out));
	wri_mauth_encode(&w, 2, NULL, 3, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	wri_mauth_encode(NULL, 2, NULL, 0, 0);
	free(front);
	wrt_json_free(&j);
}

static wr_status reply_copy(const uint8_t *p, size_t n, wri_mauth_reply *out)
{
	uint8_t *q = dup_bytes(p, n);
	wr_status st = wri_mauth_reply_decode(q, n, out);

	free(q);
	return st;
}

static int reply_is_zero(const wri_mauth_reply *r)
{
	wri_mauth_reply z;

	memset(&z, 0, sizeof(z));
	return memcmp(r, &z, sizeof(z)) == 0;
}

static void test_mauth_reply(void)
{
	wrt_json j;
	uint8_t *front = NULL;
	size_t front_n = 0, i;
	wri_mauth_reply r;
	uint8_t *f;
	bld b;

	if (load_hex(&j, "monclient/mauthreply-renewal-scrubbed.json", "front_hex", &front, &front_n) != 0) {
		WRT_CHECK(0 && "vector load");
		return;
	}
	WRT_CHECK_U64(front_n, jint(&j, expect_of(&j), "front_len"));
	f = front;
	memset(&r, 0xAA, sizeof(r));
	WRT_CHECK_STATUS(WR_OK, wri_mauth_reply_decode(f, front_n, &r));
	WRT_CHECK_U64(r.protocol, jint(&j, expect_of(&j), "protocol"));
	WRT_CHECK_U64(r.result, jint(&j, expect_of(&j), "result"));
	WRT_CHECK_U64(r.global_id, 0x3c84); /* the session's id, the same value the request carried */
	WRT_CHECK_U64(r.payload_len, front_n - 4 - 4 - 8 - 4 - 4); /* result_bl; result_msg "" is the last 4 bytes */
	WRT_CHECK(r.payload == f + 20);
	WRT_CHECK_U64(r.payload[0] | (r.payload[1] << 8), 0x0200); /* response header */
	WRT_CHECK_U64(r.payload[2], 0);                            /* status 0 */

	/* every cut is refused with a zeroed output */
	for (i = 0; i < front_n; i++) {
		memset(&r, 0x66, sizeof(r));
		WRT_CHECK(reply_copy(front, i, &r) != WR_OK);
		WRT_CHECK(reply_is_zero(&r));
	}
	/* a trailing extra is tolerated (a later class version may append fields) */
	{
		uint8_t *g = (uint8_t *)malloc(front_n + 3);

		if (g) {
			memcpy(g, front, front_n);
			memset(g + front_n, 0xEE, 3);
			WRT_CHECK_STATUS(WR_OK, wri_mauth_reply_decode(g, front_n + 3, &r));
			free(g);
		}
	}

	/* hand-built: a refusal with a negative errno, a blob, a message */
	b.n = 0;
	b_u32(&b, 2);
	b_u32(&b, (uint32_t)-13);
	b_u64(&b, 0x1122334455667788ull);
	b_u32(&b, 3), b_u8(&b, 1), b_u8(&b, 2), b_u8(&b, 3);
	b_str(&b, "denied");
	{
		uint8_t *held = dup_bytes(b.d, b.n); /* the payload points into the input: keep it alive */

		WRT_CHECK_STATUS(WR_OK, wri_mauth_reply_decode(held, b.n, &r));
		WRT_CHECK_U64(r.protocol, 2);
		WRT_CHECK(r.result == -13);
		WRT_CHECK_U64(r.global_id, 0x1122334455667788ull);
		WRT_CHECK_U64(r.payload_len, 3);
		WRT_CHECK(r.payload == held + 20);
		WRT_CHECK_U64(r.payload[2], 3);
		free(held);
	}
	for (i = 0; i < b.n; i++) {
		WRT_CHECK(reply_copy(b.d, i, &r) != WR_OK);
		WRT_CHECK(reply_is_zero(&r));
	}
	/* blob length past the end / above the cap, message length past the end */
	b.d[16] = 0xff, b.d[17] = 0xff, b.d[18] = 0xff, b.d[19] = 0xff;
	WRT_CHECK_STATUS(WR_E_TOOBIG, reply_copy(b.d, b.n, &r));
	b.d[16] = 0xf0, b.d[17] = 0xff, b.d[18] = 0x00, b.d[19] = 0x00; /* 65520: under the cap, past the end */
	WRT_CHECK_STATUS(WR_E_TRUNCATED, reply_copy(b.d, b.n, &r));
	b.d[16] = 3, b.d[17] = 0;
	b.d[23] = 0x7f; /* message length 127, only 6 bytes follow */
	WRT_CHECK(reply_copy(b.d, b.n, &r) != WR_OK);
	WRT_CHECK(reply_is_zero(&r));
	/* a long result_msg is skipped, not an error: the numeric result must survive it */
	{
		static uint8_t longmsg[8 + 8 + 4 + 4 + 4 + 9000];
		uint8_t *held;

		b.n = 0;
		b_u32(&b, 2), b_u32(&b, (uint32_t)-13), b_u64(&b, 7), b_u32(&b, 0), b_u32(&b, 9000);
		memcpy(longmsg, b.d, b.n);
		memset(longmsg + b.n, 'x', 9000);
		held = dup_bytes(longmsg, b.n + 9000);
		WRT_CHECK_STATUS(WR_OK, wri_mauth_reply_decode(held, b.n + 9000, &r));
		WRT_CHECK(r.result == -13);
		WRT_CHECK_U64(r.payload_len, 0);
		/* ... but it still has to be there in full */
		WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_mauth_reply_decode(held, b.n + 8999, &r));
		WRT_CHECK(reply_is_zero(&r));
		free(held);
		/* a result_bl one past the 64 KiB cap is too big, exactly at the cap is read */
		b.n = 0;
		b_u32(&b, 2), b_u32(&b, 0), b_u64(&b, 7), b_u32(&b, 65537);
		held = (uint8_t *)calloc(1, b.n + 65537 + 4);
		if (held) {
			memcpy(held, b.d, b.n);
			WRT_CHECK_STATUS(WR_E_TOOBIG, wri_mauth_reply_decode(held, b.n + 65537 + 4, &r));
			held[16] = 0, held[17] = 0, held[18] = 1, held[19] = 0; /* 65536 */
			WRT_CHECK_STATUS(WR_OK, wri_mauth_reply_decode(held, b.n + 65536 + 4, &r));
			WRT_CHECK_U64(r.payload_len, 65536);
			free(held);
		}
	}
	/* a zero-length blob */
	b.n = 0;
	b_u32(&b, 2), b_u32(&b, 0), b_u64(&b, 5), b_u32(&b, 0), b_u32(&b, 0);
	WRT_CHECK_STATUS(WR_OK, reply_copy(b.d, b.n, &r));
	WRT_CHECK_U64(r.payload_len, 0); /* (r.payload dangles after the copy is freed: not touched) */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mauth_reply_decode(b.d, b.n, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mauth_reply_decode(NULL, 5, &r));

	free(front);
	wrt_json_free(&j);
}

int main(void)
{
	test_subscribe();
	test_getmap_and_types();
	test_monmap_vector();
	test_monmap_built();
	test_monmap_cuts();
	test_osdmap_vectors();
	test_osdmap_built();
	test_mauth();
	test_mauth_reply();
	return wrt_finish();
}
