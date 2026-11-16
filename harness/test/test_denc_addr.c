/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of core/src/msgr2/wri_m2_addr.c (entity_addr_t, entity_addrvec_t; msgr2.md 2.8).
 *
 *  - addresses decoded from the committed vectors: the MMonMap of monclient/mmonmap-e3.json and the
 *    HELLO / CLIENT_IDENT / SERVER_IDENT frames of msgr2/frames-crc.json (whole segments are
 *    walked, the expected values come from the JSON fields), canonical re-encode == original bytes;
 *  - IPv6, blank, short elen, non-zero reserved bytes, struct_v above 1;
 *  - rejections: marker 0, bad marker, struct_compat > 1, elen above the sockaddr, unknown family,
 *    every truncation point;
 *  - address vectors: markers 1 and 2, more entries than the caller keeps, count cap;
 *  - a deterministic mutation loop that checks decode -> encode -> decode is stable.
 *
 * Inputs handed to the decoders are exact-size heap buffers so ASan sees any over-read.
 */
#include "wrt.h"

#include "wri_m2_addr.h"

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

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/*
 * Hand-built marker-1 entity_addr_t, independent of the encoder under test.
 * sa/sa_n are the bytes after the 2-byte family field; elen is written as given (so a test can
 * lie); struct_len is written as given too. Returns the number of bytes written.
 */
static size_t hand_addr(uint8_t *o, uint8_t struct_v, uint8_t compat, uint32_t struct_len, uint32_t type,
			uint32_t nonce, uint32_t elen, uint16_t family, const uint8_t *sa, size_t sa_n)
{
	size_t n = 0;

	o[n++] = 1;
	o[n++] = struct_v;
	o[n++] = compat;
	put32(o + n, struct_len), n += 4;
	put32(o + n, type), n += 4;
	put32(o + n, nonce), n += 4;
	put32(o + n, elen), n += 4;
	if (elen != 0) {
		o[n++] = (uint8_t)family;
		o[n++] = (uint8_t)(family >> 8);
		if (sa_n)
			memcpy(o + n, sa, sa_n);
		n += sa_n;
	}
	return n;
}

/* Canonical IPv4: port big-endian, address, eight zero bytes. */
static size_t v4_canon(uint8_t *o, uint32_t type, uint32_t nonce, const uint8_t ip[4], uint16_t port)
{
	uint8_t sa[14];

	memset(sa, 0, sizeof(sa));
	sa[0] = (uint8_t)(port >> 8);
	sa[1] = (uint8_t)port;
	memcpy(sa + 2, ip, 4);
	return hand_addr(o, 1, 1, 28, type, nonce, 16, 2, sa, sizeof(sa));
}

static size_t v6_canon(uint8_t *o, uint32_t type, uint32_t nonce, const uint8_t ip[16], uint16_t port,
		       uint32_t flowinfo, uint32_t scope)
{
	uint8_t sa[26];

	memset(sa, 0, sizeof(sa));
	sa[0] = (uint8_t)(port >> 8);
	sa[1] = (uint8_t)port;
	sa[2] = (uint8_t)(flowinfo >> 24); /* network order inside the sockaddr */
	sa[3] = (uint8_t)(flowinfo >> 16);
	sa[4] = (uint8_t)(flowinfo >> 8);
	sa[5] = (uint8_t)flowinfo;
	memcpy(sa + 6, ip, 16);
	sa[22] = (uint8_t)scope; /* scope id is host order (little-endian on Linux) */
	sa[23] = (uint8_t)(scope >> 8);
	sa[24] = (uint8_t)(scope >> 16);
	sa[25] = (uint8_t)(scope >> 24);
	return hand_addr(o, 1, 1, 40, type, nonce, 28, 10, sa, sizeof(sa));
}

static size_t blank_canon(uint8_t *o, uint32_t type, uint32_t nonce)
{
	uint8_t sa[26];

	memset(sa, 0, sizeof(sa));
	return hand_addr(o, 1, 1, 40, type, nonce, 28, 0, sa, sizeof(sa));
}

/* Decode exactly one address from n bytes (heap copy); returns the status, *left = bytes unread. */
static wr_status dec1(const uint8_t *wire, size_t n, wri_eaddr *a, size_t *left)
{
	uint8_t *buf = dup_bytes(wire, n);
	wri_rd r;
	wr_status st;

	wri_rd_init(&r, buf, n);
	st = wri_eaddr_decode(&r, a);
	if (left)
		*left = wri_rd_left(&r);
	free(buf);
	return st;
}

/* Encode a into a buffer of exactly `cap` heap bytes; returns the status, copies to out. */
static wr_status enc1(const wri_eaddr *a, uint8_t *out, size_t cap, size_t *len)
{
	uint8_t *buf = (uint8_t *)malloc(cap ? cap : 1);
	wri_wr w;
	wr_status st;

	if (!buf)
		exit(2);
	wri_wr_init(&w, buf, cap);
	wri_eaddr_encode(&w, a);
	st = w.err;
	if (len)
		*len = wri_wr_len(&w);
	if (st == WR_OK && out)
		memcpy(out, buf, wri_wr_len(&w));
	free(buf);
	return st;
}

static int parse_ip4(const char *s, uint8_t ip[4])
{
	unsigned a, b, c, d;
	char tail;

	if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4 || a > 255 || b > 255 || c > 255 || d > 255)
		return -1;
	ip[0] = (uint8_t)a;
	ip[1] = (uint8_t)b;
	ip[2] = (uint8_t)c;
	ip[3] = (uint8_t)d;
	return 0;
}

/* Compare a decoded address with the {type, nonce, family, ip, port, hex} JSON object of the vectors,
 * and check the canonical re-encode against the original bytes. */
static void check_addr_json(const wrt_json *j, wrt_tok t, const wri_eaddr *a, const char *what)
{
	int ok = 0;
	char *ip = wrt_json_strdup(j, wrt_json_get(j, t, "ip"));
	uint8_t want_ip[4];
	uint8_t enc[WRI_EADDR_MAX_WIRE];
	size_t enc_len = 0;
	uint8_t *want_wire = NULL;
	size_t want_n = 0;

	WRT_CHECK_U64(a->type, wrt_json_int(j, wrt_json_get(j, t, "type"), &ok));
	WRT_CHECK_U64(a->nonce, wrt_json_int(j, wrt_json_get(j, t, "nonce"), &ok));
	WRT_CHECK_U64(a->port, wrt_json_int(j, wrt_json_get(j, t, "port"), &ok));
	WRT_CHECK_U64(wrt_json_int(j, wrt_json_get(j, t, "family"), &ok), 2);
	WRT_CHECK_U64(a->family, WR_AF_IPV4);
	WRT_CHECK(ip != NULL && parse_ip4(ip, want_ip) == 0);
	if (ip != NULL) {
		WRT_CHECK_MEM(a->ip, want_ip, 4);
	}
	{
		static const uint8_t zero12[12] = {0};

		WRT_CHECK_MEM(a->ip + 4, zero12, 12);
	}
	if (wrt_json_get_hex(j, t, "hex", &want_wire, &want_n) == 0) {
		WRT_CHECK_U64(a->raw_len, want_n);
		WRT_CHECK_U64(want_n, 35);
		if (a->raw_len == want_n)
			WRT_CHECK_MEM(a->raw, want_wire, want_n);
		WRT_CHECK_STATUS(WR_OK, enc1(a, enc, sizeof(enc), &enc_len));
		WRT_CHECK_U64(enc_len, want_n);
		if (enc_len == want_n)
			WRT_CHECK_MEM(enc, want_wire, want_n);
	} else {
		WRT_CHECK(0 && "vector address has no hex");
	}
	(void)what;
	free(ip);
	free(want_wire);
}

/* ---- vectors: MMonMap --------------------------------------------------------------------- */

static void test_monmap_addrvec(void)
{
	wrt_json j;
	uint8_t *map = NULL;
	size_t map_n = 0, i, at = (size_t)-1;
	static const uint8_t pat[] = {2, 2, 0, 0, 0, 1, 1, 1, 0x1c, 0, 0, 0}; /* marker 2, count 2, first addr */
	wrt_tok mons, mon, addrs;
	wri_eaddr a[WRI_EADDRVEC_MAX];
	size_t stored = 0, total = 0;
	wri_rd r;
	uint8_t *buf;
	uint8_t enc[128];
	wri_wr w;

	if (wrt_json_load_vec(&j, "monclient/mmonmap-e3.json") != 0) {
		WRT_CHECK(0 && "cannot load mmonmap-e3.json");
		return;
	}
	WRT_CHECK(wrt_json_get_hex(&j, wrt_json_root(&j), "monmap_hex", &map, &map_n) == 0);
	for (i = 0; map && i + sizeof(pat) <= map_n; i++)
		if (memcmp(map + i, pat, sizeof(pat)) == 0) {
			at = i;
			break;
		}
	WRT_CHECK(at != (size_t)-1);
	if (at == (size_t)-1)
		goto out;

	buf = dup_bytes(map + at, map_n - at);
	wri_rd_init(&r, buf, map_n - at);
	WRT_CHECK_STATUS(WR_OK, wri_eaddrvec_decode(&r, a, WRI_EADDRVEC_MAX, &stored, &total));
	WRT_CHECK_U64(stored, 2);
	WRT_CHECK_U64(total, 2);
	WRT_CHECK_U64(r.pos, 5 + 35 + 35);

	mons = wrt_json_get(&j, wrt_json_get(&j, wrt_json_get(&j, wrt_json_root(&j), "expect"), "monmap"), "mons");
	mon = wrt_json_get(&j, mons, "winrbd-ceph1");
	addrs = wrt_json_get(&j, mon, "addrs");
	WRT_CHECK_U64(wrt_json_count(&j, addrs), 2);
	for (i = 0; i < 2 && i < stored; i++) {
		wrt_tok t = wrt_json_at(&j, addrs, i);
		int ok = 0;
		char *ip = wrt_json_strdup(&j, wrt_json_get(&j, t, "ip"));
		uint8_t want_ip[4];

		WRT_CHECK_U64(a[i].type, wrt_json_int(&j, wrt_json_get(&j, t, "type"), &ok));
		WRT_CHECK_U64(a[i].port, wrt_json_int(&j, wrt_json_get(&j, t, "port"), &ok));
		WRT_CHECK_U64(a[i].nonce, wrt_json_int(&j, wrt_json_get(&j, t, "nonce"), &ok));
		WRT_CHECK(ip != NULL && parse_ip4(ip, want_ip) == 0);
		if (ip != NULL) {
			WRT_CHECK_MEM(a[i].ip, want_ip, 4);
		}
		free(ip);
		WRT_CHECK_U64(a[i].family, WR_AF_IPV4);
	}
	WRT_CHECK_U64(a[0].type, WRI_EADDR_TYPE_MSGR2);
	WRT_CHECK_U64(a[0].port, 3300);
	WRT_CHECK_U64(a[1].type, WRI_EADDR_TYPE_LEGACY);
	WRT_CHECK_U64(a[1].port, 6789);

	/* canonical re-encode of the vector == the original 75 bytes */
	wri_wr_init(&w, enc, sizeof(enc));
	wri_eaddrvec_encode(&w, a, stored);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(wri_wr_len(&w), 75);
	if (wri_wr_len(&w) == 75)
		WRT_CHECK_MEM(enc, map + at, 75);
	free(buf);
out:
	free(map);
	wrt_json_free(&j);
}

/* ---- vectors: frames ---------------------------------------------------------------------- */

#define PREAMBLE_LEN 32u /* crc-mode preamble; segment 0 starts right after it */

static void frame_ident_checks(const wrt_json *j, wrt_tok f, wri_rd *seg, int client)
{
	wrt_tok fields = wrt_json_get(j, f, "fields");
	wrt_tok addrs = wrt_json_get(j, fields, "addrs");
	wri_eaddr a[WRI_EADDRVEC_MAX], target;
	size_t stored = 0, total = 0, i, before = seg->pos;
	int ok = 0;

	WRT_CHECK_STATUS(WR_OK, wri_eaddrvec_decode(seg, a, WRI_EADDRVEC_MAX, &stored, &total));
	WRT_CHECK_U64(total, wrt_json_count(j, addrs));
	WRT_CHECK_U64(stored, total);
	for (i = 0; i < stored; i++)
		check_addr_json(j, wrt_json_at(j, addrs, i), &a[i], "ident addrs");
	/* the vector is 5 + 35 * n bytes */
	WRT_CHECK_U64(seg->pos - before, 5 + 35 * stored);
	if (client) {
		WRT_CHECK_STATUS(WR_OK, wri_eaddr_decode(seg, &target));
		check_addr_json(j, wrt_json_get(j, fields, "target"), &target, "target");
	}
	WRT_CHECK_U64((uint64_t)wri_rd_i64(seg), (uint64_t)wrt_json_int(j, wrt_json_get(j, fields, "gid"), &ok));
	WRT_CHECK_U64(wri_rd_u64(seg), wrt_json_int(j, wrt_json_get(j, fields, "global_seq"), &ok));
	WRT_CHECK_U64(wri_rd_u64(seg), wrt_json_int(j, wrt_json_get(j, fields, "supported"), &ok));
	WRT_CHECK_U64(wri_rd_u64(seg), wrt_json_int(j, wrt_json_get(j, fields, "required"), &ok));
	WRT_CHECK_U64(wri_rd_u64(seg), wrt_json_int(j, wrt_json_get(j, fields, "flags"), &ok));
	WRT_CHECK_U64(wri_rd_u64(seg), wrt_json_int(j, wrt_json_get(j, fields, "cookie"), &ok));
	WRT_CHECK(wri_rd_ok(seg));
	WRT_CHECK_U64(wri_rd_left(seg), 0); /* the whole segment was consumed */
}

static void test_frames(void)
{
	wrt_json j;
	wrt_tok frames;
	size_t i, n, seen_hello = 0, seen_client = 0, seen_server = 0;

	if (wrt_json_load_vec(&j, "msgr2/frames-crc.json") != 0) {
		WRT_CHECK(0 && "cannot load frames-crc.json");
		return;
	}
	frames = wrt_json_get(&j, wrt_json_root(&j), "frames");
	n = wrt_json_count(&j, frames);
	for (i = 0; i < n; i++) {
		wrt_tok f = wrt_json_at(&j, frames, i);
		char *tag = wrt_json_strdup(&j, wrt_json_get(&j, f, "tag_name"));
		uint8_t *wire = NULL, *copy;
		size_t wire_n = 0, seg_len;
		int ok = 0;
		wri_rd r, seg;

		if (tag == NULL)
			continue;
		if (strcmp(tag, "HELLO") != 0 && strcmp(tag, "CLIENT_IDENT") != 0 && strcmp(tag, "SERVER_IDENT") != 0) {
			free(tag);
			continue;
		}
		WRT_CHECK(wrt_json_get_hex(&j, f, "hex", &wire, &wire_n) == 0);
		seg_len = (size_t)wrt_json_int(&j, wrt_json_at(&j, wrt_json_get(&j, f, "segment_lengths"), 0), &ok);
		WRT_CHECK(wire != NULL && PREAMBLE_LEN + seg_len <= wire_n);
		if (wire == NULL || PREAMBLE_LEN + seg_len > wire_n) {
			free(tag);
			free(wire);
			continue;
		}
		/* exact-size copy of segment 0 only */
		copy = dup_bytes(wire + PREAMBLE_LEN, seg_len);
		wri_rd_init(&r, copy, seg_len);
		seg = wri_rd_sub(&r, seg_len);

		if (strcmp(tag, "HELLO") == 0) {
			wri_eaddr a;
			wrt_tok fields = wrt_json_get(&j, f, "fields");

			seen_hello++;
			WRT_CHECK_U64(wri_rd_u8(&seg), wrt_json_int(&j, wrt_json_get(&j, fields, "entity_type"), &ok));
			WRT_CHECK_STATUS(WR_OK, wri_eaddr_decode(&seg, &a));
			check_addr_json(&j, wrt_json_get(&j, fields, "peer_addr"), &a, "peer_addr");
			WRT_CHECK_U64(wri_rd_left(&seg), 0);
		} else if (strcmp(tag, "CLIENT_IDENT") == 0) {
			seen_client++;
			frame_ident_checks(&j, f, &seg, 1);
		} else {
			seen_server++;
			frame_ident_checks(&j, f, &seg, 0);
		}
		free(copy);
		free(wire);
		free(tag);
	}
	WRT_CHECK(seen_hello >= 2);
	WRT_CHECK(seen_client >= 3);
	WRT_CHECK(seen_server >= 3);
	wrt_json_free(&j);
}

/* ---- canonical encodings ------------------------------------------------------------------ */

static void test_ipv4_canonical(void)
{
	static const uint8_t ip[4] = {10, 77, 0, 10};
	uint8_t wire[WRI_EADDR_MAX_WIRE], enc[WRI_EADDR_MAX_WIRE];
	size_t n = v4_canon(wire, WRI_EADDR_TYPE_MSGR2, 0xA1B2C3D4u, ip, 3300), left = 99, enc_len = 0;
	wri_eaddr a;

	WRT_CHECK_U64(n, 35);
	WRT_CHECK_STATUS(WR_OK, dec1(wire, n, &a, &left));
	WRT_CHECK_U64(left, 0);
	WRT_CHECK_U64(a.type, 2);
	WRT_CHECK_U64(a.nonce, 0xA1B2C3D4u);
	WRT_CHECK_U64(a.family, WR_AF_IPV4);
	WRT_CHECK_U64(a.port, 3300);
	WRT_CHECK_MEM(a.ip, ip, 4);
	WRT_CHECK_U64(a.raw_len, 35);
	WRT_CHECK_MEM(a.raw, wire, n);
	WRT_CHECK_STATUS(WR_OK, enc1(&a, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, 35);
	WRT_CHECK_MEM(enc, wire, 35);
	/* port 0x0CE4 on the wire is 0C E4, big-endian */
	WRT_CHECK_U64(wire[21], 0x0C);
	WRT_CHECK_U64(wire[22], 0xE4);
}

static void test_ipv6_round_trip(void)
{
	static const uint8_t ip[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	uint8_t wire[WRI_EADDR_MAX_WIRE], enc[WRI_EADDR_MAX_WIRE];
	size_t n = v6_canon(wire, WRI_EADDR_TYPE_MSGR2, 7, ip, 6800, 0, 0), left = 99, enc_len = 0;
	wri_eaddr a;
	wr_addr pub;

	WRT_CHECK_U64(n, 47);
	WRT_CHECK_STATUS(WR_OK, dec1(wire, n, &a, &left));
	WRT_CHECK_U64(left, 0);
	WRT_CHECK_U64(a.family, WR_AF_IPV6);
	WRT_CHECK_U64(a.port, 6800);
	WRT_CHECK_U64(a.nonce, 7);
	WRT_CHECK_MEM(a.ip, ip, 16);
	WRT_CHECK_U64(a.raw_len, 47);
	WRT_CHECK_MEM(a.raw, wire, n);
	WRT_CHECK_STATUS(WR_OK, enc1(&a, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, 47);
	WRT_CHECK_MEM(enc, wire, 47);
	WRT_CHECK_U64(wire[19], 10); /* AF_INET6 is 10 on the wire */
	WRT_CHECK_U64(wire[20], 0);

	wri_eaddr_to_wr(&pub, &a);
	WRT_CHECK_U64(pub.family, WR_AF_IPV6);
	WRT_CHECK_U64(pub.port, 6800);
	WRT_CHECK_U64(pub.nonce, 7);
	WRT_CHECK_MEM(pub.ip, ip, 16);
}

static void test_ipv6_flowinfo_scope_kept(void)
{
	/* link-local with a scope id and flowinfo: the server compares them, so the copy must keep them */
	static const uint8_t ip[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5};
	uint8_t wire[WRI_EADDR_MAX_WIRE], enc[WRI_EADDR_MAX_WIRE];
	size_t n = v6_canon(wire, WRI_EADDR_TYPE_MSGR2, 1, ip, 3300, 0x01020304u, 3), enc_len = 0;
	wri_eaddr a, other;

	WRT_CHECK_STATUS(WR_OK, dec1(wire, n, &a, NULL));
	WRT_CHECK_MEM(a.raw, wire, n);
	WRT_CHECK_STATUS(WR_OK, enc1(&a, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, 47);
	WRT_CHECK_MEM(enc, wire, 47);

	/* a different scope id is a different address under the server's bytewise compare */
	n = v6_canon(wire, WRI_EADDR_TYPE_MSGR2, 1, ip, 3300, 0x01020304u, 4);
	WRT_CHECK_STATUS(WR_OK, dec1(wire, n, &other, NULL));
	WRT_CHECK(!wri_eaddr_equal(&a, &other));

	/* editing a typed field makes raw stale: the encoder follows the fields (reserved bytes zero) */
	a.port = 9999;
	WRT_CHECK_STATUS(WR_OK, enc1(&a, enc, sizeof(enc), &enc_len));
	{
		wri_eaddr back;
		static const uint8_t zero4[4] = {0};

		WRT_CHECK_STATUS(WR_OK, dec1(enc, enc_len, &back, NULL));
		WRT_CHECK_U64(back.port, 9999);
		WRT_CHECK_MEM(back.ip, ip, 16);
		WRT_CHECK_MEM(back.raw + 21 + 2, zero4, 4); /* flowinfo */
		WRT_CHECK_MEM(back.raw + 21 + 22, zero4, 4); /* scope id */
	}
}

static void test_ipv4_reserved_bytes_kept(void)
{
	/* non-zero bytes in the eight zero bytes of sockaddr_in are part of the object the server compares */
	uint8_t sa[14] = {0x0C, 0xE4, 10, 77, 0, 10, 0, 0, 0, 0, 0, 0, 0, 1};
	uint8_t wire[WRI_EADDR_MAX_WIRE], enc[WRI_EADDR_MAX_WIRE], canon[WRI_EADDR_MAX_WIRE];
	static const uint8_t ip[4] = {10, 77, 0, 10};
	size_t n = hand_addr(wire, 1, 1, 28, 2, 0, 16, 2, sa, sizeof(sa)), enc_len = 0;
	size_t cn = v4_canon(canon, 2, 0, ip, 3300);
	wri_eaddr a, c;

	WRT_CHECK_STATUS(WR_OK, dec1(wire, n, &a, NULL));
	WRT_CHECK_STATUS(WR_OK, dec1(canon, cn, &c, NULL));
	WRT_CHECK_U64(a.port, 3300);
	WRT_CHECK(!wri_eaddr_equal(&a, &c));
	WRT_CHECK_STATUS(WR_OK, enc1(&a, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, n);
	WRT_CHECK_MEM(enc, wire, n);
}

static void test_blank(void)
{
	uint8_t canon[WRI_EADDR_MAX_WIRE], elen0[64], enc[WRI_EADDR_MAX_WIRE];
	size_t cn = blank_canon(canon, WRI_EADDR_TYPE_NONE, 0), en, enc_len = 0, left = 9;
	wri_eaddr a, b, built;
	static const uint8_t zero16[16] = {0};

	WRT_CHECK_U64(cn, 47);
	WRT_CHECK_U64(canon[15], 28); /* elen */
	WRT_CHECK_U64(canon[19], 0);  /* family 0 */

	WRT_CHECK_STATUS(WR_OK, dec1(canon, cn, &a, &left));
	WRT_CHECK_U64(left, 0);
	WRT_CHECK_U64(a.family, 0);
	WRT_CHECK_U64(a.port, 0);
	WRT_CHECK_MEM(a.ip, zero16, 16);
	WRT_CHECK_STATUS(WR_OK, enc1(&a, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, 47);
	WRT_CHECK_MEM(enc, canon, 47);

	/* elen 0: struct_len 12, no family, no bytes */
	en = hand_addr(elen0, 1, 1, 12, 0, 0, 0, 0, NULL, 0);
	WRT_CHECK_U64(en, 19);
	WRT_CHECK_STATUS(WR_OK, dec1(elen0, en, &b, &left));
	WRT_CHECK_U64(left, 0);
	WRT_CHECK_U64(b.family, 0);
	WRT_CHECK(wri_eaddr_equal(&a, &b)); /* same object for the server */
	WRT_CHECK_STATUS(WR_OK, enc1(&b, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, 47); /* the encoder always emits the canonical form */
	WRT_CHECK_MEM(enc, canon, 47);

	/* built from the public type: family 0 / unknown number is blank */
	{
		wr_addr pub;

		memset(&pub, 0, sizeof(pub));
		wri_eaddr_from_wr(&built, &pub, 0);
		WRT_CHECK(wri_eaddr_equal(&built, &a));
		pub.family = 99;
		wri_eaddr_from_wr(&built, &pub, 0);
		WRT_CHECK(wri_eaddr_equal(&built, &a));
		wri_eaddr_to_wr(&pub, &built);
		WRT_CHECK_U64(pub.family, 0);
	}
}

static void test_short_elen(void)
{
	/* a decoder accepts an elen below the full sockaddr; the rest is zero */
	uint8_t wire[WRI_EADDR_MAX_WIRE], canon[WRI_EADDR_MAX_WIRE];
	static const uint8_t sa[6] = {0x0C, 0xE4, 10, 77, 0, 10};
	static const uint8_t ip[4] = {10, 77, 0, 10};
	size_t n = hand_addr(wire, 1, 1, 12 + 8, 2, 0, 8, 2, sa, sizeof(sa));
	size_t cn = v4_canon(canon, 2, 0, ip, 3300), left = 9;
	wri_eaddr a, c;

	WRT_CHECK_STATUS(WR_OK, dec1(wire, n, &a, &left));
	WRT_CHECK_U64(left, 0);
	WRT_CHECK_U64(a.port, 3300);
	WRT_CHECK_MEM(a.ip, ip, 4);
	WRT_CHECK_STATUS(WR_OK, dec1(canon, cn, &c, NULL));
	WRT_CHECK(wri_eaddr_equal(&a, &c));

	/* elen 2: only the family, so port 0 and address 0.0.0.0 */
	n = hand_addr(wire, 1, 1, 12 + 2, 2, 5, 2, 2, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, dec1(wire, n, &a, NULL));
	WRT_CHECK_U64(a.family, WR_AF_IPV4);
	WRT_CHECK_U64(a.port, 0);
	WRT_CHECK_U64(a.raw_len, 35);
}

static void test_struct_v_and_trailing(void)
{
	/* struct_v 2 with extra bytes inside struct_len: skipped; the next byte is the caller's */
	static const uint8_t ip[4] = {10, 77, 0, 10};
	uint8_t canon[WRI_EADDR_MAX_WIRE], wire[WRI_EADDR_MAX_WIRE + 8];
	size_t cn = v4_canon(canon, 2, 0, ip, 3300), left = 0;
	wri_eaddr a, c;

	WRT_CHECK_STATUS(WR_OK, dec1(canon, cn, &c, NULL));
	memcpy(wire, canon, cn);
	wire[1] = 2;                       /* struct_v */
	put32(wire + 3, 28 + 5);           /* five extra bytes inside struct_len */
	memcpy(wire + cn, "\x01\x02\x03\x04\x05", 5);
	wire[cn + 5] = 0xEE;               /* belongs to the caller */
	WRT_CHECK_STATUS(WR_OK, dec1(wire, cn + 6, &a, &left));
	WRT_CHECK_U64(left, 1);
	WRT_CHECK(wri_eaddr_equal(&a, &c));
	WRT_CHECK_U64(a.raw_len, 35);
	WRT_CHECK_MEM(a.raw, canon, 35); /* raw is the version-1 form */
}

/* ---- rejections --------------------------------------------------------------------------- */

static void test_reject_markers(void)
{
	static const uint8_t ip[4] = {10, 77, 0, 10};
	uint8_t wire[WRI_EADDR_MAX_WIRE];
	size_t n = v4_canon(wire, 2, 0, ip, 3300);
	uint8_t m;
	wri_eaddr a;

	wire[0] = 0; /* legacy sockaddr_storage form */
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, dec1(wire, n, &a, NULL));
	for (m = 2; m < 255; m += 61) {
		wire[0] = m;
		WRT_CHECK_STATUS(WR_E_ENCODING, dec1(wire, n, &a, NULL));
	}
	wire[0] = 255;
	WRT_CHECK_STATUS(WR_E_ENCODING, dec1(wire, n, &a, NULL));
}

static void test_reject_compat(void)
{
	static const uint8_t ip[4] = {10, 77, 0, 10};
	uint8_t wire[WRI_EADDR_MAX_WIRE];
	size_t n = v4_canon(wire, 2, 0, ip, 3300);
	wri_eaddr a;

	wire[2] = 2; /* struct_compat 2 */
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, dec1(wire, n, &a, NULL));
	wire[2] = 0; /* compat 0 is fine */
	WRT_CHECK_STATUS(WR_OK, dec1(wire, n, &a, NULL));
}

static void test_reject_elen(void)
{
	uint8_t sa[40], wire[80];
	size_t n;
	wri_eaddr a;

	memset(sa, 0, sizeof(sa));
	/* IPv4: 14 bytes after the family is the most */
	n = hand_addr(wire, 1, 1, 12 + 2 + 14, 2, 0, 16, 2, sa, 14);
	WRT_CHECK_STATUS(WR_OK, dec1(wire, n, &a, NULL));
	n = hand_addr(wire, 1, 1, 12 + 2 + 15, 2, 0, 17, 2, sa, 15);
	WRT_CHECK_STATUS(WR_E_ENCODING, dec1(wire, n, &a, NULL));
	n = hand_addr(wire, 1, 1, 12 + 2 + 26, 2, 0, 28, 2, sa, 26);
	WRT_CHECK_STATUS(WR_E_ENCODING, dec1(wire, n, &a, NULL));
	/* IPv6 and blank: 26 */
	n = hand_addr(wire, 1, 1, 12 + 2 + 26, 2, 0, 28, 10, sa, 26);
	WRT_CHECK_STATUS(WR_OK, dec1(wire, n, &a, NULL));
	n = hand_addr(wire, 1, 1, 12 + 2 + 27, 2, 0, 29, 10, sa, 27);
	WRT_CHECK_STATUS(WR_E_ENCODING, dec1(wire, n, &a, NULL));
	n = hand_addr(wire, 1, 1, 12 + 2 + 27, 2, 0, 29, 0, sa, 27);
	WRT_CHECK_STATUS(WR_E_ENCODING, dec1(wire, n, &a, NULL));
	/* an absurd elen does not cause any big read */
	n = hand_addr(wire, 1, 1, 12 + 2, 2, 0, 0xFFFFFFFFu, 2, NULL, 0);
	WRT_CHECK_STATUS(WR_E_ENCODING, dec1(wire, n, &a, NULL));
	/* elen 1 cannot hold the family field */
	n = hand_addr(wire, 1, 1, 12 + 1, 2, 0, 1, 2, NULL, 0);
	wire[19] = 2;
	WRT_CHECK_STATUS(WR_E_ENCODING, dec1(wire, 19 + 1, &a, NULL));
	/* elen promises more than struct_len holds */
	n = hand_addr(wire, 1, 1, 12 + 2 + 4, 2, 0, 16, 2, sa, 4);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, dec1(wire, n, &a, NULL));
}

static void test_reject_family(void)
{
	uint8_t sa[26];
	uint8_t wire[64];
	size_t n;
	wri_eaddr a;

	memset(sa, 0, sizeof(sa));
	/* AF_UNIX-like family number: we only speak IP */
	n = hand_addr(wire, 1, 1, 12 + 2 + 14, 2, 0, 16, 1, sa, 14);
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, dec1(wire, n, &a, NULL));
	n = hand_addr(wire, 1, 1, 12 + 2 + 26, 2, 0, 28, 7, sa, 26);
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, dec1(wire, n, &a, NULL));
	/* a failed decode leaves the output zeroed */
	{
		static const uint8_t zero[sizeof(a)] = {0};

		WRT_CHECK_MEM(&a, zero, sizeof(a));
	}
}

static void test_every_truncation(void)
{
	static const uint8_t ip4[4] = {10, 77, 0, 10};
	static const uint8_t ip6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	uint8_t w4[WRI_EADDR_MAX_WIRE], w6[WRI_EADDR_MAX_WIRE], wb[WRI_EADDR_MAX_WIRE];
	size_t n4 = v4_canon(w4, 2, 1, ip4, 3300), n6 = v6_canon(w6, 2, 1, ip6, 3300, 0, 0);
	size_t nb = blank_canon(wb, 0, 0), k;
	wri_eaddr a;

	for (k = 0; k < n4; k++)
		WRT_CHECK_STATUS(WR_E_TRUNCATED, dec1(w4, k, &a, NULL));
	for (k = 0; k < n6; k++)
		WRT_CHECK_STATUS(WR_E_TRUNCATED, dec1(w6, k, &a, NULL));
	for (k = 0; k < nb; k++)
		WRT_CHECK_STATUS(WR_E_TRUNCATED, dec1(wb, k, &a, NULL));
	WRT_CHECK_STATUS(WR_OK, dec1(w4, n4, &a, NULL));
	WRT_CHECK_STATUS(WR_OK, dec1(w6, n6, &a, NULL));
	WRT_CHECK_STATUS(WR_OK, dec1(wb, nb, &a, NULL));
}

static void test_decode_sticky_and_args(void)
{
	static const uint8_t ip[4] = {10, 77, 0, 10};
	uint8_t wire[WRI_EADDR_MAX_WIRE];
	size_t n = v4_canon(wire, 2, 0, ip, 3300);
	wri_rd r;
	wri_eaddr a;

	wri_rd_init(&r, wire, n);
	wri_rd_fail(&r, WR_E_ENCODING);
	WRT_CHECK_STATUS(WR_E_ENCODING, wri_eaddr_decode(&r, &a));
	wri_rd_init(&r, wire, n);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_eaddr_decode(&r, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_eaddr_decode(NULL, &a));
}

/* ---- encoder limits ----------------------------------------------------------------------- */

static void test_encode_overflow(void)
{
	wr_addr pub;
	wri_eaddr a;
	size_t cap, len = 0;
	uint8_t out[WRI_EADDR_MAX_WIRE];

	memset(&pub, 0, sizeof(pub));
	pub.family = WR_AF_IPV6;
	pub.ip[15] = 1;
	pub.port = 1;
	wri_eaddr_from_wr(&a, &pub, WRI_EADDR_TYPE_MSGR2);
	for (cap = 0; cap < 47; cap++)
		WRT_CHECK_STATUS(WR_E_TOOBIG, enc1(&a, out, cap, &len));
	WRT_CHECK_STATUS(WR_OK, enc1(&a, out, 47, &len));
	WRT_CHECK_U64(len, 47);

	pub.family = WR_AF_IPV4;
	wri_eaddr_from_wr(&a, &pub, WRI_EADDR_TYPE_MSGR2);
	for (cap = 0; cap < 35; cap++)
		WRT_CHECK_STATUS(WR_E_TOOBIG, enc1(&a, out, cap, &len));
	WRT_CHECK_STATUS(WR_OK, enc1(&a, out, 35, &len));
	WRT_CHECK_U64(len, 35);
	{
		wri_wr w;

		wri_wr_init(&w, out, sizeof(out));
		wri_eaddr_encode(&w, NULL);
		WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	}
}

static void test_from_wr_to_wr(void)
{
	wr_addr pub, back;
	wri_eaddr a;
	uint8_t want[WRI_EADDR_MAX_WIRE];
	static const uint8_t ip[4] = {10, 77, 0, 10};
	size_t wn = v4_canon(want, WRI_EADDR_TYPE_ANY, 0x01020304u, ip, 3300);

	memset(&pub, 0, sizeof(pub));
	pub.family = WR_AF_IPV4;
	memcpy(pub.ip, ip, 4);
	pub.port = 3300;
	pub.nonce = 0x01020304u;
	wri_eaddr_from_wr(&a, &pub, WRI_EADDR_TYPE_ANY);
	WRT_CHECK_U64(a.raw_len, wn);
	WRT_CHECK_MEM(a.raw, want, wn);
	WRT_CHECK_U64(a.type, 3);
	wri_eaddr_to_wr(&back, &a);
	WRT_CHECK_MEM(&back, &pub, sizeof(pub));

	/* junk in the unused ip bytes of an IPv4 wr_addr never reaches the wire */
	memset(pub.ip + 4, 0xFF, 12);
	wri_eaddr_from_wr(&a, &pub, WRI_EADDR_TYPE_ANY);
	WRT_CHECK_MEM(a.raw, want, wn);

	/* the wire family numbers (2, 10) are not the public ones (4, 6) */
	WRT_CHECK(WR_AF_IPV4 != 2u && WR_AF_IPV6 != 10u);
}

static void test_equality(void)
{
	static const uint8_t ip[4] = {10, 77, 0, 10};
	uint8_t w1[WRI_EADDR_MAX_WIRE], w2[WRI_EADDR_MAX_WIRE];
	wri_eaddr a, b;
	size_t n;

	n = v4_canon(w1, 2, 0, ip, 3300);
	WRT_CHECK_STATUS(WR_OK, dec1(w1, n, &a, NULL));
	WRT_CHECK_STATUS(WR_OK, dec1(w1, n, &b, NULL));
	WRT_CHECK(wri_eaddr_equal(&a, &b));
	WRT_CHECK(wri_eaddr_equal(&a, &a));
	n = v4_canon(w2, 1, 0, ip, 3300); /* type */
	WRT_CHECK_STATUS(WR_OK, dec1(w2, n, &b, NULL));
	WRT_CHECK(!wri_eaddr_equal(&a, &b));
	n = v4_canon(w2, 2, 1, ip, 3300); /* nonce */
	WRT_CHECK_STATUS(WR_OK, dec1(w2, n, &b, NULL));
	WRT_CHECK(!wri_eaddr_equal(&a, &b));
	n = v4_canon(w2, 2, 0, ip, 3301); /* port */
	WRT_CHECK_STATUS(WR_OK, dec1(w2, n, &b, NULL));
	WRT_CHECK(!wri_eaddr_equal(&a, &b));
	{
		static const uint8_t ip2[4] = {10, 77, 0, 11}; /* address */

		n = v4_canon(w2, 2, 0, ip2, 3300);
		WRT_CHECK_STATUS(WR_OK, dec1(w2, n, &b, NULL));
		WRT_CHECK(!wri_eaddr_equal(&a, &b));
	}
	WRT_CHECK(!wri_eaddr_equal(NULL, &a));
	WRT_CHECK(!wri_eaddr_equal(&a, NULL));
}

static void test_equality_follows_fields(void)
{
	static const uint8_t ip[4] = {10, 77, 0, 10};
	uint8_t w1[WRI_EADDR_MAX_WIRE];
	wri_eaddr a, b, z1, z2;
	size_t n = v4_canon(w1, 2, 7, ip, 3300);

	WRT_CHECK_STATUS(WR_OK, dec1(w1, n, &a, NULL));
	b = a;
	WRT_CHECK(wri_eaddr_equal(&a, &b));
	/* editing a typed field after decoding must show up even though raw is now stale */
	b.nonce = 8;
	WRT_CHECK(!wri_eaddr_equal(&a, &b));
	b = a;
	b.port = 3301;
	WRT_CHECK(!wri_eaddr_equal(&a, &b));
	b = a;
	b.ip[3] = 11;
	WRT_CHECK(!wri_eaddr_equal(&a, &b));
	b = a;
	b.type = WRI_EADDR_TYPE_LEGACY;
	WRT_CHECK(!wri_eaddr_equal(&a, &b));
	b = a;
	b.family = WR_AF_IPV6;
	WRT_CHECK(!wri_eaddr_equal(&a, &b));
	/* an edit that restores the original value is equal again */
	b = a;
	b.port = 1;
	b.port = a.port;
	WRT_CHECK(wri_eaddr_equal(&a, &b));
	/* hand-built structs with no raw (raw_len 0) are compared by their fields, not all-equal */
	memset(&z1, 0, sizeof(z1));
	memset(&z2, 0, sizeof(z2));
	z1.family = WR_AF_IPV4;
	z1.port = 1;
	z2.family = WR_AF_IPV4;
	z2.port = 2;
	WRT_CHECK(!wri_eaddr_equal(&z1, &z2));
	z2.port = 1;
	WRT_CHECK(wri_eaddr_equal(&z1, &z2));
	/* and a hand-built address equals the decoded one with the same fields */
	z1.type = 2;
	z1.nonce = 7;
	z1.port = 3300;
	memcpy(z1.ip, ip, 4);
	WRT_CHECK(wri_eaddr_equal(&z1, &a));
	/* junk in the unused ip bytes of an IPv4 address is not part of the address */
	memset(z1.ip + 4, 0xAA, 12);
	WRT_CHECK(wri_eaddr_equal(&z1, &a));
}

static void test_tampered_raw(void)
{
	/* raw is a cache: whatever it holds, the encoder never emits a malformed or out-of-range encoding */
	static const uint8_t ip6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5};
	uint8_t wire[WRI_EADDR_MAX_WIRE], enc[WRI_EADDR_MAX_WIRE], canon[WRI_EADDR_MAX_WIRE];
	size_t n = v6_canon(wire, 2, 1, ip6, 3300, 0x01020304u, 3), enc_len = 0, cn, i;
	wri_eaddr a, t;

	WRT_CHECK_STATUS(WR_OK, dec1(wire, n, &a, NULL));
	{ /* the plain canonical form for the same typed fields (no flowinfo / scope id) */
		wr_addr pub;
		wri_eaddr c;

		wri_eaddr_to_wr(&pub, &a);
		wri_eaddr_from_wr(&c, &pub, 2);
		cn = c.raw_len;
		memcpy(canon, c.raw, cn);
		WRT_CHECK_U64(cn, 47);
	}
	/* damaged caches: marker, elen, length, family; every one falls back to the typed fields */
	t = a;
	t.raw[0] = 0;
	WRT_CHECK_STATUS(WR_OK, enc1(&t, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, 47);
	WRT_CHECK(enc[0] == 1 && memcmp(enc + 21 + 2, "\0\0\0\0", 4) == 0);
	t = a;
	t.raw[15] = 29; /* elen above a sockaddr */
	WRT_CHECK_STATUS(WR_OK, enc1(&t, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, 47);
	WRT_CHECK(memcmp(enc + 19 + 2 + 2, "\0\0\0\0", 4) == 0);
	t = a;
	t.raw[15] = 1; /* elen below the family field */
	WRT_CHECK_STATUS(WR_OK, enc1(&t, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, 47);
	t = a;
	t.raw_len = 46; /* length that does not match elen */
	WRT_CHECK_STATUS(WR_OK, enc1(&t, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, 47);
	t = a;
	t.raw_len = 255; /* longer than the array */
	WRT_CHECK_STATUS(WR_OK, enc1(&t, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, 47);
	WRT_CHECK_MEM(enc, canon, 47);
	for (i = 0; i < 35; i++) { /* every too-short raw_len */
		t = a;
		t.raw_len = (uint8_t)i;
		WRT_CHECK_STATUS(WR_OK, enc1(&t, enc, sizeof(enc), &enc_len));
		WRT_CHECK_U64(enc_len, 47);
		WRT_CHECK_MEM(enc, canon, 47);
	}
	t = a;
	t.raw[19] = 2; /* raw says IPv4, fields say IPv6 */
	WRT_CHECK_STATUS(WR_OK, enc1(&t, enc, sizeof(enc), &enc_len));
	WRT_CHECK_MEM(enc, canon, 47);
	/* an unknown family number in the struct is written as a blank address, never as that number */
	t = a;
	t.family = 77;
	WRT_CHECK_STATUS(WR_OK, enc1(&t, enc, sizeof(enc), &enc_len));
	WRT_CHECK_U64(enc_len, 47);
	WRT_CHECK(enc[19] == 0 && enc[20] == 0);
}

static void test_conversion_null_args(void)
{
	wr_addr pub;
	wri_eaddr a;

	memset(&pub, 0, sizeof(pub));
	memset(&a, 0, sizeof(a));
	wri_eaddr_to_wr(NULL, &a);                       /* must not crash */
	wri_eaddr_from_wr(NULL, &pub, WRI_EADDR_TYPE_ANY); /* must not crash */
	memset(&pub, 0xFF, sizeof(pub));
	wri_eaddr_to_wr(&pub, NULL);
	WRT_CHECK_U64(pub.family, 0);
	WRT_CHECK_U64(pub.port, 0);
	WRT_CHECK_U64(pub.nonce, 0);
	memset(&a, 0xFF, sizeof(a));
	wri_eaddr_from_wr(&a, NULL, WRI_EADDR_TYPE_ANY);
	WRT_CHECK_U64(a.family, 0);
	WRT_CHECK_U64(a.raw_len, 47);
	WRT_CHECK_U64(a.type, 3);
}

/* ---- address vectors ---------------------------------------------------------------------- */

/* marker 2, count, then n canonical IPv4 addresses (port = 3300 + i) */
static size_t build_vec(uint8_t *o, uint32_t count, uint32_t entries)
{
	size_t n = 0;
	uint32_t i;
	uint8_t ip[4] = {10, 77, 0, 10};

	o[n++] = 2;
	put32(o + n, count), n += 4;
	for (i = 0; i < entries; i++) {
		ip[3] = (uint8_t)(10 + i);
		n += v4_canon(o + n, (i & 1) ? 1u : 2u, i, ip, (uint16_t)(3300 + i));
	}
	return n;
}

static wr_status vdec(const uint8_t *wire, size_t n, wri_eaddr *out, size_t max, size_t *stored, size_t *total,
		      size_t *left)
{
	uint8_t *buf = dup_bytes(wire, n);
	wri_rd r;
	wr_status st;

	wri_rd_init(&r, buf, n);
	st = wri_eaddrvec_decode(&r, out, max, stored, total);
	if (left)
		*left = wri_rd_left(&r);
	free(buf);
	return st;
}

static void test_vec_basic(void)
{
	uint8_t wire[5 + 35 * 4];
	size_t n = build_vec(wire, 3, 3), stored = 9, total = 9, left = 9, i;
	wri_eaddr a[WRI_EADDRVEC_MAX];

	WRT_CHECK_STATUS(WR_OK, vdec(wire, n, a, WRI_EADDRVEC_MAX, &stored, &total, &left));
	WRT_CHECK_U64(stored, 3);
	WRT_CHECK_U64(total, 3);
	WRT_CHECK_U64(left, 0);
	for (i = 0; i < 3; i++) {
		WRT_CHECK_U64(a[i].port, 3300 + i);
		WRT_CHECK_U64(a[i].nonce, i);
		WRT_CHECK_U64(a[i].ip[3], 10 + i);
		WRT_CHECK_U64(a[i].type, (i & 1) ? 1 : 2);
	}
	/* re-encode */
	{
		uint8_t enc[5 + 35 * 4];
		wri_wr w;

		wri_wr_init(&w, enc, sizeof(enc));
		wri_eaddrvec_encode(&w, a, 3);
		WRT_CHECK(wri_wr_ok(&w));
		WRT_CHECK_U64(wri_wr_len(&w), n);
		WRT_CHECK_MEM(enc, wire, n);
	}
	/* empty vector */
	n = build_vec(wire, 0, 0);
	WRT_CHECK_STATUS(WR_OK, vdec(wire, n, a, WRI_EADDRVEC_MAX, &stored, &total, &left));
	WRT_CHECK_U64(stored, 0);
	WRT_CHECK_U64(total, 0);
	WRT_CHECK_U64(left, 0);
}

static void test_vec_more_than_max(void)
{
	uint8_t wire[5 + 35 * 4];
	size_t n = build_vec(wire, 4, 4), stored, total, left;
	wri_eaddr a[2];

	memset(a, 0, sizeof(a));
	WRT_CHECK_STATUS(WR_OK, vdec(wire, n, a, 2, &stored, &total, &left));
	WRT_CHECK_U64(stored, 2);
	WRT_CHECK_U64(total, 4);
	WRT_CHECK_U64(left, 0); /* all four were consumed */
	WRT_CHECK_U64(a[1].port, 3301);

	/* max 0: nothing stored (out may be NULL), the count is still reported */
	WRT_CHECK_STATUS(WR_OK, vdec(wire, n, NULL, 0, &stored, &total, &left));
	WRT_CHECK_U64(stored, 0);
	WRT_CHECK_U64(total, 4);
	WRT_CHECK_U64(left, 0);

	/* out == NULL with max > 0 is a caller bug */
	WRT_CHECK_STATUS(WR_E_INVAL, vdec(wire, n, NULL, 2, &stored, &total, &left));

	/* NULL count pointers are accepted */
	WRT_CHECK_STATUS(WR_OK, vdec(wire, n, a, 2, NULL, NULL, &left));

	/* a malformed entry beyond `max` is still an error */
	{
		uint8_t bad[5 + 35 * 4];

		memcpy(bad, wire, n);
		bad[5 + 35 * 3 + 2] = 5; /* last entry: struct_compat 5 */
		WRT_CHECK_STATUS(WR_E_UNSUPPORTED, vdec(bad, n, a, 2, &stored, &total, &left));
		WRT_CHECK_U64(stored, 0);
		WRT_CHECK_U64(total, 0);
	}
}

static void test_vec_count_cap(void)
{
	uint8_t wire[5 + 35 * 17];
	size_t n, stored, total, left, i;
	wri_eaddr a[WRI_EADDRVEC_MAX];

	/* exactly 16: accepted, 8 stored */
	n = build_vec(wire, 16, 16);
	WRT_CHECK_STATUS(WR_OK, vdec(wire, n, a, WRI_EADDRVEC_MAX, &stored, &total, &left));
	WRT_CHECK_U64(stored, 8);
	WRT_CHECK_U64(total, 16);
	WRT_CHECK_U64(left, 0);
	for (i = 0; i < 8; i++)
		WRT_CHECK_U64(a[i].port, 3300 + i);

	/* 17: over the cap even though every entry is there */
	n = build_vec(wire, 17, 17);
	WRT_CHECK_STATUS(WR_E_TOOBIG, vdec(wire, n, a, WRI_EADDRVEC_MAX, &stored, &total, &left));
	WRT_CHECK_U64(stored, 0);
	WRT_CHECK_U64(total, 0);

	/* hostile counts with almost no data */
	n = build_vec(wire, 0xFFFFFFFFu, 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, vdec(wire, n, a, WRI_EADDRVEC_MAX, &stored, &total, &left));
	n = build_vec(wire, 16, 2); /* claims 16, carries 2 */
	WRT_CHECK_STATUS(WR_E_TOOBIG, vdec(wire, n, a, WRI_EADDRVEC_MAX, &stored, &total, &left));
}

static void test_vec_marker1_shared(void)
{
	/* marker 1: the versioned body of one entity_addr_t follows directly */
	static const uint8_t ip[4] = {10, 77, 0, 10};
	uint8_t one[WRI_EADDR_MAX_WIRE], wire[WRI_EADDR_MAX_WIRE];
	size_t n = v4_canon(one, 2, 3, ip, 3300), stored = 9, total = 9, left = 9;
	wri_eaddr a[2], direct;

	memcpy(wire, one, n); /* the leading marker byte (1) is the shared one */
	WRT_CHECK_STATUS(WR_OK, vdec(wire, n, a, 2, &stored, &total, &left));
	WRT_CHECK_U64(stored, 1);
	WRT_CHECK_U64(total, 1);
	WRT_CHECK_U64(left, 0);
	WRT_CHECK_STATUS(WR_OK, dec1(one, n, &direct, NULL));
	WRT_CHECK(wri_eaddr_equal(&a[0], &direct));
	WRT_CHECK_U64(a[0].raw_len, 35);

	WRT_CHECK_STATUS(WR_OK, vdec(wire, n, NULL, 0, &stored, &total, &left));
	WRT_CHECK_U64(stored, 0);
	WRT_CHECK_U64(total, 1);
}

static void test_vec_reject(void)
{
	uint8_t wire[5 + 35 * 2];
	size_t n = build_vec(wire, 2, 2), stored, total, left, k;
	wri_eaddr a[4];

	wire[0] = 0;
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, vdec(wire, n, a, 4, &stored, &total, &left));
	wire[0] = 3;
	WRT_CHECK_STATUS(WR_E_ENCODING, vdec(wire, n, a, 4, &stored, &total, &left));
	wire[0] = 255;
	WRT_CHECK_STATUS(WR_E_ENCODING, vdec(wire, n, a, 4, &stored, &total, &left));
	wire[0] = 2;

	/* an entry with the legacy marker 0 inside a marker-2 vector */
	wire[5] = 0;
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, vdec(wire, n, a, 4, &stored, &total, &left));
	WRT_CHECK_U64(stored, 0);
	WRT_CHECK_U64(total, 0);
	wire[5] = 1;

	/* every truncation, for both forms */
	for (k = 0; k < n; k++)
		WRT_CHECK(vdec(wire, k, a, 4, &stored, &total, &left) != WR_OK);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, vdec(wire, 0, a, 4, &stored, &total, &left));
	{
		uint8_t one[WRI_EADDR_MAX_WIRE];
		static const uint8_t ip[4] = {1, 2, 3, 4};
		size_t on = v4_canon(one, 2, 0, ip, 1);

		for (k = 0; k < on; k++)
			WRT_CHECK_STATUS(WR_E_TRUNCATED, vdec(one, k, a, 4, &stored, &total, &left));
	}
	/* the first entries stored before a late failure are cleared again */
	{
		static const uint8_t zero[sizeof(wri_eaddr)] = {0};

		WRT_CHECK_STATUS(WR_E_TRUNCATED, vdec(wire, n - 1, a, 4, &stored, &total, &left));
		WRT_CHECK_MEM(&a[0], zero, sizeof(a[0]));
	}
}

static void test_vec_args(void)
{
	static const uint8_t ip[4] = {10, 77, 0, 10};
	uint8_t wire[5 + 35];
	uint8_t *buf;
	size_t n = 0, stored = 9, total = 9;
	wri_eaddr out[2];
	wri_rd r;

	wire[n++] = 2;
	put32(wire + n, 1), n += 4;
	n += v4_canon(wire + n, 2, 0, ip, 3300);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_eaddrvec_decode(NULL, out, 2, &stored, &total));
	WRT_CHECK_U64(stored, 0);
	WRT_CHECK_U64(total, 0);
	buf = dup_bytes(wire, n);
	wri_rd_init(&r, buf, n);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_eaddrvec_decode(&r, NULL, 2, &stored, &total)); /* capacity without memory */
	free(buf);
	/* the result counters are optional, and a capacity of 0 just counts */
	buf = dup_bytes(wire, n);
	wri_rd_init(&r, buf, n);
	WRT_CHECK_STATUS(WR_OK, wri_eaddrvec_decode(&r, NULL, 0, NULL, NULL));
	WRT_CHECK_U64(wri_rd_left(&r), 0);
	free(buf);
	buf = dup_bytes(wire, n);
	wri_rd_init(&r, buf, n);
	WRT_CHECK_STATUS(WR_OK, wri_eaddrvec_decode(&r, NULL, 0, &stored, &total));
	WRT_CHECK_U64(stored, 0);
	WRT_CHECK_U64(total, 1);
	free(buf);
	/* a reader that already failed keeps its error and reports nothing */
	buf = dup_bytes(wire, n);
	wri_rd_init(&r, buf, n);
	wri_rd_fail(&r, WR_E_ENCODING);
	stored = total = 9;
	WRT_CHECK_STATUS(WR_E_ENCODING, wri_eaddrvec_decode(&r, out, 2, &stored, &total));
	WRT_CHECK_U64(stored, 0);
	WRT_CHECK_U64(total, 0);
	free(buf);
}

static void test_vec_encode_limits(void)
{
	wri_eaddr a[17];
	wr_addr pub;
	uint8_t out[5 + 35 * 17];
	wri_wr w;
	size_t i;

	memset(&pub, 0, sizeof(pub));
	pub.family = WR_AF_IPV4;
	for (i = 0; i < 17; i++) {
		pub.port = (uint16_t)(i + 1);
		wri_eaddr_from_wr(&a[i], &pub, WRI_EADDR_TYPE_MSGR2);
	}
	wri_wr_init(&w, out, sizeof(out));
	wri_eaddrvec_encode(&w, a, 17);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	wri_wr_init(&w, out, sizeof(out));
	wri_eaddrvec_encode(&w, a, 16);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(wri_wr_len(&w), 5 + 35 * 16);
	wri_wr_init(&w, out, 5 + 35 * 16 - 1);
	wri_eaddrvec_encode(&w, a, 16);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	wri_wr_init(&w, out, sizeof(out));
	wri_eaddrvec_encode(&w, NULL, 1);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	wri_wr_init(&w, out, sizeof(out));
	wri_eaddrvec_encode(&w, NULL, 0);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(wri_wr_len(&w), 5);
	WRT_CHECK_U64(out[0], 2);
}

/* ---- mutation loop ------------------------------------------------------------------------ */

static uint32_t rng_state = 0x1234ABCDu;

static uint32_t rng(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

static void test_mutation_stable(void)
{
	static const uint8_t ip6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	static const uint8_t ip4[4] = {10, 77, 0, 10};
	uint8_t base[3][WRI_EADDR_MAX_WIRE];
	size_t base_n[3];
	unsigned it, accepted = 0;

	base_n[0] = v4_canon(base[0], 2, 9, ip4, 3300);
	base_n[1] = v6_canon(base[1], 1, 9, ip6, 6800, 5, 6);
	base_n[2] = blank_canon(base[2], 0, 0);
	for (it = 0; it < 60000; it++) {
		unsigned which = rng() % 3, flips = 1 + rng() % 3, f;
		uint8_t wire[WRI_EADDR_MAX_WIRE + 4];
		size_t n = base_n[which];
		wri_eaddr a, b;
		uint8_t enc[WRI_EADDR_MAX_WIRE];
		size_t enc_len = 0;

		memcpy(wire, base[which], n);
		for (f = 0; f < flips; f++)
			wire[rng() % n] = (uint8_t)rng();
		if (rng() % 4 == 0)
			n = rng() % (n + 1); /* also try cut-off inputs */
		if (dec1(wire, n, &a, NULL) != WR_OK)
			continue;
		accepted++;
		/* decode -> encode succeeds, the result decodes to the same address, and is canonical */
		WRT_CHECK_STATUS(WR_OK, enc1(&a, enc, sizeof(enc), &enc_len));
		WRT_CHECK(enc_len == a.raw_len && memcmp(enc, a.raw, enc_len) == 0);
		WRT_CHECK_STATUS(WR_OK, dec1(enc, enc_len, &b, NULL));
		WRT_CHECK(wri_eaddr_equal(&a, &b));
		WRT_CHECK(a.type == b.type && a.nonce == b.nonce && a.family == b.family && a.port == b.port &&
			  memcmp(a.ip, b.ip, 16) == 0);
	}
	WRT_CHECK(accepted > 1000); /* the mutations must exercise the accept path, not only rejections */
}

int main(void)
{
	test_monmap_addrvec();
	test_frames();
	test_ipv4_canonical();
	test_ipv6_round_trip();
	test_ipv6_flowinfo_scope_kept();
	test_ipv4_reserved_bytes_kept();
	test_blank();
	test_short_elen();
	test_struct_v_and_trailing();
	test_reject_markers();
	test_reject_compat();
	test_reject_elen();
	test_reject_family();
	test_every_truncation();
	test_decode_sticky_and_args();
	test_encode_overflow();
	test_from_wr_to_wr();
	test_equality();
	test_equality_follows_fields();
	test_tampered_raw();
	test_conversion_null_args();
	test_vec_basic();
	test_vec_more_than_max();
	test_vec_count_cap();
	test_vec_marker1_shared();
	test_vec_reject();
	test_vec_args();
	test_vec_encode_limits();
	test_mutation_stable();
	return wrt_finish();
}
