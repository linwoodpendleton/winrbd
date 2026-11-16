/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of core/src/msgr2/wri_m2_ctl.c and wri_m2_hdr2.c (control-frame payloads and the
 * 41-byte ceph_msg_header2; msgr2.md 2.7, 2.9).
 *
 *  - segment 0 of the control frames in msgr2/frames-crc.json (HELLO, AUTH_REQUEST, AUTH_REPLY_MORE,
 *    AUTH_REQUEST_MORE, AUTH_DONE, AUTH_SIGNATURE, CLIENT_IDENT, SERVER_IDENT, AUTH_BAD_METHOD,
 *    IDENT_MISSING_FEATURES, KEEPALIVE2 / _ACK) decode to the documented fields, and the encoders
 *    reproduce the bytes (also into every too-small buffer: sticky WR_E_TOOBIG, no write past cap);
 *  - header2 of the MESSAGE frames and of the monclient vectors (header2_hex);
 *  - every truncation point, trailing bytes, count and blob caps, AUTH_BAD_METHOD with more entries
 *    than are stored, SERVER_IDENT with more addresses than are stored, NULL arguments.
 *
 * Every buffer handed to a decoder or encoder is an exact-size heap block so ASan sees any overrun.
 */
#include "wrt.h"

#include "wri_m2_ctl.h"

/* ---- helpers ------------------------------------------------------------------------------ */

static uint8_t *xalloc(size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n ? n : 1);

	if (!q) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	return q;
}

static uint8_t *dup_bytes(const uint8_t *p, size_t n)
{
	uint8_t *q = xalloc(n);

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

static uint64_t get64(const uint8_t *p)
{
	uint64_t v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = (v << 8) | p[i];
	return v;
}

static uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int is_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i])
			return 0;
	return 1;
}

/* ---- the frame vectors -------------------------------------------------------------------- */

static wrt_json J;

struct fr {
	uint8_t *hex; /* the whole frame */
	size_t seg0_len;
	const uint8_t *seg0; /* hex + 32 */
	wrt_tok fields;
};

static int find_frame(const char *name, struct fr *f)
{
	wrt_tok frames = wrt_json_get(&J, wrt_json_root(&J), "frames");
	size_t i, n = wrt_json_count(&J, frames);

	for (i = 0; i < n; i++) {
		wrt_tok t = wrt_json_at(&J, frames, i);
		char *nm = wrt_json_strdup(&J, wrt_json_get(&J, t, "name"));
		int hit = nm != NULL && strcmp(nm, name) == 0;
		size_t hn = 0;
		int ok = 0;

		free(nm);
		if (!hit)
			continue;
		f->fields = wrt_json_get(&J, t, "fields");
		if (wrt_json_get_hex(&J, t, "hex", &f->hex, &hn) != 0)
			return -1;
		f->seg0_len = (size_t)wrt_json_int(&J, wrt_json_at(&J, wrt_json_get(&J, t, "segment_lengths"), 0), &ok);
		f->seg0 = f->hex + 32;
		return (ok && hn >= 32 + f->seg0_len) ? 0 : -1;
	}
	return -1;
}

static int jget_int(wrt_tok obj, const char *key, int64_t *v)
{
	int ok = 0;
	wrt_tok t = wrt_json_get(&J, obj, key);

	*v = (t == WRT_NONE) ? 0 : wrt_json_int(&J, t, &ok);
	return ok;
}

#define NEED_FRAME(f, name)                                                                       \
	do {                                                                                      \
		if (find_frame((name), &(f)) != 0) {                                              \
			fprintf(stderr, "%s:%d: frame %s missing in frames-crc.json\n", __FILE__,  \
				__LINE__, (name));                                                \
			wrt_failures++;                                                           \
			return;                                                                   \
		}                                                                                 \
	} while (0)

/* ---- generic sweeps ----------------------------------------------------------------------- */

typedef wr_status (*dec_fn)(const uint8_t *p, size_t n);

/*
 * Prefixes 0..n-1 fail (WR_E_TRUNCATED when strict, any error otherwise), the whole payload
 * decodes, and one extra byte is WR_E_ENCODING.
 */
static void sweep(const char *what, dec_fn dec, const uint8_t *p, size_t n, int strict)
{
	size_t k;
	uint8_t *buf;

	for (k = 0; k < n; k++) {
		wr_status st;

		buf = dup_bytes(p, k);
		st = dec(buf, k);
		free(buf);
		if (strict ? st != WR_E_TRUNCATED : st == WR_OK) {
			wrt_failures++;
			fprintf(stderr, "%s: prefix %zu of %zu gave %d\n", what, k, n, (int)st);
		}
		wrt_checks++;
	}
	buf = dup_bytes(p, n);
	WRT_CHECK_STATUS(WR_OK, dec(buf, n));
	free(buf);
	buf = xalloc(n + 1);
	memcpy(buf, p, n);
	buf[n] = 0;
	WRT_CHECK_STATUS(WR_E_ENCODING, dec(buf, n + 1));
	free(buf);
}

static wr_status dec_hello(const uint8_t *p, size_t n)
{
	wri_m2_hello h;
	wri_rd r;
	wr_status st;

	wri_rd_init(&r, p, n);
	st = wri_m2_hello_decode(&r, &h);
	if (st != WR_OK)
		WRT_CHECK(is_zero(&h, sizeof(h)));
	return st;
}

static wr_status dec_bad(const uint8_t *p, size_t n)
{
	wri_m2_bad_method b;
	wri_rd r;
	wr_status st;

	wri_rd_init(&r, p, n);
	st = wri_m2_bad_method_decode(&r, &b);
	if (st != WR_OK)
		WRT_CHECK(is_zero(&b, sizeof(b)));
	return st;
}

static wr_status dec_more(const uint8_t *p, size_t n)
{
	const uint8_t *pl = p;
	uint32_t len = 77;
	wri_rd r;
	wr_status st;

	wri_rd_init(&r, p, n);
	st = wri_m2_auth_more_decode(&r, &pl, &len);
	if (st != WR_OK)
		WRT_CHECK(pl == NULL && len == 0);
	return st;
}

static wr_status dec_done(const uint8_t *p, size_t n)
{
	wri_m2_auth_done d;
	wri_rd r;
	wr_status st;

	wri_rd_init(&r, p, n);
	st = wri_m2_auth_done_decode(&r, &d);
	if (st != WR_OK)
		WRT_CHECK(is_zero(&d, sizeof(d)));
	return st;
}

static wr_status dec_sig(const uint8_t *p, size_t n)
{
	uint8_t sig[32];
	wri_rd r;
	wr_status st;

	memset(sig, 0xEE, sizeof(sig));
	wri_rd_init(&r, p, n);
	st = wri_m2_auth_sig_decode(&r, sig);
	if (st != WR_OK)
		WRT_CHECK(is_zero(sig, sizeof(sig)));
	return st;
}

static wr_status dec_sident(const uint8_t *p, size_t n)
{
	wri_m2_server_ident s;
	wri_rd r;
	wr_status st;

	wri_rd_init(&r, p, n);
	st = wri_m2_server_ident_decode(&r, &s);
	if (st != WR_OK)
		WRT_CHECK(is_zero(&s, sizeof(s)));
	return st;
}

static wr_status dec_u64(const uint8_t *p, size_t n)
{
	uint64_t v = 5;
	wri_rd r;
	wr_status st;

	wri_rd_init(&r, p, n);
	st = wri_m2_u64_decode(&r, &v);
	if (st != WR_OK)
		WRT_CHECK(v == 0);
	return st;
}

static wr_status dec_ka(const uint8_t *p, size_t n)
{
	uint32_t s = 5, ns = 6;
	wri_rd r;
	wr_status st;

	wri_rd_init(&r, p, n);
	st = wri_m2_keepalive_decode(&r, &s, &ns);
	if (st != WR_OK)
		WRT_CHECK(s == 0 && ns == 0);
	return st;
}

typedef void (*enc_fn)(wri_wr *w, const void *ctx);

/* Encode into an exact-size buffer and compare; into every smaller buffer: WR_E_TOOBIG, no overrun. */
static void enc_vs(const char *what, enc_fn f, const void *ctx, const uint8_t *want, size_t n)
{
	size_t cap;

	for (cap = 0; cap <= n; cap++) {
		uint8_t *buf = xalloc(cap);
		wri_wr w;

		wri_wr_init(&w, buf, cap);
		f(&w, ctx);
		if (cap == n) {
			WRT_CHECK(wri_wr_ok(&w));
			WRT_CHECK(wri_wr_len(&w) == n);
			if (wri_wr_len(&w) == n)
				wrt_check_mem_(__FILE__, __LINE__, what, buf, want, n);
		} else {
			wrt_checks++;
			if (w.err != WR_E_TOOBIG || w.pos > cap) {
				wrt_failures++;
				fprintf(stderr, "%s: cap %zu of %zu: err %d pos %zu\n", what, cap, n,
					(int)w.err, w.pos);
			}
		}
		free(buf);
	}
}

/* ---- address helper ----------------------------------------------------------------------- */

static void check_addr_json(const wri_eaddr *a, wrt_tok t)
{
	int64_t v;
	char *ip = wrt_json_strdup(&J, wrt_json_get(&J, t, "ip"));
	unsigned b[4] = {0, 0, 0, 0};
	uint8_t *hex = NULL;
	size_t hn = 0;

	WRT_CHECK(jget_int(t, "type", &v) && a->type == (uint32_t)v);
	WRT_CHECK(jget_int(t, "nonce", &v) && a->nonce == (uint32_t)v);
	WRT_CHECK(jget_int(t, "family", &v) && v == 2 && a->family == WR_AF_IPV4);
	WRT_CHECK(jget_int(t, "port", &v) && a->port == (uint16_t)v);
	WRT_CHECK(ip != NULL && sscanf(ip, "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]) == 4);
	WRT_CHECK(a->ip[0] == b[0] && a->ip[1] == b[1] && a->ip[2] == b[2] && a->ip[3] == b[3]);
	WRT_CHECK(wrt_json_get_hex(&J, t, "hex", &hex, &hn) == 0 && hn == a->raw_len);
	if (hex && hn == a->raw_len)
		WRT_CHECK_MEM(a->raw, hex, hn);
	free(ip);
	free(hex);
}

/* ---- HELLO -------------------------------------------------------------------------------- */

static void enc_hello(wri_wr *w, const void *c) { wri_m2_hello_encode(w, (const wri_m2_hello *)c); }

static void test_hello(void)
{
	static const char *const names[] = {"mon-hello-client", "mon-hello-server"};
	size_t i;

	for (i = 0; i < 2; i++) {
		struct fr f;
		wri_m2_hello h;
		wri_rd r;
		int64_t v;
		uint8_t *seg;

		NEED_FRAME(f, names[i]);
		seg = dup_bytes(f.seg0, f.seg0_len);
		wri_rd_init(&r, seg, f.seg0_len);
		WRT_CHECK_STATUS(WR_OK, wri_m2_hello_decode(&r, &h));
		WRT_CHECK(jget_int(f.fields, "entity_type", &v) && h.entity_type == (uint8_t)v);
		check_addr_json(&h.peer_addr, wrt_json_get(&J, f.fields, "peer_addr"));
		enc_vs(names[i], enc_hello, &h, seg, f.seg0_len);
		sweep(names[i], dec_hello, seg, f.seg0_len, 1);
		free(seg);
		free(f.hex);
	}
	WRT_CHECK(WRI_ENTITY_CLIENT == 8 && WRI_ENTITY_MON == 1 && WRI_ENTITY_OSD == 4);
}

/* ---- AUTH_REQUEST ------------------------------------------------------------------------- */

struct areq {
	uint32_t method;
	uint32_t modes[20];
	size_t nmodes;
	const uint8_t *payload;
	size_t plen;
};

static void enc_areq(wri_wr *w, const void *c)
{
	const struct areq *a = (const struct areq *)c;

	wri_m2_auth_request_encode(w, a->method, a->modes, a->nmodes, a->payload, a->plen);
}

static void test_auth_request(void)
{
	static const char *const names[] = {"mon-auth-request", "osd-auth-request-authorizer"};
	size_t i;

	for (i = 0; i < 2; i++) {
		struct fr f;
		struct areq a;
		int64_t v;
		uint8_t *seg;
		wrt_tok modes;
		wrt_tok pl;
		size_t plen;

		NEED_FRAME(f, names[i]);
		seg = dup_bytes(f.seg0, f.seg0_len);
		/* method u32, count u32 (1), mode u32, blob len u32, blob: pulled apart by hand. */
		WRT_CHECK(get32(seg) == 2 && get32(seg + 4) == 1 && get32(seg + 8) == 1);
		plen = get32(seg + 12);
		WRT_CHECK(f.seg0_len == 16 + plen);
		a.method = get32(seg);
		modes = wrt_json_get(&J, f.fields, "modes");
		a.nmodes = wrt_json_count(&J, modes);
		WRT_CHECK(a.nmodes == 1);
		a.modes[0] = (uint32_t)wrt_json_int(&J, wrt_json_at(&J, modes, 0), &(int){0});
		a.payload = seg + 16;
		a.plen = plen;
		WRT_CHECK(jget_int(f.fields, "method", &v) && a.method == (uint32_t)v);
		pl = wrt_json_get(&J, f.fields, "payload");
		{
			int64_t jl;
			uint8_t *ph = NULL;
			size_t phn = 0;

			if (jget_int(pl, "len", &jl))
				WRT_CHECK((size_t)jl == plen);
			else if (wrt_json_get_hex(&J, pl, "hex", &ph, &phn) == 0) {
				WRT_CHECK(phn == plen);
				if (phn == plen)
					WRT_CHECK_MEM(a.payload, ph, plen);
			} else
				WRT_CHECK(0);
			free(ph);
		}
		enc_vs(names[i], enc_areq, &a, seg, f.seg0_len);
		free(seg);
		free(f.hex);
	}
}

static void test_auth_request_caps(void)
{
	struct areq a;
	uint8_t big[WRI_M2_AUTH_BLOB_MAX + 1];
	uint8_t *out = xalloc(sizeof(big) + 128);
	wri_wr w;
	size_t i;

	memset(&a, 0, sizeof(a));
	memset(big, 0x41, sizeof(big));
	for (i = 0; i < 20; i++)
		a.modes[i] = (uint32_t)i;
	/* exactly the limits */
	a.nmodes = WRI_M2_VEC_WIRE_MAX;
	a.payload = big;
	a.plen = WRI_M2_AUTH_BLOB_MAX;
	wri_wr_init(&w, out, sizeof(big) + 128);
	enc_areq(&w, &a);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK(wri_wr_len(&w) == 4 + 4 + 4 * WRI_M2_VEC_WIRE_MAX + 4 + WRI_M2_AUTH_BLOB_MAX);
	/* one past */
	a.nmodes = WRI_M2_VEC_WIRE_MAX + 1;
	a.plen = 0;
	wri_wr_init(&w, out, sizeof(big) + 128);
	enc_areq(&w, &a);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	a.nmodes = 0;
	a.plen = WRI_M2_AUTH_BLOB_MAX + 1;
	wri_wr_init(&w, out, sizeof(big) + 128);
	enc_areq(&w, &a);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	/* NULL data with a non-zero length */
	a.plen = 5;
	a.payload = NULL;
	wri_wr_init(&w, out, 64);
	enc_areq(&w, &a);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	a.plen = 0;
	a.nmodes = 2;
	wri_wr_init(&w, out, 64);
	wri_m2_auth_request_encode(&w, 2, NULL, 2, NULL, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	/* empty everything is legal: method + two zero lengths */
	wri_wr_init(&w, out, 64);
	wri_m2_auth_request_encode(&w, 2, NULL, 0, NULL, 0);
	WRT_CHECK(wri_wr_ok(&w) && wri_wr_len(&w) == 12);
	wri_m2_auth_request_encode(NULL, 2, NULL, 0, NULL, 0); /* must not crash */
	free(out);
}

/* ---- AUTH_REPLY_MORE / AUTH_REQUEST_MORE -------------------------------------------------- */

struct more {
	const uint8_t *p;
	size_t n;
};

static void enc_more(wri_wr *w, const void *c)
{
	const struct more *m = (const struct more *)c;

	wri_m2_auth_more_encode(w, m->p, m->n);
}

static void test_auth_more(void)
{
	static const char *const names[] = {"mon-auth-reply-more", "osd-auth-reply-more-challenge",
					    "mon-auth-request-more", "osd-auth-request-more-authorizer"};
	size_t i;

	for (i = 0; i < 4; i++) {
		struct fr f;
		wri_rd r;
		const uint8_t *pl = NULL;
		uint32_t len = 0;
		uint8_t *seg;
		wrt_tok p;
		int64_t jl;
		uint8_t *ph = NULL;
		size_t phn = 0;
		struct more m;

		NEED_FRAME(f, names[i]);
		seg = dup_bytes(f.seg0, f.seg0_len);
		wri_rd_init(&r, seg, f.seg0_len);
		WRT_CHECK_STATUS(WR_OK, wri_m2_auth_more_decode(&r, &pl, &len));
		WRT_CHECK(len + 4 == f.seg0_len && pl == seg + 4);
		p = wrt_json_get(&J, f.fields, "payload");
		if (jget_int(p, "len", &jl))
			WRT_CHECK((uint32_t)jl == len);
		else if (wrt_json_get_hex(&J, p, "hex", &ph, &phn) == 0) {
			/* the JSON may show only a prefix of a long blob */
			WRT_CHECK(phn <= len);
			if (phn <= len)
				WRT_CHECK_MEM(pl, ph, phn);
		} else
			WRT_CHECK(0);
		free(ph);
		m.p = pl;
		m.n = len;
		enc_vs(names[i], enc_more, &m, seg, f.seg0_len);
		sweep(names[i], dec_more, seg, f.seg0_len, 1);
		free(seg);
		free(f.hex);
	}
}

static void test_auth_more_caps(void)
{
	uint8_t hdr[4];
	uint8_t *big;
	wri_rd r;
	const uint8_t *pl;
	uint32_t len;
	uint8_t *buf;

	/* length field over the cap: refused before looking at the data */
	put32(hdr, WRI_M2_AUTH_BLOB_MAX + 1);
	buf = dup_bytes(hdr, 4);
	wri_rd_init(&r, buf, 4);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_auth_more_decode(&r, &pl, &len));
	free(buf);
	put32(hdr, 0xFFFFFFFFu);
	buf = dup_bytes(hdr, 4);
	wri_rd_init(&r, buf, 4);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_auth_more_decode(&r, &pl, &len));
	free(buf);
	/* length exactly at the cap with the data present */
	big = xalloc(4 + WRI_M2_AUTH_BLOB_MAX);
	put32(big, WRI_M2_AUTH_BLOB_MAX);
	memset(big + 4, 0x5A, WRI_M2_AUTH_BLOB_MAX);
	wri_rd_init(&r, big, 4 + WRI_M2_AUTH_BLOB_MAX);
	WRT_CHECK_STATUS(WR_OK, wri_m2_auth_more_decode(&r, &pl, &len));
	WRT_CHECK(len == WRI_M2_AUTH_BLOB_MAX && pl == big + 4);
	/* length at the cap, data missing: truncated, not toobig */
	wri_rd_init(&r, big, 4 + 100);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_m2_auth_more_decode(&r, &pl, &len));
	free(big);
	/* empty blob */
	put32(hdr, 0);
	buf = dup_bytes(hdr, 4);
	wri_rd_init(&r, buf, 4);
	WRT_CHECK_STATUS(WR_OK, wri_m2_auth_more_decode(&r, &pl, &len));
	WRT_CHECK(len == 0);
	free(buf);
	/* NULL arguments */
	wri_rd_init(&r, hdr, 4);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_auth_more_decode(NULL, &pl, &len));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_auth_more_decode(&r, NULL, &len));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_auth_more_decode(&r, &pl, NULL));
}

/* ---- AUTH_DONE ---------------------------------------------------------------------------- */

static void enc_done(wri_wr *w, const void *c) { wri_m2_auth_done_encode(w, (const wri_m2_auth_done *)c); }

static void test_auth_done(void)
{
	static const char *const names[] = {"mon-auth-done", "osd-auth-done"};
	size_t i;

	for (i = 0; i < 2; i++) {
		struct fr f;
		wri_m2_auth_done d;
		wri_rd r;
		int64_t v;
		uint8_t *seg;
		wrt_tok p;
		uint8_t *ph = NULL;
		size_t phn = 0;

		NEED_FRAME(f, names[i]);
		seg = dup_bytes(f.seg0, f.seg0_len);
		wri_rd_init(&r, seg, f.seg0_len);
		WRT_CHECK_STATUS(WR_OK, wri_m2_auth_done_decode(&r, &d));
		WRT_CHECK(jget_int(f.fields, "global_id", &v) && d.global_id == (uint64_t)v);
		WRT_CHECK(jget_int(f.fields, "mode", &v) && d.mode == (uint32_t)v && d.mode == WRI_CONN_MODE_CRC);
		WRT_CHECK(d.payload == seg + 16 && d.payload_len + 16 == f.seg0_len);
		p = wrt_json_get(&J, f.fields, "payload");
		if (jget_int(p, "len", &v))
			WRT_CHECK((uint32_t)v == d.payload_len);
		else if (wrt_json_get_hex(&J, p, "hex", &ph, &phn) == 0) {
			WRT_CHECK(phn == d.payload_len);
			if (phn == d.payload_len)
				WRT_CHECK_MEM(d.payload, ph, phn);
		} else
			WRT_CHECK(0);
		free(ph);
		enc_vs(names[i], enc_done, &d, seg, f.seg0_len);
		sweep(names[i], dec_done, seg, f.seg0_len, 1);
		free(seg);
		free(f.hex);
	}
}

static void test_auth_done_caps(void)
{
	uint8_t b[16];
	wri_m2_auth_done d;
	wri_rd r;
	uint8_t *buf;

	memset(b, 0, sizeof(b));
	b[0] = 7;
	b[8] = 2;
	put32(b + 12, WRI_M2_AUTH_BLOB_MAX + 1);
	buf = dup_bytes(b, 16);
	wri_rd_init(&r, buf, 16);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_auth_done_decode(&r, &d));
	WRT_CHECK(is_zero(&d, sizeof(d)));
	free(buf);
	put32(b + 12, 0); /* empty payload is fine */
	buf = dup_bytes(b, 16);
	wri_rd_init(&r, buf, 16);
	WRT_CHECK_STATUS(WR_OK, wri_m2_auth_done_decode(&r, &d));
	WRT_CHECK(d.global_id == 7 && d.mode == 2 && d.payload_len == 0);
	free(buf);
	wri_rd_init(&r, b, 16);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_auth_done_decode(&r, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_auth_done_decode(NULL, &d));
}

/* ---- AUTH_SIGNATURE ----------------------------------------------------------------------- */

static void enc_sig(wri_wr *w, const void *c) { wri_m2_auth_sig_encode(w, (const uint8_t *)c); }

static void test_auth_sig(void)
{
	static const char *const names[] = {"mon-auth-signature-client", "mon-auth-signature-server"};
	size_t i;

	for (i = 0; i < 2; i++) {
		struct fr f;
		wri_rd r;
		uint8_t sig[32];
		uint8_t *seg;
		uint8_t *ph = NULL;
		size_t phn = 0;

		NEED_FRAME(f, names[i]);
		WRT_CHECK(f.seg0_len == 32);
		seg = dup_bytes(f.seg0, f.seg0_len);
		wri_rd_init(&r, seg, 32);
		WRT_CHECK_STATUS(WR_OK, wri_m2_auth_sig_decode(&r, sig));
		WRT_CHECK(wrt_json_hex(&J, wrt_json_get(&J, wrt_json_get(&J, f.fields, "sig"), "hex"), &ph, &phn) == 0 && phn == 32);
		if (ph && phn == 32)
			WRT_CHECK_MEM(sig, ph, 32);
		enc_vs(names[i], enc_sig, sig, seg, 32);
		sweep(names[i], dec_sig, seg, 32, 1);
		free(ph);
		free(seg);
		free(f.hex);
	}
}

/* ---- CLIENT_IDENT ------------------------------------------------------------------------- */

static void enc_cident(wri_wr *w, const void *c) { wri_m2_client_ident_encode(w, (const wri_m2_client_ident *)c); }

static void addr_from_json(wri_eaddr *a, wrt_tok t)
{
	uint8_t *hex = NULL;
	size_t hn = 0;
	wri_rd r;

	memset(a, 0, sizeof(*a));
	if (wrt_json_get_hex(&J, t, "hex", &hex, &hn) != 0) {
		WRT_CHECK(0);
		return;
	}
	wri_rd_init(&r, hex, hn);
	WRT_CHECK_STATUS(WR_OK, wri_eaddr_decode(&r, a));
	free(hex);
}

static void test_client_ident(void)
{
	static const char *const names[] = {"mon-client-ident-first-connection",
					    "mon-client-ident-lossless-intent", "osd-client-ident"};
	size_t i;

	for (i = 0; i < 3; i++) {
		struct fr f;
		wri_m2_client_ident c;
		int64_t v;
		wrt_tok addrs;

		NEED_FRAME(f, names[i]);
		memset(&c, 0, sizeof(c));
		addrs = wrt_json_get(&J, f.fields, "addrs");
		WRT_CHECK(wrt_json_count(&J, addrs) == 1);
		addr_from_json(&c.addrs[0], wrt_json_at(&J, addrs, 0));
		addr_from_json(&c.target, wrt_json_get(&J, f.fields, "target"));
		check_addr_json(&c.addrs[0], wrt_json_at(&J, addrs, 0));
		check_addr_json(&c.target, wrt_json_get(&J, f.fields, "target"));
		WRT_CHECK(jget_int(f.fields, "gid", &v));
		c.gid = v;
		WRT_CHECK(jget_int(f.fields, "global_seq", &v));
		c.global_seq = (uint64_t)v;
		WRT_CHECK(jget_int(f.fields, "supported", &v));
		c.supported = (uint64_t)v;
		WRT_CHECK(jget_int(f.fields, "required", &v));
		c.required = (uint64_t)v;
		WRT_CHECK(jget_int(f.fields, "flags", &v));
		c.flags = (uint64_t)v;
		WRT_CHECK(jget_int(f.fields, "cookie", &v));
		c.cookie = (uint64_t)v;
		enc_vs(names[i], enc_cident, &c, f.seg0, f.seg0_len);
		/* the tail of the segment is hand-checked: the six integers sit at the end */
		WRT_CHECK(get64(f.seg0 + f.seg0_len - 8) == c.cookie);
		WRT_CHECK(get64(f.seg0 + f.seg0_len - 16) == c.flags);
		free(f.hex);
	}
}

/* ---- SERVER_IDENT ------------------------------------------------------------------------- */

static void enc_sident(wri_wr *w, const void *c) { wri_m2_server_ident_encode(w, (const wri_m2_server_ident *)c); }

static void test_server_ident(void)
{
	static const char *const names[] = {"mon-server-ident", "mon-server-ident-answer-to-lossless-intent",
					    "osd-server-ident"};
	size_t i;

	for (i = 0; i < 3; i++) {
		struct fr f;
		wri_m2_server_ident s;
		wri_rd r;
		int64_t v;
		wrt_tok addrs;
		uint8_t *seg;
		size_t k;

		NEED_FRAME(f, names[i]);
		seg = dup_bytes(f.seg0, f.seg0_len);
		wri_rd_init(&r, seg, f.seg0_len);
		WRT_CHECK_STATUS(WR_OK, wri_m2_server_ident_decode(&r, &s));
		addrs = wrt_json_get(&J, f.fields, "addrs");
		WRT_CHECK(s.n_addrs == wrt_json_count(&J, addrs) && s.n_addrs == 2);
		for (k = 0; k < s.n_addrs; k++)
			check_addr_json(&s.addrs[k], wrt_json_at(&J, addrs, k));
		WRT_CHECK(jget_int(f.fields, "gid", &v) && s.gid == v);
		WRT_CHECK(jget_int(f.fields, "global_seq", &v) && s.global_seq == (uint64_t)v);
		WRT_CHECK(jget_int(f.fields, "supported", &v) && s.supported == (uint64_t)v);
		WRT_CHECK(jget_int(f.fields, "required", &v) && s.required == (uint64_t)v);
		WRT_CHECK(jget_int(f.fields, "flags", &v) && s.flags == (uint64_t)v);
		WRT_CHECK(jget_int(f.fields, "cookie", &v) && s.cookie == (uint64_t)v);
		enc_vs(names[i], enc_sident, &s, seg, f.seg0_len);
		sweep(names[i], dec_sident, seg, f.seg0_len, 0);
		free(seg);
		free(f.hex);
	}
}

/* addrvec with n canonical v4 addresses (port = 1000 + index), then the six integers. */
static size_t build_sident(uint8_t *out, size_t cap, uint32_t count_on_wire, size_t n_present)
{
	wri_wr w;
	size_t i;
	wri_eaddr a;
	wr_addr pub;

	wri_wr_init(&w, out, cap);
	wri_wr_u8(&w, 2);
	wri_wr_u32(&w, count_on_wire);
	for (i = 0; i < n_present; i++) {
		memset(&pub, 0, sizeof(pub));
		pub.family = WR_AF_IPV4;
		pub.ip[0] = 10;
		pub.ip[3] = (uint8_t)(i + 1);
		pub.port = (uint16_t)(1000 + i);
		wri_eaddr_from_wr(&a, &pub, WRI_EADDR_TYPE_MSGR2);
		wri_eaddr_encode(&w, &a);
	}
	wri_wr_i64(&w, -5);
	wri_wr_u64(&w, 1);
	wri_wr_u64(&w, 2);
	wri_wr_u64(&w, 3);
	wri_wr_u64(&w, 4);
	wri_wr_u64(&w, 5);
	return wri_wr_ok(&w) ? wri_wr_len(&w) : 0;
}

static void test_server_ident_caps(void)
{
	uint8_t big[16 * 47 + 64];
	size_t n;
	wri_m2_server_ident s;
	wri_rd r;
	uint8_t *buf;
	uint32_t cnt;

	/* 8 and fewer fit; 9..16 are accepted but only 8 are stored; 17 is refused. */
	for (cnt = 0; cnt <= 17; cnt++) {
		size_t i;

		n = build_sident(big, sizeof(big), cnt, cnt);
		WRT_CHECK(n != 0);
		buf = dup_bytes(big, n);
		wri_rd_init(&r, buf, n);
		if (cnt <= WRI_EADDRVEC_WIRE_MAX) {
			WRT_CHECK_STATUS(WR_OK, wri_m2_server_ident_decode(&r, &s));
			WRT_CHECK(s.n_addrs == (cnt < WRI_EADDRVEC_MAX ? cnt : WRI_EADDRVEC_MAX));
			for (i = 0; i < s.n_addrs; i++)
				WRT_CHECK(s.addrs[i].port == 1000 + i && s.addrs[i].ip[3] == i + 1);
			WRT_CHECK(s.gid == -5 && s.global_seq == 1 && s.supported == 2 && s.required == 3 &&
				  s.flags == 4 && s.cookie == 5);
		} else {
			WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_server_ident_decode(&r, &s));
			WRT_CHECK(is_zero(&s, sizeof(s)));
		}
		free(buf);
	}
	/* a hostile count with nothing behind it */
	{
		uint8_t h[5];

		h[0] = 2;
		put32(h + 1, 0xFFFFFFFFu);
		buf = dup_bytes(h, 5);
		wri_rd_init(&r, buf, 5);
		WRT_CHECK(wri_m2_server_ident_decode(&r, &s) != WR_OK);
		free(buf);
	}
	/* encoder keeps at most WRI_EADDRVEC_MAX entries */
	{
		wri_m2_server_ident full;
		uint8_t out[8 * 47 + 64];
		wri_wr w;

		memset(&full, 0, sizeof(full));
		full.n_addrs = 99;
		wri_wr_init(&w, out, sizeof(out));
		wri_m2_server_ident_encode(&w, &full);
		WRT_CHECK(wri_wr_ok(&w));
		WRT_CHECK(get32(out + 1) == WRI_EADDRVEC_MAX);
	}
	wri_rd_init(&r, big, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_server_ident_decode(&r, NULL));
}

/* ---- AUTH_BAD_METHOD ---------------------------------------------------------------------- */

static void enc_bad(wri_wr *w, const void *c) { wri_m2_bad_method_encode(w, (const wri_m2_bad_method *)c); }

static void test_bad_method(void)
{
	static const char *const names[] = {"wrongkey-auth-bad-method", "no-osd-caps-auth-bad-method"};
	size_t i;

	for (i = 0; i < 2; i++) {
		struct fr f;
		wri_m2_bad_method b;
		wri_rd r;
		int64_t v;
		uint8_t *seg;
		wrt_tok l;
		size_t k;

		NEED_FRAME(f, names[i]);
		seg = dup_bytes(f.seg0, f.seg0_len);
		wri_rd_init(&r, seg, f.seg0_len);
		WRT_CHECK_STATUS(WR_OK, wri_m2_bad_method_decode(&r, &b));
		WRT_CHECK(jget_int(f.fields, "method", &v) && b.method == (uint32_t)v);
		WRT_CHECK(jget_int(f.fields, "result", &v) && b.result == (int32_t)v && b.result == -13);
		l = wrt_json_get(&J, f.fields, "methods");
		WRT_CHECK(b.n_methods == wrt_json_count(&J, l));
		for (k = 0; k < b.n_methods; k++)
			WRT_CHECK(b.allowed_methods[k] == (uint32_t)wrt_json_int(&J, wrt_json_at(&J, l, k), &(int){0}));
		l = wrt_json_get(&J, f.fields, "modes");
		WRT_CHECK(b.n_modes == wrt_json_count(&J, l) && b.n_modes == 2);
		for (k = 0; k < b.n_modes; k++)
			WRT_CHECK(b.allowed_modes[k] == (uint32_t)wrt_json_int(&J, wrt_json_at(&J, l, k), &(int){0}));
		enc_vs(names[i], enc_bad, &b, seg, f.seg0_len);
		sweep(names[i], dec_bad, seg, f.seg0_len, 0);
		free(seg);
		free(f.hex);
	}
}

/* method u32, result i32, then two vectors with the given counts and bytes present. */
static size_t build_bad(uint8_t *out, size_t cap, uint32_t cnt1, uint32_t n1, uint32_t cnt2, uint32_t n2)
{
	wri_wr w;
	uint32_t i;

	wri_wr_init(&w, out, cap);
	wri_wr_u32(&w, 2);
	wri_wr_i32(&w, -95);
	wri_wr_u32(&w, cnt1);
	for (i = 0; i < n1; i++)
		wri_wr_u32(&w, 100 + i);
	wri_wr_u32(&w, cnt2);
	for (i = 0; i < n2; i++)
		wri_wr_u32(&w, 200 + i);
	return wri_wr_ok(&w) ? wri_wr_len(&w) : 0;
}

static void test_bad_method_caps(void)
{
	uint8_t big[256];
	wri_m2_bad_method b;
	wri_rd r;
	uint8_t *buf;
	size_t n;
	uint32_t k;

	/* more entries than are stored: the first WRI_M2_MODES_MAX are kept, the rest consumed */
	for (k = 0; k <= 16; k++) {
		n = build_bad(big, sizeof(big), k, k, 16 - k, 16 - k);
		buf = dup_bytes(big, n);
		wri_rd_init(&r, buf, n);
		WRT_CHECK_STATUS(WR_OK, wri_m2_bad_method_decode(&r, &b));
		WRT_CHECK(b.n_methods == (k < WRI_M2_MODES_MAX ? k : WRI_M2_MODES_MAX));
		WRT_CHECK(b.n_modes == (16 - k < WRI_M2_MODES_MAX ? 16 - k : WRI_M2_MODES_MAX));
		{
			uint32_t i;

			for (i = 0; i < b.n_methods; i++)
				WRT_CHECK(b.allowed_methods[i] == 100 + i);
			for (i = 0; i < b.n_modes; i++)
				WRT_CHECK(b.allowed_modes[i] == 200 + i);
		}
		WRT_CHECK(b.method == 2 && b.result == -95);
		free(buf);
	}
	/* count 17 in either vector: too big (counts are checked before bytes are read) */
	n = build_bad(big, sizeof(big), 17, 17, 0, 0);
	buf = dup_bytes(big, n);
	wri_rd_init(&r, buf, n);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_bad_method_decode(&r, &b));
	WRT_CHECK(is_zero(&b, sizeof(b)));
	free(buf);
	n = build_bad(big, sizeof(big), 1, 1, 17, 17);
	buf = dup_bytes(big, n);
	wri_rd_init(&r, buf, n);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_bad_method_decode(&r, &b));
	free(buf);
	/* hostile counts */
	n = build_bad(big, sizeof(big), 0xFFFFFFFFu, 0, 0, 0);
	buf = dup_bytes(big, n);
	wri_rd_init(&r, buf, n);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_bad_method_decode(&r, &b));
	free(buf);
	/* a count the remaining bytes cannot hold */
	n = build_bad(big, sizeof(big), 4, 3, 0, 0);
	buf = dup_bytes(big, n);
	wri_rd_init(&r, buf, n);
	WRT_CHECK(wri_m2_bad_method_decode(&r, &b) != WR_OK);
	free(buf);
	/* empty lists are fine */
	n = build_bad(big, sizeof(big), 0, 0, 0, 0);
	buf = dup_bytes(big, n);
	wri_rd_init(&r, buf, n);
	WRT_CHECK_STATUS(WR_OK, wri_m2_bad_method_decode(&r, &b));
	WRT_CHECK(b.n_methods == 0 && b.n_modes == 0);
	free(buf);
	/* encoder refuses a struct that claims more than it can hold */
	{
		uint8_t out[128];
		wri_wr w;

		memset(&b, 0, sizeof(b));
		b.n_modes = WRI_M2_MODES_MAX + 1;
		wri_wr_init(&w, out, sizeof(out));
		wri_m2_bad_method_encode(&w, &b);
		WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
		wri_wr_init(&w, out, sizeof(out));
		wri_m2_bad_method_encode(&w, NULL);
		WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	}
}

/* ---- single-u64, KEEPALIVE2 --------------------------------------------------------------- */

static void enc_u64(wri_wr *w, const void *c) { wri_m2_u64_encode(w, *(const uint64_t *)c); }

struct ka {
	uint32_t s, n;
};

static void enc_ka(wri_wr *w, const void *c)
{
	const struct ka *k = (const struct ka *)c;

	wri_m2_keepalive_encode(w, k->s, k->n);
}

static void test_small_payloads(void)
{
	static const char *const knames[] = {"keepalive2-client", "keepalive2-ack-server"};
	size_t i;
	struct fr f;

	for (i = 0; i < 2; i++) {
		wri_rd r;
		struct ka k;
		int64_t v;
		uint8_t *seg;

		NEED_FRAME(f, knames[i]);
		WRT_CHECK(f.seg0_len == 8);
		seg = dup_bytes(f.seg0, 8);
		wri_rd_init(&r, seg, 8);
		WRT_CHECK_STATUS(WR_OK, wri_m2_keepalive_decode(&r, &k.s, &k.n));
		WRT_CHECK(jget_int(f.fields, "sec", &v) && k.s == (uint32_t)v);
		WRT_CHECK(jget_int(f.fields, "nsec", &v) && k.n == (uint32_t)v);
		enc_vs(knames[i], enc_ka, &k, seg, 8);
		sweep(knames[i], dec_ka, seg, 8, 1);
		free(seg);
		free(f.hex);
	}
	{
		wri_rd r;
		uint8_t *seg;
		uint64_t v;
		int64_t jv;

		NEED_FRAME(f, "ident-missing-features-probe");
		seg = dup_bytes(f.seg0, f.seg0_len);
		WRT_CHECK(f.seg0_len == 8);
		wri_rd_init(&r, seg, 8);
		WRT_CHECK_STATUS(WR_OK, wri_m2_u64_decode(&r, &v));
		WRT_CHECK(jget_int(f.fields, "features", &jv) && v == (uint64_t)jv);
		enc_vs("u64", enc_u64, &v, seg, 8);
		sweep("u64", dec_u64, seg, 8, 1);
		free(seg);
		free(f.hex);
	}
	{
		uint64_t v = 0xFEDCBA9876543210ull;
		uint8_t b[8];
		wri_wr w;
		wri_rd r;
		uint64_t back = 0;

		wri_wr_init(&w, b, 8);
		wri_m2_u64_encode(&w, v);
		WRT_CHECK(b[0] == 0x10 && b[7] == 0xFE);
		wri_rd_init(&r, b, 8);
		WRT_CHECK_STATUS(WR_OK, wri_m2_u64_decode(&r, &back));
		WRT_CHECK(back == v);
		wri_rd_init(&r, b, 8);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_u64_decode(&r, NULL));
		{
			uint32_t ns = 0;

			WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_keepalive_decode(&r, NULL, &ns));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_keepalive_decode(&r, &ns, NULL));
		}
	}
}

/* ---- header2 ------------------------------------------------------------------------------ */

static void check_hdr2_expect(const wri_m2_hdr2 *h, const uint8_t *raw, wrt_tok expect)
{
	int64_t v;

	if (jget_int(expect, "type", &v))
		WRT_CHECK(h->type == (uint16_t)v);
	if (jget_int(expect, "version", &v))
		WRT_CHECK(h->version == (uint16_t)v);
	if (jget_int(expect, "compat", &v))
		WRT_CHECK(h->compat_version == (uint16_t)v);
	if (jget_int(expect, "priority", &v))
		WRT_CHECK(h->priority == (uint16_t)v);
	if (jget_int(expect, "tid", &v))
		WRT_CHECK(h->tid == (uint64_t)v);
	if (jget_int(expect, "seq", &v))
		WRT_CHECK(h->seq == (uint64_t)v);
	/* hand-read cross checks of the fixed offsets */
	WRT_CHECK(h->seq == get64(raw) && h->tid == get64(raw + 8) && h->ack_seq == get64(raw + 28));
	WRT_CHECK(h->flags == raw[36] && h->flags == WRI_M2_MSGF_COMPLETE_NOCRC);
	WRT_CHECK(h->data_pre_padding_len == 0 && h->data_off == 0);
}

static void test_hdr2_one(const uint8_t *raw)
{
	wri_m2_hdr2 h, h2;
	uint8_t enc[WRI_M2_HDR2_LEN];
	uint8_t *exact;
	size_t k;

	exact = dup_bytes(raw, WRI_M2_HDR2_LEN);
	WRT_CHECK_STATUS(WR_OK, wri_m2_hdr2_decode(exact, WRI_M2_HDR2_LEN, &h));
	wri_m2_hdr2_encode(enc, &h);
	WRT_CHECK_MEM(enc, raw, WRI_M2_HDR2_LEN);
	free(exact);
	for (k = 0; k < WRI_M2_HDR2_LEN; k++) {
		exact = dup_bytes(raw, k);
		WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_m2_hdr2_decode(exact, k, &h2));
		WRT_CHECK(is_zero(&h2, sizeof(h2)));
		free(exact);
	}
	/* extra bytes are ignored */
	exact = xalloc(WRI_M2_HDR2_LEN + 7);
	memcpy(exact, raw, WRI_M2_HDR2_LEN);
	memset(exact + WRI_M2_HDR2_LEN, 0xA5, 7);
	WRT_CHECK_STATUS(WR_OK, wri_m2_hdr2_decode(exact, WRI_M2_HDR2_LEN + 7, &h2));
	WRT_CHECK(memcmp(&h, &h2, sizeof(h)) == 0);
	free(exact);
}

static void test_hdr2(void)
{
	static const char *const mon[] = {
		"mauth-renewal-scrubbed.json", "mauthreply-renewal-scrubbed.json", "mmongetmap.json",
		"mmonmap-e3.json", "mmonsubscribe-config-monmap.json", "mmonsubscribe-mgrmap.json",
		"mmonsubscribe-osdmap-start0-onetime.json", "mmonsubscribe-reconnect.json",
		"mosdmap-v4-full-e42.json"};
	static const char *const frames[] = {"mon-message-first-client", "osd-message-four-segments-client",
					     "osd-message-two-segments-server"};
	size_t i;

	for (i = 0; i < sizeof(mon) / sizeof(mon[0]); i++) {
		wrt_json j;
		char rel[128];
		uint8_t *raw = NULL;
		size_t n = 0;
		wri_m2_hdr2 h;

		snprintf(rel, sizeof(rel), "monclient/%s", mon[i]);
		if (wrt_json_load_vec(&j, rel) != 0) {
			WRT_CHECK(0);
			continue;
		}
		if (wrt_json_get_hex(&j, wrt_json_root(&j), "header2_hex", &raw, &n) != 0 || n != WRI_M2_HDR2_LEN) {
			WRT_CHECK(0);
			wrt_json_free(&j);
			continue;
		}
		WRT_CHECK_STATUS(WR_OK, wri_m2_hdr2_decode(raw, n, &h));
		{
			/* the expectation block lives in the other JSON, so swap the global for the helper */
			wrt_json keep = J;

			J = j;
			check_hdr2_expect(&h, raw, wrt_json_get(&J, wrt_json_root(&J), "expect"));
			J = keep;
		}
		test_hdr2_one(raw);
		free(raw);
		wrt_json_free(&j);
	}
	for (i = 0; i < 3; i++) {
		struct fr f;
		wri_m2_hdr2 h;
		int64_t v;

		NEED_FRAME(f, frames[i]);
		WRT_CHECK(f.seg0_len == WRI_M2_HDR2_LEN);
		WRT_CHECK_STATUS(WR_OK, wri_m2_hdr2_decode(f.seg0, f.seg0_len, &h));
		WRT_CHECK(jget_int(f.fields, "seq", &v) && h.seq == (uint64_t)v);
		WRT_CHECK(jget_int(f.fields, "tid", &v) && h.tid == (uint64_t)v);
		WRT_CHECK(jget_int(f.fields, "type", &v) && h.type == (uint16_t)v);
		WRT_CHECK(jget_int(f.fields, "priority", &v) && h.priority == (uint16_t)v);
		WRT_CHECK(jget_int(f.fields, "version", &v) && h.version == (uint16_t)v);
		WRT_CHECK(jget_int(f.fields, "pre_padding", &v) && h.data_pre_padding_len == (uint32_t)v);
		WRT_CHECK(jget_int(f.fields, "data_off", &v) && h.data_off == (uint16_t)v);
		WRT_CHECK(jget_int(f.fields, "ack_seq", &v) && h.ack_seq == (uint64_t)v);
		WRT_CHECK(jget_int(f.fields, "flags", &v) && h.flags == (uint8_t)v);
		WRT_CHECK(jget_int(f.fields, "compat", &v) && h.compat_version == (uint16_t)v);
		test_hdr2_one(f.seg0);
		free(f.hex);
	}
	/* hand-built values: reserved bytes are written as zero and ignored when read */
	{
		wri_m2_hdr2 h, back;
		uint8_t enc[WRI_M2_HDR2_LEN];

		memset(&h, 0, sizeof(h));
		h.seq = 0x0102030405060708ull;
		h.tid = 0xF1F2F3F4F5F6F7F8ull;
		h.type = 0xABCD;
		h.priority = 0x1234;
		h.version = 0x5678;
		h.data_pre_padding_len = 0x9ABCDEF0u;
		h.data_off = 0x4321;
		h.ack_seq = 0x1122334455667788ull;
		h.flags = 0xFF;
		h.compat_version = 0xBEEF;
		memset(enc, 0x77, sizeof(enc));
		wri_m2_hdr2_encode(enc, &h);
		WRT_CHECK(enc[0] == 0x08 && enc[7] == 0x01 && enc[16] == 0xCD && enc[17] == 0xAB);
		WRT_CHECK(enc[22] == 0xF0 && enc[25] == 0x9A && enc[26] == 0x21 && enc[28] == 0x88);
		WRT_CHECK(enc[36] == 0xFF && enc[37] == 0xEF && enc[38] == 0xBE && enc[39] == 0 && enc[40] == 0);
		enc[39] = 9;
		enc[40] = 9;
		WRT_CHECK_STATUS(WR_OK, wri_m2_hdr2_decode(enc, sizeof(enc), &back));
		WRT_CHECK(memcmp(&h, &back, sizeof(h)) == 0);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_hdr2_decode(NULL, 41, &back));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_hdr2_decode(enc, 41, NULL));
		wri_m2_hdr2_encode(NULL, &h); /* must not crash */
	}
}

/* ---- NULL arguments, error stickiness ----------------------------------------------------- */

static void test_null_args(void)
{
	wri_rd r;
	wri_wr w;
	uint8_t b[64];
	uint8_t sig[32];
	wri_m2_hello h;
	wri_m2_bad_method bm;

	memset(b, 0, sizeof(b));
	wri_rd_init(&r, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_hello_decode(&r, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_hello_decode(NULL, &h));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_bad_method_decode(&r, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_bad_method_decode(NULL, &bm));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_auth_sig_decode(&r, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_auth_sig_decode(NULL, sig));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_u64_decode(NULL, (uint64_t *)(void *)b));
	/* encoders with a NULL writer or NULL struct */
	wri_m2_hello_encode(NULL, &h);
	wri_m2_client_ident_encode(NULL, NULL);
	wri_m2_auth_done_encode(NULL, NULL);
	wri_m2_auth_sig_encode(NULL, sig);
	wri_m2_keepalive_encode(NULL, 1, 2);
	wri_wr_init(&w, b, sizeof(b));
	wri_m2_hello_encode(&w, NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	wri_wr_init(&w, b, sizeof(b));
	wri_m2_client_ident_encode(&w, NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	wri_wr_init(&w, b, sizeof(b));
	wri_m2_auth_done_encode(&w, NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	wri_wr_init(&w, b, sizeof(b));
	wri_m2_server_ident_encode(&w, NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	wri_wr_init(&w, b, sizeof(b));
	wri_m2_auth_sig_encode(&w, NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	/* a reader that already failed stays failed with its own status */
	wri_rd_init(&r, b, sizeof(b));
	wri_rd_fail(&r, WR_E_RANGE);
	WRT_CHECK_STATUS(WR_E_RANGE, wri_m2_u64_decode(&r, (uint64_t *)(void *)sig));
}

int main(void)
{
	if (wrt_json_load_vec(&J, "msgr2/frames-crc.json") != 0) {
		fprintf(stderr, "cannot load msgr2/frames-crc.json\n");
		return 1;
	}
	test_hello();
	test_auth_request();
	test_auth_request_caps();
	test_auth_more();
	test_auth_more_caps();
	test_auth_done();
	test_auth_done_caps();
	test_auth_sig();
	test_client_ident();
	test_server_ident();
	test_server_ident_caps();
	test_bad_method();
	test_bad_method_caps();
	test_small_payloads();
	test_hdr2();
	test_null_args();
	wrt_json_free(&J);
	return wrt_finish();
}
