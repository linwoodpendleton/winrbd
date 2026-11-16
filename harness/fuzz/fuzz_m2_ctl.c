/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the msgr2 control-payload decoders and the pre-auth logs
 * (core/src/msgr2/wri_m2_ctl.c, wri_m2_hdr2.c, wri_m2_preauth.c).
 *
 * Byte 0 selects the payload type, the rest is the payload (an exact-size heap copy, so ASan sees
 * any over-read):
 *
 *   0 HELLO           decode; on success re-encode (must succeed), decode again, compare
 *   1 AUTH_BAD_METHOD decode; re-encode the stored entries, decode again, compare
 *   2 AUTH_*_MORE     decode; on success the encoding must equal the input exactly
 *   3 AUTH_DONE       same
 *   4 AUTH_SIGNATURE  same
 *   5 SERVER_IDENT    decode; re-encode the stored addresses, decode again, compare
 *   6 u64 / KEEPALIVE2  both decoders; success means the encoding equals the input
 *   7 ceph_msg_header2  decode; encode then decode must reproduce the structure
 *   8 pre-auth logs   byte 1 = capacity (0..255), then pieces of (side, length) read from the data:
 *                     the logs must match a simple model and never exceed the capacity
 *   9 sig_verify      16 key bytes, then a sent log; the expected value verifies, a flipped bit not
 *  10 encoders        byte 1 selects the encoder, byte 2 the output capacity (x4), the rest feeds the
 *                     fields (counts and lengths may be hostile): never a write past the capacity,
 *                     failures are sticky WR_E_TOOBIG / WR_E_INVAL, successes decode back
 *
 * A violated property traps.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_m2_ctl.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

static uint8_t *heap_copy(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n ? n : 1);

	if (q != NULL && n != 0)
		memcpy(q, p, n);
	return q;
}

static void fuzz_hello(const uint8_t *p, size_t n)
{
	wri_m2_hello a, b;
	uint8_t enc[WRI_EADDR_MAX_WIRE + 1];
	wri_rd r;
	wri_wr w;

	wri_rd_init(&r, p, n);
	if (wri_m2_hello_decode(&r, &a) != WR_OK)
		return;
	wri_wr_init(&w, enc, sizeof(enc));
	wri_m2_hello_encode(&w, &a);
	check(wri_wr_ok(&w));
	wri_rd_init(&r, enc, wri_wr_len(&w));
	check(wri_m2_hello_decode(&r, &b) == WR_OK);
	check(a.entity_type == b.entity_type && wri_eaddr_equal(&a.peer_addr, &b.peer_addr));
}

static void fuzz_bad(const uint8_t *p, size_t n)
{
	wri_m2_bad_method a, b;
	uint8_t enc[4 + 4 + 4 + 4 * WRI_M2_MODES_MAX + 4 + 4 * WRI_M2_MODES_MAX];
	wri_rd r;
	wri_wr w;

	wri_rd_init(&r, p, n);
	if (wri_m2_bad_method_decode(&r, &a) != WR_OK)
		return;
	check(a.n_methods <= WRI_M2_MODES_MAX && a.n_modes <= WRI_M2_MODES_MAX);
	wri_wr_init(&w, enc, sizeof(enc));
	wri_m2_bad_method_encode(&w, &a);
	check(wri_wr_ok(&w));
	wri_rd_init(&r, enc, wri_wr_len(&w));
	check(wri_m2_bad_method_decode(&r, &b) == WR_OK);
	check(memcmp(&a, &b, sizeof(a)) == 0);
}

static void fuzz_exact_blob(int kind, const uint8_t *p, size_t n)
{
	uint8_t *enc = (uint8_t *)malloc(n ? n : 1);
	wri_rd r;
	wri_wr w;

	if (enc == NULL)
		return;
	wri_rd_init(&r, p, n);
	wri_wr_init(&w, enc, n);
	if (kind == 2) {
		const uint8_t *pl;
		uint32_t len;

		if (wri_m2_auth_more_decode(&r, &pl, &len) != WR_OK)
			goto out;
		check(len <= WRI_M2_AUTH_BLOB_MAX);
		wri_m2_auth_more_encode(&w, pl, len);
	} else if (kind == 3) {
		wri_m2_auth_done d;

		if (wri_m2_auth_done_decode(&r, &d) != WR_OK)
			goto out;
		check(d.payload_len <= WRI_M2_AUTH_BLOB_MAX);
		wri_m2_auth_done_encode(&w, &d);
	} else {
		uint8_t sig[32];

		if (wri_m2_auth_sig_decode(&r, sig) != WR_OK)
			goto out;
		wri_m2_auth_sig_encode(&w, sig);
	}
	check(wri_wr_ok(&w) && wri_wr_len(&w) == n && (n == 0 || memcmp(enc, p, n) == 0));
out:
	free(enc);
}

static void fuzz_sident(const uint8_t *p, size_t n)
{
	wri_m2_server_ident a, b;
	uint8_t enc[8 * WRI_EADDR_MAX_WIRE + 64];
	wri_rd r;
	wri_wr w;
	size_t i;

	wri_rd_init(&r, p, n);
	if (wri_m2_server_ident_decode(&r, &a) != WR_OK)
		return;
	check(a.n_addrs <= WRI_EADDRVEC_MAX);
	wri_wr_init(&w, enc, sizeof(enc));
	wri_m2_server_ident_encode(&w, &a);
	check(wri_wr_ok(&w));
	wri_rd_init(&r, enc, wri_wr_len(&w));
	check(wri_m2_server_ident_decode(&r, &b) == WR_OK);
	check(a.n_addrs == b.n_addrs && a.gid == b.gid && a.global_seq == b.global_seq &&
	      a.supported == b.supported && a.required == b.required && a.flags == b.flags &&
	      a.cookie == b.cookie);
	for (i = 0; i < a.n_addrs; i++)
		check(wri_eaddr_equal(&a.addrs[i], &b.addrs[i]));
}

static void fuzz_small(const uint8_t *p, size_t n)
{
	uint8_t enc[8];
	wri_rd r;
	wri_wr w;
	uint64_t v;
	uint32_t s, ns;

	wri_rd_init(&r, p, n);
	if (wri_m2_u64_decode(&r, &v) == WR_OK) {
		wri_wr_init(&w, enc, sizeof(enc));
		wri_m2_u64_encode(&w, v);
		check(wri_wr_ok(&w) && n == 8 && memcmp(enc, p, 8) == 0);
	}
	wri_rd_init(&r, p, n);
	if (wri_m2_keepalive_decode(&r, &s, &ns) == WR_OK) {
		wri_wr_init(&w, enc, sizeof(enc));
		wri_m2_keepalive_encode(&w, s, ns);
		check(wri_wr_ok(&w) && n == 8 && memcmp(enc, p, 8) == 0);
	}
}

static void fuzz_hdr2(const uint8_t *p, size_t n)
{
	wri_m2_hdr2 a, b;
	uint8_t enc[WRI_M2_HDR2_LEN];

	if (wri_m2_hdr2_decode(p, n, &a) != WR_OK) {
		check(n < WRI_M2_HDR2_LEN);
		return;
	}
	check(n >= WRI_M2_HDR2_LEN);
	wri_m2_hdr2_encode(enc, &a);
	check(wri_m2_hdr2_decode(enc, sizeof(enc), &b) == WR_OK);
	check(memcmp(&a, &b, sizeof(a)) == 0);
}

static void fuzz_preauth(const uint8_t *p, size_t n)
{
	uint8_t rxb[256], txb[256], mrx[256], mtx[256];
	uint32_t cap, mrx_n = 0, mtx_n = 0;
	int overflow = 0;
	wri_m2_preauth pa;
	size_t pos = 1;

	if (n < 1)
		return;
	cap = p[0];
	wri_m2_preauth_init(&pa, rxb, txb, cap);
	while (pos + 1 < n) {
		uint8_t sel = p[pos++];
		size_t len = p[pos++];
		int rx = (sel & 1) == 0;

		if (sel & 0x80)
			wri_m2_preauth_stop(&pa);
		if (len > n - pos)
			len = n - pos;
		if (rx)
			wri_m2_preauth_rx(&pa, p + pos, len);
		else
			wri_m2_preauth_tx(&pa, p + pos, len);
		/* model */
		if (!(sel & 0x80) && !overflow && pa.enabled && len != 0) {
			uint32_t *ml = rx ? &mrx_n : &mtx_n;

			if (len > cap - *ml)
				overflow = 1;
			else {
				memcpy(rx ? mrx + *ml : mtx + *ml, p + pos, len);
				*ml += (uint32_t)len;
			}
		}
		pos += len;
		check(pa.rx_len <= cap && pa.tx_len <= cap);
	}
	check((pa.err != WR_OK) == (overflow != 0));
	{
		check(pa.rx_len == mrx_n && pa.tx_len == mtx_n);
		check(mrx_n == 0 || memcmp(rxb, mrx, mrx_n) == 0);
		check(mtx_n == 0 || memcmp(txb, mtx, mtx_n) == 0);
	}
	wri_m2_preauth_wipe(&pa);
	check(pa.rx_len == 0 && pa.tx_len == 0);
}

/* the checked comparison of wri_m2_sig_verify against the model of the sent log */
static void fuzz_preauth_verify(const uint8_t *p, size_t n)
{
	uint8_t rxb[64], txb[64], key[16], sig[32], bad[32];
	wri_m2_preauth pa;
	wr_status st;
	size_t i;

	if (n < sizeof(key) + 1)
		return;
	memcpy(key, p, sizeof(key));
	p += sizeof(key);
	n -= sizeof(key);
	wri_m2_preauth_init(&pa, rxb, txb, sizeof(txb));
	wri_m2_preauth_tx(&pa, p + 1, n - 1 < 80 ? n - 1 : 80);
	check(wri_m2_sig_verify(NULL, &pa, key, sizeof(key), sig) == WR_E_STATE || pa.err != WR_OK);
	wri_m2_preauth_stop(&pa);
	wri_m2_sig_expected(NULL, &pa, key, sizeof(key), sig);
	st = wri_m2_sig_verify(NULL, &pa, key, sizeof(key), sig);
	if (pa.err != WR_OK) {
		check(st == pa.err);
		return;
	}
	check(st == WR_OK);
	i = p[0] % 32u;
	memcpy(bad, sig, 32);
	bad[i] ^= (uint8_t)(1u << (p[0] & 7u));
	check(wri_m2_sig_verify(NULL, &pa, key, sizeof(key), bad) == WR_E_M2_SIGNATURE);
}

static uint8_t fam(uint32_t v)
{
	static const uint8_t f[4] = {0u, WR_AF_IPV4, WR_AF_IPV6, 0x7fu};

	return f[v & 3u];
}

static void fuzz_encoders(const uint8_t *p, size_t n)
{
	enum { MAXV = 40 };
	uint32_t vec[MAXV];
	uint8_t *out;
	size_t cap, i, k;
	wri_wr w;
	wri_rd r;
	unsigned sel;

	if (n < 3)
		return;
	sel = p[0] % 6u;
	cap = (size_t)p[1] * 4u;
	p += 2;
	n -= 2;
	out = (uint8_t *)malloc(cap ? cap : 1);
	if (out == NULL)
		return;
	wri_wr_init(&w, out, cap);
	k = p[0] % (MAXV + 1u);
	for (i = 0; i < MAXV; i++)
		vec[i] = (i + 1 < n) ? (uint32_t)p[i + 1] * 0x01010101u : 0u;
	if (sel == 0) { /* AUTH_REQUEST: hostile mode count, payload as long as the input */
		wri_m2_auth_request_encode(&w, 2u, vec, k, p, n);
		if (k > WRI_M2_VEC_WIRE_MAX)
			check(w.err == WR_E_TOOBIG);
	} else if (sel == 1) { /* AUTH_BAD_METHOD, counts above the stored maximum are refused */
		wri_m2_bad_method b;
		uint32_t j;

		memset(&b, 0, sizeof(b));
		b.method = 2;
		b.result = -13;
		b.n_methods = (uint32_t)k % 8u;
		b.n_modes = (uint32_t)(n % 8u);
		for (j = 0; j < WRI_M2_MODES_MAX; j++) {
			b.allowed_methods[j] = vec[j];
			b.allowed_modes[j] = vec[j + 4];
		}
		wri_m2_bad_method_encode(&w, &b);
		if (b.n_methods > WRI_M2_MODES_MAX || b.n_modes > WRI_M2_MODES_MAX)
			check(w.err == WR_E_TOOBIG);
		else if (wri_wr_ok(&w)) {
			wri_m2_bad_method back;

			wri_rd_init(&r, out, wri_wr_len(&w));
			check(wri_m2_bad_method_decode(&r, &back) == WR_OK);
			check(back.n_methods == b.n_methods && back.n_modes == b.n_modes);
		}
	} else if (sel == 2) { /* AUTH_*_MORE */
		const uint8_t *pl;
		uint32_t len;

		wri_m2_auth_more_encode(&w, p, n);
		if (wri_wr_ok(&w)) {
			wri_rd_init(&r, out, wri_wr_len(&w));
			check(wri_m2_auth_more_decode(&r, &pl, &len) == WR_OK && len == n && memcmp(pl, p, n) == 0);
		}
	} else if (sel == 3) { /* AUTH_DONE */
		wri_m2_auth_done d, back;

		d.global_id = 7;
		d.mode = 1;
		d.payload = p;
		d.payload_len = (uint32_t)n;
		wri_m2_auth_done_encode(&w, &d);
		if (wri_wr_ok(&w)) {
			wri_rd_init(&r, out, wri_wr_len(&w));
			check(wri_m2_auth_done_decode(&r, &back) == WR_OK && back.payload_len == n);
		}
	} else if (sel == 4) { /* CLIENT_IDENT with arbitrary address fields */
		wri_m2_client_ident c;

		memset(&c, 0, sizeof(c));
		c.addrs[0].type = vec[0];
		c.addrs[0].family = fam(vec[1]);
		c.target.type = vec[2];
		c.target.family = fam(vec[3]);
		c.gid = -1;
		wri_m2_client_ident_encode(&w, &c);
	} else { /* SERVER_IDENT with a hostile address count */
		wri_m2_server_ident s;

		memset(&s, 0, sizeof(s));
		s.n_addrs = k;
		s.addrs[0].family = fam(vec[0]);
		wri_m2_server_ident_encode(&w, &s);
	}
	check(w.pos <= cap);
	check(wri_wr_ok(&w) || w.err == WR_E_TOOBIG || w.err == WR_E_INVAL);
	free(out);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *buf;
	unsigned mode;

	if (size < 1)
		return 0;
	mode = data[0] % 11u;
	data++;
	size--;
	if (mode == 8) {
		fuzz_preauth(data, size);
		return 0;
	}
	if (mode == 9) {
		fuzz_preauth_verify(data, size);
		return 0;
	}
	if (mode == 10) {
		fuzz_encoders(data, size);
		return 0;
	}
	buf = heap_copy(data, size);
	if (buf == NULL)
		return 0;
	switch (mode) {
	case 0:
		fuzz_hello(buf, size);
		break;
	case 1:
		fuzz_bad(buf, size);
		break;
	case 2:
	case 3:
	case 4:
		fuzz_exact_blob((int)mode, buf, size);
		break;
	case 5:
		fuzz_sident(buf, size);
		break;
	case 6:
		fuzz_small(buf, size);
		break;
	default:
		fuzz_hdr2(buf, size);
		break;
	}
	free(buf);
	return 0;
}
