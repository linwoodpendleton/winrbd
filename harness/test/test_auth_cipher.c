/* SPDX-License-Identifier: MIT */
/*
 * test_auth_cipher - the cephx ciphers, the type-2 key derivation, the envelope and the challenge
 * proof (core/src/auth/wri_cx_cipher.c, wri_cx_envelope.c; docs/spec/cephx.md 2.4 to 2.8).
 *
 * Known answers: cephx/cipher-type1.json and cipher-type2.json (decrypt the ciphertexts, encrypt
 * with the vector's confounder injected through a fake host random and compare bytes, derived-key
 * table, sealed envelopes), the RFC 8009 appendix A values (KDF outputs and ciphertexts), and
 * cephx/challenge-proof.json for both key types.
 *
 * Properties: every byte of a type-2 ciphertext flipped is refused and decrypts nothing (a counting
 * CBC override proves the cipher is never entered), wrong key and wrong usage, short and odd
 * lengths, bad type-1 padding, out_cap one byte short at every size (exact-size heap buffers, so the
 * sanitizers see an overrun), in == out and partial overlap refused, a failing or missing host
 * random, bad keys, failure wipes, host overrides are used for every primitive, the KDF edge cases,
 * the envelope magic, version byte and item pointers, seal overflow and overlap.
 */
#include "wrt.h"

#include "wri_aes.h"
#include "wri_cx.h"
#include "wri_hash.h"
#include "wri_le.h"
#include "wri_prim.h"

/* ---- fakes and helpers ----------------------------------------------------------------------- */

struct fake_rng {
	const uint8_t *bytes; /* handed out first, then 0xA5 filler */
	size_t n, pos;
	int fail;
	unsigned calls;
};

static wr_status fake_random(void *ctx, uint8_t *out, size_t n)
{
	struct fake_rng *f = (struct fake_rng *)ctx;
	size_t i;

	f->calls++;
	if (f->fail) {
		for (i = 0; i < n; i++)
			out[i] = 0x77; /* garbage the core must not leave behind */
		return WR_E_HOST_RANDOM;
	}
	for (i = 0; i < n; i++)
		out[i] = f->pos < f->n ? f->bytes[f->pos++] : (uint8_t)(0xA5u ^ (unsigned)i);
	return WR_OK;
}

static void ctx_init(wri_ctx *x, struct fake_rng *f, const wr_prim_ops *prim)
{
	memset(x, 0, sizeof(*x));
	memset(f, 0, sizeof(*f));
	x->host.size = (uint32_t)sizeof(x->host);
	x->host.ctx = f;
	x->host.random = fake_random;
	x->host.prim = prim;
}

static void rng_set(struct fake_rng *f, const uint8_t *b, size_t n)
{
	f->bytes = b;
	f->n = n;
	f->pos = 0;
}

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;

static uint32_t rnd(void)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (uint32_t)((rng_state * 0x2545f4914f6cdd1dull) >> 32);
}

static void rnd_fill(uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)rnd();
}

/* Exact-size heap block: an out-of-bounds access is caught by the sanitizers. */
static uint8_t *heap_new(size_t n)
{
	uint8_t *q = (uint8_t *)calloc(n != 0 ? n : 1, 1);

	if (q == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	return q;
}

static uint8_t *heap_dup(const uint8_t *p, size_t n)
{
	uint8_t *q = heap_new(n);

	if (n != 0)
		memcpy(q, p, n);
	return q;
}

static int all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

static wr_key mkkey(unsigned type, const uint8_t *secret, size_t n)
{
	wr_key k;

	WRT_CHECK(wr_key_from_raw(&k, type, secret, n) == WR_OK);
	return k;
}

static wr_key seq_key(unsigned type, size_t n) /* secret 00 01 02 ... */
{
	uint8_t s[WR_KEY_MAX];
	size_t i;

	for (i = 0; i < n; i++)
		s[i] = (uint8_t)i;
	return mkkey(type, s, n);
}

/* ---- host override that counts its calls ----------------------------------------------------- */

struct spy {
	unsigned cbc_enc, cbc_dec, h384, h256;
};

static wr_status spy_cbc(void *c, const uint8_t *key, size_t klen, const uint8_t iv[16], const uint8_t *in,
			 uint8_t *out, size_t nb, int enc)
{
	struct spy *s = (struct spy *)c;
	wri_aes_ctx a;

	if (enc)
		s->cbc_enc++;
	else
		s->cbc_dec++;
	if (wri_aes_setkey(&a, key, klen) != WR_OK)
		return WR_E_CRYPTO_KEY;
	if (enc)
		wri_aes_cbc_enc(&a, iv, in, out, nb);
	else
		wri_aes_cbc_dec(&a, iv, in, out, nb);
	return WR_OK;
}

static wr_status spy_enc(void *c, const uint8_t *k, size_t kl, const uint8_t iv[16], const uint8_t *in,
			 uint8_t *out, size_t nb)
{
	return spy_cbc(c, k, kl, iv, in, out, nb, 1);
}

static wr_status spy_dec(void *c, const uint8_t *k, size_t kl, const uint8_t iv[16], const uint8_t *in,
			 uint8_t *out, size_t nb)
{
	return spy_cbc(c, k, kl, iv, in, out, nb, 0);
}

static void spy_h384(void *c, const uint8_t *key, size_t klen, const wr_iov *iov, size_t niov, uint8_t out[48])
{
	((struct spy *)c)->h384++;
	wri_hmac_sha384(key, klen, iov, niov, out);
}

static void spy_h256(void *c, const uint8_t *key, size_t klen, const wr_iov *iov, size_t niov, uint8_t out[32])
{
	((struct spy *)c)->h256++;
	wri_hmac_sha256(key, klen, iov, niov, out);
}

static void spy_init(wr_prim_ops *p, struct spy *s)
{
	memset(p, 0, sizeof(*p));
	memset(s, 0, sizeof(*s));
	p->size = (uint32_t)sizeof(*p);
	p->ctx = s;
	p->aes_cbc_enc = spy_enc;
	p->aes_cbc_dec = spy_dec;
	p->hmac_sha384 = spy_h384;
	p->hmac_sha256 = spy_h256;
}

/* ---- known answers ---------------------------------------------------------------------------- */

static void test_cipher_len(void)
{
	size_t n;

	for (n = 0; n < 100; n++) {
		WRT_CHECK(wri_cx_cipher_len(1, n) == 16 * (n / 16 + 1));
		WRT_CHECK(wri_cx_cipher_len(2, n) == n + 40);
	}
	WRT_CHECK(wri_cx_cipher_len(0, 5) == 0);
	WRT_CHECK(wri_cx_cipher_len(3, 5) == 0);
	WRT_CHECK(wri_cx_cipher_len(1, SIZE_MAX) == 0);
	WRT_CHECK(wri_cx_cipher_len(1, SIZE_MAX - 15) == 0);
	WRT_CHECK(wri_cx_cipher_len(2, SIZE_MAX - 39) == 0);
	WRT_CHECK(wri_cx_cipher_len(2, SIZE_MAX - 40) == SIZE_MAX);
}

static void test_type1_vectors(void)
{
	wrt_json j;
	wrt_tok root, vecs, envs;
	uint8_t *sec = NULL, *iv = NULL;
	size_t sn = 0, ivn = 0, i, nv;
	wr_key k;
	wri_ctx x;
	struct fake_rng f;

	ctx_init(&x, &f, NULL);
	if (wrt_json_load_vec(&j, "cephx/cipher-type1.json") != 0) {
		WRT_CHECK(0 && "cipher-type1.json loads");
		return;
	}
	root = wrt_json_root(&j);
	WRT_CHECK(wrt_json_get_hex(&j, root, "key_secret", &sec, &sn) == 0);
	WRT_CHECK(wrt_json_get_hex(&j, root, "iv", &iv, &ivn) == 0);
	WRT_CHECK(ivn == 16 && memcmp(iv, "cephsageyudagreg", 16) == 0);
	k = mkkey(1, sec, sn);
	vecs = wrt_json_get(&j, root, "vectors");
	nv = wrt_json_count(&j, vecs);
	WRT_CHECK(nv >= 8);
	for (i = 0; i < nv; i++) {
		wrt_tok v = wrt_json_at(&j, vecs, i);
		uint8_t *pt = NULL, *ct = NULL, *out;
		size_t pn = 0, cn = 0, on = 99;

		WRT_CHECK(wrt_json_get_hex(&j, v, "plaintext", &pt, &pn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, v, "ciphertext", &ct, &cn) == 0);
		WRT_CHECK(cn == wri_cx_cipher_len(1, pn));

		out = heap_new(cn);
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 0x77, pt, pn, out, cn, &on));
		WRT_CHECK(on == cn);
		WRT_CHECK_MEM(out, ct, cn);
		WRT_CHECK(f.calls == 0); /* type 1 draws no random */
		free(out);

		out = heap_new(cn);
		on = 99;
		WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k, 0x99, ct, cn, out, cn, &on)); /* usage ignored */
		WRT_CHECK(on == pn);
		WRT_CHECK_MEM(out, pt, pn);
		free(out);
		free(pt);
		free(ct);
	}

	envs = wrt_json_get(&j, root, "envelopes");
	for (i = 0; i < wrt_json_count(&j, envs); i++) {
		wrt_tok e = wrt_json_at(&j, envs, i);
		uint8_t *item = NULL, *sealed = NULL, *out, *scratch;
		size_t in_n = 0, sn2 = 0, on = 0, il = 0;
		const uint8_t *it = NULL;
		int ok = 0;
		uint32_t usage = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, e, "usage"), &ok);

		WRT_CHECK(wrt_json_get_hex(&j, e, "item", &item, &in_n) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, e, "sealed_length_prefixed", &sealed, &sn2) == 0);
		WRT_CHECK(sn2 >= 4 && wri_le32_get(sealed) == sn2 - 4);
		out = heap_new(sn2 - 4);
		WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&x, &k, usage, item, in_n, out, sn2 - 4, &on));
		WRT_CHECK(on == sn2 - 4);
		WRT_CHECK_MEM(out, sealed + 4, sn2 - 4);
		free(out);
		scratch = heap_new(sn2 - 4);
		WRT_CHECK_STATUS(WR_OK, wri_cx_open(&x, &k, usage, sealed + 4, sn2 - 4, scratch, sn2 - 4, &it, &il));
		WRT_CHECK(il == in_n && it >= scratch && it + il <= scratch + (sn2 - 4));
		WRT_CHECK_MEM(it, item, in_n);
		free(scratch);
		free(item);
		free(sealed);
	}
	free(sec);
	free(iv);
	wrt_json_free(&j);
}

static void kdf_check(const uint8_t *base, size_t bn, uint32_t usage, const uint8_t *ke, const uint8_t *ki)
{
	uint8_t a[32], b[24];

	wri_cx_kdf(NULL, base, bn, usage, 0xAA, a, sizeof(a));
	wri_cx_kdf(NULL, base, bn, usage, 0x55, b, sizeof(b));
	WRT_CHECK_MEM(a, ke, 32);
	WRT_CHECK_MEM(b, ki, 24);
}

static void test_type2_vectors(void)
{
	wrt_json j;
	wrt_tok root, vecs, derived, envs;
	uint8_t *sec = NULL;
	size_t sn = 0, i, nv, nd;
	wr_key k;
	wri_ctx x;
	struct fake_rng f;

	if (wrt_json_load_vec(&j, "cephx/cipher-type2.json") != 0) {
		WRT_CHECK(0 && "cipher-type2.json loads");
		return;
	}
	root = wrt_json_root(&j);
	WRT_CHECK(wrt_json_get_hex(&j, root, "key_secret", &sec, &sn) == 0);
	WRT_CHECK(sn == 32);
	k = mkkey(2, sec, sn);

	derived = wrt_json_get(&j, root, "derived");
	nd = wrt_json_count(&j, derived);
	WRT_CHECK(nd == 6);
	for (i = 0; i < nd; i++) {
		wrt_tok d, val;
		const char *name = wrt_json_key_at(&j, derived, i, &val);
		uint8_t *ke = NULL, *ki = NULL;
		size_t kn = 0, in = 0;
		uint32_t usage = (uint32_t)strtoul(name, NULL, 0);

		d = val;
		WRT_CHECK(wrt_json_get_hex(&j, d, "ke", &ke, &kn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, d, "ki", &ki, &in) == 0);
		WRT_CHECK(kn == 32 && in == 24);
		kdf_check(sec, sn, usage, ke, ki);
		free(ke);
		free(ki);
	}

	vecs = wrt_json_get(&j, root, "vectors");
	nv = wrt_json_count(&j, vecs);
	WRT_CHECK(nv == 30);
	for (i = 0; i < nv; i++) {
		wrt_tok v = wrt_json_at(&j, vecs, i);
		uint8_t *conf = NULL, *pt = NULL, *ct = NULL, *out;
		size_t cn = 0, pn = 0, tn = 0, on = 99;
		int ok = 0;
		uint32_t usage = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, v, "usage"), &ok);

		WRT_CHECK(wrt_json_get_hex(&j, v, "confounder", &conf, &cn) == 0 && cn == 16);
		WRT_CHECK(wrt_json_get_hex(&j, v, "plaintext", &pt, &pn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, v, "ciphertext_with_mac", &ct, &tn) == 0);
		WRT_CHECK(tn == pn + 40);

		ctx_init(&x, &f, NULL);
		rng_set(&f, conf, 16);
		out = heap_new(tn);
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, usage, pt, pn, out, tn, &on));
		WRT_CHECK(on == tn && f.calls == 1);
		WRT_CHECK_MEM(out, ct, tn);
		free(out);

		out = heap_new(tn - 24);
		on = 99;
		WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k, usage, ct, tn, out, tn - 24, &on));
		WRT_CHECK(on == pn);
		WRT_CHECK_MEM(out, pt, pn);
		free(out);
		free(conf);
		free(pt);
		free(ct);
	}

	envs = wrt_json_get(&j, root, "envelopes");
	for (i = 0; i < wrt_json_count(&j, envs); i++) {
		wrt_tok e = wrt_json_at(&j, envs, i);
		uint8_t *item = NULL, *sealed = NULL, *conf = NULL, *out, *scratch;
		size_t in_n = 0, sn2 = 0, cn = 0, on = 0, il = 0;
		const uint8_t *it = NULL;
		int ok = 0;
		uint32_t usage = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, e, "usage"), &ok);

		WRT_CHECK(wrt_json_get_hex(&j, e, "item", &item, &in_n) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, e, "confounder", &conf, &cn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, e, "sealed_length_prefixed", &sealed, &sn2) == 0);
		WRT_CHECK(sn2 >= 4 && wri_le32_get(sealed) == sn2 - 4);
		ctx_init(&x, &f, NULL);
		rng_set(&f, conf, cn);
		out = heap_new(sn2 - 4);
		WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&x, &k, usage, item, in_n, out, sn2 - 4, &on));
		WRT_CHECK(on == sn2 - 4);
		WRT_CHECK_MEM(out, sealed + 4, sn2 - 4);
		free(out);
		scratch = heap_new(sn2 - 4);
		WRT_CHECK_STATUS(WR_OK, wri_cx_open(&x, &k, usage, sealed + 4, sn2 - 4, scratch, sn2 - 4, &it, &il));
		WRT_CHECK(il == in_n);
		WRT_CHECK_MEM(it, item, in_n);
		/* the same ciphertext under another usage is refused */
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT,
				 wri_cx_open(&x, &k, usage + 1, sealed + 4, sn2 - 4, scratch, sn2 - 4, &it, &il));
		WRT_CHECK(it == NULL && il == 0);
		free(scratch);
		free(item);
		free(sealed);
		free(conf);
	}
	free(sec);
	wrt_json_free(&j);
}

static void test_rfc8009(void)
{
	wrt_json j;
	wrt_tok root, vecs;
	uint8_t *base = NULL, *ke = NULL, *ki = NULL;
	size_t bn = 0, kn = 0, in = 0, i;
	wr_key k;
	wri_ctx x;
	struct fake_rng f;

	if (wrt_json_load_vec(&j, "cephx/rfc8009-aes256-cts-hmac-sha384-192.json") != 0) {
		WRT_CHECK(0 && "rfc8009 vectors load");
		return;
	}
	root = wrt_json_root(&j);
	WRT_CHECK(wrt_json_get_hex(&j, root, "base_key", &base, &bn) == 0 && bn == 32);
	WRT_CHECK(wrt_json_get_hex(&j, root, "ke_usage2", &ke, &kn) == 0);
	WRT_CHECK(wrt_json_get_hex(&j, root, "ki_usage2", &ki, &in) == 0);
	kdf_check(base, bn, 2, ke, ki);
	k = mkkey(2, base, bn);
	vecs = wrt_json_get(&j, root, "vectors");
	WRT_CHECK(wrt_json_count(&j, vecs) == 4);
	for (i = 0; i < wrt_json_count(&j, vecs); i++) {
		wrt_tok v = wrt_json_at(&j, vecs, i);
		uint8_t *conf = NULL, *pt = NULL, *ct = NULL, *out;
		size_t cn = 0, pn = 0, tn = 0, on = 0;

		WRT_CHECK(wrt_json_get_hex(&j, v, "confounder", &conf, &cn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, v, "plaintext", &pt, &pn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, v, "ciphertext", &ct, &tn) == 0);
		ctx_init(&x, &f, NULL);
		rng_set(&f, conf, cn);
		out = heap_new(tn);
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 2, pt, pn, out, tn, &on));
		WRT_CHECK(on == tn);
		WRT_CHECK_MEM(out, ct, tn);
		free(out);
		out = heap_new(tn - 24);
		WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k, 2, ct, tn, out, tn - 24, &on));
		WRT_CHECK(on == pn);
		WRT_CHECK_MEM(out, pt, pn);
		free(out);
		free(conf);
		free(pt);
		free(ct);
	}
	free(base);
	free(ke);
	free(ki);
	wrt_json_free(&j);
}

/* A "0x..." string member as an unsigned 64-bit value (wrt_json_int would saturate above 2^63). */
static uint64_t json_u64(const wrt_json *j, wrt_tok obj, const char *key)
{
	char *s = wrt_json_strdup(j, wrt_json_get(j, obj, key));
	uint64_t v = 0;

	WRT_CHECK(s != NULL);
	if (s != NULL) {
		v = (uint64_t)strtoull(s, NULL, 0);
		free(s);
	}
	return v;
}

static void test_challenge_proof(void)
{
	wrt_json j;
	wrt_tok root, vecs;
	size_t i;
	wri_ctx x;
	struct fake_rng f;

	ctx_init(&x, &f, NULL);
	if (wrt_json_load_vec(&j, "cephx/challenge-proof.json") != 0) {
		WRT_CHECK(0 && "challenge-proof.json loads");
		return;
	}
	root = wrt_json_root(&j);
	vecs = wrt_json_get(&j, root, "vectors");
	WRT_CHECK(wrt_json_count(&j, vecs) == 2);
	for (i = 0; i < wrt_json_count(&j, vecs); i++) {
		wrt_tok v = wrt_json_at(&j, vecs, i);
		uint8_t *sec = NULL;
		size_t sn = 0;
		int ok = 0;
		unsigned type = (unsigned)wrt_json_int(&j, wrt_json_get(&j, v, "key_type"), &ok);
		uint64_t sc = json_u64(&j, v, "server_challenge");
		uint64_t cc = json_u64(&j, v, "client_challenge");
		uint64_t want = json_u64(&j, v, "proof");
		uint64_t got = 1, again = 2;
		wr_key k;

		WRT_CHECK(wrt_json_get_hex(&j, v, "key_secret", &sec, &sn) == 0);
		k = mkkey(type, sec, sn);
		WRT_CHECK_STATUS(WR_OK, wri_cx_challenge_proof(&x, &k, sc, cc, &got));
		WRT_CHECK_U64(got, want);
		WRT_CHECK_STATUS(WR_OK, wri_cx_challenge_proof(&x, &k, sc, cc, &again));
		WRT_CHECK_U64(again, got); /* deterministic for both types */
		WRT_CHECK(f.calls == 0);
		if (type == 1) {
			uint8_t *lp = NULL;
			size_t ln = 0;
			uint64_t acc = 0;
			int w;

			WRT_CHECK(wrt_json_get_hex(&j, v, "length_prefixed_ciphertext_36_bytes", &lp, &ln) == 0);
			WRT_CHECK(ln == 36);
			for (w = 0; w < 4; w++)
				acc ^= wri_le64_get(lp + 8 * w);
			WRT_CHECK_U64(acc, want);
			free(lp);
		}
		free(sec);
	}
	wrt_json_free(&j);

	/* swapping the two challenges changes the proof; a bad key and a NULL output are refused */
	{
		wr_key k1 = seq_key(1, 16), k2 = seq_key(2, 32), bad = k1;
		uint64_t a = 0, b = 0;

		WRT_CHECK(wri_cx_challenge_proof(&x, &k1, 1, 2, &a) == WR_OK);
		WRT_CHECK(wri_cx_challenge_proof(&x, &k1, 2, 1, &b) == WR_OK && a != b);
		WRT_CHECK(wri_cx_challenge_proof(&x, &k2, 1, 2, &a) == WR_OK);
		WRT_CHECK(wri_cx_challenge_proof(&x, &k2, 2, 1, &b) == WR_OK && a != b);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_challenge_proof(&x, &k1, 1, 2, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_challenge_proof(&x, NULL, 1, 2, &a));
		bad.type = 7;
		WRT_CHECK_STATUS(WR_E_AUTH_KEY_TYPE, wri_cx_challenge_proof(&x, &bad, 1, 2, &a));
		WRT_CHECK(a == 0);
		bad = k2;
		bad.len = 31;
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cx_challenge_proof(&x, &bad, 1, 2, &a));
	}
}

/* ---- tamper, errors, edge cases --------------------------------------------------------------- */

static void test_roundtrip_and_wrong_key(void)
{
	wri_ctx x;
	struct fake_rng f;
	unsigned type;
	size_t n, trial;

	ctx_init(&x, &f, NULL);
	for (type = 1; type <= 2; type++) {
		for (n = 0; n <= 200; n += (n < 40 ? 1 : 7)) {
			wr_key k = seq_key(type, type == 1 ? 16 : 32);
			uint8_t pt[200], *ct, *out;
			size_t cl = wri_cx_cipher_len(type, n), on = 0, w = (type == 1 ? cl : cl - 24);

			rnd_fill(pt, sizeof(pt));
			ct = heap_new(cl);
			WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 0x10, pt, n, ct, cl, &on));
			WRT_CHECK(on == cl);
			out = heap_new(w);
			WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k, 0x10, ct, cl, out, w, &on));
			WRT_CHECK(on == n);
			WRT_CHECK_MEM(out, pt, n);
			free(out);
			free(ct);
		}
	}

	/* type 2: another usage or another key never verifies; type 1: usage is ignored */
	{
		wr_key k2 = seq_key(2, 32), o2 = seq_key(2, 32), k1 = seq_key(1, 16);
		uint8_t pt[40], ct[80], out[80];
		size_t on = 0, cl = 0;

		o2.secret[31] ^= 1;
		rnd_fill(pt, sizeof(pt));
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k2, 5, pt, 40, ct, sizeof(ct), &cl));
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k2, 6, ct, cl, out, sizeof(out), &on));
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &o2, 5, ct, cl, out, sizeof(out), &on));
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k1, 5, pt, 40, ct, sizeof(ct), &cl));
		WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k1, 6, ct, cl, out, sizeof(out), &on));
		WRT_CHECK(on == 40);
	}

	/* a longer type-2 secret uses all of it: changing a byte beyond 32 changes the result */
	{
		wr_key a = seq_key(2, 40), b = seq_key(2, 40);
		uint8_t pt[10] = {1, 2, 3}, c1[50], c2[50], conf[16] = {9};
		size_t n1 = 0, n2 = 0;

		b.secret[39] ^= 0x80;
		rng_set(&f, conf, 16);
		WRT_CHECK(wri_cx_encrypt(&x, &a, 3, pt, 10, c1, sizeof(c1), &n1) == WR_OK);
		rng_set(&f, conf, 16);
		WRT_CHECK(wri_cx_encrypt(&x, &b, 3, pt, 10, c2, sizeof(c2), &n2) == WR_OK);
		WRT_CHECK(n1 == 50 && n2 == 50 && memcmp(c1, c2, 50) != 0);
	}

	/* open under a wrong key: the magic catches it for both types */
	for (type = 1; type <= 2; type++) {
		wr_key k = seq_key(type, type == 1 ? 16 : 32);
		unsigned fails = 0;

		for (trial = 0; trial < 300; trial++) {
			wr_key o = k;
			uint8_t item[24], ct[128], scratch[128];
			const uint8_t *it = NULL;
			size_t cl = 0, il = 0;

			rnd_fill(item, sizeof(item));
			rnd_fill(o.secret, o.len);
			WRT_CHECK(wri_cx_seal(&x, &k, 0x12, item, sizeof(item), ct, sizeof(ct), &cl) == WR_OK);
			if (wri_cx_open(&x, &o, 0x12, ct, cl, scratch, sizeof(scratch), &it, &il) == WR_E_AUTH_DECRYPT) {
				fails++;
				WRT_CHECK(it == NULL && il == 0);
			}
		}
		WRT_CHECK(fails == 300);
	}
}

static void test_type2_tamper(void)
{
	wri_ctx x;
	struct fake_rng f;
	struct spy s;
	wr_prim_ops po;
	wr_key k = seq_key(2, 32);
	uint8_t pt[45], ct[85], out[85];
	size_t cl = 0, on = 0, i, bit;

	spy_init(&po, &s);
	ctx_init(&x, &f, &po);
	rnd_fill(pt, sizeof(pt));
	WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 0x04, pt, sizeof(pt), ct, sizeof(ct), &cl));
	WRT_CHECK(cl == 85);
	WRT_CHECK(s.cbc_enc >= 1 && s.h384 >= 3); /* the overrides were used: 2 KDF + 1 MAC */
	WRT_CHECK(s.h256 == 0);
	WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k, 0x04, ct, cl, out, sizeof(out), &on));

	for (i = 0; i < cl; i++) {
		for (bit = 0; bit < 8; bit++) {
			uint8_t c2[85];

			memcpy(c2, ct, cl);
			c2[i] ^= (uint8_t)(1u << bit);
			memset(out, 0xEE, sizeof(out));
			s.cbc_dec = 0;
			on = 77;
			WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, 0x04, c2, cl, out, sizeof(out), &on));
			WRT_CHECK(on == 0);
			WRT_CHECK(s.cbc_dec == 0); /* MAC first: nothing was decrypted */
			if (bit == 0)
				WRT_CHECK(all_zero(out, cl - 24)); /* work area wiped; the rest untouched */
		}
	}
	/* truncated and extended ciphertexts */
	for (i = 0; i < cl; i++) {
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, 0x04, ct, i, out, sizeof(out), &on));
	}
	{
		uint8_t big[86];

		memcpy(big, ct, cl);
		big[85] = 0;
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, 0x04, big, 86, out, sizeof(out), &on));
	}
	/* the smallest valid message: empty plaintext, 40 bytes */
	WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 9, NULL, 0, ct, sizeof(ct), &cl));
	WRT_CHECK(cl == 40);
	WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k, 9, ct, cl, out, sizeof(out), &on));
	WRT_CHECK(on == 0);
}

static void test_type1_padding(void)
{
	wri_ctx x;
	struct fake_rng f;
	wr_key k = seq_key(1, 16);
	wri_aes_ctx a;
	static const uint8_t iv[16] = "cephsageyudagreg";
	size_t on = 0, i;
	uint8_t plain[32], ct[32], out[32];

	ctx_init(&x, &f, NULL);
	WRT_CHECK(wri_aes_setkey(&a, k.secret, 16) == WR_OK);

	/* handcrafted last bytes: pad 0, 17, 255 and a run that is not all the same byte */
	for (i = 0; i < 4; i++) {
		static const uint8_t last[4] = {0, 17, 255, 3};

		memset(plain, 0x41, sizeof(plain));
		plain[31] = last[i];
		if (i == 3) {
			plain[30] = 3;
			plain[29] = 4; /* claims 3 pad bytes, but 29 is not 3 */
		}
		wri_aes_cbc_enc(&a, iv, plain, ct, 2);
		memset(out, 0, sizeof(out));
		on = 55;
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, 0, ct, 32, out, 32, &on));
		WRT_CHECK(on == 0 && all_zero(out, 32));
	}
	/* a good pad of every length 1..16 */
	for (i = 1; i <= 16; i++) {
		size_t pn = 32 - i;

		memset(plain, 0x41, sizeof(plain));
		memset(plain + pn, (int)i, i);
		wri_aes_cbc_enc(&a, iv, plain, ct, 2);
		WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k, 0, ct, 32, out, 32, &on));
		WRT_CHECK(on == pn);
	}
	/* lengths that are not a non-zero multiple of 16 */
	{
		uint8_t big[48] = {0};
		static const size_t bad[] = {0, 1, 15, 17, 31, 33, 47};

		for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
			WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, 0, big, bad[i], out, sizeof(out), &on));
	}
	/* aligned plaintext gets a whole extra block */
	{
		uint8_t pt16[16] = {0}, c[32];

		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 0, pt16, 16, c, 32, &on));
		WRT_CHECK(on == 32);
	}
}

static void test_caps_overlap_and_failures(void)
{
	wri_ctx x;
	struct fake_rng f;
	unsigned type;

	ctx_init(&x, &f, NULL);
	for (type = 1; type <= 2; type++) {
		wr_key k = seq_key(type, type == 1 ? 16 : 32);
		size_t n, on = 123;

		for (n = 0; n <= 70; n += 5) {
			size_t cl = wri_cx_cipher_len(type, n), w = type == 1 ? cl : cl - 24, cap;
			uint8_t pt[80], *ct, *out;

			rnd_fill(pt, sizeof(pt));
			ct = heap_new(cl);
			WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 1, pt, n, ct, cl, &on));
			for (cap = 0; cap < cl; cap++) { /* encrypt: every short output refused, untouched */
				uint8_t *o = heap_new(cap);

				on = 123;
				WRT_CHECK_STATUS(WR_E_TOOBIG, wri_cx_encrypt(&x, &k, 1, pt, n, o, cap, &on));
				WRT_CHECK(on == 0 && all_zero(o, cap));
				free(o);
			}
			for (cap = 0; cap < w; cap++) { /* decrypt */
				uint8_t *o = heap_new(cap);

				on = 123;
				WRT_CHECK_STATUS(WR_E_TOOBIG, wri_cx_decrypt(&x, &k, 1, ct, cl, o, cap, &on));
				WRT_CHECK(on == 0 && all_zero(o, cap));
				free(o);
			}
			out = heap_new(w);
			WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k, 1, ct, cl, out, w, &on));
			free(out);
			free(ct);
		}
		{
			uint8_t buf[200];
			size_t cl = 0;

			memset(buf, 0, sizeof(buf));
			rnd_fill(buf, 48);
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_encrypt(&x, &k, 1, buf, 20, buf, sizeof(buf), &cl)); /* in == out */
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_encrypt(&x, &k, 1, buf, 20, buf + 5, 100, &cl));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_encrypt(&x, &k, 1, buf + 30, 20, buf, 60, &cl));
			WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 1, buf, 20, buf + 100, 100, &cl));
			WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 1, buf, 20, buf + 100, 100, &cl));
			rnd_fill(buf, 80);
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_decrypt(&x, &k, 1, buf, 80, buf, 80, &cl));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_decrypt(&x, &k, 1, buf, 80, buf + 8, 80, &cl));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_decrypt(&x, &k, 1, buf + 8, 64, buf, 20, &cl));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_encrypt(&x, &k, 1, buf, 1, NULL, 100, &cl));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_encrypt(&x, &k, 1, NULL, 1, buf, 100, &cl));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_encrypt(&x, &k, 1, buf, 1, buf + 100, 100, NULL));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_decrypt(&x, &k, 1, buf, 80, buf + 100, 100, NULL));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_decrypt(&x, NULL, 1, buf, 80, buf + 100, 100, &cl));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_encrypt(&x, NULL, 1, buf, 80, buf + 100, 100, &cl));
		}
		/* absurd length: refused before any pointer is followed */
		{
			uint8_t b[4];
			size_t cl = 0;

			WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_cx_encrypt(&x, &k, 1, b, SIZE_MAX - 3, b, 4, &cl));
			WRT_CHECK_STATUS(WR_E_TOOBIG, wri_cx_decrypt(&x, &k, 1, b, SIZE_MAX & ~(size_t)15, b + 4, 0, &cl));
		}
	}

	/* host random: failing, missing, and the output is not left holding plaintext */
	{
		wr_key k = seq_key(2, 32);
		uint8_t pt[20], out[60];
		size_t on = 5;
		wri_ctx nox;

		rnd_fill(pt, sizeof(pt));
		f.fail = 1;
		memset(out, 0xCC, sizeof(out));
		WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_cx_encrypt(&x, &k, 1, pt, 20, out, sizeof(out), &on));
		WRT_CHECK(on == 0 && all_zero(out, 60));
		f.fail = 0;
		nox = x;
		nox.host.random = NULL;
		WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_cx_encrypt(&nox, &k, 1, pt, 20, out, sizeof(out), &on));
		WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_cx_encrypt(NULL, &k, 1, pt, 20, out, sizeof(out), &on));
		{
			uint8_t big[100];

			WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_cx_seal(NULL, &k, 1, pt, 20, big, sizeof(big), &on));
		}
		/* type 1 and decrypt work without a context */
		{
			wr_key k1 = seq_key(1, 16);
			uint8_t c[48], p[48];
			size_t cn = 0, pn = 0;

			WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(NULL, &k1, 0, pt, 20, c, sizeof(c), &cn));
			WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(NULL, &k1, 0, c, cn, p, sizeof(p), &pn));
			WRT_CHECK(pn == 20 && memcmp(p, pt, 20) == 0);
		}
	}

	/* bad keys */
	{
		wr_key k = seq_key(1, 16);
		uint8_t b[64] = {0}, o[64];
		size_t on = 0;

		k.type = 0;
		WRT_CHECK_STATUS(WR_E_AUTH_KEY_TYPE, wri_cx_encrypt(&x, &k, 1, b, 4, o, sizeof(o), &on));
		k.type = 3;
		WRT_CHECK_STATUS(WR_E_AUTH_KEY_TYPE, wri_cx_decrypt(&x, &k, 1, b, 32, o, sizeof(o), &on));
		k.type = 1;
		k.len = 15;
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cx_encrypt(&x, &k, 1, b, 4, o, sizeof(o), &on));
		k.type = 2;
		k.len = 31;
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cx_decrypt(&x, &k, 1, b, 64, o, sizeof(o), &on));
		k.len = 65; /* beyond the storage: never read */
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cx_encrypt(&x, &k, 1, b, 4, o, sizeof(o), &on));
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cx_seal(&x, &k, 1, b, 4, o, sizeof(o), &on));
	}
}

static void test_override_dispatch(void)
{
	wri_ctx x;
	struct fake_rng f;
	struct spy s;
	wr_prim_ops po;
	wr_key k1 = seq_key(1, 16), k2 = seq_key(2, 32);
	uint8_t pt[33], ct[100], out[100];
	size_t cl = 0, on = 0;
	uint64_t pr = 0;

	spy_init(&po, &s);
	ctx_init(&x, &f, &po);
	rnd_fill(pt, sizeof(pt));
	WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k1, 0, pt, 33, ct, sizeof(ct), &cl));
	WRT_CHECK(s.cbc_enc == 1 && s.h384 == 0);
	WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k1, 0, ct, cl, out, sizeof(out), &on));
	WRT_CHECK(s.cbc_dec == 1 && on == 33 && memcmp(out, pt, 33) == 0);
	WRT_CHECK_STATUS(WR_OK, wri_cx_challenge_proof(&x, &k1, 1, 2, &pr));
	WRT_CHECK(s.cbc_enc == 2);
	memset(&s, 0, sizeof(s));
	WRT_CHECK_STATUS(WR_OK, wri_cx_challenge_proof(&x, &k2, 1, 2, &pr));
	WRT_CHECK(s.h256 == 1);
	WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k2, 4, pt, 33, ct, sizeof(ct), &cl));
	WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k2, 4, ct, cl, out, sizeof(out), &on));
	WRT_CHECK(on == 33 && memcmp(out, pt, 33) == 0);
	WRT_CHECK(s.h384 == 3 + 3); /* encrypt: Ke, Ki, MAC; decrypt: Ki, MAC, Ke */
	/* the proof of a type-2 key is the same with and without the override */
	{
		wri_ctx plain;
		struct fake_rng f2;
		uint64_t pr2 = 1;

		ctx_init(&plain, &f2, NULL);
		WRT_CHECK_STATUS(WR_OK, wri_cx_challenge_proof(&plain, &k2, 1, 2, &pr2));
		WRT_CHECK_U64(pr2, pr);
	}
}

static void test_kdf_edges(void)
{
	uint8_t a[64], b[48], c[24];
	uint8_t base[32];
	size_t i;

	for (i = 0; i < sizeof(base); i++)
		base[i] = (uint8_t)(i * 3);
	memset(a, 0x55, sizeof(a));
	wri_cx_kdf(NULL, base, sizeof(base), 1, 0xAA, a, 0); /* nothing written */
	WRT_CHECK(a[0] == 0x55);
	wri_cx_kdf(NULL, base, sizeof(base), 1, 0xAA, a, 49); /* too long: zero-filled, never partial */
	WRT_CHECK(all_zero(a, 49) && a[49] == 0x55);
	wri_cx_kdf(NULL, base, sizeof(base), 1, 0x55, b, 48);
	wri_cx_kdf(NULL, base, sizeof(base), 1, 0x55, c, 24);
	WRT_CHECK(memcmp(b, c, 24) != 0); /* the length is part of the label: not a prefix */
	wri_cx_kdf(NULL, base, sizeof(base), 2, 0x55, c, 24);
	WRT_CHECK(memcmp(b, c, 24) != 0); /* the usage is part of it too */
}

static void test_envelope_edges(void)
{
	wri_ctx x;
	struct fake_rng f;
	unsigned type;

	ctx_init(&x, &f, NULL);
	for (type = 1; type <= 2; type++) {
		wr_key k = seq_key(type, type == 1 ? 16 : 32);
		uint8_t item[50], ct[200], scratch[200], buf[300], *heap;
		const uint8_t *it = (const uint8_t *)1;
		size_t cl = 0, il = 99, need, i;

		rnd_fill(item, sizeof(item));
		WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&x, &k, 0x10, item, 50, ct, sizeof(ct), &cl));
		WRT_CHECK(cl == wri_cx_cipher_len(type, 59));
		WRT_CHECK_STATUS(WR_OK, wri_cx_open(&x, &k, 0x10, ct, cl, scratch, sizeof(scratch), &it, &il));
		WRT_CHECK(il == 50 && memcmp(it, item, 50) == 0);

		/* scratch too small: refused, nothing written */
		memset(scratch, 0, sizeof(scratch));
		heap = heap_new(cl - 25);
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_cx_open(&x, &k, 0x10, ct, cl, heap, cl - 25, &it, &il));
		WRT_CHECK(it == NULL && il == 0);
		free(heap);
		/* scratch overlapping the ciphertext */
		memcpy(buf, ct, cl);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_open(&x, &k, 0x10, buf, cl, buf, cl + 10, &it, &il));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_open(&x, &k, 0x10, buf, cl, buf + 5, 150, &it, &il));
		WRT_CHECK(it == NULL);
		/* NULL result pointers */
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_open(&x, &k, 0x10, ct, cl, scratch, sizeof(scratch), NULL, &il));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_open(&x, &k, 0x10, ct, cl, scratch, sizeof(scratch), &it, NULL));

		/* seal: out too small at every size; item overlapping out; item_len overflow */
		need = cl;
		for (i = 0; i < need; i++) {
			uint8_t *o = heap_new(i);

			WRT_CHECK_STATUS(WR_E_TOOBIG, wri_cx_seal(&x, &k, 1, item, 50, o, i, &cl));
			WRT_CHECK(cl == 0 && all_zero(o, i));
			free(o);
		}
		memcpy(buf, item, 50);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_seal(&x, &k, 1, buf, 50, buf, sizeof(buf), &cl));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_seal(&x, &k, 1, buf + 10, 20, buf, sizeof(buf), &cl));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_seal(&x, &k, 1, buf, 20, buf + 10, sizeof(buf) - 10, &cl));
		WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_cx_seal(&x, &k, 1, buf, SIZE_MAX - 4, ct, sizeof(ct), &cl));
		WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_cx_seal(&x, &k, 1, buf, SIZE_MAX, ct, sizeof(ct), &cl));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_seal(&x, &k, 1, NULL, 3, ct, sizeof(ct), &cl));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_seal(&x, &k, 1, item, 3, ct, sizeof(ct), NULL));
		/* an empty item with a NULL pointer is fine and opens to an empty item */
		WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&x, &k, 1, NULL, 0, ct, sizeof(ct), &cl));
		WRT_CHECK(cl == wri_cx_cipher_len(type, 9));
		WRT_CHECK_STATUS(WR_OK, wri_cx_open(&x, &k, 1, ct, cl, scratch, sizeof(scratch), &it, &il));
		WRT_CHECK(il == 0 && it == scratch + 9);
	}

	/* hand-built plaintexts: wrong magic, short body, any version byte; a failed open wipes scratch */
	for (type = 1; type <= 2; type++) {
		wr_key k = seq_key(type, type == 1 ? 16 : 32);
		uint8_t plain[40], ct[100], scratch[100];
		const uint8_t *it = NULL;
		size_t cl = 0, il = 0, i;

		memset(plain, 0x5A, sizeof(plain));
		plain[0] = 1;
		wri_le64_put(plain + 1, WRI_CX_MAGIC);
		plain[9] = 0x42;
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 7, plain, 10, ct, sizeof(ct), &cl));
		WRT_CHECK_STATUS(WR_OK, wri_cx_open(&x, &k, 7, ct, cl, scratch, sizeof(scratch), &it, &il));
		WRT_CHECK(il == 1 && it[0] == 0x42);

		plain[0] = 77; /* the version byte is not checked */
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 7, plain, 10, ct, sizeof(ct), &cl));
		WRT_CHECK_STATUS(WR_OK, wri_cx_open(&x, &k, 7, ct, cl, scratch, sizeof(scratch), &it, &il));

		for (i = 1; i < 9; i++) { /* every magic byte matters */
			plain[0] = 1;
			plain[i] ^= 0x01;
			WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 7, plain, 10, ct, sizeof(ct), &cl));
			memset(scratch, 0xEE, sizeof(scratch));
			WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_open(&x, &k, 7, ct, cl, scratch, sizeof(scratch), &it, &il));
			WRT_CHECK(it == NULL && il == 0 && all_zero(scratch, type == 1 ? cl : cl - 24));
			plain[i] ^= 0x01;
		}
		for (i = 0; i < 9; i++) { /* a body shorter than the 9-byte header */
			WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 7, plain, i, ct, sizeof(ct), &cl));
			WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_open(&x, &k, 7, ct, cl, scratch, sizeof(scratch), &it, &il));
			WRT_CHECK(it == NULL && il == 0);
		}
	}
}

/* ---- review additions: boundaries, padding runs, long keys, short MACed frames ------------------- */

/* Two regions overlapping by exactly one byte are refused, regions that merely touch are accepted. */
static void test_overlap_boundaries(void)
{
	wri_ctx x;
	struct fake_rng f;
	unsigned type;

	ctx_init(&x, &f, NULL);
	for (type = 1; type <= 2; type++) {
		wr_key k = seq_key(type, type == 1 ? 16 : 32);
		const size_t n = 20, need = wri_cx_cipher_len(type, n), w = type == 1 ? need : need - 24;
		const size_t seal_need = wri_cx_cipher_len(type, n + 9);
		uint8_t buf[400], ct[200];
		size_t on = 0, il = 0;
		const uint8_t *it;

		memset(buf, 0, sizeof(buf));
		rnd_fill(buf, sizeof(buf));
		/* encrypt: in = buf + 100 .. +n, out of `need` bytes */
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_encrypt(&x, &k, 1, buf + 100, n, buf + 100 + n - 1, need, &on));
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 1, buf + 100, n, buf + 100 + n, need, &on));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_encrypt(&x, &k, 1, buf + 100 + need - 1, n, buf + 100, need, &on));
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 1, buf + 100 + need, n, buf + 100, need, &on));
		/* decrypt: the out region is out_cap bytes long, whatever the result length; random bytes are
		 * not a valid ciphertext, so a call that gets past the overlap check ends in AUTH_DECRYPT */
		rnd_fill(buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_decrypt(&x, &k, 1, buf + 100, need, buf + 100 + need - 1, w, &on));
		WRT_CHECK(on == 0);
		WRT_CHECK(wri_cx_decrypt(&x, &k, 1, buf + 100, need, buf + 100 + need, w, &on) != WR_E_INVAL);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_decrypt(&x, &k, 1, buf + 100 + w - 1, need, buf + 100, w, &on));
		WRT_CHECK(wri_cx_decrypt(&x, &k, 1, buf + 100 + w, need, buf + 100, w, &on) != WR_E_INVAL);
		/* seal: item of 20 bytes, out of seal_need bytes */
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_seal(&x, &k, 1, buf + 100, n, buf + 100 + n - 1, seal_need, &on));
		WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&x, &k, 1, buf + 100, n, buf + 100 + n, seal_need, &on));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_seal(&x, &k, 1, buf + 100 + seal_need - 1, n, buf + 100, seal_need, &on));
		WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&x, &k, 1, buf + 100 + seal_need, n, buf + 100, seal_need, &on));
		/* open: ciphertext and scratch */
		WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&x, &k, 1, buf, n, ct, sizeof(ct), &on));
		memcpy(buf + 100, ct, on);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_open(&x, &k, 1, buf + 100, on, buf + 100 + on - 1, 100, &it, &il));
		WRT_CHECK(it == NULL);
	}
}

/* wri_cx_encrypt_at, the in-place entry the envelope builder uses, on its own. */
static void test_encrypt_at(void)
{
	wri_ctx x;
	struct fake_rng f;
	unsigned type;

	ctx_init(&x, &f, NULL);
	for (type = 1; type <= 2; type++) {
		wr_key k = seq_key(type, type == 1 ? 16 : 32);
		const size_t n = 21, lead = wri_cx_enc_lead(type), need = wri_cx_cipher_len(type, n);
		uint8_t *buf = heap_new(need), pt[21], *ref = heap_new(need);
		size_t on = 77;

		rnd_fill(pt, sizeof(pt));
		WRT_CHECK(lead == (type == 1 ? 0u : 16u));
		memcpy(buf + lead, pt, n);
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt_at(&x, &k, 5, buf, need, n, &on));
		WRT_CHECK(on == need);
		/* the same bytes as the copying entry point (a fresh fake rng gives the same confounder) */
		ctx_init(&x, &f, NULL);
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 5, pt, n, ref, need, &on));
		WRT_CHECK(on == need && memcmp(buf, ref, need) == 0);
		free(ref);
		free(buf);

		/* one byte short: refused whatever else is wrong with nothing */
		buf = heap_new(need - 1);
		on = 77;
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_cx_encrypt_at(&x, &k, 5, buf, need - 1, n, &on));
		WRT_CHECK(on == 0);
		on = 77;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_encrypt_at(&x, &k, 5, buf, need - 1, n, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_encrypt_at(&x, &k, 5, NULL, need, n, &on));
		WRT_CHECK(on == 0);
		WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_cx_encrypt_at(&x, &k, 5, buf, need - 1, SIZE_MAX - 3, &on));
		free(buf);

		/* a failing random leaves the whole area zero, plaintext included */
		buf = heap_new(need);
		memcpy(buf + lead, pt, n);
		f.fail = 1;
		if (type == 2) {
			WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_cx_encrypt_at(&x, &k, 5, buf, need, n, &on));
			WRT_CHECK(on == 0 && all_zero(buf, need));
		}
		f.fail = 0;
		free(buf);
	}
}

/* Type-1 padding: runs of 17 and 255, the first byte of a run, the byte before it, a single block. */
static void test_type1_pad_runs(void)
{
	wri_ctx x;
	struct fake_rng f;
	wr_key k = seq_key(1, 16);
	wri_aes_ctx a;
	static const uint8_t iv[16] = "cephsageyudagreg";
	uint8_t plain[32], ct[32], out[32];
	size_t on = 0, i;

	ctx_init(&x, &f, NULL);
	WRT_CHECK(wri_aes_setkey(&a, k.secret, 16) == WR_OK);

	/* 17 equal bytes of value 17 at the end of two blocks: a pad of 17 does not exist */
	memset(plain, 0x41, sizeof(plain));
	memset(plain + 15, 17, 17);
	wri_aes_cbc_enc(&a, iv, plain, ct, 2);
	on = 9;
	WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, 0, ct, 32, out, 32, &on));
	WRT_CHECK(on == 0 && all_zero(out, 32));
	/* the same for one block, where n - pad would wrap */
	for (i = 0; i < 3; i++) {
		static const uint8_t last[3] = {17, 255, 0};

		memset(plain, last[i], 16);
		wri_aes_cbc_enc(&a, iv, plain, ct, 1);
		on = 9;
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, 0, ct, 16, out, 16, &on));
		WRT_CHECK(on == 0 && all_zero(out, 16));
	}
	/* a full block of 16 is the whole padding: an empty plaintext */
	memset(plain, 16, 16);
	wri_aes_cbc_enc(&a, iv, plain, ct, 1);
	WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k, 0, ct, 16, out, 16, &on));
	WRT_CHECK(on == 0);
	/* 255 equal bytes cannot be 16 equal bytes of anything but 16 */
	memset(plain, 255, 32);
	wri_aes_cbc_enc(&a, iv, plain, ct, 2);
	WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, 0, ct, 32, out, 32, &on));

	for (i = 2; i <= 16; i++) { /* the first byte of the run is wrong: refused */
		memset(plain, 0x41, sizeof(plain));
		memset(plain + 32 - i, (int)i, i);
		plain[32 - i] = (uint8_t)(i ^ 0x80);
		wri_aes_cbc_enc(&a, iv, plain, ct, 2);
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, 0, ct, 32, out, 32, &on));
		/* every other byte of the run wrong, one at a time */
		{
			size_t j;

			for (j = 1; j < i - 1; j++) {
				memset(plain + 32 - i, (int)i, i);
				plain[32 - i + j] ^= 0x01;
				wri_aes_cbc_enc(&a, iv, plain, ct, 2);
				WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, 0, ct, 32, out, 32, &on));
			}
		}
		/* the byte just before the run is not part of it and may be anything */
		memset(plain, 0x41, sizeof(plain));
		memset(plain + 32 - i, (int)i, i);
		plain[32 - i - 1] = (uint8_t)(i ^ 0x5A);
		wri_aes_cbc_enc(&a, iv, plain, ct, 2);
		WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k, 0, ct, 32, out, 32, &on));
		WRT_CHECK(on == 32 - i);
	}
}

/* Type-2 decrypt: nothing of the confounder lingers; a short body behind a VALID MAC is still refused. */
static void test_type2_tail_and_short(void)
{
	wri_ctx x;
	struct fake_rng f;
	wr_key k = seq_key(2, 32);
	uint8_t ki[24], full[48], ct[64], *out, pt[20];
	size_t on = 0, n, w;
	wr_iov iov[2];
	static const uint8_t zero16[16] = {0};
	const uint32_t usage = 0x11;

	ctx_init(&x, &f, NULL);
	rnd_fill(pt, sizeof(pt));
	WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, usage, pt, 20, ct, sizeof(ct), &on));
	WRT_CHECK(on == 60);
	w = 60 - 24;
	out = heap_new(w);
	memset(out, 0xEE, w);
	WRT_CHECK_STATUS(WR_OK, wri_cx_decrypt(&x, &k, usage, ct, 60, out, w, &on));
	WRT_CHECK(on == 20 && memcmp(out, pt, 20) == 0);
	WRT_CHECK(all_zero(out + 20, w - 20)); /* the 16 bytes the shift left behind are wiped */
	free(out);

	/* a body of 0..15 bytes with a correct MAC over it: the cipher needs 16, so refused, not decrypted */
	wri_cx_kdf(NULL, k.secret, k.len, usage, 0x55, ki, sizeof(ki));
	for (n = 24; n < 40; n++) {
		size_t m = n - 24;
		uint8_t frame[40];

		rnd_fill(frame, m);
		iov[0].base = zero16;
		iov[0].len = 16;
		iov[1].base = frame;
		iov[1].len = m;
		wri_hmac_sha384(ki, sizeof(ki), iov, 2, full);
		memcpy(frame + m, full, 24);
		out = heap_new(m != 0 ? m : 1);
		on = 5;
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, usage, frame, n, out, m, &on));
		WRT_CHECK(on == 0);
		free(out);
	}
	/* n < 24 can never carry a MAC */
	for (n = 0; n < 24; n++) {
		uint8_t frame[24] = {0};

		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &k, usage, frame, n, ct, sizeof(ct), &on));
	}
	/* the working area may not be NULL when it has a size */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_decrypt(&x, &k, usage, ct, 60, NULL, 36, &on));
	{
		wr_key k1 = seq_key(1, 16);

		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_decrypt(&x, &k1, usage, ct, 32, NULL, 32, &on));
	}
}

/* Secrets longer than the minimum: type 2 uses every stored byte, type 1 only the first 16. */
static void test_long_keys(void)
{
	wri_ctx x;
	struct fake_rng f;
	size_t len;

	ctx_init(&x, &f, NULL);
	for (len = 33; len <= WR_KEY_MAX; len += 15) {
		wr_key k = seq_key(2, len), kshort = seq_key(2, 32);
		uint8_t pt[40], ct[100], out[100], ke[32], ki[24], mac[48];
		static const uint8_t zero16[16] = {0};
		size_t cl = 0, on = 0;
		wr_iov iov[2];
		uint64_t proof = 0, p32 = 0, want = 0;
		uint8_t blob[16], h[32];
		size_t i;

		rnd_fill(pt, sizeof(pt));
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 0x04, pt, sizeof(pt), ct, sizeof(ct), &cl));
		WRT_CHECK(cl == 80);
		/* an outside check: derive both keys from the whole secret, verify the MAC, decrypt */
		wri_cx_kdf(NULL, k.secret, len, 0x04, 0x55, ki, sizeof(ki));
		wri_cx_kdf(NULL, k.secret, len, 0x04, 0xAA, ke, sizeof(ke));
		iov[0].base = zero16;
		iov[0].len = 16;
		iov[1].base = ct;
		iov[1].len = cl - 24;
		wri_hmac_sha384(ki, sizeof(ki), iov, 2, mac);
		WRT_CHECK(memcmp(mac, ct + cl - 24, 24) == 0);
		WRT_CHECK(wri_cts3_dec(NULL, ke, 32, zero16, ct, cl - 24, out) == WR_OK);
		WRT_CHECK(memcmp(out + 16, pt, sizeof(pt)) == 0);
		/* the first 32 bytes alone are a different key */
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_decrypt(&x, &kshort, 0x04, ct, cl, out, sizeof(out), &on));

		/* the challenge proof: HMAC-SHA256 over the whole secret */
		for (i = 0; i < 8; i++) {
			blob[i] = (uint8_t)(0x10 + i);
			blob[8 + i] = (uint8_t)(0x20 + i);
		}
		iov[0].base = blob;
		iov[0].len = 16;
		wri_hmac_sha256(k.secret, len, iov, 1, h);
		for (i = 0; i < 4; i++)
			want ^= wri_le64_get(h + 8 * i);
		WRT_CHECK_STATUS(WR_OK, wri_cx_challenge_proof(&x, &k, wri_le64_get(blob), wri_le64_get(blob + 8), &proof));
		WRT_CHECK(proof == want);
		WRT_CHECK_STATUS(WR_OK, wri_cx_challenge_proof(&x, &kshort, wri_le64_get(blob), wri_le64_get(blob + 8), &p32));
		WRT_CHECK(p32 != proof);
	}
	/* type 1: bytes 16 and up of a longer secret do not matter, for the cipher and for the proof */
	{
		wr_key a = seq_key(1, 16), b = seq_key(1, 40);
		uint8_t pt[30], c1[64], c2[64];
		size_t n1 = 0, n2 = 0;
		uint64_t pa = 0, pb = 0;

		rnd_fill(pt, sizeof(pt));
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &a, 0, pt, sizeof(pt), c1, sizeof(c1), &n1));
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &b, 0, pt, sizeof(pt), c2, sizeof(c2), &n2));
		WRT_CHECK(n1 == n2 && memcmp(c1, c2, n1) == 0);
		WRT_CHECK_STATUS(WR_OK, wri_cx_challenge_proof(&x, &a, 1, 2, &pa));
		WRT_CHECK_STATUS(WR_OK, wri_cx_challenge_proof(&x, &b, 1, 2, &pb));
		WRT_CHECK(pa == pb);
	}
}

/* Envelope: a plaintext one byte shorter than the header is refused even with the right bytes. */
static void test_envelope_short_header(void)
{
	wri_ctx x;
	struct fake_rng f;
	unsigned type;

	ctx_init(&x, &f, NULL);
	for (type = 1; type <= 2; type++) {
		wr_key k = seq_key(type, type == 1 ? 16 : 32);
		uint8_t plain[9], ct[64], scratch[64];
		const uint8_t *it = (const uint8_t *)1;
		size_t cl = 0, il = 5;

		plain[0] = 1;
		wri_le64_put(plain + 1, WRI_CX_MAGIC);
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 3, plain, 8, ct, sizeof(ct), &cl));
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_open(&x, &k, 3, ct, cl, scratch, sizeof(scratch), &it, &il));
		WRT_CHECK(it == NULL && il == 0);
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&x, &k, 3, plain, 9, ct, sizeof(ct), &cl));
		WRT_CHECK_STATUS(WR_OK, wri_cx_open(&x, &k, 3, ct, cl, scratch, sizeof(scratch), &it, &il));
		WRT_CHECK(il == 0 && it == scratch + 9);
		/* no scratch at all */
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_cx_open(&x, &k, 3, ct, cl, NULL, 0, &it, &il));
		WRT_CHECK(it == NULL && il == 0);
	}
}

int main(void)
{
	test_cipher_len();
	test_type1_vectors();
	test_type2_vectors();
	test_rfc8009();
	test_challenge_proof();
	test_roundtrip_and_wrong_key();
	test_type2_tamper();
	test_type1_padding();
	test_caps_overlap_and_failures();
	test_override_dispatch();
	test_kdf_edges();
	test_envelope_edges();
	test_overlap_boundaries();
	test_encrypt_at();
	test_type1_pad_runs();
	test_type2_tail_and_short();
	test_long_keys();
	test_envelope_short_header();
	(void)heap_dup;
	return wrt_finish();
}
