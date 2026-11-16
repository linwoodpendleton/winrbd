/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_cts - AES-CBC ciphertext stealing, variant CS3 (core/src/crypto/wri_cts.c, declared
 * in wri_aes.h).
 *
 * Known answers: the four RFC 8009 appendix A vectors (confounder || plaintext encrypted with the
 * derived Ke and a zero IV must give "aes_output": the plaintext sizes 0, 6, 16 and 21 give message
 * lengths 16, 22, 32 and 37, so the single block, the short tail and the block-aligned swap cases are
 * all covered) and the CTS part of cephx/cipher-type2.json (30 vectors, six usages, up to 101
 * bytes). Both directions, out of place and in place.
 *
 * Properties: an independent CS3 written here from the definition (zero pad, plain CBC through the
 * block functions, swap the last two blocks, truncate) equals the module for every length 16..80
 * and both key sizes with random keys and IVs; decrypt inverts encrypt; in == out equals out of
 * place; n < 16 and bad arguments are rejected before anything is touched; the output beyond n is
 * never written (exact-size heap buffers for the sanitizer builds); the IV is never modified; CTS
 * runs on top of an overridden CBC (the call pattern is checked, in place too) and an override
 * failure is returned unchanged (a positive status becomes WR_E_INVAL); a decrypt that fails wipes its
 * output; two n-byte ranges that overlap other than exactly are refused (WR_E_INVAL) before anything
 * is read or written, and disjoint adjacent ranges work.
 */
#include "wrt.h"

#include "wri_aes.h"

/* ---- helpers --------------------------------------------------------------------------------- */

static uint64_t rng_state = 0x243f6a8885a308d3ull;

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

/* Exact-size heap block, so an out-of-bounds access is caught by the sanitizers. */
static uint8_t *heap_dup(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n != 0 ? n : 1);

	if (q == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	if (n != 0)
		memcpy(q, p, n);
	return q;
}

/* Independent CS3 from the definition (no code shared with wri_cts.c except the block cipher). */
static void ref_cs3_enc(const uint8_t *key, size_t klen, const uint8_t iv[16], const uint8_t *in, size_t n,
			uint8_t *out)
{
	wri_aes_ctx c;
	uint8_t pad[96 + 16], ct[96 + 16], chain[16], blk[16];
	size_t k = (n + 15) / 16, i, j, r = n - 16 * (k - 1);

	WRT_CHECK(wri_aes_setkey(&c, key, klen) == WR_OK);
	memset(pad, 0, sizeof(pad));
	memcpy(pad, in, n);
	memcpy(chain, iv, 16);
	for (i = 0; i < k; i++) {
		for (j = 0; j < 16; j++)
			blk[j] = (uint8_t)(pad[16 * i + j] ^ chain[j]);
		wri_aes_enc_block(&c, blk, chain);
		memcpy(ct + 16 * i, chain, 16);
	}
	if (k == 1) {
		memcpy(out, ct, 16);
		return;
	}
	memcpy(out, ct, 16 * (k - 2));
	memcpy(out + 16 * (k - 2), ct + 16 * (k - 1), 16);
	memcpy(out + 16 * (k - 1), ct + 16 * (k - 2), r);
}

/* One known answer: enc(msg) == want, dec(want) == msg, out of place and in place. */
static void check_kat(const uint8_t *ke, size_t klen, const uint8_t *msg, size_t n, const uint8_t *want,
		      const char *what)
{
	static const uint8_t zero_iv[16];
	uint8_t *in = heap_dup(msg, n), *out = (uint8_t *)malloc(n), *buf = heap_dup(msg, n);
	uint8_t *ct = heap_dup(want, n);

	WRT_CHECK(out != NULL);
	WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(NULL, ke, klen, zero_iv, in, n, out));
	wrt_checks++;
	if (memcmp(out, want, n) != 0) {
		wrt_failures++;
		fprintf(stderr, "%s: encrypt mismatch (n=%zu)\n", what, n);
	}
	WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(NULL, ke, klen, zero_iv, buf, n, buf));
	wrt_checks++;
	if (memcmp(buf, want, n) != 0) {
		wrt_failures++;
		fprintf(stderr, "%s: in-place encrypt mismatch (n=%zu)\n", what, n);
	}
	memset(out, 0xEE, n);
	WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(NULL, ke, klen, zero_iv, ct, n, out));
	wrt_checks++;
	if (memcmp(out, msg, n) != 0) {
		wrt_failures++;
		fprintf(stderr, "%s: decrypt mismatch (n=%zu)\n", what, n);
	}
	WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(NULL, ke, klen, zero_iv, ct, n, ct));
	wrt_checks++;
	if (memcmp(ct, msg, n) != 0) {
		wrt_failures++;
		fprintf(stderr, "%s: in-place decrypt mismatch (n=%zu)\n", what, n);
	}
	free(in);
	free(out);
	free(buf);
	free(ct);
}

/* ---- known answers --------------------------------------------------------------------------- */

static void test_rfc8009(void)
{
	wrt_json j;
	wrt_tok root, vecs, v;
	size_t i, nv, nvec = 0;

	if (wrt_json_load_vec(&j, "cephx/rfc8009-aes256-cts-hmac-sha384-192.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	root = wrt_json_root(&j);
	vecs = wrt_json_get(&j, root, "vectors");
	nv = wrt_json_count(&j, vecs);
	WRT_CHECK(nv == 4);
	for (i = 0; i < nv; i++) {
		uint8_t *ke = NULL, *conf = NULL, *pt = NULL, *want = NULL, *msg;
		size_t kn = 0, cn = 0, pn = 0, wn = 0;

		v = wrt_json_at(&j, vecs, i);
		WRT_CHECK(wrt_json_get_hex(&j, v, "ke", &ke, &kn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, v, "confounder", &conf, &cn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, v, "plaintext", &pt, &pn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, v, "aes_output", &want, &wn) == 0);
		if (ke == NULL || conf == NULL || pt == NULL || want == NULL) {
			free(ke), free(conf), free(pt), free(want);
			continue;
		}
		WRT_CHECK(kn == 32 && cn == 16 && wn == cn + pn);
		msg = (uint8_t *)malloc(cn + pn);
		WRT_CHECK(msg != NULL);
		memcpy(msg, conf, cn);
		if (pn != 0)
			memcpy(msg + cn, pt, pn);
		check_kat(ke, kn, msg, cn + pn, want, "rfc8009");
		nvec++;
		free(msg);
		free(ke);
		free(conf);
		free(pt);
		free(want);
	}
	WRT_CHECK(nvec == 4);
	wrt_json_free(&j);
}

static void test_cipher_type2(void)
{
	wrt_json j;
	wrt_tok root, vecs, derived, v;
	size_t i, nv, nvec = 0;

	if (wrt_json_load_vec(&j, "cephx/cipher-type2.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	root = wrt_json_root(&j);
	vecs = wrt_json_get(&j, root, "vectors");
	derived = wrt_json_get(&j, root, "derived");
	nv = wrt_json_count(&j, vecs);
	WRT_CHECK(nv == 30);
	for (i = 0; i < nv; i++) {
		uint8_t *ke = NULL, *conf = NULL, *pt = NULL, *cm = NULL, *msg;
		size_t kn = 0, cn = 0, pn = 0, mn = 0;
		char name[16];
		int ok = 0;
		wrt_tok d;

		v = wrt_json_at(&j, vecs, i);
		snprintf(name, sizeof(name), "0x%02x", (unsigned)wrt_json_int(&j, wrt_json_get(&j, v, "usage"), &ok));
		WRT_CHECK(ok);
		d = wrt_json_get(&j, derived, name);
		WRT_CHECK(d != WRT_NONE);
		WRT_CHECK(wrt_json_get_hex(&j, d, "ke", &ke, &kn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, v, "confounder", &conf, &cn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, v, "plaintext", &pt, &pn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, v, "ciphertext_with_mac", &cm, &mn) == 0);
		if (ke == NULL || conf == NULL || pt == NULL || cm == NULL || mn != cn + pn + 24) {
			WRT_CHECK(0);
			free(ke), free(conf), free(pt), free(cm);
			continue;
		}
		msg = (uint8_t *)malloc(cn + pn);
		WRT_CHECK(msg != NULL);
		memcpy(msg, conf, cn);
		if (pn != 0)
			memcpy(msg + cn, pt, pn);
		/* the MAC is the last 24 bytes; the CTS part is everything before it */
		check_kat(ke, kn, msg, cn + pn, cm, "cipher-type2");
		nvec++;
		free(msg);
		free(ke);
		free(conf);
		free(pt);
		free(cm);
	}
	WRT_CHECK(nvec == 30);
	wrt_json_free(&j);
}

/* ---- properties ------------------------------------------------------------------------------ */

static void test_against_reference_and_roundtrip(void)
{
	static const size_t ks[2] = {16, 32};
	size_t n, ki, round;

	for (ki = 0; ki < 2; ki++) {
		for (n = 16; n <= 80; n++) {
			for (round = 0; round < 8; round++) {
				uint8_t key[32], iv[16], iv0[16], want[96], pt[96];
				uint8_t *in, *out, *buf, *back;

				rnd_fill(key, sizeof(key));
				rnd_fill(iv, sizeof(iv));
				if (round == 0)
					memset(iv, 0, sizeof(iv));
				memcpy(iv0, iv, sizeof(iv));
				rnd_fill(pt, sizeof(pt));
				ref_cs3_enc(key, ks[ki], iv, pt, n, want);

				in = heap_dup(pt, n);
				out = (uint8_t *)malloc(n);
				buf = heap_dup(pt, n);
				back = (uint8_t *)malloc(n);
				WRT_CHECK(out != NULL && back != NULL);

				WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(NULL, key, ks[ki], iv, in, n, out));
				WRT_CHECK_MEM(out, want, n);
				WRT_CHECK_MEM(in, pt, n); /* input untouched */
				WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(NULL, key, ks[ki], iv, buf, n, buf));
				WRT_CHECK_MEM(buf, want, n);
				WRT_CHECK_MEM(iv, iv0, 16);

				WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(NULL, key, ks[ki], iv, out, n, back));
				WRT_CHECK_MEM(back, pt, n);
				WRT_CHECK_MEM(out, want, n); /* ciphertext untouched */
				WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(NULL, key, ks[ki], iv, buf, n, buf));
				WRT_CHECK_MEM(buf, pt, n);
				WRT_CHECK_MEM(iv, iv0, 16);

				free(in);
				free(out);
				free(buf);
				free(back);
			}
		}
	}
}

static void test_shape(void)
{
	/* For n > 16 the output must differ from plain CBC only by the swap: check the structure
	 * directly with the CBC layer for one aligned and one unaligned size. */
	static const size_t sizes[3] = {32, 37, 48};
	uint8_t key[32], iv[16], pt[64], cbc[64], cts[64];
	wri_aes_ctx c;
	size_t s, k, r, i;

	for (s = 0; s < 3; s++) {
		size_t n = sizes[s];

		rnd_fill(key, sizeof(key));
		rnd_fill(iv, sizeof(iv));
		rnd_fill(pt, sizeof(pt));
		memset(pt + n, 0, sizeof(pt) - n); /* zero padding for the plain CBC reference */
		k = (n + 15) / 16;
		r = n - 16 * (k - 1);
		WRT_CHECK(wri_aes_setkey(&c, key, 32) == WR_OK);
		wri_aes_cbc_enc(&c, iv, pt, cbc, k);
		WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(NULL, key, 32, iv, pt, n, cts));
		for (i = 0; i + 2 < k; i++)
			WRT_CHECK_MEM(cts + 16 * i, cbc + 16 * i, 16);
		WRT_CHECK_MEM(cts + 16 * (k - 2), cbc + 16 * (k - 1), 16);
		WRT_CHECK_MEM(cts + 16 * (k - 1), cbc + 16 * (k - 2), r);
	}
}

static void test_not_written_past_n(void)
{
	uint8_t key[32], iv[16], pt[96], big[96 + 32];
	size_t n;

	rnd_fill(key, sizeof(key));
	rnd_fill(iv, sizeof(iv));
	rnd_fill(pt, sizeof(pt));
	for (n = 16; n <= 80; n++) {
		size_t i;

		memset(big, 0xA5, sizeof(big));
		WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(NULL, key, 32, iv, pt, n, big + 16));
		for (i = 0; i < 16; i++)
			WRT_CHECK(big[i] == 0xA5);
		for (i = 16 + n; i < sizeof(big); i++)
			WRT_CHECK(big[i] == 0xA5);
		memset(big, 0xA5, sizeof(big));
		WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(NULL, key, 32, iv, pt, n, big + 16));
		for (i = 0; i < 16; i++)
			WRT_CHECK(big[i] == 0xA5);
		for (i = 16 + n; i < sizeof(big); i++)
			WRT_CHECK(big[i] == 0xA5);
	}
}

static void test_rejections(void)
{
	uint8_t key[32] = {1}, iv[16] = {2}, in[64] = {3}, out[64];
	size_t n;

	for (n = 0; n < 16; n++) {
		memset(out, 0x77, sizeof(out));
		WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_cts3_enc(NULL, key, 32, iv, in, n, out));
		WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_cts3_dec(NULL, key, 32, iv, in, n, out));
		WRT_CHECK(out[0] == 0x77 && out[15] == 0x77); /* nothing written */
	}
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_cts3_enc(NULL, key, 32, iv, in, 15, out));
	/* key length: 16 and 32 only */
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cts3_enc(NULL, key, 24, iv, in, 32, out));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cts3_dec(NULL, key, 0, iv, in, 32, out));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cts3_enc(NULL, key, 17, iv, in, 32, out));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cts3_enc(NULL, NULL, 32, iv, in, 32, out));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cts3_enc(NULL, key, 32, NULL, in, 32, out));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cts3_enc(NULL, key, 32, iv, NULL, 32, out));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cts3_dec(NULL, key, 32, iv, in, 32, NULL));
	/* 16-byte keys work */
	WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(NULL, key, 16, iv, in, 40, out));
	/* a wrong-length key never reaches the cipher, even for n == 16 */
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cts3_enc(NULL, key, 24, iv, in, 16, out));
}

/* ---- CTS on an overridden CBC ---------------------------------------------------------------- */

struct fake {
	unsigned enc_calls, dec_calls;
	size_t enc_blocks, dec_blocks;
	wr_status fail_with; /* returned (and nothing done) once calls reach fail_at; 0 = never */
	unsigned fail_at;
};

static wr_status fake_enc(void *ctx, const uint8_t *key, size_t klen, const uint8_t iv[16], const uint8_t *in,
			  uint8_t *out, size_t nb)
{
	struct fake *f = (struct fake *)ctx;
	wri_aes_ctx c;

	f->enc_calls++;
	f->enc_blocks += nb;
	if (f->fail_with != 0 && f->enc_calls + f->dec_calls >= f->fail_at)
		return f->fail_with;
	if (wri_aes_setkey(&c, key, klen) != WR_OK)
		return WR_E_CRYPTO_KEY;
	wri_aes_cbc_enc(&c, iv, in, out, nb);
	return WR_OK;
}

static wr_status fake_dec(void *ctx, const uint8_t *key, size_t klen, const uint8_t iv[16], const uint8_t *in,
			  uint8_t *out, size_t nb)
{
	struct fake *f = (struct fake *)ctx;
	wri_aes_ctx c;

	f->dec_calls++;
	f->dec_blocks += nb;
	if (f->fail_with != 0 && f->enc_calls + f->dec_calls >= f->fail_at)
		return f->fail_with;
	if (wri_aes_setkey(&c, key, klen) != WR_OK)
		return WR_E_CRYPTO_KEY;
	wri_aes_cbc_dec(&c, iv, in, out, nb);
	return WR_OK;
}

static void test_override(void)
{
	struct fake f;
	wr_prim_ops ops;
	uint8_t key[32], iv[16], pt[96], a[96], b[96], back[96];
	size_t n;

	memset(&f, 0, sizeof(f));
	memset(&ops, 0, sizeof(ops));
	ops.size = sizeof(ops);
	ops.ctx = &f;
	ops.aes_cbc_enc = fake_enc;
	ops.aes_cbc_dec = fake_dec;
	rnd_fill(key, sizeof(key));
	rnd_fill(iv, sizeof(iv));
	rnd_fill(pt, sizeof(pt));

	for (n = 16; n <= 80; n++) {
		memset(&f, 0, sizeof(f));
		WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(&ops, key, 32, iv, pt, n, a));
		WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(NULL, key, 32, iv, pt, n, b));
		WRT_CHECK_MEM(a, b, n);
		/* single block: one call; otherwise one call over k-1 blocks and one for the tail */
		WRT_CHECK(f.enc_calls == (n == 16 ? 1u : 2u));
		WRT_CHECK(f.enc_blocks == (n == 16 ? 1u : (n + 15) / 16));
		WRT_CHECK(f.dec_calls == 0);
		memset(&f, 0, sizeof(f));
		WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(&ops, key, 32, iv, a, n, back));
		WRT_CHECK_MEM(back, pt, n);
		WRT_CHECK(f.enc_calls == 0);
		/* single block: 1 call; else the stolen block, k-2 blocks (if any) and the block k-1: k blocks */
		WRT_CHECK(f.dec_calls == (n == 16 ? 1u : (n <= 32 ? 2u : 3u)));
		WRT_CHECK(f.dec_blocks == (n == 16 ? 1u : (size_t)((n + 15) / 16)));
	}

	/* a failure inside the override is returned as is, encrypt and decrypt, at every call index */
	{
		unsigned at;

		for (at = 1; at <= 3; at++) {
			/* encrypt of 70 bytes makes 2 CBC calls, decrypt makes 3 */
			memset(&f, 0, sizeof(f));
			f.fail_with = WR_E_CRYPTO_KEY;
			f.fail_at = at;
			WRT_CHECK_STATUS(at <= 2 ? WR_E_CRYPTO_KEY : WR_OK, wri_cts3_enc(&ops, key, 32, iv, pt, 70, a));
			memset(&f, 0, sizeof(f));
			f.fail_with = WR_E_CRYPTO_LEN;
			f.fail_at = at;
			WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_cts3_dec(&ops, key, 32, iv, b, 70, a));
		}
	}

	/* an override must never be entered for a bad key length or n < 16 */
	memset(&f, 0, sizeof(f));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cts3_enc(&ops, key, 24, iv, pt, 40, a));
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_cts3_enc(&ops, key, 32, iv, pt, 15, a));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_cts3_dec(&ops, key, 24, iv, pt, 40, a));
	WRT_CHECK(f.enc_calls == 0 && f.dec_calls == 0);
}

/* in == out and disjoint (even adjacent) ranges work; every other overlap is WR_E_INVAL, writes
 * nothing, and never enters an override. */
static void test_overlap(void)
{
	struct fake f;
	wr_prim_ops ops;
	uint8_t key[32], iv[16], arena[4 * 96], keep[4 * 96], ref[96];
	size_t n, off, dir;

	memset(&f, 0, sizeof(f));
	memset(&ops, 0, sizeof(ops));
	ops.size = sizeof(ops);
	ops.ctx = &f;
	ops.aes_cbc_enc = fake_enc;
	ops.aes_cbc_dec = fake_dec;
	rnd_fill(key, sizeof(key));
	rnd_fill(iv, sizeof(iv));

	for (n = 16; n <= 70; n += 3) {
		for (dir = 0; dir < 2; dir++) {
			for (off = 0; off <= 2 * n && off + n <= sizeof(arena) / 2; off++) {
				uint8_t *in = arena + 96, *out = arena + 96 + off;
				int ok = (off == 0 || off >= n);

				rnd_fill(arena, sizeof(arena));
				if (dir == 0)
					ref_cs3_enc(key, 32, iv, in, n, ref);
				memcpy(keep, arena, sizeof(arena));
				memset(&f, 0, sizeof(f));
				if (dir == 0) {
					WRT_CHECK_STATUS(ok ? WR_OK : WR_E_INVAL, wri_cts3_enc(&ops, key, 32, iv, in, n, out));
					if (ok)
						WRT_CHECK_MEM(out, ref, n);
				} else {
					WRT_CHECK_STATUS(ok ? WR_OK : WR_E_INVAL, wri_cts3_dec(&ops, key, 32, iv, in, n, out));
				}
				if (!ok) {
					WRT_CHECK_MEM(arena, keep, sizeof(arena));
					WRT_CHECK(f.enc_calls == 0 && f.dec_calls == 0);
				}
				/* output below the input */
				memcpy(arena, keep, sizeof(arena));
				memset(&f, 0, sizeof(f));
				if (dir == 0)
					WRT_CHECK_STATUS(ok ? WR_OK : WR_E_INVAL, wri_cts3_enc(NULL, key, 32, iv, out, n, in));
				else
					WRT_CHECK_STATUS(ok ? WR_OK : WR_E_INVAL, wri_cts3_dec(NULL, key, 32, iv, out, n, in));
				if (!ok)
					WRT_CHECK_MEM(arena, keep, sizeof(arena));
			}
		}
	}
}

/* In place through an overridden CBC, both directions, every length. */
static void test_override_in_place(void)
{
	struct fake f;
	wr_prim_ops ops;
	uint8_t key[32], iv[16], pt[96], want[96];
	size_t n, ki;

	memset(&f, 0, sizeof(f));
	memset(&ops, 0, sizeof(ops));
	ops.size = sizeof(ops);
	ops.ctx = &f;
	ops.aes_cbc_enc = fake_enc;
	ops.aes_cbc_dec = fake_dec;
	for (ki = 0; ki < 2; ki++) {
		for (n = 16; n <= 80; n++) {
			uint8_t *buf;

			rnd_fill(key, sizeof(key));
			rnd_fill(iv, sizeof(iv));
			rnd_fill(pt, sizeof(pt));
			ref_cs3_enc(key, ki ? 32 : 16, iv, pt, n, want);
			buf = heap_dup(pt, n);
			WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(&ops, key, ki ? 32 : 16, iv, buf, n, buf));
			WRT_CHECK_MEM(buf, want, n);
			WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(&ops, key, ki ? 32 : 16, iv, buf, n, buf));
			WRT_CHECK_MEM(buf, pt, n);
			free(buf);
		}
	}
}

/* A failed decrypt leaves no partial plaintext: the output is all zero whichever CBC call failed,
 * out of place and in place; a positive status from the host is reported as WR_E_INVAL. */
static void test_dec_failure_wipes(void)
{
	static const size_t sizes[] = {16, 17, 31, 32, 33, 48, 70, 80};
	struct fake f;
	wr_prim_ops ops;
	uint8_t key[32], iv[16], pt[96], ct[96];
	size_t si;

	memset(&ops, 0, sizeof(ops));
	ops.size = sizeof(ops);
	ops.ctx = &f;
	ops.aes_cbc_enc = fake_enc;
	ops.aes_cbc_dec = fake_dec;
	rnd_fill(key, sizeof(key));
	rnd_fill(iv, sizeof(iv));
	rnd_fill(pt, sizeof(pt));
	for (si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
		size_t n = sizes[si];
		unsigned at, calls = (n == 16) ? 1u : (n <= 32 ? 2u : 3u);

		memset(&f, 0, sizeof(f));
		WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(&ops, key, 32, iv, pt, n, ct));
		for (at = 1; at <= calls; at++) {
			uint8_t *out = (uint8_t *)malloc(n), *buf = heap_dup(ct, n);
			size_t i, nz = 0;

			WRT_CHECK(out != NULL);
			memset(out, 0x5A, n);
			memset(&f, 0, sizeof(f));
			f.fail_with = WR_E_CRYPTO_LEN;
			f.fail_at = at;
			WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_cts3_dec(&ops, key, 32, iv, ct, n, out));
			for (i = 0; i < n; i++)
				nz += out[i] != 0;
			WRT_CHECK(nz == 0);
			memset(&f, 0, sizeof(f));
			f.fail_with = WR_E_CRYPTO_LEN;
			f.fail_at = at;
			WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_cts3_dec(&ops, key, 32, iv, buf, n, buf));
			for (nz = 0, i = 0; i < n; i++)
				nz += buf[i] != 0;
			WRT_CHECK(nz == 0);
			/* a positive status from the host */
			memset(&f, 0, sizeof(f));
			f.fail_with = (wr_status)7;
			f.fail_at = at;
			WRT_CHECK_STATUS(WR_E_INVAL, wri_cts3_dec(&ops, key, 32, iv, ct, n, out));
			memset(&f, 0, sizeof(f));
			f.fail_with = (wr_status)7;
			f.fail_at = at;
			WRT_CHECK_STATUS(at <= (n == 16 ? 1u : 2u) ? WR_E_INVAL : WR_OK, wri_cts3_enc(&ops, key, 32, iv, pt, n, out));
			free(out);
			free(buf);
		}
	}
}

int main(void)
{
	test_rfc8009();
	test_cipher_type2();
	test_against_reference_and_roundtrip();
	test_shape();
	test_not_written_past_n();
	test_rejections();
	test_override();
	test_overlap();
	test_override_in_place();
	test_dec_failure_wipes();
	return wrt_finish();
}
