/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_aes - AES key schedule, block functions and CBC (core/src/crypto/wri_aes.c and
 * wri_aes_cbc.c).
 *
 * Known answers: FIPS 197 appendix C.1 to C.3 (single blocks, all three key sizes), NIST SP
 * 800-38A F.2.1 to F.2.6 (CBC, encrypt and decrypt, all three key sizes), and the CBC part of
 * harness/vectors/cephx/cipher-type1.json (cephx type 1: AES-128, fixed IV, PKCS#7 padding, applied
 * here by the test). Properties: in-place equals out-of-place, the iv is never modified, nothing is
 * written past the last block, CBC equals a hand-chained loop over the block function, random round
 * trips, key length rejection and the fail-closed behaviour of an unkeyed or rejected context.
 *
 * Extra guards against a wrong table entry or a wrong schedule that the fixed vectors above could
 * miss: FIPS 197 appendix A round-key checkpoints, and an independent textbook AES written here
 * (S-box computed from GF(2^8) inversion, byte-wise rounds, no tables) compared with the module on
 * thousands of random keys and blocks for all three key sizes in both directions. Buffer tests use
 * exact-size heap blocks and odd alignments so a sanitizer build catches any out-of-bounds access.
 */
#include "wrt.h"

#include "wri_aes.h"

/* ---- helpers --------------------------------------------------------------------------------- */

/* Decode hex into buf (at most max bytes); returns the byte count, 0 on any error. */
static size_t hx(const char *hex, uint8_t *buf, size_t max)
{
	uint8_t *tmp = NULL;
	size_t n = 0;

	if (wrt_hex_decode(hex, strlen(hex), &tmp, &n) != 0)
		return 0;
	if (n > max) {
		free(tmp);
		return 0;
	}
	memcpy(buf, tmp, n);
	free(tmp);
	return n;
}

/* xorshift64*: deterministic test data, not a security primitive. */
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

static const size_t key_sizes[3] = {16, 24, 32};

/* ---- FIPS 197 appendix C --------------------------------------------------------------------- */

static void test_fips197(void)
{
	static const struct {
		const char *key, *ct;
	} v[3] = {
	    {"000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"},
	    {"000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"},
	    {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"},
	};
	uint8_t key[32], pt[16], ct[16], out[16], back[16];
	wri_aes_ctx c;
	size_t i, klen;

	hx("00112233445566778899aabbccddeeff", pt, sizeof(pt));
	for (i = 0; i < 3; i++) {
		klen = hx(v[i].key, key, sizeof(key));
		WRT_CHECK_U64(klen, key_sizes[i]);
		hx(v[i].ct, ct, sizeof(ct));
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, klen));
		WRT_CHECK_U64(c.rounds, 10 + 2 * i);
		wri_aes_enc_block(&c, pt, out);
		WRT_CHECK_MEM(out, ct, 16);
		wri_aes_dec_block(&c, ct, back);
		WRT_CHECK_MEM(back, pt, 16);
	}
}

/* FIPS 197 appendix B: the worked 128-bit example with a non-sequential key. */
static void test_fips197_appendix_b(void)
{
	uint8_t key[16], pt[16], ct[16], out[16];
	wri_aes_ctx c;

	hx("2b7e151628aed2a6abf7158809cf4f3c", key, sizeof(key));
	hx("3243f6a8885a308d313198a2e0370734", pt, sizeof(pt));
	hx("3925841d02dc09fbdc118597196a0b32", ct, sizeof(ct));
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, 16));
	wri_aes_enc_block(&c, pt, out);
	WRT_CHECK_MEM(out, ct, 16);
	wri_aes_dec_block(&c, ct, out);
	WRT_CHECK_MEM(out, pt, 16);
	/* the block functions allow in == out */
	memcpy(out, pt, 16);
	wri_aes_enc_block(&c, out, out);
	WRT_CHECK_MEM(out, ct, 16);
	wri_aes_dec_block(&c, out, out);
	WRT_CHECK_MEM(out, pt, 16);
}

/* ---- NIST SP 800-38A F.2 --------------------------------------------------------------------- */

static void test_sp800_38a_cbc(void)
{
	static const char *iv_hex = "000102030405060708090a0b0c0d0e0f";
	static const char *pt_hex = "6bc1bee22e409f96e93d7e117393172a"
				    "ae2d8a571e03ac9c9eb76fac45af8e51"
				    "30c81c46a35ce411e5fbc1191a0a52ef"
				    "f69f2445df4f9b17ad2b417be66c3710";
	static const struct {
		const char *key, *ct;
	} v[3] = {
	    {"2b7e151628aed2a6abf7158809cf4f3c", /* F.2.1 / F.2.2 */
	     "7649abac8119b246cee98e9b12e9197d"
	     "5086cb9b507219ee95db113a917678b2"
	     "73bed6b8e3c1743b7116e69e22229516"
	     "3ff1caa1681fac09120eca307586e1a7"},
	    {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", /* F.2.3 / F.2.4 */
	     "4f021db243bc633d7178183a9fa071e8"
	     "b4d9ada9ad7dedf4e5e738763f69145a"
	     "571b242012fb7ae07fa9baac3df102e0"
	     "08b0e27988598881d920a9e64f5615cd"},
	    {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", /* F.2.5 / F.2.6 */
	     "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
	     "9cfc4e967edb808d679f777bc6702c7d"
	     "39f23369a9d9bacfa530e26304231461"
	     "b2eb05e2c39be9fcda6c19078c6a9d1b"},
	};
	uint8_t key[32], iv[16], iv0[16], pt[64], ct[64], buf[64];
	wri_aes_ctx c;
	size_t i, klen;

	hx(iv_hex, iv, sizeof(iv));
	memcpy(iv0, iv, sizeof(iv));
	WRT_CHECK_U64(hx(pt_hex, pt, sizeof(pt)), 64);
	for (i = 0; i < 3; i++) {
		klen = hx(v[i].key, key, sizeof(key));
		WRT_CHECK_U64(klen, key_sizes[i]);
		WRT_CHECK_U64(hx(v[i].ct, ct, sizeof(ct)), 64);
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, klen));

		memset(buf, 0, sizeof(buf));
		wri_aes_cbc_enc(&c, iv, pt, buf, 4);
		WRT_CHECK_MEM(buf, ct, 64);
		memset(buf, 0, sizeof(buf));
		wri_aes_cbc_dec(&c, iv, ct, buf, 4);
		WRT_CHECK_MEM(buf, pt, 64);

		/* in place */
		memcpy(buf, pt, 64);
		wri_aes_cbc_enc(&c, iv, buf, buf, 4);
		WRT_CHECK_MEM(buf, ct, 64);
		wri_aes_cbc_dec(&c, iv, buf, buf, 4);
		WRT_CHECK_MEM(buf, pt, 64);

		/* the first n blocks of a longer message do not depend on what follows */
		memset(buf, 0, sizeof(buf));
		wri_aes_cbc_enc(&c, iv, pt, buf, 2);
		WRT_CHECK_MEM(buf, ct, 32);
		WRT_CHECK_MEM(iv, iv0, 16); /* the iv is never modified */
	}
}

/* ---- cephx type 1 (cipher-type1.json) -------------------------------------------------------- */

static void test_cephx_type1_vectors(void)
{
	wrt_json j;
	wrt_tok root, vecs;
	uint8_t *secret = NULL, *iv = NULL;
	size_t secret_n = 0, iv_n = 0, i, n;
	wri_aes_ctx c;

	if (wrt_json_load_vec(&j, "cephx/cipher-type1.json") != 0) {
		WRT_CHECK(!"cipher-type1.json loads");
		return;
	}
	root = wrt_json_root(&j);
	WRT_CHECK(wrt_json_get_hex(&j, root, "key_secret", &secret, &secret_n) == 0);
	WRT_CHECK(wrt_json_get_hex(&j, root, "iv", &iv, &iv_n) == 0);
	vecs = wrt_json_get(&j, root, "vectors");
	n = wrt_json_count(&j, vecs);
	WRT_CHECK(n >= 8);
	WRT_CHECK(secret_n >= 16 && iv_n == 16);
	if (secret_n < 16 || iv_n != 16) {
		free(secret);
		free(iv);
		wrt_json_free(&j);
		return;
	}
	/* type 1 uses the first 16 bytes of the secret as an AES-128 key (cephx.md 2.4) */
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, secret, 16));

	for (i = 0; i < n; i++) {
		wrt_tok e = wrt_json_at(&j, vecs, i);
		uint8_t *pt = NULL, *want = NULL, *buf = NULL, *back = NULL;
		size_t pt_n = 0, want_n = 0, padded;
		unsigned pad;

		if (wrt_json_get_hex(&j, e, "plaintext", &pt, &pt_n) != 0 ||
		    wrt_json_get_hex(&j, e, "ciphertext", &want, &want_n) != 0) {
			WRT_CHECK(!"vector fields decode");
			free(pt);
			free(want);
			continue;
		}
		/* PKCS#7: always 1..16 bytes of padding, each the pad length (cephx.md 2.4) */
		pad = 16u - (unsigned)(pt_n % 16u);
		padded = pt_n + pad;
		WRT_CHECK_U64(padded, want_n);
		buf = (uint8_t *)malloc(padded + 1);
		back = (uint8_t *)malloc(padded + 1);
		if (buf != NULL && back != NULL && padded == want_n) {
			if (pt_n > 0)
				memcpy(buf, pt, pt_n);
			memset(buf + pt_n, (int)pad, pad);
			wri_aes_cbc_enc(&c, iv, buf, buf, padded / 16);
			WRT_CHECK_MEM(buf, want, want_n);
			wri_aes_cbc_dec(&c, iv, want, back, want_n / 16);
			WRT_CHECK_U64(back[padded - 1], pad);
			if (pt_n > 0)
				WRT_CHECK_MEM(back, pt, pt_n);
		} else {
			WRT_CHECK(!"allocation / length");
		}
		free(buf);
		free(back);
		free(pt);
		free(want);
	}
	free(secret);
	free(iv);
	wrt_json_free(&j);
}

/* ---- properties ------------------------------------------------------------------------------ */

/* CBC must equal the textbook chain built from the single-block function. */
static void test_cbc_equals_manual_chain(void)
{
	uint8_t key[32], iv[16], pt[16 * 9], got[16 * 9], want[16 * 9], x[16];
	wri_aes_ctx c;
	size_t k, b, j;

	for (k = 0; k < 3; k++) {
		rnd_fill(key, sizeof(key));
		rnd_fill(iv, sizeof(iv));
		rnd_fill(pt, sizeof(pt));
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, key_sizes[k]));
		memcpy(x, iv, 16);
		for (b = 0; b < 9; b++) {
			for (j = 0; j < 16; j++)
				x[j] = (uint8_t)(x[j] ^ pt[b * 16 + j]);
			wri_aes_enc_block(&c, x, x);
			memcpy(want + b * 16, x, 16);
		}
		wri_aes_cbc_enc(&c, iv, pt, got, 9);
		WRT_CHECK_MEM(got, want, sizeof(want));
	}
}

static void test_random_roundtrips(void)
{
	uint8_t key[32], iv[16], iv0[16], pt[16 * 33], ct[16 * 33], ct2[16 * 33], back[16 * 33], blk[16], blk2[16];
	wri_aes_ctx c;
	size_t k, iter, nb;

	for (k = 0; k < 3; k++) {
		for (iter = 0; iter < 200; iter++) {
			rnd_fill(key, sizeof(key));
			rnd_fill(iv, sizeof(iv));
			memcpy(iv0, iv, sizeof(iv));
			rnd_fill(pt, sizeof(pt));
			nb = (size_t)(rnd() % 34u); /* 0 to 33 blocks */
			WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, key_sizes[k]));

			/* single block round trip, both directions */
			wri_aes_enc_block(&c, pt, blk);
			wri_aes_dec_block(&c, blk, blk2);
			WRT_CHECK_MEM(blk2, pt, 16);
			wri_aes_dec_block(&c, pt, blk);
			wri_aes_enc_block(&c, blk, blk2);
			WRT_CHECK_MEM(blk2, pt, 16);

			/* CBC out of place, then in place: same bytes */
			memset(ct, 0xaa, sizeof(ct));
			wri_aes_cbc_enc(&c, iv, pt, ct, nb);
			memcpy(ct2, pt, sizeof(pt));
			wri_aes_cbc_enc(&c, iv, ct2, ct2, nb);
			WRT_CHECK_MEM(ct2, ct, nb * 16);
			/* nothing is written past the last block */
			{
				size_t t;
				int clean = 1;

				for (t = nb * 16; t < sizeof(ct); t++)
					if (ct[t] != 0xaa)
						clean = 0;
				WRT_CHECK(clean);
			}
			WRT_CHECK_MEM(iv, iv0, 16);

			memset(back, 0x55, sizeof(back));
			wri_aes_cbc_dec(&c, iv, ct, back, nb);
			WRT_CHECK_MEM(back, pt, nb * 16);
			WRT_CHECK(nb == 33 || back[nb * 16] == 0x55);
			wri_aes_cbc_dec(&c, iv, ct2, ct2, nb); /* in place */
			WRT_CHECK_MEM(ct2, pt, nb * 16);
			WRT_CHECK_MEM(iv, iv0, 16);
		}
	}
}

static void test_key_sensitivity(void)
{
	/* flipping one key bit or one plaintext bit changes the block (sanity against a no-op schedule) */
	uint8_t key[32], key2[32], pt[16], a[16], b[16];
	wri_aes_ctx c1, c2;
	size_t k;

	for (k = 0; k < 3; k++) {
		rnd_fill(key, sizeof(key));
		rnd_fill(pt, sizeof(pt));
		memcpy(key2, key, sizeof(key));
		key2[key_sizes[k] - 1] ^= 1;
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c1, key, key_sizes[k]));
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c2, key2, key_sizes[k]));
		wri_aes_enc_block(&c1, pt, a);
		wri_aes_enc_block(&c2, pt, b);
		WRT_CHECK(memcmp(a, b, 16) != 0);
	}
}

static void test_key_length_rejection(void)
{
	static const size_t bad[] = {0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 48, 64, 65, 4096};
	uint8_t key[4096];
	wri_aes_ctx c;
	size_t i;

	memset(key, 0x42, sizeof(key));
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_aes_setkey(&c, key, bad[i]));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_aes_setkey(&c, NULL, 15));
	/* valid lengths with missing pointers are an argument error, not a crash */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_aes_setkey(&c, NULL, 16));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_aes_setkey(NULL, key, 32));
	/* a good key followed by a rejected one: see test_failed_setkey_fails_closed */
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, 16));
	WRT_CHECK_U64(c.rounds, 10);
}

static void test_unkeyed_context_fails_closed(void)
{
	wri_aes_ctx c;
	uint8_t in[16], out[16], zero[16];

	memset(&c, 0, sizeof(c));
	memset(in, 0x11, sizeof(in));
	memset(zero, 0, sizeof(zero));
	memset(out, 0xee, sizeof(out));
	wri_aes_enc_block(&c, in, out);
	WRT_CHECK_MEM(out, zero, 16);
	memset(out, 0xee, sizeof(out));
	wri_aes_dec_block(&c, in, out);
	WRT_CHECK_MEM(out, zero, 16);
}

/* Zero blocks: no read, no write. Guard bytes must survive. */
static void test_zero_blocks(void)
{
	wri_aes_ctx c;
	uint8_t key[16], iv[16], buf[16];

	memset(key, 1, sizeof(key));
	memset(iv, 2, sizeof(iv));
	memset(buf, 0x77, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, 16));
	wri_aes_cbc_enc(&c, iv, buf, buf, 0);
	wri_aes_cbc_dec(&c, iv, buf, buf, 0);
	{
		uint8_t want[16];

		memset(want, 0x77, sizeof(want));
		WRT_CHECK_MEM(buf, want, 16);
	}
}


/* ---- independent reference AES (textbook, byte oriented) -------------------------------------- */

static uint8_t ref_sbox[256], ref_isbox[256];

static uint8_t ref_xtime(uint8_t x)
{
	return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0u));
}

static uint8_t ref_mul(uint8_t a, uint8_t b)
{
	uint8_t r = 0;

	while (b) {
		if (b & 1u)
			r ^= a;
		a = ref_xtime(a);
		b >>= 1;
	}
	return r;
}

static uint8_t ref_rotl8(uint8_t x, unsigned n)
{
	return (uint8_t)((x << n) | (x >> (8u - n)));
}

static void ref_init(void)
{
	unsigned x, i;

	for (x = 0; x < 256; x++) {
		uint8_t inv = 1, b, s;

		if (x == 0) {
			inv = 0;
		} else {
			for (i = 0; i < 254; i++) /* x^254 = x^-1 in GF(2^8) */
				inv = ref_mul(inv, (uint8_t)x);
		}
		b = inv;
		s = (uint8_t)(b ^ ref_rotl8(b, 1) ^ ref_rotl8(b, 2) ^ ref_rotl8(b, 3) ^ ref_rotl8(b, 4) ^ 0x63u);
		ref_sbox[x] = s;
		ref_isbox[s] = (uint8_t)x;
	}
}

/* Expanded key as bytes: 16 * (Nr + 1). */
static void ref_expand(const uint8_t *key, size_t klen, uint8_t *w, unsigned *nr)
{
	unsigned nk = (unsigned)klen / 4u, total, i, j;
	uint8_t rc = 1;

	*nr = nk + 6u;
	total = 4u * (*nr + 1u);
	memcpy(w, key, klen);
	for (i = nk; i < total; i++) {
		uint8_t t[4];

		memcpy(t, w + 4u * (i - 1u), 4);
		if (i % nk == 0) {
			uint8_t t0 = t[0];

			t[0] = (uint8_t)(ref_sbox[t[1]] ^ rc);
			t[1] = ref_sbox[t[2]];
			t[2] = ref_sbox[t[3]];
			t[3] = ref_sbox[t0];
			rc = ref_xtime(rc);
		} else if (nk > 6u && i % nk == 4u) {
			for (j = 0; j < 4; j++)
				t[j] = ref_sbox[t[j]];
		}
		for (j = 0; j < 4; j++)
			w[4u * i + j] = (uint8_t)(w[4u * (i - nk) + j] ^ t[j]);
	}
}

static void ref_addkey(uint8_t *st, const uint8_t *rk)
{
	unsigned i;

	for (i = 0; i < 16; i++)
		st[i] ^= rk[i];
}

static void ref_subshift(uint8_t *st, const uint8_t *box, int inverse)
{
	uint8_t t[16];
	unsigned r, c;

	for (r = 0; r < 4; r++)
		for (c = 0; c < 4; c++) {
			if (!inverse)
				t[r + 4u * c] = box[st[r + 4u * ((c + r) % 4u)]];
			else
				t[r + 4u * ((c + r) % 4u)] = box[st[r + 4u * c]];
		}
	memcpy(st, t, 16);
}

static void ref_mix(uint8_t *st, int inverse)
{
	unsigned c;

	for (c = 0; c < 4; c++) {
		uint8_t a0 = st[4u * c], a1 = st[4u * c + 1], a2 = st[4u * c + 2], a3 = st[4u * c + 3];

		if (!inverse) {
			st[4u * c] = (uint8_t)(ref_mul(a0, 2) ^ ref_mul(a1, 3) ^ a2 ^ a3);
			st[4u * c + 1] = (uint8_t)(a0 ^ ref_mul(a1, 2) ^ ref_mul(a2, 3) ^ a3);
			st[4u * c + 2] = (uint8_t)(a0 ^ a1 ^ ref_mul(a2, 2) ^ ref_mul(a3, 3));
			st[4u * c + 3] = (uint8_t)(ref_mul(a0, 3) ^ a1 ^ a2 ^ ref_mul(a3, 2));
		} else {
			st[4u * c] = (uint8_t)(ref_mul(a0, 14) ^ ref_mul(a1, 11) ^ ref_mul(a2, 13) ^ ref_mul(a3, 9));
			st[4u * c + 1] = (uint8_t)(ref_mul(a0, 9) ^ ref_mul(a1, 14) ^ ref_mul(a2, 11) ^ ref_mul(a3, 13));
			st[4u * c + 2] = (uint8_t)(ref_mul(a0, 13) ^ ref_mul(a1, 9) ^ ref_mul(a2, 14) ^ ref_mul(a3, 11));
			st[4u * c + 3] = (uint8_t)(ref_mul(a0, 11) ^ ref_mul(a1, 13) ^ ref_mul(a2, 9) ^ ref_mul(a3, 14));
		}
	}
}

static void ref_enc(const uint8_t *w, unsigned nr, const uint8_t in[16], uint8_t out[16])
{
	uint8_t st[16];
	unsigned r;

	memcpy(st, in, 16);
	ref_addkey(st, w);
	for (r = 1; r < nr; r++) {
		ref_subshift(st, ref_sbox, 0);
		ref_mix(st, 0);
		ref_addkey(st, w + 16u * r);
	}
	ref_subshift(st, ref_sbox, 0);
	ref_addkey(st, w + 16u * nr);
	memcpy(out, st, 16);
}

static void ref_dec(const uint8_t *w, unsigned nr, const uint8_t in[16], uint8_t out[16])
{
	uint8_t st[16];
	unsigned r;

	memcpy(st, in, 16);
	ref_addkey(st, w + 16u * nr);
	for (r = nr - 1u; r >= 1; r--) {
		ref_subshift(st, ref_isbox, 1);
		ref_addkey(st, w + 16u * r);
		ref_mix(st, 1);
	}
	ref_subshift(st, ref_isbox, 1);
	ref_addkey(st, w);
	memcpy(out, st, 16);
}

/* The reference must itself be right: FIPS 197 appendix C, then the module is compared with it. */
static void test_against_reference(void)
{
	uint8_t key[32], pt[16], a[16], b[16], w[240], fk[32], fpt[16], fct[16];
	wri_aes_ctx c;
	unsigned nr, k, iter, x;
	int sbox_ok = 1;

	ref_init();
	/* spot checks of the computed S-box against FIPS 197 figure 7 */
	WRT_CHECK_U64(ref_sbox[0x00], 0x63);
	WRT_CHECK_U64(ref_sbox[0x01], 0x7c);
	WRT_CHECK_U64(ref_sbox[0x53], 0xed);
	WRT_CHECK_U64(ref_sbox[0xff], 0x16);
	for (x = 0; x < 256; x++)
		if (ref_isbox[ref_sbox[x]] != x)
			sbox_ok = 0;
	WRT_CHECK(sbox_ok);

	hx("00112233445566778899aabbccddeeff", fpt, sizeof(fpt));
	hx("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", fk, sizeof(fk));
	hx("8ea2b7ca516745bfeafc49904b496089", fct, sizeof(fct));
	ref_expand(fk, 32, w, &nr);
	ref_enc(w, nr, fpt, a);
	WRT_CHECK_MEM(a, fct, 16);
	ref_dec(w, nr, fct, a);
	WRT_CHECK_MEM(a, fpt, 16);
	hx("69c4e0d86a7b0430d8cdb78070b4c55a", fct, sizeof(fct));
	ref_expand(fk, 16, w, &nr);
	ref_enc(w, nr, fpt, a);
	WRT_CHECK_MEM(a, fct, 16);
	hx("dda97ca4864cdfe06eaf70a0ec0d7191", fct, sizeof(fct));
	ref_expand(fk, 24, w, &nr);
	ref_enc(w, nr, fpt, a);
	WRT_CHECK_MEM(a, fct, 16);

	for (k = 0; k < 3; k++) {
		for (iter = 0; iter < 3000; iter++) {
			unsigned j;
			int same_sched = 1;

			rnd_fill(key, sizeof(key));
			rnd_fill(pt, sizeof(pt));
			if (iter == 0) {
				memset(key, 0, sizeof(key));
				memset(pt, 0, sizeof(pt));
			} else if (iter == 1) {
				memset(key, 0xff, sizeof(key));
				memset(pt, 0xff, sizeof(pt));
			}
			WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, key_sizes[k]));
			ref_expand(key, key_sizes[k], w, &nr);
			WRT_CHECK_U64(c.rounds, nr);
			/* the round key words are the reference bytes, big endian */
			for (j = 0; j < 4u * (nr + 1u); j++) {
				uint32_t v = ((uint32_t)w[4u * j] << 24) | ((uint32_t)w[4u * j + 1] << 16) |
					     ((uint32_t)w[4u * j + 2] << 8) | (uint32_t)w[4u * j + 3];

				if (c.rk[j] != v)
					same_sched = 0;
			}
			WRT_CHECK(same_sched);
			ref_enc(w, nr, pt, a);
			wri_aes_enc_block(&c, pt, b);
			WRT_CHECK_MEM(b, a, 16);
			ref_dec(w, nr, pt, a);
			wri_aes_dec_block(&c, pt, b);
			WRT_CHECK_MEM(b, a, 16);
		}
	}
}

/* FIPS 197 appendix A: last round-key words of the three worked key expansions. */
static void test_key_schedule_checkpoints(void)
{
	static const struct {
		const char *key;
		size_t klen;
		uint32_t first_derived, last;
		unsigned nwords;
	} v[3] = {
	    {"2b7e151628aed2a6abf7158809cf4f3c", 16, 0xa0fafe17u, 0xb6630ca6u, 44}, /* A.1: w4, w43 */
	    {"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", 24, 0xfe0c91f7u, 0x01002202u, 52}, /* A.2: w6, w51 */
	    {"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", 32, 0x9ba35411u, 0x706c631eu, 60}, /* A.3: w8, w59 */
	};
	uint8_t key[32];
	wri_aes_ctx c;
	size_t i;

	for (i = 0; i < 3; i++) {
		WRT_CHECK_U64(hx(v[i].key, key, sizeof(key)), v[i].klen);
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, v[i].klen));
		WRT_CHECK_U64(c.rk[v[i].klen / 4], v[i].first_derived);
		WRT_CHECK_U64(c.rk[v[i].nwords - 1], v[i].last);
	}
}

/* ---- buffers: exact-size heap blocks, odd alignment, streaming ------------------------------- */

static void test_exact_buffers_and_alignment(void)
{
	uint8_t key[32], iv[16], *pt, *ct, *back, *region;
	wri_aes_ctx c;
	size_t k, nb, off;

	for (k = 0; k < 3; k++) {
		rnd_fill(key, sizeof(key));
		rnd_fill(iv, sizeof(iv));
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, key_sizes[k]));
		for (nb = 1; nb <= 9; nb++) {
			size_t n = nb * 16;

			pt = (uint8_t *)malloc(n);
			ct = (uint8_t *)malloc(n);
			back = (uint8_t *)malloc(n);
			if (pt == NULL || ct == NULL || back == NULL) {
				WRT_CHECK(!"allocation");
				free(pt);
				free(ct);
				free(back);
				continue;
			}
			rnd_fill(pt, n);
			wri_aes_cbc_enc(&c, iv, pt, ct, nb); /* ASan: no read or write beyond n */
			wri_aes_cbc_dec(&c, iv, ct, back, nb);
			WRT_CHECK_MEM(back, pt, n);
			/* in place, exact-size buffer */
			memcpy(back, pt, n);
			wri_aes_cbc_enc(&c, iv, back, back, nb);
			WRT_CHECK_MEM(back, ct, n);
			wri_aes_cbc_dec(&c, iv, back, back, nb);
			WRT_CHECK_MEM(back, pt, n);
			free(pt);
			free(ct);
			free(back);
		}
		/* iv, input and output at odd addresses (the code does byte loads, never word casts) */
		for (off = 1; off < 8; off++) {
			uint8_t ref[16 * 4];

			region = (uint8_t *)malloc(16 + 16 * 4 + 16 * 4 + 16 + 8);
			if (region == NULL) {
				WRT_CHECK(!"allocation");
				continue;
			}
			memcpy(region + off, iv, 16);
			rnd_fill(region + off + 16, 16 * 4);
			wri_aes_cbc_enc(&c, iv, region + off + 16, ref, 4);
			wri_aes_cbc_enc(&c, region + off, region + off + 16, region + off + 16 + 16 * 4, 4);
			WRT_CHECK_MEM(region + off + 16 + 16 * 4, ref, 16 * 4);
			wri_aes_cbc_dec(&c, region + off, region + off + 16 + 16 * 4, region + off + 16, 4);
			wri_aes_cbc_enc(&c, iv, region + off + 16, region + off + 16, 4);
			WRT_CHECK_MEM(region + off + 16, ref, 16 * 4);
			free(region);
		}
	}
}

/* An iv that lives inside the output buffer is read once up front. */
static void test_iv_aliases_output(void)
{
	uint8_t key[16], buf[16 * 3], pt[16 * 2], iv[16], want[16 * 2], got[16 * 2];
	wri_aes_ctx c;

	rnd_fill(key, sizeof(key));
	rnd_fill(iv, sizeof(iv));
	rnd_fill(pt, sizeof(pt));
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, 16));
	wri_aes_cbc_enc(&c, iv, pt, want, 2);
	memcpy(buf, iv, 16); /* iv is the first block of the output region */
	wri_aes_cbc_enc(&c, buf, pt, buf, 2);
	memcpy(got, buf, 32);
	WRT_CHECK_MEM(got, want, 32);
	wri_aes_cbc_dec(&c, iv, want, got, 2);
	WRT_CHECK_MEM(got, pt, 32);
}

/* CBC is a stream: two calls chained through the last ciphertext block equal one call. */
static void test_cbc_chaining_split(void)
{
	uint8_t key[32], iv[16], pt[16 * 8], whole[16 * 8], parts[16 * 8], back[16 * 8];
	wri_aes_ctx c;
	size_t k, cut;

	for (k = 0; k < 3; k++) {
		rnd_fill(key, sizeof(key));
		rnd_fill(iv, sizeof(iv));
		rnd_fill(pt, sizeof(pt));
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, key_sizes[k]));
		wri_aes_cbc_enc(&c, iv, pt, whole, 8);
		for (cut = 0; cut <= 8; cut++) {
			wri_aes_cbc_enc(&c, iv, pt, parts, cut);
			wri_aes_cbc_enc(&c, cut ? parts + 16 * (cut - 1) : iv, pt + 16 * cut, parts + 16 * cut, 8 - cut);
			WRT_CHECK_MEM(parts, whole, sizeof(whole));
			wri_aes_cbc_dec(&c, iv, whole, back, cut);
			wri_aes_cbc_dec(&c, cut ? whole + 16 * (cut - 1) : iv, whole + 16 * cut, back + 16 * cut, 8 - cut);
			WRT_CHECK_MEM(back, pt, sizeof(pt));
		}
	}
}

/* CBC error propagation: one flipped ciphertext bit garbles that block and flips the same bit in the next. */
static void test_cbc_bit_flip_shape(void)
{
	uint8_t key[16], iv[16], pt[16 * 4], ct[16 * 4], back[16 * 4];
	wri_aes_ctx c;
	size_t i;

	rnd_fill(key, sizeof(key));
	rnd_fill(iv, sizeof(iv));
	rnd_fill(pt, sizeof(pt));
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, 16));
	wri_aes_cbc_enc(&c, iv, pt, ct, 4);
	ct[16 + 5] ^= 0x40; /* block 1, byte 5 */
	wri_aes_cbc_dec(&c, iv, ct, back, 4);
	WRT_CHECK_MEM(back, pt, 16);                    /* block 0 intact */
	WRT_CHECK(memcmp(back + 16, pt + 16, 16) != 0); /* block 1 garbled */
	for (i = 0; i < 16; i++)
		WRT_CHECK(back[32 + i] == (uint8_t)(pt[32 + i] ^ (i == 5 ? 0x40 : 0)));
	WRT_CHECK_MEM(back + 48, pt + 48, 16); /* block 3 intact */
}

/* cipher-type1.json envelopes: sealed = u32le len || CBC(1 || magic || item || PKCS#7 padding). */
static void test_cephx_type1_envelopes(void)
{
	static const uint8_t magic[8] = {0x55, 0xaa, 0x26, 0x88, 0xad, 0x9c, 0x00, 0xff};
	wrt_json j;
	wrt_tok root, envs;
	uint8_t *secret = NULL, *iv = NULL;
	size_t secret_n = 0, iv_n = 0, i, n;
	wri_aes_ctx c;

	if (wrt_json_load_vec(&j, "cephx/cipher-type1.json") != 0) {
		WRT_CHECK(!"cipher-type1.json loads");
		return;
	}
	root = wrt_json_root(&j);
	WRT_CHECK(wrt_json_get_hex(&j, root, "key_secret", &secret, &secret_n) == 0);
	WRT_CHECK(wrt_json_get_hex(&j, root, "iv", &iv, &iv_n) == 0);
	envs = wrt_json_get(&j, root, "envelopes");
	n = wrt_json_count(&j, envs);
	WRT_CHECK(n >= 3);
	if (secret_n >= 16 && iv_n == 16)
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, secret, 16));
	else
		n = 0;
	for (i = 0; i < n; i++) {
		wrt_tok e = wrt_json_at(&j, envs, i);
		uint8_t *item = NULL, *sealed = NULL, *plain = NULL, *again = NULL;
		size_t item_n = 0, sealed_n = 0, ct_n, plain_n, pad;

		if (wrt_json_get_hex(&j, e, "item", &item, &item_n) != 0 ||
		    wrt_json_get_hex(&j, e, "sealed_length_prefixed", &sealed, &sealed_n) != 0 || sealed_n < 4 + 16) {
			WRT_CHECK(!"envelope fields decode");
			free(item);
			free(sealed);
			continue;
		}
		ct_n = (size_t)sealed[0] | ((size_t)sealed[1] << 8) | ((size_t)sealed[2] << 16) | ((size_t)sealed[3] << 24);
		WRT_CHECK_U64(ct_n, sealed_n - 4);
		WRT_CHECK_U64(ct_n % 16, 0);
		plain = (uint8_t *)malloc(ct_n);
		again = (uint8_t *)malloc(ct_n);
		if (plain != NULL && again != NULL && ct_n % 16 == 0 && ct_n == sealed_n - 4) {
			wri_aes_cbc_dec(&c, iv, sealed + 4, plain, ct_n / 16);
			pad = plain[ct_n - 1];
			WRT_CHECK(pad >= 1 && pad <= 16);
			plain_n = ct_n - pad;
			WRT_CHECK_U64(plain_n, 1 + 8 + item_n);
			if (plain_n == 1 + 8 + item_n) {
				WRT_CHECK_U64(plain[0], 1);
				WRT_CHECK_MEM(plain + 1, magic, 8);
				if (item_n > 0)
					WRT_CHECK_MEM(plain + 9, item, item_n);
			}
			wri_aes_cbc_enc(&c, iv, plain, again, ct_n / 16);
			WRT_CHECK_MEM(again, sealed + 4, ct_n);
		} else {
			WRT_CHECK(!"allocation / length");
		}
		free(plain);
		free(again);
		free(item);
		free(sealed);
	}
	free(secret);
	free(iv);
	wrt_json_free(&j);
}

/* A rejected setkey leaves the context unusable, never half old / half new. */
static void test_failed_setkey_fails_closed(void)
{
	uint8_t key[32], in[16], out[16], zero[16], iv[16], ct[32], pt[32];
	wri_aes_ctx c;

	memset(key, 0x42, sizeof(key));
	memset(in, 0x11, sizeof(in));
	memset(zero, 0, sizeof(zero));
	memset(iv, 0x33, sizeof(iv));
	memset(pt, 0x55, sizeof(pt));
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, 32));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_aes_setkey(&c, key, 17));
	WRT_CHECK_U64(c.rounds, 0);
	wri_aes_enc_block(&c, in, out);
	WRT_CHECK_MEM(out, zero, 16);
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, 16));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_aes_setkey(&c, NULL, 16));
	WRT_CHECK_U64(c.rounds, 0);
	wri_aes_dec_block(&c, in, out);
	WRT_CHECK_MEM(out, zero, 16);
	/* CBC on a dead context writes zero blocks and still stays inside its buffer */
	memset(ct, 0xaa, sizeof(ct));
	wri_aes_cbc_enc(&c, iv, pt, ct, 1);
	WRT_CHECK_MEM(ct, zero, 16);
	WRT_CHECK(ct[16] == 0xaa && ct[31] == 0xaa);
	/* a NULL context is an error path, not a crash */
	memset(out, 0xee, sizeof(out));
	wri_aes_enc_block(NULL, in, out);
	WRT_CHECK_MEM(out, zero, 16);
	/* and the context recovers with a good key */
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, 32));
	WRT_CHECK_U64(c.rounds, 14);
	/* bad length with a NULL context: the length error wins for an invalid size, EINVAL for a valid one */
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_aes_setkey(NULL, key, 5));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_aes_setkey(NULL, key, 16));
}

int main(void)
{
	test_fips197();
	test_fips197_appendix_b();
	test_sp800_38a_cbc();
	test_cephx_type1_vectors();
	test_cbc_equals_manual_chain();
	test_random_roundtrips();
	test_key_sensitivity();
	test_key_length_rejection();
	test_unkeyed_context_fails_closed();
	test_zero_blocks();
	test_key_schedule_checkpoints();
	test_against_reference();
	test_exact_buffers_and_alignment();
	test_iv_aliases_output();
	test_cbc_chaining_split();
	test_cbc_bit_flip_shape();
	test_cephx_type1_envelopes();
	test_failed_setkey_fails_closed();
	return wrt_finish();
}
