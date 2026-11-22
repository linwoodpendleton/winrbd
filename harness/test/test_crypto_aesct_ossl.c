/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_aesct_ossl - differential test of the constant-time AES (wri_aesct) against OpenSSL's EVP AES-128 and AES-256.
 * Built only when OpenSSL is found (the name ends in _ossl); OpenSSL is never a dependency of the core.
 *
 *   - ECB: 20,000 random cases per key size, 1..40 blocks;
 *   - CTR: 20,000 random cases per key size, random 12-byte nonce and random 32-bit start counter, 0..600 bytes. OpenSSL's CTR
 *     increments the whole 128-bit block, wri_aesct_ctr32 only the last 32 bits, so a message that crosses the wrap of the 32-bit
 *     counter is compared as two OpenSSL runs: up to the wrap with the starting counter block, then the rest with a block whose
 *     counter is 0 (which is what GCM's counter does); counters near the wrap are the norm in this test, not the exception;
 *   - the counter written back by ctr32 is checked against the arithmetic.
 * The random source is a fixed-seed xorshift, so a failure reproduces.
 */
#include "wrt.h"

#include <openssl/evp.h>

#include "wri_aesct.h"

#define NCASES 20000u

static uint64_t rng_state = 0x13198a2e03707344ull;

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

static uint8_t *xmalloc(size_t n)
{
	uint8_t *p = (uint8_t *)calloc(n != 0 ? n : 1, 1);

	if (p == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	return p;
}

/* One-shot OpenSSL AES in ECB or CTR mode, no padding. Returns 0 on success. */
static int ossl_aes(int ctr_mode, size_t klen, const uint8_t *key, const uint8_t *iv, const uint8_t *in, size_t n, uint8_t *out)
{
	const EVP_CIPHER *ci;
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	int len = 0, len2 = 0, rc = -1;

	if (c == NULL)
		return -1;
	if (klen == 16u)
		ci = ctr_mode ? EVP_aes_128_ctr() : EVP_aes_128_ecb();
	else
		ci = ctr_mode ? EVP_aes_256_ctr() : EVP_aes_256_ecb();
	if (EVP_EncryptInit_ex(c, ci, NULL, key, iv) == 1 && EVP_CIPHER_CTX_set_padding(c, 0) == 1 &&
	    (n == 0u || EVP_EncryptUpdate(c, out, &len, in, (int)n) == 1) && EVP_EncryptFinal_ex(c, out + len, &len2) == 1)
		rc = (size_t)(len + len2) == n ? 0 : -1;
	EVP_CIPHER_CTX_free(c);
	return rc;
}

static void put_ctr(uint8_t ctr[16], const uint8_t *nonce, uint32_t cnt)
{
	memcpy(ctr, nonce, 12);
	ctr[12] = (uint8_t)(cnt >> 24);
	ctr[13] = (uint8_t)(cnt >> 16);
	ctr[14] = (uint8_t)(cnt >> 8);
	ctr[15] = (uint8_t)cnt;
}

static void test_ecb(void)
{
	unsigned i;
	size_t bad = 0;

	for (i = 0; i < 2u * NCASES; i++) {
		size_t klen = (i & 1u) ? 32u : 16u, n = 16u * (1u + rnd() % 40u);
		uint8_t key[32], *in = xmalloc(n), *want = xmalloc(n), *got = xmalloc(n);
		wri_aesct_ctx c;

		rnd_fill(key, klen);
		rnd_fill(in, n);
		WRT_CHECK(ossl_aes(0, klen, key, NULL, in, n, want) == 0);
		WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, klen));
		wri_aesct_encrypt_blocks(&c, in, got, n / 16u);
		if (memcmp(want, got, n) != 0)
			bad++;
		wri_aesct_wipe(&c);
		free(in);
		free(want);
		free(got);
	}
	WRT_CHECK_U64(bad, 0);
}

static void test_ctr(void)
{
	unsigned i;
	size_t bad = 0, wraps = 0;

	for (i = 0; i < 2u * NCASES; i++) {
		size_t klen = (i & 1u) ? 32u : 16u, n = rnd() % 601u, first, blocks = (n + 15u) / 16u;
		uint8_t key[32], nonce[12], ctr[16], iv[16], end[16];
		uint8_t *in = xmalloc(n), *want = xmalloc(n), *got = xmalloc(n);
		uint32_t start, room; /* blocks left before the 32-bit counter wraps: room == 0 means 2^32 */
		wri_aesct_ctx c;

		rnd_fill(key, klen);
		rnd_fill(in, n);
		rnd_fill(nonce, sizeof(nonce));
		switch (i % 4u) { /* three of four near the wrap, so crossing it is common */
		case 0: start = rnd(); break;
		case 1: start = 0u - (1u + rnd() % 40u); break;
		case 2: start = 0u - (1u + rnd() % 3u); break;
		default: start = 0xffffffffu; break;
		}
		room = 0u - start;
		put_ctr(ctr, nonce, start);
		/* OpenSSL, as one run up to the wrap and one after it */
		if (room != 0u && (size_t)room < blocks) {
			first = (size_t)room * 16u;
			wraps++;
			put_ctr(iv, nonce, start);
			WRT_CHECK(ossl_aes(1, klen, key, iv, in, first, want) == 0);
			put_ctr(iv, nonce, 0u);
			WRT_CHECK(ossl_aes(1, klen, key, iv, in + first, n - first, want + first) == 0);
		} else {
			put_ctr(iv, nonce, start);
			WRT_CHECK(ossl_aes(1, klen, key, iv, in, n, want) == 0);
		}
		WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, klen));
		wri_aesct_ctr32(&c, ctr, in, got, n);
		put_ctr(end, nonce, start + (uint32_t)blocks);
		if ((n != 0u && memcmp(want, got, n) != 0) || memcmp(ctr, end, 16) != 0) {
			bad++;
			fprintf(stderr, "CTR case %u (klen %zu, start 0x%08x, n %zu) differs from OpenSSL\n", i, klen, start, n);
		}
		wri_aesct_wipe(&c);
		free(in);
		free(want);
		free(got);
	}
	WRT_CHECK_U64(bad, 0);
	WRT_CHECK(wraps > 1000u); /* the wrap really was exercised */
}

int main(void)
{
	test_ecb();
	test_ctr();
	return wrt_finish();
}
