/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_gcm_ossl - the portable streaming AES-GCM (wri_gcm) against OpenSSL EVP (libcrypto 3.x), the differential oracle.
 * Built only when OpenSSL is found (the name ends in _ossl); OpenSSL is never a dependency of the core.
 *
 * Random cases from a fixed-seed generator (a failure reproduces), AES-128 and AES-256, a 12-byte IV, additional data of 0 to 300
 * bytes and a message of 0 to 3000 bytes (now and then 70 KB), fed to the core in random pieces (0 to 70 bytes at a time, so partial
 * blocks of every kind occur, or in one piece):
 *   - ciphertext and tag equal OpenSSL's, out of place and in place;
 *   - OpenSSL decrypts what the core encrypted, and the core decrypts what OpenSSL encrypted (in place as well), with an operation
 *     in the middle of a long run on the same key and object (the key is reused for 16 operations at a time);
 *   - one flipped bit in the ciphertext, the tag, the additional data or the IV is refused by both (and an operation on the same
 *     object right after the refusal works).
 */
#include "wrt.h"

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
int main(void)
{
	WRT_SKIP("OpenSSL older than 3.0: differential test needs the 3.x EVP API");
	return 0;
}
#else

#include <openssl/evp.h>

#include "wri_gcm.h"

#define NCASES 6000u
#define MAXN 70000u

static uint64_t rng_state = 0x3f84d5b5b5470917ull;

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

static const EVP_CIPHER *cipher_for(size_t keylen)
{
	return keylen == 16u ? EVP_aes_128_gcm() : EVP_aes_256_gcm();
}

static int ossl_enc(const uint8_t *key, size_t keylen, const uint8_t *iv, const uint8_t *aad, size_t aadlen, const uint8_t *in,
		    size_t n, uint8_t *out, uint8_t tag[16])
{
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	int len = 0, rc = -1;

	if (c == NULL)
		return -1;
	if (EVP_EncryptInit_ex(c, cipher_for(keylen), NULL, NULL, NULL) == 1 &&
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 && EVP_EncryptInit_ex(c, NULL, NULL, key, iv) == 1 &&
	    (aadlen == 0 || EVP_EncryptUpdate(c, NULL, &len, aad, (int)aadlen) == 1) &&
	    (n == 0 || EVP_EncryptUpdate(c, out, &len, in, (int)n) == 1) && EVP_EncryptFinal_ex(c, out + n, &len) == 1 &&
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1)
		rc = 0;
	EVP_CIPHER_CTX_free(c);
	return rc;
}

static int ossl_dec(const uint8_t *key, size_t keylen, const uint8_t *iv, const uint8_t *aad, size_t aadlen, const uint8_t *in,
		    size_t n, const uint8_t tag[16], uint8_t *out)
{
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	uint8_t t[16];
	int len = 0, rc = -1;

	if (c == NULL)
		return -1;
	memcpy(t, tag, 16);
	if (EVP_DecryptInit_ex(c, cipher_for(keylen), NULL, NULL, NULL) == 1 &&
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 && EVP_DecryptInit_ex(c, NULL, NULL, key, iv) == 1 &&
	    (aadlen == 0 || EVP_DecryptUpdate(c, NULL, &len, aad, (int)aadlen) == 1) &&
	    (n == 0 || EVP_DecryptUpdate(c, out, &len, in, (int)n) == 1) &&
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, t) == 1 && EVP_DecryptFinal_ex(c, out + n, &len) == 1)
		rc = 0;
	EVP_CIPHER_CTX_free(c);
	return rc;
}

/* The core, one operation, data in pieces of 0 .. maxstep bytes (0 = one piece); aad in pieces of the same kind. */
static wr_status core_op(wri_gcm *g, int dec, const uint8_t *iv, const uint8_t *aad, size_t aadn, const uint8_t *in, uint8_t *out,
			 size_t n, uint8_t tag[16], size_t maxstep)
{
	size_t pos;
	wr_status st = wri_gcm_start(g, iv, 12, dec);

	if (st != WR_OK)
		return st;
	for (pos = 0; pos < aadn;) {
		size_t step = (maxstep == 0u) ? aadn - pos : (size_t)(rnd() % (maxstep + 1u));

		if (step > aadn - pos)
			step = aadn - pos;
		st = wri_gcm_aad(g, aad + pos, step);
		if (st != WR_OK)
			return st;
		pos += step;
	}
	for (pos = 0; pos < n;) {
		size_t step = (maxstep == 0u) ? n - pos : (size_t)(rnd() % (maxstep + 1u));

		if (step > n - pos)
			step = n - pos;
		st = wri_gcm_update(g, in + pos, out + pos, step);
		if (st != WR_OK)
			return st;
		pos += step;
	}
	return dec ? wri_gcm_final_dec(g, tag) : wri_gcm_final_enc(g, tag);
}

static void test_random(void)
{
	uint8_t *buf = (uint8_t *)calloc(MAXN + 16u, 1), *pt = (uint8_t *)calloc(MAXN, 1), *ct_o = (uint8_t *)calloc(MAXN + 16u, 1),
		*ct_c = (uint8_t *)calloc(MAXN + 16u, 1), *back = (uint8_t *)calloc(MAXN + 16u, 1);
	uint8_t key[32], iv[12], aad[300], tag_o[16], tag_c[16], bad[16];
	size_t i, keylen = 16;
	wri_gcm g;

	if (buf == NULL || pt == NULL || ct_o == NULL || ct_c == NULL || back == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	for (i = 0; i < NCASES; i++) {
		size_t aadlen = (i % 5u == 0u) ? 0u : rnd() % 301u, n = (i % 97u == 0u) ? MAXN : rnd() % 3001u, bit;
		size_t maxstep = (rnd() % 4u == 0u) ? 0u : 1u + rnd() % 70u;

		if (i % 16u == 0u) { /* a new key every sixteen operations, the same object and key in between */
			keylen = (i % 32u == 0u) ? 16u : 32u;
			rnd_fill(key, keylen);
			WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, keylen));
		}
		rnd_fill(iv, 12);
		rnd_fill(aad, aadlen);
		rnd_fill(pt, n);

		WRT_CHECK_STATUS(0, ossl_enc(key, keylen, iv, aad, aadlen, pt, n, ct_o, tag_o));
		memset(tag_c, 0xee, 16);
		WRT_CHECK_STATUS(WR_OK, core_op(&g, 0, iv, aad, aadlen, pt, ct_c, n, tag_c, maxstep));
		WRT_CHECK(memcmp(ct_c, ct_o, n) == 0);
		WRT_CHECK(memcmp(tag_c, tag_o, 16) == 0);
		/* in place */
		memcpy(buf, pt, n);
		WRT_CHECK_STATUS(WR_OK, core_op(&g, 0, iv, aad, aadlen, buf, buf, n, tag_c, maxstep));
		WRT_CHECK(memcmp(buf, ct_o, n) == 0);
		WRT_CHECK(memcmp(tag_c, tag_o, 16) == 0);

		/* cross decryption */
		WRT_CHECK_STATUS(0, ossl_dec(key, keylen, iv, aad, aadlen, ct_c, n, tag_c, back));
		WRT_CHECK(memcmp(back, pt, n) == 0);
		WRT_CHECK_STATUS(WR_OK, core_op(&g, 1, iv, aad, aadlen, ct_o, back, n, tag_o, maxstep));
		WRT_CHECK(memcmp(back, pt, n) == 0);
		memcpy(buf, ct_o, n);
		WRT_CHECK_STATUS(WR_OK, core_op(&g, 1, iv, aad, aadlen, buf, buf, n, tag_o, maxstep));
		WRT_CHECK(memcmp(buf, pt, n) == 0);

		/* one flipped bit: refused by both */
		memcpy(bad, tag_o, 16);
		switch (rnd() % 4u) {
		case 0:
			bit = rnd() % 128u;
			bad[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
			break;
		case 1:
			if (n > 0u) {
				bit = rnd() % (n * 8u);
				ct_o[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
			} else {
				bad[0] ^= 1;
			}
			break;
		case 2:
			if (aadlen > 0u) {
				bit = rnd() % (aadlen * 8u);
				aad[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
			} else {
				bad[1] ^= 0x80;
			}
			break;
		default:
			bit = rnd() % 96u;
			iv[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
			break;
		}
		WRT_CHECK_STATUS(-1, ossl_dec(key, keylen, iv, aad, aadlen, ct_o, n, bad, back));
		WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, core_op(&g, 1, iv, aad, aadlen, ct_o, back, n, bad, maxstep));
	}
	wri_gcm_wipe(&g);
	free(buf);
	free(pt);
	free(ct_o);
	free(ct_c);
	free(back);
}

int main(void)
{
	test_random();
	printf("crypto.gcm_ossl: %lu checks, %lu failures\n", wrt_checks, wrt_failures);
	return wrt_finish();
}

#endif
