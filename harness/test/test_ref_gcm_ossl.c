/* SPDX-License-Identifier: MIT */
/*
 * test_ref_gcm_ossl - the reference AES-GCM (harness/test/support/ref_gcm.c) against OpenSSL EVP (libcrypto 3.x).
 * Built only when OpenSSL is found (the name ends in _ossl); OpenSSL is a differential oracle, never a dependency.
 *
 * Random cases from a fixed-seed generator (a failure reproduces), each checked in both directions:
 *   - key of 16, 24 or 32 bytes, IV of 1 to 128 bytes (the most OpenSSL takes) (one third of the cases use the 96-bit IV of msgr2),
 *     additional data of 0 to 200 bytes (every third case none), message of 0 to 400 bytes: the reference's
 *     ciphertext and tag equal OpenSSL's; OpenSSL decrypts the reference's output and the reference decrypts
 *     OpenSSL's (in place as well);
 *   - a flipped bit anywhere (ciphertext, tag, additional data, IV) is refused by both;
 *   - ref_secure_seal / ref_secure_open against AES-128-GCM with the 12-byte nonce, including nonce stepping
 *     over a run of 40 operations and a counter that wraps in the middle of it.
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

#include "ref_gcm.h"

#define NCASES 6000

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

static const EVP_CIPHER *cipher_for(size_t keylen)
{
	return keylen == 16 ? EVP_aes_128_gcm() : (keylen == 24 ? EVP_aes_192_gcm() : EVP_aes_256_gcm());
}

/* OpenSSL encrypt: returns 0 on success. */
static int ossl_enc(const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, const uint8_t *aad,
		    size_t aadlen, const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[16])
{
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	int len = 0, rc = -1;

	if (c == NULL)
		return -1;
	if (EVP_EncryptInit_ex(c, cipher_for(keylen), NULL, NULL, NULL) == 1 &&
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, (int)ivlen, NULL) == 1 &&
	    EVP_EncryptInit_ex(c, NULL, NULL, key, iv) == 1 &&
	    (aadlen == 0 || EVP_EncryptUpdate(c, NULL, &len, aad, (int)aadlen) == 1) &&
	    (n == 0 || EVP_EncryptUpdate(c, out, &len, in, (int)n) == 1) && EVP_EncryptFinal_ex(c, out + n, &len) == 1 &&
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1)
		rc = 0;
	EVP_CIPHER_CTX_free(c);
	return rc;
}

/* OpenSSL decrypt: 0 when the tag verified. */
static int ossl_dec(const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, const uint8_t *aad,
		    size_t aadlen, const uint8_t *in, size_t n, const uint8_t tag[16], uint8_t *out)
{
	EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
	uint8_t t[16];
	int len = 0, rc = -1;

	if (c == NULL)
		return -1;
	memcpy(t, tag, 16);
	if (EVP_DecryptInit_ex(c, cipher_for(keylen), NULL, NULL, NULL) == 1 &&
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, (int)ivlen, NULL) == 1 &&
	    EVP_DecryptInit_ex(c, NULL, NULL, key, iv) == 1 &&
	    (aadlen == 0 || EVP_DecryptUpdate(c, NULL, &len, aad, (int)aadlen) == 1) &&
	    (n == 0 || EVP_DecryptUpdate(c, out, &len, in, (int)n) == 1) &&
	    EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, t) == 1 && EVP_DecryptFinal_ex(c, out + n, &len) == 1)
		rc = 0;
	EVP_CIPHER_CTX_free(c);
	return rc;
}

static void test_random(void)
{
	static uint8_t key[32], iv[200], aad[200], pt[400], ct_r[400], ct_o[400], back[400], buf[400];
	size_t i;

	for (i = 0; i < NCASES; i++) {
		static const size_t kl[3] = {16, 24, 32};
		size_t keylen = kl[rnd() % 3], ivlen = (i % 3 == 0) ? 12 : 1 + rnd() % 128, aadlen = (i % 3 == 1) ? 0 : rnd() % 201,
		       n = rnd() % 401, bit;
		uint8_t tag_r[16], tag_o[16], bad[16];
		int bad_field;

		rnd_fill(key, keylen);
		rnd_fill(iv, ivlen);
		rnd_fill(aad, aadlen);
		rnd_fill(pt, n);

		WRT_CHECK_STATUS(0, ref_gcm_seal(key, keylen, iv, ivlen, aad, aadlen, pt, n, ct_r, tag_r));
		WRT_CHECK_STATUS(0, ossl_enc(key, keylen, iv, ivlen, aad, aadlen, pt, n, ct_o, tag_o));
		WRT_CHECK(memcmp(ct_r, ct_o, n) == 0);
		WRT_CHECK(memcmp(tag_r, tag_o, 16) == 0);

		/* cross decryption, and in place */
		WRT_CHECK_STATUS(0, ossl_dec(key, keylen, iv, ivlen, aad, aadlen, ct_r, n, tag_r, back));
		WRT_CHECK(memcmp(back, pt, n) == 0);
		WRT_CHECK_STATUS(0, ref_gcm_open(key, keylen, iv, ivlen, aad, aadlen, ct_o, n, tag_o, back));
		WRT_CHECK(memcmp(back, pt, n) == 0);
		memcpy(buf, ct_o, n);
		WRT_CHECK_STATUS(0, ref_gcm_open(key, keylen, iv, ivlen, aad, aadlen, buf, n, tag_o, buf));
		WRT_CHECK(memcmp(buf, pt, n) == 0);

		/* one flipped bit in a random place: refused by both */
		memcpy(bad, tag_r, 16);
		bad_field = (int)(rnd() % 4);
		if (bad_field == 0) {
			bit = rnd() % 128;
			bad[bit / 8] ^= (uint8_t)(1u << (bit % 8));
		} else if (bad_field == 1 && n > 0) {
			bit = rnd() % (n * 8);
			ct_r[bit / 8] ^= (uint8_t)(1u << (bit % 8));
		} else if (bad_field == 2 && aadlen > 0) {
			bit = rnd() % (aadlen * 8);
			aad[bit / 8] ^= (uint8_t)(1u << (bit % 8));
		} else {
			bit = rnd() % (ivlen * 8);
			iv[bit / 8] ^= (uint8_t)(1u << (bit % 8));
		}
		WRT_CHECK_STATUS(-1, ref_gcm_open(key, keylen, iv, ivlen, aad, aadlen, ct_r, n, bad, back));
		WRT_CHECK_STATUS(-1, ossl_dec(key, keylen, iv, ivlen, aad, aadlen, ct_r, n, bad, back));
	}
}

static void test_secure_ops(void)
{
	static uint8_t pt[300], wire_r[316], wire_o[316], back[300];
	uint8_t key[16], nr[12], no[12], ro[12], tag[16];
	size_t i;

	rnd_fill(key, 16);
	rnd_fill(nr, 12);
	/* start 20 operations before the 64-bit counter wraps: bytes 4..11 = 2^64 - 20 */
	memset(nr + 4, 0xff, 8);
	nr[4] = (uint8_t)(0xff - 19);
	memcpy(no, nr, 12);
	memcpy(ro, nr, 12);
	for (i = 0; i < 40; i++) {
		size_t n = rnd() % 301;
		uint8_t iv_before[12];

		rnd_fill(pt, n);
		memcpy(iv_before, no, 12);
		ref_secure_seal(key, nr, pt, n, wire_r);
		/* OpenSSL with the same nonce, stepped here by hand: little-endian add of one to bytes 4..11 */
		WRT_CHECK_STATUS(0, ossl_enc(key, 16, no, 12, NULL, 0, pt, n, wire_o, tag));
		memcpy(wire_o + n, tag, 16);
		WRT_CHECK(memcmp(wire_r, wire_o, n + 16) == 0);
		{
			int k;

			for (k = 4; k < 12; k++)
				if (++no[k] != 0)
					break;
		}
		WRT_CHECK(memcmp(nr, no, 12) == 0);
		WRT_CHECK_STATUS(0, ref_secure_open(key, ro, wire_o, n, back));
		WRT_CHECK(memcmp(back, pt, n) == 0);
		WRT_CHECK(memcmp(ro, no, 12) == 0);
		WRT_CHECK(memcmp(iv_before, no, 4) == 0); /* the fixed field never changes */
	}
	/* the run crossed the wrap: the counter is now 20 (bytes 4.. = 14 00 ...) */
	WRT_CHECK(nr[4] == 20 && nr[5] == 0 && nr[11] == 0);
}

int main(void)
{
	test_random();
	test_secure_ops();
	return wrt_finish();
}

#endif /* OPENSSL_VERSION_NUMBER */
