/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_diff_ossl - differential test of the portable primitives against OpenSSL (libcrypto 3.x).
 * Built only when OpenSSL is found (the name ends in _ossl); OpenSSL is never a dependency of the core.
 *
 * 10,000 random cases each, through the dispatch layer with no override table (so the code under
 * test is what a host without overrides runs):
 *   - HMAC-SHA256 and HMAC-SHA384, keys of 0..200 bytes (shorter and longer than both block sizes),
 *     messages of 0..300 bytes cut into 1..5 gather elements;
 *   - AES-128-CBC and AES-256-CBC, 0..20 blocks, encrypt and decrypt, random IVs, in and out of place;
 *   - CBC-CS3 with AES-256 (OpenSSL's AES-256-CBC-CTS with cts_mode CS3), lengths 16..300, both
 *     directions, random IVs (the cephx use is IV 0; other IVs must agree too), and AES-128 CS3 as
 *     well when OpenSSL offers it;
 *   - the same CTS built on top of an OpenSSL-backed CBC override (2,000 cases), so the dispatch
 *     contract and the CTS construction are checked with no portable AES in the path;
 *   - raw CRC-32C against a bitwise reference written here, random seeds, lengths 0..600, random
 *     start offsets (alignment) in a larger buffer.
 * The random source is a fixed-seed xorshift, so a failure reproduces.
 */
#include "wrt.h"

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
/* The provider API (EVP_CipherInit_ex2, OSSL_PARAM, the CTS mode parameter) is OpenSSL 3. With an
 * older libcrypto this test says so and is reported as skipped instead of breaking the build. */
int main(void)
{
	WRT_SKIP("OpenSSL older than 3.0: differential test needs the 3.x provider API");
	return 0;
}
#else

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#include "wri_aes.h"
#include "wri_crc32c.h"
#include "wri_hash.h"
#include "wri_prim.h"

#define NCASES 10000

static uint64_t rng_state = 0xa4093822299f31d0ull;

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

/* ---- HMAC ------------------------------------------------------------------------------------ */

static void test_hmac(void)
{
	static uint8_t key[200], msg[300], want[64], got[64];
	size_t i;

	for (i = 0; i < NCASES; i++) {
		size_t klen = rnd() % 201, mlen = rnd() % 301, nio = 1 + rnd() % 5, off = 0, j;
		wr_iov iov[5];
		unsigned wl = 0;
		int is384 = (int)(i & 1);

		rnd_fill(key, klen);
		rnd_fill(msg, mlen);
		for (j = 0; j < nio; j++) {
			size_t len = (j + 1 == nio) ? mlen - off : (mlen - off != 0 ? rnd() % (mlen - off + 1) : 0);

			iov[j].base = msg + off;
			iov[j].len = len;
			off += len;
		}
		WRT_CHECK(off == mlen);
		WRT_CHECK(HMAC(is384 ? EVP_sha384() : EVP_sha256(), klen != 0 ? key : (const uint8_t *)"", (int)klen,
			       msg, mlen, want, &wl) != NULL);
		WRT_CHECK(wl == (is384 ? 48u : 32u));
		if (is384)
			wri_p_hmac_sha384(NULL, key, klen, iov, nio, got);
		else
			wri_p_hmac_sha256(NULL, key, klen, iov, nio, got);
		WRT_CHECK_MEM(got, want, wl);
	}
}

/* ---- AES-CBC and CTS ------------------------------------------------------------------------- */

/* OpenSSL one-shot CBC / CBC-CTS (cts = NULL for plain CBC, else the mode name). Returns 0 on success. */
static int ossl_cipher(const char *name, const char *cts, int enc, const uint8_t *key, const uint8_t *iv,
		       const uint8_t *in, size_t n, uint8_t *out)
{
	EVP_CIPHER *ci = EVP_CIPHER_fetch(NULL, name, NULL);
	EVP_CIPHER_CTX *c;
	OSSL_PARAM params[2];
	int len = 0, len2 = 0, rc = -1;
	char mode[8];

	if (ci == NULL)
		return -2;
	c = EVP_CIPHER_CTX_new();
	if (c == NULL) {
		EVP_CIPHER_free(ci);
		return -1;
	}
	if (cts != NULL) {
		snprintf(mode, sizeof(mode), "%s", cts);
		params[0] = OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, mode, 0);
		params[1] = OSSL_PARAM_construct_end();
	}
	if (EVP_CipherInit_ex2(c, ci, key, iv, enc, cts != NULL ? params : NULL) == 1) {
		EVP_CIPHER_CTX_set_padding(c, 0);
		if (EVP_CipherUpdate(c, out, &len, in, (int)n) == 1 && EVP_CipherFinal_ex(c, out + len, &len2) == 1 &&
		    (size_t)(len + len2) == n)
			rc = 0;
	}
	EVP_CIPHER_CTX_free(c);
	EVP_CIPHER_free(ci);
	return rc;
}

static void test_cbc(void)
{
	static uint8_t key[32], iv[16], pt[16 * 20], ct_ref[16 * 20], got[16 * 20], back[16 * 20];
	size_t i;

	for (i = 0; i < NCASES; i++) {
		size_t klen = (i & 1) ? 32 : 16, nb = rnd() % 21;
		const char *name = klen == 32 ? "AES-256-CBC" : "AES-128-CBC";

		rnd_fill(key, sizeof(key));
		rnd_fill(iv, sizeof(iv));
		rnd_fill(pt, sizeof(pt));
		if (nb == 0)
			continue; /* OpenSSL one-shot of an empty buffer is not meaningful; the core's no-op is tested elsewhere */
		WRT_CHECK(ossl_cipher(name, NULL, 1, key, iv, pt, nb * 16, ct_ref) == 0);
		WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(NULL, key, klen, iv, pt, got, nb));
		WRT_CHECK_MEM(got, ct_ref, nb * 16);
		memcpy(back, pt, nb * 16);
		WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(NULL, key, klen, iv, back, back, nb)); /* in place */
		WRT_CHECK_MEM(back, ct_ref, nb * 16);
		WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_dec(NULL, key, klen, iv, ct_ref, got, nb));
		WRT_CHECK_MEM(got, pt, nb * 16);
		WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_dec(NULL, key, klen, iv, back, back, nb));
		WRT_CHECK_MEM(back, pt, nb * 16);
	}
}

static void test_cts(void)
{
	static uint8_t key[32], iv[16], pt[300], ct_ref[300], got[300], back[300];
	size_t i;

	EVP_CIPHER *probe = EVP_CIPHER_fetch(NULL, "AES-256-CBC-CTS", NULL);

	/* OpenSSL 3 ships CBC-CTS in its default provider; without it the CTS differential would be
	 * silently empty, so its absence is a failure, not a skip. */
	WRT_CHECK(probe != NULL);
	if (probe == NULL)
		return;
	EVP_CIPHER_free(probe);
	for (i = 0; i < NCASES; i++) {
		size_t klen = (i % 4 == 3) ? 16 : 32, n = 16 + rnd() % 285;
		const char *name = klen == 32 ? "AES-256-CBC-CTS" : "AES-128-CBC-CTS";

		rnd_fill(key, sizeof(key));
		rnd_fill(iv, sizeof(iv));
		if (i % 3 == 0)
			memset(iv, 0, sizeof(iv)); /* the cephx case */
		rnd_fill(pt, sizeof(pt));
		WRT_CHECK(ossl_cipher(name, "CS3", 1, key, iv, pt, n, ct_ref) == 0);
		WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(NULL, key, klen, iv, pt, n, got));
		WRT_CHECK_MEM(got, ct_ref, n);
		memcpy(back, pt, n);
		WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(NULL, key, klen, iv, back, n, back));
		WRT_CHECK_MEM(back, ct_ref, n);
		WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(NULL, key, klen, iv, ct_ref, n, got));
		WRT_CHECK_MEM(got, pt, n);
		WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(NULL, key, klen, iv, back, n, back));
		WRT_CHECK_MEM(back, pt, n);
		/* decrypt direction against OpenSSL on random ciphertext too (any bytes are a valid CS3 input) */
		rnd_fill(ct_ref, n);
		WRT_CHECK(ossl_cipher(name, "CS3", 0, key, iv, ct_ref, n, back) == 0);
		WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(NULL, key, klen, iv, ct_ref, n, got));
		WRT_CHECK_MEM(got, back, n);
	}
}

/* CTS built by the core on top of a CBC that is OpenSSL's: the dispatch contract (stateless one-shot
 * calls, in place allowed) and the CTS construction are checked against OpenSSL's own CTS, with no
 * portable AES involved in the path. */
static wr_status ossl_cbc_member(void *ctx, int enc, const uint8_t *key, size_t klen, const uint8_t iv[16],
				 const uint8_t *in, uint8_t *out, size_t nb)
{
	(void)ctx;
	if (nb == 0)
		return WR_OK;
	return ossl_cipher(klen == 32 ? "AES-256-CBC" : "AES-128-CBC", NULL, enc, key, iv, in, nb * 16, out) == 0
		       ? WR_OK
		       : WR_E_CRYPTO_KEY;
}

static wr_status ossl_enc_member(void *ctx, const uint8_t *key, size_t klen, const uint8_t iv[16], const uint8_t *in,
				 uint8_t *out, size_t nb)
{
	return ossl_cbc_member(ctx, 1, key, klen, iv, in, out, nb);
}

static wr_status ossl_dec_member(void *ctx, const uint8_t *key, size_t klen, const uint8_t iv[16], const uint8_t *in,
				 uint8_t *out, size_t nb)
{
	return ossl_cbc_member(ctx, 0, key, klen, iv, in, out, nb);
}

static void test_cts_on_ossl_cbc(void)
{
	static uint8_t key[32], iv[16], pt[300], ct_ref[300], got[300], back[300];
	wr_prim_ops ops;
	size_t i;

	memset(&ops, 0, sizeof(ops));
	ops.size = sizeof(ops);
	ops.aes_cbc_enc = ossl_enc_member;
	ops.aes_cbc_dec = ossl_dec_member;
	for (i = 0; i < 2000; i++) {
		size_t klen = (i & 1) ? 16 : 32, n = 16 + rnd() % 285;
		const char *name = klen == 32 ? "AES-256-CBC-CTS" : "AES-128-CBC-CTS";

		rnd_fill(key, sizeof(key));
		rnd_fill(iv, sizeof(iv));
		if (i % 2 == 0)
			memset(iv, 0, sizeof(iv));
		rnd_fill(pt, sizeof(pt));
		WRT_CHECK(ossl_cipher(name, "CS3", 1, key, iv, pt, n, ct_ref) == 0);
		WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(&ops, key, klen, iv, pt, n, got));
		WRT_CHECK_MEM(got, ct_ref, n);
		memcpy(back, pt, n);
		WRT_CHECK_STATUS(WR_OK, wri_cts3_enc(&ops, key, klen, iv, back, n, back));
		WRT_CHECK_MEM(back, ct_ref, n);
		WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(&ops, key, klen, iv, ct_ref, n, got));
		WRT_CHECK_MEM(got, pt, n);
		WRT_CHECK_STATUS(WR_OK, wri_cts3_dec(&ops, key, klen, iv, back, n, back));
		WRT_CHECK_MEM(back, pt, n);
	}
}

/* ---- CRC-32C --------------------------------------------------------------------------------- */

static uint32_t crc_bitwise(uint32_t crc, const uint8_t *p, size_t n)
{
	size_t i;
	int b;

	for (i = 0; i < n; i++) {
		crc ^= p[i];
		for (b = 0; b < 8; b++)
			crc = (crc >> 1) ^ (0x82F63B78u & (uint32_t)(0u - (crc & 1u)));
	}
	return crc;
}

static void test_crc(void)
{
	static uint8_t buf[600 + 16];
	size_t i;

	rnd_fill(buf, sizeof(buf));
	for (i = 0; i < NCASES; i++) {
		size_t off = rnd() % 16, n = rnd() % 601;
		uint32_t seed = (i % 5 == 0) ? 0 : (i % 5 == 1) ? 0xFFFFFFFFu : rnd();

		WRT_CHECK_U64(wri_p_crc32c(NULL, seed, buf + off, n), crc_bitwise(seed, buf + off, n));
	}
	/* fresh data too, not only one buffer */
	for (i = 0; i < 200; i++) {
		size_t n = rnd() % 601;

		rnd_fill(buf, n);
		WRT_CHECK_U64(wri_p_crc32c(NULL, 0xFFFFFFFFu, buf, n), crc_bitwise(0xFFFFFFFFu, buf, n));
	}
}

int main(void)
{
	test_hmac();
	test_cbc();
	test_crc();
	test_cts();
	test_cts_on_ossl_cbc();
	return wrt_finish();
}

#endif /* OPENSSL_VERSION_NUMBER >= 3.0 */
