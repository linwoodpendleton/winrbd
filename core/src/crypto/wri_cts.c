/* SPDX-License-Identifier: MIT */
/*
 * wri_cts.c - AES-CBC with ciphertext stealing, variant CS3 (the cephx type-2 cipher, cephx.md 2.5),
 * built on the CBC dispatchers only (wri_p_aes_cbc_enc / wri_p_aes_cbc_dec). A host that overrides
 * CBC therefore gets CTS without any extra primitive.
 *
 * Definition used here. Let n >= 16 be the message length, k = ceil(n / 16) the block count and
 * r = n - 16 * (k - 1) in 1..16 the length of the last (possibly short) block.
 *   n == 16:  the output is the single CBC block.
 *   n  > 16:  zero-pad the message to k blocks, run plain CBC with the given IV to get C1..Ck,
 *             then emit C1..C(k-2), Ck, and the first r bytes of C(k-1). The last two blocks are
 *             swapped even when r == 16. The output is exactly n bytes.
 * The encryptor never builds the padded message: blocks 1..k-1 are encrypted in place by one CBC
 * call, the zero-padded tail is encrypted as one extra block chained to C(k-1), and the two
 * results are written to their swapped positions.
 *
 * Decryption inverts it. With Cs the full block and X the r short bytes that follow it: one-block
 * CBC decryption of Cs with a zero IV gives D = (tail padded with zeros) xor C(k-1). Zero padding
 * means D[r..16) already equals C(k-1)[r..16), so C(k-1) = X || D[r..16) is rebuilt, the tail is
 * D[0..r) xor X, and blocks 1..k-1 are then an ordinary CBC decryption.
 *
 * Calling convention: n is a byte length; n < 16 gives WR_E_CRYPTO_LEN, a key length other than 16
 * or 32 gives WR_E_CRYPTO_KEY, NULL arguments WR_E_INVAL (in all these cases nothing is touched and
 * no override is entered). in == out is allowed (exact overlap); two ranges of n bytes that overlap
 * in any other way are refused with WR_E_INVAL before anything is read or written, so the in-place
 * steps below never see a half-overlapped buffer (this also stops an absurd n from being walked
 * past the end of a buffer when the buffers are distinct). On an error from the CBC layer an
 * encrypt may leave partial ciphertext in out; a decrypt wipes out (all n bytes) so that no partial
 * plaintext escapes. Memory: at most 64 bytes of stack scratch plus whatever the CBC layer uses
 * (the reference path adds one key schedule); everything is wiped before returning. No recursion,
 * no loops over the data (the CBC layer does the work), no allocation.
 */
#include "wri_aes.h"
#include "wri_misc.h"
#include "wri_prim.h"

WR_FILE_LICENCE_MIT

#define WRI_CTS_BS 16u

/* True when [a, a + n) and [b, b + n) share a byte but are not the same range (distance form, so
 * no sum can wrap). */
static int wri_cts_partial_overlap(const void *a, const void *b, size_t n)
{
	uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
	uintptr_t d = x > y ? x - y : y - x;

	return x != y && (uint64_t)d < (uint64_t)n;
}

wr_status wri_cts3_enc(const wr_prim_ops *prim, const uint8_t *key, size_t klen, const uint8_t iv[16],
		       const uint8_t *in, size_t n, uint8_t *out)
{
	uint8_t tail[WRI_CTS_BS]; /* zero-padded last block, then its ciphertext */
	uint8_t prev[WRI_CTS_BS]; /* C(k-1) */
	size_t k, r, head;
	wr_status st;

	if (n < WRI_CTS_BS)
		return WR_E_CRYPTO_LEN;
	if (key == NULL || (klen != 16u && klen != 32u))
		return WR_E_CRYPTO_KEY;
	if (iv == NULL || in == NULL || out == NULL)
		return WR_E_INVAL;
	if (wri_cts_partial_overlap(in, out, n))
		return WR_E_INVAL;
	if (n == WRI_CTS_BS)
		return wri_p_aes_cbc_enc(prim, key, klen, iv, in, out, 1);

	k = (n >> 4) + ((n & 15u) != 0 ? 1u : 0u);
	head = (k - 1) * WRI_CTS_BS; /* byte offset of the last (short or full) block, < n */
	r = n - head;

	WR_MEMSET(tail, 0, sizeof(tail));
	WR_MEMSET(prev, 0, sizeof(prev));
	WR_MEMCPY(tail, in + head, r); /* read before out may overwrite it (in == out) */

	st = wri_p_aes_cbc_enc(prim, key, klen, iv, in, out, k - 1);
	if (st == WR_OK) {
		WR_MEMCPY(prev, out + head - WRI_CTS_BS, WRI_CTS_BS);
		st = wri_p_aes_cbc_enc(prim, key, klen, prev, tail, tail, 1);
	}
	if (st == WR_OK) {
		WR_MEMCPY(out + head, prev, r);
		WR_MEMCPY(out + head - WRI_CTS_BS, tail, WRI_CTS_BS);
	}
	wri_secure_zero(tail, sizeof(tail));
	wri_secure_zero(prev, sizeof(prev));
	return st;
}

wr_status wri_cts3_dec(const wr_prim_ops *prim, const uint8_t *key, size_t klen, const uint8_t iv[16],
		       const uint8_t *in, size_t n, uint8_t *out)
{
	uint8_t d[WRI_CTS_BS];     /* one-block decryption of the stolen block */
	uint8_t prev[WRI_CTS_BS];  /* rebuilt C(k-1) */
	uint8_t chain[WRI_CTS_BS]; /* C(k-2), or the IV, the chaining value before block k-1 */
	uint8_t zero[WRI_CTS_BS];
	size_t k, r, head, j;
	wr_status st;

	if (n < WRI_CTS_BS)
		return WR_E_CRYPTO_LEN;
	if (key == NULL || (klen != 16u && klen != 32u))
		return WR_E_CRYPTO_KEY;
	if (iv == NULL || in == NULL || out == NULL)
		return WR_E_INVAL;
	if (wri_cts_partial_overlap(in, out, n))
		return WR_E_INVAL;
	if (n == WRI_CTS_BS) {
		st = wri_p_aes_cbc_dec(prim, key, klen, iv, in, out, 1);
		if (st != WR_OK)
			wri_secure_zero(out, WRI_CTS_BS);
		return st;
	}

	k = (n >> 4) + ((n & 15u) != 0 ? 1u : 0u);
	head = (k - 1) * WRI_CTS_BS; /* offset of the short bytes X; the full block Cs sits just before */
	r = n - head;

	WR_MEMSET(zero, 0, sizeof(zero));
	WR_MEMSET(prev, 0, sizeof(prev)); /* defined before any early exit wipes them */
	WR_MEMSET(chain, 0, sizeof(chain));
	WR_MEMCPY(d, in + head - WRI_CTS_BS, WRI_CTS_BS);
	st = wri_p_aes_cbc_dec(prim, key, klen, zero, d, d, 1);
	if (st != WR_OK)
		goto done;

	/* Rebuild C(k-1) and the tail plaintext; X is read here, before out can overwrite it. */
	WR_MEMCPY(prev, in + head, r);
	WR_MEMCPY(prev + r, d + r, WRI_CTS_BS - r);
	for (j = 0; j < r; j++)
		out[head + j] = (uint8_t)(d[j] ^ in[head + j]);

	/* Chaining value before block k-1, saved before the CBC call below may overwrite it. */
	if (k >= 3)
		WR_MEMCPY(chain, in + head - 2 * WRI_CTS_BS, WRI_CTS_BS);
	else
		WR_MEMCPY(chain, iv, WRI_CTS_BS);
	if (k >= 3) {
		st = wri_p_aes_cbc_dec(prim, key, klen, iv, in, out, k - 2);
		if (st != WR_OK)
			goto done;
	}
	st = wri_p_aes_cbc_dec(prim, key, klen, chain, prev, out + head - WRI_CTS_BS, 1);
done:
	if (st != WR_OK)
		wri_secure_zero(out, n); /* no half-decrypted plaintext on failure (in == out: the ciphertext goes too) */
	wri_secure_zero(d, sizeof(d));
	wri_secure_zero(prev, sizeof(prev));
	wri_secure_zero(chain, sizeof(chain));
	return st;
}
