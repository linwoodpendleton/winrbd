/* SPDX-License-Identifier: MIT */
/*
 * wri_aes_cbc.c - CBC mode over whole 16-byte blocks, no padding (NIST SP 800-38A section 6.2),
 * on top of the block functions in wri_aes.c.
 *
 * Calling convention: nblocks is a block count, not a byte count. The caller owns the buffer
 * length checks (every wire length was capped before it got here); with nblocks == 0 nothing is
 * read or written. Offsets are advanced by pointer step, never as index * 16, so no length product
 * can wrap. A context without a good key schedule makes every block come out as zeros (fail closed,
 * wri_aes.c). The iv is read once and never modified; the chaining value is kept in a local
 * 16-byte buffer (not wiped on return: the plaintext it holds belongs to the caller, and the
 * caller wipes the key context with wri_secure_zero). in == out is allowed (exact overlap); any
 * other partial overlap of in and out is not supported. Same limitation as wri_aes.c: table
 * based, not constant time.
 */
#include "wri_aes.h"

WR_FILE_LICENCE_MIT

#define WRI_AES_BS 16u

void wri_aes_cbc_enc(const wri_aes_ctx *c, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t nblocks)
{
	uint8_t chain[WRI_AES_BS];
	uint8_t blk[WRI_AES_BS];
	unsigned j;

	if (nblocks == 0)
		return;
	WR_MEMCPY(chain, iv, WRI_AES_BS);
	for (; nblocks != 0; nblocks--) {
		for (j = 0; j < WRI_AES_BS; j++)
			blk[j] = (uint8_t)(in[j] ^ chain[j]);
		wri_aes_enc_block(c, blk, chain); /* the ciphertext is the next chaining value */
		WR_MEMCPY(out, chain, WRI_AES_BS);
		in += WRI_AES_BS;
		out += WRI_AES_BS;
	}
}

void wri_aes_cbc_dec(const wri_aes_ctx *c, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t nblocks)
{
	uint8_t chain[WRI_AES_BS]; /* previous ciphertext block (or the iv) */
	uint8_t cur[WRI_AES_BS];   /* this ciphertext block, saved before out may overwrite it */
	uint8_t blk[WRI_AES_BS];
	unsigned j;

	if (nblocks == 0)
		return;
	WR_MEMCPY(chain, iv, WRI_AES_BS);
	for (; nblocks != 0; nblocks--) {
		WR_MEMCPY(cur, in, WRI_AES_BS);
		wri_aes_dec_block(c, cur, blk);
		for (j = 0; j < WRI_AES_BS; j++)
			out[j] = (uint8_t)(blk[j] ^ chain[j]);
		WR_MEMCPY(chain, cur, WRI_AES_BS);
		in += WRI_AES_BS;
		out += WRI_AES_BS;
	}
}
