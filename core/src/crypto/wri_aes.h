/* SPDX-License-Identifier: MIT */
/*
 * wri_aes.h - AES-128/256 block cipher, CBC mode, and CBC with ciphertext stealing, variant
 * CS3 (the cephx type-2 cipher, cephx.md 2.5). Portable reference code; table based, NOT
 * constant time against cache attacks (documented limitation, architecture doc 2.6).
 *
 * CTS is built on CBC only so a host that overrides aes_cbc_enc/dec (wr_host.h) gets CTS for
 * free; it therefore takes a raw key and the prim table, not a key schedule.
 */
#ifndef WRI_AES_H
#define WRI_AES_H

#include "wr_err.h"
#include "wr_host.h"
#include "wr_port.h"

typedef struct wri_aes_ctx {
	uint32_t rk[60]; /* round keys: 4 * (rounds + 1) words, up to AES-256 */
	uint32_t rounds; /* 10 or 14 (12 for 24-byte keys) */
} wri_aes_ctx;

/* klen 16, 24 or 32; WR_E_CRYPTO_KEY otherwise. */
WR_MUST_CHECK wr_status wri_aes_setkey(wri_aes_ctx *c, const uint8_t *key, size_t klen);
void wri_aes_enc_block(const wri_aes_ctx *c, const uint8_t in[16], uint8_t out[16]);
void wri_aes_dec_block(const wri_aes_ctx *c, const uint8_t in[16], uint8_t out[16]);

/* CBC without padding over nblocks blocks. in == out allowed. iv is not modified. */
void wri_aes_cbc_enc(const wri_aes_ctx *c, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t nblocks);
void wri_aes_cbc_dec(const wri_aes_ctx *c, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t nblocks);

/*
 * CBC-CS3 over n >= 16 bytes (no padding; output length == n). n == 16 is a single block. For
 * n > 16 the last two ciphertext blocks are always swapped, even when n is a multiple of 16
 * (cephx.md 2.5). in == out allowed. WR_E_CRYPTO_LEN if n < 16. prim may be NULL.
 */
WR_MUST_CHECK wr_status wri_cts3_enc(const wr_prim_ops *prim, const uint8_t *key, size_t klen,
				     const uint8_t iv[16], const uint8_t *in, size_t n, uint8_t *out);
WR_MUST_CHECK wr_status wri_cts3_dec(const wr_prim_ops *prim, const uint8_t *key, size_t klen,
				     const uint8_t iv[16], const uint8_t *in, size_t n, uint8_t *out);

#endif /* WRI_AES_H */
