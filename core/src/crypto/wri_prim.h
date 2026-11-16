/* SPDX-License-Identifier: MIT */
/*
 * wri_prim.h - dispatch between the host's primitive overrides (wr_prim_ops) and the portable
 * reference code. Every protocol-level call site uses these, never the wri_* reference
 * functions directly, so an override takes effect everywhere. prim may be NULL.
 */
#ifndef WRI_PRIM_H
#define WRI_PRIM_H

#include "wr_err.h"
#include "wr_host.h"
#include "wr_port.h"

uint32_t wri_p_crc32c(const wr_prim_ops *prim, uint32_t seed, const uint8_t *p, size_t n);

void wri_p_hmac_sha256(const wr_prim_ops *prim, const uint8_t *key, size_t klen, const wr_iov *iov,
		       size_t niov, uint8_t out[32]);
void wri_p_hmac_sha384(const wr_prim_ops *prim, const uint8_t *key, size_t klen, const wr_iov *iov,
		       size_t niov, uint8_t out[48]);

/* AES-CBC, no padding. klen 16 or 32. in == out allowed. */
WR_MUST_CHECK wr_status wri_p_aes_cbc_enc(const wr_prim_ops *prim, const uint8_t *key, size_t klen,
					  const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t nblocks);
WR_MUST_CHECK wr_status wri_p_aes_cbc_dec(const wr_prim_ops *prim, const uint8_t *key, size_t klen,
					  const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t nblocks);

#endif /* WRI_PRIM_H */
