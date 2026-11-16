/* SPDX-License-Identifier: MIT */
/*
 * wri_hash.h - SHA-256, SHA-384 (SHA-512 core) and HMAC over gather lists. Portable reference
 * implementations; call sites that may be overridden by the host go through wri_prim.h.
 */
#ifndef WRI_HASH_H
#define WRI_HASH_H

#include "wr_port.h"
#include "wr_types.h"

#define WRI_SHA256_LEN 32u
#define WRI_SHA384_LEN 48u

typedef struct wri_sha256_ctx {
	uint32_t h[8];
	uint64_t total; /* bytes hashed */
	uint8_t buf[64];
	uint32_t fill;
} wri_sha256_ctx;

typedef struct wri_sha512_ctx { /* also used for SHA-384 */
	uint64_t h[8];
	uint64_t total_lo, total_hi; /* bytes hashed, 128-bit */
	uint8_t buf[128];
	uint32_t fill;
} wri_sha512_ctx;

void wri_sha256_init(wri_sha256_ctx *c);
void wri_sha256_update(wri_sha256_ctx *c, const uint8_t *p, size_t n);
void wri_sha256_final(wri_sha256_ctx *c, uint8_t out[32]); /* wipes the context */

void wri_sha384_init(wri_sha512_ctx *c);
void wri_sha384_update(wri_sha512_ctx *c, const uint8_t *p, size_t n);
void wri_sha384_final(wri_sha512_ctx *c, uint8_t out[48]); /* wipes the context */

/* HMAC (RFC 2104) over the concatenation of niov gather elements. Keys longer than the block
 * size are hashed first, as the RFC says. No failure paths: all inputs are valid. */
void wri_hmac_sha256(const uint8_t *key, size_t klen, const wr_iov *iov, size_t niov, uint8_t out[32]);
void wri_hmac_sha384(const uint8_t *key, size_t klen, const wr_iov *iov, size_t niov, uint8_t out[48]);

#endif /* WRI_HASH_H */
