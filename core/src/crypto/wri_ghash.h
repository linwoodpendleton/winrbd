/* SPDX-License-Identifier: MIT */
/*
 * wri_ghash.h - GHASH, the GCM authenticator: multiplication in GF(2^128) with the polynomial x^128 + x^7 + x^2 + x + 1 in
 * GCM's reflected bit order (NIST SP 800-38D 6.3), constant time. Docs: docs/design/core-architecture.md 35.2.
 *
 * Constant time: no table indexed by H, by the running value or by data (the usual 4-bit and 8-bit tables ARE secret-indexed and
 * are therefore not used); the multiplication is done with word operations whose count does not depend on any value (the integer
 * multiplication of bit-masked words, or an equivalent that holds the same rule as wri_aesct.h). A slow bitwise multiplication is
 * the reference the module's tests compare against, it is not the product.
 */
#ifndef WRI_GHASH_H
#define WRI_GHASH_H

#include "wr_port.h"

#define WRI_GHASH_BLOCK 16u

typedef struct wri_ghash {
	uint32_t h[4];   /* the hash key H = E(K, 0^128), in the owner's representation (wri_ghash.c: bit reversed words, polynomial order) */
	uint32_t y[4];   /* the running value (big-endian words of the 16 bytes) */
	uint32_t aux[8]; /* owner's scratch (H in big-endian words and two sums for the Karatsuba steps); written by init, read only after it */
} wri_ghash;

/* Set H (16 bytes as AES produced them) and clear the running value. H is secret: wipe the object when done. */
void wri_ghash_init(wri_ghash *g, const uint8_t h[16]);
/* y = 0, H kept. */
void wri_ghash_reset(wri_ghash *g);
/* For each of nblocks 16-byte blocks: y = (y XOR block) * H. p needs no alignment; nblocks is public; partial blocks are the caller's
 * to pad (GCM zero-pads and then feeds the length block). Temporaries derived from H are wiped before the call returns. Misuse fails
 * closed: nblocks > 0 with p == NULL wipes the object (so the value cannot silently cover less data than the caller meant); a NULL
 * object or nblocks == 0 does nothing. An object that was never initialised or was wiped has H = 0: its value is always zero. */
void wri_ghash_blocks(wri_ghash *g, const uint8_t *p, size_t nblocks);
/* The running value as 16 bytes (not wiped). */
void wri_ghash_get(const wri_ghash *g, uint8_t out[16]);
/* Erase H and y. */
void wri_ghash_wipe(wri_ghash *g);

#endif /* WRI_GHASH_H */
