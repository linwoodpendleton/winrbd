/* SPDX-License-Identifier: MIT */
/*
 * wri_crush_hash.h - the hashes of object placement: the string hash that turns an object name into
 * a placement seed, the CRUSH 32-bit mixing hashes, and the stable modulo. Pure functions, no state.
 * Written from docs/spec/crush-and-placement.md 3.1 and 3.2; vectors in harness/vectors/crush/hash-vectors.json.
 */
#ifndef WRI_CRUSH_HASH_H
#define WRI_CRUSH_HASH_H

#include "wr_port.h"

/* Pool object_hash values (crush-and-placement.md 3.1). Any other value is an unsupported pool. */
#define WRI_STR_HASH_LINUX 1u
#define WRI_STR_HASH_RJENKINS 2u

/* ceph_str_hash_rjenkins over n bytes (3.1.1). The length is u32 like the original; callers cap names far below that.
 * s == NULL is allowed only with n == 0 (the empty name); NULL with n != 0 returns 0 and reads nothing. */
uint32_t wri_str_hash_rjenkins(const uint8_t *s, uint32_t n);
/* Linux dcache string hash (3.1.2), for legacy pools with object_hash 1. */
uint32_t wri_str_hash_linux(const uint8_t *s, uint32_t n);
/* By pool object_hash id; WRI_STR_HASH_* only, any other id returns 0 and sets *ok to 0 (ok may be NULL). */
uint32_t wri_str_hash(uint32_t hash_id, const uint8_t *s, uint32_t n, int *ok);

/* CRUSH rjenkins1 hashes of 1 to 4 words (3.2.1); arguments are the u32 bit patterns (negative ids included). */
uint32_t wri_crush_hash1(uint32_t a);
uint32_t wri_crush_hash2(uint32_t a, uint32_t b);
uint32_t wri_crush_hash3(uint32_t a, uint32_t b, uint32_t c);
uint32_t wri_crush_hash4(uint32_t a, uint32_t b, uint32_t c, uint32_t d);

/* cbits(v): number of bits needed to represent v (0 for 0). */
uint32_t wri_cbits(uint32_t v);
/* (1 << cbits(n - 1)) - 1; n must be non-zero (callers reject pg_num 0), 0 is returned for n == 0 so nothing shifts by 32. */
uint32_t wri_pg_mask(uint32_t n);
/* x & bmask if that is below b, else x & (bmask >> 1) (crush-and-placement.md 3.2). */
uint32_t wri_stable_mod(uint32_t x, uint32_t b, uint32_t bmask);

#endif /* WRI_CRUSH_HASH_H */
