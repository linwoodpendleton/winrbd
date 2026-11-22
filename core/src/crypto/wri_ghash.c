/* SPDX-License-Identifier: MIT */
/*
 * wri_ghash.c - constant-time GHASH (see wri_ghash.h and docs/design/core-architecture.md 35.2).
 *
 * Written from NIST SP 800-38D 6.3 (the field, the reflected bit order) and from the general technique of multiplying
 * integers whose bits are spread out so that the carries of the integer sum cannot reach the bits that are kept; no code or
 * table was taken from any library.
 *
 * Representation. A block is 16 bytes; bit i of the block (bit 0 = the most significant bit of byte 0) is the coefficient of x^i
 * of a polynomial over GF(2), reduced modulo x^128 + x^7 + x^2 + x + 1. Read as four big-endian words w[0..3] ("BE form"), the
 * coefficient of x^(32 j + k) is bit 31 - k of w[j]; reversing the bits of every word (rev32) gives the "natural form" in which
 * word j bit k is that coefficient, and there an ordinary carry-less multiplication followed by a reduction by fixed shifts is
 * the field product. The running value y is kept in BE form (so reset, get and the xor with a block are plain word operations),
 * H is kept in natural form in h[] with its BE form in aux[0..3] and two helper sums in aux[4..7] (see wri_ghash_init).
 *
 * Carry-less 32 x 32 multiplication with the integer multiplier (bmul32): every operand is split into four masks, the bits at
 * positions 0, 1, 2, 3 modulo 4. The product of two such masked words has bits only at positions that are a fixed residue modulo
 * 4, and the integer sum at one kept position is a count of at most 8 terms (eight positions of each mask), which fits the four
 * bit wide field below the next kept position, so no carry reaches a kept bit and the lowest bit of each count is the parity, i.e.
 * the carry-less coefficient. The 16 multiplications and the masks are the same for every input. That gives the low 32 bits of the
 * 63-bit product; the high 32 bits come from the same function applied to the bit reversed operands (the reversed product is the
 * reversed 63-bit product shifted by one), so one 32 x 32 -> 64 carry-less product is two bmul32 and one bit reversal of the result;
 * the reversals of the operands are kept alongside them (reversal is linear, so the Karatsuba sums of reversed words are xors).
 * A 128 x 128 product is nine such products (two levels of Karatsuba), then the 255-bit result is folded back by shifts of 1, 2
 * and 7 bits (x^128 = x^7 + x^2 + x + 1), twice because the first fold overflows by seven bits.
 *
 * Constant time: no table, no data dependent branch or loop count or address, no shift by a secret amount; the only
 * operations on secret words are and, or, xor, constant shifts and 32-bit multiplication. The multiplication instruction is
 * constant time on the x86, ARM64 and Windows-class cores this runs on; a host on a core with a data dependent multiplier uses
 * the accelerated GCM hook (wr_prim_ops.gcm_*) instead.
 */
#include "wri_ghash.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/* Reverse the bit order of a 32-bit word. */
WR_INLINE uint32_t gh_rev32(uint32_t x)
{
	x = ((x & 0x55555555u) << 1) | ((x >> 1) & 0x55555555u);
	x = ((x & 0x33333333u) << 2) | ((x >> 2) & 0x33333333u);
	x = ((x & 0x0F0F0F0Fu) << 4) | ((x >> 4) & 0x0F0F0F0Fu);
	x = (x << 24) | ((x & 0x0000FF00u) << 8) | ((x >> 8) & 0x0000FF00u) | (x >> 24);
	return x;
}

WR_INLINE uint32_t gh_load_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

WR_INLINE void gh_store_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/* The low 32 bits of the carry-less product of a and b (see the file header). */
static uint32_t gh_bmul32(uint32_t a, uint32_t b)
{
	const uint32_t m0 = 0x11111111u, m1 = 0x22222222u, m2 = 0x44444444u, m3 = 0x88888888u;
	uint32_t a0 = a & m0, a1 = a & m1, a2 = a & m2, a3 = a & m3;
	uint32_t b0 = b & m0, b1 = b & m1, b2 = b & m2, b3 = b & m3;
	uint32_t c0 = (a0 * b0) ^ (a1 * b3) ^ (a2 * b2) ^ (a3 * b1);
	uint32_t c1 = (a0 * b1) ^ (a1 * b0) ^ (a2 * b3) ^ (a3 * b2);
	uint32_t c2 = (a0 * b2) ^ (a1 * b1) ^ (a2 * b0) ^ (a3 * b3);
	uint32_t c3 = (a0 * b3) ^ (a1 * b2) ^ (a2 * b1) ^ (a3 * b0);

	return (c0 & m0) | (c1 & m1) | (c2 & m2) | (c3 & m3);
}

/* The high 32 bits of the carry-less product of a and b, from the bit reversals ra and rb of the operands (the caller has them, or
 * forms them by xor since reversal is linear); the low 32 bits are gh_bmul32 (a, b). */
WR_INLINE uint32_t gh_clmul32_hi(uint32_t ra, uint32_t rb)
{
	return gh_rev32(gh_bmul32(ra, rb)) >> 1;
}

/* 64 x 64 -> 128 carry-less product (one Karatsuba step over three 32 x 32 products); every operand is two words. */
static void gh_clmul64(const uint32_t *a, const uint32_t *ra, const uint32_t *b, const uint32_t *rb, uint32_t *out)
{
	uint32_t lm, hm;

	out[0] = gh_bmul32(a[0], b[0]);
	out[1] = gh_clmul32_hi(ra[0], rb[0]);
	out[2] = gh_bmul32(a[1], b[1]);
	out[3] = gh_clmul32_hi(ra[1], rb[1]);
	lm = gh_bmul32(a[0] ^ a[1], b[0] ^ b[1]) ^ out[0] ^ out[2];
	hm = gh_clmul32_hi(ra[0] ^ ra[1], rb[0] ^ rb[1]) ^ out[1] ^ out[3];
	out[1] ^= lm;
	out[2] ^= hm;
}

/* The scratch of one block: everything derived from H or from the data that a caller of wri_ghash_blocks must not leave behind. */
typedef struct gh_tmp {
	uint32_t x[4];    /* y xor block, natural form (folded in place for the middle product) */
	uint32_t rx[4];   /* the same, BE form */
	uint32_t prod[8]; /* the 255-bit product, natural form */
	uint32_t mid[4];  /* the middle Karatsuba product */
} gh_tmp;

/* The Karatsuba combination: mid = mid ^ low ^ high, then prod[2..5] ^= mid. (A separate function keeps each frame small in the
 * unoptimised sanitizer builds, where every temporary of a long function gets its own stack slot.) */
static void gh_mid_combine(gh_tmp *t)
{
	size_t i;

	for (i = 0; i < 4u; i++)
		t->mid[i] ^= t->prod[i] ^ t->prod[4u + i];
	for (i = 0; i < 4u; i++)
		t->prod[2u + i] ^= t->mid[i];
}

/* x0 ^= x2, x1 ^= x3 in both forms: the operand of the middle product. */
static void gh_fold_halves(gh_tmp *t)
{
	t->x[0] ^= t->x[2];
	t->x[1] ^= t->x[3];
	t->rx[0] ^= t->rx[2];
	t->rx[1] ^= t->rx[3];
}

/* t->prod = t->x * H as plain polynomials (no reduction). */
static void gh_clmul128(gh_tmp *t, const wri_ghash *g)
{
	gh_clmul64(&t->x[0], &t->rx[0], &g->h[0], &g->aux[0], &t->prod[0]);
	gh_clmul64(&t->x[2], &t->rx[2], &g->h[2], &g->aux[2], &t->prod[4]);
	/* middle: (x0 ^ x2, x1 ^ x3) times (h0 ^ h2, h1 ^ h3); the H side sums sit in aux[4..7] */
	gh_fold_halves(t);
	gh_clmul64(&t->x[0], &t->rx[0], &g->aux[4], &g->aux[6], &t->mid[0]);
	gh_mid_combine(t);
}

/* r = c mod (x^128 + x^7 + x^2 + x + 1) for the 8-word natural-form product c; r may not alias c. */
static void gh_reduce(const uint32_t *c, uint32_t *r)
{
	uint32_t ov = (c[7] >> 31) ^ (c[7] >> 30) ^ (c[7] >> 25); /* the seven bits the first fold pushes above x^127 */
	size_t i;

	for (i = 0; i < 4u; i++) {
		uint32_t h = c[4u + i];
		uint32_t carry = (i == 0u) ? 0u : (c[3u + i] >> 31) ^ (c[3u + i] >> 30) ^ (c[3u + i] >> 25);

		r[i] = c[i] ^ h ^ (h << 1) ^ (h << 2) ^ (h << 7) ^ carry;
	}
	r[0] ^= ov ^ (ov << 1) ^ (ov << 2) ^ (ov << 7);
}

void wri_ghash_init(wri_ghash *g, const uint8_t h[16])
{
	size_t i;

	if (g == NULL)
		return;
	for (i = 0; i < 4u; i++) {
		uint32_t be = (h != NULL) ? gh_load_be32(h + 4u * i) : 0u; /* no H: H = 0, the same all-zero object that wipe leaves */

		g->aux[i] = be;               /* H in BE form */
		g->h[i] = gh_rev32(be);       /* H in natural form */
		g->y[i] = 0;
	}
	/* the sums the middle Karatsuba product needs: natural form of (h0 ^ h2, h1 ^ h3), then their BE form */
	g->aux[4] = g->h[0] ^ g->h[2];
	g->aux[5] = g->h[1] ^ g->h[3];
	g->aux[6] = g->aux[0] ^ g->aux[2];
	g->aux[7] = g->aux[1] ^ g->aux[3];
}

void wri_ghash_reset(wri_ghash *g)
{
	if (g != NULL)
		WR_MEMSET(g->y, 0, sizeof(g->y));
}

void wri_ghash_blocks(wri_ghash *g, const uint8_t *p, size_t nblocks)
{
	gh_tmp t;
	size_t n, i;

	if (g == NULL || nblocks == 0u)
		return;
	if (p == NULL) {
		/* blocks to hash but no data: skipping them would leave a value that covers less than the caller meant to authenticate, so
		 * the misuse destroys the object instead (H = 0, y = 0: every later value is the constant zero, and a tag built on it fails
		 * against any honest peer's) */
		wri_secure_zero(g, sizeof(*g));
		return;
	}
	for (n = 0; n < nblocks; n++, p += WRI_GHASH_BLOCK) {
		for (i = 0; i < 4u; i++) {
			t.rx[i] = g->y[i] ^ gh_load_be32(p + 4u * i);
			t.x[i] = gh_rev32(t.rx[i]);
		}
		gh_clmul128(&t, g);
		gh_reduce(t.prod, t.x); /* x is dead after the product: the result goes there */
		for (i = 0; i < 4u; i++)
			g->y[i] = gh_rev32(t.x[i]);
	}
	wri_secure_zero(&t, sizeof(t));
}

void wri_ghash_get(const wri_ghash *g, uint8_t out[16])
{
	size_t i;

	if (out == NULL)
		return;
	if (g == NULL) {
		WR_MEMSET(out, 0, 16);
		return;
	}
	for (i = 0; i < 4u; i++)
		gh_store_be32(out + 4u * i, g->y[i]);
}

void wri_ghash_wipe(wri_ghash *g)
{
	if (g != NULL)
		wri_secure_zero(g, sizeof(*g));
}
