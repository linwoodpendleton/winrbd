/* SPDX-License-Identifier: MIT */
/*
 * wri_crush_hash.c - object name hashes, the CRUSH 32-bit mixing hashes and the stable modulo.
 *
 * Written from docs/spec/crush-and-placement.md 3.1 and 3.2. Everything is u32 arithmetic that wraps,
 * nothing here keeps state, and no pointer is read past the length the caller gives.
 */
#include "wri_crush_hash.h"

WR_FILE_LICENCE_MIT

#define WRI_CRUSH_HASH_SEED 1315423911u /* 0x4E67C6A7 */
#define WRI_CRUSH_HASH_X 231232u
#define WRI_CRUSH_HASH_Y 1232u
#define WRI_STR_HASH_GOLDEN 0x9e3779b9u

/* The nine-round mix of 3.2.1: the three words are updated in place. */
static void wri_mix(uint32_t *pa, uint32_t *pb, uint32_t *pc)
{
	uint32_t a = *pa, b = *pb, c = *pc;

	a = a - b - c;
	a ^= c >> 13;
	b = b - c - a;
	b ^= a << 8;
	c = c - a - b;
	c ^= b >> 13;
	a = a - b - c;
	a ^= c >> 12;
	b = b - c - a;
	b ^= a << 16;
	c = c - a - b;
	c ^= b >> 5;
	a = a - b - c;
	a ^= c >> 3;
	b = b - c - a;
	b ^= a << 10;
	c = c - a - b;
	c ^= b >> 15;
	*pa = a;
	*pb = b;
	*pc = c;
}

/* ---- string hashes (3.1) ---------------------------------------------------------------------- */

static uint32_t wri_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint32_t wri_str_hash_rjenkins(const uint8_t *s, uint32_t n)
{
	uint32_t a = WRI_STR_HASH_GOLDEN, b = WRI_STR_HASH_GOLDEN, c = 0;
	uint32_t left = n;

	if (s == NULL && n != 0)
		return 0; /* bytes announced but none given: refuse like wri_str_hash_linux, never read (NULL is fine with n == 0) */
	while (left >= 12u) {
		a += wri_le32(s);
		b += wri_le32(s + 4);
		c += wri_le32(s + 8);
		wri_mix(&a, &b, &c);
		s += 12;
		left -= 12u;
	}
	c += n;
	/* The tail of 1..11 bytes; c's low byte holds the length, so its bytes start one byte up. */
	switch (left) {
	case 11:
		c += (uint32_t)s[10] << 24;
		/* fall through */
	case 10:
		c += (uint32_t)s[9] << 16;
		/* fall through */
	case 9:
		c += (uint32_t)s[8] << 8;
		/* fall through */
	case 8:
		b += (uint32_t)s[7] << 24;
		/* fall through */
	case 7:
		b += (uint32_t)s[6] << 16;
		/* fall through */
	case 6:
		b += (uint32_t)s[5] << 8;
		/* fall through */
	case 5:
		b += (uint32_t)s[4];
		/* fall through */
	case 4:
		a += (uint32_t)s[3] << 24;
		/* fall through */
	case 3:
		a += (uint32_t)s[2] << 16;
		/* fall through */
	case 2:
		a += (uint32_t)s[1] << 8;
		/* fall through */
	case 1:
		a += (uint32_t)s[0];
		/* fall through */
	default:
		break;
	}
	wri_mix(&a, &b, &c);
	return c;
}

uint32_t wri_str_hash_linux(const uint8_t *s, uint32_t n)
{
	uint32_t h = 0, i;

	if (s == NULL)
		return 0; /* n == 0 gives 0 as well; with bytes announced and none given there is nothing to hash */
	for (i = 0; i < n; i++) {
		uint32_t ch = s[i];

		h = (h + (ch << 4) + (ch >> 4)) * 11u;
	}
	return h;
}

uint32_t wri_str_hash(uint32_t hash_id, const uint8_t *s, uint32_t n, int *ok)
{
	if ((s == NULL && n != 0) || (hash_id != WRI_STR_HASH_RJENKINS && hash_id != WRI_STR_HASH_LINUX)) {
		if (ok != NULL)
			*ok = 0;
		return 0;
	}
	if (ok != NULL)
		*ok = 1;
	return hash_id == WRI_STR_HASH_RJENKINS ? wri_str_hash_rjenkins(s, n) : wri_str_hash_linux(s, n);
}

/* ---- CRUSH hashes (3.2.1) --------------------------------------------------------------------- */

uint32_t wri_crush_hash1(uint32_t a)
{
	uint32_t h = WRI_CRUSH_HASH_SEED ^ a;
	uint32_t b = a, x = WRI_CRUSH_HASH_X, y = WRI_CRUSH_HASH_Y;

	wri_mix(&b, &x, &h);
	wri_mix(&y, &a, &h);
	return h;
}

uint32_t wri_crush_hash2(uint32_t a, uint32_t b)
{
	uint32_t h = WRI_CRUSH_HASH_SEED ^ a ^ b;
	uint32_t x = WRI_CRUSH_HASH_X, y = WRI_CRUSH_HASH_Y;

	wri_mix(&a, &b, &h);
	wri_mix(&x, &a, &h);
	wri_mix(&b, &y, &h);
	return h;
}

uint32_t wri_crush_hash3(uint32_t a, uint32_t b, uint32_t c)
{
	uint32_t h = WRI_CRUSH_HASH_SEED ^ a ^ b ^ c;
	uint32_t x = WRI_CRUSH_HASH_X, y = WRI_CRUSH_HASH_Y;

	wri_mix(&a, &b, &h);
	wri_mix(&c, &x, &h);
	wri_mix(&y, &a, &h);
	wri_mix(&b, &x, &h);
	wri_mix(&y, &c, &h);
	return h;
}

uint32_t wri_crush_hash4(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
	uint32_t h = WRI_CRUSH_HASH_SEED ^ a ^ b ^ c ^ d;
	uint32_t x = WRI_CRUSH_HASH_X, y = WRI_CRUSH_HASH_Y;

	wri_mix(&a, &b, &h);
	wri_mix(&c, &d, &h);
	wri_mix(&a, &x, &h);
	wri_mix(&y, &b, &h);
	wri_mix(&c, &x, &h);
	wri_mix(&y, &d, &h);
	return h;
}

/* ---- pg arithmetic (3.2) ---------------------------------------------------------------------- */

uint32_t wri_cbits(uint32_t v)
{
	uint32_t n = 0;

	while (v != 0) {
		n++;
		v >>= 1;
	}
	return n;
}

uint32_t wri_pg_mask(uint32_t n)
{
	uint32_t bits;

	if (n == 0)
		return 0;
	bits = wri_cbits(n - 1u);
	if (bits >= 32u)
		return 0xffffffffu; /* 1 << 32 is undefined; the mask of that width is all ones */
	return (1u << bits) - 1u;
}

uint32_t wri_stable_mod(uint32_t x, uint32_t b, uint32_t bmask)
{
	if ((x & bmask) < b)
		return x & bmask;
	return x & (bmask >> 1);
}
