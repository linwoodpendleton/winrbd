/* SPDX-License-Identifier: MIT */
/*
 * wri_misc.c - secure wipe, constant-time compare, checked size arithmetic, 64-bit division and
 * the strict base64 decoder (see wri_misc.h).
 */
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

void wri_secure_zero(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	/* Volatile stores cannot be dropped as "dead" by the optimiser, unlike memset. */
	while (n-- > 0)
		*v++ = 0;
}

int wri_ct_memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint32_t diff = 0;
	size_t i;

	for (i = 0; i < n; i++)
		diff |= (uint32_t)(a[i] ^ b[i]);
	/* diff is 0..255: (diff - 1) has bit 8 set only for diff == 0. No branch on the data. */
	return (int)(((diff - 1u) >> 8) & 1u);
}

/* ---- checked arithmetic ------------------------------------------------------------------- */

wr_status wri_add_sz(size_t a, size_t b, size_t *out)
{
	if (a > (size_t)SIZE_MAX - b)
		return WR_E_OVERFLOW;
	if (out)
		*out = a + b;
	return WR_OK;
}

wr_status wri_mul_sz(size_t a, size_t b, size_t *out)
{
	if (a != 0 && b > (size_t)SIZE_MAX / a)
		return WR_E_OVERFLOW;
	if (out)
		*out = a * b;
	return WR_OK;
}

wr_status wri_align_up(size_t v, size_t align, size_t *out)
{
	size_t mask;

	if (align == 0 || (align & (align - 1)) != 0)
		return WR_E_INVAL;
	mask = align - 1;
	if (v > (size_t)SIZE_MAX - mask)
		return WR_E_OVERFLOW;
	if (out)
		*out = (v + mask) & ~mask;
	return WR_OK;
}

/* ---- 64-bit division ---------------------------------------------------------------------- */

/*
 * Unsigned 64 / 32 by long division, one quotient bit per step from the top. Only shifts by one
 * and compares, so a 32-bit compiler needs no library call. The partial remainder stays below
 * den (< 2^32) between steps, hence below 2^33 after the shift: it fits in 64 bits.
 */
static uint64_t wri_udiv64_u32(uint64_t num, uint32_t den)
{
	uint64_t q = 0, r = 0, bit;

	for (bit = (uint64_t)1 << 63; bit != 0; bit >>= 1) {
		r <<= 1;
		if ((num & bit) != 0)
			r |= 1;
		if (r >= den) {
			r -= den;
			q |= bit;
		}
	}
	return q;
}

int64_t wri_div_s64_u32_slow(int64_t num, uint32_t den)
{
	uint64_t mag, q;
	int neg = num < 0;

	if (den == 0)
		return 0;
	/* |num| as unsigned; 0 - (uint64)INT64_MIN is 2^63, the correct magnitude, with no overflow */
	mag = neg ? (uint64_t)0 - (uint64_t)num : (uint64_t)num;
	q = wri_udiv64_u32(mag, den);
	if (!neg)
		return (int64_t)q; /* q <= INT64_MAX because mag <= INT64_MAX */
	if (q > (uint64_t)INT64_MAX) /* only INT64_MIN / 1 */
		return INT64_MIN;
	return -(int64_t)q;
}

int64_t wri_div_s64_u32(int64_t num, uint32_t den)
{
	if (den == 0)
		return 0;
#if defined(WR_NATIVE_DIV64)
	return num / (int64_t)den; /* den >= 1, so neither a zero divide nor INT64_MIN / -1 */
#else
	return wri_div_s64_u32_slow(num, den);
#endif
}

/* ---- base64 ------------------------------------------------------------------------------- */

/* Value of a base64 digit (the standard alphabet), or -1. Each range test is one unsigned subtraction: below the range it wraps high. */
static int wri_b64_val(unsigned char c)
{
	const unsigned v = c;

	if (v - 'A' < 26u)
		return (int)(v - 'A');
	if (v - 'a' < 26u)
		return (int)(v - 'a') + 26;
	if (v - '0' < 10u)
		return (int)(v - '0') + 52;
	return v == '+' ? 62 : (v == '/' ? 63 : -1);
}

static int wri_b64_space(unsigned char c)
{
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

/*
 * Emit the bytes of a finished group of nq digits (2, 3 or 4) held in acc, 6 bits per digit.
 * Writes nothing and returns an error if cap would be exceeded or spare bits are set.
 */
static wr_status wri_b64_emit(uint32_t acc, unsigned nq, uint8_t *out, size_t cap, size_t *o)
{
	size_t k = nq - 1u; /* 2 digits -> 1 byte, 3 -> 2, 4 -> 3 */

	if (k > cap - *o)
		return WR_E_TOOBIG;
	if (nq == 2) {
		if ((acc & 0x0fu) != 0)
			return WR_E_ENCODING;
		out[(*o)++] = (uint8_t)(acc >> 4);
	} else if (nq == 3) {
		if ((acc & 0x03u) != 0)
			return WR_E_ENCODING;
		out[(*o)++] = (uint8_t)(acc >> 10);
		out[(*o)++] = (uint8_t)((acc >> 2) & 0xffu);
	} else {
		out[(*o)++] = (uint8_t)(acc >> 16);
		out[(*o)++] = (uint8_t)((acc >> 8) & 0xffu);
		out[(*o)++] = (uint8_t)(acc & 0xffu);
	}
	return WR_OK;
}

wr_status wri_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap, size_t *out_len)
{
	size_t i, o = 0;
	uint32_t acc = 0;
	unsigned nq = 0;   /* digits in the current group */
	unsigned pads = 0; /* '=' seen in the current group */
	int done = 0;      /* a group was closed by padding: only whitespace may follow */
	wr_status st = WR_OK;

	if (out_len == NULL)
		return WR_E_INVAL;
	*out_len = 0;
	if ((n != 0 && in == NULL) || (cap != 0 && out == NULL))
		return WR_E_INVAL;

	for (i = 0; i < n && st == WR_OK; i++) {
		unsigned char c = (unsigned char)in[i];
		int v;

		if (wri_b64_space(c))
			continue;
		if (done) {
			st = WR_E_ENCODING; /* anything after the closing padding */
		} else if (c == '=') {
			if (nq < 2) {
				st = WR_E_ENCODING; /* "=" or "A=" cannot be a valid group */
			} else if (++pads + nq == 4) {
				st = wri_b64_emit(acc, nq, out, cap, &o);
				done = 1;
				nq = 0;
				pads = 0;
			}
		} else if (pads != 0) {
			st = WR_E_ENCODING; /* digit after the first '=' of a group */
		} else if ((v = wri_b64_val(c)) < 0) {
			st = WR_E_ENCODING;
		} else {
			acc = (acc << 6) | (uint32_t)v;
			if (++nq == 4) {
				st = wri_b64_emit(acc, nq, out, cap, &o);
				nq = 0;
				acc = 0;
			}
		}
	}
	if (st == WR_OK && (nq != 0 || pads != 0))
		st = WR_E_ENCODING; /* missing padding, or a single dangling digit */
	if (st != WR_OK) {
		if (o != 0)
			wri_secure_zero(out, o);
		return st;
	}
	*out_len = o;
	return WR_OK;
}
