/* SPDX-License-Identifier: MIT */
/*
 * wri_sha512.c - the SHA-512 compression core (FIPS 180-4, section 6.4) and SHA-384 on top of it
 * (section 6.5), written from the standard.
 *
 * Only SHA-384 is exported: cephx key type 2 needs HMAC-SHA384 and nothing needs plain SHA-512.
 * The context is the SHA-512 one (wri_sha512_ctx) with a 128-bit byte counter held as two u64
 * words; the padding stores the bit count modulo 2^128. No heap, no recursion, the const
 * tables are the only static data. The context is wiped by final.
 */
#include "wri_hash.h"

WR_FILE_LICENCE_MIT

/* Round constants: the first 64 bits of the fractional parts of the cube roots of the first 80
 * primes (FIPS 180-4, 4.2.3). */
static const uint64_t wri_sha512_k[80] = {
	0x428a2f98d728ae22ull, 0x7137449123ef65cdull,
	0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
	0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
	0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
	0xd807aa98a3030242ull, 0x12835b0145706fbeull,
	0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
	0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull,
	0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
	0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
	0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
	0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull,
	0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
	0x983e5152ee66dfabull, 0xa831c66d2db43210ull,
	0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
	0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
	0x06ca6351e003826full, 0x142929670a0e6e70ull,
	0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull,
	0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
	0x650a73548baf63deull, 0x766a0abb3c77b2a8ull,
	0x81c2c92e47edaee6ull, 0x92722c851482353bull,
	0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
	0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
	0xd192e819d6ef5218ull, 0xd69906245565a910ull,
	0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
	0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
	0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
	0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
	0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
	0x748f82ee5defb2fcull, 0x78a5636f43172f60ull,
	0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
	0x90befffa23631e28ull, 0xa4506cebde82bde9ull,
	0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
	0xca273eceea26619cull, 0xd186b8c721c0c207ull,
	0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
	0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
	0x113f9804bef90daeull, 0x1b710b35131c471bull,
	0x28db77f523047d84ull, 0x32caab7b40c72493ull,
	0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
	0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
	0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

/* SHA-384 initial hash value: the first 64 bits of the fractional parts of the square roots of
 * the ninth to sixteenth primes (FIPS 180-4, 5.3.4). */
static const uint64_t wri_sha384_iv[8] = {
	0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull,
	0x9159015a3070dd17ull, 0x152fecd8f70e5939ull,
	0x67332667ffc00b31ull, 0x8eb44a8768581511ull,
	0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull,
};

static uint64_t wri_sha512_ror(uint64_t x, unsigned n)
{
	return (x >> n) | (x << (64u - n));
}

static uint64_t wri_sha512_be64_get(const uint8_t *p)
{
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < 8; i++)
		v = (v << 8) | (uint64_t)p[i];
	return v;
}

static void wri_sha512_be64_put(uint8_t *p, uint64_t v)
{
	unsigned i;

	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (56u - 8u * i));
}

/* Wipe that the optimiser may not drop (the context holds key-derived state inside HMAC). */
static void wri_sha512_wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0)
		*v++ = 0;
}

/* Message schedule word i (i >= 16) from the 16-word ring: word t replaces word t-16 in place, so
 * the schedule costs 128 bytes of stack instead of 640. */
static uint64_t wri_sha512_sched(uint64_t w[16], unsigned i)
{
	uint64_t w15 = w[(i + 1u) & 15u];
	uint64_t w2 = w[(i + 14u) & 15u];
	uint64_t s0 = wri_sha512_ror(w15, 1) ^ wri_sha512_ror(w15, 8) ^ (w15 >> 7);
	uint64_t s1 = wri_sha512_ror(w2, 19) ^ wri_sha512_ror(w2, 61) ^ (w2 >> 6);

	w[i & 15u] += s0 + w[(i + 9u) & 15u] + s1;
	return w[i & 15u];
}

/* One round on the working state s[0..7] = a..h; kw = K[i] + W[i]. The rounds are kept in their own
 * small function so no caller frame grows large even in unoptimised sanitizer builds. */
static void wri_sha512_round(uint64_t s[8], uint64_t kw)
{
	uint64_t e = s[4];
	uint64_t a = s[0];
	uint64_t t1 = s[7] + (wri_sha512_ror(e, 14) ^ wri_sha512_ror(e, 18) ^ wri_sha512_ror(e, 41)) +
		      ((e & s[5]) ^ (~e & s[6])) + kw;
	uint64_t t2 = (wri_sha512_ror(a, 28) ^ wri_sha512_ror(a, 34) ^ wri_sha512_ror(a, 39)) +
		      ((a & s[1]) ^ (a & s[2]) ^ (s[1] & s[2]));

	s[7] = s[6];
	s[6] = s[5];
	s[5] = e;
	s[4] = s[3] + t1;
	s[3] = s[2];
	s[2] = s[1];
	s[1] = a;
	s[0] = t1 + t2;
}

/* Process one 128-byte block. */
static void wri_sha512_block(uint64_t h[8], const uint8_t *blk)
{
	uint64_t w[16];
	uint64_t s[8];
	unsigned i;

	for (i = 0; i < 16; i++)
		w[i] = wri_sha512_be64_get(blk + 8u * i);
	for (i = 0; i < 8; i++)
		s[i] = h[i];

	for (i = 0; i < 80; i++) {
		uint64_t wi = (i < 16) ? w[i] : wri_sha512_sched(w, i);

		wri_sha512_round(s, wri_sha512_k[i] + wi);
	}
	for (i = 0; i < 8; i++)
		h[i] += s[i];

	wri_sha512_wipe(w, sizeof(w));
	wri_sha512_wipe(s, sizeof(s));
}

void wri_sha384_init(wri_sha512_ctx *c)
{
	unsigned i;

	for (i = 0; i < 8; i++)
		c->h[i] = wri_sha384_iv[i];
	c->total_lo = 0;
	c->total_hi = 0;
	c->fill = 0;
	WR_MEMSET(c->buf, 0, sizeof(c->buf));
}

void wri_sha384_update(wri_sha512_ctx *c, const uint8_t *p, size_t n)
{
	uint64_t lo;

	if (n == 0)
		return;
	lo = c->total_lo + (uint64_t)n;
	if (lo < c->total_lo) /* carry into the high word */
		c->total_hi++;
	c->total_lo = lo;

	if (c->fill > 0) {
		size_t room = sizeof(c->buf) - c->fill;
		size_t take = n < room ? n : room;

		WR_MEMCPY(c->buf + c->fill, p, take);
		c->fill += (uint32_t)take;
		p += take;
		n -= take;
		if (c->fill < sizeof(c->buf))
			return;
		wri_sha512_block(c->h, c->buf);
		c->fill = 0;
	}
	while (n >= sizeof(c->buf)) {
		wri_sha512_block(c->h, p);
		p += sizeof(c->buf);
		n -= sizeof(c->buf);
	}
	if (n > 0) {
		WR_MEMCPY(c->buf, p, n);
		c->fill = (uint32_t)n;
	}
}

void wri_sha384_final(wri_sha512_ctx *c, uint8_t out[48])
{
	/* bit length = byte count * 8, as a 128-bit value */
	uint64_t bits_hi = (c->total_hi << 3) | (c->total_lo >> 61);
	uint64_t bits_lo = c->total_lo << 3;
	unsigned i;

	/* Padding: one 0x80 byte, zeros, then the 128-bit big-endian bit length in the last 16
	 * bytes of a block; if fewer than 16 bytes are left after the 0x80, an extra block is used. */
	c->buf[c->fill++] = 0x80u;
	if (c->fill > 112u) {
		WR_MEMSET(c->buf + c->fill, 0, sizeof(c->buf) - c->fill);
		wri_sha512_block(c->h, c->buf);
		c->fill = 0;
	}
	WR_MEMSET(c->buf + c->fill, 0, 112u - c->fill);
	wri_sha512_be64_put(c->buf + 112, bits_hi);
	wri_sha512_be64_put(c->buf + 120, bits_lo);
	wri_sha512_block(c->h, c->buf);

	/* SHA-384 is the first six of the eight state words. */
	for (i = 0; i < 6; i++)
		wri_sha512_be64_put(out + 8u * i, c->h[i]);

	wri_sha512_wipe(c, sizeof(*c));
}
