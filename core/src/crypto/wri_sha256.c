/* SPDX-License-Identifier: MIT */
/*
 * wri_sha256.c - SHA-256 (FIPS 180-4, section 6.2), written from the standard.
 *
 * Streaming interface: init, update any number of times, final. The message length is counted
 * in a 64-bit byte counter (the padding stores it as a bit count modulo 2^64, as the standard
 * says). No heap, no globals except the const constant tables, no recursion. The context is
 * wiped by final.
 */
#include "wri_hash.h"

WR_FILE_LICENCE_MIT

/* Round constants: the first 32 bits of the fractional parts of the cube roots of the first 64
 * primes (FIPS 180-4, 4.2.2). */
static const uint32_t wri_sha256_k[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
	0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
	0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
	0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
	0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
	0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
	0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
	0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

/* Initial hash value: the first 32 bits of the fractional parts of the square roots of the first
 * eight primes (FIPS 180-4, 5.3.3). */
static const uint32_t wri_sha256_iv[8] = {
	0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
	0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

WR_STATIC_ASSERT(sizeof(uint32_t) == 4, sha256_u32_is_4_bytes);

static uint32_t wri_sha256_ror(uint32_t x, unsigned n)
{
	return (x >> n) | (x << (32u - n));
}

static uint32_t wri_sha256_be32_get(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wri_sha256_be32_put(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/* Wipe that the optimiser may not drop (the context holds key-derived state inside HMAC). */
static void wri_sha256_wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0)
		*v++ = 0;
}

/* Message schedule word i (i >= 16) from the 16-word ring: word t replaces word t-16 in place, so
 * the schedule costs 64 bytes of stack instead of 256. */
static uint32_t wri_sha256_sched(uint32_t w[16], unsigned i)
{
	uint32_t w15 = w[(i + 1u) & 15u];
	uint32_t w2 = w[(i + 14u) & 15u];
	uint32_t s0 = wri_sha256_ror(w15, 7) ^ wri_sha256_ror(w15, 18) ^ (w15 >> 3);
	uint32_t s1 = wri_sha256_ror(w2, 17) ^ wri_sha256_ror(w2, 19) ^ (w2 >> 10);

	w[i & 15u] += s0 + w[(i + 9u) & 15u] + s1;
	return w[i & 15u];
}

/* One round on the working state s[0..7] = a..h; kw = K[i] + W[i]. The rounds are kept in their own
 * small function so no caller frame grows large even in unoptimised sanitizer builds. */
static void wri_sha256_round(uint32_t s[8], uint32_t kw)
{
	uint32_t e = s[4];
	uint32_t a = s[0];
	uint32_t t1 = s[7] + (wri_sha256_ror(e, 6) ^ wri_sha256_ror(e, 11) ^ wri_sha256_ror(e, 25)) +
		      ((e & s[5]) ^ (~e & s[6])) + kw;
	uint32_t t2 = (wri_sha256_ror(a, 2) ^ wri_sha256_ror(a, 13) ^ wri_sha256_ror(a, 22)) +
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

/* Process one 64-byte block. */
static void wri_sha256_block(uint32_t h[8], const uint8_t *blk)
{
	uint32_t w[16];
	uint32_t s[8];
	unsigned i;

	for (i = 0; i < 16; i++)
		w[i] = wri_sha256_be32_get(blk + 4u * i);
	for (i = 0; i < 8; i++)
		s[i] = h[i];

	for (i = 0; i < 64; i++) {
		uint32_t wi = (i < 16) ? w[i] : wri_sha256_sched(w, i);

		wri_sha256_round(s, wri_sha256_k[i] + wi);
	}
	for (i = 0; i < 8; i++)
		h[i] += s[i];

	wri_sha256_wipe(w, sizeof(w));
	wri_sha256_wipe(s, sizeof(s));
}

void wri_sha256_init(wri_sha256_ctx *c)
{
	unsigned i;

	for (i = 0; i < 8; i++)
		c->h[i] = wri_sha256_iv[i];
	c->total = 0;
	c->fill = 0;
	WR_MEMSET(c->buf, 0, sizeof(c->buf));
}

void wri_sha256_update(wri_sha256_ctx *c, const uint8_t *p, size_t n)
{
	if (n == 0)
		return;
	c->total += (uint64_t)n;

	if (c->fill > 0) {
		size_t room = sizeof(c->buf) - c->fill;
		size_t take = n < room ? n : room;

		WR_MEMCPY(c->buf + c->fill, p, take);
		c->fill += (uint32_t)take;
		p += take;
		n -= take;
		if (c->fill < sizeof(c->buf))
			return;
		wri_sha256_block(c->h, c->buf);
		c->fill = 0;
	}
	while (n >= sizeof(c->buf)) {
		wri_sha256_block(c->h, p);
		p += sizeof(c->buf);
		n -= sizeof(c->buf);
	}
	if (n > 0) {
		WR_MEMCPY(c->buf, p, n);
		c->fill = (uint32_t)n;
	}
}

void wri_sha256_final(wri_sha256_ctx *c, uint8_t out[32])
{
	uint64_t bits = c->total << 3; /* modulo 2^64, as the standard defines */
	unsigned i;

	/* Padding: one 0x80 byte, zeros, then the 64-bit big-endian bit length in the last 8 bytes
	 * of a block; if fewer than 8 bytes are left after the 0x80, a whole extra block is used. */
	c->buf[c->fill++] = 0x80u;
	if (c->fill > 56u) {
		WR_MEMSET(c->buf + c->fill, 0, sizeof(c->buf) - c->fill);
		wri_sha256_block(c->h, c->buf);
		c->fill = 0;
	}
	WR_MEMSET(c->buf + c->fill, 0, 56u - c->fill);
	wri_sha256_be32_put(c->buf + 56, (uint32_t)(bits >> 32));
	wri_sha256_be32_put(c->buf + 60, (uint32_t)bits);
	wri_sha256_block(c->h, c->buf);

	for (i = 0; i < 8; i++)
		wri_sha256_be32_put(out + 4u * i, c->h[i]);

	wri_sha256_wipe(c, sizeof(*c));
}
