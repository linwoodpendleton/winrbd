/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_ghash - the constant-time GHASH of core/src/crypto/wri_ghash.c.
 *
 * What is checked:
 *   - the GHASH values inside eight test cases of the GCM specification (McGrew and Viega, test cases 1 to 4 for AES-128 and 13 to
 *     16 for AES-256, 96-bit IVs): H is computed with the table-driven AES of the core, the additional data, the cipher text and the
 *     length block are fed as the standard defines, every intermediate value is compared with the reference, test case 2's two
 *     published GHASH values are pinned, and the final value xor E(K, J0) must be the published tag;
 *   - a bit-by-bit multiplication written here from NIST SP 800-38D 6.3 (algorithm 1), against the module on 200,000 random
 *     (H, block sequence) cases, every value after every block, plus all 128 x 128 single-bit pairs (the reduction paths) and a
 *     set of dense and sparse patterns;
 *   - algebra that needs no reference: H = 0 gives 0, H = the field's one (0x80 00 .. 00) is the identity, the block 0x80 00 .. 00
 *     returns H, multiplication commutes (swap the roles of H and the block) and distributes over xor, a zero block multiplies the
 *     running value by H, the one-block value Y * H is linear in Y;
 *   - blocks split at any point equal one call (every split point of messages up to 20 blocks, three-way splits at random);
 *   - reset keeps H (the object's h and aux words do not change) and zeroes the running value; init fully determines the object;
 *   - input pointers at every alignment 0 to 7 (heap blocks of exact size so a sanitizer sees any read past the end);
 *   - get does not change the state; wipe clears the whole object; NULL arguments do nothing, except that blocks to hash with no
 *     data pointer destroy the object (fail closed) and a missing H is the all-zero object;
 *   - a 1000-block message in random pieces against the reference, H and its derived words unchanged by blocks.
 */
#include "wrt.h"

#include "wri_aes.h"
#include "wri_ghash.h"

/* ---- helpers --------------------------------------------------------------------------------- */

static size_t hx(const char *hex, uint8_t *buf, size_t max)
{
	size_t n = 0, i;

	for (i = 0; hex[i] != '\0' && hex[i + 1u] != '\0'; i += 2u) {
		unsigned v = 0, k;

		for (k = 0; k < 2u; k++) {
			char c = hex[i + k];

			v = v * 16u + (unsigned)((c >= 'a') ? c - 'a' + 10 : (c >= 'A') ? c - 'A' + 10 : c - '0');
		}
		if (n >= max)
			return 0;
		buf[n++] = (uint8_t)v;
	}
	return n;
}

/* xorshift64*: deterministic test data, not a security primitive. */
static uint64_t rng_state = 0x243f6a8885a308d3ull;

static uint32_t rnd(void)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (uint32_t)((rng_state * 0x2545f4914f6cdd1dull) >> 32);
}

static void rnd_fill(uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)rnd();
}

/* A mixture: mostly uniform, sometimes sparse, dense or structured, so the reduction and carry paths are exercised. */
static void rnd_block(uint8_t *p)
{
	unsigned kind = rnd() % 8u;
	size_t i;

	rnd_fill(p, 16);
	if (kind == 0u)
		memset(p, 0, 16);
	else if (kind == 1u)
		memset(p, 0xff, 16);
	else if (kind == 2u) {
		memset(p, 0, 16);
		p[rnd() % 16u] = (uint8_t)(1u << (rnd() % 8u));
	} else if (kind == 3u) {
		for (i = 0; i < 16u; i++)
			p[i] |= (uint8_t)rnd();
	} else if (kind == 4u) {
		for (i = 0; i < 16u; i++)
			p[i] &= (uint8_t)rnd();
	}
}

/* ---- the reference: NIST SP 800-38D 6.3, algorithm 1 ---------------------------------------------- */

typedef struct { uint64_t hi, lo; } u128; /* the 128-bit string, bit 0 = the most significant bit of hi */

static u128 u128_load(const uint8_t *p)
{
	u128 r = {0, 0};
	int i;

	for (i = 0; i < 8; i++) {
		r.hi = (r.hi << 8) | p[i];
		r.lo = (r.lo << 8) | p[8 + i];
	}
	return r;
}

static void u128_store(u128 v, uint8_t *p)
{
	int i;

	for (i = 7; i >= 0; i--) {
		p[i] = (uint8_t)v.hi;
		p[8 + i] = (uint8_t)v.lo;
		v.hi >>= 8;
		v.lo >>= 8;
	}
}

/* Z = X . Y: Z = 0, V = Y; for i = 0..127: if x_i = 1 then Z ^= V; if LSB1(V) = 0 then V = V >> 1 else V = (V >> 1) ^ R, R = 11100001 || 0^120. */
static u128 ref_mul(u128 x, u128 y)
{
	u128 z = {0, 0}, v = y;
	int i;

	for (i = 0; i < 128; i++) {
		int xi = (int)(((i < 64) ? (x.hi >> (63 - i)) : (x.lo >> (127 - i))) & 1u);
		int lsb = (int)(v.lo & 1u);

		if (xi) {
			z.hi ^= v.hi;
			z.lo ^= v.lo;
		}
		v.lo = (v.lo >> 1) | (v.hi << 63);
		v.hi >>= 1;
		if (lsb)
			v.hi ^= 0xe100000000000000ull;
	}
	return z;
}

/* y = (y ^ block) . H for each block */
static u128 ref_blocks(u128 y, u128 h, const uint8_t *p, size_t nblocks)
{
	size_t i;

	for (i = 0; i < nblocks; i++) {
		u128 b = u128_load(p + 16u * i);

		y.hi ^= b.hi;
		y.lo ^= b.lo;
		y = ref_mul(y, h);
	}
	return y;
}

static int get_eq(const wri_ghash *g, u128 want)
{
	uint8_t got[16], w[16];

	wri_ghash_get(g, got);
	u128_store(want, w);
	return memcmp(got, w, 16) == 0;
}

static void get_bytes(const wri_ghash *g, uint8_t out[16])
{
	wri_ghash_get(g, out);
}

/* ---- GCM specification test cases -------------------------------------------------------------- */

typedef struct tc {
	const char *name, *key, *iv, *aad, *ct, *tag;
} tc;

#define K128Z "00000000000000000000000000000000"
#define K256Z "0000000000000000000000000000000000000000000000000000000000000000"
#define K128B "feffe9928665731c6d6a8f9467308308"
#define K256B K128B K128B
#define IVB "cafebabefacedbaddecaf888"
#define AADB "feedfacedeadbeeffeedfacedeadbeefabaddad2"
#define CT128_3 "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05" \
		"1ba30b396a0aac973d58e091473f5985"
#define CT128_4 "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05" \
		"1ba30b396a0aac973d58e091"
#define CT256_15 "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838" \
		 "c5f61e6393ba7a0abcc9f662898015ad"
#define CT256_16 "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838" \
		 "c5f61e6393ba7a0abcc9f662"

static const tc tcs[] = {
	{"gcm-tc1", K128Z, "000000000000000000000000", "", "", "58e2fccefa7e3061367f1d57a4e7455a"},
	{"gcm-tc2", K128Z, "000000000000000000000000", "", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"},
	{"gcm-tc3", K128B, IVB, "", CT128_3, "4d5c2af327cd64a62cf35abd2ba6fab4"},
	{"gcm-tc4", K128B, IVB, AADB, CT128_4, "5bc94fbc3221a5db94fae95ae7121a47"},
	{"gcm-tc13", K256Z, "000000000000000000000000", "", "", "530f8afbc74536b9a963b4f1c4cb738b"},
	{"gcm-tc14", K256Z, "000000000000000000000000", "", "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"},
	{"gcm-tc15", K256B, IVB, "", CT256_15, "b094dac5d93471bdec1a502270e3cc6c"},
	{"gcm-tc16", K256B, IVB, AADB, CT256_16, "76fc6ece0f4e1768cddf8853bb2d551b"},
};

/* Feed `len` bytes the way GCM does: zero padded to whole blocks. */
static void feed_padded(wri_ghash *g, u128 *rg, u128 h, const uint8_t *d, size_t len)
{
	uint8_t blk[16];
	size_t full = len / 16u, rest = len % 16u;

	if (full != 0u) {
		wri_ghash_blocks(g, d, full);
		*rg = ref_blocks(*rg, h, d, full);
		WRT_CHECK(get_eq(g, *rg));
	}
	if (rest != 0u) {
		memset(blk, 0, sizeof(blk));
		memcpy(blk, d + 16u * full, rest);
		wri_ghash_blocks(g, blk, 1);
		*rg = ref_blocks(*rg, h, blk, 1);
		WRT_CHECK(get_eq(g, *rg));
	}
}

static void test_gcm_spec(void)
{
	size_t t;

	for (t = 0; t < sizeof(tcs) / sizeof(tcs[0]); t++) {
		const tc *c = &tcs[t];
		uint8_t key[32], iv[16], aad[32], ct[80], tag[16], hk[16], j0[16], ek[16], lenblk[16], s[16], z[16] = {0};
		size_t klen = hx(c->key, key, sizeof(key)), ivl = hx(c->iv, iv, 12), al = hx(c->aad, aad, sizeof(aad));
		size_t cl = hx(c->ct, ct, sizeof(ct)), i;
		wri_aes_ctx a;
		wri_ghash g;
		u128 rg = {0, 0}, h;
		uint64_t abits, cbits;

		(void)ivl;
		hx(c->tag, tag, sizeof(tag));
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&a, key, klen));
		wri_aes_enc_block(&a, z, hk);
		memcpy(j0, iv, 12);
		j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
		wri_aes_enc_block(&a, j0, ek);
		h = u128_load(hk);

		wri_ghash_init(&g, hk);
		feed_padded(&g, &rg, h, aad, al);
		feed_padded(&g, &rg, h, ct, cl);
		/* test case 2 publishes the GHASH value after the cipher text block and after the length block */
		if (t == 1u) {
			uint8_t x1[16], x2[16];

			hx("5e2ec746917062882c85b0685353deb7", x1, 16);
			hx("f38cbb1ad69223dcc3457ae5b6b0f885", x2, 16);
			get_bytes(&g, s);
			WRT_CHECK_MEM(s, x1, 16);
			abits = 0; cbits = 128;
			for (i = 0; i < 8u; i++) {
				lenblk[i] = (uint8_t)(abits >> (56 - 8u * i));
				lenblk[8u + i] = (uint8_t)(cbits >> (56 - 8u * i));
			}
			wri_ghash_blocks(&g, lenblk, 1);
			get_bytes(&g, s);
			WRT_CHECK_MEM(s, x2, 16);
			/* the same value from the reset object with the three blocks fed in one call */
			{
				uint8_t all[32];

				memcpy(all, ct, 16);
				memcpy(all + 16, lenblk, 16);
				wri_ghash_reset(&g);
				wri_ghash_blocks(&g, all, 2);
				get_bytes(&g, s);
				WRT_CHECK_MEM(s, x2, 16);
			}
			wri_ghash_init(&g, hk);
			rg.hi = rg.lo = 0;
			feed_padded(&g, &rg, h, ct, cl);
		}
		abits = (uint64_t)al * 8u;
		cbits = (uint64_t)cl * 8u;
		for (i = 0; i < 8u; i++) {
			lenblk[i] = (uint8_t)(abits >> (56 - 8u * i));
			lenblk[8u + i] = (uint8_t)(cbits >> (56 - 8u * i));
		}
		wri_ghash_blocks(&g, lenblk, 1);
		rg = ref_blocks(rg, h, lenblk, 1);
		WRT_CHECK(get_eq(&g, rg));
		get_bytes(&g, s);
		for (i = 0; i < 16u; i++)
			s[i] ^= ek[i];
		if (memcmp(s, tag, 16) != 0)
			fprintf(stderr, "%s: tag mismatch\n", c->name);
		WRT_CHECK_MEM(s, tag, 16);
		wri_ghash_wipe(&g);
	}
}

/* ---- the reference against the module -------------------------------------------------------------- */

static void test_random_vs_reference(void)
{
	uint8_t hb[16], data[16u * 8u];
	unsigned n;

	for (n = 0; n < 200000u; n++) {
		wri_ghash g;
		u128 h, y = {0, 0};
		size_t nb = rnd() % 8u, i;
		unsigned mode = rnd() % 4u;

		rnd_block(hb);
		for (i = 0; i < nb; i++)
			rnd_block(data + 16u * i);
		h = u128_load(hb);
		wri_ghash_init(&g, hb);
		if (mode == 0u) {
			/* one call, compared at the end */
			wri_ghash_blocks(&g, data, nb);
			y = ref_blocks(y, h, data, nb);
			WRT_CHECK(get_eq(&g, y));
		} else {
			/* block by block, compared after each (an unlucky multiplication would show at the first wrong value) */
			for (i = 0; i < nb; i++) {
				wri_ghash_blocks(&g, data + 16u * i, 1);
				y = ref_blocks(y, h, data + 16u * i, 1);
				WRT_CHECK(get_eq(&g, y));
			}
		}
	}
}

static void test_single_bits(void)
{
	/* every H with one bit set against every block with one bit set: all 16,384 pairs, every reduction path */
	unsigned a, b;

	for (a = 0; a < 128u; a++) {
		uint8_t hb[16] = {0};
		wri_ghash g;
		u128 h;

		hb[a / 8u] = (uint8_t)(0x80u >> (a % 8u));
		h = u128_load(hb);
		wri_ghash_init(&g, hb);
		for (b = 0; b < 128u; b++) {
			uint8_t blk[16] = {0};
			u128 y;

			blk[b / 8u] = (uint8_t)(0x80u >> (b % 8u));
			wri_ghash_reset(&g);
			wri_ghash_blocks(&g, blk, 1);
			y = ref_mul(u128_load(blk), h);
			WRT_CHECK(get_eq(&g, y));
		}
	}
}

static void test_patterns(void)
{
	static const uint8_t fill[] = {0x00, 0xff, 0x01, 0x80, 0xaa, 0x55, 0x0f, 0xf0, 0xe1, 0x87, 0x7f, 0xfe};
	size_t i, j;

	for (i = 0; i < sizeof(fill); i++)
		for (j = 0; j < sizeof(fill); j++) {
			uint8_t hb[16], blk[32];
			wri_ghash g;
			u128 h, y = {0, 0};

			memset(hb, fill[i], 16);
			memset(blk, fill[j], 32);
			h = u128_load(hb);
			wri_ghash_init(&g, hb);
			wri_ghash_blocks(&g, blk, 2);
			y = ref_blocks(y, h, blk, 2);
			WRT_CHECK(get_eq(&g, y));
		}
}

/* ---- algebra without a reference ------------------------------------------------------------------ */

static void test_algebra(void)
{
	static const uint8_t one[16] = {0x80}; /* the field's 1 in GCM's order: the coefficient of x^0 is bit 0, the top bit of byte 0 */
	uint8_t zero[16] = {0}, hb[16], a[16], b[16], c[16], r1[16], r2[16], r3[16], blk[48];
	wri_ghash g, g2;
	unsigned n;
	size_t i;

	/* H = 0: the running value is 0 whatever the data */
	wri_ghash_init(&g, zero);
	for (n = 0; n < 50u; n++) {
		rnd_block(blk);
		rnd_block(blk + 16);
		wri_ghash_blocks(&g, blk, 2);
		get_bytes(&g, r1);
		WRT_CHECK_MEM(r1, zero, 16);
	}
	/* H = 1: y_n = y_(n-1) xor block_n, so the value is the xor of all blocks */
	wri_ghash_init(&g, one);
	memset(r2, 0, 16);
	for (n = 0; n < 50u; n++) {
		rnd_block(blk);
		wri_ghash_blocks(&g, blk, 1);
		for (i = 0; i < 16u; i++)
			r2[i] ^= blk[i];
		get_bytes(&g, r1);
		WRT_CHECK_MEM(r1, r2, 16);
	}
	for (n = 0; n < 2000u; n++) {
		rnd_block(hb);
		rnd_block(a);
		rnd_block(b);
		/* the block "1" returns H; the zero block leaves 0; a zero block on a running value multiplies it by H */
		wri_ghash_init(&g, hb);
		wri_ghash_blocks(&g, one, 1);
		get_bytes(&g, r1);
		WRT_CHECK_MEM(r1, hb, 16);
		wri_ghash_reset(&g);
		wri_ghash_blocks(&g, zero, 1);
		get_bytes(&g, r1);
		WRT_CHECK_MEM(r1, zero, 16);
		wri_ghash_blocks(&g, a, 1);   /* y = a.H */
		wri_ghash_blocks(&g, zero, 1); /* y = a.H.H */
		wri_ghash_init(&g2, hb);
		wri_ghash_blocks(&g2, a, 1);
		get_bytes(&g2, r2);
		wri_ghash_init(&g2, hb);
		wri_ghash_blocks(&g2, r2, 1); /* (a.H).H */
		get_bytes(&g2, r3);
		get_bytes(&g, r1);
		WRT_CHECK_MEM(r1, r3, 16);
		/* commutativity: a.b computed with H = b and block a, and with H = a and block b */
		wri_ghash_init(&g, b);
		wri_ghash_blocks(&g, a, 1);
		get_bytes(&g, r1);
		wri_ghash_init(&g2, a);
		wri_ghash_blocks(&g2, b, 1);
		get_bytes(&g2, r2);
		WRT_CHECK_MEM(r1, r2, 16);
		/* distributivity over xor: (a ^ b).H = a.H ^ b.H, and the one-block value is linear in the block */
		for (i = 0; i < 16u; i++)
			c[i] = a[i] ^ b[i];
		wri_ghash_init(&g, hb);
		wri_ghash_blocks(&g, c, 1);
		get_bytes(&g, r1);
		wri_ghash_reset(&g);
		wri_ghash_blocks(&g, a, 1);
		get_bytes(&g, r2);
		wri_ghash_reset(&g);
		wri_ghash_blocks(&g, b, 1);
		get_bytes(&g, r3);
		for (i = 0; i < 16u; i++)
			r2[i] ^= r3[i];
		WRT_CHECK_MEM(r1, r2, 16);
	}
}

/* ---- splitting, reset, alignment, wipe -------------------------------------------------------------- */

static void test_splits(void)
{
	enum { MAXB = 20 };
	uint8_t hb[16], data[16 * MAXB], whole[16], part[16];
	unsigned n, k;

	for (n = 0; n < 60u; n++) {
		size_t nb = 1u + rnd() % MAXB, s;
		wri_ghash g, g2;

		rnd_block(hb);
		rnd_fill(data, 16u * nb);
		wri_ghash_init(&g, hb);
		wri_ghash_blocks(&g, data, nb);
		get_bytes(&g, whole);
		/* every single split point (including 0 and nb: an empty call) */
		for (s = 0; s <= nb; s++) {
			wri_ghash_init(&g2, hb);
			wri_ghash_blocks(&g2, data, s);
			wri_ghash_blocks(&g2, data + 16u * s, nb - s);
			get_bytes(&g2, part);
			WRT_CHECK_MEM(part, whole, 16);
		}
		/* random three-way and many-way splits */
		for (k = 0; k < 20u; k++) {
			size_t pos = 0;

			wri_ghash_init(&g2, hb);
			while (pos < nb) {
				size_t take = rnd() % (nb - pos + 1u);

				wri_ghash_blocks(&g2, data + 16u * pos, take);
				pos += take;
			}
			get_bytes(&g2, part);
			WRT_CHECK_MEM(part, whole, 16);
		}
		/* one block at a time */
		wri_ghash_init(&g2, hb);
		for (s = 0; s < nb; s++)
			wri_ghash_blocks(&g2, data + 16u * s, 1);
		get_bytes(&g2, part);
		WRT_CHECK_MEM(part, whole, 16);
	}
}

static void test_reset_init_wipe(void)
{
	uint8_t hb[16], data[64], r1[16], r2[16], zero[16] = {0};
	wri_ghash g, g2, saved;
	unsigned char *raw;
	size_t i;

	rnd_block(hb);
	rnd_fill(data, sizeof(data));
	wri_ghash_init(&g, hb);
	get_bytes(&g, r1);
	WRT_CHECK_MEM(r1, zero, 16); /* init clears the running value */
	wri_ghash_blocks(&g, data, 4);
	get_bytes(&g, r1);
	get_bytes(&g, r2); /* get changes nothing */
	WRT_CHECK_MEM(r1, r2, 16);
	WRT_CHECK(memcmp(r1, zero, 16) != 0);
	saved = g;
	/* reset: y = 0, h and aux untouched */
	wri_ghash_reset(&g);
	WRT_CHECK(memcmp(g.h, saved.h, sizeof(g.h)) == 0);
	WRT_CHECK(memcmp(g.aux, saved.aux, sizeof(g.aux)) == 0);
	get_bytes(&g, r2);
	WRT_CHECK_MEM(r2, zero, 16);
	wri_ghash_blocks(&g, data, 4);
	get_bytes(&g, r2);
	WRT_CHECK_MEM(r1, r2, 16); /* the same H gives the same value after the reset */
	/* init fully determines the object whatever was in it before */
	memset(&g2, 0xa5, sizeof(g2));
	wri_ghash_init(&g2, hb);
	wri_ghash_init(&g, hb);
	WRT_CHECK(memcmp(&g, &g2, sizeof(g)) == 0);
	/* wipe: every byte of the object is zero, get then gives zeros, a new init works */
	wri_ghash_blocks(&g, data, 4);
	wri_ghash_wipe(&g);
	raw = (unsigned char *)&g;
	for (i = 0; i < sizeof(g); i++)
		WRT_CHECK(raw[i] == 0u);
	memset(r1, 0xee, 16);
	wri_ghash_get(&g, r1);
	WRT_CHECK_MEM(r1, zero, 16);
	wri_ghash_init(&g, hb);
	wri_ghash_blocks(&g, data, 4);
	get_bytes(&g, r1);
	wri_ghash_init(&g2, hb);
	wri_ghash_blocks(&g2, data, 4);
	get_bytes(&g2, r2);
	WRT_CHECK_MEM(r1, r2, 16);
	/* NULL arguments are ignored (nothing to check but that they return) */
	wri_ghash_init(NULL, hb);
	wri_ghash_reset(NULL);
	wri_ghash_blocks(NULL, data, 1);
	wri_ghash_blocks(NULL, NULL, 1);
	wri_ghash_blocks(&g, NULL, 0); /* nothing to hash: no data pointer needed, nothing changes */
	wri_ghash_blocks(&g, data, 0);
	wri_ghash_get(&g, NULL);
	wri_ghash_wipe(NULL);
	get_bytes(&g, r2);
	WRT_CHECK_MEM(r1, r2, 16); /* none of that touched the value */
	/* a missing object reads as zeros */
	memset(r2, 0xee, 16);
	wri_ghash_get(NULL, r2);
	WRT_CHECK_MEM(r2, zero, 16);
	/* blocks to hash but no data fails closed: the object is destroyed (never a value that covers less than asked) */
	wri_ghash_blocks(&g, NULL, 1);
	raw = (unsigned char *)&g;
	for (i = 0; i < sizeof(g); i++)
		WRT_CHECK(raw[i] == 0u);
	/* a missing H is the all-zero object; an object that was never keyed (or was wiped) hashes everything to zero */
	wri_ghash_init(&g, NULL);
	WRT_CHECK(memcmp(g.h, zero, 16) == 0 && memcmp(g.aux, zero, 16) == 0);
	wri_ghash_blocks(&g, data, 4);
	get_bytes(&g, r2);
	WRT_CHECK_MEM(r2, zero, 16);
	wri_ghash_init(&g2, zero);
	WRT_CHECK(memcmp(&g, &g2, sizeof(g)) == 0);
}

/* The object stays the same where it must: blocks changes only the running value, so a long message and the sequence of values stay
 * tied to one H; a 1000-block message (a 16 KB segment) against the reference. */
static void test_long_message(void)
{
	enum { NB = 1000 };
	uint8_t hb[16], *data = (uint8_t *)malloc(16u * NB);
	wri_ghash g, before;
	u128 h, y = {0, 0};
	size_t pos = 0;

	WRT_CHECK(data != NULL);
	if (data == NULL)
		return;
	rnd_block(hb);
	rnd_fill(data, 16u * NB);
	h = u128_load(hb);
	wri_ghash_init(&g, hb);
	before = g;
	while (pos < NB) {
		size_t take = 1u + rnd() % 97u;

		if (take > NB - pos)
			take = NB - pos;
		wri_ghash_blocks(&g, data + 16u * pos, take);
		pos += take;
		/* H, its derived words and the scratch never change under blocks */
		WRT_CHECK(memcmp(g.h, before.h, sizeof(g.h)) == 0);
		WRT_CHECK(memcmp(g.aux, before.aux, sizeof(g.aux)) == 0);
	}
	y = ref_blocks(y, h, data, NB);
	WRT_CHECK(get_eq(&g, y));
	free(data);
}

static void test_alignment(void)
{
	enum { NB = 6 };
	uint8_t hb[16], data[16 * NB], whole[16], got[16];
	size_t off, nb;
	wri_ghash g;

	rnd_block(hb);
	rnd_fill(data, sizeof(data));
	for (nb = 0; nb <= NB; nb++) {
		wri_ghash_init(&g, hb);
		wri_ghash_blocks(&g, data, nb);
		get_bytes(&g, whole);
		for (off = 0; off < 8u; off++) {
			/* exact-size heap block (so a sanitizer sees any read past the end), the data at byte offset off */
			uint8_t *raw = (uint8_t *)malloc(off + 16u * nb + 1u), *p; /* +1: never a zero-size request */

			if (raw == NULL)
				continue;
			p = raw + off;
			memcpy(p, data, 16u * nb);
			wri_ghash_init(&g, hb);
			wri_ghash_blocks(&g, p, nb);
			get_bytes(&g, got);
			WRT_CHECK_MEM(got, whole, 16);
			free(raw);
		}
	}
	for (off = 1; off < 8u; off++) {
		uint8_t *raw = (uint8_t *)malloc(off + 16u);
		wri_ghash g2;
		u128 h = u128_load(hb), y = {0, 0};

		if (raw == NULL)
			continue;
		memcpy(raw + off, hb, 16); /* H itself at an unaligned address */
		wri_ghash_init(&g2, raw + off);
		wri_ghash_blocks(&g2, data, 1);
		y = ref_blocks(y, h, data, 1);
		WRT_CHECK(get_eq(&g2, y));
		free(raw);
	}
}

int main(void)
{
	test_gcm_spec();
	test_random_vs_reference();
	test_single_bits();
	test_patterns();
	test_algebra();
	test_splits();
	test_reset_init_wipe();
	test_long_message();
	test_alignment();
	printf("crypto.ghash: %lu checks, %lu failures\n", wrt_checks, wrt_failures);
	return wrt_finish();
}
