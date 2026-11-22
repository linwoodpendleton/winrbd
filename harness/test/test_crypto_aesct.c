/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_aesct - the constant-time bitsliced AES (core/src/crypto/wri_aesct.c) against the table-driven reference
 * (wri_aes.c) and against published answers.
 *
 * What is checked:
 *   - FIPS 197 appendix B and C.1 / C.3, and NIST SP 800-38A F.1 (ECB) and F.5 (CTR) for AES-128 and AES-256;
 *   - the S-box circuit: all 256 outputs in every one of the 32 lanes, against the S-box of wri_aes.c (the reference S-box is read
 *     out of the reference key schedule, so no table is copied into the test);
 *   - 100,000 random (key size, key, block count, data) cases of ECB against wri_aes_enc_block, with exact-size heap buffers (a
 *     sanitizer build sees any write or read past them), in place and out of place; block counts that cross the two-block chunking;
 *   - ctr32 against a counter mode built on wri_aes_enc_block, counters 0, 1, 0xfffffffe, 0xffffffff and random ones, both key sizes,
 *     lengths 0..70 and some longer, in place and out of place, the advanced counter, no carry out of the 32-bit counter, split calls;
 *   - failed setkey (17, 24, 0 bytes, NULL key, NULL context): statuses, and a context that encrypts to zeros (ECB and ctr32) even when
 *     it held a good key before; rekeying a used context; wipe leaves nothing; a NULL or unkeyed context never crashes; a good context
 *     with a NULL input, counter or output writes zeros (never the plain text, in place included) or nothing;
 *   - the stack of the block function (painted-stack measurement; skipped where the sanitizer or the compiler makes it meaningless).
 * The random source is a fixed-seed xorshift, so a failure reproduces.
 */
#include "wrt.h"

#include "wri_aes.h"
#include "wri_aesct.h"

/* ---- helpers --------------------------------------------------------------------------------- */

static size_t hx(const char *hex, uint8_t *buf, size_t max)
{
	uint8_t *tmp = NULL;
	size_t n = 0;

	if (wrt_hex_decode(hex, strlen(hex), &tmp, &n) != 0)
		return 0;
	if (n > max) {
		free(tmp);
		return 0;
	}
	memcpy(buf, tmp, n);
	free(tmp);
	return n;
}

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

static uint8_t *xmalloc(size_t n)
{
	uint8_t *p = (uint8_t *)calloc(n != 0 ? n : 1, 1);

	if (p == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	return p;
}

/* Counter mode on the reference block cipher: the last four bytes of ctr are a big-endian counter that wraps without carry. */
static void ref_ctr32(const wri_aes_ctx *rc, const uint8_t ctr[16], const uint8_t *in, uint8_t *out, size_t n)
{
	uint8_t blk[16], ks[16];
	uint32_t cnt = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16) | ((uint32_t)ctr[14] << 8) | ctr[15];
	size_t i, j;

	memcpy(blk, ctr, 12);
	for (i = 0; i < n; i += 16) {
		blk[12] = (uint8_t)(cnt >> 24);
		blk[13] = (uint8_t)(cnt >> 16);
		blk[14] = (uint8_t)(cnt >> 8);
		blk[15] = (uint8_t)cnt;
		wri_aes_enc_block(rc, blk, ks);
		for (j = 0; j < 16 && i + j < n; j++)
			out[i + j] = (uint8_t)(in[i + j] ^ ks[j]);
		cnt++;
	}
}

static void put_ctr(uint8_t ctr[16], const uint8_t *prefix, uint32_t cnt)
{
	memcpy(ctr, prefix, 12);
	ctr[12] = (uint8_t)(cnt >> 24);
	ctr[13] = (uint8_t)(cnt >> 16);
	ctr[14] = (uint8_t)(cnt >> 8);
	ctr[15] = (uint8_t)cnt;
}

/* ---- known answers --------------------------------------------------------------------------- */

static void check_ecb_vec(const char *keyhex, const char *pthex, const char *cthex)
{
	uint8_t key[32], pt[64], ct[64], out[64];
	size_t klen = hx(keyhex, key, sizeof(key)), n = hx(pthex, pt, sizeof(pt)), m = hx(cthex, ct, sizeof(ct));
	wri_aesct_ctx c;

	WRT_CHECK(klen == 16u || klen == 32u);
	WRT_CHECK(n == m && n % 16u == 0u && n != 0u);
	WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, klen));
	WRT_CHECK_U64(c.rounds, klen == 16u ? 10u : 14u);
	wri_aesct_encrypt_blocks(&c, pt, out, n / 16u);
	WRT_CHECK_MEM(out, ct, n);
	memcpy(out, pt, n); /* in place */
	wri_aesct_encrypt_blocks(&c, out, out, n / 16u);
	WRT_CHECK_MEM(out, ct, n);
	wri_aesct_wipe(&c);
}

static void check_ctr_vec(const char *keyhex, const char *ctrhex, const char *pthex, const char *cthex)
{
	uint8_t key[32], ctr[16], ctr0[16], pt[64], ct[64], out[64];
	size_t klen = hx(keyhex, key, sizeof(key)), n = hx(pthex, pt, sizeof(pt)), m = hx(cthex, ct, sizeof(ct));
	wri_aesct_ctx c;

	WRT_CHECK(hx(ctrhex, ctr, sizeof(ctr)) == 16u);
	memcpy(ctr0, ctr, 16);
	WRT_CHECK(n == m && n != 0u);
	WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, klen));
	wri_aesct_ctr32(&c, ctr, pt, out, n);
	WRT_CHECK_MEM(out, ct, n);
	/* the 64 bytes are four blocks: the counter ends four on, the nonce part is untouched */
	WRT_CHECK(memcmp(ctr, ctr0, 12) == 0);
	WRT_CHECK_U64(((uint32_t)ctr[12] << 24 | (uint32_t)ctr[13] << 16 | (uint32_t)ctr[14] << 8 | ctr[15]) -
			      ((uint32_t)ctr0[12] << 24 | (uint32_t)ctr0[13] << 16 | (uint32_t)ctr0[14] << 8 | ctr0[15]),
		      (n + 15u) / 16u);
	wri_aesct_wipe(&c);
}

static void test_known_answers(void)
{
	const char *p4 = "6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51"
			 "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710";
	const char *k128 = "2b7e151628aed2a6abf7158809cf4f3c";
	const char *k256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
	const char *ctr = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

	/* FIPS 197 appendix B and C.1, C.3 */
	check_ecb_vec(k128, "3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32");
	check_ecb_vec("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a");
	check_ecb_vec("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff",
		      "8ea2b7ca516745bfeafc49904b496089");
	/* SP 800-38A F.1.1 and F.1.5 (four blocks) */
	check_ecb_vec(k128, p4,
		      "3ad77bb40d7a3660a89ecaf32466ef97" "f5d3d58503b9699de785895a96fdbaaf"
		      "43b1cd7f598ece23881b00e3ed030688" "7b0c785e27e8ad3f8223207104725dd4");
	check_ecb_vec(k256, p4,
		      "f3eed1bdb5d2a03c064b5a7e3db181f8" "591ccb10d410ed26dc5ba74a31362870"
		      "b6ed21b99ca6f4f9f153e7b1beafed1d" "23304b7a39f9f3ff067d8d8f9e24ecc7");
	/* SP 800-38A F.5.1 and F.5.5: the counter never carries out of its last four bytes there, so ctr32 gives the same bytes */
	check_ctr_vec(k128, ctr, p4,
		      "874d6191b620e3261bef6864990db6ce" "9806f66b7970fdff8617187bb9fffdff"
		      "5ae4df3edbd5d35e5b4f09020db03eab" "1e031dda2fbe03d1792170a0f3009cee");
	check_ctr_vec(k256, ctr, p4,
		      "601ec313775789a5b7a7f504bbf3d228" "f443e3ca4d62b59aca84e990cacaf5c5"
		      "2b0930daa23de94ce87017ba2d84988d" "dfc9c58db67aada613c2dd08457941a6");
}

/* ---- the S-box circuit ------------------------------------------------------------------------ */

/* The reference S-box, read out of the reference key schedule: with w0 = 0 and w3 = x x x x, word 4 is SubWord(RotWord(w3)) ^ Rcon. */
static uint8_t ref_sbox(unsigned x)
{
	uint8_t key[16];
	wri_aes_ctx rc;
	uint32_t w4;

	memset(key, 0, sizeof(key));
	memset(key + 12, (int)x, 4);
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&rc, key, 16));
	w4 = rc.rk[4] ^ 0x01000000u;
	WRT_CHECK_U64(w4 & 0xffu, (w4 >> 8) & 0xffu);
	WRT_CHECK_U64(w4 & 0xffu, w4 >> 24);
	return (uint8_t)(w4 & 0xffu);
}

static void test_sbox(void)
{
	uint8_t ref[256], in[32], out[32];
	unsigned base, shift, j, v;

	for (v = 0; v < 256u; v++)
		ref[v] = ref_sbox(v);
	/* the reference itself: a few values every textbook lists, so a broken reference cannot agree with a broken circuit */
	WRT_CHECK_U64(ref[0x00], 0x63);
	WRT_CHECK_U64(ref[0x01], 0x7c);
	WRT_CHECK_U64(ref[0x53], 0xed);
	WRT_CHECK_U64(ref[0xff], 0x16);
	/* every value in every one of the 32 lanes: lane j of call (base, shift) holds value base * 32 + ((j + shift) mod 32) */
	for (base = 0; base < 8u; base++) {
		for (shift = 0; shift < 32u; shift++) {
			for (j = 0; j < 32u; j++)
				in[j] = (uint8_t)(base * 32u + ((j + shift) & 31u));
			wri_aesct_sbox32(in, out);
			for (j = 0; j < 32u; j++) {
				if (out[j] != ref[in[j]]) {
					fprintf(stderr, "sbox lane %u value 0x%02x: got 0x%02x, want 0x%02x\n", j, in[j], out[j],
						ref[in[j]]);
					WRT_CHECK(out[j] == ref[in[j]]);
					return;
				}
			}
			WRT_CHECK(1);
		}
	}
	/* in place */
	for (j = 0; j < 32u; j++)
		in[j] = (uint8_t)(j * 7u + 3u);
	wri_aesct_sbox32(in, out);
	wri_aesct_sbox32(in, in);
	WRT_CHECK_MEM(in, out, 32);
}

/* ---- ECB against the reference ----------------------------------------------------------------- */

#define ECB_CASES 100000u

static void test_ecb_random(void)
{
	unsigned i;
	size_t failures = 0;

	for (i = 0; i < ECB_CASES; i++) {
		static const size_t sizes[2] = {16, 32};
		size_t klen = sizes[rnd() & 1u], nblk = 1u + (i % 9u == 8u ? rnd() % 40u : rnd() % 8u), n = nblk * 16u, b;
		uint8_t key[32];
		uint8_t *in = xmalloc(n), *out = xmalloc(n), *want = xmalloc(n), *ip = xmalloc(n);
		wri_aes_ctx rc;
		wri_aesct_ctx c;

		rnd_fill(key, klen);
		rnd_fill(in, n);
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&rc, key, klen));
		WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, klen));
		for (b = 0; b < nblk; b++)
			wri_aes_enc_block(&rc, in + 16u * b, want + 16u * b);
		wri_aesct_encrypt_blocks(&c, in, out, nblk);
		memcpy(ip, in, n);
		wri_aesct_encrypt_blocks(&c, ip, ip, nblk); /* in place */
		if (memcmp(out, want, n) != 0 || memcmp(ip, want, n) != 0) {
			failures++;
			fprintf(stderr, "ECB case %u (klen %zu, %zu blocks) differs from the reference\n", i, klen, nblk);
		}
		wri_aesct_wipe(&c);
		free(in);
		free(out);
		free(want);
		free(ip);
	}
	WRT_CHECK_U64(failures, 0);
}

/* Block counts 0, 1, 2, 3, 5, 31 and the neighbours of the two-block chunk, nothing written past the end, nothing for 0 blocks. */
static void test_ecb_counts_and_guards(void)
{
	static const size_t counts[] = {0, 1, 2, 3, 4, 5, 6, 7, 15, 16, 17, 31, 32, 33, 1001};
	size_t ci, i;
	uint8_t key[32];
	wri_aes_ctx rc;
	wri_aesct_ctx c;

	for (ci = 0; ci < sizeof(counts) / sizeof(counts[0]); ci++) {
		size_t nblk = counts[ci], n = nblk * 16u, b;
		size_t klen = (ci & 1u) ? 32u : 16u;
		uint8_t *in = xmalloc(n + 32u), *out = xmalloc(n + 32u), *want = xmalloc(n + 32u);

		rnd_fill(key, klen);
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&rc, key, klen));
		WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, klen));
		rnd_fill(in, n + 32u);
		memset(out, 0xcd, n + 32u);
		for (b = 0; b < nblk; b++)
			wri_aes_enc_block(&rc, in + 16u * b, want + 16u * b);
		wri_aesct_encrypt_blocks(&c, in, out, nblk);
		WRT_CHECK_MEM(out, want, n);
		for (i = 0; i < 32u; i++)
			WRT_CHECK(out[n + i] == 0xcdu); /* the guard bytes behind the output are untouched */
		/* unaligned buffers: shift both by one byte */
		memcpy(out + 1, in, n);
		wri_aesct_encrypt_blocks(&c, out + 1, out + 1, nblk);
		WRT_CHECK(memcmp(out + 1, want, n) == 0);
		wri_aesct_wipe(&c);
		free(in);
		free(out);
		free(want);
	}
}

/* ---- ctr32 against the reference ------------------------------------------------------------------ */

static void ctr_case(const wri_aes_ctx *rc, const wri_aesct_ctx *c, size_t klen, const uint8_t *prefix, uint32_t start, size_t n)
{
	uint8_t ctr[16], ctr2[16], ref_c[16];
	uint8_t *in = xmalloc(n), *want = xmalloc(n), *out = xmalloc(n), *ip = xmalloc(n + 8u);
	uint32_t adv = (uint32_t)((n + 15u) / 16u);
	int ok = 1;

	rnd_fill(in, n);
	put_ctr(ctr, prefix, start);
	memcpy(ctr2, ctr, 16);
	ref_ctr32(rc, ctr, in, want, n);
	put_ctr(ref_c, prefix, start + adv); /* wraps modulo 2^32, never into the prefix */

	wri_aesct_ctr32(c, ctr, in, out, n);
	if (n != 0u && memcmp(out, want, n) != 0)
		ok = 0;
	if (memcmp(ctr, ref_c, 16) != 0)
		ok = 0;
	/* in place: and the bytes behind the n are not touched */
	memset(ip, 0xa7, n + 8u);
	memcpy(ip, in, n);
	wri_aesct_ctr32(c, ctr2, ip, ip, n);
	if (n != 0u && memcmp(ip, want, n) != 0)
		ok = 0;
	{
		size_t i;

		for (i = 0; i < 8u; i++)
			if (ip[n + i] != 0xa7u)
				ok = 0;
	}
	if (memcmp(ctr2, ref_c, 16) != 0)
		ok = 0;
	if (!ok) {
		fprintf(stderr, "ctr32 differs: klen %zu start 0x%08x n %zu\n", klen, start, n);
		WRT_CHECK(ok);
	}
	free(in);
	free(want);
	free(out);
	free(ip);
}

static void test_ctr_reference(void)
{
	/* the first four are the wrap; the rest make the +1 carry out of byte 15, 14, 13 and 12 within the block (a counter that carried
	 * into the nonce or counted little-endian differs from the reference there) */
	static const uint32_t starts[] = {0u, 1u, 0xfffffffeu, 0xffffffffu, 0x7fffffffu, 0xfffffff0u, 0x000000f8u, 0x0000fff8u,
					  0x00fffff8u, 0x7ffffff8u, 0x80000000u, 0x0000ffffu, 0x00ffffffu};
	size_t ki, si, n;
	unsigned i;

	for (ki = 0; ki < 2; ki++) {
		size_t klen = ki ? 32u : 16u;
		uint8_t key[32], prefix[12];
		wri_aes_ctx rc;
		wri_aesct_ctx c;

		rnd_fill(key, klen);
		WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&rc, key, klen));
		WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, klen));
		for (si = 0; si < sizeof(starts) / sizeof(starts[0]); si++) {
			for (n = 0; n <= 70u; n++) {
				rnd_fill(prefix, sizeof(prefix));
				ctr_case(&rc, &c, klen, prefix, starts[si], n);
			}
			/* an all-ones prefix: a carry out of the counter would show as a changed byte 11 */
			memset(prefix, 0xff, sizeof(prefix));
			ctr_case(&rc, &c, klen, prefix, starts[si], 64u);
			ctr_case(&rc, &c, klen, prefix, starts[si], 100u);
			ctr_case(&rc, &c, klen, prefix, starts[si], 1000u);
			ctr_case(&rc, &c, klen, prefix, starts[si], 4099u); /* many 32-byte passes of the loop */
		}
		for (i = 0; i < 2000u; i++) {
			rnd_fill(prefix, sizeof(prefix));
			ctr_case(&rc, &c, klen, prefix, rnd(), rnd() % 300u);
		}
		wri_aesct_wipe(&c);
	}
}

/* Wrap without carry, spelled out: counter 0xffffffff, two blocks: the second block uses 00000000 and the nonce bytes stay. */
static void test_ctr_wrap_explicit(void)
{
	uint8_t key[16], ctr[16], in[32], out[32], blk[16], ks0[16], ks1[16];
	wri_aesct_ctx c;
	wri_aes_ctx rc;
	size_t i;

	rnd_fill(key, sizeof(key));
	memset(ctr, 0x55, 12);
	ctr[12] = ctr[13] = ctr[14] = ctr[15] = 0xff;
	memset(in, 0, sizeof(in));
	WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, 16));
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&rc, key, 16));
	wri_aesct_ctr32(&c, ctr, in, out, 32);
	memcpy(blk, ctr, 12);
	memset(blk + 12, 0xff, 4);
	wri_aes_enc_block(&rc, blk, ks0);
	memset(blk + 12, 0, 4);
	wri_aes_enc_block(&rc, blk, ks1);
	WRT_CHECK_MEM(out, ks0, 16);
	WRT_CHECK_MEM(out + 16, ks1, 16);
	for (i = 0; i < 12; i++)
		WRT_CHECK(ctr[i] == 0x55u);
	WRT_CHECK(ctr[12] == 0 && ctr[13] == 0 && ctr[14] == 0 && ctr[15] == 1);
	wri_aesct_wipe(&c);
}

/* One call over a message equals calls over pieces that are multiples of 16 (the way GCM feeds it), counter carried between them. */
static void test_ctr_split(void)
{
	unsigned i;

	for (i = 0; i < 500u; i++) {
		size_t klen = (i & 1u) ? 32u : 16u, n = rnd() % 400u, off = 0;
		uint8_t key[32], ctr[16], ctr2[16], prefix[12];
		uint8_t *in = xmalloc(n), *a = xmalloc(n), *b = xmalloc(n);
		wri_aesct_ctx c;

		rnd_fill(key, klen);
		rnd_fill(in, n);
		rnd_fill(prefix, sizeof(prefix));
		put_ctr(ctr, prefix, rnd() | ((i & 4u) ? 0xfffffff0u : 0u));
		memcpy(ctr2, ctr, 16);
		WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, klen));
		wri_aesct_ctr32(&c, ctr, in, a, n);
		while (off < n) {
			size_t piece = (n - off <= 16u) ? n - off : 16u * (1u + rnd() % 3u);

			if (piece > n - off)
				piece = n - off;
			wri_aesct_ctr32(&c, ctr2, in + off, b + off, piece);
			off += piece;
		}
		WRT_CHECK(n == 0u || memcmp(a, b, n) == 0);
		WRT_CHECK_MEM(ctr, ctr2, 16);
		wri_aesct_wipe(&c);
		free(in);
		free(a);
		free(b);
	}
}

/* ---- failure, wipe, re-keying --------------------------------------------------------------------- */

static void check_zero_context(const wri_aesct_ctx *c, const char *what)
{
	uint8_t in[48], out[48], ctr[16], ctr0[16];
	size_t i;

	memset(in, 0x33, sizeof(in));
	memset(out, 0xee, sizeof(out));
	wri_aesct_encrypt_blocks(c, in, out, 3);
	for (i = 0; i < sizeof(out); i++)
		if (out[i] != 0u) {
			fprintf(stderr, "%s: ECB output byte %zu is 0x%02x, want 0\n", what, i, out[i]);
			WRT_CHECK(out[i] == 0u);
			break;
		}
	memset(out, 0xee, sizeof(out));
	memset(ctr, 0x11, 16);
	memcpy(ctr0, ctr, 16);
	wri_aesct_ctr32(c, ctr, in, out, 40);
	for (i = 0; i < 40u; i++)
		if (out[i] != 0u) {
			fprintf(stderr, "%s: ctr32 output byte %zu is 0x%02x, want 0 (never the plain text)\n", what, i, out[i]);
			WRT_CHECK(out[i] == 0u);
			break;
		}
	WRT_CHECK(out[40] == 0xeeu);
	WRT_CHECK_MEM(ctr, ctr0, 16);
}

static void test_failed_setkey(void)
{
	static const size_t bad[] = {0, 1, 15, 17, 24, 31, 33, 64};
	uint8_t key[64];
	wri_aesct_ctx c;
	size_t i;

	memset(key, 0x42, sizeof(key));
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		/* the context held a good key first: a failed call must not leave it usable */
		WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, 16));
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_aesct_setkey(&c, key, bad[i]));
		WRT_CHECK_U64(c.rounds, 0);
		check_zero_context(&c, "bad key length");
	}
	WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, 32));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_aesct_setkey(&c, NULL, 16));
	WRT_CHECK_U64(c.rounds, 0);
	check_zero_context(&c, "NULL key");
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_aesct_setkey(&c, NULL, 0));
	check_zero_context(&c, "NULL key, length 0");
	WRT_CHECK_STATUS(WR_E_INVAL, wri_aesct_setkey(NULL, key, 16));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_aesct_setkey(NULL, key, 24));
	/* a context that never saw setkey and was zeroed, and one filled with garbage but rounds 0 */
	memset(&c, 0, sizeof(c));
	check_zero_context(&c, "zeroed context");
	memset(&c, 0xff, sizeof(c));
	c.rounds = 0;
	check_zero_context(&c, "garbage schedule, rounds 0");
	memset(&c, 0xff, sizeof(c));
	c.rounds = 12; /* what 24-byte AES would have; refused here */
	check_zero_context(&c, "rounds 12");
	/* NULL arguments never crash */
	{
		uint8_t buf[16] = {0}, ctr[16] = {0};

		wri_aesct_encrypt_blocks(NULL, buf, buf, 1);
		wri_aesct_ctr32(NULL, ctr, buf, buf, 16);
		wri_aesct_encrypt_blocks(&c, NULL, buf, 1);
		wri_aesct_encrypt_blocks(&c, buf, NULL, 1);
		wri_aesct_ctr32(&c, NULL, buf, buf, 16);
		wri_aesct_wipe(NULL);
	}
}

/* A valid key, but a missing buffer: never a crash, never the plain text left in place, never a moved counter. */
static void test_null_args_valid_context(void)
{
	uint8_t key[16], buf[48], out[48], ctr[16], ctr0[16], s32[32];
	wri_aesct_ctx c;
	size_t i;

	memset(key, 0x42, sizeof(key));
	WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, 16));
	memset(ctr, 0x21, sizeof(ctr));
	memcpy(ctr0, ctr, sizeof(ctr));
	/* in == NULL: the output is zeros, not whatever was there */
	memset(out, 0xee, sizeof(out));
	wri_aesct_encrypt_blocks(&c, NULL, out, 3);
	for (i = 0; i < sizeof(out); i++)
		WRT_CHECK(out[i] == 0u);
	memset(out, 0xee, sizeof(out));
	wri_aesct_ctr32(&c, ctr, NULL, out, 40);
	for (i = 0; i < 40u; i++)
		WRT_CHECK(out[i] == 0u);
	WRT_CHECK(out[40] == 0xeeu);
	WRT_CHECK_MEM(ctr, ctr0, 16);
	/* ctr == NULL, in place: the plain text must not survive as "ciphertext" */
	memset(buf, 0x77, sizeof(buf));
	wri_aesct_ctr32(&c, NULL, buf, buf, 33);
	for (i = 0; i < 33u; i++)
		WRT_CHECK(buf[i] == 0u);
	WRT_CHECK(buf[33] == 0x77u);
	/* out == NULL: nothing to write, nothing to crash, the counter stays */
	wri_aesct_encrypt_blocks(&c, buf, NULL, 3);
	wri_aesct_ctr32(&c, ctr, buf, NULL, 40);
	WRT_CHECK_MEM(ctr, ctr0, 16);
	/* zero length: nothing written, counter unchanged */
	memset(out, 0xee, sizeof(out));
	wri_aesct_encrypt_blocks(&c, buf, out, 0);
	wri_aesct_ctr32(&c, ctr, buf, out, 0);
	WRT_CHECK(out[0] == 0xeeu);
	WRT_CHECK_MEM(ctr, ctr0, 16);
	/* the S-box hook: a missing input gives zeros, a missing output is ignored */
	memset(s32, 0xee, sizeof(s32));
	wri_aesct_sbox32(NULL, s32);
	for (i = 0; i < sizeof(s32); i++)
		WRT_CHECK(s32[i] == 0u);
	wri_aesct_sbox32(s32, NULL);
	wri_aesct_wipe(&c);
}

static void test_rekey_and_wipe(void)
{
	uint8_t k128[16], k256[32], blk[16], a[16], b[16], want[16];
	wri_aesct_ctx c;
	wri_aes_ctx rc;
	size_t i;
	const uint8_t *p = (const uint8_t *)&c;

	rnd_fill(k128, sizeof(k128));
	rnd_fill(k256, sizeof(k256));
	rnd_fill(blk, sizeof(blk));
	/* 256 -> 128 -> 256 on the same context: nothing of the earlier schedule is used */
	WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, k256, 32));
	WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, k128, 16));
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&rc, k128, 16));
	wri_aes_enc_block(&rc, blk, want);
	wri_aesct_encrypt_blocks(&c, blk, a, 1);
	WRT_CHECK_MEM(a, want, 16);
	WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, k256, 32));
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&rc, k256, 32));
	wri_aes_enc_block(&rc, blk, want);
	wri_aesct_encrypt_blocks(&c, blk, b, 1);
	WRT_CHECK_MEM(b, want, 16);
	WRT_CHECK(memcmp(a, b, 16) != 0);
	/* the same key twice gives the same context bytes (the schedule holds nothing else) */
	{
		wri_aesct_ctx d;

		memset(&d, 0x5a, sizeof(d));
		WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&d, k256, 32));
		WRT_CHECK(memcmp(&c, &d, sizeof(c)) == 0);
	}
	/* wipe: every byte of the context is zero, and the context then encrypts to zeros */
	wri_aesct_wipe(&c);
	for (i = 0; i < sizeof(c); i++)
		if (p[i] != 0u) {
			fprintf(stderr, "context byte %zu is 0x%02x after wipe\n", i, p[i]);
			WRT_CHECK(p[i] == 0u);
			break;
		}
	WRT_CHECK_U64(c.rounds, 0);
	check_zero_context(&c, "wiped");
	/* a failed setkey also leaves the schedule empty */
	WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, k128, 16));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_aesct_setkey(&c, k128, 17));
	for (i = 0; i < sizeof(c); i++)
		if (p[i] != 0u) {
			WRT_CHECK(p[i] == 0u);
			break;
		}
}

/* ---- stack ------------------------------------------------------------------------------------------ */

#if defined(__GNUC__) || defined(__clang__)
#define WRT_NOINLINE __attribute__((noinline))
#else
#define WRT_NOINLINE
#endif

#if defined(__SANITIZE_ADDRESS__)
#define STACK_PROBE_OK 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer)
#define STACK_PROBE_OK 0
#endif
#endif
#ifndef STACK_PROBE_OK
#if defined(__GNUC__) || defined(__clang__)
#define STACK_PROBE_OK 1
#else
#define STACK_PROBE_OK 0
#endif
#endif

#if STACK_PROBE_OK
#define PROBE_BYTES 8192u

static wri_aesct_ctx probe_ctx;
static uint8_t probe_in[96], probe_out[96], probe_cb[16];
static volatile uint8_t probe_sink;

static void probe_noop(void) {}
static void probe_ecb1(void) { wri_aesct_encrypt_blocks(&probe_ctx, probe_in, probe_out, 1); }
static void probe_ecb5(void) { wri_aesct_encrypt_blocks(&probe_ctx, probe_in, probe_out, 5); }
static void probe_ctr(void) { wri_aesct_ctr32(&probe_ctx, probe_cb, probe_in, probe_out, 77); }
static void probe_setkey(void) { WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&probe_ctx, probe_in, 32)); }

static WRT_NOINLINE void stack_paint(void)
{
	volatile uint8_t b[PROBE_BYTES];
	size_t i;

	for (i = 0; i < PROBE_BYTES; i++)
		b[i] = 0xa5u;
	probe_sink = b[0];
}

/* Reading the unwritten part of the frame is the point of the probe, not a mistake. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
/* the same frame shape as stack_paint: the lowest address that no longer holds the paint is the deepest byte anything wrote */
static WRT_NOINLINE size_t stack_depth(void)
{
	volatile uint8_t b[PROBE_BYTES];
	size_t i;

	for (i = 128; i < PROBE_BYTES; i++) /* the lowest bytes may sit below the painted frame of the other function */
		if (b[i] != 0xa5u)
			return PROBE_BYTES - i;
	return 0;
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

static WRT_NOINLINE size_t stack_probe(void (*volatile fn)(void))
{
	stack_paint();
	fn();
	return stack_depth();
}

static void test_stack(void)
{
	size_t base, ecb1, ecb5, ctr, setk;
	size_t limit_block, limit_ctr;

	memset(probe_in, 0x61, sizeof(probe_in));
	memset(probe_cb, 0x07, sizeof(probe_cb));
	WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&probe_ctx, probe_in, 32));
	base = stack_probe(probe_noop);
	ecb1 = stack_probe(probe_ecb1);
	ecb5 = stack_probe(probe_ecb5);
	ctr = stack_probe(probe_ctr);
	setk = stack_probe(probe_setkey);
	ecb1 = ecb1 > base ? ecb1 - base : 0;
	ecb5 = ecb5 > base ? ecb5 - base : 0;
	ctr = ctr > base ? ctr - base : 0;
	setk = setk > base ? setk - base : 0;
	printf("stack (bytes beyond the caller): encrypt_blocks 1 block %zu, 5 blocks %zu, ctr32 %zu, setkey %zu\n", ecb1, ecb5, ctr,
	       setk);
#if defined(__OPTIMIZE__)
	limit_block = 256u; /* design 35.1: under 256 bytes in an optimised build */
	limit_ctr = 384u;
#else
	limit_block = 2048u; /* -O0 gives every temporary of the circuit its own slot; the 256 byte rule is for optimised builds */
	limit_ctr = 2560u;
#endif
	WRT_CHECK(ecb1 < limit_block);
	WRT_CHECK(ecb5 < limit_block);
	WRT_CHECK(ctr < limit_ctr);
	WRT_CHECK(setk < 2u * limit_ctr);
	WRT_CHECK(ecb1 != 0u); /* the probe saw the call: a zero would mean the measurement is broken */
}
#else
static void test_stack(void)
{
	fprintf(stderr, "note: stack measurement skipped (sanitizer or compiler without the needed behaviour)\n");
}
#endif

int main(void)
{
	test_known_answers();
	test_sbox();
	test_ecb_counts_and_guards();
	test_ecb_random();
	test_ctr_reference();
	test_ctr_wrap_explicit();
	test_ctr_split();
	test_failed_setkey();
	test_null_args_valid_context();
	test_rekey_and_wipe();
	test_stack();
	return wrt_finish();
}
