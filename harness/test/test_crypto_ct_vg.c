/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_ct_vg - the Valgrind constant-time check of design 35.6 (module ct-check).
 *
 * The technique (known as ctgrind): the key, the IV, the additional data and the data are marked UNDEFINED with the Valgrind client
 * requests, the code under test runs, and Memcheck reports every conditional jump, address computation or system call argument that
 * depends on an undefined bit. Code that is constant time in the sense of wri_aesct.h / wri_ghash.h / wri_gcm.h produces no report; a
 * table lookup indexed by a key byte or a branch on a data byte produces one. The outputs that are public BY DESIGN are declassified
 * (marked defined) before the test looks at them: the ciphertext, the tag, and the answer of a tag comparison (the status that
 * wri_gcm_final_dec / wri_pgcm_final_dec return). For the cipher and hash primitives the output block is declassified only so the
 * result can be compared with the independent reference of harness/test/support/ref_gcm.c; nothing else is ever declassified, and
 * every status that must not depend on a secret (setkey, start, update, final_enc) is checked while still unmarked, so a status that
 * leaks would be reported at the check itself.
 *
 * What runs under the marks ("groups", each one is named in the Valgrind log as CT-OK <name> when it produced no report):
 *   aesct-blocks   wri_aesct_setkey (AES-128 and AES-256) and wri_aesct_encrypt_blocks, 1 to 16 blocks
 *   aesct-ctr      wri_aesct_ctr32 at lengths 1 to 1000 (partial blocks, a counter that wraps), counter block undefined
 *   aesct-sbox     the S-box circuit on 32 undefined bytes
 *   ghash          wri_ghash_init / blocks / get with H and the data undefined, one call and split calls, reset and reuse
 *   gcm-seal       wri_gcm seal at 23 data lengths x 4 additional-data lengths x both key sizes, one call / random pieces, in place or not
 *   gcm-open       the same messages opened (the tag comparison result declassified), and the plaintext equal to the original
 *   gcm-reject     a flipped tag bit, ciphertext bit or additional-data bit gives WR_E_CRYPTO_MAC (the answer declassified)
 *   pgcm           the dispatcher wri_pgcm (portable path) seal / open / reject on multiples of 16 bytes
 *   m2s-init       wri_m2s_init: the connection secret's key bytes undefined, key and nonce derivation, then one sealed and opened block
 *                  through the two directions. The nonce seeds are left defined: GCM does not need a nonce to be secret, and init has
 *                  to compare the two seeds (equal seeds are WR_E_M2_SECRET), which no code can do without a decision on them. While
 *                  the module is still the skeleton (WR_E_UNSUPPORTED) the group reports "skeleton" and checks nothing. The sealed block is
 *                  also compared with the independent reference at the offsets of msgr2-secure-mode.md 2.6 (key S[0..15], client sends
 *                  with S[28..39], receives with S[16..27]), so a swapped seed that still round-trips through the code itself fails.
 *   m2s-seal       a whole secure frame sealed through wri_m2_tx_frame (key bytes and every segment byte undefined; 1 to 4 segments, with
 *                  and without a second and a third part; the bounce-buffer stream drained piecewise), the wire declassified and taken
 *                  apart with the reference: preamble fields, inline bytes, padding, epilogue, the tags, the nonce of each part in order;
 *                  the slot and the bounce buffer zero after wri_m2_secure_off. While the transmit side is still the skeleton the group
 *                  says so (CT-NOTE) and the driver prints a note; every other group must run at least one case.
 * Every wipe (aesct, ghash, gcm, pgcm, m2s) is also checked to leave all bytes zero.
 *
 * The control (--run=control): the same marking and the same harness around the table-driven wri_aes_setkey / wri_aes_enc_block (cephx
 * CBC uses them; they index S-box tables by key and state bytes) and around a compare that returns at the first differing byte. Memcheck
 * MUST report all three, otherwise the whole check proves nothing, and the driver demands exactly that (exit code 99 and the three
 * CT-CONTROL-OK lines in the log).
 *
 * How it is used. ctest "crypto.ct.valgrind" runs this binary with --drive: the driver finds Valgrind (WRT_VALGRIND or PATH), runs
 * the binary under "valgrind --error-exitcode=99" first in the normal mode (must exit 0, "ERROR SUMMARY: 0 errors", every group
 * CT-OK) and then in control mode (must exit 99 with the three controls reported). It skips (77) with the reason where Valgrind or
 * its header is missing (unless WRT_CT_REQUIRE is set in the environment: then that is a failure, so CI notices a runner image that lost
 * the package), or when the binary carries a sanitizer that Valgrind cannot run. ctest "crypto.ct.vg" (no arguments) runs the
 * same checks in process, the client requests being no-ops outside Valgrind: functional results against the reference, and, in the
 * sanitizer flavours, the memory safety of the harness around them. The file also works by hand:
 *     valgrind --error-exitcode=99 ./test_crypto_ct_vg
 * Nothing here measures time.
 */
#define _POSIX_C_SOURCE 200809L

#include "wrt.h"

#include "ref_gcm.h"
#include "wri_aes.h"
#include "wri_aesct.h"
#include "wri_gcm.h"
#include "wri_ghash.h"
#include "wri_m2_sec.h"
#include "wri_pgcm.h"

#if defined(WRT_HAVE_VALGRIND_H)
#include <valgrind/memcheck.h>
#define CT_HAVE_VG 1
#else
#define CT_HAVE_VG 0
#endif

#if defined(__unix__) || defined(__unix) || defined(__APPLE__)
#define CT_HAVE_POSIX 1
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#else
#define CT_HAVE_POSIX 0
#endif

/* ---- the Valgrind seam -------------------------------------------------------------------------- */

#if CT_HAVE_VG
#define SECRET(p, n) ((void)VALGRIND_MAKE_MEM_UNDEFINED((p), (n)))
#define PUBLIC(p, n) ((void)VALGRIND_MAKE_MEM_DEFINED((p), (n)))
#define VG_ERRORS() ((unsigned long)VALGRIND_COUNT_ERRORS)
#define UNDER_VG() (RUNNING_ON_VALGRIND != 0)
#else
#define SECRET(p, n) ((void)(p), (void)(n))
#define PUBLIC(p, n) ((void)(p), (void)(n))
#define VG_ERRORS() 0ul
#define UNDER_VG() 0
#endif

/*
 * A skip that CI can turn into a failure: with WRT_CT_REQUIRE set in the environment (the CI jobs set it) a missing Valgrind or header
 * is an error, so the check cannot vanish unnoticed from a runner image that lost the package. Without it the test skips (77) as before.
 */
static void skip_or_fail(const char *reason)
{
	const char *req = getenv("WRT_CT_REQUIRE");

	if (req != NULL && req[0] != '\0' && strcmp(req, "0") != 0) {
		fprintf(stderr, "FAIL: %s (WRT_CT_REQUIRE is set, a skip is not allowed)\n", reason);
		exit(1);
	}
	WRT_SKIP(reason);
}

/* One line of output: into the Valgrind log when running under it (the driver reads that file), else on stdout. */
static void note(const char *line)
{
#if CT_HAVE_VG
	if (UNDER_VG()) {
		VALGRIND_PRINTF("%s\n", line);
		return;
	}
#endif
	printf("%s\n", line);
	fflush(stdout);
}

/* ---- helpers ------------------------------------------------------------------------------------ */

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;

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

/* 1 when all n bytes are zero (the wipe checks; the object is public by then, so the loop is no leak). */
static int all_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	uint8_t acc = 0;
	size_t i;

	for (i = 0; i < n; i++)
		acc = (uint8_t)(acc | b[i]);
	return acc == 0;
}

/* The Memcheck error count at the last case check (every group shares it: the gcm groups interleave). */
static unsigned long g_last_errors;

/* A group: how many cases ran, how many reported anything. */
typedef struct group {
	const char *name;
	unsigned cases;
	unsigned reported; /* cases that produced a Memcheck report */
} group;

static void group_begin(group *g, const char *name)
{
	g->name = name;
	g->cases = g->reported = 0;
	g_last_errors = VG_ERRORS();
}

/* Call right after the calls of a case: a case that produced a report is a failure of the test, named with its parameters. */
static void group_case(group *g, const char *what, unsigned long a, unsigned long b, unsigned long c)
{
	const unsigned long now = VG_ERRORS();

	g->cases++;
	if (now != g_last_errors) {
		g->reported++;
		wrt_checks++;
		wrt_failures++;
		if (g->reported <= 8)
			fprintf(stderr, "%s: Memcheck reported %lu error(s) in %s (%lu, %lu, %lu): the code branches on or indexes by a secret\n",
				g->name, now - g_last_errors, what, a, b, c);
		g_last_errors = now;
	}
}

static void group_end(const group *g)
{
	char line[160];

	snprintf(line, sizeof(line), "%s %s cases=%u reported=%u", g->reported == 0 ? "CT-OK" : "CT-BAD", g->name, g->cases, g->reported);
	note(line);
}

/* ---- aesct ---------------------------------------------------------------------------------------- */

static void grp_aesct_blocks(void)
{
	static const size_t klens[2] = {16, 32};
	static const size_t nbs[] = {1, 2, 3, 4, 5, 8, 9, 16};
	group g;
	size_t ki, ni, i;

	group_begin(&g, "aesct-blocks");
	for (ki = 0; ki < 2; ki++) {
		const size_t klen = klens[ki];
		uint8_t key_pub[32], key[32];
		ref_aes ra;
		wri_aesct_ctx c;

		rnd_fill(key_pub, sizeof(key_pub));
		WRT_CHECK(ref_aes_init(&ra, key_pub, klen) == 0);
		memcpy(key, key_pub, sizeof(key));
		memset(&c, 0, sizeof(c));
		SECRET(key, klen);
		WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, klen));
		group_case(&g, "setkey", klen, 0, 0);

		for (ni = 0; ni < sizeof(nbs) / sizeof(nbs[0]); ni++) {
			const size_t nb = nbs[ni];
			uint8_t in_pub[16 * 16], in[16 * 16], out[16 * 16], exp[16 * 16];

			rnd_fill(in_pub, sizeof(in_pub));
			memcpy(in, in_pub, sizeof(in));
			memset(out, 0xee, sizeof(out));
			for (i = 0; i < nb; i++)
				ref_aes_encrypt_block(&ra, in_pub + 16 * i, exp + 16 * i);
			SECRET(in, 16 * nb);
			wri_aesct_encrypt_blocks(&c, in, out, nb);
			group_case(&g, "encrypt_blocks", klen, nb, 0);
			PUBLIC(out, 16 * nb);
			WRT_CHECK_MEM(out, exp, 16 * nb);

			/* in place */
			SECRET(in, 16 * nb);
			wri_aesct_encrypt_blocks(&c, in, in, nb);
			group_case(&g, "encrypt_blocks in place", klen, nb, 0);
			PUBLIC(in, 16 * nb);
			WRT_CHECK_MEM(in, exp, 16 * nb);
		}
		wri_aesct_wipe(&c);
		PUBLIC(&c, sizeof(c));
		WRT_CHECK(all_zero(&c, sizeof(c))); /* the schedule is gone */
	}
	group_end(&g);
}

static void grp_aesct_ctr(void)
{
	static const size_t klens[2] = {16, 32};
	static const size_t lens[] = {1, 15, 16, 17, 31, 32, 33, 64, 100, 255, 1000};
	group g;
	size_t ki, li;

	group_begin(&g, "aesct-ctr");
	for (ki = 0; ki < 2; ki++) {
		const size_t klen = klens[ki];
		uint8_t key_pub[32], key[32];
		ref_aes ra;
		wri_aesct_ctx c;

		rnd_fill(key_pub, sizeof(key_pub));
		WRT_CHECK(ref_aes_init(&ra, key_pub, klen) == 0);
		memcpy(key, key_pub, sizeof(key));
		memset(&c, 0, sizeof(c));
		SECRET(key, klen);
		WRT_CHECK_STATUS(WR_OK, wri_aesct_setkey(&c, key, klen));

		for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
			const size_t n = lens[li];
			int wrap;

			for (wrap = 0; wrap < 2; wrap++) {
				uint8_t in_pub[1000], in[1000], out[1000], exp[1000];
				uint8_t ctr_pub[16], ctr[16], ctr_exp[16];
				size_t off, blocks;

				rnd_fill(in_pub, sizeof(in_pub));
				rnd_fill(ctr_pub, sizeof(ctr_pub));
				if (wrap) {
					/* the 32-bit counter starts two blocks before its wrap: the increment must be arithmetic, not a branch */
					ctr_pub[12] = 0xff;
					ctr_pub[13] = 0xff;
					ctr_pub[14] = 0xff;
					ctr_pub[15] = 0xfe;
				}
				memcpy(ctr_exp, ctr_pub, 16);
				blocks = (n + 15) / 16;
				for (off = 0; off < n; off += 16) {
					uint8_t ks[16];
					size_t j, take = (n - off < 16) ? n - off : 16;
					uint32_t v;

					ref_aes_encrypt_block(&ra, ctr_exp, ks);
					for (j = 0; j < take; j++)
						exp[off + j] = (uint8_t)(in_pub[off + j] ^ ks[j]);
					v = ((uint32_t)ctr_exp[12] << 24) | ((uint32_t)ctr_exp[13] << 16) | ((uint32_t)ctr_exp[14] << 8) | ctr_exp[15];
					v += 1u;
					ctr_exp[12] = (uint8_t)(v >> 24);
					ctr_exp[13] = (uint8_t)(v >> 16);
					ctr_exp[14] = (uint8_t)(v >> 8);
					ctr_exp[15] = (uint8_t)v;
				}
				(void)blocks;
				memcpy(in, in_pub, sizeof(in));
				memcpy(ctr, ctr_pub, 16);
				memset(out, 0xee, sizeof(out));
				SECRET(in, n);
				SECRET(ctr, 16);
				wri_aesct_ctr32(&c, ctr, in, out, n);
				group_case(&g, "ctr32", klen, n, (unsigned long)wrap);
				PUBLIC(out, n);
				PUBLIC(ctr, 16);
				WRT_CHECK_MEM(out, exp, n);
				WRT_CHECK_MEM(ctr, ctr_exp, 16);
			}
		}
		wri_aesct_wipe(&c);
	}
	group_end(&g);
}

static void grp_aesct_sbox(void)
{
	group g;
	ref_aes ra;
	uint8_t key[16];
	unsigned round;
	size_t i;

	group_begin(&g, "aesct-sbox");
	rnd_fill(key, sizeof(key));
	WRT_CHECK(ref_aes_init(&ra, key, 16) == 0);
	for (round = 0; round < 16; round++) {
		uint8_t in_pub[32], in[32], out[32], exp[32];

		for (i = 0; i < 32; i++)
			in_pub[i] = (uint8_t)(round * 32u + i); /* rounds 0..7 cover all 256 values, 8..15 repeat them in another lane */
		if (round >= 8)
			rnd_fill(in_pub, sizeof(in_pub));
		for (i = 0; i < 32; i++)
			exp[i] = ra.sbox[in_pub[i]];
		memcpy(in, in_pub, sizeof(in));
		memset(out, 0xee, sizeof(out));
		SECRET(in, 32);
		wri_aesct_sbox32(in, out);
		group_case(&g, "sbox32", round, 0, 0);
		PUBLIC(out, 32);
		WRT_CHECK_MEM(out, exp, 32);
	}
	group_end(&g);
}

/* ---- ghash ---------------------------------------------------------------------------------------- */

/* Y = fold over the blocks of ((Y ^ X) * H), the reference's way (no length block: wri_ghash_get is the bare running value). */
static void ref_fold(const uint8_t h[16], const uint8_t *p, size_t nblocks, uint8_t y[16])
{
	size_t i, j;

	memset(y, 0, 16);
	for (i = 0; i < nblocks; i++) {
		uint8_t t[16];

		for (j = 0; j < 16; j++)
			t[j] = (uint8_t)(y[j] ^ p[16 * i + j]);
		ref_gf128_mul(t, h, y);
	}
}

static void grp_ghash(void)
{
	static const size_t nbs[] = {1, 2, 3, 4, 5, 8, 13};
	group g;
	size_t ni;

	group_begin(&g, "ghash");
	for (ni = 0; ni < sizeof(nbs) / sizeof(nbs[0]); ni++) {
		const size_t nb = nbs[ni];
		int split;

		for (split = 0; split < 3; split++) {
			uint8_t h_pub[16], h[16], d_pub[16 * 13], d[16 * 13], out[16], exp[16];
			wri_ghash gh;
			size_t first;

			rnd_fill(h_pub, 16);
			rnd_fill(d_pub, sizeof(d_pub));
			ref_fold(h_pub, d_pub, nb, exp);
			memcpy(h, h_pub, 16);
			memcpy(d, d_pub, sizeof(d));
			memset(&gh, 0, sizeof(gh));
			SECRET(h, 16);
			SECRET(d, 16 * nb);
			wri_ghash_init(&gh, h);
			first = (split == 0) ? nb : (split == 1 ? 1 : nb / 2);
			if (first > nb)
				first = nb;
			wri_ghash_blocks(&gh, d, first);
			if (nb > first)
				wri_ghash_blocks(&gh, d + 16 * first, nb - first);
			wri_ghash_get(&gh, out);
			group_case(&g, "ghash", nb, (unsigned long)split, 0);
			PUBLIC(out, 16);
			WRT_CHECK_MEM(out, exp, 16);

			/* reset keeps H: the same data again gives the same value */
			wri_ghash_reset(&gh);
			wri_ghash_blocks(&gh, d, nb);
			wri_ghash_get(&gh, out);
			group_case(&g, "ghash after reset", nb, (unsigned long)split, 0);
			PUBLIC(out, 16);
			WRT_CHECK_MEM(out, exp, 16);
			wri_ghash_wipe(&gh);
			PUBLIC(&gh, sizeof(gh));
			WRT_CHECK(all_zero(&gh, sizeof(gh))); /* H and the running value are gone */
		}
	}
	group_end(&g);
}

/* ---- gcm -------------------------------------------------------------------------------------------- */

#define MAXLEN 4096u
#define MAXAAD 64u

/* Feed n bytes through wri_gcm_update in one call (split 0) or in random pieces of 1 to 40 bytes (split 1). */
static wr_status gcm_feed(wri_gcm *g, const uint8_t *in, uint8_t *out, size_t n, int split)
{
	size_t off = 0;
	wr_status st;

	if (!split)
		return wri_gcm_update(g, in, out, n);
	while (off < n) {
		size_t take = 1u + (size_t)(rnd() % 40u);

		if (take > n - off)
			take = n - off;
		st = wri_gcm_update(g, in + off, out + off, take);
		if (st != WR_OK)
			return st;
		off += take;
	}
	return WR_OK;
}

static wr_status gcm_feed_aad(wri_gcm *g, const uint8_t *aad, size_t n, int split)
{
	size_t off = 0;
	wr_status st;

	if (!split)
		return wri_gcm_aad(g, aad, n);
	while (off < n) {
		size_t take = 1u + (size_t)(rnd() % 7u);

		if (take > n - off)
			take = n - off;
		st = wri_gcm_aad(g, aad + off, take);
		if (st != WR_OK)
			return st;
		off += take;
	}
	return WR_OK;
}

/* Run one decrypt operation over (aad, ct) and return the status of the tag comparison with the comparison result declassified. */
static wr_status gcm_open_once(wri_gcm *g, const uint8_t *iv, const uint8_t *aad, size_t alen, const uint8_t *ct, uint8_t *pt, size_t n,
			       const uint8_t tag[16], int split, int inplace)
{
	wr_status st, fin;

	st = wri_gcm_start(g, iv, WRI_GCM_IV_LEN, 1);
	WRT_CHECK_STATUS(WR_OK, st);
	st = gcm_feed_aad(g, aad, alen, split);
	WRT_CHECK_STATUS(WR_OK, st);
	if (inplace) {
		memcpy(pt, ct, n);
		st = gcm_feed(g, pt, pt, n, split);
	} else {
		st = gcm_feed(g, ct, pt, n, split);
	}
	WRT_CHECK_STATUS(WR_OK, st);
	fin = wri_gcm_final_dec(g, tag);
	PUBLIC(&fin, sizeof(fin)); /* the one decision that is public by design: the tag matched or not */
	return fin;
}

static void gcm_one(group *gs, group *go, group *gr, size_t klen, size_t plen, size_t alen, unsigned idx)
{
	const int split = (int)(idx & 1u), inplace = (int)((idx >> 1) & 1u);
	uint8_t key_pub[32], iv_pub[12], aad_pub[MAXAAD], pt_pub[MAXLEN];
	uint8_t key[32], iv[12], aad[MAXAAD], pt[MAXLEN], ct[MAXLEN], ct_exp[MAXLEN], tag[16], tag_exp[16];
	uint8_t pt2[MAXLEN], ct_bad[MAXLEN], tag_bad[16], aad_bad[MAXAAD];
	wri_gcm g;
	wr_status st;

	rnd_fill(key_pub, sizeof(key_pub));
	rnd_fill(iv_pub, sizeof(iv_pub));
	rnd_fill(aad_pub, sizeof(aad_pub));
	rnd_fill(pt_pub, plen);
	WRT_CHECK(ref_gcm_seal(key_pub, klen, iv_pub, 12, aad_pub, alen, pt_pub, plen, ct_exp, tag_exp) == 0);

	memcpy(key, key_pub, sizeof(key));
	memcpy(iv, iv_pub, sizeof(iv));
	memcpy(aad, aad_pub, sizeof(aad));
	memcpy(pt, pt_pub, plen);
	memset(ct, 0xee, sizeof(ct));
	memset(tag, 0xee, sizeof(tag));
	memset(&g, 0, sizeof(g));
	SECRET(key, klen);
	SECRET(iv, sizeof(iv));
	SECRET(aad, alen);
	SECRET(pt, plen);

	/* seal */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, klen));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, WRI_GCM_IV_LEN, 0));
	WRT_CHECK_STATUS(WR_OK, gcm_feed_aad(&g, aad, alen, split));
	if (inplace) {
		memcpy(ct, pt, plen); /* the copy keeps the "undefined" bits of the plaintext */
		st = gcm_feed(&g, ct, ct, plen, split);
	} else {
		st = gcm_feed(&g, pt, ct, plen, split);
	}
	WRT_CHECK_STATUS(WR_OK, st);
	WRT_CHECK_STATUS(WR_OK, wri_gcm_final_enc(&g, tag));
	group_case(gs, "seal", klen, plen, alen);
	PUBLIC(ct, plen);
	PUBLIC(tag, sizeof(tag));
	WRT_CHECK_MEM(ct, ct_exp, plen);
	WRT_CHECK_MEM(tag, tag_exp, 16);

	/* open (the key stays undefined: only the ciphertext and the tag are public now) */
	memset(pt2, 0xee, sizeof(pt2));
	st = gcm_open_once(&g, iv, aad, alen, ct, pt2, plen, tag, split, inplace);
	WRT_CHECK_STATUS(WR_OK, st);
	group_case(go, "open", klen, plen, alen);
	PUBLIC(pt2, plen);
	WRT_CHECK_MEM(pt2, pt_pub, plen);

	/* reject: one flipped bit anywhere in the tag, the ciphertext or the additional data */
	if (plen <= 65u) {
		memcpy(tag_bad, tag, sizeof(tag_bad));
		tag_bad[idx % 16u] = (uint8_t)(tag_bad[idx % 16u] ^ (1u << (idx % 8u)));
		memset(pt2, 0xee, sizeof(pt2));
		st = gcm_open_once(&g, iv, aad, alen, ct, pt2, plen, tag_bad, split, inplace);
		WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, st);
		group_case(gr, "tag bit", klen, plen, alen);
		if (plen > 0) {
			memcpy(ct_bad, ct, plen);
			ct_bad[idx % plen] = (uint8_t)(ct_bad[idx % plen] ^ (1u << ((idx >> 3) % 8u)));
			memset(pt2, 0xee, sizeof(pt2));
			st = gcm_open_once(&g, iv, aad, alen, ct_bad, pt2, plen, tag, split, inplace);
			WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, st);
			group_case(gr, "ciphertext bit", klen, plen, alen);
		}
		if (alen > 0) {
			memcpy(aad_bad, aad, alen);
			aad_bad[idx % alen] = (uint8_t)(aad_bad[idx % alen] ^ 0x80u);
			memset(pt2, 0xee, sizeof(pt2));
			st = gcm_open_once(&g, iv, aad_bad, alen, ct, pt2, plen, tag, split, inplace);
			WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, st);
			group_case(gr, "aad bit", klen, plen, alen);
		}
	}
	wri_gcm_wipe(&g);
	PUBLIC(&g, sizeof(g));
	WRT_CHECK(all_zero(&g, sizeof(g))); /* key schedule, H, counter, tag mask and staging are gone */
}

static void grp_gcm(void)
{
	static const size_t klens[2] = {16, 32};
	static const size_t plens[] = {0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 1000, 1500, 4096};
	static const size_t alens[] = {0, 13, 16, 33};
	group gs, go, gr;
	size_t ki, pi, ai;
	unsigned idx = 0;

	group_begin(&gs, "gcm-seal");
	group_begin(&go, "gcm-open");
	group_begin(&gr, "gcm-reject");
	for (ki = 0; ki < 2; ki++)
		for (pi = 0; pi < sizeof(plens) / sizeof(plens[0]); pi++)
			for (ai = 0; ai < sizeof(alens) / sizeof(alens[0]); ai++)
				gcm_one(&gs, &go, &gr, klens[ki], plens[pi], alens[ai], idx++);
	group_end(&gs);
	group_end(&go);
	group_end(&gr);
}

/* ---- pgcm (the dispatcher, portable path) ---------------------------------------------------------- */

static void pgcm_one(group *g, size_t n, unsigned idx)
{
	uint8_t key_pub[16], iv_pub[12], pt_pub[1024], key[16], iv[12], pt[1024], ct[1024], tag[16], ct_exp[1024], tag_exp[16], pt2[1024], tag_bad[16];
	wri_pgcm p;
	wr_status st;

	rnd_fill(key_pub, sizeof(key_pub));
	rnd_fill(iv_pub, sizeof(iv_pub));
	rnd_fill(pt_pub, sizeof(pt_pub));
	WRT_CHECK(ref_gcm_seal(key_pub, 16, iv_pub, 12, NULL, 0, pt_pub, n, ct_exp, tag_exp) == 0);
	memcpy(key, key_pub, sizeof(key));
	memcpy(iv, iv_pub, sizeof(iv));
	memcpy(pt, pt_pub, sizeof(pt));
	memset(ct, 0xee, sizeof(ct));
	memset(tag, 0xee, sizeof(tag));
	memset(&p, 0, sizeof(p));
	SECRET(key, sizeof(key));
	SECRET(iv, sizeof(iv));
	SECRET(pt, n);

	WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(&p, NULL, key));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&p, iv, 0));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&p, pt, ct, n));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_final_enc(&p, tag));
	group_case(g, "seal", n, 0, 0);
	PUBLIC(ct, n);
	PUBLIC(tag, sizeof(tag));
	WRT_CHECK_MEM(ct, ct_exp, n);
	WRT_CHECK_MEM(tag, tag_exp, 16);

	memset(pt2, 0xee, sizeof(pt2));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&p, iv, 1));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&p, ct, pt2, n));
	st = wri_pgcm_final_dec(&p, tag);
	PUBLIC(&st, sizeof(st));
	WRT_CHECK_STATUS(WR_OK, st);
	group_case(g, "open", n, 0, 0);
	PUBLIC(pt2, n);
	WRT_CHECK_MEM(pt2, pt_pub, n);

	memcpy(tag_bad, tag, sizeof(tag_bad));
	tag_bad[idx % 16u] = (uint8_t)(tag_bad[idx % 16u] ^ 0x01u);
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&p, iv, 1));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&p, ct, pt2, n));
	st = wri_pgcm_final_dec(&p, tag_bad);
	PUBLIC(&st, sizeof(st));
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, st);
	group_case(g, "reject", n, 0, 0);
	wri_pgcm_wipe(&p);
	PUBLIC(&p, sizeof(p));
	WRT_CHECK(all_zero(&p, sizeof(p)));
}

static void grp_pgcm(void)
{
	static const size_t ns[] = {0, 16, 32, 48, 64, 256, 1024};
	group g;
	size_t i;

	group_begin(&g, "pgcm");
	for (i = 0; i < sizeof(ns) / sizeof(ns[0]); i++)
		pgcm_one(&g, ns[i], (unsigned)i);
	group_end(&g);
}

/* ---- wri_m2s_init (key and nonce derivation of a secure connection) -------------------------------- */

static void grp_m2s(void)
{
	group g;
	uint8_t secret_pub[64], secret[64], pt_pub[32], pt[32], ct[32], pt2[32], tag[16], tag_bad[16];
	wri_m2s tx_side, rx_side; /* the client's view and the server's view (crossed) of the same secret */
	wr_status st1, st2, st;
	uint8_t iv_tx[WRI_M2S_NONCE_LEN], iv_rx[WRI_M2S_NONCE_LEN];

	group_begin(&g, "m2s-init");
	rnd_fill(secret_pub, sizeof(secret_pub));
	rnd_fill(pt_pub, sizeof(pt_pub));
	memcpy(secret, secret_pub, sizeof(secret));
	memcpy(pt, pt_pub, sizeof(pt));
	memset(&tx_side, 0, sizeof(tx_side));
	memset(&rx_side, 0, sizeof(rx_side));
	SECRET(secret, WRI_M2S_KEY_LEN); /* the key bytes; the nonce seeds stay defined (see the header comment) */
	SECRET(pt, sizeof(pt));
	st1 = wri_m2s_init(&tx_side, NULL, secret, sizeof(secret), 0);
	st2 = wri_m2s_init(&rx_side, NULL, secret, sizeof(secret), 1);
	group_case(&g, "init", 0, 0, 0);
	if (st1 == WR_E_UNSUPPORTED && st2 == WR_E_UNSUPPORTED) {
		note("CT-NOTE m2s-init skeleton (WR_E_UNSUPPORTED): derivation not checked yet");
		group_end(&g);
		return;
	}
	WRT_CHECK_STATUS(WR_OK, st1);
	WRT_CHECK_STATUS(WR_OK, st2);
	if (st1 == WR_OK && st2 == WR_OK) {
		/* what the client sends the server must open, under the key and nonce each side derived */
		memcpy(iv_tx, tx_side.tx_n.cur, sizeof(iv_tx));
		memcpy(iv_rx, rx_side.rx_n.cur, sizeof(iv_rx));
		WRT_CHECK_MEM(iv_tx, iv_rx, sizeof(iv_tx));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&tx_side.tx, iv_tx, 0));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&tx_side.tx, pt, ct, sizeof(pt)));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_final_enc(&tx_side.tx, tag));
		group_case(&g, "seal", 0, 0, 0);
		PUBLIC(ct, sizeof(ct));
		PUBLIC(tag, sizeof(tag));
		/* The offsets of docs/spec/msgr2-secure-mode.md 2.6, from the independent reference and not from the derivation under test:
		 * the key is S[0..15]; the client sends with the nonce seeded at S[28..39] and receives with the one at S[16..27]; the
		 * server (crossed) the other way round. A swapped or shifted seed would still round-trip through the code itself. */
		{
			uint8_t nonce[WRI_M2S_NONCE_LEN], want[sizeof(pt) + WRI_M2S_TAG_LEN];

			memcpy(nonce, secret_pub + 28, sizeof(nonce));
			ref_secure_seal(secret_pub, nonce, pt_pub, sizeof(pt_pub), want);
			WRT_CHECK_MEM(ct, want, sizeof(ct));
			WRT_CHECK_MEM(tag, want + sizeof(ct), sizeof(tag));
			WRT_CHECK_MEM(tx_side.tx_n.cur, secret_pub + 28, WRI_M2S_NONCE_LEN);
			WRT_CHECK_MEM(tx_side.rx_n.cur, secret_pub + 16, WRI_M2S_NONCE_LEN);
			WRT_CHECK_MEM(rx_side.tx_n.cur, secret_pub + 16, WRI_M2S_NONCE_LEN);
			WRT_CHECK_MEM(rx_side.rx_n.cur, secret_pub + 28, WRI_M2S_NONCE_LEN);
		}
		memset(pt2, 0xee, sizeof(pt2));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&rx_side.rx, iv_rx, 1));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&rx_side.rx, ct, pt2, sizeof(ct)));
		st = wri_pgcm_final_dec(&rx_side.rx, tag);
		PUBLIC(&st, sizeof(st));
		WRT_CHECK_STATUS(WR_OK, st);
		group_case(&g, "open", 0, 0, 0);
		PUBLIC(pt2, sizeof(pt2));
		WRT_CHECK_MEM(pt2, pt_pub, sizeof(pt2));

		memcpy(tag_bad, tag, sizeof(tag_bad));
		tag_bad[3] = (uint8_t)(tag_bad[3] ^ 0x10u);
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&rx_side.rx, iv_rx, 1));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&rx_side.rx, ct, pt2, sizeof(ct)));
		st = wri_pgcm_final_dec(&rx_side.rx, tag_bad);
		PUBLIC(&st, sizeof(st));
		WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, st);
		group_case(&g, "reject", 0, 0, 0);
	}
	wri_m2s_wipe(&tx_side);
	wri_m2s_wipe(&rx_side);
	PUBLIC(&tx_side, sizeof(tx_side));
	PUBLIC(&rx_side, sizeof(rx_side));
	WRT_CHECK(all_zero(&tx_side, sizeof(tx_side)) && all_zero(&rx_side, sizeof(rx_side))); /* keys, schedules and nonces are gone */
	group_end(&g);
}

/* ---- the secure codec's seal (wri_m2_tx_frame with the queue bound to a secure slot) --------------------- */

#define SEAL_SEG_CAP 1600u
#define SEAL_WIRE_CAP 4096u

typedef struct seal_shape {
	unsigned nseg;
	uint32_t len[WRI_M2_MAX_SEGS];
} seal_shape;

static size_t pad16z(size_t x)
{
	return (x + 15u) & ~(size_t)15u;
}

/*
 * One frame, sealed with the connection secret's key bytes and every segment byte undefined, drained from the queue (in pieces, the
 * encode buffer entries and the bounce-buffer stream), declassified, and then taken apart with the independent reference: three parts at
 * most, the nonces of the spec in order, preamble fields, inline bytes, padding, epilogue. Returns 0 when the codec is still the
 * skeleton (WR_E_UNSUPPORTED), else 1.
 */
static int seal_one(group *g, const seal_shape *sh, unsigned idx)
{
	static const uint8_t tag_byte = 0x0a; /* a frame tag the builder accepts (1 .. WRI_M2_TAG_MAX) */
	uint8_t secret_pub[64], secret[64];
	uint8_t seg_pub[WRI_M2_MAX_SEGS][SEAL_SEG_CAP], seg[WRI_M2_MAX_SEGS][SEAL_SEG_CAP];
	uint8_t enc[2048], bounce[256], wire[SEAL_WIRE_CAP], pt[SEAL_WIRE_CAP], nonce[WRI_M2S_NONCE_LEN];
	wri_m2s_slot slot;
	wri_m2_txq q;
	wri_m2_seg_src src[WRI_M2_MAX_SEGS];
	unsigned nops = 0, i, guard = 0;
	size_t wire_len = 0, off, n2, n3, k;
	uint64_t expect;
	wr_status st;

	rnd_fill(secret_pub, sizeof(secret_pub));
	memcpy(secret, secret_pub, sizeof(secret));
	memset(seg_pub, 0, sizeof(seg_pub));
	for (i = 0; i < sh->nseg; i++)
		rnd_fill(seg_pub[i], sh->len[i]);
	memcpy(seg, seg_pub, sizeof(seg));
	memset(&slot, 0, sizeof(slot));
	memset(&q, 0, sizeof(q));
	memset(bounce, 0xcd, sizeof(bounce));
	wri_m2_txq_init(&q, enc, sizeof(enc));

	SECRET(secret, WRI_M2S_KEY_LEN); /* the nonce seeds stay defined, as in grp_m2s */
	st = wri_m2s_init(&slot.s, NULL, secret, sizeof(secret), 0);
	WRT_CHECK_STATUS(WR_OK, st);
	if (st != WR_OK)
		return 1;
	/* what wri_m2_secure_on binds, without the receive parser it also needs a banner for */
	slot.tx.s = &slot.s;
	slot.tx.bounce = bounce;
	slot.tx.bounce_cap = sizeof(bounce);
	q.sx = &slot.tx;
	for (i = 0; i < sh->nseg; i++) {
		src[i].p = seg[i];
		src[i].len = sh->len[i];
		src[i].ref = (uint8_t)((i + idx) & 1u);
		SECRET(seg[i], sh->len[i]);
	}
	st = wri_m2_tx_frame(&q, NULL, tag_byte, src, sh->nseg, NULL, NULL);
	if (st == WR_E_UNSUPPORTED) {
		wri_m2_secure_off(NULL, &q, &slot);
		return 0;
	}
	WRT_CHECK_STATUS(WR_OK, st);
	expect = wri_m2s_wire_len(sh->len, sh->nseg, &nops);
	WRT_CHECK_U64(q.pending, expect);

	while (q.pending != 0 && guard++ < 4096u) {
		wr_iov iov[WRI_M2_TXQ_IOV];
		const size_t n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
		size_t take = 0;

		WRT_CHECK(n > 0);
		if (n == 0)
			break;
		for (k = 0; k < n; k++) {
			if (((idx & 2u) != 0u) && k > 0)
				break; /* consume one entry at a time: the stream refills between pieces */
			if (wire_len + iov[k].len > sizeof(wire)) {
				WRT_CHECK(0 && "wire longer than the frame arithmetic");
				wri_m2_secure_off(NULL, &q, &slot);
				return 1;
			}
			memcpy(wire + wire_len, iov[k].base, iov[k].len);
			wire_len += iov[k].len;
			take += iov[k].len;
		}
		wri_m2_txq_consume(&q, take);
	}
	WRT_CHECK(q.pending == 0);
	group_case(g, "seal", sh->nseg, sh->len[0], idx);
	PUBLIC(wire, wire_len); /* ciphertext and tags: public by design */
	WRT_CHECK_U64(wire_len, expect);
	if (wire_len != expect || wire_len < WRI_M2S_P1_WIRE) {
		wri_m2_secure_off(NULL, &q, &slot);
		return 1;
	}

	/* the reference opens the parts in wire order, nonce from S[28..39] (client transmit), key S[0..15] */
	memcpy(nonce, secret_pub + 28, sizeof(nonce));
	WRT_CHECK(ref_secure_open(secret_pub, nonce, wire, WRI_M2S_P1_PLAIN, pt) == 0);
	WRT_CHECK(pt[0] == tag_byte && pt[1] == sh->nseg);
	for (i = 0; i < WRI_M2_MAX_SEGS; i++) {
		const uint32_t want = i < sh->nseg ? sh->len[i] : 0u;
		const uint32_t got = (uint32_t)pt[2 + 6 * i] | ((uint32_t)pt[3 + 6 * i] << 8) | ((uint32_t)pt[4 + 6 * i] << 16) |
				     ((uint32_t)pt[5 + 6 * i] << 24);

		WRT_CHECK_U64(got, want);
	}
	WRT_CHECK(pt[26] == 0 && pt[27] == 0);
	{
		uint8_t inl[WRI_M2S_INLINE];

		memset(inl, 0, sizeof(inl));
		memcpy(inl, seg_pub[0], sh->len[0] < WRI_M2S_INLINE ? sh->len[0] : WRI_M2S_INLINE);
		WRT_CHECK_MEM(pt + 32, inl, sizeof(inl));
	}
	off = WRI_M2S_P1_WIRE;
	if (sh->len[0] > WRI_M2S_INLINE) {
		n2 = pad16z(sh->len[0]) - WRI_M2S_INLINE;
		WRT_CHECK(off + n2 + WRI_M2S_TAG_LEN <= wire_len);
		if (off + n2 + WRI_M2S_TAG_LEN <= wire_len) {
			WRT_CHECK(ref_secure_open(secret_pub, nonce, wire + off, n2, pt) == 0);
			WRT_CHECK_MEM(pt, seg_pub[0] + WRI_M2S_INLINE, sh->len[0] - WRI_M2S_INLINE);
			WRT_CHECK(all_zero(pt + (sh->len[0] - WRI_M2S_INLINE), n2 - (sh->len[0] - WRI_M2S_INLINE))); /* zero padding */
			off += n2 + WRI_M2S_TAG_LEN;
		}
	}
	if (sh->nseg > 1) {
		size_t at = 0;

		n3 = WRI_M2S_EPI_LEN;
		for (i = 1; i < sh->nseg; i++)
			n3 += pad16z(sh->len[i]);
		WRT_CHECK(off + n3 + WRI_M2S_TAG_LEN <= wire_len);
		if (off + n3 + WRI_M2S_TAG_LEN <= wire_len) {
			WRT_CHECK(ref_secure_open(secret_pub, nonce, wire + off, n3, pt) == 0);
			for (i = 1; i < sh->nseg; i++) {
				const size_t pl = pad16z(sh->len[i]);

				WRT_CHECK_MEM(pt + at, seg_pub[i], sh->len[i]);
				WRT_CHECK(all_zero(pt + at + sh->len[i], pl - sh->len[i]));
				at += pl;
			}
			WRT_CHECK(pt[at] == WRI_M2_LATE_COMPLETE); /* epilogue: late_status, then 15 zero bytes */
			WRT_CHECK(all_zero(pt + at + 1u, WRI_M2S_EPI_LEN - 1u));
			off += n3 + WRI_M2S_TAG_LEN;
		}
	}
	WRT_CHECK_U64(off, wire_len);

	/* the end of the connection wipes the slot and the bounce buffer, which held plaintext padding and epilogue */
	wri_m2_secure_off(NULL, &q, &slot);
	PUBLIC(&slot, sizeof(slot));
	PUBLIC(bounce, sizeof(bounce));
	WRT_CHECK(all_zero(&slot, sizeof(slot)) && all_zero(bounce, sizeof(bounce)) && q.sx == NULL);
	return 1;
}

static void grp_m2s_seal(void)
{
	static const seal_shape shapes[] = {
		{1, {0, 0, 0, 0}},      {1, {1, 0, 0, 0}},      {1, {32, 0, 0, 0}},        {1, {48, 0, 0, 0}},         {1, {49, 0, 0, 0}},
		{1, {64, 0, 0, 0}},     {1, {200, 0, 0, 0}},    {2, {16, 16, 0, 0}},       {2, {48, 1, 0, 0}},         {2, {0, 64, 0, 0}},
		{2, {100, 300, 0, 0}},  {3, {60, 33, 500, 0}},  {4, {47, 5, 17, 1500}},    {2, {150, 1500, 0, 0}},
	};
	group g;
	size_t i;
	unsigned idx;

	group_begin(&g, "m2s-seal");
	for (i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++)
		for (idx = 0; idx < 4u; idx++)
			if (!seal_one(&g, &shapes[i], idx)) {
				note("CT-NOTE m2s-seal skeleton (WR_E_UNSUPPORTED): the secure transmit side is not checked yet");
				group_end(&g);
				return;
			}
	group_end(&g);
}

/* ---- the controls (what a leak looks like) ---------------------------------------------------------- */

typedef int (*eq_fn)(const uint8_t *a, const uint8_t *b, size_t n);

/* Returns at the first differing byte: the running time and the branch depend on the data. Reached through a volatile pointer so the
 * compiler cannot fold it into something branch-free. */
static int leaky_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (a[i] != b[i])
			return 0;
	return 1;
}

static volatile eq_fn leaky_eq_ptr = leaky_eq;
static volatile int control_sink;

/* One control: it must make Memcheck report something. Returns 1 when it did. */
static int control_seen(const char *name, unsigned long before)
{
	const unsigned long now = VG_ERRORS();
	char line[160];

	if (now != before) {
		snprintf(line, sizeof(line), "CT-CONTROL-OK %s reported=%lu", name, now - before);
		note(line);
		return 1;
	}
	snprintf(line, sizeof(line), "CT-CONTROL-MISSED %s", name);
	note(line);
	wrt_checks++;
	wrt_failures++;
	fprintf(stderr, "control %s: Memcheck reported nothing, the check cannot see a leak\n", name);
	return 0;
}

static int run_control(void)
{
	uint8_t key[16], in[16], out[16], a[16], b[16];
	wri_aes_ctx c;
	unsigned long before;

	rnd_fill(key, sizeof(key));
	rnd_fill(in, sizeof(in));
	memset(&c, 0, sizeof(c));

	/* 1. the table key schedule: S-box lookups indexed by key bytes */
	SECRET(key, sizeof(key));
	before = VG_ERRORS();
	WRT_CHECK_STATUS(WR_OK, wri_aes_setkey(&c, key, sizeof(key)));
	(void)control_seen("table-aes-setkey", before);

	/* 2. the table block function: lookups indexed by state bytes (the schedule is declassified so only the data is tested) */
	PUBLIC(&c, sizeof(c));
	SECRET(in, sizeof(in));
	before = VG_ERRORS();
	wri_aes_enc_block(&c, in, out);
	(void)control_seen("table-aes-block", before);

	/* 3. a compare with an early exit: a branch on a secret */
	rnd_fill(a, sizeof(a));
	rnd_fill(b, sizeof(b));
	SECRET(a, sizeof(a));
	before = VG_ERRORS();
	control_sink = leaky_eq_ptr(a, b, sizeof(a));
	(void)control_seen("branch-compare", before);

	return wrt_finish();
}

/* ---- the two entry points that run in process --------------------------------------------------------- */

static int run_main(void)
{
	grp_aesct_blocks();
	grp_aesct_ctr();
	grp_aesct_sbox();
	grp_ghash();
	grp_gcm();
	grp_pgcm();
	grp_m2s();
	grp_m2s_seal();
	return wrt_finish();
}

/* ---- the driver --------------------------------------------------------------------------------------- */

#if CT_HAVE_VG && CT_HAVE_POSIX

/* The groups a complete run of the normal mode must have reported clean (a run that died half way must not pass). */
static const char *const k_groups[] = {"aesct-blocks", "aesct-ctr", "aesct-sbox", "ghash", "gcm-seal", "gcm-open", "gcm-reject", "pgcm", "m2s-init", "m2s-seal"};
static const char *const k_controls[] = {"table-aes-setkey", "table-aes-block", "branch-compare"};

static int is_exec_file(const char *path)
{
	return access(path, X_OK) == 0;
}

/* The valgrind executable: $WRT_VALGRIND, else the first one on PATH. 0 when none. */
static int find_valgrind(char *out, size_t cap)
{
	const char *env = getenv("WRT_VALGRIND");
	const char *path = getenv("PATH");
	size_t i = 0;

	if (env != NULL && env[0] != '\0') {
		if (strlen(env) >= cap || !is_exec_file(env))
			return 0;
		strcpy(out, env);
		return 1;
	}
	if (path == NULL)
		path = "/usr/bin:/bin";
	while (path[i] != '\0' || i == 0) {
		const char *end = strchr(path + i, ':');
		size_t len = end != NULL ? (size_t)(end - (path + i)) : strlen(path + i);

		if (len > 0 && len + 10 < cap) {
			memcpy(out, path + i, len);
			strcpy(out + len, "/valgrind");
			if (is_exec_file(out))
				return 1;
		}
		if (end == NULL)
			break;
		i += len + 1;
	}
	return 0;
}

/* Run "valgrind ... self --run=<mode>" with the log in `log`; returns the exit code, or -1 when it did not exit normally. */
static int run_under_valgrind(const char *vg, const char *self, const char *mode, const char *log)
{
	char logopt[600], runopt[64];
	char *argv[12];
	pid_t pid;
	int status = 0, n = 0;

	snprintf(logopt, sizeof(logopt), "--log-file=%s", log);
	snprintf(runopt, sizeof(runopt), "--run=%s", mode);
	argv[n++] = (char *)vg;
	argv[n++] = (char *)"--error-exitcode=99";
	argv[n++] = (char *)"--track-origins=yes";
	argv[n++] = (char *)"--leak-check=no";
	argv[n++] = logopt;
	argv[n++] = (char *)self;
	argv[n++] = runopt;
	argv[n] = NULL;
	fflush(NULL);
	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		execv(vg, argv);
		_exit(126);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static char *slurp(const char *path)
{
	FILE *f = fopen(path, "rb");
	char *buf = NULL;
	size_t cap = 0, len = 0, got;

	if (f == NULL)
		return NULL;
	for (;;) {
		if (len + 4096u + 1u > cap) {
			char *nb;

			cap = cap ? cap * 2u : 65536u;
			nb = (char *)realloc(buf, cap);
			if (nb == NULL) {
				free(buf);
				fclose(f);
				return NULL;
			}
			buf = nb;
		}
		got = fread(buf + len, 1, cap - len - 1u, f);
		if (got == 0)
			break;
		len += got;
	}
	buf[len] = '\0';
	fclose(f);
	return buf;
}

static void dump_log(const char *what, const char *text)
{
	fprintf(stderr, "---- %s: Valgrind log ----\n", what);
	if (text != NULL) {
		size_t n = strlen(text);

		fwrite(text, 1, n > 60000u ? 60000u : n, stderr);
		if (n > 60000u)
			fprintf(stderr, "\n[... %zu more bytes ...]\n", n - 60000u);
	}
	fprintf(stderr, "---- end of log ----\n");
}

static int has(const char *text, const char *needle)
{
	return text != NULL && strstr(text, needle) != NULL;
}

static int has_line(const char *text, const char *prefix, const char *name)
{
	char key[128];

	snprintf(key, sizeof(key), "%s %s ", prefix, name);
	return has(text, key);
}

/* The path to run under Valgrind: this executable as the kernel knows it (a test started through PATH has no slash in argv[0], and
 * Valgrind would look for it in the current directory), else argv[0]. */
static const char *self_exe(const char *argv0, char *buf, size_t cap)
{
#if defined(__linux__)
	const ssize_t n = readlink("/proc/self/exe", buf, cap - 1u);

	if (n > 0) {
		buf[n] = '\0';
		return buf;
	}
#else
	(void)buf;
	(void)cap;
#endif
	return argv0;
}

static int drive(const char *self)
{
	char vg[512], log[256];
	char *text;
	int rc, ok = 1;
	size_t i;

	if (!find_valgrind(vg, sizeof(vg)))
		skip_or_fail("valgrind is not installed (apt install valgrind; or set WRT_VALGRIND to the executable)");

	/* 1. the normal mode: nothing may be reported, every group must have run */
	snprintf(log, sizeof(log), "wrt_ct_vg_%ld_main.log", (long)getpid());
	rc = run_under_valgrind(vg, self, "main", log);
	text = slurp(log);
	if (rc != 0) {
		fprintf(stderr, "FAIL: normal mode under Valgrind exited with %d (0 expected; 99 = Memcheck reported a secret-dependent branch or address)\n", rc);
		ok = 0;
	}
	if (!has(text, "ERROR SUMMARY: 0 errors")) {
		fprintf(stderr, "FAIL: normal mode: no \"ERROR SUMMARY: 0 errors\" in the log\n");
		ok = 0;
	}
	if (has(text, "CT-BAD ")) {
		fprintf(stderr, "FAIL: normal mode: a group reported errors (CT-BAD)\n");
		ok = 0;
	}
	for (i = 0; i < sizeof(k_groups) / sizeof(k_groups[0]); i++) {
		char zero[128];

		if (!has_line(text, "CT-OK", k_groups[i])) {
			fprintf(stderr, "FAIL: normal mode: group %s did not finish clean (no CT-OK line)\n", k_groups[i]);
			ok = 0;
		}
		/* a group that ran no case at all is no evidence (an empty list of checks reads as all green): only a skeleton says so */
		snprintf(zero, sizeof(zero), "CT-OK %s cases=0 ", k_groups[i]);
		if (has(text, zero) && !has_line(text, "CT-NOTE", k_groups[i])) {
			fprintf(stderr, "FAIL: normal mode: group %s ran no case and did not say it is a skeleton\n", k_groups[i]);
			ok = 0;
		}
	}
	if (has(text, "CT-NOTE "))
		printf("note: a group reported a CT-NOTE (a module that is still a skeleton is not checked yet)\n");
	if (!ok)
		dump_log("normal mode", text);
	free(text);
	(void)unlink(log);
	if (!ok)
		return 1;

	/* 2. the control: the known-bad code through the same harness MUST be reported (exit 99, all three controls seen) */
	snprintf(log, sizeof(log), "wrt_ct_vg_%ld_control.log", (long)getpid());
	rc = run_under_valgrind(vg, self, "control", log);
	text = slurp(log);
	if (rc != 99) {
		fprintf(stderr, "FAIL: control under Valgrind exited with %d (99 expected: the known-bad code must be reported)\n", rc);
		ok = 0;
	}
	for (i = 0; i < sizeof(k_controls) / sizeof(k_controls[0]); i++)
		if (!has_line(text, "CT-CONTROL-OK", k_controls[i])) {
			fprintf(stderr, "FAIL: control %s was not reported by Memcheck: the check cannot see this kind of leak\n", k_controls[i]);
			ok = 0;
		}
	if (has(text, "CT-CONTROL-MISSED")) {
		fprintf(stderr, "FAIL: a control was missed\n");
		ok = 0;
	}
	if (!has(text, "Use of uninitialised value") || !has(text, "Conditional jump or move depends on uninitialised value")) {
		fprintf(stderr, "FAIL: the control log lacks the two report kinds (address use and conditional jump)\n");
		ok = 0;
	}
	if (!ok)
		dump_log("control", text);
	free(text);
	(void)unlink(log);
	if (!ok)
		return 1;
	printf("crypto.ct.valgrind: %zu groups clean, %zu controls reported, valgrind: %s\n", sizeof(k_groups) / sizeof(k_groups[0]),
	       sizeof(k_controls) / sizeof(k_controls[0]), vg);
	return 0;
}

#endif /* CT_HAVE_VG && CT_HAVE_POSIX */

/* Sanitizers that cannot run under Valgrind (they map their own shadow memory over the address space Valgrind wants). */
WRT_UNUSED static const char *sanitizer_in_use(void)
{
#if defined(WRT_CT_SANITIZE)
	return WRT_CT_SANITIZE; /* the harness build was configured with WR_SANITIZE */
#elif defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
	return "AddressSanitizer or ThreadSanitizer";
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer) || __has_feature(thread_sanitizer)
	return "a Clang sanitizer";
#else
	return NULL;
#endif
#else
	return NULL;
#endif
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "";

	if (strcmp(mode, "--drive") == 0) {
#if !CT_HAVE_VG
		skip_or_fail("the Valgrind client-request header (valgrind/memcheck.h, package valgrind or libvalgrind-dev) was not found when this test was built");
#elif !CT_HAVE_POSIX
		WRT_SKIP("this platform has no fork/exec to run Valgrind");
#else
		const char *san = sanitizer_in_use();

		if (san != NULL) {
			char why[200];

			snprintf(why, sizeof(why), "built with %s: sanitizer runtimes do not run under Valgrind (the plain flavours run this check)", san);
			WRT_SKIP(why);
		}
		if (UNDER_VG())
			return run_main(); /* already under Valgrind: just run it */
		{
			char exe[1024];

			return drive(self_exe(argv[0], exe, sizeof(exe)));
		}
#endif
	}
	if (strcmp(mode, "--run=control") == 0) {
		if (!UNDER_VG())
			WRT_SKIP("the control only means something under Valgrind (use --drive)");
		return run_control();
	}
	if (argc > 1 && strcmp(mode, "--run=main") != 0) {
		fprintf(stderr, "usage: %s [--drive | --run=main | --run=control]\n", argv[0]);
		return 2;
	}
	return run_main();
}
