/* SPDX-License-Identifier: MIT */
/*
 * test_crush_ln - the fixed-point log of straw2 (core/src/crush/wri_crush_ln.c) and the two tables it reads
 * through the accessors of core/crush_ln/ (docs/spec/crush-and-placement.md 3.4.2 and 5.1).
 *
 * Checks:
 *   - the ten known answers of note 5.1 (and the crush_ln rows of vectors/crush/hash-vectors.json);
 *   - the table facts of 3.4.2: the 129 RH values are ceil(2^55 / (128 + k)), the last LH is the deliberate
 *     0x0000ffff00000000, first and last entries of both tables, both tables non-decreasing where they must be;
 *   - properties of the function: non-decreasing over the whole domain, inputs masked to 16 bits, powers of two
 *     land on whole multiples of 2^44;
 *   - a golden digest: SHA-256 over all 65,536 outputs, each as 8 big-endian bytes in input order.
 *
 * How the golden digest was made (once, outside this repository; nothing of Ceph is needed at test time):
 *   1. make an empty directory D outside the repo and an empty file D/acconfig.h;
 *   2. write D/wrap.c: it #includes src/crush/mapper.c of the pinned Ceph release (v20.2.5, commit
 *      ed27c686770872022f4c1de04f6b0ac5d5384ded; crush_ln is static there, so the wrapper sees it by including the
 *      file) and has a main() that, for u = 0..65535, writes crush_ln(u) to stdout as 8 big-endian bytes;
 *   3. cc -O1 -w -I D -I <ceph>/src -I <ceph>/src/include -I <ceph>/src/crush -o D/wrap D/wrap.c
 *         <ceph>/src/crush/hash.c <ceph>/src/crush/crush.c
 *   4. D/wrap | sha256sum
 * The digest below is that output (524,288 bytes). The same pass gave the ten known answers.
 */
#include "wrt.h"
#include "wri_crush_ln.h"
#include "wri_hash.h"

#define GOLDEN_DIGEST "0c25821f60752f6bfd9fcfe308cc7df3e16949c2b2523f84e8fbbaa3a386737f"

static void test_known_answers(void)
{
	static const struct {
		uint32_t u;
		uint64_t want;
	} k[] = {
		{0, 0x000000000000ull},      {1, 0x100000000000ull},      {2, 0x195c01a39fbdull},
		{255, 0x800000000000ull},    {256, 0x80171e3b6d7aull},    {0x1234, 0xc2fb9e09ec18ull},
		{0x7fff, 0xf00000000000ull}, {0x8000, 0xf0002e2a60a0ull}, {0xfffe, 0xfffffd61ad10ull},
		{0xffff, 0xfffff0000000ull},
	};
	size_t i;

	for (i = 0; i < sizeof(k) / sizeof(k[0]); i++)
		WRT_CHECK_U64(wri_crush_ln(k[i].u), k[i].want);
}

static void test_vector_file(void)
{
	wrt_json j;
	wrt_tok arr;
	size_t i, n;

	if (wrt_json_load_vec(&j, "crush/hash-vectors.json") != 0) {
		WRT_CHECK(!"hash-vectors.json loads");
		return;
	}
	arr = wrt_json_get(&j, wrt_json_root(&j), "crush_ln");
	n = wrt_json_count(&j, arr);
	WRT_CHECK(n == 10u);
	for (i = 0; i < n; i++) {
		wrt_tok row = wrt_json_at(&j, arr, i);
		char *res = wrt_json_strdup(&j, wrt_json_get(&j, row, "result"));
		uint32_t u = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, row, "u"), NULL);

		WRT_CHECK(res != NULL);
		if (res != NULL)
			WRT_CHECK_U64(wri_crush_ln(u), strtoull(res, NULL, 16));
		free(res);
	}
	wrt_json_free(&j);
}

/* 3.4.2: RH_LH[2k] = ceil(2^48 / (1 + k/128)) = ceil(2^55 / (128 + k)) for k = 0..128, and a deliberate last LH. */
static void test_table_facts(void)
{
	const int64_t *rl = wri_crush_ln_rh_lh();
	const int64_t *ll = wri_crush_ln_ll();
	uint32_t k;

	WRT_CHECK(rl != NULL && ll != NULL);
	if (rl == NULL || ll == NULL)
		return;
	WRT_CHECK_U64(WRI_CRUSH_LN_RH_LH_COUNT, 258);
	WRT_CHECK_U64(WRI_CRUSH_LN_LL_COUNT, 256);
	for (k = 0; k <= 128u; k++) {
		uint64_t d = 128u + (uint64_t)k;
		uint64_t want = ((1ull << 55) + d - 1u) / d;

		WRT_CHECK_U64(rl[2u * k], want);
	}
	WRT_CHECK_U64(rl[0], 0x0001000000000000ull); /* 2^48 */
	WRT_CHECK_U64(rl[1], 0);
	WRT_CHECK_U64(rl[256], 0x0000800000000000ull); /* 2^47: k = 128 */
	WRT_CHECK_U64(rl[257], 0x0000ffff00000000ull);  /* the fudge: 2^48 - 2^32, not 2^48 */
	/* RH falls and LH rises with k (LH is the log of 1 + k/128) */
	for (k = 1; k <= 128u; k++) {
		WRT_CHECK(rl[2u * k] < rl[2u * (k - 1u)]);
		WRT_CHECK(rl[2u * k + 1u] > rl[2u * (k - 1u) + 1u]);
	}
	for (k = 0; k < 128u; k++)
		WRT_CHECK(rl[2u * k + 1u] < (1ll << 48)); /* log2 below 1.0 for k < 128 */
	WRT_CHECK_U64(rl[2], 0x0000fe03f80fe040ull); /* spot-check slot 1 */
	WRT_CHECK_U64(rl[3], 0x000002dfca16dde1ull);

	WRT_CHECK_U64(ll[0], 0);
	WRT_CHECK_U64(ll[1], 0x00000002e2a60a00ull);
	WRT_CHECK_U64(ll[255], 0x000002dced24f814ull);
	for (k = 1; k < 256u; k++)
		WRT_CHECK(ll[k] > ll[k - 1u]);
	/* the same table pointers every call (read-only data, no copy) */
	WRT_CHECK(wri_crush_ln_rh_lh() == rl && wri_crush_ln_ll() == ll);
}

static void test_properties(void)
{
	uint32_t u, e;
	uint64_t prev = 0;

	/* non-decreasing up to 0xfffe; the last input is the one fudged entry and lands just below its neighbour */
	for (u = 0; u <= 0xfffeu; u++) {
		uint64_t v = wri_crush_ln(u);

		WRT_CHECK(v >= prev);
		WRT_CHECK(v < 0x1000000000000ull);
		prev = v;
	}
	WRT_CHECK(wri_crush_ln(0xffffu) < wri_crush_ln(0xfffeu));
	/* u + 1 = 2^e gives exactly e * 2^44 (e = 16 is the fudged top entry, covered by the known answers) */
	for (e = 0; e < 16u; e++)
		WRT_CHECK_U64(wri_crush_ln((1u << e) - 1u), (uint64_t)e << 44);
	/* only the low 16 bits count */
	for (u = 0; u < 5000u; u++) {
		WRT_CHECK_U64(wri_crush_ln(u | 0x10000u), wri_crush_ln(u));
		WRT_CHECK_U64(wri_crush_ln(u | 0xabcd0000u), wri_crush_ln(u));
	}
	WRT_CHECK_U64(wri_crush_ln(0xffffffffu), wri_crush_ln(0xffffu));
}

static void test_golden_digest(void)
{
	wri_sha256_ctx c;
	uint8_t out[32];
	char hex[65];
	uint32_t u;

	wri_sha256_init(&c);
	for (u = 0; u <= 0xffffu; u++) {
		uint64_t v = wri_crush_ln(u);
		uint8_t b[8];
		int i;

		for (i = 0; i < 8; i++)
			b[i] = (uint8_t)(v >> (56 - 8 * i));
		wri_sha256_update(&c, b, 8);
	}
	wri_sha256_final(&c, out);
	wrt_hex_encode(out, 32, hex);
	wrt_checks++;
	if (strcmp(hex, GOLDEN_DIGEST) != 0) {
		wrt_failures++;
		fprintf(stderr, "%s:%d: crush_ln digest %s, want %s\n", __FILE__, __LINE__, hex, GOLDEN_DIGEST);
	}
}

int main(void)
{
	test_known_answers();
	test_vector_file();
	test_table_facts();
	test_properties();
	test_golden_digest();
	return wrt_finish();
}
