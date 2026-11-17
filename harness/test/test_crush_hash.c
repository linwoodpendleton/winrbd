/* SPDX-License-Identifier: MIT */
/*
 * test_crush_hash - the object name hashes, the CRUSH mixing hashes and the pg arithmetic
 * (core/src/crush/wri_crush_hash.c, docs/spec/crush-and-placement.md 3.1 and 3.2).
 *
 * Checks:
 *   - every row of vectors/crush/hash-vectors.json: ten names in both string hash flavours (namespace case
 *     included), hash2/3/4, stable_mod, the HASHPSPOOL placement seed; plus the three hash1 values and the
 *     legacy seeds of note 5.1;
 *   - the string hashes for lengths 0..40 (and a few longer ones) against a second implementation written in
 *     this file straight from the note, byte by byte with no shared code: every tail length, every multiple of
 *     12, the length folded into c;
 *   - hash1..4 against a second implementation driven by the round table of 3.2.1;
 *   - the dispatcher, wri_cbits, wri_pg_mask at the edges (0, 1, 2, 3, 100, 128, 2^31 and the values whose
 *     mask is 32 bits wide, where a shift by 32 would be undefined);
 *   - the 3.2 consistency check: stable_mod(stable_mod(x, pg_num, m1), pgp_num, m2) == stable_mod(x, pgp_num, m2)
 *     for pg_num 1..299, every pgp_num <= pg_num and 600 values of x.
 */
#include "wrt.h"
#include "wri_crush_hash.h"

/* ---- a second implementation, from the note --------------------------------------------------- */

/* One round of 3.2.1: t = t - u - v, then t ^= (w >> s) or (w << s). */
struct round {
	int t, u, v, w; /* indexes into {a, b, c} */
	int left;       /* 1: shift left, 0: shift right */
	unsigned shift;
};

static const struct round ROUNDS[9] = {
	{0, 1, 2, 2, 0, 13}, {1, 2, 0, 0, 1, 8}, {2, 0, 1, 1, 0, 13},
	{0, 1, 2, 2, 0, 12}, {1, 2, 0, 0, 1, 16}, {2, 0, 1, 1, 0, 5},
	{0, 1, 2, 2, 0, 3}, {1, 2, 0, 0, 1, 10}, {2, 0, 1, 1, 0, 15},
};

static void ref_mix(uint32_t *a, uint32_t *b, uint32_t *c)
{
	uint32_t *v[3];
	int i;

	v[0] = a;
	v[1] = b;
	v[2] = c;
	for (i = 0; i < 9; i++) {
		const struct round *r = &ROUNDS[i];
		uint32_t w = *v[r->w];
		uint32_t d = r->left ? (uint32_t)(w << r->shift) : (uint32_t)(w >> r->shift);

		*v[r->t] = (uint32_t)(*v[r->t] - *v[r->u] - *v[r->v]);
		*v[r->t] ^= d;
	}
}

static uint32_t ref_str_rjenkins(const uint8_t *k, uint32_t n)
{
	uint32_t a = 0x9e3779b9u, b = 0x9e3779b9u, c = 0;
	uint32_t pos = 0, len = n, i;

	while (len >= 12u) {
		uint32_t w[3] = {0, 0, 0};

		for (i = 0; i < 12u; i++)
			w[i / 4u] |= (uint32_t)k[pos + i] << (8u * (i % 4u));
		a = (uint32_t)(a + w[0]);
		b = (uint32_t)(b + w[1]);
		c = (uint32_t)(c + w[2]);
		ref_mix(&a, &b, &c);
		pos += 12u;
		len -= 12u;
	}
	c = (uint32_t)(c + n);
	for (i = 0; i < len; i++) {
		uint32_t byte = k[pos + i];

		if (i < 4u)
			a = (uint32_t)(a + (byte << (8u * i)));
		else if (i < 8u)
			b = (uint32_t)(b + (byte << (8u * (i - 4u))));
		else
			c = (uint32_t)(c + (byte << (8u * (i - 8u + 1u)))); /* c's low byte is the length */
	}
	ref_mix(&a, &b, &c);
	return c;
}

static uint32_t ref_str_linux(const uint8_t *k, uint32_t n)
{
	uint64_t h = 0; /* wide on purpose: reduce modulo 2^32 after every byte */
	uint32_t i;

	for (i = 0; i < n; i++)
		h = ((h + ((uint64_t)k[i] << 4) + (k[i] >> 4)) * 11u) & 0xffffffffu;
	return (uint32_t)h;
}

static uint32_t ref_hash(unsigned nargs, uint32_t in0, uint32_t in1, uint32_t in2, uint32_t in3)
{
	uint32_t seed = 1315423911u, x = 231232u, y = 1232u, h;
	uint32_t a = in0, b = in1, c = in2, d = in3;

	switch (nargs) {
	case 1:
		h = seed ^ a;
		b = a;
		ref_mix(&b, &x, &h);
		ref_mix(&y, &a, &h);
		return h;
	case 2:
		h = seed ^ a ^ b;
		ref_mix(&a, &b, &h);
		ref_mix(&x, &a, &h);
		ref_mix(&b, &y, &h);
		return h;
	case 3:
		h = seed ^ a ^ b ^ c;
		ref_mix(&a, &b, &h);
		ref_mix(&c, &x, &h);
		ref_mix(&y, &a, &h);
		ref_mix(&b, &x, &h);
		ref_mix(&y, &c, &h);
		return h;
	default:
		h = seed ^ a ^ b ^ c ^ d;
		ref_mix(&a, &b, &h);
		ref_mix(&c, &d, &h);
		ref_mix(&a, &x, &h);
		ref_mix(&y, &b, &h);
		ref_mix(&c, &x, &h);
		ref_mix(&y, &d, &h);
		return h;
	}
}

/* ---- helpers ---------------------------------------------------------------------------------- */

static uint32_t rng_state = 0x2468ace1u;

static uint32_t rng(void)
{
	rng_state = rng_state * 1664525u + 1013904223u; /* fixed seed: runs are reproducible */
	return rng_state;
}

static uint32_t parse_hex32(const char *s)
{
	return (uint32_t)strtoul(s, NULL, 16);
}

/* ---- the vector file -------------------------------------------------------------------------- */

static void test_vector_strings(const wrt_json *j, wrt_tok root)
{
	wrt_tok arr = wrt_json_get(j, root, "rjenkins_str");
	size_t i, n = wrt_json_count(j, arr);

	WRT_CHECK(n == 10u);
	for (i = 0; i < n; i++) {
		wrt_tok row = wrt_json_at(j, arr, i);
		uint8_t *in = NULL;
		size_t len = 0;
		char *rj = wrt_json_strdup(j, wrt_json_get(j, row, "rjenkins"));
		char *lx = wrt_json_strdup(j, wrt_json_get(j, row, "linux_dcache"));
		int ok = -1;

		WRT_CHECK(rj != NULL && lx != NULL);
		WRT_CHECK(wrt_json_get_hex(j, row, "input_hex", &in, &len) == 0);
		if (rj != NULL && lx != NULL && in != NULL) {
			WRT_CHECK_U64(wri_str_hash_rjenkins(in, (uint32_t)len), parse_hex32(rj));
			WRT_CHECK_U64(wri_str_hash_linux(in, (uint32_t)len), parse_hex32(lx));
			WRT_CHECK_U64(wri_str_hash(WRI_STR_HASH_RJENKINS, in, (uint32_t)len, &ok), parse_hex32(rj));
			WRT_CHECK(ok == 1);
			WRT_CHECK_U64(wri_str_hash(WRI_STR_HASH_LINUX, in, (uint32_t)len, &ok), parse_hex32(lx));
			WRT_CHECK(ok == 1);
		}
		free(in);
		free(rj);
		free(lx);
	}
}

static void test_vector_crush_hash(const wrt_json *j, wrt_tok root)
{
	wrt_tok arr = wrt_json_get(j, root, "crush_hash");
	size_t i, n = wrt_json_count(j, arr);

	WRT_CHECK(n == 10u);
	for (i = 0; i < n; i++) {
		wrt_tok row = wrt_json_at(j, arr, i);
		char *fn = wrt_json_strdup(j, wrt_json_get(j, row, "fn"));
		char *res = wrt_json_strdup(j, wrt_json_get(j, row, "result"));
		wrt_tok args = wrt_json_get(j, row, "args");
		uint32_t v[4] = {0, 0, 0, 0};
		size_t k, na = wrt_json_count(j, args);
		uint32_t got = 0;

		WRT_CHECK(fn != NULL && res != NULL && na >= 2u && na <= 4u);
		if (fn == NULL || res == NULL || na < 2u || na > 4u) {
			free(fn);
			free(res);
			continue;
		}
		for (k = 0; k < na; k++)
			v[k] = (uint32_t)wrt_json_int(j, wrt_json_at(j, args, k), NULL);
		if (strcmp(fn, "hash2") == 0 && na == 2u)
			got = wri_crush_hash2(v[0], v[1]);
		else if (strcmp(fn, "hash3") == 0 && na == 3u)
			got = wri_crush_hash3(v[0], v[1], v[2]);
		else if (strcmp(fn, "hash4") == 0 && na == 4u)
			got = wri_crush_hash4(v[0], v[1], v[2], v[3]);
		else
			WRT_CHECK(!"unknown crush hash row");
		WRT_CHECK_U64(got, parse_hex32(res));
		free(fn);
		free(res);
	}
}

static void test_vector_stable_mod(const wrt_json *j, wrt_tok root)
{
	wrt_tok arr = wrt_json_get(j, root, "stable_mod");
	size_t i, n = wrt_json_count(j, arr);

	WRT_CHECK(n == 6u);
	for (i = 0; i < n; i++) {
		wrt_tok row = wrt_json_at(j, arr, i);
		uint32_t x = (uint32_t)wrt_json_int(j, wrt_json_get(j, row, "x"), NULL);
		uint32_t b = (uint32_t)wrt_json_int(j, wrt_json_get(j, row, "b"), NULL);
		uint32_t m = (uint32_t)wrt_json_int(j, wrt_json_get(j, row, "mask"), NULL);
		uint32_t want = (uint32_t)wrt_json_int(j, wrt_json_get(j, row, "result"), NULL);

		WRT_CHECK_U64(wri_stable_mod(x, b, m), want);
		WRT_CHECK_U64(wri_pg_mask(b) <= m, 1); /* the mask in the row is the pool's own: never narrower than the pg count needs */
	}
}

static void test_vector_pps(const wrt_json *j, wrt_tok root)
{
	wrt_tok arr = wrt_json_get(j, root, "pps_hashpspool");
	size_t i, n = wrt_json_count(j, arr);

	WRT_CHECK(n == 3u);
	for (i = 0; i < n; i++) {
		wrt_tok row = wrt_json_at(j, arr, i);
		uint32_t pool = (uint32_t)wrt_json_int(j, wrt_json_get(j, row, "pool"), NULL);
		uint32_t seed = (uint32_t)wrt_json_int(j, wrt_json_get(j, row, "seed"), NULL);
		char *pps = wrt_json_strdup(j, wrt_json_get(j, row, "pps"));

		WRT_CHECK(pps != NULL);
		if (pps != NULL)
			WRT_CHECK_U64(wri_crush_hash2(seed, pool), parse_hex32(pps));
		free(pps);
	}
}

static void test_vectors_file(void)
{
	wrt_json j;
	wrt_tok root;

	if (wrt_json_load_vec(&j, "crush/hash-vectors.json") != 0) {
		WRT_CHECK(!"hash-vectors.json loads");
		return;
	}
	root = wrt_json_root(&j);
	test_vector_strings(&j, root);
	test_vector_crush_hash(&j, root);
	test_vector_stable_mod(&j, root);
	test_vector_pps(&j, root);
	wrt_json_free(&j);
}

/* The rest of note 5.1 that the file does not hold: hash1 and the pool-id arithmetic of the legacy seed. */
static void test_note_values(void)
{
	WRT_CHECK_U64(wri_crush_hash1(0), 0x17c4a80bu);
	WRT_CHECK_U64(wri_crush_hash1(1), 0xd5082851u);
	WRT_CHECK_U64(wri_crush_hash1(0xffffffffu), 0x7f71bc2au);
	/* legacy pps = stable_mod(seed, pgp_num, mask) + pool, pgp_num 12 */
	WRT_CHECK_U64(wri_stable_mod(6, 12, wri_pg_mask(12)) + 1u, 7);
	WRT_CHECK_U64(wri_stable_mod(6, 12, wri_pg_mask(12)) + 2u, 8);
	WRT_CHECK_U64(wri_pg_mask(12), 15);
	WRT_CHECK_U64(wri_pg_mask(100), 127);
	WRT_CHECK_U64(wri_pg_mask(1), 0);
}

/* ---- string hashes against the second implementation ------------------------------------------ */

static void test_string_lengths(void)
{
	uint8_t buf[200];
	uint32_t n, i, round;

	/* lengths 0..40 on several byte patterns: random, all zero, all 0xff (sign-extension traps) */
	for (round = 0; round < 6; round++) {
		for (i = 0; i < sizeof(buf); i++) {
			if (round == 0)
				buf[i] = 0;
			else if (round == 1)
				buf[i] = 0xff;
			else if (round == 2)
				buf[i] = (uint8_t)(0x80u + (i & 0x7fu)); /* high bit set: a signed-char read would differ */
			else
				buf[i] = (uint8_t)(rng() >> 13);
		}
		for (n = 0; n <= 40; n++) {
			WRT_CHECK_U64(wri_str_hash_rjenkins(buf, n), ref_str_rjenkins(buf, n));
			WRT_CHECK_U64(wri_str_hash_linux(buf, n), ref_str_linux(buf, n));
		}
		/* longer names, including 4 KiB-like boundaries and an unaligned start */
		for (n = 41; n <= 190; n += 7) {
			WRT_CHECK_U64(wri_str_hash_rjenkins(buf + 1, n), ref_str_rjenkins(buf + 1, n));
			WRT_CHECK_U64(wri_str_hash_linux(buf + 3, n), ref_str_linux(buf + 3, n));
		}
	}
	/* the length is folded into c: two names that differ only by trailing zero bytes hash apart */
	memset(buf, 0, sizeof(buf));
	for (n = 1; n < 40; n++)
		WRT_CHECK(wri_str_hash_rjenkins(buf, n) != wri_str_hash_rjenkins(buf, n + 1u));
	/* the empty string: the final mix still runs */
	WRT_CHECK_U64(wri_str_hash_rjenkins(NULL, 0), 0xbd49d10du);
	WRT_CHECK_U64(wri_str_hash_rjenkins(buf, 0), 0xbd49d10du);
	WRT_CHECK_U64(wri_str_hash_linux(NULL, 0), 0);
}

/* Buffers of exactly n bytes on the heap: under ASan a read past the end (a tail case that reads one byte too many,
 * a 12-byte block read at 11 bytes left) is a failure, which the 200-byte buffers of the test above would hide. */
static void test_exact_buffers(void)
{
	uint32_t n, i;

	for (n = 0; n <= 80u; n++) {
		uint8_t *b = (uint8_t *)malloc(n != 0u ? n : 1u);
		uint8_t *u = (uint8_t *)malloc(n + 1u); /* the same bytes at an odd address */

		WRT_CHECK(b != NULL && u != NULL);
		if (b == NULL || u == NULL) {
			free(b);
			free(u);
			return;
		}
		for (i = 0; i < n; i++) {
			b[i] = (uint8_t)(0x80u + rng());
			u[i + 1u] = b[i];
		}
		WRT_CHECK_U64(wri_str_hash_rjenkins(b, n), ref_str_rjenkins(b, n));
		WRT_CHECK_U64(wri_str_hash_linux(b, n), ref_str_linux(b, n));
		WRT_CHECK_U64(wri_str_hash_rjenkins(u + 1, n), ref_str_rjenkins(b, n));
		WRT_CHECK_U64(wri_str_hash(WRI_STR_HASH_RJENKINS, b, n, NULL), ref_str_rjenkins(b, n));
		WRT_CHECK_U64(wri_str_hash(WRI_STR_HASH_LINUX, b, n, NULL), ref_str_linux(b, n));
		/* every byte counts: one flipped bit anywhere changes both hashes (a dropped tail byte would not) */
		for (i = 0; i < n; i++) {
			uint32_t was_r = wri_str_hash_rjenkins(b, n), was_l = wri_str_hash_linux(b, n);

			b[i] ^= 0x10u;
			WRT_CHECK(wri_str_hash_rjenkins(b, n) != was_r);
			WRT_CHECK(wri_str_hash_linux(b, n) != was_l);
			b[i] ^= 0x10u;
		}
		free(b);
		free(u);
	}
}

/* NULL with announced bytes: all entry points refuse (0) and read nothing; NULL with no bytes is the empty name. */
static void test_null_input(void)
{
	WRT_CHECK_U64(wri_str_hash_rjenkins(NULL, 1), 0);
	WRT_CHECK_U64(wri_str_hash_rjenkins(NULL, 12), 0);
	WRT_CHECK_U64(wri_str_hash_rjenkins(NULL, 0xffffffffu), 0);
	WRT_CHECK_U64(wri_str_hash_linux(NULL, 1), 0);
	WRT_CHECK_U64(wri_str_hash_linux(NULL, 0xffffffffu), 0);
	WRT_CHECK_U64(wri_str_hash_rjenkins(NULL, 0), 0xbd49d10du);
}

static void test_dispatch(void)
{
	static const uint8_t foo[3] = {'f', 'o', 'o'};
	int ok = 7;

	WRT_CHECK_U64(wri_str_hash(WRI_STR_HASH_RJENKINS, foo, 3, &ok), 0x7fc1f406u);
	WRT_CHECK(ok == 1);
	WRT_CHECK_U64(wri_str_hash(WRI_STR_HASH_LINUX, foo, 3, &ok), 0x0024db2au);
	WRT_CHECK(ok == 1);
	ok = 7;
	WRT_CHECK_U64(wri_str_hash(0, foo, 3, &ok), 0);
	WRT_CHECK(ok == 0);
	ok = 7;
	WRT_CHECK_U64(wri_str_hash(3, foo, 3, &ok), 0);
	WRT_CHECK(ok == 0);
	ok = 7;
	WRT_CHECK_U64(wri_str_hash(0xffffffffu, foo, 3, &ok), 0);
	WRT_CHECK(ok == 0);
	ok = 7;
	WRT_CHECK_U64(wri_str_hash(WRI_STR_HASH_RJENKINS, NULL, 3, &ok), 0); /* bytes missing: refuse, never read */
	WRT_CHECK(ok == 0);
	/* ok may be NULL */
	WRT_CHECK_U64(wri_str_hash(WRI_STR_HASH_RJENKINS, foo, 3, NULL), 0x7fc1f406u);
	WRT_CHECK_U64(wri_str_hash(9, foo, 3, NULL), 0);
	ok = 7;
	WRT_CHECK_U64(wri_str_hash(WRI_STR_HASH_RJENKINS, NULL, 0, &ok), 0xbd49d10du);
	WRT_CHECK(ok == 1);
}

/* ---- the CRUSH hashes against the second implementation --------------------------------------- */

static void test_hash_random(void)
{
	static const uint32_t edge[] = {0, 1, 2, 0x7fffffffu, 0x80000000u, 0xfffffffeu, 0xffffffffu};
	uint32_t i, j, k;

	for (i = 0; i < 20000; i++) {
		uint32_t a = rng(), b = rng(), c = rng(), d = rng();

		WRT_CHECK_U64(wri_crush_hash1(a), ref_hash(1, a, 0, 0, 0));
		WRT_CHECK_U64(wri_crush_hash2(a, b), ref_hash(2, a, b, 0, 0));
		WRT_CHECK_U64(wri_crush_hash3(a, b, c), ref_hash(3, a, b, c, 0));
		WRT_CHECK_U64(wri_crush_hash4(a, b, c, d), ref_hash(4, a, b, c, d));
	}
	for (i = 0; i < sizeof(edge) / sizeof(edge[0]); i++)
		for (j = 0; j < sizeof(edge) / sizeof(edge[0]); j++)
			for (k = 0; k < sizeof(edge) / sizeof(edge[0]); k++) {
				WRT_CHECK_U64(wri_crush_hash2(edge[i], edge[j]), ref_hash(2, edge[i], edge[j], 0, 0));
				WRT_CHECK_U64(wri_crush_hash3(edge[i], edge[j], edge[k]), ref_hash(3, edge[i], edge[j], edge[k], 0));
				WRT_CHECK_U64(wri_crush_hash4(edge[i], edge[j], edge[k], edge[i]),
					      ref_hash(4, edge[i], edge[j], edge[k], edge[i]));
			}
}

/* ---- cbits, masks, stable_mod ----------------------------------------------------------------- */

static void test_cbits_and_mask(void)
{
	uint32_t v;

	WRT_CHECK_U64(wri_cbits(0), 0);
	WRT_CHECK_U64(wri_cbits(1), 1);
	WRT_CHECK_U64(wri_cbits(2), 2);
	WRT_CHECK_U64(wri_cbits(3), 2);
	WRT_CHECK_U64(wri_cbits(7), 3);
	WRT_CHECK_U64(wri_cbits(8), 4);
	WRT_CHECK_U64(wri_cbits(15), 4);
	WRT_CHECK_U64(wri_cbits(16), 5);
	WRT_CHECK_U64(wri_cbits(31), 5);
	WRT_CHECK_U64(wri_cbits(0x7fffffffu), 31);
	WRT_CHECK_U64(wri_cbits(0x80000000u), 32);
	WRT_CHECK_U64(wri_cbits(0xffffffffu), 32);
	for (v = 1; v < 40000; v++) {
		uint32_t want = 0, t = v;

		while (t != 0) {
			want++;
			t /= 2u;
		}
		WRT_CHECK_U64(wri_cbits(v), want);
	}

	WRT_CHECK_U64(wri_pg_mask(0), 0);
	WRT_CHECK_U64(wri_pg_mask(1), 0);
	WRT_CHECK_U64(wri_pg_mask(2), 1);
	WRT_CHECK_U64(wri_pg_mask(3), 3);
	WRT_CHECK_U64(wri_pg_mask(4), 3);
	WRT_CHECK_U64(wri_pg_mask(5), 7);
	WRT_CHECK_U64(wri_pg_mask(100), 127);
	WRT_CHECK_U64(wri_pg_mask(128), 127);
	WRT_CHECK_U64(wri_pg_mask(129), 255);
	WRT_CHECK_U64(wri_pg_mask(0x80000000u), 0x7fffffffu); /* 2^31 */
	WRT_CHECK_U64(wri_pg_mask(0x80000001u), 0xffffffffu); /* needs 32 bits: no shift by 32 */
	WRT_CHECK_U64(wri_pg_mask(0xffffffffu), 0xffffffffu);
	/* the mask is a power of two minus one that covers n - 1 and is at most twice n - 1 */
	for (v = 1; v < 5000; v++) {
		uint32_t m = wri_pg_mask(v);

		WRT_CHECK((m & (m + 1u)) == 0u);
		WRT_CHECK(m >= v - 1u);
		WRT_CHECK(v == 1u || (m >> 1) < v - 1u);
	}
}

static void test_stable_mod_basic(void)
{
	uint32_t x;

	WRT_CHECK_U64(wri_stable_mod(0x7fc1f406u, 12, 15), 6);
	WRT_CHECK_U64(wri_stable_mod(0xffffffffu, 100, 127), 63);
	WRT_CHECK_U64(wri_stable_mod(12345, 1, 0), 0);
	/* power-of-two counts are a plain mask */
	for (x = 0; x < 1000; x++)
		WRT_CHECK_U64(wri_stable_mod(x * 2654435761u, 32, 31), (x * 2654435761u) & 31u);
	/* the result is always below b */
	for (x = 0; x < 20000; x++) {
		uint32_t b = 1u + rng() % 300u, v = rng();

		WRT_CHECK(wri_stable_mod(v, b, wri_pg_mask(b)) < b);
	}
}

/* The check of 3.2: masking with pg_num first and then pgp_num equals masking with pgp_num alone. */
static void test_stable_mod_nested(void)
{
	uint32_t xs[600];
	uint32_t i, pg_num, pgp_num;
	unsigned long bad = 0;

	xs[0] = 0;
	xs[1] = 0xffffffffu;
	xs[2] = 0x80000000u;
	xs[3] = 0x7fffffffu;
	for (i = 4; i < 600u; i++)
		xs[i] = (i < 200u) ? i - 4u : rng();
	for (pg_num = 1; pg_num <= 299u; pg_num++) {
		uint32_t m1 = wri_pg_mask(pg_num);

		for (pgp_num = 1; pgp_num <= pg_num; pgp_num++) {
			uint32_t m2 = wri_pg_mask(pgp_num);

			for (i = 0; i < 600u; i++) {
				uint32_t direct = wri_stable_mod(xs[i], pgp_num, m2);
				uint32_t nested = wri_stable_mod(wri_stable_mod(xs[i], pg_num, m1), pgp_num, m2);

				if (direct != nested)
					bad++;
			}
		}
	}
	wrt_checks++;
	if (bad != 0) {
		wrt_failures++;
		fprintf(stderr, "%s:%d: stable_mod nesting differs in %lu cases\n", __FILE__, __LINE__, bad);
	}
}

int main(void)
{
	test_vectors_file();
	test_note_values();
	test_string_lengths();
	test_exact_buffers();
	test_null_input();
	test_dispatch();
	test_hash_random();
	test_cbits_and_mask();
	test_stable_mod_basic();
	test_stable_mod_nested();
	return wrt_finish();
}
