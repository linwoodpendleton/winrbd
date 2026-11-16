/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of core/src/util/wri_misc.c: secure wipe, constant-time compare, checked size
 * arithmetic, 64-bit division (shift-subtract against the native and a 128-bit reference) and the
 * strict base64 decoder (RFC 4648 vectors, the public test keyrings, malformed input).
 */
#include "wrt.h"
#include "wri_misc.h"

/* ---- wipe and compare --------------------------------------------------------------------- */

static void test_secure_zero(void)
{
	uint8_t b[32];
	size_t i;

	memset(b, 0xAB, sizeof(b));
	wri_secure_zero(b + 4, 20);
	for (i = 0; i < sizeof(b); i++)
		WRT_CHECK_U64(b[i], (i >= 4 && i < 24) ? 0 : 0xAB);
	wri_secure_zero(b, 0); /* no-op */
	WRT_CHECK_U64(b[0], 0xAB);
	wri_secure_zero(NULL, 0);
	wri_secure_zero(b, sizeof(b));
	for (i = 0; i < sizeof(b); i++)
		WRT_CHECK_U64(b[i], 0);
}

static void test_ct_memeq(void)
{
	uint8_t a[33], b[33];
	size_t i, n;

	for (i = 0; i < sizeof(a); i++)
		a[i] = (uint8_t)(i * 7 + 1);
	memcpy(b, a, sizeof(a));
	WRT_CHECK_U64(wri_ct_memeq(a, b, sizeof(a)), 1);
	WRT_CHECK_U64(wri_ct_memeq(a, b, 0), 1);
	WRT_CHECK_U64(wri_ct_memeq(NULL, NULL, 0), 1);
	/* a single differing bit at every position and bit gives exactly 0 */
	for (i = 0; i < sizeof(a); i++) {
		unsigned bit;

		for (bit = 0; bit < 8; bit++) {
			b[i] = (uint8_t)(a[i] ^ (1u << bit));
			WRT_CHECK_U64(wri_ct_memeq(a, b, sizeof(a)), 0);
			/* a difference after the compared length does not matter */
			for (n = 0; n <= i; n++)
				if (wri_ct_memeq(a, b, n) != 1)
					WRT_CHECK(0);
		}
		b[i] = a[i];
	}
	/* every byte differing, including 0x00 vs 0xFF (the extreme xor) */
	memset(a, 0x00, sizeof(a));
	memset(b, 0xFF, sizeof(b));
	WRT_CHECK_U64(wri_ct_memeq(a, b, sizeof(a)), 0);
	/* several differing bytes whose xors would cancel in a naive sum */
	a[0] = 1;
	b[0] = 0;
	a[1] = 0;
	b[1] = 1;
	WRT_CHECK_U64(wri_ct_memeq(a, b, 2), 0);
}

/* ---- checked arithmetic ------------------------------------------------------------------- */

static void test_checked_arith(void)
{
	size_t out = 77;
	const size_t M = (size_t)-1;

	WRT_CHECK_STATUS(WR_OK, wri_add_sz(1, 2, &out));
	WRT_CHECK_U64(out, 3);
	WRT_CHECK_STATUS(WR_OK, wri_add_sz(M, 0, &out));
	WRT_CHECK_U64(out, M);
	WRT_CHECK_STATUS(WR_OK, wri_add_sz(M - 5, 5, &out));
	WRT_CHECK_U64(out, M);
	out = 77;
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_add_sz(M, 1, &out));
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_add_sz(1, M, &out));
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_add_sz(M, M, &out));
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_add_sz(M - 5, 6, &out));
	WRT_CHECK_U64(out, 77); /* untouched on failure */
	WRT_CHECK_STATUS(WR_OK, wri_add_sz(1, 2, NULL));
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_add_sz(M, 1, NULL));

	WRT_CHECK_STATUS(WR_OK, wri_mul_sz(6, 7, &out));
	WRT_CHECK_U64(out, 42);
	WRT_CHECK_STATUS(WR_OK, wri_mul_sz(0, M, &out));
	WRT_CHECK_U64(out, 0);
	WRT_CHECK_STATUS(WR_OK, wri_mul_sz(M, 0, &out));
	WRT_CHECK_U64(out, 0);
	WRT_CHECK_STATUS(WR_OK, wri_mul_sz(M, 1, &out));
	WRT_CHECK_U64(out, M);
	WRT_CHECK_STATUS(WR_OK, wri_mul_sz(1, M, &out));
	WRT_CHECK_U64(out, M);
	out = 77;
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_mul_sz(M, 2, &out));
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_mul_sz(2, M, &out));
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_mul_sz(M, M, &out));
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_mul_sz((M / 2) + 1, 2, &out));
	WRT_CHECK_U64(out, 77);
	WRT_CHECK_STATUS(WR_OK, wri_mul_sz(M / 2, 2, &out)); /* largest product of the form 2k that fits */
	WRT_CHECK_U64(out, M - 1);
	WRT_CHECK_STATUS(WR_OK, wri_mul_sz(65536, 65535, &out)); /* a 32-bit host: just under 2^32 */
	WRT_CHECK_U64(out, (uint64_t)65536 * 65535);
	if (sizeof(size_t) == 4)
		WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_mul_sz(65536, 65536, &out));

	WRT_CHECK_STATUS(WR_OK, wri_align_up(0, 16, &out));
	WRT_CHECK_U64(out, 0);
	WRT_CHECK_STATUS(WR_OK, wri_align_up(1, 16, &out));
	WRT_CHECK_U64(out, 16);
	WRT_CHECK_STATUS(WR_OK, wri_align_up(16, 16, &out));
	WRT_CHECK_U64(out, 16);
	WRT_CHECK_STATUS(WR_OK, wri_align_up(17, 1, &out));
	WRT_CHECK_U64(out, 17);
	WRT_CHECK_STATUS(WR_OK, wri_align_up(M - 15, 16, &out)); /* M - 15 is a multiple of 16 */
	WRT_CHECK_U64(out, M - 15);
	out = 77;
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_align_up(M - 14, 16, &out));
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_align_up(M, 2, &out));
	WRT_CHECK_STATUS(WR_OK, wri_align_up(M, 1, &out));
	WRT_CHECK_U64(out, M);
	out = 77;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_align_up(5, 0, &out));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_align_up(5, 3, &out));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_align_up(5, 12, &out));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_align_up(5, M, &out)); /* all bits set is not a power of two */
	WRT_CHECK_U64(out, 77);
	WRT_CHECK_STATUS(WR_OK, wri_align_up(5, (size_t)1 << (sizeof(size_t) * 8 - 1), &out));
	WRT_CHECK_U64(out, (size_t)1 << (sizeof(size_t) * 8 - 1));
}

/* ---- division ----------------------------------------------------------------------------- */

static uint64_t s64;
static uint64_t xs(void)
{
	s64 ^= s64 << 13;
	s64 ^= s64 >> 7;
	s64 ^= s64 << 17;
	return s64;
}

/* A signed value with a random number of significant bits, so small and huge operands are both common. */
static int64_t rand_s64(void)
{
	uint64_t v = xs();
	unsigned bits = (unsigned)(xs() % 64) + 1;

	v = bits == 64 ? v : (v & (((uint64_t)1 << bits) - 1));
	return (xs() & 1) ? (int64_t)(0 - v) : (int64_t)v;
}

static uint32_t rand_u32(void)
{
	uint32_t v = (uint32_t)xs();
	unsigned bits = (unsigned)(xs() % 32) + 1;

	v = bits == 32 ? v : (v & (((uint32_t)1 << bits) - 1));
	return v;
}

#ifdef __SIZEOF_INT128__
__extension__ typedef __int128 wrt_i128;
#endif

/* Reference answer; with 128-bit integers where the compiler has them, otherwise by checking the
 * defining property q * den + r == num with r of the sign of num and |r| < den. */
static int div_matches_reference(int64_t num, uint32_t den, int64_t got)
{
#ifdef __SIZEOF_INT128__
	wrt_i128 want = (wrt_i128)num / (wrt_i128)den;

	return (wrt_i128)got == want;
#else
	int64_t prod = got * (int64_t)den; /* |prod| <= |num|: no overflow */
	int64_t r = num - prod;

	if (r != 0 && ((r < 0) != (num < 0)))
		return 0;
	return (r < 0 ? -(r + 1) + 1 : r) < (int64_t)den; /* |r| < den without negating INT64_MIN */
#endif
}

static void test_div_fixed(void)
{
	WRT_CHECK(wri_div_s64_u32_slow(100, 7) == 14);
	WRT_CHECK(wri_div_s64_u32_slow(-100, 7) == -14); /* truncates toward zero, not floor */
	WRT_CHECK(wri_div_s64_u32_slow(-1, 2) == 0);
	WRT_CHECK(wri_div_s64_u32_slow(1, 2) == 0);
	WRT_CHECK(wri_div_s64_u32_slow(0, 5) == 0);
	WRT_CHECK(wri_div_s64_u32_slow(INT64_MAX, 1) == INT64_MAX);
	WRT_CHECK(wri_div_s64_u32_slow(INT64_MIN, 1) == INT64_MIN);
	WRT_CHECK(wri_div_s64_u32_slow(INT64_MIN, 2) == INT64_MIN / 2);
	WRT_CHECK(wri_div_s64_u32_slow(INT64_MIN, 0xFFFFFFFFu) == INT64_MIN / 0xFFFFFFFFll);
	WRT_CHECK(wri_div_s64_u32_slow(INT64_MIN + 1, 1) == INT64_MIN + 1);
	WRT_CHECK(wri_div_s64_u32_slow(INT64_MAX, 0xFFFFFFFFu) == INT64_MAX / 0xFFFFFFFFll);
	WRT_CHECK(wri_div_s64_u32_slow(0x7FFFFFFFFFFFFFFFll, 0x80000000u) == 0xFFFFFFFFll);
	WRT_CHECK(wri_div_s64_u32_slow(-0x7FFFFFFFFFFFFFFFll, 0x80000000u) == -0xFFFFFFFFll);
	WRT_CHECK(wri_div_s64_u32_slow(1, 0) == 0); /* division by zero is defined as 0, never a trap */
	WRT_CHECK(wri_div_s64_u32_slow(INT64_MIN, 0) == 0);
	WRT_CHECK(wri_div_s64_u32(1, 0) == 0);
	WRT_CHECK(wri_div_s64_u32(-100, 7) == -14);
	WRT_CHECK(wri_div_s64_u32(INT64_MIN, 1) == INT64_MIN);
	WRT_CHECK(wri_div_s64_u32(INT64_MIN, 0xFFFFFFFFu) == INT64_MIN / 0xFFFFFFFFll);
}

static void test_div_random(void)
{
	unsigned long i;
	unsigned long mismatch_slow = 0, mismatch_native = 0, mismatch_ref = 0;

	s64 = 0x2545F4914F6CDD1Dull;
	for (i = 0; i < 1000000ul; i++) {
		int64_t num = rand_s64();
		uint32_t den = rand_u32();
		int64_t slow, nat;

		if (den == 0)
			den = 1;
		if (i % 64 == 0)
			den = (uint32_t)(0xFFFFFFFFu - (xs() & 3)); /* near the top of the divisor range */
		if (i % 97 == 0)
			num = (xs() & 1) ? INT64_MIN + (int64_t)(xs() & 3) : INT64_MAX - (int64_t)(xs() & 3);
		slow = wri_div_s64_u32_slow(num, den);
		nat = wri_div_s64_u32(num, den);
		if (slow != nat)
			mismatch_native++;
		if (!div_matches_reference(num, den, slow))
			mismatch_ref++;
		if (!div_matches_reference(num, den, nat))
			mismatch_slow++;
	}
	WRT_CHECK_U64(mismatch_ref, 0);
	WRT_CHECK_U64(mismatch_slow, 0);
	WRT_CHECK_U64(mismatch_native, 0);
}

/* ---- base64 ------------------------------------------------------------------------------- */

static wr_status b64(const char *s, uint8_t *out, size_t cap, size_t *len)
{
	return wri_b64_decode(s, strlen(s), out, cap, len);
}

static void check_dec(const char *in, const char *want)
{
	uint8_t out[64];
	size_t len = 99;
	wr_status st = b64(in, out, sizeof(out), &len);

	WRT_CHECK_STATUS(WR_OK, st);
	WRT_CHECK_U64(len, strlen(want));
	if (len == strlen(want))
		WRT_CHECK_MEM(out, want, len);
}

static void check_bad(const char *in, wr_status want)
{
	uint8_t out[64];
	size_t len = 99;
	wr_status st;

	memset(out, 0xEE, sizeof(out));
	st = b64(in, out, sizeof(out), &len);
	if (st != want)
		fprintf(stderr, "  (input \"%s\")\n", in);
	WRT_CHECK_STATUS(want, st);
	WRT_CHECK_U64(len, 0);
	/* nothing decoded survives a failure */
	WRT_CHECK(out[0] == 0xEE || out[0] == 0);
}

static void test_b64_rfc4648(void)
{
	check_dec("", "");
	check_dec("Zg==", "f");
	check_dec("Zm8=", "fo");
	check_dec("Zm9v", "foo");
	check_dec("Zm9vYg==", "foob");
	check_dec("Zm9vYmE=", "fooba");
	check_dec("Zm9vYmFy", "foobar");
	/* ASCII whitespace anywhere is skipped, including inside a group and after the padding */
	check_dec("Zm9v\nYmFy\n", "foobar");
	check_dec("  Z m 9 v\tY\r\nmFy ", "foobar");
	check_dec("Zm9vYg==\n\n", "foob");
	check_dec("Zm9vYg\n==", "foob");
	check_dec("\v\f", "");
	/* all 64 digits */
	{
		uint8_t out[48];
		size_t len;
		const char *all = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		WRT_CHECK_STATUS(WR_OK, wri_b64_decode(all, 64, out, sizeof(out), &len));
		WRT_CHECK_U64(len, 48);
		/* digit values 0..63 packed 6 bits each: first three bytes are 0x00 0x10 0x83 */
		WRT_CHECK_U64(out[0], 0x00);
		WRT_CHECK_U64(out[1], 0x10);
		WRT_CHECK_U64(out[2], 0x83);
		/* last group is digits 60 61 62 63 */
		WRT_CHECK_U64(out[45], 0xF3);
		WRT_CHECK_U64(out[46], 0xDF);
		WRT_CHECK_U64(out[47], 0xBF);
	}
}

static void test_b64_malformed(void)
{
	/* padding */
	check_bad("Zg", WR_E_ENCODING);      /* padding missing */
	check_bad("Zg=", WR_E_ENCODING);     /* too little */
	check_bad("Zm8", WR_E_ENCODING);
	check_bad("Zg===", WR_E_ENCODING);   /* too much */
	check_bad("Zm8==", WR_E_ENCODING);
	check_bad("Zm9v=", WR_E_ENCODING);   /* padding after a full group */
	check_bad("Zm9v====", WR_E_ENCODING);
	check_bad("=", WR_E_ENCODING);
	check_bad("====", WR_E_ENCODING);
	check_bad("=Zg=", WR_E_ENCODING);
	check_bad("Z===", WR_E_ENCODING);    /* one digit is not a byte */
	check_bad("Z", WR_E_ENCODING);
	check_bad("Zm9vY", WR_E_ENCODING);
	check_bad("Zg=A", WR_E_ENCODING);    /* digit after padding */
	check_bad("Zg==Zg==", WR_E_ENCODING); /* data after the closing group */
	check_bad("Zm9vYg==Zm9v", WR_E_ENCODING);
	check_bad("Zm8=Zm8=", WR_E_ENCODING);
	/* characters outside the alphabet */
	check_bad("Zm9*", WR_E_ENCODING);
	check_bad("Zm9-", WR_E_ENCODING);    /* URL-safe alphabet is not accepted */
	check_bad("Zm9_", WR_E_ENCODING);
	check_bad("Zm9.", WR_E_ENCODING);
	check_bad("Zm9\xC3\xA9", WR_E_ENCODING);
	check_bad("Zm9\x80", WR_E_ENCODING);
	/* spare bits must be zero: "Zh==" would also decode to "f" but is not canonical */
	check_bad("Zh==", WR_E_ENCODING);
	check_bad("Zm9=", WR_E_ENCODING);    /* '9' has low bits 01 */
	check_bad("Zm9vYh==", WR_E_ENCODING);
	{
		uint8_t out[8];
		size_t len = 99;

		/* an embedded NUL is a bad character, it does not end the string */
		WRT_CHECK_STATUS(WR_E_ENCODING, wri_b64_decode("Zm9v\0YmFy", 9, out, sizeof(out), &len));
		WRT_CHECK_U64(len, 0);
	}
}

static void test_b64_caps_and_args(void)
{
	uint8_t out[8];
	size_t len = 99;
	uint8_t guard[16];

	/* exact fit, one byte short, zero capacity */
	WRT_CHECK_STATUS(WR_OK, b64("Zm9vYmFy", out, 6, &len));
	WRT_CHECK_U64(len, 6);
	WRT_CHECK_STATUS(WR_E_TOOBIG, b64("Zm9vYmFy", out, 5, &len));
	WRT_CHECK_U64(len, 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, b64("Zm9vYg==", out, 3, &len)); /* the padded last group */
	WRT_CHECK_STATUS(WR_OK, b64("Zm9vYg==", out, 4, &len));
	WRT_CHECK_U64(len, 4);
	WRT_CHECK_STATUS(WR_E_TOOBIG, b64("Zg==", out, 0, &len));
	WRT_CHECK_STATUS(WR_OK, b64("", out, 0, &len));
	WRT_CHECK_U64(len, 0);
	WRT_CHECK_STATUS(WR_OK, wri_b64_decode(NULL, 0, NULL, 0, &len));

	/* never writes past cap: guard bytes behind a tight buffer stay intact */
	memset(guard, 0x5A, sizeof(guard));
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_b64_decode("Zm9vYmFyZm9vYmFy", 16, guard, 8, &len));
	WRT_CHECK_U64(guard[8], 0x5A);
	WRT_CHECK_U64(guard[15], 0x5A);
	/* what was decoded before the failure is wiped */
	WRT_CHECK_U64(guard[0] | guard[5], 0);

	/* argument errors */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_b64_decode("Zg==", 4, out, 8, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_b64_decode(NULL, 4, out, 8, &len));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_b64_decode("Zg==", 4, NULL, 8, &len));
	WRT_CHECK_U64(len, 0);
}

/* Reference encoder for the round trip. */
static size_t enc64(const uint8_t *p, size_t n, char *out)
{
	static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i, o = 0;

	for (i = 0; i < n; i += 3) {
		uint32_t v = (uint32_t)p[i] << 16;
		size_t left = n - i;

		if (left > 1)
			v |= (uint32_t)p[i + 1] << 8;
		if (left > 2)
			v |= p[i + 2];
		out[o++] = tab[(v >> 18) & 63];
		out[o++] = tab[(v >> 12) & 63];
		out[o++] = left > 1 ? tab[(v >> 6) & 63] : '=';
		out[o++] = left > 2 ? tab[v & 63] : '=';
	}
	out[o] = 0;
	return o;
}

static void test_b64_roundtrip(void)
{
	unsigned n, iter;

	s64 = 0x9E3779B97F4A7C15ull;
	for (n = 0; n <= 100; n++) {
		for (iter = 0; iter < 20; iter++) {
			uint8_t src[100], dec[104];
			char text[160];
			size_t tl, len = 0, i;

			for (i = 0; i < n; i++)
				src[i] = (uint8_t)xs();
			tl = enc64(src, n, text);
			WRT_CHECK_STATUS(WR_OK, wri_b64_decode(text, tl, dec, sizeof(dec), &len));
			WRT_CHECK_U64(len, n);
			WRT_CHECK_MEM(dec, src, n);
			/* one corrupted character must either fail or decode to something else, never crash */
			if (tl > 0) {
				size_t k = (size_t)(xs() % tl);
				char saved = text[k];

				text[k] = '!';
				WRT_CHECK_STATUS(WR_E_ENCODING, wri_b64_decode(text, tl, dec, sizeof(dec), &len));
				text[k] = saved;
			}
			/* dropping the last character always fails: wrong length */
			if (tl > 0)
				WRT_CHECK_STATUS(WR_E_ENCODING, wri_b64_decode(text, tl - 1, dec, sizeof(dec), &len));
		}
	}
}

/* The public test keyrings: "key = <base64 of the cephx key encoding>" (cephx.md 2.3): a u16 type,
 * a 4-byte timestamp pair, a u16 length and the secret. Type 1 -> 28 bytes, type 2 -> 44 bytes. */
static void test_b64_keyrings(void)
{
	static const struct {
		const char *file;
		size_t raw_len;
		uint8_t type;
	} files[] = {
		{"public/keys/client.vec-k1.keyring", 28, 1},
		{"public/keys/wrong.vec-k1.keyring", 28, 1},
		{"public/keys/client.vec-k2.keyring", 44, 2},
		{"public/keys/wrong.vec-k2.keyring", 44, 2},
	};
	size_t f;

	for (f = 0; f < sizeof(files) / sizeof(files[0]); f++) {
		uint8_t *text = NULL;
		size_t tlen = 0, i, start = 0, end;
		uint8_t raw[64];
		size_t rawlen = 0;
		int found = 0;

		if (wrt_read_file(wrt_vec_path(files[f].file), &text, &tlen) != 0) {
			WRT_CHECK(0);
			continue;
		}
		for (i = 0; i + 3 < tlen; i++) {
			if (memcmp(text + i, "key", 3) == 0 && (i == 0 || text[i - 1] == '\n' || text[i - 1] == '\t' || text[i - 1] == ' ')) {
				size_t j = i + 3;

				while (j < tlen && (text[j] == ' ' || text[j] == '\t'))
					j++;
				if (j < tlen && text[j] == '=') {
					j++;
					start = j;
					found = 1;
					break;
				}
			}
		}
		WRT_CHECK(found);
		if (found) {
			wr_status st;

			end = start;
			while (end < tlen && text[end] != '\n' && text[end] != '\r')
				end++;
			st = wri_b64_decode((const char *)text + start, end - start, raw, sizeof(raw), &rawlen);
			WRT_CHECK_STATUS(WR_OK, st);
			WRT_CHECK_U64(rawlen, files[f].raw_len);
			WRT_CHECK_U64(raw[0], files[f].type); /* little-endian u16 type */
			WRT_CHECK_U64(raw[1], 0);
			/* the secret length field at offset 10 matches the remaining bytes */
			WRT_CHECK_U64(raw[10] | ((unsigned)raw[11] << 8), files[f].raw_len - 12);
			/* a decoded key is wiped when the cap is too small for it */
			WRT_CHECK_STATUS(WR_E_TOOBIG,
					 wri_b64_decode((const char *)text + start, end - start, raw, rawlen - 1, &rawlen));
			/* the whole file tail (newline and all) decodes the same: trailing whitespace is skipped */
			WRT_CHECK_STATUS(WR_OK, wri_b64_decode((const char *)text + start, tlen - start, raw, sizeof(raw), &rawlen));
			WRT_CHECK_U64(rawlen, files[f].raw_len);
		}
		memset(raw, 0, sizeof(raw));
		free(text);
	}
}

int main(void)
{
	test_secure_zero();
	test_ct_memeq();
	test_checked_arith();
	test_div_fixed();
	test_div_random();
	test_b64_rfc4648();
	test_b64_malformed();
	test_b64_caps_and_args();
	test_b64_roundtrip();
	test_b64_keyrings();
	return wrt_finish();
}
