/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_hash - SHA-256, SHA-384 and HMAC-SHA256/384 (wri_hash.h).
 *
 * Known answers come from FIPS 180-4 (the example messages) and RFC 4231 (HMAC test cases 1 to 7);
 * the "sweep" digests (a hash over the digests of many inputs, covering every padding boundary and
 * every key length around the block sizes) were computed once with an independent implementation.
 * On top of that: streaming equals one-shot for every split offset, gather lists cut at pseudo
 * random points equal the concatenated input, the empty list, the 64/128-bit counters, and the
 * context is all zero after final. Vector files: msgr2/preauth-hmac.json, secure/pre-auth-signature-synthetic.json,
 * cephx/challenge-proof.json, cephx/rfc8009-*.json and cephx/cipher-type2.json (the 24-byte HMAC-SHA384 tag).
 */
#include "wrt.h"
#include "wri_hash.h"

/* ---- helpers --------------------------------------------------------------------------------- */

static uint32_t rng_state = 0x1234abcdu;

static uint32_t rng(void)
{
	rng_state = rng_state * 1664525u + 1013904223u; /* LCG, fixed seed: runs are reproducible */
	return rng_state >> 8;
}

static void check_hex(const uint8_t *got, size_t n, const char *hex, const char *what)
{
	char buf[2 * 64 + 1];

	wrt_checks++;
	wrt_hex_encode(got, n, buf);
	if (strcmp(buf, hex) != 0) {
		wrt_failures++;
		fprintf(stderr, "%s: got  %s\n%s: want %s\n", what, buf, what, hex);
	}
}

/* prefix compare for the truncated RFC 4231 case 5 */
static void check_hex_prefix(const uint8_t *got, size_t n, const char *hex, const char *what)
{
	char buf[2 * 64 + 1];

	wrt_checks++;
	wrt_hex_encode(got, n, buf);
	if (strncmp(buf, hex, strlen(hex)) != 0) {
		wrt_failures++;
		fprintf(stderr, "%s: got  %s\n%s: want %s...\n", what, buf, what, hex);
	}
}

static void sha256_oneshot(const uint8_t *p, size_t n, uint8_t out[32])
{
	wri_sha256_ctx c;

	wri_sha256_init(&c);
	wri_sha256_update(&c, p, n);
	wri_sha256_final(&c, out);
}

static void sha384_oneshot(const uint8_t *p, size_t n, uint8_t out[48])
{
	wri_sha512_ctx c;

	wri_sha384_init(&c);
	wri_sha384_update(&c, p, n);
	wri_sha384_final(&c, out);
}

static int all_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != 0)
			return 0;
	return 1;
}

/* ---- SHA-256 / SHA-384 known answers --------------------------------------------------------- */

static const char *const m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static const char *const m896 =
	"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

typedef struct kat {
	const char *name;
	const char *msg;
	const char *sha256;
	const char *sha384;
} kat;

static const kat kats[] = {
	{"empty", "",
	 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	 "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
	{"abc", "abc",
	 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	 "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
	{"448 bit", NULL /* m448 */,
	 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
	 "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b"},
	{"896 bit", NULL /* m896 */,
	 "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
	 "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"},
};

static void test_known_answers(void)
{
	size_t i;
	uint8_t d256[32], d384[48];

	for (i = 0; i < sizeof(kats) / sizeof(kats[0]); i++) {
		const char *msg = kats[i].msg;

		if (msg == NULL)
			msg = (i == 2) ? m448 : m896;
		sha256_oneshot((const uint8_t *)msg, strlen(msg), d256);
		sha384_oneshot((const uint8_t *)msg, strlen(msg), d384);
		check_hex(d256, 32, kats[i].sha256, "sha256 kat");
		check_hex(d384, 48, kats[i].sha384, "sha384 kat");
	}
	WRT_CHECK_U64(strlen(m448) * 8, 448);
	WRT_CHECK_U64(strlen(m896) * 8, 896);
}

static void test_million_a(void)
{
	wri_sha256_ctx c256;
	wri_sha512_ctx c384;
	uint8_t chunk[1000];
	uint8_t d256[32], d384[48];
	int i;

	memset(chunk, 'a', sizeof(chunk));
	wri_sha256_init(&c256);
	wri_sha384_init(&c384);
	for (i = 0; i < 1000; i++) {
		wri_sha256_update(&c256, chunk, sizeof(chunk));
		wri_sha384_update(&c384, chunk, sizeof(chunk));
	}
	wri_sha256_final(&c256, d256);
	wri_sha384_final(&c384, d384);
	check_hex(d256, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "sha256 1M a");
	check_hex(d384, 48,
		  "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
		  "sha384 1M a");

	/* the same million bytes in awkward, varying chunk sizes */
	wri_sha256_init(&c256);
	wri_sha384_init(&c384);
	{
		size_t left = 1000000, step = 1;

		while (left > 0) {
			size_t n = step < left ? step : left;

			wri_sha256_update(&c256, chunk, n > sizeof(chunk) ? sizeof(chunk) : n);
			wri_sha384_update(&c384, chunk, n > sizeof(chunk) ? sizeof(chunk) : n);
			if (n > sizeof(chunk)) {
				/* feed the rest of an oversized step in further calls */
				size_t more = n - sizeof(chunk);

				while (more > 0) {
					size_t m = more < sizeof(chunk) ? more : sizeof(chunk);

					wri_sha256_update(&c256, chunk, m);
					wri_sha384_update(&c384, chunk, m);
					more -= m;
				}
			}
			left -= n;
			step = step * 3u + 1u;
			if (step > 5000)
				step = (step % 61u) + 1u;
		}
	}
	wri_sha256_final(&c256, d256);
	wri_sha384_final(&c384, d384);
	check_hex(d256, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", "sha256 1M a (odd chunks)");
	check_hex(d384, 48,
		  "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
		  "sha384 1M a (odd chunks)");
}

/* ---- every length 0..300: padding boundaries ------------------------------------------------- */

static void pattern(uint8_t *p, size_t n, unsigned mul, unsigned add)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)((i * mul + add) & 0xffu);
}

static void test_length_sweep(void)
{
	uint8_t msg[300];
	uint8_t acc256[301 * 32];
	uint8_t acc384[301 * 48];
	uint8_t d256[32], d384[48];
	size_t len;

	for (len = 0; len <= 300; len++) {
		pattern(msg, len, 7, 3);
		sha256_oneshot(msg, len, acc256 + len * 32);
		sha384_oneshot(msg, len, acc384 + len * 48);
	}
	sha256_oneshot(acc256, sizeof(acc256), d256);
	sha384_oneshot(acc384, sizeof(acc384), d384);
	check_hex(d256, 32, "7d917fbd2cf49ddff9ad0a8706bba32d204e92e71d2e369c5a03d6af29278c9f", "sha256 sweep");
	check_hex(d384, 48,
		  "efec719c84acba157f057b3a8be4ab46d8d39b7f85dca15c051420621873dcdbf6b165d5061f55337fce615e1957e330",
		  "sha384 sweep");
}

/* ---- incremental == one-shot ----------------------------------------------------------------- */

static void test_incremental(void)
{
	static const size_t lens[] = {200, 300};
	uint8_t msg[300];
	uint8_t want256[32], want384[48], got256[32], got384[48];
	size_t li, off, i;

	for (li = 0; li < sizeof(lens) / sizeof(lens[0]); li++) {
		size_t len = lens[li];

		pattern(msg, len, 13, 5);
		sha256_oneshot(msg, len, want256);
		sha384_oneshot(msg, len, want384);

		/* two pieces split at every offset 0..200 (offsets past the end are clamped) */
		for (off = 0; off <= 200; off++) {
			size_t cut = off < len ? off : len;
			wri_sha256_ctx c256;
			wri_sha512_ctx c384;

			wri_sha256_init(&c256);
			wri_sha256_update(&c256, msg, cut);
			wri_sha256_update(&c256, msg + cut, len - cut);
			wri_sha256_final(&c256, got256);
			WRT_CHECK_MEM(got256, want256, 32);

			wri_sha384_init(&c384);
			wri_sha384_update(&c384, msg, cut);
			wri_sha384_update(&c384, msg + cut, len - cut);
			wri_sha384_final(&c384, got384);
			WRT_CHECK_MEM(got384, want384, 48);
		}

		/* byte at a time, and with empty updates (NULL, 0) sprinkled in */
		{
			wri_sha256_ctx c256;
			wri_sha512_ctx c384;

			wri_sha256_init(&c256);
			wri_sha384_init(&c384);
			for (i = 0; i < len; i++) {
				wri_sha256_update(&c256, msg + i, 1);
				wri_sha384_update(&c384, msg + i, 1);
				if (i % 7 == 0) {
					wri_sha256_update(&c256, NULL, 0);
					wri_sha384_update(&c384, NULL, 0);
				}
			}
			wri_sha256_final(&c256, got256);
			wri_sha384_final(&c384, got384);
			WRT_CHECK_MEM(got256, want256, 32);
			WRT_CHECK_MEM(got384, want384, 48);
		}

		/* three pieces at pseudo-random cut points */
		for (i = 0; i < 300; i++) {
			size_t a = rng() % (len + 1), b = rng() % (len + 1), t;
			wri_sha256_ctx c256;
			wri_sha512_ctx c384;

			if (a > b) {
				t = a;
				a = b;
				b = t;
			}
			wri_sha256_init(&c256);
			wri_sha256_update(&c256, msg, a);
			wri_sha256_update(&c256, msg + a, b - a);
			wri_sha256_update(&c256, msg + b, len - b);
			wri_sha256_final(&c256, got256);
			WRT_CHECK_MEM(got256, want256, 32);

			wri_sha384_init(&c384);
			wri_sha384_update(&c384, msg, a);
			wri_sha384_update(&c384, msg + a, b - a);
			wri_sha384_update(&c384, msg + b, len - b);
			wri_sha384_final(&c384, got384);
			WRT_CHECK_MEM(got384, want384, 48);
		}
	}
}

/* ---- counters and wiping --------------------------------------------------------------------- */

static void test_counters(void)
{
	wri_sha256_ctx c256;
	wri_sha512_ctx c384;
	uint8_t msg[40];

	memset(msg, 0x5a, sizeof(msg));

	wri_sha256_init(&c256);
	wri_sha256_update(&c256, msg, 40);
	wri_sha256_update(&c256, msg, 0);
	WRT_CHECK_U64(c256.total, 40);
	WRT_CHECK_U64(c256.fill, 40);
	wri_sha256_update(&c256, msg, 40);
	WRT_CHECK_U64(c256.total, 80);
	WRT_CHECK_U64(c256.fill, 16);

	wri_sha384_init(&c384);
	WRT_CHECK_U64(c384.total_lo, 0);
	WRT_CHECK_U64(c384.total_hi, 0);
	c384.total_lo = UINT64_MAX - 15u; /* white-box: carry from the low into the high word */
	wri_sha384_update(&c384, msg, 40);
	WRT_CHECK_U64(c384.total_lo, 24);
	WRT_CHECK_U64(c384.total_hi, 1);
	wri_sha384_update(&c384, msg, 0);
	WRT_CHECK_U64(c384.total_hi, 1);
}

static void test_wipe_after_final(void)
{
	wri_sha256_ctx c256;
	wri_sha512_ctx c384;
	uint8_t out256[32], out384[48];
	uint8_t msg[150];
	static const size_t lens[] = {0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 150};
	size_t i;

	pattern(msg, sizeof(msg), 3, 9);
	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		wri_sha256_init(&c256);
		wri_sha256_update(&c256, msg, lens[i]);
		wri_sha256_final(&c256, out256);
		WRT_CHECK(all_zero(&c256, sizeof(c256)));

		wri_sha384_init(&c384);
		wri_sha384_update(&c384, msg, lens[i]);
		wri_sha384_final(&c384, out384);
		WRT_CHECK(all_zero(&c384, sizeof(c384)));
	}
}

/* ---- HMAC: RFC 4231 -------------------------------------------------------------------------- */

typedef struct hmac_case {
	const char *name;
	uint8_t key[131];
	size_t klen;
	uint8_t data[160];
	size_t dlen;
	int trunc; /* bytes compared when the RFC gives only a truncated value, else 0 */
	const char *h256;
	const char *h384;
} hmac_case;

static void set_str(uint8_t *dst, size_t *len, const char *s)
{
	*len = strlen(s);
	memcpy(dst, s, *len);
}

static void test_hmac_rfc4231(void)
{
	static hmac_case cases[7];
	size_t i;

	memset(cases, 0, sizeof(cases));

	cases[0].name = "rfc4231 case 1";
	memset(cases[0].key, 0x0b, 20);
	cases[0].klen = 20;
	set_str(cases[0].data, &cases[0].dlen, "Hi There");
	cases[0].h256 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
	cases[0].h384 = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6";

	cases[1].name = "rfc4231 case 2";
	set_str(cases[1].key, &cases[1].klen, "Jefe");
	set_str(cases[1].data, &cases[1].dlen, "what do ya want for nothing?");
	cases[1].h256 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
	cases[1].h384 = "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649";

	cases[2].name = "rfc4231 case 3";
	memset(cases[2].key, 0xaa, 20);
	cases[2].klen = 20;
	memset(cases[2].data, 0xdd, 50);
	cases[2].dlen = 50;
	cases[2].h256 = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
	cases[2].h384 = "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27";

	cases[3].name = "rfc4231 case 4";
	for (i = 0; i < 25; i++)
		cases[3].key[i] = (uint8_t)(i + 1);
	cases[3].klen = 25;
	memset(cases[3].data, 0xcd, 50);
	cases[3].dlen = 50;
	cases[3].h256 = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";
	cases[3].h384 = "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb";

	/* case 5: the RFC publishes only the first 128 bits */
	cases[4].name = "rfc4231 case 5";
	memset(cases[4].key, 0x0c, 20);
	cases[4].klen = 20;
	set_str(cases[4].data, &cases[4].dlen, "Test With Truncation");
	cases[4].trunc = 16;
	cases[4].h256 = "a3b6167473100ee06e0c796c2955552b";
	cases[4].h384 = "3abf34c3503b2a23a46efc619baef897";

	/* case 6: key longer than the block of either hash (131 bytes) */
	cases[5].name = "rfc4231 case 6";
	memset(cases[5].key, 0xaa, 131);
	cases[5].klen = 131;
	set_str(cases[5].data, &cases[5].dlen, "Test Using Larger Than Block-Size Key - Hash Key First");
	cases[5].h256 = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";
	cases[5].h384 = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952";

	/* case 7: long key and data longer than a block */
	cases[6].name = "rfc4231 case 7";
	memset(cases[6].key, 0xaa, 131);
	cases[6].klen = 131;
	set_str(cases[6].data, &cases[6].dlen,
		"This is a test using a larger than block-size key and a larger than block-size data. "
		"The key needs to be hashed before being used by the HMAC algorithm.");
	cases[6].h256 = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2";
	cases[6].h384 = "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e";

	for (i = 0; i < 7; i++) {
		const hmac_case *tc = &cases[i];
		wr_iov iov;
		uint8_t o256[32], o384[48];

		iov.base = tc->data;
		iov.len = tc->dlen;
		wri_hmac_sha256(tc->key, tc->klen, &iov, 1, o256);
		wri_hmac_sha384(tc->key, tc->klen, &iov, 1, o384);
		if (tc->trunc) {
			check_hex_prefix(o256, 32, tc->h256, tc->name);
			check_hex_prefix(o384, 48, tc->h384, tc->name);
		} else {
			check_hex(o256, 32, tc->h256, tc->name);
			check_hex(o384, 48, tc->h384, tc->name);
		}
	}
	WRT_CHECK_U64(cases[6].dlen, 152);
}

/* ---- HMAC: key length sweep, gather lists, empty list ---------------------------------------- */

static void test_hmac_key_sweep(void)
{
	uint8_t key[300], msg[100];
	uint8_t acc256[301 * 32];
	uint8_t acc384[301 * 48];
	uint8_t d256[32], d384[48];
	size_t k;

	for (k = 0; k <= 300; k++) {
		size_t ml = (k * 3) % 97;
		wr_iov iov;

		pattern(key, k, 5, 1);
		pattern(msg, ml, 11, 7);
		iov.base = msg;
		iov.len = ml;
		wri_hmac_sha256(key, k, &iov, 1, acc256 + k * 32);
		wri_hmac_sha384(key, k, &iov, 1, acc384 + k * 48);
	}
	sha256_oneshot(acc256, sizeof(acc256), d256);
	sha384_oneshot(acc384, sizeof(acc384), d384);
	check_hex(d256, 32, "6d652fc108e9d9edc0b7ee9af618e8719b88089f165efaf5a9c2e514c0714710", "hmac256 key sweep");
	check_hex(d384, 48,
		  "8d0f0730e8a1271e8b877d306d5c7ef49d5cc90cca0df1afe09df693fe9ef3118860b3b7164f129bbefd0bb0c7a4849d",
		  "hmac384 key sweep");
}

#define MAX_PIECES 12

static void test_hmac_iov(void)
{
	uint8_t key[300], msg[400];
	uint8_t want256[32], got256[32], want384[48], got384[48];
	wr_iov one, iov[MAX_PIECES];
	size_t round;

	pattern(msg, sizeof(msg), 29, 17);
	for (round = 0; round < 2000; round++) {
		size_t klen = rng() % 301, mlen = rng() % 401;
		size_t npieces = 1 + rng() % MAX_PIECES, pos = 0, p;

		pattern(key, klen, 3, (unsigned)(round & 0xffu));
		one.base = msg;
		one.len = mlen;
		wri_hmac_sha256(key, klen, &one, 1, want256);
		wri_hmac_sha384(key, klen, &one, 1, want384);

		/* cut the same bytes into npieces random pieces; some are empty (base may be NULL) */
		for (p = 0; p < npieces; p++) {
			size_t take = (p + 1 == npieces) ? mlen - pos : rng() % (mlen - pos + 1);

			if (take == 0 && (rng() & 1u)) {
				iov[p].base = NULL;
			} else {
				iov[p].base = msg + pos;
			}
			iov[p].len = take;
			pos += take;
		}
		WRT_CHECK_U64(pos, mlen);
		wri_hmac_sha256(key, klen, iov, npieces, got256);
		wri_hmac_sha384(key, klen, iov, npieces, got384);
		WRT_CHECK_MEM(got256, want256, 32);
		WRT_CHECK_MEM(got384, want384, 48);
	}
}

static void test_hmac_empty(void)
{
	static const uint8_t key[3] = {'k', 'e', 'y'};
	wr_iov zero;
	uint8_t o256[32], o384[48];

	/* empty list: HMAC of the empty message */
	wri_hmac_sha256(key, sizeof(key), NULL, 0, o256);
	wri_hmac_sha384(key, sizeof(key), NULL, 0, o384);
	check_hex(o256, 32, "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0", "hmac256 empty list");
	check_hex(o384, 48,
		  "99f44bb4e73c9d0ef26533596c8d8a32a5f8c10a9b997d30d89a7e35ba1ccf200b985f72431202b891fe350da410e43f",
		  "hmac384 empty list");

	/* one zero-length element, NULL base: same thing */
	zero.base = NULL;
	zero.len = 0;
	memset(o256, 0xee, sizeof(o256));
	memset(o384, 0xee, sizeof(o384));
	wri_hmac_sha256(key, sizeof(key), &zero, 1, o256);
	wri_hmac_sha384(key, sizeof(key), &zero, 1, o384);
	check_hex(o256, 32, "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0", "hmac256 empty element");
	check_hex(o384, 48,
		  "99f44bb4e73c9d0ef26533596c8d8a32a5f8c10a9b997d30d89a7e35ba1ccf200b985f72431202b891fe350da410e43f",
		  "hmac384 empty element");

	/* empty key and empty message must not crash and must be deterministic (key NULL allowed) */
	{
		uint8_t a[32], b[32];

		wri_hmac_sha256(NULL, 0, NULL, 0, a);
		wri_hmac_sha256(key, 0, NULL, 0, b);
		WRT_CHECK_MEM(a, b, 32);
		/* HMAC-SHA256 of the empty key and empty message (independently computed) */
		check_hex(a, 32, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad", "hmac256 empty/empty");
	}
}

/* ---- vectors committed in harness/vectors/ (public / synthetic) ------------------------------ */

static int load_vec(wrt_json *j, const char *rel)
{
	if (wrt_json_load_vec(j, rel) != 0) {
		wrt_checks++;
		wrt_failures++;
		fprintf(stderr, "cannot load vector file %s\n", rel);
		return -1;
	}
	return 0;
}

static void hmac256_one(const uint8_t *key, size_t klen, const uint8_t *msg, size_t n, uint8_t out[32])
{
	wr_iov iov;

	iov.base = msg;
	iov.len = n;
	wri_hmac_sha256(key, klen, &iov, 1, out);
}

/* msgr2 AUTH_SIGNATURE (docs/spec/msgr2.md 3.3): both signatures, and the must_not_verify cases. */
static void test_vec_preauth(void)
{
	wrt_json j;
	uint8_t *key = NULL, *rx = NULL, *tx = NULL, *csig = NULL, *ssig = NULL;
	size_t klen = 0, rxn = 0, txn = 0, cn = 0, sn = 0;
	uint8_t mac[32];
	wrt_tok root, bad, t;
	size_t i;

	if (load_vec(&j, "msgr2/preauth-hmac.json") != 0)
		return;
	root = wrt_json_root(&j);
	WRT_CHECK(wrt_json_get_hex(&j, root, "session_key_secret_hex", &key, &klen) == 0);
	WRT_CHECK(wrt_json_get_hex(&j, root, "bytes_received_by_client_hex", &rx, &rxn) == 0);
	WRT_CHECK(wrt_json_get_hex(&j, root, "bytes_sent_by_client_hex", &tx, &txn) == 0);
	WRT_CHECK(wrt_json_get_hex(&j, root, "client_signature_hex", &csig, &cn) == 0);
	WRT_CHECK(wrt_json_get_hex(&j, root, "server_signature_hex", &ssig, &sn) == 0);
	if (key && rx && tx && csig && ssig && cn == 32 && sn == 32 && rxn > 0) {
		hmac256_one(key, klen, rx, rxn, mac);
		WRT_CHECK_MEM(mac, csig, 32);
		hmac256_one(key, klen, tx, txn, mac);
		WRT_CHECK_MEM(mac, ssig, 32);

		/* every must_not_verify value is a 32-byte MAC that must differ from both real ones */
		bad = wrt_json_get(&j, root, "must_not_verify");
		WRT_CHECK(bad != WRT_NONE);
		for (i = 0; bad != WRT_NONE && i < wrt_json_count(&j, bad); i++) {
			uint8_t *v = NULL;
			size_t vn = 0;

			(void)wrt_json_key_at(&j, bad, i, &t);
			WRT_CHECK(wrt_json_hex(&j, t, &v, &vn) == 0);
			WRT_CHECK_U64(vn, 32);
			if (v && vn == 32) {
				WRT_CHECK(memcmp(v, csig, 32) != 0);
				WRT_CHECK(memcmp(v, ssig, 32) != 0);
			}
			free(v);
		}
		/* a one-bit change anywhere in the transcript changes the MAC */
		rx[rxn / 2] ^= 0x01u;
		hmac256_one(key, klen, rx, rxn, mac);
		WRT_CHECK(memcmp(mac, csig, 32) != 0);
		/* and so does a one-bit change in the key */
		rx[rxn / 2] ^= 0x01u;
		key[0] ^= 0x80u;
		hmac256_one(key, klen, rx, rxn, mac);
		WRT_CHECK(memcmp(mac, csig, 32) != 0);
	} else {
		WRT_CHECK(0);
	}
	free(key);
	free(rx);
	free(tx);
	free(csig);
	free(ssig);
	wrt_json_free(&j);
}

static void test_vec_preauth_synthetic(void)
{
	wrt_json j;
	wrt_tok cases;
	size_t i;

	if (load_vec(&j, "secure/pre-auth-signature-synthetic.json") != 0)
		return;
	cases = wrt_json_get(&j, wrt_json_root(&j), "cases");
	WRT_CHECK(cases != WRT_NONE && wrt_json_count(&j, cases) >= 2);
	for (i = 0; cases != WRT_NONE && i < wrt_json_count(&j, cases); i++) {
		wrt_tok c = wrt_json_at(&j, cases, i);
		uint8_t *key = NULL, *tr = NULL, *want = NULL;
		size_t kn = 0, tn = 0, wn = 0;
		uint8_t mac[32];

		if (wrt_json_get_hex(&j, c, "session_key_secret_hex", &key, &kn) == 0 &&
		    wrt_json_get_hex(&j, c, "transcript_hex", &tr, &tn) == 0 &&
		    wrt_json_get_hex(&j, c, "hmac_sha256_hex", &want, &wn) == 0 && wn == 32) {
			hmac256_one(key, kn, tr, tn, mac);
			WRT_CHECK_MEM(mac, want, 32);
		} else {
			WRT_CHECK(0);
		}
		free(key);
		free(tr);
		free(want);
	}
	wrt_json_free(&j);
}

/* cephx 2.8 challenge proof for key types other than 1: HMAC-SHA256(secret, blob). */
static void test_vec_challenge_proof(void)
{
	wrt_json j;
	wrt_tok vs;
	size_t i, seen = 0;

	if (load_vec(&j, "cephx/challenge-proof.json") != 0)
		return;
	vs = wrt_json_get(&j, wrt_json_root(&j), "vectors");
	for (i = 0; vs != WRT_NONE && i < wrt_json_count(&j, vs); i++) {
		wrt_tok v = wrt_json_at(&j, vs, i);
		uint8_t *key = NULL, *blob = NULL, *want = NULL;
		size_t kn = 0, bn = 0, wn = 0;
		uint8_t mac[32];

		if (wrt_json_get(&j, v, "hmac_sha256_digest") == WRT_NONE)
			continue; /* type 1 has no HMAC */
		if (wrt_json_get_hex(&j, v, "key_secret", &key, &kn) == 0 &&
		    wrt_json_get_hex(&j, v, "blob", &blob, &bn) == 0 &&
		    wrt_json_get_hex(&j, v, "hmac_sha256_digest", &want, &wn) == 0 && wn == 32) {
			hmac256_one(key, kn, blob, bn, mac);
			WRT_CHECK_MEM(mac, want, 32);
			seen++;
		} else {
			WRT_CHECK(0);
		}
		free(key);
		free(blob);
		free(want);
	}
	WRT_CHECK(seen >= 1);
	wrt_json_free(&j);
}

/* The 24-byte tag of cephx type 2 / RFC 8009: first 24 bytes of HMAC-SHA384(Ki, 16 zero bytes ||
 * ciphertext). Checks the RFC 8009 appendix vectors and the synthetic cephx ones. */
static void mac24(const uint8_t *ki, size_t kn, const uint8_t *ct, size_t n, uint8_t out[24])
{
	static const uint8_t zero_iv[16] = {0};
	wr_iov iov[2];
	uint8_t full[48];

	iov[0].base = zero_iv;
	iov[0].len = sizeof(zero_iv);
	iov[1].base = ct;
	iov[1].len = n;
	wri_hmac_sha384(ki, kn, iov, 2, full);
	memcpy(out, full, 24);
}

static void test_vec_type2_mac(void)
{
	wrt_json j;
	wrt_tok vs, root;
	size_t i, seen = 0;
	uint8_t *ki_rfc = NULL;
	size_t ki_rfc_n = 0;

	if (load_vec(&j, "cephx/rfc8009-aes256-cts-hmac-sha384-192.json") == 0) {
		root = wrt_json_root(&j);
		vs = wrt_json_get(&j, root, "vectors");
		WRT_CHECK(wrt_json_get_hex(&j, root, "ki_usage2", &ki_rfc, &ki_rfc_n) == 0);
		for (i = 0; vs != WRT_NONE && ki_rfc && i < wrt_json_count(&j, vs); i++) {
			wrt_tok v = wrt_json_at(&j, vs, i);
			uint8_t *aes = NULL, *tag = NULL;
			size_t an = 0, tn = 0;
			uint8_t mac[24];

			if (wrt_json_get_hex(&j, v, "aes_output", &aes, &an) == 0 &&
			    wrt_json_get_hex(&j, v, "truncated_hmac", &tag, &tn) == 0 && tn == 24) {
				mac24(ki_rfc, ki_rfc_n, aes, an, mac);
				WRT_CHECK_MEM(mac, tag, 24);
				seen++;
			} else {
				WRT_CHECK(0);
			}
			free(aes);
			free(tag);
		}
		WRT_CHECK(seen >= 4);
		free(ki_rfc);
		wrt_json_free(&j);
	}

	seen = 0;
	if (load_vec(&j, "cephx/cipher-type2.json") == 0) {
		wrt_tok derived;

		root = wrt_json_root(&j);
		derived = wrt_json_get(&j, root, "derived");
		vs = wrt_json_get(&j, root, "vectors");
		for (i = 0; vs != WRT_NONE && derived != WRT_NONE && i < wrt_json_count(&j, vs); i++) {
			wrt_tok v = wrt_json_at(&j, vs, i);
			char key[8];
			wrt_tok d;
			uint8_t *ki = NULL, *cwm = NULL;
			size_t kn = 0, cn = 0;
			int ok = 0;
			int64_t usage = wrt_json_int(&j, wrt_json_get(&j, v, "usage"), &ok);

			if (!ok || usage < 0 || usage > 0xff) {
				WRT_CHECK(0);
				continue;
			}
			snprintf(key, sizeof(key), "0x%02x", (unsigned)usage);
			d = wrt_json_get(&j, derived, key);
			if (d != WRT_NONE && wrt_json_get_hex(&j, d, "ki", &ki, &kn) == 0 &&
			    wrt_json_get_hex(&j, v, "ciphertext_with_mac", &cwm, &cn) == 0 && cn >= 24) {
				uint8_t mac[24];

				mac24(ki, kn, cwm, cn - 24, mac);
				WRT_CHECK_MEM(mac, cwm + cn - 24, 24);
				seen++;
			} else {
				WRT_CHECK(0);
			}
			free(ki);
			free(cwm);
		}
		WRT_CHECK(seen >= 4);
		wrt_json_free(&j);
	}
}

/* ---- API corner cases ------------------------------------------------------------------------ */

/* The digest must not depend on the output buffer's previous content or on the context's old bytes. */
static void test_dirty_buffers(void)
{
	uint8_t msg[77];
	uint8_t want256[32], want384[48], got256[32], got384[48];
	wri_sha256_ctx c256;
	wri_sha512_ctx c384;

	pattern(msg, sizeof(msg), 17, 2);
	sha256_oneshot(msg, sizeof(msg), want256);
	sha384_oneshot(msg, sizeof(msg), want384);

	memset(&c256, 0xa5, sizeof(c256));
	memset(&c384, 0xa5, sizeof(c384));
	memset(got256, 0xee, sizeof(got256));
	memset(got384, 0xee, sizeof(got384));
	wri_sha256_init(&c256);
	wri_sha384_init(&c384);
	wri_sha256_update(&c256, msg, sizeof(msg));
	wri_sha384_update(&c384, msg, sizeof(msg));
	wri_sha256_final(&c256, got256);
	wri_sha384_final(&c384, got384);
	WRT_CHECK_MEM(got256, want256, 32);
	WRT_CHECK_MEM(got384, want384, 48);
}

/* The output of a HMAC may overlap the message or the key: it is written only after the last read. */
static void test_hmac_out_aliases_input(void)
{
	uint8_t key[40], msg[100];
	uint8_t want256[32], want384[48];
	uint8_t buf[100];
	wr_iov iov;

	pattern(key, sizeof(key), 9, 4);
	pattern(msg, sizeof(msg), 5, 8);
	iov.base = msg;
	iov.len = sizeof(msg);
	wri_hmac_sha256(key, sizeof(key), &iov, 1, want256);
	wri_hmac_sha384(key, sizeof(key), &iov, 1, want384);

	memcpy(buf, msg, sizeof(buf));
	iov.base = buf;
	wri_hmac_sha256(key, sizeof(key), &iov, 1, buf); /* out over the start of the message */
	WRT_CHECK_MEM(buf, want256, 32);
	memcpy(buf, msg, sizeof(buf));
	wri_hmac_sha384(key, sizeof(key), &iov, 1, buf);
	WRT_CHECK_MEM(buf, want384, 48);

	{
		uint8_t kbuf[48];
		wr_iov m;

		memcpy(kbuf, key, sizeof(key));
		m.base = msg;
		m.len = sizeof(msg);
		wri_hmac_sha384(kbuf, sizeof(key), &m, 1, kbuf); /* out over the key */
		WRT_CHECK_MEM(kbuf, want384, 48);
	}
}

/* Distinct keys and messages give distinct MACs; keys differing only by trailing zeros are the
 * same key (RFC 2104 zero-pads), which pins the pad construction. */
static void test_hmac_separation(void)
{
	static const uint8_t k1[4] = {1, 2, 3, 4};
	static const uint8_t k2[5] = {1, 2, 3, 4, 0};
	static const uint8_t k3[4] = {1, 2, 3, 5};
	static const uint8_t m[3] = {'a', 'b', 'c'};
	uint8_t a[32], b[32], c[32];

	hmac256_one(k1, sizeof(k1), m, sizeof(m), a);
	hmac256_one(k2, sizeof(k2), m, sizeof(m), b);
	hmac256_one(k3, sizeof(k3), m, sizeof(m), c);
	WRT_CHECK_MEM(a, b, 32);
	WRT_CHECK(memcmp(a, c, 32) != 0);
	hmac256_one(k1, sizeof(k1), m, sizeof(m) - 1, c);
	WRT_CHECK(memcmp(a, c, 32) != 0);
}

/* Both sides of the `klen > block` branch: a block-sized key is used as is, a longer one is
 * hashed first, so HMAC(K) == HMAC(H(K)) exactly for the longer keys (RFC 2104 section 2). */
static void test_hmac_long_key_identity(void)
{
	uint8_t key[129], dg256[32], dg384[48];
	uint8_t msg[10];
	uint8_t a[32], b[32], a4[48], b4[48];
	wr_iov iov;
	size_t klen;

	pattern(msg, sizeof(msg), 1, 1);
	iov.base = msg;
	iov.len = sizeof(msg);
	for (klen = 63; klen <= 129; klen++) {
		pattern(key, klen, 7, 3);
		if (klen > 64) {
			sha256_oneshot(key, klen, dg256);
			wri_hmac_sha256(key, klen, &iov, 1, a);
			wri_hmac_sha256(dg256, 32, &iov, 1, b);
			WRT_CHECK_MEM(a, b, 32);
		}
		if (klen > 128) {
			sha384_oneshot(key, klen, dg384);
			wri_hmac_sha384(key, klen, &iov, 1, a4);
			wri_hmac_sha384(dg384, 48, &iov, 1, b4);
			WRT_CHECK_MEM(a4, b4, 48);
		}
	}
}

/* Length counters above 32 bits: feed 2^32 + 5 bytes (the same 64 KiB block over and over, byte i
 * = i mod 256) and compare with digests of the same stream computed with an independent
 * implementation. Too slow for sanitizer runs, so it only runs when WRT_BIG=1 is set. */
static void test_big_length(void)
{
	static uint8_t blk[65536];
	wri_sha256_ctx c256;
	wri_sha512_ctx c384;
	uint8_t d256[32], d384[48];
	uint64_t total = (1ull << 32) + 5u, left;
	const char *e = getenv("WRT_BIG");

	if (e == NULL || e[0] != '1')
		return;
	pattern(blk, sizeof(blk), 1, 0);
	wri_sha256_init(&c256);
	wri_sha384_init(&c384);
	for (left = total; left > 0;) {
		size_t n = left < sizeof(blk) ? (size_t)left : sizeof(blk);

		wri_sha256_update(&c256, blk, n);
		wri_sha384_update(&c384, blk, n);
		left -= n;
	}
	WRT_CHECK_U64(c256.total, total);
	WRT_CHECK_U64(c384.total_lo, total);
	wri_sha256_final(&c256, d256);
	wri_sha384_final(&c384, d384);
	check_hex(d256, 32, "b009608b2d4be88c115a634b84b7ee15976a5eba82991eed9ce3e1902a79d678",
		  "sha256 2^32+5 bytes");
	check_hex(d384, 48,
		  "96d822c998be1f2bc569bb2d6d45a1aea66d364d074cb0079244c334d56ea12edd0c716f5f77f6ef5bed53e1265d865f",
		  "sha384 2^32+5 bytes");
}

int main(void)
{
	test_known_answers();
	test_million_a();
	test_length_sweep();
	test_incremental();
	test_counters();
	test_wipe_after_final();
	test_hmac_rfc4231();
	test_hmac_key_sweep();
	test_hmac_iov();
	test_hmac_empty();
	test_vec_preauth();
	test_vec_preauth_synthetic();
	test_vec_challenge_proof();
	test_vec_type2_mac();
	test_dirty_buffers();
	test_hmac_out_aliases_input();
	test_hmac_separation();
	test_hmac_long_key_identity();
	test_big_length();
	return wrt_finish();
}
