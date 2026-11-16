/* SPDX-License-Identifier: MIT */
/*
 * test_auth_key - the key API (core/src/auth/wr_key.c; docs/spec/cephx.md 2.3).
 *
 * wr_key_from_raw: both types at their minimum and at the storage limit, unknown types, short and
 * oversized secrets, NULL arguments, the output zeroed on every failure. wr_key_parse_base64:
 * the encoded form built here from fields (so every field is exercised), the two session keys of
 * cephx/session-type{1,2}-crc.json (whose challenge proofs the parsed keys must reproduce), bad
 * base64 of every kind, a blob that is short, long, or whose inner length lies, type 0 and 3,
 * secrets too short or too long. wr_key_parse_keyring: the four throw-away keyrings of
 * public/keys/ (type and length, and that each decrypts what it encrypted), whitespace and
 * CRLF variants, no key line, comments and look-alike words, two key lines (the first wins, even
 * when it is the bad one), the length argument cutting the text, exact-size heap buffers for the
 * sanitizers. wr_key_wipe.
 */
#include "wrt.h"

#include "wri_cx.h"
#include "wri_le.h"

/* ---- helpers --------------------------------------------------------------------------------- */

static void b64_encode(const uint8_t *p, size_t n, char *out) /* needs 4 * ceil(n / 3) + 1 bytes */
{
	static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i, o = 0;

	for (i = 0; i < n; i += 3) {
		uint32_t v = (uint32_t)p[i] << 16;

		if (i + 1 < n)
			v |= (uint32_t)p[i + 1] << 8;
		if (i + 2 < n)
			v |= p[i + 2];
		out[o++] = tab[(v >> 18) & 63u];
		out[o++] = tab[(v >> 12) & 63u];
		out[o++] = i + 1 < n ? tab[(v >> 6) & 63u] : '=';
		out[o++] = i + 2 < n ? tab[v & 63u] : '=';
	}
	out[o] = 0;
}

/* base64 of { u16 type, utime (8 bytes), u16 slen, secret[slen] } with a free-standing length field */
static size_t key_blob(uint8_t *blob, unsigned type, const uint8_t *secret, size_t slen, unsigned lenfield)
{
	memset(blob, 0, 12);
	wri_le16_put(blob, (uint16_t)type);
	wri_le32_put(blob + 2, 0x6543abcdu); /* utime: ignored */
	wri_le32_put(blob + 6, 0x01020304u);
	wri_le16_put(blob + 10, (uint16_t)lenfield);
	if (slen != 0)
		memcpy(blob + 12, secret, slen);
	return 12 + slen;
}

static wr_status parse_b64(wr_key *k, unsigned type, const uint8_t *secret, size_t slen, unsigned lenfield)
{
	uint8_t blob[300];
	char text[500];
	size_t n = key_blob(blob, type, secret, slen, lenfield);

	b64_encode(blob, n, text);
	return wr_key_parse_base64(k, text, strlen(text));
}

static int key_is_zero(const wr_key *k)
{
	const uint8_t *p = (const uint8_t *)k;
	size_t i;

	for (i = 0; i < sizeof(*k); i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

static void key_dirty(wr_key *k)
{
	memset(k, 0xFF, sizeof(*k));
}

static wr_status parse_ring(wr_key *k, const char *text)
{
	size_t n = strlen(text);
	char *h = (char *)malloc(n != 0 ? n : 1); /* exact size: an over-read is an ASan report */
	wr_status st;

	if (h == NULL)
		exit(2);
	memcpy(h, text, n);
	st = wr_key_parse_keyring(k, h, n);
	free(h);
	return st;
}

#define RING_K1 "AQAAAAAAAAAAABAAT9OnFgMN4iZ+tt7URv1ouQ=="
#define RING_K2 "AgAAAAAAAAAAACAA1Y6mSz75PDaeovgIUqwRsPxHqzS8Ege/HZb4eoC92t4="

static wr_status fake_random(void *ctx, uint8_t *out, size_t n)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < n; i++)
		out[i] = (uint8_t)(0x31 * i + 7);
	return WR_OK;
}

/* ---- from_raw and wipe -------------------------------------------------------------------------- */

static void test_from_raw(void)
{
	uint8_t s[100];
	wr_key k;
	size_t i, n;

	for (i = 0; i < sizeof(s); i++)
		s[i] = (uint8_t)(i + 1);

	for (n = 16; n <= WR_KEY_MAX; n++) {
		key_dirty(&k);
		WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&k, WR_KEY_TYPE_AES, s, n));
		WRT_CHECK(k.type == 1 && k.len == n && memcmp(k.secret, s, n) == 0);
		WRT_CHECK(n == WR_KEY_MAX || k.secret[n] == 0); /* the tail is zero, not stale */
	}
	for (n = 32; n <= WR_KEY_MAX; n++) {
		WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&k, WR_KEY_TYPE_AES256K, s, n));
		WRT_CHECK(k.type == 2 && k.len == n && memcmp(k.secret, s, n) == 0);
	}

	key_dirty(&k);
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wr_key_from_raw(&k, 1, s, 15));
	WRT_CHECK(key_is_zero(&k));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wr_key_from_raw(&k, 1, s, 0));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wr_key_from_raw(&k, 2, s, 31));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wr_key_from_raw(&k, 2, s, 16));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wr_key_from_raw(&k, 1, s, 65));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wr_key_from_raw(&k, 2, s, 100));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wr_key_from_raw(&k, 1, s, 256 + 16)); /* does not wrap into the u8 */
	WRT_CHECK(key_is_zero(&k));
	for (i = 0; i < 6; i++) {
		static const unsigned bad[] = {0, 3, 4, 255, 256 + 1, 0xFFFFFFFFu};

		key_dirty(&k);
		WRT_CHECK_STATUS(WR_E_AUTH_KEY_TYPE, wr_key_from_raw(&k, bad[i], s, 32));
		WRT_CHECK(key_is_zero(&k));
	}
	key_dirty(&k);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_key_from_raw(&k, 1, NULL, 16));
	WRT_CHECK(key_is_zero(&k));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_key_from_raw(NULL, 1, s, 16));
	/* the type check comes first, so a bad type with NULL data is still a type error */
	WRT_CHECK_STATUS(WR_E_AUTH_KEY_TYPE, wr_key_from_raw(&k, 9, NULL, 0));

	/* the secret may be the key's own bytes (re-validating a copy): the result is intact */
	WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&k, 2, s, 40));
	WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&k, 2, k.secret, 40));
	WRT_CHECK(k.type == 2 && k.len == 40 && memcmp(k.secret, s, 40) == 0 && k.secret[40] == 0);
	WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&k, 1, k.secret, 16)); /* shorter and of another type */
	WRT_CHECK(k.type == 1 && k.len == 16 && memcmp(k.secret, s, 16) == 0 && k.secret[16] == 0);
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wr_key_from_raw(&k, 2, k.secret, 16));
	WRT_CHECK(key_is_zero(&k)); /* a failed call leaves a zero key even then */
}

static void test_wipe(void)
{
	wr_key k;

	key_dirty(&k);
	wr_key_wipe(&k);
	WRT_CHECK(key_is_zero(&k));
	wr_key_wipe(NULL); /* must not crash */
}

/* ---- base64 form ------------------------------------------------------------------------------- */

static void test_parse_base64(void)
{
	uint8_t s[80];
	wr_key k;
	size_t i, n;

	for (i = 0; i < sizeof(s); i++)
		s[i] = (uint8_t)(0xA0 ^ i);

	for (n = 16; n <= 64; n++) { /* every size that fits, both types where valid */
		key_dirty(&k);
		WRT_CHECK_STATUS(WR_OK, parse_b64(&k, 1, s, n, (unsigned)n));
		WRT_CHECK(k.type == 1 && k.len == n && memcmp(k.secret, s, n) == 0);
		if (n >= 32) {
			WRT_CHECK_STATUS(WR_OK, parse_b64(&k, 2, s, n, (unsigned)n));
			WRT_CHECK(k.type == 2 && k.len == n && memcmp(k.secret, s, n) == 0);
		}
	}

	key_dirty(&k);
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, parse_b64(&k, 1, s, 15, 15));
	WRT_CHECK(key_is_zero(&k));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, parse_b64(&k, 2, s, 31, 31));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, parse_b64(&k, 1, s, 0, 0));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, parse_b64(&k, 1, s, 65, 65)); /* does not fit wr_key */
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, parse_b64(&k, 2, s, 80, 80));
	WRT_CHECK(key_is_zero(&k));
	WRT_CHECK_STATUS(WR_E_AUTH_KEY_TYPE, parse_b64(&k, 0, s, 16, 16));
	WRT_CHECK_STATUS(WR_E_AUTH_KEY_TYPE, parse_b64(&k, 3, s, 32, 32));
	WRT_CHECK_STATUS(WR_E_AUTH_KEY_TYPE, parse_b64(&k, 0x0101, s, 32, 32)); /* the whole u16 counts */
	WRT_CHECK(key_is_zero(&k));
	/* the inner length must match what is there, exactly */
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_b64(&k, 1, s, 16, 17));
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_b64(&k, 1, s, 16, 15));
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_b64(&k, 2, s, 32, 0xFFFF));
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_b64(&k, 2, s, 33, 32)); /* trailing byte */
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_b64(&k, 2, s, 32, 31));
	WRT_CHECK(key_is_zero(&k));

	/* a blob too short for the 12-byte header, byte by byte */
	for (n = 0; n < 12; n++) {
		uint8_t blob[12] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0};
		char text[40];

		b64_encode(blob, n, text);
		WRT_CHECK_STATUS(WR_E_TRUNCATED, wr_key_parse_base64(&k, text, strlen(text)));
		WRT_CHECK(key_is_zero(&k));
	}
}

static void test_base64_syntax(void)
{
	wr_key k;
	char text[200];
	size_t n = strlen(RING_K1);

	WRT_CHECK_STATUS(WR_OK, wr_key_parse_base64(&k, RING_K1, n));
	WRT_CHECK(k.type == 1 && k.len == 16);

	/* whitespace around and inside is skipped */
	snprintf(text, sizeof(text), " \t%s\r\n", RING_K1);
	WRT_CHECK_STATUS(WR_OK, wr_key_parse_base64(&k, text, strlen(text)));
	snprintf(text, sizeof(text), "AQAAAAAA\nAAAAABAA\n T9OnFgMN4iZ+tt7URv1ouQ==");
	WRT_CHECK_STATUS(WR_OK, wr_key_parse_base64(&k, text, strlen(text)));
	WRT_CHECK(k.type == 1 && k.len == 16 && k.secret[0] == 0x4f);

	key_dirty(&k);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, wr_key_parse_base64(&k, "", 0));
	WRT_CHECK(key_is_zero(&k));
	WRT_CHECK_STATUS(WR_E_TRUNCATED, wr_key_parse_base64(&k, "  \n", 3));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_key_parse_base64(&k, NULL, 4));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_key_parse_base64(NULL, RING_K1, n));
	WRT_CHECK_STATUS(WR_E_ENCODING, wr_key_parse_base64(&k, "AQAA*AAA", 8));    /* bad character */
	WRT_CHECK_STATUS(WR_E_ENCODING, wr_key_parse_base64(&k, "AQAAAAAA=", 9));    /* stray padding */
	WRT_CHECK_STATUS(WR_E_ENCODING, wr_key_parse_base64(&k, "AQAAA", 5));        /* dangling char */
	WRT_CHECK_STATUS(WR_E_ENCODING, wr_key_parse_base64(&k, RING_K1 "AAAA", n + 4)); /* data after padding */
	WRT_CHECK_STATUS(WR_E_ENCODING, wr_key_parse_base64(&k, "AQAAAAAAAAAAABAAT9OnFgMN4iZ+tt7URv1ouQ=", n - 1));
	WRT_CHECK(key_is_zero(&k));

	/* an enormous input never overruns: it decodes to far more than a key holds */
	{
		char *big = (char *)malloc(100000);

		if (big == NULL)
			exit(2);
		memset(big, 'A', 100000);
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wr_key_parse_base64(&k, big, 100000));
		WRT_CHECK(key_is_zero(&k));
		free(big);
	}
}

/* ---- session vectors: the parsed keys reproduce the challenge proofs --------------------------- */

static uint64_t json_u64(const wrt_json *j, wrt_tok obj, const char *key)
{
	char *s = wrt_json_strdup(j, wrt_json_get(j, obj, key));
	uint64_t v = 0;

	WRT_CHECK(s != NULL);
	if (s != NULL) {
		v = (uint64_t)strtoull(s, NULL, 0);
		free(s);
	}
	return v;
}

static void test_session_keys(void)
{
	static const char *const files[] = {"cephx/session-type1-crc.json", "cephx/session-type2-crc.json"};
	size_t f, i;

	for (f = 0; f < 2; f++) {
		wrt_json j;
		wrt_tok root, conns;
		char *b64;
		wr_key k;
		wri_ctx x;

		memset(&x, 0, sizeof(x));
		if (wrt_json_load_vec(&j, files[f]) != 0) {
			WRT_CHECK(0 && "session vector loads");
			continue;
		}
		root = wrt_json_root(&j);
		b64 = wrt_json_strdup(&j, wrt_json_get(&j, root, "keyring_key_base64"));
		WRT_CHECK(b64 != NULL);
		if (b64 == NULL) {
			wrt_json_free(&j);
			continue;
		}
		WRT_CHECK_STATUS(WR_OK, wr_key_parse_base64(&k, b64, strlen(b64)));
		WRT_CHECK(k.type == f + 1 && k.len == (f == 0 ? 16u : 32u));
		conns = wrt_json_get(&j, root, "connections");
		WRT_CHECK(wrt_json_count(&j, conns) >= 2);
		for (i = 0; i < wrt_json_count(&j, conns); i++) {
			wrt_tok e = wrt_json_get(&j, wrt_json_at(&j, conns, i), "expect");
			uint64_t sc, cc, want, got = 0;

			if (wrt_json_get(&j, e, "proof") == WRT_NONE)
				continue; /* the OSD connection has no mon proof */
			sc = json_u64(&j, e, "server_challenge");
			cc = json_u64(&j, e, "client_challenge");
			want = json_u64(&j, e, "proof");
			WRT_CHECK_STATUS(WR_OK, wri_cx_challenge_proof(&x, &k, sc, cc, &got));
			WRT_CHECK_U64(got, want);
		}
		free(b64);
		wrt_json_free(&j);
	}
}

/* ---- keyring text --------------------------------------------------------------------------------- */

static void test_public_keyrings(void)
{
	static const struct {
		const char *file;
		unsigned type;
		size_t len;
	} rings[] = {{"public/keys/client.vec-k1.keyring", 1, 16},
		     {"public/keys/client.vec-k2.keyring", 2, 32},
		     {"public/keys/wrong.vec-k1.keyring", 1, 16},
		     {"public/keys/wrong.vec-k2.keyring", 2, 32}};
	wr_key keys[4];
	size_t i;

	for (i = 0; i < 4; i++) {
		uint8_t *buf = NULL;
		size_t n = 0;

		if (wrt_read_file(wrt_vec_path(rings[i].file), &buf, &n) != 0) {
			WRT_CHECK(0 && "keyring file reads");
			continue;
		}
		key_dirty(&keys[i]);
		WRT_CHECK_STATUS(WR_OK, wr_key_parse_keyring(&keys[i], (const char *)buf, n));
		WRT_CHECK(keys[i].type == rings[i].type && keys[i].len == rings[i].len);
		free(buf);
	}
	WRT_CHECK(memcmp(keys[0].secret, keys[2].secret, 16) != 0); /* the "wrong" keys differ */
	WRT_CHECK(memcmp(keys[1].secret, keys[3].secret, 32) != 0);
	/* the parsed keys work: a message survives its own key and is refused by the "wrong" one */
	for (i = 0; i < 2; i++) {
		wri_ctx x;
		uint8_t buf[80], out[80];
		size_t cn = 0, on = 0;

		memset(&x, 0, sizeof(x));
		x.host.size = (uint32_t)sizeof(x.host);
		x.host.random = fake_random;
		WRT_CHECK(wri_cx_encrypt(&x, &keys[i], 0, (const uint8_t *)"hello", 5, buf, sizeof(buf), &cn) == WR_OK);
		WRT_CHECK(wri_cx_decrypt(&x, &keys[i], 0, buf, cn, out, sizeof(out), &on) == WR_OK && on == 5);
		WRT_CHECK(wri_cx_decrypt(&x, &keys[i + 2], 0, buf, cn, out, sizeof(out), &on) != WR_OK ||
			  memcmp(out, "hello", 5) != 0);
	}
}

static void test_keyring_variants(void)
{
	wr_key k;
	char text[400];
	size_t i;
	static const char *const same[] = {
		"[client.x]\n\tkey = " RING_K1 "\n",
		"[client.x]\r\n\tkey = " RING_K1 "\r\n",
		"[client.x]\r\n\tkey = " RING_K1 "\r\n\tcaps mon = \"allow r\"\r\n",
		"key = " RING_K1,                              /* no header, no newline */
		"key=" RING_K1 "\n",                           /* no blanks */
		"   key   =    " RING_K1 "   \t \n",          /* many blanks, trailing blanks */
		"\n\n\n[client.x]\n\n  key =\t" RING_K1 "\n\n",
		"; key = bogus\n# key = bogus\n[client.x]\nkeyring = /etc/x\nkeys = 1\nkey " "= " RING_K1 "\n",
		"[client.x]\n\tcaps osd = \"allow rw\"\n\tkey = " RING_K1 "\n",
		"key\t=\t" RING_K1 "\r",
	};

	for (i = 0; i < sizeof(same) / sizeof(same[0]); i++) {
		key_dirty(&k);
		WRT_CHECK_STATUS(WR_OK, parse_ring(&k, same[i]));
		WRT_CHECK(k.type == 1 && k.len == 16 && k.secret[0] == 0x4f && k.secret[15] == 0xb9);
	}

	/* a type-2 key the same way */
	snprintf(text, sizeof(text), "[client.y]\r\n\tkey = %s\r\n", RING_K2);
	WRT_CHECK_STATUS(WR_OK, parse_ring(&k, text));
	WRT_CHECK(k.type == 2 && k.len == 32);

	/* two key lines: the first wins, and a bad first line is not skipped */
	snprintf(text, sizeof(text), "[a]\nkey = %s\n[b]\nkey = %s\n", RING_K2, RING_K1);
	WRT_CHECK_STATUS(WR_OK, parse_ring(&k, text));
	WRT_CHECK(k.type == 2);
	snprintf(text, sizeof(text), "[a]\nkey = %s\n[b]\nkey = %s\n", RING_K1, RING_K2);
	WRT_CHECK_STATUS(WR_OK, parse_ring(&k, text));
	WRT_CHECK(k.type == 1);
	snprintf(text, sizeof(text), "key = !!!!\nkey = %s\n", RING_K1);
	key_dirty(&k);
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_ring(&k, text));
	WRT_CHECK(key_is_zero(&k));
	WRT_CHECK_STATUS(WR_E_TRUNCATED, parse_ring(&k, "key =\nkey = " RING_K1 "\n"));
	WRT_CHECK_STATUS(WR_E_TRUNCATED, parse_ring(&k, "key =   \r\n"));

	/* the word "key" without "=" is not a key line: the search goes on */
	WRT_CHECK_STATUS(WR_OK, parse_ring(&k, "key " RING_K2 "\nkey = " RING_K1 "\n"));
	WRT_CHECK(k.type == 1);

	/* no key line at all */
	key_dirty(&k);
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_ring(&k, ""));
	WRT_CHECK(key_is_zero(&k));
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_ring(&k, "\n\r\n  \t\n"));
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_ring(&k, "[client.x]\n\tcaps mon = \"allow r\"\n"));
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_ring(&k, "key\n"));
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_ring(&k, "key " RING_K1 "\n")); /* no "=" */
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_ring(&k, "keyring = " RING_K1 "\n"));
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_ring(&k, "xkey = " RING_K1 "\n"));
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_ring(&k, "Key = " RING_K1 "\n")); /* case matters */
	WRT_CHECK_STATUS(WR_E_ENCODING, parse_ring(&k, "k\ney\n= " RING_K1 "\n"));
	WRT_CHECK(key_is_zero(&k));

	/* the length argument cuts the text; the rest is never looked at */
	{
		static const char t[] = "key = " RING_K1 "\nkey = junk";
		size_t full = 6 + strlen(RING_K1);
		char *h = (char *)malloc(full);

		if (h == NULL)
			exit(2);
		memcpy(h, t, full);
		WRT_CHECK_STATUS(WR_OK, wr_key_parse_keyring(&k, h, full));
		WRT_CHECK_STATUS(WR_E_ENCODING, wr_key_parse_keyring(&k, h, full - 4)); /* cut inside the value */
		WRT_CHECK_STATUS(WR_E_TRUNCATED, wr_key_parse_keyring(&k, h, 5));       /* "key =" and no value */
		WRT_CHECK_STATUS(WR_E_ENCODING, wr_key_parse_keyring(&k, h, 0));
		free(h);
	}
	WRT_CHECK_STATUS(WR_E_INVAL, wr_key_parse_keyring(&k, NULL, 5));
	WRT_CHECK_STATUS(WR_E_ENCODING, wr_key_parse_keyring(&k, NULL, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_key_parse_keyring(NULL, "key = x", 7));

	/* every prefix of a valid keyring is either parsed or refused, never read past its end */
	snprintf(text, sizeof(text), "[client.x]\r\n\tkey = %s\r\n", RING_K2);
	for (i = 0; i <= strlen(text); i++) {
		char *h = (char *)malloc(i != 0 ? i : 1);

		if (h == NULL)
			exit(2);
		memcpy(h, text, i);
		(void)wr_key_parse_keyring(&k, h, i);
		free(h);
	}

	/* an embedded NUL is not base64 */
	{
		static const char t[] = "key = AQAAAAAA\0AAAABAA";

		WRT_CHECK(wr_key_parse_keyring(&k, t, sizeof(t) - 1) != WR_OK);
	}
	/* a very long value: refused, not read past the output */
	{
		char *big = (char *)malloc(70000);

		if (big == NULL)
			exit(2);
		memcpy(big, "key = ", 6);
		memset(big + 6, 'B', 69994);
		WRT_CHECK(wr_key_parse_keyring(&k, big, 70000) != WR_OK);
		WRT_CHECK(key_is_zero(&k));
		free(big);
	}
}

int main(void)
{
	test_from_raw();
	test_wipe();
	test_parse_base64();
	test_base64_syntax();
	test_session_keys();
	test_public_keyrings();
	test_keyring_variants();
	return wrt_finish();
}
