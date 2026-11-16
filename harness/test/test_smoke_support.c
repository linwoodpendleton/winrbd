/* SPDX-License-Identifier: MIT */
/* Test of the test support itself: hex helpers and the JSON reader, on a committed vector file. */
#include "wrt.h"

static void test_hex(void)
{
	uint8_t *b;
	size_t n;
	char out[16];

	WRT_CHECK(wrt_hex_decode("00 ff\n7A", 8, &b, &n) == 0);
	WRT_CHECK_U64(n, 3);
	WRT_CHECK_U64(b[0], 0x00);
	WRT_CHECK_U64(b[1], 0xff);
	WRT_CHECK_U64(b[2], 0x7a);
	wrt_hex_encode(b, n, out);
	WRT_CHECK(strcmp(out, "00ff7a") == 0);
	free(b);
	WRT_CHECK(wrt_hex_decode("abc", 3, &b, &n) == -1); /* odd digit count */
	WRT_CHECK(wrt_hex_decode("zz", 2, &b, &n) == -1);
}

static void test_json_inline(void)
{
	static const char doc[] = "{\"a\": [1, 2, {\"x\": \"h\\u0069\"}], \"b\": true, \"hex\": \"0a0B\", \"n\": \"0x10\"}";
	wrt_json j;
	wrt_tok a, x, hex;
	uint8_t *b;
	size_t n;
	char *s;
	int ok;

	WRT_CHECK(wrt_json_parse(&j, doc, sizeof(doc) - 1) == 0);
	a = wrt_json_get(&j, wrt_json_root(&j), "a");
	WRT_CHECK_U64(wrt_json_count(&j, a), 3);
	WRT_CHECK_U64(wrt_json_int(&j, wrt_json_at(&j, a, 1), &ok), 2);
	WRT_CHECK(ok);
	x = wrt_json_get(&j, wrt_json_at(&j, a, 2), "x");
	s = wrt_json_strdup(&j, x);
	WRT_CHECK(s && strcmp(s, "hi") == 0);
	free(s);
	WRT_CHECK(wrt_json_is_bool(&j, wrt_json_get(&j, wrt_json_root(&j), "b")));
	hex = wrt_json_get(&j, wrt_json_root(&j), "hex");
	WRT_CHECK(wrt_json_hex(&j, hex, &b, &n) == 0 && n == 2 && b[0] == 0x0a && b[1] == 0x0b);
	free(b);
	WRT_CHECK_U64(wrt_json_int(&j, wrt_json_get(&j, wrt_json_root(&j), "n"), &ok), 16);
	WRT_CHECK(wrt_json_get(&j, wrt_json_root(&j), "missing") == WRT_NONE);
	wrt_json_free(&j);
	WRT_CHECK(wrt_json_parse(&j, "{\"a\": [1,", 9) != 0); /* truncated */
}

static void test_json_vector(void)
{
	wrt_json j;
	wrt_tok crc;

	/* the committed CRC-32C vectors must parse; their contents are checked by the crc32c module test */
	WRT_CHECK(wrt_json_load_vec(&j, "msgr2/crc32c.json") == 0);
	crc = wrt_json_root(&j);
	WRT_CHECK(crc != WRT_NONE);
	WRT_CHECK(wrt_json_count(&j, crc) > 0);
	wrt_json_free(&j);
}

int main(void)
{
	test_hex();
	test_json_inline();
	test_json_vector();
	return wrt_finish();
}
