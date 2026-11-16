/* SPDX-License-Identifier: MIT */
/*
 * wr_key.c - the public key API (wr_key.h): building a key from raw bytes, parsing the base64 form
 * of a keyring, finding the key line in keyring text, and wiping.
 *
 * The encoded form (docs/spec/cephx.md 2.3) is  u16 type | utime created (8 bytes, ignored) |
 * u16 secret_len | secret  with every integer little-endian. The secret length must match what is
 * left of the decoded data exactly (a longer or shorter blob is rejected), type 1 needs at least
 * 16 secret bytes and type 2 at least 32. wr_key keeps up to WR_KEY_MAX (64) bytes: a longer secret
 * is refused rather than truncated, because the type-2 key derivation uses the whole secret and a
 * cut one would silently derive different keys. Real keys are exactly 16 or 32 bytes.
 *
 * Error codes: an unknown type (0 and anything but 1 and 2) is WR_E_AUTH_KEY_TYPE; a secret that is
 * too short or too long for storage is WR_E_CRYPTO_KEY; bad base64 or a blob whose lengths disagree
 * is WR_E_ENCODING; a blob too short to hold the header is WR_E_TRUNCATED. On every failure the
 * output key is zeroed, and every temporary that held key bytes is wiped. Nothing here logs.
 *
 * Keyring text: the first line whose first word is "key" followed by "=" (blanks around the "="
 * optional, leading blanks allowed, LF or CRLF line ends) is the key line; its value runs to the end
 * of the line (trailing blanks and the CR are dropped). The first such line decides the result: if
 * it is malformed the call fails, later lines are not tried. Section headers, comments, "caps" lines
 * and words that merely start with "key" (such as "keyring") are skipped. No key line at all is
 * WR_E_ENCODING.
 */
#include "wr_key.h"

#include "wri_le.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define KEY_HDR 12u /* u16 type + utime(8) + u16 secret_len */

void wr_key_wipe(wr_key *k)
{
	if (k != NULL)
		wri_secure_zero(k, sizeof(*k));
}

wr_status wr_key_from_raw(wr_key *out, unsigned type, const uint8_t *secret, size_t len)
{
	wr_key t; /* built aside, so `secret` may point into *out (a re-validated copy of a key) */

	if (out == NULL)
		return WR_E_INVAL;
	if (type != WR_KEY_TYPE_AES && type != WR_KEY_TYPE_AES256K) {
		wr_key_wipe(out);
		return WR_E_AUTH_KEY_TYPE;
	}
	if (secret == NULL && len != 0) {
		wr_key_wipe(out);
		return WR_E_INVAL;
	}
	if (len > WR_KEY_MAX || len < (type == WR_KEY_TYPE_AES ? 16u : 32u)) {
		wr_key_wipe(out);
		return WR_E_CRYPTO_KEY;
	}
	wr_key_wipe(&t);
	t.type = (uint8_t)type;
	t.len = (uint8_t)len;
	WR_MEMCPY(t.secret, secret, len);
	WR_MEMCPY(out, &t, sizeof(t));
	wr_key_wipe(&t);
	return WR_OK;
}

wr_status wr_key_parse_base64(wr_key *out, const char *b64, size_t n)
{
	uint8_t raw[KEY_HDR + WR_KEY_MAX];
	size_t rn = 0, slen;
	unsigned type;
	wr_status st;

	if (out == NULL)
		return WR_E_INVAL;
	wr_key_wipe(out);
	st = wri_b64_decode(b64, n, raw, sizeof(raw), &rn); /* wipes what it wrote if it fails */
	if (st == WR_E_TOOBIG)
		st = WR_E_CRYPTO_KEY; /* decodes to more than a key can hold */
	if (st != WR_OK)
		return st;
	if (rn < KEY_HDR) {
		st = WR_E_TRUNCATED;
	} else {
		type = wri_le16_get(raw);
		slen = wri_le16_get(raw + 10);
		if (slen != rn - KEY_HDR)
			st = WR_E_ENCODING;
		else
			st = wr_key_from_raw(out, type, raw + KEY_HDR, slen);
	}
	wri_secure_zero(raw, sizeof(raw));
	return st;
}

static int key_is_blank(char c)
{
	return c == ' ' || c == '\t';
}

wr_status wr_key_parse_keyring(wr_key *out, const char *text, size_t n)
{
	size_t pos = 0;

	if (out == NULL)
		return WR_E_INVAL;
	wr_key_wipe(out);
	if (text == NULL && n != 0)
		return WR_E_INVAL;

	while (pos < n) {
		size_t s = pos, e = pos, v;

		while (e < n && text[e] != '\n')
			e++;
		pos = e < n ? e + 1 : n; /* next line */

		while (s < e && key_is_blank(text[s]))
			s++;
		if (e - s < 3 || text[s] != 'k' || text[s + 1] != 'e' || text[s + 2] != 'y')
			continue;
		v = s + 3;
		if (v < e && !key_is_blank(text[v]) && text[v] != '=')
			continue; /* "keyring", "keys" ... */
		while (v < e && key_is_blank(text[v]))
			v++;
		if (v >= e || text[v] != '=')
			continue; /* the word "key" without an "=" is not a key line */
		v++;
		while (v < e && key_is_blank(text[v]))
			v++;
		while (e > v && (key_is_blank(text[e - 1]) || text[e - 1] == '\r'))
			e--;
		return wr_key_parse_base64(out, text + v, e - v);
	}
	return WR_E_ENCODING;
}
