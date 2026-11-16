/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the cephx cipher and envelope decoders (core/src/auth/wri_cx_cipher.c,
 * wri_cx_envelope.c): arbitrary ciphertext into decrypt and open, with fixed keys of both types.
 *
 * Byte 0: bit 0 picks the key type (0: type 1, 1: type 2), bits 1..2 pick the mode. Byte 1 is the
 * usage value. The rest is the payload, copied to an exact-size heap block (so ASan sees any
 * over-read); the output / scratch buffer is an exact-size heap block too.
 *
 *   mode 0  wri_cx_open(payload): on success the item lies inside the scratch and the bytes before it
 *           are the 9-byte header with the magic; on failure the item pointer is NULL
 *   mode 1  wri_cx_decrypt(payload): a type-1 result must encrypt back to the very same bytes (the
 *           cipher is deterministic and the padding check is strict); a type-2 success means the MAC
 *           verified, so the payload must have the right length; on failure the working area is zero
 *   mode 2  wri_cx_seal(payload as the item) then wri_cx_open: the item comes back unchanged
 *   mode 3  wri_cx_encrypt(payload) then wri_cx_decrypt: the plaintext comes back unchanged
 *
 * Bit 3 of byte 0 switches to the key parsers instead (the key type and mode bits are then unused):
 * the payload is fed to wr_key_parse_keyring and to wr_key_parse_base64; a failure leaves an all-zero
 * key, a success a key of type 1 or 2 with a secret length the type allows and zeros after it.
 *
 * A violated property traps. The host random is a fixed counter, so runs are reproducible.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_cx.h"
#include "wri_le.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

static wr_status fuzz_random(void *ctx, uint8_t *out, size_t n)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < n; i++)
		out[i] = (uint8_t)(0x1D * i + 0x42);
	return WR_OK;
}

static uint8_t *heap_new(size_t n)
{
	uint8_t *q = (uint8_t *)calloc(n != 0 ? n : 1, 1);

	if (q == NULL)
		exit(2);
	return q;
}

static uint8_t *heap_copy(const uint8_t *p, size_t n)
{
	uint8_t *q = heap_new(n);

	if (n != 0)
		memcpy(q, p, n);
	return q;
}

static int all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

/* Bytes the working area must hold for a ciphertext of n bytes under this key type. */
static size_t work_len(unsigned type, size_t n)
{
	return type == WR_KEY_TYPE_AES ? n : (n >= 24 ? n - 24 : 0);
}

static void mode_open(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *p, size_t n)
{
	size_t w = work_len(k->type, n), il = 99;
	uint8_t *scratch = heap_new(w);
	const uint8_t *it = (const uint8_t *)1;
	wr_status st = wri_cx_open(x, k, usage, p, n, scratch, w, &it, &il);

	if (st == WR_OK) {
		check(it != NULL && it >= scratch + 9 && it + il <= scratch + w);
		check(wri_le64_get(scratch + 1) == WRI_CX_MAGIC);
	} else {
		check(it == NULL && il == 0);
		check(all_zero(scratch, w));
	}
	free(scratch);
}

static void mode_decrypt(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *p, size_t n)
{
	size_t w = work_len(k->type, n), on = 99;
	uint8_t *out = heap_new(w);
	wr_status st = wri_cx_decrypt(x, k, usage, p, n, out, w, &on);

	if (st != WR_OK) {
		check(on == 0 && all_zero(out, w));
	} else if (k->type == WR_KEY_TYPE_AES) {
		size_t cl = 0;
		uint8_t *back = heap_new(n);

		check(on < n && n - on <= 16);
		check(wri_cx_encrypt(x, k, usage, out, on, back, n, &cl) == WR_OK);
		check(cl == n && memcmp(back, p, n) == 0); /* strict padding: it re-encrypts to the same bytes */
		free(back);
	} else {
		check(n >= 40 && on == n - 40);
	}
	free(out);
}

static void mode_seal_open(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *p, size_t n)
{
	size_t cl = 0, il = 0, need = wri_cx_cipher_len(k->type, n + 9);
	uint8_t *ct = heap_new(need), *scratch = heap_new(need);
	const uint8_t *it = NULL;

	if (need == 0 || n > 4096) {
		free(ct);
		free(scratch);
		return;
	}
	check(wri_cx_seal(x, k, usage, p, n, ct, need, &cl) == WR_OK && cl == need);
	check(wri_cx_open(x, k, usage, ct, cl, scratch, need, &it, &il) == WR_OK);
	check(il == n && (n == 0 || memcmp(it, p, n) == 0));
	free(ct);
	free(scratch);
}

static void mode_enc_dec(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *p, size_t n)
{
	size_t need = wri_cx_cipher_len(k->type, n), cl = 0, on = 0, w = work_len(k->type, need);
	uint8_t *ct, *out;

	if (need == 0 || n > 4096)
		return;
	ct = heap_new(need);
	out = heap_new(w);
	check(wri_cx_encrypt(x, k, usage, p, n, ct, need, &cl) == WR_OK && cl == need);
	check(wri_cx_decrypt(x, k, usage, ct, cl, out, w, &on) == WR_OK);
	check(on == n && (n == 0 || memcmp(out, p, n) == 0));
	free(ct);
	free(out);
}

static void check_key(const wr_key *k, wr_status st)
{
	size_t i;

	if (st != WR_OK) {
		check(all_zero((const uint8_t *)k, sizeof(*k)));
		return;
	}
	check(k->type == WR_KEY_TYPE_AES || k->type == WR_KEY_TYPE_AES256K);
	check(k->len <= WR_KEY_MAX && k->len >= (k->type == WR_KEY_TYPE_AES ? 16u : 32u));
	for (i = k->len; i < WR_KEY_MAX; i++)
		check(k->secret[i] == 0);
}

static void mode_key(const uint8_t *p, size_t n)
{
	wr_key k;
	wr_status st;

	memset(&k, 0xAB, sizeof(k));
	st = wr_key_parse_keyring(&k, (const char *)p, n);
	check_key(&k, st);
	memset(&k, 0xAB, sizeof(k));
	st = wr_key_parse_base64(&k, (const char *)p, n);
	check_key(&k, st);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint8_t k1_secret[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	uint8_t k2_secret[32];
	wri_ctx x;
	wr_key k;
	uint8_t *payload;
	size_t i;
	unsigned type;
	uint32_t usage;

	if (size < 2)
		return 0;
	for (i = 0; i < sizeof(k2_secret); i++)
		k2_secret[i] = (uint8_t)i;
	memset(&x, 0, sizeof(x));
	x.host.size = (uint32_t)sizeof(x.host);
	x.host.random = fuzz_random;

	if ((data[0] & 8u) != 0) {
		payload = heap_copy(data + 2, size - 2);
		mode_key(payload, size - 2);
		free(payload);
		return 0;
	}
	type = (data[0] & 1u) ? WR_KEY_TYPE_AES256K : WR_KEY_TYPE_AES;
	usage = data[1];
	check(type == WR_KEY_TYPE_AES ? wr_key_from_raw(&k, type, k1_secret, sizeof(k1_secret)) == WR_OK
				      : wr_key_from_raw(&k, type, k2_secret, sizeof(k2_secret)) == WR_OK);
	payload = heap_copy(data + 2, size - 2);
	switch ((data[0] >> 1) & 3u) {
	case 0:
		mode_open(&x, &k, usage, payload, size - 2);
		break;
	case 1:
		mode_decrypt(&x, &k, usage, payload, size - 2);
		break;
	case 2:
		mode_seal_open(&x, &k, usage, payload, size - 2);
		break;
	default:
		mode_enc_dec(&x, &k, usage, payload, size - 2);
		break;
	}
	free(payload);
	return 0;
}
