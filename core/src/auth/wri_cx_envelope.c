/* SPDX-License-Identifier: MIT */
/*
 * wri_cx_envelope.c - the cephx "encode + encrypt" envelope (docs/spec/cephx.md 2.6) and the
 * challenge proof of CephXAuthenticate (2.8).
 *
 * Every encrypted cephx item is  u8 1 | u64 magic | item  encrypted with the key's own cipher.
 * seal builds that plaintext directly in the output buffer (the cipher layer encrypts in place), so
 * no second buffer is needed; open decrypts into the caller's scratch, requires the magic (the only
 * integrity check of a type-1 key) and hands back a pointer to the item inside the scratch. The
 * version byte is not checked, as in the reference decoder; trailing bytes after the item are the
 * caller's business. Nothing here allocates; plaintext left in a scratch buffer by a failed open is
 * wiped.
 *
 * The challenge proof: type 1 is the XOR of the four whole little-endian u64 words of the 36-byte
 * length-prefixed ciphertext of (server challenge || client challenge); that value is
 * deterministic because the type-1 cipher has no randomness. Type 2 cannot do that (its confounder
 * is random), so it is the XOR of the four u64 words of HMAC-SHA256(secret, the same 16 bytes).
 */
#include "wri_cx.h"

#include "wri_hash.h"
#include "wri_le.h"
#include "wri_misc.h"
#include "wri_prim.h"

WR_FILE_LICENCE_MIT

#define CX_ENV_HDR 9u /* u8 version + u64 magic */

static wr_status cx_env_key_check(const wr_key *k)
{
	if (k == NULL)
		return WR_E_INVAL;
	if (k->len > WR_KEY_MAX)
		return WR_E_CRYPTO_KEY;
	if (k->type == WR_KEY_TYPE_AES)
		return k->len >= 16u ? WR_OK : WR_E_CRYPTO_KEY;
	if (k->type == WR_KEY_TYPE_AES256K)
		return k->len >= 32u ? WR_OK : WR_E_CRYPTO_KEY;
	return WR_E_AUTH_KEY_TYPE;
}

wr_status wri_cx_seal(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *item, size_t item_len,
		      uint8_t *out, size_t out_cap, size_t *out_n)
{
	size_t plain_n, need, lead;
	uintptr_t a, b;
	wr_status st;

	if (out_n == NULL)
		return WR_E_INVAL;
	*out_n = 0;
	st = cx_env_key_check(k);
	if (st != WR_OK)
		return st;
	if ((item == NULL && item_len != 0) || out == NULL)
		return WR_E_INVAL;
	st = wri_add_sz(CX_ENV_HDR, item_len, &plain_n);
	if (st != WR_OK)
		return st;
	need = wri_cx_cipher_len(k->type, plain_n);
	if (need == 0)
		return WR_E_OVERFLOW;
	if (out_cap < need)
		return WR_E_TOOBIG;
	if (item_len != 0) { /* the item must not overlap the buffer the plaintext is built in */
		a = (uintptr_t)item;
		b = (uintptr_t)out;
		if (a <= b ? (uint64_t)(b - a) < (uint64_t)item_len : (uint64_t)(a - b) < (uint64_t)need)
			return WR_E_INVAL;
	}
	lead = wri_cx_enc_lead(k->type);
	out[lead] = 1;
	wri_le64_put(out + lead + 1, WRI_CX_MAGIC);
	if (item_len != 0)
		WR_MEMCPY(out + lead + CX_ENV_HDR, item, item_len);
	return wri_cx_encrypt_at(x, k, usage, out, need, plain_n, out_n);
}

wr_status wri_cx_open(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *ct, size_t n,
		      uint8_t *scratch, size_t scratch_cap, const uint8_t **item, size_t *item_len)
{
	size_t pn = 0;
	wr_status st;

	if (item == NULL || item_len == NULL)
		return WR_E_INVAL;
	*item = NULL;
	*item_len = 0;
	st = wri_cx_decrypt(x, k, usage, ct, n, scratch, scratch_cap, &pn);
	if (st != WR_OK)
		return st;
	if (pn < CX_ENV_HDR || wri_le64_get(scratch + 1) != WRI_CX_MAGIC) {
		wri_secure_zero(scratch, n < scratch_cap ? n : scratch_cap);
		return WR_E_AUTH_DECRYPT;
	}
	*item = scratch + CX_ENV_HDR;
	*item_len = pn - CX_ENV_HDR;
	return WR_OK;
}

wr_status wri_cx_challenge_proof(const wri_ctx *x, const wr_key *k, uint64_t server_challenge,
				 uint64_t client_challenge, uint64_t *proof)
{
	uint8_t blob[16];
	uint64_t acc = 0;
	size_t i;
	wr_status st;

	if (proof == NULL)
		return WR_E_INVAL;
	*proof = 0;
	st = cx_env_key_check(k);
	if (st != WR_OK)
		return st;
	wri_le64_put(blob, server_challenge); /* the server's value comes first */
	wri_le64_put(blob + 8, client_challenge);

	if (k->type == WR_KEY_TYPE_AES) {
		uint8_t lp[40]; /* u32 length | 32 bytes of ciphertext, then slack: 36 bytes are used */
		size_t ct_n = 0;

		st = wri_cx_seal(x, k, 0, blob, sizeof(blob), lp + 4, sizeof(lp) - 4, &ct_n);
		if (st == WR_OK && ct_n != 32u)
			st = WR_E_CRYPTO_LEN;
		if (st == WR_OK) {
			wri_le32_put(lp, (uint32_t)ct_n);
			for (i = 0; i < 4; i++) /* whole words only: the last 4 bytes do not count */
				acc ^= wri_le64_get(lp + 8 * i);
		}
		wri_secure_zero(lp, sizeof(lp));
	} else {
		uint8_t mac[WRI_SHA256_LEN];
		wr_iov iov;

		iov.base = blob;
		iov.len = sizeof(blob);
		wri_p_hmac_sha256(x != NULL ? x->host.prim : NULL, k->secret, k->len, &iov, 1, mac);
		for (i = 0; i < 4; i++)
			acc ^= wri_le64_get(mac + 8 * i);
		wri_secure_zero(mac, sizeof(mac));
	}
	wri_secure_zero(blob, sizeof(blob));
	if (st == WR_OK)
		*proof = acc;
	return st;
}
