/* SPDX-License-Identifier: MIT */
/*
 * wri_cx_cipher.c - the two cephx ciphers (docs/spec/cephx.md 2.4 and 2.5), the type-2 key
 * derivation and the length helper. The envelope and the challenge proof are in wri_cx_envelope.c.
 *
 * Type 1 ("aes"): AES-128-CBC over the first 16 bytes of the secret, one fixed IV for every
 * message, PKCS#7 padding with a full extra block when the input is already aligned. There is no
 * MAC; integrity rests on the magic of the envelope. Decrypt rejects a length that is not a
 * non-zero multiple of 16 and a pad run that is not 1..16 copies of the pad length (checked without
 * a data-dependent branch).
 *
 * Type 2 ("aes256k"): the RFC 8009 profile aes256-cts-hmac-sha384-192 as Ceph uses it. The whole
 * stored secret is the base key; for a usage value U the encryption key Ke (32 bytes, label byte
 * 0xAA) and the integrity key Ki (24 bytes, label byte 0x55) come from wri_cx_kdf. Encrypt builds
 * M = confounder(16, from the host RNG) || plaintext, encrypts M with AES-256 CBC ciphertext
 * stealing (variant CS3, zero IV) and appends the first 24 bytes of HMAC-SHA384(Ki, 16 zero bytes ||
 * ciphertext). Decrypt checks the length (>= 40), verifies that MAC in constant time and only then
 * decrypts; a mismatch decrypts nothing.
 *
 * Every primitive goes through the wri_p_* dispatchers (wri_prim.h), so a host override takes
 * effect; CTS, the KDF and the padding are always the core's own. All derived keys are wiped before
 * a function returns, and so is any plaintext a failed call may have produced. Stack use is below
 * 200 bytes per frame; nothing is allocated; no recursion.
 */
#include "wri_cx.h"

#include "wri_aes.h"
#include "wri_hash.h"
#include "wri_le.h"
#include "wri_misc.h"
#include "wri_prim.h"

WR_FILE_LICENCE_MIT

#define CX_BS 16u        /* AES block */
#define CX_CONF 16u      /* type-2 confounder */
#define CX_MAC 24u       /* type-2 truncated MAC */
#define CX_KE_LEN 32u
#define CX_KI_LEN 24u

/* The type-1 IV, the same for every message (cephx.md 2.1). */
static const uint8_t cx_iv1[CX_BS] = {'c', 'e', 'p', 'h', 's', 'a', 'g', 'e', 'y', 'u', 'd', 'a', 'g', 'r', 'e', 'g'};
static const uint8_t cx_zero_iv[CX_BS] = {0};

static const wr_prim_ops *cx_prim(const wri_ctx *x)
{
	return x != NULL ? x->host.prim : NULL;
}

/* A key must be of a known type with a secret length that fits storage and the type's minimum. */
static wr_status cx_key_check(const wr_key *k)
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

/* 1 if [a, a + an) and [b, b + bn) share a byte (distance form, no sum can wrap). */
static int cx_overlap(const void *a, size_t an, const void *b, size_t bn)
{
	uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;

	if (an == 0 || bn == 0)
		return 0;
	if (x <= y)
		return (uint64_t)(y - x) < (uint64_t)an;
	return (uint64_t)(x - y) < (uint64_t)bn;
}

/* ---- length and key derivation ------------------------------------------------------------- */

size_t wri_cx_cipher_len(unsigned key_type, size_t n)
{
	size_t out;

	if (key_type == WR_KEY_TYPE_AES) {
		if (wri_add_sz(n, CX_BS - (n & (CX_BS - 1u)), &out) != WR_OK)
			return 0;
		return out;
	}
	if (key_type == WR_KEY_TYPE_AES256K) {
		if (wri_add_sz(n, CX_CONF + CX_MAC, &out) != WR_OK)
			return 0;
		return out;
	}
	return 0;
}

size_t wri_cx_enc_lead(unsigned key_type)
{
	return key_type == WR_KEY_TYPE_AES256K ? CX_CONF : 0u;
}

void wri_cx_kdf(const wr_prim_ops *prim, const uint8_t *base, size_t blen, uint32_t usage, uint8_t type_byte,
		uint8_t *out, size_t out_len)
{
	uint8_t in[14], mac[WRI_SHA384_LEN];
	wr_iov iov;

	if (out_len == 0)
		return;
	if (out_len > WRI_SHA384_LEN) {
		WR_MEMSET(out, 0, out_len);
		return;
	}
	in[0] = 0;
	in[1] = 0;
	in[2] = 0;
	in[3] = 1; /* counter i = 1: one HMAC block is enough for <= 48 bytes */
	wri_be32_put(in + 4, usage);
	in[8] = type_byte;
	in[9] = 0; /* separator, then an empty context */
	wri_be32_put(in + 10, (uint32_t)(out_len * 8u));
	iov.base = in;
	iov.len = sizeof(in);
	wri_p_hmac_sha384(prim, base, blen, &iov, 1, mac);
	WR_MEMCPY(out, mac, out_len);
	wri_secure_zero(mac, sizeof(mac));
}

/* HMAC-SHA384(Ki, 16 zero bytes || ct), first 24 bytes into out. */
static void cx_mac2(const wr_prim_ops *prim, const uint8_t ki[CX_KI_LEN], const uint8_t *ct, size_t ct_len,
		    uint8_t out[CX_MAC])
{
	uint8_t full[WRI_SHA384_LEN];
	wr_iov iov[2];

	iov[0].base = cx_zero_iv;
	iov[0].len = CX_BS;
	iov[1].base = ct;
	iov[1].len = ct_len;
	wri_p_hmac_sha384(prim, ki, CX_KI_LEN, iov, 2, full);
	WR_MEMCPY(out, full, CX_MAC);
	wri_secure_zero(full, sizeof(full));
}

/* ---- encrypt ------------------------------------------------------------------------------- */

static wr_status cx_enc1_at(const wr_prim_ops *prim, const wr_key *k, uint8_t *buf, size_t n, size_t need)
{
	size_t i;

	for (i = n; i < need; i++)
		buf[i] = (uint8_t)(need - n); /* 1..16 copies of the pad length */
	return wri_p_aes_cbc_enc(prim, k->secret, 16, cx_iv1, buf, buf, need / CX_BS);
}

static wr_status cx_enc2_at(const wri_ctx *x, const wr_key *k, uint32_t usage, uint8_t *buf, size_t n)
{
	const wr_prim_ops *prim = cx_prim(x);
	uint8_t ke[CX_KE_LEN], ki[CX_KI_LEN];
	size_t m = n + CX_CONF; /* confounder + plaintext, cannot wrap: the caller sized buf */
	wr_status st;

	st = wri_random(x, buf, CX_CONF);
	if (st != WR_OK)
		return st;
	wri_cx_kdf(prim, k->secret, k->len, usage, 0xAA, ke, sizeof(ke));
	wri_cx_kdf(prim, k->secret, k->len, usage, 0x55, ki, sizeof(ki));
	st = wri_cts3_enc(prim, ke, sizeof(ke), cx_zero_iv, buf, m, buf);
	if (st == WR_OK)
		cx_mac2(prim, ki, buf, m, buf + m);
	wri_secure_zero(ke, sizeof(ke));
	wri_secure_zero(ki, sizeof(ki));
	return st;
}

wr_status wri_cx_encrypt_at(const wri_ctx *x, const wr_key *k, uint32_t usage, uint8_t *buf, size_t cap,
			    size_t n_plain, size_t *out_n)
{
	size_t need;
	wr_status st;

	if (out_n == NULL)
		return WR_E_INVAL;
	*out_n = 0;
	st = cx_key_check(k);
	if (st != WR_OK)
		return st;
	if (buf == NULL)
		return WR_E_INVAL;
	need = wri_cx_cipher_len(k->type, n_plain);
	if (need == 0)
		return WR_E_OVERFLOW;
	if (cap < need)
		return WR_E_TOOBIG;
	if (k->type == WR_KEY_TYPE_AES)
		st = cx_enc1_at(cx_prim(x), k, buf, n_plain, need);
	else
		st = cx_enc2_at(x, k, usage, buf, n_plain);
	if (st != WR_OK) {
		wri_secure_zero(buf, need); /* no plaintext or half-made ciphertext is left behind */
		return st;
	}
	*out_n = need;
	return WR_OK;
}

wr_status wri_cx_encrypt(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *in, size_t n,
			 uint8_t *out, size_t out_cap, size_t *out_n)
{
	size_t need, lead;
	wr_status st;

	if (out_n == NULL)
		return WR_E_INVAL;
	*out_n = 0;
	st = cx_key_check(k);
	if (st != WR_OK)
		return st;
	if ((in == NULL && n != 0) || out == NULL)
		return WR_E_INVAL;
	need = wri_cx_cipher_len(k->type, n);
	if (need == 0)
		return WR_E_OVERFLOW;
	if (out_cap < need)
		return WR_E_TOOBIG;
	if (cx_overlap(in, n, out, need))
		return WR_E_INVAL; /* in == out is not allowed either */
	lead = wri_cx_enc_lead(k->type);
	if (n != 0)
		WR_MEMCPY(out + lead, in, n);
	return wri_cx_encrypt_at(x, k, usage, out, need, n, out_n);
}

/* ---- decrypt ------------------------------------------------------------------------------- */

static wr_status cx_dec1(const wr_prim_ops *prim, const wr_key *k, const uint8_t *in, size_t n, uint8_t *out,
			 size_t *out_n)
{
	uint32_t pad, bad, diff = 0, j;
	wr_status st;

	st = wri_p_aes_cbc_dec(prim, k->secret, 16, cx_iv1, in, out, n / CX_BS);
	if (st != WR_OK)
		return st;
	/*
	 * Padding check without a data-dependent branch or early exit, so a forged ciphertext cannot
	 * learn from the timing which of "pad byte out of range" and "pad run not uniform" it hit.
	 * n >= 16, so the last 16 bytes always exist. Bytes of the last block that lie inside the pad
	 * run (j < pad) must all equal pad.
	 */
	pad = out[n - 1];
	bad = ((pad - 1u) | (CX_BS - pad)) >> 31; /* 1 for pad == 0 and pad > 16 */
	for (j = 0; j < CX_BS; j++) {
		uint32_t in_run = (j - pad) >> 31; /* 1 while j < pad (both values are tiny) */

		diff |= (0u - in_run) & (uint32_t)(out[n - 1u - j] ^ (uint8_t)pad);
	}
	if (bad != 0 || diff != 0)
		return WR_E_AUTH_DECRYPT;
	*out_n = n - pad;
	return WR_OK;
}

static wr_status cx_dec2(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *in, size_t n,
			 uint8_t *out, size_t *out_n)
{
	const wr_prim_ops *prim = cx_prim(x);
	size_t m = n - CX_MAC; /* confounder + plaintext */
	uint8_t key[CX_KE_LEN], mac[CX_MAC];
	wr_status st;
	int ok;

	/* Integrity first: only Ki is derived, and nothing is decrypted if the MAC differs. */
	wri_cx_kdf(prim, k->secret, k->len, usage, 0x55, key, CX_KI_LEN);
	cx_mac2(prim, key, in, m, mac);
	ok = wri_ct_memeq(mac, in + m, CX_MAC);
	wri_secure_zero(mac, sizeof(mac));
	wri_secure_zero(key, sizeof(key));
	if (!ok)
		return WR_E_AUTH_DECRYPT;

	wri_cx_kdf(prim, k->secret, k->len, usage, 0xAA, key, CX_KE_LEN);
	st = wri_cts3_dec(prim, key, CX_KE_LEN, cx_zero_iv, in, m, out);
	wri_secure_zero(key, sizeof(key));
	if (st != WR_OK)
		return st;
	WR_MEMMOVE(out, out + CX_CONF, m - CX_CONF); /* drop the confounder */
	wri_secure_zero(out + (m - CX_CONF), CX_CONF);
	*out_n = m - CX_CONF;
	return WR_OK;
}

wr_status wri_cx_decrypt(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *in, size_t n,
			 uint8_t *out, size_t out_cap, size_t *out_n)
{
	size_t work;
	wr_status st;

	if (out_n == NULL)
		return WR_E_INVAL;
	*out_n = 0;
	st = cx_key_check(k);
	if (st != WR_OK)
		return st;
	if ((in == NULL && n != 0) || (out == NULL && out_cap != 0))
		return WR_E_INVAL;
	if (cx_overlap(in, n, out, out_cap))
		return WR_E_INVAL;
	if (k->type == WR_KEY_TYPE_AES) {
		if (n == 0 || (n & (CX_BS - 1u)) != 0)
			return WR_E_AUTH_DECRYPT;
		work = n;
	} else {
		if (n < CX_CONF + CX_MAC)
			return WR_E_AUTH_DECRYPT;
		work = n - CX_MAC;
	}
	if (out_cap < work)
		return WR_E_TOOBIG; /* out is the working area for the whole ciphertext */

	if (k->type == WR_KEY_TYPE_AES)
		st = cx_dec1(cx_prim(x), k, in, n, out, out_n);
	else
		st = cx_dec2(x, k, usage, in, n, out, out_n);
	if (st != WR_OK) {
		wri_secure_zero(out, work); /* no partial plaintext escapes */
		*out_n = 0;
	}
	return st;
}
