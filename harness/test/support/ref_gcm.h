/* SPDX-License-Identifier: MIT */
/*
 * ref_gcm.h - the independent reference AES-GCM of the secure-mode tests.
 *
 * Written from FIPS 197 (AES) and NIST SP 800-38D (GCM) and shares nothing with core/: no header, no table,
 * no helper. It is deliberately the dullest possible implementation, so that a bug in the core's fast or
 * constant-time code cannot hide behind the same bug here:
 *
 *   - AES is byte oriented. The S-box and its inverse are computed when a key is set, from the multiplicative
 *     inverse in GF(2^8) (modulus x^8 + x^4 + x^3 + x + 1) followed by the affine map of FIPS 197 5.1.1; there is
 *     no table in the source. All three key sizes (16, 24, 32 bytes) work (the GCM specification's test cases
 *     use all three); msgr2 uses 16.
 *   - GHASH multiplies in GF(2^128) one bit at a time (SP 800-38D algorithm 1).
 *   - GCM takes any IV length (J0 through GHASH when it is not 96 bits) and any additional data length.
 *   - ref_secure_seal / ref_secure_open do one msgr2 secure-mode operation in one call: AES-128-GCM, the 12-byte
 *     nonce of docs/spec/msgr2-secure-mode.md 2.6 used as the IV and stepped afterwards, no additional data, a
 *     16-byte tag appended to the ciphertext.
 *
 * Test code only: libc allowed, no global state (so it is safe to call from several threads), speed is not a
 * goal (a few hundred KB/s). The one-call forms, ref_secure_seal / ref_secure_open and the block and counter
 * temporaries wipe what they keyed (volatile stores), so the oracle does not leave a lab key on the stack; a
 * ref_gcm_key or ref_aes the caller owns is wiped with ref_gcm_wipe (or memset by the caller). Lengths beyond
 * SP 800-38D 5.2.1.1 (message over 2^36 - 32 bytes, IV or additional data of 2^61 bytes or more) are refused.
 * Buffers may overlap exactly (in = out, in place); partial overlap is not supported.
 */
#ifndef REF_GCM_H
#define REF_GCM_H

#include <stddef.h>
#include <stdint.h>

#define REF_AES_BLOCK 16
#define REF_GCM_TAG 16

/* ---- AES ------------------------------------------------------------------------------------- */

typedef struct ref_aes {
	uint8_t sbox[256];
	uint8_t isbox[256];
	uint8_t rk[15 * 16]; /* round keys, (rounds + 1) * 16 bytes used */
	int rounds;          /* 10, 12 or 14 */
} ref_aes;

/* keylen must be 16, 24 or 32. Returns 0, or -1 for any other length (the context is then unusable). */
int ref_aes_init(ref_aes *a, const uint8_t *key, size_t keylen);
void ref_aes_encrypt_block(const ref_aes *a, const uint8_t in[16], uint8_t out[16]);
void ref_aes_decrypt_block(const ref_aes *a, const uint8_t in[16], uint8_t out[16]);

/* ---- GHASH ----------------------------------------------------------------------------------- */

/* out = x * y in GF(2^128) with the bit order of SP 800-38D (the leftmost bit of byte 0 is x^0). */
void ref_gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]);

/* GHASH_H(A || pad || C || pad || [len(A)]64 || [len(C)]64): the whole GCM hash of additional data and
 * ciphertext, as SP 800-38D 6.4 defines it. */
void ref_ghash(const uint8_t h[16], const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t ctlen,
	       uint8_t out[16]);

/* ---- GCM ------------------------------------------------------------------------------------- */

typedef struct ref_gcm_key {
	ref_aes aes;
	uint8_t h[16]; /* the hash subkey, E_K(0^128) */
} ref_gcm_key;

/* keylen 16, 24 or 32. 0 or -1. */
int ref_gcm_setkey(ref_gcm_key *k, const uint8_t *key, size_t keylen);
/* Overwrite the whole key context (round keys, S-boxes, hash subkey) with zeros. */
void ref_gcm_wipe(ref_gcm_key *k);

/* Encrypt: out gets n ciphertext bytes (in == out allowed), tag gets 16 bytes. ivlen must be >= 1 (any length up
 * to what memory allows, SP 800-38D allows 1 .. 2^64 - 1 bits). Returns 0, or -1 when ivlen is 0 or a length is
 * beyond the SP 800-38D limits (nothing is written then). aad may be NULL
 * when aadlen is 0; in/out may be NULL when n is 0. */
int ref_gcm_encrypt(const ref_gcm_key *k, const uint8_t *iv, size_t ivlen, const uint8_t *aad, size_t aadlen,
		    const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[REF_GCM_TAG]);

/* Decrypt and verify: returns 0 when the tag matches (out holds the plaintext), -1 when it does not (out is
 * then zero-filled, so a caller that ignores the status cannot act on forged plaintext), when ivlen is 0 (zero-
 * filled too) or when a length is beyond the SP 800-38D limits (out untouched). The tag is authenticated before
 * any plaintext is produced, compared in full (16 bytes, every byte, no early exit); no shorter tag is accepted. */
int ref_gcm_decrypt(const ref_gcm_key *k, const uint8_t *iv, size_t ivlen, const uint8_t *aad, size_t aadlen,
		    const uint8_t *in, size_t n, const uint8_t tag[REF_GCM_TAG], uint8_t *out);

/* One-call forms (set the key, run, forget it). */
int ref_gcm_seal(const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, const uint8_t *aad,
		 size_t aadlen, const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[REF_GCM_TAG]);
int ref_gcm_open(const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, const uint8_t *aad,
		 size_t aadlen, const uint8_t *in, size_t n, const uint8_t tag[REF_GCM_TAG], uint8_t *out);

/* ---- one msgr2 secure-mode operation ----------------------------------------------------------- */

#define REF_SECURE_KEY 16
#define REF_SECURE_NONCE 12

/* Step a nonce as docs/spec/msgr2-secure-mode.md 2.6 says: rev 1 adds one to the little-endian 64-bit counter in
 * bytes 4..11 (wrapping modulo 2^64, no carry into bytes 0..3); rev 0 adds one to the little-endian 32-bit field
 * in bytes 0..3 (wrapping modulo 2^32). Any other rev is treated as 1. */
void ref_secure_nonce_step(uint8_t nonce[REF_SECURE_NONCE], int rev);

/* Seal one operation: out gets n ciphertext bytes followed by the 16-byte tag (n + 16 bytes; in == out allowed,
 * the tag is then written right behind the n bytes). The nonce is used as the IV and then stepped (rev 1). */
void ref_secure_seal(const uint8_t key[REF_SECURE_KEY], uint8_t nonce[REF_SECURE_NONCE], const uint8_t *in,
		     size_t n, uint8_t *out);
/* Open one operation: in holds n ciphertext bytes followed by the tag; out gets n plaintext bytes. Returns 0 or
 * -1 on a bad tag (out zero-filled). The nonce is stepped in both cases, as the stock receiver does. */
int ref_secure_open(const uint8_t key[REF_SECURE_KEY], uint8_t nonce[REF_SECURE_NONCE], const uint8_t *in,
		    size_t n, uint8_t *out);

/* The same with the nonce revision chosen (0 = msgr2.0, 32-bit step; 1 = msgr2.1). */
void ref_secure_seal_rev(const uint8_t key[REF_SECURE_KEY], uint8_t nonce[REF_SECURE_NONCE], int rev,
			 const uint8_t *in, size_t n, uint8_t *out);
int ref_secure_open_rev(const uint8_t key[REF_SECURE_KEY], uint8_t nonce[REF_SECURE_NONCE], int rev,
			const uint8_t *in, size_t n, uint8_t *out);

#endif /* REF_GCM_H */
