/* SPDX-License-Identifier: MIT */
/*
 * wri_gcm.h - AES-GCM (NIST SP 800-38D) over the constant-time AES and GHASH of this directory: the portable implementation of
 * msgr2 secure mode's AES-128-GCM, streaming, 96-bit IV. Docs: docs/design/core-architecture.md 35.3.
 *
 * The shape follows how msgr2 uses GCM: a key set once per direction of a connection, then many short operations, each with its
 * own 12-byte IV, data arriving in pieces, one 16-byte tag at the end. The general entry points take any length (so the NIST
 * vectors, which have partial blocks and additional data, run against them unchanged); the msgr2 code calls them only with
 * multiples of 16 through wri_pgcm.h, which is also where a host override is chosen.
 *
 * Rules: the IV is supplied by the caller and used exactly as given (nonce policy lives in wri_m2_sec.h, not here); at most
 * 2^36 - 32 bytes per operation (WR_E_CRYPTO_LEN beyond: the counter would wrap); additional data only before the first data byte
 * (WR_E_STATE after); a decrypt writes plaintext as it goes and the caller acts on it only after wri_gcm_final_dec said WR_OK;
 * the tag comparison is constant time; wri_gcm_wipe erases key schedule, H, counter, tag mask and staging.
 *
 * Fail closed: a call refused inside a running operation (wrong state, bad length, NULL buffer, operation over the cap, a final
 * of the other direction, an IV that is not 12 bytes) ALSO ends that operation: counter, tag mask, hash value and staging are
 * erased and the object is "keyed, idle" again, so a caller that ignores a status cannot go on to a tag or an OK that covers
 * less than it meant to. Both finals end the operation whatever they return. Every entry point other than wri_gcm_setkey needs an
 * object that was zeroed, set up by wri_gcm_setkey or wiped (never indeterminate memory). In-place (in == out) is allowed,
 * partial overlap is refused (WR_E_INVAL, fail closed like the other refusals). Nonce
 * policy (never one IV twice under one key) is the caller's, wri_m2_sec.h; this layer uses the IV it is given. The two limits of SP 800-38D 5.2.1.1 are enforced: 2^36 - 32 bytes of data (so the 32-bit block counter, which
 * starts at 2, never wraps) and 2^61 - 1 bytes of additional data.
 */
#ifndef WRI_GCM_H
#define WRI_GCM_H

#include "wri_aesct.h"
#include "wri_ghash.h"

#define WRI_GCM_IV_LEN 12u
#define WRI_GCM_TAG_LEN 16u

typedef enum wri_gcm_state {
	WRI_GCM_NOKEY = 0,
	WRI_GCM_KEYED,   /* key set, no operation running */
	WRI_GCM_AAD,     /* an operation started, only additional data so far */
	WRI_GCM_DATA     /* data has been fed */
} wri_gcm_state;

typedef struct wri_gcm {
	wri_aesct_ctx aes;
	wri_ghash gh;
	uint8_t ctr[16];   /* next counter block */
	uint8_t ekj0[16];  /* E(K, J0): the tag mask */
	uint8_t part[16];  /* ghash staging of a partial block of ciphertext or additional data */
	uint8_t ks[16];    /* unused keystream of the block a partial update stopped in */
	uint64_t aad_len;  /* bytes */
	uint64_t data_len; /* bytes */
	uint8_t state;     /* wri_gcm_state */
	uint8_t dir;       /* 0 encrypt, 1 decrypt */
	uint8_t part_len;  /* bytes in part (0 .. 15) */
	uint8_t ks_left;   /* bytes of ks not yet used (0 .. 15) */
} wri_gcm;

/* klen 16 or 32 (WR_E_CRYPTO_KEY otherwise; a NULL key or object is WR_E_INVAL); derives H. Allowed again later: the previous key
 * and operation are erased first. On any failure the object is wiped (unkeyed). */
WR_MUST_CHECK wr_status wri_gcm_setkey(wri_gcm *g, const uint8_t *key, size_t klen);
/* Begin an operation: WR_E_STATE without a key; ivlen must be 12 (WR_E_CRYPTO_LEN); a NULL iv or a decrypt other than 0 or 1 is
 * WR_E_INVAL. An operation still running is discarded first (also when this call is refused). */
WR_MUST_CHECK wr_status wri_gcm_start(wri_gcm *g, const uint8_t *iv, size_t ivlen, int decrypt);
/* Additional authenticated data, before any data: WR_E_STATE after the first byte of data or without a start; n == 0 is a no-op
 * (and NULL p is fine); WR_E_CRYPTO_LEN beyond 2^61 - 1 bytes in total. May be called in pieces of any size. */
WR_MUST_CHECK wr_status wri_gcm_aad(wri_gcm *g, const uint8_t *p, size_t n);
/* Encrypt or decrypt n bytes (any n, in == out allowed; buffers that overlap without being the same range are WR_E_INVAL, nothing
 * written) and authenticate the ciphertext. WR_E_STATE without a start;
 * WR_E_CRYPTO_LEN when the operation would pass 2^36 - 32 bytes (nothing is written); n == 0 is a no-op and does not end the
 * additional data. A decrypt writes plain text as it goes: do not act on it before wri_gcm_final_dec said WR_OK. */
WR_MUST_CHECK wr_status wri_gcm_update(wri_gcm *g, const uint8_t *in, uint8_t *out, size_t n);
/* End an encrypt operation: the tag. WR_E_STATE when no encrypt operation is running (the tag is zeroed on every failure). */
WR_MUST_CHECK wr_status wri_gcm_final_enc(wri_gcm *g, uint8_t tag[WRI_GCM_TAG_LEN]);
/* End a decrypt operation: WR_OK, or WR_E_CRYPTO_MAC if the tag is wrong (constant time). */
WR_MUST_CHECK wr_status wri_gcm_final_dec(wri_gcm *g, const uint8_t tag[WRI_GCM_TAG_LEN]);
/* Discard the running operation (if any); the key stays. */
void wri_gcm_abort(wri_gcm *g);
/* Erase the whole object (key schedule, H, operation); it is unkeyed afterwards. */
void wri_gcm_wipe(wri_gcm *g);

#endif /* WRI_GCM_H */
