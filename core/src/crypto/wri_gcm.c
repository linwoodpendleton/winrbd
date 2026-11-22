/* SPDX-License-Identifier: MIT */
/*
 * wri_gcm.c - portable constant-time AES-GCM (see wri_gcm.h and docs/design/core-architecture.md 35.3), written from NIST
 * SP 800-38D: the counter blocks are J0 = IV || 0x00000001 for a 96-bit IV and inc32 afterwards, the tag mask is E(K, J0), the
 * authenticated string is A || pad || C || pad || [len(A)]64 || [len(C)]64 with the lengths in bits.
 *
 * Shape of an operation. start() sets the counter and the tag mask and clears GHASH; aad() feeds additional data (a partial last
 * block waits in `part`); the first update() with data pads and absorbs that partial block, then every update() takes any length:
 * whole blocks go straight through CTR and GHASH, and a tail shorter than a block draws a whole keystream block into `ks`, uses
 * the first bytes now and the rest at the next update(), while the ciphertext bytes of that block collect in `part` until it is
 * full. Invariant while data is flowing: ks_left + part_len is 16 or both are 0. Decrypt hashes the ciphertext BEFORE it is
 * turned into plain text (in place is allowed), encrypt hashes it afterwards.
 *
 * Fail closed. A refusal inside a running operation (a wrong state, a bad length, a missing buffer, an operation past the cap,
 * a final of the wrong direction) also ABORTS that operation: its counter, tag mask, hash value and staging are erased and the
 * object goes back to "keyed, idle", so a caller that ignores the status cannot go on to obtain a tag or an OK that covers less
 * than it meant to authenticate. The two finals end the operation on every path.
 *
 * Constant time: nothing here branches on, indexes by or loops over a key or data byte. The branches and loops depend on lengths,
 * the state and the direction, which are public; the tag is compared with wri_ct_memeq. The secret-bearing work is in wri_aesct
 * and wri_ghash (their headers carry the argument). Wiping covers every array this file owns (the key schedule and H are inside
 * the two sub-objects, which the same wipe erases); what portable C cannot reach is a scalar spilled to a dead stack frame, which
 * is the same limit as in the two headers.
 *
 * No libc beyond the memory macros, no global state, no allocation. Stack: the largest frame is the 16-byte local tag or hash
 * subkey buffer plus the callee's.
 */
#include "wri_gcm.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/* SP 800-38D 5.2.1.1: len(P) <= 2^39 - 256 bits = 2^36 - 32 bytes (the 32-bit counter starts at 2 and must not wrap), and
 * len(A) <= 2^64 - 1 bits, i.e. under 2^61 bytes. */
#define GCM_DATA_MAX (((uint64_t)1 << 36) - 32u)
#define GCM_AAD_MAX (((uint64_t)1 << 61) - 1u)

static void gcm_put_be64(uint8_t *p, uint64_t v)
{
	int i;

	for (i = 7; i >= 0; i--) {
		p[i] = (uint8_t)v;
		v >>= 8;
	}
}

/* Erase everything that belongs to the running operation (not the key schedule or H): back to "keyed, idle". */
static void gcm_end_op(wri_gcm *g)
{
	wri_secure_zero(g->ctr, sizeof(g->ctr));
	wri_secure_zero(g->ekj0, sizeof(g->ekj0));
	wri_secure_zero(g->part, sizeof(g->part));
	wri_secure_zero(g->ks, sizeof(g->ks));
	wri_ghash_reset(&g->gh);
	g->aad_len = 0;
	g->data_len = 0;
	g->part_len = 0;
	g->ks_left = 0;
	g->dir = 0;
	if (g->state != WRI_GCM_NOKEY)
		g->state = WRI_GCM_KEYED;
}

/* 1 when [in, in + n) and [out, out + n) overlap without being the same range (n > 0). In place is fine, a shifted overlap is not: the
 * keystream and hash steps work on several blocks at a time, so a write could land on input that has not been read yet. */
static int gcm_partial_overlap(const uint8_t *in, const uint8_t *out, size_t n)
{
	const uintptr_t a = (uintptr_t)in, b = (uintptr_t)out;

	if (a == b)
		return 0;
	return (a < b) ? ((b - a) < (uintptr_t)n) : ((a - b) < (uintptr_t)n);
}

/* Refuse: abort the operation (if any) and return the status. */
static wr_status gcm_refuse(wri_gcm *g, wr_status st)
{
	gcm_end_op(g);
	return st;
}

/* Pad the partial block in `part` with zeros and absorb it. */
static void gcm_flush_part(wri_gcm *g)
{
	size_t i;

	if (g->part_len == 0u)
		return;
	for (i = g->part_len; i < 16u; i++)
		g->part[i] = 0;
	wri_ghash_blocks(&g->gh, g->part, 1);
	wri_secure_zero(g->part, sizeof(g->part));
	g->part_len = 0;
}

wr_status wri_gcm_setkey(wri_gcm *g, const uint8_t *key, size_t klen)
{
	uint8_t h[16];
	wr_status st;

	if (g == NULL)
		return WR_E_INVAL;
	wri_secure_zero(g, sizeof(*g)); /* the previous key and operation are gone whatever happens next */
	st = wri_aesct_setkey(&g->aes, key, klen);
	if (st != WR_OK) {
		wri_secure_zero(g, sizeof(*g));
		return st;
	}
	WR_MEMSET(h, 0, sizeof(h));
	wri_aesct_encrypt_blocks(&g->aes, h, h, 1);
	wri_ghash_init(&g->gh, h);
	wri_secure_zero(h, sizeof(h));
	g->state = WRI_GCM_KEYED;
	return WR_OK;
}

wr_status wri_gcm_start(wri_gcm *g, const uint8_t *iv, size_t ivlen, int decrypt)
{
	if (g == NULL)
		return WR_E_INVAL;
	if (g->state == WRI_GCM_NOKEY)
		return WR_E_STATE;
	gcm_end_op(g); /* an operation that was never finished is discarded */
	if (ivlen != WRI_GCM_IV_LEN)
		return WR_E_CRYPTO_LEN;
	if (iv == NULL || (decrypt != 0 && decrypt != 1))
		return WR_E_INVAL;
	WR_MEMCPY(g->ctr, iv, WRI_GCM_IV_LEN);
	g->ctr[12] = 0;
	g->ctr[13] = 0;
	g->ctr[14] = 0;
	g->ctr[15] = 1;
	wri_aesct_encrypt_blocks(&g->aes, g->ctr, g->ekj0, 1); /* E(K, J0) */
	g->ctr[15] = 2;                                          /* the first data counter */
	g->dir = (uint8_t)decrypt;
	g->state = WRI_GCM_AAD;
	return WR_OK;
}

wr_status wri_gcm_aad(wri_gcm *g, const uint8_t *p, size_t n)
{
	size_t take, nb;

	if (g == NULL)
		return WR_E_INVAL;
	if (g->state != WRI_GCM_AAD)
		return gcm_refuse(g, WR_E_STATE); /* no operation, or data has already been fed */
	if (n == 0)
		return WR_OK;
	if (p == NULL)
		return gcm_refuse(g, WR_E_INVAL);
	if ((uint64_t)n > GCM_AAD_MAX - g->aad_len)
		return gcm_refuse(g, WR_E_CRYPTO_LEN);
	g->aad_len += (uint64_t)n;
	if (g->part_len != 0u) {
		take = 16u - g->part_len;
		if (take > n)
			take = n;
		WR_MEMCPY(g->part + g->part_len, p, take);
		g->part_len = (uint8_t)(g->part_len + take);
		p += take;
		n -= take;
		if (g->part_len == 16u) {
			wri_ghash_blocks(&g->gh, g->part, 1);
			wri_secure_zero(g->part, sizeof(g->part));
			g->part_len = 0;
		}
	}
	nb = n / 16u;
	if (nb != 0) {
		wri_ghash_blocks(&g->gh, p, nb);
		p += nb * 16u;
		n -= nb * 16u;
	}
	if (n != 0) {
		WR_MEMCPY(g->part, p, n);
		g->part_len = (uint8_t)n;
	}
	return WR_OK;
}

/* Step 1 of an update: use up the keystream block an earlier partial update stopped in. Takes at most n bytes, returns how many. */
static size_t gcm_drain_ks(wri_gcm *g, const uint8_t *in, uint8_t *out, size_t n)
{
	const size_t off = 16u - g->ks_left;
	size_t take = g->ks_left, i;

	if (take > n)
		take = n;
	for (i = 0; i < take; i++) {
		const uint8_t c = in[i];
		const uint8_t o = (uint8_t)(c ^ g->ks[off + i]);

		out[i] = o;
		g->part[g->part_len + i] = g->dir ? c : o;
		g->ks[off + i] = 0;
	}
	g->part_len = (uint8_t)(g->part_len + take);
	g->ks_left = (uint8_t)(g->ks_left - take);
	if (g->ks_left == 0u) {
		wri_ghash_blocks(&g->gh, g->part, 1);
		wri_secure_zero(g->part, sizeof(g->part));
		g->part_len = 0;
	}
	return take;
}

/* Step 2: nb whole blocks. Decrypt hashes the input first (it may be overwritten in place), encrypt hashes the output. */
static void gcm_blocks(wri_gcm *g, const uint8_t *in, uint8_t *out, size_t nb)
{
	if (g->dir) {
		wri_ghash_blocks(&g->gh, in, nb);
		wri_aesct_ctr32(&g->aes, g->ctr, in, out, nb * 16u);
	} else {
		wri_aesct_ctr32(&g->aes, g->ctr, in, out, nb * 16u);
		wri_ghash_blocks(&g->gh, out, nb);
	}
}

/* Step 3: a tail of 1 .. 15 bytes: one keystream block now, its unused part kept for the next call. */
static void gcm_tail(wri_gcm *g, const uint8_t *in, uint8_t *out, size_t n)
{
	size_t i;

	WR_MEMSET(g->ks, 0, sizeof(g->ks));
	wri_aesct_ctr32(&g->aes, g->ctr, g->ks, g->ks, 16u);
	for (i = 0; i < n; i++) {
		const uint8_t c = in[i];
		const uint8_t o = (uint8_t)(c ^ g->ks[i]);

		out[i] = o;
		g->part[i] = g->dir ? c : o;
		g->ks[i] = 0;
	}
	g->part_len = (uint8_t)n;
	g->ks_left = (uint8_t)(16u - n);
}

wr_status wri_gcm_update(wri_gcm *g, const uint8_t *in, uint8_t *out, size_t n)
{
	size_t take, nb;

	if (g == NULL)
		return WR_E_INVAL;
	if (g->state != WRI_GCM_AAD && g->state != WRI_GCM_DATA)
		return gcm_refuse(g, WR_E_STATE);
	if (n == 0)
		return WR_OK;
	if (in == NULL || out == NULL)
		return gcm_refuse(g, WR_E_INVAL);
	if (gcm_partial_overlap(in, out, n))
		return gcm_refuse(g, WR_E_INVAL); /* nothing written: the contract allows in == out and disjoint buffers only */
	if ((uint64_t)n > GCM_DATA_MAX - g->data_len)
		return gcm_refuse(g, WR_E_CRYPTO_LEN);
	if (g->state == WRI_GCM_AAD) {
		gcm_flush_part(g); /* the additional data ends here: a partial block is zero padded */
		g->state = WRI_GCM_DATA;
	}
	g->data_len += (uint64_t)n;

	if (g->ks_left != 0u) {
		take = gcm_drain_ks(g, in, out, n);
		in += take;
		out += take;
		n -= take;
	}
	nb = n / 16u;
	if (nb != 0) {
		gcm_blocks(g, in, out, nb);
		in += nb * 16u;
		out += nb * 16u;
		n -= nb * 16u;
	}
	if (n != 0)
		gcm_tail(g, in, out, n);
	return WR_OK;
}

/* Absorb the partial block and the length block and form the tag. The operation must be running in direction `dir`. */
static wr_status gcm_finish(wri_gcm *g, int dir, uint8_t tag[WRI_GCM_TAG_LEN])
{
	uint8_t lens[16];
	size_t i;

	if (g->state != WRI_GCM_AAD && g->state != WRI_GCM_DATA)
		return WR_E_STATE;
	if ((int)g->dir != dir)
		return WR_E_STATE;
	gcm_flush_part(g);
	gcm_put_be64(lens, g->aad_len << 3);
	gcm_put_be64(lens + 8, g->data_len << 3);
	wri_ghash_blocks(&g->gh, lens, 1);
	wri_ghash_get(&g->gh, tag);
	for (i = 0; i < WRI_GCM_TAG_LEN; i++)
		tag[i] = (uint8_t)(tag[i] ^ g->ekj0[i]);
	wri_secure_zero(lens, sizeof(lens));
	return WR_OK;
}

wr_status wri_gcm_final_enc(wri_gcm *g, uint8_t tag[WRI_GCM_TAG_LEN])
{
	wr_status st;

	if (tag == NULL)
		return (g != NULL) ? gcm_refuse(g, WR_E_INVAL) : WR_E_INVAL;
	if (g == NULL) {
		WR_MEMSET(tag, 0, WRI_GCM_TAG_LEN);
		return WR_E_INVAL;
	}
	st = gcm_finish(g, 0, tag);
	if (st != WR_OK)
		WR_MEMSET(tag, 0, WRI_GCM_TAG_LEN);
	gcm_end_op(g);
	return st;
}

wr_status wri_gcm_final_dec(wri_gcm *g, const uint8_t tag[WRI_GCM_TAG_LEN])
{
	uint8_t want[WRI_GCM_TAG_LEN];
	wr_status st;

	if (g == NULL)
		return WR_E_INVAL;
	if (tag == NULL)
		return gcm_refuse(g, WR_E_INVAL);
	st = gcm_finish(g, 1, want);
	if (st == WR_OK) {
		/* No branch on the comparison: 1 (equal) gives all-zero bits = WR_OK, 0 gives the mask of WR_E_CRYPTO_MAC. The caller's
		 * decision on the answer is the one place a tag mismatch becomes public. */
		st = (wr_status)((int32_t)WR_E_CRYPTO_MAC & ((int32_t)wri_ct_memeq(want, tag, WRI_GCM_TAG_LEN) - 1));
	}
	wri_secure_zero(want, sizeof(want));
	gcm_end_op(g);
	return st;
}

void wri_gcm_abort(wri_gcm *g)
{
	if (g != NULL)
		gcm_end_op(g);
}

void wri_gcm_wipe(wri_gcm *g)
{
	if (g != NULL)
		wri_secure_zero(g, sizeof(*g));
}
