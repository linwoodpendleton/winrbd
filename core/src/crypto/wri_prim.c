/* SPDX-License-Identifier: MIT */
/*
 * wri_prim.c - the dispatch layer declared in wri_prim.h.
 *
 * Every call looks at the host's primitive table (wr_prim_ops, wr_host.h). The host's member is
 * used only when ALL of these hold: the table pointer is not NULL, the table's `size` covers the
 * member (a host compiled against an older, shorter table never has a member read past its
 * end), and the member itself is not NULL. Otherwise the portable reference code runs. The test
 * is one pointer comparison per call; there is no state and nothing is cached.
 *
 * The core validates everything the AES calls can report before an override is entered: the key
 * length (16 or 32; the reference could also do 24, but the protocol never uses it and an override
 * is only promised those two), NULL arguments, the block count (so that nblocks * 16 fits in
 * size_t) and the buffer overlap rule (in == out exactly, or the two ranges do not touch; a partial
 * overlap is refused with WR_E_INVAL because no host CBC is promised to cope with it). An empty
 * call (nblocks == 0) succeeds without entering the override or reading any buffer. The same checks
 * guard the reference path, so a call fails the same way whichever code would have run it. A host
 * member that fails with a value that is not a valid failure code (a positive number) is reported
 * as WR_E_INVAL, so a buggy override can never look like success to a caller that tests for < 0.
 *
 * The crc32c and HMAC members cannot fail and are not validated: their callers (all inside the
 * core) build the gather list from lengths that were checked against the receive buffers, and pass
 * a non-NULL base for every non-empty element and a non-NULL key whenever klen != 0.
 *
 * The reference AES path derives a key schedule on the stack for each call, as the contract for
 * an override says a host does too, and wipes it before returning.
 */
#include "wri_prim.h"

#include "wri_aes.h"
#include "wri_crc32c.h"
#include "wri_hash.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/* True when the table can supply `member` (size covers it, pointer set). */
#define WRI_PRIM_HAS(prim, member) \
	((prim) != NULL && (prim)->size >= (offsetof(wr_prim_ops, member) + sizeof((prim)->member)) && \
	 (prim)->member != NULL)

uint32_t wri_p_crc32c(const wr_prim_ops *prim, uint32_t seed, const uint8_t *p, size_t n)
{
	if (WRI_PRIM_HAS(prim, crc32c))
		return prim->crc32c(prim->ctx, seed, p, n);
	return wri_crc32c(seed, p, n);
}

void wri_p_hmac_sha256(const wr_prim_ops *prim, const uint8_t *key, size_t klen, const wr_iov *iov,
		       size_t niov, uint8_t out[32])
{
	if (WRI_PRIM_HAS(prim, hmac_sha256)) {
		prim->hmac_sha256(prim->ctx, key, klen, iov, niov, out);
		return;
	}
	wri_hmac_sha256(key, klen, iov, niov, out);
}

void wri_p_hmac_sha384(const wr_prim_ops *prim, const uint8_t *key, size_t klen, const wr_iov *iov,
		       size_t niov, uint8_t out[48])
{
	if (WRI_PRIM_HAS(prim, hmac_sha384)) {
		prim->hmac_sha384(prim->ctx, key, klen, iov, niov, out);
		return;
	}
	wri_hmac_sha384(key, klen, iov, niov, out);
}

/* True when [a, a + n) and [b, b + n) share a byte but are not the same range. Written with the
 * distance of the two addresses so that no sum can wrap, whatever n is. */
static int wri_p_partial_overlap(const void *a, const void *b, size_t n)
{
	uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
	uintptr_t d = x > y ? x - y : y - x;

	return x != y && (uint64_t)d < (uint64_t)n;
}

/* Arguments every CBC call must satisfy before any code (override or reference) sees them.
 * Returns WR_OK for a call that has work to do; *empty is set (and WR_OK returned) when
 * nblocks == 0, so that the caller returns without touching a buffer or the override. */
static wr_status wri_p_cbc_check(const uint8_t *key, size_t klen, const uint8_t *iv, const uint8_t *in,
				 const uint8_t *out, size_t nblocks, int *empty)
{
	*empty = 0;
	if (key == NULL || (klen != 16u && klen != 32u))
		return WR_E_CRYPTO_KEY;
	if (nblocks > (size_t)-1 / 16u)
		return WR_E_CRYPTO_LEN;
	if (iv == NULL || (nblocks != 0 && (in == NULL || out == NULL)))
		return WR_E_INVAL;
	if (nblocks == 0) {
		*empty = 1;
		return WR_OK;
	}
	if (wri_p_partial_overlap(in, out, nblocks * 16u))
		return WR_E_INVAL;
	return WR_OK;
}

/* A host member may only return WR_OK or a negative code (wr_err.h). */
static wr_status wri_p_host_status(wr_status st)
{
	return st > 0 ? WR_E_INVAL : st;
}

wr_status wri_p_aes_cbc_enc(const wr_prim_ops *prim, const uint8_t *key, size_t klen, const uint8_t iv[16],
			    const uint8_t *in, uint8_t *out, size_t nblocks)
{
	wri_aes_ctx c;
	int empty;
	wr_status st = wri_p_cbc_check(key, klen, iv, in, out, nblocks, &empty);

	if (st != WR_OK || empty)
		return st;
	if (WRI_PRIM_HAS(prim, aes_cbc_enc))
		return wri_p_host_status(prim->aes_cbc_enc(prim->ctx, key, klen, iv, in, out, nblocks));
	st = wri_aes_setkey(&c, key, klen);
	if (st == WR_OK)
		wri_aes_cbc_enc(&c, iv, in, out, nblocks);
	wri_secure_zero(&c, sizeof(c));
	return st;
}

wr_status wri_p_aes_cbc_dec(const wr_prim_ops *prim, const uint8_t *key, size_t klen, const uint8_t iv[16],
			    const uint8_t *in, uint8_t *out, size_t nblocks)
{
	wri_aes_ctx c;
	int empty;
	wr_status st = wri_p_cbc_check(key, klen, iv, in, out, nblocks, &empty);

	if (st != WR_OK || empty)
		return st;
	if (WRI_PRIM_HAS(prim, aes_cbc_dec))
		return wri_p_host_status(prim->aes_cbc_dec(prim->ctx, key, klen, iv, in, out, nblocks));
	st = wri_aes_setkey(&c, key, klen);
	if (st == WR_OK)
		wri_aes_cbc_dec(&c, iv, in, out, nblocks);
	wri_secure_zero(&c, sizeof(c));
	return st;
}
