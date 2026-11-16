/* SPDX-License-Identifier: MIT */
/*
 * wri_hmac.c - HMAC-SHA256 and HMAC-SHA384 (RFC 2104) over a gather list.
 *
 *   HMAC(K, m) = H((K0 xor opad) || H((K0 xor ipad) || m))
 *
 * K0 is the key zero-padded to the hash block size (64 bytes for SHA-256, 128 for SHA-384);
 * a key longer than the block is replaced by its hash first. The message is the concatenation
 * of the gather elements; zero-length elements (with any base, NULL included) and an empty
 * list are fine, and nothing is copied: elements go straight into the hash.
 *
 * Everything lives on the stack and is wiped before returning (the key pad, the inner digest,
 * the hashed key). There are no failure paths.
 */
#include "wri_hash.h"

WR_FILE_LICENCE_MIT

#define WRI_HMAC_IPAD 0x36u
#define WRI_HMAC_OPAD 0x5cu

#define WRI_HMAC256_BLOCK 64u
#define WRI_HMAC384_BLOCK 128u

/* Wipe that the optimiser may not drop. */
static void wri_hmac_wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0)
		*v++ = 0;
}

/* Turn the pad buffer holding K0 xor from into K0 xor to (the two pad bytes differ). */
static void wri_hmac_repad(uint8_t *pad, size_t n, unsigned from, unsigned to)
{
	size_t i;

	for (i = 0; i < n; i++)
		pad[i] = (uint8_t)(pad[i] ^ (from ^ to));
}

void wri_hmac_sha256(const uint8_t *key, size_t klen, const wr_iov *iov, size_t niov, uint8_t out[32])
{
	wri_sha256_ctx c;
	uint8_t pad[WRI_HMAC256_BLOCK];
	uint8_t inner[WRI_SHA256_LEN];
	size_t i;

	/* K0 in pad; a long key is hashed first */
	WR_MEMSET(pad, 0, sizeof(pad));
	if (klen > sizeof(pad)) {
		wri_sha256_init(&c);
		wri_sha256_update(&c, key, klen);
		wri_sha256_final(&c, pad); /* 32 bytes, the rest stays zero */
	} else if (klen > 0) {
		WR_MEMCPY(pad, key, klen);
	}

	wri_hmac_repad(pad, sizeof(pad), 0, WRI_HMAC_IPAD); /* pad = K0 xor ipad */
	wri_sha256_init(&c);
	wri_sha256_update(&c, pad, sizeof(pad));
	for (i = 0; i < niov; i++)
		if (iov[i].len > 0)
			wri_sha256_update(&c, iov[i].base, iov[i].len);
	wri_sha256_final(&c, inner);

	wri_hmac_repad(pad, sizeof(pad), WRI_HMAC_IPAD, WRI_HMAC_OPAD); /* pad = K0 xor opad */
	wri_sha256_init(&c);
	wri_sha256_update(&c, pad, sizeof(pad));
	wri_sha256_update(&c, inner, sizeof(inner));
	wri_sha256_final(&c, out);

	wri_hmac_wipe(pad, sizeof(pad));
	wri_hmac_wipe(inner, sizeof(inner));
}

void wri_hmac_sha384(const uint8_t *key, size_t klen, const wr_iov *iov, size_t niov, uint8_t out[48])
{
	wri_sha512_ctx c;
	uint8_t pad[WRI_HMAC384_BLOCK];
	uint8_t inner[WRI_SHA384_LEN];
	size_t i;

	WR_MEMSET(pad, 0, sizeof(pad));
	if (klen > sizeof(pad)) {
		wri_sha384_init(&c);
		wri_sha384_update(&c, key, klen);
		wri_sha384_final(&c, pad); /* 48 bytes, the rest stays zero */
	} else if (klen > 0) {
		WR_MEMCPY(pad, key, klen);
	}

	wri_hmac_repad(pad, sizeof(pad), 0, WRI_HMAC_IPAD);
	wri_sha384_init(&c);
	wri_sha384_update(&c, pad, sizeof(pad));
	for (i = 0; i < niov; i++)
		if (iov[i].len > 0)
			wri_sha384_update(&c, iov[i].base, iov[i].len);
	wri_sha384_final(&c, inner);

	wri_hmac_repad(pad, sizeof(pad), WRI_HMAC_IPAD, WRI_HMAC_OPAD);
	wri_sha384_init(&c);
	wri_sha384_update(&c, pad, sizeof(pad));
	wri_sha384_update(&c, inner, sizeof(inner));
	wri_sha384_final(&c, out);

	wri_hmac_wipe(pad, sizeof(pad));
	wri_hmac_wipe(inner, sizeof(inner));
}
