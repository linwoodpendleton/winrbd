/* SPDX-License-Identifier: MIT */
/*
 * ref_gcm.c - the independent reference AES-GCM (see ref_gcm.h for what it is for and what it is not).
 *
 * From FIPS 197 and SP 800-38D only. The state is a 16-byte array in the order of the input block, so byte
 * i is row (i % 4), column (i / 4). Everything is byte oriented and branches on data: this is a test oracle.
 */
#include <string.h>

#include "ref_gcm.h"

/* Overwrite n bytes in a way the compiler may not drop as a dead store (volatile stores). */
static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- != 0)
		*v++ = 0;
}

void ref_gcm_wipe(ref_gcm_key *k)
{
	wipe(k, sizeof(*k));
}

/* SP 800-38D 5.2.1.1: the IV has 1 .. 2^64 - 1 bits, the additional data at most 2^64 - 1 bits, the plaintext at
 * most 2^39 - 256 bits (2^36 - 32 bytes: past that the 32-bit block counter would wrap and reuse a keystream
 * block). The 2^61 limits make the bit lengths fit the 64-bit length fields without overflow. */
static int lengths_ok(size_t ivlen, size_t aadlen, size_t n)
{
	return ivlen != 0 && (uint64_t)ivlen < ((uint64_t)1 << 61) && (uint64_t)aadlen < ((uint64_t)1 << 61) &&
	       (uint64_t)n <= (((uint64_t)1 << 36) - 32);
}

/* ---- GF(2^8) --------------------------------------------------------------------------------- */

/* Product in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (0x11b), shift and add. */
static uint8_t gm8(uint8_t a, uint8_t b)
{
	uint8_t p = 0;
	int i;

	for (i = 0; i < 8; i++) {
		if (b & 1)
			p ^= a;
		b >>= 1;
		a = (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
	}
	return p;
}

static uint8_t rotl8(uint8_t x, int n)
{
	return (uint8_t)((x << n) | (x >> (8 - n)));
}

/* The S-box of FIPS 197 5.1.1: the multiplicative inverse in GF(2^8) (0 for 0), then the affine map. The inverses
 * come from the powers of the generator 3: with 3^i = x, the inverse of x is 3^(255 - i) because 3^255 = 1. */
static void make_sboxes(ref_aes *a)
{
	uint8_t pw[256], inv[256];
	unsigned i, x;
	uint8_t g = 1;

	for (i = 0; i < 255; i++) {
		pw[i] = g;
		g = gm8(g, 3);
	}
	pw[255] = 1; /* 3^255 = 3^0 */
	memset(inv, 0, sizeof(inv));
	for (i = 0; i < 255; i++)
		inv[pw[i]] = pw[(255 - i) % 255];
	for (x = 0; x < 256; x++) {
		uint8_t b = inv[x];
		uint8_t s = (uint8_t)(b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63);

		a->sbox[x] = s;
		a->isbox[s] = (uint8_t)x;
	}
}

/* ---- AES ------------------------------------------------------------------------------------- */

int ref_aes_init(ref_aes *a, const uint8_t *key, size_t keylen)
{
	size_t nk, total, i;
	uint8_t rcon = 1;

	memset(a, 0, sizeof(*a));
	if (keylen != 16 && keylen != 24 && keylen != 32)
		return -1;
	make_sboxes(a);
	nk = keylen / 4;
	a->rounds = (int)nk + 6;
	total = 4 * ((size_t)a->rounds + 1); /* words of the schedule */
	memcpy(a->rk, key, keylen);
	for (i = nk; i < total; i++) {
		uint8_t t[4];
		size_t j;

		memcpy(t, a->rk + 4 * (i - 1), 4);
		if (i % nk == 0) {
			uint8_t u = t[0];

			t[0] = (uint8_t)(a->sbox[t[1]] ^ rcon); /* RotWord, SubWord, Rcon */
			t[1] = a->sbox[t[2]];
			t[2] = a->sbox[t[3]];
			t[3] = a->sbox[u];
			rcon = (uint8_t)((rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0));
		} else if (nk > 6 && i % nk == 4) {
			for (j = 0; j < 4; j++)
				t[j] = a->sbox[t[j]];
		}
		for (j = 0; j < 4; j++)
			a->rk[4 * i + j] = (uint8_t)(a->rk[4 * (i - nk) + j] ^ t[j]);
	}
	return 0;
}

static void add_round_key(uint8_t s[16], const uint8_t *rk)
{
	int i;

	for (i = 0; i < 16; i++)
		s[i] ^= rk[i];
}

static void sub_bytes(uint8_t s[16], const uint8_t box[256])
{
	int i;

	for (i = 0; i < 16; i++)
		s[i] = box[s[i]];
}

/* Row r rotates left by r (encryption) or right by r (decryption). */
static void shift_rows(uint8_t s[16], int inverse)
{
	uint8_t t[16];
	int r, c;

	for (r = 0; r < 4; r++)
		for (c = 0; c < 4; c++) {
			int from = inverse ? (c + 4 - r) % 4 : (c + r) % 4;

			t[r + 4 * c] = s[r + 4 * from];
		}
	memcpy(s, t, 16);
}

static void mix_columns(uint8_t s[16], int inverse)
{
	static const uint8_t fwd[4] = {2, 3, 1, 1}, inv[4] = {14, 11, 13, 9};
	const uint8_t *m = inverse ? inv : fwd;
	uint8_t t[16];
	int r, c, k;

	for (c = 0; c < 4; c++)
		for (r = 0; r < 4; r++) {
			uint8_t v = 0;

			/* row r of the circulant matrix: coefficient m[(k - r) mod 4] on input row k */
			for (k = 0; k < 4; k++)
				v ^= gm8(m[(k + 4 - r) % 4], s[k + 4 * c]);
			t[r + 4 * c] = v;
		}
	memcpy(s, t, 16);
}

void ref_aes_encrypt_block(const ref_aes *a, const uint8_t in[16], uint8_t out[16])
{
	uint8_t s[16];
	int round;

	memcpy(s, in, 16);
	add_round_key(s, a->rk);
	for (round = 1; round < a->rounds; round++) {
		sub_bytes(s, a->sbox);
		shift_rows(s, 0);
		mix_columns(s, 0);
		add_round_key(s, a->rk + 16 * round);
	}
	sub_bytes(s, a->sbox);
	shift_rows(s, 0);
	add_round_key(s, a->rk + 16 * a->rounds);
	memcpy(out, s, 16);
	wipe(s, sizeof(s));
}

void ref_aes_decrypt_block(const ref_aes *a, const uint8_t in[16], uint8_t out[16])
{
	uint8_t s[16];
	int round;

	memcpy(s, in, 16);
	add_round_key(s, a->rk + 16 * a->rounds);
	for (round = a->rounds - 1; round >= 1; round--) {
		shift_rows(s, 1);
		sub_bytes(s, a->isbox);
		add_round_key(s, a->rk + 16 * round);
		mix_columns(s, 1);
	}
	shift_rows(s, 1);
	sub_bytes(s, a->isbox);
	add_round_key(s, a->rk);
	memcpy(out, s, 16);
	wipe(s, sizeof(s));
}

/* ---- GHASH ----------------------------------------------------------------------------------- */

void ref_gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16])
{
	uint8_t z[16], v[16];
	int i, j;

	memset(z, 0, 16);
	memcpy(v, y, 16);
	for (i = 0; i < 128; i++) {
		int lsb;

		if ((x[i / 8] >> (7 - i % 8)) & 1)
			for (j = 0; j < 16; j++)
				z[j] ^= v[j];
		lsb = v[15] & 1;
		for (j = 15; j > 0; j--)
			v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
		v[0] >>= 1;
		if (lsb)
			v[0] ^= 0xe1; /* R = 11100001 || 0^120 */
	}
	memcpy(out, z, 16);
}

/* Y = (Y xor blocks of data, the last one zero padded) * H, for each block. */
static void ghash_absorb(const uint8_t h[16], uint8_t y[16], const uint8_t *p, size_t n)
{
	while (n != 0) {
		uint8_t blk[16];
		size_t take = n < 16 ? n : 16;
		int i;

		memset(blk, 0, 16);
		memcpy(blk, p, take);
		for (i = 0; i < 16; i++)
			y[i] ^= blk[i];
		ref_gf128_mul(y, h, y);
		p += take;
		n -= take;
	}
}

static void put_be64(uint8_t *p, uint64_t v)
{
	int i;

	for (i = 7; i >= 0; i--) {
		p[i] = (uint8_t)v;
		v >>= 8;
	}
}

void ref_ghash(const uint8_t h[16], const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t ctlen,
	       uint8_t out[16])
{
	uint8_t y[16], lens[16];

	memset(y, 0, 16);
	ghash_absorb(h, y, aad, aadlen);
	ghash_absorb(h, y, ct, ctlen);
	put_be64(lens, (uint64_t)aadlen * 8u);
	put_be64(lens + 8, (uint64_t)ctlen * 8u);
	ghash_absorb(h, y, lens, 16);
	memcpy(out, y, 16);
}

/* ---- GCM ------------------------------------------------------------------------------------- */

int ref_gcm_setkey(ref_gcm_key *k, const uint8_t *key, size_t keylen)
{
	static const uint8_t zero[16] = {0};

	if (ref_aes_init(&k->aes, key, keylen) != 0)
		return -1;
	ref_aes_encrypt_block(&k->aes, zero, k->h);
	return 0;
}

/* J0 of SP 800-38D 7.1 step 2. */
static void make_j0(const ref_gcm_key *k, const uint8_t *iv, size_t ivlen, uint8_t j0[16])
{
	if (ivlen == 12) {
		memcpy(j0, iv, 12);
		j0[12] = 0;
		j0[13] = 0;
		j0[14] = 0;
		j0[15] = 1;
	} else {
		/* GHASH(IV || 0^(s+64) || [len(IV)]64): the generic hash with no additional data and the IV as the
		 * "ciphertext" has exactly that shape (zero pad, a zero 64-bit length of A, the IV's bit length). */
		ref_ghash(k->h, NULL, 0, iv, ivlen, j0);
	}
}

/* inc32: the last four bytes as a big-endian counter modulo 2^32. */
static void inc32(uint8_t cb[16])
{
	int i;

	for (i = 15; i >= 12; i--)
		if (++cb[i] != 0)
			break;
}

static void ctr_xor(const ref_gcm_key *k, const uint8_t j0[16], const uint8_t *in, size_t n, uint8_t *out)
{
	uint8_t cb[16], ks[16];
	size_t i, off = 0;

	memcpy(cb, j0, 16);
	while (off < n) {
		size_t take = n - off < 16 ? n - off : 16;

		inc32(cb);
		ref_aes_encrypt_block(&k->aes, cb, ks);
		for (i = 0; i < take; i++)
			out[off + i] = (uint8_t)(in[off + i] ^ ks[i]);
		off += take;
	}
	wipe(cb, sizeof(cb));
	wipe(ks, sizeof(ks));
}

static void make_tag(const ref_gcm_key *k, const uint8_t j0[16], const uint8_t *aad, size_t aadlen,
		     const uint8_t *ct, size_t n, uint8_t tag[16])
{
	uint8_t s[16], ej0[16];
	int i;

	ref_ghash(k->h, aad, aadlen, ct, n, s);
	ref_aes_encrypt_block(&k->aes, j0, ej0);
	for (i = 0; i < 16; i++)
		tag[i] = (uint8_t)(s[i] ^ ej0[i]);
	wipe(s, sizeof(s));
	wipe(ej0, sizeof(ej0));
}

int ref_gcm_encrypt(const ref_gcm_key *k, const uint8_t *iv, size_t ivlen, const uint8_t *aad, size_t aadlen,
		    const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[REF_GCM_TAG])
{
	uint8_t j0[16];

	if (!lengths_ok(ivlen, aadlen, n))
		return -1; /* nothing written */
	make_j0(k, iv, ivlen, j0);
	ctr_xor(k, j0, in, n, out);
	make_tag(k, j0, aad, aadlen, out, n, tag);
	wipe(j0, sizeof(j0));
	return 0;
}

int ref_gcm_decrypt(const ref_gcm_key *k, const uint8_t *iv, size_t ivlen, const uint8_t *aad, size_t aadlen,
		    const uint8_t *in, size_t n, const uint8_t tag[REF_GCM_TAG], uint8_t *out)
{
	uint8_t j0[16], want[16], diff = 0;
	int i;

	if (!lengths_ok(ivlen, aadlen, n)) {
		/* a zero IV length is a caller bug: zero the output as for a bad tag. Past the SP 800-38D size limits
		 * (64 GiB) the buffer is left alone: nothing was authenticated and nothing is released */
		if (ivlen == 0 && n != 0 && (uint64_t)n <= (((uint64_t)1 << 36) - 32))
			memset(out, 0, n);
		return -1;
	}
	make_j0(k, iv, ivlen, j0);
	make_tag(k, j0, aad, aadlen, in, n, want); /* over the ciphertext, before anything is written to out */
	for (i = 0; i < 16; i++)
		diff |= (uint8_t)(want[i] ^ tag[i]); /* every byte, no early exit */
	wipe(want, sizeof(want));
	if (diff != 0) {
		wipe(j0, sizeof(j0));
		if (n != 0)
			memset(out, 0, n);
		return -1;
	}
	ctr_xor(k, j0, in, n, out);
	wipe(j0, sizeof(j0));
	return 0;
}

int ref_gcm_seal(const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, const uint8_t *aad,
		 size_t aadlen, const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[REF_GCM_TAG])
{
	ref_gcm_key k;
	int rc;

	if (ref_gcm_setkey(&k, key, keylen) != 0) {
		ref_gcm_wipe(&k);
		return -1;
	}
	rc = ref_gcm_encrypt(&k, iv, ivlen, aad, aadlen, in, n, out, tag);
	ref_gcm_wipe(&k);
	return rc;
}

int ref_gcm_open(const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen, const uint8_t *aad,
		 size_t aadlen, const uint8_t *in, size_t n, const uint8_t tag[REF_GCM_TAG], uint8_t *out)
{
	ref_gcm_key k;
	int rc;

	if (ref_gcm_setkey(&k, key, keylen) != 0) {
		ref_gcm_wipe(&k);
		if (n != 0 && (uint64_t)n <= (((uint64_t)1 << 36) - 32))
			memset(out, 0, n);
		return -1;
	}
	rc = ref_gcm_decrypt(&k, iv, ivlen, aad, aadlen, in, n, tag, out);
	ref_gcm_wipe(&k);
	return rc;
}

/* ---- one msgr2 secure-mode operation ----------------------------------------------------------- */

void ref_secure_nonce_step(uint8_t nonce[REF_SECURE_NONCE], int rev)
{
	int i;

	if (rev == 0) {
		for (i = 0; i < 4; i++)
			if (++nonce[i] != 0)
				break;
	} else {
		for (i = 4; i < 12; i++)
			if (++nonce[i] != 0)
				break;
	}
}

void ref_secure_seal_rev(const uint8_t key[REF_SECURE_KEY], uint8_t nonce[REF_SECURE_NONCE], int rev,
			 const uint8_t *in, size_t n, uint8_t *out)
{
	ref_gcm_key k;
	uint8_t tag[REF_GCM_TAG];

	(void)ref_gcm_setkey(&k, key, REF_SECURE_KEY);
	(void)ref_gcm_encrypt(&k, nonce, REF_SECURE_NONCE, NULL, 0, in, n, out, tag);
	ref_gcm_wipe(&k);
	memcpy(out + n, tag, REF_GCM_TAG);
	ref_secure_nonce_step(nonce, rev);
}

int ref_secure_open_rev(const uint8_t key[REF_SECURE_KEY], uint8_t nonce[REF_SECURE_NONCE], int rev,
			const uint8_t *in, size_t n, uint8_t *out)
{
	ref_gcm_key k;
	uint8_t tag[REF_GCM_TAG];
	int rc;

	memcpy(tag, in + n, REF_GCM_TAG); /* before out is written: in == out is allowed */
	(void)ref_gcm_setkey(&k, key, REF_SECURE_KEY);
	rc = ref_gcm_decrypt(&k, nonce, REF_SECURE_NONCE, NULL, 0, in, n, tag, out);
	ref_gcm_wipe(&k);
	ref_secure_nonce_step(nonce, rev);
	return rc;
}

void ref_secure_seal(const uint8_t key[REF_SECURE_KEY], uint8_t nonce[REF_SECURE_NONCE], const uint8_t *in,
		     size_t n, uint8_t *out)
{
	ref_secure_seal_rev(key, nonce, 1, in, n, out);
}

int ref_secure_open(const uint8_t key[REF_SECURE_KEY], uint8_t nonce[REF_SECURE_NONCE], const uint8_t *in,
		    size_t n, uint8_t *out)
{
	return ref_secure_open_rev(key, nonce, 1, in, n, out);
}
