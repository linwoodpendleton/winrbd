/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_prim - the dispatch layer (core/src/crypto/wri_prim.c, declared in wri_prim.h).
 *
 * A fake override table counts calls and records the arguments it was given. Checked: with every
 * member set the override runs and its result is returned (the reference is not consulted); a NULL
 * table, a NULL member, and a `size` that stops before a member each fall back to the portable code
 * with results identical to the reference functions (known answers included); the members before the
 * cut-off still dispatch while the ones after it do not; ctx is passed through; key lengths other than
 * 16 and 32 (24 included) are refused before the override is entered, so is a block count whose byte
 * size would overflow; failures of an override are returned unchanged (a positive "failure" is turned
 * into WR_E_INVAL); in == out works through the reference path; a partial in/out overlap is refused
 * before the override is entered; nblocks == 0 touches nothing and never enters the override; a table
 * whose size stops one byte short of a member does not dispatch that member; HMAC-SHA384 known
 * answer (RFC 4231 case 1) and the empty-key / empty-list edge cases agree with the reference.
 */
#include "wrt.h"

#include "wri_aes.h"
#include "wri_crc32c.h"
#include "wri_hash.h"
#include "wri_prim.h"

static uint64_t rng_state = 0x13198a2e03707344ull;

static uint32_t rnd(void)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (uint32_t)((rng_state * 0x2545f4914f6cdd1dull) >> 32);
}

static void rnd_fill(uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)rnd();
}

struct fake {
	unsigned crc, h256, h384, enc, dec;
	uint32_t last_seed;
	size_t last_n, last_klen, last_nblocks, last_niov;
	const void *last_key;
	wr_status ret; /* returned by the AES members */
};

static uint32_t fk_crc(void *ctx, uint32_t seed, const uint8_t *p, size_t n)
{
	struct fake *f = (struct fake *)ctx;

	(void)p;
	f->crc++;
	f->last_seed = seed;
	f->last_n = n;
	return 0xC0FFEE00u;
}

static void fk_h256(void *ctx, const uint8_t *key, size_t klen, const wr_iov *iov, size_t niov, uint8_t out[32])
{
	struct fake *f = (struct fake *)ctx;

	(void)iov;
	f->h256++;
	f->last_key = key;
	f->last_klen = klen;
	f->last_niov = niov;
	memset(out, 0x56, 32);
}

static void fk_h384(void *ctx, const uint8_t *key, size_t klen, const wr_iov *iov, size_t niov, uint8_t out[48])
{
	struct fake *f = (struct fake *)ctx;

	(void)iov;
	f->h384++;
	f->last_key = key;
	f->last_klen = klen;
	f->last_niov = niov;
	memset(out, 0x84, 48);
}

static wr_status fk_enc(void *ctx, const uint8_t *key, size_t klen, const uint8_t iv[16], const uint8_t *in,
			uint8_t *out, size_t nb)
{
	struct fake *f = (struct fake *)ctx;

	(void)iv;
	(void)in;
	f->enc++;
	f->last_key = key;
	f->last_klen = klen;
	f->last_nblocks = nb;
	if (f->ret == WR_OK && nb != 0)
		memset(out, 0xEC, nb * 16);
	return f->ret;
}

static wr_status fk_dec(void *ctx, const uint8_t *key, size_t klen, const uint8_t iv[16], const uint8_t *in,
			uint8_t *out, size_t nb)
{
	struct fake *f = (struct fake *)ctx;

	(void)iv;
	(void)in;
	f->dec++;
	f->last_key = key;
	f->last_klen = klen;
	f->last_nblocks = nb;
	if (f->ret == WR_OK && nb != 0)
		memset(out, 0xDC, nb * 16);
	return f->ret;
}

static void full_ops(wr_prim_ops *o, struct fake *f)
{
	memset(o, 0, sizeof(*o));
	o->size = sizeof(*o);
	o->ctx = f;
	o->crc32c = fk_crc;
	o->hmac_sha256 = fk_h256;
	o->hmac_sha384 = fk_h384;
	o->aes_cbc_enc = fk_enc;
	o->aes_cbc_dec = fk_dec;
}

/* Run every dispatcher against the reference with a random input and check equality. */
static void check_equals_reference(const wr_prim_ops *prim, int *ran)
{
	uint8_t key[32], iv[16], buf[160], a[160], b[160], h1[48], h2[48];
	wr_iov iov[3];
	wri_aes_ctx c;
	size_t n = 1 + rnd() % 150, klen = (rnd() & 1) ? 16 : 32, nb = rnd() % 9;
	uint32_t seed = rnd();

	rnd_fill(key, sizeof(key));
	rnd_fill(iv, sizeof(iv));
	rnd_fill(buf, sizeof(buf));

	WRT_CHECK_U64(wri_p_crc32c(prim, seed, buf, n), wri_crc32c(seed, buf, n));

	iov[0].base = buf;
	iov[0].len = n / 3;
	iov[1].base = buf + n / 3;
	iov[1].len = n - n / 3;
	iov[2].base = NULL;
	iov[2].len = 0;
	{
		size_t kl = 1 + rnd() % 32;

		wri_p_hmac_sha256(prim, key, kl, iov, 3, h1);
		wri_hmac_sha256(key, kl, iov, 3, h2);
		WRT_CHECK_MEM(h1, h2, 32);
		wri_p_hmac_sha384(prim, key, kl, iov, 3, h1);
		wri_hmac_sha384(key, kl, iov, 3, h2);
		WRT_CHECK_MEM(h1, h2, 48);
	}

	WRT_CHECK(wri_aes_setkey(&c, key, klen) == WR_OK);
	wri_aes_cbc_enc(&c, iv, buf, a, nb);
	WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(prim, key, klen, iv, buf, b, nb));
	WRT_CHECK_MEM(a, b, nb * 16);
	wri_aes_cbc_dec(&c, iv, buf, a, nb);
	WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_dec(prim, key, klen, iv, buf, b, nb));
	WRT_CHECK_MEM(a, b, nb * 16);
	(*ran)++;
}

static void test_known_answers_no_table(void)
{
	static const uint8_t nine[9] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
	/* FIPS 197 C.1: key 000102..0f, plaintext 00112233..ff, zero IV so CBC of one block is ECB */
	static const uint8_t k128[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	static const uint8_t pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				       0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	static const uint8_t ct[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
				       0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
	static const uint8_t iv0[16];
	uint8_t out[16], back[16], mac[32];
	static const uint8_t k4231[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
					  0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
	wr_iov hi = {(const uint8_t *)"Hi There", 8};
	char hex[65];

	WRT_CHECK_U64(wri_p_crc32c(NULL, 0xFFFFFFFFu, nine, 9), 0x1CF96D7Cu);
	WRT_CHECK_U64(wri_p_crc32c(NULL, 0, nine, 9), 0x58E3FA20u);
	WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(NULL, k128, 16, iv0, pt, out, 1));
	WRT_CHECK_MEM(out, ct, 16);
	WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_dec(NULL, k128, 16, iv0, out, back, 1));
	WRT_CHECK_MEM(back, pt, 16);
	/* RFC 4231 case 1 */
	wri_p_hmac_sha256(NULL, k4231, 20, &hi, 1, mac);
	wrt_hex_encode(mac, 32, hex);
	WRT_CHECK(strcmp(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") == 0);
}

static void test_override_used(void)
{
	struct fake f;
	wr_prim_ops ops;
	uint8_t key[32] = {1}, iv[16] = {2}, buf[64] = {3}, out[64], mac[48];
	wr_iov iov = {buf, 5};

	memset(&f, 0, sizeof(f));
	full_ops(&ops, &f);

	WRT_CHECK_U64(wri_p_crc32c(&ops, 0x1234u, buf, 7), 0xC0FFEE00u);
	WRT_CHECK(f.crc == 1 && f.last_seed == 0x1234u && f.last_n == 7);
	wri_p_hmac_sha256(&ops, key, 32, &iov, 1, mac);
	WRT_CHECK(f.h256 == 1 && f.last_klen == 32 && f.last_key == key && f.last_niov == 1 && mac[0] == 0x56 &&
		  mac[31] == 0x56);
	wri_p_hmac_sha384(&ops, key, 7, &iov, 1, mac);
	WRT_CHECK(f.h384 == 1 && f.last_klen == 7 && mac[0] == 0x84 && mac[47] == 0x84);
	WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(&ops, key, 16, iv, buf, out, 3));
	WRT_CHECK(f.enc == 1 && f.last_klen == 16 && f.last_nblocks == 3 && out[0] == 0xEC && out[47] == 0xEC);
	WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_dec(&ops, key, 32, iv, buf, out, 2));
	WRT_CHECK(f.dec == 1 && f.last_klen == 32 && f.last_nblocks == 2 && out[0] == 0xDC && out[31] == 0xDC);
	WRT_CHECK(f.enc == 1 && f.crc == 1 && f.h256 == 1 && f.h384 == 1);

	/* failures are returned unchanged and the call is still counted once */
	f.ret = WR_E_CRYPTO_LEN;
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_p_aes_cbc_enc(&ops, key, 16, iv, buf, out, 1));
	f.ret = WR_E_CRYPTO_KEY;
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_p_aes_cbc_dec(&ops, key, 16, iv, buf, out, 1));
	WRT_CHECK(f.enc == 2 && f.dec == 2);
}

static void test_fallbacks(void)
{
	struct fake f;
	wr_prim_ops ops;
	int i, ran = 0;

	memset(&f, 0, sizeof(f));

	/* NULL table */
	for (i = 0; i < 50; i++)
		check_equals_reference(NULL, &ran);

	/* a table with every member NULL, full size */
	memset(&ops, 0, sizeof(ops));
	ops.size = sizeof(ops);
	ops.ctx = &f;
	for (i = 0; i < 50; i++)
		check_equals_reference(&ops, &ran);

	/* size 0, and sizes that cut the table at each member: members before the cut dispatch,
	 * members from the cut on fall back to the reference (the fake would give wrong answers) */
	{
		size_t sizes[8], s;

		sizes[0] = 0;
		sizes[1] = offsetof(wr_prim_ops, ctx);      /* covers size only */
		sizes[2] = offsetof(wr_prim_ops, crc32c);   /* covers size, ctx */
		sizes[3] = offsetof(wr_prim_ops, hmac_sha256);
		sizes[4] = offsetof(wr_prim_ops, hmac_sha384);
		sizes[5] = offsetof(wr_prim_ops, aes_cbc_enc);
		sizes[6] = offsetof(wr_prim_ops, aes_cbc_dec);
		sizes[7] = sizeof(ops);
		for (s = 0; s < 8; s++) {
			uint8_t key[32] = {5}, iv[16] = {6}, buf[64] = {7}, out[64], mac[48];
			wr_iov iov = {buf, 9};
			uint32_t want;

			full_ops(&ops, &f);
			ops.size = (uint32_t)sizes[s];
			memset(&f, 0, sizeof(f));
			want = wri_crc32c(9, buf, 20);
			WRT_CHECK_U64(wri_p_crc32c(&ops, 9, buf, 20), s > 2 ? 0xC0FFEE00u : want);
			WRT_CHECK((f.crc == 1) == (s > 2));
			wri_p_hmac_sha256(&ops, key, 16, &iov, 1, mac);
			WRT_CHECK((f.h256 == 1) == (s > 3));
			wri_p_hmac_sha384(&ops, key, 16, &iov, 1, mac);
			WRT_CHECK((f.h384 == 1) == (s > 4));
			WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(&ops, key, 16, iv, buf, out, 2));
			WRT_CHECK((f.enc == 1) == (s > 5));
			WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_dec(&ops, key, 16, iv, buf, out, 2));
			WRT_CHECK((f.dec == 1) == (s > 6));
			(void)s;
		}
	}

	/* one NULL member does not disable the others */
	full_ops(&ops, &f);
	ops.crc32c = NULL;
	memset(&f, 0, sizeof(f));
	{
		uint8_t buf[8] = {1}, key[16] = {1}, iv[16] = {0}, out[16];

		WRT_CHECK_U64(wri_p_crc32c(&ops, 3, buf, 8), wri_crc32c(3, buf, 8));
		WRT_CHECK(f.crc == 0);
		WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(&ops, key, 16, iv, buf, out, 1));
		WRT_CHECK(f.enc == 1);
	}
	/* NULL dec and hmac_sha384 members fall back while the others still dispatch */
	full_ops(&ops, &f);
	ops.aes_cbc_dec = NULL;
	ops.hmac_sha384 = NULL;
	memset(&f, 0, sizeof(f));
	{
		uint8_t key[32] = {9}, iv[16] = {8}, ct[32], want[32], got[32], m1[48], m2[48];
		wr_iov iov = {key, 11};
		wri_aes_ctx c;

		WRT_CHECK(wri_aes_setkey(&c, key, 32) == WR_OK);
		memset(ct, 0x31, sizeof(ct));
		wri_aes_cbc_dec(&c, iv, ct, want, 2);
		WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_dec(&ops, key, 32, iv, ct, got, 2));
		WRT_CHECK_MEM(got, want, 32);
		wri_p_hmac_sha384(&ops, key, 5, &iov, 1, m1);
		wri_hmac_sha384(key, 5, &iov, 1, m2);
		WRT_CHECK_MEM(m1, m2, 48);
		WRT_CHECK(f.dec == 0 && f.h384 == 0);
		WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(&ops, key, 32, iv, ct, got, 1));
		wri_p_hmac_sha256(&ops, key, 5, &iov, 1, m1);
		WRT_CHECK(f.enc == 1 && f.h256 == 1);
	}
	WRT_CHECK(ran == 100);
}

static void test_arg_validation(void)
{
	struct fake f;
	wr_prim_ops ops;
	uint8_t key[32] = {1}, iv[16] = {2}, buf[48] = {3}, out[48];
	size_t kl;
	const wr_prim_ops *tables[2];
	size_t t;

	memset(&f, 0, sizeof(f));
	full_ops(&ops, &f);
	tables[0] = NULL;
	tables[1] = &ops;

	for (t = 0; t < 2; t++) {
		const wr_prim_ops *p = tables[t];

		for (kl = 0; kl <= 40; kl++) {
			wr_status want = (kl == 16 || kl == 32) ? WR_OK : WR_E_CRYPTO_KEY;

			memset(&f, 0, sizeof(f));
			WRT_CHECK_STATUS(want, wri_p_aes_cbc_enc(p, key, kl, iv, buf, out, 2));
			WRT_CHECK_STATUS(want, wri_p_aes_cbc_dec(p, key, kl, iv, buf, out, 2));
			if (want != WR_OK) /* the override must not be entered */
				WRT_CHECK(f.enc == 0 && f.dec == 0);
		}
		memset(&f, 0, sizeof(f));
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_p_aes_cbc_enc(p, NULL, 32, iv, buf, out, 1));
		WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_p_aes_cbc_enc(p, key, 32, iv, buf, out, (size_t)-1));
		WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_p_aes_cbc_dec(p, key, 32, iv, buf, out, (size_t)-1 / 16u + 1u));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_p_aes_cbc_enc(p, key, 32, NULL, buf, out, 1));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_p_aes_cbc_dec(p, key, 32, iv, NULL, out, 1));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_p_aes_cbc_dec(p, key, 32, iv, buf, NULL, 1));
		WRT_CHECK(f.enc == 0 && f.dec == 0);
		/* zero blocks: ok, buffers may be NULL, nothing written */
		memset(out, 0x99, sizeof(out));
		WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(p, key, 32, iv, NULL, NULL, 0));
		WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_dec(p, key, 16, iv, buf, out, 0));
		WRT_CHECK(out[0] == 0x99);
		/* ... and an empty call never enters the override, but still validates key and iv */
		WRT_CHECK(f.enc == 0 && f.dec == 0);
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_p_aes_cbc_enc(p, key, 24, iv, NULL, NULL, 0));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_p_aes_cbc_dec(p, key, 16, NULL, NULL, NULL, 0));
		WRT_CHECK(f.enc == 0 && f.dec == 0);
	}
}

/* in == out is fine, disjoint is fine (even adjacent), anything in between is WR_E_INVAL and never
 * reaches the override (nor writes a byte). */
static void test_overlap(void)
{
	struct fake f;
	wr_prim_ops ops;
	uint8_t key[32] = {1}, iv[16] = {2}, buf[16 * 8];
	const wr_prim_ops *tables[2];
	size_t t, nb, off;

	memset(&f, 0, sizeof(f));
	full_ops(&ops, &f);
	tables[0] = NULL;
	tables[1] = &ops;
	for (t = 0; t < 2; t++) {
		for (nb = 1; nb <= 3; nb++) {
			for (off = 0; off <= 16 * 4; off++) {
				uint8_t keep[sizeof(buf)];
				wr_status want;
				uint8_t *in = buf, *out = buf + off;
				size_t bytes = nb * 16;

				/* off 0: same range (ok); 0 < off < bytes: partial overlap; off >= bytes: disjoint */
				want = (off != 0 && off < bytes) ? WR_E_INVAL : WR_OK;
				if (off + bytes > sizeof(buf))
					continue;
				rnd_fill(buf, sizeof(buf));
				memcpy(keep, buf, sizeof(buf));
				memset(&f, 0, sizeof(f));
				WRT_CHECK_STATUS(want, wri_p_aes_cbc_enc(tables[t], key, 32, iv, in, out, nb));
				if (want == WR_E_INVAL) {
					WRT_CHECK_MEM(buf, keep, sizeof(buf));
					WRT_CHECK(f.enc == 0);
				}
				if (want == WR_OK && t == 1)
					WRT_CHECK(f.enc == 1);
				/* the same with the output below the input */
				memcpy(buf, keep, sizeof(buf));
				memset(&f, 0, sizeof(f));
				WRT_CHECK_STATUS(want, wri_p_aes_cbc_dec(tables[t], key, 16, iv, out, in, nb));
				if (want == WR_E_INVAL)
					WRT_CHECK(f.dec == 0);
			}
		}
	}
	/* an absurd block count cannot wrap the overlap test into a false "disjoint": the count is
	 * refused first */
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_p_aes_cbc_enc(NULL, key, 16, iv, buf, buf + 3, (size_t)-1 / 16u + 1u));
	/* the largest legal count with distinct small buffers is a partial overlap, not a read past them */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_p_aes_cbc_enc(NULL, key, 16, iv, buf, buf + 64, (size_t)-1 / 16u));
}

/* A host that returns a positive number as a failure must not look like success. */
static void test_override_status(void)
{
	struct fake f;
	wr_prim_ops ops;
	uint8_t key[32] = {1}, iv[16] = {2}, buf[32] = {3}, out[32];

	memset(&f, 0, sizeof(f));
	full_ops(&ops, &f);
	f.ret = (wr_status)5;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_p_aes_cbc_enc(&ops, key, 16, iv, buf, out, 2));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_p_aes_cbc_dec(&ops, key, 32, iv, buf, out, 2));
	f.ret = (wr_status)0x7fffffff;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_p_aes_cbc_enc(&ops, key, 16, iv, buf, out, 1));
	/* a negative code, even one outside the crypto block, is passed through unchanged */
	f.ret = WR_E_HOST_RANDOM;
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_p_aes_cbc_enc(&ops, key, 16, iv, buf, out, 1));
	f.ret = WR_E_CRYPTO_MAC;
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, wri_p_aes_cbc_dec(&ops, key, 16, iv, buf, out, 1));
	WRT_CHECK(f.enc == 3 && f.dec == 2);
}

/* size one byte short of a member: that member is not used (its last byte would be read past the
 * host's table). One byte past the start of the member is also short. */
static void test_size_boundary(void)
{
	struct fake f;
	wr_prim_ops ops;
	uint8_t key[32] = {5}, iv[16] = {6}, buf[64] = {7}, out[64], mac[48];
	wr_iov iov = {buf, 9};
	size_t ends[5], i;

	ends[0] = offsetof(wr_prim_ops, crc32c) + sizeof(ops.crc32c);
	ends[1] = offsetof(wr_prim_ops, hmac_sha256) + sizeof(ops.hmac_sha256);
	ends[2] = offsetof(wr_prim_ops, hmac_sha384) + sizeof(ops.hmac_sha384);
	ends[3] = offsetof(wr_prim_ops, aes_cbc_enc) + sizeof(ops.aes_cbc_enc);
	ends[4] = offsetof(wr_prim_ops, aes_cbc_dec) + sizeof(ops.aes_cbc_dec);
	for (i = 0; i < 5; i++) {
		unsigned short_by;

		for (short_by = 0; short_by <= 1; short_by++) {
			unsigned hit[5];

			full_ops(&ops, &f);
			ops.size = (uint32_t)(ends[i] - short_by);
			memset(&f, 0, sizeof(f));
			(void)wri_p_crc32c(&ops, 1, buf, 4);
			wri_p_hmac_sha256(&ops, key, 16, &iov, 1, mac);
			wri_p_hmac_sha384(&ops, key, 16, &iov, 1, mac);
			WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(&ops, key, 16, iv, buf, out, 1));
			WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_dec(&ops, key, 16, iv, buf, out, 1));
			hit[0] = f.crc, hit[1] = f.h256, hit[2] = f.h384, hit[3] = f.enc, hit[4] = f.dec;
			/* members 0..i-1 fit entirely; member i fits only when short_by == 0 */
			{
				size_t m;

				for (m = 0; m < 5; m++)
					WRT_CHECK(hit[m] == ((m < i || (m == i && short_by == 0)) ? 1u : 0u));
			}
		}
	}
}

/* HMAC edge cases through the dispatcher match the reference: empty key, empty list, key longer
 * than both block sizes, many tiny elements. And HMAC-SHA384 RFC 4231 case 1. */
static void test_hmac_dispatch(void)
{
	static const uint8_t k20[20] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
					0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
	wr_iov hi = {(const uint8_t *)"Hi There", 8};
	uint8_t mac[48], ref[48], key[200], msg[64];
	wr_iov many[64];
	char hex[97];
	size_t i, klen;
	static const size_t klens[] = {0, 1, 32, 48, 63, 64, 65, 127, 128, 129, 200};

	wri_p_hmac_sha384(NULL, k20, 20, &hi, 1, mac);
	wrt_hex_encode(mac, 48, hex);
	WRT_CHECK(strcmp(hex, "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
			      "faea9ea9076ede7f4af152e8b2fa9cb6") == 0);

	rnd_fill(key, sizeof(key));
	rnd_fill(msg, sizeof(msg));
	for (i = 0; i < 64; i++) {
		many[i].base = msg + i;
		many[i].len = 1;
	}
	for (i = 0; i < sizeof(klens) / sizeof(klens[0]); i++) {
		klen = klens[i];
		wri_p_hmac_sha256(NULL, klen ? key : NULL, klen, NULL, 0, mac);
		wri_hmac_sha256(klen ? key : NULL, klen, NULL, 0, ref);
		WRT_CHECK_MEM(mac, ref, 32);
		wri_p_hmac_sha384(NULL, klen ? key : NULL, klen, NULL, 0, mac);
		wri_hmac_sha384(klen ? key : NULL, klen, NULL, 0, ref);
		WRT_CHECK_MEM(mac, ref, 48);
		wri_p_hmac_sha384(NULL, key, klen, many, 64, mac);
		wri_hmac_sha384(key, klen, many, 64, ref);
		WRT_CHECK_MEM(mac, ref, 48);
		/* the same message as one element */
		{
			wr_iov one = {msg, 64};

			wri_p_hmac_sha384(NULL, key, klen, &one, 1, ref);
			WRT_CHECK_MEM(mac, ref, 48);
		}
	}
}

static void test_in_place_reference(void)
{
	uint8_t key[32], iv[16], pt[96], *buf, ref[96];
	size_t klen, nb;

	for (klen = 16; klen <= 32; klen += 16) {
		for (nb = 0; nb <= 6; nb++) {
			rnd_fill(key, sizeof(key));
			rnd_fill(iv, sizeof(iv));
			rnd_fill(pt, sizeof(pt));
			buf = (uint8_t *)malloc(nb * 16 + 1);
			WRT_CHECK(buf != NULL);
			memcpy(buf, pt, nb * 16);
			WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(NULL, key, klen, iv, pt, ref, nb));
			WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_enc(NULL, key, klen, iv, buf, buf, nb));
			WRT_CHECK_MEM(buf, ref, nb * 16);
			WRT_CHECK_STATUS(WR_OK, wri_p_aes_cbc_dec(NULL, key, klen, iv, buf, buf, nb));
			WRT_CHECK_MEM(buf, pt, nb * 16);
			free(buf);
		}
	}
}

int main(void)
{
	test_known_answers_no_table();
	test_override_used();
	test_fallbacks();
	test_arg_validation();
	test_overlap();
	test_override_status();
	test_size_boundary();
	test_hmac_dispatch();
	test_in_place_reference();
	return wrt_finish();
}
