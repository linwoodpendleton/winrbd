/* SPDX-License-Identifier: MIT */
/*
 * test_ref_gcm - the reference AES-GCM (harness/test/support/ref_gcm.c) that every secure-mode test is built on.
 * The reference is only useful if it is right, so it is checked against things that are not it:
 *
 *   - FIPS 197: the S-box (generated from the field inverse) and every block vector of appendix B and C.1 to C.3,
 *     both directions, plus the last round key of appendix A.1;
 *   - the 18 test cases of the GCM specification and the CAVP cases of harness/vectors/secure/gcm-nist.json, in
 *     both directions, out of place and in place, through the one-call and the keyed API;
 *   - every single-bit change of ciphertext, tag, additional data, IV (and key) of every vector is refused, and the
 *     refused plaintext buffer is all zero; so are a few structural changes (truncation, data moved between the
 *     additional data and the ciphertext, a different IV length with the same leading bytes);
 *   - message lengths 0 to 100 against additional-data lengths 0 to 100: round trip, in place equals out of place,
 *     and the tag equals a second computation of the hash by powers of H (a different algebraic route than the
 *     reference's Horner loop); the same bit-flip sweep for every message length 0 to 100;
 *   - GF(2^128) multiplication laws (identity, commutative, distributive, associative) on random operands;
 *   - msgr2 secure mode: ref_secure_seal / ref_secure_open against frames A and B of docs/spec/msgr2-secure-mode.md
 *     5.2 (through the multi-operation walk of every frame of secure-frames-synthetic.json: operation sizes,
 *     nonce stepping, all tags), the nonce step of both revisions including the wrap, and the failure behaviour.
 *
 *   - IV lengths that are a whole number of blocks (16, 32, 128 bytes; the published cases have none), as literals
 *     computed with OpenSSL; the SP 800-38D length limits; the key wipe; nonce stepping checked against a counter the
 *     test keeps itself (a run across the 2^64 wrap, a different nonce for every operation); every bit of a secure
 *     operation refused, also in place; the frame walk checks the preamble CRC, the zero padding and the empty segment slots.
 *
 * Agreement with OpenSSL on random inputs is test_ref_gcm_ossl.c (built only where libcrypto exists).
 */
#include "wrt.h"

#include "ref_gcm.h"

/* ---- helpers --------------------------------------------------------------------------------- */

static uint64_t rng_state = 0x243f6a8885a308d3ull;

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

/* Decode a hex literal into buf (at most max bytes); returns the length, 0 on any error. */
static size_t hx(const char *hex, uint8_t *buf, size_t max)
{
	uint8_t *tmp = NULL;
	size_t n = 0;

	if (wrt_hex_decode(hex, strlen(hex), &tmp, &n) != 0)
		return 0;
	if (n > max) {
		free(tmp);
		return 0;
	}
	if (n != 0)
		memcpy(buf, tmp, n);
	free(tmp);
	return n;
}

static int all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

/* ---- AES ------------------------------------------------------------------------------------- */

/* The S-box by the definition, written differently from the reference: the inverse found by searching for the
 * element whose product is 1 (a bitwise product written here), then the affine transformation of FIPS 197
 * equation 5.1 bit by bit, s_i = b_i + b_(i+4) + b_(i+5) + b_(i+6) + b_(i+7) + c_i, c = 0x63. */
static unsigned gmul_slow(unsigned a, unsigned b)
{
	unsigned r = 0;
	int i;

	for (i = 7; i >= 0; i--) {
		r <<= 1;
		if (r & 0x100)
			r ^= 0x11b;
		if ((b >> i) & 1)
			r ^= a;
	}
	return r;
}

static unsigned sbox_by_definition(unsigned x)
{
	unsigned inv = 0, y, s = 0;
	int i;

	if (x != 0)
		for (y = 1; y < 256; y++)
			if (gmul_slow(x, y) == 1) {
				inv = y;
				break;
			}
	for (i = 0; i < 8; i++) {
		unsigned bit = ((inv >> i) ^ (inv >> ((i + 4) % 8)) ^ (inv >> ((i + 5) % 8)) ^ (inv >> ((i + 6) % 8)) ^
				(inv >> ((i + 7) % 8)) ^ (0x63u >> i)) & 1u;

		s |= bit << i;
	}
	return s;
}

static void test_aes(void)
{
	static ref_aes a;
	uint8_t key[32], in[16], want[16], out[16], back[16];
	unsigned x, seen_ok = 1;
	size_t kl;
	static const size_t bad_lens[] = {0, 1, 15, 17, 20, 23, 25, 31, 33, 48, 64};
	size_t i;

	/* the S-box: spot values of FIPS 197 figure 7, bijection, inverse table consistency */
	WRT_CHECK_U64(hx("000102030405060708090a0b0c0d0e0f", key, 32), 16);
	WRT_CHECK_STATUS(0, ref_aes_init(&a, key, 16));
	WRT_CHECK_U64(a.sbox[0x00], 0x63);
	WRT_CHECK_U64(a.sbox[0x01], 0x7c);
	WRT_CHECK_U64(a.sbox[0x02], 0x77);
	WRT_CHECK_U64(a.sbox[0x53], 0xed); /* the worked example of FIPS 197 5.1.1 */
	WRT_CHECK_U64(a.sbox[0x80], 0xcd);
	WRT_CHECK_U64(a.sbox[0xff], 0x16);
	WRT_CHECK_U64(a.isbox[0x63], 0x00);
	WRT_CHECK_U64(a.isbox[0xed], 0x53);
	{
		int hit[256];

		memset(hit, 0, sizeof(hit));
		for (x = 0; x < 256; x++) {
			hit[a.sbox[x]]++;
			if (a.isbox[a.sbox[x]] != x)
				seen_ok = 0;
		}
		for (x = 0; x < 256; x++)
			if (hit[x] != 1)
				seen_ok = 0;
		WRT_CHECK(seen_ok);
		for (x = 0; x < 256; x++)
			WRT_CHECK_U64(a.sbox[x], sbox_by_definition(x));
	}

	/* FIPS 197 appendix A.1: the last word of the AES-128 schedule for 2b7e1516..., and the round count */
	kl = hx("2b7e151628aed2a6abf7158809cf4f3c", key, 32);
	WRT_CHECK_U64(kl, 16);
	WRT_CHECK_STATUS(0, ref_aes_init(&a, key, kl));
	WRT_CHECK_U64(a.rounds, 10);
	hx("d014f9a8c9ee2589e13f0cc8b6630ca6", want, 16);
	WRT_CHECK_MEM(a.rk + 160, want, 16);
	/* appendix B */
	hx("3243f6a8885a308d313198a2e0370734", in, 16);
	hx("3925841d02dc09fbdc118597196a0b32", want, 16);
	ref_aes_encrypt_block(&a, in, out);
	WRT_CHECK_MEM(out, want, 16);
	ref_aes_decrypt_block(&a, want, back);
	WRT_CHECK_MEM(back, in, 16);

	/* appendix C.1 to C.3: plaintext 00112233..., key 00 01 02 ... of 16, 24, 32 bytes */
	hx("00112233445566778899aabbccddeeff", in, 16);
	for (i = 0; i < 3; i++) {
		static const size_t klen[3] = {16, 24, 32};
		static const char *ct[3] = {"69c4e0d86a7b0430d8cdb78070b4c55a", "dda97ca4864cdfe06eaf70a0ec0d7191",
					    "8ea2b7ca516745bfeafc49904b496089"};
		static const int rounds[3] = {10, 12, 14};
		size_t j;

		for (j = 0; j < klen[i]; j++)
			key[j] = (uint8_t)j;
		WRT_CHECK_STATUS(0, ref_aes_init(&a, key, klen[i]));
		WRT_CHECK_U64(a.rounds, rounds[i]);
		hx(ct[i], want, 16);
		ref_aes_encrypt_block(&a, in, out);
		WRT_CHECK_MEM(out, want, 16);
		ref_aes_decrypt_block(&a, want, back);
		WRT_CHECK_MEM(back, in, 16);
		/* in place */
		memcpy(out, in, 16);
		ref_aes_encrypt_block(&a, out, out);
		WRT_CHECK_MEM(out, want, 16);
		ref_aes_decrypt_block(&a, out, out);
		WRT_CHECK_MEM(out, in, 16);
	}

	/* random keys and blocks: decrypt inverts encrypt for all three sizes */
	for (i = 0; i < 300; i++) {
		static const size_t klen[3] = {16, 24, 32};
		size_t l = klen[i % 3];

		rnd_fill(key, l);
		rnd_fill(in, 16);
		WRT_CHECK_STATUS(0, ref_aes_init(&a, key, l));
		ref_aes_encrypt_block(&a, in, out);
		ref_aes_decrypt_block(&a, out, back);
		WRT_CHECK_MEM(back, in, 16);
	}

	/* every other key length is refused */
	memset(key, 0x11, sizeof(key));
	for (i = 0; i < sizeof(bad_lens) / sizeof(bad_lens[0]); i++) {
		if (bad_lens[i] > sizeof(key))
			continue;
		WRT_CHECK_STATUS(-1, ref_aes_init(&a, key, bad_lens[i]));
	}
}

/* ---- GF(2^128) ------------------------------------------------------------------------------- */

static void test_gf128(void)
{
	uint8_t one[16], a[16], b[16], c[16], t1[16], t2[16], t3[16];
	int i, j;

	memset(one, 0, 16);
	one[0] = 0x80; /* the field element 1 (x^0) is the leftmost bit */
	for (i = 0; i < 200; i++) {
		rnd_fill(a, 16);
		rnd_fill(b, 16);
		rnd_fill(c, 16);
		ref_gf128_mul(a, one, t1);
		WRT_CHECK_MEM(t1, a, 16);
		ref_gf128_mul(one, a, t1);
		WRT_CHECK_MEM(t1, a, 16);
		ref_gf128_mul(a, b, t1);
		ref_gf128_mul(b, a, t2);
		WRT_CHECK_MEM(t1, t2, 16); /* commutative */
		for (j = 0; j < 16; j++)
			t3[j] = (uint8_t)(b[j] ^ c[j]);
		ref_gf128_mul(a, t3, t1);
		ref_gf128_mul(a, b, t2);
		ref_gf128_mul(a, c, t3);
		for (j = 0; j < 16; j++)
			t2[j] ^= t3[j];
		WRT_CHECK_MEM(t1, t2, 16); /* distributive over xor */
		ref_gf128_mul(a, b, t1);
		ref_gf128_mul(t1, c, t1);
		ref_gf128_mul(b, c, t2);
		ref_gf128_mul(a, t2, t2);
		WRT_CHECK_MEM(t1, t2, 16); /* associative */
	}
	/* multiplying by x (0x40 00 ...) shifts right by one bit and reduces with 0xe1 when a bit falls off */
	memset(a, 0, 16);
	a[0] = 0x40;
	memset(b, 0, 16);
	b[15] = 0x01; /* x^127 */
	ref_gf128_mul(a, b, t1);
	memset(t2, 0, 16);
	t2[0] = 0xe1; /* x^128 = x^7 + x^2 + x + 1 */
	WRT_CHECK_MEM(t1, t2, 16);
}

/* ---- the published vectors ---------------------------------------------------------------------- */

typedef struct tcase {
	char *name;
	uint8_t *key, *iv, *aad, *pt, *ct, *tag;
	size_t keylen, ivlen, aadlen, ptlen, ctlen, taglen;
} tcase;

static void tcase_free(tcase *c)
{
	free(c->name);
	free(c->key);
	free(c->iv);
	free(c->aad);
	free(c->pt);
	free(c->ct);
	free(c->tag);
}

static int tcase_load(const wrt_json *j, wrt_tok t, tcase *c)
{
	memset(c, 0, sizeof(*c));
	c->name = wrt_json_strdup(j, wrt_json_get(j, t, "name"));
	if (wrt_json_get_hex(j, t, "key_hex", &c->key, &c->keylen) != 0 ||
	    wrt_json_get_hex(j, t, "iv_hex", &c->iv, &c->ivlen) != 0 ||
	    wrt_json_get_hex(j, t, "aad_hex", &c->aad, &c->aadlen) != 0 ||
	    wrt_json_get_hex(j, t, "pt_hex", &c->pt, &c->ptlen) != 0 ||
	    wrt_json_get_hex(j, t, "ct_hex", &c->ct, &c->ctlen) != 0 ||
	    wrt_json_get_hex(j, t, "tag_hex", &c->tag, &c->taglen) != 0 || c->name == NULL) {
		tcase_free(c);
		return -1;
	}
	return 0;
}

/* Every single-bit change of IV, additional data, ciphertext, tag (and key) must be refused, with an all-zero
 * output buffer. `k` is keyed once for the changes that do not touch the key. */
static void sweep_bitflips(const char *name, const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
			   const uint8_t *aad, size_t aadlen, const uint8_t *ct, size_t n, const uint8_t *tag,
			   int with_key)
{
	ref_gcm_key k;
	uint8_t *civ = (uint8_t *)malloc(ivlen), *caad = (uint8_t *)malloc(aadlen + 1), *cct = (uint8_t *)malloc(n + 1),
		*out = (uint8_t *)malloc(n + 1), ctag[16], ckey[32];
	size_t bit, refused = 0, tried = 0;

	if (!civ || !caad || !cct || !out) {
		WRT_CHECK(0);
		free(civ);
		free(caad);
		free(cct);
		free(out);
		return;
	}
	WRT_CHECK_STATUS(0, ref_gcm_setkey(&k, key, keylen));
	/* sanity: the unmodified input is accepted, so a refusal below is due to the change alone */
	memset(out, 0xaa, n + 1);
	WRT_CHECK_STATUS(0, ref_gcm_decrypt(&k, iv, ivlen, aad, aadlen, ct, n, tag, out));

#define EXPECT_REFUSED(call)                                                                      \
	do {                                                                                      \
		memset(out, 0xaa, n + 1);                                                         \
		tried++;                                                                          \
		if ((call) != 0 && all_zero(out, n) && out[n] == 0xaa)                            \
			refused++;                                                                \
	} while (0)

	for (bit = 0; bit < ivlen * 8; bit++) {
		memcpy(civ, iv, ivlen);
		civ[bit / 8] ^= (uint8_t)(1u << (bit % 8));
		EXPECT_REFUSED(ref_gcm_decrypt(&k, civ, ivlen, aad, aadlen, ct, n, tag, out));
	}
	for (bit = 0; bit < aadlen * 8; bit++) {
		memcpy(caad, aad, aadlen);
		caad[bit / 8] ^= (uint8_t)(1u << (bit % 8));
		EXPECT_REFUSED(ref_gcm_decrypt(&k, iv, ivlen, caad, aadlen, ct, n, tag, out));
	}
	for (bit = 0; bit < n * 8; bit++) {
		memcpy(cct, ct, n);
		cct[bit / 8] ^= (uint8_t)(1u << (bit % 8));
		EXPECT_REFUSED(ref_gcm_decrypt(&k, iv, ivlen, aad, aadlen, cct, n, tag, out));
	}
	for (bit = 0; bit < 128; bit++) {
		memcpy(ctag, tag, 16);
		ctag[bit / 8] ^= (uint8_t)(1u << (bit % 8));
		EXPECT_REFUSED(ref_gcm_decrypt(&k, iv, ivlen, aad, aadlen, ct, n, ctag, out));
	}
	if (with_key) {
		ref_gcm_key kk;

		for (bit = 0; bit < keylen * 8; bit++) {
			memcpy(ckey, key, keylen);
			ckey[bit / 8] ^= (uint8_t)(1u << (bit % 8));
			WRT_CHECK_STATUS(0, ref_gcm_setkey(&kk, ckey, keylen));
			EXPECT_REFUSED(ref_gcm_decrypt(&kk, iv, ivlen, aad, aadlen, ct, n, tag, out));
		}
	}
#undef EXPECT_REFUSED
	if (refused != tried) {
		fprintf(stderr, "%s: only %zu of %zu single-bit changes refused\n", name, refused, tried);
		WRT_CHECK(0);
	} else {
		WRT_CHECK(tried >= 128 + ivlen * 8);
	}
	free(civ);
	free(caad);
	free(cct);
	free(out);
}

static void test_vectors(void)
{
	wrt_json j;
	wrt_tok cases;
	size_t i, nc, checked = 0;

	if (wrt_json_load_vec(&j, "secure/gcm-nist.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	cases = wrt_json_get(&j, wrt_json_root(&j), "cases");
	nc = wrt_json_count(&j, cases);
	WRT_CHECK(nc >= 20); /* 18 of the GCM specification + the CAVP ones */
	for (i = 0; i < nc; i++) {
		tcase c;
		ref_gcm_key k;
		uint8_t out[128], tag[16], buf[128];

		if (tcase_load(&j, wrt_json_at(&j, cases, i), &c) != 0) {
			WRT_CHECK(0);
			continue;
		}
		WRT_CHECK(c.ptlen == c.ctlen && c.taglen == 16 && c.ptlen < sizeof(out) && c.ivlen >= 1);
		if (c.ptlen != c.ctlen || c.taglen != 16 || c.ptlen >= sizeof(out)) {
			tcase_free(&c);
			continue;
		}
		checked++;

		/* encrypt (one-call and keyed API) */
		memset(out, 0x5a, sizeof(out));
		memset(tag, 0x5a, 16);
		WRT_CHECK_STATUS(0, ref_gcm_seal(c.key, c.keylen, c.iv, c.ivlen, c.aad, c.aadlen, c.pt, c.ptlen, out, tag));
		if (memcmp(out, c.ct, c.ptlen) != 0 || memcmp(tag, c.tag, 16) != 0)
			fprintf(stderr, "vector %s: encrypt differs\n", c.name);
		WRT_CHECK_MEM(out, c.ct, c.ptlen);
		WRT_CHECK_MEM(tag, c.tag, 16);
		WRT_CHECK(out[c.ptlen] == 0x5a); /* nothing written past the end */
		WRT_CHECK_STATUS(0, ref_gcm_setkey(&k, c.key, c.keylen));
		memset(tag, 0, 16);
		WRT_CHECK_STATUS(0, ref_gcm_encrypt(&k, c.iv, c.ivlen, c.aad, c.aadlen, c.pt, c.ptlen, out, tag));
		WRT_CHECK_MEM(out, c.ct, c.ptlen);
		WRT_CHECK_MEM(tag, c.tag, 16);

		/* in place */
		memcpy(buf, c.pt, c.ptlen);
		WRT_CHECK_STATUS(0, ref_gcm_encrypt(&k, c.iv, c.ivlen, c.aad, c.aadlen, buf, c.ptlen, buf, tag));
		WRT_CHECK_MEM(buf, c.ct, c.ptlen);
		WRT_CHECK_MEM(tag, c.tag, 16);

		/* decrypt (one-call, keyed, in place) */
		memset(out, 0x5a, sizeof(out));
		WRT_CHECK_STATUS(0, ref_gcm_open(c.key, c.keylen, c.iv, c.ivlen, c.aad, c.aadlen, c.ct, c.ctlen, c.tag, out));
		WRT_CHECK_MEM(out, c.pt, c.ptlen);
		WRT_CHECK(out[c.ptlen] == 0x5a);
		memset(out, 0x5a, sizeof(out));
		WRT_CHECK_STATUS(0, ref_gcm_decrypt(&k, c.iv, c.ivlen, c.aad, c.aadlen, c.ct, c.ctlen, c.tag, out));
		WRT_CHECK_MEM(out, c.pt, c.ptlen);
		memcpy(buf, c.ct, c.ctlen);
		WRT_CHECK_STATUS(0, ref_gcm_decrypt(&k, c.iv, c.ivlen, c.aad, c.aadlen, buf, c.ctlen, c.tag, buf));
		WRT_CHECK_MEM(buf, c.pt, c.ptlen);

		/* the bit-flip sweep, key included */
		sweep_bitflips(c.name, c.key, c.keylen, c.iv, c.ivlen, c.aad, c.aadlen, c.ct, c.ctlen, c.tag, 1);

		/* structural changes */
		if (c.ptlen > 0) {
			memset(out, 0xaa, sizeof(out));
			WRT_CHECK_STATUS(-1, ref_gcm_decrypt(&k, c.iv, c.ivlen, c.aad, c.aadlen, c.ct, c.ctlen - 1, c.tag, out));
		}
		if (c.aadlen > 0) {
			/* data moved from the additional data into the ciphertext position keeps the byte string but not
			 * the structure (the hash covers the two lengths) */
			uint8_t both[256];

			if (c.aadlen + c.ctlen <= sizeof(both)) {
				memcpy(both, c.aad, c.aadlen);
				memcpy(both + c.aadlen, c.ct, c.ctlen);
				memset(out, 0xaa, sizeof(out));
				WRT_CHECK_STATUS(-1, ref_gcm_decrypt(&k, c.iv, c.ivlen, NULL, 0, both, c.aadlen + c.ctlen, c.tag,
								     out));
				WRT_CHECK_STATUS(-1, ref_gcm_decrypt(&k, c.iv, c.ivlen, c.aad, c.aadlen - 1, c.ct, c.ctlen, c.tag, out));
			}
		}
		/* the IV with one byte more or one byte less is another IV */
		if (c.ivlen > 1)
			WRT_CHECK_STATUS(-1, ref_gcm_decrypt(&k, c.iv, c.ivlen - 1, c.aad, c.aadlen, c.ct, c.ctlen, c.tag, out));
		{
			uint8_t longiv[80];

			if (c.ivlen < sizeof(longiv)) {
				memcpy(longiv, c.iv, c.ivlen);
				longiv[c.ivlen] = 0;
				WRT_CHECK_STATUS(-1, ref_gcm_decrypt(&k, longiv, c.ivlen + 1, c.aad, c.aadlen, c.ct, c.ctlen, c.tag, out));
			}
		}
		tcase_free(&c);
	}
	WRT_CHECK(checked == nc);
	wrt_json_free(&j);
}

/* ---- argument checks ------------------------------------------------------------------------- */

static void test_args(void)
{
	uint8_t key[16] = {1}, iv[12] = {2}, in[8] = {3}, out[8], tag[16];
	ref_gcm_key k;

	WRT_CHECK_STATUS(-1, ref_gcm_setkey(&k, key, 15));
	WRT_CHECK_STATUS(-1, ref_gcm_setkey(&k, key, 0));
	WRT_CHECK_STATUS(-1, ref_gcm_seal(key, 17, iv, 12, NULL, 0, in, 8, out, tag));
	WRT_CHECK_STATUS(0, ref_gcm_setkey(&k, key, 16));
	WRT_CHECK_STATUS(-1, ref_gcm_encrypt(&k, iv, 0, NULL, 0, in, 8, out, tag));
	memset(out, 0xee, sizeof(out));
	WRT_CHECK_STATUS(-1, ref_gcm_decrypt(&k, iv, 0, NULL, 0, in, 8, tag, out));
	WRT_CHECK(all_zero(out, 8));
	memset(out, 0xee, sizeof(out));
	WRT_CHECK_STATUS(-1, ref_gcm_open(key, 3, iv, 12, NULL, 0, in, 8, tag, out));
	WRT_CHECK(all_zero(out, 8));
	/* NULL pointers where the length is zero */
	WRT_CHECK_STATUS(0, ref_gcm_encrypt(&k, iv, 12, NULL, 0, NULL, 0, NULL, tag));
	WRT_CHECK_STATUS(0, ref_gcm_decrypt(&k, iv, 12, NULL, 0, NULL, 0, tag, NULL));
}

/* ---- lengths 0 .. 100 ---------------------------------------------------------------------------- */

/* The tag by a second route: S = sum over the blocks X_i of A || pad || C || pad || lengths of X_i * H^(m + 1 - i),
 * the powers of H taken one by one, then tag = S xor E(J0) (J0 from the 96-bit IV). Not the reference's Horner
 * loop: if the loop mishandled the block order or the padding, the two would differ. */
static void tag_by_powers(const ref_gcm_key *k, const uint8_t iv[12], const uint8_t *aad, size_t aadlen,
			  const uint8_t *ct, size_t n, uint8_t tag[16])
{
	uint8_t blocks[16 * 64], j0[16], ej0[16], s[16], p[16];
	size_t nb = 0, i, off;
	size_t m;
	int b;

	memset(blocks, 0, sizeof(blocks));
	for (off = 0; off < aadlen; off += 16, nb++)
		memcpy(blocks + 16 * nb, aad + off, aadlen - off < 16 ? aadlen - off : 16);
	for (off = 0; off < n; off += 16, nb++)
		memcpy(blocks + 16 * nb, ct + off, n - off < 16 ? n - off : 16);
	for (i = 0; i < 8; i++) {
		blocks[16 * nb + 7 - i] = (uint8_t)(((uint64_t)aadlen * 8u) >> (8 * i));
		blocks[16 * nb + 15 - i] = (uint8_t)(((uint64_t)n * 8u) >> (8 * i));
	}
	nb++;
	m = nb;
	memset(s, 0, 16);
	/* H^1 is k->h; block i (0-based) is multiplied by H^(m - i) */
	for (i = 0; i < m; i++) {
		size_t e = m - i, q;

		memcpy(p, k->h, 16);
		for (q = 1; q < e; q++)
			ref_gf128_mul(p, k->h, p);
		ref_gf128_mul(blocks + 16 * i, p, p);
		for (b = 0; b < 16; b++)
			s[b] ^= p[b];
	}
	memcpy(j0, iv, 12);
	j0[12] = 0;
	j0[13] = 0;
	j0[14] = 0;
	j0[15] = 1;
	ref_aes_encrypt_block(&k->aes, j0, ej0);
	for (b = 0; b < 16; b++)
		tag[b] = (uint8_t)(s[b] ^ ej0[b]);
}

static void test_lengths(void)
{
	size_t n, a;
	static const size_t keylens[3] = {16, 24, 32};

	for (n = 0; n <= 100; n++) {
		uint8_t key[32], iv[12], aad[100], pt[100], ct[100], ct2[100], back[100], tag[16], tag2[16], tag3[16];
		ref_gcm_key k;
		size_t kl = keylens[n % 3];

		rnd_fill(key, kl);
		rnd_fill(iv, 12);
		rnd_fill(pt, 100);
		rnd_fill(aad, 100);
		WRT_CHECK_STATUS(0, ref_gcm_setkey(&k, key, kl));
		for (a = 0; a <= 100; a++) {
			WRT_CHECK_STATUS(0, ref_gcm_encrypt(&k, iv, 12, aad, a, pt, n, ct, tag));
			WRT_CHECK_STATUS(0, ref_gcm_decrypt(&k, iv, 12, aad, a, ct, n, tag, back));
			if (memcmp(back, pt, n) != 0)
				WRT_CHECK(0);
			if (a % 9 == 0 || a == 100) {
				/* in place equals out of place, and the second computation of the tag agrees */
				memcpy(ct2, pt, n);
				WRT_CHECK_STATUS(0, ref_gcm_encrypt(&k, iv, 12, aad, a, ct2, n, ct2, tag2));
				WRT_CHECK(memcmp(ct, ct2, n) == 0 && memcmp(tag, tag2, 16) == 0);
				tag_by_powers(&k, iv, aad, a, ct, n, tag3);
				WRT_CHECK_MEM(tag3, tag, 16);
				WRT_CHECK_STATUS(0, ref_gcm_decrypt(&k, iv, 12, aad, a, ct2, n, tag2, ct2));
				WRT_CHECK(memcmp(ct2, pt, n) == 0);
			}
		}
		/* CTR property: with the data length changed the common prefix of the ciphertext is the same */
		if (n > 0) {
			WRT_CHECK_STATUS(0, ref_gcm_encrypt(&k, iv, 12, NULL, 0, pt, n - 1, ct2, tag2));
			WRT_CHECK(memcmp(ct, ct2, n - 1) == 0 || n < 1);
		}
		/* the bit-flip sweep for this message length (additional data and IV length vary with it) */
		{
			size_t alen = (n * 7) % 41, ivlen = (n % 3 == 0) ? 12 : (n % 3 == 1 ? 8 : 20);
			uint8_t ivb[20];

			memcpy(ivb, iv, 12);
			rnd_fill(ivb + 12, 8);
			WRT_CHECK_STATUS(0, ref_gcm_encrypt(&k, ivb, ivlen, aad, alen, pt, n, ct, tag));
			sweep_bitflips("lengths", key, kl, ivb, ivlen, aad, alen, ct, n, tag, n % 10 == 0);
		}
	}
}

/* ---- non-96-bit IVs agree with their definition ------------------------------------------------ */

/* For an IV that is not 96 bits J0 is a hash of the IV (SP 800-38D 7.1); the published cases cover three such
 * lengths. Here every IV length from 1 to 130 bytes round-trips and gives another tag than every other length
 * for the same leading bytes (the IV length is part of what is hashed). */
static void test_iv_lengths(void)
{
	uint8_t key[16], iv[130], pt[40], ct[40], back[40], tags[131][16];
	ref_gcm_key k;
	size_t l, m;

	rnd_fill(key, 16);
	rnd_fill(iv, sizeof(iv));
	rnd_fill(pt, sizeof(pt));
	WRT_CHECK_STATUS(0, ref_gcm_setkey(&k, key, 16));
	for (l = 1; l <= 130; l++) {
		WRT_CHECK_STATUS(0, ref_gcm_encrypt(&k, iv, l, NULL, 0, pt, sizeof(pt), ct, tags[l]));
		WRT_CHECK_STATUS(0, ref_gcm_decrypt(&k, iv, l, NULL, 0, ct, sizeof(pt), tags[l], back));
		WRT_CHECK_MEM(back, pt, sizeof(pt));
	}
	for (l = 1; l <= 130; l++)
		for (m = l + 1; m <= 130; m++)
			if (memcmp(tags[l], tags[m], 16) == 0)
				WRT_CHECK(0);
}


/* ---- IV lengths of whole blocks, limits, wipe -------------------------------------------------- */

/* Key 00 01 .. 0f, IV bytes 0x40 + i, additional data 0x80 + i, plaintext (7 i + 1) mod 256; expected values
 * computed with OpenSSL (the published cases have no IV of 16, 32 or 128 bytes: the cases where the GHASH of the
 * IV needs no zero padding in its last block). */
static void test_block_iv(void)
{
	static const struct {
		size_t ivl, aadl, ptl;
		const char *ct, *tag;
	} v[] = {
		{16, 0, 0, "", "9a35ea39e7e0b68e871e7bf5d69f7296"},
		{16, 13, 37, "f75a9903c361778ba4aa27468121830991e290854acc43d182b4478280755de2f6983ac8d0",
		 "08cc210e05d92eb8384c4ccafc981ebc"},
		{32, 20, 64,
		 "369779af2fdcce6b383d4c413c9e85239f06fa07cbc503ec23a93370df2048d0cc2e58f56e2498d6a661c8c1e77bae50ba6e3788741b"
		 "59f0ae04cf4c89f716da",
		 "f329eb36aebfbd7ef0b6be6739e609bb"},
		{128, 5, 17, "a3f2b2529323c98c89776cfabf56f7b4a5", "759e8cc9e48fc810a31e4cd5f8850cbb"},
	};
	size_t i, j;

	for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
		uint8_t key[16], iv[128], aad[20], pt[64], ct[64], want[64], tag[16], wtag[16], back[64];

		for (j = 0; j < 16; j++)
			key[j] = (uint8_t)j;
		for (j = 0; j < v[i].ivl; j++)
			iv[j] = (uint8_t)(0x40 + j);
		for (j = 0; j < v[i].aadl; j++)
			aad[j] = (uint8_t)(0x80 + j);
		for (j = 0; j < v[i].ptl; j++)
			pt[j] = (uint8_t)(7 * j + 1);
		WRT_CHECK_U64(hx(v[i].ct, want, sizeof(want)), v[i].ptl);
		WRT_CHECK_U64(hx(v[i].tag, wtag, 16), 16);
		WRT_CHECK_STATUS(0, ref_gcm_seal(key, 16, iv, v[i].ivl, aad, v[i].aadl, pt, v[i].ptl, ct, tag));
		WRT_CHECK_MEM(ct, want, v[i].ptl);
		WRT_CHECK_MEM(tag, wtag, 16);
		WRT_CHECK_STATUS(0, ref_gcm_open(key, 16, iv, v[i].ivl, aad, v[i].aadl, ct, v[i].ptl, tag, back));
		WRT_CHECK_MEM(back, pt, v[i].ptl);
	}
}

static void test_limits_and_wipe(void)
{
	uint8_t key[16] = {7}, iv[12] = {9}, tag[16], out[16];
	ref_gcm_key k;
	size_t i;
	const uint8_t *p = (const uint8_t *)&k;
	int zero = 1;

	WRT_CHECK_STATUS(0, ref_gcm_setkey(&k, key, 16));
	WRT_CHECK(!all_zero(p, sizeof(k))); /* the context holds the schedule and the S-boxes */
	ref_gcm_wipe(&k);
	for (i = 0; i < sizeof(k); i++)
		if (p[i] != 0)
			zero = 0;
	WRT_CHECK(zero);

	if (sizeof(size_t) >= 8) {
		/* SP 800-38D 5.2.1.1: the plaintext is at most 2^36 - 32 bytes, or the 32-bit block counter wraps and a
		 * keystream block is used twice. The limits are checked before any buffer is touched, so NULL is safe. */
		const size_t maxn = ((size_t)1 << 36) - 32;
		const size_t huge = (size_t)1 << 61;

		memset(tag, 0x77, 16);
		WRT_CHECK_STATUS(0, ref_gcm_setkey(&k, key, 16));
		WRT_CHECK_STATUS(-1, ref_gcm_encrypt(&k, iv, 12, NULL, 0, NULL, maxn + 1, NULL, tag));
		WRT_CHECK_STATUS(-1, ref_gcm_encrypt(&k, iv, 12, NULL, 0, NULL, (size_t)1 << 36, NULL, tag));
		WRT_CHECK_STATUS(-1, ref_gcm_encrypt(&k, iv, 12, NULL, huge, NULL, 0, NULL, tag));
		WRT_CHECK_STATUS(-1, ref_gcm_encrypt(&k, iv, 12, NULL, huge + 12345, NULL, 0, NULL, tag));
		WRT_CHECK_STATUS(-1, ref_gcm_encrypt(&k, iv, huge, NULL, 0, NULL, 0, NULL, tag));
		WRT_CHECK_STATUS(-1, ref_gcm_encrypt(&k, iv, (size_t)-1, NULL, 0, NULL, 0, NULL, tag));
		WRT_CHECK_STATUS(-1, ref_gcm_decrypt(&k, iv, 12, NULL, 0, NULL, maxn + 1, tag, NULL));
		WRT_CHECK_STATUS(-1, ref_gcm_decrypt(&k, iv, 12, NULL, huge, NULL, 0, tag, NULL));
		WRT_CHECK_STATUS(-1, ref_gcm_decrypt(&k, iv, huge, NULL, 0, NULL, 0, tag, NULL));
		WRT_CHECK(all_zero(tag, 16) == 0 && tag[0] == 0x77); /* the tag buffer was not written either */
		memset(out, 0x33, sizeof(out));
		WRT_CHECK_STATUS(-1, ref_gcm_open(key, 16, iv, 12, NULL, 0, out, maxn + 1, tag, out));
		WRT_CHECK(out[0] == 0x33); /* too long to zero: left alone, still refused */
		ref_gcm_wipe(&k);
	}
}

/* ---- msgr2 secure mode -------------------------------------------------------------------------- */

static void test_nonce_step(void)
{
	uint8_t n[12], want[12];

	/* rev 1: the last eight bytes are a little-endian counter, the first four never change */
	hx("1c1d1e1f2021222324252627", n, 12);
	ref_secure_nonce_step(n, 1);
	hx("1c1d1e1f2121222324252627", want, 12);
	WRT_CHECK_MEM(n, want, 12);
	hx("1c1d1e1fffffffffffffffff", n, 12);
	ref_secure_nonce_step(n, 1);
	hx("1c1d1e1f0000000000000000", want, 12);
	WRT_CHECK_MEM(n, want, 12); /* wraps to zero, no carry into the fixed field */
	hx("ffffffffffffffffffffffff", n, 12);
	ref_secure_nonce_step(n, 1);
	hx("ffffffff0000000000000000", want, 12);
	WRT_CHECK_MEM(n, want, 12);
	/* carries inside the counter, none into the fixed field */
	hx("01020304ffffffffffffff00", n, 12);
	ref_secure_nonce_step(n, 1);
	hx("010203040000000000000001", want, 12);
	WRT_CHECK_MEM(n, want, 12);
	hx("01020304fe00000000000000", n, 12);
	ref_secure_nonce_step(n, 1);
	hx("01020304ff00000000000000", want, 12);
	WRT_CHECK_MEM(n, want, 12);
	hx("01020304ff00000000000000", n, 12);
	ref_secure_nonce_step(n, 1);
	hx("010203040001000000000000", want, 12);
	WRT_CHECK_MEM(n, want, 12);
	hx("01020304ffffffff00000000", n, 12);
	ref_secure_nonce_step(n, 1);
	hx("010203040000000001000000", want, 12);
	WRT_CHECK_MEM(n, want, 12);
	hx("01020304ffffffffffffff7f", n, 12);
	ref_secure_nonce_step(n, 1);
	hx("010203040000000000000080", want, 12);
	WRT_CHECK_MEM(n, want, 12);

	/* any rev other than 0 steps the 64-bit counter */
	hx("000000000000000000000000", n, 12);
	ref_secure_nonce_step(n, 7);
	hx("000000000100000000000000", want, 12);
	WRT_CHECK_MEM(n, want, 12);

	/* rev 0: the first four bytes are a little-endian 32-bit counter, the rest never changes */
	hx("fe0000009900000000000000", n, 12);
	ref_secure_nonce_step(n, 0);
	hx("ff0000009900000000000000", want, 12);
	WRT_CHECK_MEM(n, want, 12);
	ref_secure_nonce_step(n, 0);
	hx("000100009900000000000000", want, 12);
	WRT_CHECK_MEM(n, want, 12);
	hx("ffffffff9a9b9c9d9e9fa0a1", n, 12);
	ref_secure_nonce_step(n, 0);
	hx("000000009a9b9c9d9e9fa0a1", want, 12);
	WRT_CHECK_MEM(n, want, 12);
}

typedef struct frame_walk {
	uint32_t nops;
	size_t wire;
} frame_walk;

static size_t pad16(size_t x)
{
	return (x + 15) & ~(size_t)15;
}

/* CRC-32C (Castagnoli), the raw update with seed 0 and no final inversion, as the preamble of a secure frame uses
 * (docs/spec/msgr2-secure-mode.md 2.8), written bit by bit here (the reflected polynomial 0x82f63b78). */
static uint32_t crc32c_raw(const uint8_t *p, size_t n)
{
	uint32_t c = 0;
	size_t i;
	int b;

	for (i = 0; i < n; i++) {
		c ^= p[i];
		for (b = 0; b < 8; b++)
			c = (c >> 1) ^ ((c & 1) ? 0x82f63b78u : 0);
	}
	return c;
}

/* Open every operation of one secure frame (docs/spec/msgr2-secure-mode.md 2.8) with consecutive nonces. The
 * first operation gives the preamble, from which the segment lengths and so the number and sizes of the others
 * follow. Returns 0 if every tag verified and the sizes add up to the wire length. */
static int walk_frame(const uint8_t key[16], const uint8_t first_nonce[12], const uint8_t *wire, size_t wirelen,
		      size_t *nops_out)
{
	uint8_t nonce[12], pre[80], seg[16384];
	size_t pos = 0, nops = 0, len[4] = {0, 0, 0, 0}, nseg, i, tail = 0;

	memcpy(nonce, first_nonce, 12);
	if (wirelen < 96 || ref_secure_open(key, nonce, wire, 80, pre) != 0)
		return -1;
	nops = 1;
	pos = 96;
	nseg = pre[1];
	if (nseg < 1 || nseg > 4)
		return -1;
	/* the preamble CRC covers bytes 0..27 (little endian at 28), unused segment slots, flags and the reserved
	 * byte are zero, the last segment of a frame with more than one is not empty */
	if (crc32c_raw(pre, 28) != ((uint32_t)pre[28] | (uint32_t)pre[29] << 8 | (uint32_t)pre[30] << 16 | (uint32_t)pre[31] << 24))
		return -1;
	if (pre[26] != 0 || pre[27] != 0)
		return -1;
	for (i = nseg; i < 4; i++)
		if (pre[2 + 6 * i] | pre[3 + 6 * i] | pre[4 + 6 * i] | pre[5 + 6 * i] | pre[6 + 6 * i] | pre[7 + 6 * i])
			return -1;
	for (i = 0; i < nseg; i++)
		len[i] = (size_t)pre[2 + 6 * i] | (size_t)pre[3 + 6 * i] << 8 | (size_t)pre[4 + 6 * i] << 16 |
			 (size_t)pre[5 + 6 * i] << 24;
	if (nseg > 1 && len[nseg - 1] == 0)
		return -1; /* trailing empty segments are dropped */
	/* the sender's padding is zero (the stock receiver does not check it, so only a sender that is not ours
	 * could differ; the vectors come from ours) */
	if (len[0] < 48)
		for (i = 32 + len[0]; i < 80; i++)
			if (pre[i] != 0)
				return -1;
	if (len[0] > 48) {
		size_t part = pad16(len[0]) - 48;

		if (part > sizeof(seg) || pos + part + 16 > wirelen || ref_secure_open(key, nonce, wire + pos, part, seg) != 0)
			return -1;
		for (i = len[0] - 48; i < part; i++)
			if (seg[i] != 0)
				return -1;
		pos += part + 16;
		nops++;
	}
	if (nseg > 1) {
		size_t off = 0;

		for (i = 1; i < nseg; i++)
			tail += pad16(len[i]);
		tail += 16; /* the epilogue */
		if (tail > sizeof(seg) || pos + tail + 16 > wirelen || ref_secure_open(key, nonce, wire + pos, tail, seg) != 0)
			return -1;
		for (i = 1; i < nseg; i++) {
			size_t k;

			for (k = len[i]; k < pad16(len[i]); k++)
				if (seg[off + k] != 0)
					return -1;
			off += pad16(len[i]);
		}
		if ((seg[tail - 16] & 0x0f) != 0x0e) /* late_status: complete */
			return -1;
		for (i = 1; i < 16; i++)
			if (seg[tail - 16 + i] != 0)
				return -1;
		pos += tail + 16;
		nops++;
	}
	*nops_out = nops;
	return pos == wirelen ? 0 : -1;
}

static void test_secure(void)
{
	wrt_json j;
	uint8_t key[16], nonce[12], wire[256], pt[200], ct[216], frame[256], want[16];
	uint8_t *kb = NULL;
	size_t kn = 0, i, d;

	/* ---- frame A of docs/spec/msgr2-secure-mode.md 5.2, built from the spec's plaintext ---- */
	hx("000102030405060708090a0b0c0d0e0f", key, 16);
	hx("1c1d1e1f2021222324252627", nonce, 12);
	hx("07012000000008000000000000000000000000000000000000000000a80c9872", pt, 32);
	memset(pt + 32, 0xa5, 32);
	memset(pt + 64, 0, 16);
	hx("5ee83e477793cc7cbb381480b30cc69431dabdf879b50b483d403cfd1b1ec96a"
	   "e363935876ea5233f5930611558cad49725d69ea832d072f15bad3bf4b43581f"
	   "01654a9d4a848c689172d4521fcf8108ee387f09dafe616e6a0c5adfa581ad5e",
	   wire, sizeof(wire));
	ref_secure_seal(key, nonce, pt, 80, ct);
	WRT_CHECK_MEM(ct, wire, 96);
	hx("1c1d1e1f2121222324252627", want, 12);
	WRT_CHECK_MEM(nonce, want, 12); /* stepped once */
	hx("1c1d1e1f2021222324252627", nonce, 12);
	memset(frame, 0xee, sizeof(frame));
	WRT_CHECK_STATUS(0, ref_secure_open(key, nonce, wire, 80, frame));
	WRT_CHECK_MEM(frame, pt, 80);
	WRT_CHECK(frame[80] == 0xee); /* the tag is not copied out */
	hx("1c1d1e1f2121222324252627", want, 12);
	WRT_CHECK_MEM(nonce, want, 12);

	/* ---- frame B: two operations, nonce stepped between them ---- */
	hx("11021400000008000a000000080000000000000000000000000000007669e7cf", pt, 32);
	memset(pt + 32, 0x11, 20);
	memset(pt + 52, 0, 28);
	hx("1c1d1e1f2121222324252627", nonce, 12);
	ref_secure_seal(key, nonce, pt, 80, ct);
	memset(pt, 0x22, 10);
	memset(pt + 10, 0, 6);
	pt[16] = 0x0e;
	memset(pt + 17, 0, 15);
	ref_secure_seal(key, nonce, pt, 32, ct + 96);
	hx("98283b6ff8ab6493cd1f43d679c4a3a38a8577da66639b20d42f050521ea2d40"
	   "4380360af91a14019d02906a063be428f187b4b3c0183c65656b15d047b91e7a"
	   "e9f5a5aadcdc5350ca29264420199b1b20d32c03240c290bc1cc826c68a2c43c"
	   "31004d2d0a48882efde2210977ac057a35e0d0b282f4010584c004c4ffd0a4ca"
	   "f5a419f42a8a57c28a08980d974b4183",
	   wire, sizeof(wire));
	WRT_CHECK_MEM(ct, wire, 144);
	hx("1c1d1e1f2321222324252627", want, 12);
	WRT_CHECK_MEM(nonce, want, 12);

	/* in place, both directions */
	memcpy(frame, pt, 32);
	hx("1c1d1e1f2221222324252627", nonce, 12);
	ref_secure_seal(key, nonce, frame, 32, frame);
	WRT_CHECK_MEM(frame, wire + 96, 48);
	hx("1c1d1e1f2221222324252627", nonce, 12);
	WRT_CHECK_STATUS(0, ref_secure_open(key, nonce, frame, 32, frame));
	WRT_CHECK_MEM(frame, pt, 32);

	/* ---- a tag failure steps the nonce, zeroes the output, and a replay with the old nonce still opens ---- */
	hx("1c1d1e1f2221222324252627", nonce, 12);
	memcpy(frame, wire + 96, 48);
	frame[47] ^= 1;
	memset(ct, 0xcc, 40);
	WRT_CHECK_STATUS(-1, ref_secure_open(key, nonce, frame, 32, ct));
	WRT_CHECK(all_zero(ct, 32) && ct[32] == 0xcc);
	hx("1c1d1e1f2321222324252627", want, 12);
	WRT_CHECK_MEM(nonce, want, 12);
	/* wrong nonce (the next one): refused */
	WRT_CHECK_STATUS(-1, ref_secure_open(key, nonce, wire + 96, 32, ct));

	/* ---- empty operation: just a tag ---- */
	hx("000000000000000000000000", nonce, 12);
	ref_secure_seal(key, nonce, NULL, 0, ct);
	{
		uint8_t t2[16], zero12[12] = {0};

		WRT_CHECK_STATUS(0, ref_gcm_seal(key, 16, zero12, 12, NULL, 0, NULL, 0, NULL, t2));
		WRT_CHECK_MEM(ct, t2, 16);
	}
	hx("000000000000000000000000", nonce, 12);
	WRT_CHECK_STATUS(0, ref_secure_open(key, nonce, ct, 0, NULL));

	/* ---- the nonce wrap with a real operation: counter 2^64 - 1, then 0 ---- */
	hx("010203ffffffffffffffffff", nonce, 12);
	ref_secure_seal(key, nonce, (const uint8_t *)"0123456789abcdef", 16, ct);
	hx("010203ff0000000000000000", want, 12);
	WRT_CHECK_MEM(nonce, want, 12);
	ref_secure_seal(key, nonce, (const uint8_t *)"0123456789abcdef", 16, ct + 32);
	WRT_CHECK(memcmp(ct, ct + 32, 32) != 0); /* never the same nonce twice, so never the same output */
	{
		uint8_t iv1[12], t2[16], c2[16];

		hx("010203ffffffffffffffffff", iv1, 12);
		WRT_CHECK_STATUS(0, ref_gcm_seal(key, 16, iv1, 12, NULL, 0, (const uint8_t *)"0123456789abcdef", 16, c2, t2));
		WRT_CHECK_MEM(ct, c2, 16);
		WRT_CHECK_MEM(ct + 16, t2, 16);
		hx("010203ff0000000000000000", iv1, 12);
		WRT_CHECK_STATUS(0, ref_gcm_seal(key, 16, iv1, 12, NULL, 0, (const uint8_t *)"0123456789abcdef", 16, c2, t2));
		WRT_CHECK_MEM(ct + 32, c2, 16);
		WRT_CHECK_MEM(ct + 48, t2, 16);
	}
	/* rev 0: the 32-bit field steps and wraps, the counter bytes stay */
	hx("ffffffff0000000000000007", nonce, 12);
	ref_secure_seal_rev(key, nonce, 0, (const uint8_t *)"0123456789abcdef", 16, ct);
	hx("000000000000000000000007", want, 12);
	WRT_CHECK_MEM(nonce, want, 12);
	hx("ffffffff0000000000000007", nonce, 12);
	WRT_CHECK_STATUS(0, ref_secure_open_rev(key, nonce, 0, ct, 16, frame));
	WRT_CHECK_MEM(frame, "0123456789abcdef", 16);
	WRT_CHECK_MEM(nonce, want, 12);

	/* ---- every frame of the synthetic vector file, both directions, through the multi-operation walk ---- */
	if (wrt_json_load_vec(&j, "secure/secure-frames-synthetic.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	if (wrt_json_get_hex(&j, wrt_json_root(&j), "key_hex", &kb, &kn) != 0 || kn != 16) {
		WRT_CHECK(0);
		wrt_json_free(&j);
		return;
	}
	memcpy(key, kb, 16);
	free(kb);
	for (d = 0; d < 2; d++) {
		wrt_tok arr = wrt_json_get(&j, wrt_json_root(&j), d == 0 ? "client_to_server" : "server_to_client");
		size_t nf = wrt_json_count(&j, arr);

		WRT_CHECK(nf > 0);
		for (i = 0; i < nf; i++) {
			wrt_tok f = wrt_json_at(&j, arr, i);
			uint8_t *w = NULL, *iv = NULL;
			size_t wn = 0, ivn = 0, nops = 0;
			int ok, gops;

			if (wrt_json_get_hex(&j, f, "wire_hex", &w, &wn) != 0 || wrt_json_get_hex(&j, f, "first_iv_hex", &iv, &ivn) != 0 ||
			    ivn != 12) {
				WRT_CHECK(0);
				free(w);
				free(iv);
				continue;
			}
			gops = (int)wrt_json_int(&j, wrt_json_get(&j, f, "gcm_operations"), &ok);
			WRT_CHECK(ok);
			WRT_CHECK_STATUS(0, walk_frame(key, iv, w, wn, &nops));
			WRT_CHECK_U64(nops, gops);
			free(w);
			free(iv);
		}
	}
	wrt_json_free(&j);
}


/* The nonce stepping against a counter the test keeps itself: operation i of a stream that starts at
 * (fixed, 2^64 - 8) uses fixed || le64(2^64 - 8 + i), including across the wrap; every operation of the run has
 * another nonce, hence another keystream (the same plaintext never gives the same ciphertext twice). */
static void test_nonce_run(void)
{
	uint8_t key[16], nonce[12], expect[12], seed[12], pt[16] = {0}, wire[40][32];
	size_t i, j;
	uint64_t ctr = ~(uint64_t)0 - 7;

	hx("000102030405060708090a0b0c0d0e0f", key, 16);
	memcpy(nonce, "\xaa\xbb\xcc\xdd", 4);
	for (j = 0; j < 8; j++)
		nonce[4 + j] = (uint8_t)(ctr >> (8 * j));
	memcpy(seed, nonce, 12);
	for (i = 0; i < 40; i++) {
		uint8_t out[32], ref[32], tag[16];
		ref_gcm_key k;

		memcpy(expect, "\xaa\xbb\xcc\xdd", 4);
		for (j = 0; j < 8; j++)
			expect[4 + j] = (uint8_t)((ctr + i) >> (8 * j));
		WRT_CHECK_MEM(nonce, expect, 12); /* the nonce this operation is about to use */
		ref_secure_seal(key, nonce, pt, 16, out);
		WRT_CHECK_STATUS(0, ref_gcm_setkey(&k, key, 16));
		WRT_CHECK_STATUS(0, ref_gcm_encrypt(&k, expect, 12, NULL, 0, pt, 16, ref, tag));
		WRT_CHECK_MEM(out, ref, 16);
		WRT_CHECK_MEM(out + 16, tag, 16);
		memcpy(wire[i], out, 32);
		ref_gcm_wipe(&k);
		for (j = 0; j < i; j++)
			if (memcmp(wire[j], wire[i], 32) == 0)
				WRT_CHECK(0); /* a repeated nonce would repeat the output */
	}
	/* 40 operations from 2^64 - 8: the counter is at 32 now, the fixed field is untouched */
	WRT_CHECK(memcmp(nonce, seed, 4) == 0);
	for (j = 0; j < 8; j++)
		expect[4 + j] = (uint8_t)((uint64_t)32 >> (8 * j));
	WRT_CHECK_MEM(nonce + 4, expect + 4, 8);
}

/* Every bit of one secure operation (ciphertext and tag) is refused, in place too, with the output zeroed, and the
 * receiver's nonce still steps; the same bytes with the unchanged nonce are accepted. */
static void test_secure_sweep(void)
{
	uint8_t key[16], nonce[12], start[12], pt[40], wire[56], w2[56], out[56];
	size_t bit, n = 40, i;

	hx("000102030405060708090a0b0c0d0e0f", key, 16);
	hx("a1a2a3a4b0b1b2b3b4b5b6b7", start, 12);
	for (i = 0; i < n; i++)
		pt[i] = (uint8_t)(i * 3 + 5);
	memcpy(nonce, start, 12);
	ref_secure_seal(key, nonce, pt, n, wire);
	for (bit = 0; bit < (n + 16) * 8; bit++) {
		uint8_t want[12];

		memcpy(w2, wire, n + 16);
		w2[bit / 8] ^= (uint8_t)(1u << (bit % 8));
		memcpy(nonce, start, 12);
		memset(out, 0xcc, sizeof(out));
		if (ref_secure_open(key, nonce, w2, n, out) == 0 || !all_zero(out, n) || out[n] != 0xcc)
			WRT_CHECK(0);
		memcpy(want, start, 12);
		ref_secure_nonce_step(want, 1);
		WRT_CHECK_MEM(nonce, want, 12);
		/* in place: the zero fill replaces the buffer, nothing forged is left in it */
		memcpy(nonce, start, 12);
		if (ref_secure_open(key, nonce, w2, n, w2) == 0 || !all_zero(w2, n))
			WRT_CHECK(0);
	}
	/* a tag cut short is not a tag: the same ciphertext with the tag moved by one byte is refused */
	memcpy(nonce, start, 12);
	memcpy(w2, wire, n + 16);
	memmove(w2 + n + 1, w2 + n, 15);
	w2[n] = 0;
	WRT_CHECK_STATUS(-1, ref_secure_open(key, nonce, w2, n, out));
	/* the receiver must not accept the next operation's nonce, nor the previous one's */
	memcpy(nonce, start, 12);
	ref_secure_nonce_step(nonce, 1);
	WRT_CHECK_STATUS(-1, ref_secure_open(key, nonce, wire, n, out));
	memcpy(nonce, start, 12);
	WRT_CHECK_STATUS(0, ref_secure_open(key, nonce, wire, n, out));
	WRT_CHECK_MEM(out, pt, n);
}

/* ---- main ------------------------------------------------------------------------------------ */

int main(void)
{
	test_aes();
	test_gf128();
	test_vectors();
	test_args();
	test_block_iv();
	test_limits_and_wipe();
	test_lengths();
	test_iv_lengths();
	test_nonce_step();
	test_secure();
	test_nonce_run();
	test_secure_sweep();
	return wrt_finish();
}
