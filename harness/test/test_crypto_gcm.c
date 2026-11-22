/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_gcm - the portable streaming AES-GCM of core/src/crypto/wri_gcm.c (design 35.3).
 *
 * What is checked, against the independent reference of harness/test/support/ref_gcm.c and the published vectors:
 *   - every case of harness/vectors/secure/gcm-nist.json in both directions: the 96-bit IV cases of AES-128 and AES-256 give the
 *     published ciphertext and tag (one call, byte by byte, in place) and decrypt back; the cases with another IV length are refused
 *     by start() with WR_E_CRYPTO_LEN; the 192-bit key cases are refused by setkey() with WR_E_CRYPTO_KEY;
 *   - additional data in pieces, partial blocks, zero-length updates, lengths 0 to 70 of both against the reference;
 *   - a million random split points: a 1 KiB message under random AES-128 and AES-256 keys, additional data of random length, the
 *     message and the additional data fed in random pieces (0 to 40 bytes, so partial blocks begin and end at every offset), both
 *     directions, in place and not, ciphertext and tag equal to the reference's every time (a "split point" is one piece fed);
 *   - every single bit of ciphertext, tag, IV, additional data and key changed gives WR_E_CRYPTO_MAC;
 *   - state errors: no key, no start, AAD after data, update or final after the final, a final of the other direction, an IV of the
 *     wrong length, a bad key size, NULL arguments; every refusal inside an operation ends it (a later final is refused and never
 *     produces a tag or an OK); start discards an operation that was not finished;
 *   - the length cap through the module's own counters (2^36 - 32 bytes of data, 2^61 - 1 bytes of additional data), nothing written
 *     on a refused update;
 *   - frames A and B of docs/spec/msgr2-secure-mode.md 5.2 operation by operation (nonce stepped by the test), and every frame of
 *     secure-frames-synthetic.json opened and re-sealed through the streaming interface;
 *   - wipe (the whole object is zero, nothing keyed), the object after a final (operation fields zero, next operation works).
 * The random source is a fixed-seed xorshift, so a failure reproduces.
 */
#include "wrt.h"

#include "ref_gcm.h"
#include "wri_gcm.h"

/* ---- helpers --------------------------------------------------------------------------------- */

static uint64_t rng_state = 0x452821e638d01377ull;

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

static uint8_t *xalloc(size_t n)
{
	uint8_t *p = (uint8_t *)calloc(n != 0 ? n : 1u, 1);

	if (p == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	return p;
}

static int all_byte(const uint8_t *p, size_t n, uint8_t v)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != v)
			return 0;
	return 1;
}

static int is_zero_obj(const void *p, size_t n)
{
	return all_byte((const uint8_t *)p, n, 0);
}

/* Feed n bytes in pieces of 0 .. maxstep bytes (maxstep 0: one piece). *splits counts the pieces. */
static wr_status feed_aad(wri_gcm *g, const uint8_t *p, size_t n, size_t maxstep, uint64_t *splits)
{
	size_t pos = 0;

	while (pos < n) {
		size_t step = (maxstep == 0u) ? n - pos : (size_t)(rnd() % (maxstep + 1u));
		wr_status st;

		if (step > n - pos)
			step = n - pos;
		st = wri_gcm_aad(g, p + pos, step);
		if (splits != NULL)
			(*splits)++;
		if (st != WR_OK)
			return st;
		pos += step;
	}
	return WR_OK;
}

/* in == out when inplace (the caller passes the same buffer). */
static wr_status feed_data(wri_gcm *g, const uint8_t *in, uint8_t *out, size_t n, size_t maxstep, uint64_t *splits)
{
	size_t pos = 0;

	while (pos < n) {
		size_t step = (maxstep == 0u) ? n - pos : (size_t)(rnd() % (maxstep + 1u));
		wr_status st;

		if (step > n - pos)
			step = n - pos;
		st = wri_gcm_update(g, in + pos, out + pos, step);
		if (splits != NULL)
			(*splits)++;
		if (st != WR_OK)
			return st;
		pos += step;
	}
	return WR_OK;
}

/* One whole operation through the streaming API. maxstep 0 = one call per part, 1 = byte by byte. For decrypt, tag is the tag to
 * verify and the return value is the final's; for encrypt, tag receives the tag. */
static wr_status run_op(wri_gcm *g, int dec, const uint8_t *iv, const uint8_t *aad, size_t aadn, const uint8_t *in, uint8_t *out,
			size_t n, uint8_t tag[16], size_t maxstep, uint64_t *splits)
{
	wr_status st = wri_gcm_start(g, iv, 12, dec);

	if (st != WR_OK)
		return st;
	st = feed_aad(g, aad, aadn, maxstep, splits);
	if (st != WR_OK)
		return st;
	st = feed_data(g, in, out, n, maxstep, splits);
	if (st != WR_OK)
		return st;
	return dec ? wri_gcm_final_dec(g, tag) : wri_gcm_final_enc(g, tag);
}

/* ---- the published vectors ------------------------------------------------------------------- */

static void test_nist_vectors(void)
{
	wrt_json j;
	wrt_tok cases;
	size_t nc, i, used = 0, refused_iv = 0, refused_key = 0;
	wri_gcm g;

	if (wrt_json_load_vec(&j, "secure/gcm-nist.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	cases = wrt_json_get(&j, wrt_json_root(&j), "cases");
	nc = wrt_json_count(&j, cases);
	WRT_CHECK(nc >= 20u);
	for (i = 0; i < nc; i++) {
		wrt_tok c = wrt_json_at(&j, cases, i);
		uint8_t *key = NULL, *iv = NULL, *aad = NULL, *pt = NULL, *ct = NULL, *tag = NULL;
		size_t kn = 0, ivn = 0, an = 0, pn = 0, cn = 0, tn = 0, k;
		uint8_t *buf, got[16];

		if (wrt_json_get_hex(&j, c, "key_hex", &key, &kn) != 0 || wrt_json_get_hex(&j, c, "iv_hex", &iv, &ivn) != 0 ||
		    wrt_json_get_hex(&j, c, "aad_hex", &aad, &an) != 0 || wrt_json_get_hex(&j, c, "pt_hex", &pt, &pn) != 0 ||
		    wrt_json_get_hex(&j, c, "ct_hex", &ct, &cn) != 0 || wrt_json_get_hex(&j, c, "tag_hex", &tag, &tn) != 0 ||
		    pn != cn || tn != 16u) {
			WRT_CHECK(0);
			free(key); free(iv); free(aad); free(pt); free(ct); free(tag);
			continue;
		}
		if (kn == 24u) {
			/* AES-192: nothing here needs it, refused and nothing left keyed */
			memset(&g, 0xaa, sizeof(g));
			WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_gcm_setkey(&g, key, kn));
			WRT_CHECK(is_zero_obj(&g, sizeof(g)));
			WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_start(&g, iv, 12, 0));
			refused_key++;
		} else {
			WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, kn));
			if (ivn != 12u) {
				/* 64-bit and 480-bit IVs: refused, no operation is left running */
				WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_gcm_start(&g, iv, ivn, 0));
				WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_gcm_start(&g, iv, ivn, 1));
				WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_update(&g, pt, pt, 0));
				refused_iv++;
			} else {
				used++;
				buf = xalloc(pn + 1u);
				for (k = 0; k < 3u; k++) {
					size_t maxstep = (k == 0u) ? 0u : (k == 1u) ? 1u : 7u;

					/* encrypt, out of place */
					memset(got, 0xee, 16);
					memset(buf, 0xee, pn + 1u);
					WRT_CHECK_STATUS(WR_OK, run_op(&g, 0, iv, aad, an, pt, buf, pn, got, maxstep, NULL));
					WRT_CHECK_MEM(buf, ct, pn);
					WRT_CHECK_MEM(got, tag, 16);
					WRT_CHECK(buf[pn] == 0xee);
					/* encrypt, in place */
					memcpy(buf, pt, pn);
					WRT_CHECK_STATUS(WR_OK, run_op(&g, 0, iv, aad, an, buf, buf, pn, got, maxstep, NULL));
					WRT_CHECK_MEM(buf, ct, pn);
					WRT_CHECK_MEM(got, tag, 16);
					/* decrypt, out of place */
					memset(buf, 0xee, pn + 1u);
					WRT_CHECK_STATUS(WR_OK, run_op(&g, 1, iv, aad, an, ct, buf, pn, tag, maxstep, NULL));
					WRT_CHECK_MEM(buf, pt, pn);
					WRT_CHECK(buf[pn] == 0xee);
					/* decrypt, in place */
					memcpy(buf, ct, pn);
					WRT_CHECK_STATUS(WR_OK, run_op(&g, 1, iv, aad, an, buf, buf, pn, tag, maxstep, NULL));
					WRT_CHECK_MEM(buf, pt, pn);
				}
				free(buf);
			}
		}
		wri_gcm_wipe(&g);
		free(key); free(iv); free(aad); free(pt); free(ct); free(tag);
	}
	/* 20 published cases: AES-128 with a 96-bit IV 6 and AES-256 4 (run), AES-128 and AES-256 with a 64-bit or 480-bit IV 4 (the IV
	 * is refused), AES-192 6 (the key is refused) */
	WRT_CHECK_U64(used, 10);
	WRT_CHECK_U64(refused_iv, 4);
	WRT_CHECK_U64(refused_key, 6);
	WRT_CHECK_U64(used + refused_iv + refused_key, nc);
	wrt_json_free(&j);
}

/* ---- the reference over lengths and key sizes -------------------------------------------------- */

static void test_lengths_vs_reference(void)
{
	size_t an, n, ks;
	wri_gcm g;
	uint8_t key[32], iv[12], aad[80], pt[80], ct[80], rct[80], tag[16], rtag[16], out[80];

	for (ks = 0; ks < 2u; ks++) {
		size_t klen = ks ? 32u : 16u;

		rnd_fill(key, sizeof(key));
		WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, klen));
		for (an = 0; an <= 70u; an++) {
			for (n = 0; n <= 70u; n++) {
				rnd_fill(iv, sizeof(iv));
				rnd_fill(aad, sizeof(aad));
				rnd_fill(pt, sizeof(pt));
				WRT_CHECK(ref_gcm_seal(key, klen, iv, 12, aad, an, pt, n, rct, rtag) == 0);
				memcpy(ct, pt, n);
				WRT_CHECK_STATUS(WR_OK, run_op(&g, 0, iv, aad, an, ct, ct, n, tag, (an + n) % 3u == 0u ? 5u : 0u, NULL));
				WRT_CHECK_MEM(ct, rct, n);
				WRT_CHECK_MEM(tag, rtag, 16);
				WRT_CHECK_STATUS(WR_OK, run_op(&g, 1, iv, aad, an, rct, out, n, rtag, (an + n) % 4u == 0u ? 3u : 0u, NULL));
				WRT_CHECK_MEM(out, pt, n);
			}
		}
		wri_gcm_wipe(&g);
	}
}

/* ---- a million random split points -------------------------------------------------------------- */

#define SPLIT_TARGET 1000000u
#define NPOOL 48u
#define MSG 1024u

static void test_random_splits(void)
{
	static uint8_t pt[NPOOL][MSG], ct[NPOOL][MSG], aad[NPOOL][80], key[NPOOL][32], iv[NPOOL][12], tag[NPOOL][16];
	size_t klen[NPOOL], aadn[NPOOL], i;
	uint64_t splits = 0, ops = 0;
	size_t last = NPOOL;
	wri_gcm g;
	uint8_t buf[MSG + 16], t[16];

	for (i = 0; i < NPOOL; i++) {
		klen[i] = (i & 1u) ? 32u : 16u;
		aadn[i] = (i < 6u) ? i : (size_t)(rnd() % 81u); /* 0 .. 5 first, then random */
		rnd_fill(key[i], 32);
		rnd_fill(iv[i], 12);
		rnd_fill(aad[i], 80);
		rnd_fill(pt[i], MSG);
		WRT_CHECK(ref_gcm_seal(key[i], klen[i], iv[i], 12, aad[i], aadn[i], pt[i], MSG, ct[i], tag[i]) == 0);
	}
	while (splits < SPLIT_TARGET) {
		size_t c = (last != NPOOL && (rnd() & 1u)) ? last : (size_t)(rnd() % NPOOL);
		size_t maxstep = 1u + (rnd() % 40u);
		int dec = (int)(rnd() & 1u), inplace = (int)(rnd() & 1u);
		const uint8_t *src = dec ? ct[c] : pt[c];
		const uint8_t *want = dec ? pt[c] : ct[c];
		wr_status st;

		if (c != last) { /* the key is reused for as long as the same case comes up, and set again when another one does */
			WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key[c], klen[c]));
			last = c;
		}
		memset(buf, 0xee, sizeof(buf));
		if (inplace)
			memcpy(buf, src, MSG);
		memset(t, 0xee, sizeof(t));
		if (dec) {
			memcpy(t, tag[c], 16);
			st = run_op(&g, 1, iv[c], aad[c], aadn[c], inplace ? buf : src, buf, MSG, t, maxstep, &splits);
			WRT_CHECK_STATUS(WR_OK, st);
		} else {
			st = run_op(&g, 0, iv[c], aad[c], aadn[c], inplace ? buf : src, buf, MSG, t, maxstep, &splits);
			WRT_CHECK_STATUS(WR_OK, st);
			WRT_CHECK_MEM(t, tag[c], 16);
		}
		WRT_CHECK_MEM(buf, want, MSG);
		WRT_CHECK(buf[MSG] == 0xee);
		ops++;
	}
	wri_gcm_wipe(&g);
	printf("crypto.gcm: %" PRIu64 " split points in %" PRIu64 " operations\n", splits, ops);
}

/* ---- every bit ---------------------------------------------------------------------------------- */

static void test_every_bit(void)
{
	size_t ks, b, which;

	for (ks = 0; ks < 2u; ks++) {
		const size_t klen = ks ? 32u : 16u;
		uint8_t key[32], iv[12], aad[20], pt[48], ct[48], tag[16], k2[32], iv2[12], aad2[20], ct2[48], tag2[16], out[48];
		wri_gcm g;
		const size_t sizes[5] = {klen, 12u, sizeof(aad), sizeof(ct), 16u};
		size_t flipped = 0;

		rnd_fill(key, sizeof(key));
		rnd_fill(iv, sizeof(iv));
		rnd_fill(aad, sizeof(aad));
		rnd_fill(pt, sizeof(pt));
		WRT_CHECK(ref_gcm_seal(key, klen, iv, 12, aad, sizeof(aad), pt, sizeof(pt), ct, tag) == 0);
		WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, klen));
		WRT_CHECK_STATUS(WR_OK, run_op(&g, 1, iv, aad, sizeof(aad), ct, out, sizeof(ct), tag, 0, NULL));
		for (which = 0; which < 5u; which++) {
			for (b = 0; b < sizes[which] * 8u; b++) {
				memcpy(k2, key, sizeof(k2));
				memcpy(iv2, iv, sizeof(iv2));
				memcpy(aad2, aad, sizeof(aad2));
				memcpy(ct2, ct, sizeof(ct2));
				memcpy(tag2, tag, sizeof(tag2));
				switch (which) {
				case 0: k2[b / 8u] ^= (uint8_t)(1u << (b % 8u)); break;
				case 1: iv2[b / 8u] ^= (uint8_t)(1u << (b % 8u)); break;
				case 2: aad2[b / 8u] ^= (uint8_t)(1u << (b % 8u)); break;
				case 3: ct2[b / 8u] ^= (uint8_t)(1u << (b % 8u)); break;
				default: tag2[b / 8u] ^= (uint8_t)(1u << (b % 8u)); break;
				}
				WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, k2, klen));
				WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, run_op(&g, 1, iv2, aad2, sizeof(aad2), ct2, out, sizeof(ct2), tag2,
									 (b % 3u == 0u) ? 5u : 0u, NULL));
				flipped++;
			}
		}
		WRT_CHECK_U64(flipped, (klen + 12u + sizeof(aad) + sizeof(ct) + 16u) * 8u);
		/* and the object still works with the right key afterwards */
		WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, klen));
		WRT_CHECK_STATUS(WR_OK, run_op(&g, 1, iv, aad, sizeof(aad), ct, out, sizeof(ct), tag, 0, NULL));
		WRT_CHECK_MEM(out, pt, sizeof(pt));
		wri_gcm_wipe(&g);
	}
}

/* ---- state errors ------------------------------------------------------------------------------- */

static void test_setkey_errors(void)
{
	wri_gcm g;
	uint8_t key[64], zero[sizeof(wri_gcm)];
	const size_t bad[] = {0, 1, 8, 15, 17, 23, 24, 25, 31, 33, 48, 64};
	size_t i;

	memset(key, 0x33, sizeof(key));
	memset(zero, 0, sizeof(zero));
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		memset(&g, 0xaa, sizeof(g));
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_gcm_setkey(&g, key, bad[i]));
		WRT_CHECK(memcmp(&g, zero, sizeof(g)) == 0); /* unkeyed and clean */
		WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_start(&g, key, 12, 0));
	}
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_setkey(NULL, key, 16));
	memset(&g, 0xaa, sizeof(g));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_setkey(&g, NULL, 16));
	WRT_CHECK(memcmp(&g, zero, sizeof(g)) == 0);
	memset(&g, 0xaa, sizeof(g));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_setkey(&g, NULL, 32));
	WRT_CHECK(memcmp(&g, zero, sizeof(g)) == 0);
	/* a failed second setkey drops the first key */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, 16));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_gcm_setkey(&g, key, 17));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_start(&g, key, 12, 0));
	/* NULL object everywhere */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_start(NULL, key, 12, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_aad(NULL, key, 1));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_update(NULL, key, key, 1));
	memset(key, 0xee, 16);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_final_enc(NULL, key));
	WRT_CHECK(all_byte(key, 16, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_final_dec(NULL, key));
	wri_gcm_wipe(NULL);
	wri_gcm_abort(NULL);
}

static void test_state_errors(void)
{
	wri_gcm g;
	uint8_t key[16], iv[12], tag[16], d[64], o[64], zero[16], good[16], ct[32], pt[32];
	size_t i;

	rnd_fill(key, 16);
	rnd_fill(iv, 12);
	rnd_fill(pt, 32);
	memset(zero, 0, 16);
	WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, 16));
	WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, pt, 32, ct, good) == 0);

	/* no start yet */
	memset(tag, 0xee, 16);
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_aad(&g, d, 4));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_update(&g, d, o, 4));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag));
	WRT_CHECK(all_byte(tag, 16, 0));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_dec(&g, good));

	/* the IV: only 12 bytes */
	for (i = 0; i <= 17u; i++) {
		if (i == 12u)
			continue;
		WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_gcm_start(&g, d, i, 0));
		WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_update(&g, d, o, 4)); /* nothing was started */
	}
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_gcm_start(&g, d, (size_t)1 << 20, 1));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_start(&g, NULL, 12, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_start(&g, iv, 12, 2));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_start(&g, iv, 12, -1));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_update(&g, d, o, 4));

	/* AAD after data: refused, and the operation is dead: no tag, no OK */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_aad(&g, d, 5));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, pt, o, 3));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_aad(&g, d, 1));
	memset(tag, 0xee, 16);
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_update(&g, pt, o, 3));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag));
	WRT_CHECK(all_byte(tag, 16, 0));
	/* the same for a decrypt */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 1));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, ct, o, 16));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_aad(&g, d, 1));
	WRT_CHECK(wri_gcm_final_dec(&g, good) != WR_OK);

	/* a zero-length update is not data: AAD may still follow; a zero-length AAD with a NULL pointer is fine */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, NULL, NULL, 0));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_aad(&g, NULL, 0));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_aad(&g, d, 7));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, d, o, 0));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_aad(&g, d, 7));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, pt, o, 1));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_aad(&g, d, 1));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag));

	/* NULL buffers with data: refused, operation dead */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_update(&g, NULL, o, 4));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_update(&g, d, NULL, 4));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_aad(&g, NULL, 4));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_final_enc(&g, NULL));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag)); /* the NULL tag ended it */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 1));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_final_dec(&g, NULL));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_dec(&g, good));

	/* the direction must match the final; the wrong final ends the operation */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 1));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, ct, o, 32));
	memset(tag, 0xee, 16);
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag));
	WRT_CHECK(all_byte(tag, 16, 0));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_dec(&g, good)); /* gone */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, pt, o, 32));
	WRT_CHECK(wri_gcm_final_dec(&g, good) != WR_OK);
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag)); /* gone */

	/* a wrong tag: MAC error, the operation is over, the next one is fine */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 1));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, ct, o, 32));
	good[15] ^= 1;
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, wri_gcm_final_dec(&g, good));
	good[15] ^= 1;
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_dec(&g, good));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_update(&g, ct, o, 16));
	WRT_CHECK_STATUS(WR_OK, run_op(&g, 1, iv, NULL, 0, ct, o, 32, good, 0, NULL));
	WRT_CHECK_MEM(o, pt, 32);

	/* final twice */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, pt, o, 32));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_final_enc(&g, tag));
	WRT_CHECK_MEM(o, ct, 32);
	WRT_CHECK_MEM(tag, good, 16);
	memset(tag, 0xee, 16);
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag));
	WRT_CHECK(all_byte(tag, 16, 0));

	/* start discards an unfinished operation (also one that is refused), and leaves nothing of it behind */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_aad(&g, d, 9));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, d, o, 21));
	WRT_CHECK_STATUS(WR_OK, run_op(&g, 0, iv, NULL, 0, pt, o, 32, tag, 0, NULL));
	WRT_CHECK_MEM(o, ct, 32);
	WRT_CHECK_MEM(tag, good, 16);
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, d, o, 21));
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_gcm_start(&g, iv, 13, 0)); /* refused start: the old operation is gone too */
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag));

	/* buffers that overlap without being the same range are refused (the operation ends, nothing is written); in place and
	 * back-to-back (adjacent) buffers are fine */
	{
		uint8_t buf[64], ref[64];
		static const size_t off[] = {1, 5, 15, 16, 17, 31};
		size_t k;
		int dir;

		for (dir = 0; dir < 2; dir++) {
			for (k = 0; k < sizeof(off) / sizeof(off[0]); k++) {
				memset(buf, 0x5c, sizeof(buf));
				memcpy(ref, buf, sizeof(buf));
				WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, dir));
				/* input below output, then output below input; both overlap by 32 - off bytes */
				WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_update(&g, buf, buf + off[k], 32));
				WRT_CHECK_MEM(buf, ref, 64);
				WRT_CHECK_STATUS(WR_E_STATE, dir ? wri_gcm_final_dec(&g, good) : wri_gcm_final_enc(&g, tag));
				WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, dir));
				WRT_CHECK_STATUS(WR_E_INVAL, wri_gcm_update(&g, buf + off[k], buf, 32));
				WRT_CHECK_MEM(buf, ref, 64);
				WRT_CHECK_STATUS(WR_E_STATE, dir ? wri_gcm_final_dec(&g, good) : wri_gcm_final_enc(&g, tag));
			}
			/* the same pointer is in place; the next 32 bytes are adjacent, not overlapping; one byte next to the input too */
			WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, dir));
			WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, buf, buf, 32));
			WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, buf, buf + 32, 32));
			WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, buf, buf + 1, 1));
			wri_gcm_abort(&g);
		}
	}

	/* abort keeps the key */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, d, o, 21));
	wri_gcm_abort(&g);
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag));
	WRT_CHECK_STATUS(WR_OK, run_op(&g, 0, iv, NULL, 0, pt, o, 32, tag, 0, NULL));
	WRT_CHECK_MEM(o, ct, 32);
	wri_gcm_wipe(&g);
}

/* The keystream bytes of a partial block that were used are erased at once (white box: the unused rest is what stays in `ks`). */
static void test_used_keystream_erased(void)
{
	wri_gcm g;
	uint8_t key[16], iv[12], d[32], o[32];
	int dir;

	memset(key, 3, sizeof(key));
	memset(iv, 4, sizeof(iv));
	memset(d, 0x77, sizeof(d));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, 16));
	for (dir = 0; dir < 2; dir++) {
		WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, dir));
		WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, d, o, 5)); /* the tail path */
		WRT_CHECK_U64(g.ks_left, 11);
		WRT_CHECK(all_byte(g.ks, 5, 0));
		WRT_CHECK(!all_byte(g.ks + 5, 11, 0)); /* the unused part is still there */
		WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, d, o, 3)); /* the drain path */
		WRT_CHECK_U64(g.ks_left, 8);
		WRT_CHECK(all_byte(g.ks, 8, 0));
		WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, d, o, 8));
		WRT_CHECK_U64(g.ks_left, 0);
		WRT_CHECK(all_byte(g.ks, 16, 0));
		WRT_CHECK_U64(g.part_len, 0);
		wri_gcm_abort(&g);
	}
	wri_gcm_wipe(&g);
}

static void test_wipe_and_idle_state(void)
{
	wri_gcm g;
	uint8_t key[32], iv[12], pt[40], o[40], tag[16];
	size_t i, ks;

	rnd_fill(key, 32);
	rnd_fill(iv, 12);
	rnd_fill(pt, 40);
	for (ks = 0; ks < 2u; ks++) {
		const size_t klen = ks ? 32u : 16u;

		WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, klen));
		WRT_CHECK_U64(g.state, WRI_GCM_KEYED);
		WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
		WRT_CHECK_U64(g.state, WRI_GCM_AAD);
		WRT_CHECK_STATUS(WR_OK, wri_gcm_aad(&g, pt, 5));
		WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, pt, o, 23));
		WRT_CHECK_U64(g.state, WRI_GCM_DATA);
		WRT_CHECK_U64(g.aad_len, 5);
		WRT_CHECK_U64(g.data_len, 23);
		WRT_CHECK_U64(g.part_len, 7);
		WRT_CHECK_U64(g.ks_left, 9);
		WRT_CHECK_STATUS(WR_OK, wri_gcm_final_enc(&g, tag));
		/* after a final: keyed and idle, no operation data, the key schedule still there */
		WRT_CHECK_U64(g.state, WRI_GCM_KEYED);
		WRT_CHECK(is_zero_obj(g.ctr, 16) && is_zero_obj(g.ekj0, 16) && is_zero_obj(g.part, 16) && is_zero_obj(g.ks, 16));
		WRT_CHECK(g.aad_len == 0u && g.data_len == 0u && g.part_len == 0u && g.ks_left == 0u);
		WRT_CHECK_STATUS(WR_OK, run_op(&g, 0, iv, NULL, 0, pt, o, 40, tag, 0, NULL));
		/* wipe: every byte of the object */
		wri_gcm_wipe(&g);
		for (i = 0; i < sizeof(g); i++)
			if (((const uint8_t *)&g)[i] != 0)
				break;
		WRT_CHECK_U64(i, sizeof(g));
		WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_start(&g, iv, 12, 0));
		WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_update(&g, pt, o, 16));
	}
}

/* ---- the length cap, through the module's counters ----------------------------------------------- */

static void test_length_caps(void)
{
	const uint64_t cap = ((uint64_t)1 << 36) - 32u, acap = ((uint64_t)1 << 61) - 1u;
	wri_gcm g;
	uint8_t key[16], iv[12], d[64], o[64], tag[16];

	memset(key, 7, 16);
	memset(iv, 9, 12);
	memset(d, 1, sizeof(d));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, 16));

	/* exactly up to the cap is fine, one more byte is not, and nothing is written for the refused call */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	g.data_len = cap - 32u;
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, d, o, 32));
	WRT_CHECK_U64(g.data_len, cap);
	memset(o, 0xee, sizeof(o));
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_gcm_update(&g, d, o, 1));
	WRT_CHECK(all_byte(o, sizeof(o), 0xee));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag)); /* the refusal ended the operation */

	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	g.data_len = cap - 16u;
	memset(o, 0xee, sizeof(o));
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_gcm_update(&g, d, o, 17));
	WRT_CHECK(all_byte(o, sizeof(o), 0xee));

	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 1));
	g.data_len = cap;
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, d, o, 0)); /* nothing more is not more */
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_gcm_update(&g, d, o, 1));
	WRT_CHECK(wri_gcm_final_dec(&g, tag) != WR_OK);

	/* a partial block on the cap: the last counter value is the cap's */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	g.data_len = cap - 5u;
	WRT_CHECK_STATUS(WR_OK, wri_gcm_update(&g, d, o, 5));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_final_enc(&g, tag));

	/* additional data */
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	g.aad_len = acap - 5u;
	WRT_CHECK_STATUS(WR_OK, wri_gcm_aad(&g, d, 5));
	WRT_CHECK_U64(g.aad_len, acap);
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_gcm_aad(&g, d, 1));
	WRT_CHECK_STATUS(WR_E_STATE, wri_gcm_final_enc(&g, tag));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	g.aad_len = acap - 5u;
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_gcm_aad(&g, d, 6));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_start(&g, iv, 12, 0));
	WRT_CHECK_STATUS(WR_OK, wri_gcm_aad(&g, d, 6)); /* the counters of a new operation start at zero */
	wri_gcm_wipe(&g);
}

/* ---- msgr2 secure mode frames ------------------------------------------------------------------ */

static void nonce_step(uint8_t n[12]) /* msgr2.1: little-endian 64-bit counter in bytes 4..11 */
{
	size_t i;

	for (i = 4; i < 12u; i++) {
		n[i]++;
		if (n[i] != 0u)
			break;
	}
}

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
	memcpy(buf, tmp, n);
	free(tmp);
	return n;
}

/* Seal (dec == 0: in -> out, tag out) or open (dec == 1: tag in) one operation with the nonce, in random pieces, and step the nonce. */
static wr_status frame_op(wri_gcm *g, uint8_t nonce[12], int dec, const uint8_t *in, uint8_t *out, size_t n, uint8_t tag[16])
{
	wr_status st = run_op(g, dec, nonce, NULL, 0, in, out, n, tag, (rnd() & 1u) ? 1u + rnd() % 40u : 0u, NULL);

	nonce_step(nonce);
	return st;
}

/* open: the tag is an input (copied, so a const wire buffer can be used) */
static wr_status frame_open(wri_gcm *g, uint8_t nonce[12], const uint8_t *in, uint8_t *out, size_t n, const uint8_t *tag)
{
	uint8_t t[16];

	memcpy(t, tag, 16);
	return frame_op(g, nonce, 1, in, out, n, t);
}

static void test_frames_a_b(void)
{
	wri_gcm g;
	uint8_t key[16], nonce[12], pt[96], wire[144], out[144], tag[16];

	hx("000102030405060708090a0b0c0d0e0f", key, 16);
	WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, 16));

	/* frame A: one operation of 80 bytes (preamble 32, signature 32, 16 zero bytes), wire = 80 + tag */
	hx("07012000000008000000000000000000000000000000000000000000a80c9872", pt, 32);
	memset(pt + 32, 0xa5, 32);
	memset(pt + 64, 0, 16);
	hx("5ee83e477793cc7cbb381480b30cc69431dabdf879b50b483d403cfd1b1ec96a"
	   "e363935876ea5233f5930611558cad49725d69ea832d072f15bad3bf4b43581f"
	   "01654a9d4a848c689172d4521fcf8108ee387f09dafe616e6a0c5adfa581ad5e",
	   wire, sizeof(wire));
	hx("1c1d1e1f2021222324252627", nonce, 12);
	memcpy(out, pt, 80);
	WRT_CHECK_STATUS(WR_OK, frame_op(&g, nonce, 0, out, out, 80, tag)); /* in place */
	WRT_CHECK_MEM(out, wire, 80);
	WRT_CHECK_MEM(tag, wire + 80, 16);
	hx("1c1d1e1f2121222324252627", out + 100, 12);
	WRT_CHECK_MEM(nonce, out + 100, 12);
	hx("1c1d1e1f2021222324252627", nonce, 12);
	memcpy(out, wire, 80);
	WRT_CHECK_STATUS(WR_OK, frame_open(&g, nonce, out, out, 80, wire + 80)); /* open in place */
	WRT_CHECK_MEM(out, pt, 80);
	/* a flipped bit anywhere of the 96 wire bytes is refused */
	{
		size_t b;

		for (b = 0; b < 96u * 8u; b++) {
			memcpy(out, wire, 96);
			out[b / 8u] ^= (uint8_t)(1u << (b % 8u));
			hx("1c1d1e1f2021222324252627", nonce, 12);
			WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, frame_open(&g, nonce, out, out, 80, out + 80));
		}
	}

	/* frame B: two operations (80 bytes, then 32), the nonce stepped between them */
	hx("11021400000008000a000000080000000000000000000000000000007669e7cf", pt, 32);
	memset(pt + 32, 0x11, 20);
	memset(pt + 52, 0, 28);
	{
		uint8_t op2[32];

		memset(op2, 0, 32);
		memset(op2, 0x22, 10);
		op2[16] = 0x0e;
		hx("98283b6ff8ab6493cd1f43d679c4a3a38a8577da66639b20d42f050521ea2d40"
	   "4380360af91a14019d02906a063be428f187b4b3c0183c65656b15d047b91e7a"
	   "e9f5a5aadcdc5350ca29264420199b1b20d32c03240c290bc1cc826c68a2c43c"
	   "31004d2d0a48882efde2210977ac057a35e0d0b282f4010584c004c4ffd0a4ca"
	   "f5a419f42a8a57c28a08980d974b4183",
		   wire, sizeof(wire));
		hx("1c1d1e1f2121222324252627", nonce, 12);
		memcpy(out, pt, 80);
		WRT_CHECK_STATUS(WR_OK, frame_op(&g, nonce, 0, out, out, 80, tag));
		WRT_CHECK_MEM(out, wire, 80);
		WRT_CHECK_MEM(tag, wire + 80, 16);
		memcpy(out + 96, op2, 32);
		WRT_CHECK_STATUS(WR_OK, frame_op(&g, nonce, 0, out + 96, out + 96, 32, tag));
		WRT_CHECK_MEM(out + 96, wire + 96, 32);
		WRT_CHECK_MEM(tag, wire + 128, 16);
		hx("1c1d1e1f2321222324252627", out + 128, 12);
		WRT_CHECK_MEM(nonce, out + 128, 12);
		/* open both again, with the operations' nonces */
		hx("1c1d1e1f2121222324252627", nonce, 12);
		memcpy(out, wire, 80);
		WRT_CHECK_STATUS(WR_OK, frame_open(&g, nonce, out, out, 80, wire + 80));
		WRT_CHECK_MEM(out, pt, 80);
		memcpy(out + 96, wire + 96, 32);
		WRT_CHECK_STATUS(WR_OK, frame_open(&g, nonce, out + 96, out + 96, 32, wire + 128));
		WRT_CHECK_MEM(out + 96, op2, 32);
		/* the second operation under the first one's nonce does not open: the nonce is part of the key stream and the tag */
		hx("1c1d1e1f2121222324252627", nonce, 12);
		memcpy(out + 96, wire + 96, 32);
		WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, frame_open(&g, nonce, out + 96, out + 96, 32, wire + 128));
	}
	wri_gcm_wipe(&g);
}

/* Walk every frame of the synthetic vector file (design 34.6, msgr2-secure-mode.md 2.8): open the operations with consecutive nonces,
 * the first gives the segment lengths and so the sizes of the others; then seal the plain text again and require the wire bytes. */
static size_t pad16(size_t x)
{
	return (x + 15u) & ~(size_t)15u;
}

static int walk_frame(wri_gcm *g, const uint8_t first[12], const uint8_t *wire, size_t wn, size_t *nops_out)
{
	uint8_t nonce[12], pre[80], seg[8192], plain[8192], resealed[8192];
	size_t pos = 0, len[4] = {0, 0, 0, 0}, nseg, i, tail = 0, nops = 0, opn[3], opoff[3], pn = 0, k;

	memcpy(nonce, first, 12);
	if (wn < 96u)
		return -1;
	if (frame_open(g, nonce, wire, pre, 80, wire + 80) != WR_OK)
		return -1;
	opn[0] = 80;
	opoff[0] = 0;
	nops = 1;
	pos = 96;
	memcpy(plain, pre, 80);
	pn = 80;
	nseg = pre[1];
	if (nseg < 1u || nseg > 4u)
		return -1;
	for (i = 0; i < nseg; i++)
		len[i] = (size_t)pre[2 + 6 * i] | (size_t)pre[3 + 6 * i] << 8 | (size_t)pre[4 + 6 * i] << 16 | (size_t)pre[5 + 6 * i] << 24;
	if (len[0] > 48u) {
		size_t part = pad16(len[0]) - 48u;

		if (part > sizeof(seg) || pos + part + 16u > wn ||
		    frame_open(g, nonce, wire + pos, seg, part, wire + pos + part) != WR_OK)
			return -1;
		memcpy(plain + pn, seg, part);
		opn[nops] = part;
		opoff[nops] = pos;
		pn += part;
		pos += part + 16u;
		nops++;
	}
	if (nseg > 1u) {
		for (i = 1; i < nseg; i++)
			tail += pad16(len[i]);
		tail += 16u;
		if (tail > sizeof(seg) || pos + tail + 16u > wn ||
		    frame_open(g, nonce, wire + pos, seg, tail, wire + pos + tail) != WR_OK)
			return -1;
		memcpy(plain + pn, seg, tail);
		opn[nops] = tail;
		opoff[nops] = pos;
		pn += tail;
		pos += tail + 16u;
		nops++;
	}
	if (pos != wn)
		return -1;
	/* seal again, op by op, in place, and compare with the wire */
	memcpy(nonce, first, 12);
	{
		size_t src = 0;

		for (k = 0; k < nops; k++) {
			uint8_t tg[16];

			memcpy(resealed, plain + src, opn[k]);
			if (frame_op(g, nonce, 0, resealed, resealed, opn[k], tg) != WR_OK)
				return -1;
			if (memcmp(resealed, wire + opoff[k], opn[k]) != 0 || memcmp(tg, wire + opoff[k] + opn[k], 16) != 0)
				return -1;
			src += opn[k];
		}
	}
	*nops_out = nops;
	return 0;
}

static void test_frame_file(void)
{
	wrt_json j;
	uint8_t key[16], *kb = NULL;
	size_t kn = 0, d, i, frames = 0;
	wri_gcm g;

	if (wrt_json_load_vec(&j, "secure/secure-frames-synthetic.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	if (wrt_json_get_hex(&j, wrt_json_root(&j), "key_hex", &kb, &kn) != 0 || kn != 16u) {
		WRT_CHECK(0);
		wrt_json_free(&j);
		return;
	}
	memcpy(key, kb, 16);
	free(kb);
	WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, 16));
	for (d = 0; d < 2u; d++) {
		wrt_tok arr = wrt_json_get(&j, wrt_json_root(&j), d == 0u ? "client_to_server" : "server_to_client");
		size_t nf = wrt_json_count(&j, arr);

		WRT_CHECK(nf > 0u);
		for (i = 0; i < nf; i++) {
			wrt_tok f = wrt_json_at(&j, arr, i);
			uint8_t *w = NULL, *iv = NULL;
			size_t wn = 0, ivn = 0, nops = 0;
			int ok, gops;

			if (wrt_json_get_hex(&j, f, "wire_hex", &w, &wn) != 0 || wrt_json_get_hex(&j, f, "first_iv_hex", &iv, &ivn) != 0 ||
			    ivn != 12u) {
				WRT_CHECK(0);
				free(w);
				free(iv);
				continue;
			}
			gops = (int)wrt_json_int(&j, wrt_json_get(&j, f, "gcm_operations"), &ok);
			WRT_CHECK(ok);
			WRT_CHECK(walk_frame(&g, iv, w, wn, &nops) == 0);
			WRT_CHECK_U64(nops, gops);
			frames++;
			free(w);
			free(iv);
		}
	}
	WRT_CHECK(frames >= 9u);
	wri_gcm_wipe(&g);
	wrt_json_free(&j);
}

/* ---- a long message, one call and in pieces ------------------------------------------------------ */

static void test_long_message(void)
{
	const size_t n = 300000u;
	uint8_t key[16], iv[12], aad[33], tag[16], rtag[16], *pt = xalloc(n), *ct = xalloc(n), *rct = xalloc(n);
	wri_gcm g;
	uint64_t splits = 0;

	rnd_fill(key, 16);
	rnd_fill(iv, 12);
	rnd_fill(aad, sizeof(aad));
	rnd_fill(pt, n);
	WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, aad, sizeof(aad), pt, n, rct, rtag) == 0);
	WRT_CHECK_STATUS(WR_OK, wri_gcm_setkey(&g, key, 16));
	memcpy(ct, pt, n);
	WRT_CHECK_STATUS(WR_OK, run_op(&g, 0, iv, aad, sizeof(aad), ct, ct, n, tag, 0, NULL));
	WRT_CHECK_MEM(ct, rct, n);
	WRT_CHECK_MEM(tag, rtag, 16);
	memcpy(ct, pt, n);
	WRT_CHECK_STATUS(WR_OK, run_op(&g, 0, iv, aad, sizeof(aad), ct, ct, n, tag, 4093u, &splits));
	WRT_CHECK_MEM(ct, rct, n);
	WRT_CHECK_MEM(tag, rtag, 16);
	WRT_CHECK_STATUS(WR_OK, run_op(&g, 1, iv, aad, sizeof(aad), ct, ct, n, tag, 1999u, &splits));
	WRT_CHECK_MEM(ct, pt, n);
	wri_gcm_wipe(&g);
	free(pt);
	free(ct);
	free(rct);
}

int main(void)
{
	test_nist_vectors();
	test_lengths_vs_reference();
	test_random_splits();
	test_every_bit();
	test_setkey_errors();
	test_state_errors();
	test_wipe_and_idle_state();
	test_used_keystream_erased();
	test_length_caps();
	test_frames_a_b();
	test_frame_file();
	test_long_message();
	printf("crypto.gcm: %lu checks, %lu failures\n", wrt_checks, wrt_failures);
	return wrt_finish();
}
