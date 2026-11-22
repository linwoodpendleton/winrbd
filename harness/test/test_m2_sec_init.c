/* SPDX-License-Identifier: MIT */
/*
 * test_m2_sec_init - the per-connection secure state: wri_m2s_init and wri_m2s_wipe (core/src/msgr2/wri_m2_sec.c, design 34.3 to 34.5,
 * docs/spec/msgr2-secure-mode.md 2.6).
 *
 * What is checked:
 *   - the slices of the connection secret: with the synthetic secret 00 01 .. 3f of harness/vectors/secure/secure-frames-synthetic.json,
 *     the key is S[0..15], the transmit nonce of the client is seeded from S[28..39] and its receive nonce from S[16..27]; `crossed`
 *     swaps the two. Proved on the wire: every frame of the file, client to server and server to client, is walked in both views with
 *     the nonces the connection state hands out, opened by the independent reference GCM (harness/test/support/ref_gcm.c), re-sealed or
 *     re-opened by the core's own two directions of the state (ciphertext and tag equal the file's, tags verify), and its layout
 *     (operations, part sizes, total length, segment contents) checked against a formula written in this file;
 *     the wrong direction does not open the first frame of the other one;
 *   - secrets of 0, 1, 39, 40, 41, 64, 128, 129 and absurd sizes: below 40 and above 128 (and a NULL secret) are WR_E_M2_SECRET with the
 *     whole object zero and inactive; the bytes past 40 are never used (two secrets that differ only there give the same state);
 *   - equal nonce seeds (every position of the 12 bytes, all-zero secret, both views) are WR_E_M2_SECRET, one differing bit is fine;
 *   - the object's previous contents are ignored (filled with garbage before: same result on success, all zero on failure);
 *   - a host GCM override: both directions are keyed with S[0..15], through two distinct states inside the object, a refusal by the host
 *     (either direction) is returned as the host gave it with everything wiped (the host's wipe was called for every state it keyed or
 *     refused), wri_m2s_wipe releases both host states and leaves zeros; a table without the GCM members (or one too small) selects
 *     the portable code;
 *   - wri_m2s_wipe: all zero after a success, safe on an all-zero object, twice, and with NULL;
 *   - the state keeps nothing of the caller's secret buffer: clobbering or wiping it after init changes no byte of the object (the
 *     object equals one made from an untouched copy, host table pointer included);
 *   - both views at once: a client state and a server state (`crossed`) exchange operations in both directions, several in flight
 *     (a transmit operation open while a receive operation of the same state is open, finished in either order), against the
 *     independent ref_secure_seal / ref_secure_open stepped from the seeds of the secret: the two directions of one state never
 *     disturb each other, and the nonces of the two directions of one connection never meet (first 4096 each, several secrets).
 */
#include "wrt.h"

#include "ref_gcm.h"
#include "wri_m2_sec.h"
#include "wri_pgcm.h"

static uint64_t rng_state = 0x243f6a8885a308d3ull;

static uint32_t rnd(void)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (uint32_t)((rng_state * 0x2545f4914f6cdd1dull) >> 32);
}

static int all_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != 0u)
			return 0;
	return 1;
}

/* ---- the frame walker: a connection state against the wire bytes of the vector file ------------------ */

typedef struct side {
	wri_m2s_nonce *n;
	wri_pgcm *g;
	int enc; /* 1: this direction encrypts (the file's bytes are what it must produce), 0: it decrypts (the file's bytes must open) */
} side;

/* One operation: nonce taken from the state's stream, the wire bytes opened with the reference, then checked through the core's GCM of
 * the same direction. `pt` receives the plaintext. Returns 0 when everything agrees. */
static int do_op(side *sd, const uint8_t key[16], const uint8_t *first_iv, const uint8_t *ct, size_t len, const uint8_t tag[16], uint8_t *pt)
{
	uint8_t iv[12], buf[8192], tag2[16];
	int rc = 0;

	if (len > sizeof(buf))
		return -10;
	if (wri_m2s_nonce_take(sd->n, 0, iv) != WR_OK)
		return -1;
	if (first_iv != NULL && memcmp(iv, first_iv, 12) != 0)
		return -2;
	if (ref_gcm_open(key, 16, iv, 12, NULL, 0, ct, len, tag, pt) != 0)
		return -3;
	if (sd->enc) {
		memcpy(buf, pt, len);
		if (wri_pgcm_start(sd->g, iv, 0) != WR_OK || wri_pgcm_update(sd->g, buf, buf, len) != WR_OK ||
		    wri_pgcm_final_enc(sd->g, tag2) != WR_OK)
			return -4;
		if (memcmp(buf, ct, len) != 0 || memcmp(tag2, tag, 16) != 0)
			rc = -5;
	} else {
		memcpy(buf, ct, len);
		if (wri_pgcm_start(sd->g, iv, 1) != WR_OK || wri_pgcm_update(sd->g, buf, buf, len) != WR_OK ||
		    wri_pgcm_final_dec(sd->g, tag) != WR_OK)
			return -6;
		if (memcmp(buf, pt, len) != 0)
			rc = -7;
	}
	return rc;
}

static uint64_t pad16_i(uint64_t x)
{
	return (x + 15u) / 16u * 16u;
}

typedef struct segspec {
	uint32_t len;
	uint8_t fill;
} segspec;

/* Walk one frame of the file. Returns 0 when it is exactly what the layout of 2.8 says. */
static int walk_frame(side *sd, const uint8_t key[16], const uint8_t *first_iv, const uint8_t *w, size_t wn, unsigned tag_byte,
		      const segspec spec[4], unsigned gcm_ops, int *failed_at)
{
	uint8_t p1[80], p2[8192], p3[8192], seg0[8192];
	uint32_t len[4] = {0, 0, 0, 0};
	unsigned nseg, i, ops = 1, nops_core = 0;
	size_t off = 96, n2 = 0, n3 = 0;
	int rc;

	*failed_at = 0;
	if (wn < 96u)
		return -20;
	rc = do_op(sd, key, first_iv, w, 80, w + 80, p1);
	if (rc != 0) {
		*failed_at = 1;
		return rc;
	}
	/* the preamble: tag, nseg, 4 x (le32 length, le16 alignment), flags, reserved, crc */
	nseg = p1[1];
	if (p1[0] != tag_byte || nseg < 1u || nseg > 4u || p1[26] != 0 || p1[27] != 0)
		return -21;
	for (i = 0; i < 4u; i++)
		len[i] = (uint32_t)p1[2 + 6u * i] | ((uint32_t)p1[3 + 6u * i] << 8) | ((uint32_t)p1[4 + 6u * i] << 16) |
			 ((uint32_t)p1[5 + 6u * i] << 24);
	for (i = 0; i < 4u; i++)
		if (len[i] != spec[i].len)
			return -22;
	/* the layout, from the decrypted preamble: what is on the wire after part 1 */
	if (len[0] > 48u) {
		n2 = (size_t)(pad16_i(len[0]) - 48u);
		ops++;
	}
	if (nseg > 1u) {
		for (i = 1; i < nseg; i++)
			n3 += (size_t)pad16_i(len[i]);
		n3 += 16u;
		ops++;
	}
	if (96u + (n2 ? n2 + 16u : 0u) + (n3 ? n3 + 16u : 0u) != wn || ops != gcm_ops)
		return -23;
	if (n2 > sizeof(p2) || n3 > sizeof(p3))
		return -24;
	/* the core's own arithmetic says the same */
	if (wri_m2s_wire_len(len, nseg, &nops_core) != (uint64_t)wn || nops_core != ops)
		return -25;
	/* segment 0: the inline bytes, then part 2 */
	memcpy(seg0, p1 + 32, 48);
	if (n2 != 0) {
		rc = do_op(sd, key, NULL, w + off, n2, w + off + n2, p2);
		if (rc != 0) {
			*failed_at = 2;
			return rc;
		}
		memcpy(seg0 + 48, p2, n2);
		off += n2 + 16u;
	}
	for (i = 0; i < len[0]; i++)
		if (seg0[i] != spec[0].fill)
			return -26;
	for (i = len[0]; i < 48u + (uint32_t)n2; i++) /* the zero padding of segment 0 */
		if (seg0[i] != 0u)
			return -27;
	if (n3 != 0) {
		size_t pos = 0;
		unsigned s;

		rc = do_op(sd, key, NULL, w + off, n3, w + off + n3, p3);
		if (rc != 0) {
			*failed_at = 3;
			return rc;
		}
		off += n3 + 16u;
		for (s = 1; s < nseg; s++) {
			for (i = 0; i < len[s]; i++)
				if (p3[pos + i] != spec[s].fill)
					return -28;
			for (i = len[s]; i < (uint32_t)pad16_i(len[s]); i++)
				if (p3[pos + i] != 0u)
					return -29;
			pos += (size_t)pad16_i(len[s]);
		}
		/* the epilogue block: late status "complete", 15 zeros */
		if (p3[pos] != 0x0eu || !all_zero(p3 + pos + 1, 15))
			return -30;
	}
	return off == wn ? 0 : -31;
}

/* Walk every frame of one direction of the file with the given side. */
static void walk_direction(wrt_json *j, const char *dir, side *sd, const uint8_t key[16], size_t *frames)
{
	wrt_tok arr = wrt_json_get(j, wrt_json_root(j), dir);
	size_t nf = wrt_json_count(j, arr), i, k;

	WRT_CHECK(nf > 0u);
	for (i = 0; i < nf; i++) {
		wrt_tok f = wrt_json_at(j, arr, i), segs = wrt_json_get(j, f, "segments");
		uint8_t *w = NULL, *iv = NULL;
		size_t wn = 0, ivn = 0;
		segspec spec[4];
		int ok = 0, fa = 0, rc;
		unsigned tag, gops;

		memset(spec, 0, sizeof(spec));
		if (wrt_json_get_hex(j, f, "wire_hex", &w, &wn) != 0 || wrt_json_get_hex(j, f, "first_iv_hex", &iv, &ivn) != 0 || ivn != 12u) {
			WRT_CHECK(0);
			free(w);
			free(iv);
			continue;
		}
		tag = (unsigned)wrt_json_int(j, wrt_json_get(j, f, "tag"), &ok);
		WRT_CHECK(ok);
		gops = (unsigned)wrt_json_int(j, wrt_json_get(j, f, "gcm_operations"), &ok);
		WRT_CHECK(ok);
		for (k = 0; k < 4u && k < wrt_json_count(j, segs); k++) {
			wrt_tok sg = wrt_json_at(j, segs, k);

			spec[k].len = (uint32_t)wrt_json_int(j, wrt_json_get(j, sg, "length"), &ok);
			spec[k].fill = (uint8_t)wrt_json_int(j, wrt_json_get(j, sg, "fill_byte"), &ok);
		}
		rc = walk_frame(sd, key, iv, w, wn, tag, spec, gops, &fa);
		if (rc != 0)
			fprintf(stderr, "%s frame %zu: walk failed %d (part %d)\n", dir, i, rc, fa);
		WRT_CHECK(rc == 0);
		(*frames)++;
		free(w);
		free(iv);
	}
}

static void test_vector_file(void)
{
	wrt_json j;
	uint8_t *secret = NULL, *txs = NULL, *rxs = NULL, *key = NULL;
	size_t sn = 0, tn = 0, rn = 0, kn = 0, frames = 0;
	int crossed;
	wri_m2s s;

	if (wrt_json_load_vec(&j, "secure/secure-frames-synthetic.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	if (wrt_json_get_hex(&j, wrt_json_root(&j), "secret_hex", &secret, &sn) != 0 || sn != 64u ||
	    wrt_json_get_hex(&j, wrt_json_root(&j), "client_tx_seed_hex", &txs, &tn) != 0 || tn != 12u ||
	    wrt_json_get_hex(&j, wrt_json_root(&j), "client_rx_seed_hex", &rxs, &rn) != 0 || rn != 12u ||
	    wrt_json_get_hex(&j, wrt_json_root(&j), "key_hex", &key, &kn) != 0 || kn != 16u) {
		WRT_CHECK(0);
		wrt_json_free(&j);
		return;
	}
	/* the file's own claims about the slices, against the secret it carries (and the secret 00..3f of the design) */
	{
		size_t i;

		for (i = 0; i < 64u; i++)
			WRT_CHECK(secret[i] == (uint8_t)i);
		WRT_CHECK_MEM(key, secret, 16);
		WRT_CHECK_MEM(txs, secret + 28, 12);
		WRT_CHECK_MEM(rxs, secret + 16, 12);
	}
	for (crossed = 0; crossed < 2; crossed++) {
		side c2s, s2c;
		const uint8_t *tx_seed = crossed ? rxs : txs, *rx_seed = crossed ? txs : rxs;

		WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, NULL, secret, sn, crossed));
		WRT_CHECK(s.active == 1u);
		WRT_CHECK_MEM(s.tx_n.seed, tx_seed, 12);
		WRT_CHECK_MEM(s.tx_n.cur, tx_seed, 12);
		WRT_CHECK_MEM(s.rx_n.seed, rx_seed, 12);
		WRT_CHECK_MEM(s.rx_n.cur, rx_seed, 12);
		WRT_CHECK(s.tx_n.started == 0u && s.rx_n.started == 0u && s.tx_n.ops == 0u && s.rx_n.ops == 0u);
		WRT_CHECK(s.ops_limit == WRI_M2S_OPS_LIMIT_DEFAULT);
		WRT_CHECK(s.tx.keyed == 1u && s.rx.keyed == 1u && wri_pgcm_is_host(&s.tx) == 0 && wri_pgcm_is_host(&s.rx) == 0);
		/* the client view: it sends client_to_server with tx and reads server_to_client with rx; the server's view is the mirror */
		c2s.n = crossed ? &s.rx_n : &s.tx_n;
		c2s.g = crossed ? &s.rx : &s.tx;
		c2s.enc = crossed ? 0 : 1;
		s2c.n = crossed ? &s.tx_n : &s.rx_n;
		s2c.g = crossed ? &s.tx : &s.rx;
		s2c.enc = crossed ? 1 : 0;
		walk_direction(&j, "client_to_server", &c2s, key, &frames);
		walk_direction(&j, "server_to_client", &s2c, key, &frames);
		wri_m2s_wipe(&s);
		WRT_CHECK(all_zero(&s, sizeof(s)));
	}
	WRT_CHECK(frames >= 18u);
	/* the wrong direction does not open the first frame of the other: the client's rx stream is not the server's tx stream of the
	 * client-to-server file */
	{
		wrt_tok arr = wrt_json_get(&j, wrt_json_root(&j), "client_to_server");
		uint8_t *w = NULL, pt[80], iv[12];
		size_t wn = 0;

		WRT_CHECK(wrt_json_get_hex(&j, wrt_json_at(&j, arr, 0), "wire_hex", &w, &wn) == 0 && wn >= 96u);
		WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, NULL, secret, sn, 0));
		WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&s.rx_n, 0, iv)); /* the client's receive nonce */
		WRT_CHECK(ref_gcm_open(key, 16, iv, 12, NULL, 0, w, 80, w + 80, pt) != 0);
		WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&s.tx_n, 0, iv)); /* its transmit nonce does */
		WRT_CHECK(ref_gcm_open(key, 16, iv, 12, NULL, 0, w, 80, w + 80, pt) == 0);
		wri_m2s_wipe(&s);
		free(w);
	}
	free(secret);
	free(txs);
	free(rxs);
	free(key);
	wrt_json_free(&j);
}

/* ---- lengths, seeds, previous contents ----------------------------------------------------------------- */

static void fresh_secret(uint8_t *sec, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		sec[i] = (uint8_t)rnd();
	sec[16] ^= 0x5au; /* the two seeds certainly differ */
}

/* Encrypt one 80-byte block with the transmit direction: a functional fingerprint of key and tx nonce (ct then tag). */
static void fingerprint(wri_m2s *s, uint8_t out[96])
{
	uint8_t iv[12], pt[80];

	memset(pt, 0x3c, sizeof(pt));
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&s->tx_n, 0, iv));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&s->tx, iv, 0));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&s->tx, pt, out, 80));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_final_enc(&s->tx, out + 80));
}

static void test_lengths(void)
{
	static const size_t good[] = {40, 41, 63, 64, 65, 100, 127, 128};
	static const size_t bad[] = {0, 1, 16, 28, 39, 129, 130, 200, 4096, (size_t)0x7fffffffu, (size_t)-1};
	uint8_t sec[256], fp1[96], fp2[96];
	wri_m2s s, s2;
	size_t i;
	int crossed;

	fresh_secret(sec, sizeof(sec));
	for (crossed = 0; crossed < 2; crossed++) {
		for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
			WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, NULL, sec, good[i], crossed));
			WRT_CHECK(s.active == 1u && s.tx.keyed == 1u && s.rx.keyed == 1u);
			/* the same state whatever the length: only the first 40 bytes count */
			WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s2, NULL, sec, 40, crossed));
			WRT_CHECK_MEM(s.tx_n.seed, s2.tx_n.seed, 12);
			WRT_CHECK_MEM(s.rx_n.seed, s2.rx_n.seed, 12);
			fingerprint(&s, fp1);
			fingerprint(&s2, fp2);
			WRT_CHECK_MEM(fp1, fp2, 96);
			wri_m2s_wipe(&s);
			wri_m2s_wipe(&s2);
		}
		for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			memset(&s, 0xab, sizeof(s)); /* the previous contents are ignored, the failed object ends all zero */
			WRT_CHECK_STATUS(WR_E_M2_SECRET, wri_m2s_init(&s, NULL, sec, bad[i], crossed));
			WRT_CHECK(all_zero(&s, sizeof(s)));
		}
		memset(&s, 0xab, sizeof(s));
		WRT_CHECK_STATUS(WR_E_M2_SECRET, wri_m2s_init(&s, NULL, NULL, 64, crossed));
		WRT_CHECK(all_zero(&s, sizeof(s)));
	}
	/* the bytes after 40 are really unused: change them, nothing changes; change a byte before, the key stream does */
	{
		uint8_t sec2[64];

		memcpy(sec2, sec, 64);
		for (i = 40; i < 64u; i++)
			sec2[i] ^= 0xffu;
		WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, NULL, sec, 64, 0));
		WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s2, NULL, sec2, 64, 0));
		fingerprint(&s, fp1);
		fingerprint(&s2, fp2);
		WRT_CHECK_MEM(fp1, fp2, 96);
		wri_m2s_wipe(&s2);
		for (i = 0; i < 16u; i++) { /* each key byte matters */
			memcpy(sec2, sec, 64);
			sec2[i] ^= 0x01u;
			WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s2, NULL, sec2, 64, 0));
			WRT_CHECK(s2.tx_n.ops == 0u);
			wri_m2s_wipe(&s);
			WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, NULL, sec, 64, 0));
			fingerprint(&s, fp1);
			fingerprint(&s2, fp2);
			WRT_CHECK(memcmp(fp1, fp2, 96) != 0);
			wri_m2s_wipe(&s2);
		}
		wri_m2s_wipe(&s);
	}
}

static void test_seeds(void)
{
	uint8_t sec[64];
	wri_m2s s, ref;
	size_t i;
	int crossed;

	for (crossed = 0; crossed < 2; crossed++) {
		/* equal seeds: refused, whatever the key and the rest */
		fresh_secret(sec, sizeof(sec));
		memcpy(sec + 28, sec + 16, 12);
		memset(&s, 0xab, sizeof(s));
		WRT_CHECK_STATUS(WR_E_M2_SECRET, wri_m2s_init(&s, NULL, sec, 64, crossed));
		WRT_CHECK(all_zero(&s, sizeof(s)) && s.active == 0u);
		WRT_CHECK_STATUS(WR_E_M2_SECRET, wri_m2s_init(&s, NULL, sec, 40, crossed)); /* also at the shortest length */
		memset(sec, 0, sizeof(sec)); /* the all-zero secret */
		WRT_CHECK_STATUS(WR_E_M2_SECRET, wri_m2s_init(&s, NULL, sec, 64, crossed));
		WRT_CHECK(all_zero(&s, sizeof(s)));
		/* seeds that differ in one bit of any byte, in any direction, are fine */
		fresh_secret(sec, sizeof(sec));
		memcpy(sec + 28, sec + 16, 12);
		for (i = 0; i < 12u * 8u; i++) {
			uint8_t t[64];

			memcpy(t, sec, 64);
			t[28 + i / 8u] ^= (uint8_t)(1u << (i % 8u));
			memset(&s, 0xab, sizeof(s));
			WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, NULL, t, 64, crossed));
			WRT_CHECK(memcmp(s.tx_n.seed, s.rx_n.seed, 12) != 0);
			wri_m2s_wipe(&s);
			WRT_CHECK(all_zero(&s, sizeof(s)));
			/* the same difference in seed A instead */
			memcpy(t, sec, 64);
			t[16 + i / 8u] ^= (uint8_t)(1u << (i % 8u));
			WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, NULL, t, 64, crossed));
			wri_m2s_wipe(&s);
		}
	}
	/* the previous contents do not matter on success either: dirty object and clean object give the same state */
	fresh_secret(sec, sizeof(sec));
	memset(&s, 0xab, sizeof(s));
	WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, NULL, sec, 64, 0));
	memset(&ref, 0, sizeof(ref));
	WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&ref, NULL, sec, 64, 0));
	WRT_CHECK(s.active == 1u && ref.active == 1u);
	WRT_CHECK(memcmp(s.tx_n.seed, ref.tx_n.seed, 12) == 0 && memcmp(s.rx_n.seed, ref.rx_n.seed, 12) == 0);
	WRT_CHECK(s.ops_limit == ref.ops_limit && s.tx_n.ops == 0u && s.rx_n.ops == 0u && s.tx_n.started == 0u);
	/* crossed really swaps: client tx = server rx */
	WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&ref, NULL, sec, 64, 1));
	WRT_CHECK(memcmp(s.tx_n.seed, ref.rx_n.seed, 12) == 0 && memcmp(s.rx_n.seed, ref.tx_n.seed, 12) == 0);
	WRT_CHECK(memcmp(s.tx_n.seed, sec + 28, 12) == 0 && memcmp(s.rx_n.seed, sec + 16, 12) == 0);
	wri_m2s_wipe(&s);
	wri_m2s_wipe(&ref);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2s_init(NULL, NULL, sec, 64, 0));
}

/* ---- the host override ----------------------------------------------------------------------------- */

typedef struct spy {
	unsigned setkeys;       /* gcm_setkey calls */
	unsigned fail_at;       /* the call number (1 = first) that is refused; 0 = none */
	wr_status fail_status;
	void *keyed_states[4];  /* states handed to gcm_setkey, in call order */
	uint8_t keys[4][16];
	unsigned wipes;
	void *wiped_states[8];
} spy;

static wr_status sp_setkey(void *ctx, void *state, const uint8_t key[16])
{
	spy *sp = (spy *)ctx;
	unsigned k = sp->setkeys++;

	if (k < 4u) {
		sp->keyed_states[k] = state;
		memcpy(sp->keys[k], key, 16);
	}
	if (sp->fail_at != 0u && sp->setkeys == sp->fail_at)
		return sp->fail_status;
	memcpy(state, key, 16); /* the "host key object" */
	return WR_OK;
}

static wr_status sp_start(void *ctx, void *state, const uint8_t iv[12], int decrypt)
{
	(void)ctx;
	(void)state;
	(void)iv;
	(void)decrypt;
	return WR_OK;
}

static void sp_update(void *ctx, void *state, const uint8_t *in, uint8_t *out, size_t n)
{
	(void)ctx;
	(void)state;
	(void)in;
	(void)out;
	(void)n;
}

static void sp_final_enc(void *ctx, void *state, uint8_t tag[16])
{
	(void)ctx;
	(void)state;
	memset(tag, 0, 16);
}

static wr_status sp_final_dec(void *ctx, void *state, const uint8_t tag[16])
{
	(void)ctx;
	(void)state;
	(void)tag;
	return WR_OK;
}

static void sp_wipe(void *ctx, void *state)
{
	spy *sp = (spy *)ctx;

	if (sp->wipes < 8u)
		sp->wiped_states[sp->wipes] = state;
	sp->wipes++;
	memset(state, 0, 16);
}

static void spy_table(wr_prim_ops *t, spy *sp)
{
	memset(t, 0, sizeof(*t));
	t->size = (uint32_t)sizeof(*t);
	t->ctx = sp;
	t->gcm_state_bytes = 16u;
	t->gcm_setkey = sp_setkey;
	t->gcm_start = sp_start;
	t->gcm_update = sp_update;
	t->gcm_final_enc = sp_final_enc;
	t->gcm_final_dec = sp_final_dec;
	t->gcm_wipe = sp_wipe;
}

static int was_wiped(const spy *sp, const void *state)
{
	unsigned i;

	for (i = 0; i < sp->wipes && i < 8u; i++)
		if (sp->wiped_states[i] == state)
			return 1;
	return 0;
}

static void test_host_override(void)
{
	uint8_t sec[64];
	wr_prim_ops t;
	spy sp;
	wri_m2s s;
	unsigned k;

	fresh_secret(sec, sizeof(sec));
	/* both directions keyed through the host, two distinct states inside the object, both with S[0..15] */
	memset(&sp, 0, sizeof(sp));
	spy_table(&t, &sp);
	memset(&s, 0xab, sizeof(s));
	WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, &t, sec, 64, 0));
	WRT_CHECK(wri_pgcm_is_host(&s.tx) == 1 && wri_pgcm_is_host(&s.rx) == 1);
	WRT_CHECK_U64(sp.setkeys, 2);
	WRT_CHECK(sp.keyed_states[0] == (void *)s.tx.u.host_state && sp.keyed_states[1] == (void *)s.rx.u.host_state);
	WRT_CHECK(sp.keyed_states[0] != sp.keyed_states[1]);
	WRT_CHECK_MEM(sp.keys[0], sec, 16);
	WRT_CHECK_MEM(sp.keys[1], sec, 16);
	WRT_CHECK(sp.wipes == 0u);
	wri_m2s_wipe(&s); /* releases the host's objects and zeroes the lot */
	WRT_CHECK_U64(sp.wipes, 2);
	WRT_CHECK(was_wiped(&sp, sp.keyed_states[0]) && was_wiped(&sp, sp.keyed_states[1]));
	WRT_CHECK(all_zero(&s, sizeof(s)));
	/* a second wipe changes nothing and does not call the host again */
	wri_m2s_wipe(&s);
	WRT_CHECK_U64(sp.wipes, 2);

	/* the host refuses the key (either direction): its status comes back as it was, nothing stays keyed, the host's states are wiped */
	for (k = 1; k <= 2u; k++) {
		memset(&sp, 0, sizeof(sp));
		sp.fail_at = k;
		sp.fail_status = WR_E_CRYPTO_KEY;
		spy_table(&t, &sp);
		memset(&s, 0xab, sizeof(s));
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_m2s_init(&s, &t, sec, 64, 1));
		WRT_CHECK(all_zero(&s, sizeof(s)) && s.active == 0u);
		WRT_CHECK_U64(sp.setkeys, k); /* it stopped at the refusal, no fallback to the portable code */
		{
			unsigned i;

			for (i = 0; i < sp.setkeys; i++)
				WRT_CHECK(was_wiped(&sp, sp.keyed_states[i]));
		}
	}
	/* too-short secrets and equal seeds are refused before the host is asked for anything */
	memset(&sp, 0, sizeof(sp));
	spy_table(&t, &sp);
	WRT_CHECK_STATUS(WR_E_M2_SECRET, wri_m2s_init(&s, &t, sec, 39, 0));
	memcpy(sec + 28, sec + 16, 12);
	WRT_CHECK_STATUS(WR_E_M2_SECRET, wri_m2s_init(&s, &t, sec, 64, 0));
	WRT_CHECK_U64(sp.setkeys, 0);
	WRT_CHECK_U64(sp.wipes, 0);
	fresh_secret(sec, sizeof(sec));

	/* a table that names no GCM member (an older host: `size` ends before them) or has one missing: the portable code */
	memset(&sp, 0, sizeof(sp));
	spy_table(&t, &sp);
	t.size = (uint32_t)offsetof(wr_prim_ops, gcm_state_bytes);
	WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, &t, sec, 64, 0));
	WRT_CHECK(wri_pgcm_is_host(&s.tx) == 0 && wri_pgcm_is_host(&s.rx) == 0 && sp.setkeys == 0u);
	wri_m2s_wipe(&s);
	spy_table(&t, &sp);
	t.gcm_final_dec = NULL;
	WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, &t, sec, 64, 0));
	WRT_CHECK(wri_pgcm_is_host(&s.tx) == 0 && sp.setkeys == 0u);
	wri_m2s_wipe(&s);
	WRT_CHECK(all_zero(&s, sizeof(s)));
}

static void test_wipe(void)
{
	uint8_t sec[64];
	wri_m2s s;
	uint8_t iv[12];

	fresh_secret(sec, sizeof(sec));
	WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, NULL, sec, 64, 0));
	/* use it a little, then wipe in the middle of an operation: nothing of key, nonce or counter state is left */
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&s.tx_n, 0, iv));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&s.tx, iv, 0));
	wri_m2s_wipe(&s);
	WRT_CHECK(all_zero(&s, sizeof(s)));
	wri_m2s_wipe(&s); /* an all-zero object, twice */
	WRT_CHECK(all_zero(&s, sizeof(s)));
	wri_m2s_wipe(NULL);
	/* nothing can run on a wiped state: the GCM objects are unkeyed */
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_start(&s.tx, iv, 0));
}

/* ---- nothing of the secret is kept; two directions in flight; two views -------------------------------- */

static void test_no_retained_secret(void)
{
	uint8_t sec[64], keep[64];
	wri_m2s a, b;
	wr_prim_ops t;
	spy sp;
	size_t i;
	int crossed;

	for (crossed = 0; crossed < 2; crossed++) {
		fresh_secret(sec, sizeof(sec));
		memcpy(keep, sec, sizeof(keep));
		WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&a, NULL, sec, sizeof(sec), crossed));
		/* the caller wipes its copy right after init (34.3): scribble, then zero it */
		memset(sec, 0xee, sizeof(sec));
		WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&b, NULL, keep, sizeof(keep), crossed));
		WRT_CHECK(memcmp(&a, &b, sizeof(a)) == 0); /* no pointer into the secret, no byte that depends on its later contents */
		memset(sec, 0, sizeof(sec));
		WRT_CHECK(memcmp(&a, &b, sizeof(a)) == 0);
		wri_m2s_wipe(&a);
		wri_m2s_wipe(&b);
	}
	/* the host path: the object holds the table pointer and the host's state, never the secret's address; the host's key object is the
	 * host's own business (it got the 16 key bytes by value) */
	fresh_secret(sec, sizeof(sec));
	memcpy(keep, sec, sizeof(keep));
	memset(&sp, 0, sizeof(sp));
	spy_table(&t, &sp);
	WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&a, &t, sec, sizeof(sec), 0));
	for (i = 0; i < sizeof(sec); i++)
		sec[i] = (uint8_t)~sec[i];
	{
		const uint8_t *pa = (const uint8_t *)&a;
		uintptr_t lo = (uintptr_t)sec, hi = (uintptr_t)sec + sizeof(sec), v;

		/* no pointer-sized word of the object points into the old secret buffer */
		for (i = 0; i + sizeof(v) <= sizeof(a); i++) {
			memcpy(&v, pa + i, sizeof(v));
			WRT_CHECK(v < lo || v >= hi);
		}
	}
	WRT_CHECK_MEM(sp.keys[0], keep, 16);
	wri_m2s_wipe(&a);
}

/* One operation through a state's own direction: nonce from the state's stream (same discipline as the transmit and receive code). */
static void st_seal(wri_m2s *s, const uint8_t *pt, size_t n, uint8_t *out)
{
	uint8_t iv[12];

	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&s->tx_n, s->ops_limit, iv));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&s->tx, iv, 0));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&s->tx, pt, out, n));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_final_enc(&s->tx, out + n));
}

static void test_loopback_two_views(void)
{
	uint8_t sec[64], key[16], cnonce_tx[12], cnonce_rx[12];
	wri_m2s cl, sv;
	uint32_t round;
	unsigned k;

	for (k = 0; k < 6u; k++) {
		fresh_secret(sec, sizeof(sec));
		if (k == 0u) { /* the synthetic secret of the vector file */
			size_t i;

			for (i = 0; i < sizeof(sec); i++)
				sec[i] = (uint8_t)i;
		}
		memcpy(key, sec, 16);
		memcpy(cnonce_tx, sec + 28, 12); /* the independent model: the client's transmit and receive nonces, stepped by the reference */
		memcpy(cnonce_rx, sec + 16, 12);
		WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&cl, NULL, sec, sizeof(sec), 0));
		WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&sv, NULL, sec, sizeof(sec), 1));
		for (round = 0; round < 40u; round++) {
			uint8_t c2s_pt[160], c2s_ct[176], s2c_pt[96], s2c_ct[112], ref_ct[176], got[176], iv[12], tmp16[16] = {0};
			size_t n1 = 16u * (1u + rnd() % 10u), n2 = 16u * (1u + rnd() % 6u), i;

			for (i = 0; i < sizeof(c2s_pt); i++)
				c2s_pt[i] = (uint8_t)rnd();
			for (i = 0; i < sizeof(s2c_pt); i++)
				s2c_pt[i] = (uint8_t)rnd();
			/* the client seals (transmit direction) and the server seals (its transmit direction) */
			st_seal(&cl, c2s_pt, n1, c2s_ct);
			st_seal(&sv, s2c_pt, n2, s2c_ct);
			ref_secure_seal(key, cnonce_tx, c2s_pt, n1, ref_ct);
			WRT_CHECK_MEM(c2s_ct, ref_ct, n1 + 16u); /* the client's stream is what the reference makes from seed B */
			ref_secure_seal(key, cnonce_rx, s2c_pt, n2, ref_ct);
			WRT_CHECK_MEM(s2c_ct, ref_ct, n2 + 16u); /* and the server's from seed A */
			/* now both ends open what the other sent, with the two directions of each state in flight at once: the client has a
			 * transmit operation open (a first piece fed) while its receive operation runs, and the other way round on the server */
			if (round % 2u == 0u) {
				uint8_t tmp[16], tmpo[16], dummy_iv[12];

				memset(tmp, 0x5a, sizeof(tmp));
				memset(dummy_iv, 0x77, sizeof(dummy_iv));
				/* an open encrypt operation on cl.tx that is not a wire operation (no nonce taken from the stream): pure interference */
				WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&cl.tx, dummy_iv, 0));
				WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&cl.tx, tmp, tmpo, 16));
			}
			WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&sv.rx_n, sv.ops_limit, iv));
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&sv.rx, iv, 1));
			memcpy(got, c2s_ct, n1);
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&sv.rx, got, got, n1));
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_final_dec(&sv.rx, c2s_ct + n1));
			WRT_CHECK_MEM(got, c2s_pt, n1);
			WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&cl.rx_n, cl.ops_limit, iv));
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&cl.rx, iv, 1));
			memcpy(got, s2c_ct, n2);
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&cl.rx, got, got, n2));
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_final_dec(&cl.rx, s2c_ct + n2));
			WRT_CHECK_MEM(got, s2c_pt, n2);
			if (round % 2u == 0u) /* the open interference operation of the client's transmit side is fed once more and left open: the next start ends it */
				WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&cl.tx, tmp16, tmp16, 16));
			/* a flipped tag bit is refused by the receiving direction and does not disturb the other one */
			if (round % 8u == 7u) {
				uint8_t bad[48];

				st_seal(&cl, c2s_pt, 32, bad);
				bad[32 + (round % 16u)] ^= 0x04u;
				WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&sv.rx_n, sv.ops_limit, iv));
				WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&sv.rx, iv, 1));
				memcpy(got, bad, 32);
				WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&sv.rx, got, got, 32));
				WRT_CHECK(wri_pgcm_final_dec(&sv.rx, bad + 32) != WR_OK);
				ref_secure_nonce_step(cnonce_tx, 1);
				/* the stream goes on: the very next operation in that direction still opens (the nonce was spent, not reused) */
			}
		}
		/* the nonces of the two directions of one connection never meet, whatever the secret (the first 1024 of each) */
		{
			wri_m2s a2;
			static uint8_t xs[1024][12];
			uint8_t y[12];
			uint32_t i, j;

			WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&a2, NULL, sec, sizeof(sec), 0));
			for (i = 0; i < 1024u; i++)
				WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&a2.tx_n, a2.ops_limit, xs[i]));
			for (j = 0; j < 1024u; j++) {
				WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&a2.rx_n, a2.ops_limit, y));
				for (i = 0; i < 1024u; i++)
					WRT_CHECK(memcmp(xs[i], y, 12) != 0); /* the same nonce in both directions under one key: the bug this exists for */
			}
			wri_m2s_wipe(&a2);
		}
		wri_m2s_wipe(&cl);
		wri_m2s_wipe(&sv);
	}
}

int main(void)
{
	test_vector_file();
	test_lengths();
	test_seeds();
	test_host_override();
	test_wipe();
	test_no_retained_secret();
	test_loopback_two_views();
	return wrt_finish();
}
