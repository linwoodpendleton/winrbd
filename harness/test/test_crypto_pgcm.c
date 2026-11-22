/* SPDX-License-Identifier: MIT */
/*
 * test_crypto_pgcm - the per-direction GCM dispatcher of core/src/crypto/wri_pgcm.c (design 35.4).
 *
 * The host side is a FAKE host table built on the independent reference (harness/test/support/ref_gcm.c): its state is one byte (an
 * index into the table's own slots, so gcm_state_bytes may be claimed as 1 or 256), it counts every call, and it records a
 * violation whenever the core breaks the contract of wr_host.h (an update that is not a multiple of 16 or has a NULL buffer, an
 * update or final outside an operation, a start inside one, a final of the wrong direction, a setkey into a state that is not
 * zeroed, a state pointer that is not 8-byte aligned). Every test ends with "no violations".
 *
 * What is checked:
 *   - when the override is used and when it is not: the full table is used; each of the six members NULL, a table whose size stops
 *     before the last member (or before gcm_state_bytes, as an old host's), gcm_state_bytes 0, 257, 0xffffffff, and a NULL table are
 *     not (the host's setkey is never called, wri_pgcm_is_host says 0, the portable code gives the right bytes); 1 and 256 are;
 *   - the portable path and the host path give identical bytes (ciphertext and tag) on thousands of random operations (16-byte
 *     multiples, random pieces, in place and not, both directions, rekeying), equal to the reference's, and a wrong tag is refused;
 *   - a failing host setkey is returned as given (a positive answer becomes WR_E_CRYPTO_KEY), the host's wipe runs once on its state,
 *     the object is all zero and unkeyed (start gives WR_E_STATE) and nothing falls back to the portable code;
 *   - the operation rules, identical on both paths: a length that is not a multiple of 16 is WR_E_CRYPTO_LEN, update and final need
 *     a start (WR_E_STATE, the host not called), a final of the other direction is WR_E_STATE, a NULL buffer or tag is WR_E_INVAL,
 *     and each refusal inside an operation ends it for good (the final that follows is refused, with a zeroed tag, never OK) while
 *     the host's state is closed with a real final so it is ready for the next start; start inside an operation closes the old one;
 *   - a host's final_dec answer is passed on (WR_OK, WR_E_CRYPTO_MAC), a host answer that is neither is turned into a failure;
 *   - wipe: the object is zero, the host's wipe runs once (a second wipe does not call it again), the host state is 8-byte aligned
 *     whatever the object's own alignment, no slot is left live;
 *   - frames A and B of docs/spec/msgr2-secure-mode.md 5.2 and every frame of secure-frames-synthetic.json, opened and sealed again,
 *     through the portable path and through the host path.
 */
#include "wrt.h"

#include "ref_gcm.h"
#include "wri_pgcm.h"

/* ---- helpers --------------------------------------------------------------------------------- */

static uint64_t rng_state = 0x9216d5d98979fb1bull;

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

static int all_byte(const uint8_t *p, size_t n, uint8_t v)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != v)
			return 0;
	return 1;
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

/* ---- the fake host --------------------------------------------------------------------------- */

#define FH_SLOTS 8
#define FH_MAXMSG 70000u

typedef struct fh_slot {
	int live;
	int open;
	int dec;
	uint8_t iv[12];
	ref_gcm_key key;
	uint8_t *ct; /* ciphertext of the running operation so far */
	size_t len;
} fh_slot;

typedef struct fh {
	fh_slot slot[FH_SLOTS];
	unsigned n_setkey, n_start, n_update, n_fin_enc, n_fin_dec, n_wipe;
	unsigned violations;
	int setkey_answer;    /* returned by gcm_setkey instead of success when not 0 */
	int final_dec_answer; /* returned by gcm_final_dec instead of the real answer when not 0 */
} fh;

static void fh_violation(fh *h, const char *what)
{
	h->violations++;
	fprintf(stderr, "fake host: contract violation: %s\n", what);
}

static fh_slot *fh_get(fh *h, void *state, const char *call)
{
	const uint8_t *s = (const uint8_t *)state;

	if (((uintptr_t)state & 7u) != 0u)
		fh_violation(h, "state pointer not 8-byte aligned");
	if (s[0] == 0u || s[0] > FH_SLOTS || !h->slot[s[0] - 1u].live) {
		fh_violation(h, call);
		return NULL;
	}
	return &h->slot[s[0] - 1u];
}

static unsigned fh_live(const fh *h)
{
	unsigned i, n = 0;

	for (i = 0; i < FH_SLOTS; i++)
		n += (unsigned)h->slot[i].live;
	return n;
}

static wr_status fh_setkey(void *ctx, void *state, const uint8_t key[16])
{
	fh *h = (fh *)ctx;
	uint8_t *s = (uint8_t *)state;
	unsigned i;

	h->n_setkey++;
	if (((uintptr_t)state & 7u) != 0u)
		fh_violation(h, "setkey: state pointer not 8-byte aligned");
	if (s[0] != 0u)
		fh_violation(h, "setkey into a state that is not zeroed");
	if (h->setkey_answer != 0)
		return (wr_status)h->setkey_answer;
	for (i = 0; i < FH_SLOTS; i++) {
		if (!h->slot[i].live) {
			fh_slot *sl = &h->slot[i];

			memset(sl, 0, sizeof(*sl));
			if (ref_gcm_setkey(&sl->key, key, 16) != 0)
				return WR_E_CRYPTO_KEY;
			sl->ct = (uint8_t *)calloc(FH_MAXMSG, 1);
			if (sl->ct == NULL)
				exit(2);
			sl->live = 1;
			s[0] = (uint8_t)(i + 1u);
			return WR_OK;
		}
	}
	return WR_E_BUSY;
}

static wr_status fh_start(void *ctx, void *state, const uint8_t iv[12], int decrypt)
{
	fh *h = (fh *)ctx;
	fh_slot *sl;

	h->n_start++;
	sl = fh_get(h, state, "start without a key");
	if (sl == NULL)
		return WR_E_STATE;
	if (sl->open)
		fh_violation(h, "start inside a running operation");
	if (decrypt != 0 && decrypt != 1)
		fh_violation(h, "start: decrypt is not 0 or 1");
	if (iv == NULL)
		fh_violation(h, "start: NULL iv");
	memcpy(sl->iv, iv, 12);
	sl->dec = decrypt;
	sl->open = 1;
	sl->len = 0;
	return WR_OK;
}

/* Counter mode written out with the reference's block cipher: block b of the message uses the counter value b + 2 behind the IV. */
static void fh_update(void *ctx, void *state, const uint8_t *in, uint8_t *out, size_t n)
{
	fh *h = (fh *)ctx;
	fh_slot *sl;
	size_t i;

	h->n_update++;
	sl = fh_get(h, state, "update without a key");
	if (sl == NULL)
		return;
	if (!sl->open) {
		fh_violation(h, "update outside an operation");
		return;
	}
	if (n == 0u || (n & 15u) != 0u) {
		fh_violation(h, "update length is zero or not a multiple of 16");
		return;
	}
	if (in == NULL || out == NULL) {
		fh_violation(h, "update with a NULL buffer");
		return;
	}
	if (sl->len + n > FH_MAXMSG) {
		fh_violation(h, "message too long for the fake");
		return;
	}
	for (i = 0; i < n; i += 16u) {
		uint8_t cb[16], ks[16];
		uint32_t ctr = (uint32_t)((sl->len + i) / 16u) + 2u;
		size_t k;

		memcpy(cb, sl->iv, 12);
		cb[12] = (uint8_t)(ctr >> 24);
		cb[13] = (uint8_t)(ctr >> 16);
		cb[14] = (uint8_t)(ctr >> 8);
		cb[15] = (uint8_t)ctr;
		ref_aes_encrypt_block(&sl->key.aes, cb, ks);
		for (k = 0; k < 16u; k++) {
			uint8_t c = in[i + k];
			uint8_t o = (uint8_t)(c ^ ks[k]);

			out[i + k] = o;
			sl->ct[sl->len + i + k] = sl->dec ? c : o;
		}
	}
	sl->len += n;
}

/* tag = GHASH(ct) xor E(K, IV || 1) */
static void fh_tag(fh_slot *sl, uint8_t tag[16])
{
	uint8_t j0[16], e[16], g[16];
	size_t i;

	memcpy(j0, sl->iv, 12);
	j0[12] = 0;
	j0[13] = 0;
	j0[14] = 0;
	j0[15] = 1;
	ref_aes_encrypt_block(&sl->key.aes, j0, e);
	ref_ghash(sl->key.h, NULL, 0, sl->ct, sl->len, g);
	for (i = 0; i < 16u; i++)
		tag[i] = (uint8_t)(g[i] ^ e[i]);
}

static void fh_final_enc(void *ctx, void *state, uint8_t tag[16])
{
	fh *h = (fh *)ctx;
	fh_slot *sl;

	h->n_fin_enc++;
	sl = fh_get(h, state, "final_enc without a key");
	if (sl == NULL)
		return;
	if (!sl->open)
		fh_violation(h, "final_enc outside an operation");
	else if (sl->dec)
		fh_violation(h, "final_enc of a decrypt operation");
	fh_tag(sl, tag);
	sl->open = 0;
}

static wr_status fh_final_dec(void *ctx, void *state, const uint8_t tag[16])
{
	fh *h = (fh *)ctx;
	fh_slot *sl;
	uint8_t want[16];
	wr_status st;

	h->n_fin_dec++;
	sl = fh_get(h, state, "final_dec without a key");
	if (sl == NULL)
		return WR_E_STATE;
	if (!sl->open)
		fh_violation(h, "final_dec outside an operation");
	else if (!sl->dec)
		fh_violation(h, "final_dec of an encrypt operation");
	fh_tag(sl, want);
	st = (memcmp(want, tag, 16) == 0) ? WR_OK : WR_E_CRYPTO_MAC;
	sl->open = 0;
	return h->final_dec_answer != 0 ? (wr_status)h->final_dec_answer : st;
}

static void fh_wipe(void *ctx, void *state)
{
	fh *h = (fh *)ctx;
	uint8_t *s = (uint8_t *)state;

	h->n_wipe++;
	if (s[0] != 0u && s[0] <= FH_SLOTS && h->slot[s[0] - 1u].live) {
		fh_slot *sl = &h->slot[s[0] - 1u];

		free(sl->ct);
		memset(sl, 0, sizeof(*sl));
	}
	s[0] = 0;
}

static void fh_init(fh *h)
{
	memset(h, 0, sizeof(*h));
}

/* A full table over the fake. */
static void tab_full(wr_prim_ops *t, fh *h)
{
	memset(t, 0, sizeof(*t));
	t->size = (uint32_t)sizeof(*t);
	t->ctx = h;
	t->gcm_state_bytes = 256u;
	t->gcm_setkey = fh_setkey;
	t->gcm_start = fh_start;
	t->gcm_update = fh_update;
	t->gcm_final_enc = fh_final_enc;
	t->gcm_final_dec = fh_final_dec;
	t->gcm_wipe = fh_wipe;
}

/* ---- running operations through the dispatcher ----------------------------------------------- */

/* One operation in pieces of 16-byte multiples (maxblocks 0: one piece), in place when out == in. */
static wr_status pg_op(wri_pgcm *g, int dec, const uint8_t iv[12], const uint8_t *in, uint8_t *out, size_t n, uint8_t tag[16],
		       size_t maxblocks)
{
	size_t pos = 0;
	wr_status st = wri_pgcm_start(g, iv, dec);

	if (st != WR_OK)
		return st;
	while (pos < n) {
		size_t step = (maxblocks == 0u) ? n - pos : 16u * (1u + (size_t)(rnd() % maxblocks));

		if (step > n - pos)
			step = n - pos;
		st = wri_pgcm_update(g, in + pos, out + pos, step);
		if (st != WR_OK)
			return st;
		pos += step;
	}
	return dec ? wri_pgcm_final_dec(g, tag) : wri_pgcm_final_enc(g, tag);
}

/* ---- which path is taken --------------------------------------------------------------------- */

static void check_path(const wr_prim_ops *tab, fh *h, int want_host, const char *what)
{
	wri_pgcm g;
	uint8_t key[16], iv[12], pt[48], ct[48], rct[48], tag[16], rtag[16];

	rnd_fill(key, 16);
	rnd_fill(iv, 12);
	rnd_fill(pt, 48);
	memset(&g, 0, sizeof(g));
	WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, pt, 48, rct, rtag) == 0);
	h->n_setkey = h->n_start = h->n_update = h->n_fin_enc = h->n_fin_dec = h->n_wipe = 0;
	if (wri_pgcm_setkey(&g, tab, key) != WR_OK) {
		fprintf(stderr, "check_path(%s): setkey failed\n", what);
		WRT_CHECK(0);
		return;
	}
	if ((wri_pgcm_is_host(&g) != 0) != (want_host != 0)) {
		fprintf(stderr, "check_path(%s): is_host = %d, want %d\n", what, wri_pgcm_is_host(&g), want_host);
		WRT_CHECK(0);
	}
	WRT_CHECK(want_host ? h->n_setkey == 1u : h->n_setkey == 0u);
	WRT_CHECK_STATUS(WR_OK, pg_op(&g, 0, iv, pt, ct, 48, tag, 2));
	WRT_CHECK_MEM(ct, rct, 48);
	WRT_CHECK_MEM(tag, rtag, 16);
	WRT_CHECK_STATUS(WR_OK, pg_op(&g, 1, iv, ct, ct, 48, rtag, 0));
	WRT_CHECK_MEM(ct, pt, 48);
	if (want_host) {
		WRT_CHECK(h->n_start == 2u && h->n_fin_enc == 1u && h->n_fin_dec == 1u && h->n_update >= 2u);
	} else {
		WRT_CHECK(h->n_start == 0u && h->n_update == 0u && h->n_fin_enc == 0u && h->n_fin_dec == 0u);
	}
	wri_pgcm_wipe(&g);
	WRT_CHECK(want_host ? h->n_wipe == 1u : h->n_wipe == 0u);
	WRT_CHECK_U64(fh_live(h), 0);
}

static void test_decision(void)
{
	fh h;
	wr_prim_ops t;
	size_t m;
	/* the six members by their offset in the table (a mutable view of the struct) */
	void **members[6];

	fh_init(&h);
	tab_full(&t, &h);
	check_path(&t, &h, 1, "full table");
	check_path(NULL, &h, 0, "NULL table");

	/* the table is only a host's; the old table has no GCM members at all */
	tab_full(&t, &h);
	t.size = (uint32_t)offsetof(wr_prim_ops, gcm_state_bytes);
	check_path(&t, &h, 0, "size ends before gcm_state_bytes (a part A host)");
	tab_full(&t, &h);
	t.size = 0;
	check_path(&t, &h, 0, "size 0");
	tab_full(&t, &h);
	t.size = (uint32_t)offsetof(wr_prim_ops, gcm_wipe); /* five members covered, the sixth is beyond the size */
	check_path(&t, &h, 0, "size stops before gcm_wipe");
	tab_full(&t, &h);
	t.size = (uint32_t)(offsetof(wr_prim_ops, gcm_wipe) + sizeof(t.gcm_wipe) - 1u);
	check_path(&t, &h, 0, "size one byte short of gcm_wipe");
	tab_full(&t, &h);
	t.size = (uint32_t)(offsetof(wr_prim_ops, gcm_wipe) + sizeof(t.gcm_wipe));
	check_path(&t, &h, 1, "size exactly covers gcm_wipe");
	tab_full(&t, &h);
	t.size = (uint32_t)sizeof(t) + 64u;
	check_path(&t, &h, 1, "size larger than the core's table (a newer host)");

	/* each member missing */
	for (m = 0; m < 6u; m++) {
		tab_full(&t, &h);
		members[0] = (void **)(void *)&t.gcm_setkey;
		members[1] = (void **)(void *)&t.gcm_start;
		members[2] = (void **)(void *)&t.gcm_update;
		members[3] = (void **)(void *)&t.gcm_final_enc;
		members[4] = (void **)(void *)&t.gcm_final_dec;
		members[5] = (void **)(void *)&t.gcm_wipe;
		*members[m] = NULL;
		check_path(&t, &h, 0, "one member NULL");
	}

	/* the state size */
	{
		static const uint32_t bad[] = {0u, 257u, 258u, 1024u, 0x80000000u, 0xffffffffu};
		static const uint32_t good[] = {1u, 8u, 255u, 256u};
		size_t i;

		for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			tab_full(&t, &h);
			t.gcm_state_bytes = bad[i];
			check_path(&t, &h, 0, "gcm_state_bytes out of range");
		}
		for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
			tab_full(&t, &h);
			t.gcm_state_bytes = good[i];
			check_path(&t, &h, 1, "gcm_state_bytes in range");
		}
	}
	/* the other members of the table are irrelevant (CRC and AES overrides stay out of it) */
	tab_full(&t, &h);
	t.crc32c = NULL;
	check_path(&t, &h, 1, "other members NULL");
	WRT_CHECK_U64(h.violations, 0);
}

/* ---- identical bytes on both paths ---------------------------------------------------------------- */

static void test_equivalence(void)
{
	fh h;
	wr_prim_ops t;
	size_t i;
	wri_pgcm gp, gh;
	uint8_t key[16], iv[12], buf_p[4096], buf_h[4096], src[4096], rct[4096], tag_p[16], tag_h[16], rtag[16];

	fh_init(&h);
	tab_full(&t, &h);
	memset(&gp, 0, sizeof(gp));
	memset(&gh, 0, sizeof(gh));
	for (i = 0; i < 1500u; i++) {
		size_t n = 16u * (size_t)(rnd() % 129u); /* 0 .. 2048 */
		int dec = (int)(rnd() & 1u), inplace = (int)(rnd() & 1u);
		size_t maxblocks = (rnd() % 3u == 0u) ? 0u : 1u + rnd() % 9u;

		if (i % 25u == 0u) {
			rnd_fill(key, 16);
			wri_pgcm_wipe(&gp);
			wri_pgcm_wipe(&gh);
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(&gp, NULL, key));
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(&gh, &t, key));
			WRT_CHECK(!wri_pgcm_is_host(&gp) && wri_pgcm_is_host(&gh));
		}
		rnd_fill(iv, 12);
		rnd_fill(src, n);
		/* encrypt side: plain text from src; decrypt side: the reference's ciphertext (so the tag is right), sometimes a bad one */
		if (dec) {
			uint8_t pt[4096];

			rnd_fill(pt, n);
			WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, pt, n, src, rtag) == 0);
			memcpy(rct, pt, n);
		} else {
			WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, src, n, rct, rtag) == 0);
		}
		memset(buf_p, 0xee, sizeof(buf_p));
		memset(buf_h, 0xee, sizeof(buf_h));
		if (inplace) {
			memcpy(buf_p, src, n);
			memcpy(buf_h, src, n);
		}
		memcpy(tag_p, rtag, 16);
		memcpy(tag_h, rtag, 16);
		WRT_CHECK_STATUS(WR_OK, pg_op(&gp, dec, iv, inplace ? buf_p : src, buf_p, n, tag_p, maxblocks));
		WRT_CHECK_STATUS(WR_OK, pg_op(&gh, dec, iv, inplace ? buf_h : src, buf_h, n, tag_h, maxblocks));
		WRT_CHECK_MEM(buf_p, rct, n);
		WRT_CHECK_MEM(buf_h, rct, n);
		WRT_CHECK_MEM(buf_p, buf_h, sizeof(buf_p)); /* also the bytes behind the message are untouched, alike */
		WRT_CHECK_MEM(tag_p, tag_h, 16);
		WRT_CHECK_MEM(tag_p, rtag, 16);
		/* a wrong tag, both paths refuse (and the plaintext they wrote is the caller's to drop) */
		if (dec && (i & 1u)) {
			tag_p[rnd() % 16u] ^= (uint8_t)(1u << (rnd() % 8u));
			memcpy(tag_h, tag_p, 16);
			memcpy(buf_p, src, n);
			memcpy(buf_h, src, n);
			WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, pg_op(&gp, 1, iv, buf_p, buf_p, n, tag_p, maxblocks));
			WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, pg_op(&gh, 1, iv, buf_h, buf_h, n, tag_h, maxblocks));
		}
	}
	wri_pgcm_wipe(&gp);
	wri_pgcm_wipe(&gh);
	WRT_CHECK_U64(fh_live(&h), 0);
	WRT_CHECK_U64(h.violations, 0);
}

/* ---- keys that are refused -------------------------------------------------------------------- */

static void test_setkey_failure(void)
{
	fh h;
	wr_prim_ops t;
	wri_pgcm g;
	uint8_t key[16], iv[12], tag[16], d[32], zero[sizeof(wri_pgcm)];
	size_t i;
	static const int answers[] = {WR_E_CRYPTO_KEY, WR_E_BUSY, WR_E_UNSUPPORTED, 5, 1};

	rnd_fill(key, 16);
	rnd_fill(iv, 12);
	memset(zero, 0, sizeof(zero));
	for (i = 0; i < sizeof(answers) / sizeof(answers[0]); i++) {
		fh_init(&h);
		tab_full(&t, &h);
		h.setkey_answer = answers[i];
		memset(&g, 0, sizeof(g));
		if (answers[i] < 0)
			WRT_CHECK_STATUS(answers[i], wri_pgcm_setkey(&g, &t, key));
		else
			WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_pgcm_setkey(&g, &t, key)); /* a positive answer is never success-like */
		WRT_CHECK_U64(h.n_setkey, 1);
		WRT_CHECK_U64(h.n_wipe, 1); /* the host is told to release whatever the refused call left */
		WRT_CHECK(memcmp(&g, zero, sizeof(g)) == 0);
		WRT_CHECK(wri_pgcm_is_host(&g) == 0);
		WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_start(&g, iv, 0));
		WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_update(&g, d, d, 16));
		memset(tag, 0xee, 16);
		WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_enc(&g, tag));
		WRT_CHECK(all_byte(tag, 16, 0));
		WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_dec(&g, tag));
		WRT_CHECK_U64(h.n_start + h.n_update + h.n_fin_enc + h.n_fin_dec, 0); /* nothing fell back to the host, or from it */
		wri_pgcm_wipe(&g);
		WRT_CHECK_U64(h.n_wipe, 1); /* an unkeyed object has nothing to wipe at the host */
		WRT_CHECK_U64(h.violations, 0);
	}
	/* a key that is NULL, an object that is NULL */
	fh_init(&h);
	tab_full(&t, &h);
	memset(&g, 0xaa, sizeof(g));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_setkey(&g, &t, NULL));
	WRT_CHECK(memcmp(&g, zero, sizeof(g)) == 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_setkey(NULL, &t, key));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_setkey(&g, NULL, NULL));
	WRT_CHECK_U64(h.n_setkey, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_start(NULL, iv, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_update(NULL, d, d, 16));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_final_enc(NULL, tag));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_final_dec(NULL, tag));
	WRT_CHECK(wri_pgcm_is_host(NULL) == 0);
	wri_pgcm_wipe(NULL);
}

/* ---- the operation rules, on both paths ------------------------------------------------------------ */

static void test_rules_on(const wr_prim_ops *tab, fh *h, const char *name)
{
	wri_pgcm g;
	uint8_t key[16], iv[12], pt[64], ct[64], rct[64], tag[16], rtag[16], o[64];
	const size_t badlen[] = {1, 15, 17, 31, 33, 47};
	size_t i;
	const int host = tab != NULL;
	unsigned before;

	fprintf(stderr, "rules: %s\n", name);
	rnd_fill(key, 16);
	rnd_fill(iv, 12);
	rnd_fill(pt, 64);
	memset(&g, 0, sizeof(g));
	WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, pt, 64, rct, rtag) == 0);
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(&g, tab, key));
	WRT_CHECK((wri_pgcm_is_host(&g) != 0) == host);

	/* nothing started: update and final are refused and the host is not called */
	before = h->n_update + h->n_fin_enc + h->n_fin_dec;
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_update(&g, pt, o, 16));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_update(&g, pt, o, 5)); /* the state first, the length is not looked at */
	memset(tag, 0xee, 16);
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_enc(&g, tag));
	WRT_CHECK(all_byte(tag, 16, 0));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_dec(&g, rtag));
	WRT_CHECK_U64(h->n_update + h->n_fin_enc + h->n_fin_dec, before);

	/* start: NULL iv, bad direction */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_start(&g, NULL, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_start(&g, iv, 2));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_start(&g, iv, -1));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_update(&g, pt, o, 16));

	/* every length that is not a multiple of 16 is refused, after other data too; the operation is dead */
	for (i = 0; i < sizeof(badlen) / sizeof(badlen[0]); i++) {
		int dec = (int)(i & 1u);

		WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, dec));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, pt, o, 16));
		memset(o + 16, 0xee, 32);
		WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_pgcm_update(&g, pt, o + 16, badlen[i]));
		WRT_CHECK(all_byte(o + 16, 32, 0xee));
		WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_update(&g, pt, o, 16)); /* dead */
		memset(tag, 0xee, 16);
		if (dec) {
			WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_dec(&g, rtag));
		} else {
			WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_enc(&g, tag));
			WRT_CHECK(all_byte(tag, 16, 0));
		}
		/* and the object is usable again: the same key, the next operation */
		memcpy(ct, pt, 64);
		WRT_CHECK_STATUS(WR_OK, pg_op(&g, 0, iv, ct, ct, 64, tag, 0));
		WRT_CHECK_MEM(ct, rct, 64);
		WRT_CHECK_MEM(tag, rtag, 16);
		if (host)
			WRT_CHECK_U64(h->violations, 0);
	}
	/* a refused first update */
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 0));
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_pgcm_update(&g, pt, o, 3));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_enc(&g, tag));

	/* a zero-length update is accepted and changes nothing (the host is not called for it) */
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 0));
	before = h->n_update;
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, NULL, NULL, 0));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, pt, o, 0));
	WRT_CHECK_U64(h->n_update, before);
	memcpy(ct, pt, 64);
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, ct, ct, 64));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_final_enc(&g, tag));
	WRT_CHECK_MEM(ct, rct, 64);
	WRT_CHECK_MEM(tag, rtag, 16);

	/* NULL buffers with data, a NULL tag */
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_update(&g, NULL, o, 16));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_enc(&g, tag));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 1));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_update(&g, pt, NULL, 16));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_dec(&g, rtag));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 0));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, pt, o, 16));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_final_enc(&g, NULL));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_enc(&g, tag)); /* the NULL tag ended it */
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 1));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_final_dec(&g, NULL));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_dec(&g, rtag));

	/* a final of the other direction ends the operation and gives no tag and no OK */
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 1));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, rct, o, 64));
	memset(tag, 0xee, 16);
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_enc(&g, tag));
	WRT_CHECK(all_byte(tag, 16, 0));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_dec(&g, rtag));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 0));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, pt, o, 64));
	WRT_CHECK(wri_pgcm_final_dec(&g, rtag) == WR_E_STATE);
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_enc(&g, tag));

	/* buffers that overlap without being the same range: refused before the host is called, nothing written, the operation is dead */
	for (i = 0; i < 2u; i++) {
		uint8_t buf[64], ref[64];

		memset(buf, 0x5c, sizeof(buf));
		memcpy(ref, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, (int)i));
		before = h->n_update;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_update(&g, buf, buf + 16, 32));
		WRT_CHECK_MEM(buf, ref, 64);
		WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_update(&g, buf, buf, 16));
		WRT_CHECK_STATUS(WR_E_STATE, i ? wri_pgcm_final_dec(&g, rtag) : wri_pgcm_final_enc(&g, tag));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, (int)i));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_update(&g, buf + 16, buf, 32));
		WRT_CHECK_STATUS(WR_E_STATE, i ? wri_pgcm_final_dec(&g, rtag) : wri_pgcm_final_enc(&g, tag));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, (int)i));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_update(&g, buf, buf + 1, 16));
		WRT_CHECK_STATUS(WR_E_STATE, i ? wri_pgcm_final_dec(&g, rtag) : wri_pgcm_final_enc(&g, tag));
		WRT_CHECK_U64(h->n_update, before);
		/* in place and back to back are fine */
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, (int)i));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, buf, buf, 16));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, buf, buf + 16, 16));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, buf + 32, buf + 16 + 32, 16));
		if (i)
			WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, wri_pgcm_final_dec(&g, rtag)); /* other bytes than rct: the tag does not match */
		else
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_final_enc(&g, tag));
	}

	/* the 2^36 - 32 byte cap of one operation (2^32 - 2 blocks) is the dispatcher's own rule, so a host never sees a longer one:
	 * the block counter is set through the object (the test is white box, like the gcm test's length cap) */
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 0));
	g.blocks = 0xfffffffeu - 2u;
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, pt, o, 32)); /* exactly up to the cap */
	WRT_CHECK_U64(g.blocks, 0xfffffffeu);
	before = h->n_update;
	memset(o, 0xee, 16);
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_pgcm_update(&g, pt, o, 16)); /* one block more */
	WRT_CHECK(all_byte(o, 16, 0xee));
	WRT_CHECK_U64(h->n_update, before); /* the host was not called */
	memset(tag, 0xee, 16);
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_enc(&g, tag)); /* the refusal ended it */
	WRT_CHECK(all_byte(tag, 16, 0));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 1));
	g.blocks = 0xfffffffeu - 1u;
	WRT_CHECK_STATUS(WR_E_CRYPTO_LEN, wri_pgcm_update(&g, pt, o, 32)); /* two blocks over from one block under */
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_dec(&g, rtag));
	WRT_CHECK_STATUS(WR_OK, pg_op(&g, 0, iv, pt, o, 64, tag, 0)); /* a new operation counts from zero again */
	WRT_CHECK_MEM(o, rct, 64);
	if (host)
		WRT_CHECK_U64(h->violations, 0);

	/* a final ends the operation: nothing more is accepted */
	WRT_CHECK_STATUS(WR_OK, pg_op(&g, 0, iv, pt, o, 64, tag, 0));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_update(&g, pt, o, 16));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_enc(&g, tag));

	/* start inside an operation closes the old one */
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 1));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, pt, o, 32));
	WRT_CHECK_STATUS(WR_OK, pg_op(&g, 0, iv, pt, o, 64, tag, 0));
	WRT_CHECK_MEM(o, rct, 64);
	WRT_CHECK_MEM(tag, rtag, 16);
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 0));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, pt, o, 32));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgcm_start(&g, NULL, 0)); /* a refused start also closes it */
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_enc(&g, tag));

	/* a wrong tag: MAC error, over; the right one then works */
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(&g, iv, 1));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(&g, rct, o, 64));
	rtag[0] ^= 1;
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, wri_pgcm_final_dec(&g, rtag));
	rtag[0] ^= 1;
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_final_dec(&g, rtag));
	WRT_CHECK_STATUS(WR_OK, pg_op(&g, 1, iv, rct, o, 64, rtag, 3));
	WRT_CHECK_MEM(o, pt, 64);

	if (host) {
		/* the host's state is never left in an operation: every start has had its final */
		unsigned i2, open = 0;

		for (i2 = 0; i2 < FH_SLOTS; i2++)
			open += (unsigned)(h->slot[i2].live && h->slot[i2].open);
		WRT_CHECK_U64(open, 0);
		WRT_CHECK_U64(h->n_start, h->n_fin_enc + h->n_fin_dec);
		WRT_CHECK_U64(h->violations, 0);
	}
	wri_pgcm_wipe(&g);
	WRT_CHECK_U64(fh_live(h), 0);
}

static void test_rules(void)
{
	fh h;
	wr_prim_ops t;

	fh_init(&h);
	tab_full(&t, &h);
	test_rules_on(NULL, &h, "portable");
	WRT_CHECK_U64(h.n_setkey + h.n_start + h.n_update + h.n_fin_enc + h.n_fin_dec, 0);
	test_rules_on(&t, &h, "host");
}

/* a host's final_dec answer */
static void test_final_dec_answers(void)
{
	fh h;
	wr_prim_ops t;
	wri_pgcm g;
	uint8_t key[16], iv[12], ct[16], tag[16], o[16];
	size_t i;
	static const struct { int answer; int want; } cases[] = {
		{0, WR_OK}, {WR_E_CRYPTO_MAC, WR_E_CRYPTO_MAC}, {WR_E_STATE, WR_E_STATE}, {3, WR_E_CRYPTO_MAC}, {1000, WR_E_CRYPTO_MAC}};

	rnd_fill(key, 16);
	rnd_fill(iv, 12);
	rnd_fill(ct, 16);
	fh_init(&h);
	tab_full(&t, &h);
	memset(&g, 0, sizeof(g));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(&g, &t, key));
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		uint8_t pt[16];

		/* the right tag for ct, so the fake's own answer is success; the override replaces it */
		memset(pt, 0, 16);
		WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, pt, 16, ct, tag) == 0);
		h.final_dec_answer = cases[i].answer;
		WRT_CHECK_STATUS(cases[i].want, pg_op(&g, 1, iv, ct, o, 16, tag, 0));
		if (cases[i].answer != 0)
			WRT_CHECK(cases[i].want != WR_OK);
	}
	/* the host's own verdict is final: its MAC answer for a tag the reference accepts is passed on as it is */
	h.final_dec_answer = WR_E_CRYPTO_MAC;
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, pg_op(&g, 1, iv, ct, o, 16, tag, 0));
	wri_pgcm_wipe(&g);
	WRT_CHECK_U64(h.violations, 0);
}

/* ---- wipe and alignment ---------------------------------------------------------------------------- */

static void test_wipe_and_alignment(void)
{
	fh h;
	wr_prim_ops t;
	uint8_t key[16], iv[12], d[32], tag[16], zero[sizeof(wri_pgcm)];
	uint8_t raw[sizeof(wri_pgcm) + 32];
	size_t off;
	wri_pgcm *g;

	rnd_fill(key, 16);
	rnd_fill(iv, 12);
	memset(d, 1, sizeof(d));
	memset(zero, 0, sizeof(zero));
	fh_init(&h);
	tab_full(&t, &h);

	/* the host state is 8-byte aligned whatever the alignment (8, 16, ...) of the object */
	WRT_CHECK(offsetof(wri_pgcm, u) % 8u == 0u);
	for (off = 0; off < 32u; off += 8u) {
		uintptr_t base = ((uintptr_t)raw + 7u) & ~(uintptr_t)7u;

		g = (wri_pgcm *)(void *)(base + off);
		memset(g, 0, sizeof(*g));
		WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(g, &t, key));
		WRT_CHECK_STATUS(WR_OK, pg_op(g, 0, iv, d, d, 32, tag, 0));
		WRT_CHECK(((uintptr_t)(void *)g->u.host_state & 7u) == 0u);
		wri_pgcm_wipe(g);
	}
	WRT_CHECK_U64(h.violations, 0);

	/* the host path: wipe runs the host's wipe once, then the whole object is zero; a second wipe does not call it again */
	memset(&h, 0, sizeof(h));
	tab_full(&t, &h);
	g = (wri_pgcm *)(void *)raw;
	memset(g, 0, sizeof(*g));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(g, &t, key));
	WRT_CHECK(wri_pgcm_is_host(g));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_start(g, iv, 0));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_update(g, d, d, 16));
	wri_pgcm_wipe(g); /* in the middle of an operation */
	WRT_CHECK_U64(h.n_wipe, 1);
	WRT_CHECK(memcmp(g, zero, sizeof(*g)) == 0);
	WRT_CHECK(wri_pgcm_is_host(g) == 0);
	wri_pgcm_wipe(g);
	WRT_CHECK_U64(h.n_wipe, 1);
	WRT_CHECK_U64(fh_live(&h), 0);
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_start(g, iv, 0));
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_update(g, d, d, 16));

	/* the portable path: the whole object, key schedule included, is zero */
	memset(g, 0, sizeof(*g));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(g, NULL, key));
	WRT_CHECK_STATUS(WR_OK, pg_op(g, 0, iv, d, d, 32, tag, 0));
	WRT_CHECK(memcmp(g, zero, sizeof(*g)) != 0);
	wri_pgcm_wipe(g);
	WRT_CHECK(memcmp(g, zero, sizeof(*g)) == 0);
	WRT_CHECK_STATUS(WR_E_STATE, wri_pgcm_start(g, iv, 0));

	/* keying again after a wipe, host then portable then host: no state leaks across (the objects are re-zeroed by setkey) */
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(g, &t, key));
	WRT_CHECK(wri_pgcm_is_host(g));
	wri_pgcm_wipe(g);
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(g, NULL, key));
	WRT_CHECK(!wri_pgcm_is_host(g));
	wri_pgcm_wipe(g);
	WRT_CHECK_U64(fh_live(&h), 0);
	WRT_CHECK_U64(h.violations, 0);
}

/* ---- frames, through both paths --------------------------------------------------------------------- */

static void nonce_step(uint8_t n[12])
{
	size_t i;

	for (i = 4; i < 12u; i++) {
		n[i]++;
		if (n[i] != 0u)
			break;
	}
}

static size_t pad16(size_t x)
{
	return (x + 15u) & ~(size_t)15u;
}

/* One secure-mode operation through the dispatcher, then step the nonce. */
static wr_status op_pg(wri_pgcm *g, uint8_t nonce[12], int dec, const uint8_t *in, uint8_t *out, size_t n, const uint8_t *tag_in,
		       uint8_t *tag_out)
{
	uint8_t t[16];
	wr_status st;

	if (dec)
		memcpy(t, tag_in, 16);
	st = pg_op(g, dec, nonce, in, out, n, dec ? t : tag_out, (rnd() & 1u) ? 1u + rnd() % 5u : 0u);
	nonce_step(nonce);
	return st;
}

static int walk_frame(wri_pgcm *g, const uint8_t first[12], const uint8_t *wire, size_t wn, size_t *nops_out)
{
	uint8_t nonce[12], pre[80], seg[8192], plain[8192], resealed[8192];
	size_t pos = 96, len[4] = {0, 0, 0, 0}, nseg, i, tail = 0, nops = 1, opn[3], opoff[3], pn = 80, k, src = 0;

	memcpy(nonce, first, 12);
	if (wn < 96u || op_pg(g, nonce, 1, wire, pre, 80, wire + 80, NULL) != WR_OK)
		return -1;
	opn[0] = 80;
	opoff[0] = 0;
	memcpy(plain, pre, 80);
	nseg = pre[1];
	if (nseg < 1u || nseg > 4u)
		return -1;
	for (i = 0; i < nseg; i++)
		len[i] = (size_t)pre[2 + 6 * i] | (size_t)pre[3 + 6 * i] << 8 | (size_t)pre[4 + 6 * i] << 16 | (size_t)pre[5 + 6 * i] << 24;
	if (len[0] > 48u) {
		size_t part = pad16(len[0]) - 48u;

		if (part > sizeof(seg) || pos + part + 16u > wn ||
		    op_pg(g, nonce, 1, wire + pos, seg, part, wire + pos + part, NULL) != WR_OK)
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
		    op_pg(g, nonce, 1, wire + pos, seg, tail, wire + pos + tail, NULL) != WR_OK)
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
	memcpy(nonce, first, 12);
	for (k = 0; k < nops; k++) {
		uint8_t tg[16];

		memcpy(resealed, plain + src, opn[k]);
		if (op_pg(g, nonce, 0, resealed, resealed, opn[k], NULL, tg) != WR_OK)
			return -1;
		if (memcmp(resealed, wire + opoff[k], opn[k]) != 0 || memcmp(tg, wire + opoff[k] + opn[k], 16) != 0)
			return -1;
		src += opn[k];
	}
	*nops_out = nops;
	return 0;
}

static void frames_on(const wr_prim_ops *tab, fh *h, const char *name)
{
	wrt_json j;
	wri_pgcm g;
	uint8_t key[16], nonce[12], pt[96], wire[144], out[144], tag[16], *kb = NULL;
	size_t kn = 0, d, i, frames = 0;

	fprintf(stderr, "frames: %s\n", name);
	hx("000102030405060708090a0b0c0d0e0f", key, 16);
	memset(&g, 0, sizeof(g));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(&g, tab, key));
	WRT_CHECK((wri_pgcm_is_host(&g) != 0) == (tab != NULL));

	/* frame A */
	hx("07012000000008000000000000000000000000000000000000000000a80c9872", pt, 32);
	memset(pt + 32, 0xa5, 32);
	memset(pt + 64, 0, 16);
	hx("5ee83e477793cc7cbb381480b30cc69431dabdf879b50b483d403cfd1b1ec96ae363935876ea5233f5930611558cad49725d69ea832d072f1"
	   "5bad3bf4b43581f01654a9d4a848c689172d4521fcf8108ee387f09dafe616e6a0c5adfa581ad5e",
	   wire, sizeof(wire));
	hx("1c1d1e1f2021222324252627", nonce, 12);
	memcpy(out, pt, 80);
	WRT_CHECK_STATUS(WR_OK, op_pg(&g, nonce, 0, out, out, 80, NULL, tag));
	WRT_CHECK_MEM(out, wire, 80);
	WRT_CHECK_MEM(tag, wire + 80, 16);
	hx("1c1d1e1f2021222324252627", nonce, 12);
	memcpy(out, wire, 80);
	WRT_CHECK_STATUS(WR_OK, op_pg(&g, nonce, 1, out, out, 80, wire + 80, NULL));
	WRT_CHECK_MEM(out, pt, 80);

	/* frame B */
	{
		uint8_t op1[80], op2[32];

		hx("11021400000008000a000000080000000000000000000000000000007669e7cf", op1, 32);
		memset(op1 + 32, 0x11, 20);
		memset(op1 + 52, 0, 28);
		memset(op2, 0, 32);
		memset(op2, 0x22, 10);
		op2[16] = 0x0e;
		hx("98283b6ff8ab6493cd1f43d679c4a3a38a8577da66639b20d42f050521ea2d404380360af91a14019d02906a063be428f187b4b3c0183c65656b15d047b9"
		   "1e7ae9f5a5aadcdc5350ca29264420199b1b20d32c03240c290bc1cc826c68a2c43c31004d2d0a48882efde2210977ac057a35e0d0b282f4010584c004c4ffd0"
		   "a4caf5a419f42a8a57c28a08980d974b4183",
		   wire, sizeof(wire));
		hx("1c1d1e1f2121222324252627", nonce, 12);
		memcpy(out, op1, 80);
		WRT_CHECK_STATUS(WR_OK, op_pg(&g, nonce, 0, out, out, 80, NULL, tag));
		WRT_CHECK_MEM(out, wire, 80);
		WRT_CHECK_MEM(tag, wire + 80, 16);
		memcpy(out + 96, op2, 32);
		WRT_CHECK_STATUS(WR_OK, op_pg(&g, nonce, 0, out + 96, out + 96, 32, NULL, tag));
		WRT_CHECK_MEM(out + 96, wire + 96, 32);
		WRT_CHECK_MEM(tag, wire + 128, 16);
		hx("1c1d1e1f2121222324252627", nonce, 12);
		memcpy(out, wire, 80);
		WRT_CHECK_STATUS(WR_OK, op_pg(&g, nonce, 1, out, out, 80, wire + 80, NULL));
		WRT_CHECK_MEM(out, op1, 80);
		memcpy(out + 96, wire + 96, 32);
		WRT_CHECK_STATUS(WR_OK, op_pg(&g, nonce, 1, out + 96, out + 96, 32, wire + 128, NULL));
		WRT_CHECK_MEM(out + 96, op2, 32);
	}

	/* every frame of the vector file */
	if (wrt_json_load_vec(&j, "secure/secure-frames-synthetic.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	if (wrt_json_get_hex(&j, wrt_json_root(&j), "key_hex", &kb, &kn) != 0 || kn != 16u || memcmp(kb, key, 16) != 0) {
		WRT_CHECK(0);
		free(kb);
		wrt_json_free(&j);
		return;
	}
	free(kb);
	for (d = 0; d < 2u; d++) {
		wrt_tok arr = wrt_json_get(&j, wrt_json_root(&j), d == 0u ? "client_to_server" : "server_to_client");
		size_t nf = wrt_json_count(&j, arr);

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
	wrt_json_free(&j);
	wri_pgcm_wipe(&g);
	WRT_CHECK_U64(fh_live(h), 0);
	WRT_CHECK_U64(h->violations, 0);
}

static void test_frames(void)
{
	fh h;
	wr_prim_ops t;

	fh_init(&h);
	tab_full(&t, &h);
	frames_on(NULL, &h, "portable");
	frames_on(&t, &h, "host");
	WRT_CHECK(h.n_start > 20u);
}

int main(void)
{
	test_decision();
	test_equivalence();
	test_setkey_failure();
	test_rules();
	test_final_dec_answers();
	test_wipe_and_alignment();
	test_frames();
	printf("crypto.pgcm: %lu checks, %lu failures\n", wrt_checks, wrt_failures);
	return wrt_finish();
}
