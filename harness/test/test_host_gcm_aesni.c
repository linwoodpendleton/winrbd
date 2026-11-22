/* SPDX-License-Identifier: MIT */
/*
 * test_host_gcm_aesni - the AES-NI / PCLMULQDQ hook of harness/host/wrl_gcm_aesni.c (design 35.4, module host-gcm-aesni).
 *
 * The implementation file is included here (not linked) so that the test can (a) replace the CPUID reader to see what the hook
 * does on a CPU that lacks a feature and (b) look into the state for the few white-box checks (the counter near the 2^32 wrap, what
 * a final erases). Everything else goes through the six public members of the table, and through the core's dispatcher wri_pgcm.
 *
 * What is checked (the CPU-gating part runs on every x86-64 machine, the rest is skipped, with a reason, when the CPU has no
 * AES, PCLMULQDQ or SSE4.1):
 *   - gating: each of the four CPUID bits (PCLMULQDQ, SSSE3, SSE4.1, AES) missing, a CPU without leaf 1, a NULL table: -1 and the
 *     table untouched; wrl_gcm_aesni_available agrees;
 *   - the table: size, state bytes in 1 .. 256 and a multiple of 8, six members set, every other member NULL, deterministic;
 *   - NIST: every case of secure/gcm-nist.json the contract can express (AES-128, 96-bit IV, no additional data, whole blocks;
 *     the others are listed as out of contract), both directions, in pieces of one, two and random blocks, in place, through the
 *     table directly and through wri_pgcm;
 *   - differential: lengths 16 .. 64 KiB (every multiple of 16 up to 1 KiB, then random up to 64 KiB, the 64 KiB edge), random
 *     splits into multiples of 16, in place and out of place, unaligned buffers, state at both 8-byte alignments, key reuse over
 *     several operations and rekeying, both directions, against the core's portable GCM (through wri_pgcm without a table) and, for
 *     lengths up to 2 KiB, against the independent ref_gcm; flipped tag and ciphertext bits are refused by both;
 *   - the contract and its fail-closed side: a length that is not a multiple of 16, NULL buffers, partially overlapping buffers,
 *     an operation past 2^36 - 32 bytes, an update outside an operation: poison the operation (all-zero tag, WR_E_CRYPTO_MAC) and
 *     write nothing; a later operation on the same state is still right; a start inside an operation drops it; a final of the
 *     wrong direction; start without a key; the counter near the wrap of 2^32 blocks gives the stock keystream with no carry
 *     into the IV; a final erases the operation but keeps the key;
 *   - wipe: the state is all zero afterwards, no byte outside it (guards before and after) is touched by anything above;
 *   - the loopback: msgr2-shaped frames (80, 16 k, 16 k + 16 byte operations, nonce stepped as the spec says) sealed by the
 *     hook and opened by the portable code, and the other way round, bytes identical to ref_secure_seal_rev.
 */
#include "wrt.h"

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <cpuid.h>
#define T_X86 1
static unsigned t_ecx_mask = 0xffffffffu;
static int t_cpuid_missing;

static int t_cpuid1(unsigned *ecx)
{
	unsigned a = 0, b = 0, c = 0, d = 0;

	if (t_cpuid_missing || !__get_cpuid(1, &a, &b, &c, &d))
		return 0;
	*ecx = c & t_ecx_mask;
	return 1;
}
#define WRL_GCM_AESNI_CPUID1 t_cpuid1
#endif

#include "../host/wrl_gcm_aesni.c"

#include "ref_gcm.h"
#include "wri_pgcm.h"

/* ---- helpers --------------------------------------------------------------------------------- */

static uint64_t rng_state = 0x5be0cd19137e2179ull;

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

static void *xalloc(size_t n)
{
	void *p = malloc(n == 0u ? 1u : n);

	if (p == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	return p;
}

static wr_prim_ops ops;

/* A host state with guard bytes on both sides: the hook may touch gcm_state_bytes bytes and nothing else. off is 0 or 8 (the state is
 * 8-byte aligned always, 16-byte aligned or not). */
#define GUARD 64u
#define GBYTE 0xa5u

typedef struct hstate {
	uint8_t *raw;
	uint8_t *st;
	size_t sz;
	size_t total;
} hstate;

static void hs_init(hstate *h, size_t off)
{
	h->sz = ops.gcm_state_bytes;
	h->total = 2u * GUARD + 16u + h->sz;
	h->raw = (uint8_t *)xalloc(h->total);
	memset(h->raw, (int)GBYTE, h->total);
	h->st = h->raw + GUARD + off;
	memset(h->st, 0, h->sz); /* the core hands over zeroed (or wiped) memory */
}

static int hs_guards_ok(const hstate *h)
{
	size_t lo = (size_t)(h->st - h->raw);

	return all_byte(h->raw, lo, (uint8_t)GBYTE) && all_byte(h->st + h->sz, h->total - lo - h->sz, (uint8_t)GBYTE);
}

static void hs_free(hstate *h)
{
	free(h->raw);
	h->raw = NULL;
}

/* How an operation's data is cut into updates: 0 one piece, 1 one block at a time, 2 random multiples of 16 (also big ones). */
static size_t pick_piece(size_t left, int split)
{
	size_t step;

	if (split == 0)
		return left;
	if (split == 1)
		return left < 16u ? left : 16u;
	switch (rnd() % 4u) {
	case 0:
		step = 16u * (1u + rnd() % 4u);
		break;
	case 1:
		step = 16u * (1u + rnd() % 64u);
		break;
	case 2:
		step = 16u * (1u + rnd() % 600u);
		break;
	default:
		step = left;
		break;
	}
	return step > left ? left : step;
}

/* One whole operation on the hook. For decrypt, tag is the tag to verify and the result is the final's; for encrypt tag is output. */
static wr_status hk_run(void *st, int dec, const uint8_t iv[12], const uint8_t *in, uint8_t *out, size_t n, int split, uint8_t tag[16])
{
	wr_status s = ops.gcm_start(NULL, st, iv, dec);
	size_t pos = 0;

	if (s != WR_OK)
		return s;
	while (pos < n) {
		size_t step = pick_piece(n - pos, split);

		ops.gcm_update(NULL, st, in + pos, out + pos, step);
		pos += step;
	}
	if (dec)
		return ops.gcm_final_dec(NULL, st, tag);
	ops.gcm_final_enc(NULL, st, tag);
	return WR_OK;
}

/* The same on the core's dispatcher. */
static wr_status pg_run(wri_pgcm *g, int dec, const uint8_t iv[12], const uint8_t *in, uint8_t *out, size_t n, int split, uint8_t tag[16])
{
	wr_status s = wri_pgcm_start(g, iv, dec);
	size_t pos = 0;

	if (s != WR_OK)
		return s;
	while (pos < n) {
		size_t step = pick_piece(n - pos, split);

		s = wri_pgcm_update(g, in + pos, out + pos, step);
		if (s != WR_OK)
			return s;
		pos += step;
	}
	if (dec)
		return wri_pgcm_final_dec(g, tag);
	return wri_pgcm_final_enc(g, tag);
}

/* ---- the CPU gate ---------------------------------------------------------------------------- */

#ifdef T_X86
static void test_gating(void)
{
	static const unsigned bits[4] = {1u, 9u, 19u, 25u}; /* PCLMULQDQ, SSSE3, SSE4.1, AES */
	wr_prim_ops o;
	size_t i;
	int real;

	t_ecx_mask = 0xffffffffu;
	t_cpuid_missing = 0;
	real = wrl_gcm_aesni_available();
	for (i = 0; i < 4u; i++) {
		t_ecx_mask = ~(1u << bits[i]);
		memset(&o, 0x5a, sizeof(o));
		WRT_CHECK(wrl_gcm_aesni_ops(&o) == -1);
		WRT_CHECK(all_byte((const uint8_t *)&o, sizeof(o), 0x5au)); /* untouched */
		WRT_CHECK(wrl_gcm_aesni_available() == 0);
	}
	t_ecx_mask = 0u;
	memset(&o, 0x5a, sizeof(o));
	WRT_CHECK(wrl_gcm_aesni_ops(&o) == -1);
	WRT_CHECK(all_byte((const uint8_t *)&o, sizeof(o), 0x5au));
	t_ecx_mask = 0xffffffffu;
	t_cpuid_missing = 1; /* CPUID leaf 1 not there */
	memset(&o, 0x5a, sizeof(o));
	WRT_CHECK(wrl_gcm_aesni_ops(&o) == -1);
	WRT_CHECK(all_byte((const uint8_t *)&o, sizeof(o), 0x5au));
	WRT_CHECK(wrl_gcm_aesni_available() == 0);
	t_cpuid_missing = 0;
	WRT_CHECK(wrl_gcm_aesni_ops(NULL) == -1);
	WRT_CHECK(wrl_gcm_aesni_available() == real); /* the real answer is back */
	if (real) {
		memset(&o, 0x5a, sizeof(o));
		WRT_CHECK(wrl_gcm_aesni_ops(&o) == 0);
	}
}
#endif

/* ---- the table ------------------------------------------------------------------------------- */

static void test_table(void)
{
	wr_prim_ops o, p;

	memset(&o, 0x77, sizeof(o));
	WRT_CHECK(wrl_gcm_aesni_ops(&o) == 0);
	WRT_CHECK_U64(o.size, sizeof(wr_prim_ops));
	WRT_CHECK(o.gcm_state_bytes >= 1u && o.gcm_state_bytes <= WR_GCM_HOST_STATE_MAX);
	WRT_CHECK_U64(o.gcm_state_bytes % 8u, 0);
	WRT_CHECK_U64(o.gcm_state_bytes, WRL_GCM_AESNI_STATE_BYTES);
	WRT_CHECK(o.gcm_setkey != NULL && o.gcm_start != NULL && o.gcm_update != NULL);
	WRT_CHECK(o.gcm_final_enc != NULL && o.gcm_final_dec != NULL && o.gcm_wipe != NULL);
	/* "portable" for everything else: ctx and the one-shot members stay NULL */
	WRT_CHECK(o.ctx == NULL && o.crc32c == NULL && o.hmac_sha256 == NULL && o.hmac_sha384 == NULL);
	WRT_CHECK(o.aes_cbc_enc == NULL && o.aes_cbc_dec == NULL);
	memset(&p, 0x11, sizeof(p));
	WRT_CHECK(wrl_gcm_aesni_ops(&p) == 0);
	WRT_CHECK(memcmp(&o, &p, sizeof(o)) == 0); /* deterministic, no stray bytes */
	ops = o;
}

/* ---- the published vectors ------------------------------------------------------------------- */

static void test_nist(void)
{
	wrt_json j;
	wrt_tok cases;
	size_t nc, i, used = 0, outside = 0;
	wri_pgcm *g = (wri_pgcm *)xalloc(sizeof(*g));
	hstate h;

	hs_init(&h, 0);
	if (wrt_json_load_vec(&j, "secure/gcm-nist.json") != 0) {
		WRT_CHECK(0);
		free(g);
		hs_free(&h);
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
		} else if (kn != 16u || ivn != 12u || an != 0u || pn % 16u != 0u) {
			outside++; /* AES-192/256, other IV lengths, additional data, partial blocks: the hook's contract excludes them */
		} else {
			used++;
			buf = (uint8_t *)xalloc(pn + 16u);
			WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, h.st, key));
			for (k = 0; k < 3u; k++) {
				int split = (int)k; /* one piece, one block at a time, random blocks */

				memset(buf, 0xee, pn + 16u);
				memset(got, 0xee, 16);
				WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 0, iv, pt, buf, pn, split, got));
				WRT_CHECK_MEM(buf, ct, pn);
				WRT_CHECK_MEM(got, tag, 16);
				WRT_CHECK(buf[pn] == 0xee); /* nothing written beyond n */
				memcpy(buf, pt, pn); /* in place */
				WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 0, iv, buf, buf, pn, split, got));
				WRT_CHECK_MEM(buf, ct, pn);
				WRT_CHECK_MEM(got, tag, 16);
				memset(buf, 0xee, pn + 16u);
				WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 1, iv, ct, buf, pn, split, tag));
				WRT_CHECK_MEM(buf, pt, pn);
				memcpy(buf, ct, pn);
				WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 1, iv, buf, buf, pn, split, tag));
				WRT_CHECK_MEM(buf, pt, pn);
				/* a wrong tag (the last bit flipped) is refused */
				memcpy(got, tag, 16);
				got[15] ^= 1u;
				WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, hk_run(h.st, 1, iv, ct, buf, pn, split, got));
			}
			ops.gcm_wipe(NULL, h.st);
			/* the same through the dispatcher with the hook table */
			memset(g, 0, sizeof(*g));
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(g, &ops, key));
			WRT_CHECK(wri_pgcm_is_host(g) == 1);
			WRT_CHECK_STATUS(WR_OK, pg_run(g, 0, iv, pt, buf, pn, 2, got));
			WRT_CHECK_MEM(buf, ct, pn);
			WRT_CHECK_MEM(got, tag, 16);
			WRT_CHECK_STATUS(WR_OK, pg_run(g, 1, iv, ct, buf, pn, 2, tag));
			WRT_CHECK_MEM(buf, pt, pn);
			wri_pgcm_wipe(g);
			free(buf);
		}
		free(key); free(iv); free(aad); free(pt); free(ct); free(tag);
	}
	/* the 20 published cases: TC1 (empty), TC2 (one block), TC3 (four blocks) and the two empty-message cases fit the contract */
	WRT_CHECK(used >= 3u);
	WRT_CHECK_U64(used + outside, nc);
	WRT_CHECK(hs_guards_ok(&h));
	wrt_json_free(&j);
	free(g);
	hs_free(&h);
}

/* ---- differential ---------------------------------------------------------------------------- */

#define MAXN 65536u
#define REF_MAX 2048u

/* One case against the portable GCM (a dispatcher without a table) and, for short ones, the reference. The hook state h is keyed
 * with key already; pg is a portable dispatcher keyed with the same key. */
static void diff_case(hstate *h, wri_pgcm *pg, const uint8_t key[16], size_t n, int inplace, int split, uint8_t *bin, uint8_t *bout,
		      uint8_t *pt, uint8_t *ct_h, uint8_t *ct_p, uint8_t *rt, size_t off)
{
	uint8_t iv[12], tag_h[16], tag_p[16], tag_r[16], bad[16];
	uint8_t *in = bin + off, *out = inplace ? bin + off : bout + ((off * 7u) & 15u);
	size_t bit;

	rnd_fill(iv, 12);
	rnd_fill(pt, n);

	/* encrypt on the hook */
	memcpy(in, pt, n);
	WRT_CHECK_STATUS(WR_OK, hk_run(h->st, 0, iv, in, out, n, split, tag_h));
	memcpy(ct_h, out, n);
	/* encrypt on the portable code */
	WRT_CHECK_STATUS(WR_OK, pg_run(pg, 0, iv, pt, ct_p, n, 2, tag_p));
	WRT_CHECK(memcmp(ct_h, ct_p, n) == 0);
	WRT_CHECK(memcmp(tag_h, tag_p, 16) == 0);
	if (n <= REF_MAX) {
		WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, pt, n, rt, tag_r) == 0);
		WRT_CHECK(memcmp(ct_h, rt, n) == 0);
		WRT_CHECK(memcmp(tag_h, tag_r, 16) == 0);
	}
	/* decrypt on the hook what the portable code encrypted, and the other way round */
	memcpy(in, ct_p, n);
	WRT_CHECK_STATUS(WR_OK, hk_run(h->st, 1, iv, in, out, n, split, tag_p));
	WRT_CHECK(memcmp(out, pt, n) == 0);
	WRT_CHECK_STATUS(WR_OK, pg_run(pg, 1, iv, ct_h, rt, n, 2, tag_h));
	WRT_CHECK(memcmp(rt, pt, n) == 0);
	/* a flipped tag bit and a flipped ciphertext bit are refused by both, and the state works again right after */
	memcpy(bad, tag_h, 16);
	bit = rnd() % 128u;
	bad[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
	memcpy(in, ct_h, n);
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, hk_run(h->st, 1, iv, in, out, n, split, bad));
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, pg_run(pg, 1, iv, ct_h, rt, n, 2, bad));
	if (n > 0u) {
		size_t cb = rnd() % (n * 8u);

		memcpy(in, ct_h, n);
		in[cb / 8u] ^= (uint8_t)(1u << (cb % 8u));
		WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, hk_run(h->st, 1, iv, in, out, n, split, tag_h));
	}
	memcpy(in, ct_h, n);
	WRT_CHECK_STATUS(WR_OK, hk_run(h->st, 1, iv, in, out, n, split, tag_h));
	WRT_CHECK(memcmp(out, pt, n) == 0);
}

static void test_differential(size_t state_off)
{
	hstate h;
	wri_pgcm *pg = (wri_pgcm *)xalloc(sizeof(*pg));
	uint8_t *bin = (uint8_t *)xalloc(MAXN + 64u), *bout = (uint8_t *)xalloc(MAXN + 64u), *pt = (uint8_t *)xalloc(MAXN);
	uint8_t *ct_h = (uint8_t *)xalloc(MAXN), *ct_p = (uint8_t *)xalloc(MAXN), *rt = (uint8_t *)xalloc(MAXN);
	uint8_t key[16];
	size_t n, i, ncase = 0;

	hs_init(&h, state_off);
	memset(pg, 0, sizeof(*pg));
	rnd_fill(key, 16);
	WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, h.st, key));
	WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(pg, NULL, key));
	WRT_CHECK(wri_pgcm_is_host(pg) == 0);

	/* every multiple of 16 up to 1 KiB, both ways of cutting it, in place and not */
	for (n = 16u; n <= 1024u; n += 16u) {
		int inplace;

		for (inplace = 0; inplace < 2; inplace++) {
			diff_case(&h, pg, key, n, inplace, inplace ? 1 : 2, bin, bout, pt, ct_h, ct_p, rt, (n + (size_t)inplace) & 15u);
			ncase++;
		}
		if (n % 256u == 0u) { /* rekey now and then: a fresh key in the same state, no wipe in between */
			rnd_fill(key, 16);
			WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, h.st, key));
			wri_pgcm_wipe(pg);
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(pg, NULL, key));
		}
	}
	/* random lengths up to 64 KiB */
	for (i = 0; i < 260u; i++) {
		n = 16u * (1u + rnd() % (MAXN / 16u));
		if (i % 5u == 0u)
			n = 16u * (1u + rnd() % 130u); /* around the 4-block groups of the loop */
		diff_case(&h, pg, key, n, (int)(rnd() & 1u), (int)(rnd() % 3u), bin, bout, pt, ct_h, ct_p, rt, rnd() & 15u);
		ncase++;
	}
	/* the edges */
	diff_case(&h, pg, key, MAXN, 0, 0, bin, bout, pt, ct_h, ct_p, rt, 0);
	diff_case(&h, pg, key, MAXN, 1, 1, bin, bout, pt, ct_h, ct_p, rt, 3);
	diff_case(&h, pg, key, MAXN - 16u, 1, 2, bin, bout, pt, ct_h, ct_p, rt, 15);
	ncase += 3u;
	WRT_CHECK_U64(ncase, 64u * 2u + 260u + 3u);
	WRT_CHECK(hs_guards_ok(&h));
	ops.gcm_wipe(NULL, h.st);
	WRT_CHECK(all_byte(h.st, h.sz, 0));
	WRT_CHECK(hs_guards_ok(&h));
	wri_pgcm_wipe(pg);
	free(pg); free(bin); free(bout); free(pt); free(ct_h); free(ct_p); free(rt);
	hs_free(&h);
}

/* ---- the contract and the fail-closed side --------------------------------------------------- */

/* The expected result of an operation done right, from the reference. */
static WRT_UNUSED void ref_op(const uint8_t key[16], const uint8_t iv[12], const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[16])
{
	WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, in, n, out, tag) == 0);
}

#ifdef WRL_AESNI
/* After a poisoned operation the state still does the next one right. */
static void expect_still_good(void *st, const uint8_t key[16])
{
	uint8_t iv[12], pt[160], ct[160], rct[160], tag[16], rtag[16];

	rnd_fill(iv, 12);
	rnd_fill(pt, sizeof(pt));
	WRT_CHECK_STATUS(WR_OK, hk_run(st, 0, iv, pt, ct, sizeof(pt), 2, tag));
	ref_op(key, iv, pt, sizeof(pt), rct, rtag);
	WRT_CHECK_MEM(ct, rct, sizeof(pt));
	WRT_CHECK_MEM(tag, rtag, 16);
}

static void test_contract(void)
{
	hstate h;
	uint8_t key[16], iv[12], zero16[16], buf[256], sent[256], tag[16], good[16], ptx[256];
	wrl_gs *s;
	size_t i;

	hs_init(&h, 8);
	s = (wrl_gs *)h.st;
	rnd_fill(key, 16);
	rnd_fill(iv, 12);
	memset(zero16, 0, 16);

	/* ---- no key: everything is refused or does nothing */
	WRT_CHECK_STATUS(WR_E_STATE, ops.gcm_start(NULL, h.st, iv, 0));
	memset(buf, 0xee, sizeof(buf));
	memset(tag, 0xee, 16);
	ops.gcm_update(NULL, h.st, buf, buf, 32);
	WRT_CHECK(all_byte(buf, sizeof(buf), 0xee));
	ops.gcm_final_enc(NULL, h.st, tag);
	WRT_CHECK(all_byte(tag, 16, 0)); /* a tag is never made without an operation */
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, ops.gcm_final_dec(NULL, h.st, zero16));
	WRT_CHECK(all_byte(h.st, h.sz, 0)); /* still unkeyed */

	/* ---- setkey and start argument checks */
	WRT_CHECK_STATUS(WR_E_INVAL, ops.gcm_setkey(NULL, h.st, NULL));
	WRT_CHECK(all_byte(h.st, h.sz, 0));
	WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, h.st, key));
	WRT_CHECK_STATUS(WR_E_INVAL, ops.gcm_start(NULL, h.st, NULL, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, ops.gcm_start(NULL, h.st, iv, 2));
	WRT_CHECK_STATUS(WR_E_INVAL, ops.gcm_start(NULL, h.st, iv, -1));
	expect_still_good(h.st, key);

	/* ---- a length that is not a multiple of 16 poisons the operation, writes nothing, and the final never says yes */
	for (i = 1; i < 16u; i++) {
		size_t sz = 32u + i;

		rnd_fill(ptx, sizeof(ptx));
		memcpy(buf, ptx, sizeof(buf));
		memcpy(sent, ptx, sizeof(sent));
		WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
		ops.gcm_update(NULL, h.st, buf, buf, 16); /* a good block first */
		ops.gcm_update(NULL, h.st, buf + 16, buf + 16, sz - 16u);
		WRT_CHECK(memcmp(buf + 16, sent + 16, sz - 16u) == 0); /* the bad piece is not written */
		ops.gcm_update(NULL, h.st, buf + 16, buf + 16, 16);    /* and the operation stays dead */
		WRT_CHECK(memcmp(buf + 16, sent + 16, 16) == 0);
		memset(tag, 0xee, 16);
		ops.gcm_final_enc(NULL, h.st, tag);
		WRT_CHECK(all_byte(tag, 16, 0));
		expect_still_good(h.st, key);
		/* the decrypt side: even the tag of the good prefix is not accepted */
		ref_op(key, iv, ptx, 16, sent, good);
		WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 1));
		ops.gcm_update(NULL, h.st, sent, buf, 16);
		ops.gcm_update(NULL, h.st, sent, buf, 15);
		WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, ops.gcm_final_dec(NULL, h.st, good));
		expect_still_good(h.st, key);
	}
	/* 1 and 15 and 17 bytes as the first and only update */
	{
		static const size_t bad_len[3] = {1u, 15u, 17u};

		for (i = 0; i < 3u; i++) {
			memset(buf, 0xee, sizeof(buf));
			WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
			ops.gcm_update(NULL, h.st, buf, buf, bad_len[i]);
			WRT_CHECK(all_byte(buf, sizeof(buf), 0xee));
			ops.gcm_final_enc(NULL, h.st, tag);
			WRT_CHECK(all_byte(tag, 16, 0));
		}
	}

	/* ---- NULL buffers */
	memset(buf, 0xee, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
	ops.gcm_update(NULL, h.st, NULL, buf, 16);
	ops.gcm_update(NULL, h.st, buf, buf, 16);
	WRT_CHECK(all_byte(buf, 16, 0xee));
	ops.gcm_final_enc(NULL, h.st, tag);
	WRT_CHECK(all_byte(tag, 16, 0));
	WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 1));
	ops.gcm_update(NULL, h.st, buf, NULL, 16);
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, ops.gcm_final_dec(NULL, h.st, zero16));
	/* n == 0 with NULL buffers is a no-op that does not hurt the operation */
	rnd_fill(ptx, 64);
	WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
	ops.gcm_update(NULL, h.st, NULL, NULL, 0);
	memcpy(buf, ptx, 64);
	ops.gcm_update(NULL, h.st, buf, buf, 64);
	ops.gcm_update(NULL, h.st, NULL, NULL, 0);
	ops.gcm_final_enc(NULL, h.st, tag);
	ref_op(key, iv, ptx, 64, sent, good);
	WRT_CHECK_MEM(buf, sent, 64);
	WRT_CHECK_MEM(tag, good, 16);

	/* ---- partial overlap: both directions of the shift, one byte and one block, in place is fine */
	for (i = 0; i < 4u; i++) {
		static const size_t shift[4] = {1u, 16u, 48u, 15u};
		int backwards = (int)(i & 1u);

		rnd_fill(buf, sizeof(buf));
		memcpy(sent, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
		if (backwards)
			ops.gcm_update(NULL, h.st, buf + shift[i], buf, 64);
		else
			ops.gcm_update(NULL, h.st, buf, buf + shift[i], 64);
		WRT_CHECK(memcmp(buf, sent, sizeof(buf)) == 0); /* nothing written */
		ops.gcm_final_enc(NULL, h.st, tag);
		WRT_CHECK(all_byte(tag, 16, 0));
	}
	expect_still_good(h.st, key);

	/* ---- no operation running: nothing is written, nothing breaks; after a final too */
	memset(buf, 0xee, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
	ops.gcm_final_enc(NULL, h.st, tag); /* an empty operation */
	ref_op(key, iv, NULL, 0, sent, good);
	WRT_CHECK_MEM(tag, good, 16);
	ops.gcm_update(NULL, h.st, buf, buf, 32);
	WRT_CHECK(all_byte(buf, sizeof(buf), 0xee));
	ops.gcm_final_enc(NULL, h.st, tag); /* a second final of the same operation */
	WRT_CHECK(all_byte(tag, 16, 0));
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, ops.gcm_final_dec(NULL, h.st, good));
	expect_still_good(h.st, key);

	/* ---- a final of the other direction fails and ends the operation */
	WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, ops.gcm_final_dec(NULL, h.st, good));
	WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 1));
	memset(tag, 0xee, 16);
	ops.gcm_final_enc(NULL, h.st, tag);
	WRT_CHECK(all_byte(tag, 16, 0));
	expect_still_good(h.st, key);

	/* ---- a start inside an operation drops the old one */
	{
		uint8_t iv2[12];

		rnd_fill(iv2, 12);
		rnd_fill(ptx, 128);
		memcpy(buf, ptx, 128);
		WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
		ops.gcm_update(NULL, h.st, buf, buf, 80);
		WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 0, iv2, ptx, buf, 128, 1, tag));
		ref_op(key, iv2, ptx, 128, sent, good);
		WRT_CHECK_MEM(buf, sent, 128);
		WRT_CHECK_MEM(tag, good, 16);
	}

	/* ---- the end of an operation erases it and keeps the key */
	WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 0, iv, ptx, buf, 128, 2, tag));
	WRT_CHECK(all_byte(s->acc, sizeof(s->acc), 0));
	WRT_CHECK(all_byte(s->iv, sizeof(s->iv), 0));
	WRT_CHECK_U64(s->ctr, 0);
	WRT_CHECK_U64(s->mode, M_IDLE);
	WRT_CHECK(!all_byte(s->rk, sizeof(s->rk), 0)); /* the key is still there */
	expect_still_good(h.st, key);

	/* ---- the 2^36 - 32 byte cap and the counter near the wrap of 2^32 */
	{
		uint8_t ks[48], want[48], ctrb[16], z[48];
		ref_aes a;

		memset(z, 0, sizeof(z));
		WRT_CHECK(ref_aes_init(&a, key, 16) == 0);
		/* three blocks left: they are the stock keystream with the counter wrapping to 0xffffffff and no carry into the IV */
		WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
		s->ctr = 0xfffffffdu;
		ops.gcm_update(NULL, h.st, z, ks, 48);
		for (i = 0; i < 3u; i++) {
			uint32_t c = 0xfffffffdu + (uint32_t)i;

			memcpy(ctrb, iv, 12);
			ctrb[12] = (uint8_t)(c >> 24);
			ctrb[13] = (uint8_t)(c >> 16);
			ctrb[14] = (uint8_t)(c >> 8);
			ctrb[15] = (uint8_t)c;
			ref_aes_encrypt_block(&a, ctrb, want + 16u * i);
		}
		WRT_CHECK_MEM(ks, want, 48);
		WRT_CHECK_U64(s->mode, M_ENC); /* 2^32 - 2 blocks is exactly the cap: still fine */
		/* now the operation is full: one more block poisons it and writes nothing */
		memset(ks, 0xee, 16);
		ops.gcm_update(NULL, h.st, z, ks, 16);
		WRT_CHECK(all_byte(ks, 16, 0xee));
		WRT_CHECK_U64(s->mode, M_FAILED);
		memset(tag, 0xee, 16);
		ops.gcm_final_enc(NULL, h.st, tag);
		WRT_CHECK(all_byte(tag, 16, 0));
		/* four blocks when three are left: refused as a whole, nothing written (not even the first three) */
		WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
		s->ctr = 0xfffffffdu;
		memset(ks, 0xee, 48);
		{
			uint8_t big[64], bo[64];

			memset(big, 0, sizeof(big));
			memset(bo, 0xee, sizeof(bo));
			ops.gcm_update(NULL, h.st, big, bo, 64);
			WRT_CHECK(all_byte(bo, sizeof(bo), 0xee));
		}
		WRT_CHECK_U64(s->mode, M_FAILED);
		ops.gcm_final_enc(NULL, h.st, tag);
		/* a length so large that a block count of it could never fit: refused before anything is read */
		WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 1));
		ops.gcm_update(NULL, h.st, z, ks, (size_t)1 << 40);
		WRT_CHECK_U64(s->mode, M_FAILED);
		WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, ops.gcm_final_dec(NULL, h.st, z));
		expect_still_good(h.st, key);
	}

	/* ---- wipe: all of the state and nothing else; a wiped state is unkeyed; a second wipe and a NULL are harmless */
	ops.gcm_wipe(NULL, h.st);
	WRT_CHECK(all_byte(h.st, h.sz, 0));
	WRT_CHECK(hs_guards_ok(&h));
	WRT_CHECK_STATUS(WR_E_STATE, ops.gcm_start(NULL, h.st, iv, 0));
	ops.gcm_wipe(NULL, h.st);
	ops.gcm_wipe(NULL, NULL);
	WRT_CHECK(all_byte(h.st, h.sz, 0));
	WRT_CHECK(hs_guards_ok(&h));
	/* wipe in the middle of an operation too */
	WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, h.st, key));
	WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
	memset(buf, 0x42, 64);
	ops.gcm_update(NULL, h.st, buf, buf, 64);
	ops.gcm_wipe(NULL, h.st);
	WRT_CHECK(all_byte(h.st, h.sz, 0));
	WRT_CHECK(hs_guards_ok(&h));
	hs_free(&h);
}
#endif

/* ---- the published frames, tag corruption, two states at once -------------------------------- */

#ifdef WRL_AESNI
static size_t pad16_(size_t x)
{
	return (x + 15u) & ~(size_t)15u;
}

/* One operation through the hook on a keyed state, ciphertext and tag checked against what is on the wire (opn bytes then 16 tag bytes),
 * then opened again from the wire in place, and a one-bit damage to the ciphertext and to the tag refused. */
static int frame_op(void *st, const uint8_t iv[12], const uint8_t *wire_op, size_t opn, uint8_t *plain_out)
{
	uint8_t *buf = (uint8_t *)xalloc(opn + 16u), tag[16], wt[16];
	int bad = 0;

	memcpy(wt, wire_op + opn, 16);
	memcpy(buf, wire_op, opn);
	if (hk_run(st, 1, iv, buf, buf, opn, 2, wt) != WR_OK) {
		free(buf);
		return -1;
	}
	memcpy(plain_out, buf, opn);
	/* sealed again it is the wire */
	if (hk_run(st, 0, iv, buf, buf, opn, 1, tag) != WR_OK || memcmp(buf, wire_op, opn) != 0 || memcmp(tag, wire_op + opn, 16) != 0)
		bad = 1;
	/* damage: the last ciphertext byte, the first tag byte */
	memcpy(buf, wire_op, opn);
	buf[opn - 1u] ^= 0x80u;
	if (hk_run(st, 1, iv, buf, buf, opn, 0, wt) != WR_E_CRYPTO_MAC)
		bad = 1;
	memcpy(buf, wire_op, opn);
	memcpy(tag, wire_op + opn, 16);
	tag[0] ^= 1u;
	if (hk_run(st, 1, iv, buf, buf, opn, 0, tag) != WR_E_CRYPTO_MAC)
		bad = 1;
	free(buf);
	return bad ? -1 : 0;
}

/* A whole msgr2 revision 1 secure frame (docs/spec/msgr2-secure-mode.md): the preamble operation of 80 bytes, the rest of segment 0 when
 * its padded length exceeds 48, the later segments with the epilogue; nonce stepped after every operation as the spec says. */
static int frame_walk(void *st, const uint8_t first[12], const uint8_t *wire, size_t wn, size_t *nops_out)
{
	uint8_t nonce[12], pre[80], seg[8192];
	size_t pos = 96, len[4] = {0, 0, 0, 0}, nseg, i, nops = 1;

	memcpy(nonce, first, 12);
	if (wn < 96u || frame_op(st, nonce, wire, 80, pre) != 0)
		return -1;
	ref_secure_nonce_step(nonce, 1);
	nseg = pre[1];
	if (nseg < 1u || nseg > 4u)
		return -1;
	for (i = 0; i < nseg; i++)
		len[i] = (size_t)pre[2 + 6 * i] | (size_t)pre[3 + 6 * i] << 8 | (size_t)pre[4 + 6 * i] << 16 | (size_t)pre[5 + 6 * i] << 24;
	if (len[0] > 48u) {
		size_t part = pad16_(len[0]) - 48u;

		if (part > sizeof(seg) || pos + part + 16u > wn || frame_op(st, nonce, wire + pos, part, seg) != 0)
			return -1;
		ref_secure_nonce_step(nonce, 1);
		pos += part + 16u;
		nops++;
	}
	if (nseg > 1u) {
		size_t tail = 16u;

		for (i = 1; i < nseg; i++)
			tail += pad16_(len[i]);
		if (tail > sizeof(seg) || pos + tail + 16u > wn || frame_op(st, nonce, wire + pos, tail, seg) != 0)
			return -1;
		ref_secure_nonce_step(nonce, 1);
		pos += tail + 16u;
		nops++;
	}
	if (pos != wn)
		return -1;
	*nops_out = nops;
	return 0;
}

/* Known answers that do not come from this repository's own GCM code: frames A and B of the secure mode note, and every frame of
 * secure-frames-synthetic.json, which was produced by a separate sender and checked against captured sessions. */
static void test_frames(void)
{
	static const char frame_a[] =
	    "5ee83e477793cc7cbb381480b30cc69431dabdf879b50b483d403cfd1b1ec96ae363935876ea5233f5930611558cad49725d69ea832d072f15bad3bf4b43581f0"
	    "1654a9d4a848c689172d4521fcf8108ee387f09dafe616e6a0c5adfa581ad5e";
	hstate h;
	wrt_json j;
	uint8_t key[16], nonce[12], wire[160], pre[96], *kb = NULL;
	size_t kn = 0, d, i, frames = 0, ops_seen = 0;

	hs_init(&h, 8);
	{
		uint8_t *t = NULL;
		size_t tn = 0;

		WRT_CHECK(wrt_hex_decode("000102030405060708090a0b0c0d0e0f", 32, &t, &tn) == 0 && tn == 16u);
		memcpy(key, t, 16);
		free(t);
		WRT_CHECK(wrt_hex_decode("1c1d1e1f2021222324252627", 24, &t, &tn) == 0 && tn == 12u);
		memcpy(nonce, t, 12);
		free(t);
		WRT_CHECK(wrt_hex_decode(frame_a, strlen(frame_a), &t, &tn) == 0 && tn == 96u);
		memcpy(wire, t, 96);
		free(t);
	}
	WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, h.st, key));
	WRT_CHECK(frame_op(h.st, nonce, wire, 80, pre) == 0);
	WRT_CHECK(pre[0] == 0x07 && pre[1] == 0x01 && pre[2] == 0x20 && pre[31] == 0x72); /* the AUTH_SIGNATURE preamble, 32 byte segment */
	WRT_CHECK(all_byte(pre + 32, 32, 0xa5) && all_byte(pre + 64, 16, 0));

	if (wrt_json_load_vec(&j, "secure/secure-frames-synthetic.json") != 0) {
		WRT_CHECK(0);
		hs_free(&h);
		return;
	}
	if (wrt_json_get_hex(&j, wrt_json_root(&j), "key_hex", &kb, &kn) != 0 || kn != 16u || memcmp(kb, key, 16) != 0) {
		WRT_CHECK(0);
		free(kb);
		wrt_json_free(&j);
		hs_free(&h);
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

			if (wrt_json_get_hex(&j, f, "wire_hex", &w, &wn) != 0 || wrt_json_get_hex(&j, f, "first_iv_hex", &iv, &ivn) != 0 || ivn != 12u) {
				WRT_CHECK(0);
				free(w);
				free(iv);
				continue;
			}
			gops = (int)wrt_json_int(&j, wrt_json_get(&j, f, "gcm_operations"), &ok);
			WRT_CHECK(ok);
			WRT_CHECK(frame_walk(h.st, iv, w, wn, &nops) == 0);
			WRT_CHECK_U64(nops, gops);
			ops_seen += nops;
			frames++;
			free(w);
			free(iv);
		}
	}
	WRT_CHECK(frames >= 9u);
	WRT_CHECK(ops_seen >= 12u);
	WRT_CHECK(hs_guards_ok(&h));
	wrt_json_free(&j);
	ops.gcm_wipe(NULL, h.st);
	hs_free(&h);
}

/* Every single-bit damage of the tag is refused (128 cases), so is an all-zero tag, the tag of another IV, another key, and the tag of
 * a shorter message; a missing tag (NULL) is a refusal that ends the operation; a missing tag buffer at the end of an encryption
 * writes nothing and ends it too. The decryption has written the plaintext by then (the contract says the caller must not use it). */
static void test_tag_checks(void)
{
	hstate h;
	uint8_t key[16], key2[16], iv[12], iv2[12], pt[96], ct[96], tag[16], t2[16], bad[16], out[96];
	size_t bit;
	wrl_gs *s;

	hs_init(&h, 0);
	s = (wrl_gs *)h.st;
	rnd_fill(key, 16);
	rnd_fill(key2, 16);
	rnd_fill(iv, 12);
	rnd_fill(iv2, 12);
	rnd_fill(pt, sizeof(pt));
	WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, h.st, key));
	WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 0, iv, pt, ct, sizeof(pt), 2, tag));
	WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 1, iv, ct, out, sizeof(pt), 2, tag));
	for (bit = 0; bit < 128u; bit++) {
		memcpy(bad, tag, 16);
		bad[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
		WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, hk_run(h.st, 1, iv, ct, out, sizeof(pt), (int)(bit % 3u), bad));
	}
	memset(bad, 0, 16);
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, hk_run(h.st, 1, iv, ct, out, sizeof(pt), 0, bad));
	memset(bad, 0xff, 16);
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, hk_run(h.st, 1, iv, ct, out, sizeof(pt), 0, bad));
	/* the same message under another IV and under another key gives another tag, which this one does not accept */
	WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 0, iv2, pt, out, sizeof(pt), 0, t2));
	WRT_CHECK(memcmp(t2, tag, 16) != 0);
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, hk_run(h.st, 1, iv, ct, out, sizeof(pt), 0, t2));
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, hk_run(h.st, 1, iv2, ct, out, sizeof(pt), 0, tag)); /* right tag, wrong IV */
	/* the tag of a shorter message (a truncated frame) */
	WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 0, iv, pt, out, 80, 0, t2));
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, hk_run(h.st, 1, iv, ct, out, sizeof(pt), 0, t2));
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, hk_run(h.st, 1, iv, ct, out, 80, 0, tag));
	WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 1, iv, ct, out, 80, 0, t2)); /* the 80-byte prefix with its own tag is a good message */
	WRT_CHECK_MEM(out, pt, 80);
	WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, h.st, key2));
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, hk_run(h.st, 1, iv, ct, out, sizeof(pt), 0, tag));
	WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, h.st, key));

	/* the tag pointer is NULL */
	WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 1));
	ops.gcm_update(NULL, h.st, ct, out, sizeof(pt));
	WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, ops.gcm_final_dec(NULL, h.st, NULL));
	WRT_CHECK_U64(s->mode, M_IDLE);
	WRT_CHECK(all_byte(s->acc, sizeof(s->acc), 0));
	WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, h.st, iv, 0));
	ops.gcm_update(NULL, h.st, pt, out, sizeof(pt));
	ops.gcm_final_enc(NULL, h.st, NULL);
	WRT_CHECK_U64(s->mode, M_IDLE);
	WRT_CHECK(all_byte(s->acc, sizeof(s->acc), 0));
	WRT_CHECK_STATUS(WR_OK, hk_run(h.st, 1, iv, ct, out, sizeof(pt), 2, tag)); /* and the state is as good as before */
	WRT_CHECK(hs_guards_ok(&h));
	ops.gcm_wipe(NULL, h.st);
	hs_free(&h);
}

/* A random walk over the six members against a small model: the hook either does exactly what the model says (the stock result of
 * ref_gcm over the data fed so far) or, after anything outside the contract since the last start, never says yes and never
 * produces a tag that verifies. Steps: start in either direction with a fresh IV, valid updates of random size and place (apart, in
 * place), invalid ones (odd length, NULL, partial overlap, too long), finals with the right tag, a wrong tag and none, a start
 * inside an operation, a final without an operation, a wipe and a rekey. */
#define SM_MAX 1024u

static void test_state_machine(void)
{
	hstate h;
	uint8_t key[16], iv[12], in[SM_MAX + 64u], outb[SM_MAX + 64u], acc_in[SM_MAX], keep[SM_MAX], pt_ref[SM_MAX], tg[16], rt[16], tmp[SM_MAX];
	size_t acc_n = 0, step;
	int keyed = 0, running = 0, dec = 0, clean = 0;
	unsigned long n_ok_enc = 0, n_ok_dec = 0, n_refused = 0;

	hs_init(&h, 8);
	rnd_fill(key, 16);
	memset(iv, 0, 12);
	for (step = 0; step < 20000u; step++) {
		/* weights out of 32: rekey 1, wipe 1, start 6, valid update 14, invalid update 2, encrypt final 3, decrypt final 4, odd final 1 */
		unsigned r32 = rnd() % 32u;
		unsigned act = r32 == 0u ? 0u : r32 == 1u ? 1u : r32 < 8u ? 2u : r32 < 22u ? 4u : r32 < 24u ? 10u : r32 < 27u ? 11u : r32 < 31u ? 12u : 15u;

		switch (act) {
		case 0: /* rekey */
			rnd_fill(key, 16);
			WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, h.st, key));
			keyed = 1;
			running = 0;
			break;
		case 1: /* wipe */
			ops.gcm_wipe(NULL, h.st);
			keyed = 0;
			running = 0;
			WRT_CHECK(all_byte(h.st, h.sz, 0));
			break;
		case 2: { /* start */
			wr_status st;

			rnd_fill(iv, 12);
			dec = (int)(rnd() & 1u);
			st = ops.gcm_start(NULL, h.st, iv, dec);
			if (!keyed) {
				WRT_CHECK_STATUS(WR_E_STATE, st);
				running = 0;
			} else {
				WRT_CHECK_STATUS(WR_OK, st);
				running = 1;
				clean = 1;
				acc_n = 0;
			}
			break;
		}
		case 4: { /* a valid update */
			size_t n = 16u * (1u + rnd() % 4u);
			int inplace = (int)(rnd() & 1u);

			if (acc_n + n > SM_MAX)
				break;
			rnd_fill(in, n);
			memset(outb, 0xee, n);
			if (inplace) {
				memcpy(outb, in, n);
				ops.gcm_update(NULL, h.st, outb, outb, n);
			} else {
				ops.gcm_update(NULL, h.st, in, outb, n);
			}
			if (running && clean) {
				memcpy(acc_in + acc_n, in, n);
				acc_n += n;
				/* the data side is the stock keystream xor, whatever the direction */
				WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, acc_in, acc_n, tmp, rt) == 0);
				WRT_CHECK_MEM(outb, tmp + acc_n - n, n);
			} else if (inplace) { /* outside a clean operation (none, or one already poisoned) nothing is written */
				WRT_CHECK_MEM(outb, in, n);
			} else {
				WRT_CHECK(all_byte(outb, n, 0xee));
			}
			break;
		}
		case 10: { /* an invalid update: it poisons a running operation and writes nothing */
			size_t kind = rnd() % 4u, n = 32u;

			rnd_fill(in, 64);
			memset(outb, 0xee, 64);
			memcpy(keep, in, 64);
			if (kind == 0u)
				ops.gcm_update(NULL, h.st, in, outb, 16u * (rnd() % 3u) + 1u + rnd() % 15u);
			else if (kind == 1u)
				ops.gcm_update(NULL, h.st, NULL, outb, n);
			else if (kind == 2u)
				ops.gcm_update(NULL, h.st, in, in + 16, n);
			else
				ops.gcm_update(NULL, h.st, in + 16, in, n);
			WRT_CHECK(all_byte(outb, 64, 0xee));
			WRT_CHECK(memcmp(in, keep, 64) == 0);
			clean = 0;
			break;
		}
		case 11: /* a final that encrypts */
			memset(tg, 0xee, 16);
			ops.gcm_final_enc(NULL, h.st, tg);
			if (running && clean && !dec) {
				WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, acc_in, acc_n, tmp, rt) == 0);
				WRT_CHECK_MEM(tg, rt, 16);
				n_ok_enc++;
			} else {
				WRT_CHECK(all_byte(tg, 16, 0)); /* never a tag without a clean encrypting operation */
				if (running)
					n_refused++;
			}
			running = 0;
			break;
		case 12: { /* a final that decrypts: the right tag, a wrong one, or none */
			unsigned which = rnd() % 4u; /* 0 and 3: the right tag, 1: a bit flipped, 2: none */
			wr_status st, want_st;

			if (running && !dec) {
				memset(tg, 0, 16);
			} else {
				/* the tag the data deserves: the keystream undoes the ciphertext, sealing that gives the tag over the ciphertext */
				WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, acc_in, acc_n, pt_ref, rt) == 0);
				WRT_CHECK(ref_gcm_seal(key, 16, iv, 12, NULL, 0, pt_ref, acc_n, tmp, tg) == 0);
				if (acc_n > 0u)
					WRT_CHECK_MEM(tmp, acc_in, acc_n);
			}
			if (which == 1u)
				tg[rnd() % 16u] ^= (uint8_t)(1u << (rnd() % 8u));
			st = (which == 2u) ? ops.gcm_final_dec(NULL, h.st, NULL) : ops.gcm_final_dec(NULL, h.st, tg);
			want_st = (running && clean && dec && (which == 0u || which == 3u)) ? WR_OK : WR_E_CRYPTO_MAC;
			WRT_CHECK_STATUS(want_st, st);
			if (want_st == WR_OK)
				n_ok_dec++;
			else if (running)
				n_refused++;
			running = 0;
			break;
		}
		default: /* 15: a final of the wrong kind or without an operation, to be refused */
			memset(tg, 0, 16);
			if (!running || !dec) {
				WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, ops.gcm_final_dec(NULL, h.st, tg));
			} else {
				memset(tg, 0xee, 16);
				ops.gcm_final_enc(NULL, h.st, tg);
				WRT_CHECK(all_byte(tg, 16, 0));
			}
			running = 0;
			break;
		}
	}
	fprintf(stderr, "state machine: %lu good encrypts, %lu good decrypts, %lu refused\n", n_ok_enc, n_ok_dec, n_refused);
	WRT_CHECK(n_ok_enc > 100u && n_ok_dec > 100u && n_refused > 100u);
	WRT_CHECK(hs_guards_ok(&h));
	ops.gcm_wipe(NULL, h.st);
	hs_free(&h);
}

/* Two states, two keys, one table, operations interleaved piece by piece: nothing is shared between states (no global state), and
 * a final on one does not disturb the other. */
static void test_two_states(void)
{
	hstate a, b;
	uint8_t ka[16], kb[16], iva[12], ivb[12], pa[1024], pb[1024], oa[1024], ob[1024], ta[16], tb[16], ra[1024], rb[1024], rta[16], rtb[16];
	size_t pos = 0, round;

	hs_init(&a, 0);
	hs_init(&b, 8);
	for (round = 0; round < 40u; round++) {
		size_t n = 16u * (1u + rnd() % 64u);

		pos = 0;
		rnd_fill(ka, 16);
		rnd_fill(kb, 16);
		rnd_fill(iva, 12);
		rnd_fill(ivb, 12);
		rnd_fill(pa, n);
		rnd_fill(pb, n);
		WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, a.st, ka));
		WRT_CHECK_STATUS(WR_OK, ops.gcm_setkey(NULL, b.st, kb));
		WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, a.st, iva, 0));
		WRT_CHECK_STATUS(WR_OK, ops.gcm_start(NULL, b.st, ivb, 1)); /* b decrypts what a would like to see as plaintext: any bytes do */
		while (pos < n) {
			size_t step = 16u * (1u + rnd() % 8u);

			if (step > n - pos)
				step = n - pos;
			ops.gcm_update(NULL, a.st, pa + pos, oa + pos, step);
			ops.gcm_update(NULL, b.st, pb + pos, ob + pos, step);
			pos += step;
		}
		/* b ends first, then a */
		ops.gcm_final_enc(NULL, a.st, ta);
		memset(tb, 0, 16);
		(void)ops.gcm_final_dec(NULL, b.st, tb); /* the tag is wrong, the plaintext is what matters here */
		WRT_CHECK(ref_gcm_seal(ka, 16, iva, 12, NULL, 0, pa, n, ra, rta) == 0);
		WRT_CHECK_MEM(oa, ra, n);
		WRT_CHECK_MEM(ta, rta, 16);
		/* b's keystream is the stock one: sealing the ciphertext bytes as "plaintext" of the reference gives the same xor */
		WRT_CHECK(ref_gcm_seal(kb, 16, ivb, 12, NULL, 0, ob, n, rb, rtb) == 0); /* rb = ob xor ks = pb xor ks xor ks */
		WRT_CHECK_MEM(rb, pb, n);
	}
	WRT_CHECK(hs_guards_ok(&a) && hs_guards_ok(&b));
	ops.gcm_wipe(NULL, a.st);
	ops.gcm_wipe(NULL, b.st);
	hs_free(&a);
	hs_free(&b);
}
#endif

/* ---- the dispatcher and the loopback --------------------------------------------------------- */

static void test_pgcm_loopback(void)
{
	wri_pgcm *tx = (wri_pgcm *)xalloc(sizeof(*tx)), *rx = (wri_pgcm *)xalloc(sizeof(*rx));
	uint8_t key[16], nonce[12], rnonce[12], *pt = (uint8_t *)xalloc(4096u + 16u), *w1 = (uint8_t *)xalloc(4096u + 16u);
	uint8_t *w2 = (uint8_t *)xalloc(4096u + 16u), *w3 = (uint8_t *)xalloc(4096u + 16u), *back = (uint8_t *)xalloc(4096u + 16u);
	int rev, dir;
	size_t frame, nops = 0;

	for (dir = 0; dir < 2; dir++) {
		for (rev = 0; rev < 2; rev++) {
			memset(tx, 0, sizeof(*tx));
			memset(rx, 0, sizeof(*rx));
			rnd_fill(key, 16);
			rnd_fill(nonce, 12);
			if (rev == 0) { /* msgr2.0 steps a 32-bit field: start it close to the wrap */
				nonce[0] = 0xf0;
				nonce[1] = 0xff;
				nonce[2] = 0xff;
				nonce[3] = 0xff;
			}
			memcpy(rnonce, nonce, 12);
			/* dir 0: the hook seals, the portable code opens. dir 1: the other way round. */
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(tx, dir == 0 ? &ops : NULL, key));
			WRT_CHECK_STATUS(WR_OK, wri_pgcm_setkey(rx, dir == 0 ? NULL : &ops, key));
			WRT_CHECK(wri_pgcm_is_host(tx) == (dir == 0));
			WRT_CHECK(wri_pgcm_is_host(rx) == (dir == 1));
			for (frame = 0; frame < 60u; frame++) {
				/* a frame: three operations of 80, 16 k and 16 k + 16 bytes (the shape docs/spec/msgr2-secure-mode.md has) */
				size_t k = (frame < 8u) ? frame : 1u + rnd() % 200u;
				size_t sizes[3], j;

				sizes[0] = 80u;
				sizes[1] = 16u * k;
				sizes[2] = 16u * k + 16u;
				for (j = 0; j < 3u; j++) {
					size_t n = sizes[j];
					uint8_t tag_ref[16], refnonce[12], *rd;

					if (n == 0u)
						continue; /* k == 0: an empty segment has no operation */
					rnd_fill(pt, n);
					/* the stock operation: ciphertext then tag, nonce stepped afterwards */
					memcpy(refnonce, rnonce, 12);
					ref_secure_seal_rev(key, refnonce, rev, pt, n, w3);
					memcpy(rnonce, refnonce, 12);
					WRT_CHECK_STATUS(WR_OK, pg_run(tx, 0, nonce, pt, w1, n, 2, w1 + n));
					WRT_CHECK(memcmp(w1, w3, n + 16u) == 0); /* ciphertext and tag are the stock bytes */
					memcpy(tag_ref, w3 + n, 16);
					/* the other side opens it (in place every other time) */
					memcpy(w2, w1, n + 16u);
					rd = (frame & 1u) ? w2 : back;
					WRT_CHECK_STATUS(WR_OK, pg_run(rx, 1, nonce, w2, rd, n, 2, tag_ref));
					WRT_CHECK(memcmp(rd, pt, n) == 0);
					/* a damaged operation is refused by the receiver, which then goes on */
					memcpy(w2, w1, n + 16u);
					w2[rnd() % n] ^= 1u;
					WRT_CHECK_STATUS(WR_E_CRYPTO_MAC, pg_run(rx, 1, nonce, w2, back, n, 2, tag_ref));
					ref_secure_nonce_step(nonce, rev);
					nops++;
				}
			}
			wri_pgcm_wipe(tx);
			wri_pgcm_wipe(rx);
			WRT_CHECK(all_byte((const uint8_t *)tx, sizeof(*tx), 0));
			WRT_CHECK(all_byte((const uint8_t *)rx, sizeof(*rx), 0));
		}
	}
	WRT_CHECK(nops > 400u);
	free(tx);
	free(rx);
	free(pt); free(w1); free(w2); free(w3); free(back);
}

/* ---- main ------------------------------------------------------------------------------------ */

int main(void)
{
#ifdef T_X86
	test_gating();
#endif
	if (!wrl_gcm_aesni_available()) {
		wr_prim_ops o;

		WRT_CHECK(wrl_gcm_aesni_ops(&o) == -1);
		if (wrt_failures != 0u)
			return wrt_finish();
		WRT_SKIP("no AES-NI hook here: needs x86-64 with gcc or clang and a CPU with AES, PCLMULQDQ, SSSE3 and SSE4.1");
	}
	test_table();
	test_nist();
	test_differential(0);
	test_differential(8);
#ifdef WRL_AESNI
	test_contract();
	test_frames();
	test_tag_checks();
	test_two_states();
	test_state_machine();
#endif
	test_pgcm_loopback();
	return wrt_finish();
}
