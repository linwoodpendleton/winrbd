/* SPDX-License-Identifier: MIT */
/*
 * test_m2_sec_tx_diff - the secure transmit side against the independent peer, over random scenarios (core/src/msgr2/wri_m2_sec_tx.c and
 * wri_m2_sec_tx2.c; the same body as the fuzz target fuzz_m2_sec_tx, see m2_sec_tx_scn.h).
 *
 * A scenario is a byte string: encode buffer and bounce sizes, a secret, and steps that send frames of random shapes (empty segment 0 up to tens
 * of kilobytes, one to four segments), let the host consume random amounts, drain, and reset the connection in the middle of a stream. Held at
 * every step: the pending count is exact, a peek is repeatable and shows progress, the caller's memory is freed and poisoned the moment the
 * host consumed its frame (so a later read is a report under the address sanitizer and a wrong byte otherwise) and never written; held at the
 * end: the bytes consumed are those of the independent encoder (ref_gcm), less what a reset dropped (a frame refused for room took no nonce:
 * the next one still matches), and the independent decoder reads every frame back.
 *
 * Also: a fixed list of hand-built scenarios that name the interesting cases (they are the committed fuzz seeds too: ctest replays
 * harness/fuzz/seeds/fuzz_m2_sec_tx through the same body), the same scenarios with the accelerated GCM hook when WRT_GCM_ACCEL=1 (the bytes
 * of the two runs must be identical: the portable code on one side and the hook on the other), and a differential against the in-test model
 * of the spec's operation order built from ref_secure_seal alone (the preamble CRC from the independent CRC, one seal per part).
 */
#include <dirent.h>
#include <stdlib.h>
#include <string.h>

#include "wrt.h"

#define TXR_CHECK WRT_CHECK
#include "m2_sec_tx_scn.h"

#include "../host/wrl_gcm_aesni.c"

/* ---- the model: parts sealed one by one with ref_secure_seal ------------------------------------------------------------- */

/* One frame the way docs/spec/msgr2-secure-mode.md 3.3 says, from ref_secure_seal only: out must hold the whole frame; returns its size. */
static size_t model_frame(const uint8_t key[16], uint8_t nonce[12], uint8_t tag, unsigned nseg, const uint8_t *const seg[4], const uint32_t len[4], uint8_t *out)
{
	uint8_t pre[32], p1[80], *pt, *w = out;
	size_t i, n3 = 0, r0, padded;

	memset(pre, 0, sizeof(pre));
	pre[0] = tag;
	pre[1] = (uint8_t)nseg;
	for (i = 0; i < nseg; i++) {
		pre[2 + 6 * i] = (uint8_t)len[i];
		pre[3 + 6 * i] = (uint8_t)(len[i] >> 8);
		pre[4 + 6 * i] = (uint8_t)(len[i] >> 16);
		pre[5 + 6 * i] = (uint8_t)(len[i] >> 24);
		pre[6 + 6 * i] = i == 3 ? 0x00 : 0x08; /* alignment 8, and 4096 = 0x1000 for the fourth segment */
		pre[7 + 6 * i] = i == 3 ? 0x10 : 0x00;
	}
	{
		uint32_t crc = sim_sec_crc32c(0, pre, 28);

		pre[28] = (uint8_t)crc;
		pre[29] = (uint8_t)(crc >> 8);
		pre[30] = (uint8_t)(crc >> 16);
		pre[31] = (uint8_t)(crc >> 24);
	}
	memcpy(p1, pre, 32);
	memset(p1 + 32, 0, 48);
	memcpy(p1 + 32, seg[0], len[0] < 48u ? len[0] : 48u);
	ref_secure_seal(key, nonce, p1, 80, w);
	w += 96;
	if (len[0] > 48u) {
		r0 = len[0] - 48u;
		padded = (r0 + 15u) & ~(size_t)15u;
		pt = (uint8_t *)calloc(padded, 1);
		memcpy(pt, seg[0] + 48, r0);
		ref_secure_seal(key, nonce, pt, padded, w);
		w += padded + 16u;
		free(pt);
	}
	if (nseg > 1u) {
		for (i = 1; i < nseg; i++)
			n3 += (len[i] + 15u) & ~15u;
		pt = (uint8_t *)calloc(n3 + 16u, 1);
		n3 = 0;
		for (i = 1; i < nseg; i++) {
			memcpy(pt + n3, seg[i], len[i]);
			n3 += (len[i] + 15u) & ~15u;
		}
		pt[n3] = 0x0e;
		ref_secure_seal(key, nonce, pt, n3 + 16u, w);
		w += n3 + 16u + 16u;
		free(pt);
	}
	return (size_t)(w - out);
}

static void model_check(txr *r, const uint8_t secret[64], uint8_t nonce[12], unsigned nseg, const uint32_t len[4])
{
	static uint8_t d[4][400];
	uint8_t model[2048];
	const uint8_t *sp[4];
	wri_m2_seg_src src[4];
	size_t k, n, before = r->wire_len;
	unsigned i;

	(void)secret;
	for (i = 0; i < 4u; i++) {
		for (k = 0; k < sizeof(d[i]); k++)
			d[i][k] = (uint8_t)(i * 37u + k * 3u + len[0]);
		sp[i] = d[i];
	}
	memset(src, 0, sizeof(src));
	for (i = 0; i < nseg; i++) {
		src[i].p = len[i] != 0u ? d[i] : NULL;
		src[i].len = len[i];
	}
	WRT_CHECK_STATUS(WR_OK, txr_send(r, 17, src, nseg)); /* noref: the model is the expectation here */
	txr_drain(r, 0, 0);
	n = model_frame(secret, nonce, 17, nseg, sp, len, model);
	WRT_CHECK(r->wire_len - before == n && memcmp(r->wire + before, model, n) == 0);
}

static void test_model(void)
{
	static const uint32_t l0s[] = {0, 1, 47, 48, 49, 95, 96, 97, 130};
	static const uint32_t ls[] = {1, 15, 16, 17, 70};
	uint8_t secret[64], nonce[12];
	txr r;
	unsigned a, b, i;

	for (i = 0; i < sizeof(secret); i++)
		secret[i] = (uint8_t)(255u - i);
	WRT_CHECK_STATUS(WR_OK, txr_open(&r, 4096u, 256u, NULL, secret));
	r.noref = 1;
	memcpy(nonce, secret + 28, 12); /* the client transmits with the seed S[28..39] */
	for (a = 0; a < sizeof(l0s) / sizeof(l0s[0]); a++) {
		uint32_t one[4] = {l0s[a], 0, 0, 0};

		model_check(&r, secret, nonce, 1, one);
		for (b = 0; b < sizeof(ls) / sizeof(ls[0]); b++) {
			uint32_t two[4] = {l0s[a], ls[b], 0, 0}, three[4] = {l0s[a], 0, ls[b], 0}, four[4] = {l0s[a], ls[b], 0, 33};

			model_check(&r, secret, nonce, 2, two);
			model_check(&r, secret, nonce, 3, three);
			model_check(&r, secret, nonce, 4, four);
		}
	}
	txr_close(&r);
}

/* ---- the scenarios ---------------------------------------------------------------------------------------------------------- */

static uint64_t g_state = 0x243f6a8885a308d3ull;

static uint32_t rnd(void)
{
	g_state ^= g_state >> 12;
	g_state ^= g_state << 25;
	g_state ^= g_state >> 27;
	return (uint32_t)((g_state * 0x2545f4914f6cdd1dull) >> 32);
}

static void scenario_both(const uint8_t *d, size_t n, size_t budget, const wr_prim_ops *accel)
{
	uint8_t *w0 = NULL, *w1 = NULL;
	size_t n0 = 0, n1 = 0;

	txr_scenario(d, n, NULL, budget, &w0, &n0);
	if (accel != NULL) {
		txr_scenario(d, n, accel, budget, &w1, &n1);
		WRT_CHECK(n0 == n1 && (n0 == 0u || memcmp(w0, w1, n0) == 0)); /* the hook and the portable code put the same bytes on the wire */
	}
	free(w0);
	free(w1);
}

static void test_random(const wr_prim_ops *accel)
{
	unsigned i, k;
	uint8_t buf[700];

	for (i = 0; i < 400u; i++) {
		size_t n = 40u + rnd() % (sizeof(buf) - 40u);

		for (k = 0; k < n; k++)
			buf[k] = (uint8_t)rnd();
		scenario_both(buf, n, 2048u + (size_t)(rnd() % 40000u), accel);
	}
}

/* The committed fuzz seeds are scenarios too: replay them here with the accelerated hook as well and a bigger data budget. */
static void test_seed_dir(const wr_prim_ops *accel)
{
	char path[1024], file[1280];
	const char *vec = getenv("WRT_VECTOR_DIR");
	DIR *dir;
	struct dirent *e;
	unsigned seen = 0;

	if (vec == NULL)
		return;
	snprintf(path, sizeof(path), "%s/../fuzz/seeds/fuzz_m2_sec_tx", vec);
	dir = opendir(path);
	if (dir == NULL)
		return; /* a tree without the seeds: the random scenarios above are the coverage */
	while ((e = readdir(dir)) != NULL) {
		uint8_t *buf = NULL;
		size_t n = 0;

		if (e->d_name[0] == '.')
			continue;
		snprintf(file, sizeof(file), "%s/%s", path, e->d_name);
		if (wrt_read_file(file, &buf, &n) != 0)
			continue;
		scenario_both(buf, n, 200000u, accel);
		free(buf);
		seen++;
	}
	closedir(dir);
	WRT_CHECK(seen > 0u);
}

int main(void)
{
	const char *acc = getenv("WRT_GCM_ACCEL");
	static wr_prim_ops ops;
	const wr_prim_ops *accel = NULL;

	if (acc != NULL && strcmp(acc, "1") == 0) {
		if (wrl_gcm_aesni_ops(&ops) == 0)
			accel = &ops;
		else
			fprintf(stderr, "note: WRT_GCM_ACCEL=1 but the CPU lacks AES / PCLMULQDQ / SSE4.1: the accelerated pass is skipped\n");
	}
	if (accel != NULL) {
		txr probe;

		WRT_CHECK_STATUS(WR_OK, txr_open(&probe, 4096u, 4096u, accel, NULL));
		WRT_CHECK(wri_pgcm_is_host(&probe.slot.s.tx)); /* the hook really is the one in use */
		txr_close(&probe);
	}
	test_model();
	test_random(accel);
	test_seed_dir(accel);
	return wrt_finish();
}
