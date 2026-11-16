/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the envelope, blob and address decoders (core/src/denc, core/src/msgr2/wri_m2_addr.c).
 *
 * Byte 0 selects the mode, the rest is the payload (an exact-size heap copy, so ASan sees any
 * over-read):
 *
 *   mode % 3 == 0  one entity_addr_t: decode; on success encode it again (must succeed), the
 *                  encoding must be the canonical form kept in raw, must decode back to an equal
 *                  address, and when the consumed input bytes already are the canonical form the
 *                  encoding must equal them
 *   mode % 3 == 1  one entity_addrvec_t with a small capacity: decode; on success re-encode the stored
 *                  entries, decode again and compare
 *   mode % 3 == 2  envelope and blob walk: open an envelope (supported compat from byte 1), read a
 *                  blob and a utime out of the body, then re-write what was read
 *
 * A violated property traps.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_denc.h"
#include "wri_m2_addr.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

static uint8_t *heap_copy(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n ? n : 1);

	if (q != NULL && n != 0)
		memcpy(q, p, n);
	return q;
}

static void fuzz_addr(const uint8_t *p, size_t n)
{
	uint8_t *buf = heap_copy(p, n);
	uint8_t enc[WRI_EADDR_MAX_WIRE];
	wri_rd r;
	wri_wr w;
	wri_eaddr a, b;
	wr_addr pub;

	if (buf == NULL)
		return;
	wri_rd_init(&r, buf, n);
	if (wri_eaddr_decode(&r, &a) == WR_OK) {
		size_t consumed = r.pos;

		check(a.raw_len == 35 || a.raw_len == 47);
		wri_wr_init(&w, enc, sizeof(enc));
		wri_eaddr_encode(&w, &a);
		check(wri_wr_ok(&w));
		check(wri_wr_len(&w) == a.raw_len && memcmp(enc, a.raw, a.raw_len) == 0);
		if (consumed == a.raw_len && memcmp(buf, a.raw, consumed) == 0)
			check(memcmp(enc, buf, consumed) == 0); /* canonical input comes back unchanged */

		wri_rd_init(&r, enc, wri_wr_len(&w));
		check(wri_eaddr_decode(&r, &b) == WR_OK);
		check(wri_eaddr_equal(&a, &b));
		check(a.type == b.type && a.nonce == b.nonce && a.family == b.family && a.port == b.port);
		check(memcmp(a.ip, b.ip, sizeof(a.ip)) == 0);

		/* the typed fields alone rebuild an address of the same family, port and nonce */
		wri_eaddr_to_wr(&pub, &a);
		wri_eaddr_from_wr(&b, &pub, a.type);
		check(b.family == a.family && b.port == a.port && b.nonce == a.nonce);
	} else {
		static const uint8_t zero[sizeof(a)] = {0};

		check(memcmp(&a, zero, sizeof(a)) == 0); /* a failed decode leaves nothing behind */
	}
	free(buf);
}

#define VEC_CAP 3u

static void fuzz_vec(const uint8_t *p, size_t n)
{
	uint8_t *buf = heap_copy(p, n);
	uint8_t enc[5 + 35 * 16 + 12 * 16];
	wri_eaddr a[VEC_CAP], b[VEC_CAP];
	size_t stored = 99, total = 99, stored2 = 99, total2 = 99, i;
	wri_rd r;
	wri_wr w;

	if (buf == NULL)
		return;
	wri_rd_init(&r, buf, n);
	if (wri_eaddrvec_decode(&r, a, VEC_CAP, &stored, &total) == WR_OK) {
		check(stored <= VEC_CAP && stored <= total && total <= WRI_EADDRVEC_WIRE_MAX);
		wri_wr_init(&w, enc, sizeof(enc));
		wri_eaddrvec_encode(&w, a, stored);
		check(wri_wr_ok(&w));
		wri_rd_init(&r, enc, wri_wr_len(&w));
		check(wri_eaddrvec_decode(&r, b, VEC_CAP, &stored2, &total2) == WR_OK);
		check(stored2 == stored && total2 == stored);
		for (i = 0; i < stored; i++)
			check(wri_eaddr_equal(&a[i], &b[i]));
		check(wri_rd_left(&r) == 0);
	} else {
		check(stored == 0 && total == 0);
	}
	free(buf);
}

static void fuzz_env(const uint8_t *p, size_t n)
{
	uint8_t *buf = NULL;
	uint8_t out[512];
	wri_rd r;
	wri_wr w;
	wri_env e;
	const uint8_t *blob;
	uint32_t len = 0, sec = 0, nsec = 0;
	size_t mark;

	if (n == 0)
		return;
	buf = heap_copy(p + 1, n - 1);
	if (buf == NULL)
		return;
	wri_rd_init(&r, buf, n - 1);
	if (wri_env_open(&r, p[0], &e) == WR_OK) {
		check(e.compat <= p[0]);
		blob = wri_denc_blob(&e.body, &len, 64);
		wri_denc_utime(&e.body, &sec, &nsec);
		if (blob != NULL && wri_rd_ok(&e.body)) {
			wri_rd back;
			wri_env e2;
			const uint8_t *blob2;
			uint32_t len2 = 0, sec2 = 0, nsec2 = 0;

			wri_wr_init(&w, out, sizeof(out));
			mark = wri_env_begin(&w, e.v, e.compat);
			wri_denc_put_blob(&w, blob, len);
			wri_denc_put_utime(&w, sec, nsec);
			wri_env_end(&w, mark);
			check(wri_wr_ok(&w));
			wri_rd_init(&back, out, wri_wr_len(&w));
			check(wri_env_open(&back, e.compat, &e2) == WR_OK);
			check(e2.v == e.v && e2.body.len == 4u + len + 8u);
			blob2 = wri_denc_blob(&e2.body, &len2, 64);
			wri_denc_utime(&e2.body, &sec2, &nsec2);
			check(blob2 != NULL && len2 == len && (len == 0 || memcmp(blob2, blob, len) == 0));
			check(sec2 == sec && nsec2 == nsec && wri_rd_left(&e2.body) == 0);
		}
	}
	free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0)
		return 0;
	switch (data[0] % 3u) {
	case 0:
		fuzz_addr(data + 1, size - 1);
		break;
	case 1:
		fuzz_vec(data + 1, size - 1);
		break;
	default:
		fuzz_env(data + 1, size - 1);
		break;
	}
	return 0;
}
