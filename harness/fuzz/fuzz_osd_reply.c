/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the decoders of what an OSD sends back (core/src/osd/wri_osd_rep.c): the MOSDOpReply front, the SPARSE_READ output
 * and the STAT output.
 *
 * Byte 0 selects the decoder (mode % 3); the rest is an exact-size heap copy so ASan sees any over-read.
 *
 *   0  wri_mosdopreply_decode   bytes 1 and 2 are the msgr2 header's version and compat_version, then the front.
 *        success: version 8 and compat <= 8, n_ops <= 8, the name inside the input and within its limit, out_total equal to the sum of
 *                 the out_len values, the unused array slots zero; failure: WR_E_OSD_VERSION exactly when the pair is not accepted,
 *                 else WR_E_OSD_PROTO, and the output is all zero
 *   1  wri_osd_sparse_decode    byte 1 the capacity of the extent array (0 .. 255), bytes 2 .. 5 and 6 .. 9 the request offset and
 *        length as u32 each (bit 7 of byte 1 moves them to the top of the 64 bit range), then the output.
 *        success: at most min(capacity, 64) extents, ascending, disjoint, inside the request, summing to data_len, the data
 *                 filling the input to its end; failure: all three results zero
 *   2  wri_osd_stat_decode      success only for exactly 16 bytes; failure: results zero
 *
 * A violated property traps.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_osd_msg.h"

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

static int all_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != 0)
			return 0;
	return 1;
}

static void fuzz_reply(const uint8_t *in, size_t n)
{
	uint16_t ver, compat;
	uint8_t *buf;
	wri_mosdopreply r;
	wr_status st;

	if (n < 2)
		return;
	ver = in[0];
	compat = in[1];
	buf = heap_copy(in + 2, n - 2);
	check(buf != NULL);
	memset(&r, 0xEE, sizeof(r));
	st = wri_mosdopreply_decode(buf, n - 2, ver, compat, &r);
	if (st == WR_OK) {
		uint64_t total = 0;
		uint32_t i;

		check(ver == 8 && compat <= 8);
		check(r.n_ops <= WRI_OSD_OPS_MAX);
		check(r.oid_len <= WRI_OSD_NAME_LIMIT);
		check(r.oid_len == 0 || (r.oid >= buf && r.oid + r.oid_len <= buf + (n - 2)));
		check(r.do_redirect <= 1);
		for (i = 0; i < r.n_ops; i++)
			total += r.out_len[i];
		check(total == r.out_total);
		for (i = r.n_ops; i < WRI_OSD_OPS_MAX; i++)
			check(r.op_code[i] == 0 && r.out_len[i] == 0 && r.rval[i] == 0);
	} else {
		check(st == ((ver != 8 || compat > 8) ? WR_E_OSD_VERSION : WR_E_OSD_PROTO));
		check(all_zero(&r, sizeof(r)));
	}
	free(buf);
}

static void fuzz_sparse(const uint8_t *in, size_t n)
{
	wri_osd_extent ext[255 + 1];
	uint32_t ne = 0xDEAD, doff = 0xBEEF, dlen = 0xF00D;
	uint32_t emax, i;
	uint64_t ro, rl, used = 0, sum = 0;
	uint8_t *buf;
	wr_status st;

	if (n < 9)
		return;
	emax = in[0] & 0x7Fu;
	if ((in[0] & 0x7Fu) == 0x7Fu)
		emax = 255; /* some inputs offer more room than the decoder will use */
	ro = (uint64_t)in[1] | ((uint64_t)in[2] << 8) | ((uint64_t)in[3] << 16) | ((uint64_t)in[4] << 24);
	rl = (uint64_t)in[5] | ((uint64_t)in[6] << 8) | ((uint64_t)in[7] << 16) | ((uint64_t)in[8] << 24);
	if ((in[0] & 0x80u) != 0)
		ro |= 0xFFFFFFFF00000000ull; /* a request at the top of the 64 bit range: its end may wrap */
	memset(ext, 0xEE, sizeof(ext));
	buf = heap_copy(in + 9, n - 9);
	check(buf != NULL);
	st = wri_osd_sparse_decode(buf, (uint32_t)(n - 9), ro, rl, ext, emax, &ne, &doff, &dlen);
	if (st == WR_OK) {
		uint32_t cap = emax < WRI_OSD_SPARSE_EXT_MAX ? emax : WRI_OSD_SPARSE_EXT_MAX;

		check(ne <= cap);
		for (i = 0; i < ne; i++) {
			uint64_t rel;

			check(ext[i].off >= ro);
			rel = ext[i].off - ro;
			check(rel >= used && rel <= rl && ext[i].len <= rl - rel);
			used = rel + ext[i].len;
			sum += ext[i].len;
		}
		check(sum == dlen);
		check((uint64_t)doff == 4u + 16u * (uint64_t)ne + 4u);
		check((uint64_t)doff + dlen == (uint64_t)(n - 9));
	} else {
		check(st == WR_E_OSD_PROTO || st == WR_E_TOOBIG);
		check(ne == 0 && doff == 0 && dlen == 0);
	}
	free(buf);
}

static void fuzz_stat(const uint8_t *in, size_t n)
{
	uint64_t size = 1;
	uint32_t sec = 1, nsec = 1;
	uint8_t *buf = heap_copy(in, n);
	wr_status st;

	check(buf != NULL);
	st = wri_osd_stat_decode(buf, (uint32_t)n, &size, &sec, &nsec);
	if (st == WR_OK) {
		check(n == 16);
	} else {
		check(st == WR_E_OSD_PROTO && n != 16);
		check(size == 0 && sec == 0 && nsec == 0);
	}
	free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1)
		return 0;
	switch (data[0] % 3u) {
	case 0:
		fuzz_reply(data + 1, size - 1);
		break;
	case 1:
		fuzz_sparse(data + 1, size - 1);
		break;
	default:
		fuzz_stat(data + 1, size - 1);
		break;
	}
	return 0;
}
