/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the CRUSH mapper (core/src/crush/wri_crush_map.c, wri_crush_buck.c, wri_crush_audit.c).
 *
 * Input layout:
 *   byte 0        rule id
 *   byte 1        result_max - 1, modulo 16 (so 1 to 16)
 *   bytes 2..5    x, little endian
 *   byte 6        choose_args pool id, as a signed byte (-1 selects the default set)
 *   byte 7        work budget: 1 << (byte % 21)
 *   byte 8        number of OSD weights n (0 means no weight array at all: every device is out)
 *   next 2 n      the weights, little-endian 16-bit: 0xffff is "in" (0x10000), anything else is the value as it is
 *   rest          a CRUSH blob (an exact-size heap copy, so ASan sees any over-read)
 *
 * The blob is decoded into a 64 KiB room; a map that does not decode ends the run. Otherwise, properties (a violated
 * one traps):
 *   - the audit answers WR_OK or one of NO_RULE / UNSUPPORTED / LOOP, with a reason (module and text) in the errinfo,
 *     and leaves the errinfo alone when it answers WR_OK;
 *   - the mapper answers WR_OK or NO_RULE / UNSUPPORTED / LOOP / WORK; on any failure the result count is 0, and the
 *     reason is filled;
 *   - on success n <= result_max, and every result is a device below max_devices or an existing bucket (a rule can
 *     emit the bucket it took);
 *   - the work left is never above the budget, and is 0 after WR_E_CRUSH_WORK;
 *   - a second run gives the same status, results and work (the result is a pure function of the inputs);
 *   - a map and rule that the audit accepted never fail for a structural reason (NO_RULE, UNSUPPORTED, LOOP): only
 *     the work budget can stop the mapper;
 *   - nothing is read outside the region, the weight array and the result buffer (ASan, exact-size copies).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_crush.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define ROOM 65536u
#define HDR 9u

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

static int structural(wr_status st)
{
	return st == WR_E_CRUSH_NO_RULE || st == WR_E_CRUSH_UNSUPPORTED || st == WR_E_CRUSH_LOOP;
}

static void check_result(const wri_crush *c, const int32_t *res, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		if (res[i] >= 0)
			check(res[i] < c->max_devices);
		else
			check(wri_crush_bucket(c, res[i]) != NULL);
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t rule, rmax, x, nw, budget, i, n1 = 0, n2 = 0;
	int32_t pool;
	uint32_t *w = NULL;
	uint8_t *blob, *room;
	size_t blob_n, used = 0;
	wri_crush *c;
	wr_errinfo why;
	wr_status st, sa, s1, s2;
	int32_t r1[WRI_CRUSH_RESULT_MAX], r2[WRI_CRUSH_RESULT_MAX];
	wri_crush_ws ws1, ws2;
	wri_crush_in in;

	if (size < HDR)
		return 0;
	rule = data[0];
	rmax = 1u + (data[1] % WRI_CRUSH_RESULT_MAX);
	x = (uint32_t)data[2] | ((uint32_t)data[3] << 8) | ((uint32_t)data[4] << 16) | ((uint32_t)data[5] << 24);
	pool = (int32_t)(int8_t)data[6];
	budget = 1u << (data[7] % 21u);
	nw = data[8];
	if (size < HDR + 2u * (size_t)nw)
		return 0;
	if (nw != 0) {
		w = (uint32_t *)malloc((size_t)nw * sizeof(uint32_t));
		check(w != NULL);
		for (i = 0; i < nw; i++) {
			uint32_t v = (uint32_t)data[HDR + 2u * i] | ((uint32_t)data[HDR + 2u * i + 1u] << 8);

			w[i] = v == 0xffffu ? 0x10000u : v;
		}
	}
	blob_n = size - HDR - 2u * (size_t)nw;
	blob = (uint8_t *)malloc(blob_n != 0 ? blob_n : 1u);
	room = (uint8_t *)malloc(ROOM);
	check(blob != NULL && room != NULL);
	if (blob_n != 0)
		memcpy(blob, data + HDR + 2u * (size_t)nw, blob_n);

	memset(&why, 0, sizeof(why));
	st = wri_crush_decode(blob, blob_n, room, ROOM, &used, &why);
	if (st != WR_OK) {
		free(blob);
		free(room);
		free(w);
		return 0;
	}
	c = (wri_crush *)(void *)room;
	check(wri_crush_check(c, used) == WR_OK);

	/* the audit */
	memset(&why, 0, sizeof(why));
	sa = wri_crush_audit_rule(c, rule, rmax, &why);
	check(sa == WR_OK || structural(sa));
	if (sa == WR_OK) {
		check(why.status == 0 && why.what == NULL);
	} else {
		check(why.status == sa && why.module == WR_MOD_CRUSH && why.what != NULL);
	}

	/* the mapper, twice */
	in.rule = rule;
	in.x = x;
	in.result_max = rmax;
	in.osd_weight = w;
	in.weight_max = nw;
	in.args_pool = pool;
	memset(&ws1, 0, sizeof(ws1));
	memset(&ws2, 0, sizeof(ws2));
	ws1.work = ws2.work = budget;
	memset(&why, 0, sizeof(why));
	s1 = wri_crush_do_rule(c, &in, &ws1, r1, &n1, &why);
	check(s1 == WR_OK || structural(s1) || s1 == WR_E_CRUSH_WORK);
	if (s1 == WR_OK) {
		check(n1 <= rmax);
		check_result(c, r1, n1);
		check(why.status == 0);
	} else {
		check(n1 == 0);
		check(why.status == s1 && why.module == WR_MOD_CRUSH && why.what != NULL);
	}
	check(ws1.work <= budget);
	if (s1 == WR_E_CRUSH_WORK)
		check(ws1.work == 0);
	s2 = wri_crush_do_rule(c, &in, &ws2, r2, &n2, NULL);
	check(s2 == s1 && n1 == n2 && ws1.work == ws2.work);
	for (i = 0; i < n1 && s1 == WR_OK; i++)
		check(r1[i] == r2[i]);
	if (sa == WR_OK)
		check(!structural(s1));

	free(blob);
	free(room);
	free(w);
	return 0;
}
