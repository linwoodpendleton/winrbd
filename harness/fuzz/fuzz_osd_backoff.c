/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the MOSDBackoff decoder and acknowledgement encoder (core/src/osd/wri_osd_bo.c).
 *
 * Byte 0 and 1 are the msgr2 header's version and compat_version, the rest is the front as an exact-size heap copy.
 *
 *   wri_mbackoff_decode
 *     success: version >= 1 and compat <= 1, op 1 .. 3, key / name within 2048 and namespace within 256 bytes, every string inside
 *              the input; failure: WR_E_OSD_VERSION for an unaccepted pair, else WR_E_OSD_PROTO (or WR_E_OSD_VERSION from the struct
 *              header of a position), output all zero
 *   then, on success:
 *     wri_hobj_cmp  reflexive on both positions, antisymmetric between them; wri_mbackoff_covers consistent with it (a single-object
 *                   backoff covers its own position and nothing that compares unequal)
 *     wri_mbackoff_encode_ack  for a BLOCK: exactly wri_mbackoff_ack_len bytes, which decode again as an ACK_BLOCK with the same pgid,
 *                   id, epoch and positions; one byte less is WR_E_TOOBIG; for any other op: WR_E_INVAL
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

static int sgn(int v)
{
	return v < 0 ? -1 : v > 0 ? 1 : 0;
}

static int in_buf(const uint8_t *p, uint32_t len, const uint8_t *buf, size_t n)
{
	return len == 0 || (p >= buf && (size_t)(p - buf) + len <= n);
}

static void check_hobj(const wri_hobj *h, const uint8_t *buf, size_t n)
{
	check(h->key_len <= WRI_OSD_NAME_LIMIT && h->oid_len <= WRI_OSD_NAME_LIMIT && h->nspace_len <= 256u);
	check(in_buf(h->key, h->key_len, buf, n) && in_buf(h->oid, h->oid_len, buf, n) && in_buf(h->nspace, h->nspace_len, buf, n));
	check(h->max <= 1);
}

static void check_ack(const wri_mbackoff *m)
{
	size_t len = wri_mbackoff_ack_len(m);
	uint8_t *ack = (uint8_t *)malloc(len ? len : 1);
	uint8_t *exact;
	wri_wr w;
	wri_mbackoff a;

	check(ack != NULL);
	wri_wr_init(&w, ack, len);
	if (m->op != WRI_BACKOFF_BLOCK) {
		check(wri_mbackoff_encode_ack(&w, m) == WR_E_INVAL);
		free(ack);
		return;
	}
	check(wri_mbackoff_encode_ack(&w, m) == WR_OK);
	check(wri_wr_len(&w) == len);
	exact = heap_copy(ack, len);
	check(exact != NULL);
	check(wri_mbackoff_decode(exact, len, 1, 1, &a) == WR_OK);
	check(a.op == WRI_BACKOFF_ACK_BLOCK && a.id == m->id && a.map_epoch == m->map_epoch && a.pool == m->pool && a.pg_seed == m->pg_seed);
	check(wri_hobj_cmp(&a.begin, &m->begin) == 0 && wri_hobj_cmp(&a.end, &m->end) == 0);
	check(a.begin.snap == m->begin.snap && a.end.snap == m->end.snap && a.begin.hash == m->begin.hash && a.end.hash == m->end.hash);
	free(exact);
	if (len > 0) {
		uint8_t *small = (uint8_t *)malloc(len);

		check(small != NULL);
		wri_wr_init(&w, small, len - 1);
		check(wri_mbackoff_encode_ack(&w, m) == WR_E_TOOBIG);
		free(small);
	}
	free(ack);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint16_t ver, compat;
	uint8_t *buf;
	wri_mbackoff m;
	wr_status st;

	if (size < 2)
		return 0;
	ver = data[0];
	compat = data[1];
	buf = heap_copy(data + 2, size - 2);
	check(buf != NULL);
	memset(&m, 0xEE, sizeof(m));
	st = wri_mbackoff_decode(buf, size - 2, ver, compat, &m);
	if (st == WR_OK) {
		check(ver >= 1 && compat <= 1);
		check(m.op >= WRI_BACKOFF_BLOCK && m.op <= WRI_BACKOFF_UNBLOCK);
		check_hobj(&m.begin, buf, size - 2);
		check_hobj(&m.end, buf, size - 2);
		check(wri_hobj_cmp(&m.begin, &m.begin) == 0 && wri_hobj_cmp(&m.end, &m.end) == 0);
		check(sgn(wri_hobj_cmp(&m.begin, &m.end)) == -sgn(wri_hobj_cmp(&m.end, &m.begin)));
		if (wri_hobj_cmp(&m.begin, &m.end) == 0) {
			check(wri_mbackoff_covers(&m, &m.begin) == 1);
		} else {
			check(wri_mbackoff_covers(&m, &m.begin) == (wri_hobj_cmp(&m.begin, &m.end) < 0));
			check(wri_mbackoff_covers(&m, &m.end) == 0);
		}
		check_ack(&m);
	} else {
		if (ver < 1 || compat > 1)
			check(st == WR_E_OSD_VERSION);
		else
			check(st == WR_E_OSD_PROTO || st == WR_E_OSD_VERSION); /* the latter from a position's own struct header */
		check(all_zero(&m, sizeof(m)));
	}
	free(buf);
	return 0;
}
