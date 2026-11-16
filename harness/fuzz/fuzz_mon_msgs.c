/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the monitor message decoders (core/src/mon): MonMap, MOSDMap front header,
 * MAuthReply, the MMonMap front wrapper and the mon_host parser.
 *
 * Byte 0 selects the decoder (mode % 5), the rest is the payload as an exact-size heap copy so ASan
 * sees any over-read. MOSDMap takes its header version from byte 1.
 *
 *   0  wri_monmap_decode      success: at most WRI_MON_MAXMONS ranks, at least one valid rank, every
 *                             valid rank holds a msgr2 address with a family; failure: output zero
 *   1  wri_mosdmap_info_decode  success: first <= last when any map is present, counts capped,
 *                             version >= 2; failure: output zero
 *   2  wri_mauth_reply_decode success: payload inside the input; failure: output zero
 *   3  wri_mmonmap_front, then wri_monmap_decode on the blob it returns (blob inside the input)
 *   4  wr_mon_parse_hosts     success: 1..8 addresses, each IPv4 or IPv6 with a non-zero port;
 *                             failure: count 0
 *
 * A violated property traps.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_mon.h"

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

static void fuzz_monmap_buf(const uint8_t *buf, size_t n)
{
	wri_monmap m;
	size_t i, valid = 0;
	wr_status st = wri_monmap_decode(buf, n, &m);

	if (st == WR_OK) {
		check(m.n_mons >= 1 && m.n_mons <= WRI_MON_MAXMONS);
		for (i = 0; i < WRI_MON_MAXMONS; i++) {
			if (i >= m.n_mons) {
				check(m.rank_valid[i] == 0);
				continue;
			}
			if (m.rank_valid[i]) {
				valid++;
				check(m.addr[i].type == WRI_EADDR_TYPE_MSGR2);
				check(m.addr[i].family == WR_AF_IPV4 || m.addr[i].family == WR_AF_IPV6);
				check(m.addr[i].raw_len == 35 || m.addr[i].raw_len == 47);
			}
		}
		check(valid >= 1);
	} else {
		check(all_zero(&m, sizeof(m)));
	}
}

static void fuzz_monmap(const uint8_t *p, size_t n)
{
	uint8_t *buf = heap_copy(p, n);

	if (buf == NULL)
		return;
	fuzz_monmap_buf(buf, n);
	free(buf);
}

static void fuzz_mosdmap(const uint8_t *p, size_t n)
{
	uint8_t *buf;
	wri_mosdmap_info o;
	uint16_t ver;
	wr_status st;

	if (n == 0)
		return;
	ver = p[0];
	buf = heap_copy(p + 1, n - 1);
	if (buf == NULL)
		return;
	st = wri_mosdmap_info_decode(buf, n - 1, ver, &o);
	if (st == WR_OK) {
		check(ver >= 2);
		check(o.n_incremental <= 1024 && o.n_full <= 1024);
		if (o.n_incremental + o.n_full != 0)
			check(o.first_epoch <= o.last_epoch);
		else
			check(o.first_epoch == 0 && o.last_epoch == 0);
		/* every counted entry took at least 8 bytes of the input */
		check(((size_t)o.n_incremental + (size_t)o.n_full) * 8u <= n - 1);
	} else {
		check(all_zero(&o, sizeof(o)));
	}
	free(buf);
}

static void fuzz_reply(const uint8_t *p, size_t n)
{
	uint8_t *buf = heap_copy(p, n);
	wri_mauth_reply r;
	wr_status st;

	if (buf == NULL)
		return;
	st = wri_mauth_reply_decode(buf, n, &r);
	if (st == WR_OK) {
		check(r.payload != NULL);
		check(r.payload >= buf && r.payload_len <= n && (size_t)(r.payload - buf) <= n - r.payload_len);
		check(r.payload_len <= 65536u);
	} else {
		check(all_zero(&r, sizeof(r)));
	}
	free(buf);
}

static void fuzz_front(const uint8_t *p, size_t n)
{
	uint8_t *buf = heap_copy(p, n);
	const uint8_t *blob = NULL;
	size_t blob_n = 0;

	if (buf == NULL)
		return;
	if (wri_mmonmap_front(buf, n, &blob, &blob_n) == WR_OK) {
		check(blob == buf + 4 && blob_n <= n - 4);
		fuzz_monmap_buf(blob, blob_n);
	} else {
		check(blob == NULL && blob_n == 0);
	}
	free(buf);
}

static void fuzz_hosts(const uint8_t *p, size_t n)
{
	char *buf = (char *)heap_copy(p, n);
	wr_addr a[WR_MAX_MONS];
	size_t cnt = 99, i;
	wr_status st;

	if (buf == NULL)
		return;
	st = wr_mon_parse_hosts(buf, n, a, WR_MAX_MONS, &cnt);
	if (st == WR_OK) {
		check(cnt >= 1 && cnt <= WR_MAX_MONS);
		for (i = 0; i < cnt; i++) {
			check(a[i].family == WR_AF_IPV4 || a[i].family == WR_AF_IPV6);
			check(a[i].port != 0);
			if (a[i].family == WR_AF_IPV4)
				check(all_zero(a[i].ip + 4, 12));
		}
	} else {
		check(cnt == 0);
		check(st == WR_E_MON_HOSTS_SYNTAX || st == WR_E_MON_NO_V2_ADDR);
	}
	free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0)
		return 0;
	switch (data[0] % 5u) {
	case 0:
		fuzz_monmap(data + 1, size - 1);
		break;
	case 1:
		fuzz_mosdmap(data + 1, size - 1);
		break;
	case 2:
		fuzz_reply(data + 1, size - 1);
		break;
	case 3:
		fuzz_front(data + 1, size - 1);
		break;
	default:
		fuzz_hosts(data + 1, size - 1);
		break;
	}
	return 0;
}
