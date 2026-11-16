/* SPDX-License-Identifier: MIT */
/*
 * wri_mosdmap_hdr.c - the front header of MOSDMap (docs/spec/mon-client.md 2.6).
 *
 * Body order: fsid, incremental_maps, maps, cluster_osdmap_trim_lower_bound, newest_map (the last
 * two from header version 2), the removed-snaps block (from version 4). Each of the two map lists is
 * u32 count, then count times {u32 epoch, u32 blob length, blob}. The blobs are stepped over by
 * their length and never looked at: decoding an OSDMap is another module's job, and the consumer
 * gets the raw front.
 */
#include "wri_mon.h"

WR_FILE_LICENCE_MIT

#define MOSDMAP_LIST_MAX 1024u /* entries accepted per list; a monitor sends 40 by default */

/* Running bounds over the epoch keys of both lists. */
typedef struct epoch_range {
	uint32_t lo, hi;
	int any;
} epoch_range;

/* Walk one list; every blob is skipped by its length. Returns the entry count (0 and an error on r if bad). */
static uint32_t walk_list(wri_rd *r, epoch_range *rg)
{
	uint32_t c = wri_rd_count(r, MOSDMAP_LIST_MAX, 8), i;

	for (i = 0; i < c; i++) {
		uint32_t epoch = wri_rd_u32(r);
		uint32_t len = wri_rd_u32(r);

		wri_rd_skip(r, (size_t)len);
		if (!wri_rd_ok(r))
			return 0;
		if (!rg->any || epoch < rg->lo)
			rg->lo = epoch;
		if (!rg->any || epoch > rg->hi)
			rg->hi = epoch;
		rg->any = 1;
	}
	return c;
}

wr_status wri_mosdmap_info_decode(const uint8_t *front, size_t n, uint16_t msg_version, wri_mosdmap_info *out)
{
	wri_rd r;
	epoch_range rg;

	if (out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	if (front == NULL && n != 0)
		return WR_E_INVAL;
	/* No trim bound and no newest_map before version 2: the missing-range logic cannot work. */
	if (msg_version < 2)
		return WR_E_MON_PROTO;

	rg.lo = rg.hi = 0;
	rg.any = 0;
	wri_rd_init(&r, front, n);
	wri_rd_copy(&r, out->fsid, sizeof(out->fsid));
	out->n_incremental = walk_list(&r, &rg);
	out->n_full = walk_list(&r, &rg);
	out->oldest_map = wri_rd_u32(&r);
	out->newest_map = wri_rd_u32(&r);
	if (msg_version >= 4) {
		/* Obsolete removed-snaps map: a current monitor always writes an empty one. */
		uint32_t gap = wri_rd_u32(&r);

		if (wri_rd_ok(&r) && gap != 0) {
			WR_MEMSET(out, 0, sizeof(*out));
			return WR_E_MON_PROTO;
		}
	}
	/* Versions 2 to 4 have a fixed layout; a higher one may append fields we do not know. */
	if (wri_rd_ok(&r) && msg_version <= 4 && wri_rd_left(&r) != 0)
		wri_rd_fail(&r, WR_E_ENCODING);
	if (!wri_rd_ok(&r)) {
		wr_status st = r.err;

		WR_MEMSET(out, 0, sizeof(*out));
		return st;
	}
	if (rg.any) {
		out->first_epoch = rg.lo;
		out->last_epoch = rg.hi;
	}
	return WR_OK;
}
