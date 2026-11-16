/* SPDX-License-Identifier: MIT */
/*
 * wri_monmap.c - decoder of the MonMap blob carried by MMonMap (docs/spec/mon-client.md 2.4).
 *
 * Only what a v2-only client needs is read: fsid, epoch, the monitor names with their address
 * vectors (field "mon_info") and the rank order (field "ranks"). Everything before that is
 * stepped over by its own length, everything after it (min_mon_release, strategy, stretch mode,
 * auth cipher fields, whatever a newer release appends) is dropped with the envelope.
 *
 * The map stores monitors sorted by name; the ranks vector gives the rank order. The decoder
 * therefore remembers where mon_info starts, reads the ranks, and looks every rank's name up in a
 * second walk over mon_info. That costs a few extra name compares and needs no temporary table,
 * so the stack stays small and the work is bounded by (ranks kept) x (mon_info entries).
 */
#include "wri_mon.h"

#include "wri_denc.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define MONMAP_COUNT_MAX 64u /* entries accepted in mon_info and in ranks on the wire */
#define MONMAP_NAME_MAX 255u /* longest monitor name read */

/* The envelope helper reports a too-new struct_compat as WR_E_UNSUPPORTED; here it is a map version problem. */
static wr_status map_status(wr_status st)
{
	return st == WR_E_UNSUPPORTED ? WR_E_MON_MAP_VERSION : st;
}

/*
 * Read one mon_info_t body: the name again, then the address vector. Sets *valid and *out when the
 * monitor has an address of type msgr2 with a usable family and a non-zero port. A vector that cannot be used at all
 * (legacy sockaddr marker, unknown family) means "no msgr2 address" for this monitor, not a broken
 * map; any other error (truncation, a malformed address) fails the whole decode.
 */
static wr_status pick_addr(wri_rd *body, wri_eaddr *out, uint8_t *valid)
{
	wri_eaddr v[WRI_EADDRVEC_MAX];
	size_t stored = 0, total = 0, i;
	uint32_t name_len = 0;
	wr_status st;

	*valid = 0;
	(void)wri_denc_str(body, &name_len, MONMAP_NAME_MAX);
	if (!wri_rd_ok(body))
		return body->err;
	st = wri_eaddrvec_decode(body, v, WRI_EADDRVEC_MAX, &stored, &total);
	if (st == WR_E_UNSUPPORTED)
		return WR_OK;
	if (st != WR_OK)
		return st;
	for (i = 0; i < stored; i++) {
		/* a msgr2 entry with port 0 cannot be dialled: treated like a blank one */
		if (v[i].type == WRI_EADDR_TYPE_MSGR2 && v[i].family != 0 && v[i].port != 0) {
			*out = v[i];
			*valid = 1;
			break;
		}
	}
	return WR_OK;
}

/* Walk a copy of the mon_info entries for `name`; the first one with that key wins. */
static wr_status find_mon(wri_rd mi, uint32_t n_info, const uint8_t *name, uint32_t name_len, wri_eaddr *addr,
			  uint8_t *valid)
{
	uint32_t k;

	for (k = 0; k < n_info; k++) {
		uint32_t key_len = 0;
		const uint8_t *key = wri_denc_str(&mi, &key_len, MONMAP_NAME_MAX);
		wri_env me;
		wr_status st;

		if (key == NULL)
			return mi.err;
		st = wri_env_open(&mi, 1, &me);
		if (st != WR_OK)
			return map_status(st);
		if (key_len == name_len && wri_ct_memeq(key, name, name_len))
			return pick_addr(&me.body, addr, valid);
	}
	return WR_OK;
}

wr_status wri_monmap_decode(const uint8_t *p, size_t n, wri_monmap *out)
{
	wri_rd r, mi;
	wri_env e;
	uint32_t n_info, n_ranks, i, k;
	wr_status st;
	int any = 0;

	if (out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	if (p == NULL && n != 0)
		return WR_E_INVAL;
	if (n == 0)
		return WR_E_TRUNCATED;
	/* struct_v is the first byte: below 6 the layout lacks "ranks" (or is the legacy 16-bit form). */
	if (p[0] < 6)
		return WR_E_MON_MAP_VERSION;

	wri_rd_init(&r, p, n);
	st = wri_env_open(&r, 10, &e);
	if (st != WR_OK)
		return map_status(st);

	wri_rd_copy(&e.body, out->fsid, sizeof(out->fsid));
	out->epoch = wri_rd_u32(&e.body);
	wri_rd_skip(&e.body, 16); /* last_changed, created: two utime_t */
	for (k = 0; k < 2; k++) { /* persistent_features, optional_features: envelope + u64, skipped whole */
		wri_env f;

		st = wri_env_open(&e.body, 255, &f);
		if (st != WR_OK)
			goto fail;
	}

	/* mon_info: map<string, mon_info_t>, each value an envelope. Skip it, remembering where it starts. */
	n_info = wri_rd_count(&e.body, MONMAP_COUNT_MAX, 4u + 6u);
	mi = e.body;
	for (k = 0; k < n_info && wri_rd_ok(&e.body); k++) {
		wri_env me;

		(void)wri_denc_str(&e.body, NULL, MONMAP_NAME_MAX);
		if (!wri_rd_ok(&e.body))
			break;
		st = wri_env_open(&e.body, 1, &me);
		if (st != WR_OK)
			goto fail;
	}

	/* ranks: vector<string>, names in rank order; the first WRI_MON_MAXMONS are kept. */
	n_ranks = wri_rd_count(&e.body, MONMAP_COUNT_MAX, 4);
	for (i = 0; i < n_ranks && wri_rd_ok(&e.body); i++) {
		uint32_t name_len = 0;
		const uint8_t *name = wri_denc_str(&e.body, &name_len, MONMAP_NAME_MAX);

		if (name == NULL)
			break;
		if (i < WRI_MON_MAXMONS) {
			st = find_mon(mi, n_info, name, name_len, &out->addr[i], &out->rank_valid[i]);
			if (st != WR_OK)
				goto fail;
			out->n_mons = i + 1u;
		}
	}
	if (!wri_rd_ok(&e.body)) {
		st = e.body.err;
		goto fail;
	}
	for (i = 0; i < out->n_mons; i++)
		any |= out->rank_valid[i];
	if (!any) {
		st = WR_E_MON_NO_V2_ADDR;
		goto fail;
	}
	return WR_OK;

fail:
	if (st == WR_OK)
		st = e.body.err != WR_OK ? e.body.err : WR_E_ENCODING;
	st = map_status(st);
	WR_MEMSET(out, 0, sizeof(*out));
	return st;
}
