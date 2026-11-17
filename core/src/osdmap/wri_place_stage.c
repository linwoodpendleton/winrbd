/* SPDX-License-Identifier: MIT */
/*
 * wri_place_stage.c - the stages of placement that run after CRUSH: dropping OSDs that do not exist, the three
 * upmap tables, the up set, primary affinity and the temp overrides (docs/design/core-architecture.md 16.4,
 * crush note 3.7, osdmap.md 3.7).
 *
 * Every stage is a small function on a plain list of OSD ids that the caller owns; none allocates, none keeps
 * state, and every id that comes out of a map table is bound-checked against max_osd (CRUSH_ITEM_NONE is far above
 * any max_osd, so "a valid id" is simply 0 <= id < max_osd). The order of the stages is wri_place_pg's business
 * (wri_place.c); each stage can be called alone, which is how the tests pin its edge cases.
 *
 * Lists that come from a map table are cut at WRI_PLACE_LIST_MAX members (the table builder already caps a vector
 * at WRI_MAP_PGVEC_MAX); the caller's buffers hold that many.
 */
#include "wri_place.h"

WR_FILE_LICENCE_MIT

/* A real OSD id of this map (not NONE, not negative, below max_osd). */
static int valid_id(const wri_osdmap *m, int32_t id)
{
	return id >= 0 && (uint32_t)id < m->max_osd;
}

/* A valid id whose reweight is 0: the monitor never maps onto it, and an upmap that names one is ignored. */
static int valid_out_id(const wri_osdmap *m, int32_t id)
{
	return valid_id(m, id) && wri_osd_weight(m, id) == 0u;
}

uint32_t wri_place_drop_nonexistent(const wri_osdmap *m, int32_t *v, uint32_t n)
{
	uint32_t i, k = 0;

	for (i = 0; i < n; i++)
		if (wri_osd_exists(m, v[i]))
			v[k++] = v[i];
	return k;
}

void wri_place_upmap(const wri_osdmap *m, uint64_t pgkey, int32_t *v, uint32_t *n)
{
	const int32_t *vals = NULL;
	uint32_t nv = 0, i, j;

	if (*n > WRI_PLACE_LIST_MAX)
		*n = WRI_PLACE_LIST_MAX; /* the caller's buffer holds no more; never index past it */

	/* pg_upmap: a member that is an OSD with weight 0 abandons the whole upmap step (items and primary included);
	 * otherwise the list replaces the raw one whatever its length. */
	if (wri_pgtab_find(m, WRI_TAB_PG_UPMAP, pgkey, &vals, &nv)) {
		for (i = 0; i < nv; i++)
			if (valid_out_id(m, vals[i]))
				return;
		if (nv > WRI_PLACE_LIST_MAX)
			nv = WRI_PLACE_LIST_MAX;
		for (i = 0; i < nv; i++)
			v[i] = vals[i];
		*n = nv;
	}

	/* pg_upmap_items: (from, to) pairs, one after the other on the list as the previous pair left it. */
	if (wri_pgtab_find(m, WRI_TAB_PG_UPMAP_ITEMS, pgkey, &vals, &nv)) {
		for (i = 0; i + 1u < nv; i += 2u) {
			int32_t from = vals[i], to = vals[i + 1u];
			int has_to = 0;
			uint32_t pos = *n;

			for (j = 0; j < *n; j++) {
				if (v[j] == to) {
					has_to = 1;
					break;
				}
			}
			if (has_to || valid_out_id(m, to))
				continue;
			for (j = 0; j < *n; j++) {
				if (v[j] == from) {
					pos = j;
					break;
				}
			}
			if (pos < *n)
				v[pos] = to;
		}
	}

	/* pg_upmap_primaries: an OSD with a non-zero weight that sits behind the first place is swapped to the front. */
	if (wri_pgtab_find(m, WRI_TAB_PG_UPMAP_PRIMARY, pgkey, &vals, &nv) && nv >= 1u) {
		int32_t p = vals[0];

		if (valid_id(m, p) && wri_osd_weight(m, p) != 0u) {
			for (j = 1; j < *n; j++) {
				if (v[j] == p) {
					v[j] = v[0];
					v[0] = p;
					break;
				}
			}
		}
	}
}

uint32_t wri_place_up_set(const wri_osdmap *m, const int32_t *raw, uint32_t n, int32_t *up, int32_t *primary)
{
	uint32_t i, k = 0;

	for (i = 0; i < n; i++) { /* k <= i, so up may be the same array as raw */
		int32_t id = raw[i];

		if (wri_osd_up(m, id))
			up[k++] = id;
	}
	if (primary != NULL)
		*primary = k != 0 ? up[0] : -1;
	return k;
}

void wri_place_affinity(const wri_osdmap *m, uint32_t pps, int32_t *up, uint32_t n, int32_t *primary)
{
	uint32_t i, pos = n, fallback = n, j;
	int32_t pri;
	int any = 0;

	if (wri_map_aff(m) == NULL || n == 0u)
		return;
	for (i = 0; i < n; i++) {
		if (wri_osd_aff(m, up[i]) != (uint32_t)WRI_OSD_IN_FULL) {
			any = 1;
			break;
		}
	}
	if (!any)
		return;
	/* Reject a member as primary when its affinity is below 1.0 and a hash of (seed, osd) lands at or above it:
	 * the chance of acceptance is the affinity. The first accepted member wins, else the first rejected one. */
	for (i = 0; i < n; i++) {
		uint32_t a = wri_osd_aff(m, up[i]);

		if (a < (uint32_t)WRI_OSD_IN_FULL && (wri_crush_hash2(pps, (uint32_t)up[i]) >> 16) >= a) {
			if (fallback == n)
				fallback = i;
		} else {
			pos = i;
			break;
		}
	}
	if (pos == n)
		pos = fallback;
	if (pos == n)
		return; /* not reachable with n > 0: every member is either accepted or the fallback */
	pri = up[pos];
	for (j = pos; j > 0; j--)
		up[j] = up[j - 1u];
	up[0] = pri;
	if (primary != NULL)
		*primary = pri;
}

void wri_place_temp(const wri_osdmap *m, uint64_t pgkey, int32_t *temp, uint32_t *n, int32_t *temp_primary)
{
	const int32_t *vals = NULL;
	uint32_t nv = 0, i, k = 0;

	if (wri_pgtab_find(m, WRI_TAB_PG_TEMP, pgkey, &vals, &nv)) {
		for (i = 0; i < nv && k < WRI_PLACE_LIST_MAX; i++)
			if (wri_osd_up(m, vals[i]))
				temp[k++] = vals[i];
	}
	*n = k;
	*temp_primary = -1;
	/* primary_temp is taken as stored (no validity check, a stored -1 stays -1); else the first temp member. */
	if (wri_pgtab_find(m, WRI_TAB_PRIMARY_TEMP, pgkey, &vals, &nv) && nv >= 1u)
		*temp_primary = vals[0];
	else if (k != 0)
		*temp_primary = temp[0];
}
