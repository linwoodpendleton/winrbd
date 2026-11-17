/* SPDX-License-Identifier: MIT */
/*
 * wri_osdmap_inc.c - apply one OSDMap::Incremental to a held map and build the next epoch into another slot
 * (docs/spec/osdmap.md 2.6, 3.4 to 3.6; architecture 15.4). The pools and the rule audit are in wri_osdmap_inc2.c, the per-OSD arrays and the
 * pg tables in wri_osdmap_inc3.c; wri_osdmap_inc.h is their shared private header.
 *
 * The build is a fixed sequence, every step of which can fail without having touched anything but the new slot:
 *   1. the three envelopes (wrapper, client block, OSD-only block) and the CRC fields are located; the CRC is checked when
 *      the configuration asks for it, before a row is interpreted;
 *   2. rows 1 to 8 are read: the fsid and epoch checks of osdmap.md 3.5 steps 1 and 2; a non-empty `fullmap` row is decoded
 *      as a full map and that is all (step 4), nothing else of the incremental is looked at;
 *   3. the INDEX walk steps over rows 9 to 29 once, checks every count against the bytes left and the OSD ids against the new
 *      max_osd, and notes where each row starts;
 *   4. the tracked pools are re-resolved (names, records, removals), and a counting merge of each pg table learns how big the
 *      new tables are;
 *   5. the slot is carved exactly, the CRUSH region last; the per-OSD arrays are built (common prefix copied, then weights,
 *      affinity, state XOR, new up OSDs in the order of osdmap.md 3.5), the pool records, the tables (the same merge, filling)
 *      and the CRUSH region (decoded, or the held one copied) are written;
 *   6. the rule audit sets the status of every present tracked pool, and the builder finishes the header (the magic is set
 *      last, so a slot that failed half way is never a map).
 * The held map is only read.
 */
#include "wri_osdmap_inc.h"
#include "wri_crc32c.h"
#include "wri_ctx.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define CRC_SEED 0xFFFFFFFFu /* osdmap.md 2.4.5: the raw register, start all ones, no final inversion */
#define OSD_BLOCK_COMPAT_ANY 0xFFu
#define INC_BYTES_MAX 0x7fffffffu /* row offsets are u32 */

/* ---- failures ----------------------------------------------------------------------------------------- */

static wr_status fail_at(wr_errinfo *why, wr_status st, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	WRI_ERRINFO(why, st, WR_MOD_MAP, what, a0, a1, a2);
	return st;
}

static wr_status env_status(wr_status st)
{
	return st == WR_E_UNSUPPORTED ? WR_E_MAP_VERSION : wri_full_status(st);
}

static wr_status fail_row(const wri_inc_ix *ix, const wri_rd *r, unsigned row, const char *what)
{
	wr_status st = wri_full_status(r->err);

	WRI_ERRINFO(ix->why, st, WR_MOD_MAP, what, wri_inc_off(ix, r), row, (uint64_t)(int64_t)r->err);
	return st;
}

/* ---- the envelopes ------------------------------------------------------------------------------------- */

/* The wrapper and the client block: legacy envelope with the thresholds (7, 7), compat at most 8, then the client block with the floors
 * of osdmap.md 4.1. `we` is left with its body positioned after the client block; `ce` is the client block. */
static wr_status open_wrapper(const uint8_t *p, size_t n, wri_env *we, wri_env *ce, wr_errinfo *why)
{
	wri_rd r;
	uint64_t v0 = n >= 1u ? p[0] : 0u, c0 = n >= 2u ? p[1] : 0u;
	wr_status st;

	wri_rd_init(&r, p, n);
	st = wri_env_open_legacy(&r, WRI_MAP_WRAPPER_MIN_V, 7u, 7u, WRI_MAP_WRAPPER_MAX_COMPAT, we);
	if (st != WR_OK)
		return fail_at(why, env_status(st),
			       st == WR_E_MAP_VERSION ? "incremental wrapper version or struct_compat not supported" : "incremental wrapper cut short",
			       0, v0, c0);
	st = wri_env_open(&we->body, (uint8_t)WRI_MAP_INC_BLOCK_MAX_COMPAT, ce);
	if (st != WR_OK)
		return fail_at(why, env_status(st),
			       st == WR_E_UNSUPPORTED ? "incremental client block struct_compat not supported" : "incremental client block cut short",
			       we->body.pos, ce->v, ce->compat);
	if (ce->v < WRI_MAP_INC_BLOCK_MIN_V)
		return fail_at(why, WR_E_MAP_VERSION, "incremental client block older than the supported floor", we->body.pos, ce->v,
			       WRI_MAP_INC_BLOCK_MIN_V);
	if (wri_rd_left(&r) != 0)
		return fail_at(why, WR_E_MAP_CORRUPT, "bytes after the incremental wrapper", n - wri_rd_left(&r), wri_rd_left(&r), 0);
	return WR_OK;
}

/* Step over the OSD-only block, read inc_crc and full_crc (wrapper v8 and up) and check inc_crc when the configuration asks for it:
 * the wrapper up to the field, then everything after it (osdmap.md 2.6.1). */
static wr_status check_crc(const wri_mapcfg *cfg, const uint8_t *p, size_t n, wri_env *we, wr_errinfo *why)
{
	wri_env oe;
	uint32_t stored = 0;
	size_t crc_pos = 0;
	wr_status st = wri_env_open(&we->body, OSD_BLOCK_COMPAT_ANY, &oe); /* only its length matters: whatever its version, it is jumped over */

	if (st != WR_OK)
		return fail_at(why, wri_full_status(st), "incremental OSD-only block cut short", we->body.pos, oe.v, oe.compat);
	if (we->v < 8u)
		return WR_OK;
	crc_pos = (size_t)(we->body.p - p) + we->body.pos;
	stored = wri_rd_u32(&we->body);
	(void)wri_rd_u32(&we->body); /* full_crc: checking it needs a byte-exact re-encode of the whole map (osdmap.md Q4) */
	if (!wri_rd_ok(&we->body))
		return fail_at(why, WR_E_MAP_CORRUPT, "incremental CRC fields missing", crc_pos, 0, 0);
	if (cfg->verify_crc != 0) {
		uint32_t crc = wri_crc32c(CRC_SEED, p, crc_pos);

		crc = wri_crc32c(crc, p + crc_pos + 4u, n - crc_pos - 4u);
		if (crc != stored)
			return fail_at(why, WR_E_MAP_CRC, "incremental CRC does not match", crc_pos, stored, crc);
	}
	return WR_OK;
}

/* Steps 1 and 2: the envelopes and the CRC fields, the CRC when asked; then the index is started. */
static wr_status open_front(const wri_mapcfg *cfg, const uint8_t *p, size_t n, wri_inc_ix *ix, wr_errinfo *why)
{
	wri_env we, ce;
	wr_status st = open_wrapper(p, n, &we, &ce, why);

	if (st == WR_OK)
		st = check_crc(cfg, p, n, &we, why);
	if (st != WR_OK)
		return st;
	WR_MEMSET(ix, 0, sizeof(*ix));
	ix->base = p;
	ix->body = ce.body;
	ix->why = why;
	ix->block_v = ce.v;
	ix->n_rows = ce.v >= 9u ? WRI_INC_ROWS_V9 : WRI_INC_ROWS_V8;
	ix->new_pool_max = -1;
	ix->new_flags = -1;
	ix->new_max_osd = -1;
	ix->max_osd_limit = cfg->max_osd < WRI_MAP_OSD_HARD_MAX ? cfg->max_osd : WRI_MAP_OSD_HARD_MAX;
	return WR_OK;
}

/* ---- the index walk ------------------------------------------------------------------------------------ */

static void skip_snap_sets(wri_rd *r) /* map<s64, interval_set<snapid>> */
{
	uint32_t n = wri_denc_count(r, 0xFFFFFFFFu, 8u + 4u);
	uint32_t i;

	for (i = 0; i < n && wri_rd_ok(r); i++) {
		wri_rd_skip(r, 8u);
		wri_denc_skip_interval_set(r);
	}
}

/* A map<s32 osd, ...> whose values take `vsize` bytes (or an address vector when vsize is 0): the ids must fit the new max_osd. */
static wr_status osd_map(wri_inc_ix *ix, wri_rd *r, unsigned row, size_t vsize, const char *what)
{
	uint32_t n = wri_rd_count(r, 0xFFFFFFFFu, vsize != 0 ? 4u + vsize : 4u + 5u);
	uint32_t i;

	for (i = 0; i < n && wri_rd_ok(r); i++) {
		int32_t id = wri_rd_i32(r);

		if (!wri_rd_ok(r))
			break;
		if (id < 0 || (uint32_t)id >= ix->max_osd)
			return fail_at(ix->why, WR_E_MAP_CORRUPT, "an OSD id of the incremental is outside max_osd", wri_inc_off(ix, r), (uint64_t)(int64_t)id,
				       ix->max_osd);
		if (vsize != 0) {
			wri_rd_skip(r, vsize);
		} else {
			wri_osd_addr scratch;
			wr_status st = wri_osdmap_read_addr(r, &scratch);

			if (st != WR_OK)
				return fail_at(ix->why, st == WR_E_MAP_VERSION ? WR_E_MAP_VERSION : WR_E_MAP_CORRUPT,
					       st == WR_E_MAP_VERSION ? "OSD address in a form this client does not read" : "OSD address vector is malformed",
					       wri_inc_off(ix, r), i, n);
		}
	}
	if (!wri_rd_ok(r))
		return fail_row(ix, r, row, what);
	if (row == WRI_INC_R_AFFINITY)
		ix->n_aff = n;
	return WR_OK;
}

/* Step over one row and learn what the walk needs from it. */
static wr_status skip_row(wri_inc_ix *ix, wri_rd *r, unsigned row)
{
	wr_status st = WR_OK;
	uint32_t n, i, len;

	switch (row) {
	case 1: /* fsid */
		wri_rd_copy(r, ix->fsid, sizeof(ix->fsid));
		break;
	case 2: /* epoch */
		ix->epoch = wri_rd_u32(r);
		break;
	case 3: /* modified */
		wri_rd_skip(r, 8u);
		break;
	case 4: /* new_pool_max */
		ix->new_pool_max = wri_rd_i64(r);
		break;
	case 5: /* new_flags */
		ix->new_flags = wri_rd_i32(r);
		break;
	case 6: /* fullmap, a blob */
	case 7: /* crush, a blob */
		len = wri_rd_u32(r);
		if (wri_rd_ok(r)) {
			uint32_t pos = (uint32_t)r->pos;

			(void)wri_rd_bytes(r, len);
			if (wri_rd_ok(r) && row == 6u) {
				ix->full_pos = pos;
				ix->full_len = len;
			} else if (wri_rd_ok(r)) {
				ix->crush_pos = pos;
				ix->crush_len = len;
			}
		}
		break;
	case 8: /* new_max_osd */
		ix->new_max_osd = wri_rd_i32(r);
		if (wri_rd_ok(r) && ix->new_max_osd >= 0) {
			if ((uint32_t)ix->new_max_osd > ix->max_osd_limit)
				return fail_at(ix->why, WR_E_MAP_BUDGET, "new_max_osd above the configured limit", (uint64_t)(int64_t)ix->new_max_osd,
					       ix->max_osd_limit, 0);
			ix->max_osd = (uint32_t)ix->new_max_osd;
		}
		break;
	case WRI_INC_R_NEW_POOLS:
		return wri_inc_skip_pools(ix, r);
	case WRI_INC_R_POOL_NAMES:
		return wri_inc_skip_names(ix, r);
	case WRI_INC_R_OLD_POOLS:
		return wri_inc_skip_idset(ix, r);
	case WRI_INC_R_UP:
		return osd_map(ix, r, row, 0u, "new_up_client is malformed");
	case WRI_INC_R_STATE:
		return osd_map(ix, r, row, 4u, "new_state is malformed");
	case WRI_INC_R_WEIGHT:
		return osd_map(ix, r, row, 4u, "new_weight is malformed");
	case WRI_INC_R_AFFINITY:
		return osd_map(ix, r, row, 4u, "new_primary_affinity is malformed");
	case WRI_INC_R_PG_TEMP:
		return wri_inc_skip_pgmap(ix, r, WRI_INC_PGMAP_VEC, "new_pg_temp is malformed");
	case WRI_INC_R_PRIMARY_TEMP:
		return wri_inc_skip_pgmap(ix, r, WRI_INC_PGMAP_ONE, "new_primary_temp is malformed");
	case 18: /* new_erasure_code_profiles */
		wri_denc_skip_str_map_map(r);
		break;
	case 19: /* old_erasure_code_profiles: vector<string> */
		n = wri_rd_count(r, 0xFFFFFFFFu, 4u);
		for (i = 0; i < n && wri_rd_ok(r); i++)
			wri_denc_skip_str(r);
		break;
	case WRI_INC_R_NEW_UPMAP:
		return wri_inc_skip_pgmap(ix, r, WRI_INC_PGMAP_VEC, "new_pg_upmap is malformed");
	case WRI_INC_R_OLD_UPMAP:
		return wri_inc_skip_pgset(ix, r, "old_pg_upmap is malformed");
	case WRI_INC_R_NEW_ITEMS:
		return wri_inc_skip_pgmap(ix, r, WRI_INC_PGMAP_PAIRS, "new_pg_upmap_items is malformed");
	case WRI_INC_R_OLD_ITEMS:
		return wri_inc_skip_pgset(ix, r, "old_pg_upmap_items is malformed");
	case 24: /* new_removed_snaps */
	case 25: /* new_purged_snaps */
		skip_snap_sets(r);
		break;
	case 26: /* new_last_up_change */
	case 27: /* new_last_in_change */
		wri_rd_skip(r, 8u);
		break;
	case WRI_INC_R_NEW_UPMAP_PRIMARY:
		return wri_inc_skip_pgmap(ix, r, WRI_INC_PGMAP_ONE, "new_pg_upmap_primary is malformed");
	default: /* 29 old_pg_upmap_primary */
		return wri_inc_skip_pgset(ix, r, "old_pg_upmap_primary is malformed");
	}
	if (!wri_rd_ok(r))
		return fail_row(ix, r, row, "an incremental row is malformed or cut short");
	return st;
}

/* Rows first..last of the client block, recording where each starts; `r` carries on from where the last call stopped. */
static wr_status walk_rows(wri_inc_ix *ix, wri_rd *r, unsigned first, unsigned last)
{
	unsigned row;

	for (row = first; row <= last; row++) {
		wr_status st;

		ix->off[row] = (uint32_t)r->pos;
		st = skip_row(ix, r, row);
		if (st != WR_OK)
			return st;
	}
	ix->off[last + 1u] = (uint32_t)r->pos;
	return WR_OK;
}

/* ---- CRUSH --------------------------------------------------------------------------------------------- */

static wr_status build_crush(const wri_inc_ix *ix, const wri_osdmap *src, wri_mapbuild *b, wr_errinfo *why)
{
	const wri_crush *c = wri_map_crush(src);
	uint8_t *room;

	if (ix->crush_len != 0) { /* a complete new CRUSH map: decoded into whatever is left of the slot */
		size_t left = wri_mapbuild_crush_left(b), used = 0;
		wr_status st;

		if (left == 0)
			return fail_at(why, WR_E_MAP_BUDGET, "map slot too small for the CRUSH region", 0, 0, b->cap);
		room = wri_mapbuild_crush_room(b, left);
		if (room == NULL)
			return WR_E_MAP_BUDGET;
		st = wri_crush_decode(ix->body.p + ix->crush_pos, ix->crush_len, room, left, &used, why);
		return st == WR_OK ? WR_OK : wri_full_status(st);
	}
	if (c == NULL)
		return fail_at(why, WR_E_MAP_CORRUPT, "the held map has no CRUSH map", 0, 0, 0);
	room = wri_mapbuild_crush_room(b, c->bytes); /* no change: the held region, which is position independent */
	if (room == NULL)
		return WR_E_MAP_BUDGET;
	WR_MEMCPY(room, c, c->bytes);
	return WR_OK;
}

/* ---- the build ----------------------------------------------------------------------------------------- */

static int overlaps(const void *a, size_t an, const void *b, size_t bn)
{
	uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;

	return x < y + bn && y < x + an;
}

/* Step 2 for a full map embedded in the incremental: decode it into the slot and check it is the map this incremental names. The decoder
 * reports in a local errinfo: on success it may hold a note (a pool this client cannot use), which must not hide a failure found here. */
static wr_status embedded_full(const wri_mapcfg *cfg, const wri_osdmap *src, const wri_inc_ix *ix, uint8_t *slot, size_t cap, wr_errinfo *why)
{
	wr_errinfo local;
	wr_status st, bad = WR_OK;
	const wri_osdmap *m;

	WR_MEMSET(&local, 0, sizeof(local));
	st = wri_osdmap_decode_full(cfg, ix->body.p + ix->full_pos, ix->full_len, slot, cap, &local);
	if (st != WR_OK) {
		if (why != NULL && why->status == WR_OK)
			*why = local;
		return st;
	}
	m = (const wri_osdmap *)(const void *)slot;
	if (!wri_ct_memeq(m->fsid, src->fsid, sizeof(m->fsid)))
		bad = fail_at(why, WR_E_MAP_FSID, "the embedded full map belongs to another cluster", 0, 0, 0);
	else if (m->epoch != ix->epoch)
		bad = fail_at(why, WR_E_MAP_EPOCH, "the embedded full map is not the epoch of its incremental", m->epoch, ix->epoch, 0);
	if (bad != WR_OK)
		WR_MEMSET(slot, 0, 4u); /* not a map after all */
	else if (why != NULL && why->status == WR_OK && local.status != WR_OK)
		*why = local; /* the note of the decoder: the first pool this client cannot use */
	return bad;
}

/* Steps 3 to 6 on a slot whose builder is open and a validated index: sizes, carve, fill. */
static wr_status build(const wri_mapcfg *cfg, const wri_osdmap *src, wri_inc_ix *ix, const wri_inc_pools *pp, wri_mapbuild *b, wr_errinfo *why)
{
	uint32_t tn[WRI_TAB_COUNT], tnv[WRI_TAB_COUNT], k;
	wr_errinfo note;
	wr_status st = WR_OK;
	int has_aff = src->aff_off != 0 || ix->n_aff != 0;

	WR_MEMSET(&note, 0, sizeof(note));
	for (k = 0; k < WRI_TAB_COUNT && st == WR_OK; k++) /* the counting merge */
		st = wri_inc_merge_tab(ix, pp, src, k, NULL, &tn[k], &tnv[k]);
	if (st != WR_OK)
		return st;

	st = wri_mapbuild_osds(b, ix->max_osd, has_aff); /* carve in the layout order, the CRUSH room last */
	if (st == WR_OK)
		st = wri_mapbuild_pools(b, cfg->n_pools);
	for (k = 0; st == WR_OK && k < WRI_TAB_COUNT; k++)
		st = wri_mapbuild_tab(b, k, tn[k], tnv[k]);
	if (st == WR_OK)
		st = build_crush(ix, src, b, why); /* decode or copy the CRUSH region into the room that ends the slot */
	if (st != WR_OK)
		return st;

	b->m->epoch = ix->epoch; /* step 3 */
	WR_MEMCPY(b->m->fsid, src->fsid, sizeof(b->m->fsid));
	b->m->flags = ix->new_flags >= 0 ? (uint32_t)ix->new_flags : src->flags; /* step 5 */
	st = wri_inc_apply_osds(ix, b, src);
	if (st == WR_OK)
		st = wri_inc_fill_pools(ix, pp, src, b, &note);
	for (k = 0; k < WRI_TAB_COUNT && st == WR_OK; k++)
		st = wri_inc_merge_tab(ix, pp, src, k, b, NULL, NULL);
	if (st != WR_OK)
		return st;

	wri_inc_audit_pools(b, &note);
	wri_mapbuild_finish(b);
	if (why != NULL && why->status == WR_OK && note.status != WR_OK)
		*why = note;
	return WR_OK;
}

/* The arguments and the held map: what can be wrong before a byte of the incremental is read. */
static wr_status check_args(const wri_mapcfg *cfg, const wri_osdmap *src, const uint8_t *p, size_t n, uint8_t *slot, size_t cap, wr_errinfo *why)
{
	if (cfg == NULL || src == NULL || (p == NULL && n != 0))
		return WR_E_INVAL;
	if (slot != NULL && overlaps(slot, cap, src, src->cap))
		return fail_at(why, WR_E_INVAL, "the new slot overlaps the held map", 0, 0, 0);
	if (!wri_inc_src_sane(src))
		return fail_at(why, WR_E_INVAL, "the held map is not a finished map", 0, 0, 0);
	if (cfg->n_pools > WRI_MAP_POOLS_MAX)
		return fail_at(why, WR_E_MAP_BUDGET, "more tracked pools than the map can hold", cfg->n_pools, WRI_MAP_POOLS_MAX, 0);
	if (src->n_pools != cfg->n_pools)
		return fail_at(why, WR_E_MAP_RESYNC, "the held map was decoded with another set of tracked pools", src->n_pools, cfg->n_pools, 0);
	if (n > INC_BYTES_MAX)
		return fail_at(why, WR_E_MAP_BUDGET, "incremental larger than 2 GiB", n, INC_BYTES_MAX, 0);
	if (slot != NULL && p != NULL && n != 0 && overlaps(slot, cap, p, n)) /* the build would write over the bytes it is still reading */
		return fail_at(why, WR_E_INVAL, "the new slot overlaps the incremental", 0, 0, 0);
	return WR_OK;
}

/* Steps 1 and 2: the fsid is the held one, the epoch is the next one (unless the incremental carries a complete map). */
static wr_status check_identity(const wri_inc_ix *ix, const wri_osdmap *src, wr_errinfo *why)
{
	if (!wri_ct_memeq(ix->fsid, src->fsid, sizeof(ix->fsid)))
		return fail_at(why, WR_E_MAP_FSID, "incremental belongs to another cluster", 0, 0, 0);
	if (ix->full_len == 0 && (uint64_t)ix->epoch != (uint64_t)src->epoch + 1u)
		return fail_at(why, WR_E_MAP_EPOCH, "incremental does not follow the held epoch", ix->epoch, src->epoch, (uint64_t)src->epoch + 1u);
	return WR_OK;
}

/* Rows 1 to 8 (identity, the embedded map, the sizes), then the identity checks; `r` carries on at row 9. */
static wr_status read_head(const wri_mapcfg *cfg, const wri_osdmap *src, const uint8_t *p, size_t n, wri_inc_ix *ix, wri_rd *r, wr_errinfo *why)
{
	wr_status st = open_front(cfg, p, n, ix, why);

	if (st != WR_OK)
		return st;
	ix->max_osd = src->max_osd;
	*r = ix->body;
	st = walk_rows(ix, r, 1u, WRI_INC_R_MAX_OSD);
	return st == WR_OK ? check_identity(ix, src, why) : st;
}

wr_status wri_osdmap_apply_inc(const wri_mapcfg *cfg, const wri_osdmap *src, const uint8_t *p, size_t n, uint8_t *slot, size_t cap,
			       wr_errinfo *why)
{
	wri_inc_pools pp;
	wri_inc_ix ix;
	wri_mapbuild b;
	wri_rd r;
	wr_status st;

	if (slot != NULL && cap >= 4u && ((uintptr_t)slot & 3u) == 0 && (src == NULL || !overlaps(slot, cap, src, src->cap)) &&
	    (p == NULL || n == 0 || !overlaps(slot, cap, p, n)))
		WR_MEMSET(slot, 0, 4u); /* whatever happens next, the slot is not a map */
	st = check_args(cfg, src, p, n, slot, cap, why);
	if (st != WR_OK)
		return st;
	if (cap > (size_t)cfg->slot_bytes)
		cap = (size_t)cfg->slot_bytes;
	st = read_head(cfg, src, p, n, &ix, &r, why);
	if (st != WR_OK)
		return st;
	if (ix.full_len != 0)
		return embedded_full(cfg, src, &ix, slot, cap, why); /* step 4: nothing else of the incremental is applied */
	st = walk_rows(&ix, &r, WRI_INC_R_NEW_POOLS, ix.n_rows);
	if (st == WR_OK)
		st = wri_inc_resolve_pools(cfg, src, &ix, &pp);
	if (st != WR_OK)
		return st;
	wri_mapbuild_begin(&b, slot, cap, why);
	st = wri_mapbuild_status(&b);
	return st == WR_OK ? build(cfg, src, &ix, &pp, &b, why) : st;
}
