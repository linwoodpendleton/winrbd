/* SPDX-License-Identifier: MIT */
/*
 * wri_osdmap_inc2.c - the pool side of applying an OSDMap::Incremental (docs/spec/osdmap.md 3.5 steps 8 to 10, architecture 15.4):
 *
 *   - walkers that step over the pool-keyed containers of the client block (new_pools, new_pool_names, old_pools) and check that their keys
 *     ascend;
 *   - the tracked pools of the new map: which pool a tracked name belongs to after new_pool_names, new_pools and old_pools, and where each
 *     pool's record comes from;
 *   - the pool records of the new slot, and the rule audit that decides the status of every present tracked pool.
 * The per-OSD arrays and the pg tables are in wri_osdmap_inc3.c, the entry point and the envelope in wri_osdmap_inc.c.
 */
#include "wri_osdmap_inc.h"
#include "wri_ctx.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define PG_ENTRY_MIN 21u /* pg_t (17 bytes) + a u32 count or an s32 */
#define PG_KEY_MIN 17u

/* ---- walkers (the index walk) -------------------------------------------------------------------------- */

/* pg_t order is (pool, seed); a key that does not rise strictly is damage. */
static int pg_after(const wri_pg *pg, int have_prev, const wri_pg *prev)
{
	return !have_prev || pg->pool > prev->pool || (pg->pool == prev->pool && pg->seed > prev->seed);
}

wr_status wri_inc_skip_pgmap(const wri_inc_ix *ix, wri_rd *r, unsigned style, const char *what)
{
	uint32_t n, i, cnt;
	wri_pg pg, prev;
	int have_prev = 0;

	prev.pool = 0;
	prev.seed = 0;
	n = wri_rd_count(r, 0xFFFFFFFFu, PG_ENTRY_MIN);
	for (i = 0; i < n && wri_rd_ok(r); i++) {
		if (wri_denc_pg(r, &pg) != WR_OK)
			break;
		if (!pg_after(&pg, have_prev, &prev))
			return wri_inc_fail_val(ix, r, WR_E_MAP_CORRUPT, "pg keys are not strictly ascending", pg.pool, pg.seed);
		prev = pg;
		have_prev = 1;
		if (style == WRI_INC_PGMAP_ONE) {
			wri_rd_skip(r, 4u);
		} else {
			size_t elem = style == WRI_INC_PGMAP_PAIRS ? 8u : 4u;

			cnt = wri_rd_count(r, 0xFFFFFFFFu, elem);
			if (wri_rd_ok(r))
				wri_rd_skip(r, (size_t)cnt * elem); /* wri_rd_count checked cnt * elem against the bytes left */
		}
	}
	if (!wri_rd_ok(r))
		return wri_inc_fail_rd(ix, r, what);
	return WR_OK;
}

wr_status wri_inc_skip_pgset(const wri_inc_ix *ix, wri_rd *r, const char *what)
{
	uint32_t n, i;
	wri_pg pg, prev;
	int have_prev = 0;

	prev.pool = 0;
	prev.seed = 0;
	n = wri_rd_count(r, 0xFFFFFFFFu, PG_KEY_MIN);
	for (i = 0; i < n && wri_rd_ok(r); i++) {
		if (wri_denc_pg(r, &pg) != WR_OK)
			break;
		if (!pg_after(&pg, have_prev, &prev))
			return wri_inc_fail_val(ix, r, WR_E_MAP_CORRUPT, "pg keys are not strictly ascending", pg.pool, pg.seed);
		prev = pg;
		have_prev = 1;
	}
	if (!wri_rd_ok(r))
		return wri_inc_fail_rd(ix, r, what);
	return WR_OK;
}

wr_status wri_inc_skip_pools(const wri_inc_ix *ix, wri_rd *r)
{
	uint32_t n, i;
	int64_t prev = 0;

	n = wri_rd_count(r, 0xFFFFFFFFu, 8u + 6u); /* s64 key + the envelope header of a pg_pool_t */
	for (i = 0; i < n && wri_rd_ok(r); i++) {
		int64_t id = wri_rd_i64(r);
		wr_status st;

		if (!wri_rd_ok(r))
			break;
		if (i > 0 && id <= prev)
			return wri_inc_fail_val(ix, r, WR_E_MAP_CORRUPT, "new_pools ids are not strictly ascending", (uint64_t)id, (uint64_t)prev);
		prev = id;
		st = wri_pool_skip(r, NULL);
		if (st != WR_OK)
			return wri_inc_fail_val(ix, r, wri_full_status(st),
					st == WR_E_MAP_VERSION ? "pg_pool_t older than struct_v 5 cannot be stepped over" : "pg_pool_t cut short",
					(uint64_t)id, 0);
	}
	if (!wri_rd_ok(r))
		return wri_inc_fail_rd(ix, r, "new_pools is malformed");
	return WR_OK;
}

wr_status wri_inc_skip_names(const wri_inc_ix *ix, wri_rd *r)
{
	uint32_t n, i;
	int64_t prev = 0;

	n = wri_rd_count(r, 0xFFFFFFFFu, 8u + 4u); /* s64 key + string length */
	for (i = 0; i < n && wri_rd_ok(r); i++) {
		int64_t id = wri_rd_i64(r);
		uint32_t len = wri_rd_u32(r);

		(void)wri_rd_bytes(r, len);
		if (!wri_rd_ok(r))
			break;
		if (i > 0 && id <= prev)
			return wri_inc_fail_val(ix, r, WR_E_MAP_CORRUPT, "new_pool_names ids are not strictly ascending", (uint64_t)id, (uint64_t)prev);
		prev = id;
	}
	if (!wri_rd_ok(r))
		return wri_inc_fail_rd(ix, r, "new_pool_names is malformed");
	return WR_OK;
}

wr_status wri_inc_skip_idset(const wri_inc_ix *ix, wri_rd *r)
{
	uint32_t n, i;
	int64_t prev = 0;

	n = wri_rd_count(r, 0xFFFFFFFFu, 8u);
	for (i = 0; i < n && wri_rd_ok(r); i++) {
		int64_t id = wri_rd_i64(r);

		if (!wri_rd_ok(r))
			break;
		if (i > 0 && id <= prev)
			return wri_inc_fail_val(ix, r, WR_E_MAP_CORRUPT, "old_pools ids are not strictly ascending", (uint64_t)id, (uint64_t)prev);
		prev = id;
	}
	if (!wri_rd_ok(r))
		return wri_inc_fail_rd(ix, r, "old_pools is malformed");
	return WR_OK;
}

/* ---- the tracked pools --------------------------------------------------------------------------------- */

static int name_is(const wri_mapcfg *cfg, uint32_t k, const uint8_t *name, uint32_t len)
{
	return cfg->name_len[k] != 0 && cfg->name_len[k] <= WRI_MAP_NAME_MAX && len == cfg->name_len[k] && wri_ct_memeq(cfg->name[k], name, len);
}

/* The slot of the held map that holds pool `id`, or -1. */
static int held_slot(const wri_map_pool *hp, uint32_t n, int64_t id)
{
	uint32_t j;

	for (j = 0; j < n; j++)
		if (hp[j].present != 0 && hp[j].id == id)
			return (int)j;
	return -1;
}

/* One entry of new_pool_names (id, name) against every tracked slot. */
static wr_status name_entry(const wri_mapcfg *cfg, const wri_map_pool *hp, const wri_inc_ix *ix, wri_inc_pools *pp, int64_t id,
			    const uint8_t *name, uint32_t len)
{
	uint32_t k;

	for (k = 0; k < pp->n; k++) {
		if (name_is(cfg, k, name, len)) {
			if (pp->matched[k] != 0) {
				WRI_ERRINFO(ix->why, WR_E_MAP_CORRUPT, WR_MOD_MAP, "a tracked pool name belongs to two pool ids", id, pp->mid[k], k);
				return WR_E_MAP_CORRUPT;
			}
			pp->matched[k] = 1;
			pp->mid[k] = id;
		} else if (hp != NULL && hp[k].present != 0 && hp[k].id == id) {
			pp->away[k] = 1; /* the pool we held under this id has another name now */
		}
	}
	return WR_OK;
}

/* Scan new_pool_names: a tracked name may now belong to another id, and an id may now carry another name. */
static wr_status scan_names(const wri_mapcfg *cfg, const wri_map_pool *hp, const wri_inc_ix *ix, wri_inc_pools *pp)
{
	uint32_t i, cnt;
	wri_rd r = wri_inc_row(ix, WRI_INC_R_POOL_NAMES);
	wr_status st = WR_OK;

	cnt = wri_rd_count(&r, 0xFFFFFFFFu, 8u + 4u);
	for (i = 0; i < cnt && wri_rd_ok(&r) && st == WR_OK; i++) {
		int64_t id = wri_rd_i64(&r);
		uint32_t len = wri_rd_u32(&r);
		const uint8_t *name = wri_rd_bytes(&r, len);

		if (wri_rd_ok(&r) && name != NULL)
			st = name_entry(cfg, hp, ix, pp, id, name, len);
	}
	if (st != WR_OK)
		return st;
	if (!wri_rd_ok(&r))
		return wri_inc_fail_rd(ix, &r, "new_pool_names is malformed");
	for (i = 0; i < pp->n; i++) {
		if (pp->matched[i] != 0) {
			pp->found[i] = 1;
			pp->id[i] = pp->mid[i];
		} else if (hp != NULL && hp[i].present != 0 && pp->away[i] == 0) {
			pp->found[i] = 1;
			pp->id[i] = hp[i].id;
		}
	}
	return WR_OK;
}

/* Scan new_pools (which tracked ids carry a record in this incremental) and then old_pools (removals last, so a pool in both is removed). */
static wr_status scan_records(const wri_inc_ix *ix, wri_inc_pools *pp)
{
	uint32_t n = pp->n, k, i, cnt;
	wri_rd r = wri_inc_row(ix, WRI_INC_R_NEW_POOLS);

	cnt = wri_rd_count(&r, 0xFFFFFFFFu, 8u + 6u);
	for (i = 0; i < cnt && wri_rd_ok(&r); i++) {
		int64_t id = wri_rd_i64(&r);

		if (!wri_rd_ok(&r) || wri_pool_skip(&r, NULL) != WR_OK)
			break;
		for (k = 0; k < n; k++)
			if (pp->found[k] != 0 && pp->id[k] == id)
				pp->in_inc[k] = 1;
	}
	if (!wri_rd_ok(&r))
		return wri_inc_fail_rd(ix, &r, "new_pools is malformed");

	r = wri_inc_row(ix, WRI_INC_R_OLD_POOLS);
	cnt = wri_rd_count(&r, 0xFFFFFFFFu, 8u);
	for (i = 0; i < cnt && wri_rd_ok(&r); i++) {
		int64_t id = wri_rd_i64(&r);

		for (k = 0; k < n; k++) {
			if (pp->found[k] != 0 && pp->id[k] == id) {
				pp->found[k] = 0;
				pp->in_inc[k] = 0;
			}
		}
	}
	if (!wri_rd_ok(&r))
		return wri_inc_fail_rd(ix, &r, "old_pools is malformed");
	return WR_OK;
}

/* A pool that is there needs a record, and its pg-table entries must have been kept (slot k). */
static wr_status check_one(const wri_inc_ix *ix, const wri_osdmap *src, const wri_map_pool *hp, wri_inc_pools *pp, uint32_t k)
{
	int j = hp != NULL ? held_slot(hp, src->n_pools, pp->id[k]) : -1;

	if (pp->in_inc[k] != 0) {
		/* a record for an id the held map did not track: sound only for a pool created in this very epoch, whose id is above the old
		 * pool_max (the monitor raises new_pool_max for every pool it creates); a rename of an older pool would have lost its entries.
		 * The held map keeps no pool_max, so "an epoch that creates a pool" stands in for "above the old pool_max": an older pool renamed
		 * to a tracked name in the very epoch another pool is created is taken for a new one (its earlier entries are missing until the next full map) */
		if (j < 0 && !(ix->new_pool_max != -1 && pp->id[k] <= ix->new_pool_max)) {
			WRI_ERRINFO(ix->why, WR_E_MAP_RESYNC, WR_MOD_MAP,
				    "a tracked pool name now belongs to a pool whose earlier pg table entries were not kept", k, pp->id[k], ix->new_pool_max);
			return WR_E_MAP_RESYNC;
		}
		return WR_OK;
	}
	if (j < 0) {
		WRI_ERRINFO(ix->why, WR_E_MAP_RESYNC, WR_MOD_MAP, "a tracked pool name now belongs to a pool this client holds no record of", k, pp->id[k], 0);
		return WR_E_MAP_RESYNC;
	}
	pp->held[k] = (int8_t)j;
	return WR_OK;
}

static wr_status check_records(const wri_inc_ix *ix, const wri_osdmap *src, const wri_map_pool *hp, wri_inc_pools *pp)
{
	uint32_t k;
	wr_status st = WR_OK;

	for (k = 0; k < pp->n && st == WR_OK; k++)
		if (pp->found[k] != 0)
			st = check_one(ix, src, hp, pp, k);
	return st;
}

wr_status wri_inc_resolve_pools(const wri_mapcfg *cfg, const wri_osdmap *src, const wri_inc_ix *ix, wri_inc_pools *pp)
{
	const wri_map_pool *hp = src->n_pools != 0 ? wri_map_pools(src) : NULL;
	uint32_t k;
	wr_status st;

	WR_MEMSET(pp, 0, sizeof(*pp));
	pp->n = cfg->n_pools;
	for (k = 0; k < WRI_MAP_POOLS_MAX; k++)
		pp->held[k] = -1;
	st = scan_names(cfg, hp, ix, pp);
	if (st == WR_OK)
		st = scan_records(ix, pp);
	if (st == WR_OK)
		st = check_records(ix, src, hp, pp);
	return st;
}

/* Decode one record into the pool slot `pl`; the first reason a pool cannot be used is kept in `note`. */
static wr_status decode_record(const wri_inc_ix *ix, wri_rd *r, wri_map_pool *pl, int64_t id, wr_errinfo *note)
{
	wr_errinfo local;
	wr_status st;

	WR_MEMSET(&local, 0, sizeof(local));
	pl->id = id; /* the decoder reads the id from the record it fills */
	st = wri_pool_decode(r, pl, &local);
	if (st != WR_OK) {
		st = wri_full_status(st);
		WRI_ERRINFO(ix->why, st, WR_MOD_MAP, local.what != NULL ? local.what : "tracked pg_pool_t is malformed", wri_inc_off(ix, r), id, local.a0);
		return st;
	}
	if (local.status != WR_OK && note->status == WR_OK)
		*note = local;
	return WR_OK;
}

/* One new_pools entry: decode it into the first tracked slot that carries this id and copy it to the other slots of the same id. */
static wr_status fill_entry(const wri_inc_ix *ix, const wri_inc_pools *pp, wri_map_pool *pl, wri_rd *r, int64_t id, wr_errinfo *note)
{
	uint32_t k;
	int first = -1;
	wr_status st;

	for (k = 0; k < pp->n && first < 0; k++)
		if (pp->found[k] != 0 && pp->in_inc[k] != 0 && pp->id[k] == id)
			first = (int)k;
	if (first < 0) {
		st = wri_pool_skip(r, NULL);
		return st == WR_OK ? WR_OK : wri_inc_fail_val(ix, r, wri_full_status(st), "pg_pool_t cut short", (uint64_t)id, 0);
	}
	st = decode_record(ix, r, &pl[first], id, note);
	if (st != WR_OK)
		return st;
	for (k = (uint32_t)first + 1u; k < pp->n; k++) /* the same name tracked twice: the same record */
		if (pp->found[k] != 0 && pp->in_inc[k] != 0 && pp->id[k] == id)
			pl[k] = pl[first];
	return WR_OK;
}

wr_status wri_inc_fill_pools(const wri_inc_ix *ix, const wri_inc_pools *pp, const wri_osdmap *src, wri_mapbuild *b, wr_errinfo *note)
{
	wri_map_pool *pl = (wri_map_pool *)(void *)(wri_map_base_rw(b->m) + b->m->pool_off);
	const wri_map_pool *hp = src->n_pools != 0 ? wri_map_pools(src) : NULL;
	uint32_t n = pp->n, k, i, cnt;
	wri_rd r;

	for (k = 0; k < n; k++) { /* held records: copied, and the audit decides the status again */
		if (pp->found[k] == 0 || pp->in_inc[k] != 0 || pp->held[k] < 0 || hp == NULL)
			continue;
		pl[k] = hp[pp->held[k]];
		if (pl[k].status != WR_E_POOL_UNSUPPORTED)
			pl[k].status = WR_OK;
	}

	r = wri_inc_row(ix, WRI_INC_R_NEW_POOLS);
	cnt = wri_rd_count(&r, 0xFFFFFFFFu, 8u + 6u);
	for (i = 0; i < cnt && wri_rd_ok(&r); i++) {
		int64_t id = wri_rd_i64(&r);
		wr_status st;

		if (!wri_rd_ok(&r))
			break;
		st = fill_entry(ix, pp, pl, &r, id, note);
		if (st != WR_OK)
			return st;
	}
	if (!wri_rd_ok(&r))
		return wri_inc_fail_rd(ix, &r, "new_pools is malformed");
	return WR_OK;
}

/* ---- the rule audit ------------------------------------------------------------------------------------ */

/* The rule audit of every present tracked pool that is otherwise usable: its answer is the pool's status. */
void wri_inc_audit_pools(wri_mapbuild *b, wr_errinfo *note)
{
	wri_map_pool *pl = (wri_map_pool *)(void *)(wri_map_base_rw(b->m) + b->m->pool_off);
	const wri_crush *c = wri_map_crush(b->m);
	uint32_t k;

	for (k = 0; k < b->m->n_pools; k++) {
		wr_errinfo local;
		wr_status st;

		if (pl[k].present == 0 || pl[k].status != WR_OK)
			continue;
		WR_MEMSET(&local, 0, sizeof(local));
		st = wri_crush_audit_rule(c, pl[k].crush_rule, pl[k].size, &local);
		if (st == WR_OK)
			continue;
		pl[k].status = st;
		if (note->status == WR_OK) {
			*note = local;
			if (note->status == WR_OK)
				WRI_ERRINFO(note, st, WR_MOD_CRUSH, "the pool's CRUSH rule cannot be used", pl[k].crush_rule, (uint64_t)pl[k].id, 0);
		}
	}
}

/* ---- the held map -------------------------------------------------------------------------------------- */

/* The sections of the held slot lie inside it: what the copy reads is in bounds even if the slot was damaged. A finished map
 * that passed wri_osdmap_check always satisfies this; it is not a substitute for that check. */
static int in_slot(const wri_osdmap *s, uint32_t off, uint64_t len)
{
	return (uint64_t)off >= sizeof(*s) && off <= s->bytes && len <= (uint64_t)(s->bytes - off);
}

static int src_arrays_ok(const wri_osdmap *s)
{
	uint64_t mo = s->max_osd;

	if (mo > WRI_MAP_OSD_HARD_MAX || s->n_pools > WRI_MAP_POOLS_MAX)
		return 0;
	if (mo != 0 && (!in_slot(s, s->state_off, mo) || !in_slot(s, s->weight_off, mo * 4u) ||
			!in_slot(s, s->addr_off, mo * sizeof(wri_osd_addr)) || (s->aff_off != 0 && !in_slot(s, s->aff_off, mo * 4u))))
		return 0;
	return s->n_pools == 0 || in_slot(s, s->pool_off, (uint64_t)s->n_pools * sizeof(wri_map_pool));
}

static int src_tabs_ok(const wri_osdmap *s)
{
	unsigned k;

	for (k = 0; k < WRI_TAB_COUNT; k++) {
		const wri_pgtab *t = &s->tab[k];

		if (t->n > t->cap_n || t->nv > t->cap_nv)
			return 0;
		if (t->n != 0 && (!in_slot(s, t->key_off, (uint64_t)t->n * 8u) || !in_slot(s, t->off_off, ((uint64_t)t->n + 1u) * 4u) ||
				  !in_slot(s, t->val_off, (uint64_t)t->nv * 4u)))
			return 0;
	}
	return 1;
}

int wri_inc_src_sane(const wri_osdmap *s)
{
	if (s->magic != WRI_MAP_MAGIC || s->bytes < sizeof(*s) || s->bytes > s->cap || !src_arrays_ok(s) || !src_tabs_ok(s))
		return 0;
	if (s->crush_off != 0) {
		const wri_crush *c;

		if (!in_slot(s, s->crush_off, sizeof(wri_crush)))
			return 0;
		c = wri_map_crush(s);
		if (c->bytes < sizeof(wri_crush) || !in_slot(s, s->crush_off, c->bytes))
			return 0;
	}
	return 1;
}
