/* SPDX-License-Identifier: MIT */
/*
 * wri_mapstore.c - the map store: memory plan, set-up, tracked pools, queries and placement through the cache
 * (docs/design/core-architecture.md 15.3, 15.5, 15.7). The message side (the cursor, the epoch policy, the
 * re-request control) is wri_mapstore_msg.c.
 *
 * Nothing here writes a map slot: the held slot is only ever replaced as a whole by a step, so every query sees one
 * finished map. Answers are plain structs; nothing handed out points into a slot except wri_mapstore_map and
 * wri_mapstore_pool, which say how long theirs stay valid.
 */
#include "wri_mapstore.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/* The public target holds as many replicas as a placement result (wr_map.h WR_MAP_REP_MAX). */
WR_STATIC_ASSERT(WR_MAP_REP_MAX == WRI_REP_MAX, mapstore_rep_max);

#define SLOT_MIN_BYTES (16u * 1024u) /* below this not even a three-OSD map fits */
#define SECTION_ALIGN 16u

/* ---- memory --------------------------------------------------------------------------------------------- */

/* The configuration the store can run with (map_slot_bytes != 0 only). */
static wr_status check_cfg(const wr_config *cfg)
{
	if (cfg->map_slot_bytes < SLOT_MIN_BYTES)
		return WR_E_INVAL;
	if (cfg->map_pools == 0 || cfg->map_pools > WRI_MAP_POOLS_MAX)
		return WR_E_INVAL;
	if (cfg->map_max_osd == 0 || cfg->map_max_osd > WRI_MAP_OSD_HARD_MAX)
		return WR_E_INVAL;
	if (cfg->crush_work_max == 0) /* every mapping would run out of work at once: a map that can place nothing */
		return WR_E_INVAL;
	return WR_OK;
}

/* Bytes of the placement cache: 0 for none; WR_E_OVERFLOW when the size does not fit size_t. */
static wr_status cache_bytes(const wr_config *cfg, size_t *out)
{
	*out = 0;
	if (cfg->map_pg_cache == 0)
		return WR_OK;
	*out = wri_pgcache_bytes(cfg->map_pg_cache);
	return *out == 0 ? WR_E_OVERFLOW : WR_OK;
}

wr_status wri_mapstore_mem(const wr_config *cfg, size_t *arena_bytes, size_t *bulk_bytes)
{
	size_t cb, used;
	wr_status st;

	if (arena_bytes != NULL)
		*arena_bytes = 0;
	if (bulk_bytes != NULL)
		*bulk_bytes = 0;
	if (cfg == NULL || arena_bytes == NULL || bulk_bytes == NULL)
		return WR_E_INVAL;
	if (cfg->map_slot_bytes == 0)
		return WR_OK; /* maps disabled: the store costs nothing */
	st = check_cfg(cfg);
	if (st != WR_OK)
		return st;
	st = cache_bytes(cfg, &cb);
	if (st != WR_OK)
		return st;
	used = 0;
	if (cb != 0) {
		st = wri_arena_plan(&used, cb, SECTION_ALIGN);
		if (st != WR_OK)
			return st;
	}
	*arena_bytes = used;
	used = 0;
	st = wri_arena_plan(&used, cfg->map_slot_bytes, SECTION_ALIGN);
	if (st == WR_OK)
		st = wri_arena_plan(&used, cfg->map_slot_bytes, SECTION_ALIGN);
	if (st != WR_OK) {
		*arena_bytes = 0;
		return st;
	}
	*bulk_bytes = used;
	return WR_OK;
}

wr_status wri_mapstore_init(wri_mapstore *s, const wr_config *cfg, wri_arena *arena, wri_arena *bulk)
{
	wri_arena a, b;
	size_t cb;
	void *cmem = NULL;
	uint8_t *s0, *s1;
	wr_status st;

	if (s == NULL || cfg == NULL)
		return WR_E_INVAL;
	WR_MEMSET(s, 0, sizeof(*s));
	if (cfg->map_slot_bytes == 0)
		return WR_OK; /* disabled: enabled stays 0, every call below is inert */
	if (arena == NULL || bulk == NULL)
		return WR_E_INVAL;
	st = check_cfg(cfg);
	if (st != WR_OK)
		return st;
	st = cache_bytes(cfg, &cb);
	if (st != WR_OK)
		return st;

	/* carve from copies, so that a region that is too small is left as it was */
	a = *arena;
	b = *bulk;
	if (cb != 0) {
		cmem = wri_arena_take(&a, cb, SECTION_ALIGN);
		if (cmem == NULL)
			return WR_E_BUDGET;
	}
	s0 = (uint8_t *)wri_arena_take(&b, cfg->map_slot_bytes, SECTION_ALIGN);
	s1 = s0 == NULL ? NULL : (uint8_t *)wri_arena_take(&b, cfg->map_slot_bytes, SECTION_ALIGN);
	if (s0 == NULL || s1 == NULL)
		return WR_E_BUDGET;
	*arena = a;
	*bulk = b;

	s->enabled = 1;
	s->max_pools = (uint8_t)cfg->map_pools;
	s->slot[0] = s0;
	s->slot[1] = s1;
	WR_MEMSET(s0, 0, 4); /* the arena hands out zeroed memory; make "no map in this slot" explicit anyway */
	WR_MEMSET(s1, 0, 4);
	s->cfg.slot_bytes = cfg->map_slot_bytes;
	s->cfg.max_osd = cfg->map_max_osd;
	s->cfg.work_max = cfg->crush_work_max;
	s->cfg.verify_crc = cfg->map_verify_crc != 0 ? 1u : 0u;
	s->base_ms = cfg->map_refetch_ms == 0 ? 1u : cfg->map_refetch_ms;
	if (s->base_ms > WRI_MAPSTORE_BACKOFF_MAX_MS)
		s->base_ms = WRI_MAPSTORE_BACKOFF_MAX_MS;
	s->backoff_ms = s->base_ms;
	wri_pgcache_init(&s->cache, cmem, cmem == NULL ? 0u : cfg->map_pg_cache);
	s->st.slot_bytes = cfg->map_slot_bytes;
	return WR_OK;
}

/* ---- tracked pools -------------------------------------------------------------------------------------- */

wr_status wri_mapstore_track(wri_mapstore *s, const uint8_t *name, size_t len, uint32_t *handle)
{
	uint32_t i;

	if (handle != NULL)
		*handle = 0;
	if (s == NULL || !s->enabled || name == NULL || len == 0)
		return WR_E_INVAL;
	if (len > WRI_MAP_NAME_MAX)
		return WR_E_TOOBIG;
	for (i = 0; i < s->cfg.n_pools; i++) {
		if (s->cfg.name_len[i] == len && wri_ct_memeq(s->cfg.name[i], name, len)) {
			if (handle != NULL)
				*handle = i;
			return WR_OK;
		}
	}
	if (s->cfg.n_pools >= s->max_pools)
		return WR_E_BUSY;
	i = s->cfg.n_pools;
	s->cfg.name_len[i] = (uint8_t)len;
	WR_MEMCPY(s->cfg.name[i], name, len);
	s->cfg.n_pools = (uint8_t)(i + 1u);
	if (handle != NULL)
		*handle = i;
	/* A held map was decoded without this name: no record to apply an incremental to, only a full map resolves it. */
	if (s->have_map && !s->fatal) {
		wr_errinfo e;

		WR_MEMSET(&e, 0, sizeof(e));
		WRI_ERRINFO(&e, WR_E_MAP_RESYNC, WR_MOD_MAP, "pool tracked after the held map was built: a full map is needed", i, 0,
			    s->epoch);
		wri_mapstore_need_full(s, &e);
	}
	return WR_OK;
}

/* ---- queries -------------------------------------------------------------------------------------------- */

const wri_osdmap *wri_mapstore_map(const wri_mapstore *s)
{
	if (s == NULL || !s->enabled || !s->have_map)
		return NULL;
	return (const wri_osdmap *)(const void *)s->slot[s->cur];
}

wr_status wri_mapstore_pool(const wri_mapstore *s, uint32_t h, const wri_map_pool **out)
{
	const wri_osdmap *m;
	const wri_map_pool *p;

	if (out != NULL)
		*out = NULL;
	if (s == NULL || out == NULL || !s->enabled || h >= s->cfg.n_pools)
		return WR_E_INVAL;
	m = wri_mapstore_map(s);
	if (m == NULL)
		return WR_E_MAP_NONE;
	if (h >= m->n_pools)
		return WR_E_POOL_NOT_FOUND; /* tracked after this map was built: the next epoch resolves it */
	p = &wri_map_pools(m)[h];
	if (!p->present)
		return WR_E_POOL_NOT_FOUND;
	*out = p;
	return WR_OK;
}

void wri_mapstore_stats(const wri_mapstore *s, wr_map_stats *out)
{
	const wri_osdmap *m;

	if (out == NULL)
		return;
	WR_MEMSET(out, 0, sizeof(*out));
	if (s == NULL)
		return;
	*out = s->st;
	out->epoch = s->have_map ? s->epoch : 0u;
	out->newest_seen = s->newest_seen;
	out->cache_hits = s->cache.hits;
	out->cache_misses = s->cache.misses;
	m = wri_mapstore_map(s);
	out->slot_used = m != NULL ? m->bytes : 0u;
}

/* ---- targets -------------------------------------------------------------------------------------------- */

static void clear_target(wr_target *out)
{
	WR_MEMSET(out, 0, sizeof(*out));
	out->up_primary = -1;
	out->acting_primary = -1;
}

/* The address of an OSD as the public type; family 0 when the map has none for it. */
static void fill_addr(const wri_osdmap *m, int32_t osd, wr_addr *out)
{
	const wri_osd_addr *a;

	WR_MEMSET(out, 0, sizeof(*out));
	if (osd < 0 || (uint32_t)osd >= m->max_osd)
		return;
	a = &wri_map_addr(m)[osd];
	if (a->family != WR_AF_IPV4 && a->family != WR_AF_IPV6)
		return;
	out->family = a->family;
	WR_MEMCPY(out->ip, a->ip, sizeof(out->ip));
	out->port = a->port;
	out->nonce = a->nonce;
}

/* Steps 3 to 9 for a seed that is known to name a PG of the pool, through the cache; fills the target. */
static wr_status place(wri_mapstore *s, const wri_osdmap *m, uint32_t h, const wri_map_pool *p, uint32_t ps, uint32_t seed,
		       wr_target *out)
{
	wri_pg_result res;
	wr_errinfo why;
	/* The cache key carries the tracked-pool handle, not the 64-bit pool id cut to 32 bits: two tracked pools whose ids differ
	 * only above bit 31 (a hostile map can name them) would otherwise share cache entries and answer each other's queries. */
	uint64_t key = wri_pg_key(h, seed);
	uint32_t i;
	wr_status st = WR_OK;

	if (!wri_pgcache_get(&s->cache, m->epoch, key, &res)) {
		WR_MEMSET(&why, 0, sizeof(why));
		st = wri_place_pg(m, h, seed, s->cfg.work_max, &s->ws, &res, &why);
		if (st != WR_OK)
			return st;
		wri_pgcache_put(&s->cache, m->epoch, key, &res);
	}
	out->epoch = m->epoch;
	out->pool_id = p->id;
	out->ps = ps;
	out->pg_seed = seed;
	if (res.n_up > WR_MAP_REP_MAX || res.n_acting > WR_MAP_REP_MAX) /* never from the mapper or the cache: do not trust it */
		return WR_E_MAP_CORRUPT;
	if (res.n_acting == 0 || res.acting_primary < 0)
		return WR_E_PLACE_UNMAPPABLE; /* nothing usable now: hold the op until a newer map */
	out->n_up = res.n_up;
	out->n_acting = res.n_acting;
	for (i = 0; i < res.n_up; i++)
		out->up[i] = res.up[i];
	for (i = 0; i < res.n_acting; i++)
		out->acting[i] = res.acting[i];
	out->up_primary = res.up_primary;
	out->acting_primary = res.acting_primary;
	fill_addr(m, res.acting_primary, &out->primary_addr);
	return WR_OK;
}

wr_status wri_mapstore_target_pg(wri_mapstore *s, uint32_t h, uint32_t pg_seed, wr_target *out)
{
	const wri_map_pool *p;
	wr_status st;

	if (out == NULL)
		return WR_E_INVAL;
	clear_target(out);
	if (s == NULL)
		return WR_E_INVAL;
	st = wri_mapstore_pool(s, h, &p);
	if (st != WR_OK)
		return st;
	if (p->status != WR_OK)
		return (wr_status)p->status;
	if (pg_seed >= p->pg_num)
		return WR_E_RANGE;
	st = place(s, wri_mapstore_map(s), h, p, pg_seed, pg_seed, out);
	if (st != WR_OK && st != WR_E_PLACE_UNMAPPABLE)
		clear_target(out);
	return st;
}

wr_status wri_mapstore_target(wri_mapstore *s, uint32_t h, const wri_oid *o, wr_target *out)
{
	const wri_map_pool *p;
	uint32_t ps = 0;
	wr_status st;

	if (out == NULL)
		return WR_E_INVAL;
	clear_target(out);
	if (s == NULL || o == NULL)
		return WR_E_INVAL;
	st = wri_mapstore_pool(s, h, &p);
	if (st != WR_OK)
		return st;
	if (p->status != WR_OK)
		return (wr_status)p->status;
	st = wri_place_hash(p, o, &ps);
	if (st != WR_OK)
		return st;
	st = place(s, wri_mapstore_map(s), h, p, ps, wri_place_pg_seed(p, ps), out);
	if (st != WR_OK && st != WR_E_PLACE_UNMAPPABLE)
		clear_target(out);
	return st;
}
