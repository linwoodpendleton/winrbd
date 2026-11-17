/* SPDX-License-Identifier: MIT */
/*
 * wri_osdmap.h - the compact OSD map: what a client keeps of an OSDMap, in one flat slot.
 *
 * A MAP SLOT is a block of `slot_bytes` bytes of the bulk region. A map is built into a slot in one go
 * (decode of a full map, or "copy the held map and apply one incremental") and never changed afterwards;
 * the map store keeps two slots and swaps which one is the held map when a build succeeds
 * (docs/design/core-architecture.md 15.3, 15.5). The first bytes of a slot are the wri_osdmap header; the
 * sections that follow are placed by a bump layout and addressed by byte offsets from the slot start, so a
 * slot can be copied with memcpy and sits at different addresses in the two slots. Structs may overlay a
 * slot: it is our own memory, host byte order, never wire bytes.
 *
 *   header | state[max_osd] u8 | weight[max_osd] u32 | affinity[max_osd] u32 (only if present) |
 *   addr[max_osd] wri_osd_addr | pools[n_pools] wri_map_pool | five pg tables | CRUSH region (wri_crush.h)
 *
 * Only the pools the client tracks (by name, wr_client_pool_track) are kept: their records and their entries
 * in pg_temp, primary_temp, pg_upmap, pg_upmap_items and pg_upmap_primaries. Everything else in the wire
 * map is skipped by length. Per OSD we keep two state bits (EXISTS, UP), the reweight, the primary affinity
 * and the first msgr2 address.
 *
 * This header is owned by module osdmap-core (wri_osdmap.c). The decoders are in wri_osdmap_dec.h, the
 * placement pipeline in wri_place.h.
 */
#ifndef WRI_OSDMAP_H
#define WRI_OSDMAP_H

#include "wr_err.h"
#include "wr_port.h"
#include "wr_types.h"
#include "wri_crush.h"
#include "wri_denc_map.h"

/* ---- limits ------------------------------------------------------------------------------------ */

#define WRI_MAP_MAGIC 0x57414d31u       /* "WAM1": first word of a map slot */
#define WRI_MAP_POOLS_MAX 8u            /* tracked pools at most */
#define WRI_MAP_NAME_MAX 128u           /* longest tracked pool name */
#define WRI_MAP_OSD_HARD_MAX 262144u    /* max_osd above this is refused whatever the configuration says */
#define WRI_MAP_PGVEC_MAX 32u           /* longest pg_temp / pg_upmap vector or upmap-items pair list we keep */
#define WRI_REP_MAX WRI_CRUSH_RESULT_MAX /* replicas of a placement result */
#define WRI_MAP_SLOT_ALIGN 16u
#define WRI_MAP_NAME_ID_BITS 31u        /* tracked pool ids must fit an s31: every real pool id does */

/* OSD state bits we keep (rados.h bit 0 and 1); the wire's other bits are dropped. */
#define WRI_OSD_EXISTS 0x01u
#define WRI_OSD_UP 0x02u
#define WRI_OSD_IN_FULL 0x10000u /* weight / affinity 1.0 in 16.16 */
#define WRI_OSD_NONE 0x7fffffff  /* CRUSH_ITEM_NONE in pg_temp / pg_upmap vectors and results */

/* pg_pool_t.flags bits a client reads (osdmap.md 2.7.2) */
#define WRI_POOL_F_HASHPSPOOL 0x1u
#define WRI_POOL_F_FULL 0x2u
#define WRI_POOL_F_FULL_QUOTA 0x400u
#define WRI_POOL_F_SELFMANAGED_SNAPS 0x2000u
#define WRI_POOL_F_POOL_SNAPS 0x4000u
#define WRI_POOL_F_EIO 0x10000u

/* map flags (rados.h): pause bits and the deprecated FULL, kept raw */
#define WRI_MAP_F_FULL 0x2u
#define WRI_MAP_F_PAUSERD 0x4u
#define WRI_MAP_F_PAUSEWR 0x8u

/* pool types */
#define WRI_POOL_REPLICATED 1u
#define WRI_POOL_ERASURE 3u

/* ---- per-OSD and per-pool records -------------------------------------------------------------- */

/* The first msgr2 address of an OSD (osdmap.md 3.8). family 0 = none: the OSD cannot be contacted. 24 bytes. */
typedef struct wri_osd_addr {
	uint32_t nonce;
	uint16_t port; /* host order */
	uint8_t family; /* 0 none, WR_AF_IPV4, WR_AF_IPV6 */
	uint8_t reserved;
	uint8_t ip[16];
} wri_osd_addr;
WR_STATIC_ASSERT(sizeof(wri_osd_addr) == 24u, wri_osd_addr_size);

/*
 * A tracked pool as one map holds it. `present` is 0 when the pool's name is not in the map (deleted or not yet
 * created); then only `name_idx` is meaningful. `status` is WR_OK when the pool can be used by this client, else
 * the reason (WR_E_POOL_UNSUPPORTED, WR_E_CRUSH_NO_RULE, ... : decided when the map is adopted, after the CRUSH rule audit).
 * 56 bytes.
 */
typedef struct wri_map_pool {
	int64_t id;
	uint64_t flags;
	uint32_t pg_num, pgp_num;
	uint32_t pg_num_mask, pgp_num_mask; /* recomputed, never on the wire */
	uint32_t last_force_op_resend;
	uint32_t pg_num_pending;
	int32_t status;
	uint8_t present;
	uint8_t type;       /* WRI_POOL_* */
	uint8_t size;       /* replicas */
	uint8_t min_size;
	uint8_t crush_rule;
	uint8_t object_hash; /* WRI_STR_HASH_* */
	uint8_t reserved[2];
	uint32_t reserved2;  /* explicit tail so the size is 56 where a 64-bit member is 8-aligned (x86-64) and where it is 4-aligned (i386) */
} wri_map_pool;
WR_STATIC_ASSERT(sizeof(wri_map_pool) == 56u, wri_map_pool_size);

/* ---- pg-keyed tables --------------------------------------------------------------------------- */

/* The five tables, in header order. Keys are wri_pg_key() values, sorted ascending, unique. */
#define WRI_TAB_PG_TEMP 0u         /* values: the acting OSDs (s32) */
#define WRI_TAB_PRIMARY_TEMP 1u    /* one value: the OSD */
#define WRI_TAB_PG_UPMAP 2u        /* values: the replacement OSD list */
#define WRI_TAB_PG_UPMAP_ITEMS 3u  /* values: (from, to) pairs, flattened */
#define WRI_TAB_PG_UPMAP_PRIMARY 4u /* one value: the OSD */
#define WRI_TAB_COUNT 5u

/*
 * One table: n entries with keys key[n] (u64), offsets off[n + 1] (u32, into val) and values val[nv] (s32);
 * entry i owns val[off[i] .. off[i+1]). The three arrays are at byte offsets from the slot start; cap_n and
 * cap_nv are the room carved for them (a build may fill less).
 */
typedef struct wri_pgtab {
	uint32_t n, nv;
	uint32_t cap_n, cap_nv;
	uint32_t key_off, off_off, val_off;
	uint32_t reserved;
} wri_pgtab;

/* ---- the map header ------------------------------------------------------------------------------ */

typedef struct wri_osdmap {
	uint32_t magic;    /* WRI_MAP_MAGIC; 0 in a slot that holds no map */
	uint32_t bytes;    /* bytes of the slot in use, header included */
	uint32_t cap;      /* bytes of the slot */
	uint32_t epoch;
	uint8_t fsid[16];
	uint32_t flags;    /* map flags (WRI_MAP_F_*), raw */
	uint32_t max_osd;
	uint32_t n_pools;  /* tracked pool records (the store's tracked count at build time) */
	uint32_t state_off, weight_off, aff_off, addr_off, pool_off; /* aff_off == 0: no affinity array, all default */
	uint32_t crush_off; /* offset of the wri_crush region, 0 = none */
	uint32_t n_exists, n_up; /* derived counts, for diagnostics */
	wri_pgtab tab[WRI_TAB_COUNT];
} wri_osdmap;

/* ---- accessors ---------------------------------------------------------------------------------- */

WR_INLINE const uint8_t *wri_map_base(const wri_osdmap *m) { return (const uint8_t *)m; }
WR_INLINE uint8_t *wri_map_base_rw(wri_osdmap *m) { return (uint8_t *)m; }

WR_INLINE const uint8_t *wri_map_state(const wri_osdmap *m) { return wri_map_base(m) + m->state_off; }
WR_INLINE const uint32_t *wri_map_weight(const wri_osdmap *m)
{
	return (const uint32_t *)(const void *)(wri_map_base(m) + m->weight_off);
}
/* NULL when the map has no affinity array (every OSD has the default). */
WR_INLINE const uint32_t *wri_map_aff(const wri_osdmap *m)
{
	return m->aff_off == 0 ? NULL : (const uint32_t *)(const void *)(wri_map_base(m) + m->aff_off);
}
WR_INLINE const wri_osd_addr *wri_map_addr(const wri_osdmap *m)
{
	return (const wri_osd_addr *)(const void *)(wri_map_base(m) + m->addr_off);
}
WR_INLINE const wri_map_pool *wri_map_pools(const wri_osdmap *m)
{
	return (const wri_map_pool *)(const void *)(wri_map_base(m) + m->pool_off);
}
/* NULL when the map carries no CRUSH region (never for a map the store adopted). */
WR_INLINE const wri_crush *wri_map_crush(const wri_osdmap *m)
{
	return m->crush_off == 0 ? NULL : (const wri_crush *)(const void *)(wri_map_base(m) + m->crush_off);
}

/* An OSD "exists" iff 0 <= id < max_osd and EXISTS is set; "up" additionally needs UP (osdmap.md 2.7.1). */
WR_INLINE int wri_osd_exists(const wri_osdmap *m, int32_t id)
{
	return id >= 0 && (uint32_t)id < m->max_osd && (wri_map_state(m)[id] & WRI_OSD_EXISTS) != 0;
}
WR_INLINE int wri_osd_up(const wri_osdmap *m, int32_t id)
{
	return wri_osd_exists(m, id) && (wri_map_state(m)[id] & WRI_OSD_UP) != 0;
}
/* Reweight of an OSD, 0 for an id outside 0..max_osd-1 (out). */
WR_INLINE uint32_t wri_osd_weight(const wri_osdmap *m, int32_t id)
{
	return (id >= 0 && (uint32_t)id < m->max_osd) ? wri_map_weight(m)[id] : 0u;
}
/* Primary affinity, WRI_OSD_IN_FULL (the default and the maximum) when there is no array or the id is outside the map. */
WR_INLINE uint32_t wri_osd_aff(const wri_osdmap *m, int32_t id)
{
	const uint32_t *a = wri_map_aff(m);

	return (a != NULL && id >= 0 && (uint32_t)id < m->max_osd) ? a[id] : (uint32_t)WRI_OSD_IN_FULL;
}

WR_INLINE const uint64_t *wri_pgtab_keys(const wri_osdmap *m, unsigned kind)
{
	return (const uint64_t *)(const void *)(wri_map_base(m) + m->tab[kind].key_off);
}
WR_INLINE const uint32_t *wri_pgtab_offs(const wri_osdmap *m, unsigned kind)
{
	return (const uint32_t *)(const void *)(wri_map_base(m) + m->tab[kind].off_off);
}
WR_INLINE const int32_t *wri_pgtab_vals(const wri_osdmap *m, unsigned kind)
{
	return (const int32_t *)(const void *)(wri_map_base(m) + m->tab[kind].val_off);
}

/*
 * Binary search for `key` in table `kind`. 1 and *vals / *nvals set (vals points into the slot) when found,
 * 0 when not (vals / nvals untouched). Either out pointer may be NULL.
 */
int wri_pgtab_find(const wri_osdmap *m, unsigned kind, uint64_t key, const int32_t **vals, uint32_t *nvals);

/* ---- building a map in a slot (used by the decoders; module osdmap-core) ----------------------------- */

/*
 * Layout builder: bump-carves the sections of one map in the slot. Every carve is range-checked against
 * the slot and fails with WR_E_MAP_BUDGET (reason in *why: which section, bytes wanted, bytes left) without
 * writing past the slot. The builder never reads the slot before it has zeroed what it carves.
 *
 * Rules every carve follows:
 *  - Alignment: every section starts on a multiple of 4 bytes from the slot start; the sections that hold 64-bit
 *    members (the pool records, the key array of each pg table, the CRUSH region) on a multiple of 8. The slot itself
 *    must be 16-byte aligned (the builder refuses less than 8, see wri_mapbuild_status).
 *  - Zeroing: a carve zeroes everything it advances over, alignment padding included, so two builds of the same
 *    map are byte-identical whatever the slot held before. Bytes past `used` are never touched.
 *  - All or nothing: a carve that fails changes neither the builder nor the slot. Carving a section twice
 *    (or an unknown table kind) is a caller bug and is WR_E_INVAL; sections may be carved in any order, but the
 *    CRUSH region should come last (see wri_mapbuild_finish).
 *  - Errinfo of WR_E_MAP_BUDGET (module WR_MOD_MAP): `what` names the section ("map slot too small for the pg_temp
 *    table"), a0 = bytes the section needs counted from the end of the previous section (alignment padding
 *    included), a1 = bytes free at that point, a2 = slot size. For a limit that is not the slot (max_osd above the
 *    hard cap, too many pools, a pg vector too long, a pg table whose carved room is full) `what` says so and a0 / a1
 *    are the value and the limit.
 */
typedef struct wri_mapbuild {
	wri_osdmap *m;   /* the header at the start of the slot; NULL when wri_mapbuild_begin refused the slot */
	size_t cap;
	size_t used;
	wr_errinfo *why; /* may be NULL */
} wri_mapbuild;

/*
 * Zero the header, set magic = 0 (not a map yet), cap, used = sizeof header. slot is 16-byte aligned. A slot that
 * cannot hold the header, is NULL or is not even 8-byte aligned leaves a refused builder (m == NULL, the reason is
 * already in *why): every later call on it fails with wri_mapbuild_status(), nothing is written, left returns 0 and
 * finish does nothing. cap is clamped to 4 GiB - 1 (offsets are u32).
 */
void wri_mapbuild_begin(wri_mapbuild *b, uint8_t *slot, size_t cap, wr_errinfo *why);
/* WR_OK for a usable builder; for a refused one the status every carve returns: WR_E_MAP_BUDGET (slot smaller than the
 * header) or WR_E_INVAL (NULL or misaligned slot). */
wr_status wri_mapbuild_status(const wri_mapbuild *b);
/* max_osd (<= WRI_MAP_OSD_HARD_MAX, else WR_E_MAP_BUDGET): carve state, weight, addr (zeroed) and, if has_aff,
 * affinity (set to WRI_OSD_IN_FULL). All four or none. Sets max_osd and the four offsets. */
WR_MUST_CHECK wr_status wri_mapbuild_osds(wri_mapbuild *b, uint32_t max_osd, int has_aff);
/* Carve n_pools (<= WRI_MAP_POOLS_MAX, else WR_E_MAP_BUDGET) zeroed pool records. Sets n_pools and pool_off. */
WR_MUST_CHECK wr_status wri_mapbuild_pools(wri_mapbuild *b, uint32_t n_pools);
/* Carve room for cap_n entries / cap_nv values of table `kind` (keys u64[cap_n], offsets u32[cap_n + 1], values
 * s32[cap_nv]); the table starts empty (n = nv = 0, offsets[0] = 0). */
WR_MUST_CHECK wr_status wri_mapbuild_tab(wri_mapbuild *b, unsigned kind, uint32_t cap_n, uint32_t cap_nv);
/* Carve `n` bytes (8-byte aligned, zeroed) for the CRUSH region and set crush_off; returns NULL + error if it does not fit
 * (WR_E_MAP_BUDGET; an n above the slot size is refused before it is added to anything, so no size_t wraps), or if n is 0
 * or the region was already carved (WR_E_INVAL). A decoder that does not know the region
 * size in advance may carve the largest room there is (wri_mapbuild_crush_left) as the last section and decode into it:
 * wri_mapbuild_finish gives the unused tail back. A room that is larger than its region and is not last leaves a hole in
 * the middle of the slot, which wri_osdmap_check refuses. */
uint8_t *wri_mapbuild_crush_room(wri_mapbuild *b, size_t n);
/* Bytes still free in the slot (0 for a refused builder). */
size_t wri_mapbuild_left(const wri_mapbuild *b);
/* The largest n wri_mapbuild_crush_room can carve now: the free bytes after the 8-byte alignment of the region (0 for a
 * refused builder or when nothing is left). */
size_t wri_mapbuild_crush_left(const wri_mapbuild *b);
/*
 * Append one entry; keys must be strictly ascending (WR_E_MAP_CORRUPT otherwise), nvals <= WRI_MAP_PGVEC_MAX * 2 (a longer
 * vector is WR_E_MAP_BUDGET: a limit of ours, not a malformed map), WR_E_MAP_BUDGET when the carved room is full (entries or
 * values), WR_E_INVAL for an unknown kind or vals == NULL with nvals > 0. A failed push changes nothing. The table does not
 * police how many values an entry of a one-value table has; the placement code reads the count it is given.
 */
WR_MUST_CHECK wr_status wri_pgtab_push(wri_mapbuild *b, unsigned kind, uint64_t key, const int32_t *vals, uint32_t nvals);
/*
 * Copy a whole table of another finished map (the unchanged tables of an incremental): carves exactly src's n entries and
 * nv values for `kind` and copies keys, offsets and values. The table must not be carved yet (WR_E_INVAL), src must carry
 * WRI_MAP_MAGIC (WR_E_INVAL) and a sane table (WR_E_MAP_CORRUPT); a slot that cannot take it is WR_E_MAP_BUDGET. The array
 * sections and the CRUSH region are not copied here: a caller carves them (wri_mapbuild_osds, _pools, _crush_room) and
 * copies the bytes it wants to keep itself.
 */
WR_MUST_CHECK wr_status wri_mapbuild_copy_tab(wri_mapbuild *b, unsigned kind, const wri_osdmap *src);
/*
 * Set the final header fields: magic, bytes = used, and the derived counts n_exists (OSDs with EXISTS) and n_up (OSDs with
 * EXISTS and UP, as wri_osd_up). If the CRUSH region is the last section and holds a region (WRI_CRUSH_MAGIC) shorter than
 * its room, bytes stops at the end of the region. Does nothing for a refused builder.
 */
void wri_mapbuild_finish(wri_mapbuild *b);

/*
 * Structural self-check of a finished slot: magic, bytes within cap, every offset inside `bytes` and aligned, array
 * bounds, sections disjoint and packed as the builder packs them (gaps are alignment padding only), per-OSD records
 * (state bits, address family) and pool records sane, derived counts equal to the state array, tables sorted with
 * consistent offsets, CRUSH region valid (wri_crush_check). A section that was never
 * carved (offset 0, size 0) is an empty section, not an error; crush_off 0 is a map without CRUSH (the store refuses it
 * separately). Fields with no invariant (epoch, fsid, flags, weights, affinities) are not checked. For tests and
 * fuzzing; WR_OK or WR_E_MAP_CORRUPT.
 */
WR_MUST_CHECK wr_status wri_osdmap_check(const wri_osdmap *m);

#endif /* WRI_OSDMAP_H */
