/* SPDX-License-Identifier: MIT */
/*
 * wri_denc_map.h - the encodings the OSDMap, the incrementals and the CRUSH blob need beyond wri_denc.h:
 * the legacy envelope of the map wrapper and of pg_pool_t, pg_t, varints, and walkers that step over
 * values a client does not keep. Pure functions on the cursors; module denc-map (wri_denc_map.c).
 * Written from docs/spec/osdmap.md 2.1 and 2.2.
 */
#ifndef WRI_DENC_MAP_H
#define WRI_DENC_MAP_H

#include "wri_denc.h"

/*
 * The "legacy" versioned envelope (osdmap.md 2.2): u8 struct_v, then u8 struct_compat only when
 * struct_v >= compat_at, then u32 struct_len only when struct_v >= len_at. The outer OSDMap wrapper and the
 * incremental use (7, 7); pg_pool_t uses (5, 5). Below `min_v` or when struct_len is absent the structure
 * cannot be skipped, so it is refused: WR_E_MAP_VERSION. struct_compat above `supported_compat`: WR_E_MAP_VERSION.
 * struct_len above the bytes left in the parent: WR_E_TRUNCATED. On success e->body is the body sub-reader and
 * the parent is already past the structure (same contract as wri_env_open).
 */
WR_MUST_CHECK wr_status wri_env_open_legacy(wri_rd *r, uint8_t min_v, uint8_t compat_at, uint8_t len_at,
					    uint8_t supported_compat, wri_env *e);

/*
 * pg_t (17 bytes: u8 version, u64 pool, u32 seed, s32 preferred that is skipped). The pool is returned as read: entries of
 * pools the client does not track are filtered by the caller, so a huge id is not an error here (tracked pool ids are
 * below 2^31, which the pool decoder enforces).
 */
typedef struct wri_pg {
	uint64_t pool;
	uint32_t seed;
} wri_pg;
WR_MUST_CHECK wr_status wri_denc_pg(wri_rd *r, wri_pg *out);
/* The packed sort key of a pg of a tracked pool (id below 2^31): (pool << 32) | seed. Ascending keys = the wire order of pg-keyed maps. */
WR_INLINE uint64_t wri_pg_key(uint32_t pool, uint32_t seed) { return ((uint64_t)pool << 32) | seed; }

/* varint (7 bits per byte, low group first, at most 10 bytes); WR_E_ENCODING when it does not end or overflows 64 bits. */
uint64_t wri_denc_varint(wri_rd *r);

/* Step over values without keeping them. Counts are capped by wri_rd_count (a hostile count cannot loop). */
void wri_denc_skip_str(wri_rd *r);                    /* u32 length + bytes */
void wri_denc_skip_str_map(wri_rd *r);                /* map<string,string> */
void wri_denc_skip_str_map_map(wri_rd *r);            /* map<string, map<string,string>> */
void wri_denc_skip_interval_set(wri_rd *r);           /* u32 count + count x (u64 start, u64 length) */
void wri_denc_skip_env(wri_rd *r);                    /* a modern envelope (u8 v, u8 compat, u32 len + body) */
void wri_denc_skip_i32_vec(wri_rd *r, uint32_t max);  /* vector<s32>, count <= max */

/* A u32 count of map / set / vector elements of at least elem_min bytes, at most max (see wri_rd_count). */
uint32_t wri_denc_count(wri_rd *r, uint32_t max, size_t elem_min);

#endif /* WRI_DENC_MAP_H */
