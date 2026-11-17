/* SPDX-License-Identifier: MIT */
/*
 * wri_mapstore.h - the map store: owns the two map slots, takes the monitor's MOSDMap messages, keeps the held
 * map current, and answers placement queries on it.
 *
 * The store sits between the monitor client and the object client (docs/design/core-architecture.md 15, 17).
 * It knows nothing of connections: raw map messages come in through a wri_map_io (peek / release, implemented
 * by the client glue over wri_mon_mapmsg_peek / release), and the three things it asks of the world (a full-map
 * re-request, an event, the time) go out the same way. That keeps it testable with a scripted fake source.
 *
 * One message is consumed one EPOCH per step (a full map decode or one incremental apply is the unit of work), the
 * message stays held in its monitor slot until its last entry is done, and wri_mapstore_step reports whether
 * more work is left, so wr_client_run never stalls on a message of forty epochs. Entries that are not newer than the
 * held epoch are stepped over without counting as work.
 *
 * Epoch policy (docs/spec/osdmap.md 3.2):
 *   - a message with another fsid than the held map is dropped;
 *   - epochs are walked in ascending order over the incrementals and full maps of the message (a full map goes first when
 *     both lists carry the same epoch); an incremental is applied only to epoch - 1; a full map is adopted whenever its
 *     epoch is newer than the held one (or equals it while the held map was built before a pool was tracked: the one case
 *     where a map of the held epoch replaces the held map, and the placement cache is cleared then); the epoch a list entry
 *     is labelled with must be the epoch the map inside names, and the fsid inside must be the message's, or the entry
 *     fails: the held epoch never goes down;
 *   - an incremental that does not follow the held epoch (a gap), a decode failure or an apply failure keeps the
 *     held map, drops the rest of the message and asks the monitor for a full map (subscribe start 0), at most one
 *     request per map_refetch_ms, doubling (to 32 s) while the failures continue;
 *   - with no map yet only full maps are used; if the first full map cannot be decoded for a reason a retry cannot
 *     change (WR_E_MAP_BUDGET, WR_E_MAP_VERSION), WR_EV_FATAL is raised.
 *
 * Module mapstore (wri_mapstore.c, wri_mapstore_msg.c); the glue to the engine is module client-glue.
 */
#ifndef WRI_MAPSTORE_H
#define WRI_MAPSTORE_H

#include "wr_client.h"
#include "wr_map.h"
#include "wri_crush.h"
#include "wri_ctx.h"
#include "wri_mem.h"
#include "wri_osdmap_dec.h"
#include "wri_place.h"

/* ---- the world as the store sees it -------------------------------------------------------------------- */

typedef struct wri_map_io {
	void *ctx;
	/* The oldest unreleased raw monitor map message (wr_client_mapmsg_peek semantics), 1 if there is one. */
	int (*peek)(void *ctx, wr_mapmsg *out);
	/* Free the message last peeked. */
	void (*release)(void *ctx);
	/* Ask the monitor for the OSD map from `start` on (0 = a full map of the newest epoch): wri_mon_want_osdmap. */
	void (*want_osdmap)(void *ctx, uint32_t start);
	/* Raise a public event (WR_EV_MAP, WR_EV_MAP_RESYNC, WR_EV_FATAL); err may be NULL. */
	void (*event)(void *ctx, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *err);
} wri_map_io;

/* ---- the store ------------------------------------------------------------------------------------------ */

#define WRI_MAPSTORE_BACKOFF_MAX_MS 32000u

typedef struct wri_mapstore {
	uint8_t enabled;     /* map_slot_bytes != 0 */
	uint8_t cur;         /* index of the held slot (0 or 1), valid when have_map */
	uint8_t have_map;
	uint8_t want_full;   /* a full map must be requested (gap, failure, a pool tracked after the held map was built) */
	uint8_t fatal;       /* WR_EV_FATAL raised: nothing is requested or decoded any more, messages are released unread */
	uint8_t msg_open;    /* a message is being consumed */
	uint8_t max_pools;   /* tracked pools allowed: wr_config.map_pools, at most WRI_MAP_POOLS_MAX */
	uint8_t ev_map;      /* an epoch was adopted in this step: WR_EV_MAP is raised once at its end */
	wri_mapcfg cfg;      /* budgets and tracked pool names (cfg.n_pools = pools tracked so far), handed to the decoders */
	uint8_t *slot[2];    /* the two map slots in the bulk region, cfg.slot_bytes each */
	uint32_t epoch;      /* held epoch, 0 = none */
	uint32_t newest_seen;/* newest epoch announced by the monitor (the largest newest_map of any message) */

	/* cursor into the message being consumed (offsets into the front the source holds) */
	uint32_t msg_len;
	uint32_t inc_pos, inc_left;   /* next incremental entry (u32 epoch, u32 len, blob) and how many remain */
	uint32_t full_pos, full_left; /* the same for the full maps */

	/* re-request control (ms of the monotonic clock) */
	uint64_t refetch_at_ms;       /* earliest time the next request may go out, 0 = now */
	uint32_t base_ms;             /* map_refetch_ms, at least 1 */
	uint32_t backoff_ms;          /* current spacing; doubled by each request, reset by a successful apply */
	uint32_t fail_streak;         /* consecutive failures since the last applied epoch */
	uint32_t ev_epoch;            /* epoch to report with the pending WR_EV_MAP */

	wri_crush_ws ws;              /* mapper workspace (one query at a time: the engine is single-owner) */
	wri_pgcache cache;

	wr_map_stats st;              /* counters and last error, copied out by wr_client_map_stats */
	wr_errinfo err;               /* first failure since the last applied epoch */
	wr_errinfo cause;             /* what made want_full true last: carried by the next WR_EV_MAP_RESYNC */
} wri_mapstore;

/* ---- memory (module mapstore) ----------------------------------------------------------------------------- */

/*
 * Bytes the store needs: arena (the struct itself is part of the client; this is the placement cache) and bulk (two
 * slots of map_slot_bytes). Plain wri_arena_plan sums like the other modules: the owner adds WRI_ARENA_SLACK once.
 * Both 0 when maps are disabled. WR_E_INVAL for a config the store cannot use (slot smaller than 16 KiB, map_pools
 * 0 or above WRI_MAP_POOLS_MAX, map_max_osd 0 or above WRI_MAP_OSD_HARD_MAX, crush_work_max 0).
 */
WR_MUST_CHECK wr_status wri_mapstore_mem(const wr_config *cfg, size_t *arena_bytes, size_t *bulk_bytes);

/* Zero *s, copy the config, carve the slots from `bulk` and the cache from `arena`. WR_E_BUDGET when a region is too small. */
WR_MUST_CHECK wr_status wri_mapstore_init(wri_mapstore *s, const wr_config *cfg, wri_arena *arena, wri_arena *bulk);

/* ---- tracked pools -------------------------------------------------------------------------------------------- */

/*
 * Track a pool by name: the map keeps its record and its overrides from the next FULL map on (a map already held was built
 * without the name, so the pool reads as not found until the full map this call asks the monitor for arrives; that map may
 * carry the held epoch itself).
 * Adding a name already tracked returns its handle. WR_E_BUSY if map_pools names are tracked, WR_E_TOOBIG for a name
 * above WRI_MAP_NAME_MAX, WR_E_INVAL for an empty name or maps disabled.
 */
WR_MUST_CHECK wr_status wri_mapstore_track(wri_mapstore *s, const uint8_t *name, size_t len, uint32_t *handle);

/* ---- driving it -------------------------------------------------------------------------------------------------- */

/*
 * Consume the monitor's map messages: at most one epoch of work per call and never more than *budget bytes of message
 * walked (the budget is decremented by what was done). Returns 1 if more work is ready (a message is still open or a
 * new one is waiting) so the scheduler runs again at once. Called from wr_client_run after the monitor step.
 * Raw MMonMap messages are released unread (the monitor client has already adopted them).
 */
int wri_mapstore_step(const wri_ctx *x, wri_mapstore *s, const wri_map_io *io, uint32_t *budget);

/* The time the store next wants to run (a rate-limited re-request), WR_DEADLINE_NONE if none. */
uint64_t wri_mapstore_deadline(const wri_mapstore *s);

/* ---- queries (no side effects but the cache and the workspace) ------------------------------------------------------ */

/* The held map, NULL before the first one (or when maps are disabled). Valid until the next step that adopts an epoch. */
const wri_osdmap *wri_mapstore_map(const wri_mapstore *s);
/*
 * Pool record of tracked pool `h` in the held map (a pool the client cannot use is still returned, with its status
 * in the record: only target refuses it). WR_E_INVAL (handle not tracked, checked first), WR_E_MAP_NONE (no map yet),
 * WR_E_POOL_NOT_FOUND (name not in the map, or tracked after the held map was built). The pointer is into the held slot.
 */
WR_MUST_CHECK wr_status wri_mapstore_pool(const wri_mapstore *s, uint32_t h, const wri_map_pool **out);
/*
 * Placement of a PG or an object in a tracked pool against the held map, through the cache. Fills the public wr_target:
 * epoch, pool id, ps, pg_seed, up / acting sets and primaries, and the address of the acting primary (family 0 when the
 * OSD has no msgr2 address). *out is cleared first (primaries -1) and is filled only on success, except that
 * WR_E_PLACE_UNMAPPABLE (the acting set is empty) leaves epoch, pool id, ps and pg_seed in it so the caller can tell
 * which epoch said so. Statuses: those of wri_mapstore_pool, the pool's own status when it is not WR_OK, those of
 * wri_place_hash and wri_place_pg, WR_E_MAP_CORRUPT for a result that does not fit a wr_target, and for target_pg
 * WR_E_RANGE when pg_seed is not below the pool's pg_num (no such PG: a caller holding a seed from an older epoch re-targets by object). For target_pg `ps` is the seed itself.
 */
WR_MUST_CHECK wr_status wri_mapstore_target_pg(wri_mapstore *s, uint32_t h, uint32_t pg_seed, wr_target *out);
WR_MUST_CHECK wr_status wri_mapstore_target(wri_mapstore *s, uint32_t h, const wri_oid *o, wr_target *out);
/* Copy out the counters (and the slot usage of the held map). */
void wri_mapstore_stats(const wri_mapstore *s, wr_map_stats *out);

/* ---- internal to wri_mapstore.c and wri_mapstore_msg.c --------------------------------------------------------------- */

/* Record `cause` (NULL: a bare WR_E_MAP_RESYNC) as the reason a full map is wanted and set want_full. */
void wri_mapstore_need_full(wri_mapstore *s, const wr_errinfo *cause);

#endif /* WRI_MAPSTORE_H */
