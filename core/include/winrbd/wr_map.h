/* SPDX-License-Identifier: MIT */
/*
 * wr_map.h - the OSD map and object placement, as a host or the object client sees them.
 *
 * The engine decodes the monitor's maps itself when wr_config.map_slot_bytes is non-zero (then raw map
 * delivery, wr_client_mapmsg_peek, is no longer used and WR_EV_MAPMSG is not raised). The client TRACKS the
 * pools it uses by name; the map keeps only those (docs/design/core-architecture.md 15.3). Everything here
 * is a read-only query on the held map and returns plain structs: nothing points into the map, so a result stays
 * valid when the next epoch is adopted (and is then simply stale: compare `epoch`).
 *
 * Not thread-safe, like the rest of the client (architecture 3.3): call from the thread that owns the client.
 * Statuses: WR_E_MAP_NONE until the first map has been adopted; WR_E_POOL_NOT_FOUND when a tracked pool's name is
 * not in the map; the pool's own status (WR_E_POOL_UNSUPPORTED, WR_E_CRUSH_NO_RULE, ...) when it cannot be used.
 * A NULL or destroyed client, and a client created without the map module (map_slot_bytes == 0), are WR_E_INVAL on every
 * call below (wr_client_map_stats then reports zeros). Outputs are cleared on every failure; the one partial answer is
 * WR_E_PLACE_UNMAPPABLE from the two target calls, which keeps `epoch`, `pool_id`, `ps` and `pg_seed` of the wr_target
 * (so the caller knows which epoch said "nobody serves this PG") and nothing else.
 *
 * Events: WR_EV_MAP (wr_client.h) says an epoch was adopted; it is coalesced, so one pending event carries the newest
 * epoch however many epochs a message held. WR_EV_MAP_RESYNC says a full map was asked for (informational). A first
 * map that can never be used (WR_E_MAP_BUDGET, WR_E_MAP_VERSION) raises WR_EV_FATAL and ends the client (WR_CS_FAILED).
 * While the monitor session is down the held map keeps answering.
 */
#ifndef WR_MAP_H
#define WR_MAP_H

#include "wr_client.h"
#include "wr_err.h"
#include "wr_types.h"

#define WR_MAP_REP_MAX 16u /* replicas in a wr_target; pools with a larger size are unsupported */

/* Handle of a tracked pool: the index in the order of wr_client_pool_track calls. */
typedef uint32_t wr_pool_h;

/* pg_pool_t.flags bits a client acts on (the raw 64-bit flags are returned too). */
#define WR_POOL_F_HASHPSPOOL 0x1ull
#define WR_POOL_F_FULL 0x2ull
#define WR_POOL_F_FULL_QUOTA 0x400ull
#define WR_POOL_F_SELFMANAGED_SNAPS 0x2000ull
#define WR_POOL_F_POOL_SNAPS 0x4000ull /* the OSD would replace a writer's snapshot context with the pool's own */
#define WR_POOL_F_EIO 0x10000ull       /* every client op must fail with EIO */

/* OSDMap.flags bits (rados.h) */
#define WR_MAP_F_FULL 0x2u
#define WR_MAP_F_PAUSERD 0x4u
#define WR_MAP_F_PAUSEWR 0x8u

typedef struct wr_map_info {
	uint32_t epoch;
	uint32_t flags;   /* WR_MAP_F_* */
	uint32_t max_osd;
	uint32_t n_up;    /* OSDs that exist and are up */
	uint8_t fsid[16];
} wr_map_info;

typedef struct wr_pool_info {
	int64_t id;
	uint64_t flags;       /* WR_POOL_F_* and others, raw */
	uint32_t size;        /* replicas */
	uint32_t min_size;
	uint32_t pg_num, pgp_num;
	uint32_t last_force_op_resend; /* an op sent before this epoch must be resent */
	wr_status status;     /* WR_OK, or why this client cannot use the pool */
} wr_pool_info;

/* An object to place: byte strings (no NUL needed), any may be empty. RBD data objects use only `name`. */
typedef struct wr_object_id {
	const void *name;
	size_t name_len;
	const void *nspace;
	size_t nspace_len;
	const void *key; /* locator key, normally empty */
	size_t key_len;
} wr_object_id;

/* Where an object lives in the held map. */
typedef struct wr_target {
	uint32_t epoch;          /* the map epoch this answer is from */
	int64_t pool_id;
	uint32_t ps;             /* full 32-bit object hash: the "hash" field of an OSD op */
	uint32_t pg_seed;        /* ps after stable_mod: the PG is (pool_id, pg_seed) */
	uint8_t n_up, n_acting;
	uint8_t reserved[2];
	int32_t up[WR_MAP_REP_MAX];
	int32_t acting[WR_MAP_REP_MAX];
	int32_t up_primary;
	int32_t acting_primary;  /* the OSD an op goes to; -1 never occurs in a successful answer */
	wr_addr primary_addr;    /* msgr2 address of the acting primary; family 0 = the map has none for it */
} wr_target;

/* Counters of the map machinery, to tune budgets and for diagnostics. */
typedef struct wr_map_stats {
	uint32_t epoch;          /* held epoch, 0 = none */
	uint32_t newest_seen;    /* newest epoch the monitor announced */
	uint32_t n_full, n_inc;  /* full maps adopted, incrementals applied */
	uint32_t n_resync;       /* full-map re-requests caused by a gap or a failure */
	uint32_t n_bad;          /* entries that failed to decode or apply */
	uint32_t n_skipped;      /* entries not newer than the held epoch */
	uint32_t n_fsid_drop;    /* messages dropped for another fsid */
	uint32_t slot_bytes;     /* size of a map slot */
	uint32_t slot_used;      /* bytes the held map uses */
	uint32_t slot_used_max;  /* most bytes any map has used */
	uint32_t msg_bytes_max;  /* largest map message handled */
	uint32_t cache_hits, cache_misses;
	wr_status last_err;      /* status of the last failure, WR_OK if none */
	uint32_t n_msg_toobig;   /* map messages the monitor link discarded for being above wr_config.mon_msg_cap: such a map never reaches the store */
	uint32_t n_msg_bad;      /* map messages the monitor link discarded as undecodable or newer than the decoder */
} wr_map_stats;

/*
 * Track a pool by name (at most wr_config.map_pools of them). May be called before the first map arrives; the handle
 * stays valid for the life of the client. Calling it again with the same name returns the same handle.
 * WR_E_BUSY when the table is full, WR_E_TOOBIG for a name over 128 bytes, WR_E_INVAL for an empty or NULL name, a NULL
 * out, or when maps are disabled (map_slot_bytes == 0). A pool tracked after the first map reads as WR_E_POOL_NOT_FOUND
 * until the full map the engine then asks for arrives (a full map of the held epoch is accepted for that; a real monitor
 * answers the request with exactly that map). The call itself does no I/O and cannot wake the host: the request is made by
 * the next wr_client_run and sent by the one after it (the first returns more_work), so call wr_client_run after tracking
 * a pool on a running client; a host that only runs on socket events and timers waits for its next timer (keepalive_ms).
 */
WR_MUST_CHECK wr_status wr_client_pool_track(wr_client *c, const char *name, wr_pool_h *out);

WR_MUST_CHECK wr_status wr_client_map_info(const wr_client *c, wr_map_info *out);
WR_MUST_CHECK wr_status wr_client_pool_info(const wr_client *c, wr_pool_h h, wr_pool_info *out);

/* The first msgr2 address of an OSD and whether it is up; WR_E_RANGE for an id the map does not have. up may be NULL. */
WR_MUST_CHECK wr_status wr_client_osd_addr(const wr_client *c, int32_t osd, wr_addr *out, uint8_t *up);

/*
 * Place an object / a PG of a tracked pool in the held map. WR_E_PLACE_UNMAPPABLE when no OSD can serve the PG now (the
 * target then holds only its identification, see the top of this file); WR_E_TOOBIG when the object name, namespace and
 * locator key together are above 4096 bytes, or any of them cannot be counted in 32 bits (the bytes are not read); WR_E_RANGE from the PG call for a seed not below the pool's
 * pg_num; WR_E_INVAL for a NULL oid, or a length announced without a pointer.
 */
WR_MUST_CHECK wr_status wr_client_map_target(wr_client *c, wr_pool_h h, const wr_object_id *oid, wr_target *out);
WR_MUST_CHECK wr_status wr_client_map_target_pg(wr_client *c, wr_pool_h h, uint32_t pg_seed, wr_target *out);

void wr_client_map_stats(const wr_client *c, wr_map_stats *out);

#endif /* WR_MAP_H */
