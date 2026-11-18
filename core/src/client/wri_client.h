/* SPDX-License-Identifier: MIT */
/*
 * wri_client.h - the engine object behind the public wr_client API (wr_client.h).
 *
 * Owns the connection table, the handshake (pre-auth) pool, the cephx client, the monitor client,
 * the event ring and the scheduler wr_client_run(). Everything is carved from the host's regions at
 * create time (wr_client_mem_required computes the sizes from the modules' own *_mem() functions and
 * the same layout routine create uses); nothing is allocated afterwards.
 *
 * Pending host actions are DERIVED from per-connection flags, not queued: wr_client_next_action
 * scans the connection table (round-robin), so the output side cannot overflow. Events are a small
 * ring; if it overflows the oldest non-fatal event is dropped and a counter is incremented
 * (documented loss of informational events, never of data, never of WR_EV_FATAL).
 *
 * Source layout: wr_client.c (public lifecycle, run, events, state), wri_client_conn.c (connection
 * table, the host-facing wr_conn_* calls, derived actions, the monitor link hooks),
 * wri_client_mem.c (configuration check, memory layout, create-time carving), wri_client_map.c (the map store's
 * stage of a run and its io adapter over the monitor client), wr_map.c (the public map API, wr_map.h); with the OSD
 * client on (wr_config.osd_sessions != 0) also wri_client_osd.c (memory, create, the stage of a run, stats),
 * wri_client_osd_conn.c (the OSD link: connections with role OSD), wr_image.c (the public image API, wr_image.h) and
 * core/src/rbd/wri_rbd_step.c (the image layer's pass), see wri_client_osd.h.
 *
 * Memory rule: every allocation of the engine uses an alignment of at most 16 bytes, so the arena
 * bytes a create consumes do not depend on how the host's (16-byte aligned) base is aligned beyond
 * that, and wr_client_mem_required is exact: it equals wr_stats.arena_used / bulk_used after create.
 */
#ifndef WRI_CLIENT_H
#define WRI_CLIENT_H

#include "wr_client.h"
#include "wri_ctx.h"
#include "wri_cx.h"
#include "wri_m2_conn.h"
#include "wri_mem.h"
#include "wri_mapstore.h"
#include "wri_mon.h"

#define WRI_CLIENT_MAGIC 0x57524331u /* "WRC1" */
#define WRI_EVENT_RING 8u

#define WRI_CLIENT_CONNS_MAX 1024u        /* max_conns upper bound (the id carries slot + 1 in 16 bits) */
#define WRI_CLIENT_HANDSHAKES_MAX 1024u
#define WRI_CLIENT_RX_MIN 64u             /* smallest rx_buf_bytes (a preamble and a little more) */
#define WRI_CLIENT_CTL_MIN 64u
#define WRI_CLIENT_TX_MIN 256u            /* above the largest handshake frame (CLIENT_IDENT, 196 bytes) */
/*
 * The authentication payload that carries a ticket (AUTH_REQUEST_MORE with the held ticket of a reclaim, later the
 * OSD authorizer) is built in place in the upper half of the encode buffer (wri_m2_conn.h), so tx_buf_bytes must be
 * at least 2 * (ticket_cap + WRI_CLIENT_AUTH_SLACK) + WRI_CLIENT_TX_FRAME. A smaller buffer lets the first login
 * through and then fails every reconnect with a ticket in hand, which is why create refuses it up front.
 */
#define WRI_CLIENT_AUTH_SLACK 256u        /* request header, challenge proof, envelope framing around a ticket */
#define WRI_CLIENT_TX_FRAME 72u           /* frame preamble, CRC and epilogue around the payload */
#define WRI_CLIENT_PREAUTH_MIN 256u
#define WRI_CLIENT_DEFAULT_BUDGET (256u * 1024u)
#define WRI_CLIENT_CONNECT_GRACE_MS 1000u /* the engine's own connect deadline = the action timeout + this */

/* Per-connection host-facing flags (the derived action queue). */
#define WRI_CF_WANT_CONNECT 0x01u /* the connection waits for a TCP connect: emit WR_ACT_CONNECT once */
#define WRI_CF_CONNECT_SENT 0x02u /* WR_ACT_CONNECT was handed to the host (so the host owes a wr_conn_closed) */
#define WRI_CF_CLOSE_SENT 0x04u   /* WR_ACT_CLOSE was handed to the host */
#define WRI_CF_TX_NOTIFIED 0x08u  /* WR_ACT_TX_READY emitted for the current transmit queue contents */
#define WRI_CF_REBASE 0x10u       /* wr_conn_connected ran since the last run: re-base the handshake deadline */

typedef struct wri_cslot {
	wri_m2_conn conn;
	uint8_t flags;
	uint8_t in_use;
	uint64_t connect_deadline_ms; /* engine backstop for a host that never reports the connect; NONE if unset */
} wri_cslot;

struct wri_osdc;
struct wri_rbd;
struct wri_cosd;

struct wr_client {
	uint32_t magic;
	wri_ctx x;
	wr_client_state state;

	uint8_t *arena_base; /* the host's arena region and what create consumed (wiped by destroy) */
	size_t arena_used;
	size_t bulk_used;

	wri_cx_client cx;
	wri_mon mon;
	wri_mon_link link;     /* hooks the monitor client uses to drive connections */
	wri_mapstore map;      /* the OSD map store (enabled only when cfg.map_slot_bytes != 0, inert otherwise) */
	wri_map_io map_io;     /* what the store sees of the monitor client and the event ring */

	/* The OSD client and the image layer (wri_client_osd.h): all three NULL while osd_sessions == 0, then the engine is what it was
	 * apart from these pointers. osd and rbd point into the aux block `og` (which also holds the per-connection auth contexts and the
	 * image handles); the three are set by wri_client_osd_init and never change. */
	struct wri_osdc *osd;
	struct wri_rbd *rbd;
	struct wri_cosd *og;

	wri_cslot *slot;       /* x.cfg.max_conns entries */
	uint32_t n_slot;
	uint32_t step_cursor;  /* round-robin start of the connection steps (fairness under a work budget) */
	uint32_t act_cursor;   /* round-robin position of wr_client_next_action */

	wri_m2_preauth *pa;    /* x.cfg.max_handshakes entries; pa_used[] marks the ones in use */
	uint8_t *pa_used;
	uint32_t n_pa;

	uint32_t my_nonce;     /* random entity_addr nonce, drawn once at create */
	uint64_t global_seq;   /* strictly increasing across connections */

	wr_event ev[WRI_EVENT_RING];
	uint8_t ev_head, ev_len;
	uint32_t ev_dropped;   /* informational events lost to a full ring */

	wr_errinfo last_err;   /* first failure since the last success */
	wr_errinfo mon_err_seen; /* mon.err as last copied (to notice a new failure) */
	wr_stats stats;        /* hiwater marks and the create-time sizes; the in-use counts are live fields below */
	uint32_t pa_in_use;
};

/* ---- memory layout (wri_client_mem.c) ------------------------------------------------------------ */

typedef struct wri_layout {
	size_t ring, ctl, tx;      /* per connection buffers */
	size_t pa_stride;          /* one transcript buffer, preauth_cap rounded up to 16 */
	size_t pa_mem;             /* all transcripts: max_handshakes * 2 * pa_stride */
	uint32_t seg_cap_max;      /* cap of segments 1..3 of a connection */
	size_t arena;              /* bytes create takes from the arena region */
	size_t bulk;               /* bytes create takes from the bulk region */
} wri_layout;

/* Cap of segments 1..3 of a connection for this configuration (the largest op payload of the OSD client has to fit it). */
uint32_t wri_client_seg_cap(const wr_config *cfg);

/* Validate cfg (abi, size, ranges) and compute the layout. WR_E_ABI / WR_E_INVAL / WR_E_OVERFLOW. */
WR_MUST_CHECK wr_status wri_client_layout(const wr_config *cfg, wri_layout *lay);

/*
 * Carve and initialise the whole engine inside the two arenas (already sized by wri_client_layout;
 * the arenas' bases are 16-byte aligned). On any failure the caller wipes what was taken.
 */
WR_MUST_CHECK wr_status wri_client_carve(wri_arena *arena, wri_arena *bulk, const wr_config *cfg, const wri_layout *lay,
					 const wr_host_ops *host, const wr_cluster_spec *spec, uint32_t nonce,
					 wr_client **out);

/* ---- connections (wri_client_conn.c) --------------------------------------------------------------- */

/* Resolve a public connection id to its slot; NULL if stale, invalid or the slot is free. */
wri_cslot *wri_client_slot_of(wr_client *c, wr_conn_id id);

/* Fill c->link with the monitor link hooks (open / close / send / event / keepalive / acks). */
void wri_client_link_init(wr_client *c);

/*
 * Open a connection with the given role (WRI_ENTITY_MON: the cephx client's embedded handshake, WRI_ENTITY_OSD: the slot's own cephx handshake
 * context, wri_client_osd.h) in a free slot and handshake slot: the engine side of both links. WR_E_BUSY when no slot is free, a handshake slot
 * is not free or the engine has failed; WR_E_INVAL for a role the engine has no auth context for (OSD without the OSD client).
 */
WR_MUST_CHECK wr_status wri_client_conn_open(wr_client *c, uint8_t role, const wri_eaddr *addr, const wri_m2_upper *up, void *up_ctx,
					     uint16_t *slot_out);
/* The close and send hooks of both links (their signatures are the same in wri_mon_link and wri_osd_link). */
void wri_client_link_close(void *ctx, uint16_t slot, wr_status why);
wr_status wri_client_link_send(void *ctx, uint16_t slot, const wri_m2_msg_out *m);

/*
 * Housekeeping after the connections ran: hand back handshake slots whose connection let go of its
 * transcript, free slots whose connection ended before the host ever saw a connect (the host owes
 * no wr_conn_closed for those), enforce the engine's connect backstop. Idempotent.
 */
void wri_client_conn_housekeeping(wr_client *c);

/* A host connect was reported: the handshake deadline is re-based to the time of the next run. */
void wri_client_conn_rebase(wr_client *c);

/* Earliest wake-up wanted by the connections (handshake, stall retry, connect backstop). */
uint64_t wri_client_conn_deadline(const wr_client *c);

/* Close every live connection (fatal error). */
void wri_client_conn_close_all(wr_client *c, wr_status why);

/* Step every connection (rotating start, one shared work budget). Returns 1 if the budget ran out with work left. */
int wri_client_conn_step_all(wr_client *c, uint32_t *budget);

/* Fill the connection and handshake fields of a wr_stats. */
void wri_client_conn_stats(const wr_client *c, wr_stats *out);

/* ---- the OSD map stage (wri_client_map.c) ---------------------------------------------------------------- */

/* Point the store's io at the monitor client and the event ring (create time, after the store was initialised). */
void wri_client_map_io_init(wr_client *c);

/*
 * One run's map stage, after the monitor step: the store consumes the monitor's map messages (at most one epoch of
 * work, never fewer than one entry even when the connections used the whole budget, so a busy link cannot starve it).
 * A fatal first map ends the client the way a failed random source does (state WR_CS_FAILED, connections closed).
 * Returns 1 when more is ready. 0 and no effect when maps are disabled.
 */
int wri_client_map_step(wr_client *c, uint32_t budget);

/* The earliest time the store wants to run (a rate-limited full-map request), WR_DEADLINE_NONE if none or disabled. */
uint64_t wri_client_map_deadline(const wr_client *c);

/* ---- events (wr_client.c) ------------------------------------------------------------------------- */

/*
 * Queue a public event (used by the monitor client through its link and by the map store). WR_EV_MAP is coalesced: a
 * pending one is updated in place (newest epoch) instead of queued again, and like WR_EV_FATAL it is never the event
 * dropped when the ring is full.
 */
void wri_client_push_event(wr_client *c, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *err);

#endif /* WRI_CLIENT_H */
