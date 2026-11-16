/* SPDX-License-Identifier: MIT */
/*
 * wri_mon.h - monitor client: message codecs, MonMap, the session state machine.
 * Spec: docs/spec/mon-client.md. Scope of this milestone: connect, authenticate, subscribe to the
 * monmap and the osdmap, deliver the raw MMonMap and MOSDMap fronts to the consumer, keep the
 * session alive, hunt on failure, renew tickets. Decoding the OSDMap is a later module.
 *
 * Message codecs are pure functions over cursors (fuzzable alone). The session machine talks to
 * its connection through wri_m2_conn.h and to the auth layer through wri_cx.h.
 */
#ifndef WRI_MON_H
#define WRI_MON_H

#include "wr_client.h"
#include "wr_err.h"
#include "wr_key.h"
#include "wr_types.h"
#include "wri_cursor.h"
#include "wri_ctx.h"
#include "wri_cx.h"
#include "wri_m2_addr.h"
#include "wri_m2_conn.h"
#include "wri_mem.h"

/* ---- message types (mon-client.md 2.2) ------------------------------------------------------ */

#define WRI_MSG_MON_MAP 4u
#define WRI_MSG_MON_GET_MAP 5u
#define WRI_MSG_MON_SUBSCRIBE 15u
#define WRI_MSG_MON_SUBSCRIBE_ACK 16u
#define WRI_MSG_AUTH 17u
#define WRI_MSG_AUTH_REPLY 18u
#define WRI_MSG_OSD_MAP 41u

/* ---- codecs ----------------------------------------------------------------------------------- */

#define WRI_MON_MAXMONS 8u

typedef struct wri_monmap {
	uint8_t fsid[16];
	uint32_t epoch;
	uint32_t n_mons;                    /* stored */
	wri_eaddr addr[WRI_MON_MAXMONS];    /* the msgr2 (type 2) address of each monitor, in rank order */
	uint8_t rank_valid[WRI_MON_MAXMONS];/* 0 if the monitor had no msgr2 address */
} wri_monmap;

/*
 * Decode a MonMap blob (struct_v 6..10, skipping unknown trailing bytes by struct_len; refuse
 * struct_compat > 10 and struct_v < 6: WR_E_MON_MAP_VERSION). Keeps only the first dialable msgr2
 * address (family set, port non-zero) of each monitor. WR_E_MON_NO_V2_ADDR if no monitor has one.
 */
WR_MUST_CHECK wr_status wri_monmap_decode(const uint8_t *p, size_t n, wri_monmap *out);

/* MMonMap front: u32 length + MonMap bytes. Returns the blob without decoding it. */
WR_MUST_CHECK wr_status wri_mmonmap_front(const uint8_t *front, size_t n, const uint8_t **monmap, size_t *monmap_len);

/* MMonGetMap: empty front. MMonSubscribe v3: map<string, {start u64, flags u8}>, then hostname string. */
typedef struct wri_sub_item {
	const char *what; /* "monmap", "osdmap" */
	uint64_t start;
	uint8_t flags;    /* 0 = continuous, 1 = ONETIME */
} wri_sub_item;
void wri_mmonsubscribe_encode(wri_wr *w, const wri_sub_item *items, size_t n, const char *hostname);

/*
 * MOSDMap v4 front, header fields only (no map decoding): fsid, the epoch range of the
 * incrementals and full maps present, the trim bound and newest_map. The map blobs are stepped over
 * by their length and not located: the consumer re-walks the raw front itself. Rejects header
 * version < 2 and a non-empty removed-snaps block (WR_E_MON_PROTO). Only counts and ranges are
 * extracted; every count is capped.
 */
typedef struct wri_mosdmap_info {
	uint8_t fsid[16];
	uint32_t n_incremental, n_full;
	uint32_t first_epoch, last_epoch; /* over incrementals and full maps present, 0 if none */
	uint32_t newest_map;
	uint32_t oldest_map;
} wri_mosdmap_info;
WR_MUST_CHECK wr_status wri_mosdmap_info_decode(const uint8_t *front, size_t n, uint16_t msg_version, wri_mosdmap_info *out);

/* MAuth / MAuthReply wrappers for in-session renewal (cephx.md 2.11). */
void wri_mauth_encode(wri_wr *w, uint32_t protocol, const uint8_t *payload, size_t n, uint32_t monmap_epoch);
typedef struct wri_mauth_reply {
	uint32_t protocol;
	int32_t result;
	uint64_t global_id;
	const uint8_t *payload;
	uint32_t payload_len;
} wri_mauth_reply;
WR_MUST_CHECK wr_status wri_mauth_reply_decode(const uint8_t *front, size_t n, wri_mauth_reply *out);

/* ---- session state machine ------------------------------------------------------------------ */

/*
 * The machine drives ONE monitor session at a time (mon-client.md 3.2, 3.3, 3.5, 3.6, 3.7, 3.8,
 * architecture 8.3). It never touches a connection directly: it asks the owner for one through
 * wri_mon_link, receives the connection's events through the wri_m2_upper table of wri_mon_upper()
 * (whose context pointer is the wri_mon), and does all of its own work inside wri_mon_step().
 * The callbacks only record what happened (and route message bytes into slots); sending messages,
 * raising events, timers and the hunting policy live in step.
 *
 * Source layout: wri_mon.c (init, the upper-layer table, consumer calls, ticket renewal),
 * wri_mon_hunt.c (step, hunting and back-off, session set-up, keepalive), wri_mon_maps.c (routing and
 * applying MMonMap / MOSDMap, the slots, subscriptions).
 */

typedef enum wri_mon_state {
	WRI_MON_IDLE = 0,
	WRI_MON_HUNT_WAIT,    /* no session: backing off, or about to open the next rank */
	WRI_MON_CONNECTING,   /* connection open, handshake in progress */
	WRI_MON_SYNC,         /* READY: MMonGetMap and MMonSubscribe sent (or being sent), waiting for the first MMonMap */
	WRI_MON_ACTIVE,
	WRI_MON_RENEW         /* in-session MAuth outstanding */
} wri_mon_state;

/* A bulk slot holding one raw map message. kind 0 = free; a filled slot is "held" once the consumer peeked it. */
typedef struct wri_mapslot {
	uint8_t kind;          /* 0 free, WR_MAPMSG_* when filled */
	uint8_t held;          /* handed to the consumer, waiting for release */
	uint8_t notified;      /* WR_EV_MAPMSG was raised for it */
	uint8_t reserved8;
	uint16_t msg_version, msg_compat;
	uint32_t newest_epoch;
	uint32_t len;
	uint32_t order;        /* delivery order, strictly increasing */
	uint8_t *buf;          /* mon_msg_cap bytes in the bulk region */
} wri_mapslot;

#define WRI_MON_MAXSLOTS 4u
#define WRI_MON_NO_SLOT 0xffffu     /* wri_mon.conn_slot: no monitor connection */
#define WRI_MON_FSID_MAX 3u         /* consecutive fsid mismatches that end the session (WR_E_MON_FSID) */
#define WRI_MON_RENEW_AGAIN_MAX 3u  /* back-to-back MAuth rounds before a renewal waits (the "again" loop) */
#define WRI_MON_RETRY_MS 10u        /* retry time after a send found the transmit queue full */
#define WRI_MON_MIN_WAIT_MS 10u     /* floor of the effective back-off minimum, whatever the config says */
#define WRI_MON_DEFAULT_PORT 3300u
/* Highest message header version each decoder here understands; a message whose compat_version is above it is refused (mon-client.md 2.1). */
#define WRI_MMONMAP_MAX_VERSION 1u
#define WRI_MOSDMAP_MAX_VERSION 4u
#define WRI_MAUTHREPLY_MAX_VERSION 1u

typedef struct wri_mon {
	const wri_ctx *x;             /* the engine's context (kept for the upper-layer callbacks) */
	wri_mon_state st;
	uint8_t rank;                 /* index into addrs of the NEXT monitor to try */
	uint8_t cur_rank;             /* index of the monitor of the current / last connection */
	uint8_t n_addrs;
	uint8_t from_monmap;          /* addrs came from a MonMap */
	uint8_t failed_in_round;      /* ranks that failed since the last success (a full round raises UNREACHABLE) */
	uint8_t have_monmap;          /* a MonMap with epoch > 0 was applied */
	uint8_t fsid_known;           /* fsid below is valid (cluster spec or learned) */
	uint8_t fsid_bad;             /* consecutive fsid mismatches */
	uint8_t fsid[16];
	wri_eaddr addrs[WRI_MON_MAXMONS]; /* from the cluster spec, replaced by the monmap once received */
	wri_eaddr cur_addr;           /* the address dialled by the current / last connection */
	uint32_t monmap_epoch;        /* held */
	uint32_t osdmap_have;         /* newest osdmap epoch received (the consumer applies in order) */
	uint32_t sub_osdmap_start;    /* start epoch for the next (re)subscription: 0 on the first session */

	/* hunting and timers (ms of the monotonic clock) */
	uint32_t min_wait_ms, max_wait_ms; /* effective back-off bounds */
	uint32_t backoff_ms;          /* base of the next wait; doubles on every failed attempt */
	uint64_t hunt_at_ms;          /* HUNT_WAIT: open the next rank at this time */
	uint64_t conn_deadline_ms;    /* CONNECTING / SYNC guard: the connection never got going */
	uint64_t active_since_ms;
	uint64_t next_ping_ms, ping_since_ms; /* keepalive: next KEEPALIVE2 / oldest unanswered one */
	uint64_t renew_at_ms;         /* cached wri_cx_next_renew_ms, WR_DEADLINE_NONE if none */
	uint64_t renew_hold_ms;       /* no renewal before this time (after the "again" cap) */
	uint64_t renew_deadline_ms;   /* RENEW: no MAuthReply by then = failed */
	uint64_t deadline_ms;         /* the earliest time step() wants to run again (cached by step) */
	uint32_t ka_seen;             /* KEEPALIVE2_ACK count of the connection last looked at */
	uint8_t ping_out;             /* a KEEPALIVE2 is unanswered */
	uint8_t ka_on;                /* keepalives are sent (the link has the hook and keepalive_ms != 0) */
	uint8_t renew_rounds;

	/* per-session flags */
	uint16_t conn_slot;           /* connection index in the client, WRI_MON_NO_SLOT none */
	uint8_t ev_ready, ev_closed;  /* set by the callbacks, consumed by step */
	uint8_t need_getmap, need_sub, resub; /* messages still to send */
	uint8_t up;                   /* SESSION_UP raised for this session */
	uint8_t got_monmap;           /* a valid MonMap arrived on this session */
	uint8_t stable;               /* ACTIVE for keepalive_ms: the session counts as a success */
	uint8_t stalled;              /* plan() answered WR_E_BUSY and has not been satisfied since */
	uint8_t retry;                /* a send found the queue full: step again soon */
	uint8_t fsid_fail;            /* WRI_MON_FSID_MAX mismatches in a row */
	wr_errinfo close_err;         /* what the connection reported (ev_closed) */

	/* map slots */
	wri_mapslot slot[WRI_MON_MAXSLOTS];
	uint32_t nslots;
	uint32_t order_next;
	uint32_t slot_hiwater;        /* most slots occupied at once (wr_stats.mapmsg_hiwater) */
	uint8_t plan_slot;            /* slot the message being received goes into, 0xff none */
	wri_monmap mm;                /* scratch of the MonMap decoder */
	wri_mosdmap_info info;        /* scratch of the MOSDMap header decoder */

	/* MAuth renewal buffers (bulk): the request payload / the reply, and the message front */
	uint8_t *abuf, *fbuf;
	uint32_t abuf_cap;
	uint32_t ar_len;              /* MAuthReply front waiting in abuf (0 none) */
	uint8_t plan_auth;            /* the message being received goes into abuf */
	wr_status ar_err;             /* the answer to the renewal in flight cannot be used (too big, too new): WR_OK none; step fails the session */

	/* counters, to tune budgets and for tests */
	uint32_t n_sessions;          /* sessions that reached SESSION_UP */
	uint32_t n_toobig;            /* map messages larger than mon_msg_cap, discarded */
	uint32_t n_bad_msg;           /* map messages that did not decode, discarded */
	uint32_t n_fsid_drop;         /* map messages dropped for a wrong fsid */
	uint32_t n_dup_monmap;        /* MonMap with epoch <= held, ignored */
	uint32_t n_ignored;           /* messages of other types, discarded */
	uint32_t n_opens;             /* link.open calls that were accepted */
	wr_errinfo err;               /* why the last session ended or failed to start; cleared when a session is stable */
} wri_mon;

/*
 * Bulk bytes the monitor client needs (mapmsg_queue slots of mon_msg_cap, plus two small renewal
 * buffers), and init. The bulk arena is a second wri_arena over the host's bulk region. Like
 * wri_cx_client_mem the size is the plain wri_arena_plan sum: the owner adds WRI_ARENA_SLACK once.
 * WR_E_INVAL for mapmsg_queue outside 1..WRI_MON_MAXSLOTS or a mon_msg_cap below 64; init also
 * WR_E_MON_NO_V2_ADDR when the cluster spec has no usable monitor address, WR_E_BUDGET when the arena is
 * too small. On failure *m is zero.
 */
wr_status wri_mon_bulk_mem(const wr_config *cfg, size_t *bulk_bytes);
WR_MUST_CHECK wr_status wri_mon_init(wri_mon *m, const wri_ctx *x, wri_arena *bulk, const wr_cluster_spec *spec);

/*
 * Events the session machine needs from the client, and what it asks of it. The client owns the
 * connection table; the monitor client asks for exactly one monitor connection at a time through
 * these hooks (kept as a small vtable so the machine is testable with a fake link). `slot` is the
 * index the connection has in the client's table (wri_m2_conn.slot), the same value open() returned:
 * the upper-layer callbacks identify their connection by it.
 */
typedef struct wri_mon_link {
	void *ctx;
	/* Open a connection to addr; returns WR_OK and the slot, or WR_E_BUSY if none is free. */
	wr_status (*open)(void *ctx, const wri_eaddr *addr, uint16_t *slot);
	/* Close it (wri_m2_conn_close). The machine forgets the slot before calling and ignores the callbacks of it. */
	void (*close)(void *ctx, uint16_t slot, wr_status why);
	/* Send a MESSAGE on the monitor connection (wri_m2_conn_send_message; WR_E_BUSY = retry later). */
	wr_status (*send)(void *ctx, uint16_t slot, const wri_m2_msg_out *m);
	/* Raise a public event. */
	void (*event)(void *ctx, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *err);
	/* KEEPALIVE2 with this stamp (wri_m2_conn_send_keepalive; WR_E_BUSY = retry later). NULL: no keepalives are sent. */
	wr_status (*keepalive)(void *ctx, uint16_t slot, uint32_t sec, uint32_t nsec);
	/* KEEPALIVE2_ACK frames the connection received so far (wri_m2_conn.n_ka_ack). NULL: no ack timeout. */
	uint32_t (*keepalive_acks)(void *ctx, uint16_t slot);
} wri_mon_link;

/*
 * The upper-layer table the monitor client gives its connection (plan / message / ready / closed);
 * the context pointer of the connection must be the wri_mon. plan() routes MMonMap and MOSDMap fronts
 * into the bulk slots (WR_E_BUSY when all are occupied: the connection stalls, nothing is dropped),
 * the MAuthReply of a pending renewal into the renewal buffer, and discards everything else; a front
 * above mon_msg_cap is discarded and counted (WR_E_MON_MSG_TOOBIG) and the session keeps running. A map
 * message whose header compat_version is above WRI_MMONMAP_MAX_VERSION / WRI_MOSDMAP_MAX_VERSION is discarded
 * the same way (counted in n_bad_msg). A MAuthReply for the renewal in flight that cannot be read (compat above
 * WRI_MAUTHREPLY_MAX_VERSION, empty, above the renewal buffer) is not stored: step ends the session with
 * WR_E_MON_PROTO / WR_E_MON_MSG_TOOBIG at once instead of waiting for the reply timeout.
 */
const wri_m2_upper *wri_mon_upper(void);

/*
 * Drive timers and the hunting policy; call every run, after the connection steps. cx may be NULL
 * (no renewal and no ticket bookkeeping then). Never calls a link hook while a callback is running.
 */
void wri_mon_step(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link);

/* Earliest deadline of the monitor client, WR_DEADLINE_NONE if none (0 before the first step). */
uint64_t wri_mon_deadline(const wri_mon *m);

/*
 * The consumer asks for the oldest filled slot / frees the one it holds. peek is idempotent until
 * release (it keeps returning the oldest unreleased message); release frees the message peeked.
 */
int wri_mon_mapmsg_peek(wri_mon *m, wr_mapmsg *out);
void wri_mon_mapmsg_release(wri_mon *m);
/* Slots occupied now and the most ever occupied at once (for wr_client_get_stats). Either pointer may be NULL. */
void wri_mon_mapmsg_stats(const wri_mon *m, uint32_t *in_use, uint32_t *hiwater);

/*
 * The consumer could not apply a map range: resubscribe the osdmap from `start` (0 = from scratch).
 * Takes effect at once on a live session (the cached deadline is cleared, so the next step sends it), otherwise
 * with the next one.
 */
void wri_mon_want_osdmap(wri_mon *m, uint32_t start);

/* ---- internal to the monitor client sources (wri_mon*.c); no other module calls these -------------- */

#define WRI_MON_LOSE_CONN_DONE 0x1u /* the connection has reported closed already: do not call link.close */

/* End the session (and the connection unless CONN_DONE): record why, raise DOWN / AUTH_FAILED / UNREACHABLE, schedule the next try.
 * why->status WR_OK = planned reconnect (a ticket renewal by new session), not a failure. */
void wri_mon_lose(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link, const wr_errinfo *why,
		  unsigned flags);
/* Build an errinfo and wri_mon_lose() it. */
void wri_mon_fail(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link, wr_status st, unsigned line,
		  const char *what, uint64_t a0, uint64_t a1, uint64_t a2);
#define WRI_MON_FAIL(x, m, cx, link, st, what, a0, a1, a2) \
	wri_mon_fail((x), (m), (cx), (link), (st), (unsigned)__LINE__, (what), (uint64_t)(a0), (uint64_t)(a1), (uint64_t)(a2))
/* now + d, saturating below WR_DEADLINE_NONE. */
uint64_t wri_mon_add_ms(uint64_t now, uint64_t d);

/* wri_mon_maps.c */
wr_status wri_mon_plan_msg(wri_mon *m, const wri_m2_hdr2 *hdr, const uint32_t seglen[3], wri_m2_sink sink[3]);
void wri_mon_on_msg(wri_mon *m, const wri_m2_hdr2 *hdr, const uint32_t stored[3]);
WR_MUST_CHECK wr_status wri_mon_send_getmap(const wri_mon_link *link, uint16_t slot);
WR_MUST_CHECK wr_status wri_mon_send_subscribe(const wri_mon *m, const wri_mon_link *link, uint16_t slot);
void wri_mon_notify_maps(wri_mon *m, const wri_mon_link *link);
void wri_mon_slots_reset_session(wri_mon *m);

/* wri_mon.c: ticket renewal over the session (MAuth / MAuthReply), called from step in ACTIVE / RENEW. */
void wri_mon_renew_step(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link);

#endif /* WRI_MON_H */
