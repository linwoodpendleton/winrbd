/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_sess.h - OSD sessions: a bounded table of msgr2 connections to OSDs, the cephx authorizer handshake they run, the
 * delivery of replies and backoffs to the request layer, and the MOSDBackoff table of each session.
 * Design: docs/design/core-architecture.md section 21.
 *
 * A session is "the connection to OSD n". It owns no memory of its own beyond the table the engine carved at create time (the
 * msgr2 connection slots stay in the engine's connection table, wri_client.h; a session only remembers the slot number). It
 * reaches the engine through the wri_osd_link function table (open, close, send ...), exactly as the monitor client reaches it
 * through wri_mon_link, so a test drives it with a scripted link, a real wri_m2_conn pair over sim_osd, or the whole engine.
 * The request layer (wri_osd_req.h) is its only user: it asks for a session by OSD id, sends messages on it and gets the replies
 * back through wri_osd_sess_up.
 *
 * Rules (section 21):
 *   - at most osd_sessions sessions; a session for a new OSD takes a free slot, else evicts the least recently used session that
 *     has nothing in flight (closing it), else the caller waits (WR_E_BUSY);
 *   - one authentication at a time per free handshake slot (max_handshakes, wri_client.h); no session opens while the engine holds no
 *     valid OSD ticket (WR_E_BUSY: the caller retries at the next run);
 *   - a lost session is reopened only after a cool-down (osd_connect_timeout_ms doubled up to 10 s per consecutive failure of that OSD)
 *     so a dead OSD costs one connect per cool-down, not one per run;
 *   - READY requires the connection features the message versions need (design 22.1): else the session closes with WR_E_OSD_VERSION;
 *   - on a connection every MESSAGE of type 43 (reply) and 61 (backoff) is delivered; type 41 (MOSDMap) and everything else is discarded
 *     (counted); a reply for a tid the request layer no longer waits for is discarded without storing its data (the sink is NULL).
 *
 * Re-entrancy. The wri_osd_sess_up callbacks run inside the connection's step (reply, bad_reply, unblock, ready, lost) or inside the
 * table's own calls (lost: wri_osd_sess_acquire when it evicts or re-addresses a session, wri_osd_sess_step, wri_osd_sess_reset). They
 * must only record what happened; they may call wri_osd_sess_send / wri_osd_sess_inflight / wri_osd_sess_blocked and read the session,
 * but never wri_osd_sess_acquire, wri_osd_sess_step or the connection's step, and the request layer does its resends and its own
 * resets from its step, not from a callback. The link's open must not call the upper table before it returned (a refused connection
 * reports itself at its next step, as wri_m2_conn does).
 *
 * Module osd-sess: wri_osd_sess.c (table, open, close, LRU, cool-down), wri_osd_sess_up.c (the wri_m2_upper table: plan / message /
 * ready / closed), wri_osd_sess_bo.c (the backoff table).
 */
#ifndef WRI_OSD_SESS_H
#define WRI_OSD_SESS_H

#include "wr_config.h"
#include "wr_err.h"
#include "wr_types.h"
#include "wri_ctx.h"
#include "wri_m2_addr.h"
#include "wri_m2_conn.h"
#include "wri_mem.h"
#include "wri_osd_msg.h"

/* ---- what a session needs from the engine ------------------------------------------------------------------------- */

typedef struct wri_osd_link {
	void *ctx;
	/* Open a connection (role OSD) to addr with this upper-layer table and context. WR_OK and the connection slot, or WR_E_BUSY when
	 * no connection or handshake slot is free (an old one is still closing): retry later. */
	wr_status (*open)(void *ctx, const wri_eaddr *addr, const wri_m2_upper *up, void *up_ctx, uint16_t *slot);
	/* Close it (wri_m2_conn_close); the table forgets the slot before calling and ignores callbacks of it afterwards. */
	void (*close)(void *ctx, uint16_t slot, wr_status why);
	/* Send a MESSAGE (WR_E_BUSY = the transmit queue has no room yet). data is referenced, not copied. */
	wr_status (*send)(void *ctx, uint16_t slot, const wri_m2_msg_out *m);
	/* 1 if the connection's transmit queue holds nothing the host has not consumed yet (so no data pointer is referenced). The table also
	 * asks it before it accepts a MOSDBackoff frame: the ACK_BLOCK is queued at once, so the frame waits (WR_E_BUSY from plan) until it is 1. */
	int (*tx_idle)(void *ctx, uint16_t slot);
	/* The connection's negotiated features (wri_m2_conn.features), 0 for a slot that is not READY. OPTIONAL (NULL): the table then reads the
	 * word from the connection that is passed to its ready callback. */
	uint64_t (*features)(void *ctx, uint16_t slot);
	/* 1 if the cephx client holds a usable OSD ticket now. */
	int (*have_ticket)(void *ctx);
	/* The ticket / handshake gate: 1 if a new authentication may start now (a free handshake slot). */
	int (*handshake_free)(void *ctx);
} wri_osd_link;

/* ---- what a session tells the request layer ------------------------------------------------------------------------ */

typedef struct wri_osd_sess_up {
	void *ctx;
	/* Where the data segment of the reply to `tid` on session s goes: *dst NULL (and *cap 0) discards it. Called when the reply's
	 * header arrives, before its bytes: only operations in state SENT on session s may get a sink. *n_ops is the number of
	 * operations of the message that was sent under that tid (the reply must echo exactly that many: a different count closes the
	 * session as a protocol error); 0 for a tid with no operation (nothing is checked then). A reply whose data segment is longer
	 * than *cap is a protocol error too (bad_reply for that tid): the bytes are read through and thrown away, never stored. */
	void (*sink)(void *ctx, uint32_t s, uint64_t tid, uint8_t **dst, uint32_t *cap, uint32_t *n_ops);
	/* A complete, verified reply (its data segment length equals the sum of the echoed payload lengths). `stored` = bytes that landed
	 * in the sink (0 when it was discarded). `rep` borrows the session's front buffer: valid during the call only. */
	void (*reply)(void *ctx, uint32_t s, uint64_t tid, const wri_mosdopreply *rep, uint32_t stored);
	/* A reply that did not decode (or whose data length does not add up): the session closes itself after this call. */
	void (*bad_reply)(void *ctx, uint32_t s, uint64_t tid, const wr_errinfo *why);
	/* The session reached READY: queued operations may be sent. */
	void (*ready)(void *ctx, uint32_t s);
	/* The session is gone (reset, failure, close, eviction): every operation SENT on it must be resent and every operation waiting for
	 * it must ask for a session again; its backoffs are already cleared and n_inflight is already 0 (do not call
	 * wri_osd_sess_inflight(-1) for the operations that are resent). why->status is WR_OK for a close the table or the owner asked for. */
	void (*lost)(void *ctx, uint32_t s, const wr_errinfo *why);
	/* A backoff was removed by an UNBLOCK: operations of that PG in the range must be sent again (design 21.5). */
	void (*unblock)(void *ctx, uint32_t s, int64_t pool, uint32_t pg_seed);
} wri_osd_sess_up;

/* ---- the table ------------------------------------------------------------------------------------------------------- */

/* One MOSDBackoff entry (osd-ops.md 3.7). Names longer than WRI_OSD_OID_MAX, a key or a namespace cannot be kept exactly: such an entry
 * is `coarse` and holds every request of its PG (safe: the UNBLOCK removes it by id). A coarse entry also stands for further BLOCKs of
 * its PG that find the table full: it keeps their ids (begin_len of them, 8 bytes each, little endian, in begin_oid), and is removed
 * when the last of its ids is unblocked. */
typedef struct wri_backoff {
	uint64_t id;
	int64_t pool;
	uint32_t pg_seed;
	uint32_t begin_hash, end_hash;
	uint64_t begin_snap, end_snap;
	uint8_t used;
	uint8_t coarse;
	uint8_t begin_max, end_max;
	uint8_t begin_len, end_len;       /* name lengths */
	uint8_t reserved8[2];
	uint8_t begin_oid[WRI_OSD_OID_MAX];
	uint8_t end_oid[WRI_OSD_OID_MAX];
} wri_backoff;

typedef enum wri_os_state {
	WRI_OS_FREE = 0,
	WRI_OS_COOLDOWN,  /* no connection; the slot remembers the OSD and when it may be tried again */
	WRI_OS_OPENING,   /* connection open, handshake in progress */
	WRI_OS_READY,
	WRI_OS_CLOSING    /* only while the table's own close call is running (the connection's closed callback is ignored then) */
} wri_os_state;

struct wri_osd_sess_tab;

typedef struct wri_osd_sess {
	struct wri_osd_sess_tab *tab; /* set at init: the upper-layer callbacks of the connection get this struct as their context */
	uint8_t state;                /* wri_os_state */
	uint8_t replied;              /* READY: at least one reply arrived (the fail streak was reset then) */
	uint8_t bo_lost;              /* a BLOCK could not be stored: an UNBLOCK of an unknown id still releases its PG */
	uint8_t rx_flags;             /* internal: state of the reply being received (WRI_OSRX_*) */
	uint8_t msg_version;          /* READY: the MOSDOp version this connection takes, WRI_MOSDOP_VERSION or WRI_MOSDOP_VERSION_V8 */
	uint8_t rx_n_ops;             /* internal: operations the request layer sent under rx_tid, 0 = not checked */
	uint8_t reserved8[2];
	int32_t osd;                  /* OSD id, -1 when free */
	wr_addr addr;                 /* the address the session was opened to: a map that gives the OSD another address closes it */
	uint16_t conn_slot;           /* the engine's connection slot while OPENING / READY, WRI_OS_NOSLOT otherwise */
	uint16_t n_backoff;           /* entries in use */
	uint32_t n_inflight;          /* operations SENT and not answered */
	uint32_t fail_streak;         /* consecutive failed attempts to this OSD (cool-down grows with it) */
	uint64_t cooldown_until_ms;   /* COOLDOWN: not before */
	uint64_t last_used_ms;        /* last send, reply or acquire (LRU) */
	uint64_t rx_tid;              /* tid of the reply whose data segment is being received into a sink, 0 = none (a cancel of that op resets the session) */
	uint64_t features;            /* READY: the negotiated word, the `features` field of every request */
	uint8_t *front;               /* osd_front_cap bytes: the front segment of the message being received */
	uint32_t front_len;           /* internal: front bytes announced for the frame in progress */
	uint32_t rx_data_len;         /* internal: data segment bytes announced for the frame in progress */
	wri_backoff *bo;              /* backoff_slots entries */
	wr_errinfo err;               /* first failure of the current attempt */
} wri_osd_sess;

#define WRI_OS_NOSLOT 0xffffu     /* conn_slot of a session without a connection */
#define WRI_OSRX_OVER 0x1u        /* rx_flags: the reply being received has a data segment that does not fit its destination: read through, reported as bad */

typedef struct wri_osd_sess_tab {
	const wri_ctx *x;
	wri_osd_link link;
	wri_osd_sess_up up;
	wri_osd_sess *s;              /* osd_sessions entries */
	uint32_t n;
	uint32_t hiwater;             /* most sessions OPENING or READY at once */
	uint32_t n_resets;            /* sessions that ended with a failure: a lost or refused connection, a timeout, a protocol error (not the orderly closes) */
	uint32_t n_backoff_blocks, n_backoff_overflow, n_osdmap_discarded, n_other_discarded;
	uint32_t n_opened;            /* connections opened */
	uint32_t n_evicted;           /* idle READY sessions closed to make room (LRU) */
	uint32_t n_idle_closed;       /* READY sessions closed by osd_idle_ms */
	uint32_t n_backoff_noack;     /* BLOCKs whose ACK_BLOCK could not be sent (queue full or an oversized entry); the hold stays */
	uint32_t n_replies;           /* verified replies delivered */
	uint32_t n_bad_replies;       /* replies that failed the checks (the session was closed) */
} wri_osd_sess_tab;

#define WRI_OSD_COOLDOWN_MAX_MS 10000u /* cap of the cool-down after repeated failures (design 21.3) */
#define WRI_OSD_FRONT_MIN 544u         /* smallest osd_front_cap the table accepts: the largest reply front (8 echoed operations, a 95 byte name: 533 bytes) and the largest exact backoff front (two 96 byte names: 307) must fit */

/* The feature bits one OSD connection needs (design 21.6, osd-ops.md 4.4): a bit with its incarnation marker is the pair as it is in the
 * negotiated word. READY needs every bit of WRI_OSDFEAT_NEED; without WRI_OSDFEAT_SQUID the session takes MOSDOp v8. */
#define WRI_OSDFEAT_OBJECTLOCATOR (1ull << 8)
#define WRI_OSDFEAT_PGID64 (1ull << 9)
#define WRI_OSDFEAT_RESEND_ON_SPLIT ((1ull << 21) | (1ull << 57))
#define WRI_OSDFEAT_NEW_OSDOP (1ull << 56)
#define WRI_OSDFEAT_NEW_OSDOPREPLY (1ull << 58)
#define WRI_OSDFEAT_SQUID ((1ull << 49) | (1ull << 57))
#define WRI_OSDFEAT_NEED (WRI_OSDFEAT_OBJECTLOCATOR | WRI_OSDFEAT_PGID64 | WRI_OSDFEAT_RESEND_ON_SPLIT | WRI_OSDFEAT_NEW_OSDOP | WRI_OSDFEAT_NEW_OSDOPREPLY)

/* Arena bytes for osd_sessions sessions with their front buffers and backoff tables (same plan / take pair as the other modules): the
 * session array, then all front buffers, then all backoff tables, each 16-byte aligned. 0 bytes for osd_sessions == 0. WR_E_INVAL for an
 * osd_front_cap below WRI_OSD_FRONT_MIN or a backoff_slots of 0 (a table with no room cannot hold a BLOCK at all). */
WR_MUST_CHECK wr_status wri_osd_sess_mem(const wr_config *cfg, size_t *arena_bytes);
/* x must outlive the table (the clock and the limits are read from it). link->features may be NULL (the connection passed to the ready
 * callback carries the word); every other hook of link and of up is required (WR_E_INVAL). */
WR_MUST_CHECK wr_status wri_osd_sess_init(wri_osd_sess_tab *t, const wri_ctx *x, wri_arena *arena, const wri_osd_link *link,
					  const wri_osd_sess_up *up);

/*
 * The session for OSD `osd` at `addr`, opening one if needed. WR_OK and *s: the session is OPENING or READY (the caller waits for
 * up->ready, or sends at once when wri_osd_sess_ready()). WR_E_BUSY: no usable slot now (all busy with operations in flight, the OSD
 * is cooling down, no OSD ticket, no handshake slot, the engine has no free connection): the caller keeps the operation in WAIT_SESS
 * and asks again at the next step. An existing session for the same OSD at another address is closed first (the OSD moved).
 */
WR_MUST_CHECK wr_status wri_osd_sess_acquire(wri_osd_sess_tab *t, int32_t osd, const wr_addr *addr, uint32_t *s);
int wri_osd_sess_ready(const wri_osd_sess_tab *t, uint32_t s);
/* The session struct of index s (NULL if out of range or the table is NULL): the request layer reads features, msg_version, osd, rx_tid. */
const wri_osd_sess *wri_osd_sess_at(const wri_osd_sess_tab *t, uint32_t s);
/* The index of a session struct of this table. */
uint32_t wri_osd_sess_index(const wri_osd_sess_tab *t, const wri_osd_sess *sess);
/* Send a MESSAGE on a READY session; WR_E_STATE otherwise, WR_E_BUSY when the transmit queue is full. Updates last_used_ms. */
WR_MUST_CHECK wr_status wri_osd_sess_send(wri_osd_sess_tab *t, uint32_t s, const wri_m2_msg_out *m);
/* Count an operation as SENT (+1) / answered or dropped (-1) on session s (inflight bookkeeping the LRU uses; the count never goes below 0).
 * A +1 also counts as use of the session. Ignored for a session without a connection. */
void wri_osd_sess_inflight(wri_osd_sess_tab *t, uint32_t s, int delta);
/* Reset a session now (timeout, protocol error, a cancel that must drop a referenced buffer): close the connection, clear the backoffs,
 * tell up->lost once. A why with a status other than WR_OK counts as a reset and starts a cool-down (the OSD is in doubt); NULL or WR_OK
 * is a deliberate close (a cancel): no penalty, the next acquire opens a new connection at once. Does nothing for a session without a
 * connection. */
void wri_osd_sess_reset(wri_osd_sess_tab *t, uint32_t s, const wr_errinfo *why);
/* 1 if the connection's transmit queue holds no unconsumed bytes (no data pointer of ours is referenced). */
int wri_osd_sess_tx_idle(const wri_osd_sess_tab *t, uint32_t s);
/* 1 if a backoff of session s holds a request at (pool, pg_seed, hash, oid): a coarse entry of that PG, or wri_mbackoff_covers over its
 * precise entries. The request's namespace is empty (the request layer never sets one). */
int wri_osd_sess_blocked(const wri_osd_sess_tab *t, uint32_t s, int64_t pool, uint32_t pg_seed, uint32_t hash, const uint8_t *oid,
			 uint32_t oid_len);

/* Periodic work: idle sessions are closed after osd_idle_ms (up->lost with status WR_OK), a session found in the transient CLOSING state is
 * freed. Returns the earliest time it wants to run again: the end of a running cool-down, the idle deadline of a READY session with
 * nothing in flight (WR_DEADLINE_NONE if none). A cool-down that has passed is not reported again: the next acquire of that OSD simply
 * reuses the entry (and keeps its streak). Called from the engine's run, after the connections ran. */
uint64_t wri_osd_sess_step(wri_osd_sess_tab *t);

/* The wri_m2_upper table every OSD connection is opened with; the connection's context pointer is the wri_osd_sess. */
const wri_m2_upper *wri_osd_sess_upper(void);

/* ---- internal to the osd-sess sources (wri_osd_sess*.c); no other module calls these ------------------------------------ */

/* End the connection of a session (OPENING / READY) and the session with it: link close (status of why), backoffs cleared, up->lost once.
 * orderly != 0: a close the table or the owner asked for (no fail streak, no cool-down, the entry becomes FREE). */
void wri_os_end(wri_osd_sess_tab *t, wri_osd_sess *s, const wr_errinfo *why, int orderly);
/* The connection reported its own end (closed callback): the same without the link close. */
void wri_os_lost(wri_osd_sess_tab *t, wri_osd_sess *s, const wr_errinfo *why);
/* Fill an errinfo (zeroed first) of module OSD. */
void wri_os_err(wr_errinfo *e, wr_status st, unsigned line, const char *what, uint64_t a0, uint64_t a1, uint64_t a2);
#define WRI_OS_ERR(e, st, what, a0, a1, a2) wri_os_err((e), (st), (unsigned)__LINE__, (what), (uint64_t)(a0), (uint64_t)(a1), (uint64_t)(a2))
/* Backoff table (wri_osd_sess_bo.c). */
void wri_os_bo_clear(wri_osd_sess *s);
/* A decoded MOSDBackoff front of session s (BLOCK / UNBLOCK / ACK_BLOCK). `front` holds the bytes the strings of `m` borrow from. */
void wri_os_bo_handle(wri_osd_sess_tab *t, wri_osd_sess *s, const wri_mbackoff *m);

#endif /* WRI_OSD_SESS_H */
