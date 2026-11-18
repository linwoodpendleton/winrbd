/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_req.h - the object operation engine ("Objecter" role): a bounded table of object operations, each one MOSDOp message
 * against one object, with its target chosen from the OSD map, tids, resend on connection loss and map change, timeouts, EAGAIN,
 * backoff and cancellation. Design: docs/design/core-architecture.md section 23; rules: docs/spec/osd-ops.md 3.
 *
 * The owner (the RBD layer, wri_rbd.h) fills an operation slot, submits it, and later pulls it from the done list; nothing here calls
 * the owner. The operation names its object (pool handle + name), its operations, the data segment it sends (a pointer into the
 * owner's memory: a write buffer, or the control-call input buffer) and where the reply's data segment goes (the owner's read
 * buffer, or a control-call output buffer). It is encoded afresh at every transmission, so a resend after a map change carries the
 * new epoch, target and snapshot context at no extra memory.
 *
 * State machine of an operation (section 23.2):
 *
 *   FREE -> NEW -> { WAIT_MAP | HOMELESS | PAUSED | WAIT_SESS | QUEUED } -> SENT -> DONE -> FREE
 *
 *   WAIT_MAP   no map yet, or the pool is not (yet) in it
 *   HOMELESS   the PG has no usable OSD or the OSD has no address: wait for a newer map
 *   PAUSED     the map carries PAUSERD / PAUSEWR (HONOR_PAUSE) or the pool is full without FULL_TRY
 *   WAIT_SESS  the target OSD has no READY session yet (connecting, authenticating, cooling down, or no free session slot)
 *   QUEUED     ready to send (the transmit queue was full, or a backoff holds it)
 *   SENT       on the wire; a reply is awaited until deadline_ms
 *
 * Ordering and resend rules, in short (23.3 to 23.6): ops are sent in ascending tid order per session; a resend keeps the tid and
 * adds one to retry_attempt; a new tid is taken only after an EAGAIN reply; a write is never abandoned (23.7), only completed or
 * detached into a copy; a read may be dropped at any time.
 *
 * Buffers. The owner's data and output buffers are referenced by the connections (the transmit queue points into `data`, a reply is received into `out`), so
 * an op that leaves a session without that connection being reset (moved by a new map, held back with no primary) must not be answered or ended while the old
 * connection could still touch them: before the op is sent on another session, or ends without an answer, the session it left is reset if its queue is not
 * empty or it is receiving that op's reply (wri_or_quiet_prev). The same rule is what cancel applies to every session an op was sent on.
 *
 * Module osd-req: wri_osd_req.c (table, submit, done, release, completion), wri_osd_req_tgt.c (targeting, map changes, pause),
 * wri_osd_req_send.c (session handling, encode and send, replies, backoff, timeouts), wri_osd_req_zomb.c (cancel and zombies).
 */
#ifndef WRI_OSD_REQ_H
#define WRI_OSD_REQ_H

#include "wr_map.h"
#include "wri_osd_msg.h"
#include "wri_osd_sess.h"

/* ---- what the request engine needs from the map ----------------------------------------------------------------------- */

/* The queries of wr_map.h, as a function table: the engine glue implements them over wr_client_*; a test scripts them. */
typedef struct wri_osd_map_ops {
	void *ctx;
	uint32_t (*epoch)(void *ctx);                      /* held epoch, 0 = no map yet */
	uint32_t (*flags)(void *ctx);                      /* map flags (WR_MAP_F_*) of the held map */
	wr_status (*pool_info)(void *ctx, wr_pool_h h, wr_pool_info *out);
	wr_status (*target)(void *ctx, wr_pool_h h, const wr_object_id *oid, wr_target *out);
} wri_osd_map_ops;

/* ---- one operation --------------------------------------------------------------------------------------------------- */

typedef enum wri_op_state {
	WRI_OP_FREE = 0,
	WRI_OP_NEW,
	WRI_OP_WAIT_MAP,
	WRI_OP_HOMELESS,
	WRI_OP_PAUSED,
	WRI_OP_WAIT_SESS,
	WRI_OP_QUEUED,
	WRI_OP_SENT,
	WRI_OP_DONE
} wri_op_state;

#define WRI_LAST_NONE 0xffffu /* wri_osd_op.last_sess of an op with no live transmission (session indexes are below osd_sessions <= 65535) */
#define WRI_OPK_READ 0u   /* no operation of the message can write: READ flag, snapshot context ignored */
#define WRI_OPK_WRITE 1u  /* the message may write: WRITE flag, FULL_TRY, mtime, snapshot context */

#define WRI_OPF_CONTROL 0x01u   /* taken from the control reserve (ctl_ops) */
#define WRI_OPF_ZOMBIE 0x02u    /* the owner is gone: the data is the core's copy, the result is dropped (and the op freed) when it is answered */
#define WRI_OPF_NEWTID 0x04u    /* reserved: a fresh tid is taken when the EAGAIN reply is processed (the op is relinked at the tail then), so the flag is never set */
#define WRI_OPF_MIDRX 0x08u     /* a cancel found its reply being received: the session was reset first (kept for the statistics of that op) */
#define WRI_OPF_ALLOC 0x10u     /* internal: the slot is taken (wri_osdc_alloc) but not submitted yet */
#define WRI_OPF_INRING 0x20u    /* internal: DONE and still in the done ring (release waits for the pop) */

typedef struct wri_osd_op {
	uint8_t state;              /* wri_op_state */
	uint8_t kind;               /* WRI_OPK_* */
	uint8_t flags;              /* WRI_OPF_* */
	uint8_t n_ops;
	uint32_t owner;             /* the submitter's tag: opaque here (the RBD layer packs image, request slot and generation) */
	uint32_t next, prev;        /* submission (tid) order list; WRI_NIL ends it */
	uint64_t tid;               /* strictly increasing per client lifetime; kept across resends */
	wr_pool_h pool;             /* handle of the tracked pool of the object */
	uint8_t oid_len;
 	uint8_t oid[WRI_OSD_OID_MAX];
	uint16_t last_sess;         /* session of the latest transmission while that connection lives (WRI_LAST_NONE: none, or its connection is gone): the one session whose queue or receive path may still touch the owner's buffers (it sits in the padding after the name: the table stays at 576 bytes) */
	const wri_snapc *snapc;     /* write snapshot context at the time of each send (the image's current one), NULL = empty */
	/* data */
	const uint8_t *data;        /* the request's data segment (sum of ops[i].in_len bytes); stays valid until DONE or until detached */
	uint32_t data_len;
	uint8_t *out;               /* where the reply's data segment goes (NULL = discard); */
	uint32_t out_cap;           /* its capacity: a longer reply is a protocol error for this op */
	uint32_t out_stored;        /* bytes that landed there */
	/* placement of the latest targeting (while SENT it is the last transmission's: the resend decisions compare the new target with it; the address is the one of its session) */
	uint32_t sent_epoch;        /* map epoch of the last transmission, 0 = never sent */
	uint32_t pg_seed, hash;
	int32_t osd;                /* target primary of the last placement, -1 = none */
	uint32_t sess;              /* session index while WAIT_SESS / QUEUED / SENT, WRI_NIL otherwise */
	int32_t retry_attempt;      /* transmissions so far, minus one; goes into the message (0 before and at the first one) */
	int64_t pool_id;            /* the pool's id as the map answered it at the latest targeting: the pgid of the message, the backoff match */
	uint32_t sub_epoch;         /* held epoch when the op was submitted, 0 = no map yet */
	uint32_t zoff, zlen;        /* ZOMBIE: the op's block (data, snapshot context) in the zombie area */
	uint32_t tx_mask;           /* bit (session index & 31) for every session this op was transmitted on: their transmit queues may still point into `data` (cancel resets them first) */
	uint64_t submit_ms, sent_ms, deadline_ms;
	/* result */
	wr_status status;           /* DONE: WR_OK or the final status (wri_osd_errno_status of result, or why the engine gave up); EOPNOTSUPP is WR_E_OSD_NOENT only when the message holds a CALL
	                             * ("no such class or method"), for any other message it is WR_E_OSD_ERRNO: a data operation the OSD cannot do is never "the object is missing" */
	int32_t result;             /* the message result as sent by the OSD (negative errno) or 0 */
	uint64_t user_version;
	wri_osd_opd ops[WRI_OSD_OPS_MAX];
} wri_osd_op;

/* ---- the engine ------------------------------------------------------------------------------------------------------- */

/* Where WR_EV_IO_STALL / WR_EV_IO_RESUME go (the engine's event ring, or a test's log). `arg` is the OSD id (or 0xffffffff when there is none); for a
 * stall `err` says why (WR_E_TIMEOUT with a0 = the OSD id, the failure of a session, WR_E_OSD_MAP_STALE). Called from inside the engine's calls and
 * callbacks: it must only record. */
typedef void (*wri_osdc_event_fn)(void *ctx, wr_ev_kind kind, uint32_t arg, const wr_errinfo *err);

typedef struct wri_osdc {
	const wri_ctx *x;
	wri_osd_map_ops map;
	wri_osd_sess_tab sess;
	wri_osd_op *op;             /* max_ops slots */
	uint32_t n_op;
	uint32_t free_head, n_free, n_free_ctl; /* free list (linked through next); n_free_ctl = control reserve not yet claimed (ctl_ops minus control ops in use) */
	uint32_t head, tail;        /* submission order (ascending tid) of the live ops (NEW .. SENT) */
	uint32_t *done_ring;        /* completed ops in completion order: a ring of max_ops slot indices */
	uint32_t done_len, done_pos;
	uint64_t next_tid;          /* the counter of the next tid (starts at 1; tid = counter << 16 | slot) */
	uint32_t n_inflight;        /* ops in states NEW .. SENT (zombies included) */
	uint32_t inflight_bytes;    /* their payload: data_len + out_cap */
	uint32_t map_epoch_seen;    /* the epoch the last map pass ran against */
	uint32_t map_since_ms;      /* mono time (ms, low word) since which the map has not advanced while ops wait for it, 0 = fine */
	uint8_t *scratch;           /* osd_front_cap bytes: the encode buffer of one request front */
	/* zombies: copies of the data of cancelled writes that were already sent (bulk region) */
	uint8_t *zbuf;
	uint32_t zcap, zused, zmax;
	uint64_t n_done, n_resent, n_failed;
	uint32_t hiwater;
	uint8_t stalled;            /* WR_EV_IO_STALL raised and not yet resumed */
	uint8_t rerun;              /* the engine reset a session itself (cancel, wri_or_quiet_prev) and that session's other ops wait for a new one: the next step must run at once (deadline = now, step returns more) */
	wr_errinfo err;             /* first failure since the last success */
	/* ---- added by the module (the part above is the skeleton's) ---- */
	wri_osdc_event_fn event;
	void *event_ctx;
	uint32_t *sess_pass;        /* per session: the pass in which a transmit queue said BUSY (that session's pass stopped) */
	uint32_t pass;              /* number of wri_osdc_step calls */
	uint32_t n_ctl_used;        /* control ops in use (alloc to release, zombies included) */
	uint64_t retry_at_ms;       /* 0, or when an op left QUEUED by a full transmit queue is tried again */
	uint64_t sess_next_ms;      /* what wri_osd_sess_step answered last: the next idle close / cool-down end */
	uint32_t n_stray, n_stale, n_eagain, n_redirect, n_timeouts, n_blocked_held, n_unblock_resend, n_zombies, n_zombies_done;
	uint32_t n_quiesced;        /* sessions reset because an op left them while they still referenced its buffers (wri_or_quiet_prev) */
} wri_osdc;

/* Arena and bulk bytes (the op table, the done ring, the scratch, the sessions; the zombie area). 0 and 0 when osd_sessions is 0; WR_E_INVAL for a
 * configuration the engine cannot use (max_ops 0, ctl_ops not below max_ops, op_timeout_ms 0, what wri_osd_sess_mem refuses). */
WR_MUST_CHECK wr_status wri_osdc_mem(const wr_config *cfg, size_t *arena_bytes, size_t *bulk_bytes);
/* Carves the op table and the sessions (the session table's link is `link`; its upper-layer callbacks are this module's). x and map must outlive the
 * engine. The map ops need all four functions (WR_E_INVAL). */
WR_MUST_CHECK wr_status wri_osdc_init(wri_osdc *o, const wri_ctx *x, wri_arena *arena, wri_arena *bulk, const wri_osd_map_ops *map,
				      const wri_osd_link *link);
/* Where the stall / resume events go; NULL (the default) drops them. */
void wri_osdc_set_event(wri_osdc *o, wri_osdc_event_fn fn, void *ctx);

/* A zeroed op slot, or WRI_NIL (backpressure: max_ops in use, or only the control reserve is left and `control` is 0). */
uint32_t wri_osdc_alloc(wri_osdc *o, int control);
wri_osd_op *wri_osdc_at(const wri_osdc *o, uint32_t idx);
/*
 * Submit a filled slot: the owner has set kind, n_ops and ops[] (code, flags, in_len, off, len, cls lengths), pool, oid_len, oid, snapc, data,
 * data_len, out, out_cap, owner. Takes the tid, checks the shape (WR_E_INVAL: n_ops 0 or above WRI_OSD_OPS_MAX, sum of in_len != data_len, a data
 * length without a data pointer or an output capacity without an output pointer, a READ whose length is above the output capacity (the answer could not
 * land: a reply longer than the output costs the whole session), an empty or too long name, a kind other than READ / WRITE, a read-kind message with a write
 * operation; WR_E_UNSUPPORTED: an operation code outside the table of design 22.2; WR_E_STATE: not an allocated slot) and puts
 * the op in NEW; the slot is freed again by wri_osdc_release() after the owner pulled it from the done list. WR_E_BUSY when inflight_bytes_max would
 * be exceeded (the slot stays the owner's); WR_E_TOOBIG when the op alone is above it (it could never be admitted).
 */
WR_MUST_CHECK wr_status wri_osdc_submit(wri_osdc *o, uint32_t idx);
/* The oldest finished op (completion order), WRI_NIL if none. */
uint32_t wri_osdc_pop_done(wri_osdc *o);
/* Return a finished op that was popped (or a slot that was allocated and never submitted). Anything else (a live op, a zombie, a slot still in the done
 * ring, a free slot) is ignored. */
void wri_osdc_release(wri_osdc *o, uint32_t idx);

/*
 * Cancel an op (osd-ops.md 3.3 item 7). The owner's buffers (data, out, snapc) are free again as soon as WR_OK is returned.
 *   - A READ, and a WRITE that never left (no transmission so far), is dropped: it completes with WR_E_CANCELLED into the done list (pull and release it).
 *     If its reply is being received into its buffer (the session's rx_tid is its tid) the session is reset first (an orderly close, no cool-down) and the
 *     op carries WRI_OPF_MIDRX; the completion is in the done list when the call returns.
 *   - A WRITE that was transmitted at least once may have been applied and is not abandoned: its data and snapshot context are copied into the zombie area
 *     (first fit) and the op becomes a ZOMBIE (WRI_OPF_ZOMBIE): it is resent until answered and then freed without telling anybody. WR_OK is returned and
 *     NOTHING is put into the done list; the op is the engine's now and wri_osdc_count_owner() keeps counting it (by its owner tag) until it is answered.
 *     If the transmit queue of its session still references the owner's buffer the session is reset first (orderly); the copy is made at once, while the
 *     buffer is valid.
 *   - WR_E_BUSY: the copy does not fit the zombie area now. Nothing was changed; the op is live and completes normally, and the cancel may be repeated
 *     after the next completion. (The skeleton said BUSY also for the reset cases and a completion "by itself": here the reset is done inside the call and
 *     the cancel finishes in it, so those cases return WR_OK.)
 *   - An op that is already DONE or already a ZOMBIE: WR_OK, nothing changes. A free or never submitted slot: WR_E_STATE.
 * After WR_OK the owner must not touch the op, except to pull it from the done list when it is not a zombie (check WRI_OPF_ZOMBIE right after the call).
 */
WR_MUST_CHECK wr_status wri_osdc_cancel(wri_osdc *o, uint32_t idx);

/*
 * One pass: deadlines expire (the session is reset, its ops resent); a new epoch of the map -> retarget every op and resend those that must (section
 * 23.4); NEW / WAIT_MAP / HOMELESS / PAUSED ops are targeted; WAIT_SESS / QUEUED ops get a session and are sent in ascending tid order; the stale-map
 * rule of R-B5 (map_stale_ms) fails never-sent waiting ops; the session table's periodic work runs. Returns 1 if more work is ready (the op budget ran
 * out). `budget` bounds the messages encoded in one call (0 = none sent).
 */
int wri_osdc_step(wri_osdc *o, uint32_t budget);
/* Earliest time the engine wants to run without new input (an op deadline, a cool-down, a transmit retry, the map-stale limit), WR_DEADLINE_NONE if
 * none; the current time when an op is waiting to be targeted. */
uint64_t wri_osdc_deadline(const wri_osdc *o);

/* The ops of one owner tag range, for the RBD layer's cancel-all: number of non-FREE ops whose owner & mask == tag (zombies included). */
uint32_t wri_osdc_count_owner(const wri_osdc *o, uint32_t tag, uint32_t mask);

/* ---- internal to the osd-req sources (wri_osd_req*.c); no other module calls these ---------------------------------------- */

/* A call that carries large locals is kept out of its caller's frame: the sanitizer builds at -O0 count every temporary against the 1024 byte frame limit. */
#if defined(__GNUC__) || defined(__clang__)
#define OR_NOINLINE __attribute__((noinline))
#else
#define OR_NOINLINE
#endif

/* Outcome of a targeting (wri_osd_req_tgt.c). */
enum { WRI_PL_OK = 0, WRI_PL_WAIT_MAP, WRI_PL_HOMELESS, WRI_PL_PAUSED, WRI_PL_FAIL };
typedef struct wri_place {
	int outcome;                /* WRI_PL_* */
	wr_status status;           /* WRI_PL_FAIL: how the op ends */
	wr_target t;                /* WRI_PL_OK */
	wr_pool_info pi;            /* WRI_PL_OK, PAUSED, HOMELESS: the pool as the map answered */
} wri_place;

/* The target of op `op` in the held map, and what to do with it (23.3); no state is changed. */
void wri_or_place(const wri_osdc *o, const wri_osd_op *op, wri_place *p);
/* One op through the map pass (23.4): a new epoch, the first targeting of a new op, or the placement just before a transmission; may complete the op. `changed` /
 * `skipped`: the epoch differs from the one of the last pass / advanced by more than one. *p is the caller's scratch and holds the target when 1 is returned: the op is
 * WAIT_SESS then (sendable) and its placement fields are current. */
int wri_or_retarget(wri_osdc *o, uint32_t idx, int changed, int skipped, wri_place *p);
/* The map-stale rule (23.8): fail the never-sent ops that wait for the map for longer than map_stale_ms. */
void wri_or_stale(wri_osdc *o);
/* The time an op that waits for the map becomes eligible for the stale rule / the pool-not-found verdict (map_stale_ms after the later of its submission
 * and the last advance of the map), WR_DEADLINE_NONE when map_stale_ms is 0. */
uint64_t wri_or_stale_due(const wri_osdc *o, const wri_osd_op *op);

/* The common completion of an op (wri_osd_req.c): out of the submission list, accounting, into the done ring (a zombie: freed). status becomes op->status. */
void wri_or_complete(wri_osdc *o, uint32_t idx, wr_status st);
void wri_or_free_slot(wri_osdc *o, uint32_t idx);
void wri_or_unlink(wri_osdc *o, uint32_t idx);
void wri_or_link_tail(wri_osdc *o, uint32_t idx);
/* Remember the first failure (the engine's err) and raise events. */
void wri_or_note_err(wri_osdc *o, wr_status st, const char *what, uint64_t a0, uint64_t a1, uint64_t a2);
void wri_or_event(wri_osdc *o, wr_ev_kind kind, uint32_t arg, const wr_errinfo *err);
/* Payload bytes of an op as the budget counts them. */
uint32_t wri_or_bytes(const wri_osd_op *op);
/* An op leaves its session (SENT -> pre-send): the in-flight count of the session goes down. */
void wri_or_detach(wri_osdc *o, wri_osd_op *op);
/* The op table slot of a tid on session s in state SENT, or NULL (a stray). */
wri_osd_op *wri_or_find(wri_osdc *o, uint32_t s, uint64_t tid);
/* The session callbacks of the engine (wri_osd_req_send.c). */
void wri_or_up(wri_osdc *o, wri_osd_sess_up *up);
/* One op of the pass: target it (when it must be) and send it if it can go (wri_osd_req_send.c). */
void wri_or_send_one(wri_osdc *o, uint32_t idx, uint32_t budget, uint32_t *sent, int *more, int changed, int skipped);
/* Timeouts of SENT ops (wri_osd_req_send.c). */
void wri_or_timeouts(wri_osdc *o);
/* Zombie area (wri_osd_req_zomb.c). */
void wri_or_zombie_free(wri_osdc *o, wri_osd_op *op);
/* The op is about to be sent on session `keep` (or to end without an answer: WRI_NIL) while an earlier transmission left on another session: if that session
 * still has a transmit queue that may point into the op's data, or is receiving the answer into the op's output, it is reset first (orderly), so that no connection
 * touches the owner's buffers once the op is DONE. Only ever called from the engine's own step (never from a session callback). */
void wri_or_quiet_prev(wri_osdc *o, const wri_osd_op *op, uint32_t keep);

#endif /* WRI_OSD_REQ_H */
