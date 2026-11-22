/* SPDX-License-Identifier: MIT */
/*
 * wr_client.h - the client engine and its transport surface ("the pump").
 *
 * The engine is strictly sans-IO. It never opens a socket, reads a clock, allocates memory,
 * blocks, or calls the host (except the leaf callbacks of wr_host.h). A host:
 *
 *   - owns the sockets, timers, threads or main loop;
 *   - calls wr_client_run() with the current time whenever something happened or a deadline
 *     passed;
 *   - drains the action queue (connect / close / "bytes ready to send");
 *   - moves bytes: receives into the window the core names, sends what the core exposes;
 *   - pulls events and raw map messages.
 *
 * Threading contract: one owner. A wr_client is not thread-safe and not re-entrant: no
 * function here may be called from inside another call into the same client. A host with many
 * threads serialises them (one worker, or one lock) itself.
 *
 * Reference host loop (about 30 lines in the Linux harness, see architecture doc 2.3):
 *
 *   for (;;) {
 *       wr_clock now = host_clock();
 *       wr_run_result r = wr_client_run(c, &now, 256 * 1024);
 *       wr_action a;
 *       while (wr_client_next_action(c, &a)) host_do_action(&a);   // connect / close
 *       for each live connection id:
 *           n = wr_conn_tx_peek(c, id, iov, 8);  send(...);  wr_conn_tx_consume(c, id, sent);
 *           room = wr_conn_rx_window(c, id, &p); recv(fd, p, room);  wr_conn_rx_commit(c, id, got);
 *       wait_until(r.more_work ? now : r.next_deadline_ms, socket events);
 *   }
 */
#ifndef WR_CLIENT_H
#define WR_CLIENT_H

#include "wr_config.h"
#include "wr_err.h"
#include "wr_host.h"
#include "wr_key.h"
#include "wr_types.h"

typedef struct wr_client wr_client; /* opaque; lives at the start of the arena region */

/* ---- lifecycle ---------------------------------------------------------------------------- */

typedef struct wr_mem_req {
	size_t arena; /* small, hot: engine state, connections, buffers. Non-paged on Windows. */
	size_t bulk;  /* large, cold: monitor message buffers (later: OSDMap and CRUSH slots).
			 iPXE: umalloc(); the two regions may be the same allocation elsewhere. */
} wr_mem_req;

/* Pure arithmetic, overflow-checked. WR_E_ABI if cfg->size/abi do not match this build. */
wr_status wr_client_mem_required(const wr_config *cfg, wr_mem_req *out);

/*
 * Create a client inside the supplied regions. Nothing is allocated afterwards, ever. Copies
 * cfg, the host ops and the cluster spec (including the key) into the arena; the caller may
 * wipe its copies. WR_E_BUDGET if a region is too small, nothing is partly initialised then.
 * The client does nothing until the first wr_client_run().
 */
wr_status wr_client_create(const wr_config *cfg, const wr_host_ops *host, const wr_cluster_spec *cluster,
			   wr_mem_region arena, wr_mem_region bulk, wr_client **out);

/* Wipes all secrets in the arena. The host closes its sockets itself. */
void wr_client_destroy(wr_client *c);

/* ---- the pump ----------------------------------------------------------------------------- */

typedef struct wr_run_result {
	uint64_t next_deadline_ms; /* wake no later than this (monotonic); WR_DEADLINE_NONE = no timer */
	uint32_t more_work;        /* 1 = the work budget ran out, call again right away */
} wr_run_result;

/*
 * Advance every machine: expire deadlines, parse committed received bytes, run the monitor
 * client, queue output. work_budget bounds the bytes of CRC / crypto / copy work done in this
 * call (0 = default of 256 KiB) so a kernel worker or the iPXE main loop never stalls.
 */
wr_run_result wr_client_run(wr_client *c, const wr_clock *now, uint32_t work_budget);

typedef enum wr_act_kind {
	WR_ACT_NONE = 0,
	WR_ACT_CONNECT = 1,  /* open a TCP connection to addr, then wr_conn_connected() or wr_conn_closed() */
	WR_ACT_CLOSE = 2,    /* close the connection, then wr_conn_closed() (the slot is freed by that call) */
	WR_ACT_TX_READY = 3  /* the connection has bytes to send: wr_conn_tx_peek() */
} wr_act_kind;

typedef struct wr_action {
	wr_act_kind kind;
	wr_conn_id conn;
	wr_addr addr;         /* CONNECT only */
	uint32_t timeout_ms;  /* CONNECT only: give up and report wr_conn_closed() after this long */
} wr_action;

/* Returns 1 and fills *out, or 0 if the queue is empty. Actions are queued by wr_client_run(). */
int wr_client_next_action(wr_client *c, wr_action *out);

/* The TCP connection for id is established. */
void wr_conn_connected(wr_client *c, wr_conn_id id);

/*
 * The TCP connection is gone for any reason: connect failed, reset, EOF, or the host finished a
 * WR_ACT_CLOSE. host_errno is only carried into diagnostics (0 = orderly). Unknown or stale ids
 * are ignored.
 */
void wr_conn_closed(wr_client *c, wr_conn_id id, int host_errno);

/*
 * Receive. The window is where the next received bytes must be written; it may point into
 * a staging buffer or, later, straight into a caller's I/O buffer. Returns its size; 0 means
 * backpressure (do not read now; try after the next wr_client_run). The pointer stays valid
 * until the next wr_conn_rx_commit() or wr_client_run() for this client. wr_conn_rx_commit(n)
 * with n <= window records that n bytes arrived; it is O(1): all parsing happens in run.
 */
size_t wr_conn_rx_window(wr_client *c, wr_conn_id id, uint8_t **ptr);
void wr_conn_rx_commit(wr_client *c, wr_conn_id id, size_t n);

/* Convenience for push-style hosts (iPXE): copy up to n bytes through the window; returns bytes taken. */
size_t wr_conn_rx_push(wr_client *c, wr_conn_id id, const uint8_t *data, size_t n);

/*
 * Transmit. Fills up to max_iov gather elements with pending bytes and returns how many. The
 * memory stays valid until wr_conn_tx_consume() covers it or the connection closes. The host
 * sends as much as its transport accepts and reports it; partial acceptance is normal.
 */
size_t wr_conn_tx_peek(wr_client *c, wr_conn_id id, wr_iov *iov, size_t max_iov);
void wr_conn_tx_consume(wr_client *c, wr_conn_id id, size_t n);

/* ---- events and raw map messages ---------------------------------------------------------- */

typedef enum wr_ev_kind {
	WR_EV_NONE = 0,
	WR_EV_MON_SESSION_UP = 1,      /* authenticated monitor session, subscriptions sent */
	WR_EV_MON_SESSION_DOWN = 2,    /* session lost; the engine is hunting; err says why */
	WR_EV_AUTH_FAILED = 3,         /* cephx refused us; the engine keeps retrying with back-off */
	WR_EV_CLUSTER_UNREACHABLE = 4, /* a full round of monitors failed; still retrying */
	WR_EV_MAPMSG = 5,              /* a raw map message is waiting: wr_client_mapmsg_peek() */
	WR_EV_TICKETS_RENEWED = 6,
	WR_EV_FATAL = 7,               /* unrecoverable (bad config, no random, a first map that can never be decoded); err says why */
	WR_EV_MAP = 8,                 /* wr_map.h: a new OSD map epoch was adopted (event.epoch); re-target outstanding ops */
	WR_EV_MAP_RESYNC = 9,          /* wr_map.h: a gap or a bad map made the engine ask for a full map; err says why (informational) */
	WR_EV_IMAGE = 10,              /* wr_image.h: an image changed state (opened, failed, closed) or size; event.epoch is its slot */
	WR_EV_IO_STALL = 11,           /* wr_image.h: operations are unanswered (OSD session reset, OSD map stale); err says why; informational */
	WR_EV_IO_RESUME = 12           /* wr_image.h: the stall is over (an answer arrived); informational */
} wr_ev_kind;

typedef struct wr_event {
	wr_ev_kind kind;
	uint32_t epoch; /* WR_EV_MAPMSG: newest epoch in the message; WR_EV_MAP: the epoch adopted; WR_EV_IMAGE: the image slot; else 0 */
	wr_errinfo err; /* DOWN / AUTH_FAILED / UNREACHABLE / FATAL */
} wr_event;

int wr_client_next_event(wr_client *c, wr_event *out); /* 1 = filled, 0 = none */

/*
 * Raw map messages from the monitor, handed over undecoded (milestones 1 to 3; the engine consumes them itself, and
 * stops delivering them, when wr_config.map_slot_bytes is non-zero: see wr_map.h).
 * kind MONMAP: front is an MMonMap front (contains the MonMap blob). OSDMAP: front is an MOSDMap
 * front (fsid, incrementals, full maps, bounds). The bytes are the msgr2 front segment exactly
 * as received, already checksum-verified. front points into the bulk region and stays valid
 * until wr_client_mapmsg_release(); while a message is held the monitor connection may stall
 * (mapmsg_queue slots in the config).
 */
typedef enum wr_mapmsg_kind { WR_MAPMSG_MONMAP = 1, WR_MAPMSG_OSDMAP = 2 } wr_mapmsg_kind;

typedef struct wr_mapmsg {
	wr_mapmsg_kind kind;
	uint16_t msg_version, msg_compat; /* ceph_msg_header2 version / compat_version */
	uint32_t newest_epoch;            /* MONMAP: monmap epoch; OSDMAP: newest map epoch in the message */
	const uint8_t *front;
	size_t front_len;
} wr_mapmsg;

int wr_client_mapmsg_peek(wr_client *c, wr_mapmsg *out); /* 1 = oldest held message, 0 = none */
void wr_client_mapmsg_release(wr_client *c);             /* frees the slot of the message last peeked */

/* ---- state and diagnostics ---------------------------------------------------------------- */

typedef enum wr_client_state {
	WR_CS_CREATED = 0,
	WR_CS_HUNTING = 1,    /* no monitor session: connecting / authenticating / backing off */
	WR_CS_ACTIVE = 2,     /* authenticated monitor session, subscribed */
	WR_CS_FAILED = 3      /* WR_EV_FATAL was raised */
} wr_client_state;

wr_client_state wr_client_get_state(const wr_client *c);
const wr_errinfo *wr_client_last_error(const wr_client *c); /* first failure since the last success; never NULL */

/* Pool usage, to tune budgets from real runs. */
typedef struct wr_stats {
	uint32_t conns_in_use, conns_hiwater;
	uint32_t handshakes_in_use, handshakes_hiwater;
	uint32_t mapmsg_in_use, mapmsg_hiwater;
	uint32_t arena_used, bulk_used;
	/* Connection modes (secure mode, docs/design/core-architecture.md 34.8, 37), counted since create: connections that reached READY in each mode,
	 * and secure connections that ended on a connection-secret, nonce or tag failure (WR_E_M2_SECRET / WR_E_M2_NONCE / WR_E_M2_SEC_TAG). A tool proves
	 * "every connection was secure" with conns_crc == 0 and conns_secure != 0. The "msgr2 session ready" log record carries the mode too (its fourth number).
	 * READY is noticed at the end of the engine step that made a connection READY: a connection that is already failed or closed again by then (a peer that
	 * sends garbage right behind SERVER_IDENT, a session layer that closes at once) has its "session ready" record in the log and is not in these counters.
	 * Counters stop at 2^32 - 1. */
	uint32_t conns_secure, conns_crc, sec_failures;
} wr_stats;

void wr_client_get_stats(const wr_client *c, wr_stats *out);

#endif /* WR_CLIENT_H */
