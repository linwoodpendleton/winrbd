/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_conn.h - one msgr2 client connection (lossy, crc or secure mode, revision 1): the state machine
 * from "TCP connected" to READY and the message flow after it. Spec: docs/spec/msgr2.md 3, 4.
 *
 * The connection knows nothing about cephx or the monitor protocol. Authentication goes through
 * the wri_auth_ops interface (implemented by auth/wri_cx.h, or by a stub in tests) and message
 * delivery through wri_m2_upper (implemented by the monitor client; later the OSD client).
 * It owns no memory: the client carves the ring, buffers and pre-auth slot from the arena and
 * binds them with wri_m2_conn_bind() before use.
 *
 * Callbacks (auth ops, upper ops) are synchronous, run inside wri_m2_conn_step(), and may call
 * wri_m2_conn_send_message() but never wri_m2_conn_step().
 *
 * Source layout: wri_m2_conn.c (lifecycle, plumbing, the step loop, failure), wri_m2_conn_hs.c
 * (banner to SERVER_IDENT), wri_m2_conn_msg.c (READY: MESSAGE, KEEPALIVE2, sending; the byte plumbing of the pump), wri_m2_conn_sec.c
 * (secure mode: the offer, the checks on AUTH_DONE, the switch, the wipe; docs/design/core-architecture.md 34).
 *
 * Secure mode (milestone 11). A connection is crc only until the owner hands it a secure slot (wri_m2_conn_set_secure): then AUTH_REQUEST
 * offers what the slot says, AUTH_DONE may answer any mode that was offered, and a secure answer switches both directions to the secure
 * framing at the frame boundary behind AUTH_DONE (34.4). Everything after that (our AUTH_SIGNATURE, the server's, CLIENT_IDENT,
 * SERVER_IDENT, the session) is sealed; the layers above (the auth ops, wri_m2_upper) see no difference. Every way a connection ends
 * (failure, close, the host reporting the socket gone, a new open() of the same slot) wipes the secure slot; the connection secret
 * itself exists in the auth layer until the key schedule has been made from it, and nowhere else.
 *
 * Backpressure. A frame whose answer does not fit into the transmit queue yet, or whose plan() says
 * WR_E_BUSY, is not lost: the connection keeps it as the held event, does no work on it, and asks
 * again at the next step (see wri_m2_conn_deadline). Nothing irreversible happens before the room is
 * known, so a retry never repeats an authentication step.
 *
 * Rules for the engine that owns the connection:
 *   - sizing: the frames that carry an authentication payload (AUTH_REQUEST, AUTH_REQUEST_MORE) are built
 *     in place in the upper half of the encode buffer while the transmit queue is empty, so tx_buf_bytes
 *     must be at least 2 * (largest payload) + 72 (the default profiles give an OSD authorizer 4 KiB
 *     and more), and at least 196 bytes (the largest handshake frame, CLIENT_IDENT); a frame that cannot fit fails the
 *     connection with WR_E_TOOBIG at once, never silently and never by a wait that runs into the timeout;
 *   - scheduling: step a connection when bytes were committed, when its wri_m2_conn_deadline() is due
 *     (handshake timeout, retry after backpressure) and after the host consumed transmit bytes of a
 *     stalled connection (the deadline becomes 0 then);
 *   - after wri_m2_conn_step() / on_connected() / close() left the state FAILED or CLOSING, up->closed has
 *     been called and c->pa is NULL: return the handshake slot (c->pa_slot) to the pool and emit the close;
 *     the one exception is a refused nonce inside wri_m2_conn_send_message / send_keepalive (secure mode only): the
 *     state is FAILED, c->pa is NULL and the secure slot is wiped, but up->closed is called by the next step, which
 *     wri_m2_conn_deadline() asks for at once;
 *     wri_m2_conn_on_closed() ends the life of the slot (state FREE) and reports the loss if nothing
 *     was reported before.
 */
#ifndef WRI_M2_CONN_H
#define WRI_M2_CONN_H

#include "wr_err.h"
#include "wr_types.h"
#include "wri_ctx.h"
#include "wri_m2_addr.h"
#include "wri_m2_ctl.h"
#include "wri_m2_frame.h"
#include "wri_mem.h"

typedef enum wri_m2_state {
	WRI_M2_FREE = 0,
	WRI_M2_CONNECTING,  /* host asked to connect; waiting for wr_conn_connected */
	WRI_M2_BANNER,      /* banner sent; waiting for the peer's */
	WRI_M2_HELLO,       /* HELLO sent; waiting for the peer's */
	WRI_M2_AUTH,        /* AUTH_REQUEST sent; AUTH_REPLY_MORE / AUTH_REQUEST_MORE rounds */
	WRI_M2_SIG,         /* AUTH_DONE processed, our signature sent; waiting for the peer's */
	WRI_M2_IDENT,       /* CLIENT_IDENT sent; waiting for SERVER_IDENT */
	WRI_M2_READY,       /* MESSAGE / KEEPALIVE2 flow */
	WRI_M2_FAILED,      /* error recorded; waiting for the host to close */
	WRI_M2_CLOSING      /* close requested; waiting for wr_conn_closed */
} wri_m2_state;

/* What the connection authenticates as. Every error an op returns is final: the connection fails with that
 * status (there is no "try again later" answer, WR_E_BUSY included). */
typedef struct wri_auth_ops {
	/* Build the AUTH_REQUEST auth_payload into out (monitor: mode byte, entity, global id;
	 * OSD: the authorizer). target_type is WRI_ENTITY_MON or WRI_ENTITY_OSD. out is a writer over the
	 * in-place scratch of the connection (half of its encode buffer): a payload that does not fit makes
	 * the connection fail with WR_E_TOOBIG. */
	wr_status (*begin)(void *a, uint8_t target_type, wri_wr *out);
	/* AUTH_REPLY_MORE received: consume `reply`, write the AUTH_REQUEST_MORE payload into out (at most
	 * WRI_M2_AUTH_BLOB_MAX bytes, else WR_E_TOOBIG). Called at most WRI_M2C_AUTH_ROUNDS times per
	 * connection; never repeated for one reply. */
	wr_status (*more)(void *a, const uint8_t *reply, size_t n, wri_wr *out);
	/* AUTH_DONE received: consume the final payload; the peer-assigned global_id and the mode
	 * the server chose (the connection already checked it is one we offered: crc). Called once. */
	wr_status (*done)(void *a, uint64_t global_id, uint32_t mode, const uint8_t *payload, size_t n);
	/* Raw session key bytes for AUTH_SIGNATURE (valid after done, read once right after it). The
	 * connection only ever offers cephx, so *len 0 / NULL is refused (WR_E_CRYPTO_KEY): a signature
	 * with the "no key" value (32 zero bytes) would prove nothing. */
	void (*session_key)(void *a, const uint8_t **key, size_t *len);
	/* The gid for CLIENT_IDENT (valid after done): -1 on a monitor connection whose AUTH_REQUEST asked
	 * for a NEW global id (0), the reclaimed id when it carried one, the monitor-assigned global id on
	 * an OSD connection (cephx.md 3.3 step 5, msgr2.md 3.5). */
	int64_t (*ident_gid)(void *a, uint8_t target_type);
	/* Secure mode (design 34.3). The 64-byte connection secret the AUTH_DONE payload carried: valid after done() succeeded in secure mode,
	 * read once by the connection right after it (the provider wipes its copy when the connection has taken it, or when the handshake
	 * ends). *len 0 / NULL when there is none. NULL member = this auth never has one: a secure AUTH_DONE then fails with WR_E_M2_SECRET.
	 * done() itself checks that a secure mode comes with a secret of at least WRI_M2S_SECRET_MIN bytes (WR_E_M2_SECRET) and that a crc mode
	 * comes without one (WR_E_AUTH_PROTO). Appended last so an implementation that does not know it keeps working. */
	void (*conn_secret)(void *a, const uint8_t **secret, size_t *len);
} wri_auth_ops;

typedef struct wri_m2_conn wri_m2_conn;
struct wri_m2s_slot; /* wri_m2_sec.h */

typedef struct wri_m2_upper { /* function table only; the context pointer lives in the connection */
	/*
	 * Header 2 of an incoming MESSAGE is verified and its segment lengths are known: say where
	 * each of front / middle / data goes (sink[i] for segment i+1; dst NULL = discard). Return
	 * WR_OK, WR_E_BUSY (no room right now: the frame is held and plan() is asked again at the next
	 * step, nothing is lost; backpressure) or another error (the connection fails). Unknown message
	 * types should be discarded (dst NULL), not failed (mon-client.md 2.2). A message() call follows a
	 * plan() call only if the frame completes: a frame that is aborted by its sender, or a connection
	 * that fails, leaves partly filled sinks and no message() call.
	 */
	wr_status (*plan)(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t seglen[3],
			  wri_m2_sink sink[3]);
	/* The frame is complete and every checksum passed; the sinks hold the segments. stored[i] is the
	 * number of bytes written into sink i (0 for a discarded segment). Called only for a message
	 * whose seq is greater than every seq seen so far (see wri_m2_conn.in_seq). */
	void (*message)(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t stored[3]);
	/* Session reached READY (SERVER_IDENT accepted). */
	void (*ready)(void *ctx, wri_m2_conn *c);
	/* Connection failed or closed; errinfo has the first cause. Called once. */
	void (*closed)(void *ctx, wri_m2_conn *c, const wr_errinfo *err);
} wri_m2_upper;

struct wri_m2_conn {
	wri_m2_state state;
	uint8_t role;        /* WRI_ENTITY_MON or WRI_ENTITY_OSD: the peer we dial */
	uint8_t revision1;   /* peer advertised REVISION_1 (always required) */
	uint8_t mode;        /* WRI_CONN_MODE_CRC or WRI_CONN_MODE_SECURE after AUTH_DONE */
	uint8_t close_reported;
	uint8_t held_ev;     /* internal: receive event not resolved yet (SEG0 or FRAME), see wri_m2_conn.c */
	uint8_t stalled;     /* internal: the last step stopped on backpressure (see wri_m2_conn_deadline) */
	uint8_t auth_rounds; /* AUTH_REPLY_MORE rounds answered so far (at most WRI_M2C_AUTH_ROUNDS) */
	uint8_t cur_keep;    /* internal: the MESSAGE being received is delivered (not dropped as old) */
	uint16_t slot;       /* index in the client's connection table */
	uint16_t gen;        /* generation, for wr_conn_id */
	wr_conn_id id;
	wri_eaddr target;    /* address dialled, byte-exact as it was in the map / spec */
	wr_addr dial;        /* the same for the host */

	uint64_t deadline_ms;       /* of the current state, WR_DEADLINE_NONE = none */
	uint64_t retry_ms;          /* when a stalled connection wants its next step (0 = as soon as possible) */
	uint64_t last_rx_ms, last_tx_ms; /* mono time of the last complete frame received / queued */
	uint64_t out_seq, in_seq;   /* MESSAGE sequence: both start at 0, first message is 1; in_seq is the
				       highest seq delivered, out_seq the last one we sent */
	uint64_t global_id;         /* from AUTH_DONE */
	int64_t peer_gid;           /* from SERVER_IDENT */
	uint64_t global_seq;        /* our client-wide connection counter value for this connection */
	uint64_t features;          /* SERVER_IDENT supported & ours (connection features) */
	uint64_t server_flags;      /* SERVER_IDENT flags (bit 0 lossy) */
	uint64_t server_cookie;     /* SERVER_IDENT cookie (0 for the lossy session we asked for) */
	uint32_t my_nonce;          /* entity_addr nonce we advertise */
	uint8_t my_ip[16];          /* our address as the server sees it (HELLO peer_addr) */
	uint8_t my_family;

	/* Keepalive and traffic counters for the owner (the monitor client keeps its own deadlines). */
	uint64_t ka_ack_ms;         /* mono time of the last KEEPALIVE2_ACK, 0 = none yet */
	uint32_t ka_ack_sec, ka_ack_nsec; /* the stamp that ACK carried */
	uint32_t n_ka_ack;          /* KEEPALIVE2_ACK frames received */
	uint32_t n_msg_in;          /* MESSAGE frames delivered to up->message */
	uint32_t n_msg_dropped;     /* MESSAGE frames dropped as old (seq <= in_seq) or aborted by the sender */
	uint32_t n_seq_gaps;        /* delivered messages that skipped sequence numbers */
	uint32_t ctl_cap;           /* segment 0 buffer size */
	uint32_t seg_cap_max;       /* cap of segments 1..3 */

	wri_m2_rx rx;
	wri_m2_txq tx;
	wri_ring ring;              /* receive staging, bound by the client */
	uint8_t *ctl_buf;           /* segment 0 buffer, ctl_buf_bytes */
	uint32_t pa_slot;           /* handshake slot index in the client's pool, or WRI_NIL */
	wri_m2_preauth *pa;         /* bound while handshaking, NULL after AUTH_SIGNATURE */
	uint8_t sig_want[32];       /* the signature the server must send, computed at AUTH_DONE (wiped after the check) */
	wri_m2_hdr2 cur_hdr;        /* header of the MESSAGE being received */
	struct wri_m2s_slot *sec;   /* secure-mode state (offer, key, nonces, bounce), carved by the client when the policy may end in secure;
				       NULL = this connection offers and speaks crc only (the behaviour of parts A to C). The only field
				       secure mode adds here: the iPXE arena budget has no room for more (design 36.3) */

	const wri_auth_ops *auth;
	void *auth_ctx;
	const wri_m2_upper *up;
	void *up_ctx;
	wr_errinfo err;
};

/* Bind per-connection resources (all carved from the arena by the client). Resets the state. */
void wri_m2_conn_bind(wri_m2_conn *c, uint16_t slot, uint8_t *ring_buf, uint32_t ring_cap, uint8_t *ctl_buf,
		      uint32_t ctl_cap, uint8_t *tx_buf, uint32_t tx_cap, uint32_t seg_cap_max);

/*
 * Start a connection: state CONNECTING. The client queues WR_ACT_CONNECT itself. pa is a
 * handshake slot (pre-auth logs) the client reserved; the connection sets c->pa to NULL (and wipes the logs) once AUTH_SIGNATURE is verified or the
 * connection fails; the client then returns the slot to its pool. my_nonce is the
 * process-wide random entity nonce, global_seq the strictly increasing client counter.
 */
void wri_m2_conn_open(wri_m2_conn *c, wr_conn_id id, uint8_t role, const wri_eaddr *target, const wr_addr *dial,
		      const wri_auth_ops *auth, void *auth_ctx, const wri_m2_upper *up, void *up_ctx, wri_m2_preauth *pa,
		      uint32_t my_nonce, uint64_t global_seq);

/*
 * Secure mode (design 34): choose what AUTH_REQUEST offers (WRI_M2_OFFER_*, wri_m2_modes.h) and hand the connection its secure-mode slot;
 * the offer and the bounce buffer are stored IN the slot (wri_m2s_slot.offer, .tx.bounce), so the connection itself grows by one pointer.
 * Call after wri_m2_conn_open() and before wri_m2_conn_on_connected(). A connection that was never given a slot (sec NULL) offers crc
 * only and cannot end in secure mode: a secure AUTH_DONE fails it with WR_E_M2_MODE, as before part D; an offer with the secure bit and
 * no slot is WR_E_INVAL. bounce is the slot's bounce buffer (a multiple of 16, at least 256 bytes).
 *
 * The slot belongs to the connection from this call until the connection ends: whatever it held is erased here, and at the end of the
 * connection (failure, close, on_closed, a new open()) it is wiped to zero, offer and bounce pointer included, the bounce buffer erased
 * (wri_m2_secure_off), and the connection lets go of the pointer (c->sec is NULL again). A slot is therefore good for ONE connection:
 * call this again after every wri_m2_conn_open().
 *   WR_E_INVAL  NULL c; an offer with a bit that is not a WRI_M2_OFFER_* or that offers nothing but SECURE_FIRST; the secure bit without
 *               a slot; the secure bit with a NULL bounce, a bounce_cap below 256 or not a multiple of 16 (checked here, so a bad
 *               configuration shows at open and not at the first secure connection);
 *   WR_E_STATE  the connection is not in CONNECTING (open() was refused, or the TCP connection is already reported): nothing changes.
 * offer 0 with a slot is crc only (the slot is then only wiped at the end). The auth ops of the connection are not asked about secrets
 * here: an auth without a conn_secret member can still be offered secure, and a secure AUTH_DONE then fails with WR_E_M2_SECRET.
 */
WR_MUST_CHECK wr_status wri_m2_conn_set_secure(wri_m2_conn *c, uint8_t offer, struct wri_m2s_slot *sec, uint8_t *bounce,
					       uint32_t bounce_cap);

/* The host's TCP connect finished: send the banner. */
void wri_m2_conn_on_connected(const wri_ctx *x, wri_m2_conn *c);
/* The host reports the socket gone (reset, EOF, connect failure, or after our close request). */
void wri_m2_conn_on_closed(const wri_ctx *x, wri_m2_conn *c, int host_errno);

/* Receive and transmit plumbing, same shape as the public pump. In secure mode a tx_consume can also end the connection: when the transmit key was
 * wiped meanwhile (a stream that could not be refilled) nothing more can ever be sent, so the connection fails with the builder's status; like a refused
 * nonce it is reported at the next step (wri_m2_conn_deadline() is 0 until then). */
size_t wri_m2_conn_rx_window(wri_m2_conn *c, uint8_t **ptr);
void wri_m2_conn_rx_commit(wri_m2_conn *c, size_t n);
size_t wri_m2_conn_tx_peek(const wri_m2_conn *c, wr_iov *iov, size_t max);
void wri_m2_conn_tx_consume(wri_m2_conn *c, size_t n);

/*
 * Parse committed bytes, run the handshake, dispatch frames, check deadlines. *budget (bytes of
 * work) is decremented; returns 1 if budget ran out with work left. A failed connection moves
 * to FAILED, calls up->closed once and asks the client (via state) to emit WR_ACT_CLOSE.
 */
int wri_m2_conn_step(const wri_ctx *x, wri_m2_conn *c, uint32_t *budget);

/*
 * The engine is being destroyed (or a slot is being taken out of use without the connection having ended): erase every secret the connection holds, at
 * once and without a single callback: the transcripts, the expected signature, the staged bytes, the control buffer, the unsent output, and in secure
 * mode the key schedule, the nonces, the staging and the bounce buffer (wri_m2_secure_off), and make the auth layer drop its copy of the connection secret
 * while the handshake slot is still ours. The connection is FREE afterwards and nobody is told (up->closed is NOT called). Safe on any state, on a
 * connection that already ended, and any number of times.
 */
void wri_m2_conn_wipe(wri_m2_conn *c);

/* Request an orderly close (client emits WR_ACT_CLOSE). The state becomes CLOSING, up->closed is called
 * once with why recorded as the first cause (why == WR_OK: closed with status 0). Does nothing in FREE,
 * FAILED and CLOSING. */
void wri_m2_conn_close(const wri_ctx *x, wri_m2_conn *c, wr_status why);

/*
 * Send a MESSAGE (READY only; WR_E_STATE otherwise, WR_E_BUSY if the queue is full). seq and
 * ack_seq are filled by the connection. data may be NULL; if given it is referenced, not copied,
 * and must stay valid until the host consumed it.
 * Secure mode (34.6, 34.5): WR_E_BUSY also while the data of an earlier frame is still being sealed piece by piece (a stream owns the end of the wire);
 * nothing is consumed by a BUSY answer, not a sequence number and not a nonce. A refused nonce (the operation limit or the counter wrapped all the way
 * round) ends the connection with WR_E_M2_NONCE before any byte of the frame exists: this call returns WR_E_STATE (the connection is not READY any more,
 * which every caller already treats as "the session went away"), c->err holds the cause, and up->closed is called at the next wri_m2_conn_step()
 * (wri_m2_conn_deadline() is 0 until then). The same holds for send_keepalive, and for any other refusal after which the secure transmit key is gone
 * (a host that fails to start an operation after the frame's nonces were taken: the builder wipes the key, the peer could not decode anything behind
 * the gap): the connection ends with that status instead of staying READY with a transmit side that can never send again.
 */
typedef struct wri_m2_msg_out {
	uint16_t type;
	uint16_t priority;
	uint16_t version;
	uint16_t compat_version;
	uint64_t tid;
	const uint8_t *front;
	uint32_t front_len;
	const uint8_t *data;
	uint32_t data_len;
} wri_m2_msg_out;
WR_MUST_CHECK wr_status wri_m2_conn_send_message(const wri_ctx *x, wri_m2_conn *c, const wri_m2_msg_out *m);

/*
 * Send KEEPALIVE2 with the given stamp (READY only: WR_E_STATE otherwise, WR_E_BUSY if the queue is
 * full). When to send is the owner's business (the monitor client does it every keepalive_ms); the
 * answer shows up in ka_ack_ms / ka_ack_sec / ka_ack_nsec / n_ka_ack.
 */
WR_MUST_CHECK wr_status wri_m2_conn_send_keepalive(const wri_ctx *x, wri_m2_conn *c, uint32_t sec, uint32_t nsec);

/*
 * Earliest time the connection wants wri_m2_conn_step() to run although no byte arrived:
 *   - the handshake deadline (BANNER to IDENT; config handshake_timeout_ms from the moment the host
 *     reported the TCP connection, 0 = no deadline);
 *   - while the last step stopped on backpressure: a short retry time, and 0 (at once) after the host
 *     consumed transmit bytes (wri_m2_conn_tx_consume);
 *   - 0 (at once) for a connection that failed without the owner having been told: an open() that was refused, or a
 *     refused nonce found inside a send call, a secure send whose builder lost its key, or a tx_consume that found the transmit key gone (the
 *     report is made by the next step).
 * WR_DEADLINE_NONE if none. A scheduler that steps only connections with new bytes must also step the
 * ones whose deadline is due.
 */
uint64_t wri_m2_conn_deadline(const wri_m2_conn *c);

/*
 * errinfo encoding of WR_E_M2_BAD_METHOD (AUTH_BAD_METHOD, msgr2.md 3.2): peer_result = the server's
 * result (negative errno), a0 = bit mask of its allowed methods (bit v for method v < 64), a1 = bit
 * mask of its allowed connection modes, a2 = the method we offered. Other statuses: a0 / a1 / a2 as
 * the `what` string says.
 */

/* ---- internal to the m2-conn sources (wri_m2_conn*.c); no other module calls these --------------- */

#define WRI_M2C_AUTH_ROUNDS 4u  /* AUTH_REPLY_MORE rounds accepted per connection */
#define WRI_M2C_STALL_RETRY_MS 10u

/* BANNER .. READY: the states in which bytes flow (shared by wri_m2_conn.c and the plumbing in wri_m2_conn_msg.c). */
static inline int wri_m2c_state_live(unsigned s)
{
	return s >= WRI_M2_BANNER && s <= WRI_M2_READY;
}

/* Record the first failure, wipe the handshake material, call up->closed once, state FAILED. */
void wri_m2c_fail(const wri_ctx *x, wri_m2_conn *c, wr_status st, unsigned line, const char *what, uint64_t a0,
		  uint64_t a1, uint64_t a2);
/* The same, but up->closed is not called now: the next wri_m2_conn_step() (or on_closed) reports it. For a failure found inside a call of the upper layer
 * (a send), which must not see its own session torn down from under it. wri_m2_conn_deadline() is 0 until the report has been made. */
void wri_m2c_fail_deferred(const wri_ctx *x, wri_m2_conn *c, wr_status st, unsigned line, const char *what, uint64_t a0, uint64_t a1, uint64_t a2);
#define WRI_M2C_FAIL(x, c, st, what, a0, a1, a2) \
	wri_m2c_fail((x), (c), (st), (unsigned)__LINE__, (what), (uint64_t)(a0), (uint64_t)(a1), (uint64_t)(a2))

/* ---- secure mode, internal (wri_m2_conn_sec.c; called by wri_m2_conn.c and wri_m2_conn_hs.c) ---- */

/* What AUTH_REQUEST offers: the slot's offer, or crc only (WRI_M2_OFFER_CRC) without a slot or with an empty one. Never 0. */
uint8_t wri_m2c_offer(const wri_m2_conn *c);
/* Wire bytes of a single-segment control frame of len0 payload bytes, in crc framing (secure == 0) or in secure framing: the number the
 * room checks of the handlers need (the two differ: a secure frame is at least 96 bytes and carries a 16-byte tag per operation). */
uint32_t wri_m2c_frame_bytes(int secure, uint32_t len0);
/* AUTH_DONE named `mode`: WR_OK when it is one we offered, else the connection fails with WR_E_M2_MODE (a0 = the mode, a1 = our offer mask). */
wr_status wri_m2c_sec_check_mode(const wri_ctx *x, wri_m2_conn *c, uint32_t mode);
/* The switch of 34.4 for a secure AUTH_DONE that auth->done() accepted: take the secret from the auth layer, release the AUTH_DONE FRAME
 * event, wri_m2_secure_on, ask the auth layer to forget the secret. WR_OK, or the connection failed (WR_E_M2_SECRET, WR_E_STATE, the status
 * of a host refusing the key); never WR_E_BUSY. Must not run unless the room for our signature frame was checked first. */
wr_status wri_m2c_sec_switch(const wri_ctx *x, wri_m2_conn *c);
/* The secure life of the connection is over (failure, close, the transport gone): wri_m2_secure_off on the slot, and the auth layer's copy of
 * the secret is dropped while the handshake slot is still the connection's (c->pa != NULL). Safe to call any number of times. */
void wri_m2c_sec_end(wri_m2_conn *c);
/* A transmit status of a send call: WR_E_M2_NONCE (the nonce was refused, 34.5), or any refusal after which the secure transmit key is gone (the builder
 * wipes it when a frame failed after its nonces were taken), fails the connection WITHOUT calling up->closed (the report comes at the next step) and the
 * caller gets WR_E_STATE; any other status (OK, BUSY, TOOBIG, INVAL ...) is returned as it is. */
wr_status wri_m2c_tx_status(const wri_ctx *x, wri_m2_conn *c, wr_status st);
/* After the host consumed transmit bytes: a secure connection whose transmit key was wiped meanwhile (a stream that could not be refilled) is failed
 * the same way (deferred). Nothing otherwise. */
void wri_m2c_tx_check(const wri_ctx *x, wri_m2_conn *c);

/* Queue one single-segment control frame (copied); logs it into the pre-auth transcript while one is bound. */
WR_MUST_CHECK wr_status wri_m2c_send(const wri_ctx *x, wri_m2_conn *c, uint8_t tag, const uint8_t *p, uint32_t n);
/* 1 if the queue has room for `bytes` more encode-buffer bytes. */
int wri_m2c_tx_room(const wri_m2_conn *c, uint32_t bytes);
/* WR_OK if there is room now; WR_E_BUSY if there will be once the host consumed bytes; otherwise (`bytes` exceeds
 * the whole encode buffer, so no wait can help) the connection fails with WR_E_TOOBIG and that is returned. */
WR_MUST_CHECK wr_status wri_m2c_need_room(const wri_ctx *x, wri_m2_conn *c, uint32_t bytes);

/* Handlers. They return WR_OK (event resolved), WR_E_BUSY (backpressure: nothing was changed, ask again
 * later) or an error, in which case wri_m2c_fail() has been called already. */
wr_status wri_m2c_hs_banner(const wri_ctx *x, wri_m2_conn *c);  /* BANNER event */
wr_status wri_m2c_hs_frame(const wri_ctx *x, wri_m2_conn *c);   /* FRAME event of a control frame, states HELLO..IDENT */
wr_status wri_m2c_msg_seg0(const wri_ctx *x, wri_m2_conn *c);   /* SEG0 event of a MESSAGE */
wr_status wri_m2c_ready_frame(const wri_ctx *x, wri_m2_conn *c);/* FRAME event in READY (MESSAGE, KEEPALIVE2, ACK ...) */

#endif /* WRI_M2_CONN_H */
