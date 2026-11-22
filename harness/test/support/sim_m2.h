/* SPDX-License-Identifier: MIT */
/*
 * sim_m2.h - a scriptable msgr2.1 SERVER for tests (harness code, libc allowed, never part of the
 * core). Every connection-level test talks to it through an in-memory duplex:
 *
 *     sim_m2_feed(s, bytes, n)       bytes the client wrote
 *     sim_m2_drain(s, out, cap)      bytes the server wants the client to read
 *
 * It is written from docs/spec/msgr2.md section 3 (the server behaviour observed in the notes),
 * not from any client code, and uses only the m2-frame parser / builder, wri_hmac_sha256 and
 * wri_ct_memeq (signature compare) of the core. Control-frame payloads are encoded and decoded by small private routines in sim_m2.c.
 *
 * What it does (crc mode, revision 1, lossy session):
 *   banner (the server sends its banner at creation), HELLO, AUTH_REQUEST / AUTH_REQUEST_MORE via
 *   a pluggable callback table (REPLY_MORE, DONE, BAD_METHOD, silent close), AUTH_SIGNATURE both
 *   ways over its own pre-auth logs, the COMPRESSION stage when both banners advertise it,
 *   CLIENT_IDENT -> SERVER_IDENT / IDENT_MISSING_FEATURES / WAIT, then MESSAGE receive (recorded;
 *   sequence numbers enforced), MESSAGE send, KEEPALIVE2 echo and ACK tolerance.
 *
 * Secure mode (sim_m2_sec.h, written from msgr2-secure-mode.md with ref_gcm and nothing of the core): the server picks the first of
 * the client's modes that cfg.modes allows (none: AUTH_BAD_METHOD, -EOPNOTSUPP, its lists); when secure was picked it issues a
 * 64-byte secret from a seeded generator (sim_m2_conn_secret: the auth callbacks put it into the cephx payload, the two ways of
 * cephx.md 2.10), and once it has sent AUTH_DONE with mode secure EVERYTHING after it, in both directions, goes through the
 * secure encoder and decoder: the signature frames first, then the session. The crc handshake and the crc session are byte for
 * byte what they were. Every secret issued is recorded (sim_m2_cfg.sec / sim_m2_sec_setup, sim_sec_log). The faults of
 * sim_m2_fault.sec are the secure-mode hooks; the part A hooks (out_limit, out_chunk, corrupt_frame, bad_signature,
 * oversize_frame, no_keepalive_ack, send_wait, missing_features) keep working: corrupt_frame damages ciphertext (the tag is
 * the integrity of this mode: PREAMBLE flips a bit of the preamble's ciphertext, SEG0 of segment 0's, EPILOGUE of the
 * epilogue block's), oversize_frame is an authentic part 1 that claims the length.
 *
 * A protocol violation by the client makes the server close (sim_m2_closed() turns true once what
 * it had queued is drained), like a stock daemon does. sim_m2_error() says why.
 */
#ifndef SIM_M2_H
#define SIM_M2_H

#include "wr_err.h"
#include "wr_types.h"
#include "wri_m2_frame.h"
#include "sim_m2_sec.h"

#define SIM_M2_ENT_MON 0x01u
#define SIM_M2_ENT_OSD 0x04u
#define SIM_M2_ENT_CLIENT 0x08u

#define SIM_M2_AUTH_NONE 1u
#define SIM_M2_AUTH_CEPHX 2u
#define SIM_M2_MODE_CRC 1u
#define SIM_M2_MODE_SECURE 2u

#define SIM_M2_KEY_MAX 64u
#define SIM_M2_LIST_MAX 8u
#define SIM_M2_ADDR_MAX 64u    /* largest entity_addr_t the server stores */
#define SIM_M2_HDR2_LEN 41u    /* ceph_msg_header2 */
#define SIM_M2_TAGLOG 256u

/* ---- auth callback table ------------------------------------------------------------------ */

#define SIM_AUTH_MORE 1       /* answer AUTH_REPLY_MORE with rep->payload */
#define SIM_AUTH_DONE 2       /* answer AUTH_DONE: global id, mode, payload; rep->key is the session key */
#define SIM_AUTH_BAD_METHOD 3 /* answer AUTH_BAD_METHOD: rep->result and the two lists */
#define SIM_AUTH_CLOSE 4      /* close without any frame (the server's -EBUSY case) */

typedef struct sim_m2_auth_reply {
	const uint8_t *payload; /* owned by the callback, valid until the next call */
	uint32_t payload_len;
	uint8_t key[SIM_M2_KEY_MAX]; /* DONE: raw session key bytes; key_len 0 = no key (32 zero bytes sign) */
	uint32_t key_len;
	uint64_t global_id; /* DONE: 0 = the configured global id */
	uint32_t mode;      /* DONE: 0 = the negotiated connection mode */
	int32_t result;     /* BAD_METHOD: negative errno, 0 = -13 */
	uint32_t methods[SIM_M2_LIST_MAX], n_methods; /* BAD_METHOD lists; empty = the configured ones */
	uint32_t modes[SIM_M2_LIST_MAX], n_modes;
} sim_m2_auth_reply;

typedef struct sim_m2_auth_ops {
	void *ctx;
	/* AUTH_REQUEST: method, the client's preferred modes, the method payload. The mode the server
	 * negotiated is already applied (it is in `rep` only if the callback overrides it). Return a
	 * SIM_AUTH_* verdict. */
	int (*request)(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
		       uint32_t n, sim_m2_auth_reply *rep);
	/* AUTH_REQUEST_MORE. May be NULL when `request` never returns SIM_AUTH_MORE. */
	int (*more)(void *ctx, const uint8_t *p, uint32_t n, sim_m2_auth_reply *rep);
} sim_m2_auth_ops;

/* A ready-made callback set: `rounds` REPLY_MORE answers, then DONE (or BAD_METHOD if fail_result). */
typedef struct sim_m2_auth_script {
	uint32_t rounds;
	uint8_t more_payload[128];
	uint32_t more_len;
	uint8_t done_payload[512];
	uint32_t done_len;
	uint8_t key[SIM_M2_KEY_MAX];
	uint32_t key_len;
	int32_t fail_result;  /* nonzero: the last step answers BAD_METHOD with this result instead of DONE */
	uint32_t mode;        /* DONE mode override, 0 = negotiated */
	uint32_t step;        /* internal: REPLY_MORE answers given in the current attempt */
	/* what the server saw (the last of each) */
	uint32_t n_request, n_more, last_method, last_nmodes, last_modes[SIM_M2_LIST_MAX];
	uint8_t last_request[512], last_more[512];
	uint32_t last_request_len, last_more_len;
} sim_m2_auth_script;
void sim_m2_auth_script_ops(sim_m2_auth_ops *ops, sim_m2_auth_script *sc);

/* ---- configuration and fault hooks -------------------------------------------------------- */

typedef struct sim_m2_fault {
	int64_t out_limit;        /* -1 = off; else no more than this many server bytes are ever delivered */
	uint8_t out_limit_close;  /* 1: EOF once the limit is reached, 0: the stream just stops (stall) */
	uint32_t out_chunk;       /* 0 = off; else a drain call returns at most this many bytes (1 = byte at a time) */
	uint32_t corrupt_frame;   /* 0 = off; else the 1-based index of the server frame whose CRC is damaged */
	uint8_t corrupt_part;     /* SIM_M2_CORRUPT_* (falls back to a part the frame has) */
	uint8_t bad_signature;    /* our AUTH_SIGNATURE is wrong (one bit flipped) */
	uint64_t missing_features;/* != 0: answer CLIENT_IDENT with IDENT_MISSING_FEATURES, this mask */
	uint8_t send_wait;        /* answer CLIENT_IDENT with WAIT */
	uint32_t done_mode;       /* != 0: connection mode written into AUTH_DONE instead of the negotiated one (1 = crc although secure was
				   * negotiated: the conversation stays crc; 2 = secure although crc was negotiated: no secret, the server stops) */
	uint32_t oversize_frame;  /* != 0: server frame K is only a preamble that claims oversize_len bytes in its last segment */
	uint32_t oversize_len;
	uint8_t no_keepalive_ack; /* swallow KEEPALIVE2 without answering */
	sim_sec_fault sec;        /* secure-mode hooks (sim_m2_sec.h); zero = off */
} sim_m2_fault;
#define SIM_M2_CORRUPT_PREAMBLE 0
#define SIM_M2_CORRUPT_SEG0 1     /* the inline CRC after segment 0 */
#define SIM_M2_CORRUPT_EPILOGUE 2 /* the CRC slot of segment 1 in the epilogue */

#define SIM_M2_SEQ_STRICT 0 /* seq must be exactly in_seq + 1: anything else closes the connection */
#define SIM_M2_SEQ_STOCK 1  /* a stock daemon: old seq -> connection silently stops being read, gaps accepted */

typedef struct sim_m2_cfg {
	uint8_t entity_type;            /* our HELLO entity type, SIM_M2_ENT_MON (default) / _OSD */
	uint64_t banner_supported;      /* default 3 (REVISION_1 | COMPRESSION), like a stock daemon */
	uint64_t banner_required;       /* default 0 */
	uint32_t banner_payload_len;    /* default 16; other values test the client's banner checks */
	uint8_t banner_v1;              /* send the legacy "ceph v027" prefix instead */
	uint8_t client_ip[4];           /* the address HELLO reports as the client's (default 10.77.0.20) */
	uint16_t client_port;           /* default 50000 */
	uint8_t server_ip[4];           /* our own msgr2 address (default 10.77.0.10) */
	uint16_t server_port;           /* default 3300 */
	uint32_t server_nonce;          /* default 0 */
	uint16_t legacy_port;           /* port of the second, type 1 address in SERVER_IDENT (default 6789) */
	uint8_t check_target;           /* 1: CLIENT_IDENT target_addr must equal our address byte for byte, else close */
	uint32_t methods[SIM_M2_LIST_MAX], n_methods; /* allowed auth methods, default {2} */
	uint32_t modes[SIM_M2_LIST_MAX], n_modes;     /* allowed connection modes in our order, default {1, 2} */
	uint64_t global_id;             /* default 4242 */
	int64_t server_gid;             /* SERVER_IDENT gid, default 1 */
	uint64_t server_global_seq;     /* 0 = echo the client's */
	uint64_t ident_supported;       /* SERVER_IDENT supported, default 0x3f07fffffffdffff */
	uint64_t ident_required;        /* required features: enforced and sent, default MSG_ADDR2 (bit 59) */
	uint64_t ident_flags;           /* default 1 = lossy */
	uint64_t ident_cookie;          /* default 0 */
	uint32_t ctl_cap;               /* segment 0 cap (control frames), default 16 KiB */
	uint32_t seg_cap;               /* cap of each of segments 1..3, default 1 MiB */
	uint32_t max_msgs;              /* messages kept in sim->msgs, default 128 (more are counted, not kept) */
	uint32_t msg_bytes_cap;         /* total segment bytes kept in sim->msgs, default 64 MiB (a message that would
					 * exceed it is counted, not kept) */
	uint8_t seq_policy;             /* SIM_M2_SEQ_STRICT (default) or SIM_M2_SEQ_STOCK */
	uint32_t preauth_cap;           /* cap of each pre-auth log, default 1 MiB */
	uint32_t out_cap;               /* cap of the queued server output, default 16 MiB */
	sim_sec_cfg sec;                /* where the connection secret comes from (seed, or a fixed one) */
	sim_m2_fault f;
} sim_m2_cfg;

void sim_m2_cfg_default(sim_m2_cfg *c);

/* ---- what the server recorded ------------------------------------------------------------- */

typedef struct sim_m2_msg {
	uint64_t seq, tid, ack_seq;
	uint16_t type, priority, version, data_off, compat_version, reserved;
	uint32_t pre_padding;
	uint8_t flags;
	uint8_t nseg;                 /* segments in the frame, 1..4 (empty trailing ones are not sent) */
	uint8_t *seg[3];              /* front, middle, data (malloc'd copies; NULL = empty) */
	uint32_t seg_len[3];
} sim_m2_msg;

typedef struct sim_m2_ident { /* the last CLIENT_IDENT */
	uint8_t addrs[SIM_M2_ADDR_MAX * 2]; /* the addrvec body after marker and count: the entity_addrs back to back */
	uint32_t addrs_len, n_addrs;
	uint8_t target[SIM_M2_ADDR_MAX];
	uint32_t target_len;
	int64_t gid;
	uint64_t global_seq, supported, required, flags, cookie;
} sim_m2_ident;

enum { /* sim_m2.state */
	SIM_M2_ST_BANNER = 0, /* waiting for the client banner */
	SIM_M2_ST_HELLO,
	SIM_M2_ST_AUTH,
	SIM_M2_ST_SIGNATURE,
	SIM_M2_ST_COMPRESSION,
	SIM_M2_ST_IDENT,
	SIM_M2_ST_READY,
	SIM_M2_ST_REFUSED, /* sent WAIT / IDENT_MISSING_FEATURES / AUTH_DONE in secure mode: nothing more is read */
	SIM_M2_ST_DEAD     /* protocol violation or hook: closed */
};

/* The frame the server is handling now (from the crc parser or the secure decoder): the dispatch reads only this. */
typedef struct sim_m2_cur {
	uint8_t tag, nseg;
	uint32_t len[4];
	const uint8_t *p[4];  /* valid until the next frame is parsed */
} sim_m2_cur;

typedef struct sim_m2_secst {
	uint8_t secret[SIM_SEC_SECRET_MAX]; /* the secret issued for the current AUTH attempt */
	uint32_t secret_len;                /* 0 = none issued */
	uint8_t issued;
	uint64_t rng;                       /* the generator of the secrets of this connection */
	uint64_t seed;                      /* from sim_m2_sec_setup, used when cfg.sec.seed is 0 */
	sim_sec_log *log;                   /* where issued secrets are recorded (may be NULL) */
	sim_sec_ctx ctx;                    /* the server's two directions, live once tx_on */
	sim_sec_dec dec;                    /* reads the client's frames once rx_on */
	uint8_t tx_on;                      /* secure framing in the server's transmit direction */
	uint8_t rx_on;                      /* ... and in its receive direction */
	uint8_t rx_pending;                 /* AUTH_DONE sent: the receive side switches at the next frame boundary */
	uint32_t n_tx_frames, n_rx_frames;  /* secure frames sent / received (aborted ones included in rx) */
	uint32_t n_aborted;                 /* frames received with late_status 0x1 */
} sim_m2_secst;

typedef struct sim_m2 sim_m2;
struct sim_m2 {
	sim_m2_cfg cfg;
	sim_m2_auth_ops auth;
	uint8_t state;
	wr_errinfo err; /* why the server closed on a client violation (status 0 = none) */

	/* callback after every recorded MESSAGE (a monitor simulation answers from here) */
	void (*on_message)(void *ctx, sim_m2 *s, const sim_m2_msg *m);
	void *on_message_ctx;

	/* the handshake as seen */
	wri_m2_banner client_banner;
	uint8_t client_hello_type;
	uint8_t client_hello_addr[SIM_M2_ADDR_MAX];
	uint32_t client_hello_addr_len;
	uint32_t conn_mode;      /* what AUTH_DONE said */
	uint8_t key[SIM_M2_KEY_MAX];
	uint32_t key_len;
	uint64_t global_id;      /* what AUTH_DONE said */
	sim_m2_ident ident;
	uint8_t compression_requested;

	/* pre-auth logs (msgr2.md 3.4): what the client sent before its AUTH_SIGNATURE, what we sent
	 * up to and including AUTH_DONE; frozen at those points */
	uint8_t *rx_log, *tx_log;
	uint32_t rx_log_len, tx_log_len;

	/* frames seen / sent */
	uint8_t rx_tags[SIM_M2_TAGLOG];
	uint32_t n_rx_frames;
	uint32_t n_rx_by_tag[WRI_M2_TAG_MAX + 1u];
	uint32_t n_tx_frames; /* server frames emitted so far (the index of corrupt_frame / oversize_frame) */

	sim_m2_cur cur;
	sim_m2_secst sec;

	/* session */
	uint64_t in_seq, out_seq;
	sim_m2_msg *msgs;       /* recorded client messages, in order */
	uint32_t n_msgs;        /* kept */
	uint32_t n_msgs_seen;   /* all, including those beyond max_msgs / msg_bytes_cap */
	uint64_t msgs_bytes;    /* segment bytes held by the kept messages */
	uint32_t n_seq_gaps, n_seq_dups; /* STOCK policy counters */
	uint32_t n_keepalive;   /* KEEPALIVE2 received */
	uint32_t last_ka_sec, last_ka_nsec;
	uint32_t n_keepalive_ack;
	uint32_t last_kaack_sec, last_kaack_nsec;
	uint32_t n_ack;
	uint64_t last_ack_seq;

	/* internals */
	wri_m2_rx rx;
	wri_ring ring;
	uint8_t ring_buf[8192];
	uint8_t *seg0, *sink[3], *scratch, *enc;
	uint32_t enc_cap;
	uint8_t *out;
	size_t out_cap, out_head, out_len;
	uint64_t delivered;
	uint32_t frame_start;  /* rx log length at the start of the frame being handled */
	uint8_t rx_log_on, tx_log_on, await_more, stall_in, close_pending, out_dead, expect_compression;
	uint32_t negotiated_mode, auth_method;
};

/* Create a server with the given configuration (NULL = defaults) and callbacks (NULL = answer every
 * AUTH_REQUEST with AUTH_DONE and no key). The server banner is queued at once, as a daemon sends it
 * right after accept. NULL on out of memory or on a configuration that cannot work (a method / mode
 * list longer than SIM_M2_LIST_MAX, a zero ctl_cap / seg_cap, buffer sizes that do not fit 32 bits). */
sim_m2 *sim_m2_new(const sim_m2_cfg *cfg, const sim_m2_auth_ops *auth);
void sim_m2_free(sim_m2 *s);

/* Bytes the client wrote. Returns how many were taken: all of them, or 0 once the server has closed. */
size_t sim_m2_feed(sim_m2 *s, const uint8_t *p, size_t n);
/* Bytes for the client: up to cap (fewer with the out_chunk / out_limit hooks); 0 = nothing right now. */
size_t sim_m2_drain(sim_m2 *s, uint8_t *out, size_t cap);
/* Bytes queued and not yet deliverable-counted (ignores the hooks). */
size_t sim_m2_pending(const sim_m2 *s);
/* 1 once the client would read EOF: closed by the server (violation, hook or sim_m2_close) and all it had
 * to say was drained, or the out_limit hook cut the stream in close mode. */
int sim_m2_closed(const sim_m2 *s);
/* Server-initiated close. */
void sim_m2_close(sim_m2 *s);
const wr_errinfo *sim_m2_error(const sim_m2 *s);

/* Queue one server frame, going through every fault hook (it counts as server frame n_tx_frames + 1).
 * WR_E_STATE after the server died, WR_E_TOOBIG / WR_E_INVAL from the builder or the output cap. */
WR_MUST_CHECK wr_status sim_m2_send_frame(sim_m2 *s, uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg);
/* A server-initiated MESSAGE (state READY only): seq = ++out_seq, ack_seq = in_seq, flags 3,
 * compat_version = version. Empty trailing segments are dropped; an empty middle in front of data stays. */
WR_MUST_CHECK wr_status sim_m2_send_message(sim_m2 *s, uint16_t type, uint64_t tid, uint16_t version,
					    const uint8_t *front, uint32_t flen, const uint8_t *middle,
					    uint32_t mlen, const uint8_t *data, uint32_t dlen);
WR_MUST_CHECK wr_status sim_m2_send_keepalive(sim_m2 *s, uint32_t sec, uint32_t nsec);

/* ---- secure mode ---------------------------------------------------------------------------------------------------- */

/* For the auth callbacks of a monitor / OSD simulation: where to record the secrets this connection issues and a seed for them
 * (used unless cfg.sec.seed is set). Call it from the first AUTH_REQUEST callback, before sim_m2_conn_secret(). */
void sim_m2_sec_setup(sim_m2 *s, sim_sec_log *log, uint64_t seed);
/* The connection secret to put into the auth payload of this AUTH_DONE: NULL when there is none (crc was negotiated, or the
 * omit_secret hook). Issues it (and records it) on the first call of an attempt. *len gets its length. */
const uint8_t *sim_m2_conn_secret(sim_m2 *s, uint32_t *len);
/* The connection mode the server negotiated for the current AUTH_REQUEST (0 before one, or when it refused). */
uint32_t sim_m2_negotiated_mode(const sim_m2 *s);
/* 1 once the server talks secure in both directions. */
int sim_m2_is_secure(const sim_m2 *s);

/* Drop the recorded messages (the counters stay). */
void sim_m2_msgs_clear(sim_m2 *s);

/* Entity address helper (IPv4, marker 1): writes the 35 bytes of an entity_addr_t. type 2 = MSGR2, 1 = LEGACY, 3 = ANY. */
#define SIM_M2_ADDR4_LEN 35u
void sim_m2_put_addr4(uint8_t out[SIM_M2_ADDR4_LEN], uint32_t type, uint32_t nonce, const uint8_t ip[4], uint16_t port);

#endif /* SIM_M2_H */
