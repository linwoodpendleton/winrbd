/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_frame.h - msgr2.1 framing in crc mode (revision 1): banner, 32-byte preamble, up to four
 * segments with their CRCs, epilogue. Spec: docs/spec/msgr2.md 2.2 to 2.6.1.
 *
 * Two halves, both free of connection logic so they can be fuzzed alone:
 *   - an incremental RECEIVE parser that is fed bytes through the same window/commit shape as
 *     the public pump, verifies everything and reports events;
 *   - a frame BUILDER that appends complete frames to a transmit queue (gather list).
 * Secure mode (milestone 11) adds a second codec behind the same interface; nothing above this
 * file changes. Invariant for the layers above: they only ever see bytes of segments that
 * passed their integrity check (inline CRC for segment 0, epilogue CRC for the others).
 */
#ifndef WRI_M2_FRAME_H
#define WRI_M2_FRAME_H

#include "wr_err.h"
#include "wr_host.h"
#include "wr_types.h"
#include "wri_mem.h"

/* ---- constants (msgr2.md 2.2, 2.3, 2.4, 2.6.1) -------------------------------------------- */

#define WRI_M2_BANNER_PREFIX "ceph v2\n" /* 8 bytes */
#define WRI_M2_BANNER_HEAD 10u           /* prefix + u16 payload length */
#define WRI_M2_BANNER_LEN 26u            /* what we send: head + 16 */
#define WRI_M2_BANNER_PAYLOAD_MAX 64u    /* largest peer banner payload we accept */
#define WRI_M2_FEATURE_REVISION_1 1u     /* msgr2 banner feature bit 0; we advertise exactly this */

#define WRI_M2_PREAMBLE_LEN 32u
#define WRI_M2_MAX_SEGS 4u
#define WRI_M2_CRC_LEN 4u
#define WRI_M2_EPILOGUE_LEN 13u
#define WRI_M2_LATE_COMPLETE 0x0Eu
#define WRI_M2_LATE_ABORTED 0x01u

typedef enum wri_m2_tag {
	WRI_M2_TAG_HELLO = 1,
	WRI_M2_TAG_AUTH_REQUEST = 2,
	WRI_M2_TAG_AUTH_BAD_METHOD = 3,
	WRI_M2_TAG_AUTH_REPLY_MORE = 4,
	WRI_M2_TAG_AUTH_REQUEST_MORE = 5,
	WRI_M2_TAG_AUTH_DONE = 6,
	WRI_M2_TAG_AUTH_SIGNATURE = 7,
	WRI_M2_TAG_CLIENT_IDENT = 8,
	WRI_M2_TAG_SERVER_IDENT = 9,
	WRI_M2_TAG_IDENT_MISSING_FEATURES = 10,
	WRI_M2_TAG_SESSION_RECONNECT = 11,
	WRI_M2_TAG_SESSION_RESET = 12,
	WRI_M2_TAG_SESSION_RETRY = 13,
	WRI_M2_TAG_SESSION_RETRY_GLOBAL = 14,
	WRI_M2_TAG_SESSION_RECONNECT_OK = 15,
	WRI_M2_TAG_WAIT = 16,
	WRI_M2_TAG_MESSAGE = 17,
	WRI_M2_TAG_KEEPALIVE2 = 18,
	WRI_M2_TAG_KEEPALIVE2_ACK = 19,
	WRI_M2_TAG_ACK = 20,
	WRI_M2_TAG_COMPRESSION_REQUEST = 21,
	WRI_M2_TAG_COMPRESSION_DONE = 22
} wri_m2_tag;
#define WRI_M2_TAG_MAX 22u

/* ---- banner ------------------------------------------------------------------------------- */

typedef struct wri_m2_banner {
	uint64_t supported; /* msgr2 feature bits the peer supports */
	uint64_t required;  /* bits the peer requires */
} wri_m2_banner;

/* Write our 26-byte banner (supported 0x1, required 0x0) into out[26]. */
void wri_m2_banner_build(uint8_t out[WRI_M2_BANNER_LEN]);

/*
 * Validate the 10-byte head. On success *payload_len is the number of bytes that follow.
 * WR_E_M2_PEER_V1 if the prefix is "ceph v027", WR_E_M2_BANNER for any other prefix or a
 * payload shorter than 16 or longer than WRI_M2_BANNER_PAYLOAD_MAX.
 */
WR_MUST_CHECK wr_status wri_m2_banner_head(const uint8_t head[WRI_M2_BANNER_HEAD], uint32_t *payload_len);

/*
 * Decode and check the payload: needs >= 16 bytes, extra bytes ignored. Rejects (WR_E_M2_FEATURES)
 * a peer without REVISION_1 in `supported`, and a peer whose `required` has bits outside ours (0x1).
 */
WR_MUST_CHECK wr_status wri_m2_banner_payload(const uint8_t *p, size_t n, wri_m2_banner *out);

/* ---- preamble ----------------------------------------------------------------------------- */

typedef struct wri_m2_desc {
	uint8_t tag;
	uint8_t nseg;           /* 1..4 */
	uint8_t flags;          /* preamble byte 26 (bit 0 = compressed; we reject non-zero) */
	uint16_t align[4];
	uint32_t len[4];        /* segment lengths; unused segments 0 */
} wri_m2_desc;

/*
 * Verify (CRC seed 0 over bytes 0..27, nseg 1..4, last segment non-empty when nseg > 1, tag in
 * 1..22, reserved byte 0, flags 0, unused segments zero) and decode a preamble.
 * WR_E_M2_FRAME_CRC, WR_E_M2_FRAME_FORM or WR_E_M2_TAG.
 */
WR_MUST_CHECK wr_status wri_m2_preamble_parse(const wr_prim_ops *prim, const uint8_t p[WRI_M2_PREAMBLE_LEN],
					      wri_m2_desc *out);
void wri_m2_preamble_build(const wr_prim_ops *prim, uint8_t out[WRI_M2_PREAMBLE_LEN], const wri_m2_desc *d);

/* Bytes of the frame after the preamble: seg0 + 4 if seg0 non-empty, + L1..L3, + 13 if nseg > 1. */
uint64_t wri_m2_frame_body_len(const wri_m2_desc *d);

/* ---- receive parser ----------------------------------------------------------------------- */

typedef enum wri_m2_rx_state {
	WRI_RX_BANNER_HEAD = 0,
	WRI_RX_BANNER_PAYLOAD,
	WRI_RX_PREAMBLE,
	WRI_RX_SEG0,      /* segment 0 payload then its inline CRC */
	WRI_RX_SEGS,      /* segments 1..3 payloads */
	WRI_RX_EPILOGUE,
	WRI_RX_DEAD       /* error recorded; no further input is accepted */
} wri_m2_rx_state;

typedef enum wri_m2_rx_ev {
	WRI_RXE_NONE = 0,
	WRI_RXE_BANNER,    /* peer banner verified: wri_m2_rx_banner() */
	WRI_RXE_SEG0,      /* preamble and segment 0 verified: desc and seg0 are valid; the owner MAY
			      choose sinks for segments 1..3 now (wri_m2_rx_sink) before calling step again */
	WRI_RXE_FRAME,     /* all segments verified and the frame is complete: desc, seg0, sinks valid */
	WRI_RXE_ABORTED,   /* late_status said the sender aborted the frame: drop it */
	WRI_RXE_ERROR      /* fatal: wri_m2_rx_error() */
} wri_m2_rx_ev;

/* Where a segment's bytes go. dst == NULL: discard. cap is the room; a segment longer than cap
 * is a fatal WR_E_M2_FRAME_TOOBIG. Bytes are CRC-checked as they land, so on any error the sink
 * contents are undefined (documented contract for zero-copy reads, architecture doc 2.5). */
typedef struct wri_m2_sink {
	uint8_t *dst;
	uint32_t cap;
} wri_m2_sink;

typedef struct wri_m2_rx {
	uint8_t state;       /* wri_m2_rx_state */
	uint8_t seg;         /* segment being received */
	uint8_t seg0_inline_crc_ok;
	uint8_t pending_ev;
	wri_m2_desc desc;
	wri_m2_banner banner;
	wri_m2_sink sink[WRI_M2_MAX_SEGS]; /* sink[0] is the owner's control buffer, set at init */
	uint32_t stored[WRI_M2_MAX_SEGS];  /* bytes written into each sink */
	uint32_t seg_pos;     /* bytes of the current element received so far */
	uint32_t crc;         /* running CRC of the current segment */
	uint32_t seg_crc[WRI_M2_MAX_SEGS]; /* verified or received CRCs per segment */
	uint8_t stage[WRI_M2_PREAMBLE_LEN]; /* staging for preamble / epilogue / inline CRC */
	uint32_t direct;      /* bytes committed straight into the sink but not yet CRC'd (see window) */
	uint32_t seg_cap_max; /* hard cap on any segment length (config) */
	wr_errinfo err;
} wri_m2_rx;

/*
 * Start (or restart) a parser at the banner. seg0 is the owner's buffer for segment 0 of every
 * frame; seg0_cap bounds control frames (config ctl_buf_bytes). seg_cap_max bounds segments 1..3.
 */
void wri_m2_rx_init(wri_m2_rx *rx, uint8_t *seg0, uint32_t seg0_cap, uint32_t seg_cap_max);

/*
 * Receive plumbing, same shape as the public pump. The parser consumes from `ring` (bytes the
 * host committed) and, when a big segment has a sink and the ring is empty, exposes the sink
 * itself as the window so data lands in place with no staging copy.
 *   window: pointer + size where the next network bytes go; 0 only when the parser is dead (an
 *           error is recorded) or the ring is full. An event that is pending (SEG0, FRAME, ABORTED)
 *           does not close the window: bytes of what follows wait in the ring until step has
 *           released the event. Call step to make room.
 *   commit: n <= window (a larger n is clamped, never an overrun); O(1), no parsing or CRC work.
 */
size_t wri_m2_rx_window(wri_m2_rx *rx, wri_ring *ring, uint8_t **ptr);
void wri_m2_rx_commit(wri_m2_rx *rx, wri_ring *ring, size_t n);

/*
 * Do parsing, CRC and copy work on committed bytes until an event or until *budget (bytes of
 * work) is spent. Returns the event; WRI_RXE_NONE means "need more input or out of budget".
 * log_fn, if non-NULL, receives every raw byte consumed in wire order (pre-auth transcript);
 * the connection passes the transcript append function. After a FRAME / SEG0 event the
 * owner reads desc / seg0 and calls step again; the parser never advances past an event by itself.
 *
 * Details the layers above may rely on:
 *   - budget may be NULL (no limit). Every byte the parser takes in, including the banner, the
 *     preamble, the CRCs and the epilogue, costs one unit exactly once; events that need no bytes
 *     are returned even when the budget is 0.
 *   - A frame always yields SEG0 first (segment 0 and its inline CRC verified, or immediately
 *     after the preamble when segment 0 is empty), then FRAME or ABORTED, or ERROR at any point.
 *     FRAME, ABORTED and ERROR are sticky: step reports the same event again until next_frame()
 *     releases a FRAME / ABORTED; ERROR is permanent (no resynchronisation) and window() is 0.
 *   - Limits: segment 0 must fit seg0_cap (seg_cap_max if segment 0 is discarded); segments 1..3
 *     must not exceed seg_cap_max nor, when a sink was chosen, its cap. The first check happens
 *     when the preamble is complete, the second at the first step after SEG0.
 *   - After a FRAME, stored[i] is the number of bytes written into sink i (0 for a discarded
 *     segment; stored[0] is the length of segment 0). Unused CRC slots of the epilogue are not
 *     checked; a used but empty segment must carry 0xFFFFFFFF.
 *   - A big segment (1 KiB or more still to come) with a sink is received straight into the sink
 *     when the ring is empty; everything else goes through the ring.
 */
typedef void (*wri_m2_log_fn)(void *log, const uint8_t *p, size_t n);
wri_m2_rx_ev wri_m2_rx_step(wri_m2_rx *rx, wri_ring *ring, const wr_prim_ops *prim, uint32_t *budget,
			    wri_m2_log_fn log_fn, void *log);

/* Choose the sink of segment 1..3. Only valid between a SEG0 event and the next step (it is
 * ignored at any other time, so the limits checked at that step cannot be bypassed). */
void wri_m2_rx_sink(wri_m2_rx *rx, unsigned seg, uint8_t *dst, uint32_t cap);
const wri_m2_banner *wri_m2_rx_banner(const wri_m2_rx *rx);
const wr_errinfo *wri_m2_rx_error(const wri_m2_rx *rx);
/* Ready the parser for the next frame after FRAME / ABORTED (also clears sinks 1..3). */
void wri_m2_rx_next_frame(wri_m2_rx *rx);

/* ---- transmit queue and frame builder ----------------------------------------------------- */

#define WRI_M2_TXQ_IOV 8u

/*
 * Pending output of one connection: an encode buffer owned by the connection plus a short
 * gather list over it and over caller memory that must stay valid until consumed (message data
 * segments, zero copy). Several frames may be queued while room remains.
 */
typedef struct wri_m2_txq {
	uint8_t *buf;      /* encode buffer */
	uint32_t cap;
	uint32_t used;     /* bytes of buf appended since the queue was last empty (not reclaimed piecemeal) */
	wr_iov iov[WRI_M2_TXQ_IOV];
	uint32_t niov;
	uint64_t pending;  /* bytes not yet consumed */
	wr_status err;     /* first hard failure of the builder (WR_E_INVAL / WR_E_TOOBIG), kept for diagnostics;
			      WR_E_BUSY is not recorded and nothing here blocks later appends; cleared by reset */
} wri_m2_txq;

void wri_m2_txq_init(wri_m2_txq *q, uint8_t *buf, uint32_t cap);
WR_INLINE int wri_m2_txq_idle(const wri_m2_txq *q) { return q->pending == 0; }
size_t wri_m2_txq_peek(const wri_m2_txq *q, wr_iov *out, size_t max);
void wri_m2_txq_consume(wri_m2_txq *q, size_t n);
/* Drop everything (connection reset): nothing pending, encode buffer free, error cleared. */
void wri_m2_txq_reset(wri_m2_txq *q);

typedef struct wri_m2_seg_src {
	const uint8_t *p;
	uint32_t len;
	uint8_t ref; /* 1 = reference caller memory (must stay valid until consumed), 0 = copy.
			Segment 3 (the data segment) is ALWAYS referenced, whatever ref says. */
} wri_m2_seg_src;

/* Append the banner (26 bytes) to the queue; reports the bytes through log_fn like tx_frame. */
WR_MUST_CHECK wr_status wri_m2_tx_banner(wri_m2_txq *q, wri_m2_log_fn log_fn, void *log);

/*
 * Append one complete crc-mode rev-1 frame: preamble (alignments 8, and 4096 for a fourth
 * segment), segment 0 and its CRC, segments 1..nseg-1, epilogue (late_status 0x0E, CRCs seed
 * 0xFFFFFFFF; an empty used segment carries 0xFFFFFFFF; unused slots 0). nseg 1..4; the last
 * segment must be non-empty when nseg > 1 (WR_E_INVAL). WR_E_BUSY / WR_E_TOOBIG if the queue has
 * no room (the caller retries after the host consumed bytes). If log_fn is non-NULL the exact bytes
 * appended are also reported through it, in wire order, for the pre-auth transcript.
 */
WR_MUST_CHECK wr_status wri_m2_tx_frame(wri_m2_txq *q, const wr_prim_ops *prim, uint8_t tag,
					const wri_m2_seg_src *seg, unsigned nseg, wri_m2_log_fn log_fn, void *log);

#endif /* WRI_M2_FRAME_H */
