/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_sec.h - msgr2.1 SECURE mode: the second codec behind the seam of wri_m2_frame.h (design decision D8 of the architecture,
 * detailed in docs/design/core-architecture.md 34). Spec: docs/spec/msgr2-secure-mode.md 2.5 to 2.8 and 3.2 to 3.4 (checked against
 * 80 captured secure connections).
 *
 * What is here, in order: the sizes and constants of the secure framing; the nonce stream of one direction and the rule that
 * refuses a nonce twice; the per-connection state (key, two nonce streams, two GCM directions); the transmit side (a frame becomes
 * one to three tagged parts, the data of the last part encrypted piecewise through a bounce buffer); the receive side (a parser with
 * the same event contract as the crc parser: the owner only ever sees bytes of an operation whose tag verified); the switch from crc
 * to secure at the frame boundary after AUTH_DONE.
 *
 * Source layout: wri_m2_sec.c (derivation, nonces, lengths, the switch), wri_m2_sec_tx.c (transmit), wri_m2_sec_rx.c and
 * wri_m2_sec_rx2.c (receive). Nothing above the codec seam changes: wri_m2_rx_* and wri_m2_txq_* dispatch here when their `sx`
 * pointer is set (it is NULL in crc mode and until wri_m2_secure_on() succeeded).
 *
 * The invariants every function here holds: (1) a nonce/key pair is used once: a nonce is taken exactly once per GCM operation, in
 * wire order, and a nonce that would repeat is refused (WR_E_M2_NONCE) before any byte is produced; (2) plaintext received is
 * released to the layers above only after the tag of the operation it belongs to verified (the sinks are scratch until the FRAME
 * event, as in crc mode); (3) a tag failure is fatal for the connection, there is no resynchronisation; (4) every secret (the
 * connection secret, the key schedule, H, the keystream and the plaintext staging) is wiped when the connection ends or fails.
 */
#ifndef WRI_M2_SEC_H
#define WRI_M2_SEC_H

#include "wr_err.h"
#include "wr_host.h"
#include "wri_m2_frame.h"
#include "wri_pgcm.h"

/* ---- constants (msgr2-secure-mode.md 2.5, 2.6, 2.8) --------------------------------------------- */

#define WRI_M2S_SECRET_MIN 40u   /* 16 key + 12 + 12 nonce seeds; a shorter secret is WR_E_M2_SECRET */
#define WRI_M2S_SECRET_MAX 128u  /* the largest secret we accept (the servers send 64); more is WR_E_M2_SECRET */
#define WRI_M2S_KEY_LEN 16u
#define WRI_M2S_NONCE_LEN 12u
#define WRI_M2S_BLOCK 16u        /* crypto block: every segment is zero padded to a multiple of it */
#define WRI_M2S_TAG_LEN 16u
#define WRI_M2S_INLINE 48u       /* bytes of segment 0 carried in the first part */
#define WRI_M2S_P1_PLAIN 80u     /* preamble (32) + inline (48): the plaintext of part 1 */
#define WRI_M2S_P1_WIRE 96u      /* part 1 on the wire: 80 ciphertext + tag */
#define WRI_M2S_EPI_LEN 16u      /* epilogue in secure mode: late_status + 15 zero bytes (inside part 3) */
#define WRI_M2S_OPS_LIMIT_DEFAULT ((uint64_t)1 << 40) /* operations per direction before the connection is retired (34.5) */

/* ---- nonce stream (msgr2-secure-mode.md 2.6) ------------------------------------------------------ */

/*
 * One direction's nonce: 12 bytes used verbatim as the GCM IV, bytes 0..3 a fixed field, bytes 4..11 a little-endian counter. The first
 * operation uses the seed unchanged; each operation steps the counter by one (wrapping modulo 2^64, never carrying into the fixed
 * field: revision 1). `ops` counts operations taken.
 */
typedef struct wri_m2s_nonce {
	uint8_t seed[WRI_M2S_NONCE_LEN];
	uint8_t cur[WRI_M2S_NONCE_LEN];
	uint8_t started;
	uint8_t reserved[3];
	uint64_t ops;
} wri_m2s_nonce;

void wri_m2s_nonce_init(wri_m2s_nonce *n, const uint8_t seed[WRI_M2S_NONCE_LEN]);
/*
 * Take the nonce of the next operation: out = the current value, then step. Refused with WR_E_M2_NONCE (out untouched, state
 * unchanged) when the current value equals the seed again after a start (the counter wrapped all the way round: the next use would
 * repeat a nonce under the same key) or when `ops` has reached `limit` (limit 0 = no limit besides the wrap). This is the whole of
 * "nonce exhaustion"; msgr2 has no rekeying, a new key means a new TCP connection and a new authentication (34.5).
 */
WR_MUST_CHECK wr_status wri_m2s_nonce_take(wri_m2s_nonce *n, uint64_t limit, uint8_t out[WRI_M2S_NONCE_LEN]);

/* ---- per-connection secure state ------------------------------------------------------------------ */

/*
 * Key and nonces of one connection, from the 64-byte connection secret S: key = S[0..15]; the client transmits with the nonce seeded
 * from S[28..39] and receives with the one seeded from S[16..27] (`crossed` swaps them: the server's view, used by loopback tests);
 * S[40..] is unused. Both directions use the same AES key through two GCM objects (they may run at the same time).
 */
typedef struct wri_m2s {
	uint8_t active;       /* 1 after a successful wri_m2s_init until wipe */
	uint8_t reserved[7];
	wri_pgcm tx;          /* encrypt direction */
	wri_pgcm rx;          /* decrypt direction */
	wri_m2s_nonce tx_n, rx_n;
	uint64_t ops_limit;   /* WRI_M2S_OPS_LIMIT_DEFAULT unless a test lowers it */
} wri_m2s;

/*
 * Derive and arm. n < WRI_M2S_SECRET_MIN or > WRI_M2S_SECRET_MAX, a NULL secret, or a secret whose two seeds are equal (the two
 * directions would share a nonce stream): WR_E_M2_SECRET. prim may be NULL (portable GCM); a host override (wr_host.h) is chosen here,
 * per direction, and its refusal of the key is returned as the host gave it. The previous contents of *s are ignored (an object that
 * was keyed has to be wiped before it is keyed again, as for wri_pgcm). On any failure the object is wiped and inactive (all zero).
 * The caller wipes ITS copy of the secret right after this returns; nothing here keeps a pointer into it.
 */
WR_MUST_CHECK wr_status wri_m2s_init(wri_m2s *s, const wr_prim_ops *prim, const uint8_t *secret, size_t n, int crossed);
/* Release the host's key objects (if any) and zero the whole object. The object must be zero or have been through wri_m2s_init
 * (successfully or not): the host's wipe is called on what init keyed, never on indeterminate memory. Safe to call twice. */
void wri_m2s_wipe(wri_m2s *s);

/*
 * Wire arithmetic of one frame (msgr2-secure-mode.md 2.8, 5.1): len[0..nseg) are the logical segment lengths, nseg 1 .. 4 (the last
 * one non-empty when nseg > 1). Returns the bytes on the wire (always >= 96) and, if nops is non-NULL, the number of GCM operations
 * (1, 2 or 3). 0 for an invalid shape. Overflow-safe (64-bit).
 */
uint64_t wri_m2s_wire_len(const uint32_t len[WRI_M2_MAX_SEGS], unsigned nseg, unsigned *nops);

/* ---- transmit -------------------------------------------------------------------------------------- */

/*
 * Transmit-side state of one connection, bound to the queue by wri_m2_secure_on(). A frame is built so that the queue holds, in this
 * order: (a) parts 1 and 2 (and, when they fit, the whole of part 3) encrypted into the connection's encode buffer; (b) for a part 3
 * that does not fit, the rest as a STREAM: the plaintext of the REFERENCED segments (wri_m2_seg_src.ref set, and segment 3 always) stays
 * in the caller's memory (zero copy, valid until consumed, as in crc mode), is encrypted `bounce_cap` bytes at a time into the bounce
 * buffer when the host has consumed what was ahead of it, and the 16-byte epilogue and the tag are appended last. A segment that is not
 * referenced is a copy, as in crc mode: it, and every segment ahead of it in part 3, is encrypted into the encode buffer before the frame
 * call returns (so the caller may reuse its memory at once; the room it needs counts as room "now": WR_E_BUSY / WR_E_TOOBIG). Frames queued while a stream is active are refused with WR_E_BUSY (the nonce order
 * is the order of the calls, and a stream owns the end of the wire until it has drained). q->pending counts the stream's bytes from
 * the start, so wri_m2_txq_idle() is exact.
 */
typedef struct wri_m2s_tx {
	wri_m2s *s;
	uint8_t *bounce;        /* bounce buffer, owned by the connection's slot, carved by the client */
	uint32_t bounce_cap;    /* multiple of 16, at least 256 */
	uint32_t b_off, b_len;  /* unconsumed bytes of the bounce buffer: [b_off, b_off + b_len) */
	uint64_t stream_left;   /* wire bytes of the active stream not yet produced (0 = no stream) */
	struct {
		const uint8_t *p;
		uint32_t len;
	} src[WRI_M2_MAX_SEGS]; /* segments 1 .. 3 of the active stream, plaintext in caller memory */
	uint8_t nseg;           /* segments of the frame being streamed */
	uint8_t cur;            /* segment being encrypted */
	uint8_t phase;          /* 0 idle, 1 data, 2 epilogue, 3 tag */
	uint8_t late_status;    /* epilogue byte (WRI_M2_LATE_COMPLETE) */
	uint32_t cur_off;       /* bytes of src[cur] already encrypted */
} wri_m2s_tx;

/* The transmit-side functions the queue dispatches to when q->sx is set (wri_m2_txq_* and wri_m2_tx_frame in wri_m2_tx.c). */
WR_MUST_CHECK wr_status wri_m2s_tx_frame(wri_m2_txq *q, const wr_prim_ops *prim, uint8_t tag, const wri_m2_seg_src *seg,
					 unsigned nseg);
/* Append the stream's current slice (if any) to an iov list that already has n entries from the encode buffer; returns the new count. */
size_t wri_m2s_tx_peek_more(const wri_m2_txq *q, wr_iov *out, size_t n, size_t max);
/* The host consumed n bytes beyond the encode-buffer entries: advance the stream and refill the bounce; returns the part of n that was
 * not stream bytes (0 when everything was). */
size_t wri_m2s_tx_consume(wri_m2_txq *q, size_t n);
/* 1 when no stream is active and the bounce buffer is empty (the queue may then be reported drained). */
int wri_m2s_tx_done(const wri_m2_txq *q);
/* wri_m2_txq_reset: forget the stream (the connection is going away). Does not wipe the keys. */
void wri_m2s_tx_reset(wri_m2_txq *q);

/* ---- receive ---------------------------------------------------------------------------------------- */

/*
 * Receive-side state of one connection. The parser shares the fields of wri_m2_rx (desc, sink, stored, pending_ev, err) and has the
 * same events and the same window / commit / step / sink / next_frame contract as the crc parser (wri_m2_frame.h), with these
 * differences, all invisible to the layers above:
 *   - a frame arrives as 1 to 3 parts; part 1 (96 bytes) is staged and decrypted first, its tag is verified, THEN the preamble CRC and the
 *     shape rules are checked and the lengths become known (a hostile length can never be acted on before the tag said it is ours);
 *   - segment 0 reaches the owner (event SEG0) only after the tag of the operation that carried its last byte verified;
 *   - segments 1 .. 3 land in their sinks as they arrive and are decrypted in place (a big segment that has a sink is still received
 *     straight into it, the "direct" window); the plaintext stays unannounced until the epilogue's tag verified and FRAME is returned,
 *     so the contract "sink contents are undefined on any error" is unchanged;
 *   - padding (up to 15 bytes per segment) is decrypted into a scratch block and dropped, the receiver does not check it;
 *   - the work budget counts every byte taken from the ring once, plus every byte decrypted once (so a budget of 1 still makes progress);
 *   - the pre-auth transcript callback is never called (the transcript ended before the first secure frame).
 * Failures: tag mismatch WR_E_M2_SEC_TAG; nonce refusal WR_E_M2_NONCE; the shape and length rules of the crc parser with the same
 * statuses (WR_E_M2_FRAME_CRC for the preamble CRC, WR_E_M2_FRAME_FORM, WR_E_M2_FRAME_TOOBIG, WR_E_M2_TAG).
 */
typedef struct wri_m2s_rx {
	wri_m2s *s;
	uint8_t state;          /* WRI_M2SR_* (owned by wri_m2_sec_rx.c) */
	uint8_t op_open;        /* a GCM operation has been started and not finished */
	uint8_t nops;           /* operations the current frame has (1 .. 3), known after part 1 */
	uint8_t reserved8;
	uint32_t pos;           /* bytes of the current element taken from the ring */
	uint32_t dec;           /* bytes of the current element already through the GCM update */
	uint64_t part_left;     /* wire bytes of the current part still to come */
	uint8_t p1[WRI_M2S_P1_WIRE];  /* part 1: ciphertext then tag; decrypted in place */
	uint8_t blk[WRI_M2S_BLOCK];   /* staging of a final partial block (the cut at a segment end) */
	uint8_t tag[WRI_M2S_TAG_LEN]; /* the tag of the operation in progress, as received */
} wri_m2s_rx;

/* The receive-side functions wri_m2_rx_* dispatch to when rx->sx is set. */
size_t wri_m2s_rx_window(wri_m2_rx *rx, wri_ring *ring, uint8_t **ptr);
void wri_m2s_rx_commit(wri_m2_rx *rx, wri_ring *ring, size_t n);
wri_m2_rx_ev wri_m2s_rx_step(wri_m2_rx *rx, wri_ring *ring, const wr_prim_ops *prim, uint32_t *budget);
/* After wri_m2_rx_next_frame() reset the shared fields: reset the secure parser's per-frame state too. */
void wri_m2s_rx_next(wri_m2_rx *rx);

/* ---- the switch ------------------------------------------------------------------------------------- */

/* Everything one connection needs, carved by the client from the arena when the policy may end in secure mode (section 36). */
typedef struct wri_m2s_slot {
	uint8_t offer;          /* WRI_M2_OFFER_* (wri_m2_modes.h): what this connection's AUTH_REQUEST offers; 0 = crc only */
	uint8_t reserved[7];
	wri_m2s s;
	wri_m2s_rx rx;
	wri_m2s_tx tx;
} wri_m2s_slot;

/* Bytes of a slot (without the bounce buffer): a constant of the build, for the memory plan. */
size_t wri_m2s_slot_bytes(void);

/*
 * Switch a connection to secure framing. Call it once, after AUTH_DONE has been fully processed and its FRAME event released
 * (wri_m2_rx_next_frame), before the connection sends its own AUTH_SIGNATURE and before the receive parser takes another byte: the signature
 * frames are the first encrypted frames in both directions. `bounce` is the slot's bounce buffer (bounce_cap a multiple of 16, at least
 * 256; the queue's own encode buffer keeps carrying parts 1 and 2). Derives the key (wri_m2s_init, not crossed: this is the client),
 * binds both sides and sets rx->sx and q->sx; the receive parser then starts in the state wri_m2s_rx_next() leaves it in (a slot's
 * receive state is zero before that call). The queue is NOT required to be empty (34.4): crc frames still queued stay crc, every frame
 * built afterwards is secure.
 * Errors leave both sides in crc mode and the slot all zero (its previous contents are ignored; the caller fails the connection):
 *   WR_E_INVAL   a NULL rx, q or slot (nothing is touched); a NULL bounce, a bounce_cap below 256 or not a multiple of 16;
 *   WR_E_STATE   the parser is not at a frame boundary (state not "waiting for a preamble", bytes of a frame already taken, an event
 *                not yet released, bytes committed straight into a sink, a dead parser, or still before the banner is done);
 *   WR_E_M2_SECRET  the secret is missing, shorter than 40 or longer than 128 bytes, or has equal nonce seeds; or the status of a
 *                host key refusal.
 * A second call, while rx->sx or q->sx is set, is WR_E_STATE and touches nothing (the live slot stays intact; the connection fails and
 * wri_m2_secure_off() cleans up). Checks run in the order above, secret last.
 */
WR_MUST_CHECK wr_status wri_m2_secure_on(wri_m2_rx *rx, wri_m2_txq *q, wri_m2s_slot *slot, const wr_prim_ops *prim,
					 const uint8_t *secret, size_t secret_len, uint8_t *bounce, uint32_t bounce_cap);
/* Connection ended or failed: wipe the key material (the host's too), the staging and the bounce buffer, clear rx->sx and q->sx when
 * they point at this slot, zero the slot. The slot must be zero or have been through wri_m2_secure_on (success or failure). Safe to
 * call twice and on a slot that never switched. It is the END of the secure life of the seam, never a way back to crc: with the seam
 * cleared the queue would build plaintext crc frames and the parser would read crc frames, so the connection that called it must be
 * over (failed or closed) and its parser and queue restarted (wri_m2_rx_init / wri_m2_txq_init) before they carry anything again. */
void wri_m2_secure_off(wri_m2_rx *rx, wri_m2_txq *q, wri_m2s_slot *slot);

#endif /* WRI_M2_SEC_H */
