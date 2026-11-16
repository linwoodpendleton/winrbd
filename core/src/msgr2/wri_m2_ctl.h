/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_ctl.h - msgr2 control-frame payloads (segment 0 of non-MESSAGE frames), the 41-byte
 * ceph_msg_header2, and the pre-auth transcript with the AUTH_SIGNATURE computation.
 * Spec: docs/spec/msgr2.md 2.7, 2.9, 3.3, 3.4. Control payloads have no version header of
 * their own: fields back to back. Every decoder is bounds-checked and caps every count.
 *
 * Decoded structs borrow from the input buffer (blobs are pointers into it); they are valid
 * only while that buffer is.
 *
 * Decoder contract (all control-payload decoders below, except where a function says otherwise):
 *  - the reader must be bounded to exactly segment 0 of the frame (rev-1 crc mode has no padding);
 *  - every field is read, then the reader must be exactly at its end: a payload with bytes left
 *    over is WR_E_ENCODING (the spec gives these frames a fixed field list and no extension room,
 *    msgr2.md 2.1), a short one is WR_E_TRUNCATED;
 *  - every vector count is capped (WRI_M2_VEC_WIRE_MAX on the wire, WRI_M2_MODES_MAX stored), every
 *    blob at WRI_M2_AUTH_BLOB_MAX: over the cap is WR_E_TOOBIG;
 *  - on any error the output is zeroed. NULL arguments are WR_E_INVAL.
 * Encoders never fail by return value: errors (buffer too small WR_E_TOOBIG, NULL data with a
 * length WR_E_INVAL, a count or blob over the cap WR_E_TOOBIG) are sticky in the writer.
 */
#ifndef WRI_M2_CTL_H
#define WRI_M2_CTL_H

#include "wr_err.h"
#include "wr_host.h"
#include "wr_types.h"
#include "wri_cursor.h"
#include "wri_m2_addr.h"

/* Entity types (HELLO) and constants (msgr2.md 2.7 / cephx.md 2.1). */
#define WRI_ENTITY_MON 0x01u
#define WRI_ENTITY_OSD 0x04u
#define WRI_ENTITY_CLIENT 0x08u
#define WRI_AUTH_METHOD_CEPHX 2u
#define WRI_CONN_MODE_CRC 1u
#define WRI_CONN_MODE_SECURE 2u

#define WRI_M2_MODES_MAX 4u    /* entries kept from a modes / methods vector */
#define WRI_M2_VEC_WIRE_MAX 16u /* largest u32 vector count accepted (and written) */
#define WRI_M2_AUTH_BLOB_MAX 65536u

/* HELLO: entity_type u8, peer_addr entity_addr_t */
typedef struct wri_m2_hello {
	uint8_t entity_type;
	wri_eaddr peer_addr;
} wri_m2_hello;
WR_MUST_CHECK wr_status wri_m2_hello_decode(wri_rd *r, wri_m2_hello *out);
void wri_m2_hello_encode(wri_wr *w, const wri_m2_hello *h);

/* AUTH_REQUEST: method u32, preferred_modes vec<u32>, auth_payload blob */
void wri_m2_auth_request_encode(wri_wr *w, uint32_t method, const uint32_t *modes, size_t nmodes,
				const uint8_t *payload, size_t payload_len);

/* AUTH_BAD_METHOD: method u32, result i32, allowed_methods vec<u32>, allowed_modes vec<u32> */
typedef struct wri_m2_bad_method {
	uint32_t method;
	int32_t result;
	uint32_t allowed_methods[WRI_M2_MODES_MAX];
	uint32_t n_methods; /* stored (<= WRI_M2_MODES_MAX) */
	uint32_t allowed_modes[WRI_M2_MODES_MAX];
	uint32_t n_modes;
} wri_m2_bad_method;
WR_MUST_CHECK wr_status wri_m2_bad_method_decode(wri_rd *r, wri_m2_bad_method *out);
void wri_m2_bad_method_encode(wri_wr *w, const wri_m2_bad_method *b); /* writes the stored entries */

/* AUTH_REPLY_MORE / AUTH_REQUEST_MORE: one blob */
WR_MUST_CHECK wr_status wri_m2_auth_more_decode(wri_rd *r, const uint8_t **payload, uint32_t *len);
void wri_m2_auth_more_encode(wri_wr *w, const uint8_t *payload, size_t len);

/* AUTH_DONE: global_id u64, connection_mode u32, auth_payload blob */
typedef struct wri_m2_auth_done {
	uint64_t global_id;
	uint32_t mode;
	const uint8_t *payload;
	uint32_t payload_len;
} wri_m2_auth_done;
WR_MUST_CHECK wr_status wri_m2_auth_done_decode(wri_rd *r, wri_m2_auth_done *out);
void wri_m2_auth_done_encode(wri_wr *w, const wri_m2_auth_done *d);

/* AUTH_SIGNATURE: exactly 32 bytes */
WR_MUST_CHECK wr_status wri_m2_auth_sig_decode(wri_rd *r, uint8_t out[32]);
void wri_m2_auth_sig_encode(wri_wr *w, const uint8_t sig[32]);

/* CLIENT_IDENT: addrs vec, target_addr, gid i64, global_seq u64, supported u64, required u64, flags u64, cookie u64 */
typedef struct wri_m2_client_ident {
	wri_eaddr addrs[1]; /* we send exactly one */
	wri_eaddr target;
	int64_t gid;
	uint64_t global_seq;
	uint64_t supported, required, flags, cookie;
} wri_m2_client_ident;
void wri_m2_client_ident_encode(wri_wr *w, const wri_m2_client_ident *c);

/* SERVER_IDENT: addrs vec, gid i64, global_seq u64, supported u64, required u64, flags u64, cookie u64 */
typedef struct wri_m2_server_ident {
	wri_eaddr addrs[WRI_EADDRVEC_MAX];
	size_t n_addrs; /* stored */
	int64_t gid;
	uint64_t global_seq, supported, required, flags, cookie;
} wri_m2_server_ident;
WR_MUST_CHECK wr_status wri_m2_server_ident_decode(wri_rd *r, wri_m2_server_ident *out);
/* Writes the first min(n_addrs, WRI_EADDRVEC_MAX) addresses. */
void wri_m2_server_ident_encode(wri_wr *w, const wri_m2_server_ident *s);

/* IDENT_MISSING_FEATURES: features u64.  KEEPALIVE2 / _ACK: utime.  ACK: seq u64. */
WR_MUST_CHECK wr_status wri_m2_u64_decode(wri_rd *r, uint64_t *out); /* single-u64 payloads */
void wri_m2_u64_encode(wri_wr *w, uint64_t v);
WR_MUST_CHECK wr_status wri_m2_keepalive_decode(wri_rd *r, uint32_t *sec, uint32_t *nsec);
void wri_m2_keepalive_encode(wri_wr *w, uint32_t sec, uint32_t nsec);

/* ---- ceph_msg_header2 (41 bytes, segment 0 of a MESSAGE frame; msgr2.md 2.9) ---------------- */

#define WRI_M2_HDR2_LEN 41u
#define WRI_M2_MSGF_COMPLETE_NOCRC 3u /* flags value the stock client sends */

typedef struct wri_m2_hdr2 {
	uint64_t seq;
	uint64_t tid;
	uint16_t type;
	uint16_t priority;
	uint16_t version;
	uint32_t data_pre_padding_len;
	uint16_t data_off;
	uint64_t ack_seq;
	uint8_t flags;
	uint16_t compat_version;
} wri_m2_hdr2;

/* Needs len >= 41 (the stock code does not check; we must). Extra bytes are ignored. Every field
 * is peer-controlled: data_pre_padding_len and data_off are layout hints, never lengths to trust
 * (the segment lengths of the frame are the only authority), and flags is not validated. */
WR_MUST_CHECK wr_status wri_m2_hdr2_decode(const uint8_t *p, size_t len, wri_m2_hdr2 *out);
void wri_m2_hdr2_encode(uint8_t out[WRI_M2_HDR2_LEN], const wri_m2_hdr2 *h);

/* ---- pre-auth transcript and AUTH_SIGNATURE (msgr2.md 3.3, 3.4) ------------------------------ */

/*
 * Two capped byte logs per handshake: every byte received and every byte sent since the TCP
 * connection opened (banner, HELLO, AUTH_* frames, as on the wire), independent buffers. They are
 * kept across AUTH_BAD_METHOD retries and wiped after AUTH_SIGNATURE is verified.
 */
typedef struct wri_m2_preauth {
	uint8_t *rx_buf;
	uint8_t *tx_buf;
	uint32_t cap;
	uint32_t rx_len, tx_len;
	uint8_t enabled;
	wr_status err; /* WR_E_M2_PREAUTH_TOOBIG once a log would overflow: the handshake must fail */
} wri_m2_preauth;

void wri_m2_preauth_init(wri_m2_preauth *p, uint8_t *rx_buf, uint8_t *tx_buf, uint32_t cap);
void wri_m2_preauth_rx(void *p, const uint8_t *b, size_t n); /* matches wri_m2_log_fn */
void wri_m2_preauth_tx(void *p, const uint8_t *b, size_t n); /* matches wri_m2_log_fn */
/* Stop appending (do this before building our own AUTH_SIGNATURE, so neither signature frame
 * enters a log). The buffers are kept for the two HMACs until wri_m2_preauth_wipe(). */
void wri_m2_preauth_stop(wri_m2_preauth *p);
/* Zero the logged bytes, set both lengths to 0 and stay disabled. err is left as it was. */
void wri_m2_preauth_wipe(wri_m2_preauth *p);

/* Our AUTH_SIGNATURE = HMAC-SHA256(session_key, every byte RECEIVED); the value expected from the
 * server = HMAC-SHA256(session_key, every byte we SENT). key_len 0 / NULL = all-zero 32 bytes
 * (auth method none). */
/* Callers must check p->err == WR_OK first: after an overflow the logs are incomplete and a signature
 * over them is meaningless. */
void wri_m2_sig_ours(const wr_prim_ops *prim, const wri_m2_preauth *p, const uint8_t *key, size_t key_len, uint8_t out[32]);
void wri_m2_sig_expected(const wr_prim_ops *prim, const wri_m2_preauth *p, const uint8_t *key, size_t key_len, uint8_t out[32]);

/*
 * Check the AUTH_SIGNATURE received from the server against HMAC-SHA256(key, every byte we sent),
 * comparing in constant time. Use this instead of comparing the output of wri_m2_sig_expected()
 * yourself. Returns WR_OK; WR_E_M2_SIGNATURE on a mismatch; the sticky p->err
 * (WR_E_M2_PREAUTH_TOOBIG) when a log overflowed; WR_E_STATE while the logs are still being appended
 * to (call wri_m2_preauth_stop() before building our own AUTH_SIGNATURE); WR_E_INVAL for NULL
 * arguments or a key that is neither (NULL, 0) = "no key" nor (non-NULL, non-zero length). Call it
 * before wri_m2_preauth_wipe().
 */
WR_MUST_CHECK wr_status wri_m2_sig_verify(const wr_prim_ops *prim, const wri_m2_preauth *p, const uint8_t *key,
					  size_t key_len, const uint8_t got[32]);

#endif /* WRI_M2_CTL_H */
