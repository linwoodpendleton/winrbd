/* SPDX-License-Identifier: MIT */
/*
 * wr_err.h - status codes and structured error information.
 *
 * A wr_status is 0 for success or -(code) for failure. Codes are stable numbers, grouped
 * by module so a log line identifies the layer at a glance:
 *
 *      1 ..  19   generic (any module)
 *     20 ..  39   host services and crypto primitives
 *     40 ..  79   msgr2 (framing, handshake, connection)
 *     80 ..  99   cephx (keys, tickets, authorizer)
 *    100 .. 119   monitor client (monmap, subscription, hunting)
 *    120 .. 139   OSD map and incrementals (decoding, applying, the map store)
 *    140 .. 159   pools (lookup, unsupported configurations)
 *    160 .. 179   CRUSH (decoding, rules, mapping)
 *    180 .. 199   object placement
 *    200 .. 239   reserved: osd client, rbd (later milestones)
 *
 * Adding a code = appending one line to the right block of WR_STATUS_LIST. The text is
 * English, static, and never formatted: hosts that want another language key off the code.
 * The core never uses errno and never aborts on untrusted input.
 */
#ifndef WR_ERR_H
#define WR_ERR_H

#include "wr_types.h"

/* X(NAME, code, "English text") */
#define WR_STATUS_LIST(X)                                                                     \
	/* generic */                                                                             \
	X(WR_E_INVAL, 1, "invalid argument")                                                      \
	X(WR_E_STATE, 2, "call not valid in the current state")                                   \
	X(WR_E_BUSY, 3, "resource busy, retry later")                                             \
	X(WR_E_TOOBIG, 4, "value or buffer too large")                                            \
	X(WR_E_TRUNCATED, 5, "input ended before the structure was complete")                     \
	X(WR_E_BUDGET, 6, "configured memory or count budget exhausted")                          \
	X(WR_E_UNSUPPORTED, 7, "feature or version not supported by this client")                 \
	X(WR_E_CANCELLED, 8, "operation cancelled")                                               \
	X(WR_E_TIMEOUT, 9, "operation timed out")                                                 \
	X(WR_E_ABI, 10, "ABI version or structure size mismatch")                                 \
	X(WR_E_OVERFLOW, 11, "arithmetic overflow in a length or count")                          \
	X(WR_E_ENCODING, 12, "malformed encoding")                                                \
	X(WR_E_RANGE, 13, "value out of range")                                                   \
	/* host services and crypto */                                                            \
	X(WR_E_HOST_RANDOM, 20, "host could not supply random bytes")                             \
	X(WR_E_CRYPTO_KEY, 21, "unusable key (wrong type or length)")                             \
	X(WR_E_CRYPTO_MAC, 22, "message authentication code mismatch")                            \
	X(WR_E_CRYPTO_LEN, 23, "bad length for this cipher operation")                            \
	X(WR_E_NET_CONNECT, 24, "network connection could not be established")                    \
	X(WR_E_NET_CLOSED, 25, "network connection closed by the peer or the host")               \
	/* msgr2 */                                                                               \
	X(WR_E_M2_BANNER, 40, "bad msgr2 banner")                                                 \
	X(WR_E_M2_PEER_V1, 41, "peer speaks the legacy v1 protocol, only msgr2 is supported")     \
	X(WR_E_M2_FEATURES, 42, "msgr2 feature negotiation failed")                               \
	X(WR_E_M2_FRAME_CRC, 43, "frame checksum mismatch")                                       \
	X(WR_E_M2_FRAME_FORM, 44, "malformed frame")                                              \
	X(WR_E_M2_FRAME_TOOBIG, 45, "frame or segment larger than the configured limit")          \
	X(WR_E_M2_TAG, 46, "unknown or unsupported frame tag")                                    \
	X(WR_E_M2_STATE, 47, "frame not allowed in this connection state")                        \
	X(WR_E_M2_HELLO, 48, "unexpected peer type in HELLO")                                     \
	X(WR_E_M2_IDENT, 49, "peer identification frame rejected")                                \
	X(WR_E_M2_ADDR, 50, "server addresses do not contain the dialled address")                \
	X(WR_E_M2_PREAUTH_TOOBIG, 51, "pre-authentication transcript larger than the limit")      \
	X(WR_E_M2_SIGNATURE, 52, "authentication signature mismatch")                             \
	X(WR_E_M2_MODE, 53, "connection mode not offered or not supported")                       \
	X(WR_E_M2_BAD_METHOD, 54, "server refused the offered authentication method or mode")     \
	X(WR_E_M2_MISSING_FEATURES, 55, "server requires features this client does not advertise") \
	X(WR_E_M2_WAIT, 56, "server asked the client to wait (connection race)")                  \
	X(WR_E_M2_ABORTED_FRAME, 57, "peer sent an aborted frame")                                \
	X(WR_E_M2_SEQ, 58, "message sequence number out of order")                                \
	X(WR_E_M2_HANDSHAKE_TIMEOUT, 59, "connection handshake did not finish in time")           \
	/* cephx */                                                                               \
	X(WR_E_AUTH_DENIED, 80, "server denied authentication (wrong key or no permission)")      \
	X(WR_E_AUTH_DECRYPT, 81, "could not decrypt an authentication message (wrong key?)")      \
	X(WR_E_AUTH_PROTO, 82, "unexpected authentication message")                               \
	X(WR_E_AUTH_GID0, 83, "server assigned global id 0")                                      \
	X(WR_E_AUTH_TICKET_TOOBIG, 84, "service ticket larger than the configured limit")         \
	X(WR_E_AUTH_TICKET_EXPIRED, 85, "service ticket expired")                                 \
	X(WR_E_AUTH_KEY_TYPE, 86, "unsupported cephx key type")                                   \
	X(WR_E_AUTH_RESULT, 87, "server returned an error status in the authentication reply")    \
	/* monitor client */                                                                      \
	X(WR_E_MON_MAP_VERSION, 100, "monitor map version not supported")                         \
	X(WR_E_MON_NO_V2_ADDR, 101, "no msgr2 monitor address available")                         \
	X(WR_E_MON_UNREACHABLE, 102, "no monitor could be reached")                               \
	X(WR_E_MON_FSID, 103, "cluster id mismatch (wrong cluster?)")                             \
	X(WR_E_MON_MSG_TOOBIG, 104, "monitor message larger than the configured limit")           \
	X(WR_E_MON_PROTO, 105, "unexpected monitor message")                                      \
	X(WR_E_MON_HOSTS_SYNTAX, 106, "monitor address list could not be parsed")                  \
	/* OSD map */                                                                             \
	X(WR_E_MAP_NONE, 120, "no OSD map received yet")                                          \
	X(WR_E_MAP_FSID, 121, "OSD map belongs to another cluster (fsid mismatch)")               \
	X(WR_E_MAP_VERSION, 122, "OSD map or incremental encoding version not supported")         \
	X(WR_E_MAP_CORRUPT, 123, "malformed OSD map or incremental")                              \
	X(WR_E_MAP_EPOCH, 124, "incremental does not follow the held epoch")                      \
	X(WR_E_MAP_BUDGET, 125, "OSD map does not fit the configured map budget (cluster too large for this profile)") \
	X(WR_E_MAP_CRC, 126, "OSD map checksum mismatch")                                         \
	X(WR_E_MAP_RESYNC, 127, "OSD map cannot be advanced incrementally, a full map is needed") \
	/* pools */                                                                               \
	X(WR_E_POOL_NOT_FOUND, 140, "pool not found in the OSD map")                              \
	X(WR_E_POOL_UNSUPPORTED, 141, "pool configuration not supported (erasure coded, cache tier, stretch or unsupported hash)") \
	/* CRUSH */                                                                               \
	X(WR_E_CRUSH_ENCODING, 160, "malformed CRUSH map")                                        \
	X(WR_E_CRUSH_UNSUPPORTED, 161, "CRUSH map uses an unsupported bucket algorithm, rule step or tunable") \
	X(WR_E_CRUSH_NO_RULE, 162, "the pool's CRUSH rule does not exist or is not a replicated rule") \
	X(WR_E_CRUSH_LOOP, 163, "CRUSH hierarchy too deep or cyclic")                             \
	X(WR_E_CRUSH_WORK, 164, "CRUSH evaluation exceeded its work budget")                      \
	/* placement */                                                                           \
	X(WR_E_PLACE_UNMAPPABLE, 180, "no usable OSD currently serves this placement group")

enum {
#define WR_X_ENUM(name, code, text) name = -(code),
	WR_STATUS_LIST(WR_X_ENUM)
#undef WR_X_ENUM
	WR_STATUS_ENUM_END_ = 0
};

/* Static English text for a status; "unknown status" for a code not in the list. Never NULL. */
const char *wr_strerror(wr_status st);
/* Symbolic name, for example "WR_E_M2_FRAME_CRC"; "WR_E_UNKNOWN" for an unlisted code. */
const char *wr_status_name(wr_status st);

/*
 * Structured detail for the first failure of a machine (connection, client). "First failure
 * wins": later errors caused by the same failure do not overwrite it, so the root cause is
 * what the host reads. All pointers are to static strings. A caller that passes one to a core
 * function zeroes it first: the core reads `status` to keep the first failure and leaves the
 * structure alone when it already holds one.
 */
typedef struct wr_errinfo {
	wr_status status;
	uint8_t module;       /* WR_MOD_* of the layer that detected it */
	uint8_t reserved8;
	uint16_t line;        /* source line of the detection point (debugging aid) */
	int32_t peer_result;  /* result sent by the peer (negative errno), 0 if none */
	uint32_t conn;        /* wr_conn_id, 0 if none */
	uint64_t a0, a1, a2;  /* context: expected / got / offset / mask ... meaning depends on status */
	const char *what;     /* static string naming the check that failed, or NULL */
} wr_errinfo;

#endif /* WR_ERR_H */
