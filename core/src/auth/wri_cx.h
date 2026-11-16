/* SPDX-License-Identifier: MIT */
/*
 * wri_cx.h - cephx client side. Spec: docs/spec/cephx.md.
 *
 * Layers, bottom up:
 *   1. ciphers   : raw encrypt / decrypt for key type 1 (AES-128-CBC, fixed IV, PKCS#7) and type 2
 *                  (AES-256 CTS + HMAC-SHA384, RFC 8009 KDF). Dispatch is by the type field of
 *                  the key being used, never global (cephx.md 3.4): a ticket may carry a session
 *                  key of a different type than the key that wrapped it.
 *   2. envelope  : u8 1 | u64 magic | item, sealed with a usage number (cephx.md 2.6).
 *   3. tickets   : the per-service store, times converted to the local monotonic clock at receipt.
 *   4. the client machine: monitor handshake (CEPHX_GET_AUTH_SESSION_KEY), in-session renewal
 *                  (CEPHX_GET_PRINCIPAL_SESSION_KEY), OSD authorizer with its challenge round
 *                  trip. It plugs into a msgr2 connection through wri_auth_ops.
 * Secrets are never logged and are wiped with wri_secure_zero when dropped.
 */
#ifndef WRI_CX_H
#define WRI_CX_H

#include "wr_err.h"
#include "wr_key.h"
#include "wr_types.h"
#include "wri_cursor.h"
#include "wri_ctx.h"
#include "wri_m2_conn.h"
#include "wri_mem.h"

/* ---- constants (cephx.md 2.1) ------------------------------------------------------------- */

#define WRI_CX_MAGIC 0xff009cad8826aa55ull
#define WRI_CX_SERVICE_MON 0x01u
#define WRI_CX_SERVICE_OSD 0x04u
#define WRI_CX_SERVICE_AUTH 0x20u
#define WRI_CX_REQ_GET_AUTH_SESSION_KEY 0x0100u
#define WRI_CX_REQ_GET_PRINCIPAL_SESSION_KEY 0x0200u
#define WRI_CX_USAGE_CONN_SECRET 0x03u
#define WRI_CX_USAGE_TICKET_SESSION_KEY 0x04u
#define WRI_CX_USAGE_TICKET_BLOB 0x05u
#define WRI_CX_USAGE_AUTHORIZE 0x10u
#define WRI_CX_USAGE_AUTHORIZE_CHALLENGE 0x11u
#define WRI_CX_USAGE_AUTHORIZE_REPLY 0x12u
#define WRI_CX_MON_AUTH_MODE 10u /* first auth_payload byte on a monitor connection */
#define WRI_CX_AUTHORIZER_V 1u
#define WRI_CX_WANT_MASK 0x24u   /* AUTH | OSD */

/* ---- 1. ciphers ---------------------------------------------------------------------------- */

/* Ciphertext length for a plaintext of n bytes under a key type (type 1: padded up, a full extra
 * block when aligned; type 2: n + 16 confounder + 24 MAC). 0 for an unsupported type. */
size_t wri_cx_cipher_len(unsigned key_type, size_t n);

/*
 * Raw encrypt / decrypt of one buffer. `usage` is ignored by type 1. Type-2 encrypt draws a
 * 16-byte confounder from the host RNG (WR_E_HOST_RANDOM); type-2 decrypt verifies the MAC
 * (constant time) before touching the ciphertext (WR_E_AUTH_DECRYPT on mismatch), needs >= 40
 * bytes. Type-1 decrypt needs a non-zero multiple of 16 and checks the pad byte is 1..16.
 * out_cap too small: WR_E_TOOBIG. in == out is NOT allowed.
 */
WR_MUST_CHECK wr_status wri_cx_encrypt(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *in,
				       size_t n, uint8_t *out, size_t out_cap, size_t *out_n);
WR_MUST_CHECK wr_status wri_cx_decrypt(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *in,
				       size_t n, uint8_t *out, size_t out_cap, size_t *out_n);

/*
 * Encrypt with the plaintext already in place (internal to wri_cx_cipher.c / wri_cx_envelope.c; the
 * envelope builder uses it to avoid a second buffer). The caller writes n_plain plaintext bytes at
 * buf + wri_cx_enc_lead(k->type) (0 for type 1, 16 for type 2, where the confounder goes), buf holds
 * cap bytes in all, and the ciphertext comes out at buf[0 .. *out_n). cap must be >=
 * wri_cx_cipher_len(type, n_plain), else WR_E_TOOBIG. On failure buf is wiped.
 */
size_t wri_cx_enc_lead(unsigned key_type);
WR_MUST_CHECK wr_status wri_cx_encrypt_at(const wri_ctx *x, const wr_key *k, uint32_t usage, uint8_t *buf,
					  size_t cap, size_t n_plain, size_t *out_n);

/* RFC 8009 KDF with an empty context, as Ceph uses it: HMAC-SHA384(base, 00 00 00 01 | usage(be32) |
 * type_byte | 00 | out_bits(be32)), first out_len bytes (Ke: 0xAA, 32; Ki: 0x55, 24). out_len must be
 * <= 48; for a larger value the output is zero-filled (never a partial key). */
void wri_cx_kdf(const wr_prim_ops *prim, const uint8_t *base, size_t blen, uint32_t usage, uint8_t type_byte,
		uint8_t *out, size_t out_len);

/* The "key" field of CephXAuthenticate (cephx.md 2.8), per key type. Type 1 is deterministic. */
WR_MUST_CHECK wr_status wri_cx_challenge_proof(const wri_ctx *x, const wr_key *k, uint64_t server_challenge,
					       uint64_t client_challenge, uint64_t *proof);

/* ---- 2. envelope --------------------------------------------------------------------------- */

/*
 * seal: encrypt (u8 1 | u64 magic | item). Output is the raw ciphertext; the caller adds the
 * u32 length prefix when the shape is "length-prefixed" (wri_cx_put_sealed does both).
 * open: decrypt into scratch, require the magic, point *item at the item bytes inside scratch.
 * WR_E_AUTH_DECRYPT on MAC / magic / padding failure. scratch must hold >= n bytes.
 */
WR_MUST_CHECK wr_status wri_cx_seal(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *item,
				    size_t item_len, uint8_t *out, size_t out_cap, size_t *out_n);
WR_MUST_CHECK wr_status wri_cx_open(const wri_ctx *x, const wr_key *k, uint32_t usage, const uint8_t *ct, size_t n,
				    uint8_t *scratch, size_t scratch_cap, const uint8_t **item, size_t *item_len);

/* ---- 3. tickets ---------------------------------------------------------------------------- */

#define WRI_CX_NTICKETS 2u /* AUTH and OSD */
#define WRI_CX_SLOT_AUTH 0u /* index in wri_cx_client.ticket[] */
#define WRI_CX_SLOT_OSD 1u

/*
 * One held service ticket. `blob` is the encoded CephXTicketBlob exactly as it is re-sent inside an
 * authorizer or as the old ticket of a reconnect (u8 v | u64 secret_id | u32 len | data, cephx.md
 * 2.7); the machine never looks inside the data. Its storage is ticket_cap bytes of the arena.
 */
typedef struct wri_cx_ticket {
	uint8_t have;
	uint32_t service;       /* WRI_CX_SERVICE_* */
	uint64_t secret_id;     /* from the CephXTicketBlob header (informational; the blob is re-sent whole) */
	wr_key session_key;     /* its own type (cephx.md 3.4) */
	uint8_t *blob;
	uint32_t blob_len;
	uint64_t valid_until_ms;  /* local monotonic: receipt time + validity */
	uint64_t renew_at_ms;     /* valid_until - validity_seconds / 4 (real-valued, so seconds * 250 ms) */
	uint32_t gen;             /* bumped every time the slot is stored, so a handshake notices a swap */
} wri_cx_ticket;

/* ---- 4. the client machine ------------------------------------------------------------------ */

typedef enum wri_cx_state {
	WRI_CX_IDLE = 0,
	WRI_CX_MON_SENT_REQ,       /* AUTH_REQUEST payload sent (mode byte, entity, global id) */
	WRI_CX_MON_SENT_AUTH,      /* challenge answered; waiting for AUTH_DONE */
	WRI_CX_OSD_SENT_AUTHORIZER,/* authorizer sent; waiting for the challenge */
	WRI_CX_OSD_SENT_CHALLENGE, /* challenge answered; waiting for AUTH_DONE */
	WRI_CX_DONE,
	WRI_CX_FAILED
} wri_cx_state;

typedef struct wri_cx_client {
	const wri_ctx *x;
	wri_cx_state st;
	uint8_t target_type;        /* WRI_ENTITY_MON or WRI_ENTITY_OSD for the connection in progress */
	char user[WR_ENTITY_MAX];   /* id without "client." */
	uint8_t user_len;
	uint8_t req_new_gid;        /* 1: the AUTH_REQUEST of the monitor connection in progress carried
				       global id 0 (a new session); 0: it reclaimed global_id */
	wr_key principal;
	uint64_t global_id;         /* 0 until the monitor assigned one; reused to reclaim */
	uint64_t server_challenge;
	uint64_t client_challenge;
	uint64_t authorizer_nonce;  /* OSD authorizer; wiped when the handshake ends */
	uint32_t want_mask;         /* service tickets requested, WRI_CX_WANT_MASK; a test may change it */
	uint32_t renew_mask;        /* services asked for by the last wri_cx_renew_build */
	uint32_t osd_gen;           /* ticket[OSD].gen when the OSD handshake in progress began */
	wri_cx_ticket ticket[WRI_CX_NTICKETS];
	uint32_t ticket_cap;
	uint8_t *scratch;           /* decrypt scratch, scratch_cap bytes; always wiped after use */
	uint32_t scratch_cap;
	const uint8_t *sess_key;    /* the session key of the finished handshake (inside ticket[]), else NULL */
	size_t sess_key_len;
	wr_errinfo err;             /* first failure of the connection in progress; cleared by begin */
} wri_cx_client;

/* Arena bytes wri_cx_client_init takes for a given config (ticket blobs + scratch). */
wr_status wri_cx_client_mem(const wr_config *cfg, size_t *arena_bytes);

/*
 * Initialise: copies the principal key (validated: type 1 or 2, secret long enough) and the user (a
 * leading "client." is stripped; 1 to WR_ENTITY_MAX - 1 bytes), carves ticket and scratch storage
 * from the arena (WR_E_BUDGET if it is too small), sets want_mask to WRI_CX_WANT_MASK. WR_E_INVAL for
 * a ticket_cap outside 13 .. 65536. On any failure everything copied so far is wiped and *c is zero.
 */
WR_MUST_CHECK wr_status wri_cx_client_init(wri_cx_client *c, const wri_ctx *x, wri_arena *a, const wr_cluster_spec *spec);
/* Wipe every secret (principal, session keys, tickets, scratch). */
void wri_cx_client_wipe(wri_cx_client *c);

/*
 * The wri_auth_ops table; the `a` argument is a wri_cx_client *. Handles monitor and OSD peers.
 * The machine keeps ONE handshake state (state, target, challenge, nonce): the caller runs one cephx
 * handshake at a time. begin() supersedes an unfinished one (a connection that died mid-handshake
 * never reports it), and a late more / done of the superseded connection then fails or, for two
 * OSD handshakes, can complete against the other one's nonce; a failed monitor done also forgets
 * every ticket. Two connections in handshake at once therefore cause spurious failures and retries,
 * never a weaker authentication, but the engine should not do it.
 */
const wri_auth_ops *wri_cx_ops(void);

/* Ticket queries. A ticket counts as held while now < valid_until, needs renewal at renew_at. */
int wri_cx_have(const wri_cx_client *c, uint32_t service, uint64_t now_ms);
const wri_cx_ticket *wri_cx_ticket_get(const wri_cx_client *c, uint32_t service);
/* Earliest renew_at over held tickets; WR_DEADLINE_NONE if none. */
uint64_t wri_cx_next_renew_ms(const wri_cx_client *c);
/* Drop all tickets and the global id (used after a definitive AUTH failure so we start clean). */
void wri_cx_forget(wri_cx_client *c);

/*
 * In-session renewal on an established monitor session (MAuth / MAuthReply, cephx.md 3.6 B,
 * mon-client.md 3.8): build the MAuth auth_payload (CephXRequestHeader 0x0200 | authorizer for
 * service AUTH | CephXServiceTicketRequest{want}) and later handle the reply payload. The
 * MAuth / MAuthReply message wrappers are the monitor module's job (wri_mon.h).
 */
WR_MUST_CHECK wr_status wri_cx_renew_build(wri_cx_client *c, uint32_t service_mask, wri_wr *payload);
/* Accepted only while a request built by wri_cx_renew_build is pending (WR_E_STATE otherwise: a
 * replayed or unsolicited reply never replaces a ticket); the first accepted reply ends the request. */
WR_MUST_CHECK wr_status wri_cx_renew_handle(wri_cx_client *c, const uint8_t *payload, size_t n);

/* ---- internal to core/src/auth/ (shared by wri_cx_ticket.c, wri_cx_client.c, wri_cx_renew.c) ------ */

/* Drop one ticket slot: wipe the session key and the blob, bump gen. */
void wri_cx_slot_clear(wri_cx_client *c, unsigned slot);

/* Slot of a service ticket (WRI_CX_SLOT_*), or -1 for a service this client does not keep. */
int wri_cx_slot_of(uint32_t service);

#define WRI_CX_TR_INITIAL 1u  /* reply to GET_AUTH_SESSION_KEY: exactly one ticket, for AUTH, key = principal */
#define WRI_CX_TR_SERVICES 2u /* extra / renewal reply: tickets for other services, key = AUTH session key */

/*
 * Decode a "ticket reply" (cephx.md 2.7) from r and store the tickets this client keeps (AUTH, OSD) as
 * they are validated, one slot at a time (a failed ticket leaves its slot as it was). Tickets for other
 * services are skipped without being decrypted. *stored gets the mask of services stored. The
 * reader's position is left after the reply. See wri_cx_ticket.c for the error codes.
 */
WR_MUST_CHECK wr_status wri_cx_ticket_reply(wri_cx_client *c, wri_rd *r, unsigned kind, uint32_t *stored);

/* Record the first failure in c->err and return st (never logs a secret). */
wr_status wri_cx_fail(wri_cx_client *c, wr_status st, unsigned line, const char *what, uint64_t a0, uint64_t a1,
		      uint64_t a2);
#define WRI_CX_FAIL(c, st, what, a0, a1, a2) \
	wri_cx_fail((c), (st), (unsigned)__LINE__, (what), (uint64_t)(a0), (uint64_t)(a1), (uint64_t)(a2))

/*
 * Append an authorizer to w: u8 1 | u64 global_id | u32 service | the ticket blob | u32 len | proof,
 * the proof being CephXAuthorize{v 2, nonce, have_challenge, plus_one} sealed with the ticket's
 * session key under usage 0x10 (cephx.md 2.7, 3.3). Draws a confounder from the host RNG for a
 * type-2 key. The writer's sticky error is returned if it has one.
 */
WR_MUST_CHECK wr_status wri_cx_put_authorizer(const wri_cx_client *c, uint32_t service, const wri_cx_ticket *t,
					      uint64_t nonce, int have_challenge, uint64_t plus_one, wri_wr *w);

#endif /* WRI_CX_H */
