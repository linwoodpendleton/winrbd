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

/*
 * The per-handshake state of one cephx handshake (section 21.2 of the architecture): which step it is at, the
 * peer kind, the two challenges, the OSD authorizer nonce, the ticket generation the OSD handshake began
 * with, the view of the session key it ended with, and the first failure. The same field list is used twice,
 * so the two can never drift apart: by wri_cx_hs (one handshake slot) and by wri_cx_client (the EMBEDDED
 * handshake, slot 0, that wri_cx_ops() drives; the fields keep their part A names, which the part A tests
 * and wri_cx_forget() read).
 */
#define WRI_CX_HS_FIELDS                                                                                   \
	wri_cx_state st;            /* IDLE until begin(); FAILED after any failure */                  \
	uint8_t target_type;        /* WRI_ENTITY_MON or WRI_ENTITY_OSD for the connection in progress */ \
	uint8_t req_new_gid;        /* 1: the AUTH_REQUEST of the monitor connection in progress carried   \
				       global id 0 (a new session); 0: it reclaimed global_id */            \
	uint64_t server_challenge;                                                                         \
	uint64_t client_challenge;                                                                         \
	uint64_t authorizer_nonce;  /* OSD authorizer; wiped when the handshake ends */                    \
	uint32_t osd_gen;           /* ticket[OSD].gen when the OSD handshake in progress began */         \
	const uint8_t *sess_key;    /* session key of the finished handshake (inside ticket[]), else NULL */ \
	size_t sess_key_len;                                                                               \
	uint32_t key_gen;           /* ticket[].gen of the slot sess_key points into, when the handshake ended */ \
	uint64_t gid;               /* the global id the handshake ended with (OSD: the one it presented) */ \
	wr_errinfo err;             /* first failure of the connection in progress; cleared by begin */

typedef struct wri_cx_client {
	const wri_ctx *x;
	char user[WR_ENTITY_MAX];   /* id without "client." */
	uint8_t user_len;
	wr_key principal;
	uint64_t global_id;         /* 0 until the monitor assigned one; reused to reclaim */
	uint32_t want_mask;         /* service tickets requested, WRI_CX_WANT_MASK; a test may change it */
	uint32_t renew_mask;        /* services asked for by the last wri_cx_renew_build */
	wri_cx_ticket ticket[WRI_CX_NTICKETS];
	uint32_t ticket_cap;
	uint8_t *scratch;           /* decrypt scratch, scratch_cap bytes; always wiped after use. Shared by every
				       handshake: the auth callbacks run to completion one at a time */
	uint32_t scratch_cap;
	WRI_CX_HS_FIELDS            /* the embedded slot-0 handshake of wri_cx_ops() */
} wri_cx_client;

/*
 * One handshake slot, bound to the client whose ticket store, principal key and global id it uses. The
 * connection's handshake slot owns it for the life of the handshake (carved with wri_cx_hs_carve, sized with
 * wri_cx_hs_mem); the `a` argument of wri_cx_hs_ops() is a pointer to it. Everything the handshake needs
 * from the client is read through `cl`; everything it changes about itself stays in these fields.
 */
typedef struct wri_cx_hs {
	wri_cx_client *cl;          /* NULL while unbound (every op answers WR_E_INVAL) */
	WRI_CX_HS_FIELDS
} wri_cx_hs;

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
 * The wri_auth_ops table whose `a` argument is a wri_cx_client *: the monitor path, driven by the embedded
 * slot-0 handshake of the client (the WRI_CX_HS_FIELDS of the client struct). It keeps ONE handshake state:
 * begin() supersedes an unfinished one (a connection that died mid-handshake never reports it), and a late
 * more / done of the superseded connection then fails or, for two OSD handshakes, can complete against the
 * other one's nonce. Use it for one connection at a time (the monitor's); several OSD connections in
 * handshake together use wri_cx_hs_ops() with one wri_cx_hs each.
 */
const wri_auth_ops *wri_cx_ops(void);

/*
 * The wri_auth_ops table whose `a` argument is a wri_cx_hs *: the same machine, with its state in the slot.
 * Any number of handshakes (monitor or OSD, one per slot) may be in flight against one client at the same
 * time and interleave step by step: a begin / more / done / failure / wipe of one touches nothing of
 * another. What stays shared on purpose, because it is the client's identity and not a handshake's:
 *   - the ticket store, the principal key, the global id and the renewal state;
 *   - a ticket stored while a handshake is in flight (a monitor reply with a new OSD ticket, a renewal)
 *     bumps the slot's generation, so an OSD handshake that began earlier fails with WR_E_STATE instead of
 *     finishing with a key that is no longer the held one;
 *   - a failed monitor done forgets every ticket and the global id (wri_cx_forget), as it does for the
 *     embedded handshake, so OSD handshakes in flight then fail with WR_E_STATE.
 * The failure of a slot is recorded in its own `err`; the client's `err` (renewal and the embedded
 * handshake) is not written by a slot.
 */
const wri_auth_ops *wri_cx_hs_ops(void);

/* Arena bytes wri_cx_hs_carve takes for cfg->max_handshakes slots. WR_E_INVAL for max_handshakes 0. */
WR_MUST_CHECK wr_status wri_cx_hs_mem(const wr_config *cfg, size_t *arena_bytes);
/* Carve cfg->max_handshakes zeroed, unbound slots (16-byte aligned) into *hs; *n gets their number. WR_E_BUDGET
 * if the arena is too small (nothing is taken then). */
WR_MUST_CHECK wr_status wri_cx_hs_carve(wri_arena *a, const wr_config *cfg, wri_cx_hs **hs, uint32_t *n);
/* Bind a slot to a client and start it idle (whatever the slot held is wiped first). WR_E_INVAL for NULL. */
WR_MUST_CHECK wr_status wri_cx_hs_init(wri_cx_hs *h, wri_cx_client *c);
/* Wipe a slot (challenges, nonce, error, the view of the key) and unbind it: the whole struct is zero after.
 * Call it when the connection that owned the slot ends, on success as well as on failure. Idempotent. */
void wri_cx_hs_wipe(wri_cx_hs *h);

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

/* ---- internal to core/src/auth/ (the handshake machine of wri_cx_hs.c, used by wri_cx_client.c) ------ */

/* The machine itself, on a bound slot. wri_cx_hs_ops() is these behind the auth-ops signatures; wri_cx_ops()
 * runs them on a stack copy of the client's embedded handshake (load, run, store, wipe the copy). */
wr_status wri_cx_hs_do_begin(wri_cx_hs *h, uint8_t target_type, wri_wr *out);
wr_status wri_cx_hs_do_more(wri_cx_hs *h, const uint8_t *reply, size_t n, wri_wr *out);
wr_status wri_cx_hs_do_done(wri_cx_hs *h, uint64_t global_id, uint32_t mode, const uint8_t *payload, size_t n);
void wri_cx_hs_do_session_key(const wri_cx_hs *h, const uint8_t **key, size_t *len);
int64_t wri_cx_hs_do_ident_gid(const wri_cx_hs *h, uint8_t target_type);
/* Copy the embedded handshake fields of the client into h (binding it to c), and back. */
void wri_cx_hs_load(wri_cx_hs *h, wri_cx_client *c);
void wri_cx_hs_store(wri_cx_client *c, const wri_cx_hs *h);

/* ---- internal to core/src/auth/ (shared by wri_cx_ticket.c, wri_cx_client.c, wri_cx_hs.c, wri_cx_renew.c) ---- */

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
