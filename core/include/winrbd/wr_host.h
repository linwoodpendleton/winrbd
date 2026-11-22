/* SPDX-License-Identifier: MIT */
/*
 * wr_host.h - the shim: everything the core needs from the host that cannot be expressed as
 * data flowing through the pump API of wr_client.h.
 *
 * The core never calls into the host except through these leaf callbacks. Each one is
 * synchronous, non-blocking, must not call back into the core, and must be safe at the
 * highest IRQL the host ever drives the core at.
 *
 * NOT in the shim, by design: sockets, DNS, threads, locks, allocation, the clock, files.
 * Sockets and time are data (see wr_client.h); memory is handed over once (wr_config.h).
 */
#ifndef WR_HOST_H
#define WR_HOST_H

#include "wr_err.h"
#include "wr_types.h"

/* ---- logging ------------------------------------------------------------------------------ */

enum { WR_LOG_ERR = 1, WR_LOG_WARN = 2, WR_LOG_INFO = 3, WR_LOG_DEBUG = 4, WR_LOG_TRACE = 5 };

/*
 * Structured log record. msg is a static literal; the four numbers are its arguments. The host
 * formats it ("msg a0=.. a1=..") or drops it. The core never puts key material, tickets,
 * connection secrets or payload bytes into a record (enforced by a canary test).
 */
typedef struct wr_log_rec {
	uint8_t level;   /* WR_LOG_* */
	uint8_t module;  /* WR_MOD_* */
	uint16_t reserved16;
	wr_conn_id conn; /* 0 if none */
	wr_status status;
	const char *msg;
	uint64_t a0, a1, a2, a3;
} wr_log_rec;

/* ---- optional primitive overrides ----------------------------------------------------------
 *
 * The core carries its own portable MIT implementation of every primitive and always builds
 * it. A host may replace any of them (AES-NI, CNG, iPXE crypto) by filling members of this
 * table. A NULL member means "use the portable code". Members are stateless one-shot calls so
 * the core stays allocation free. All inputs are validated by the core before the call.
 *
 * The table is extensible: `size` is sizeof(wr_prim_ops) as the host compiled it, and members
 * beyond `size` are treated as NULL. The GCM members (secure mode, milestone 11) are the newest.
 */
typedef struct wr_prim_ops {
	uint32_t size;
	void *ctx;
	/* CRC-32C (Castagnoli), raw update: no initial or final inversion (msgr2.md 2.5). */
	uint32_t (*crc32c)(void *ctx, uint32_t seed, const uint8_t *p, size_t n);
	/* HMAC over the concatenation of the iovs. */
	void (*hmac_sha256)(void *ctx, const uint8_t *key, size_t klen, const wr_iov *iov, size_t niov,
			    uint8_t out[32]);
	void (*hmac_sha384)(void *ctx, const uint8_t *key, size_t klen, const wr_iov *iov, size_t niov,
			    uint8_t out[48]);
	/* AES in CBC mode, no padding, nblocks 16-byte blocks. klen is 16 or 32. in == out allowed.
	 * The host derives the key schedule itself on every call. Return WR_OK or a WR_E_CRYPTO_*. */
	wr_status (*aes_cbc_enc)(void *ctx, const uint8_t *key, size_t klen, const uint8_t iv[16],
				 const uint8_t *in, uint8_t *out, size_t nblocks);
	wr_status (*aes_cbc_dec)(void *ctx, const uint8_t *key, size_t klen, const uint8_t iv[16],
				 const uint8_t *in, uint8_t *out, size_t nblocks);

	/*
	 * AES-128-GCM for msgr2 secure mode (docs/design/core-architecture.md section 35.4). STREAMING and STATEFUL, unlike
	 * the one-shot members above, because a connection keeps its key for its whole life and a frame is two to three
	 * operations whose data arrives in pieces; rebuilding a key schedule (or a BCrypt key handle) per call would cost more
	 * than the cipher. The override is used only when gcm_state_bytes is in 1 .. WR_GCM_HOST_STATE_MAX AND all six
	 * function members are non-NULL AND the host's `size` covers them; otherwise the portable constant-time GCM of the
	 * core runs. The core hands the host `gcm_state_bytes` bytes of 8-byte-aligned memory inside the connection's slot (the
	 * host never allocates); one state per direction of a connection.
	 *
	 * Operation rules (the core guarantees them, a host may rely on them):
	 *   - gcm_setkey once per state, key is 16 bytes (AES-128; the only key size msgr2 has);
	 *   - gcm_start begins one operation with a fresh 12-byte IV and NO additional authenticated data;
	 *   - every gcm_update length is a multiple of 16 (every msgr2 operation is: 80, 16 * k, 16 * k + 16); in == out is
	 *     allowed, otherwise the buffers do not overlap; a decrypt update writes plaintext at once (the core does not act
	 *     on it before gcm_final_dec succeeded);
	 *   - an operation ends with gcm_final_enc (tag out) or gcm_final_dec (tag in, WR_OK or WR_E_CRYPTO_MAC, constant
	 *     time); after a final the state is ready for the next gcm_start;
	 *   - gcm_wipe erases the state and any host key object (connection end, failure, destroy).
	 * No call blocks, allocates or calls back into the core; each is safe at the IRQL the host drives the core at (a
	 * host that cannot guarantee that for BCrypt leaves the members NULL and takes the portable code).
	 */
	uint32_t gcm_state_bytes;
	wr_status (*gcm_setkey)(void *ctx, void *state, const uint8_t key[16]);
	wr_status (*gcm_start)(void *ctx, void *state, const uint8_t iv[12], int decrypt);
	void (*gcm_update)(void *ctx, void *state, const uint8_t *in, uint8_t *out, size_t n);
	void (*gcm_final_enc)(void *ctx, void *state, uint8_t tag[16]);
	wr_status (*gcm_final_dec)(void *ctx, void *state, const uint8_t tag[16]);
	void (*gcm_wipe)(void *ctx, void *state);
} wr_prim_ops;

/* The most state bytes a host GCM override may ask for per direction of a connection. */
#define WR_GCM_HOST_STATE_MAX 256u

/* ---- the host ops table ------------------------------------------------------------------ */

typedef struct wr_host_ops {
	uint32_t size; /* sizeof(wr_host_ops) as compiled by the host; checked at create */
	void *ctx;     /* passed back to every callback */

	/*
	 * Fill out[0..n) with cryptographically secure random bytes. Used for the cephx client
	 * challenge, the type-2 confounder, authorizer nonces, the entity_addr nonce and back-off
	 * jitter. On failure return WR_E_HOST_RANDOM: the core fails the connection, it never falls
	 * back to a weak source. Required.
	 */
	wr_status (*random)(void *ctx, uint8_t *out, size_t n);

	/* Log sink. May be NULL. */
	void (*log)(void *ctx, const wr_log_rec *rec);

	/* Primitive overrides. May be NULL (all portable). The pointed-to table must outlive the client. */
	const wr_prim_ops *prim;
} wr_host_ops;

#endif /* WR_HOST_H */
