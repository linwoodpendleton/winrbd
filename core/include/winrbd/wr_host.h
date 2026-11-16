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
 * beyond `size` are treated as NULL. GCM members join with the secure-mode milestone.
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
} wr_prim_ops;

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
