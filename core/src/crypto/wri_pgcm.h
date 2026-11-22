/* SPDX-License-Identifier: MIT */
/*
 * wri_pgcm.h - the dispatcher between the host's GCM override (wr_prim_ops, wr_host.h) and the portable wri_gcm, for ONE direction
 * of a msgr2 secure connection. Every secure-mode call site uses this and never wri_gcm directly (the same rule as wri_prim.h), so
 * an override takes effect everywhere and a host that disagrees with the vectors shows up as a vector difference.
 * Docs: docs/design/core-architecture.md 35.4.
 *
 * The override is taken only when gcm_state_bytes is in 1 .. WR_GCM_HOST_STATE_MAX, all six function members are present and the
 * host's table `size` covers them; the decision is made once, in wri_pgcm_setkey(), and kept in the object. The storage is one
 * union, so a connection pays for the larger of the two, never both. Update lengths are multiples of 16 (WR_E_CRYPTO_LEN else): that
 * is what msgr2 produces and what lets a host use block-wise APIs such as chained BCrypt calls.
 *
 * The dispatcher enforces the operation rules itself, so a host never sees a call the contract forbids and both paths behave the
 * same: update and final need a running operation (WR_E_STATE), a final of the other direction is WR_E_STATE, a length that is not
 * a multiple of 16 is WR_E_CRYPTO_LEN, so is one that would take the operation past 2^36 - 32 bytes (the 32-bit block counter
 * of GCM; the dispatcher counts it itself so a host never has to), a NULL buffer or buffers that overlap without being the same
 * range are WR_E_INVAL, and any such refusal inside an operation ends it for good: the
 * final that follows returns WR_E_STATE (tag zeroed) and never WR_OK, and for a host the operation is closed with a real final
 * call (result discarded) so its state is ready for the next start. A start while an operation is still running closes that one the
 * same way. A host's final_dec result is returned as the host gave it. The object must be zeroed or wiped before its first setkey
 * (indeterminate memory is not allowed); setkey does not look at the previous contents, so wipe a keyed object before keying it
 * again (the host's key object is released by wri_pgcm_wipe, not by setkey).
 */
#ifndef WRI_PGCM_H
#define WRI_PGCM_H

#include "wri_gcm.h"
#include "wr_host.h"

typedef struct wri_pgcm {
	const wr_prim_ops *host; /* the table when the override is in use, else NULL (portable) */
	uint8_t keyed;
	uint8_t op;  /* 0 idle, 1 running, 2 refused (still to be ended; its final fails) */
	uint8_t dir; /* direction of the running operation: 0 encrypt, 1 decrypt */
	uint8_t reserved;
	uint32_t blocks; /* 16-byte blocks fed to the running operation (the same 2^36 - 32 byte cap on both paths) */
	union {
		wri_gcm sw;
		uint64_t host_state[WR_GCM_HOST_STATE_MAX / 8u]; /* 8-byte aligned, as wr_host.h promises */
	} u;
} wri_pgcm;

/* prim may be NULL; key may not (WR_E_INVAL, object unkeyed). A host key that is refused (a failing gcm_setkey) is returned as is,
 * the host's gcm_wipe is called on its state and the object stays unkeyed: it does NOT fall back to the portable code. */
WR_MUST_CHECK wr_status wri_pgcm_setkey(wri_pgcm *g, const wr_prim_ops *prim, const uint8_t key[16]);
/* WR_E_STATE when unkeyed; WR_E_INVAL for a NULL iv or a decrypt other than 0 or 1. */
WR_MUST_CHECK wr_status wri_pgcm_start(wri_pgcm *g, const uint8_t iv[WRI_GCM_IV_LEN], int decrypt);
WR_MUST_CHECK wr_status wri_pgcm_update(wri_pgcm *g, const uint8_t *in, uint8_t *out, size_t n);
WR_MUST_CHECK wr_status wri_pgcm_final_enc(wri_pgcm *g, uint8_t tag[WRI_GCM_TAG_LEN]);
WR_MUST_CHECK wr_status wri_pgcm_final_dec(wri_pgcm *g, const uint8_t tag[WRI_GCM_TAG_LEN]);
/* 1 when the host override is in use (tests and the stats line report it). */
int wri_pgcm_is_host(const wri_pgcm *g);
/* End a running (or refused) operation without computing a tag: nothing is produced, the key stays, the object is idle and ready for the next
 * start; idle or unkeyed is a no-op. A host gets a real final call (result discarded) so its state is ready too. The portable path does no
 * GHASH work at all, which is what a caller that drops a half-sent operation (a stream cut by a reset) wants, and a shallow call chain. */
void wri_pgcm_abort(wri_pgcm *g);
void wri_pgcm_wipe(wri_pgcm *g);

#endif /* WRI_PGCM_H */
