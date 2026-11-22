/* SPDX-License-Identifier: MIT */
/*
 * wrl_gcm_aesni.h - the accelerated AES-128-GCM hook of the Linux host: the six gcm_* members of wr_prim_ops (wr_host.h,
 * docs/design/core-architecture.md 35.4) implemented with the AES and PCLMULQDQ instructions of x86-64.
 *
 * Harness code, never part of core/. The functions use intrinsics under per-function `target` attributes, so no global -m flag
 * is needed; on anything other than x86-64 with gcc or clang the file compiles to a stub that reports "unavailable". The CPU is
 * checked at run time (CPUID: AES, PCLMULQDQ, SSE4.1 and SSSE3), so one binary runs everywhere.
 *
 * Constant time: the cipher is the AES instruction and the multiplication the PCLMULQDQ instruction, neither has a secret-
 * dependent address or branch, and neither does this code; the tag comparison accumulates all 16 bytes before it decides.
 * Not hardened: key-derived values pass through vector registers and compiler spill slots, which portable C cannot erase
 * (gcm_wipe erases the state the core handed over, which holds the key schedule and the hash key; the plaintext, keystream and hash
 * input blocks the bulk loop keeps in locals are erased when each update returns, as are the IV and tag scratch copies).
 *
 * Nonces: the hook cannot see which IVs were used before (it keeps no history), so "never the same IV twice under one key" is the
 * caller's rule, kept by the core's nonce stream (wri_m2s_nonce_take); a start with an IV is taken as it is. Tags are always 16 bytes
 * and all of them are compared; a NULL tag in a final is a refusal (decrypt) or writes nothing (encrypt) and ends the operation.
 *
 * Contract (the core guarantees it; the hook fails closed when it is broken): the key is 16 bytes, every update is a multiple of
 * 16 bytes (a violation, a NULL buffer, buffers that overlap without being the same range, or an operation past 2^36 - 32 bytes
 * poisons the running operation: its final_enc then returns an all-zero tag and its final_dec WR_E_CRYPTO_MAC, never a good
 * answer), no additional data, a fresh 12-byte IV per start.
 */
#ifndef WRL_GCM_AESNI_H
#define WRL_GCM_AESNI_H

#include "winrbd/wr_host.h"

/* Bytes of the per-direction state the hook asks for: at most WR_GCM_HOST_STATE_MAX, a multiple of 8. It holds the expanded key
 * (176), the hash key and its square (32), the running hash (16), the IV, the block counter and the operation mode. */
#define WRL_GCM_AESNI_STATE_BYTES 248u

/* 1 when this build has the hook and the CPU has AES, PCLMULQDQ, SSE4.1 and SSSE3; else 0. */
int wrl_gcm_aesni_available(void);

/* When the hook is available: zero *out, set size = sizeof(wr_prim_ops), gcm_state_bytes and the six gcm_* members (every other
 * member stays NULL, which means "portable code"), and return 0. Otherwise return -1 and leave *out untouched (also for NULL).
 * The functions ignore the table's ctx. A host that wants more overrides copies the seven GCM fields into its own table. */
int wrl_gcm_aesni_ops(wr_prim_ops *out);

#endif /* WRL_GCM_AESNI_H */
