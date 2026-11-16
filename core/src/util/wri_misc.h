/* SPDX-License-Identifier: MIT */
/* wri_misc.h - small utilities: secure wipe, constant-time compare, checked arithmetic, base64. */
#ifndef WRI_MISC_H
#define WRI_MISC_H

#include "wr_err.h"
#include "wr_port.h"

/*
 * 64-bit division is native on 64-bit targets. A host may force either choice by defining
 * WR_NATIVE_DIV64 or WR_NO_NATIVE_DIV64 before this header (WR_HOST_CONFIG_HEADER); the default
 * is native on x86-64 and ARM64 and the shift-subtract loop everywhere else (i386 iPXE, so the
 * linker never needs __divdi3).
 */
#if !defined(WR_NATIVE_DIV64) && !defined(WR_NO_NATIVE_DIV64)
#if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__) || defined(_M_ARM64)
#define WR_NATIVE_DIV64 1
#endif
#endif

/* Zero memory so the compiler cannot elide it (volatile stores). Used for every secret. */
void wri_secure_zero(void *p, size_t n);

/* 1 if the n bytes are equal, 0 otherwise; time independent of the contents. For MACs and tags. */
int wri_ct_memeq(const uint8_t *a, const uint8_t *b, size_t n);

/*
 * a + b and a * b on size_t with overflow detection: return 0 and set *out, or WR_E_OVERFLOW
 * (then *out is left untouched). out may be NULL when only the check is wanted.
 */
WR_MUST_CHECK wr_status wri_add_sz(size_t a, size_t b, size_t *out);
WR_MUST_CHECK wr_status wri_mul_sz(size_t a, size_t b, size_t *out);

/* Round up to a multiple of align. WR_E_INVAL if align is not a power of two (0 included),
 * WR_E_OVERFLOW on wrap; *out is left untouched on failure. */
WR_MUST_CHECK wr_status wri_align_up(size_t v, size_t align, size_t *out);

/*
 * Signed 64-bit divided by unsigned 32-bit, truncating toward zero (CRUSH straw2). Uses the
 * native operator when WR_NATIVE_DIV64 is defined (x86-64, ARM64, harness) and a shift-subtract
 * loop otherwise, so a 32-bit host never needs the compiler's __divdi3.
 */
int64_t wri_div_s64_u32(int64_t num, uint32_t den);
/* The shift-subtract implementation, always compiled so tests can compare it with the native one. */
int64_t wri_div_s64_u32_slow(int64_t num, uint32_t den);
/* Division by zero is not a trap in the core: both variants return 0 for den == 0. */

/*
 * Standard base64 (RFC 4648, '=' padding, no line breaks; ASCII whitespace is skipped).
 * Decodes at most cap bytes into out; *out_len gets the count (0 on failure). WR_E_ENCODING on
 * a bad character, bad or missing padding, data after padding, a dangling single character, or
 * non-zero spare bits in the last group (the canonical form only); WR_E_TOOBIG if cap is too
 * small; WR_E_INVAL for NULL in/out/out_len with a non-zero length. Bytes written to out before
 * a failure are wiped, so a half-decoded key never lingers.
 */
WR_MUST_CHECK wr_status wri_b64_decode(const char *in, size_t n, uint8_t *out, size_t cap, size_t *out_len);

#endif /* WRI_MISC_H */
