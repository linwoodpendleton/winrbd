/* SPDX-License-Identifier: MIT */
/*
 * wr_port.h - the only header that touches the toolchain.
 *
 * Everything in core/ includes this (directly or through another core header). It supplies
 * the fixed-width types, the memory primitives, a C99 static assert and the licence tag.
 * A host that needs different behaviour (kernel memcpy, iPXE licence tags, no <stdint.h>)
 * provides a header named by -DWR_HOST_CONFIG_HEADER="my_cfg.h"; it is included first and
 * may predefine any WR_* macro below.
 *
 * Rules enforced for all of core/ (see docs/design/core-architecture.md, section 1):
 *   - ISO C99. Headers allowed: <stddef.h> and <stdint.h> only (both are freestanding).
 *   - No libc calls except WR_MEMCPY / WR_MEMMOVE / WR_MEMSET (WR_MEMCMP is defined for host glue; the core
 *     compares with wri_ct_memeq instead, so an optimiser that turns memcmp(...) == 0 into bcmp, as clang
 *     does at -O2, finds nothing to turn).
 *   - No writable globals, no floating point, no recursion, no VLAs.
 */
#ifndef WR_PORT_H
#define WR_PORT_H

#ifdef WR_HOST_CONFIG_HEADER
#include WR_HOST_CONFIG_HEADER
#endif

#include <stddef.h>
#include <stdint.h>

/* ---- memory primitives (the only libc surface of core) ------------------------------------ */
#if !defined(WR_MEMCPY)
#if defined(__GNUC__) || defined(__clang__)
#define WR_MEMCPY(d, s, n)  __builtin_memcpy((d), (s), (n))
#define WR_MEMMOVE(d, s, n) __builtin_memmove((d), (s), (n))
#define WR_MEMSET(d, c, n)  __builtin_memset((d), (c), (n))
#define WR_MEMCMP(a, b, n)  __builtin_memcmp((a), (b), (n))
#else
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
#define WR_MEMCPY(d, s, n)  memcpy((d), (s), (n))
#define WR_MEMMOVE(d, s, n) memmove((d), (s), (n))
#define WR_MEMSET(d, c, n)  memset((d), (c), (n))
#define WR_MEMCMP(a, b, n)  memcmp((a), (b), (n))
#endif
#endif

/* ---- language helpers ---------------------------------------------------------------------- */
#if defined(_MSC_VER)
#define WR_INLINE static __inline
#else
#define WR_INLINE static inline
#endif

#if defined(__GNUC__) || defined(__clang__)
#define WR_MUST_CHECK __attribute__((warn_unused_result))
#define WR_UNUSED     __attribute__((unused))
#else
#define WR_MUST_CHECK
#define WR_UNUSED
#endif

/* C99 has no _Static_assert. File-scope use only. name must be a unique identifier. */
#define WR_STATIC_ASSERT(cond, name) typedef char wr_static_assert_##name[(cond) ? 1 : -1]

/*
 * Licence tag. Every core .c file has this on its own line after the includes, WITHOUT a
 * trailing semicolon. Default: nothing. The iPXE glue defines it as "FILE_LICENCE ( MIT );"
 * through WR_HOST_CONFIG_HEADER so the iPXE licence check sees MIT.
 */
#ifndef WR_FILE_LICENCE_MIT
#define WR_FILE_LICENCE_MIT
#endif

/* Compile-time log ceiling: messages above this level compile to nothing (1 = errors only). */
#ifndef WR_LOG_MAX_LEVEL
#define WR_LOG_MAX_LEVEL 5
#endif

#endif /* WR_PORT_H */
