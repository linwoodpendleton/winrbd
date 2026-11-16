/* SPDX-License-Identifier: MIT */
/*
 * wri_mem.h - memory building blocks. The core never allocates: the host passes regions in, an
 * init-time bump arena carves them once, and everything at run time lives in fixed pools and
 * rings sized from wr_config. Pool objects refer to each other by u32 index, never by pointer:
 * halves memory on 64-bit hosts, gives the same struct layout on i386 and x64, keeps arenas
 * relocatable, and turns dangling pointers into bounds-checked index errors.
 */
#ifndef WRI_MEM_H
#define WRI_MEM_H

#include "wr_err.h"
#include "wr_port.h"

/* ---- bump arena (init time only) ---------------------------------------------------------- */

typedef struct wri_arena {
	uint8_t *base;
	size_t cap;
	size_t used;
} wri_arena;

#define WRI_ARENA_MAX_ALIGN 64u
/* Extra bytes to add once to a wri_arena_plan total when the base is only 16-byte aligned (the
 * host contract of wr_config.h): take() aligns the real address, plan() assumes a base aligned to
 * WRI_ARENA_MAX_ALIGN, so the first take can cost up to this much more padding than planned. */
#define WRI_ARENA_SLACK (WRI_ARENA_MAX_ALIGN - 16u)

/* A NULL base gives an empty arena. */
void wri_arena_init(wri_arena *a, void *base, size_t cap);
/*
 * Returns zeroed memory whose ADDRESS is aligned to `align` (a power of two, at most 64), or NULL
 * if the arena is exhausted or align is invalid. n == 0 returns an aligned pointer and takes
 * nothing but the padding. Never fails half way: on NULL the arena is unchanged.
 */
void *wri_arena_take(wri_arena *a, size_t n, size_t align);
/* take() of count objects of elem bytes each; NULL on overflow of count * elem too. */
void *wri_arena_take_array(wri_arena *a, size_t count, size_t elem, size_t align);
/* Bytes not yet taken (padding for the next alignment not included). */
WR_INLINE size_t wri_arena_left(const wri_arena *a) { return a->cap - a->used; }
/*
 * Same arithmetic without allocating: advances *used by the padding and n bytes a take() would
 * need, offsets taken relative to an arena base aligned to WRI_ARENA_MAX_ALIGN (add
 * WRI_ARENA_SLACK once for a 16-byte-aligned base). WR_E_OVERFLOW if the sum does not fit in
 * size_t, WR_E_INVAL for a bad align; *used is unchanged on failure.
 */
WR_MUST_CHECK wr_status wri_arena_plan(size_t *used, size_t n, size_t align);
/* plan() of count objects of elem bytes each. */
WR_MUST_CHECK wr_status wri_arena_plan_array(size_t *used, size_t count, size_t elem, size_t align);

/* ---- fixed pool of equal-size objects with an intrusive free list ------------------------- */

#define WRI_NIL 0xffffffffu

typedef struct wri_pool {
	uint8_t *base;
	uint32_t obj_size; /* >= 4; the first 4 bytes of a free object hold the next free index */
	uint32_t nobj;
	uint32_t nfree;
	uint32_t hiwater; /* most objects ever in use at once */
	uint32_t free_head;
} wri_pool;

/*
 * Carve nobj objects of obj_size bytes (16-byte aligned base) out of the arena. WR_E_INVAL if
 * obj_size < 4 or nobj == WRI_NIL, WR_E_OVERFLOW if the total does not fit in size_t,
 * WR_E_BUDGET if the arena is too small (nothing is taken then). nobj == 0 is a valid, always
 * empty pool. obj_size should be a multiple of the alignment the object type needs.
 */
WR_MUST_CHECK wr_status wri_pool_init(wri_pool *p, wri_arena *a, uint32_t obj_size, uint32_t nobj);
/* Index of a zeroed object, or WRI_NIL if the pool is empty (backpressure, not an error). */
uint32_t wri_pool_get(wri_pool *p);
/*
 * Return an object: it is wiped (volatile stores, so no stale key material survives in a free
 * slot) and pushed on the free list. An index >= nobj, or a put on a pool that is already
 * entirely free, is ignored, and so is a put of the object that is already at the head of the
 * free list (an immediate double put). Returning the same object twice in any other pattern is a
 * caller bug the pool cannot detect: it would hand the object out twice.
 */
void wri_pool_put(wri_pool *p, uint32_t idx);
/* Pointer for an index, NULL if idx >= nobj. */
void *wri_pool_at(const wri_pool *p, uint32_t idx);

/* ---- byte ring (receive staging) ---------------------------------------------------------- */

typedef struct wri_ring {
	uint8_t *buf;
	uint32_t cap;
	uint32_t head; /* read position */
	uint32_t len;  /* bytes stored */
} wri_ring;

/* A NULL buf gives a zero-capacity ring. */
void wri_ring_init(wri_ring *r, uint8_t *buf, uint32_t cap);
/* Bytes that can still be stored (cap - len). */
uint32_t wri_ring_free(const wri_ring *r);
/*
 * Largest contiguous writable span (for a recv window): returns its length and stores its start
 * in *ptr (ptr may be NULL). After filling k <= span bytes call wri_ring_commit(r, k). When the
 * free space wraps, the span ends at the end of the buffer; commit and ask again for the rest.
 */
uint32_t wri_ring_write_span(const wri_ring *r, uint8_t **ptr);
/* Count k bytes as stored. k is clamped to the free space, so a bad k can never corrupt the ring. */
void wri_ring_commit(wri_ring *r, uint32_t n);
/* Largest contiguous readable span (length, start in *ptr, ptr may be NULL); consume with wri_ring_drop. */
uint32_t wri_ring_read_span(const wri_ring *r, const uint8_t **ptr);
/* Discard the oldest n bytes (clamped to what is stored). An empty ring restarts at offset 0. */
void wri_ring_drop(wri_ring *r, uint32_t n);
/* Copy out up to n bytes without removing them; returns bytes copied. */
uint32_t wri_ring_peek(const wri_ring *r, uint8_t *dst, uint32_t n);
/* Append up to n bytes from src (wrapping as needed); returns how many fit (min(n, free)). */
uint32_t wri_ring_write(wri_ring *r, const uint8_t *src, uint32_t n);
/* peek() followed by drop() of what was copied. */
uint32_t wri_ring_read(wri_ring *r, uint8_t *dst, uint32_t n);
/* Empty the ring and wipe the whole buffer (secure zero): use after a failed handshake. */
void wri_ring_reset_wipe(wri_ring *r);

#endif /* WRI_MEM_H */
