/* SPDX-License-Identifier: MIT */
/*
 * wri_mem.c - bump arena, index pool and byte ring (see wri_mem.h for the contracts).
 *
 * All three are plain data structures over memory the host handed in; nothing here allocates.
 * Every size computation that involves a caller-supplied number is checked against wrap-around
 * first (size_t is 32 bits on the iPXE i386 build).
 */
#include "wri_mem.h"
#include "wri_le.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/* ---- bump arena --------------------------------------------------------------------------- */

static int wri_arena_align_ok(size_t align)
{
	return align != 0 && align <= WRI_ARENA_MAX_ALIGN && (align & (align - 1)) == 0;
}

void wri_arena_init(wri_arena *a, void *base, size_t cap)
{
	a->base = (uint8_t *)base;
	a->cap = base ? cap : 0;
	a->used = 0;
}

void *wri_arena_take(wri_arena *a, size_t n, size_t align)
{
	size_t mask, low, pad, start;

	if (!wri_arena_align_ok(align) || a->base == NULL || a->used > a->cap)
		return NULL;
	mask = align - 1;
	/* Padding is computed from the real address, so the returned pointer is aligned whatever
	 * the base alignment is. Only the low bits matter, so the unsigned wrap is harmless. */
	low = (size_t)(((uintptr_t)a->base + (uintptr_t)a->used) & (uintptr_t)mask);
	pad = (align - low) & mask;
	if (pad > a->cap - a->used)
		return NULL;
	start = a->used + pad;
	if (n > a->cap - start)
		return NULL;
	a->used = start + n;
	if (n != 0)
		WR_MEMSET(a->base + start, 0, n);
	return a->base + start;
}

void *wri_arena_take_array(wri_arena *a, size_t count, size_t elem, size_t align)
{
	size_t total;

	if (wri_mul_sz(count, elem, &total) != WR_OK)
		return NULL;
	return wri_arena_take(a, total, align);
}

wr_status wri_arena_plan(size_t *used, size_t n, size_t align)
{
	size_t aligned, end;
	wr_status st;

	if (!wri_arena_align_ok(align))
		return WR_E_INVAL;
	st = wri_align_up(*used, align, &aligned);
	if (st != WR_OK)
		return st;
	st = wri_add_sz(aligned, n, &end);
	if (st != WR_OK)
		return st;
	*used = end;
	return WR_OK;
}

wr_status wri_arena_plan_array(size_t *used, size_t count, size_t elem, size_t align)
{
	size_t total;
	wr_status st = wri_mul_sz(count, elem, &total);

	if (st != WR_OK)
		return st;
	return wri_arena_plan(used, total, align);
}

/* ---- index pool --------------------------------------------------------------------------- */

wr_status wri_pool_init(wri_pool *p, wri_arena *a, uint32_t obj_size, uint32_t nobj)
{
	size_t total;
	uint8_t *mem = NULL;
	uint32_t i;
	wr_status st;

	if (obj_size < 4 || nobj == WRI_NIL)
		return WR_E_INVAL;
	st = wri_mul_sz((size_t)obj_size, (size_t)nobj, &total);
	if (st != WR_OK)
		return st;
	if (nobj != 0) {
		mem = (uint8_t *)wri_arena_take(a, total, 16);
		if (mem == NULL)
			return WR_E_BUDGET;
	}
	p->base = mem;
	p->obj_size = obj_size;
	p->nobj = nobj;
	p->nfree = nobj;
	p->hiwater = 0;
	p->free_head = nobj != 0 ? 0 : WRI_NIL;
	for (i = 0; i < nobj; i++)
		wri_le32_put(mem + (size_t)i * obj_size, i + 1 < nobj ? i + 1 : WRI_NIL);
	return WR_OK;
}

uint32_t wri_pool_get(wri_pool *p)
{
	uint32_t idx = p->free_head;
	uint8_t *obj;
	uint32_t next, used;

	if (idx == WRI_NIL || p->nfree == 0 || idx >= p->nobj)
		return WRI_NIL;
	obj = p->base + (size_t)idx * p->obj_size;
	next = wri_le32_get(obj);
	if (next != WRI_NIL && next >= p->nobj) {
		/* A free slot was written to after it was returned (a caller bug). Do not follow the
		 * garbage index: give up the rest of the free list rather than leave the pool. */
		next = WRI_NIL;
		p->nfree = 1;
	}
	p->free_head = next;
	p->nfree--;
	WR_MEMSET(obj, 0, p->obj_size);
	used = p->nobj - p->nfree;
	if (used > p->hiwater)
		p->hiwater = used;
	return idx;
}

void wri_pool_put(wri_pool *p, uint32_t idx)
{
	uint8_t *obj;

	if (idx >= p->nobj || p->nfree >= p->nobj)
		return;
	if (idx == p->free_head)
		return; /* the commonest double put (put, put): linking it again would make a cycle */
	obj = p->base + (size_t)idx * p->obj_size;
	wri_secure_zero(obj, p->obj_size);
	wri_le32_put(obj, p->free_head);
	p->free_head = idx;
	p->nfree++;
}

void *wri_pool_at(const wri_pool *p, uint32_t idx)
{
	if (idx >= p->nobj)
		return NULL;
	return p->base + (size_t)idx * p->obj_size;
}

/* ---- byte ring ---------------------------------------------------------------------------- */

void wri_ring_init(wri_ring *r, uint8_t *buf, uint32_t cap)
{
	r->buf = buf;
	r->cap = buf ? cap : 0;
	r->head = 0;
	r->len = 0;
}

uint32_t wri_ring_free(const wri_ring *r)
{
	return r->cap - r->len;
}

/* Offset of the first free byte. head < cap whenever cap > 0, and len <= cap. */
static uint32_t wri_ring_tail(const wri_ring *r)
{
	uint32_t first = r->cap - r->head; /* bytes from head to the end of the buffer */

	return r->len < first ? r->head + r->len : r->len - first;
}

uint32_t wri_ring_write_span(const wri_ring *r, uint8_t **ptr)
{
	uint32_t tail = wri_ring_tail(r);
	uint32_t span;

	if (r->len == r->cap)
		span = 0;
	else if (tail >= r->head) /* free space runs from tail to the end of the buffer */
		span = r->cap - tail;
	else /* free space has wrapped: it ends where the data begins */
		span = r->head - tail;
	if (ptr)
		*ptr = r->buf ? r->buf + tail : NULL;
	return span;
}

void wri_ring_commit(wri_ring *r, uint32_t n)
{
	uint32_t room = r->cap - r->len;

	r->len += n < room ? n : room;
}

uint32_t wri_ring_read_span(const wri_ring *r, const uint8_t **ptr)
{
	uint32_t first = r->cap - r->head;

	if (ptr)
		*ptr = r->buf ? r->buf + r->head : NULL;
	return r->len < first ? r->len : first;
}

void wri_ring_drop(wri_ring *r, uint32_t n)
{
	uint32_t first = r->cap - r->head;

	if (n > r->len)
		n = r->len;
	r->head = n >= first ? n - first : r->head + n;
	r->len -= n;
	if (r->len == 0)
		r->head = 0;
}

uint32_t wri_ring_peek(const wri_ring *r, uint8_t *dst, uint32_t n)
{
	uint32_t first = r->cap - r->head;

	if (n > r->len)
		n = r->len;
	if (n == 0)
		return 0;
	if (n <= first) {
		WR_MEMCPY(dst, r->buf + r->head, n);
	} else {
		WR_MEMCPY(dst, r->buf + r->head, first);
		WR_MEMCPY(dst + first, r->buf, n - first);
	}
	return n;
}

uint32_t wri_ring_write(wri_ring *r, const uint8_t *src, uint32_t n)
{
	uint32_t room = r->cap - r->len;
	uint32_t tail, chunk;

	if (n > room)
		n = room;
	if (n == 0)
		return 0;
	tail = wri_ring_tail(r);
	chunk = r->cap - tail; /* contiguous bytes from tail to the end of the buffer */
	if (n <= chunk) {
		WR_MEMCPY(r->buf + tail, src, n);
	} else {
		WR_MEMCPY(r->buf + tail, src, chunk);
		WR_MEMCPY(r->buf, src + chunk, n - chunk);
	}
	r->len += n;
	return n;
}

uint32_t wri_ring_read(wri_ring *r, uint8_t *dst, uint32_t n)
{
	uint32_t got = wri_ring_peek(r, dst, n);

	wri_ring_drop(r, got);
	return got;
}

void wri_ring_reset_wipe(wri_ring *r)
{
	if (r->buf)
		wri_secure_zero(r->buf, r->cap);
	r->head = 0;
	r->len = 0;
}
