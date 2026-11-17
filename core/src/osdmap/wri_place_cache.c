/* SPDX-License-Identifier: MIT */
/*
 * wri_place_cache.c - the placement cache (docs/design/core-architecture.md 16.4, "Cache").
 *
 * A direct-mapped table: the entry of a key is entry number (mix(key) mod n), and a newer result for another key simply
 * replaces whatever lives there. An entry is valid for one map epoch only: it carries the epoch it was computed for, and a
 * lookup under any other epoch misses, so a new map never needs an invalidation pass and a result of an older map cannot be
 * returned. Epoch 0 marks an empty entry (a real map never has epoch 0), so the zeroed memory the arena hands out is an
 * empty cache.
 *
 * What is kept: the up and acting sets and the two primaries. The raw set and the placement seed are not (the client does
 * not need them to route a request), so a hit reports n_raw 0 and pps 0.
 *
 * Nothing here allocates, locks or keeps global state; the cache is used by one owner at a time like the rest of the store.
 * A cache that cannot be used (n 0, no memory, memory not 8-byte aligned) is a cache that never hits.
 */
#include "wri_place.h"

WR_FILE_LICENCE_MIT

/* Spread the key over 32 bits: the pool id sits in the upper half and the PG seed in the lower, and neighbouring seeds of
 * one pool must not collide just because n is a small power of two. A finalizer of the xor-shift / multiply kind, followed by
 * a fold, so the final reduction is a plain 32-bit modulo (a 64-bit one would need a library routine on a 32-bit target). */
static uint32_t slot_of(uint64_t key, uint32_t n)
{
	uint64_t x = key;
	uint32_t h;

	x ^= x >> 33;
	x *= 0xff51afd7ed558ccdull;
	x ^= x >> 33;
	x *= 0xc4ceb9fe1a85ec53ull;
	x ^= x >> 33;
	h = (uint32_t)x ^ (uint32_t)(x >> 32);
	return h % n;
}

static uint8_t clamp_count(uint8_t n)
{
	return n > WRI_REP_MAX ? (uint8_t)WRI_REP_MAX : n;
}

size_t wri_pgcache_bytes(uint32_t n)
{
	size_t bytes = (size_t)n * sizeof(wri_pgc_entry);

	/* on a 32-bit size_t the product can wrap: then there is no such cache, and init() yields a disabled one */
	if (bytes / sizeof(wri_pgc_entry) != (size_t)n)
		return 0;
	return bytes;
}

void wri_pgcache_init(wri_pgcache *c, void *mem, uint32_t n)
{
	size_t bytes;

	if (c == NULL)
		return;
	WR_MEMSET(c, 0, sizeof(*c));
	bytes = wri_pgcache_bytes(n);
	if (mem == NULL || n == 0 || bytes == 0 || ((uintptr_t)mem & 7u) != 0)
		return; /* disabled: e == NULL and n == 0 */
	WR_MEMSET(mem, 0, bytes); /* the contract says zeroed; an empty entry is epoch 0, so make sure of it */
	c->e = (wri_pgc_entry *)mem;
	c->n = n;
}

void wri_pgcache_clear(wri_pgcache *c)
{
	if (c == NULL || c->e == NULL || c->n == 0)
		return;
	WR_MEMSET(c->e, 0, wri_pgcache_bytes(c->n)); /* every entry back to epoch 0; the counters are statistics and stay */
}

int wri_pgcache_get(wri_pgcache *c, uint32_t epoch, uint64_t key, wri_pg_result *out)
{
	const wri_pgc_entry *e;
	uint32_t i;

	if (c == NULL)
		return 0;
	if (c->e == NULL || c->n == 0 || epoch == 0) {
		c->misses++;
		return 0;
	}
	e = &c->e[slot_of(key, c->n)];
	if (e->epoch != epoch || e->key != key) {
		c->misses++;
		return 0;
	}
	c->hits++;
	if (out != NULL) { /* a NULL out is a probe */
		WR_MEMSET(out, 0, sizeof(*out));
		out->n_up = clamp_count(e->n_up);
		out->n_acting = clamp_count(e->n_acting);
		for (i = 0; i < out->n_up; i++)
			out->up[i] = e->up[i];
		for (i = 0; i < out->n_acting; i++)
			out->acting[i] = e->acting[i];
		out->up_primary = e->up_primary;
		out->acting_primary = e->acting_primary;
	}
	return 1;
}

void wri_pgcache_put(wri_pgcache *c, uint32_t epoch, uint64_t key, const wri_pg_result *res)
{
	wri_pgc_entry *e;
	uint32_t i;

	if (c == NULL || res == NULL || c->e == NULL || c->n == 0 || epoch == 0)
		return;
	e = &c->e[slot_of(key, c->n)];
	WR_MEMSET(e, 0, sizeof(*e));
	e->key = key;
	e->n_up = clamp_count(res->n_up);
	e->n_acting = clamp_count(res->n_acting);
	for (i = 0; i < e->n_up; i++)
		e->up[i] = res->up[i];
	for (i = 0; i < e->n_acting; i++)
		e->acting[i] = res->acting[i];
	e->up_primary = res->up_primary;
	e->acting_primary = res->acting_primary;
	e->epoch = epoch; /* last: the entry is valid only once it is complete */
}
