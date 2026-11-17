/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the CRUSH blob decoder (core/src/crush/wri_crush_dec.c, wri_crush_dec2.c).
 *
 * The whole input is one blob (an exact-size heap copy, so ASan sees any over-read). It is decoded into a 64 KiB room
 * between guard bands, twice, once with the room pre-filled with one byte and once with another, and once more with the
 * input cut by one byte. Properties (a violated one traps):
 *
 *   - a failure is WR_E_CRUSH_ENCODING or WR_E_MAP_BUDGET with a reason (module, what) in the errinfo, *used is 0 and the
 *     header of the room is not a finished region (magic never set);
 *   - a success gives a region whose size is a multiple of 4 inside the room, wri_crush_check accepts it, every bucket,
 *     rule and choose_args override can be walked through the accessors, and every bucket item is a device below
 *     max_devices or a slot below max_buckets;
 *   - the second decode with the other pre-fill gives the same status, the same size and the same bytes (no decision on a
 *     byte of the room that the decoder did not write, and no byte of the region left unwritten);
 *   - nothing outside the room is written (the guard bands are intact);
 *   - a region that was decoded and then damaged (one bit flipped, one word set to all ones, both at places taken from the
 *     input, in an exact-size copy so ASan sees any over-read) is judged by wri_crush_check without a crash, and when the check
 *     still accepts it every accessor walk holds (the check is what a paranoid caller trusts after a memcpy).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_crush.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define ROOM 65536u
#define GUARD 64u
#define PAT_A 0xA5u
#define PAT_B 0x3Cu

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

typedef struct room {
	uint8_t *buf; /* GUARD + ROOM + GUARD bytes */
	uint8_t pat;
} room;

static void room_fill(room *r, uint8_t pat)
{
	r->pat = pat;
	memset(r->buf, pat, ROOM + 2u * GUARD);
}

static void room_guards(const room *r)
{
	size_t i;

	for (i = 0; i < GUARD; i++) {
		check(r->buf[i] == r->pat);
		check(r->buf[GUARD + ROOM + i] == r->pat);
	}
}

/* Touch everything a mapper could reach, and check the facts that make the accessors safe. */
static void walk(const wri_crush *c)
{
	uint32_t slot, i, k, s;
	volatile uint64_t sink = 0;

	for (slot = 0; slot < c->max_buckets; slot++) {
		const wri_cbucket *b = wri_crush_bucket_at(c, slot);

		if (b == NULL)
			continue;
		check(b->id == -1 - (int32_t)slot && b->hash == 0 && b->alg >= 1 && b->alg <= 5 && b->size <= WRI_CRUSH_MAX_BUCKET_SIZE);
		for (i = 0; i < b->size; i++) {
			int32_t it = wri_cbucket_items(b)[i];

			check(it >= 0 ? it < c->max_devices : (uint32_t)(-1 - it) < c->max_buckets);
			if (b->alg == WRI_CRUSH_ALG_STRAW2) {
				check(wri_cbucket_w(b)[i] < 0x80000000u);
				sink += wri_cbucket_w(b)[i];
			} else if (b->alg == WRI_CRUSH_ALG_STRAW) {
				sink += wri_cbucket_w(b)[i];
			} else if (b->alg == WRI_CRUSH_ALG_LIST) {
				sink += wri_cbucket_w(b)[i] + wri_cbucket_sums(b)[i];
			}
		}
	}
	for (i = 0; i < c->max_rules; i++) {
		unsigned kind = wri_crush_rule_kind(c, i);
		const wri_crule *r = wri_crush_rule(c, i);

		check((kind == 2) == (r != NULL));
		if (r == NULL)
			continue;
		check(r->nsteps <= WRI_CRUSH_MAX_STEPS);
		for (k = 0; k < r->nsteps; k++)
			sink += wri_crule_steps(r)[k].op;
	}
	check(c->n_sets == 0 ? c->set_tab == 0 : c->set_tab != 0);
	for (s = 0; s < c->n_sets; s++) {
		const wri_cargs_set *set = (const wri_cargs_set *)(const void *)((const uint8_t *)c + c->set_tab) + s;
		const uint32_t *ix = wri_crush_args_index(c, set->pool);

		check(ix != NULL);
		for (slot = 0; slot < c->max_buckets; slot++) {
			const wri_cargs *a = wri_crush_args_of(c, ix, slot);
			const wri_cbucket *b = wri_crush_bucket_at(c, slot);

			if (a == NULL)
				continue;
			check(b != NULL && b->alg == WRI_CRUSH_ALG_STRAW2);
			for (k = 0; k < a->n_pos && k < 4u; k++)
				for (i = 0; i < b->size; i++) {
					check(wri_cargs_row(a, b->size, k)[i] < 0x80000000u);
					sink += wri_cargs_row(a, b->size, k)[i];
				}
			if (a->has_ids != 0)
				for (i = 0; i < b->size; i++)
					sink += (uint32_t)wri_cargs_ids(a, b->size)[i];
		}
	}
	(void)sink;
}

/* A deterministic pick from the input: where to damage the region. */
static uint32_t pick(const uint8_t *data, size_t size, uint32_t salt)
{
	uint32_t h = 2166136261u ^ salt;
	size_t i;

	for (i = 0; i < size; i++)
		h = (h ^ data[i]) * 16777619u;
	return h;
}

static void damage(const uint8_t *region, size_t used, const uint8_t *data, size_t size)
{
	uint8_t *copy = (uint8_t *)malloc(used); /* exact size, malloc alignment: 4-aligned as wri_crush_check needs */
	uint32_t p1 = pick(data, size, 1), p2 = pick(data, size, 2);
	size_t at;
	uint32_t ones = 0xffffffffu;

	if (copy == NULL)
		abort();
	memcpy(copy, region, used);
	copy[p1 % used] ^= (uint8_t)(1u << (p1 >> 29));
	if (wri_crush_check((const wri_crush *)(const void *)copy, used) == WR_OK)
		walk((const wri_crush *)(const void *)copy);
	memcpy(copy, region, used);
	at = (size_t)(p2 % used) & ~(size_t)3u;
	if (at + 4u <= used)
		memcpy(copy + at, &ones, 4);
	if (wri_crush_check((const wri_crush *)(const void *)copy, used) == WR_OK)
		walk((const wri_crush *)(const void *)copy);
	free(copy);
}

static wr_status one(const uint8_t *blob, size_t n, room *r, size_t *used, wr_errinfo *why)
{
	wr_status st;

	memset(why, 0, sizeof(*why));
	*used = 99;
	st = wri_crush_decode(blob, n, r->buf + GUARD, ROOM, used, why);
	room_guards(r);
	if (st == WR_OK) {
		check(*used >= WRI_CRUSH_HDR_BYTES && *used <= ROOM && (*used % 4u) == 0u);
		check(wri_crush_check((const wri_crush *)(const void *)(r->buf + GUARD), *used) == WR_OK);
		walk((const wri_crush *)(const void *)(r->buf + GUARD));
		check(why->status == WR_OK);
	} else {
		check(st == WR_E_CRUSH_ENCODING || st == WR_E_MAP_BUDGET);
		check(*used == 0 && why->status == st && why->module == WR_MOD_CRUSH && why->what != NULL);
		check(((const wri_crush *)(const void *)(r->buf + GUARD))->magic != WRI_CRUSH_MAGIC);
	}
	return st;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *blob = (uint8_t *)malloc(size ? size : 1u);
	uint8_t *cut = (uint8_t *)malloc(size ? size : 1u);
	room ra, rb;
	size_t ua, ub;
	wr_errinfo why;
	wr_status sa, sb;

	ra.buf = (uint8_t *)malloc(ROOM + 2u * GUARD);
	rb.buf = (uint8_t *)malloc(ROOM + 2u * GUARD);
	if (blob == NULL || cut == NULL || ra.buf == NULL || rb.buf == NULL)
		abort();
	if (size != 0) {
		memcpy(blob, data, size);
		memcpy(cut, data, size);
	}

	room_fill(&ra, PAT_A);
	sa = one(blob, size, &ra, &ua, &why);
	room_fill(&rb, PAT_B);
	sb = one(blob, size, &rb, &ub, &why);
	check(sa == sb && ua == ub);
	if (sa == WR_OK) {
		check(memcmp(ra.buf + GUARD, rb.buf + GUARD, ua) == 0);
		damage(rb.buf + GUARD, ub, data, size);
	}

	if (size > 0) { /* the same input cut by one byte: refused or a smaller valid map, never a crash */
		room_fill(&ra, PAT_A);
		(void)one(cut, size - 1u, &ra, &ua, &why);
	}
	free(blob);
	free(cut);
	free(ra.buf);
	free(rb.buf);
	return 0;
}
