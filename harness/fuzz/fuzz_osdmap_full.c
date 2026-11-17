/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the full-map decoder (core/src/osdmap/wri_osdmap_full.c, wri_osdmap_full2.c).
 *
 * The whole input is one OSDMap blob (an exact-size heap copy, so ASan sees any over-read). It is decoded into a 128 KiB slot
 * between guard bands, twice, once with the slot pre-filled with one byte and once with another, with four tracked pool
 * names and the CRC check off (so that mutations reach the row parsers), once more with the CRC recomputed (so that a
 * mutated map gets past the check when the envelopes still nest), and once with a second set of eight names (one twice, one
 * empty) and max_osd limited to 16. Properties (a violated one traps):
 *
 *   - a failure is one of the map or CRUSH statuses, with the same status, a module and a reason in the errinfo, and the slot
 *     has magic 0; a success gives a map that passes wri_osdmap_check, whose bytes are inside the slot, whose guards are intact,
 *     and whose per-OSD arrays, pool records and tables can all be walked through the accessors;
 *   - the two pre-fills give the same status and the same bytes (a decision taken on a byte of the slot that the decoder did not
 *     write shows up as a difference);
 *   - a slot of exactly the used size gives the same map, one byte less gives WR_E_MAP_BUDGET;
 *   - wri_osdmap_full_info agrees with a successful decode on the epoch and the fsid, and never reads past the input;
 *   - the input cut by one byte is refused (the wrapper claims more than there is).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wrt_mapgen.h"
#include "wri_osdmap_dec.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define ROOM (128u * 1024u)
#define GUARD 64u
#define PAT_A 0xA5u
#define PAT_B 0x3Cu

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

typedef struct room {
	uint8_t *buf; /* GUARD + cap + GUARD bytes, malloc alignment */
	size_t cap;
	uint8_t pat;
} room;

static void room_new(room *r, size_t cap)
{
	r->cap = cap;
	r->buf = (uint8_t *)malloc(cap + 2u * GUARD);
	if (r->buf == NULL)
		abort();
}

static void room_fill(room *r, uint8_t pat)
{
	r->pat = pat;
	memset(r->buf, pat, r->cap + 2u * GUARD);
}

static void room_guards(const room *r)
{
	size_t i;

	for (i = 0; i < GUARD; i++) {
		check(r->buf[i] == r->pat);
		check(r->buf[GUARD + r->cap + i] == r->pat);
	}
}

static void mkcfg(wri_mapcfg *c, uint32_t slot_bytes, int verify)
{
	static const char *const names[] = {".mgr", "winrbd", "pool1", "pool2"};
	unsigned k;

	memset(c, 0, sizeof(*c));
	c->slot_bytes = slot_bytes;
	c->max_osd = 4096;
	c->work_max = 200000;
	c->verify_crc = (uint8_t)verify;
	c->n_pools = 4;
	for (k = 0; k < 4; k++) {
		c->name_len[k] = (uint8_t)strlen(names[k]);
		memcpy(c->name[k], names[k], c->name_len[k]);
	}
}

/* A second set of tracked names: one name twice, an unused (empty) entry, the largest count, and a small max_osd limit, so the
 * paths of "the same record for two handles", "no name" and "max_osd above the limit" are reached by mutation too. */
static void mkcfg_alt(wri_mapcfg *c, uint32_t slot_bytes)
{
	static const char *const names[] = {"pool1", "pool1", "", ".mgr", "winrbd", "pool2", "pool3", "x"};
	unsigned k;

	memset(c, 0, sizeof(*c));
	c->slot_bytes = slot_bytes;
	c->max_osd = 16;
	c->work_max = 200000;
	c->verify_crc = 0;
	c->n_pools = WRI_MAP_POOLS_MAX;
	for (k = 0; k < WRI_MAP_POOLS_MAX; k++) {
		c->name_len[k] = (uint8_t)strlen(names[k]);
		memcpy(c->name[k], names[k], c->name_len[k]);
	}
}

/* Touch everything a placement could reach and check the facts that make the accessors safe. */
static void walk(const wri_osdmap *m)
{
	uint32_t i, k, j;
	volatile uint64_t sink = 0;

	check(m->magic == WRI_MAP_MAGIC && m->bytes <= m->cap && m->bytes >= sizeof(*m));
	for (i = 0; i < m->max_osd; i++) {
		const wri_osd_addr *a = &wri_map_addr(m)[i];

		sink += wri_map_state(m)[i] + wri_map_weight(m)[i] + wri_osd_aff(m, (int32_t)i) + a->port + a->nonce;
		check(a->family == 0 || a->family == WR_AF_IPV4 || a->family == WR_AF_IPV6);
		check(wri_osd_up(m, (int32_t)i) <= wri_osd_exists(m, (int32_t)i));
	}
	for (k = 0; k < m->n_pools; k++) {
		const wri_map_pool *p = &wri_map_pools(m)[k];

		check(p->present <= 1u);
		if (p->present == 0)
			continue;
		check(p->status == WR_OK || p->status == WR_E_POOL_UNSUPPORTED || p->status == WR_E_CRUSH_NO_RULE ||
		      p->status == WR_E_CRUSH_UNSUPPORTED || p->status == WR_E_CRUSH_LOOP || p->status == WR_E_CRUSH_ENCODING ||
		      p->status == WR_E_CRUSH_WORK);
		if (p->status == WR_OK) {
			check(p->type == WRI_POOL_REPLICATED && p->size >= 1 && p->size <= WRI_REP_MAX && p->pg_num > 0 && p->pgp_num > 0);
			check((p->pg_num_mask & (p->pg_num_mask + 1u)) == 0 && (p->pgp_num_mask & (p->pgp_num_mask + 1u)) == 0);
		}
	}
	for (k = 0; k < WRI_TAB_COUNT; k++) {
		const uint64_t *keys = m->tab[k].n != 0 ? wri_pgtab_keys(m, k) : NULL;
		const uint32_t *offs = wri_pgtab_offs(m, k);
		const int32_t *vals = wri_pgtab_vals(m, k);

		for (i = 0; i < m->tab[k].n; i++) {
			const int32_t *got;
			uint32_t n;

			check(wri_pgtab_find(m, k, keys[i], &got, &n));
			check(n == offs[i + 1u] - offs[i] && got == vals + offs[i]);
			for (j = 0; j < n; j++)
				sink += (uint32_t)got[j];
			/* only tracked pools are kept, and only pools the map names (ids below 2^31) */
			check((keys[i] >> 32) < ((uint64_t)1 << 31));
		}
	}
	check(wri_map_crush(m) != NULL);
	(void)sink;
}

/* One decode with all the checks; returns the status. */
static wr_status one(const wri_mapcfg *cfg, const uint8_t *blob, size_t n, room *r, wr_errinfo *why)
{
	wr_status st;

	memset(why, 0, sizeof(*why));
	st = wri_osdmap_decode_full(cfg, blob, n, r->buf + GUARD, r->cap, why);
	room_guards(r);
	if (st == WR_OK) {
		const wri_osdmap *m = (const wri_osdmap *)(const void *)(r->buf + GUARD);

		check(wri_osdmap_check(m) == WR_OK);
		walk(m);
	} else {
		uint32_t magic;

		check(st == WR_E_MAP_VERSION || st == WR_E_MAP_CORRUPT || st == WR_E_MAP_CRC || st == WR_E_MAP_BUDGET ||
		      st == WR_E_CRUSH_ENCODING || st == WR_E_CRUSH_UNSUPPORTED);
		check(why->status == st && why->module != 0 && why->what != NULL);
		memcpy(&magic, r->buf + GUARD, 4);
		check(magic == 0);
	}
	return st;
}

/* The two pre-fills, the exact size and one byte less. */
static wr_status both(const wri_mapcfg *cfg, const uint8_t *blob, size_t n, room *ra, room *rb)
{
	wr_errinfo why;
	wr_status sa, sb;

	room_fill(ra, PAT_A);
	sa = one(cfg, blob, n, ra, &why);
	room_fill(rb, PAT_B);
	sb = one(cfg, blob, n, rb, &why);
	check(sa == sb);
	if (sa == WR_OK) {
		const wri_osdmap *ma = (const wri_osdmap *)(const void *)(ra->buf + GUARD);
		const wri_osdmap *mb = (const wri_osdmap *)(const void *)(rb->buf + GUARD);
		wri_map_blob_info bi;
		room rx;
		wri_mapcfg c2 = *cfg;
		size_t used = ma->bytes;

		check(ma->bytes == mb->bytes);
		check(memcmp(ra->buf + GUARD, rb->buf + GUARD, used) == 0);
		check(wri_osdmap_full_info(blob, n, &bi, &why) == WR_OK);
		check(bi.epoch == ma->epoch && memcmp(bi.fsid, ma->fsid, 16) == 0 && bi.has_fullmap == 0);

		/* the exact size gives the same map (its `cap` is the one field that differs), one byte less is a budget failure */
		room_new(&rx, used);
		c2.slot_bytes = (uint32_t)used;
		room_fill(&rx, PAT_B);
		check(one(&c2, blob, n, &rx, &why) == WR_OK);
		check(memcmp(rx.buf + GUARD, ra->buf + GUARD, 8) == 0 && memcmp(rx.buf + GUARD + 12, ra->buf + GUARD + 12, used - 12u) == 0);
		free(rx.buf);
		room_new(&rx, used - 1u);
		c2.slot_bytes = (uint32_t)(used - 1u);
		room_fill(&rx, PAT_A);
		check(one(&c2, blob, n, &rx, &why) == WR_E_MAP_BUDGET);
		free(rx.buf);
	}
	return sa;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t *blob = (uint8_t *)malloc(size ? size : 1u);
	uint8_t *fixed = (uint8_t *)malloc(size ? size : 1u);
	uint8_t *cut = (uint8_t *)malloc(size ? size : 1u);
	room ra, rb;
	wri_mapcfg cfg;
	wri_map_blob_info bi;
	wr_errinfo why;
	wr_status first;

	if (blob == NULL || fixed == NULL || cut == NULL)
		abort();
	room_new(&ra, ROOM);
	room_new(&rb, ROOM);
	if (size != 0) {
		memcpy(blob, data, size);
		memcpy(fixed, data, size);
		memcpy(cut, data, size);
	}

	mkcfg(&cfg, ROOM, 0);
	first = both(&cfg, blob, size, &ra, &rb);

	/* the CRC recomputed over the mutated bytes (when the envelopes nest), checked this time */
	mkcfg(&cfg, ROOM, 1);
	if (size >= 12 && wrt_mg_fix_crc(fixed, size, 0) == 0)
		both(&cfg, fixed, size, &ra, &rb);
	else
		both(&cfg, blob, size, &ra, &rb); /* whatever it is, the check must not crash */

	/* the other tracked-name set (duplicates, an empty name, eight pools) and a small max_osd limit */
	mkcfg_alt(&cfg, ROOM);
	(void)both(&cfg, blob, size, &ra, &rb);

	/* a map that does not fit a small slot: budget or success, the same rules */
	mkcfg(&cfg, 4096u, 0);
	{
		room rs;

		room_new(&rs, 4096u);
		room_fill(&rs, PAT_A);
		(void)one(&cfg, blob, size, &rs, &why);
		free(rs.buf);
	}

	/* the header facts of whatever this is: never a crash, outputs zeroed on failure */
	if (wri_osdmap_full_info(blob, size, &bi, &why) != WR_OK) {
		wri_map_blob_info z;

		memset(&z, 0, sizeof(z));
		check(memcmp(&bi, &z, sizeof(z)) == 0);
	}
	if (wri_osdmap_inc_info(blob, size, &bi, &why) != WR_OK) {
		wri_map_blob_info z;

		memset(&z, 0, sizeof(z));
		check(memcmp(&bi, &z, sizeof(z)) == 0);
	}

	if (first == WR_OK && size > 0) { /* a map that decodes, cut by one byte: the wrapper claims more than there is */
		mkcfg(&cfg, ROOM, 0);
		room_fill(&ra, PAT_A);
		check(one(&cfg, cut, size - 1u, &ra, &why) != WR_OK);
	}
	free(blob);
	free(fixed);
	free(cut);
	free(ra.buf);
	free(rb.buf);
	return 0;
}
