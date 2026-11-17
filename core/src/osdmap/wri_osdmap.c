/* SPDX-License-Identifier: MIT */
/*
 * wri_osdmap.c - the map slot builder and the structural check (see wri_osdmap.h for the contracts).
 *
 * The builder is a bump allocator over the slot with three properties the decoders lean on: a carve that does
 * not fit changes nothing (the sizes are planned in 64-bit locals first, then committed), everything a carve
 * advances over is zeroed (so a map is a pure function of its content, not of what the slot held before), and
 * no byte past the slot is ever touched. The pg tables are in wri_osdmap_tab.c.
 */
#include "wri_osdmap.h"
#include "wri_ctx.h"

WR_FILE_LICENCE_MIT

#define WRI_HDR_BYTES ((uint64_t)sizeof(wri_osdmap))
#define WRI_SLOT_MIN_ALIGN 8u /* the layout holds 64-bit members; the contract is 16 */

/* ---- carving ----------------------------------------------------------------------------------------- */

static const char *wri_tab_nospace(unsigned kind)
{
	switch (kind) {
	case WRI_TAB_PG_TEMP:
		return "map slot too small for the pg_temp table";
	case WRI_TAB_PRIMARY_TEMP:
		return "map slot too small for the primary_temp table";
	case WRI_TAB_PG_UPMAP:
		return "map slot too small for the pg_upmap table";
	case WRI_TAB_PG_UPMAP_ITEMS:
		return "map slot too small for the pg_upmap_items table";
	default:
		return "map slot too small for the pg_upmap_primaries table";
	}
}

/*
 * Plan one section: it starts at *pos rounded up to `align` and is `len` bytes long. On success *off gets the start
 * and *pos the end; nothing is written. On failure the errinfo says which section and how much was wanted.
 */
static int wri_plan(wri_mapbuild *b, uint64_t *pos, uint64_t len, uint64_t align, const char *what, uint32_t *off)
{
	uint64_t start = (*pos + (align - 1u)) & ~(align - 1u); /* *pos <= cap < 2^32 */
	uint64_t end;

	/* The table and array callers pass lengths below 2^36, but wri_mapbuild_crush_room passes the caller's size_t as it
	 * is: a length above the slot is refused before it is added, so start + len cannot wrap whatever the caller sends. */
	if (len > (uint64_t)b->cap) {
		WRI_ERRINFO(b->why, WR_E_MAP_BUDGET, WR_MOD_MAP, what, len, (uint64_t)b->cap - *pos, b->cap);
		return 0;
	}
	end = start + len;
	if (end > (uint64_t)b->cap) {
		WRI_ERRINFO(b->why, WR_E_MAP_BUDGET, WR_MOD_MAP, what, end - *pos, (uint64_t)b->cap - *pos, b->cap);
		return 0;
	}
	*off = (uint32_t)start;
	*pos = end;
	return 1;
}

/* Zero everything from `used` up to the planned end (sections and their padding) and move `used` there. */
static void wri_commit(wri_mapbuild *b, uint64_t end)
{
	WR_MEMSET(wri_map_base_rw(b->m) + b->used, 0, (size_t)(end - (uint64_t)b->used));
	b->used = (size_t)end;
}

wr_status wri_mapbuild_status(const wri_mapbuild *b)
{
	if (b->m != NULL)
		return WR_OK;
	return (uint64_t)b->cap < WRI_HDR_BYTES ? WR_E_MAP_BUDGET : WR_E_INVAL;
}

void wri_mapbuild_begin(wri_mapbuild *b, uint8_t *slot, size_t cap, wr_errinfo *why)
{
	b->m = NULL;
	b->cap = 0;
	b->used = 0;
	b->why = why;
	if (((uint64_t)cap >> 32) != 0) /* offsets are u32; a shift, not a compare, so a 32-bit size_t builds without a type-limits warning */
		cap = (size_t)0xffffffffu;
	b->cap = cap;
	if ((uint64_t)cap < WRI_HDR_BYTES) {
		WRI_ERRINFO(why, WR_E_MAP_BUDGET, WR_MOD_MAP, "map slot smaller than the map header", WRI_HDR_BYTES, cap, cap);
		return;
	}
	if (slot == NULL) { /* a bad argument, not a budget: cap stays so wri_mapbuild_status says WR_E_INVAL */
		WRI_ERRINFO(why, WR_E_INVAL, WR_MOD_MAP, "map slot is NULL", 0, 0, cap);
		return;
	}
	if (((uintptr_t)slot & (WRI_SLOT_MIN_ALIGN - 1u)) != 0) {
		WRI_ERRINFO(why, WR_E_INVAL, WR_MOD_MAP, "map slot is not 8-byte aligned (16 is the contract)", (uintptr_t)slot & 15u, 0, cap);
		return;
	}
	b->m = (wri_osdmap *)(void *)slot;
	WR_MEMSET(slot, 0, sizeof(wri_osdmap));
	b->m->cap = (uint32_t)cap;
	b->used = sizeof(wri_osdmap);
}

wr_status wri_mapbuild_osds(wri_mapbuild *b, uint32_t max_osd, int has_aff)
{
	uint64_t pos;
	uint32_t so, wo, ao = 0, dro;
	wr_status st = wri_mapbuild_status(b);
	uint32_t *a;
	uint32_t i;

	if (st != WR_OK)
		return st;
	if (b->m->state_off != 0) {
		WRI_ERRINFO(b->why, WR_E_INVAL, WR_MOD_MAP, "OSD arrays carved twice", 0, 0, b->cap);
		return WR_E_INVAL;
	}
	if (max_osd > WRI_MAP_OSD_HARD_MAX) {
		WRI_ERRINFO(b->why, WR_E_MAP_BUDGET, WR_MOD_MAP, "max_osd above the hard cap", max_osd, WRI_MAP_OSD_HARD_MAX, b->cap);
		return WR_E_MAP_BUDGET;
	}
	pos = b->used;
	if (!wri_plan(b, &pos, max_osd, 4u, "map slot too small for the OSD state array", &so) ||
	    !wri_plan(b, &pos, (uint64_t)max_osd * 4u, 4u, "map slot too small for the OSD weight array", &wo) ||
	    (has_aff && !wri_plan(b, &pos, (uint64_t)max_osd * 4u, 4u, "map slot too small for the primary affinity array", &ao)) ||
	    !wri_plan(b, &pos, (uint64_t)max_osd * sizeof(wri_osd_addr), 4u, "map slot too small for the OSD address array", &dro))
		return WR_E_MAP_BUDGET;
	wri_commit(b, pos);
	b->m->max_osd = max_osd;
	b->m->state_off = so;
	b->m->weight_off = wo;
	b->m->aff_off = ao;
	b->m->addr_off = dro;
	if (ao != 0) {
		a = (uint32_t *)(void *)(wri_map_base_rw(b->m) + ao);
		for (i = 0; i < max_osd; i++)
			a[i] = WRI_OSD_IN_FULL;
	}
	return WR_OK;
}

wr_status wri_mapbuild_pools(wri_mapbuild *b, uint32_t n_pools)
{
	uint64_t pos;
	uint32_t off;
	wr_status st = wri_mapbuild_status(b);

	if (st != WR_OK)
		return st;
	if (b->m->pool_off != 0) {
		WRI_ERRINFO(b->why, WR_E_INVAL, WR_MOD_MAP, "pool records carved twice", 0, 0, b->cap);
		return WR_E_INVAL;
	}
	if (n_pools > WRI_MAP_POOLS_MAX) {
		WRI_ERRINFO(b->why, WR_E_MAP_BUDGET, WR_MOD_MAP, "more tracked pools than the map can hold", n_pools, WRI_MAP_POOLS_MAX, b->cap);
		return WR_E_MAP_BUDGET;
	}
	pos = b->used;
	if (!wri_plan(b, &pos, (uint64_t)n_pools * sizeof(wri_map_pool), 8u, "map slot too small for the pool records", &off))
		return WR_E_MAP_BUDGET;
	wri_commit(b, pos);
	b->m->n_pools = n_pools;
	b->m->pool_off = off;
	return WR_OK;
}

wr_status wri_mapbuild_tab(wri_mapbuild *b, unsigned kind, uint32_t cap_n, uint32_t cap_nv)
{
	uint64_t pos;
	uint32_t ko, oo, vo;
	wri_pgtab *t;
	wr_status st = wri_mapbuild_status(b);

	if (st != WR_OK)
		return st;
	if (kind >= WRI_TAB_COUNT) {
		WRI_ERRINFO(b->why, WR_E_INVAL, WR_MOD_MAP, "unknown pg table kind", kind, WRI_TAB_COUNT, b->cap);
		return WR_E_INVAL;
	}
	t = &b->m->tab[kind];
	if (t->off_off != 0) {
		WRI_ERRINFO(b->why, WR_E_INVAL, WR_MOD_MAP, "pg table carved twice", kind, 0, b->cap);
		return WR_E_INVAL;
	}
	pos = b->used;
	if (!wri_plan(b, &pos, (uint64_t)cap_n * 8u, 8u, wri_tab_nospace(kind), &ko) ||
	    !wri_plan(b, &pos, ((uint64_t)cap_n + 1u) * 4u, 4u, wri_tab_nospace(kind), &oo) ||
	    !wri_plan(b, &pos, (uint64_t)cap_nv * 4u, 4u, wri_tab_nospace(kind), &vo))
		return WR_E_MAP_BUDGET;
	wri_commit(b, pos);
	t->n = 0;
	t->nv = 0;
	t->cap_n = cap_n;
	t->cap_nv = cap_nv;
	t->key_off = ko;
	t->off_off = oo;
	t->val_off = vo;
	return WR_OK;
}

uint8_t *wri_mapbuild_crush_room(wri_mapbuild *b, size_t n)
{
	uint64_t pos;
	uint32_t off;

	if (wri_mapbuild_status(b) != WR_OK)
		return NULL;
	if (b->m->crush_off != 0 || n == 0) {
		WRI_ERRINFO(b->why, WR_E_INVAL, WR_MOD_MAP, b->m->crush_off != 0 ? "CRUSH region carved twice" : "empty CRUSH region", n, 0, b->cap);
		return NULL;
	}
	pos = b->used;
	if (!wri_plan(b, &pos, (uint64_t)n, 8u, "map slot too small for the CRUSH region", &off))
		return NULL;
	wri_commit(b, pos);
	b->m->crush_off = off;
	return wri_map_base_rw(b->m) + off;
}

size_t wri_mapbuild_left(const wri_mapbuild *b)
{
	return b->m == NULL ? 0u : b->cap - b->used;
}

size_t wri_mapbuild_crush_left(const wri_mapbuild *b)
{
	uint64_t start;

	if (b->m == NULL)
		return 0;
	start = ((uint64_t)b->used + 7u) & ~(uint64_t)7u; /* 64-bit: used + 7 wraps a 32-bit size_t at a slot of 4 GiB - 1 */
	return start > (uint64_t)b->cap ? 0u : (size_t)((uint64_t)b->cap - start);
}

/* ---- finishing ------------------------------------------------------------------------------------------ */

/* 1 if no section other than the CRUSH region starts after it (so the region is what ends the slot's content). */
static int wri_crush_is_last(const wri_osdmap *m)
{
	unsigned k;

	if (m->state_off > m->crush_off || m->weight_off > m->crush_off || m->aff_off > m->crush_off ||
	    m->addr_off > m->crush_off || m->pool_off > m->crush_off)
		return 0;
	for (k = 0; k < WRI_TAB_COUNT; k++)
		if (m->tab[k].key_off > m->crush_off || m->tab[k].off_off > m->crush_off || m->tab[k].val_off > m->crush_off)
			return 0;
	return 1;
}

void wri_mapbuild_finish(wri_mapbuild *b)
{
	wri_osdmap *m = b->m;
	const uint8_t *state;
	const wri_crush *c;
	uint32_t i, ne = 0, nu = 0;
	size_t room;

	if (m == NULL)
		return;
	if (m->crush_off != 0 && wri_crush_is_last(m)) {
		room = b->used - m->crush_off;
		c = wri_map_crush(m);
		if (room >= sizeof(wri_crush) && c->magic == WRI_CRUSH_MAGIC && c->bytes >= sizeof(wri_crush) && c->bytes <= room)
			b->used = (size_t)m->crush_off + c->bytes;
	}
	if (m->state_off != 0) {
		state = wri_map_state(m);
		for (i = 0; i < m->max_osd; i++) {
			if ((state[i] & WRI_OSD_EXISTS) != 0) {
				ne++;
				if ((state[i] & WRI_OSD_UP) != 0)
					nu++;
			}
		}
	}
	m->n_exists = ne;
	m->n_up = nu;
	m->bytes = (uint32_t)b->used;
	m->magic = WRI_MAP_MAGIC;
}

/* ---- the structural check -------------------------------------------------------------------------------- */

#define WRI_SPANS_MAX 24u /* state, weight, affinity, address, pools, 3 x 5 table arrays, CRUSH: 21 */

typedef struct wri_span {
	uint32_t start, end;
} wri_span;

typedef struct wri_spans {
	wri_span s[WRI_SPANS_MAX];
	unsigned n;
} wri_spans;

/* A section of `len` bytes at `off` lies inside the used part of the slot and is aligned. */
static int wri_inside(uint32_t bytes, uint32_t off, uint64_t len, uint32_t align)
{
	return (uint64_t)off >= WRI_HDR_BYTES && (off & (align - 1u)) == 0 && off <= bytes && len <= (uint64_t)(bytes - off);
}

/* The same, and a non-empty section is recorded for the overlap test. */
static int wri_sec(wri_spans *sp, uint32_t bytes, uint32_t off, uint64_t len, uint32_t align)
{
	if (!wri_inside(bytes, off, len, align))
		return 0;
	if (len != 0) {
		if (sp->n >= WRI_SPANS_MAX)
			return 0;
		sp->s[sp->n].start = off;
		sp->s[sp->n].end = off + (uint32_t)len;
		sp->n++;
	}
	return 1;
}

/*
 * The recorded sections do not overlap and are packed the way the builder packs them: the first one starts less than 8
 * bytes after the header, each next one less than 8 bytes after the previous (alignment padding only), and the slot
 * ends less than 8 bytes after the last. A header that lost or grew a count therefore fails, not only one that points
 * outside the slot.
 */
static int wri_spans_packed(wri_spans *sp, uint32_t bytes)
{
	unsigned i, j;
	wri_span t;
	uint32_t prev = (uint32_t)WRI_HDR_BYTES;

	for (i = 1; i < sp->n; i++) { /* insertion sort by start: at most 21 entries */
		t = sp->s[i];
		for (j = i; j > 0 && sp->s[j - 1u].start > t.start; j--)
			sp->s[j] = sp->s[j - 1u];
		sp->s[j] = t;
	}
	for (i = 0; i < sp->n; i++) {
		if (sp->s[i].start < prev || sp->s[i].start - prev >= 8u)
			return 0;
		prev = sp->s[i].end;
	}
	return bytes - prev < 8u;
}

static int wri_osds_ok(const wri_osdmap *m, wri_spans *sp)
{
	uint32_t i, ne = 0, nu = 0;
	const uint8_t *state;
	const wri_osd_addr *ad;

	if (m->state_off == 0)
		return m->weight_off == 0 && m->aff_off == 0 && m->addr_off == 0 && m->max_osd == 0 && m->n_exists == 0 && m->n_up == 0;
	if (!wri_sec(sp, m->bytes, m->state_off, m->max_osd, 4u) || !wri_sec(sp, m->bytes, m->weight_off, (uint64_t)m->max_osd * 4u, 4u) ||
	    !wri_sec(sp, m->bytes, m->addr_off, (uint64_t)m->max_osd * sizeof(wri_osd_addr), 4u))
		return 0;
	if (m->aff_off != 0 && !wri_sec(sp, m->bytes, m->aff_off, (uint64_t)m->max_osd * 4u, 4u))
		return 0;
	state = wri_map_state(m);
	ad = wri_map_addr(m);
	for (i = 0; i < m->max_osd; i++) {
		if ((state[i] & ~(uint8_t)(WRI_OSD_EXISTS | WRI_OSD_UP)) != 0)
			return 0;
		if (ad[i].family != 0 && ad[i].family != WR_AF_IPV4 && ad[i].family != WR_AF_IPV6)
			return 0;
		if ((state[i] & WRI_OSD_EXISTS) != 0) {
			ne++;
			if ((state[i] & WRI_OSD_UP) != 0)
				nu++;
		}
	}
	return ne == m->n_exists && nu == m->n_up;
}

static int wri_pools_ok(const wri_osdmap *m, wri_spans *sp)
{
	uint32_t i;
	const wri_map_pool *p;

	if (m->pool_off == 0)
		return m->n_pools == 0;
	if (!wri_sec(sp, m->bytes, m->pool_off, (uint64_t)m->n_pools * sizeof(wri_map_pool), 8u))
		return 0;
	p = wri_map_pools(m);
	for (i = 0; i < m->n_pools; i++)
		if (p[i].present > 1u)
			return 0;
	return 1;
}

static int wri_tab_ok(const wri_osdmap *m, unsigned kind, wri_spans *sp)
{
	const wri_pgtab *t = &m->tab[kind];
	const uint64_t *keys;
	const uint32_t *offs;
	uint32_t i;

	if (t->off_off == 0)
		return t->key_off == 0 && t->val_off == 0 && t->n == 0 && t->nv == 0 && t->cap_n == 0 && t->cap_nv == 0;
	if (t->n > t->cap_n || t->nv > t->cap_nv)
		return 0;
	if (!wri_sec(sp, m->bytes, t->key_off, (uint64_t)t->cap_n * 8u, 8u) ||
	    !wri_sec(sp, m->bytes, t->off_off, ((uint64_t)t->cap_n + 1u) * 4u, 4u) ||
	    !wri_sec(sp, m->bytes, t->val_off, (uint64_t)t->cap_nv * 4u, 4u))
		return 0;
	keys = wri_pgtab_keys(m, kind);
	offs = wri_pgtab_offs(m, kind);
	if (offs[0] != 0)
		return 0;
	for (i = 0; i < t->n; i++) {
		if (offs[i + 1u] < offs[i] || offs[i + 1u] - offs[i] > WRI_MAP_PGVEC_MAX * 2u)
			return 0;
		if (i > 0 && keys[i] <= keys[i - 1u])
			return 0;
	}
	return offs[t->n] == t->nv;
}

static int wri_crush_ok(const wri_osdmap *m, wri_spans *sp)
{
	const wri_crush *c;

	if (m->crush_off == 0)
		return 1;
	if (!wri_inside(m->bytes, m->crush_off, sizeof(wri_crush), 8u)) /* the header must be readable before its size is */
		return 0;
	c = wri_map_crush(m);
	if (c->bytes < sizeof(wri_crush) || !wri_sec(sp, m->bytes, m->crush_off, c->bytes, 8u))
		return 0;
	return wri_crush_check(c, c->bytes) == WR_OK;
}

wr_status wri_osdmap_check(const wri_osdmap *m)
{
	wri_spans sp;
	unsigned k;

	sp.n = 0;
	if (m == NULL || ((uintptr_t)m & (WRI_SLOT_MIN_ALIGN - 1u)) != 0 || m->magic != WRI_MAP_MAGIC)
		return WR_E_MAP_CORRUPT;
	if ((uint64_t)m->bytes < WRI_HDR_BYTES || m->bytes > m->cap)
		return WR_E_MAP_CORRUPT;
	if (m->max_osd > WRI_MAP_OSD_HARD_MAX || m->n_pools > WRI_MAP_POOLS_MAX)
		return WR_E_MAP_CORRUPT;
	if (!wri_osds_ok(m, &sp) || !wri_pools_ok(m, &sp))
		return WR_E_MAP_CORRUPT;
	for (k = 0; k < WRI_TAB_COUNT; k++)
		if (!wri_tab_ok(m, k, &sp))
			return WR_E_MAP_CORRUPT;
	if (!wri_crush_ok(m, &sp) || !wri_spans_packed(&sp, m->bytes))
		return WR_E_MAP_CORRUPT;
	return WR_OK;
}
