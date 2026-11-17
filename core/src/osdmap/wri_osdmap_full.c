/* SPDX-License-Identifier: MIT */
/*
 * wri_osdmap_full.c - a complete OSDMap blob into a map slot (docs/spec/osdmap.md 2.4, 3.3, 3.6; architecture 15.4), the
 * header facts of a full map and of an incremental, and the address reader the full map and the incremental share.
 *
 * The decode is a fixed sequence, every step of which can fail without having touched anything but the slot:
 *   1. the three envelopes (wrapper, client block, OSD-only block) and the CRC field are located, nothing else is read;
 *   2. when the configuration asks for it the CRC is checked, before a single row is interpreted;
 *   3. the tracked pool names are resolved to ids (the pools come first on the wire and the names after them, so this is a
 *      walk over rows 5 and 6 that decodes nothing);
 *   4. a counting walk over rows 7 to 25 (wri_osdmap_full2.c) learns max_osd and the size of every table;
 *   5. the slot is carved exactly, in the layout order of wri_osdmap.h, the CRUSH room last;
 *   6. the tracked pool records are decoded, then a second walk over rows 7 to 25 fills the arrays and tables and decodes
 *      the CRUSH blob straight from the wire into the room;
 *   7. the rule audit sets the status of every present tracked pool, and the builder finishes the header.
 * Failing at any point leaves the slot with magic 0 (the builder zeroes the header first and sets the magic last).
 */
#include "wri_osdmap_dec.h"
#include "wri_crc32c.h"
#include "wri_ctx.h"
#include "wri_m2_addr.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define CRC_SEED 0xFFFFFFFFu /* osdmap.md 2.4.5: the raw register, start all ones, no final inversion */
#define OSD_BLOCK_COMPAT_ANY 0xFFu

/* ---- statuses ----------------------------------------------------------------------------------------- */

/* The status of a failed envelope open: a compat above what we know is "version", everything else follows the common rule. */
static wr_status env_status(wr_status st)
{
	return st == WR_E_UNSUPPORTED ? WR_E_MAP_VERSION : wri_full_status(st);
}

static wr_status fail_at(wr_errinfo *why, wr_status st, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	WRI_ERRINFO(why, st, WR_MOD_MAP, what, a0, a1, a2);
	return st;
}

/* ---- addresses (osdmap.md 2.1.2, 2.1.3, 3.8) ------------------------------------------------------------- */

static wr_status addr_fail(wri_rd *r, wri_osd_addr *out, wr_status st)
{
	WR_MEMSET(out, 0, sizeof(*out));
	wri_rd_fail(r, st);
	return st;
}

wr_status wri_osdmap_read_addr(wri_rd *r, wri_osd_addr *out)
{
	uint8_t marker;
	uint32_t count, i;
	size_t start;
	int have = 0;

	if (r == NULL)
		return WR_E_INVAL;
	if (out == NULL) {
		wri_rd_fail(r, WR_E_INVAL);
		return WR_E_INVAL;
	}
	WR_MEMSET(out, 0, sizeof(*out));
	if (r->err != WR_OK)
		return r->err;

	start = r->pos;
	marker = wri_rd_u8(r);
	if (!wri_rd_ok(r))
		return addr_fail(r, out, WR_E_MAP_CORRUPT);
	if (marker == 0)
		return addr_fail(r, out, WR_E_MAP_VERSION); /* the legacy sockaddr_storage form: only senders without MSG_ADDR2 write it */
	if (marker == 1) {
		count = 1; /* the marker byte is shared with the one entity_addr_t that follows */
	} else if (marker == 2) {
		count = wri_rd_count(r, WRI_EADDRVEC_WIRE_MAX, 7u); /* an entry is at least its marker and envelope header */
		if (!wri_rd_ok(r))
			return addr_fail(r, out, WR_E_MAP_CORRUPT);
	} else {
		return addr_fail(r, out, WR_E_MAP_CORRUPT);
	}

	for (i = 0; i < count && wri_rd_ok(r); i++) {
		wri_rd t = *r; /* a copy at the start of the entry: the decoder reads the marker itself */
		wri_env e;
		wri_eaddr a;

		if (marker == 1) {
			t.pos = start;
		} else {
			uint8_t em = wri_rd_u8(r);

			if (!wri_rd_ok(r))
				return addr_fail(r, out, WR_E_MAP_CORRUPT);
			if (em != 1u)
				return addr_fail(r, out, em == 0 ? WR_E_MAP_VERSION : WR_E_MAP_CORRUPT);
		}
		/* every entry is walked by its own length, so the stream stays aligned whatever it holds */
		if (wri_env_open(r, 1, &e) != WR_OK)
			return addr_fail(r, out, env_status(r->err));
		if (have)
			continue; /* the rest of the vector is consumed, not decoded */
		if (wri_eaddr_decode(&t, &a) != WR_OK) {
			if (t.err == WR_E_UNSUPPORTED)
				continue; /* a socket family we do not speak: this entry is not usable, the next may be */
			return addr_fail(r, out, WR_E_MAP_CORRUPT);
		}
		if (a.type == WRI_EADDR_TYPE_MSGR2 && (a.family == WR_AF_IPV4 || a.family == WR_AF_IPV6)) {
			out->nonce = a.nonce;
			out->port = a.port;
			out->family = a.family;
			WR_MEMCPY(out->ip, a.ip, sizeof(out->ip));
			have = 1;
		}
	}
	if (!wri_rd_ok(r))
		return addr_fail(r, out, wri_full_status(r->err));
	return WR_OK;
}

/* ---- the envelopes and the header facts ----------------------------------------------------------------- */

/*
 * The wrapper and the client block of a full map (inc == 0) or an incremental (inc == 1): legacy envelope with the
 * thresholds (7, 7), compat at most 8, then the client block with the floors of osdmap.md 4.1. `we` and `ce` are the
 * open envelopes; ce->body is positioned at row 1. The OSD-only block and anything after it are not looked at.
 */
static wr_status open_blocks(const uint8_t *p, size_t n, unsigned inc, wri_rd *r, wri_env *we, wri_env *ce, wr_errinfo *why)
{
	uint32_t floor_v = inc ? WRI_MAP_INC_BLOCK_MIN_V : WRI_MAP_FULL_BLOCK_MIN_V;
	uint32_t max_compat = inc ? WRI_MAP_INC_BLOCK_MAX_COMPAT : WRI_MAP_FULL_BLOCK_MAX_COMPAT;
	uint64_t v0 = n >= 1u ? p[0] : 0u, c0 = n >= 2u ? p[1] : 0u;
	wr_status st;

	wri_rd_init(r, p, n);
	st = wri_env_open_legacy(r, WRI_MAP_WRAPPER_MIN_V, 7u, 7u, WRI_MAP_WRAPPER_MAX_COMPAT, we);
	if (st != WR_OK)
		return fail_at(why, env_status(st),
			       st == WR_E_MAP_VERSION ? "OSD map wrapper version or struct_compat not supported" : "OSD map wrapper cut short",
			       0, v0, c0);
	st = wri_env_open(&we->body, (uint8_t)max_compat, ce);
	if (st != WR_OK)
		return fail_at(why, env_status(st),
			       st == WR_E_UNSUPPORTED ? "OSD map client block struct_compat not supported" : "OSD map client block cut short",
			       we->body.pos, ce->v, ce->compat);
	if (ce->v < floor_v)
		return fail_at(why, WR_E_MAP_VERSION, "OSD map client block older than the supported floor", we->body.pos, ce->v, floor_v);
	return WR_OK;
}

static wr_status blob_info(const uint8_t *p, size_t n, unsigned inc, wri_map_blob_info *out, wr_errinfo *why)
{
	wri_rd r;
	wri_env we, ce;
	wr_status st;

	if (out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	if (p == NULL && n != 0)
		return WR_E_INVAL;
	st = open_blocks(p, n, inc, &r, &we, &ce, why);
	if (st != WR_OK)
		return st;
	wri_rd_copy(&ce.body, out->fsid, sizeof(out->fsid)); /* 1 fsid */
	out->epoch = wri_rd_u32(&ce.body);                    /* 2 epoch */
	if (inc && wri_rd_ok(&ce.body)) {
		uint32_t len;

		/* rows 3 to 5 are fixed size (modified, new_pool_max, new_flags); row 6 is the embedded full map: only its length counts */
		wri_rd_skip(&ce.body, 8u + 8u + 4u);
		len = wri_rd_u32(&ce.body);
		if (wri_rd_ok(&ce.body) && (size_t)len > wri_rd_left(&ce.body))
			wri_rd_fail(&ce.body, WR_E_TRUNCATED);
		out->has_fullmap = len != 0 ? 1u : 0u;
	}
	if (!wri_rd_ok(&ce.body)) {
		st = wri_full_status(ce.body.err);
		WR_MEMSET(out, 0, sizeof(*out));
		return fail_at(why, st, inc ? "incremental header rows cut short" : "OSD map header rows cut short", ce.body.pos, ce.body.len, 0);
	}
	return WR_OK;
}

wr_status wri_osdmap_full_info(const uint8_t *p, size_t n, wri_map_blob_info *out, wr_errinfo *why)
{
	return blob_info(p, n, 0u, out, why);
}

wr_status wri_osdmap_inc_info(const uint8_t *p, size_t n, wri_map_blob_info *out, wr_errinfo *why)
{
	return blob_info(p, n, 1u, out, why);
}

/* ---- the tracked pools (rows 5 and 6) -------------------------------------------------------------------- */

/*
 * Pass one: walk the pools map stepping over every record by its envelope, then the name map, matching each name with the
 * tracked names of the configuration. `r` ends after row 6. A name that is not in the map leaves its pool not found; ids and
 * names are written in key order, so a repeated or descending key is damage, and so is a tracked name on two ids.
 */
static wr_status resolve_names(const wri_mapcfg *cfg, wri_rd *r, wri_full_ids *ids, const uint8_t *base, wr_errinfo *why)
{
	uint32_t n, i, k;
	int64_t prev = 0;
	wr_status st;

	n = wri_rd_count(r, 0xFFFFFFFFu, 8u + 6u); /* s64 key + the envelope header of a pg_pool_t */
	for (i = 0; i < n && wri_rd_ok(r); i++) {
		int64_t id = wri_rd_i64(r);

		if (!wri_rd_ok(r))
			break;
		if (i > 0 && id <= prev)
			return fail_at(why, WR_E_MAP_CORRUPT, "pool ids are not strictly ascending", (size_t)(r->p - base) + r->pos, (uint64_t)id, (uint64_t)prev);
		prev = id;
		st = wri_pool_skip(r, NULL);
		if (st != WR_OK)
			return fail_at(why, wri_full_status(st), st == WR_E_MAP_VERSION ? "pg_pool_t older than struct_v 5 cannot be stepped over" : "pg_pool_t cut short",
				       (size_t)(r->p - base) + r->pos, (uint64_t)id, 0);
	}
	if (!wri_rd_ok(r))
		return fail_at(why, wri_full_status(r->err), "pools map is malformed", (size_t)(r->p - base) + r->pos, r->len, 0);

	n = wri_rd_count(r, 0xFFFFFFFFu, 8u + 4u); /* s64 key + string length */
	for (i = 0; i < n && wri_rd_ok(r); i++) {
		int64_t id = wri_rd_i64(r);
		uint32_t len = wri_rd_u32(r);
		const uint8_t *name = wri_rd_bytes(r, len);

		if (!wri_rd_ok(r) || name == NULL)
			break;
		if (i > 0 && id <= prev)
			return fail_at(why, WR_E_MAP_CORRUPT, "pool name ids are not strictly ascending", (size_t)(r->p - base) + r->pos, (uint64_t)id, (uint64_t)prev);
		prev = id;
		for (k = 0; k < ids->n; k++) {
			if (cfg->name_len[k] == 0 || cfg->name_len[k] > WRI_MAP_NAME_MAX || len != cfg->name_len[k] || !wri_ct_memeq(cfg->name[k], name, len))
				continue;
			if (ids->found[k] != 0)
				return fail_at(why, WR_E_MAP_CORRUPT, "a tracked pool name belongs to two pool ids", (size_t)(r->p - base) + r->pos, (uint64_t)id, (uint64_t)ids->id[k]);
			ids->found[k] = 1;
			ids->id[k] = id;
		}
	}
	if (!wri_rd_ok(r))
		return fail_at(why, wri_full_status(r->err), "pool_name map is malformed", (size_t)(r->p - base) + r->pos, r->len, 0);
	return WR_OK;
}

static int ids_find(const wri_full_ids *ids, int64_t id)
{
	uint32_t k;

	for (k = 0; k < ids->n; k++)
		if (ids->found[k] != 0 && ids->id[k] == id)
			return (int)k;
	return -1;
}

/* Pass two: decode the records of the tracked pools into the carved pool array; every other record is stepped over again. */
static wr_status fill_pools(wri_rd *r, const wri_full_ids *ids, wri_mapbuild *b, const uint8_t *base, wr_errinfo *why, wr_errinfo *note)
{
	wri_map_pool *pl = (wri_map_pool *)(void *)(wri_map_base_rw(b->m) + b->m->pool_off);
	uint32_t n, i;

	n = wri_rd_count(r, 0xFFFFFFFFu, 8u + 6u);
	for (i = 0; i < n && wri_rd_ok(r); i++) {
		int64_t id = wri_rd_i64(r);
		int k = ids_find(ids, id);
		wr_status st;

		if (!wri_rd_ok(r))
			break;
		if (k < 0) {
			st = wri_pool_skip(r, NULL);
		} else {
			wr_errinfo local;
			uint32_t k2;

			WR_MEMSET(&local, 0, sizeof(local));
			pl[k].id = id;
			st = wri_pool_decode(r, &pl[k], &local);
			if (st != WR_OK) {
				st = wri_full_status(st);
				WRI_ERRINFO(why, st, WR_MOD_MAP, local.what != NULL ? local.what : "tracked pg_pool_t is malformed",
					    (size_t)(r->p - base) + r->pos, (uint64_t)id, local.a0);
				return st;
			}
			if (local.status != WR_OK && note->status == WR_OK)
				*note = local; /* the first pool this client cannot use: reported with the map that carried it */
			for (k2 = (uint32_t)k + 1u; k2 < ids->n; k2++) /* the same name tracked twice: the same record */
				if (ids->found[k2] != 0 && ids->id[k2] == id)
					pl[k2] = pl[k];
		}
		if (st != WR_OK)
			return fail_at(why, wri_full_status(st), "pg_pool_t cut short", (size_t)(r->p - base) + r->pos, (uint64_t)id, 0);
	}
	if (!wri_rd_ok(r))
		return fail_at(why, wri_full_status(r->err), "pools map is malformed", (size_t)(r->p - base) + r->pos, r->len, 0);
	return WR_OK;
}

/* The rule audit of every present tracked pool that is otherwise usable: its answer is the pool's status. */
static void audit_pools(wri_mapbuild *b, wr_errinfo *note)
{
	wri_map_pool *pl = (wri_map_pool *)(void *)(wri_map_base_rw(b->m) + b->m->pool_off);
	const wri_crush *c = wri_map_crush(b->m);
	uint32_t k;

	for (k = 0; k < b->m->n_pools; k++) {
		wr_errinfo local;
		wr_status st;

		if (pl[k].present == 0 || pl[k].status != WR_OK)
			continue;
		WR_MEMSET(&local, 0, sizeof(local));
		st = wri_crush_audit_rule(c, pl[k].crush_rule, pl[k].size, &local);
		if (st == WR_OK)
			continue;
		pl[k].status = st;
		if (note->status == WR_OK) {
			*note = local;
			if (note->status == WR_OK)
				WRI_ERRINFO(note, st, WR_MOD_CRUSH, "the pool's CRUSH rule cannot be used", pl[k].crush_rule, (uint64_t)pl[k].id, 0);
		}
	}
}

/* ---- the decoder ----------------------------------------------------------------------------------------- */

/* Carve the slot from what the counting pass learned. The CRUSH room is the last section and takes everything that is left. */
static wr_status carve(wri_mapbuild *b, const wri_mapcfg *cfg, const wri_full_walk *w)
{
	uint8_t *room;
	size_t left;
	unsigned k;
	wr_status st;

	st = wri_mapbuild_osds(b, w->max_osd, w->has_aff);
	if (st == WR_OK)
		st = wri_mapbuild_pools(b, cfg->n_pools);
	for (k = 0; st == WR_OK && k < WRI_TAB_COUNT; k++)
		st = wri_mapbuild_tab(b, k, w->tab_n[k], w->tab_nv[k]);
	if (st != WR_OK)
		return st;
	left = wri_mapbuild_crush_left(b);
	if (left == 0)
		return fail_at(b->why, WR_E_MAP_BUDGET, "map slot too small for the CRUSH region", 0, 0, b->cap);
	room = wri_mapbuild_crush_room(b, left);
	return room == NULL ? WR_E_MAP_BUDGET : WR_OK; /* the room is the whole rest of the slot: the builder only refuses a plan overflow */
}

/* What the first step leaves for the rest: the client block's reader positioned at row 1's successor, and the header facts. */
typedef struct front {
	wri_rd rows;      /* the client block body, after rows 1 to 4 */
	uint32_t block_v; /* struct_v of the client block */
	uint32_t epoch;
	uint8_t fsid[16];
} front;

/* Steps 1 and 2: the three envelopes and the CRC field, then the CRC when asked, then rows 1 to 4. */
static wr_status read_front(const wri_mapcfg *cfg, const uint8_t *p, size_t n, front *f, wr_errinfo *why)
{
	wri_rd r;
	wri_env we, ce, oe;
	uint32_t stored = 0;
	size_t crc_pos = 0;
	wr_status st;

	st = open_blocks(p, n, 0u, &r, &we, &ce, why);
	if (st != WR_OK)
		return st;
	if (wri_rd_left(&r) != 0)
		return fail_at(why, WR_E_MAP_CORRUPT, "bytes after the OSD map wrapper", n - wri_rd_left(&r), wri_rd_left(&r), 0);
	st = wri_env_open(&we.body, OSD_BLOCK_COMPAT_ANY, &oe); /* only its length matters: whatever its version, it is jumped over */
	if (st != WR_OK)
		return fail_at(why, wri_full_status(st), "OSD-only block cut short", we.body.pos, oe.v, oe.compat);
	if (we.v >= 8u) { /* the CRC field */
		crc_pos = (size_t)(we.body.p - p) + we.body.pos;
		stored = wri_rd_u32(&we.body);
		if (!wri_rd_ok(&we.body))
			return fail_at(why, WR_E_MAP_CORRUPT, "OSD map CRC field missing", crc_pos, 0, 0);
	}
	if (cfg->verify_crc != 0 && we.v >= 8u) { /* over the wrapper without the CRC field (osdmap.md 2.4.5) */
		uint32_t crc = wri_crc32c(CRC_SEED, p, crc_pos);

		crc = wri_crc32c(crc, p + crc_pos + 4u, n - crc_pos - 4u);
		if (crc != stored)
			return fail_at(why, WR_E_MAP_CRC, "OSD map CRC does not match", crc_pos, stored, crc);
	}
	/* rows 1 to 4: fsid, epoch, created, modified */
	f->rows = ce.body;
	f->block_v = ce.v;
	wri_rd_copy(&f->rows, f->fsid, sizeof(f->fsid));
	f->epoch = wri_rd_u32(&f->rows);
	wri_rd_skip(&f->rows, 16u);
	if (!wri_rd_ok(&f->rows))
		return fail_at(why, WR_E_MAP_CORRUPT, "OSD map header rows cut short", f->rows.pos, f->rows.len, 0);
	return WR_OK;
}

/* Steps 3 to 7 on a slot whose builder is open. */
static wr_status build(const wri_mapcfg *cfg, const uint8_t *p, front *f, wri_mapbuild *b, wr_errinfo *why)
{
	wri_full_ids ids;
	wri_full_walk w;
	wri_rd c2, rc;
	wr_errinfo note;
	wr_status st;

	WR_MEMSET(&note, 0, sizeof(note));
	WR_MEMSET(&ids, 0, sizeof(ids));
	ids.n = cfg->n_pools;
	c2 = f->rows; /* pass two starts where row 5 starts */
	st = resolve_names(cfg, &f->rows, &ids, p, why);
	if (st != WR_OK)
		return st;

	WR_MEMSET(&w, 0, sizeof(w)); /* the counting walk */
	w.base = p;
	w.ids = &ids;
	w.block_v = f->block_v;
	w.max_osd_limit = cfg->max_osd < WRI_MAP_OSD_HARD_MAX ? cfg->max_osd : WRI_MAP_OSD_HARD_MAX;
	w.why = why;
	rc = f->rows;
	st = wri_full_rows(&w, &rc);
	if (st != WR_OK)
		return st;

	st = carve(b, cfg, &w);
	if (st != WR_OK)
		return st;

	b->m->epoch = f->epoch; /* the filling walk */
	WR_MEMCPY(b->m->fsid, f->fsid, sizeof(f->fsid));
	st = fill_pools(&c2, &ids, b, p, why, &note);
	if (st != WR_OK)
		return st;
	w.b = b;
	rc = f->rows;
	st = wri_full_rows(&w, &rc);
	if (st != WR_OK)
		return st;

	audit_pools(b, &note); /* the rule audit, then the header */
	wri_mapbuild_finish(b);
	if (why != NULL && why->status == WR_OK && note.status != WR_OK)
		*why = note;
	return WR_OK;
}

wr_status wri_osdmap_decode_full(const wri_mapcfg *cfg, const uint8_t *p, size_t n, uint8_t *slot, size_t cap, wr_errinfo *why)
{
	wri_mapbuild b;
	front f;
	wr_status st;

	if (slot != NULL && cap >= 4u && ((uintptr_t)slot & 3u) == 0)
		WR_MEMSET(slot, 0, 4u); /* whatever happens next, the slot is not a map */
	if (cfg == NULL || (p == NULL && n != 0))
		return WR_E_INVAL;
	if (cap > (size_t)cfg->slot_bytes)
		cap = (size_t)cfg->slot_bytes;
	wri_mapbuild_begin(&b, slot, cap, why);
	st = wri_mapbuild_status(&b);
	if (st != WR_OK)
		return st;
	if (cfg->n_pools > WRI_MAP_POOLS_MAX)
		return fail_at(why, WR_E_MAP_BUDGET, "more tracked pools than the map can hold", cfg->n_pools, WRI_MAP_POOLS_MAX, 0);
	st = read_front(cfg, p, n, &f, why);
	if (st != WR_OK)
		return st;
	return build(cfg, p, &f, &b, why);
}
