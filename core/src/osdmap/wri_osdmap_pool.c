/* SPDX-License-Identifier: MIT */
/*
 * wri_osdmap_pool.c - one pg_pool_t of an OSDMap (docs/spec/osdmap.md 2.5, architecture 15.2.4).
 *
 * The record sits in its own legacy envelope (struct_v, struct_compat and struct_len, thresholds 5 and 5), so
 * whatever the pool's version a reader can step over it with one jump (wri_pool_skip) and a decoder that stops
 * early or meets newer rows still ends on the envelope end (wri_pool_decode).
 *
 * For a pool of struct_v 29 or more the decoder walks the rows of the table in 2.5 in wire order. A few are
 * kept, a few are read to decide whether this client can use the pool at all, and the rest are stepped over
 * with fixed sizes or the skip helpers of wri_denc_map.h; no count read from the wire is trusted on its own
 * (the helpers cap it against the bytes that are left). Rows 53 and above are never read: the reader jumps to
 * the envelope end. A pool this client cannot serve is not an error: it comes back with status
 * WR_E_POOL_UNSUPPORTED and the reason in the errinfo, and the reader is still left on the envelope end, so the
 * map around it keeps decoding. Only a malformed record (cut short, bad encoding) or a struct_compat the
 * decoder does not know fails the call.
 *
 * Everything works on the bytes of the cursor; nothing is allocated and nothing is global.
 */
#include "wri_osdmap_dec.h"
#include "wri_crush_hash.h"
#include "wri_ctx.h"

WR_FILE_LICENCE_MIT

/* Every pool id of a real cluster fits 31 bits (the pg key packs it above the 32-bit seed, tracked ids are
 * checked against this). */
#define WRI_POOL_ID_LIMIT ((int64_t)1 << WRI_MAP_NAME_ID_BITS)

/* ---- failures ----------------------------------------------------------------------------------- */

/* A hard failure: the destination is wiped (only the id the caller set survives) and the reader carries the
 * error, so a caller that does not look at the status still sees a failed cursor. */
static wr_status pool_fail(wri_rd *r, wri_map_pool *out, int64_t id, wr_errinfo *why, wr_status st, const char *what,
			   uint64_t a0, uint64_t a1, uint64_t a2)
{
	WR_MEMSET(out, 0, sizeof(*out));
	out->id = id;
	wri_rd_fail(r, st);
	WRI_ERRINFO(why, st, WR_MOD_MAP, what, a0, a1, a2);
	return r->err;
}

/* ---- the unsupported rules (15.2.4) ------------------------------------------------------------ */

/* What the rows decided; the unsupported test itself is pool_reason(). */
typedef struct pool_facts {
	int64_t id;
	uint8_t v;
	int tiers_nonempty;
	int64_t tier_of, read_tier, write_tier;
	int profile_nonempty;
	uint32_t stretch_count;
} pool_facts;

/* The first reason this client cannot use the pool, or NULL. a0 / a1 get the offending value and the limit. */
static const char *pool_reason(const wri_map_pool *p, const pool_facts *f, uint64_t *a0, uint64_t *a1)
{
	*a0 = 0;
	*a1 = 0;
	if (f->v < WRI_POOL_MIN_V) {
		*a0 = f->v;
		*a1 = WRI_POOL_MIN_V;
		return "pool record older than struct_v 29";
	}
	if (f->id < 0 || f->id >= WRI_POOL_ID_LIMIT) {
		*a0 = (uint64_t)f->id;
		*a1 = (uint64_t)WRI_POOL_ID_LIMIT;
		return "pool id does not fit 31 bits";
	}
	if (p->type != WRI_POOL_REPLICATED) {
		*a0 = p->type;
		*a1 = WRI_POOL_REPLICATED;
		return "pool is not replicated (erasure coded)";
	}
	if (f->tier_of >= 0) {
		*a0 = (uint64_t)f->tier_of;
		return "pool is a cache tier (tier_of is set)";
	}
	if (f->tiers_nonempty) {
		return "pool has cache tiers";
	}
	if (f->read_tier >= 0) {
		*a0 = (uint64_t)f->read_tier;
		return "pool has a read overlay (read_tier is set)";
	}
	if (f->write_tier >= 0) {
		*a0 = (uint64_t)f->write_tier;
		return "pool has a write overlay (write_tier is set)";
	}
	if (f->profile_nonempty)
		return "pool names an erasure code profile";
	if (f->stretch_count != 0) {
		*a0 = f->stretch_count;
		return "pool is a stretch pool";
	}
	if (p->object_hash != WRI_STR_HASH_LINUX && p->object_hash != WRI_STR_HASH_RJENKINS) {
		*a0 = p->object_hash;
		return "object hash is neither linux nor rjenkins";
	}
	if (p->size == 0 || p->size > WRI_REP_MAX) {
		*a0 = p->size;
		*a1 = WRI_REP_MAX;
		return "pool size is 0 or above the supported replica count";
	}
	if (p->pg_num == 0) {
		return "pg_num is 0";
	}
	if (p->pgp_num == 0) {
		return "pgp_num is 0";
	}
	return NULL;
}

/* ---- the rows ----------------------------------------------------------------------------------- */

/*
 * Rows 1 to 52 of a pool whose struct_v is at least 29 (so every row with "since" 29 or lower is present). The
 * cursor `b` is the envelope body; errors stay in it. Fixed-size rows that nothing reads are skipped in groups.
 */
static void pool_rows(wri_rd *b, uint8_t v, wri_map_pool *p, pool_facts *f)
{
	uint32_t n, i;

	p->type = wri_rd_u8(b);        /* 1 type */
	p->size = wri_rd_u8(b);        /* 2 size */
	p->crush_rule = wri_rd_u8(b);  /* 3 crush_rule */
	p->object_hash = wri_rd_u8(b); /* 4 object_hash */
	p->pg_num = wri_rd_u32(b);     /* 5 pg_num */
	p->pgp_num = wri_rd_u32(b);    /* 6 pgp_num */
	wri_rd_skip(b, 4u + 4u);       /* 7 lpg_num, lpgp_num */
	wri_rd_skip(b, 4u);            /* 8 last_change */
	wri_rd_skip(b, 8u + 4u);       /* 9 snap_seq, 10 snap_epoch */

	/* 11 snaps: map<u64, envelope>; an entry is at least the key (8) and an envelope header (6) */
	n = wri_denc_count(b, 0xFFFFFFFFu, 8u + 6u);
	for (i = 0; i < n && wri_rd_ok(b); i++) {
		wri_rd_skip(b, 8u);
		wri_denc_skip_env(b);
	}
	wri_denc_skip_interval_set(b); /* 12 removed_snaps */
	wri_rd_skip(b, 8u);            /* 13 auid */
	p->flags = wri_rd_u64(b);      /* 14 flags */
	wri_rd_skip(b, 4u);            /* 15 crash_replay_interval */
	p->min_size = wri_rd_u8(b);    /* 16 min_size */
	wri_rd_skip(b, 8u + 8u);       /* 17, 18 quota_max_bytes, quota_max_objects */

	/* 19 tiers: set<u64>, only "is it empty" matters */
	n = wri_denc_count(b, 0xFFFFFFFFu, 8u);
	f->tiers_nonempty = n != 0;
	wri_rd_skip(b, (size_t)n * 8u); /* n * 8 is below the bytes left: wri_denc_count checked it */
	f->tier_of = wri_rd_i64(b);     /* 20 tier_of */
	wri_rd_skip(b, 1u);             /* 21 cache_mode */
	f->read_tier = wri_rd_i64(b);   /* 22 read_tier */
	f->write_tier = wri_rd_i64(b);  /* 23 write_tier */
	wri_denc_skip_str_map(b);       /* 24 properties */
	wri_denc_skip_env(b);           /* 25 hit_set_params */
	wri_rd_skip(b, 4u + 4u);        /* 26 hit_set_period, hit_set_count */
	wri_rd_skip(b, 4u);             /* 27 stripe_width */
	wri_rd_skip(b, 8u + 8u);        /* 28 target_max_bytes, target_max_objects */
	wri_rd_skip(b, 4u + 4u);        /* 29 cache target dirty / full ratio */
	wri_rd_skip(b, 4u + 4u);        /* 30 cache min flush / evict age */

	/* 31 erasure_code_profile: a string, only "is it empty" matters */
	n = wri_rd_u32(b);
	f->profile_nonempty = n != 0;
	wri_rd_skip(b, (size_t)n);      /* checked against the bytes left, never added to a position */

	wri_rd_skip(b, 4u);       /* 32 last_force_op_resend_preluminous */
	wri_rd_skip(b, 4u);       /* 33 min_read_recency_for_promote */
	wri_rd_skip(b, 8u);       /* 34 expected_num_objects */
	wri_rd_skip(b, 4u);       /* 35 cache_target_dirty_high_ratio_micro */
	wri_rd_skip(b, 4u);       /* 36 min_write_recency_for_promote */
	wri_rd_skip(b, 1u + 1u);  /* 37 use_gmt_hitset, 38 fast_read */
	wri_rd_skip(b, 4u + 4u);  /* 39 hit_set_grade_decay_rate, hit_set_search_last_n */
	wri_denc_skip_env(b);     /* 40 opts */
	wri_rd_skip(b, 4u);       /* 41 last_force_op_resend_prenautilus */
	wri_denc_skip_str_map_map(b); /* 42 application_metadata */
	wri_rd_skip(b, 4u + 4u);  /* 43 create_time (u32 sec, u32 nsec) */
	wri_rd_skip(b, 4u + 4u);  /* 44 pg_num_target, 45 pgp_num_target */
	p->pg_num_pending = wri_rd_u32(b); /* 46 pg_num_pending */
	wri_rd_skip(b, 4u + 4u);  /* 47 two old merge epochs */
	p->last_force_op_resend = wri_rd_u32(b); /* 48 last_force_op_resend */
	wri_rd_skip(b, 1u);       /* 49 pg_autoscale_mode */
	wri_denc_skip_env(b);     /* 50 last_pg_merge_meta */

	/* 51 the stretch fields, written by struct_v 30 only */
	if (v == 30u) {
		f->stretch_count = wri_rd_u32(b);
		wri_rd_skip(b, 4u + 4u + 4u); /* bucket_target, bucket_barrier, mandatory_member */
	}
	/* 52 peering crush data, an optional<tuple<u32 x 4>>, from struct_v 31 */
	if (v >= 31u) {
		uint8_t present = wri_rd_u8(b);

		if (present != 0) {
			uint32_t count = wri_rd_u32(b);

			wri_rd_skip(b, 4u + 4u + 4u);
			if (count != 0)
				f->stretch_count = count;
		}
	}
	/* 53 and up (nonprimary_shards, newer rows): not read, the caller's envelope jump skips them */
}

/* ---- decode ------------------------------------------------------------------------------------- */

wr_status wri_pool_decode(wri_rd *r, wri_map_pool *out, wr_errinfo *why)
{
	wri_env e;
	pool_facts f;
	const char *reason;
	uint64_t a0, a1;
	size_t start;
	int64_t id;
	wr_status st;

	if (r == NULL || out == NULL) {
		if (r != NULL)
			wri_rd_fail(r, WR_E_INVAL);
		return WR_E_INVAL;
	}
	/* the caller sets `id` (the key of the pools map) before the call; it is the only field read */
	id = out->id;
	WR_MEMSET(out, 0, sizeof(*out));
	out->id = id;
	WR_MEMSET(&f, 0, sizeof(f));
	f.id = id;
	f.tier_of = -1;
	f.read_tier = -1;
	f.write_tier = -1;
	start = r->pos;

	st = wri_env_open_legacy(r, 5u, 5u, 5u, (uint8_t)WRI_POOL_MAX_COMPAT, &e);
	if (st != WR_OK) {
		uint64_t v = 0, compat = 0;

		/* the two header bytes, for the report only (the helper reads them itself, with its own bounds) */
		if (start < r->len && r->len - start >= 1u)
			v = r->p[start];
		if (start < r->len && r->len - start >= 2u && v >= 5u)
			compat = r->p[start + 1u];
		return pool_fail(r, out, id, why, st,
				 st == WR_E_MAP_VERSION ? "pg_pool_t version or struct_compat not supported"
							: "pg_pool_t envelope cut short",
				 start, v, compat);
	}
	f.v = e.v;

	/* below the floor the rows are not walked: the record is stepped over and the pool refused */
	if (e.v >= WRI_POOL_MIN_V) {
		pool_rows(&e.body, e.v, out, &f);
		if (e.body.err != WR_OK)
			return pool_fail(r, out, id, why, e.body.err, "pg_pool_t body cut short or malformed", start,
					 e.body.pos, e.body.len);
		out->pg_num_mask = wri_pg_mask(out->pg_num);
		out->pgp_num_mask = wri_pg_mask(out->pgp_num);
	}
	/* e.body is a sub-reader over exactly struct_len bytes and the parent is already past them: the jump to the
	 * envelope end is done, whatever the body held (unknown newer rows included) */

	out->present = 1;
	reason = pool_reason(out, &f, &a0, &a1);
	if (reason != NULL) {
		out->status = WR_E_POOL_UNSUPPORTED;
		WRI_ERRINFO(why, WR_E_POOL_UNSUPPORTED, WR_MOD_MAP, reason, a0, a1, (uint64_t)id);
	} else {
		out->status = WR_OK;
	}
	return WR_OK;
}

/* ---- skip --------------------------------------------------------------------------------------- */

wr_status wri_pool_skip(wri_rd *r, wr_errinfo *why)
{
	wri_env e;
	size_t start;
	wr_status st;

	if (r == NULL)
		return WR_E_INVAL;
	start = r->pos;
	/* No compat limit: a record that is only stepped over is never interpreted (the same as wri_denc_skip_env). */
	st = wri_env_open_legacy(r, 5u, 5u, 5u, 0xFFu, &e);
	if (st != WR_OK)
		WRI_ERRINFO(why, st, WR_MOD_MAP,
			    st == WR_E_MAP_VERSION ? "pg_pool_t older than struct_v 5 has no length to skip by"
						   : "pg_pool_t envelope cut short",
			    start, 0, 0);
	return st;
}
