/* SPDX-License-Identifier: MIT */
/*
 * test_osdmap_pool.c - wri_pool_decode and wri_pool_skip (core/src/osdmap/wri_osdmap_pool.c, architecture 15.2.4).
 *
 *  - the two pools of osdmap/full-e42.hex against the state summary of osdmap/expected.json, and the eight pools of
 *    public/denc-map/pools-e202.bin (pool snapshots, a cache tier, an overlay, odd pg_num / pgp_num) against the
 *    `ceph osd dump` lines of pools-e202.txt;
 *  - every row combination wrt_mapgen writes for struct_v 29, 30, 31 and 32 (every optional part empty or not, a tail
 *    after the known rows, the stretch / peering fields present with a zero count, big varints in row 53), each pool
 *    with distinct values in every field so a row of the wrong size shifts everything after it: kept fields, masks,
 *    status, the reader's end position, and wri_pool_skip ending on the same offset;
 *  - every truncation point: the envelope cut (the length says more than the buffer has) and the body cut with the
 *    length patched (the decoder must fail exactly while a row it reads is missing and succeed as soon as only
 *    the unread rows 53 and up are cut: that pins "rows 1 to 52, never 53");
 *  - the unsupported shapes (erasure, each tier field, a profile, stretch, hash 3, size 0 and 17, pg_num 0 and pgp_num 0,
 *    an id of 2^31 and above, struct_v below 29) with the status and the reason in the errinfo, and the shapes that are
 *    NOT refusals (POOL_SNAPS, EIO, hash 1, no HASHPSPOOL, size 16, a zero stretch count);
 *  - struct_compat 32 accepted, 33 rejected (skip still steps over it), struct_v 33 and 40 with extra rows and a tail,
 *    struct_v 5 .. 28 stepped over, struct_v below 5 refused, hostile lengths and counts, every byte of rich pools
 *    mutated (the result is a clean error or a decode that ends on the envelope end, run under the sanitizers),
 *    random multi-byte mutations, argument and sticky-error handling;
 *  - the masks for pg_num 1, 2, 3, 12, 100, 128, 2^31 (and the all-ones width limit).
 *
 * Buffers handed to the decoder are exact-size heap copies, so a read past the end shows up under AddressSanitizer.
 */
#include "wrt.h"
#include "wrt_mapgen.h"
#include "wri_crush_hash.h"
#include "wri_osdmap_dec.h"

/* ---- helpers ------------------------------------------------------------------------------------ */

static uint64_t g_rng = 0x2545F4914F6CDD1Dull;

static uint32_t rnd(void)
{
	g_rng ^= g_rng >> 12;
	g_rng ^= g_rng << 25;
	g_rng ^= g_rng >> 27;
	return (uint32_t)((g_rng * 0x2545F4914F6CDD1Dull) >> 32);
}

static uint8_t *xdup(const uint8_t *p, size_t n)
{
	uint8_t *c = (uint8_t *)malloc(n == 0 ? 1 : n);

	if (c == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	if (n != 0)
		memcpy(c, p, n);
	return c;
}

static void put_u32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static size_t varint_len(uint64_t v)
{
	size_t n = 1;

	while (v >= 0x80u) {
		v >>= 7;
		n++;
	}
	return n;
}

/* the mask of osdmap.md 2.5, written out independently of the core: (1 << bits(n - 1)) - 1 */
static uint32_t mask_ref(uint32_t n)
{
	uint32_t m, bits = 0;

	if (n == 0)
		return 0;
	m = n - 1u;
	while (m != 0) {
		bits++;
		m >>= 1;
	}
	return bits >= 32u ? 0xffffffffu : (1u << bits) - 1u;
}

/* The unsupported rules of 15.2.4, written from the architecture text and not from the decoder. */
static int unsupported_ref(const wrt_mg_pool *m, int64_t id)
{
	if (m->v < 29)
		return 1;
	if (id < 0 || id >= ((int64_t)1 << 31))
		return 1;
	if (m->type != 1)
		return 1;
	if (m->tier_of >= 0 || m->tiers.n != 0 || m->read_tier >= 0 || m->write_tier >= 0)
		return 1;
	if (m->erasure_code_profile[0] != '\0')
		return 1;
	if (m->v == 30 && m->stretch_count != 0)
		return 1;
	if (m->v >= 31 && m->peering_present && m->peering_count != 0)
		return 1;
	if (m->object_hash != 1 && m->object_hash != 2)
		return 1;
	if (m->size == 0 || m->size > 16)
		return 1;
	if (m->pg_num == 0 || m->pgp_num == 0)
		return 1;
	return 0;
}

/* ---- decode one buffer and compare with the model ------------------------------------------------- */

/* A freshly filled destination, so that "every field is written" is visible. */
static void dirty(wri_map_pool *o, int64_t id)
{
	memset(o, 0xEE, sizeof(*o));
	o->id = id;
}

static int is_wiped(const wri_map_pool *o, int64_t id)
{
	wri_map_pool z;

	memset(&z, 0, sizeof(z));
	z.id = id;
	return memcmp(o, &z, sizeof(z)) == 0;
}

/* Kept fields of a pool of struct_v >= 29 against the model. */
static void check_kept(const wri_map_pool *o, const wrt_mg_pool *m, int64_t id)
{
	WRT_CHECK_U64(o->id, id);
	WRT_CHECK_U64(o->present, 1);
	WRT_CHECK_U64(o->type, m->type);
	WRT_CHECK_U64(o->size, m->size);
	WRT_CHECK_U64(o->min_size, m->min_size);
	WRT_CHECK_U64(o->crush_rule, m->crush_rule);
	WRT_CHECK_U64(o->object_hash, m->object_hash);
	WRT_CHECK_U64(o->pg_num, m->pg_num);
	WRT_CHECK_U64(o->pgp_num, m->pgp_num);
	WRT_CHECK_U64(o->pg_num_mask, mask_ref(m->pg_num));
	WRT_CHECK_U64(o->pgp_num_mask, mask_ref(m->pgp_num));
	WRT_CHECK_U64(o->flags, m->flags);
	WRT_CHECK_U64(o->pg_num_pending, m->pg_num_pending);
	WRT_CHECK_U64(o->last_force_op_resend, m->last_force_op_resend);
	WRT_CHECK_U64(o->reserved[0], 0);
	WRT_CHECK_U64(o->reserved2, 0);
}

/*
 * Decode enc[0..n) (the whole encoding of m, id as the map key) with `trail` extra bytes after it, and check:
 * status, kept fields, errinfo, the end position, and that wri_pool_skip ends on the same offset.
 */
static void check_one(const uint8_t *enc, size_t n, const wrt_mg_pool *m, int64_t id, size_t trail)
{
	uint8_t *tmp = (uint8_t *)malloc(n + trail + 1), *buf;
	wri_rd r, rs;
	wri_map_pool o;
	wr_errinfo why, why2;
	int uns = unsupported_ref(m, id);

	if (tmp == NULL)
		exit(2);
	memcpy(tmp, enc, n);
	memset(tmp + n, 0xCC, trail);
	buf = xdup(tmp, n + trail); /* exact size: a read past the end is a heap overflow under the sanitizer */
	free(tmp);
	memset(&why, 0, sizeof(why));
	memset(&why2, 0, sizeof(why2));
	dirty(&o, id);
	wri_rd_init(&r, buf, n + trail);
	WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, &why));
	WRT_CHECK_U64(r.err, WR_OK);
	WRT_CHECK_U64(r.pos, n);
	WRT_CHECK_U64(o.present, 1);
	WRT_CHECK_U64(o.id, id);
	if (m->v >= 29)
		check_kept(&o, m, id);
	WRT_CHECK_U64(o.status, uns ? WR_E_POOL_UNSUPPORTED : WR_OK);
	if (uns) {
		WRT_CHECK_U64(why.status, WR_E_POOL_UNSUPPORTED);
		WRT_CHECK_U64(why.module, WR_MOD_MAP);
		WRT_CHECK(why.what != NULL && why.what[0] != '\0');
	} else {
		WRT_CHECK_U64(why.status, WR_OK); /* a usable pool leaves the errinfo alone */
		WRT_CHECK(why.what == NULL);
	}
	wri_rd_init(&rs, buf, n + trail);
	WRT_CHECK_STATUS(WR_OK, wri_pool_skip(&rs, &why2));
	WRT_CHECK_U64(rs.pos, n);
	WRT_CHECK_U64(rs.err, WR_OK);
	WRT_CHECK_U64(why2.status, WR_OK);
	free(buf);
}

/* A decode that must fail with one of the cursor's error codes; destination wiped, id kept, cursor failed. */
static void check_fails(const uint8_t *p, size_t n, int64_t id, wr_status want)
{
	uint8_t *c = xdup(p, n);
	wri_rd r;
	wri_map_pool o;
	wr_errinfo why;
	wr_status st;

	memset(&why, 0, sizeof(why));
	dirty(&o, id);
	wri_rd_init(&r, c, n);
	st = wri_pool_decode(&r, &o, &why);
	if (want != WR_OK) {
		WRT_CHECK_U64((uint32_t)st, (uint32_t)want);
	} else {
		WRT_CHECK(st != WR_OK);
	}
	WRT_CHECK_U64((uint32_t)r.err, (uint32_t)st);
	WRT_CHECK(is_wiped(&o, id));
	WRT_CHECK_U64((uint32_t)why.status, (uint32_t)st);
	WRT_CHECK(why.what != NULL);
	free(c);
}

/* ---- building pools ------------------------------------------------------------------------------ */

#define OPT_SNAPS 0x001u
#define OPT_REMOVED 0x002u
#define OPT_PROPS 0x004u
#define OPT_HITSET 0x008u
#define OPT_OPTS 0x010u
#define OPT_APPMETA 0x020u
#define OPT_TAIL 0x040u
#define OPT_PEERING 0x080u /* v30: stretch fields with a zero count; v31 up: the tuple present with a zero count */
#define OPT_VARINTS 0x100u /* v32: big varints in row 53 */
#define OPT_ALL 0x1ffu

/* A supported replicated pool whose every wire field has a value of its own. */
static void make_pool(wrt_mg_pool *p, uint8_t v, unsigned opt, uint32_t seed)
{
	wrt_mg_pool_init(p, v);
	p->size = (uint8_t)(1u + seed % 16u);
	p->min_size = (uint8_t)(1u + (seed >> 3) % 7u);
	p->crush_rule = (uint8_t)((seed * 37u) % 256u);
	p->object_hash = (seed & 1u) ? 1 : 2;
	p->pg_num = 1u + (seed * 2654435761u) % 5000u;
	p->pgp_num = 1u + (seed * 40503u) % 4000u;
	p->flags = 0x40000000000ull | ((uint64_t)(seed & 0xffu) << 20) | WRT_MG_POOL_HASHPSPOOL | ((seed & 2u) ? (1ull << 13) : 0u);
	p->pg_num_pending = 0x01000000u + seed;
	p->last_force_op_resend = 0x02000000u + seed * 3u;

	p->lpg_num = 11;
	p->lpgp_num = 12;
	p->last_change = 13;
	p->snap_seq = 0x1400000014ull;
	p->snap_epoch = 15;
	p->auid = 16;
	p->crash_replay_interval = 17;
	p->quota_max_bytes = 0x1200000012ull;
	p->quota_max_objects = 0x1300000013ull;
	p->cache_mode = 3;
	p->hit_set_period = 20;
	p->hit_set_count = 21;
	p->stripe_width = 22;
	p->target_max_bytes = 0x1700000017ull;
	p->target_max_objects = 0x1800000018ull;
	p->cache_target_dirty_ratio_micro = 25;
	p->cache_target_full_ratio_micro = 26;
	p->cache_min_flush_age = 27;
	p->cache_min_evict_age = 28;
	p->last_force_op_resend_preluminous = 29;
	p->min_read_recency_for_promote = 30;
	p->expected_num_objects = 0x1f0000001full;
	p->cache_target_dirty_high_ratio_micro = 32;
	p->min_write_recency_for_promote = 33;
	p->use_gmt_hitset = 1;
	p->fast_read = 1;
	p->hit_set_grade_decay_rate = 34;
	p->hit_set_search_last_n = 35;
	p->last_force_op_resend_prenautilus = 36;
	p->create_time.sec = 37;
	p->create_time.nsec = 38;
	p->pg_num_target = 39;
	p->pgp_num_target = 40;
	p->pg_num_dec_a = 41;
	p->pg_num_dec_b = 42;
	p->pg_autoscale_mode = 1;
	{
		unsigned i;

		for (i = 0; i < sizeof(p->merge_meta); i++)
			p->merge_meta[i] = (uint8_t)(0x30u + i);
	}

	if (opt & OPT_SNAPS) {
		wrt_mg_snap a, b;

		memset(&a, 0, sizeof(a));
		memset(&b, 0, sizeof(b));
		a.id = 1;
		a.stamp.sec = 5;
		snprintf(a.name, sizeof(a.name), "snap-one");
		b.id = 2;
		b.stamp.sec = 6;
		snprintf(b.name, sizeof(b.name), "second");
		WRT_MG_PUSH(p->snaps, wrt_mg_snap, a);
		WRT_MG_PUSH(p->snaps, wrt_mg_snap, b);
	}
	if (opt & OPT_REMOVED) {
		wrt_mg_iv a, b;

		a.start = 3;
		a.len = 4;
		b.start = 100;
		b.len = 1000;
		WRT_MG_PUSH(p->removed_snaps, wrt_mg_iv, a);
		WRT_MG_PUSH(p->removed_snaps, wrt_mg_iv, b);
	}
	if (opt & OPT_PROPS) {
		wrt_mg_kv a, b;

		memset(&a, 0, sizeof(a));
		memset(&b, 0, sizeof(b));
		snprintf(a.k, sizeof(a.k), "key-a");
		snprintf(a.v, sizeof(a.v), "value-a");
		snprintf(b.k, sizeof(b.k), "key-b");
		snprintf(b.v, sizeof(b.v), "value-b-longer");
		WRT_MG_PUSH(p->properties, wrt_mg_kv, a);
		WRT_MG_PUSH(p->properties, wrt_mg_kv, b);
	}
	if (opt & OPT_HITSET)
		p->hit_set_type = 2;
	if (opt & OPT_OPTS) {
		wrt_mg_opt a, b;

		a.key = 5;
		a.val = 1000;
		b.key = 9;
		b.val = -7;
		WRT_MG_PUSH(p->opts, wrt_mg_opt, a);
		WRT_MG_PUSH(p->opts, wrt_mg_opt, b);
	}
	if (opt & OPT_APPMETA) {
		wrt_mg_app a, b;
		wrt_mg_kv kv;

		memset(&a, 0, sizeof(a));
		memset(&b, 0, sizeof(b));
		snprintf(a.app, sizeof(a.app), "rbd");
		memset(&kv, 0, sizeof(kv));
		snprintf(kv.k, sizeof(kv.k), "image");
		snprintf(kv.v, sizeof(kv.v), "disk0");
		WRT_MG_PUSH(a.kv, wrt_mg_kv, kv);
		snprintf(b.app, sizeof(b.app), "rgw");
		WRT_MG_PUSH(p->application_metadata, wrt_mg_app, a);
		WRT_MG_PUSH(p->application_metadata, wrt_mg_app, b);
	}
	if (opt & OPT_TAIL)
		p->tail = 37;
	if (opt & OPT_PEERING) {
		if (v == 30) {
			p->stretch_count = 0;
			p->stretch_target = 3;
			p->stretch_barrier = 4;
			p->stretch_mandatory = 5;
		} else if (v >= 31) {
			p->peering_present = 1;
			p->peering_count = 0;
			p->peering_target = 3;
			p->peering_barrier = 4;
			p->peering_mandatory = 5;
		}
	}
	if ((opt & OPT_VARINTS) && v >= 32) {
		p->nonprimary_lo = 0xfedcba9876543210ull;
		p->nonprimary_hi = 0x0123456789abcdefull;
	}
}

/* Encode a pool (checked), returning the bytes in a malloc'd buffer. */
static uint8_t *encode_pool(const wrt_mg_pool *p, size_t *n)
{
	wrt_mg_buf b;
	uint8_t *out;

	memset(&b, 0, sizeof(b));
	if (wrt_mg_pool_encode(p, &b) != 0) {
		WRT_CHECK(0 && "wrt_mg_pool_encode failed");
		*n = 0;
		return xdup((const uint8_t *)"", 0);
	}
	out = xdup(b.p, b.len);
	*n = b.len;
	wrt_mg_buf_free(&b);
	return out;
}

/* ---- truncation points --------------------------------------------------------------------------- */

static void cut_tests(const uint8_t *enc, size_t n, const wrt_mg_pool *m, int64_t id)
{
	size_t body = n - 6u, rows_end, k;

	/* the envelope cut: the length says more than the buffer has (header cut: not even a length) */
	for (k = 0; k < n; k++) {
		uint8_t *c = xdup(enc, k);
		wri_rd r;
		wri_map_pool o;
		wr_errinfo why;
		wr_status st;

		memset(&why, 0, sizeof(why));
		dirty(&o, id);
		wri_rd_init(&r, c, k);
		st = wri_pool_decode(&r, &o, &why);
		WRT_CHECK_U64((uint32_t)st, (uint32_t)WR_E_TRUNCATED);
		WRT_CHECK_U64((uint32_t)r.err, (uint32_t)WR_E_TRUNCATED);
		WRT_CHECK(is_wiped(&o, id));
		WRT_CHECK_U64((uint32_t)why.status, (uint32_t)WR_E_TRUNCATED);
		wri_rd_init(&r, c, k);
		WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_pool_skip(&r, NULL));
		free(c);
	}
	if (m->v < 29)
		return;
	/* the end of the last row the decoder reads: row 52 (53 and up are jumped over, then the tail) */
	rows_end = body - m->tail - (m->v >= 32 ? varint_len(m->nonprimary_lo) + varint_len(m->nonprimary_hi) : 0u);
	/* the body cut: the length patched so the envelope is whole but the rows run out */
	for (k = 0; k < body; k++) {
		uint8_t *c = xdup(enc, 6u + k);
		wri_rd r, rs;
		wri_map_pool o;
		wr_errinfo why;
		wr_status st;

		put_u32(c + 2, (uint32_t)k);
		memset(&why, 0, sizeof(why));
		dirty(&o, id);
		wri_rd_init(&r, c, 6u + k);
		st = wri_pool_decode(&r, &o, &why);
		if (k < rows_end) {
			WRT_CHECK(st == WR_E_TRUNCATED || st == WR_E_TOOBIG);
			WRT_CHECK_U64((uint32_t)r.err, (uint32_t)st);
			WRT_CHECK(is_wiped(&o, id));
		} else {
			WRT_CHECK_U64((uint32_t)st, (uint32_t)WR_OK);
			WRT_CHECK_U64(r.pos, 6u + k);
			check_kept(&o, m, id);
		}
		/* skip never looks inside */
		wri_rd_init(&rs, c, 6u + k);
		WRT_CHECK_STATUS(WR_OK, wri_pool_skip(&rs, NULL));
		WRT_CHECK_U64(rs.pos, 6u + k);
		free(c);
	}
}

/* ---- mutations ------------------------------------------------------------------------------------ */

/* Whatever the bytes, the result is a clean failure or a decode that ends on the envelope end; skip agrees. */
static void mutant(const uint8_t *buf, size_t n)
{
	uint8_t *c = xdup(buf, n);
	wri_rd r, rs;
	wri_map_pool o;
	wr_errinfo why;
	wr_status st, ss;

	memset(&why, 0, sizeof(why));
	dirty(&o, 7);
	wri_rd_init(&r, c, n);
	st = wri_pool_decode(&r, &o, &why);
	wri_rd_init(&rs, c, n);
	ss = wri_pool_skip(&rs, NULL);
	if (st == WR_OK) {
		WRT_CHECK_U64(r.err, WR_OK);
		WRT_CHECK(ss == WR_OK);
		WRT_CHECK_U64(r.pos, rs.pos);
		WRT_CHECK(r.pos >= 6u && r.pos <= n);
		WRT_CHECK_U64(o.present, 1);
		WRT_CHECK_U64(o.id, 7);
		WRT_CHECK_U64(o.pg_num_mask, mask_ref(o.pg_num));
		WRT_CHECK_U64(o.pgp_num_mask, mask_ref(o.pgp_num));
	} else {
		WRT_CHECK_U64((uint32_t)r.err, (uint32_t)st);
		WRT_CHECK(is_wiped(&o, 7));
		WRT_CHECK(why.what != NULL);
		if (st != WR_E_MAP_VERSION && st != WR_E_TRUNCATED) {
			/* a failure inside the body, so the envelope itself was whole: skip steps over it */
			WRT_CHECK(ss == WR_OK);
			WRT_CHECK(rs.pos >= 6u && rs.pos <= n);
		}
	}
	free(c);
}

static void mutation_tests(void)
{
	static const unsigned opts[] = {0, OPT_ALL, OPT_SNAPS | OPT_REMOVED | OPT_PROPS, OPT_HITSET | OPT_OPTS | OPT_APPMETA | OPT_TAIL};
	unsigned vi, oi;
	uint32_t it;

	for (vi = 29; vi <= 32; vi++) {
		for (oi = 0; oi < sizeof(opts) / sizeof(opts[0]); oi++) {
			wrt_mg_pool p;
			size_t n, i, j;
			uint8_t *enc;
			static const uint8_t vals[] = {0x00, 0x01, 0x02, 0x7f, 0x80, 0xfe, 0xff};

			make_pool(&p, (uint8_t)vi, opts[oi], vi * 7u + oi);
			enc = encode_pool(&p, &n);
			for (i = 0; i < n; i++) {
				uint8_t *m = xdup(enc, n);

				for (j = 0; j < sizeof(vals); j++) {
					m[i] = vals[j];
					mutant(m, n);
				}
				m[i] = (uint8_t)(enc[i] ^ 0x55u);
				mutant(m, n);
				free(m);
			}
			/* the whole header: every struct_v and every struct_compat (5 .. 255 and 0 .. 255) with the rest as it is.
			 * A pool record always has its two header bytes; the guard also tells gcc so (-Wstringop-overflow). */
			WRT_CHECK(n >= 2);
			for (j = 0; n >= 2 && j < 256; j++) {
				uint8_t *m = xdup(enc, n);

				m[0] = (uint8_t)j;
				mutant(m, n);
				m[0] = enc[0];
				m[1] = (uint8_t)j;
				mutant(m, n);
				free(m);
			}
			/* every 32-bit window set to 0, to 0xffffffff, to the bytes left after it plus one and to the bytes left
			 * itself: every count and every length of the record takes each of them, and a count or a length that is
			 * one too many must fail while one that is exactly right may succeed */
			for (i = 0; i + 4u <= n; i++) {
				uint8_t *m = xdup(enc, n);
				uint32_t left = (uint32_t)(n - (i + 4u));

				put_u32(m + i, 0);
				mutant(m, n);
				put_u32(m + i, 0xffffffffu);
				mutant(m, n);
				put_u32(m + i, left + 1u);
				mutant(m, n);
				put_u32(m + i, left);
				mutant(m, n);
				free(m);
			}
			/* random multi-byte damage, plus a random cut of the buffer */
			for (it = 0; it < 300; it++) {
				uint8_t *m = xdup(enc, n);
				uint32_t flips = 1u + rnd() % 4u;
				size_t cutn = n;

				while (flips-- != 0)
					m[rnd() % n] = (uint8_t)rnd();
				if ((rnd() & 7u) == 0)
					cutn = rnd() % (n + 1u);
				mutant(m, cutn);
				free(m);
			}
			free(enc);
			wrt_mg_pool_free(&p);
		}
	}
}

/*
 * The reads of a pool are bounded by its own struct_len, not by the buffer: the length is patched to k while the rest of
 * the record (and 64 bytes of other data) is still in the buffer behind it. Where the rows run out inside k the decode
 * must fail exactly as it does on a buffer that ends at k, and where it succeeds it must stop at 6 + k, never at the
 * old end. (With an exact-size buffer an over-read would show up under AddressSanitizer; here the bytes exist, so only the
 * status can tell.) The same for a nested envelope that claims more than the pool body holds.
 */
static void in_place_cut_tests(const uint8_t *enc, size_t n, const wrt_mg_pool *m, int64_t id)
{
	size_t body, rows_end, k;
	uint8_t *big;

	if (n < 6u || n > ((size_t)1 << 20)) /* also tells the optimiser the size is sane (a false overflow warning otherwise) */
		return;
	body = n - 6u;
	big = (uint8_t *)malloc(n + 64u);
	if (big == NULL)
		exit(2);
	rows_end = body - m->tail - (m->v >= 32 ? varint_len(m->nonprimary_lo) + varint_len(m->nonprimary_hi) : 0u);
	for (k = 0; k < body; k++) {
		uint8_t *c;
		wri_rd r;
		wri_map_pool o;
		wr_status st;

		memcpy(big, enc, n);
		memset(big + n, 0xA5, 64u);
		put_u32(big + 2, (uint32_t)k);
		c = xdup(big, n + 64u);
		dirty(&o, id);
		wri_rd_init(&r, c, n + 64u);
		st = wri_pool_decode(&r, &o, NULL);
		if (k < rows_end) {
			WRT_CHECK(st == WR_E_TRUNCATED || st == WR_E_TOOBIG);
			WRT_CHECK(is_wiped(&o, id));
		} else {
			WRT_CHECK_U64((uint32_t)st, (uint32_t)WR_OK);
			WRT_CHECK_U64(r.pos, 6u + k);
		}
		free(c);
	}
	free(big);
}

/* ---- tests --------------------------------------------------------------------------------------- */

static void test_combinations(void)
{
	unsigned v, opt;
	uint32_t seed = 1;

	for (v = 29; v <= 32; v++) {
		for (opt = 0; opt <= OPT_ALL; opt++) {
			wrt_mg_pool p;
			size_t n;
			uint8_t *enc;

			make_pool(&p, (uint8_t)v, opt, seed++);
			enc = encode_pool(&p, &n);
			check_one(enc, n, &p, (int64_t)(seed % 1000u), 0);
			check_one(enc, n, &p, (int64_t)(seed % 1000u), 11); /* bytes after the record are not touched */
			if (opt == 0 || opt == OPT_ALL || opt == (OPT_TAIL | OPT_PEERING) || opt == (OPT_VARINTS | OPT_SNAPS)) {
				cut_tests(enc, n, &p, 3);
				in_place_cut_tests(enc, n, &p, 3);
			}
			free(enc);
			wrt_mg_pool_free(&p);
		}
	}
}

static void test_newer_versions(void)
{
	static const uint8_t vers[] = {33, 34, 40, 255};
	unsigned i, opt;

	for (i = 0; i < sizeof(vers); i++) {
		for (opt = 0; opt <= OPT_ALL; opt += 1u + (opt & 0x7u)) {
			wrt_mg_pool p;
			size_t n, k;
			uint8_t *enc, *grown;

			/* v33 and up: the rows of 31 and 32 are written as for v32, then a tail of rows we do not know */
			make_pool(&p, vers[i], opt | OPT_TAIL, 100u + i);
			p.tail = 200;
			enc = encode_pool(&p, &n);
			check_one(enc, n, &p, 2, 0);
			check_one(enc, n, &p, 2, 5);
			cut_tests(enc, n, &p, 2);
			in_place_cut_tests(enc, n, &p, 2);
			/* the same with the bytes of the unknown rows non-zero */
			grown = xdup(enc, n);
			for (k = n - p.tail; k < n; k++)
				grown[k] = (uint8_t)(0x80u + k);
			check_one(grown, n, &p, 2, 0);
			free(grown);
			free(enc);
			wrt_mg_pool_free(&p);
		}
	}
}

static void test_flags_not_refusals(void)
{
	static const int shapes[] = {WRT_MG_SHAPE_POOL_SNAPS, WRT_MG_SHAPE_EIO, WRT_MG_SHAPE_LINUX_HASH, WRT_MG_SHAPE_NO_HASHPSPOOL};
	unsigned v, i;

	for (v = 29; v <= 32; v++) {
		for (i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
			wrt_mg_pool p;
			size_t n;
			uint8_t *enc;
			wri_rd r;
			wri_map_pool o;
			wr_errinfo why;

			dirty(&o, 4);
			make_pool(&p, (uint8_t)v, OPT_SNAPS | OPT_APPMETA, v + i);
			wrt_mg_pool_shape(&p, shapes[i]);
			enc = encode_pool(&p, &n);
			WRT_CHECK(!unsupported_ref(&p, 4));
			check_one(enc, n, &p, 4, 0);
			memset(&why, 0, sizeof(why));
			wri_rd_init(&r, enc, n);
			WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, &why));
			WRT_CHECK_U64(o.status, WR_OK);
			WRT_CHECK_U64(why.status, WR_OK);
			if (shapes[i] == WRT_MG_SHAPE_POOL_SNAPS)
				WRT_CHECK((o.flags & WRI_POOL_F_POOL_SNAPS) != 0);
			if (shapes[i] == WRT_MG_SHAPE_EIO)
				WRT_CHECK((o.flags & WRI_POOL_F_EIO) != 0);
			if (shapes[i] == WRT_MG_SHAPE_LINUX_HASH)
				WRT_CHECK_U64(o.object_hash, WRI_STR_HASH_LINUX);
			if (shapes[i] == WRT_MG_SHAPE_NO_HASHPSPOOL)
				WRT_CHECK((o.flags & WRI_POOL_F_HASHPSPOOL) == 0);
			free(enc);
			wrt_mg_pool_free(&p);
		}
	}
}

typedef struct shape_case {
	int shape;
	const char *name;
	uint8_t v_fixed; /* 0 = any of 29..32 */
	int check_a0;    /* what errinfo.a0 should be, when non-negative */
} shape_case;

static void test_unsupported_shapes(void)
{
	static const shape_case cases[] = {
		{WRT_MG_SHAPE_STRETCH, "stretch v30", 30, 2},
		{WRT_MG_SHAPE_STRETCH_V31, "stretch v31", 31, 2},
		{WRT_MG_SHAPE_ERASURE, "erasure", 0, 3},
		{WRT_MG_SHAPE_TIER_OF, "tier_of", 0, 5},
		{WRT_MG_SHAPE_TIERS, "tiers", 0, -1},
		{WRT_MG_SHAPE_READ_TIER, "read_tier", 0, 9},
		{WRT_MG_SHAPE_WRITE_TIER, "write_tier", 0, 9},
		{WRT_MG_SHAPE_EC_PROFILE, "ec profile", 0, -1},
		{WRT_MG_SHAPE_HASH3, "hash 3", 0, 3},
		{WRT_MG_SHAPE_SIZE0, "size 0", 0, 0},
		{WRT_MG_SHAPE_SIZE17, "size 17", 0, 17},
		{WRT_MG_SHAPE_PGNUM0, "pg_num 0", 0, -1},
		{WRT_MG_SHAPE_PGPNUM0, "pgp_num 0", 0, -1},
	};
	enum { NCASES = sizeof(cases) / sizeof(cases[0]) };
	const char *reason[NCASES];
	unsigned c, v, opt, d;

	memset((void *)reason, 0, sizeof(reason));
	for (c = 0; c < NCASES; c++) {
		for (v = 29; v <= 32; v++) {
			if (cases[c].v_fixed != 0 && cases[c].v_fixed != v)
				continue;
			for (opt = 0; opt < 3; opt++) {
				wrt_mg_pool p;
				size_t n;
				uint8_t *enc;
				wri_rd r;
				wri_map_pool o;
				wr_errinfo why;

				make_pool(&p, (uint8_t)v, opt == 0 ? 0u : OPT_ALL, v + c);
				if (opt == 2)
					p.tail = 9;
				wrt_mg_pool_shape(&p, cases[c].shape);
				enc = encode_pool(&p, &n);
				WRT_CHECK(unsupported_ref(&p, 6));
				check_one(enc, n, &p, 6, 0);

				memset(&why, 0, sizeof(why));
				dirty(&o, 6);
				wri_rd_init(&r, enc, n);
				WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, &why)); /* never a failure */
				WRT_CHECK_U64(o.status, WR_E_POOL_UNSUPPORTED);
				WRT_CHECK_U64(o.present, 1);
				WRT_CHECK_U64(why.status, WR_E_POOL_UNSUPPORTED);
				WRT_CHECK_U64(why.module, WR_MOD_MAP);
				WRT_CHECK_U64(r.pos, n);
				if (cases[c].check_a0 >= 0)
					WRT_CHECK_U64(why.a0, (uint64_t)cases[c].check_a0);
				if (cases[c].shape == WRT_MG_SHAPE_ERASURE) {
					WRT_CHECK_U64(o.type, 3);
					WRT_CHECK_U64(o.size, 6);
				}
				if (opt == 0 && v == (cases[c].v_fixed != 0 ? cases[c].v_fixed : 32u))
					reason[c] = why.what;
				free(enc);
				wrt_mg_pool_free(&p);
			}
		}
	}
	/* each shape has a reason of its own, except the pairs that are one rule (stretch in v30 and v31, size 0 and 17) */
	for (c = 0; c < NCASES; c++) {
		WRT_CHECK(reason[c] != NULL);
		for (d = c + 1; d < NCASES; d++) {
			int same_rule = (cases[c].shape == WRT_MG_SHAPE_STRETCH && cases[d].shape == WRT_MG_SHAPE_STRETCH_V31) ||
					(cases[c].shape == WRT_MG_SHAPE_SIZE0 && cases[d].shape == WRT_MG_SHAPE_SIZE17);

			if (reason[c] != NULL && reason[d] != NULL)
				WRT_CHECK((strcmp(reason[c], reason[d]) == 0) == same_rule);
		}
	}
}

static void test_zero_counts_are_supported(void)
{
	unsigned v;

	/* a stretch field block with a zero bucket count (v30) or an empty / zero tuple (v31 and up) is an ordinary pool */
	for (v = 30; v <= 32; v++) {
		wrt_mg_pool p;
		size_t n;
		uint8_t *enc;

		make_pool(&p, (uint8_t)v, OPT_PEERING, v);
		enc = encode_pool(&p, &n);
		WRT_CHECK(!unsupported_ref(&p, 1));
		check_one(enc, n, &p, 1, 0);
		free(enc);
		wrt_mg_pool_free(&p);
	}
	/* the largest replica count that is still served, the smallest, and both hashes */
	{
		static const uint8_t sizes[] = {1, 2, 15, 16};
		unsigned i;

		for (i = 0; i < sizeof(sizes); i++) {
			wrt_mg_pool p;
			size_t n;
			uint8_t *enc;

			make_pool(&p, 32, 0, 3);
			p.size = sizes[i];
			p.object_hash = (uint8_t)(1u + (i & 1u));
			enc = encode_pool(&p, &n);
			check_one(enc, n, &p, 1, 0);
			free(enc);
			wrt_mg_pool_free(&p);
		}
	}
}

static void test_ids(void)
{
	static const int64_t ids[] = {0, 1, 12345, 0x7ffffffe, 0x7fffffff, 0x80000000ll, 0x80000001ll, 0xffffffffll,
				      0x100000000ll, INT64_MAX, -1, INT64_MIN};
	unsigned i, v;

	for (v = 29; v <= 32; v++) {
		for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
			wrt_mg_pool p;
			size_t n;
			uint8_t *enc;
			wri_rd r;
			wri_map_pool o;
			wr_errinfo why;

			make_pool(&p, (uint8_t)v, OPT_SNAPS, v);
			enc = encode_pool(&p, &n);
			check_one(enc, n, &p, ids[i], 0);
			memset(&why, 0, sizeof(why));
			dirty(&o, ids[i]);
			wri_rd_init(&r, enc, n);
			WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, &why));
			WRT_CHECK_U64(o.id, ids[i]); /* the caller's id is kept */
			if (ids[i] >= 0 && ids[i] < 0x80000000ll) {
				WRT_CHECK_U64(o.status, WR_OK);
			} else {
				WRT_CHECK_U64(o.status, WR_E_POOL_UNSUPPORTED);
				WRT_CHECK_U64(why.a0, (uint64_t)ids[i]);
				WRT_CHECK_U64(o.pg_num, p.pg_num); /* the rows are still read */
			}
			free(enc);
			wrt_mg_pool_free(&p);
		}
	}
}

static void test_old_versions(void)
{
	unsigned v;

	/* mapgen writes the rows of its own struct_v from 19 up: 19 .. 28 are stepped over and refused */
	for (v = 19; v <= 28; v++) {
		wrt_mg_pool p;
		size_t n;
		uint8_t *enc;

		make_pool(&p, (uint8_t)v, OPT_SNAPS | (v >= 26 ? OPT_APPMETA : 0u) | OPT_TAIL, v); /* the model frees app metadata from v26 */
		enc = encode_pool(&p, &n);
		check_one(enc, n, &p, 5, 0);
		cut_tests(enc, n, &p, 5);
		free(enc);
		wrt_mg_pool_free(&p);
	}
	/* hand-made envelopes: any struct_v from 5, any body */
	for (v = 5; v <= 28; v++) {
		uint8_t hdr[6 + 40];
		wri_rd r, rs;
		wri_map_pool o;
		wr_errinfo why;
		size_t i;

		hdr[0] = (uint8_t)v;
		hdr[1] = 5;
		put_u32(hdr + 2, 40);
		for (i = 0; i < 40; i++)
			hdr[6 + i] = (uint8_t)(0xA0u + i);
		{
			uint8_t *c = xdup(hdr, sizeof(hdr));

			memset(&why, 0, sizeof(why));
			dirty(&o, 3);
			wri_rd_init(&r, c, sizeof(hdr));
			WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, &why));
			WRT_CHECK_U64(r.pos, sizeof(hdr));
			WRT_CHECK_U64(o.status, WR_E_POOL_UNSUPPORTED);
			WRT_CHECK_U64(o.present, 1);
			WRT_CHECK_U64(why.status, WR_E_POOL_UNSUPPORTED);
			WRT_CHECK_U64(why.a0, v);
			WRT_CHECK_U64(why.a1, 29);
			wri_rd_init(&rs, c, sizeof(hdr));
			WRT_CHECK_STATUS(WR_OK, wri_pool_skip(&rs, NULL));
			WRT_CHECK_U64(rs.pos, sizeof(hdr));
			free(c);
		}
	}
	/* below 5 the record has no length to skip by */
	for (v = 0; v < 5; v++) {
		uint8_t hdr[6 + 8];
		uint8_t *c;
		wri_rd rs;

		memset(hdr, 0, sizeof(hdr));
		hdr[0] = (uint8_t)v;
		hdr[1] = 5;
		put_u32(hdr + 2, 8);
		c = xdup(hdr, sizeof(hdr));
		check_fails(c, sizeof(hdr), 3, WR_E_MAP_VERSION);
		wri_rd_init(&rs, c, sizeof(hdr));
		WRT_CHECK_STATUS(WR_E_MAP_VERSION, wri_pool_skip(&rs, NULL));
		free(c);
	}
}

static void test_compat(void)
{
	static const uint8_t compats[] = {0, 1, 5, 31, 32, 33, 34, 100, 255};
	unsigned i, v;

	for (v = 29; v <= 32; v++) {
		for (i = 0; i < sizeof(compats); i++) {
			wrt_mg_pool p;
			size_t n;
			uint8_t *enc;
			wri_rd rs;

			make_pool(&p, (uint8_t)v, OPT_SNAPS, v);
			p.compat = compats[i];
			enc = encode_pool(&p, &n);
			if (compats[i] <= 32) {
				check_one(enc, n, &p, 8, 0);
			} else {
				check_fails(enc, n, 8, WR_E_MAP_VERSION);
				/* a record that is only skipped is never interpreted: any compat steps over */
				wri_rd_init(&rs, enc, n);
				WRT_CHECK_STATUS(WR_OK, wri_pool_skip(&rs, NULL));
				WRT_CHECK_U64(rs.pos, n);
			}
			free(enc);
			wrt_mg_pool_free(&p);
		}
	}
	/* compat is judged before the length: a hostile length with a compat above 32 is a version error, not a truncation */
	{
		uint8_t hdr[6] = {32, 33, 0xff, 0xff, 0xff, 0xff};

		check_fails(hdr, sizeof(hdr), 1, WR_E_MAP_VERSION);
	}
}

static void test_types_and_tier_zero(void)
{
	static const uint8_t types[] = {0, 2, 3, 4, 5, 128, 255};
	unsigned v, i;

	for (v = 29; v <= 32; v++) {
		for (i = 0; i < sizeof(types); i++) {
			wrt_mg_pool p;
			size_t n;
			uint8_t *enc;

			make_pool(&p, (uint8_t)v, OPT_SNAPS, v + i);
			p.type = types[i]; /* anything but 1 (replicated) is refused, not only 3 */
			enc = encode_pool(&p, &n);
			WRT_CHECK(unsupported_ref(&p, 1));
			check_one(enc, n, &p, 1, 0);
			free(enc);
			wrt_mg_pool_free(&p);
		}
		/* pool 0 is a real pool id: a tier field of 0 names it, and only a negative value means "none" */
		for (i = 0; i < 6; i++) {
			wrt_mg_pool p;
			size_t n;
			uint8_t *enc;
			wri_rd r;
			wri_map_pool o;

			make_pool(&p, (uint8_t)v, 0, v);
			if (i == 0)
				p.tier_of = 0;
			else if (i == 1)
				p.read_tier = 0;
			else if (i == 2)
				p.write_tier = 0;
			else if (i == 3)
				p.tier_of = INT64_MAX;
			else if (i == 4)
				p.read_tier = -2; /* any negative value is "none" */
			else
				p.write_tier = INT64_MIN;
			enc = encode_pool(&p, &n);
			WRT_CHECK(unsupported_ref(&p, 1) == (i <= 3));
			check_one(enc, n, &p, 1, 0);
			dirty(&o, 1);
			wri_rd_init(&r, enc, n);
			WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, NULL));
			WRT_CHECK_U64(o.status, i <= 3 ? WR_E_POOL_UNSUPPORTED : WR_OK);
			free(enc);
			wrt_mg_pool_free(&p);
		}
	}
	/* the optional tuple of v31 and up is a bool on the wire: any non-zero byte means "present" */
	for (v = 31; v <= 32; v++) {
		for (i = 0; i < 4; i++) {
			wrt_mg_pool p;
			size_t n;
			uint8_t *enc;

			make_pool(&p, (uint8_t)v, OPT_PEERING, v);
			p.peering_present = (uint8_t)(i == 0 ? 2 : i == 1 ? 255 : 1);
			p.peering_count = i == 3 ? 4 : (i == 2 ? 0 : 2);
			enc = encode_pool(&p, &n);
			WRT_CHECK(unsupported_ref(&p, 1) == (p.peering_count != 0));
			check_one(enc, n, &p, 1, 0);
			free(enc);
			wrt_mg_pool_free(&p);
		}
	}
}

static void test_hostile(void)
{
	wrt_mg_pool p;
	size_t n;
	uint8_t *enc;

	make_pool(&p, 32, OPT_SNAPS | OPT_APPMETA, 9);
	enc = encode_pool(&p, &n);

	/* struct_len larger than the buffer */
	{
		uint8_t *c = xdup(enc, n);

		put_u32(c + 2, 0xffffffffu);
		check_fails(c, n, 1, WR_E_TRUNCATED);
		put_u32(c + 2, (uint32_t)(n - 5u));
		check_fails(c, n, 1, WR_E_TRUNCATED);
		free(c);
	}
	/* snaps count 0xFFFFFFFF (body offset 36, wire offset 42): refused against the bytes left, quickly */
	{
		uint8_t *c = xdup(enc, n);

		put_u32(c + 42, 0xffffffffu);
		check_fails(c, n, 1, WR_E_TOOBIG);
		put_u32(c + 42, 1000000u);
		check_fails(c, n, 1, WR_E_TOOBIG);
		free(c);
	}
	/* tiers count (body offset 81, wire offset 87 for a pool without snapshots) that fits 4 bytes per element but not 8 */
	{
		wrt_mg_pool q;
		size_t qn;
		uint8_t *qe;

		make_pool(&q, 32, 0, 9);
		qe = encode_pool(&q, &qn);
		put_u32(qe + 87, (uint32_t)((qn - 91u) / 6u));
		check_fails(qe, qn, 1, WR_E_TOOBIG);
		put_u32(qe + 87, 0xffffffffu);
		check_fails(qe, qn, 1, WR_E_TOOBIG);
		put_u32(qe + 87, 0);
		check_one(qe, qn, &q, 1, 0); /* and the original value still decodes */
		free(qe);
		wrt_mg_pool_free(&q);
	}
	/* an empty pool with a body shorter than the rows */
	{
		uint8_t hdr[6 + 3] = {32, 5, 3, 0, 0, 0, 1, 3, 0};

		check_fails(hdr, sizeof(hdr), 1, WR_E_TRUNCATED);
	}
	/* a newer struct_v with a body too short for the rows it must at least have */
	{
		uint8_t hdr[6 + 3] = {200, 5, 3, 0, 0, 0, 1, 3, 0};

		check_fails(hdr, sizeof(hdr), 1, WR_E_TRUNCATED);
	}
	free(enc);
	wrt_mg_pool_free(&p);
}

static void test_masks(void)
{
	static const struct {
		uint32_t n, mask;
	} cases[] = {{1, 0},       {2, 1},         {3, 3},         {4, 3},          {5, 7},        {12, 15},
		     {100, 127},   {128, 127},     {129, 255},     {1000, 1023},    {4096, 4095},  {0x40000000u, 0x3fffffffu},
		     {0x40000001u, 0x7fffffffu},   {0x80000000u, 0x7fffffffu},      {0x80000001u, 0xffffffffu}, {0xffffffffu, 0xffffffffu}};
	unsigned i, v;

	for (v = 29; v <= 32; v++) {
		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			wrt_mg_pool p;
			size_t n;
			uint8_t *enc;
			wri_rd r;
			wri_map_pool o;

			dirty(&o, 1);
			make_pool(&p, (uint8_t)v, 0, 1);
			p.pg_num = cases[i].n;
			p.pgp_num = cases[cases[i].n % 16u].n; /* an unrelated value: the two masks are independent */
			enc = encode_pool(&p, &n);
			wri_rd_init(&r, enc, n);
			WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, NULL));
			WRT_CHECK_U64(o.pg_num, cases[i].n);
			WRT_CHECK_U64(o.pg_num_mask, cases[i].mask);
			WRT_CHECK_U64(o.pgp_num, p.pgp_num);
			WRT_CHECK_U64(o.pgp_num_mask, mask_ref(p.pgp_num));
			free(enc);
			wrt_mg_pool_free(&p);

			/* and the other way round: pgp_num carries the case */
			make_pool(&p, (uint8_t)v, 0, 1);
			p.pgp_num = cases[i].n;
			enc = encode_pool(&p, &n);
			wri_rd_init(&r, enc, n);
			WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, NULL));
			WRT_CHECK_U64(o.pgp_num_mask, cases[i].mask);
			WRT_CHECK_U64(o.pg_num_mask, mask_ref(p.pg_num));
			free(enc);
			wrt_mg_pool_free(&p);
		}
	}
	/* pg_num 0 has no mask (0), the pool is unsupported */
	{
		wrt_mg_pool p;
		size_t n;
		uint8_t *enc;
		wri_rd r;
		wri_map_pool o;

		dirty(&o, 1);
		make_pool(&p, 32, 0, 1);
		p.pg_num = 0;
		enc = encode_pool(&p, &n);
		wri_rd_init(&r, enc, n);
		WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, NULL));
		WRT_CHECK_U64(o.pg_num_mask, 0);
		WRT_CHECK_U64(o.status, WR_E_POOL_UNSUPPORTED);
		free(enc);
		wrt_mg_pool_free(&p);
	}
}

static void test_back_to_back(void)
{
	/* three records one after another: decode, skip, decode, every one ends on the next one's start */
	wrt_mg_pool a, b, c;
	size_t na, nb, nc;
	uint8_t *ea, *eb, *ec, *all;
	wri_rd r;
	wri_map_pool o;

	make_pool(&a, 32, OPT_ALL, 1);
	make_pool(&b, 30, OPT_SNAPS, 2);
	make_pool(&c, 29, OPT_APPMETA | OPT_TAIL, 3);
	ea = encode_pool(&a, &na);
	eb = encode_pool(&b, &nb);
	ec = encode_pool(&c, &nc);
	all = (uint8_t *)malloc(na + nb + nc);
	memcpy(all, ea, na);
	memcpy(all + na, eb, nb);
	memcpy(all + na + nb, ec, nc);
	{
		uint8_t *exact = xdup(all, na + nb + nc);

		free(all);
		all = exact;
	}
	wri_rd_init(&r, all, na + nb + nc);
	dirty(&o, 1);
	WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, NULL));
	WRT_CHECK_U64(r.pos, na);
	check_kept(&o, &a, 1);
	WRT_CHECK_STATUS(WR_OK, wri_pool_skip(&r, NULL));
	WRT_CHECK_U64(r.pos, na + nb);
	dirty(&o, 3);
	WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, NULL));
	WRT_CHECK_U64(r.pos, na + nb + nc);
	check_kept(&o, &c, 3);
	WRT_CHECK_U64(wri_rd_left(&r), 0);
	free(all);
	free(ea);
	free(eb);
	free(ec);
	wrt_mg_pool_free(&a);
	wrt_mg_pool_free(&b);
	wrt_mg_pool_free(&c);
}

static void test_errinfo_and_args(void)
{
	wrt_mg_pool p;
	size_t n;
	uint8_t *enc;
	wri_rd r;
	wri_map_pool o;
	wr_errinfo why;

	make_pool(&p, 32, 0, 1);
	p.size = 17;
	enc = encode_pool(&p, &n);

	/* first failure wins: an errinfo that already holds a reason keeps it, the pool still reports its status */
	memset(&why, 0, sizeof(why));
	why.status = WR_E_MAP_CRC;
	why.what = "earlier";
	dirty(&o, 1);
	wri_rd_init(&r, enc, n);
	WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, &why));
	WRT_CHECK_U64(o.status, WR_E_POOL_UNSUPPORTED);
	WRT_CHECK_U64(why.status, WR_E_MAP_CRC);
	WRT_CHECK(strcmp(why.what, "earlier") == 0);

	/* a NULL errinfo is fine, for a usable pool, an unsupported one and a failure */
	dirty(&o, 1);
	wri_rd_init(&r, enc, n);
	WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, NULL));
	WRT_CHECK_STATUS(WR_OK, wri_pool_skip(&(wri_rd){enc, n, 0, WR_OK}, NULL));
	{
		uint8_t *c = xdup(enc, n - 1u);

		dirty(&o, 1);
		wri_rd_init(&r, c, n - 1u);
		WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_pool_decode(&r, &o, NULL));
		free(c);
	}

	/* NULL arguments */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pool_decode(NULL, &o, &why));
	wri_rd_init(&r, enc, n);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pool_decode(&r, NULL, &why));
	WRT_CHECK_U64(r.err, WR_E_INVAL);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pool_skip(NULL, &why));

	/* a reader that already failed gives its error back, nothing is read, the destination is wiped */
	wri_rd_init(&r, enc, n);
	wri_rd_fail(&r, WR_E_TRUNCATED);
	memset(&why, 0, sizeof(why));
	dirty(&o, 77);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_pool_decode(&r, &o, &why));
	WRT_CHECK(is_wiped(&o, 77));
	WRT_CHECK_U64(r.pos, 0);
	wri_rd_init(&r, enc, n);
	wri_rd_fail(&r, WR_E_ENCODING);
	WRT_CHECK_STATUS(WR_E_ENCODING, wri_pool_skip(&r, NULL));

	/* an empty buffer */
	wri_rd_init(&r, NULL, 0);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_pool_decode(&r, &o, NULL));
	wri_rd_init(&r, NULL, 0);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_pool_skip(&r, NULL));

	free(enc);
	wrt_mg_pool_free(&p);
}

/* ---- real maps ------------------------------------------------------------------------------------ */

typedef struct found_pool {
	int64_t id;
	size_t off, end; /* the record in the map buffer */
} found_pool;

/* Locate the pool records of a full map: wrapper (legacy 7), client block, fsid / epoch / created / modified, the pools map. */
static unsigned find_pools(const uint8_t *map, size_t n, found_pool *out, unsigned max)
{
	wri_rd r;
	wri_env wrap, cb;
	uint32_t np, i;

	wri_rd_init(&r, map, n);
	if (wri_env_open_legacy(&r, 7, 7, 7, 8, &wrap) != WR_OK || wri_env_open(&wrap.body, 10, &cb) != WR_OK) {
		WRT_CHECK(0 && "cannot open the map envelopes");
		return 0;
	}
	wri_rd_skip(&cb.body, 16u + 4u + 8u + 8u);
	np = wri_denc_count(&cb.body, 0xFFFFFFFFu, 8u + 6u);
	WRT_CHECK(wri_rd_ok(&cb.body) && np <= max);
	if (!wri_rd_ok(&cb.body) || np > max)
		return 0;
	for (i = 0; i < np; i++) {
		out[i].id = (int64_t)wri_rd_u64(&cb.body);
		out[i].off = (size_t)(cb.body.p - map) + cb.body.pos;
		WRT_CHECK_STATUS(WR_OK, wri_pool_skip(&cb.body, NULL));
		out[i].end = (size_t)(cb.body.p - map) + cb.body.pos;
	}
	return np;
}

static int load_hex_vec(const char *rel, uint8_t **out, size_t *n)
{
	return wrt_mg_load_hex_file(wrt_vec_path(rel), out, n);
}

static int64_t jint(const wrt_json *j, wrt_tok obj, const char *key)
{
	int ok = 0;
	int64_t v = wrt_json_int(j, wrt_json_get(j, obj, key), &ok);

	WRT_CHECK(ok);
	return v;
}

static void test_e42(void)
{
	uint8_t *map;
	size_t mapn, i;
	found_pool fp[4];
	unsigned np;
	wrt_json j;
	wrt_tok pools;

	if (load_hex_vec("osdmap/full-e42.hex", &map, &mapn) != 0) {
		WRT_CHECK(0 && "cannot load osdmap/full-e42.hex");
		return;
	}
	if (wrt_json_load_vec(&j, "osdmap/expected.json") != 0) {
		WRT_CHECK(0 && "cannot load osdmap/expected.json");
		free(map);
		return;
	}
	pools = wrt_json_get(&j, wrt_json_get(&j, wrt_json_get(&j, wrt_json_root(&j), "full_e42"), "state"), "pools");
	WRT_CHECK(pools != WRT_NONE);
	np = find_pools(map, mapn, fp, 4);
	WRT_CHECK_U64(np, 2);
	WRT_CHECK_U64(wrt_json_count(&j, pools), 2);
	for (i = 0; i < np; i++) {
		char key[24];
		wrt_tok t;
		wri_rd r;
		wri_map_pool o;
		wr_errinfo why;

		snprintf(key, sizeof(key), "%d", (int)fp[i].id);
		t = wrt_json_get(&j, pools, key);
		WRT_CHECK(t != WRT_NONE);
		if (t == WRT_NONE)
			continue;
		memset(&why, 0, sizeof(why));
		dirty(&o, fp[i].id);
		wri_rd_init(&r, map, mapn);
		r.pos = fp[i].off;
		WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, &why));
		WRT_CHECK_U64(r.pos, fp[i].end);
		WRT_CHECK_U64(o.id, fp[i].id);
		WRT_CHECK_U64(o.status, WR_OK);
		WRT_CHECK_U64(why.status, WR_OK);
		WRT_CHECK_U64(o.present, 1);
		WRT_CHECK_U64(o.type, jint(&j, t, "type"));
		WRT_CHECK_U64(o.size, jint(&j, t, "size"));
		WRT_CHECK_U64(o.min_size, jint(&j, t, "min_size"));
		WRT_CHECK_U64(o.crush_rule, jint(&j, t, "crush_rule"));
		WRT_CHECK_U64(o.object_hash, jint(&j, t, "object_hash"));
		WRT_CHECK_U64(o.pg_num, jint(&j, t, "pg_num"));
		WRT_CHECK_U64(o.pgp_num, jint(&j, t, "pgp_num"));
		WRT_CHECK_U64(o.flags, jint(&j, t, "flags"));
		WRT_CHECK_U64(o.pg_num_mask, mask_ref(o.pg_num));
		WRT_CHECK_U64(o.pgp_num_mask, mask_ref(o.pgp_num));
	}
	/* the two pools of the lab, spelled out */
	if (np == 2) {
		wri_rd r;
		wri_map_pool o;

		wri_rd_init(&r, map, mapn);
		r.pos = fp[0].off;
		dirty(&o, 1);
		WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, NULL));
		WRT_CHECK_U64(fp[0].id, 1);
		WRT_CHECK_U64(o.size, 2);
		WRT_CHECK_U64(o.min_size, 1);
		WRT_CHECK_U64(o.pg_num, 1);
		WRT_CHECK_U64(o.pg_num_mask, 0);
		WRT_CHECK_U64(o.crush_rule, 0);
		WRT_CHECK_U64(o.flags, 1);
		wri_rd_init(&r, map, mapn);
		r.pos = fp[1].off;
		dirty(&o, 2);
		WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, NULL));
		WRT_CHECK_U64(fp[1].id, 2);
		WRT_CHECK_U64(o.size, 3);
		WRT_CHECK_U64(o.min_size, 2);
		WRT_CHECK_U64(o.pg_num, 32);
		WRT_CHECK_U64(o.pgp_num, 32);
		WRT_CHECK_U64(o.pg_num_mask, 31);
		WRT_CHECK_U64(o.crush_rule, 1);
		WRT_CHECK_U64(o.flags, 0x2001);
		WRT_CHECK_U64(o.object_hash, WRI_STR_HASH_RJENKINS);
		/* every truncation of the real record */
		{
			size_t k;

			for (k = fp[1].off; k < fp[1].end; k++) {
				uint8_t *c = xdup(map + fp[1].off, k - fp[1].off);
				wri_rd rc;

				wri_rd_init(&rc, c, k - fp[1].off);
				WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_pool_decode(&rc, &o, NULL));
				free(c);
			}
		}
	}
	wrt_json_free(&j);
	free(map);
}

typedef struct e202_case {
	int64_t id;
	int usable;
	uint8_t size, min_size, crush_rule;
	uint32_t pg_num, pgp_num;
	uint64_t flag_set, flag_clear; /* bits that must be set / clear in flags */
} e202_case;

static void test_e202(void)
{
	/* pools-e202.txt: `ceph osd dump` of the lab with pools that make the optional parts of pg_pool_t non-empty */
	static const e202_case cases[] = {
		{1, 1, 2, 1, 0, 1, 1, WRI_POOL_F_HASHPSPOOL, WRI_POOL_F_SELFMANAGED_SNAPS | WRI_POOL_F_POOL_SNAPS},
		{2, 1, 3, 2, 1, 32, 32, WRI_POOL_F_HASHPSPOOL | WRI_POOL_F_SELFMANAGED_SNAPS, WRI_POOL_F_POOL_SNAPS},
		{7, 1, 2, 1, 0, 7, 4, 0, WRI_POOL_F_HASHPSPOOL | WRI_POOL_F_POOL_SNAPS},
		{8, 1, 2, 1, 0, 14, 14, WRI_POOL_F_HASHPSPOOL, WRI_POOL_F_POOL_SNAPS},
		{9, 1, 2, 1, 0, 1, 1, WRI_POOL_F_HASHPSPOOL | WRI_POOL_F_POOL_SNAPS, WRI_POOL_F_SELFMANAGED_SNAPS},
		{10, 0, 2, 1, 0, 1, 1, WRI_POOL_F_HASHPSPOOL, 0}, /* has a tier, a read tier and a write tier */
		{11, 1, 2, 1, 0, 1, 1, WRI_POOL_F_HASHPSPOOL | WRI_POOL_F_SELFMANAGED_SNAPS, WRI_POOL_F_POOL_SNAPS},
		{12, 0, 2, 1, 0, 1, 1, WRI_POOL_F_HASHPSPOOL, 0}, /* a cache tier of pool 10 */
	};
	uint8_t *map;
	size_t mapn, i;
	found_pool fp[16];
	unsigned np;

	if (wrt_read_file(wrt_vec_path("public/denc-map/pools-e202.bin"), &map, &mapn) != 0) {
		WRT_CHECK(0 && "cannot load public/denc-map/pools-e202.bin");
		return;
	}
	np = find_pools(map, mapn, fp, 16);
	WRT_CHECK_U64(np, sizeof(cases) / sizeof(cases[0]));
	for (i = 0; i < np && i < sizeof(cases) / sizeof(cases[0]); i++) {
		const e202_case *c = &cases[i];
		wri_rd r;
		wri_map_pool o;
		wr_errinfo why;
		size_t k;

		WRT_CHECK_U64(fp[i].id, c->id);
		memset(&why, 0, sizeof(why));
		dirty(&o, fp[i].id);
		wri_rd_init(&r, map, mapn);
		r.pos = fp[i].off;
		WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, &why));
		WRT_CHECK_U64(r.pos, fp[i].end);
		WRT_CHECK_U64(o.present, 1);
		WRT_CHECK_U64(o.status, c->usable ? WR_OK : WR_E_POOL_UNSUPPORTED);
		WRT_CHECK_U64(why.status, c->usable ? WR_OK : WR_E_POOL_UNSUPPORTED);
		WRT_CHECK_U64(o.type, 1);
		WRT_CHECK_U64(o.size, c->size);
		WRT_CHECK_U64(o.min_size, c->min_size);
		WRT_CHECK_U64(o.crush_rule, c->crush_rule);
		WRT_CHECK_U64(o.object_hash, 2);
		WRT_CHECK_U64(o.pg_num, c->pg_num);
		WRT_CHECK_U64(o.pgp_num, c->pgp_num);
		WRT_CHECK_U64(o.pg_num_mask, mask_ref(c->pg_num));
		WRT_CHECK_U64(o.pgp_num_mask, mask_ref(c->pgp_num));
		WRT_CHECK_U64(o.flags & c->flag_set, c->flag_set);
		WRT_CHECK_U64(o.flags & c->flag_clear, 0);
		WRT_CHECK_U64(o.pg_num_pending, o.pg_num); /* no merge in progress */
		/* pool 7 has pg_num 7 and pgp_num 4: the two masks differ */
		if (c->id == 7) {
			WRT_CHECK_U64(o.pg_num_mask, 7);
			WRT_CHECK_U64(o.pgp_num_mask, 3);
		}
		/* the real record, cut anywhere: always a clean failure */
		for (k = 0; k < fp[i].end - fp[i].off; k++) {
			uint8_t *cc = xdup(map + fp[i].off, k);
			wri_rd rc;
			wri_map_pool oc;

			dirty(&oc, 1);
			wri_rd_init(&rc, cc, k);
			WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_pool_decode(&rc, &oc, NULL));
			free(cc);
		}
		/* the real record with its body cut (length patched): never reads past the cut */
		{
			size_t blen = fp[i].end - fp[i].off - 6u;

			for (k = 0; k < blen; k++) {
				uint8_t *cc = xdup(map + fp[i].off, 6u + k);
				wri_rd rc;
				wri_map_pool oc;
				wr_status st;

				dirty(&oc, 1);
				put_u32(cc + 2, (uint32_t)k);
				wri_rd_init(&rc, cc, 6u + k);
				st = wri_pool_decode(&rc, &oc, NULL);
				if (k < blen - 2u) /* the last two bytes are the empty nonprimary set of row 53 */
					WRT_CHECK(st == WR_E_TRUNCATED || st == WR_E_TOOBIG);
				else
					WRT_CHECK_U64((uint32_t)st, (uint32_t)WR_OK);
				free(cc);
			}
		}
		/* decode and skip end together on the real record */
		wri_rd_init(&r, map, mapn);
		r.pos = fp[i].off;
		WRT_CHECK_STATUS(WR_OK, wri_pool_skip(&r, NULL));
		WRT_CHECK_U64(r.pos, fp[i].end);
	}
	/* the five details of the dump that decide the verdicts */
	if (np == 8) {
		wri_rd r;
		wri_map_pool o;
		wr_errinfo why;

		dirty(&o, 10);
		memset(&why, 0, sizeof(why));
		wri_rd_init(&r, map, mapn);
		r.pos = fp[5].off; /* pool 10: tiers 12, read_tier 12, write_tier 12 */
		WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, &why));
		WRT_CHECK(strstr(why.what, "tier") != NULL);
		memset(&why, 0, sizeof(why));
		wri_rd_init(&r, map, mapn);
		r.pos = fp[7].off; /* pool 12: tier_of 10 */
		WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, &why));
		WRT_CHECK_U64(why.a0, 10);
	}
	free(map);
}

/*
 * pools-e957.bin: `ceph osd getmap` at epoch 957 of the lab with an erasure coded pool (56), a pool that finished a merge
 * (57) and a pool in the middle of one (58: pg_num 32, pgp_num 31, pg_num_pending 31, targets 1). Ground truth:
 * pools-e957.txt (the `ceph osd dump 957` pool lines and the JSON fields that line does not show).
 */
typedef struct e957_case {
	int64_t id;
	int usable;
	uint8_t type, size, min_size, crush_rule;
	uint32_t pg_num, pgp_num, pending;
	uint64_t flags;
} e957_case;

static void test_e957(void)
{
	static const e957_case cases[] = {
		{1, 1, 1, 2, 1, 0, 1, 1, 1, 1},
		{2, 1, 1, 3, 2, 1, 32, 32, 32, 0x2001},
		{56, 0, 3, 3, 2, 2, 32, 32, 32, 1}, /* erasure coded: the pool is refused, the map around it decodes */
		{57, 1, 1, 2, 1, 0, 4, 4, 4, 1},
		{58, 1, 1, 2, 1, 0, 32, 31, 31, 1}, /* merge in progress: pg_num_pending below pg_num */
	};
	uint8_t *map;
	size_t mapn, i;
	found_pool fp[16];
	unsigned np;

	if (wrt_read_file(wrt_vec_path("public/denc-map/pools-e957.bin"), &map, &mapn) != 0) {
		WRT_CHECK(0 && "cannot load public/denc-map/pools-e957.bin");
		return;
	}
	np = find_pools(map, mapn, fp, 16);
	WRT_CHECK_U64(np, sizeof(cases) / sizeof(cases[0]));
	for (i = 0; i < np && i < sizeof(cases) / sizeof(cases[0]); i++) {
		const e957_case *c = &cases[i];
		wri_rd r;
		wri_map_pool o;
		wr_errinfo why;
		size_t k;

		WRT_CHECK_U64(fp[i].id, c->id);
		memset(&why, 0, sizeof(why));
		dirty(&o, fp[i].id);
		wri_rd_init(&r, map, mapn);
		r.pos = fp[i].off;
		WRT_CHECK_STATUS(WR_OK, wri_pool_decode(&r, &o, &why));
		WRT_CHECK_U64(r.pos, fp[i].end);
		WRT_CHECK_U64(o.present, 1);
		WRT_CHECK_U64(o.status, c->usable ? WR_OK : WR_E_POOL_UNSUPPORTED);
		WRT_CHECK_U64(why.status, c->usable ? WR_OK : WR_E_POOL_UNSUPPORTED);
		WRT_CHECK_U64(o.type, c->type);
		WRT_CHECK_U64(o.size, c->size);
		WRT_CHECK_U64(o.min_size, c->min_size);
		WRT_CHECK_U64(o.crush_rule, c->crush_rule);
		WRT_CHECK_U64(o.object_hash, WRI_STR_HASH_RJENKINS);
		WRT_CHECK_U64(o.pg_num, c->pg_num);
		WRT_CHECK_U64(o.pgp_num, c->pgp_num);
		WRT_CHECK_U64(o.pg_num_mask, mask_ref(c->pg_num));
		WRT_CHECK_U64(o.pgp_num_mask, mask_ref(c->pgp_num));
		WRT_CHECK_U64(o.pg_num_pending, c->pending);
		WRT_CHECK_U64(o.flags, c->flags);
		WRT_CHECK_U64(o.last_force_op_resend, 0);
		if (!c->usable)
			WRT_CHECK(strstr(why.what, "erasure") != NULL);
		/* the real record, cut anywhere, and with its length patched to every shorter value inside a bigger buffer */
		for (k = 0; k < fp[i].end - fp[i].off; k++) {
			uint8_t *cc = xdup(map + fp[i].off, k);
			wri_rd rc;
			wri_map_pool oc;

			dirty(&oc, 1);
			wri_rd_init(&rc, cc, k);
			WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_pool_decode(&rc, &oc, NULL));
			free(cc);
		}
		for (k = 0; k + 6u < fp[i].end - fp[i].off - 2u; k++) { /* rows 1 .. 52 are cut; the last two bytes are row 53 */
			size_t at = fp[i].off;
			uint8_t *cc = xdup(map, mapn);
			wri_rd rc;
			wri_map_pool oc;
			wr_status st;

			put_u32(cc + at + 2u, (uint32_t)k);
			dirty(&oc, 1);
			wri_rd_init(&rc, cc, mapn);
			rc.pos = at;
			st = wri_pool_decode(&rc, &oc, NULL);
			WRT_CHECK(st == WR_E_TRUNCATED || st == WR_E_TOOBIG);
			free(cc);
		}
		wri_rd_init(&r, map, mapn);
		r.pos = fp[i].off;
		WRT_CHECK_STATUS(WR_OK, wri_pool_skip(&r, NULL));
		WRT_CHECK_U64(r.pos, fp[i].end);
	}
	free(map);
}

int main(void)
{
	test_e42();
	test_e202();
	test_e957();
	test_combinations();
	test_newer_versions();
	test_flags_not_refusals();
	test_unsupported_shapes();
	test_zero_counts_are_supported();
	test_types_and_tier_zero();
	test_ids();
	test_old_versions();
	test_compat();
	test_hostile();
	test_masks();
	test_back_to_back();
	test_errinfo_and_args();
	mutation_tests();
	return wrt_finish();
}
