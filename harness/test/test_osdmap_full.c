/* SPDX-License-Identifier: MIT */
/*
 * test_osdmap_full.c - wri_osdmap_decode_full, wri_osdmap_full_info, wri_osdmap_inc_info and wri_osdmap_read_addr
 * (core/src/osdmap/wri_osdmap_full.c, wri_osdmap_full2.c; architecture 15.4, osdmap.md 2.4, 3.3, 3.6, 4).
 *
 *  - full-e42.hex against expected.json (epoch, flags, max_osd, per-OSD state, weight, address, both pools, the CRUSH
 *    region); the full map embedded in incremental 1; the header facts of every committed full map and incremental;
 *  - every real full map of the public capture sets (21 monitor states and 8 offline maps) against the independent
 *    reader of wrt_mapgen, with the CRC verified;
 *  - generated maps (wrt_mapgen) with the tracked pools in every mix (absent, present, renamed, a name on two ids, a
 *    record missing for a known name), entries of untracked pools in all five tables (they are filtered, in the order of
 *    the wire), address vectors of every shape, per-OSD arrays one entry short and one long, hostile counts, a raised
 *    struct_v with a tail (accepted) and a raised struct_compat (refused), block v8 (refused), an OSD-only block with a
 *    huge struct_len, a CRC that is right, one flipped byte (WR_E_MAP_CRC when verifying) and a wrapper without CRC, pg
 *    keys that are not ascending, vectors that are too long, tracked erasure / rule-less / old pools giving a per-pool status
 *    while the map is accepted, max_osd at 0, at the limit and above it, every truncation and every single-byte mutation of a
 *    real map;
 *  - the argument checks (NULL slot, misaligned slot, a slot smaller than the header), and that a failed decode leaves magic 0.
 *
 * Every decode runs twice, with the slot pre-filled with two different patterns: the bytes of the finished map must be
 * identical, and the guard bytes around the slot untouched. Input is an exact-size heap copy, so an over-read is an ASan report.
 */
#include "wrt.h"
#include "wrt_mapgen.h"
#include "wri_crc32c.h"
#include "wri_ctx.h"
#include "wri_osdmap_dec.h"

/* ---- helpers ------------------------------------------------------------------------------------ */

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

typedef struct slot {
	uint8_t *raw, *p;
	size_t cap, total;
} slot;

static void slot_new(slot *s, size_t cap)
{
	uintptr_t a;

	s->total = cap + 32u + 15u + 64u;
	s->raw = (uint8_t *)malloc(s->total);
	if (s->raw == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	memset(s->raw, 0xA5, s->total);
	a = ((uintptr_t)s->raw + 32u + 15u) & ~(uintptr_t)15u;
	s->p = (uint8_t *)a;
	s->cap = cap;
}
static void slot_free(slot *s) { free(s->raw); }
static int slot_guard_ok(const slot *s)
{
	size_t i, pre = (size_t)(s->p - s->raw);

	for (i = 0; i < pre; i++)
		if (s->raw[i] != 0xA5)
			return 0;
	for (i = pre + s->cap; i < s->total; i++)
		if (s->raw[i] != 0xA5)
			return 0;
	return 1;
}

static void cfg_init(wri_mapcfg *c, uint32_t slot_bytes, uint32_t max_osd, int verify, const char *const *names, unsigned n)
{
	unsigned k;

	memset(c, 0, sizeof(*c));
	c->slot_bytes = slot_bytes;
	c->max_osd = max_osd;
	c->work_max = 200000;
	c->verify_crc = (uint8_t)verify;
	c->n_pools = (uint8_t)n;
	for (k = 0; k < n; k++) {
		c->name_len[k] = (uint8_t)strlen(names[k]);
		memcpy(c->name[k], names[k], c->name_len[k]);
	}
}

#define SLOT_BYTES (1u << 20)

/* Decode into `s` (pre-filled with `fill`). Checks the guards and, on failure, magic 0. */
static wr_status dec1(const wri_mapcfg *cfg, const uint8_t *b, size_t n, slot *s, uint8_t fill, wr_errinfo *why)
{
	uint8_t *c = xdup(b, n);
	wr_status st;

	memset(s->p, fill, s->cap);
	if (why != NULL)
		memset(why, 0, sizeof(*why));
	st = wri_osdmap_decode_full(cfg, c, n, s->p, s->cap, why);
	free(c);
	WRT_CHECK(slot_guard_ok(s));
	if (st != WR_OK && s->cap >= 4u) {
		uint32_t magic;

		memcpy(&magic, s->p, 4);
		WRT_CHECK_U64(magic, 0);
	}
	return st;
}

/* Decode twice with different pre-fills; success must give the same bytes and a map that passes the structural check. */
static wr_status dec(const wri_mapcfg *cfg, const uint8_t *b, size_t n, slot *s, wr_errinfo *why)
{
	slot s2;
	wr_status st = dec1(cfg, b, n, s, 0x00, why);
	wr_status st2;

	slot_new(&s2, s->cap);
	st2 = dec1(cfg, b, n, &s2, 0xFF, NULL);
	WRT_CHECK_STATUS(st, st2);
	if (st == WR_OK && st2 == WR_OK) {
		const wri_osdmap *m = (const wri_osdmap *)(const void *)s->p;
		const wri_osdmap *m2 = (const wri_osdmap *)(const void *)s2.p;

		WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(m));
		WRT_CHECK_U64(m->bytes, m2->bytes);
		if (m->bytes == m2->bytes)
			WRT_CHECK(memcmp(s->p, s2.p, m->bytes) == 0);
	}
	slot_free(&s2);
	return st;
}

static const wri_osdmap *map_of(const slot *s) { return (const wri_osdmap *)(const void *)s->p; }

static void enc(const wrt_mg_map *m, wrt_mg_buf *b)
{
	memset(b, 0, sizeof(*b));
	WRT_CHECK(wrt_mg_map_encode(m, b) == 0);
}

/* ---- the model comparison ----------------------------------------------------------------------------- */

/* The first usable msgr2 entry of an address vector as the notes define it (osdmap.md 3.8). */
static void addr_ref(const wrt_mg_addrvec *av, wri_osd_addr *o)
{
	uint32_t i;

	memset(o, 0, sizeof(*o));
	for (i = 0; i < av->n && i < WRT_MG_AV_MAX; i++) {
		const wrt_mg_addr *a = &av->a[i];

		if (a->type != 2 || a->elen < 2 || (a->family != 2 && a->family != 10))
			continue;
		o->nonce = a->nonce;
		o->port = (uint16_t)(((unsigned)a->sa[0] << 8) | a->sa[1]);
		if (a->family == 2) {
			o->family = WR_AF_IPV4;
			memcpy(o->ip, a->sa + 2, 4);
		} else {
			o->family = WR_AF_IPV6;
			memcpy(o->ip, a->sa + 6, 16);
		}
		return;
	}
}

typedef struct tracked {
	int found;
	int64_t id;
} tracked;

static void resolve_ref(const wrt_mg_map *mod, const wri_mapcfg *cfg, tracked *t)
{
	uint32_t k, i;

	for (k = 0; k < cfg->n_pools; k++) {
		t[k].found = 0;
		t[k].id = 0;
		for (i = 0; i < mod->pool_names.n; i++) {
			const wrt_mg_pname *pn = &WRT_MG_E(mod->pool_names, wrt_mg_pname, i);

			if (strlen(pn->name) == cfg->name_len[k] && memcmp(pn->name, cfg->name[k], cfg->name_len[k]) == 0) {
				t[k].found = 1;
				t[k].id = pn->id;
			}
		}
	}
}

static int is_tracked(const tracked *t, uint32_t n, uint64_t pool)
{
	uint32_t k;

	for (k = 0; k < n; k++)
		if (t[k].found && pool < ((uint64_t)1 << 31) && t[k].id == (int64_t)pool)
			return 1;
	return 0;
}

static void check_tables(const wri_osdmap *m, const wrt_mg_map *mod, const tracked *t, uint32_t nt)
{
	uint32_t i, n[WRI_TAB_COUNT], nv[WRI_TAB_COUNT], k;

	memset(n, 0, sizeof(n));
	memset(nv, 0, sizeof(nv));
	for (i = 0; i < mod->pg_temp.n; i++) {
		const wrt_mg_pg_list *e = &WRT_MG_E(mod->pg_temp, wrt_mg_pg_list, i);
		const int32_t *got;
		uint32_t ngot;

		if (!is_tracked(t, nt, e->pg.pool))
			continue;
		n[WRI_TAB_PG_TEMP]++;
		nv[WRI_TAB_PG_TEMP] += e->osds.n;
		if (wri_pgtab_find(m, WRI_TAB_PG_TEMP, wri_pg_key((uint32_t)e->pg.pool, e->pg.seed), &got, &ngot)) {
			WRT_CHECK_U64(ngot, e->osds.n);
			if (ngot == e->osds.n && ngot != 0)
				WRT_CHECK(memcmp(got, e->osds.v, ngot * 4u) == 0);
		} else {
			WRT_CHECK(0 && "pg_temp entry of a tracked pool is missing");
		}
	}
	for (i = 0; i < mod->pg_upmap.n; i++) {
		const wrt_mg_pg_list *e = &WRT_MG_E(mod->pg_upmap, wrt_mg_pg_list, i);
		const int32_t *got;
		uint32_t ngot;

		if (!is_tracked(t, nt, e->pg.pool))
			continue;
		n[WRI_TAB_PG_UPMAP]++;
		nv[WRI_TAB_PG_UPMAP] += e->osds.n;
		if (wri_pgtab_find(m, WRI_TAB_PG_UPMAP, wri_pg_key((uint32_t)e->pg.pool, e->pg.seed), &got, &ngot)) {
			WRT_CHECK_U64(ngot, e->osds.n);
			if (ngot == e->osds.n && ngot != 0)
				WRT_CHECK(memcmp(got, e->osds.v, ngot * 4u) == 0);
		} else {
			WRT_CHECK(0 && "pg_upmap entry of a tracked pool is missing");
		}
	}
	for (i = 0; i < mod->pg_upmap_items.n; i++) {
		const wrt_mg_pg_items *e = &WRT_MG_E(mod->pg_upmap_items, wrt_mg_pg_items, i);
		const int32_t *got;
		uint32_t ngot;

		if (!is_tracked(t, nt, e->pg.pool))
			continue;
		n[WRI_TAB_PG_UPMAP_ITEMS]++;
		nv[WRI_TAB_PG_UPMAP_ITEMS] += e->items.n * 2u;
		if (wri_pgtab_find(m, WRI_TAB_PG_UPMAP_ITEMS, wri_pg_key((uint32_t)e->pg.pool, e->pg.seed), &got, &ngot)) {
			uint32_t q;

			WRT_CHECK_U64(ngot, e->items.n * 2u);
			for (q = 0; q < e->items.n && ngot == e->items.n * 2u; q++) {
				WRT_CHECK_U64((uint32_t)got[2u * q], (uint32_t)WRT_MG_E(e->items, wrt_mg_pair, q).from);
				WRT_CHECK_U64((uint32_t)got[2u * q + 1u], (uint32_t)WRT_MG_E(e->items, wrt_mg_pair, q).to);
			}
		} else {
			WRT_CHECK(0 && "pg_upmap_items entry of a tracked pool is missing");
		}
	}
	for (k = 0; k < 2; k++) { /* primary_temp, pg_upmap_primaries: one OSD per entry */
		const wrt_mg_vec *vec = k == 0 ? &mod->primary_temp : &mod->pg_upmap_primaries;
		unsigned kind = k == 0 ? WRI_TAB_PRIMARY_TEMP : WRI_TAB_PG_UPMAP_PRIMARY;

		for (i = 0; i < vec->n; i++) {
			const wrt_mg_pg_osd *e = &WRT_MG_E(*vec, wrt_mg_pg_osd, i);
			const int32_t *got;
			uint32_t ngot;

			if (!is_tracked(t, nt, e->pg.pool))
				continue;
			n[kind]++;
			nv[kind]++;
			if (wri_pgtab_find(m, kind, wri_pg_key((uint32_t)e->pg.pool, e->pg.seed), &got, &ngot)) {
				WRT_CHECK_U64(ngot, 1);
				if (ngot == 1)
					WRT_CHECK_U64((uint32_t)got[0], (uint32_t)e->osd);
			} else {
				WRT_CHECK(0 && "one-OSD table entry of a tracked pool is missing");
			}
		}
	}
	/* nothing else is in the tables, and nothing of an untracked pool */
	for (k = 0; k < WRI_TAB_COUNT; k++) {
		WRT_CHECK_U64(m->tab[k].n, n[k]);
		WRT_CHECK_U64(m->tab[k].nv, nv[k]);
		WRT_CHECK_U64(m->tab[k].cap_n, n[k]);
		WRT_CHECK_U64(m->tab[k].cap_nv, nv[k]);
	}
}

#define WANT_ANY 0x7FFFFFFF /* in a `want` array: do not compare this pool's status */

/* The whole slot against the independent model. `want` (n_pools entries, or NULL = all WR_OK) are the expected pool statuses. */
static void compare_model(const wri_osdmap *m, const wrt_mg_map *mod, const wri_mapcfg *cfg, const int32_t *want)
{
	tracked t[WRI_MAP_POOLS_MAX];
	const uint8_t *state = wri_map_state(m);
	const wri_osd_addr *ad = wri_map_addr(m);
	uint32_t i, k;

	WRT_CHECK_U64(m->epoch, mod->epoch);
	WRT_CHECK_MEM(m->fsid, mod->fsid, 16);
	WRT_CHECK_U64(m->flags, mod->flags);
	WRT_CHECK_U64(m->max_osd, (uint32_t)mod->max_osd);
	WRT_CHECK_U64(m->n_pools, cfg->n_pools);
	WRT_CHECK((wri_map_aff(m) != NULL) == (mod->osd_primary_affinity.n != 0));
	for (i = 0; i < m->max_osd && i < (uint32_t)mod->max_osd; i++) {
		wri_osd_addr want_ad;

		WRT_CHECK_U64(state[i], WRT_MG_E(mod->osd_state, uint32_t, i) & 3u);
		WRT_CHECK_U64(wri_map_weight(m)[i], WRT_MG_E(mod->osd_weight, uint32_t, i));
		WRT_CHECK_U64(wri_osd_aff(m, (int32_t)i), wrt_mg_affinity(mod, (int32_t)i));
		addr_ref(&WRT_MG_E(mod->client_addrs, wrt_mg_addrvec, i), &want_ad);
		if (memcmp(&ad[i], &want_ad, sizeof(want_ad)) != 0) {
			WRT_CHECK(0 && "OSD address differs from the model");
			fprintf(stderr, "  osd %u: family %u/%u port %u/%u\n", i, ad[i].family, want_ad.family, ad[i].port, want_ad.port);
		}
	}
	resolve_ref(mod, cfg, t);
	for (k = 0; k < cfg->n_pools; k++) {
		const wri_map_pool *p = &wri_map_pools(m)[k];
		const wrt_mg_pool *mp = t[k].found ? wrt_mg_map_pool(mod, t[k].id) : NULL;

		if (mp == NULL) {
			WRT_CHECK_U64(p->present, 0);
			WRT_CHECK_U64(p->status, 0);
			continue;
		}
		WRT_CHECK_U64(p->present, 1);
		WRT_CHECK_U64(p->id, t[k].id);
		WRT_CHECK_U64(p->type, mp->type);
		WRT_CHECK_U64(p->size, mp->size);
		WRT_CHECK_U64(p->min_size, mp->min_size);
		WRT_CHECK_U64(p->crush_rule, mp->crush_rule);
		WRT_CHECK_U64(p->object_hash, mp->object_hash);
		WRT_CHECK_U64(p->pg_num, mp->pg_num);
		WRT_CHECK_U64(p->pgp_num, mp->pgp_num);
		WRT_CHECK_U64(p->flags, mp->flags);
		WRT_CHECK_U64(p->pg_num_mask, wrt_mg_pg_mask(mp->pg_num));
		WRT_CHECK_U64(p->pgp_num_mask, wrt_mg_pg_mask(mp->pgp_num));
		WRT_CHECK_U64(p->last_force_op_resend, mp->last_force_op_resend);
		WRT_CHECK_U64(p->pg_num_pending, mp->pg_num_pending);
		if (want == NULL || want[k] != WANT_ANY)
			WRT_CHECK_U64((uint32_t)p->status, (uint32_t)(want != NULL ? want[k] : WR_OK));
	}
	check_tables(m, mod, t, cfg->n_pools);
	WRT_CHECK(wri_map_crush(m) != NULL);
}

/* ---- the lab maps ------------------------------------------------------------------------------------ */

static int64_t jint(const wrt_json *j, wrt_tok obj, const char *key)
{
	int ok = 0;
	int64_t v = wrt_json_int(j, wrt_json_get(j, obj, key), &ok);

	WRT_CHECK(ok);
	return v;
}

static int load_hex(const char *rel, uint8_t **out, size_t *n)
{
	return wrt_mg_load_hex_file(wrt_vec_path(rel), out, n);
}

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

/* "10.77.0.10:6802" -> ip and port */
static void parse_addr(const char *s, uint8_t ip[4], unsigned *port)
{
	unsigned a, b, c, d;

	if (sscanf(s, "%u.%u.%u.%u:%u", &a, &b, &c, &d, port) != 5) {
		WRT_CHECK(0 && "address string");
		return;
	}
	ip[0] = (uint8_t)a;
	ip[1] = (uint8_t)b;
	ip[2] = (uint8_t)c;
	ip[3] = (uint8_t)d;
}

/* The expected.json summary of a map state (the format of full_e42.state and chain.<epoch>). */
static void check_summary(const wri_osdmap *m, const wrt_json *j, wrt_tok st, const wri_mapcfg *cfg, const uint32_t *pool_ids)
{
	wrt_tok osd_state = wrt_json_get(j, st, "osd_state"), weight = wrt_json_get(j, st, "osd_weight");
	wrt_tok addrs = wrt_json_get(j, st, "client_addrs"), aff = wrt_json_get(j, st, "osd_primary_affinity");
	wrt_tok pools = wrt_json_get(j, st, "pools");
	uint32_t i, k;

	WRT_CHECK_U64(m->epoch, jint(j, st, "epoch"));
	WRT_CHECK_U64(m->flags, jint(j, st, "flags"));
	WRT_CHECK_U64(m->max_osd, jint(j, st, "max_osd"));
	WRT_CHECK_U64(wrt_json_count(j, osd_state), m->max_osd);
	for (i = 0; i < m->max_osd; i++) {
		int ok = 0;
		wrt_tok v = wrt_json_at(j, addrs, i);
		size_t e, ne = wrt_json_count(j, v);
		wri_osd_addr want;
		int have = 0;

		WRT_CHECK_U64(wri_map_state(m)[i], wrt_json_int(j, wrt_json_at(j, osd_state, i), &ok) & 3);
		WRT_CHECK_U64(wri_map_weight(m)[i], wrt_json_int(j, wrt_json_at(j, weight, i), &ok));
		if (wrt_json_count(j, aff) != 0)
			WRT_CHECK_U64(wri_osd_aff(m, (int32_t)i), wrt_json_int(j, wrt_json_at(j, aff, i), &ok));
		memset(&want, 0, sizeof(want));
		for (e = 0; e < ne && !have; e++) { /* [type, "ip:port", nonce] */
			wrt_tok ent = wrt_json_at(j, v, e);
			unsigned port = 0;
			char *s;

			if (wrt_json_int(j, wrt_json_at(j, ent, 0), &ok) != 2)
				continue;
			s = wrt_json_strdup(j, wrt_json_at(j, ent, 1));
			parse_addr(s, want.ip, &port);
			free(s);
			want.family = WR_AF_IPV4;
			want.port = (uint16_t)port;
			want.nonce = (uint32_t)wrt_json_int(j, wrt_json_at(j, ent, 2), &ok);
			have = 1;
		}
		WRT_CHECK(memcmp(&wri_map_addr(m)[i], &want, sizeof(want)) == 0);
	}
	for (k = 0; k < cfg->n_pools; k++) {
		char key[24];
		wrt_tok t;
		const wri_map_pool *p = &wri_map_pools(m)[k];

		snprintf(key, sizeof(key), "%u", pool_ids[k]);
		t = wrt_json_get(j, pools, key);
		WRT_CHECK(t != WRT_NONE);
		if (t == WRT_NONE) {
			WRT_CHECK_U64(p->present, 0);
			continue;
		}
		WRT_CHECK_U64(p->present, 1);
		WRT_CHECK_U64(p->id, pool_ids[k]);
		WRT_CHECK_U64(p->status, WR_OK);
		WRT_CHECK_U64(p->type, jint(j, t, "type"));
		WRT_CHECK_U64(p->size, jint(j, t, "size"));
		WRT_CHECK_U64(p->min_size, jint(j, t, "min_size"));
		WRT_CHECK_U64(p->crush_rule, jint(j, t, "crush_rule"));
		WRT_CHECK_U64(p->object_hash, jint(j, t, "object_hash"));
		WRT_CHECK_U64(p->pg_num, jint(j, t, "pg_num"));
		WRT_CHECK_U64(p->pgp_num, jint(j, t, "pgp_num"));
		WRT_CHECK_U64(p->flags, jint(j, t, "flags"));
	}
	WRT_CHECK_U64(m->tab[WRI_TAB_PG_TEMP].n, 0);
	WRT_CHECK_U64(m->tab[WRI_TAB_PG_UPMAP].n, 0);
	WRT_CHECK_U64(m->tab[WRI_TAB_PG_UPMAP_ITEMS].n, 0);
	WRT_CHECK_U64(m->tab[WRI_TAB_PRIMARY_TEMP].n, 0);
	WRT_CHECK_U64(m->tab[WRI_TAB_PG_UPMAP_PRIMARY].n, 0);
}

/* The CRUSH region of the lab map against the dump in expected.json "crush". */
static void check_lab_crush(const wri_osdmap *m, const wrt_json *j, wrt_tok cr)
{
	const wri_crush *c = wri_map_crush(m);
	wrt_tok tun = wrt_json_get(j, cr, "tunables"), bk = wrt_json_get(j, cr, "buckets"), rules = wrt_json_get(j, cr, "rules");
	size_t i;

	WRT_CHECK(c != NULL);
	if (c == NULL)
		return;
	WRT_CHECK_U64(c->max_devices, jint(j, cr, "max_devices"));
	WRT_CHECK_U64(c->tun.choose_local_tries, jint(j, tun, "choose_local_tries"));
	WRT_CHECK_U64(c->tun.choose_local_fallback_tries, jint(j, tun, "choose_local_fallback_tries"));
	WRT_CHECK_U64(c->tun.choose_total_tries, jint(j, tun, "choose_total_tries"));
	WRT_CHECK_U64(c->tun.chooseleaf_descend_once, jint(j, tun, "chooseleaf_descend_once"));
	WRT_CHECK_U64(c->tun.chooseleaf_vary_r, jint(j, tun, "chooseleaf_vary_r"));
	WRT_CHECK_U64(c->tun.chooseleaf_stable, jint(j, tun, "chooseleaf_stable"));
	for (i = 0; i < wrt_json_count(j, bk); i++) { /* "-3": [type, alg, [items], [weights]] */
		wrt_tok v;
		const char *k = wrt_json_key_at(j, bk, i, &v);
		int32_t id = (int32_t)atoi(k);
		const wri_cbucket *b = wri_crush_bucket(c, id);
		size_t q;

		WRT_CHECK(b != NULL);
		if (b == NULL)
			continue;
		WRT_CHECK_U64(b->type, wrt_json_int(j, wrt_json_at(j, v, 0), &(int){0}));
		WRT_CHECK_U64(b->alg, wrt_json_int(j, wrt_json_at(j, v, 1), &(int){0}));
		WRT_CHECK_U64(b->size, wrt_json_count(j, wrt_json_at(j, v, 2)));
		for (q = 0; q < b->size && q < wrt_json_count(j, wrt_json_at(j, v, 2)); q++) {
			WRT_CHECK_U64((uint32_t)wri_cbucket_items(b)[q], (uint32_t)wrt_json_int(j, wrt_json_at(j, wrt_json_at(j, v, 2), q), &(int){0}));
			WRT_CHECK_U64(wri_cbucket_w(b)[q], wrt_json_int(j, wrt_json_at(j, wrt_json_at(j, v, 3), q), &(int){0}));
		}
	}
	for (i = 0; i < wrt_json_count(j, rules); i++) { /* "0": [type, [[op, a1, a2], ...]] */
		wrt_tok v, steps;
		const char *k = wrt_json_key_at(j, rules, i, &v);
		const wri_crule *r = wri_crush_rule(c, (uint32_t)atoi(k));
		size_t q;

		WRT_CHECK(r != NULL);
		if (r == NULL)
			continue;
		steps = wrt_json_at(j, v, 1);
		WRT_CHECK_U64(r->nsteps, wrt_json_count(j, steps));
		for (q = 0; q < r->nsteps && q < wrt_json_count(j, steps); q++) {
			wrt_tok s = wrt_json_at(j, steps, q);

			WRT_CHECK_U64(wri_crule_steps(r)[q].op, wrt_json_int(j, wrt_json_at(j, s, 0), &(int){0}));
			WRT_CHECK_U64((uint32_t)wri_crule_steps(r)[q].arg1, (uint32_t)wrt_json_int(j, wrt_json_at(j, s, 1), &(int){0}));
			WRT_CHECK_U64((uint32_t)wri_crule_steps(r)[q].arg2, (uint32_t)wrt_json_int(j, wrt_json_at(j, s, 2), &(int){0}));
		}
	}
}

static void test_e42(void)
{
	static const char *const names[] = {".mgr", "winrbd"};
	static const uint32_t ids[] = {1, 2};
	uint8_t *map;
	size_t mapn;
	wrt_json j;
	wrt_tok full, st;
	wri_mapcfg cfg;
	slot s;
	wr_errinfo why;

	if (load_hex("osdmap/full-e42.hex", &map, &mapn) != 0 || wrt_json_load_vec(&j, "osdmap/expected.json") != 0) {
		WRT_CHECK(0 && "cannot load the e42 vectors");
		return;
	}
	full = wrt_json_get(&j, wrt_json_root(&j), "full_e42");
	st = wrt_json_get(&j, full, "state");
	WRT_CHECK_U64(mapn, jint(&j, full, "bytes"));
	cfg_init(&cfg, SLOT_BYTES, 2048, 1, names, 2);
	slot_new(&s, SLOT_BYTES);
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, map, mapn, &s, &why));
	WRT_CHECK_U64(why.status, WR_OK);
	check_summary(map_of(&s), &j, st, &cfg, ids);
	check_lab_crush(map_of(&s), &j, wrt_json_get(&j, wrt_json_root(&j), "crush"));
	WRT_CHECK_U64(map_of(&s)->n_exists, 3);
	WRT_CHECK_U64(map_of(&s)->n_up, 3);
	WRT_CHECK_U64(wri_map_pools(map_of(&s))[1].pg_num_mask, 31);
	WRT_CHECK_U64(wri_map_pools(map_of(&s))[0].pg_num_mask, 0);
	/* the map and the slot are the same size class: a few hundred bytes, not the slot */
	WRT_CHECK(map_of(&s)->bytes < 2048u);

	/* only one pool tracked, none, a name that is not in the map, the same name twice */
	{
		static const char *const one[] = {"winrbd"}, *const none[] = {"nosuch"}, *const mix[] = {"nosuch", ".mgr", "winrbd"}, *const dup[] = {"winrbd", "winrbd"};
		wri_mapcfg c2;

		cfg_init(&c2, SLOT_BYTES, 2048, 1, one, 1);
		WRT_CHECK_STATUS(WR_OK, dec(&c2, map, mapn, &s, NULL));
		WRT_CHECK_U64(wri_map_pools(map_of(&s))[0].id, 2);
		WRT_CHECK_U64(wri_map_pools(map_of(&s))[0].size, 3);
		cfg_init(&c2, SLOT_BYTES, 2048, 1, NULL, 0);
		WRT_CHECK_STATUS(WR_OK, dec(&c2, map, mapn, &s, NULL));
		WRT_CHECK_U64(map_of(&s)->n_pools, 0);
		cfg_init(&c2, SLOT_BYTES, 2048, 1, none, 1);
		WRT_CHECK_STATUS(WR_OK, dec(&c2, map, mapn, &s, NULL));
		WRT_CHECK_U64(wri_map_pools(map_of(&s))[0].present, 0);
		cfg_init(&c2, SLOT_BYTES, 2048, 1, mix, 3);
		WRT_CHECK_STATUS(WR_OK, dec(&c2, map, mapn, &s, NULL));
		WRT_CHECK_U64(wri_map_pools(map_of(&s))[0].present, 0);
		WRT_CHECK_U64(wri_map_pools(map_of(&s))[1].id, 1);
		WRT_CHECK_U64(wri_map_pools(map_of(&s))[2].id, 2);
		cfg_init(&c2, SLOT_BYTES, 2048, 1, dup, 2);
		WRT_CHECK_STATUS(WR_OK, dec(&c2, map, mapn, &s, NULL));
		WRT_CHECK_U64(wri_map_pools(map_of(&s))[0].id, 2);
		WRT_CHECK_U64(wri_map_pools(map_of(&s))[1].id, 2);
	}
	slot_free(&s);
	wrt_json_free(&j);
	free(map);
}

/* The header facts of every committed full map and incremental, and the full map embedded in incremental 1. */
static void test_inc_and_info(void)
{
	static const char *const names[] = {".mgr"};
	wrt_mg_line *lines = NULL;
	size_t nl = 0, i;
	uint8_t *map;
	size_t mapn;
	wri_map_blob_info bi;
	wr_errinfo why;
	wrt_json j;
	wri_mapcfg cfg;
	slot s;

	if (load_hex("osdmap/full-e42.hex", &map, &mapn) != 0 || wrt_mg_load_epoch_lines(wrt_vec_path("osdmap/incrementals.hex"), &lines, &nl) != 0) {
		WRT_CHECK(0 && "cannot load the incremental vectors");
		return;
	}
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_full_info(map, mapn, &bi, &why));
	WRT_CHECK_U64(bi.epoch, 42);
	WRT_CHECK_U64(bi.has_fullmap, 0);
	WRT_CHECK(memcmp(bi.fsid, "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 16) == 0);
	WRT_CHECK_U64(nl, 89);
	for (i = 0; i < nl; i++) {
		wri_map_blob_info ib;
		uint8_t *c = xdup(lines[i].p, lines[i].n);

		WRT_CHECK_STATUS(WR_OK, wri_osdmap_inc_info(c, lines[i].n, &ib, &why));
		WRT_CHECK_U64(ib.epoch, lines[i].epoch);
		WRT_CHECK_U64(ib.has_fullmap, lines[i].epoch == 1 ? 1 : 0);
		WRT_CHECK(memcmp(ib.fsid, bi.fsid, 16) == 0);
		/* an incremental is not a full map: the client block of the incremental is v9 and so passes, but rows 1 and 2 are all
		 * it has in common; a full-map info of it must not crash (it reads the same two rows) */
		free(c);
	}
	/* the full map embedded in incremental 1 against chain.1 */
	if (nl >= 1 && wrt_json_load_vec(&j, "osdmap/expected.json") == 0) {
		wrt_mg_inc inc;
		static const uint32_t no_pools[1] = {0};

		WRT_CHECK(wrt_mg_inc_parse(lines[0].p, lines[0].n, &inc) == 0);
		WRT_CHECK(inc.fullmap_len > 0);
		cfg_init(&cfg, SLOT_BYTES, 2048, 1, names, 0);
		slot_new(&s, SLOT_BYTES);
		WRT_CHECK_STATUS(WR_OK, wri_osdmap_full_info(inc.fullmap, inc.fullmap_len, &bi, &why));
		WRT_CHECK_U64(bi.epoch, 1);
		WRT_CHECK_STATUS(WR_OK, dec(&cfg, inc.fullmap, inc.fullmap_len, &s, &why));
		check_summary(map_of(&s), &j, wrt_json_get(&j, wrt_json_get(&j, wrt_json_root(&j), "chain"), "1"), &cfg, no_pools);
		WRT_CHECK_U64(map_of(&s)->max_osd, 0);
		slot_free(&s);
		wrt_mg_inc_free(&inc);
		wrt_json_free(&j);
	}
	/* info on every prefix of a real map: refused (the wrapper claims more than is there), outputs zeroed, no read past the end */
	for (i = 0; i < mapn; i += (i < 48u ? 1u : 29u)) {
		uint8_t *c = xdup(map, i);
		wri_map_blob_info zero;

		memset(&bi, 0xEE, sizeof(bi));
		memset(&zero, 0, sizeof(zero));
		WRT_CHECK(wri_osdmap_full_info(c, i, &bi, NULL) != WR_OK);
		WRT_CHECK(memcmp(&bi, &zero, sizeof(bi)) == 0);
		memset(&bi, 0xEE, sizeof(bi));
		WRT_CHECK(wri_osdmap_inc_info(c, i, &bi, NULL) != WR_OK);
		WRT_CHECK(memcmp(&bi, &zero, sizeof(bi)) == 0);
		free(c);
	}
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_full_info(map, mapn, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_inc_info(NULL, 5, &bi, NULL));
	wrt_mg_free_lines(lines, nl);
	free(map);
}

/* ---- real maps against the independent reader ------------------------------------------------------- */

static void check_real_blob(const char *label, const uint8_t *b, size_t n)
{
	static const char *const names[] = {"winrbd", ".mgr", "rbd", "np", "p7", "pool1"};
	static const int32_t any[WRI_MAP_POOLS_MAX] = {WANT_ANY, WANT_ANY, WANT_ANY, WANT_ANY, WANT_ANY, WANT_ANY, WANT_ANY, WANT_ANY};
	wrt_mg_map mod;
	wri_mapcfg cfg;
	slot s;
	wr_errinfo why;
	wr_status st;

	cfg_init(&cfg, SLOT_BYTES, 32768, 1, names, 6);
	slot_new(&s, SLOT_BYTES);
	st = dec(&cfg, b, n, &s, &why);
	if (st != WR_OK) {
		fprintf(stderr, "%s: decode failed: %d (%s) %s\n", label, (int)st, wrt_status_name_(st), why.what != NULL ? why.what : "");
		WRT_CHECK(0 && "a real map must decode");
	} else if (wrt_mg_map_parse(b, n, &mod) == 0) {
		compare_model(map_of(&s), &mod, &cfg, any);
		WRT_CHECK(mod.crc_ok);
		wrt_mg_map_free(&mod);
	} else {
		WRT_CHECK(0 && "the model reader cannot parse a real map");
	}
	slot_free(&s);
}

static void test_real_maps(void)
{
	wrt_json idx;
	wrt_tok files;
	size_t i, n_maps = 0;
	uint8_t *b;
	size_t bn;

	if (load_hex("public/mapb/base-e666.hex", &b, &bn) == 0) {
		check_real_blob("base-e666", b, bn);
		n_maps++;
		free(b);
	}
	if (wrt_json_load_vec(&idx, "public/mapb/INDEX.json") != 0) {
		WRT_CHECK(0 && "cannot load public/mapb/INDEX.json");
		return;
	}
	files = wrt_json_get(&idx, wrt_json_root(&idx), "files");
	for (i = 0; i < wrt_json_count(&idx, files); i++) {
		wrt_tok v;
		const char *k = wrt_json_key_at(&idx, files, i, &v);
		size_t kl = strlen(k);
		char rel[256];

		if (!((strncmp(k, "maps/e", 6) == 0 && kl > 4 && strcmp(k + kl - 4, ".hex") == 0) ||
		      (strncmp(k, "offline/", 8) == 0 && kl > 11 && strcmp(k + kl - 11, ".osdmap.hex") == 0)))
			continue;
		snprintf(rel, sizeof(rel), "public/mapb/%s", k);
		if (load_hex(rel, &b, &bn) != 0) {
			WRT_CHECK(0 && "cannot load a listed map");
			continue;
		}
		check_real_blob(k, b, bn);
		n_maps++;
		free(b);
	}
	printf("osdmap.full: %zu real full maps decoded and compared\n", n_maps);
	WRT_CHECK(n_maps >= 25);
	wrt_json_free(&idx);
}

/* ---- generated maps ------------------------------------------------------------------------------------ */

static void add_pg_tables(wrt_mg_map *m, uint64_t pool, uint32_t seed0)
{
	int32_t l[3] = {1, 0, 2};
	wrt_mg_pair pr[2] = {{0, 2}, {1, 0}};
	wrt_mg_pg pg;

	pg.pool = pool;
	pg.seed = seed0;
	wrt_mg_map_set_pg_temp(m, pg, l, 3);
	wrt_mg_map_set_pg_upmap(m, pg, l, 2);
	wrt_mg_map_set_pg_upmap_items(m, pg, pr, 2);
	wrt_mg_map_set_primary_temp(m, pg, 2);
	wrt_mg_map_set_upmap_primary(m, pg, 1);
	pg.seed = seed0 + 5;
	wrt_mg_map_set_pg_temp(m, pg, l, 2);
	wrt_mg_map_set_pg_upmap_items(m, pg, pr, 1);
	wrt_mg_map_set_primary_temp(m, pg, 0);
}

/* A cluster of `n_osds` with three pools (ids 1, 2, 3 named pool1 .. pool3) and tables on pools 1, 2, 3 and 7 and a huge pool id. */
static void gen_map(wrt_mg_map *m, uint32_t n_osds, uint32_t n_pools)
{
	wrt_mg_cluster_spec s;

	wrt_mg_cluster_spec_init(&s, n_osds);
	s.n_pools = n_pools;
	s.n_affinity = n_osds / 2;
	s.never_up_pct = 15;
	s.up_pct = 80;
	s.out_pct = 10;
	s.ipv6_every = 7;
	s.v1_only_every = 5;
	s.epoch = 77;
	s.seed = 99;
	WRT_CHECK(wrt_mg_build_map(m, &s) == 0);
	add_pg_tables(m, 1, 3);
	add_pg_tables(m, 2, 0);
	add_pg_tables(m, 3, 10);
	add_pg_tables(m, 7, 1);
	add_pg_tables(m, 0x7fffffffull, 2);
	add_pg_tables(m, 0x100000000ull, 4);
	add_pg_tables(m, 0xffffffffffffffffull, 6);
}

static void test_generated_mixes(void)
{
	static const char *const sets[][4] = {
		{"pool1"}, {"pool2", "pool3"}, {"pool1", "pool2", "pool3", "pool4"}, {"nosuch", "pool1"}, {"pool3", "pool1"}, {""},
	};
	static const unsigned counts[] = {1, 2, 4, 2, 2, 0};
	unsigned si, variant;
	slot s;

	slot_new(&s, SLOT_BYTES);
	for (variant = 0; variant < 4; variant++) {
		for (si = 0; si < sizeof(sets) / sizeof(sets[0]); si++) {
			wrt_mg_map m;
			wrt_mg_buf b;
			wri_mapcfg cfg;
			wr_errinfo why;

			gen_map(&m, 12 + variant * 20, 3);
			if (variant == 1) { /* pool2 renamed: the tracked name pool2 is absent, id 2 now answers to "renamed" */
				snprintf(WRT_MG_E(m.pool_names, wrt_mg_pname, 1).name, WRT_MG_NAME_MAX, "renamed");
			} else if (variant == 2) { /* the record of pool 3 is missing though its name is there */
				wrt_mg_pool_free(&WRT_MG_E(m.pools, wrt_mg_pool_ent, 2).p);
				wrt_mg_vec_del(&m.pools, sizeof(wrt_mg_pool_ent), 2);
			} else if (variant == 3) { /* pool1 has no name: the pool exists but cannot be tracked */
				wrt_mg_vec_del(&m.pool_names, sizeof(wrt_mg_pname), 0);
			}
			enc(&m, &b);
			cfg_init(&cfg, SLOT_BYTES, 2048, 1, sets[si], counts[si]);
			WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, &why));
			if (wri_osdmap_check(map_of(&s)) == WR_OK)
				compare_model(map_of(&s), &m, &cfg, NULL);
			/* the same without CRC verification must give the same map */
			cfg.verify_crc = 0;
			WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, NULL));
			wrt_mg_buf_free(&b);
			wrt_mg_map_free(&m);
		}
	}
	slot_free(&s);
}

/* Address vectors of every shape, through wri_osdmap_read_addr directly. */
static wr_status read_addr_of(const wrt_mg_addrvec *av, wri_osd_addr *out, size_t *left_after)
{
	wrt_mg_buf b;
	uint8_t *c;
	wri_rd r;
	wr_status st;
	uint8_t tail[3] = {0xAA, 0xBB, 0xCC};

	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_addrvec_encode(av, &b) == 0);
	wrt_mg_buf_put(&b, tail, 3);
	c = xdup(b.p, b.len);
	wri_rd_init(&r, c, b.len);
	st = wri_osdmap_read_addr(&r, out);
	if (st == WR_OK)
		*left_after = wri_rd_left(&r);
	free(c);
	wrt_mg_buf_free(&b);
	return st;
}

static void test_read_addr(void)
{
	wrt_mg_addrvec av;
	wri_osd_addr a, want;
	size_t left = 99;
	uint8_t ip6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2};
	unsigned i;

	/* v2 only, v1 + v2 (v1 first), v2 + v1, IPv6 */
	wrt_mg_av_v2(&av, 0x0a4d000a, 6802, 77);
	WRT_CHECK_STATUS(WR_OK, read_addr_of(&av, &a, &left));
	WRT_CHECK_U64(left, 3);
	WRT_CHECK_U64(a.family, WR_AF_IPV4);
	WRT_CHECK_U64(a.port, 6802);
	WRT_CHECK_U64(a.nonce, 77);
	WRT_CHECK(a.ip[0] == 10 && a.ip[1] == 77 && a.ip[2] == 0 && a.ip[3] == 10 && a.ip[4] == 0 && a.reserved == 0);
	wrt_mg_av_v2v1(&av, 0x0a4d000b, 6810, 5);
	WRT_CHECK_STATUS(WR_OK, read_addr_of(&av, &a, &left));
	WRT_CHECK_U64(a.port, 6810);
	WRT_CHECK_U64(left, 3);
	{
		wrt_mg_addr t = av.a[0];

		av.a[0] = av.a[1];
		av.a[1] = t; /* v1 first, v2 second */
	}
	WRT_CHECK_STATUS(WR_OK, read_addr_of(&av, &a, &left));
	WRT_CHECK_U64(a.port, 6810);
	WRT_CHECK_U64(left, 3);
	wrt_mg_av_v6(&av, ip6, 6820, 9);
	WRT_CHECK_STATUS(WR_OK, read_addr_of(&av, &a, &left));
	WRT_CHECK_U64(a.family, WR_AF_IPV6);
	WRT_CHECK_U64(a.port, 6820);
	WRT_CHECK(memcmp(a.ip, ip6, 16) == 0);
	/* empty, blank, v1 only, type "any" (3): no usable address, not an error, the vector consumed */
	memset(&want, 0, sizeof(want));
	wrt_mg_av_empty(&av);
	memset(&a, 0xEE, sizeof(a));
	WRT_CHECK_STATUS(WR_OK, read_addr_of(&av, &a, &left));
	WRT_CHECK(memcmp(&a, &want, sizeof(a)) == 0);
	WRT_CHECK_U64(left, 3);
	wrt_mg_av_blank(&av);
	WRT_CHECK_STATUS(WR_OK, read_addr_of(&av, &a, &left));
	WRT_CHECK(memcmp(&a, &want, sizeof(a)) == 0);
	WRT_CHECK_U64(left, 3);
	wrt_mg_av_v1(&av, 0x0a4d000a, 6803, 1);
	WRT_CHECK_STATUS(WR_OK, read_addr_of(&av, &a, &left));
	WRT_CHECK(memcmp(&a, &want, sizeof(a)) == 0);
	wrt_mg_av_v2(&av, 0x0a4d000a, 6802, 1);
	av.a[0].type = 3;
	WRT_CHECK_STATUS(WR_OK, read_addr_of(&av, &a, &left));
	WRT_CHECK(memcmp(&a, &want, sizeof(a)) == 0);
	/* a blank entry, then an entry of an unknown socket family, then the usable one: the first two are passed over */
	wrt_mg_av_v2(&av, 0x0a4d000a, 6802, 4);
	av.n = 3;
	av.a[2] = av.a[0];
	wrt_mg_addr_blank(&av.a[0]);
	av.a[0].type = 2;
	av.a[1] = av.a[2];
	av.a[1].family = 99;
	WRT_CHECK_STATUS(WR_OK, read_addr_of(&av, &a, &left));
	WRT_CHECK_U64(a.port, 6802);
	WRT_CHECK_U64(a.nonce, 4);
	WRT_CHECK_U64(left, 3);
	/* the usable entry first and then entries that are not even decodable (an unknown family): consumed by length */
	wrt_mg_av_v2v1(&av, 0x0a4d000a, 6802, 4);
	av.n = 3;
	av.a[2] = av.a[1];
	av.a[2].family = 77;
	WRT_CHECK_STATUS(WR_OK, read_addr_of(&av, &a, &left));
	WRT_CHECK_U64(a.port, 6802);
	WRT_CHECK_U64(left, 3);
	/* marker 1: one entity without a count, marker 0 (legacy): version, marker 3: corrupt */
	wrt_mg_av_v2(&av, 0x0a4d000a, 6802, 4);
	av.marker = 1;
	WRT_CHECK_STATUS(WR_OK, read_addr_of(&av, &a, &left));
	WRT_CHECK_U64(a.port, 6802);
	WRT_CHECK_U64(left, 3);
	wrt_mg_av_legacy(&av, 0x0a4d000a, 6802, 4);
	WRT_CHECK_STATUS(WR_E_MAP_VERSION, read_addr_of(&av, &a, &left));
	WRT_CHECK_U64(a.family, 0);
	/* hand-made bytes: a count above 16, a cut entry, an entry with struct_compat 2, an entry marker 0, a short body */
	{
		static const uint8_t big[] = {2, 17, 0, 0, 0};
		static const uint8_t compat2[] = {2, 1, 0, 0, 0, 1, 1, 2, 12, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0};
		static const uint8_t em0[] = {2, 1, 0, 0, 0, 0, 1, 1, 12, 0, 0, 0};
		static const uint8_t shortb[] = {2, 1, 0, 0, 0, 1, 1, 1, 4, 0, 0, 0, 2, 0, 0, 0};
		static const uint8_t m3[] = {3, 0, 0, 0, 0};
		const struct {
			const uint8_t *b;
			size_t n;
			wr_status want;
		} cases[] = {{big, sizeof(big), WR_E_MAP_CORRUPT},         {compat2, sizeof(compat2), WR_E_MAP_VERSION}, {em0, sizeof(em0), WR_E_MAP_VERSION},
			     {shortb, sizeof(shortb), WR_E_MAP_CORRUPT}, {m3, sizeof(m3), WR_E_MAP_CORRUPT}};

		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			uint8_t *c = xdup(cases[i].b, cases[i].n);
			wri_rd r;

			wri_rd_init(&r, c, cases[i].n);
			memset(&a, 0xEE, sizeof(a));
			WRT_CHECK_STATUS(cases[i].want, wri_osdmap_read_addr(&r, &a));
			WRT_CHECK_U64(a.family, 0);
			WRT_CHECK(!wri_rd_ok(&r));
			free(c);
		}
		/* every truncation of a good vector fails cleanly */
		wrt_mg_av_v2v1(&av, 0x0a4d000a, 6802, 4);
		{
			wrt_mg_buf b;

			memset(&b, 0, sizeof(b));
			WRT_CHECK(wrt_mg_addrvec_encode(&av, &b) == 0);
			for (i = 0; i < b.len; i++) {
				uint8_t *c = xdup(b.p, i);
				wri_rd r;

				wri_rd_init(&r, c, i);
				WRT_CHECK(wri_osdmap_read_addr(&r, &a) != WR_OK);
				free(c);
			}
			wrt_mg_buf_free(&b);
		}
	}
	/* a reader that already failed gives its error and a zero address; NULL arguments */
	{
		uint8_t z[8] = {0};
		wri_rd r;

		wri_rd_init(&r, z, 8);
		wri_rd_fail(&r, WR_E_TRUNCATED);
		memset(&a, 0xEE, sizeof(a));
		WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_osdmap_read_addr(&r, &a));
		WRT_CHECK_U64(a.family, 0);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_read_addr(NULL, &a));
		wri_rd_init(&r, z, 8);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_read_addr(&r, NULL));
	}
}

/* Address shapes in a whole map: IPv6, v1 only, never booted, all of them in one cluster (the model reader decides). */
static void test_map_addresses(void)
{
	static const char *const names[] = {"pool1"};
	wrt_mg_map m;
	wrt_mg_buf b;
	wri_mapcfg cfg;
	slot s;
	wr_errinfo why;
	uint32_t i, n6 = 0, n4 = 0, n0 = 0;

	gen_map(&m, 70, 1);
	enc(&m, &b);
	cfg_init(&cfg, SLOT_BYTES, 2048, 1, names, 1);
	slot_new(&s, SLOT_BYTES);
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, &why));
	compare_model(map_of(&s), &m, &cfg, NULL);
	for (i = 0; i < map_of(&s)->max_osd; i++) {
		const wri_osd_addr *a = &wri_map_addr(map_of(&s))[i];

		if (a->family == WR_AF_IPV6)
			n6++;
		else if (a->family == WR_AF_IPV4)
			n4++;
		else
			n0++; /* never booted, or v1 only */
	}
	WRT_CHECK(n6 > 0 && n4 > 0 && n0 > 0);
	slot_free(&s);
	wrt_mg_buf_free(&b);
	wrt_mg_map_free(&m);
}

/* ---- hostile shapes ----------------------------------------------------------------------------------- */

static void put32le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/* A map of 2 OSDs that never booted, no pools and no tables, no affinity: the client block rows are at fixed offsets. */
static void bare_map(wrt_mg_map *m)
{
	wrt_mg_cluster_spec s;

	wrt_mg_cluster_spec_init(&s, 2);
	s.n_pools = 0;
	s.never_up_pct = 100;
	WRT_CHECK(wrt_mg_build_map(m, &s) == 0);
}

#define OFF_POOLS 36u /* from the client block body: fsid 16, epoch 4, created 8, modified 8 */
#define OFF_NAMES 40u
#define OFF_MAXOSD 52u
#define OFF_STATE 56u
#define OFF_WEIGHT (OFF_STATE + 4u + 8u)
#define OFF_ADDRS (OFF_WEIGHT + 4u + 8u)
#define OFF_PGTEMP (OFF_ADDRS + 4u + 10u)
#define OFF_PRIMTEMP (OFF_PGTEMP + 4u)
#define OFF_AFF (OFF_PRIMTEMP + 4u)
#define OFF_CRUSHLEN (OFF_AFF + 4u)

static void test_hostile_counts(void)
{
	wrt_mg_map m;
	wrt_mg_buf b;
	wrt_mg_layout l;
	wri_mapcfg cfg;
	slot s;
	static const uint32_t row_off[] = {OFF_POOLS, OFF_NAMES, OFF_STATE, OFF_WEIGHT, OFF_ADDRS, OFF_PGTEMP, OFF_PRIMTEMP, OFF_AFF, OFF_CRUSHLEN};
	static const uint32_t hostile[] = {0xFFFFFFFFu, 0x7FFFFFFFu, 0x10000000u, 0x00010000u, 3u, 1u};
	unsigned r, h;

	bare_map(&m);
	enc(&m, &b);
	WRT_CHECK(wrt_mg_wrapper_layout(b.p, b.len, &l) == 0);
	WRT_CHECK_U64(le32(b.p + l.client_body + OFF_MAXOSD), 2);
	WRT_CHECK_U64(le32(b.p + l.client_body + OFF_POOLS), 0);
	cfg_init(&cfg, SLOT_BYTES, 2048, 1, NULL, 0);
	slot_new(&s, SLOT_BYTES);
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, NULL));
	for (r = 0; r < sizeof(row_off) / sizeof(row_off[0]); r++) {
		for (h = 0; h < sizeof(hostile) / sizeof(hostile[0]); h++) {
			uint8_t *c = xdup(b.p, b.len);
			uint32_t was = le32(c + l.client_body + row_off[r]);

			if (hostile[h] != was) {
				wr_status st;

				put32le(c + l.client_body + row_off[r], hostile[h]);
				WRT_CHECK(wrt_mg_fix_crc(c, b.len, 0) == 0);
				st = dec(&cfg, c, b.len, &s, NULL);
				if (st == WR_OK)
					fprintf(stderr, "row at +%u set to 0x%x was accepted\n", row_off[r], hostile[h]);
				if (st != WR_E_MAP_CORRUPT && st != WR_E_MAP_BUDGET && st != WR_E_CRUSH_ENCODING && st != WR_E_MAP_VERSION)
					fprintf(stderr, "row at +%u set to 0x%x gave %d (%s)\n", row_off[r], hostile[h], (int)st, wrt_status_name_(st));
				/* a count that points into the rows behind it reads them as records of the wrong shape: corrupt, or a version it cannot step over */
				WRT_CHECK(st == WR_E_MAP_CORRUPT || st == WR_E_MAP_BUDGET || st == WR_E_CRUSH_ENCODING || st == WR_E_MAP_VERSION);
			}
			free(c);
		}
	}
	/* max_osd: negative is corrupt, above the hard cap is a budget failure whatever the configuration says */
	{
		uint8_t *c = xdup(b.p, b.len);
		wr_errinfo why;

		put32le(c + l.client_body + OFF_MAXOSD, 0xFFFFFFFFu);
		WRT_CHECK(wrt_mg_fix_crc(c, b.len, 0) == 0);
		WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, dec(&cfg, c, b.len, &s, &why));
		WRT_CHECK(why.what != NULL && why.module == WR_MOD_MAP);
		put32le(c + l.client_body + OFF_MAXOSD, WRI_MAP_OSD_HARD_MAX + 1u);
		WRT_CHECK(wrt_mg_fix_crc(c, b.len, 0) == 0);
		cfg.max_osd = 0x7FFFFFFFu;
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, dec(&cfg, c, b.len, &s, &why));
		WRT_CHECK_U64(why.a1, WRI_MAP_OSD_HARD_MAX + 1u);
		WRT_CHECK_U64(why.a2, WRI_MAP_OSD_HARD_MAX);
		free(c);
	}
	slot_free(&s);
	wrt_mg_buf_free(&b);
	wrt_mg_map_free(&m);
}

static void test_max_osd_limits(void)
{
	static const char *const names[] = {"pool1"};
	static const uint32_t nos[] = {0, 1, 64, 65};
	unsigned i;
	slot s;

	slot_new(&s, SLOT_BYTES);
	for (i = 0; i < sizeof(nos) / sizeof(nos[0]); i++) {
		wrt_mg_map m;
		wrt_mg_buf b;
		wri_mapcfg cfg;
		wr_errinfo why;

		gen_map(&m, nos[i], 1);
		enc(&m, &b);
		cfg_init(&cfg, SLOT_BYTES, 64, 1, names, 1);
		if (nos[i] <= 64) { /* at the cap and below it */
			WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, &why));
			WRT_CHECK_U64(map_of(&s)->max_osd, nos[i]);
			compare_model(map_of(&s), &m, &cfg, NULL);
		} else { /* cap + 1 */
			WRT_CHECK_STATUS(WR_E_MAP_BUDGET, dec(&cfg, b.p, b.len, &s, &why));
			WRT_CHECK_U64(why.status, WR_E_MAP_BUDGET);
			WRT_CHECK_U64(why.a1, 65);
			WRT_CHECK_U64(why.a2, 64);
		}
		wrt_mg_buf_free(&b);
		wrt_mg_map_free(&m);
	}
	slot_free(&s);
}

/* The per-OSD arrays one entry short and one long (osdmap.md 3.6); an empty affinity vector is the one legal shortening. */
static void test_array_lengths(void)
{
	static const char *const names[] = {"pool1"};
	slot s;
	unsigned c;

	slot_new(&s, SLOT_BYTES);
	for (c = 0; c < 9; c++) {
		wrt_mg_map m;
		wrt_mg_buf b;
		wri_mapcfg cfg;
		wr_status st;

		gen_map(&m, 9, 1);
		WRT_CHECK(m.osd_primary_affinity.n == 9);
		switch (c) {
		case 0: wrt_mg_vec_resize0(&m.osd_state, 4, 8); break;
		case 1: wrt_mg_vec_resize0(&m.osd_state, 4, 10); break;
		case 2: wrt_mg_vec_resize0(&m.osd_weight, 4, 8); break;
		case 3: wrt_mg_vec_resize0(&m.osd_weight, 4, 10); break;
		case 4: wrt_mg_vec_resize0(&m.client_addrs, sizeof(wrt_mg_addrvec), 8); break;
		case 5: wrt_mg_vec_resize0(&m.client_addrs, sizeof(wrt_mg_addrvec), 10); break;
		case 6: wrt_mg_vec_resize0(&m.osd_primary_affinity, 4, 8); break;
		case 7: wrt_mg_vec_resize0(&m.osd_primary_affinity, 4, 10); break;
		default: wrt_mg_vec_resize0(&m.osd_primary_affinity, 4, 0); break;
		}
		enc(&m, &b);
		cfg_init(&cfg, SLOT_BYTES, 2048, 1, names, 1);
		st = dec(&cfg, b.p, b.len, &s, NULL);
		if (c == 8) {
			WRT_CHECK_STATUS(WR_OK, st);
			WRT_CHECK(wri_map_aff(map_of(&s)) == NULL);
			WRT_CHECK_U64(wri_osd_aff(map_of(&s), 3), WRI_OSD_IN_FULL);
			compare_model(map_of(&s), &m, &cfg, NULL);
		} else {
			WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, st);
		}
		wrt_mg_buf_free(&b);
		wrt_mg_map_free(&m);
	}
	slot_free(&s);
}

/* Versions, tails, the OSD-only block, the CRC. */
static void test_versions_and_crc(void)
{
	static const char *const names[] = {"pool1", "pool2"};
	wrt_mg_map m, m9;
	wrt_mg_buf b;
	wri_mapcfg cfg;
	wrt_mg_layout l;
	slot s;
	wr_errinfo why;
	size_t i;
	uint8_t *c;

	slot_new(&s, SLOT_BYTES);
	gen_map(&m, 10, 2);
	cfg_init(&cfg, SLOT_BYTES, 2048, 1, names, 2);

	/* raised struct_v with a tail on every level: accepted, and the tail is inside the CRC range */
	m.wrapper_v = 9;
	m.wrapper_tail = 7;
	m.client_v = 11;
	m.client_tail = 13;
	m.osd_v = 14;
	m.osd_tail = 5;
	enc(&m, &b);
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, &why));
	compare_model(map_of(&s), &m, &cfg, NULL);
	c = xdup(b.p, b.len);
	c[b.len - 1] ^= 0x40; /* the last byte of the wrapper tail */
	WRT_CHECK_STATUS(WR_E_MAP_CRC, dec(&cfg, c, b.len, &s, &why));
	cfg.verify_crc = 0;
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, c, b.len, &s, NULL));
	cfg.verify_crc = 1;
	free(c);
	wrt_mg_buf_free(&b);
	m.wrapper_tail = m.client_tail = m.osd_tail = 0;

	/* struct_compat: the highest accepted value passes, one more is refused (the OSD-only block's is never looked at) */
	m.wrapper_v = 8;
	m.client_v = 10;
	m.osd_v = 9;
	m.wrapper_compat = 8;
	m.client_compat = 10;
	m.osd_compat = 255;
	enc(&m, &b);
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, NULL));
	wrt_mg_buf_free(&b);
	m.wrapper_compat = 9;
	enc(&m, &b);
	WRT_CHECK_STATUS(WR_E_MAP_VERSION, dec(&cfg, b.p, b.len, &s, &why));
	WRT_CHECK_U64(why.status, WR_E_MAP_VERSION);
	wrt_mg_buf_free(&b);
	m.wrapper_compat = 7;
	m.client_compat = 11;
	enc(&m, &b);
	WRT_CHECK_STATUS(WR_E_MAP_VERSION, dec(&cfg, b.p, b.len, &s, &why));
	wrt_mg_buf_free(&b);
	m.client_compat = 1;

	/* wrapper below 7, client block v8 (refused) and v9 (accepted: no row 25), wrapper v7 (no CRC field) */
	m.wrapper_v = 6;
	enc(&m, &b);
	WRT_CHECK_STATUS(WR_E_MAP_VERSION, dec(&cfg, b.p, b.len, &s, NULL));
	wrt_mg_buf_free(&b);
	m.wrapper_v = 8;
	m.client_v = 8;
	enc(&m, &b);
	WRT_CHECK_STATUS(WR_E_MAP_VERSION, dec(&cfg, b.p, b.len, &s, NULL));
	wrt_mg_buf_free(&b);
	m.client_v = 9;
	enc(&m, &b);
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, NULL));
	WRT_CHECK(wrt_mg_map_parse(b.p, b.len, &m9) == 0); /* the model of a v9 block has no pg_upmap_primaries: neither has the slot */
	WRT_CHECK_U64(m9.pg_upmap_primaries.n, 0);
	compare_model(map_of(&s), &m9, &cfg, NULL);
	WRT_CHECK_U64(map_of(&s)->tab[WRI_TAB_PG_UPMAP_PRIMARY].n, 0);
	wrt_mg_map_free(&m9);
	wrt_mg_buf_free(&b);
	m.client_v = 10;
	m.wrapper_v = 7;
	enc(&m, &b);
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, NULL)); /* verify_crc is on, but a v7 wrapper has no CRC to verify */
	compare_model(map_of(&s), &m, &cfg, NULL);
	wrt_mg_buf_free(&b);
	m.wrapper_v = 8;

	/* the CRC: right (rule of osdmap.md 2.4.5), then one flipped byte at a time */
	enc(&m, &b);
	WRT_CHECK(wrt_mg_wrapper_layout(b.p, b.len, &l) == 0);
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, NULL));
	WRT_CHECK_U64(wri_crc32c(0xFFFFFFFFu, b.p, l.osd_end), le32(b.p + l.osd_end));
	for (i = 0; i < b.len; i += (i < 64u || (i >= l.osd_body && i < l.osd_end + 4u && (i % 11u) == 0)) ? 1u : 7u) {
		wr_status st;

		c = xdup(b.p, b.len);
		c[i] ^= 0x01;
		cfg.verify_crc = 1;
		st = dec(&cfg, c, b.len, &s, &why);
		WRT_CHECK(st != WR_OK);
		if (i >= l.client_body) /* a byte the envelopes do not describe: only the CRC can notice it */
			WRT_CHECK_STATUS(WR_E_MAP_CRC, st);
		if (i >= l.osd_body && i < l.osd_end + 4u) { /* never read: accepted when the CRC is not checked */
			cfg.verify_crc = 0;
			WRT_CHECK_STATUS(WR_OK, dec(&cfg, c, b.len, &s, NULL));
			cfg.verify_crc = 1;
		}
		free(c);
	}

	/* an OSD-only block that claims a huge length, and one that leaves no room for the CRC */
	c = xdup(b.p, b.len);
	put32le(c + l.osd_off + 2, 0x7FFFFFFFu);
	WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, dec(&cfg, c, b.len, &s, &why));
	put32le(c + l.osd_off + 2, (uint32_t)(l.wrapper_end - l.osd_body - 2u));
	WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, dec(&cfg, c, b.len, &s, &why));
	free(c);
	/* bytes after the wrapper are refused; a wrapper that claims more than there is */
	c = (uint8_t *)malloc(b.len + 1u);
	memcpy(c, b.p, b.len);
	c[b.len] = 0;
	WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, dec(&cfg, c, b.len + 1u, &s, &why));
	free(c);
	WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, dec(&cfg, b.p, b.len - 1u, &s, &why));
	wrt_mg_buf_free(&b);
	wrt_mg_map_free(&m);
	slot_free(&s);
}

/* Tracked pools that this client cannot use: a per-pool status and an accepted map. */
static void test_pool_status(void)
{
	static const char *const names[] = {"pool1", "pool2", "pool3", "pool4"};
	wrt_mg_map m;
	wrt_mg_buf b;
	wri_mapcfg cfg;
	wrt_mg_layout l;
	slot s;
	wr_errinfo why;
	int32_t want[4];
	uint8_t *c;

	slot_new(&s, SLOT_BYTES);
	gen_map(&m, 10, 4);
	cfg_init(&cfg, SLOT_BYTES, 2048, 1, names, 4);

	wrt_mg_pool_shape(&WRT_MG_E(m.pools, wrt_mg_pool_ent, 1).p, WRT_MG_SHAPE_ERASURE);  /* pool 2: erasure */
	WRT_MG_E(m.pools, wrt_mg_pool_ent, 2).p.crush_rule = 77;                               /* pool 3: no such rule */
	wrt_mg_pool_shape(&WRT_MG_E(m.pools, wrt_mg_pool_ent, 3).p, WRT_MG_SHAPE_POOL_SNAPS); /* pool 4: snaps flag, still usable */
	enc(&m, &b);
	want[0] = WR_OK;
	want[1] = WR_E_POOL_UNSUPPORTED;
	want[2] = WR_E_CRUSH_NO_RULE;
	want[3] = WR_OK;
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, &why));
	compare_model(map_of(&s), &m, &cfg, want);
	WRT_CHECK_U64(why.status, WR_E_POOL_UNSUPPORTED); /* the first reason, reported with the map that carried it */
	WRT_CHECK(why.what != NULL);
	/* the tables of the unusable pools are kept anyway */
	WRT_CHECK(wri_pgtab_find(map_of(&s), WRI_TAB_PG_TEMP, wri_pg_key(2, 0), NULL, NULL));
	wrt_mg_buf_free(&b);

	/* a tracked pool of struct_v 28: stepped over, status unsupported, only the id is known */
	wrt_mg_pool_free(&WRT_MG_E(m.pools, wrt_mg_pool_ent, 1).p);
	wrt_mg_pool_init(&WRT_MG_E(m.pools, wrt_mg_pool_ent, 1).p, 28);
	enc(&m, &b);
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, &why));
	WRT_CHECK_U64(wri_map_pools(map_of(&s))[1].status, WR_E_POOL_UNSUPPORTED);
	WRT_CHECK_U64(wri_map_pools(map_of(&s))[1].present, 1);
	WRT_CHECK_U64(wri_map_pools(map_of(&s))[1].id, 2);
	wrt_mg_buf_free(&b);

	/* struct_compat 33 on a tracked pool fails the map (version); on an untracked one it is stepped over */
	wrt_mg_pool_free(&WRT_MG_E(m.pools, wrt_mg_pool_ent, 1).p);
	wrt_mg_pool_init(&WRT_MG_E(m.pools, wrt_mg_pool_ent, 1).p, 32);
	WRT_MG_E(m.pools, wrt_mg_pool_ent, 1).p.compat = 33;
	enc(&m, &b);
	WRT_CHECK_STATUS(WR_E_MAP_VERSION, dec(&cfg, b.p, b.len, &s, &why));
	cfg_init(&cfg, SLOT_BYTES, 2048, 1, names, 1); /* only pool1 tracked */
	WRT_CHECK_STATUS(WR_OK, dec(&cfg, b.p, b.len, &s, &why));
	/* a pool record of struct_v 4 has no length to skip by: the map is refused whether the pool is tracked or not */
	WRT_CHECK(wrt_mg_wrapper_layout(b.p, b.len, &l) == 0);
	c = xdup(b.p, b.len);
	c[l.client_body + OFF_POOLS + 4u + 8u] = 4; /* struct_v of the first pool record */
	WRT_CHECK(wrt_mg_fix_crc(c, b.len, 0) == 0);
	WRT_CHECK_STATUS(WR_E_MAP_VERSION, dec(&cfg, c, b.len, &s, &why));
	free(c);
	wrt_mg_buf_free(&b);

	wrt_mg_map_free(&m);
	slot_free(&s);
}

/* Table shapes: order, duplicates, vector lengths, filtered entries. */
static void test_table_shapes(void)
{
	static const char *const names[] = {"pool1"};
	wri_mapcfg cfg;
	slot s;
	wr_errinfo why;
	unsigned t;

	slot_new(&s, SLOT_BYTES);
	cfg_init(&cfg, SLOT_BYTES, 2048, 1, names, 1);
	for (t = 0; t < 13; t++) {
		wrt_mg_map m;
		wrt_mg_buf b;
		wr_status st, want = WR_E_MAP_CORRUPT;
		wrt_mg_pg_list pl;
		wrt_mg_pg_items pi;
		wrt_mg_pg_osd po;
		int32_t v[200];
		wrt_mg_pair pr[40];
		wrt_mg_pg pg;
		unsigned q;

		gen_map(&m, 6, 1);
		memset(&pl, 0, sizeof(pl));
		memset(&pi, 0, sizeof(pi));
		memset(&po, 0, sizeof(po));
		for (q = 0; q < 200; q++)
			v[q] = (int32_t)(q % 6);
		for (q = 0; q < 40; q++) {
			pr[q].from = (int32_t)(q % 6);
			pr[q].to = (int32_t)((q + 1) % 6);
		}
		pg.pool = 1;
		pg.seed = 500;
		/* the generated tables end with the entries of pool 2^64-1: appended entries are out of order unless a setter places them */
		switch (t) {
		case 0: /* a tracked pg after the largest key: descending */
			pl.pg.pool = 1;
			pl.pg.seed = 2;
			WRT_MG_PUSH(m.pg_temp, wrt_mg_pg_list, pl);
			break;
		case 1: /* the last key twice (an untracked pool: order is checked on every entry, kept or not) */
			pl.pg = WRT_MG_E(m.pg_temp, wrt_mg_pg_list, m.pg_temp.n - 1u).pg;
			WRT_MG_PUSH(m.pg_temp, wrt_mg_pg_list, pl);
			break;
		case 2: /* primary_temp: two untracked entries, descending */
			po.pg.pool = 0xFFFFFFFFFFFFFFFFull;
			po.pg.seed = 100;
			WRT_MG_PUSH(m.primary_temp, wrt_mg_pg_osd, po);
			po.pg.seed = 99;
			WRT_MG_PUSH(m.primary_temp, wrt_mg_pg_osd, po);
			break;
		case 3: /* pg_upmap: the last key twice */
			pl.pg = WRT_MG_E(m.pg_upmap, wrt_mg_pg_list, m.pg_upmap.n - 1u).pg;
			WRT_MG_PUSH(m.pg_upmap, wrt_mg_pg_list, pl);
			break;
		case 4: /* pg_upmap_items: a tracked pg after the largest key */
			pi.pg.pool = 1;
			pi.pg.seed = 0;
			WRT_MG_PUSH(m.pg_upmap_items, wrt_mg_pg_items, pi);
			break;
		case 5: /* pg_upmap_primaries: the last key twice */
			po.pg = WRT_MG_E(m.pg_upmap_primaries, wrt_mg_pg_osd, m.pg_upmap_primaries.n - 1u).pg;
			WRT_MG_PUSH(m.pg_upmap_primaries, wrt_mg_pg_osd, po);
			break;
		case 6: /* 33 OSDs in a pg_temp of a tracked pool: a limit of ours */
			wrt_mg_map_set_pg_temp(&m, pg, v, 33);
			want = WR_E_MAP_BUDGET;
			break;
		case 7: /* 32 are kept */
			wrt_mg_map_set_pg_upmap(&m, pg, v, 32);
			want = WR_OK;
			break;
		case 8: /* 33 upmap pairs: too long */
			wrt_mg_map_set_pg_upmap_items(&m, pg, pr, 33);
			want = WR_E_MAP_BUDGET;
			break;
		case 9: /* 32 pairs are kept */
			wrt_mg_map_set_pg_upmap_items(&m, pg, pr, 32);
			want = WR_OK;
			break;
		case 10: /* 200 OSDs on a pool that is not tracked: filtered, not an error */
			pg.pool = 99;
			wrt_mg_map_set_pg_temp(&m, pg, v, 200);
			wrt_mg_map_set_pg_upmap(&m, pg, v, 200);
			want = WR_OK;
			break;
		case 11: /* an empty vector, key 0 and the largest seed, a negative OSD */
			pg.seed = 0xFFFFFFFFu;
			wrt_mg_map_set_pg_temp(&m, pg, NULL, 0);
			wrt_mg_map_set_primary_temp(&m, pg, -1);
			pg.seed = 0;
			wrt_mg_map_set_pg_temp(&m, pg, v, 1);
			pg.pool = 0;
			wrt_mg_map_set_pg_temp(&m, pg, v, 1);
			want = WR_OK;
			break;
		default: /* CRUSH_ITEM_NONE inside a vector */
			v[1] = WRT_MG_NONE;
			wrt_mg_map_set_pg_temp(&m, pg, v, 3);
			want = WR_OK;
			break;
		}
		enc(&m, &b);
		st = dec(&cfg, b.p, b.len, &s, &why);
		WRT_CHECK_STATUS(want, st);
		if (st == WR_OK)
			compare_model(map_of(&s), &m, &cfg, NULL);
		wrt_mg_buf_free(&b);
		wrt_mg_map_free(&m);
	}
	slot_free(&s);
}

/* The pools map and the pool_name map: order, duplicates, names on two ids, ids at the edge of the 31-bit limit, a legacy address. */
static void test_pool_maps(void)
{
	static const char *const names[] = {"pool1", "pool2", "pool3", "pool4"};
	static const char *const dup[] = {"pool1", "pool1"};
	slot s;
	unsigned c;

	slot_new(&s, SLOT_BYTES);
	for (c = 0; c < 11; c++) {
		wrt_mg_map m;
		wrt_mg_buf b;
		wri_mapcfg cfg;
		wr_status st, want = WR_E_MAP_CORRUPT;
		wr_errinfo why;
		int32_t wst[4] = {WR_OK, WR_OK, WR_OK, WR_OK};
		int compare = 0;

		gen_map(&m, 10, 4);
		cfg_init(&cfg, SLOT_BYTES, 2048, 1, names, 4);
		switch (c) {
		case 0: /* the pools map written out of order: the ids are not ascending */
		{
			wrt_mg_pool_ent t = WRT_MG_E(m.pools, wrt_mg_pool_ent, 0);

			WRT_MG_E(m.pools, wrt_mg_pool_ent, 0) = WRT_MG_E(m.pools, wrt_mg_pool_ent, 1);
			WRT_MG_E(m.pools, wrt_mg_pool_ent, 1) = t;
			break;
		}
		case 1: /* the same id twice in the pools map */
			WRT_MG_E(m.pools, wrt_mg_pool_ent, 1).id = WRT_MG_E(m.pools, wrt_mg_pool_ent, 0).id;
			break;
		case 2: /* the pool_name map out of order */
		{
			wrt_mg_pname t = WRT_MG_E(m.pool_names, wrt_mg_pname, 0);

			WRT_MG_E(m.pool_names, wrt_mg_pname, 0) = WRT_MG_E(m.pool_names, wrt_mg_pname, 1);
			WRT_MG_E(m.pool_names, wrt_mg_pname, 1) = t;
			break;
		}
		case 3: /* the same id twice in the pool_name map */
			WRT_MG_E(m.pool_names, wrt_mg_pname, 2).id = WRT_MG_E(m.pool_names, wrt_mg_pname, 1).id;
			break;
		case 4: /* a tracked name on two pool ids: damage */
			snprintf(WRT_MG_E(m.pool_names, wrt_mg_pname, 1).name, WRT_MG_NAME_MAX, "pool1");
			break;
		case 5: /* the same name on two ids is fine while nobody tracks it */
			snprintf(WRT_MG_E(m.pool_names, wrt_mg_pname, 0).name, WRT_MG_NAME_MAX, "twin");
			snprintf(WRT_MG_E(m.pool_names, wrt_mg_pname, 1).name, WRT_MG_NAME_MAX, "twin");
			cfg_init(&cfg, SLOT_BYTES, 2048, 1, names + 2, 2);
			want = WR_OK;
			compare = 1;
			break;
		case 6: /* one name tracked twice: both handles get the same record */
			cfg_init(&cfg, SLOT_BYTES, 2048, 1, dup, 2);
			want = WR_OK;
			compare = 1;
			break;
		case 7: /* the largest id that fits 31 bits: a normal pool, and its table entries are kept */
			WRT_MG_E(m.pools, wrt_mg_pool_ent, 3).id = 0x7fffffffll;
			WRT_MG_E(m.pool_names, wrt_mg_pname, 3).id = 0x7fffffffll;
			want = WR_OK;
			compare = 1;
			break;
		case 8: /* one id more: the pool is present but unusable, and none of its table entries are kept */
			WRT_MG_E(m.pools, wrt_mg_pool_ent, 3).id = 0x80000000ll;
			WRT_MG_E(m.pool_names, wrt_mg_pname, 3).id = 0x80000000ll;
			add_pg_tables(&m, 0x80000000ull, 3);
			wst[3] = WR_E_POOL_UNSUPPORTED;
			want = WR_OK;
			compare = 1;
			break;
		case 9: /* a negative pool id (the pools map is in key order, so it comes first) */
			WRT_MG_E(m.pools, wrt_mg_pool_ent, 0).id = -5;
			WRT_MG_E(m.pool_names, wrt_mg_pname, 0).id = -5;
			wst[0] = WR_E_POOL_UNSUPPORTED;
			want = WR_OK;
			compare = 1;
			break;
		case 10: /* an OSD address vector in the legacy form (marker 0): a version this client does not read */
			wrt_mg_av_legacy(&WRT_MG_E(m.client_addrs, wrt_mg_addrvec, 4), 0x0a4d000a, 6802, 4);
			want = WR_E_MAP_VERSION;
			break;
		default:
			break;
		}
		enc(&m, &b);
		memset(&why, 0, sizeof(why));
		st = dec(&cfg, b.p, b.len, &s, &why);
		WRT_CHECK_STATUS(want, st);
		if (st != WR_OK) {
			WRT_CHECK_U64(why.status, want);
			WRT_CHECK(why.what != NULL && why.module == WR_MOD_MAP);
		} else if (compare) {
			if (c == 6) { /* the two handles are the same record */
				WRT_CHECK(memcmp(&wri_map_pools(map_of(&s))[0], &wri_map_pools(map_of(&s))[1], sizeof(wri_map_pool)) == 0);
				WRT_CHECK_U64(wri_map_pools(map_of(&s))[0].present, 1);
			}
			if (c == 8) {
				WRT_CHECK_U64(wri_map_pools(map_of(&s))[3].present, 1);
				WRT_CHECK_U64(wri_map_pools(map_of(&s))[3].status, WR_E_POOL_UNSUPPORTED);
			}
			compare_model(map_of(&s), &m, &cfg, wst);
		}
		wrt_mg_buf_free(&b);
		wrt_mg_map_free(&m);
	}
	slot_free(&s);
}

/* ---- truncations and mutations ------------------------------------------------------------------------ */

static void test_truncations_and_mutations(void)
{
	static const char *const names[] = {".mgr", "winrbd"};
	uint8_t *map;
	size_t mapn, i, ok = 0;
	wri_mapcfg cfg;
	slot s;
	unsigned seed = 12345;

	if (load_hex("osdmap/full-e42.hex", &map, &mapn) != 0) {
		WRT_CHECK(0 && "cannot load full-e42.hex");
		return;
	}
	slot_new(&s, 64u * 1024u);
	cfg_init(&cfg, 64u * 1024u, 2048, 1, names, 2);
	/* every truncation: refused; with the CRC check off too (the wrapper length no longer fits) */
	for (i = 0; i < mapn; i++) {
		cfg.verify_crc = (uint8_t)(i & 1u);
		WRT_CHECK(dec1(&cfg, map, i, &s, 0x5A, NULL) != WR_OK);
	}
	/* every byte flipped three ways, without the CRC check: a clean error or a map that passes the structural check */
	cfg.verify_crc = 0;
	for (i = 0; i < mapn; i++) {
		unsigned k;

		for (k = 0; k < 3; k++) {
			uint8_t *c = xdup(map, mapn);
			wr_status st;

			seed = seed * 1103515245u + 12345u;
			c[i] ^= k == 0 ? 0x01u : k == 1 ? 0x80u : (uint8_t)(seed >> 16 | 1u);
			st = dec1(&cfg, c, mapn, &s, 0x33, NULL);
			if (st == WR_OK) {
				ok++;
				WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(map_of(&s)));
			}
			free(c);
		}
	}
	printf("osdmap.full: %zu of %zu single-byte mutations of e42 still decode (all pass the structural check)\n", ok, mapn * 3u);
	/* the same with the CRC check on: a mutation of any covered byte is refused */
	cfg.verify_crc = 1;
	for (i = 0; i < mapn; i += 3) {
		uint8_t *c = xdup(map, mapn);

		c[i] ^= 0x10;
		WRT_CHECK(dec1(&cfg, c, mapn, &s, 0x77, NULL) != WR_OK);
		free(c);
	}
	slot_free(&s);
	free(map);
}

/* ---- the arguments -------------------------------------------------------------------------------------- */

static void test_arguments(void)
{
	static const char *const names[] = {".mgr"};
	uint8_t *map;
	size_t mapn;
	wri_mapcfg cfg;
	slot s;
	wr_errinfo why;

	if (load_hex("osdmap/full-e42.hex", &map, &mapn) != 0) {
		WRT_CHECK(0 && "cannot load full-e42.hex");
		return;
	}
	cfg_init(&cfg, SLOT_BYTES, 2048, 1, names, 1);
	slot_new(&s, SLOT_BYTES);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_decode_full(NULL, map, mapn, s.p, s.cap, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_decode_full(&cfg, NULL, mapn, s.p, s.cap, NULL));
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_decode_full(&cfg, map, mapn, NULL, SLOT_BYTES, &why));
	WRT_CHECK_U64(why.status, WR_E_INVAL);
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_decode_full(&cfg, map, mapn, s.p + 4, SLOT_BYTES - 16u, &why)); /* 4-aligned only */
	/* a slot smaller than the header: budget, nothing written beyond it */
	{
		slot t;
		size_t cp;

		for (cp = 0; cp < sizeof(wri_osdmap); cp += 17) {
			slot_new(&t, cp);
			memset(&why, 0, sizeof(why));
			WRT_CHECK_STATUS(WR_E_MAP_BUDGET, dec1(&cfg, map, mapn, &t, 0x11, &why));
			slot_free(&t);
		}
	}
	/* a cap above cfg.slot_bytes is clamped to it: a map that needs more than the slot_bytes is a budget failure */
	cfg.slot_bytes = 400;
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, dec1(&cfg, map, mapn, &s, 0x22, &why));
	WRT_CHECK(slot_guard_ok(&s));
	{
		size_t k;

		for (k = 0; k < s.cap && k < 8192; k++) /* beyond slot_bytes nothing is written */
			if (k >= 400 && s.p[k] != 0x22)
				break;
		WRT_CHECK(k >= s.cap || k >= 8192);
	}
	/* more tracked pools than a map holds */
	cfg.slot_bytes = SLOT_BYTES;
	cfg.n_pools = WRI_MAP_POOLS_MAX + 1u;
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, dec1(&cfg, map, mapn, &s, 0x22, &why));
	cfg.n_pools = 1;
	/* a name longer than the tracked maximum never matches (and never reads past the name array) */
	cfg.name_len[0] = 200;
	WRT_CHECK_STATUS(WR_OK, dec1(&cfg, map, mapn, &s, 0x22, &why));
	WRT_CHECK_U64(wri_map_pools(map_of(&s))[0].present, 0);
	slot_free(&s);
	free(map);
}

int main(void)
{
	test_e42();
	test_inc_and_info();
	test_real_maps();
	test_generated_mixes();
	test_read_addr();
	test_map_addresses();
	test_hostile_counts();
	test_max_osd_limits();
	test_array_lengths();
	test_versions_and_crc();
	test_pool_status();
	test_table_shapes();
	test_pool_maps();
	test_truncations_and_mutations();
	test_arguments();
	return wrt_finish();
}
