/* SPDX-License-Identifier: MIT */
/*
 * test_map_skel.c - the skeleton of part B (OSD map, CRUSH, placement) keeps its promises.
 *
 * The modules of docs/design/core-architecture.md section 17 replace stubs and add code behind frozen headers; this test pins
 * what the skeleton itself guarantees until then and afterwards:
 *   - the new status codes exist with their documented numbers, names and texts;
 *   - the layouts the modules share (compact map, compact CRUSH region, tables) have their documented sizes, and the inline
 *     accessors of wri_crush.h and wri_osdmap.h read a hand-built region correctly;
 *   - the profiles leave the map module off, wr_config_enable_maps() fills the documented budgets, and the engine's footprint
 *     with maps on is the plain one plus the store's cache (arena) and its two slots (bulk), exactly (the glue module, wave 6);
 *   - the public map API: a NULL client and a client created without maps are refused with WR_E_INVAL, outputs cleared
 *     (the behaviour with maps on is test_client_map.c);
 *   - core/crush_ln/ holds Ceph's two log tables byte for byte (SHA-256 of the header) and its accessors return them.
 */
#include "wrt.h"
#include "winrbd.h"
#include "wri_hash.h"
#include "wri_crush_ln.h"
#include "wri_mapstore.h"

static void test_status_codes(void)
{
	WRT_CHECK_U64(-WR_E_MAP_NONE, 120);
	WRT_CHECK_U64(-WR_E_MAP_RESYNC, 127);
	WRT_CHECK_U64(-WR_E_POOL_NOT_FOUND, 140);
	WRT_CHECK_U64(-WR_E_POOL_UNSUPPORTED, 141);
	WRT_CHECK_U64(-WR_E_CRUSH_ENCODING, 160);
	WRT_CHECK_U64(-WR_E_CRUSH_WORK, 164);
	WRT_CHECK_U64(-WR_E_PLACE_UNMAPPABLE, 180);
	WRT_CHECK(strcmp(wr_status_name(WR_E_MAP_BUDGET), "WR_E_MAP_BUDGET") == 0);
	WRT_CHECK(strcmp(wr_status_name(WR_E_CRUSH_UNSUPPORTED), "WR_E_CRUSH_UNSUPPORTED") == 0);
	WRT_CHECK(strcmp(wr_strerror(WR_E_PLACE_UNMAPPABLE), "no usable OSD currently serves this placement group") == 0);
	WRT_CHECK(strlen(wr_strerror(WR_E_MAP_CRC)) > 8u);
}

static void test_layouts(void)
{
	WRT_CHECK_U64(sizeof(wri_osd_addr), 24);
	WRT_CHECK_U64(sizeof(wri_map_pool), 56);
	WRT_CHECK_U64(sizeof(wri_pgtab), 32);
	WRT_CHECK_U64(sizeof(wri_cbucket), 16);
	WRT_CHECK_U64(sizeof(wri_cstep), 12);
	WRT_CHECK_U64(sizeof(wri_crush), 56);
	WRT_CHECK_U64(sizeof(wri_pgc_entry), 152);
	WRT_CHECK(sizeof(wri_osdmap) % 4u == 0u);
	WRT_CHECK(WRI_REP_MAX == WR_MAP_REP_MAX);
	WRT_CHECK(WRI_POOL_F_EIO == WR_POOL_F_EIO && WRI_MAP_F_PAUSEWR == WR_MAP_F_PAUSEWR);
}

/* A compact CRUSH region built by hand: one straw2 bucket (id -1, items 3 and 4), a replicated rule, a rule of another type,
 * and a default choose_args set with a weight row and ids for the bucket. */
static void test_crush_accessors(void)
{
	union {
		uint8_t b[512];
		uint64_t align;
	} u;
	wri_crush *c = (wri_crush *)(void *)u.b;
	uint32_t off, boff, aoff, idx;
	const wri_cbucket *bk;
	const wri_cargs *a;
	const uint32_t *ix;
	wri_cargs_set *set;
	wri_cbucket *b;
	wri_cargs *ca;
	uint32_t *w;

	memset(&u, 0, sizeof(u));
	c->magic = WRI_CRUSH_MAGIC;
	c->max_buckets = 2;
	c->max_rules = 2;
	c->bucket_tab = (uint32_t)sizeof(wri_crush);
	c->rule_tab = c->bucket_tab + 8u;
	c->n_sets = 1;
	c->set_tab = c->rule_tab + 8u;
	off = c->set_tab + (uint32_t)sizeof(wri_cargs_set);
	idx = off;
	off += 8u;
	set = (wri_cargs_set *)(void *)(u.b + c->set_tab);
	set->pool = -1;
	set->index = idx;
	boff = off;
	b = (wri_cbucket *)(void *)(u.b + boff);
	b->id = -1;
	b->type = 1;
	b->alg = WRI_CRUSH_ALG_STRAW2;
	b->size = 2;
	((int32_t *)(void *)(b + 1))[0] = 3;
	((int32_t *)(void *)(b + 1))[1] = 4;
	w = (uint32_t *)(void *)(u.b + boff + 16u + 8u);
	w[0] = 0x10000u;
	w[1] = 0x20000u;
	off += 16u + 8u + 8u;
	((uint32_t *)(void *)(u.b + c->bucket_tab))[0] = boff;
	((uint32_t *)(void *)(u.b + c->rule_tab))[0] = off;
	((uint32_t *)(void *)(u.b + c->rule_tab))[1] = WRI_CRUSH_RULE_OTHER;
	((wri_crule *)(void *)(u.b + off))->nsteps = 1;
	off += 4u;
	((wri_cstep *)(void *)(u.b + off))->op = WRI_CRUSH_OP_TAKE;
	((wri_cstep *)(void *)(u.b + off))->arg1 = -1;
	off += 12u;
	aoff = off;
	ca = (wri_cargs *)(void *)(u.b + aoff);
	ca->n_pos = 1;
	ca->has_ids = 1;
	w = (uint32_t *)(void *)(ca + 1);
	w[0] = 7;
	w[1] = 9;
	((int32_t *)(void *)w)[2] = -5;
	((int32_t *)(void *)w)[3] = -6;
	off += 8u + 16u;
	((uint32_t *)(void *)(u.b + idx))[0] = aoff;
	c->bytes = off;

	bk = wri_crush_bucket(c, -1);
	WRT_CHECK(bk != NULL && bk->id == -1 && bk->size == 2);
	WRT_CHECK(wri_cbucket_items(bk)[0] == 3 && wri_cbucket_items(bk)[1] == 4);
	WRT_CHECK(wri_cbucket_w(bk)[0] == 0x10000u && wri_cbucket_w(bk)[1] == 0x20000u);
	WRT_CHECK(wri_crush_bucket(c, -2) == NULL); /* a hole */
	WRT_CHECK(wri_crush_bucket(c, -3) == NULL); /* past max_buckets */
	WRT_CHECK(wri_crush_bucket(c, 5) == NULL);  /* a device id */
	WRT_CHECK_U64(wri_crush_rule_kind(c, 0), 2);
	WRT_CHECK_U64(wri_crush_rule_kind(c, 1), 1);
	WRT_CHECK_U64(wri_crush_rule_kind(c, 2), 0);
	WRT_CHECK(wri_crush_rule(c, 0) != NULL && wri_crush_rule(c, 1) == NULL && wri_crush_rule(c, 7) == NULL);
	WRT_CHECK(wri_crule_steps(wri_crush_rule(c, 0))[0].op == WRI_CRUSH_OP_TAKE);
	ix = wri_crush_args_index(c, 42); /* no set keyed 42: the default set (-1) applies */
	a = wri_crush_args_of(c, ix, 0);
	WRT_CHECK(ix != NULL && a != NULL && wri_crush_args_of(c, ix, 1) == NULL);
	WRT_CHECK(wri_cargs_row(a, 2, 0)[1] == 9u && wri_cargs_row(a, 2, 5)[0] == 7u); /* the last row serves higher positions */
	WRT_CHECK(wri_cargs_ids(a, 2)[0] == -5 && wri_cargs_ids(a, 2)[1] == -6);
	set->pool = 3;
	WRT_CHECK(wri_crush_args_index(c, 3) != NULL && wri_crush_args_index(c, 42) == NULL);
}

static void test_config(void)
{
	wr_config plain, c;
	wr_mem_req a, b;

	wr_config_profile_ipxe(&plain);
	WRT_CHECK_U64(plain.map_slot_bytes, 0); /* maps are opt-in: a plain profile keeps raw delivery */
	WRT_CHECK_U64(sizeof(wr_config), 164);
	c = plain;
	wr_config_enable_maps(&c, WR_MAPS_IPXE);
	WRT_CHECK_U64(c.map_slot_bytes, 256u * 1024u);
	WRT_CHECK_U64(c.map_max_osd, 2048);
	WRT_CHECK_U64(c.map_pools, 2);
	WRT_CHECK_U64(c.map_pg_cache, 32);
	WRT_CHECK_U64(c.crush_work_max, 200000);
	WRT_CHECK_U64(c.map_verify_crc, 0);
	WRT_CHECK_U64(c.mon_msg_cap, plain.mon_msg_cap); /* the rest of the profile is untouched */
	wr_config_profile_kernel(&c);
	wr_config_enable_maps(&c, WR_MAPS_KERNEL);
	WRT_CHECK_U64(c.map_slot_bytes, 1024u * 1024u);
	WRT_CHECK_U64(c.map_max_osd, 8192);
	WRT_CHECK_U64(c.map_pools, 4);
	WRT_CHECK_U64(c.map_pg_cache, 256);
	WRT_CHECK_U64(c.map_verify_crc, 1);
	wr_config_profile_harness(&c);
	wr_config_enable_maps(&c, WR_MAPS_HARNESS);
	WRT_CHECK_U64(c.map_slot_bytes, 4u * 1024u * 1024u);
	WRT_CHECK_U64(c.map_max_osd, 32768);
	WRT_CHECK_U64(c.map_pools, 8);
	WRT_CHECK_U64(c.map_pg_cache, 4096);
	WRT_CHECK(c.map_max_osd <= WRI_MAP_OSD_HARD_MAX && c.map_pools <= WRI_MAP_POOLS_MAX);

	/* the glue (wave 6): maps on cost the two slots (bulk) and the placement cache (arena) and nothing else; maps off cost
	 * nothing but the store struct every client embeds (inert) */
	wr_config_profile_ipxe(&c);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&c, &a));
	wr_config_enable_maps(&c, WR_MAPS_IPXE);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&c, &b));
	WRT_CHECK_U64(b.bulk, a.bulk + 2u * 256u * 1024u);
	WRT_CHECK_U64(b.arena, a.arena + 32u * sizeof(wri_pgc_entry));
	c.map_pg_cache = 0;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&c, &b));
	WRT_CHECK_U64(b.arena, a.arena);
	c.map_slot_bytes = 0; /* back to plain, the other map fields do not matter */
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&c, &b));
	WRT_CHECK_U64(b.arena, a.arena);
	WRT_CHECK_U64(b.bulk, a.bulk);
}

static void test_public_stubs(void)
{
	wr_pool_h h = 5;
	wr_map_info mi;
	wr_pool_info pi;
	wr_target t;
	wr_addr ad;
	uint8_t up = 9;
	wr_object_id oid;
	wr_map_stats st;

	memset(&oid, 0, sizeof(oid));
	memset(&st, 0xff, sizeof(st));
	/* no client: WR_E_INVAL, every output cleared (a client without maps is the same, see test_client_map.c) */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_track(NULL, "rbd", &h));
	WRT_CHECK_U64(h, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_info(NULL, &mi));
	WRT_CHECK_U64(mi.epoch, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_info(NULL, 0, &pi));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_osd_addr(NULL, 0, &ad, &up));
	WRT_CHECK_U64(up, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target(NULL, 0, &oid, &t));
	WRT_CHECK(t.acting_primary == -1 && t.up_primary == -1);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target_pg(NULL, 0, 1, &t));
	wr_client_map_stats(NULL, &st);
	WRT_CHECK_U64(st.epoch, 0);
	WRT_CHECK_U64(st.cache_hits, 0);
}

static void hex_digest(const uint8_t d[32], char out[65])
{
	wrt_hex_encode(d, 32, out);
	out[64] = '\0';
}

static void test_crush_ln_tables(void)
{
	const int64_t *rh = wri_crush_ln_rh_lh(), *ll = wri_crush_ln_ll();
	FILE *f = fopen(WRT_VECTOR_DIR "/../../core/crush_ln/crush_ln_table.h", "rb");
	wri_sha256_ctx sc;
	uint8_t buf[4096], d[32];
	char hex[65];
	size_t n;

	WRT_CHECK(rh != NULL && ll != NULL);
	WRT_CHECK_U64((uint64_t)rh[0], 0x0001000000000000ull);
	WRT_CHECK_U64((uint64_t)rh[1], 0);
	WRT_CHECK_U64((uint64_t)rh[2], 0x0000fe03f80fe040ull);
	WRT_CHECK_U64((uint64_t)rh[256], 0x0000800000000000ull);
	WRT_CHECK_U64((uint64_t)rh[257], 0x0000ffff00000000ull); /* the deliberate last entry, crush note 3.4.2 */
	WRT_CHECK_U64((uint64_t)ll[0], 0);
	WRT_CHECK_U64((uint64_t)ll[1], 0x00000002e2a60a00ull);
	WRT_CHECK_U64((uint64_t)ll[255], 0x000002dced24f814ull);
	if (f == NULL) {
		fprintf(stderr, "map.skel: no source tree around the harness, table digest not checked\n");
		return;
	}
	wri_sha256_init(&sc);
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
		wri_sha256_update(&sc, buf, n);
	fclose(f);
	wri_sha256_final(&sc, d);
	hex_digest(d, hex);
	/* the digest of Ceph v20.2.5 src/crush/crush_ln_table.h, also written in core/crush_ln/README.md */
	WRT_CHECK(strcmp(hex, "9d0cdacacbb4a21da36f134368e41e835fca1d5d6058e6abebb85775339e1b1a") == 0);
}

int main(void)
{
	test_status_codes();
	test_layouts();
	test_crush_accessors();
	test_config();
	test_public_stubs();
	test_crush_ln_tables();
	return wrt_finish();
}
