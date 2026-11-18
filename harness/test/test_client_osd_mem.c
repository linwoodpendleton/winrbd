/* SPDX-License-Identifier: MIT */
/*
 * test_client_osd_mem.c - the memory plan and the configuration check of the OSD client inside the engine (module client-glue-osd;
 * core/src/client/wri_client_osd.c and wri_client_mem.c; docs/design/core-architecture.md 26).
 *
 *   exactness      wr_client_mem_required equals what wr_client_create consumes (arena_used / bulk_used), for the three profiles with maps and the OSD
 *                  client on, at every legal base alignment, and for random legal configurations (odd front caps, odd zombie sizes, any number of images,
 *                  requests, sessions, operations); nothing beyond the consumed bytes is written (pattern fill, guard bytes); the numbers are printed,
 *                  they are what the footprint rows of core/README.md and wr_config_enable_osd are tuned from
 *   budget         a region one byte too small (either one) is WR_E_BUDGET and leaves the host's memory exactly as it was
 *   validation     every OSD field of the configuration: the refused values (WR_E_INVAL) and the accepted edges, the fields that may be zero; a refused
 *                  configuration never touches the regions
 *   off            with osd_sessions == 0 the three engine pointers are NULL, nothing of the OSD client is planned or taken
 *   shape          after create the layer has the configured tables (white box: operation slots, images, requests, sessions, handles)
 */
#include "wrt.h"

#include "core_budgets.h"
#include "wri_client_osd.h"

#define PATTERN 0xa5u

static uint64_t g_rng = 0x9e3779b97f4a7c15ull;

static uint64_t rnd(void)
{
	g_rng ^= g_rng >> 12;
	g_rng ^= g_rng << 25;
	g_rng ^= g_rng >> 27;
	return g_rng * 0x2545f4914f6cdd1dull;
}

static wr_status h_random(void *ctx, uint8_t *out, size_t n)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < n; i++)
		out[i] = (uint8_t)(rnd() >> 56);
	return WR_OK;
}

static void make_host(wr_host_ops *h)
{
	memset(h, 0, sizeof(*h));
	h->size = (uint32_t)sizeof(*h);
	h->random = h_random;
}

static void make_spec(wr_cluster_spec *sp)
{
	uint8_t raw[32];
	size_t i;

	memset(sp, 0, sizeof(*sp));
	for (i = 0; i < sizeof(raw); i++)
		raw[i] = (uint8_t)(i * 5u + 1u);
	strcpy(sp->user, "client.winrbd");
	WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&sp->key, WR_KEY_TYPE_AES256K, raw, 32u));
	sp->n_mons = 1;
	sp->mons[0].family = WR_AF_IPV4;
	sp->mons[0].ip[0] = 10, sp->mons[0].ip[1] = 77, sp->mons[0].ip[3] = 10;
	sp->mons[0].port = 3300;
}

typedef struct region {
	uint8_t *raw, *base;
	size_t size;
} region;

static void region_new(region *r, size_t size, size_t off)
{
	uintptr_t p;

	r->raw = (uint8_t *)malloc(size + 192u);
	if (r->raw == NULL)
		abort();
	p = ((uintptr_t)r->raw + 63u) & ~(uintptr_t)63u;
	r->base = (uint8_t *)p + off;
	r->size = size;
	memset(r->base, (int)PATTERN, size + 64u); /* a guard of 64 bytes behind the region too */
}

static int untouched(const region *r, size_t from)
{
	size_t i;

	for (i = from; i < r->size + 64u; i++)
		if (r->base[i] != PATTERN)
			return 0;
	return 1;
}

/* The configurations: the profile with maps and the OSD client on. */
static void cfg_of(wr_config *cfg, unsigned which)
{
	switch (which) {
	case 0:
		wr_config_profile_ipxe(cfg);
		wr_config_enable_maps(cfg, WR_MAPS_IPXE);
		wr_config_enable_osd(cfg, WR_MAPS_IPXE);
		break;
	case 1:
		wr_config_profile_kernel(cfg);
		wr_config_enable_maps(cfg, WR_MAPS_KERNEL);
		wr_config_enable_osd(cfg, WR_MAPS_KERNEL);
		break;
	default:
		wr_config_profile_harness(cfg);
		wr_config_enable_maps(cfg, WR_MAPS_HARNESS);
		wr_config_enable_osd(cfg, WR_MAPS_HARNESS);
		break;
	}
}

static const char *const g_names[] = {"ipxe+maps+osd", "kernel+maps+osd", "harness+maps+osd"};

/* mem_required == bytes consumed at the base alignment `off`, nothing beyond is written, the layer has the shape of the configuration. */
static void check_exact(const wr_config *cfg, size_t off, const char *label)
{
	wr_host_ops host;
	wr_cluster_spec sp;
	wr_mem_req req;
	region a, b;
	wr_client *c = NULL;
	wr_stats st;

	make_host(&host);
	make_spec(&sp);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(cfg, &req));
	WRT_CHECK(req.arena != 0 && req.bulk != 0);
	region_new(&a, req.arena, off);
	region_new(&b, req.bulk, off);
	WRT_CHECK_STATUS(WR_OK, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c));
	if (c == NULL) {
		fprintf(stderr, "  (%s, off %zu) create failed\n", label, off);
		free(a.raw);
		free(b.raw);
		return;
	}
	wr_client_get_stats(c, &st);
	WRT_CHECK_U64(st.arena_used, req.arena);
	WRT_CHECK_U64(st.bulk_used, req.bulk);
	WRT_CHECK(untouched(&a, st.arena_used));
	WRT_CHECK(untouched(&b, st.bulk_used));
	WRT_CHECK(wr_client_get_state(c) == WR_CS_CREATED);
	if (cfg->osd_sessions != 0u) {
		WRT_CHECK(c->osd != NULL && c->rbd != NULL && c->og != NULL);
		if (c->osd != NULL && c->rbd != NULL && c->og != NULL) {
			WRT_CHECK_U64(c->osd->n_op, cfg->max_ops);
			WRT_CHECK_U64(c->osd->sess.n, cfg->osd_sessions);
			WRT_CHECK_U64(c->rbd->n_img, cfg->max_images);
			WRT_CHECK_U64(c->rbd->n_rq, cfg->max_reqs);
			WRT_CHECK_U64(c->og->n_h, cfg->max_images);
			WRT_CHECK_U64(c->og->n_hs, cfg->max_conns);
			WRT_CHECK_U64(c->osd->zcap, cfg->zombie_bytes);
			WRT_CHECK(c->rbd->osd == c->osd && c->osd == &c->og->osd && c->rbd == &c->og->rbd);
			WRT_CHECK_U64(c->n_slot, cfg->max_conns);
		}
	} else {
		WRT_CHECK(c->osd == NULL && c->rbd == NULL && c->og == NULL);
	}
	wr_client_destroy(c);
	free(a.raw);
	free(b.raw);
}

static void test_profiles(void)
{
	static const size_t arena_budget[3] = {WRB_IPXE_OSD_ARENA, WRB_KERNEL_OSD_ARENA, WRB_HARNESS_OSD_ARENA};
	static const size_t bulk_budget[3] = {WRB_IPXE_OSD_BULK, WRB_KERNEL_OSD_BULK, WRB_HARNESS_OSD_BULK};
	unsigned i;
	size_t off;

	for (i = 0; i < 3u; i++) {
		wr_config cfg, maps_only;
		wr_mem_req req, base;

		cfg_of(&cfg, i);
		maps_only = cfg;
		maps_only.osd_sessions = 0;
		maps_only.max_conns = i == 0u ? 4 : i == 1u ? 8 : 16; /* the profiles' own counts */
		maps_only.max_handshakes = i == 0u ? 1 : i == 1u ? 2 : 4;
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&maps_only, &base));
		printf("footprint %-17s arena %9zu B (%8.1f KiB)  bulk %10zu B (%9.1f KiB)  [OSD client alone: arena %zu B, bulk %zu B]\n", g_names[i],
		       req.arena, (double)req.arena / 1024.0, req.bulk, (double)req.bulk / 1024.0, req.arena - base.arena, req.bulk - base.bulk);
		WRT_CHECK(req.arena <= arena_budget[i]);
		WRT_CHECK(req.bulk <= bulk_budget[i]);
		/* the bulk grows by exactly the zombie area */
		WRT_CHECK_U64(req.bulk, base.bulk + cfg.zombie_bytes);
		for (off = 0; off < 64u; off += 16u) {
			if (i == 2u && off != 0u && off != 48u)
				continue; /* the harness profile is big: two alignments are enough */
			check_exact(&cfg, off, g_names[i]);
		}
		/* the same profile with the OSD client off is the engine it was */
		check_exact(&maps_only, 0, "maps only");
	}
}

/* Random legal configurations: the plan stays exact. */
static void test_random_configs(void)
{
	unsigned i;

	for (i = 0; i < 60u; i++) {
		wr_config cfg;
		static const uint32_t cbytes[] = {64, 100, 1000, 5000, 16384};

		cfg_of(&cfg, 0);
		cfg.osd_sessions = (uint16_t)(1u + rnd() % 8u);
		cfg.max_conns = (uint16_t)(cfg.osd_sessions + 2u + rnd() % 4u);
		cfg.max_handshakes = (uint16_t)(1u + rnd() % cfg.max_conns);
		cfg.ctl_ops = (uint16_t)(1u + rnd() % 4u);
		cfg.max_ops = (uint16_t)(cfg.ctl_ops + 1u + rnd() % 100u);
		cfg.max_images = (uint16_t)(1u + rnd() % 5u);
		cfg.max_reqs = (uint16_t)(1u + rnd() % 40u);
		cfg.max_snaps = (uint16_t)(rnd() % 40u);
		cfg.backoff_slots = (uint16_t)(1u + rnd() % 40u);
		cfg.osd_front_cap = (uint16_t)(WRI_OSD_FRONT_MIN + rnd() % 3000u);
		cfg.tx_buf_bytes = 2u * (cfg.ticket_cap + WRI_CLIENT_AUTH_SLACK) + WRI_CLIENT_TX_FRAME + cfg.osd_front_cap + (uint32_t)(rnd() % 3000u);
		cfg.rx_buf_bytes = cbytes[rnd() % 5u];
		cfg.op_bytes_max = 4096u + (uint32_t)(rnd() % 900000u);
		cfg.inflight_bytes_max = cfg.op_bytes_max + (uint32_t)(rnd() % 3000000u);
		cfg.zombie_bytes = (uint32_t)(rnd() % 3u == 0u ? 0u : rnd() % 300000u);
		cfg.op_timeout_ms = 1u + (uint32_t)(rnd() % 20000u);
		cfg.osd_connect_timeout_ms = 1u + (uint32_t)(rnd() % 5000u);
		cfg.hdr_refresh_ms = (uint32_t)(rnd() % 3u == 0u ? 0u : rnd() % 60000u);
		cfg.img_ctl_bytes = 256u + (uint32_t)(rnd() % 9000u);
		cfg.map_stale_ms = (uint32_t)(rnd() % 3u == 0u ? 0u : rnd() % 60000u);
		cfg.osd_idle_ms = (uint32_t)(rnd() % 2u == 0u ? 0u : rnd() % 60000u);
		cfg.osd_flags = (uint8_t)(rnd() & 7u);
		if (i % 3u == 0u) { /* odd map budgets as well */
			cfg.map_slot_bytes = 16u * 1024u + (uint32_t)(rnd() % 40000u);
			cfg.map_pg_cache = (uint16_t)(rnd() % 100u);
			cfg.map_pools = (uint16_t)(1u + rnd() % 8u);
			cfg.map_max_osd = 1u + (uint32_t)(rnd() % 5000u);
		}
		check_exact(&cfg, (size_t)(rnd() % 4u) * 16u, "random+osd");
	}
}

/* Regions one byte too small: BUDGET, and the host's memory is exactly as it was. */
static void test_budget(const wr_config *cfg, const char *label)
{
	wr_host_ops host;
	wr_cluster_spec sp;
	wr_mem_req req;
	region a, b;
	wr_client *c = (wr_client *)1;

	(void)label;
	make_host(&host);
	make_spec(&sp);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(cfg, &req));
	region_new(&a, req.arena, 0);
	region_new(&b, req.bulk, 0);
	WRT_CHECK_STATUS(WR_E_BUDGET, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size - 1u}, (wr_mem_region){b.base, b.size}, &c));
	WRT_CHECK(c == NULL);
	WRT_CHECK(untouched(&a, 0) && untouched(&b, 0));
	WRT_CHECK_STATUS(WR_E_BUDGET, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size - 1u}, &c));
	WRT_CHECK(c == NULL);
	WRT_CHECK(untouched(&a, 0) && untouched(&b, 0));
	WRT_CHECK_STATUS(WR_E_BUDGET, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size / 2u}, (wr_mem_region){b.base, b.size / 2u}, &c));
	WRT_CHECK(untouched(&a, 0) && untouched(&b, 0));
	/* the exact sizes work */
	WRT_CHECK_STATUS(WR_OK, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c));
	WRT_CHECK(c != NULL);
	wr_client_destroy(c);
	free(a.raw);
	free(b.raw);
}

/* One mutation of a good configuration and the status of wr_client_mem_required for it. */
static wr_status mem_st(const wr_config *cfg)
{
	wr_mem_req req;

	req.arena = req.bulk = 77;
	return wr_client_mem_required(cfg, &req);
}

#define CHECK_REFUSED(field_assign)                  \
	do {                                         \
		wr_config m_;                        \
		wr_mem_req r_;                       \
		cfg_of(&m_, 0);                      \
		field_assign;                        \
		r_.arena = r_.bulk = 77;             \
		WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&m_, &r_)); \
		WRT_CHECK(r_.arena == 0u && r_.bulk == 0u); /* outputs cleared on every failure */ \
	} while (0)

#define CHECK_ACCEPTED(field_assign)                 \
	do {                                         \
		wr_config m_;                        \
		cfg_of(&m_, 0);                      \
		field_assign;                        \
		WRT_CHECK_STATUS(WR_OK, mem_st(&m_)); \
	} while (0)

static void test_validation(void)
{
	wr_config good;
	wr_host_ops host;
	wr_cluster_spec sp;
	wr_mem_req req;
	region a, b;
	wr_client *c = (wr_client *)1;
	uint32_t seg;

	cfg_of(&good, 0);
	WRT_CHECK_STATUS(WR_OK, mem_st(&good));
	seg = wri_client_seg_cap(&good);
	WRT_CHECK_U64(seg, 4u * 1024u * 1024u); /* 4 x mon_msg_cap */

	CHECK_REFUSED(m_.map_slot_bytes = 0);                   /* the layer needs the map module */
	CHECK_REFUSED(m_.max_conns = (uint16_t)(m_.osd_sessions + 1u)); /* the monitor keeps its two slots */
	CHECK_ACCEPTED(m_.max_conns = (uint16_t)(m_.osd_sessions + 2u));
	CHECK_ACCEPTED(m_.max_conns = (uint16_t)(m_.osd_sessions + 2u); m_.max_handshakes = m_.max_conns);
	CHECK_REFUSED(m_.max_conns = 1025; m_.osd_sessions = 1023); /* above the engine's table limit */
	CHECK_REFUSED(m_.max_ops = m_.ctl_ops);
	CHECK_REFUSED(m_.ctl_ops = 0);
	CHECK_ACCEPTED(m_.max_ops = (uint16_t)(m_.ctl_ops + 1u));
	CHECK_ACCEPTED(m_.max_ops = 65535);
	CHECK_REFUSED(m_.op_bytes_max = seg + 1u; m_.inflight_bytes_max = seg + 1u);
	CHECK_ACCEPTED(m_.op_bytes_max = seg; m_.inflight_bytes_max = seg);
	CHECK_REFUSED(m_.op_bytes_max = m_.inflight_bytes_max + 1u);
	CHECK_ACCEPTED(m_.op_bytes_max = m_.inflight_bytes_max);
	CHECK_REFUSED(m_.max_images = 0);
	CHECK_REFUSED(m_.max_reqs = 0);
	CHECK_REFUSED(m_.backoff_slots = 0);
	CHECK_REFUSED(m_.osd_front_cap = 0);
	CHECK_REFUSED(m_.osd_front_cap = (uint16_t)(WRI_OSD_FRONT_MIN - 1u));
	CHECK_ACCEPTED(m_.osd_front_cap = (uint16_t)WRI_OSD_FRONT_MIN);
	CHECK_REFUSED(m_.op_bytes_max = 0);
	CHECK_REFUSED(m_.inflight_bytes_max = 0);
	CHECK_REFUSED(m_.op_timeout_ms = 0);
	CHECK_REFUSED(m_.osd_connect_timeout_ms = 0);
	CHECK_REFUSED(m_.img_ctl_bytes = 0);
	/* the encode buffer must hold an OSD request front */
	CHECK_REFUSED(m_.osd_front_cap = 8000; m_.tx_buf_bytes = 8192);
	CHECK_ACCEPTED(m_.osd_front_cap = 4000; m_.tx_buf_bytes = 8192);
	/* what may be zero: "never" or "none" */
	CHECK_ACCEPTED(m_.max_snaps = 0);
	CHECK_ACCEPTED(m_.zombie_bytes = 0);
	CHECK_ACCEPTED(m_.hdr_refresh_ms = 0);
	CHECK_ACCEPTED(m_.map_stale_ms = 0);
	CHECK_ACCEPTED(m_.osd_idle_ms = 0);
	CHECK_ACCEPTED(m_.osd_flags = 0xff);
	/* the engine's own limits still apply */
	CHECK_REFUSED(m_.max_handshakes = 0);
	CHECK_REFUSED(m_.osd_sessions = 3; m_.max_conns = 4);

	/* a refused configuration never gets as far as the regions */
	{
		wr_config bad = good;

		bad.ctl_ops = 0;
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&good, &req));
		make_host(&host);
		make_spec(&sp);
		region_new(&a, req.arena, 0);
		region_new(&b, req.bulk, 0);
		WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&bad, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c));
		WRT_CHECK(c == NULL);
		WRT_CHECK(untouched(&a, 0) && untouched(&b, 0));
		free(a.raw);
		free(b.raw);
	}
}

/* Zero is a working value where it is allowed: a client with no zombie area, no snapshots in a context and no refresh is created and runs. */
static void test_zero_edges(void)
{
	wr_config cfg;
	wr_host_ops host;
	wr_cluster_spec sp;
	wr_mem_req req;
	region a, b;
	wr_client *c = NULL;

	cfg_of(&cfg, 0);
	cfg.zombie_bytes = 0;
	cfg.max_snaps = 0;
	cfg.hdr_refresh_ms = 0;
	cfg.map_stale_ms = 0;
	cfg.osd_idle_ms = 0;
	make_host(&host);
	make_spec(&sp);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	region_new(&a, req.arena, 0);
	region_new(&b, req.bulk, 0);
	WRT_CHECK_STATUS(WR_OK, wr_client_create(&cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c));
	WRT_CHECK(c != NULL && c->osd != NULL && c->osd->zbuf == NULL && c->osd->zcap == 0u);
	if (c != NULL) {
		wr_clock now;
		wr_run_result rr;
		wr_osd_stats st;

		now.mono_ms = 1000;
		now.wall_ms = 1700000000000ull;
		rr = wr_client_run(c, &now, 0);
		(void)rr;
		wr_client_osd_stats(c, &st);
		WRT_CHECK(st.zombie_bytes_max == 0u && st.ops_inflight == 0u);
		wr_client_destroy(c);
	}
	free(a.raw);
	free(b.raw);
}

int main(void)
{
	wr_config cfg;
	unsigned i;

	test_profiles();
	test_random_configs();
	for (i = 0; i < 3u; i++) {
		cfg_of(&cfg, i);
		if (i != 2u) /* the harness profile has 75 MB of regions: the one-byte-short cases are the same code */
			test_budget(&cfg, g_names[i]);
	}
	wr_config_profile_ipxe(&cfg);
	wr_config_enable_maps(&cfg, WR_MAPS_IPXE);
	wr_config_enable_osd(&cfg, WR_MAPS_IPXE);
	cfg.zombie_bytes = 1;
	test_budget(&cfg, "odd zombie");
	test_validation();
	test_zero_edges();
	return wrt_finish();
}
