/* SPDX-License-Identifier: MIT */
/*
 * test_client_mem.c - the memory contract of the client engine: wr_client_mem_required is exact
 * (it equals the bytes wr_client_create consumes, for every legal base alignment), create validates
 * the regions before it touches them, and the three profiles stay inside the budgets of the
 * architecture document (section 5.2). The real byte counts are printed so the profile numbers in
 * core/src/client/wr_config.c can be tuned from them. The same for the three profiles with the OSD map module on
 * (wr_config_enable_maps: two map slots in the bulk, the placement cache in the arena), for random map budgets (slot sizes
 * that are not a multiple of 16, no cache) and for regions one byte too small. And with the OSD client and the image layer on
 * top of the maps (wr_config_enable_osd, module client-glue-osd): the footprint rows inside the raised budgets, the plan exact at
 * every base alignment, the bulk growing by exactly the zombie area. (The OSD client's own configuration checks and random plans are
 * test_client_osd_mem.c.)
 */
#include "wrt.h"

#include "core_budgets.h"
#include "wri_client.h"

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

static void make_spec(wr_cluster_spec *sp, unsigned type)
{
	uint8_t raw[32];
	size_t i;

	memset(sp, 0, sizeof(*sp));
	for (i = 0; i < sizeof(raw); i++)
		raw[i] = (uint8_t)(i * 5u + 1u);
	strcpy(sp->user, "client.winrbd");
	WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&sp->key, type, raw, type == WR_KEY_TYPE_AES ? 16u : 32u));
	sp->n_mons = 1;
	sp->mons[0].family = WR_AF_IPV4;
	sp->mons[0].ip[0] = 10, sp->mons[0].ip[1] = 77, sp->mons[0].ip[3] = 10;
	sp->mons[0].port = 3300;
}

/* A malloc'd block whose usable base sits `off` bytes (0, 16, 32, 48) past a 64-byte boundary. */
typedef struct region {
	uint8_t *raw; /* what malloc returned */
	uint8_t *base;
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

static void region_free(region *r)
{
	free(r->raw);
}

static int untouched(const region *r, size_t from)
{
	size_t i;

	for (i = from; i < r->size + 64u; i++)
		if (r->base[i] != PATTERN)
			return 0;
	return 1;
}

/* mem_required == bytes consumed, at the base alignment `off`; nothing beyond the consumed bytes is written. */
static void check_exact(const wr_config *cfg, size_t off, const char *label)
{
	wr_host_ops host;
	wr_cluster_spec sp;
	wr_mem_req req;
	region a, b;
	wr_client *c = NULL;
	wr_stats st;

	make_host(&host);
	make_spec(&sp, WR_KEY_TYPE_AES256K);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(cfg, &req));
	WRT_CHECK(req.arena != 0 && req.bulk != 0);
	region_new(&a, req.arena, off);
	region_new(&b, req.bulk, off);
	WRT_CHECK_STATUS(WR_OK, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c));
	if (c == NULL) {
		fprintf(stderr, "  (%s, off %zu) create failed\n", label, off);
		region_free(&a);
		region_free(&b);
		return;
	}
	wr_client_get_stats(c, &st);
	WRT_CHECK_U64(st.arena_used, req.arena);
	WRT_CHECK_U64(st.bulk_used, req.bulk);
	WRT_CHECK(untouched(&a, st.arena_used));
	WRT_CHECK(untouched(&b, st.bulk_used));
	WRT_CHECK(wr_client_get_state(c) == WR_CS_CREATED);
	wr_client_destroy(c);
	region_free(&a);
	region_free(&b);
}

static void profile_numbers(const char *name, const wr_config *cfg, size_t arena_budget, size_t bulk_budget)
{
	wr_mem_req req;
	size_t slots_bytes = sizeof(wri_cslot);

	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(cfg, &req));
	printf("footprint %-8s arena %8zu B (%7.1f KiB)  bulk %9zu B (%8.1f KiB)  [sizeof(wri_cslot) %zu, sizeof(wr_client) %zu]\n", name,
	       req.arena, (double)req.arena / 1024.0, req.bulk, (double)req.bulk / 1024.0, slots_bytes, sizeof(wr_client));
	if (arena_budget != 0) {
		WRT_CHECK(req.arena <= arena_budget);
		WRT_CHECK(req.bulk <= bulk_budget);
	}
}

static void test_profiles(void)
{
	wr_config ipxe, kern, harness;
	size_t off;

	wr_config_profile_ipxe(&ipxe);
	wr_config_profile_kernel(&kern);
	wr_config_profile_harness(&harness);
	/* budgets of the architecture document 5.2: iPXE arena about 80 KiB of connection buffers + 16 KiB of
	 * transcripts + keys and tickets (128 KiB with the structures), bulk one 1 MiB message slot plus the
	 * renewal buffers; the kernel profile 8 connections of 48 KiB + 2 handshakes of 32 KiB, bulk 2 x 4 MiB. */
	profile_numbers("ipxe", &ipxe, 128u * 1024u, 1024u * 1024u + 16u * 1024u);
	profile_numbers("kernel", &kern, 512u * 1024u, 8u * 1024u * 1024u + 32u * 1024u);
	profile_numbers("harness", &harness, 0, 0);
	for (off = 0; off < 64u; off += 16u) {
		check_exact(&ipxe, off, "ipxe");
		check_exact(&kern, off, "kernel");
	}
	check_exact(&harness, 0, "harness");
	check_exact(&harness, 48, "harness");
}

/* The three profiles with the map module on: footprint inside the raised budgets, the plan exact at every base alignment, and
 * the two map slots and the cache really come out of the regions (the sums differ from the plain profile by exactly them). */
static void test_profiles_maps(void)
{
	static const struct {
		const char *name;
		void (*profile)(wr_config *);
		wr_map_profile mp;
		size_t arena_budget, bulk_budget;
		size_t slot, cache;
	} rows[] = {
		{"ipxe+maps", wr_config_profile_ipxe, WR_MAPS_IPXE, WRB_IPXE_MAPS_ARENA, WRB_IPXE_MAPS_BULK, 256u * 1024u, 32u},
		{"kernel+maps", wr_config_profile_kernel, WR_MAPS_KERNEL, WRB_KERNEL_MAPS_ARENA, WRB_KERNEL_MAPS_BULK, 1024u * 1024u, 256u},
		{"harness+maps", wr_config_profile_harness, WR_MAPS_HARNESS, WRB_HARNESS_MAPS_ARENA, WRB_HARNESS_MAPS_BULK, 4u * 1024u * 1024u, 4096u},
	};
	size_t i, off;

	for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
		wr_config plain, cfg;
		wr_mem_req a, b;

		rows[i].profile(&plain);
		cfg = plain;
		wr_config_enable_maps(&cfg, rows[i].mp);
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&plain, &a));
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &b));
		profile_numbers(rows[i].name, &cfg, rows[i].arena_budget, rows[i].bulk_budget);
		WRT_CHECK_U64(b.bulk, a.bulk + 2u * rows[i].slot);
		WRT_CHECK_U64(b.arena, a.arena + rows[i].cache * 152u);
		for (off = 0; off < 64u; off += 16u)
			check_exact(&cfg, off, rows[i].name);
	}
}

/* The three profiles with the OSD client on: inside the budgets of core_budgets.h, exact at every base alignment, the bulk grows by the zombie area
 * and nothing else, the arena by more than the sessions' connection buffers (a connection of the profile costs what it did). */
static void test_profiles_osd(void)
{
	static const struct {
		const char *name;
		void (*profile)(wr_config *);
		wr_map_profile mp;
		size_t arena_budget, bulk_budget;
	} rows[] = {
		{"ipxe+maps+osd", wr_config_profile_ipxe, WR_MAPS_IPXE, WRB_IPXE_OSD_ARENA, WRB_IPXE_OSD_BULK},
		{"kernel+maps+osd", wr_config_profile_kernel, WR_MAPS_KERNEL, WRB_KERNEL_OSD_ARENA, WRB_KERNEL_OSD_BULK},
		{"harness+maps+osd", wr_config_profile_harness, WR_MAPS_HARNESS, WRB_HARNESS_OSD_ARENA, WRB_HARNESS_OSD_BULK},
	};
	size_t i, off;

	for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
		wr_config maps, cfg;
		wr_mem_req a, b;

		rows[i].profile(&maps);
		wr_config_enable_maps(&maps, rows[i].mp);
		cfg = maps;
		wr_config_enable_osd(&cfg, rows[i].mp);
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&maps, &a));
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &b));
		profile_numbers(rows[i].name, &cfg, rows[i].arena_budget, rows[i].bulk_budget);
		WRT_CHECK_U64(b.bulk, a.bulk + cfg.zombie_bytes);
		WRT_CHECK(b.arena > a.arena);
		for (off = 0; off < 64u; off += i == 2u ? 48u : 16u)
			check_exact(&cfg, off, rows[i].name);
	}
}

/* Random legal configurations: the plan stays exact. */
static void test_random_configs(void)
{
	unsigned i;

	for (i = 0; i < 60u; i++) {
		wr_config cfg;
		static const uint32_t sizes[] = {64, 100, 256, 1000, 4096, 5000, 16384};

		wr_config_profile_ipxe(&cfg);
		cfg.max_conns = (uint16_t)(2u + rnd() % 14u);
		cfg.max_handshakes = (uint16_t)(1u + rnd() % cfg.max_conns);
		cfg.rx_buf_bytes = sizes[rnd() % 7u];
		cfg.ctl_buf_bytes = sizes[rnd() % 7u];
		cfg.preauth_cap = 256u + (uint32_t)(rnd() % 20000u);
		cfg.ticket_cap = 64u + (uint32_t)(rnd() % 4000u);
		cfg.tx_buf_bytes = 2u * (cfg.ticket_cap + WRI_CLIENT_AUTH_SLACK) + WRI_CLIENT_TX_FRAME + (uint32_t)(rnd() % 9000u);
		cfg.mon_msg_cap = 64u + (uint32_t)(rnd() % 100000u);
		cfg.mapmsg_queue = (uint16_t)(1u + rnd() % 4u);
		check_exact(&cfg, (size_t)(rnd() % 4u) * 16u, "random");
		if (i % 2u == 0u) { /* and with the map module on: odd slot sizes (no multiple of 16), any cache, pools 1..8 */
			static const uint16_t caches[] = {0, 1, 3, 32, 100, 4096};

			cfg.map_slot_bytes = 16u * 1024u + (uint32_t)(rnd() % 40000u);
			cfg.map_max_osd = 1u + (uint32_t)(rnd() % 5000u);
			cfg.map_pools = (uint16_t)(1u + rnd() % 8u);
			cfg.map_pg_cache = caches[rnd() % 6u];
			cfg.crush_work_max = 1u + (uint32_t)(rnd() % 100000u);
			cfg.map_verify_crc = (uint8_t)(rnd() & 1u);
			cfg.map_refetch_ms = (uint32_t)(rnd() % 5000u);
			check_exact(&cfg, (size_t)(rnd() % 4u) * 16u, "random+maps");
		}
	}
}

/* Regions too small: BUDGET, and the host's memory is exactly as it was. */
static void test_budget(const wr_config *cfg, const char *label)
{
	wr_host_ops host;
	wr_cluster_spec sp;
	wr_mem_req req;
	region a, b;
	wr_client *c = (wr_client *)1;

	(void)label;
	make_host(&host);
	make_spec(&sp, WR_KEY_TYPE_AES);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(cfg, &req));
	region_new(&a, req.arena, 0);
	region_new(&b, req.bulk, 0);
	WRT_CHECK_STATUS(WR_E_BUDGET, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size - 1u}, (wr_mem_region){b.base, b.size}, &c));
	WRT_CHECK(c == NULL);
	WRT_CHECK(untouched(&a, 0) && untouched(&b, 0));
	WRT_CHECK_STATUS(WR_E_BUDGET, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size - 1u}, &c));
	WRT_CHECK(c == NULL);
	WRT_CHECK(untouched(&a, 0) && untouched(&b, 0));
	WRT_CHECK_STATUS(WR_E_BUDGET, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, 0}, (wr_mem_region){b.base, 0}, &c));
	WRT_CHECK(untouched(&a, 0) && untouched(&b, 0));
	/* the exact sizes work */
	WRT_CHECK_STATUS(WR_OK, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c));
	WRT_CHECK(c != NULL);
	wr_client_destroy(c);
	region_free(&a);
	region_free(&b);
}

/* Anything else that is wrong with the arguments is refused before the regions are written, too. */
static void test_refusals_leave_memory_alone(void)
{
	wr_config cfg;
	wr_host_ops host;
	wr_cluster_spec sp;
	wr_mem_req req;
	region a, b;
	wr_client *c = NULL;

	wr_config_profile_ipxe(&cfg);
	make_host(&host);
	make_spec(&sp, WR_KEY_TYPE_AES256K);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	region_new(&a, req.arena, 0);
	region_new(&b, req.bulk, 0);

	host.random = NULL;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c));
	make_host(&host);
	sp.key.len = 7; /* a key the engine cannot use */
	WRT_CHECK(wr_client_create(&cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c) != WR_OK);
	make_spec(&sp, WR_KEY_TYPE_AES256K);
	sp.n_mons = 0;
	WRT_CHECK_STATUS(WR_E_MON_NO_V2_ADDR, wr_client_create(&cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c));
	make_spec(&sp, WR_KEY_TYPE_AES256K);
	strcpy(sp.user, "client.");
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c));
	WRT_CHECK(c == NULL);
	WRT_CHECK(untouched(&a, 0) && untouched(&b, 0));
	region_free(&a);
	region_free(&b);
}

static void test_required_args(void)
{
	wr_config cfg;
	wr_mem_req req;

	wr_config_profile_kernel(&cfg);
	req.arena = req.bulk = 77;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(NULL, &req));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, NULL));
	cfg.abi++;
	WRT_CHECK_STATUS(WR_E_ABI, wr_client_mem_required(&cfg, &req));
	WRT_CHECK_U64(req.arena, 0);
	WRT_CHECK_U64(req.bulk, 0);
	wr_config_profile_kernel(&cfg);
	cfg.size--;
	WRT_CHECK_STATUS(WR_E_ABI, wr_client_mem_required(&cfg, &req));
	wr_config_profile_kernel(&cfg);
	cfg.max_conns = 1; /* a renewal needs a second connection */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	wr_config_profile_kernel(&cfg);
	cfg.max_handshakes = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	wr_config_profile_kernel(&cfg);
	cfg.mapmsg_queue = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	wr_config_profile_kernel(&cfg);
	cfg.mode_policy = 0; /* a policy that does not exist (a zeroed config): refused, never a silent crc */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	wr_config_profile_kernel(&cfg);
	cfg.tx_buf_bytes = 100; /* below the largest handshake frame */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	wr_config_profile_kernel(&cfg);
	/* the encode buffer must hold an authentication payload with a held ticket in its upper half (a reclaim after a
	 * reconnect): one byte short is refused, the exact size is accepted */
	cfg.tx_buf_bytes = 2u * (cfg.ticket_cap + WRI_CLIENT_AUTH_SLACK) + WRI_CLIENT_TX_FRAME - 1u;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	cfg.tx_buf_bytes += 1u;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	cfg.ticket_cap = 0xffffffffu; /* the sum does not wrap in 32 bits: refused, not accepted by accident */
	cfg.tx_buf_bytes = 0xffffffffu;
	WRT_CHECK(wr_client_mem_required(&cfg, &req) != WR_OK);
	wr_config_profile_kernel(&cfg);
	cfg.mon_msg_cap = 0xffffffffu; /* sizes that overflow a 32-bit size_t are reported, not wrapped */
	cfg.mapmsg_queue = 4;
	req.arena = req.bulk = 0;
	if (sizeof(size_t) == 4u)
		WRT_CHECK_STATUS(WR_E_OVERFLOW, wr_client_mem_required(&cfg, &req));
	else
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
}

int main(void)
{
	wr_config cfg;

	test_profiles();
	test_profiles_maps();
	test_profiles_osd();
	test_random_configs();
	wr_config_profile_ipxe(&cfg);
	test_budget(&cfg, "ipxe");
	wr_config_profile_kernel(&cfg);
	test_budget(&cfg, "kernel");
	wr_config_enable_maps(&cfg, WR_MAPS_KERNEL); /* one byte short of either region, with the map module on */
	test_budget(&cfg, "kernel+maps");
	wr_config_profile_ipxe(&cfg);
	wr_config_enable_maps(&cfg, WR_MAPS_IPXE);
	test_budget(&cfg, "ipxe+maps");
	wr_config_enable_osd(&cfg, WR_MAPS_IPXE);
	test_budget(&cfg, "ipxe+maps+osd"); /* the OSD client's blocks of both regions, one byte short */
	wr_config_profile_kernel(&cfg);
	wr_config_enable_maps(&cfg, WR_MAPS_KERNEL);
	wr_config_enable_osd(&cfg, WR_MAPS_KERNEL);
	test_budget(&cfg, "kernel+maps+osd");
	test_refusals_leave_memory_alone();
	test_required_args();
	return wrt_finish();
}
