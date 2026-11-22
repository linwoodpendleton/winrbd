/* SPDX-License-Identifier: MIT */
/*
 * test_client_sec_mem.c (ctest client.sec.mem) - the memory plan of secure mode in the engine (docs/design/core-architecture.md 34.2, 36, 37; module
 * client-glue-sec).
 *
 * The rule: when the policy may end in secure (wri_m2_policy_may_secure over mode_policy and mode_policy_osd) the arena holds one wri_m2s_slot and one
 * bounce buffer of sec_tx_chunk bytes for EVERY connection slot, and nothing else changes (the bulk is the same); under CRC_ONLY none of it exists and
 * sec_tx_chunk is not looked at. What is checked:
 *
 *   exactness   for the three profiles (iPXE and kernel with the maps and the OSD client, harness with the maps) x the five policies x the mixed
 *               monitor / OSD pairs x random sec_tx_chunk and connection counts, and for 150 random legal configurations: wr_client_mem_required
 *               equals the bytes create consumes (wr_stats), at every base alignment, nothing beyond them is written, and the difference to the same
 *               configuration under CRC_ONLY is EXACTLY align16(max_conns * sizeof(wri_m2s_slot)) + max_conns * sec_tx_chunk in the arena and 0 in the bulk;
 *   one byte    a region one byte too small (either one) is WR_E_BUDGET and leaves the host's memory exactly as it was
 *   crc only    costs the three pointers of the seam per connection and nothing else: the arena does not depend on sec_tx_chunk, on mode_policy_osd
 *               being CRC_ONLY or 0, or on any secure-mode constant, and one connection more costs exactly its slot and its three buffers
 *   validation  an unknown policy (0, 6, 255, on either role), a missing or bad sec_tx_chunk (0 with a secure policy; below 256; not a multiple of 16;
 *               also a bad one under CRC_ONLY) is WR_E_INVAL from both wr_client_mem_required and wr_client_create, before a byte of the regions is
 *               written; a size that cannot be planned is an error, not a wrap
 *   layout      the engine's slot array and bounce area sit inside the arena, 16-byte aligned, one slot and one chunk per connection, all in the
 *               region (the carve of slot i is the slot the connection i is handed, see client.sec.conn); destroy leaves the arena zero
 */
#include "wrt.h"

#include "core_budgets.h"
#include "wri_client.h"

#define PATTERN 0xa5u

static uint64_t g_rng = 0x2545f4914f6cdd1dull;

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

static int all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

static size_t up16(size_t n)
{
	return (n + 15u) & ~(size_t)15u;
}

/* ---- the profiles ------------------------------------------------------------------------------------------- */

typedef struct prof {
	const char *name;
	void (*profile)(wr_config *);
	wr_map_profile mp;
	int osd; /* maps and the OSD client (else the maps only) */
} prof;

static const prof g_prof[3] = {
	{"ipxe+maps+osd", wr_config_profile_ipxe, WR_MAPS_IPXE, 1},
	{"kernel+maps+osd", wr_config_profile_kernel, WR_MAPS_KERNEL, 1},
	{"harness+maps", wr_config_profile_harness, WR_MAPS_HARNESS, 0},
};

static void make_cfg(wr_config *cfg, const prof *p, uint8_t policy)
{
	p->profile(cfg);
	wr_config_enable_maps(cfg, p->mp);
	if (p->osd)
		wr_config_enable_osd(cfg, p->mp);
	wr_config_enable_secure(cfg, p->mp, policy);
}

static int may_secure(const wr_config *cfg)
{
	return cfg->mode_policy != WR_MODE_CRC_ONLY || (cfg->mode_policy_osd != 0u && cfg->mode_policy_osd != WR_MODE_CRC_ONLY);
}

/* The arena bytes secure mode adds for this configuration: the slot array (aligned up, the bounce array starts on a 16-byte boundary) and the bounces. */
static size_t sec_extra(const wr_config *cfg)
{
	if (!may_secure(cfg))
		return 0;
	return up16((size_t)cfg->max_conns * sizeof(wri_m2s_slot)) + (size_t)cfg->max_conns * cfg->sec_tx_chunk;
}

/* The configuration under CRC_ONLY: what the plan was before secure mode (sec_tx_chunk is then not looked at). */
static void as_crc_only(wr_config *cfg)
{
	cfg->mode_policy = WR_MODE_CRC_ONLY;
	cfg->mode_policy_osd = 0;
	cfg->sec_tx_chunk = 0;
}

/* mem_required == the bytes consumed at base alignment `off`; the secure difference is exactly sec_extra; nothing beyond the consumed bytes is written; the
 * engine's slot array and bounce area are where the plan puts them; destroy zeroes the arena. */
static void check_exact(const wr_config *cfg, size_t off, const char *label)
{
	wr_host_ops host;
	wr_cluster_spec sp;
	wr_mem_req req, base;
	wr_config crc = *cfg;
	region a, b;
	wr_client *c = NULL;
	wr_stats st;
	uint32_t i;
	int zero_ok = 1;

	make_host(&host);
	make_spec(&sp);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(cfg, &req));
	as_crc_only(&crc);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&crc, &base));
	WRT_CHECK_U64(req.arena, base.arena + sec_extra(cfg)); /* exactly the slots and the bounce buffers, nothing else moved */
	WRT_CHECK_U64(req.bulk, base.bulk);
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
	/* a fresh engine has made no connection yet */
	WRT_CHECK(st.conns_secure == 0u && st.conns_crc == 0u && st.sec_failures == 0u);
	if (may_secure(cfg)) {
		WRT_CHECK(c->sec != NULL && c->sec_bounce != NULL && c->sec_chunk == cfg->sec_tx_chunk && c->n_slot == cfg->max_conns);
		if (c->sec != NULL && c->sec_bounce != NULL) {
			const uint8_t *lo = a.base, *hi = a.base + req.arena;
			const uint8_t *s0 = (const uint8_t *)c->sec, *s1 = (const uint8_t *)(c->sec + cfg->max_conns);

			WRT_CHECK(((uintptr_t)c->sec & 15u) == 0u && ((uintptr_t)c->sec_bounce & 15u) == 0u);
			WRT_CHECK(s0 >= lo && s1 <= hi);
			WRT_CHECK(c->sec_bounce >= s1 && c->sec_bounce + (size_t)cfg->max_conns * c->sec_chunk <= hi);
			WRT_CHECK(c->sec_bounce == (const uint8_t *)(((uintptr_t)s1 + 15u) & ~(uintptr_t)15u)); /* one chunk per connection, right behind the slots */
			/* every slot and bounce buffer starts as zero (the arena zeroes what it hands out, whatever the host's memory held); a connection is handed its
			 * slot at open, which erases it again */
			for (i = 0; i < cfg->max_conns * (unsigned)sizeof(wri_m2s_slot); i++)
				zero_ok &= s0[i] == 0u;
			for (i = 0; i < cfg->max_conns * cfg->sec_tx_chunk; i++)
				zero_ok &= c->sec_bounce[i] == 0u;
			WRT_CHECK(zero_ok);
		}
	} else {
		WRT_CHECK(c->sec == NULL && c->sec_bounce == NULL && c->sec_chunk == 0u);
	}
	wr_client_destroy(c);
	WRT_CHECK(all_zero(a.base, req.arena)); /* keys, slots and bounce buffers: the arena part in use is zero */
	free(a.raw);
	free(b.raw);
}

/* One byte short of either region: WR_E_BUDGET, the host's memory untouched. */
static void check_budget(const wr_config *cfg)
{
	wr_host_ops host;
	wr_cluster_spec sp;
	wr_mem_req req;
	region a, b;
	wr_client *c = (wr_client *)1;

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
	/* the secure part alone: a region that holds everything but the last byte of the bounce area */
	if (may_secure(cfg)) {
		WRT_CHECK_STATUS(WR_E_BUDGET, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size - 1u}, (wr_mem_region){b.base, b.size}, &c));
		WRT_CHECK(untouched(&a, 0));
	}
	WRT_CHECK_STATUS(WR_OK, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c));
	WRT_CHECK(c != NULL);
	wr_client_destroy(c);
	free(a.raw);
	free(b.raw);
}

/* ---- the matrix of the three profiles x the policies ---------------------------------------------------------- */

static void test_matrix(void)
{
	unsigned pi;
	uint8_t pol;

	for (pi = 0; pi < 3u; pi++) {
		for (pol = WR_MODE_CRC_ONLY; pol <= WR_MODE_STOCK; pol++) {
			wr_config cfg, crc;
			wr_mem_req a, b;
			size_t off;

			make_cfg(&cfg, &g_prof[pi], pol);
			crc = cfg;
			as_crc_only(&crc);
			WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &a));
			WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&crc, &b));
			if (pol == WR_MODE_CRC_ONLY) {
				WRT_CHECK_U64(a.arena, b.arena); /* the default costs nothing, though wr_config_enable_secure set the chunk */
			} else {
				WRT_CHECK(a.arena > b.arena);
				WRT_CHECK_U64(a.arena - b.arena, up16((size_t)cfg.max_conns * wri_m2s_slot_bytes()) + (size_t)cfg.max_conns * cfg.sec_tx_chunk);
			}
			printf("client.sec.mem %-16s policy %u: arena %9zu B (crc only %9zu B, +%8zu B = %u x (%zu + %u))\n", g_prof[pi].name, pol, a.arena, b.arena,
			       a.arena - b.arena, cfg.max_conns, wri_m2s_slot_bytes(), pol == WR_MODE_CRC_ONLY ? 0u : cfg.sec_tx_chunk);
			for (off = 0; off < 64u; off += pi == 2u ? 48u : 16u)
				check_exact(&cfg, off, g_prof[pi].name);
			check_budget(&cfg);
		}
		/* the mixed pairs: the monitor on one policy, the OSDs on another; secure slots exist when either may end in secure */
		{
			static const uint8_t mon[] = {WR_MODE_CRC_ONLY, WR_MODE_SECURE_ONLY, WR_MODE_CRC_FIRST, WR_MODE_CRC_ONLY, WR_MODE_STOCK, WR_MODE_CRC_ONLY};
			static const uint8_t osd[] = {WR_MODE_SECURE_ONLY, WR_MODE_CRC_ONLY, WR_MODE_STOCK, 0, WR_MODE_CRC_ONLY, WR_MODE_CRC_ONLY};
			unsigned k;

			for (k = 0; k < sizeof(mon); k++) {
				wr_config cfg;

				make_cfg(&cfg, &g_prof[pi], mon[k]);
				cfg.mode_policy_osd = osd[k];
				check_exact(&cfg, (size_t)(k % 4u) * 16u, g_prof[pi].name);
				WRT_CHECK(may_secure(&cfg) == wri_m2_policy_may_secure(cfg.mode_policy, cfg.mode_policy_osd));
			}
		}
	}
}

/* ---- crc only costs the three pointers -------------------------------------------------------------------------- */

static void test_crc_only(void)
{
	unsigned pi;
	wr_config cfg;
	wr_mem_req a, b;

	/* the seam of the secure codec is three pointers per connection: the connection's slot, the parser's and the queue's codec pointers */
	WRT_CHECK(sizeof(((wri_m2_conn *)0)->sec) == sizeof(void *));
	WRT_CHECK(sizeof(((wri_m2_rx *)0)->sx) == sizeof(void *));
	WRT_CHECK(sizeof(((wri_m2_txq *)0)->sx) == sizeof(void *));
	for (pi = 0; pi < 3u; pi++) {
		static const uint32_t chunks[] = {0u, 256u, 4096u, 65536u, 1000000u};
		unsigned k;
		wr_config base;

		make_cfg(&base, &g_prof[pi], WR_MODE_CRC_ONLY);
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&base, &a));
		for (k = 0; k < sizeof(chunks) / sizeof(chunks[0]); k++) {
			cfg = base;
			cfg.sec_tx_chunk = chunks[k]; /* any valid size, or none: not looked at, not allocated */
			WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &b));
			WRT_CHECK_U64(b.arena, a.arena);
			WRT_CHECK_U64(b.bulk, a.bulk);
		}
		cfg = base;
		cfg.mode_policy_osd = WR_MODE_CRC_ONLY; /* "the same" spelled out */
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &b));
		WRT_CHECK_U64(b.arena, a.arena);
	}
	/* one connection more costs exactly its slot (with the three pointers in it) and its three buffers; two keep the 16-byte rounding of the slot array out */
	wr_config_profile_ipxe(&cfg);
	{
		wr_config big = cfg;
		wri_layout lay;

		big.max_conns = (uint16_t)(cfg.max_conns + 2u);
		big.max_handshakes = cfg.max_handshakes;
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &a));
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&big, &b));
		WRT_CHECK_STATUS(WR_OK, wri_client_layout(&cfg, &lay));
		WRT_CHECK_U64(b.arena - a.arena, 2u * (sizeof(wri_cslot) + lay.ring + lay.ctl + lay.tx));
		/* and with a secure policy, two connections more cost two slots and two bounce buffers on top of that */
		cfg.max_conns = big.max_conns;
		wr_config_enable_secure(&cfg, WR_MAPS_IPXE, WR_MODE_SECURE_FIRST);
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &a));
		big.max_conns = (uint16_t)(cfg.max_conns + 2u);
		wr_config_enable_secure(&big, WR_MAPS_IPXE, WR_MODE_SECURE_FIRST);
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&big, &b));
		WRT_CHECK_U64(b.arena - a.arena, 2u * (sizeof(wri_cslot) + lay.ring + lay.ctl + lay.tx) + 2u * wri_m2s_slot_bytes() + 2u * cfg.sec_tx_chunk);
	}
}

/* ---- validation -------------------------------------------------------------------------------------------------- */

static void refused(const wr_config *cfg, wr_status want)
{
	wr_mem_req req;
	wr_host_ops host;
	wr_cluster_spec sp;
	region a, b;
	wr_client *c = NULL;

	req.arena = req.bulk = 77;
	WRT_CHECK_STATUS(want, wr_client_mem_required(cfg, &req));
	WRT_CHECK_U64(req.arena, 0);
	WRT_CHECK_U64(req.bulk, 0);
	make_host(&host);
	make_spec(&sp);
	region_new(&a, 1u << 20, 0);
	region_new(&b, 1u << 22, 0);
	WRT_CHECK_STATUS(want, wr_client_create(cfg, &host, &sp, (wr_mem_region){a.base, a.size}, (wr_mem_region){b.base, b.size}, &c));
	WRT_CHECK(c == NULL);
	WRT_CHECK(untouched(&a, 0) && untouched(&b, 0)); /* before a byte of the regions is written */
	free(a.raw);
	free(b.raw);
}

static void test_validation(void)
{
	static const uint8_t bad_policy[] = {0, 6, 7, 100, 255};
	static const uint32_t bad_chunk[] = {1, 15, 16, 240, 255, 257, 271, 4097, 4111, 65535};
	wr_config cfg;
	unsigned i, pi;
	wr_mem_req req;

	for (pi = 0; pi < 3u; pi++) {
		wr_config ok;

		make_cfg(&ok, &g_prof[pi], WR_MODE_STOCK);
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&ok, &req));
		for (i = 0; i < sizeof(bad_policy); i++) {
			cfg = ok;
			cfg.mode_policy = bad_policy[i]; /* the monitor's policy, with a good OSD policy */
			cfg.mode_policy_osd = 0;
			refused(&cfg, WR_E_INVAL);
			cfg = ok;
			cfg.mode_policy_osd = bad_policy[i] == 0 ? 6 : bad_policy[i]; /* the OSD's (0 means "the same" and is valid, so 6 stands in for it) */
			refused(&cfg, WR_E_INVAL);
			cfg = ok;
			as_crc_only(&cfg);
			cfg.mode_policy = bad_policy[i]; /* and no secure slots to hide behind: still a configuration error */
			refused(&cfg, WR_E_INVAL);
		}
		for (i = 0; i < sizeof(bad_chunk) / sizeof(bad_chunk[0]); i++) {
			if (bad_chunk[i] >= 256u && bad_chunk[i] % 16u == 0u)
				continue;
			cfg = ok;
			cfg.sec_tx_chunk = bad_chunk[i];
			refused(&cfg, WR_E_INVAL);
			cfg.mode_policy_osd = WR_MODE_SECURE_ONLY; /* the OSD role alone may end in secure: the same rule */
			cfg.mode_policy = WR_MODE_CRC_ONLY;
			refused(&cfg, WR_E_INVAL);
			as_crc_only(&cfg);
			cfg.sec_tx_chunk = bad_chunk[i]; /* a bad size is a bug in the host's configuration even where it is not used */
			refused(&cfg, WR_E_INVAL);
		}
		cfg = ok;
		cfg.sec_tx_chunk = 0; /* secure slots need a bounce buffer: 0 is not "the profile's value" here, it is refused, never a silent crc */
		refused(&cfg, WR_E_INVAL);
		cfg.mode_policy = WR_MODE_CRC_ONLY;
		cfg.mode_policy_osd = WR_MODE_STOCK;
		refused(&cfg, WR_E_INVAL);
		cfg = ok;
		cfg.sec_tx_chunk = 256u; /* the smallest and the biggest sizes that are fine */
		WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
		cfg.sec_tx_chunk = 0xfffffff0u;
		{
			wr_status st = wr_client_mem_required(&cfg, &req);

			WRT_CHECK(st == WR_OK || st == WR_E_OVERFLOW); /* 50 bounce buffers of 4 GiB: planned in 64 bits, or reported on 32; never wrapped */
			if (st == WR_OK)
				WRT_CHECK(req.arena > (size_t)cfg.max_conns * 0xfffffff0u);
		}
		cfg.sec_tx_chunk = 0xfffffff1u;
		WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	}
}

/* ---- random legal configurations ---------------------------------------------------------------------------------- */

static void test_random(void)
{
	unsigned i;

	for (i = 0; i < 150u; i++) {
		wr_config cfg;
		static const uint32_t sizes[] = {64, 100, 256, 1000, 4096, 5000, 16384};
		uint8_t pol = (uint8_t)(1u + rnd() % 5u);

		wr_config_profile_ipxe(&cfg); /* small buffers: the point is the plan, not the profile */
		cfg.max_conns = (uint16_t)(2u + rnd() % 14u);
		cfg.max_handshakes = (uint16_t)(1u + rnd() % cfg.max_conns);
		cfg.rx_buf_bytes = sizes[rnd() % 7u];
		cfg.ctl_buf_bytes = sizes[rnd() % 7u];
		cfg.preauth_cap = 256u + (uint32_t)(rnd() % 20000u);
		cfg.ticket_cap = 64u + (uint32_t)(rnd() % 4000u);
		cfg.tx_buf_bytes = 2u * (cfg.ticket_cap + WRI_CLIENT_AUTH_SLACK) + WRI_CLIENT_TX_FRAME + (uint32_t)(rnd() % 9000u);
		cfg.mon_msg_cap = 64u + (uint32_t)(rnd() % 100000u);
		cfg.mapmsg_queue = (uint16_t)(1u + rnd() % 4u);
		cfg.mode_policy = pol;
		cfg.mode_policy_osd = (uint8_t)(rnd() % 4u == 0u ? 1u + rnd() % 5u : 0u);
		cfg.sec_tx_chunk = (rnd() % 3u == 0u && pol == WR_MODE_CRC_ONLY && cfg.mode_policy_osd == 0u) ? 0u : 256u + 16u * (uint32_t)(rnd() % 4000u);
		if (i % 3u == 0u) { /* with the map module: odd slot sizes, any cache, pools 1..8 */
			static const uint16_t caches[] = {0, 1, 3, 32, 100, 4096};

			cfg.map_slot_bytes = 16u * 1024u + (uint32_t)(rnd() % 40000u);
			cfg.map_max_osd = 1u + (uint32_t)(rnd() % 5000u);
			cfg.map_pools = (uint16_t)(1u + rnd() % 8u);
			cfg.map_pg_cache = caches[rnd() % 6u];
			cfg.crush_work_max = 1u + (uint32_t)(rnd() % 100000u);
			cfg.map_verify_crc = (uint8_t)(rnd() & 1u);
			cfg.map_refetch_ms = (uint32_t)(rnd() % 5000u);
		}
		if (i % 6u == 0u && cfg.map_slot_bytes != 0u) { /* and the OSD client on top of the maps: its own connection count rule */
			wr_config osd;

			wr_config_profile_ipxe(&osd);
			wr_config_enable_maps(&osd, WR_MAPS_IPXE);
			wr_config_enable_osd(&osd, WR_MAPS_IPXE);
			osd.max_conns = (uint16_t)(osd.osd_sessions + 2u + rnd() % 4u);
			osd.max_handshakes = (uint16_t)(1u + rnd() % 3u);
			osd.mode_policy = cfg.mode_policy;
			osd.mode_policy_osd = cfg.mode_policy_osd;
			osd.sec_tx_chunk = cfg.sec_tx_chunk;
			cfg = osd;
		}
		check_exact(&cfg, (size_t)(rnd() % 4u) * 16u, "random");
	}
}

int main(void)
{
	test_matrix();
	test_crc_only();
	test_validation();
	test_random();
	return wrt_finish();
}
