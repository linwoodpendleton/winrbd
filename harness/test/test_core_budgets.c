/* SPDX-License-Identifier: MIT */
/*
 * test_core_budgets.c - the memory budgets of the three configuration profiles (docs/design/core-architecture.md
 * section 5.2) as a test.
 *
 * For each profile (ipxe, kernel, harness) it
 *   1. prints the footprint wr_client_mem_required announces (arena and bulk, with the per-connection breakdown) and
 *      fails if it exceeds the documented budget of the profile;
 *   2. runs a full session against the simulated monitor through the public pump API: login, subscriptions, a large
 *      map message (three quarters of the profile's message cap), a pushed epoch, a monitor restart and the recovery
 *      onto a new session;
 *   3. prints the high-water marks of every pool and buffer (connections, handshake slots, map message slots, receive
 *      ring, encode buffer, pre-auth transcripts, the largest map message front) next to their capacities and fails
 *      if one exceeds its capacity or if the engine took more memory than it announced.
 *
 * The rings and buffers are sampled white-box (wri_client_slot_of) after every pump round. The documented budgets are in
 * core_budgets.h (shared with test_core_docs, which checks that core/README.md says the same for the plain profiles; this
 * test checks the rows of the map-enabled profiles, see check_readme_rows).
 *
 * The three profiles are run three times: plain, with the OSD map module on, and with the OSD client and the image layer on top of it
 * (wr_config_enable_osd: the arena grows by the connections, the operation table, the sessions and the image tables, the bulk by the zombie
 * area; the engine without images does the same session as before, the OSD stage of every run finds nothing to do). The map run: (wr_config_enable_maps; the engine then consumes
 * the monitor's map messages itself, nothing is delivered raw, and the map slots and the placement cache are part of the exactly
 * sized regions). With maps on the session also runs against a clean monitor, where the epochs are adopted: epoch 42, then 43,
 * then again after a monitor restart.
 *
 * Memory discipline, checked for every profile (design section 5.1):
 *   - the regions handed to wr_client_create are EXACTLY the announced sizes, pre-filled with a byte pattern (so the engine
 *     cannot lean on zeroed memory) and surrounded by guard bands; after the session the guard bands must still hold the
 *     pattern (no write outside the region, ASan cannot see that inside one allocation);
 *   - after wr_client_destroy the whole arena is zero (keys, tickets and transcripts are wiped);
 *   - a map message whose front is larger than mon_msg_cap is never stored or delivered, never ends the session for
 *     good, and does not touch memory outside the regions either.
 */
#include "core_budgets.h"
#include "sim_mon_tc.h"
#include "wri_client.h"

#define MAXH 8u
#define TICK_MS 50u

#define GUARD 64u
#define NO_PAD 0xffffffffu /* host_new: the monitor's map message carries no pad (a clean cluster) */

typedef struct region {
	uint8_t *raw, *base;
	size_t size, total;
	uint8_t pat;
} region;

/* a 64-byte aligned region of exactly `size` bytes inside guard bands, all of it filled with `pat` */
static void region_init(region *r, size_t size, uint8_t pat)
{
	r->size = size;
	r->pat = pat;
	r->total = size + 2u * GUARD + 64u;
	r->raw = (uint8_t *)malloc(r->total);
	if (r->raw == NULL)
		abort();
	memset(r->raw, pat, r->total);
	r->base = (uint8_t *)(((uintptr_t)r->raw + GUARD + 63u) & ~(uintptr_t)63u);
}

/* every byte outside [base, base + size) still holds the pattern */
static int region_guards_intact(const region *r)
{
	size_t i, front = (size_t)(r->base - r->raw);

	for (i = 0; i < front; i++)
		if (r->raw[i] != r->pat)
			return 0;
	for (i = front + r->size; i < r->total; i++)
		if (r->raw[i] != r->pat)
			return 0;
	return 1;
}

static int region_all_zero(const region *r)
{
	size_t i;

	for (i = 0; i < r->size; i++)
		if (r->base[i] != 0)
			return 0;
	return 1;
}

typedef struct profile {
	const char *name;
	void (*fill)(wr_config *);
	size_t arena_budget, bulk_budget;
	int budgeted; /* 1: a product profile, the documented budget is part of the contract */
	int secure;   /* 1: a policy that may end in secure (STOCK): the session runs sealed, with a smaller map message (the simulator's cipher is slow) */
} profile;

typedef struct hw { /* high-water marks seen while the session ran */
	uint32_t ring, tx, pa_rx, pa_tx, map_front;
	uint32_t max_conns_live;
} hw;

typedef struct hconn {
	int used, connected, closing;
	wr_conn_id id;
	sim_mon_conn *sc;
} hconn;

typedef struct host {
	wr_config cfg;
	wr_host_ops ops;
	wr_cluster_spec spec;
	sim_mon_cfg scfg;
	sim_mon *sim;
	region arena, bulk;
	wr_mem_req req;
	wr_client *c;
	hconn hc[MAXH];
	uint64_t now, rng;
	hw w;
	unsigned n_maps, n_fatal, n_map_ev, n_mapmsg_ev;
	uint32_t last_map_epoch;
} host;

static void harness_profile(wr_config *c)
{
	wr_config_profile_harness(c);
}

static void ipxe_maps(wr_config *c)
{
	wr_config_profile_ipxe(c);
	wr_config_enable_maps(c, WR_MAPS_IPXE);
}

static void kernel_maps(wr_config *c)
{
	wr_config_profile_kernel(c);
	wr_config_enable_maps(c, WR_MAPS_KERNEL);
}

static void harness_maps(wr_config *c)
{
	wr_config_profile_harness(c);
	wr_config_enable_maps(c, WR_MAPS_HARNESS);
}

static void ipxe_osd(wr_config *c)
{
	ipxe_maps(c);
	wr_config_enable_osd(c, WR_MAPS_IPXE);
}

static void kernel_osd(wr_config *c)
{
	kernel_maps(c);
	wr_config_enable_osd(c, WR_MAPS_KERNEL);
}

static void harness_osd(wr_config *c)
{
	harness_maps(c);
	wr_config_enable_osd(c, WR_MAPS_HARNESS);
}

static void ipxe_osd_sec(wr_config *c)
{
	ipxe_osd(c);
	wr_config_enable_secure(c, WR_MAPS_IPXE, WR_MODE_STOCK);
}

static void kernel_osd_sec(wr_config *c)
{
	kernel_osd(c);
	wr_config_enable_secure(c, WR_MAPS_KERNEL, WR_MODE_STOCK);
}

static void harness_osd_sec(wr_config *c)
{
	harness_osd(c);
	wr_config_enable_secure(c, WR_MAPS_HARNESS, WR_MODE_STOCK);
}

static wr_status h_random(void *ctx, uint8_t *out, size_t n)
{
	host *h = (host *)ctx;
	size_t i;

	for (i = 0; i < n; i++) {
		h->rng ^= h->rng >> 12;
		h->rng ^= h->rng << 25;
		h->rng ^= h->rng >> 27;
		out[i] = (uint8_t)((h->rng * 0x2545f4914f6cdd1dull) >> 56);
	}
	return WR_OK;
}

/* pad_over_cap = 0: a map message of three quarters of the cap; else its front is that many bytes above the cap */
static host *host_new(const profile *pr, uint32_t pad_over_cap)
{
	host *h = (host *)calloc(1, sizeof(*h));
	uint32_t cap;

	if (h == NULL)
		abort();
	pr->fill(&h->cfg);
	cap = h->cfg.mon_msg_cap;
	h->rng = 0x0123456789abcdefull;
	h->now = 10000;
	h->ops.size = (uint32_t)sizeof(h->ops);
	h->ops.ctx = h;
	h->ops.random = h_random;

	mt_cfg(&h->scfg, WR_KEY_TYPE_AES256K);
	/* a map message of three quarters of the cap (at most 4 MiB so the harness profile stays quick): the front
	 * stays well formed, only a pad of zero bytes is added to the last map blob */
	h->scfg.osdmap_pad = cap / 4u * 3u;
	if (h->scfg.osdmap_pad > (4u << 20))
		h->scfg.osdmap_pad = 4u << 20;
	if (h->cfg.mode_policy != WR_MODE_CRC_ONLY && h->scfg.osdmap_pad > (128u << 10))
		h->scfg.osdmap_pad = 128u << 10; /* sealed by the simulator's reference cipher (about 1 MB/s): keep the secure rows quick */
	if (pad_over_cap == NO_PAD)
		h->scfg.osdmap_pad = 0;
	else if (pad_over_cap != 0)
		h->scfg.osdmap_pad = cap + pad_over_cap; /* the whole front (pad plus the maps) is above the cap */
	h->sim = sim_mon_new(&h->scfg);
	if (h->sim == NULL)
		abort();
	strcpy(h->spec.user, "client.winrbd");
	h->spec.key = h->scfg.key;
	h->spec.n_mons = 1;
	h->spec.mons[0].family = WR_AF_IPV4;
	h->spec.mons[0].ip[0] = 10, h->spec.mons[0].ip[1] = 77, h->spec.mons[0].ip[3] = 10;
	h->spec.mons[0].port = 3300;

	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&h->cfg, &h->req));
	region_init(&h->arena, h->req.arena, 0xA5u); /* exactly what was announced: not a byte of slack */
	region_init(&h->bulk, h->req.bulk, 0x5Au);
	WRT_CHECK_STATUS(WR_OK, wr_client_create(&h->cfg, &h->ops, &h->spec, (wr_mem_region){h->arena.base, h->req.arena},
						 (wr_mem_region){h->bulk.base, h->req.bulk}, &h->c));
	if (h->c == NULL)
		abort();
	return h;
}

static void host_free(host *h)
{
	unsigned i;

	wr_client_destroy(h->c);
	/* destroy wipes what it owns: no key, ticket or transcript survives in the arena */
	WRT_CHECK(region_all_zero(&h->arena));
	WRT_CHECK(region_guards_intact(&h->arena));
	WRT_CHECK(region_guards_intact(&h->bulk));
	for (i = 0; i < MAXH; i++)
		if (h->hc[i].used && h->hc[i].sc != NULL)
			sim_mon_conn_free(h->hc[i].sc);
	sim_mon_free(h->sim);
	free(h->arena.raw);
	free(h->bulk.raw);
	free(h);
}

static hconn *hc_find(host *h, wr_conn_id id)
{
	unsigned i;

	for (i = 0; i < MAXH; i++)
		if (h->hc[i].used && h->hc[i].id == id)
			return &h->hc[i];
	return NULL;
}

static void hc_end(host *h, hconn *hc, int err)
{
	if (hc->sc != NULL)
		sim_mon_conn_free(hc->sc);
	hc->sc = NULL;
	wr_conn_closed(h->c, hc->id, err);
	hc->used = 0;
}

static void sample(host *h, hconn *hc)
{
	wri_cslot *s = wri_client_slot_of(h->c, hc->id);

	if (s == NULL)
		return;
	if (s->conn.ring.len > h->w.ring)
		h->w.ring = s->conn.ring.len;
	if (s->conn.tx.used > h->w.tx)
		h->w.tx = s->conn.tx.used;
	if (s->conn.pa != NULL) {
		if (s->conn.pa->rx_len > h->w.pa_rx)
			h->w.pa_rx = s->conn.pa->rx_len;
		if (s->conn.pa->tx_len > h->w.pa_tx)
			h->w.pa_tx = s->conn.pa->tx_len;
	}
}

static void host_events(host *h)
{
	wr_event e;

	while (wr_client_next_event(h->c, &e)) {
		if (e.kind == WR_EV_FATAL)
			h->n_fatal++;
		if (e.kind == WR_EV_MAPMSG)
			h->n_mapmsg_ev++;
		if (e.kind == WR_EV_MAP) {
			h->n_map_ev++;
			h->last_map_epoch = e.epoch;
		}
	}
	for (;;) {
		wr_mapmsg m;

		if (!wr_client_mapmsg_peek(h->c, &m))
			break;
		if (m.front_len > h->w.map_front)
			h->w.map_front = (uint32_t)m.front_len;
		h->n_maps++;
		wr_client_mapmsg_release(h->c);
	}
}

static unsigned host_actions(host *h)
{
	wr_action a;
	unsigned n = 0, i;

	while (wr_client_next_action(h->c, &a)) {
		hconn *hc;

		n++;
		switch (a.kind) {
		case WR_ACT_CONNECT:
			for (i = 0; i < MAXH && h->hc[i].used; i++) {
			}
			WRT_CHECK(i < MAXH);
			if (i == MAXH)
				abort();
			memset(&h->hc[i], 0, sizeof(h->hc[i]));
			h->hc[i].used = 1;
			h->hc[i].id = a.conn;
			break;
		case WR_ACT_CLOSE:
			hc = hc_find(h, a.conn);
			WRT_CHECK(hc != NULL);
			if (hc != NULL)
				hc->closing = 1;
			break;
		default:
			break;
		}
	}
	return n;
}

static int host_io(host *h)
{
	unsigned i, live = 0;
	int progress = 0;

	for (i = 0; i < MAXH; i++) {
		hconn *hc = &h->hc[i];
		wr_iov iov[8];
		uint8_t *w = NULL;
		size_t n, k, sent = 0, room;

		if (!hc->used)
			continue;
		live++;
		if (hc->closing) {
			hc_end(h, hc, 0);
			progress = 1;
			continue;
		}
		if (!hc->connected) {
			hc->sc = sim_mon_accept(h->sim);
			WRT_CHECK(hc->sc != NULL);
			if (hc->sc == NULL)
				abort();
			wr_conn_connected(h->c, hc->id);
			hc->connected = 1;
			progress = 1;
		}
		sample(h, hc);
		n = wr_conn_tx_peek(h->c, hc->id, iov, 8);
		for (k = 0; k < n; k++) {
			(void)sim_mon_feed(hc->sc, iov[k].base, iov[k].len);
			sent += iov[k].len;
		}
		if (sent != 0) {
			wr_conn_tx_consume(h->c, hc->id, sent);
			progress = 1;
		}
		sample(h, hc);
		room = wr_conn_rx_window(h->c, hc->id, &w);
		if (room != 0) {
			n = sim_mon_drain(hc->sc, w, room);
			if (n != 0) {
				wr_conn_rx_commit(h->c, hc->id, n);
				progress = 1;
			}
		}
		sample(h, hc);
		if (hc->sc != NULL && sim_mon_closed(hc->sc)) {
			hc_end(h, hc, 0);
			progress = 1;
		}
	}
	if (live > h->w.max_conns_live)
		h->w.max_conns_live = live;
	return progress;
}

static void pump(host *h)
{
	unsigned guard;

	for (guard = 0; guard < 200000u; guard++) {
		wr_clock clk;
		wr_run_result r;
		unsigned acts;
		int io;

		clk.mono_ms = h->now;
		clk.wall_ms = 1700000000000ull + h->now;
		r = wr_client_run(h->c, &clk, 0);
		host_events(h);
		acts = host_actions(h);
		io = host_io(h);
		host_events(h);
		if (acts == 0 && !io && !r.more_work)
			return;
	}
	WRT_CHECK(0); /* the engine does not settle */
}

static int reach_active(host *h, uint64_t max_ms)
{
	uint64_t end = h->now + max_ms;

	pump(h);
	while (h->now < end && wr_client_get_state(h->c) != WR_CS_ACTIVE) {
		h->now += TICK_MS;
		pump(h);
	}
	return wr_client_get_state(h->c) == WR_CS_ACTIVE;
}

static void run_ms(host *h, uint64_t ms)
{
	uint64_t end = h->now + ms;

	pump(h);
	while (h->now < end) {
		h->now += TICK_MS;
		pump(h);
	}
}

static void line(const char *what, uint64_t hi, uint64_t cap)
{
	printf("    %-30s %10llu of %10llu  (%5.1f %%)\n", what, (unsigned long long)hi, (unsigned long long)cap,
	       cap != 0 ? 100.0 * (double)hi / (double)cap : 0.0);
}

static void check_profile(const profile *pr)
{
	host *h;
	wr_config cfg;
	wri_layout lay;
	wr_mem_req req;
	wr_stats st;
	wr_map_stats ms;
	hw *w;
	int maps;

	/* 1. the footprint */
	pr->fill(&cfg);
	maps = cfg.map_slot_bytes != 0u;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	WRT_CHECK_STATUS(WR_OK, wri_client_layout(&cfg, &lay));
	printf("profile %-8s footprint: arena %zu B (%.1f KiB), bulk %zu B (%.1f KiB)\n", pr->name, req.arena,
	       (double)req.arena / 1024.0, req.bulk, (double)req.bulk / 1024.0);
	printf("    per connection: ring %zu, control %zu, encode %zu; handshake slot: 2 x %zu; segment cap %u; "
	       "sizeof(wri_cslot) %zu, sizeof(wr_client) %zu\n",
	       lay.ring, lay.ctl, lay.tx, lay.pa_stride, lay.seg_cap_max, sizeof(wri_cslot), sizeof(wr_client));
	printf("    budget: arena <= %zu B, bulk <= %zu B%s\n", pr->arena_budget, pr->bulk_budget,
	       pr->budgeted ? "" : " (sanity cap, not a product profile)");
	if (req.arena > pr->arena_budget || req.bulk > pr->bulk_budget)
		fprintf(stderr, "  BUDGET OVERRUN: profile %s needs arena %zu / bulk %zu, budget %zu / %zu\n", pr->name,
			req.arena, req.bulk, pr->arena_budget, pr->bulk_budget);
	WRT_CHECK(req.arena <= pr->arena_budget);
	WRT_CHECK(req.bulk <= pr->bulk_budget);

	/* 2. a full session */
	h = host_new(pr, 0);
	WRT_CHECK(reach_active(h, 30000));
	run_ms(h, 3000);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
	if (maps)
		WRT_CHECK(h->n_maps == 0u && h->n_mapmsg_ev == 0u); /* the engine is the consumer: nothing is delivered raw */
	else
		WRT_CHECK(h->n_maps >= 2u); /* the monmap and the (large) first map message */
	WRT_CHECK(sim_mon_push_epoch(h->sim) == WR_OK);
	run_ms(h, 1000);
	sim_mon_restart(h->sim);
	WRT_CHECK(reach_active(h, 120000));
	run_ms(h, 3000);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
	WRT_CHECK(h->sim->n_logins >= 2u); /* the restart made a second session */

	/* 3. the high-water marks */
	w = &h->w;
	wr_client_get_stats(h->c, &st);
	wr_client_map_stats(h->c, &ms);
	if (maps) /* the largest front the store opened, the same figure the host's peeks give without maps */
		w->map_front = ms.msg_bytes_max > w->map_front ? ms.msg_bytes_max : w->map_front;
	printf("  session: %u logins, %u map messages, largest front %u B\n", h->sim->n_logins, h->n_maps, w->map_front);
	if (maps) {
		printf("  map store: epoch %u (newest seen %u), %u full / %u incremental / %u bad, %u re-requests, slot %u of %u B (high-water %u)\n",
		       ms.epoch, ms.newest_seen, ms.n_full, ms.n_inc, ms.n_bad, ms.n_resync, ms.slot_used, ms.slot_bytes, ms.slot_used_max);
		WRT_CHECK(ms.slot_used_max <= ms.slot_bytes);
		WRT_CHECK(ms.msg_bytes_max <= cfg.mon_msg_cap);
		WRT_CHECK_U64(h->n_mapmsg_ev, 0);
	}
	line("connections (pool)", st.conns_hiwater, cfg.max_conns);
	line("handshake slots (pool)", st.handshakes_hiwater, cfg.max_handshakes);
	line("map message slots (pool)", st.mapmsg_hiwater, cfg.mapmsg_queue);
	line("largest map front / mon_msg_cap", w->map_front, cfg.mon_msg_cap);
	line("receive ring / rx_buf_bytes", w->ring, cfg.rx_buf_bytes);
	line("encode buffer / tx_buf_bytes", w->tx, cfg.tx_buf_bytes);
	line("transcript received / preauth_cap", w->pa_rx, cfg.preauth_cap);
	line("transcript sent / preauth_cap", w->pa_tx, cfg.preauth_cap);
	line("arena taken / announced", st.arena_used, req.arena);
	line("bulk taken / announced", st.bulk_used, req.bulk);

	if (pr->secure) { /* STOCK offers [secure, crc] to the monitor and the simulator allows both: every session ran sealed, none in crc */
		WRT_CHECK(st.conns_secure >= 2u && st.conns_crc == 0u && st.sec_failures == 0u);
		printf("  modes: %u secure, %u crc connections, %u secure failures; secure state per connection %zu B + %u B bounce\n", st.conns_secure,
		       st.conns_crc, st.sec_failures, wri_m2s_slot_bytes(), cfg.sec_tx_chunk);
	} else {
		WRT_CHECK(st.conns_secure == 0u && st.conns_crc >= 2u && st.sec_failures == 0u);
	}
	WRT_CHECK_U64(st.arena_used, req.arena); /* nothing is taken after create, and create takes what it announced */
	WRT_CHECK_U64(st.bulk_used, req.bulk);
	WRT_CHECK(st.conns_hiwater >= 1u && st.conns_hiwater <= cfg.max_conns);
	WRT_CHECK(st.handshakes_hiwater >= 1u && st.handshakes_hiwater <= cfg.max_handshakes);
	WRT_CHECK(st.mapmsg_hiwater >= 1u && st.mapmsg_hiwater <= cfg.mapmsg_queue);
	WRT_CHECK(w->max_conns_live <= cfg.max_conns);
	WRT_CHECK(w->map_front >= h->scfg.osdmap_pad && w->map_front <= cfg.mon_msg_cap); /* the padded message got through, within the cap */
	WRT_CHECK(w->ring >= 1u && w->ring <= cfg.rx_buf_bytes);
	WRT_CHECK(w->tx >= 1u && w->tx <= cfg.tx_buf_bytes);
	WRT_CHECK(w->pa_rx >= 1u && w->pa_rx <= cfg.preauth_cap);
	WRT_CHECK(w->pa_tx >= 1u && w->pa_tx <= cfg.preauth_cap);
	/* headroom: no buffer that guards against a hostile peer may be the limit of an honest session */
	WRT_CHECK(w->pa_rx < cfg.preauth_cap / 2u);
	WRT_CHECK(w->tx < cfg.tx_buf_bytes);
	WRT_CHECK_U64(h->n_fatal, 0);
	WRT_CHECK(region_guards_intact(&h->arena) && region_guards_intact(&h->bulk));
	host_free(h);
}

/*
 * A map message whose front is above mon_msg_cap (the cap is the budget of one bulk slot): it must never be stored or
 * handed to the consumer, the engine must not give up (no FATAL), the session must be usable afterwards, and nothing
 * outside the two exactly sized regions may be written while the oversized bytes are read and thrown away.
 */
static void check_oversize(const profile *pr)
{
	host *h = host_new(pr, 16u * 1024u);
	wr_stats st;
	wr_config cfg;

	pr->fill(&cfg);
	WRT_CHECK(h->scfg.osdmap_pad > cfg.mon_msg_cap);
	WRT_CHECK(reach_active(h, 60000));
	run_ms(h, 5000);
	WRT_CHECK(reach_active(h, 120000));
	wr_client_get_stats(h->c, &st);
	printf("profile %-8s oversize front (%u B > cap %u B): %u logins, %u map messages delivered, largest front %u B\n",
	       pr->name, (unsigned)h->scfg.osdmap_pad, (unsigned)cfg.mon_msg_cap, h->sim->n_logins, h->n_maps,
	       h->w.map_front);
	WRT_CHECK(h->w.map_front <= cfg.mon_msg_cap); /* the oversized front never reached the consumer */
	if (cfg.map_slot_bytes != 0u) {
		wr_map_stats ms;

		wr_client_map_stats(h->c, &ms);
		WRT_CHECK(ms.msg_bytes_max <= cfg.mon_msg_cap && ms.epoch == 0u); /* nor the store: it never saw the map, there is none */
		WRT_CHECK(ms.n_msg_toobig >= 1u && ms.n_msg_bad == 0u); /* and the host can tell why it has no map */
		WRT_CHECK_U64(h->n_maps, 0);
	} else {
		WRT_CHECK(h->n_maps >= 1u); /* the monmap did */
	}
	WRT_CHECK_U64(h->n_fatal, 0);
	WRT_CHECK_U64(st.arena_used, h->req.arena);
	WRT_CHECK_U64(st.bulk_used, h->req.bulk);
	WRT_CHECK(h->w.ring <= cfg.rx_buf_bytes && h->w.tx <= cfg.tx_buf_bytes);
	WRT_CHECK(region_guards_intact(&h->arena) && region_guards_intact(&h->bulk));
	host_free(h);
}

/*
 * The map module against a clean monitor (no pad on the map message): the store adopts epoch 42, then 43 (pushed), keeps it
 * across a monitor restart, and answers placement queries on the way, all inside the exactly sized regions.
 */
static void check_maps_clean(const profile *pr)
{
	host *h = host_new(pr, NO_PAD);
	wr_pool_h p0 = 9, p1 = 9;
	wr_map_stats ms;
	wr_object_id oid;
	wr_target t;
	wr_stats st;
	uint8_t nm[6] = {'r', 'b', 'd', '_', 'x', 'y'};

	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, ".mgr", &p0));
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, "winrbd", &p1));
	WRT_CHECK(reach_active(h, 30000));
	run_ms(h, 3000);
	wr_client_map_stats(h->c, &ms);
	WRT_CHECK(ms.epoch == 42u && ms.n_full == 1u && ms.n_bad == 0u && ms.n_resync == 0u);
	WRT_CHECK_U64(h->last_map_epoch, 42);
	memset(&oid, 0, sizeof(oid));
	oid.name = nm;
	oid.name_len = sizeof(nm);
	WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, p1, &oid, &t));
	WRT_CHECK_U64(t.epoch, 42);
	WRT_CHECK(sim_mon_push_epoch(h->sim) == WR_OK);
	run_ms(h, 1000);
	wr_client_map_stats(h->c, &ms);
	WRT_CHECK(ms.epoch == 43u && ms.n_inc == 1u && ms.n_bad == 0u);
	WRT_CHECK_U64(h->last_map_epoch, 43);
	sim_mon_restart(h->sim);
	WRT_CHECK(reach_active(h, 120000));
	run_ms(h, 3000);
	wr_client_map_stats(h->c, &ms);
	WRT_CHECK(ms.epoch == 43u && ms.n_full == 1u && ms.n_resync == 0u && ms.n_bad == 0u); /* the map outlived the session */
	WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, p1, &oid, &t));
	WRT_CHECK_U64(t.epoch, 43);
	wr_client_get_stats(h->c, &st);
	printf("profile %-8s clean maps: epoch %u, slot %u of %u B (high-water %u), largest front %u B, cache %u hits / %u misses; arena %zu bulk %zu\n",
	       pr->name, ms.epoch, ms.slot_used, ms.slot_bytes, ms.slot_used_max, ms.msg_bytes_max, ms.cache_hits, ms.cache_misses,
	       (size_t)st.arena_used, (size_t)st.bulk_used);
	WRT_CHECK_U64(st.arena_used, h->req.arena);
	WRT_CHECK_U64(st.bulk_used, h->req.bulk);
	WRT_CHECK_U64(h->n_fatal, 0);
	WRT_CHECK(h->n_maps == 0u && h->n_mapmsg_ev == 0u);
	WRT_CHECK(region_guards_intact(&h->arena) && region_guards_intact(&h->bulk));
	host_free(h);
}

/* core/README.md carries a footprint row per map-enabled profile (the plain ones are checked by test_core_docs). */
static void readme_row(const char *doc, const char *label, void (*fill)(wr_config *), size_t arena_budget, size_t bulk_budget, int product)
{
	wr_config cfg;
	wr_mem_req req;
	char want[256], key[64];
	const char *row;

	fill(&cfg);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	snprintf(key, sizeof(key), "| `%s` |", label);
	row = strstr(doc, key);
	if (product)
		snprintf(want, sizeof(want), "| `%s` | %.0f KiB | %.0f KiB | %u KiB / %u KiB |", label, (double)req.arena / 1024.0,
			 (double)req.bulk / 1024.0, (unsigned)(arena_budget / 1024u), (unsigned)(bulk_budget / 1024u));
	else
		snprintf(want, sizeof(want), "| `%s` | %.1f MiB | %.0f MiB | (sanity cap %u MiB / %u MiB) |", label,
			 (double)req.arena / 1048576.0, (double)req.bulk / 1048576.0, (unsigned)(arena_budget / 1048576u),
			 (unsigned)(bulk_budget / 1048576u));
	WRT_CHECK(row != NULL);
	if (row == NULL) {
		fprintf(stderr, "core/README.md has no footprint row for %s; it should read: %s\n", label, want);
		return;
	}
	if (strncmp(row, want, strlen(want)) != 0) {
		const char *eol = strchr(row, '\n');

		fprintf(stderr, "core/README.md footprint row of %s is stale\n  has:    %.*s\n  should: %s\n", label,
			eol != NULL ? (int)(eol - row) : 80, row, want);
		WRT_CHECK(0);
	} else {
		WRT_CHECK(1);
	}
}

static void check_readme_rows(void)
{
	FILE *f = fopen(WRT_VECTOR_DIR "/../../core/README.md", "rb");
	char *doc;
	long n;

	if (f == NULL) {
		fprintf(stderr, "core.budgets: no source tree around the harness, README rows not checked\n");
		return;
	}
	if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET) != 0)
		abort();
	doc = (char *)malloc((size_t)n + 1u);
	if (doc == NULL || fread(doc, 1, (size_t)n, f) != (size_t)n)
		abort();
	doc[n] = '\0';
	fclose(f);
	readme_row(doc, "ipxe + maps", ipxe_maps, WRB_IPXE_MAPS_ARENA, WRB_IPXE_MAPS_BULK, 1);
	readme_row(doc, "kernel + maps", kernel_maps, WRB_KERNEL_MAPS_ARENA, WRB_KERNEL_MAPS_BULK, 1);
	readme_row(doc, "harness + maps", harness_maps, WRB_HARNESS_MAPS_ARENA, WRB_HARNESS_MAPS_BULK, 0);
	readme_row(doc, "ipxe + maps + osd", ipxe_osd, WRB_IPXE_OSD_ARENA, WRB_IPXE_OSD_BULK, 1);
	readme_row(doc, "kernel + maps + osd", kernel_osd, WRB_KERNEL_OSD_ARENA, WRB_KERNEL_OSD_BULK, 1);
	readme_row(doc, "harness + maps + osd", harness_osd, WRB_HARNESS_OSD_ARENA, WRB_HARNESS_OSD_BULK, 0);
	readme_row(doc, "ipxe + maps + osd + secure", ipxe_osd_sec, WRB_IPXE_OSD_SEC_ARENA, WRB_IPXE_OSD_BULK, 1);
	readme_row(doc, "kernel + maps + osd + secure", kernel_osd_sec, WRB_KERNEL_OSD_SEC_ARENA, WRB_KERNEL_OSD_BULK, 1);
	readme_row(doc, "harness + maps + osd + secure", harness_osd_sec, WRB_HARNESS_OSD_SEC_ARENA, WRB_HARNESS_OSD_BULK, 0);
	free(doc);
}

int main(void)
{
	static const profile profiles[] = {
		{"ipxe", wr_config_profile_ipxe, WRB_IPXE_ARENA, WRB_IPXE_BULK, 1, 0},
		{"kernel", wr_config_profile_kernel, WRB_KERNEL_ARENA, WRB_KERNEL_BULK, 1, 0},
		{"harness", harness_profile, WRB_HARNESS_ARENA, WRB_HARNESS_BULK, 0, 0},
		{"ipxe+maps", ipxe_maps, WRB_IPXE_MAPS_ARENA, WRB_IPXE_MAPS_BULK, 1, 0},
		{"kern+maps", kernel_maps, WRB_KERNEL_MAPS_ARENA, WRB_KERNEL_MAPS_BULK, 1, 0},
		{"harn+maps", harness_maps, WRB_HARNESS_MAPS_ARENA, WRB_HARNESS_MAPS_BULK, 0, 0},
		{"ipxe+osd", ipxe_osd, WRB_IPXE_OSD_ARENA, WRB_IPXE_OSD_BULK, 1, 0},
		{"kern+osd", kernel_osd, WRB_KERNEL_OSD_ARENA, WRB_KERNEL_OSD_BULK, 1, 0},
		{"harn+osd", harness_osd, WRB_HARNESS_OSD_ARENA, WRB_HARNESS_OSD_BULK, 0, 0},
		{"ipxe+osd+sec", ipxe_osd_sec, WRB_IPXE_OSD_SEC_ARENA, WRB_IPXE_OSD_BULK, 1, 1},
		{"kern+osd+sec", kernel_osd_sec, WRB_KERNEL_OSD_SEC_ARENA, WRB_KERNEL_OSD_BULK, 1, 1},
		{"harn+osd+sec", harness_osd_sec, WRB_HARNESS_OSD_SEC_ARENA, WRB_HARNESS_OSD_BULK, 0, 1},
	};
	size_t i;

	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++)
		check_profile(&profiles[i]);
	for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); i++)
		if (profiles[i].budgeted && !profiles[i].secure) /* a 4 MiB front sealed by the simulator's cipher is not worth the minutes: client.sec.* run the secure refusals */
			check_oversize(&profiles[i]);
	for (i = 3; i < sizeof(profiles) / sizeof(profiles[0]); i++)
		check_maps_clean(&profiles[i]);
	check_readme_rows();
	return wrt_finish();
}
