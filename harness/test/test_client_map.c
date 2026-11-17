/* SPDX-License-Identifier: MIT */
/*
 * test_client_map.c - the OSD map module inside the client engine (module client-glue; core/src/client/wri_client_map.c,
 * wr_map.c; docs/design/core-architecture.md 15.6 and 15.7), through the PUBLIC API only: a small host plays the Linux
 * loop against the simulated monitor, which serves the real lab chain of harness/vectors/osdmap (the full map of epoch 42
 * and the stored incrementals) from sim_mon_load_osdmap_vectors().
 *
 *   maps on: before the first map every query says WR_E_MAP_NONE; the first message holds the full map of epoch 42 and
 *     the 219 object names of placement-names-e42.json place exactly like `ceph osd map` did (target by object and by
 *     PG); map_info / pool_info / osd_addr agree with expected.json; no WR_EV_MAPMSG is ever raised and the raw peek
 *     is empty (one consumer);
 *   incrementals: a batch of eight epochs in one message is one WR_EV_MAP when the host drains once (coalesced), one
 *     per epoch when it drains after every run; the state at the end equals the monitor's own summary of that epoch;
 *   a gap (incrementals 45 and 46 on a client at 42): the held map keeps serving, one MMonSubscribe with start 0 goes
 *     out, WR_EV_MAP_RESYNC says why, the answer (a mixed message: the full map of 42, stale, and incrementals 43 to
 *     47) brings the client to 47; a second gap right away is rate-limited by map_refetch_ms;
 *   the first map that can never be decoded (budget): WR_EV_FATAL, state FAILED, queries say WR_E_MAP_NONE;
 *   the monitor session drops and comes back: queries keep answering during the hunt, the stream resumes from held + 1 (no
 *     full-map re-fetch), a new epoch is adopted afterwards;
 *   a pool tracked after the first map is resolved by the full map the engine asks for (a full map of the held epoch);
 *   maps off: raw delivery as before (WR_EV_MAPMSG, peek / release), the map API refuses with WR_E_INVAL;
 *   configuration: map_pools 1..8, slot >= 16 KiB, map_max_osd within the hard cap, a non-zero work budget;
 *   API contract: NULL and destroyed clients, empty and over-long names, the same name twice, a full table, outputs
 *     cleared on every failure.
 */
#include "sim_mon_tc.h"
#include "wri_client.h"
#include "wrt_mapgen.h"

/* in sim_mon_maps.c (sim_mon.h belongs to another module) */
wr_status sim_mon_load_osdmap_vectors(sim_mon *m, uint32_t newest, uint32_t last);

#define MAXH 4u
#define MAXEV 512u
#define TICK_MS 50u

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
	uint8_t *arena_raw, *bulk_raw;
	wr_client *c;
	hconn hc[MAXH];
	uint64_t now, rng;
	int drain_each; /* drain the event queue after every wr_client_run (else once per settled pump) */
	uint32_t budget; /* work budget of every wr_client_run (0 = the engine's default) */
	wr_event ev[MAXEV];
	unsigned n_ev, n_raw_peek, n_raw_osd, n_raw_mon;
	unsigned n_run;
} host;

static wrt_mg_line *g_inc; /* the 89 stored incrementals, by epoch - 1 */
static size_t g_ninc;

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

/* The configuration of every test: the harness profile with small messages and the iPXE map budgets (256 KiB slots). */
static void base_cfg(wr_config *cfg)
{
	wr_config_profile_harness(cfg);
	cfg->mon_msg_cap = 256u * 1024u;
	cfg->max_conns = 4;
	cfg->max_handshakes = 2;
	wr_config_enable_maps(cfg, WR_MAPS_IPXE);
}

static host *host_new(const wr_config *cfg, uint32_t newest, uint32_t last)
{
	host *h = (host *)calloc(1, sizeof(*h));
	wr_mem_req req;
	uintptr_t p;

	if (h == NULL)
		abort();
	h->cfg = *cfg;
	h->rng = 0x0123456789abcdefull;
	h->now = 10000;
	h->ops.size = (uint32_t)sizeof(h->ops);
	h->ops.ctx = h;
	h->ops.random = h_random;
	mt_cfg(&h->scfg, WR_KEY_TYPE_AES256K);
	h->sim = sim_mon_new(&h->scfg);
	if (h->sim == NULL)
		abort();
	if (newest != 0u)
		WRT_CHECK_STATUS(WR_OK, sim_mon_load_osdmap_vectors(h->sim, newest, last));
	strcpy(h->spec.user, "client.winrbd");
	h->spec.key = h->scfg.key;
	h->spec.n_mons = 1;
	h->spec.mons[0].family = WR_AF_IPV4;
	h->spec.mons[0].ip[0] = 10, h->spec.mons[0].ip[1] = 77, h->spec.mons[0].ip[3] = 10;
	h->spec.mons[0].port = 3300;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&h->cfg, &req));
	h->arena_raw = (uint8_t *)calloc(1, req.arena + 128u);
	h->bulk_raw = (uint8_t *)calloc(1, req.bulk + 128u);
	if (h->arena_raw == NULL || h->bulk_raw == NULL)
		abort();
	p = ((uintptr_t)h->arena_raw + 63u) & ~(uintptr_t)63u;
	WRT_CHECK_STATUS(WR_OK, wr_client_create(&h->cfg, &h->ops, &h->spec, (wr_mem_region){(void *)p, req.arena},
						 (wr_mem_region){(void *)(((uintptr_t)h->bulk_raw + 63u) & ~(uintptr_t)63u), req.bulk},
						 &h->c));
	if (h->c == NULL)
		abort();
	return h;
}

static void host_free(host *h)
{
	unsigned i;

	wr_client_destroy(h->c);
	for (i = 0; i < MAXH; i++)
		if (h->hc[i].used && h->hc[i].sc != NULL)
			sim_mon_conn_free(h->hc[i].sc);
	sim_mon_free(h->sim);
	free(h->arena_raw);
	free(h->bulk_raw);
	free(h);
}

/* ---- the pump ----------------------------------------------------------------------------------------- */

static void drain_events(host *h)
{
	wr_event e;
	wr_mapmsg m;

	while (wr_client_next_event(h->c, &e))
		if (h->n_ev < MAXEV)
			h->ev[h->n_ev++] = e;
	if (h->cfg.map_slot_bytes != 0u) { /* maps on: the engine is the only consumer, a peek has nothing to return (and is not looped on) */
		if (wr_client_mapmsg_peek(h->c, &m)) {
			h->n_raw_peek++;
			WRT_CHECK(0);
		}
		return;
	}
	while (wr_client_mapmsg_peek(h->c, &m)) { /* raw delivery */
		h->n_raw_peek++;
		h->n_raw_osd += m.kind == WR_MAPMSG_OSDMAP;
		h->n_raw_mon += m.kind == WR_MAPMSG_MONMAP;
		wr_client_mapmsg_release(h->c);
	}
}

static unsigned count_ev(const host *h, wr_ev_kind k)
{
	unsigned i, n = 0;

	for (i = 0; i < h->n_ev; i++)
		n += h->ev[i].kind == k;
	return n;
}

static const wr_event *last_ev(const host *h, wr_ev_kind k)
{
	unsigned i;

	for (i = h->n_ev; i > 0; i--)
		if (h->ev[i - 1u].kind == k)
			return &h->ev[i - 1u];
	return NULL;
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

static unsigned host_actions(host *h)
{
	wr_action a;
	unsigned n = 0, i;

	while (wr_client_next_action(h->c, &a)) {
		hconn *hc;

		n++;
		if (a.kind == WR_ACT_CONNECT) {
			for (i = 0; i < MAXH && h->hc[i].used; i++) {
			}
			if (i == MAXH)
				abort();
			memset(&h->hc[i], 0, sizeof(h->hc[i]));
			h->hc[i].used = 1;
			h->hc[i].id = a.conn;
		} else if (a.kind == WR_ACT_CLOSE) {
			hc = hc_find(h, a.conn);
			WRT_CHECK(hc != NULL);
			if (hc != NULL)
				hc->closing = 1;
		}
	}
	return n;
}

static int host_io(host *h)
{
	unsigned i;
	int progress = 0;

	for (i = 0; i < MAXH; i++) {
		hconn *hc = &h->hc[i];
		wr_iov iov[8];
		uint8_t *w = NULL;
		size_t n, k, sent = 0, room;

		if (!hc->used)
			continue;
		if (hc->closing) {
			hc_end(h, hc, 0);
			progress = 1;
			continue;
		}
		if (!hc->connected) {
			hc->sc = sim_mon_accept(h->sim);
			if (hc->sc == NULL)
				abort();
			wr_conn_connected(h->c, hc->id);
			hc->connected = 1;
			progress = 1;
		}
		n = wr_conn_tx_peek(h->c, hc->id, iov, 8);
		for (k = 0; k < n; k++) {
			(void)sim_mon_feed(hc->sc, iov[k].base, iov[k].len);
			sent += iov[k].len;
		}
		if (sent != 0) {
			wr_conn_tx_consume(h->c, hc->id, sent);
			progress = 1;
		}
		room = wr_conn_rx_window(h->c, hc->id, &w);
		if (room != 0) {
			n = sim_mon_drain(hc->sc, w, room);
			if (n != 0) {
				wr_conn_rx_commit(h->c, hc->id, n);
				progress = 1;
			}
		}
		if (hc->sc != NULL && sim_mon_closed(hc->sc)) {
			hc_end(h, hc, 0);
			progress = 1;
		}
	}
	return progress;
}

static void pump(host *h)
{
	unsigned guard;

	for (guard = 0; guard < 100000u; guard++) {
		wr_clock clk;
		wr_run_result r;
		unsigned acts;
		int io;

		clk.mono_ms = h->now;
		clk.wall_ms = 1700000000000ull + h->now;
		r = wr_client_run(h->c, &clk, h->budget);
		h->n_run++;
		if (h->drain_each)
			drain_events(h);
		acts = host_actions(h);
		io = host_io(h);
		if (acts == 0 && !io && !r.more_work) {
			drain_events(h);
			return;
		}
	}
	WRT_CHECK(0); /* the engine does not settle */
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

/* Pump in ticks until the held epoch is `epoch` (or the time is up); 1 if it is. */
static int run_to_epoch(host *h, uint32_t epoch, uint64_t max_ms)
{
	uint64_t end = h->now + max_ms;
	wr_map_info mi;

	pump(h);
	while (h->now < end) {
		if (wr_client_map_info(h->c, &mi) == WR_OK && mi.epoch == epoch)
			return 1;
		h->now += TICK_MS;
		pump(h);
	}
	return wr_client_map_info(h->c, &mi) == WR_OK && mi.epoch == epoch;
}

static sim_mon_conn *live_conn(host *h)
{
	unsigned i;

	for (i = 0; i < MAXH; i++)
		if (h->hc[i].used && h->hc[i].connected && h->hc[i].sc != NULL && !sim_mon_closed(h->hc[i].sc))
			return h->hc[i].sc;
	return NULL;
}

static uint32_t total_subscribes(const host *h)
{
	return h->sim->n_subscribe;
}

/* ---- the monitor's own summary of an epoch (expected.json) -------------------------------------------- */

static void check_vs_expected(host *h, uint32_t epoch)
{
	wrt_json j;
	wrt_tok e;
	char key[16];
	wr_map_info mi;
	int ok = 0;
	size_t i, n, up = 0;
	wrt_tok st;

	WRT_CHECK(wrt_json_load_vec(&j, "osdmap/expected.json") == 0);
	snprintf(key, sizeof(key), "%u", (unsigned)epoch);
	e = wrt_json_get(&j, wrt_json_get(&j, wrt_json_root(&j), "chain"), key);
	WRT_CHECK(e != WRT_NONE);
	WRT_CHECK_STATUS(WR_OK, wr_client_map_info(h->c, &mi));
	WRT_CHECK_U64(mi.epoch, epoch);
	WRT_CHECK_U64(mi.flags, (uint64_t)wrt_json_int(&j, wrt_json_get(&j, e, "flags"), &ok));
	WRT_CHECK_U64(mi.max_osd, (uint64_t)wrt_json_int(&j, wrt_json_get(&j, e, "max_osd"), &ok));
	st = wrt_json_get(&j, e, "osd_state");
	n = wrt_json_count(&j, st);
	for (i = 0; i < n; i++)
		up += ((uint64_t)wrt_json_int(&j, wrt_json_at(&j, st, i), &ok) & 3u) == 3u;
	WRT_CHECK_U64(mi.n_up, up);
	WRT_CHECK_U64(mi.fsid[0], 0x00);
	WRT_CHECK_U64(mi.fsid[1], 0x11);
	WRT_CHECK_U64(mi.fsid[15], 0xff);
	wrt_json_free(&j);
}

/* ---- the 219 object names ------------------------------------------------------------------------------ */

static int jlist_eq(const wrt_json *j, wrt_tok arr, const int32_t *got, uint32_t n)
{
	size_t i;
	int ok = 0;

	if (wrt_json_count(j, arr) != n)
		return 0;
	for (i = 0; i < n; i++)
		if (wrt_json_int(j, wrt_json_at(j, arr, i), &ok) != (int64_t)got[i])
			return 0;
	return 1;
}

/* Every name of the oracle through wr_client_map_target (and its PG through wr_client_map_target_pg); returns how many matched. */
static unsigned check_names(host *h, uint32_t epoch)
{
	wrt_json j;
	wrt_tok entries;
	size_t i, n;
	unsigned compared = 0;

	WRT_CHECK(wrt_json_load_vec(&j, "osdmap/placement-names-e42.json") == 0);
	entries = wrt_json_get(&j, wrt_json_root(&j), "entries");
	n = wrt_json_count(&j, entries);
	WRT_CHECK_U64(n, 219);
	for (i = 0; i < n; i++) {
		wrt_tok row = wrt_json_at(&j, entries, i);
		int ok = 0;
		int64_t pool_id = wrt_json_int(&j, wrt_json_at(&j, row, 0), &ok);
		uint8_t *name = NULL, *ns = NULL;
		size_t nn = 0, nsn = 0;
		wr_object_id oid;
		wr_target t, t2;
		wr_pool_h ph = pool_id == 1 ? 0u : 1u; /* tracked in the order .mgr, winrbd */
		char *pgid, want[48];

		WRT_CHECK(wrt_json_hex(&j, wrt_json_at(&j, row, 1), &name, &nn) == 0);
		WRT_CHECK(wrt_json_hex(&j, wrt_json_at(&j, row, 2), &ns, &nsn) == 0);
		memset(&oid, 0, sizeof(oid));
		oid.name = name;
		oid.name_len = nn;
		oid.nspace = ns;
		oid.nspace_len = nsn;
		WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, ph, &oid, &t));
		WRT_CHECK_U64(t.epoch, epoch);
		WRT_CHECK_U64((uint64_t)t.pool_id, (uint64_t)pool_id);
		WRT_CHECK_U64(t.ps, (uint64_t)wrt_json_int(&j, wrt_json_at(&j, row, 3), &ok));
		pgid = wrt_json_strdup(&j, wrt_json_at(&j, row, 4));
		snprintf(want, sizeof(want), "%u.%x", (unsigned)pool_id, (unsigned)t.pg_seed);
		WRT_CHECK(pgid != NULL && strcmp(pgid, want) == 0);
		free(pgid);
		WRT_CHECK(jlist_eq(&j, wrt_json_at(&j, row, 5), t.up, t.n_up));
		WRT_CHECK_U64((uint32_t)t.up_primary, (uint32_t)wrt_json_int(&j, wrt_json_at(&j, row, 6), &ok));
		WRT_CHECK(jlist_eq(&j, wrt_json_at(&j, row, 7), t.acting, t.n_acting));
		WRT_CHECK_U64((uint32_t)t.acting_primary, (uint32_t)wrt_json_int(&j, wrt_json_at(&j, row, 8), &ok));
		WRT_CHECK(t.primary_addr.family == WR_AF_IPV4 && t.primary_addr.ip[0] == 10 && t.primary_addr.ip[1] == 77);
		WRT_CHECK_STATUS(WR_OK, wr_client_map_target_pg(h->c, ph, t.pg_seed, &t2));
		WRT_CHECK_U64(t2.ps, t.pg_seed); /* by PG, `ps` is the seed itself */
		t2.ps = t.ps;
		WRT_CHECK(memcmp(&t, &t2, sizeof(t)) == 0);
		compared++;
		free(name);
		free(ns);
	}
	wrt_json_free(&j);
	return compared;
}

/* A host with maps on, both lab pools tracked, run to the first map (epoch 42). */
static host *first_map_host(const wr_config *cfg, uint32_t newest, uint32_t last)
{
	host *h = host_new(cfg, newest, last);
	wr_pool_h p0 = 9, p1 = 9;

	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, ".mgr", &p0));
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, "winrbd", &p1));
	WRT_CHECK(p0 == 0u && p1 == 1u);
	WRT_CHECK(run_to_epoch(h, 42, 30000));
	return h;
}

/* ---- tests -------------------------------------------------------------------------------------------- */

static void t_first_map(void)
{
	wr_config cfg;
	host *h;
	wr_pool_h p0 = 9, p1 = 9;
	wr_map_info mi;
	wr_pool_info pi;
	wr_addr ad;
	wr_target t;
	wr_object_id oid;
	wr_map_stats st;
	uint8_t up = 7;
	wr_event const *e;

	fprintf(stderr, "maps on: the first map and the 219 names\n");
	base_cfg(&cfg);
	h = host_new(&cfg, 42, 51);
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, ".mgr", &p0));
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, "winrbd", &p1));
	WRT_CHECK(p0 == 0u && p1 == 1u);
	/* before the first map: nothing to say */
	memset(&oid, 0, sizeof(oid));
	WRT_CHECK_STATUS(WR_E_MAP_NONE, wr_client_map_info(h->c, &mi));
	WRT_CHECK_STATUS(WR_E_MAP_NONE, wr_client_pool_info(h->c, p0, &pi));
	WRT_CHECK_STATUS(WR_E_MAP_NONE, wr_client_osd_addr(h->c, 0, &ad, &up));
	WRT_CHECK_STATUS(WR_E_MAP_NONE, wr_client_map_target(h->c, p1, &oid, &t));
	WRT_CHECK_STATUS(WR_E_MAP_NONE, wr_client_map_target_pg(h->c, p1, 0, &t));
	WRT_CHECK(t.n_acting == 0 && t.acting_primary == -1 && t.up_primary == -1);
	WRT_CHECK_U64(up, 0);
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.epoch == 0 && st.slot_bytes == cfg.map_slot_bytes);

	WRT_CHECK(run_to_epoch(h, 42, 30000));
	WRT_CHECK_U64(wr_client_get_state(h->c), WR_CS_ACTIVE);
	check_vs_expected(h, 42);
	WRT_CHECK_U64(check_names(h, 42), 219);
	/* the map module is the only consumer of the monitor's messages */
	WRT_CHECK_U64(count_ev(h, WR_EV_MAPMSG), 0);
	WRT_CHECK_U64(h->n_raw_peek, 0);
	WRT_CHECK_U64(count_ev(h, WR_EV_MAP), 1);
	e = last_ev(h, WR_EV_MAP);
	WRT_CHECK(e != NULL && e->epoch == 42);
	WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
	/* pools */
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_info(h->c, p0, &pi));
	WRT_CHECK(pi.id == 1 && pi.pg_num == 1 && pi.pgp_num == 1 && pi.size == 2 && pi.min_size == 1 && pi.status == WR_OK);
	WRT_CHECK(pi.flags == WR_POOL_F_HASHPSPOOL);
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_info(h->c, p1, &pi));
	WRT_CHECK(pi.id == 2 && pi.pg_num == 32 && pi.pgp_num == 32 && pi.size == 3 && pi.min_size == 2 && pi.status == WR_OK);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_info(h->c, 2, &pi)); /* not tracked */
	/* OSD addresses */
	WRT_CHECK_STATUS(WR_OK, wr_client_osd_addr(h->c, 1, &ad, &up));
	WRT_CHECK(up == 1 && ad.family == WR_AF_IPV4 && ad.port == 6810 && ad.ip[0] == 10 && ad.ip[1] == 77 && ad.ip[3] == 10);
	WRT_CHECK_STATUS(WR_OK, wr_client_osd_addr(h->c, 2, &ad, NULL));
	WRT_CHECK_STATUS(WR_E_RANGE, wr_client_osd_addr(h->c, 3, &ad, &up));
	WRT_CHECK(up == 0 && ad.family == 0);
	WRT_CHECK_STATUS(WR_E_RANGE, wr_client_osd_addr(h->c, -1, &ad, &up));
	/* a PG outside the pool */
	WRT_CHECK_STATUS(WR_E_RANGE, wr_client_map_target_pg(h->c, p1, 32, &t));
	WRT_CHECK(t.n_acting == 0 && t.acting_primary == -1);
	/* stats */
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.epoch == 42 && st.n_full == 1 && st.n_inc == 0 && st.n_bad == 0 && st.n_resync == 0 && st.newest_seen == 42);
	WRT_CHECK(st.slot_used != 0 && st.slot_used <= st.slot_bytes && st.slot_used_max == st.slot_used && st.msg_bytes_max != 0);
	WRT_CHECK(st.cache_hits > 0 && st.cache_misses > 0 && st.last_err == WR_OK);
	/* the same with the CRC of the map checked */
	host_free(h);
	cfg.map_verify_crc = 1;
	h = first_map_host(&cfg, 42, 51);
	WRT_CHECK_U64(check_names(h, 42), 219);
	host_free(h);
}

static void t_incrementals(void)
{
	wr_config cfg;
	host *h;
	wr_map_stats st;
	unsigned k;
	const wr_event *e;

	fprintf(stderr, "incrementals: one message of eight epochs, coalesced and not\n");
	base_cfg(&cfg);
	for (k = 0; k < 2u; k++) {
		h = first_map_host(&cfg, 42, 51);
		h->drain_each = (int)k;
		h->n_ev = 0;
		h->sim->osd_newest = 49;
		WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(h->sim)); /* 50: epochs 43 .. 50 go out in ONE message */
		pump(h); /* no time passes: one epoch per run, and more_work keeps the host running until the message is done */
		check_vs_expected(h, 50);
		wr_client_map_stats(h->c, &st);
		WRT_CHECK(st.n_inc == 8 && st.n_full == 1 && st.n_bad == 0 && st.n_resync == 0 && st.newest_seen == 50);
		WRT_CHECK(st.slot_used_max >= st.slot_used);
		if (k == 0u) { /* drained once after the whole batch: the pending WR_EV_MAP carries the newest epoch, nothing is queued twice */
			WRT_CHECK_U64(count_ev(h, WR_EV_MAP), 1);
			e = last_ev(h, WR_EV_MAP);
			WRT_CHECK(e != NULL && e->epoch == 50);
		} else { /* drained after every run: one event per adopted epoch, in order */
			unsigned i, seen = 0;

			WRT_CHECK_U64(count_ev(h, WR_EV_MAP), 8);
			for (i = 0; i < h->n_ev; i++)
				if (h->ev[i].kind == WR_EV_MAP)
					WRT_CHECK_U64(h->ev[i].epoch, 43u + seen++);
		}
		WRT_CHECK_U64(count_ev(h, WR_EV_MAPMSG), 0);
		WRT_CHECK_U64(h->n_raw_peek, 0);
		/* the placement of epoch 50 still answers (the cache of epoch 42 does not leak into it) */
		{
			wr_object_id oid;
			wr_target t;
			uint8_t nm[4] = {'a', 'b', 'c', 'd'};

			memset(&oid, 0, sizeof(oid));
			oid.name = nm;
			oid.name_len = 4;
			WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, 1, &oid, &t));
			WRT_CHECK_U64(t.epoch, 50);
		}
		host_free(h);
	}
}

/* A MOSDMap v4 front with the given incrementals (and no full maps), like the monitor's emit routine. */
static size_t build_inc_front(uint8_t *buf, size_t cap, const uint8_t fsid[16], const uint32_t *epochs, unsigned n, uint32_t newest)
{
	wri_wr w;
	unsigned i;

	wri_wr_init(&w, buf, cap);
	wri_wr_bytes(&w, fsid, 16);
	wri_wr_u32(&w, n);
	for (i = 0; i < n; i++) {
		wri_wr_u32(&w, epochs[i]);
		wri_wr_u32(&w, (uint32_t)g_inc[epochs[i] - 1u].n);
		wri_wr_bytes(&w, g_inc[epochs[i] - 1u].p, g_inc[epochs[i] - 1u].n);
	}
	wri_wr_u32(&w, 0); /* no full maps */
	wri_wr_u32(&w, 1); /* the oldest epoch the monitor keeps */
	wri_wr_u32(&w, newest);
	wri_wr_u32(&w, 0); /* removed snaps */
	WRT_CHECK(wri_wr_ok(&w));
	return wri_wr_len(&w);
}

static void send_gap(host *h, const uint32_t *epochs, unsigned n, uint32_t newest)
{
	static uint8_t front[64 * 1024];
	size_t len = build_inc_front(front, sizeof(front), h->sim->fsid, epochs, n, newest);
	sim_mon_conn *sc = live_conn(h);

	WRT_CHECK(sc != NULL);
	if (sc != NULL)
		WRT_CHECK_STATUS(WR_OK, sim_mon_send_message(sc, 41, 4, 3, front, (uint32_t)len));
}

static void t_gap(void)
{
	wr_config cfg;
	host *h;
	wr_map_stats st;
	wr_map_info mi;
	const wr_event *e;
	uint32_t gap1[2] = {45, 46}, gap2[2] = {49, 50}, subs;
	wr_object_id oid;
	wr_target t;
	uint8_t nm[3] = {'x', 'y', 'z'};

	fprintf(stderr, "a gap: the held map serves, one request for a full map, a mixed answer, rate limit\n");
	base_cfg(&cfg);
	h = first_map_host(&cfg, 42, 51);
	h->sim->osd_newest = 47; /* what a start-0 request will be answered with: 42 (full) and 43 .. 47 */
	memset(&oid, 0, sizeof(oid));
	oid.name = nm;
	oid.name_len = 3;
	subs = total_subscribes(h);
	h->n_ev = 0;
	send_gap(h, gap1, 2, 47);
	pump(h);
	/* the gap message was dropped, a full map was asked for, and the request went out exactly once so far */
	WRT_CHECK_U64(count_ev(h, WR_EV_MAP_RESYNC) >= 1u, 1);
	e = last_ev(h, WR_EV_MAP_RESYNC);
	WRT_CHECK(e != NULL && e->err.status == WR_E_MAP_EPOCH);
	WRT_CHECK_U64(total_subscribes(h), subs + 1u);
	{
		sim_mon_conn *sc = live_conn(h);
		unsigned i, found = 0;

		WRT_CHECK(sc != NULL);
		for (i = 0; sc != NULL && i < sc->n_last_sub; i++)
			if (strcmp(sc->last_sub[i].name, "osdmap") == 0) {
				found = 1;
				WRT_CHECK_U64(sc->last_sub[i].start, 0);
			}
		WRT_CHECK(found);
	}
	/* the answer is a mixed message (full 42, stale; incrementals 43 .. 47): the client lands on 47, in the same pump (the
	 * request is sent by the run after the one that decided to make it, because the engine says more_work) */
	check_vs_expected(h, 47);
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.n_resync == 1 && st.n_inc == 5 && st.n_full == 1 && st.n_skipped >= 1 && st.n_bad == 0);
	WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, 1, &oid, &t));
	WRT_CHECK_U64(t.epoch, 47);
	WRT_CHECK_U64(wr_client_get_state(h->c), WR_CS_ACTIVE);

	/* a second gap at once: the request waits until map_refetch_ms (1 s) after the previous one */
	subs = total_subscribes(h);
	h->sim->osd_newest = 51;
	send_gap(h, gap2, 2, 51);
	pump(h);
	WRT_CHECK_STATUS(WR_OK, wr_client_map_info(h->c, &mi)); /* the held map keeps serving meanwhile */
	WRT_CHECK_U64(mi.epoch, 47);
	{ /* the rate-limited request is a timer of the engine: next_deadline_ms names it (nothing else is due within a second) */
		wr_clock clk;
		wr_run_result r;

		clk.mono_ms = h->now;
		clk.wall_ms = 1700000000000ull + h->now;
		r = wr_client_run(h->c, &clk, 0);
		WRT_CHECK(r.next_deadline_ms > h->now && r.next_deadline_ms <= h->now + 1000u);
	}
	WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, 1, &oid, &t));
	run_ms(h, 900);
	WRT_CHECK_U64(total_subscribes(h), subs); /* rate limited */
	WRT_CHECK(run_to_epoch(h, 51, 6000)); /* then it goes: full 42 stale, 43 .. 47 stale, 48 .. 51 applied */
	WRT_CHECK(total_subscribes(h) > subs);
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.n_resync == 2 && st.n_inc == 9 && st.epoch == 51);
	WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
	host_free(h);
}

/* The event ring: WR_EV_MAP is coalesced and never the event that is dropped when the ring is full (white-box: the engine's
 * own push function, the one the monitor link and the store use). */
static void t_event_ring(void)
{
	wr_config cfg;
	host *h;
	unsigned i, n_map = 0, n_msg = 0, n_fatal = 0;
	wr_event e;
	wr_errinfo why;

	fprintf(stderr, "event ring: WR_EV_MAP coalesced and kept\n");
	base_cfg(&cfg);
	h = host_new(&cfg, 0, 0);
	memset(&why, 0, sizeof(why));
	wri_client_push_event(h->c, WR_EV_MAP, 5, NULL);
	wri_client_push_event(h->c, WR_EV_FATAL, 0, &why);
	for (i = 0; i < 12u; i++)
		wri_client_push_event(h->c, WR_EV_MAPMSG, i, NULL); /* informational: the oldest of them is what a full ring drops */
	wri_client_push_event(h->c, WR_EV_MAP, 9, NULL);        /* the pending one is updated, nothing is queued */
	wri_client_push_event(h->c, WR_EV_MAP, 7, NULL);        /* an older epoch never lowers it */
	for (i = 0; i < 12u; i++)
		wri_client_push_event(h->c, WR_EV_MAPMSG, 100u + i, NULL);
	while (wr_client_next_event(h->c, &e)) {
		n_map += e.kind == WR_EV_MAP;
		n_msg += e.kind == WR_EV_MAPMSG;
		n_fatal += e.kind == WR_EV_FATAL;
		if (e.kind == WR_EV_MAP)
			WRT_CHECK_U64(e.epoch, 9);
		if (e.kind == WR_EV_MAPMSG)
			WRT_CHECK(e.epoch >= 100u + 12u - 6u); /* the newest informational events survived, the oldest were dropped */
	}
	WRT_CHECK(n_map == 1u && n_fatal == 1u && n_msg == 6u); /* a ring of 8: the two protected events and the newest six */
	host_free(h);
}

static void t_first_map_fatal(void)
{
	wr_config cfg;
	host *h;
	const wr_event *e;
	wr_map_info mi;
	wr_map_stats st;
	uint32_t subs;

	fprintf(stderr, "a first map that can never fit is fatal\n");
	base_cfg(&cfg);
	cfg.map_max_osd = 2; /* the lab map has 3 OSDs: WR_E_MAP_BUDGET, and a retry is the same map */
	h = host_new(&cfg, 42, 51);
	run_ms(h, 8000);
	WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 1);
	e = last_ev(h, WR_EV_FATAL);
	WRT_CHECK(e != NULL && e->err.status == WR_E_MAP_BUDGET && e->err.module == WR_MOD_MAP);
	WRT_CHECK_U64(wr_client_get_state(h->c), WR_CS_FAILED);
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wr_client_last_error(h->c)->status);
	WRT_CHECK_STATUS(WR_E_MAP_NONE, wr_client_map_info(h->c, &mi));
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.epoch == 0 && st.n_bad == 1 && st.last_err == WR_E_MAP_BUDGET && st.n_resync == 0);
	/* it stays stopped: no session, no more requests, nothing raised again */
	subs = total_subscribes(h);
	run_ms(h, 70000);
	WRT_CHECK_U64(total_subscribes(h), subs);
	WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 1);
	WRT_CHECK_U64(wr_client_get_state(h->c), WR_CS_FAILED);
	WRT_CHECK(live_conn(h) == NULL);
	{ /* a dead client still answers the map calls, with "no map" */
		wr_pool_h ph = 9;
		wr_target t;
		wr_object_id oid;
		wr_pool_info pi;
		wr_addr ad;
		uint8_t up = 4;

		memset(&oid, 0, sizeof(oid));
		WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, "winrbd", &ph));
		WRT_CHECK_U64(ph, 0);
		WRT_CHECK_STATUS(WR_E_MAP_NONE, wr_client_pool_info(h->c, ph, &pi));
		WRT_CHECK_STATUS(WR_E_MAP_NONE, wr_client_map_target(h->c, ph, &oid, &t));
		WRT_CHECK_STATUS(WR_E_MAP_NONE, wr_client_osd_addr(h->c, 0, &ad, &up));
		WRT_CHECK_U64(up, 0);
		WRT_CHECK_U64(wr_client_get_state(h->c), WR_CS_FAILED);
		run_ms(h, 2000);
		WRT_CHECK_U64(total_subscribes(h), subs); /* tracking a pool did not wake the monitor link of a dead client */
		WRT_CHECK_U64(count_ev(h, WR_EV_MAP_RESYNC), 0);
	}
	host_free(h);
}

static void t_monitor_drops(void)
{
	wr_config cfg;
	host *h;
	wr_map_stats st;
	wr_object_id oid;
	wr_target t;
	uint8_t nm[5] = {'o', 'b', 'j', '-', '1'};
	unsigned i, hunting = 0;

	fprintf(stderr, "the monitor session drops: queries keep answering, the stream resumes from held + 1\n");
	base_cfg(&cfg);
	h = first_map_host(&cfg, 42, 51);
	memset(&oid, 0, sizeof(oid));
	oid.name = nm;
	oid.name_len = sizeof(nm);
	WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, 1, &oid, &t));
	sim_mon_restart(h->sim);
	pump(h); /* the cut is noticed */
	for (i = 0; i < 400u && wr_client_get_state(h->c) != WR_CS_ACTIVE; i++) {
		wr_target t2;
		wr_map_info mi;

		h->now += TICK_MS;
		pump(h);
		if (wr_client_get_state(h->c) == WR_CS_HUNTING) {
			hunting++;
			WRT_CHECK_STATUS(WR_OK, wr_client_map_info(h->c, &mi)); /* a hunt does not take the map away */
			WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, 1, &oid, &t2));
			WRT_CHECK(memcmp(&t, &t2, sizeof(t)) == 0);
		}
	}
	WRT_CHECK(hunting > 0);
	WRT_CHECK_U64(wr_client_get_state(h->c), WR_CS_ACTIVE);
	/* the new session asked for held + 1, not for everything: no full-map re-fetch happened */
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.epoch == 42 && st.n_resync == 0 && st.n_full == 1);
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(h->sim)); /* 43 is committed after the restart */
	WRT_CHECK(run_to_epoch(h, 43, 5000));
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.n_inc == 1 && st.n_full == 1 && st.n_resync == 0 && st.n_bad == 0);
	WRT_CHECK_U64(count_ev(h, WR_EV_MAPMSG), 0);
	host_free(h);
}

static void t_late_track(void)
{
	wr_config cfg;
	host *h;
	wr_pool_h hm = 9, hx = 9, h4 = 9, again = 9;
	wr_pool_info pi;
	wr_map_stats st;
	const wr_event *e;

	fprintf(stderr, "a pool tracked after the first map\n");
	base_cfg(&cfg);
	cfg.map_pools = 3;
	h = host_new(&cfg, 42, 51);
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, "winrbd", &again));
	WRT_CHECK(run_to_epoch(h, 42, 30000));
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_info(h->c, again, &pi));
	WRT_CHECK(pi.id == 2);
	h->n_ev = 0;
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, ".mgr", &hm));
	{ /* the call wakes nothing by itself; the run the host makes next decides to ask for the full map and says "run again at once" */
		wr_clock clk;
		wr_run_result r;
		uint32_t subs = total_subscribes(h);

		clk.mono_ms = h->now;
		clk.wall_ms = 1700000000000ull + h->now;
		r = wr_client_run(h->c, &clk, 0);
		WRT_CHECK_U64(r.more_work, 1);
		WRT_CHECK_U64(total_subscribes(h), subs); /* not sent yet: the monitor step of this run was before the store's */
		(void)host_actions(h);
		(void)host_io(h);
		(void)wr_client_run(h->c, &clk, 0); /* the second run puts the subscription on the wire */
		(void)host_actions(h);
		(void)host_io(h);
		WRT_CHECK_U64(total_subscribes(h), subs + 1u);
	}
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, "no-such-pool", &hx));
	WRT_CHECK(hm == 1u && hx == 2u);
	WRT_CHECK_STATUS(WR_E_BUSY, wr_client_pool_track(h->c, "one-too-many", &h4)); /* map_pools is 3 */
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, ".mgr", &h4)); /* the same name: the same handle */
	WRT_CHECK_U64(h4, hm);
	/* the held map was built without these names: not found until the full map the engine asks for arrives */
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wr_client_pool_info(h->c, hm, &pi));
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_info(h->c, again, &pi)); /* the first one is untouched */
	run_ms(h, 3000);
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_info(h->c, hm, &pi));
	WRT_CHECK(pi.id == 1);
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wr_client_pool_info(h->c, hx, &pi)); /* a name the cluster does not have */
	{
		wr_target t;
		wr_object_id oid;

		memset(&oid, 0, sizeof(oid));
		WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wr_client_map_target(h->c, hx, &oid, &t));
		WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, hm, &oid, &t));
	}
	e = last_ev(h, WR_EV_MAP_RESYNC);
	WRT_CHECK(e != NULL && e->err.status == WR_E_MAP_RESYNC);
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.epoch == 42 && st.n_resync == 1 && st.n_full == 2); /* a full map of the held epoch */
	host_free(h);
}

/* The longest pool name, the same name twice, the table limit: the edges of wr_client_pool_track on a live client. */
static void t_track_names(void)
{
	wr_config cfg;
	host *h;
	char name[WRI_MAP_NAME_MAX + 2u];
	wr_pool_h hl = 9, hl2 = 9, hx = 9, again = 9;
	wr_pool_info pi;

	fprintf(stderr, "pool names: the 128-byte edge, the same name twice, a full table\n");
	base_cfg(&cfg);
	cfg.map_pools = 3;
	h = first_map_host(&cfg, 42, 51); /* .mgr and winrbd are tracked: one entry left */
	memset(name, 'q', sizeof(name));
	name[WRI_MAP_NAME_MAX + 1u] = '\0';
	WRT_CHECK_STATUS(WR_E_TOOBIG, wr_client_pool_track(h->c, name, &hx)); /* 129 bytes, with room in the table */
	WRT_CHECK_U64(hx, 0);
	name[WRI_MAP_NAME_MAX] = '\0';
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, name, &hl)); /* exactly 128 */
	WRT_CHECK_U64(hl, 2);
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, name, &hl2)); /* the same name, the same handle, even with the table full */
	WRT_CHECK_U64(hl2, 2);
	name[WRI_MAP_NAME_MAX - 1u] = 'r'; /* a name that differs in the last byte only is another pool */
	WRT_CHECK_STATUS(WR_E_BUSY, wr_client_pool_track(h->c, name, &hx));
	WRT_CHECK_U64(hx, 0);
	/* a name that is a prefix of a tracked one is not that one */
	name[WRI_MAP_NAME_MAX - 1u] = '\0';
	WRT_CHECK_STATUS(WR_E_BUSY, wr_client_pool_track(h->c, name, &hx));
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_track(h->c, "winrbd", &again)); /* a tracked name is found before the full table matters */
	WRT_CHECK_U64(again, 1);
	run_ms(h, 3000); /* the full map the late name asked for: the long name is not in the cluster */
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wr_client_pool_info(h->c, hl, &pi));
	WRT_CHECK_STATUS(WR_OK, wr_client_pool_info(h->c, again, &pi));
	WRT_CHECK(pi.id == 2 && pi.status == WR_OK);
	host_free(h);
}

/* One map slot only (the iPXE profile: mapmsg_queue 1): the connection stalls while the store holds a message, and the store
 * still walks a message of eight epochs, answers a gap with a full map and keeps the session alive meanwhile. */
static void t_one_slot(void)
{
	wr_config cfg;
	host *h;
	wr_map_stats st;
	wr_stats es;
	uint32_t gap[2] = {45, 46}, subs;

	fprintf(stderr, "one map message slot: a batch, a gap, the session stays up\n");
	base_cfg(&cfg);
	cfg.mapmsg_queue = 1;
	h = first_map_host(&cfg, 42, 51);
	h->sim->osd_newest = 49;
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(h->sim)); /* 43 .. 50 in one message */
	WRT_CHECK(run_to_epoch(h, 50, 5000));
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.n_inc == 8 && st.n_bad == 0 && st.n_resync == 0);
	h->sim->osd_newest = 51;
	subs = total_subscribes(h);
	send_gap(h, gap, 2, 51); /* 45, 46 on a client at 50: stale, not a gap; nothing to do */
	pump(h);
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.epoch == 50 && st.n_resync == 0 && st.n_bad == 0 && st.n_skipped >= 2);
	gap[0] = 52;
	gap[1] = 53;
	send_gap(h, gap, 2, 53); /* 52, 53 on a client at 50 with 51 missing: a gap */
	pump(h);
	WRT_CHECK(total_subscribes(h) > subs);
	WRT_CHECK(run_to_epoch(h, 51, 6000)); /* the answer to start 0: the full map of 42 and 43 .. 51 */
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.n_resync == 1 && st.epoch == 51);
	wr_client_get_stats(h->c, &es);
	WRT_CHECK(es.mapmsg_hiwater == 1u);
	WRT_CHECK_U64(wr_client_get_state(h->c), WR_CS_ACTIVE);
	WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
	host_free(h);
}

/* The monitor goes away while the store is part-way through a message of eight epochs: the message stays in its slot, the store
 * finishes it, and the new session asks for the epochs after the newest it was sent (no full map, nothing applied twice). */
static void t_cut_mid_message(void)
{
	wr_config cfg;
	host *h;
	wr_map_stats st;
	wr_map_info mi;
	unsigned i, k;

	fprintf(stderr, "the monitor session dies in the middle of a message\n");
	base_cfg(&cfg);
	for (k = 0; k < 3u; k++) { /* the iPXE case (one slot) and two slots with a cut; one slot with a host that releases anyway */
		cfg.mapmsg_queue = (uint16_t)(k == 1u ? 2u : 1u);
		h = first_map_host(&cfg, 42, 51);
		h->sim->osd_newest = 49;
		WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(h->sim)); /* 43 .. 50 in one message */
		for (i = 0; i < 200u; i++) { /* run by hand until a few epochs are in, but not all */
			wr_clock clk;

			clk.mono_ms = h->now;
			clk.wall_ms = 1700000000000ull + h->now;
			(void)wr_client_run(h->c, &clk, 0);
			(void)host_actions(h);
			(void)host_io(h);
			if (wr_client_map_info(h->c, &mi) == WR_OK && mi.epoch >= 45u)
				break;
		}
		WRT_CHECK_STATUS(WR_OK, wr_client_map_info(h->c, &mi));
		WRT_CHECK(mi.epoch >= 45u && mi.epoch < 50u);
		if (k == 2u) { /* no cut: a host that calls release (it owns nothing with maps on) must not free the store's message */
			wr_mapmsg m;

			wr_client_mapmsg_release(h->c);
			wr_client_mapmsg_release(h->c);
			WRT_CHECK(!wr_client_mapmsg_peek(h->c, &m));
		} else {
			sim_mon_restart(h->sim); /* the connection is cut here */
		}
		WRT_CHECK(run_to_epoch(h, 50, 20000));
		wr_client_map_stats(h->c, &st);
		WRT_CHECK(st.n_full == 1 && st.n_inc == 8 && st.n_bad == 0 && st.n_resync == 0 && st.epoch == 50);
		WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
		host_free(h);
	}
}

/* A tiny work budget per run: the connections use all of it, the store still gets one entry per run, so the first map and a batch
 * of epochs arrive, only in more runs. */
static void t_small_budget(void)
{
	wr_config cfg;
	host *h;
	wr_map_stats st;
	unsigned k;
	static const uint32_t budgets[2] = {1u, 64u};

	fprintf(stderr, "a tiny work budget per run\n");
	base_cfg(&cfg);
	for (k = 0; k < 2u; k++) {
		h = host_new(&cfg, 42, 51);
		h->budget = budgets[k];
		WRT_CHECK(run_to_epoch(h, 42, 60000));
		h->sim->osd_newest = 49;
		WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(h->sim));
		WRT_CHECK(run_to_epoch(h, 50, 60000));
		wr_client_map_stats(h->c, &st);
		WRT_CHECK(st.n_full == 1 && st.n_inc == 8 && st.n_bad == 0 && st.n_resync == 0);
		WRT_CHECK_U64(wr_client_get_state(h->c), WR_CS_ACTIVE);
		host_free(h);
	}
}

static void t_maps_off(void)
{
	wr_config cfg;
	host *h;
	wr_pool_h ph = 5;
	wr_map_info mi;
	wr_pool_info pi;
	wr_addr ad;
	wr_target t;
	wr_object_id oid;
	wr_map_stats st;
	uint8_t up = 3;

	fprintf(stderr, "maps off: raw delivery as before, the map API refuses\n");
	wr_config_profile_harness(&cfg);
	cfg.mon_msg_cap = 256u * 1024u;
	cfg.max_conns = 4;
	cfg.max_handshakes = 2;
	WRT_CHECK_U64(cfg.map_slot_bytes, 0);
	h = host_new(&cfg, 0, 0);
	/* raw: WR_EV_MAPMSG events, and the host's peek / release (drain_events) sees the monmap and the osdmap message */
	pump(h);
	run_ms(h, 3000);
	WRT_CHECK(count_ev(h, WR_EV_MAPMSG) >= 2u);
	WRT_CHECK(h->n_raw_osd == 1 && h->n_raw_mon >= 1 && count_ev(h, WR_EV_MAP) == 0);
	WRT_CHECK_U64(wr_client_get_state(h->c), WR_CS_ACTIVE);
	/* the map API */
	memset(&oid, 0, sizeof(oid));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_track(h->c, "rbd", &ph));
	WRT_CHECK_U64(ph, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_info(h->c, &mi));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_info(h->c, 0, &pi));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_osd_addr(h->c, 0, &ad, &up));
	WRT_CHECK_U64(up, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target(h->c, 0, &oid, &t));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target_pg(h->c, 0, 0, &t));
	wr_client_map_stats(h->c, &st);
	WRT_CHECK(st.epoch == 0 && st.slot_bytes == 0);
	host_free(h);
}

static void t_config(void)
{
	wr_config cfg;
	wr_mem_req req, plain;

	fprintf(stderr, "configuration\n");
	wr_config_profile_kernel(&cfg);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &plain));
	{ /* a value that is not a profile changes nothing: maps stay off, and a configuration with maps on keeps its budgets */
		wr_config before = cfg, on;

		wr_config_enable_maps(&cfg, (wr_map_profile)0);
		WRT_CHECK(memcmp(&before, &cfg, sizeof(cfg)) == 0);
		wr_config_enable_maps(&cfg, (wr_map_profile)99);
		WRT_CHECK(memcmp(&before, &cfg, sizeof(cfg)) == 0);
		wr_config_enable_maps(&cfg, WR_MAPS_IPXE);
		on = cfg;
		wr_config_enable_maps(&cfg, (wr_map_profile)-1);
		WRT_CHECK(memcmp(&on, &cfg, sizeof(cfg)) == 0);
		cfg = before;
	}
	wr_config_enable_maps(&cfg, WR_MAPS_KERNEL);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	/* two slots of 1 MiB, plus the placement cache (256 entries) in the arena */
	WRT_CHECK(req.bulk >= plain.bulk + 2u * 1024u * 1024u && req.bulk <= plain.bulk + 2u * 1024u * 1024u + 16u);
	WRT_CHECK(req.arena >= plain.arena + 256u * 152u && req.arena <= plain.arena + 256u * 152u + 256u);

	cfg.map_pools = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	cfg.map_pools = 9;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	cfg.map_pools = 8;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	cfg.map_pools = 1;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	cfg.map_slot_bytes = 16u * 1024u - 1u;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	cfg.map_slot_bytes = 16u * 1024u;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	cfg.map_slot_bytes = 16u * 1024u + 1u; /* not a multiple of 16: the plan is still exact (see test_client_mem) */
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	cfg.map_slot_bytes = 1024u * 1024u;
	cfg.map_max_osd = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	cfg.map_max_osd = WRI_MAP_OSD_HARD_MAX + 1u;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	cfg.map_max_osd = WRI_MAP_OSD_HARD_MAX;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	cfg.crush_work_max = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_mem_required(&cfg, &req));
	cfg.crush_work_max = 1;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	cfg.map_pg_cache = 0; /* no cache: no arena cost, still a working store */
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	WRT_CHECK_U64(req.arena, plain.arena);
	/* a refused configuration is refused by create too, before anything is written */
	cfg.map_pools = 0;
	{
		wr_host_ops ops;
		wr_cluster_spec sp;
		wr_client *c = (wr_client *)1;
		uint8_t a[64];

		memset(&ops, 0, sizeof(ops));
		memset(&sp, 0, sizeof(sp));
		ops.size = (uint32_t)sizeof(ops);
		ops.random = h_random;
		WRT_CHECK_STATUS(WR_E_INVAL, wr_client_create(&cfg, &ops, &sp, (wr_mem_region){a, sizeof(a)}, (wr_mem_region){a, sizeof(a)}, &c));
		WRT_CHECK(c == NULL);
	}
}

static void t_api(void)
{
	wr_config cfg;
	host *h;
	wr_pool_h ph = 7;
	char longname[200];
	wr_map_info mi;
	wr_pool_info pi;
	wr_addr ad;
	wr_target t;
	wr_object_id oid;
	uint8_t nm[2] = {'a', 'b'};
	uint8_t up = 5;
	wr_client *dead;

	fprintf(stderr, "API contract\n");
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_track(NULL, "rbd", &ph));
	WRT_CHECK_U64(ph, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_info(NULL, &mi));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_info(NULL, 0, &pi));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_osd_addr(NULL, 0, &ad, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target(NULL, 0, NULL, &t));
	WRT_CHECK(t.acting_primary == -1 && t.up_primary == -1);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target_pg(NULL, 0, 0, &t));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target(NULL, 0, NULL, NULL));

	base_cfg(&cfg);
	cfg.map_pools = 2;
	h = first_map_host(&cfg, 42, 51);
	memset(longname, 'p', sizeof(longname));
	longname[199] = '\0';
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_track(h->c, "", &ph));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_track(h->c, NULL, &ph));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_track(h->c, "rbd", NULL));
	WRT_CHECK_STATUS(WR_E_TOOBIG, wr_client_pool_track(h->c, longname, &ph));
	WRT_CHECK_U64(ph, 0);
	longname[128] = '\0'; /* exactly the cap: accepted syntactically, but the table (2 pools) is full */
	WRT_CHECK_STATUS(WR_E_BUSY, wr_client_pool_track(h->c, longname, &ph));
	/* targets: bad object descriptions */
	memset(&oid, 0, sizeof(oid));
	oid.name_len = 3; /* announced bytes without a pointer */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target(h->c, 1, &oid, &t));
	WRT_CHECK(t.acting_primary == -1 && t.n_acting == 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target(h->c, 1, NULL, &t));
	oid.name = nm;
	oid.name_len = 2;
	WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, 1, &oid, &t));
	oid.name_len = 5000; /* above the placement cap (the bytes are not read) */
	{
		uint8_t *big = (uint8_t *)calloc(1, 5000);

		oid.name = big;
		WRT_CHECK_STATUS(WR_E_TOOBIG, wr_client_map_target(h->c, 1, &oid, &t));
		WRT_CHECK(t.acting_primary == -1);
		free(big);
	}
	oid.name = nm;
	oid.name_len = 0; /* an empty object name is legal */
	WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, 1, &oid, &t));
	if (sizeof(size_t) > 4u) { /* a length above 4 GiB is refused, never truncated to the 2 bytes below it (nothing is read) */
		size_t huge = (((size_t)1 << 31) << 1) | 2u;

		oid.name_len = huge;
		WRT_CHECK_STATUS(WR_E_TOOBIG, wr_client_map_target(h->c, 1, &oid, &t));
		WRT_CHECK(t.acting_primary == -1 && t.n_acting == 0);
		oid.name_len = 2;
		oid.nspace = nm;
		oid.nspace_len = huge;
		WRT_CHECK_STATUS(WR_E_TOOBIG, wr_client_map_target(h->c, 1, &oid, &t));
		oid.nspace_len = 0;
		oid.key = nm;
		oid.key_len = huge;
		WRT_CHECK_STATUS(WR_E_TOOBIG, wr_client_map_target(h->c, 1, &oid, &t));
		oid.key = NULL;
		oid.key_len = 0;
	}
	/* the three parts together are counted against the cap (4096): each alone below it, the sum above */
	{
		uint8_t *part = (uint8_t *)calloc(1, 2048);

		oid.name = part;
		oid.name_len = 2048;
		oid.nspace = part;
		oid.nspace_len = 2048;
		WRT_CHECK_STATUS(WR_OK, wr_client_map_target(h->c, 1, &oid, &t)); /* exactly the cap */
		oid.key = part;
		oid.key_len = 1;
		WRT_CHECK_STATUS(WR_E_TOOBIG, wr_client_map_target(h->c, 1, &oid, &t)); /* the locator key counts too */
		WRT_CHECK(t.acting_primary == -1 && t.n_up == 0);
		free(part);
		oid.key = NULL;
		oid.key_len = 0;
		oid.nspace = NULL;
		oid.nspace_len = 0;
	}
	oid.name = nm;
	oid.name_len = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_info(h->c, 0, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_osd_addr(h->c, 0, NULL, &up));
	WRT_CHECK_U64(up, 0);
	wr_client_map_stats(h->c, NULL); /* no output: nothing happens */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target_pg(h->c, 1, 0, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_info(h->c, 99, &pi));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target_pg(h->c, 99, 0, &t));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_info(h->c, NULL));
	/* a destroyed client is not a client */
	dead = h->c;
	wr_client_destroy(dead);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_info(dead, &mi));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_map_target_pg(dead, 1, 0, &t));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_client_pool_track(dead, "rbd", &ph));
	host_free(h); /* destroying a destroyed client is a no-op */
}

int main(void)
{
	WRT_CHECK(wrt_mg_load_epoch_lines(wrt_vec_path("osdmap/incrementals.hex"), &g_inc, &g_ninc) == 0 && g_ninc == 89u);
	t_first_map();
	t_incrementals();
	t_gap();
	t_event_ring();
	t_first_map_fatal();
	t_monitor_drops();
	t_late_track();
	t_track_names();
	t_one_slot();
	t_cut_mid_message();
	t_small_budget();
	t_maps_off();
	t_config();
	t_api();
	wrt_mg_free_lines(g_inc, g_ninc);
	return wrt_finish();
}
