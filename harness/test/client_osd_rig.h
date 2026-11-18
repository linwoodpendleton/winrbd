/* SPDX-License-Identifier: MIT */
/*
 * client_osd_rig.h - the rig of the client-glue-osd tests: the WHOLE engine (wr_client with the map module, the OSD client and the image layer) against
 * one sim_mon and N sim_osd over one shared object store, driven the way a host drives it, through the PUBLIC API only (wr_client_run, the actions,
 * wr_conn_*, wr_image_*, wr_client_next_done). The in-test pump is the host: it dials the address of an action to the simulator that owns it, moves the
 * bytes both ways, reports closes, advances the clock and settles.
 *
 * The cluster is made by the test mapgen: n_osd OSDs on n_osd hosts (so every PG has a primary somewhere and the primaries are spread over all of them),
 * two pools ("pool1" = id 1, "pool2" = id 2), the OSD addresses 10.77.0.(40 + i):(6810 + i), nonce 7000 + i (the simulators check the dialled address byte for
 * byte). The monitor serves that map as epoch 1; cw_map_next() makes later epochs (an OSD marked down, an OSD back up with a new address).
 * Test code: libc allowed, everything static inline so every test executable carries its own copy.
 */
#ifndef CLIENT_OSD_RIG_H
#define CLIENT_OSD_RIG_H

#include "sim_mon_tc.h"
#include "sim_osd.h"
#include "wr_image.h"
#include "wr_map.h"
#include "wri_client.h"
#include "wri_client_osd.h"
#include "wrt_mapgen.h"

#define CW_MAX_OSD 8u
#define CW_MAXC 40u
#define CW_EV 512u
#define CW_POOL 1
#define CW_DPOOL 2
#define CW_TICK_MS 50u

typedef struct cw_conn {
	int used, closing, osd; /* osd: index of the OSD, -1 for the monitor */
	wr_conn_id id;
	sim_mon_conn *mc;
	sim_osd_conn *oc;
	uint32_t timeout_ms;    /* the action's connect timeout */
	uint64_t rx_total;      /* bytes delivered to the engine on this connection */
	uint8_t inj[512];       /* bytes the fuzzer plays as the peer: delivered next, ahead of what the simulator queued */
	size_t inj_len;
	uint64_t flip_off;      /* flip the bits of flip_mask in the byte of the stream at this offset (once; 0 mask = off) */
	uint8_t flip_mask;
} cw_conn;

typedef struct cw {
	wr_config cfg;
	wr_host_ops ops;
	wr_cluster_spec spec;
	sim_mon_cfg mcfg;
	sim_mon *mon;
	sim_store *store;
	sim_osd *osd[CW_MAX_OSD];
	sim_osd_cfg ocfg[CW_MAX_OSD];
	wr_addr addr[CW_MAX_OSD];
	int osd_down[CW_MAX_OSD];        /* a connect to this OSD fails at once (a dead host) */
	unsigned n_osd;
	wrt_mg_map desc;                 /* the map of the newest epoch the monitor serves */
	uint32_t epoch;
	uint8_t *arena_raw, *bulk_raw;
	wr_mem_req req;
	wr_client *c;
	cw_conn hc[CW_MAXC];
	uint64_t now, rng;
	uint32_t budget;                 /* work budget of every run, 0 = the engine's default */
	wr_run_result last;
	wr_event ev[CW_EV];
	unsigned n_ev;
	unsigned n_actions, n_connects, n_connects_osd, n_closes, n_runs;
	uint32_t connect_timeout_seen[CW_MAX_OSD + 1u]; /* the timeout of the last CONNECT action to the OSD (index n_osd = monitor) */
	unsigned conns_osd_live_max;
	uint8_t *arena_base, *bulk_base; /* the regions the engine got (exactly the announced sizes, pre-filled with a pattern) */
	uint8_t arena_pat, bulk_pat;
	int fail_random;                 /* the host random source fails (the engine must end, never fall back) */
	unsigned n_log, n_leak_log, n_leak_wire, n_leak_ev; /* the key canary: records and wire bytes that showed key material */
	uint64_t digest;                 /* FNV-1a over everything the host can observe: actions, bytes sent, events, completions */
} cw;

/* A completion the test pulled: the request pointer and its final status. */
#define CW_DONE_MAX 4096u
typedef struct cw_done {
	wr_io_req *req;
	wr_status st;
} cw_done;
static cw_done g_cw_done[CW_DONE_MAX];
static unsigned g_cw_ndone;

/* The fill patterns of the two regions (a fuzz target runs one input twice with different ones: the engine must not read a byte it never wrote). */
static uint8_t g_cw_pat_a = 0xA5u, g_cw_pat_b = 0x5Au;

static inline void cw_dig(cw *w, const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		w->digest = (w->digest ^ b[i]) * 0x100000001b3ull;
}

static inline void cw_dig_u64(cw *w, uint64_t v)
{
	uint8_t b[8];
	unsigned i;

	for (i = 0; i < 8u; i++)
		b[i] = (uint8_t)(v >> (8u * i));
	cw_dig(w, b, sizeof(b));
}

/* A printable key for the canary scans (NULL = the usual generated key). 32 bytes with the terminator; an AES key uses the first 16. */
static const char *g_cw_canary;

static inline wr_status cw_random(void *ctx, uint8_t *out, size_t n)
{
	cw *w = (cw *)ctx;
	size_t i;

	if (w->fail_random)
		return WR_E_HOST_RANDOM;
	for (i = 0; i < n; i++) {
		w->rng ^= w->rng >> 12;
		w->rng ^= w->rng << 25;
		w->rng ^= w->rng >> 27;
		out[i] = (uint8_t)((w->rng * 0x2545f4914f6cdd1dull) >> 56);
	}
	return WR_OK;
}

/* ---- the key canary -------------------------------------------------------------------------------------------------- */

static inline int cw_contains(const uint8_t *hay, size_t hn, const uint8_t *needle, size_t nn)
{
	size_t i;

	if (nn == 0 || hn < nn)
		return 0;
	for (i = 0; i + nn <= hn; i++)
		if (hay[i] == needle[0] && memcmp(hay + i, needle, nn) == 0)
			return 1;
	return 0;
}

/* A 64-bit number equal to any 8-byte window of the key, either byte order. */
static inline int cw_number_is_key_word(const cw *w, uint64_t v)
{
	const wr_key *k = &w->mcfg.key;
	size_t i, j;

	for (i = 0; i + 8u <= k->len; i++) {
		uint64_t le = 0, be = 0;

		for (j = 0; j < 8u; j++) {
			le |= (uint64_t)k->secret[i + j] << (8u * j);
			be = (be << 8) | k->secret[i + j];
		}
		if (v == le || v == be)
			return 1;
	}
	return 0;
}

static inline void cw_log(void *ctx, const wr_log_rec *r)
{
	cw *w = (cw *)ctx;

	w->n_log++;
	if (r->msg != NULL && (strstr(r->msg, "CANARY") != NULL || cw_contains((const uint8_t *)r->msg, strlen(r->msg), w->mcfg.key.secret, 6)))
		w->n_leak_log++;
	if (cw_number_is_key_word(w, r->a0) || cw_number_is_key_word(w, r->a1) || cw_number_is_key_word(w, r->a2) || cw_number_is_key_word(w, r->a3))
		w->n_leak_log++;
}

static inline void cw_check_errinfo(cw *w, const wr_errinfo *e)
{
	if (cw_number_is_key_word(w, e->a0) || cw_number_is_key_word(w, e->a1) || cw_number_is_key_word(w, e->a2) ||
	    (e->what != NULL && strstr(e->what, "CANARY") != NULL))
		w->n_leak_ev++;
}

/* ---- configuration ------------------------------------------------------------------------------------------------- */

/* The default of the tests: the iPXE profile with maps and the OSD client (small, so the sanitizer builds stay quick). op_bytes_max 256 KiB, so a request of a
 * few hundred KiB is cut into several operations. */
static inline void cw_cfg_default(wr_config *cfg)
{
	wr_config_profile_ipxe(cfg);
	wr_config_enable_maps(cfg, WR_MAPS_IPXE);
	wr_config_enable_osd(cfg, WR_MAPS_IPXE);
	cfg->op_bytes_max = 256u * 1024u;
	cfg->max_images = 2;
	cfg->max_reqs = 16;
	cfg->osd_sessions = 6;
	cfg->max_conns = 8;
	cfg->max_handshakes = 2;
	cfg->hdr_refresh_ms = 2000;
}

/* ---- the world ------------------------------------------------------------------------------------------------------- */

static inline uint32_t cw_ip(unsigned i) { return 0x0a4d0000u | (40u + i); }
static inline uint16_t cw_port(unsigned i) { return (uint16_t)(6810u + i); }
static inline uint32_t cw_nonce(unsigned i) { return 7000u + i; }

/* The full map of epoch `desc.epoch`, added to the monitor and committed (epoch 1: the monitor's newest). */
static inline int cw_build_map(cw *w, unsigned n_osd, unsigned pg_num)
{
	wrt_mg_cluster_spec s;
	wrt_mg_buf b;
	unsigned i;

	memset(&b, 0, sizeof(b));
	wrt_mg_cluster_spec_init(&s, n_osd);
	s.osds_per_host = 1;
	s.n_pools = 2;
	s.pg_num = pg_num;
	s.pool_size = n_osd < 3u ? n_osd : 3u;
	s.epoch = 1;
	s.seed = 77;
	if (wrt_mg_build_map(&w->desc, &s) != 0)
		return -1;
	for (i = 0; i < n_osd; i++)
		wrt_mg_av_v2(&WRT_MG_E(w->desc.client_addrs, wrt_mg_addrvec, i), cw_ip(i), cw_port(i), cw_nonce(i));
	memcpy(w->desc.fsid, w->mon->fsid, 16); /* the maps must name the cluster the monitor's monmap names */
	w->epoch = w->desc.epoch;
	if (wrt_mg_map_encode(&w->desc, &b) != 0)
		return -2;
	if (sim_mon_add_epoch(w->mon, w->epoch, b.p, b.len, NULL, 0) != WR_OK || sim_mon_push_epoch(w->mon) != WR_OK) {
		wrt_mg_buf_free(&b);
		return -3;
	}
	wrt_mg_buf_free(&b);
	return 0;
}

/* The next epoch of the cluster, as an incremental built from `edit` (called with the incremental to fill and the description to keep in step). 0 = ok. */
typedef void (*cw_edit_fn)(wrt_mg_inc *inc, wrt_mg_map *desc, void *arg);

static inline int cw_map_next(cw *w, cw_edit_fn edit, void *arg)
{
	wrt_mg_inc inc;
	wrt_mg_buf b;
	int rc = 0;

	memset(&b, 0, sizeof(b));
	wrt_mg_inc_init(&inc, w->desc.fsid, w->epoch + 1u);
	if (edit != NULL)
		edit(&inc, &w->desc, arg);
	if (wrt_mg_inc_encode(&inc, &b) != 0)
		rc = -1;
	else if (sim_mon_add_epoch(w->mon, w->epoch + 1u, NULL, 0, b.p, b.len) != WR_OK || sim_mon_push_epoch(w->mon) != WR_OK)
		rc = -2;
	else
		w->epoch++, w->desc.epoch = w->epoch;
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(&inc);
	return rc;
}

/* Start the world: n_osd simulators, the monitor with the map, the client created over `cfg` (0 = cw_cfg_default). 0 = ok. */
static inline int cw_open(cw *w, const wr_config *cfg, unsigned n_osd, unsigned pg_num, unsigned key_type)
{
	unsigned i;
	uintptr_t p;

	memset(w, 0, sizeof(*w));
	g_cw_ndone = 0;
	if (n_osd == 0u || n_osd > CW_MAX_OSD)
		return -1;
	w->n_osd = n_osd;
	if (cfg != NULL)
		w->cfg = *cfg;
	else
		cw_cfg_default(&w->cfg);
	w->rng = 0x0123456789abcdefull;
	w->now = 10000;
	w->ops.size = (uint32_t)sizeof(w->ops);
	w->ops.ctx = w;
	w->ops.random = cw_random;
	w->ops.log = cw_log;
	mt_cfg(&w->mcfg, key_type);
	if (g_cw_canary != NULL) {
		uint8_t raw[32];

		memset(raw, 0, sizeof(raw));
		memcpy(raw, g_cw_canary, strlen(g_cw_canary) < sizeof(raw) ? strlen(g_cw_canary) : sizeof(raw));
		if (wr_key_from_raw(&w->mcfg.key, key_type, raw, key_type == WR_KEY_TYPE_AES ? 16u : 32u) != WR_OK)
			return -9;
	}
	w->mcfg.no_default_osdmaps = 1;
	w->mon = sim_mon_new(&w->mcfg);
	w->store = sim_store_new();
	if (w->mon == NULL || w->store == NULL)
		return -2;
	if (cw_build_map(w, n_osd, pg_num) != 0)
		return -3;
	for (i = 0; i < n_osd; i++) {
		memset(&w->addr[i], 0, sizeof(w->addr[i]));
		w->addr[i].family = WR_AF_IPV4;
		w->addr[i].ip[0] = 10, w->addr[i].ip[1] = 77, w->addr[i].ip[2] = 0, w->addr[i].ip[3] = (uint8_t)(40u + i);
		w->addr[i].port = cw_port(i);
		w->addr[i].nonce = cw_nonce(i);
		sim_osd_cfg_default(&w->ocfg[i]);
		w->ocfg[i].mon = w->mon;
		w->ocfg[i].store = w->store;
		w->ocfg[i].id = (int32_t)i;
		w->ocfg[i].seed = 11u + i;
		w->ocfg[i].m2.server_ip[0] = 10, w->ocfg[i].m2.server_ip[1] = 77, w->ocfg[i].m2.server_ip[2] = 0;
		w->ocfg[i].m2.server_ip[3] = w->addr[i].ip[3];
		w->ocfg[i].m2.server_port = w->addr[i].port;
		w->ocfg[i].m2.server_nonce = w->addr[i].nonce;
		w->ocfg[i].m2.check_target = 1;
		w->osd[i] = sim_osd_new(&w->ocfg[i]);
		if (w->osd[i] == NULL)
			return -4;
	}
	strcpy(w->spec.user, "client.winrbd");
	w->spec.key = w->mcfg.key;
	w->spec.n_mons = 1;
	w->spec.mons[0].family = WR_AF_IPV4;
	w->spec.mons[0].ip[0] = 10, w->spec.mons[0].ip[1] = 77, w->spec.mons[0].ip[3] = 10;
	w->spec.mons[0].port = 3300;
	if (wr_client_mem_required(&w->cfg, &w->req) != WR_OK)
		return -5;
	w->arena_raw = (uint8_t *)malloc(w->req.arena + 128u);
	w->bulk_raw = (uint8_t *)malloc(w->req.bulk + 128u);
	if (w->arena_raw == NULL || w->bulk_raw == NULL)
		return -6;
	w->arena_pat = g_cw_pat_a; /* the engine must not lean on zeroed memory */
	w->bulk_pat = g_cw_pat_b;
	w->digest = 0xcbf29ce484222325ull;
	memset(w->arena_raw, w->arena_pat, w->req.arena + 128u);
	memset(w->bulk_raw, w->bulk_pat, w->req.bulk + 128u);
	p = ((uintptr_t)w->arena_raw + 63u) & ~(uintptr_t)63u;
	w->arena_base = (uint8_t *)p;
	w->bulk_base = (uint8_t *)(((uintptr_t)w->bulk_raw + 63u) & ~(uintptr_t)63u);
	if (wr_client_create(&w->cfg, &w->ops, &w->spec, (wr_mem_region){w->arena_base, w->req.arena},
			     (wr_mem_region){w->bulk_base, w->req.bulk}, &w->c) != WR_OK)
		return -7;
	return w->c != NULL ? 0 : -8;
}

static inline void cw_free(cw *w)
{
	unsigned i;

	if (w->c != NULL)
		wr_client_destroy(w->c);
	for (i = 0; i < CW_MAXC; i++) {
		if (w->hc[i].used && w->hc[i].mc != NULL)
			sim_mon_conn_free(w->hc[i].mc);
		if (w->hc[i].used && w->hc[i].oc != NULL)
			sim_osd_conn_free(w->hc[i].oc);
	}
	for (i = 0; i < w->n_osd; i++)
		if (w->osd[i] != NULL)
			sim_osd_free(w->osd[i]);
	if (w->mon != NULL)
		sim_mon_free(w->mon);
	if (w->store != NULL)
		sim_store_free(w->store);
	wrt_mg_map_free(&w->desc);
	free(w->arena_raw);
	free(w->bulk_raw);
	memset(w, 0, sizeof(*w));
}

/* ---- the pump -------------------------------------------------------------------------------------------------------- */

static inline cw_conn *cw_find(cw *w, wr_conn_id id)
{
	unsigned i;

	for (i = 0; i < CW_MAXC; i++)
		if (w->hc[i].used && w->hc[i].id == id)
			return &w->hc[i];
	return NULL;
}

static inline void cw_end(cw *w, cw_conn *hc, int err)
{
	if (hc->mc != NULL)
		sim_mon_conn_free(hc->mc);
	if (hc->oc != NULL)
		sim_osd_conn_free(hc->oc);
	hc->mc = NULL;
	hc->oc = NULL;
	wr_conn_closed(w->c, hc->id, err);
	hc->used = 0;
}

/* Which simulator owns an address: an OSD index, or -1 for the monitor, -2 for nobody. */
static inline int cw_owner(const cw *w, const wr_addr *a)
{
	unsigned i;

	if (a->ip[0] == 10 && a->ip[1] == 77 && a->ip[2] == 0 && a->ip[3] == 10 && a->port == 3300)
		return -1;
	for (i = 0; i < w->n_osd; i++)
		if (a->ip[3] == w->addr[i].ip[3] && a->port == w->addr[i].port)
			return (int)i;
	return -2;
}

static inline unsigned cw_actions(cw *w)
{
	wr_action a;
	unsigned n = 0;

	while (wr_client_next_action(w->c, &a)) {
		cw_conn *hc;
		unsigned i;

		n++;
		w->n_actions++;
		cw_dig_u64(w, (uint64_t)a.kind);
		cw_dig_u64(w, a.conn);
		cw_dig_u64(w, a.timeout_ms);
		if (a.kind == WR_ACT_CONNECT) {
			cw_dig(w, a.addr.ip, 4);
			cw_dig_u64(w, a.addr.port);
			int who = cw_owner(w, &a.addr);

			for (i = 0; i < CW_MAXC && w->hc[i].used; i++) {
			}
			if (i == CW_MAXC)
				abort();
			hc = &w->hc[i];
			memset(hc, 0, sizeof(*hc));
			hc->used = 1;
			hc->id = a.conn;
			hc->osd = who;
			hc->timeout_ms = a.timeout_ms;
			w->n_connects++;
			w->connect_timeout_seen[who >= 0 ? (unsigned)who : w->n_osd] = a.timeout_ms;
			if (who >= 0)
				w->n_connects_osd++;
			if (who == -2 || (who >= 0 && w->osd_down[who])) {
				cw_end(w, hc, 111); /* connection refused */
			} else {
				if (who == -1)
					hc->mc = sim_mon_accept(w->mon);
				else
					hc->oc = sim_osd_accept(w->osd[who]);
				if (hc->mc == NULL && hc->oc == NULL)
					cw_end(w, hc, 111); /* the simulator has no room */
				else
					wr_conn_connected(w->c, hc->id);
			}
		} else if (a.kind == WR_ACT_CLOSE) {
			w->n_closes++;
			hc = cw_find(w, a.conn);
			if (hc != NULL)
				hc->closing = 1;
		}
	}
	return n;
}

static inline int cw_io(cw *w)
{
	unsigned i, live_osd = 0;
	int progress = 0;

	for (i = 0; i < CW_MAXC; i++) {
		cw_conn *hc = &w->hc[i];
		wr_iov iov[8];
		uint8_t *win = NULL;
		size_t n, k, sent = 0, room;

		if (!hc->used)
			continue;
		if (hc->osd >= 0)
			live_osd++;
		if (hc->closing) {
			cw_end(w, hc, 0);
			progress = 1;
			continue;
		}
		n = wr_conn_tx_peek(w->c, hc->id, iov, 8);
		for (k = 0; k < n; k++) {
			cw_dig(w, iov[k].base, iov[k].len);
			if (cw_contains((const uint8_t *)iov[k].base, iov[k].len, w->mcfg.key.secret, 8u))
				w->n_leak_wire++; /* the key never travels */
			if (hc->mc != NULL)
				(void)sim_mon_feed(hc->mc, (const uint8_t *)iov[k].base, iov[k].len);
			else
				(void)sim_osd_feed(hc->oc, (const uint8_t *)iov[k].base, iov[k].len);
			sent += iov[k].len;
		}
		if (sent != 0u) {
			wr_conn_tx_consume(w->c, hc->id, sent);
			progress = 1;
		}
		room = wr_conn_rx_window(w->c, hc->id, &win);
		if (room != 0u && win != NULL) {
			if (hc->inj_len != 0u) {
				n = room < hc->inj_len ? room : hc->inj_len;
				memcpy(win, hc->inj, n);
				memmove(hc->inj, hc->inj + n, hc->inj_len - n);
				hc->inj_len -= n;
			} else {
				n = hc->mc != NULL ? sim_mon_drain(hc->mc, win, room) : sim_osd_drain(hc->oc, win, room);
			}
			if (n != 0u && hc->flip_mask != 0u && hc->flip_off >= hc->rx_total && hc->flip_off < hc->rx_total + n) {
				win[hc->flip_off - hc->rx_total] ^= hc->flip_mask;
				hc->flip_mask = 0;
			}
			hc->rx_total += n;
			if (n != 0u) {
				wr_conn_rx_commit(w->c, hc->id, n);
				progress = 1;
			}
		}
		if ((hc->mc != NULL && sim_mon_closed(hc->mc)) || (hc->oc != NULL && sim_osd_closed(hc->oc))) {
			cw_end(w, hc, 104); /* the peer's EOF or reset */
			progress = 1;
		}
	}
	if (live_osd > w->conns_osd_live_max)
		w->conns_osd_live_max = live_osd;
	return progress;
}

static inline void cw_events(cw *w)
{
	wr_event e;

	while (wr_client_next_event(w->c, &e)) {
		cw_check_errinfo(w, &e.err);
		cw_dig_u64(w, (uint64_t)e.kind);
		cw_dig_u64(w, e.epoch);
		cw_dig_u64(w, (uint64_t)(int64_t)e.err.status);
		if (w->n_ev < CW_EV)
			w->ev[w->n_ev++] = e;
	}
}

static inline unsigned cw_count_ev(const cw *w, wr_ev_kind k)
{
	unsigned i, n = 0;

	for (i = 0; i < w->n_ev; i++)
		n += w->ev[i].kind == k;
	return n;
}

static inline const wr_event *cw_last_ev(const cw *w, wr_ev_kind k)
{
	unsigned i;

	for (i = w->n_ev; i > 0; i--)
		if (w->ev[i - 1u].kind == k)
			return &w->ev[i - 1u];
	return NULL;
}

/* Pull every finished request into g_cw_done. */
static inline unsigned cw_pull(cw *w)
{
	wr_io_req *r;
	unsigned n = 0;

	while ((r = wr_client_next_done(w->c)) != NULL) {
		cw_dig_u64(w, (uint64_t)(int64_t)r->status);
		cw_dig_u64(w, r->offset);
		if (g_cw_ndone < CW_DONE_MAX) {
			g_cw_done[g_cw_ndone].req = r;
			g_cw_done[g_cw_ndone].st = r->status;
			g_cw_ndone++;
		}
		n++;
	}
	return n;
}

/* Forget the completions recorded for a request structure the test reuses. */
static inline void cw_done_forget(const wr_io_req *r)
{
	unsigned i, j = 0;

	for (i = 0; i < g_cw_ndone; i++)
		if (g_cw_done[i].req != r)
			g_cw_done[j++] = g_cw_done[i];
	g_cw_ndone = j;
}

/* wr_image_submit for a request structure the test reuses (the stack slot of an earlier request is the same address): its old completion record goes first. */
static inline wr_status cw_submit(wr_image *img, wr_io_req *r)
{
	if (r != NULL)
		cw_done_forget(r);
	return wr_image_submit(img, r);
}

static inline const cw_done *cw_done_of(const wr_io_req *r)
{
	unsigned i;

	for (i = 0; i < g_cw_ndone; i++)
		if (g_cw_done[i].req == r)
			return &g_cw_done[i];
	return NULL;
}

/* One round of the host loop: run, take the actions, move the bytes, pull. 1 if anything happened. */
static inline int cw_round(cw *w)
{
	wr_clock clk;
	int progress;

	clk.mono_ms = w->now;
	clk.wall_ms = 1700000000000ull + w->now;
	w->last = wr_client_run(w->c, &clk, w->budget);
	w->n_runs++;
	progress = w->last.more_work != 0u;
	progress |= cw_actions(w) != 0u;
	progress |= cw_io(w);
	progress |= cw_pull(w) != 0u;
	cw_events(w);
	return progress;
}

/* Settle: rounds until nothing moves (bounded). Returns the rounds used. */
static inline int cw_settle(cw *w)
{
	int rounds = 0, quiet = 0;

	while (rounds < 20000 && quiet < 3) {
		quiet = cw_round(w) ? 0 : quiet + 1;
		rounds++;
	}
	return rounds;
}

/* Advance the clock by ms in ticks of at most CW_TICK_MS, settling after each. */
static inline void cw_tick(cw *w, uint64_t ms)
{
	while (ms != 0u) {
		uint64_t d = ms < CW_TICK_MS ? ms : CW_TICK_MS;

		w->now += d;
		ms -= d;
		(void)cw_settle(w);
	}
}

/* Settle and advance until `done()` is true or limit_ms of simulated time passed. Returns 1 if done. */
static inline int cw_until(cw *w, int (*done)(void *), void *arg, uint64_t limit_ms)
{
	uint64_t spent = 0;

	(void)cw_settle(w);
	while (!done(arg)) {
		if (spent >= limit_ms)
			return 0;
		cw_tick(w, CW_TICK_MS);
		spent += CW_TICK_MS;
	}
	return 1;
}

/* ---- images and data ------------------------------------------------------------------------------------------------- */

/* An image of the store: pool CW_POOL (metadata), `data_pool` for data (-1 = same pool). */
static inline int cw_image(cw *w, const char *name, const char *id, uint64_t size, uint8_t order, uint64_t features, int64_t data_pool)
{
	sim_rbd_image_cfg c;

	memset(&c, 0, sizeof(c));
	c.pool = CW_POOL;
	c.name = name;
	c.id = id;
	c.size = size;
	c.order = order;
	c.features = features;
	c.data_pool = data_pool;
	return sim_rbd_image_create(w->store, &c) == WR_OK ? 0 : -1;
}

static inline wr_image_params cw_params(const char *name, int want_write)
{
	wr_image_params p;

	memset(&p, 0, sizeof(p));
	p.size = (uint32_t)sizeof(p);
	p.pool = "pool1";
	p.name = name;
	p.snap_id = WR_SNAP_HEAD;
	p.want_write = (uint8_t)want_write;
	return p;
}

typedef struct cw_state_arg {
	cw *w;
	wr_image *img;
	wr_image_state want;
} cw_state_arg;

static inline int cw_state_is(void *a)
{
	cw_state_arg *s = (cw_state_arg *)a;

	return wr_image_get_state(s->img) == s->want;
}

/* Open an image and settle until OPEN (or FAILED). Returns the image, NULL if the open call itself failed. */
static inline wr_image *cw_open_image(cw *w, const wr_image_params *p, wr_image_state *final)
{
	wr_image *img = NULL;
	cw_state_arg a;
	wr_status st = wr_image_open(w->c, p, &img);

	if (st != WR_OK) {
		if (final != NULL)
			*final = WR_IMG_FREE;
		return NULL;
	}
	a.w = w;
	a.img = img;
	a.want = WR_IMG_OPEN;
	if (!cw_until(w, cw_state_is, &a, 60000u)) {
		/* FAILED is a final state too */
		(void)0;
	}
	if (final != NULL)
		*final = wr_image_get_state(img);
	return img;
}

/* A byte pattern: a function of (seed, absolute byte offset), so a read can be checked anywhere without a model. */
static inline uint8_t cw_pat(uint32_t seed, uint64_t off)
{
	uint64_t x = off * 0x9e3779b97f4a7c15ull + (uint64_t)seed * 0xbf58476d1ce4e5b9ull;

	x ^= x >> 29;
	x *= 0x94d049bb133111ebull;
	x ^= x >> 32;
	return (uint8_t)x;
}

static inline void cw_fill(uint8_t *buf, uint32_t seed, uint64_t off, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		buf[i] = cw_pat(seed, off + i);
}

static inline size_t cw_diff(const uint8_t *buf, uint32_t seed, uint64_t off, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (buf[i] != cw_pat(seed, off + i))
			return i + 1u;
	return 0;
}

static inline wr_io_req cw_req(wr_io_kind kind, uint64_t off, uint64_t len, void *buf)
{
	wr_io_req r;

	memset(&r, 0, sizeof(r));
	r.kind = kind;
	r.offset = off;
	r.length = len;
	r.buf = buf;
	return r;
}

/* Submit, run, and settle until the request is pulled: its status, or WR_E_INTERNAL-like -9999 if it never completed. Submit errors are returned as they are. */
#define CW_NEVER (-9999)
static inline wr_status cw_do(cw *w, wr_image *img, wr_io_req *r, uint64_t limit_ms)
{
	wr_status st;
	uint64_t spent = 0;
	const cw_done *d;

	st = cw_submit(img, r);
	if (st != WR_OK)
		return st;
	(void)cw_settle(w);
	while ((d = cw_done_of(r)) == NULL && spent < limit_ms) {
		cw_tick(w, CW_TICK_MS);
		spent += CW_TICK_MS;
	}
	return d != NULL ? d->st : (wr_status)CW_NEVER;
}

#endif /* CLIENT_OSD_RIG_H */
