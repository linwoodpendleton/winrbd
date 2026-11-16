/* SPDX-License-Identifier: MIT */
/*
 * test_client_secrets.c - key hygiene of the client engine.
 *
 *   - A canary key (printable, so a stray string match is easy to see) is used for whole sessions of both
 *     key types: login, ticket renewal with a short ticket lifetime, a monitor restart (reclaim), and a
 *     session with the wrong key. The host log sink scans every record (message and the four numbers) and
 *     every event / errinfo the engine hands out for the canary words; the transmit side scans everything
 *     the engine writes to the wire for the key bytes (the key never travels).
 *   - A positive control: the canary IS found in the arena while the client lives, so the scan is able to
 *     see it; after wr_client_destroy the arena holds no key bytes (principal, session keys, ticket blobs
 *     all gone: the used part is all zero), and neither does the bulk region.
 */
#include "sim_mon_tc.h"
#include "wri_client.h"

#define MAXH 4u

static const char canary_text[] = "CANARYKEY-0123456789-ABCDEFGHIJ"; /* 31 characters + NUL: 32 bytes with the terminator */

typedef struct region {
	uint8_t *raw, *base;
	size_t size;
} region;

typedef struct hconn {
	int used, connected, closing;
	wr_conn_id id;
	sim_mon_conn *sc;
} hconn;

typedef struct sh {
	wr_client *c;
	wr_config cfg;
	wr_host_ops ops;
	wr_cluster_spec spec;
	region arena, bulk;
	sim_mon *sim;
	sim_mon_cfg scfg;
	wr_key key; /* the canary key */
	uint64_t rng, now;
	hconn hc[MAXH];
	unsigned n_log, n_leak_log, n_leak_wire, n_leak_ev, n_events;
} sh;

static int contains(const uint8_t *hay, size_t hn, const uint8_t *needle, size_t nn)
{
	size_t i;

	if (nn == 0 || hn < nn)
		return 0;
	for (i = 0; i + nn <= hn; i++)
		if (hay[i] == needle[0] && memcmp(hay + i, needle, nn) == 0)
			return 1;
	return 0;
}

/* One 64-bit number equal to any aligned or unaligned 8-byte window of the key, either byte order. */
static int number_is_key_word(const sh *h, uint64_t v)
{
	size_t i, k;

	for (i = 0; i + 8u <= h->key.len; i++) {
		uint64_t le = 0, be = 0;

		for (k = 0; k < 8u; k++) {
			le |= (uint64_t)h->key.secret[i + k] << (8u * k);
			be = (be << 8) | h->key.secret[i + k];
		}
		if (v == le || v == be)
			return 1;
	}
	return 0;
}

static void log_cb(void *ctx, const wr_log_rec *r)
{
	sh *h = (sh *)ctx;

	h->n_log++;
	if (r->msg != NULL && (strstr(r->msg, "CANARY") != NULL || contains((const uint8_t *)r->msg, strlen(r->msg), h->key.secret, 6)))
		h->n_leak_log++;
	if (number_is_key_word(h, r->a0) || number_is_key_word(h, r->a1) || number_is_key_word(h, r->a2) || number_is_key_word(h, r->a3))
		h->n_leak_log++;
}

static void check_errinfo(sh *h, const wr_errinfo *e)
{
	if (number_is_key_word(h, e->a0) || number_is_key_word(h, e->a1) || number_is_key_word(h, e->a2) ||
	    (e->what != NULL && strstr(e->what, "CANARY") != NULL))
		h->n_leak_ev++;
}

static wr_status h_random(void *ctx, uint8_t *out, size_t n)
{
	sh *h = (sh *)ctx;
	size_t i;

	for (i = 0; i < n; i++) {
		h->rng ^= h->rng >> 12;
		h->rng ^= h->rng << 25;
		h->rng ^= h->rng >> 27;
		out[i] = (uint8_t)((h->rng * 0x2545f4914f6cdd1dull) >> 56);
	}
	return WR_OK;
}

static void region_new(region *r, size_t size)
{
	r->raw = (uint8_t *)calloc(1, size + 128u);
	if (r->raw == NULL)
		abort();
	r->base = (uint8_t *)(((uintptr_t)r->raw + 63u) & ~(uintptr_t)63u);
	r->size = size;
}

static sh *sh_new(unsigned type, int wrong_key)
{
	sh *h = (sh *)calloc(1, sizeof(*h));
	wr_mem_req req;
	size_t klen = type == WR_KEY_TYPE_AES ? 16u : 32u;

	if (h == NULL)
		abort();
	wr_config_profile_harness(&h->cfg);
	h->cfg.mon_msg_cap = 256u * 1024u;
	h->rng = 0x5eed5eed5eed5eedull;
	h->now = 10000;
	h->ops.size = (uint32_t)sizeof(h->ops);
	h->ops.ctx = h;
	h->ops.random = h_random;
	h->ops.log = log_cb;
	WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&h->key, type, (const uint8_t *)canary_text, klen));
	mt_cfg(&h->scfg, type);
	h->scfg.key = h->key;
	h->scfg.tkt[sim_mon_slot(WRI_CX_SERVICE_OSD)].validity_s = 20; /* renewal at 15 s: the in-session path runs too */
	h->sim = sim_mon_new(&h->scfg);
	if (h->sim == NULL)
		abort();
	strcpy(h->spec.user, "client.winrbd");
	if (wrong_key)
		mt_key(&h->spec.key, type, 77);
	else
		h->spec.key = h->key;
	h->spec.n_mons = 1;
	h->spec.mons[0].family = WR_AF_IPV4;
	h->spec.mons[0].ip[0] = 10, h->spec.mons[0].ip[1] = 77, h->spec.mons[0].ip[3] = 10;
	h->spec.mons[0].port = 3300;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&h->cfg, &req));
	region_new(&h->arena, req.arena);
	region_new(&h->bulk, req.bulk);
	WRT_CHECK_STATUS(WR_OK, wr_client_create(&h->cfg, &h->ops, &h->spec, (wr_mem_region){h->arena.base, h->arena.size},
						 (wr_mem_region){h->bulk.base, h->bulk.size}, &h->c));
	if (h->c == NULL)
		abort();
	return h;
}

static void sh_free(sh *h)
{
	unsigned i;

	for (i = 0; i < MAXH; i++)
		if (h->hc[i].used && h->hc[i].sc != NULL)
			sim_mon_conn_free(h->hc[i].sc);
	sim_mon_free(h->sim);
	free(h->arena.raw);
	free(h->bulk.raw);
	free(h);
}

static void hc_end(sh *h, hconn *hc, int err)
{
	if (hc->sc != NULL)
		sim_mon_conn_free(hc->sc);
	hc->sc = NULL;
	wr_conn_closed(h->c, hc->id, err);
	hc->used = 0;
}

static int host_round(sh *h)
{
	wr_clock clk = {h->now, 0};
	wr_action a;
	wr_event e;
	wr_mapmsg m;
	unsigned i;
	int progress = 0;
	wr_run_result r = wr_client_run(h->c, &clk, 0);

	while (wr_client_next_event(h->c, &e)) {
		h->n_events++;
		check_errinfo(h, &e.err);
	}
	check_errinfo(h, wr_client_last_error(h->c));
	while (wr_client_mapmsg_peek(h->c, &m))
		wr_client_mapmsg_release(h->c);
	while (wr_client_next_action(h->c, &a)) {
		progress = 1;
		if (a.kind == WR_ACT_CONNECT) {
			for (i = 0; i < MAXH && h->hc[i].used; i++) {
			}
			if (i == MAXH)
				abort();
			memset(&h->hc[i], 0, sizeof(h->hc[i]));
			h->hc[i].used = 1;
			h->hc[i].id = a.conn;
		} else if (a.kind == WR_ACT_CLOSE) {
			for (i = 0; i < MAXH; i++)
				if (h->hc[i].used && h->hc[i].id == a.conn)
					h->hc[i].closing = 1;
		}
	}
	for (i = 0; i < MAXH; i++) {
		hconn *hc = &h->hc[i];
		wr_iov iov[8];
		uint8_t *w = NULL;
		size_t n, k, room, sent = 0;

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
			hc->connected = progress = 1;
		}
		n = wr_conn_tx_peek(h->c, hc->id, iov, 8);
		for (k = 0; k < n; k++) {
			if (contains(iov[k].base, iov[k].len, h->key.secret, 16))
				h->n_leak_wire++; /* the key (or a long piece of it) on the wire */
			(void)sim_mon_feed(hc->sc, iov[k].base, iov[k].len);
			sent += iov[k].len;
		}
		if (sent != 0) {
			wr_conn_tx_consume(h->c, hc->id, sent);
			progress = 1;
		}
		room = wr_conn_rx_window(h->c, hc->id, &w);
		if (room != 0 && w != NULL) {
			size_t got = sim_mon_drain(hc->sc, w, room);

			if (got != 0) {
				wr_conn_rx_commit(h->c, hc->id, got);
				progress = 1;
			}
		}
		if (hc->sc != NULL && sim_mon_closed(hc->sc)) {
			hc_end(h, hc, 0);
			progress = 1;
		}
	}
	return progress || r.more_work;
}

static void run_ms(sh *h, uint64_t ms)
{
	uint64_t end = h->now + ms;
	unsigned guard;

	while (h->now < end) {
		for (guard = 0; guard < 100000u && host_round(h); guard++) {
		}
		h->now += 50;
	}
}

/* ---- the scan of the arena -------------------------------------------------------------------------------- */

static int in_region(const region *r, const uint8_t *needle, size_t nn)
{
	return contains(r->base, r->size, needle, nn);
}

static void check_scenario(unsigned type, const char *label)
{
	sh *h = sh_new(type, 0);
	uint8_t sess[WR_KEY_MAX], osd[WR_KEY_MAX];
	size_t sess_len, osd_len, i;
	wr_stats st;
	const uint8_t *abuf, *fbuf;
	uint32_t abuf_cap;

	run_ms(h, 40000); /* login, two OSD ticket renewals (every 15 s), keepalives */
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
	WRT_CHECK(h->sim->n_renewals >= 1u);
	sim_mon_restart(h->sim); /* a reclaim with the old ticket */
	run_ms(h, 20000);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
	WRT_CHECK_U64(h->sim->n_reclaims, 1);
	WRT_CHECK(h->n_log > 0u);
	WRT_CHECK_U64(h->n_leak_log, 0);
	WRT_CHECK_U64(h->n_leak_wire, 0);
	WRT_CHECK_U64(h->n_leak_ev, 0);
	printf("secrets %-6s: %u log records, %u events scanned, no canary seen\n", label, h->n_log, h->n_events);

	/* positive control: the scan can see the key while the client lives */
	WRT_CHECK(in_region(&h->arena, h->key.secret, h->key.len));
	WRT_CHECK(h->c->cx.ticket[WRI_CX_SLOT_AUTH].have);
	sess_len = h->c->cx.ticket[WRI_CX_SLOT_AUTH].session_key.len;
	memcpy(sess, h->c->cx.ticket[WRI_CX_SLOT_AUTH].session_key.secret, sess_len);
	WRT_CHECK(sess_len >= 16u && in_region(&h->arena, sess, sess_len));
	osd_len = h->c->cx.ticket[WRI_CX_SLOT_OSD].have ? h->c->cx.ticket[WRI_CX_SLOT_OSD].session_key.len : 0;
	if (osd_len != 0)
		memcpy(osd, h->c->cx.ticket[WRI_CX_SLOT_OSD].session_key.secret, osd_len);

	wr_client_get_stats(h->c, &st);
	abuf = h->c->mon.abuf;
	fbuf = h->c->mon.fbuf;
	abuf_cap = h->c->mon.abuf_cap;
	WRT_CHECK(abuf != NULL && fbuf != NULL && abuf_cap != 0u);
	wr_client_destroy(h->c);
	for (i = 0; abuf != NULL && fbuf != NULL && i < abuf_cap; i++) /* the renewal buffers live in the bulk region: sealed cephx payloads */
		if (abuf[i] != 0 || fbuf[i] != 0) {
			WRT_CHECK(0 && "renewal buffers not zero after destroy");
			break;
		}
	for (i = 0; i < st.arena_used; i++)
		if (h->arena.base[i] != 0) {
			WRT_CHECK(0 && "arena not zero after destroy");
			break;
		}
	WRT_CHECK(!in_region(&h->arena, h->key.secret, 16));
	WRT_CHECK(!in_region(&h->arena, sess, sess_len));
	if (osd_len != 0)
		WRT_CHECK(!in_region(&h->arena, osd, osd_len));
	WRT_CHECK(!in_region(&h->bulk, h->key.secret, 16));
	WRT_CHECK(!in_region(&h->bulk, sess, sess_len));
	h->c = NULL;
	sh_free(h);
}

/* A refused login (wrong key) and the hunting that follows leak nothing either. */
static void check_wrong_key(unsigned type, const char *label)
{
	sh *h = sh_new(type, 1);

	run_ms(h, 30000);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_HUNTING);
	WRT_CHECK(h->n_log > 0u);
	WRT_CHECK_U64(h->n_leak_log, 0);
	WRT_CHECK_U64(h->n_leak_wire, 0);
	WRT_CHECK_U64(h->n_leak_ev, 0);
	/* the key the client holds is not the canary here, so the positive control is about the sim's canary on the wire only */
	printf("secrets %-6s wrong key: %u log records, no canary seen\n", label, h->n_log);
	wr_client_destroy(h->c);
	h->c = NULL;
	sh_free(h);
}

int main(void)
{
	check_scenario(WR_KEY_TYPE_AES, "k1");
	check_scenario(WR_KEY_TYPE_AES256K, "k2");
	check_wrong_key(WR_KEY_TYPE_AES, "k1");
	check_wrong_key(WR_KEY_TYPE_AES256K, "k2");
	return wrt_finish();
}
