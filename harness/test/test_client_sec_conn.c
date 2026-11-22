/* SPDX-License-Identifier: MIT */
/*
 * test_client_sec_conn.c (ctest client.sec.conn) - the whole engine in secure mode (docs/design/core-architecture.md 34.2, 34.5, 34.9, 37; module client-glue-sec):
 * wr_client with the maps, the OSD client and the image layer against one sim_mon and N sim_osd (client_osd_rig.h plays the host through the public API only),
 * with the monitor and the OSDs on every allowed-modes list a server can have.
 *
 *   matrix        every policy x every allowed list of the monitor x every allowed list of the OSDs (45 worlds, the policy on both roles), and the 25
 *                 (monitor policy, OSD policy) pairs against servers that allow both: the mode each connection gets is what the first of OUR modes the server
 *                 allows says (the "msgr2 session ready" record carries it, and conns_secure / conns_crc / the secrets the simulators issued agree); a
 *                 world where the server allows none of the offered modes ends in WR_E_M2_BAD_METHOD (WR_EV_AUTH_FAILED with the mask for the monitor), no
 *                 mode is counted, and the log record names the setting to change; a world that works opens an image, writes, reads, flushes, discards, and
 *                 every byte is what the model says
 *   two images    two images on one engine in secure mode, requests interleaved
 *   restarts      the monitor and the OSDs restarted under I/O (twelve writes in flight each time): every write completes, nothing is lost, every
 *                 connection has a secret of its own (the simulators' logs are all different, and the client counted every one of them)
 *   limit         the operation limit lowered to 100 (a test device, g_sc_limit): connections are retired by WR_E_M2_NONCE before a frame is produced and
 *                 redialled, sec_failures counts them, no request is lost, none is applied twice, and a random workload still matches the byte model
 *   renewal       the monitor's tickets expire early (a renewal every 15 s) and the OSD connections idle out: the session and the I/O go on in secure mode
 *   chunk         the smallest legal bounce buffer (256 bytes: every big data segment goes out in many pieces) and one that is not a power of two
 *   small rings   the staging ring of every connection from its smallest sizes up (64, 100, 1000 bytes), sealed and in crc mode
 *   crc is crc    CRC_ONLY against servers that allow both: no slot is handed to a connection, every connection is crc, secure mode was never asked for
 *   fail closed   a connection that cannot be given its secure slot fails with the reason and never runs as crc, never reaches the network, is never counted
 */
#include "wrt.h"

#include "client_sec_rig.h"

#define IMG_SIZE (4u << 20)
#define IMG_ORDER 18u /* 256 KiB objects: a few requests cross an object boundary */
#define SMALL_SIZE (512u << 10) /* the matrix worlds: the simulator's cipher is slow (about 1 MB/s), 45 + 25 worlds read the whole image back */
#define SMALL_ORDER 17u

/* ---- one world ---------------------------------------------------------------------------------------------------------- */

/* The expected counters of the connections that reached READY, against the engine's own, the READY records and the simulators. */
static void check_counters(cw *w, const sc_opts *o, unsigned exp_mon, unsigned exp_osd, int osd_ok)
{
	wr_stats st;
	unsigned mon_s, mon_c, osd_s, osd_c;
	unsigned n_osd_conns = 0, i;

	wr_client_get_stats(w->c, &st);
	sc_ready_counts(WRI_ENTITY_MON, &mon_s, &mon_c);
	sc_ready_counts(WRI_ENTITY_OSD, &osd_s, &osd_c);
	/* every monitor connection is in the mode the offer and the server's list make of it, every OSD connection in the other role's */
	WRT_CHECK(exp_mon == WRI_CONN_MODE_SECURE ? (mon_c == 0u && mon_s >= 1u) : (mon_s == 0u && mon_c >= 1u));
	if (osd_ok)
		WRT_CHECK(exp_osd == WRI_CONN_MODE_SECURE ? (osd_c == 0u && osd_s >= 1u) : (osd_s == 0u && osd_c >= 1u)); /* the image's I/O needed at least one OSD session */
	WRT_CHECK_U64(st.conns_secure, mon_s + osd_s);
	WRT_CHECK_U64(st.conns_crc, mon_c + osd_c);
	WRT_CHECK_U64(st.sec_failures, 0);
	/* the simulators issued a secret for every secure connection and for no other */
	WRT_CHECK_U64(sc_secrets_total(w), st.conns_secure);
	WRT_CHECK(sc_secrets_distinct(w));
	/* every connection to an OSD that the host dialled reached READY */
	for (i = 0; i < CW_MAXC; i++)
		n_osd_conns += w->hc[i].used && w->hc[i].osd >= 0;
	WRT_CHECK(osd_s + osd_c >= n_osd_conns);
	(void)o;
}

/* What the connections that are up look like, against the policy: a connection whose offer has the secure bit has its slot (and the other kind has none), a READY
 * connection is in the mode its keys say (sealed = secure mode, no key = crc), and a connection of a role whose offer lacks crc is never in crc (no downgrade). */
static void check_slots(const cw *w, uint8_t pol, uint8_t pol_osd)
{
	unsigned i, ready = 0;

	for (i = 0; i < w->c->n_slot; i++) {
		const wri_cslot *s = &w->c->slot[i];
		uint8_t offer;
		int sealed;

		if (!s->in_use || s->conn.state < WRI_M2_CONNECTING || s->conn.state > WRI_M2_READY)
			continue;
		offer = wri_m2_offer_for(pol, pol_osd, s->conn.role);
		WRT_CHECK((offer & WRI_M2_OFFER_SECURE) != 0u ? s->conn.sec == &w->c->sec[i] : s->conn.sec == NULL); /* slot i for connection i, none for a crc-only offer */
		if (s->conn.state != WRI_M2_READY)
			continue;
		ready++;
		sealed = s->conn.sec != NULL && s->conn.sec->s.active;
		WRT_CHECK(s->conn.mode == (sealed ? WRI_CONN_MODE_SECURE : WRI_CONN_MODE_CRC));
		WRT_CHECK(wri_m2_offer_has(offer, s->conn.mode)); /* the mode it is in was offered: never crc under secure-only, never secure under crc-only */
	}
	WRT_CHECK(ready >= 1u);
}

static void check_combo(uint8_t pol, uint8_t pol_osd, unsigned mon_allow, unsigned osd_allow, unsigned key_type, unsigned steps)
{
	cw w;
	sc_opts o = sc_defaults(pol);
	unsigned exp_mon, exp_osd;
	wr_stats st;

	o.policy_osd = pol_osd;
	o.mon_allow = mon_allow;
	o.osd_allow = osd_allow;
	o.key_type = key_type;
	WRT_CHECK_U64(sc_open(&w, &o), 0);
	exp_mon = sc_expect_mode(pol, pol_osd, WRI_ENTITY_MON, mon_allow);
	exp_osd = sc_expect_mode(pol, pol_osd, WRI_ENTITY_OSD, osd_allow);

	if (exp_mon == 0u) { /* the monitor refuses: no session, no map, no image; the event says why and the log says what to change */
		const wr_event *ev;
		const sc_logrec *hint;
		uint8_t offer = wri_m2_offer_for(pol, pol_osd, WRI_ENTITY_MON);

		(void)offer;

		cw_tick(&w, 6000);
		ev = cw_last_ev(&w, WR_EV_AUTH_FAILED);
		WRT_CHECK(ev != NULL);
		if (ev != NULL) {
			WRT_CHECK_STATUS(WR_E_M2_BAD_METHOD, ev->err.status);
			WRT_CHECK_U64(ev->err.a1, sc_mode_mask(mon_allow)); /* the server's allowed modes, as it listed them */
			WRT_CHECK(ev->err.peer_result < 0);
		}
		WRT_CHECK_STATUS(WR_E_M2_BAD_METHOD, wr_client_last_error(w.c)->status);
		wr_client_get_stats(w.c, &st);
		WRT_CHECK(st.conns_secure == 0u && st.conns_crc == 0u && st.sec_failures == 0u);
		hint = sc_find_log("monitor", WR_E_M2_BAD_METHOD, 0u);
		WRT_CHECK(hint != NULL);
		if (hint != NULL) { /* the record carries the server's allowed modes, our offer and the role */
			WRT_CHECK_U64(hint->a0, sc_mode_mask(mon_allow));
			WRT_CHECK_U64(hint->a1, offer);
			WRT_CHECK_U64(hint->a2, WRI_ENTITY_MON);
			WRT_CHECK(hint->level == WR_LOG_WARN);
		}
		if ((mon_allow & (SC_ALLOW_CRC | SC_ALLOW_SECURE)) == SC_ALLOW_SECURE) /* only secure allowed, crc-only offered: say "raise the policy" (the order bit of the list does not matter) */
			WRT_CHECK(sc_count_log("allows only secure mode", 0u) >= 1u);
		if ((mon_allow & (SC_ALLOW_CRC | SC_ALLOW_SECURE)) == SC_ALLOW_CRC)
			WRT_CHECK(sc_count_log("allows only crc mode", 0u) >= 1u);
		WRT_CHECK_U64(sc_secrets_total(&w), 0); /* nothing was negotiated, so nothing was issued */
		WRT_CHECK_U64(w.n_leak_log + w.n_leak_wire + w.n_leak_ev, 0);
		cw_free(&w);
		return;
	}
	if (steps != 0u) {
		wr_image *img = sc_image(&w, "img", "id0001", SMALL_SIZE, SMALL_ORDER);

		if (exp_osd == 0u) { /* the OSDs refuse: the monitor session is fine, the image never opens, and the log names the OSD setting */
			WRT_CHECK(img == NULL);
			cw_tick(&w, 4000);
			WRT_CHECK(sc_count_log("OSD ", WR_E_M2_BAD_METHOD) >= 1u);
			if ((osd_allow & (SC_ALLOW_CRC | SC_ALLOW_SECURE)) == SC_ALLOW_SECURE) /* masked: the list's order bit is OR-ed in for some worlds */
				WRT_CHECK(sc_count_log("OSD allows only secure mode", 0u) >= 1u);
			if ((osd_allow & (SC_ALLOW_CRC | SC_ALLOW_SECURE)) == SC_ALLOW_CRC)
				WRT_CHECK(sc_count_log("OSD allows only crc mode", 0u) >= 1u);
			wr_client_get_stats(w.c, &st);
			WRT_CHECK(st.conns_secure + st.conns_crc >= 1u && st.sec_failures == 0u); /* the monitor's connection only */
			cw_free(&w);
			return;
		}
		WRT_CHECK(img != NULL);
		if (img != NULL) {
			sc_work k;
			unsigned i;

			WRT_CHECK_U64(sc_work_init(&k, SMALL_SIZE, 11u, 16u * 1024u), 0);
			for (i = 0; i < steps; i++)
				sc_work_step(&w, img, &k, 60000);
			WRT_CHECK_U64(k.n_fail, 0);
			WRT_CHECK_U64(k.n_bad_read, 0);
			WRT_CHECK_U64(sc_work_verify(&w, img, &k, 60000), 0);
			sc_work_free(&k);
			WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_DRAIN));
			(void)cw_settle(&w);
		}
		check_counters(&w, &o, exp_mon, exp_osd, 1);
	} else {
		(void)cw_settle(&w);
		cw_tick(&w, 3000);
		check_counters(&w, &o, exp_mon, exp_osd, 0);
	}
	check_slots(&w, pol, pol_osd);
	WRT_CHECK_U64(w.n_leak_log + w.n_leak_wire + w.n_leak_ev, 0);
	cw_free(&w);
}

static void test_matrix(void)
{
	static const unsigned allows[3] = {SC_ALLOW_CRC, SC_ALLOW_SECURE, SC_ALLOW_CRC | SC_ALLOW_SECURE};
	uint8_t pol;
	unsigned m, o, n = 0;

	for (pol = WR_MODE_CRC_ONLY; pol <= WR_MODE_STOCK; pol++)
		for (m = 0; m < 3u; m++)
			for (o = 0; o < 3u; o++) {
				/* the allowed list's order is the server's own and does not matter: vary it with the key type */
				unsigned ma = allows[m] | (n % 2u ? SC_ALLOW_SECURE_FIRST : 0u), oa = allows[o] | (n % 3u == 1u ? SC_ALLOW_SECURE_FIRST : 0u);

				check_combo(pol, 0u, ma, oa, n % 2u ? WR_KEY_TYPE_AES : WR_KEY_TYPE_AES256K, 8u);
				n++;
			}
}

/* The monitor on one policy and the OSDs on another, the servers allow both: every pair of policies. */
static void test_pairs(void)
{
	uint8_t pm, po;
	unsigned n = 0;

	for (pm = WR_MODE_CRC_ONLY; pm <= WR_MODE_STOCK; pm++)
		for (po = WR_MODE_CRC_ONLY; po <= WR_MODE_STOCK; po++) {
			check_combo(pm, po, SC_ALLOW_CRC | SC_ALLOW_SECURE, SC_ALLOW_CRC | SC_ALLOW_SECURE, n % 2u ? WR_KEY_TYPE_AES : WR_KEY_TYPE_AES256K, 4u);
			n++;
		}
}

/* ---- CRC_ONLY is crc ------------------------------------------------------------------------------------------------------ */

static void test_crc_is_crc(void)
{
	cw w;
	sc_opts o = sc_defaults(WR_MODE_CRC_ONLY);
	unsigned i;
	wr_stats st;
	wr_image *img;

	WRT_CHECK_U64(sc_open(&w, &o), 0);
	WRT_CHECK(w.c->sec == NULL && w.c->sec_bounce == NULL); /* enable_secure filled the chunk, CRC_ONLY allocated nothing */
	img = sc_image(&w, "img", "id0001", IMG_SIZE, IMG_ORDER);
	WRT_CHECK(img != NULL);
	if (img != NULL) {
		sc_work k;

		WRT_CHECK_U64(sc_work_init(&k, IMG_SIZE, 3u, 16u * 1024u), 0);
		for (i = 0; i < 10u; i++)
			sc_work_step(&w, img, &k, 60000);
		WRT_CHECK(k.n_fail == 0u && k.n_bad_read == 0u);
		sc_work_free(&k);
	}
	for (i = 0; i < w.c->n_slot; i++)
		WRT_CHECK(w.c->slot[i].conn.sec == NULL); /* never handed a slot: crc only, secure mode was not asked for */
	wr_client_get_stats(w.c, &st);
	WRT_CHECK(st.conns_secure == 0u && st.conns_crc >= 2u && st.sec_failures == 0u);
	WRT_CHECK_U64(sc_secrets_total(&w), 0);
	cw_free(&w);
}

/* ---- two images ----------------------------------------------------------------------------------------------------------- */

static void test_two_images(void)
{
	cw w;
	sc_opts o = sc_defaults(WR_MODE_SECURE_FIRST);
	wr_image *a, *b;
	sc_work ka, kb;
	unsigned i;
	wr_stats st;

	/* two images need max_images 2 (the rig default) and enough sessions for both: the default has them */
	WRT_CHECK_U64(sc_open(&w, &o), 0);
	a = sc_image(&w, "imgA", "idA001", IMG_SIZE, IMG_ORDER);
	b = sc_image(&w, "imgB", "idB001", IMG_SIZE, 17u);
	WRT_CHECK(a != NULL && b != NULL);
	if (a != NULL && b != NULL) {
		WRT_CHECK_U64(sc_work_init(&ka, IMG_SIZE, 21u, 20u * 1024u), 0);
		WRT_CHECK_U64(sc_work_init(&kb, IMG_SIZE, 22u, 20u * 1024u), 0);
		for (i = 0; i < 16u; i++) {
			sc_work_step(&w, a, &ka, 60000);
			sc_work_step(&w, b, &kb, 60000);
		}
		WRT_CHECK(ka.n_fail == 0u && ka.n_bad_read == 0u && kb.n_fail == 0u && kb.n_bad_read == 0u);
		WRT_CHECK_U64(sc_work_verify(&w, a, &ka, 60000), 0);
		WRT_CHECK_U64(sc_work_verify(&w, b, &kb, 60000), 0);
		sc_work_free(&ka);
		sc_work_free(&kb);
		WRT_CHECK_STATUS(WR_OK, wr_image_close(a, WR_CLOSE_DRAIN));
		WRT_CHECK_STATUS(WR_OK, wr_image_close(b, WR_CLOSE_DRAIN));
	}
	(void)cw_settle(&w);
	wr_client_get_stats(w.c, &st);
	WRT_CHECK(st.conns_secure >= 2u && st.conns_crc == 0u && st.sec_failures == 0u); /* the monitor and at least one OSD, all sealed */
	WRT_CHECK(sc_secrets_distinct(&w));
	cw_free(&w);
}

/* ---- restarts under I/O --------------------------------------------------------------------------------------------------- */

#define NW 12u
#define WLEN (16u * 1024u)

typedef struct restart_world {
	cw *w;
	wr_io_req q[NW];
	uint8_t *buf[NW];
} restart_world;

static int all_done(void *a)
{
	restart_world *r = (restart_world *)a;
	unsigned i;

	for (i = 0; i < NW; i++)
		if (cw_done_of(&r->q[i]) == NULL)
			return 0;
	return 1;
}

static void test_restarts(void)
{
	cw w;
	sc_opts o = sc_defaults(WR_MODE_SECURE_ONLY);
	restart_world r;
	wr_image *img;
	unsigned round, i, before;
	wr_stats st;
	uint32_t seed = 1000u;

	memset(&r, 0, sizeof(r));
	r.w = &w;
	WRT_CHECK_U64(sc_open(&w, &o), 0);
	img = sc_image(&w, "img", "id0001", IMG_SIZE, IMG_ORDER);
	WRT_CHECK(img != NULL);
	if (img == NULL) {
		cw_free(&w);
		return;
	}
	for (i = 0; i < NW; i++)
		r.buf[i] = (uint8_t *)malloc(WLEN);
	before = sc_secrets_total(&w);
	for (round = 0; round < 4u; round++) {
		unsigned ok = 0;

		for (i = 0; i < NW; i++) {
			uint64_t off = ((uint64_t)round * NW + i) * 65536u + 4093u * (i % 3u); /* distinct, some across an object end */

			cw_fill(r.buf[i], seed + round, off, WLEN);
			r.q[i] = cw_req(WR_IO_WRITE, off, WLEN, r.buf[i]);
			WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r.q[i]));
		}
		cw_tick(&w, 150); /* in flight: some on the wire, some sealed and half sent */
		switch (round) {
		case 0:
			sim_osd_restart(w.osd[0]);
			break;
		case 1:
			sim_mon_restart(w.mon);
			break;
		case 2:
			sim_osd_restart(w.osd[1]);
			sim_osd_restart(w.osd[2]);
			sim_mon_restart(w.mon);
			break;
		default:
			for (i = 0; i < w.n_osd; i++)
				sim_osd_restart(w.osd[i]);
			break;
		}
		WRT_CHECK(cw_until(&w, all_done, &r, 120000));
		for (i = 0; i < NW; i++) {
			const cw_done *d = cw_done_of(&r.q[i]);

			ok += d != NULL && d->st == WR_OK;
		}
		WRT_CHECK_U64(ok, NW); /* nothing lost, nothing failed: a connection that dies is redialled and the requests resent under their tids */
	}
	/* read everything back */
	for (round = 0; round < 4u; round++)
		for (i = 0; i < NW; i++) {
			uint64_t off = ((uint64_t)round * NW + i) * 65536u + 4093u * (i % 3u);
			wr_io_req q = cw_req(WR_IO_READ, off, WLEN, r.buf[i]);

			memset(r.buf[i], 0xEE, WLEN);
			WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &q, 60000));
			WRT_CHECK_U64(cw_diff(r.buf[i], seed + round, off, WLEN), 0);
		}
	wr_client_get_stats(w.c, &st);
	printf("client.sec.conn restarts: %u secrets issued (%u before), conns_secure %u, conns_crc %u, sec_failures %u\n", sc_secrets_total(&w), before,
	       st.conns_secure, st.conns_crc, st.sec_failures);
	WRT_CHECK(sc_secrets_total(&w) >= before + 3u); /* every restart made new connections */
	WRT_CHECK(sc_secrets_distinct(&w)); /* ... and each had its own secret, the old ones were not reused */
	WRT_CHECK_U64(st.conns_secure, sc_secrets_total(&w));
	WRT_CHECK_U64(st.conns_crc, 0);
	WRT_CHECK_U64(st.sec_failures, 0); /* a reset is not a secure-mode failure */
	{
		unsigned viol, doubled = sc_doubled(&w, &viol);

		WRT_CHECK_U64(viol, 0);
		WRT_CHECK_U64(doubled, 0);
	}
	WRT_CHECK_U64(w.n_leak_log + w.n_leak_wire + w.n_leak_ev, 0);
	for (i = 0; i < NW; i++)
		free(r.buf[i]);
	cw_free(&w);
}

/* ---- the operation limit ------------------------------------------------------------------------------------------------ */

static void test_limit(void)
{
	cw w;
	sc_opts o = sc_defaults(WR_MODE_SECURE_ONLY);
	wr_image *img;
	sc_work k;
	wr_stats st;
	unsigned i, viol, doubled;
	uint64_t nonces_seen = 0;

	o.limit = 100; /* per direction: a connection that carries a few dozen frames is retired */
	WRT_CHECK_U64(sc_open(&w, &o), 0);
	img = sc_image(&w, "img", "id0001", 1u << 20, SMALL_ORDER);
	WRT_CHECK(img != NULL);
	if (img == NULL) {
		cw_free(&w);
		return;
	}
	WRT_CHECK_U64(sc_work_init(&k, 1u << 20, 77u, 12u * 1024u), 0);
	for (i = 0; i < 170u; i++)
		sc_work_step(&w, img, &k, 120000);
	WRT_CHECK_U64(k.n_fail, 0);
	WRT_CHECK_U64(k.n_bad_read, 0); /* the part C model test, in secure mode, across the retirements */
	WRT_CHECK_U64(sc_work_verify(&w, img, &k, 120000), 0);
	sc_work_free(&k);
	WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_DRAIN));
	(void)cw_settle(&w);
	wr_client_get_stats(w.c, &st);
	for (i = 0; i < g_sc_nlog; i++)
		nonces_seen += g_sc_log[i].st == WR_E_M2_NONCE;
	printf("client.sec.conn limit 100: %u secure connections, %u retired on the limit (%llu records), %u limits set, %u reconnects to OSDs\n", st.conns_secure,
	       st.sec_failures, (unsigned long long)nonces_seen, g_sc_limit_set, w.n_connects_osd);
	WRT_CHECK(st.sec_failures >= 3u); /* connections WERE retired by the limit (and the engine counted them) */
	WRT_CHECK(nonces_seen >= st.sec_failures);
	WRT_CHECK(st.conns_secure >= st.sec_failures + 2u); /* ... and redialled: more connections than failures */
	WRT_CHECK_U64(st.conns_crc, 0);
	WRT_CHECK(g_sc_limit_set >= st.conns_secure);
	WRT_CHECK(sc_secrets_distinct(&w)); /* a redial is a new key */
	doubled = sc_doubled(&w, &viol);
	WRT_CHECK_U64(viol, 0);
	WRT_CHECK_U64(doubled, 0);
	/* the secret of a retired connection is gone from the engine's memory: nothing of any secret is in it but what a live connection holds as its key
	 * schedule and nonces (the unused tail S[40..] and the window of S[16..] that are not nonce seeds are nowhere) */
	WRT_CHECK_U64(sc_scan_memory(&w, 1), 0);
	WRT_CHECK_U64(sc_scan_memory(&w, 0), 0);
	WRT_CHECK_U64(w.n_leak_log + w.n_leak_wire + w.n_leak_ev, 0);
	cw_free(&w);
}

/* ---- renewal ----------------------------------------------------------------------------------------------------------------- */

static void test_renewal(void)
{
	cw w;
	sc_opts o = sc_defaults(WR_MODE_SECURE_FIRST);
	wr_image *img;
	sc_work k;
	wr_stats st;
	unsigned i, renewals_before;

	WRT_CHECK_U64(sc_open(&w, &o), 0);
	w.mon->cfg.tkt[sim_mon_slot(WRI_CX_SERVICE_OSD)].validity_s = 20; /* a renewal every 15 s (the in-session path) */
	img = sc_image(&w, "img", "id0001", IMG_SIZE, IMG_ORDER);
	WRT_CHECK(img != NULL);
	if (img == NULL) {
		cw_free(&w);
		return;
	}
	WRT_CHECK_U64(sc_work_init(&k, IMG_SIZE, 5u, 20u * 1024u), 0);
	for (i = 0; i < 6u; i++)
		sc_work_step(&w, img, &k, 60000);
	renewals_before = w.mon->n_renewals;
	for (i = 0; i < 4u; i++) { /* 12 s of idle between bursts: 48 s in all, two to three renewals */
		cw_tick(&w, 12000);
		sc_work_step(&w, img, &k, 60000);
		sc_work_step(&w, img, &k, 60000);
	}
	WRT_CHECK(w.mon->n_renewals > renewals_before);
	WRT_CHECK(w.mon->n_renewals >= 1u);
	WRT_CHECK(k.n_fail == 0u && k.n_bad_read == 0u);
	WRT_CHECK_U64(sc_work_verify(&w, img, &k, 60000), 0);
	sc_work_free(&k);
	wr_client_get_stats(w.c, &st);
	WRT_CHECK(st.conns_secure >= 2u && st.conns_crc == 0u && st.sec_failures == 0u);
	WRT_CHECK(sc_secrets_distinct(&w));
	WRT_CHECK_U64(w.n_leak_log + w.n_leak_wire + w.n_leak_ev, 0);
	cw_free(&w);
}

/* ---- the bounce buffer sizes --------------------------------------------------------------------------------------------------- */

static void test_chunks(void)
{
	static const uint32_t chunks[] = {256u, 1008u, 4096u};
	unsigned c;

	for (c = 0; c < sizeof(chunks) / sizeof(chunks[0]); c++) {
		cw w;
		sc_opts o = sc_defaults(WR_MODE_SECURE_ONLY);
		wr_image *img;
		sc_work k;
		unsigned i;

		o.sec_tx_chunk = chunks[c];
		o.n_osd = 2;
		WRT_CHECK_U64(sc_open(&w, &o), 0);
		img = sc_image(&w, "img", "id0001", IMG_SIZE, IMG_ORDER);
		WRT_CHECK(img != NULL);
		if (img != NULL) {
			WRT_CHECK_U64(sc_work_init(&k, IMG_SIZE, 90u + c, 40u * 1024u), 0);
			for (i = 0; i < 10u; i++) /* data segments of up to 40 KiB go out in pieces of `chunk` bytes */
				sc_work_step(&w, img, &k, 120000);
			WRT_CHECK(k.n_fail == 0u && k.n_bad_read == 0u);
			WRT_CHECK_U64(sc_work_verify(&w, img, &k, 120000), 0);
			sc_work_free(&k);
		}
		WRT_CHECK_U64(w.c->sec_chunk, chunks[c]);
		cw_free(&w);
	}
}

/* ---- small receive rings ------------------------------------------------------------------------------------------------------ */

/* The staging ring of every connection from its smallest legal size up: the secure parser stages part 1 in its own slot, so a ring that is smaller than a frame
 * is as good as it is in crc mode. The same worlds in crc mode as the reference. */
static void test_small_rings(void)
{
	static const uint32_t rings[] = {64u, 100u, 1000u};
	unsigned r, pol;

	for (pol = 0; pol < 2u; pol++)
		for (r = 0; r < sizeof(rings) / sizeof(rings[0]); r++) {
			cw w;
			sc_opts o = sc_defaults(pol ? WR_MODE_SECURE_ONLY : WR_MODE_CRC_ONLY);
			wr_image *img;
			sc_work k;
			unsigned i;
			wr_stats st;

			o.rx_buf_bytes = rings[r];
			o.sec_tx_chunk = 512u;
			o.n_osd = 2;
			WRT_CHECK_U64(sc_open(&w, &o), 0);
			img = sc_image(&w, "img", "id0001", SMALL_SIZE, SMALL_ORDER);
			WRT_CHECK(img != NULL);
			if (img != NULL) {
				WRT_CHECK_U64(sc_work_init(&k, SMALL_SIZE, 120u + r, 16u * 1024u), 0);
				for (i = 0; i < 8u; i++)
					sc_work_step(&w, img, &k, 120000);
				WRT_CHECK(k.n_fail == 0u && k.n_bad_read == 0u);
				WRT_CHECK_U64(sc_work_verify(&w, img, &k, 120000), 0);
				sc_work_free(&k);
			}
			wr_client_get_stats(w.c, &st);
			WRT_CHECK(pol ? (st.conns_secure >= 2u && st.conns_crc == 0u) : (st.conns_crc >= 2u && st.conns_secure == 0u));
			cw_free(&w);
		}
}

/* ---- fail closed ---------------------------------------------------------------------------------------------------------- */

/* The engine hands every connection whose offer has the secure bit its slot and bounce buffer at open. If the connection refuses them (it cannot happen with
 * a configuration that passed the check at create; here the engine's own copy of the bounce size is damaged on purpose, through the internal header), the
 * connection must FAIL with the reason: never run on as a crc-only connection that was meant to offer secure, never reach the network, never be counted. The
 * failure is reported like a refused open (at the next step; no WR_ACT_CLOSE is owed, the host never saw a connect), and the engine keeps trying. */
static void test_prepare_failure_fails_closed(void)
{
	static const uint8_t pol[] = {WR_MODE_SECURE_ONLY, WR_MODE_SECURE_FIRST, WR_MODE_CRC_FIRST, WR_MODE_STOCK};
	unsigned k, i;

	for (k = 0; k < sizeof(pol); k++) {
		cw w;
		sc_opts o = sc_defaults(pol[k]);
		wr_stats st;

		WRT_CHECK_U64(sc_open(&w, &o), 0);
		WRT_CHECK(w.c->sec != NULL && w.c->sec_chunk >= 256u);
		w.c->sec_chunk = 100; /* not a multiple of 16: wri_m2_conn_set_secure refuses it with WR_E_INVAL */
		cw_tick(&w, 6000);
		wr_client_get_stats(w.c, &st);
		WRT_CHECK_U64(w.n_connects, 0); /* no socket was ever asked for: the connection died inside open */
		WRT_CHECK(st.conns_secure == 0u && st.conns_crc == 0u);
		WRT_CHECK_U64(sc_secrets_total(&w), 0);
		WRT_CHECK(sc_count_log("connection failed", WR_E_INVAL) >= 1u);
		WRT_CHECK(sc_count_log("session ready", 0) == 0u);
		for (i = 0; i < w.c->n_slot; i++)
			WRT_CHECK(!w.c->slot[i].in_use || w.c->slot[i].conn.state != WRI_M2_READY);
		WRT_CHECK(wr_client_get_state(w.c) != WR_CS_ACTIVE);
		cw_free(&w);
	}
}

int main(void)
{
	test_crc_is_crc();
	test_prepare_failure_fails_closed();
	test_matrix();
	test_pairs();
	test_two_images();
	test_restarts();
	test_limit();
	test_renewal();
	test_chunks();
	test_small_rings();
	return wrt_finish();
}
