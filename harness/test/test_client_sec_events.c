/* SPDX-License-Identifier: MIT */
/*
 * test_client_sec_events.c (ctest client.sec.events) - what the engine tells the host about secure mode, and what it never tells it (docs/design/core-architecture.md
 * 34.2, 34.3, 34.8, 37; module client-glue-sec). The whole engine against sim_mon and sim_osd through the public API, as in client.sec.conn.
 *
 *   refusals      AUTH_BAD_METHOD from the monitor is WR_EV_AUTH_FAILED with WR_E_M2_BAD_METHOD, the server's allowed-modes mask in the errinfo and
 *                 wr_client_last_error; the engine's log record carries the mask, our offer and the role, and says which setting to change ({secure} allowed
 *                 with a crc-only offer, {crc} with a secure-only one); no mode is counted, no automatic second attempt with another mode is made (the
 *                 server sees no AUTH_REQUEST that offers a mode the policy does not list)
 *   ready record  every "msgr2 session ready" record carries the role and the mode (conns_secure / conns_crc are made of exactly these)
 *   downgrade     a server that answers AUTH_DONE with a mode that was not offered (crc under secure-only, secure under crc-only): WR_E_M2_MODE, never READY, never counted
 *   failures      a server that negotiates secure and sends no secret, a secret that is too short, a wrong key, a wrong nonce seed, a damaged frame in the
 *                 session: the connection fails with WR_E_M2_SECRET / WR_E_M2_SEC_TAG, sec_failures counts it, the connection never counted as secure unless
 *                 it reached READY; a secret in crc mode is WR_E_AUTH_PROTO and no secure failure; the same for an OSD that refuses
 *   closed first  a secure failure recorded inside a send call and not yet seen by a step is still counted (sec_failures) when the host reports the socket
 *                 closed first (wr_conn_closed looks at the connection before it turns FREE)
 *   saturation    the counters stop at 2^32 - 1 (white box: put at the limit, the engine goes on connecting and failing)
 *   canary        the key canary of part A, extended: a printable key and every issued connection secret through whole secure sessions, refusals, failures
 *                 and restarts of both key types: no log record, event or errinfo carries a word of the key or of any secret, no "CANARY" string, and the
 *                 wire never carries the key
 *   destroy       a client destroyed while data is half way through its bounce buffer: the arena part in use is zero (slots, bounce buffers, key schedules,
 *                 the staging of the parser), no secret of any connection is anywhere in the arena or the bulk, nothing outside the regions was written
 *   host gcm      the host's own GCM objects (the table of wr_host.h, a fake that keeps one object per direction of a connection): every object the
 *                 engine keyed is wiped when its connection ends, and a destroy in the middle of a session hands back every one that is left
 *   live          while the connections are up the unused tail of every secret and the whole secret are in no byte of the engine's memory: what a connection
 *                 keeps is its key schedule and its two nonces
 */
#include "wrt.h"

#include "client_sec_rig.h"
#include "wri_pgcm.h"

#define IMG_SIZE (1u << 20)
#define IMG_ORDER 17u

/* 1 when a 64-bit number equals any 8-byte window of any issued secret, either byte order. */
static int number_is_secret_word(const cw *w, uint64_t v)
{
	const sim_sec_log *logs[CW_MAX_OSD + 1u];
	unsigned n = 0, i, a;

	logs[n++] = sim_mon_secrets(w->mon);
	for (i = 0; i < w->n_osd; i++)
		logs[n++] = sim_osd_secrets(w->osd[i]);
	for (i = 0; i < n; i++)
		for (a = 0; a < logs[i]->kept; a++) {
			const uint8_t *s = logs[i]->secret[a];
			size_t k, j, len = logs[i]->len[a];

			for (k = 0; k + 8u <= len; k++) {
				uint64_t le = 0, be = 0;

				for (j = 0; j < 8u; j++) {
					le |= (uint64_t)s[k + j] << (8u * j);
					be = (be << 8) | s[k + j];
				}
				if (v == le || v == be)
					return 1;
			}
		}
	return 0;
}

/* Records, events and errinfos that show a word of an issued secret (the rig's own canary counts the key). */
static unsigned secret_leaks(const cw *w)
{
	unsigned i, n = 0;

	for (i = 0; i < g_sc_nlog; i++)
		n += number_is_secret_word(w, g_sc_log[i].a0) + number_is_secret_word(w, g_sc_log[i].a1) + number_is_secret_word(w, g_sc_log[i].a2) +
		     number_is_secret_word(w, g_sc_log[i].a3);
	for (i = 0; i < w->n_ev; i++)
		n += number_is_secret_word(w, w->ev[i].err.a0) + number_is_secret_word(w, w->ev[i].err.a1) + number_is_secret_word(w, w->ev[i].err.a2);
	return n;
}

/* ---- the refusal ---------------------------------------------------------------------------------------------------------- */

static void test_refusals(void)
{
	static const struct {
		uint8_t policy;
		unsigned allow;
		const char *hint;
	} rows[] = {
		{WR_MODE_CRC_ONLY, SC_ALLOW_SECURE, "monitor allows only secure mode"},
		{WR_MODE_CRC_FIRST, SC_ALLOW_SECURE, NULL}, /* crc-first reaches secure: no refusal */
		{WR_MODE_SECURE_ONLY, SC_ALLOW_CRC, "monitor allows only crc mode"},
		{WR_MODE_SECURE_FIRST, SC_ALLOW_CRC, NULL},
	};
	unsigned r, key;

	for (key = 0; key < 2u; key++)
		for (r = 0; r < sizeof(rows) / sizeof(rows[0]); r++) {
			cw w;
			sc_opts o = sc_defaults(rows[r].policy);
			unsigned refuse = rows[r].hint != NULL;
			unsigned i;
			wr_stats st;

			o.mon_allow = rows[r].allow;
			o.key_type = key ? WR_KEY_TYPE_AES : WR_KEY_TYPE_AES256K;
			WRT_CHECK_U64(sc_open(&w, &o), 0);
			/* no second attempt with another mode: the hunt goes on with the same offer, so a refusing server refuses every connection it gets (a second try
			 * that listed the other mode would have been answered) */
			cw_tick(&w, 9000);
			wr_client_get_stats(w.c, &st);
			if (!refuse) {
				WRT_CHECK(cw_count_ev(&w, WR_EV_AUTH_FAILED) == 0u);
				WRT_CHECK(st.conns_secure + st.conns_crc >= 1u);
				WRT_CHECK(wr_client_get_state(w.c) == WR_CS_ACTIVE);
			} else {
				const wr_event *ev = cw_last_ev(&w, WR_EV_AUTH_FAILED);
				const wr_errinfo *le = wr_client_last_error(w.c);
				const sc_logrec *h = sc_find_log("monitor", WR_E_M2_BAD_METHOD, 0u);

				WRT_CHECK(ev != NULL && h != NULL);
				if (ev != NULL) {
					WRT_CHECK_STATUS(WR_E_M2_BAD_METHOD, ev->err.status);
					WRT_CHECK_U64(ev->err.a1, sc_mode_mask(rows[r].allow));
					WRT_CHECK_U64(ev->err.a2, 2); /* the method we offered: cephx */
					WRT_CHECK(ev->err.peer_result < 0 && ev->err.module == WR_MOD_M2 && ev->err.conn != 0u);
					WRT_CHECK(ev->err.what != NULL);
				}
				WRT_CHECK_STATUS(WR_E_M2_BAD_METHOD, le->status);
				WRT_CHECK_U64(le->a1, sc_mode_mask(rows[r].allow));
				WRT_CHECK(sc_count_log(rows[r].hint, WR_E_M2_BAD_METHOD) >= 1u); /* which setting to change */
				if (h != NULL) {
					WRT_CHECK_U64(h->a0, sc_mode_mask(rows[r].allow));
					WRT_CHECK_U64(h->a1, wri_m2_offer_for(rows[r].policy, 0, WRI_ENTITY_MON));
					WRT_CHECK_U64(h->a2, WRI_ENTITY_MON);
				}
				WRT_CHECK(st.conns_secure == 0u && st.conns_crc == 0u && st.sec_failures == 0u);
				WRT_CHECK(wr_client_get_state(w.c) != WR_CS_ACTIVE);
				WRT_CHECK(w.n_connects >= 2u); /* it kept hunting (back-off), as the engine always did on a refusal */
				for (i = 0; i < w.n_ev; i++)
					WRT_CHECK(w.ev[i].kind != WR_EV_FATAL); /* a mode refusal is not fatal: fix the policy (or the server) and it connects */
			}
			if (refuse)
				WRT_CHECK_U64(sc_secrets_total(&w), 0); /* nothing was negotiated, so nothing was issued */
			else
				WRT_CHECK(sc_secrets_total(&w) >= 1u || rows[r].allow == SC_ALLOW_CRC);
			WRT_CHECK_U64(w.n_leak_log + w.n_leak_wire + w.n_leak_ev + secret_leaks(&w), 0);
			cw_free(&w);
		}
}

/* ---- the READY record ------------------------------------------------------------------------------------------------------ */

static void test_ready_record(void)
{
	static const uint8_t pols[] = {WR_MODE_CRC_ONLY, WR_MODE_SECURE_ONLY, WR_MODE_STOCK};
	unsigned p;

	for (p = 0; p < sizeof(pols); p++) {
		cw w;
		sc_opts o = sc_defaults(pols[p]);
		wr_image *img;
		unsigned i, n_ready = 0, mon_s, mon_c, osd_s, osd_c;
		wr_stats st;

		WRT_CHECK_U64(sc_open(&w, &o), 0);
		img = sc_image(&w, "img", "id0001", IMG_SIZE, IMG_ORDER);
		WRT_CHECK(img != NULL);
		for (i = 0; i < g_sc_nlog; i++) {
			const sc_logrec *r = &g_sc_log[i];

			if (r->msg == NULL || strcmp(r->msg, "msgr2 session ready") != 0)
				continue;
			n_ready++;
			WRT_CHECK(r->st == WR_OK && r->level == WR_LOG_INFO && r->module == WR_MOD_M2 && r->conn != 0u);
			WRT_CHECK(r->a0 == WRI_ENTITY_MON || r->a0 == WRI_ENTITY_OSD);
			WRT_CHECK(r->a3 == (pols[p] == WR_MODE_CRC_ONLY ? WRI_CONN_MODE_CRC : WRI_CONN_MODE_SECURE) ||
				  (pols[p] == WR_MODE_STOCK && r->a0 == WRI_ENTITY_OSD && r->a3 == WRI_CONN_MODE_CRC)); /* STOCK: [secure, crc] to a monitor, [crc, secure] to an OSD */
		}
		wr_client_get_stats(w.c, &st);
		sc_ready_counts(WRI_ENTITY_MON, &mon_s, &mon_c);
		sc_ready_counts(WRI_ENTITY_OSD, &osd_s, &osd_c);
		WRT_CHECK(n_ready >= 2u && n_ready == mon_s + mon_c + osd_s + osd_c);
		WRT_CHECK_U64(st.conns_secure, mon_s + osd_s);
		WRT_CHECK_U64(st.conns_crc, mon_c + osd_c);
		if (pols[p] == WR_MODE_STOCK)
			WRT_CHECK(mon_s == 1u && mon_c == 0u && osd_c >= 1u && osd_s == 0u);
		cw_free(&w);
	}
}

/* ---- the failures ----------------------------------------------------------------------------------------------------------- */

typedef struct failcase {
	const char *name;
	uint8_t policy;
	int osd;                 /* the fault is on the OSDs (else on the monitor) */
	wr_status status;        /* the status of the connection failure the engine logs */
	int secure_failure;      /* counts in sec_failures */
	void (*set)(sim_m2_cfg *);
} failcase;

static void f_omit(sim_m2_cfg *c)
{
	c->f.sec.omit_secret = 1;
}

static void f_short(sim_m2_cfg *c)
{
	c->f.sec.secret_len = 20;
}

static void f_crc_secret(sim_m2_cfg *c)
{
	c->f.sec.secret_in_crc = 1;
}

static void f_wrong_key(sim_m2_cfg *c)
{
	c->f.sec.wrong_key_tx = 1;
}

static void f_wrong_seed(sim_m2_cfg *c)
{
	c->f.sec.wrong_seed_tx = 1;
}

static void f_done_crc(sim_m2_cfg *c)
{ /* secure was negotiated (and a secret issued) but AUTH_DONE says crc: a downgrade attempt; the conversation would stay in the clear */
	c->f.done_mode = WRI_CONN_MODE_CRC;
}

static void f_done_secure(sim_m2_cfg *c)
{ /* crc was negotiated but AUTH_DONE says secure: a mode nobody offered */
	c->f.done_mode = WRI_CONN_MODE_SECURE;
}

static void f_flip(sim_m2_cfg *c)
{ /* a bit of the ciphertext of the server's 6th frame (HELLO, AUTH_REPLY_MORE, AUTH_DONE, AUTH_SIGNATURE, SERVER_IDENT, then the first message, after READY): the tag says no */
	c->f.sec.mut_frame = 6;
	c->f.sec.mut.mask = SIM_SEC_M_FLIP;
	c->f.sec.mut.flip_part = 1;
	c->f.sec.mut.flip_region = SIM_SEC_R_RAW;
	c->f.sec.mut.flip_byte = 7;
	c->f.sec.mut.flip_bit = 3;
}

static void test_failures(void)
{
	static const failcase cases[] = {
		{"mon: secure, no secret", WR_MODE_SECURE_ONLY, 0, WR_E_M2_SECRET, 1, f_omit},
		{"mon: secret of 20 bytes", WR_MODE_SECURE_ONLY, 0, WR_E_M2_SECRET, 1, f_short},
		{"mon: secret in crc mode", WR_MODE_CRC_ONLY, 0, WR_E_AUTH_PROTO, 0, f_crc_secret},
		{"mon: wrong key", WR_MODE_SECURE_ONLY, 0, WR_E_M2_SEC_TAG, 1, f_wrong_key},
		{"mon: wrong nonce seed", WR_MODE_SECURE_ONLY, 0, WR_E_M2_SEC_TAG, 1, f_wrong_seed},
		{"mon: flipped bit in the session", WR_MODE_SECURE_ONLY, 0, WR_E_M2_SEC_TAG, 1, f_flip},
		{"osd: secure, no secret", WR_MODE_SECURE_ONLY, 1, WR_E_M2_SECRET, 1, f_omit},
		{"osd: wrong key", WR_MODE_SECURE_ONLY, 1, WR_E_M2_SEC_TAG, 1, f_wrong_key},
		{"osd: secret in crc mode", WR_MODE_CRC_ONLY, 1, WR_E_AUTH_PROTO, 0, f_crc_secret},
		/* a server that answers with a mode we did not offer: no downgrade to crc under secure-only, no secure under crc-only (WR_E_M2_MODE, never READY) */
		{"mon: crc answered under secure-only", WR_MODE_SECURE_ONLY, 0, WR_E_M2_MODE, 0, f_done_crc},
		{"mon: secure answered under crc-only", WR_MODE_CRC_ONLY, 0, WR_E_M2_MODE, 0, f_done_secure},
		{"osd: crc answered under secure-only", WR_MODE_SECURE_ONLY, 1, WR_E_M2_MODE, 0, f_done_crc},
		{"osd: secure answered under crc-only", WR_MODE_CRC_ONLY, 1, WR_E_M2_MODE, 0, f_done_secure},
	};
	unsigned c;

	for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
		cw w;
		sc_opts o = sc_defaults(cases[c].policy);
		wr_stats st;
		unsigned i;
		wr_image *img = NULL;

		o.n_osd = 2;
		o.key_type = c % 2u ? WR_KEY_TYPE_AES : WR_KEY_TYPE_AES256K;
		WRT_CHECK_U64(sc_open(&w, &o), 0);
		if (cases[c].osd)
			for (i = 0; i < w.n_osd; i++)
				cases[c].set(&w.osd[i]->cfg.m2);
		else
			cases[c].set(&w.mon->cfg.m2);
		if (cases[c].osd) {
			img = sc_image(&w, "img", "id0001", IMG_SIZE, IMG_ORDER);
			WRT_CHECK(img == NULL); /* the OSDs never complete a connection: the image cannot open */
			cw_tick(&w, 4000);
		} else {
			cw_tick(&w, 25000);
		}
		wr_client_get_stats(w.c, &st);
		if (sc_count_log("msgr2 connection failed", cases[c].status) < 1u)
			fprintf(stderr, "  case '%s': no connection failure with status %d in the log\n", cases[c].name, (int)cases[c].status);
		WRT_CHECK(sc_count_log("msgr2 connection failed", cases[c].status) >= 1u);
		if (cases[c].secure_failure)
			WRT_CHECK(st.sec_failures >= 1u);
		else
			WRT_CHECK_U64(st.sec_failures, 0);
		if (!cases[c].osd && c != 5u) /* nothing was counted as a connection of the monitor: none reached READY (the flip lets the first sessions through) */
			WRT_CHECK(st.conns_secure + st.conns_crc == 0u);
		if (c == 5u)
			WRT_CHECK(st.conns_secure >= 1u && st.sec_failures >= 1u); /* the damaged frame came after READY: that session counted, then died on the tag */
		if (cases[c].osd)
			WRT_CHECK(st.conns_secure + st.conns_crc >= 1u); /* the monitor's session is fine (it has no fault) */
		/* a failed secure connection leaves nothing of its secret behind */
		WRT_CHECK_U64(sc_scan_memory(&w, 1), 0);
		WRT_CHECK_U64(sc_scan_memory(&w, 0), 0);
		WRT_CHECK_U64(w.n_leak_log + w.n_leak_wire + w.n_leak_ev + secret_leaks(&w), 0);
		(void)img;
		cw_free(&w);
	}
}

/* ---- a failure the host's report of the closed socket overtakes -------------------------------------------------------------- */

/* A secure failure that is recorded inside a send call (a refused transmit nonce, a lost key) is reported to the upper layer, and counted by the engine, at the next
 * step. If the host reports the socket closed BEFORE that step, the msgr2 connection turns FREE inside wr_conn_closed and nobody would have seen how it ended: the
 * engine looks at the connection first. White box on purpose (the failure is recorded the way the transmit side records it). */
static void test_failure_before_closed(void)
{
	static const wr_status why[] = {WR_E_M2_SEC_TAG, WR_E_M2_NONCE, WR_E_M2_SECRET};
	unsigned k;

	for (k = 0; k < sizeof(why) / sizeof(why[0]); k++) {
		cw w;
		sc_opts o = sc_defaults(WR_MODE_SECURE_ONLY);
		wr_stats before, after;
		wri_cslot *s = NULL;
		unsigned i;
		wr_conn_id id;

		WRT_CHECK_U64(sc_open(&w, &o), 0);
		cw_tick(&w, 3000); /* the monitor session is up */
		for (i = 0; i < w.c->n_slot; i++)
			if (w.c->slot[i].in_use && w.c->slot[i].conn.state == WRI_M2_READY && w.c->slot[i].conn.mode == WRI_CONN_MODE_SECURE)
				s = &w.c->slot[i];
		WRT_CHECK(s != NULL);
		if (s == NULL) {
			cw_free(&w);
			continue;
		}
		wr_client_get_stats(w.c, &before);
		WRT_CHECK(before.conns_secure >= 1u && before.sec_failures == 0u);
		id = s->conn.id;
		wri_m2c_fail_deferred(&w.c->x, &s->conn, why[k], (unsigned)__LINE__, "test: recorded inside a send call", 0, 0, 0);
		WRT_CHECK(s->conn.state == WRI_M2_FAILED && !s->conn.close_reported); /* nobody was told, no step ran */
		wr_conn_closed(w.c, id, 0);                                            /* the host's report comes first */
		wr_client_get_stats(w.c, &after);
		WRT_CHECK_U64(after.sec_failures, 1);
		WRT_CHECK_U64(after.conns_secure, before.conns_secure);
		WRT_CHECK_U64(after.conns_crc, before.conns_crc);
		WRT_CHECK_U64(sc_scan_memory(&w, 0), 0);
		cw_free(&w);
	}
}

/* ---- the counters stop at 2^32 - 1 ------------------------------------------------------------------------------------------ */

/* "Counters stop at 2^32 - 1" (wr_client.h): a counter that wrapped to 0 would make a tool believe that no connection was ever in the other mode. White box: the
 * counters are put at the limit and the engine goes on making connections, secure ones, crc ones and failing ones. */
static void test_counters_saturate(void)
{
	static const uint32_t max = 0xffffffffu;
	unsigned k;

	for (k = 0; k < 3u; k++) {
		cw w;
		sc_opts o = sc_defaults(k == 0u ? WR_MODE_SECURE_FIRST : k == 1u ? WR_MODE_CRC_ONLY : WR_MODE_SECURE_ONLY);
		wr_stats st;

		WRT_CHECK_U64(sc_open(&w, &o), 0);
		cw_tick(&w, 3000); /* the monitor session is up */
		w.c->stats.conns_secure = w.c->stats.conns_crc = w.c->stats.sec_failures = max;
		if (k == 2u)
			w.mon->cfg.m2.f.sec.wrong_key_tx = 1; /* the connections made from now on die on a tag: sec_failures */
		sim_mon_restart(w.mon);
		cw_tick(&w, k == 2u ? 12000 : 4000);
		wr_client_get_stats(w.c, &st);
		WRT_CHECK_U64(st.conns_secure, max); /* READY connections of either mode, failures: nothing wrapped */
		WRT_CHECK_U64(st.conns_crc, max);
		WRT_CHECK_U64(st.sec_failures, max);
		if (k == 2u)
			WRT_CHECK(sc_count_log("msgr2 connection failed", WR_E_M2_SEC_TAG) >= 1u);
		cw_free(&w);
	}
}

/* ---- the canary ------------------------------------------------------------------------------------------------------------- */

static void test_canary(void)
{
	static const char *canaries[2] = {"CANARY-WINRBD-KEY-0123456789ab", "CANARYCANARYCANARYCANARYCANARY!"};
	unsigned key;

	for (key = 0; key < 2u; key++) {
		cw w;
		sc_opts o = sc_defaults(WR_MODE_SECURE_FIRST);
		wr_image *img;
		sc_work k;
		unsigned i;
		wr_stats st;

		g_cw_canary = canaries[key];
		o.key_type = key ? WR_KEY_TYPE_AES256K : WR_KEY_TYPE_AES;
		o.n_osd = 2;
		WRT_CHECK_U64(sc_open(&w, &o), 0);
		img = sc_image(&w, "img", "id0001", IMG_SIZE, IMG_ORDER);
		WRT_CHECK(img != NULL);
		if (img != NULL) {
			WRT_CHECK_U64(sc_work_init(&k, IMG_SIZE, 31u + key, 16u * 1024u), 0);
			for (i = 0; i < 8u; i++)
				sc_work_step(&w, img, &k, 60000);
			sim_mon_restart(w.mon); /* a new session: a new secret */
			sim_osd_restart(w.osd[0]);
			for (i = 0; i < 8u; i++)
				sc_work_step(&w, img, &k, 60000);
			WRT_CHECK(k.n_fail == 0u && k.n_bad_read == 0u);
			sc_work_free(&k);
		}
		wr_client_get_stats(w.c, &st);
		WRT_CHECK(st.conns_secure >= 3u); /* the monitor and an OSD session, then at least the monitor again after its restart */
		WRT_CHECK(sc_secrets_total(&w) >= 3u);
		/* the rig's canary: the key in no log record, event or errinfo, on no wire; and the secrets in none of them */
		WRT_CHECK_U64(w.n_leak_log, 0);
		WRT_CHECK_U64(w.n_leak_wire, 0);
		WRT_CHECK_U64(w.n_leak_ev, 0);
		WRT_CHECK_U64(secret_leaks(&w), 0);
		WRT_CHECK(w.n_log >= 3u && g_sc_nlog >= 3u); /* the engine did log (a READY record per connection at least): the scans looked at something */
		cw_free(&w);
		g_cw_canary = NULL;
	}
}

/* ---- the host's GCM objects ------------------------------------------------------------------------------------------------ */

#define HG_MAX 64u
typedef struct hostgcm {
	wri_pgcm obj[HG_MAX];
	uint8_t used[HG_MAX];
	unsigned n_setkey, n_wipe, n_start, n_fail_setkey;
	unsigned refuse_after; /* setkey refuses (WR_E_CRYPTO_KEY) from this many on; 0 = never */
} hostgcm;

static hostgcm g_hg;

static wr_status hg_setkey(void *ctx, void *state, const uint8_t key[16])
{
	hostgcm *h = (hostgcm *)ctx;
	uint64_t idx;
	unsigned i;

	if (h->refuse_after != 0u && h->n_setkey >= h->refuse_after) {
		h->n_fail_setkey++;
		return WR_E_CRYPTO_KEY;
	}
	for (i = 0; i < HG_MAX && h->used[i]; i++) {
	}
	if (i == HG_MAX)
		return WR_E_BUDGET;
	if (wri_pgcm_setkey(&h->obj[i], NULL, key) != WR_OK)
		return WR_E_CRYPTO_KEY;
	h->used[i] = 1;
	h->n_setkey++;
	idx = (uint64_t)i + 1u;
	memcpy(state, &idx, sizeof(idx));
	return WR_OK;
}

static wri_pgcm *hg_obj(void *ctx, void *state)
{
	hostgcm *h = (hostgcm *)ctx;
	uint64_t idx;

	memcpy(&idx, state, sizeof(idx));
	if (idx == 0u || idx > HG_MAX || !h->used[idx - 1u])
		abort(); /* a state the engine never keyed, or one it already wiped */
	return &h->obj[idx - 1u];
}

static wr_status hg_start(void *ctx, void *state, const uint8_t iv[12], int decrypt)
{
	((hostgcm *)ctx)->n_start++;
	return wri_pgcm_start(hg_obj(ctx, state), iv, decrypt);
}

static void hg_update(void *ctx, void *state, const uint8_t *in, uint8_t *out, size_t n)
{
	if (wri_pgcm_update(hg_obj(ctx, state), in, out, n) != WR_OK)
		abort();
}

static void hg_final_enc(void *ctx, void *state, uint8_t tag[16])
{
	if (wri_pgcm_final_enc(hg_obj(ctx, state), tag) != WR_OK)
		abort();
}

static wr_status hg_final_dec(void *ctx, void *state, const uint8_t tag[16])
{
	return wri_pgcm_final_dec(hg_obj(ctx, state), tag);
}

static void hg_wipe(void *ctx, void *state)
{
	hostgcm *h = (hostgcm *)ctx;
	uint64_t idx;

	memcpy(&idx, state, sizeof(idx));
	if (idx == 0u || idx > HG_MAX || !h->used[idx - 1u])
		return; /* never keyed (a failed setkey), or already wiped: nothing to hand back */
	wri_pgcm_wipe(&h->obj[idx - 1u]);
	h->used[idx - 1u] = 0;
	h->n_wipe++;
	memset(state, 0, sizeof(idx));
}

static unsigned hg_live(const hostgcm *h)
{
	unsigned i, n = 0;

	for (i = 0; i < HG_MAX; i++)
		n += h->used[i];
	return n;
}

static void hg_table(wr_prim_ops *t, hostgcm *h)
{
	memset(t, 0, sizeof(*t));
	t->size = (uint32_t)sizeof(*t);
	t->ctx = h;
	t->gcm_state_bytes = 8u;
	t->gcm_setkey = hg_setkey;
	t->gcm_start = hg_start;
	t->gcm_update = hg_update;
	t->gcm_final_enc = hg_final_enc;
	t->gcm_final_dec = hg_final_dec;
	t->gcm_wipe = hg_wipe;
}

static void test_host_gcm(void)
{
	unsigned round;

	for (round = 0; round < 2u; round++) {
		cw w;
		sc_opts o = sc_defaults(WR_MODE_SECURE_ONLY);
		wr_prim_ops tab;
		wr_image *img;
		sc_work k;
		unsigned i, live, active = 0;
		wr_stats st;

		memset(&g_hg, 0, sizeof(g_hg));
		hg_table(&tab, &g_hg);
		o.n_osd = 2;
		WRT_CHECK_U64(sc_open(&w, &o), 0);
		w.c->x.host.prim = &tab; /* the engine keeps a copy of the host table: the override is read at every switch to secure */
		if (round == 1u)
			g_hg.refuse_after = 3u; /* the host refuses the key of the third object on: a connection that cannot be keyed fails, it never runs sealed with other code */
		img = sc_image(&w, "img", "id0001", IMG_SIZE, IMG_ORDER);
		if (round == 0u) {
			WRT_CHECK(img != NULL);
			WRT_CHECK_U64(sc_work_init(&k, IMG_SIZE, 61u, 16u * 1024u), 0);
			for (i = 0; i < 8u && img != NULL; i++)
				sc_work_step(&w, img, &k, 60000);
			WRT_CHECK(k.n_fail == 0u && k.n_bad_read == 0u);
			sc_work_free(&k);
			sim_osd_restart(w.osd[0]);
			sim_mon_restart(w.mon);
			(void)cw_settle(&w);
			cw_tick(&w, 2000);
			wr_client_get_stats(w.c, &st);
			for (i = 0; i < w.c->n_slot; i++)
				active += w.c->slot[i].in_use && w.c->slot[i].conn.sec != NULL && w.c->slot[i].conn.sec->s.active;
			live = hg_live(&g_hg);
			WRT_CHECK(g_hg.n_start >= 8u && st.conns_secure >= 3u);
			WRT_CHECK_U64(live, 2u * active); /* one object per direction of every keyed connection, no more: the ended ones were handed back */
			WRT_CHECK(g_hg.n_wipe >= 1u);
		} else {
			cw_tick(&w, 3000);
			WRT_CHECK(g_hg.n_fail_setkey >= 1u); /* the refusal happened ... */
			wr_client_get_stats(w.c, &st);
			WRT_CHECK(st.sec_failures == 0u && st.conns_crc == 0u); /* ... and no connection went on in crc or with other code instead */
			WRT_CHECK(sc_count_log("msgr2 connection failed", WR_E_CRYPTO_KEY) >= 1u || sc_count_log("msgr2 connection failed", 0) >= 1u);
		}
		wr_client_destroy(w.c); /* in the middle of a session */
		w.c = NULL;
		WRT_CHECK_U64(hg_live(&g_hg), 0); /* every object that was keyed is wiped */
		WRT_CHECK_U64(g_hg.n_setkey, g_hg.n_wipe);
		cw_free(&w);
	}
}

/* ---- the live memory ---------------------------------------------------------------------------------------------------------- */

static void test_live_memory(void)
{
	cw w;
	sc_opts o = sc_defaults(WR_MODE_SECURE_ONLY);
	wr_image *img;
	unsigned i, active = 0;

	o.n_osd = 2;
	WRT_CHECK_U64(sc_open(&w, &o), 0);
	img = sc_image(&w, "img", "id0001", IMG_SIZE, IMG_ORDER);
	WRT_CHECK(img != NULL);
	for (i = 0; i < w.c->n_slot; i++)
		active += w.c->slot[i].in_use && w.c->slot[i].conn.sec != NULL && w.c->slot[i].conn.sec->s.active;
	WRT_CHECK(active >= 2u); /* the monitor's and at least one OSD's connection are keyed */
	WRT_CHECK(sc_secrets_total(&w) >= active);
	/* the secret is nowhere in one piece, and its unused tail is nowhere at all: the key schedule and the nonce seeds are all that is kept */
	WRT_CHECK_U64(sc_scan_memory(&w, 0), 0);
	WRT_CHECK_U64(sc_scan_memory(&w, 1), 0);
	cw_free(&w);
}

/* ---- destroy in the middle of a stream ----------------------------------------------------------------------------------- */

static int any_stream(const cw *w)
{
	unsigned i;

	for (i = 0; i < w->c->n_slot; i++) {
		const wri_cslot *s = &w->c->slot[i];

		if (s->in_use && s->conn.sec != NULL && s->conn.sec->s.active && !wri_m2s_tx_done(&s->conn.tx))
			return 1;
	}
	return 0;
}

static void test_destroy(void)
{
	static const uint32_t chunks[] = {256u, 4096u};
	unsigned c;

	for (c = 0; c < 2u; c++) {
		cw w;
		sc_opts o = sc_defaults(WR_MODE_SECURE_ONLY);
		wr_image *img;
		enum { NREQ = 6, LEN = 96 * 1024 };
		static uint8_t bufs[NREQ][LEN];
		wr_io_req q[NREQ];
		unsigned i, rounds, secure_live = 0;
		size_t k, nonzero_before = 0, nonzero = 0, guard_bad = 0;
		uint8_t *arena;
		size_t used;

		o.n_osd = 2;
		o.sec_tx_chunk = chunks[c];
		WRT_CHECK_U64(sc_open(&w, &o), 0);
		img = sc_image(&w, "img", "id0001", IMG_SIZE, IMG_ORDER);
		WRT_CHECK(img != NULL);
		if (img == NULL) {
			cw_free(&w);
			continue;
		}
		for (i = 0; i < NREQ; i++) {
			cw_fill(bufs[i], 40u + i, (uint64_t)i * LEN, LEN);
			q[i] = cw_req(WR_IO_WRITE, (uint64_t)i * LEN, LEN, bufs[i]);
			WRT_CHECK_STATUS(WR_OK, cw_submit(img, &q[i]));
		}
		/* round by round, until a connection is in the middle of sealing a data segment through its bounce buffer */
		for (rounds = 0; rounds < 4000u && !any_stream(&w); rounds++)
			(void)cw_round(&w);
		WRT_CHECK(any_stream(&w)); /* the test is where it means to be: a stream is open, part of a frame is sealed and unsent */
		for (i = 0; i < w.c->n_slot; i++)
			secure_live += w.c->slot[i].in_use && w.c->slot[i].conn.sec != NULL && w.c->slot[i].conn.sec->s.active;
		WRT_CHECK(secure_live >= 1u);
		for (k = 0; k < w.req.arena; k++)
			nonzero_before += w.arena_base[k] != 0u;
		WRT_CHECK(nonzero_before > 0u);
		WRT_CHECK(sc_secrets_total(&w) >= 1u);
		arena = w.arena_base;
		used = w.req.arena;
		wr_client_destroy(w.c);
		w.c = NULL;
		for (k = 0; k < used; k++)
			nonzero += arena[k] != 0u;
		WRT_CHECK_U64(nonzero, 0); /* the engine, the slots, the bounce buffers with sealed data in them, the key schedules: zero */
		WRT_CHECK_U64(sc_scan_memory(&w, 0) + sc_scan_memory(&w, 1), 0);
		for (k = 0; k < (size_t)(w.arena_base - w.arena_raw); k++)
			guard_bad += w.arena_raw[k] != w.arena_pat;
		for (k = used + (size_t)(w.arena_base - w.arena_raw); k < w.req.arena + 128u; k++)
			guard_bad += w.arena_raw[k] != w.arena_pat;
		WRT_CHECK_U64(guard_bad, 0);
		guard_bad = 0;
		for (k = (size_t)(w.bulk_base - w.bulk_raw) + w.req.bulk; k < w.req.bulk + 128u; k++)
			guard_bad += w.bulk_raw[k] != w.bulk_pat;
		WRT_CHECK_U64(guard_bad, 0);
		cw_free(&w);
	}
}

int main(void)
{
	test_refusals();
	test_ready_record();
	test_failures();
	test_failure_before_closed();
	test_counters_saturate();
	test_canary();
	test_live_memory();
	test_host_gcm();
	test_destroy();
	return wrt_finish();
}
