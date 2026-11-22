/* SPDX-License-Identifier: MIT */
/*
 * client_sec_rig.h - the rig of the client-glue-sec tests (client.sec.conn, client.sec.events, fuzz_client_secure): the world of client_osd_rig.h (the WHOLE
 * engine with the maps, the OSD client and the image layer against one sim_mon and N sim_osd, the in-test pump playing the host) with secure mode switched
 * on, plus what the secure tests need on top:
 *
 *   - the policies of the client and the allowed-modes lists of the simulated servers (sc_open: the monitor's and the OSDs' lists are set on the simulators
 *     after cw_open made them; the simulators copy their list into every connection they accept, so a list changed later applies to later connections);
 *   - a log tap (sc_log): every record the engine emits is kept (message, status, numbers) for the tests, and the canary of the rig still sees it; and the
 *     operation-limit hook of the tests (34.5): with g_sc_limit != 0 every secure connection gets that limit on both directions the moment it is READY, so a
 *     test can retire connections after a handful of frames (the engine has no setting for it: a limit that low is a test device);
 *   - the expectation of the negotiation (sc_expect_mode): what the server answers to an offer, from the first of OUR modes it allows;
 *   - the secrets the simulators issued (sc_secrets_*), and scans of the engine's memory for them;
 *   - a model-checked random workload on an image (sc_model_*), and a byte-exact read-back.
 *
 * Test code: libc allowed, everything static inline so every test executable carries its own copy. sim_osd_int.h is the simulator's own header ("not for
 * tests"): there is no public way to change an OSD simulator's allowed modes after it was made, and cw_open makes them.
 */
#ifndef CLIENT_SEC_RIG_H
#define CLIENT_SEC_RIG_H

#include "client_osd_rig.h"
#include "sim_osd_int.h"
#include "wri_m2_modes.h"
#include "wri_m2_sec.h"

#define SC_ALLOW_CRC 1u
#define SC_ALLOW_SECURE 2u
#define SC_ALLOW_SECURE_FIRST 4u /* with both: the simulator lists secure before crc (its order does not matter: the server walks the CLIENT's list) */

/* The bits of AUTH_BAD_METHOD's allowed-modes mask (errinfo a1): bit v for mode v. */
static inline uint64_t sc_mode_mask(unsigned allow)
{
	return ((allow & SC_ALLOW_CRC) ? ((uint64_t)1 << WRI_CONN_MODE_CRC) : 0u) | ((allow & SC_ALLOW_SECURE) ? ((uint64_t)1 << WRI_CONN_MODE_SECURE) : 0u);
}

static inline void sc_allow(sim_m2_cfg *m2, unsigned allow)
{
	unsigned n = 0;

	if ((allow & SC_ALLOW_SECURE_FIRST) && (allow & SC_ALLOW_SECURE))
		m2->modes[n++] = SIM_M2_MODE_SECURE;
	if (allow & SC_ALLOW_CRC)
		m2->modes[n++] = SIM_M2_MODE_CRC;
	if (!(allow & SC_ALLOW_SECURE_FIRST) && (allow & SC_ALLOW_SECURE))
		m2->modes[n++] = SIM_M2_MODE_SECURE;
	m2->n_modes = n;
}

/* What a server that allows `allow` answers to the offer of (policy, policy_osd) for a peer of this role: the first of OUR modes it allows, 0 = it refuses
 * (AUTH_BAD_METHOD). */
static inline unsigned sc_expect_mode(uint8_t policy, uint8_t policy_osd, uint8_t role, unsigned allow)
{
	uint32_t list[2];
	size_t n = wri_m2_offer_list(wri_m2_offer_for(policy, policy_osd, role), list), i;

	for (i = 0; i < n; i++) {
		if (list[i] == WRI_CONN_MODE_CRC && (allow & SC_ALLOW_CRC))
			return WRI_CONN_MODE_CRC;
		if (list[i] == WRI_CONN_MODE_SECURE && (allow & SC_ALLOW_SECURE))
			return WRI_CONN_MODE_SECURE;
	}
	return 0;
}

/* ---- the log tap ------------------------------------------------------------------------------------------------------ */

#define SC_LOG_MAX 1024u
typedef struct sc_logrec {
	const char *msg; /* static literal of the engine */
	wr_status st;
	uint8_t level, module;
	wr_conn_id conn;
	uint64_t a0, a1, a2, a3;
} sc_logrec;

static sc_logrec g_sc_log[SC_LOG_MAX];
static unsigned g_sc_nlog;
static uint64_t g_sc_limit; /* != 0: the operation limit every secure connection gets at READY (both directions) */
static unsigned g_sc_limit_set;

static inline void sc_log(void *ctx, const wr_log_rec *r)
{
	cw *w = (cw *)ctx;

	cw_log(ctx, r); /* the rig's canary first */
	if (g_sc_nlog < SC_LOG_MAX) {
		sc_logrec *k = &g_sc_log[g_sc_nlog++];

		k->msg = r->msg;
		k->st = r->status;
		k->level = r->level;
		k->module = r->module;
		k->conn = r->conn;
		k->a0 = r->a0, k->a1 = r->a1, k->a2 = r->a2, k->a3 = r->a3;
	}
	if (g_sc_limit != 0u && r->msg != NULL && strcmp(r->msg, "msgr2 session ready") == 0 && r->a3 == WRI_CONN_MODE_SECURE && w != NULL && w->c != NULL) {
		wri_cslot *s = wri_client_slot_of(w->c, r->conn);

		if (s != NULL && s->conn.sec != NULL && s->conn.sec->s.active) {
			s->conn.sec->s.ops_limit = g_sc_limit; /* the test device: the connection is retired after this many operations per direction */
			g_sc_limit_set++;
		}
	}
}

/* Records whose message contains `needle` (and, when st != 0, that carry this status). */
static inline unsigned sc_count_log(const char *needle, wr_status st)
{
	unsigned i, n = 0;

	for (i = 0; i < g_sc_nlog; i++)
		n += g_sc_log[i].msg != NULL && strstr(g_sc_log[i].msg, needle) != NULL && (st == 0 || g_sc_log[i].st == st);
	return n;
}

static inline const sc_logrec *sc_find_log(const char *needle, wr_status st, unsigned nth)
{
	unsigned i;

	for (i = 0; i < g_sc_nlog; i++)
		if (g_sc_log[i].msg != NULL && strstr(g_sc_log[i].msg, needle) != NULL && (st == 0 || g_sc_log[i].st == st) && nth-- == 0u)
			return &g_sc_log[i];
	return NULL;
}

/* READY records of one role: how many, and how many in each mode. */
static inline void sc_ready_counts(uint8_t role, unsigned *n_secure, unsigned *n_crc)
{
	unsigned i;

	*n_secure = *n_crc = 0;
	for (i = 0; i < g_sc_nlog; i++) {
		if (g_sc_log[i].msg == NULL || strcmp(g_sc_log[i].msg, "msgr2 session ready") != 0 || g_sc_log[i].a0 != role)
			continue;
		if (g_sc_log[i].a3 == WRI_CONN_MODE_SECURE)
			(*n_secure)++;
		else if (g_sc_log[i].a3 == WRI_CONN_MODE_CRC)
			(*n_crc)++;
		else
			(*n_crc) += 1000u; /* a mode nobody defined: the caller's equality checks fail */
	}
}

/* ---- the world --------------------------------------------------------------------------------------------------------- */

typedef struct sc_opts {
	uint8_t policy, policy_osd;  /* mode_policy, mode_policy_osd */
	unsigned mon_allow, osd_allow; /* SC_ALLOW_* of the simulated servers */
	unsigned key_type;
	unsigned n_osd;
	uint32_t sec_tx_chunk;       /* 0 = the profile's 4 KiB */
	uint32_t rx_buf_bytes;       /* 0 = the profile's: the staging ring of every connection (a small one makes the parser work in pieces) */
	uint64_t limit;              /* the operation limit of every secure connection (0 = none) */
} sc_opts;

static inline sc_opts sc_defaults(uint8_t policy)
{
	sc_opts o;

	memset(&o, 0, sizeof(o));
	o.policy = policy;
	o.mon_allow = o.osd_allow = SC_ALLOW_CRC | SC_ALLOW_SECURE;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.n_osd = 3;
	return o;
}

/* Start the world with the options; the rig's default engine configuration (iPXE profile, maps, the OSD client: 8 connections, 6 OSD sessions) with secure
 * mode on. 0 = ok. */
static inline int sc_open(cw *w, const sc_opts *o)
{
	wr_config cfg;
	unsigned i;
	int rc;

	g_sc_nlog = 0;
	g_sc_limit = o->limit;
	g_sc_limit_set = 0;
	cw_cfg_default(&cfg);
	wr_config_enable_secure(&cfg, WR_MAPS_IPXE, o->policy);
	cfg.mode_policy_osd = o->policy_osd;
	if (o->sec_tx_chunk != 0u)
		cfg.sec_tx_chunk = o->sec_tx_chunk;
	if (o->rx_buf_bytes != 0u)
		cfg.rx_buf_bytes = o->rx_buf_bytes;
	rc = cw_open(w, &cfg, o->n_osd, 8, o->key_type);
	if (rc != 0)
		return rc;
	w->c->x.host.log = sc_log; /* the engine keeps a copy of the host table: tap it before the first run */
	sc_allow(&w->mon->cfg.m2, o->mon_allow);
	for (i = 0; i < w->n_osd; i++)
		sc_allow(&w->osd[i]->cfg.m2, o->osd_allow);
	return 0;
}

/* ---- the secrets the simulators issued ---------------------------------------------------------------------------------- */

static inline unsigned sc_secrets_total(const cw *w)
{
	unsigned i, n = sim_mon_secrets(w->mon)->n;

	for (i = 0; i < w->n_osd; i++)
		n += sim_osd_secrets(w->osd[i])->n;
	return n;
}

/* 1 when every secret any simulator issued differs from every other one (within a simulator and across them). */
static inline int sc_secrets_distinct(const cw *w)
{
	const sim_sec_log *logs[CW_MAX_OSD + 1u];
	unsigned n = 0, i, j, a, b;

	logs[n++] = sim_mon_secrets(w->mon);
	for (i = 0; i < w->n_osd; i++)
		logs[n++] = sim_osd_secrets(w->osd[i]);
	for (i = 0; i < n; i++) {
		if (logs[i]->kept != logs[i]->n || !sim_sec_log_distinct(logs[i]))
			return 0;
		for (j = i + 1u; j < n; j++)
			for (a = 0; a < logs[i]->kept; a++)
				for (b = 0; b < logs[j]->kept; b++)
					if (logs[i]->len[a] == logs[j]->len[b] && memcmp(logs[i]->secret[a], logs[j]->secret[b], logs[i]->len[a]) == 0)
						return 0;
	}
	return 1;
}

/* How many times `needle` (n bytes) occurs in [hay, hay + hn). */
static inline unsigned sc_occurs(const uint8_t *hay, size_t hn, const uint8_t *needle, size_t n)
{
	size_t i;
	unsigned k = 0;

	if (n == 0u || hn < n)
		return 0;
	for (i = 0; i + n <= hn; i++)
		if (hay[i] == needle[0] && memcmp(hay + i, needle, n) == 0)
			k++;
	return k;
}

/* The secrets of every secure connection that was ever made: how many of them (or of their unused tail S[40..63], or of any 16-byte window of the
 * part of the secret that is not the key, S[16..63]) are in the engine's memory right now. `part`: 0 the whole secret, 1 the tail S[40..], 2 windows of S[16..]. */
static inline unsigned sc_scan_memory(const cw *w, int part)
{
	const sim_sec_log *logs[CW_MAX_OSD + 1u];
	unsigned n = 0, i, a, hits = 0;

	logs[n++] = sim_mon_secrets(w->mon);
	for (i = 0; i < w->n_osd; i++)
		logs[n++] = sim_osd_secrets(w->osd[i]);
	for (i = 0; i < n; i++)
		for (a = 0; a < logs[i]->kept; a++) {
			const uint8_t *s = logs[i]->secret[a];
			size_t len = logs[i]->len[a], k;

			if (part == 0 && len >= 16u) {
				hits += sc_occurs(w->arena_base, w->req.arena, s, len) + sc_occurs(w->bulk_base, w->req.bulk, s, len);
			} else if (part == 1 && len >= 40u + 8u) { /* a tail of fewer than 8 bytes proves nothing: it is in any memory by chance */
				hits += sc_occurs(w->arena_base, w->req.arena, s + 40u, len - 40u) + sc_occurs(w->bulk_base, w->req.bulk, s + 40u, len - 40u);
			} else if (part == 2) {
				for (k = 16u; k + 16u <= len; k += 8u)
					hits += sc_occurs(w->arena_base, w->req.arena, s + k, 16u) + sc_occurs(w->bulk_base, w->req.bulk, s + k, 16u);
			}
		}
	return hits;
}

/* ---- a model-checked workload --------------------------------------------------------------------------------------------- */

typedef struct sc_work {
	uint64_t rng;
	uint8_t *model;      /* what the image must hold */
	uint64_t size;
	uint32_t seed;
	unsigned n_fail;     /* requests that did not complete with WR_OK */
	unsigned n_bad_read; /* reads that differ from the model */
	unsigned n_ops;
	uint8_t *buf;
	uint32_t buf_cap;
} sc_work;

static inline uint64_t sc_rnd(sc_work *k)
{
	k->rng ^= k->rng >> 12;
	k->rng ^= k->rng << 25;
	k->rng ^= k->rng >> 27;
	return k->rng * 0x2545f4914f6cdd1dull;
}

static inline int sc_work_init(sc_work *k, uint64_t size, uint32_t seed, uint32_t buf_cap)
{
	memset(k, 0, sizeof(*k));
	k->rng = 0x9e3779b97f4a7c15ull ^ ((uint64_t)seed << 17);
	k->size = size;
	k->seed = seed;
	k->buf_cap = buf_cap;
	k->model = (uint8_t *)calloc(1, (size_t)size);
	k->buf = (uint8_t *)malloc(buf_cap);
	return k->model != NULL && k->buf != NULL ? 0 : -1;
}

static inline void sc_work_free(sc_work *k)
{
	free(k->model);
	free(k->buf);
	memset(k, 0, sizeof(*k));
}

/* One random operation on the image, waited for, and checked against the model. */
static inline void sc_work_step(cw *w, wr_image *img, sc_work *k, uint64_t limit_ms)
{
	uint64_t r = sc_rnd(k), len = 1u + (r >> 8) % (k->buf_cap - 1u), off;
	unsigned kind = (unsigned)(r % 10u);
	wr_io_req q;
	wr_status st;

	off = (sc_rnd(k) >> 3) % (k->size - len);
	if (kind < 4u) { /* write */
		cw_fill(k->buf, k->seed + (uint32_t)k->n_ops, off, (size_t)len);
		q = cw_req(WR_IO_WRITE, off, len, k->buf);
		st = cw_do(w, img, &q, limit_ms);
		if (st == WR_OK)
			memcpy(k->model + off, k->buf, (size_t)len);
		else
			k->n_fail++;
	} else if (kind < 8u) { /* read, checked against the model */
		memset(k->buf, 0xEE, (size_t)len);
		q = cw_req(WR_IO_READ, off, len, k->buf);
		st = cw_do(w, img, &q, limit_ms);
		if (st != WR_OK)
			k->n_fail++;
		else if (memcmp(k->buf, k->model + off, (size_t)len) != 0)
			k->n_bad_read++;
	} else if (kind == 8u) { /* discard */
		q = cw_req(WR_IO_DISCARD, off, len, NULL);
		st = cw_do(w, img, &q, limit_ms);
		if (st == WR_OK)
			memset(k->model + off, 0, (size_t)len);
		else
			k->n_fail++;
	} else { /* flush */
		q = cw_req(WR_IO_FLUSH, 0, 0, NULL);
		st = cw_do(w, img, &q, limit_ms);
		if (st != WR_OK)
			k->n_fail++;
	}
	k->n_ops++;
}

/* Read the whole image back in pieces of buf_cap and compare it with the model: the number of pieces that differ (or failed). */
static inline unsigned sc_work_verify(cw *w, wr_image *img, sc_work *k, uint64_t limit_ms)
{
	uint64_t off;
	unsigned bad = 0;

	for (off = 0; off < k->size; off += k->buf_cap) {
		uint64_t len = k->size - off < k->buf_cap ? k->size - off : k->buf_cap;
		wr_io_req q = cw_req(WR_IO_READ, off, len, k->buf);

		memset(k->buf, 0xEE, (size_t)len);
		if (cw_do(w, img, &q, limit_ms) != WR_OK || memcmp(k->buf, k->model + off, (size_t)len) != 0)
			bad++;
	}
	return bad;
}

/* The OSD requests the simulators executed more than once (the same global id and tid executed twice: a write applied twice), and the violations they saw. */
static inline unsigned sc_doubled(const cw *w, unsigned *violations)
{
	unsigned i, a, b, n_doubled = 0;

	*violations = 0;
	for (i = 0; i < w->n_osd; i++)
		*violations += sim_osd_n_violations(w->osd[i]);
	for (i = 0; i < w->n_osd; i++) {
		uint32_t n = 0;
		const sim_osd_rec *ra = sim_osd_recs(w->osd[i], &n);

		for (a = 0; a < n; a++) {
			unsigned j;

			if (!ra[a].executed || !ra[a].mutating)
				continue;
			for (j = i; j < w->n_osd; j++) {
				uint32_t m = 0;
				const sim_osd_rec *rb = sim_osd_recs(w->osd[j], &m);

				for (b = j == i ? a + 1u : 0u; b < m; b++)
					if (rb[b].executed && rb[b].mutating && rb[b].tid == ra[a].tid && rb[b].global_id == ra[a].global_id)
						n_doubled++;
			}
		}
	}
	return n_doubled;
}

/* Open an image of the store and the engine, settled; the image or NULL. */
static inline wr_image *sc_image(cw *w, const char *name, const char *id, uint64_t size, uint8_t order)
{
	wr_image_state fin = WR_IMG_FREE;
	wr_image_params p = cw_params(name, 1);
	wr_image *img;

	if (cw_image(w, name, id, size, order, 0x21, -1) != 0)
		return NULL;
	img = cw_open_image(w, &p, &fin);
	return fin == WR_IMG_OPEN ? img : NULL;
}

#endif /* CLIENT_SEC_RIG_H */
