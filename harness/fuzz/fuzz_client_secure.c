/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the whole client engine in SECURE mode (module client-glue-sec: core/src/client/wri_client_modes.c, wri_client_mem.c, the secure slots
 * and everything the engine hands them to: wri_m2_conn_sec.c, wri_m2_sec*.c, the GCM layer), through the PUBLIC API only. The engine (maps, OSD client, an
 * RBD image of 1 MiB with 16 KiB objects) runs against the simulated monitor and up to three simulated OSDs over one object store (test/client_sec_rig.h plays
 * the host), under one of the five connection-mode policies, against servers with any allowed-modes list, and the input script drives host calls, restarts,
 * and FAULTS OF THE SECURE LAYER of the simulators (no secret, a short one, a wrong key, a wrong nonce seed, a damaged or truncated frame at a chosen number,
 * a secret in crc mode), with the operation limit of every connection lowered by the header so that retirements by WR_E_M2_NONCE happen inside the run.
 *
 * Input layout:
 *
 *   byte 0   bit 0 key type, bit 1 osd_sessions 2 or 4, bits 2..4 the policy (one of the five, three of them twice), bit 5 op_bytes_max 32 KiB or 256 KiB,
 *            bit 6 sec_tx_chunk 256 bytes or 4 KiB (every data segment goes out in many pieces or a few)
 *   byte 1   bits 0..1 the monitor's allowed modes (0 both, 1 crc, 2 secure, 3 both with secure listed first), bits 2..3 the OSDs', bits 4..7 the operation
 *            limit (0 = none, else 24 + 16 * n operations per direction)
 *   rest     operations: an opcode byte (mod 14) and three argument bytes a, b, c:
 *              0 run      a: advance the virtual clock by (a % 24 + 1) ticks of 50 ms, settling at each
 *              1 write    (a, b) offset, c length class, a seed: a write of at most 20000 bytes
 *              2 read     the same shape, the bytes it must read are what the model says
 *              3 flush
 *              4 discard / 5 write-zeroes  (a, b) offset, c length
 *              6 cancel   the oldest request in flight
 *              7 reopen   close the image (a & 1: abandon), open it again
 *              8 osd      sim_osd_restart of OSD (a % n): every connection cut
 *              9 monitor  sim_mon_restart
 *             10 osd fault  a selects one of: silent, hold the answers (released when switched off), drop the next answers, EAGAIN, redirect, a dead host
 *             11 secure fault  a % 8: no secret, a secret of b bytes, a wrong key, a wrong seed, a flipped bit in the server's frame number 4 + b % 12
 *                         (its ciphertext, its tag or its epilogue by c), a truncated frame (and the server closes), a secret in crc mode, a restore of
 *                         everything; c bit 7 puts it on the monitor, else on the OSDs; c bit 6 instead sets the mode AUTH_DONE announces (a % 3: crc, secure,
 *                         or the negotiated one again): a downgrade under secure-only, a mode nobody offered under crc-only. The fault applies to the
 *                         connections made from now on.
 *             12 servers   the allowed modes of the monitor (a) and of the OSDs (b) change (0 both, 1 crc, 2 secure, 3 both); an engine whose servers
 *                         refuse its offer ends in BAD_METHOD and keeps hunting; the end of the run restores both lists
 *             13 wire      a, b, c: flip the bits c in the stream of a live connection at offset a * 37 + b (the data is only still the model's when the
 *                         connection was sealed: the tag refuses it; on a crc connection the world is marked as no longer the model's)
 *
 * Properties (a violated one traps): no crash or undefined behaviour (ASan / UBSan); the host loop settles; the pools stay inside the configuration; a request
 * completes AT MOST once and only after it was submitted; in a world the fuzzer did not corrupt (no flip on a crc connection) every request that was accepted
 * completes after the faults are cleared, and a READ that completes with success returns exactly what the model says (the model is dropped as soon as a write
 * fails or is cancelled: it may or may not have been applied): a sealed connection never carries wrong data, whatever its peer does to the stream; every secret
 * a simulator issued differs from every other; conns_secure never exceeds the secrets issued, nothing is counted as secure under CRC_ONLY, and the counters
 * never exceed the READY records or the connections the host made; the secrets are in no byte of the arena or the bulk after destroy, the arena part in use is zero and nothing outside
 * the regions was written.
 *
 * The downgrade a hostile server can try without a secret: op 11 (a = 0, c bit 7 or not) turns the secret off and a second op 11 with c bit 6 makes AUTH_DONE
 * announce crc, then the connection is made again (op 8 / 9); the server then really speaks crc, and only the offer gate of the connection (a mode we did not offer)
 * stands between a secure-only client and a crc session (seeds downgrade_secure_only_*_crc_nosecret). Without the "no secret" step the crc announcement is also
 * refused by the cephx layer (crc with a secret), which would hide a broken offer gate.
 *
 * Determinism (no read of uninitialised memory): every input is played TWICE, with the two regions pre-filled with different byte patterns; a digest of
 * everything the host can observe (every action, every byte the engine transmits, every event, every completion with its read data, the counters after each
 * step, the modes of the connections) must be identical.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test/client_sec_rig.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAX_INPUT 1536u
#define MAX_OPS 70u
#define FZ_IMG_SIZE (1u << 20)
#define FZ_ORDER 14u
#define FZ_BUF 20000u
#define FZ_NREQ 8u
#define FZ_SETTLE_LIMIT 19000

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

typedef struct fzreq {
	wr_io_req r;
	uint8_t buf[FZ_BUF];
	uint8_t exp[FZ_BUF];
	int live, exp_ok, is_read, is_write, seq;
} fzreq;

typedef struct fz {
	cw w;
	uint8_t *model;
	int model_ok, tainted;
	wr_image *img;
	fzreq *rq;
	uint32_t seq;
	unsigned n_submitted, n_done;
	const uint8_t *in;
	size_t in_n, pos;
	unsigned policy;
} fz;

static int in_byte(fz *f)
{
	return f->pos < f->in_n ? f->in[f->pos++] : 0;
}

/* ---- completions ----------------------------------------------------------------------------------------------------------- */

static fzreq *find_req(fz *f, const wr_io_req *r)
{
	unsigned i;

	for (i = 0; i < FZ_NREQ; i++)
		if (&f->rq[i].r == r)
			return &f->rq[i];
	return NULL;
}

static void reap(fz *f)
{
	unsigned i, j;

	for (i = 0; i < g_cw_ndone; i++) {
		fzreq *q = find_req(f, g_cw_done[i].req);

		check(q != NULL); /* nothing completes that we did not submit */
		for (j = 0; j < i; j++)
			check(g_cw_done[j].req != g_cw_done[i].req); /* and nothing completes twice */
		check(q->live);
		q->live = 0;
		f->n_done++;
		cw_dig_u64(&f->w, (uint64_t)(int64_t)g_cw_done[i].st);
		if (q->is_read && g_cw_done[i].st == WR_OK) {
			cw_dig(&f->w, q->buf, q->r.length);
			if (q->exp_ok && f->model_ok && !f->tainted)
				check(memcmp(q->buf, q->exp, (size_t)q->r.length) == 0); /* success means the right bytes */
		}
		if (q->is_write && g_cw_done[i].st != WR_OK)
			f->model_ok = 0; /* it may or may not have been applied */
	}
	g_cw_ndone = 0;
}

static void invariants(fz *f)
{
	wr_osd_stats st;
	wr_stats ws;
	const wr_config *cfg = &f->w.cfg;

	wr_client_osd_stats(f->w.c, &st);
	wr_client_get_stats(f->w.c, &ws);
	check(st.ops_inflight <= cfg->max_ops);
	check(st.reqs_inflight <= cfg->max_reqs);
	check(st.sessions_open <= cfg->osd_sessions);
	check(ws.conns_in_use <= cfg->max_conns);
	check(ws.handshakes_in_use <= cfg->max_handshakes);
	/* the mode counters: a secure connection has a secret, nothing is issued under CRC_ONLY, and the READY records add up to the counters */
	check(ws.conns_secure <= sc_secrets_total(&f->w));
	if (f->policy == WR_MODE_CRC_ONLY) {
		check(ws.conns_secure == 0u && ws.sec_failures == 0u); /* secure mode was never asked for: no connection is secure, none fails as one */
	} else {
		unsigned mon_s, mon_c, osd_s, osd_c;

		sc_ready_counts(WRI_ENTITY_MON, &mon_s, &mon_c);
		sc_ready_counts(WRI_ENTITY_OSD, &osd_s, &osd_c);
		/* every connection the engine counted was announced by a READY record in its mode (a connection that is READY and fails inside the same step is
		 * in the log and not in the counters: at most; the log tap is bounded and stops counting when it is full) */
		check(g_sc_nlog >= SC_LOG_MAX || (ws.conns_secure <= mon_s + osd_s && ws.conns_crc <= mon_c + osd_c));
	}
	check(ws.conns_secure + ws.conns_crc <= f->w.n_connects);
	/* no downgrade, no upgrade the policy did not ask for, whatever the servers answer or the fuzzer does to the stream: under SECURE_ONLY no connection of
	 * either role ever reaches READY in crc mode (nor in a mode nobody defined: sc_ready_counts adds 1000 for those), under CRC_ONLY none in secure */
	if (f->policy == WR_MODE_SECURE_ONLY || f->policy == WR_MODE_CRC_ONLY) {
		unsigned mon_s, mon_c, osd_s, osd_c;

		sc_ready_counts(WRI_ENTITY_MON, &mon_s, &mon_c);
		sc_ready_counts(WRI_ENTITY_OSD, &osd_s, &osd_c);
		if (f->policy == WR_MODE_SECURE_ONLY)
			check(ws.conns_crc == 0u && mon_c == 0u && osd_c == 0u);
		else
			check(ws.conns_secure == 0u && mon_s == 0u && osd_s == 0u);
	}
	check(sc_secrets_distinct(&f->w));
	cw_dig_u64(&f->w, st.ops_inflight);
	cw_dig_u64(&f->w, st.reqs_inflight);
	cw_dig_u64(&f->w, st.sessions_open);
	cw_dig_u64(&f->w, st.ops_done);
	cw_dig_u64(&f->w, st.ops_resent);
	cw_dig_u64(&f->w, st.n_session_resets);
	cw_dig_u64(&f->w, ws.conns_in_use);
	cw_dig_u64(&f->w, ws.conns_secure);
	cw_dig_u64(&f->w, ws.conns_crc);
	cw_dig_u64(&f->w, ws.sec_failures);
	cw_dig_u64(&f->w, (uint64_t)wr_client_get_state(f->w.c));
	cw_dig_u64(&f->w, (uint64_t)wr_image_get_state(f->img));
}

static void settle(fz *f)
{
	check(cw_settle(&f->w) < FZ_SETTLE_LIMIT); /* the host loop does not spin */
	reap(f);
	invariants(f);
}

static void tick(fz *f, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		f->w.now += CW_TICK_MS;
		settle(f);
	}
}

/* ---- the host's calls --------------------------------------------------------------------------------------------------------- */

static fzreq *free_req(fz *f)
{
	unsigned i;

	for (i = 0; i < FZ_NREQ; i++)
		if (!f->rq[i].live)
			return &f->rq[i];
	return NULL;
}

static void submit(fz *f, wr_io_kind kind, unsigned a, unsigned b, unsigned c)
{
	fzreq *q = free_req(f);
	uint64_t off = ((uint64_t)a * 4099u + b * 13u) % FZ_IMG_SIZE;
	uint64_t len = 1u + ((uint64_t)c * 97u + a) % FZ_BUF;
	wr_status st;

	if (q == NULL || f->img == NULL)
		return;
	if (off + len > FZ_IMG_SIZE && (a & 7u) != 7u)
		len = FZ_IMG_SIZE - off;
	if (len == 0u)
		len = 1;
	memset(&q->r, 0, sizeof(q->r));
	q->r.kind = kind;
	q->r.offset = kind == WR_IO_FLUSH ? 0u : off;
	q->r.length = kind == WR_IO_FLUSH ? 0u : len;
	q->r.buf = kind == WR_IO_READ || kind == WR_IO_WRITE ? q->buf : NULL;
	q->r.timeout_ms = (c ^ b) % 4u == 0u ? 1500u + (c ^ b) * 50u : 0u;
	q->is_read = kind == WR_IO_READ;
	q->is_write = kind == WR_IO_WRITE || kind == WR_IO_DISCARD || kind == WR_IO_WRITE_ZEROES;
	q->exp_ok = 0;
	if (kind == WR_IO_WRITE && len <= FZ_BUF)
		cw_fill(q->buf, ++f->seq, off, (size_t)len);
	if (kind == WR_IO_READ)
		memset(q->buf, 0xEE, FZ_BUF);
	cw_done_forget(&q->r);
	st = wr_image_submit(f->img, &q->r);
	if (st != WR_OK) {
		cw_dig_u64(&f->w, (uint64_t)(int64_t)st);
		return;
	}
	q->live = 1;
	q->seq = (int)++f->seq;
	f->n_submitted++;
	if (off + len <= FZ_IMG_SIZE) { /* the model follows the order of acceptance (the fence) */
		if (kind == WR_IO_WRITE)
			memcpy(f->model + off, q->buf, (size_t)len);
		else if (kind == WR_IO_DISCARD || kind == WR_IO_WRITE_ZEROES)
			memset(f->model + off, 0, (size_t)len);
		else if (kind == WR_IO_READ) {
			memcpy(q->exp, f->model + off, (size_t)len);
			q->exp_ok = 1;
		}
	}
}

static void open_image(fz *f)
{
	wr_image_params p = cw_params("img", 1);
	wr_image *img = NULL;

	if (wr_image_open(f->w.c, &p, &img) == WR_OK)
		f->img = img;
	else
		f->img = NULL;
}

static fzreq *oldest_live(fz *f)
{
	unsigned i;
	fzreq *best = NULL;

	for (i = 0; i < FZ_NREQ; i++)
		if (f->rq[i].live && (best == NULL || f->rq[i].seq < best->seq))
			best = &f->rq[i];
	return best;
}

static cw_conn *any_conn(cw *w, unsigned n)
{
	unsigned i, k = 0, total = 0;

	for (i = 0; i < CW_MAXC; i++)
		total += w->hc[i].used && (w->hc[i].oc != NULL || w->hc[i].mc != NULL);
	if (total == 0u)
		return NULL;
	n %= total;
	for (i = 0; i < CW_MAXC; i++)
		if (w->hc[i].used && (w->hc[i].oc != NULL || w->hc[i].mc != NULL)) {
			if (k == n)
				return &w->hc[i];
			k++;
		}
	return NULL;
}

static void do_osd_fault(fz *f, unsigned a, unsigned b)
{
	cw *w = &f->w;
	unsigned o = b % w->n_osd;
	sim_osd_fault *ft = sim_osd_faults(w->osd[o]);

	switch (a % 6u) {
	case 0:
		ft->silent = (uint8_t)!ft->silent;
		break;
	case 1:
		ft->hold_replies = (uint8_t)!ft->hold_replies;
		if (!ft->hold_replies)
			(void)sim_osd_release(w->osd[o], 0);
		break;
	case 2:
		ft->drop_replies = 1u + b % 3u;
		break;
	case 3:
		ft->eagain_ops = 1u + b % 3u;
		break;
	case 4:
		ft->redirect = (uint8_t)!ft->redirect;
		break;
	default:
		w->osd_down[o] = !w->osd_down[o];
		break;
	}
}

/* The faults of the secure layer go into the simulators' configuration: every connection they accept from now on carries them. */
static void set_sec_fault(sim_m2_cfg *m2, unsigned a, unsigned b, unsigned c)
{
	sim_sec_fault *sf = &m2->f.sec;

	if (c & 0x40u) { /* the mode AUTH_DONE announces is not the negotiated one: crc (a downgrade) or secure (a mode nobody offered); a % 3 == 2: back to honest */
		m2->f.done_mode = a % 3u == 0u ? WRI_CONN_MODE_CRC : a % 3u == 1u ? WRI_CONN_MODE_SECURE : 0u;
		return;
	}
	switch (a % 8u) {
	case 0:
		sf->omit_secret = (uint8_t)!sf->omit_secret;
		break;
	case 1:
		sf->secret_len = b % 3u == 0u ? 0u : b % 130u; /* too short, odd, long, or the usual 64 */
		break;
	case 2:
		sf->wrong_key_tx = (uint8_t)!sf->wrong_key_tx;
		break;
	case 3:
		sf->wrong_seed_tx = (uint8_t)!sf->wrong_seed_tx;
		break;
	case 4:
		sf->mut_frame = 4u + b % 12u;
		sf->mut.mask = SIM_SEC_M_FLIP;
		sf->mut.flip_part = 1;
		sf->mut.flip_region = (uint8_t)(c % 3u);
		sf->mut.flip_byte = (c >> 2) % 14u;
		sf->mut.flip_bit = (uint8_t)(b & 7u);
		break;
	case 5:
		sf->mut_frame = 4u + b % 12u;
		sf->mut.mask = SIM_SEC_M_TRUNC;
		sf->mut.truncate_at = 1u + c % 90u;
		sf->mut_close = 1;
		break;
	case 6:
		sf->secret_in_crc = (uint8_t)!sf->secret_in_crc;
		break;
	default:
		memset(sf, 0, sizeof(*sf));
		m2->f.done_mode = 0;
		break;
	}
}

static void do_sec_fault(fz *f, unsigned a, unsigned b, unsigned c)
{
	cw *w = &f->w;

	if (c & 0x80u) {
		set_sec_fault(&w->mon->cfg.m2, a, b, c);
	} else {
		unsigned i;

		for (i = 0; i < w->n_osd; i++)
			set_sec_fault(&w->osd[i]->cfg.m2, a, b, c);
	}
}

static unsigned allow_of(unsigned v)
{
	switch (v & 3u) {
	case 0:
		return SC_ALLOW_CRC | SC_ALLOW_SECURE;
	case 1:
		return SC_ALLOW_CRC;
	case 2:
		return SC_ALLOW_SECURE;
	default:
		return SC_ALLOW_CRC | SC_ALLOW_SECURE | SC_ALLOW_SECURE_FIRST;
	}
}

static void set_servers(fz *f, unsigned a, unsigned b)
{
	unsigned i;

	sc_allow(&f->w.mon->cfg.m2, allow_of(a));
	for (i = 0; i < f->w.n_osd; i++)
		sc_allow(&f->w.osd[i]->cfg.m2, allow_of(b));
}

static void clear_faults(fz *f)
{
	cw *w = &f->w;
	unsigned j;

	for (j = 0; j < w->n_osd; j++) {
		sim_osd_fault *ft = sim_osd_faults(w->osd[j]);

		ft->silent = 0;
		ft->hold_replies = 0;
		ft->drop_replies = 0;
		ft->eagain_ops = 0;
		ft->redirect = 0;
		w->osd_down[j] = 0;
		memset(&w->osd[j]->cfg.m2.f.sec, 0, sizeof(w->osd[j]->cfg.m2.f.sec));
		w->osd[j]->cfg.m2.f.done_mode = 0;
		(void)sim_osd_release(w->osd[j], 0);
	}
	memset(&w->mon->cfg.m2.f.sec, 0, sizeof(w->mon->cfg.m2.f.sec));
	w->mon->cfg.m2.f.done_mode = 0;
	set_servers(f, 0, 0); /* both servers allow both modes again */
}

/* A connection whose stream a flip or raw bytes reach: the data stays the model's only when it is sealed (the tag refuses what is not the server's). */
static int sealed(const fz *f, const cw_conn *hc)
{
	wri_cslot *s = wri_client_slot_of(f->w.c, hc->id);

	return s != NULL && s->conn.sec != NULL && s->conn.sec->s.active;
}

static void do_op(fz *f)
{
	unsigned op = (unsigned)in_byte(f) % 14u, a = (unsigned)in_byte(f), b = (unsigned)in_byte(f), c = (unsigned)in_byte(f);
	fzreq *q;

	switch (op) {
	case 0:
		tick(f, a % 24u + 1u);
		return;
	case 1:
		submit(f, WR_IO_WRITE, a, b, c);
		break;
	case 2:
		submit(f, WR_IO_READ, a, b, c);
		break;
	case 3:
		submit(f, WR_IO_FLUSH, 0, 0, 0);
		break;
	case 4:
		submit(f, WR_IO_DISCARD, a, b, c);
		break;
	case 5:
		submit(f, WR_IO_WRITE_ZEROES, a, b, c);
		break;
	case 6:
		q = oldest_live(f);
		if (q != NULL && f->img != NULL) {
			cw_dig_u64(&f->w, (uint64_t)(int64_t)wr_image_cancel(f->img, &q->r));
			if (q->is_write)
				f->model_ok = 0;
		}
		break;
	case 7:
		if (f->img != NULL) {
			unsigned k;

			if (a & 1u)
				f->model_ok = 0; /* abandoned writes continue as zombies: they may land later */
			/* a draining close lets the writes in flight finish on the OLD handle and the fence that orders overlapping requests is per handle:
			 * a read on the new handle may run before a write, discard or write-zeroes of the old one has landed (the same finding as in
			 * fuzz_client_osd, see test_fuzzlong_close_drain). The model holds only while none is in flight at the reopen. */
			for (k = 0; k < FZ_NREQ; k++)
				if (f->rq[k].live && f->rq[k].is_write)
					f->model_ok = 0;
			cw_dig_u64(&f->w, (uint64_t)(int64_t)wr_image_close(f->img, (a & 1u) ? WR_CLOSE_ABANDON : WR_CLOSE_DRAIN));
		}
		open_image(f);
		break;
	case 8:
		sim_osd_restart(f->w.osd[a % f->w.n_osd]);
		break;
	case 9:
		sim_mon_restart(f->w.mon);
		break;
	case 10:
		do_osd_fault(f, a, b);
		break;
	case 11:
		do_sec_fault(f, a, b, c);
		break;
	case 12:
		set_servers(f, a, b);
		break;
	default: {
		cw_conn *hc = any_conn(&f->w, a);

		if (hc != NULL) {
			if (!sealed(f, hc))
				f->tainted = 1; /* a crc connection (or one still shaking hands) may carry a flip the checksum misses: the model is no longer the truth */
			hc->flip_off = (uint64_t)a * 37u + b;
			hc->flip_mask = (uint8_t)(c != 0u ? c : 1u);
		}
		break;
	}
	}
	settle(f);
}

/* ---- one run ------------------------------------------------------------------------------------------------------------------- */

static uint64_t run_once(const uint8_t *data, size_t size, uint8_t pat_a, uint8_t pat_b)
{
	static const uint8_t policies[8] = {WR_MODE_CRC_ONLY, WR_MODE_CRC_FIRST, WR_MODE_SECURE_FIRST, WR_MODE_SECURE_ONLY, WR_MODE_STOCK,
					    WR_MODE_SECURE_ONLY, WR_MODE_SECURE_FIRST, WR_MODE_STOCK};
	fz *f = (fz *)calloc(1, sizeof(*f));
	wr_config cfg;
	unsigned n_ops = 0, i;
	uint64_t digest;
	size_t k, used, nonzero = 0, guard_bad = 0;
	unsigned hdr = size > 0u ? data[0] : 0u, hdr2 = size > 1u ? data[1] : 0u;
	uint8_t policy = policies[(hdr >> 2) & 7u];

	check(f != NULL);
	f->model = (uint8_t *)calloc(1, FZ_IMG_SIZE);
	f->rq = (fzreq *)calloc(FZ_NREQ, sizeof(fzreq));
	check(f->model != NULL && f->rq != NULL);
	f->model_ok = 1;
	f->in = data;
	f->in_n = size;
	f->pos = size > 1u ? 2u : size;
	f->policy = policy;
	g_cw_pat_a = pat_a;
	g_cw_pat_b = pat_b;
	cw_cfg_default(&cfg);
	wr_config_enable_secure(&cfg, WR_MAPS_IPXE, policy);
	cfg.sec_tx_chunk = (hdr & 0x40u) ? 4096u : 256u;
	cfg.osd_sessions = (hdr & 2u) ? 4 : 2;
	cfg.max_conns = (uint16_t)(cfg.osd_sessions + 2u);
	cfg.op_bytes_max = (hdr & 0x20u) ? 256u * 1024u : 32u * 1024u;
	cfg.max_ops = 8;
	cfg.ctl_ops = 2;
	cfg.max_reqs = FZ_NREQ;
	cfg.hdr_refresh_ms = 3000;
	cfg.op_timeout_ms = 3000;
	cfg.map_stale_ms = 20000;
	g_sc_nlog = 0;
	g_sc_limit = (hdr2 >> 4) == 0u ? 0u : 24u + 16u * (hdr2 >> 4);
	g_sc_limit_set = 0;
	check(cw_open(&f->w, &cfg, 3, 8, (hdr & 1u) ? WR_KEY_TYPE_AES : WR_KEY_TYPE_AES256K) == 0);
	f->w.c->x.host.log = sc_log; /* the engine keeps a copy of the host table: tap it before the first run */
	set_servers(f, hdr2, hdr2 >> 2);
	check(cw_image(&f->w, "img", "fz0001", FZ_IMG_SIZE, FZ_ORDER, 0x21, -1) == 0);
	g_cw_ndone = 0;
	open_image(f);
	settle(f);
	while (f->pos < f->in_n && n_ops < MAX_OPS) {
		do_op(f);
		n_ops++;
	}
	/* a good world at the end: no faults, both servers allow both modes, every host alive; a world the fuzzer did not corrupt completes everything it accepted */
	clear_faults(f);
	tick(f, 40);
	tick(f, 400); /* 20 s: the longest cool-down and timeouts of the configuration pass */
	if (!f->tainted)
		for (i = 0; i < FZ_NREQ; i++)
			check(!f->rq[i].live);
	if (f->img != NULL)
		cw_dig_u64(&f->w, (uint64_t)(int64_t)wr_image_close(f->img, WR_CLOSE_ABANDON));
	settle(f);
	digest = f->w.digest;
	used = f->w.req.arena;
	check(wr_client_get_state(f->w.c) != WR_CS_CREATED);
	{
		wr_stats ws;

		wr_client_get_stats(f->w.c, &ws);
		check(ws.arena_used == f->w.req.arena && ws.bulk_used == f->w.req.bulk); /* the engine took exactly what it announced, nothing since */
	}
	wr_client_destroy(f->w.c);
	for (k = 0; k < used; k++)
		nonzero += f->w.arena_base[k] != 0u;
	check(nonzero == 0u);
	check(sc_scan_memory(&f->w, 0) == 0u && sc_scan_memory(&f->w, 1) == 0u); /* no secret of any connection is left in either region */
	for (k = 0; k < (size_t)(f->w.arena_base - f->w.arena_raw); k++)
		guard_bad += f->w.arena_raw[k] != f->w.arena_pat;
	for (k = used + (size_t)(f->w.arena_base - f->w.arena_raw); k < f->w.req.arena + 128u; k++)
		guard_bad += f->w.arena_raw[k] != f->w.arena_pat;
	check(guard_bad == 0u);
	guard_bad = 0;
	for (k = (size_t)(f->w.bulk_base - f->w.bulk_raw) + f->w.req.bulk; k < f->w.req.bulk + 128u; k++)
		guard_bad += f->w.bulk_raw[k] != f->w.bulk_pat;
	check(guard_bad == 0u);
	f->w.c = NULL;
	cw_free(&f->w);
	free(f->model);
	free(f->rq);
	free(f);
	g_sc_limit = 0;
	return digest;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint64_t d1, d2;

	if (size > MAX_INPUT)
		size = MAX_INPUT;
	d1 = run_once(data, size, 0xA5u, 0x5Au);
	d2 = run_once(data, size, 0x3Cu, 0xC3u);
	check(d1 == d2); /* the same input behaves the same whatever the memory held before */
	return 0;
}
