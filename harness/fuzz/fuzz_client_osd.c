/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the whole client engine WITH the OSD client and an RBD image on it (module client-glue-osd: core/src/client/wri_client_osd*.c,
 * wr_image.c, core/src/rbd/wri_rbd_step.c and everything below them), through the PUBLIC API only. The engine runs against the simulated monitor and up to
 * three simulated OSDs over one object store (test/client_osd_rig.h plays the host), an image of 1 MiB (16 KiB objects) is opened for writing, and the input
 * script is a series of host calls, faults and hostile bytes. The fuzzer also plays the OSD: well-framed messages of any type on a connection that finished
 * its REAL handshake (cephx authorizer round trip included), raw bytes in place of the stream, flipped bits.
 *
 * Input layout:
 *
 *   byte 0   bit 0 key type (aes / aes256k), bit 1 osd_sessions 2 or 4 (the table evicts or not), bit 2 op_bytes_max 32 KiB or 256 KiB, bit 3 max_ops 6 or 16,
 *            bit 4 the host delivers one byte at a time for the first connections (a byte-granular stream)
 *   rest     operations: an opcode byte (mod 14) and three argument bytes a, b, c (more bytes follow for op 11 and 12):
 *              0 run      a: advance the virtual clock by (a % 24 + 1) ticks of 50 ms, settling at each; with c == 255 instead: advance it by (a + 1) * 250 ms
 *                         WITHOUT running the engine (the next submit or open is timed against a clock that is old)
 *              1 write    (a, b) offset, c length class, a seed: a write of at most 20000 bytes
 *              2 read     the same shape, the bytes it must read are what the model says
 *              3 flush
 *              4 discard / 5 write-zeroes  (a, b) offset, c length
 *              6 cancel   the oldest request in flight (a: its timeout)
 *              7 reopen   close the image (a & 1: abandon), open it again
 *              8 osd      sim_osd_restart of OSD (a % n): every connection cut, held answers lost
 *              9 monitor  sim_mon_restart
 *             10 fault    a selects one of: silent, hold the answers (released when switched off), drop the next answers, EAGAIN, redirect, refuse the
 *                         authorizer, no duplicate detection, a connect that is refused (a dead host), a reply with a damaged length, answers in reverse
 *             11 msg      a, b, len, bytes: one well-framed MESSAGE from the OSD on a live connection after its handshake: a type chosen by a (MOSDOpReply,
 *                         MOSDBackoff, MOSDMap, MOSDOp, an unknown type), header version / compat from b, a front of the next bytes
 *             12 raw      a, len, bytes: the next bytes the host delivers on a live OSD connection are these (framing and checksums unchecked)
 *             13 flip     a, b, c: flip the bits c in the stream of a live connection at offset a * 37 + b
 *
 * Properties (a violated one traps): no crash or undefined behaviour (ASan / UBSan); the host loop settles (no instant repeats for ever); the pools stay
 * inside the configuration (operations, requests, sessions, connections); a request completes AT MOST once and only after it was submitted; with a world
 * the fuzzer did not corrupt (no msg / raw / flip, no damaged reply) every request that was accepted completes (after the faults are cleared), and a READ that
 * completes with success returns exactly what the model says an image with those writes holds (the model is dropped as soon as a write fails or is
 * cancelled: it may or may not have been applied); a destroyed client leaves the arena part in use all zero and nothing outside the regions written.
 *
 * Determinism property (no read of uninitialised memory): every input is played TWICE, once with the two regions pre-filled with one byte pattern and once with
 * another; a digest of everything the host can observe (every action, every byte the engine transmits, every event, every completion with its read data and the
 * counters after each step) must be identical.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test/client_osd_rig.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAX_INPUT 2048u
#define MAX_OPS 90u
#define FZ_IMG_SIZE (1u << 20)
#define FZ_ORDER 14u
#define FZ_BUF 20000u
#define FZ_NREQ 10u
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

/* Take the completions the rig pulled: each of ours exactly once, a read's bytes against the model (while it still holds), the digest. */
static void reap(fz *f)
{
	unsigned i, j;

	for (i = 0; i < g_cw_ndone; i++) {
		fzreq *q = find_req(f, g_cw_done[i].req);

		check(q != NULL); /* nothing completes that we did not submit */
		for (j = 0; j < i; j++)
			check(g_cw_done[j].req != g_cw_done[i].req); /* and nothing completes twice */
		check(q->live); /* ... or without having been submitted */
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
	cw_dig_u64(&f->w, st.ops_inflight);
	cw_dig_u64(&f->w, st.reqs_inflight);
	cw_dig_u64(&f->w, st.sessions_open);
	cw_dig_u64(&f->w, st.ops_done);
	cw_dig_u64(&f->w, st.ops_resent);
	cw_dig_u64(&f->w, st.n_session_resets);
	cw_dig_u64(&f->w, ws.conns_in_use);
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

static void submit(fz *f, wr_io_kind kind, unsigned a, unsigned b, unsigned c, unsigned timeout_class)
{
	fzreq *q = free_req(f);
	uint64_t off = ((uint64_t)a * 4099u + b * 13u) % FZ_IMG_SIZE;
	uint64_t len = 1u + ((uint64_t)c * 97u + a) % FZ_BUF;
	wr_status st;

	if (q == NULL || f->img == NULL)
		return;
	if (off + len > FZ_IMG_SIZE && (a & 7u) != 7u)
		len = FZ_IMG_SIZE - off; /* mostly inside the image; one in eight may stick out (WR_E_RANGE) */
	if (len == 0u)
		len = 1;
	memset(&q->r, 0, sizeof(q->r));
	q->r.kind = kind;
	q->r.offset = kind == WR_IO_FLUSH ? 0u : off;
	q->r.length = kind == WR_IO_FLUSH ? 0u : len;
	q->r.buf = kind == WR_IO_READ || kind == WR_IO_WRITE ? q->buf : NULL;
	q->r.timeout_ms = timeout_class % 4u == 0u ? 1500u + timeout_class * 50u : 0u;
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
		return; /* refused with no I/O: not accepted, not in flight */
	}
	q->live = 1;
	q->seq = (int)++f->seq;
	f->n_submitted++;
	/* the model follows the order of acceptance: a request sees every overlapping request accepted before it and none accepted after it (the fence) */
	if (off + len <= FZ_IMG_SIZE) {
		if (kind == WR_IO_WRITE)
			memcpy(f->model + off, q->buf, (size_t)len);
		else if (kind == WR_IO_DISCARD || kind == WR_IO_WRITE_ZEROES)
			memset(f->model + off, 0, (size_t)len);
		else if (kind == WR_IO_READ) {
			memcpy(q->exp, f->model + off, (size_t)len);
			q->exp_ok = 1;
		}
	}
	/* a write accepted while the image is not writable (or past its end) fails: the status is the request's own, the model is dropped then by reap() */
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

/* A live connection to an OSD (the n-th), NULL if none. */
static cw_conn *osd_conn(cw *w, unsigned n)
{
	unsigned i, k = 0, total = 0;

	for (i = 0; i < CW_MAXC; i++)
		total += w->hc[i].used && w->hc[i].osd >= 0 && w->hc[i].oc != NULL;
	if (total == 0u)
		return NULL;
	n %= total;
	for (i = 0; i < CW_MAXC; i++)
		if (w->hc[i].used && w->hc[i].osd >= 0 && w->hc[i].oc != NULL) {
			if (k == n)
				return &w->hc[i];
			k++;
		}
	return NULL;
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

static void do_fault(fz *f, unsigned a, unsigned b)
{
	cw *w = &f->w;
	unsigned o = b % w->n_osd;
	sim_osd_fault *ft = sim_osd_faults(w->osd[o]);

	switch (a % 10u) {
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
	case 5:
		ft->refuse_auth = (uint8_t)!ft->refuse_auth;
		break;
	case 6:
		ft->no_dedup = (uint8_t)!ft->no_dedup;
		break;
	case 7:
		w->osd_down[o] = !w->osd_down[o];
		break;
	case 8:
		ft->bad_reply_len = (uint8_t)!ft->bad_reply_len;
		f->tainted = 1; /* a lying OSD: the data is no longer the model's */
		break;
	default:
		ft->reverse_release = (uint8_t)!ft->reverse_release;
		break;
	}
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
		ft->refuse_auth = 0;
		ft->bad_reply_len = 0;
		ft->reverse_release = 0;
		w->osd_down[j] = 0;
		(void)sim_osd_release(w->osd[j], 0);
	}
}

static void play_msg(fz *f, unsigned a, unsigned b, unsigned len)
{
	static const uint16_t types[] = {43, 61, 41, 42, 999, 43, 61, 17};
	cw_conn *hc = osd_conn(&f->w, a >> 3);
	uint8_t front[64];
	unsigned i;

	len %= sizeof(front) + 1u;
	for (i = 0; i < len; i++)
		front[i] = (uint8_t)in_byte(f);
	f->tainted = 1;
	if (hc == NULL)
		return;
	cw_dig_u64(&f->w, (uint64_t)(int64_t)sim_m2_send_message(sim_osd_conn_m2(hc->oc), types[a % 8u], (uint64_t)b * 65537u + a, (uint16_t)(b % 12u), front, len, NULL, 0, NULL, 0));
}

static void play_raw(fz *f, unsigned a, unsigned len)
{
	cw_conn *hc = osd_conn(&f->w, a);
	unsigned i;

	len %= 65u;
	f->tainted = 1;
	if (hc == NULL) {
		for (i = 0; i < len; i++)
			(void)in_byte(f);
		return;
	}
	for (i = 0; i < len && hc->inj_len < sizeof(hc->inj); i++)
		hc->inj[hc->inj_len++] = (uint8_t)in_byte(f);
}

static void do_op(fz *f)
{
	unsigned op = (unsigned)in_byte(f) % 14u, a = (unsigned)in_byte(f), b = (unsigned)in_byte(f), c = (unsigned)in_byte(f);
	fzreq *q;

	switch (op) {
	case 0:
		if (c == 0xffu) { /* an idle spell: the clock moves (up to 64 s) and the engine is not run, so the next submit or open is timed against an old clock */
			f->w.now += ((uint64_t)a + 1u) * 250u;
			return;
		}
		tick(f, a % 24u + 1u);
		return;
	case 1:
		submit(f, WR_IO_WRITE, a, b, c, c ^ b);
		break;
	case 2:
		submit(f, WR_IO_READ, a, b, c, c ^ b);
		break;
	case 3:
		submit(f, WR_IO_FLUSH, 0, 0, 0, c);
		break;
	case 4:
		submit(f, WR_IO_DISCARD, a, b, c, c);
		break;
	case 5:
		submit(f, WR_IO_WRITE_ZEROES, a, b, c, c);
		break;
	case 6:
		q = oldest_live(f);
		if (q != NULL && f->img != NULL) {
			wr_status st = wr_image_cancel(f->img, &q->r);

			cw_dig_u64(&f->w, (uint64_t)(int64_t)st);
			if (q->is_write)
				f->model_ok = 0; /* a cancelled write may have been applied in part or whole */
		}
		break;
	case 7:
		if (f->img != NULL) {
			if (a & 1u)
				f->model_ok = 0; /* abandoned writes continue as zombies: they may land later */
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
		do_fault(f, a, b);
		break;
	case 11:
		play_msg(f, a, b, c);
		break;
	case 12:
		play_raw(f, a, b);
		break;
	default: {
		cw_conn *hc = any_conn(&f->w, a);

		f->tainted = 1;
		if (hc != NULL) {
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
	fz *f = (fz *)calloc(1, sizeof(*f));
	wr_config cfg;
	unsigned n_ops = 0, i;
	uint64_t digest;
	size_t k, used, nonzero = 0, guard_bad = 0;
	unsigned hdr = size > 0u ? data[0] : 0u;

	check(f != NULL);
	f->model = (uint8_t *)calloc(1, FZ_IMG_SIZE);
	f->rq = (fzreq *)calloc(FZ_NREQ, sizeof(fzreq));
	check(f->model != NULL && f->rq != NULL);
	f->model_ok = 1;
	f->in = data;
	f->in_n = size;
	f->pos = size > 0u ? 1u : 0u;
	g_cw_pat_a = pat_a;
	g_cw_pat_b = pat_b;
	cw_cfg_default(&cfg);
	cfg.osd_sessions = (hdr & 2u) ? 4 : 2;
	cfg.max_conns = (uint16_t)(cfg.osd_sessions + 2u);
	cfg.op_bytes_max = (hdr & 4u) ? 256u * 1024u : 32u * 1024u;
	cfg.max_ops = (hdr & 8u) ? 16 : 6;
	cfg.ctl_ops = 2;
	cfg.max_reqs = FZ_NREQ;
	cfg.hdr_refresh_ms = 3000;
	cfg.op_timeout_ms = 3000;
	cfg.map_stale_ms = 20000;
	check(cw_open(&f->w, &cfg, 3, 8, (hdr & 1u) ? WR_KEY_TYPE_AES : WR_KEY_TYPE_AES256K) == 0);
	check(cw_image(&f->w, "img", "fz0001", FZ_IMG_SIZE, FZ_ORDER, 0x21, -1) == 0);
	g_cw_ndone = 0;
	open_image(f);
	settle(f);
	while (f->pos < f->in_n && n_ops < MAX_OPS) {
		do_op(f);
		n_ops++;
	}
	/* a good world at the end: no faults, nothing held, every host alive; a world the fuzzer did not corrupt completes everything it accepted */
	clear_faults(f);
	tick(f, 40);
	tick(f, 400); /* 20 s: the longest cool-down and timeouts of the configuration pass */
	if (!f->tainted)
		for (i = 0; i < FZ_NREQ; i++)
			check(!f->rq[i].live);
	/* the end: the image is let go of, the client destroyed, the arena wiped, nothing written outside the regions */
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
	for (k = 0; k < (size_t)(f->w.arena_base - f->w.arena_raw); k++)
		guard_bad += f->w.arena_raw[k] != f->w.arena_pat;
	for (k = used + (size_t)(f->w.arena_base - f->w.arena_raw); k < f->w.req.arena + 128u; k++)
		guard_bad += f->w.arena_raw[k] != f->w.arena_pat;
	check(guard_bad == 0u);
	/* the bulk: nothing beyond what the engine took was written (the part it took is the engine's: map slots, message buffers, the zombie area) */
	guard_bad = 0;
	for (k = (size_t)(f->w.bulk_base - f->w.bulk_raw) + f->w.req.bulk; k < f->w.req.bulk + 128u; k++)
		guard_bad += f->w.bulk_raw[k] != f->w.bulk_pat;
	check(guard_bad == 0u);
	f->w.c = NULL;
	cw_free(&f->w);
	free(f->model);
	free(f->rq);
	free(f);
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
