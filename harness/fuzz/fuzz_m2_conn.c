/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the msgr2 connection state machine (core/src/msgr2/wri_m2_conn.c, wri_m2_conn_hs.c,
 * wri_m2_conn_msg.c): random bytes fed to a connection that the scriptable server of sim_m2.h has
 * walked into each state first.
 *
 * Input layout:
 *
 *   byte 0       bits 0-2 the state the fuzz bytes meet: 0 BANNER, 1 HELLO, 2 AUTH, 3 SIG, 4 IDENT, 5 READY
 *                (6 and 7 count as 5), bits 3-4 feeding style (all at once, one byte at a time, random
 *                pieces, pieces of 7), bit 5 the upper layer discards every message, bit 6 its plan()
 *                answers WR_E_BUSY a few times first, bit 7 the host never consumes transmit bytes
 *   byte 1       bits 0-1 receive ring size (16, 64, 1024, 8192), bits 4-7 work budget per step
 *                (0 = unlimited, else 1, 2, 3, 7, 16, ...)
 *   bytes 2-3    segment cap for segments 1..3 minus 1 (little endian)
 *   rest         the bytes fed to the connection; the last 8 of them (when the connection ends up in READY)
 *                choose a few sends of messages and keepalives
 *
 * The state is reached with an honest server, so the fuzz bytes meet a real handshake in progress: the
 * server goes quiet at the chosen point (out_limit), exactly as a stalled peer would.
 *
 * Properties (a violated one traps): no crash or undefined behaviour (ASan / UBSan); sinks given to the
 * connection are exact-size heap blocks with canary bytes behind them and nothing is written outside
 * them; stored[i] never exceeds the segment length; delivered sequence numbers strictly increase; a
 * failed connection reported its first error once, keeps it, releases the handshake slot, offers no
 * window and nothing to transmit and sends nothing after the failure; a live connection never
 * reported a close; no MESSAGE or KEEPALIVE2 frame is ever written before SERVER_IDENT was processed;
 * the receive ring never overflows; our message sequence numbers rise by exactly one per accepted send.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test/m2_conn_rig.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define HDR 4u
#define CANARY 8u
#define MAX_INPUT 70000u

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

typedef struct fz {
	rig *r;
	uint8_t *blk[3];
	uint32_t blen[3];
	int discard, busy;
	uint32_t rng;
	uint64_t last_seq;
	int have_seq;
	int ready_seen;
	wr_status first_err;
	size_t sent_at_fail;
	int failed_seen;
} fz;

static uint32_t rnd(fz *z)
{
	z->rng ^= z->rng << 13;
	z->rng ^= z->rng >> 17;
	z->rng ^= z->rng << 5;
	return z->rng;
}

static void blocks_release(fz *z)
{
	unsigned i, k;

	for (i = 0; i < 3; i++) {
		if (z->blk[i] != NULL) {
			for (k = 0; k < CANARY; k++)
				check(z->blk[i][z->blen[i] + k] == 0xA5); /* nothing written past the end */
			free(z->blk[i]);
			z->blk[i] = NULL;
		}
	}
}

static wr_status fz_plan(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t seglen[3], wri_m2_sink sink[3])
{
	fz *z = (fz *)ctx;
	unsigned i, k;

	(void)c;
	(void)hdr;
	check(c->state == WRI_M2_READY);
	if (z->busy > 0) {
		z->busy--;
		return WR_E_BUSY;
	}
	blocks_release(z); /* a message that never completed (aborted) leaves its blocks behind */
	if (z->discard)
		return WR_OK;
	for (i = 0; i < 3; i++) {
		z->blen[i] = seglen[i];
		z->blk[i] = (uint8_t *)malloc((size_t)seglen[i] + CANARY);
		check(z->blk[i] != NULL);
		for (k = 0; k < CANARY; k++)
			z->blk[i][seglen[i] + k] = 0xA5;
		sink[i].dst = z->blk[i];
		/* now and then a sink one byte short: the connection must refuse the segment before writing */
		sink[i].cap = (seglen[i] != 0 && rnd(z) % 16 == 0) ? seglen[i] - 1u : seglen[i];
	}
	return WR_OK;
}

static void fz_message(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t stored[3])
{
	fz *z = (fz *)ctx;
	unsigned i;

	check(c->state == WRI_M2_READY);
	check(!z->have_seq || hdr->seq > z->last_seq); /* strictly increasing */
	z->last_seq = hdr->seq;
	z->have_seq = 1;
	check(hdr->seq == c->in_seq);
	for (i = 0; i < 3; i++)
		if (z->blk[i] != NULL)
			check(stored[i] <= z->blen[i]);
	blocks_release(z);
}

static void fz_ready(void *ctx, wri_m2_conn *c)
{
	fz *z = (fz *)ctx;

	check(c->state == WRI_M2_READY);
	check(!z->ready_seen);
	z->ready_seen = 1;
}

static void fz_closed(void *ctx, wri_m2_conn *c, const wr_errinfo *err)
{
	fz *z = (fz *)ctx;

	z->r->up.n_closed++;
	check(z->r->up.n_closed == 1);
	check(err->status < 0 && err->status == c->err.status);
	z->first_err = err->status;
}

static const wri_m2_upper fz_ops = {fz_plan, fz_message, fz_ready, fz_closed};

static void sent_frames_ok(const rig *r, int ready_seen)
{
	size_t off = WRI_M2_BANNER_LEN;

	if (r->sent_len < WRI_M2_BANNER_LEN)
		return;
	while (off + WRI_M2_PREAMBLE_LEN <= r->sent_len) {
		wri_m2_desc d;

		check(wri_m2_preamble_parse(NULL, r->sent + off, &d) == WR_OK); /* our own output is well formed */
		if (!ready_seen)
			check(d.tag != WRI_M2_TAG_MESSAGE && d.tag != WRI_M2_TAG_KEEPALIVE2);
		off += WRI_M2_PREAMBLE_LEN + (size_t)wri_m2_frame_body_len(&d);
	}
	check(off == r->sent_len);
}

static void invariants(fz *z)
{
	rig *r = z->r;
	wri_m2_conn *c = &r->c;
	wr_iov iov[WRI_M2_TXQ_IOV];
	uint8_t *w;

	check(c->ring.len <= c->ring.cap);
	check(c->state >= WRI_M2_BANNER && c->state <= WRI_M2_CLOSING);
	if (c->state == WRI_M2_FAILED) {
		check(c->err.status < 0);
		check(r->up.n_closed == 1);
		check(c->pa == NULL);
		check(wri_m2_conn_tx_peek(c, iov, WRI_M2_TXQ_IOV) == 0);
		check(wri_m2_conn_rx_window(c, &w) == 0);
		if (!z->failed_seen) {
			z->failed_seen = 1;
			z->first_err = c->err.status;
			z->sent_at_fail = r->sent_len;
		}
		check(c->err.status == z->first_err); /* the first cause is kept */
		check(r->sent_len == z->sent_at_fail);  /* nothing is sent after the failure */
	} else {
		check(r->up.n_closed == 0);
		check(c->err.status == WR_OK);
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint32_t ring_caps[4] = {16, 64, 1024, 8192};
	static const uint32_t budgets[16] = {0, 1, 2, 3, 7, 16, 31, 64, 100, 255, 500, 1000, 4096, 5000, 10000, 65536};
	static const int64_t limits[6] = {0, 26, 98, 239, 307, -1}; /* where the server goes quiet, per state */
	unsigned state, style, i;
	uint32_t seed = 1, budget_sel;
	const uint8_t *fuzz;
	size_t rest, pos = 0, guard = 0;
	rig r;
	fz z;

	if (size < HDR || size > MAX_INPUT)
		return 0;
	state = data[0] & 7u;
	if (state > 5u)
		state = 5u;
	style = (data[0] >> 3) & 3u;
	budget_sel = data[1] >> 4;
	for (i = 0; i < size && i < 16; i++)
		seed = seed * 31u + data[i];
	fuzz = data + HDR;
	rest = size - HDR;

	rig_init(&r);
	r.ring_cap = ring_caps[data[1] & 3u];
	r.seg_cap_max = 1u + (uint32_t)data[2] + ((uint32_t)data[3] << 8);
	r.io_cap = 1u << 20;
	r.scfg.out_cap = 1u << 18;
	r.scfg.preauth_cap = 1u << 14;
	r.scfg.msg_bytes_cap = 1u << 16;
	r.scfg.f.out_limit = limits[state];
	rig_start(&r);
	if (state != 0)
		rig_pump(&r);
	else
		(void)rig_flush_tx(&r); /* the banner goes out; the server's is not read yet */
	if (r.c.state != (state == 0 ? WRI_M2_BANNER : state == 1 ? WRI_M2_HELLO : state == 2 ? WRI_M2_AUTH :
			  state == 3 ? WRI_M2_SIG : state == 4 ? WRI_M2_IDENT : WRI_M2_READY)) {
		/* the honest prefix did not reach the state: a bug of the rig, not a property of the input */
		check(0);
	}
	memset(&z, 0, sizeof(z));
	z.r = &r;
	z.rng = seed | 1u;
	z.discard = (data[0] >> 5) & 1u;
	z.busy = ((data[0] >> 6) & 1u) ? 3 : 0;
	z.ready_seen = r.c.state == WRI_M2_READY;
	r.c.up = &fz_ops;
	r.c.up_ctx = &z;
	r.up.n_ready = 0;

	/* the fuzz bytes meet the connection */
	while (r.c.state >= WRI_M2_BANNER && r.c.state <= WRI_M2_READY && guard++ < 8 * rest + 4096) {
		uint8_t *w = NULL;
		size_t room = wri_m2_conn_rx_window(&r.c, &w), k;
		uint32_t b = budgets[budget_sel & 15u], *bp = b != 0 ? &b : NULL;

		if (room != 0 && w != NULL && pos < rest) {
			k = style == 0 ? rest : style == 1 ? 1 : style == 2 ? 1 + rnd(&z) % 300 : 7;
			k = k < room ? k : room;
			k = k < rest - pos ? k : rest - pos;
			memcpy(w, fuzz + pos, k);
			memcpy(r.rcvd + r.rcvd_len, fuzz + pos, k);
			r.rcvd_len += k;
			wri_m2_conn_rx_commit(&r.c, k);
			pos += k;
		}
		(void)wri_m2_conn_step(&r.x, &r.c, bp);
		invariants(&z);
		if (!(data[0] & 0x80u))
			(void)rig_flush_tx(&r);
		else if (z.rng % 7 == 0)
			(void)rig_flush_tx(&r); /* now and then the host catches up */
		if (r.c.stalled) {
			r.x.now.mono_ms += WRI_M2C_STALL_RETRY_MS; /* the retry time passes */
			if (z.busy == 0 && (data[0] & 0x80u))
				(void)rig_flush_tx(&r);
		}
		if (pos >= rest && r.c.ring.len == 0 && r.c.rx.direct == 0 && !r.c.stalled)
			break;
		if (pos >= rest && r.c.stalled && guard > 4 * rest + 100)
			break;
	}
	invariants(&z);
	/* time passing: handshake deadlines fire */
	r.x.now.mono_ms += 10000;
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	invariants(&z);

	if (r.c.state == WRI_M2_READY && size >= HDR + 8u) {
		static uint8_t datab[4096];
		const uint8_t *t = data + size - 8u;
		wri_m2_msg_out m;
		unsigned n;

		for (n = 0; n < 4; n++) {
			uint64_t before = r.c.out_seq;
			wr_status st;

			memset(&m, 0, sizeof(m));
			m.type = (uint16_t)(t[n] | (t[(n + 1) & 7] << 8));
			m.tid = n;
			m.version = 1;
			m.front = fuzz;
			m.front_len = (uint32_t)(t[(n + 2) & 7] * 16u) < (uint32_t)rest ? (uint32_t)(t[(n + 2) & 7] * 16u) : (uint32_t)rest;
			if (t[(n + 3) & 7] & 1u) {
				m.data = datab;
				m.data_len = (uint32_t)t[(n + 4) & 7] * 16u;
			}
			if (n == 3)
				st = wri_m2_conn_send_keepalive(&r.x, &r.c, t[0], t[1]);
			else
				st = wri_m2_conn_send_message(&r.x, &r.c, &m);
			check(st == WR_OK || st == WR_E_BUSY || st == WR_E_TOOBIG);
			check(r.c.out_seq == before + (n != 3 && st == WR_OK ? 1u : 0u));
			if (st == WR_E_BUSY)
				(void)rig_flush_tx(&r);
		}
		(void)rig_flush_tx(&r);
		invariants(&z);
	}
	sent_frames_ok(&r, z.ready_seen);
	blocks_release(&z);
	rig_free(&r);
	return 0;
}
