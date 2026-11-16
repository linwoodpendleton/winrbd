/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the whole client engine (the sources under core/src/client and everything below them) through the PUBLIC pump
 * API only: the engine runs against the simulated monitor of test/support/sim_mon.h, a small host moves the bytes,
 * and the input script decides where the world misbehaves: bytes of the monitor's stream that are flipped on the
 * way, connections cut by the host, a monitor that restarts, a clock that steps back, a random source that dies,
 * and calls that break the host contract (sizes past the window, bytes nobody sent, ids that are not the engine's).
 *
 * Input layout:
 *
 *   byte 0   bit 0 key type (aes / aes256k), bits 1-2 profile (0 harness with 256 KiB messages, 1 ipxe, 2 kernel,
 *            3 harness with a 64-byte receive ring), bit 3 the host pushes bytes (rx_push) instead of using the
 *            window, bits 4-7 work budget per run (0 = default, else 64 << n)
 *   rest     operations, an opcode byte (mod 11) and one or two argument bytes:
 *              0 run        a: advance the virtual clock by (a % 40 + 1) ticks of 50 ms, pumping at each
 *              1 flip       a, b: flip bits b in the monitor's stream at offset (a * 37) of the newest connection
 *              2 cut        the host drops the newest connection (wr_conn_closed with an errno)
 *              3 restart    the monitor restarts
 *              4 back       a run with a clock that stepped back, and a small budget
 *              5 abuse      a, b: one call that breaks the host contract (selector a)
 *              6 maps       toggle: the consumer holds the map messages / releases them
 *              7 random     toggle: the host random source fails / works again
 *              8 slow       a: the host sends at most (a % 64 + 1) bytes per round for a while
 *              9 msg        a, b, len16, bytes: the fuzzer plays the MONITOR: one well-framed MESSAGE (valid CRCs, valid
 *                           header) from the simulator on the newest connection, after the real handshake, with a
 *                           message type picked by a (MMonMap, MOSDMap, MAuthReply, subscribe ack, a few others and two
 *                           out-of-range types), header version / compat from b and a front made of the next bytes
 *              10 raw       a, len8, bytes: the fuzzer plays the monitor at the byte level: the next bytes the host
 *                           delivers on the newest connection are these (framing, CRCs and all unchecked), ahead of
 *                           whatever the simulated monitor still had queued
 *
 * Properties (a violated one traps): no crash or undefined behaviour (ASan / UBSan); the pump settles (no round
 * ever repeats forever at one instant); pool accounting stays inside the configuration (connections and handshakes
 * in use never exceed their tables, one monitor session at a time plus at most the ones still closing); a
 * connection that was told to the host is either still known or was closed by the host; a FATAL event only after the
 * random source failed; with a good world at the end (no flips, no cuts, random ok) the engine reaches ACTIVE
 * again; after destroy the arena part in use is all zero.
 *
 * Memory properties (the budget rules of docs/design/core-architecture.md section 5): both regions are filled with a
 * pattern and surrounded by guard bands, and the host hands the engine more bytes than wr_client_mem_required asks
 * for; at the end nothing outside the first `arena_used` / `bulk_used` bytes was written (so no write outside the
 * arena, none into the spare tail, none into the guards), `arena_used` / `bulk_used` equal what mem_required announced
 * (the arena high-water cannot exceed the budget because nothing is taken after create), and for the ipxe and kernel
 * profiles the announced sizes are within the documented budgets. The engine allocates nothing else: the core has no
 * allocator to call (the core_no_libc check proves it), so there is nothing else to leak.
 *
 * Determinism property (no read of uninitialised memory): every input is played TWICE, once with the two regions
 * pre-filled with one byte pattern and once with another, and a digest of everything the host can observe (the bytes the
 * engine transmits, every event, action and map message, the state after each pump) must be identical. A decision taken
 * on a byte the engine never wrote would make the two runs diverge. Memory the engine really needs zeroed it zeroes
 * itself; the harness never hands it calloc'ed memory.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sim_mon_tc.h"
#include "wri_client.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAX_INPUT 4096u
#define MAX_OPS 160u
#define MAXH 6u
#define TICK_MS 50u
#define SETTLE_ROUNDS 5000u
#define GUARD 64u      /* guard band before each region */
#define SPARE 128u     /* bytes handed to create beyond what mem_required asks for */
#define PAT_A 0xA5u    /* the two fill patterns of the two runs of one input */
#define PAT_B 0x3Cu

/* The documented budgets of the profiles (core/src/client/wr_config.c, architecture section 5.2). */
#define BUDGET_IPXE_ARENA (128u * 1024u)
#define BUDGET_IPXE_BULK (1024u * 1024u + 16u * 1024u)
#define BUDGET_KERNEL_ARENA (512u * 1024u)
#define BUDGET_KERNEL_BULK (8u * 1024u * 1024u + 32u * 1024u)

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

static void dig(uint64_t *d, const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		*d = (*d ^ b[i]) * 0x100000001b3ull;
}

static void dig_u64(uint64_t *d, uint64_t v)
{
	uint8_t b[8];
	unsigned i;

	for (i = 0; i < 8u; i++)
		b[i] = (uint8_t)(v >> (8u * i));
	dig(d, b, sizeof(b));
}

typedef struct hconn {
	int used, connected, closing;
	wr_conn_id id;
	sim_mon_conn *sc;
	uint64_t rx_total;
	uint8_t stash[512];
	size_t stash_len;
	uint8_t inj[512]; /* bytes the fuzzer wants delivered next (op 10) */
	size_t inj_len;
} hconn;

typedef struct fz {
	wr_config cfg;
	wr_host_ops ops;
	wr_cluster_spec spec;
	sim_mon_cfg scfg;
	sim_mon *sim;
	uint8_t *arena_raw, *bulk_raw, *arena, *bulk;
	size_t arena_size, bulk_size;       /* what wr_client_mem_required announced */
	size_t arena_total, bulk_total;     /* bytes of the raw allocations (guards, region, spare tail) */
	int prof;
	uint8_t pat;       /* the fill pattern of this run */
	uint64_t digest;   /* FNV-1a over everything the host can observe */
	wr_client *c;
	hconn hc[MAXH];
	uint64_t now, rng;
	uint32_t budget;
	int push_mode, hold_maps, rng_fail, rng_failed_ever, any_flip, any_cut, saw_fatal;
	size_t tx_limit;
	unsigned slow_rounds;
	uint64_t flip_at;
	uint8_t flip_mask;
	int flip_armed;
} fz;

static wr_status h_random(void *ctx, uint8_t *out, size_t n)
{
	fz *f = (fz *)ctx;
	size_t i;

	if (f->rng_fail) {
		f->rng_failed_ever = 1;
		return WR_E_HOST_RANDOM;
	}
	for (i = 0; i < n; i++) {
		f->rng ^= f->rng >> 12;
		f->rng ^= f->rng << 25;
		f->rng ^= f->rng >> 27;
		out[i] = (uint8_t)((f->rng * 0x2545f4914f6cdd1dull) >> 56);
	}
	return WR_OK;
}

static hconn *hc_find(fz *f, wr_conn_id id)
{
	unsigned i;

	for (i = 0; i < MAXH; i++)
		if (f->hc[i].used && f->hc[i].id == id)
			return &f->hc[i];
	return NULL;
}

static hconn *hc_newest(fz *f)
{
	hconn *best = NULL;
	unsigned i;

	for (i = 0; i < MAXH; i++)
		if (f->hc[i].used && f->hc[i].connected && (best == NULL || f->hc[i].id > best->id))
			best = &f->hc[i];
	return best;
}

static void hc_end(fz *f, hconn *hc, int err)
{
	if (hc->sc != NULL)
		sim_mon_conn_free(hc->sc);
	hc->sc = NULL;
	wr_conn_closed(f->c, hc->id, err);
	hc->used = 0;
}

static void drain_events(fz *f)
{
	wr_event e;

	while (wr_client_next_event(f->c, &e)) {
		check(e.kind >= WR_EV_MON_SESSION_UP && e.kind <= WR_EV_FATAL);
		dig_u64(&f->digest, (uint64_t)e.kind);
		dig_u64(&f->digest, (uint64_t)e.epoch);
		dig_u64(&f->digest, (uint64_t)e.err.status);
		if (e.kind == WR_EV_FATAL) {
			check(f->rng_failed_ever); /* FATAL only follows a dead random source */
			f->saw_fatal = 1;
		}
	}
	if (f->hold_maps)
		return;
	for (;;) {
		wr_mapmsg m;

		if (!wr_client_mapmsg_peek(f->c, &m))
			break;
		check(m.front != NULL && m.front_len != 0 && (m.kind == WR_MAPMSG_MONMAP || m.kind == WR_MAPMSG_OSDMAP));
		dig_u64(&f->digest, (uint64_t)m.kind);
		dig_u64(&f->digest, (uint64_t)m.front_len);
		dig(&f->digest, m.front, m.front_len);
		wr_client_mapmsg_release(f->c);
	}
}

static unsigned do_actions(fz *f)
{
	wr_action a;
	unsigned n = 0, i;

	while (wr_client_next_action(f->c, &a)) {
		hconn *hc;

		n++;
		dig_u64(&f->digest, (uint64_t)a.kind);
		dig_u64(&f->digest, (uint64_t)a.conn);
		switch (a.kind) {
		case WR_ACT_CONNECT:
			check(hc_find(f, a.conn) == NULL);
			for (i = 0; i < MAXH && f->hc[i].used; i++) {
			}
			check(i < MAXH); /* the engine never has more connections than the host table (max_conns <= MAXH) */
			memset(&f->hc[i], 0, sizeof(f->hc[i]));
			f->hc[i].used = 1;
			f->hc[i].id = a.conn;
			break;
		case WR_ACT_CLOSE:
			hc = hc_find(f, a.conn);
			check(hc != NULL);
			hc->closing = 1;
			break;
		case WR_ACT_TX_READY:
			hc = hc_find(f, a.conn);
			check(hc != NULL && hc->connected);
			break;
		default:
			check(0);
			break;
		}
	}
	return n;
}

static int hc_tx(fz *f, hconn *hc)
{
	wr_iov iov[8];
	size_t n = wr_conn_tx_peek(f->c, hc->id, iov, 8), i, sent = 0, room = f->slow_rounds ? f->tx_limit : (size_t)-1;

	for (i = 0; i < n && room > 0; i++) {
		size_t take = iov[i].len < room ? iov[i].len : room;

		dig(&f->digest, iov[i].base, take);
		(void)sim_mon_feed(hc->sc, iov[i].base, take);
		sent += take;
		room -= take;
	}
	if (sent == 0)
		return 0;
	wr_conn_tx_consume(f->c, hc->id, sent);
	return 1;
}

/* Apply the armed flip to bytes about to be delivered (stream offsets rx_total .. rx_total + n). */
static void maybe_flip(fz *f, hconn *hc, uint8_t *p, size_t n)
{
	if (f->flip_armed && hc == hc_newest(f) && f->flip_at >= hc->rx_total && f->flip_at < hc->rx_total + n) {
		p[f->flip_at - hc->rx_total] ^= f->flip_mask;
		f->flip_armed = 0;
		f->any_flip = 1;
	}
}

static int hc_rx(fz *f, hconn *hc)
{
	uint8_t *w = NULL;
	size_t room, n;

	if (f->push_mode) {
		if (hc->stash_len == 0 && hc->inj_len != 0) {
			memcpy(hc->stash, hc->inj, hc->inj_len);
			hc->stash_len = hc->inj_len;
			hc->inj_len = 0;
		} else if (hc->stash_len == 0) {
			hc->stash_len = sim_mon_drain(hc->sc, hc->stash, sizeof(hc->stash));
			maybe_flip(f, hc, hc->stash, hc->stash_len);
		}
		if (hc->stash_len != 0) {
			size_t taken = wr_conn_rx_push(f->c, hc->id, hc->stash, hc->stash_len);

			check(taken <= hc->stash_len); /* the engine cannot take more than it was offered */
			dig_u64(&f->digest, (uint64_t)taken);
			memmove(hc->stash, hc->stash + taken, hc->stash_len - taken);
			hc->stash_len -= taken;
			hc->rx_total += taken;
			return taken != 0;
		}
		return 0;
	}
	room = wr_conn_rx_window(f->c, hc->id, &w);
	dig_u64(&f->digest, (uint64_t)room);
	if (room == 0)
		return 0;
	check(w != NULL);
	if (hc->inj_len != 0) {
		n = hc->inj_len < room ? hc->inj_len : room;
		memcpy(w, hc->inj, n);
		memmove(hc->inj, hc->inj + n, hc->inj_len - n);
		hc->inj_len -= n;
		hc->rx_total += n;
		wr_conn_rx_commit(f->c, hc->id, n);
		return 1;
	}
	n = sim_mon_drain(hc->sc, w, room);
	if (n == 0)
		return 0;
	maybe_flip(f, hc, w, n);
	hc->rx_total += n;
	wr_conn_rx_commit(f->c, hc->id, n);
	return 1;
}

static int do_io(fz *f)
{
	unsigned i;
	int progress = 0;

	for (i = 0; i < MAXH; i++) {
		hconn *hc = &f->hc[i];

		if (!hc->used)
			continue;
		if (hc->closing) {
			hc_end(f, hc, 0);
			progress = 1;
			continue;
		}
		if (!hc->connected) {
			hc->sc = sim_mon_accept(f->sim);
			if (hc->sc == NULL) { /* the simulator is full of live connections: the host connect fails */
				hc_end(f, hc, 111);
				progress = 1;
				continue;
			}
			wr_conn_connected(f->c, hc->id);
			hc->connected = 1;
			progress = 1;
		}
		if (hc_tx(f, hc))
			progress = 1;
		if (hc_rx(f, hc))
			progress = 1;
		if (hc->sc != NULL && sim_mon_closed(hc->sc) && hc->stash_len == 0 && hc->inj_len == 0) {
			hc_end(f, hc, 0);
			progress = 1;
		}
	}
	return progress;
}

static void check_pools(fz *f)
{
	wr_stats st;
	unsigned i, live = 0;

	wr_client_get_stats(f->c, &st);
	check(st.conns_in_use <= f->cfg.max_conns && st.handshakes_in_use <= f->cfg.max_handshakes);
	check(st.handshakes_in_use <= st.conns_in_use);
	check(st.conns_hiwater <= f->cfg.max_conns && st.handshakes_hiwater <= f->cfg.max_handshakes);
	for (i = 0; i < MAXH; i++) {
		if (!f->hc[i].used)
			continue;
		live++;
		check(wri_client_slot_of(f->c, f->hc[i].id) != NULL); /* a connection the host holds is one the engine knows */
	}
	check(live <= st.conns_in_use);
}

static void pump(fz *f)
{
	unsigned guard;

	for (guard = 0; guard < SETTLE_ROUNDS; guard++) {
		wr_clock clk;
		unsigned acts;
		int io;
		wr_run_result r;

		clk.mono_ms = f->now;
		clk.wall_ms = 1700000000000ull + f->now;
		r = wr_client_run(f->c, &clk, f->budget);
		drain_events(f);
		acts = do_actions(f);
		io = do_io(f);
		drain_events(f);
		if (f->slow_rounds != 0u && guard % 8u == 7u)
			f->slow_rounds--;
		check_pools(f);
		dig_u64(&f->digest, (uint64_t)wr_client_get_state(f->c));
		dig_u64(&f->digest, (uint64_t)r.more_work);
		if (acts == 0 && !io && !r.more_work)
			return;
	}
	check(0); /* the engine does not settle at one instant */
}

static void tick(fz *f, unsigned n)
{
	unsigned i;

	pump(f);
	for (i = 0; i < n; i++) {
		f->now += TICK_MS;
		pump(f);
	}
}

static void abuse(fz *f, uint8_t sel, uint8_t arg)
{
	hconn *hc = hc_newest(f);
	wr_conn_id id = hc != NULL ? hc->id : (wr_conn_id)arg;
	uint8_t junk[24], *w = NULL;
	wr_iov iov[4];
	size_t room;
	unsigned i;

	for (i = 0; i < sizeof(junk); i++)
		junk[i] = (uint8_t)(arg * 31u + i);
	switch (sel % 10u) {
	case 0:
		wr_conn_rx_commit(f->c, id, (size_t)-1);
		break;
	case 1:
		room = wr_conn_rx_window(f->c, id, &w);
		wr_conn_rx_commit(f->c, id, room + 1u + arg);
		break;
	case 2:
		wr_conn_tx_consume(f->c, id, (size_t)-1);
		break;
	case 3:
		(void)wr_conn_rx_push(f->c, id, junk, sizeof(junk));
		break;
	case 4:
		wr_conn_connected(f->c, id);
		break;
	case 5:
		(void)wr_conn_tx_peek(f->c, id, iov, 1u + arg % 4u);
		break;
	case 6:
		wr_conn_closed(f->c, (wr_conn_id)(arg * 0x01010101u) | 0x80000000u, 3); /* nobody's id */
		break;
	case 7:
		wr_conn_rx_commit(f->c, (wr_conn_id)arg << 16, 9);
		wr_conn_tx_consume(f->c, (wr_conn_id)arg, 9);
		break;
	case 8:
		(void)wr_conn_rx_window(f->c, id ^ 0x10000u, &w); /* the generation of another connection */
		break;
	default:
		(void)wr_client_next_event(f->c, NULL);
		(void)wr_client_mapmsg_peek(f->c, NULL);
		wr_client_get_stats(f->c, NULL);
		break;
	}
}

static void fz_setup(fz *f, uint8_t b0, uint8_t pat)
{
	wr_mem_req req;
	unsigned type = (b0 & 1u) ? WR_KEY_TYPE_AES256K : WR_KEY_TYPE_AES, prof = (b0 >> 1) & 3u;
	uintptr_t p;

	memset(f, 0, sizeof(*f));
	f->pat = pat;
	f->digest = 0xcbf29ce484222325ull;
	switch (prof) {
	case 1:
		wr_config_profile_ipxe(&f->cfg);
		break;
	case 2:
		wr_config_profile_kernel(&f->cfg);
		f->cfg.max_conns = 4; /* the host table is small: fewer slots keep the fuzzer fast */
		break;
	default:
		wr_config_profile_harness(&f->cfg);
		f->cfg.mon_msg_cap = 256u * 1024u;
		f->cfg.max_conns = 4;
		f->cfg.max_handshakes = 2;
		if (prof == 3u)
			f->cfg.rx_buf_bytes = 64;
		break;
	}
	f->push_mode = (b0 >> 3) & 1u;
	f->budget = (b0 >> 4) == 0u ? 0u : (uint32_t)64u << ((b0 >> 4) & 7u);
	f->now = 10000;
	f->rng = 0xfeedfacecafebeefull;
	f->tx_limit = 16;
	f->ops.size = (uint32_t)sizeof(f->ops);
	f->ops.ctx = f;
	f->ops.random = h_random;

	mt_cfg(&f->scfg, type);
	f->sim = sim_mon_new(&f->scfg);
	check(f->sim != NULL);
	strcpy(f->spec.user, "client.winrbd");
	f->spec.key = f->scfg.key;
	f->spec.n_mons = 1;
	f->spec.mons[0].family = WR_AF_IPV4;
	f->spec.mons[0].ip[0] = 10, f->spec.mons[0].ip[1] = 77, f->spec.mons[0].ip[3] = 10;
	f->spec.mons[0].port = 3300;

	check(wr_client_mem_required(&f->cfg, &req) == WR_OK);
	f->prof = (int)prof;
	if (prof == 1u)
		check(req.arena <= BUDGET_IPXE_ARENA && req.bulk <= BUDGET_IPXE_BULK);
	f->arena_size = req.arena;
	f->bulk_size = req.bulk;
	f->arena_total = req.arena + SPARE + 2u * GUARD + 64u;
	f->bulk_total = req.bulk + SPARE + 2u * GUARD + 64u;
	f->arena_raw = (uint8_t *)malloc(f->arena_total);
	f->bulk_raw = (uint8_t *)malloc(f->bulk_total);
	check(f->arena_raw != NULL && f->bulk_raw != NULL);
	memset(f->arena_raw, f->pat, f->arena_total); /* the engine must not rely on zeroed memory, nor touch the rest */
	memset(f->bulk_raw, f->pat, f->bulk_total);
	p = ((uintptr_t)f->arena_raw + GUARD + 63u) & ~(uintptr_t)63u;
	f->arena = (uint8_t *)p;
	p = ((uintptr_t)f->bulk_raw + GUARD + 63u) & ~(uintptr_t)63u;
	f->bulk = (uint8_t *)p;
	check(wr_client_create(&f->cfg, &f->ops, &f->spec, (wr_mem_region){f->arena, f->arena_size + SPARE},
			       (wr_mem_region){f->bulk, f->bulk_size + SPARE}, &f->c) == WR_OK);
	check(f->c != NULL);
}

/* Every byte of raw[0 .. base) and of [base + used, raw + total) still holds the fill pattern. */
static int outside_untouched(const uint8_t *raw, const uint8_t *base, size_t used, size_t total, uint8_t pat)
{
	size_t i, front = (size_t)(base - raw);

	for (i = 0; i < front; i++)
		if (raw[i] != pat)
			return 0;
	for (i = front + used; i < total; i++)
		if (raw[i] != pat)
			return 0;
	return 1;
}

static void fz_end(fz *f)
{
	wr_stats st;
	size_t i;
	unsigned k;

	wr_client_get_stats(f->c, &st);
	/* the footprint is fixed at create: what the engine took is exactly what it announced, so it is within the budget */
	check(st.arena_used == f->arena_size && st.bulk_used == f->bulk_size);
	if (f->prof == 2) {
		check(st.arena_used <= BUDGET_KERNEL_ARENA && st.bulk_used <= BUDGET_KERNEL_BULK);
	}
	check(st.conns_hiwater <= f->cfg.max_conns && st.handshakes_hiwater <= f->cfg.max_handshakes);
	check(st.mapmsg_hiwater <= f->cfg.mapmsg_queue);
	wr_client_destroy(f->c);
	for (i = 0; i < st.arena_used; i++)
		check(f->arena[i] == 0);
	check(outside_untouched(f->arena_raw, f->arena, st.arena_used, f->arena_total, f->pat));
	check(outside_untouched(f->bulk_raw, f->bulk, st.bulk_used, f->bulk_total, f->pat));
	for (k = 0; k < MAXH; k++)
		if (f->hc[k].used && f->hc[k].sc != NULL)
			sim_mon_conn_free(f->hc[k].sc);
	sim_mon_free(f->sim);
	free(f->arena_raw);
	free(f->bulk_raw);
}

/* Play one input from a region fill pattern; the result is the digest of everything the host observed. */
static uint64_t run_script(const uint8_t *data, size_t size, uint8_t pat)
{
	fz *f;
	uint64_t digest;
	size_t pos = 1;
	unsigned ops = 0;

	f = (fz *)calloc(1, sizeof(*f));
	check(f != NULL);
	fz_setup(f, data[0], pat);
	tick(f, 4);
	while (pos < size && ops++ < MAX_OPS) {
		uint8_t op = data[pos++] % 11u, a = pos < size ? data[pos] : 0, b = pos + 1u < size ? data[pos + 1u] : 0;
		hconn *hc;

		switch (op) {
		case 0:
			pos += pos < size;
			tick(f, a % 40u + 1u);
			break;
		case 1:
			pos += 2u;
			hc = hc_newest(f);
			if (hc != NULL) {
				f->flip_armed = 1;
				f->flip_at = hc->rx_total + (uint64_t)a * 37u;
				f->flip_mask = b != 0u ? b : 1u;
			}
			break;
		case 2:
			hc = hc_newest(f);
			if (hc != NULL) {
				hc_end(f, hc, 104);
				f->any_cut = 1;
			}
			break;
		case 3:
			sim_mon_restart(f->sim);
			break;
		case 4: {
			wr_clock clk;

			clk.mono_ms = f->now > 3000u ? f->now - 3000u : 0;
			clk.wall_ms = 0;
			(void)wr_client_run(f->c, &clk, 64u);
			break;
		}
		case 5:
			pos += 2u;
			abuse(f, a, b);
			break;
		case 6:
			f->hold_maps = !f->hold_maps;
			break;
		case 7:
			f->rng_fail = !f->rng_fail;
			break;
		case 9: { /* the monitor sends a well-framed message with fuzzed content */
			static const uint16_t types[8] = {4u, 41u, 18u, 15u, 22u, 1u, 0u, 0xffffu};
			size_t flen = 0, avail;
			uint16_t ver = (uint16_t)(b & 15u), compat = (uint16_t)(b >> 4);

			pos += 2u;
			if (pos + 1u < size)
				flen = (size_t)data[pos] | ((size_t)data[pos + 1u] << 8);
			pos += 2u;
			avail = pos < size ? size - pos : 0u;
			if (flen > avail)
				flen = avail;
			hc = hc_newest(f);
			if (hc != NULL && hc->sc != NULL)
				(void)sim_mon_send_message(hc->sc, types[a % 8u], ver, compat, data + pos, (uint32_t)flen);
			pos += flen;
			break;
		}
		case 10: { /* the monitor's byte stream is replaced for the next bytes */
			size_t n = 0, avail;

			pos += 1u;
			if (pos < size)
				n = data[pos];
			pos += 1u;
			avail = pos < size ? size - pos : 0u;
			if (n > avail)
				n = avail;
			hc = hc_newest(f);
			if (hc != NULL && hc->inj_len + n <= sizeof(hc->inj)) {
				memcpy(hc->inj + hc->inj_len, data + pos, n);
				hc->inj_len += n;
			}
			pos += n;
			break;
		}
		default:
			pos += pos < size;
			f->tx_limit = (size_t)(a % 64u) + 1u;
			f->slow_rounds = 40;
			break;
		}
		check_pools(f);
	}
	/* a good world again: the engine must find its way back to a monitor session unless it died of the random source */
	f->hold_maps = 0;
	f->rng_fail = 0;
	f->flip_armed = 0;
	f->slow_rounds = 0;
	if (!f->saw_fatal) {
		unsigned i;

		for (i = 0; i < 4000u && wr_client_get_state(f->c) != WR_CS_ACTIVE; i++) { /* up to 200 s of virtual time */
			f->now += TICK_MS;
			pump(f);
		}
		check(wr_client_get_state(f->c) == WR_CS_ACTIVE);
	} else {
		check(wr_client_get_state(f->c) == WR_CS_FAILED);
	}
	dig_u64(&f->digest, (uint64_t)f->arena_size);
	dig_u64(&f->digest, (uint64_t)f->bulk_size);
	fz_end(f);
	digest = f->digest;
	free(f);
	return digest;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1u || size > MAX_INPUT)
		return 0;
	/* the same script over two different fill patterns must look identical from the host's side */
	check(run_script(data, size, PAT_A) == run_script(data, size, PAT_B));
	return 0;
}
