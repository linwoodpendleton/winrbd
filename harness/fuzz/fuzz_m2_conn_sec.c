/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the msgr2 connection in secure mode (core/src/msgr2/wri_m2_conn*.c with a secure slot): a WHOLE secure connection against the
 * secure peer of sim_m2.h, driven by the input. The simulator's codec is independent of the core's, so the fuzzer reaches the code behind the tag
 * check with frames that are authentic, well framed and wrong in exactly one chosen way, and every defect it puts in is a defect the connection
 * must catch (or, for padding, ignore).
 *
 * Input layout (a byte past the end reads as 0):
 *   byte 0   bits 0-2 policy (1..5, mod 5), bit 3 the peer is a monitor, bits 4-5 the server's allowed modes (crc / secure / both / secure first),
 *            bit 6 no secure slot (a connection of parts A to C), bit 7 the handshake is left to the script (no pump after start)
 *   byte 1   bits 0-1 bounce buffer (256, 272, 1024, 4096), bits 2-3 receive chunking (all, 1, 7, 1..300), bits 4-5 transmit chunking
 *            (all, 1, 5, 1000), bit 6 the upper layer's plan() answers WR_E_BUSY a few times first, bit 7 it discards every message
 *   byte 2   the defect the server puts into one of its secure frames (the low 5 bits): 0 none, 1 flipped bit in part 1, 2 tag of part 1 over other data,
 *            3 wrong key, 4 nonce of part 1 off by one, 5 preamble CRC, 6 compressed flag, 7 reserved byte, 8 segment count, 9 frame tag, 10 lying
 *            lengths, 11 junk in an unused slot, 12 empty last segment, 13 epilogue status, 14 padding garbage, 15 cut frame, 16 flipped bit anywhere,
 *            17 tag of any part over other data, 18 nonce of any part off by one (19 to 31: none)
 *   byte 3   which server frame (the handshake's frames are 3 to 5, the session's follow)
 *   bytes 4, 5   the parameters of the defect (part, byte, bit, length ...)
 *   byte 6   hooks of the server: bit 0 wrong signature, 1 sends with the wrong seed, 2 wrong key, 3 reads with the wrong seed, 4 no secret,
 *            5 a 39-byte secret, 6 / 7 the nonce counters start a few operations below 2^64 (receive / transmit)
 *   byte 7   bit 0 a tiny segment cap (the connection must refuse a big frame), bits 1-2 the encode buffer (2048, 4096, 8192, 4096), bit 3 the host
 *            provides the GCM (a table that is the portable one underneath and can be told to refuse the Nth transmit operation, see the action below)
 *   rest     a script of actions, one byte each (high nibble the action, low nibble its argument) with parameter bytes behind it:
 *            client message, client keepalive, server message, server keepalive, server ACK, pump, lower the operation limit, close,
 *            the transport reports EOF, time passes, a defect for the NEXT server frame, host chunking changes, the host GCM refuses a coming transmit operation
 *
 * Properties (a violated one traps):
 *   - no crash, no undefined behaviour, no write outside a sink (ASan; the sinks of the rig are exact-size heap blocks);
 *   - once a connection ended (failed or closed): up->closed was called exactly once, the first cause is kept, nothing is written after it, the
 *     codec seam is back to crc, the secure slot and the bounce buffer are all zero, the auth layer holds no secret, there is no window and nothing to
 *     transmit; a live connection never reported a close;
 *   - a message delivered to the upper layer is byte for byte one the server sent (never a corrupted one), in strictly increasing sequence;
 *   - what the server decoded from us is exactly the prefix of what we sent, in order (its decoder verifies every tag in the nonce order of the notes);
 *   - a connection that is still alive has its transmit key: a send that lost it (the host refused an operation after the nonces were taken) ended
 *     the connection, it did not leave it READY with a transmit side that can never send again;
 *   - a server frame with a defect the tag catches (kinds 1 to 4: a bit of part 1 flipped, its tag over other data, a wrong key, its nonce off by one;
 *     they apply to every frame there is), received in full, never leaves the connection READY;
 *   - the operation limit holds: after the script lowers it, neither direction of a live secure connection takes a nonce past what the limit allowed it
 *     (a count already above the new limit stays where it is; the limit only refuses the next take, it never lets one through);
 *   - a server secret shorter than the 40 bytes a key and two nonce seeds need (hook 5) never switches the connection to secure mode;
 *   - when the host provides the GCM, every key object it made has been handed back to it (wiped) by the time the connection has ended, whatever ended it;
 *   - without any defect, hook, limit, close or time step the connection comes up when the modes allow and every message arrives, both ways.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test/m2_conn_rig.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAX_INPUT 20000u
#define MAX_ACTIONS 60u
#define MAX_REC 64u

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

/* A status the script does not care about (the call may be refused: the connection is not READY, a stream drains, ...): the explicit sink that a
 * must-check attribute accepts. */
static void ignore_status(wr_status st)
{
	(void)st;
}

typedef struct rec {
	uint64_t tid;
	uint32_t fl, ml, dl;
	uint8_t seed;
} rec;

typedef struct fzs {
	rig *r;
	const uint8_t *in;
	size_t n, pos;
	rec cli[MAX_REC], srv[MAX_REC];
	unsigned n_cli, n_srv;
	uint8_t *keep[2u * MAX_ACTIONS]; /* buffers handed to the connection by reference: they live until the end (two per client message, one message per action at most) */
	unsigned n_keep;
	int ended, mut_a, any_fault, failed_seen;
	int desync;  /* a frame that announces another layout than the sealed one (defects 8, 10, 15) was armed: later frames may be swallowed as the body of that frame */
	int len_lie; /* a frame whose announced segment lengths differ from the ones the server sealed was sent (defect 10) */
	uint32_t mut_a_frame;
	wr_status first_err;
	size_t sent_at_end;
	uint64_t tid;
	hostg hg;          /* the host GCM of the connection when byte 7 asks for one */
	wr_prim_ops hprim;
	int use_host;
	int short_secret;  /* the server issues a secret below the 40 bytes a key and two nonce seeds need (hook 5): the connection must never go secure */
	int limit_set;     /* the script lowered the operation limit of the live key: neither direction may go past what the limit allowed it from then on */
	uint64_t cap_tx, cap_rx;
} fzs;

static uint8_t rd8(fzs *z)
{
	return z->pos < z->n ? z->in[z->pos++] : 0;
}

static void pat(uint8_t *p, size_t n, uint8_t seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed + i * 7u);
}

static void invariants(fzs *z)
{
	rig *r = z->r;
	wri_m2_conn *c = &r->c;
	wr_iov iov[WRI_M2_TXQ_IOV];
	uint8_t *w;
	size_t i;
	uint64_t last = 0;

	check(c->ring.len <= c->ring.cap);
	if (c->state == WRI_M2_FAILED && !c->close_reported) { /* a failure found inside a send call: wanting its step, wiped already; the report follows */
		check(r->up.n_closed == 0 && wri_m2_conn_deadline(c) == 0 && c->sec == NULL && c->rx.sx == NULL && c->tx.sx == NULL);
		check(r->slot == NULL || rig_slot_zero(r));
		(void)wri_m2_conn_step(&r->x, c, NULL);
		check(r->up.n_closed == 1);
	}
	if (c->state == WRI_M2_FAILED || c->state == WRI_M2_CLOSING || c->state == WRI_M2_FREE) {
		check(r->up.n_closed == 1);
		check(c->pa == NULL);
		check(c->sec == NULL && c->rx.sx == NULL && c->tx.sx == NULL);
		if (r->slot != NULL) {
			check(rig_slot_zero(r));
			check(r->au.hand_len == 0);
		}
		check(wri_m2_conn_tx_peek(c, iov, WRI_M2_TXQ_IOV) == 0);
		check(wri_m2_conn_rx_window(c, &w) == 0);
		check(c->tx.pending == 0);
		if (!z->ended) {
			z->ended = 1;
			z->first_err = r->up.closed_err.status;
			z->sent_at_end = r->sent_len;
		}
		check(!z->short_secret || (c->tx.sx == NULL && c->rx.sx == NULL));
		if (z->use_host) /* every key object the host made was handed back to it (wiped), whatever ended the connection */
			check(z->hg.wipes >= z->hg.n_keyed);
		check(r->up.closed_err.status == z->first_err); /* the first cause is the one reported (and the only report) */
		check(r->sent_len == z->sent_at_end);            /* nothing is written after the end */
	} else {
		check(r->up.n_closed == 0);
		check(!(z->short_secret && (c->tx.sx != NULL || c->rx.sx != NULL))); /* a secret that is too short for the key and the seeds is never switched on */
		if (c->tx.sx != NULL) {
			check(r->slot != NULL && c->tx.sx == &r->slot->tx && c->rx.sx == &r->slot->rx);
			check(r->slot->s.active == 1);
			check(r->slot->s.tx.keyed == 1u && r->slot->s.rx.keyed == 1u); /* a live secure connection can still send (and receive) */
			if (z->limit_set) /* the operation limit holds: a direction that reached it takes no further nonce (not a byte on the wire under a counter past it) */
				check(r->slot->s.tx_n.ops <= z->cap_tx && r->slot->s.rx_n.ops <= z->cap_rx);
		}
	}
	for (i = 0; i < r->up.n_msgs; i++) { /* delivered sequence numbers strictly increase */
		check(r->up.msgs[i].hdr.seq > last);
		last = r->up.msgs[i].hdr.seq;
	}
}

static void step_pump(fzs *z)
{
	rig_pump(z->r);
	invariants(z);
}

static int mut_class_a(unsigned kind)
{
	return kind >= 1 && kind <= 4;
}

/* The defect of kind `kind` with parameters a and b. Kinds 1 to 4 name part 1 and its first 80 bytes only: every secure frame has them, so the
 * defect certainly applies to the frame it is armed for (the property "never READY" relies on it). */
static void make_mut(sim_sec_mut *m, unsigned kind, uint8_t a, uint8_t b)
{
	memset(m, 0, sizeof(*m));
	switch (kind) {
	case 1:
		m->mask = SIM_SEC_M_FLIP;
		m->flip_part = 1;
		m->flip_region = (uint8_t)(b & 1u); /* the ciphertext or the tag */
		m->flip_byte = m->flip_region == SIM_SEC_R_RAW ? (uint32_t)(a % 80u) : (uint32_t)(a % 16u);
		m->flip_bit = (uint8_t)((b >> 1) & 7u);
		break;
	case 2:
		m->mask = SIM_SEC_M_TAG;
		m->tag_part = 1;
		break;
	case 3:
		m->mask = SIM_SEC_M_KEY;
		break;
	case 4:
		m->mask = SIM_SEC_M_NONCE;
		m->nonce_part = 1;
		m->nonce_delta = (b & 1u) ? 1 : -1;
		break;
	case 5:
		m->mask = SIM_SEC_M_PRE_CRC;
		m->pre_crc_xor = a;
		break;
	case 6:
		m->mask = SIM_SEC_M_FLAGS;
		m->pre_flags = (uint8_t)(a | 1u);
		break;
	case 7:
		m->mask = SIM_SEC_M_RESERVED;
		m->pre_reserved = (uint8_t)(a | 1u);
		break;
	case 8:
		m->mask = SIM_SEC_M_PRE_NSEG;
		m->pre_nseg = (uint8_t)(a % 8u);
		break;
	case 9:
		m->mask = SIM_SEC_M_PRE_TAG;
		m->pre_tag = a;
		break;
	case 10:
		m->mask = SIM_SEC_M_PRE_LEN;
		m->pre_len_mask = (uint8_t)(a & 15u);
		m->pre_len[0] = (uint32_t)b << (a >> 4);
		m->pre_len[1] = (uint32_t)b << ((a >> 4) + 1u);
		m->pre_len[2] = (uint32_t)b * 3u;
		m->pre_len[3] = (uint32_t)b << 12;
		break;
	case 11:
		m->mask = SIM_SEC_M_SLOT;
		m->slot_junk = (uint8_t)(a | 1u);
		break;
	case 12:
		m->mask = SIM_SEC_M_KEEP_TAIL;
		break;
	case 13:
		m->mask = SIM_SEC_M_LATE;
		m->late_status = a;
		break;
	case 14:
		m->mask = SIM_SEC_M_PAD;
		m->pad_fill = a;
		break;
	case 15:
		m->mask = SIM_SEC_M_TRUNC;
		m->truncate_at = (uint32_t)a | ((uint32_t)b << 8);
		break;
	case 16: /* a bit anywhere: a part the frame may not have makes the simulator refuse the frame, which is then not sent */
		m->mask = SIM_SEC_M_FLIP;
		m->flip_part = (uint8_t)(1u + a % 3u);
		m->flip_region = (uint8_t)(b % 3u);
		m->flip_byte = (uint32_t)(a >> 2) * 5u + (uint32_t)(b >> 4);
		m->flip_bit = (uint8_t)(b & 7u);
		break;
	case 17:
		m->mask = SIM_SEC_M_TAG;
		m->tag_part = (uint8_t)(1u + a % 3u);
		break;
	case 18:
		m->mask = SIM_SEC_M_NONCE;
		m->nonce_part = (uint8_t)(1u + a % 3u);
		m->nonce_delta = (b & 1u) ? 1 : -1;
		break;
	default:
		break;
	}
}

static void do_client_message(fzs *z, uint8_t a)
{
	uint32_t fl = rd8(z), dl = (uint32_t)rd8(z) << (a & 7u);
	uint8_t seed = (uint8_t)z->n_cli;
	uint8_t *front = (uint8_t *)malloc(fl + 1u), *d = (uint8_t *)malloc(dl + 1u);
	wri_m2_msg_out m;
	wr_status st;

	pat(front, fl, seed);
	pat(d, dl, (uint8_t)(seed + 91u));
	memset(&m, 0, sizeof(m));
	m.type = 0x700;
	m.priority = 127;
	m.version = 3;
	m.compat_version = 1;
	m.tid = ++z->tid;
	m.front = fl != 0 ? front : NULL;
	m.front_len = fl;
	m.data = dl != 0 ? d : NULL;
	m.data_len = dl;
	st = wri_m2_conn_send_message(&z->r->x, &z->r->c, &m);
	if (st == WR_E_BUSY) { /* a stream is draining: the host catches up, the retry must work */
		step_pump(z);
		st = wri_m2_conn_send_message(&z->r->x, &z->r->c, &m);
	}
	check(st == WR_OK || st == WR_E_STATE || st == WR_E_BUSY || st == WR_E_TOOBIG || st == WR_E_M2_NONCE);
	if (st == WR_OK && z->n_cli < MAX_REC) {
		z->cli[z->n_cli].tid = m.tid, z->cli[z->n_cli].fl = fl, z->cli[z->n_cli].dl = dl, z->cli[z->n_cli].seed = seed;
		z->n_cli++;
	}
	/* The data segment is referenced, never copied: the buffers stay until the host consumed them, i.e. to the end of the run, whether the call
	 * succeeded or not (a stream may still be reading them; an earlier version freed them as soon as its small table was full, which the fuzzer found
	 * as a use after free in the rig's flush). One client message per action and MAX_ACTIONS actions: the table always has room. */
	check(z->n_keep + 2u <= sizeof(z->keep) / sizeof(z->keep[0]));
	z->keep[z->n_keep++] = front;
	z->keep[z->n_keep++] = d;
}

static void do_server_message(fzs *z, uint8_t a)
{
	uint32_t fl = rd8(z), ml = rd8(z) % 100u, dl = (uint32_t)rd8(z) << (a & 7u);
	uint8_t seed = (uint8_t)(z->n_srv + 5u);
	uint8_t *front = (uint8_t *)malloc(fl + 1u), *mid = (uint8_t *)malloc(ml + 1u), *d = (uint8_t *)malloc(dl + 1u);
	wr_status st;
	uint64_t tid = ++z->tid;

	pat(front, fl, seed);
	pat(mid, ml, (uint8_t)(seed + 33u));
	pat(d, dl, (uint8_t)(seed + 66u));
	st = sim_m2_send_message(z->r->s, 0x701, tid, 4, fl != 0 ? front : NULL, fl, ml != 0 ? mid : NULL, ml, dl != 0 ? d : NULL, dl);
	if (st == WR_OK && z->n_srv < MAX_REC) {
		z->srv[z->n_srv].tid = tid, z->srv[z->n_srv].fl = fl, z->srv[z->n_srv].ml = ml, z->srv[z->n_srv].dl = dl, z->srv[z->n_srv].seed = seed;
		z->n_srv++;
	}
	free(front), free(mid), free(d);
}

static void run_action(fzs *z, uint8_t b)
{
	rig *r = z->r;
	uint8_t a = (uint8_t)(b & 15u);

	switch (b >> 4) {
	case 0:
		do_client_message(z, a);
		break;
	case 1:
		ignore_status(wri_m2_conn_send_keepalive(&r->x, &r->c, rd8(z), rd8(z)));
		break;
	case 2:
		do_server_message(z, a);
		break;
	case 3:
		ignore_status(sim_m2_send_keepalive(r->s, rd8(z), rd8(z)));
		break;
	case 4: {
		uint8_t ack[8] = {1, 0, 0, 0, 0, 0, 0, 0};
		wri_m2_seg_src seg;

		seg.p = ack, seg.len = 8, seg.ref = 0;
		ignore_status(sim_m2_send_frame(r->s, WRI_M2_TAG_ACK, &seg, 1));
		break;
	}
	case 5:
		break; /* the pump below */
	case 6:
		if (r->slot != NULL && r->slot->s.active) { /* lower the operation limit of the live key */
			uint64_t base = (a & 1u) ? r->slot->s.tx_n.ops : r->slot->s.rx_n.ops;

			r->slot->s.ops_limit = base + rd8(z) % 4u;
			/* a direction already past the new limit keeps the count it has (the limit only refuses the NEXT take): the cap is the larger of the two */
			z->cap_tx = r->slot->s.tx_n.ops > r->slot->s.ops_limit ? r->slot->s.tx_n.ops : r->slot->s.ops_limit;
			z->cap_rx = r->slot->s.rx_n.ops > r->slot->s.ops_limit ? r->slot->s.rx_n.ops : r->slot->s.ops_limit;
			z->limit_set = 1;
			z->any_fault = 1;
		}
		break;
	case 7:
		wri_m2_conn_close(&r->x, &r->c, WR_E_TIMEOUT);
		z->any_fault = 1;
		break;
	case 8:
		wri_m2_conn_on_closed(&r->x, &r->c, 104);
		z->any_fault = 1;
		break;
	case 9:
		r->x.now.mono_ms += (uint64_t)rd8(z) * 100u;
		(void)wri_m2_conn_step(&r->x, &r->c, NULL);
		z->any_fault = 1;
		break;
	case 10: {
		unsigned kind = a + (rd8(z) & 1u ? 16u : 0u);
		uint8_t pa = rd8(z), pb = rd8(z);

		if (kind != 0 && kind < 19u) {
			if (z->mut_a && r->s->n_tx_frames < z->mut_a_frame)
				z->mut_a = 0; /* the earlier defect was never sent: the new one replaces it */
			make_mut(&r->s->cfg.f.sec.mut, kind, pa, pb);
			r->s->cfg.f.sec.mut_frame = r->s->n_tx_frames + 1u;
			z->any_fault = 1;
			if (kind == 10u)
				z->len_lie = 1;
			if (kind == 8u || kind == 10u || kind == 15u)
				z->desync = 1;
			if (mut_class_a(kind)) {
				z->mut_a = 1;
				z->mut_a_frame = r->s->cfg.f.sec.mut_frame;
			}
		}
		break;
	}
	case 11:
		r->tx_chunk = a % 17u;
		break;
	case 12:
		r->rx_chunk = a % 17u;
		break;
	case 13:
		if (z->use_host) { /* the host refuses a coming transmit operation (the 1st to 3rd from now) */
			z->hg.fail_enc_start = z->hg.n_enc_starts + 1u + (unsigned)(a % 3u);
			z->any_fault = 1;
		}
		break;
	default:
		break;
	}
	if ((b >> 4) != 5 || (a & 1u))
		step_pump(z);
	else
		invariants(z);
}

static void final_checks(fzs *z, int clean)
{
	rig *r = z->r;
	size_t i, k;
	uint64_t seq_ok = 0;

	/* delivered messages are the server's, byte for byte */
	for (i = 0; i < r->up.n_msgs; i++) {
		const rig_msg *g = &r->up.msgs[i];
		unsigned s;

		for (s = 0; s < z->n_srv && z->srv[s].tid != g->hdr.tid; s++)
			;
		check(s < z->n_srv);
		if (r->up.discard_all)
			continue; /* everything went to the bin: nothing stored */
		/* A defect-10 frame announces other segment lengths than the ones the server sealed. The segments are padded to their alignment (8, 8, 8,
		 * 4096), so a lie that keeps the padded layout is still a frame whose every tag verifies, with a length field the protocol has no other copy of
		 * to compare against (the message header carries no lengths): the connection delivers it, as it must, and what it holds is then the
		 * announced lengths, not the sent ones (a finding of the long fuzz run, the input is a committed seed). Every other frame must be exact. */
		if (z->len_lie && !(g->stored[0] == z->srv[s].fl && g->stored[1] == z->srv[s].ml && g->stored[2] == z->srv[s].dl))
			continue;
		check(g->stored[0] == z->srv[s].fl && g->stored[1] == z->srv[s].ml && g->stored[2] == z->srv[s].dl);
		for (k = 0; k < 3; k++) {
			uint32_t len = g->stored[k];
			uint8_t expect[1];
			uint32_t j;

			for (j = 0; j < len; j++) {
				expect[0] = (uint8_t)(z->srv[s].seed + 33u * k + j * 7u);
				check(g->seg[k][j] == expect[0]);
			}
		}
	}
	/* what the server decoded from us is a prefix of what we sent, in order */
	check(r->s->n_msgs <= z->n_cli);
	for (i = 0; i < r->s->n_msgs && i < z->n_cli; i++) {
		const sim_m2_msg *g = &r->s->msgs[i];
		uint32_t j;

		check(g->tid == z->cli[i].tid);
		check(g->seg_len[0] == z->cli[i].fl && g->seg_len[2] == z->cli[i].dl);
		for (j = 0; j < g->seg_len[0]; j++)
			check(g->seg[0][j] == (uint8_t)(z->cli[i].seed + j * 7u));
		for (j = 0; j < g->seg_len[2]; j++)
			check(g->seg[2][j] == (uint8_t)(z->cli[i].seed + 91u + j * 7u));
		seq_ok = g->seq;
		check(seq_ok == i + 1u);
	}
	/* a defect the tag catches, received in full, never leaves the connection READY. Not after a frame that announced another layout than it carries
	 * (defects 8, 10, 15): such a frame waits for the bytes it announced and swallows the frames behind it as its own body, tag defect or not, so the
	 * frame with the defect is never looked at as a frame of its own (a finding of the long fuzz run; the input is a committed seed) */
	if (z->mut_a && !z->desync && r->c.state == WRI_M2_READY && r->s->state != SIM_M2_ST_DEAD && !r->s->out_dead && sim_m2_pending(r->s) == 0 &&
	    r->c.ring.len == 0 && r->c.rx.direct == 0 && sim_m2_is_secure(r->s) && r->s->n_tx_frames >= z->mut_a_frame && z->mut_a_frame >= 4u)
		check(0);
	if (clean && r->c.state == WRI_M2_READY) { /* no defect, no hook, no limit, no close: everything arrives */
		check(r->s->n_msgs == z->n_cli);
		check(r->up.n_msgs == z->n_srv || r->up.n_msgs >= RIG_MAXMSG - 1u || r->up.discard_all);
		if (r->slot != NULL && r->c.tx.sx != NULL) {
			check(r->slot->s.tx_n.ops == r->s->sec.dec.rx->ops);
			check(r->slot->s.rx_n.ops == r->s->sec.ctx.tx.ops);
		}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint32_t bounces[4] = {256, 272, 1024, 4096};
	static const size_t rx_chunks[4] = {0, 1, 7, 0}; /* (the last one: 1..300, from a parameter byte) */
	static const size_t tx_chunks[4] = {0, 1, 5, 1000};
	static const uint8_t lists[4][2] = {{1, 0}, {2, 0}, {1, 2}, {2, 1}};
	static const uint32_t tx_caps[4] = {2048, 4096, 8192, 4096};
	rig *r;
	fzs z;
	uint8_t b0, b1, kind, mf, pa, pb, hooks, b7;
	unsigned policy, role_mon, lst, actions;
	uint8_t offer;
	size_t i;

	if (size < 8 || size > MAX_INPUT)
		return 0;
	b0 = data[0], b1 = data[1], kind = data[2] & 31u, mf = data[3], pa = data[4], pb = data[5], hooks = data[6], b7 = data[7];
	r = (rig *)malloc(sizeof(*r));
	check(r != NULL);
	memset(&z, 0, sizeof(z));
	z.r = r;
	z.in = data + 8;
	z.n = size - 8;
	policy = 1u + (b0 & 7u) % 5u;
	role_mon = (b0 >> 3) & 1u;
	lst = (b0 >> 4) & 3u;
	rig_init(r);
	r->role = role_mon ? WRI_ENTITY_MON : WRI_ENTITY_OSD;
	r->scfg.entity_type = role_mon ? SIM_M2_ENT_MON : SIM_M2_ENT_OSD;
	r->io_cap = 1u << 21;
	r->scfg.out_cap = 1u << 20;
	r->scfg.msg_bytes_cap = 1u << 20;
	r->scfg.preauth_cap = 1u << 14;
	r->scfg.seg_cap = 1u << 17;
	r->seg_cap_max = (b7 & 1u) ? 1u + (uint32_t)b7 * 16u : (1u << 17);
	r->tx_cap = tx_caps[(b7 >> 1) & 3u];
	r->bounce_cap = bounces[b1 & 3u];
	r->rx_chunk = rx_chunks[(b1 >> 2) & 3u];
	if (((b1 >> 2) & 3u) == 3u)
		r->rx_chunk = 1u + (size_t)pa % 300u;
	r->tx_chunk = tx_chunks[(b1 >> 4) & 3u];
	r->up.busy_times = ((b1 >> 6) & 1u) ? 3 : 0;
	r->up.discard_all = (b1 >> 7) & 1u;
	offer = wri_m2_offer_for((uint8_t)policy, 0, role_mon ? WRI_ENTITY_MON : WRI_ENTITY_OSD);
	if (!((b0 >> 6) & 1u))
		rig_enable_secure(r, offer);
	rig_server_modes(r, lists[lst][0], lists[lst][1]);
	if (b7 & 1u)
		z.any_fault = 1;
	/* the faults of the server */
	if (hooks & 0x01u)
		r->scfg.f.bad_signature = 1;
	if (hooks & 0x02u)
		r->scfg.f.sec.wrong_seed_tx = 1;
	if (hooks & 0x04u)
		r->scfg.f.sec.wrong_key_tx = 1;
	if (hooks & 0x08u)
		r->scfg.f.sec.wrong_seed_rx = 1;
	if (hooks & 0x10u)
		r->scfg.f.sec.omit_secret = 1;
	if (hooks & 0x20u) {
		r->scfg.f.sec.secret_len = 39;
		z.short_secret = 1;
	}
	if (hooks & 0x40u) {
		r->scfg.f.sec.has_ctr_a = 1;
		r->scfg.f.sec.ctr_a = 0u - 1u - (uint64_t)(pb & 7u);
	}
	if (hooks & 0x80u) {
		r->scfg.f.sec.has_ctr_b = 1;
		r->scfg.f.sec.ctr_b = 0u - 1u - (uint64_t)(pb >> 5);
	}
	if (hooks & 0x3fu)
		z.any_fault = 1;
	if (kind != 0 && kind < 19u && (mf & 0x80u) == 0) { /* a defect in a frame chosen up front (the rest of the defects come from the script) */
		make_mut(&r->scfg.f.sec.mut, kind, pa, pb);
		r->scfg.f.sec.mut_frame = 3u + (uint32_t)(mf % 12u);
		z.any_fault = 1;
		if (kind == 10u)
			z.len_lie = 1;
		if (kind == 8u || kind == 10u || kind == 15u)
			z.desync = 1;
		if (mut_class_a(kind)) {
			z.mut_a = 1;
			z.mut_a_frame = r->scfg.f.sec.mut_frame;
		}
	}
	if ((b7 & 0x08u) && !((b0 >> 6) & 1u)) { /* the host's GCM (only a connection that can go secure has any use for it) */
		hg_table(&z.hprim, &z.hg);
		r->x.host.prim = &z.hprim;
		z.use_host = 1;
	}
	rig_start(r);
	if (!(b0 & 0x80u))
		rig_pump(r);
	invariants(&z);
	for (actions = 0; actions < MAX_ACTIONS && z.pos < z.n; actions++)
		run_action(&z, rd8(&z));
	rig_pump(r);
	invariants(&z);
	/* time passing: the handshake deadline fires if the connection is still in it */
	r->x.now.mono_ms += 20000;
	(void)wri_m2_conn_step(&r->x, &r->c, NULL);
	invariants(&z);
	/* a connection that is still alive ends with the transport */
	final_checks(&z, !z.any_fault);
	if (r->c.state != WRI_M2_FREE && r->c.state != WRI_M2_FAILED && r->c.state != WRI_M2_CLOSING) {
		wri_m2_conn_on_closed(&r->x, &r->c, 0);
		invariants(&z);
	}
	for (i = 0; i < z.n_keep; i++)
		free(z.keep[i]);
	rig_free(r);
	free(r);
	return 0;
}
