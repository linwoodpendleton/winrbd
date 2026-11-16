/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the monitor client's session machine (core/src/mon/wri_mon*.c): arbitrary monitor
 * message fronts delivered through the upper-layer callbacks of a session that is brought to SYNC /
 * ACTIVE first, mixed with the events a connection and a consumer produce. The machine runs against a
 * fake link; the callbacks are called the way wri_m2_conn calls them (plan, then the bytes into the sink,
 * then message; or plan alone for an aborted frame).
 *
 * Input layout:
 *
 *   byte 0   bits 0-1 mapmsg_queue - 1, bit 2 the cluster spec knows the fsid, bit 3 a cephx machine with
 *            held tickets (renewal is exercised), bits 4-5 mon_msg_cap (512 / 4096 / 70000 / 300000),
 *            bit 6 the link has the keepalive hooks, bit 7 three monitor addresses instead of one
 *   rest     a stream of operations, each an opcode byte (mod 10) followed by its arguments:
 *              0 deliver   type sel, version, compat, mode, u16 length, then that many bytes of the input
 *              1 time      u16: advance the clock by that many ms (steps at the deadlines on the way)
 *              2 peek      1 = also release afterwards
 *              3 release
 *              4 closed    status selector
 *              5 ready
 *              6 want_osdmap   u32
 *              7 acks      bump the keepalive ACK count
 *              8 link      selector: send busy / send failure / open failure / open busy / keepalive busy
 *              9 stale     the same callbacks from a connection that is not the monitor's
 *
 * Properties (a violated one traps): no crash or undefined behaviour (ASan / UBSan); the machine never
 * writes outside the sink it offered and every sink lies inside a slot or the renewal buffer with a cap
 * not above its size; guard bytes behind the bulk region stay untouched; plan answers only OK or BUSY and
 * BUSY only for a map type; slot invariants (kind, held, len <= cap, an occupied slot has bytes, at most
 * one held); the held slot's bytes do not change under the consumer; the monmap epoch never decreases;
 * the osdmap subscription start only decreases through want_osdmap; the state and the connection slot
 * agree; one open at a time; timers do not make the machine step at the same instant forever; events
 * carry a known kind.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_mon.h"
#include "wri_misc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define GUARD 64u
#define MAX_INPUT 100000u
#define MAX_OPS 400u

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

typedef struct fz {
	wri_ctx x;
	wri_mon m;
	wri_cx_client cx;
	int have_cx, have_ka;
	wri_mon_link link;
	wr_cluster_spec spec;
	uint8_t *bulk, *cxmem;
	size_t bulk_n;
	wri_m2_conn fc;
	uint64_t seq;
	/* fake link behaviour */
	uint16_t next_slot;
	int send_busy, send_fail, open_fail, open_busy, ka_busy;
	unsigned opens_live; /* opened and not closed / reported closed */
	uint32_t acks;
	uint32_t rng;
	unsigned n_map_events;
	/* what the consumer holds */
	int holding;
	uint8_t held_copy[128];
	size_t held_n;
	const uint8_t *held_ptr;
	/* monotonic things */
	uint32_t last_monmap_epoch;
	uint32_t last_sub_start;
	int want_called;
} fz;

static wr_status f_random(void *c, uint8_t *out, size_t n)
{
	fz *z = (fz *)c;
	size_t i;

	for (i = 0; i < n; i++) {
		z->rng ^= z->rng << 13;
		z->rng ^= z->rng >> 17;
		z->rng ^= z->rng << 5;
		out[i] = (uint8_t)z->rng;
	}
	return WR_OK;
}

static wr_status f_open(void *c, const wri_eaddr *a, uint16_t *slot)
{
	fz *z = (fz *)c;

	check(a != NULL && a->type == WRI_EADDR_TYPE_MSGR2 && a->port != 0);
	check(z->m.conn_slot == WRI_MON_NO_SLOT); /* one monitor session at a time */
	if (z->open_busy > 0) {
		z->open_busy--;
		return WR_E_BUSY;
	}
	if (z->open_fail > 0) {
		z->open_fail--;
		return WR_E_NET_CONNECT;
	}
	*slot = z->next_slot++;
	if (z->next_slot == WRI_MON_NO_SLOT)
		z->next_slot = 3;
	memset(&z->fc, 0, sizeof(z->fc));
	z->fc.slot = *slot;
	z->opens_live++;
	return WR_OK;
}

static void f_close(void *c, uint16_t slot, wr_status why)
{
	fz *z = (fz *)c;

	(void)why;
	check(slot == z->fc.slot);
	check(z->m.conn_slot == WRI_MON_NO_SLOT); /* the machine forgets the slot before it asks */
}

static wr_status f_send(void *c, uint16_t slot, const wri_m2_msg_out *m)
{
	fz *z = (fz *)c;

	check(slot == z->fc.slot && slot == z->m.conn_slot);
	check(m != NULL && m->front_len < 70000u && (m->front_len == 0 || m->front != NULL));
	check(m->data == NULL && m->data_len == 0);
	check(m->type == WRI_MSG_MON_GET_MAP || m->type == WRI_MSG_MON_SUBSCRIBE || m->type == WRI_MSG_AUTH);
	if (z->send_busy > 0) {
		z->send_busy--;
		return WR_E_BUSY;
	}
	if (z->send_fail > 0) {
		z->send_fail--;
		return WR_E_STATE;
	}
	return WR_OK;
}

static void f_event(void *c, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *err)
{
	fz *z = (fz *)c;

	(void)epoch;
	check(kind >= WR_EV_MON_SESSION_UP && kind <= WR_EV_TICKETS_RENEWED);
	if (kind == WR_EV_MAPMSG)
		z->n_map_events++;
	if (kind == WR_EV_MON_SESSION_DOWN || kind == WR_EV_AUTH_FAILED || kind == WR_EV_CLUSTER_UNREACHABLE)
		check(err != NULL);
}

static wr_status f_keepalive(void *c, uint16_t slot, uint32_t sec, uint32_t nsec)
{
	fz *z = (fz *)c;

	(void)sec;
	check(slot == z->m.conn_slot && nsec < 1000000000u);
	if (z->ka_busy > 0) {
		z->ka_busy--;
		return WR_E_BUSY;
	}
	return WR_OK;
}

static uint32_t f_acks(void *c, uint16_t slot)
{
	(void)slot;
	return ((fz *)c)->acks;
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v, p[1] = (uint8_t)(v >> 8), p[2] = (uint8_t)(v >> 16), p[3] = (uint8_t)(v >> 24);
}

static void step(fz *z)
{
	wri_mon_step(&z->x, &z->m, z->have_cx ? &z->cx : NULL, &z->link);
}

/* ---- invariants ------------------------------------------------------------------------------------------------ */

static void invariants(fz *z)
{
	const wri_mon *m = &z->m;
	unsigned i, held = 0;

	check(m->nslots >= 1 && m->nslots <= WRI_MON_MAXSLOTS);
	check((unsigned)m->st <= (unsigned)WRI_MON_RENEW);
	for (i = 0; i < m->nslots; i++) {
		const wri_mapslot *s = &m->slot[i];

		check(s->kind == 0 || s->kind == WR_MAPMSG_MONMAP || s->kind == WR_MAPMSG_OSDMAP);
		check(s->held <= 1);
		held += s->held;
		if (s->kind != 0) {
			check(s->len != 0 && s->len <= z->x.cfg.mon_msg_cap);
		} else {
			check(!s->held);
		}
		check(s->buf >= z->bulk && s->buf + z->x.cfg.mon_msg_cap <= z->bulk + z->bulk_n - GUARD);
	}
	check(held <= 1);
	if (m->st == WRI_MON_IDLE || m->st == WRI_MON_HUNT_WAIT)
		check(m->conn_slot == WRI_MON_NO_SLOT);
	else
		check(m->conn_slot != WRI_MON_NO_SLOT);
	check(m->monmap_epoch >= z->last_monmap_epoch);
	z->last_monmap_epoch = m->monmap_epoch;
	if (!z->want_called)
		check(m->sub_osdmap_start >= z->last_sub_start);
	z->last_sub_start = m->sub_osdmap_start;
	z->want_called = 0;
	check(m->n_addrs >= 1 && m->n_addrs <= WRI_MON_MAXMONS && m->rank < m->n_addrs);
	check(m->min_wait_ms >= WRI_MON_MIN_WAIT_MS && m->max_wait_ms >= m->min_wait_ms);
	check(m->backoff_ms >= m->min_wait_ms || m->backoff_ms == 0);
	check(m->backoff_ms <= m->max_wait_ms || m->backoff_ms == 0);
	check(m->ar_len <= m->abuf_cap);
	check(m->ar_err == WR_OK || m->st == WRI_MON_RENEW); /* an unreadable reply is acted on at the next step, never carried over */
	if (m->st == WRI_MON_IDLE || m->st == WRI_MON_HUNT_WAIT) /* the wrong-cluster count belongs to one session */
		check(!m->fsid_fail && !m->fsid_bad && m->ar_len == 0 && m->ar_err == WR_OK);
	/* guard bytes behind the bulk region */
	for (i = 0; i < GUARD; i++)
		check(z->bulk[z->bulk_n - GUARD + i] == 0xA5);
	/* the bytes the consumer holds do not change */
	if (z->holding && z->held_ptr != NULL)
		check(memcmp(z->held_ptr, z->held_copy, z->held_n) == 0);
}

/* ---- operations ------------------------------------------------------------------------------------------------- */

static const uint16_t types[] = {WRI_MSG_MON_MAP, WRI_MSG_OSD_MAP, WRI_MSG_AUTH_REPLY, WRI_MSG_MON_SUBSCRIBE_ACK, 62, 1796};

static void op_deliver(fz *z, const uint8_t *a, size_t *pos, size_t n)
{
	uint8_t sel, ver, compat, mode;
	uint32_t len, avail, seglen;
	uint16_t type;
	wri_m2_hdr2 h;
	wri_m2_sink sink[3];
	uint32_t sl[3], stored[3] = {0, 0, 0};
	wr_status st;
	unsigned i;

	if (*pos + 6u > n) {
		*pos = n;
		return;
	}
	sel = a[(*pos)++], ver = a[(*pos)++], compat = a[(*pos)++], mode = a[(*pos)++];
	len = a[*pos] | ((uint32_t)a[*pos + 1u] << 8);
	*pos += 2;
	avail = (uint32_t)(n - *pos);
	if (len > avail)
		len = avail;
	type = sel < sizeof(types) / sizeof(types[0]) ? types[sel] : (uint16_t)(sel * 257u);
	memset(&h, 0, sizeof(h));
	h.seq = ++z->seq, h.type = type, h.version = ver, h.compat_version = compat, h.priority = 196;
	seglen = len;
	if ((mode & 3u) == 1u)
		seglen = z->x.cfg.mon_msg_cap + 1u + (uint32_t)(mode >> 2); /* a front above the cap */
	if ((mode & 3u) == 2u)
		seglen = len + (uint32_t)(mode >> 2); /* the frame is longer than what the sink will hold below */
	sl[0] = seglen, sl[1] = mode & 0x10u ? 5u : 0u, sl[2] = mode & 0x20u ? 7u : 0u;
	memset(sink, 0xCD, sizeof(sink));
	st = wri_mon_upper()->plan(&z->m, &z->fc, &h, sl, sink);
	check(st == WR_OK || st == WR_E_BUSY);
	if (st == WR_E_BUSY) {
		check(type == WRI_MSG_MON_MAP || type == WRI_MSG_OSD_MAP);
		check(z->m.stalled);
		*pos += len;
		return;
	}
	check(sink[1].dst == NULL && sink[2].dst == NULL);
	if (sink[0].dst != NULL) {
		const uint8_t *b = sink[0].dst;

		check(sink[0].cap <= z->x.cfg.mon_msg_cap || sink[0].cap <= z->m.abuf_cap);
		check(sink[0].cap >= seglen);
		check(seglen <= z->x.cfg.mon_msg_cap || type == WRI_MSG_AUTH_REPLY);
		/* inside the bulk region, outside the guard */
		check(b >= z->bulk && b + sink[0].cap <= z->bulk + z->bulk_n - GUARD);
		/* only min(len, seglen) bytes arrive; a front that stays short is the connection's business, the machine copes */
		stored[0] = seglen < len ? seglen : len;
		memcpy(sink[0].dst, a + *pos, stored[0]);
	}
	for (i = 1; i < 3; i++)
		(void)sl[i];
	if (!(mode & 0x40u)) /* 0x40: the frame is aborted by its sender: plan, but no message() */
		wri_mon_upper()->message(&z->m, &z->fc, &h, stored);
	*pos += len;
}

static void op_time(fz *z, const uint8_t *a, size_t *pos, size_t n)
{
	uint64_t until;
	unsigned same = 0, iter = 0;
	uint32_t ms;

	if (*pos + 2u > n) {
		*pos = n;
		return;
	}
	ms = a[*pos] | ((uint32_t)a[*pos + 1u] << 8);
	*pos += 2;
	if (ms & 0x8000u)
		ms = (ms & 0x7fffu) * 8u; /* up to 262 s */
	until = z->x.now.mono_ms + ms;
	for (;;) {
		uint64_t d;

		step(z);
		invariants(z);
		d = wri_mon_deadline(&z->m);
		if (d == WR_DEADLINE_NONE || d > until || ++iter > 20000u)
			break;
		if (d <= z->x.now.mono_ms) {
			check(++same < 40u); /* a deadline in the past again and again: a tight loop */
		} else {
			z->x.now.mono_ms = d;
			same = 0;
		}
	}
	z->x.now.mono_ms = until;
	step(z);
}

static void op_peek(fz *z, const uint8_t *a, size_t *pos, size_t n)
{
	wr_mapmsg mm;
	int release = *pos < n ? (a[(*pos)++] & 1) : 0;

	if (z->holding) {
		check(wri_mon_mapmsg_peek(&z->m, &mm));
		check(mm.front == z->held_ptr); /* idempotent until released */
	} else if (wri_mon_mapmsg_peek(&z->m, &mm)) {
		check(mm.kind == WR_MAPMSG_MONMAP || mm.kind == WR_MAPMSG_OSDMAP);
		check(mm.front_len != 0 && mm.front_len <= z->x.cfg.mon_msg_cap);
		check(mm.front >= z->bulk && mm.front + mm.front_len <= z->bulk + z->bulk_n - GUARD);
		z->holding = 1;
		z->held_ptr = mm.front;
		z->held_n = mm.front_len < sizeof(z->held_copy) ? mm.front_len : sizeof(z->held_copy);
		memcpy(z->held_copy, mm.front, z->held_n);
	}
	if (release && z->holding) {
		wri_mon_mapmsg_release(&z->m);
		z->holding = 0;
	}
}

static void op_release(fz *z)
{
	wri_mon_mapmsg_release(&z->m);
	z->holding = 0;
}

static void op_closed(fz *z, const uint8_t *a, size_t *pos, size_t n)
{
	static const wr_status st[] = {WR_E_NET_CLOSED, WR_E_NET_CONNECT, WR_E_M2_BAD_METHOD, WR_E_AUTH_DENIED, WR_E_M2_HANDSHAKE_TIMEOUT,
				       WR_E_M2_FRAME_CRC, WR_E_AUTH_DECRYPT, WR_E_TIMEOUT, WR_OK};
	wr_errinfo e;
	uint8_t sel = *pos < n ? a[(*pos)++] : 0;

	memset(&e, 0, sizeof(e));
	e.status = st[sel % (sizeof(st) / sizeof(st[0]))];
	e.module = WR_MOD_M2;
	if (e.status == WR_E_M2_BAD_METHOD)
		e.peer_result = -13;
	wri_mon_upper()->closed(&z->m, &z->fc, &e);
	step(z);
}

static void op_link(fz *z, const uint8_t *a, size_t *pos, size_t n)
{
	uint8_t sel = *pos < n ? a[(*pos)++] : 0;

	switch (sel % 5u) {
	case 0: z->send_busy = 1 + (int)(sel >> 4 & 3); break;
	case 1: z->send_fail = 1; break;
	case 2: z->open_fail = 1 + (int)(sel >> 4 & 3); break;
	case 3: z->open_busy = 1 + (int)(sel >> 4 & 3); break;
	default: z->ka_busy = 1 + (int)(sel >> 4 & 3); break;
	}
}

static void op_stale(fz *z, const uint8_t *a, size_t *pos, size_t n)
{
	wri_m2_conn other;
	wri_m2_hdr2 h;
	wri_m2_sink sink[3];
	uint32_t sl[3] = {64, 0, 0}, stored[3] = {64, 0, 0};
	uint8_t sel = *pos < n ? a[(*pos)++] : 0;
	wr_errinfo e;

	memset(&other, 0, sizeof(other));
	other.slot = (uint16_t)(z->fc.slot + 1u);
	memset(&h, 0, sizeof(h));
	h.type = (sel & 1u) ? WRI_MSG_MON_MAP : WRI_MSG_OSD_MAP;
	memset(&e, 0, sizeof(e));
	e.status = WR_E_NET_CLOSED;
	check(wri_mon_upper()->plan(&z->m, &other, &h, sl, sink) == WR_OK);
	check(sink[0].dst == NULL);
	wri_mon_upper()->message(&z->m, &other, &h, stored);
	wri_mon_upper()->ready(&z->m, &other);
	wri_mon_upper()->closed(&z->m, &other, &e);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz *z;
	wr_config cfg;
	static const uint32_t caps[4] = {512u, 4096u, 70000u, 300000u};
	size_t pos = 1, need = 0, cxn = 0, nops = 0;
	wri_arena a, ca;
	uint8_t b0;

	if (size < 1u || size > MAX_INPUT)
		return 0;
	b0 = data[0];
	z = (fz *)calloc(1, sizeof(*z));
	check(z != NULL);
	wr_config_profile_harness(&cfg);
	cfg.mapmsg_queue = (uint16_t)((b0 & 3u) + 1u);
	cfg.mon_msg_cap = caps[(b0 >> 4) & 3u];
	cfg.ticket_cap = 1024;
	z->x.cfg = cfg;
	z->x.host.size = (uint32_t)sizeof(z->x.host);
	z->x.host.ctx = z;
	z->x.host.random = f_random;
	z->x.now.mono_ms = 1000;
	z->rng = 0x9e3779b9u;
	z->next_slot = 3;
	z->have_ka = (b0 >> 6) & 1;
	z->link.ctx = z;
	z->link.open = f_open, z->link.close = f_close, z->link.send = f_send, z->link.event = f_event;
	if (z->have_ka)
		z->link.keepalive = f_keepalive, z->link.keepalive_acks = f_acks;
	z->spec.n_mons = (b0 & 0x80u) ? 3 : 1;
	{
		unsigned i;

		for (i = 0; i < z->spec.n_mons; i++) {
			z->spec.mons[i].family = WR_AF_IPV4;
			z->spec.mons[i].ip[0] = 10, z->spec.mons[i].ip[3] = (uint8_t)(10u + i);
			z->spec.mons[i].port = (uint16_t)(i == 2 ? 0 : 3300);
		}
	}
	if (b0 & 4u) {
		static const uint8_t fsid[16] = {0x52, 0x76, 0x27, 0x25, 0xe1, 0x9a, 0x11, 0xf1, 0x88, 0x6d, 0x52, 0x54, 0x00, 0x77, 0x00, 0x01};

		z->spec.fsid_known = 1;
		memcpy(z->spec.fsid, fsid, 16);
	}
	check(wri_mon_bulk_mem(&cfg, &need) == WR_OK);
	z->bulk_n = need + WRI_ARENA_SLACK + GUARD;
	z->bulk = (uint8_t *)malloc(z->bulk_n);
	check(z->bulk != NULL);
	memset(z->bulk, 0xA5, z->bulk_n);
	wri_arena_init(&a, z->bulk, z->bulk_n - GUARD);
	check(wri_mon_init(&z->m, &z->x, &a, &z->spec) == WR_OK);
	if (b0 & 8u) { /* a cephx machine with an AUTH and an OSD ticket held: the renewal path */
		wri_cx_ticket *t;

		z->spec.key.type = WR_KEY_TYPE_AES256K, z->spec.key.len = 32;
		memset(z->spec.key.secret, 0x42, 32);
		strcpy(z->spec.user, "winrbd");
		check(wri_cx_client_mem(&cfg, &cxn) == WR_OK);
		z->cxmem = (uint8_t *)malloc(cxn + WRI_ARENA_SLACK);
		wri_arena_init(&ca, z->cxmem, cxn + WRI_ARENA_SLACK);
		check(wri_cx_client_init(&z->cx, &z->x, &ca, &z->spec) == WR_OK);
		z->have_cx = 1;
		z->cx.global_id = 4100;
		t = &z->cx.ticket[WRI_CX_SLOT_AUTH];
		t->have = 1, t->service = WRI_CX_SERVICE_AUTH;
		t->session_key.type = WR_KEY_TYPE_AES256K, t->session_key.len = 32;
		memset(t->session_key.secret, 0x33, 32);
		t->blob_len = 33;
		t->blob[0] = 1, put32(t->blob + 9, 20), memset(t->blob + 13, 0xEE, 20);
		t->valid_until_ms = 1000u + 3600u * 1000u * 72u;
		t->renew_at_ms = 1000u + 3600u * 1000u * 54u;
		t = &z->cx.ticket[WRI_CX_SLOT_OSD];
		t->have = 1, t->service = WRI_CX_SERVICE_OSD;
		t->session_key.type = WR_KEY_TYPE_AES256K, t->session_key.len = 32;
		memset(t->session_key.secret, 0x44, 32);
		t->blob_len = 33;
		t->blob[0] = 1, put32(t->blob + 9, 20), memset(t->blob + 13, 0xDD, 20);
		t->valid_until_ms = 1000u + 60000u;
		t->renew_at_ms = 1000u + 45000u;
	}
	/* a session in SYNC to start from (most of the operations need one) */
	step(z);
	wri_mon_upper()->ready(&z->m, &z->fc);
	step(z);
	invariants(z);
	while (pos < size && nops++ < MAX_OPS) {
		uint8_t op = data[pos++];

		switch (op % 10u) {
		case 0: op_deliver(z, data, &pos, size); break;
		case 1: op_time(z, data, &pos, size); break;
		case 2: op_peek(z, data, &pos, size); break;
		case 3: op_release(z); break;
		case 4: op_closed(z, data, &pos, size); break;
		case 5:
			wri_mon_upper()->ready(&z->m, &z->fc);
			step(z);
			break;
		case 6:
			if (pos + 4u <= size) {
				uint32_t v = data[pos] | ((uint32_t)data[pos + 1] << 8) | ((uint32_t)data[pos + 2] << 16) |
					     ((uint32_t)data[pos + 3] << 24);

				wri_mon_want_osdmap(&z->m, v);
				z->want_called = 1;
				pos += 4;
			} else {
				pos = size;
			}
			break;
		case 7: z->acks++; break;
		case 8: op_link(z, data, &pos, size); break;
		default: op_stale(z, data, &pos, size); break;
		}
		invariants(z);
	}
	/* drain: whatever the consumer holds can be released, and every map left is well formed */
	{
		wr_mapmsg mm;
		unsigned guard = 0;

		z->holding = 0;
		while (wri_mon_mapmsg_peek(&z->m, &mm) && guard++ < 16u) {
			check(mm.front_len != 0 && mm.front_len <= z->x.cfg.mon_msg_cap);
			wri_mon_mapmsg_release(&z->m);
		}
	}
	invariants(z);
	if (z->have_cx)
		wri_cx_client_wipe(&z->cx);
	free(z->cxmem);
	free(z->bulk);
	free(z);
	return 0;
}
