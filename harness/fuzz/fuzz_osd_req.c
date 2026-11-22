/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the object request engine (core/src/osd/wri_osd_req*.c): a program of operations an owner, a map, a clock, a connection layer and a hostile
 * OSD can do to the engine, played against the REAL session table (wri_osd_sess) on a scripted engine link (no sockets, no simulator: replies are frames
 * built here and handed to the table the way the msgr2 parser does, through plan() and message()).
 *
 * Input layout:
 *
 *   byte 0   bits 0-2 max_ops (3 .. 10), bits 3-4 sessions (1 .. 4), bits 5-6 zombie area (0 / 256 / 1024 / 8192 bytes), bit 7 FULL_TRY off
 *   byte 1   bit 0 HONOR_PAUSE off, bit 1 map_stale_ms = 0 (else 20000), bits 2-3 inflight_bytes_max (3000 / 20000 / 1 MiB / 1 MiB), bit 4 op_timeout 2000 (else 5000),
 *            bits 5-6 backoff slots (1 / 2 / 4 / 8)
 *   rest     operations, each an opcode byte (mod 14) and its arguments:
 *              0 submit    kind / control / pool / object / operation count and codes / data length / output capacity / snapshot context
 *              1 cancel    slot
 *              2 map       what changes (a primary, the epoch by 1 to 4, pool flags, force-resend epoch, pause / full flags, pool present, address, pg_num)
 *              3 time      u16: milliseconds (times a scale), wall clock on or off, then a step
 *              4 step      budget (0 .. 7)
 *              5 ready     session: its connection reaches READY (feature word selector)
 *              6 closed    session: its connection ends (status selector)
 *              7 reply     a reply to a live op (or to a made-up tid): operation count, payload lengths, result, retry attempt, tid variant, data length
 *              8 garbage   a reply whose front is raw input bytes
 *              9 backoff   BLOCK / UNBLOCK of a PG (or an object) on a session
 *             10 knobs     link: transmit queue idle / send refusal / open refusal / ticket / handshake gate / closed slots held
 *             11 pop       the owner pulls a completion and releases it (or does not: selector)
 *             12 hostile   release / cancel / count_owner of an arbitrary slot index
 *             13 idle      the engine frees the slots of closed connections, a large jump in time and a step
 *
 * Properties (a violated one traps): no crash or undefined behaviour (ASan / UBSan); the slots are conserved (free + live + done ring + the owner's == max_ops);
 * the submission list is consistent (links, strictly ascending tids, slot = tid & 0xffff, states NEW .. SENT) and counts n_inflight; inflight_bytes is exactly the
 * sum over it and never above the budget; the zombie area is consistent (blocks inside it, disjoint, zused their sum); every op SENT holds a live READY session
 * and counts in that session's in-flight number; no message goes out for an op that is not about to be sent, with other data than the op's (a zombie: its copy),
 * on a session that is not READY, into a standing backoff, while the map pauses it, or beyond the budget of the call; a tid is never reused and grows with every
 * submit; a sink is only handed out for an op SENT on that session, with the op's own buffer and capacity (never for a zombie); an op completes once; after every
 * fault is lifted and every op answered the table is empty, nothing is accounted and the free list is whole.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test/osd_sess_rig.h"
#include "wri_osd_req.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAX_INPUT 20000u
#define MAX_STEPS 400u
#define NSLOT 12u
#define BUF 512u
#define MAXO 12u

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

/* ---- the scripted map ------------------------------------------------------------------------------------------------------------ */

typedef struct fzmap {
	uint32_t epoch, flags, pg_num;
	int present[2];
	wr_status pstatus[2];
	uint64_t pflags[2];
	uint32_t last_force[2];
	int prim[16];
	int addr_var[4];
} fzmap;

static wr_addr fz_addr(int osd, int var)
{
	wr_addr a;

	memset(&a, 0, sizeof(a));
	a.family = WR_AF_IPV4;
	a.ip[0] = 10, a.ip[1] = 77, a.ip[2] = 0, a.ip[3] = (uint8_t)(40 + osd);
	a.port = (uint16_t)(6810 + osd + (var & 1));
	a.nonce = 7000u + (uint32_t)osd;
	return a;
}

static uint32_t m_epoch(void *c) { return ((fzmap *)c)->epoch; }
static uint32_t m_flags(void *c) { return ((fzmap *)c)->flags; }

static wr_status m_pool_info(void *c, wr_pool_h h, wr_pool_info *out)
{
	fzmap *m = (fzmap *)c;

	memset(out, 0, sizeof(*out));
	if (m->epoch == 0)
		return WR_E_MAP_NONE;
	if (h >= 2u || !m->present[h])
		return WR_E_POOL_NOT_FOUND;
	out->id = 2 + (int64_t)h;
	out->flags = m->pflags[h];
	out->size = 3;
	out->pg_num = out->pgp_num = m->pg_num;
	out->last_force_op_resend = m->last_force[h];
	out->status = m->pstatus[h];
	return WR_OK;
}

static wr_status m_target(void *c, wr_pool_h h, const wr_object_id *oid, wr_target *out)
{
	fzmap *m = (fzmap *)c;
	const uint8_t *nm = (const uint8_t *)oid->name;
	uint32_t hash = 2166136261u, pg;
	size_t i;
	int osd;

	memset(out, 0, sizeof(*out));
	if (m->epoch == 0)
		return WR_E_MAP_NONE;
	if (h >= 2u || !m->present[h])
		return WR_E_POOL_NOT_FOUND;
	if (m->pstatus[h] != WR_OK)
		return m->pstatus[h];
	for (i = 0; i < oid->name_len; i++)
		hash = (hash ^ nm[i]) * 16777619u;
	pg = hash & (m->pg_num - 1u);
	out->epoch = m->epoch;
	out->pool_id = 2 + (int64_t)h;
	out->ps = hash;
	out->pg_seed = pg;
	osd = m->prim[pg];
	if (osd < 0)
		return WR_E_PLACE_UNMAPPABLE;
	out->n_up = out->n_acting = 1;
	out->up[0] = out->acting[0] = osd;
	out->up_primary = out->acting_primary = osd;
	if (osd < 4 && m->addr_var[osd] >= 0)
		out->primary_addr = fz_addr(osd, m->addr_var[osd]);
	return WR_OK;
}

/* ---- the scripted engine link and the owner ------------------------------------------------------------------------------------------ */

typedef struct fz {
	wri_ctx x;
	uint8_t *mem, *bulk;
	wri_arena arena, barena;
	wri_osdc o;
	fzmap m;
	/* link */
	struct {
		int used, closing;
		wri_m2_conn conn;
		const wri_m2_upper *up;
		void *up_ctx;
	} sl[NSLOT];
	unsigned n_slots;
	int have_ticket, hs_free, tx_idle, closing_holds;
	wr_status open_st, send_st;
	unsigned sends_in_call;
	/* the owner */
	uint8_t dbuf[MAXO][BUF], obuf[MAXO][BUF];
	uint64_t sids[MAXO][4];
	wri_snapc sc[MAXO];
	uint8_t owned[MAXO];             /* 2: popped and not released (the owner holds it); 1: allocated, not yet submitted */
	uint8_t refd[NSLOT][MAXO];       /* the connection's transmit queue may still point into the data buffer of that op (a message was sent while the host held the queue) */
	uint64_t last_submit_tid;
	int honor_pause, full_try;
	unsigned n_submits, n_pops;
} fz;

/* ---- the link ---------------------------------------------------------------------------------------------------------------------- */

static wr_status l_open(void *ctx, const wri_eaddr *addr, const wri_m2_upper *up, void *up_ctx, uint16_t *out)
{
	fz *f = (fz *)ctx;
	unsigned i;

	(void)addr;
	if (f->open_st != WR_OK)
		return f->open_st;
	check(up == wri_osd_sess_upper() && up_ctx != NULL);
	for (i = 0; i < f->n_slots; i++) {
		if (!f->sl[i].used) {
			memset(&f->sl[i], 0, sizeof(f->sl[i]));
			memset(f->refd[i], 0, sizeof(f->refd[i]));
			f->sl[i].used = 1;
			f->sl[i].up = up;
			f->sl[i].up_ctx = up_ctx;
			f->sl[i].conn.slot = (uint16_t)i;
			f->sl[i].conn.role = WRI_ENTITY_OSD;
			f->sl[i].conn.state = WRI_M2_CONNECTING;
			*out = (uint16_t)i;
			return WR_OK;
		}
	}
	return WR_E_BUSY;
}

static void l_close(void *ctx, uint16_t s, wr_status why)
{
	fz *f = (fz *)ctx;

	(void)why;
	check(s < f->n_slots && f->sl[s].used && !f->sl[s].closing);
	f->sl[s].closing = 1;
	memset(f->refd[s], 0, sizeof(f->refd[s])); /* the queue is dropped with the connection */
	f->sl[s].conn.state = WRI_M2_CLOSING;
	if (!f->closing_holds)
		f->sl[s].used = 0;
}

/* The property checks of a message the engine hands to a session. */
static wr_status l_send(void *ctx, uint16_t slot, const wri_m2_msg_out *m)
{
	fz *f = (fz *)ctx;
	const wri_osdc *o = &f->o;
	const wri_osd_op *op;
	const wri_osd_sess *sp;
	uint32_t pass_flags;

	check(m != NULL && slot < f->n_slots && f->sl[slot].used && !f->sl[slot].closing);
	check(f->sl[slot].conn.state == WRI_M2_READY);
	if (m->type == WRI_MSG_OSD_BACKOFF) /* the session table's own ACK_BLOCK */
		return f->send_st == WR_E_STATE ? WR_OK : f->send_st;
	check(m->type == WRI_MSG_OSD_OP && m->priority == WRI_MSG_PRIO_CLIENT && m->front != NULL && m->front_len != 0u && m->front_len <= f->x.cfg.osd_front_cap);
	check((m->tid & 0xffffu) < o->n_op);
	op = &o->op[m->tid & 0xffffu];
	check(op->tid == m->tid && (op->state == WRI_OP_WAIT_SESS || op->state == WRI_OP_QUEUED) && op->sess < o->sess.n);
	sp = &o->sess.s[op->sess];
	check(sp->state == WRI_OS_READY && sp->conn_slot == slot && sp->osd == op->osd);
	check(m->data_len == op->data_len);
	if (op->data_len != 0u) {
		if ((op->flags & WRI_OPF_ZOMBIE) != 0u)
			check(m->data == op->data && op->data >= o->zbuf && op->data + op->data_len <= o->zbuf + o->zcap);
		else
			check(m->data == op->data && op->data == f->dbuf[op - o->op]);
		if (!f->tx_idle && (op->flags & WRI_OPF_ZOMBIE) == 0u && f->send_st == WR_OK)
			f->refd[slot][op - o->op] = 1; /* the host does not consume: the queue points into the owner's buffer */
	}
	/* not into a standing backoff, not while the map holds the op, and no more messages than the call may send */
	check(!wri_osd_sess_blocked(&o->sess, op->sess, op->pool_id, op->pg_seed, op->hash, op->oid, op->oid_len));
	pass_flags = f->m.flags;
	if (f->honor_pause)
		check(!((op->kind == WRI_OPK_READ && (pass_flags & WR_MAP_F_PAUSERD) != 0u) || (op->kind == WRI_OPK_WRITE && (pass_flags & WR_MAP_F_PAUSEWR) != 0u)));
	if (f->send_st == WR_OK)
		f->sends_in_call++; /* only messages that were accepted count against the budget of the call */
	return f->send_st;
}

static int l_tx_idle(void *ctx, uint16_t s)
{
	fz *f = (fz *)ctx;

	check(s < f->n_slots && f->sl[s].used);
	return f->tx_idle;
}

static int l_ticket(void *ctx) { return ((fz *)ctx)->have_ticket; }
static int l_hs(void *ctx) { return ((fz *)ctx)->hs_free; }

/* ---- invariants --------------------------------------------------------------------------------------------------------------------- */

static void check_all(fz *f)
{
	wri_osdc *o = &f->o;
	uint32_t i, k, n = o->n_op, live = 0, ring = 0, owned = 0, nfree = 0, prev = WRI_NIL, ctl = 0, inring = 0;
	uint64_t bytes = 0, prev_tid = 0, zsum = 0;

	for (i = o->free_head; i != WRI_NIL; i = o->op[i].next) {
		check(nfree < n && o->op[i].state == WRI_OP_FREE && (o->op[i].flags & WRI_OPF_ALLOC) == 0u);
		nfree++;
	}
	check(nfree == o->n_free);
	for (i = o->head; i != WRI_NIL; prev = i, i = o->op[i].next) {
		const wri_osd_op *op = &o->op[i];

		check(live < n && op->prev == prev && (op->tid & 0xffffu) == i && op->tid > prev_tid);
		check(op->state >= WRI_OP_NEW && op->state <= WRI_OP_SENT && (op->flags & (WRI_OPF_ALLOC | WRI_OPF_INRING)) == 0u);
		live++;
		prev_tid = op->tid;
		bytes += wri_or_bytes(op);
		if (op->state == WRI_OP_SENT) {
			check(op->sess < o->sess.n && o->sess.s[op->sess].state == WRI_OS_READY && op->sent_epoch != 0u && op->deadline_ms >= op->sent_ms);
		} else if (op->state != WRI_OP_WAIT_SESS && op->state != WRI_OP_QUEUED) {
			check(op->sess == WRI_NIL);
		}
		if ((op->flags & WRI_OPF_ZOMBIE) != 0u) {
			check(op->out == NULL && op->out_cap == 0u && op->kind == WRI_OPK_WRITE && op->sent_epoch != 0u);
			if (op->zlen != 0u)
				check((uint64_t)op->zoff + op->zlen <= o->zcap && (op->zoff & 7u) == 0u);
			zsum += op->zlen;
		} else {
			check(op->zlen == 0u);
		}
	}
	check(prev == o->tail && live == o->n_inflight && bytes == o->inflight_bytes && o->inflight_bytes <= f->x.cfg.inflight_bytes_max);
	check(zsum == o->zused && o->zused <= o->zcap && o->zmax >= o->zused);
	for (i = 0; i < n; i++) { /* zombie blocks are disjoint */
		for (k = i + 1u; k < n; k++) {
			const wri_osd_op *a = &o->op[i], *b = &o->op[k];

			if ((a->flags & WRI_OPF_ZOMBIE) != 0u && (b->flags & WRI_OPF_ZOMBIE) != 0u && a->zlen != 0u && b->zlen != 0u && a->state != WRI_OP_FREE &&
			    b->state != WRI_OP_FREE)
				check(a->zoff + a->zlen <= b->zoff || b->zoff + b->zlen <= a->zoff);
		}
	}
	for (k = 0; k < o->done_len; k++) {
		const wri_osd_op *op;

		i = o->done_ring[(o->done_pos + k) % n];
		check(i < n);
		op = &o->op[i];
		check(op->state == WRI_OP_DONE && (op->flags & WRI_OPF_INRING) != 0u);
		ring++;
	}
	for (i = 0; i < n; i++) {
		const wri_osd_op *op = &o->op[i];

		inring += (op->flags & WRI_OPF_INRING) != 0u ? 1u : 0u;
		owned += f->owned[i] != 0u ? 1u : 0u;
		ctl += (op->state != WRI_OP_FREE || (op->flags & WRI_OPF_ALLOC) != 0u) && (op->flags & WRI_OPF_CONTROL) != 0u ? 1u : 0u;
		if (f->owned[i] == 2u)
			check(op->state == WRI_OP_DONE && (op->flags & WRI_OPF_INRING) == 0u);
	}
	check(inring == o->done_len && ring == o->done_len);
	check(nfree + live + ring + owned == n); /* no slot leaked, none counted twice */
	check(ctl == o->n_ctl_used && o->n_free_ctl == (o->x->cfg.ctl_ops > ctl ? o->x->cfg.ctl_ops - ctl : 0u));
	for (k = 0; k < o->sess.n; k++) { /* the session's in-flight count is the number of ops SENT on it */
		const wri_osd_sess *sp = &o->sess.s[k];
		uint32_t cnt = 0;

		for (i = o->head; i != WRI_NIL; i = o->op[i].next)
			cnt += (o->op[i].state == WRI_OP_SENT && o->op[i].sess == k) ? 1u : 0u;
		check(sp->n_inflight == cnt);
	}
}

/* ---- the program ------------------------------------------------------------------------------------------------------------------- */

typedef struct rd {
	const uint8_t *p;
	size_t n, pos;
} rd;

static uint8_t rd8(rd *r)
{
	return r->pos < r->n ? r->p[r->pos++] : 0u;
}

static uint16_t rd16(rd *r)
{
	uint16_t lo = rd8(r);

	return (uint16_t)(lo | ((uint16_t)rd8(r) << 8));
}

static const uint8_t *rdbytes(rd *r, size_t len, size_t *got)
{
	size_t left = r->n - r->pos;
	const uint8_t *p = r->p + r->pos;

	*got = len < left ? len : left;
	r->pos += *got;
	return p;
}

static uint16_t pick_code(unsigned kind, uint8_t sel)
{
	static const uint16_t rd_codes[8] = {WRI_OSD_OP_READ, WRI_OSD_OP_READ, WRI_OSD_OP_STAT, WRI_OSD_OP_CALL, WRI_OSD_OP_SPARSE_READ, WRI_OSD_OP_GETXATTR,
					     WRI_OSD_OP_OMAPGETVALS, 0x9999};
	static const uint16_t wr_codes[8] = {WRI_OSD_OP_WRITE, WRI_OSD_OP_WRITE, WRI_OSD_OP_ZERO, WRI_OSD_OP_TRUNCATE, WRI_OSD_OP_DELETE, WRI_OSD_OP_CREATE,
					     WRI_OSD_OP_READ, WRI_OSD_OP_WRITEFULL};

	return kind == WRI_OPK_READ ? rd_codes[sel & 7u] : wr_codes[sel & 7u];
}

static void do_submit(fz *f, rd *r)
{
	uint8_t a = rd8(r), b = rd8(r), c = rd8(r), d = rd8(r), e = rd8(r), g = rd8(r);
	unsigned kind = (a >> 1) & 1u, n_ops = 1u + (c & 3u), k;
	uint32_t i, sum = 0;
	wri_osd_op *op;
	wr_status st;
	size_t nl;

	i = wri_osdc_alloc(&f->o, a & 1);
	if (i == WRI_NIL)
		return;
	check(i < f->o.n_op && f->owned[i] == 0u);
	f->owned[i] = 1;
	op = wri_osdc_at(&f->o, i);
	check(op->state == WRI_OP_FREE && (op->flags & WRI_OPF_ALLOC) != 0u && op->tid == 0u && op->osd == -1 && op->sess == WRI_NIL);
	op->kind = (uint8_t)kind;
	op->pool = (wr_pool_h)((a >> 2) & 3u);
	nl = (b & 8u) ? 90u : 2u + (b & 3u);
	memset(op->oid, 'a' + (int)(b & 7u), nl);
	op->oid[nl - 1u] = (uint8_t)('0' + (b & 7u));
	op->oid_len = (uint8_t)((a & 0x80u) && (b & 16u) ? WRI_OSD_OID_MAX + 1u : nl); /* sometimes too long */
	op->owner = 0x100u + i;
	op->n_ops = (uint8_t)n_ops;
	memset(f->dbuf[i], (int)(0x40u + i), BUF);
	for (k = 0; k < n_ops; k++) {
		wri_osd_opd *od = &op->ops[k];
		uint16_t code = pick_code(kind, (uint8_t)(d >> (2u * k)));

		od->code = code;
		od->off = (uint64_t)(e & 15u) * 64u;
		od->len = 16u + (uint64_t)(g & 63u);
		if (code == WRI_OSD_OP_WRITE || code == WRI_OSD_OP_WRITEFULL) {
			od->in_len = (uint32_t)od->len;
		} else if (code == WRI_OSD_OP_CALL) {
			od->cls_class_len = 3;
			od->cls_method_len = 6;
			od->in_len = 9u + (g & 1u);
		} else if (code == WRI_OSD_OP_GETXATTR || code == WRI_OSD_OP_OMAPGETVALS) {
			od->in_len = 4;
		}
		sum += od->in_len;
	}
	op->data_len = sum + ((g & 0x80u) && (e & 0x80u) ? 1u : 0u); /* sometimes a length that does not add up */
	op->data = op->data_len != 0u ? f->dbuf[i] : NULL;
	if (e & 0x40u) { /* a buffer for the output: a read (or a call) gets its capacity */
		op->out = f->obuf[i];
		op->out_cap = 8u + (uint32_t)(g & 0x3fu) * 8u;
	}
	if ((e & 0x30u) != 0u && kind == WRI_OPK_WRITE) { /* a snapshot context, sometimes not a valid one */
		unsigned ns = (e >> 4) & 3u, j;

		f->sc[i].seq = 10;
		f->sc[i].n = ns;
		f->sc[i].cap = 4;
		f->sc[i].snaps = f->sids[i];
		for (j = 0; j < 4u; j++)
			f->sids[i][j] = 9u - j * ((g & 0x40u) && j == 1u ? 0u : 1u);
		op->snapc = &f->sc[i];
	}
	st = wri_osdc_submit(&f->o, i);
	if (st == WR_OK) {
		f->owned[i] = 0;
		check(op->tid > f->last_submit_tid && (op->tid & 0xffffu) == i && op->state == WRI_OP_NEW);
		f->last_submit_tid = op->tid;
		f->n_submits++;
	} else {
		check(st == WR_E_INVAL || st == WR_E_UNSUPPORTED || st == WR_E_BUSY || st == WR_E_TOOBIG);
		check(op->state == WRI_OP_FREE && (op->flags & WRI_OPF_ALLOC) != 0u);
		wri_osdc_release(&f->o, i); /* the slot stays the owner's after a refusal: here it gives it back */
		f->owned[i] = 0;
	}
}

static void do_cancel(fz *f, uint32_t idx)
{
	wri_osdc *o = &f->o;
	wr_status st;
	int was_live;
	wri_osd_op *op;

	op = wri_osdc_at(o, idx);
	was_live = op != NULL && op->state >= WRI_OP_NEW && op->state <= WRI_OP_SENT && (op->flags & WRI_OPF_ZOMBIE) == 0u;
	st = wri_osdc_cancel(o, idx);
	if (op == NULL) {
		check(st == WR_E_INVAL);
		return;
	}
	check(st == WR_OK || st == WR_E_BUSY || st == WR_E_STATE);
	if (st == WR_OK && was_live) {
		if ((op->flags & WRI_OPF_ZOMBIE) != 0u) {
			check(op->kind == WRI_OPK_WRITE && op->sent_epoch != 0u && op->out == NULL && (op->flags & WRI_OPF_INRING) == 0u && op->state != WRI_OP_DONE);
			check(wri_osdc_count_owner(o, op->owner, 0xffffffffu) >= 1u);
		} else {
			check(op->state == WRI_OP_DONE && op->status == WR_E_CANCELLED && (op->flags & WRI_OPF_INRING) != 0u);
			memset(f->obuf[idx], 0xEE, BUF); /* the owner's buffers are free */
			memset(f->dbuf[idx], 0xEE, BUF);
		}
	}
	if (st == WR_E_BUSY) {
		check(was_live && op->kind == WRI_OPK_WRITE && op->sent_epoch != 0u && (op->flags & WRI_OPF_ZOMBIE) == 0u && op->state != WRI_OP_DONE);
	}
}

static void do_map(fz *f, rd *r)
{
	uint8_t a = rd8(r), b = rd8(r);
	fzmap *m = &f->m;
	static const uint64_t pf[3] = {WR_POOL_F_FULL, WR_POOL_F_FULL_QUOTA, WR_POOL_F_EIO};
	static const uint32_t mf[3] = {WR_MAP_F_PAUSERD, WR_MAP_F_PAUSEWR, WR_MAP_F_FULL};
	static const wr_status ps[3] = {WR_OK, WR_E_POOL_UNSUPPORTED, WR_E_CRUSH_NO_RULE};

	switch (a % 12u) {
	case 0:
		m->prim[b & 15u] = (int)((b >> 4) % 4u) - 1;
		break;
	case 1:
		m->epoch += (uint32_t)(b & 3u);
		break;
	case 2:
		m->pflags[b & 1u] ^= pf[(b >> 1) % 3u];
		break;
	case 3:
		m->last_force[b & 1u] = m->epoch + (uint32_t)(b >> 4 & 1u);
		break;
	case 4:
		m->flags ^= mf[b % 3u];
		break;
	case 5:
		m->present[b & 1u] ^= 1;
		break;
	case 6:
		m->addr_var[b & 3u] = (int)((b >> 2) % 3u) - 1;
		break;
	case 7:
		m->pg_num = (b & 1u) ? 16u : 8u;
		break;
	case 8:
		m->pstatus[b & 1u] = ps[(b >> 1) % 3u];
		break;
	case 9:
		m->epoch = 0; /* no map */
		break;
	case 10: {
		unsigned i;

		for (i = 0; i < 16u; i++)
			m->prim[i] = (int)(b % 3u);
		break;
	}
	default:
		if (m->epoch > 3u)
			m->epoch -= 1u + (uint32_t)(b & 1u); /* a map that goes back */
		break;
	}
	if (a % 12u != 9u && a % 12u < 11u)
		m->epoch += 1u; /* every change is a new epoch */
	if (m->epoch == 0u && a % 12u != 9u)
		m->epoch = 1u;
}

static uint64_t feat_of(unsigned sel)
{
	uint64_t all = 0x3f07fffffffdffffull;

	switch (sel & 7u) {
	case 0:
	case 1:
	case 2:
		return all;
	case 3:
		return all & ~(1ull << 49);
	case 4:
		return all & ~(1ull << 8);
	default:
		return all;
	}
}

static void do_ready(fz *f, uint32_t s, unsigned sel)
{
	const wri_osd_sess *p = &f->o.sess.s[s % f->o.sess.n];
	uint16_t slot = p->conn_slot;

	if (p->state != WRI_OS_OPENING || slot == WRI_OS_NOSLOT)
		return;
	f->sl[slot].conn.features = feat_of(sel);
	f->sl[slot].conn.state = WRI_M2_READY;
	f->sl[slot].up->ready(f->sl[slot].up_ctx, &f->sl[slot].conn);
}

static void do_closed(fz *f, uint32_t s, unsigned sel)
{
	static const wr_status sts[4] = {WR_E_NET_CLOSED, WR_E_M2_HANDSHAKE_TIMEOUT, WR_OK, WR_E_OSD_PROTO};
	const wri_osd_sess *p = &f->o.sess.s[s % f->o.sess.n];
	uint16_t slot = p->conn_slot;
	wr_errinfo e;

	if ((p->state != WRI_OS_OPENING && p->state != WRI_OS_READY) || slot == WRI_OS_NOSLOT)
		return;
	memset(&e, 0, sizeof(e));
	e.status = sts[sel & 3u];
	e.module = WR_MOD_M2;
	f->sl[slot].conn.state = WRI_M2_FAILED;
	f->sl[slot].up->closed(f->sl[slot].up_ctx, &f->sl[slot].conn, &e);
	f->sl[slot].used = 0;
}

/* One MESSAGE on session s, delivered the way the msgr2 parser does: plan(), the bytes into the sinks (never beyond their cap), message(). */
static void deliver(fz *f, uint32_t s, uint16_t type, uint64_t tid, uint16_t ver, uint16_t compat, const uint8_t *front, uint32_t flen, const uint8_t *data,
		    uint32_t dlen)
{
	wri_osd_sess *p = &f->o.sess.s[s];
	uint16_t slot = p->conn_slot;
	wri_m2_conn *c;
	wri_m2_hdr2 h;
	uint32_t seglen[3], stored[3];
	wri_m2_sink sink[3];
	wr_status st;

	if (slot == WRI_OS_NOSLOT || !f->sl[slot].used || p->state != WRI_OS_READY)
		return;
	c = &f->sl[slot].conn;
	if (type == WRI_MSG_OSD_OPREPLY && (tid & 0xffffu) < f->o.n_op && f->o.op[tid & 0xffffu].tid == tid)
		f->refd[slot][tid & 0xffffu] = 0; /* a reply that names the op's tid on that connection: the OSD consumed its request (and all before it), whatever the reply says */
	memset(&h, 0, sizeof(h));
	h.seq = ++c->in_seq;
	h.tid = tid;
	h.type = type;
	h.version = ver;
	h.compat_version = compat;
	seglen[0] = flen, seglen[1] = 0, seglen[2] = dlen;
	memset(sink, 0, sizeof(sink));
	st = wri_osd_sess_upper()->plan(f->sl[slot].up_ctx, c, &h, seglen, sink);
	check(st == WR_OK || st == WR_E_BUSY || st == WR_E_OSD_PROTO);
	if (st == WR_E_BUSY) {
		c->in_seq--;
		return;
	}
	if (st != WR_OK) { /* the connection fails */
		wr_errinfo e;

		memset(&e, 0, sizeof(e));
		e.status = st;
		e.module = WR_MOD_M2;
		c->state = WRI_M2_FAILED;
		f->sl[slot].up->closed(f->sl[slot].up_ctx, c, &e);
		f->sl[slot].used = 0;
		return;
	}
	if (sink[2].dst != NULL) { /* a destination is only ever an op's own output buffer, for an op that is SENT on this session */
		const wri_osd_op *op = (tid & 0xffffu) < f->o.n_op ? &f->o.op[tid & 0xffffu] : NULL;

		check(op != NULL && op->state == WRI_OP_SENT && op->tid == tid && op->sess == s && (op->flags & WRI_OPF_ZOMBIE) == 0u);
		check(sink[2].dst == op->out && sink[2].cap == op->out_cap && op->out_cap != 0u);
	}
	stored[0] = stored[1] = stored[2] = 0;
	if (sink[0].dst != NULL) {
		stored[0] = flen < sink[0].cap ? flen : sink[0].cap;
		memcpy(sink[0].dst, front, stored[0]);
	}
	if (sink[2].dst != NULL) {
		stored[2] = dlen < sink[2].cap ? dlen : sink[2].cap;
		memcpy(sink[2].dst, data, stored[2]);
	}
	wri_osd_sess_upper()->message(f->sl[slot].up_ctx, c, &h, stored);
}

static const uint8_t k_payload[600] = {0x5a};

static void do_reply(fz *f, rd *r)
{
	uint8_t a = rd8(r), b = rd8(r), c = rd8(r), d = rd8(r), e = rd8(r), g = rd8(r), vsel = rd8(r);
	static const int32_t results[9] = {0, 0, 0, -WRI_ERRNO_EAGAIN, -WRI_ERRNO_ENOENT, -WRI_ERRNO_EIO, -WRI_ERRNO_ENOSPC, 100, -WRI_ERRNO_EBLOCKLISTED};
	wri_osdc *o = &f->o;
	uint32_t sent[MAXO], n_sent = 0, i, s = 0, n_ops = 1, plen[WRI_OSD_OPS_MAX], dlen = 0;
	uint64_t tid;
	int32_t retry = 0;
	rframe fr;
	const wri_osd_op *op = NULL;

	for (i = o->head; i != WRI_NIL; i = o->op[i].next)
		if (o->op[i].state == WRI_OP_SENT && n_sent < MAXO)
			sent[n_sent++] = i;
	if (n_sent != 0u) {
		op = &o->op[sent[a % n_sent]];
		s = op->sess;
		tid = op->tid;
		n_ops = op->n_ops;
		retry = op->retry_attempt;
	} else {
		s = a % o->sess.n;
		tid = ((uint64_t)(1u + (a & 7u)) << 16) | (b % o->n_op);
		retry = -1;
	}
	switch (e & 7u) { /* a tid that is not quite the op's */
	case 3:
		tid ^= (uint64_t)1u << 16;
		break;
	case 4:
		tid += 1u;
		break;
	case 5:
		tid = 0;
		break;
	default:
		break;
	}
	switch (b & 3u) { /* operation count: the op's, one more, one, none */
	case 1:
		n_ops += 1u;
		break;
	case 2:
		n_ops = 1;
		break;
	case 3:
		n_ops = (b >> 2) & 1u ? 8u : 0u;
		break;
	default:
		break;
	}
	if (n_ops > WRI_OSD_OPS_MAX)
		n_ops = WRI_OSD_OPS_MAX;
	for (i = 0; i < n_ops; i++) {
		uint64_t want = op != NULL && i < op->n_ops && op->ops[i].code == WRI_OSD_OP_READ ? op->ops[i].len : 16u;

		plen[i] = (c & 1u) ? (uint32_t)want : ((c & 2u) ? (uint32_t)want + 1u : 0u);
		if (op != NULL && op->out == NULL && !(c & 4u))
			plen[i] = 0;
		if (plen[i] > 100u)
			plen[i] = 100u;
		dlen += plen[i];
	}
	switch (d & 3u) {
	case 1:
		retry = -1;
		break;
	case 2:
		retry += 1;
		break;
	case 3:
		retry = 9;
		break;
	default:
		break;
	}
	if (g & 1u)
		dlen += 1u; /* the data segment is longer than the lengths say */
	if ((g & 2u) && dlen != 0u)
		dlen -= 1u; /* or shorter */
	rf_reply(&fr, "o", n_ops, plen, results[(d >> 2) % 9u], retry);
	deliver(f, s, WRI_MSG_OSD_OPREPLY, tid, (vsel & 1u) ? 9 : 8, (vsel & 2u) ? 9 : 2, fr.b, fr.n, k_payload, dlen);
}

static void do_garbage(fz *f, rd *r)
{
	uint8_t a = rd8(r), b = rd8(r);
	size_t flen, dlen;
	const uint8_t *front = rdbytes(r, 4u + (size_t)(a % 200u), &flen);
	const uint8_t *data = rdbytes(r, (size_t)(b & 63u), &dlen);
	wri_osdc *o = &f->o;
	uint32_t i, s = a % o->sess.n;
	uint64_t tid = ((uint64_t)(1u + (a & 3u)) << 16) | (b % o->n_op);

	for (i = o->head; i != WRI_NIL; i = o->op[i].next)
		if (o->op[i].state == WRI_OP_SENT && (b & 0x80u) != 0u) {
			s = o->op[i].sess;
			tid = o->op[i].tid;
			break;
		}
	deliver(f, s, WRI_MSG_OSD_OPREPLY, tid, 8, 2, front, (uint32_t)flen, data, (uint32_t)dlen);
}

static void do_backoff(fz *f, rd *r)
{
	uint8_t a = rd8(r), b = rd8(r), c = rd8(r);
	wri_mbackoff m;
	uint8_t buf[512];
	uint32_t n, s = a % f->o.sess.n;
	static const uint8_t nm[3] = {'a', 'b', 'c'};

	memset(&m, 0, sizeof(m));
	m.pool = 2 + (int64_t)(b & 1u);
	m.pg_seed = (uint32_t)(c & 15u);
	m.map_epoch = f->m.epoch;
	m.id = 1u + (uint64_t)(b >> 1 & 7u);
	m.begin.pool = m.end.pool = m.pool;
	if ((c & 0x80u) != 0u) { /* one object: the engine's names are 'a'..'h' repeated, so a whole name is only matched by luck; the table keeps it exact */
		m.begin.oid = m.end.oid = nm;
		m.begin.oid_len = m.end.oid_len = 3;
		m.begin.hash = m.end.hash = (uint32_t)c * 2654435761u;
		m.begin.snap = m.end.snap = WRI_SNAP_NOSNAP;
	} else { /* the whole PG */
		m.begin.oid = m.end.oid = (const uint8_t *)"";
		m.end.max = 1;
		m.begin.snap = 0;
		m.end.snap = WRI_SNAP_NOSNAP;
	}
	n = rf_backoff(buf, sizeof(buf), &m, (uint8_t)((b & 0x80u) ? WRI_BACKOFF_BLOCK : WRI_BACKOFF_UNBLOCK));
	if (n != 0u)
		deliver(f, s, WRI_MSG_OSD_BACKOFF, 0, 1, 1, buf, n, NULL, 0);
}

static void do_knobs(fz *f, rd *r)
{
	uint8_t a = rd8(r), b = rd8(r);
	static const wr_status sends[4] = {WR_OK, WR_E_BUSY, WR_E_TOOBIG, WR_E_STATE};

	switch (a % 6u) {
	case 0:
		f->tx_idle = b & 1;
		if (f->tx_idle)
			memset(f->refd, 0, sizeof(f->refd)); /* the host consumed everything */
		break;
	case 1:
		f->send_st = sends[b & 3u];
		break;
	case 2:
		f->open_st = (b & 1u) ? WR_E_BUSY : WR_OK;
		break;
	case 3:
		f->have_ticket = b & 1;
		break;
	case 4:
		f->hs_free = b & 1;
		break;
	default:
		f->closing_holds = b & 1;
		break;
	}
}

static void do_pop(fz *f, rd *r)
{
	uint8_t a = rd8(r);
	wri_osdc *o = &f->o;
	uint32_t i = wri_osdc_pop_done(o), k;
	wri_osd_op *op;

	if (i == WRI_NIL) {
		check(o->done_len == 0u);
		return;
	}
	check(i < o->n_op);
	op = &o->op[i];
	check(op->state == WRI_OP_DONE && (op->flags & WRI_OPF_INRING) == 0u && f->owned[i] == 0u && (op->flags & WRI_OPF_ZOMBIE) == 0u);
	/* the buffer goes back to the owner now: no connection may still be about to send it (the property of wri_or_quiet_prev) */
	for (k = 0; k < f->n_slots; k++)
		check(!(f->sl[k].used && !f->sl[k].closing && f->refd[k][i]));
	f->n_pops++;
	f->owned[i] = 2;
	if (a & 1u) {
		wri_osdc_release(o, i);
		f->owned[i] = 0;
		check(op->state == WRI_OP_FREE);
	}
}

static void do_hostile(fz *f, rd *r)
{
	uint8_t a = rd8(r), b = rd8(r);
	wri_osdc *o = &f->o;
	uint32_t idx = (uint32_t)b % (o->n_op + 3u);
	const wri_osd_op *op = idx < o->n_op ? &o->op[idx] : NULL;
	uint8_t before = op != NULL ? op->state : 0;

	if (a & 1u) {
		wri_osdc_release(o, idx);
		if (op != NULL && f->owned[idx] == 2u && op->state == WRI_OP_FREE)
			f->owned[idx] = 0;
		else if (op != NULL && before != WRI_OP_DONE)
			check(op->state == before || op->state == WRI_OP_FREE); /* a live op cannot be released */
	} else if (a & 2u) {
		do_cancel(f, idx);
	} else {
		(void)wri_osdc_count_owner(o, (uint32_t)b << 8, 0xffffff00u);
		(void)wri_osdc_count_owner(o, 0, 0);
	}
}

static void do_step(fz *f, unsigned budget)
{
	f->sends_in_call = 0;
	(void)wri_osdc_step(&f->o, budget);
	check(f->sends_in_call <= budget);
}

static void run_op(fz *f, rd *r)
{
	uint8_t op = (uint8_t)(rd8(r) % 14u), a, b;

	switch (op) {
	case 0:
		do_submit(f, r);
		break;
	case 1:
		do_cancel(f, rd8(r) % (f->o.n_op + 3u));
		break;
	case 2:
		do_map(f, r);
		break;
	case 3: {
		uint16_t ms = rd16(r);
		uint8_t sc = rd8(r);

		f->x.now.mono_ms += (uint64_t)ms * (1u + (sc & 7u));
		f->x.now.wall_ms = (sc & 8u) ? 1700000000000ull + f->x.now.mono_ms : 0u;
		do_step(f, 4);
		break;
	}
	case 4:
		do_step(f, rd8(r) & 7u);
		break;
	case 5:
		a = rd8(r);
		b = rd8(r);
		do_ready(f, a, b);
		break;
	case 6:
		a = rd8(r);
		b = rd8(r);
		do_closed(f, a, b);
		break;
	case 7:
		do_reply(f, r);
		break;
	case 8:
		do_garbage(f, r);
		break;
	case 9:
		do_backoff(f, r);
		break;
	case 10:
		do_knobs(f, r);
		break;
	case 11:
		do_pop(f, r);
		break;
	case 12:
		do_hostile(f, r);
		break;
	default: {
		unsigned i;

		for (i = 0; i < f->n_slots; i++)
			if (f->sl[i].used && f->sl[i].closing)
				f->sl[i].used = 0;
		f->x.now.mono_ms += 20000u + rd16(r);
		do_step(f, 3);
		break;
	}
	}
	check_all(f);
}

/* ---- quiesce: every fault lifted, every op answered ------------------------------------------------------------------------------------ */

static void answer_all(fz *f)
{
	wri_osdc *o = &f->o;
	uint32_t i;
	uint32_t plen[WRI_OSD_OPS_MAX];
	rframe fr;

	for (i = o->head; i != WRI_NIL; i = o->op[i].next) {
		const wri_osd_op *op = &o->op[i];
		uint32_t k, dlen = 0;

		if (op->state != WRI_OP_SENT)
			continue;
		for (k = 0; k < op->n_ops; k++) {
			plen[k] = (op->ops[k].code == WRI_OSD_OP_READ && op->out != NULL) ? (uint32_t)op->ops[k].len : 0u;
			if (plen[k] > op->out_cap || dlen + plen[k] > op->out_cap)
				plen[k] = 0;
			if (plen[k] > 100u)
				plen[k] = 100u;
			dlen += plen[k];
		}
		rf_reply(&fr, "o", op->n_ops, plen, 0, op->retry_attempt);
		deliver(f, op->sess, WRI_MSG_OSD_OPREPLY, op->tid, 8, 2, fr.b, fr.n, k_payload, dlen);
		return; /* the list may have changed: one reply per pass */
	}
}

static void quiesce(fz *f)
{
	wri_osdc *o = &f->o;
	unsigned round, i;

	f->have_ticket = f->hs_free = f->tx_idle = 1;
	f->closing_holds = 0;
	f->open_st = f->send_st = WR_OK;
	for (i = 0; i < f->n_slots; i++)
		if (f->sl[i].used && f->sl[i].closing)
			f->sl[i].used = 0;
	f->m.present[0] = f->m.present[1] = 1;
	f->m.pstatus[0] = f->m.pstatus[1] = WR_OK;
	f->m.pflags[0] = f->m.pflags[1] = 0;
	f->m.flags = 0;
	f->m.pg_num = 8;
	for (i = 0; i < 16u; i++)
		f->m.prim[i] = (int)(i % 3u);
	for (i = 0; i < 4u; i++)
		f->m.addr_var[i] = 0;
	{ /* epochs only grow in a real cluster, and this target lets the scripted map go back: end above every epoch an operation saw, or an
	   * operation for a pool the map never has would wait for a newer map for ever (map_stale_ms 0) */
		uint32_t hi = f->m.epoch < 100u ? 100u : f->m.epoch;

		/* the epoch the engine last saw counts too: a held operation looks at a map only when the epoch differs from that one, and the
		 * scripted map may have gone back below it since (a finding of the long run: ending on the very epoch the engine had seen left a
		 * paused write held for ever, because no operation had recorded that epoch) */
		if (o->map_epoch_seen > hi)
			hi = o->map_epoch_seen;
		for (i = 0; i < o->n_op; i++) {
			if (o->op[i].sub_epoch > hi)
				hi = o->op[i].sub_epoch;
			if (o->op[i].sent_epoch > hi)
				hi = o->op[i].sent_epoch;
		}
		f->m.epoch = hi + 10u;
	}
	for (i = 0; i < o->sess.n; i++)
		wri_osd_sess_reset(&o->sess, i, NULL); /* an orderly close forgets every backoff */
	for (round = 0; round < 400u; round++) {
		uint32_t s, idx;

		f->x.now.mono_ms += 11000u;
		do_step(f, 8);
		for (s = 0; s < o->sess.n; s++)
			do_ready(f, s, 0);
		do_step(f, 8);
		for (i = 0; i < 2u * MAXO; i++)
			answer_all(f);
		while ((idx = wri_osdc_pop_done(o)) != WRI_NIL) {
			f->owned[idx] = 0;
			wri_osdc_release(o, idx);
		}
		for (idx = 0; idx < o->n_op; idx++)
			if (f->owned[idx] == 2u) {
				wri_osdc_release(o, idx);
				f->owned[idx] = 0;
			}
		check_all(f);
		if (o->n_inflight == 0u && o->done_len == 0u)
			break;
	}
	/* everything ended: nothing live, no zombie, no byte accounted, the free list whole */
	check(o->n_inflight == 0u && o->inflight_bytes == 0u && o->head == WRI_NIL && o->tail == WRI_NIL && o->done_len == 0u);
	check(o->n_free == o->n_op && o->n_ctl_used == 0u && o->zused == 0u && o->n_zombies == o->n_zombies_done);
}

/* ---- the entry ---------------------------------------------------------------------------------------------------------------------- */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint32_t zb[4] = {0, 256, 1024, 8192};
	static const uint32_t ib[4] = {3000, 20000, 1u << 20, 1u << 20};
	static const uint16_t bo[4] = {1, 2, 4, 8};
	fz *f;
	rd r;
	size_t need_a = 0, need_b = 0;
	wri_osd_link l;
	wri_osd_map_ops mo;
	unsigned steps = 0, i;
	uint8_t b0, b1;

	if (size < 2u || size > MAX_INPUT)
		return 0;
	f = (fz *)calloc(1, sizeof(*f));
	if (f == NULL)
		return 0;
	r.p = data, r.n = size, r.pos = 0;
	b0 = rd8(&r);
	b1 = rd8(&r);
	wr_config_profile_harness(&f->x.cfg);
	f->x.cfg.max_ops = (uint16_t)(3u + (b0 & 7u));
	f->x.cfg.ctl_ops = 1;
	f->x.cfg.osd_sessions = (uint16_t)(1u + ((b0 >> 3) & 3u));
	f->x.cfg.zombie_bytes = zb[(b0 >> 5) & 3u];
	f->x.cfg.osd_flags = (uint8_t)(((b0 & 0x80u) ? 0u : WR_OSDF_FULL_TRY) | ((b1 & 1u) ? 0u : WR_OSDF_HONOR_PAUSE));
	f->x.cfg.map_stale_ms = (b1 & 2u) ? 0u : 20000u;
	f->x.cfg.inflight_bytes_max = ib[(b1 >> 2) & 3u];
	f->x.cfg.op_timeout_ms = (b1 & 16u) ? 2000u : 5000u;
	f->x.cfg.osd_connect_timeout_ms = 2000;
	f->x.cfg.osd_front_cap = 2048;
	f->x.cfg.backoff_slots = bo[(b1 >> 5) & 3u];
	f->x.cfg.max_snaps = 8;
	f->x.cfg.osd_idle_ms = (b1 & 128u) ? 3000u : 0u;
	f->x.now.mono_ms = 100000;
	f->honor_pause = (f->x.cfg.osd_flags & WR_OSDF_HONOR_PAUSE) != 0u;
	f->full_try = (f->x.cfg.osd_flags & WR_OSDF_FULL_TRY) != 0u;
	if (wri_osdc_mem(&f->x.cfg, &need_a, &need_b) != WR_OK) {
		free(f);
		return 0;
	}
	f->mem = (uint8_t *)calloc(1, need_a + 128u);
	f->bulk = (uint8_t *)calloc(1, need_b + 128u);
	if (f->mem == NULL || f->bulk == NULL) {
		free(f->mem), free(f->bulk), free(f);
		return 0;
	}
	wri_arena_init(&f->arena, (uint8_t *)(((uintptr_t)f->mem + 63u) & ~(uintptr_t)63u), need_a + 64u);
	wri_arena_init(&f->barena, (uint8_t *)(((uintptr_t)f->bulk + 63u) & ~(uintptr_t)63u), need_b + 64u);
	f->n_slots = f->x.cfg.osd_sessions + 2u > NSLOT ? NSLOT : f->x.cfg.osd_sessions + 2u;
	f->have_ticket = f->hs_free = f->tx_idle = 1;
	f->m.epoch = 10;
	f->m.pg_num = 8;
	f->m.present[0] = 1;
	for (i = 0; i < 16u; i++)
		f->m.prim[i] = (int)(i % 3u);
	memset(&l, 0, sizeof(l));
	l.ctx = f;
	l.open = l_open;
	l.close = l_close;
	l.send = l_send;
	l.tx_idle = l_tx_idle;
	l.have_ticket = l_ticket;
	l.handshake_free = l_hs;
	memset(&mo, 0, sizeof(mo));
	mo.ctx = &f->m;
	mo.epoch = m_epoch;
	mo.flags = m_flags;
	mo.pool_info = m_pool_info;
	mo.target = m_target;
	if (wri_osdc_init(&f->o, &f->x, &f->arena, &f->barena, &mo, &l) != WR_OK) {
		free(f->mem), free(f->bulk), free(f);
		return 0;
	}
	check_all(f);
	while (r.pos < r.n && steps++ < MAX_STEPS)
		run_op(f, &r);
	quiesce(f);
	free(f->mem);
	free(f->bulk);
	free(f);
	return 0;
}
