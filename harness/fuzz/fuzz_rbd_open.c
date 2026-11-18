/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the RBD open machine (core/src/rbd/wri_rbd_open*.c): hostile answers to the control reads, played against the REAL image layer and the
 * REAL request engine (wri_osdc over a link that never connects: the control reads stay in the table and the harness completes them by hand, with a reply
 * of its own making), a scripted map, a clock, and an owner that opens, refreshes, fails and closes images in any order.
 *
 * Input layout:
 *
 *   byte 0   bits 0-1 max_snaps (2 / 4 / 8 / 8), bits 2-3 ctl_ops (1 / 2 / 3 / 3), bits 4-5 max_images (1 / 2 / 3 / 3), bit 6 hdr_refresh_ms = 0 (else 1000),
 *            bit 7 the pools table has no n_full hook
 *   byte 1   bit 0 map present (epoch 10; else none yet), bit 1 pool 1 present, bit 2 pool 0 in pool-snapshot mode, bit 3 pool 1 unsupported,
 *            bit 4 map_stale_ms = 2000 (else 0: the wait of POOLS for a full map is not bounded)
 *   rest     actions, an opcode byte (mod 10) and its arguments:
 *              0 start    flags: writer, by id, data pool named, "ghost" for the data pool, open timeout (none / 300 / 2000 / 2000), name and id both
 *              1 step     one pass: the I/O half collects (control reads stay DONE), the open machine runs
 *              2 time     u8 x 25 ms, then a pass
 *              3 answer   image, mode, then the reply of the control read in flight: a valid one built from 14 parameter bytes (header, extra or id) and
 *                         mutated (one byte, a cut, a negative rval, a wrong stored length), or raw bytes; status OK or an errno
 *              4 map      pool, field: present, pool-snapshot flag, unsupported status, id change, a full map adopted (n_full + 1), epoch 0 / 10
 *              5 close    image, flags
 *              6 refresh  image: wri_rbd_open_refresh_now
 *              7 fail     image: wri_rbd_img_fail with a status
 *              8 idle     a pass without time (9: one millisecond)
 *
 * Properties (a violated one traps): no crash or undefined behaviour (ASan / UBSan); every image is FREE, OPENING, OPEN, FAILED or CLOSING and its fields agree
 * with that state (a FAILED image has its first failure and no read in flight, an OPEN one came through the profile: order 12 to 25, a prefix that makes a valid
 * object name, features inside the profile, a writer with no flags and no parent and a context of at most max_snaps ids, a snapshot context that is valid);
 * the control read of an image is a live control operation of the engine with the image's owner tag; no control slot is ever lost (the engine's count equals the
 * reads in flight plus the finished ones nobody released yet) and after every image is closed and the machine ran a few passes all of them are back; a closed
 * slot has a new generation; the first failure of an image is never replaced.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wri_ctx.h"
#include "wri_le.h"
#include "wri_mem.h"
#include "wri_osd_req.h"
#include "wri_rbd_io.h"
#include "wri_rbd_open.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAX_INPUT 8192u
#define MAX_STEPS 300u
#define IMG_CTL 1024u

static void check_at(int cond, unsigned line)
{
	if (!cond) {
		fprintf(stderr, "fuzz_rbd_open: property violated at line %u\n", line);
		__builtin_trap();
	}
}

#define check(cond) check_at((cond) != 0, (unsigned)__LINE__)

/* ---- the scripted map and the pools table -------------------------------------------------------------------------------------------- */

typedef struct fzmap {
	uint32_t epoch;
	int present[2];
	wr_status status[2];
	uint64_t flags[2];
	int64_t id[2];
} fzmap;

static uint32_t m_epoch(void *c) { return ((fzmap *)c)->epoch; }
static uint32_t m_flags(void *c) { (void)c; return 0; }

static wr_status m_pool_info(void *c, wr_pool_h h, wr_pool_info *out)
{
	fzmap *m = (fzmap *)c;

	memset(out, 0, sizeof(*out));
	if (m->epoch == 0)
		return WR_E_MAP_NONE;
	if (h >= 2u || !m->present[h])
		return WR_E_POOL_NOT_FOUND;
	out->id = m->id[h];
	out->flags = m->flags[h];
	out->size = 3;
	out->pg_num = out->pgp_num = 8;
	out->status = m->status[h];
	return WR_OK;
}

static wr_status m_target(void *c, wr_pool_h h, const wr_object_id *oid, wr_target *out)
{
	(void)c;
	(void)h;
	(void)oid;
	memset(out, 0, sizeof(*out));
	return WR_E_PLACE_UNMAPPABLE; /* nothing is ever placed: the control reads wait in the table until the harness answers them */
}

typedef struct fz {
	wri_ctx x;
	uint8_t *mem, *obj;
	wri_arena arena, oarena;
	wri_osdc o;
	wri_rbd L;
	wri_rbd_pools pools;
	fzmap m;
	uint32_t n_full;
	int32_t first_err[4];
} fz;

static wr_status p_track(void *ctx, const char *name, wr_pool_h *h)
{
	(void)ctx;
	if (strcmp(name, "meta") == 0)
		*h = 0;
	else if (strcmp(name, "data") == 0 || strcmp(name, "ghost") == 0)
		*h = 1;
	else
		return WR_E_TOOBIG;
	return WR_OK;
}

static uint32_t p_nfull(void *ctx) { return ((fz *)ctx)->n_full; }

/* The link never connects: no session, no traffic. */
static wr_status l_open(void *ctx, const wri_eaddr *addr, const wri_m2_upper *up, void *up_ctx, uint16_t *slot)
{
	(void)ctx;
	(void)addr;
	(void)up;
	(void)up_ctx;
	(void)slot;
	return WR_E_BUSY;
}
static void l_close(void *ctx, uint16_t s, wr_status why) { (void)ctx; (void)s; (void)why; }
static wr_status l_send(void *ctx, uint16_t s, const wri_m2_msg_out *m) { (void)ctx; (void)s; (void)m; return WR_E_BUSY; }
static int l_idle(void *ctx, uint16_t s) { (void)ctx; (void)s; return 1; }
static int l_no(void *ctx) { (void)ctx; return 0; }

/* ---- the reply the harness hands to a control read ---------------------------------------------------------------------------------- */

typedef struct rd {
	const uint8_t *p;
	size_t n, pos;
} rd;

static uint8_t rb(rd *r) { return r->pos < r->n ? r->p[r->pos++] : 0u; }

static void put_u32(uint8_t *o, size_t *n, uint32_t v) { wri_le32_put(o + *n, v); *n += 4; }
static void put_u64(uint8_t *o, size_t *n, uint64_t v) { wri_le64_put(o + *n, v); *n += 8; }

/* The eight outputs of a header read from 14 parameter bytes. Returns the total, lens[] the per-operation lengths. */
static size_t build_header(uint8_t *out, uint32_t lens[8], const uint8_t *q)
{
	size_t n = 0, at;
	unsigned i, ns = q[8] % 12u;
	uint64_t seq = 100u + q[12], feat = (uint64_t)q[5] | ((uint64_t)(q[6] & 0x1fu) << 8) | ((q[13] & 1u) != 0 ? 1ull << 40 : 0u);

	at = n;
	out[n++] = (uint8_t)(12u + q[0] % 16u); /* order 12 .. 27 */
	put_u64(out, &n, ((uint64_t)q[1] << 12) | ((uint64_t)q[2] << 20) | q[3]);
	lens[0] = (uint32_t)(n - at);
	at = n;
	{
		unsigned len = (q[13] & 2u) != 0 ? ((q[13] & 4u) != 0 ? 0u : 79u + (q[13] >> 4)) : 9u + q[13] % 20u;

		put_u32(out, &n, len);
		for (i = 0; i < len; i++)
			out[n++] = (uint8_t)((q[13] & 8u) != 0 && i == 3u ? 0x01u : 'a' + i % 20u);
	}
	lens[1] = (uint32_t)(n - at);
	at = n;
	put_u64(out, &n, feat);
	put_u64(out, &n, 0);
	lens[2] = (uint32_t)(n - at);
	at = n;
	put_u64(out, &n, q[7] & 3u);
	lens[3] = (uint32_t)(n - at);
	at = n;
	put_u64(out, &n, seq);
	put_u32(out, &n, ns);
	for (i = 0; i < ns; i++)
		put_u64(out, &n, seq - i - ((q[12] & 1u) != 0 && i == 2u ? 100u : 0u)); /* a descending run, sometimes not */
	lens[4] = (uint32_t)(n - at);
	at = n;
	put_u64(out, &n, q[9] % 3u == 0 ? (uint64_t)-1 : 1u + q[9] % 3u); /* -1, 2 or 3 */
	lens[5] = (uint32_t)(n - at);
	at = n;
	out[n++] = 1; /* parent_get: struct v1, compat 1 */
	out[n++] = 1;
	{
		size_t len_at = n, body;

		n += 4;
		body = n;
		put_u64(out, &n, (q[10] & 1u) != 0 ? 2u : (uint64_t)-1);
		put_u32(out, &n, 0);
		if ((q[10] & 1u) != 0) {
			put_u32(out, &n, 3);
			out[n++] = 'a';
			out[n++] = 'b';
			out[n++] = 'c';
		} else {
			put_u32(out, &n, 0);
		}
		put_u64(out, &n, (q[10] & 1u) != 0 ? 5u : 0xfffffffffffffffeull);
		wri_le32_put(out + len_at, (uint32_t)(n - body));
	}
	lens[6] = (uint32_t)(n - at);
	at = n;
	out[n++] = (uint8_t)(q[11] & 1u);
	if ((q[11] & 1u) != 0)
		put_u64(out, &n, 1ull << 26);
	lens[7] = (uint32_t)(n - at);
	return n;
}

static size_t build_extra(uint8_t *out, uint32_t lens[8], const uint8_t *q, unsigned n_ops)
{
	size_t n = 0;

	if (n_ops == 2u || (q[11] & 0x80u) == 0) {
		put_u64(out, &n, (q[11] & 2u) != 0 ? 1ull << 22 : (uint64_t)q[1] << 12);
		put_u64(out, &n, (q[11] & 4u) != 0 ? 1u : q[2]);
		lens[0] = 16;
	}
	if (n_ops == 2u) {
		put_u64(out, &n, q[3] & 3u);
		lens[1] = 8;
	} else if (n_ops == 1u && (q[11] & 0x80u) != 0) {
		put_u64(out, &n, q[3] & 3u);
		lens[0] = 8;
	}
	return n;
}

static size_t build_id(uint8_t *out, uint32_t lens[8], const uint8_t *q)
{
	size_t n = 0;
	unsigned i, len = (q[0] & 0x10u) != 0 ? (unsigned)(q[1] % 70u) : 1u + q[1] % 20u;

	put_u32(out, &n, len);
	for (i = 0; i < len; i++)
		out[n++] = (uint8_t)((q[0] & 0x20u) != 0 && i == 2u ? '-' : 'a' + i % 26u);
	lens[0] = (uint32_t)n;
	return n;
}

/* Answer the control read of image k as the cluster might: complete the engine's op with a reply made from the input. */
static void answer(fz *f, rd *r)
{
	unsigned k = rb(r) % f->L.n_img;
	uint8_t mode = rb(r), q[14], raw[256];
	uint32_t lens[8] = {0}, idx;
	wri_osd_op *op;
	wri_rbd_img *m = &f->L.img[k];
	size_t n = 0, i;
	wr_status st = WR_OK;
	int32_t result = 0;

	for (i = 0; i < 14u; i++)
		q[i] = rb(r);
	idx = m->ctl_op;
	if (idx == WRI_NIL)
		return;
	op = wri_osdc_at(&f->o, idx);
	if (op == NULL || op->state == WRI_OP_DONE || op->state == WRI_OP_FREE)
		return;
	if ((mode & 7u) >= 4u) { /* the whole message failed */
		static const int32_t errs[4] = {-2, -108, -1, -5};

		result = errs[(mode & 7u) - 4u];
		st = wri_osd_errno_status(result);
	}
	if ((mode & 8u) != 0 && st == WR_OK) { /* raw bytes: every operation gets a slice of what the input holds */
		size_t want = rb(r);

		for (i = 0; i < want && r->pos < r->n && n < sizeof(raw); i++)
			raw[n++] = rb(r);
		for (i = 0; i < op->n_ops; i++)
			lens[i] = (uint32_t)(n / op->n_ops) + (i + 1u == op->n_ops ? (uint32_t)(n % op->n_ops) : 0u);
	} else if (st == WR_OK) {
		uint8_t big[600];

		if (m->ros == (uint8_t)WRI_ROS_HEADER || m->ros == (uint8_t)WRI_ROS_REFRESH)
			n = build_header(big, lens, q);
		else if (m->ros == (uint8_t)WRI_ROS_EXTRA)
			n = build_extra(big, lens, q, op->n_ops);
		else
			n = build_id(big, lens, q);
		if ((mode & 0x10u) != 0 && n != 0) /* one byte replaced */
			big[q[12] % n] = (uint8_t)(q[13] ^ 0x5au);
		if (n > sizeof(raw))
			n = sizeof(raw);
		memcpy(raw, big, n);
		if ((mode & 0x20u) != 0 && n != 0) { /* cut: the operations that lose bytes say so, the later ones are empty */
			size_t keep = q[12] % n, left = keep;

			for (i = 0; i < op->n_ops; i++) {
				uint32_t take = (uint32_t)(left < lens[i] ? left : lens[i]);

				lens[i] = take;
				left -= take;
			}
			n = keep;
		}
	}
	for (i = 0; i < op->n_ops; i++) {
		op->ops[i].out_len = lens[i];
		op->ops[i].rval = (mode & 0x40u) != 0 && i == (size_t)(q[11] % op->n_ops) ? -61 : 0;
	}
	if (n > op->out_cap)
		n = op->out_cap;
	if (n != 0 && op->out != NULL)
		memcpy(op->out, raw, n);
	op->out_stored = (uint32_t)n + ((mode & 0x80u) != 0 ? 1u : 0u);
	if (op->out_stored > op->out_cap)
		op->out_stored = op->out_cap;
	op->result = result;
	wri_or_complete(&f->o, idx, st);
}

/* ---- invariants --------------------------------------------------------------------------------------------------------------------- */

static void check_img(fz *f, uint32_t k)
{
	const wri_rbd_img *m = &f->L.img[k];
	const wri_osdc *o = &f->o;

	check(m->slot == k && m->snapc.cap == f->x.cfg.max_snaps && m->ctl_in != NULL && m->ctl_out != NULL && m->snapc.snaps != NULL);
	check(m->state <= (uint8_t)WR_IMG_CLOSING);
	if (m->ctl_op != WRI_NIL) {
		const wri_osd_op *op;

		check(m->ctl_op < o->n_op);
		op = &o->op[m->ctl_op];
		check(op->state != WRI_OP_FREE || (op->flags & WRI_OPF_ALLOC) != 0u);
		check((op->flags & WRI_OPF_CONTROL) != 0u && op->owner == (((uint32_t)m->slot << 16) | m->gen));
		check(m->state == (uint8_t)WR_IMG_OPENING || m->state == (uint8_t)WR_IMG_OPEN);
	}
	switch ((wr_image_state)m->state) {
	case WR_IMG_FREE:
		check(m->ctl_op == WRI_NIL && m->err.status == WR_OK && m->id[0] == '\0' && m->n_reqs == 0u && !m->writable && m->snapc.n == 0u);
		break;
	case WR_IMG_OPENING:
		check(!m->writable && m->ros >= (uint8_t)WRI_ROS_POOLS && m->ros <= (uint8_t)WRI_ROS_EXTRA && m->err.status == WR_OK);
		break;
	case WR_IMG_FAILED:
		check(m->err.status != WR_OK && m->ctl_op == WRI_NIL && m->ros == (uint8_t)WRI_ROS_IDLE && m->next_refresh_ms == WR_DEADLINE_NONE);
		check(f->first_err[k] == 0 || f->first_err[k] == m->err.status); /* the first failure stays */
		break;
	case WR_IMG_CLOSING:
		check(m->ctl_op == WRI_NIL && m->was_open == 1u);
		break;
	case WR_IMG_OPEN:
	default:
		check(m->was_open == 1u && m->ros >= (uint8_t)WRI_ROS_READY && m->ros <= (uint8_t)WRI_ROS_REFRESH && m->err.status == WR_OK);
		check(m->order >= 12u && m->order <= 25u && m->prefix[0] != '\0' && strlen(m->prefix) <= WRI_RBD_PREFIX_LEN_MAX);
		check(m->features == (m->features & (m->want_write ? 0xa3ull : 0x1ffull)));
		check(m->snapc.n <= m->snapc.cap && wri_snapc_valid(&m->snapc));
		check(m->writable == (m->want_write ? 1u : 0u));
		if (m->writable) {
			check(m->flags == 0u && !m->hdr.has_parent && !m->hdr.has_overlap && m->snapc.n <= f->x.cfg.max_snaps);
			/* with a period there is always a next refresh; without one only a refresh that was asked for and is pending has a time */
			check(f->x.cfg.hdr_refresh_ms != 0u ? m->next_refresh_ms != WR_DEADLINE_NONE
							    : (m->ros == (uint8_t)WRI_ROS_READY) == (m->next_refresh_ms == WR_DEADLINE_NONE));
		} else {
			check(m->next_refresh_ms == WR_DEADLINE_NONE && m->ros == (uint8_t)WRI_ROS_READY);
		}
		check(m->size == m->hdr.size && m->order == m->hdr.order);
		break;
	}
}

static void check_all(fz *f)
{
	const wri_osdc *o = &f->o;
	uint32_t i, claimed = 0, ctl = 0, nfree = 0, live = 0, ring = 0, popped = 0;

	for (i = 0; i < f->L.n_img; i++) {
		check_img(f, i);
		claimed += f->L.img[i].ctl_op != WRI_NIL;
	}
	for (i = o->free_head; i != WRI_NIL; i = o->op[i].next) {
		check(nfree < o->n_op);
		nfree++;
	}
	for (i = o->head; i != WRI_NIL; i = o->op[i].next) {
		check(live < o->n_op);
		live++;
	}
	for (i = 0; i < o->n_op; i++) {
		const wri_osd_op *op = &o->op[i];

		ring += (op->flags & WRI_OPF_INRING) != 0u;
		popped += op->state == WRI_OP_DONE && (op->flags & WRI_OPF_INRING) == 0u;
		ctl += (op->state != WRI_OP_FREE || (op->flags & WRI_OPF_ALLOC) != 0u) && (op->flags & WRI_OPF_CONTROL) != 0u;
	}
	check(nfree == o->n_free && live == o->n_inflight && ring == o->done_len && nfree + live + ring + popped == o->n_op);
	check(ctl == o->n_ctl_used && ctl >= claimed);
	/* every control op that is not an image's read is a finished one waiting to be released (or in the ring) */
	for (i = 0; i < o->n_op; i++) {
		const wri_osd_op *op = &o->op[i];

		if (op->state == WRI_OP_FREE || (op->flags & WRI_OPF_CONTROL) == 0u)
			continue;
		if (op->state != WRI_OP_DONE) {
			uint32_t slot = op->owner >> 16, own = 0;

			if (slot < f->L.n_img)
				own = f->L.img[slot].ctl_op == i && op->owner == (((uint32_t)slot << 16) | f->L.img[slot].gen);
			check(own); /* a live control read that no image waits for is a leak (a cancelled one is DONE at once) */
		}
	}
}

/* One pass of the glue: the engine, the machine, the I/O half's collect (control reads stay DONE). */
static void pass(fz *f)
{
	uint64_t dl = WR_DEADLINE_NONE;
	uint32_t img;
	wr_status st;
	unsigned i;

	for (i = 0; i < 3u; i++) {
		int more = wri_osdc_step(&f->o, 8);

		more |= wri_rbd_open_step(&f->L, &dl);
		(void)wri_rbd_io_collect(&f->L);
		while (wri_rbd_io_take_fatal(&f->L, &img, &st))
			;
		if (!more)
			break;
	}
}

/* wri_rbd_close is must-check and a (void) cast does not silence gcc: the status is only a refusal of a bad slot or flag here. */
static wr_status do_close(fz *f, uint32_t slot, uint32_t flags)
{
	wr_status st = wri_rbd_close(&f->L, slot, flags);

	check(st == WR_OK || st == WR_E_INVAL);
	return st;
}

static void note_fail(fz *f)
{
	uint32_t k;

	for (k = 0; k < f->L.n_img && k < 4u; k++) {
		const wri_rbd_img *m = &f->L.img[k];

		if (m->state == (uint8_t)WR_IMG_FAILED && f->first_err[k] == 0)
			f->first_err[k] = m->err.status;
		if (m->state == (uint8_t)WR_IMG_FREE)
			f->first_err[k] = 0;
	}
}

static int setup(fz *f, uint8_t b0, uint8_t b1)
{
	static const uint16_t snaps[4] = {2, 4, 8, 8};
	size_t need_a = 0, need_b = 0, need_l = 0;
	wr_config *c = &f->x.cfg;
	wri_osd_link l;
	wri_osd_map_ops mo;

	memset(f, 0, sizeof(*f));
	wr_config_profile_harness(c);
	c->osd_sessions = 1;
	c->max_ops = 12;
	c->ctl_ops = (uint16_t)(1u + ((b0 >> 2) & 3u) % 3u);
	c->max_images = (uint16_t)(1u + ((b0 >> 4) & 3u) % 3u);
	c->max_reqs = 4;
	c->max_snaps = snaps[b0 & 3u];
	c->backoff_slots = 2;
	c->osd_front_cap = 2048;
	c->op_bytes_max = 1u << 20;
	c->inflight_bytes_max = 1u << 22;
	c->zombie_bytes = 0;
	c->op_timeout_ms = 5000;
	c->osd_connect_timeout_ms = 1000;
	c->hdr_refresh_ms = (b0 & 0x40u) != 0 ? 0u : 1000u;
	c->img_ctl_bytes = IMG_CTL;
	c->map_stale_ms = (b1 & 0x10u) != 0 ? 2000u : 0u;
	c->osd_flags = WR_OSDF_FULL_TRY | WR_OSDF_HONOR_PAUSE;
	f->x.now.mono_ms = 1000;
	f->m.epoch = (b1 & 1u) != 0 ? 10u : 0u;
	f->m.present[0] = 1;
	f->m.present[1] = (b1 & 2u) != 0;
	f->m.id[0] = 2;
	f->m.id[1] = 3;
	f->m.flags[0] = (b1 & 4u) != 0 ? WR_POOL_F_POOL_SNAPS : 0u;
	f->m.status[1] = (b1 & 8u) != 0 ? WR_E_POOL_UNSUPPORTED : WR_OK;
	f->n_full = f->m.epoch != 0 ? 1u : 0u;
	memset(&mo, 0, sizeof(mo));
	mo.ctx = &f->m;
	mo.epoch = m_epoch;
	mo.flags = m_flags;
	mo.pool_info = m_pool_info;
	mo.target = m_target;
	memset(&l, 0, sizeof(l));
	l.ctx = f;
	l.open = l_open;
	l.close = l_close;
	l.send = l_send;
	l.tx_idle = l_idle;
	l.have_ticket = l_no;
	l.handshake_free = l_no;
	if (wri_osdc_mem(c, &need_a, &need_b) != WR_OK || wri_rbd_mem(c, &need_l) != WR_OK)
		return 0;
	f->mem = (uint8_t *)calloc(1, need_a + need_l + 256u);
	f->obj = (uint8_t *)calloc(1, need_b + 64u);
	if (f->mem == NULL || f->obj == NULL)
		return 0;
	wri_arena_init(&f->arena, (uint8_t *)(((uintptr_t)f->mem + 63u) & ~(uintptr_t)63u), need_a + need_l + 128u);
	wri_arena_init(&f->oarena, (uint8_t *)(((uintptr_t)f->obj + 63u) & ~(uintptr_t)63u), need_b);
	if (wri_osdc_init(&f->o, &f->x, &f->arena, &f->oarena, &mo, &l) != WR_OK)
		return 0;
	if (wri_rbd_init(&f->L, &f->x, &f->arena, &f->o) != WR_OK)
		return 0;
	f->pools.ctx = f;
	f->pools.track = p_track;
	f->pools.n_full = (b0 & 0x80u) != 0 ? NULL : p_nfull;
	return 1;
}

static void start(fz *f, rd *r)
{
	uint8_t a = rb(r);
	wr_image_params p;
	uint32_t slot;
	static const uint32_t tmo[4] = {0, 300, 2000, 2000};

	memset(&p, 0, sizeof(p));
	p.size = (uint32_t)sizeof(p);
	p.pool = "meta";
	p.snap_id = WR_SNAP_HEAD;
	p.want_write = (uint8_t)(a & 1u);
	if ((a & 2u) != 0) {
		p.id = "ab12cd34ef56";
		if ((a & 0x40u) != 0)
			p.name = "shown";
	} else {
		p.name = "fuzz-image";
	}
	if ((a & 4u) != 0)
		p.data_pool = (a & 8u) != 0 ? "ghost" : "data";
	p.open_timeout_ms = tmo[(a >> 4) & 3u];
	if (wri_rbd_open_start(&f->L, &f->pools, &p, &slot) == WR_OK) {
		check(slot < f->L.n_img && f->L.img[slot].state == (uint8_t)WR_IMG_OPENING && f->L.img[slot].ros == (uint8_t)WRI_ROS_POOLS);
	}
}

static void map_change(fz *f, rd *r)
{
	uint8_t a = rb(r);
	unsigned h = a & 1u;

	switch ((a >> 1) & 7u) {
	case 0:
		f->m.present[h] = !f->m.present[h];
		break;
	case 1:
		f->m.flags[h] ^= WR_POOL_F_POOL_SNAPS;
		break;
	case 2:
		f->m.status[h] = f->m.status[h] == WR_OK ? WR_E_POOL_UNSUPPORTED : WR_OK;
		break;
	case 3:
		f->m.id[h] += 100;
		break;
	case 4:
		f->n_full++;
		break;
	case 5:
		f->m.epoch = f->m.epoch == 0 ? 10u : 0u;
		break;
	default:
		f->m.present[h] = 1;
		f->n_full++;
		break;
	}
}

static void run(fz *f, const uint8_t *data, size_t size)
{
	rd r;
	unsigned steps;

	r.p = data + 2;
	r.n = size - 2u;
	r.pos = 0;
	for (steps = 0; steps < MAX_STEPS && r.pos < r.n; steps++) {
		uint8_t opc = rb(&r) % 10u;
		unsigned k;

		switch (opc) {
		case 0:
			start(f, &r);
			break;
		case 1:
		case 8:
			pass(f);
			break;
		case 2:
			f->x.now.mono_ms += (uint64_t)rb(&r) * 25u;
			pass(f);
			break;
		case 3:
			answer(f, &r);
			pass(f);
			break;
		case 4:
			map_change(f, &r);
			pass(f);
			break;
		case 5:
			k = rb(&r) % f->L.n_img;
			(void)do_close(f, k, rb(&r) & 1u);
			break;
		case 6:
			wri_rbd_open_refresh_now(&f->L, rb(&r) % f->L.n_img);
			break;
		case 7: {
			wr_errinfo why;

			memset(&why, 0, sizeof(why));
			why.status = (wr_status)(WR_E_OSD_BLOCKLISTED - (int)(rb(&r) % 3u));
			why.module = WR_MOD_RBD;
			wri_rbd_img_fail(&f->L, rb(&r) % f->L.n_img, &why);
			break;
		}
		default:
			f->x.now.mono_ms += 1;
			pass(f);
			break;
		}
		note_fail(f);
		check_all(f);
	}
}

/* Everything closed: the machine and the engine are empty again. */
static void teardown(fz *f)
{
	uint32_t k;
	unsigned i;

	for (k = 0; k < f->L.n_img; k++) {
		uint16_t gen = f->L.img[k].gen;
		int was_free = f->L.img[k].state == (uint8_t)WR_IMG_FREE;

		(void)do_close(f, k, WR_CLOSE_ABANDON);
		check(f->L.img[k].state == (uint8_t)WR_IMG_FREE);
		check(was_free || f->L.img[k].gen != gen); /* a slot that was in use comes back with a new generation */
	}
	for (i = 0; i < 4u; i++) {
		f->x.now.mono_ms += 10;
		pass(f);
		check_all(f);
	}
	check(f->o.n_ctl_used == 0u && f->o.n_inflight == 0u && f->o.done_len == 0u && f->o.n_free == f->o.n_op && f->o.inflight_bytes == 0u);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz *f;

	if (size < 3u || size > MAX_INPUT)
		return 0;
	f = (fz *)malloc(sizeof(*f));
	if (f == NULL)
		return 0;
	if (setup(f, data[0], data[1])) {
		run(f, data, size);
		teardown(f);
	}
	free(f->mem);
	free(f->obj);
	free(f);
	return 0;
}
