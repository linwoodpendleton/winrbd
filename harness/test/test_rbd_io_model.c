/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_io_model.c - random image I/O against a flat byte-array model and against sim_store, byte for byte (design 30.1, layer 4).
 *
 * Tens of thousands of reads, writes, discards, write-zeroes and flushes (unaligned, across objects, whole objects, the last byte of the image) are in
 * flight together over real sessions. The model needs no knowledge of the order of the answers: overlapping requests run in submission order (the fence), so
 *   - the final bytes are those of applying every write in submission order,
 *   - a read returns the model's bytes as of its own submission (a later overlapping write cannot start before it ended, an earlier one has ended),
 *   - a flush completes after every write submitted before it.
 * All three are checked at every completion. The cluster misbehaves on command: replies held and released in bursts, OSD restarts under I/O, connections cut,
 * answers lost after the write was applied (with duplicate detection and without it: the fence alone keeps the bytes right), EAGAIN. At the end, and at
 * quiet points on the way, the image read through the layer and the objects of the store both equal the model.
 *
 * WRT_RBD_MODEL_N scales the number of requests (default as in main(); one scenario takes about a second plain, a few under the sanitizers).
 */
#include "rbd_io_rig.h"

#define NSLOT 48u
#define MAXLEN (256u * 1024u)

typedef struct mslot {
	rio_rq x;
	int active;
	uint8_t *buf, *exp;
	uint64_t off, len;
	unsigned kind;
	uint64_t sub;
	unsigned ndeps;
	uint64_t deps[NSLOT];
	uint64_t iter;
} mslot;

typedef struct scen {
	const char *name;
	uint8_t order;
	uint64_t size;
	uint32_t op_bytes_max, max_ops, ctl_ops, max_reqs, inflight_bytes_max;
	unsigned n_req;
	uint64_t seed;
	int holds, restarts, drops, cuts, eagain, no_dedup;
	unsigned n_osd, n_sess;
} scen;

static rbio B;
static mslot S[NSLOT];
static uint8_t *model;
static uint64_t *comp_order;     /* by submission number: completion order, 0 = not done */
static uint64_t rng;
static unsigned failures_printed;
static uint64_t t_start;

static uint64_t rnd(void)
{
	rng ^= rng >> 12;
	rng ^= rng << 25;
	rng ^= rng >> 27;
	return rng * 0x2545F4914F6CDD1Dull;
}

static uint64_t rnd_n(uint64_t n) { return n == 0 ? 0 : rnd() % n; }

static sim_osd *osd_k(unsigned k) { return B.g.w.osd[k]; }

static void bad(const mslot *s, const char *what, uint64_t extra)
{
	WRT_CHECK(0);
	if (failures_printed++ < 5)
		fprintf(stderr, "  model: %s: slot kind %u off %" PRIu64 " len %" PRIu64 " sub %" PRIu64 " iter %" PRIu64 " (%" PRIu64 ")\n", what, s->kind, s->off, s->len,
			s->sub, s->iter, extra);
}

/* One request is done: check it against the model. */
static void complete_slot(mslot *s)
{
	unsigned i;

	if (s->x.st != WR_OK)
		bad(s, "status", (uint64_t)(int64_t)s->x.st);
	if (s->kind == (unsigned)WR_IO_READ && s->x.st == WR_OK && memcmp(s->buf, s->exp, (size_t)s->len) != 0) {
		size_t k = 0;

		while (k < s->len && s->buf[k] == s->exp[k])
			k++;
		bad(s, "read differs from the model at submission", k);
	}
	comp_order[s->sub] = (uint64_t)s->x.order + 1u;
	if (s->kind == (unsigned)WR_IO_FLUSH) {
		for (i = 0; i < s->ndeps; i++)
			if (comp_order[s->deps[i]] == 0 || comp_order[s->deps[i]] > comp_order[s->sub])
				bad(s, "flush completed before a write submitted earlier", s->deps[i]);
	}
	s->active = 0;
}

/* Every done request, in the order the layer completed them (the flush check compares completion orders). */
static unsigned harvest(void)
{
	unsigned n = 0;

	for (;;) {
		unsigned i, best = NSLOT;

		for (i = 0; i < NSLOT; i++)
			if (S[i].active && S[i].x.done && (best == NSLOT || S[i].x.order < S[best].x.order))
				best = i;
		if (best == NSLOT)
			return n;
		complete_slot(&S[best]);
		n++;
	}
}

/* Submit one random request; 1 if it was accepted. */
static int submit_random(const scen *c, uint64_t iter)
{
	unsigned i, slot = NSLOT, k, pick;
	mslot *s;
	uint64_t off, len, size = c->size, obj = 1ull << c->order;
	wr_io_kind kind;
	wr_status st;

	for (i = 0; i < NSLOT; i++)
		if (!S[i].active) {
			slot = i;
			break;
		}
	if (slot == NSLOT)
		return 0;
	s = &S[slot];
	pick = (unsigned)rnd_n(100);
	kind = pick < 36 ? WR_IO_READ : pick < 72 ? WR_IO_WRITE : pick < 80 ? WR_IO_DISCARD : pick < 88 ? WR_IO_WRITE_ZEROES : WR_IO_FLUSH;
	/* a range: small, medium or large, anywhere; sometimes whole objects, sometimes the end of the image */
	k = (unsigned)rnd_n(100);
	if (k < 55)
		len = 1 + rnd_n(4096);
	else if (k < 80)
		len = 1 + rnd_n(3u * obj);
	else if (k < 92)
		len = 1 + rnd_n(MAXLEN);
	else
		len = obj * (1 + rnd_n(3));
	if (len > size)
		len = size;
	if (len > MAXLEN)
		len = MAXLEN;
	off = rnd_n(size - len + 1);
	k = (unsigned)rnd_n(100);
	if (k < 12) {
		off &= ~(obj - 1u); /* object aligned start */
		if (off + len > size)
			off = size - len;
	} else if (k < 18) {
		off = size - len; /* ends exactly at the end of the image */
	}
	if (kind == WR_IO_FLUSH)
		off = len = 0;
	memset(&s->x, 0, sizeof(s->x));
	s->kind = (unsigned)kind;
	s->off = off;
	s->len = len;
	s->iter = iter;
	if (kind == WR_IO_WRITE) {
		size_t j;
		uint64_t w = rnd();

		for (j = 0; j < len; j++) /* a cheap pattern with a random base: every write is distinguishable from the bytes it replaces */
			s->buf[j] = (uint8_t)(w >> ((j & 7u) * 8u)) ^ (uint8_t)(j * 131u);
	}
	rio_fill_req(&s->x, kind, off, len, kind == WR_IO_FLUSH || kind == WR_IO_DISCARD || kind == WR_IO_WRITE_ZEROES ? NULL : s->buf, 0);
	if (kind == WR_IO_READ)
		memset(s->buf, 0xA5, (size_t)len); /* the read must overwrite every byte, by data or by zero-fill */
	st = rio_submit(&B, 0, &s->x);
	if (st == WR_E_BUSY)
		return 0; /* the request table is full: nothing was queued, try again after a completion */
	if (st != WR_OK) {
		bad(s, "submit", (uint64_t)(int64_t)st);
		return 0;
	}
	s->sub = s->x.sub_no;
	s->active = 1;
	s->ndeps = 0;
	comp_order[s->sub] = 0;
	/* the model, in submission order */
	switch (kind) {
	case WR_IO_READ:
		memcpy(s->exp, model + off, (size_t)len);
		break;
	case WR_IO_WRITE:
		memcpy(model + off, s->buf, (size_t)len);
		break;
	case WR_IO_DISCARD:
	case WR_IO_WRITE_ZEROES:
		memset(model + off, 0, (size_t)len);
		break;
	case WR_IO_FLUSH:
		for (i = 0; i < NSLOT; i++) {
			const mslot *o = &S[i];

			if (o != s && o->active && (o->kind == (unsigned)WR_IO_WRITE || o->kind == (unsigned)WR_IO_DISCARD || o->kind == (unsigned)WR_IO_WRITE_ZEROES) &&
			    comp_order[o->sub] == 0)
				s->deps[s->ndeps++] = o->sub;
		}
		break;
	default:
		break;
	}
	return 1;
}

static unsigned active_count(void)
{
	unsigned i, n = 0;

	for (i = 0; i < NSLOT; i++)
		n += S[i].active ? 1u : 0u;
	return n;
}

static void set_hold(const scen *c, int on)
{
	unsigned k;

	for (k = 0; k < c->n_osd; k++)
		sim_osd_faults(osd_k(k))->hold_replies = (uint8_t)on;
}

static void release_some(const scen *c, uint32_t n)
{
	unsigned k;

	for (k = 0; k < c->n_osd; k++)
		(void)sim_osd_release(osd_k(k), n);
}

/* The layer's own invariants, at any moment. */
static void check_budgets(const scen *c)
{
	WRT_CHECK(B.r.reqs_inflight <= c->max_reqs);
	WRT_CHECK(B.g.o.n_inflight <= B.g.o.n_op);
	WRT_CHECK(B.g.o.inflight_bytes <= c->inflight_bytes_max);
	WRT_CHECK(B.r.done_len <= B.r.n_rq);
}

/* Everything is quiet: read the whole image through the layer, compare with the model and with the store. */
static void compare_all(const scen *c)
{
	static rio_rq x;
	uint8_t *got = (uint8_t *)malloc((size_t)c->size);
	uint8_t *st = (uint8_t *)malloc((size_t)c->size);
	uint64_t pos, chunk = 256u * 1024u;

	if (got == NULL || st == NULL) {
		WRT_CHECK(0);
		free(got);
		free(st);
		return;
	}
	memset(got, 0xA5, (size_t)c->size);
	for (pos = 0; pos < c->size; pos += chunk) {
		uint64_t n = c->size - pos < chunk ? c->size - pos : chunk;

		WRT_CHECK(rio_go(&B, 0, &x, WR_IO_READ, pos, n, got + pos, 0));
		WRT_CHECK(rio_until(&B, &x, 600000) && x.st == WR_OK);
	}
	WRT_CHECK_MEM(got, model, (size_t)c->size);
	WRT_CHECK(rio_store_read(&B, 0, 0, st, (size_t)c->size));
	WRT_CHECK_MEM(st, model, (size_t)c->size);
	free(got);
	free(st);
}

/* Bring everything to an end: faults off, replies released, time passed. */
static void finish_all(const scen *c)
{
	unsigned k, guard = 0;

	for (k = 0; k < c->n_osd; k++) {
		sim_osd_fault *f = sim_osd_faults(osd_k(k));

		f->hold_replies = 0;
		f->drop_replies = 0;
		f->cut_after_ops = 0;
		f->eagain_ops = 0;
	}
	while (active_count() != 0 && guard++ < 4000) {
		release_some(c, 0);
		(void)rio_run(&B);
		(void)harvest();
		if (active_count() != 0)
			rio_tick(&B, 100);
		(void)harvest();
	}
	WRT_CHECK(active_count() == 0);
	(void)rio_run(&B);
	WRT_CHECK(rio_idle(&B));
}

static void run_scenario(const scen *c, unsigned scale_pct)
{
	rio_params p = rio_defaults();
	unsigned total = (unsigned)((uint64_t)c->n_req * scale_pct / 100u), submitted = 0, i, quiet_at = 0;
	uint64_t iter = 0, stall = 0;
	unsigned hold_left = 0;
	uint64_t resent0;

	p.n_osd = c->n_osd;
	p.n_sess = c->n_sess;
	p.max_ops = c->max_ops;
	p.ctl_ops = c->ctl_ops;
	p.max_reqs = c->max_reqs;
	p.op_bytes_max = c->op_bytes_max;
	p.inflight_bytes_max = c->inflight_bytes_max;
	p.zombie_bytes = 1u << 20;
	if (rio_open(&B, &p) != 0 || rio_image(&B, 0, "model", c->size, c->order, 1) == NULL) {
		WRT_CHECK(0);
		return;
	}
	if (c->no_dedup) {
		for (i = 0; i < c->n_osd; i++)
			sim_osd_faults(osd_k(i))->no_dedup = 1;
	}
	if (c->n_osd > 1) {
		for (i = 0; i < MW_PG_MAX; i++)
			B.g.m.prim[i] = (int)(i % c->n_osd);
	}
	model = (uint8_t *)calloc(1, (size_t)c->size);
	comp_order = (uint64_t *)calloc((size_t)total + 20000u, sizeof(uint64_t)); /* submissions: the random ones and the reads of the quiet-point compares */
	memset(S, 0, sizeof(S));
	for (i = 0; i < NSLOT; i++) {
		S[i].buf = (uint8_t *)malloc(MAXLEN);
		S[i].exp = (uint8_t *)malloc(MAXLEN);
	}
	if (model == NULL || comp_order == NULL) {
		WRT_CHECK(0);
		return;
	}
	rng = c->seed;
	failures_printed = 0;
	B.g.w.e.x.now.mono_ms += 1; /* the clock is never zero */
	t_start = rio_now(&B);
	quiet_at = total / 4u + 1u;
	while (submitted < total || active_count() != 0) {
		unsigned act = (unsigned)rnd_n(100), done_now;

		iter++;
		if (iter > 20u * (uint64_t)total + 50000u) { /* no progress: say where it is stuck, and stop */
			unsigned q;

			fprintf(stderr, "  model: %s STUCK at iter %" PRIu64 ": submitted %u of %u, active %u, engine in flight %u, held %u\n", c->name, iter, submitted, total,
				active_count(), B.g.o.n_inflight, c->n_osd != 0 ? sim_osd_n_held(osd_k(0)) : 0u);
			for (q = 0; q < NSLOT; q++)
				if (S[q].active)
					fprintf(stderr, "    slot %u kind %u off %" PRIu64 " len %" PRIu64 "\n", q, S[q].kind, S[q].off, S[q].len);
			{
				uint32_t o;

				for (o = 0; o < B.g.o.n_op; o++) {
					const wri_osd_op *op = &B.g.o.op[o];

					if (op->state != WRI_OP_FREE)
						fprintf(stderr, "    op %u state %u kind %u sess %u osd %d tid %" PRIu64 " retry %d zombie %u owner %x deadline %" PRIu64 " now %" PRIu64 "\n", o, op->state, op->kind, op->sess, op->osd, op->tid,
							op->retry_attempt, (op->flags & WRI_OPF_ZOMBIE) != 0, op->owner, op->deadline_ms, rio_now(&B));
				}
				for (o = 0; o < B.g.o.sess.n; o++)
					fprintf(stderr, "    sess %u state %u osd %d inflight %u streak %u cooldown_until %" PRIu64 " conn_slot %u\n", o, B.g.o.sess.s[o].state, B.g.o.sess.s[o].osd, B.g.o.sess.s[o].n_inflight,
						B.g.o.sess.s[o].fail_streak, B.g.o.sess.s[o].cooldown_until_ms, B.g.o.sess.s[o].conn_slot);
				for (o = 0; o < W_EC; o++)
					fprintf(stderr, "    ec %u in_use %d state %d osd_idx %d dead %d\n", o, B.g.w.ec[o].in_use, (int)B.g.w.ec[o].c.state, B.g.w.ec[o].osd_idx, B.g.w.ec[o].dead_target);
				fprintf(stderr, "    osd_down %d %d %d ticket_off %d max_hs %u live %u\n", B.g.w.osd_down[0], B.g.w.osd_down[1], B.g.w.osd_down[2], B.g.w.ticket_off, B.g.w.max_hs, w_live(&B.g.w));
				for (o = 0; o < B.r.n_rq; o++)
					if (B.r.rq[o].state != WRI_RQ_FREE)
						fprintf(stderr, "    rq %u state %u kind %u cur %" PRIu64 " end %" PRIu64 " ops_out %u seq %" PRIu64 "\n", o, B.r.rq[o].state, B.r.rq[o].kind, B.r.rq[o].cur, B.r.rq[o].off + B.r.rq[o].len, B.r.rq[o].ops_out, B.r.rq[o].seq);
			}
			WRT_CHECK(0);
			break;
		}
		if (submitted < total && act < 60) {
			unsigned burst = 1u + (unsigned)rnd_n(4);

			while (burst-- != 0 && submitted < total)
				if (submit_random(c, iter))
					submitted++;
				else
					break;
		} else if (act < 72) {
			(void)rio_run(&B);
		} else if (act < 84 && c->holds) {
			if (hold_left == 0) {
				set_hold(c, 1);
				hold_left = 3u + (unsigned)rnd_n(12);
			} else {
				release_some(c, 1u + (uint32_t)rnd_n(6));
				if (--hold_left == 0) {
					set_hold(c, 0);
					release_some(c, 0);
				}
			}
		} else if (act < 90) {
			rio_tick(&B, 1u + (uint64_t)rnd_n(60)); /* time passes: deadlines, cool-downs, resends */
		} else {
			unsigned f = (unsigned)rnd_n(200); /* the cluster misbehaves now and then */

			if (f < 2 && c->restarts) {
				sim_osd_restart(osd_k((unsigned)rnd_n(c->n_osd)));
				rio_tick(&B, 100u * (1u + (unsigned)rnd_n(8)));
			} else if (f < 5 && c->drops) {
				sim_osd_faults(osd_k((unsigned)rnd_n(c->n_osd)))->drop_replies = 1u + (uint32_t)rnd_n(3);
			} else if (f < 8 && c->cuts) {
				sim_osd_faults(osd_k((unsigned)rnd_n(c->n_osd)))->cut_after_ops = 1u + (uint32_t)rnd_n(6);
			} else if (f < 12 && c->eagain) {
				sim_osd_faults(osd_k((unsigned)rnd_n(c->n_osd)))->eagain_ops = 1u + (uint32_t)rnd_n(3);
			} else {
				(void)rio_run(&B);
			}
		}
		(void)rio_collect_done(&B);
		done_now = harvest();
		check_budgets(c);
		if (done_now == 0 && active_count() != 0)
			stall++;
		else
			stall = 0;
		if (stall > 24) { /* nothing completes: let the cluster answer, and time pass */
			release_some(c, 0);
			rio_tick(&B, 250);
			(void)harvest();
			stall = 0;
		}
		if (submitted >= quiet_at && quiet_at != 0 && c->n_req >= 1000u) { /* a quiet point: compare everything, then go on */
			finish_all(c);
			compare_all(c);
			quiet_at = submitted + total / 4u + 1u;
			hold_left = 0;
		}
	}
	finish_all(c);
	compare_all(c);
	resent0 = B.g.o.n_resent;
	if (c->restarts || c->drops || c->cuts)
		WRT_CHECK(resent0 != 0); /* the faults really happened */
	/* the simulated time stays inside the life of the OSD tickets (an hour: nothing in this rig renews them) */
	WRT_CHECK(rio_now(&B) - t_start < 3000u * 1000u);
	fprintf(stderr, "  %-14s %" PRIu64 " s, requests %u, ops %" PRIu64 ", resent %" PRIu64 ", eagain %u, zombies %" PRIu64 "/%u, sessions reset %u\n", c->name, (rio_now(&B) - t_start) / 1000u, submitted,
		B.g.o.n_done, resent0, B.g.o.n_eagain, B.r.n_zombie_entries, B.g.o.n_zombies, B.g.o.sess.n_resets);
	for (i = 0; i < NSLOT; i++) {
		free(S[i].buf);
		free(S[i].exp);
	}
	free(model);
	free(comp_order);
	model = NULL;
	comp_order = NULL;
	rio_close(&B);
}

int main(void)
{
	/* image, budgets, requests, seed, then the faults: holds, restarts, drops, cuts, eagain, no_dedup; OSDs, sessions */
	static const scen sc[] = {
		/* clean cluster, replies held and released in bursts: the order of the answers is random */
		{"clean", 12, 1u << 20, 3000, 32, 2, 32, 64u << 20, 6000, 0x1111, 1, 0, 0, 0, 0, 0, 1, 2},
		/* tiny table: one data slot, four requests, a few KiB in flight */
		{"tiny", 12, 1u << 19, 4096, 3, 2, 4, 16384, 2500, 0x2222, 1, 0, 0, 0, 0, 0, 1, 2},
		/* restarts, cut connections, lost answers, EAGAIN under I/O, three OSDs */
		{"faults", 14, 3u << 19, 1u << 16, 64, 4, 32, 8u << 20, 8000, 0x3333, 1, 1, 1, 1, 1, 0, 3, 3},
		/* the same without duplicate detection: only the fence keeps the bytes right */
		{"no_dedup", 13, 1u << 20, 8192, 32, 2, 24, 4u << 20, 8000, 0x4444, 1, 1, 1, 1, 0, 1, 2, 2},
		/* large objects, whole-object extents, a small client table */
		{"big_objects", 20, 8u << 20, 1u << 20, 16, 2, 8, 4u << 20, 3000, 0x5555, 1, 1, 1, 0, 0, 0, 2, 2},
		/* an image that is not a multiple of the object size: the last object is partial (extents, discards and reads of the tail), small cuts, faults */
		{"odd_size", 12, (1u << 19) + 3001u, 3000, 32, 2, 32, 8u << 20, 6000, 0x6666, 1, 1, 1, 1, 0, 1, 2, 2},
		{"odd_big", 21, (5u << 21) + 12345u, 1u << 19, 16, 2, 8, 4u << 20, 2500, 0x7777, 1, 1, 1, 0, 0, 0, 2, 2},
	};
	unsigned scale = 100, i;
	const char *env = getenv("WRT_RBD_MODEL_N"), *only = getenv("WRT_RBD_MODEL_ONLY");

	if (env != NULL && atoi(env) > 0)
		scale = (unsigned)atoi(env);
	for (i = 0; i < sizeof(sc) / sizeof(sc[0]); i++)
		if (only == NULL || strcmp(only, sc[i].name) == 0)
			run_scenario(&sc[i], scale);
	return wrt_finish();
}
