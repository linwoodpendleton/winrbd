/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_io_chaos.c - requests that end without all their answers, at random (design 25.5): short timeouts, host cancels at any moment (waiting, cut, sent,
 * answered but not pulled), replies held and released, answers lost, connections cut, a zombie area too small for every copy (WR_E_BUSY: the request ends by
 * itself), a table that is nearly full. Some rounds close the image under the load (wri_rbd_io_fail_image: ABANDON and DRAIN). What it checks is what must hold whatever happens:
 *   - every request is completed exactly once, with OK, CANCELLED or TIMEOUT, and its priv words are the host's again when it is pulled;
 *   - the layer returns to nothing: no table entry, no operation, no zombie, no byte in flight, the image's counters at zero;
 *   - the bytes of the image: a request that completed OK was applied, and everything applied was applied in submission order, so every byte is the one of
 *     the last covering write among those that are known to have been applied (OK) and the ones submitted after the last of them; a byte nobody covered is zero.
 * Every write fills its range with one byte value of its own, so the owner of a byte is read off the byte.
 */
#include "rbd_io_rig.h"

#define ORDER 12u
#define OBJ (1u << ORDER)
#define IMG_SIZE (24u * OBJ)
#define MAXREQ 160u
#define MAXLEN (3u * OBJ)

typedef struct creq {
	rio_rq x;
	uint8_t buf[MAXLEN];
	unsigned kind, fill;   /* a write / discard / zeroes: fill = the byte value (discard and zeroes: 0) */
	uint64_t off, len;
	int cancelled;         /* the host called cancel on it */
} creq;

static rbio B;
static creq R[MAXREQ];
static unsigned n_req;
static uint64_t rng;

static uint64_t rnd(void)
{
	rng ^= rng >> 12;
	rng ^= rng << 25;
	rng ^= rng >> 27;
	return rng * 0x2545F4914F6CDD1Dull;
}

static uint64_t rnd_n(uint64_t n) { return n == 0 ? 0 : rnd() % n; }

static sim_osd *osd_k(unsigned k) { return B.g.w.osd[k]; }

static int is_mut(unsigned kind) { return kind == WR_IO_WRITE || kind == WR_IO_DISCARD || kind == WR_IO_WRITE_ZEROES; }

static void submit_one(void)
{
	creq *c = &R[n_req];
	unsigned pick = (unsigned)rnd_n(100);
	wr_io_kind kind = pick < 30 ? WR_IO_READ : pick < 70 ? WR_IO_WRITE : pick < 78 ? WR_IO_DISCARD : pick < 86 ? WR_IO_WRITE_ZEROES : WR_IO_FLUSH;
	uint64_t len = 1 + rnd_n(pick < 50 ? 600 : MAXLEN), off;
	uint32_t timeout = rnd_n(100) < 35 ? (uint32_t)(1 + rnd_n(400)) : 0;
	wr_status st;

	if (len > MAXLEN)
		len = MAXLEN;
	off = rnd_n(IMG_SIZE - len + 1);
	if (kind == WR_IO_FLUSH)
		off = len = 0;
	memset(c, 0, sizeof(*c));
	c->kind = (unsigned)kind;
	c->off = off;
	c->len = len;
	if (kind == WR_IO_WRITE) {
		c->fill = n_req % 250u + 1u; /* 1 .. 250, distinct among MAXREQ <= 250 requests */
		memset(c->buf, (int)c->fill, (size_t)len);
	}
	rio_fill_req(&c->x, kind, off, len, kind == WR_IO_WRITE || kind == WR_IO_READ ? c->buf : NULL, timeout);
	st = rio_submit(&B, 0, &c->x);
	if (st == WR_E_BUSY)
		return; /* the table is full: nothing was queued */
	WRT_CHECK_STATUS(WR_OK, st);
	if (st == WR_OK)
		n_req++;
}

static void cancel_one(void)
{
	unsigned i, start = (unsigned)rnd_n(n_req != 0 ? n_req : 1);

	for (i = 0; i < n_req; i++) {
		creq *c = &R[(start + i) % n_req];
		wr_status st;

		if (c->x.done)
			continue;
		st = wri_rbd_cancel(&B.r, 0, &c->x.q);
		WRT_CHECK(st == WR_OK || st == WR_E_BUSY || st == WR_E_STATE); /* STATE: it finished already and waits to be pulled */
		if (st == WR_OK || st == WR_E_BUSY)
			c->cancelled = 1;
		return;
	}
}

static unsigned pending(void)
{
	unsigned i, n = 0;

	for (i = 0; i < n_req; i++)
		n += R[i].x.done ? 0u : 1u;
	return n;
}

static void faults(unsigned n_osd, int on)
{
	unsigned k;

	for (k = 0; k < n_osd; k++) {
		sim_osd_fault *f = sim_osd_faults(osd_k(k));

		if (!on) {
			f->hold_replies = 0;
			f->drop_replies = 0;
			f->cut_after_ops = 0;
		}
	}
}

/* What happened around a byte that is not what any admissible write left: the requests that cover it and what the OSDs executed on its object. */
static void dump_history(uint64_t pos)
{
	char name[WRI_RBD_OBJNAME_MAX];
	unsigned i, k;

	rio_oname(&B, 0, pos >> ORDER, name);
	for (i = 0; i < n_req; i++) {
		const creq *c = &R[i];

		if (pos >= c->off && pos < c->off + c->len && c->kind != WR_IO_READ)
			fprintf(stderr, "    req %u kind %u [%llu,+%llu) fill %u status %d cancelled %d timeout %u\n", i, c->kind, (unsigned long long)c->off, (unsigned long long)c->len, c->fill,
				(int)c->x.st, c->cancelled, c->x.q.timeout_ms);
	}
	for (k = 0; k < B.g.w.n_osd; k++) {
		uint32_t n = 0, j;
		const sim_osd_rec *all = sim_osd_recs(osd_k(k), &n);

		for (j = 0; j < n; j++)
			if (all[j].mutating && strcmp(all[j].oid, name) == 0)
				fprintf(stderr, "    osd %u rec %u tid %llu conn %u op %x off %llu len %llu retry %u executed %u dup %u dropped %u result %d\n", k, j, (unsigned long long)all[j].tid, all[j].conn,
					all[j].op_code[0], (unsigned long long)all[j].op_off[0], (unsigned long long)all[j].op_len[0], all[j].retry_attempt, all[j].executed, all[j].duplicate,
					all[j].dropped_reply, (int)all[j].result);
	}
}

/* The end state of the image against the history of the requests. */
static void check_bytes(void)
{
	static uint8_t st[IMG_SIZE];
	uint64_t pos;
	unsigned i;

	WRT_CHECK(rio_store_read(&B, 0, 0, st, IMG_SIZE));
	for (pos = 0; pos < IMG_SIZE; pos++) {
		int last_ok = -1, found = 0, any_cover = 0;
		uint8_t b = st[pos];

		for (i = 0; i < n_req; i++) {
			const creq *c = &R[i];

			if (!is_mut(c->kind) || pos < c->off || pos >= c->off + c->len)
				continue;
			any_cover = 1;
			if (c->x.st == WR_OK)
				last_ok = (int)i;
		}
		if (!any_cover) {
			WRT_CHECK(b == 0);
			continue;
		}
		if (last_ok < 0 && b == 0)
			found = 1; /* nothing was applied here: a hole */
		for (i = last_ok < 0 ? 0u : (unsigned)last_ok; i < n_req && !found; i++) {
			const creq *c = &R[i];

			if (is_mut(c->kind) && pos >= c->off && pos < c->off + c->len && b == (uint8_t)c->fill)
				found = 1;
		}
		if (!found) {
			WRT_CHECK(0);
			fprintf(stderr, "  chaos: byte %llu = %u is not what any admissible write left (last OK write %d)\n", (unsigned long long)pos, b, last_ok);
			dump_history(pos);
			return;
		}
	}
}

static void round_run(unsigned seed, unsigned n_osd, unsigned zombie_bytes, unsigned max_reqs, unsigned steps, unsigned mode)
{
	rio_params p = rio_defaults();
	unsigned i, step, k, guard;
	const wri_rbd_img *im;

	p.n_osd = n_osd;
	p.n_sess = n_osd;
	p.max_reqs = max_reqs;
	p.max_ops = 24;
	p.op_bytes_max = 3000;
	p.zombie_bytes = zombie_bytes;
	p.op_timeout_ms = 3000;
	if (rio_open(&B, &p) != 0 || rio_image(&B, 0, "chaos", IMG_SIZE, ORDER, 1) == NULL) {
		WRT_CHECK(0);
		return;
	}
	if (n_osd > 1)
		for (i = 0; i < MW_PG_MAX; i++)
			B.g.m.prim[i] = (int)(i % n_osd);
	im = &B.r.img[0];
	rng = 0x9E3779B97F4A7C15ull ^ ((uint64_t)seed << 17);
	n_req = 0;
	for (step = 0; step < steps; step++) {
		unsigned act = (unsigned)rnd_n(100);

		if (act < 35 && n_req < MAXREQ - 4u) {
			for (k = 1u + (unsigned)rnd_n(3); k != 0; k--)
				submit_one();
		} else if (act < 50) {
			cancel_one();
		} else if (act < 62) {
			for (k = 0; k < n_osd; k++)
				sim_osd_faults(osd_k(k))->hold_replies = (uint8_t)rnd_n(2);
		} else if (act < 74) {
			for (k = 0; k < n_osd; k++)
				(void)sim_osd_release(osd_k(k), 1u + (uint32_t)rnd_n(4));
		} else if (act < 80) {
			sim_osd_faults(osd_k((unsigned)rnd_n(n_osd)))->drop_replies = 1u + (uint32_t)rnd_n(2);
		} else if (act < 84) {
			sim_osd_faults(osd_k((unsigned)rnd_n(n_osd)))->cut_after_ops = 1u + (uint32_t)rnd_n(4);
		} else if (act < 92) {
			rio_tick(&B, 1u + (uint64_t)rnd_n(120));
		}
		if (mode != 0 && step == steps / 2u)
			wri_rbd_io_fail_image(&B.r, 0, WR_E_CANCELLED, mode == 1 ? WR_CLOSE_ABANDON : WR_CLOSE_DRAIN); /* the image closes under the load */
		(void)rio_run(&B);
		WRT_CHECK(B.r.reqs_inflight <= max_reqs && B.r.done_len <= B.r.n_rq);
		WRT_CHECK(im->n_reqs <= max_reqs);
	}
	/* everything ends: faults off, replies out, time passes (zombies are resent until answered) */
	faults(n_osd, 0);
	for (guard = 0; guard < 6000 && (pending() != 0 || !rio_idle(&B)); guard++) {
		for (k = 0; k < n_osd; k++)
			(void)sim_osd_release(osd_k(k), 0);
		(void)rio_run(&B);
		rio_tick(&B, 100);
	}
	(void)rio_run(&B);
	WRT_CHECK(pending() == 0);
	WRT_CHECK(rio_idle(&B));
	WRT_CHECK(B.r.n_completed == B.r.n_submitted);
	WRT_CHECK(B.r.reqs_inflight == 0 && im->n_reqs == 0 && im->n_writes_unfinished == 0);
	WRT_CHECK(B.g.o.n_inflight == 0 && B.g.o.inflight_bytes == 0 && B.g.o.zused == 0 && B.g.o.n_zombies == B.g.o.n_zombies_done);
	for (i = 0; i < n_req; i++) {
		const creq *c = &R[i];

		WRT_CHECK(c->x.done);
		WRT_CHECK(c->x.st == WR_OK || c->x.st == WR_E_CANCELLED || c->x.st == WR_E_TIMEOUT);
		if (c->x.st == WR_E_CANCELLED && mode == 0)
			WRT_CHECK(c->cancelled);
		if (c->x.st == WR_E_TIMEOUT)
			WRT_CHECK(c->x.q.timeout_ms != 0);
		WRT_CHECK(c->x.q.priv[0] == 0 && c->x.q.priv[1] == 0); /* the structure is the host's again */
	}
	if (mode != 1) /* an abandon lets go of the fence entries of its zombies: what the abandoned writes do to later ones is unknown, by design (25.5) */
		check_bytes();
	rio_close(&B);
}

int main(void)
{
	unsigned seed, scale = 1;
	const char *env = getenv("WRT_RBD_CHAOS_N");

	if (env != NULL && atoi(env) > 0)
		scale = (unsigned)atoi(env);
	for (seed = 1; seed <= 12u * scale; seed++) {
		round_run(seed, 1u + seed % 3u, seed % 2u ? 1u << 20 : 6000u, seed % 4u == 0 ? 6u : 32u, 220, 0);
		round_run(seed + 1000u, 2, 2000, 12, 160, 0);
		round_run(seed + 2000u, 1u + seed % 2u, seed % 3u ? 1u << 20 : 3000u, 16, 200, 1u + seed % 2u);
	}
	return wrt_finish();
}
