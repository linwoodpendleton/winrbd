/* SPDX-License-Identifier: MIT */
/*
 * wrl_cmp.c - the krbd comparison engine (docs/design/core-architecture.md section 33; the contract is in wrl_cmp.h).
 *
 * Layout of this file:
 *   1. helpers: hashes, patterns, records
 *   2. the model: a flat image in 64 KiB chunks allocated when first written
 *   3. the device worker: one thread that runs the device's blocking calls, so the watchdog never waits on a hung device
 *   4. the engine and its lanes: one lane is one operation in flight (apply, verify, triage), lanes never overlap in the range
 *      they touch, so the model can be updated when an operation starts
 *   5. attribution (the three-way table), scan, the op generators, the phases and the run
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wrl_cmp.h"

#define CHUNK 65536u
#define BUF_ALIGN 4096u
#define MAX_LANES 64u
#define SCAN_RESTARTS 3u
#define DRAIN_GRACE_MS 20000u
#define PROGRESS_MS 30000u
#define DEFAULT_OPS 20000u
#define DEFAULT_CHECKPOINT 5000u
#define DEFAULT_STALL_MS 180000u
#define DEFAULT_MEM (1ull << 30)
#define RECENT 16u

/* ---- 1. helpers --------------------------------------------------------------------------------------------------- */

static uint64_t mix64(uint64_t x)
{
	x += 0x9e3779b97f4a7c15ull;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
	return x ^ (x >> 31);
}

uint64_t wrl_cmp_digest(const uint8_t *p, size_t n, uint64_t seed)
{
	uint64_t h = 0xcbf29ce484222325ull ^ seed;
	size_t i;

	for (i = 0; i < n; i++)
		h = (h ^ p[i]) * 0x100000001b3ull;
	return h;
}

uint8_t wrl_cmp_pattern_byte(unsigned kind, uint64_t salt, uint64_t x)
{
	switch (kind) {
	case 1:
		return 0;
	case 2:
		return (uint8_t)(((x & ~7ull) ^ (salt * 0x0101010101010101ull) ^ 0xa5a5a5a5a5a5a5a5ull) >> (8u * (unsigned)(x & 7u)));
	default:
		return (uint8_t)(mix64(salt * 0x2545f4914f6cdd1dull + (x >> 3)) >> (8u * (unsigned)(x & 7u)));
	}
}

/* buf[i] = the pattern at absolute offset off + i (a word at a time: the pattern is a function of the 8-byte word). */
static uint64_t pat_word(unsigned kind, uint64_t salt, uint64_t x)
{
	if (kind == 2u)
		return (x & ~7ull) ^ (salt * 0x0101010101010101ull) ^ 0xa5a5a5a5a5a5a5a5ull;
	return mix64(salt * 0x2545f4914f6cdd1dull + (x >> 3));
}

static void pat_fill(unsigned kind, uint64_t salt, uint64_t off, uint8_t *buf, size_t n)
{
	size_t i = 0;

	if (kind == 1u) {
		memset(buf, 0, n);
		return;
	}
	while (i < n && ((off + i) & 7u) != 0u) { /* up to the first whole word */
		buf[i] = (uint8_t)(pat_word(kind, salt, off + i) >> (8u * (unsigned)((off + i) & 7u)));
		i++;
	}
	for (; i + 8u <= n; i += 8u) {
		uint64_t w = pat_word(kind, salt, off + i);

		buf[i] = (uint8_t)w;
		buf[i + 1] = (uint8_t)(w >> 8);
		buf[i + 2] = (uint8_t)(w >> 16);
		buf[i + 3] = (uint8_t)(w >> 24);
		buf[i + 4] = (uint8_t)(w >> 32);
		buf[i + 5] = (uint8_t)(w >> 40);
		buf[i + 6] = (uint8_t)(w >> 48);
		buf[i + 7] = (uint8_t)(w >> 56);
	}
	if (i < n) {
		uint64_t w = pat_word(kind, salt, off + i);
		unsigned sh = 0;

		for (; i < n; i++, sh += 8u)
			buf[i] = (uint8_t)(w >> sh);
	}
}

static uint64_t down(uint64_t x, uint64_t a)
{
	return x - x % a;
}

static uint64_t up(uint64_t x, uint64_t a)
{
	return down(x + a - 1u, a);
}

static void *xalloc(size_t n)
{
	void *p = NULL;

	if (n == 0u)
		n = 1;
	if (posix_memalign(&p, BUF_ALIGN, up(n, BUF_ALIGN)) != 0)
		return NULL;
	return p;
}

/* Memory the run cannot free because a device call or a core request may still use it (a hang): kept reachable on purpose. */
static void **g_keep;
static size_t g_keep_n, g_keep_cap;
static pthread_mutex_t g_keep_mu = PTHREAD_MUTEX_INITIALIZER;

static void keep(void *p)
{
	if (p == NULL)
		return;
	pthread_mutex_lock(&g_keep_mu);
	if (g_keep_n == g_keep_cap) {
		size_t nc = g_keep_cap == 0u ? 64u : g_keep_cap * 2u;
		void **np = (void **)realloc((void *)g_keep, nc * sizeof(*np));

		if (np == NULL) {
			pthread_mutex_unlock(&g_keep_mu);
			return;
		}
		g_keep = np;
		g_keep_cap = nc;
	}
	g_keep[g_keep_n++] = p;
	pthread_mutex_unlock(&g_keep_mu);
}

static const char *kind_name(unsigned k)
{
	switch (k) {
	case WRL_CMP_K_READ: return "read";
	case WRL_CMP_K_WRITE: return "write";
	case WRL_CMP_K_DISCARD: return "discard";
	case WRL_CMP_K_ZEROES: return "zeroes";
	case WRL_CMP_K_FLUSH: return "flush";
	case WRL_CMP_K_PAST: return "past";
	default: return "?";
	}
}

static const char *first_class_name(uint64_t mask)
{
	unsigned i;

	for (i = 0; i < WRL_EC_COUNT; i++)
		if ((mask >> i) & 1u)
			return wrl_cmp_class_name(i);
	return "-";
}

static const char *dir_name(unsigned d)
{
	switch (d) {
	case WRL_CMP_DIR_C2K: return "core-to-krbd";
	case WRL_CMP_DIR_K2C: return "krbd-to-core";
	case WRL_CMP_DIR_INTER: return "interleave";
	default: return "scan";
	}
}

/* ---- 2. the model ------------------------------------------------------------------------------------------------- */

typedef struct model {
	uint8_t **c;
	uint64_t size, n, used;
	int oom;
} model;

static int model_init(model *m, uint64_t size)
{
	memset(m, 0, sizeof(*m));
	m->size = size;
	m->n = (size + CHUNK - 1u) / CHUNK;
	m->c = (uint8_t **)calloc((size_t)m->n, sizeof(uint8_t *));
	return m->c != NULL ? 0 : -1;
}

static void model_free(model *m)
{
	uint64_t i;

	for (i = 0; m->c != NULL && i < m->n; i++)
		free(m->c[i]);
	free((void *)m->c);
	memset(m, 0, sizeof(*m));
}

static uint8_t *model_chunk(model *m, uint64_t i)
{
	if (m->c[i] == NULL) {
		m->c[i] = (uint8_t *)calloc(1, CHUNK);
		if (m->c[i] == NULL) {
			m->oom = 1;
			return NULL;
		}
		m->used++;
	}
	return m->c[i];
}

static void model_write(model *m, uint64_t off, uint64_t len, unsigned kind, uint64_t salt)
{
	while (len > 0u) {
		uint64_t ci = off / CHUNK, co = off % CHUNK, n = CHUNK - co;
		uint8_t *c = model_chunk(m, ci);

		if (n > len)
			n = len;
		if (c == NULL)
			return;
		pat_fill(kind, salt, off, c + co, (size_t)n);
		off += n;
		len -= n;
	}
}

static void model_zero(model *m, uint64_t off, uint64_t len)
{
	while (len > 0u) {
		uint64_t ci = off / CHUNK, co = off % CHUNK, n = CHUNK - co;

		if (n > len)
			n = len;
		if (m->c[ci] != NULL) {
			if (n == CHUNK) { /* the whole chunk: back to "never written" */
				free(m->c[ci]);
				m->c[ci] = NULL;
				m->used--;
			} else {
				memset(m->c[ci] + co, 0, (size_t)n);
			}
		}
		off += n;
		len -= n;
	}
}

static void model_read(const model *m, uint64_t off, uint64_t len, uint8_t *out)
{
	while (len > 0u) {
		uint64_t ci = off / CHUNK, co = off % CHUNK, n = CHUNK - co;

		if (n > len)
			n = len;
		if (m->c[ci] != NULL)
			memcpy(out, m->c[ci] + co, (size_t)n);
		else
			memset(out, 0, (size_t)n);
		out += n;
		off += n;
		len -= n;
	}
}

/* Offset (relative to buf) of the first byte of buf that differs from the model's bytes at off, or len if none. */
static uint64_t model_first_diff(const model *m, uint64_t off, const uint8_t *buf, uint64_t len)
{
	uint64_t done = 0;

	while (done < len) {
		uint64_t x = off + done, ci = x / CHUNK, co = x % CHUNK, n = CHUNK - co, i;

		if (n > len - done)
			n = len - done;
		if (m->c[ci] != NULL) {
			if (memcmp(buf + done, m->c[ci] + co, (size_t)n) != 0) {
				for (i = 0; i < n; i++)
					if (buf[done + i] != m->c[ci][co + i])
						return done + i;
			}
		} else {
			for (i = 0; i < n; i++)
				if (buf[done + i] != 0u)
					return done + i;
		}
		done += n;
	}
	return len;
}

static void model_flip(model *m, uint64_t off)
{
	uint8_t *c = model_chunk(m, off / CHUNK);

	if (c != NULL)
		c[off % CHUNK] ^= 0x5au;
}

/* What a device discard does to the model: the range shrunk inward to `gran` within each object (krbd's alloc_size rule), then zeros. */
static void model_discard_dev(model *m, uint64_t off, uint64_t len, uint64_t obj, uint64_t gran)
{
	uint64_t end = off + len;

	while (off < end) {
		uint64_t ob = off / obj * obj, oe = ob + obj, seg_end = end < oe ? end : oe;
		uint64_t a = ob + up(off - ob, gran), b = ob + down(seg_end - ob, gran);

		if (a < b)
			model_zero(m, a, b - a);
		off = seg_end;
	}
}

/* ---- 3. the device worker --------------------------------------------------------------------------------------- */

enum { DJ_READ = 1, DJ_WRITE, DJ_DISCARD, DJ_ZEROES, DJ_FLUSH };

typedef struct djob {
	int kind;
	uint64_t off, len;
	void *buf;
	long res;
	int done;
} djob;

typedef struct dw {
	pthread_mutex_t mu;
	pthread_cond_t cv;      /* the worker waits for jobs on it */
	pthread_cond_t cv_done; /* the engine waits for a job to finish on it */
	pthread_t th;
	wrl_cmp_dev dev;
	djob **q;
	unsigned qcap, qhead, qn;
	int quit, busy, started, mono;
} dw;

static void dw_exec(const wrl_cmp_dev *d, djob *j)
{
	switch (j->kind) {
	case DJ_READ:
		j->res = d->pread(d->ctx, j->buf, (size_t)j->len, j->off);
		break;
	case DJ_WRITE:
		j->res = d->pwrite(d->ctx, j->buf, (size_t)j->len, j->off);
		break;
	case DJ_DISCARD:
		j->res = d->discard != NULL ? d->discard(d->ctx, j->off, j->len) : -ENOTSUP;
		break;
	case DJ_ZEROES:
		j->res = d->zeroes != NULL ? d->zeroes(d->ctx, j->off, j->len) : -ENOTSUP;
		break;
	default:
		j->res = d->flush != NULL ? d->flush(d->ctx) : 0;
		break;
	}
}

static void *dw_main(void *arg)
{
	dw *w = (dw *)arg;

	pthread_mutex_lock(&w->mu);
	for (;;) {
		djob *j;

		while (w->qn == 0u && !w->quit)
			pthread_cond_wait(&w->cv, &w->mu);
		if (w->qn == 0u)
			break;
		j = w->q[w->qhead];
		w->qhead = (w->qhead + 1u) % w->qcap;
		w->qn--;
		w->busy = 1;
		pthread_mutex_unlock(&w->mu);
		dw_exec(&w->dev, j);
		pthread_mutex_lock(&w->mu);
		w->busy = 0;
		j->done = 1;
		pthread_cond_broadcast(&w->cv_done);
	}
	pthread_mutex_unlock(&w->mu);
	return NULL;
}

static dw *dw_start(const wrl_cmp_dev *dev, unsigned qcap)
{
	dw *w = (dw *)calloc(1, sizeof(*w));

	if (w == NULL)
		return NULL;
	w->dev = *dev;
	w->qcap = qcap;
	w->q = (djob **)calloc(qcap, sizeof(djob *));
	if (w->q == NULL) {
		free(w);
		return NULL;
	}
	pthread_mutex_init(&w->mu, NULL);
	pthread_cond_init(&w->cv, NULL);
	w->mono = 0;
	{
		pthread_condattr_t ca;

		/* the engine's wait for a device call is bounded by the monotonic clock: a step of the wall clock must not stretch it (the watchdog runs
		 * between two waits) */
		if (pthread_condattr_init(&ca) == 0) {
			if (pthread_condattr_setclock(&ca, CLOCK_MONOTONIC) == 0 && pthread_cond_init(&w->cv_done, &ca) == 0)
				w->mono = 1;
			pthread_condattr_destroy(&ca);
		}
		if (!w->mono)
			pthread_cond_init(&w->cv_done, NULL);
	}
	if (pthread_create(&w->th, NULL, dw_main, w) != 0) {
		pthread_mutex_destroy(&w->mu);
		pthread_cond_destroy(&w->cv);
		pthread_cond_destroy(&w->cv_done);
		free((void *)w->q);
		free(w);
		return NULL;
	}
	w->started = 1;
	return w;
}

static void dw_submit(dw *w, djob *j)
{
	pthread_mutex_lock(&w->mu);
	j->done = 0;
	j->res = 0;
	w->q[(w->qhead + w->qn) % w->qcap] = j;
	w->qn++;
	pthread_cond_signal(&w->cv);
	pthread_mutex_unlock(&w->mu);
}

static int dw_done(dw *w, djob *j)
{
	int d;

	pthread_mutex_lock(&w->mu);
	d = j->done;
	pthread_mutex_unlock(&w->mu);
	return d;
}

/* Sleep until a device call finishes or about `usec` microseconds passed (a lost wake-up costs at most that). */
static void dw_wait(dw *w, unsigned usec)
{
	struct timespec ts;

	clock_gettime(w->mono ? CLOCK_MONOTONIC : CLOCK_REALTIME, &ts);
	ts.tv_nsec += (long)usec * 1000L;
	while (ts.tv_nsec >= 1000000000L) {
		ts.tv_nsec -= 1000000000L;
		ts.tv_sec++;
	}
	pthread_mutex_lock(&w->mu);
	(void)pthread_cond_timedwait(&w->cv_done, &w->mu, &ts);
	pthread_mutex_unlock(&w->mu);
}

/* 1 = the worker was idle and is gone, 0 = it is inside a device call: abandoned (the caller must keep everything it may touch). */
static int dw_stop(dw *w)
{
	int idle;

	pthread_mutex_lock(&w->mu);
	idle = !w->busy && w->qn == 0u;
	w->quit = 1;
	pthread_cond_signal(&w->cv);
	pthread_mutex_unlock(&w->mu);
	if (idle) {
		pthread_join(w->th, NULL);
		pthread_mutex_destroy(&w->mu);
		pthread_cond_destroy(&w->cv);
		pthread_cond_destroy(&w->cv_done);
		free((void *)w->q);
		free(w);
		return 1;
	}
	pthread_detach(w->th);
	keep(w);
	keep((void *)w->q);
	return 0;
}

/* ---- 4. the engine ------------------------------------------------------------------------------------------------ */

enum { WR_CORE = 1, WR_DEV = 2 }; /* writers */
enum { LS_IDLE = 0, LS_APPLY, LS_SWITCH, LS_VERIFY, LS_TRIAGE, LS_PAST, LS_SCAN, LS_DEAD };
enum { FB_CORE = 1, FB_DEV = 2 }; /* who failed the first pass */

typedef struct op {
	uint8_t kind, writer, pat;
	unsigned dir;
	uint64_t salt, no, off, len, classes;
	int switched;
} op;

typedef struct lane {
	int state;
	op o;
	wr_io_req req;
	int core_busy;
	wr_io_kind core_kind;
	uint64_t core_seq, t_core, t_dev[2]; /* when each request in flight was handed over (the watchdog's per-request age) */
	djob dj[2];
	int dj_busy[2];
	unsigned pending;
	uint8_t *wbuf, *cbuf, *dbuf, *tcbuf, *tdbuf, *tmbuf;
	uint64_t lo, hi, dhi;
	uint64_t need;       /* request buffer bytes charged to the memory budget */
	unsigned tries;
	unsigned first_bad;
	uint64_t pass_first; /* the first differing byte of the first pass (absolute offset) */
	wr_status core_st;
	long dev_res[2];
	int dev_apply;       /* the apply step ran a device operation (slot 0) */
} lane;

typedef struct eng {
	wrl_cmp_cfg c;
	FILE *out;
	uint64_t t0, last_prog, last_report;
	wr_image_info info;
	uint64_t size, obj, devsz, chunk, dchunk, gran, mem_max, stall_ms, ckpt;
	uint32_t sector, depth;
	model m;
	dw *w;
	lane *lanes;
	unsigned nl;
	wrl_cmp_result r;
	int stop, stalled, rc, corrupt_fired, model_flipped, core_dead;
	uint64_t mem_used, seq, nops, ncomp; /* ncomp: completions seen (core and device), to tell a step that did something */
	unsigned dev_busy, core_busy;
	/* the device scanner */
	djob sdj;
	int sdj_busy;
	uint64_t t_sdj;
	uint8_t *sbuf;
	uint64_t s_off, s_len;
	/* scan state */
	int sc_bad;
	unsigned sc_who;
	uint64_t sc_win_lo, sc_win_hi;
	uint64_t recent[RECENT][2];
	unsigned nrecent;
	op last_op;
	int have_last;
	uint8_t scratch[8192]; /* the buffer of a past-the-end request, which the core must refuse unread: such ops are at most one sector long */
} eng;

static uint64_t eng_now(const eng *e)
{
	struct timespec ts;

	if (e->c.now_ms != NULL)
		return e->c.now_ms(e->c.clock_ctx);
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

#if defined(__GNUC__) || defined(__clang__)
#define PRINTF_LIKE(a, b) __attribute__((format(printf, a, b)))
#else
#define PRINTF_LIKE(a, b)
#endif

static void rec(eng *e, const char *kind, const char *fmt, ...) PRINTF_LIKE(3, 4);

static void rec(eng *e, const char *kind, const char *fmt, ...)
{
	va_list ap;

	fprintf(e->out, "@%llu %s ", (unsigned long long)(eng_now(e) - e->t0), kind);
	va_start(ap, fmt);
	vfprintf(e->out, fmt, ap);
	va_end(ap);
	fputc('\n', e->out);
	fflush(e->out);
}

#define LLU(x) ((unsigned long long)(x))

static void fail(eng *e, int rc)
{
	if (e->rc == 0)
		e->rc = rc;
	e->stop = 1;
}

static int lane_busy(const lane *l)
{
	return l->state != LS_IDLE;
}

static unsigned lanes_active(const eng *e)
{
	unsigned i, n = 0;

	for (i = 0; i < e->nl; i++)
		n += lane_busy(&e->lanes[i]) ? 1u : 0u;
	return n;
}

static unsigned inflight(const eng *e)
{
	return e->core_busy + e->dev_busy;
}

/* A completion happened: the watchdog's clock restarts. */
static void progress(eng *e)
{
	uint64_t now = eng_now(e);

	e->ncomp++;
	if (inflight(e) > 0u && now - e->last_prog > e->r.max_gap_ms)
		e->r.max_gap_ms = now - e->last_prog;
	e->last_prog = now;
}

/* ---- lane buffers ---- */

static void lane_free_bufs(lane *l)
{
	free(l->wbuf);
	free(l->cbuf);
	free(l->dbuf);
	free(l->tcbuf);
	free(l->tdbuf);
	free(l->tmbuf);
	l->wbuf = l->cbuf = l->dbuf = l->tcbuf = l->tdbuf = l->tmbuf = NULL;
}

static void lane_release(eng *e, lane *l)
{
	lane_free_bufs(l);
	e->mem_used -= l->need < e->mem_used ? l->need : e->mem_used;
	l->need = 0;
	l->state = LS_IDLE;
	l->pending = 0;
	l->tries = 0;
	l->first_bad = 0;
}

static int lane_alloc(uint8_t **p, size_t n)
{
	if (*p != NULL)
		return 0;
	*p = (uint8_t *)xalloc(n);
	return *p != NULL ? 0 : -1;
}

/* ---- device and core submits ---- */

static void dev_submit(eng *e, lane *l, unsigned slot, int kind, uint64_t off, uint64_t len, void *buf)
{
	djob *j = &l->dj[slot];

	j->kind = kind;
	j->off = off;
	j->len = len;
	j->buf = buf;
	l->dj_busy[slot] = 1;
	l->t_dev[slot] = eng_now(e);
	e->dev_busy++;
	l->pending++;
	dw_submit(e->w, j);
}

/* 1 = queued, 0 = refused (st says why). */
static int core_submit(eng *e, lane *l, wr_io_kind k, uint64_t off, uint64_t len, void *buf, wr_status *st)
{
	memset(&l->req, 0, sizeof(l->req));
	l->req.kind = k;
	l->req.offset = off;
	l->req.length = len;
	l->req.buf = (k == WR_IO_READ || k == WR_IO_WRITE) ? buf : NULL;
	l->req.user = l;
	l->core_kind = k;
	l->core_seq = ++e->seq;
	*st = wr_image_submit(e->c.img, &l->req);
	if (*st != WR_OK)
		return 0;
	l->core_busy = 1;
	l->t_core = eng_now(e);
	e->core_busy++;
	l->pending++;
	return 1;
}

static void io_error(eng *e, const char *what, const lane *l, wr_status st, long dres)
{
	e->r.errors++;
	rec(e, "error", "%s op=%llu kind=%s off=%llu len=%llu status=%s (%s) dev_result=%ld", what, LLU(l->o.no), kind_name(l->o.kind),
	    LLU(l->o.off), LLU(l->o.len), wr_status_name(st), wr_strerror(st), dres);
	fail(e, 4);
}

static int submit_or_fail(eng *e, lane *l, wr_io_kind k, uint64_t off, uint64_t len, void *buf)
{
	wr_status st;

	if (core_submit(e, l, k, off, len, buf, &st))
		return 1;
	io_error(e, st == WR_E_BUSY ? "core request table full (--depth is above the engine's max_reqs)" : "core refused a request", l, st, 0);
	return 0;
}

/* ---- corruption hooks (test only) ---- */

static void corrupt_read(eng *e, unsigned who, uint64_t lo, uint8_t *buf, uint64_t n)
{
	if (e->c.corrupt != who || e->c.corrupt_off < lo || e->c.corrupt_off >= lo + n)
		return;
	if (e->c.corrupt_once && e->corrupt_fired)
		return;
	buf[e->c.corrupt_off - lo] ^= 0x01u;
	e->corrupt_fired = 1;
}

static void corrupt_model(eng *e, uint64_t lo, uint64_t hi)
{
	if (e->c.corrupt != WRL_CMP_CORRUPT_MODEL || e->model_flipped || e->c.corrupt_off < lo || e->c.corrupt_off >= hi)
		return;
	model_flip(&e->m, e->c.corrupt_off);
	e->model_flipped = 1;
}

/* ---- 5a. attribution ---------------------------------------------------------------------------------------------- */

static void emit_diff(eng *e, const lane *l, const char *verdict, const char *alone, uint64_t first, const char *note)
{
	uint64_t n = l->hi - l->lo, dn = l->dhi > l->lo ? l->dhi - l->lo : 0u, wlo, whi, dwhi;
	uint64_t dc = wrl_cmp_digest(l->tcbuf, (size_t)n, 0), dd = dn > 0u ? wrl_cmp_digest(l->tdbuf, (size_t)dn, 0) : 0u;
	uint64_t dm = wrl_cmp_digest(l->tmbuf, (size_t)n, 0), wc, wd = 0, wm;

	wlo = down(first, CHUNK);
	if (wlo < l->lo)
		wlo = l->lo;
	whi = down(first, CHUNK) + CHUNK;
	if (whi > l->hi)
		whi = l->hi;
	dwhi = whi < l->lo + dn ? whi : l->lo + dn;
	wc = wrl_cmp_digest(l->tcbuf + (wlo - l->lo), (size_t)(whi - wlo), 0);
	if (dn > 0u && wlo < dwhi)
		wd = wrl_cmp_digest(l->tdbuf + (wlo - l->lo), (size_t)(dwhi - wlo), 0);
	wm = wrl_cmp_digest(l->tmbuf + (wlo - l->lo), (size_t)(whi - wlo), 0);
	e->r.diffs++;
	e->r.diff_op = l->o.no;
	e->r.diff_off = l->o.off;
	e->r.diff_len = l->o.len;
	e->r.diff_first = first;
	e->r.dig_core = dc;
	e->r.dig_dev = dd;
	e->r.dig_model = dm;
	snprintf(e->r.verdict, sizeof(e->r.verdict), "%s", verdict);
	rec(e, "diff", "dir=%s op=%llu kind=%s writer=%s cls=%s off=%llu len=%llu lo=%llu hi=%llu first_diff=%llu window=%llu+%llu "
	    "core=%016llx krbd=%016llx model=%016llx wcore=%016llx wkrbd=%016llx wmodel=%016llx verdict=%s alone=%s first_pass=%s tries=%u%s%s seed=%llu",
	    dir_name(l->o.dir), LLU(l->o.no), kind_name(l->o.kind), l->o.writer == WR_CORE ? "core" : (l->o.writer == WR_DEV ? "krbd" : "none"),
	    first_class_name(l->o.classes), LLU(l->o.off), LLU(l->o.len), LLU(l->lo),
	    LLU(l->hi), LLU(first), LLU(wlo), LLU(whi - wlo), LLU(dc), LLU(dd), LLU(dm), LLU(wc), LLU(wd), LLU(wm), verdict, alone,
	    l->first_bad == (FB_CORE | FB_DEV) ? "both" : (l->first_bad == FB_CORE ? "core" : "krbd"), l->tries, note[0] != '\0' ? " note=" : "", note,
	    LLU(e->r.seed));
	fail(e, 1);
}

/* The fresh reads are in tcbuf (core) and tdbuf (device); decide. 1 = the lane is finished (ok, transient or failed), 0 = read again. */
static int triage_decide(eng *e, lane *l)
{
	uint64_t n = l->hi - l->lo, dn = l->dhi > l->lo ? l->dhi - l->lo : 0u, fc, fd = 0, fcd;
	int cm, dm, cd;
	const char *note = "";

	model_read(&e->m, l->lo, n, l->tmbuf);
	if (e->c.corrupt == WRL_CMP_CORRUPT_CORE)
		corrupt_read(e, WRL_CMP_CORRUPT_CORE, l->lo, l->tcbuf, n);
	if (e->c.corrupt == WRL_CMP_CORRUPT_DEV && dn > 0u)
		corrupt_read(e, WRL_CMP_CORRUPT_DEV, l->lo, l->tdbuf, dn);
	fc = model_first_diff(&e->m, l->lo, l->tcbuf, n);
	cm = fc == n;
	if (dn > 0u) {
		fd = model_first_diff(&e->m, l->lo, l->tdbuf, dn);
		dm = fd == dn;
	} else {
		dm = 1; /* no device witness for this range (the tail of an image that is not a whole number of sectors) */
	}
	fcd = dn > 0u ? (memcmp(l->tcbuf, l->tdbuf, (size_t)dn) == 0 ? dn : 0u) : n;
	cd = dn > 0u ? fcd == dn : 1;
	if (cm && dm) {
		if (l->first_bad == FB_DEV) { /* the first pass was damaged on the device side only, and it did not repeat */
			e->r.transients++;
			rec(e, "retry", "dir=%s op=%llu kind=%s off=%llu len=%llu lo=%llu hi=%llu verdict=device transient=1 first_diff=%llu note=first_read_of_the_device_differed_fresh_reads_agree",
			    dir_name(l->o.dir), LLU(l->o.no), kind_name(l->o.kind), LLU(l->o.off), LLU(l->o.len), LLU(l->lo), LLU(l->hi), LLU(l->pass_first));
			return 1;
		}
		/* the core's first read differed from the model and a second one did not: a core bug that comes and goes */
		emit_diff(e, l, "core", "core", l->pass_first, "transient_the_core_read_differed_once");
		return 1;
	}
	if (dm && !cm) {
		emit_diff(e, l, "core", "core", l->lo + fc, "");
		return 1;
	}
	if (cm && !dm) {
		if (l->tries == 0u) {
			l->tries++;
			rec(e, "retry", "dir=%s op=%llu kind=%s off=%llu len=%llu lo=%llu hi=%llu verdict=device first_diff=%llu note=reading_again",
			    dir_name(l->o.dir), LLU(l->o.no), kind_name(l->o.kind), LLU(l->o.off), LLU(l->o.len), LLU(l->lo), LLU(l->hi), LLU(l->lo + fd));
			return 0;
		}
		emit_diff(e, l, "device", "krbd", l->lo + fd, "");
		return 1;
	}
	if (cd) {
		note = l->o.writer == WR_CORE ? "writer_core:a_write_fault_both_readers_see_or_a_tool_bug" :
		       (l->o.writer == WR_DEV ? "writer_krbd:a_write_fault_both_readers_see_or_a_tool_bug" : "a_tool_bug");
		emit_diff(e, l, "model", "model", l->lo + (fc < fd || dn == 0u ? fc : fd), note);
		return 1;
	}
	emit_diff(e, l, "both", "none", l->lo + (fc < fd || dn == 0u ? fc : fd), "");
	return 1;
}

/* ---- lane state machine ------------------------------------------------------------------------------------------ */

static void lane_done_ok(eng *e, lane *l)
{
	if (l->o.kind != WRL_CMP_K_PAST)
		e->r.ops[l->o.kind]++;
	lane_release(e, l);
}

static int start_verify(eng *e, lane *l);
static int start_triage(eng *e, lane *l);

static void lane_apply_done(eng *e, lane *l)
{
	if (l->o.kind == WRL_CMP_K_FLUSH || l->o.kind == WRL_CMP_K_PAST) {
		if (l->o.kind == WRL_CMP_K_PAST)
			e->r.refusals_ok++;
		lane_done_ok(e, l);
		return;
	}
	if (l->o.switched && l->o.kind != WRL_CMP_K_READ && l->state == LS_APPLY) {
		/* the writer changed: BLKFLSBUF before the other side reads */
		l->state = LS_SWITCH;
		dev_submit(e, l, 0, DJ_FLUSH, 0, 0, NULL);
		return;
	}
	if (!start_verify(e, l))
		lane_release(e, l);
}

static int start_verify(eng *e, lane *l)
{
	uint64_t n = l->hi - l->lo;

	l->state = LS_VERIFY;
	l->pending = 0;
	if (lane_alloc(&l->cbuf, (size_t)n) != 0 || (l->dhi > l->lo && lane_alloc(&l->dbuf, (size_t)(l->dhi - l->lo)) != 0)) {
		rec(e, "error", "out of memory for the verification buffers op=%llu bytes=%llu", LLU(l->o.no), LLU(n));
		fail(e, 3);
		return 0;
	}
	if (!submit_or_fail(e, l, WR_IO_READ, l->lo, n, l->cbuf))
		return 0;
	if (l->dhi > l->lo)
		dev_submit(e, l, 1, DJ_READ, l->lo, l->dhi - l->lo, l->dbuf);
	return 1;
}

static int start_triage(eng *e, lane *l)
{
	uint64_t n = l->hi - l->lo;

	l->state = LS_TRIAGE;
	l->pending = 0;
	if (lane_alloc(&l->tcbuf, (size_t)n) != 0 || lane_alloc(&l->tmbuf, (size_t)n) != 0 || (l->dhi > l->lo && lane_alloc(&l->tdbuf, (size_t)(l->dhi - l->lo)) != 0)) {
		rec(e, "error", "out of memory for the triage buffers op=%llu bytes=%llu", LLU(l->o.no), LLU(n));
		fail(e, 3);
		return 0;
	}
	if (!submit_or_fail(e, l, WR_IO_READ, l->lo, n, l->tcbuf))
		return 0;
	if (l->dhi > l->lo)
		dev_submit(e, l, 1, DJ_READ, l->lo, l->dhi - l->lo, l->tdbuf);
	return 1;
}

/* The first pass of a verification is complete: compare with the model. */
static void verify_done(eng *e, lane *l)
{
	uint64_t n = l->hi - l->lo, dn = l->dhi > l->lo ? l->dhi - l->lo : 0u, cf, df;
	int core_bad, dev_bad;

	if (l->core_st != WR_OK) {
		io_error(e, "core read failed", l, l->core_st, l->dev_res[1]);
		lane_release(e, l);
		return;
	}
	if (dn > 0u && l->dev_res[1] != (long)dn) {
		io_error(e, l->dev_res[1] < 0 ? "device read failed" : "device read came back short", l, WR_OK, l->dev_res[1]);
		lane_release(e, l);
		return;
	}
	e->r.bytes_read_core += n;
	e->r.bytes_read_dev += dn;
	corrupt_model(e, l->lo, l->hi);
	corrupt_read(e, WRL_CMP_CORRUPT_CORE, l->lo, l->cbuf, n);
	if (dn > 0u)
		corrupt_read(e, WRL_CMP_CORRUPT_DEV, l->lo, l->dbuf, dn);
	cf = model_first_diff(&e->m, l->lo, l->cbuf, n);
	df = dn > 0u ? model_first_diff(&e->m, l->lo, l->dbuf, dn) : 0u;
	core_bad = cf != n;
	dev_bad = dn > 0u && df != dn;
	if (!core_bad && !dev_bad) {
		lane_done_ok(e, l);
		return;
	}
	l->first_bad = (core_bad ? (unsigned)FB_CORE : 0u) | (dev_bad ? (unsigned)FB_DEV : 0u);
	l->pass_first = l->lo + (core_bad && (!dev_bad || cf < df) ? cf : df);
	l->tries = 0;
	if (!start_triage(e, l))
		lane_release(e, l);
}

static void triage_done(eng *e, lane *l)
{
	uint64_t n = l->hi - l->lo, dn = l->dhi > l->lo ? l->dhi - l->lo : 0u;

	if (l->core_st != WR_OK || (dn > 0u && l->dev_res[1] != (long)dn)) {
		io_error(e, "a read during triage failed", l, l->core_st, l->dev_res[1]);
		lane_release(e, l);
		return;
	}
	e->r.bytes_read_core += n;
	e->r.bytes_read_dev += dn;
	if (triage_decide(e, l) || e->stop) {
		lane_release(e, l);
		return;
	}
	if (!start_triage(e, l))
		lane_release(e, l);
}

/* The refusal checks of a past-the-end op: the core's submit refused it (stage 0), the device's calls did (stage 1). */
static void past_done(eng *e, lane *l)
{
	if (l->dev_res[0] > 0 || l->dev_res[1] >= 0) {
		rec(e, "diff", "dir=%s op=%llu kind=past writer=none cls=past_end off=%llu len=%llu verdict=device alone=krbd note=the_device_accepted_a_request_at_or_past_its_end read=%ld write=%ld seed=%llu",
		    dir_name(l->o.dir), LLU(l->o.no), LLU(l->o.off), LLU(l->o.len), l->dev_res[0], l->dev_res[1], LLU(e->r.seed));
		e->r.diffs++;
		snprintf(e->r.verdict, sizeof(e->r.verdict), "device");
		fail(e, 1);
		lane_release(e, l);
		return;
	}
	lane_apply_done(e, l);
}

/* One completion (core or device) of a lane arrived; when all it waits for is in, move on. */
static void lane_event(eng *e, lane *l)
{
	if (l->pending > 0u)
		l->pending--;
	if (l->pending > 0u)
		return;
	if (e->stop && l->state != LS_IDLE && l->state != LS_SCAN && l->state != LS_DEAD) { /* the run is over: finish nothing new */
		lane_release(e, l);
		return;
	}
	switch (l->state) {
	case LS_APPLY:
		if (l->core_st != WR_OK) {
			io_error(e, "core write-class request failed", l, l->core_st, l->dev_res[0]);
			lane_release(e, l);
			return;
		}
		if (l->dev_apply && (l->dev_res[0] < 0 || (l->o.kind == WRL_CMP_K_WRITE && (uint64_t)l->dev_res[0] != l->dj[0].len))) {
			io_error(e, l->dev_res[0] < 0 ? (l->o.kind == WRL_CMP_K_FLUSH ? "device flush failed" : "device write-class request failed")
						      : "device write came back short", l, WR_OK, l->dev_res[0]);
			lane_release(e, l);
			return;
		}
		lane_apply_done(e, l);
		return;
	case LS_SWITCH:
		if (l->dev_res[0] < 0) {
			io_error(e, "device flush (BLKFLSBUF) failed", l, WR_OK, l->dev_res[0]);
			lane_release(e, l);
			return;
		}
		if (!start_verify(e, l))
			lane_release(e, l);
		return;
	case LS_VERIFY:
		verify_done(e, l);
		return;
	case LS_TRIAGE:
		triage_done(e, l);
		return;
	case LS_PAST:
		past_done(e, l);
		return;
	default:
		return;
	}
}

/* ---- operations: geometry, footprint, start ---- */

static void op_footprint(const eng *e, const op *o, uint64_t *lo, uint64_t *hi, uint64_t *dhi)
{
	uint64_t a = o->off, b = o->off + o->len, margin = 0;

	*lo = *hi = *dhi = 0;
	if (o->kind == WRL_CMP_K_FLUSH || o->kind == WRL_CMP_K_PAST)
		return;
	if (o->kind != WRL_CMP_K_READ)
		margin = e->sector;
	*lo = down(a > margin ? a - margin : 0u, e->sector);
	*hi = up(b + margin, e->sector); /* whole sectors, so the device reads every byte of the range, also of a one byte read */
	if (*hi > e->size)
		*hi = e->size;
	*dhi = *hi < e->devsz ? down(*hi, e->sector) : e->devsz;
	if (*dhi < *lo)
		*dhi = *lo;
}

static int footprints_overlap(const eng *e, uint64_t lo, uint64_t hi)
{
	unsigned i;

	if (hi <= lo)
		return 0;
	for (i = 0; i < e->nl; i++) {
		const lane *l = &e->lanes[i];

		if (lane_busy(l) && l->hi > l->lo && l->lo < hi && lo < l->hi)
			return 1;
	}
	return 0;
}

/* Does the model change like a write-class op? Applies the op to the model (the lane's range is exclusive, so now is as good as later). */
static void model_apply(eng *e, const op *o)
{
	if (o->kind == WRL_CMP_K_WRITE) {
		model_write(&e->m, o->off, o->len, o->pat, o->salt);
	} else if (o->kind == WRL_CMP_K_DISCARD) {
		if (o->writer == WR_DEV && !e->c.mirror)
			model_discard_dev(&e->m, o->off, o->len, e->obj, e->gran);
		else
			model_zero(&e->m, o->off, o->len);
	} else if (o->kind == WRL_CMP_K_ZEROES) {
		model_zero(&e->m, o->off, o->len);
	}
}

static void account_write(eng *e, const op *o)
{
	if (o->kind != WRL_CMP_K_WRITE && o->kind != WRL_CMP_K_DISCARD && o->kind != WRL_CMP_K_ZEROES)
		return;
	if (o->writer == WR_DEV) {
		e->r.writes_dev++;
		e->r.bytes_written_dev += o->len;
	} else {
		e->r.writes_core++;
		e->r.bytes_written_core += o->len;
	}
}

static wr_io_kind io_kind_of(unsigned k)
{
	return k == WRL_CMP_K_WRITE ? WR_IO_WRITE : (k == WRL_CMP_K_DISCARD ? WR_IO_DISCARD : (k == WRL_CMP_K_ZEROES ? WR_IO_WRITE_ZEROES : WR_IO_FLUSH));
}

static uint64_t op_need(const op *o, uint64_t lo, uint64_t hi, uint64_t dhi)
{
	uint64_t n = (hi - lo) + (dhi - lo);

	if (o->kind == WRL_CMP_K_WRITE)
		n += o->len;
	return n;
}

/* The past-the-end op: the core's submits must be refused (WR_E_RANGE); the device's read and write at its end must fail. */
static void start_past(eng *e, lane *l)
{
	wr_status st;
	unsigned i;
	uint64_t at;

	l->state = LS_PAST;
	l->pending = 0;
	if (l->o.len > sizeof(e->scratch)) { /* the generators never make one: a request the core wrongly accepted would run over the buffer */
		rec(e, "error", "a past-the-end op of %llu bytes does not fit the scratch buffer op=%llu", LLU(l->o.len), LLU(l->o.no));
		fail(e, 3);
		l->state = LS_IDLE;
		return;
	}
	for (i = 0; i < 2u; i++) {
		memset(&l->req, 0, sizeof(l->req));
		l->req.kind = i == 0u ? WR_IO_READ : WR_IO_WRITE;
		l->req.offset = l->o.off;
		l->req.length = l->o.len;
		l->req.buf = e->scratch;
		l->req.user = l;
		st = wr_image_submit(e->c.img, &l->req);
		if (st == WR_E_RANGE)
			continue;
		if (st == WR_OK) { /* accepted: nothing of it may happen, so no buffer is needed: cancel it at once */
			rec(e, "diff", "dir=%s op=%llu kind=past writer=core cls=past_end off=%llu len=%llu verdict=core alone=core note=the_core_accepted_a_%s_at_or_past_the_end seed=%llu",
			    dir_name(l->o.dir), LLU(l->o.no), LLU(l->o.off), LLU(l->o.len), i == 0u ? "read" : "write", LLU(e->r.seed));
			e->r.diffs++;
			snprintf(e->r.verdict, sizeof(e->r.verdict), "core");
			l->state = LS_DEAD; /* the request is still the core's: its completion is collected by core_done */
			l->core_busy = 1;
			l->core_kind = l->req.kind;
			l->core_seq = ++e->seq;
			l->t_core = eng_now(e); /* the watchdog's age of it starts now, not at whatever this lane did before */
			e->core_busy++;
			if (wr_image_cancel(e->c.img, &l->req) != WR_OK)
				l->core_busy = 1; /* WR_E_BUSY: the core cancels it by itself; either way core_done collects it */
			fail(e, 1);
			return;
		}
		io_error(e, "the core refused a past-the-end request with a status other than WR_E_RANGE", l, st, 0);
		l->state = LS_IDLE;
		return;
	}
	/* the device: only for requests that begin at the end of the image or beyond it; one that crosses it is the core's check alone */
	if (l->o.off >= e->size) {
		/* the first sector at or past the end of the image AND of the device: the device's own end when the image is a whole number of sectors,
		 * else the next boundary (a block device shows none of the odd tail; a regular file of the self test holds it) */
		at = (e->size % e->sector == 0u ? e->devsz : up(e->size, e->sector)) + (l->o.off - e->size) / e->sector * e->sector;
		if (lane_alloc(&l->cbuf, e->sector) != 0) {
			fail(e, 3);
			l->state = LS_IDLE;
			return;
		}
		memset(l->cbuf, 0, e->sector);
		l->need = e->sector;
		e->mem_used += l->need;
		l->dev_res[0] = -1;
		l->dev_res[1] = -1;
		dev_submit(e, l, 0, DJ_READ, at, e->sector, l->cbuf);
		dev_submit(e, l, 1, DJ_WRITE, at, e->sector, l->cbuf);
		return;
	}
	l->dev_res[0] = l->dev_res[1] = -1;
	lane_apply_done(e, l);
}

static void start_apply(eng *e, lane *l)
{
	const op *o = &l->o;
	wr_status st;

	l->state = LS_APPLY;
	l->pending = 0;
	l->dev_res[0] = l->dev_res[1] = 0;
	l->dev_apply = 0;
	l->core_st = WR_OK;
	if (o->kind == WRL_CMP_K_READ) {
		lane_apply_done(e, l);
		return;
	}
	if (o->kind == WRL_CMP_K_FLUSH) {
		if (!submit_or_fail(e, l, WR_IO_FLUSH, 0, 0, NULL))
			goto fail_lane;
		l->dev_apply = 1;
		dev_submit(e, l, 0, DJ_FLUSH, 0, 0, NULL);
		return;
	}
	if (o->kind == WRL_CMP_K_WRITE && lane_alloc(&l->wbuf, (size_t)o->len) != 0) {
		rec(e, "error", "out of memory for a write buffer op=%llu bytes=%llu", LLU(o->no), LLU(o->len));
		fail(e, 3);
		goto fail_lane;
	}
	if (o->kind == WRL_CMP_K_WRITE)
		pat_fill(o->pat, o->salt, o->off, l->wbuf, (size_t)o->len);
	if (o->writer == WR_CORE || e->c.mirror) {
		if (!core_submit(e, l, io_kind_of(o->kind), o->off, o->len, l->wbuf, &st)) {
			io_error(e, "core refused a request", l, st, 0);
			goto fail_lane;
		}
	}
	if (o->writer == WR_DEV || e->c.mirror) {
		int dk = o->kind == WRL_CMP_K_WRITE ? DJ_WRITE : (o->kind == WRL_CMP_K_DISCARD ? DJ_DISCARD : DJ_ZEROES);

		if (e->c.mirror && o->writer == WR_CORE && dk == DJ_DISCARD)
			dk = DJ_ZEROES; /* the file has no cache and no granularity: a discard is zeros, exactly like the core's */
		l->dev_apply = 1;
		dev_submit(e, l, 0, dk, o->off, o->len, l->wbuf);
	}
	return;
fail_lane:
	lane_release(e, l);
}

/* 1 = started, 0 = could not now (conflict or memory), the caller tries again after a completion. */
static int lane_start(eng *e, const op *o)
{
	uint64_t lo, hi, dhi, need;
	unsigned i;
	lane *l = NULL;

	for (i = 0; i < e->nl; i++)
		if (!lane_busy(&e->lanes[i])) {
			l = &e->lanes[i];
			break;
		}
	if (l == NULL)
		return 0;
	op_footprint(e, o, &lo, &hi, &dhi);
	if (footprints_overlap(e, lo, hi))
		return 0;
	need = op_need(o, lo, hi, dhi);
	if (e->mem_used > 0u && e->mem_used + need > e->mem_max)
		return 0;
	if (lanes_active(e) == 0u && inflight(e) == 0u)
		e->last_prog = eng_now(e);
	l->o = *o;
	l->lo = lo;
	l->hi = hi;
	l->dhi = dhi;
	l->need = need;
	e->mem_used += need;
	l->tries = 0;
	l->first_bad = 0;
	account_write(e, &l->o);
	if (o->kind == WRL_CMP_K_PAST) {
		start_past(e, l);
		if (l->state == LS_IDLE)
			lane_release(e, l);
		return 1;
	}
	model_apply(e, &l->o);
	if (e->m.oom) {
		rec(e, "error", "the model ran out of memory");
		fail(e, 3);
		lane_release(e, l);
		return 1;
	}
	start_apply(e, l);
	return 1;
}

/* ---- the pump step and its completions ---- */

static void core_done(eng *e, wr_io_req *r)
{
	lane *l = (lane *)r->user;

	if (l == NULL || l < e->lanes || l >= e->lanes + e->nl || !l->core_busy || r != &l->req) {
		if (e->r.bad_completions++ < 8u)
			rec(e, "error", "completion of a request that is not in flight (twice?) status=%s", wr_status_name(r->status));
		fail(e, 4);
		return;
	}
	l->core_busy = 0;
	e->core_busy--;
	l->core_st = r->status;
	progress(e);
	if (l->core_kind == WR_IO_FLUSH && r->status == WR_OK) {
		unsigned i;

		for (i = 0; i < e->nl; i++) { /* every write accepted before the flush must have completed */
			const lane *w = &e->lanes[i];

			if (w != l && w->core_busy && w->core_seq < l->core_seq && w->core_kind != WR_IO_READ && w->core_kind != WR_IO_FLUSH) {
				if (e->r.barrier_violations++ < 8u)
					rec(e, "error", "flush completed before an earlier write: kind=%d off=%llu len=%llu", (int)w->core_kind, LLU(w->req.offset), LLU(w->req.length));
				fail(e, 4);
				break;
			}
		}
	}
	lane_event(e, l);
}

static void harvest_dev(eng *e)
{
	unsigned i, k;

	for (i = 0; i < e->nl; i++) {
		lane *l = &e->lanes[i];

		for (k = 0; k < 2u; k++) {
			if (l->dj_busy[k] && dw_done(e->w, &l->dj[k])) {
				l->dj_busy[k] = 0;
				e->dev_busy--;
				l->dev_res[k] = l->dj[k].res;
				progress(e);
				lane_event(e, l);
			}
		}
	}
}

static void pump_events(eng *e)
{
	wr_event ev;
	wr_mapmsg mm;

	while (wr_client_next_event(e->c.client, &ev)) {
		if (ev.kind == WR_EV_IO_STALL)
			e->r.n_stall++;
		else if (ev.kind == WR_EV_IO_RESUME)
			e->r.n_resume++;
		else if (ev.kind == WR_EV_FATAL || ev.kind == WR_EV_AUTH_FAILED)
			rec(e, "event", "%s status=%s what=\"%s\"", ev.kind == WR_EV_FATAL ? "FATAL" : "AUTH_FAILED", wr_status_name(ev.err.status),
			    ev.err.what != NULL ? ev.err.what : "");
		if (e->c.verbose && ev.kind != WR_EV_MAP && ev.kind != WR_EV_MAPMSG)
			rec(e, "event", "kind=%d epoch=%u status=%s", (int)ev.kind, (unsigned)ev.epoch, wr_status_name(ev.err.status));
	}
	while (wr_client_mapmsg_peek(e->c.client, &mm)) /* only when the engine does not consume the maps itself */
		wr_client_mapmsg_release(e->c.client);
}

/* The watchdog: a request (a core request or a device call) handed over longer ago than stall_ms and not answered is a hang. */
static void check_stall(eng *e)
{
	uint64_t now, age, worst = 0;
	unsigned i, k;

	if (inflight(e) == 0u || e->stalled)
		return;
	now = eng_now(e);
	for (i = 0; i < e->nl; i++) {
		const lane *l = &e->lanes[i];

		if (l->core_busy && now - l->t_core > worst)
			worst = now - l->t_core;
		for (k = 0; k < 2u; k++)
			if (l->dj_busy[k] && now - l->t_dev[k] > worst)
				worst = now - l->t_dev[k];
	}
	age = e->sdj_busy ? now - e->t_sdj : 0u;
	if (age > worst)
		worst = age;
	if (worst <= e->stall_ms)
		return;
	e->stalled = 1;
	if (worst > e->r.max_gap_ms)
		e->r.max_gap_ms = worst;
	for (i = 0; i < e->nl; i++) {
		const lane *l = &e->lanes[i];

		if (lane_busy(l))
			rec(e, "stall", "lane=%u state=%d op=%llu kind=%s off=%llu len=%llu core_busy=%d device_jobs=%d", i, l->state, LLU(l->o.no),
			    kind_name(l->o.kind), LLU(l->o.off), LLU(l->o.len), l->core_busy, l->dj_busy[0] + l->dj_busy[1]);
	}
	rec(e, "stall", "a request has had no answer for %llu ms (limit %llu) core_inflight=%u device_inflight=%u: hang", LLU(worst), LLU(e->stall_ms),
	    e->core_busy, e->dev_busy);
	fail(e, 4);
}

static void eng_step(eng *e)
{
	wr_io_req *r;
	int devwait = e->dev_busy > 0u;
	uint64_t before = e->ncomp;
	wr_status st = wrl_loop_step(e->c.loop, devwait ? 0 : 20);

	pump_events(e);
	if (st != WR_OK && !e->core_dead) {
		e->core_dead = 1;
		rec(e, "error", "the client failed: status=%s (%s)", wr_status_name(st), wr_strerror(st));
		fail(e, 3);
	}
	if (wr_image_get_state(e->c.img) == WR_IMG_FAILED && !e->core_dead) {
		const wr_errinfo *ei = wr_image_error(e->c.img);

		e->core_dead = 1;
		rec(e, "error", "the image failed: status=%s peer_result=%d what=\"%s\"", wr_status_name(ei->status), (int)ei->peer_result,
		    ei->what != NULL ? ei->what : "");
		fail(e, 3);
	}
	harvest_dev(e);
	while ((r = wr_client_next_done(e->c.client)) != NULL)
		core_done(e, r);
	if (devwait && e->ncomp == before && !e->stop) /* a device call is out and nothing came back: sleep on its completion, a little */
		dw_wait(e->w, 300);
	check_stall(e);
}

/* ---- 5b. scan ------------------------------------------------------------------------------------------------------ */

static void scan_mismatch(eng *e, unsigned who, uint64_t off, uint64_t first)
{
	if (e->sc_bad)
		return;
	e->sc_bad = 1;
	e->sc_who = who;
	e->sc_win_lo = down(off + first, CHUNK);
	e->sc_win_hi = e->sc_win_lo + CHUNK < e->size ? e->sc_win_lo + CHUNK : e->size;
}

static void scan_core_done(eng *e, lane *l)
{
	uint64_t first;

	if (l->core_st != WR_OK) {
		io_error(e, "core read failed during the scan", l, l->core_st, 0);
		lane_release(e, l);
		return;
	}
	e->r.scan_bytes_core += l->o.len;
	corrupt_read(e, WRL_CMP_CORRUPT_CORE, l->o.off, l->cbuf, l->o.len);
	first = model_first_diff(&e->m, l->o.off, l->cbuf, l->o.len);
	if (first != l->o.len)
		scan_mismatch(e, FB_CORE, l->o.off, first);
	lane_release(e, l);
}

static void scan_dev_done(eng *e)
{
	uint64_t first;

	if (e->sdj.res != (long)e->s_len) {
		rec(e, "error", "%s during the scan off=%llu len=%llu dev_result=%ld", e->sdj.res < 0 ? "device read failed" : "device read came back short",
		    LLU(e->s_off), LLU(e->s_len), e->sdj.res);
		fail(e, 4);
		return;
	}
	e->r.scan_bytes_dev += e->s_len;
	corrupt_read(e, WRL_CMP_CORRUPT_DEV, e->s_off, e->sbuf, e->s_len);
	first = model_first_diff(&e->m, e->s_off, e->sbuf, e->s_len);
	if (first != e->s_len)
		scan_mismatch(e, FB_DEV, e->s_off, first);
}

/* Run the triage of a window that a scan read found different: lane 0 does it like any other verification. */
static int scan_triage(eng *e)
{
	lane *l = &e->lanes[0];

	memset(&l->o, 0, sizeof(l->o));
	l->o.kind = WRL_CMP_K_READ;
	l->o.dir = 0;
	l->o.no = e->nops;
	l->o.off = e->sc_win_lo;
	l->o.len = e->sc_win_hi - e->sc_win_lo;
	l->o.classes = 0;
	l->lo = e->sc_win_lo;
	l->hi = e->sc_win_hi;
	l->dhi = l->hi < e->devsz ? down(l->hi, e->sector) : e->devsz;
	if (l->dhi < l->lo)
		l->dhi = l->lo;
	l->need = (l->hi - l->lo) * 3u;
	e->mem_used += l->need;
	l->first_bad = e->sc_who;
	l->pass_first = e->sc_win_lo;
	l->tries = 0;
	l->dev_res[0] = l->dev_res[1] = 0;
	l->core_st = WR_OK;
	if (!start_triage(e, l)) {
		lane_release(e, l);
		return -1;
	}
	while (lane_busy(l) && !e->stop)
		eng_step(e);
	return e->stop ? -1 : 0; /* 0 = the window turned out to be a transient device fault */
}

/* A full read of the image by both clients against the model. 0 ok, -1 failed or stopped. */
static int scan_run(eng *e, const char *why)
{
	unsigned restarts = 0, i;
	uint64_t t0 = eng_now(e);

	e->r.scans++;
	for (;;) {
		uint64_t cnext = 0, dnext = 0;

		e->sc_bad = 0;
		while (!e->stop) {
			if (!e->sc_bad) {
				for (i = 0; i < e->nl && cnext < e->size; i++) {
					lane *l = &e->lanes[i];
					uint64_t n;

					if (lane_busy(l))
						continue;
					n = e->chunk < e->size - cnext ? e->chunk : e->size - cnext;
					if (lane_alloc(&l->cbuf, (size_t)n) != 0) {
						fail(e, 3);
						break;
					}
					l->state = LS_SCAN;
					memset(&l->o, 0, sizeof(l->o));
					l->o.kind = WRL_CMP_K_READ;
					l->o.off = cnext;
					l->o.len = n;
					l->pending = 0;
					l->need = 0;
					l->lo = l->hi = l->dhi = 0;
					if (!submit_or_fail(e, l, WR_IO_READ, cnext, n, l->cbuf)) {
						lane_release(e, l);
						break;
					}
					cnext += n;
				}
				if (!e->sdj_busy && dnext < e->devsz && !e->stop) {
					uint64_t n = e->dchunk < e->devsz - dnext ? e->dchunk : e->devsz - dnext;

					e->s_off = dnext;
					e->s_len = n;
					e->sdj.kind = DJ_READ;
					e->sdj.off = dnext;
					e->sdj.len = n;
					e->sdj.buf = e->sbuf;
					e->sdj_busy = 1;
					e->t_sdj = eng_now(e);
					e->dev_busy++;
					dw_submit(e->w, &e->sdj);
					dnext += n;
				}
			}
			if (cnext >= e->size && dnext >= e->devsz && lanes_active(e) == 0u && !e->sdj_busy)
				break;
			if (e->sc_bad && lanes_active(e) == 0u && !e->sdj_busy)
				break;
			eng_step(e);
			if (e->sdj_busy && dw_done(e->w, &e->sdj)) {
				e->sdj_busy = 0;
				e->dev_busy--;
				progress(e);
				scan_dev_done(e);
			}
			for (i = 0; i < e->nl; i++) {
				lane *l = &e->lanes[i];

				if (l->state == LS_SCAN && !l->core_busy) {
					scan_core_done(e, l);
				}
			}
		}
		if (e->stop)
			return -1;
		if (!e->sc_bad)
			break;
		if (scan_triage(e) != 0 || e->stop)
			return -1;
		/* the triage said the device alone differed once and not again: look at the whole image again, a bounded number of times */
		if (++restarts > SCAN_RESTARTS) {
			rec(e, "error", "the scan found a transient device difference %u times: giving up", restarts);
			fail(e, 1);
			return -1;
		}
	}
	rec(e, "scan", "why=%s core_bytes=%llu krbd_bytes=%llu ms=%llu ok=1", why, LLU(e->size), LLU(e->devsz), LLU(eng_now(e) - t0));
	return 0;
}

/* ---- 5c. generators and phases -------------------------------------------------------------------------------- */

typedef struct gen {
	int edges;
	unsigned dir;
	wrl_cmp_edge *list;
	uint32_t n, i;
	uint64_t ops_left, deadline; /* random: 0 deadline = none */
	int have;
	op next;
} gen;

static uint64_t rng_next(uint64_t *s)
{
	*s += 0x9e3779b97f4a7c15ull;
	return mix64(*s);
}

static uint64_t rng_below(uint64_t *s, uint64_t n)
{
	return n <= 1u ? 0u : rng_next(s) % n;
}

/* The writer of the op by direction; reads and flushes have none. */
static uint8_t pick_writer(unsigned dir, uint64_t no)
{
	if (dir == WRL_CMP_DIR_C2K)
		return WR_CORE;
	if (dir == WRL_CMP_DIR_K2C)
		return WR_DEV;
	return (no & 1u) != 0u ? WR_DEV : WR_CORE;
}

/* The device writes whole sectors: round the range out (and inside its capacity). A range that ends up empty is turned into a read. */
static void op_for_writer(const eng *e, op *o)
{
	if (o->kind != WRL_CMP_K_WRITE && o->kind != WRL_CMP_K_DISCARD && o->kind != WRL_CMP_K_ZEROES)
		return;
	if (o->writer == WR_DEV && !e->c.mirror) {
		uint64_t lo = down(o->off, e->sector), hi = up(o->off + o->len, e->sector);

		if (hi > e->devsz)
			hi = e->devsz;
		if (hi <= lo) {
			o->kind = WRL_CMP_K_READ;
			o->writer = 0;
			return;
		}
		o->off = lo;
		o->len = hi - lo;
	}
}

static void gen_edge(eng *e, gen *g, op *o)
{
	const wrl_cmp_edge *d = &g->list[g->i];

	memset(o, 0, sizeof(*o));
	o->kind = d->kind;
	o->off = d->off;
	o->len = d->len;
	o->pat = d->pat;
	o->classes = d->classes;
	o->dir = g->dir;
	o->no = e->nops;
	o->salt = mix64(e->r.seed ^ (o->no * 0xd1342543de82ef95ull));
	o->writer = pick_writer(g->dir, o->no);
	if (d->kind == WRL_CMP_K_READ || d->kind == WRL_CMP_K_FLUSH || d->kind == WRL_CMP_K_PAST)
		o->writer = 0;
	if (g->dir == WRL_CMP_DIR_INTER && o->writer != 0u) /* alternate per write-class op, not per list entry, so each class meets both writers */
		o->writer = (e->r.writes_core + e->r.writes_dev) % 2u == 0u ? WR_CORE : WR_DEV;
	op_for_writer(e, o);
}

static void note_recent(eng *e, const op *o)
{
	if (o->kind == WRL_CMP_K_FLUSH || o->kind == WRL_CMP_K_PAST || o->len == 0u)
		return;
	e->recent[e->nrecent % RECENT][0] = o->off;
	e->recent[e->nrecent % RECENT][1] = o->len;
	e->nrecent++;
}

static void gen_random(eng *e, gen *g, op *o)
{
	uint64_t s = mix64(e->r.seed ^ (e->nops * 0xa24baed4963ee407ull)), maxlen = e->c.max_len, nb = e->size / e->obj;
	uint64_t r, off, len, w;
	unsigned bucket;

	memset(o, 0, sizeof(*o));
	o->dir = g->dir;
	o->no = e->nops;
	o->salt = mix64(s ^ 0x5851f42d4c957f2dull);
	r = rng_below(&s, 100);
	o->kind = r < 24 ? WRL_CMP_K_READ : (r < 72 ? WRL_CMP_K_WRITE : (r < 82 ? WRL_CMP_K_DISCARD : (r < 92 ? WRL_CMP_K_ZEROES : (r < 96 ? WRL_CMP_K_FLUSH : WRL_CMP_K_WRITE))));
	r = rng_below(&s, 100);
	o->pat = r < 84 ? 0u : (r < 92 ? 2u : (r < 96 ? 1u : 0u));
	if (o->kind == WRL_CMP_K_FLUSH) {
		o->writer = 0;
		return;
	}
	/* length: small ranges are where ragged edges live */
	bucket = (unsigned)rng_below(&s, 100);
	if (bucket < 30u)
		len = 1u + rng_below(&s, 512);
	else if (bucket < 55u)
		len = 513u + rng_below(&s, 15872);
	else if (bucket < 80u)
		len = 16384u + rng_below(&s, e->obj > 16384u ? e->obj - 16384u : 1u);
	else
		len = 1u + rng_below(&s, maxlen);
	if (len > maxlen)
		len = maxlen;
	if (len > e->size)
		len = e->size;
	/* offset: object boundaries (40%), what an earlier operation touched (15%, 40% when interleaving), the end of the image (10%), anywhere */
	w = rng_below(&s, 100);
	if (w < 40u && nb > 0u) {
		uint64_t b = (1u + rng_below(&s, nb)) * e->obj, d = rng_below(&s, 4u * e->sector + 33u), c1 = rng_next(&s), c2 = rng_next(&s);

		off = (c1 & 1u) != 0u ? b + d : (b >= d ? b - d : 0u);
		if ((c2 & 1u) != 0u)
			off = off > len ? off - len : 0u; /* ends near the boundary instead of starting there */
	} else if (w < (g->dir == WRL_CMP_DIR_INTER ? 80u : 55u) && e->nrecent > 0u) {
		unsigned k = (unsigned)rng_below(&s, e->nrecent < RECENT ? e->nrecent : RECENT);
		uint64_t ro = e->recent[k][0], rl = e->recent[k][1], d = rng_below(&s, rl + 1u), c1 = rng_next(&s);

		off = (c1 & 1u) != 0u ? ro + d : (ro >= d ? ro - d : 0u);
	} else if (w < 65u) {
		uint64_t back = rng_below(&s, 2u * e->sector + 1u);

		off = e->size > len + back ? e->size - len - back : 0u;
	} else {
		off = rng_below(&s, e->size);
	}
	if (off >= e->size)
		off = e->size - 1u;
	if (len > e->size - off)
		len = e->size - off;
	o->off = off;
	o->len = len;
	o->writer = pick_writer(g->dir, e->nops);
	if (o->kind == WRL_CMP_K_READ)
		o->writer = 0;
	op_for_writer(e, o);
}

/* The next op of the generator without taking it; 0 = exhausted. */
static int gen_peek(eng *e, gen *g)
{
	if (g->have)
		return 1;
	if (g->edges) {
		if (g->i >= g->n)
			return 0;
		gen_edge(e, g, &g->next);
	} else {
		if (g->ops_left == 0u || (g->deadline != 0u && eng_now(e) >= g->deadline))
			return 0;
		gen_random(e, g, &g->next);
	}
	if (e->have_last)
		g->next.switched = g->next.writer != 0u && e->last_op.writer != 0u && g->next.writer != e->last_op.writer;
	g->have = 1;
	return 1;
}

static void gen_take(eng *e, gen *g)
{
	if (g->next.writer != 0u || g->next.kind == WRL_CMP_K_WRITE || g->next.kind == WRL_CMP_K_DISCARD || g->next.kind == WRL_CMP_K_ZEROES) {
		e->last_op = g->next;
		e->have_last = 1;
	}
	note_recent(e, &g->next);
	g->have = 0;
	if (g->edges) {
		g->i++;
		e->r.edges_run++;
	} else if (g->ops_left > 0u) {
		g->ops_left--;
	}
	e->nops++;
}

static void report_progress(eng *e, const char *phase)
{
	uint64_t now = eng_now(e);

	if (now - e->last_report < (e->c.verbose ? PROGRESS_MS / 15u : PROGRESS_MS))
		return;
	e->last_report = now;
	rec(e, "progress", "phase=%s ops=%llu reads=%llu writes=%llu discards=%llu zeroes=%llu flushes=%llu core_written=%llu krbd_written=%llu model_chunks=%llu inflight=%u",
	    phase, LLU(e->nops), LLU(e->r.ops[WRL_CMP_K_READ]), LLU(e->r.ops[WRL_CMP_K_WRITE]), LLU(e->r.ops[WRL_CMP_K_DISCARD]),
	    LLU(e->r.ops[WRL_CMP_K_ZEROES]), LLU(e->r.ops[WRL_CMP_K_FLUSH]), LLU(e->r.bytes_written_core), LLU(e->r.bytes_written_dev),
	    LLU(e->m.used), lanes_active(e));
}

/* Run one generator to the end (issuing, completing, checkpointing); drains before it returns. */
static int run_gen(eng *e, gen *g, const char *phase)
{
	uint64_t since_ckpt = 0;
	int ckpt_due = 0;

	while (!e->stop) {
		int issued = 0;

		while (!e->stop && !ckpt_due && gen_peek(e, g)) {
			if (!lane_start(e, &g->next))
				break;
			gen_take(e, g);
			issued = 1;
			if (!g->edges && ++since_ckpt >= e->ckpt)
				ckpt_due = 1;
		}
		if (ckpt_due && lanes_active(e) == 0u && !e->stop) {
			e->r.checkpoints++;
			if (scan_run(e, "checkpoint") != 0)
				break;
			ckpt_due = 0;
			since_ckpt = 0;
			continue;
		}
		if (!g->have && !gen_peek(e, g) && lanes_active(e) == 0u && !ckpt_due)
			break;
		if (!issued || lanes_active(e) > 0u)
			eng_step(e);
		report_progress(e, phase);
	}
	return e->stop ? -1 : 0;
}

/* Wait for everything in flight (bounded), so the caller may free its buffers. */
static void drain(eng *e)
{
	uint64_t t0 = eng_now(e);

	while (inflight(e) > 0u && !e->stalled && !e->core_dead && eng_now(e) - t0 < DRAIN_GRACE_MS + e->stall_ms) {
		eng_step(e);
		if (e->sdj_busy && dw_done(e->w, &e->sdj)) {
			e->sdj_busy = 0;
			e->dev_busy--;
		}
	}
}

static unsigned dir_list(unsigned mask, unsigned *out)
{
	unsigned n = 0;

	if (mask & WRL_CMP_DIR_C2K)
		out[n++] = WRL_CMP_DIR_C2K;
	if (mask & WRL_CMP_DIR_K2C)
		out[n++] = WRL_CMP_DIR_K2C;
	if (mask & WRL_CMP_DIR_INTER)
		out[n++] = WRL_CMP_DIR_INTER;
	return n;
}

static int phase_edges(eng *e, const unsigned *dirs, unsigned nd)
{
	wrl_cmp_geom geo;
	wrl_cmp_edge *list;
	uint32_t n;
	unsigned d;
	int rc = 0;

	geo.size = e->size;
	geo.order = e->info.order;
	geo.sector = e->sector;
	n = wrl_cmp_edges_build(&geo, NULL, 0);
	list = (wrl_cmp_edge *)calloc(n != 0u ? n : 1u, sizeof(*list));
	if (list == NULL || n == 0u) {
		free(list);
		rec(e, "error", "no edge list for this geometry (size=%llu order=%u)", LLU(e->size), (unsigned)geo.order);
		fail(e, 3);
		return -1;
	}
	(void)wrl_cmp_edges_build(&geo, list, n);
	rec(e, "phase", "name=edges edges=%u dirs=%u", (unsigned)n, nd);
	for (d = 0; d < nd && rc == 0; d++) {
		gen g;

		memset(&g, 0, sizeof(g));
		g.edges = 1;
		g.dir = dirs[d];
		g.list = list;
		g.n = n;
		rc = run_gen(e, &g, "edges");
		if (rc == 0)
			rec(e, "phase", "name=edges dir=%s done ops=%llu", dir_name(dirs[d]), LLU(e->nops));
	}
	free(list);
	return rc;
}

static int phase_random(eng *e, const unsigned *dirs, unsigned nd)
{
	unsigned d;
	uint64_t total = e->c.ops, per, rem;
	uint64_t time_per = e->c.time_ms / nd;
	int rc = 0;

	if (total == 0u && e->c.time_ms == 0u)
		total = DEFAULT_OPS;
	if (total == 0u)
		total = UINT64_MAX / 2u; /* bounded by the time only */
	per = total / nd;
	rem = total % nd;
	rec(e, "phase", "name=random ops=%llu time_ms=%llu dirs=%u max_len=%llu checkpoint=%llu", LLU(e->c.ops != 0u || e->c.time_ms == 0u ? total : 0u),
	    LLU(e->c.time_ms), nd, LLU(e->c.max_len), LLU(e->ckpt));
	for (d = 0; d < nd && rc == 0; d++) {
		gen g;
		uint64_t before = e->nops;

		memset(&g, 0, sizeof(g));
		g.dir = dirs[d];
		g.ops_left = per + (d + 1u == nd ? rem : 0u);
		g.deadline = e->c.time_ms != 0u ? eng_now(e) + time_per : 0u;
		rc = run_gen(e, &g, "random");
		if (rc == 0)
			rec(e, "phase", "name=random dir=%s done ops=%llu", dir_name(dirs[d]), LLU(e->nops - before));
	}
	return rc;
}

/* ---- the run ------------------------------------------------------------------------------------------------------ */

static int eng_setup(eng *e, const wrl_cmp_cfg *cfg)
{
	uint64_t dsz = 0, maxlen;
	int rc;

	e->c = *cfg;
	e->out = cfg->out != NULL ? cfg->out : stdout;
	e->r.seed = cfg->seed;
	e->t0 = eng_now(e);
	e->last_prog = e->last_report = e->t0;
	if (e->c.depth == 0u)
		e->c.depth = 8;
	if (e->c.depth > MAX_LANES)
		e->c.depth = MAX_LANES;
	e->depth = e->c.depth;
	e->stall_ms = cfg->stall_ms != 0u ? cfg->stall_ms : DEFAULT_STALL_MS;
	e->mem_max = cfg->mem_max != 0u ? cfg->mem_max : DEFAULT_MEM;
	e->ckpt = cfg->checkpoint != 0u ? cfg->checkpoint : DEFAULT_CHECKPOINT;
	if (cfg->client == NULL || cfg->loop == NULL || cfg->img == NULL || cfg->dev.pread == NULL || cfg->dev.pwrite == NULL || cfg->dev.size == NULL) {
		rec(e, "error", "wrl_cmp_run: the client, the loop, the image and the device calls are required");
		return 3;
	}
	e->sector = cfg->dev.sector != 0u ? cfg->dev.sector : 512u;
	if (e->sector < 512u || e->sector > 4096u || (e->sector & (e->sector - 1u)) != 0u) {
		rec(e, "error", "bad device sector size %u", (unsigned)e->sector);
		return 3;
	}
	if (wr_image_get_info(cfg->img, &e->info) != WR_OK || wr_image_get_state(cfg->img) != WR_IMG_OPEN) {
		rec(e, "error", "the image is not open");
		return 3;
	}
	if (!e->info.writable) {
		rec(e, "error", "the image was opened read-only: the comparison writes");
		return 3;
	}
	e->size = e->info.size_bytes;
	e->obj = e->info.object_size;
	rc = cfg->dev.size(cfg->dev.ctx, &dsz);
	if (rc != 0) {
		rec(e, "error", "cannot read the device capacity: %d", rc);
		return 3;
	}
	e->devsz = dsz;
	if (e->size == 0u || e->devsz != down(e->size, e->sector)) {
		rec(e, "error", "the device holds %llu bytes, the image %llu (a device of %u byte sectors shows %llu)", LLU(e->devsz), LLU(e->size),
		    (unsigned)e->sector, LLU(down(e->size, e->sector)));
		return 3;
	}
	e->gran = cfg->discard_gran != 0u ? cfg->discard_gran : e->sector;
	e->chunk = cfg->chunk != 0u ? cfg->chunk : (1u << 20);
	if (e->chunk > (256ull << 20))
		e->chunk = 256ull << 20; /* a scan buffer per lane: also keeps the device's 3/2 sized chunk from overflowing */
	e->dchunk = up(e->chunk + e->chunk / 2u, e->sector);
	if (e->dchunk == e->chunk)
		e->dchunk += e->sector;
	maxlen = cfg->max_len != 0u ? cfg->max_len : e->obj + e->obj / 2u;
	if (maxlen > (8ull << 20))
		maxlen = 8ull << 20;
	if (maxlen == 0u)
		maxlen = 1;
	e->c.max_len = maxlen;
	if (model_init(&e->m, e->size) != 0) {
		rec(e, "error", "cannot allocate the model");
		return 3;
	}
	e->nl = e->depth;
	e->lanes = (lane *)calloc(e->nl, sizeof(lane));
	e->sbuf = (uint8_t *)xalloc((size_t)e->dchunk);
	e->w = dw_start(&cfg->dev, e->nl * 2u + 4u);
	if (e->lanes == NULL || e->sbuf == NULL || e->w == NULL) {
		rec(e, "error", "cannot start the engine (memory or threads)");
		return 3;
	}
	return 0;
}

/* Frees what the run owns. Returns 0 when a device call or a core request may still be using memory of the engine (a hang): then nothing the
 * jobs point into is freed, and the caller must not free the engine itself, because the device scanner's job (sdj) lives inside it. */
static int eng_teardown(eng *e)
{
	unsigned i;
	int idle = 1;

	if (e->w != NULL)
		idle = dw_stop(e->w);
	for (i = 0; e->lanes != NULL && i < e->nl; i++) {
		lane *l = &e->lanes[i];

		if (l->core_busy || l->dj_busy[0] || l->dj_busy[1]) {
			keep(l->wbuf);
			keep(l->cbuf);
			keep(l->dbuf);
			keep(l->tcbuf);
			keep(l->tdbuf);
			keep(l->tmbuf);
			idle = 0;
		} else {
			lane_free_bufs(l);
		}
	}
	if (e->sdj_busy) {
		keep(e->sbuf);
		idle = 0;
	} else {
		free(e->sbuf);
	}
	if (idle) {
		free(e->lanes);
		model_free(&e->m);
	} else { /* a device call or a core request may still be using it */
		keep(e->lanes);
		keep((void *)e->m.c);
	}
	return idle;
}

int wrl_cmp_run(const wrl_cmp_cfg *cfg, wrl_cmp_result *res)
{
	eng *e = (eng *)calloc(1, sizeof(*e));
	unsigned dirs[3], nd, ph = cfg != NULL ? cfg->phases : 0u;
	int setup;
	wr_osd_stats os;

	if (e == NULL)
		return 3;
	if (cfg == NULL) {
		free(e);
		return 3;
	}
	setup = eng_setup(e, cfg);
	if (setup != 0) {
		int rc = setup;

		if (res != NULL)
			*res = e->r;
		if (eng_teardown(e)) /* a setup that stopped half way leaves the unused members NULL / zero, which the teardown handles */
			free(e);
		else
			keep(e); /* a worker thread may still be inside a job of it */
		if (res != NULL)
			res->exit_code = rc;
		return rc;
	}
	nd = dir_list(cfg->dirs != 0u ? cfg->dirs : WRL_CMP_DIR_ALL, dirs);
	if (ph == 0u)
		ph = WRL_CMP_PH_ALL;
	rec(e, "plan", "label=%s seed=%llu dirs=%u phases=%u depth=%u size=%llu order=%u object_size=%llu sector=%u device_bytes=%llu max_len=%llu chunk=%llu "
	    "device_chunk=%llu checkpoint=%llu stall_ms=%llu discard_gran=%llu mem_max=%llu%s",
	    cfg->label != NULL ? cfg->label : "-", LLU(cfg->seed), cfg->dirs != 0u ? cfg->dirs : WRL_CMP_DIR_ALL, ph, e->depth, LLU(e->size),
	    (unsigned)e->info.order, LLU(e->obj), (unsigned)e->sector, LLU(e->devsz), LLU(e->c.max_len), LLU(e->chunk), LLU(e->dchunk), LLU(e->ckpt),
	    LLU(e->stall_ms), LLU(e->gran), LLU(e->mem_max), cfg->mirror ? " self_test_mirror=1" : "");
	if (ph & WRL_CMP_PH_EDGES) {
		if (phase_edges(e, dirs, nd) == 0 && !e->stop) {
			(void)scan_run(e, "edges");
		}
	}
	if (!e->stop && (ph & WRL_CMP_PH_RANDOM)) {
		if (phase_random(e, dirs, nd) == 0 && !e->stop)
			(void)scan_run(e, "random");
	}
	if (!e->stop && (ph & WRL_CMP_PH_SCAN) && !(ph & (WRL_CMP_PH_EDGES | WRL_CMP_PH_RANDOM)))
		(void)scan_run(e, "scan");
	if (e->stop && !e->stalled)
		drain(e);
	pump_events(e);
	memset(&os, 0, sizeof(os));
	wr_client_osd_stats(cfg->client, &os);
	e->r.exit_code = e->rc;
	rec(e, "stats", "ops_done=%llu ops_resent=%llu ops_failed=%llu session_resets=%u ops_hiwater=%u reqs_hiwater=%u io_stalls=%u io_resumes=%u "
	    "max_gap_ms=%llu barrier_violations=%u bad_completions=%u model_chunks=%llu",
	    LLU(os.ops_done), LLU(os.ops_resent), LLU(os.ops_failed), os.n_session_resets, os.ops_hiwater, os.reqs_hiwater, e->r.n_stall, e->r.n_resume,
	    LLU(e->r.max_gap_ms), e->r.barrier_violations, e->r.bad_completions, LLU(e->m.used));
	rec(e, "result", "ok=%d exit=%d diffs=%llu transients=%llu errors=%llu verdict=%s ops=%llu reads=%llu writes=%llu discards=%llu zeroes=%llu flushes=%llu "
	    "refusals=%llu edges=%llu core_writes=%llu krbd_writes=%llu core_bytes_written=%llu krbd_bytes_written=%llu core_bytes_read=%llu krbd_bytes_read=%llu "
	    "checkpoints=%llu scans=%llu scan_core_bytes=%llu scan_krbd_bytes=%llu seed=%llu%s%s",
	    e->rc == 0 ? 1 : 0, e->rc, LLU(e->r.diffs), LLU(e->r.transients), LLU(e->r.errors), e->r.verdict[0] != '\0' ? e->r.verdict : "none", LLU(e->nops),
	    LLU(e->r.ops[WRL_CMP_K_READ]), LLU(e->r.ops[WRL_CMP_K_WRITE]), LLU(e->r.ops[WRL_CMP_K_DISCARD]), LLU(e->r.ops[WRL_CMP_K_ZEROES]),
	    LLU(e->r.ops[WRL_CMP_K_FLUSH]), LLU(e->r.refusals_ok), LLU(e->r.edges_run), LLU(e->r.writes_core), LLU(e->r.writes_dev),
	    LLU(e->r.bytes_written_core), LLU(e->r.bytes_written_dev), LLU(e->r.bytes_read_core), LLU(e->r.bytes_read_dev), LLU(e->r.checkpoints),
	    LLU(e->r.scans), LLU(e->r.scan_bytes_core), LLU(e->r.scan_bytes_dev), LLU(cfg->seed), cfg->label != NULL ? " label=" : "",
	    cfg->label != NULL ? cfg->label : "");
	if (res != NULL)
		*res = e->r;
	{
		int rc = e->rc;

		if (eng_teardown(e))
			free(e);
		else
			keep(e); /* a device call is still inside one of its jobs, and the job of the device scanner is part of the engine */
		return rc;
	}
}
