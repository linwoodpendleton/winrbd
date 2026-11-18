/* SPDX-License-Identifier: MIT */
/*
 * wr-rbd - open an RBD image with the winrbd core and do block I/O on it, on the Linux host. The first end-to-end client
 * of milestone 8 and the driver of the lab matrix (harness/lab/live-rbd.sh): every command prints machine readable
 * records, and the exit status says whether the image held what it should.
 *
 *   wr-rbd --mon <ip[:port]> --user <name> --keyring <file> --pool <pool> (--image <name> | --id <id>)
 *          [--data-pool <pool>] [--rw] [options] <command> [args]
 *
 * Commands (OFF and LEN are bytes; K, M, G, T suffixes and 0x are understood):
 *   info                          open the image and print what the header says
 *   read OFF LEN [FILE]           read a range; to FILE (a hole file of LEN bytes) or, without it, print a checksum
 *   write OFF LEN --pattern P     write a pattern;  write OFF (LEN | -) --file FILE writes the file (LEN - = all of it)
 *   fill [OFF LEN] [--pattern P]  write a pattern over a range, default the whole image with rand:1
 *   verify [OFF LEN] --pattern P  read a range back and compare it with a pattern; the first difference is reported
 *   discard OFF LEN               discard a range;  zeroes OFF LEN: write zeroes
 *   compare FILE                  compare the image with a file byte by byte (an `rbd export` of the stock tools)
 *   bench read|write [--total N] [--random]   throughput and latency of sequential or random I/O of --io-size
 *   random N SEED                 N random unaligned, cross-object operations against an in-memory model of the image
 *                                 (the first --model-bytes); every read is checked, the whole region is read back at the end
 *   shell                         read commands from stdin, one per line, on ONE open image, until quit or end of input;
 *                                 each command prints "done N rc=R" (this is how a script takes a snapshot between two writes)
 *   sleep MS, echo TEXT, quit     (shell only) wait while the engine keeps running, print a marker, leave
 *
 * Patterns (a function of the absolute byte offset, so a range can be checked anywhere): zero, byte:N, seq (offset mod
 * 256), offset (each aligned 8 byte word holds its own offset, little endian), rand:SEED.
 *
 * Options: --io-size N (default 128K), --depth N requests in flight (8), --timeout MS to open the image (30000),
 *   --io-timeout MS per request (0 = none), --run-timeout MS for one command (0 = none), --op-timeout MS the engine's
 *   unanswered-operation timeout, --hdr-refresh MS header re-read interval of a writer (0 = never), --ordersnap,
 *   --no-full-try, --fsid UUID, --stats-only (no event lines), -v, and for random: --model-bytes N (default 32M),
 *   --max-len N (default 1.5 objects, at most 8M), --delay-ms N between operations, --save FILE (the model at the end), --no-final-verify,
 *   --overlap (do not wait for overlapping requests in flight: the core must run them in submission order, design C14; the model is
 *   checked against what each read must see at its submission).
 *   Flags may stand before or after the command. A write needs --rw (the writer profile P1); without it the image opens read-only.
 *
 * Output (stdout, "@<ms since start> <kind> <key=value ...>"): event, image, result, stats, mismatch / error lines.
 * Diagnostics go to stderr. The key is read from the keyring file, handed to the core and wiped; it is never printed.
 *
 * Exit status: 0 success, 1 the image differs from what was expected (verify, compare, random), 2 usage or setup error,
 * 3 the image could not be opened or the client failed, 4 a request failed (no difference found) or the core broke its contract
 * (a FLUSH completed while an earlier write was unanswered, a request completed twice: "error" lines, counted in the stats line).
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "wrl_host.h"

#define KEYRING_MAX 4096u
#define LINE_MAX_BYTES 1024u
#define MAX_ARGS 24u
#define MAX_SLOTS 256u
#define DEFAULT_IO 131072u
#define DEFAULT_MODEL (32u << 20)
#define PRINT_LIMIT 8u /* mismatch / error lines printed per command */
#define SLOT_MEM_MAX (4ull << 30) /* request buffers of one command, all slots together */

/* ---- small helpers ------------------------------------------------------------------------------------------- */

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0)
		*v++ = 0;
}

static uint64_t now_us(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000u;
}

static uint64_t now_ms(void)
{
	return now_us() / 1000u;
}

static uint64_t mix64(uint64_t x)
{
	x += 0x9e3779b97f4a7c15ull;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
	return x ^ (x >> 31);
}

typedef struct rng {
	uint64_t s;
} rng;

static uint64_t rnd(rng *r)
{
	r->s += 0x9e3779b97f4a7c15ull;
	return mix64(r->s);
}

static uint64_t rnd_below(rng *r, uint64_t n)
{
	return n <= 1u ? 0u : rnd(r) % n;
}

/* A number: decimal, or hexadecimal with a 0x prefix (a leading 0 is NOT octal: "010" is ten), with an optional K / M / G / T
 * suffix (powers of 1024, an "iB" or "B" after it is ignored). No white space and no sign (strtoull would take " -1" as 2^64 - 1). */
static int parse_u64(const char *s, uint64_t *out)
{
	char *end = NULL;
	unsigned long long v;
	uint64_t mul = 1;
	int base = 10;

	if (s == NULL || *s < '0' || *s > '9')
		return -1;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		base = 16;
	errno = 0;
	v = strtoull(s, &end, base);
	if (errno != 0 || end == s)
		return -1;
	switch (*end) {
	case 'k': case 'K': mul = 1ull << 10; end++; break;
	case 'm': case 'M': mul = 1ull << 20; end++; break;
	case 'g': case 'G': mul = 1ull << 30; end++; break;
	case 't': case 'T': mul = 1ull << 40; end++; break;
	default: break;
	}
	if (mul != 1u && (*end == 'i' || *end == 'I'))
		end++;
	if (*end == 'b' || *end == 'B')
		end++;
	if (*end != '\0' || (mul != 1u && v > UINT64_MAX / mul))
		return -1;
	*out = (uint64_t)v * mul;
	return 0;
}

static int fsid_parse(const char *s, uint8_t *out)
{
	unsigned i, n = 0;

	for (i = 0; s[i] != '\0'; i++) {
		int v;
		char ch = s[i];

		if (ch == '-')
			continue;
		if (ch >= '0' && ch <= '9')
			v = ch - '0';
		else if (ch >= 'a' && ch <= 'f')
			v = ch - 'a' + 10;
		else if (ch >= 'A' && ch <= 'F')
			v = ch - 'A' + 10;
		else
			return -1;
		if (n >= 32u)
			return -1;
		if ((n & 1u) == 0)
			out[n / 2u] = (uint8_t)(v << 4);
		else
			out[n / 2u] = (uint8_t)(out[n / 2u] | v);
		n++;
	}
	return n == 32u ? 0 : -1;
}

/* ---- patterns ---------------------------------------------------------------------------------------------- */

enum { P_ZERO = 0, P_BYTE, P_SEQ, P_OFFSET, P_RAND };

typedef struct pat {
	int kind;
	uint64_t arg;
} pat;

static int pat_parse(const char *s, pat *p)
{
	uint64_t v = 0;

	memset(p, 0, sizeof(*p));
	if (s == NULL)
		return -1;
	if (strcmp(s, "zero") == 0) {
		p->kind = P_ZERO;
	} else if (strcmp(s, "seq") == 0) {
		p->kind = P_SEQ;
	} else if (strcmp(s, "offset") == 0) {
		p->kind = P_OFFSET;
	} else if (strncmp(s, "byte:", 5) == 0 && parse_u64(s + 5, &v) == 0 && v <= 255u) {
		p->kind = P_BYTE;
		p->arg = v;
	} else if (strncmp(s, "rand:", 5) == 0 && parse_u64(s + 5, &v) == 0) {
		p->kind = P_RAND;
		p->arg = v;
	} else {
		return -1;
	}
	return 0;
}

static uint8_t pat_at(const pat *p, uint64_t x)
{
	switch (p->kind) {
	case P_BYTE:
		return (uint8_t)p->arg;
	case P_SEQ:
		return (uint8_t)x;
	case P_OFFSET:
		return (uint8_t)((x & ~7ull) >> (8u * (unsigned)(x & 7u)));
	case P_RAND:
		return (uint8_t)(mix64(p->arg * 0x2545f4914f6cdd1dull + (x >> 3)) >> (8u * (unsigned)(x & 7u)));
	case P_ZERO:
	default:
		return 0;
	}
}

/* buf[i] = pattern at absolute offset off + i. */
static void pat_fill(const pat *p, uint8_t *buf, uint64_t off, size_t n)
{
	size_t i;

	if (p->kind == P_ZERO) {
		memset(buf, 0, n);
		return;
	}
	if (p->kind == P_BYTE) {
		memset(buf, (int)p->arg, n);
		return;
	}
	for (i = 0; i < n; i++)
		buf[i] = pat_at(p, off + i);
}

/* ---- the tool ---------------------------------------------------------------------------------------------- */

typedef struct opts {
	const char *mon, *user, *keyring, *pool, *image, *id, *data_pool, *fsid;
	int rw, ordersnap, no_full_try, stats_only, verbose;
	uint64_t io_size, depth, open_timeout_ms, io_timeout_ms, run_timeout_ms, op_timeout_ms, hdr_refresh_ms;
	int have_op_timeout, have_hdr_refresh;
	/* per command */
	const char *pattern, *file, *save;
	uint64_t total, model_bytes, max_len, delay_ms;
	int random_io, no_final_verify, overlap;
} opts;

typedef struct slot {
	wr_io_req req;
	uint8_t *buf, *ref;
	int busy;
	wr_io_kind kind;
	uint64_t off, len, opno, t_us;
	uint64_t seq; /* submit order over the whole run (the flush barrier check) */
	wr_status st;
} slot;

struct job;

typedef struct tool {
	opts o;
	wr_client *c;
	wrl_loop *loop;
	wr_image *img;
	wr_image_info info;
	wr_mem_region arena, bulk;
	uint64_t t0_ms;
	slot *slots;
	unsigned nslots;
	size_t cap;
	unsigned inflight;
	int just_submitted;
	wr_status fatal;           /* the client failed: nothing more can be done */
	wr_status submit_err;      /* the last refused submit */
	unsigned n_stall, n_resume, n_map, n_resync;
	uint64_t n_events;
	uint64_t submit_seq;
	unsigned barrier_viol; /* a FLUSH completed while an earlier write was still unanswered */
	unsigned bad_done;     /* a completion that was not one of the busy requests (twice, or a stranger) */
	struct job *job;
	/* shell input */
	char inbuf[LINE_MAX_BYTES * 2u];
	size_t inlen;
	int in_eof, in_skip;
} tool;

typedef struct job {
	int (*issue)(tool *t, struct job *j); /* submit what can go now; 1 = nothing left to issue (in flight ones may remain) */
	void (*complete)(tool *t, struct job *j, slot *s);
} job;

static const char *ev_name(wr_ev_kind k)
{
	switch (k) {
	case WR_EV_MON_SESSION_UP: return "MON_SESSION_UP";
	case WR_EV_MON_SESSION_DOWN: return "MON_SESSION_DOWN";
	case WR_EV_AUTH_FAILED: return "AUTH_FAILED";
	case WR_EV_CLUSTER_UNREACHABLE: return "CLUSTER_UNREACHABLE";
	case WR_EV_MAPMSG: return "MAPMSG";
	case WR_EV_TICKETS_RENEWED: return "TICKETS_RENEWED";
	case WR_EV_FATAL: return "FATAL";
	case WR_EV_MAP: return "MAP";
	case WR_EV_MAP_RESYNC: return "MAP_RESYNC";
	case WR_EV_IMAGE: return "IMAGE";
	case WR_EV_IO_STALL: return "IO_STALL";
	case WR_EV_IO_RESUME: return "IO_RESUME";
	case WR_EV_NONE:
	default: return "NONE";
	}
}

static const char *img_state_name(wr_image_state s)
{
	switch (s) {
	case WR_IMG_OPENING: return "OPENING";
	case WR_IMG_OPEN: return "OPEN";
	case WR_IMG_FAILED: return "FAILED";
	case WR_IMG_CLOSING: return "CLOSING";
	case WR_IMG_FREE:
	default: return "FREE";
	}
}

static uint64_t since(const tool *t)
{
	return now_ms() - t->t0_ms;
}

static void print_event(tool *t, const wr_event *e)
{
	t->n_events++;
	if (e->kind == WR_EV_IO_STALL)
		t->n_stall++;
	else if (e->kind == WR_EV_IO_RESUME)
		t->n_resume++;
	else if (e->kind == WR_EV_MAP)
		t->n_map++;
	else if (e->kind == WR_EV_MAP_RESYNC)
		t->n_resync++;
	if (t->o.stats_only)
		return;
	printf("@%llu event %s", (unsigned long long)since(t), ev_name(e->kind));
	if (e->kind == WR_EV_MAP)
		printf(" epoch=%u", (unsigned)e->epoch);
	if (e->kind == WR_EV_IMAGE) {
		const wr_image *im = wr_client_image_at(t->c, e->epoch);

		printf(" slot=%u state=%s", (unsigned)e->epoch, im != NULL ? img_state_name(wr_image_get_state(im)) : "FREE");
	}
	if (e->err.status != WR_OK)
		printf(" status=%s peer_result=%d what=\"%s\"", wr_status_name(e->err.status), (int)e->err.peer_result,
		       e->err.what != NULL ? e->err.what : "");
	printf("\n");
	fflush(stdout);
}

static void pump_events(tool *t)
{
	wr_event e;
	wr_mapmsg m;

	while (wr_client_next_event(t->c, &e))
		print_event(t, &e);
	while (wr_client_mapmsg_peek(t->c, &m)) /* only when the engine does not consume the maps itself */
		wr_client_mapmsg_release(t->c);
}

/* Is r the request of one of the busy slots? (r->user came from the core: it is only trusted after this check.) */
static int slot_owns(const tool *t, const slot *s, const wr_io_req *r)
{
	return t->slots != NULL && s >= t->slots && s < t->slots + t->nslots && s->busy && r == &s->req;
}

/* "FLUSH completes when every write accepted before it has completed" (design C14): when a flush comes back, no write submitted
 * before it may still be unanswered. Writes complete (and are marked) earlier in the same done queue, so a slot still busy
 * with an older sequence number is a barrier violation. */
static void flush_barrier_check(tool *t, const slot *f)
{
	unsigned i;

	for (i = 0; i < t->nslots; i++) {
		const slot *w = &t->slots[i];

		if (!w->busy || w->seq >= f->seq)
			continue;
		if (w->kind != WR_IO_WRITE && w->kind != WR_IO_DISCARD && w->kind != WR_IO_WRITE_ZEROES)
			continue;
		if (t->barrier_viol++ < PRINT_LIMIT)
			printf("@%llu error flush completed before an earlier write: kind=%d off=%llu len=%llu\n", (unsigned long long)since(t),
			       (int)w->kind, (unsigned long long)w->off, (unsigned long long)w->len);
		return;
	}
}

/* One turn of the host loop and the bookkeeping after it: events, finished requests. */
static void tool_step(tool *t, int wait_ms)
{
	wr_status st = wrl_loop_step(t->loop, wait_ms);
	wr_io_req *r;

	pump_events(t);
	if (st != WR_OK && t->fatal == WR_OK)
		t->fatal = st;
	while ((r = wr_client_next_done(t->c)) != NULL) {
		slot *s = (slot *)r->user;

		/* The core hands every request back exactly once. A completion that is not the request of a busy slot is the core's
		 * bug (a request completed twice, or one the tool never made): count it, do not touch the books, never use the slot. */
		if (!slot_owns(t, s, r)) {
			if (t->bad_done++ < PRINT_LIMIT)
				printf("@%llu error completion of a request that is not in flight (twice?) status=%s\n", (unsigned long long)since(t),
				       wr_status_name(r->status));
			continue;
		}
		s->busy = 0;
		s->st = r->status;
		if (t->inflight > 0)
			t->inflight--;
		if (s->kind == WR_IO_FLUSH && s->st == WR_OK)
			flush_barrier_check(t, s);
		if (t->job != NULL && t->job->complete != NULL)
			t->job->complete(t, t->job, s);
	}
	t->just_submitted = 0;
}

/* Run the engine for ms milliseconds (a sleep that keeps the sessions alive). */
static void tool_pump_for(tool *t, uint64_t ms)
{
	uint64_t end = now_ms() + ms;

	while (t->fatal == WR_OK && now_ms() < end) {
		uint64_t left = end - now_ms();

		tool_step(t, left > 20u ? 20 : (int)left);
	}
}

static void slots_free(tool *t)
{
	unsigned i;

	for (i = 0; i < t->nslots; i++) {
		free(t->slots[i].buf);
		free(t->slots[i].ref);
	}
	free(t->slots);
	t->slots = NULL;
	t->nslots = 0;
}

static int slots_alloc(tool *t, unsigned n, size_t cap, int with_ref)
{
	unsigned i;

	slots_free(t);
	if (n == 0u || n > MAX_SLOTS || (uint64_t)n * (uint64_t)cap * (with_ref ? 2u : 1u) > SLOT_MEM_MAX)
		return -1;
	t->slots = (slot *)calloc(n, sizeof(slot));
	if (t->slots == NULL)
		return -1;
	t->nslots = n;
	t->cap = cap;
	for (i = 0; i < n; i++) {
		t->slots[i].buf = (uint8_t *)malloc(cap != 0u ? cap : 1u);
		if (t->slots[i].buf == NULL)
			return -1;
		if (with_ref) {
			t->slots[i].ref = (uint8_t *)malloc(cap != 0u ? cap : 1u);
			if (t->slots[i].ref == NULL)
				return -1;
		}
	}
	return 0;
}

static slot *slot_get(tool *t)
{
	unsigned i;

	for (i = 0; i < t->nslots; i++)
		if (!t->slots[i].busy)
			return &t->slots[i];
	return NULL;
}

/* 1 queued, 0 the table is full (retry after a completion), -1 refused (t->submit_err). */
static int tool_submit(tool *t, slot *s, wr_io_kind kind, uint64_t off, uint64_t len)
{
	wr_status st;

	memset(&s->req, 0, sizeof(s->req));
	s->req.kind = kind;
	s->req.timeout_ms = (uint32_t)t->o.io_timeout_ms;
	s->req.offset = off;
	s->req.length = len;
	s->req.buf = (kind == WR_IO_READ || kind == WR_IO_WRITE) ? s->buf : NULL;
	s->req.user = s;
	s->kind = kind;
	s->off = off;
	s->len = len;
	s->st = WR_OK;
	s->t_us = now_us();
	s->seq = ++t->submit_seq;
	st = wr_image_submit(t->img, &s->req);
	if (st == WR_E_BUSY)
		return 0;
	if (st != WR_OK) {
		t->submit_err = st;
		return -1;
	}
	s->busy = 1;
	t->inflight++;
	t->just_submitted = 1;
	return 1;
}

/* Drive a job until it has issued everything and every request came back. 0 ok, -1 the client failed or timed out. */
static int tool_run(tool *t, job *j)
{
	uint64_t t_end = t->o.run_timeout_ms != 0u ? now_ms() + t->o.run_timeout_ms : 0;
	int rc = 0;

	t->job = j;
	for (;;) {
		int fin = j->issue(t, j);

		if (fin && t->inflight == 0u)
			break;
		if (t->fatal != WR_OK || wr_image_get_state(t->img) == WR_IMG_FAILED || wr_image_get_state(t->img) == WR_IMG_FREE) {
			rc = -1;
			break;
		}
		if (t_end != 0u && now_ms() >= t_end) {
			fprintf(stderr, "wr-rbd: command timed out (--run-timeout)\n");
			rc = -1;
			break;
		}
		tool_step(t, t->just_submitted ? 0 : 20);
	}
	t->job = NULL;
	if (rc != 0 && t->inflight != 0u && t->fatal == WR_OK)
		t->fatal = WR_E_TIMEOUT; /* requests still own the buffers: nothing may reuse them, so the tool stops after this command */
	return rc;
}

/* ---- opening ------------------------------------------------------------------------------------------------- */

static int tool_create(tool *t, const wr_cluster_spec *spec, unsigned *level)
{
	wr_config cfg;
	wr_host_ops ops;
	wr_mem_req req;
	wr_status st;

	wr_config_profile_harness(&cfg);
	wr_config_enable_maps(&cfg, WR_MAPS_HARNESS);
	wr_config_enable_osd(&cfg, WR_MAPS_HARNESS);
	cfg.mon_msg_cap = 8u * 1024u * 1024u;
	cfg.max_images = 1;
	if (t->o.have_op_timeout)
		cfg.op_timeout_ms = (uint32_t)t->o.op_timeout_ms;
	if (t->o.have_hdr_refresh)
		cfg.hdr_refresh_ms = (uint32_t)t->o.hdr_refresh_ms;
	if (t->o.ordersnap)
		cfg.osd_flags = (uint8_t)(cfg.osd_flags | WR_OSDF_ORDERSNAP);
	if (t->o.no_full_try)
		cfg.osd_flags = (uint8_t)(cfg.osd_flags & ~WR_OSDF_FULL_TRY);
	wrl_host_ops_init(&ops, level);
	st = wr_client_mem_required(&cfg, &req);
	if (st == WR_OK)
		st = wrl_mem_alloc(&t->arena, req.arena);
	if (st == WR_OK) {
		st = wrl_mem_alloc(&t->bulk, req.bulk);
		if (st != WR_OK)
			wrl_mem_free(&t->arena);
	}
	if (st == WR_OK) {
		st = wr_client_create(&cfg, &ops, spec, t->arena, t->bulk, &t->c);
		if (st != WR_OK) {
			wrl_mem_free(&t->arena);
			wrl_mem_free(&t->bulk);
		}
	}
	if (st != WR_OK) {
		fprintf(stderr, "wr-rbd: cannot create the client: %s\n", wr_strerror(st));
		return -1;
	}
	st = wrl_loop_create(t->c, &t->loop);
	if (st != WR_OK) {
		fprintf(stderr, "wr-rbd: cannot create the loop: %s\n", wr_strerror(st));
		wr_client_destroy(t->c);
		wrl_mem_free(&t->arena);
		wrl_mem_free(&t->bulk);
		t->c = NULL;
		return -1;
	}
	return 0;
}

static void print_image(tool *t)
{
	const wr_image_info *i = &t->info;

	printf("@%llu image id=%s prefix=%s size=%llu features=0x%llx flags=0x%llx order=%u object_size=%u pool_id=%lld data_pool_id=%lld "
	       "writable=%u n_snaps=%u snap_seq=%llu max_io=%u\n",
	       (unsigned long long)since(t), i->image_id, i->object_prefix, (unsigned long long)i->size_bytes, (unsigned long long)i->features,
	       (unsigned long long)i->flags, (unsigned)i->order, (unsigned)i->object_size, (long long)i->pool_id, (long long)i->data_pool_id,
	       (unsigned)i->writable, (unsigned)i->n_snaps, (unsigned long long)i->snap_seq, (unsigned)i->max_io_bytes);
	fflush(stdout);
}

/* 0 open, -1 failed (reported). */
static int tool_open_image(tool *t)
{
	wr_image_params p;
	wr_status st;
	uint64_t limit = now_ms() + t->o.open_timeout_ms + 10000u;

	memset(&p, 0, sizeof(p));
	p.size = (uint32_t)sizeof(p);
	p.pool = t->o.pool;
	p.name = t->o.id != NULL ? NULL : t->o.image;
	p.id = t->o.id;
	p.data_pool = t->o.data_pool;
	p.snap_id = WR_SNAP_HEAD;
	p.open_timeout_ms = (uint32_t)t->o.open_timeout_ms;
	p.want_write = (uint8_t)(t->o.rw ? 1 : 0);
	st = wr_image_open(t->c, &p, &t->img);
	if (st != WR_OK) {
		printf("@%llu result open ok=0 status=%s (%s)\n", (unsigned long long)since(t), wr_status_name(st), wr_strerror(st));
		return -1;
	}
	while (t->fatal == WR_OK && wr_image_get_state(t->img) == WR_IMG_OPENING && now_ms() < limit)
		tool_step(t, 20);
	if (wr_image_get_state(t->img) != WR_IMG_OPEN) {
		const wr_errinfo *e = wr_image_error(t->img);
		wr_status why = t->fatal != WR_OK ? t->fatal : e->status;

		printf("@%llu result open ok=0 state=%s status=%s peer_result=%d what=\"%s\" (%s)\n", (unsigned long long)since(t),
		       img_state_name(wr_image_get_state(t->img)), wr_status_name(why), (int)e->peer_result, e->what != NULL ? e->what : "",
		       wr_strerror(why));
		return -1;
	}
	if (wr_image_get_info(t->img, &t->info) != WR_OK) {
		printf("@%llu result open ok=0 status=get_info\n", (unsigned long long)since(t));
		return -1;
	}
	return 0;
}

/* ---- request checks ---------------------------------------------------------------------------------------- */

static unsigned g_err_printed;

static void report_error(const tool *t, const slot *s, const char *what)
{
	if (g_err_printed++ < PRINT_LIMIT)
		printf("@%llu error %s kind=%d off=%llu len=%llu status=%s (%s)\n", (unsigned long long)since(t), what, (int)s->kind,
		       (unsigned long long)s->off, (unsigned long long)s->len, wr_status_name(s->st), wr_strerror(s->st));
}

static void report_submit_error(const tool *t, const char *what)
{
	printf("@%llu error %s status=%s (%s)\n", (unsigned long long)since(t), what, wr_status_name(t->submit_err), wr_strerror(t->submit_err));
}

static uint64_t fnv64(const uint8_t *p, size_t n, uint64_t h)
{
	size_t i;

	for (i = 0; i < n; i++)
		h = (h ^ p[i]) * 0x100000001b3ull;
	return h;
}

/* ---- range jobs: read / write / verify / compare / discard over [off, end) in chunks -------------------------------- */

enum { RJ_SUM = 0, RJ_OUT, RJ_VERIFY, RJ_COMPARE, RJ_MODEL_CHECK, RJ_MODEL_LOAD, RJ_W_PAT, RJ_W_FILE, RJ_NONE };

typedef struct rangejob {
	job j;
	int mode;
	wr_io_kind kind;
	uint64_t off, end, next, chunk;
	pat p;
	FILE *f;
	uint8_t *model; /* RJ_MODEL_* : model[x - model_base] is the byte at image offset x */
	uint64_t model_base;
	int flush_state; /* writes end with one FLUSH: 0 not yet, 1 sent */
	int want_flush;
	/* results */
	uint64_t bytes, ops, errors, diffs, first_diff, nonzero, sum;
	int have_diff;
	uint8_t first_got, first_want;
	int hard_fail;
} rangejob;

static void rj_note_diff(rangejob *r, uint64_t at, uint8_t got, uint8_t want)
{
	if (!r->have_diff || at < r->first_diff) { /* requests complete out of order: keep the lowest offset */
		r->have_diff = 1;
		r->first_diff = at;
		r->first_got = got;
		r->first_want = want;
	}
}

/* Compare s->buf with the expected bytes; counts every differing byte. */
static void rj_check(rangejob *r, const slot *s, const uint8_t *want_buf)
{
	uint64_t i;

	for (i = 0; i < s->len; i++) {
		uint8_t want = want_buf != NULL ? want_buf[i] : pat_at(&r->p, s->off + i);

		if (s->buf[i] != want) {
			r->diffs++;
			rj_note_diff(r, s->off + i, s->buf[i], want);
		}
	}
}

static void rj_complete(tool *t, job *j, slot *s)
{
	rangejob *r = (rangejob *)(void *)j;
	uint64_t i;

	if (s->kind == WR_IO_FLUSH) {
		if (s->st != WR_OK) {
			r->errors++;
			report_error(t, s, "flush");
		}
		return;
	}
	r->ops++;
	if (s->st != WR_OK) {
		r->errors++;
		report_error(t, s, "request");
		return;
	}
	r->bytes += s->len;
	if (s->kind != WR_IO_READ)
		return;
	switch (r->mode) {
	case RJ_SUM:
		for (i = 0; i < s->len; i++)
			r->nonzero += s->buf[i] != 0;
		r->sum ^= fnv64(s->buf, (size_t)s->len, 0xcbf29ce484222325ull ^ mix64(s->off));
		break;
	case RJ_OUT:
		if (fseeko(r->f, (off_t)(s->off - r->off), SEEK_SET) != 0 || fwrite(s->buf, 1, (size_t)s->len, r->f) != (size_t)s->len) {
			r->hard_fail = 1;
			fprintf(stderr, "wr-rbd: cannot write the output file\n");
		}
		break;
	case RJ_VERIFY:
		rj_check(r, s, NULL);
		break;
	case RJ_COMPARE:
		rj_check(r, s, s->ref);
		break;
	case RJ_MODEL_CHECK:
		rj_check(r, s, r->model + (s->off - r->model_base));
		break;
	case RJ_MODEL_LOAD:
		memcpy(r->model + (s->off - r->model_base), s->buf, (size_t)s->len);
		break;
	default:
		break;
	}
}

static int rj_issue(tool *t, job *j)
{
	rangejob *r = (rangejob *)(void *)j;

	while (r->next < r->end) {
		slot *s = slot_get(t);
		uint64_t len = r->end - r->next;
		int rc;

		if (s == NULL)
			return 0;
		if (len > r->chunk)
			len = r->chunk;
		if (r->mode == RJ_W_PAT) {
			pat_fill(&r->p, s->buf, r->next, (size_t)len);
		} else if (r->mode == RJ_W_FILE || r->mode == RJ_COMPARE) {
			uint8_t *dst = r->mode == RJ_W_FILE ? s->buf : s->ref;

			if (fread(dst, 1, (size_t)len, r->f) != (size_t)len) {
				fprintf(stderr, "wr-rbd: short read of the input file\n");
				r->hard_fail = 1;
				r->next = r->end;
				return 0;
			}
		}
		rc = tool_submit(t, s, r->kind, r->next, len);
		if (rc == 0) {
			/* the request table is full: this chunk is read again next time, so the input file must not have moved on */
			if ((r->mode == RJ_W_FILE || r->mode == RJ_COMPARE) && fseeko(r->f, -(off_t)len, SEEK_CUR) != 0) {
				fprintf(stderr, "wr-rbd: cannot rewind the input file\n");
				r->hard_fail = 1;
				r->next = r->end;
			}
			return 0;
		}
		if (rc < 0) {
			report_submit_error(t, "submit");
			r->errors++;
			r->hard_fail = 1;
			r->next = r->end;
			return 0;
		}
		r->next += len;
	}
	if (r->want_flush && !r->flush_state && !r->hard_fail) {
		slot *s = slot_get(t);
		int rc;

		if (s == NULL)
			return 0;
		rc = tool_submit(t, s, WR_IO_FLUSH, 0, 0);
		if (rc == 0)
			return 0;
		if (rc < 0) { /* refused: never retried for ever */
			report_submit_error(t, "flush submit");
			r->errors++;
			r->hard_fail = 1;
		}
		r->flush_state = 1;
		return 0;
	}
	return 1;
}

static void rj_init(rangejob *r, int mode, wr_io_kind kind, uint64_t off, uint64_t len, uint64_t chunk)
{
	memset(r, 0, sizeof(*r));
	r->j.issue = rj_issue;
	r->j.complete = rj_complete;
	r->mode = mode;
	r->kind = kind;
	r->off = off;
	r->next = off;
	r->end = off + len;
	r->chunk = chunk;
	r->want_flush = kind == WR_IO_WRITE || kind == WR_IO_DISCARD || kind == WR_IO_WRITE_ZEROES;
}

/* 0 = job ran, -1 = the client failed under it. */
static int rj_run(tool *t, rangejob *r, int with_ref)
{
	uint64_t chunk = r->chunk;
	unsigned depth = (unsigned)t->o.depth;
	uint64_t total = r->end - r->off;
	uint64_t n_chunks = chunk != 0u ? (total + chunk - 1u) / chunk : 1u;

	if (n_chunks < depth)
		depth = (unsigned)(n_chunks != 0u ? n_chunks : 1u);
	g_err_printed = 0;
	if (slots_alloc(t, depth + 1u, (r->kind == WR_IO_READ || r->kind == WR_IO_WRITE) ? (size_t)chunk : 1u, with_ref) != 0) {
		fprintf(stderr, "wr-rbd: out of memory for the request buffers\n");
		return -1;
	}
	return tool_run(t, &r->j);
}

/* the chunk size of a request: --io-size, but never above what the image accepts */
static uint64_t chunk_size(const tool *t)
{
	uint64_t c = t->o.io_size;

	if (c > t->info.max_io_bytes)
		c = t->info.max_io_bytes;
	return c != 0u ? c : DEFAULT_IO;
}

static int finish_rc(const rangejob *r, int run_rc)
{
	if (run_rc != 0 || r->hard_fail)
		return 3;
	if (r->diffs != 0u)
		return 1;
	return r->errors != 0u ? 4 : 0;
}

/* ---- commands ------------------------------------------------------------------------------------------------ */

static int need_rw(const tool *t, const char *cmd)
{
	if (t->info.writable)
		return 0;
	printf("@%llu result %s ok=0 status=need --rw\n", (unsigned long long)since(t), cmd);
	return 2;
}

static int check_range(const tool *t, const char *cmd, uint64_t off, uint64_t len)
{
	if (off <= t->info.size_bytes && len <= t->info.size_bytes - off)
		return 0;
	printf("@%llu result %s ok=0 status=range off=%llu len=%llu size=%llu\n", (unsigned long long)since(t), cmd, (unsigned long long)off,
	       (unsigned long long)len, (unsigned long long)t->info.size_bytes);
	return 2;
}

static int cmd_info(tool *t)
{
	printf("@%llu result info ok=1 state=%s\n", (unsigned long long)since(t), img_state_name(wr_image_get_state(t->img)));
	return 0;
}

static void print_diff_line(const tool *t, const char *cmd, const rangejob *r, uint64_t off, uint64_t len)
{
	printf("@%llu result %s ok=%d off=%llu len=%llu bytes=%llu diffs=%llu errors=%llu", (unsigned long long)since(t), cmd,
	       (r->diffs == 0u && r->errors == 0u && !r->hard_fail) ? 1 : 0, (unsigned long long)off, (unsigned long long)len,
	       (unsigned long long)r->bytes, (unsigned long long)r->diffs, (unsigned long long)r->errors);
	if (r->have_diff)
		printf(" first_diff=%llu got=0x%02x want=0x%02x", (unsigned long long)r->first_diff, (unsigned)r->first_got, (unsigned)r->first_want);
	printf("\n");
	fflush(stdout);
}

static int cmd_read(tool *t, int npos, char **pos)
{
	rangejob r;
	uint64_t off, len;
	int rc, st;
	FILE *f = NULL;

	if (npos < 2 || npos > 3 || parse_u64(pos[0], &off) != 0 || parse_u64(pos[1], &len) != 0) {
		fprintf(stderr, "wr-rbd: usage: read OFF LEN [FILE]\n");
		return 2;
	}
	if ((rc = check_range(t, "read", off, len)) != 0)
		return rc;
	rj_init(&r, npos == 3 ? RJ_OUT : RJ_SUM, WR_IO_READ, off, len, chunk_size(t));
	if (npos == 3) {
		f = fopen(pos[2], "wb");
		if (f == NULL || (len != 0u && fseeko(f, (off_t)(len - 1u), SEEK_SET) != 0) || (len != 0u && fputc(0, f) == EOF)) {
			fprintf(stderr, "wr-rbd: cannot create %s\n", pos[2]);
			if (f != NULL)
				fclose(f);
			return 2;
		}
		r.f = f;
	}
	st = rj_run(t, &r, 0);
	if (f != NULL && fclose(f) != 0)
		r.hard_fail = 1;
	print_diff_line(t, "read", &r, off, len);
	if (npos == 2 && r.errors == 0u && !r.hard_fail && st == 0) /* a checksum of a failed read would look like a result */
		printf("@%llu read-sum chunk=%llu sum=%016llx nonzero=%llu\n", (unsigned long long)since(t), (unsigned long long)chunk_size(t),
		       (unsigned long long)r.sum, (unsigned long long)r.nonzero);
	fflush(stdout);
	return finish_rc(&r, st);
}

static int cmd_write(tool *t, int npos, char **pos, int is_fill)
{
	rangejob r;
	uint64_t off = 0, len = t->info.size_bytes;
	int rc, st;
	FILE *f = NULL;
	pat p = {0, 0};
	int from_file = t->o.file != NULL;

	if (!is_fill && npos != 2) {
		fprintf(stderr, "wr-rbd: usage: write OFF LEN (--pattern P | --file FILE)\n");
		return 2;
	}
	if (is_fill && npos != 0 && npos != 2) {
		fprintf(stderr, "wr-rbd: usage: fill [OFF LEN] [--pattern P]\n");
		return 2;
	}
	if (npos == 2 && parse_u64(pos[0], &off) != 0) {
		fprintf(stderr, "wr-rbd: bad OFF\n");
		return 2;
	}
	if (npos == 2 && strcmp(pos[1], "-") == 0 && from_file) {
		off_t fl = -1;

		f = fopen(t->o.file, "rb");
		if (f != NULL && fseeko(f, 0, SEEK_END) == 0)
			fl = ftello(f);
		if (f != NULL)
			fclose(f);
		f = NULL;
		if (fl < 0) {
			fprintf(stderr, "wr-rbd: cannot read %s (a regular file is needed to write all of it)\n", t->o.file);
			return 2;
		}
		len = (uint64_t)fl;
	} else if (npos == 2 && parse_u64(pos[1], &len) != 0) {
		fprintf(stderr, "wr-rbd: bad LEN\n");
		return 2;
	}
	if (is_fill && npos == 0)
		off = 0;
	if (!from_file && pat_parse(t->o.pattern != NULL ? t->o.pattern : (is_fill ? "rand:1" : NULL), &p) != 0) {
		fprintf(stderr, "wr-rbd: a valid --pattern (zero, byte:N, seq, offset, rand:SEED) or --file is required\n");
		return 2;
	}
	if ((rc = need_rw(t, is_fill ? "fill" : "write")) != 0 || (rc = check_range(t, is_fill ? "fill" : "write", off, len)) != 0)
		return rc;
	rj_init(&r, from_file ? RJ_W_FILE : RJ_W_PAT, WR_IO_WRITE, off, len, chunk_size(t));
	if (!from_file)
		r.p = p;
	else {
		f = fopen(t->o.file, "rb");
		if (f == NULL) {
			fprintf(stderr, "wr-rbd: cannot read %s\n", t->o.file);
			return 2;
		}
		r.f = f;
	}
	st = rj_run(t, &r, 0);
	if (f != NULL)
		fclose(f);
	print_diff_line(t, is_fill ? "fill" : "write", &r, off, len);
	return finish_rc(&r, st);
}

static int cmd_verify(tool *t, int npos, char **pos)
{
	rangejob r;
	uint64_t off = 0, len = t->info.size_bytes;
	pat p;
	int rc, st;

	if (npos != 0 && (npos != 2 || parse_u64(pos[0], &off) != 0 || parse_u64(pos[1], &len) != 0)) {
		fprintf(stderr, "wr-rbd: usage: verify [OFF LEN] --pattern P\n");
		return 2;
	}
	if (pat_parse(t->o.pattern, &p) != 0) {
		fprintf(stderr, "wr-rbd: a valid --pattern is required\n");
		return 2;
	}
	if ((rc = check_range(t, "verify", off, len)) != 0)
		return rc;
	rj_init(&r, RJ_VERIFY, WR_IO_READ, off, len, chunk_size(t));
	r.p = p;
	st = rj_run(t, &r, 0);
	print_diff_line(t, "verify", &r, off, len);
	return finish_rc(&r, st);
}

static int cmd_discard(tool *t, int npos, char **pos, wr_io_kind kind, const char *name)
{
	rangejob r;
	uint64_t off, len;
	int rc, st;

	if (npos != 2 || parse_u64(pos[0], &off) != 0 || parse_u64(pos[1], &len) != 0) {
		fprintf(stderr, "wr-rbd: usage: %s OFF LEN\n", name);
		return 2;
	}
	if ((rc = need_rw(t, name)) != 0 || (rc = check_range(t, name, off, len)) != 0)
		return rc;
	rj_init(&r, RJ_NONE, kind, off, len, 64u << 20);
	st = rj_run(t, &r, 0);
	print_diff_line(t, name, &r, off, len);
	return finish_rc(&r, st);
}

static int cmd_compare(tool *t, int npos, char **pos)
{
	rangejob r;
	FILE *f;
	uint64_t fsize, len;
	off_t fl = -1;
	int st;

	if (npos != 1) {
		fprintf(stderr, "wr-rbd: usage: compare FILE\n");
		return 2;
	}
	f = fopen(pos[0], "rb");
	if (f == NULL || fseeko(f, 0, SEEK_END) != 0 || (fl = ftello(f)) < 0) {
		fprintf(stderr, "wr-rbd: cannot read %s (a regular file is needed)\n", pos[0]);
		if (f != NULL)
			fclose(f);
		return 2;
	}
	fsize = (uint64_t)fl;
	rewind(f);
	len = fsize < t->info.size_bytes ? fsize : t->info.size_bytes;
	rj_init(&r, RJ_COMPARE, WR_IO_READ, 0, len, chunk_size(t));
	r.f = f;
	st = rj_run(t, &r, 1);
	fclose(f);
	if (fsize != t->info.size_bytes) {
		r.diffs++;
		printf("@%llu size_mismatch image=%llu file=%llu\n", (unsigned long long)since(t), (unsigned long long)t->info.size_bytes,
		       (unsigned long long)fsize);
	}
	print_diff_line(t, "compare", &r, 0, len);
	return finish_rc(&r, st);
}

/* ---- bench ---------------------------------------------------------------------------------------------------- */

typedef struct benchjob {
	job j;
	wr_io_kind kind;
	uint64_t io, total, issued, done_bytes, ops, errors, lat_sum_us, lat_max_us, region;
	int random_io;
	rng r;
	uint64_t cursor;
} benchjob;

static int bj_issue(tool *t, job *j)
{
	benchjob *b = (benchjob *)(void *)j;

	while (b->issued < b->total) {
		slot *s = slot_get(t);
		uint64_t off;
		int rc;

		if (s == NULL)
			return 0;
		if (b->random_io)
			off = rnd_below(&b->r, b->region / b->io) * b->io;
		else {
			off = b->cursor;
			b->cursor = b->cursor + b->io >= b->region ? 0 : b->cursor + b->io;
		}
		rc = tool_submit(t, s, b->kind, off, b->io);
		if (rc == 0)
			return 0;
		if (rc < 0) {
			report_submit_error(t, "submit");
			b->errors++;
			b->issued = b->total;
			return 1;
		}
		b->issued += b->io;
	}
	return 1;
}

static void bj_complete(tool *t, job *j, slot *s)
{
	benchjob *b = (benchjob *)(void *)j;
	uint64_t lat = now_us() - s->t_us;

	if (s->st != WR_OK) {
		b->errors++;
		report_error(t, s, "request");
		return;
	}
	b->ops++;
	b->done_bytes += s->len;
	b->lat_sum_us += lat;
	if (lat > b->lat_max_us)
		b->lat_max_us = lat;
}

static int cmd_bench(tool *t, int npos, char **pos)
{
	benchjob b;
	uint64_t t0, el_us;
	unsigned i;
	int st;

	memset(&b, 0, sizeof(b));
	if (npos != 1 || (strcmp(pos[0], "read") != 0 && strcmp(pos[0], "write") != 0)) {
		fprintf(stderr, "wr-rbd: usage: bench read|write [--total N] [--io-size N] [--depth N] [--random]\n");
		return 2;
	}
	b.kind = strcmp(pos[0], "read") == 0 ? WR_IO_READ : WR_IO_WRITE;
	b.io = chunk_size(t);
	b.total = t->o.total != 0u ? t->o.total : (64u << 20);
	b.random_io = t->o.random_io;
	b.r.s = 12345;
	b.region = t->info.size_bytes / b.io * b.io;
	if (b.region == 0u) {
		printf("@%llu result bench ok=0 status=image smaller than --io-size\n", (unsigned long long)since(t));
		return 2;
	}
	if (b.kind == WR_IO_WRITE && need_rw(t, "bench") != 0)
		return 2;
	b.j.issue = bj_issue;
	b.j.complete = bj_complete;
	g_err_printed = 0;
	if (slots_alloc(t, (unsigned)t->o.depth, (size_t)b.io, 0) != 0)
		return 3;
	if (b.kind == WR_IO_WRITE)
		for (i = 0; i < t->nslots; i++) {
			pat p;

			p.kind = P_RAND;
			p.arg = 99u + i;
			pat_fill(&p, t->slots[i].buf, 0, (size_t)b.io);
		}
	t0 = now_us();
	st = tool_run(t, &b.j);
	el_us = now_us() - t0;
	if (el_us == 0u)
		el_us = 1;
	printf("@%llu result bench ok=%d kind=%s io_size=%llu depth=%llu random=%d ops=%llu bytes=%llu errors=%llu elapsed_ms=%llu mib_s=%.1f "
	       "iops=%.0f lat_avg_us=%llu lat_max_us=%llu\n",
	       (unsigned long long)since(t), (st == 0 && b.errors == 0u) ? 1 : 0, pos[0], (unsigned long long)b.io, (unsigned long long)t->o.depth,
	       b.random_io, (unsigned long long)b.ops, (unsigned long long)b.done_bytes, (unsigned long long)b.errors,
	       (unsigned long long)(el_us / 1000u), (double)b.done_bytes / 1048576.0 / ((double)el_us / 1e6),
	       (double)b.ops / ((double)el_us / 1e6), (unsigned long long)(b.ops != 0u ? b.lat_sum_us / b.ops : 0u),
	       (unsigned long long)b.lat_max_us);
	fflush(stdout);
	if (st != 0)
		return 3;
	return b.errors != 0u ? 4 : 0;
}

/* ---- random I/O against a model ----------------------------------------------------------------------------------- */

typedef struct randjob {
	job j;
	rng r;
	uint64_t seed, n_ops, issued, region, max_len, obj;
	uint8_t *model;
	int writable;
	uint64_t delay_ms, last_issue_ms;
	/* the operation drawn but not yet issued (so the sequence of operations depends on the seed alone) */
	int have_pending;
	wr_io_kind pk;
	uint64_t poff, plen, popno;
	int overlap;                 /* --overlap: no waiting for in-flight requests; overlapping ones are the point */
	uint64_t prev_off, prev_len; /* the range of the previous read / write / discard / zeroes drawn (0 length: none yet) */
	/* results */
	uint64_t n_write, n_read, n_discard, n_zero, n_flush, bytes_w, bytes_r, errors, mismatches, mism_bytes, n_conflict_waits;
} randjob;

static uint64_t rand_len(randjob *g, uint64_t cap)
{
	uint64_t pick = rnd_below(&g->r, 100), v;

	if (pick < 25u)
		v = 1u + rnd_below(&g->r, 512);
	else if (pick < 60u)
		v = 1u + rnd_below(&g->r, 16384);
	else if (pick < 85u)
		v = 1u + rnd_below(&g->r, 262144);
	else
		v = 1u + rnd_below(&g->r, g->max_len);
	if (v > g->max_len)
		v = g->max_len;
	if (v > cap)
		v = cap;
	return v != 0u ? v : 1u;
}

/* Draw the next operation. */
static void rand_draw0(randjob *g)
{
	uint64_t w = rnd_below(&g->r, 100), len, off, mode;

	if (!g->writable)
		w = 50; /* a read-only image: reads only */
	if (w < 45u && g->writable)
		g->pk = WR_IO_WRITE;
	else if (w < 75u || !g->writable)
		g->pk = WR_IO_READ;
	else if (w < 83u)
		g->pk = WR_IO_DISCARD;
	else if (w < 90u)
		g->pk = WR_IO_WRITE_ZEROES;
	else
		g->pk = WR_IO_FLUSH;
	g->popno = g->issued;
	if (g->pk == WR_IO_FLUSH) {
		g->poff = g->plen = 0;
		return;
	}
	len = rand_len(g, g->region);
	mode = rnd_below(&g->r, 5);
	if ((g->pk == WR_IO_DISCARD || g->pk == WR_IO_WRITE_ZEROES) && rnd_below(&g->r, 100) < 40u && g->region >= g->obj) {
		uint64_t objs = g->region / g->obj, m = 1u + rnd_below(&g->r, objs < 2u ? 1u : 2u);

		g->poff = rnd_below(&g->r, objs - m + 1u) * g->obj;
		g->plen = m * g->obj;
		return;
	}
	if (mode == 0u) { /* anywhere */
		off = rnd_below(&g->r, g->region - len + 1u);
	} else if (mode == 1u) { /* sector aligned */
		off = rnd_below(&g->r, (g->region - len) / 512u + 1u) * 512u;
	} else if (mode == 2u && g->region > g->obj) { /* straddles an object boundary */
		uint64_t b = (1u + rnd_below(&g->r, g->region / g->obj - 1u)) * g->obj, back = 1u + rnd_below(&g->r, len > 1u ? len - 1u : 1u);

		if (back > b)
			back = b;
		off = b - back;
		if (off + len > g->region)
			len = g->region - off;
	} else if (mode == 3u) { /* the start */
		off = 0;
	} else { /* the end */
		off = g->region - len;
	}
	g->poff = off;
	g->plen = len;
}

/* With --overlap about half of the operations start inside the range of the one drawn before (which is usually still in flight at
 * depth > 1), so overlapping reads and writes in flight are the common case. Drawn from the seed alone, like everything else. */
static void rand_draw(randjob *g)
{
	rand_draw0(g);
	if (g->pk == WR_IO_FLUSH || !g->overlap)
		return;
	if (g->prev_len != 0u && rnd_below(&g->r, 100) < 50u) {
		uint64_t o = g->prev_off + rnd_below(&g->r, g->prev_len);

		if (o + g->plen > g->region)
			o = g->region - g->plen;
		g->poff = o;
	}
	g->prev_off = g->poff;
	g->prev_len = g->plen;
}

static int rand_conflict(const tool *t, const randjob *g)
{
	unsigned i;

	if (g->pk == WR_IO_FLUSH || g->overlap)
		return 0;
	for (i = 0; i < t->nslots; i++) {
		const slot *s = &t->slots[i];

		if (!s->busy || s->kind == WR_IO_FLUSH)
			continue;
		if (s->kind == WR_IO_READ && g->pk == WR_IO_READ)
			continue;
		if (s->off < g->poff + g->plen && g->poff < s->off + s->len)
			return 1;
	}
	return 0;
}

static int rj2_issue(tool *t, job *j)
{
	randjob *g = (randjob *)(void *)j;

	while (g->issued < g->n_ops) {
		slot *s;
		int rc;

		if (g->delay_ms != 0u && now_ms() < g->last_issue_ms + g->delay_ms)
			return 0;
		s = slot_get(t);
		if (s == NULL)
			return 0;
		if (!g->have_pending) {
			rand_draw(g);
			g->have_pending = 1;
		}
		if (rand_conflict(t, g)) {
			g->n_conflict_waits++;
			return 0;
		}
		if (g->pk == WR_IO_WRITE) {
			pat p;

			p.kind = P_RAND;
			p.arg = mix64(g->seed ^ (g->popno * 0x9e3779b97f4a7c15ull)) | 1u;
			pat_fill(&p, s->buf, g->poff, (size_t)g->plen);
		} else if (g->pk == WR_IO_READ && g->overlap) {
			/* requests that overlap run in submission order (design C14): this read must see exactly the writes submitted before it */
			memcpy(s->ref, g->model + g->poff, (size_t)g->plen);
		}
		rc = tool_submit(t, s, g->pk, g->poff, g->plen);
		if (rc == 0)
			return 0;
		if (rc < 0) {
			report_submit_error(t, "submit");
			g->errors++;
			g->issued = g->n_ops;
			return 1;
		}
		s->opno = g->popno;
		switch (g->pk) {
		case WR_IO_WRITE:
			memcpy(g->model + g->poff, s->buf, (size_t)g->plen);
			g->n_write++;
			g->bytes_w += g->plen;
			break;
		case WR_IO_DISCARD:
			memset(g->model + g->poff, 0, (size_t)g->plen);
			g->n_discard++;
			break;
		case WR_IO_WRITE_ZEROES:
			memset(g->model + g->poff, 0, (size_t)g->plen);
			g->n_zero++;
			break;
		case WR_IO_FLUSH:
			g->n_flush++;
			break;
		case WR_IO_READ:
		default:
			g->n_read++;
			break;
		}
		g->issued++;
		g->have_pending = 0;
		g->last_issue_ms = now_ms();
	}
	return 1;
}

static void rj2_complete(tool *t, job *j, slot *s)
{
	randjob *g = (randjob *)(void *)j;
	const uint8_t *want;

	if (s->st != WR_OK) {
		g->errors++;
		report_error(t, s, "request");
		return;
	}
	if (s->kind != WR_IO_READ)
		return;
	g->bytes_r += s->len;
	want = g->overlap ? s->ref : g->model + s->off;
	if (memcmp(s->buf, want, (size_t)s->len) != 0) {
		uint64_t i = 0, n = 0;

		while (i < s->len) {
			n += s->buf[i] != want[i];
			i++;
		}
		for (i = 0; s->buf[i] == want[i]; i++) {
		}
		g->mismatches++;
		g->mism_bytes += n;
		if (g->mismatches <= PRINT_LIMIT)
			printf("@%llu mismatch op=%llu read off=%llu len=%llu first_diff=%llu got=0x%02x want=0x%02x differing_bytes=%llu\n",
			       (unsigned long long)since(t), (unsigned long long)s->opno, (unsigned long long)s->off, (unsigned long long)s->len,
			       (unsigned long long)(s->off + i), (unsigned)s->buf[i], (unsigned)want[i], (unsigned long long)n);
	}
}

static int cmd_random(tool *t, int npos, char **pos)
{
	randjob g;
	rangejob load, check;
	uint64_t n_ops, seed, region;
	int rc = 0, st;
	uint64_t t0 = now_ms();

	if (npos != 2 || parse_u64(pos[0], &n_ops) != 0 || parse_u64(pos[1], &seed) != 0) {
		fprintf(stderr, "wr-rbd: usage: random N SEED [--model-bytes N] [--max-len N] [--delay-ms N] [--overlap] [--save FILE]\n");
		return 2;
	}
	memset(&g, 0, sizeof(g));
	region = t->o.model_bytes != 0u ? t->o.model_bytes : DEFAULT_MODEL;
	if (region > t->info.size_bytes)
		region = t->info.size_bytes;
	if (region == 0u) {
		printf("@%llu result random ok=0 status=empty image\n", (unsigned long long)since(t));
		return 2;
	}
	g.writable = t->info.writable;
	g.region = region;
	g.obj = t->info.object_size;
	g.max_len = t->o.max_len != 0u ? t->o.max_len : (uint64_t)t->info.object_size + t->info.object_size / 2u;
	if (g.max_len > (8u << 20) && t->o.max_len == 0u)
		g.max_len = 8u << 20;
	if (g.max_len > t->info.max_io_bytes)
		g.max_len = t->info.max_io_bytes;
	if (g.max_len > region)
		g.max_len = region;
	g.n_ops = n_ops;
	g.seed = seed;
	g.r.s = seed * 0x2545f4914f6cdd1dull + 1u;
	g.delay_ms = t->o.delay_ms;
	g.overlap = t->o.overlap;
	g.j.issue = rj2_issue;
	g.j.complete = rj2_complete;
	g.model = (uint8_t *)calloc(1, (size_t)region);
	if (g.model == NULL) {
		fprintf(stderr, "wr-rbd: out of memory for the model\n");
		return 3;
	}
	/* 1. the model starts as the image is */
	rj_init(&load, RJ_MODEL_LOAD, WR_IO_READ, 0, region, chunk_size(t));
	load.model = g.model;
	st = rj_run(t, &load, 0);
	if (st != 0 || load.errors != 0u || load.hard_fail) {
		printf("@%llu result random ok=0 status=cannot read the initial content errors=%llu\n", (unsigned long long)since(t),
		       (unsigned long long)load.errors);
		free(g.model);
		return 3;
	}
	/* 2. the operations */
	{
		size_t cap = (size_t)g.max_len;

		if (cap < 1u)
			cap = 1;
		g_err_printed = 0;
		if (slots_alloc(t, (unsigned)t->o.depth, cap, g.overlap) != 0) {
			free(g.model);
			return 3;
		}
		st = tool_run(t, &g.j);
	}
	/* 3. the whole region again */
	rj_init(&check, RJ_MODEL_CHECK, WR_IO_READ, 0, region, chunk_size(t));
	check.model = g.model;
	if (st == 0 && !t->o.no_final_verify)
		st = rj_run(t, &check, 0);
	if (t->o.save != NULL) {
		FILE *f = fopen(t->o.save, "wb");

		if (f == NULL || fwrite(g.model, 1, (size_t)region, f) != (size_t)region || fclose(f) != 0)
			fprintf(stderr, "wr-rbd: cannot save the model to %s\n", t->o.save);
	}
	printf("@%llu result random ok=%d seed=%llu ops=%llu writes=%llu reads=%llu discards=%llu zeroes=%llu flushes=%llu bytes_written=%llu "
	       "bytes_read=%llu region=%llu max_len=%llu read_mismatches=%llu final_diff_bytes=%llu errors=%llu conflict_waits=%llu elapsed_ms=%llu\n",
	       (unsigned long long)since(t), (st == 0 && g.mismatches == 0u && check.diffs == 0u && g.errors == 0u && check.errors == 0u) ? 1 : 0,
	       (unsigned long long)seed, (unsigned long long)g.issued, (unsigned long long)g.n_write, (unsigned long long)g.n_read,
	       (unsigned long long)g.n_discard, (unsigned long long)g.n_zero, (unsigned long long)g.n_flush, (unsigned long long)g.bytes_w,
	       (unsigned long long)g.bytes_r, (unsigned long long)region, (unsigned long long)g.max_len, (unsigned long long)g.mismatches,
	       (unsigned long long)check.diffs, (unsigned long long)(g.errors + check.errors), (unsigned long long)g.n_conflict_waits,
	       (unsigned long long)(now_ms() - t0));
	if (check.have_diff)
		printf("@%llu mismatch final first_diff=%llu got=0x%02x want=0x%02x\n", (unsigned long long)since(t),
		       (unsigned long long)check.first_diff, (unsigned)check.first_got, (unsigned)check.first_want);
	fflush(stdout);
	if (st != 0)
		rc = 3;
	else if (g.mismatches != 0u || check.diffs != 0u)
		rc = 1;
	else if (g.errors != 0u || check.errors != 0u)
		rc = 4;
	free(g.model);
	return rc;
}

/* ---- command line ------------------------------------------------------------------------------------------- */

static void usage(void)
{
	fprintf(stderr,
		"usage: wr-rbd --mon <ip[:port]> --user <name> --keyring <file> --pool <pool> (--image <name> | --id <id>) [--data-pool <pool>] [--rw]\n"
		"              [--io-size N] [--depth N] [--timeout MS] [--io-timeout MS] [--run-timeout MS] [--op-timeout MS] [--hdr-refresh MS]\n"
		"              [--ordersnap] [--no-full-try] [--fsid UUID] [--stats-only] [-v] <command> [args]\n"
		"commands: info | read OFF LEN [FILE] | write OFF LEN (--pattern P | --file FILE) | fill [OFF LEN] [--pattern P] |\n"
		"          verify [OFF LEN] --pattern P | discard OFF LEN | zeroes OFF LEN | compare FILE | bench read|write [--total N] [--random] |\n"
		"          random N SEED [--model-bytes N] [--max-len N] [--delay-ms N] [--overlap] [--save FILE] [--no-final-verify] | shell\n"
		"patterns: zero | byte:N | seq | offset | rand:SEED\n");
}

static int num_opt(const char *name, const char *v, uint64_t *out)
{
	if (parse_u64(v, out) != 0) {
		fprintf(stderr, "wr-rbd: bad value for %s\n", name);
		return -1;
	}
	return 0;
}

/* Parse flags and positionals from argv. Flags may come before and after the command. Returns the number of positionals found
 * (stored in pos), or -1 on a usage error. */
static int parse_args(opts *o, int argc, char **argv, char **pos, int max_pos)
{
	int i, npos = 0;

	for (i = 0; i < argc; i++) {
		const char *a = argv[i];
		int has_val = i + 1 < argc;

		if (a[0] == '-' && a[1] != '\0' && !(a[1] >= '0' && a[1] <= '9')) {
#define STROPT(flag, field) \
	if (strcmp(a, flag) == 0 && has_val) { o->field = argv[++i]; continue; }
#define NUMOPT(flag, field) \
	if (strcmp(a, flag) == 0 && has_val) { if (num_opt(flag, argv[++i], &o->field) != 0) return -1; continue; }
			STROPT("--mon", mon) STROPT("--user", user) STROPT("--keyring", keyring) STROPT("--pool", pool) STROPT("--image", image)
			STROPT("--id", id) STROPT("--data-pool", data_pool) STROPT("--fsid", fsid) STROPT("--pattern", pattern)
			STROPT("--file", file) STROPT("--save", save)
			NUMOPT("--io-size", io_size) NUMOPT("--depth", depth) NUMOPT("--timeout", open_timeout_ms)
			NUMOPT("--io-timeout", io_timeout_ms) NUMOPT("--run-timeout", run_timeout_ms) NUMOPT("--total", total)
			NUMOPT("--model-bytes", model_bytes) NUMOPT("--max-len", max_len) NUMOPT("--delay-ms", delay_ms)
#undef STROPT
#undef NUMOPT
			if (strcmp(a, "--op-timeout") == 0 && has_val) {
				if (num_opt(a, argv[++i], &o->op_timeout_ms) != 0)
					return -1;
				o->have_op_timeout = 1;
			} else if (strcmp(a, "--hdr-refresh") == 0 && has_val) {
				if (num_opt(a, argv[++i], &o->hdr_refresh_ms) != 0)
					return -1;
				o->have_hdr_refresh = 1;
			} else if (strcmp(a, "--rw") == 0)
				o->rw = 1;
			else if (strcmp(a, "--ordersnap") == 0)
				o->ordersnap = 1;
			else if (strcmp(a, "--no-full-try") == 0)
				o->no_full_try = 1;
			else if (strcmp(a, "--stats-only") == 0)
				o->stats_only = 1;
			else if (strcmp(a, "--random") == 0)
				o->random_io = 1;
			else if (strcmp(a, "--overlap") == 0)
				o->overlap = 1;
			else if (strcmp(a, "--no-final-verify") == 0)
				o->no_final_verify = 1;
			else if (strcmp(a, "-v") == 0)
				o->verbose = 1;
			else {
				fprintf(stderr, "wr-rbd: unknown or incomplete option %s\n", a);
				return -1;
			}
			continue;
		}
		if (npos >= max_pos)
			return -1;
		pos[npos++] = argv[i];
	}
	return npos;
}

/* The numbers that size buffers and reach 32 bit fields of the core: refused (not truncated) when out of range. 0 = fine. */
static int check_limits(const opts *o)
{
	if (o->depth == 0u || o->depth > MAX_SLOTS - 1u || o->io_size == 0u || o->io_size > (256u << 20)) {
		fprintf(stderr, "wr-rbd: --depth must be 1 to %u and --io-size 1 to 256M\n", MAX_SLOTS - 1u);
		return -1;
	}
	if (o->open_timeout_ms > UINT32_MAX || o->io_timeout_ms > UINT32_MAX || o->op_timeout_ms > UINT32_MAX || o->hdr_refresh_ms > UINT32_MAX ||
	    (o->have_op_timeout && o->op_timeout_ms == 0u)) {
		fprintf(stderr, "wr-rbd: a timeout is at most 4294967295 ms (and --op-timeout is not 0)\n");
		return -1;
	}
	return 0;
}

static int dispatch(tool *t, const char *cmd, int npos, char **pos)
{
	if (strcmp(cmd, "info") == 0)
		return cmd_info(t);
	if (strcmp(cmd, "read") == 0)
		return cmd_read(t, npos, pos);
	if (strcmp(cmd, "write") == 0)
		return cmd_write(t, npos, pos, 0);
	if (strcmp(cmd, "fill") == 0)
		return cmd_write(t, npos, pos, 1);
	if (strcmp(cmd, "verify") == 0)
		return cmd_verify(t, npos, pos);
	if (strcmp(cmd, "discard") == 0)
		return cmd_discard(t, npos, pos, WR_IO_DISCARD, "discard");
	if (strcmp(cmd, "zeroes") == 0)
		return cmd_discard(t, npos, pos, WR_IO_WRITE_ZEROES, "zeroes");
	if (strcmp(cmd, "compare") == 0)
		return cmd_compare(t, npos, pos);
	if (strcmp(cmd, "bench") == 0)
		return cmd_bench(t, npos, pos);
	if (strcmp(cmd, "random") == 0)
		return cmd_random(t, npos, pos);
	fprintf(stderr, "wr-rbd: unknown command %s\n", cmd);
	return 2;
}

/* dispatch, and a command during which the core broke its own contract (a flush overtook a write, a request came back twice) is a
 * failed command, whatever the command itself found. */
static int dispatch_checked(tool *t, const char *cmd, int npos, char **pos)
{
	unsigned before = t->barrier_viol + t->bad_done;
	int rc = dispatch(t, cmd, npos, pos);

	if (rc == 0 && t->barrier_viol + t->bad_done != before)
		rc = 4;
	return rc;
}

/* ---- shell ----------------------------------------------------------------------------------------------------- */

/* The next input line (without the newline) while the engine keeps running. 1 = a line, 0 = end of input or failure. A line that does
 * not fit is refused as a whole (reported on stderr, run as an empty line): its tail must never run as a command of its own. */
static int shell_getline(tool *t, char *line, size_t cap)
{
	for (;;) {
		char *nl = memchr(t->inbuf, '\n', t->inlen);

		if (t->in_skip) { /* inside the rest of a refused line */
			if (nl == NULL) {
				t->inlen = 0;
			} else {
				memmove(t->inbuf, nl + 1, t->inlen - (size_t)(nl + 1 - t->inbuf));
				t->inlen -= (size_t)(nl + 1 - t->inbuf);
				t->in_skip = 0;
			}
			nl = t->in_skip ? NULL : memchr(t->inbuf, '\n', t->inlen);
		}
		if (!t->in_skip && nl != NULL) {
			size_t n = (size_t)(nl - t->inbuf);

			if (n >= cap) {
				fprintf(stderr, "wr-rbd: shell line too long (limit %u bytes): ignored\n", (unsigned)(cap - 1u));
				n = 0;
			}
			memcpy(line, t->inbuf, n);
			line[n] = '\0';
			memmove(t->inbuf, nl + 1, t->inlen - (size_t)(nl + 1 - t->inbuf));
			t->inlen -= (size_t)(nl + 1 - t->inbuf);
			return 1;
		}
		if (!t->in_skip && t->inlen >= cap) { /* no newline within the limit: refuse the whole line, tail included */
			fprintf(stderr, "wr-rbd: shell line too long (limit %u bytes): ignored\n", (unsigned)(cap - 1u));
			t->in_skip = 1;
			t->inlen = 0;
			line[0] = '\0';
			return 1;
		}
		if (t->in_eof || t->fatal != WR_OK) {
			if (!t->in_skip && t->inlen != 0u && t->fatal == WR_OK) { /* a last line without a newline */
				size_t n = t->inlen < cap - 1u ? t->inlen : cap - 1u;

				memcpy(line, t->inbuf, n);
				line[n] = '\0';
				t->inlen = 0;
				return 1;
			}
			return 0;
		}
		{
			struct pollfd pf;

			pf.fd = 0;
			pf.events = POLLIN;
			pf.revents = 0;
			if (poll(&pf, 1, 0) > 0 && t->inlen < sizeof(t->inbuf)) {
				ssize_t n = read(0, t->inbuf + t->inlen, sizeof(t->inbuf) - t->inlen);

				if (n > 0)
					t->inlen += (size_t)n;
				else if (n == 0 || (errno != EINTR && errno != EAGAIN))
					t->in_eof = 1;
				continue;
			}
		}
		tool_step(t, 20);
	}
}

static int cmd_shell(tool *t)
{
	char line[LINE_MAX_BYTES];
	unsigned seq = 0;
	int worst = 0;

	printf("@%llu shell ready\n", (unsigned long long)since(t));
	fflush(stdout);
	while (shell_getline(t, line, sizeof(line))) {
		char *argv[MAX_ARGS], *p = line, *pos[MAX_ARGS];
		int argc = 0, npos, rc = 0;
		opts o = t->o;
		opts saved;

		while (*p != '\0' && argc < (int)MAX_ARGS) {
			while (*p == ' ' || *p == '\t' || *p == '\r')
				p++;
			if (*p == '\0')
				break;
			argv[argc++] = p;
			while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\r')
				p++;
			if (*p != '\0')
				*p++ = '\0';
		}
		if (argc == 0 || argv[0][0] == '#')
			continue;
		seq++;
		if (strcmp(argv[0], "quit") == 0 || strcmp(argv[0], "exit") == 0)
			break;
		if (strcmp(argv[0], "echo") == 0) {
			int k;

			printf("@%llu echo", (unsigned long long)since(t));
			for (k = 1; k < argc; k++)
				printf(" %s", argv[k]);
			printf("\n");
		} else if (strcmp(argv[0], "sleep") == 0) {
			uint64_t ms = 0;

			if (argc != 2 || parse_u64(argv[1], &ms) != 0)
				rc = 2;
			else
				tool_pump_for(t, ms);
		} else {
			npos = parse_args(&o, argc - 1, argv + 1, pos, (int)MAX_ARGS);
			if (npos < 0 || check_limits(&o) != 0)
				rc = 2;
			else {
				saved = t->o;
				t->o = o;
				rc = dispatch_checked(t, argv[0], npos, pos);
				t->o = saved;
			}
		}
		if (t->fatal != WR_OK)
			rc = 3;
		if (rc > worst)
			worst = rc;
		printf("@%llu done %u rc=%d\n", (unsigned long long)since(t), seq, rc);
		fflush(stdout);
		if (t->fatal != WR_OK)
			break;
	}
	printf("@%llu result shell ok=%d commands=%u\n", (unsigned long long)since(t), worst == 0 ? 1 : 0, seq);
	return worst;
}

/* ---- main ------------------------------------------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	tool t;
	char *pos[MAX_ARGS];
	int npos, rc = 0;
	unsigned level = WR_LOG_WARN;
	wr_cluster_spec spec;
	static char kr[KEYRING_MAX];
	size_t krlen = 0, nmon = 0;
	wr_status st;
	const char *cmd;
	wr_osd_stats os;

	memset(&t, 0, sizeof(t));
	t.o.io_size = DEFAULT_IO;
	t.o.depth = 8;
	t.o.open_timeout_ms = 30000;
	npos = parse_args(&t.o, argc - 1, argv + 1, pos, (int)MAX_ARGS);
	if (npos < 1 || t.o.mon == NULL || t.o.user == NULL || t.o.keyring == NULL || t.o.pool == NULL || (t.o.image == NULL && t.o.id == NULL)) {
		usage();
		return 2;
	}
	if (check_limits(&t.o) != 0)
		return 2;
	if (t.o.verbose)
		level = WR_LOG_DEBUG;
	cmd = pos[0];
	if (strcmp(cmd, "info") != 0 && strcmp(cmd, "read") != 0 && strcmp(cmd, "write") != 0 && strcmp(cmd, "fill") != 0 &&
	    strcmp(cmd, "verify") != 0 && strcmp(cmd, "discard") != 0 && strcmp(cmd, "zeroes") != 0 && strcmp(cmd, "compare") != 0 &&
	    strcmp(cmd, "bench") != 0 && strcmp(cmd, "random") != 0 && strcmp(cmd, "shell") != 0) {
		fprintf(stderr, "wr-rbd: unknown command %s\n", cmd);
		usage();
		return 2;
	}
	memset(&spec, 0, sizeof(spec));
	if (strlen(t.o.user) >= sizeof(spec.user)) {
		fprintf(stderr, "wr-rbd: user name too long\n");
		return 2;
	}
	strcpy(spec.user, t.o.user);
	if (t.o.fsid != NULL) {
		if (fsid_parse(t.o.fsid, spec.fsid) != 0) {
			fprintf(stderr, "wr-rbd: bad --fsid\n");
			return 2;
		}
		spec.fsid_known = 1;
	}
	st = wr_mon_parse_hosts(t.o.mon, strlen(t.o.mon), spec.mons, WR_MAX_MONS, &nmon);
	if (st != WR_OK) {
		fprintf(stderr, "wr-rbd: --mon: %s\n", wr_strerror(st));
		return 2;
	}
	spec.n_mons = (uint8_t)nmon;
	st = wrl_read_text_file(t.o.keyring, kr, sizeof(kr), &krlen);
	if (st == WR_OK)
		st = wr_key_parse_keyring(&spec.key, kr, krlen);
	wipe(kr, sizeof(kr));
	if (st != WR_OK) {
		fprintf(stderr, "wr-rbd: keyring %s: %s\n", t.o.keyring, wr_strerror(st));
		return 2;
	}
	t.t0_ms = now_ms();
	if (tool_create(&t, &spec, &level) != 0) {
		wr_key_wipe(&spec.key);
		return 2;
	}
	wr_key_wipe(&spec.key);
	if (tool_open_image(&t) != 0) {
		rc = 3;
	} else {
		print_image(&t);
		if (strcmp(cmd, "shell") == 0)
			rc = cmd_shell(&t);
		else
			rc = dispatch_checked(&t, cmd, npos - 1, pos + 1);
	}
	pump_events(&t);
	memset(&os, 0, sizeof(os));
	wr_client_osd_stats(t.c, &os);
	printf("@%llu stats ops_inflight=%u ops_hiwater=%u reqs_hiwater=%u sessions_hiwater=%u ops_done=%llu ops_resent=%llu ops_failed=%llu "
	       "session_resets=%u backoff_blocks=%u backoff_overflow=%u osdmap_discarded=%u zombie_bytes_max=%u events=%llu io_stalls=%u io_resumes=%u maps=%u barrier_violations=%u bad_completions=%u\n",
	       (unsigned long long)since(&t), os.ops_inflight, os.ops_hiwater, os.reqs_hiwater, os.sessions_hiwater, (unsigned long long)os.ops_done,
	       (unsigned long long)os.ops_resent, (unsigned long long)os.ops_failed, os.n_session_resets, os.n_backoff_blocks,
	       os.n_backoff_overflow, os.n_osdmap_discarded, os.zombie_bytes_max, (unsigned long long)t.n_events, t.n_stall, t.n_resume, t.n_map, t.barrier_viol, t.bad_done);
	fflush(stdout);
	if (t.img != NULL && wr_image_get_state(t.img) != WR_IMG_FREE && t.fatal == WR_OK)
		st = wr_image_close(t.img, WR_CLOSE_ABANDON); /* the process ends next: a refusal changes nothing */
	slots_free(&t);
	wrl_loop_destroy(t.loop);
	wr_client_destroy(t.c);
	wrl_mem_free(&t.arena);
	wrl_mem_free(&t.bulk);
	if (rc == 0 && t.fatal != WR_OK)
		rc = 3;
	return rc;
}
