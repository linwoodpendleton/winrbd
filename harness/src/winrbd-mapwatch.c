/* SPDX-License-Identifier: MIT */
/*
 * winrbd-mapwatch - the live placement probe (docs/design/core-architecture.md 18.4). It logs in to a real monitor with
 * the whole core (msgr2, cephx, monitor client), lets the core's own map store decode the OSD map and follow every
 * incremental, and prints where objects and placement groups of tracked pools live, in the held epoch. A script compares
 * the printed rows with `ceph osd map -f json` and `ceph pg map` of the same epoch (harness/tools/map_placement_lab.py).
 *
 *   winrbd-mapwatch --mon <ip[:port]> --user <name> --keyring <file> --pool <name> [--pool <name>]... [options]
 *
 *   --names <file>      object names to place (one per line), printed once the maps are held and again at every later epoch
 *                       while --follow lasts
 *   --prefix S --count N  the names S0 .. S<N-1> instead of (or beside) a file
 *   --follow <s>        keep following the cluster for this many seconds after the first table (default 0)
 *   --stdin             read commands from standard input (below); the tool then runs until `quit` or end of input
 *   --trace <file>      at EVERY epoch the core adopts, append "== epoch N", one "pool" line per tracked pool and one row per
 *                       placement group (up to --trace-pgs per pool, default 1024). The rows are what the core said at exactly
 *                       that epoch; a script gets the monitor's table of the same epoch with `ceph osd getmap N`.
 *   --save-maps <dir>   write every full map and incremental of every map message the store is handed to
 *                       <dir>/full-<epoch>.bin and <dir>/inc-<epoch>.bin (the exact bytes the engine consumed, dropped
 *                       messages included), so a chain can be replayed offline.
 *   --log <file>        events (session up / down, map adopted, re-requests) with a millisecond clock
 *   --timeout <ms>      give up when no session or no first map exists after this long (default 20000)
 *   -v                  core log on stderr
 *
 * Commands (--stdin), one per line; every command answers with one line "ok ..." or "err ...":
 *   wait-epoch <N> [s]  run until the held epoch is at least N (default 30 s)           -> ok epoch=<held>
 *   wait-pools [s]      run until every tracked pool resolves                          -> ok epoch=<held>
 *   pump <ms>           run for this long                                              -> ok epoch=<held>
 *   place <pool> <out> <prefix> <count> [first]   place <prefix><first> .. <prefix><first+count-1>
 *   placef <pool> <out> <names file>              place the names of a file          -> ok epoch=<E> rows=<n> unmappable=<u>
 *   pgs <pool> <out>    every placement group of the pool (<out> '-' = standard output) -> ok epoch=<E> rows=<n> unmappable=<u>
 *   track <pool>        track one more pool (at most 8, also after the first map)
 *   info                counters: epoch, newest, full maps, incrementals, re-requests, bad, skipped, dropped by the hook
 *   drop <n>            fault injection: the next n map messages that carry incrementals never reach the map store (as if the
 *                       link had lost them): the next one has a gap and the store must ask the monitor for a full map
 *   quit
 *
 * Row format (one line per answer; the keys never change):
 *   <epoch> <pool> <object> ps=<hex> pg=<pool id>.<seed hex> up=[a,b] upp=<n> acting=[a,b] actp=<n>
 *   <epoch> <pool> pg=<pool id>.<seed hex> up=[a,b] upp=<n> acting=[a,b] actp=<n>               (a placement group)
 * and `UNMAPPABLE` instead of the sets when no OSD serves the group. Object names are printed with \xHH for every byte that
 * is not printable ASCII, a space or a backslash.
 *
 * The key is read from the keyring file, handed to the core and wiped; it is never printed. Harness code: it reads two things
 * from core internals (the map-store io hook that implements --save-maps, --trace's per-epoch view and `drop`).
 * Exit status: 0 healthy; 1 no session or no map in time; 2 usage or setup error; 3 the client failed fatally; 4 a map entry
 * failed to decode or apply that no re-request recovered (n_bad above the count of re-requests); 5 authentication refused.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wrl_host.h"
#include "wri_client.h"

#define MW_DEFAULT_TIMEOUT_MS 20000
#define MW_KEYRING_MAX 4096u
#define MW_MAX_POOLS 8u
#define MW_LINE_MAX 1024u
#define MW_NAME_MAX 512u
#define MW_PATH_MAX 512u

typedef struct mw_app {
	wr_client *c;
	wrl_loop *loop;
	uint64_t t0;
	const char *pool_name[MW_MAX_POOLS];
	wr_pool_h pool[MW_MAX_POOLS];
	unsigned n_pools;
	FILE *log, *trace;
	unsigned trace_pgs;
	char save_dir[MW_PATH_MAX];
	uint32_t traced_epoch;
	unsigned n_auth_failed, n_fatal, n_map_events, n_resync_events, n_session_up, n_session_down;
	wr_errinfo first_err;
	/* the io hook */
	int (*real_peek)(void *ctx, wr_mapmsg *out);
	void (*real_release)(void *ctx);
	int msg_seen; /* the message the store holds was looked at already (saved, maybe dropped) */
	unsigned drop_left, n_dropped;
	unsigned n_saved_inc, n_saved_full;
	int in_hook;
	/* stdin */
	char inbuf[MW_LINE_MAX * 2u];
	size_t inlen;
	int eof;
} mw_app;

static mw_app *g_app; /* the io hook has no context argument of its own; one app per process (harness code) */

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0)
		*v++ = 0;
}

static uint64_t now_ms(void)
{
	wr_clock c;

	wrl_clock(&c);
	return c.mono_ms;
}

static void logf_(mw_app *a, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void logf_(mw_app *a, const char *fmt, ...)
{
	va_list ap;

	if (a->log == NULL)
		return;
	fprintf(a->log, "@%llu ", (unsigned long long)(now_ms() - a->t0));
	va_start(ap, fmt);
	vfprintf(a->log, fmt, ap);
	va_end(ap);
	fputc('\n', a->log);
	fflush(a->log);
}

/* ---- rows --------------------------------------------------------------------------------------------------------- */

static void put_bytes(FILE *f, const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (p[i] > 0x20u && p[i] < 0x7fu && p[i] != '\\')
			fputc((int)p[i], f);
		else
			fprintf(f, "\\x%02x", (unsigned)p[i]);
	}
	if (n == 0u)
		fputc('-', f);
}

static void put_ids(FILE *f, const int32_t *v, unsigned n)
{
	unsigned i;

	fputc('[', f);
	for (i = 0; i < n; i++)
		fprintf(f, "%s%d", i ? "," : "", (int)v[i]);
	fputc(']', f);
}

static void put_sets(FILE *f, wr_status st, const wr_target *t)
{
	if (st == WR_E_PLACE_UNMAPPABLE) {
		fputs(" UNMAPPABLE", f);
	} else if (st != WR_OK) {
		fprintf(f, " ERROR %s", wr_status_name(st));
	} else {
		fputs(" up=", f);
		put_ids(f, t->up, t->n_up);
		fprintf(f, " upp=%d acting=", (int)t->up_primary);
		put_ids(f, t->acting, t->n_acting);
		fprintf(f, " actp=%d", (int)t->acting_primary);
	}
	fputc('\n', f);
}

/* One object. Returns 1 for a row that is not a plain answer (unmappable or an error). */
static int row_object(mw_app *a, FILE *f, unsigned pi, const uint8_t *name, size_t n, uint32_t epoch)
{
	wr_object_id oid;
	wr_target t;
	wr_status st;

	memset(&oid, 0, sizeof(oid));
	oid.name = name;
	oid.name_len = n;
	memset(&t, 0, sizeof(t));
	st = wr_client_map_target(a->c, a->pool[pi], &oid, &t);
	fprintf(f, "%u %s ", (unsigned)epoch, a->pool_name[pi]);
	put_bytes(f, name, n);
	if (st == WR_OK || st == WR_E_PLACE_UNMAPPABLE)
		fprintf(f, " ps=%08x pg=%lld.%x", (unsigned)t.ps, (long long)t.pool_id, (unsigned)t.pg_seed);
	put_sets(f, st, &t);
	return st != WR_OK;
}

static int row_pg(mw_app *a, FILE *f, unsigned pi, uint32_t seed, uint32_t epoch, int64_t pool_id)
{
	wr_target t;
	wr_status st;

	memset(&t, 0, sizeof(t));
	st = wr_client_map_target_pg(a->c, a->pool[pi], seed, &t);
	fprintf(f, "%u %s pg=%lld.%x", (unsigned)epoch, a->pool_name[pi], (long long)pool_id, (unsigned)seed);
	put_sets(f, st, &t);
	return st != WR_OK;
}

static int held_epoch(mw_app *a, uint32_t *epoch)
{
	wr_map_info mi;

	if (wr_client_map_info(a->c, &mi) != WR_OK)
		return 0;
	*epoch = mi.epoch;
	return 1;
}

static int pool_ok(mw_app *a, unsigned pi, wr_pool_info *pinf)
{
	return wr_client_pool_info(a->c, a->pool[pi], pinf) == WR_OK && pinf->status == WR_OK;
}

/* every placement group of pool pi (all of them, up to max_pgs); returns the rows that were not plain answers, -1 when the pool is not usable */
static int table_pgs(mw_app *a, FILE *f, unsigned pi, unsigned max_pgs, unsigned *rows)
{
	wr_pool_info pinf;
	uint32_t epoch, s;
	int bad = 0;

	*rows = 0;
	if (!held_epoch(a, &epoch) || !pool_ok(a, pi, &pinf))
		return -1;
	for (s = 0; s < pinf.pg_num && *rows < max_pgs; s++) {
		bad += row_pg(a, f, pi, s, epoch, pinf.id);
		(*rows)++;
	}
	return bad;
}

/* ---- the io hook: --save-maps, --trace and `drop` ----------------------------------------------------------------------- */

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void save_blob(mw_app *a, const char *kind, uint32_t epoch, const uint8_t *p, size_t n)
{
	char path[MW_PATH_MAX + 64];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s-%u.bin", a->save_dir, kind, (unsigned)epoch);
	f = fopen(path, "wb");
	if (f == NULL) {
		fprintf(stderr, "winrbd-mapwatch: cannot write %s: %s\n", path, strerror(errno));
		return;
	}
	if (fwrite(p, 1, n, f) != n)
		fprintf(stderr, "winrbd-mapwatch: short write to %s\n", path);
	fclose(f);
}

/*
 * Walk the two lists of an MOSDMap front: fsid(16), u32 n, {u32 epoch, u32 len, blob}*, u32 n, {...}* (incrementals, then full
 * maps). Saves the blobs when --save-maps is on and returns the number of incrementals (the `drop` fault only takes messages
 * that carry some).
 */
static unsigned walk_front(mw_app *a, const uint8_t *f, size_t n, int save)
{
	size_t off = 16;
	unsigned list, n_inc = 0;

	for (list = 0; list < 2u; list++) {
		uint32_t cnt, i;

		if (n < off + 4u)
			return n_inc;
		cnt = rd32(f + off);
		off += 4;
		if (cnt > 4096u)
			return n_inc;
		for (i = 0; i < cnt; i++) {
			uint32_t ep, len;

			if (n < off + 8u)
				return n_inc;
			ep = rd32(f + off);
			len = rd32(f + off + 4);
			off += 8;
			if (len > n - off)
				return n_inc;
			if (list == 0u)
				n_inc++;
			if (save && a->save_dir[0] != '\0' && len > 0u) {
				save_blob(a, list == 0u ? "inc" : "full", ep, f + off, len);
				if (list == 0u)
					a->n_saved_inc++;
				else
					a->n_saved_full++;
			}
			off += len;
		}
	}
	return n_inc;
}

static void trace_epoch(mw_app *a)
{
	uint32_t epoch;
	unsigned pi, rows;
	int saved_hook;

	if (a->trace == NULL || !held_epoch(a, &epoch) || epoch == a->traced_epoch)
		return;
	a->traced_epoch = epoch;
	fprintf(a->trace, "== epoch %u\n", (unsigned)epoch);
	for (pi = 0; pi < a->n_pools; pi++) {
		wr_pool_info pinf;

		if (!pool_ok(a, pi, &pinf)) {
			fprintf(a->trace, "pool %s ABSENT\n", a->pool_name[pi]);
			continue;
		}
		fprintf(a->trace, "pool %s id=%lld size=%u min_size=%u pg_num=%u pgp_num=%u flags=%llx\n", a->pool_name[pi], (long long)pinf.id,
			(unsigned)pinf.size, (unsigned)pinf.min_size, (unsigned)pinf.pg_num, (unsigned)pinf.pgp_num, (unsigned long long)pinf.flags);
		saved_hook = a->in_hook;
		a->in_hook = 1;
		(void)table_pgs(a, a->trace, pi, a->trace_pgs, &rows);
		a->in_hook = saved_hook;
	}
	fflush(a->trace);
	logf_(a, "epoch adopted %u", (unsigned)epoch);
}

static int hook_peek(void *ctx, wr_mapmsg *out)
{
	mw_app *a = g_app;

	if (a == NULL)
		return 0;
	/* the held epoch may have moved since the last look: the table of every epoch is written at the start of the next step */
	if (!a->in_hook)
		trace_epoch(a);
	for (;;) {
		if (!a->real_peek(ctx, out))
			return 0;
		if (a->msg_seen)
			return 1;
		a->msg_seen = 1;
		if (out->kind == WR_MAPMSG_OSDMAP) {
			unsigned n_inc = walk_front(a, out->front, out->front_len, 1);

			if (a->drop_left != 0u && n_inc != 0u) {
				a->drop_left--;
				a->n_dropped++;
				logf_(a, "fault: map message of newest epoch %u (%u incrementals) dropped before the store", (unsigned)out->newest_epoch, n_inc);
				a->real_release(ctx);
				a->msg_seen = 0;
				continue;
			}
		}
		return 1;
	}
}

static void hook_release(void *ctx)
{
	mw_app *a = g_app;

	if (a != NULL)
		a->msg_seen = 0;
	if (a != NULL)
		a->real_release(ctx);
}

/* ---- running ------------------------------------------------------------------------------------------------------ */

static const char *ev_name(wr_ev_kind k)
{
	switch (k) {
	case WR_EV_MON_SESSION_UP:
		return "MON_SESSION_UP";
	case WR_EV_MON_SESSION_DOWN:
		return "MON_SESSION_DOWN";
	case WR_EV_AUTH_FAILED:
		return "AUTH_FAILED";
	case WR_EV_CLUSTER_UNREACHABLE:
		return "CLUSTER_UNREACHABLE";
	case WR_EV_MAPMSG:
		return "MAPMSG";
	case WR_EV_TICKETS_RENEWED:
		return "TICKETS_RENEWED";
	case WR_EV_FATAL:
		return "FATAL";
	case WR_EV_MAP:
		return "MAP";
	case WR_EV_MAP_RESYNC:
		return "MAP_RESYNC";
	case WR_EV_NONE:
	default:
		return "NONE";
	}
}

static void drain_events(mw_app *a)
{
	wr_event e;

	while (wr_client_next_event(a->c, &e)) {
		logf_(a, "event %s epoch=%u%s%s", ev_name(e.kind), (unsigned)e.epoch, e.err.status != WR_OK ? " status=" : "",
		      e.err.status != WR_OK ? wr_status_name(e.err.status) : "");
		switch (e.kind) {
		case WR_EV_MON_SESSION_UP:
			a->n_session_up++;
			break;
		case WR_EV_MON_SESSION_DOWN:
			a->n_session_down++;
			break;
		case WR_EV_AUTH_FAILED:
			if (a->n_auth_failed++ == 0)
				a->first_err = e.err;
			break;
		case WR_EV_FATAL:
			if (a->n_fatal++ == 0)
				a->first_err = e.err;
			break;
		case WR_EV_MAP:
			a->n_map_events++;
			break;
		case WR_EV_MAP_RESYNC:
			a->n_resync_events++;
			break;
		default:
			break;
		}
	}
}

/* One step of the loop plus what follows it. Returns 0, or 1 when the client can go no further (fatal, refused). */
static int pump(mw_app *a, int ms)
{
	wr_status st = wrl_loop_step(a->loop, ms);

	drain_events(a);
	trace_epoch(a);
	return st != WR_OK && st != WR_E_TIMEOUT ? 1 : (a->n_auth_failed != 0 || a->n_fatal != 0);
}

static int all_pools_ok(mw_app *a)
{
	wr_pool_info pinf;
	unsigned i;

	for (i = 0; i < a->n_pools; i++)
		if (!pool_ok(a, i, &pinf))
			return 0;
	return a->n_pools != 0u;
}

/* Run until a map is held at epoch `want` or later and, with need_pools, every tracked pool resolves, or the time is up. 1 on success. */
static int run_until(mw_app *a, uint32_t want, uint64_t limit_ms, int need_pools)
{
	uint64_t end = now_ms() + limit_ms;
	uint32_t e = 0;

	for (;;) {
		if (held_epoch(a, &e) && e >= want && (!need_pools || all_pools_ok(a)))
			return 1;
		if (now_ms() >= end || pump(a, 50))
			return held_epoch(a, &e) && e >= want && (!need_pools || all_pools_ok(a));
	}
}

static int run_for(mw_app *a, uint64_t ms)
{
	uint64_t end = now_ms() + ms;

	while (now_ms() < end)
		if (pump(a, 20))
			return 1;
	return 0;
}

static int track_pool(mw_app *a, const char *name)
{
	char *copy;

	if (a->n_pools >= MW_MAX_POOLS)
		return -1;
	copy = strdup(name);
	if (copy == NULL || wr_client_pool_track(a->c, copy, &a->pool[a->n_pools]) != WR_OK) {
		free(copy);
		return -1;
	}
	a->pool_name[a->n_pools++] = copy;
	return 0;
}

static int pool_index(mw_app *a, const char *name)
{
	unsigned i;

	for (i = 0; i < a->n_pools; i++)
		if (strcmp(a->pool_name[i], name) == 0)
			return (int)i;
	return -1;
}

/* ---- name sources --------------------------------------------------------------------------------------------------- */

typedef struct names {
	char *buf;
	size_t *off, *len;
	size_t n;
} names;

static void names_free(names *s)
{
	free(s->buf);
	free(s->off);
	free(s->len);
	memset(s, 0, sizeof(*s));
}

static int names_from_file(names *s, const char *path)
{
	FILE *f = fopen(path, "rb");
	size_t cap = 0, used = 0, i, nl = 0;
	char *buf = NULL;
	int ch;

	memset(s, 0, sizeof(*s));
	if (f == NULL)
		return -1;
	while ((ch = fgetc(f)) != EOF) {
		if (used + 2u > cap) {
			char *nb;

			cap = cap ? cap * 2u : 4096u;
			nb = realloc(buf, cap);
			if (nb == NULL) {
				free(buf);
				fclose(f);
				return -1;
			}
			buf = nb;
		}
		buf[used++] = (char)ch;
		if (ch == '\n')
			nl++;
	}
	fclose(f);
	if (used != 0u && buf[used - 1u] != '\n') {
		buf[used++] = '\n';
		nl++;
	}
	s->off = calloc(nl + 1u, sizeof(size_t));
	s->len = calloc(nl + 1u, sizeof(size_t));
	if (s->off == NULL || s->len == NULL) {
		free(buf);
		names_free(s);
		return -1;
	}
	s->buf = buf;
	for (i = 0; i < used;) {
		size_t j = i;

		while (j < used && buf[j] != '\n')
			j++;
		if (j > i && j - i <= MW_NAME_MAX) {
			s->off[s->n] = i;
			s->len[s->n] = j - i;
			s->n++;
		}
		i = j + 1u;
	}
	return 0;
}

static void place_names_file(mw_app *a, FILE *out, unsigned pi, const names *s, unsigned *rows, unsigned *unmappable)
{
	uint32_t epoch = 0;
	size_t i;

	*rows = *unmappable = 0;
	if (!held_epoch(a, &epoch))
		return;
	for (i = 0; i < s->n; i++) {
		*unmappable += (unsigned)row_object(a, out, pi, (const uint8_t *)s->buf + s->off[i], s->len[i], epoch);
		(*rows)++;
	}
}

static void place_prefix(mw_app *a, FILE *out, unsigned pi, const char *prefix, unsigned first, unsigned count, unsigned *rows,
			 unsigned *unmappable)
{
	uint32_t epoch = 0;
	unsigned i;

	*rows = *unmappable = 0;
	if (!held_epoch(a, &epoch))
		return;
	for (i = 0; i < count; i++) {
		char nm[MW_NAME_MAX];
		int n = snprintf(nm, sizeof(nm), "%s%u", prefix, first + i);

		if (n <= 0 || (size_t)n >= sizeof(nm))
			continue;
		*unmappable += (unsigned)row_object(a, out, pi, (const uint8_t *)nm, (size_t)n, epoch);
		(*rows)++;
	}
}

/* ---- the commands ---------------------------------------------------------------------------------------------------- */

static void print_info(mw_app *a)
{
	wr_map_stats ms;
	uint32_t e = 0;

	wr_client_map_stats(a->c, &ms);
	(void)held_epoch(a, &e);
	printf("ok epoch=%u newest=%u full=%u inc=%u resync=%u bad=%u skipped=%u msg_bad=%u msg_toobig=%u fsid_drop=%u dropped_by_hook=%u "
	       "saved_inc=%u saved_full=%u map_events=%u resync_events=%u last_err=%s\n",
	       (unsigned)e, (unsigned)ms.newest_seen, (unsigned)ms.n_full, (unsigned)ms.n_inc, (unsigned)ms.n_resync, (unsigned)ms.n_bad,
	       (unsigned)ms.n_skipped, (unsigned)ms.n_msg_bad, (unsigned)ms.n_msg_toobig, (unsigned)ms.n_fsid_drop, a->n_dropped,
	       a->n_saved_inc, a->n_saved_full, a->n_map_events, a->n_resync_events, wr_status_name(ms.last_err));
}

static FILE *open_out(const char *path)
{
	return strcmp(path, "-") == 0 ? stdout : fopen(path, "w");
}

static void close_out(FILE *f)
{
	if (f == stdout)
		fflush(f);
	else if (f != NULL)
		fclose(f);
}

/* Returns 1 to quit. */
static int command(mw_app *a, char *line)
{
	char *tok[8];
	int nt = 0;
	char *p = line;
	uint32_t e = 0;

	while (*p != '\0' && nt < 8) {
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '\0')
			break;
		tok[nt++] = p;
		while (*p != '\0' && *p != ' ' && *p != '\t')
			p++;
		if (*p != '\0')
			*p++ = '\0';
	}
	if (nt == 0)
		return 0;
	if (strcmp(tok[0], "quit") == 0) {
		printf("ok bye\n");
		return 1;
	}
	if (strcmp(tok[0], "info") == 0) {
		print_info(a);
	} else if (strcmp(tok[0], "wait-epoch") == 0 && nt >= 2) {
		unsigned long want = strtoul(tok[1], NULL, 10), secs = nt >= 3 ? strtoul(tok[2], NULL, 10) : 30u;

		if (run_until(a, (uint32_t)want, (uint64_t)secs * 1000u, 0) && held_epoch(a, &e))
			printf("ok epoch=%u\n", (unsigned)e);
		else
			printf("err timeout waiting for epoch %lu (held %u)\n", want, held_epoch(a, &e) ? (unsigned)e : 0u);
	} else if (strcmp(tok[0], "wait-pools") == 0) {
		unsigned long secs = nt >= 2 ? strtoul(tok[1], NULL, 10) : 30u;

		if (run_until(a, 1, (uint64_t)secs * 1000u, 1) && held_epoch(a, &e))
			printf("ok epoch=%u\n", (unsigned)e);
		else
			printf("err timeout waiting for the pools\n");
	} else if (strcmp(tok[0], "pump") == 0 && nt >= 2) {
		(void)run_for(a, strtoul(tok[1], NULL, 10));
		printf("ok epoch=%u\n", held_epoch(a, &e) ? (unsigned)e : 0u);
	} else if (strcmp(tok[0], "track") == 0 && nt >= 2) {
		if (track_pool(a, tok[1]) == 0)
			printf("ok pools=%u\n", a->n_pools);
		else
			printf("err cannot track %s\n", tok[1]);
	} else if (strcmp(tok[0], "drop") == 0 && nt >= 2) {
		a->drop_left = (unsigned)strtoul(tok[1], NULL, 10);
		printf("ok drop=%u\n", a->drop_left);
	} else if ((strcmp(tok[0], "place") == 0 && nt >= 5) || (strcmp(tok[0], "placef") == 0 && nt >= 4) ||
		   (strcmp(tok[0], "pgs") == 0 && nt >= 3)) {
		int pi = pool_index(a, tok[1]);
		FILE *out;
		unsigned rows = 0, unm = 0;
		names ns;
		wr_pool_info pinf;
		int bad = 0;

		if (pi < 0) {
			printf("err pool %s is not tracked\n", tok[1]);
			return 0;
		}
		out = open_out(tok[2]);
		if (out == NULL) {
			printf("err cannot write %s\n", tok[2]);
			return 0;
		}
		if (!held_epoch(a, &e) || !pool_ok(a, (unsigned)pi, &pinf)) {
			close_out(out);
			printf("err no usable map or pool %s absent in epoch %u\n", tok[1], held_epoch(a, &e) ? (unsigned)e : 0u);
			return 0;
		}
		if (strcmp(tok[0], "pgs") == 0) {
			bad = table_pgs(a, out, (unsigned)pi, 0xffffffffu, &rows);
			unm = bad < 0 ? 0u : (unsigned)bad;
		} else if (strcmp(tok[0], "place") == 0) {
			place_prefix(a, out, (unsigned)pi, tok[3], nt >= 6 ? (unsigned)strtoul(tok[5], NULL, 10) : 0u,
				     (unsigned)strtoul(tok[4], NULL, 10), &rows, &unm);
		} else {
			if (names_from_file(&ns, tok[3]) != 0) {
				close_out(out);
				printf("err cannot read %s\n", tok[3]);
				return 0;
			}
			place_names_file(a, out, (unsigned)pi, &ns, &rows, &unm);
			names_free(&ns);
		}
		close_out(out);
		printf("ok epoch=%u rows=%u unmappable=%u\n", (unsigned)e, rows, unm);
	} else {
		printf("err unknown or incomplete command: %s\n", tok[0]);
	}
	return 0;
}

/* Read what is there, run whole lines. Returns 1 when the tool should end. */
static int poll_stdin(mw_app *a, int wait_ms)
{
	struct pollfd pf;
	char *nl;

	if (a->eof)
		return 1;
	pf.fd = 0;
	pf.events = POLLIN;
	pf.revents = 0;
	if (poll(&pf, 1, wait_ms) > 0 && (pf.revents & (POLLIN | POLLHUP)) != 0) {
		/* room left in the buffer, spelled so that no path can make it larger than the buffer */
		size_t room = a->inlen < sizeof(a->inbuf) - 1u ? sizeof(a->inbuf) - 1u - a->inlen : 0u;
		ssize_t n = room > 0u ? read(0, a->inbuf + a->inlen, room) : 0;

		if (n <= 0 && room > 0u)
			a->eof = 1;
		else if (n > 0)
			a->inlen += (size_t)n;
	}
	a->inbuf[a->inlen] = '\0';
	while ((nl = memchr(a->inbuf, '\n', a->inlen)) != NULL) {
		size_t used = (size_t)(nl - a->inbuf) + 1u;
		int quit;

		*nl = '\0';
		quit = command(a, a->inbuf);
		fflush(stdout);
		memmove(a->inbuf, a->inbuf + used, a->inlen - used);
		a->inlen -= used;
		a->inbuf[a->inlen] = '\0';
		if (quit)
			return 1;
	}
	if (a->inlen >= sizeof(a->inbuf) - 1u) {
		printf("err line too long\n");
		a->inlen = 0;
	}
	return a->eof && a->inlen == 0;
}

static void usage(void)
{
	fprintf(stderr, "usage: winrbd-mapwatch --mon <ip[:port]> --user <name> --keyring <file> --pool <name> [--pool <name>]...\n"
			"       [--names <file>] [--prefix S --count N] [--follow <s>] [--stdin] [--trace <file>] [--trace-pgs N]\n"
			"       [--save-maps <dir>] [--log <file>] [--timeout <ms>] [-v]\n");
}

int main(int argc, char **argv)
{
	const char *mon = NULL, *user = NULL, *keyring = NULL, *names_file = NULL, *prefix = NULL, *trace_path = NULL, *log_path = NULL;
	unsigned count = 0, follow_s = 0, level = WR_LOG_WARN, trace_pgs = 1024;
	int timeout_ms = MW_DEFAULT_TIMEOUT_MS, use_stdin = 0, i, rc = 0;
	mw_app a;
	wr_cluster_spec spec;
	wr_config cfg;
	wr_host_ops ops;
	wr_mem_req req;
	wr_mem_region arena, bulk;
	static char kr[MW_KEYRING_MAX];
	size_t krlen = 0, nmon = 0;
	wr_status st;
	wr_map_stats ms;

	memset(&a, 0, sizeof(a));
	memset(&spec, 0, sizeof(spec));
	for (i = 1; i < argc; i++) {
		const char *s = argv[i];
		int has = i + 1 < argc;

		if (strcmp(s, "--mon") == 0 && has)
			mon = argv[++i];
		else if (strcmp(s, "--user") == 0 && has)
			user = argv[++i];
		else if (strcmp(s, "--keyring") == 0 && has)
			keyring = argv[++i];
		else if (strcmp(s, "--pool") == 0 && has) {
			if (a.n_pools >= MW_MAX_POOLS) {
				fprintf(stderr, "winrbd-mapwatch: at most %u pools\n", MW_MAX_POOLS);
				return 2;
			}
			a.pool_name[a.n_pools++] = argv[++i];
		} else if (strcmp(s, "--names") == 0 && has)
			names_file = argv[++i];
		else if (strcmp(s, "--prefix") == 0 && has)
			prefix = argv[++i];
		else if (strcmp(s, "--count") == 0 && has)
			count = (unsigned)strtoul(argv[++i], NULL, 10);
		else if (strcmp(s, "--follow") == 0 && has)
			follow_s = (unsigned)strtoul(argv[++i], NULL, 10);
		else if (strcmp(s, "--timeout") == 0 && has)
			timeout_ms = (int)strtol(argv[++i], NULL, 10);
		else if (strcmp(s, "--trace") == 0 && has)
			trace_path = argv[++i];
		else if (strcmp(s, "--trace-pgs") == 0 && has)
			trace_pgs = (unsigned)strtoul(argv[++i], NULL, 10);
		else if (strcmp(s, "--save-maps") == 0 && has) {
			if (strlen(argv[i + 1]) >= MW_PATH_MAX) {
				fprintf(stderr, "winrbd-mapwatch: --save-maps path too long\n");
				return 2;
			}
			strcpy(a.save_dir, argv[++i]);
		} else if (strcmp(s, "--log") == 0 && has)
			log_path = argv[++i];
		else if (strcmp(s, "--stdin") == 0)
			use_stdin = 1;
		else if (strcmp(s, "-v") == 0)
			level = WR_LOG_DEBUG;
		else {
			usage();
			return 2;
		}
	}
	if (mon == NULL || user == NULL || keyring == NULL || a.n_pools == 0u || timeout_ms <= 0 || (prefix != NULL && count == 0u)) {
		usage();
		return 2;
	}
	if (a.save_dir[0] != '\0' && mkdir(a.save_dir, 0700) != 0 && errno != EEXIST) {
		fprintf(stderr, "winrbd-mapwatch: cannot create %s: %s\n", a.save_dir, strerror(errno));
		return 2;
	}
	if (strlen(user) >= sizeof(spec.user)) {
		fprintf(stderr, "winrbd-mapwatch: user name too long\n");
		return 2;
	}
	strcpy(spec.user, user);
	st = wr_mon_parse_hosts(mon, strlen(mon), spec.mons, WR_MAX_MONS, &nmon);
	if (st != WR_OK) {
		fprintf(stderr, "winrbd-mapwatch: --mon: %s\n", wr_strerror(st));
		return 2;
	}
	spec.n_mons = (uint8_t)nmon;
	st = wrl_read_text_file(keyring, kr, sizeof(kr), &krlen);
	if (st == WR_OK)
		st = wr_key_parse_keyring(&spec.key, kr, krlen);
	wipe(kr, sizeof(kr));
	if (st != WR_OK) {
		fprintf(stderr, "winrbd-mapwatch: keyring %s: %s\n", keyring, wr_strerror(st));
		return 2;
	}
	if (log_path != NULL && (a.log = fopen(log_path, "w")) == NULL) {
		fprintf(stderr, "winrbd-mapwatch: cannot write %s\n", log_path);
		wr_key_wipe(&spec.key);
		return 2;
	}
	if (trace_path != NULL && (a.trace = fopen(trace_path, "w")) == NULL) {
		fprintf(stderr, "winrbd-mapwatch: cannot write %s\n", trace_path);
		wr_key_wipe(&spec.key);
		return 2;
	}
	a.trace_pgs = trace_pgs;

	wr_config_profile_harness(&cfg);
	wr_config_enable_maps(&cfg, WR_MAPS_HARNESS);
	wrl_host_ops_init(&ops, &level);
	st = wr_client_mem_required(&cfg, &req);
	if (st == WR_OK)
		st = wrl_mem_alloc(&arena, req.arena);
	if (st == WR_OK) {
		st = wrl_mem_alloc(&bulk, req.bulk);
		if (st != WR_OK)
			wrl_mem_free(&arena);
	}
	if (st == WR_OK) {
		st = wr_client_create(&cfg, &ops, &spec, arena, bulk, &a.c);
		if (st != WR_OK) {
			wrl_mem_free(&arena);
			wrl_mem_free(&bulk);
		}
	}
	wr_key_wipe(&spec.key);
	if (st != WR_OK) {
		fprintf(stderr, "winrbd-mapwatch: cannot create the client: %s\n", wr_strerror(st));
		return 2;
	}
	/* the pool names given on the command line are tracked now (before the first map: the first full map keeps their records) */
	{
		const char *given[MW_MAX_POOLS];
		unsigned n = a.n_pools;

		memcpy(given, a.pool_name, sizeof(given));
		a.n_pools = 0;
		for (i = 0; (unsigned)i < n; i++)
			if (track_pool(&a, given[i]) != 0) {
				fprintf(stderr, "winrbd-mapwatch: cannot track pool %s\n", given[i]);
				wr_client_destroy(a.c);
				wrl_mem_free(&arena);
				wrl_mem_free(&bulk);
				return 2;
			}
	}
	st = wrl_loop_create(a.c, &a.loop);
	if (st != WR_OK) {
		fprintf(stderr, "winrbd-mapwatch: cannot create the loop: %s\n", wr_strerror(st));
		wr_client_destroy(a.c);
		wrl_mem_free(&arena);
		wrl_mem_free(&bulk);
		return 2;
	}
	/* the hook: save, trace and fault injection see every message between the monitor client and the store */
	g_app = &a;
	a.real_peek = a.c->map_io.peek;
	a.real_release = a.c->map_io.release;
	a.c->map_io.peek = hook_peek;
	a.c->map_io.release = hook_release;
	a.t0 = now_ms();
	logf_(&a, "start mon=%s user=%s pools=%u", mon, user, a.n_pools);

	if (!run_until(&a, 1, (uint64_t)timeout_ms, names_file != NULL || prefix != NULL)) {
		const wr_errinfo *e = wr_client_last_error(a.c);

		if (a.n_auth_failed != 0u) {
			fprintf(stderr, "winrbd-mapwatch: authentication refused: %s\n", wr_status_name(a.first_err.status));
			rc = 5;
		} else if (a.n_fatal != 0u || wr_client_get_state(a.c) == WR_CS_FAILED) {
			fprintf(stderr, "winrbd-mapwatch: the client failed: %s\n", wr_status_name(a.first_err.status));
			rc = 3;
		} else {
			fprintf(stderr, "winrbd-mapwatch: no usable map within %d ms (last error %s)\n", timeout_ms, wr_status_name(e->status));
			rc = 1;
		}
		goto done;
	}
	if (a.trace != NULL)
		trace_epoch(&a);
	if (names_file != NULL || prefix != NULL) {
		uint64_t until = now_ms() + (uint64_t)follow_s * 1000u;
		uint32_t last = 0;
		names ns;
		int have_names = 0;

		if (names_file != NULL) {
			if (names_from_file(&ns, names_file) != 0) {
				fprintf(stderr, "winrbd-mapwatch: cannot read %s\n", names_file);
				rc = 2;
				goto done;
			}
			have_names = 1;
		}
		do {
			uint32_t e = 0;

			if (held_epoch(&a, &e) && e != last && all_pools_ok(&a)) {
				unsigned pi, rows, unm;

				last = e;
				for (pi = 0; pi < a.n_pools; pi++) {
					if (have_names)
						place_names_file(&a, stdout, pi, &ns, &rows, &unm);
					if (prefix != NULL)
						place_prefix(&a, stdout, pi, prefix, 0, count, &rows, &unm);
				}
				fflush(stdout);
			}
			if (follow_s == 0u || pump(&a, 50))
				break;
		} while (now_ms() < until);
		if (have_names)
			names_free(&ns);
	}
	if (use_stdin) {
		while (!poll_stdin(&a, 0)) {
			if (pump(&a, 20)) {
				printf("err the client failed\n");
				rc = a.n_auth_failed != 0u ? 5 : 3;
				break;
			}
		}
	}
done:
	drain_events(&a);
	wr_client_map_stats(a.c, &ms);
	if (rc == 0 && ms.n_bad > ms.n_resync) {
		fprintf(stderr, "winrbd-mapwatch: %u map entries failed, %u re-requests\n", (unsigned)ms.n_bad, (unsigned)ms.n_resync);
		rc = 4;
	}
	fprintf(stderr,
		"winrbd-mapwatch: held epoch %u, newest seen %u, %u full maps, %u incrementals, %u re-requests, %u skipped, %u bad, %u "
		"dropped by the hook, exit %d\n",
		(unsigned)ms.epoch, (unsigned)ms.newest_seen, (unsigned)ms.n_full, (unsigned)ms.n_inc, (unsigned)ms.n_resync, (unsigned)ms.n_skipped,
		(unsigned)ms.n_bad, a.n_dropped, rc);
	if (a.log != NULL)
		fclose(a.log);
	if (a.trace != NULL)
		fclose(a.trace);
	g_app = NULL;
	wrl_loop_destroy(a.loop);
	wr_client_destroy(a.c);
	wrl_mem_free(&arena);
	wrl_mem_free(&bulk);
	for (i = 0; (unsigned)i < a.n_pools; i++)
		free((void *)a.pool_name[i]);
	return rc;
}
