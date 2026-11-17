/* SPDX-License-Identifier: MIT */
/*
 * mapstore_rig.h - shared by test_mapstore_epoch.c, test_mapstore_mem.c and fuzz_mapstore.c: a scripted fake of the
 * world a map store sees (wri_map_io) and a fixture that owns the store, its memory and the clock.
 *
 * The fake source keeps a queue of messages. Each front is an exact-size heap copy that is FREED when the store releases the
 * message, so a store that kept a pointer into a front past its release is an ASan report, and a store that releases
 * early or twice is a counter or an assertion. It records every request for a full map (the `start` it passed) and every
 * event (kind, epoch, the status and text of the errinfo), so a test can say what happened in what order.
 */
#ifndef MAPSTORE_RIG_H
#define MAPSTORE_RIG_H

#include "wrt.h"
#include "wrt_mapgen.h"
#include "wri_ctx.h"
#include "wri_mapstore.h"
#include "wri_osdmap_dec.h"

#define MS_Q 16u
#define MS_LOG 512u

typedef struct ms_msg {
	wr_mapmsg_kind kind;
	uint16_t version;
	uint32_t newest;
	uint8_t *front;
	size_t len;
} ms_msg;

typedef struct ms_evrec_s {
	wr_ev_kind kind;
	uint32_t epoch;
	wr_status status; /* of the errinfo, WR_OK when none was given */
	const char *what;
	int has_err;
} ms_evrec;

typedef struct ms_src {
	ms_msg q[MS_Q];
	unsigned head, tail;
	unsigned n_peek, n_release, n_want, n_ev;
	uint32_t want_start[MS_LOG];
	ms_evrec ev[MS_LOG];
	unsigned n_kind[16];       /* events by kind */
	unsigned releases_at_peek; /* n_release as of the last successful peek (for "released only after its last entry") */
	int double_release;
} ms_src;

static int ms_peek(void *ctx, wr_mapmsg *out)
{
	ms_src *s = (ms_src *)ctx;
	const ms_msg *m;

	s->n_peek++;
	if (s->head == s->tail)
		return 0;
	m = &s->q[s->head % MS_Q];
	memset(out, 0, sizeof(*out));
	out->kind = m->kind;
	out->msg_version = m->version;
	out->msg_compat = 1;
	out->newest_epoch = m->newest;
	out->front = m->front;
	out->front_len = m->len;
	s->releases_at_peek = s->n_release;
	return 1;
}

static void ms_release(void *ctx)
{
	ms_src *s = (ms_src *)ctx;

	if (s->head == s->tail) {
		s->double_release = 1; /* released with nothing held */
		return;
	}
	free(s->q[s->head % MS_Q].front);
	s->q[s->head % MS_Q].front = NULL;
	s->head++;
	s->n_release++;
}

static void ms_want(void *ctx, uint32_t start)
{
	ms_src *s = (ms_src *)ctx;

	if (s->n_want < MS_LOG)
		s->want_start[s->n_want] = start;
	s->n_want++;
}

static void ms_event(void *ctx, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *err)
{
	ms_src *s = (ms_src *)ctx;

	if (s->n_ev < MS_LOG) {
		ms_evrec *e = &s->ev[s->n_ev];

		e->kind = kind;
		e->epoch = epoch;
		e->has_err = err != NULL;
		e->status = err != NULL ? err->status : WR_OK;
		e->what = err != NULL ? err->what : NULL;
	}
	s->n_ev++;
	if ((unsigned)kind < 16u)
		s->n_kind[kind]++;
}

/* Queue a message (the front is copied). */
WRT_UNUSED static void ms_post(ms_src *s, wr_mapmsg_kind kind, uint16_t version, uint32_t newest, const uint8_t *front, size_t len)
{
	ms_msg *m;

	if (s->tail - s->head >= MS_Q) {
		fprintf(stderr, "ms_post: queue full\n");
		exit(2);
	}
	m = &s->q[s->tail % MS_Q];
	m->kind = kind;
	m->version = version;
	m->newest = newest;
	m->front = (uint8_t *)malloc(len == 0 ? 1 : len);
	if (m->front == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	if (len != 0)
		memcpy(m->front, front, len);
	m->len = len;
	s->tail++;
}

WRT_UNUSED static unsigned ms_pending(const ms_src *s) { return s->tail - s->head; }

/* Free what is still queued. */
WRT_UNUSED static void ms_src_free(ms_src *s)
{
	while (s->head != s->tail) {
		free(s->q[s->head % MS_Q].front);
		s->q[s->head % MS_Q].front = NULL;
		s->head++;
	}
}

/* ---- the fixture ---------------------------------------------------------------------------------------- */

typedef struct ms_fix {
	ms_src src;
	wri_ctx x;
	wri_mapstore s;
	wri_map_io io;
	wr_config cfg;
	void *amem, *bmem;
	size_t abytes, bbytes;
	wri_arena arena, bulk;
	wr_status init_st;
} ms_fix;

/* The configuration the tests use: harness profile, maps on, small enough to be quick, CRC checking on. */
WRT_UNUSED static void ms_cfg(wr_config *cfg)
{
	wr_config_profile_harness(cfg);
	wr_config_enable_maps(cfg, WR_MAPS_HARNESS);
	cfg->map_slot_bytes = 1024u * 1024u;
	cfg->map_max_osd = 4096;
	cfg->map_pools = 8;
	cfg->map_pg_cache = 64;
	cfg->map_refetch_ms = 1000;
	cfg->map_verify_crc = 1;
}

/* Allocate the regions the store needs for `cfg` (with the 16-byte base slack) and run init. */
WRT_UNUSED static void ms_open(ms_fix *f, const wr_config *cfg)
{
	size_t ab = 0, bb = 0;

	memset(f, 0, sizeof(*f));
	f->cfg = *cfg;
	f->io.ctx = &f->src;
	f->io.peek = ms_peek;
	f->io.release = ms_release;
	f->io.want_osdmap = ms_want;
	f->io.event = ms_event;
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_mem(cfg, &ab, &bb));
	f->abytes = ab + WRI_ARENA_SLACK + 64u;
	f->bbytes = bb + WRI_ARENA_SLACK + 64u;
	f->amem = calloc(1, f->abytes);
	f->bmem = calloc(1, f->bbytes);
	if (f->amem == NULL || f->bmem == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	wri_arena_init(&f->arena, f->amem, f->abytes);
	wri_arena_init(&f->bulk, f->bmem, f->bbytes);
	f->init_st = wri_mapstore_init(&f->s, cfg, &f->arena, &f->bulk);
	WRT_CHECK_STATUS(WR_OK, f->init_st);
}

WRT_UNUSED static void ms_close(ms_fix *f)
{
	ms_src_free(&f->src);
	free(f->amem);
	free(f->bmem);
	f->amem = f->bmem = NULL;
}

/* Track a pool by name, checking the handle. */
WRT_UNUSED static void ms_track(ms_fix *f, const char *name, uint32_t want_handle)
{
	uint32_t h = 99;

	WRT_CHECK_STATUS(WR_OK, wri_mapstore_track(&f->s, (const uint8_t *)name, strlen(name), &h));
	WRT_CHECK_U64(h, want_handle);
}

/* One step at time `now` with a generous budget; the answer of wri_mapstore_step. */
WRT_UNUSED static int ms_step(ms_fix *f, uint64_t now)
{
	uint32_t budget = 0x40000000u;

	f->x.now.mono_ms = now;
	return wri_mapstore_step(&f->x, &f->s, &f->io, &budget);
}

/* The bytes of the held map (a copy, for "the held map is what it was"). */
WRT_UNUSED static uint8_t *ms_held_copy(const ms_fix *f, size_t *n)
{
	const wri_osdmap *m = wri_mapstore_map(&f->s);
	uint8_t *c;

	*n = 0;
	if (m == NULL)
		return NULL;
	c = (uint8_t *)malloc(m->bytes);
	if (c == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	memcpy(c, m, m->bytes);
	*n = m->bytes;
	return c;
}

/* ---- MOSDMap fronts ------------------------------------------------------------------------------------- */

typedef struct ms_item {
	int is_full;
	uint32_t epoch;
	const uint8_t *p;
	size_t n;
} ms_item;

/* A message of header version 4 carrying the items (the lists keep the order given), and queue it. */
WRT_UNUSED static void ms_post_items(ms_src *src, const uint8_t fsid[16], const ms_item *it, uint32_t n, uint32_t newest)
{
	wrt_mg_mitem *mi = (wrt_mg_mitem *)calloc(n == 0 ? 1 : n, sizeof(*mi));
	wrt_mg_buf b;
	uint32_t i;

	if (mi == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	for (i = 0; i < n; i++) {
		mi[i].is_full = it[i].is_full;
		mi[i].epoch = it[i].epoch;
		mi[i].p = it[i].p;
		mi[i].n = it[i].n;
	}
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_mosdmap_front(&b, fsid, mi, n, 1, newest, 4, 0) == 0);
	ms_post(src, WR_MAPMSG_OSDMAP, 4, newest, b.p, b.len);
	wrt_mg_buf_free(&b);
	free(mi);
}

/* ---- the lab chain: full-e42 and the 89 incrementals, plus the model that replays them ------------------- */

#define MS_LAB_EPOCHS 89u

typedef struct ms_lab {
	uint8_t *full42;
	size_t full42_n;
	wrt_mg_line *lines; /* lines[e - 1] is the incremental of epoch e */
	size_t nlines;
	uint8_t fsid[16];
} ms_lab;

WRT_UNUSED static int ms_lab_load(ms_lab *l)
{
	memset(l, 0, sizeof(*l));
	if (wrt_mg_load_hex_file(wrt_vec_path("osdmap/full-e42.hex"), &l->full42, &l->full42_n) != 0)
		return -1;
	if (wrt_mg_load_epoch_lines(wrt_vec_path("osdmap/incrementals.hex"), &l->lines, &l->nlines) != 0)
		return -1;
	if (l->nlines != MS_LAB_EPOCHS || l->full42_n < 32u)
		return -1;
	{
		wri_map_blob_info info;

		if (wri_osdmap_full_info(l->full42, l->full42_n, &info, NULL) != WR_OK)
			return -1;
		memcpy(l->fsid, info.fsid, 16);
	}
	return 0;
}

WRT_UNUSED static void ms_lab_free(ms_lab *l)
{
	free(l->full42);
	wrt_mg_free_lines(l->lines, l->nlines);
	l->full42 = NULL;
	l->lines = NULL;
}

#endif /* MAPSTORE_RIG_H */
