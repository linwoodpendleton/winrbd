/* SPDX-License-Identifier: MIT */
/*
 * test_mapstore_epoch.c - the map store following the cluster (core/src/osdmap/wri_mapstore.c, wri_mapstore_msg.c;
 * docs/design/core-architecture.md 15.5). A scripted fake source (mapstore_rig.h) plays the monitor client's side of
 * wri_map_io; the messages are built by the wrt_mapgen writer and by the real lab chain (full-e42.hex and the 89 stored
 * incrementals of harness/vectors/osdmap), and the wrt_mapgen model replays the same incrementals as the second opinion.
 *
 *   full map, then incrementals; one message of 41 epochs with interleaved lists and a same-epoch tie; one epoch per step,
 *   more_work and the budget; WR_EV_MAP once per step; a message released only after its last entry; a gap: one request
 *   with start 0, none while rate-limited, the next after the back-off, doubling to 32 s, reset by a success; another
 *   fsid dropped and counted; a decode, label, CRC or apply failure keeps the held map byte for byte and asks for a full
 *   map; the budget and version failures are fatal for the first map only; transient first-map failures retry; an
 *   incremental with no map; MMonMap released unread; a pool tracked after a map (also on a quiet cluster, where the answer
 *   is a full map of the held epoch); an empty entry blob; queries before the first map, with an
 *   absent, an unsupported and an unmappable pool; the 219 object names of the epoch-42 oracle placed through the store.
 */
#include "mapstore_rig.h"

static ms_lab lab;
static wrt_mg_map models[MS_LAB_EPOCHS + 1u]; /* models[e]: the state after epoch e (models[0]: before epoch 1) */
static wrt_mg_buf enc[MS_LAB_EPOCHS + 1u];   /* enc[e]: models[e] written as a full map */

/* ---- set-up ---------------------------------------------------------------------------------------------- */

static void setup_lab(void)
{
	uint32_t e;

	WRT_CHECK(ms_lab_load(&lab) == 0);
	wrt_mg_model_init(&models[0]);
	for (e = 1; e <= MS_LAB_EPOCHS; e++) {
		wrt_mg_inc inc;

		WRT_CHECK_U64(lab.lines[e - 1].epoch, e);
		WRT_CHECK(wrt_mg_inc_parse(lab.lines[e - 1].p, lab.lines[e - 1].n, &inc) == 0);
		WRT_CHECK(wrt_mg_map_clone(&models[e - 1], &models[e]) == 0);
		WRT_CHECK_STATUS(WRT_MG_E_OK, wrt_mg_model_apply(&models[e], &inc));
		wrt_mg_inc_free(&inc);
		WRT_CHECK(wrt_mg_map_encode(&models[e], &enc[e]) == 0);
	}
}

static ms_fix *new_fix_cfg(const wr_config *cfg, int track)
{
	ms_fix *f = (ms_fix *)calloc(1, sizeof(*f));

	if (f == NULL)
		exit(2);
	ms_open(f, cfg);
	if (track) {
		ms_track(f, ".mgr", 0); /* pool 1 of the lab */
		ms_track(f, "winrbd", 1); /* pool 2 */
	}
	return f;
}

static ms_fix *new_fix(void)
{
	wr_config cfg;

	ms_cfg(&cfg);
	return new_fix_cfg(&cfg, 1);
}

static void del_fix(ms_fix *f)
{
	WRT_CHECK(!f->src.double_release);
	WRT_CHECK_U64(ms_pending(&f->src), 0); /* a test leaves no message behind */
	ms_close(f);
	free(f);
}

static void post_one(ms_fix *f, int is_full, uint32_t epoch, const uint8_t *p, size_t n)
{
	ms_item it;

	it.is_full = is_full;
	it.epoch = epoch;
	it.p = p;
	it.n = n;
	ms_post_items(&f->src, lab.fsid, &it, 1, epoch);
}

static void post_inc(ms_fix *f, uint32_t e) { post_one(f, 0, e, lab.lines[e - 1].p, lab.lines[e - 1].n); }
static void post_model_full(ms_fix *f, uint32_t e) { post_one(f, 1, e, enc[e].p, enc[e].len); }

/* The real map of epoch 42 as the first map. */
static void adopt42(ms_fix *f, uint64_t now)
{
	post_one(f, 1, 42, lab.full42, lab.full42_n);
	WRT_CHECK_U64(ms_step(f, now), 0);
	WRT_CHECK_U64(f->s.epoch, 42);
}

/* The held map against the model: epoch, size, and every OSD's state, weight and affinity. */
static void check_state(const ms_fix *f, uint32_t e)
{
	const wri_osdmap *m = wri_mapstore_map(&f->s);
	const wrt_mg_map *d = &models[e];
	int32_t i;

	WRT_CHECK(m != NULL);
	if (m == NULL)
		return;
	WRT_CHECK_U64(m->epoch, e);
	WRT_CHECK_U64(m->max_osd, (uint32_t)d->max_osd);
	for (i = 0; i < d->max_osd && (uint32_t)i < m->max_osd; i++) {
		WRT_CHECK((wri_osd_exists(m, i) != 0) == (wrt_mg_exists(d, i) != 0));
		WRT_CHECK((wri_osd_up(m, i) != 0) == (wrt_mg_is_up(d, i) != 0));
		WRT_CHECK_U64(wri_osd_weight(m, i), wrt_mg_weight(d, i));
		WRT_CHECK_U64(wri_osd_aff(m, i), wrt_mg_affinity(d, i));
	}
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(m));
}

static unsigned count_events(const ms_src *s, wr_ev_kind k) { return s->n_kind[k]; }

/* ---- the first map and the queries ----------------------------------------------------------------------------- */

static void t_full_map(void)
{
	ms_fix *f = new_fix();
	const wri_map_pool *p = NULL;
	wr_map_stats st;
	wr_target t;
	wri_oid oid;
	size_t flen;

	fprintf(stderr, "full map\n");
	/* before any map */
	WRT_CHECK(wri_mapstore_map(&f->s) == NULL);
	WRT_CHECK_STATUS(WR_E_MAP_NONE, wri_mapstore_pool(&f->s, 0, &p));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_pool(&f->s, 2, &p)); /* only two names are tracked */
	WRT_CHECK(p == NULL);
	memset(&oid, 0, sizeof(oid));
	oid.name = (const uint8_t *)"rbd_data.1.0";
	oid.name_len = 12;
	WRT_CHECK_STATUS(WR_E_MAP_NONE, wri_mapstore_target(&f->s, 0, &oid, &t));
	WRT_CHECK(t.up_primary == -1 && t.acting_primary == -1 && t.n_acting == 0 && t.epoch == 0);
	WRT_CHECK_STATUS(WR_E_MAP_NONE, wri_mapstore_target_pg(&f->s, 1, 3, &t));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_target_pg(&f->s, 9, 3, &t));
	WRT_CHECK_U64(wri_mapstore_deadline(&f->s), WR_DEADLINE_NONE);
	wri_mapstore_stats(&f->s, &st);
	WRT_CHECK(st.epoch == 0 && st.n_full == 0 && st.slot_used == 0 && st.slot_bytes == f->cfg.map_slot_bytes);
	WRT_CHECK_U64(ms_step(f, 0), 0); /* no message: nothing to do */
	WRT_CHECK_U64(f->src.n_ev, 0);

	post_one(f, 1, 42, lab.full42, lab.full42_n);
	flen = f->src.q[f->src.head % MS_Q].len;
	WRT_CHECK_U64(ms_step(f, 5), 0);
	WRT_CHECK_U64(f->s.epoch, 42);
	WRT_CHECK_U64(f->src.n_release, 1);
	WRT_CHECK_U64(f->src.n_want, 0);
	WRT_CHECK_U64(f->src.n_ev, 1);
	WRT_CHECK(f->src.ev[0].kind == WR_EV_MAP && f->src.ev[0].epoch == 42 && !f->src.ev[0].has_err);
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_pool(&f->s, 0, &p));
	WRT_CHECK(p != NULL && p->id == 1 && p->present && p->status == WR_OK);
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_pool(&f->s, 1, &p));
	WRT_CHECK(p != NULL && p->id == 2 && p->pg_num == 32 && p->size == 3);
	wri_mapstore_stats(&f->s, &st);
	WRT_CHECK_U64(st.epoch, 42);
	WRT_CHECK_U64(st.newest_seen, 42);
	WRT_CHECK(st.n_full == 1 && st.n_inc == 0 && st.n_bad == 0 && st.n_resync == 0 && st.n_skipped == 0 && st.n_fsid_drop == 0);
	WRT_CHECK(st.slot_used > 0 && st.slot_used == st.slot_used_max && st.slot_used < st.slot_bytes);
	WRT_CHECK_U64(st.msg_bytes_max, flen);
	WRT_CHECK_U64(st.last_err, WR_OK);
	WRT_CHECK_U64(wri_mapstore_deadline(&f->s), WR_DEADLINE_NONE);
	WRT_CHECK(wri_mapstore_map(&f->s) == (const wri_osdmap *)(const void *)f->s.slot[f->s.cur]);
	del_fix(f);
}

/* ---- the 219 names of the epoch-42 oracle through the store ------------------------------------------------------ */

static int64_t jint(const wrt_json *j, wrt_tok t)
{
	int ok = 0;
	int64_t v = wrt_json_int(j, t, &ok);

	WRT_CHECK(ok);
	return v;
}

static int jlist_eq(const wrt_json *j, wrt_tok arr, const int32_t *got, uint32_t n)
{
	size_t i;

	if (wrt_json_count(j, arr) != n)
		return 0;
	for (i = 0; i < n; i++)
		if (jint(j, wrt_json_at(j, arr, i)) != (int64_t)got[i])
			return 0;
	return 1;
}

/* One pass over the oracle; returns how many names were compared. With `again` the answers must equal the previous pass. */
static unsigned names_pass(ms_fix *f, const wrt_json *j, wrt_tok entries, wr_target *keep, int again)
{
	size_t i, n = wrt_json_count(j, entries);
	unsigned compared = 0;

	for (i = 0; i < n; i++) {
		wrt_tok row = wrt_json_at(j, entries, i);
		int64_t pool_id = jint(j, wrt_json_at(j, row, 0));
		uint8_t *name = NULL, *ns = NULL;
		size_t nn = 0, nsn = 0;
		wri_oid oid;
		wr_target t, t2;
		wr_status st;
		char want_pg[48];
		char *pgid;
		uint32_t h = pool_id == 1 ? 0u : 1u;

		WRT_CHECK(pool_id == 1 || pool_id == 2);
		WRT_CHECK(wrt_json_hex(j, wrt_json_at(j, row, 1), &name, &nn) == 0);
		WRT_CHECK(wrt_json_hex(j, wrt_json_at(j, row, 2), &ns, &nsn) == 0);
		memset(&oid, 0, sizeof(oid));
		oid.name = name;
		oid.name_len = (uint32_t)nn;
		oid.nspace = ns;
		oid.nspace_len = (uint32_t)nsn;
		st = wri_mapstore_target(&f->s, h, &oid, &t);
		if (nn + nsn > WRI_PLACE_NAME_MAX) {
			WRT_CHECK_STATUS(WR_E_TOOBIG, st);
			WRT_CHECK(t.n_acting == 0 && t.acting_primary == -1); /* a failure leaves the target cleared */
			free(name);
			free(ns);
			continue;
		}
		WRT_CHECK_STATUS(WR_OK, st);
		if (st == WR_OK) {
			const wri_osdmap *m = wri_mapstore_map(&f->s);
			const wri_osd_addr *a = &wri_map_addr(m)[t.acting_primary];

			compared++;
			WRT_CHECK_U64(t.epoch, 42);
			WRT_CHECK_U64((uint64_t)t.pool_id, (uint64_t)pool_id);
			WRT_CHECK_U64(t.ps, (uint64_t)jint(j, wrt_json_at(j, row, 3)));
			pgid = wrt_json_strdup(j, wrt_json_at(j, row, 4));
			snprintf(want_pg, sizeof(want_pg), "%u.%x", (unsigned)pool_id, (unsigned)t.pg_seed);
			WRT_CHECK(pgid != NULL && strcmp(pgid, want_pg) == 0);
			free(pgid);
			WRT_CHECK(jlist_eq(j, wrt_json_at(j, row, 5), t.up, t.n_up));
			WRT_CHECK_U64((uint32_t)t.up_primary, (uint32_t)jint(j, wrt_json_at(j, row, 6)));
			WRT_CHECK(jlist_eq(j, wrt_json_at(j, row, 7), t.acting, t.n_acting));
			WRT_CHECK_U64((uint32_t)t.acting_primary, (uint32_t)jint(j, wrt_json_at(j, row, 8)));
			/* the address of the acting primary is the map's own first msgr2 address */
			WRT_CHECK(a->family == WR_AF_IPV4 && t.primary_addr.family == WR_AF_IPV4);
			WRT_CHECK_U64(t.primary_addr.port, a->port);
			WRT_CHECK_U64(t.primary_addr.nonce, a->nonce);
			WRT_CHECK(memcmp(t.primary_addr.ip, a->ip, 16) == 0);
			WRT_CHECK(t.primary_addr.ip[0] == 10 && t.primary_addr.ip[1] == 77);
			/* by PG: the same answer, with ps = the seed */
			WRT_CHECK_STATUS(WR_OK, wri_mapstore_target_pg(&f->s, h, t.pg_seed, &t2));
			WRT_CHECK_U64(t2.ps, t.pg_seed);
			t2.ps = t.ps;
			WRT_CHECK(memcmp(&t, &t2, sizeof(t)) == 0);
			if (again)
				WRT_CHECK(memcmp(&t, &keep[i], sizeof(t)) == 0);
			else
				keep[i] = t;
		}
		free(name);
		free(ns);
	}
	return compared;
}

static void t_names(void)
{
	ms_fix *f = new_fix();
	wrt_json names;
	wrt_tok entries;
	wr_target *keep;
	unsigned c1, c2;
	wr_map_stats s1, s2;

	fprintf(stderr, "219 names through the store\n");
	WRT_CHECK(wrt_json_load_vec(&names, "osdmap/placement-names-e42.json") == 0);
	entries = wrt_json_get(&names, wrt_json_root(&names), "entries");
	WRT_CHECK_U64(wrt_json_count(&names, entries), 219);
	keep = (wr_target *)calloc(wrt_json_count(&names, entries), sizeof(*keep));
	adopt42(f, 0);
	c1 = names_pass(f, &names, entries, keep, 0);
	wri_mapstore_stats(&f->s, &s1);
	c2 = names_pass(f, &names, entries, keep, 1);
	wri_mapstore_stats(&f->s, &s2);
	WRT_CHECK(c1 >= 217 && c1 == c2); /* all but the over-long names the placement code refuses */
	WRT_CHECK(s2.cache_hits > s1.cache_hits); /* the second pass is answered from the cache */
	wrt_json_free(&names);
	free(keep);
	del_fix(f);
}

/* ---- epochs ------------------------------------------------------------------------------------------------- */

static void t_chain(void)
{
	ms_fix *f = new_fix();
	ms_item it[16];
	uint32_t e, k;
	unsigned n = 0;
	wr_map_stats st;

	fprintf(stderr, "full map then incrementals, one epoch per step\n");
	it[n++] = (ms_item){1, 42, lab.full42, lab.full42_n};
	for (e = 43; e <= 50; e++)
		it[n++] = (ms_item){0, e, lab.lines[e - 1].p, lab.lines[e - 1].n};
	ms_post_items(&f->src, lab.fsid, it, n, 50);
	for (k = 1; k <= 9; k++) {
		int more = ms_step(f, 100u * k);

		WRT_CHECK_U64(more, k < 9);
		WRT_CHECK_U64(f->s.epoch, 41u + k);
		WRT_CHECK_U64(f->src.n_release, k == 9 ? 1u : 0u); /* the message stays held until its last entry */
		WRT_CHECK_U64(count_events(&f->src, WR_EV_MAP), k); /* one WR_EV_MAP per step, the newest epoch */
		WRT_CHECK_U64(f->src.ev[k - 1].epoch, 41u + k);
		check_state(f, 41u + k);
	}
	WRT_CHECK_U64(f->src.n_ev, 9);
	wri_mapstore_stats(&f->s, &st);
	WRT_CHECK(st.n_full == 1 && st.n_inc == 8 && st.n_bad == 0 && st.n_skipped == 0 && st.newest_seen == 50);
	WRT_CHECK_U64(ms_step(f, 2000), 0); /* nothing left */
	del_fix(f);
}

static void t_interleaved(void)
{
	ms_fix *f = new_fix();
	ms_item it[96];
	uint32_t e, k, steps = 0;
	unsigned n = 0;
	wr_map_stats st;

	fprintf(stderr, "one message of 41 epochs, interleaved lists, a tie, a stale entry\n");
	/* full maps at 42 (the real one), 50, 60 and 70; incrementals for everything else up to 82, and one for 42 as well:
	 * the same epoch in both lists (the full map goes first and the incremental is stepped over) */
	it[n++] = (ms_item){0, 42, lab.lines[41].p, lab.lines[41].n};
	for (e = 43; e <= 82; e++) {
		if (e == 50 || e == 60 || e == 70)
			continue;
		it[n++] = (ms_item){0, e, lab.lines[e - 1].p, lab.lines[e - 1].n};
	}
	it[n++] = (ms_item){1, 42, lab.full42, lab.full42_n};
	it[n++] = (ms_item){1, 50, enc[50].p, enc[50].len};
	it[n++] = (ms_item){1, 60, enc[60].p, enc[60].len};
	it[n++] = (ms_item){1, 70, enc[70].p, enc[70].len};
	ms_post_items(&f->src, lab.fsid, it, n, 82);
	for (k = 1; k <= 41; k++) {
		int more = ms_step(f, k);

		steps++;
		WRT_CHECK_U64(more, k < 41);
		WRT_CHECK_U64(f->s.epoch, 41u + k);
		WRT_CHECK_U64(f->src.n_release, k == 41 ? 1u : 0u);
		WRT_CHECK_U64(f->src.n_ev, k);
		WRT_CHECK_U64(f->src.ev[k - 1].epoch, 41u + k);
	}
	check_state(f, 82);
	wri_mapstore_stats(&f->s, &st);
	WRT_CHECK_U64(st.n_full, 4);
	WRT_CHECK_U64(st.n_inc, 37);
	WRT_CHECK_U64(st.n_skipped, 1);
	WRT_CHECK_U64(st.n_bad, 0);
	WRT_CHECK_U64(steps, 41);
	WRT_CHECK_U64(f->src.n_want, 0);
	del_fix(f);
}

static void t_budget_and_more(void)
{
	ms_fix *f = new_fix();
	uint32_t budget;

	fprintf(stderr, "budget, more_work\n");
	adopt42(f, 0);
	post_inc(f, 43);
	post_inc(f, 44); /* two messages: more is 1 after the first even though it is finished */
	budget = 0;
	f->x.now.mono_ms = 1;
	WRT_CHECK_U64(wri_mapstore_step(&f->x, &f->s, &f->io, &budget), 1); /* no budget, work waiting: run again */
	WRT_CHECK_U64(budget, 0);
	WRT_CHECK_U64(f->s.epoch, 42);
	WRT_CHECK_U64(f->src.n_release, 1); /* only the first message (the full map) was ever released */
	budget = 3; /* less than one entry: an epoch is the unit of work, the budget just runs out */
	WRT_CHECK_U64(wri_mapstore_step(&f->x, &f->s, &f->io, &budget), 1);
	WRT_CHECK_U64(f->s.epoch, 43);
	WRT_CHECK_U64(budget, 0);
	WRT_CHECK_U64(f->src.n_release, 2);
	budget = 1000000u;
	WRT_CHECK_U64(wri_mapstore_step(&f->x, &f->s, &f->io, &budget), 0);
	WRT_CHECK_U64(f->s.epoch, 44);
	WRT_CHECK_U64(budget, 1000000u - (uint32_t)lab.lines[43].n - 8u); /* the blob and the entry's epoch and length */
	WRT_CHECK_U64(f->src.n_release, 3);
	del_fix(f);
}

/* ---- gap, back-off, recovery ---------------------------------------------------------------------------------- */

static void t_gap_backoff(void)
{
	ms_fix *f = new_fix();
	size_t hn;
	uint8_t *held;
	uint64_t next_ok = 0;
	unsigned i;
	static const uint64_t spacing[] = {1000, 2000, 4000, 8000, 16000, 32000, 32000, 32000};

	fprintf(stderr, "a gap: request, rate limit, back-off, reset\n");
	adopt42(f, 0);
	held = ms_held_copy(f, &hn);
	for (i = 0; i < 8; i++) {
		unsigned want = i + 1;

		post_inc(f, 60 + i); /* never the next epoch: a gap */
		if (i == 0) {
			WRT_CHECK_U64(ms_step(f, 0), 0);
		} else {
			WRT_CHECK_U64(ms_step(f, next_ok - 1), 0);
			WRT_CHECK_U64(f->src.n_want, i); /* rate limited: the request waits */
			WRT_CHECK(f->s.want_full == 1);
			WRT_CHECK_U64(wri_mapstore_deadline(&f->s), next_ok);
			WRT_CHECK_U64(ms_step(f, next_ok - 1), 0); /* nothing new, still waiting */
			WRT_CHECK_U64(f->src.n_want, i);
			WRT_CHECK_U64(ms_step(f, next_ok), 0);
		}
		WRT_CHECK_U64(f->src.n_want, want);
		WRT_CHECK_U64(f->src.want_start[i], 0); /* always a full map of the newest epoch */
		WRT_CHECK_U64(count_events(&f->src, WR_EV_MAP_RESYNC), want);
		WRT_CHECK(f->s.want_full == 0);
		WRT_CHECK_U64(wri_mapstore_deadline(&f->s), WR_DEADLINE_NONE);
		/* the held map is untouched and the message is gone */
		WRT_CHECK_U64(f->s.epoch, 42);
		WRT_CHECK(memcmp(held, wri_mapstore_map(&f->s), hn) == 0);
		WRT_CHECK_U64(f->src.n_release, want + 1u);
		next_ok = next_ok + spacing[i];
		WRT_CHECK_U64(f->s.refetch_at_ms, next_ok);
	}
	{ /* the RESYNC events carry the cause: an incremental that does not follow */
		unsigned k, seen = 0;

		for (k = 0; k < f->src.n_ev && k < MS_LOG; k++)
			if (f->src.ev[k].kind == WR_EV_MAP_RESYNC) {
				seen++;
				WRT_CHECK(f->src.ev[k].has_err && f->src.ev[k].status == WR_E_MAP_EPOCH && f->src.ev[k].what != NULL);
			}
		WRT_CHECK_U64(seen, 8);
	}
	{
		wr_map_stats st;

		wri_mapstore_stats(&f->s, &st);
		WRT_CHECK_U64(st.n_resync, 8);
		WRT_CHECK_U64(st.n_bad, 0); /* a gap is not a decode failure */
		WRT_CHECK_U64(st.last_err, WR_E_MAP_EPOCH);
	}
	/* the full map that answers it: adopted, and the spacing starts over */
	WRT_CHECK_U64(f->s.backoff_ms, 32000);
	post_model_full(f, 50);
	WRT_CHECK_U64(ms_step(f, next_ok), 0);
	WRT_CHECK_U64(f->s.epoch, 50);
	WRT_CHECK_U64(f->s.backoff_ms, 1000);
	WRT_CHECK_U64(f->s.fail_streak, 0);
	WRT_CHECK(f->s.err.status == WR_OK && f->s.want_full == 0);
	check_state(f, 50);
	/* a new gap: the request goes out at once (the spacing since the last one has passed) and the next spacing is 1 s */
	post_inc(f, 80);
	WRT_CHECK_U64(ms_step(f, next_ok + 1), 0);
	WRT_CHECK_U64(f->src.n_want, 9);
	WRT_CHECK_U64(f->s.refetch_at_ms, next_ok + 1 + 1000);
	free(held);
	del_fix(f);
}

static void t_fsid_drop(void)
{
	ms_fix *f = new_fix();
	uint8_t other[16];
	size_t hn;
	uint8_t *held;
	ms_item it;
	wr_map_stats st;

	fprintf(stderr, "another cluster\n");
	adopt42(f, 0);
	held = ms_held_copy(f, &hn);
	memcpy(other, lab.fsid, 16);
	other[15] ^= 0x40;
	it = (ms_item){0, 43, lab.lines[42].p, lab.lines[42].n};
	ms_post_items(&f->src, other, &it, 1, 43);
	WRT_CHECK_U64(ms_step(f, 10), 0);
	wri_mapstore_stats(&f->s, &st);
	WRT_CHECK_U64(st.n_fsid_drop, 1);
	WRT_CHECK_U64(st.n_bad, 0);
	WRT_CHECK_U64(st.newest_seen, 42); /* the other cluster's "newest 43" is not ours to believe */
	WRT_CHECK_U64(f->s.epoch, 42);
	WRT_CHECK_U64(f->src.n_release, 2); /* released, not applied */
	WRT_CHECK_U64(f->src.n_ev, 1);      /* nothing but the first map's event: no request, no resync */
	WRT_CHECK_U64(f->src.n_want, 0);
	WRT_CHECK(f->s.want_full == 0);
	WRT_CHECK(memcmp(held, wri_mapstore_map(&f->s), hn) == 0);
	/* a full map of another cluster inside a message of ours: the label and the fsid inside are checked too */
	it = (ms_item){1, 90, lab.full42, lab.full42_n}; /* its epoch is 42: the label lies */
	ms_post_items(&f->src, lab.fsid, &it, 1, 90);
	WRT_CHECK_U64(ms_step(f, 20), 0);
	WRT_CHECK_U64(f->s.epoch, 42);
	wri_mapstore_stats(&f->s, &st);
	WRT_CHECK_U64(st.n_bad, 1);
	WRT_CHECK(f->s.want_full == 0 && f->src.n_want == 1); /* asked at once */
	free(held);
	del_fix(f);
}

/* ---- failures keep the held map ------------------------------------------------------------------------------- */

typedef struct fail_case {
	const char *label;
	int is_full;
	uint32_t label_epoch;
	const uint8_t *blob;
	size_t len;
	wr_status want; /* WR_OK: any failure */
} fail_case;

static void run_fail_case(const fail_case *c)
{
	ms_fix *f = new_fix();
	size_t hn;
	uint8_t *held;
	ms_item it[2];
	wr_map_stats st;
	unsigned k, seen = 0;

	fprintf(stderr, "failure: %s\n", c->label);
	adopt42(f, 0);
	held = ms_held_copy(f, &hn);
	it[0] = (ms_item){c->is_full, c->label_epoch, c->blob, c->len};
	/* a valid incremental behind the bad entry: the rest of the message is dropped, so it must not be applied */
	it[1] = (ms_item){0, 44, lab.lines[43].p, lab.lines[43].n};
	ms_post_items(&f->src, lab.fsid, it, c->is_full ? 1u : 2u, 60);
	WRT_CHECK_U64(ms_step(f, 7), 0);
	WRT_CHECK_U64(f->s.epoch, 42);
	WRT_CHECK(memcmp(held, wri_mapstore_map(&f->s), hn) == 0); /* byte for byte */
	WRT_CHECK_U64(f->src.n_release, 2);
	wri_mapstore_stats(&f->s, &st);
	WRT_CHECK_U64(st.n_bad, 1);
	WRT_CHECK_U64(st.n_inc, 0);
	WRT_CHECK(st.last_err != WR_OK);
	if (c->want != WR_OK)
		WRT_CHECK_U64(st.last_err, c->want);
	WRT_CHECK_U64(f->src.n_want, 1); /* a full map was requested at once */
	WRT_CHECK_U64(f->src.want_start[0], 0);
	WRT_CHECK_U64(f->src.n_kind[WR_EV_FATAL], 0);
	for (k = 0; k < f->src.n_ev; k++)
		if (f->src.ev[k].kind == WR_EV_MAP_RESYNC) {
			seen++;
			WRT_CHECK(f->src.ev[k].has_err && f->src.ev[k].status == st.last_err);
		}
	WRT_CHECK_U64(seen, 1);
	WRT_CHECK(f->s.err.status == st.last_err); /* the first failure since the last applied epoch */
	/* the free slot never shows a half-built map */
	WRT_CHECK_U64(*(const uint32_t *)(const void *)f->s.slot[f->s.cur ^ 1u], 0);
	/* and the stream carries on: the right incrementals still apply */
	post_inc(f, 43);
	post_inc(f, 44);
	WRT_CHECK_U64(ms_step(f, 8), 1); /* the second message is waiting */
	WRT_CHECK_U64(f->s.epoch, 43);
	WRT_CHECK_U64(ms_step(f, 9), 0);
	WRT_CHECK_U64(f->s.epoch, 44);
	check_state(f, 44);
	free(held);
	del_fix(f);
}

static void t_failures(void)
{
	uint8_t *trunc, *crcflip, *badcompat, *other_epoch_blob;
	size_t n43 = lab.lines[42].n;
	fail_case c;

	trunc = (uint8_t *)malloc(n43);
	memcpy(trunc, lab.lines[42].p, n43);
	c = (fail_case){"truncated incremental", 0, 43, trunc, n43 - 5, WR_OK};
	run_fail_case(&c);

	crcflip = (uint8_t *)malloc(n43);
	memcpy(crcflip, lab.lines[42].p, n43);
	crcflip[n43 - 1] ^= 0x01;
	c = (fail_case){"incremental with a wrong CRC", 0, 43, crcflip, n43, WR_OK};
	run_fail_case(&c);

	/* the entry is labelled 43 but is the incremental of 44 */
	other_epoch_blob = (uint8_t *)malloc(lab.lines[43].n);
	memcpy(other_epoch_blob, lab.lines[43].p, lab.lines[43].n);
	c = (fail_case){"incremental whose epoch is not its label", 0, 43, other_epoch_blob, lab.lines[43].n, WR_E_MAP_EPOCH};
	run_fail_case(&c);

	/* a full map labelled 60 that is epoch 50 inside: it would have moved the held epoch to a number nobody sent */
	c = (fail_case){"full map whose epoch is not its label", 1, 60, enc[50].p, enc[50].len, WR_E_MAP_EPOCH};
	run_fail_case(&c);

	c = (fail_case){"empty incremental", 0, 43, lab.lines[42].p, 0, WR_OK};
	run_fail_case(&c);
	c = (fail_case){"empty full map", 1, 60, lab.full42, 0, WR_OK};
	run_fail_case(&c);

	badcompat = (uint8_t *)malloc(lab.full42_n);
	memcpy(badcompat, lab.full42, lab.full42_n);
	badcompat[1] = 9; /* wrapper struct_compat above what we read */
	c = (fail_case){"full map of a newer encoding", 1, 60, badcompat, lab.full42_n, WR_E_MAP_VERSION};
	run_fail_case(&c);

	/* a well-formed full map (right epoch, right CRC) of another cluster, inside a message that names ours */
	{
		wrt_mg_map other;
		wrt_mg_buf ob;

		memset(&ob, 0, sizeof(ob));
		WRT_CHECK(wrt_mg_map_clone(&models[50], &other) == 0);
		other.fsid[15] ^= 0x40;
		WRT_CHECK(wrt_mg_map_encode(&other, &ob) == 0);
		c = (fail_case){"full map of another cluster", 1, 50, ob.p, ob.len, WR_E_MAP_FSID};
		run_fail_case(&c);
		wrt_mg_buf_free(&ob);
		wrt_mg_map_free(&other);
	}

	/* an entry that is older than the held map is not a failure */
	{
		ms_fix *f = new_fix();
		ms_item it[2];
		wr_map_stats st;

		fprintf(stderr, "stale entries are skipped\n");
		adopt42(f, 0);
		it[0] = (ms_item){0, 40, lab.lines[39].p, lab.lines[39].n};
		it[1] = (ms_item){0, 42, lab.lines[41].p, lab.lines[41].n};
		ms_post_items(&f->src, lab.fsid, it, 2, 42);
		WRT_CHECK_U64(ms_step(f, 5), 0);
		wri_mapstore_stats(&f->s, &st);
		WRT_CHECK(st.n_skipped == 2 && st.n_bad == 0 && st.n_inc == 0 && f->src.n_want == 0);
		WRT_CHECK_U64(f->src.n_release, 2);
		del_fix(f);
	}
	free(trunc);
	free(crcflip);
	free(badcompat);
	free(other_epoch_blob);
}

/* ---- the first map ------------------------------------------------------------------------------------------------ */

static void t_first_map(void)
{
	wr_config cfg;
	ms_fix *f;
	wrt_mg_cluster_spec sp;
	wrt_mg_map big;
	wrt_mg_buf bigb;
	uint8_t *bad;
	size_t hn;
	uint8_t *held;
	wr_target tg;

	fprintf(stderr, "first map\n");
	memset(&bigb, 0, sizeof(bigb));
	wrt_mg_cluster_spec_init(&sp, 3000);
	sp.n_pools = 1;
	sp.epoch = 100;
	WRT_CHECK(wrt_mg_build_map(&big, &sp) == 0);
	WRT_CHECK(wrt_mg_map_encode(&big, &bigb) == 0);

	/* a map that cannot fit the slot is fatal when it is the first one: once, and nothing is asked for */
	ms_cfg(&cfg);
	cfg.map_slot_bytes = 16u * 1024u;
	f = new_fix_cfg(&cfg, 1);
	post_one(f, 1, 100, bigb.p, bigb.len);
	WRT_CHECK_U64(ms_step(f, 0), 0);
	WRT_CHECK_U64(f->src.n_kind[WR_EV_FATAL], 1);
	WRT_CHECK(f->src.n_ev == 1 && f->src.ev[0].kind == WR_EV_FATAL && f->src.ev[0].has_err);
	WRT_CHECK_U64(f->src.ev[0].status, WR_E_MAP_BUDGET);
	WRT_CHECK(f->src.ev[0].what != NULL && strstr(f->src.ev[0].what, "slot") != NULL); /* names the section that did not fit */
	WRT_CHECK(f->s.fatal == 1 && f->s.have_map == 0 && f->s.want_full == 0);
	WRT_CHECK_U64(f->src.n_want, 0);
	WRT_CHECK_U64(wri_mapstore_deadline(&f->s), WR_DEADLINE_NONE);
	WRT_CHECK_U64(f->src.n_release, 1);
	/* afterwards messages are released unread and nothing more is raised or asked */
	post_one(f, 1, 42, lab.full42, lab.full42_n);
	post_inc(f, 43);
	WRT_CHECK_U64(ms_step(f, 5000), 0);
	WRT_CHECK_U64(f->src.n_release, 3);
	WRT_CHECK(f->src.n_ev == 1 && f->src.n_want == 0 && f->s.have_map == 0);
	WRT_CHECK_STATUS(WR_E_MAP_NONE, wri_mapstore_target_pg(&f->s, 0, 0, &tg));
	del_fix(f);

	/* the same map with a map held: not fatal, the held map serves, a full map is requested, the cause is the budget */
	f = new_fix_cfg(&cfg, 1);
	adopt42(f, 0);
	held = ms_held_copy(f, &hn);
	post_one(f, 1, 100, bigb.p, bigb.len);
	WRT_CHECK_U64(ms_step(f, 10), 0);
	WRT_CHECK_U64(f->src.n_kind[WR_EV_FATAL], 0);
	WRT_CHECK(f->s.fatal == 0 && f->s.epoch == 42);
	WRT_CHECK(memcmp(held, wri_mapstore_map(&f->s), hn) == 0);
	WRT_CHECK_U64(f->src.n_want, 1);
	WRT_CHECK_U64(f->src.n_kind[WR_EV_MAP_RESYNC], 1);
	WRT_CHECK_U64(f->src.ev[f->src.n_ev - 1].status, WR_E_MAP_BUDGET);
	WRT_CHECK(f->src.ev[f->src.n_ev - 1].what != NULL);
	WRT_CHECK_U64(f->s.st.n_bad, 1);
	free(held);
	del_fix(f);

	/* a version this client does not read: fatal as a first map */
	f = new_fix();
	bad = (uint8_t *)malloc(lab.full42_n);
	memcpy(bad, lab.full42, lab.full42_n);
	bad[1] = 9;
	post_one(f, 1, 42, bad, lab.full42_n);
	WRT_CHECK_U64(ms_step(f, 0), 0);
	WRT_CHECK(f->src.n_kind[WR_EV_FATAL] == 1 && f->src.ev[0].status == WR_E_MAP_VERSION && f->src.n_want == 0);
	del_fix(f);

	/* a truncated or damaged first map is transient: retried under the back-off, then a good one is taken */
	f = new_fix();
	memcpy(bad, lab.full42, lab.full42_n);
	post_one(f, 1, 42, bad, lab.full42_n - 12);
	WRT_CHECK_U64(ms_step(f, 0), 0);
	WRT_CHECK(f->src.n_kind[WR_EV_FATAL] == 0 && f->s.fatal == 0 && f->src.n_want == 1 && f->src.want_start[0] == 0);
	WRT_CHECK(f->src.n_kind[WR_EV_MAP_RESYNC] == 1 && f->src.ev[0].status != WR_E_MAP_BUDGET);
	bad[lab.full42_n - 1] ^= 0x10; /* the CRC */
	post_one(f, 1, 42, bad, lab.full42_n);
	WRT_CHECK_U64(ms_step(f, 400), 0);
	WRT_CHECK(f->s.have_map == 0 && f->s.fatal == 0);
	WRT_CHECK_U64(f->src.n_want, 1); /* rate limited */
	WRT_CHECK_U64(wri_mapstore_deadline(&f->s), 1000);
	adopt42(f, 1000);
	WRT_CHECK_U64(f->src.n_want, 1); /* the map came: nothing more to ask */
	WRT_CHECK_U64(f->src.n_kind[WR_EV_MAP], 1);
	del_fix(f);
	free(bad);

	/* an incremental with no map held asks for a full map and drops the rest of its message, full map included */
	f = new_fix();
	{
		ms_item it[2];
		wr_map_stats st;

		it[0] = (ms_item){0, 43, lab.lines[42].p, lab.lines[42].n};
		it[1] = (ms_item){1, 50, enc[50].p, enc[50].len};
		ms_post_items(&f->src, lab.fsid, it, 2, 50);
		WRT_CHECK_U64(ms_step(f, 0), 0);
		WRT_CHECK(f->s.have_map == 0 && f->src.n_want == 1 && f->src.n_release == 1);
		WRT_CHECK(f->src.ev[0].kind == WR_EV_MAP_RESYNC && f->src.ev[0].status == WR_E_MAP_NONE);
		wri_mapstore_stats(&f->s, &st);
		WRT_CHECK(st.n_bad == 0 && st.n_inc == 0 && st.last_err == WR_E_MAP_NONE);
	}
	del_fix(f);

	wrt_mg_buf_free(&bigb);
	wrt_mg_map_free(&big);
}

static void t_monmap(void)
{
	ms_fix *f = new_fix();
	static const uint8_t junk[7] = {1, 2, 3, 4, 5, 6, 7};

	fprintf(stderr, "MMonMap\n");
	ms_post(&f->src, WR_MAPMSG_MONMAP, 1, 3, junk, sizeof(junk));
	WRT_CHECK_U64(ms_step(f, 0), 0);
	WRT_CHECK_U64(f->src.n_release, 1); /* released unread */
	WRT_CHECK(f->src.n_ev == 0 && f->src.n_want == 0 && f->s.have_map == 0 && f->s.want_full == 0 && f->s.st.n_bad == 0);
	/* a monmap in front of a map in the queue: both are taken in one step */
	ms_post(&f->src, WR_MAPMSG_MONMAP, 1, 4, junk, sizeof(junk));
	ms_post(&f->src, WR_MAPMSG_MONMAP, 1, 5, junk, 0);
	post_one(f, 1, 42, lab.full42, lab.full42_n);
	WRT_CHECK_U64(ms_step(f, 1), 0);
	WRT_CHECK_U64(f->src.n_release, 4);
	WRT_CHECK_U64(f->s.epoch, 42);
	WRT_CHECK_U64(f->src.n_ev, 1);
	del_fix(f);
}

/* ---- a pool tracked after the map ------------------------------------------------------------------------------------- */

static void t_late_track(void)
{
	wr_config cfg;
	ms_fix *f;
	const wri_map_pool *p = NULL;
	uint32_t h;

	fprintf(stderr, "a pool tracked after the first map\n");
	ms_cfg(&cfg);
	f = new_fix_cfg(&cfg, 0);
	ms_track(f, ".mgr", 0);
	adopt42(f, 0);
	WRT_CHECK(f->s.want_full == 0);
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_track(&f->s, (const uint8_t *)"winrbd", 6, &h));
	WRT_CHECK_U64(h, 1);
	WRT_CHECK(f->s.want_full == 1);
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wri_mapstore_pool(&f->s, 1, &p)); /* until the next full map */
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_pool(&f->s, 0, &p));
	WRT_CHECK_U64(wri_mapstore_deadline(&f->s), 0); /* due now */
	WRT_CHECK_U64(ms_step(f, 10), 0);
	WRT_CHECK_U64(f->src.n_want, 1);
	WRT_CHECK(f->src.ev[f->src.n_ev - 1].kind == WR_EV_MAP_RESYNC && f->src.ev[f->src.n_ev - 1].status == WR_E_MAP_RESYNC);
	/* an incremental now cannot be applied (the held map has no record of the new name): no failure, a full map is wanted */
	post_inc(f, 43);
	WRT_CHECK_U64(ms_step(f, 20), 0);
	WRT_CHECK_U64(f->s.epoch, 42);
	WRT_CHECK(f->s.st.n_bad == 0 && f->s.want_full == 1);
	WRT_CHECK_U64(f->src.n_want, 1); /* rate limited */
	post_model_full(f, 50);
	WRT_CHECK_U64(ms_step(f, 30), 0);
	WRT_CHECK_U64(f->s.epoch, 50);
	WRT_CHECK(f->s.want_full == 0);
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_pool(&f->s, 1, &p));
	WRT_CHECK(p->id == 2);
	/* and the incrementals go on from there */
	post_inc(f, 51);
	WRT_CHECK_U64(ms_step(f, 40), 0);
	WRT_CHECK_U64(f->s.epoch, 51);
	WRT_CHECK_U64(ms_step(f, 5000), 0);
	WRT_CHECK_U64(f->src.n_want, 1);
	del_fix(f);
}

/*
 * On a quiet cluster the monitor answers the start-0 request that a late track causes with a full map of the epoch that is
 * already held. That map is the only thing that carries the new pool's record, so it must be taken although its epoch is not
 * newer; any other same-epoch entry is still stepped over.
 */
static void t_late_track_quiet(void)
{
	wr_config cfg;
	ms_fix *f;
	const wri_map_pool *p = NULL;
	wr_target t;
	wri_oid oid;
	wr_map_stats s1, s2;
	uint32_t h;
	unsigned ev0;

	fprintf(stderr, "a pool tracked after the first map, quiet cluster\n");
	ms_cfg(&cfg);
	f = new_fix_cfg(&cfg, 0);
	ms_track(f, ".mgr", 0);
	adopt42(f, 0);
	memset(&oid, 0, sizeof(oid));
	oid.name = (const uint8_t *)"rbd_data.quiet.0000000000000001";
	oid.name_len = 31;
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_target(&f->s, 0, &oid, &t)); /* fills the cache */
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_track(&f->s, (const uint8_t *)"winrbd", 6, &h));
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wri_mapstore_pool(&f->s, 1, &p));
	WRT_CHECK_U64(ms_step(f, 10), 0);
	WRT_CHECK_U64(f->src.n_want, 1);
	WRT_CHECK_U64(f->src.want_start[0], 0);
	ev0 = f->src.n_ev;
	/* a same-epoch incremental is not a map to adopt */
	post_inc(f, 42);
	WRT_CHECK_U64(ms_step(f, 11), 0);
	WRT_CHECK_U64(f->s.st.n_skipped, 1);
	WRT_CHECK_U64(f->s.st.n_full, 1);
	/* the answer: the full map of epoch 42 again */
	post_one(f, 1, 42, lab.full42, lab.full42_n);
	WRT_CHECK_U64(ms_step(f, 12), 0);
	WRT_CHECK_U64(f->s.epoch, 42);
	WRT_CHECK_U64(f->s.st.n_full, 2);
	WRT_CHECK(f->s.want_full == 0 && f->s.st.n_bad == 0);
	WRT_CHECK_U64(f->src.n_ev, ev0 + 1); /* WR_EV_MAP: the pool is there now */
	WRT_CHECK(f->src.ev[f->src.n_ev - 1].kind == WR_EV_MAP && f->src.ev[f->src.n_ev - 1].epoch == 42);
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_pool(&f->s, 1, &p));
	WRT_CHECK(p->id == 2);
	check_state(f, 42);
	/* the cache was cleared with the replacement (the map is the same epoch, so stamps cannot tell old from new) */
	wri_mapstore_stats(&f->s, &s1);
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_target(&f->s, 0, &oid, &t));
	wri_mapstore_stats(&f->s, &s2);
	WRT_CHECK_U64(s2.cache_misses, s1.cache_misses + 1);
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_target(&f->s, 1, &oid, &t));
	WRT_CHECK(t.pool_id == 2 && t.epoch == 42);
	/* now the held map has every tracked pool: another same-epoch full map is stepped over like any stale entry */
	post_one(f, 1, 42, lab.full42, lab.full42_n);
	WRT_CHECK_U64(ms_step(f, 13), 0);
	WRT_CHECK_U64(f->s.st.n_full, 2);
	WRT_CHECK_U64(f->s.st.n_skipped, 2);
	WRT_CHECK_U64(f->src.n_ev, ev0 + 1);
	/* and the incrementals go on from there */
	post_inc(f, 43);
	WRT_CHECK_U64(ms_step(f, 14), 0);
	WRT_CHECK_U64(f->s.epoch, 43);
	WRT_CHECK_U64(f->src.n_want, 1);
	del_fix(f);
}

/* ---- placement results through the store: absent, unsupported, unmappable pools -------------------------------------- */

static void check_primary_addr(const wr_target *t)
{
	uint32_t osd = (uint32_t)t->acting_primary;

	WRT_CHECK(t->primary_addr.family == WR_AF_IPV4);
	WRT_CHECK(t->primary_addr.ip[0] == 10 && t->primary_addr.ip[1] == 77 && t->primary_addr.ip[2] == (uint8_t)(osd / 200u) &&
		  t->primary_addr.ip[3] == (uint8_t)(10u + osd % 200u));
	WRT_CHECK(t->primary_addr.port != 0);
}

static void t_queries(void)
{
	wrt_mg_cluster_spec sp;
	wrt_mg_map a, b;
	wrt_mg_pool ec;
	wrt_mg_buf ba, bb;
	ms_fix *f;
	wr_config cfg;
	wri_oid oid;
	wr_target t, t0;
	const wri_map_pool *p = NULL;
	wr_map_stats s1, s2;
	uint8_t longname[WRI_PLACE_NAME_MAX + 8u];
	uint32_t seed;
	uint8_t fsid[16];

	fprintf(stderr, "queries: absent, unsupported, unmappable\n");
	ms_cfg(&cfg);
	f = new_fix_cfg(&cfg, 0);
	ms_track(f, "pool1", 0);
	ms_track(f, "ecpool", 1);
	ms_track(f, "ghost", 2);

	memset(&ba, 0, sizeof(ba));
	memset(&bb, 0, sizeof(bb));
	wrt_mg_cluster_spec_init(&sp, 12);
	sp.n_pools = 1;
	sp.epoch = 5;
	WRT_CHECK(wrt_mg_build_map(&a, &sp) == 0);
	wrt_mg_pool_init(&ec, 32);
	wrt_mg_pool_shape(&ec, WRT_MG_SHAPE_ERASURE);
	wrt_mg_map_add_pool(&a, 7, "ecpool", &ec);
	wrt_mg_pool_free(&ec);
	WRT_CHECK(wrt_mg_map_encode(&a, &ba) == 0);
	memcpy(fsid, a.fsid, 16);
	/* the same cluster one epoch later with every OSD down */
	sp.epoch = 6;
	sp.up_pct = 0;
	WRT_CHECK(wrt_mg_build_map(&b, &sp) == 0);
	{
		wrt_mg_pool ec2;

		wrt_mg_pool_init(&ec2, 32);
		wrt_mg_pool_shape(&ec2, WRT_MG_SHAPE_ERASURE);
		wrt_mg_map_add_pool(&b, 7, "ecpool", &ec2);
		wrt_mg_pool_free(&ec2);
	}
	WRT_CHECK(wrt_mg_map_encode(&b, &bb) == 0);

	{
		ms_item it = {1, 5, ba.p, ba.len};

		ms_post_items(&f->src, fsid, &it, 1, 5);
		WRT_CHECK_U64(ms_step(f, 0), 0);
		WRT_CHECK_U64(f->s.epoch, 5);
	}
	memset(&oid, 0, sizeof(oid));
	oid.name = (const uint8_t *)"rbd_data.abc.0000000000000007";
	oid.name_len = 29;
	/* the pool statuses */
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_pool(&f->s, 0, &p));
	WRT_CHECK(p->status == WR_OK && p->id == 1);
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_pool(&f->s, 1, &p)); /* returned with its status, so the caller can report it */
	WRT_CHECK(p->id == 7 && p->status == WR_E_POOL_UNSUPPORTED);
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wri_mapstore_pool(&f->s, 2, &p));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_pool(&f->s, 3, &p));
	WRT_CHECK_STATUS(WR_E_POOL_UNSUPPORTED, wri_mapstore_target(&f->s, 1, &oid, &t));
	WRT_CHECK(t.n_acting == 0 && t.acting_primary == -1 && t.epoch == 0);
	WRT_CHECK_STATUS(WR_E_POOL_UNSUPPORTED, wri_mapstore_target_pg(&f->s, 1, 0, &t));
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wri_mapstore_target(&f->s, 2, &oid, &t));
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wri_mapstore_target_pg(&f->s, 2, 0, &t));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_target(&f->s, 0, NULL, &t));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_target(&f->s, 0, &oid, NULL));
	/* the supported pool */
	wri_mapstore_stats(&f->s, &s1);
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_target(&f->s, 0, &oid, &t0));
	WRT_CHECK(t0.epoch == 5 && t0.pool_id == 1 && t0.n_acting == 3 && t0.n_up == 3 && t0.acting_primary >= 0);
	WRT_CHECK(t0.up_primary == t0.up[0] && t0.acting_primary == t0.acting[0]);
	WRT_CHECK(t0.pg_seed < 32);
	check_primary_addr(&t0);
	wri_mapstore_stats(&f->s, &s2);
	WRT_CHECK_U64(s2.cache_misses, s1.cache_misses + 1);
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_target(&f->s, 0, &oid, &t));
	wri_mapstore_stats(&f->s, &s1);
	WRT_CHECK_U64(s1.cache_hits, s2.cache_hits + 1); /* the second ask is a cache hit and the same answer */
	WRT_CHECK(memcmp(&t, &t0, sizeof(t)) == 0);
	/* a PG that does not exist */
	seed = t0.pg_seed;
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_target_pg(&f->s, 0, 31, &t));
	WRT_CHECK_STATUS(WR_E_RANGE, wri_mapstore_target_pg(&f->s, 0, 32, &t));
	WRT_CHECK(t.n_acting == 0 && t.acting_primary == -1 && t.epoch == 0);
	WRT_CHECK_STATUS(WR_E_RANGE, wri_mapstore_target_pg(&f->s, 0, 0xffffffffu, &t));
	/* a name over the placement limit */
	memset(longname, 'x', sizeof(longname));
	oid.name = longname;
	oid.name_len = WRI_PLACE_NAME_MAX + 1u;
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_mapstore_target(&f->s, 0, &oid, &t));
	WRT_CHECK(t.acting_primary == -1);

	/* the next epoch has every OSD down: the cached answer of epoch 5 must not be served, the PG is unmappable */
	{
		ms_item it = {1, 6, bb.p, bb.len};
		wr_map_stats c1, c2;

		ms_post_items(&f->src, fsid, &it, 1, 6);
		WRT_CHECK_U64(ms_step(f, 1), 0);
		WRT_CHECK_U64(f->s.epoch, 6);
		oid.name = (const uint8_t *)"rbd_data.abc.0000000000000007";
		oid.name_len = 29;
		wri_mapstore_stats(&f->s, &c1);
		WRT_CHECK_STATUS(WR_E_PLACE_UNMAPPABLE, wri_mapstore_target(&f->s, 0, &oid, &t));
		WRT_CHECK(t.epoch == 6 && t.pool_id == 1 && t.pg_seed == seed && t.n_acting == 0 && t.acting_primary == -1);
		WRT_CHECK(t.primary_addr.family == 0);
		WRT_CHECK_STATUS(WR_E_PLACE_UNMAPPABLE, wri_mapstore_target_pg(&f->s, 0, seed, &t));
		wri_mapstore_stats(&f->s, &c2);
		WRT_CHECK(c2.cache_misses > c1.cache_misses);
	}
	wrt_mg_buf_free(&ba);
	wrt_mg_buf_free(&bb);
	wrt_mg_map_free(&a);
	wrt_mg_map_free(&b);
	del_fix(f);
}

int main(void)
{
	uint32_t e;

	setup_lab();
	t_full_map();
	t_names();
	t_chain();
	t_interleaved();
	t_budget_and_more();
	t_gap_backoff();
	t_fsid_drop();
	t_failures();
	t_first_map();
	t_monmap();
	t_late_track();
	t_late_track_quiet();
	t_queries();
	for (e = 0; e <= MS_LAB_EPOCHS; e++) {
		wrt_mg_map_free(&models[e]);
		wrt_mg_buf_free(&enc[e]);
	}
	ms_lab_free(&lab);
	return wrt_finish();
}
