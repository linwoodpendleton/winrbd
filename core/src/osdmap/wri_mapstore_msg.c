/* SPDX-License-Identifier: MIT */
/*
 * wri_mapstore_msg.c - the map store following the cluster: the cursor over an MOSDMap front, the epoch policy and
 * the rate-limited full-map re-request (docs/design/core-architecture.md 15.5; osdmap.md 3.2).
 *
 * A step does at most one epoch of work. The unit is "one full map decoded or one incremental applied (or refused)":
 * entries that are not newer than the held epoch are stepped over without counting, a message is released only after
 * its last entry (or when the rest of it is dropped), and the answer says whether more is ready so the scheduler runs
 * again at once instead of sitting on a message of forty epochs.
 *
 * What keeps the held epoch from ever going down or being advanced by a map that does not belong: an entry is adopted
 * only when its list label is newer than the held epoch, the epoch and the fsid INSIDE the map equal the label and the
 * message's fsid (a decoder checks the fsid of an incremental against the held map, and an embedded full map or a full
 * map carries its own), and the new map is built in the free slot, so a failure at any point leaves the held slot as it was.
 */
#include "wri_mapstore.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define LIST_MAX 1024u /* entries accepted per list (the monitor client takes no more: wri_mosdmap_hdr.c) */
#define DROP_MAX 64u   /* messages released without an epoch of work in one step before the step yields */
#define FSID_LEN 16u
#define ENTRY_COST 8u  /* bytes an entry costs to step over (its epoch and length), and the least charged for an epoch */

enum { RUN_EPOCH = 0, RUN_DONE = 1, RUN_BUDGET = 2 };

/* one list entry of the open message */
typedef struct entry {
	int is_full;
	uint32_t epoch;
	uint32_t len;
	uint32_t next;     /* position of the entry after this one in its list */
	const uint8_t *p;
} entry;

static void ev(const wri_map_io *io, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *err)
{
	if (io->event != NULL)
		io->event(io->ctx, kind, epoch, err);
}

static void charge(uint32_t *budget, uint32_t cost)
{
	*budget = cost >= *budget ? 0u : *budget - cost;
}

static uint64_t add_ms(uint64_t now, uint64_t d)
{
	return now > WR_DEADLINE_NONE - 1u - d ? WR_DEADLINE_NONE - 1u : now + d;
}

static void drop_rest(wri_mapstore *s)
{
	s->inc_left = 0;
	s->full_left = 0;
}

void wri_mapstore_need_full(wri_mapstore *s, const wr_errinfo *cause)
{
	if (s == NULL || s->fatal)
		return;
	s->want_full = 1;
	if (cause != NULL) {
		s->cause = *cause;
	} else {
		WR_MEMSET(&s->cause, 0, sizeof(s->cause));
		WRI_ERRINFO(&s->cause, WR_E_MAP_RESYNC, WR_MOD_MAP, "a full OSD map is needed", 0, 0, 0);
	}
}

/* ---- failures ------------------------------------------------------------------------------------------- */

/*
 * An entry could not be used: record why, drop the rest of the message, ask for a full map. `count_bad` is 0 for a gap
 * (the entry is fine, it just does not follow what we hold). A first map that fails in a way no retry can change is fatal.
 */
static void entry_failed(const wri_ctx *x, wri_mapstore *s, const wri_map_io *io, int is_full, int count_bad, wr_status st,
			 wr_errinfo *why)
{
	if (why->status == WR_OK)
		WRI_ERRINFO(why, st, WR_MOD_MAP, "OSD map entry could not be used", 0, 0, 0);
	why->status = st;
	if (why->module == 0)
		why->module = WR_MOD_MAP;
	if (count_bad)
		s->st.n_bad++;
	s->st.last_err = st;
	s->fail_streak++;
	if (s->err.status == WR_OK)
		s->err = *why;
	drop_rest(s);
	WRI_LOG(x, WR_LOG_WARN, WR_MOD_MAP, WR_CONN_NONE, st, why->what != NULL ? why->what : "OSD map entry failed", s->epoch,
		why->a0, why->a1, why->a2);
	if (!s->have_map && is_full && (st == WR_E_MAP_BUDGET || st == WR_E_MAP_VERSION)) {
		/* the first map, and a retry would be the same map: nothing to wait for */
		if (!s->fatal) {
			s->fatal = 1;
			s->want_full = 0;
			ev(io, WR_EV_FATAL, 0, why);
		}
		return;
	}
	wri_mapstore_need_full(s, why);
}

static void fail_msg(const wri_ctx *x, wri_mapstore *s, const wri_map_io *io, wr_status st, const char *what, uint64_t a0,
		     uint64_t a1, uint64_t a2)
{
	wr_errinfo why;

	WR_MEMSET(&why, 0, sizeof(why));
	WRI_ERRINFO(&why, st, WR_MOD_MAP, what, a0, a1, a2);
	entry_failed(x, s, io, 0, 1, st, &why);
}

/* ---- the message cursor --------------------------------------------------------------------------------- */

/* Step over one list of a front (count already read) leaving the reader after it. */
static void walk_list(wri_rd *r, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n && wri_rd_ok(r); i++) {
		uint32_t len;

		(void)wri_rd_u32(r); /* epoch */
		len = wri_rd_u32(r);
		wri_rd_skip(r, (size_t)len);
	}
}

/* Validate the front and set the cursor (offsets of both lists, entry counts), the fsid and the newest epoch. */
static wr_status open_msg(wri_mapstore *s, const wr_mapmsg *m, uint8_t fsid[FSID_LEN], uint32_t *newest_out, wr_errinfo *why)
{
	wri_rd r;
	uint32_t n_inc, n_full, inc_pos, full_pos, newest = 0;

	if ((m->front == NULL && m->front_len != 0) || m->front_len > 0xffffffffu) {
		WRI_ERRINFO(why, WR_E_MAP_CORRUPT, WR_MOD_MAP, "MOSDMap front is unusable", m->front_len, 0, 0);
		return WR_E_MAP_CORRUPT;
	}
	wri_rd_init(&r, m->front, m->front_len);
	wri_rd_copy(&r, fsid, FSID_LEN);
	n_inc = wri_rd_count(&r, LIST_MAX, ENTRY_COST);
	inc_pos = (uint32_t)r.pos;
	walk_list(&r, n_inc);
	n_full = wri_rd_count(&r, LIST_MAX, ENTRY_COST);
	full_pos = (uint32_t)r.pos;
	walk_list(&r, n_full);
	if (m->msg_version >= 2u) {
		(void)wri_rd_u32(&r); /* cluster_osdmap_trim_lower_bound: not used, a full map is the only recovery */
		newest = wri_rd_u32(&r);
	}
	if (!wri_rd_ok(&r)) {
		WRI_ERRINFO(why, WR_E_MAP_CORRUPT, WR_MOD_MAP, "MOSDMap front is malformed", r.pos, m->front_len, r.err);
		return WR_E_MAP_CORRUPT;
	}
	s->msg_len = (uint32_t)m->front_len;
	s->inc_pos = inc_pos;
	s->inc_left = n_inc;
	s->full_pos = full_pos;
	s->full_left = n_full;
	*newest_out = newest; /* the caller records it once the message is known to be ours */
	if (m->front_len > s->st.msg_bytes_max)
		s->st.msg_bytes_max = (uint32_t)m->front_len;
	return WR_OK;
}

/* The next entry of one list. The front was validated when the message was opened; this re-reads it through a cursor. */
static wr_status read_entry(const wri_mapstore *s, const wr_mapmsg *m, int full, entry *e)
{
	wri_rd r;
	uint32_t pos = full ? s->full_pos : s->inc_pos;

	if (m->front == NULL || m->front_len != (size_t)s->msg_len || pos > s->msg_len)
		return WR_E_MAP_CORRUPT; /* the source changed the message under us */
	wri_rd_init(&r, m->front, m->front_len);
	wri_rd_skip(&r, (size_t)pos);
	e->is_full = full;
	e->epoch = wri_rd_u32(&r);
	e->len = wri_rd_u32(&r);
	e->p = wri_rd_bytes(&r, (size_t)e->len);
	e->next = (uint32_t)r.pos;
	return wri_rd_ok(&r) ? WR_OK : WR_E_MAP_CORRUPT;
}

static void advance(wri_mapstore *s, const entry *e)
{
	if (e->is_full) {
		s->full_pos = e->next;
		s->full_left--;
	} else {
		s->inc_pos = e->next;
		s->inc_left--;
	}
}

/* ---- one epoch ------------------------------------------------------------------------------------------ */

/* The new map in `slot` is the next held map: checks that belong to the store, not to a decoder. */
static wr_status check_new(const wri_osdmap *nm, const entry *e, const uint8_t *fsid, wr_errinfo *why)
{
	if (nm->epoch != e->epoch) {
		WRI_ERRINFO(why, WR_E_MAP_EPOCH, WR_MOD_MAP, "the map names another epoch than its list entry", e->epoch, nm->epoch, 0);
		return WR_E_MAP_EPOCH;
	}
	if (!wri_ct_memeq(nm->fsid, fsid, FSID_LEN)) {
		WRI_ERRINFO(why, WR_E_MAP_FSID, WR_MOD_MAP, "the map belongs to another cluster than its message", e->epoch, 0, 0);
		return WR_E_MAP_FSID;
	}
	if (wri_map_crush(nm) == NULL) {
		WRI_ERRINFO(why, WR_E_MAP_CORRUPT, WR_MOD_MAP, "the map has no CRUSH map", e->epoch, 0, 0);
		return WR_E_MAP_CORRUPT;
	}
	return WR_OK;
}

static void commit(wri_mapstore *s, unsigned nxt, const wri_osdmap *nm, int is_full)
{
	if (s->have_map && nm->epoch == s->epoch)
		wri_pgcache_clear(&s->cache); /* a same-epoch replacement: the epoch stamps no longer tell old results from new */
	s->cur = (uint8_t)nxt;
	s->have_map = 1;
	s->epoch = nm->epoch;
	if (is_full) {
		s->st.n_full++;
		s->want_full = 0; /* a full map answers a gap, a failure and a late track alike */
	} else {
		s->st.n_inc++;
	}
	s->st.slot_used = nm->bytes;
	if (nm->bytes > s->st.slot_used_max)
		s->st.slot_used_max = nm->bytes;
	s->fail_streak = 0;
	s->backoff_ms = s->base_ms;
	WR_MEMSET(&s->err, 0, sizeof(s->err));
	s->ev_map = 1;
	s->ev_epoch = nm->epoch;
}

static void process(const wri_ctx *x, wri_mapstore *s, const wri_map_io *io, const wr_mapmsg *m, const entry *e)
{
	wr_errinfo why;
	const wri_osdmap *held = wri_mapstore_map(s), *nm;
	unsigned nxt = held != NULL ? (unsigned)(s->cur ^ 1u) : 0u;
	uint8_t *slot = s->slot[nxt];
	wr_status st;

	WR_MEMSET(&why, 0, sizeof(why));
	if (e->epoch == 0) {
		WRI_ERRINFO(&why, WR_E_MAP_CORRUPT, WR_MOD_MAP, "list entry with epoch 0", e->is_full, e->len, 0);
		entry_failed(x, s, io, e->is_full, 1, WR_E_MAP_CORRUPT, &why);
		return;
	}
	if (!e->is_full) {
		if (held == NULL) {
			WRI_ERRINFO(&why, WR_E_MAP_NONE, WR_MOD_MAP, "incremental with no map held: a full map is needed", e->epoch, 0, 0);
			entry_failed(x, s, io, 0, 0, WR_E_MAP_NONE, &why);
			return;
		}
		if (e->epoch != s->epoch + 1u) {
			WRI_ERRINFO(&why, WR_E_MAP_EPOCH, WR_MOD_MAP, "incremental does not follow the held epoch (gap)", s->epoch, e->epoch,
				    0);
			entry_failed(x, s, io, 0, 0, WR_E_MAP_EPOCH, &why);
			return;
		}
		if (held->n_pools != s->cfg.n_pools) {
			/* a pool was tracked after this map was built: its record is not in the map, an incremental cannot add it */
			WRI_ERRINFO(&why, WR_E_MAP_RESYNC, WR_MOD_MAP, "pool tracked after the held map was built: a full map is needed",
				    held->n_pools, s->cfg.n_pools, s->epoch);
			s->st.last_err = WR_E_MAP_RESYNC;
			drop_rest(s);
			wri_mapstore_need_full(s, &why);
			return;
		}
		st = wri_osdmap_apply_inc(&s->cfg, held, e->p, e->len, slot, s->cfg.slot_bytes, &why);
	} else {
		st = wri_osdmap_decode_full(&s->cfg, e->p, e->len, slot, s->cfg.slot_bytes, &why);
	}
	if (st == WR_OK) {
		nm = (const wri_osdmap *)(const void *)slot;
		st = check_new(nm, e, m->front, &why);
	}
	if (st != WR_OK) {
		WR_MEMSET(slot, 0, sizeof(uint32_t)); /* not a map, whatever the decoder left: keep the free slot's magic at 0 */
		entry_failed(x, s, io, e->is_full, 1, st, &why);
		return;
	}
	commit(s, nxt, (const wri_osdmap *)(const void *)slot, e->is_full);
}

/*
 * An entry that is not newer than the held epoch is stepped over. The one exception is a full map of the HELD epoch when the
 * held map was built before a pool was tracked: the monitor answers a start-0 request on a quiet cluster with exactly that
 * map, and it is the only way the new pool's record gets into the store (the epoch does not go down; it does not move).
 */
static int stale(const wri_mapstore *s, const entry *e)
{
	const wri_osdmap *held;

	if (!s->have_map || e->epoch > s->epoch)
		return 0;
	if (e->is_full && e->epoch == s->epoch) {
		held = wri_mapstore_map(s);
		if (held != NULL && held->n_pools != s->cfg.n_pools)
			return 0;
	}
	return 1;
}

/* Walk the open message to the first entry that is newer than the held epoch and do that one epoch of work. */
static int run_msg(const wri_ctx *x, wri_mapstore *s, const wri_map_io *io, const wr_mapmsg *m, uint32_t *budget)
{
	for (;;) {
		entry ie, fe;
		const entry *e = NULL;

		WR_MEMSET(&ie, 0, sizeof(ie));
		WR_MEMSET(&fe, 0, sizeof(fe));
		if (s->inc_left == 0 && s->full_left == 0)
			return RUN_DONE;
		if (*budget == 0)
			return RUN_BUDGET;
		if (s->inc_left != 0) {
			if (read_entry(s, m, 0, &ie) != WR_OK)
				goto corrupt;
			e = &ie;
		}
		if (s->full_left != 0) {
			if (read_entry(s, m, 1, &fe) != WR_OK)
				goto corrupt;
			/* the same epoch in both lists: the full map goes first (an incremental after it is then stepped over) */
			if (e == NULL || fe.epoch <= ie.epoch)
				e = &fe;
		}
		advance(s, e);
		if (stale(s, e)) {
			s->st.n_skipped++;
			charge(budget, ENTRY_COST);
			continue;
		}
		charge(budget, e->len < 0xffffffffu - ENTRY_COST ? e->len + ENTRY_COST : 0xffffffffu);
		process(x, s, io, m, e);
		return RUN_EPOCH;
	}
corrupt:
	fail_msg(x, s, io, WR_E_MAP_CORRUPT, "MOSDMap entry unreadable (the message changed while open)", s->inc_pos, s->full_pos, 0);
	return RUN_EPOCH;
}

/* ---- the step ------------------------------------------------------------------------------------------- */

/* A full-map request, when one is wanted and the spacing allows it. */
static void maybe_request(const wri_ctx *x, wri_mapstore *s, const wri_map_io *io)
{
	uint64_t now = x != NULL ? x->now.mono_ms : 0u;

	if (!s->want_full || s->fatal || now < s->refetch_at_ms)
		return;
	s->want_full = 0;
	s->st.n_resync++;
	s->refetch_at_ms = add_ms(now, s->backoff_ms);
	if (s->backoff_ms < WRI_MAPSTORE_BACKOFF_MAX_MS / 2u)
		s->backoff_ms *= 2u;
	else
		s->backoff_ms = WRI_MAPSTORE_BACKOFF_MAX_MS;
	if (io->want_osdmap != NULL)
		io->want_osdmap(io->ctx, 0);
	ev(io, WR_EV_MAP_RESYNC, s->epoch, &s->cause);
}

int wri_mapstore_step(const wri_ctx *x, wri_mapstore *s, const wri_map_io *io, uint32_t *budget)
{
	uint32_t unlimited = 0xffffffffu, drops = 0;
	int more = 0;
	wr_mapmsg m;

	if (s == NULL || !s->enabled || io == NULL || io->peek == NULL || io->release == NULL)
		return 0;
	if (budget == NULL)
		budget = &unlimited;
	for (;;) {
		WR_MEMSET(&m, 0, sizeof(m));
		if (!io->peek(io->ctx, &m)) {
			if (s->msg_open) { /* the source no longer has our message: nothing left to consume */
				s->msg_open = 0;
				drop_rest(s);
			}
			break;
		}
		if (!s->msg_open) {
			uint8_t fsid[FSID_LEN];
			uint32_t newest = 0;
			wr_errinfo why;

			if (s->fatal || m.kind != WR_MAPMSG_OSDMAP) {
				/* MMonMap: the monitor client has adopted it already; after a fatal first map nothing is used */
				io->release(io->ctx);
			} else if (*budget == 0) {
				more = 1;
				break;
			} else {
				WR_MEMSET(&why, 0, sizeof(why));
				if (open_msg(s, &m, fsid, &newest, &why) != WR_OK) {
					entry_failed(x, s, io, 0, 1, WR_E_MAP_CORRUPT, &why);
					io->release(io->ctx);
				} else if (s->have_map && !wri_ct_memeq(fsid, wri_mapstore_map(s)->fsid, FSID_LEN)) {
					s->st.n_fsid_drop++;
					drop_rest(s);
					io->release(io->ctx);
				} else {
					if (newest > s->newest_seen) /* only a message of our own cluster says what is newest */
						s->newest_seen = newest;
					s->msg_open = 1;
				}
			}
			if (!s->msg_open) {
				if (++drops >= DROP_MAX) {
					more = 1;
					break;
				}
				continue;
			}
		}
		{
			int r = run_msg(x, s, io, &m, budget);

			if (r == RUN_BUDGET) {
				more = 1;
				break;
			}
			if (s->inc_left == 0 && s->full_left == 0) { /* its last entry is done (or the rest was dropped) */
				io->release(io->ctx);
				s->msg_open = 0;
			}
			if (r == RUN_EPOCH)
				break;
			if (++drops >= DROP_MAX) {
				more = 1;
				break;
			}
		}
	}
	if (s->ev_map) {
		s->ev_map = 0;
		ev(io, WR_EV_MAP, s->ev_epoch, NULL);
	}
	maybe_request(x, s, io);
	if (!more) {
		WR_MEMSET(&m, 0, sizeof(m));
		more = s->msg_open || io->peek(io->ctx, &m) != 0;
	}
	return more;
}

uint64_t wri_mapstore_deadline(const wri_mapstore *s)
{
	if (s == NULL || !s->enabled || !s->want_full || s->fatal)
		return WR_DEADLINE_NONE;
	return s->refetch_at_ms;
}
