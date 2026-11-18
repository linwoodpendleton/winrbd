/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_sess_bo.c - the MOSDBackoff table of one session (design 21.5, osd-ops.md 3.7).
 *
 * BLOCK: store the entry, then acknowledge it at once with the BLOCK's own epoch. UNBLOCK: remove the entry by id and tell the request
 * layer which PG to resend (including operations already sent: the OSD may have dropped them). ACK_BLOCK from the OSD: ignored. The
 * entries live as long as the connection: settle() clears the table when it ends.
 *
 * An entry that cannot be kept exactly (a name above WRI_OSD_OID_MAX, a locator key, a namespace, or a position whose pool is not the
 * PG's) is `coarse`: it holds every request of its PG, which can only hold too much. A BLOCK that finds the table full is merged into an
 * entry of the same PG (made coarse; the extra id is kept in the entry's begin_oid bytes), so the UNBLOCK that comes for it still ends
 * the hold. Only a BLOCK for a PG that has no entry and finds no room is not held at all: it is acknowledged, counted, and `bo_lost`
 * makes the session treat the UNBLOCK of an id it does not know as the end of a backoff anyway (the requests that the OSD dropped in the
 * meantime are resent by the unblock callback, or, at the latest, by their timeout).
 */
#include "wri_osd_sess.h"

#include "wri_le.h"

WR_FILE_LICENCE_MIT

#define BO_EXTRA_MAX (WRI_OSD_OID_MAX / 8u) /* further ids a coarse entry keeps in begin_oid */
#define ACK_SCRATCH 512u                    /* an ACK_BLOCK longer than this (very long names) is not sent: the hold stays, the OSD is not told */

static uint32_t slots_of(const wri_osd_sess_tab *t)
{
	return t->x->cfg.backoff_slots;
}

void wri_os_bo_clear(wri_osd_sess *s)
{
	if (s->bo != NULL && s->n_backoff != 0 && s->tab != NULL)
		WR_MEMSET(s->bo, 0, (size_t)s->tab->x->cfg.backoff_slots * sizeof(wri_backoff));
	s->n_backoff = 0;
	s->bo_lost = 0;
}

static uint64_t extra_get(const wri_backoff *e, unsigned k)
{
	return wri_le64_get(e->begin_oid + 8u * k);
}

static void extra_put(wri_backoff *e, unsigned k, uint64_t id)
{
	wri_le64_put(e->begin_oid + 8u * k, id);
}

/* Remove the entry (or the extra id) `id`; 1 if it was there, with the PG it held. */
static int remove_id(wri_osd_sess *s, uint32_t slots, uint64_t id, int64_t *pool, uint32_t *pg_seed)
{
	uint32_t i;
	unsigned k;

	for (i = 0; i < slots; i++) {
		wri_backoff *e = &s->bo[i];

		if (!e->used)
			continue;
		if (e->id == id) {
			*pool = e->pool;
			*pg_seed = e->pg_seed;
			if (e->coarse && e->begin_len != 0) { /* another BLOCK of this PG still stands: its id takes over the entry */
				e->id = extra_get(e, (unsigned)e->begin_len - 1u);
				extra_put(e, (unsigned)e->begin_len - 1u, 0);
				e->begin_len--;
			} else {
				WR_MEMSET(e, 0, sizeof(*e));
				if (s->n_backoff != 0)
					s->n_backoff--;
			}
			return 1;
		}
		if (e->coarse) {
			for (k = 0; k < e->begin_len; k++) {
				if (extra_get(e, k) != id)
					continue;
				*pool = e->pool;
				*pg_seed = e->pg_seed;
				extra_put(e, k, extra_get(e, (unsigned)e->begin_len - 1u));
				extra_put(e, (unsigned)e->begin_len - 1u, 0);
				e->begin_len--;
				return 1;
			}
		}
	}
	return 0;
}

/* 1 if the BLOCK can be kept as exact positions. */
static int can_be_exact(const wri_mbackoff *m)
{
	return m->begin.key_len == 0 && m->end.key_len == 0 && m->begin.nspace_len == 0 && m->end.nspace_len == 0 &&
	       m->begin.oid_len <= WRI_OSD_OID_MAX && m->end.oid_len <= WRI_OSD_OID_MAX && m->begin.pool == m->pool &&
	       m->end.pool == m->pool;
}

static void fill_exact(wri_backoff *e, const wri_mbackoff *m)
{
	e->begin_hash = m->begin.hash;
	e->end_hash = m->end.hash;
	e->begin_snap = m->begin.snap;
	e->end_snap = m->end.snap;
	e->begin_max = m->begin.max;
	e->end_max = m->end.max;
	e->begin_len = (uint8_t)m->begin.oid_len;
	e->end_len = (uint8_t)m->end.oid_len;
	if (m->begin.oid_len != 0)
		WR_MEMCPY(e->begin_oid, m->begin.oid, m->begin.oid_len);
	if (m->end.oid_len != 0)
		WR_MEMCPY(e->end_oid, m->end.oid, m->end.oid_len);
}

/* Keep the BLOCK; 0 if there was no room at all. */
static int store(wri_osd_sess_tab *t, wri_osd_sess *s, const wri_mbackoff *m)
{
	uint32_t slots = slots_of(t), i;
	int64_t pool;
	uint32_t pg;
	int coarse = !can_be_exact(m);
	wri_backoff *free_e = NULL, *same = NULL;

	(void)remove_id(s, slots, m->id, &pool, &pg); /* a repeated id replaces its entry */
	for (i = 0; i < slots; i++) {
		wri_backoff *e = &s->bo[i];

		if (!e->used) {
			if (free_e == NULL)
				free_e = e;
		} else if (same == NULL && e->pool == m->pool && e->pg_seed == m->pg_seed) {
			same = e;
		}
	}
	if (free_e != NULL) {
		WR_MEMSET(free_e, 0, sizeof(*free_e));
		free_e->used = 1;
		free_e->id = m->id;
		free_e->pool = m->pool;
		free_e->pg_seed = m->pg_seed;
		if (coarse) {
			free_e->coarse = 1;
			t->n_backoff_overflow++;
		} else {
			fill_exact(free_e, m);
		}
		s->n_backoff++;
		return 1;
	}
	t->n_backoff_overflow++; /* the table is full */
	if (same == NULL || (same->coarse && same->begin_len >= BO_EXTRA_MAX)) {
		s->bo_lost = 1;
		return 0;
	}
	if (!same->coarse) { /* from exact to the whole PG: only holds more */
		WR_MEMSET(same->begin_oid, 0, sizeof(same->begin_oid));
		WR_MEMSET(same->end_oid, 0, sizeof(same->end_oid));
		same->begin_len = 0;
		same->end_len = 0;
		same->begin_snap = same->end_snap = 0;
		same->begin_hash = same->end_hash = 0;
		same->begin_max = same->end_max = 0;
		same->coarse = 1;
	}
	extra_put(same, same->begin_len, m->id);
	same->begin_len++;
	return 1;
}

static void send_ack(wri_osd_sess_tab *t, wri_osd_sess *s, const wri_mbackoff *m)
{
	uint8_t buf[ACK_SCRATCH];
	wri_m2_msg_out out;
	wri_wr w;
	wr_status st;

	if (wri_mbackoff_ack_len(m) > sizeof(buf)) {
		t->n_backoff_noack++;
		return;
	}
	wri_wr_init(&w, buf, sizeof(buf));
	st = wri_mbackoff_encode_ack(&w, m);
	if (st != WR_OK || !wri_wr_ok(&w)) {
		t->n_backoff_noack++;
		return;
	}
	WR_MEMSET(&out, 0, sizeof(out));
	out.type = (uint16_t)WRI_MSG_OSD_BACKOFF;
	out.priority = (uint16_t)WRI_MSG_PRIO_CLIENT;
	out.version = (uint16_t)WRI_MOSDBACKOFF_VERSION;
	out.compat_version = (uint16_t)WRI_MOSDBACKOFF_VERSION;
	out.front = buf;
	out.front_len = (uint32_t)wri_wr_len(&w);
	st = t->link.send(t->link.ctx, s->conn_slot, &out);
	if (st != WR_OK)
		t->n_backoff_noack++;
}

void wri_os_bo_handle(wri_osd_sess_tab *t, wri_osd_sess *s, const wri_mbackoff *m)
{
	uint32_t idx = (uint32_t)(s - t->s);
	int64_t pool = 0;
	uint32_t pg = 0;

	if (m->op == WRI_BACKOFF_BLOCK) {
		t->n_backoff_blocks++;
		(void)store(t, s, m);
		send_ack(t, s, m); /* even when nothing could be kept: the OSD stops sending only after the acknowledgement */
	} else if (m->op == WRI_BACKOFF_UNBLOCK) {
		if (remove_id(s, slots_of(t), m->id, &pool, &pg)) {
			t->up.unblock(t->up.ctx, idx, pool, pg);
			if (pool != m->pool || pg != m->pg_seed) /* the PG may have split since: release the one the OSD named too */
				t->up.unblock(t->up.ctx, idx, m->pool, m->pg_seed);
		} else if (s->bo_lost) {
			t->up.unblock(t->up.ctx, idx, m->pool, m->pg_seed);
		}
	}
	/* ACK_BLOCK from the OSD: nothing to do */
}

int wri_osd_sess_blocked(const wri_osd_sess_tab *t, uint32_t idx, int64_t pool, uint32_t pg_seed, uint32_t hash, const uint8_t *oid,
			 uint32_t oid_len)
{
	const wri_osd_sess *s = wri_osd_sess_at(t, idx);
	wri_hobj pos;
	uint32_t i, slots;

	if (s == NULL || s->n_backoff == 0 || (oid == NULL && oid_len != 0))
		return 0;
	slots = slots_of(t);
	wri_hobj_of_request(&pos, pool, hash, NULL, 0, oid, oid_len);
	for (i = 0; i < slots; i++) {
		const wri_backoff *e = &s->bo[i];
		wri_mbackoff m;

		if (!e->used || e->pool != pool || e->pg_seed != pg_seed)
			continue;
		if (e->coarse)
			return 1;
		WR_MEMSET(&m, 0, sizeof(m));
		m.pool = e->pool;
		m.pg_seed = e->pg_seed;
		m.begin.pool = m.end.pool = e->pool;
		m.begin.oid = e->begin_oid;
		m.begin.oid_len = e->begin_len;
		m.begin.hash = e->begin_hash;
		m.begin.snap = e->begin_snap;
		m.begin.max = e->begin_max;
		m.end.oid = e->end_oid;
		m.end.oid_len = e->end_len;
		m.end.hash = e->end_hash;
		m.end.snap = e->end_snap;
		m.end.max = e->end_max;
		if (wri_mbackoff_covers(&m, &pos))
			return 1;
	}
	return 0;
}
