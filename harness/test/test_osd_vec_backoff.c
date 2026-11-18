/* SPDX-License-Identifier: MIT */
/*
 * test_osd_vec_backoff - the two backoff captures of module vectors-c (harness/vectors/public/osdc/sessions/backoff-restart.json and
 * backoff-out.json: 138 MOSDBackoff messages of a stock client under load while an OSD is restarted and while one is marked out and in)
 * played into the backoff table of an OSD session of core/src/osd (wri_osd_sess.h) through the rig of the osd-sess tests, one connection
 * at a time as the OSD sent them:
 *   - every BLOCK is answered by the table with an ACK_BLOCK that equals, byte for byte, the one the stock client sent for it
 *     (type 61, priority 63, version 1 / compat 1, the BLOCK's epoch);
 *   - after every message, for every request position of the capture, wri_osd_sess_blocked() equals the model of the note (a live BLOCK of
 *     the request's PG whose range holds the position), and the positions of the requests that the stock client had to send again are
 *     held at some moment of their connection (the table holds exactly what the OSD told it not to send);
 *   - every UNBLOCK removes its entry and tells the request layer the PG to send again, once; when the capture ends the table is empty;
 *   - the same with a table of 4, 2 and 1 slots (the real traffic of 6 to 16 PG-wide blocks a connection against a table that is too
 *     small): a position is never held without a live BLOCK of its PG, no UNBLOCK is lost (every one tells the request layer to resend that
 *     PG, even one whose BLOCK did not fit), the table is empty at the end.
 * The vectors are not part of a source archive without harness/vectors/public/osdc: then the test skips with its reason.
 */
#include "osdc_vec_rig.h"
#include "osd_sess_rig.h"

typedef struct bmsg {
	int conn;
	int c2s;
	uint8_t *front;
	size_t n;
	uint16_t version, compat;
	uint64_t tid;
	wri_mbackoff m; /* decoded, borrows `front` */
} bmsg;

typedef struct rpos {
	int64_t pool;
	uint32_t seed, hash;
	char oid[100];
	uint32_t oid_len;
	int resent;      /* the stock client had to send it again */
	int seen_held;   /* held by a live BLOCK at some moment of some connection */
} rpos;

typedef struct sess_data {
	bmsg *msgs;
	size_t n_msgs;
	rpos *pos;
	size_t n_pos;
} sess_data;

static void sd_free(sess_data *d)
{
	size_t i;

	for (i = 0; i < d->n_msgs; i++)
		free(d->msgs[i].front);
	free(d->msgs);
	free(d->pos);
	memset(d, 0, sizeof(*d));
}

static int sd_load(sess_data *d, const char *name)
{
	char rel[160];
	wrt_json j;
	wrt_tok bos, exs;
	size_t i, k;

	memset(d, 0, sizeof(*d));
	snprintf(rel, sizeof(rel), "sessions/%s.json", name);
	if (ov_load(&j, rel) != 0)
		return -1;
	bos = wrt_json_get(&j, wrt_json_root(&j), "backoffs");
	exs = wrt_json_get(&j, wrt_json_root(&j), "exchanges");
	if (bos == WRT_NONE || exs == WRT_NONE) {
		wrt_json_free(&j);
		return -1;
	}
	d->n_msgs = wrt_json_count(&j, bos);
	d->msgs = (bmsg *)calloc(d->n_msgs, sizeof(bmsg));
	for (i = 0; i < d->n_msgs; i++) {
		wrt_tok t = wrt_json_at(&j, bos, i);
		char *dir = wrt_json_strdup(&j, wrt_json_get(&j, t, "dir"));
		ov_msg m;

		if (dir == NULL || ov_msg_load(&m, &j, t) != 0) {
			free(dir);
			wrt_json_free(&j);
			return -1;
		}
		d->msgs[i].conn = (int)ov_int(&j, t, "conn", -1);
		d->msgs[i].c2s = strcmp(dir, "c2s") == 0;
		d->msgs[i].front = m.front; /* ownership moves */
		d->msgs[i].n = m.front_len;
		d->msgs[i].version = m.version;
		d->msgs[i].compat = m.compat;
		d->msgs[i].tid = m.tid;
		free(m.data);
		free(dir);
		if (wri_mbackoff_decode(d->msgs[i].front, d->msgs[i].n, d->msgs[i].version, d->msgs[i].compat, &d->msgs[i].m) != WR_OK) {
			wrt_json_free(&j);
			return -1;
		}
	}
	/* every request of the session is a position the table may be asked about */
	d->pos = (rpos *)calloc(wrt_json_count(&j, exs) + 1u, sizeof(rpos));
	for (k = 0; k < wrt_json_count(&j, exs); k++) {
		wrt_tok e = wrt_json_at(&j, exs, k), rq = wrt_json_get(&j, e, "request"), sum = wrt_json_get(&j, rq, "summary");
		char *oid = wrt_json_strdup(&j, wrt_json_get(&j, sum, "oid"));
		rpos *p = &d->pos[d->n_pos];

		if (oid == NULL || strlen(oid) >= sizeof(p->oid)) {
			free(oid);
			continue;
		}
		p->pool = ov_int(&j, sum, "pool", -1);
		p->seed = (uint32_t)ov_int(&j, sum, "seed", 0);
		p->hash = (uint32_t)ov_int(&j, sum, "hash", 0);
		p->oid_len = (uint32_t)strlen(oid);
		memcpy(p->oid, oid, p->oid_len + 1u);
		p->resent = wrt_json_get(&j, e, "resends") != WRT_NONE;
		d->n_pos++;
		free(oid);
	}
	wrt_json_free(&j);
	return 0;
}

/* The model of the note: a live BLOCK of the position's PG whose range holds it. */
static int model_held(const sess_data *d, const size_t *live, size_t n_live, const rpos *p)
{
	size_t i;
	wri_hobj pos;

	wri_hobj_of_request(&pos, p->pool, p->hash, NULL, 0, (const uint8_t *)p->oid, p->oid_len);
	for (i = 0; i < n_live; i++) {
		const wri_mbackoff *b = &d->msgs[live[i]].m;

		if (b->pool == p->pool && b->pg_seed == p->seed && wri_mbackoff_covers(b, &pos))
			return 1;
	}
	return 0;
}

static int same_pg_live(const sess_data *d, const size_t *live, size_t n_live, const rpos *p)
{
	size_t i;

	for (i = 0; i < n_live; i++)
		if (d->msgs[live[i]].m.pool == p->pool && d->msgs[live[i]].m.pg_seed == p->seed)
			return 1;
	return 0;
}

typedef struct totals {
	unsigned conns, blocks, acks_equal, unblocks, checks, held_resent;
} totals;

/* One connection of the capture played into a fresh table with `slots` backoff entries. */
static void replay_conn(sess_data *d, int conn, unsigned slots, totals *t, const char *name)
{
	static osr R;
	size_t *live = (size_t *)calloc(d->n_msgs + 1u, sizeof(size_t));
	size_t n_live = 0, i, k, acks_seen = 0, blocks = 0, unblocks = 0;
	uint32_t S;
	int exact = slots >= 32u;
	unsigned n_unblock_before;

	memset(&R, 0, sizeof(R));
	if (osr_init(&R, 3, 2048, slots) != 0) {
		WRT_CHECK(0);
		free(live);
		return;
	}
	S = osr_get(&R, 1, ALL_FEATURES);
	WRT_CHECK(S != WRI_NIL);
	if (S == WRI_NIL) {
		osr_free(&R);
		free(live);
		return;
	}
	for (i = 0; i < d->n_msgs; i++) {
		bmsg *m = &d->msgs[i];

		if (m->conn != conn)
			continue;
		if (m->c2s) {
			/* what the stock client sent: the table must have sent exactly this when it got the BLOCK */
			if (m->m.op == WRI_BACKOFF_ACK_BLOCK && exact) {
				const fk_sent *a;

				WRT_CHECK(acks_seen < R.f.n_sent && acks_seen < 16u);
				if (acks_seen < R.f.n_sent && acks_seen < 16u) {
					a = &R.f.sent[acks_seen];
					WRT_CHECK(a->slot == R.t.s[S].conn_slot && a->m.type == WRI_MSG_OSD_BACKOFF && a->m.priority == WRI_MSG_PRIO_CLIENT &&
						  a->m.version == 1u && a->m.compat_version == 1u && a->m.data_len == 0u);
					WRT_CHECK(a->front_len == m->n && memcmp(a->front, m->front, m->n) == 0);
					t->acks_equal++;
				}
				acks_seen++;
			}
			continue;
		}
		n_unblock_before = R.r.n_unblock;
		WRT_CHECK_STATUS(WR_OK, osr_frame(&R, S, WRI_MSG_OSD_BACKOFF, m->tid, m->version, m->compat, m->front, (uint32_t)m->n, NULL, 0, NULL, 0, NULL));
		if (m->m.op == WRI_BACKOFF_BLOCK) {
			live[n_live++] = i;
			blocks++;
			t->blocks++;
		} else if (m->m.op == WRI_BACKOFF_UNBLOCK) {
			size_t at = n_live;

			for (k = 0; k < n_live; k++)
				if (d->msgs[live[k]].m.id == m->m.id)
					at = k;
			WRT_CHECK(at < n_live); /* the capture never unblocks what it did not block */
			if (at < n_live) {
				live[at] = live[--n_live];
			}
			unblocks++;
			t->unblocks++;
			/* no lost wake-up: the request layer is told to send this PG again, whatever became of the entry */
			WRT_CHECK(R.r.n_unblock > n_unblock_before);
			{
				unsigned u, hit = 0;

				for (u = n_unblock_before; u < R.r.n_unblock && u < FK_LOG; u++)
					if (R.r.unblock[u].s == S && R.r.unblock[u].pool == m->m.pool && R.r.unblock[u].pg == m->m.pg_seed)
						hit = 1;
				WRT_CHECK(hit);
			}
			if (exact)
				WRT_CHECK(R.r.n_unblock == n_unblock_before + 1u); /* once, with the table big enough */
		}
		/* every position of the capture: held exactly when the model says (exact table), never without a live BLOCK of its PG (any table) */
		for (k = 0; k < d->n_pos; k++) {
			rpos *p = &d->pos[k];
			int want = model_held(d, live, n_live, p);
			int got = wri_osd_sess_blocked(&R.t, S, p->pool, p->seed, p->hash, (const uint8_t *)p->oid, p->oid_len);

			if (exact) {
				if (got != want)
					fprintf(stderr, "%s conn %d message %zu: position %s of PG %u: table says %d, the note says %d\n", name, conn, i, p->oid, p->seed,
						got, want);
				WRT_CHECK(got == want);
			} else {
				if (got != 0 && !same_pg_live(d, live, n_live, p))
					fprintf(stderr, "%s conn %d message %zu: %s held with no live BLOCK of its PG\n", name, conn, i, p->oid);
				WRT_CHECK(got == 0 || same_pg_live(d, live, n_live, p));
			}
			if (got != 0 && !p->seen_held) {
				p->seen_held = 1;
				t->held_resent += p->resent;
			}
			t->checks++;
		}
	}
	/* the connection's capture ended with every BLOCK unblocked: nothing is left, the table's own counters agree */
	WRT_CHECK(n_live == 0 && R.t.s[S].n_backoff == 0u);
	WRT_CHECK(R.t.n_backoff_blocks == blocks && blocks == unblocks);
	if (exact)
		WRT_CHECK(R.t.n_backoff_noack == 0u && acks_seen == blocks && R.f.n_sent == blocks);
	WRT_CHECK(R.t.n_backoff_noack == 0u && R.f.n_send == blocks);
	/* a connection lost with a BLOCK standing clears the table (the OSD forgets the backoffs of a dead connection) */
	if (blocks > 0) {
		const bmsg *first = NULL;

		for (i = 0; i < d->n_msgs; i++)
			if (d->msgs[i].conn == conn && !d->msgs[i].c2s && d->msgs[i].m.op == WRI_BACKOFF_BLOCK) {
				first = &d->msgs[i];
				break;
			}
		if (first != NULL) {
			WRT_CHECK_STATUS(WR_OK, osr_frame(&R, S, WRI_MSG_OSD_BACKOFF, first->tid, first->version, first->compat, first->front, (uint32_t)first->n, NULL,
							 0, NULL, 0, NULL));
			WRT_CHECK(R.t.s[S].n_backoff == 1u);
			osr_closed(&R, S, WR_E_NET_CLOSED);
			WRT_CHECK(R.t.s[S].n_backoff == 0u);
		}
	}
	t->conns++;
	osr_free(&R);
	free(live);
}

static void replay_session(const char *name, totals *t)
{
	sess_data d;
	int conns[16], n_conns = 0, c;
	size_t i, k;
	static const unsigned sizes[] = {64u, 4u, 2u, 1u};

	if (sd_load(&d, name) != 0) {
		fprintf(stderr, "cannot load %s\n", name);
		WRT_CHECK(0);
		return;
	}
	for (i = 0; i < d.n_msgs; i++) {
		for (c = 0; c < n_conns; c++)
			if (conns[c] == d.msgs[i].conn)
				break;
		if (c == n_conns && n_conns < 16)
			conns[n_conns++] = d.msgs[i].conn;
	}
	WRT_CHECK(n_conns >= 3);
	for (k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++)
		for (c = 0; c < n_conns; c++)
			replay_conn(&d, conns[c], sizes[k], t, name);
	/* the requests the stock client had to send again were each held at some moment: that is why they had to */
	for (i = 0; i < d.n_pos; i++)
		if (d.pos[i].resent)
			WRT_CHECK(d.pos[i].seen_held);
	sd_free(&d);
}

int main(void)
{
	totals t;

	memset(&t, 0, sizeof(t));
	if (!ov_present())
		WRT_SKIP("harness/vectors/public/osdc is not in this tree (the lab captures of module vectors-c)");
	replay_session("backoff-restart", &t);
	replay_session("backoff-out", &t);
	fprintf(stderr, "osd.vec_backoff: %u connection replays (4 table sizes), %u BLOCKs and %u UNBLOCKs, %u ACK_BLOCKs equal to the stock client's, "
			"%u position checks, %u resent requests seen held\n",
		t.conns, t.blocks, t.unblocks, t.acks_equal, t.checks, t.held_resent);
	WRT_CHECK(t.conns >= 24 && t.blocks >= 4u * 46u && t.acks_equal >= 46u && t.checks >= 4000u && t.held_resent >= 8u);
	return wrt_finish();
}
