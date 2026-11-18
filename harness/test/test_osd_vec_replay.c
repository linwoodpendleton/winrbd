/* SPDX-License-Identifier: MIT */
/*
 * test_osd_vec_replay - the lab captures of module vectors-c (harness/vectors/public/osdc/) through the real OSD message code of
 * core/src/osd (wri_osd_msg.h): what a v20.2.5 OSD and the stock client library put on the wire in crc mode.
 *
 * Requests: every MOSDOp of every session (first transmissions and the resends after a backoff) is rebuilt from its decoded summary
 * and encoded by wri_mosdop_encode; the front must equal the captured one byte for byte (reads, writes, ZERO, TRUNCATE, DELETE,
 * SETALLOCHINT, class calls, a write with a snapshot context, a read of a snapshot, RETRY with retry_attempt above 0).
 * Replies: wri_mosdopreply_decode must give the summary's fields; the operation outputs add up to the data segment; the error
 * mapping of every result; STAT and SPARSE_READ outputs (a real two- and three-extent hole map) decode to what the client library
 * reported at capture time; a short read, a read past the end and a missing object come back as the notes say.
 * Backoffs: BLOCK and UNBLOCK of a whole PG and of one object decode to their summaries; every ACK_BLOCK the client sent equals
 * wri_mbackoff_encode_ack of its BLOCK byte for byte; every request that was held lies inside the BLOCK of its PG
 * (wri_mbackoff_covers, with the bit-reversed hash order) and one that was not does not; begin <= end.
 * The vectors are not part of a source archive without harness/vectors/public/osdc: then the test skips with its reason.
 */
#include "osdc_vec_rig.h"

typedef struct tally {
	unsigned sessions, exchanges, requests, resends, replies, backoffs, acks, blocks_checked, stat_out, sparse_out, errors_mapped;
	unsigned one_object_blocks, pg_blocks, max_end_blocks;
} tally;

static const char *const k_sessions_dir = "sessions/";

/* ---- replies ---------------------------------------------------------------------------------------------------------------------- */

static void check_reply(const wrt_json *j, const char *where, const ov_msg *rq, const ov_msg *rp, wrt_tok probe, tally *t)
{
	wri_mosdopreply r;
	wrt_tok ops, rvals, sops;
	wr_status st;
	size_t i, off = 0;
	char *oid;
	int ok = 0;

	memset(&r, 0, sizeof(r));
	st = wri_mosdopreply_decode(rp->front, rp->front_len, rp->version, rp->compat, &r);
	if (st != WR_OK) {
		fprintf(stderr, "%s: wri_mosdopreply_decode: %s\n", where, wrt_status_name_((int32_t)st));
		WRT_CHECK(st == WR_OK);
		return;
	}
	t->replies++;
	ops = wrt_json_get(j, rp->summary, "ops");
	rvals = wrt_json_get(j, rp->summary, "rvals");
	sops = wrt_json_get(j, rq->summary, "ops");
	oid = wrt_json_strdup(j, wrt_json_get(j, rp->summary, "oid"));
	WRT_CHECK(oid != NULL && r.oid_len == strlen(oid) && memcmp(r.oid, oid, r.oid_len) == 0);
	free(oid);
	WRT_CHECK((int64_t)r.pool == ov_int(j, rp->summary, "pool", -2));
	WRT_CHECK_U64(r.pg_seed, ov_int(j, rp->summary, "seed", -1));
	WRT_CHECK((int64_t)r.flags == ov_int(j, rp->summary, "flags", -1));
	WRT_CHECK((int64_t)r.result == ov_int(j, rp->summary, "result", 1));
	WRT_CHECK_U64(r.map_epoch, ov_int(j, rp->summary, "epoch", -1));
	WRT_CHECK((int64_t)r.retry_attempt == ov_int(j, rp->summary, "retry_attempt", -9));
	WRT_CHECK_U64(r.user_version, ov_u64(j, rp->summary, "user_version"));
	WRT_CHECK(r.do_redirect == 0);
	/* the reply answers THIS request (the last transmission): the same object and PG, the attempt echoed, a reply that ran is ONDISK */
	{
		char *qoid = wrt_json_strdup(j, wrt_json_get(j, rq->summary, "oid"));

		WRT_CHECK(qoid != NULL && r.oid_len == strlen(qoid) && memcmp(r.oid, qoid, r.oid_len) == 0);
		free(qoid);
		WRT_CHECK((int64_t)r.pool == ov_int(j, rq->summary, "pool", -3));
		WRT_CHECK_U64(r.pg_seed, ov_int(j, rq->summary, "seed", -1));
		WRT_CHECK((int64_t)r.retry_attempt == ov_int(j, rq->summary, "retry_attempt", -9));
		WRT_CHECK((r.flags & WRI_OSDF_ONDISK) != 0);
	}
	WRT_CHECK(ops != WRT_NONE && rvals != WRT_NONE);
	WRT_CHECK_U64(r.n_ops, wrt_json_count(j, ops));
	WRT_CHECK_U64(r.n_ops, wrt_json_count(j, rvals));
	WRT_CHECK_U64(r.n_ops, wrt_json_count(j, sops)); /* one echoed record per sent operation, also in a failed message */
	/* the whole data segment is the operations' outputs, nothing else */
	WRT_CHECK_U64(r.out_total, rp->data_total);
	for (i = 0; i < r.n_ops && i < WRI_OSD_OPS_MAX; i++) {
		wrt_tok o = wrt_json_at(j, ops, i), so = wrt_json_at(j, sops, i);
		uint32_t n = r.out_len[i];
		const uint8_t *out = rp->data != NULL ? rp->data + off : NULL;

		uint16_t sent = (uint16_t)ov_int(j, so, "code", 0);

		WRT_CHECK_U64(r.op_code[i], ov_int(j, o, "code", -1));
		WRT_CHECK_U64(n, ov_int(j, o, "out_len", -1));
		WRT_CHECK((int64_t)r.rval[i] == wrt_json_int(j, wrt_json_at(j, rvals, i), &ok) && ok);
		/* the echoed record is the one that was sent, except a ZERO that reached the end of the object (the OSD rewrote it) */
		WRT_CHECK(r.op_code[i] == sent || (sent == WRI_OSD_OP_ZERO && r.op_code[i] == WRI_OSD_OP_TRUNCATE));
		/* what an operation may bring back: nothing from a failed message or from a mutation, at most the bytes asked for by a READ */
		if (r.result < 0 && r.rval[i] == 0)
			WRT_CHECK(n == 0);
		if ((sent & 0x2000u) != 0 && sent != WRI_OSD_OP_CALL)
			WRT_CHECK(n == 0);
		if (sent == WRI_OSD_OP_READ && ov_int(j, so, "len", 0) != 0)
			WRT_CHECK((int64_t)n <= ov_int(j, so, "len", 0));
		if (sent == WRI_OSD_OP_STAT && r.result >= 0)
			WRT_CHECK(n == 16u);
		if (out != NULL && off + n <= rp->data_len) {
			if (r.result >= 0 && sent == WRI_OSD_OP_STAT) {
				uint64_t size = 0;
				uint32_t sec = 0, nsec = 0;

				WRT_CHECK_STATUS(WR_OK, wri_osd_stat_decode(out, n, &size, &sec, &nsec));
				if (probe != WRT_NONE && wrt_json_get(j, probe, "size") != WRT_NONE) {
					WRT_CHECK_U64(size, ov_int(j, probe, "size", -1));
					WRT_CHECK_U64(sec, ov_int(j, probe, "mtime", -1));
				}
				WRT_CHECK(nsec < 1000000000u);
				t->stat_out++;
				/* anything but 16 bytes is a protocol error */
				WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_osd_stat_decode(out, n - 1, &size, &sec, &nsec));
				WRT_CHECK(size == 0 && sec == 0 && nsec == 0);
			}
			if (r.result >= 0 && sent == WRI_OSD_OP_SPARSE_READ) {
				wri_osd_extent ext[WRI_OSD_SPARSE_EXT_MAX];
				uint32_t n_ext = 0, data_off = 0, data_len = 0, k;
				wrt_tok pe = probe != WRT_NONE ? wrt_json_get(j, probe, "extents") : WRT_NONE;

				WRT_CHECK_STATUS(WR_OK, wri_osd_sparse_decode(out, n, (uint64_t)ov_int(j, so, "off", 0), (uint64_t)ov_int(j, so, "len", 0),
									     ext, WRI_OSD_SPARSE_EXT_MAX, &n_ext, &data_off, &data_len));
				WRT_CHECK(data_off + data_len == n);
				if (pe != WRT_NONE) {
					uint64_t sum = 0;

					WRT_CHECK_U64(n_ext, wrt_json_count(j, pe));
					for (k = 0; k < n_ext && k < wrt_json_count(j, pe); k++) {
						wrt_tok e = wrt_json_at(j, pe, k);

						WRT_CHECK_U64(ext[k].off, wrt_json_int(j, wrt_json_at(j, e, 0), &ok));
						WRT_CHECK_U64(ext[k].len, wrt_json_int(j, wrt_json_at(j, e, 1), &ok));
						sum += ext[k].len;
					}
					WRT_CHECK_U64(sum, data_len);
				}
				t->sparse_out++;
				/* a table that is cut anywhere is refused, never read past its end */
				for (k = 0; k < n; k += (n > 64 ? n / 31 : 1)) {
					wri_osd_extent e2[WRI_OSD_SPARSE_EXT_MAX];
					uint32_t a = 0, b = 0, c = 0;

					WRT_CHECK(wri_osd_sparse_decode(out, k, (uint64_t)ov_int(j, so, "off", 0), (uint64_t)ov_int(j, so, "len", 0), e2,
									WRI_OSD_SPARSE_EXT_MAX, &a, &b, &c) != WR_OK);
					WRT_CHECK(a == 0 && b == 0 && c == 0);
				}
			}
		}
		off += n;
	}
	/* every truncation of the front fails, none reads past the end (the decoder is bounds checked against the real bytes) */
	{
		size_t k;

		for (k = 0; k < rp->front_len; k += (rp->front_len > 96 ? 7 : 1)) {
			wri_mosdopreply x;

			WRT_CHECK(wri_mosdopreply_decode(rp->front, k, rp->version, rp->compat, &x) != WR_OK);
			WRT_CHECK(x.n_ops == 0 && x.out_total == 0);
		}
	}
	/* the status of the result, as the request layer will map it */
	if (r.result < 0) {
		wr_status want = r.result == -2 ? WR_E_OSD_NOENT : r.result == -95 ? WR_E_OSD_NOENT : WR_E_OSD_ERRNO;

		WRT_CHECK_STATUS(want, wri_osd_errno_status(r.result));
		t->errors_mapped++;
	} else {
		WRT_CHECK_STATUS(WR_OK, wri_osd_errno_status(r.result));
	}
	(void)where;
}

/* ---- one session ------------------------------------------------------------------------------------------------------------------ */

typedef struct blk {
	ov_msg m;
	wri_mbackoff b;
} blk;

static int hobj_eq(const wrt_json *j, wrt_tok t, const wri_hobj *h)
{
	char *key = wrt_json_strdup(j, wrt_json_get(j, t, "key"));
	char *oid = wrt_json_strdup(j, wrt_json_get(j, t, "oid"));
	char *ns = wrt_json_strdup(j, wrt_json_get(j, t, "nspace"));
	int ok = key != NULL && oid != NULL && ns != NULL && h->key_len == strlen(key) && h->oid_len == strlen(oid) && h->nspace_len == strlen(ns) &&
		 memcmp(h->key, key, h->key_len) == 0 && memcmp(h->oid, oid, h->oid_len) == 0 && memcmp(h->nspace, ns, h->nspace_len) == 0 &&
		 h->snap == ov_u64(j, t, "snap") && h->hash == (uint32_t)ov_int(j, t, "hash", -1) && h->max == (uint8_t)ov_int(j, t, "max", 9) &&
		 h->pool == ov_int(j, t, "pool", -2);

	free(key);
	free(oid);
	free(ns);
	return ok;
}

static void check_backoffs(const wrt_json *j, wrt_tok bos, wrt_tok exs, const char *name, tally *t)
{
	enum { MAXB = 64 };
	blk *blocks = (blk *)calloc(MAXB, sizeof(blk));
	unsigned nb = 0, i, k;
	size_t n = wrt_json_count(j, bos), m;

	WRT_CHECK(blocks != NULL);
	if (blocks == NULL)
		return;
	for (m = 0; m < n; m++) {
		wrt_tok bt = wrt_json_at(j, bos, m);
		ov_msg msg;
		wri_mbackoff b;
		wrt_tok s;
		const char *dir;
		char *dstr = wrt_json_strdup(j, wrt_json_get(j, bt, "dir"));

		dir = dstr != NULL ? dstr : "";
		WRT_CHECK(ov_msg_load(&msg, j, bt) == 0);
		s = msg.summary;
		WRT_CHECK_U64(msg.type, WRI_MSG_OSD_BACKOFF);
		memset(&b, 0, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, wri_mbackoff_decode(msg.front, msg.front_len, msg.version, msg.compat, &b));
		WRT_CHECK(b.pool == ov_int(j, s, "pool", -2));
		WRT_CHECK_U64(b.pg_seed, ov_int(j, s, "seed", -1));
		WRT_CHECK_U64(b.map_epoch, ov_int(j, s, "epoch", -1));
		WRT_CHECK_U64(b.op, ov_int(j, s, "op", -1));
		WRT_CHECK_U64(b.id, ov_u64(j, s, "id"));
		WRT_CHECK(hobj_eq(j, wrt_json_get(j, s, "begin"), &b.begin));
		WRT_CHECK(hobj_eq(j, wrt_json_get(j, s, "end"), &b.end));
		WRT_CHECK(wri_hobj_cmp(&b.begin, &b.end) <= 0); /* in the bit-reversed order, whatever the raw hashes say */
		WRT_CHECK(wri_hobj_cmp(&b.begin, &b.begin) == 0 && wri_hobj_cmp(&b.end, &b.end) == 0);
		WRT_CHECK(wri_hobj_cmp(&b.end, &b.begin) >= 0);
		/* the edges of the range: begin is inside (closed), end is outside (half open), a one-object block is that object only */
		WRT_CHECK(wri_mbackoff_covers(&b, &b.begin) == 1);
		if (wri_hobj_cmp(&b.begin, &b.end) < 0) {
			WRT_CHECK(wri_mbackoff_covers(&b, &b.end) == 0);
		} else {
			wri_hobj other = b.begin;

			other.snap = b.begin.snap ^ 1u; /* not NOSNAP: not the position of a request */
			WRT_CHECK(wri_mbackoff_covers(&b, &other) == 0);
		}
		/* cut at every offset: refused, and nothing half decoded */
		for (i = 0; i < msg.front_len; i += 3) {
			wri_mbackoff x;

			WRT_CHECK(wri_mbackoff_decode(msg.front, i, msg.version, msg.compat, &x) != WR_OK);
			WRT_CHECK(x.id == 0 && x.pool == 0);
		}
		t->backoffs++;
		if (b.op == WRI_BACKOFF_BLOCK) {
			if (wri_hobj_cmp(&b.begin, &b.end) == 0)
				t->one_object_blocks++;
			else
				t->pg_blocks++;
			t->max_end_blocks += b.end.max;
			WRT_CHECK(nb < MAXB);
			if (nb < MAXB) {
				WRT_CHECK(ov_msg_load(&blocks[nb].m, j, bt) == 0);
				WRT_CHECK_STATUS(WR_OK, wri_mbackoff_decode(blocks[nb].m.front, blocks[nb].m.front_len, msg.version, msg.compat, &blocks[nb].b));
				nb++;
			}
			WRT_CHECK(strcmp(dir, "s2c") == 0);
		} else if (b.op == WRI_BACKOFF_ACK_BLOCK) {
			/* the answer to the last BLOCK with this id on this connection */
			int found = 0;

			WRT_CHECK(strcmp(dir, "c2s") == 0);
			for (i = nb; i > 0; i--) {
				const blk *bk = &blocks[i - 1];

				if (bk->b.id == b.id && bk->b.pool == b.pool && bk->b.pg_seed == b.pg_seed) {
					uint8_t buf[2048];
					wri_wr w;

					WRT_CHECK(wri_mbackoff_ack_len(&bk->b) == msg.front_len);
					wri_wr_init(&w, buf, sizeof(buf));
					WRT_CHECK_STATUS(WR_OK, wri_mbackoff_encode_ack(&w, &bk->b));
					WRT_CHECK_U64(wri_wr_len(&w), msg.front_len);
					WRT_CHECK(wri_wr_len(&w) == msg.front_len && memcmp(buf, msg.front, msg.front_len) == 0);
					/* a writer one byte short is TOOBIG, never a short message */
					wri_wr_init(&w, buf, msg.front_len - 1);
					WRT_CHECK_STATUS(WR_E_TOOBIG, wri_mbackoff_encode_ack(&w, &bk->b));
					found = 1;
					break;
				}
			}
			WRT_CHECK(found);
			t->acks++;
		} else {
			int found = 0;

			WRT_CHECK_U64(b.op, WRI_BACKOFF_UNBLOCK);
			WRT_CHECK(strcmp(dir, "s2c") == 0);
			for (i = 0; i < nb; i++)
				if (blocks[i].b.id == b.id && blocks[i].b.pg_seed == b.pg_seed)
					found = 1;
			WRT_CHECK(found);
			/* an ACK of an UNBLOCK is not a thing: encode_ack wants a BLOCK */
			{
				uint8_t buf[2048];
				wri_wr w;

				wri_wr_init(&w, buf, sizeof(buf));
				WRT_CHECK_STATUS(WR_E_INVAL, wri_mbackoff_encode_ack(&w, &b));
			}
		}
		free(dstr);
		ov_msg_free(&msg);
	}
	/* the requests that were held lie inside the BLOCK of their PG; per-object blocks cover that object only */
	for (k = 0; k < wrt_json_count(j, exs); k++) {
		wrt_tok e = wrt_json_at(j, exs, k);
		wrt_tok rq = wrt_json_get(j, e, "request"), rs = wrt_json_get(j, rq, "summary");
		wri_hobj pos;
		char *oid = wrt_json_strdup(j, wrt_json_get(j, rs, "oid"));
		char *ns = wrt_json_strdup(j, wrt_json_get(j, rs, "nspace"));
		int64_t pool = ov_int(j, rs, "pool", -2);
		uint32_t seed = (uint32_t)ov_int(j, rs, "seed", 0), hash = (uint32_t)ov_int(j, rs, "hash", 0);
		int hit = 0;

		if (wrt_json_get(j, e, "resends") == WRT_NONE) {
			free(oid);
			free(ns);
			continue;
		}
		wri_hobj_of_request(&pos, pool, hash, (const uint8_t *)ns, (uint32_t)strlen(ns), (const uint8_t *)oid, (uint32_t)strlen(oid));
		for (i = 0; i < nb; i++) {
			if (blocks[i].b.pool == pool && blocks[i].b.pg_seed == seed && wri_mbackoff_covers(&blocks[i].b, &pos)) {
				hit = 1;
				t->blocks_checked++;
			}
			/* the object next to it (same PG, another name) is covered by a PG-wide block and not by a one-object block */
			if (blocks[i].b.pool == pool && blocks[i].b.pg_seed == seed) {
				wri_hobj other;
				char oname[300];

				snprintf(oname, sizeof(oname), "%sX", oid);
				wri_hobj_of_request(&other, pool, hash, (const uint8_t *)ns, (uint32_t)strlen(ns), (const uint8_t *)oname, (uint32_t)strlen(oname));
				if (wri_hobj_cmp(&blocks[i].b.begin, &blocks[i].b.end) == 0)
					WRT_CHECK(!wri_mbackoff_covers(&blocks[i].b, &other));
			}
		}
		WRT_CHECK(hit);
		if (!hit)
			fprintf(stderr, "%s: exchange %u: a held request (%s) is in no BLOCK\n", name, k + 1u, oid != NULL ? oid : "?");
		free(oid);
		free(ns);
	}
	for (i = 0; i < nb; i++)
		ov_msg_free(&blocks[i].m);
	free(blocks);
}

static void replay_session(const char *name, tally *t)
{
	char rel[160];
	wrt_json j;
	wrt_tok root, exs, bos;
	size_t k, r;
	uint64_t prev_tid = 0;

	snprintf(rel, sizeof(rel), "%s%s.json", k_sessions_dir, name);
	if (ov_load(&j, rel) != 0) {
		fprintf(stderr, "cannot load %s\n", rel);
		WRT_CHECK(0);
		return;
	}
	root = wrt_json_root(&j);
	exs = wrt_json_get(&j, root, "exchanges");
	bos = wrt_json_get(&j, root, "backoffs");
	WRT_CHECK(exs != WRT_NONE);
	t->sessions++;
	for (k = 0; exs != WRT_NONE && k < wrt_json_count(&j, exs); k++) {
		wrt_tok e = wrt_json_at(&j, exs, k);
		wrt_tok resends = wrt_json_get(&j, e, "resends"), rp = wrt_json_get(&j, e, "reply"), probe = wrt_json_get(&j, e, "probe");
		char where[200];
		ov_msg rq, rep;
		ov_req q;
		int have_rep = rp != WRT_NONE && wrt_json_is_string(&j, rp) == 0 && wrt_json_count(&j, rp) > 0;
		const ov_msg *last = &rq;
		ov_msg again[4];
		unsigned na = 0;

		snprintf(where, sizeof(where), "%s #%zu", name, k + 1);
		t->exchanges++;
		/* one client numbers its operations once, upwards (a `rados get` is one client per object: its sessions are exempt) */
		if (strncmp(name, "objects-", 8) != 0) {
			uint64_t tid = (uint64_t)ov_int(&j, wrt_json_get(&j, e, "request"), "tid", 0);

			WRT_CHECK(tid > prev_tid);
			prev_tid = tid;
		}
		memset(&rep, 0, sizeof(rep));
		if (ov_msg_load(&rq, &j, wrt_json_get(&j, e, "request")) != 0) {
			WRT_CHECK(0);
			continue;
		}
		WRT_CHECK_U64(rq.type, WRI_MSG_OSD_OP);
		WRT_CHECK(rq.priority == WRI_MSG_PRIO_CLIENT);
		if (ov_req_build(&q, &j, rq.summary, (uint8_t)rq.version) == 0) {
			WRT_CHECK(q.h.retry_attempt == 0 && (q.h.flags & WRI_OSDF_RETRY) == 0); /* the first transmission */
			WRT_CHECK(ov_req_check(&q, &rq, where) == 0);
			t->requests++;
		} else {
			WRT_CHECK(0);
		}
		/* version 8 is the same message without the 7 otel bytes (a connection of an older release) */
		if (q.h.version == WRI_MOSDOP_VERSION) {
			uint8_t b9[4096], b8[4096];
			wri_wr w9, w8;

			wri_wr_init(&w9, b9, sizeof(b9));
			wri_wr_init(&w8, b8, sizeof(b8));
			WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w9, &q.h, q.ops, q.n_ops));
			q.h.version = WRI_MOSDOP_VERSION_V8;
			WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w8, &q.h, q.ops, q.n_ops));
			WRT_CHECK(wri_wr_len(&w9) == wri_wr_len(&w8) + 7u && memcmp(b9, b8, 87) == 0 && memcmp(b9 + 94, b8 + 87, wri_wr_len(&w8) - 87) == 0);
		}
		ov_req_free(&q);
		WRT_CHECK(resends == WRT_NONE || wrt_json_count(&j, resends) <= 4u); /* the buffer below holds four: the reply is judged against the LAST one */
		for (r = 0; resends != WRT_NONE && r < wrt_json_count(&j, resends) && na < 4; r++) {
			ov_req q2;

			WRT_CHECK(ov_msg_load(&again[na], &j, wrt_json_at(&j, resends, r)) == 0);
			WRT_CHECK(again[na].tid == rq.tid);
			if (ov_req_build(&q2, &j, again[na].summary, (uint8_t)again[na].version) == 0) {
				/* the attempts of one request are 0, 1, 2 ...: every transmission is in the set, and each carries RETRY */
				WRT_CHECK(q2.h.retry_attempt == (int32_t)(r + 1u) && (q2.h.flags & WRI_OSDF_RETRY) != 0);
				WRT_CHECK(ov_req_check(&q2, &again[na], where) == 0);
				t->resends++;
			} else {
				WRT_CHECK(0);
			}
			ov_req_free(&q2);
			last = &again[na];
			na++;
		}
		if (have_rep && ov_msg_load(&rep, &j, rp) == 0) {
			WRT_CHECK_U64(rep.type, WRI_MSG_OSD_OPREPLY);
			WRT_CHECK(rep.tid == last->tid);
			check_reply(&j, where, last, &rep, probe, t);
			ov_msg_free(&rep);
		}
		for (r = 0; r < na; r++)
			ov_msg_free(&again[r]);
		ov_msg_free(&rq);
	}
	if (bos != WRT_NONE)
		check_backoffs(&j, bos, exs, name, t);
	wrt_json_free(&j);
}

/* ---- the whole set ---------------------------------------------------------------------------------------------------------------- */

int main(void)
{
	wrt_json idx;
	wrt_tok sess;
	size_t i;
	tally t;

	memset(&t, 0, sizeof(t));
	if (!ov_present())
		WRT_SKIP("harness/vectors/public/osdc is not in this tree (the lab captures of module vectors-c)");
	if (wrt_json_load_vec(&idx, OV_DIR "INDEX.json") != 0) {
		WRT_CHECK(0);
		return wrt_finish();
	}
	sess = wrt_json_get(&idx, wrt_json_root(&idx), "sessions");
	WRT_CHECK(sess != WRT_NONE);
	for (i = 0; sess != WRT_NONE && i < wrt_json_count(&idx, sess); i++) {
		char *name = wrt_json_strdup(&idx, wrt_json_at(&idx, sess, i));

		if (name != NULL)
			replay_session(name, &t);
		free(name);
	}
	wrt_json_free(&idx);
	fprintf(stderr, "osd.vec_replay: %u sessions, %u exchanges, %u requests and %u resends re-encoded, %u replies decoded (%u STAT, %u SPARSE_READ outputs, "
			"%u error results), %u backoff messages (%u acks, %u PG-range and %u one-object blocks, %u ending at the maximum object, %u held requests placed)\n",
		t.sessions, t.exchanges, t.requests, t.resends, t.replies, t.stat_out, t.sparse_out, t.errors_mapped, t.backoffs, t.acks, t.pg_blocks,
		t.one_object_blocks, t.max_end_blocks, t.blocks_checked);
	/* the lower bounds the set must keep: the replay cannot pass by finding nothing */
	WRT_CHECK(t.sessions >= 15);
	WRT_CHECK(t.requests >= 130 && t.replies >= 130);
	WRT_CHECK(t.resends >= 30);
	WRT_CHECK(t.stat_out >= 3 && t.sparse_out >= 2 && t.errors_mapped >= 8);
	WRT_CHECK(t.backoffs >= 120 && t.acks >= 40 && t.blocks_checked >= 40);
	WRT_CHECK(t.pg_blocks >= 10 && t.one_object_blocks >= 10 && t.max_end_blocks >= 1);
	return wrt_finish();
}
