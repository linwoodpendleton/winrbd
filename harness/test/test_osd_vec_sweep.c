/* SPDX-License-Identifier: MIT */
/*
 * test_osd_vec_sweep - the captured bytes of module vectors-c (harness/vectors/public/osdc/) as the seed of an attack on the OSD message
 * code of core/src/osd (wri_osd_msg.h): the replay (test_osd_vec_replay.c) shows that the code reads what a real OSD wrote; this test shows
 * what it does with the same bytes after somebody damaged them, and what it refuses to write when it is asked for something an OSD
 * would answer EINVAL for.
 *
 * Replies and backoffs: every captured MOSDOpReply front and MOSDBackoff front is copied into an allocation of exactly its size and then
 * (a) every byte set to seven other values, (b) every four-byte window set to the lengths and counts that break arithmetic (0xffffffff,
 * 0x7fffffff, 0x80000000, 0x10000, 0x100), (c) cut at every length, (d) lengthened. The decoder must never read outside the copy (the
 * sanitizer builds are the proof), leave a cleared output when it fails, and, when it succeeds, give an output that holds together: at most 8
 * operations, output lengths that add up to out_total, strings inside the input and within their limits, a backoff whose ACK_BLOCK encodes
 * into exactly wri_mbackoff_ack_len bytes, decodes again to the same block and is refused one byte short; the order of hobject positions is
 * antisymmetric and the range test agrees with it at the two edges.
 * SPARSE_READ and STAT outputs: the same damage over the captured outputs and over synthetic tables (0, 1, 3, 64 and 65 extents, the
 * last byte of the request, a 64-bit offset), each judged against several request windows; the extents that come back are ascending,
 * disjoint, inside the window and add up to the data; one byte off either end of the window is refused.
 * Requests: every captured request is encoded into a buffer one byte shorter at every length (WR_E_TOOBIG, nothing past the buffer), and
 * each refusal rule of wri_mosdop_encode is exercised on a captured request: it must give the documented status, write nothing and leave
 * the buffer as it was; a read carries no snapshot context whatever it was given.
 * The vectors are not part of a source archive without harness/vectors/public/osdc: then the test skips with its reason.
 */
#include "osdc_vec_rig.h"

#define PSEUDO_MAX_FRONT 8192u

/* ---- what the sweeps collect from the captures ---------------------------------------------------------------------------------- */

typedef struct blob {
	uint8_t *p;
	size_t n;
	uint16_t version, compat;
} blob;

typedef struct blobs {
	blob *v;
	size_t n, cap;
} blobs;

static void blobs_add(blobs *b, const uint8_t *p, size_t n, uint16_t version, uint16_t compat)
{
	if (b->n == b->cap) {
		b->cap = b->cap != 0 ? b->cap * 2 : 64;
		b->v = (blob *)realloc(b->v, b->cap * sizeof(blob));
	}
	b->v[b->n].p = (uint8_t *)malloc(n != 0 ? n : 1);
	memcpy(b->v[b->n].p, p, n);
	b->v[b->n].n = n;
	b->v[b->n].version = version;
	b->v[b->n].compat = compat;
	b->n++;
}

static void blobs_free(blobs *b)
{
	size_t i;

	for (i = 0; i < b->n; i++)
		free(b->v[i].p);
	free(b->v);
	memset(b, 0, sizeof(*b));
}

typedef struct sparse_case {
	uint8_t *out;
	uint32_t n;
	uint64_t off, len;
} sparse_case;

typedef struct world {
	blobs replies, backoffs, stats;
	ov_req *reqs;
	ov_msg *req_msgs;
	size_t n_reqs, cap_reqs;
	sparse_case *sparse;
	size_t n_sparse, cap_sparse;
} world;

static void world_add_req(world *w, const wrt_json *j, wrt_tok t)
{
	ov_msg m;
	ov_req q;

	if (ov_msg_load(&m, j, t) != 0 || ov_req_build(&q, j, m.summary, (uint8_t)m.version) != 0) {
		WRT_CHECK(0);
		return;
	}
	if (w->n_reqs == w->cap_reqs) {
		w->cap_reqs = w->cap_reqs != 0 ? w->cap_reqs * 2 : 64;
		w->reqs = (ov_req *)realloc(w->reqs, w->cap_reqs * sizeof(ov_req));
		w->req_msgs = (ov_msg *)realloc(w->req_msgs, w->cap_reqs * sizeof(ov_msg));
	}
	w->reqs[w->n_reqs] = q;
	/* the copy must not point into the stack variable it came from */
	w->reqs[w->n_reqs].snapc.snaps = w->reqs[w->n_reqs].snaps;
	w->reqs[w->n_reqs].h.snapc = &w->reqs[w->n_reqs].snapc;
	w->reqs[w->n_reqs].h.oid = (const uint8_t *)w->reqs[w->n_reqs].oid;
	w->reqs[w->n_reqs].h.nspace = (const uint8_t *)w->reqs[w->n_reqs].nspace;
	w->req_msgs[w->n_reqs] = m;
	w->n_reqs++;
}

static void world_add_sparse(world *w, const uint8_t *out, uint32_t n, uint64_t off, uint64_t len)
{
	if (w->n_sparse == w->cap_sparse) {
		w->cap_sparse = w->cap_sparse != 0 ? w->cap_sparse * 2 : 16;
		w->sparse = (sparse_case *)realloc(w->sparse, w->cap_sparse * sizeof(sparse_case));
	}
	w->sparse[w->n_sparse].out = (uint8_t *)malloc(n != 0 ? n : 1);
	memcpy(w->sparse[w->n_sparse].out, out, n);
	w->sparse[w->n_sparse].n = n;
	w->sparse[w->n_sparse].off = off;
	w->sparse[w->n_sparse].len = len;
	w->n_sparse++;
}

static void world_free(world *w)
{
	size_t i;

	blobs_free(&w->replies);
	blobs_free(&w->backoffs);
	blobs_free(&w->stats);
	for (i = 0; i < w->n_reqs; i++) {
		ov_req_free(&w->reqs[i]);
		ov_msg_free(&w->req_msgs[i]);
	}
	for (i = 0; i < w->n_sparse; i++)
		free(w->sparse[i].out);
	free(w->reqs);
	free(w->req_msgs);
	free(w->sparse);
	memset(w, 0, sizeof(*w));
}

static void collect_session(world *w, const char *name)
{
	char rel[160];
	wrt_json j;
	wrt_tok exs, bos;
	size_t k, r;

	snprintf(rel, sizeof(rel), "sessions/%s.json", name);
	if (ov_load(&j, rel) != 0) {
		WRT_CHECK(0);
		return;
	}
	exs = wrt_json_get(&j, wrt_json_root(&j), "exchanges");
	bos = wrt_json_get(&j, wrt_json_root(&j), "backoffs");
	for (k = 0; exs != WRT_NONE && k < wrt_json_count(&j, exs); k++) {
		wrt_tok e = wrt_json_at(&j, exs, k), rq = wrt_json_get(&j, e, "request"), rp = wrt_json_get(&j, e, "reply");
		wrt_tok resends = wrt_json_get(&j, e, "resends");
		ov_msg rep;

		world_add_req(w, &j, rq);
		for (r = 0; resends != WRT_NONE && r < wrt_json_count(&j, resends); r++)
			world_add_req(w, &j, wrt_json_at(&j, resends, r));
		if (rp != WRT_NONE && ov_msg_load(&rep, &j, rp) == 0) {
			wrt_tok sops = wrt_json_get(&j, wrt_json_get(&j, rq, "summary"), "ops"), pops = wrt_json_get(&j, rep.summary, "ops");
			size_t i, off = 0;

			blobs_add(&w->replies, rep.front, rep.front_len, rep.version, rep.compat);
			/* the operation outputs of the reply: every SPARSE_READ and STAT output is a case of its own */
			for (i = 0; i < wrt_json_count(&j, pops) && i < wrt_json_count(&j, sops); i++) {
				wrt_tok so = wrt_json_at(&j, sops, i);
				uint32_t n = (uint32_t)ov_int(&j, wrt_json_at(&j, pops, i), "out_len", 0);
				uint16_t code = (uint16_t)ov_int(&j, so, "code", 0);

				if (rep.data != NULL && off + n <= rep.data_len && (int32_t)ov_int(&j, rep.summary, "result", -1) >= 0) {
					if (code == WRI_OSD_OP_SPARSE_READ)
						world_add_sparse(w, rep.data + off, n, (uint64_t)ov_int(&j, so, "off", 0), (uint64_t)ov_int(&j, so, "len", 0));
					else if (code == WRI_OSD_OP_STAT)
						blobs_add(&w->stats, rep.data + off, n, 0, 0);
				}
				off += n;
			}
			ov_msg_free(&rep);
		}
	}
	for (k = 0; bos != WRT_NONE && k < wrt_json_count(&j, bos); k++) {
		ov_msg m;

		if (ov_msg_load(&m, &j, wrt_json_at(&j, bos, k)) == 0)
			blobs_add(&w->backoffs, m.front, m.front_len, m.version, m.compat);
		else
			WRT_CHECK(0);
		ov_msg_free(&m);
	}
	wrt_json_free(&j);
}

/* ---- the damage ------------------------------------------------------------------------------------------------------------------- */

typedef void (*probe_fn)(const uint8_t *buf, size_t n, void *ctx);

/* `w` is an allocation of exactly n bytes: every probe reads it through a pointer whose last valid byte is w[n - 1]. */
static void damage(uint8_t *w, size_t n, probe_fn probe, void *ctx)
{
	static const uint8_t byte_vals[] = {0x00, 0x01, 0x7f, 0x80, 0xff};
	static const uint32_t word_vals[] = {0xffffffffu, 0x7fffffffu, 0x80000000u, 0x00010000u, 0x00000100u};
	size_t i, k;

	for (i = 0; i < n; i++) {
		uint8_t orig = w[i];

		for (k = 0; k < sizeof(byte_vals); k++) {
			w[i] = byte_vals[k];
			probe(w, n, ctx);
		}
		w[i] = (uint8_t)(orig ^ 0x01u);
		probe(w, n, ctx);
		w[i] = (uint8_t)(orig ^ 0x80u);
		probe(w, n, ctx);
		w[i] = orig;
	}
	for (i = 0; i + 4 <= n; i++) {
		uint8_t save[4];

		memcpy(save, w + i, 4);
		for (k = 0; k < sizeof(word_vals) / sizeof(word_vals[0]); k++) {
			uint32_t v = word_vals[k];

			w[i] = (uint8_t)v;
			w[i + 1] = (uint8_t)(v >> 8);
			w[i + 2] = (uint8_t)(v >> 16);
			w[i + 3] = (uint8_t)(v >> 24);
			probe(w, n, ctx);
		}
		memcpy(w + i, save, 4);
	}
	for (k = 0; k < n; k++) { /* cut at every length, each in an allocation of its own size */
		uint8_t *c = (uint8_t *)malloc(k != 0 ? k : 1);

		memcpy(c, w, k);
		probe(c, k, ctx);
		free(c);
	}
	for (k = 1; k <= 25; k += 24) { /* trailing bytes: one, and the length of a trace block */
		uint8_t *c = (uint8_t *)malloc(n + k);

		memcpy(c, w, n);
		memset(c + n, 0x5a, k);
		probe(c, n + k, ctx);
		free(c);
	}
	probe(w, n, ctx); /* and the original, last: the damage above put everything back */
}

typedef struct sweep_stats {
	unsigned long accepted, refused;
} sweep_stats;

/* ---- MOSDOpReply ------------------------------------------------------------------------------------------------------------------ */

typedef struct reply_ctx {
	uint16_t version, compat;
	sweep_stats st;
} reply_ctx;

static void reply_probe(const uint8_t *buf, size_t n, void *vctx)
{
	reply_ctx *c = (reply_ctx *)vctx;
	wri_mosdopreply r, zero;
	wr_status st;
	uint64_t sum = 0;
	unsigned i;

	memset(&r, 0xa5, sizeof(r)); /* the decoder must set every byte of its output, success or not */
	memset(&zero, 0, sizeof(zero));
	st = wri_mosdopreply_decode(buf, n, c->version, c->compat, &r);
	if (st != WR_OK) {
		WRT_CHECK(memcmp(&r, &zero, sizeof(r)) == 0);
		c->st.refused++;
		return;
	}
	c->st.accepted++;
	WRT_CHECK(r.n_ops <= WRI_OSD_OPS_MAX);
	for (i = 0; i < WRI_OSD_OPS_MAX; i++) {
		if (i < r.n_ops)
			sum += r.out_len[i];
		else
			WRT_CHECK(r.op_code[i] == 0 && r.out_len[i] == 0 && r.rval[i] == 0);
	}
	WRT_CHECK(sum == r.out_total); /* the sum cannot wrap: 8 operations of 32 bits */
	WRT_CHECK(r.oid_len <= WRI_OSD_NAME_LIMIT);
	if (r.oid_len != 0)
		WRT_CHECK(r.oid >= buf && r.oid + r.oid_len <= buf + n);
	WRT_CHECK(r.do_redirect <= 1u);
	/* version and compat are judged first and exactly */
	WRT_CHECK(c->version == WRI_MOSDOPREPLY_VERSION && c->compat <= WRI_MOSDOPREPLY_VERSION);
}

static void sweep_replies(const world *w)
{
	size_t i;
	reply_ctx c;
	wri_mosdopreply r;

	memset(&c, 0, sizeof(c));
	for (i = 0; i < w->replies.n; i++) {
		const blob *b = &w->replies.v[i];
		uint8_t *copy = (uint8_t *)malloc(b->n);

		memcpy(copy, b->p, b->n);
		c.version = b->version;
		c.compat = b->compat;
		damage(copy, b->n, reply_probe, &c);
		free(copy);
	}
	fprintf(stderr, "osd.vec_sweep: %zu reply fronts damaged: %lu decoded, %lu refused\n", w->replies.n, c.st.accepted, c.st.refused);
	WRT_CHECK(c.st.accepted > w->replies.n && c.st.refused > 100u * w->replies.n);
	/* the version words are checked before a byte is read: any other version or a compat above 8 is WR_E_OSD_VERSION and clears the output */
	for (i = 0; i < w->replies.n && i < 8; i++) {
		const blob *b = &w->replies.v[i];
		static const uint16_t bad_ver[] = {0, 1, 6, 7, 9, 10, 0xffffu};
		unsigned k;

		for (k = 0; k < sizeof(bad_ver) / sizeof(bad_ver[0]); k++) {
			memset(&r, 0xa5, sizeof(r));
			WRT_CHECK_STATUS(WR_E_OSD_VERSION, wri_mosdopreply_decode(b->p, b->n, bad_ver[k], 2, &r));
			WRT_CHECK(r.n_ops == 0 && r.oid == NULL && r.out_total == 0);
		}
		memset(&r, 0xa5, sizeof(r));
		WRT_CHECK_STATUS(WR_E_OSD_VERSION, wri_mosdopreply_decode(b->p, b->n, 8, 9, &r));
		WRT_CHECK(r.n_ops == 0 && r.oid == NULL);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mosdopreply_decode(b->p, b->n, 8, 2, NULL));
	}
}

/* ---- MOSDBackoff ------------------------------------------------------------------------------------------------------------------ */

typedef struct bo_ctx {
	uint16_t version, compat;
	sweep_stats st;
	unsigned long blocks_acked;
} bo_ctx;

static int sgn(int v)
{
	return v < 0 ? -1 : v > 0 ? 1 : 0;
}

static int str_in(const uint8_t *buf, size_t n, const uint8_t *p, uint32_t len)
{
	return len == 0 || (p >= buf && p + len <= buf + n);
}

static int hobj_same(const wri_hobj *a, const wri_hobj *b)
{
	return a->key_len == b->key_len && a->oid_len == b->oid_len && a->nspace_len == b->nspace_len &&
	       (a->key_len == 0 || memcmp(a->key, b->key, a->key_len) == 0) && (a->oid_len == 0 || memcmp(a->oid, b->oid, a->oid_len) == 0) &&
	       (a->nspace_len == 0 || memcmp(a->nspace, b->nspace, a->nspace_len) == 0) && a->snap == b->snap && a->hash == b->hash &&
	       a->max == b->max && a->pool == b->pool;
}

static void backoff_probe(const uint8_t *buf, size_t n, void *vctx)
{
	bo_ctx *c = (bo_ctx *)vctx;
	wri_mbackoff b, zero;
	wr_status st;
	int cmp_be;

	memset(&b, 0xa5, sizeof(b));
	memset(&zero, 0, sizeof(zero));
	st = wri_mbackoff_decode(buf, n, c->version, c->compat, &b);
	if (st != WR_OK) {
		WRT_CHECK(memcmp(&b, &zero, sizeof(b)) == 0);
		c->st.refused++;
		return;
	}
	c->st.accepted++;
	WRT_CHECK(b.op >= WRI_BACKOFF_BLOCK && b.op <= WRI_BACKOFF_UNBLOCK);
	WRT_CHECK(b.begin.key_len <= WRI_OSD_NAME_LIMIT && b.begin.oid_len <= WRI_OSD_NAME_LIMIT && b.begin.nspace_len <= 256u);
	WRT_CHECK(b.end.key_len <= WRI_OSD_NAME_LIMIT && b.end.oid_len <= WRI_OSD_NAME_LIMIT && b.end.nspace_len <= 256u);
	WRT_CHECK(str_in(buf, n, b.begin.key, b.begin.key_len) && str_in(buf, n, b.begin.oid, b.begin.oid_len) &&
		  str_in(buf, n, b.begin.nspace, b.begin.nspace_len));
	WRT_CHECK(str_in(buf, n, b.end.key, b.end.key_len) && str_in(buf, n, b.end.oid, b.end.oid_len) &&
		  str_in(buf, n, b.end.nspace, b.end.nspace_len));
	WRT_CHECK(b.begin.max <= 1u && b.end.max <= 1u);
	WRT_CHECK(wri_mbackoff_ack_len(&b) <= WRI_MBACKOFF_FIXED_LEN + 2u * (2048u + 2048u + 256u));
	/* the order: reflexive, antisymmetric; the range test agrees with it at the two edges */
	cmp_be = wri_hobj_cmp(&b.begin, &b.end);
	WRT_CHECK(wri_hobj_cmp(&b.begin, &b.begin) == 0 && wri_hobj_cmp(&b.end, &b.end) == 0);
	WRT_CHECK(sgn(cmp_be) == -sgn(wri_hobj_cmp(&b.end, &b.begin)));
	WRT_CHECK(wri_mbackoff_covers(&b, &b.begin) == (cmp_be <= 0 ? 1 : 0));
	WRT_CHECK(wri_mbackoff_covers(&b, &b.end) == (cmp_be == 0 ? 1 : 0));
	if (b.op != WRI_BACKOFF_BLOCK) {
		uint8_t ack[2048];
		wri_wr w;

		wri_wr_init(&w, ack, sizeof(ack));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mbackoff_encode_ack(&w, &b));
		WRT_CHECK(wri_wr_len(&w) == 0 && wri_wr_ok(&w));
		return;
	}
	/* a BLOCK is answered by an ACK_BLOCK that decodes to the same block with another op, in exactly ack_len bytes */
	{
		size_t need = wri_mbackoff_ack_len(&b), at;
		uint8_t *ack = (uint8_t *)malloc(need + 1u);
		wri_wr w;
		wri_mbackoff b2;

		WRT_CHECK(ack != NULL);
		if (ack == NULL)
			return;
		wri_wr_init(&w, ack, need);
		WRT_CHECK_STATUS(WR_OK, wri_mbackoff_encode_ack(&w, &b));
		WRT_CHECK(wri_wr_len(&w) == need);
		memset(&b2, 0xa5, sizeof(b2));
		WRT_CHECK_STATUS(WR_OK, wri_mbackoff_decode(ack, need, 1, 1, &b2));
		WRT_CHECK(b2.op == WRI_BACKOFF_ACK_BLOCK && b2.id == b.id && b2.pool == b.pool && b2.pg_seed == b.pg_seed && b2.map_epoch == b.map_epoch);
		WRT_CHECK(hobj_same(&b2.begin, &b.begin) && hobj_same(&b2.end, &b.end));
		/* never an ACK of an ACK */
		wri_wr_init(&w, ack, need);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mbackoff_encode_ack(&w, &b2));
		/* one byte short, at the end and anywhere else, is TOOBIG and the byte past the buffer is not touched */
		for (at = 0; at < need; at += need > 40 ? need / 13 : 1) {
			wri_wr_init(&w, ack, at);
			ack[at] = 0xc3;
			WRT_CHECK_STATUS(WR_E_TOOBIG, wri_mbackoff_encode_ack(&w, &b));
			WRT_CHECK(ack[at] == 0xc3);
		}
		free(ack);
		c->blocks_acked++;
	}
}

static void sweep_backoffs(const world *w)
{
	size_t i;
	bo_ctx c;

	memset(&c, 0, sizeof(c));
	for (i = 0; i < w->backoffs.n; i++) {
		const blob *b = &w->backoffs.v[i];
		uint8_t *copy = (uint8_t *)malloc(b->n);

		memcpy(copy, b->p, b->n);
		c.version = b->version;
		c.compat = b->compat;
		/* every other message version / compat is refused before a byte is read */
		{
			wri_mbackoff x;

			memset(&x, 0xa5, sizeof(x));
			WRT_CHECK_STATUS(WR_E_OSD_VERSION, wri_mbackoff_decode(copy, b->n, 0, 1, &x));
			WRT_CHECK(x.id == 0 && x.pool == 0);
			WRT_CHECK_STATUS(WR_E_OSD_VERSION, wri_mbackoff_decode(copy, b->n, 1, 2, &x));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_mbackoff_decode(copy, b->n, 1, 1, NULL));
		}
		damage(copy, b->n, backoff_probe, &c);
		free(copy);
	}
	fprintf(stderr, "osd.vec_sweep: %zu backoff fronts damaged: %lu decoded, %lu refused, %lu BLOCKs answered and decoded again\n", w->backoffs.n,
		c.st.accepted, c.st.refused, c.blocks_acked);
	WRT_CHECK(c.st.accepted > w->backoffs.n && c.st.refused > 100u * w->backoffs.n && c.blocks_acked > w->backoffs.n / 4u);
}

/* ---- the order of positions against a model written from the note ----------------------------------------------------------------- */

static uint32_t rev_loop(uint32_t v)
{
	uint32_t r = 0;
	int i;

	for (i = 0; i < 32; i++) {
		r = (r << 1) | (v & 1u);
		v >>= 1;
	}
	return r;
}

static int cmp_str(const uint8_t *a, uint32_t al, const uint8_t *b, uint32_t bl)
{
	uint32_t n = al < bl ? al : bl;
	int c = n != 0 ? memcmp(a, b, n) : 0;

	if (c != 0)
		return c < 0 ? -1 : 1;
	return al < bl ? -1 : al > bl ? 1 : 0;
}

/* osd-ops.md 2.10: the max flag, the pool, the hash with its bits reversed, the namespace, the effective key (the key, or the name when the key
 * is empty), the name, the snapshot id; the first difference wins. Two max positions sort equal (their hash is not part of the order). */
static int model_cmp(const wri_hobj *a, const wri_hobj *b)
{
	const uint8_t *ka = a->key_len != 0 ? a->key : a->oid, *kb = b->key_len != 0 ? b->key : b->oid;
	uint32_t kal = a->key_len != 0 ? a->key_len : a->oid_len, kbl = b->key_len != 0 ? b->key_len : b->oid_len;
	int c;

	if (a->max != b->max)
		return a->max != 0 ? 1 : -1;
	if (a->pool != b->pool)
		return a->pool < b->pool ? -1 : 1;
	if (a->max == 0 && rev_loop(a->hash) != rev_loop(b->hash))
		return rev_loop(a->hash) < rev_loop(b->hash) ? -1 : 1;
	c = cmp_str(a->nspace, a->nspace_len, b->nspace, b->nspace_len);
	if (c != 0)
		return c;
	c = cmp_str(ka, kal, kb, kbl);
	if (c != 0)
		return c;
	c = cmp_str(a->oid, a->oid_len, b->oid, b->oid_len);
	if (c != 0)
		return c;
	return a->snap < b->snap ? -1 : a->snap > b->snap ? 1 : 0;
}

static void sweep_order(const world *w)
{
	enum { MAXH = 900 };
	wri_hobj *h = (wri_hobj *)calloc(MAXH, sizeof(*h));
	size_t n = 0, i, j, b;
	unsigned long pairs = 0;
	static const uint8_t ns_a[] = "a", ns_zz[] = "zz", key_k[] = "k", key_a[] = "a", name_x[] = "x";
	static const uint64_t snaps[] = {0, 1, 0x1f, WRI_SNAP_NOSNAP, 0xffffffffffffffffull};

	WRT_CHECK(h != NULL);
	if (h == NULL)
		return;
	/* the positions of the lab: both ends of every block, the position of every request */
	for (b = 0; b < w->backoffs.n && n + 2u < MAXH / 2u; b++) {
		wri_mbackoff x;

		if (wri_mbackoff_decode(w->backoffs.v[b].p, w->backoffs.v[b].n, w->backoffs.v[b].version, w->backoffs.v[b].compat, &x) == WR_OK) {
			h[n++] = x.begin;
			h[n++] = x.end;
		}
	}
	for (i = 0; i < w->n_reqs && n < MAXH / 2u; i += 2) {
		const ov_req *q = &w->reqs[i];

		wri_hobj_of_request(&h[n++], q->h.pool, q->h.hash, q->h.nspace, q->h.nspace_len, q->h.oid, q->h.oid_len);
	}
	/* and every position changed in one field at a time: pool, hash (low and high bit), namespace, key, name, snapshot, max */
	{
		size_t base = n;

		for (i = 0; i < base && n + 12u < MAXH; i += (base > 60 ? base / 60 : 1)) {
			wri_hobj t = h[i];
			unsigned k;

			t.pool = h[i].pool + 1;
			h[n++] = t;
			t = h[i];
			t.pool = h[i].pool - 1;
			h[n++] = t;
			t = h[i];
			t.hash ^= 1u;
			h[n++] = t;
			t = h[i];
			t.hash ^= 0x80000000u;
			h[n++] = t;
			t = h[i];
			t.nspace = ns_a;
			t.nspace_len = 1;
			h[n++] = t;
			t = h[i];
			t.nspace = ns_zz;
			t.nspace_len = 2;
			h[n++] = t;
			t = h[i];
			t.key = key_k;
			t.key_len = 1;
			h[n++] = t;
			t = h[i];
			t.key = key_a;
			t.key_len = 1;
			h[n++] = t;
			t = h[i];
			t.oid = name_x;
			t.oid_len = 1;
			h[n++] = t;
			for (k = 0; k < sizeof(snaps) / sizeof(snaps[0]) && n < MAXH; k++) {
				t = h[i];
				t.snap = snaps[k];
				h[n++] = t;
			}
		}
	}
	WRT_CHECK(n > 300);
	for (i = 0; i < n; i++)
		for (j = 0; j < n; j++) {
			int got = wri_hobj_cmp(&h[i], &h[j]), want = model_cmp(&h[i], &h[j]);

			if (sgn(got) != want) {
				fprintf(stderr, "wri_hobj_cmp(%zu, %zu) = %d, the model of the note says %d\n", i, j, got, want);
				WRT_CHECK(0);
				goto done;
			}
			pairs++;
		}
	/* the range test is the order: a position is inside when begin <= pos < end */
	for (b = 0; b < w->backoffs.n; b += 3) {
		wri_mbackoff x;

		if (wri_mbackoff_decode(w->backoffs.v[b].p, w->backoffs.v[b].n, w->backoffs.v[b].version, w->backoffs.v[b].compat, &x) != WR_OK)
			continue;
		for (j = 0; j < n; j += 3) {
			int in = model_cmp(&x.begin, &x.end) == 0 ? model_cmp(&h[j], &x.begin) == 0
								  : (model_cmp(&x.begin, &h[j]) <= 0 && model_cmp(&h[j], &x.end) < 0);

			WRT_CHECK(wri_mbackoff_covers(&x, &h[j]) == in);
			pairs++;
		}
	}
done:
	fprintf(stderr, "osd.vec_sweep: %zu positions, %lu comparisons and range tests equal to the model of the note\n", n, pairs);
	free(h);
}

/* ---- replies of every operation count, made by hand ------------------------------------------------------------------------------- */

static void put_le(uint8_t *b, size_t *at, uint64_t v, unsigned nbytes)
{
	unsigned k;

	for (k = 0; k < nbytes; k++)
		b[(*at)++] = (uint8_t)(v >> (8 * k));
}

/* A reply front of osd-ops.md 2.9: `records` operation records and rvals while the count field says `count`. */
static size_t build_reply(uint8_t *b, size_t cap, uint32_t oid_len, uint32_t count, uint32_t records, uint32_t payload, int redirect)
{
	size_t at = 0, k;

	(void)cap;
	put_le(b, &at, oid_len, 4);
	for (k = 0; k < oid_len; k++)
		b[at++] = 'o';
	put_le(b, &at, 1, 1);          /* pg_t version */
	put_le(b, &at, 2, 8);          /* pool */
	put_le(b, &at, 7, 4);          /* seed */
	put_le(b, &at, 0xffffffffu, 4); /* retired preferred field */
	put_le(b, &at, 0x24, 8);       /* flags */
	put_le(b, &at, 0, 4);          /* result */
	put_le(b, &at, 0, 8);
	put_le(b, &at, 0, 4);          /* bad_replay_version */
	put_le(b, &at, 9, 4);          /* epoch */
	put_le(b, &at, count, 4);
	for (k = 0; k < records; k++) {
		put_le(b, &at, WRI_OSD_OP_READ, 2);
		put_le(b, &at, 0, 4);
		memset(b + at, 0, 28);
		at += 28;
		put_le(b, &at, payload, 4);
	}
	put_le(b, &at, 0, 4); /* retry_attempt */
	for (k = 0; k < records; k++)
		put_le(b, &at, 0, 4);
	memset(b + at, 0, 12); /* replay_version */
	at += 12;
	put_le(b, &at, 5, 8); /* user_version */
	put_le(b, &at, redirect ? 1u : 0u, 1);
	if (redirect) { /* request_redirect_t: struct v1 compat 1 with an object_locator_t, a name and a retired u32 inside it, all empty here */
		put_le(b, &at, 1, 1);
		put_le(b, &at, 1, 1);
		put_le(b, &at, 8, 4);
		memset(b + at, 0, 8);
		at += 8;
	}
	memset(b + at, 0, 24); /* trace */
	at += 24;
	return at;
}

static void sweep_built_replies(void)
{
	static uint8_t big[PSEUDO_MAX_FRONT];
	uint32_t n;
	wri_mosdopreply r;
	size_t len;

	for (n = 0; n <= 70; n++) {
		len = build_reply(big, sizeof(big), 3, n, n, 4, 0);
		memset(&r, 0xa5, sizeof(r));
		if (n <= WRI_OSD_OPS_MAX) {
			WRT_CHECK_STATUS(WR_OK, wri_mosdopreply_decode(big, len, 8, 2, &r));
			WRT_CHECK(r.n_ops == n && r.out_total == 4ull * n && r.oid_len == 3 && r.pg_seed == 7 && r.pool == 2 && r.map_epoch == 9);
		} else { /* the arrays hold 8: nine records with all their bytes present are still refused, whatever number the OSD says */
			WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_mosdopreply_decode(big, len, 8, 2, &r));
			WRT_CHECK(r.n_ops == 0 && r.out_total == 0);
		}
	}
	/* a count that claims more than is there, and the hostile counts: refused */
	len = build_reply(big, sizeof(big), 3, 3, 2, 4, 0);
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_mosdopreply_decode(big, len, 8, 2, &r));
	len = build_reply(big, sizeof(big), 3, 0xffffffffu, 8, 4, 0);
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_mosdopreply_decode(big, len, 8, 2, &r));
	len = build_reply(big, sizeof(big), 3, 0x80000000u, 8, 4, 0);
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_mosdopreply_decode(big, len, 8, 2, &r));
	/* eight operations that each announce 4 GiB - 1 of output: the sum is kept in 64 bits, the caller compares it with the data segment */
	len = build_reply(big, sizeof(big), 3, 8, 8, 0xffffffffu, 0);
	WRT_CHECK_STATUS(WR_OK, wri_mosdopreply_decode(big, len, 8, 2, &r));
	WRT_CHECK(r.out_total == 8ull * 0xffffffffull && r.out_total > 0xffffffffull);
	/* the object name: 2048 bytes is the limit, 2049 is refused */
	len = build_reply(big, sizeof(big), WRI_OSD_NAME_LIMIT, 1, 1, 0, 0);
	WRT_CHECK_STATUS(WR_OK, wri_mosdopreply_decode(big, len, 8, 2, &r));
	WRT_CHECK(r.oid_len == WRI_OSD_NAME_LIMIT);
	len = build_reply(big, sizeof(big), WRI_OSD_NAME_LIMIT + 1u, 1, 1, 0, 0);
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_mosdopreply_decode(big, len, 8, 2, &r));
	len = build_reply(big, sizeof(big), 0, 1, 1, 0, 0);
	WRT_CHECK_STATUS(WR_OK, wri_mosdopreply_decode(big, len, 8, 2, &r)); /* an empty name echoes an empty name: not this decoder's judgement */
	/* a redirect is detected, its body skipped by its length, and the trace block must still follow it */
	len = build_reply(big, sizeof(big), 3, 1, 1, 0, 1);
	WRT_CHECK_STATUS(WR_OK, wri_mosdopreply_decode(big, len, 8, 2, &r));
	WRT_CHECK(r.do_redirect == 1u && r.n_ops == 1u);
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_mosdopreply_decode(big, len - 1u, 8, 2, &r));
	WRT_CHECK(r.do_redirect == 0 && r.n_ops == 0);
	/* and the pg_t version byte: only 1 is a pg_t of this note */
	len = build_reply(big, sizeof(big), 3, 1, 1, 0, 0);
	big[4 + 3] = 2;
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_mosdopreply_decode(big, len, 8, 2, &r));
}

/* ---- SPARSE_READ and STAT outputs ------------------------------------------------------------------------------------------------ */

typedef struct sparse_ctx {
	uint64_t off, len;
	sweep_stats st;
} sparse_ctx;

static void sparse_judge(const uint8_t *buf, uint32_t n, uint64_t off, uint64_t len, uint32_t ext_max, sweep_stats *st)
{
	wri_osd_extent ext[WRI_OSD_SPARSE_EXT_MAX + 2u];
	uint32_t n_ext = 0xa5a5u, data_off = 0xa5a5u, data_len = 0xa5a5u, i;
	uint64_t sum = 0, edge = off;
	wr_status s;

	memset(ext, 0, sizeof(ext));
	s = wri_osd_sparse_decode(buf, n, off, len, ext_max != 0 ? ext : NULL, ext_max, &n_ext, &data_off, &data_len);
	if (s != WR_OK) {
		WRT_CHECK(n_ext == 0 && data_off == 0 && data_len == 0);
		for (i = 0; i < WRI_OSD_SPARSE_EXT_MAX + 2u; i++)
			WRT_CHECK(ext[i].off == 0 && ext[i].len == 0);
		WRT_CHECK(s == WR_E_OSD_PROTO || s == WR_E_TOOBIG);
		st->refused++;
		return;
	}
	st->accepted++;
	WRT_CHECK(n_ext <= ext_max && n_ext <= WRI_OSD_SPARSE_EXT_MAX);
	for (i = 0; i < n_ext; i++) {
		WRT_CHECK(ext[i].off >= edge && ext[i].off - off <= len && ext[i].len <= len - (ext[i].off - off)); /* ascending, disjoint, inside */
		edge = ext[i].off + ext[i].len;
		sum += ext[i].len;
	}
	WRT_CHECK(sum == data_len && (uint64_t)data_off + data_len == n);
	for (; i < WRI_OSD_SPARSE_EXT_MAX + 2u; i++)
		WRT_CHECK(ext[i].off == 0 && ext[i].len == 0); /* nothing past the table is written */
}

static void sparse_probe(const uint8_t *buf, size_t n, void *vctx)
{
	sparse_ctx *c = (sparse_ctx *)vctx;

	/* several windows: the real request, one byte narrower at each end, one byte wider, a window that wraps nothing, a tiny one */
	sparse_judge(buf, (uint32_t)n, c->off, c->len, WRI_OSD_SPARSE_EXT_MAX, &c->st);
	if (c->len > 1) {
		sparse_judge(buf, (uint32_t)n, c->off, c->len - 1, WRI_OSD_SPARSE_EXT_MAX, &c->st);
		sparse_judge(buf, (uint32_t)n, c->off + 1, c->len - 1, WRI_OSD_SPARSE_EXT_MAX, &c->st);
	}
	sparse_judge(buf, (uint32_t)n, c->off, c->len + 1, 3, &c->st);
	sparse_judge(buf, (uint32_t)n, 0, UINT64_MAX, WRI_OSD_SPARSE_EXT_MAX, &c->st);
	sparse_judge(buf, (uint32_t)n, UINT64_MAX - 7u, 7, WRI_OSD_SPARSE_EXT_MAX, &c->st);
}

/* a table of `count` extents of `step` bytes each starting at `first`, then the data */
static uint32_t sparse_build(uint8_t *out, uint32_t cap, uint32_t count, uint64_t first, uint64_t len_each, uint64_t gap)
{
	uint32_t pos = 0, i, k;
	uint64_t at = first;
	uint64_t total = len_each * count;

	for (k = 0; k < 4; k++)
		out[pos++] = (uint8_t)(count >> (8 * k));
	for (i = 0; i < count; i++) {
		for (k = 0; k < 8; k++)
			out[pos++] = (uint8_t)(at >> (8 * k));
		for (k = 0; k < 8; k++)
			out[pos++] = (uint8_t)(len_each >> (8 * k));
		at += len_each + gap;
	}
	for (k = 0; k < 4; k++)
		out[pos++] = (uint8_t)(total >> (8 * k));
	for (i = 0; i < total && pos < cap; i++)
		out[pos++] = (uint8_t)(i * 7u + 1u);
	return pos;
}

static void sweep_sparse(const world *w)
{
	sparse_ctx c;
	size_t i;
	static const struct {
		uint32_t count;
		uint64_t first, each, gap, req_off, req_len;
	} syn[] = {
		{0, 0, 0, 0, 0, 4096},      {1, 0, 4096, 0, 0, 4096},       {1, 100, 8, 0, 100, 8},   {3, 0, 16, 16, 0, 256},
		{3, 4096, 3, 1, 4096, 20}, {64, 0, 4, 4, 0, 512},           {65, 0, 4, 4, 0, 1024},   {2, UINT64_MAX - 15u, 4, 4, UINT64_MAX - 15u, 15},
	};

	memset(&c, 0, sizeof(c));
	for (i = 0; i < w->n_sparse; i++) {
		const sparse_case *sc = &w->sparse[i];
		uint8_t *copy = (uint8_t *)malloc(sc->n);

		memcpy(copy, sc->out, sc->n);
		c.off = sc->off;
		c.len = sc->len;
		damage(copy, sc->n, sparse_probe, &c);
		free(copy);
	}
	for (i = 0; i < sizeof(syn) / sizeof(syn[0]); i++) {
		uint8_t buf[2048];
		uint32_t n = sparse_build(buf, sizeof(buf), syn[i].count, syn[i].first, syn[i].each, syn[i].gap);
		uint8_t *copy = (uint8_t *)malloc(n);

		memcpy(copy, buf, n);
		c.off = syn[i].req_off;
		c.len = syn[i].req_len;
		damage(copy, n, sparse_probe, &c);
		free(copy);
	}
	fprintf(stderr, "osd.vec_sweep: %zu captured and %zu synthetic SPARSE_READ outputs damaged: %lu decoded, %lu refused\n", w->n_sparse,
		sizeof(syn) / sizeof(syn[0]), c.st.accepted, c.st.refused);
	WRT_CHECK(c.st.accepted > 100u && c.st.refused > 1000u);
	/* one byte off either end of the window, on the real captured tables */
	for (i = 0; i < w->n_sparse; i++) {
		const sparse_case *sc = &w->sparse[i];
		wri_osd_extent ext[WRI_OSD_SPARSE_EXT_MAX];
		uint32_t n_ext, doff, dlen;
		uint64_t last_end;

		uint32_t want;

		WRT_CHECK_STATUS(WR_OK, wri_osd_sparse_decode(sc->out, sc->n, sc->off, sc->len, ext, WRI_OSD_SPARSE_EXT_MAX, &n_ext, &doff, &dlen));
		want = n_ext;
		if (want == 0)
			continue;
		last_end = ext[want - 1u].off + ext[want - 1u].len;
		WRT_CHECK_STATUS(WR_OK, wri_osd_sparse_decode(sc->out, sc->n, ext[0].off, last_end - ext[0].off, ext, WRI_OSD_SPARSE_EXT_MAX, &n_ext, &doff, &dlen));
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_osd_sparse_decode(sc->out, sc->n, ext[0].off, last_end - ext[0].off - 1, ext, WRI_OSD_SPARSE_EXT_MAX, &n_ext, &doff, &dlen));
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_osd_sparse_decode(sc->out, sc->n, ext[0].off + 1, last_end - ext[0].off - 1, ext, WRI_OSD_SPARSE_EXT_MAX, &n_ext, &doff, &dlen));
		/* the caller's table is the limit: one slot short is TOOBIG (nothing stored), exactly enough is fine */
		{
			WRT_CHECK_STATUS(WR_E_TOOBIG, wri_osd_sparse_decode(sc->out, sc->n, sc->off, sc->len, NULL, 0, &n_ext, &doff, &dlen));
			WRT_CHECK(n_ext == 0 && doff == 0 && dlen == 0);
			WRT_CHECK_STATUS(WR_E_TOOBIG, wri_osd_sparse_decode(sc->out, sc->n, sc->off, sc->len, ext, want - 1u, &n_ext, &doff, &dlen));
			WRT_CHECK_STATUS(WR_OK, wri_osd_sparse_decode(sc->out, sc->n, sc->off, sc->len, ext, want, &n_ext, &doff, &dlen));
			WRT_CHECK(n_ext == want);
		}
	}
	/* STAT: exactly 16 bytes, every other length is a protocol error and clears the results */
	for (i = 0; i < w->stats.n; i++) {
		const blob *b = &w->stats.v[i];
		uint64_t size = 1, sec = 1;
		uint32_t s32 = 1, ns32 = 1, k;
		uint8_t *copy = (uint8_t *)malloc(b->n + 32u);

		memcpy(copy, b->p, b->n);
		WRT_CHECK(b->n == 16u);
		for (k = 0; k < b->n + 17u; k++) {
			wr_status s;
			uint8_t *exact = (uint8_t *)malloc(k != 0 ? k : 1);

			memset(exact, 0x33, k);
			memcpy(exact, copy, k < b->n ? k : b->n);
			size = 1;
			s32 = 1;
			ns32 = 1;
			s = wri_osd_stat_decode(exact, k, &size, &s32, &ns32);
			if (k == 16u) {
				WRT_CHECK_STATUS(WR_OK, s);
			} else {
				WRT_CHECK_STATUS(WR_E_OSD_PROTO, s);
				WRT_CHECK(size == 0 && s32 == 0 && ns32 == 0);
			}
			free(exact);
		}
		(void)sec;
		free(copy);
	}
}

/* ---- requests --------------------------------------------------------------------------------------------------------------------- */

static void req_copy(ov_req *dst, const ov_req *src)
{
	*dst = *src;
	dst->snapc.snaps = dst->snaps;
	dst->h.snapc = &dst->snapc;
	dst->h.oid = (const uint8_t *)src->oid;
	dst->h.nspace = (const uint8_t *)src->nspace;
}

/* An encode that must be refused: the status, nothing written, the buffer as it was. */
static void expect_refused(const wri_mosdop_hdr *h, const wri_osd_opd *ops, unsigned n_ops, wr_status want, const char *what)
{
	uint8_t buf[PSEUDO_MAX_FRONT], ref[PSEUDO_MAX_FRONT];
	wri_wr w;
	wr_status st;

	memset(buf, 0x5a, sizeof(buf));
	memcpy(ref, buf, sizeof(buf));
	wri_wr_init(&w, buf, sizeof(buf));
	st = wri_mosdop_encode(&w, h, ops, n_ops);
	if (st != want)
		fprintf(stderr, "wri_mosdop_encode (%s): %s, wanted %s\n", what, wrt_status_name_((int32_t)st), wrt_status_name_((int32_t)want));
	WRT_CHECK(st == want);
	WRT_CHECK(wri_wr_len(&w) == 0 && wri_wr_ok(&w));
	WRT_CHECK(memcmp(buf, ref, sizeof(buf)) == 0);
}

static int is_write(const ov_req *q)
{
	unsigned i;

	for (i = 0; i < q->n_ops; i++)
		if ((q->ops[i].code & 0x2000u) != 0)
			return 1;
	return 0;
}

static void sweep_requests(const world *w)
{
	static uint8_t longname[3000];
	size_t i;
	unsigned writes = 0, reads = 0, with_snaps = 0;

	memset(longname, 'a', sizeof(longname));
	for (i = 0; i < w->n_reqs; i++) {
		const ov_req *q0 = &w->reqs[i];
		ov_req q;
		uint8_t front[PSEUDO_MAX_FRONT];
		wri_wr wr;
		size_t n, k;
		int wrt = is_write(q0);

		req_copy(&q, q0);
		wri_wr_init(&wr, front, sizeof(front));
		WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&wr, &q.h, q.ops, q.n_ops));
		n = wri_wr_len(&wr);
		WRT_CHECK(n == w->req_msgs[i].front_len && memcmp(front, w->req_msgs[i].front, n) == 0);
		WRT_CHECK(wri_mosdop_front_max(q.h.oid_len, q.h.nspace_len, q.n_ops, q.snapc.n) >= n);
		wrt ? writes++ : reads++;
		with_snaps += wrt && q.snapc.n != 0;
		/* every shorter buffer: TOOBIG, and the bytes behind the buffer are not touched */
		for (k = 0; k < n; k += (k + 1 < n && n > 200 && k > 8 ? 3 : 1)) {
			uint8_t *buf = (uint8_t *)malloc(k + 8u);
			size_t j;
			wri_wr sw;

			memset(buf, 0xc3, k + 8u);
			wri_wr_init(&sw, buf, k);
			WRT_CHECK_STATUS(WR_E_TOOBIG, wri_mosdop_encode(&sw, &q.h, q.ops, q.n_ops));
			for (j = k; j < k + 8u; j++)
				WRT_CHECK(buf[j] == 0xc3);
			free(buf);
		}
		/* the RETRY flag follows retry_attempt and nothing else */
		{
			ov_req v;
			uint8_t f2[PSEUDO_MAX_FRONT];
			wri_wr w2;

			req_copy(&v, q0);
			v.h.flags |= WRI_OSDF_RETRY;
			v.h.retry_attempt = 0;
			wri_wr_init(&w2, f2, sizeof(f2));
			if (q0->h.retry_attempt == 0) { /* RETRY asked for by the caller, no retry: the encoder takes it away */
				WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w2, &v.h, v.ops, v.n_ops));
				WRT_CHECK(wri_wr_len(&w2) == n && memcmp(f2, front, n) == 0);
			}
			req_copy(&v, q0);
			v.h.flags &= ~WRI_OSDF_RETRY;
			wri_wr_init(&w2, f2, sizeof(f2));
			WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w2, &v.h, v.ops, v.n_ops));
			WRT_CHECK(wri_wr_len(&w2) == n && memcmp(f2, front, n) == 0); /* with or without the bit from the caller: the same bytes */
		}
		/* the refusal rules, each on this very request */
		{
			ov_req v;
			wri_osd_opd many[WRI_OSD_OPS_MAX + 1u];
			unsigned m;

			req_copy(&v, q0);
			v.h.oid_len = 0;
			expect_refused(&v.h, v.ops, v.n_ops, WR_E_RANGE, "empty object name");
			req_copy(&v, q0);
			v.h.oid = longname;
			v.h.oid_len = WRI_OSD_NAME_LIMIT + 1u;
			expect_refused(&v.h, v.ops, v.n_ops, WR_E_RANGE, "name of 2049 bytes");
			req_copy(&v, q0);
			v.h.oid = longname;
			v.h.oid_len = WRI_OSD_NAME_LIMIT;
			{
				uint8_t big[PSEUDO_MAX_FRONT];
				wri_wr bw;

				wri_wr_init(&bw, big, sizeof(big));
				WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&bw, &v.h, v.ops, v.n_ops)); /* 2048 is allowed, and fits wri_mosdop_front_max */
				WRT_CHECK(wri_mosdop_front_max(WRI_OSD_NAME_LIMIT, v.h.nspace_len, v.n_ops, v.snapc.n) >= wri_wr_len(&bw));
			}
			req_copy(&v, q0);
			v.h.nspace = longname;
			v.h.nspace_len = 257;
			expect_refused(&v.h, v.ops, v.n_ops, WR_E_RANGE, "namespace of 257 bytes");
			req_copy(&v, q0);
			v.h.pool = -1;
			expect_refused(&v.h, v.ops, v.n_ops, WR_E_RANGE, "negative pool");
			req_copy(&v, q0);
			v.h.version = 7;
			expect_refused(&v.h, v.ops, v.n_ops, WR_E_UNSUPPORTED, "version 7");
			v.h.version = 10;
			expect_refused(&v.h, v.ops, v.n_ops, WR_E_UNSUPPORTED, "version 10");
			req_copy(&v, q0);
			v.h.retry_attempt = -1;
			expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "retry_attempt below 0");
			req_copy(&v, q0);
			expect_refused(&v.h, v.ops, 0, WR_E_RANGE, "no operations");
			for (m = 0; m < WRI_OSD_OPS_MAX + 1u; m++)
				many[m] = v.ops[0];
			expect_refused(&v.h, many, WRI_OSD_OPS_MAX + 1u, WR_E_RANGE, "nine operations");
			req_copy(&v, q0);
			v.h.oid = NULL;
			expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "no name pointer");
			WRT_CHECK_STATUS(WR_E_INVAL, wri_mosdop_encode(NULL, &v.h, v.ops, v.n_ops));
			{
				uint8_t b2[64];
				wri_wr w2;

				wri_wr_init(&w2, b2, sizeof(b2));
				WRT_CHECK_STATUS(WR_E_INVAL, wri_mosdop_encode(&w2, NULL, v.ops, v.n_ops));
				WRT_CHECK_STATUS(WR_E_INVAL, wri_mosdop_encode(&w2, &v.h, NULL, v.n_ops));
			}
			for (m = 0; m < q0->n_ops; m++) {
				static const uint16_t foreign[] = {0x1220u /* CMPEXT */, 0x2226u /* WRITESAME */, 0x1208u /* ASSERT_VER */, 0x0000u, 0x1204u, 0xffffu};
				unsigned f;

				for (f = 0; f < sizeof(foreign) / sizeof(foreign[0]); f++) {
					req_copy(&v, q0);
					v.ops[m].code = foreign[f];
					expect_refused(&v.h, v.ops, v.n_ops, WR_E_UNSUPPORTED, "operation outside the table");
				}
				if (q0->ops[m].code == WRI_OSD_OP_WRITE || q0->ops[m].code == WRI_OSD_OP_WRITEFULL) {
					req_copy(&v, q0);
					v.ops[m].len += 1; /* the OSD answers EINVAL when extent.length differs from the data it got */
					expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "WRITE whose length differs from its data");
					req_copy(&v, q0);
					v.ops[m].in_len += 1;
					expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "WRITE whose data differs from its length");
				}
				if (q0->ops[m].code == WRI_OSD_OP_CALL) {
					req_copy(&v, q0);
					v.ops[m].in_len = (uint32_t)q0->ops[m].cls_class_len + q0->ops[m].cls_method_len - 1u;
					expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "CALL whose names exceed its input");
				}
			}
			if (wrt) {
				static const uint64_t bad_snapid[] = {0x1fu, 0, 0xfffffffffffffffdull, 0xffffffffffffffffull};
				unsigned s;

				for (s = 0; s < sizeof(bad_snapid) / sizeof(bad_snapid[0]); s++) {
					req_copy(&v, q0);
					v.h.snapid = bad_snapid[s];
					expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "write at a snapshot");
					/* the mutating operation decides, not the READ / WRITE bit of the caller */
					v.h.flags &= ~(uint32_t)WRI_OSDF_WRITE;
					expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "write at a snapshot with the WRITE bit cleared");
				}
				req_copy(&v, q0);
				v.snapc.seq = WRI_SNAP_MAX + 1u;
				expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "snap_seq above the highest snapshot id");
				v.snapc.seq = 0xffffffffffffffffull;
				expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "snap_seq all ones");
				if (q0->snapc.n >= 2u) { /* the captured context is valid: take it apart */
					req_copy(&v, q0);
					v.snaps[0] = v.snapc.seq + 1u; /* newest snapshot above the sequence */
					expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "newest snapshot above snap_seq");
					req_copy(&v, q0);
					v.snaps[1] = v.snaps[0]; /* a repeated id */
					expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "repeated snapshot id");
					req_copy(&v, q0);
					v.snaps[0] = q0->snaps[1]; /* ascending */
					v.snaps[1] = q0->snaps[0];
					expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "ascending snapshot ids");
					req_copy(&v, q0);
					v.snaps[v.snapc.n - 1u] = 0;
					v.snapc.n++;
					v.snaps[v.snapc.n - 1u] = 0; /* 0, 0: an id 0 is never followed by another */
					expect_refused(&v.h, v.ops, v.n_ops, WR_E_INVAL, "id 0 followed by another");
				}
			} else {
				/* a read ignores whatever context it was given and sends seq 0 and no ids: the same bytes as without one */
				static const uint64_t junk[] = {0xffffffffffffffffull, 7};
				ov_req r;
				uint8_t f2[PSEUDO_MAX_FRONT];
				wri_wr w2;

				req_copy(&r, q0);
				r.snapc.seq = junk[0];
				r.snapc.n = 2;
				r.snaps[0] = junk[1];
				r.snaps[1] = junk[1];
				wri_wr_init(&w2, f2, sizeof(f2));
				WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w2, &r.h, r.ops, r.n_ops));
				WRT_CHECK(wri_wr_len(&w2) == n && memcmp(f2, front, n) == 0);
				r.h.snapc = NULL;
				wri_wr_init(&w2, f2, sizeof(f2));
				WRT_CHECK_STATUS(WR_OK, wri_mosdop_encode(&w2, &r.h, r.ops, r.n_ops));
				WRT_CHECK(wri_wr_len(&w2) == n && memcmp(f2, front, n) == 0);
			}
		}
	}
	fprintf(stderr, "osd.vec_sweep: %zu captured requests (%u reads, %u writes, %u with a snapshot context) encoded into every shorter buffer and refused by every rule\n",
		w->n_reqs, reads, writes, with_snaps);
	WRT_CHECK(reads >= 60 && writes >= 40 && with_snaps >= 5);
}

/* ---- the whole set ---------------------------------------------------------------------------------------------------------------- */

int main(void)
{
	wrt_json idx;
	wrt_tok sess;
	world w;
	size_t i;

	if (!ov_present())
		WRT_SKIP("harness/vectors/public/osdc is not in this tree (the lab captures of module vectors-c)");
	memset(&w, 0, sizeof(w));
	if (wrt_json_load_vec(&idx, OV_DIR "INDEX.json") != 0) {
		WRT_CHECK(0);
		return wrt_finish();
	}
	sess = wrt_json_get(&idx, wrt_json_root(&idx), "sessions");
	WRT_CHECK(sess != WRT_NONE);
	for (i = 0; sess != WRT_NONE && i < wrt_json_count(&idx, sess); i++) {
		char *name = wrt_json_strdup(&idx, wrt_json_at(&idx, sess, i));

		if (name != NULL)
			collect_session(&w, name);
		free(name);
	}
	wrt_json_free(&idx);
	WRT_CHECK(w.replies.n >= 130 && w.backoffs.n >= 120 && w.n_reqs >= 170 && w.n_sparse >= 2 && w.stats.n >= 3);
	sweep_replies(&w);
	sweep_backoffs(&w);
	sweep_order(&w);
	sweep_built_replies();
	sweep_sparse(&w);
	sweep_requests(&w);
	world_free(&w);
	return wrt_finish();
}
