/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_cls_dec - the output decoders of core/src/rbd/wri_rbd_cls_dec.c (docs/spec/rbd-format2.md 2.3, 2.5, 2.7).
 *
 * Against the committed vectors: every successful call of rbd-class-calls.json is decoded and compared with the fields the capture
 * recorded (`decoded`); the outputs of the CALL operations in the replies of osd-messages.json and of osdop 09 / 10 are cut out by
 * their out_len and decoded; the omap values and the id object of header-omap.json are decoded through the decoder of the call that
 * returns the same bytes. Every decodable output is then cut at every length (the decoder must fail and leave its outputs cleared; the
 * buffers are exact-size heap blocks so the sanitizers see an over-read) and given one extra byte (WR_E_RBD_PROTO).
 * Then the tables the vectors do not have: ids and prefixes (length limits, bytes), snapshot contexts (descending, equal, zero followed
 * by another, seq out of range, more ids than the cap, a count that lies), parent_get built by hand (every field, a later version, an
 * unknown compat), the overlap marker, the lock record with 0, 1, 64 and 65 lockers, every kind of damaged envelope, tag truncation.
 */
#include "wrt.h"

#include "wri_denc.h"
#include "wri_rbd_cls.h"

/* ---- a decoder by kind, with poisoned outputs ------------------------------------------------ */

enum { K_ID, K_SIZE, K_PREFIX, K_FEAT, K_U64, K_I64, K_SNAPC, K_PARENT, K_OVERLAP, K_STRIPE, K_LOCK, K_N };

#define SNAPS_CAP 8u
#define TAG_CAP 16u

typedef struct dres {
	char id[WRI_RBD_ID_MAX];
	char prefix[WRI_RBD_PREFIX_MAX];
	uint8_t order;
	uint64_t size, a, b;
	int64_t i;
	uint8_t has, present;
	uint8_t ltype;
	uint32_t nlock, ntotal;
	char tag[TAG_CAP];
	wri_snapc sc;
	uint64_t snaps[SNAPS_CAP];
} dres;

static void poison(dres *r)
{
	memset(r, 0xa5, sizeof(*r));
	r->sc.cap = SNAPS_CAP;
	r->sc.snaps = r->snaps;
}

static wr_status run_dec(int k, const uint8_t *p, size_t n, dres *r)
{
	poison(r);
	switch (k) {
	case K_ID:
		return wri_rbd_dec_id(p, (uint32_t)n, r->id);
	case K_SIZE:
		return wri_rbd_dec_size(p, (uint32_t)n, &r->order, &r->size);
	case K_PREFIX:
		return wri_rbd_dec_prefix(p, (uint32_t)n, r->prefix);
	case K_FEAT:
		return wri_rbd_dec_features(p, (uint32_t)n, &r->a, &r->b);
	case K_U64:
		return wri_rbd_dec_u64(p, (uint32_t)n, &r->a);
	case K_I64:
		return wri_rbd_dec_i64(p, (uint32_t)n, &r->i);
	case K_SNAPC:
		return wri_rbd_dec_snapcontext(p, (uint32_t)n, &r->sc, &r->ntotal);
	case K_PARENT:
		return wri_rbd_dec_parent(p, (uint32_t)n, &r->has);
	case K_OVERLAP:
		return wri_rbd_dec_overlap(p, (uint32_t)n, &r->present, &r->a);
	case K_STRIPE:
		return wri_rbd_dec_stripe(p, (uint32_t)n, &r->a, &r->b);
	case K_LOCK:
		return wri_rbd_dec_lock_info(p, (uint32_t)n, &r->nlock, &r->ltype, r->tag, sizeof(r->tag));
	default:
		return WR_E_INVAL;
	}
}

/* after a failure every output of the kind is cleared (snapshot context: seq and n zero, the stored ids zero) */
static void check_cleared(int k, const dres *r)
{
	size_t i;

	switch (k) {
	case K_ID:
		for (i = 0; i < sizeof(r->id); i++)
			WRT_CHECK(r->id[i] == 0);
		break;
	case K_SIZE:
		WRT_CHECK(r->order == 0 && r->size == 0);
		break;
	case K_PREFIX:
		for (i = 0; i < sizeof(r->prefix); i++)
			WRT_CHECK(r->prefix[i] == 0);
		break;
	case K_FEAT:
	case K_STRIPE:
		WRT_CHECK(r->a == 0 && r->b == 0);
		break;
	case K_U64:
		WRT_CHECK(r->a == 0);
		break;
	case K_I64:
		WRT_CHECK(r->i == 0);
		break;
	case K_SNAPC:
		WRT_CHECK(r->sc.seq == 0 && r->sc.n == 0 && r->sc.cap == SNAPS_CAP && r->sc.snaps == r->snaps);
		break;
	case K_PARENT:
		WRT_CHECK(r->has == 0);
		break;
	case K_OVERLAP:
		WRT_CHECK(r->present == 0 && r->a == 0);
		break;
	case K_LOCK:
		WRT_CHECK(r->nlock == 0 && r->ltype == 0);
		for (i = 0; i < sizeof(r->tag); i++)
			WRT_CHECK(r->tag[i] == 0);
		break;
	default:
		break;
	}
}

static uint8_t *heap_dup(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n ? n : 1);

	if (q != NULL && n != 0)
		memcpy(q, p, n);
	return q;
}

/* Decode p[0..n) as exact-size heap copy. */
static wr_status dec_heap(int k, const uint8_t *p, size_t n, dres *r)
{
	uint8_t *h = heap_dup(p, n);
	wr_status st;

	if (h == NULL) {
		WRT_CHECK(0);
		return WR_E_BUDGET;
	}
	st = run_dec(k, h, n, r);
	free(h);
	return st;
}

/* The output decodes; cut at every length it fails (cleared); with one more byte it is WR_E_RBD_PROTO. */
static void check_cuts(int k, const uint8_t *p, size_t n)
{
	dres r;
	size_t cut;
	uint8_t *more = (uint8_t *)malloc(n + 1);

	for (cut = 0; cut < n; cut++) {
		wr_status st = dec_heap(k, p, cut, &r);

		if (st == WR_OK) {
			fprintf(stderr, "kind %d: cut at %zu of %zu decoded\n", k, cut, n);
			WRT_CHECK(0);
		} else {
			check_cleared(k, &r);
		}
	}
	WRT_CHECK(more != NULL);
	if (more != NULL) {
		memcpy(more, p, n);
		more[n] = 0;
		WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(k, more, n + 1, &r));
		check_cleared(k, &r);
		free(more);
	}
}

/* ---- the vectors: expected values from the capture ---------------------------------------------- */

static int streq(const char *a, const char *b)
{
	return strcmp(a, b) == 0;
}

static uint64_t jint(const wrt_json *j, wrt_tok t)
{
	char *s = wrt_json_strdup(j, t);
	uint64_t v = 0;

	if (s != NULL) { /* a string (the numbers above 2^53 are kept as strings by the writer of the vectors) */
		v = strtoull(s, NULL, 0);
		free(s);
		return v;
	}
	{
		int ok = 0;
		int64_t x = wrt_json_int(j, t, &ok);

		WRT_CHECK(ok);
		return (uint64_t)x;
	}
}

/* The kind of decoder for a vector (class, method), or -1. */
static int kind_of(const char *cls, const char *meth)
{
	if (streq(cls, "lock"))
		return streq(meth, "get_info") ? K_LOCK : -1;
	if (!streq(cls, "rbd"))
		return -1;
	if (streq(meth, "get_id") || streq(meth, "dir_get_id"))
		return K_ID;
	if (streq(meth, "get_size"))
		return K_SIZE;
	if (streq(meth, "get_object_prefix"))
		return K_PREFIX;
	if (streq(meth, "get_features"))
		return K_FEAT;
	if (streq(meth, "get_flags") || streq(meth, "op_features_get"))
		return K_U64;
	if (streq(meth, "get_data_pool"))
		return K_I64;
	if (streq(meth, "get_snapcontext"))
		return K_SNAPC;
	if (streq(meth, "parent_get"))
		return K_PARENT;
	if (streq(meth, "parent_overlap_get"))
		return K_OVERLAP;
	if (streq(meth, "get_stripe_unit_count"))
		return K_STRIPE;
	return -1;
}

static void check_vector(const wrt_json *j, wrt_tok v, const char *meth, int k, const uint8_t *out, size_t n)
{
	wrt_tok d = wrt_json_get(j, v, "decoded");
	dres r;
	wr_status st = dec_heap(k, out, n, &r);
	char *sv;

	WRT_CHECK_STATUS(WR_OK, st);
	if (st != WR_OK || d == WRT_NONE)
		return;
	switch (k) {
	case K_ID:
		sv = wrt_json_strdup(j, wrt_json_get(j, d, streq(meth, "dir_get_id") ? "id" : "value"));
		WRT_CHECK(sv != NULL && strcmp(sv, r.id) == 0);
		free(sv);
		break;
	case K_SIZE:
		WRT_CHECK_U64(r.order, jint(j, wrt_json_get(j, d, "order")));
		WRT_CHECK_U64(r.size, jint(j, wrt_json_get(j, d, "size")));
		break;
	case K_PREFIX:
		sv = wrt_json_strdup(j, wrt_json_get(j, d, "value"));
		WRT_CHECK(sv != NULL && strcmp(sv, r.prefix) == 0);
		free(sv);
		break;
	case K_FEAT:
		WRT_CHECK_U64(r.a, jint(j, wrt_json_get(j, d, "features")));
		WRT_CHECK_U64(r.b, jint(j, wrt_json_get(j, d, "incompatible")));
		break;
	case K_U64:
		WRT_CHECK_U64(r.a, jint(j, wrt_json_get(j, d, streq(meth, "get_flags") ? "flags" : "op_features")));
		break;
	case K_I64:
		WRT_CHECK_U64(r.i, jint(j, wrt_json_get(j, d, "pool")));
		break;
	case K_SNAPC: {
		wrt_tok sn = wrt_json_get(j, d, "snaps");
		size_t i;

		WRT_CHECK_U64(r.sc.seq, jint(j, wrt_json_get(j, d, "seq")));
		WRT_CHECK_U64(r.sc.n, wrt_json_count(j, sn));
		WRT_CHECK_U64(r.ntotal, wrt_json_count(j, sn));
		for (i = 0; i < wrt_json_count(j, sn) && i < r.sc.n; i++)
			WRT_CHECK_U64(r.sc.snaps[i], jint(j, wrt_json_at(j, sn, i)));
		break;
	}
	case K_PARENT: {
		wrt_tok pp = wrt_json_get(j, d, "parent");
		char *img = wrt_json_strdup(j, wrt_json_get(j, pp, "image_id"));
		int64_t pool = (int64_t)jint(j, wrt_json_get(j, pp, "pool"));
		uint64_t snap = jint(j, wrt_json_get(j, pp, "snap"));
		/* the JSON helper reads 2^64 - 2 (NOSNAP) as INT64_MAX: both mean "no snapshot" */
		int want = pool >= 0 && img != NULL && img[0] != 0 && snap != WRI_SNAP_NOSNAP && snap != (uint64_t)INT64_MAX;

		WRT_CHECK_U64(r.has, want);
		free(img);
		break;
	}
	case K_OVERLAP:
		WRT_CHECK_U64(r.present, 1);
		WRT_CHECK_U64(r.a, jint(j, wrt_json_get(j, d, "overlap")));
		break;
	case K_STRIPE:
		WRT_CHECK_U64(r.a, jint(j, wrt_json_get(j, d, "stripe_unit")));
		WRT_CHECK_U64(r.b, jint(j, wrt_json_get(j, d, "stripe_count")));
		break;
	case K_LOCK: {
		wrt_tok info = wrt_json_get(j, d, "info");

		sv = wrt_json_strdup(j, wrt_json_get(j, info, "tag"));
		WRT_CHECK_U64(r.nlock, wrt_json_count(j, wrt_json_get(j, info, "lockers")));
		WRT_CHECK_U64(r.ltype, jint(j, wrt_json_get(j, info, "type")));
		WRT_CHECK(sv != NULL && strcmp(sv, r.tag) == 0);
		free(sv);
		break;
	}
	default:
		break;
	}
}

static void test_class_call_vectors(void)
{
	wrt_json j;
	wrt_tok vs;
	size_t i, decoded = 0, refused = 0;
	size_t per_kind[K_N] = {0};
	int k;

	if (wrt_json_load_vec(&j, "rbd/rbd-class-calls.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	vs = wrt_json_get(&j, wrt_json_root(&j), "vectors");
	for (i = 0; i < wrt_json_count(&j, vs); i++) {
		wrt_tok v = wrt_json_at(&j, vs, i);
		char *cls = wrt_json_strdup(&j, wrt_json_get(&j, v, "class"));
		char *meth = wrt_json_strdup(&j, wrt_json_get(&j, v, "method"));
		uint8_t *out = NULL;
		size_t n = 0;
		int ok = 0;
		int64_t result = wrt_json_int(&j, wrt_json_get(&j, v, "result"), &ok);

		WRT_CHECK(cls != NULL && meth != NULL && ok);
		WRT_CHECK(wrt_json_get_hex(&j, v, "output_hex", &out, &n) == 0);
		if (cls != NULL && meth != NULL && out != NULL) {
			k = kind_of(cls, meth);
			if (k >= 0 && result >= 0) {
				check_vector(&j, v, meth, k, out, n);
				check_cuts(k, out, n);
				decoded++;
				per_kind[k]++;
			} else if (k >= 0) {
				dres r; /* an error reply has no output: every decoder refuses the empty output */
				WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(k, out, n, &r));
				refused++;
			}
		}
		free(cls);
		free(meth);
		free(out);
	}
	printf("class-call outputs decoded: %zu, empty outputs refused: %zu\n", decoded, refused);
	for (k = 0; k < K_N; k++)
		WRT_CHECK(per_kind[k] >= 1);
	WRT_CHECK(decoded >= 50);
	WRT_CHECK(refused >= 4);
	wrt_json_free(&j);
}

/* ---- osd-messages.json and osdop 09 / 10: outputs cut out of reply data segments --------------- */

static const char *const k_known_rbd[] = {"get_id", "get_size", "get_object_prefix", "get_features", "get_flags", "get_snapcontext",
					  "get_data_pool", "parent_get", "parent_overlap_get", "get_stripe_unit_count",
					  "op_features_get", "get_create_timestamp", "get_access_timestamp", "get_modify_timestamp",
					  "metadata_list", "image_group_get", "snapshot_get_limit", "object_map_update", "dir_get_id",
					  "dir_get_name", "get_parent", "mirror_image_get", NULL};
static const char *const k_known_lock[] = {"get_info", "lock", "unlock", "assert_locked", "break_lock", "set_cookie", NULL};

static int split_call(const uint8_t *b, size_t n, char *cls, char *meth)
{
	const char *const *tab;
	size_t cl, best = 0, k;
	int found = 0;

	if (n >= 3 && memcmp(b, "rbd", 3) == 0) {
		cl = 3;
		tab = k_known_rbd;
		strcpy(cls, "rbd");
	} else if (n >= 4 && memcmp(b, "lock", 4) == 0) {
		cl = 4;
		tab = k_known_lock;
		strcpy(cls, "lock");
	} else {
		return 0;
	}
	for (k = 0; tab[k] != NULL; k++) {
		size_t ml = strlen(tab[k]);

		if (cl + ml <= n && memcmp(b + cl, tab[k], ml) == 0 && ml > best) {
			best = ml;
			strcpy(meth, tab[k]);
			found = 1;
		}
	}
	return found;
}

/*
 * One request / reply pair as JSON objects: the request's `ops` (payload_len, code) and data hex tell which call each operation is, the
 * reply's `out_len` list and data hex hold the outputs in the same order. Every output of a CALL we have a decoder for and whose rval is 0
 * is decoded. `req_ops` is the array of operation records; for osdop 09 / 10 the request carries them in `summary.ops`.
 */
static size_t decode_reply_ops(const wrt_json *j, wrt_tok req_ops, const uint8_t *rq, size_t rqn, wrt_tok out_lens, wrt_tok rvals,
			       const uint8_t *rp, size_t rpn, dres *last_by_kind, int *seen)
{
	size_t k, roff = 0, qoff = 0, done = 0;

	for (k = 0; k < wrt_json_count(j, req_ops); k++) {
		wrt_tok o = wrt_json_at(j, req_ops, k);
		int ok = 0;
		int64_t plen = wrt_json_int(j, wrt_json_get(j, o, "payload_len"), &ok);
		int64_t olen = wrt_json_int(j, wrt_json_at(j, out_lens, k), &ok);
		int64_t rv = rvals == WRT_NONE ? 0 : wrt_json_int(j, wrt_json_at(j, rvals, k), &ok);
		char cls[8], meth[40];

		WRT_CHECK(ok && plen >= 0 && olen >= 0);
		/* the bytes of a big write or read are not kept in the vectors: nothing more to cut out of such a message */
		if (plen < 0 || olen < 0 || qoff + (size_t)plen > rqn || roff + (size_t)olen > rpn)
			break;
		if (rv == 0 && olen > 0 && split_call(rq + qoff, (size_t)plen, cls, meth)) {
			int kind = kind_of(cls, meth);

			if (kind >= 0) {
				wr_status st = dec_heap(kind, rp + roff, (size_t)olen, &last_by_kind[kind]);

				WRT_CHECK_STATUS(WR_OK, st);
				if (st == WR_OK) {
					seen[kind]++;
					done++;
					check_cuts(kind, rp + roff, (size_t)olen);
				}
			}
		}
		qoff += (size_t)plen;
		roff += (size_t)olen;
	}
	return done;
}

static void test_message_vectors(void)
{
	wrt_json j;
	wrt_tok ms;
	size_t i, done = 0;
	int seen[K_N] = {0};
	dres last[K_N];

	if (wrt_json_load_vec(&j, "rbd/osd-messages.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	ms = wrt_json_get(&j, wrt_json_root(&j), "messages");
	for (i = 0; i < wrt_json_count(&j, ms); i++) {
		wrt_tok m = wrt_json_at(&j, ms, i);
		wrt_tok req = wrt_json_get(&j, m, "request"), rep = wrt_json_get(&j, m, "reply");
		uint8_t *rq = NULL, *rp = NULL;
		size_t rqn = 0, rpn = 0;

		/* a message without data segment has no data_hex */
		if (wrt_json_get(&j, req, "data_hex") != WRT_NONE && wrt_json_get_hex(&j, req, "data_hex", &rq, &rqn) != 0)
			WRT_CHECK(0);
		if (wrt_json_get(&j, rep, "data_hex") != WRT_NONE && wrt_json_get_hex(&j, rep, "data_hex", &rp, &rpn) != 0)
			WRT_CHECK(0);
		{
			done += decode_reply_ops(&j, wrt_json_get(&j, req, "ops"), rq, rqn, wrt_json_get(&j, rep, "out_len"),
						 wrt_json_get(&j, rep, "rvals"), rp, rpn, last, seen);
		}
		free(rq);
		free(rp);
	}
	printf("reply outputs decoded from osd-messages: %zu\n", done);
	WRT_CHECK(done >= 20);
	WRT_CHECK(seen[K_ID] >= 1 && seen[K_SIZE] >= 4 && seen[K_PREFIX] >= 1 && seen[K_FEAT] >= 3 && seen[K_U64] >= 2);
	WRT_CHECK(seen[K_SNAPC] >= 2 && seen[K_PARENT] >= 1 && seen[K_OVERLAP] >= 1 && seen[K_LOCK] >= 3 && seen[K_I64] >= 1);
	wrt_json_free(&j);
}

/* osdop 09 / 10: the reply of the five-call open message, value by value (rbd info on the default-feature image) */
static void test_open_reply(const char *rel)
{
	wrt_json j;
	wrt_tok rep, ops;
	uint8_t *data = NULL;
	size_t dn = 0, off = 0;
	dres r;
	static const size_t lens[5] = {9, 16, 8, 12, 23};

	if (wrt_json_load_vec(&j, rel) != 0) {
		WRT_CHECK(0);
		return;
	}
	rep = wrt_json_get(&j, wrt_json_root(&j), "reply");
	ops = wrt_json_get(&j, wrt_json_get(&j, rep, "summary"), "ops");
	WRT_CHECK(wrt_json_get_hex(&j, wrt_json_get(&j, rep, "data"), "hex", &data, &dn) == 0);
	WRT_CHECK(wrt_json_count(&j, ops) == 5);
	if (data != NULL && dn >= 68) {
		size_t k;

		for (k = 0; k < 5; k++) {
			int ok = 0;

			WRT_CHECK_U64(wrt_json_int(&j, wrt_json_get(&j, wrt_json_at(&j, ops, k), "payload_len"), &ok), lens[k]);
		}
		WRT_CHECK_STATUS(WR_OK, dec_heap(K_SIZE, data + off, lens[0], &r));
		WRT_CHECK(r.order == 22 && r.size == 0x100000000ull);
		off += lens[0];
		WRT_CHECK_STATUS(WR_OK, dec_heap(K_FEAT, data + off, lens[1], &r));
		WRT_CHECK(r.a == 0x3d && r.b == 1); /* the capture asked with read_only = true: the server masks with the read-only set */
		off += lens[1];
		WRT_CHECK_STATUS(WR_OK, dec_heap(K_U64, data + off, lens[2], &r));
		WRT_CHECK(r.a == 0);
		off += lens[2];
		WRT_CHECK_STATUS(WR_OK, dec_heap(K_SNAPC, data + off, lens[3], &r));
		WRT_CHECK(r.sc.seq == 0 && r.sc.n == 0 && r.ntotal == 0);
		off += lens[3];
		WRT_CHECK_STATUS(WR_OK, dec_heap(K_LOCK, data + off, lens[4], &r));
		WRT_CHECK(r.nlock == 0 && r.ltype == 1 && strcmp(r.tag, "internal") == 0);
	} else {
		WRT_CHECK(0);
	}
	free(data);
	wrt_json_free(&j);
}

/* ---- header-omap.json: the stored values are the call outputs ---------------------------------- */

static void test_header_omap(void)
{
	wrt_json j;
	wrt_tok imgs;
	size_t i, n_id = 0, n_pref = 0, n_lock = 0;

	if (wrt_json_load_vec(&j, "rbd/header-omap.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	imgs = wrt_json_get(&j, wrt_json_root(&j), "images");
	for (i = 0; i < wrt_json_count(&j, imgs); i++) {
		wrt_tok img, om, t;
		const char *name = wrt_json_key_at(&j, imgs, i, &img);
		uint8_t *b = NULL;
		size_t n = 0;
		dres r;

		if (name == NULL)
			continue;
		om = wrt_json_get(&j, img, "omap_hex");
		if (streq(name, "rbd_directory")) {
			size_t k;

			for (k = 0; k < wrt_json_count(&j, om); k++) {
				const char *key = wrt_json_key_at(&j, om, k, &t);

				if (key == NULL || wrt_json_hex(&j, t, &b, &n) != 0)
					continue;
				/* name_<name> holds an id, id_<id> holds a name: names have hyphens in this lab, ids are alphanumeric */
				WRT_CHECK_STATUS(strncmp(key, "name_", 5) == 0 ? WR_OK : WR_E_RBD_BAD_ID, dec_heap(K_ID, b, n, &r));
				if (strncmp(key, "name_", 5) == 0)
					n_id++;
				free(b);
			}
			continue;
		}
		if (om == WRT_NONE)
			continue;
		if (wrt_json_get_hex(&j, img, "rbd_id_object_hex", &b, &n) == 0) {
			WRT_CHECK_STATUS(WR_OK, dec_heap(K_ID, b, n, &r));
			WRT_CHECK(strlen(r.id) == 12);
			check_cuts(K_ID, b, n);
			n_id++;
			free(b);
		}
		if (wrt_json_get_hex(&j, om, "object_prefix", &b, &n) == 0) {
			WRT_CHECK_STATUS(WR_OK, dec_heap(K_PREFIX, b, n, &r));
			WRT_CHECK(strncmp(r.prefix, "rbd_data.", 9) == 0);
			check_cuts(K_PREFIX, b, n);
			n_pref++;
			free(b);
		}
		if (wrt_json_get_hex(&j, om, "features", &b, &n) == 0) {
			WRT_CHECK_STATUS(WR_OK, dec_heap(K_U64, b, n, &r));
			WRT_CHECK(r.a != 0 && (r.a & ~0xfffull) == 0);
			free(b);
		}
		if (wrt_json_get_hex(&j, om, "size", &b, &n) == 0) {
			WRT_CHECK_STATUS(WR_OK, dec_heap(K_U64, b, n, &r));
			WRT_CHECK(r.a != 0);
			free(b);
		}
		if (wrt_json_get_hex(&j, om, "snap_seq", &b, &n) == 0) {
			WRT_CHECK_STATUS(WR_OK, dec_heap(K_U64, b, n, &r));
			free(b);
		}
		if (wrt_json_get_hex(&j, om, "data_pool_id", &b, &n) == 0) {
			WRT_CHECK_STATUS(WR_OK, dec_heap(K_I64, b, n, &r));
			WRT_CHECK(r.i == 5);
			free(b);
		}
		{ /* stripe_unit and stripe_count are two omap values; get_stripe_unit_count returns them one after the other */
			uint8_t *u = NULL, *c = NULL;
			size_t un = 0, cn = 0;

			if (wrt_json_get_hex(&j, om, "stripe_unit", &u, &un) == 0 && wrt_json_get_hex(&j, om, "stripe_count", &c, &cn) == 0 &&
			    un == 8 && cn == 8) {
				uint8_t both[16];

				memcpy(both, u, 8);
				memcpy(both + 8, c, 8);
				WRT_CHECK_STATUS(WR_OK, dec_heap(K_STRIPE, both, 16, &r));
				WRT_CHECK(r.a == 65536 && r.b == 4);
			}
			free(u);
			free(c);
		}
		if (wrt_json_get_hex(&j, img, "lock_xattr_hex", &b, &n) == 0) { /* the xattr is the structure get_info returns */
			WRT_CHECK_STATUS(WR_OK, dec_heap(K_LOCK, b, n, &r));
			WRT_CHECK(r.nlock == 0 && r.ltype == 1 && strcmp(r.tag, "internal") == 0);
			check_cuts(K_LOCK, b, n);
			n_lock++;
			free(b);
		}
	}
	WRT_CHECK(n_id >= 7 && n_pref >= 9 && n_lock >= 1);
	wrt_json_free(&j);
}

/* ---- builders for synthetic outputs --------------------------------------------------------------- */

typedef struct buf {
	uint8_t b[8192];
	wri_wr w;
} buf;

static void bstart(buf *x)
{
	wri_wr_init(&x->w, x->b, sizeof(x->b));
}

static size_t blen(const buf *x)
{
	WRT_CHECK(wri_wr_ok(&x->w));
	return x->w.pos;
}

static void put_str(buf *x, const char *s)
{
	wri_denc_put_str(&x->w, (const uint8_t *)s, strlen(s));
}

/* ---- ids and prefixes ---------------------------------------------------------------------------- */

static size_t mk_str(buf *x, size_t len, uint8_t fill)
{
	bstart(x);
	wri_wr_u32(&x->w, (uint32_t)len);
	{
		size_t i;

		for (i = 0; i < len; i++)
			wri_wr_u8(&x->w, fill);
	}
	return blen(x);
}

static void test_id(void)
{
	buf x;
	dres r;
	size_t n;
	static const char bad_chars[] = {'-', '_', ' ', '.', '/', '\0', '\x7f', (char)0x80, (char)0xff, '@', '[', '`', '{', ':'};
	size_t i;

	/* good: 1, 12 and 63 bytes, letters of both cases and digits */
	n = mk_str(&x, 1, 'a');
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_ID, x.b, n, &r));
	WRT_CHECK(strcmp(r.id, "a") == 0);
	bstart(&x);
	put_str(&x, "37841afbd1d7");
	n = blen(&x);
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_ID, x.b, n, &r));
	WRT_CHECK(strcmp(r.id, "37841afbd1d7") == 0);
	bstart(&x);
	put_str(&x, "0aZ9zA");
	n = blen(&x);
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_ID, x.b, n, &r));
	n = mk_str(&x, 63, 'Q');
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_ID, x.b, n, &r));
	WRT_CHECK(strlen(r.id) == 63);
	check_cuts(K_ID, x.b, n);
	/* 64 and more, and zero: bad id */
	n = mk_str(&x, 64, 'a');
	WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, dec_heap(K_ID, x.b, n, &r));
	check_cleared(K_ID, &r);
	n = mk_str(&x, 0, 'a');
	WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, dec_heap(K_ID, x.b, n, &r));
	n = mk_str(&x, 1000, 'a');
	WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, dec_heap(K_ID, x.b, n, &r));
	/* a length that is out of range is a bad id even when the bytes are not there; a good length with missing bytes is a bad reply */
	{
		uint8_t four[4] = {0xff, 0xff, 0xff, 0xff};

		WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, dec_heap(K_ID, four, 4, &r));
		four[0] = 5;
		four[1] = four[2] = four[3] = 0;
		WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_ID, four, 4, &r));
	}
	/* bytes that are not letters or digits, anywhere in the id */
	for (i = 0; i < sizeof(bad_chars); i++) {
		bstart(&x);
		wri_wr_u32(&x.w, 5);
		wri_wr_bytes(&x.w, (const uint8_t *)"ab", 2);
		wri_wr_u8(&x.w, (uint8_t)bad_chars[i]);
		wri_wr_bytes(&x.w, (const uint8_t *)"cd", 2);
		WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, dec_heap(K_ID, x.b, blen(&x), &r));
		check_cleared(K_ID, &r);
	}
	/* NULL */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_id(x.b, 4, NULL));
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_dec_id(NULL, 0, r.id));
}

static void test_prefix(void)
{
	buf x;
	dres r;
	size_t n, i;

	bstart(&x);
	put_str(&x, "rbd_data.2.600ecac4b85c");
	n = blen(&x);
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_PREFIX, x.b, n, &r));
	WRT_CHECK(strcmp(r.prefix, "rbd_data.2.600ecac4b85c") == 0);
	n = mk_str(&x, 1, 'p');
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_PREFIX, x.b, n, &r));
	/* the longest prefix whose data object names fit 95 bytes: 78 + '.' + 16 hex digits */
	WRT_CHECK(WRI_RBD_PREFIX_LEN_MAX + 1 + 16 == 95);
	n = mk_str(&x, WRI_RBD_PREFIX_LEN_MAX, 'x');
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_PREFIX, x.b, n, &r));
	WRT_CHECK(strlen(r.prefix) == WRI_RBD_PREFIX_LEN_MAX);
	check_cuts(K_PREFIX, x.b, n);
	n = mk_str(&x, WRI_RBD_PREFIX_LEN_MAX + 1, 'x');
	WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, dec_heap(K_PREFIX, x.b, n, &r));
	check_cleared(K_PREFIX, &r);
	n = mk_str(&x, 95, 'x');
	WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, dec_heap(K_PREFIX, x.b, n, &r));
	n = mk_str(&x, 0, 'x');
	WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, dec_heap(K_PREFIX, x.b, n, &r));
	/* bytes: visible ASCII only */
	for (i = 0; i < 256; i++) {
		int ok = i >= 0x21 && i <= 0x7e;

		bstart(&x);
		wri_wr_u32(&x.w, 3);
		wri_wr_u8(&x.w, 'a');
		wri_wr_u8(&x.w, (uint8_t)i);
		wri_wr_u8(&x.w, 'b');
		WRT_CHECK_STATUS(ok ? WR_OK : WR_E_RBD_BAD_ID, dec_heap(K_PREFIX, x.b, blen(&x), &r));
	}
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_prefix(x.b, 4, NULL));
}

/* ---- fixed layouts ------------------------------------------------------------------------------- */

static void test_fixed(void)
{
	buf x;
	dres r;
	uint8_t eight[8] = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	size_t n;

	/* get_size: order first */
	bstart(&x);
	wri_wr_u8(&x.w, 22);
	wri_wr_u64(&x.w, 0x1122334455667788ull);
	n = blen(&x);
	WRT_CHECK(n == 9);
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_SIZE, x.b, n, &r));
	WRT_CHECK(r.order == 22 && r.size == 0x1122334455667788ull);
	check_cuts(K_SIZE, x.b, n);
	/* the order is not judged here */
	x.b[0] = 0;
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_SIZE, x.b, n, &r));
	WRT_CHECK(r.order == 0);
	x.b[0] = 255;
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_SIZE, x.b, n, &r));
	WRT_CHECK(r.order == 255);
	/* features: both words as they come */
	bstart(&x);
	wri_wr_u64(&x.w, 0xffffffffffffffffull);
	wri_wr_u64(&x.w, 0x8000000000000001ull);
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_FEAT, x.b, 16, &r));
	WRT_CHECK(r.a == 0xffffffffffffffffull && r.b == 0x8000000000000001ull);
	check_cuts(K_FEAT, x.b, 16);
	/* u64, i64, stripe */
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_U64, eight, 8, &r));
	WRT_CHECK(r.a == 0xfffffffffffffffeull);
	check_cuts(K_U64, eight, 8);
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_I64, eight, 8, &r));
	WRT_CHECK(r.i == -2);
	check_cuts(K_I64, eight, 8);
	memset(eight, 0xff, 8);
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_I64, eight, 8, &r));
	WRT_CHECK(r.i == -1);
	bstart(&x);
	wri_wr_u64(&x.w, 65536);
	wri_wr_u64(&x.w, 4);
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_STRIPE, x.b, 16, &r));
	WRT_CHECK(r.a == 65536 && r.b == 4);
	check_cuts(K_STRIPE, x.b, 16);
	/* NULL */
	{
		uint8_t o = 0;
		uint64_t v = 0, w = 0;
		int64_t iv = 0;

		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_size(x.b, 9, NULL, &v));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_size(x.b, 9, &o, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_features(x.b, 16, NULL, &w));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_features(x.b, 16, &v, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_u64(x.b, 8, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_i64(x.b, 8, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_stripe(x.b, 16, NULL, &w));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_stripe(x.b, 16, &v, NULL));
		WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_dec_i64(NULL, 0, &iv));
		WRT_CHECK(iv == 0);
	}
}

/* ---- the snapshot context --------------------------------------------------------------------- */

static size_t mk_snapc(buf *x, uint64_t seq, const uint64_t *ids, uint32_t count_field, size_t n_ids)
{
	size_t i;

	bstart(x);
	wri_wr_u64(&x->w, seq);
	wri_wr_u32(&x->w, count_field);
	for (i = 0; i < n_ids; i++)
		wri_wr_u64(&x->w, ids[i]);
	return blen(x);
}

static void snapc_case(const char *what, uint64_t seq, const uint64_t *ids, size_t n_ids, wr_status want)
{
	buf x;
	dres r;
	size_t n = mk_snapc(&x, seq, ids, (uint32_t)n_ids, n_ids), i;
	wr_status st = dec_heap(K_SNAPC, x.b, n, &r);

	if (st != want)
		fprintf(stderr, "snapshot context case %s\n", what);
	WRT_CHECK_STATUS(want, st);
	if (st == WR_OK) {
		WRT_CHECK(r.sc.seq == seq && r.sc.n == n_ids && r.ntotal == n_ids);
		for (i = 0; i < n_ids; i++)
			WRT_CHECK(r.snaps[i] == ids[i]);
		check_cuts(K_SNAPC, x.b, n);
	} else {
		check_cleared(K_SNAPC, &r);
		for (i = 0; i < SNAPS_CAP; i++) /* what was stored before the refusal is wiped: zero, or still the poison */
			WRT_CHECK(r.snaps[i] == 0 || r.snaps[i] == 0xa5a5a5a5a5a5a5a5ull);
	}
}

static void test_snapcontext(void)
{
	static const uint64_t d53[] = {5, 3}, d11_9[] = {11, 9}, one[] = {1}, mx[] = {WRI_SNAP_MAX}, down[] = {4, 3, 2, 1, 0};
	static const uint64_t asc[] = {3, 5}, eq[] = {5, 5}, eq2[] = {5, 3, 3}, z_then[] = {2, 0, 1}, z_z[] = {1, 0, 0}, z_z2[] = {0, 0};
	static const uint64_t above[] = {4}, above2[] = {6, 5}, tail_up[] = {9, 7, 8}, big8[] = {8, 7, 6, 5, 4, 3, 2, 1}, big9[] = {9, 8, 7, 6, 5, 4, 3, 2, 1};
	static const uint64_t nosnap[] = {WRI_SNAP_NOSNAP};
	buf x;
	dres r;
	size_t n;

	snapc_case("empty", 0, NULL, 0, WR_OK);
	snapc_case("seq only", 7, NULL, 0, WR_OK);
	snapc_case("5,3 (the note's example)", 5, d53, 2, WR_OK);
	snapc_case("11,9 (a gap)", 11, d11_9, 2, WR_OK);
	snapc_case("one", 1, one, 1, WR_OK);
	snapc_case("max", WRI_SNAP_MAX, mx, 1, WR_OK);
	snapc_case("down to zero", 4, down, 5, WR_OK);
	snapc_case("exactly the cap", 9, big8, 8, WR_OK);
	snapc_case("ascending", 5, asc, 2, WR_E_RBD_SNAPC);
	snapc_case("equal", 5, eq, 2, WR_E_RBD_SNAPC);
	snapc_case("equal at the end", 5, eq2, 3, WR_E_RBD_SNAPC);
	snapc_case("zero followed by another", 2, z_then, 3, WR_E_RBD_SNAPC);
	snapc_case("zero twice", 1, z_z, 3, WR_E_RBD_SNAPC);
	snapc_case("zero twice from the start", 1, z_z2, 2, WR_E_RBD_SNAPC);
	snapc_case("first above seq", 3, above, 1, WR_E_RBD_SNAPC);
	snapc_case("first above seq (two)", 5, above2, 2, WR_E_RBD_SNAPC);
	snapc_case("rises at the tail", 10, tail_up, 3, WR_E_RBD_SNAPC);
	snapc_case("seq above the maximum", WRI_SNAP_NOSNAP, NULL, 0, WR_E_RBD_SNAPC);
	snapc_case("seq all ones", ~0ull, NULL, 0, WR_E_RBD_SNAPC);
	snapc_case("NOSNAP in the list", WRI_SNAP_NOSNAP, nosnap, 1, WR_E_RBD_SNAPC);

	/* more ids than the cap: nothing stored, the count reported, the status SNAPC (a valid or an invalid list alike) */
	n = mk_snapc(&x, 9, big9, 9, 9);
	WRT_CHECK_STATUS(WR_E_RBD_SNAPC, dec_heap(K_SNAPC, x.b, n, &r));
	WRT_CHECK(r.ntotal == 9 && r.sc.n == 0 && r.sc.seq == 0);
	{
		uint64_t ids[100];
		size_t i;
		wri_snapc s;
		uint64_t store[100];
		uint32_t tot = 0;

		for (i = 0; i < 100; i++)
			ids[i] = 1000 - i;
		n = mk_snapc(&x, 1000, ids, 100, 100);
		s.cap = 100;
		s.snaps = store;
		WRT_CHECK_STATUS(WR_OK, wri_rbd_dec_snapcontext(x.b, (uint32_t)n, &s, &tot));
		WRT_CHECK(s.n == 100 && s.seq == 1000 && tot == 100 && store[0] == 1000 && store[99] == 901);
		s.cap = 99;
		WRT_CHECK_STATUS(WR_E_RBD_SNAPC, wri_rbd_dec_snapcontext(x.b, (uint32_t)n, &s, &tot));
		WRT_CHECK(s.n == 0 && s.seq == 0 && tot == 100);
		s.cap = 0;
		s.snaps = NULL;
		WRT_CHECK_STATUS(WR_E_RBD_SNAPC, wri_rbd_dec_snapcontext(x.b, (uint32_t)n, &s, &tot));
		WRT_CHECK(tot == 100);
		/* cap 0 accepts an empty context without memory */
		n = mk_snapc(&x, 3, NULL, 0, 0);
		WRT_CHECK_STATUS(WR_OK, wri_rbd_dec_snapcontext(x.b, (uint32_t)n, &s, &tot));
		WRT_CHECK(s.seq == 3 && s.n == 0 && tot == 0);
		/* NULL n_total is fine */
		WRT_CHECK_STATUS(WR_OK, wri_rbd_dec_snapcontext(x.b, (uint32_t)n, &s, NULL));
		/* a cap without memory is a caller error; so is a NULL context */
		s.cap = 4;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_snapcontext(x.b, (uint32_t)n, &s, &tot));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_snapcontext(x.b, (uint32_t)n, NULL, &tot));
	}
	/* cap and the array stay the owner's whatever happens */
	n = mk_snapc(&x, 5, d53, 2, 2);
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_SNAPC, x.b, n, &r));
	WRT_CHECK(r.sc.cap == SNAPS_CAP && r.sc.snaps == r.snaps);

	/* a count that lies: more than the bytes hold, fewer than they hold, the biggest 32-bit values (cnt * 8 wraps u32) */
	n = mk_snapc(&x, 5, d53, 3, 2);
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_SNAPC, x.b, n, &r));
	WRT_CHECK(r.ntotal == 0);
	check_cleared(K_SNAPC, &r);
	n = mk_snapc(&x, 5, d53, 1, 2);
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_SNAPC, x.b, n, &r));
	n = mk_snapc(&x, 5, d53, 0xffffffffu, 2);
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_SNAPC, x.b, n, &r));
	n = mk_snapc(&x, 5, d53, 0x20000000u, 2);
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_SNAPC, x.b, n, &r));
	n = mk_snapc(&x, 5, d53, 0x20000002u, 2);
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_SNAPC, x.b, n, &r));
	n = mk_snapc(&x, 5, NULL, 1, 0);
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_SNAPC, x.b, n, &r));
	/* seq 5, one id, a stray byte */
	n = mk_snapc(&x, 5, one, 1, 1);
	x.b[n] = 0;
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_SNAPC, x.b, n + 1, &r));
	/* NULL / empty input */
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_dec_snapcontext(NULL, 0, &r.sc, NULL));
	WRT_CHECK(r.sc.n == 0 && r.sc.seq == 0);
}

/* ---- parent_get and the overlap ------------------------------------------------------------------ */

static size_t mk_parent(buf *x, uint8_t v, uint8_t compat, int64_t pool, const char *ns, const char *img, uint64_t snap, size_t extra_tail)
{
	size_t m;

	bstart(x);
	m = wri_env_begin(&x->w, v, compat);
	wri_wr_i64(&x->w, pool);
	put_str(x, ns);
	put_str(x, img);
	wri_wr_u64(&x->w, snap);
	wri_wr_zero(&x->w, extra_tail);
	wri_env_end(&x->w, m);
	return blen(x);
}

static void parent_case(const char *what, size_t n, buf *x, wr_status want, int has)
{
	dres r;
	wr_status st = dec_heap(K_PARENT, x->b, n, &r);

	if (st != want)
		fprintf(stderr, "parent case %s\n", what);
	WRT_CHECK_STATUS(want, st);
	if (st == WR_OK)
		WRT_CHECK(r.has == has);
	else
		check_cleared(K_PARENT, &r);
}

static void test_parent(void)
{
	buf x;
	size_t n;
	dres r;

	n = mk_parent(&x, 1, 1, -1, "", "", WRI_SNAP_NOSNAP, 0); /* the default: no parent (30 bytes) */
	WRT_CHECK(n == 30);
	parent_case("default", n, &x, WR_OK, 0);
	check_cuts(K_PARENT, x.b, n);
	n = mk_parent(&x, 1, 1, 2, "", "5fc091bf720", 12, 0); /* a clone */
	parent_case("clone", n, &x, WR_OK, 1);
	check_cuts(K_PARENT, x.b, n);
	n = mk_parent(&x, 1, 1, 0, "", "x", 0, 0); /* pool 0 is a pool, snap 0 a snapshot id */
	parent_case("pool 0 snap 0", n, &x, WR_OK, 1);
	n = mk_parent(&x, 1, 1, 2, "ns", "abc", 7, 0); /* a parent in a namespace is still a parent */
	parent_case("namespace", n, &x, WR_OK, 1);
	/* each of the three conditions alone */
	n = mk_parent(&x, 1, 1, -1, "", "abc", 7, 0);
	parent_case("no pool", n, &x, WR_OK, 0);
	n = mk_parent(&x, 1, 1, 2, "", "", 7, 0);
	parent_case("no id", n, &x, WR_OK, 0);
	n = mk_parent(&x, 1, 1, 2, "", "abc", WRI_SNAP_NOSNAP, 0);
	parent_case("no snap", n, &x, WR_OK, 0);
	n = mk_parent(&x, 1, 1, INT64_MIN, "", "abc", 7, 0);
	parent_case("pool most negative", n, &x, WR_OK, 0);
	/* a later version that appends fields and keeps compat 1 reads the same; one that raises compat does not */
	n = mk_parent(&x, 2, 1, 2, "", "abc", 7, 11);
	parent_case("v2 compat 1 with a tail", n, &x, WR_OK, 1);
	n = mk_parent(&x, 2, 2, 2, "", "abc", 7, 0);
	parent_case("compat 2", n, &x, WR_E_RBD_PROTO, 0);
	/* envelope damage */
	n = mk_parent(&x, 1, 1, 2, "", "abc", 7, 0);
	x.b[2] = (uint8_t)(x.b[2] + 1); /* struct length one more than the bytes */
	parent_case("length too big", n, &x, WR_E_RBD_PROTO, 0);
	x.b[2] = (uint8_t)(x.b[2] - 2); /* one less: the last field is cut */
	parent_case("length too small", n, &x, WR_E_RBD_PROTO, 0);
	n = mk_parent(&x, 1, 1, 2, "", "abc", 7, 0);
	x.b[n] = 0;
	parent_case("stray byte after the envelope", n + 1, &x, WR_E_RBD_PROTO, 0);
	/* a string whose length reaches past the struct (but not past the buffer) */
	n = mk_parent(&x, 1, 1, 2, "", "abc", 7, 8);
	x.b[6 + 8] = 200; /* the namespace length: far more than the body */
	parent_case("string past the struct", n, &x, WR_E_RBD_PROTO, 0);
	/* a string longer than anything legitimate */
	bstart(&x);
	{
		size_t m = wri_env_begin(&x.w, 1, 1), i;

		wri_wr_i64(&x.w, 2);
		wri_wr_u32(&x.w, 0);
		wri_wr_u32(&x.w, 5000);
		for (i = 0; i < 5000 / 4; i++)
			wri_wr_u32(&x.w, 0x61616161u);
		wri_wr_u64(&x.w, 7);
		wri_env_end(&x.w, m);
		n = blen(&x);
	}
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_PARENT, x.b, n, &r));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_parent(x.b, 4, NULL));
}

static void test_overlap(void)
{
	dres r;
	uint8_t absent[1] = {0};
	uint8_t present[9] = {1, 0, 0, 0, 1, 0, 0, 0, 0}; /* the clone vector: 16777216 */
	uint8_t bad[9] = {2, 0, 0, 0, 1, 0, 0, 0, 0};
	uint8_t z[9] = {1, 0, 0, 0, 0, 0, 0, 0, 0};

	WRT_CHECK_STATUS(WR_OK, dec_heap(K_OVERLAP, absent, 1, &r));
	WRT_CHECK(r.present == 0 && r.a == 0);
	check_cuts(K_OVERLAP, absent, 1);
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_OVERLAP, present, 9, &r));
	WRT_CHECK(r.present == 1 && r.a == 16777216);
	check_cuts(K_OVERLAP, present, 9);
	WRT_CHECK_STATUS(WR_OK, dec_heap(K_OVERLAP, z, 9, &r)); /* present with 0: a parent that no longer overlaps */
	WRT_CHECK(r.present == 1 && r.a == 0);
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_OVERLAP, bad, 9, &r));
	check_cleared(K_OVERLAP, &r);
	bad[0] = 0xff;
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_OVERLAP, bad, 9, &r));
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_OVERLAP, present, 8, &r)); /* marker 1 with 7 value bytes */
	{ /* a marker above 1 is refused whatever follows it, also when nothing does */
		uint8_t m2[1] = {2}, mff[1] = {0xff};

		WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_OVERLAP, m2, 1, &r));
		check_cleared(K_OVERLAP, &r);
		WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_OVERLAP, mff, 1, &r));
	}
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_OVERLAP, absent, 0, &r));
	{
		uint8_t o = 0;
		uint64_t v = 0;

		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_overlap(absent, 1, NULL, &v));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_overlap(absent, 1, &o, NULL));
	}
}

/* ---- the lock record ------------------------------------------------------------------------------ */

/* One locker the way the server sends it: id structure (type, number, cookie), info structure (expiry, address, description) of `info_len` bytes. */
static void put_locker(buf *x, const char *cookie, size_t info_len)
{
	size_t m = wri_env_begin(&x->w, 1, 1);

	wri_wr_u8(&x->w, 8);
	wri_wr_i64(&x->w, 24602);
	put_str(x, cookie);
	wri_env_end(&x->w, m);
	m = wri_env_begin(&x->w, 1, 1);
	wri_wr_zero(&x->w, info_len);
	wri_env_end(&x->w, m);
}

static size_t mk_lock(buf *x, uint32_t count_field, uint32_t n_entries, uint8_t type, const char *tag, uint8_t v, uint8_t compat, size_t tail)
{
	size_t m, i;

	bstart(x);
	m = wri_env_begin(&x->w, v, compat);
	wri_wr_u32(&x->w, count_field);
	for (i = 0; i < n_entries; i++)
		put_locker(x, "c", 40);
	wri_wr_u8(&x->w, type);
	put_str(x, tag);
	wri_wr_zero(&x->w, tail);
	wri_env_end(&x->w, m);
	return blen(x);
}

static void lock_case(const char *what, buf *x, size_t n, wr_status want, uint32_t nl, uint8_t type, const char *tag)
{
	dres r;
	wr_status st = dec_heap(K_LOCK, x->b, n, &r);

	if (st != want)
		fprintf(stderr, "lock case %s\n", what);
	WRT_CHECK_STATUS(want, st);
	if (st == WR_OK) {
		WRT_CHECK(r.nlock == nl && r.ltype == type);
		WRT_CHECK(strcmp(r.tag, tag) == 0);
	} else {
		check_cleared(K_LOCK, &r);
	}
}

static void test_lock(void)
{
	buf x;
	size_t n;
	dres r;
	uint32_t i;

	n = mk_lock(&x, 0, 0, 0, "", 1, 1, 0);
	WRT_CHECK(n == 15); /* the layering-only image's reply: 01 01 09 00 00 00, 0 lockers, type 0, empty tag */
	lock_case("none", &x, n, WR_OK, 0, 0, "");
	check_cuts(K_LOCK, x.b, n);
	n = mk_lock(&x, 0, 0, 1, "internal", 1, 1, 0); /* a released lock keeps its type and tag */
	lock_case("released", &x, n, WR_OK, 0, 1, "internal");
	n = mk_lock(&x, 1, 1, 1, "t", 1, 1, 0);
	lock_case("one", &x, n, WR_OK, 1, 1, "t");
	check_cuts(K_LOCK, x.b, n);
	n = mk_lock(&x, 2, 2, 2, "t", 1, 1, 0);
	lock_case("two shared", &x, n, WR_OK, 2, 2, "t");
	n = mk_lock(&x, 0, 0, 3, "e", 1, 1, 0);
	lock_case("type 3", &x, n, WR_OK, 0, 3, "e");
	n = mk_lock(&x, 0, 0, 4, "e", 1, 1, 0);
	lock_case("type 4", &x, n, WR_E_RBD_PROTO, 0, 0, "");
	n = mk_lock(&x, 0, 0, 255, "e", 1, 1, 0);
	lock_case("type 255", &x, n, WR_E_RBD_PROTO, 0, 0, "");
	/* a later version that appends fields keeps working; a raised compat does not */
	n = mk_lock(&x, 1, 1, 1, "t", 2, 1, 13);
	lock_case("v2 compat 1 with a tail", &x, n, WR_OK, 1, 1, "t");
	n = mk_lock(&x, 1, 1, 1, "t", 2, 2, 0);
	lock_case("compat 2", &x, n, WR_E_RBD_PROTO, 0, 0, "");
	/* the limit of 64 lockers */
	n = mk_lock(&x, 64, 64, 2, "t", 1, 1, 0);
	lock_case("64", &x, n, WR_OK, 64, 2, "t");
	{
		static uint8_t big[8192];
		wri_wr w;
		size_t m;

		wri_wr_init(&w, big, sizeof(big));
		m = wri_env_begin(&w, 1, 1);
		wri_wr_u32(&w, 65);
		for (i = 0; i < 65; i++) {
			size_t mm = wri_env_begin(&w, 1, 1);

			wri_wr_u8(&w, 8);
			wri_wr_i64(&w, i);
			wri_wr_u32(&w, 0);
			wri_env_end(&w, mm);
			mm = wri_env_begin(&w, 1, 1);
			wri_wr_zero(&w, 20);
			wri_env_end(&w, mm);
		}
		wri_wr_u8(&w, 2);
		wri_wr_u32(&w, 0);
		wri_env_end(&w, m);
		WRT_CHECK(wri_wr_ok(&w));
		WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(K_LOCK, big, w.pos, &r));
		check_cleared(K_LOCK, &r);
	}
	/* a count that lies */
	n = mk_lock(&x, 3, 1, 1, "t", 1, 1, 0);
	lock_case("count above entries", &x, n, WR_E_RBD_PROTO, 0, 0, "");
	n = mk_lock(&x, 0xffffffffu, 1, 1, "t", 1, 1, 0);
	lock_case("count 2^32 - 1", &x, n, WR_E_RBD_PROTO, 0, 0, "");
	n = mk_lock(&x, 0, 1, 1, "t", 1, 1, 0); /* fewer than the entries: the next bytes are read as type and tag and fail */
	lock_case("count below entries", &x, n, WR_E_RBD_PROTO, 0, 0, "");
	/* entry damage: id structure compat 2, id body too short for entity + cookie, info length past the end */
	n = mk_lock(&x, 1, 1, 1, "t", 1, 1, 0);
	x.b[6 + 4 + 1] = 2; /* the first entry's struct_compat */
	lock_case("entry compat 2", &x, n, WR_E_RBD_PROTO, 0, 0, "");
	n = mk_lock(&x, 1, 1, 1, "t", 1, 1, 0);
	x.b[6 + 4 + 2] = 8; /* the id structure claims 8 bytes: the entity alone does not fit with the cookie */
	lock_case("entry id too short", &x, n, WR_E_RBD_PROTO, 0, 0, "");
	n = mk_lock(&x, 1, 1, 1, "t", 1, 1, 0);
	x.b[6 + 4 + 6 + 14 + 2] = 0xff; /* the info structure claims far more than is left */
	lock_case("entry info length", &x, n, WR_E_RBD_PROTO, 0, 0, "");
	/* trailing byte after the envelope */
	n = mk_lock(&x, 0, 0, 0, "", 1, 1, 0);
	x.b[n] = 0;
	lock_case("stray byte", &x, n + 1, WR_E_RBD_PROTO, 0, 0, "");
	/* tag truncation: cap 16 here (r.tag): a 20-byte tag keeps 15 */
	n = mk_lock(&x, 0, 0, 1, "abcdefghijklmnopqrst", 1, 1, 0);
	lock_case("long tag", &x, n, WR_OK, 0, 1, "abcdefghijklmno");
	/* and with every capacity directly */
	{
		char t[32];
		uint32_t nl = 9;
		uint8_t ty = 9;
		size_t cap;

		n = mk_lock(&x, 0, 0, 2, "internal", 1, 1, 0);
		for (cap = 1; cap <= 12; cap++) {
			size_t want = cap - 1 < 8 ? cap - 1 : 8;

			memset(t, 'Z', sizeof(t));
			WRT_CHECK_STATUS(WR_OK, wri_rbd_dec_lock_info(x.b, (uint32_t)n, &nl, &ty, t, cap));
			WRT_CHECK(strlen(t) == want && memcmp(t, "internal", want) == 0 && nl == 0 && ty == 2);
			WRT_CHECK(cap >= sizeof(t) || t[cap] == 'Z'); /* nothing written past the capacity */
		}
		/* no tag wanted */
		WRT_CHECK_STATUS(WR_OK, wri_rbd_dec_lock_info(x.b, (uint32_t)n, &nl, &ty, NULL, 0));
		WRT_CHECK(ty == 2);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_lock_info(x.b, (uint32_t)n, &nl, &ty, NULL, 4));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_lock_info(x.b, (uint32_t)n, NULL, &ty, t, sizeof(t)));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_lock_info(x.b, (uint32_t)n, &nl, NULL, t, sizeof(t)));
		/* a failure clears the tag buffer too */
		memset(t, 'Z', sizeof(t));
		WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_dec_lock_info(x.b, (uint32_t)(n - 1), &nl, &ty, t, sizeof(t)));
		WRT_CHECK(t[0] == 0 && t[31] == 0 && nl == 0 && ty == 0);
	}
	/* every cut of a record with two lockers */
	n = mk_lock(&x, 2, 2, 2, "shared", 1, 1, 0);
	check_cuts(K_LOCK, x.b, n);
}

/* ---- every decoder on empty and one-byte inputs; NULL input pointers --------------------------- */

static void test_empty_inputs(void)
{
	int k;
	dres r;
	uint8_t one[1] = {0};

	for (k = 0; k < K_N; k++) {
		WRT_CHECK_STATUS(WR_E_RBD_PROTO, run_dec(k, NULL, 0, &r));
		check_cleared(k, &r);
		WRT_CHECK_STATUS(WR_E_RBD_PROTO, dec_heap(k, one, 0, &r));
		if (k != K_OVERLAP) /* a single zero byte is a valid "not present" */
			WRT_CHECK(dec_heap(k, one, 1, &r) != WR_OK);
	}
}

int main(void)
{
	test_class_call_vectors();
	test_message_vectors();
	test_open_reply("osdop/09-rbd-open-compound-5calls.json");
	test_open_reply("osdop/10-rbd-lock-get-info.json");
	test_header_omap();
	test_id();
	test_prefix();
	test_fixed();
	test_snapcontext();
	test_parent();
	test_overlap();
	test_lock();
	test_empty_inputs();
	return wrt_finish();
}
