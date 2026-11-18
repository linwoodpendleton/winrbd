/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_vec_replay - the lab captures of module vectors-c (harness/vectors/public/osdc/) through the real RBD code of core/src/rbd
 * (wri_rbd_cls.h, the geometry of wri_rbd_io.h).
 *
 * Header reads: for each of ten images made with the stock tools (feature words 0x1, 0x5, 0x21, 0x3d, 0x45, 0x81, a clone, a striped
 * image, one with snapshots, one with a foreign lock; objects of 4 KiB to 64 KiB) the captured open is replayed: get_id, the eight-call
 * header message in its reader and writer form, the extra calls of the feature bits, lock get_info. Every request is rebuilt with the
 * class-call encoders of the core (the message encoder, the operation records and the data segment must equal the capture byte for byte);
 * every reply is cut by its operation lengths and decoded with the core's decoders; the decoded header must equal `rbd info` and the
 * snapshot list of the stock tool; the refusal function must give, for the reader and the writer profile, the verdict the independent
 * checker derived from the note (status and numbers). A header read of an image that does not exist is -ENOENT as a whole.
 * Data path: the object names built by wri_rbd_obj_name are the ones the stock tools used, the exported data objects of three patterned
 * images (4, 16 and 64 KiB objects) are exactly what the geometry (wri_rbd_geom_extent) says the pattern lands in, objects that hold no
 * data do not exist (a read of them is -ENOENT: zero-fill, success), and the results of the captured reads, writes, ZERO, TRUNCATE and
 * DELETE map to image request statuses through wri_rbd_op_status. The write snapshot context of the capture equals the context the
 * decoder reads from the image header, and wri_snapc_valid accepts it.
 */
#include "osdc_vec_rig.h"

#include "wri_rbd_cls.h"
#include "wri_rbd_io.h"

typedef struct tally {
	unsigned images, messages, calls, objects, ranges, statuses, verdicts, sweeps, walks, grid;
} tally;

/* ---- the encoders against the capture ---------------------------------------------------------------------------------------------- */

#define MAX_CALLS 10u

typedef struct call_set {
	wri_osd_opd ops[MAX_CALLS];
	unsigned n;
	uint8_t buf[1024];
	wri_wr data;
} call_set;

static void cs_init(call_set *c)
{
	memset(c, 0, sizeof(*c));
	wri_wr_init(&c->data, c->buf, sizeof(c->buf));
}

#define ADD(c, expr)                                                                                                                       \
	do {                                                                                                                               \
		WRT_CHECK_STATUS(WR_OK, (expr));                                                                                           \
		(c)->n++;                                                                                                                  \
	} while (0)

static void build_calls(call_set *c, const char *label)
{
	cs_init(c);
	if (strcmp(label, "get_id") == 0) {
		ADD(c, wri_rbd_put_get_id(&c->data, &c->ops[c->n]));
	} else if (strcmp(label, "header8-reader") == 0 || strcmp(label, "header8-writer") == 0) {
		int ro = strcmp(label, "header8-reader") == 0;

		ADD(c, wri_rbd_put_get_size(&c->data, &c->ops[c->n], WRI_SNAP_NOSNAP));
		ADD(c, wri_rbd_put_get_object_prefix(&c->data, &c->ops[c->n]));
		ADD(c, wri_rbd_put_get_features(&c->data, &c->ops[c->n], WRI_SNAP_NOSNAP, ro));
		ADD(c, wri_rbd_put_get_flags(&c->data, &c->ops[c->n], WRI_SNAP_NOSNAP));
		ADD(c, wri_rbd_put_get_snapcontext(&c->data, &c->ops[c->n]));
		ADD(c, wri_rbd_put_get_data_pool(&c->data, &c->ops[c->n]));
		ADD(c, wri_rbd_put_parent_get(&c->data, &c->ops[c->n]));
		ADD(c, wri_rbd_put_parent_overlap_get(&c->data, &c->ops[c->n], WRI_SNAP_NOSNAP));
	} else if (strcmp(label, "stripe-unit-count") == 0) {
		ADD(c, wri_rbd_put_get_stripe_unit_count(&c->data, &c->ops[c->n]));
	} else if (strcmp(label, "op-features") == 0) {
		ADD(c, wri_rbd_put_op_features_get(&c->data, &c->ops[c->n]));
	} else if (strcmp(label, "lock-get-info") == 0) {
		ADD(c, wri_rbd_put_lock_get_info(&c->data, &c->ops[c->n], "rbd_lock"));
	}
}

/* the request of the capture re-encoded with the operation records and the data segment of the class-call encoders */
static void check_request(const wrt_json *j, const char *where, const ov_msg *rq, const char *label, tally *t)
{
	call_set c;
	ov_req q;
	wrt_tok sops;
	unsigned i;

	build_calls(&c, label);
	WRT_CHECK(wri_wr_ok(&c.data));
	WRT_CHECK_U64(wri_wr_len(&c.data), rq->data_total);
	if (rq->data != NULL)
		WRT_CHECK(wri_wr_len(&c.data) == rq->data_len && memcmp(c.buf, rq->data, rq->data_len) == 0);
	if (ov_req_build(&q, j, rq->summary, (uint8_t)rq->version) != 0) {
		WRT_CHECK(0);
		return;
	}
	sops = wrt_json_get(j, rq->summary, "ops");
	WRT_CHECK_U64(c.n, wrt_json_count(j, sops));
	WRT_CHECK(c.n == q.n_ops);
	/* the operation records the encoders produced are the ones that were sent */
	for (i = 0; i < c.n && i < q.n_ops; i++) {
		WRT_CHECK(c.ops[i].code == q.ops[i].code);
		WRT_CHECK(c.ops[i].flags == q.ops[i].flags);
		WRT_CHECK(c.ops[i].in_len == q.ops[i].in_len);
		WRT_CHECK(c.ops[i].cls_class_len == q.ops[i].cls_class_len);
		WRT_CHECK(c.ops[i].cls_method_len == q.ops[i].cls_method_len);
		WRT_CHECK(c.ops[i].out_len == 0 && c.ops[i].rval == 0); /* what the decoder fills later starts clean */
	}
	memcpy(q.ops, c.ops, sizeof(c.ops[0]) * (c.n < q.n_ops ? c.n : q.n_ops));
	WRT_CHECK(ov_req_check(&q, rq, where) == 0);
	t->messages++;
	t->calls += c.n;
	ov_req_free(&q);
}

/* ---- geometry of the captured images ------------------------------------------------------------------------------------------------ */

/* The object count of `rbd info`, and a walk of the whole image through the extent iterator at three run limits: every run stays inside
 * one object, the runs add up to the size, the object numbers rise by one at each object boundary and end at the last object, the names
 * are the lower-case hex of the number (checked at the first, the last and a 64-bit object number). */
static void check_geometry(const wrt_json *ij, wrt_tok gt, const char *prefix, tally *t)
{
	static const uint32_t limits[] = {4096u, 1u << 20, 0xffffffffu};
	wri_rbd_geom g;
	uint64_t size = (uint64_t)ov_int(ij, gt, "size", 0), objects = (uint64_t)ov_int(ij, gt, "objects", 0);
	unsigned l;
	char name[WRI_RBD_OBJNAME_MAX + 8];

	WRT_CHECK_STATUS(WR_OK, wri_rbd_geom_init(&g, (uint8_t)ov_int(ij, gt, "order", 0)));
	WRT_CHECK_U64(g.object_size, ov_int(ij, gt, "object_size", -1));
	WRT_CHECK_U64(wri_rbd_geom_objects(&g, size), objects);
	WRT_CHECK(wri_rbd_geom_objects(&g, size + 1u) == objects + (size % g.object_size == 0 ? 1u : 0u)); /* a partial last object counts */
	WRT_CHECK(wri_rbd_geom_objects(&g, size - 1u) == objects);                                         /* and so does a short one */
	for (l = 0; l < sizeof(limits) / sizeof(limits[0]); l++) {
		uint64_t off = 0, covered = 0, last_obj = 0;
		unsigned runs = 0;

		while (off < size) {
			uint64_t objno, obj_off;
			uint32_t run;

			wri_rbd_geom_extent(&g, off, size - off, limits[l], &objno, &obj_off, &run);
			WRT_CHECK(run > 0 && run <= limits[l] && (uint64_t)run <= size - off && obj_off + run <= g.object_size);
			WRT_CHECK(objno == off / g.object_size && obj_off == off % g.object_size);
			WRT_CHECK(covered == 0 || objno == last_obj || objno == last_obj + 1u);
			last_obj = objno;
			off += run;
			covered += run;
			runs++;
			if (runs > 100000u) {
				WRT_CHECK(0);
				break;
			}
		}
		WRT_CHECK(covered == size && last_obj == objects - 1u);
		t->walks++;
	}
	WRT_CHECK(wri_rbd_obj_name(name, sizeof(name), prefix, 0) == strlen(prefix) + 17u);
	WRT_CHECK(strcmp(name + strlen(prefix), ".0000000000000000") == 0);
	WRT_CHECK(wri_rbd_obj_name(name, sizeof(name), prefix, objects - 1u) == strlen(prefix) + 17u);
	WRT_CHECK(strtoull(name + strlen(prefix) + 1, NULL, 16) == objects - 1u);
	/* a 64-bit object number: the 16 digits are all there, lower case */
	WRT_CHECK(wri_rbd_obj_name(name, sizeof(name), prefix, 0xfedcba9876543210ull) == strlen(prefix) + 17u);
	WRT_CHECK(strcmp(name + strlen(prefix), ".fedcba9876543210") == 0);
	{
		uint64_t objno, obj_off;
		uint32_t run;
		uint64_t far = ((uint64_t)1 << 50) + 5u; /* a byte of a petabyte-scale image: nothing is truncated to 32 bits */

		wri_rbd_geom_extent(&g, far, 7, 1u << 20, &objno, &obj_off, &run);
		WRT_CHECK(objno == far >> g.order && obj_off == (far & (g.object_size - 1u)) && run == 7u);
	}
}

/* ---- the replies against `rbd info` and the checker's header ---------------------------------------------------------------------- */

static const char *status_name_of(wr_status s)
{
	return wrt_status_name_((int32_t)s);
}

static wr_status status_from(const char *id)
{
	if (strcmp(id, "OK") == 0)
		return WR_OK;
	if (strcmp(id, "RBD_E_FEATURES") == 0)
		return WR_E_RBD_FEATURES;
	if (strcmp(id, "RBD_E_STRIPING") == 0)
		return WR_E_RBD_STRIPING;
	if (strcmp(id, "RBD_E_PARENT") == 0)
		return WR_E_RBD_PARENT;
	if (strcmp(id, "RBD_E_ORDER") == 0)
		return WR_E_RBD_ORDER;
	if (strcmp(id, "RBD_E_DATA_POOL") == 0)
		return WR_E_RBD_DATA_POOL;
	if (strcmp(id, "RBD_E_FLAGS") == 0)
		return WR_E_RBD_FLAGS;
	if (strcmp(id, "RBD_E_SNAPC") == 0)
		return WR_E_RBD_SNAPC;
	return (wr_status)-1;
}

typedef struct decoded {
	wri_rbd_hdr h;
	char id[WRI_RBD_ID_MAX];
	uint64_t incompatible[2];
	uint64_t snaps[WRI_OSD_OPS_MAX * 8];
	wri_snapc snapc;
	uint32_t n_total;
	uint32_t lockers;
	uint8_t lock_type;
	char lock_tag[32];
	int got_header, got_stripe, got_op, got_lock, got_id;
} decoded;

/* One output of a header read through the decoder that belongs to it (the label and the position in the message say which). */
static wr_status dec_one(const char *label, unsigned i, const uint8_t *out, uint32_t n, decoded *d)
{
	wr_status st = WR_OK;

	if (strcmp(label, "get_id") == 0) {
		st = wri_rbd_dec_id(out, n, d->id);
		d->got_id = st == WR_OK;
	} else if (strcmp(label, "lock-get-info") == 0) {
		st = wri_rbd_dec_lock_info(out, n, &d->lockers, &d->lock_type, d->lock_tag, sizeof(d->lock_tag));
		d->got_lock = st == WR_OK;
	} else if (strcmp(label, "stripe-unit-count") == 0) {
		st = wri_rbd_dec_stripe(out, n, &d->h.stripe_unit, &d->h.stripe_count);
		d->got_stripe = st == WR_OK;
	} else if (strcmp(label, "op-features") == 0) {
		st = wri_rbd_dec_u64(out, n, &d->h.op_features);
		d->got_op = st == WR_OK;
	} else {
		/* header8: size, prefix, features, flags, snapcontext, data pool, parent, overlap */
		uint8_t present = 0;
		uint8_t has_parent = 0;
		int64_t pool = 0;

		switch (i) {
		case 0:
			st = wri_rbd_dec_size(out, n, &d->h.order, &d->h.size);
			break;
		case 1:
			st = wri_rbd_dec_prefix(out, n, d->h.prefix);
			break;
		case 2:
			st = wri_rbd_dec_features(out, n, &d->h.features, &d->incompatible[strcmp(label, "header8-writer") == 0]);
			break;
		case 3:
			st = wri_rbd_dec_u64(out, n, &d->h.flags);
			break;
		case 4:
			d->snapc.snaps = d->snaps;
			d->snapc.cap = (uint32_t)(sizeof(d->snaps) / sizeof(d->snaps[0]));
			st = wri_rbd_dec_snapcontext(out, n, &d->snapc, &d->n_total);
			break;
		case 5:
			st = wri_rbd_dec_i64(out, n, &pool);
			d->h.data_pool_id = pool;
			break;
		case 6:
			st = wri_rbd_dec_parent(out, n, &has_parent);
			d->h.has_parent = has_parent;
			break;
		case 7:
			st = wri_rbd_dec_overlap(out, n, &present, &d->h.overlap);
			d->h.has_overlap = present;
			d->got_header = st == WR_OK;
			break;
		default:
			WRT_CHECK(0);
		}
	}
	return st;
}

/* 1 if every output of the decoder for this position is clear (what a failed decode must leave). */
static int dec_clear(const decoded *d, const char *label, unsigned i)
{
	size_t k;

	if (strcmp(label, "get_id") == 0) {
		for (k = 0; k < sizeof(d->id); k++)
			if (d->id[k] != 0)
				return 0;
		return 1;
	}
	if (strcmp(label, "lock-get-info") == 0) {
		for (k = 0; k < sizeof(d->lock_tag); k++)
			if (d->lock_tag[k] != 0)
				return 0;
		return d->lockers == 0 && d->lock_type == 0;
	}
	if (strcmp(label, "stripe-unit-count") == 0)
		return d->h.stripe_unit == 0 && d->h.stripe_count == 0;
	if (strcmp(label, "op-features") == 0)
		return d->h.op_features == 0;
	switch (i) {
	case 0:
		return d->h.order == 0 && d->h.size == 0;
	case 1:
		for (k = 0; k < sizeof(d->h.prefix); k++)
			if (d->h.prefix[k] != 0)
				return 0;
		return 1;
	case 2:
		return d->h.features == 0 && d->incompatible[0] == 0 && d->incompatible[1] == 0;
	case 3:
		return d->h.flags == 0;
	case 4:
		for (k = 0; k < sizeof(d->snaps) / sizeof(d->snaps[0]); k++)
			if (d->snaps[k] != 0)
				return 0;
		return d->snapc.seq == 0 && d->snapc.n == 0;
	case 5:
		return d->h.data_pool_id == 0;
	case 6:
		return d->h.has_parent == 0;
	default:
		return d->h.has_overlap == 0 && d->h.overlap == 0;
	}
}

/* What a decode that succeeded on damaged bytes must still satisfy. */
static void dec_sane(const decoded *d, const char *label, unsigned i)
{
	size_t k;

	if (strcmp(label, "get_id") == 0) {
		size_t len = strlen(d->id);

		WRT_CHECK(len >= 1 && len < WRI_RBD_ID_MAX);
		for (k = 0; k < len; k++)
			WRT_CHECK((d->id[k] >= '0' && d->id[k] <= '9') || (d->id[k] >= 'a' && d->id[k] <= 'z') || (d->id[k] >= 'A' && d->id[k] <= 'Z'));
	} else if (strcmp(label, "lock-get-info") == 0) {
		WRT_CHECK(d->lockers <= 64u && d->lock_type <= 3u && strlen(d->lock_tag) < sizeof(d->lock_tag));
	} else if (strcmp(label, "header8-reader") == 0 || strcmp(label, "header8-writer") == 0) {
		if (i == 1) {
			size_t len = strlen(d->h.prefix);

			WRT_CHECK(len >= 1 && len <= WRI_RBD_PREFIX_LEN_MAX);
			for (k = 0; k < len; k++)
				WRT_CHECK((uint8_t)d->h.prefix[k] >= 0x21 && (uint8_t)d->h.prefix[k] <= 0x7e);
		} else if (i == 4) {
			WRT_CHECK(wri_snapc_valid(&d->snapc) && d->snapc.n <= d->snapc.cap && d->n_total == d->snapc.n);
		} else if (i == 7) {
			WRT_CHECK(d->h.has_overlap <= 1u && (d->h.has_overlap == 1u || d->h.overlap == 0));
		} else if (i == 6) {
			WRT_CHECK(d->h.has_parent <= 1u);
		}
	}
}

/*
 * The damage sweep over one captured output: one byte less and one byte more are protocol errors (every decoder consumes its output
 * exactly), so is every cut; seven damaged values at every byte and every 32-bit window set to a hostile length: no read outside the
 * allocation, a failed decode leaves its outputs clear, a successful one still satisfies what its decoder promises.
 */
static void sweep_output(const char *label, unsigned i, const uint8_t *out, uint32_t n, tally *t)
{
	static const uint32_t words[] = {0xffffffffu, 0x7fffffffu, 0x80000000u, 0x00010000u, 0x00000100u};
	decoded *d = (decoded *)calloc(1, sizeof(*d));
	uint8_t *c = (uint8_t *)malloc(n + 1u);
	uint32_t k, b, w;
	static const uint8_t bytes[] = {0x00, 0x01, 0x7f, 0x80, 0xff};

	WRT_CHECK(d != NULL && c != NULL);
	if (d == NULL || c == NULL) {
		free(d);
		free(c);
		return;
	}
	memcpy(c, out, n);
	c[n] = 0x5a;
	/* one more byte */
	WRT_CHECK(dec_one(label, i, c, n + 1u, d) != WR_OK && dec_clear(d, label, i));
	/* every shorter length, in an allocation of exactly that length */
	for (k = 0; k < n; k++) {
		uint8_t *e = (uint8_t *)malloc(k != 0 ? k : 1);

		memset(d, 0, sizeof(*d));
		memcpy(e, out, k);
		WRT_CHECK(dec_one(label, i, e, k, d) != WR_OK);
		WRT_CHECK(dec_clear(d, label, i));
		free(e);
		t->sweeps++;
	}
	/* damage inside an exact-size copy */
	free(c);
	c = (uint8_t *)malloc(n != 0 ? n : 1);
	memcpy(c, out, n);
	for (k = 0; k < n; k++) {
		uint8_t orig = c[k];

		for (b = 0; b < sizeof(bytes) + 2u; b++) {
			wr_status st;

			c[k] = b < sizeof(bytes) ? bytes[b] : (uint8_t)(orig ^ (b == sizeof(bytes) ? 0x01u : 0x80u));
			memset(d, 0, sizeof(*d));
			st = dec_one(label, i, c, n, d);
			if (st == WR_OK)
				dec_sane(d, label, i);
			else
				WRT_CHECK(dec_clear(d, label, i));
			t->sweeps++;
		}
		c[k] = orig;
	}
	for (k = 0; k + 4u <= n; k++) {
		uint8_t save[4];

		memcpy(save, c + k, 4);
		for (w = 0; w < sizeof(words) / sizeof(words[0]); w++) {
			wr_status st;

			c[k] = (uint8_t)words[w];
			c[k + 1] = (uint8_t)(words[w] >> 8);
			c[k + 2] = (uint8_t)(words[w] >> 16);
			c[k + 3] = (uint8_t)(words[w] >> 24);
			memset(d, 0, sizeof(*d));
			st = dec_one(label, i, c, n, d);
			if (st == WR_OK)
				dec_sane(d, label, i);
			else
				WRT_CHECK(dec_clear(d, label, i));
			t->sweeps++;
		}
		memcpy(c + k, save, 4);
	}
	free(c);
	free(d);
}

/* the outputs of one reply, cut by the operation lengths, through the decoders of the core */
static void decode_reply(const char *where, const ov_msg *rq, const ov_msg *rp, const char *label, decoded *d, tally *t)
{
	wri_mosdopreply r;
	size_t off = 0;
	unsigned i;
	const uint8_t *data = rp->data;
	const char *w = where;

	WRT_CHECK(wri_mosdopreply_decode(rp->front, rp->front_len, rp->version, rp->compat, &r) == WR_OK);
	WRT_CHECK(r.result == 0 && r.out_total == rp->data_total && data != NULL);
	if (data == NULL)
		return;
	(void)rq;
	for (i = 0; i < r.n_ops; i++) {
		const uint8_t *out = data + off;
		uint32_t n = r.out_len[i];
		wr_status st;

		WRT_CHECK(r.rval[i] == 0);
		st = dec_one(label, i, out, n, d);
		if (st != WR_OK)
			fprintf(stderr, "%s %s output %u: %s\n", w, label, i, status_name_of(st));
		WRT_CHECK_STATUS(WR_OK, st);
		sweep_output(label, i, out, n, t);
		off += n;
	}
	WRT_CHECK(off == rp->data_len);
}

static void check_verdict(const wrt_json *j, const char *name, const char *who, wrt_tok exp, const wri_rbd_hdr *h, int writer, tally *t)
{
	wr_errinfo why;
	wr_status st, want;
	wrt_tok num;
	char *sid = wrt_json_strdup(j, wrt_json_at(j, exp, 0));

	memset(&why, 0, sizeof(why));
	WRT_CHECK(sid != NULL);
	want = status_from(sid != NULL ? sid : "");
	WRT_CHECK(want != (wr_status)-1);
	st = wri_rbd_check_profile(h, writer, &why);
	if (st != want)
		fprintf(stderr, "%s %s: wri_rbd_check_profile says %s, the checker says %s\n", name, who, status_name_of(st), sid != NULL ? sid : "?");
	WRT_CHECK_STATUS(want, st);
	num = wrt_json_at(j, exp, 1);
	if (st == WR_E_RBD_FEATURES) {
		WRT_CHECK_U64(why.a0, ov_int(j, num, "a0", -1));
		WRT_CHECK_U64(why.a1, ov_int(j, num, "a1", -1));
		WRT_CHECK_U64(why.a2, ov_int(j, num, "a2", -1));
	} else if (st == WR_E_RBD_STRIPING) {
		WRT_CHECK_U64(why.a0, ov_int(j, num, "a0", -1));
		WRT_CHECK_U64(why.a1, ov_int(j, num, "a1", -1));
		WRT_CHECK_U64(why.a2, ov_int(j, num, "a2", -1));
	} else if (st == WR_E_RBD_PARENT) {
		uint64_t mask = (uint64_t)ov_int(j, num, "parent_get", 0) | ((uint64_t)ov_int(j, num, "overlap", 0) << 1) |
				((uint64_t)ov_int(j, num, "clone_child", 0) << 2);

		WRT_CHECK_U64(why.a0, mask);
	} else if (st == WR_E_RBD_FLAGS) {
		WRT_CHECK_U64(why.a0, ov_int(j, num, "a0", -1));
	}
	if (st != WR_OK) {
		WRT_CHECK(why.status == st && why.module == WR_MOD_RBD && why.what != NULL);
	} else {
		WRT_CHECK(why.status == WR_OK);
	}
	free(sid);
	t->verdicts++;
}

static void check_image(const wrt_json *ij, wrt_tok im, tally *t)
{
	char *name = wrt_json_strdup(ij, wrt_json_get(ij, im, "name"));
	wrt_tok gt = wrt_json_get(ij, im, "gt"), hd = wrt_json_get(ij, im, "header"), ex = wrt_json_get(ij, im, "expect");
	char rel[200];
	wrt_json sj;
	wrt_tok exs;
	decoded rd, wr;
	size_t k;
	char *gid;

	memset(&rd, 0, sizeof(rd));
	memset(&wr, 0, sizeof(wr));
	WRT_CHECK(name != NULL && gt != WRT_NONE && hd != WRT_NONE && ex != WRT_NONE);
	if (name == NULL)
		return;
	snprintf(rel, sizeof(rel), "sessions/hdr-%s.json", name);
	if (ov_load(&sj, rel) != 0) {
		WRT_CHECK(0);
		free(name);
		return;
	}
	exs = wrt_json_get(&sj, wrt_json_root(&sj), "exchanges");
	for (k = 0; exs != WRT_NONE && k < wrt_json_count(&sj, exs); k++) {
		wrt_tok e = wrt_json_at(&sj, exs, k);
		char *label = wrt_json_strdup(&sj, wrt_json_get(&sj, e, "label"));
		char where[200];
		ov_msg rq, rp;

		snprintf(where, sizeof(where), "%s %s", name, label != NULL ? label : "?");
		memset(&rp, 0, sizeof(rp));
		if (label == NULL || ov_msg_load(&rq, &sj, wrt_json_get(&sj, e, "request")) != 0 ||
		    ov_msg_load(&rp, &sj, wrt_json_get(&sj, e, "reply")) != 0) {
			WRT_CHECK(0);
			free(label);
			continue;
		}
		check_request(&sj, where, &rq, label, t);
		/* the object the message went to: the names the core builds are the ones the stock client used */
		{
			char *oid = wrt_json_strdup(&sj, wrt_json_get(&sj, rq.summary, "oid"));
			char built[WRI_RBD_OBJNAME_MAX + 16];
			char *id = wrt_json_strdup(ij, wrt_json_get(ij, gt, "id"));
			size_t n;

			if (strcmp(label, "get_id") == 0)
				n = wri_rbd_id_obj_name(built, sizeof(built), name);
			else
				n = wri_rbd_header_obj_name(built, sizeof(built), id != NULL ? id : "");
			WRT_CHECK(oid != NULL && n == strlen(oid) && strcmp(built, oid) == 0);
			free(oid);
			free(id);
		}
		decode_reply(where, &rq, &rp, label, strcmp(label, "header8-writer") == 0 ? &wr : &rd, t);
		ov_msg_free(&rq);
		ov_msg_free(&rp);
		free(label);
	}
	WRT_CHECK(rd.got_header && wr.got_header && rd.got_id && rd.got_lock);

	/* what was decoded equals `rbd info`, the snapshot list of `rbd snap ls` and the checker's header */
	gid = wrt_json_strdup(ij, wrt_json_get(ij, gt, "id"));
	WRT_CHECK(gid != NULL && strcmp(rd.id, gid) == 0);
	free(gid);
	{
		char *pfx = wrt_json_strdup(ij, wrt_json_get(ij, gt, "block_name_prefix"));

		WRT_CHECK(pfx != NULL && strcmp(rd.h.prefix, pfx) == 0);
		free(pfx);
	}
	WRT_CHECK_U64(rd.h.order, ov_int(ij, gt, "order", -1));
	WRT_CHECK_U64(rd.h.size, ov_int(ij, gt, "size", -1));
	{
		char *pfx = wrt_json_strdup(ij, wrt_json_get(ij, gt, "block_name_prefix"));

		WRT_CHECK(pfx != NULL);
		if (pfx != NULL)
			check_geometry(ij, gt, pfx, t);
		free(pfx);
	}
	WRT_CHECK_U64(rd.h.features, ov_int(ij, gt, "features_mask", -1));
	WRT_CHECK_U64(rd.h.features, ov_int(ij, hd, "features", -1));
	WRT_CHECK_U64(rd.h.flags, ov_int(ij, hd, "flags", -1));
	WRT_CHECK(rd.h.has_parent == (wrt_json_get(ij, gt, "parent") != WRT_NONE));
	WRT_CHECK_U64(rd.h.has_parent, ov_int(ij, hd, "has_parent", -1));
	WRT_CHECK_U64(rd.h.has_overlap, ov_int(ij, hd, "has_overlap", -1));
	WRT_CHECK_U64(rd.h.overlap, ov_int(ij, hd, "overlap", -1));
	WRT_CHECK(rd.h.data_pool_id == ov_int(ij, hd, "data_pool", 1));
	if (wrt_json_get(ij, gt, "data_pool_id") != WRT_NONE)
		WRT_CHECK(rd.h.data_pool_id == ov_int(ij, gt, "data_pool_id", 1));
	else
		WRT_CHECK(rd.h.data_pool_id == -1);
	if (rd.h.features & WRI_RBD_F_STRIPINGV2) {
		WRT_CHECK(rd.got_stripe);
		WRT_CHECK_U64(rd.h.stripe_unit, ov_int(ij, gt, "stripe_unit", -1));
		WRT_CHECK_U64(rd.h.stripe_count, ov_int(ij, gt, "stripe_count", -1));
	}
	WRT_CHECK((rd.h.features & WRI_RBD_F_OPERATIONS) == 0 && !rd.got_op);
	/* the server's own `incompatible` field is logged only: the reader form carries its read mask, the writer form its write mask */
	WRT_CHECK_U64(rd.incompatible[0], ov_int(ij, hd, "incompatible_reader", -1));
	WRT_CHECK_U64(wr.incompatible[1], ov_int(ij, hd, "incompatible_writer", -1));
	/* the snapshot context equals the snapshots the stock tool lists, descending, and is valid */
	{
		wrt_tok sn = wrt_json_get(ij, gt, "snaps"), hs = wrt_json_get(ij, hd, "snaps");
		size_t n = sn != WRT_NONE ? wrt_json_count(ij, sn) : 0, a;
		uint64_t last = 0, top = 0;

		WRT_CHECK_U64(rd.snapc.n, n);
		WRT_CHECK_U64(rd.n_total, n);
		WRT_CHECK_U64(rd.snapc.n, wrt_json_count(ij, hs));
		WRT_CHECK(wri_snapc_valid(&rd.snapc));
		for (a = 0; a < n; a++) {
			uint64_t id = (uint64_t)ov_int(ij, wrt_json_at(ij, sn, a), "id", -1);

			if (id > top)
				top = id;
		}
		for (a = 0; a < rd.snapc.n; a++) {
			uint64_t want = ov_u64_tok(ij, wrt_json_at(ij, hs, a));
			size_t b;
			int listed = 0;

			WRT_CHECK_U64(rd.snapc.snaps[a], want);
			WRT_CHECK(a == 0 || rd.snapc.snaps[a] < last);
			last = rd.snapc.snaps[a];
			for (b = 0; b < n; b++)
				if ((uint64_t)ov_int(ij, wrt_json_at(ij, sn, b), "id", -1) == last)
					listed = 1;
			WRT_CHECK(listed);
		}
		WRT_CHECK(rd.snapc.seq >= top);
		WRT_CHECK_U64(rd.snapc.seq, ov_u64(ij, hd, "snap_seq"));
	}
	/* the lock record: "locked" is decided by the number of lockers alone */
	WRT_CHECK_U64(rd.lockers, ov_int(ij, hd, "lockers", -1));
	WRT_CHECK_U64(rd.lockers, ov_int(ij, gt, "locks", -1));
	WRT_CHECK_U64(rd.lock_type, ov_int(ij, hd, "lock_type", -1));
	/* the refusal table, both profiles */
	check_verdict(ij, name, "reader", wrt_json_get(ij, ex, "reader"), &rd.h, 0, t);
	check_verdict(ij, name, "writer", wrt_json_get(ij, ex, "writer"), &rd.h, 1, t);
	t->images++;
	wrt_json_free(&sj);
	free(name);
}

/* a header read of an image that does not exist, and the id object that does not exist: -ENOENT for the whole message */
static void check_missing(void)
{
	wrt_json j;
	wrt_tok exs;
	size_t k;

	if (ov_load(&j, "sessions/hdr-missing.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	exs = wrt_json_get(&j, wrt_json_root(&j), "exchanges");
	WRT_CHECK(exs != WRT_NONE && wrt_json_count(&j, exs) == 2);
	for (k = 0; exs != WRT_NONE && k < wrt_json_count(&j, exs); k++) {
		wrt_tok e = wrt_json_at(&j, exs, k);
		char *label = wrt_json_strdup(&j, wrt_json_get(&j, e, "label"));
		ov_msg rq, rp;
		wri_mosdopreply r;

		WRT_CHECK(label != NULL && ov_msg_load(&rq, &j, wrt_json_get(&j, e, "request")) == 0 && ov_msg_load(&rp, &j, wrt_json_get(&j, e, "reply")) == 0);
		if (label == NULL)
			continue;
		WRT_CHECK(strcmp(label, k == 0 ? "get_id-missing" : "header8-missing") == 0);
		WRT_CHECK(wri_mosdopreply_decode(rp.front, rp.front_len, rp.version, rp.compat, &r) == WR_OK);
		WRT_CHECK(r.result == -2 && r.out_total == 0 && rp.data_total == 0);
		WRT_CHECK_STATUS(WR_E_OSD_NOENT, wri_osd_errno_status(r.result));
		{
			unsigned i;

			for (i = 0; i < r.n_ops; i++)
				WRT_CHECK(r.rval[i] == 0 && r.out_len[i] == 0);
		}
		/* the message that failed as a whole is the very request of the open: eight calls, or one for the id */
		WRT_CHECK_U64(r.n_ops, k == 0 ? 1 : 8);
		check_request(&j, "hdr-missing", &rq, k == 0 ? "get_id" : "header8-reader", &(tally){0});
		ov_msg_free(&rq);
		ov_msg_free(&rp);
		free(label);
	}
	wrt_json_free(&j);
}

/* ---- data objects of patterned images ------------------------------------------------------------------------------------------------ */

static uint8_t pat_byte(const wrt_json *j, wrt_tok segs, uint64_t o)
{
	size_t k;

	for (k = 0; k < wrt_json_count(j, segs); k++) {
		wrt_tok s = wrt_json_at(j, segs, k);
		uint64_t off = (uint64_t)wrt_json_int(j, wrt_json_at(j, s, 0), &(int){0}), len = (uint64_t)wrt_json_int(j, wrt_json_at(j, s, 1), &(int){0});
		uint64_t mul = (uint64_t)wrt_json_int(j, wrt_json_at(j, s, 2), &(int){0}), add = (uint64_t)wrt_json_int(j, wrt_json_at(j, s, 3), &(int){0});

		if (o >= off && o - off < len)
			return (uint8_t)((o * mul + add) % 251u);
	}
	return 0;
}

static void check_objects(tally *t)
{
	wrt_json j;
	wrt_tok pats, objs;
	size_t p, k;

	if (ov_load(&j, "objects.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	pats = wrt_json_get(&j, wrt_json_root(&j), "images");
	objs = wrt_json_get(&j, wrt_json_root(&j), "objects");
	WRT_CHECK(pats != WRT_NONE && objs != WRT_NONE);
	for (p = 0; pats != WRT_NONE && p < wrt_json_count(&j, pats); p++) {
		wrt_tok pt = wrt_json_at(&j, pats, p);
		char *name = wrt_json_strdup(&j, wrt_json_get(&j, pt, "name"));
		char *prefix = wrt_json_strdup(&j, wrt_json_get(&j, pt, "prefix"));
		wrt_tok segs = wrt_json_get(&j, pt, "segments");
		uint64_t size = (uint64_t)ov_int(&j, pt, "size", 0);
		wri_rbd_geom g;
		uint64_t nobj, o;
		uint8_t *present;
		char oname[WRI_RBD_OBJNAME_MAX + 8];

		WRT_CHECK(name != NULL && prefix != NULL && segs != WRT_NONE);
		WRT_CHECK_STATUS(WR_OK, wri_rbd_geom_init(&g, (uint8_t)ov_int(&j, pt, "order", 0)));
		nobj = wri_rbd_geom_objects(&g, size);
		present = (uint8_t *)calloc((size_t)nobj, 1);
		WRT_CHECK(present != NULL && nobj > 0 && nobj <= 1024);
		if (present == NULL || nobj == 0 || nobj > 1024)
			continue;
		/* the recipe's data runs through the extent iterator: the bytes are where the geometry says */
		for (k = 0; k < wrt_json_count(&j, segs); k++) {
			wrt_tok s = wrt_json_at(&j, segs, k);
			uint64_t off = (uint64_t)wrt_json_int(&j, wrt_json_at(&j, s, 0), &(int){0}), len = (uint64_t)wrt_json_int(&j, wrt_json_at(&j, s, 1), &(int){0});

			while (len > 0) {
				uint64_t objno, obj_off;
				uint32_t run;

				wri_rbd_geom_extent(&g, off, len, 1u << 20, &objno, &obj_off, &run);
				WRT_CHECK(objno == off / g.object_size && obj_off == off % g.object_size && run > 0 && run <= len && obj_off + run <= g.object_size);
				if (objno < nobj)
					present[objno] = 1;
				else
					WRT_CHECK(0);
				t->ranges++;
				off += run;
				len -= run;
			}
		}
		/* the exported objects: named as the core names them, every byte equal to the pattern, and exactly the objects the geometry says */
		for (k = 0; k < wrt_json_count(&j, objs); k++) {
			wrt_tok ot = wrt_json_at(&j, objs, k);
			char *img = wrt_json_strdup(&j, wrt_json_get(&j, ot, "image"));
			char *file = wrt_json_strdup(&j, wrt_json_get(&j, ot, "file"));
			uint64_t objno = (uint64_t)ov_int(&j, ot, "objno", -1);
			uint8_t *blob = NULL;
			size_t n = 0, i;
			char path[200];

			if (img == NULL || file == NULL || strcmp(img, name) != 0) {
				free(img);
				free(file);
				continue;
			}
			snprintf(path, sizeof(path), OV_DIR "%s", file);
			WRT_CHECK(wrt_read_file(wrt_vec_path(path), &blob, &n) == 0);
			WRT_CHECK(blob != NULL && n == (size_t)ov_int(&j, ot, "size", -1) && n <= g.object_size);
			WRT_CHECK(objno < nobj && present[objno] == 1);
			present[objno] = 2; /* seen */
			WRT_CHECK(wri_rbd_obj_name(oname, sizeof(oname), prefix, objno) == strlen(prefix) + 17u);
			for (i = 0; blob != NULL && i < n; i++)
				if (blob[i] != pat_byte(&j, segs, objno * g.object_size + i)) {
					fprintf(stderr, "%s object %llu: byte %zu differs from the pattern\n", name, (unsigned long long)objno, i);
					WRT_CHECK(0);
					break;
				}
			free(blob);
			free(img);
			free(file);
			t->objects++;
		}
		for (o = 0; o < nobj; o++) {
			if (present[o] == 1)
				fprintf(stderr, "%s: object %llu should hold data but was not exported\n", name, (unsigned long long)o);
			WRT_CHECK(present[o] != 1);
		}
		/* the names of the stock tool's own reads: every request of its session names an object the core builds identically */
		{
			char rel[160];
			wrt_json sj;

			snprintf(rel, sizeof(rel), "sessions/objects-%s.json", name);
			if (ov_load(&sj, rel) == 0) {
				wrt_tok exs = wrt_json_get(&sj, wrt_json_root(&sj), "exchanges");

				for (k = 0; exs != WRT_NONE && k < wrt_json_count(&sj, exs); k++) {
					wrt_tok e = wrt_json_at(&sj, exs, k);
					wrt_tok rs = wrt_json_get(&sj, wrt_json_get(&sj, e, "request"), "summary");
					char *oid = wrt_json_strdup(&sj, wrt_json_get(&sj, rs, "oid"));
					unsigned long long no = 0;
					int matched = 0;

					WRT_CHECK(oid != NULL);
					if (oid != NULL) {
						size_t pl = strlen(prefix);

						if (strncmp(oid, prefix, pl) == 0 && oid[pl] == '.') {
							no = strtoull(oid + pl + 1, NULL, 16);
							matched = wri_rbd_obj_name(oname, sizeof(oname), prefix, no) == strlen(oid) && strcmp(oname, oid) == 0;
						}
						WRT_CHECK(matched);
						/* a whole-object read returns exactly the exported object, a read of one that holds nothing is -ENOENT */
						{
							wrt_tok rp = wrt_json_get(&sj, wrt_json_get(&sj, e, "reply"), "summary");
							int zero_fill = 0;
							int32_t result = (int32_t)ov_int(&sj, rp, "result", 1);
							wr_status st = wri_rbd_op_status(WRI_OSD_OP_READ, result, &zero_fill);

							if (no < nobj && present[no] == 2) {
								WRT_CHECK(result >= 0);
								WRT_CHECK_STATUS(WR_OK, st);
								WRT_CHECK(zero_fill == 0);
							} else {
								WRT_CHECK(result == -2);
								WRT_CHECK_STATUS(WR_OK, st); /* no parent: a missing object reads as zeros ... */
								WRT_CHECK(zero_fill == 1);   /* ... and the caller zero-fills it */
							}
							t->statuses++;
						}
					}
					free(oid);
				}
				wrt_json_free(&sj);
			} else {
				WRT_CHECK(0);
			}
		}
		free(present);
		free(name);
		free(prefix);
	}
	wrt_json_free(&j);
}

/* ---- the image requests of the data path: statuses and shapes ------------------------------------------------------------------------- */

static void check_io(tally *t)
{
	wrt_json j;
	wrt_tok exs;
	size_t k;
	unsigned short_reads = 0, zero_fills = 0, past_end = 0, trunc_echo = 0, whiteouts = 0;

	if (ov_load(&j, "sessions/io-plain.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	exs = wrt_json_get(&j, wrt_json_root(&j), "exchanges");
	for (k = 0; exs != WRT_NONE && k < wrt_json_count(&j, exs); k++) {
		wrt_tok e = wrt_json_at(&j, exs, k);
		wrt_tok rs = wrt_json_get(&j, wrt_json_get(&j, e, "request"), "summary"), ps = wrt_json_get(&j, wrt_json_get(&j, e, "reply"), "summary");
		wrt_tok op0 = wrt_json_at(&j, wrt_json_get(&j, rs, "ops"), 0), pop0 = wrt_json_at(&j, wrt_json_get(&j, ps, "ops"), 0);
		uint16_t code = (uint16_t)ov_int(&j, op0, "code", 0);
		int32_t result = (int32_t)ov_int(&j, ps, "result", 1);
		int zf = 0;
		wr_status st = wri_rbd_op_status(code, result, &zf);

		/* ENOENT of READ, ZERO, TRUNCATE and DELETE is success for an image without a parent; READ then zero-fills */
		if (result == -2 && (code == WRI_OSD_OP_READ || code == WRI_OSD_OP_ZERO || code == WRI_OSD_OP_TRUNCATE || code == WRI_OSD_OP_DELETE)) {
			WRT_CHECK_STATUS(WR_OK, st);
			WRT_CHECK(zf == (code == WRI_OSD_OP_READ));
			zero_fills += code == WRI_OSD_OP_READ;
		}
		/* a STAT of a missing object is not an image operation: the status stays an OSD error */
		if (result == -2 && code == WRI_OSD_OP_STAT)
			WRT_CHECK_STATUS(WR_E_OSD_NOENT, st);
		if (result >= 0)
			WRT_CHECK_STATUS(WR_OK, st);
		if (code == WRI_OSD_OP_READ && result == 0) {
			uint64_t want = (uint64_t)ov_int(&j, op0, "len", 0), got = (uint64_t)ov_int(&j, pop0, "out_len", 0);
			uint64_t off = (uint64_t)ov_int(&j, op0, "off", 0);

			/* a short read: the caller zero-fills the rest of the extent (the object ends, or has a hole) */
			if (want != 0 && got < want) {
				short_reads++;
				WRT_CHECK(got + (want - got) == want);
			}
			/* a read that starts at or beyond the end is empty and successful */
			if (got == 0 && off > 0 && want != 0)
				past_end++;
		}
		if (code == WRI_OSD_OP_ZERO && (uint16_t)ov_int(&j, pop0, "code", 0) == WRI_OSD_OP_TRUNCATE)
			trunc_echo++;
	}
	/* the shapes of discard on a 16 KiB object, and what the OSD did with the stock tool's ZERO of the same shapes */
	{
		wri_rbd_geom g;

		WRT_CHECK_STATUS(WR_OK, wri_rbd_geom_init(&g, 14));
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 100, 200), WRI_OSD_OP_ZERO);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 5000, 16384 - 5000), WRI_OSD_OP_TRUNCATE);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, 16384), WRI_OSD_OP_DELETE);
	}
	wrt_json_free(&j);

	/* the snapshot context of the writes: the image header's, valid, and what the OSD answered to every write carrying it */
	if (ov_load(&j, "sessions/io-snap.json") == 0) {
		exs = wrt_json_get(&j, wrt_json_root(&j), "exchanges");
		for (k = 0; exs != WRT_NONE && k < wrt_json_count(&j, exs); k++) {
			wrt_tok e = wrt_json_at(&j, exs, k);
			wrt_tok rs = wrt_json_get(&j, wrt_json_get(&j, e, "request"), "summary"), ps = wrt_json_get(&j, wrt_json_get(&j, e, "reply"), "summary");
			ov_req q;
			ov_msg rq;

			if (ov_msg_load(&rq, &j, wrt_json_get(&j, e, "request")) == 0 && ov_req_build(&q, &j, rs, (uint8_t)rq.version) == 0) {
				WRT_CHECK(wri_snapc_valid(&q.snapc));
				if ((q.h.flags & WRI_OSDF_WRITE) != 0 && q.snapc.n > 0) {
					WRT_CHECK(q.h.snapid == WRI_SNAP_NOSNAP);
					WRT_CHECK(q.snapc.snaps[0] <= q.snapc.seq);
					WRT_CHECK((int32_t)ov_int(&j, ps, "result", 1) == 0);
					whiteouts++;
				}
				ov_req_free(&q);
			} else {
				WRT_CHECK(0);
			}
			ov_msg_free(&rq);
		}
		wrt_json_free(&j);
	} else {
		WRT_CHECK(0);
	}
	WRT_CHECK(short_reads >= 3 && zero_fills >= 2 && past_end >= 1 && trunc_echo >= 2 && whiteouts >= 4);
	t->statuses += short_reads + zero_fills;
}

/* ---- the refusal rules over a grid, against a model of the note ----------------------------------------------------------------------- */

/* rbd-format2.md 3.3 / 4.2 in the note's own order: feature bits (reader 0x1ff, writer 0xa1, the striping bit judged by its layout for both),
 * object size 12 to 25, striping, parent, data pool, flags (writer only). */
static wr_status model_refusal(const wri_rbd_hdr *h, int writer, uint64_t *a0)
{
	uint64_t mask = (writer ? 0xa1ull : 0x1ffull) | 0x2ull;

	*a0 = 0;
	if ((h->features & ~mask) != 0) {
		*a0 = h->features & ~mask;
		return WR_E_RBD_FEATURES;
	}
	if (h->order < 12 || h->order > 25) {
		*a0 = h->order;
		return WR_E_RBD_ORDER;
	}
	if ((h->features & 2u) != 0 && h->stripe_unit != 0 && h->stripe_count != 0 &&
	    (h->stripe_count != 1 || h->stripe_unit != ((uint64_t)1 << h->order)))
		return WR_E_RBD_STRIPING;
	if (h->has_parent || h->has_overlap || ((h->features & 0x100u) != 0 && (h->op_features & 2u) != 0))
		return WR_E_RBD_PARENT;
	if ((h->features & 0x80u) != 0 && h->data_pool_id < 0)
		return WR_E_RBD_DATA_POOL;
	if (writer && h->flags != 0)
		return WR_E_RBD_FLAGS;
	return WR_OK;
}

static void check_policy_grid(tally *t)
{
	static const uint64_t features[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x8, 0x10, 0x20, 0x21, 0x23, 0x40, 0x80, 0x81, 0xa1, 0xa3, 0x3d, 0x45, 0x100, 0x101, 0x181,
					    0x1ff, 0x200, 0x400, 0x800, 0x1000, 0x1a1, 0x80000000ull, 0x8000000000000000ull, 0xffffffffffffffffull};
	static const uint8_t orders[] = {0, 11, 12, 13, 16, 22, 25, 26, 63, 64, 255};
	static const uint64_t strides[][2] = {{0, 0}, {4096, 1}, {0, 5}, {4096, 4}, {8192, 1}, {1u << 22, 1}, {1u << 22, 2}, {1, 1}};
	static const int64_t pools[] = {-1, 0, 167, INT64_MIN};
	static const uint64_t opf[] = {0, 2, 0xff};
	static const uint64_t flags[] = {0, 1, 3};
	size_t f, o, s, p, q, a, b, w;

	for (f = 0; f < sizeof(features) / sizeof(features[0]); f++)
		for (o = 0; o < sizeof(orders); o++)
			for (s = 0; s < sizeof(strides) / sizeof(strides[0]); s++)
				for (p = 0; p < 3; p++)
					for (q = 0; q < sizeof(opf) / sizeof(opf[0]); q++)
						for (a = 0; a < sizeof(flags) / sizeof(flags[0]); a++)
							for (b = 0; b < sizeof(pools) / sizeof(pools[0]); b++)
								for (w = 0; w < 2; w++) {
									wri_rbd_hdr h;
									wr_errinfo why;
									uint64_t want_a0;
									wr_status want, got;

									memset(&h, 0, sizeof(h));
									h.features = features[f];
									h.order = orders[o];
									h.stripe_unit = strides[s][0];
									h.stripe_count = strides[s][1];
									h.has_parent = p == 1;
									h.has_overlap = p == 2;
									h.overlap = p == 2 ? 4096 : 0;
									h.op_features = opf[q];
									h.flags = flags[a];
									h.data_pool_id = pools[b];
									h.size = 1u << 20;
									memset(&why, 0, sizeof(why));
									want = model_refusal(&h, (int)w, &want_a0);
									got = wri_rbd_check_profile(&h, (int)w, &why);
									if (got != want) {
										fprintf(stderr, "check_profile: features %#llx order %u stripe %llu x %llu parent %zu opf %llu flags %llu pool %lld writer %zu: %s, "
												"the note says %s\n",
											(unsigned long long)h.features, h.order, (unsigned long long)h.stripe_unit, (unsigned long long)h.stripe_count, p,
											(unsigned long long)h.op_features, (unsigned long long)h.flags, (long long)h.data_pool_id, w, status_name_of(got),
											status_name_of(want));
										WRT_CHECK(0);
										return;
									}
									if (want == WR_E_RBD_FEATURES || want == WR_E_RBD_ORDER)
										WRT_CHECK_U64(why.a0, want_a0);
									if (want == WR_OK)
										WRT_CHECK(why.status == WR_OK);
									else
										WRT_CHECK(why.status == want && why.module == WR_MOD_RBD);
									t->grid++;
								}
}

/* ---- the snapshot context decoder at its edges (the captured contexts hold two ids: nothing near these limits) -------------------------------- */

static size_t snapc_out(uint8_t *b, uint64_t seq, uint32_t count, const uint64_t *ids, uint32_t n_ids)
{
	size_t at = 0;
	uint32_t i, k;

	for (k = 0; k < 8; k++)
		b[at++] = (uint8_t)(seq >> (8 * k));
	for (k = 0; k < 4; k++)
		b[at++] = (uint8_t)(count >> (8 * k));
	for (i = 0; i < n_ids; i++)
		for (k = 0; k < 8; k++)
			b[at++] = (uint8_t)(ids[i] >> (8 * k));
	return at;
}

static void check_snapc_edges(void)
{
	static const struct {
		uint64_t seq;
		uint64_t ids[4];
		uint32_t n;
		wr_status want;
	} rows[] = {
		{0, {0}, 0, WR_OK},
		{0, {0}, 1, WR_OK},                                              /* the id 0 alone is valid */
		{5, {5}, 1, WR_OK},                                              /* the newest snapshot may equal the sequence */
		{5, {6}, 1, WR_E_RBD_SNAPC},                                     /* above it may not */
		{5, {5, 3, 1}, 3, WR_OK},
		{5, {5, 5}, 2, WR_E_RBD_SNAPC},                                  /* a repeat */
		{5, {3, 5}, 2, WR_E_RBD_SNAPC},                                  /* ascending */
		{5, {3, 0}, 2, WR_OK},                                           /* ... 3, 0 ends with 0: valid */
		{5, {0, 0}, 2, WR_E_RBD_SNAPC},                                  /* an id 0 followed by another is not */
		{5, {3, 0, 0}, 3, WR_E_RBD_SNAPC},
		{WRI_SNAP_MAX, {WRI_SNAP_MAX}, 1, WR_OK},                        /* the highest sequence */
		{WRI_SNAP_MAX + 1u, {0}, 0, WR_E_RBD_SNAPC},                     /* NOSNAP and every id above it */
		{WRI_SNAP_MAX + 2u, {0}, 0, WR_E_RBD_SNAPC},
		{WRI_SNAP_MAX + 1u, {WRI_SNAP_MAX + 1u}, 1, WR_E_RBD_SNAPC},
		{0xffffffffffffffffull, {1}, 1, WR_E_RBD_SNAPC},
	};
	uint8_t b[64];
	uint64_t store[8];
	wri_snapc s;
	uint32_t total = 99;
	size_t r, n;

	for (r = 0; r < sizeof(rows) / sizeof(rows[0]); r++) {
		memset(store, 0xa5, sizeof(store));
		s.cap = 8;
		s.snaps = store;
		s.seq = 1;
		s.n = 1;
		n = snapc_out(b, rows[r].seq, rows[r].n, rows[r].ids, rows[r].n);
		WRT_CHECK_STATUS(rows[r].want, wri_rbd_dec_snapcontext(b, (uint32_t)n, &s, &total));
		if (rows[r].want == WR_OK) {
			WRT_CHECK(s.seq == rows[r].seq && s.n == rows[r].n && total == rows[r].n && wri_snapc_valid(&s));
			WRT_CHECK(memcmp(store, rows[r].ids, rows[r].n * sizeof(store[0])) == 0);
		} else {
			WRT_CHECK(s.seq == 0 && s.n == 0); /* nothing of a refused context is kept */
		}
	}
	/* a count that does not match the bytes, or that does not fit the owner's room */
	memset(store, 0, sizeof(store));
	s.cap = 2;
	s.snaps = store;
	n = snapc_out(b, 9, 3, (const uint64_t[]){9, 7, 5}, 3);
	WRT_CHECK_STATUS(WR_E_RBD_SNAPC, wri_rbd_dec_snapcontext(b, (uint32_t)n, &s, &total)); /* valid, but three ids in room for two */
	WRT_CHECK(total == 3u && s.n == 0 && store[0] == 0 && store[1] == 0);
	n = snapc_out(b, 9, 3, (const uint64_t[]){9, 7}, 2);
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_dec_snapcontext(b, (uint32_t)n, &s, &total)); /* says three, holds two */
	n = snapc_out(b, 9, 1, (const uint64_t[]){9, 7}, 2);
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_dec_snapcontext(b, (uint32_t)n, &s, &total)); /* says one, holds two */
	n = snapc_out(b, 9, 0xffffffffu, (const uint64_t[]){9}, 1);
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_dec_snapcontext(b, (uint32_t)n, &s, &total)); /* hostile count: refused before anything is read */
	n = snapc_out(b, 9, 0x20000000u, (const uint64_t[]){9}, 1);
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_dec_snapcontext(b, (uint32_t)n, &s, &total)); /* count * 8 wraps a 32-bit multiplication */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_dec_snapcontext(b, (uint32_t)n, NULL, &total));
}

/* ---- parent_get at its edges: only a pool, an image id and a snapshot together are a parent ------------------------------------------------ */

static size_t parent_out(uint8_t *b, uint8_t ver, uint8_t compat, int64_t pool, uint32_t id_len, uint64_t snap, uint32_t extra, int short_len)
{
	size_t at = 0, body_at, k;

	b[at++] = ver;
	b[at++] = compat;
	body_at = at;
	at += 4; /* the length, patched below */
	for (k = 0; k < 8; k++)
		b[at++] = (uint8_t)((uint64_t)pool >> (8 * k));
	for (k = 0; k < 4; k++)
		b[at++] = 0; /* pool_namespace: empty */
	for (k = 0; k < 4; k++)
		b[at++] = (uint8_t)(id_len >> (8 * k));
	for (k = 0; k < id_len; k++)
		b[at++] = 'a';
	for (k = 0; k < 8; k++)
		b[at++] = (uint8_t)(snap >> (8 * k));
	for (k = 0; k < extra; k++)
		b[at++] = 0x77; /* fields of a later version */
	{
		uint32_t len = (uint32_t)(at - body_at - 4u) - (short_len ? 1u : 0u);

		for (k = 0; k < 4; k++)
			b[body_at + k] = (uint8_t)(len >> (8 * k));
	}
	return at;
}

static void check_parent_edges(void)
{
	static const struct {
		int64_t pool;
		uint32_t id_len;
		uint64_t snap;
		int has;
	} rows[] = {
		{-1, 0, WRI_SNAP_NOSNAP, 0}, /* what a server writes for "no parent" */
		{2, 5, 7, 1},
		{0, 5, 7, 1},                /* pool 0 is a pool */
		{2, 5, WRI_SNAP_NOSNAP, 0},  /* no snapshot: not a parent */
		{2, 0, 7, 0},                /* no image id */
		{-1, 5, 7, 0},               /* no pool */
		{2, 5, 0, 1},
	};
	uint8_t b[256];
	size_t r, n;
	uint8_t has;

	for (r = 0; r < sizeof(rows) / sizeof(rows[0]); r++) {
		n = parent_out(b, 1, 1, rows[r].pool, rows[r].id_len, rows[r].snap, 0, 0);
		has = 9;
		WRT_CHECK_STATUS(WR_OK, wri_rbd_dec_parent(b, (uint32_t)n, &has));
		WRT_CHECK(has == rows[r].has);
	}
	n = parent_out(b, 2, 1, 2, 5, 7, 9, 0); /* version 2 with compat 1: the tail is skipped by the struct length */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_dec_parent(b, (uint32_t)n, &has));
	WRT_CHECK(has == 1u);
	n = parent_out(b, 2, 2, 2, 5, 7, 0, 0); /* compat 2: not understood */
	has = 9;
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_dec_parent(b, (uint32_t)n, &has));
	WRT_CHECK(has == 0u);
	n = parent_out(b, 1, 1, 2, 5, 7, 0, 1); /* the struct claims one byte less than the fields need */
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_dec_parent(b, (uint32_t)n, &has));
	n = parent_out(b, 1, 1, 2, 100u, 7, 0, 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_dec_parent(b, (uint32_t)n, &has)); /* a long id is read and dropped */
}

/* ---- images whose size is not a multiple of the object size: what the lab's librbd did --------------------------------------------------------- */

/* The captured images all have sizes that are exact multiples of their object size, so the last PARTIAL object never occurs in the vectors.
 * These rows were made on the lab (2026-11-17): images created with `size` bytes and the given order, `rbd info` read for the object count,
 * the byte ranges written through librbd and read back through librados from the objects the core's geometry names (every byte was where the
 * core said, and no other object existed). The tool of that check printed the extents below. */
static void check_partial_last_object(void)
{
	static const struct {
		uint8_t order;
		uint64_t size, objects;
	} img[] = {{12, 1000001u, 245u}, {16, 327757u, 6u}, {12, 2147483648ull, 524288u}, {12, 4096u, 1u}, {12, 4097u, 2u}, {22, 1u, 1u}, {16, 0u, 0u}};
	static const struct {
		uint8_t order;
		uint64_t off, len;
		unsigned n;               /* extents */
		uint64_t first_obj, first_off, first_run, last_obj, last_off, last_run;
	} walk[] = {
		{12, 4090u, 12u, 2, 0, 4090, 6, 1, 0, 6},                    /* across the first object boundary */
		{12, 8191u, 2u, 2, 1, 4095, 1, 2, 0, 1},
		{12, 999990u, 11u, 1, 244, 566, 11, 244, 566, 11},         /* the last 11 bytes of a 1000001 byte image: inside the partial object 244 */
		{16, 65530u, 20u, 2, 0, 65530, 6, 1, 0, 14},
		{16, 327680u, 77u, 1, 5, 0, 77, 5, 0, 77},                   /* the whole of the 77 byte last object of 327757 bytes */
		{16, 3u * 65536u + 100u, 70000u, 2, 3, 100, 65436, 4, 0, 4564},
		{12, 2147479552ull, 4096u, 1, 524287, 0, 4096, 524287, 0, 4096}, /* the last object of a 2 GiB image */
		{12, 1073741821ull, 9u, 2, 262143, 4093, 3, 262144, 0, 6},   /* across 1 GiB */
	};
	size_t i;

	for (i = 0; i < sizeof(img) / sizeof(img[0]); i++) {
		wri_rbd_geom g;

		WRT_CHECK_STATUS(WR_OK, wri_rbd_geom_init(&g, img[i].order));
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, img[i].size), img[i].objects);
	}
	for (i = 0; i < sizeof(walk) / sizeof(walk[0]); i++) {
		wri_rbd_geom g;
		uint64_t off = walk[i].off, len = walk[i].len, objno, obj_off;
		uint32_t run;
		unsigned n = 0;

		WRT_CHECK_STATUS(WR_OK, wri_rbd_geom_init(&g, walk[i].order));
		while (len > 0 && n < 8) {
			wri_rbd_geom_extent(&g, off, len, 1u << 20, &objno, &obj_off, &run);
			if (n == 0) {
				WRT_CHECK_U64(objno, walk[i].first_obj);
				WRT_CHECK_U64(obj_off, walk[i].first_off);
				WRT_CHECK_U64(run, walk[i].first_run);
			}
			if (len == run) {
				WRT_CHECK_U64(objno, walk[i].last_obj);
				WRT_CHECK_U64(obj_off, walk[i].last_off);
				WRT_CHECK_U64(run, walk[i].last_run);
			}
			off += run;
			len -= run;
			n++;
		}
		WRT_CHECK(len == 0 && n == walk[i].n);
	}
}

/* ---- the error mapping, every errno of the design table against every operation the image layer sends ------------------------------------------ */

typedef struct errno_row {
	int32_t result;
	wr_status want; /* wri_osd_errno_status, design 22.5 */
} errno_row;

static void check_error_table(tally *t)
{
	static const errno_row rows[] = {
		{0, WR_OK}, {1, WR_OK}, {7, WR_OK}, {INT32_MAX, WR_OK},
		{-1, WR_E_OSD_PERM}, {-2, WR_E_OSD_NOENT}, {-3, WR_E_OSD_ERRNO}, {-5, WR_E_OSD_IO}, {-11, WR_E_OSD_ERRNO}, {-13, WR_E_OSD_ERRNO},
		{-17, WR_E_OSD_ERRNO}, {-22, WR_E_OSD_ERRNO}, {-23, WR_E_OSD_ERRNO}, {-27, WR_E_OSD_ERRNO}, {-28, WR_E_OSD_NOSPC}, {-36, WR_E_OSD_ERRNO},
		{-61, WR_E_OSD_ERRNO}, {-85, WR_E_OSD_ERRNO}, {-90, WR_E_OSD_ERRNO}, {-95, WR_E_OSD_NOENT}, {-108, WR_E_OSD_BLOCKLISTED},
		{-122, WR_E_OSD_NOSPC}, {-125, WR_E_OSD_ERRNO}, {INT32_MIN, WR_E_OSD_ERRNO},
	};
	static const uint16_t codes[] = {WRI_OSD_OP_READ, WRI_OSD_OP_WRITE, WRI_OSD_OP_ZERO, WRI_OSD_OP_TRUNCATE, WRI_OSD_OP_DELETE, WRI_OSD_OP_STAT,
					 WRI_OSD_OP_CALL, WRI_OSD_OP_SETALLOCHINT, WRI_OSD_OP_WRITEFULL, WRI_OSD_OP_CREATE};
	size_t r, c;

	for (r = 0; r < sizeof(rows) / sizeof(rows[0]); r++) {
		WRT_CHECK_STATUS(rows[r].want, wri_osd_errno_status(rows[r].result));
		for (c = 0; c < sizeof(codes) / sizeof(codes[0]); c++) {
			int zf = 9;
			wr_status st = wri_rbd_op_status(codes[c], rows[r].result, &zf);
			int missing_is_hole = rows[r].result == -2 && (codes[c] == WRI_OSD_OP_READ || codes[c] == WRI_OSD_OP_ZERO ||
								       codes[c] == WRI_OSD_OP_TRUNCATE || codes[c] == WRI_OSD_OP_DELETE);

			/* an absent object is a hole for the four operations of the data path; nothing else is ever success or zero-fill, in particular an
			 * unsupported operation (-95), an I/O error (-5) or a permission error (-1) on a READ must fail the request and never read as zeros */
			WRT_CHECK_STATUS(missing_is_hole ? WR_OK : rows[r].want, st);
			WRT_CHECK(zf == (missing_is_hole && codes[c] == WRI_OSD_OP_READ ? 1 : 0));
			WRT_CHECK_STATUS(st, wri_rbd_op_status(codes[c], rows[r].result, NULL)); /* the flag pointer is optional */
			t->statuses++;
		}
	}
	/* the shapes of a discard at every edge of an object, in every order the open accepts */
	{
		unsigned order;

		for (order = 12; order <= 25; order++) {
			wri_rbd_geom g;
			uint32_t os;

			WRT_CHECK_STATUS(WR_OK, wri_rbd_geom_init(&g, (uint8_t)order));
			os = (uint32_t)g.object_size;
			WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, os), WRI_OSD_OP_DELETE);
			WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, os - 1u), WRI_OSD_OP_ZERO);
			WRT_CHECK_U64(wri_rbd_discard_op(&g, 1, os - 1u), WRI_OSD_OP_TRUNCATE);
			WRT_CHECK_U64(wri_rbd_discard_op(&g, os - 1u, 1), WRI_OSD_OP_TRUNCATE);
			WRT_CHECK_U64(wri_rbd_discard_op(&g, 1, os - 2u), WRI_OSD_OP_ZERO);
			WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, 1), WRI_OSD_OP_ZERO);
			WRT_CHECK_U64(wri_rbd_discard_op(&g, os, 1), WRI_OSD_OP_ZERO); /* not an extent of this geometry: the harmless shape */
			WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, 0), WRI_OSD_OP_ZERO);
		}
	}
}

int main(void)
{
	wrt_json idx;
	wrt_tok imgs;
	size_t i;
	tally t;

	memset(&t, 0, sizeof(t));
	if (!ov_present())
		WRT_SKIP("harness/vectors/public/osdc is not in this tree (the lab captures of module vectors-c)");
	if (ov_load(&idx, "images.json") != 0) {
		WRT_CHECK(0);
		return wrt_finish();
	}
	imgs = wrt_json_get(&idx, wrt_json_root(&idx), "images");
	WRT_CHECK(imgs != WRT_NONE);
	for (i = 0; imgs != WRT_NONE && i < wrt_json_count(&idx, imgs); i++)
		check_image(&idx, wrt_json_at(&idx, imgs, i), &t);
	wrt_json_free(&idx);
	check_missing();
	check_objects(&t);
	check_io(&t);
	check_error_table(&t);
	check_snapc_edges();
	check_parent_edges();
	check_partial_last_object();
	check_policy_grid(&t);
	fprintf(stderr, "rbd.vec_replay: %u images, %u header messages re-encoded (%u class calls, %u damaged or cut outputs, %u whole-image walks), "
			"%u refusal verdicts, %u header grid points, %u data objects, %u extent runs, %u statuses\n",
		t.images, t.messages, t.calls, t.sweeps, t.walks, t.verdicts, t.grid, t.objects, t.ranges, t.statuses);
	WRT_CHECK(t.images >= 10 && t.messages >= 40 && t.verdicts >= 20 && t.objects >= 15 && t.ranges >= 10);
	WRT_CHECK(t.sweeps >= 20000 && t.walks >= 30 && t.grid >= 500000);
	return wrt_finish();
}
