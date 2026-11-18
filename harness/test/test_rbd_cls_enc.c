/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_cls_enc - the class-call encoders of core/src/rbd/wri_rbd_cls.c (docs/spec/rbd-format2.md 2.2, 2.3, 2.7).
 *
 * Against the committed vectors: every call of harness/vectors/rbd/rbd-class-calls.json whose method has an encoder is re-encoded from
 * the arguments found in its captured input and must reproduce `class | method | input` byte for byte; every CALL operation of the
 * whole messages of osd-messages.json is cut out of the request's data segment and re-encoded the same way; the five-call open message
 * of osdop vectors 09 and 10 is encoded in one writer and compared with the captured data segment and operation records. Then the
 * encoders on their own: the exact bytes of every call, the eight-call header message (size, fits the control buffer), a record that
 * was full of garbage comes back clean, a writer that is one byte too small at every length (TOOBIG, nothing written past the end), a
 * dead writer, NULL arguments, lock strings at and over 255 bytes (nothing written), calls appended one after another.
 */
#include "wrt.h"

#include "wri_denc.h"
#include "wri_rbd_cls.h"

/* ---- one encoder by wire name ---------------------------------------------------------------- */

typedef struct enc_case {
	const char *cls, *meth;
} enc_case;

static const char *const k_known_rbd[] = {"get_id", "get_size", "get_object_prefix", "get_features", "get_flags", "get_snapcontext",
					  "get_data_pool", "parent_get", "parent_overlap_get", "get_stripe_unit_count",
					  "op_features_get", "get_create_timestamp", "get_access_timestamp", "get_modify_timestamp",
					  "metadata_list", "image_group_get", "snapshot_get_limit", "object_map_update", "dir_get_id",
					  "dir_get_name", "get_parent", "mirror_image_get", NULL};
static const char *const k_known_lock[] = {"get_info", "lock", "unlock", "assert_locked", "break_lock", "set_cookie", NULL};

static int streq(const char *a, const char *b)
{
	return strcmp(a, b) == 0;
}

/* u32 length + bytes at in[*at]; copies into dst (NUL terminated, cap bytes). 0 = ok. */
static int get_str(const uint8_t *in, size_t n, size_t *at, char *dst, size_t cap)
{
	uint32_t len;

	if (*at + 4 > n)
		return -1;
	len = (uint32_t)in[*at] | (uint32_t)in[*at + 1] << 8 | (uint32_t)in[*at + 2] << 16 | (uint32_t)in[*at + 3] << 24;
	*at += 4;
	if (len >= cap || *at + len > n)
		return -1;
	memcpy(dst, in + *at, len);
	dst[len] = 0;
	*at += len;
	return 0;
}

static uint64_t le64(const uint8_t *p)
{
	uint64_t v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = v << 8 | p[i];
	return v;
}

/*
 * Encode the call `cls meth` whose captured input is in[0..n) with our encoder. Returns 1 when an encoder exists and the input has the
 * shape it produces (st = its status), 0 when this call is not one of ours or has fields the encoder does not take (flags, a duration:
 * skipped, not failed).
 */
static int encode_wire(wri_wr *w, wri_osd_opd *op, const char *cls, const char *meth, const uint8_t *in, size_t n, wr_status *st)
{
	char name[300], cookie[300], tag[300];
	size_t at;

	if (streq(cls, "rbd")) {
		if (streq(meth, "get_id") && n == 0)
			*st = wri_rbd_put_get_id(w, op);
		else if (streq(meth, "get_object_prefix") && n == 0)
			*st = wri_rbd_put_get_object_prefix(w, op);
		else if (streq(meth, "get_snapcontext") && n == 0)
			*st = wri_rbd_put_get_snapcontext(w, op);
		else if (streq(meth, "get_data_pool") && n == 0)
			*st = wri_rbd_put_get_data_pool(w, op);
		else if (streq(meth, "parent_get") && n == 0)
			*st = wri_rbd_put_parent_get(w, op);
		else if (streq(meth, "get_stripe_unit_count") && n == 0)
			*st = wri_rbd_put_get_stripe_unit_count(w, op);
		else if (streq(meth, "op_features_get") && n == 0)
			*st = wri_rbd_put_op_features_get(w, op);
		else if (streq(meth, "get_size") && n == 8)
			*st = wri_rbd_put_get_size(w, op, le64(in));
		else if (streq(meth, "get_flags") && n == 8)
			*st = wri_rbd_put_get_flags(w, op, le64(in));
		else if (streq(meth, "parent_overlap_get") && n == 8)
			*st = wri_rbd_put_parent_overlap_get(w, op, le64(in));
		else if (streq(meth, "get_features") && n == 8)
			*st = wri_rbd_put_get_features(w, op, le64(in), -1);
		else if (streq(meth, "get_features") && n == 9 && in[8] <= 1)
			*st = wri_rbd_put_get_features(w, op, le64(in), in[8]);
		else
			return 0;
		return 1;
	}
	if (!streq(cls, "lock") || n < 6 || in[0] != 1 || in[1] != 1)
		return 0;
	if ((uint32_t)in[2] != n - 6 || in[3] != 0 || in[4] != 0 || in[5] != 0)
		return 0;
	at = 6;
	if (streq(meth, "get_info")) {
		if (get_str(in, n, &at, name, sizeof(name)) != 0 || at != n)
			return 0;
		*st = wri_rbd_put_lock_get_info(w, op, name);
		return 1;
	}
	if (streq(meth, "unlock")) {
		if (get_str(in, n, &at, name, sizeof(name)) != 0 || get_str(in, n, &at, cookie, sizeof(cookie)) != 0 || at != n)
			return 0;
		*st = wri_rbd_put_lock_unlock(w, op, name, cookie);
		return 1;
	}
	if (streq(meth, "lock")) {
		uint8_t type;
		size_t k;

		if (get_str(in, n, &at, name, sizeof(name)) != 0 || at + 1 > n)
			return 0;
		type = in[at++];
		if (get_str(in, n, &at, cookie, sizeof(cookie)) != 0 || get_str(in, n, &at, tag, sizeof(tag)) != 0)
			return 0;
		/* description "" (4 zero bytes), duration 0 (8 zero bytes), flags 0: nothing else is taken by our encoder */
		if (at + 13 != n)
			return 0;
		for (k = at; k < n; k++)
			if (in[k] != 0)
				return 0;
		*st = wri_rbd_put_lock_lock(w, op, name, type, cookie, tag);
		return 1;
	}
	return 0;
}

/* The writer holds exactly cls|meth|in and the record says so. */
static void check_call(const wri_wr *w, size_t start, const wri_osd_opd *op, const char *cls, const char *meth,
		       const uint8_t *in, size_t n)
{
	size_t cl = strlen(cls), ml = strlen(meth);

	WRT_CHECK(w->pos - start == cl + ml + n);
	if (w->pos - start == cl + ml + n) {
		WRT_CHECK_MEM(w->p + start, cls, cl);
		WRT_CHECK_MEM(w->p + start + cl, meth, ml);
		WRT_CHECK_MEM(w->p + start + cl + ml, in, n);
	}
	WRT_CHECK_U64(op->code, WRI_OSD_OP_CALL);
	WRT_CHECK_U64(op->flags, 0);
	WRT_CHECK_U64(op->in_len, cl + ml + n);
	WRT_CHECK_U64(op->cls_class_len, cl);
	WRT_CHECK_U64(op->cls_method_len, ml);
	WRT_CHECK_U64(op->off, 0);
	WRT_CHECK_U64(op->len, 0);
	WRT_CHECK_U64(op->out_len, 0);
	WRT_CHECK_U64(op->rval, 0);
}

/* ---- rbd-class-calls.json -------------------------------------------------------------------- */

static void test_class_call_vectors(void)
{
	wrt_json j;
	wrt_tok vs;
	size_t i, done = 0, skipped = 0, lock_done = 0;

	if (wrt_json_load_vec(&j, "rbd/rbd-class-calls.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	vs = wrt_json_get(&j, wrt_json_root(&j), "vectors");
	WRT_CHECK(wrt_json_count(&j, vs) >= 70);
	for (i = 0; i < wrt_json_count(&j, vs); i++) {
		wrt_tok v = wrt_json_at(&j, vs, i);
		char *cls = wrt_json_strdup(&j, wrt_json_get(&j, v, "class"));
		char *meth = wrt_json_strdup(&j, wrt_json_get(&j, v, "method"));
		char *id = wrt_json_strdup(&j, wrt_json_get(&j, v, "id"));
		uint8_t *in = NULL;
		size_t n = 0;
		uint8_t buf[512];
		wri_wr w;
		wri_osd_opd op;
		wr_status st = WR_OK;
		int r;

		WRT_CHECK(cls != NULL && meth != NULL && id != NULL);
		WRT_CHECK(wrt_json_get_hex(&j, v, "input_hex", &in, &n) == 0);
		if (cls == NULL || meth == NULL || id == NULL || in == NULL) {
			free(cls);
			free(meth);
			free(id);
			free(in);
			continue;
		}
		wri_wr_init(&w, buf, sizeof(buf));
		memset(&op, 0xa5, sizeof(op));
		r = encode_wire(&w, &op, cls, meth, in, n, &st);
		if (r == 0) {
			skipped++;
		} else {
			done++;
			if (streq(cls, "lock"))
				lock_done++;
			WRT_CHECK_STATUS(WR_OK, st);
			check_call(&w, 0, &op, cls, meth, in, n);
		}
		free(cls);
		free(meth);
		free(id);
		free(in);
	}
	/* 77 vectors: the unreproducible ones are the other methods (dir_*, get_parent, ...), the flag-carrying lock calls and break / assert / set_cookie */
	printf("class-call vectors re-encoded: %zu (lock: %zu), skipped: %zu\n", done, lock_done, skipped);
	WRT_CHECK(done >= 50);
	WRT_CHECK(lock_done >= 12);
	WRT_CHECK(skipped >= 10);
	wrt_json_free(&j);
}

/* ---- osd-messages.json: the CALL operations of whole requests -------------------------------- */

/* The method of a CALL whose bytes (class|method|input) are b[0..n): class by its first letters, method the longest known name that fits. */
static int split_call(const uint8_t *b, size_t n, char *cls, char *meth, size_t *in_off)
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
	*in_off = cl + best;
	return found;
}

static void test_message_vectors(void)
{
	wrt_json j;
	wrt_tok ms;
	size_t i, k, done = 0, messages = 0;

	if (wrt_json_load_vec(&j, "rbd/osd-messages.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	ms = wrt_json_get(&j, wrt_json_root(&j), "messages");
	WRT_CHECK(wrt_json_count(&j, ms) >= 29);
	for (i = 0; i < wrt_json_count(&j, ms); i++) {
		wrt_tok req = wrt_json_get(&j, wrt_json_at(&j, ms, i), "request");
		wrt_tok ops = wrt_json_get(&j, req, "ops");
		uint8_t *data = NULL;
		size_t dn = 0, off = 0, calls = 0;

		/* a request without data segment has no data_hex; the big writes keep only their length, not their bytes */
		if (wrt_json_get(&j, req, "data_hex") != WRT_NONE && wrt_json_get_hex(&j, req, "data_hex", &data, &dn) != 0) {
			WRT_CHECK(0);
			continue;
		}
		for (k = 0; k < wrt_json_count(&j, ops); k++) {
			wrt_tok o = wrt_json_at(&j, ops, k);
			int ok = 0;
			int64_t plen = wrt_json_int(&j, wrt_json_get(&j, o, "payload_len"), &ok);
			char *code = wrt_json_strdup(&j, wrt_json_get(&j, o, "code"));
			char cls[8], meth[40];
			size_t in_off = 0;

			WRT_CHECK(ok && plen >= 0);
			if (!ok || plen < 0 || off + (size_t)plen > dn) { /* the bytes of this and the later operations are not in the vector */
				free(code);
				break;
			}
			if (code != NULL && streq(code, "0x1401") && split_call(data + off, (size_t)plen, cls, meth, &in_off)) {
				uint8_t buf[512];
				wri_wr w;
				wri_osd_opd op;
				wr_status st = WR_OK;

				wri_wr_init(&w, buf, sizeof(buf));
				if (encode_wire(&w, &op, cls, meth, data + off + in_off, (size_t)plen - in_off, &st) == 1) {
					WRT_CHECK_STATUS(WR_OK, st);
					WRT_CHECK(w.pos == (size_t)plen);
					WRT_CHECK_MEM(buf, data + off, (size_t)plen);
					WRT_CHECK_U64(op.in_len, plen);
					done++;
					calls++;
				}
			}
			free(code);
			off += (size_t)plen;
		}
		if (calls != 0)
			messages++;
		free(data);
	}
	printf("message CALL operations re-encoded: %zu in %zu messages\n", done, messages);
	WRT_CHECK(done >= 20);
	WRT_CHECK(messages >= 10);
	wrt_json_free(&j);
}

/* ---- osdop 09 / 10: the five calls of `rbd info` in one writer ------------------------------- */

static void test_open_message(const char *rel)
{
	wrt_json j;
	wrt_tok req, ops;
	uint8_t buf[256], *want = NULL;
	size_t wn = 0, k, at = 0;
	wri_wr w;
	wri_osd_opd op[5];

	if (wrt_json_load_vec(&j, rel) != 0) {
		WRT_CHECK(0);
		return;
	}
	req = wrt_json_get(&j, wrt_json_root(&j), "request");
	ops = wrt_json_get(&j, wrt_json_get(&j, req, "summary"), "ops");
	WRT_CHECK(wrt_json_get_hex(&j, wrt_json_get(&j, req, "data"), "hex", &want, &wn) == 0);
	WRT_CHECK(wrt_json_count(&j, ops) == 5);
	wri_wr_init(&w, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_size(&w, &op[0], WRI_SNAP_NOSNAP));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_features(&w, &op[1], WRI_SNAP_NOSNAP, 1)); /* librbd sends read_only = true */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_flags(&w, &op[2], WRI_SNAP_NOSNAP));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_snapcontext(&w, &op[3]));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_lock_get_info(&w, &op[4], "rbd_lock"));
	WRT_CHECK(want != NULL && w.pos == wn);
	if (want != NULL && w.pos == wn)
		WRT_CHECK_MEM(buf, want, wn);
	for (k = 0; k < 5 && k < wrt_json_count(&j, ops); k++) {
		wrt_tok o = wrt_json_at(&j, ops, k);
		int ok = 0;
		int64_t cl = wrt_json_int(&j, wrt_json_get(&j, o, "class_len"), &ok);
		int64_t ml = wrt_json_int(&j, wrt_json_get(&j, o, "method_len"), &ok);
		int64_t il = wrt_json_int(&j, wrt_json_get(&j, o, "indata_len"), &ok);
		int64_t pl = wrt_json_int(&j, wrt_json_get(&j, o, "payload_len"), &ok);
		int64_t code = wrt_json_int(&j, wrt_json_get(&j, o, "code"), &ok);

		WRT_CHECK_U64(op[k].code, code);
		WRT_CHECK_U64(op[k].cls_class_len, cl);
		WRT_CHECK_U64(op[k].cls_method_len, ml);
		WRT_CHECK_U64(op[k].in_len, pl);
		WRT_CHECK_U64(op[k].in_len, cl + ml + il);
		at += op[k].in_len;
	}
	WRT_CHECK(at == w.pos);
	free(want);
	wrt_json_free(&j);
}

/* ---- the encoders on their own --------------------------------------------------------------- */

/* case ids of run_case, in the order of the header */
enum { C_GET_ID, C_GET_SIZE, C_PREFIX, C_FEAT_RO, C_FEAT_RW, C_FEAT_NOBYTE, C_FLAGS, C_SNAPC, C_DATAPOOL, C_PARENT, C_OVERLAP, C_STRIPE,
       C_OPFEAT, C_LOCK_INFO, C_LOCK_LOCK, C_LOCK_UNLOCK, C_N };

static wr_status run_case(int c, wri_wr *w, wri_osd_opd *op)
{
	switch (c) {
	case C_GET_ID:
		return wri_rbd_put_get_id(w, op);
	case C_GET_SIZE:
		return wri_rbd_put_get_size(w, op, 0x0123456789abcdefull);
	case C_PREFIX:
		return wri_rbd_put_get_object_prefix(w, op);
	case C_FEAT_RO:
		return wri_rbd_put_get_features(w, op, WRI_SNAP_NOSNAP, 1);
	case C_FEAT_RW:
		return wri_rbd_put_get_features(w, op, 7, 0);
	case C_FEAT_NOBYTE:
		return wri_rbd_put_get_features(w, op, 7, -1);
	case C_FLAGS:
		return wri_rbd_put_get_flags(w, op, WRI_SNAP_NOSNAP);
	case C_SNAPC:
		return wri_rbd_put_get_snapcontext(w, op);
	case C_DATAPOOL:
		return wri_rbd_put_get_data_pool(w, op);
	case C_PARENT:
		return wri_rbd_put_parent_get(w, op);
	case C_OVERLAP:
		return wri_rbd_put_parent_overlap_get(w, op, 5);
	case C_STRIPE:
		return wri_rbd_put_get_stripe_unit_count(w, op);
	case C_OPFEAT:
		return wri_rbd_put_op_features_get(w, op);
	case C_LOCK_INFO:
		return wri_rbd_put_lock_get_info(w, op, "rbd_lock");
	case C_LOCK_LOCK:
		return wri_rbd_put_lock_lock(w, op, "rbd_lock", 1, "auto 1", "internal");
	case C_LOCK_UNLOCK:
		return wri_rbd_put_lock_unlock(w, op, "rbd_lock", "auto 1");
	default:
		return WR_E_INVAL;
	}
}

static void test_exact_bytes(void)
{
	static const struct {
		int c;
		const char *cls, *meth;
		const char *in; /* hex */
	} t[] = {
		{C_GET_ID, "rbd", "get_id", ""},
		{C_GET_SIZE, "rbd", "get_size", "efcdab8967452301"},
		{C_PREFIX, "rbd", "get_object_prefix", ""},
		{C_FEAT_RO, "rbd", "get_features", "feffffffffffffff01"},
		{C_FEAT_RW, "rbd", "get_features", "070000000000000000"},
		{C_FEAT_NOBYTE, "rbd", "get_features", "0700000000000000"},
		{C_FLAGS, "rbd", "get_flags", "feffffffffffffff"},
		{C_SNAPC, "rbd", "get_snapcontext", ""},
		{C_DATAPOOL, "rbd", "get_data_pool", ""},
		{C_PARENT, "rbd", "parent_get", ""},
		{C_OVERLAP, "rbd", "parent_overlap_get", "0500000000000000"},
		{C_STRIPE, "rbd", "get_stripe_unit_count", ""},
		{C_OPFEAT, "rbd", "op_features_get", ""},
		{C_LOCK_INFO, "lock", "get_info", "01010c000000080000007262645f6c6f636b"},
		/* version 1 struct, name, type 1, cookie "auto 1", tag "internal", description "", duration 0, flags 0 */
		{C_LOCK_LOCK, "lock", "lock",
		 "010130000000" "08000000" "7262645f6c6f636b" "01" "06000000" "6175746f2031" "08000000" "696e7465726e616c" "00000000"
		 "0000000000000000" "00"},
		{C_LOCK_UNLOCK, "lock", "unlock", "010116000000" "08000000" "7262645f6c6f636b" "06000000" "6175746f2031"},
	};
	size_t i;

	WRT_CHECK(sizeof(t) / sizeof(t[0]) == C_N);
	for (i = 0; i < C_N; i++) {
		uint8_t buf[128], *in = NULL;
		size_t n = 0;
		wri_wr w;
		wri_osd_opd op;

		WRT_CHECK(wrt_hex_decode(t[i].in, strlen(t[i].in), &in, &n) == 0);
		wri_wr_init(&w, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_OK, run_case(t[i].c, &w, &op));
		check_call(&w, 0, &op, t[i].cls, t[i].meth, in, n);
		free(in);
	}
}

/* The eight calls of the open's header message: 159 bytes, one record each, well inside the 512-byte control buffer. */
static void test_header_message(void)
{
	uint8_t buf[512]; /* WRI_RBD_CTL_IN: the control buffer of an image */
	wri_wr w;
	wri_osd_opd op[WRI_OSD_OPS_MAX];
	size_t sum = 0, k;

	wri_wr_init(&w, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_size(&w, &op[0], WRI_SNAP_NOSNAP));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_object_prefix(&w, &op[1]));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_features(&w, &op[2], WRI_SNAP_NOSNAP, 1));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_flags(&w, &op[3], WRI_SNAP_NOSNAP));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_snapcontext(&w, &op[4]));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_data_pool(&w, &op[5]));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_parent_get(&w, &op[6]));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_parent_overlap_get(&w, &op[7], WRI_SNAP_NOSNAP));
	for (k = 0; k < WRI_OSD_OPS_MAX; k++)
		sum += op[k].in_len;
	WRT_CHECK_U64(sum, 159);
	WRT_CHECK_U64(w.pos, 159);
	WRT_CHECK_U64(op[0].in_len, 19);
	WRT_CHECK_U64(op[1].in_len, 20);
	WRT_CHECK_U64(op[2].in_len, 24);
	WRT_CHECK_U64(op[3].in_len, 20);
	WRT_CHECK_U64(op[4].in_len, 18);
	WRT_CHECK_U64(op[5].in_len, 16);
	WRT_CHECK_U64(op[6].in_len, 13);
	WRT_CHECK_U64(op[7].in_len, 29);
	/* the second and later calls start where the one before ended */
	WRT_CHECK(memcmp(buf + 19, "rbdget_object_prefix", 20) == 0);
	WRT_CHECK(memcmp(buf + 19 + 20 + 24 + 20 + 18 + 16, "rbdparent_get", 13) == 0);
	/* the extra reads of 24.2 fit behind them in the same buffer */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_stripe_unit_count(&w, &op[0]));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_op_features_get(&w, &op[1]));
	WRT_CHECK_U64(w.pos, 159 + 24 + 18);
}

static void test_garbage_record_cleared(void)
{
	uint8_t buf[64];
	wri_wr w;
	wri_osd_opd op;

	wri_wr_init(&w, buf, sizeof(buf));
	memset(&op, 0xa5, sizeof(op));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_id(&w, &op));
	WRT_CHECK_U64(op.flags, 0);
	WRT_CHECK_U64(op.off, 0);
	WRT_CHECK_U64(op.len, 0);
	WRT_CHECK_U64(op.out_len, 0);
	WRT_CHECK_U64(op.rval, 0);
	WRT_CHECK_U64(op.reserved8[0], 0);
	WRT_CHECK_U64(op.reserved8[1], 0);
}

/* A buffer one byte short at every length: TOOBIG, the record cleared, no write past the end (the buffers are exact-size heap blocks). */
static void test_short_writers(void)
{
	int c;

	for (c = 0; c < C_N; c++) {
		uint8_t big[128];
		wri_wr w;
		wri_osd_opd op;
		size_t full, cap;

		wri_wr_init(&w, big, sizeof(big));
		WRT_CHECK_STATUS(WR_OK, run_case(c, &w, &op));
		full = w.pos;
		for (cap = 0; cap < full; cap++) {
			uint8_t *p = (uint8_t *)malloc(cap ? cap : 1);
			wri_osd_opd z;

			memset(&z, 0, sizeof(z));
			memset(&op, 0x5a, sizeof(op));
			WRT_CHECK(p != NULL);
			if (p == NULL)
				break;
			wri_wr_init(&w, p, cap);
			WRT_CHECK_STATUS(WR_E_TOOBIG, run_case(c, &w, &op));
			WRT_CHECK(memcmp(&op, &z, sizeof(op)) == 0);
			WRT_CHECK(w.pos <= cap);
			free(p);
		}
		/* exactly full works */
		{
			uint8_t *p = (uint8_t *)malloc(full);

			WRT_CHECK(p != NULL);
			if (p != NULL) {
				wri_wr_init(&w, p, full);
				WRT_CHECK_STATUS(WR_OK, run_case(c, &w, &op));
				WRT_CHECK_U64(w.pos, full);
				WRT_CHECK_U64(op.in_len, full);
				free(p);
			}
		}
	}
}

static void test_dead_writer_and_null(void)
{
	uint8_t buf[64];
	wri_wr w;
	wri_osd_opd op;
	int c;

	for (c = 0; c < C_N; c++) {
		wri_wr_init(&w, buf, sizeof(buf));
		wri_wr_fail(&w, WR_E_ENCODING);
		memset(&op, 0xa5, sizeof(op));
		WRT_CHECK_STATUS(WR_E_ENCODING, run_case(c, &w, &op));
		WRT_CHECK_U64(w.pos, 0);
		WRT_CHECK_U64(op.code, 0);
		WRT_CHECK_U64(op.in_len, 0);
		WRT_CHECK_U64(op.rval, 0);
		/* NULL writer and NULL record */
		WRT_CHECK_STATUS(WR_E_INVAL, run_case(c, NULL, &op));
		wri_wr_init(&w, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_E_INVAL, run_case(c, &w, NULL));
		WRT_CHECK_U64(w.pos, 0);
	}
	/* NULL strings */
	wri_wr_init(&w, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_put_lock_get_info(&w, &op, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_put_lock_lock(&w, &op, NULL, 1, "c", "t"));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_put_lock_lock(&w, &op, "n", 1, NULL, "t"));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_put_lock_lock(&w, &op, "n", 1, "c", NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_put_lock_unlock(&w, &op, NULL, "c"));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_put_lock_unlock(&w, &op, "n", NULL));
	WRT_CHECK_U64(w.pos, 0);
	WRT_CHECK(wri_wr_ok(&w));
}

/* A lock string of 255 bytes is accepted, 256 is TOOBIG and leaves the writer untouched and usable. */
static void test_lock_string_limits(void)
{
	uint8_t buf[2048];
	char s255[256], s256[257];
	wri_wr w;
	wri_osd_opd op;

	memset(s255, 'a', 255);
	s255[255] = 0;
	memset(s256, 'b', 256);
	s256[256] = 0;
	wri_wr_init(&w, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_lock_get_info(&w, &op, s255));
	WRT_CHECK_U64(op.in_len, 4 + 8 + 6 + 4 + 255);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_lock_lock(&w, &op, s255, 2, s255, s255));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_lock_unlock(&w, &op, s255, s255));
	{
		size_t before = w.pos;

		memset(&op, 0xa5, sizeof(op));
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_put_lock_get_info(&w, &op, s256));
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_put_lock_lock(&w, &op, s256, 1, "c", "t"));
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_put_lock_lock(&w, &op, "n", 1, s256, "t"));
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_put_lock_lock(&w, &op, "n", 1, "c", s256));
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_put_lock_unlock(&w, &op, s256, "c"));
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_put_lock_unlock(&w, &op, "n", s256));
		WRT_CHECK_U64(op.code, 0);
		WRT_CHECK_U64(op.in_len, 0);
		WRT_CHECK_U64(w.pos, before);
		WRT_CHECK(wri_wr_ok(&w));
		WRT_CHECK_STATUS(WR_OK, wri_rbd_put_get_id(&w, &op)); /* still usable */
	}
}

/* The lock type is passed through whatever it is (the server judges it: -EINVAL for 0, rbd-format2.md 2.7); an empty name too. */
static void test_lock_passthrough(void)
{
	uint8_t buf[128];
	wri_wr w;
	wri_osd_opd op;

	wri_wr_init(&w, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_lock_lock(&w, &op, "", 0, "", ""));
	WRT_CHECK_U64(buf[4 + 4 + 6 + 4], 0); /* type byte after the name */
	wri_wr_init(&w, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_put_lock_lock(&w, &op, "x", 255, "y", "z"));
	WRT_CHECK_U64(buf[4 + 4 + 6 + 4 + 1], 255); /* after the one-byte name */
}

int main(void)
{
	test_class_call_vectors();
	test_message_vectors();
	test_open_message("osdop/09-rbd-open-compound-5calls.json");
	test_open_message("osdop/10-rbd-lock-get-info.json");
	test_exact_bytes();
	test_header_message();
	test_garbage_record_cleared();
	test_short_writers();
	test_dead_writer_and_null();
	test_lock_string_limits();
	test_lock_passthrough();
	return wrt_finish();
}
