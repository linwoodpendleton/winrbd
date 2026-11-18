/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the fake OSD, part 3: the object classes and the RBD image fixtures (docs/spec/rbd-format2.md 2.1 to 2.8).
 *   - the lab's own header objects (harness/vectors/rbd/header-omap.json: omap values, id objects, directory, lock xattrs) are loaded into the store as
 *     they are on the cluster, and every class call of harness/vectors/rbd/rbd-class-calls.json is made over the wire and must come back byte for byte
 *     (the read methods of 2.3, the error cases -EINVAL / -ENOENT / -ENOEXEC / -EIO / -EOPNOTSUPP / -EPERM, the lock class of 2.7 including the lock
 *     record with a real locker, shared locks, set_cookie, break_lock, expiry and the released lock that keeps its type and tag);
 *   - sim_rbd_image_create makes images with every feature of the note so that every refusal of an open can be provoked: striping, a data pool, a
 *     parent, flags, operation features, snapshots (valid and invalid contexts), a foreign locker; the header changes behind the client's back;
 *   - the lock class between two clients: exclusive and shared locks, tags, renewal, break, expiry on the store's clock, atomicity of a message.
 */
#include "sim_osd_rig.h"

#define POOL OR_POOL

static const or_reply *call(orc *c, const or_req *r)
{
	const or_reply *p = orc_call(c, r);

	WRT_CHECK(p != NULL && p->ok);
	return p != NULL && p->ok ? p : NULL;
}

static const or_reply *ccall(orc *c, const char *obj, const char *cls, const char *method, const void *in, uint32_t n, int writes)
{
	or_req r = or_one(obj, or_call(cls, method, in, n));

	if (writes)
		r.flags = 0x08400024u;
	return call(c, &r);
}

/* ---- loading the lab's objects --------------------------------------------------------------------------------------------------- */

typedef struct lab {
	wrt_json hdr;
	char id[16][40];
	char name[16][40];
	uint32_t n;
} lab;

static const char *last_dot(const char *s)
{
	const char *d = strrchr(s, '.');

	return d != NULL ? d + 1 : s;
}

static void load_lab(ore *e, lab *l)
{
	wrt_tok root, imgs;
	size_t i, k;

	memset(l, 0, sizeof(*l));
	if (wrt_json_load_vec(&l->hdr, "rbd/header-omap.json") != 0) {
		WRT_CHECK(!"header-omap.json loads");
		return;
	}
	root = wrt_json_root(&l->hdr);
	imgs = wrt_json_get(&l->hdr, root, "images");
	for (i = 0; i < wrt_json_count(&l->hdr, imgs); i++) {
		wrt_tok img, om, idobj;
		char name[40]; /* the key is returned in a buffer that the next call overwrites */
		uint8_t *pre = NULL, *idb = NULL;
		size_t pl = 0, idl = 0;
		char hname[80];
		char *prefix;

		snprintf(name, sizeof(name), "%.39s", wrt_json_key_at(&l->hdr, imgs, i, &img));
		om = wrt_json_get(&l->hdr, img, "omap_hex");
		if (strcmp(name, "rbd_directory") == 0) {
			for (k = 0; k < wrt_json_count(&l->hdr, om); k++) {
				wrt_tok v;
				const char *key = wrt_json_key_at(&l->hdr, om, k, &v);
				uint8_t *b = NULL;
				size_t n = 0;

				if (wrt_json_hex(&l->hdr, v, &b, &n) == 0) {
					WRT_CHECK_STATUS(WR_OK, sim_store_omap_set(e->store, POOL, "rbd_directory", key, b, n));
					free(b);
				}
			}
			continue;
		}
		if (wrt_json_get_hex(&l->hdr, om, "object_prefix", &pre, &pl) != 0 || pl < 4u)
			continue;
		prefix = (char *)malloc(pl);
		memcpy(prefix, pre + 4, pl - 4u);
		prefix[pl - 4u] = '\0';
		snprintf(l->id[l->n], sizeof(l->id[0]), "%s", last_dot(prefix));
		snprintf(l->name[l->n], sizeof(l->name[0]), "%s", name);
		snprintf(hname, sizeof(hname), "rbd_header.%s", l->id[l->n]);
		free(prefix);
		free(pre);
		for (k = 0; k < wrt_json_count(&l->hdr, om); k++) {
			wrt_tok v;
			const char *key = wrt_json_key_at(&l->hdr, om, k, &v);
			uint8_t *b = NULL;
			size_t n = 0;

			if (wrt_json_hex(&l->hdr, v, &b, &n) == 0) {
				WRT_CHECK_STATUS(WR_OK, sim_store_omap_set(e->store, POOL, hname, key, b, n));
				free(b);
			}
		}
		idobj = wrt_json_get(&l->hdr, img, "rbd_id_object_hex");
		if (idobj != WRT_NONE && wrt_json_hex(&l->hdr, idobj, &idb, &idl) == 0) {
			char iname[80];

			snprintf(iname, sizeof(iname), "rbd_id.%s", name);
			WRT_CHECK_STATUS(WR_OK, sim_store_write(e->store, POOL, iname, 0, idb, idl));
			free(idb);
		}
		{
			wrt_tok lx = wrt_json_get(&l->hdr, img, "lock_xattr_hex");
			uint8_t *b = NULL;
			size_t n = 0;

			if (lx != WRT_NONE && wrt_json_is_string(&l->hdr, lx) && wrt_json_hex(&l->hdr, lx, &b, &n) == 0) {
				WRT_CHECK_STATUS(WR_OK, sim_store_xattr_set(e->store, POOL, hname, "lock.rbd_lock", b, n));
				free(b);
			}
		}
		l->n++;
	}
}

static const char *id_of(const lab *l, const char *image)
{
	uint32_t i;

	for (i = 0; i < l->n; i++)
		if (strcmp(l->name[i], image) == 0)
			return l->id[i];
	WRT_CHECK(!"image of the lab found");
	return "";
}

/* ---- the class vectors ------------------------------------------------------------------------------------------------------------ */

static void check_vector(orc *c, const wrt_json *j, wrt_tok v, const char *obj, int writes)
{
	char *cls = wrt_json_strdup(j, wrt_json_get(j, v, "class")), *method = wrt_json_strdup(j, wrt_json_get(j, v, "method")), *vid = wrt_json_strdup(j, wrt_json_get(j, v, "id"));
	uint8_t *in = NULL, *out = NULL;
	size_t inl = 0, outl = 0;
	int ok = 0;
	int64_t result = wrt_json_int(j, wrt_json_get(j, v, "result"), &ok);
	const or_reply *p;

	WRT_CHECK(wrt_json_get_hex(j, v, "input_hex", &in, &inl) == 0 && wrt_json_get_hex(j, v, "output_hex", &out, &outl) == 0);
	p = ccall(c, obj, cls, method, in, (uint32_t)inl, writes);
	if (p != NULL) {
		if (result < 0) {
			if (p->result != (int32_t)result)
				fprintf(stderr, "vector %s: result %d, want %d\n", vid, p->result, (int)result);
			WRT_CHECK(p->result == (int32_t)result);
			WRT_CHECK(p->dlen == 0u);
		} else {
			if (p->result != 0 || p->dlen != outl || (outl != 0 && memcmp(p->data, out, outl) != 0))
				fprintf(stderr, "vector %s: result %d, %u bytes, want %u\n", vid, p->result, p->dlen, (unsigned)outl);
			WRT_CHECK(p->result == 0 && p->rval[0] == 0);
			WRT_CHECK(p->dlen == outl && (outl == 0 || memcmp(p->data, out, outl) == 0));
			WRT_CHECK(result == (int64_t)outl || result == 0);
			if (p->dlen == outl && p->n_ops == 1u && !writes)
				WRT_CHECK_U64(wri_le64_get(p->rec[0] + 14), outl); /* the OSD copies the output length into the reply's extent length */
		}
	}
	free(cls);
	free(method);
	free(vid);
	free(in);
	free(out);
}

static void lock_write_method(const char *m)
{
	(void)m;
}

/* The lab's whole messages (harness/vectors/rbd/osd-messages.json): the MOSDOp front exactly as librbd / the rbd tool sent it (version 9, v2 reqid, 24 bytes of
 * trace, otel, oloc v6) goes in, what comes back is compared with the lab's reply field by field. Only the messages about objects the test loaded. */
static void replay_messages(orc *c, ore *e)
{
	wrt_json j;
	wrt_tok msgs;
	size_t i, nm;
	static const size_t want[] = {0, 1, 2, 3, 5, 6, 7, 24, 27}; /* not 4: the access time is rewritten by the access itself, the dump is later than the message */
	uint64_t tid = 5000;
	uint32_t replayed = 0;

	(void)e;
	if (wrt_json_load_vec(&j, "rbd/osd-messages.json") != 0) {
		WRT_CHECK(!"osd-messages.json loads");
		return;
	}
	msgs = wrt_json_get(&j, wrt_json_root(&j), "messages");
	nm = wrt_json_count(&j, msgs);
	WRT_CHECK_U64(nm, 29);
	for (i = 0; i < sizeof(want) / sizeof(want[0]) && want[i] < nm; i++) {
		wrt_tok m = wrt_json_at(&j, msgs, want[i]), rq = wrt_json_get(&j, m, "request"), rp = wrt_json_get(&j, m, "reply");
		uint8_t *front = NULL, *rdata = NULL, *qdata = NULL;
		size_t fl = 0, rdl = 0, qdl = 0, k;
		char *id = wrt_json_strdup(&j, wrt_json_get(&j, m, "id"));
		int ok = 0;
		const or_reply *p;
		wrt_tok rv, ol;

		orc_forget(c);
		WRT_CHECK(wrt_json_get_hex(&j, rq, "front_hex", &front, &fl) == 0);
		if (front == NULL) {
			free(id);
			continue;
		}
		WRT_CHECK(wrt_json_get_hex(&j, rq, "data_hex", &qdata, &qdl) == 0);
		orc_send_raw(c, 42, 9, 3, ++tid, front, (uint32_t)fl, NULL, 0, qdata, (uint32_t)qdl, 0);
		p = orc_reply(c, tid);
		WRT_CHECK(p != NULL && p->ok);
		if (p != NULL && p->ok) {
			uint32_t off = 0;

			replayed++;
			WRT_CHECK(wrt_json_get_hex(&j, rp, "data_hex", &rdata, &rdl) == 0);
			if (p->result != (int32_t)wrt_json_int(&j, wrt_json_get(&j, rp, "result"), &ok))
				fprintf(stderr, "message %s: result %d\n", id, p->result);
			WRT_CHECK(p->result == (int32_t)wrt_json_int(&j, wrt_json_get(&j, rp, "result"), &ok));
			rv = wrt_json_get(&j, rp, "rvals");
			ol = wrt_json_get(&j, rp, "out_len");
			WRT_CHECK_U64(p->n_ops, wrt_json_count(&j, rv));
			for (k = 0; k < wrt_json_count(&j, rv) && k < p->n_ops; k++) {
				uint32_t want_len = (uint32_t)wrt_json_int(&j, wrt_json_at(&j, ol, k), &ok);

				WRT_CHECK(p->rval[k] == (int32_t)wrt_json_int(&j, wrt_json_at(&j, rv, k), &ok));
				if (p->payload_len[k] != want_len)
					fprintf(stderr, "message %s: op %zu has %u bytes of output, the lab's %u\n", id, k, p->payload_len[k], want_len);
				WRT_CHECK(p->payload_len[k] == want_len);
				if (want_len != 0u && want_len == p->payload_len[k] && off + want_len <= rdl && p->code[k] != 0x1202u) {
					if (memcmp(p->data + off, rdata + off, want_len) != 0)
						fprintf(stderr, "message %s: output of op %zu differs\n", id, k);
					WRT_CHECK(memcmp(p->data + off, rdata + off, want_len) == 0);
				}
				off += want_len;
			}
		}
		free(front);
		free(qdata);
		free(rdata);
		free(id);
	}
	WRT_CHECK_U64(replayed, sizeof(want) / sizeof(want[0]));
	wrt_json_free(&j);
}

static void t_vectors(void)
{
	ore e;
	orc c;
	lab l;
	wrt_json cj;
	wrt_tok vs;
	size_t i, nv;
	char hname[80];

	ore_prep_gid(&e, WR_KEY_TYPE_AES256K, 24602); /* the global id the lab's lock vectors were made by */
	ore_start(&e);
	orc_init(&c, &e, e.osd);
	c.ident_ip[0] = 192, c.ident_ip[1] = 0, c.ident_ip[2] = 2, c.ident_ip[3] = 7;
	c.ident_nonce = 1254309492u;
	WRT_CHECK_U64(orc_open(&c), OR_OK);
	WRT_CHECK_U64(e.gid, 24602);
	load_lab(&e, &l);
	if (wrt_json_load_vec(&cj, "rbd/rbd-class-calls.json") != 0) {
		WRT_CHECK(!"rbd-class-calls.json loads");
		orc_free(&c);
		ore_free(&e);
		return;
	}
	vs = wrt_json_get(&cj, wrt_json_root(&cj), "vectors");
	nv = wrt_json_count(&cj, vs);
	WRT_CHECK_U64(nv, 77);
	/* 0 .. 48: the read methods of three lab images, their id objects and the directory */
	for (i = 0; i < 49u && i < nv; i++) {
		wrt_tok v = wrt_json_at(&cj, vs, i);
		char *vid = wrt_json_strdup(&cj, wrt_json_get(&cj, v, "id")), *obj = wrt_json_strdup(&cj, wrt_json_get(&cj, v, "object")), *slash;
		char image[64];

		snprintf(image, sizeof(image), "%s", vid);
		slash = strchr(image, '/');
		if (slash != NULL)
			*slash = '\0';
		if (strcmp(obj, "rbd_header") == 0)
			snprintf(hname, sizeof(hname), "rbd_header.%s", id_of(&l, image));
		else if (strcmp(obj, "rbd_id") == 0)
			snprintf(hname, sizeof(hname), "rbd_id.%s", image);
		else
			snprintf(hname, sizeof(hname), "rbd_directory");
		check_vector(&c, &cj, v, hname, 0);
		free(vid);
		free(obj);
	}
	/* 49 .. 61: error cases and the probes of the other feature sets, on the images that carry them */
	snprintf(hname, sizeof(hname), "rbd_header.%s", id_of(&l, "img-v1"));
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 49), hname, 0); /* get_features with no input: -EINVAL */
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 50), hname, 0); /* get_size of an unknown snapshot: -ENOENT */
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 51), hname, 0); /* STRIPINGV2 clear: -ENOEXEC */
	snprintf(hname, sizeof(hname), "rbd_header.%s", id_of(&l, "t0-feat-str"));
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 52), hname, 0); /* 64 KiB x 4 */
	WRT_CHECK_STATUS(WR_OK, sim_store_write(e.store, POOL, "t4-empty", 0, (const uint8_t *)"", 0)); /* an existing object of size 0 */
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 53), "t4-empty", 0);
	WRT_CHECK_STATUS(WR_OK, sim_store_write(e.store, POOL, "t4-garbage", 0, (const uint8_t *)"\xff\xff\xff\xff\x01", 5));
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 54), "t4-garbage", 0); /* does not decode as a string: -EIO */
	snprintf(hname, sizeof(hname), "rbd_header.%s", id_of(&l, "img-v1"));
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 55), hname, 0);
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 56), hname, 0); /* an unknown class: -EPERM */
	snprintf(hname, sizeof(hname), "rbd_header.%s", id_of(&l, "t0-feat-snap"));
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 57), hname, 0); /* seq 11, snapshots 11 and 9 */
	snprintf(hname, sizeof(hname), "rbd_header.%s", id_of(&l, "t0-feat-clone"));
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 58), hname, 0); /* the parent of a clone */
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 59), hname, 0);
	snprintf(hname, sizeof(hname), "rbd_header.%s", id_of(&l, "t0-feat-dp"));
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 61), hname, 0);
	snprintf(hname, sizeof(hname), "rbd_header.%s", id_of(&l, "t0-feat-clone"));
	check_vector(&c, &cj, wrt_json_at(&cj, vs, 60), hname, 0); /* the legacy get_parent of a clone */
	replay_messages(&c, &e); /* before the lock vectors, which change the lock record of img-v1 */
	/* 62 .. 76: the lock class on a scratch object, as the lab ran it (the missing steps are made here: the lab's own unlock, the shared locks and the
	 * expiring lock) */
	{
		const char *scratch = "t20-scratch";
		const or_reply *p;
		static const uint8_t unlock_c[] = {1, 1, 0x11, 0, 0, 0, 8, 0, 0, 0, 'r', 'b', 'd', '_', 'l', 'o', 'c', 'k', 1, 0, 0, 0, 'c'};
		static const uint8_t lock_s1[] = {1, 1, 0x25, 0, 0, 0, 8, 0, 0, 0, 'r', 'b', 'd', '_', 'l', 'o', 'c', 'k', 2, 2, 0, 0, 0, 's', '1', 1, 0, 0, 0, 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		uint8_t lock_s2[sizeof(lock_s1)];
		static const uint8_t unlock_s1new[] = {1, 1, 0x15, 0, 0, 0, 8, 0, 0, 0, 'r', 'b', 'd', '_', 'l', 'o', 'c', 'k', 5, 0, 0, 0, 's', '1', 'n', 'e', 'w'};
		static const uint8_t lock_exp[] = {1, 1, 0x24, 0, 0, 0, 8, 0, 0, 0, 'r', 'b', 'd', '_', 'l', 'o', 'c', 'k', 1, 1, 0, 0, 0, 'c', 1, 0, 0, 0, 't', 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0};

		WRT_CHECK(sizeof(lock_s1) == 0x25 + 6 && sizeof(unlock_c) == 0x11 + 6 && sizeof(unlock_s1new) == 0x15 + 6 && sizeof(lock_exp) == 0x24 + 6);
		memcpy(lock_s2, lock_s1, sizeof(lock_s1));
		lock_s2[24] = '2'; /* cookie "s2" */
		for (i = 62; i <= 70; i++) {
			wrt_tok v = wrt_json_at(&cj, vs, i);
			char *m = wrt_json_strdup(&cj, wrt_json_get(&cj, v, "method"));

			check_vector(&c, &cj, v, scratch, strcmp(m, "get_info") != 0 && strcmp(m, "assert_locked") != 0);
			free(m);
		}
		p = ccall(&c, scratch, "lock", "unlock", unlock_c, sizeof(unlock_c), 1); /* the lab's step between 70 and 71 */
		WRT_CHECK(p != NULL && p->result == 0);
		check_vector(&c, &cj, wrt_json_at(&cj, vs, 71), scratch, 0); /* the locker is gone, the type and tag of the last holder stay */
		p = ccall(&c, scratch, "lock", "lock", lock_s1, sizeof(lock_s1), 1);
		WRT_CHECK(p != NULL && p->result == 0);
		p = ccall(&c, scratch, "lock", "lock", lock_s2, sizeof(lock_s2), 1);
		WRT_CHECK(p != NULL && p->result == 0);
		check_vector(&c, &cj, wrt_json_at(&cj, vs, 72), scratch, 0); /* two shared lockers of one client with different cookies */
		check_vector(&c, &cj, wrt_json_at(&cj, vs, 73), scratch, 1); /* set_cookie */
		check_vector(&c, &cj, wrt_json_at(&cj, vs, 74), scratch, 1); /* break_lock of s2 */
		p = ccall(&c, scratch, "lock", "unlock", unlock_s1new, sizeof(unlock_s1new), 1);
		WRT_CHECK(p != NULL && p->result == 0);
		/* a lock with a duration of 2 s: gone after 3 s, but the record keeps its type and tag */
		p = ccall(&c, scratch, "lock", "lock", lock_exp, sizeof(lock_exp), 1);
		WRT_CHECK(p != NULL && p->result == 0);
		{
			static const uint8_t info_in[] = {1, 1, 0x0c, 0, 0, 0, 8, 0, 0, 0, 'r', 'b', 'd', '_', 'l', 'o', 'c', 'k'};

			p = ccall(&c, scratch, "lock", "get_info", info_in, sizeof(info_in), 0);
			WRT_CHECK(p != NULL && p->dlen > 16u && wri_le32_get(p->data + 6) == 1u); /* one locker, with an absolute expiration */
			sim_store_set_time(e.store, 1700000000u + 3u);
			check_vector(&c, &cj, wrt_json_at(&cj, vs, 75), scratch, 0);
		}
		/* 76: the record of a foreign locker (what librbd leaves) goes through the decoder and the encoder unchanged */
		{
			wrt_tok v = wrt_json_at(&cj, vs, 76);
			uint8_t *out = NULL;
			size_t outl = 0;

			snprintf(hname, sizeof(hname), "rbd_header.%s", id_of(&l, "img-v1"));
			WRT_CHECK(wrt_json_get_hex(&cj, v, "output_hex", &out, &outl) == 0);
			WRT_CHECK_STATUS(WR_OK, sim_store_xattr_set(e.store, POOL, hname, "lock.rbd_lock", out, outl));
			free(out);
			check_vector(&c, &cj, v, hname, 0);
		}
	}
	(void)lock_write_method;
	wrt_json_free(&cj);
	wrt_json_free(&l.hdr);
	orc_free(&c);
	ore_free(&e);
}

/* ---- fixtures ---------------------------------------------------------------------------------------------------------------------- */

typedef struct header {
	int ok;
	uint8_t order;
	uint64_t size, features, incompat, flags, seq;
	char prefix[200];
	uint32_t n_snaps;
	uint64_t snaps[32];
	uint32_t n_lockers;
	uint8_t lock_type;
	int64_t locker_num;
	char tag[40];
	int32_t result;
} header;

/* the six-call header message of rbd-format2.md 3.2 */
static void read_header(orc *c, const char *id, int read_only, header *h)
{
	char hname[80];
	uint8_t snap[8], feat[9], none[1] = {0}, lockin[18] = {1, 1, 12, 0, 0, 0, 8, 0, 0, 0, 'r', 'b', 'd', '_', 'l', 'o', 'c', 'k'};
	or_req r;
	const or_reply *p;
	uint32_t i;

	memset(h, 0, sizeof(*h));
	snprintf(hname, sizeof(hname), "rbd_header.%s", id);
	wri_le64_put(snap, 0xfffffffffffffffeull);
	memcpy(feat, snap, 8);
	feat[8] = (uint8_t)(read_only ? 1 : 0);
	or_req_init(&r, POOL, hname);
	or_req_add(&r, or_call("rbd", "get_size", snap, 8));
	or_req_add(&r, or_call("rbd", "get_object_prefix", none, 0));
	or_req_add(&r, or_call("rbd", "get_features", feat, 9));
	or_req_add(&r, or_call("rbd", "get_flags", snap, 8));
	or_req_add(&r, or_call("rbd", "get_snapcontext", none, 0));
	or_req_add(&r, or_call("lock", "get_info", lockin, 18));
	p = call(c, &r);
	if (p == NULL)
		return;
	h->result = p->result;
	if (p->result != 0 || p->n_ops != 6u)
		return;
	h->order = p->out[0][0];
	h->size = wri_le64_get(p->out[0] + 1);
	{
		uint32_t pl = wri_le32_get(p->out[1]);

		memcpy(h->prefix, p->out[1] + 4, pl < sizeof(h->prefix) - 1u ? pl : sizeof(h->prefix) - 1u);
	}
	h->features = wri_le64_get(p->out[2]);
	h->incompat = wri_le64_get(p->out[2] + 8);
	h->flags = wri_le64_get(p->out[3]);
	h->seq = wri_le64_get(p->out[4]);
	h->n_snaps = wri_le32_get(p->out[4] + 8);
	for (i = 0; i < h->n_snaps && i < 32u; i++)
		h->snaps[i] = wri_le64_get(p->out[4] + 12 + 8u * i);
	{ /* lock get_info: struct hdr, map<locker_id, locker_info>, u8 type, string tag */
		wri_rd rd;
		wri_env e;

		wri_rd_init(&rd, p->out[5], p->payload_len[5]);
		if (wri_env_open(&rd, 1, &e) == WR_OK) {
			h->n_lockers = wri_rd_u32(&e.body);
			if (h->n_lockers == 1u) {
				wri_env id_, info;
				uint32_t cl;

				WRT_CHECK(wri_env_open(&e.body, 1, &id_) == WR_OK);
				(void)wri_rd_u8(&id_.body);
				h->locker_num = wri_rd_i64(&id_.body);
				(void)wri_denc_blob(&id_.body, &cl, 4096);
				WRT_CHECK(wri_env_open(&e.body, 1, &info) == WR_OK);
			}
			h->lock_type = wri_rd_u8(&e.body);
			{
				uint32_t tl;
				const uint8_t *t = wri_denc_blob(&e.body, &tl, 39);

				if (t != NULL)
					memcpy(h->tag, t, tl);
			}
		}
	}
	h->ok = 1;
}

static const void *none_bytes(void)
{
	static const uint8_t z[1] = {0};

	return z;
}

static int acked_(const or_reply *p) { return (p->flags & 5) == 5; }

static sim_rbd_image_cfg base_cfg(const char *name, const char *id, uint64_t features)
{
	sim_rbd_image_cfg c;

	memset(&c, 0, sizeof(c));
	c.pool = POOL;
	c.name = name;
	c.id = id;
	c.size = 10ull << 20;
	c.features = features;
	c.data_pool = -1;
	return c;
}

static void t_fixtures(void)
{
	ore e;
	orc c;
	sim_rbd_image_cfg cfg;
	header h;
	const or_reply *p;
	or_req r;
	uint8_t nosnap[8], none[1] = {0};
	uint32_t i;

	ore_prep(&e, WR_KEY_TYPE_AES256K);
	ore_start(&e);
	orc_up(&c, &e);
	wri_le64_put(nosnap, 0xfffffffffffffffeull);

	/* a plain image: order 22 by default, the prefix of an image of the metadata pool, nothing locked, no snapshots */
	cfg = base_cfg("plain", "abc123", 0x1);
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	read_header(&c, "abc123", 1, &h);
	WRT_CHECK(h.ok && h.order == 22u && h.size == 10ull << 20 && h.features == 1u && h.incompat == 1u && h.flags == 0u && h.seq == 0u && h.n_snaps == 0u);
	WRT_CHECK(strcmp(h.prefix, "rbd_data.abc123") == 0 && h.n_lockers == 0u && h.lock_type == 0u && h.tag[0] == '\0');
	/* the id object and the directory */
	p = ccall(&c, "rbd_id.plain", "rbd", "get_id", NULL, 0, 0);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 10u && wri_le32_get(p->data) == 6u && memcmp(p->data + 4, "abc123", 6) == 0);
	{
		uint8_t nm[9] = {5, 0, 0, 0, 'p', 'l', 'a', 'i', 'n'}, id[10] = {6, 0, 0, 0, 'a', 'b', 'c', '1', '2', '3'};

		p = ccall(&c, "rbd_directory", "rbd", "dir_get_id", nm, 9, 0);
		WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 10u && memcmp(p->data + 4, "abc123", 6) == 0);
		p = ccall(&c, "rbd_directory", "rbd", "dir_get_name", id, 10, 0);
		WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 9u && memcmp(p->data + 4, "plain", 5) == 0);
		nm[4] = 'x';
		p = ccall(&c, "rbd_directory", "rbd", "dir_get_id", nm, 9, 0);
		WRT_CHECK(p != NULL && p->result == -2 && p->rval[0] == -2);
		p = ccall(&c, "rbd_directory", "rbd", "dir_get_id", nm, 3, 0); /* a string that is cut */
		WRT_CHECK(p != NULL && p->result == -22);
	}
	/* the omap of the header is what the class calls show: keys in order, u64 / u8 / string values as rbd-format2.md 2.4 says */
	r = or_one("rbd_header.abc123", or_omap_vals("", 100, ""));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && wri_le32_get(p->data) == 8u);
	{
		static const char *const keys[8] = {"access_timestamp", "create_timestamp", "features", "modify_timestamp", "object_prefix", "order", "size", "snap_seq"};
		uint32_t off = 4, k;

		for (k = 0; p != NULL && k < 8u; k++) {
			uint32_t kl = wri_le32_get(p->data + off), vl;

			WRT_CHECK(kl == strlen(keys[k]) && memcmp(p->data + off + 4, keys[k], kl) == 0);
			off += 4u + kl;
			vl = wri_le32_get(p->data + off);
			if (strcmp(keys[k], "size") == 0)
				WRT_CHECK(vl == 8u && wri_le64_get(p->data + off + 4) == 10ull << 20);
			if (strcmp(keys[k], "order") == 0)
				WRT_CHECK(vl == 1u && p->data[off + 4] == 22u);
			if (strcmp(keys[k], "object_prefix") == 0)
				WRT_CHECK(vl == 4u + 15u && memcmp(p->data + off + 8, "rbd_data.abc123", 15) == 0);
			off += 4u + vl;
		}
	}
	/* object size, a custom prefix, a data pool image (the prefix carries the metadata pool id, the data pool id is a call away) */
	cfg = base_cfg("o12", "o12id", 0x1);
	cfg.order = 12;
	cfg.prefix = "custom.pfx";
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	read_header(&c, "o12id", 0, &h);
	WRT_CHECK(h.ok && h.order == 12u && strcmp(h.prefix, "custom.pfx") == 0);
	cfg = base_cfg("dp", "dpid", 0x81);
	cfg.data_pool = 5;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	read_header(&c, "dpid", 1, &h);
	WRT_CHECK(h.ok && strcmp(h.prefix, "rbd_data.2.dpid") == 0 && h.features == 0x81u && h.incompat == 0x81u);
	p = ccall(&c, "rbd_header.dpid", "rbd", "get_data_pool", none, 0, 0);
	WRT_CHECK(p != NULL && p->dlen == 8u && wri_le64_get(p->data) == 5u);
	p = ccall(&c, "rbd_header.abc123", "rbd", "get_data_pool", none, 0, 0); /* no key: -1, on any image */
	WRT_CHECK(p != NULL && p->dlen == 8u && wri_le64_get(p->data) == UINT64_MAX);
	cfg = base_cfg("dpmiss", "dpmissid", 0x81); /* the feature without the key (a refusal to provoke) */
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	p = ccall(&c, "rbd_header.dpmissid", "rbd", "get_data_pool", none, 0, 0);
	WRT_CHECK(p != NULL && wri_le64_get(p->data) == UINT64_MAX);
	/* striping: the keys, the defaults of the bit without keys, -ENOEXEC without the bit */
	cfg = base_cfg("str", "strid", 0x3);
	cfg.stripe_unit = 65536;
	cfg.stripe_count = 4;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	p = ccall(&c, "rbd_header.strid", "rbd", "get_stripe_unit_count", none, 0, 0);
	WRT_CHECK(p != NULL && p->dlen == 16u && wri_le64_get(p->data) == 65536u && wri_le64_get(p->data + 8) == 4u);
	cfg = base_cfg("str2", "str2id", 0x3);
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	p = ccall(&c, "rbd_header.str2id", "rbd", "get_stripe_unit_count", none, 0, 0);
	WRT_CHECK(p != NULL && p->dlen == 16u && wri_le64_get(p->data) == 4194304u && wri_le64_get(p->data + 8) == 1u);
	cfg = base_cfg("str3", "str3id", 0x1);
	cfg.stripe_unit = 4096;
	cfg.stripe_count = 2;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	p = ccall(&c, "rbd_header.str3id", "rbd", "get_stripe_unit_count", none, 0, 0);
	WRT_CHECK(p != NULL && p->result == -8 && p->rval[0] == -8);
	/* a clone: parent_get (pool 1, "parent", snapshot 2), the overlap, the legacy get_parent; without LAYERING the default */
	cfg = base_cfg("clone", "cloneid", 0x1);
	cfg.has_parent = 1;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	p = ccall(&c, "rbd_header.cloneid", "rbd", "parent_get", none, 0, 0);
	WRT_CHECK(p != NULL && p->dlen == 6u + 8u + 4u + 4u + 6u + 8u && wri_le64_get(p->data + 6) == 1u && wri_le32_get(p->data + 14) == 0u && memcmp(p->data + 22, "parent", 6) == 0 &&
		  wri_le64_get(p->data + 28) == 2u);
	p = ccall(&c, "rbd_header.cloneid", "rbd", "parent_overlap_get", nosnap, 8, 0);
	WRT_CHECK(p != NULL && p->dlen == 9u && p->data[0] == 1u && wri_le64_get(p->data + 1) == 10ull << 20);
	p = ccall(&c, "rbd_header.cloneid", "rbd", "get_parent", nosnap, 8, 0);
	WRT_CHECK(p != NULL && p->dlen == 8u + 4u + 6u + 8u + 8u && wri_le64_get(p->data) == 1u && wri_le64_get(p->data + 18) == 2u && wri_le64_get(p->data + 26) == 10ull << 20);
	p = ccall(&c, "rbd_header.abc123", "rbd", "parent_overlap_get", nosnap, 8, 0);
	WRT_CHECK(p != NULL && p->dlen == 1u && p->data[0] == 0u);
	cfg = base_cfg("nolayer", "nolayerid", 0x0);
	cfg.has_parent = 1; /* a parent key on an image without LAYERING: the default answer */
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	p = ccall(&c, "rbd_header.nolayerid", "rbd", "parent_get", none, 0, 0);
	WRT_CHECK(p != NULL && wri_le64_get(p->data + 6) == UINT64_MAX);
	/* flags and operation features */
	cfg = base_cfg("fl", "flid", 0x101);
	cfg.flags = 3;
	cfg.op_features = 6;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	read_header(&c, "flid", 0, &h);
	WRT_CHECK(h.ok && h.flags == 3u && h.features == 0x101u && h.incompat == 0x101u);
	p = ccall(&c, "rbd_header.flid", "rbd", "op_features_get", none, 0, 0);
	WRT_CHECK(p != NULL && p->dlen == 8u && wri_le64_get(p->data) == 6u);
	p = ccall(&c, "rbd_header.abc123", "rbd", "op_features_get", none, 0, 0);
	WRT_CHECK(p != NULL && wri_le64_get(p->data) == 0u);
	/* snapshots: the context in descending order, the size of a snapshot, an unknown one; an invalid context is served as stored */
	cfg = base_cfg("sn", "snid", 0x1);
	cfg.snap_seq = 9;
	cfg.n_snaps = 3;
	cfg.snaps[0] = 9, cfg.snaps[1] = 7, cfg.snaps[2] = 4;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	read_header(&c, "snid", 0, &h);
	WRT_CHECK(h.ok && h.seq == 9u && h.n_snaps == 3u && h.snaps[0] == 9u && h.snaps[1] == 7u && h.snaps[2] == 4u);
	{
		uint8_t s7[8], s5[8];

		wri_le64_put(s7, 7);
		wri_le64_put(s5, 5);
		p = ccall(&c, "rbd_header.snid", "rbd", "get_size", s7, 8, 0);
		WRT_CHECK(p != NULL && p->dlen == 9u && p->data[0] == 22u && wri_le64_get(p->data + 1) == 10ull << 20);
		p = ccall(&c, "rbd_header.snid", "rbd", "get_size", s5, 8, 0);
		WRT_CHECK(p != NULL && p->result == -2);
		p = ccall(&c, "rbd_header.snid", "rbd", "get_flags", s7, 8, 0);
		WRT_CHECK(p != NULL && p->dlen == 8u && wri_le64_get(p->data) == 0u);
		p = ccall(&c, "rbd_header.snid", "rbd", "get_flags", s5, 8, 0);
		WRT_CHECK(p != NULL && p->result == -2);
	}
	cfg = base_cfg("badsn", "badsnid", 0x1);
	cfg.snap_seq = 3;
	cfg.n_snaps = 1;
	cfg.snaps[0] = 5; /* a snapshot newer than the sequence: no valid context */
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	read_header(&c, "badsnid", 0, &h);
	WRT_CHECK(h.ok && h.seq == 3u && h.n_snaps == 1u && h.snaps[0] == 5u);
	/* a foreign exclusive locker */
	cfg = base_cfg("lk", "lkid", 0x4);
	cfg.lock_held = 1;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
	read_header(&c, "lkid", 0, &h);
	WRT_CHECK(h.ok && h.n_lockers == 1u && h.lock_type == 1u && h.locker_num == 77777 && strcmp(h.tag, "internal") == 0);
	/* the incompatible masks of get_features: the read-only one and the read-write one */
	{
		static const uint64_t fs[] = {0x1, 0x3d, 0x80, 0x800, 0x200, 0x4, 0xfff};
		static const uint64_t ro[] = {0x1, 0x1, 0x80, 0x800, 0x0, 0x0, 0x883};
		static const uint64_t rw[] = {0x1, 0x3d, 0x80, 0x800, 0x200, 0x4, 0xfff};

		for (i = 0; i < sizeof(fs) / sizeof(fs[0]); i++) {
			char nm[16], id[16];

			snprintf(nm, sizeof(nm), "fm%u", i);
			snprintf(id, sizeof(id), "fmid%u", i);
			cfg = base_cfg(nm, id, fs[i]);
			WRT_CHECK_STATUS(WR_OK, sim_rbd_image_create(e.store, &cfg));
			read_header(&c, id, 1, &h);
			WRT_CHECK(h.ok && h.features == fs[i] && h.incompat == ro[i]);
			read_header(&c, id, 0, &h);
			WRT_CHECK(h.ok && h.incompat == rw[i]);
		}
	}
	p = ccall(&c, "rbd_header.abc123", "rbd", "get_all_features", none, 0, 0);
	WRT_CHECK(p != NULL && p->dlen == 8u && wri_le64_get(p->data) == 0xfffu);
	/* the header changes behind the client's back: the next read sees it, the snapshots keep their own size */
	{
		const uint64_t nsn[4] = {12, 9, 7, 4};

		WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(e.store, POOL, "snid", 12, nsn, 4));
		WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_size(e.store, POOL, "snid", 20ull << 20));
		WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_features(e.store, POOL, "snid", 0x1d));
		read_header(&c, "snid", 0, &h);
		WRT_CHECK(h.ok && h.seq == 12u && h.n_snaps == 4u && h.snaps[0] == 12u && h.snaps[3] == 4u && h.size == 20ull << 20 && h.features == 0x1du);
		WRT_CHECK_STATUS(WR_E_RANGE, sim_rbd_image_set_size(e.store, POOL, "nosuch", 1));
		WRT_CHECK_STATUS(WR_E_RANGE, sim_rbd_image_set_snapc(e.store, POOL, "nosuch", 1, nsn, 1));
		WRT_CHECK_STATUS(WR_E_RANGE, sim_rbd_image_set_features(e.store, POOL, "nosuch", 1));
		WRT_CHECK_STATUS(WR_E_INVAL, sim_rbd_image_set_snapc(e.store, POOL, "snid", 1, nsn, 1025));
	}
	/* a mutating method: the size changes, the output of the message is discarded; on a missing header nothing is created */
	{
		uint8_t sz[8];

		wri_le64_put(sz, 33ull << 20);
		p = ccall(&c, "rbd_header.snid", "rbd", "set_size", sz, 8, 1);
		WRT_CHECK(p != NULL && p->result == 0 && p->replay_ver != 0u);
		WRT_CHECK(sim_osd_recs(e.osd, &i)[i - 1u].mutating == 1u);
		read_header(&c, "snid", 0, &h);
		WRT_CHECK(h.ok && h.size == 33ull << 20);
		p = ccall(&c, "rbd_header.nosuch", "rbd", "set_size", sz, 8, 1);
		WRT_CHECK(p != NULL && p->result == -2 && !sim_store_exists(e.store, POOL, "rbd_header.nosuch"));
		p = ccall(&c, "rbd_header.snid", "rbd", "set_size", none, 0, 1);
		WRT_CHECK(p != NULL && p->result == -22);
	}
	/* damage the header the way a provoked refusal needs: a missing key is -ENOENT, a short value -EIO, an input that is too short -EINVAL */
	WRT_CHECK_STATUS(WR_OK, sim_store_omap_rm(e.store, POOL, "rbd_header.abc123", "snap_seq"));
	p = ccall(&c, "rbd_header.abc123", "rbd", "get_snapcontext", none, 0, 0);
	WRT_CHECK(p != NULL && p->result == -2);
	WRT_CHECK_STATUS(WR_OK, sim_store_omap_set(e.store, POOL, "rbd_header.abc123", "size", none, 1));
	p = ccall(&c, "rbd_header.abc123", "rbd", "get_size", nosnap, 8, 0);
	WRT_CHECK(p != NULL && p->result == -5);
	p = ccall(&c, "rbd_header.abc123", "rbd", "get_size", nosnap, 4, 0);
	WRT_CHECK(p != NULL && p->result == -22);
	WRT_CHECK_STATUS(WR_OK, sim_store_omap_set(e.store, POOL, "rbd_header.abc123", "object_prefix", none, 1));
	p = ccall(&c, "rbd_header.abc123", "rbd", "get_object_prefix", none, 0, 0);
	WRT_CHECK(p != NULL && p->result == -5);
	/* a header that is not there: the whole message fails before any call runs */
	r = or_one("rbd_header.missing", or_call("rbd", "get_size", nosnap, 8));
	or_req_add(&r, or_call("rbd", "get_object_prefix", none, 0));
	p = call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2 && p->n_ops == 2u && p->rval[0] == 0 && p->rval[1] == 0 && p->dlen == 0u && (p->flags & 1) == 0);
	/* configurations that cannot be made */
	{
		sim_rbd_image_cfg bad = base_cfg("x", "y", 0);
		char longname[160];

		WRT_CHECK_STATUS(WR_E_INVAL, sim_rbd_image_create(NULL, &bad));
		WRT_CHECK_STATUS(WR_E_INVAL, sim_rbd_image_create(e.store, NULL));
		bad.name = NULL;
		WRT_CHECK_STATUS(WR_E_INVAL, sim_rbd_image_create(e.store, &bad));
		bad = base_cfg("", "y", 0);
		WRT_CHECK_STATUS(WR_E_INVAL, sim_rbd_image_create(e.store, &bad));
		bad = base_cfg("x", "", 0);
		WRT_CHECK_STATUS(WR_E_INVAL, sim_rbd_image_create(e.store, &bad));
		bad = base_cfg("x", "y", 0);
		bad.n_snaps = 17;
		WRT_CHECK_STATUS(WR_E_INVAL, sim_rbd_image_create(e.store, &bad));
		memset(longname, 'n', sizeof(longname) - 1u);
		longname[sizeof(longname) - 1u] = '\0';
		bad = base_cfg(longname, "y", 0);
		WRT_CHECK_STATUS(WR_E_INVAL, sim_rbd_image_create(e.store, &bad));
	}
	orc_free(&c);
	ore_free(&e);
}

/* ---- the lock class between two clients ------------------------------------------------------------------------------------------------- */

static uint32_t put_env_str(tb *t, const char *s) /* a struct v1/1 helper: the caller patches the length */
{
	tb_u32(t, (uint32_t)strlen(s));
	tb_bytes(t, s, strlen(s));
	return 0;
}

static void lock_in(tb *t, const char *name, uint8_t type, const char *cookie, const char *tag, uint32_t dur, uint8_t flags)
{
	t->n = 0;
	tb_u8(t, 1);
	tb_u8(t, 1);
	tb_u32(t, 0);
	(void)put_env_str(t, name);
	tb_u8(t, type);
	(void)put_env_str(t, cookie);
	(void)put_env_str(t, tag);
	(void)put_env_str(t, "");
	tb_u32(t, dur);
	tb_u32(t, 0);
	tb_u8(t, flags);
	wri_le32_put(t->b + 2, (uint32_t)(t->n - 6u));
}

static void unlock_in(tb *t, const char *name, const char *cookie)
{
	t->n = 0;
	tb_u8(t, 1);
	tb_u8(t, 1);
	tb_u32(t, 0);
	(void)put_env_str(t, name);
	(void)put_env_str(t, cookie);
	wri_le32_put(t->b + 2, (uint32_t)(t->n - 6u));
}

static void assert_in(tb *t, const char *name, uint8_t type, const char *cookie, const char *tag)
{
	t->n = 0;
	tb_u8(t, 1);
	tb_u8(t, 1);
	tb_u32(t, 0);
	(void)put_env_str(t, name);
	tb_u8(t, type);
	(void)put_env_str(t, cookie);
	(void)put_env_str(t, tag);
	wri_le32_put(t->b + 2, (uint32_t)(t->n - 6u));
}

static void info_in(tb *t, const char *name)
{
	t->n = 0;
	tb_u8(t, 1);
	tb_u8(t, 1);
	tb_u32(t, 0);
	(void)put_env_str(t, name);
	wri_le32_put(t->b + 2, (uint32_t)(t->n - 6u));
}

static int32_t lk(orc *c, const char *obj, const char *method, const tb *in)
{
	const or_reply *p = ccall(c, obj, "lock", method, in->b, (uint32_t)in->n, strcmp(method, "get_info") != 0 && strcmp(method, "assert_locked") != 0 && strcmp(method, "list_locks") != 0);

	return p != NULL ? p->result : INT32_MIN;
}

/* number of lockers and the global id / cookie of the first, from a get_info */
static uint32_t lockers(orc *c, const char *obj, const char *name, int64_t *num, char *cookie, uint8_t *type, char *tag)
{
	tb in;
	const or_reply *p;
	wri_rd rd;
	wri_env e;
	uint32_t n = 0xffffffffu;

	info_in(&in, name);
	p = ccall(c, obj, "lock", "get_info", in.b, (uint32_t)in.n, 0);
	if (p == NULL || p->result != 0)
		return n;
	wri_rd_init(&rd, p->data, p->dlen);
	if (wri_env_open(&rd, 1, &e) != WR_OK)
		return n;
	n = wri_rd_u32(&e.body);
	if (n != 0u) {
		wri_env id, info;
		uint32_t cl;
		const uint8_t *cb;

		if (wri_env_open(&e.body, 1, &id) != WR_OK)
			return 0xffffffffu;
		(void)wri_rd_u8(&id.body);
		if (num != NULL)
			*num = wri_rd_i64(&id.body);
		cb = wri_denc_blob(&id.body, &cl, 63);
		if (cookie != NULL && cb != NULL) {
			memcpy(cookie, cb, cl);
			cookie[cl] = '\0';
		}
		if (wri_env_open(&e.body, 1, &info) != WR_OK)
			return 0xffffffffu;
		{
			uint32_t k;

			for (k = 1; k < n; k++) { /* skip the others */
				wri_env i2, n2;

				if (wri_env_open(&e.body, 1, &i2) != WR_OK || wri_env_open(&e.body, 1, &n2) != WR_OK)
					return 0xffffffffu;
			}
		}
	}
	if (type != NULL)
		*type = wri_rd_u8(&e.body);
	if (tag != NULL) {
		uint32_t tl;
		const uint8_t *t = wri_denc_blob(&e.body, &tl, 39);

		if (t != NULL) {
			memcpy(tag, t, tl);
			tag[tl] = '\0';
		}
	}
	return n;
}

static void t_locks(void)
{
	ore e, eb;
	orc a, b;
	mc l2;
	tb in;
	int64_t num = 0;
	char cookie[64], tag[40];
	uint8_t type = 0;
	const or_reply *p;
	or_req r;
	uint32_t i;
	const char *o = "lock-obj";

	ore_prep(&e, WR_KEY_TYPE_AES256K);
	ore_start(&e);
	orc_up(&a, &e);
	/* a second client of the same cluster: its own login, so its own global id, and its own address */
	WRT_CHECK(mc_init(&l2, e.mon, &e.login.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&l2, 0x24), MC_OK);
	eb = e;
	eb.okey = l2.svc[OR_OSD_SLOT].key;
	memcpy(eb.blob, l2.svc[OR_OSD_SLOT].blob, l2.svc[OR_OSD_SLOT].blob_len);
	eb.blob_len = l2.svc[OR_OSD_SLOT].blob_len;
	eb.secret_id = l2.svc[OR_OSD_SLOT].secret_id;
	eb.gid = l2.gid;
	WRT_CHECK(eb.gid != e.gid);
	orc_init(&b, &eb, e.osd);
	b.ident_ip[3] = 21;
	b.ident_nonce = 0x4242;
	WRT_CHECK_U64(orc_open(&b), OR_OK);

	/* A takes the exclusive lock (the object does not exist yet: the lock call creates it) */
	lock_in(&in, "rbd_lock", 1, "a", "t", 0, 0);
	WRT_CHECK(lk(&a, o, "lock", &in) == 0);
	WRT_CHECK(sim_store_exists(e.store, POOL, o));
	WRT_CHECK(lockers(&b, o, "rbd_lock", &num, cookie, &type, tag) == 1u && num == (int64_t)e.gid && strcmp(cookie, "a") == 0 && type == 1u && strcmp(tag, "t") == 0);
	WRT_CHECK(sim_osd_recs(e.osd, &i)[i - 1u].mutating == 0u); /* get_info is a read */
	/* the refusals of a second client: exclusive, shared, another tag; the same client again: -EEXIST, renewal, a renewal of nothing */
	lock_in(&in, "rbd_lock", 1, "b", "t", 0, 0);
	WRT_CHECK(lk(&b, o, "lock", &in) == -16);
	lock_in(&in, "rbd_lock", 2, "b", "t", 0, 0);
	WRT_CHECK(lk(&b, o, "lock", &in) == -16);
	lock_in(&in, "rbd_lock", 1, "b", "other", 0, 0);
	WRT_CHECK(lk(&b, o, "lock", &in) == -16);
	lock_in(&in, "rbd_lock", 1, "a", "t", 0, 0);
	WRT_CHECK(lk(&a, o, "lock", &in) == -17);
	lock_in(&in, "rbd_lock", 1, "a", "t", 0, 1);
	WRT_CHECK(lk(&a, o, "lock", &in) == 0);
	lock_in(&in, "rbd_lock", 1, "zz", "t", 0, 2);
	WRT_CHECK(lk(&a, o, "lock", &in) == -2);
	/* inputs that do not decode, a name that is empty, a version the decoder does not know */
	lock_in(&in, "", 1, "a", "t", 0, 0);
	WRT_CHECK(lk(&a, o, "lock", &in) == -22);
	lock_in(&in, "rbd_lock", 1, "a", "t", 0, 0);
	in.n -= 3;
	WRT_CHECK(lk(&a, o, "lock", &in) == -22);
	lock_in(&in, "rbd_lock", 1, "a", "t", 0, 0);
	in.b[1] = 2;
	WRT_CHECK(lk(&a, o, "lock", &in) == -22);
	/* unlock is the caller's own: B cannot release A's lock, but anyone can break it */
	unlock_in(&in, "rbd_lock", "a");
	WRT_CHECK(lk(&b, o, "unlock", &in) == -2);
	{
		tb brk;

		brk.n = 0;
		tb_u8(&brk, 1);
		tb_u8(&brk, 1);
		tb_u32(&brk, 0);
		(void)put_env_str(&brk, "rbd_lock");
		tb_u8(&brk, 8);
		tb_u64(&brk, e.gid);
		(void)put_env_str(&brk, "a");
		wri_le32_put(brk.b + 2, (uint32_t)(brk.n - 6u));
		WRT_CHECK(lk(&b, o, "break_lock", &brk) == 0);
		WRT_CHECK(lk(&b, o, "break_lock", &brk) == -2);
	}
	WRT_CHECK(lockers(&a, o, "rbd_lock", NULL, cookie, &type, tag) == 0u && type == 1u && strcmp(tag, "t") == 0); /* the record keeps the last type and tag */
	lock_in(&in, "rbd_lock", 1, "b", "t", 0, 0);
	WRT_CHECK(lk(&b, o, "lock", &in) == 0);
	unlock_in(&in, "rbd_lock", "a");
	WRT_CHECK(lk(&a, o, "unlock", &in) == -2);
	/* assert_locked: the holder with the right type, cookie and tag; a read method */
	assert_in(&in, "rbd_lock", 1, "b", "t");
	WRT_CHECK(lk(&b, o, "assert_locked", &in) == 0);
	WRT_CHECK(sim_osd_recs(e.osd, &i)[i - 1u].mutating == 0u);
	WRT_CHECK(lk(&a, o, "assert_locked", &in) == -16);
	assert_in(&in, "rbd_lock", 1, "b", "x");
	WRT_CHECK(lk(&b, o, "assert_locked", &in) == -16);
	assert_in(&in, "rbd_lock", 2, "b", "t");
	WRT_CHECK(lk(&b, o, "assert_locked", &in) == -16);
	/* set_cookie renames the caller's lock */
	{
		tb sc;

		sc.n = 0;
		tb_u8(&sc, 1);
		tb_u8(&sc, 1);
		tb_u32(&sc, 0);
		(void)put_env_str(&sc, "rbd_lock");
		tb_u8(&sc, 1);
		(void)put_env_str(&sc, "b");
		(void)put_env_str(&sc, "t");
		(void)put_env_str(&sc, "b2");
		wri_le32_put(sc.b + 2, (uint32_t)(sc.n - 6u));
		WRT_CHECK(lk(&b, o, "set_cookie", &sc) == 0);
		WRT_CHECK(lockers(&a, o, "rbd_lock", &num, cookie, NULL, NULL) == 1u && strcmp(cookie, "b2") == 0 && num == (int64_t)eb.gid);
		WRT_CHECK(lk(&b, o, "set_cookie", &sc) == -2); /* the old cookie is gone */
	}
	unlock_in(&in, "rbd_lock", "b2");
	WRT_CHECK(lk(&b, o, "unlock", &in) == 0);
	/* shared locks: both clients hold one, an exclusive request is refused, another tag too */
	lock_in(&in, "rbd_lock", 2, "sa", "s", 0, 0);
	WRT_CHECK(lk(&a, o, "lock", &in) == 0);
	lock_in(&in, "rbd_lock", 2, "sb", "s", 0, 0);
	WRT_CHECK(lk(&b, o, "lock", &in) == 0);
	WRT_CHECK(lockers(&a, o, "rbd_lock", NULL, NULL, &type, tag) == 2u && type == 2u && strcmp(tag, "s") == 0);
	lock_in(&in, "rbd_lock", 1, "xa", "s", 0, 0);
	WRT_CHECK(lk(&a, o, "lock", &in) == -16);
	/* another lock of the same object does not mix; list_locks names them both */
	lock_in(&in, "other", 1, "oa", "", 0, 0);
	WRT_CHECK(lk(&a, o, "lock", &in) == 0);
	p = ccall(&a, o, "lock", "list_locks", none_bytes(), 0, 0);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 6u + 4u + 4u + 5u + 4u + 8u && wri_le32_get(p->data + 6) == 2u && memcmp(p->data + 14, "other", 5) == 0 && memcmp(p->data + 23, "rbd_lock", 8) == 0);

	/* a lock with a duration ends on the store's clock: held at 4 s, gone at 6 s, the other client gets it */
	lock_in(&in, "timed", 1, "ta", "t", 5, 0);
	WRT_CHECK(lk(&a, o, "lock", &in) == 0);
	lock_in(&in, "timed", 1, "tb", "t", 0, 0);
	WRT_CHECK(lk(&b, o, "lock", &in) == -16);
	sim_store_set_time(e.store, 1700000000u + 4u);
	WRT_CHECK(lk(&b, o, "lock", &in) == -16);
	sim_store_set_time(e.store, 1700000000u + 6u);
	WRT_CHECK(lockers(&b, o, "timed", NULL, NULL, &type, tag) == 0u && type == 1u);
	WRT_CHECK(lk(&b, o, "lock", &in) == 0);
	WRT_CHECK(lockers(&a, o, "timed", &num, cookie, NULL, NULL) == 1u && num == (int64_t)eb.gid && strcmp(cookie, "tb") == 0);

	/* a message is atomic: a second lock call that fails undoes the first one, nothing of it stays */
	lock_in(&in, "rbd_lock", 1, "q", "t", 0, 0);
	r = or_one("fresh", or_call("lock", "lock", in.b, (uint32_t)in.n));
	or_req_add(&r, or_call("lock", "lock", in.b, (uint32_t)in.n));
	r.flags = 0x08400024u;
	p = call(&a, &r);
	WRT_CHECK(p != NULL && p->result == -17 && p->rval[0] == 0 && p->rval[1] == -17 && !sim_store_exists(e.store, POOL, "fresh"));
	/* a lock plus a read in one message: the output of the changed object is discarded */
	info_in(&in, "rbd_lock");
	lock_in(&in, "rbd_lock", 1, "q", "t", 0, 0);
	{
		tb gi;

		info_in(&gi, "rbd_lock");
		r = or_one("fresh", or_call("lock", "lock", in.b, (uint32_t)in.n));
		or_req_add(&r, or_call("lock", "get_info", gi.b, (uint32_t)gi.n));
		r.flags = 0x08400024u;
		p = call(&a, &r);
		WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 0u && p->payload_len[1] == 0u && sim_store_exists(e.store, POOL, "fresh"));
	}
	/* an unlock or a read of an object that does not exist: -ENOENT, nothing is created */
	unlock_in(&in, "rbd_lock", "a");
	{
		or_req r2 = or_one("nobody", or_call("lock", "unlock", in.b, (uint32_t)in.n));

		r2.flags = 0x08400024u;
		p = call(&a, &r2);
		WRT_CHECK(p != NULL && p->result == -2 && !sim_store_exists(e.store, POOL, "nobody"));
	}
	info_in(&in, "rbd_lock");
	r = or_one("nobody", or_call("lock", "get_info", in.b, (uint32_t)in.n));
	p = call(&a, &r);
	WRT_CHECK(p != NULL && p->result == -2 && !acked_(p));
	mc_free(&l2);
	orc_free(&b);
	orc_free(&a);
	ore_free(&e);
}

int main(void)
{
	t_vectors();
	t_fixtures();
	t_locks();
	return wrt_finish();
}
