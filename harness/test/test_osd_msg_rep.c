/* SPDX-License-Identifier: MIT */
/*
 * test_osd_msg_rep.c - module osd-msg, the reply side (core/src/osd/wri_osd_rep.c): wri_mosdopreply_decode, wri_osd_sparse_decode,
 * wri_osd_stat_decode.
 *
 * Oracles: the captured reply fronts of harness/vectors/osdop/ against their summaries, and a test-local reply writer built from the
 * note (osd-ops.md 2.9) for everything a capture cannot show (a redirect, a hostile count, a lying length). Every reply is cut at every
 * offset; the sparse and stat outputs are checked on every rule of the note.
 */
#include "osd_msg_rig.h"

/* ---- a reply writer, independent of the core cursors ---------------------------------------------------------------------------- */

typedef struct buf {
	uint8_t *p;
	size_t n, cap;
} buf;

static void b_u8(buf *b, uint8_t v)
{
	if (b->n < b->cap)
		b->p[b->n] = v;
	b->n++;
}

static void b_le(buf *b, uint64_t v, unsigned bytes)
{
	unsigned i;

	for (i = 0; i < bytes; i++)
		b_u8(b, (uint8_t)(v >> (8 * i)));
}

static void b_zero(buf *b, size_t n)
{
	while (n--)
		b_u8(b, 0);
}

static void b_mem(buf *b, const void *p, size_t n)
{
	const uint8_t *q = (const uint8_t *)p;

	while (n--)
		b_u8(b, *q++);
}

typedef struct trep {
	const char *oid;
	int64_t oid_len;        /* >= 0: written instead of strlen(oid) (a lie) */
	uint8_t pg_ver;
	int64_t pool;
	uint32_t seed;
	int64_t flags;
	int32_t result;
	uint32_t epoch;
	uint32_t n_ops;         /* the count written */
	uint32_t n_recs;        /* records actually written */
	uint16_t code[10];
	uint32_t plen[10];
	int32_t rval[10];
	int32_t retry;
	uint64_t user_version;
	uint8_t redirect;       /* do_redirect byte */
	uint8_t redir_v, redir_compat;
	uint32_t redir_len;     /* struct_len of the redirect body, which is then written as that many 0x5A bytes */
	uint32_t redir_have;    /* bytes of body actually written */
	size_t trace;           /* trace bytes at the end */
	size_t extra;           /* more bytes after the trace */
} trep;

static trep trep_init(void)
{
	trep r;

	memset(&r, 0, sizeof(r));
	r.oid = "rbd_header.37863d7ada59";
	r.oid_len = -1;
	r.pg_ver = 1;
	r.pool = 2;
	r.seed = 3;
	r.flags = 0x08400015;
	r.epoch = 42;
	r.n_ops = r.n_recs = 1;
	r.code[0] = WRI_OSD_OP_READ;
	r.plen[0] = 100;
	r.trace = 24;
	r.redir_v = 1;
	r.redir_compat = 1;
	return r;
}

static size_t trep_build(const trep *r, uint8_t *dst, size_t cap)
{
	buf b;
	uint32_t i;

	b.p = dst;
	b.n = 0;
	b.cap = cap;
	b_le(&b, r->oid_len >= 0 ? (uint64_t)r->oid_len : strlen(r->oid), 4);
	b_mem(&b, r->oid, strlen(r->oid));
	b_u8(&b, r->pg_ver);
	b_le(&b, (uint64_t)r->pool, 8);
	b_le(&b, r->seed, 4);
	b_le(&b, 0xFFFFFFFFu, 4);
	b_le(&b, (uint64_t)r->flags, 8);
	b_le(&b, (uint32_t)r->result, 4);
	b_le(&b, 7, 8); /* bad_replay_version: version, epoch (not zero in the captures) */
	b_le(&b, 9, 4);
	b_le(&b, r->epoch, 4);
	b_le(&b, r->n_ops, 4);
	for (i = 0; i < r->n_recs; i++) {
		b_le(&b, r->code[i], 2);
		b_zero(&b, 32); /* flags and the argument union */
		b_le(&b, r->plen[i], 4);
	}
	b_le(&b, (uint32_t)r->retry, 4);
	for (i = 0; i < r->n_recs; i++)
		b_le(&b, (uint32_t)r->rval[i], 4);
	b_le(&b, 11, 8); /* replay_version */
	b_le(&b, 12, 4);
	b_le(&b, r->user_version, 8);
	b_u8(&b, r->redirect);
	if (r->redirect != 0) {
		uint32_t k;

		b_u8(&b, r->redir_v);
		b_u8(&b, r->redir_compat);
		b_le(&b, r->redir_len, 4);
		for (k = 0; k < r->redir_have; k++)
			b_u8(&b, 0x5A);
	}
	b_zero(&b, r->trace);
	b_zero(&b, r->extra);
	return b.n;
}

/* ---- decode helpers ----------------------------------------------------------------------------------------------------------- */

static int all_zero(const void *p, size_t n)
{
	const uint8_t *q = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (q[i] != 0)
			return 0;
	return 1;
}

/* Decode into a heap copy of exactly n bytes (ASan sees any over-read); *out is poisoned first so "cleared on failure" is real. */
static uint8_t *dec_copy; /* the copy the last decode borrowed from: alive until the next decode */

static wr_status dec(const uint8_t *front, size_t n, uint16_t ver, uint16_t compat, wri_mosdopreply *out)
{
	uint8_t *c = (uint8_t *)malloc(n ? n : 1);

	free(dec_copy);
	dec_copy = c;
	if (n)
		memcpy(c, front, n);
	memset(out, 0xEE, sizeof(*out));
	return wri_mosdopreply_decode(c, n, ver, compat, out);
}

/* ---- the captured replies --------------------------------------------------------------------------------------------------------- */

static void check_summary(const rig_vec *v, const wri_mosdopreply *r, const char *name)
{
	const wrt_json *j = &v->j;
	wrt_tok ops = wrt_json_get(j, v->rep_sum, "ops");
	wrt_tok rv = wrt_json_get(j, v->rep_sum, "rvals");
	char *oid = wrt_json_strdup(j, wrt_json_get(j, v->rep_sum, "oid"));
	size_t i;
	uint64_t total = 0;

	if (oid == NULL) {
		fprintf(stderr, "%s: no oid\n", name);
		WRT_CHECK(0);
		return;
	}
	WRT_CHECK(r->oid_len == strlen(oid) && memcmp(r->oid, oid, r->oid_len) == 0);
	WRT_CHECK_U64(r->pool, rig_int(j, v->rep_sum, "pool", -1));
	WRT_CHECK_U64(r->pg_seed, rig_int(j, v->rep_sum, "seed", -1));
	WRT_CHECK_U64(r->flags, rig_int(j, v->rep_sum, "flags", -1));
	WRT_CHECK_U64((uint32_t)r->result, (uint32_t)rig_int(j, v->rep_sum, "result", 12345));
	WRT_CHECK(r->result == (int32_t)rig_int(j, v->rep_sum, "result", 12345));
	WRT_CHECK_U64(r->map_epoch, rig_int(j, v->rep_sum, "epoch", -1));
	WRT_CHECK_U64(r->retry_attempt, rig_int(j, v->rep_sum, "retry_attempt", -1));
	WRT_CHECK_U64(r->user_version, rig_int(j, v->rep_sum, "user_version", -1));
	WRT_CHECK(r->do_redirect == 0);
	WRT_CHECK_U64(r->n_ops, wrt_json_count(j, ops));
	WRT_CHECK_U64(r->n_ops, wrt_json_count(j, rv));
	for (i = 0; i < r->n_ops && i < WRI_OSD_OPS_MAX; i++) {
		wrt_tok o = wrt_json_at(j, ops, i);
		int ok = 0;

		WRT_CHECK_U64(r->op_code[i], rig_int(j, o, "code", -1));
		WRT_CHECK_U64(r->out_len[i], rig_int(j, o, "payload_len", -1));
		WRT_CHECK(r->rval[i] == (int32_t)wrt_json_int(j, wrt_json_at(j, rv, i), &ok) && ok);
		total += r->out_len[i];
	}
	WRT_CHECK_U64(r->out_total, total);
	WRT_CHECK_U64(r->out_total, v->rep_data_len); /* what the data segment really held */
	free(oid);
}

static void test_vectors(void)
{
	unsigned k;

	for (k = 0; k < RIG_NVEC; k++) {
		rig_vec v;
		wri_mosdopreply r;
		size_t cut;

		if (rig_vec_load(&v, rig_vec_name[k]) != 0) {
			fprintf(stderr, "cannot load %s\n", rig_vec_name[k]);
			WRT_CHECK(0);
			continue;
		}
		if (v.rep == WRT_NONE) { /* the synthetic example has no reply */
			rig_vec_free(&v);
			continue;
		}
		WRT_CHECK_U64(v.rep_version, 8);
		WRT_CHECK_U64(v.rep_compat, 2);
		WRT_CHECK_STATUS(WR_OK, dec(v.rep_front, v.rep_len, v.rep_version, v.rep_compat, &r));
		check_summary(&v, &r, rig_vec_name[k]);
		/* trailing bytes after the trace block are ignored */
		{
			uint8_t *more = (uint8_t *)malloc(v.rep_len + 5u);
			wri_mosdopreply r2;

			memcpy(more, v.rep_front, v.rep_len);
			memset(more + v.rep_len, 0x33, 5);
			WRT_CHECK_STATUS(WR_OK, dec(more, v.rep_len + 5u, 8, 2, &r2));
			WRT_CHECK(r2.out_total == r.out_total && r2.n_ops == r.n_ops && r2.result == r.result && r2.user_version == r.user_version);
			free(more);
		}
		/* cut at every offset: every shorter front is refused and leaves the output clear */
		for (cut = 0; cut < v.rep_len; cut++) {
			wr_status st = dec(v.rep_front, cut, 8, 2, &r);

			if (st != WR_E_OSD_PROTO) {
				fprintf(stderr, "%s: cut at %zu of %zu gave %d\n", rig_vec_name[k], cut, v.rep_len, (int)st);
				WRT_CHECK(0);
			}
			WRT_CHECK(all_zero(&r, sizeof(r)));
			wrt_checks++;
		}
		/* every (version, compat) pair around the supported one */
		{
			uint16_t ver, compat;

			for (ver = 0; ver < 12; ver++)
				for (compat = 0; compat < 12; compat++) {
					wr_status st = dec(v.rep_front, v.rep_len, ver, compat, &r);
					wr_status want = (ver == 8 && compat <= 8) ? WR_OK : WR_E_OSD_VERSION;

					WRT_CHECK_STATUS(want, st);
					if (st != WR_OK)
						WRT_CHECK(all_zero(&r, sizeof(r)));
				}
			WRT_CHECK_STATUS(WR_E_OSD_VERSION, dec(v.rep_front, v.rep_len, 0xFFFF, 0xFFFF, &r));
			WRT_CHECK_STATUS(WR_E_OSD_VERSION, dec(v.rep_front, v.rep_len, 8, 0xFFFF, &r));
		}
		rig_vec_free(&v);
	}
}

/* ---- synthetic replies ---------------------------------------------------------------------------------------------------------- */

static void test_synthetic_ok(void)
{
	trep t = trep_init();
	uint8_t b[1024];
	size_t n;
	wri_mosdopreply r;
	uint32_t i;

	/* the happy path, field by field */
	t.flags = (int64_t)0x0123456789ABCDEFll;
	t.result = -2;
	t.retry = 5;
	t.user_version = 0xFEDCBA9876543210ull;
	t.pool = 0x123456789ll;
	t.seed = 0xCAFEBABEu;
	t.epoch = 0xFFFFFFFFu;
	t.rval[0] = -95;
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, dec(b, n, 8, 2, &r));
	WRT_CHECK(r.oid_len == strlen(t.oid) && memcmp(r.oid, t.oid, r.oid_len) == 0);
	WRT_CHECK_U64(r.pool, 0x123456789ll);
	WRT_CHECK_U64(r.pg_seed, 0xCAFEBABEu);
	WRT_CHECK_U64(r.flags, 0x0123456789ABCDEFll); /* 64 bit */
	WRT_CHECK(r.result == -2 && r.map_epoch == 0xFFFFFFFFu && r.retry_attempt == 5);
	WRT_CHECK_U64(r.user_version, 0xFEDCBA9876543210ull);
	WRT_CHECK(r.n_ops == 1 && r.op_code[0] == WRI_OSD_OP_READ && r.out_len[0] == 100 && r.rval[0] == -95 && r.out_total == 100);
	WRT_CHECK(r.do_redirect == 0);
	/* the unused tail of the arrays is zero */
	for (i = 1; i < WRI_OSD_OPS_MAX; i++)
		WRT_CHECK(r.op_code[i] == 0 && r.out_len[i] == 0 && r.rval[i] == 0);
	/* a negative 64 bit flag word */
	t.flags = -1;
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, dec(b, n, 8, 2, &r));
	WRT_CHECK(r.flags == -1);

	/* zero to eight echoed operations; the codes are kept as echoed (a ZERO may come back as TRUNCATE) */
	for (i = 0; i <= WRI_OSD_OPS_MAX; i++) {
		uint32_t k;
		uint64_t total = 0;

		t = trep_init();
		t.n_ops = t.n_recs = i;
		for (k = 0; k < i; k++) {
			t.code[k] = (uint16_t)(0x2200u + k);
			t.plen[k] = k * 1000u + 7u;
			t.rval[k] = (int32_t)k - 3;
			total += t.plen[k];
		}
		n = trep_build(&t, b, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, dec(b, n, 8, 2, &r));
		WRT_CHECK(r.n_ops == i && r.out_total == total);
		for (k = 0; k < i; k++)
			WRT_CHECK(r.op_code[k] == 0x2200u + k && r.out_len[k] == k * 1000u + 7u && r.rval[k] == (int32_t)k - 3);
	}

	/* out_total is a 64 bit sum: eight maximal payloads do not wrap */
	t = trep_init();
	t.n_ops = t.n_recs = 8;
	for (i = 0; i < 8; i++)
		t.plen[i] = 0xFFFFFFFFu;
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, dec(b, n, 8, 2, &r));
	WRT_CHECK_U64(r.out_total, 8ull * 0xFFFFFFFFull);

	/* an empty object name is carried */
	t = trep_init();
	t.oid = "";
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, dec(b, n, 8, 2, &r));
	WRT_CHECK(r.oid_len == 0);
	/* the longest name the OSD accepts */
	{
		static char nm[2049];

		memset(nm, 'q', 2048);
		nm[2048] = 0;
		t.oid = nm;
		{
			static uint8_t big[2300];

			n = trep_build(&t, big, sizeof(big));
			WRT_CHECK_STATUS(WR_OK, dec(big, n, 8, 2, &r));
			WRT_CHECK(r.oid_len == 2048);
		}
	}

	/* a redirect is detected and its body skipped by length; whatever follows is still read */
	t = trep_init();
	t.redirect = 1;
	t.redir_len = 20;
	t.redir_have = 20;
	t.user_version = 77;
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, dec(b, n, 8, 2, &r));
	WRT_CHECK(r.do_redirect == 1 && r.user_version == 77);
	/* any non-zero byte is "true" */
	t.redirect = 2;
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, dec(b, n, 8, 2, &r));
	WRT_CHECK(r.do_redirect == 1);
}

static void test_synthetic_bad(void)
{
	trep t;
	uint8_t b[4096];
	size_t n;
	wri_mosdopreply r;
	uint32_t i;

	/* more operations than a message may carry, in every size, even when the bytes are there */
	for (i = WRI_OSD_OPS_MAX + 1u; i <= 10; i++) {
		t = trep_init();
		t.n_ops = t.n_recs = i;
		n = trep_build(&t, b, sizeof(b));
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, dec(b, n, 8, 2, &r));
		WRT_CHECK(all_zero(&r, sizeof(r)));
	}
	{
		static const uint32_t big[] = {0x10000u, 0x7FFFFFFFu, 0x80000000u, 0xFFFFFFFFu, 0xFFFFFFFEu, 9};

		for (i = 0; i < sizeof(big) / sizeof(big[0]); i++) {
			t = trep_init();
			t.n_ops = big[i];
			t.n_recs = 1;
			n = trep_build(&t, b, sizeof(b));
			WRT_CHECK_STATUS(WR_E_OSD_PROTO, dec(b, n, 8, 2, &r));
			WRT_CHECK(all_zero(&r, sizeof(r)));
		}
	}
	/* a count that is larger than the records present (the message ends early) */
	t = trep_init();
	t.n_ops = 3;
	t.n_recs = 1;
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, dec(b, n, 8, 2, &r));
	/* a count that is smaller than the records present misreads the tail: refused by the trace rule or by shape, never a crash */
	t = trep_init();
	t.n_ops = 1;
	t.n_recs = 2;
	t.trace = 0;
	n = trep_build(&t, b, sizeof(b));
	(void)dec(b, n, 8, 2, &r);

	/* the object name: longer than the OSD allows, longer than the message, wildly long */
	{
		static const int64_t lies[] = {2049, 4096, 0x7FFFFFFF, 0xFFFFFFFFll, 200, 24};

		for (i = 0; i < sizeof(lies) / sizeof(lies[0]); i++) {
			t = trep_init();
			t.oid_len = lies[i];
			n = trep_build(&t, b, sizeof(b));
			/* 24 is one more than the real 23: the pg_t then starts one byte early and the version byte is wrong */
			WRT_CHECK_STATUS(WR_E_OSD_PROTO, dec(b, n, 8, 2, &r));
			WRT_CHECK(all_zero(&r, sizeof(r)));
		}
	}
	{
		static char nm[2100];

		memset(nm, 'q', 2049);
		nm[2049] = 0;
		t = trep_init();
		t.oid = nm; /* 2049 bytes, written honestly: over the limit */
		{
			static uint8_t big[2400];

			n = trep_build(&t, big, sizeof(big));
			WRT_CHECK_STATUS(WR_E_OSD_PROTO, dec(big, n, 8, 2, &r));
		}
	}
	/* the pg_t version byte */
	for (i = 0; i < 256; i += 17) {
		if (i == 1)
			continue;
		t = trep_init();
		t.pg_ver = (uint8_t)i;
		n = trep_build(&t, b, sizeof(b));
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, dec(b, n, 8, 2, &r));
	}
	/* the trace block must be there; a short one is refused, an extra tail is not */
	for (i = 0; i < 24; i++) {
		t = trep_init();
		t.trace = i;
		n = trep_build(&t, b, sizeof(b));
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, dec(b, n, 8, 2, &r));
	}
	t = trep_init();
	t.extra = 40;
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, dec(b, n, 8, 2, &r));

	/* a redirect whose body is cut, whose length lies, or that needs a newer reader */
	t = trep_init();
	t.redirect = 1;
	t.redir_len = 20;
	t.redir_have = 10;
	t.trace = 0;
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, dec(b, n, 8, 2, &r));
	t.redir_len = 0xFFFFFFFFu;
	t.redir_have = 30;
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, dec(b, n, 8, 2, &r));
	t = trep_init();
	t.redirect = 1;
	t.redir_len = 4;
	t.redir_have = 4;
	t.redir_compat = 2;
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, dec(b, n, 8, 2, &r));
	WRT_CHECK(all_zero(&r, sizeof(r)));
	/* a redirect that eats into the trace block leaves too little behind */
	t = trep_init();
	t.redirect = 1;
	t.redir_len = 30;
	t.redir_have = 6; /* the next 24 trace bytes complete the body: nothing is left for the trace */
	n = trep_build(&t, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, dec(b, n, 8, 2, &r));

	/* arguments */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mosdopreply_decode(b, 10, 8, 2, NULL));
	memset(&r, 0xEE, sizeof(r));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mosdopreply_decode(NULL, 10, 8, 2, &r));
	WRT_CHECK(all_zero(&r, sizeof(r)));
	memset(&r, 0xEE, sizeof(r));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_mosdopreply_decode(NULL, 0, 8, 2, &r));
	WRT_CHECK(all_zero(&r, sizeof(r)));
	memset(&r, 0xEE, sizeof(r));
	WRT_CHECK_STATUS(WR_E_OSD_VERSION, wri_mosdopreply_decode(NULL, 0, 9, 2, &r)); /* the version is judged first */
	WRT_CHECK(all_zero(&r, sizeof(r)));
}

/* ---- random bytes ----------------------------------------------------------------------------------------------------------------- */

static uint64_t rng_s = 0x1234567887654321ull;

static uint64_t rnd(void)
{
	rng_s ^= rng_s >> 12;
	rng_s ^= rng_s << 25;
	rng_s ^= rng_s >> 27;
	return rng_s * 0x2545F4914F6CDD1Dull;
}

static void test_random_reply(void)
{
	trep t = trep_init();
	uint8_t good[600], b[600];
	size_t n, i;
	unsigned it;
	wri_mosdopreply r;

	t.n_ops = t.n_recs = 3;
	t.plen[0] = 5;
	t.plen[1] = 6;
	t.plen[2] = 7;
	n = trep_build(&t, good, sizeof(good));
	/* flip bytes of a valid reply: the decoder either accepts with the invariants intact or refuses with a clear output */
	for (it = 0; it < 20000; it++) {
		size_t len = n;
		unsigned flips = 1 + (unsigned)(rnd() % 4);
		wr_status st;

		uint8_t *c;

		memcpy(b, good, n);
		for (i = 0; i < flips; i++)
			b[rnd() % n] = (uint8_t)rnd();
		if (rnd() % 4 == 0)
			len = (size_t)(rnd() % (n + 1));
		c = (uint8_t *)malloc(len ? len : 1);
		memcpy(c, b, len);
		memset(&r, 0xEE, sizeof(r));
		st = wri_mosdopreply_decode(c, len, 8, 2, &r);
		if (st == WR_OK) {
			uint64_t total = 0;
			uint32_t k;

			WRT_CHECK(r.n_ops <= WRI_OSD_OPS_MAX && r.oid_len <= WRI_OSD_NAME_LIMIT);
			WRT_CHECK(r.oid >= c && r.oid + r.oid_len <= c + len); /* the name borrows from the input and stays inside it */
			for (k = 0; k < r.n_ops; k++)
				total += r.out_len[k];
			WRT_CHECK(total == r.out_total);
			for (k = r.n_ops; k < WRI_OSD_OPS_MAX; k++)
				WRT_CHECK(r.op_code[k] == 0 && r.out_len[k] == 0 && r.rval[k] == 0);
		} else {
			WRT_CHECK(st == WR_E_OSD_PROTO);
			WRT_CHECK(all_zero(&r, sizeof(r)));
		}
		free(c);
	}
}

/* ---- SPARSE_READ output ------------------------------------------------------------------------------------------------------------ */

typedef struct sp {
	uint8_t b[600];
	size_t n;
} sp;

/* n extents then data_len then `dlen_actual` bytes of data; data_len is written as `dlen_field`. */
static void sp_build(sp *s, uint32_t count_field, uint64_t (*e)[2], uint32_t n_e, uint32_t dlen_field, uint32_t dlen_actual)
{
	buf b;
	uint32_t i;

	b.p = s->b;
	b.n = 0;
	b.cap = sizeof(s->b);
	b_le(&b, count_field, 4);
	for (i = 0; i < n_e; i++) {
		b_le(&b, e[i][0], 8);
		b_le(&b, e[i][1], 8);
	}
	b_le(&b, dlen_field, 4);
	for (i = 0; i < dlen_actual; i++)
		b_u8(&b, (uint8_t)(0x40 + i));
	s->n = b.n;
}

static wr_status sp_dec(const sp *s, uint64_t ro, uint64_t rl, wri_osd_extent *ext, uint32_t emax, uint32_t *ne, uint32_t *doff, uint32_t *dlen)
{
	uint8_t *c = (uint8_t *)malloc(s->n ? s->n : 1);
	wr_status st;

	memcpy(c, s->b, s->n);
	*ne = 0xDEAD;
	*doff = 0xBEEF;
	*dlen = 0xF00D;
	st = wri_osd_sparse_decode(c, (uint32_t)s->n, ro, rl, ext, emax, ne, doff, dlen);
	free(c);
	return st;
}

static void sp_expect_bad(const char *what, const sp *s, uint64_t ro, uint64_t rl, wr_status want)
{
	wri_osd_extent ext[8];
	uint32_t ne, doff, dlen;
	wr_status st;

	memset(ext, 0xEE, sizeof(ext));
	st = sp_dec(s, ro, rl, ext, 8, &ne, &doff, &dlen);
	wrt_checks++;
	if (st != want) {
		wrt_failures++;
		fprintf(stderr, "sparse case \"%s\": returned %d (%s), want %d (%s)\n", what, (int)st, wrt_status_name_(st), (int)want,
			wrt_status_name_(want));
	}
	WRT_CHECK(ne == 0 && doff == 0 && dlen == 0);
}

static void test_sparse(void)
{
	sp s;
	wri_osd_extent ext[8];
	uint32_t ne, doff, dlen;
	uint64_t e1[1][2] = {{4096, 100}};
	uint64_t e3[3][2] = {{4096, 100}, {5000, 50}, {8192, 4096}};
	uint64_t e_adj[2][2] = {{0, 10}, {10, 10}};
	uint64_t e_hole[2][2] = {{0, 10}, {100, 10}};
	uint64_t e_ov[2][2] = {{0, 10}, {9, 10}};
	uint64_t e_same[2][2] = {{0, 10}, {0, 10}};
	uint64_t e_desc[2][2] = {{100, 10}, {0, 10}};
	uint64_t e_before[1][2] = {{4095, 100}};
	uint64_t e_past[1][2] = {{4096 + 65536 - 99, 100}};
	uint64_t e_end[1][2] = {{4096 + 65536 - 100, 100}};
	uint64_t e_wrap[1][2] = {{0xFFFFFFFFFFFFFFF0ull, 0x20}};
	uint64_t e_huge[1][2] = {{4096, 0xFFFFFFFFFFFFFFFFull}};
	uint64_t e_zero[2][2] = {{4096, 0}, {4096, 5}};
	uint64_t e_1[1][2] = {{0, 1}};
	uint64_t e_ten[9][2];
	uint32_t i;
	wr_status st;

	/* one extent: the data starts after the table */
	sp_build(&s, 1, e1, 1, 100, 100);
	WRT_CHECK_STATUS(WR_OK, sp_dec(&s, 4096, 65536, ext, 8, &ne, &doff, &dlen));
	WRT_CHECK(ne == 1 && ext[0].off == 4096 && ext[0].len == 100 && doff == 4 + 16 + 4 && dlen == 100);
	WRT_CHECK(s.b[doff] == 0x40 && s.b[doff + dlen - 1] == 0x40 + 99);
	/* several, with gaps (holes read as zeros) */
	sp_build(&s, 3, e3, 3, 100 + 50 + 4096, 0); /* the table is fine, the data is not there */
	sp_expect_bad("data missing", &s, 4096, 65536, WR_E_OSD_PROTO);
	{
		/* build with real data: 4246 bytes does not fit the small buffer, so use smaller extents */
		uint64_t e[3][2] = {{4096, 10}, {5000, 5}, {8192, 7}};

		sp_build(&s, 3, e, 3, 22, 22);
		WRT_CHECK_STATUS(WR_OK, sp_dec(&s, 4096, 65536, ext, 8, &ne, &doff, &dlen));
		WRT_CHECK(ne == 3 && ext[0].off == 4096 && ext[0].len == 10 && ext[1].off == 5000 && ext[1].len == 5 && ext[2].off == 8192 &&
			  ext[2].len == 7 && doff == 4 + 48 + 4 && dlen == 22);
	}
	/* adjacent extents are disjoint; a gap is a hole */
	sp_build(&s, 2, e_adj, 2, 20, 20);
	WRT_CHECK_STATUS(WR_OK, sp_dec(&s, 0, 20, ext, 8, &ne, &doff, &dlen));
	WRT_CHECK(ne == 2 && ext[1].off == 10);
	sp_build(&s, 2, e_hole, 2, 20, 20);
	WRT_CHECK_STATUS(WR_OK, sp_dec(&s, 0, 110, ext, 8, &ne, &doff, &dlen));
	WRT_CHECK(ne == 2 && ext[1].off == 100);
	/* an empty result: no extents, no data */
	sp_build(&s, 0, NULL, 0, 0, 0);
	WRT_CHECK_STATUS(WR_OK, sp_dec(&s, 0, 4096, ext, 8, &ne, &doff, &dlen));
	WRT_CHECK(ne == 0 && doff == 8 && dlen == 0 && s.n == 8);
	/* a zero length request with no data is fine; one extent in it is not */
	WRT_CHECK_STATUS(WR_OK, sp_dec(&s, 5, 0, ext, 8, &ne, &doff, &dlen));
	sp_build(&s, 1, e_1, 1, 1, 1);
	sp_expect_bad("extent in an empty request", &s, 0, 0, WR_E_OSD_PROTO);
	/* a zero length extent is allowed and adds nothing */
	sp_build(&s, 2, e_zero, 2, 5, 5);
	WRT_CHECK_STATUS(WR_OK, sp_dec(&s, 4096, 100, ext, 8, &ne, &doff, &dlen));
	WRT_CHECK(ne == 2 && dlen == 5);

	/* overlap, repetition, descending order */
	sp_build(&s, 2, e_ov, 2, 20, 20);
	sp_expect_bad("overlap", &s, 0, 100, WR_E_OSD_PROTO);
	sp_build(&s, 2, e_same, 2, 20, 20);
	sp_expect_bad("same extent twice", &s, 0, 100, WR_E_OSD_PROTO);
	sp_build(&s, 2, e_desc, 2, 20, 20);
	sp_expect_bad("descending", &s, 0, 200, WR_E_OSD_PROTO);
	/* outside the request: before it, past its end by one byte, exactly at its end, wrapping, absurdly long */
	sp_build(&s, 1, e_before, 1, 100, 100);
	sp_expect_bad("starts before the request", &s, 4096, 65536, WR_E_OSD_PROTO);
	sp_build(&s, 1, e_past, 1, 100, 100);
	sp_expect_bad("one byte past the end", &s, 4096, 65536, WR_E_OSD_PROTO);
	sp_build(&s, 1, e_end, 1, 100, 100);
	WRT_CHECK_STATUS(WR_OK, sp_dec(&s, 4096, 65536, ext, 8, &ne, &doff, &dlen)); /* ends exactly at the end: inside */
	sp_build(&s, 1, e_wrap, 1, 0x20, 0x20);
	sp_expect_bad("offset + length wraps", &s, 0, 0xFFFFFFFFFFFFFFFFull, WR_E_OSD_PROTO);
	WRT_CHECK_STATUS(WR_OK, sp_dec(&s, 0xFFFFFFFFFFFFFFF0ull, 0x20, ext, 8, &ne, &doff, &dlen)); /* request at the very top, no wrap in the check */
	sp_build(&s, 1, e_huge, 1, 100, 100);
	sp_expect_bad("length 2^64 - 1", &s, 0, 0xFFFFFFFFFFFFFFFFull, WR_E_OSD_PROTO); /* data_len cannot match */
	sp_expect_bad("length above the request", &s, 4096, 65536, WR_E_OSD_PROTO);

	/* the data length must add up exactly */
	sp_build(&s, 1, e1, 1, 99, 100);
	sp_expect_bad("data_len below the extents", &s, 4096, 65536, WR_E_OSD_PROTO);
	sp_build(&s, 1, e1, 1, 101, 100);
	sp_expect_bad("data_len above the extents", &s, 4096, 65536, WR_E_OSD_PROTO);
	sp_build(&s, 1, e1, 1, 100, 99);
	sp_expect_bad("data shorter than data_len", &s, 4096, 65536, WR_E_OSD_PROTO);
	sp_build(&s, 1, e1, 1, 100, 101);
	sp_expect_bad("data longer than data_len", &s, 4096, 65536, WR_E_OSD_PROTO);
	sp_build(&s, 1, e1, 1, 0xFFFFFFFFu, 100);
	sp_expect_bad("data_len 2^32 - 1", &s, 4096, 65536, WR_E_OSD_PROTO);
	sp_build(&s, 0, NULL, 0, 1, 1);
	sp_expect_bad("data without extents", &s, 0, 100, WR_E_OSD_PROTO);

	/* the extent count: a lie in either direction, and the cap */
	sp_build(&s, 2, e1, 1, 100, 100);
	sp_expect_bad("count above the table", &s, 4096, 65536, WR_E_OSD_PROTO);
	sp_build(&s, 0xFFFFFFFFu, e1, 1, 100, 100);
	sp_expect_bad("count 2^32 - 1", &s, 4096, 65536, WR_E_OSD_PROTO);
	sp_build(&s, 0x10000000u, e1, 1, 100, 100);
	sp_expect_bad("count 2^28", &s, 4096, 65536, WR_E_OSD_PROTO);
	sp_build(&s, 1, e3, 3, 100, 100);
	sp_expect_bad("count below the table", &s, 4096, 65536, WR_E_OSD_PROTO);
	for (i = 0; i < 9; i++) {
		e_ten[i][0] = i * 2u;
		e_ten[i][1] = 1;
	}
	sp_build(&s, 9, e_ten, 9, 9, 9);
	WRT_CHECK_STATUS(WR_E_TOOBIG, sp_dec(&s, 0, 100, ext, 8, &ne, &doff, &dlen)); /* nine extents, room for eight */
	{
		wri_osd_extent e9[9];
		wri_osd_extent *e_many = (wri_osd_extent *)malloc(sizeof(wri_osd_extent) * 100);

		WRT_CHECK_STATUS(WR_E_TOOBIG, sp_dec(&s, 0, 100, e9, 8, &ne, &doff, &dlen)); /* more than the caller keeps */
		WRT_CHECK(ne == 0 && doff == 0 && dlen == 0);
		WRT_CHECK_STATUS(WR_OK, sp_dec(&s, 0, 100, e9, 9, &ne, &doff, &dlen));
		WRT_CHECK(ne == 9 && e9[8].off == 16);
		/* the decoder never keeps more than WRI_OSD_SPARSE_EXT_MAX even if the caller offers more room */
		{
			uint64_t big[WRI_OSD_SPARSE_EXT_MAX + 1u][2];
			buf b;

			for (i = 0; i < WRI_OSD_SPARSE_EXT_MAX + 1u; i++) {
				big[i][0] = i * 2u;
				big[i][1] = 1;
			}
			b.p = (uint8_t *)malloc(4 + 16 * (WRI_OSD_SPARSE_EXT_MAX + 1u) + 4 + WRI_OSD_SPARSE_EXT_MAX + 1u);
			b.n = 0;
			b.cap = 4 + 16 * (WRI_OSD_SPARSE_EXT_MAX + 1u) + 4 + WRI_OSD_SPARSE_EXT_MAX + 1u;
			b_le(&b, WRI_OSD_SPARSE_EXT_MAX + 1u, 4);
			for (i = 0; i < WRI_OSD_SPARSE_EXT_MAX + 1u; i++) {
				b_le(&b, big[i][0], 8);
				b_le(&b, big[i][1], 8);
			}
			b_le(&b, WRI_OSD_SPARSE_EXT_MAX + 1u, 4);
			b_zero(&b, WRI_OSD_SPARSE_EXT_MAX + 1u);
			WRT_CHECK_STATUS(WR_E_TOOBIG, wri_osd_sparse_decode(b.p, (uint32_t)b.n, 0, 1000, e_many, 100, &ne, &doff, &dlen));
			/* exactly the cap is fine */
			b.p[0] = (uint8_t)WRI_OSD_SPARSE_EXT_MAX;
			memmove(b.p + 4 + 16 * WRI_OSD_SPARSE_EXT_MAX, b.p + 4 + 16 * (WRI_OSD_SPARSE_EXT_MAX + 1u), 4 + WRI_OSD_SPARSE_EXT_MAX);
			b.p[4 + 16 * WRI_OSD_SPARSE_EXT_MAX] = (uint8_t)WRI_OSD_SPARSE_EXT_MAX;
			WRT_CHECK_STATUS(WR_OK, wri_osd_sparse_decode(b.p, (uint32_t)(4 + 16 * WRI_OSD_SPARSE_EXT_MAX + 4 + WRI_OSD_SPARSE_EXT_MAX), 0, 1000,
								      e_many, 100, &ne, &doff, &dlen));
			WRT_CHECK(ne == WRI_OSD_SPARSE_EXT_MAX);
			free(b.p);
		}
		free(e_many);
	}

	/* truncation at every offset of a good output (the last cut that still parses is the full length) */
	{
		uint64_t e[3][2] = {{4096, 10}, {5000, 5}, {8192, 7}};
		size_t cut;

		sp_build(&s, 3, e, 3, 22, 22);
		for (cut = 0; cut < s.n; cut++) {
			sp t = s;

			t.n = cut;
			sp_expect_bad("cut", &t, 4096, 65536, WR_E_OSD_PROTO);
		}
		/* and with one byte of garbage after the data */
		{
			sp t = s;

			t.b[t.n++] = 0;
			sp_expect_bad("trailing byte", &t, 4096, 65536, WR_E_OSD_PROTO);
		}
	}

	/* the failed decode leaves the extents it had filled cleared */
	{
		uint64_t e[3][2] = {{0, 10}, {20, 10}, {5, 10}};

		sp_build(&s, 3, e, 3, 30, 30);
		memset(ext, 0xEE, sizeof(ext));
		st = sp_dec(&s, 0, 100, ext, 8, &ne, &doff, &dlen);
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, st);
		for (i = 0; i < 3; i++)
			WRT_CHECK(ext[i].off == 0 && ext[i].len == 0);
	}

	/* arguments */
	sp_build(&s, 0, NULL, 0, 0, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sparse_decode(s.b, 8, 0, 10, ext, 8, NULL, &doff, &dlen));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sparse_decode(s.b, 8, 0, 10, ext, 8, &ne, NULL, &dlen));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sparse_decode(s.b, 8, 0, 10, ext, 8, &ne, &doff, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sparse_decode(s.b, 8, 0, 10, NULL, 8, &ne, &doff, &dlen));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sparse_decode(NULL, 8, 0, 10, ext, 8, &ne, &doff, &dlen));
	WRT_CHECK_STATUS(WR_OK, wri_osd_sparse_decode(s.b, 8, 0, 10, NULL, 0, &ne, &doff, &dlen)); /* no extents: no array needed */
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_osd_sparse_decode(NULL, 0, 0, 10, ext, 8, &ne, &doff, &dlen));
}

/* The captured SPARSE_READ reply (vector 08): the table at its head is the real one, the data is the lab pattern. */
static void test_sparse_vector(void)
{
	rig_vec v;
	wrt_tok d;
	uint8_t *head = NULL, *out;
	size_t hn = 0, total = 65560;
	wri_osd_extent ext[4];
	uint32_t ne, doff, dlen;

	if (rig_vec_load(&v, "08-rbd-sparse-read-64k.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	d = wrt_json_get(&v.j, v.rep, "data");
	WRT_CHECK(wrt_json_get_hex(&v.j, d, "head_hex", &head, &hn) == 0 && hn >= 24);
	WRT_CHECK_U64(v.rep_data_len, total);
	if (head != NULL && hn >= 24) {
		out = (uint8_t *)malloc(total);
		memset(out, 0x53, total);
		memcpy(out, head, 24);
		WRT_CHECK_STATUS(WR_OK, wri_osd_sparse_decode(out, (uint32_t)total, 0, 65536, ext, 4, &ne, &doff, &dlen));
		WRT_CHECK(ne == 1 && ext[0].off == 0 && ext[0].len == 65536 && doff == 24 && dlen == 65536);
		/* the same output asked for a smaller range is outside it */
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_osd_sparse_decode(out, (uint32_t)total, 0, 65535, ext, 4, &ne, &doff, &dlen));
		free(out);
	}
	free(head);
	rig_vec_free(&v);
}

/* ---- STAT output --------------------------------------------------------------------------------------------------------------------- */

static void test_stat(void)
{
	rig_vec v;
	uint8_t *d = NULL;
	size_t dn = 0, i;
	uint64_t size;
	uint32_t sec, nsec;
	uint8_t b[20];

	/* the captured STAT reply of vector 02 */
	if (rig_vec_load(&v, "02-rados-stat.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	WRT_CHECK(wrt_json_get_hex(&v.j, wrt_json_get(&v.j, v.rep, "data"), "hex", &d, &dn) == 0 && dn == 16);
	if (dn == 16) {
		WRT_CHECK_STATUS(WR_OK, wri_osd_stat_decode(d, 16, &size, &sec, &nsec));
		WRT_CHECK_U64(size, 100);
		WRT_CHECK_U64(sec, 0x6afacc48u);
		WRT_CHECK_U64(nsec, 0x22abe3a0u);
	}
	free(d);
	rig_vec_free(&v);

	/* byte order and width of every field */
	for (i = 0; i < 16; i++)
		b[i] = (uint8_t)(0x10 + i);
	WRT_CHECK_STATUS(WR_OK, wri_osd_stat_decode(b, 16, &size, &sec, &nsec));
	WRT_CHECK_U64(size, 0x1716151413121110ull);
	WRT_CHECK_U64(sec, 0x1B1A1918u);
	WRT_CHECK_U64(nsec, 0x1F1E1D1Cu);
	/* exactly 16 bytes: every other length is refused with the outputs cleared */
	for (i = 0; i <= 20; i++) {
		if (i == 16)
			continue;
		size = 7;
		sec = 7;
		nsec = 7;
		WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_osd_stat_decode(b, (uint32_t)i, &size, &sec, &nsec));
		WRT_CHECK(size == 0 && sec == 0 && nsec == 0);
	}
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_stat_decode(b, 16, NULL, &sec, &nsec));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_stat_decode(b, 16, &size, NULL, &nsec));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_stat_decode(b, 16, &size, &sec, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_stat_decode(NULL, 16, &size, &sec, &nsec));
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, wri_osd_stat_decode(NULL, 0, &size, &sec, &nsec));
}

int main(void)
{
	test_vectors();
	test_synthetic_ok();
	test_synthetic_bad();
	test_random_reply();
	test_sparse();
	test_sparse_vector();
	test_stat();
	return wrt_finish();
}
