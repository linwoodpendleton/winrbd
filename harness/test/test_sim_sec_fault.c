/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the secure-mode peer of the msgr2 test server, part 4: every defect it can put on the wire, seen from the other side.
 *
 * Part 1 is the encoder and the decoder alone: each plaintext-level defect (the tag is right, a rule of the preamble or the epilogue
 * is broken) must come out as the status of that rule and only after the tag of its operation verified; every key, nonce and wire
 * defect (a bit flipped in each region, a tag that belongs to other data, a repeated or skipped nonce, a wrong key) as a tag
 * failure at the right operation; truncation at every byte offset is "need more", never a frame; a decoder that failed stays failed.
 *
 * Part 2 is the simulated server (sim_m2 with scripted auth) in secure mode, observed by the scripted client: the hooks of
 * sim_m2_fault.sec on the server's frames (the signature frame, SERVER_IDENT, messages), the session-level ones (swapped seeds, a
 * wrong key), the hooks of part A in secure mode (corrupt_frame, bad_signature, oversize_frame, out_limit, no_keepalive_ack, send_wait,
 * missing_features), and the other direction: defective frames from the client make the server close with the status of the rule.
 */
#include "sim_sec_cx.h"

static uint8_t g_secret[64];

static void init_secret(void)
{
	unsigned i;

	for (i = 0; i < sizeof(g_secret); i++)
		g_secret[i] = (uint8_t)i;
}

/* ---- part 1: encoder and decoder ----------------------------------------------------------------------------------------------- */

typedef struct shape {
	const char *name;
	uint8_t tag;
	unsigned nseg;
	uint32_t len[4];
} shape;

static const shape k_shapes[] = {
	{"one operation", 7, 1, {32, 0, 0, 0}},
	{"two operations", 17, 4, {20, 70, 0, 350}},
	{"three operations", 17, 4, {105, 70, 0, 350}},
	{"two operations, long segment 0", 8, 1, {123, 0, 0, 0}},
};

typedef struct enc {
	sim_sec_spec sp;
	uint8_t *buf[4];
	uint8_t *wire;
	size_t n;
	unsigned ops;
} enc;

static void enc_make(enc *e, sim_sec_ctx *tx_side, const shape *sh, const sim_sec_mut *m)
{
	unsigned i;
	size_t k, cap;

	memset(e, 0, sizeof(*e));
	e->sp.tag = sh->tag;
	e->sp.nseg = sh->nseg;
	for (i = 0; i < sh->nseg; i++) {
		e->sp.len[i] = sh->len[i];
		e->buf[i] = (uint8_t *)malloc(sh->len[i] != 0 ? sh->len[i] : 1u);
		for (k = 0; k < sh->len[i]; k++)
			e->buf[i][k] = (uint8_t)(0x30u + i * 5u + k * 3u);
		e->sp.seg[i] = sh->len[i] != 0 ? e->buf[i] : NULL;
	}
	cap = sim_sec_frame_len(&e->sp, &e->ops, NULL);
	if (m != NULL && (m->mask & SIM_SEC_M_KEEP_TAIL) != 0 && cap == 0)
		cap = 1;
	e->wire = (uint8_t *)malloc(cap + 4096u);
	WRT_CHECK(sim_sec_encode(&tx_side->tx, &e->sp, m, e->wire, cap + 4096u, &e->n) == 0);
}

static void enc_free(enc *e)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		free(e->buf[i]);
	free(e->wire);
}

/* One frame from the server side to the client side, with a mutation; the decoder's verdict, its error and the operations it used.
 * The frame in *g points into *d: the caller frees d after reading it. */
static int decode_one(const enc *e, sim_sec_ctx *client, uint32_t cap0, uint32_t capn, wr_status *err, uint64_t *ops_used, sim_sec_frame *g,
		      sim_sec_dec *d)
{
	int r;

	sim_sec_dec_init(d, &client->rx, cap0, capn);
	WRT_CHECK(sim_sec_dec_feed(d, e->wire, e->n) == 0);
	r = sim_sec_dec_next(d, g);
	*err = d->err;
	*ops_used = client->rx.ops;
	if (r == SIM_SEC_DEC_ERROR) { /* the failure is sticky: more input, another call, the same answer */
		WRT_CHECK(sim_sec_dec_feed(d, e->wire, e->n) == 0);
		WRT_CHECK(sim_sec_dec_next(d, g) == SIM_SEC_DEC_ERROR && d->err == *err);
		WRT_CHECK(d->why != NULL);
	}
	return r;
}

typedef struct plain_case {
	const char *what;
	sim_sec_mut m;
	wr_status want; /* WR_OK = decodes */
	int multi_only; /* needs a frame with several segments */
	int free_slot;  /* needs a frame with fewer than four segments (an unused slot in the preamble) */
} plain_case;

static void test_plaintext_defects(void)
{
	static plain_case t[12];
	unsigned n = 0, i, s;

#define CASE(w, st, multi, ...)                                  \
	do {                                                     \
		memset(&t[n], 0, sizeof(t[n]));                  \
		t[n].what = (w);                                 \
		t[n].want = (st);                                \
		t[n].multi_only = (multi);                       \
		t[n].m = (sim_sec_mut){__VA_ARGS__};              \
		n++;                                             \
	} while (0)
	CASE("wrong preamble CRC", WR_E_M2_FRAME_CRC, 0, .mask = SIM_SEC_M_PRE_CRC);
	CASE("compressed flag", WR_E_M2_FRAME_FORM, 0, .mask = SIM_SEC_M_FLAGS, .pre_flags = 1);
	CASE("other flag bits", WR_E_M2_FRAME_FORM, 0, .mask = SIM_SEC_M_FLAGS, .pre_flags = 0x80);
	CASE("reserved byte", WR_E_M2_FRAME_FORM, 0, .mask = SIM_SEC_M_RESERVED, .pre_reserved = 1);
	CASE("nseg 0", WR_E_M2_FRAME_FORM, 0, .mask = SIM_SEC_M_PRE_NSEG, .pre_nseg = 0);
	CASE("nseg 5", WR_E_M2_FRAME_FORM, 0, .mask = SIM_SEC_M_PRE_NSEG, .pre_nseg = 5);
	CASE("unknown tag 0", WR_E_M2_TAG, 0, .mask = SIM_SEC_M_PRE_TAG, .pre_tag = 0);
	CASE("unknown tag 23", WR_E_M2_TAG, 0, .mask = SIM_SEC_M_PRE_TAG, .pre_tag = 23);
	CASE("an unused slot in use", WR_E_M2_FRAME_FORM, 0, .mask = SIM_SEC_M_SLOT, .slot_junk = 0x55);
	t[n - 1].free_slot = 1;
	CASE("segment above its cap", WR_E_M2_FRAME_TOOBIG, 0, .mask = SIM_SEC_M_PRE_LEN, .pre_len_mask = 1, .pre_len = {1u << 30, 0, 0, 0});
	CASE("bad epilogue nibble", WR_E_M2_FRAME_FORM, 1, .mask = SIM_SEC_M_LATE, .late_status = 0x05);
	CASE("garbage padding is ignored", WR_OK, 0, .mask = SIM_SEC_M_PAD, .pad_fill = 0xa7);
#undef CASE
	for (s = 0; s < sizeof(k_shapes) / sizeof(k_shapes[0]); s++)
		for (i = 0; i < n; i++) {
			sim_sec_ctx srv, cli;
			enc e;
			sim_sec_frame g;
			wr_status err = WR_OK;
			uint64_t ops = 0;
			int r;
			unsigned multi = k_shapes[s].nseg > 1u;
			sim_sec_dec d1, d2;

			if ((t[i].multi_only && !multi) || (t[i].free_slot && k_shapes[s].nseg == 4u))
				continue;
			WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0 && sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0);
			enc_make(&e, &srv, &k_shapes[s], &t[i].m);
			r = decode_one(&e, &cli, 0x10000u, 0x10000u, &err, &ops, &g, &d1);
			if (t[i].want == WR_OK) {
				WRT_CHECK(r == SIM_SEC_DEC_FRAME);
				if (r == SIM_SEC_DEC_FRAME)
					WRT_CHECK_MEM(g.seg[0], e.sp.seg[0], e.sp.len[0]);
			} else {
				if (r != SIM_SEC_DEC_ERROR || err != t[i].want)
					fprintf(stderr, "case \"%s\" on %s: verdict %d status %d, want %d\n", t[i].what, k_shapes[s].name, r, (int)err,
						(int)t[i].want);
				WRT_CHECK(r == SIM_SEC_DEC_ERROR);
				WRT_CHECK_STATUS(t[i].want, err);
				/* the tag of the operation that carries the preamble verified first: one nonce was taken (the epilogue rule is the last) */
				WRT_CHECK_U64(ops, t[i].want == WR_E_M2_FRAME_FORM && t[i].m.mask == SIM_SEC_M_LATE ? e.ops : 1);
			}
			sim_sec_dec_free(&d1);
			/* the same defect with ONE bit of ciphertext flipped on top is a tag failure, never the status of the rule: the tag comes first */
			{
				sim_sec_mut m2 = t[i].m;
				enc e2;

				m2.mask |= SIM_SEC_M_FLIP;
				m2.flip_part = 1;
				m2.flip_byte = 5;
				sim_sec_ctx_wipe(&srv);
				WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
				sim_sec_ctx_wipe(&cli);
				WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0);
				enc_make(&e2, &srv, &k_shapes[s], &m2);
				r = decode_one(&e2, &cli, 0x10000u, 0x10000u, &err, &ops, &g, &d2);
				WRT_CHECK(r == SIM_SEC_DEC_ERROR);
				WRT_CHECK_STATUS(WR_E_M2_SEC_TAG, err);
				sim_sec_dec_free(&d2);
				enc_free(&e2);
			}
			enc_free(&e);
		}
	/* late_status 1 is an aborted frame (tags verified, content to be dropped); 0xfe has the right low nibble: complete */
	for (s = 1; s < 3; s++) {
		static const uint8_t late[2] = {SIM_SEC_LATE_ABORTED, 0xfe};
		unsigned k;

		for (k = 0; k < 2; k++) {
			sim_sec_ctx srv, cli;
			sim_sec_mut m;
			enc e;
			sim_sec_frame g;
			wr_status err = WR_OK;
			uint64_t ops = 0;
			sim_sec_dec d;

			memset(&m, 0, sizeof(m));
			m.mask = SIM_SEC_M_LATE;
			m.late_status = late[k];
			WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0 && sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0);
			enc_make(&e, &srv, &k_shapes[s], &m);
			WRT_CHECK(decode_one(&e, &cli, 0, 0, &err, &ops, &g, &d) == (k == 0 ? SIM_SEC_DEC_ABORTED : SIM_SEC_DEC_FRAME));
			WRT_CHECK_U64(ops, e.ops); /* every operation was done, every tag verified, the nonces advanced */
			WRT_CHECK_U64(g.late_status, late[k]);
			sim_sec_dec_free(&d);
			enc_free(&e);
		}
	}
	/* a preamble that announces no segment at all (or five), with every length AND alignment zero so that no "unused slot in use" rule can catch it
	 * first: the rule on the number of segments alone. Built by hand (the encoder always writes the alignment of segment 0), sealed under a
	 * right tag. */
	{
		static const uint8_t counts[2] = {0, 5};
		unsigned k;

		for (k = 0; k < 2; k++) {
			sim_sec_ctx srv, cli;
			sim_sec_frame g;
			sim_sec_dec d;
			uint8_t plain[80], wire[96];
			uint32_t crc;

			memset(plain, 0, sizeof(plain));
			plain[0] = 7; /* a tag the decoder knows */
			plain[1] = counts[k];
			crc = sim_sec_crc32c(0, plain, 28);
			plain[28] = (uint8_t)crc, plain[29] = (uint8_t)(crc >> 8), plain[30] = (uint8_t)(crc >> 16), plain[31] = (uint8_t)(crc >> 24);
			WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0 && sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0);
			WRT_CHECK(sim_sec_seal(&srv.tx, plain, sizeof(plain), wire) == 0);
			sim_sec_dec_init(&d, &cli.rx, 0, 0);
			WRT_CHECK(sim_sec_dec_feed(&d, wire, sizeof(wire)) == 0);
			WRT_CHECK(sim_sec_dec_next(&d, &g) == SIM_SEC_DEC_ERROR);
			WRT_CHECK_STATUS(WR_E_M2_FRAME_FORM, d.err);
			WRT_CHECK_U64(cli.rx.ops, 1); /* the tag verified first */
			sim_sec_dec_free(&d);
		}
	}
	/* an empty last segment on the wire (the sender must drop it): a right tag, a malformed frame */
	{
		sim_sec_ctx srv, cli;
		sim_sec_mut m;
		enc e;
		sim_sec_frame g;
		wr_status err = WR_OK;
		uint64_t ops = 0;
		sim_sec_dec d;
		static const shape sh = {"empty last", 17, 3, {20, 30, 0, 0}};

		memset(&m, 0, sizeof(m));
		m.mask = SIM_SEC_M_KEEP_TAIL;
		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0 && sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0);
		enc_make(&e, &srv, &sh, &m);
		WRT_CHECK(decode_one(&e, &cli, 0, 0, &err, &ops, &g, &d) == SIM_SEC_DEC_ERROR);
		WRT_CHECK_STATUS(WR_E_M2_FRAME_FORM, err);
		sim_sec_dec_free(&d);
		enc_free(&e);
	}
}

/* Key, nonce, wire defects: a tag failure at the operation that carries them; the operations before it were fine. */
static void test_wire_defects(void)
{
	static const struct {
		const char *what;
		sim_sec_mut m;
		unsigned part; /* the 1-based operation whose tag must fail */
	} t[] = {
		{"flip in the preamble ciphertext", {.mask = SIM_SEC_M_FLIP, .flip_part = 1, .flip_byte = 3}, 1},
		{"flip in the inline bytes", {.mask = SIM_SEC_M_FLIP, .flip_part = 1, .flip_byte = 79, .flip_bit = 7}, 1},
		{"flip in tag 1", {.mask = SIM_SEC_M_FLIP, .flip_part = 1, .flip_region = SIM_SEC_R_TAG, .flip_byte = 15}, 1},
		{"wrong tag 1", {.mask = SIM_SEC_M_TAG, .tag_part = 1}, 1},
		{"a wrong key", {.mask = SIM_SEC_M_KEY}, 1},
		{"a repeated nonce at part 1", {.mask = SIM_SEC_M_NONCE, .nonce_delta = -1}, 1},
		{"a skipped nonce at part 1", {.mask = SIM_SEC_M_NONCE, .nonce_delta = 1}, 1},
		{"flip in part 2", {.mask = SIM_SEC_M_FLIP, .flip_part = 2, .flip_byte = 0}, 2},
		{"flip in tag 2", {.mask = SIM_SEC_M_FLIP, .flip_part = 2, .flip_region = SIM_SEC_R_TAG, .flip_byte = 0}, 2},
		{"wrong tag 2", {.mask = SIM_SEC_M_TAG, .tag_part = 2}, 2},
		{"a repeated nonce at part 2", {.mask = SIM_SEC_M_NONCE, .nonce_part = 2, .nonce_delta = -1}, 2},
		{"flip in part 3", {.mask = SIM_SEC_M_FLIP, .flip_part = 3, .flip_byte = 40}, 3},
		{"flip in the epilogue block", {.mask = SIM_SEC_M_FLIP, .flip_part = 3, .flip_region = SIM_SEC_R_EPILOGUE, .flip_byte = 0}, 3},
		{"flip in tag 3", {.mask = SIM_SEC_M_FLIP, .flip_part = 3, .flip_region = SIM_SEC_R_TAG, .flip_byte = 8}, 3},
		{"wrong tag 3", {.mask = SIM_SEC_M_TAG, .tag_part = 3}, 3},
		{"a skipped nonce at part 3", {.mask = SIM_SEC_M_NONCE, .nonce_part = 3, .nonce_delta = 5}, 3},
	};
	unsigned i, s, bits_ok = 0;

	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		/* the shape with three operations holds every part (len_0 = 105, then segments, then the epilogue) */
		sim_sec_ctx srv, cli;
		enc e;
		sim_sec_frame g;
		wr_status err = WR_OK;
		uint64_t ops = 0;
		int r;
		sim_sec_dec d;

		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0 && sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0);
		enc_make(&e, &srv, &k_shapes[2], &t[i].m);
		r = decode_one(&e, &cli, 0, 0, &err, &ops, &g, &d);
		if (r != SIM_SEC_DEC_ERROR)
			fprintf(stderr, "wire defect \"%s\": verdict %d\n", t[i].what, r);
		WRT_CHECK(r == SIM_SEC_DEC_ERROR);
		WRT_CHECK_STATUS(WR_E_M2_SEC_TAG, err);
		WRT_CHECK_U64(ops, t[i].part); /* the nonces of the operations up to the failing one were taken, none after it */
		sim_sec_dec_free(&d);
		enc_free(&e);
	}
	/* every single bit of a one-operation frame and of a two-operation frame: a tag failure, never a frame */
	for (s = 0; s < 2; s++) {
		const shape *sh = &k_shapes[s == 0 ? 0 : 1];
		sim_sec_ctx srv0;
		enc ref;
		size_t bit;

		WRT_CHECK(sim_sec_ctx_init(&srv0, g_secret, 64, 1) == 0);
		enc_make(&ref, &srv0, sh, NULL);
		for (bit = 0; bit < (s == 0 ? ref.n : 96u + 32u + 80u) * 8u; bit++) { /* all of frame 1, the first 208 bytes of the other */
			sim_sec_ctx cli;
			sim_sec_dec d;
			sim_sec_frame g;
			uint8_t *w = (uint8_t *)malloc(ref.n);
			int r;

			memcpy(w, ref.wire, ref.n);
			w[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
			WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0);
			sim_sec_dec_init(&d, &cli.rx, 0, 0);
			WRT_CHECK(sim_sec_dec_feed(&d, w, ref.n) == 0);
			r = sim_sec_dec_next(&d, &g);
			if (r == SIM_SEC_DEC_ERROR && d.err == WR_E_M2_SEC_TAG)
				bits_ok++;
			else
				fprintf(stderr, "bit %zu of %s: verdict %d status %d\n", bit, sh->name, r, (int)d.err);
			sim_sec_dec_free(&d);
			sim_sec_ctx_wipe(&cli);
			free(w);
		}
		enc_free(&ref);
	}
	WRT_CHECK_U64(bits_ok, 96u * 8u + (96u + 32u + 80u) * 8u);
}

/* Truncation at every byte: need more, never a frame; the rest of the bytes complete it. */
static void test_truncation(void)
{
	unsigned s;

	for (s = 0; s < sizeof(k_shapes) / sizeof(k_shapes[0]); s++) {
		sim_sec_ctx srv0;
		enc ref;
		size_t cut;

		WRT_CHECK(sim_sec_ctx_init(&srv0, g_secret, 64, 1) == 0);
		enc_make(&ref, &srv0, &k_shapes[s], NULL);
		for (cut = 0; cut < ref.n; cut++) {
			sim_sec_ctx cli;
			sim_sec_dec d;
			sim_sec_frame g;

			WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0);
			sim_sec_dec_init(&d, &cli.rx, 0, 0);
			WRT_CHECK(sim_sec_dec_feed(&d, ref.wire, cut) == 0);
			WRT_CHECK(sim_sec_dec_next(&d, &g) == SIM_SEC_DEC_NEED);
			WRT_CHECK_U64(d.err, 0);
			WRT_CHECK(sim_sec_dec_feed(&d, ref.wire + cut, ref.n - cut) == 0);
			WRT_CHECK(sim_sec_dec_next(&d, &g) == SIM_SEC_DEC_FRAME);
			WRT_CHECK_U64(g.wire, ref.n);
			sim_sec_dec_free(&d);
			sim_sec_ctx_wipe(&cli);
		}
		enc_free(&ref);
	}
	/* the encoder's own truncation hook: only the first N bytes come out, for every N up to the frame length */
	{
		sim_sec_ctx srv0;
		enc ref;
		size_t cut;

		WRT_CHECK(sim_sec_ctx_init(&srv0, g_secret, 64, 1) == 0);
		enc_make(&ref, &srv0, &k_shapes[2], NULL);
		for (cut = 0; cut <= ref.n + 1u; cut += 37) {
			sim_sec_ctx s2;
			sim_sec_mut m;
			enc e;

			memset(&m, 0, sizeof(m));
			m.mask = SIM_SEC_M_TRUNC;
			m.truncate_at = (uint32_t)cut;
			WRT_CHECK(sim_sec_ctx_init(&s2, g_secret, 64, 1) == 0);
			enc_make(&e, &s2, &k_shapes[2], &m);
			WRT_CHECK_U64(e.n, cut < ref.n ? cut : ref.n);
			WRT_CHECK_MEM(e.wire, ref.wire, e.n);
			enc_free(&e);
		}
		enc_free(&ref);
	}
	/* a mutation that names a part the frame does not have is refused (and the stream is not stepped) */
	{
		sim_sec_ctx srv;
		sim_sec_mut m;
		enc dummy;
		uint8_t buf[512];
		size_t n = 0;
		sim_sec_spec sp;
		uint8_t seg[32] = {0};
		uint64_t before;

		memset(&sp, 0, sizeof(sp));
		sp.tag = 7, sp.nseg = 1, sp.len[0] = 32, sp.seg[0] = seg;
		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
		before = sim_sec_dir_counter(&srv.tx);
		memset(&m, 0, sizeof(m));
		m.mask = SIM_SEC_M_FLIP;
		m.flip_part = 3; /* a one-segment frame has no part 3 */
		WRT_CHECK(sim_sec_encode(&srv.tx, &sp, &m, buf, sizeof(buf), &n) == -1);
		m.flip_part = 1;
		m.flip_byte = 96; /* past the part */
		WRT_CHECK(sim_sec_encode(&srv.tx, &sp, &m, buf, sizeof(buf), &n) == -1);
		m.mask = 0;
		WRT_CHECK(sim_sec_encode(&srv.tx, &sp, &m, buf, 95, &n) == -1); /* buffer too small */
		WRT_CHECK_U64(sim_sec_dir_counter(&srv.tx), before);
		WRT_CHECK_U64(srv.tx.ops, 0);
		(void)dummy;
	}
}

/* ---- part 2: the simulated server ------------------------------------------------------------------------------------------------- */

typedef struct rig {
	sim_m2 *s;
	sim_m2_auth_script sc;
	sim_m2_auth_ops ops;
	stc c;
	tlogin L;
} rig;

static const uint8_t k_key[32] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
				  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf};

/* The server up to AUTH_DONE (secure): HELLO is frame 1, AUTH_DONE 2; then the server's signature is 3, SERVER_IDENT 4, its first message 5. */
static void rig_open(rig *r, const sim_m2_cfg *cfg_in)
{
	sim_m2_cfg cfg;
	static const uint32_t sec[] = {2};
	tlogin *L = &r->L;
	stc_rd rd;

	memset(r, 0, sizeof(*r));
	if (cfg_in != NULL)
		cfg = *cfg_in;
	else
		sim_m2_cfg_default(&cfg);
	cfg.sec.issue_at_done = 1; /* the scripted callbacks never ask for the secret: issue it at AUTH_DONE */
	r->sc.done_len = 4;
	memcpy(r->sc.done_payload, "done", 4);
	memcpy(r->sc.key, k_key, 32);
	r->sc.key_len = 32;
	sim_m2_auth_script_ops(&r->ops, &r->sc);
	r->s = sim_m2_new(&cfg, &r->ops);
	WRT_CHECK(r->s != NULL);
	if (r->s == NULL)
		exit(1);
	stc_init_m2(&r->c, r->s);
	WRT_CHECK(tc_connect(&r->c, L) == 1);
	WRT_CHECK(stc_auth_request(&r->c, 2, sec, 1, (const uint8_t *)"req", 3) == 0);
	WRT_CHECK(tc_next_auth(&r->c, L) == 6);
	rd_init(&rd, r->c.seg[0].p, r->c.seg[0].n);
	L->gid = rd64(&rd);
	L->mode = rd32(&rd);
	r->c.log_on = 0;
	L->have_secret = 1;
	L->secret_len = r->s->sec.secret_len;
	memcpy(L->secret, r->s->sec.secret, L->secret_len);
	L->key.type = 2;
	L->key.len = 32;
	memcpy(L->key.s, k_key, 32);
	L->outcome = TL_OK;
	WRT_CHECK_U64(L->mode, 2);
}

static void rig_free(rig *r)
{
	stc_free(&r->c);
	sim_m2_free(r->s);
}

static int rig_up(rig *r)
{
	return tc_finish(&r->c, &r->L, 1);
}

/* The client sends one frame with a mutation through its own encoder. */
static void send_mut(rig *r, uint8_t tag, const uint8_t *p, uint32_t n, const sim_sec_mut *m)
{
	sim_sec_spec sp;
	uint8_t *w;
	size_t cap, got = 0;

	memset(&sp, 0, sizeof(sp));
	sp.tag = tag;
	sp.nseg = 1;
	sp.seg[0] = p;
	sp.len[0] = n;
	cap = sim_sec_frame_len(&sp, NULL, NULL);
	w = (uint8_t *)malloc(cap);
	WRT_CHECK(sim_sec_encode(&r->c.ctx.tx, &sp, m, w, cap, &got) == 0);
	stc_put(&r->c, w, got);
	free(w);
}

typedef struct hook_case {
	const char *what;
	uint32_t frame;      /* the server frame the hook is on */
	sim_sec_mut m;
	wr_status want;      /* what the client's decoder must say at that frame */
} hook_case;

static void apply(sim_m2_cfg *cfg, const hook_case *h)
{
	sim_m2_cfg_default(cfg);
	cfg->f.sec.mut = h->m;
	cfg->f.sec.mut_frame = h->frame;
}

/* The hooks on the server's frames: the signature (3), SERVER_IDENT (4) and a message (5). Frame 3 fails inside the signature exchange,
 * 4 inside the identification, 5 when the client reads the server's message. */
static void test_server_frames(void)
{
	static const hook_case t[] = {
		{"flip in the signature frame", 3, {.mask = SIM_SEC_M_FLIP, .flip_part = 1, .flip_byte = 40}, WR_E_M2_SEC_TAG},
		{"wrong tag on the signature frame", 3, {.mask = SIM_SEC_M_TAG, .tag_part = 1}, WR_E_M2_SEC_TAG},
		{"a repeated nonce on the signature frame", 3, {.mask = SIM_SEC_M_NONCE, .nonce_delta = -1}, WR_E_M2_SEC_TAG},
		{"a wrong key on SERVER_IDENT", 4, {.mask = SIM_SEC_M_KEY}, WR_E_M2_SEC_TAG},
		{"a wrong preamble CRC on SERVER_IDENT", 4, {.mask = SIM_SEC_M_PRE_CRC}, WR_E_M2_FRAME_CRC},
		{"the compressed flag on SERVER_IDENT", 4, {.mask = SIM_SEC_M_FLAGS, .pre_flags = 1}, WR_E_M2_FRAME_FORM},
		{"a skipped nonce on SERVER_IDENT", 4, {.mask = SIM_SEC_M_NONCE, .nonce_delta = 1}, WR_E_M2_SEC_TAG},
		{"a flip in part 2 of SERVER_IDENT (123 bytes)", 4, {.mask = SIM_SEC_M_FLIP, .flip_part = 2, .flip_byte = 20}, WR_E_M2_SEC_TAG},
	};
	unsigned i;

	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		sim_m2_cfg cfg;
		rig r;
		int ok;

		apply(&cfg, &t[i]);
		rig_open(&r, &cfg);
		ok = rig_up(&r);
		WRT_CHECK(!ok);
		WRT_CHECK_STATUS(t[i].want, r.c.err);
		if (t[i].frame == 4)
			WRT_CHECK(r.L.sig_ok && r.L.signed_ok); /* the signatures went by, the identification failed */
		rig_free(&r);
	}
	/* a message: frames 5 and later */
	{
		static const hook_case m[] = {
			{"flip in the message header part", 5, {.mask = SIM_SEC_M_FLIP, .flip_part = 1, .flip_byte = 60}, WR_E_M2_SEC_TAG},
			{"flip in the front (part 3)", 5, {.mask = SIM_SEC_M_FLIP, .flip_part = 3, .flip_byte = 2}, WR_E_M2_SEC_TAG},
			{"flip in the epilogue block", 5, {.mask = SIM_SEC_M_FLIP, .flip_part = 3, .flip_region = SIM_SEC_R_EPILOGUE, .flip_byte = 0},
			 WR_E_M2_SEC_TAG},
			{"flip in the last tag", 5, {.mask = SIM_SEC_M_FLIP, .flip_part = 3, .flip_region = SIM_SEC_R_TAG, .flip_byte = 15}, WR_E_M2_SEC_TAG},
			{"wrong tag on part 3", 5, {.mask = SIM_SEC_M_TAG, .tag_part = 3}, WR_E_M2_SEC_TAG},
			{"a repeated nonce at part 3", 5, {.mask = SIM_SEC_M_NONCE, .nonce_part = 2, .nonce_delta = -1}, WR_E_M2_SEC_TAG},
			{"a wrong key", 5, {.mask = SIM_SEC_M_KEY}, WR_E_M2_SEC_TAG},
			{"a wrong preamble CRC under a right tag", 5, {.mask = SIM_SEC_M_PRE_CRC}, WR_E_M2_FRAME_CRC},
			{"the compressed flag", 5, {.mask = SIM_SEC_M_FLAGS, .pre_flags = 1}, WR_E_M2_FRAME_FORM},
			{"nseg 5", 5, {.mask = SIM_SEC_M_PRE_NSEG, .pre_nseg = 5}, WR_E_M2_FRAME_FORM},
			{"a bad epilogue nibble", 5, {.mask = SIM_SEC_M_LATE, .late_status = 0x0c}, WR_E_M2_FRAME_FORM},
		};

		for (i = 0; i < sizeof(m) / sizeof(m[0]); i++) {
			sim_m2_cfg cfg;
			rig r;
			static const uint8_t front[20] = {1, 2, 3};

			apply(&cfg, &m[i]);
			rig_open(&r, &cfg);
			WRT_CHECK(rig_up(&r) == 1);
			WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 7, 1, 1, front, sizeof(front), NULL, 0, NULL, 0));
			WRT_CHECK(stc_recv(&r.c) == -1);
			WRT_CHECK_STATUS(m[i].want, r.c.err);
			rig_free(&r);
		}
	}
	/* an empty trailing segment that the hook keeps on the wire (a real sender drops it): the unmutated frame is one operation of 96 bytes, the
	 * mutated one has an epilogue and a third part, 32 bytes more; the server must size its buffer for the frame it builds, then the client
	 * rejects it behind the right tags (the rule: the last segment of a frame with several is not empty) */
	{
		hook_case h = {"empty tail kept", 5, {.mask = SIM_SEC_M_KEEP_TAIL}, WR_E_M2_FRAME_FORM};
		sim_m2_cfg cfg;
		rig r;
		static const uint8_t stamp[8] = {1, 2, 3, 4, 5, 6, 7, 8};
		wri_m2_seg_src sg[2];
		size_t before;

		apply(&cfg, &h);
		rig_open(&r, &cfg);
		WRT_CHECK(rig_up(&r) == 1);
		memset(sg, 0, sizeof(sg));
		sg[0].p = stamp;
		sg[0].len = sizeof(stamp);
		before = sim_m2_pending(r.s);
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_frame(r.s, 18, sg, 2)); /* KEEPALIVE2 with an empty second segment */
		WRT_CHECK_U64(sim_m2_pending(r.s) - before, 96u + 32u);
		WRT_CHECK(stc_recv(&r.c) == -1);
		WRT_CHECK_STATUS(h.want, r.c.err);
		rig_free(&r);
	}
	/* late_status = 1: the client's decoder reports the frame as aborted, nothing is lost, the next frame decodes (nonces advanced) */
	{
		hook_case h = {"aborted", 5, {.mask = SIM_SEC_M_LATE, .late_status = SIM_SEC_LATE_ABORTED}, WR_OK};
		sim_m2_cfg cfg;
		rig r;
		static const uint8_t front[20] = {1, 2, 3};

		apply(&cfg, &h);
		rig_open(&r, &cfg);
		WRT_CHECK(rig_up(&r) == 1);
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 7, 1, 1, front, sizeof(front), NULL, 0, NULL, 0));
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_keepalive(r.s, 5, 6));
		WRT_CHECK(stc_recv(&r.c) == 1 && r.c.tag == 17 && r.c.late == SIM_SEC_LATE_ABORTED);
		WRT_CHECK(stc_recv(&r.c) == 1 && r.c.tag == 18 && r.c.len[0] == 8);
		rig_free(&r);
	}
}

/* The session-level hooks: swapped seeds, a wrong key, a frame cut short (stall and close), the counters near the wrap. */
static void test_session_hooks(void)
{
	sim_m2_cfg cfg;
	rig r;
	uint8_t buf[256];
	size_t got, total;

	/* the server sends with the client's own seed: its first secure frame (the signature) does not verify */
	sim_m2_cfg_default(&cfg);
	cfg.f.sec.wrong_seed_tx = 1;
	rig_open(&r, &cfg);
	WRT_CHECK(rig_up(&r) == 0);
	WRT_CHECK_STATUS(WR_E_M2_SEC_TAG, r.c.err);
	rig_free(&r);
	/* ... and the same stream of nonces as the client's: its frame number one repeats the client's nonce */
	sim_m2_cfg_default(&cfg);
	cfg.f.sec.wrong_key_tx = 1;
	rig_open(&r, &cfg);
	WRT_CHECK(rig_up(&r) == 0);
	WRT_CHECK_STATUS(WR_E_M2_SEC_TAG, r.c.err);
	rig_free(&r);
	/* the server reads with the wrong seed: it cannot read the client's signature, closes with a tag failure and says nothing */
	sim_m2_cfg_default(&cfg);
	cfg.f.sec.wrong_seed_rx = 1;
	rig_open(&r, &cfg);
	WRT_CHECK(rig_up(&r) == 0);
	WRT_CHECK_STATUS(WR_E_M2_SEC_TAG, sim_m2_error(r.s)->status);
	stc_pull(&r.c);
	WRT_CHECK(r.c.eof);
	rig_free(&r);

	/* a frame cut short: stall (the stream just stops) or EOF (mut_close) */
	for (got = 0; got < 2; got++) {
		static const uint8_t front[60] = {1, 2, 3};
		int rc;

		sim_m2_cfg_default(&cfg);
		cfg.f.sec.mut_frame = 5;
		cfg.f.sec.mut.mask = SIM_SEC_M_TRUNC;
		cfg.f.sec.mut.truncate_at = 150;
		cfg.f.sec.mut_close = (uint8_t)got;
		rig_open(&r, &cfg);
		WRT_CHECK(rig_up(&r) == 1);
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 7, 1, 1, front, sizeof(front), NULL, 0, NULL, 0));
		rc = stc_recv(&r.c);
		WRT_CHECK_U64(rc, 0); /* not a frame, not an error: the rest never comes */
		WRT_CHECK_U64(sim_sec_dec_buffered(&r.c.dec), 54); /* 150 bytes arrived, the 96 of part 1 are decoded and waiting for part 3 */
		stc_pull(&r.c);
		WRT_CHECK_U64(r.c.eof, got);
		/* nothing more can be sent on a stalled stream */
		if (got == 0)
			WRT_CHECK_STATUS(WR_OK, sim_m2_send_keepalive(r.s, 1, 1));
		stc_pull(&r.c);
		WRT_CHECK_U64(sim_sec_dec_buffered(&r.c.dec), 54);
		rig_free(&r);
	}
	(void)buf;
	(void)total;

	/* the nonce counter near the wrap: the server's tx counter starts two operations below 2^64, a session goes through it */
	sim_m2_cfg_default(&cfg);
	cfg.f.sec.has_ctr_a = 1;
	cfg.f.sec.ctr_a = 0xfffffffffffffffeull;
	rig_open(&r, &cfg);
	WRT_CHECK(rig_up(&r) == 1); /* signature (counter ...fe), SERVER_IDENT (...ff and 0, 2 operations: part 2 comes after the wrap) */
	{
		static const uint8_t front[20] = {1, 2, 3};
		unsigned i;

		for (i = 0; i < 4; i++) {
			WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 7, 1, 1, front, sizeof(front), NULL, 0, NULL, 0));
			WRT_CHECK(stc_recv(&r.c) == 1 && r.c.tag == 17);
		}
		WRT_CHECK(sim_sec_dir_counter(&r.s->sec.ctx.tx) < 16);
		WRT_CHECK_U64(r.c.err, 0);
	}
	rig_free(&r);
}

/* The hooks of part A, in secure mode. */
static void test_part_a_hooks(void)
{
	sim_m2_cfg cfg;
	rig r;
	static const uint8_t front[20] = {1, 2, 3};
	unsigned i;

	/* corrupt_frame: the three places it knows, as ciphertext damage on a message frame (a tag failure) */
	for (i = 0; i < 3; i++) {
		sim_m2_cfg_default(&cfg);
		cfg.f.corrupt_frame = 5;
		cfg.f.corrupt_part = (uint8_t)i; /* PREAMBLE, SEG0, EPILOGUE */
		rig_open(&r, &cfg);
		WRT_CHECK(rig_up(&r) == 1);
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 7, 1, 1, front, sizeof(front), NULL, 0, NULL, 0));
		WRT_CHECK(stc_recv(&r.c) == -1);
		WRT_CHECK_STATUS(WR_E_M2_SEC_TAG, r.c.err);
		rig_free(&r);
	}
	/* bad_signature: the frame decodes (it is authentic), the HMAC inside differs */
	sim_m2_cfg_default(&cfg);
	cfg.f.bad_signature = 1;
	rig_open(&r, &cfg);
	WRT_CHECK(rig_up(&r) == 0);
	WRT_CHECK(r.L.signed_ok == 1 && !r.L.sig_ok); /* both frames went by, the server's HMAC does not verify */
	WRT_CHECK_U64(r.c.err, 0);
	rig_free(&r);
	/* oversize_frame: an authentic part 1 that claims more than the reader's cap, decided only after its tag */
	sim_m2_cfg_default(&cfg);
	cfg.f.oversize_frame = 5;
	cfg.f.oversize_len = 1u << 30;
	rig_open(&r, &cfg);
	WRT_CHECK(rig_up(&r) == 1);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 7, 1, 1, front, sizeof(front), NULL, 0, NULL, 0));
	r.c.dec.capn = 1u << 20;
	WRT_CHECK(stc_recv(&r.c) == -1);
	WRT_CHECK_STATUS(WR_E_M2_FRAME_TOOBIG, r.c.err);
	rig_free(&r);
	/* out_limit: the stream stops at an exact byte (stall) or ends (close); the secure frames before it are whole */
	for (i = 0; i < 2; i++) {
		sim_m2_cfg_default(&cfg);
		cfg.f.out_limit = 26 + 72 + 100 /* banner, HELLO, AUTH_DONE (crc) ... */ + 96 + 100;
		cfg.f.out_limit_close = (uint8_t)i;
		rig_open(&r, &cfg);
		WRT_CHECK(rig_up(&r) == 0); /* the limit lands inside SERVER_IDENT's bytes or before it: the identification never completes */
		stc_pull(&r.c);
		WRT_CHECK_U64(r.c.eof, i);
		rig_free(&r);
	}
	/* no_keepalive_ack: the keepalive is taken (counted) and not answered */
	sim_m2_cfg_default(&cfg);
	cfg.f.no_keepalive_ack = 1;
	rig_open(&r, &cfg);
	WRT_CHECK(rig_up(&r) == 1);
	{
		uint8_t stamp[8] = {1, 2, 3, 4, 5, 6, 7, 8};

		WRT_CHECK(stc_send1(&r.c, 18, stamp, 8) == 0);
		WRT_CHECK_U64(r.s->n_keepalive, 1);
		WRT_CHECK_U64(stc_recv(&r.c), 0);
	}
	rig_free(&r);
	/* send_wait / missing_features: the answer to CLIENT_IDENT in secure framing (WAIT 16, IDENT_MISSING_FEATURES 10) */
	sim_m2_cfg_default(&cfg);
	cfg.f.send_wait = 1;
	rig_open(&r, &cfg);
	WRT_CHECK(rig_up(&r) == 0);
	WRT_CHECK(r.c.tag == 16 && r.c.err == WR_OK && r.s->state == SIM_M2_ST_REFUSED);
	rig_free(&r);
	sim_m2_cfg_default(&cfg);
	cfg.f.missing_features = 0x1234;
	rig_open(&r, &cfg);
	WRT_CHECK(rig_up(&r) == 0);
	WRT_CHECK(r.c.tag == 10 && r.c.len[0] == 8 && ld32le(r.c.seg[0].p) == 0x1234 && r.s->state == SIM_M2_ST_REFUSED);
	rig_free(&r);
}

/* The other direction: what the server does with defective frames of the client. */
static void test_client_defects(void)
{
	static const struct {
		const char *what;
		sim_sec_mut m;
		wr_status want;
	} t[] = {
		{"a bit flipped", {.mask = SIM_SEC_M_FLIP, .flip_part = 1, .flip_byte = 11}, WR_E_M2_SEC_TAG},
		{"a tag of other data", {.mask = SIM_SEC_M_TAG, .tag_part = 1}, WR_E_M2_SEC_TAG},
		{"a repeated nonce", {.mask = SIM_SEC_M_NONCE, .nonce_delta = -1}, WR_E_M2_SEC_TAG},
		{"a wrong key", {.mask = SIM_SEC_M_KEY}, WR_E_M2_SEC_TAG},
		{"a wrong preamble CRC under a right tag", {.mask = SIM_SEC_M_PRE_CRC}, WR_E_M2_FRAME_CRC},
		{"the compressed flag", {.mask = SIM_SEC_M_FLAGS, .pre_flags = 1}, WR_E_M2_FRAME_FORM},
		{"nseg 0", {.mask = SIM_SEC_M_PRE_NSEG, .pre_nseg = 0}, WR_E_M2_FRAME_FORM},
		{"a segment above the server's cap", {.mask = SIM_SEC_M_PRE_LEN, .pre_len_mask = 1, .pre_len = {1u << 30, 0, 0, 0}}, WR_E_M2_FRAME_TOOBIG},
	};
	unsigned i;
	static const uint8_t ka[8] = {1, 2, 3, 4, 5, 6, 7, 8};

	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		rig r;

		rig_open(&r, NULL);
		WRT_CHECK(rig_up(&r) == 1);
		send_mut(&r, 18, ka, 8, &t[i].m);
		WRT_CHECK_STATUS(t[i].want, sim_m2_error(r.s)->status);
		stc_pull(&r.c);
		WRT_CHECK(r.c.eof); /* the server closed, nothing more to say */
		WRT_CHECK_U64(r.s->n_keepalive, 0);
		rig_free(&r);
	}
	/* a frame the client aborted (late_status 1, only a message has several segments): dropped, the session goes on and the nonces are in step */
	{
		rig r;
		uint8_t h[41] = {0};
		sim_sec_spec sp;
		sim_sec_mut m;
		uint8_t *w;
		size_t cap, got = 0;
		static const uint8_t front[10] = {1, 2, 3};

		rig_open(&r, NULL);
		WRT_CHECK(rig_up(&r) == 1);
		h[0] = 1; /* seq 1 */
		h[16] = 77;
		memset(&sp, 0, sizeof(sp));
		sp.tag = 17, sp.nseg = 2, sp.seg[0] = h, sp.len[0] = 41, sp.seg[1] = front, sp.len[1] = sizeof(front);
		memset(&m, 0, sizeof(m));
		m.mask = SIM_SEC_M_LATE;
		m.late_status = SIM_SEC_LATE_ABORTED;
		cap = sim_sec_frame_len(&sp, NULL, NULL);
		w = (uint8_t *)malloc(cap);
		WRT_CHECK(sim_sec_encode(&r.c.ctx.tx, &sp, &m, w, cap, &got) == 0);
		stc_put(&r.c, w, got);
		free(w);
		WRT_CHECK_U64(r.s->sec.n_aborted, 1);
		WRT_CHECK_U64(r.s->n_msgs, 0);
		WRT_CHECK_U64(sim_m2_error(r.s)->status, 0);
		WRT_CHECK(stc_send_msg(&r.c, 78, 1, front, sizeof(front), NULL, 0, NULL, 0) == 0); /* seq 1 again: the aborted one never counted */
		WRT_CHECK_U64(r.s->n_msgs, 1);
		WRT_CHECK_U64(r.s->msgs[0].type, 78);
		rig_free(&r);
	}
	/* a frame the client's state does not allow (a MESSAGE before CLIENT_IDENT) is a state error, in secure framing too */
	{
		rig r;

		rig_open(&r, NULL);
		WRT_CHECK(stc_go_secure(&r.c, r.L.secret, r.L.secret_len) == 0);
		{
			int ok = 0;

			WRT_CHECK(stc_signatures(&r.c, r.L.key.s, r.L.key.len, &ok) == 1 && ok);
		}
		WRT_CHECK(stc_send_msg(&r.c, 78, 1, ka, 8, NULL, 0, NULL, 0) == 0);
		WRT_CHECK_STATUS(WR_E_M2_STATE, sim_m2_error(r.s)->status);
		rig_free(&r);
	}
}

int main(void)
{
	init_secret();
	test_plaintext_defects();
	test_wire_defects();
	test_truncation();
	test_server_frames();
	test_session_hooks();
	test_part_a_hooks();
	test_client_defects();
	return wrt_finish();
}
