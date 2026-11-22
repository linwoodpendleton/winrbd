/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the secure-mode peer of the test servers (harness/test/support/sim_m2_sec.*), part 1: the primitives, the
 * encoder and the decoder. Nothing here touches the core: the oracle is the committed vectors, the worked frames of
 * msgr2-secure-mode.md 5.2 and the structure of the 80 captured secure connections.
 *
 *   - CRC-32C, nonce stepping, the slicing of the secret (the synthetic secret 00..3f), the two sides of a context;
 *   - the encoder against secure-frames-synthetic.json (both directions, every shape in it) and frames A and B of 5.2 as
 *     printed in the note, and against the encrypted signature frames of pre-auth-tail-synthetic.json;
 *   - the frame size table of primitives.json and the shape of every frame the real peers sent after authentication
 *     (captured-structure.json, secure sessions): wire bytes, number of GCM operations, late_status, alignments;
 *   - the decoder against the same vectors, whole, one byte at a time and at odd splits, and against the encoder on a sweep
 *     of shapes (lengths around 48, 96 and the 16-byte blocks, every segment count) in both directions;
 *   - every defect the encoder can build, as the decoder sees it: the verdict of each one (a tag failure, or, behind a right
 *     tag, the status of the preamble rule that broke), truncation at every byte offset of a frame, and the decoder's own
 *     sticky error;
 *   - the secret log.
 */
#include "wrt.h"

#include "sim_m2_sec.h"

static uint8_t g_secret[64];

static void init_secret(void)
{
	unsigned i;

	for (i = 0; i < sizeof(g_secret); i++)
		g_secret[i] = (uint8_t)i;
}

/* ---- helpers --------------------------------------------------------------------------------------------------------- */

typedef struct fr { /* a frame to encode, with the segment bytes it owns */
	sim_sec_spec sp;
	uint8_t *buf[4];
} fr;

static uint8_t pat(unsigned seg, size_t i) { return (uint8_t)(0x11u * (seg + 1u) + i * 7u + (i >> 8)); }

/* Segments of the given lengths filled with a pattern, or with `fill` when given (fill >= 0). */
static void fr_make(fr *f, uint8_t tag, unsigned nseg, const uint32_t len[4], int fill)
{
	unsigned i;
	size_t k;

	memset(f, 0, sizeof(*f));
	f->sp.tag = tag;
	f->sp.nseg = nseg;
	for (i = 0; i < nseg; i++) {
		f->sp.len[i] = len[i];
		f->buf[i] = (uint8_t *)malloc(len[i] != 0 ? len[i] : 1u);
		for (k = 0; k < len[i]; k++)
			f->buf[i][k] = fill >= 0 ? (uint8_t)fill : pat(i, k);
		f->sp.seg[i] = len[i] != 0 ? f->buf[i] : NULL;
	}
}

static void fr_free(fr *f)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		free(f->buf[i]);
}

/* The decoder's view of a frame must be the encoder's input (the trailing empty segments are gone). */
static void check_frame_eq(const sim_sec_frame *g, const sim_sec_spec *sp)
{
	unsigned n = sp->nseg, i;

	while (n > 1u && sp->len[n - 1u] == 0)
		n--;
	WRT_CHECK_U64(g->tag, sp->tag);
	WRT_CHECK_U64(g->nseg, n);
	for (i = 0; i < n; i++) {
		WRT_CHECK_U64(g->len[i], sp->len[i]);
		WRT_CHECK_U64(g->align[i], sp->align[i] != 0 ? sp->align[i] : (i == 3u ? 4096u : 8u));
		if (sp->len[i] != 0)
			WRT_CHECK_MEM(g->seg[i], sp->seg[i], sp->len[i]);
		WRT_CHECK(g->seg[i] != NULL);
	}
	for (i = n; i < 4u; i++)
		WRT_CHECK(g->seg[i] == NULL && g->len[i] == 0);
	WRT_CHECK_U64(g->flags, 0);
	WRT_CHECK_U64(g->reserved, 0);
}

/* Encode into a malloc'd buffer; returns its length, 0 on failure. */
static size_t enc_alloc(sim_sec_dir *tx, const sim_sec_spec *sp, const sim_sec_mut *m, uint8_t **out)
{
	size_t cap = sim_sec_frame_len(sp, NULL, NULL), n = 0;

	*out = (uint8_t *)malloc(cap != 0 ? cap : 1u);
	if (cap == 0 || sim_sec_encode(tx, sp, m, *out, cap, &n) != 0)
		return 0;
	return n;
}

/* Decode a whole stream fed in pieces of `chunk` bytes (0 = at once), expecting `nframes` frames of `sps`. */
static void decode_stream(sim_sec_dir *rx, const uint8_t *bytes, size_t n, size_t chunk, const sim_sec_spec *sps, unsigned nframes)
{
	sim_sec_dec d;
	sim_sec_frame g;
	size_t at = 0;
	unsigned got = 0;

	sim_sec_dec_init(&d, rx, 0, 0);
	while (at < n || got < nframes) {
		size_t k = chunk == 0 || chunk > n - at ? n - at : chunk;
		int r;

		if (k != 0) {
			WRT_CHECK(sim_sec_dec_feed(&d, bytes + at, k) == 0);
			at += k;
		}
		while ((r = sim_sec_dec_next(&d, &g)) == SIM_SEC_DEC_FRAME) {
			WRT_CHECK(got < nframes);
			if (got < nframes)
				check_frame_eq(&g, &sps[got]);
			got++;
		}
		WRT_CHECK(r == SIM_SEC_DEC_NEED);
		if (r != SIM_SEC_DEC_NEED || (k == 0 && at >= n))
			break;
	}
	WRT_CHECK_U64(got, nframes);
	WRT_CHECK_U64(sim_sec_dec_buffered(&d), 0);
	WRT_CHECK_U64(d.err, 0);
	sim_sec_dec_free(&d);
}

static uint8_t *hexv(const wrt_json *j, wrt_tok obj, const char *key, size_t *n)
{
	uint8_t *b = NULL;

	WRT_CHECK(wrt_json_get_hex(j, obj, key, &b, n) == 0);
	return b;
}

/* ---- primitives ------------------------------------------------------------------------------------------------------ */

static void test_primitives(void)
{
	wrt_json j;
	wrt_tok cr, ns;
	size_t i;
	uint8_t key[16], a[12], b[12], tmp[12];
	sim_sec_ctx cli, srv;
	uint8_t sec2[64];

	WRT_CHECK(wrt_json_load_vec(&j, "secure/primitives.json") == 0);
	cr = wrt_json_get(&j, wrt_json_root(&j), "crc32c");
	for (i = 0; i < wrt_json_count(&j, cr); i++) {
		wrt_tok c = wrt_json_at(&j, cr, i);
		int ok = 0;
		uint8_t *d = NULL;
		size_t n = 0;
		char *as = wrt_json_strdup(&j, wrt_json_get(&j, c, "data_ascii"));
		uint32_t seed = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, c, "seed"), &ok), want;

		want = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, c, "crc"), &ok);
		if (as != NULL) {
			WRT_CHECK_U64(sim_sec_crc32c(seed, (const uint8_t *)as, strlen(as)), want);
			free(as);
		} else {
			WRT_CHECK(wrt_json_get_hex(&j, c, "data_hex", &d, &n) == 0);
			WRT_CHECK_U64(sim_sec_crc32c(seed, d, n), want);
			free(d);
		}
	}
	ns = wrt_json_get(&j, wrt_json_root(&j), "nonce_step");
	for (i = 0; i < wrt_json_count(&j, ns); i++) {
		wrt_tok c = wrt_json_at(&j, ns, i);
		size_t n1, n2;
		uint8_t *s0 = hexv(&j, c, "start_hex", &n1), *s1 = hexv(&j, c, "after_one_step_hex", &n2);

		WRT_CHECK(n1 == 12 && n2 == 12);
		memcpy(tmp, s0, 12);
		sim_sec_nonce_step(tmp);
		WRT_CHECK_MEM(tmp, s1, 12);
		free(s0);
		free(s1);
	}
	wrt_json_free(&j);

	/* the counter wraps at 2^64 without a carry into the fixed field (spec 2.6) */
	memset(tmp, 0xff, 12);
	tmp[0] = 0xaa;
	sim_sec_nonce_step(tmp);
	WRT_CHECK(tmp[0] == 0xaa && tmp[4] == 0 && tmp[11] == 0 && tmp[1] == 0xff);

	/* slicing of the synthetic secret: K = 00..0f, seed A = 10..1b, seed B = 1c..27 */
	WRT_CHECK(sim_sec_slice(g_secret, 64, key, a, b) == 0);
	for (i = 0; i < 16; i++)
		WRT_CHECK_U64(key[i], i);
	for (i = 0; i < 12; i++) {
		WRT_CHECK_U64(a[i], 16 + i);
		WRT_CHECK_U64(b[i], 28 + i);
	}
	WRT_CHECK(sim_sec_slice(g_secret, 39, key, a, b) == -1 && sim_sec_slice(g_secret, 40, NULL, NULL, NULL) == 0);
	WRT_CHECK(sim_sec_slice(NULL, 64, key, a, b) == -1);

	/* the client sends with seed B and reads with seed A; the server is the crossed side */
	WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0 && sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
	WRT_CHECK_MEM(cli.tx.nonce, b, 12);
	WRT_CHECK_MEM(cli.rx.nonce, a, 12);
	WRT_CHECK_MEM(srv.tx.nonce, a, 12);
	WRT_CHECK_MEM(srv.rx.nonce, b, 12);
	WRT_CHECK_MEM(cli.tx.key, srv.tx.key, 16); /* one key, two nonce streams */
	WRT_CHECK(cli.tx.keyed && cli.rx.keyed && srv.tx.keyed && srv.rx.keyed);
	{
		sim_sec_ctx bad;

		WRT_CHECK(sim_sec_ctx_init(&bad, g_secret, 39, 0) == -1 && !bad.tx.keyed);
	}
	/* a counter patched into the secret shows up in the stream; bytes 0..3 of the seed stay */
	memcpy(sec2, g_secret, 64);
	sim_sec_secret_set_counters(sec2, 64, 1, 0xfffffffffffffffeull, 1, 7);
	WRT_CHECK(sim_sec_ctx_init(&srv, sec2, 64, 1) == 0 && sim_sec_ctx_init(&cli, sec2, 64, 0) == 0);
	WRT_CHECK_U64(sim_sec_dir_counter(&srv.tx), 0xfffffffffffffffeull); /* seed A: the server's tx */
	WRT_CHECK_U64(sim_sec_dir_counter(&cli.tx), 7);                     /* seed B: the client's tx */
	WRT_CHECK(srv.tx.nonce[0] == 16 && srv.tx.nonce[3] == 19);
	sim_sec_dir_set_counter(&cli.tx, 99);
	WRT_CHECK_U64(sim_sec_dir_counter(&cli.tx), 99);
	WRT_CHECK(cli.tx.nonce[0] == 28);
	sim_sec_ctx_wipe(&cli);
	WRT_CHECK(cli.tx.key[0] == 0 && cli.tx.nonce[0] == 0 && !cli.tx.keyed);
	sim_sec_ctx_wipe(&srv);
}

/* ---- the encoder against the committed vectors --------------------------------------------------------------------------- */

typedef struct vframe {
	fr f;
	uint8_t *wire;
	size_t wire_len;
	uint8_t *iv;
	size_t iv_len;
	unsigned ops;
} vframe;

/* Read the frames of one direction of secure-frames-synthetic.json. */
static unsigned load_dir(const wrt_json *j, const char *name, vframe *out, unsigned max)
{
	wrt_tok arr = wrt_json_get(j, wrt_json_root(j), name);
	unsigned i, n = (unsigned)wrt_json_count(j, arr);

	WRT_CHECK(n <= max);
	for (i = 0; i < n && i < max; i++) {
		wrt_tok c = wrt_json_at(j, arr, i), segs = wrt_json_get(j, c, "segments"), al = wrt_json_get(j, c, "alignments");
		unsigned k, ns = (unsigned)wrt_json_count(j, segs);
		uint32_t len[4] = {0, 0, 0, 0};
		int fill[4] = {0, 0, 0, 0}, ok = 0;
		vframe *v = &out[i];

		for (k = 0; k < ns && k < 4u; k++) {
			wrt_tok s = wrt_json_at(j, segs, k);

			len[k] = (uint32_t)wrt_json_int(j, wrt_json_get(j, s, "length"), &ok);
			fill[k] = (int)wrt_json_int(j, wrt_json_get(j, s, "fill_byte"), &ok);
		}
		fr_make(&v->f, (uint8_t)wrt_json_int(j, wrt_json_get(j, c, "tag"), &ok), ns, len, 0);
		for (k = 0; k < ns && k < 4u; k++) { /* each segment is one repeated byte in the file */
			memset(v->f.buf[k], fill[k], len[k]);
			v->f.sp.align[k] = (uint16_t)wrt_json_int(j, wrt_json_at(j, al, k < wrt_json_count(j, al) ? k : 0), &ok);
		}
		v->wire = hexv(j, c, "wire_hex", &v->wire_len);
		v->iv = hexv(j, c, "first_iv_hex", &v->iv_len);
		v->ops = (unsigned)wrt_json_int(j, wrt_json_get(j, c, "gcm_operations"), &ok);
	}
	return n;
}

static void free_dir(vframe *v, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		fr_free(&v[i].f);
		free(v[i].wire);
		free(v[i].iv);
	}
}

static void test_synthetic_frames(void)
{
	wrt_json j;
	vframe c2s[16], s2c[16];
	unsigned nc, ns, i;
	sim_sec_ctx cli, srv;
	size_t sec_n;
	uint8_t *sec, *stream_c = NULL, *stream_s = NULL;
	size_t lc = 0, ls = 0;
	sim_sec_spec spc[16], sps[16];
	unsigned ops_c = 0, ops_s = 0;

	WRT_CHECK(wrt_json_load_vec(&j, "secure/secure-frames-synthetic.json") == 0);
	sec = hexv(&j, wrt_json_root(&j), "secret_hex", &sec_n);
	WRT_CHECK(sec_n == 64 && memcmp(sec, g_secret, 64) == 0);
	free(sec);
	nc = load_dir(&j, "client_to_server", c2s, 16);
	ns = load_dir(&j, "server_to_client", s2c, 16);
	WRT_CHECK(nc >= 7 && ns >= 2);
	WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0 && sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
	for (i = 0; i < nc; i++) {
		uint8_t *w = NULL;
		size_t n, parts[3];
		unsigned ops = 0;

		WRT_CHECK_MEM(cli.tx.nonce, c2s[i].iv, 12); /* the IV of the first operation of the frame */
		n = enc_alloc(&cli.tx, &c2s[i].f.sp, NULL, &w);
		WRT_CHECK_U64(n, c2s[i].wire_len);
		if (n == c2s[i].wire_len)
			WRT_CHECK_MEM(w, c2s[i].wire, n);
		WRT_CHECK_U64(sim_sec_frame_len(&c2s[i].f.sp, &ops, parts), n);
		WRT_CHECK_U64(ops, c2s[i].ops);
		WRT_CHECK_U64(parts[0] + parts[1] + parts[2], n);
		stream_c = (uint8_t *)realloc(stream_c, lc + n);
		memcpy(stream_c + lc, w, n);
		lc += n;
		spc[i] = c2s[i].f.sp;
		ops_c += ops;
		free(w);
	}
	for (i = 0; i < ns; i++) {
		uint8_t *w = NULL;
		size_t n;

		WRT_CHECK_MEM(srv.tx.nonce, s2c[i].iv, 12);
		n = enc_alloc(&srv.tx, &s2c[i].f.sp, NULL, &w);
		WRT_CHECK_U64(n, s2c[i].wire_len);
		if (n == s2c[i].wire_len)
			WRT_CHECK_MEM(w, s2c[i].wire, n);
		stream_s = (uint8_t *)realloc(stream_s, ls + n);
		memcpy(stream_s + ls, w, n);
		ls += n;
		sps[i] = s2c[i].f.sp;
		ops_s += s2c[i].ops;
		free(w);
	}
	/* the other side decodes what the first produced: whole, one byte at a time, and in odd pieces */
	{
		static const size_t chunks[] = {0, 1, 7, 16, 95, 96, 97, 1000};
		unsigned k;

		for (k = 0; k < sizeof(chunks) / sizeof(chunks[0]); k++) {
			sim_sec_ctx c2, s2;

			WRT_CHECK(sim_sec_ctx_init(&c2, g_secret, 64, 0) == 0 && sim_sec_ctx_init(&s2, g_secret, 64, 1) == 0);
			decode_stream(&s2.rx, stream_c, lc, chunks[k], spc, nc);
			decode_stream(&c2.rx, stream_s, ls, chunks[k], sps, ns);
			WRT_CHECK_U64(s2.rx.ops, ops_c); /* one nonce per GCM operation, in step with the sender */
			WRT_CHECK_U64(c2.rx.ops, ops_s);
			WRT_CHECK_U64(sim_sec_dir_counter(&s2.rx), sim_sec_dir_counter(&cli.tx));
			WRT_CHECK_U64(sim_sec_dir_counter(&c2.rx), sim_sec_dir_counter(&srv.tx));
		}
	}
	free(stream_c);
	free(stream_s);
	free_dir(c2s, nc);
	free_dir(s2c, ns);
	wrt_json_free(&j);
}

/* Frames A and B exactly as the note prints them (5.2): the independent check of the vector file. */
static void test_note_frames(void)
{
	static const char *hexA =
		"5ee83e477793cc7cbb381480b30cc69431dabdf879b50b483d403cfd1b1ec96a"
		"e363935876ea5233f5930611558cad49725d69ea832d072f15bad3bf4b43581f"
		"01654a9d4a848c689172d4521fcf8108ee387f09dafe616e6a0c5adfa581ad5e";
	static const char *hexB =
		"98283b6ff8ab6493cd1f43d679c4a3a38a8577da66639b20d42f050521ea2d40"
		"4380360af91a14019d02906a063be428f187b4b3c0183c65656b15d047b91e7a"
		"e9f5a5aadcdc5350ca29264420199b1b20d32c03240c290bc1cc826c68a2c43c"
		"31004d2d0a48882efde2210977ac057a35e0d0b282f4010584c004c4ffd0a4ca"
		"f5a419f42a8a57c28a08980d974b4183";
	static const char *preA = "07012000000008000000000000000000000000000000000000000000a80c9872";
	static const char *preB = "11021400000008000a000000080000000000000000000000000000007669e7cf";
	sim_sec_ctx cli;
	fr a, b;
	uint8_t *wa, *wb, *ea, *eb, *pa, *pb, key[16], iv[12];
	size_t na, nb, nea, neb, npa, npb;
	uint32_t la[4] = {32, 0, 0, 0};
	sim_sec_frame g;
	sim_sec_dec d;
	size_t i;

	WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0);
	WRT_CHECK(wrt_hex_decode(hexA, strlen(hexA), &ea, &nea) == 0);
	WRT_CHECK(wrt_hex_decode(hexB, strlen(hexB), &eb, &neb) == 0);
	WRT_CHECK(wrt_hex_decode(preA, strlen(preA), &pa, &npa) == 0);
	WRT_CHECK(wrt_hex_decode(preB, strlen(preB), &pb, &npb) == 0);
	WRT_CHECK(nea == 96 && neb == 144 && npa == 32 && npb == 32);
	fr_make(&a, 7, 1, la, 0xa5);
	{
		uint32_t l2[4] = {20, 10, 0, 0};

		fr_make(&b, 17, 2, l2, -1);
		memset(b.buf[0], 0x11, 20);
		memset(b.buf[1], 0x22, 10);
	}
	/* the preambles of the note: 07 01 20000000 0800 .. crc a80c9872 and 11 02 14000000 0800 0a000000 0800 .. crc 7669e7cf */
	WRT_CHECK_U64(sim_sec_crc32c(0, pa, 28), 0x72980ca8u);
	WRT_CHECK_U64(sim_sec_crc32c(0, pb, 28), 0xcfe76976u);
	/* K = 00..0f, client tx seed 1c1d1e1f2021222324252627 and the second IV of frame B steps counter byte 4 from 20 to 21 */
	for (i = 0; i < 16; i++)
		key[i] = (uint8_t)i;
	for (i = 0; i < 12; i++)
		iv[i] = (uint8_t)(0x1c + i);
	WRT_CHECK_MEM(cli.tx.key, key, 16);
	WRT_CHECK_MEM(cli.tx.nonce, iv, 12);
	na = enc_alloc(&cli.tx, &a.sp, NULL, &wa);
	WRT_CHECK_U64(na, 96);
	WRT_CHECK_MEM(wa, ea, 96);
	iv[4] = 0x21; /* frame B's first operation */
	WRT_CHECK_MEM(cli.tx.nonce, iv, 12);
	nb = enc_alloc(&cli.tx, &b.sp, NULL, &wb);
	WRT_CHECK_U64(nb, 144);
	WRT_CHECK_MEM(wb, eb, 144);
	iv[4] = 0x23; /* two operations of B consumed: the next frame starts at counter byte 23 */
	WRT_CHECK_MEM(cli.tx.nonce, iv, 12);
	/* the decoder (the server's side) reads both */
	{
		sim_sec_ctx srv;
		int r;

		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
		sim_sec_dec_init(&d, &srv.rx, 0, 0);
		WRT_CHECK(sim_sec_dec_feed(&d, ea, 96) == 0 && sim_sec_dec_feed(&d, eb, 144) == 0);
		r = sim_sec_dec_next(&d, &g);
		WRT_CHECK(r == SIM_SEC_DEC_FRAME);
		WRT_CHECK_MEM(g.pre, pa, 32);
		check_frame_eq(&g, &a.sp);
		WRT_CHECK_U64(g.ops, 1);
		r = sim_sec_dec_next(&d, &g);
		WRT_CHECK(r == SIM_SEC_DEC_FRAME);
		WRT_CHECK_MEM(g.pre, pb, 32);
		check_frame_eq(&g, &b.sp);
		WRT_CHECK_U64(g.ops, 2);
		WRT_CHECK_U64(g.late_status, 0x0e);
		WRT_CHECK_U64(g.wire, 144);
		WRT_CHECK(sim_sec_dec_next(&d, &g) == SIM_SEC_DEC_NEED);
		sim_sec_dec_free(&d);
	}
	free(wa);
	free(wb);
	free(ea);
	free(eb);
	free(pa);
	free(pb);
	fr_free(&a);
	fr_free(&b);
}

/* The encrypted signature frames of the pre-auth vector and the IV each side continues with. */
static void test_preauth_vector(void)
{
	wrt_json j;
	sim_sec_ctx cli, srv;
	size_t n[8];
	uint8_t *cs, *ss, *cw, *sw, *cnext, *snext, *w = NULL;
	fr f;
	uint32_t l[4] = {32, 0, 0, 0};
	size_t m;

	WRT_CHECK(wrt_json_load_vec(&j, "secure/pre-auth-tail-synthetic.json") == 0);
	cs = hexv(&j, wrt_json_root(&j), "client_signature_plain_hex", &n[0]);
	ss = hexv(&j, wrt_json_root(&j), "server_signature_plain_hex", &n[1]);
	cw = hexv(&j, wrt_json_root(&j), "client_signature_frame_wire_hex", &n[2]);
	sw = hexv(&j, wrt_json_root(&j), "server_signature_frame_wire_hex", &n[3]);
	cnext = hexv(&j, wrt_json_root(&j), "client_next_iv_hex", &n[4]);
	snext = hexv(&j, wrt_json_root(&j), "server_next_iv_hex", &n[5]);
	WRT_CHECK(n[0] == 32 && n[1] == 32 && n[2] == 96 && n[3] == 96 && n[4] == 12 && n[5] == 12);
	WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0 && sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
	fr_make(&f, 7, 1, l, 0);
	memcpy(f.buf[0], cs, 32);
	m = enc_alloc(&cli.tx, &f.sp, NULL, &w);
	WRT_CHECK_U64(m, 96);
	WRT_CHECK_MEM(w, cw, 96);
	WRT_CHECK_MEM(cli.tx.nonce, cnext, 12);
	free(w);
	memcpy(f.buf[0], ss, 32);
	m = enc_alloc(&srv.tx, &f.sp, NULL, &w);
	WRT_CHECK_U64(m, 96);
	WRT_CHECK_MEM(w, sw, 96);
	WRT_CHECK_MEM(srv.tx.nonce, snext, 12);
	free(w);
	fr_free(&f);
	free(cs), free(ss), free(cw), free(sw), free(cnext), free(snext);
	wrt_json_free(&j);
}

/* ---- the size table and the captured structure ------------------------------------------------------------------------- */

static void test_size_table(void)
{
	wrt_json j;
	wrt_tok fs;
	size_t i;

	WRT_CHECK(wrt_json_load_vec(&j, "secure/primitives.json") == 0);
	fs = wrt_json_get(&j, wrt_json_root(&j), "frame_sizes");
	WRT_CHECK(wrt_json_count(&j, fs) >= 10);
	for (i = 0; i < wrt_json_count(&j, fs); i++) {
		wrt_tok c = wrt_json_at(&j, fs, i), sl = wrt_json_get(&j, c, "segment_lengths");
		uint32_t len[4] = {0, 0, 0, 0};
		unsigned k, ops = 0;
		int ok = 0;
		fr f;
		size_t parts[3], n;

		for (k = 0; k < 4u && k < wrt_json_count(&j, sl); k++)
			len[k] = (uint32_t)wrt_json_int(&j, wrt_json_at(&j, sl, k), &ok);
		fr_make(&f, 17, 4, len, -1);
		n = sim_sec_frame_len(&f.sp, &ops, parts);
		WRT_CHECK_U64(n, wrt_json_int(&j, wrt_json_get(&j, c, "wire_bytes"), &ok));
		WRT_CHECK_U64(ops, wrt_json_int(&j, wrt_json_get(&j, c, "gcm_operations"), &ok));
		{ /* and the bytes that come out have exactly that size and decode */
			sim_sec_ctx cli, srv;
			uint8_t *w = NULL;
			size_t m;

			WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0 && sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
			m = enc_alloc(&cli.tx, &f.sp, NULL, &w);
			WRT_CHECK_U64(m, n);
			decode_stream(&srv.rx, w, m, 0, &f.sp, 1);
			free(w);
		}
		fr_free(&f);
	}
	wrt_json_free(&j);
}

/* Every frame of every secure session of the captures, in the shape the real peers sent it. */
static void check_listed_frames(const wrt_json *j, wrt_tok list, sim_sec_ctx *tx, sim_sec_ctx *rx, unsigned *total, unsigned *bigp)
{
	size_t i;
	unsigned big = 0;

	for (i = 0; i < wrt_json_count(j, list); i++) {
		wrt_tok c = wrt_json_at(j, list, i), sl = wrt_json_get(j, c, "segment_lengths"), al = wrt_json_get(j, c, "alignments");
		uint32_t len[4] = {0, 0, 0, 0};
		unsigned k, nseg = (unsigned)wrt_json_count(j, sl), ops = 0, eff;
		int ok = 0;
		fr f;
		size_t n, w;
		uint8_t *wire = NULL;
		sim_sec_frame g;
		sim_sec_dec d;

		for (k = 0; k < nseg && k < 4u; k++)
			len[k] = (uint32_t)wrt_json_int(j, wrt_json_at(j, sl, k), &ok);
		for (eff = nseg; eff > 1u && len[eff - 1u] == 0; eff--)
			;
		fr_make(&f, (uint8_t)wrt_json_int(j, wrt_json_get(j, c, "tag"), &ok), nseg, len, -1);
		for (k = 0; k < nseg && k < wrt_json_count(j, al); k++)
			f.sp.align[k] = (uint16_t)wrt_json_int(j, wrt_json_at(j, al, k), &ok);
		n = sim_sec_frame_len(&f.sp, &ops, NULL);
		WRT_CHECK_U64(n, wrt_json_int(j, wrt_json_get(j, c, "wire_bytes"), &ok));
		WRT_CHECK_U64(ops, wrt_json_int(j, wrt_json_get(j, c, "gcm_operations"), &ok));
		if (n > (128u << 10)) { /* the 1 MiB and 4 MiB data frames of the captures: their size and operation count are checked, the bytes are
					 * not run through the reference AES-GCM (about 1 MB/s; the bulk test below does a 200 KB frame end to end) */
			fr_free(&f);
			(*total)++;
			big++;
			continue;
		}
		w = enc_alloc(&tx->tx, &f.sp, NULL, &wire);
		WRT_CHECK_U64(w, n);
		sim_sec_dec_init(&d, &rx->rx, 0, 0);
		WRT_CHECK(sim_sec_dec_feed(&d, wire, w) == 0);
		WRT_CHECK(sim_sec_dec_next(&d, &g) == SIM_SEC_DEC_FRAME);
		check_frame_eq(&g, &f.sp);
		WRT_CHECK_U64(g.ops, ops);
		WRT_CHECK_U64(g.wire, n);
		if (eff > 1u) { /* "late_status": 14 in the captures */
			int has = 0;
			int64_t late = wrt_json_int(j, wrt_json_get(j, c, "late_status"), &has);

			WRT_CHECK(has && late == 14 && g.late_status == 0x0e);
		}
		WRT_CHECK_U64(g.flags, wrt_json_int(j, wrt_json_get(j, c, "flags"), &ok));
		sim_sec_dec_free(&d);
		free(wire);
		fr_free(&f);
		(*total)++;
	}
	*bigp += big;
}

static void test_captured_structure(void)
{
	wrt_json j;
	wrt_tok ss;
	size_t i;
	unsigned secure = 0, frames = 0, big = 0;

	WRT_CHECK(wrt_json_load_vec(&j, "secure/captured-structure.json") == 0);
	ss = wrt_json_get(&j, wrt_json_root(&j), "sessions");
	for (i = 0; i < wrt_json_count(&j, ss); i++) {
		wrt_tok s = wrt_json_at(&j, ss, i);
		char *mode = wrt_json_strdup(&j, wrt_json_get(&j, s, "mode"));
		sim_sec_ctx cli, srv;

		if (mode == NULL || strcmp(mode, "secure") != 0) {
			free(mode);
			continue;
		}
		free(mode);
		secure++;
		WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0 && sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
		check_listed_frames(&j, wrt_json_get(&j, s, "frames_after_auth_client_first"), &cli, &srv, &frames, &big);
		check_listed_frames(&j, wrt_json_get(&j, s, "frames_after_auth_server_first"), &srv, &cli, &frames, &big);
	}
	WRT_CHECK_U64(secure, 5); /* the structure file holds five secure sessions: mon and mgr twice, one osd */
	WRT_CHECK(frames >= 30 && big == 3); /* two 4 MiB frames and one 1 MiB frame: sized only */
	wrt_json_free(&j);
}

/* ---- round trips on a sweep of shapes ------------------------------------------------------------------------------------ */

static void test_sweep(void)
{
	static const uint32_t l0[] = {0, 1, 16, 47, 48, 49, 96, 97};
	static const uint32_t l1[] = {0, 1, 16, 17, 130};
	static const uint32_t l23[] = {0, 17};
	sim_sec_ctx cli, srv;
	unsigned a, b, c, d, nf = 0, nseg;
	unsigned ops_seen[4] = {0, 0, 0, 0}, ops_sum = 0;
	uint64_t ctr0;

	WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0 && sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
	ctr0 = sim_sec_dir_counter(&cli.tx);
	for (nseg = 1; nseg <= 4; nseg++)
		for (a = 0; a < sizeof(l0) / sizeof(l0[0]); a++)
			for (b = 0; b < sizeof(l1) / sizeof(l1[0]); b++)
				for (c = 0; c < 2; c++)
					for (d = 0; d < 2; d++) {
						uint32_t len[4];
						fr f;
						sim_sec_frame g;
						sim_sec_dec dec;
						uint8_t *w = NULL;
						size_t n;
						unsigned ops;

						if ((nseg < 2 && b != 0) || (nseg < 3 && c != 0) || (nseg < 4 && d != 0))
							continue;
						len[0] = l0[a];
						len[1] = l1[b];
						len[2] = l23[c];
						len[3] = l23[d];
						fr_make(&f, (uint8_t)(1 + nf % 22), nseg, len, -1);
						n = enc_alloc(&cli.tx, &f.sp, NULL, &w);
						WRT_CHECK(n != 0);
						WRT_CHECK_U64(n, sim_sec_frame_len(&f.sp, &ops, NULL));
						ops_seen[ops]++;
						ops_sum += ops;
						sim_sec_dec_init(&dec, &srv.rx, 0, 0);
						WRT_CHECK(sim_sec_dec_feed(&dec, w, n) == 0);
						WRT_CHECK(sim_sec_dec_next(&dec, &g) == SIM_SEC_DEC_FRAME);
						check_frame_eq(&g, &f.sp);
						WRT_CHECK_U64(g.ops, ops);
						sim_sec_dec_free(&dec);
						/* and the reverse direction, crossed seeds */
						free(w);
						n = enc_alloc(&srv.tx, &f.sp, NULL, &w);
						sim_sec_dec_init(&dec, &cli.rx, 0, 0);
						WRT_CHECK(sim_sec_dec_feed(&dec, w, n) == 0);
						WRT_CHECK(sim_sec_dec_next(&dec, &g) == SIM_SEC_DEC_FRAME);
						check_frame_eq(&g, &f.sp);
						sim_sec_dec_free(&dec);
						free(w);
						fr_free(&f);
						nf++;
					}
	WRT_CHECK(nf > 200 && ops_seen[1] > 0 && ops_seen[2] > 0 && ops_seen[3] > 0);
	/* the stream stepped once per operation, and the reader of every frame stepped in step with it */
	WRT_CHECK_U64(cli.tx.ops, ops_sum);
	WRT_CHECK_U64(srv.rx.ops, ops_sum);
	WRT_CHECK_U64(sim_sec_dir_counter(&cli.tx), ctr0 + ops_sum);
	WRT_CHECK_U64(sim_sec_dir_counter(&srv.rx), ctr0 + ops_sum);
	sim_sec_ctx_wipe(&cli);
	sim_sec_ctx_wipe(&srv);
}

/* A frame built from raw plaintext parts: the pieces give the same bytes as the encoder, and any plaintext can be sealed (here: garbage
 * after a right tag is a malformed frame, never a tag failure). */
static void test_pieces(void)
{
	sim_sec_ctx a, b, srv;
	uint32_t len[4] = {20, 70, 0, 33};
	fr f;
	uint8_t *w = NULL, pre[32], p1[96], mine[256]; /* p1: 80 plaintext bytes, room for the tag */
	size_t n, k;
	sim_sec_dec d;
	sim_sec_frame g;

	WRT_CHECK(sim_sec_ctx_init(&a, g_secret, 64, 0) == 0 && sim_sec_ctx_init(&b, g_secret, 64, 0) == 0 && sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
	fr_make(&f, 17, 4, len, -1);
	n = enc_alloc(&a.tx, &f.sp, NULL, &w);
	WRT_CHECK_U64(n, 96u + 80u + 48u + 16u + 16u);
	/* part 1 by hand: preamble, then segment 0 and zero fill to 48 bytes */
	sim_sec_preamble(&f.sp, NULL, pre);
	memcpy(p1, pre, 32);
	memset(p1 + 32, 0, 48);
	memcpy(p1 + 32, f.buf[0], 20);
	WRT_CHECK(sim_sec_seal(&b.tx, p1, 80, mine) == 0);
	WRT_CHECK_MEM(mine, w, 96);
	/* part 3 by hand: segments 1 and 3 padded to 16, then the epilogue block */
	{
		uint8_t p3[80 + 48 + 16];

		memset(p3, 0, sizeof(p3));
		memcpy(p3, f.buf[1], 70);
		memcpy(p3 + 80, f.buf[3], 33);
		p3[80 + 48] = 0x0e;
		WRT_CHECK(sim_sec_seal(&b.tx, p3, 80 + 48 + 16, mine + 96) == 0);
		WRT_CHECK_MEM(mine + 96, w + 96, 160);
	}
	WRT_CHECK_U64(sim_sec_dir_counter(&a.tx), sim_sec_dir_counter(&b.tx));
	WRT_CHECK(sim_sec_seal(&b.tx, p1, 80, p1) == 0); /* in place */
	/* garbage plaintext under a right tag: the preamble rules reject it, as a malformed frame, not as a tag failure */
	for (k = 0; k < 256; k += 17) {
		uint8_t junk[80], wire[96];
		sim_sec_ctx s2, c2;

		memset(junk, (int)k, sizeof(junk));
		WRT_CHECK(sim_sec_ctx_init(&s2, g_secret, 64, 1) == 0 && sim_sec_ctx_init(&c2, g_secret, 64, 0) == 0);
		WRT_CHECK(sim_sec_seal(&s2.tx, junk, 80, wire) == 0);
		sim_sec_dec_init(&d, &c2.rx, 0, 0);
		WRT_CHECK(sim_sec_dec_feed(&d, wire, 96) == 0);
		WRT_CHECK(sim_sec_dec_next(&d, &g) == SIM_SEC_DEC_ERROR);
		WRT_CHECK(d.err == WR_E_M2_FRAME_CRC || d.err == WR_E_M2_FRAME_FORM || d.err == WR_E_M2_TAG);
		WRT_CHECK(d.err != WR_E_M2_SEC_TAG);
		sim_sec_dec_free(&d);
	}
	WRT_CHECK(sim_sec_seal(&srv.rx, p1, 80, p1) == 0);
	free(w);
	fr_free(&f);
	{
		sim_sec_dir unkeyed;

		memset(&unkeyed, 0, sizeof(unkeyed));
		WRT_CHECK(sim_sec_seal(&unkeyed, p1, 80, p1) == -1);
	}
}

/* One bulk frame crossing several 64 KiB and 4 KiB boundaries (kept small: the reference AES-GCM does about 1 MB/s). */
static void test_bulk(void)
{
	sim_sec_ctx cli, srv;
	uint32_t len[4] = {41, 100, 0, 200003};
	fr f;
	uint8_t *w = NULL;
	size_t n;
	unsigned ops;

	WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0 && sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
	fr_make(&f, 17, 4, len, -1);
	n = enc_alloc(&cli.tx, &f.sp, NULL, &w);
	WRT_CHECK_U64(n, sim_sec_frame_len(&f.sp, &ops, NULL));
	WRT_CHECK_U64(ops, 2);
	WRT_CHECK_U64(n, 96u + 112u + 200016u + 32u);
	decode_stream(&srv.rx, w, n, 4097, &f.sp, 1);
	free(w);
	fr_free(&f);
}

/* The edges of the API: a refused frame leaves the stream where it was, the size of a frame that keeps its empty tail, the decoder before
 * its first byte, the wipe helper. */
static void test_api_edges(void)
{
	sim_sec_ctx cli, srv;
	sim_sec_dec d;
	sim_sec_spec sp;
	sim_sec_mut m;
	uint8_t seg[20], buf[16], out[256], nonce0[12];
	unsigned ops = 0;
	size_t n = 0, parts[3];
	uint64_t ops0;
	size_t i;

	WRT_CHECK(sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0 && sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0);
	/* take from a decoder that never saw a byte (no buffer yet) */
	sim_sec_dec_init(&d, &srv.rx, 0, 0);
	WRT_CHECK_U64(sim_sec_dec_take(&d, buf, sizeof(buf)), 0);
	WRT_CHECK_U64(sim_sec_dec_buffered(&d), 0);
	sim_sec_dec_free(&d);
	/* the wipe helper: zeros, and NULL is fine */
	memset(buf, 0xaa, sizeof(buf));
	sim_sec_wipe(buf, sizeof(buf));
	for (i = 0; i < sizeof(buf); i++)
		WRT_CHECK(buf[i] == 0);
	sim_sec_wipe(NULL, 7);

	/* two segments, the second empty: the sender drops it (one operation, 96 bytes); a mutation that keeps it is a frame with an epilogue */
	memset(seg, 0x5a, sizeof(seg));
	memset(&sp, 0, sizeof(sp));
	sp.tag = 17;
	sp.nseg = 2;
	sp.seg[0] = seg;
	sp.len[0] = sizeof(seg);
	memset(&m, 0, sizeof(m));
	m.mask = SIM_SEC_M_KEEP_TAIL;
	WRT_CHECK_U64(sim_sec_frame_len(&sp, &ops, parts), 96);
	WRT_CHECK_U64(ops, 1);
	WRT_CHECK_U64(sim_sec_frame_len_m(&sp, NULL, NULL, NULL), 96);
	WRT_CHECK_U64(sim_sec_frame_len_m(&sp, &m, &ops, parts), 96u + 32u);
	WRT_CHECK(ops == 2 && parts[0] == 96 && parts[1] == 0 && parts[2] == 32);
	memcpy(nonce0, cli.tx.nonce, 12);
	ops0 = cli.tx.ops;
	WRT_CHECK(sim_sec_encode(&cli.tx, &sp, &m, out, 96, &n) == -1); /* the buffer of the unmutated size is too small */
	WRT_CHECK_MEM(cli.tx.nonce, nonce0, 12);
	WRT_CHECK_U64(cli.tx.ops, ops0);
	WRT_CHECK(sim_sec_encode(&cli.tx, &sp, &m, out, 128, &n) == 0 && n == 128);
	WRT_CHECK_U64(cli.tx.ops, ops0 + 2u);

	/* a mutation that names an operation, part or tag the frame does not have is refused and steps nothing */
	{
		static const struct {
			const char *what;
			sim_sec_mut m;
		} bad[] = {
			{"nonce_part 2 on a one-operation frame", {.mask = SIM_SEC_M_NONCE, .nonce_part = 2, .nonce_delta = -1}},
			{"nonce_part 3", {.mask = SIM_SEC_M_NONCE, .nonce_part = 3, .nonce_delta = 1}},
			{"flip_part 2", {.mask = SIM_SEC_M_FLIP, .flip_part = 2}},
			{"flip_part 3", {.mask = SIM_SEC_M_FLIP, .flip_part = 3}},
			{"flip_bit 8", {.mask = SIM_SEC_M_FLIP, .flip_part = 1, .flip_bit = 8}},
			{"flip_byte past the part", {.mask = SIM_SEC_M_FLIP, .flip_part = 1, .flip_byte = 96}},
			{"tag_part 3", {.mask = SIM_SEC_M_TAG, .tag_part = 3}},
			{"tag_part 0", {.mask = SIM_SEC_M_TAG, .tag_part = 0}},
		};

		sp.nseg = 1; /* one operation */
		memcpy(nonce0, cli.tx.nonce, 12);
		ops0 = cli.tx.ops;
		for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			int rc = sim_sec_encode(&cli.tx, &sp, &bad[i].m, out, sizeof(out), &n);

			if (rc != -1)
				fprintf(stderr, "refusal expected: %s\n", bad[i].what);
			WRT_CHECK(rc == -1);
			WRT_CHECK_MEM(cli.tx.nonce, nonce0, 12);
			WRT_CHECK_U64(cli.tx.ops, ops0);
		}
		/* nonce_part 2 is fine on a frame that has two operations (here a 105 byte segment 0) */
		{
			uint8_t big[105];
			sim_sec_spec s2;
			sim_sec_mut mm;

			memset(big, 1, sizeof(big));
			memset(&s2, 0, sizeof(s2));
			s2.tag = 17, s2.nseg = 1, s2.seg[0] = big, s2.len[0] = sizeof(big);
			memset(&mm, 0, sizeof(mm));
			mm.mask = SIM_SEC_M_NONCE, mm.nonce_part = 2, mm.nonce_delta = -1;
			WRT_CHECK(sim_sec_encode(&cli.tx, &s2, &mm, out, sizeof(out), &n) == 0);
			WRT_CHECK_U64(cli.tx.ops, ops0 + 2u);
		}
	}
	sim_sec_ctx_wipe(&cli);
	sim_sec_ctx_wipe(&srv);
}

/* The log of issued secrets: what "every connection got its own" is built on, so its verdicts are checked in both directions. */
static void test_secret_log(void)
{
	static sim_sec_log l; /* 33 KiB: not on the stack */
	uint8_t a[64], b[64], z[64], c[128];
	unsigned i;

	for (i = 0; i < 64; i++) {
		a[i] = (uint8_t)(i + 1u);
		b[i] = (uint8_t)(i + 2u);
		z[i] = 0;
	}
	memset(&l, 0, sizeof(l));
	WRT_CHECK(sim_sec_log_distinct(&l) == 1 && !sim_sec_log_has(&l, a, 64)); /* nothing issued: nothing repeated */
	sim_sec_log_add(&l, a, 64);
	sim_sec_log_add(&l, b, 64);
	WRT_CHECK_U64(l.n, 2);
	WRT_CHECK_U64(l.kept, 2);
	WRT_CHECK(sim_sec_log_distinct(&l) == 1);
	WRT_CHECK(sim_sec_log_has(&l, a, 64) && sim_sec_log_has(&l, b, 64) && !sim_sec_log_has(&l, z, 64));
	WRT_CHECK(!sim_sec_log_has(&l, a, 63)); /* the length is part of the identity */
	sim_sec_log_add(&l, a, 40); /* a prefix of an issued secret is another secret */
	WRT_CHECK(sim_sec_log_distinct(&l) == 1);
	sim_sec_log_add(&l, a, 64); /* the same secret twice: two connections with one key */
	WRT_CHECK_U64(l.n, 4);
	WRT_CHECK(sim_sec_log_distinct(&l) == 0);
	memset(&l, 0, sizeof(l));
	sim_sec_log_add(&l, a, 64);
	sim_sec_log_add(&l, z, 64); /* an all-zero secret is no secret */
	WRT_CHECK(sim_sec_log_distinct(&l) == 0);
	/* the first SIM_SEC_LOG_MAX are kept, all are counted; a longer secret is cut to SIM_SEC_SECRET_MAX */
	memset(&l, 0, sizeof(l));
	memset(c, 0x11, sizeof(c));
	for (i = 0; i < SIM_SEC_LOG_MAX + 5u; i++) {
		c[0] = (uint8_t)i;
		c[1] = (uint8_t)(i >> 8);
		sim_sec_log_add(&l, c, sizeof(c));
	}
	WRT_CHECK_U64(l.n, SIM_SEC_LOG_MAX + 5u);
	WRT_CHECK_U64(l.kept, SIM_SEC_LOG_MAX);
	WRT_CHECK(sim_sec_log_distinct(&l) == 1);
	sim_sec_log_add(&l, c, sizeof(c));
	WRT_CHECK_U64(l.n, SIM_SEC_LOG_MAX + 6u);
	WRT_CHECK_U64(l.kept, SIM_SEC_LOG_MAX); /* full: counted, not kept */
	memset(&l, 0, sizeof(l));
	{
		uint8_t big[SIM_SEC_SECRET_MAX + 64u];

		memset(big, 0x22, sizeof(big));
		sim_sec_log_add(&l, big, sizeof(big)); /* only SIM_SEC_SECRET_MAX bytes of it are read and kept */
		WRT_CHECK_U64(l.len[0], SIM_SEC_SECRET_MAX);
		WRT_CHECK_U64(l.n, 1);
	}
}

/* On a host whose size_t is 32 bits (the i386 run of the suite) a frame whose plaintext cannot be addressed is refused by its preamble, not
 * answered with a wrapped allocation; on a 64-bit host there is no such frame below the caps, the test has nothing to check. */
static void test_frame_size_32(void)
{
	sim_sec_ctx srv, cli;
	static const uint32_t len[4] = {20, 70, 0, 350};
	sim_sec_spec sp;
	sim_sec_mut m;
	uint8_t out[1024]; /* the encoder wants room for the whole frame, the truncation cuts it to part 1 */
	size_t n = 0;
	sim_sec_dec d;
	sim_sec_frame g;

	if (sizeof(size_t) > 4)
		return;
	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, 64, 1) == 0 && sim_sec_ctx_init(&cli, g_secret, 64, 0) == 0);
	memset(&sp, 0, sizeof(sp));
	sp.tag = 17;
	sp.nseg = 4;
	memset(&m, 0, sizeof(m));
	{
		static uint8_t b0[20], b1[70], b3[350];

		sp.seg[0] = b0, sp.seg[1] = b1, sp.seg[2] = NULL, sp.seg[3] = b3;
		sp.len[0] = len[0], sp.len[1] = len[1], sp.len[2] = len[2], sp.len[3] = len[3];
	}
	m.mask = SIM_SEC_M_PRE_LEN | SIM_SEC_M_TRUNC;
	m.pre_len_mask = 0x0eu;
	m.pre_len[1] = m.pre_len[2] = m.pre_len[3] = 0x40000000u; /* 3 GiB of segments: more than a 32-bit size_t addresses */
	m.truncate_at = 96;
	WRT_CHECK(sim_sec_encode(&srv.tx, &sp, &m, out, sizeof(out), &n) == 0 && n == 96);
	sim_sec_dec_init(&d, &cli.rx, 0xffffffffu, 0xffffffffu); /* caps that do not stop it */
	WRT_CHECK(sim_sec_dec_feed(&d, out, n) == 0);
	WRT_CHECK(sim_sec_dec_next(&d, &g) == SIM_SEC_DEC_ERROR);
	WRT_CHECK_STATUS(WR_E_M2_FRAME_TOOBIG, d.err);
	sim_sec_dec_free(&d);
}

#include <time.h>

/* SIMSEC_TIMING=1 prints the seconds each part took (the reference AES-GCM is slow; this is how a part that got too big is found). */
static void timed(const char *name, void (*fn)(void))
{
	clock_t t0 = clock();

	fn();
	if (getenv("SIMSEC_TIMING") != NULL)
		fprintf(stderr, "%-24s %6.2f s\n", name, (double)(clock() - t0) / CLOCKS_PER_SEC);
}

int main(void)
{
	init_secret();
	timed("primitives", test_primitives);
	timed("synthetic_frames", test_synthetic_frames);
	timed("note_frames", test_note_frames);
	timed("preauth_vector", test_preauth_vector);
	timed("size_table", test_size_table);
	timed("captured_structure", test_captured_structure);
	timed("sweep", test_sweep);
	timed("pieces", test_pieces);
	timed("bulk", test_bulk);
	timed("api_edges", test_api_edges);
	timed("secret_log", test_secret_log);
	timed("frame_size_32", test_frame_size_32);
	return wrt_finish();
}
