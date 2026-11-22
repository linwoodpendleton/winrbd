/* SPDX-License-Identifier: MIT */
/*
 * test_m2_sec_replay - the core's secure mode against the lab captures of module vectors-sec (harness/vectors/public/secure/): two sessions of wr-rbd
 * in secure mode (one per cephx key type; each has a monitor connection and OSD connections) against a real Ceph v20.2.5 cluster, with the connection
 * secret and the session key the cephx exchange handed over (recovered by the independent checker check_secure_core.py, which ctest vectors_secure_check
 * runs), the plaintext of every frame and the wire bytes of both directions. Offline, no cluster; the two 1 MiB data frames of each OSD connection are
 * kept as their wire size and SHA-256 with the data given as the pattern wr-rbd wrote (the bytes are re-derived and must hash to what the wire had).
 *
 *   server -> client   the stream of every connection goes through the REAL secure receive parser (wri_m2_secure_on + wri_m2_rx_*) with the recorded
 *                      secret, in several deliveries (whole through the direct window, random pieces, one byte at a time, ring only, small work
 *                      budgets, exact / roomy / discarded sinks): every frame comes out with the recorded tag, segment lengths and plaintext, no byte
 *                      past a segment lands in a sink, and the receive nonce has advanced by exactly the operations of the stream. The independent
 *                      peer of the simulators (sim_m2_sec.c, written from the spec with its own GCM) must produce the recorded wire bytes from the
 *                      recorded plaintext too: the simulator is the real server, byte for byte;
 *   client -> server   the secure TRANSMIT side of the core is fed the recorded plaintext frames, the very frames the core sent in the capture, and its
 *                      bytes are the recorded wire bytes (or hash to the recorded SHA-256), whatever the host's way of taking them (all at once,
 *                      random pieces, 61 bytes at a time), with and without referenced segments; the independent decoder reads the result back;
 *   signatures         the core's pre-auth transcript code (wri_m2_preauth) with the recorded handshake bytes and session key gives the AUTH_SIGNATURE
 *                      of both directions (the first secure frame of each): HMAC-SHA256 of what each side received;
 *   damage             a flipped bit in any part of a recorded frame (ciphertext, inline bytes, tag, the tag of a multi-segment frame), a stream read
 *                      with the other direction's nonce, a frame replayed a second time (its nonce is spent) and a frame cut one byte short are refused
 *                      or held back exactly as the design says, with the tag failure reported before any event;
 *   refusals           the AUTH_BAD_METHOD frames of real servers that allow only one mode (refusals.json: a monitor and an OSD, secure only and crc
 *                      only, both key types), injected into a connection that offered the other mode, fail it with WR_E_M2_BAD_METHOD and the errinfo
 *                      of the design: peer result -95 (EOPNOTSUPP), allowed methods {cephx}, allowed modes, the method we offered. The result code
 *                      is the answer to sec.md 6.4.
 *
 * Timing never matters (work budgets are counts); the test is slow because the independent encoder runs at about 1 MB/s. When the vectors are not part of
 * the source tree the test skips with its reason.
 */
#include "wrt.h"

#define TXR_CHECK WRT_CHECK
#include "m2_sec_tx_rig.h"
#include "m2_sec_rx_rig.h"
#include "m2_conn_rig.h"

#include "wri_hash.h"
#include "wri_m2_ctl.h"

#include "../host/wrl_gcm_aesni.c"

#define RP_BIG_WIRE 20000u /* frames of this wire size or more are "big": fewer delivery variants, no byte-at-a-time */
#define RP_SEG0_CAP 4096u
#define RP_SEG_CAP_MAX (4u * 1024u * 1024u)
#define RP_RING 4096u

/* ---- the vectors --------------------------------------------------------------------------------------------------------------------- */

typedef struct rp_frame {
	uint8_t tag;
	unsigned nseg;
	uint32_t len[4];
	uint8_t *seg[4];
	uint16_t align[4];
	uint8_t *wire;     /* the recorded bytes, NULL for an elided frame */
	uint64_t wire_len;
	uint8_t sha[32];
	unsigned nops;
} rp_frame;

typedef struct rp_conn {
	char id[16];
	int is_mon;
	uint8_t secret[64];
	uint8_t skey[32];
	size_t skey_len;
	uint8_t *hs_c, *hs_s; /* the plaintext handshake bytes: what the client sent / received before the first secure frame */
	size_t hs_c_len, hs_s_len;
	rp_frame *c2s, *s2c;
	size_t nc, ns;
	uint64_t bytes_c, bytes_s; /* wire bytes of the secure frames */
	uint64_t ops_c, ops_s;
	int has_elided_c, has_elided_s;
} rp_conn;

typedef struct rp_sess {
	wrt_json j;
	char name[8];
	rp_conn *conn;
	size_t nconn;
} rp_sess;

static uint64_t rp_mix64(uint64_t x)
{
	x += 0x9e3779b97f4a7c15ull;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
	return x ^ (x >> 31);
}

/* The patterns of wr-rbd: a function of the absolute byte offset. */
static int rp_pattern(uint8_t *buf, const char *kind, uint64_t arg, uint64_t off, size_t n)
{
	size_t i;

	if (strcmp(kind, "zero") == 0) {
		memset(buf, 0, n);
	} else if (strcmp(kind, "byte") == 0) {
		memset(buf, (int)(arg & 255u), n);
	} else if (strcmp(kind, "rand") == 0) {
		for (i = 0; i < n; i++) {
			uint64_t pos = off + i, w = rp_mix64(arg * 0x2545f4914f6cdd1dull + (pos >> 3));

			buf[i] = (uint8_t)(w >> (8u * (unsigned)(pos & 7u)));
		}
	} else {
		return -1;
	}
	return 0;
}

static int rp_get_int(const wrt_json *j, wrt_tok obj, const char *key, uint64_t *out)
{
	int ok = 0;
	wrt_tok t = wrt_json_get(j, obj, key);

	if (t == WRT_NONE)
		return -1;
	*out = (uint64_t)wrt_json_int(j, t, &ok);
	return ok ? 0 : -1;
}

static int rp_load_frame(const wrt_json *j, wrt_tok t, rp_frame *f)
{
	uint64_t v;
	wrt_tok segs = wrt_json_get(j, t, "segs"), al = wrt_json_get(j, t, "aligns"), w;
	size_t i, n, got;
	uint8_t *sha;
	uint32_t lens[4];

	memset(f, 0, sizeof(*f));
	if (rp_get_int(j, t, "tag", &v) != 0 || v < 1 || v > 22)
		return -1;
	f->tag = (uint8_t)v;
	if (segs == WRT_NONE || al == WRT_NONE)
		return -1;
	n = wrt_json_count(j, segs);
	if (n < 1 || n > 4 || wrt_json_count(j, al) != n)
		return -1;
	f->nseg = (unsigned)n;
	for (i = 0; i < n; i++) {
		wrt_tok s = wrt_json_at(j, segs, i);
		int ok = 0;

		f->align[i] = (uint16_t)wrt_json_int(j, wrt_json_at(j, al, i), &ok);
		if (!ok)
			return -1;
		if (wrt_json_is_string(j, s)) {
			size_t m = 0;

			if (wrt_json_hex(j, s, &f->seg[i], &m) != 0)
				return -1;
			f->len[i] = (uint32_t)m;
			if (f->seg[i] == NULL) {
				f->seg[i] = (uint8_t *)malloc(1);
				if (f->seg[i] == NULL)
					return -1;
			}
		} else {
			char *kind = wrt_json_strdup(j, wrt_json_get(j, s, "pattern"));
			uint64_t arg, off, len;

			if (kind == NULL || rp_get_int(j, s, "arg", &arg) != 0 || rp_get_int(j, s, "off", &off) != 0 || rp_get_int(j, s, "len", &len) != 0 ||
			    len > (8u << 20)) {
				free(kind);
				return -1;
			}
			f->seg[i] = (uint8_t *)malloc((size_t)len + 1u);
			if (f->seg[i] == NULL || rp_pattern(f->seg[i], kind, arg, off, (size_t)len) != 0) {
				free(kind);
				return -1;
			}
			free(kind);
			f->len[i] = (uint32_t)len;
		}
	}
	if (rp_get_int(j, t, "wire_len", &f->wire_len) != 0)
		return -1;
	if (wrt_json_get_hex(j, t, "wire_sha256", &sha, &got) != 0 || got != 32u)
		return -1;
	memcpy(f->sha, sha, 32);
	free(sha);
	w = wrt_json_get(j, t, "wire");
	if (w != WRT_NONE) {
		size_t m = 0;

		if (wrt_json_hex(j, w, &f->wire, &m) != 0 || m != f->wire_len)
			return -1;
	}
	for (i = 0; i < 4; i++)
		lens[i] = i < f->nseg ? f->len[i] : 0u;
	if (wri_m2s_wire_len(lens, f->nseg, &f->nops) != f->wire_len)
		return -1; /* the table of sec.md 5.1 against the recorded size */
	return 0;
}

static int rp_load_frames(const wrt_json *j, wrt_tok arr, rp_frame **out, size_t *n, uint64_t *bytes, uint64_t *ops, int *elided)
{
	size_t i;

	*n = wrt_json_count(j, arr);
	*out = (rp_frame *)calloc(*n + 1u, sizeof(rp_frame));
	if (*out == NULL)
		return -1;
	for (i = 0; i < *n; i++) {
		if (rp_load_frame(j, wrt_json_at(j, arr, i), &(*out)[i]) != 0) {
			fprintf(stderr, "frame %zu of a recorded stream does not load\n", i);
			return -1;
		}
		*bytes += (*out)[i].wire_len;
		*ops += (*out)[i].nops;
		if ((*out)[i].wire == NULL)
			*elided = 1;
	}
	return 0;
}

static void rp_free_frames(rp_frame *f, size_t n)
{
	size_t i, k;

	for (i = 0; i < n; i++) {
		for (k = 0; k < 4; k++)
			free(f[i].seg[k]);
		free(f[i].wire);
	}
	free(f);
}

static int rp_load_session(rp_sess *s, const char *name)
{
	char rel[64];
	wrt_tok conns;
	size_t i;

	memset(s, 0, sizeof(*s));
	snprintf(s->name, sizeof(s->name), "%s", name);
	snprintf(rel, sizeof(rel), "public/secure/sessions/%s.json", name);
	if (wrt_json_load_vec(&s->j, rel) != 0)
		return -1;
	conns = wrt_json_get(&s->j, wrt_json_root(&s->j), "conns");
	s->nconn = wrt_json_count(&s->j, conns);
	s->conn = (rp_conn *)calloc(s->nconn + 1u, sizeof(rp_conn));
	if (s->conn == NULL)
		return -1;
	for (i = 0; i < s->nconn; i++) {
		wrt_tok c = wrt_json_at(&s->j, conns, i), fr = wrt_json_get(&s->j, c, "frames");
		rp_conn *rc = &s->conn[i];
		char *id = wrt_json_strdup(&s->j, wrt_json_get(&s->j, c, "id")), *kind = wrt_json_strdup(&s->j, wrt_json_get(&s->j, c, "kind"));
		uint8_t *b;
		size_t m;

		if (id == NULL || kind == NULL || strlen(id) >= sizeof(rc->id)) {
			free(id);
			free(kind);
			return -1;
		}
		strcpy(rc->id, id);
		rc->is_mon = strcmp(kind, "mon") == 0;
		free(id);
		free(kind);
		if (wrt_json_get_hex(&s->j, c, "secret", &b, &m) != 0 || m != 64u)
			return -1;
		memcpy(rc->secret, b, 64);
		free(b);
		if (wrt_json_get_hex(&s->j, c, "session_key", &b, &m) != 0 || (m != 16u && m != 32u))
			return -1;
		memcpy(rc->skey, b, m);
		rc->skey_len = m;
		free(b);
		if (wrt_json_get_hex(&s->j, c, "hs_c2s", &rc->hs_c, &rc->hs_c_len) != 0 || wrt_json_get_hex(&s->j, c, "hs_s2c", &rc->hs_s, &rc->hs_s_len) != 0)
			return -1;
		if (rp_load_frames(&s->j, wrt_json_get(&s->j, fr, "c2s"), &rc->c2s, &rc->nc, &rc->bytes_c, &rc->ops_c, &rc->has_elided_c) != 0 ||
		    rp_load_frames(&s->j, wrt_json_get(&s->j, fr, "s2c"), &rc->s2c, &rc->ns, &rc->bytes_s, &rc->ops_s, &rc->has_elided_s) != 0)
			return -1;
	}
	return 0;
}

static void rp_free_session(rp_sess *s)
{
	size_t i;

	for (i = 0; i < s->nconn; i++) {
		rp_free_frames(s->conn[i].c2s, s->conn[i].nc);
		rp_free_frames(s->conn[i].s2c, s->conn[i].ns);
		free(s->conn[i].hs_c);
		free(s->conn[i].hs_s);
	}
	free(s->conn);
	wrt_json_free(&s->j);
}

static int rp_present(void)
{
	FILE *f = fopen(wrt_vec_path("public/secure/INDEX.json"), "rb");

	if (f == NULL)
		return 0;
	fclose(f);
	return 1;
}

static void rp_sha256(const uint8_t *p, size_t n, uint8_t out[32])
{
	wri_sha256_ctx c;

	wri_sha256_init(&c);
	wri_sha256_update(&c, p, n);
	wri_sha256_final(&c, out);
}

/* ---- the streams: the wire of every frame, from the recorded bytes or (elided) from the independent encoder ------------------------------- */

/*
 * The independent peer (sim_m2_sec.c) encrypts each recorded frame of one direction: the result must be the recorded wire bytes (or hash to the recorded
 * SHA-256). dir 0 = the server's stream (the independent peer in the server's view of the secret), dir 1 = the client's stream (the client's view).
 * The stream is the concatenation of all the frames' wire bytes in a malloc'd buffer (the recorded ones when there are some), with the end offset of
 * each frame in ends[]. It is built once per connection and direction and shared by every pass that needs it (the encoder is the slow part).
 */
typedef struct rp_stream {
	uint8_t *wire;
	size_t *ends;
	size_t total;
} rp_stream;

static void rp_stream_build(const rp_conn *c, int dir, rp_stream *st)
{
	sim_sec_ctx ctx;
	const rp_frame *fr = dir ? c->c2s : c->s2c;
	size_t nf = dir ? c->nc : c->ns, i, off = 0, cap = (size_t)(dir ? c->bytes_c : c->bytes_s);

	memset(st, 0, sizeof(*st));
	WRT_CHECK(sim_sec_ctx_init(&ctx, c->secret, sizeof(c->secret), dir ? 0 : 1) == 0);
	st->wire = (uint8_t *)malloc(cap + 1u);
	st->ends = (size_t *)calloc(nf + 1u, sizeof(size_t));
	if (st->wire == NULL || st->ends == NULL)
		abort();
	for (i = 0; i < nf; i++) {
		const rp_frame *f = &fr[i];
		sim_sec_spec spec;
		size_t n = 0, k;
		uint8_t sha[32];
		uint8_t *w = st->wire + off;

		memset(&spec, 0, sizeof(spec));
		spec.tag = f->tag;
		spec.nseg = f->nseg;
		for (k = 0; k < f->nseg; k++) {
			spec.seg[k] = f->seg[k];
			spec.len[k] = f->len[k];
			spec.align[k] = f->align[k];
		}
		WRT_CHECK(sim_sec_encode(&ctx.tx, &spec, NULL, w, cap - off, &n) == 0);
		WRT_CHECK(n == f->wire_len);
		if (n != f->wire_len)
			break;
		rp_sha256(w, n, sha);
		WRT_CHECK(memcmp(sha, f->sha, 32) == 0); /* the simulator's wire is the real peer's wire, byte for byte (by hash) */
		if (f->wire != NULL)
			WRT_CHECK(memcmp(w, f->wire, n) == 0);
		off += n;
		st->ends[i] = off;
	}
	st->total = off;
	WRT_CHECK(st->total == cap);
	sim_sec_ctx_wipe(&ctx);
}

static void rp_stream_free(rp_stream *st)
{
	free(st->wire);
	free(st->ends);
	memset(st, 0, sizeof(*st));
}

static int rp_all_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != 0u)
			return 0;
	return 1;
}

/* ---- receive: the real parser, several deliveries -------------------------------------------------------------------------------------------------- */

typedef struct rp_pass {
	const char *name;
	const wr_prim_ops *prim;
	unsigned split, chunk, big_chunk, budget_small, budget_big;
	int via_ring_small;
	uint8_t sinks[4];
	int stop_at_big; /* stop the stream at the first elided frame: no big frame in this pass */
} rp_pass;

static void rp_clear_frame(sxr_out *o)
{
	unsigned k;

	for (k = 0; k < 4; k++)
		free(o->fr[0].seg[k]);
	memset(&o->fr[0], 0, sizeof(o->fr[0]));
	o->nframes = 0;
	o->nev = 0;
}

static void rp_rx_pass(const rp_conn *c, const rp_stream *st, const rp_pass *p, int dir)
{
	const uint8_t *wire = st->wire;
	const size_t *ends = st->ends;
	const rp_frame *frames = dir ? c->c2s : c->s2c;
	const size_t nframes = dir ? c->nc : c->ns;
	sxr r;
	sxr_out o;
	size_t i, k;
	uint64_t ops = 0;
	int rc;

	memset(&o, 0, sizeof(o));
	/* dir 0: the client's own parser reads the server's stream; dir 1: the parser of a server (crossed seeds) reads the client's stream */
	rc = sxr_init(&r, p->prim, c->secret, sizeof(c->secret), dir, RP_SEG0_CAP, RP_SEG_CAP_MAX, RP_RING);
	WRT_CHECK_U64(rc, 0);
	if (rc != 0)
		return;
	for (i = 0; i < nframes; i++) {
		const rp_frame *f = &frames[i];
		int big = f->wire_len >= RP_BIG_WIRE;
		sxr_cfg cfg;

		if (p->stop_at_big && f->wire == NULL)
			break;
		memset(&cfg, 0, sizeof(cfg));
		cfg.split = p->split;
		cfg.chunk = big ? p->big_chunk : p->chunk;
		cfg.budget = big ? p->budget_big : p->budget_small;
		cfg.seed = (uint32_t)(0x1234u + i * 7919u);
		cfg.via_ring = !big && p->via_ring_small;
		for (k = 1; k < 4; k++)
			cfg.sink_mode[k] = p->sinks[k];
		sxr_run(&r, wire, ends[i], &cfg, &o);
		if (o.nframes != 1u || o.errored || o.stalled || o.fed != ends[i]) {
			fprintf(stderr, "  [%s %s] frame %zu (tag %u, %llu wire bytes): frames %u errored %d (%d) stalled %d fed %zu want %zu\n", c->id, p->name, i, f->tag,
				(unsigned long long)f->wire_len, o.nframes, o.errored, (int)o.err, o.stalled, o.fed, ends[i]);
			WRT_CHECK(0);
			break;
		}
		{
			const sxr_frame *g = &o.fr[0];

			WRT_CHECK(g->ev == WRI_RXE_FRAME);
			WRT_CHECK(g->desc.tag == f->tag && g->desc.nseg == f->nseg && g->desc.flags == 0u);
			WRT_CHECK(g->seg0_at_event_ok);
			for (k = 0; k < f->nseg; k++) {
				WRT_CHECK_U64(g->desc.len[k], f->len[k]);
				WRT_CHECK_U64(g->stored[k], k > 0 && p->sinks[k] == SXR_SINK_NONE ? 0u : f->len[k]);
				if (k > 0 && p->sinks[k] == SXR_SINK_NONE) {
					WRT_CHECK(g->seg[k] == NULL);
				} else if (f->len[k] != 0u) {
					WRT_CHECK(g->seg[k] != NULL && memcmp(g->seg[k], f->seg[k], f->len[k]) == 0);
				}
			}
		}
		ops += f->nops;
		rp_clear_frame(&o);
		WRT_CHECK_U64(r.ring.len, 0u);
	}
	WRT_CHECK(o.guard_bad == 0u && o.order_bad == 0u && o.hidden_bad == 0u);
	if (!p->stop_at_big)
		WRT_CHECK_U64(r.slot.s.rx_n.ops, ops); /* one nonce per GCM operation, in wire order, and no more */
	sxr_out_free(&o);
	sxr_wipe(&r);
	/* the key, the nonces, the expanded key and the staged part 1 are gone, and so is what the bounce buffer carried */
	WRT_CHECK(rp_all_zero(&r.slot, sizeof(r.slot)));
	WRT_CHECK(rp_all_zero(r.bounce, sizeof(r.bounce)));
}

static void rp_rx_all(const rp_conn *c, const rp_stream *st, int dir, const wr_prim_ops *prim, int light)
{
	rp_pass a = {"whole", prim, 0, 0, 0, 0, 0, 0, {0, SXR_SINK_EXACT, SXR_SINK_EXACT, SXR_SINK_EXACT}, 0};
	rp_pass b = {"pieces", prim, 2, 1500, 1500, 16, 4096, 0, {0, SXR_SINK_BIG, SXR_SINK_BIG, SXR_SINK_BIG}, 0};
	rp_pass d = {"bytes", prim, 3, 1, 1448, 0, 0, 1, {0, SXR_SINK_NONE, SXR_SINK_EXACT, SXR_SINK_EXACT}, 1};

	WRT_CHECK(st->total == (dir ? c->bytes_c : c->bytes_s));
	rp_rx_pass(c, st, &a, dir);
	if (!light) {
		rp_rx_pass(c, st, &b, dir);
		rp_rx_pass(c, st, &d, dir);
	}
}

/* ---- damage ---------------------------------------------------------------------------------------------------------------------------------- */

static void rp_rx_damage(const rp_conn *c, const rp_stream *st)
{
	const size_t *ends = st->ends;
	const uint8_t *wire = st->wire;
	size_t i, first_multi = 0, k;
	sxr r;
	sxr_out o;
	sxr_cfg cfg;
	int rc;

	memset(&cfg, 0, sizeof(cfg));
	cfg.sink_mode[1] = cfg.sink_mode[2] = cfg.sink_mode[3] = SXR_SINK_EXACT;
	cfg.split = 0;
	for (i = 0; i < c->ns; i++)
		if (c->s2c[i].nseg > 1u && c->s2c[i].wire_len < RP_BIG_WIRE) {
			first_multi = i;
			break;
		}
	WRT_CHECK(first_multi > 0);

	/* a bit flipped in the first frame (AUTH_SIGNATURE, one operation): ciphertext, inline area, the tag: the tag fails before any event */
	for (k = 0; k < 3; k++) {
		static const size_t at[3] = {0, 70, 95};
		uint8_t *bad = (uint8_t *)malloc(ends[0]);

		memcpy(bad, wire, ends[0]);
		bad[at[k]] ^= 0x04u;
		memset(&o, 0, sizeof(o));
		WRT_CHECK_U64(sxr_init(&r, NULL, c->secret, sizeof(c->secret), 0, RP_SEG0_CAP, RP_SEG_CAP_MAX, RP_RING), 0);
		sxr_run(&r, bad, ends[0], &cfg, &o);
		WRT_CHECK(o.errored && o.err == WR_E_M2_SEC_TAG && o.nframes == 0u && o.nev == 1u && o.order_bad == 0u);
		sxr_out_free(&o);
		sxr_wipe(&r);
		free(bad);
	}

	/* the same stream read with the other direction's nonce (the server's view of the secret): the first tag fails */
	memset(&o, 0, sizeof(o));
	rc = sxr_init(&r, NULL, c->secret, sizeof(c->secret), 1, RP_SEG0_CAP, RP_SEG_CAP_MAX, RP_RING);
	WRT_CHECK_U64(rc, 0);
	sxr_run(&r, wire, ends[0], &cfg, &o);
	WRT_CHECK(o.errored && o.err == WR_E_M2_SEC_TAG && o.nframes == 0u);
	sxr_out_free(&o);
	sxr_wipe(&r);

	/* a flipped bit in the very last byte (the tag) of a multi-segment frame: the frames before it are delivered, the frame itself never is */
	{
		size_t cut = ends[first_multi];
		uint8_t *bad = (uint8_t *)malloc(cut);

		memcpy(bad, wire, cut);
		bad[cut - 1u] ^= 0x80u;
		memset(&o, 0, sizeof(o));
		WRT_CHECK_U64(sxr_init(&r, NULL, c->secret, sizeof(c->secret), 0, RP_SEG0_CAP, RP_SEG_CAP_MAX, RP_RING), 0);
		/* one frame at a time, so that the record of the rig never overflows */
		for (i = 0; i < first_multi; i++) {
			sxr_run(&r, bad, ends[i], &cfg, &o);
			WRT_CHECK(o.nframes == 1u && !o.errored);
			rp_clear_frame(&o);
		}
		sxr_run(&r, bad, cut, &cfg, &o);
		WRT_CHECK(o.errored && o.err == WR_E_M2_SEC_TAG && o.nframes == 0u);
		sxr_out_free(&o);
		sxr_wipe(&r);
		free(bad);
	}

	/* a frame sent twice: the second copy was sealed under a nonce that is spent, its tag fails */
	{
		size_t n0 = ends[0];
		uint8_t *twice = (uint8_t *)malloc(2u * n0);

		memcpy(twice, wire, n0);
		memcpy(twice + n0, wire, n0);
		memset(&o, 0, sizeof(o));
		WRT_CHECK_U64(sxr_init(&r, NULL, c->secret, sizeof(c->secret), 0, RP_SEG0_CAP, RP_SEG_CAP_MAX, RP_RING), 0);
		sxr_run(&r, twice, n0, &cfg, &o);
		WRT_CHECK(o.nframes == 1u && !o.errored);
		rp_clear_frame(&o);
		sxr_run(&r, twice, 2u * n0, &cfg, &o);
		WRT_CHECK(o.errored && o.err == WR_E_M2_SEC_TAG && o.nframes == 0u);
		sxr_out_free(&o);
		sxr_wipe(&r);
		free(twice);
	}

	/* the last frame cut one byte short: everything before it is delivered, nothing for the cut frame, no error */
	{
		size_t cut = ends[first_multi] - 1u;

		memset(&o, 0, sizeof(o));
		WRT_CHECK_U64(sxr_init(&r, NULL, c->secret, sizeof(c->secret), 0, RP_SEG0_CAP, RP_SEG_CAP_MAX, RP_RING), 0);
		for (i = 0; i < first_multi; i++) {
			sxr_run(&r, wire, ends[i], &cfg, &o);
			WRT_CHECK(o.nframes == 1u && !o.errored);
			rp_clear_frame(&o);
		}
		sxr_run(&r, wire, cut, &cfg, &o);
		WRT_CHECK(!o.errored && !o.stalled && o.nframes == 0u);
		sxr_out_free(&o);
		sxr_wipe(&r);
	}
}

/*
 * Every kind of byte of every recorded server frame, damaged one bit at a time: for each GCM operation of the frame (part 1, part 2, part 3, by the layout of
 * sec.md 2.8, worked out here from the segment lengths and not by the core) the first, the middle and the last byte of its ciphertext and the first and the
 * last byte of its tag, and the epilogue block of part 3. Whatever the byte, the stream is refused with WR_E_M2_SEC_TAG at that frame: the frames before it
 * were delivered, the damaged one never is, no event of it reaches the owner before the operation that carries the damage (segment 0 of a frame is shown
 * only after the operation that ends it verified, so a flip in part 3 may be preceded by SEG0 and nothing else, a flip in part 1 or 2 by nothing), the
 * rig's guard bands and its order / stickiness checks hold, and the key material is gone after the wipe. The same stream cut at those points shows no
 * event of the frame and no error (a frame that is not complete is waited for, never guessed). The first byte of a frame is the preamble, so this also
 * covers a damaged preamble: it is the tag that refuses it, before its lengths are looked at.
 */
#define RP_MAX_POINTS 24u

typedef struct rp_point {
	uint64_t at; /* offset in the frame's wire bytes */
	unsigned part;
} rp_point;

static void rp_add_point(rp_point *pt, size_t *n, uint64_t at, unsigned part)
{
	WRT_CHECK(*n < RP_MAX_POINTS);
	if (*n >= RP_MAX_POINTS)
		return;
	pt[*n].at = at;
	pt[*n].part = part;
	(*n)++;
}

static size_t rp_points(const rp_frame *f, rp_point *pt)
{
	size_t n = 0;
	uint64_t start = 0, ct;
	unsigned part, nparts = 1;
	uint64_t l0 = f->len[0], rest = 0;
	unsigned k;

	if (l0 > 48u)
		nparts = 2;
	for (k = 1; k < f->nseg; k++)
		rest += (f->len[k] + 15u) & ~15ull;
	if (f->nseg > 1)
		nparts++;
	for (part = 1; part <= nparts; part++) {
		unsigned kind;

		/* the kind of the part: 1 = the first 80 bytes, 2 = the rest of segment 0, 3 = the other segments and the epilogue */
		kind = part == 1 ? 1u : (part == 2 && l0 > 48u) ? 2u : 3u;
		ct = kind == 1 ? 80u : kind == 2 ? ((l0 + 15u) & ~15ull) - 48u : rest + 16u;
		rp_add_point(pt, &n, start, kind);                /* the first ciphertext byte */
		rp_add_point(pt, &n, start + ct / 2u, kind);
		rp_add_point(pt, &n, start + ct - 1u, kind);      /* the last ciphertext byte */
		rp_add_point(pt, &n, start + ct, kind);           /* the first byte of the tag */
		rp_add_point(pt, &n, start + ct + 15u, kind);     /* the last byte of the tag */
		if (kind == 3u)
			rp_add_point(pt, &n, start + ct - 16u, kind); /* the epilogue block */
		start += ct + 16u;
	}
	WRT_CHECK(start == f->wire_len);
	return n;
}

static void rp_rx_flips(const rp_conn *c, const rp_stream *st, const wr_prim_ops *prim)
{
	size_t i, j, np;
	int seen_big = 0;
	rp_point pt[RP_MAX_POINTS];

	for (i = 0; i < c->ns; i++) {
		const rp_frame *f = &c->s2c[i];
		const size_t start = i == 0 ? 0u : st->ends[i - 1];

		np = rp_points(f, pt);
		for (j = 0; j < np; j++) {
			sxr r;
			sxr_out o;
			sxr_cfg cfg;
			size_t n = st->ends[i], pos = start + (size_t)pt[j].at;
			uint8_t *bad;
			unsigned want_ev = 2u * (unsigned)i + 1u + (pt[j].part == 3u ? 1u : 0u);
			int cut_pass;

			/* after a 1 MiB frame only the first and the last byte of a frame are damaged: every run decrypts the whole prefix again */
			if (seen_big && j != 0 && j + 1 != np)
				continue;
			WRT_CHECK(pos < n);
			for (cut_pass = 0; cut_pass < 2; cut_pass++) {
				size_t feed = cut_pass ? pos : n; /* pass 1: the stream cut off at the point (nothing damaged) */

				if (cut_pass && pt[j].at == 0u)
					continue; /* a cut at the start of the frame: that is the end of the frame before */
				bad = (uint8_t *)malloc(n);
				if (bad == NULL)
					abort();
				memcpy(bad, st->wire, n);
				if (!cut_pass)
					bad[pos] ^= (uint8_t)(1u << ((i + j) & 7u));
				memset(&o, 0, sizeof(o));
				memset(&cfg, 0, sizeof(cfg));
				cfg.sink_mode[1] = cfg.sink_mode[2] = cfg.sink_mode[3] = SXR_SINK_EXACT;
				WRT_CHECK_U64(sxr_init(&r, prim, c->secret, sizeof(c->secret), 0, RP_SEG0_CAP, RP_SEG_CAP_MAX, RP_RING), 0);
				sxr_run(&r, bad, feed, &cfg, &o);
				if (!cut_pass) {
					WRT_CHECK(o.errored && o.err == WR_E_M2_SEC_TAG);
					WRT_CHECK_U64(o.nframes, i);
					WRT_CHECK_U64(o.nev, want_ev);
					WRT_CHECK(o.evs[o.nev - 1u] == WRI_RXE_ERROR);
				} else {
					WRT_CHECK(!o.errored && !o.stalled);
					WRT_CHECK_U64(o.nframes, i);
				}
				WRT_CHECK(o.guard_bad == 0u && o.order_bad == 0u && o.hidden_bad == 0u);
				if (o.errored || o.nframes != i) {
					fprintf(stderr, "  [%s] frame %zu (tag %u, %llu wire bytes), %s at +%llu (part %u): errored %d (%d) frames %u events %u\n", c->id, i, f->tag,
						(unsigned long long)f->wire_len, cut_pass ? "cut" : "bit flipped", (unsigned long long)pt[j].at, pt[j].part, o.errored, (int)o.err,
						o.nframes, o.nev);
				}
				sxr_out_free(&o);
				sxr_wipe(&r);
				WRT_CHECK(rp_all_zero(&r.slot, sizeof(r.slot)));
				free(bad);
			}
		}
		if (f->wire == NULL)
			seen_big = 1;
	}
}

/* ---- transmit ---------------------------------------------------------------------------------------------------------------------------------- */

typedef struct rp_txpass {
	const char *name;
	const wr_prim_ops *prim;
	size_t step;        /* host bytes per cycle, 0 = everything shown */
	int random;
	int copy_segs;      /* segments 1 and 2 as copies (ref = 0) */
	int stop_at_big;
	int decode;         /* the independent decoder reads the result back */
	uint32_t enc_cap, bounce_cap;
} rp_txpass;

static void rp_tx_pass(const rp_conn *c, const rp_txpass *p)
{
	txr r;
	size_t i, k;
	uint64_t ops = 0;
	wr_status st;

	st = txr_open(&r, p->enc_cap, p->bounce_cap, p->prim, c->secret);
	WRT_CHECK_STATUS(WR_OK, st);
	if (st != WR_OK)
		return;
	r.noref = 1; /* the expectation here is the recorded wire, not the independent encoder (that is the receive side's job, above) */
	r.keep = p->decode;
	for (i = 0; i < c->nc; i++) {
		const rp_frame *f = &c->c2s[i];
		wri_m2_seg_src seg[4];
		size_t before = r.wire_len;
		uint8_t sha[32];

		if (p->stop_at_big && f->wire == NULL)
			break;
		memset(seg, 0, sizeof(seg));
		for (k = 0; k < f->nseg; k++) {
			seg[k].p = f->len[k] != 0u ? f->seg[k] : NULL;
			seg[k].len = f->len[k];
			seg[k].ref = (uint8_t)(k > 0 && !(p->copy_segs && k < 3u));
		}
		st = txr_send(&r, f->tag, seg, f->nseg);
		WRT_CHECK_STATUS(WR_OK, st);
		if (st != WR_OK)
			break;
		txr_drain(&r, f->wire_len >= RP_BIG_WIRE && p->step != 0 && p->step < 1000u ? 0u : p->step, p->random);
		WRT_CHECK_U64(r.wire_len - before, f->wire_len);
		if (r.wire_len - before == f->wire_len) {
			if (f->wire != NULL) {
				WRT_CHECK(memcmp(r.wire + before, f->wire, (size_t)f->wire_len) == 0);
			} else {
				rp_sha256(r.wire + before, (size_t)f->wire_len, sha);
				WRT_CHECK(memcmp(sha, f->sha, 32) == 0);
			}
		}
		ops += f->nops;
	}
	if (!p->stop_at_big)
		WRT_CHECK_U64(r.slot.s.tx_n.ops, ops);
	if (p->decode)
		txr_check_decode(&r, 0);
	txr_close(&r);
}

static void rp_tx_all(const rp_conn *c, const wr_prim_ops *prim, int light)
{
	rp_txpass a = {"all at once", prim, 0, 0, 0, 0, 1, 4096, 4096};
	rp_txpass b = {"random pieces, copies", prim, 1500, 1, 1, 0, 0, 2048, 256};
	rp_txpass d = {"61 bytes", prim, 61, 0, 0, 1, 0, 4096, 1024};

	rp_tx_pass(c, &a);
	if (!light) {
		rp_tx_pass(c, &b);
		rp_tx_pass(c, &d);
	}
}

/* ---- the pre-auth signature ------------------------------------------------------------------------------------------------------------------ */

static void rp_signatures(const rp_conn *c)
{
	wri_m2_preauth pa, pb;
	const uint32_t cap = (uint32_t)(c->hs_s_len > c->hs_c_len ? c->hs_s_len : c->hs_c_len) + 16u;
	uint8_t *rxb = (uint8_t *)calloc(cap, 1), *txb = (uint8_t *)calloc(cap, 1), ours[32], expect[32], bad[32], key[32];
	size_t i;

	if (rxb == NULL || txb == NULL)
		abort();
	wri_m2_preauth_init(&pa, rxb, txb, cap);
	/* the connection logs what it reads and writes in pieces: feed the recorded bytes the same way */
	for (i = 0; i < c->hs_s_len; i += 37u)
		wri_m2_preauth_rx(&pa, c->hs_s + i, c->hs_s_len - i < 37u ? c->hs_s_len - i : 37u);
	for (i = 0; i < c->hs_c_len; i += 53u)
		wri_m2_preauth_tx(&pa, c->hs_c + i, c->hs_c_len - i < 53u ? c->hs_c_len - i : 53u);
	/* still logging: the verify entry point refuses (our own signature frame could end up in the log) */
	WRT_CHECK(c->ns >= 1u && c->s2c[0].len[0] == 32u);
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_sig_verify(NULL, &pa, c->skey, c->skey_len, c->s2c[0].seg[0]));
	wri_m2_preauth_stop(&pa);
	WRT_CHECK_STATUS(WR_OK, pa.err);
	wri_m2_sig_ours(NULL, &pa, c->skey, c->skey_len, ours);
	wri_m2_sig_expected(NULL, &pa, c->skey, c->skey_len, expect);
	WRT_CHECK(c->nc >= 1u && c->c2s[0].tag == 7 && c->c2s[0].len[0] == 32u && memcmp(ours, c->c2s[0].seg[0], 32) == 0);
	WRT_CHECK(c->ns >= 1u && c->s2c[0].tag == 7 && c->s2c[0].len[0] == 32u && memcmp(expect, c->s2c[0].seg[0], 32) == 0);
	WRT_CHECK(memcmp(ours, expect, 32) != 0); /* the two directions sign different transcripts */

	/* the verify entry point of the connection: the server's recorded signature passes, and nothing near it does */
	WRT_CHECK_STATUS(WR_OK, wri_m2_sig_verify(NULL, &pa, c->skey, c->skey_len, c->s2c[0].seg[0]));
	WRT_CHECK_STATUS(WR_E_M2_SIGNATURE, wri_m2_sig_verify(NULL, &pa, c->skey, c->skey_len, ours)); /* the other direction's signature */
	for (i = 0; i < 256u; i++) { /* every single bit of the signature */
		memcpy(bad, c->s2c[0].seg[0], 32);
		bad[i >> 3] ^= (uint8_t)(1u << (i & 7u));
		WRT_CHECK_STATUS(WR_E_M2_SIGNATURE, wri_m2_sig_verify(NULL, &pa, c->skey, c->skey_len, bad));
	}
	for (i = 0; i < c->skey_len; i++) { /* every byte of the session key: a signature under another key is another signature */
		memcpy(key, c->skey, c->skey_len);
		key[i] ^= 0x40u;
		WRT_CHECK_STATUS(WR_E_M2_SIGNATURE, wri_m2_sig_verify(NULL, &pa, key, c->skey_len, c->s2c[0].seg[0]));
	}
	/* a key that is not there is a caller bug, never the all-zero signature of "no authentication" */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_sig_verify(NULL, &pa, NULL, c->skey_len, c->s2c[0].seg[0]));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_sig_verify(NULL, &pa, c->skey, 0, c->s2c[0].seg[0]));
	/* a transcript without its first byte (the banner is part of it) and a transcript with one more byte sign something else */
	wri_m2_preauth_init(&pb, rxb, txb, cap);
	wri_m2_preauth_rx(&pb, c->hs_s + 1, c->hs_s_len - 1u);
	wri_m2_preauth_tx(&pb, c->hs_c + 1, c->hs_c_len - 1u);
	wri_m2_preauth_stop(&pb);
	WRT_CHECK_STATUS(WR_E_M2_SIGNATURE, wri_m2_sig_verify(NULL, &pb, c->skey, c->skey_len, c->s2c[0].seg[0]));
	/* a log that does not fit its buffers is an error of its own, sticky, and no signature is compared against it */
	wri_m2_preauth_init(&pb, rxb, txb, (uint32_t)c->hs_c_len - 1u);
	wri_m2_preauth_rx(&pb, c->hs_s, c->hs_s_len > c->hs_c_len - 1u ? c->hs_c_len - 1u : c->hs_s_len);
	wri_m2_preauth_tx(&pb, c->hs_c, c->hs_c_len);
	wri_m2_preauth_tx(&pb, c->hs_c, 1); /* nothing is appended after the error */
	wri_m2_preauth_stop(&pb);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, pb.err);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, wri_m2_sig_verify(NULL, &pb, c->skey, c->skey_len, c->s2c[0].seg[0]));

	wri_m2_preauth_wipe(&pa);
	WRT_CHECK(rp_all_zero(rxb, cap) && rp_all_zero(txb, cap)); /* both logs are erased by the wipe (every byte the second log held lies inside the first) */
	free(rxb);
	free(txb);
}

/* ---- one session ------------------------------------------------------------------------------------------------------------------------------ */

static void rp_session(const char *name, const wr_prim_ops *accel)
{
	rp_sess s;
	size_t i;
	uint64_t mon_conns = 0, osd_conns = 0, frames = 0, big = 0;

	if (rp_load_session(&s, name) != 0) {
		fprintf(stderr, "session %s does not load\n", name);
		WRT_CHECK(0);
		return;
	}
	WRT_CHECK(s.nconn >= 2u);
	for (i = 0; i < s.nconn; i++) {
		const rp_conn *c = &s.conn[i];
		size_t j;

		fprintf(stderr, "  %s %s: %zu client frames (%llu wire bytes), %zu server frames (%llu wire bytes)\n", name, c->id, c->nc, (unsigned long long)c->bytes_c,
			c->ns, (unsigned long long)c->bytes_s);
		if (c->is_mon)
			mon_conns++;
		else
			osd_conns++;
		frames += c->nc + c->ns;
		for (j = 0; j < c->nc; j++)
			big += c->c2s[j].wire == NULL;
		for (j = 0; j < c->ns; j++)
			big += c->s2c[j].wire == NULL;
		WRT_CHECK(c->nc >= 2u && c->ns >= 2u && c->c2s[1].tag == 8 && c->s2c[1].tag == 9); /* CLIENT_IDENT, SERVER_IDENT: no COMPRESSION frame in between */
		rp_signatures(c);
		{
			rp_stream ss, cs;

			rp_stream_build(c, 0, &ss);
			rp_stream_build(c, 1, &cs);
			rp_rx_all(c, &ss, 0, NULL, 0);
			rp_rx_all(c, &cs, 1, NULL, 0); /* the recorded client stream through the parser of a server: the core's transmit and receive agree with the real client */
			rp_tx_all(c, NULL, 0);
			if (accel != NULL) {
				rp_rx_all(c, &ss, 0, accel, 1);
				rp_rx_all(c, &cs, 1, accel, 1);
				rp_tx_all(c, accel, 1);
			}
			if (i == 0 || (!c->has_elided_s && i == 1))
				rp_rx_damage(c, &ss);
			rp_rx_flips(c, &ss, NULL);
			if (accel != NULL && i == 0)
				rp_rx_flips(c, &ss, accel); /* the host's GCM must refuse the same bytes (a hook that forgets the tag would pass everything else) */
			rp_stream_free(&ss);
			rp_stream_free(&cs);
		}
	}
	WRT_CHECK(mon_conns >= 1u && osd_conns >= 1u && frames > 20u && big >= 2u);
	rp_free_session(&s);
}

/* ---- the refusals -------------------------------------------------------------------------------------------------------------------------------- */

static void rp_refusals(void)
{
	wrt_json j;
	wrt_tok atts;
	size_t i, n;

	WRT_CHECK(wrt_json_load_vec(&j, "public/secure/refusals.json") == 0);
	atts = wrt_json_get(&j, wrt_json_root(&j), "attempts");
	n = wrt_json_count(&j, atts);
	WRT_CHECK(n >= 8u);
	for (i = 0; i < n; i++) {
		wrt_tok a = wrt_json_at(&j, atts, i);
		char *name = wrt_json_strdup(&j, wrt_json_get(&j, a, "name")), *setting = wrt_json_strdup(&j, wrt_json_get(&j, a, "server_setting"));
		uint8_t *s2c = NULL;
		size_t s2c_n = 0, hello_end = 0, bm_len = 0;
		uint64_t key_type = 0;
		int secure_only = setting != NULL && strcmp(setting, "secure-only") == 0;
		rig r;
		int shape_ok = 0;

		WRT_CHECK(name != NULL && setting != NULL && wrt_json_get_hex(&j, a, "s2c", &s2c, &s2c_n) == 0 && s2c_n > 98u);
		WRT_CHECK(rp_get_int(&j, a, "key_type", &key_type) == 0 && (key_type == 1u || key_type == 2u));
		/* the server's bytes: banner (26), HELLO, then the AUTH_BAD_METHOD frame; both are crc frames of one segment. A record that is not of this
		 * shape is a failure of the test, never a read past its bytes. */
		if (s2c != NULL && s2c_n > 98u) {
			hello_end = 26u + 32u + (size_t)wri_le32_get(s2c + 26u + 2u) + 4u;
			if (hello_end + 34u <= s2c_n) {
				bm_len = s2c_n - hello_end;
				shape_ok = (uint64_t)bm_len == 32u + (uint64_t)wri_le32_get(s2c + hello_end + 2u) + 4u && s2c[hello_end] == 3u; /* AUTH_BAD_METHOD */
			}
		}
		WRT_CHECK(shape_ok);
		if (!shape_ok) {
			free(s2c);
			free(name);
			free(setting);
			continue;
		}
		/* a connection that offered only the mode this server does not allow, which has sent its AUTH_REQUEST and waits for the answer */
		rig_init(&r);
		rig_enable_secure(&r, secure_only ? WRI_M2_OFFER_CRC : WRI_M2_OFFER_SECURE);
		r.scfg.f.out_limit = (int64_t)hello_end;
		rig_start(&r);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_AUTH);
		rig_inject(&r, s2c + hello_end, bm_len);
		rig_check_failed(&r, WR_E_M2_BAD_METHOD);
		WRT_CHECK_U64((int64_t)r.c.err.peer_result, -95);                 /* EOPNOTSUPP: sec.md 6.4 */
		WRT_CHECK_U64(r.c.err.a0, 1u << 2);                               /* allowed methods {cephx} */
		WRT_CHECK_U64(r.c.err.a1, secure_only ? 1u << 2 : 1u << 1);       /* allowed modes: bit v = mode v (1 crc, 2 secure) */
		WRT_CHECK_U64(r.c.err.a2, 2);                                     /* the method we offered */
		rig_free(&r);
		free(s2c);
		free(name);
		free(setting);
	}
	wrt_json_free(&j);
}

int main(void)
{
	const char *accel_env = getenv("WRT_GCM_ACCEL");
	wr_prim_ops accel;
	int want_accel = accel_env == NULL || strcmp(accel_env, "0") != 0;
	const wr_prim_ops *ap = NULL;

	if (!rp_present())
		WRT_SKIP("harness/vectors/public/secure is not part of this source tree");
	if (want_accel && wrl_gcm_aesni_available() && wrl_gcm_aesni_ops(&accel) == 0)
		ap = &accel;
	rp_session("k2", ap);
	rp_session("k1", ap);
	rp_refusals();
	return wrt_finish();
}
