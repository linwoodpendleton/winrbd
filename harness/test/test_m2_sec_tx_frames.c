/* SPDX-License-Identifier: MIT */
/*
 * test_m2_sec_tx_frames - the secure transmit side, frame by frame (core/src/msgr2/wri_m2_sec_tx.c, design 34.6): what the builder puts on
 * the wire for every shape, and what it does before it is allowed to take a nonce.
 *
 * What is checked:
 *   - frames A and B of docs/spec/msgr2-secure-mode.md 5.2 byte for byte, and every frame of secure-frames-synthetic.json in both directions
 *     (the server's view is the client's with the two nonce seeds swapped in the secret), 1, 2 and 3 operations, a 4096-byte data segment;
 *   - every shape of the size table of the spec: 1, 2 and 3 operations, an empty segment 0, len_0 = 47, 48, 49, 95, 96, 97, segments of 1, 15,
 *     16 and 17 bytes, four segments, a 4 MiB data segment; the bytes equal the independent encoder's (same key, same nonces), the independent
 *     decoder of sim_m2_sec reads them back segment by segment, the pending count is the wire size from the start, the operations taken are the
 *     table's; all of it with an encode buffer that holds whole frames and with one that forces the stream, and with a 1 MiB / 4 MiB bounce;
 *   - an exhaustive sweep of every len_0 from 0 to 130 against the segment lengths around the block size;
 *   - what happens before a nonce is taken: a bad shape (tag 0, 23, no segments, five, an empty last segment, bytes without a pointer), a frame
 *     that never fits, one that does not fit now, a stream that is still going: no nonce is taken (the nonce state is byte for byte unchanged,
 *     and the next frame that is accepted has the next nonce on the wire); the operation limit refuses all-or-none and says WR_E_M2_NONCE;
 *   - the status the queue records (WR_E_TOOBIG, not WR_E_BUSY) and the dispatch of wri_m2_tx_frame into the codec;
 *   - the copy rule: a segment without `ref` is out of the caller's memory when the call returns (poisoned and freed at once, then drained,
 *     in every host step), the head of part 3 up to the last copy is encrypted at once and counts as room needed now (BUSY / TOOBIG before
 *     any nonce), segment 3 is referenced whatever its flag says; no banner can be queued behind the switch;
 *   - the caller's memory is only read: a read-only mapping with a no-access page right behind the data, and never beyond its last byte;
 *   - an encode buffer that is full of other frames, the gather list at its limit (a frame that needs a new entry when all eight are used);
 *   - a refusal after the nonces were taken (a host that cannot start an operation) leaves the queue as it was, the key wiped, every later frame
 *     WR_E_STATE; the wipe of the slot and the bounce buffer at the end of the connection;
 *   - everything again with the accelerated GCM hook when WRT_GCM_ACCEL=1 and the CPU has it.
 */
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "wrt.h"

#define TXR_CHECK WRT_CHECK
#include "m2_sec_tx_rig.h"

#include "../host/wrl_gcm_aesni.c"

#include "wri_m2_modes.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

static const wr_prim_ops *g_prim; /* NULL = portable GCM; the accelerated table on the second pass */

/* ---- frames ----------------------------------------------------------------------------------------------------- */

typedef struct fb {
	uint8_t *p[4];
	wri_m2_seg_src s[4];
	unsigned n;
} fb;

static uint8_t pat(unsigned seg, size_t i)
{
	return (uint8_t)(0x31u * (seg + 1u) + i * 13u + (i >> 7));
}

/* Segments of exactly the given sizes (allocated exactly, so a read past the end is an ASan report), patterned. */
static void fb_make(fb *f, unsigned nseg, const uint32_t *len)
{
	unsigned i;
	size_t k;

	memset(f, 0, sizeof(*f));
	f->n = nseg;
	for (i = 0; i < nseg; i++) {
		if (len[i] != 0u) {
			f->p[i] = (uint8_t *)malloc(len[i]);
			WRT_CHECK(f->p[i] != NULL);
			for (k = 0; k < len[i]; k++)
				f->p[i][k] = pat(i, k);
		}
		f->s[i].p = f->p[i];
		f->s[i].len = len[i];
		f->s[i].ref = 1; /* referenced: the tests of the stream free the memory when the host consumed it; the copy rule has its own test */
	}
}

static void fb_free(fb *f)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		free(f->p[i]);
}

static uint64_t pad16u(uint64_t x)
{
	return (x + 15u) & ~(uint64_t)15u;
}

/* The wire arithmetic written out here, independent of the core's: parts 1 (96), 2 (when len_0 > 48), 3 (when there are more segments). */
static void shape_bytes(unsigned nseg, const uint32_t *len, uint64_t *p12, uint64_t *p3, unsigned *ops)
{
	unsigned i;

	*p12 = 96u;
	*p3 = 0;
	*ops = 1u;
	if (len[0] > 48u) {
		*p12 += pad16u(len[0]) - 48u + 16u;
		(*ops)++;
	}
	if (nseg > 1u) {
		for (i = 1; i < nseg; i++)
			*p3 += pad16u(len[i]);
		*p3 += 32u;
		(*ops)++;
	}
}

static uint64_t ops_taken(const txr *r)
{
	return r->slot.s.tx_n.ops;
}

/* Send one frame of this shape into an empty queue and drain it; the verdict has to be the one the room rule predicts. */
static void check_shape(txr *r, uint8_t tag, unsigned nseg, const uint32_t *len, size_t step)
{
	fb f;
	uint64_t p12, p3, before = ops_taken(r);
	unsigned nops;
	wr_status st, want;

	fb_make(&f, nseg, len);
	shape_bytes(nseg, len, &p12, &p3, &nops);
	want = p12 > r->enc_cap ? WR_E_TOOBIG : WR_OK;
	st = txr_send(r, tag, f.s, nseg);
	WRT_CHECK_STATUS(want, st);
	if (st == WR_OK) {
		WRT_CHECK_U64(r->q.pending, p12 + p3); /* exact from the frame start */
		WRT_CHECK_U64(ops_taken(r) - before, nops);
		txr_check_queue(r);
		txr_drain(r, step, 0);
	} else {
		WRT_CHECK_U64(ops_taken(r), before);
		WRT_CHECK(wri_m2_txq_idle(&r->q));
	}
	fb_free(&f);
}

/* ---- the worked example and the vector file ---------------------------------------------------------------------- */

static const char frame_a_hex[] =
	"5ee83e477793cc7cbb381480b30cc69431dabdf879b50b483d403cfd1b1ec96a"
	"e363935876ea5233f5930611558cad49725d69ea832d072f15bad3bf4b43581f"
	"01654a9d4a848c689172d4521fcf8108ee387f09dafe616e6a0c5adfa581ad5e";
static const char frame_b_hex[] =
	"98283b6ff8ab6493cd1f43d679c4a3a38a8577da66639b20d42f050521ea2d40"
	"4380360af91a14019d02906a063be428f187b4b3c0183c65656b15d047b91e7a"
	"e9f5a5aadcdc5350ca29264420199b1b20d32c03240c290bc1cc826c68a2c43c"
	"31004d2d0a48882efde2210977ac057a35e0d0b282f4010584c004c4ffd0a4ca"
	"f5a419f42a8a57c28a08980d974b4183";

static void test_spec_frames(void)
{
	static const uint32_t cfg[][2] = {{4096u, 4096u}, {512u, 256u}, {160u, 272u}}; /* whole in the encode buffer; streamed pieces */
	unsigned c;

	for (c = 0; c < 3u; c++) {
		txr r;
		uint8_t *want = NULL, *want_b = NULL;
		size_t n = 0, nb = 0;
		uint8_t a[32], x[20], y[10];
		wri_m2_seg_src sa, sb[2];

		WRT_CHECK_STATUS(WR_OK, txr_open(&r, cfg[c][0], cfg[c][1], g_prim, NULL));
		memset(a, 0xa5, sizeof(a));
		memset(x, 0x11, sizeof(x));
		memset(y, 0x22, sizeof(y));
		sa.p = a;
		sa.len = sizeof(a);
		sa.ref = 1;
		sb[0].p = x;
		sb[0].len = sizeof(x);
		sb[0].ref = 1;
		sb[1].p = y;
		sb[1].len = sizeof(y);
		sb[1].ref = 1;
		WRT_CHECK(wrt_hex_decode(frame_a_hex, strlen(frame_a_hex), &want, &n) == 0 && n == 96u);
		WRT_CHECK(wrt_hex_decode(frame_b_hex, strlen(frame_b_hex), &want_b, &nb) == 0 && nb == 144u);
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_AUTH_SIGNATURE, &sa, 1));
		WRT_CHECK_U64(r.q.pending, 96);
		txr_drain(&r, c == 2u ? 7u : 0u, 0);
		WRT_CHECK(r.wire_len == 96u && memcmp(r.wire, want, 96) == 0); /* frame A byte for byte */
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, sb, 2));
		WRT_CHECK_U64(r.q.pending, 144);
		txr_drain(&r, c == 2u ? 16u : 0u, 0);
		WRT_CHECK(r.wire_len == 96u + 144u && memcmp(r.wire + 96, want_b, 144) == 0); /* frame B byte for byte */
		WRT_CHECK(txr_wire_matches(&r));
		free(want);
		free(want_b);
		txr_close(&r);
	}
}

/* Run the frames of one direction of the vector file; swapped = the secret with its two seeds exchanged (the server's transmit stream). */
static void run_vector_dir(const wrt_json *j, const char *dir, int swapped, uint32_t enc_cap, uint32_t bounce_cap)
{
	wrt_tok arr = wrt_json_get(j, wrt_json_root(j), dir);
	size_t i, nfr = wrt_json_count(j, arr);
	uint8_t secret[64];
	uint64_t ops_sum = 0;
	txr r;

	for (i = 0; i < sizeof(secret); i++)
		secret[i] = (uint8_t)i;
	if (swapped) {
		for (i = 0; i < 12u; i++) {
			uint8_t t = secret[16u + i];

			secret[16u + i] = secret[28u + i];
			secret[28u + i] = t;
		}
	}
	WRT_CHECK_STATUS(WR_OK, txr_open(&r, enc_cap, bounce_cap, g_prim, secret));
	WRT_CHECK(nfr > 0u);
	for (i = 0; i < nfr; i++) {
		wrt_tok c = wrt_json_at(j, arr, i), segs = wrt_json_get(j, c, "segments");
		unsigned k, ns = (unsigned)wrt_json_count(j, segs), nseg;
		uint32_t len[4] = {0, 0, 0, 0};
		uint8_t fill[4] = {0, 0, 0, 0};
		uint8_t *seg[4] = {NULL, NULL, NULL, NULL};
		wri_m2_seg_src src[4];
		uint8_t *wire = NULL;
		size_t wire_n = 0, before = r.wire_len;
		int ok = 0;

		for (k = 0; k < ns && k < 4u; k++) {
			wrt_tok s = wrt_json_at(j, segs, k);

			len[k] = (uint32_t)wrt_json_int(j, wrt_json_get(j, s, "length"), &ok);
			fill[k] = (uint8_t)wrt_json_int(j, wrt_json_get(j, s, "fill_byte"), &ok);
		}
		nseg = ns;
		while (nseg > 1u && len[nseg - 1u] == 0u) /* a sender drops trailing empty segments */
			nseg--;
		memset(src, 0, sizeof(src));
		for (k = 0; k < nseg; k++) {
			if (len[k] != 0u) {
				seg[k] = (uint8_t *)malloc(len[k]);
				WRT_CHECK(seg[k] != NULL);
				memset(seg[k], fill[k], len[k]);
			}
			src[k].p = seg[k];
			src[k].len = len[k];
			src[k].ref = 1; /* referenced: freed only after the host consumed the frame (the copy rule has its own test) */
		}
		WRT_CHECK(wrt_json_get_hex(j, c, "wire_hex", &wire, &wire_n) == 0);
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, (uint8_t)wrt_json_int(j, wrt_json_get(j, c, "tag"), &ok), src, nseg));
		txr_drain(&r, 0, 0);
		WRT_CHECK(r.wire_len - before == wire_n && memcmp(r.wire + before, wire, wire_n) == 0);
		ops_sum += (uint64_t)wrt_json_int(j, wrt_json_get(j, c, "gcm_operations"), &ok);
		WRT_CHECK_U64(r.slot.s.tx_n.ops, ops_sum); /* the operations of the table, nonce by nonce */
		for (k = 0; k < 4u; k++)
			free(seg[k]);
		free(wire);
	}
	WRT_CHECK(txr_wire_matches(&r));
	txr_close(&r);
}

static void test_vector_file(void)
{
	wrt_json j;
	static const uint32_t cfg[][2] = {{65536u, 4096u}, {1024u, 256u}};
	unsigned c;

	if (wrt_json_load_vec(&j, "secure/secure-frames-synthetic.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	for (c = 0; c < 2u; c++) {
		run_vector_dir(&j, "client_to_server", 0, cfg[c][0], cfg[c][1]);
		run_vector_dir(&j, "server_to_client", 1, cfg[c][0], cfg[c][1]);
	}
	wrt_json_free(&j);
}

/* ---- the size table, every shape ---------------------------------------------------------------------------------- */

static void shape_sweep(uint32_t enc_cap, uint32_t bounce_cap, size_t step)
{
	static const uint32_t l0s[] = {0, 1, 8, 41, 47, 48, 49, 63, 64, 95, 96, 97, 100, 112, 113, 200};
	static const uint32_t segs[] = {1, 15, 16, 17, 31, 32, 33, 100};
	txr r;
	unsigned a, b, c, d;

	WRT_CHECK_STATUS(WR_OK, txr_open(&r, enc_cap, bounce_cap, g_prim, NULL));
	r.keep = 1;
	for (a = 0; a < sizeof(l0s) / sizeof(l0s[0]); a++) {
		uint32_t len[4] = {l0s[a], 0, 0, 0};

		check_shape(&r, WRI_M2_TAG_KEEPALIVE2, 1, len, step); /* one segment: one or two operations */
		for (b = 0; b < sizeof(segs) / sizeof(segs[0]); b++) {
			uint32_t two[4] = {l0s[a], segs[b], 0, 0};

			check_shape(&r, WRI_M2_TAG_MESSAGE, 2, two, step); /* two or three operations */
			for (c = 0; c < sizeof(segs) / sizeof(segs[0]); c += 3u) {
				uint32_t three[4] = {l0s[a], segs[b], segs[c], 0};
				uint32_t four[4];

				check_shape(&r, WRI_M2_TAG_MESSAGE, 3, three, step);
				for (d = 0; d < sizeof(segs) / sizeof(segs[0]); d += 3u) {
					four[0] = l0s[a];
					four[1] = (b & 1u) ? 0u : segs[b]; /* an empty middle segment */
					four[2] = (c & 1u) ? 0u : segs[c];
					four[3] = segs[d];
					check_shape(&r, WRI_M2_TAG_MESSAGE, 4, four, step);
				}
			}
			{
				uint32_t gap[4] = {l0s[a], 0, segs[b], 0}; /* an empty middle segment, last one non-empty */

				check_shape(&r, WRI_M2_TAG_MESSAGE, 3, gap, step);
			}
		}
	}
	WRT_CHECK(txr_wire_matches(&r));
	txr_check_decode(&r, 0);
	txr_check_decode(&r, 1); /* the decoder fed one byte at a time reads the same frames */
	txr_close(&r);
}

static void test_shapes(void)
{
	shape_sweep(65536u, 4096u, 0);    /* every frame whole in the encode buffer */
	shape_sweep(65536u, 256u, 16);    /* same, the host takes 16 bytes at a time */
	shape_sweep(256u, 256u, 0);       /* a small encode buffer: parts 1 and 2 only, the rest streamed (and TOOBIG where parts 1 and 2 alone are too big) */
	shape_sweep(224u, 272u, 7);       /* the part 3 streamed through a bounce buffer of 272 bytes, odd host steps */
}

/* Every len_0 from 0 to 130 against segment lengths around the block size. */
static void test_exhaustive(void)
{
	txr r;
	uint32_t l0;
	static const uint32_t m1[] = {1, 15, 16, 17, 47, 48, 49};
	unsigned i;

	WRT_CHECK_STATUS(WR_OK, txr_open(&r, 1024u, 256u, g_prim, NULL));
	for (l0 = 0; l0 <= 130u; l0++) {
		uint32_t one[4] = {l0, 0, 0, 0};

		check_shape(&r, WRI_M2_TAG_MESSAGE, 1, one, 0);
		for (i = 0; i < sizeof(m1) / sizeof(m1[0]); i++) {
			uint32_t two[4] = {l0, m1[i], 0, 0};
			uint32_t three[4] = {l0, 0, m1[i], 0};
			uint32_t four[4] = {l0, m1[i], 0, m1[(i + 3u) % 7u]};

			check_shape(&r, WRI_M2_TAG_MESSAGE, 2, two, 0);
			check_shape(&r, WRI_M2_TAG_MESSAGE, 3, three, 16);
			check_shape(&r, WRI_M2_TAG_MESSAGE, 4, four, 0);
		}
	}
	WRT_CHECK(txr_wire_matches(&r));
	txr_close(&r);
}

/* A 4 MiB data segment through the stream. The independent encoder needs seconds for it, so it only runs on the first pass; the first pass
 * is read back by the independent decoder (every tag, every segment byte), the second one (other piece size, other host steps) has to put
 * exactly the same bytes on the wire as the first. */
static void test_big(void)
{
	static const uint32_t big = 4u << 20;
	static const uint32_t cfg[][2] = {{4096u, 65536u}, {512u, 4096u}};
	uint32_t len[4] = {41, 0, 0, big};
	uint8_t *first = NULL;
	size_t first_n = 0;
	unsigned c;

	for (c = 0; c < 2u; c++) {
		txr r;
		fb f;

		WRT_CHECK_STATUS(WR_OK, txr_open(&r, cfg[c][0], cfg[c][1], g_prim, NULL));
		r.keep = c == 0u;
		r.noref = 1;
		fb_make(&f, 4, len);
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, f.s, 4));
		WRT_CHECK_U64(r.q.pending, 96u + 4194304u + 32u); /* part 1, the data segment (a multiple of 16), epilogue block and tag */
		txr_drain(&r, c == 0u ? 0u : 4096u, 0);
		WRT_CHECK_U64(r.wire_len, 96u + 4194304u + 32u);
		if (c == 0u) {
			txr_check_decode(&r, 65536u);
			first = r.wire;
			first_n = r.wire_len;
			r.wire = NULL;
			r.wire_len = r.wire_cap = 0;
		} else {
			WRT_CHECK(first_n == r.wire_len && memcmp(first, r.wire, first_n) == 0);
		}
		fb_free(&f);
		txr_close(&r);
	}
	free(first);
}

/* ---- what is decided before a nonce is taken -------------------------------------------------------------------------- */

static int nonce_same(const txr *r, const wri_m2s_nonce *snap)
{
	return memcmp(&r->slot.s.tx_n, snap, sizeof(*snap)) == 0;
}

static void test_no_nonce(void)
{
	txr r;
	wri_m2s_nonce snap;
	fb f, g, h;
	uint32_t l1[4] = {20, 10, 0, 0}, big[4] = {400, 0, 0, 0}, mid[4] = {120, 0, 0, 0}, five[4] = {1, 1, 1, 1};
	wri_m2_seg_src bad[5];
	uint8_t z[8] = {0};

	WRT_CHECK_STATUS(WR_OK, txr_open(&r, 320u, 256u, g_prim, NULL));
	snap = r.slot.s.tx_n;
	fb_make(&f, 2, l1);
	/* a bad shape */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&r.q, g_prim, 0, f.s, 2, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&r.q, g_prim, 23, f.s, 2, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&r.q, g_prim, 17, f.s, 0, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&r.q, g_prim, 17, f.s, 5, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&r.q, g_prim, 17, NULL, 1, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2s_tx_frame(&r.q, g_prim, 0, f.s, 2));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2s_tx_frame(&r.q, g_prim, 23, f.s, 2));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2s_tx_frame(&r.q, g_prim, 17, f.s, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2s_tx_frame(&r.q, g_prim, 17, f.s, 5));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2s_tx_frame(&r.q, g_prim, 17, NULL, 1));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2s_tx_frame(NULL, g_prim, 17, f.s, 1));
	memset(bad, 0, sizeof(bad));
	bad[0].p = z;
	bad[0].len = 8;
	bad[1].p = z;
	bad[1].len = 0; /* the last of two segments is empty */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&r.q, g_prim, 17, bad, 2, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2s_tx_frame(&r.q, g_prim, 17, bad, 2));
	bad[1].len = 4;
	bad[1].p = NULL; /* bytes without a pointer */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&r.q, g_prim, 17, bad, 2, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2s_tx_frame(&r.q, g_prim, 17, bad, 2));
	WRT_CHECK(nonce_same(&r, &snap) && wri_m2_txq_idle(&r.q) && r.q.used == 0u && r.q.niov == 0u);
	WRT_CHECK(r.q.err == WR_E_INVAL); /* the first hard failure is kept for diagnostics */
	/* a frame that never fits: parts 1 and 2 of a 400-byte segment 0 are 96 + 368 > 320 */
	fb_make(&g, 1, big);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_tx_frame(&r.q, g_prim, 17, g.s, 1, NULL, NULL));
	WRT_CHECK(nonce_same(&r, &snap) && wri_m2_txq_idle(&r.q));
	/* a frame that fits now is accepted and gets the first nonce ... */
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, 17, f.s, 2)); /* 96 + 48 = 144 bytes, 2 operations */
	WRT_CHECK_U64(ops_taken(&r), 2);
	snap = r.slot.s.tx_n;
	/* ... one that does not fit next to it is BUSY (parts 1 and 2 are 192 bytes, 176 are left) and takes none */
	fb_make(&h, 1, mid);
	WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_tx_frame(&r.q, g_prim, 17, h.s, 1, NULL, NULL));
	WRT_CHECK(nonce_same(&r, &snap));
	WRT_CHECK(r.q.err == WR_E_INVAL); /* BUSY is not a failure and is not recorded; TOOBIG after INVAL leaves the first one */
	/* a second frame that fits is queued behind it */
	{
		uint32_t tiny[4] = {8, 0, 0, 0};
		fb t;

		fb_make(&t, 1, tiny);
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, 18, t.s, 1)); /* 96 more: 240 of 320 */
		snap = r.slot.s.tx_n;
		WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_tx_frame(&r.q, g_prim, 18, t.s, 1, NULL, NULL)); /* 336 > 320 */
		WRT_CHECK(nonce_same(&r, &snap));
		fb_free(&t);
	}
	/* the BUSY retry changes nothing on the wire: drain, retry, the next nonce follows */
	txr_drain(&r, 0, 0);
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, 17, h.s, 1));
	txr_drain(&r, 0, 0);
	WRT_CHECK(txr_wire_matches(&r));
	/* four segments of one byte are fine (the shape is valid), the stream-less limit of the gather list is below */
	fb_free(&g);
	fb_make(&g, 4, five);
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, 17, g.s, 4));
	txr_drain(&r, 0, 0);
	WRT_CHECK(txr_wire_matches(&r));
	fb_free(&f);
	fb_free(&g);
	fb_free(&h);
	txr_close(&r);
}

/* The edges of the room rule: a frame whose parts 1 and 2 fill the encode buffer exactly is accepted, one byte more is not; part 3 goes into
 * the encode buffer when it fits next to them exactly, and is streamed when it is one block too big. */
static void test_exact_fit(void)
{
	static const struct {
		uint32_t enc_cap, first; /* the encode buffer, and bytes already queued by an earlier frame (0 or 96) */
		wr_status want;
		int streamed;
	} t[] = {
		{144u, 0u, WR_OK, 0},       /* wire 144 = the whole buffer: inline */
		{143u, 0u, WR_OK, 1},       /* one byte short of the whole: parts 1 and 2 (96) in the buffer, part 3 streamed */
		{128u, 0u, WR_OK, 1},
		{96u, 0u, WR_OK, 1},        /* parts 1 and 2 are exactly the buffer */
		{95u, 0u, WR_E_TOOBIG, 0},  /* one byte less: they can never fit */
		{240u, 96u, WR_OK, 0},      /* 96 queued + 144 = 240: inline */
		{239u, 96u, WR_OK, 1},
		{192u, 96u, WR_OK, 1},      /* 96 queued + parts 1 and 2 (96) = 192 exactly */
		{191u, 96u, WR_E_BUSY, 0},  /* one byte short: wait for the host */
		{96u, 96u, WR_E_BUSY, 0},   /* fits an empty buffer (parts 1 and 2 = 96), not next to the queued frame */
	};
	static const uint32_t l0[4] = {20, 0, 0, 0}, l1[4] = {20, 10, 0, 0};
	unsigned i;

	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		txr r;
		fb a, b;
		wri_m2s_nonce snap;
		wr_status st;

		WRT_CHECK_STATUS(WR_OK, txr_open(&r, t[i].enc_cap, 256u, g_prim, NULL));
		fb_make(&a, 1, l0);
		fb_make(&b, 2, l1);
		if (t[i].first != 0u)
			WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_KEEPALIVE2, a.s, 1));
		snap = r.slot.s.tx_n;
		st = txr_send(&r, WRI_M2_TAG_MESSAGE, b.s, 2);
		WRT_CHECK_STATUS(t[i].want, st);
		if (st == WR_OK) {
			WRT_CHECK((r.slot.tx.stream_left != 0u || r.slot.tx.b_len != 0u) == (t[i].streamed != 0));
		} else {
			WRT_CHECK(memcmp(&r.slot.s.tx_n, &snap, sizeof(snap)) == 0);
		}
		txr_drain(&r, 0, 0);
		if (st != WR_OK) { /* after the host made room the frame goes through (BUSY) or never does (TOOBIG) */
			WRT_CHECK_STATUS(t[i].want == WR_E_BUSY ? WR_OK : WR_E_TOOBIG, txr_send(&r, WRI_M2_TAG_MESSAGE, b.s, 2));
			txr_drain(&r, 0, 0);
		}
		WRT_CHECK(txr_wire_matches(&r));
		fb_free(&a);
		fb_free(&b);
		txr_close(&r);
	}
}

/*
 * The copy rule (wri_m2_seg_src.ref): a segment without `ref` (segment 3 is always referenced) is a copy, as in the crc builder: when the call
 * returns it is out of the caller's memory, which may then be reused (the engine encodes the front of every message into one scratch buffer and
 * the monitor client into its stack). A stream may read only referenced memory, so the head of part 3 (everything up to the last copied segment)
 * is encrypted into the encode buffer at once and counts as room needed now. Here the copies are poisoned and freed the moment the call
 * returns, then the host drains in several ways: the wire must be the independent encoder's all the same, and a copy that can never be
 * made is WR_E_TOOBIG, one that cannot be made now is WR_E_BUSY, both before any nonce is taken.
 */
static void copy_frame(uint32_t enc, uint32_t bnc, unsigned nseg, const uint32_t *len, unsigned copymask, wr_status want, int streamed,
		       size_t step)
{
	txr r;
	fb f;
	wri_m2s_nonce snap;
	wr_status st;
	unsigned i;

	WRT_CHECK_STATUS(WR_OK, txr_open(&r, enc, bnc, g_prim, NULL));
	r.keep = 1;
	fb_make(&f, nseg, len);
	for (i = 0; i < nseg; i++)
		f.s[i].ref = (uint8_t)(((copymask >> i) & 1u) == 0u);
	f.s[3].ref = (uint8_t)((copymask & 0x10u) != 0u); /* segment 3 is referenced whatever its flag says */
	snap = r.slot.s.tx_n;
	st = txr_send(&r, WRI_M2_TAG_MESSAGE, f.s, nseg);
	WRT_CHECK_STATUS(want, st);
	if (st == WR_OK) {
		WRT_CHECK((r.slot.tx.stream_left != 0u || r.slot.tx.b_len != 0u) == (streamed != 0));
		for (i = 0; i < nseg; i++) {
			if (i != 3u && f.s[i].ref == 0u && f.p[i] != NULL) { /* a copy: gone from the caller's memory */
				memset(f.p[i], 0xee, len[i]);
				free(f.p[i]);
				f.p[i] = NULL;
			}
		}
		txr_drain(&r, step, 0);
		WRT_CHECK(txr_wire_matches(&r));
		txr_check_decode(&r, 0);
	} else {
		WRT_CHECK(memcmp(&r.slot.s.tx_n, &snap, sizeof(snap)) == 0 && wri_m2_txq_idle(&r.q) && r.q.used == 0u);
	}
	fb_free(&f);
	txr_close(&r);
}

static void test_copy_rule(void)
{
	static const size_t steps[] = {0u, 1u, 7u, 100u};
	unsigned k;

	for (k = 0; k < sizeof(steps) / sizeof(steps[0]); k++) {
		const size_t st = steps[k];
		static const uint32_t a[4] = {20, 100, 0, 3000};   /* the front is a copy, the data referenced: the usual message */
		static const uint32_t b[4] = {20, 40, 40, 2000};   /* a copy behind a referenced segment: both are in the head */
		static const uint32_t c[4] = {20, 400, 0, 0};      /* the head is all of part 3 but the epilogue and the tag do not fit */
		static const uint32_t d[4] = {200, 10, 10, 10};    /* part 2 and every segment a copy: all inline when it fits */
		static const uint32_t e[4] = {20, 3000, 100, 3000}; /* the referenced segment 1 sits ahead of a copy: it is read at once, so it must fit */
		static const uint32_t g[4] = {20, 0, 0, 5000};     /* nothing to copy: the stream is as before */

		copy_frame(512u, 256u, 4, a, 0x02u, WR_OK, 1, st);   /* head 112 + 96 <= 512, the 3000 streamed */
		copy_frame(512u, 272u, 4, a, 0x12u, WR_OK, 1, st);   /* segment 3's flag does not matter */
		copy_frame(512u, 256u, 4, b, 0x04u, WR_OK, 1, st);   /* segment 2 a copy: segment 1 (40, referenced) is read at once too */
		copy_frame(512u, 256u, 4, b, 0x06u, WR_OK, 1, st);
		copy_frame(512u, 256u, 2, c, 0x02u, WR_OK, 1, st);   /* 96 + 400 = 496 <= 512, 496 + 32 > 512: only epilogue and tag streamed */
		copy_frame(1024u, 256u, 2, c, 0x02u, WR_OK, 0, st);  /* it all fits: inline */
		copy_frame(2048u, 256u, 4, d, 0x07u, WR_OK, 0, st);
		copy_frame(512u, 256u, 4, g, 0x00u, WR_OK, 1, st);
		copy_frame(512u, 256u, 4, e, 0x04u, WR_E_TOOBIG, 0, st); /* 96 + 3008 + 112 never fits 512 */
		copy_frame(4096u, 256u, 4, e, 0x04u, WR_OK, 1, st);      /* here it does: head 3008 + 112, 3000 streamed */
		copy_frame(512u, 256u, 2, c, 0x02u, WR_OK, 1, st);
		{
			static const uint32_t big[4] = {20, 600, 0, 100};

			copy_frame(512u, 256u, 4, big, 0x02u, WR_E_TOOBIG, 0, st); /* a copy that can never be made */
		}
	}
}

/* A copy that does not fit now is WR_E_BUSY (the host makes room), takes no nonce and leaves the queue as it was; after the drain the frame
 * goes through, its copy is freed (poisoned) at once, and a frame behind it streams. */
static void test_copy_busy(void)
{
	static const uint32_t first[4] = {100, 0, 0, 0}, second[4] = {20, 250, 0, 0}, data[4] = {20, 100, 0, 4000};
	txr r;
	fb a, b, d;
	wri_m2s_nonce snap;
	uint64_t pending;
	uint32_t used;

	WRT_CHECK_STATUS(WR_OK, txr_open(&r, 512u, 256u, g_prim, NULL));
	r.keep = 1;
	fb_make(&a, 1, first);
	fb_make(&b, 2, second);
	fb_make(&d, 4, data);
	b.s[1].ref = 0;
	d.s[1].ref = 0;
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_KEEPALIVE2, a.s, 1)); /* 176 bytes queued */
	snap = r.slot.s.tx_n;
	pending = r.q.pending;
	used = r.q.used;
	WRT_CHECK_STATUS(WR_E_BUSY, txr_send(&r, WRI_M2_TAG_MESSAGE, b.s, 2)); /* 96 + 256 on top of 176: 528 > 512 */
	WRT_CHECK(memcmp(&r.slot.s.tx_n, &snap, sizeof(snap)) == 0 && r.q.pending == pending && r.q.used == used);
	txr_drain(&r, 0, 0);
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, b.s, 2)); /* 96 + 256 + 32 = 384: inline */
	memset(b.p[1], 0xee, second[1]); /* the copy is out: poisoned and freed before the host takes a byte */
	free(b.p[1]);
	b.p[1] = NULL;
	txr_drain(&r, 3, 0);
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, d.s, 4)); /* head 112, then a stream of the 4000 */
	WRT_CHECK(r.slot.tx.stream_left != 0u || r.slot.tx.b_len != 0u);
	memset(d.p[1], 0xee, data[1]);
	free(d.p[1]);
	d.p[1] = NULL;
	txr_drain(&r, 17, 0);
	WRT_CHECK(txr_wire_matches(&r));
	txr_check_decode(&r, 0);
	fb_free(&a);
	fb_free(&b);
	fb_free(&d);
	txr_close(&r);
}

/* The banner is plaintext and belongs before the switch: behind it the queue refuses to write one (it would be an unencrypted write on a secure
 * connection, and behind a stream it would also be out of order). Nothing is queued, no nonce is touched. */
static void test_no_banner(void)
{
	static const uint32_t l[4] = {20, 10, 0, 0};
	txr r;
	fb f;
	wri_m2s_nonce snap;

	WRT_CHECK_STATUS(WR_OK, txr_open(&r, 256u, 256u, g_prim, NULL));
	snap = r.slot.s.tx_n;
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_tx_banner(&r.q, NULL, NULL));
	WRT_CHECK(r.q.used == 0u && r.q.niov == 0u && r.q.pending == 0u && memcmp(&r.slot.s.tx_n, &snap, sizeof(snap)) == 0);
	fb_make(&f, 2, l);
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, 17, f.s, 2)); /* a stream: still nothing may be written behind it */
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_tx_banner(&r.q, NULL, NULL));
	txr_drain(&r, 0, 0);
	WRT_CHECK(txr_wire_matches(&r));
	fb_free(&f);
	txr_close(&r);
}

/* The operation limit refuses all or none of a frame's nonces: a frame of 3 operations at 2 left changes nothing. */
static void test_ops_limit(void)
{
	txr r;
	uint32_t three[4] = {100, 20, 0, 0}, two[4] = {20, 20, 0, 0}, one[4] = {20, 0, 0, 0};
	fb f3, f2, f1;
	wri_m2s_nonce snap;

	WRT_CHECK_STATUS(WR_OK, txr_open(&r, 4096u, 256u, g_prim, NULL));
	r.slot.s.ops_limit = 4; /* a test lowers it to a handful of operations (34.5) */
	fb_make(&f3, 2, three);
	fb_make(&f2, 2, two);
	fb_make(&f1, 1, one);
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, 17, f3.s, 2)); /* 3 operations */
	snap = r.slot.s.tx_n;
	WRT_CHECK_STATUS(WR_E_M2_NONCE, wri_m2_tx_frame(&r.q, g_prim, 17, f2.s, 2, NULL, NULL)); /* needs 2, one is left */
	WRT_CHECK(nonce_same(&r, &snap) && r.q.err == WR_E_M2_NONCE);
	WRT_CHECK_U64(r.q.pending, 96u + 80u + 64u); /* only the first frame is queued: 240 bytes */
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, 18, f1.s, 1)); /* the last one */
	WRT_CHECK_STATUS(WR_E_M2_NONCE, wri_m2_tx_frame(&r.q, g_prim, 18, f1.s, 1, NULL, NULL));
	txr_drain(&r, 0, 0);
	WRT_CHECK(txr_wire_matches(&r));
	/* nothing of a refused frame was ever produced: the queue is idle, the encode buffer untouched beyond what was consumed */
	WRT_CHECK(wri_m2_txq_idle(&r.q));
	fb_free(&f3);
	fb_free(&f2);
	fb_free(&f1);
	txr_close(&r);
}

/* A full gather list: eight crc-framed pieces queued before the switch use every entry; a secure frame behind them then needs a new entry. */
static void test_gather_limit(void)
{
	txr r;
	uint8_t junk[8];
	uint32_t l[4] = {20, 0, 0, 0};
	fb f;
	unsigned i;

	memset(junk, 0x5a, sizeof(junk));
	memset(&r, 0, sizeof(r));
	/* an encode buffer with eight referenced entries queued (as crc mode does for referenced segments) before the switch */
	r.rng = 1;
	r.enc_cap = 2048u;
	r.bounce_cap = 256u;
	r.enc = txr_alloc_guarded(&r.enc_raw, r.enc_cap, 0xcd);
	r.bounce = txr_alloc_guarded(&r.bnc_raw, r.bounce_cap, 0xcd);
	r.prim = g_prim;
	for (i = 0; i < sizeof(r.secret); i++)
		r.secret[i] = (uint8_t)i;
	txr_rx_to_boundary(&r);
	wri_m2_txq_init(&r.q, r.enc, r.enc_cap);
	for (i = 0; i < WRI_M2_TXQ_IOV; i++) { /* one encode-buffer entry, then seven referenced ones: the last one does not end at buf + used */
		r.q.iov[i].base = i == 0u ? r.enc : junk;
		r.q.iov[i].len = i == 0u ? 4u : sizeof(junk);
		r.q.pending += r.q.iov[i].len;
	}
	r.q.used = 4u;
	r.q.niov = WRI_M2_TXQ_IOV;
	WRT_CHECK_STATUS(WR_OK, wri_m2_secure_on(&r.rx, &r.q, &r.slot, g_prim, r.secret, sizeof(r.secret), r.bounce, r.bounce_cap));
	r.open = 1;
	WRT_CHECK_STATUS(0, sim_sec_ctx_init(&r.ref, r.secret, sizeof(r.secret), 0));
	fb_make(&f, 1, l);
	{
		wri_m2s_nonce snap = r.slot.s.tx_n;

		WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_tx_frame(&r.q, g_prim, 17, f.s, 1, NULL, NULL)); /* no entry left for it */
		WRT_CHECK(nonce_same(&r, &snap) && r.q.niov == WRI_M2_TXQ_IOV);
	}
	/* the host consumes the first two entries (12 bytes): now there is room for the new entry */
	wri_m2_txq_consume(&r.q, 4u + 8u);
	WRT_CHECK_U64(r.q.niov, WRI_M2_TXQ_IOV - 2u);
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&r.q, g_prim, 17, f.s, 1, NULL, NULL));
	WRT_CHECK_U64(r.q.niov, WRI_M2_TXQ_IOV - 1u);
	WRT_CHECK(r.q.iov[r.q.niov - 1u].base == r.enc + 4u && r.q.iov[r.q.niov - 1u].len == 96u);
	fb_free(&f);
	txr_close(&r);
}

/* ---- the caller's memory is only read ----------------------------------------------------------------------------------- */

static void test_readonly_caller(void)
{
	long pg = sysconf(_SC_PAGESIZE);
	size_t span = (size_t)pg * 4u;
	uint8_t *m = (uint8_t *)mmap(NULL, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	unsigned c;

	if (m == MAP_FAILED || pg < 4096) {
		WRT_CHECK(0);
		return;
	}
	for (c = 0; c < 4u; c++) {
		static const uint32_t cfg[4][2] = {{65536u, 4096u}, {512u, 256u}, {512u, 4096u}, {320u, 272u}};
		static const uint32_t lens[4] = {17u, 1000u, 8192u, 4093u};
		uint32_t len[4] = {41, 0, 0, lens[c]};
		uint8_t *data = m + (size_t)pg + ((size_t)pg * 2u - lens[c]); /* ends exactly where the no-access page begins */
		wri_m2_seg_src src[4];
		txr r;
		size_t i;

		if (lens[c] > (uint32_t)pg * 2u) { /* longer than the window: shrink to fit the two pages */
			len[3] = (uint32_t)pg * 2u;
			data = m + (size_t)pg;
		}
		for (i = 0; i < len[3]; i++)
			data[i] = pat(3, i);
		memset(src, 0, sizeof(src));
		{
			static const uint8_t h[41] = {1};

			src[0].p = h;
			src[0].len = 41;
		}
		src[3].p = data;
		src[3].len = len[3];
		/* the page before is read-write, the data pages read-only, the page after no access at all */
		WRT_CHECK(mprotect(m, (size_t)pg, PROT_NONE) == 0);
		WRT_CHECK(mprotect(m + (size_t)pg, (size_t)pg * 2u, PROT_READ) == 0);
		WRT_CHECK(mprotect(m + (size_t)pg * 3u, (size_t)pg, PROT_NONE) == 0);
		WRT_CHECK_STATUS(WR_OK, txr_open(&r, cfg[c][0], cfg[c][1], g_prim, NULL));
		r.keep = 1;
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, src, 4));
		txr_drain(&r, c == 3u ? 5u : 0u, 0);
		WRT_CHECK(txr_wire_matches(&r));
		txr_check_decode(&r, 0);
		txr_close(&r);
		WRT_CHECK(mprotect(m, span, PROT_READ | PROT_WRITE) == 0);
	}
	munmap(m, span);
}

/* ---- a refusal after the nonces were taken ----------------------------------------------------------------------------------- */

typedef struct hspy {
	unsigned starts;
	unsigned fail_start_at; /* the nth start (1-based) is refused */
	unsigned updates, finals;
} hspy;

static wr_status h_setkey(void *ctx, void *state, const uint8_t key[16])
{
	(void)ctx;
	memcpy(state, key, 16);
	return WR_OK;
}
static wr_status h_start(void *ctx, void *state, const uint8_t iv[12], int decrypt)
{
	hspy *h = (hspy *)ctx;

	(void)state;
	(void)iv;
	(void)decrypt;
	h->starts++;
	return h->fail_start_at != 0u && h->starts == h->fail_start_at ? WR_E_CRYPTO_KEY : WR_OK;
}
static void h_update(void *ctx, void *state, const uint8_t *in, uint8_t *out, size_t n)
{
	hspy *h = (hspy *)ctx;

	(void)state;
	h->updates++;
	if (in != out)
		memcpy(out, in, n);
}
static void h_final_enc(void *ctx, void *state, uint8_t tag[16])
{
	hspy *h = (hspy *)ctx;

	(void)state;
	h->finals++;
	memset(tag, 0x77, 16);
}
static wr_status h_final_dec(void *ctx, void *state, const uint8_t tag[16])
{
	(void)ctx;
	(void)state;
	(void)tag;
	return WR_OK;
}
static void h_wipe(void *ctx, void *state)
{
	(void)ctx;
	memset(state, 0, 16);
}

static void test_failure_after_nonce(void)
{
	static uint32_t cfg[3][2] = {{4096u, 256u}, {256u, 256u}, {4096u, 256u}};
	unsigned c;

	for (c = 0; c < 3u; c++) {
		/* c 0: the third operation of an inline frame fails to start; c 1: the stream's start; c 2: the first operation */
		hspy h;
		wr_prim_ops ops;
		txr r;
		uint32_t l[4] = {100, 300, 0, 0};
		fb f;
		wri_m2s_nonce snap;
		uint64_t pend;

		memset(&h, 0, sizeof(h));
		memset(&ops, 0, sizeof(ops));
		ops.size = sizeof(ops);
		ops.ctx = &h;
		ops.gcm_state_bytes = 16;
		ops.gcm_setkey = h_setkey;
		ops.gcm_start = h_start;
		ops.gcm_update = h_update;
		ops.gcm_final_enc = h_final_enc;
		ops.gcm_final_dec = h_final_dec;
		ops.gcm_wipe = h_wipe;
		h.fail_start_at = c == 0u ? 3u : (c == 1u ? 3u : 1u);
		WRT_CHECK_STATUS(WR_OK, txr_open(&r, cfg[c][0], cfg[c][1], &ops, NULL));
		WRT_CHECK(wri_pgcm_is_host(&r.slot.s.tx));
		fb_make(&f, 2, l); /* three operations: 100 > 48, two segments */
		snap = r.slot.s.tx_n;
		pend = r.q.pending;
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, wri_m2_tx_frame(&r.q, &ops, 17, f.s, 2, NULL, NULL));
		WRT_CHECK_U64(r.slot.s.tx_n.ops, snap.ops + 3u); /* the nonces are spent, never reused */
		WRT_CHECK(r.q.pending == pend && r.q.niov == 0u && r.q.used == 0u && wri_m2_txq_idle(&r.q));
		{
			size_t i;
			int all = 1;

			for (i = 0; i < 400u && i < r.enc_cap; i++)
				if (r.enc[i] != 0 && r.enc[i] != 0xcd)
					all = 0;
			WRT_CHECK(all); /* whatever was built there was erased */
		}
		WRT_CHECK(r.slot.s.tx.keyed == 0u); /* the transmit key is gone */
		WRT_CHECK_STATUS(WR_E_STATE, wri_m2_tx_frame(&r.q, &ops, 17, f.s, 2, NULL, NULL));
		WRT_CHECK(r.q.err == WR_E_CRYPTO_KEY);
		WRT_CHECK_U64(r.slot.s.tx_n.ops, snap.ops + 3u);
		fb_free(&f);
		txr_close(&r);
	}
}

/* ---- the end of the connection ---------------------------------------------------------------------------------------------- */

static void test_wipe(void)
{
	txr r;
	uint32_t l[4] = {20, 3000, 0, 0};
	fb f;
	size_t i;
	int zero = 1;

	WRT_CHECK_STATUS(WR_OK, txr_open(&r, 256u, 256u, g_prim, NULL));
	fb_make(&f, 2, l);
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, 17, f.s, 2)); /* a stream, half sent */
	(void)txr_pull(&r, 100);
	WRT_CHECK(!wri_m2_txq_idle(&r.q) && !wri_m2s_tx_done(&r.q));
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	for (i = 0; i < r.bounce_cap; i++)
		if (r.bounce[i] != 0)
			zero = 0;
	WRT_CHECK(zero);
	for (i = 0; i < sizeof(r.slot); i++)
		if (((const uint8_t *)&r.slot)[i] != 0)
			zero = 0;
	WRT_CHECK(zero);
	WRT_CHECK(r.q.sx == NULL);
	wri_m2_txq_reset(&r.q);
	WRT_CHECK(wri_m2_txq_idle(&r.q));
	fb_free(&f);
	txr_close(&r);
}

static void run_all(const wr_prim_ops *prim)
{
	static const struct {
		const char *name;
		void (*fn)(void);
	} tests[] = {{"spec_frames", test_spec_frames}, {"vector_file", test_vector_file}, {"shapes", test_shapes},
		     {"exhaustive", test_exhaustive}, {"no_nonce", test_no_nonce}, {"exact_fit", test_exact_fit}, {"ops_limit", test_ops_limit},
		     {"gather_limit", test_gather_limit}, {"readonly_caller", test_readonly_caller},
		     {"failure_after_nonce", test_failure_after_nonce}, {"wipe", test_wipe}, {"big", test_big}, {"copy_rule", test_copy_rule},
		     {"copy_busy", test_copy_busy}, {"no_banner", test_no_banner}};
	size_t i;

	g_prim = prim;
	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		clock_t t0 = clock();

		tests[i].fn();
		if (getenv("WRT_VERBOSE") != NULL)
			fprintf(stderr, "%s%s: %.2f s\n", prim != NULL ? "accel " : "", tests[i].name, (double)(clock() - t0) / CLOCKS_PER_SEC);
	}
}

int main(void)
{
	const char *accel = getenv("WRT_GCM_ACCEL");

	run_all(NULL);
	if (accel != NULL && strcmp(accel, "1") == 0) {
		static wr_prim_ops ops;

		if (wrl_gcm_aesni_ops(&ops) == 0) {
			txr probe;

			WRT_CHECK_STATUS(WR_OK, txr_open(&probe, 4096u, 4096u, &ops, NULL));
			WRT_CHECK(wri_pgcm_is_host(&probe.slot.s.tx)); /* the hook really is the one in use */
			txr_close(&probe);
			run_all(&ops);
		} else {
			fprintf(stderr, "note: WRT_GCM_ACCEL=1 but the CPU lacks AES / PCLMULQDQ / SSE4.1: the accelerated pass is skipped\n");
		}
	}
	return wrt_finish();
}
