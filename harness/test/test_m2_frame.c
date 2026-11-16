/* SPDX-License-Identifier: MIT */
/*
 * Unit test of the msgr2.1 crc-mode framing (core/src/msgr2/wri_m2_frame.h): banner, preamble,
 * the receive parser and the frame builder against the 28 committed frames of
 * vectors/msgr2/frames-crc.json, the frame shapes of vectors/msgr2/handshake-skeletons.json, and a
 * table of malformed inputs.
 */
#include "wrt.h"

#include "wri_crc32c.h"
#include "wri_le.h"
#include "wri_m2_frame.h"

#define RING_CAP 8192u
#define SEG0_CAP 4096u
#define SEG_MAX (1u << 20)
#define SCRATCH 70000u
#define NFRAMES_CRC 31u /* frames of the crc-mode connections in handshake-skeletons.json */

/* ---- small helpers ------------------------------------------------------------------------- */

typedef struct harness {
	wri_m2_rx rx;
	wri_ring ring;
	uint8_t ringbuf[RING_CAP];
	uint8_t seg0[SEG0_CAP];
} harness;

static uint8_t g_scratch[3][SCRATCH]; /* sinks for segments 1..3 */

static void h_init(harness *h, uint32_t seg0_cap, uint32_t seg_max)
{
	memset(h, 0, sizeof(*h));
	wri_ring_init(&h->ring, h->ringbuf, RING_CAP);
	wri_m2_rx_init(&h->rx, h->seg0, seg0_cap, seg_max);
}

/* Put bytes into the ring through the public window/commit pair (the ring is large enough). */
static void h_feed(harness *h, const uint8_t *p, size_t n)
{
	while (n > 0) {
		uint8_t *w;
		size_t room = wri_m2_rx_window(&h->rx, &h->ring, &w);
		size_t k = n < room ? n : room;

		if (k == 0)
			return;
		memcpy(w, p, k);
		wri_m2_rx_commit(&h->rx, &h->ring, k);
		p += k;
		n -= k;
	}
}

static wri_m2_rx_ev h_step(harness *h) { return wri_m2_rx_step(&h->rx, &h->ring, NULL, NULL, NULL, NULL); }

static void h_banner(harness *h)
{
	uint8_t b[WRI_M2_BANNER_LEN];

	wri_m2_banner_build(b);
	h_feed(h, b, sizeof(b));
	WRT_CHECK_U64(h_step(h), WRI_RXE_BANNER);
}

/* Run bytes through a fresh parser (banner already done). Sinks for segments 1..3 are the global
 * scratch buffers with cap sink_cap, or none (discard) when sink_cap is 0. Returns the final event
 * (FRAME, ABORTED or ERROR) or NONE if the parser ran out of input. */
static wri_m2_rx_ev h_run(harness *h, const uint8_t *p, size_t n, uint32_t sink_cap)
{
	wri_m2_rx_ev ev;
	unsigned i;

	h_feed(h, p, n);
	for (;;) {
		ev = h_step(h);
		if (ev == WRI_RXE_SEG0) {
			if (sink_cap != 0)
				for (i = 1; i < 4; i++)
					wri_m2_rx_sink(&h->rx, i, g_scratch[i - 1], sink_cap);
			continue;
		}
		return ev;
	}
}

static size_t build_frame(uint8_t *out, size_t cap, uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg)
{
	wri_m2_txq q;
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t n, i, total = 0;

	static uint8_t enc[SCRATCH];

	wri_m2_txq_init(&q, enc, sizeof(enc));
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, tag, seg, nseg, NULL, NULL));
	n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < n; i++) {
		if (total + iov[i].len > cap)
			return 0;
		memcpy(out + total, iov[i].base, iov[i].len);
		total += iov[i].len;
	}
	return total;
}

/* Recompute the preamble CRC after a test edited bytes 0..27. */
static void fix_pre(uint8_t *f) { wri_le32_put(f + 28, wri_crc32c(0, f, 28)); }

/* ---- banner -------------------------------------------------------------------------------- */

static void test_banner(void)
{
	static const uint8_t want[26] = {'c', 'e', 'p', 'h', ' ', 'v', '2', '\n', 16, 0, 1, 0, 0, 0, 0, 0,
					 0,   0,   0,   0,   0,   0,   0,   0,    0,  0};
	uint8_t b[WRI_M2_BANNER_LEN + 64];
	uint32_t plen = 99;
	wri_m2_banner bn;

	wri_m2_banner_build(b);
	WRT_CHECK_MEM(b, want, sizeof(want));
	WRT_CHECK_STATUS(WR_OK, wri_m2_banner_head(b, &plen));
	WRT_CHECK_U64(plen, 16);
	WRT_CHECK_STATUS(WR_OK, wri_m2_banner_payload(b + 10, 16, &bn));
	WRT_CHECK_U64(bn.supported, 1);
	WRT_CHECK_U64(bn.required, 0);

	/* what a stock v20.2.5 daemon sends: supported 3 (REVISION_1 + COMPRESSION), required 0 */
	wri_le64_put(b + 10, 3);
	WRT_CHECK_STATUS(WR_OK, wri_m2_banner_payload(b + 10, 16, &bn));
	WRT_CHECK_U64(bn.supported, 3);
	/* required bit 0 is something we have; bit 1 or any other is not */
	wri_le64_put(b + 18, 1);
	WRT_CHECK_STATUS(WR_OK, wri_m2_banner_payload(b + 10, 16, &bn));
	wri_le64_put(b + 18, 2);
	WRT_CHECK_STATUS(WR_E_M2_FEATURES, wri_m2_banner_payload(b + 10, 16, &bn));
	WRT_CHECK_U64(bn.required, 2); /* decoded values stay available for the error report */
	wri_le64_put(b + 18, (uint64_t)1 << 40);
	WRT_CHECK_STATUS(WR_E_M2_FEATURES, wri_m2_banner_payload(b + 10, 16, &bn));
	wri_le64_put(b + 18, 0);
	/* no REVISION_1: msgr2.0 framing is not implemented */
	wri_le64_put(b + 10, 2);
	WRT_CHECK_STATUS(WR_E_M2_FEATURES, wri_m2_banner_payload(b + 10, 16, &bn));
	wri_le64_put(b + 10, 0);
	WRT_CHECK_STATUS(WR_E_M2_FEATURES, wri_m2_banner_payload(b + 10, 16, &bn));
	wri_le64_put(b + 10, 1);
	/* short payload, NULL arguments, extra bytes are ignored */
	WRT_CHECK_STATUS(WR_E_M2_BANNER, wri_m2_banner_payload(b + 10, 15, &bn));
	WRT_CHECK_STATUS(WR_E_M2_BANNER, wri_m2_banner_payload(b + 10, 0, &bn));
	WRT_CHECK_STATUS(WR_E_M2_BANNER, wri_m2_banner_payload(NULL, 16, &bn));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_banner_payload(b + 10, 16, NULL));
	memset(b + 26, 0xEE, 48);
	WRT_CHECK_STATUS(WR_OK, wri_m2_banner_payload(b + 10, 64, &bn));

	/* head: payload length bounds 16..64, prefix, v1 */
	wri_le16_put(b + 8, 15);
	WRT_CHECK_STATUS(WR_E_M2_BANNER, wri_m2_banner_head(b, &plen));
	WRT_CHECK_U64(plen, 0);
	wri_le16_put(b + 8, 16);
	WRT_CHECK_STATUS(WR_OK, wri_m2_banner_head(b, &plen));
	wri_le16_put(b + 8, 64);
	WRT_CHECK_STATUS(WR_OK, wri_m2_banner_head(b, &plen));
	WRT_CHECK_U64(plen, 64);
	wri_le16_put(b + 8, 65);
	WRT_CHECK_STATUS(WR_E_M2_BANNER, wri_m2_banner_head(b, &plen));
	wri_le16_put(b + 8, 0xFFFF);
	WRT_CHECK_STATUS(WR_E_M2_BANNER, wri_m2_banner_head(b, &plen));
	wri_le16_put(b + 8, 16);
	b[7] = 'X';
	WRT_CHECK_STATUS(WR_E_M2_BANNER, wri_m2_banner_head(b, &plen));
	b[7] = '\n';
	b[0] = 'C';
	WRT_CHECK_STATUS(WR_E_M2_BANNER, wri_m2_banner_head(b, &plen));
	memcpy(b, "ceph v027\0", 10);
	WRT_CHECK_STATUS(WR_E_M2_PEER_V1, wri_m2_banner_head(b, &plen));
	memcpy(b, "ceph v027\xff", 10);
	WRT_CHECK_STATUS(WR_E_M2_PEER_V1, wri_m2_banner_head(b, &plen));
	memcpy(b, "ceph v026\0", 10);
	WRT_CHECK_STATUS(WR_E_M2_BANNER, wri_m2_banner_head(b, &plen));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_banner_head(NULL, &plen));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_banner_head(b, NULL));

	/* the same through the parser: an HTTP request or a v1 peer is told apart */
	{
		harness *h = (harness *)malloc(sizeof(*h));
		static const uint8_t v1[10] = {'c', 'e', 'p', 'h', ' ', 'v', '0', '2', '7', 0};

		h_init(h, SEG0_CAP, SEG_MAX);
		h_feed(h, v1, sizeof(v1));
		WRT_CHECK_U64(h_step(h), WRI_RXE_ERROR);
		WRT_CHECK_U64(wri_m2_rx_error(&h->rx)->status, WR_E_M2_PEER_V1);
		free(h);
	}
}

/* ---- preamble ------------------------------------------------------------------------------ */

static void raw_pre(uint8_t out[32], unsigned tag, unsigned nseg, const uint32_t len[4], unsigned flags,
		    unsigned reserved)
{
	unsigned i;

	memset(out, 0, 32);
	out[0] = (uint8_t)tag;
	out[1] = (uint8_t)nseg;
	for (i = 0; i < 4; i++) {
		wri_le32_put(out + 2 + 6 * i, len[i]);
		wri_le16_put(out + 6 + 6 * i, len[i] ? 8 : 0);
	}
	out[26] = (uint8_t)flags;
	out[27] = (uint8_t)reserved;
	fix_pre(out);
}

static void test_preamble(void)
{
	static const struct {
		const char *what;
		unsigned tag, nseg, flags, reserved;
		uint32_t len[4];
		wr_status want;
	} tab[] = {
		{"valid 1 segment", 1, 1, 0, 0, {36, 0, 0, 0}, WR_OK},
		{"valid empty frame (WAIT)", 16, 1, 0, 0, {0, 0, 0, 0}, WR_OK},
		{"valid 4 segments, empty middle", 17, 4, 0, 0, {41, 224, 0, 100}, WR_OK},
		{"valid empty seg 0, data in 1", 17, 2, 0, 0, {0, 10, 0, 0}, WR_OK},
		{"nseg 0", 1, 0, 0, 0, {0, 0, 0, 0}, WR_E_M2_FRAME_FORM},
		{"nseg 5", 1, 5, 0, 0, {1, 1, 1, 1}, WR_E_M2_FRAME_FORM},
		{"nseg 255", 1, 255, 0, 0, {1, 1, 1, 1}, WR_E_M2_FRAME_FORM},
		{"empty last segment (2)", 17, 2, 0, 0, {41, 0, 0, 0}, WR_E_M2_FRAME_FORM},
		{"empty last segment (4)", 17, 4, 0, 0, {41, 5, 5, 0}, WR_E_M2_FRAME_FORM},
		{"unused segment 1 has a length", 1, 1, 0, 0, {5, 7, 0, 0}, WR_E_M2_FRAME_FORM},
		{"unused segment 3 has a length", 17, 3, 0, 0, {5, 7, 7, 9}, WR_E_M2_FRAME_FORM},
		{"tag 0", 0, 1, 0, 0, {4, 0, 0, 0}, WR_E_M2_TAG},
		{"tag 23", 23, 1, 0, 0, {4, 0, 0, 0}, WR_E_M2_TAG},
		{"tag 255", 255, 1, 0, 0, {4, 0, 0, 0}, WR_E_M2_TAG},
		{"tag 22 is fine", 22, 1, 0, 0, {5, 0, 0, 0}, WR_OK},
		{"flags set", 1, 1, 1, 0, {4, 0, 0, 0}, WR_E_M2_FRAME_FORM},
		{"flags 0x80", 1, 1, 0x80, 0, {4, 0, 0, 0}, WR_E_M2_FRAME_FORM},
		{"reserved set", 1, 1, 0, 1, {4, 0, 0, 0}, WR_E_M2_FRAME_FORM},
		{"huge lengths are the parser's cap, not the decoder's", 17, 4, 0, 0,
		 {0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu}, WR_OK},
	};
	size_t i;
	uint8_t p[32], q[32];
	wri_m2_desc d, d2;

	for (i = 0; i < sizeof(tab) / sizeof(tab[0]); i++) {
		raw_pre(p, tab[i].tag, tab[i].nseg, tab[i].len, tab[i].flags, tab[i].reserved);
		if (wri_m2_preamble_parse(NULL, p, &d) != tab[i].want)
			fprintf(stderr, "preamble case failed: %s\n", tab[i].what);
		WRT_CHECK_STATUS(tab[i].want, wri_m2_preamble_parse(NULL, p, &d));
		if (tab[i].want == WR_OK) {
			unsigned k;

			WRT_CHECK_U64(d.tag, tab[i].tag);
			WRT_CHECK_U64(d.nseg, tab[i].nseg);
			for (k = 0; k < 4; k++)
				WRT_CHECK_U64(d.len[k], tab[i].len[k]);
		}
	}

	/* a wrong CRC fails first, whatever else is wrong */
	raw_pre(p, 1, 1, tab[0].len, 0, 0);
	p[28] ^= 1;
	WRT_CHECK_STATUS(WR_E_M2_FRAME_CRC, wri_m2_preamble_parse(NULL, p, &d));
	raw_pre(p, 1, 1, tab[0].len, 0, 0);
	p[5] ^= 0x40; /* a length bit flipped after the CRC was made */
	WRT_CHECK_STATUS(WR_E_M2_FRAME_CRC, wri_m2_preamble_parse(NULL, p, &d));
	raw_pre(p, 0, 0, tab[0].len, 7, 7);
	p[31] ^= 0x80;
	WRT_CHECK_STATUS(WR_E_M2_FRAME_CRC, wri_m2_preamble_parse(NULL, p, &d));
	/* the CRC is seed 0 over bytes 0..27 */
	raw_pre(p, 1, 1, tab[0].len, 0, 0);
	WRT_CHECK_U64(wri_le32_get(p + 28), wri_crc32c(0, p, 28));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_preamble_parse(NULL, NULL, &d));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_preamble_parse(NULL, p, NULL));

	/* build/parse round trip, alignments kept, unused slots zeroed */
	memset(&d, 0, sizeof(d));
	d.tag = 17;
	d.nseg = 4;
	d.len[0] = 41;
	d.len[1] = 224;
	d.len[2] = 0;
	d.len[3] = 100;
	d.align[0] = d.align[1] = d.align[2] = 8;
	d.align[3] = 4096;
	wri_m2_preamble_build(NULL, p, &d);
	WRT_CHECK_STATUS(WR_OK, wri_m2_preamble_parse(NULL, p, &d2));
	WRT_CHECK(memcmp(&d, &d2, sizeof(d)) == 0);
	d.nseg = 2;
	d.len[2] = 77; /* beyond nseg: the builder must not write it */
	d.len[3] = 99;
	d.len[1] = 5;
	wri_m2_preamble_build(NULL, q, &d);
	WRT_CHECK_STATUS(WR_OK, wri_m2_preamble_parse(NULL, q, &d2));
	WRT_CHECK_U64(d2.len[2], 0);
	WRT_CHECK_U64(d2.len[3], 0);
	WRT_CHECK_U64(d2.align[3], 0);

	/* frame_body_len: seg0 + 4 when seg0 non-empty, L1..L3, +13 when nseg > 1 */
	memset(&d, 0, sizeof(d));
	d.nseg = 1;
	WRT_CHECK_U64(wri_m2_frame_body_len(&d), 0);
	d.len[0] = 8;
	WRT_CHECK_U64(wri_m2_frame_body_len(&d), 12);
	d.nseg = 4;
	d.len[1] = 224;
	d.len[3] = 100;
	d.len[0] = 41;
	WRT_CHECK_U64(wri_m2_frame_body_len(&d), 41 + 4 + 224 + 100 + 13);
	d.len[0] = 0;
	d.len[1] = 10;
	d.len[2] = 0;
	d.len[3] = 20;
	WRT_CHECK_U64(wri_m2_frame_body_len(&d), 10 + 20 + 13); /* empty seg 0: no inline CRC */
	d.len[0] = d.len[1] = d.len[2] = d.len[3] = 0xFFFFFFFFu;
	WRT_CHECK_U64(wri_m2_frame_body_len(&d), 4 * (uint64_t)0xFFFFFFFFu + 4 + 13); /* 64-bit, no wrap */
}

/* ---- the committed frames ------------------------------------------------------------------ */

static void check_segments(const uint8_t *f, size_t size, const wri_m2_desc *d, const uint8_t *seg0,
			   const uint32_t stored[4], uint8_t *const bufs[4])
{
	size_t off = 32;
	unsigned i;

	if (d->len[0] != 0) {
		WRT_CHECK_MEM(seg0, f + off, d->len[0]);
		off += d->len[0] + 4;
	}
	for (i = 1; i < d->nseg; i++) {
		WRT_CHECK_U64(stored[i], d->len[i]);
		if (d->len[i] != 0)
			WRT_CHECK_MEM(bufs[i], f + off, d->len[i]);
		off += d->len[i];
	}
	off += d->nseg > 1 ? 13 : 0;
	WRT_CHECK_U64(off, size);
}

static void test_vector_frames(void)
{
	wrt_json j;
	wrt_tok frames;
	size_t nf, k;
	harness *h = (harness *)malloc(sizeof(*h));

	if (wrt_json_load_vec(&j, "msgr2/frames-crc.json") != 0) {
		WRT_CHECK(0 && "cannot load frames-crc.json");
		free(h);
		return;
	}
	frames = wrt_json_get(&j, wrt_json_root(&j), "frames");
	nf = wrt_json_count(&j, frames);
	WRT_CHECK_U64(nf, 28);

	h_init(h, SEG0_CAP, SEG_MAX);
	h_banner(h);

	for (k = 0; k < nf; k++) {
		wrt_tok f = wrt_json_at(&j, frames, k);
		uint8_t *hex = NULL;
		size_t size = 0, i;
		int ok = 0;
		wri_m2_desc d;
		char *name = wrt_json_strdup(&j, wrt_json_get(&j, f, "name"));
		wrt_tok lens = wrt_json_get(&j, f, "segment_lengths");
		wrt_tok aligns = wrt_json_get(&j, f, "segment_alignments");
		wrt_tok epi = wrt_json_get(&j, f, "epilogue");
		unsigned nseg = (unsigned)wrt_json_count(&j, lens);
		uint32_t want_len[4] = {0, 0, 0, 0};
		uint32_t stored[4] = {0, 0, 0, 0};
		uint8_t *bufs[4] = {NULL, g_scratch[0], g_scratch[1], g_scratch[2]};
		wri_m2_seg_src src[4];
		size_t off;
		wri_m2_rx_ev ev;

		WRT_CHECK(wrt_json_get_hex(&j, f, "hex", &hex, &size) == 0);
		if (hex == NULL) {
			free(name);
			continue;
		}
		WRT_CHECK_U64(size, wrt_json_int(&j, wrt_json_get(&j, f, "size"), &ok));
		for (i = 0; i < nseg && i < 4; i++)
			want_len[i] = (uint32_t)wrt_json_int(&j, wrt_json_at(&j, lens, i), &ok);

		/* 1. preamble decode */
		WRT_CHECK_STATUS(WR_OK, wri_m2_preamble_parse(NULL, hex, &d));
		WRT_CHECK_U64(d.tag, wrt_json_int(&j, wrt_json_get(&j, f, "tag"), &ok));
		WRT_CHECK_U64(d.nseg, nseg);
		WRT_CHECK_U64(d.flags, 0);
		for (i = 0; i < 4; i++) {
			WRT_CHECK_U64(d.len[i], want_len[i]);
			WRT_CHECK_U64(d.align[i], i < nseg ? wrt_json_int(&j, wrt_json_at(&j, aligns, i), &ok) : 0);
		}
		WRT_CHECK_U64(wri_le32_get(hex + 28), wrt_json_int(&j, wrt_json_get(&j, f, "preamble_crc"), &ok));
		WRT_CHECK_U64(wri_m2_frame_body_len(&d) + 32, size);

		/* 2. the CRCs the vector documents */
		off = 32 + want_len[0];
		WRT_CHECK_U64(wri_le32_get(hex + off), wrt_json_int(&j, wrt_json_get(&j, f, "segment0_crc"), &ok));
		WRT_CHECK_U64(wri_le32_get(hex + off), wri_crc32c(0xFFFFFFFFu, hex + 32, want_len[0]));
		if (nseg > 1) {
			wrt_tok slots = wrt_json_get(&j, epi, "crc_slots");
			size_t eo = size - 13;
			size_t so = off + 4;

			WRT_CHECK_U64(hex[eo], wrt_json_int(&j, wrt_json_get(&j, epi, "late_status"), &ok));
			for (i = 1; i < 4; i++) {
				uint32_t slot = wri_le32_get(hex + eo + 1 + 4 * (i - 1));

				WRT_CHECK_U64(slot, wrt_json_int(&j, wrt_json_at(&j, slots, i - 1), &ok));
				if (i < nseg) {
					WRT_CHECK_U64(slot, wri_crc32c(0xFFFFFFFFu, hex + so, want_len[i]));
					so += want_len[i];
				} else {
					WRT_CHECK_U64(slot, 0);
				}
			}
		}

		/* 3. the receive parser: SEG0 (segment 0 verified), then FRAME with the segments in place */
		h_feed(h, hex, size);
		ev = h_step(h);
		WRT_CHECK_U64(ev, WRI_RXE_SEG0);
		WRT_CHECK_U64(h->rx.desc.tag, d.tag);
		WRT_CHECK_U64(h->rx.desc.nseg, nseg);
		WRT_CHECK(memcmp(h->rx.desc.len, d.len, sizeof(d.len)) == 0);
		WRT_CHECK_U64(h->rx.stored[0], want_len[0]);
		if (want_len[0] != 0)
			WRT_CHECK_MEM(h->seg0, hex + 32, want_len[0]);
		for (i = 1; i < 4; i++)
			wri_m2_rx_sink(&h->rx, (unsigned)i, bufs[i], SCRATCH);
		ev = h_step(h);
		WRT_CHECK_U64(ev, WRI_RXE_FRAME);
		for (i = 0; i < 4; i++)
			stored[i] = h->rx.stored[i];
		check_segments(hex, size, &d, h->seg0, stored, bufs);
		WRT_CHECK_U64(h->ring.len, 0); /* consumed exactly one frame */
		wri_m2_rx_next_frame(&h->rx);

		/* 4. the builder reproduces the frame byte for byte (copy mode and reference mode) */
		for (i = 0; i < nseg; i++) {
			src[i].p = hex + 32 + (i == 0 ? 0 : want_len[0] + 4 + (i > 1 ? want_len[1] : 0) + (i > 2 ? want_len[2] : 0));
			src[i].len = want_len[i];
			src[i].ref = 0;
		}
		for (i = 0; i < 2; i++) {
			uint8_t out[SCRATCH];
			size_t got;
			unsigned m;

			for (m = 0; m < nseg; m++)
				src[m].ref = (uint8_t)i;
			got = build_frame(out, sizeof(out), d.tag, src, nseg);
			WRT_CHECK_U64(got, size);
			if (got == size && memcmp(out, hex, size) != 0)
				fprintf(stderr, "builder differs for %s (ref=%zu)\n", name ? name : "?", i);
			WRT_CHECK(got == size && memcmp(out, hex, size) == 0);
		}
		free(hex);
		free(name);
	}
	wrt_json_free(&j);
	free(h);
}

/* Every frame shape of the committed handshake skeletons, rebuilt and sized. */
static void test_skeleton_shapes(void)
{
	wrt_json j;
	wrt_tok conns;
	size_t c, nframes = 0;

	if (wrt_json_load_vec(&j, "msgr2/handshake-skeletons.json") != 0) {
		WRT_CHECK(0 && "cannot load handshake-skeletons.json");
		return;
	}
	conns = wrt_json_get(&j, wrt_json_root(&j), "connections");
	for (c = 0; c < wrt_json_count(&j, conns); c++) {
		wrt_tok cn = wrt_json_at(&j, conns, c);
		wrt_tok streams = wrt_json_get(&j, cn, "streams");
		char *mode = wrt_json_strdup(&j, wrt_json_get(&j, cn, "mode"));
		size_t s;

		if (mode != NULL && strcmp(mode, "crc") != 0) { /* secure mode frames are not crc framing */
			free(mode);
			continue;
		}
		free(mode);
		for (s = 0; s < wrt_json_count(&j, streams); s++) {
			wrt_tok fr = wrt_json_get(&j, wrt_json_at(&j, streams, s), "frames");
			size_t i;

			for (i = 0; i < wrt_json_count(&j, fr); i++) {
				wrt_tok f = wrt_json_at(&j, fr, i);
				wrt_tok lens = wrt_json_get(&j, f, "segment_lengths");
				unsigned nseg = (unsigned)wrt_json_count(&j, lens), m;
				wri_m2_seg_src src[4];
				static uint8_t pay[SCRATCH];
				static uint8_t out[SCRATCH];
				int ok = 0;
				size_t got;
				int64_t tag = wrt_json_int(&j, wrt_json_get(&j, f, "tag"), &ok);
				int64_t wire = wrt_json_int(&j, wrt_json_get(&j, f, "wire_size"), &ok);
				wri_m2_desc d;
				harness *h;

				for (m = 0; m < nseg && m < 4; m++) {
					src[m].len = (uint32_t)wrt_json_int(&j, wrt_json_at(&j, lens, m), &ok);
					src[m].p = pay;
					src[m].ref = 0;
				}
				memset(pay, 0x5A, sizeof(pay));
				got = build_frame(out, sizeof(out), (uint8_t)tag, src, nseg);
				WRT_CHECK_U64(got, wire);
				WRT_CHECK_STATUS(WR_OK, wri_m2_preamble_parse(NULL, out, &d));
				WRT_CHECK_U64(wri_m2_frame_body_len(&d) + 32, wire);
				/* and the parser takes it whole */
				h = (harness *)malloc(sizeof(*h));
				h_init(h, SEG0_CAP, SEG_MAX);
				h_banner(h);
				WRT_CHECK_U64(h_run(h, out, got, SCRATCH), WRI_RXE_FRAME);
				free(h);
				nframes++;
			}
		}
	}
	WRT_CHECK_U64(nframes, NFRAMES_CRC);
	wrt_json_free(&j);
}

/* ---- malformed input through the parser ---------------------------------------------------- */

static uint8_t g_pay[SCRATCH];

static size_t mk(uint8_t *out, uint8_t tag, unsigned nseg, uint32_t l0, uint32_t l1, uint32_t l2, uint32_t l3)
{
	wri_m2_seg_src s[4];

	memset(g_pay, 0x37, sizeof(g_pay));
	s[0].p = g_pay;
	s[0].len = l0;
	s[1].p = g_pay + 100;
	s[1].len = l1;
	s[2].p = g_pay + 200;
	s[2].len = l2;
	s[3].p = g_pay + 300;
	s[3].len = l3;
	s[0].ref = s[1].ref = s[2].ref = s[3].ref = 0;
	return build_frame(out, SCRATCH, tag, s, nseg);
}

static void expect_error(const char *what, const uint8_t *f, size_t n, uint32_t seg0_cap, uint32_t seg_max,
			 uint32_t sink_cap, wr_status want)
{
	harness *h = (harness *)malloc(sizeof(*h));
	wri_m2_rx_ev ev;

	h_init(h, seg0_cap, seg_max);
	h_banner(h);
	ev = h_run(h, f, n, sink_cap);
	if (ev != WRI_RXE_ERROR || wri_m2_rx_error(&h->rx)->status != want)
		fprintf(stderr, "negative case failed: %s (event %d, status %d)\n", what, (int)ev,
			(int)wri_m2_rx_error(&h->rx)->status);
	WRT_CHECK_U64(ev, WRI_RXE_ERROR);
	WRT_CHECK_STATUS(want, wri_m2_rx_error(&h->rx)->status);
	/* an error is permanent and sticky */
	WRT_CHECK_U64(h_step(h), WRI_RXE_ERROR);
	WRT_CHECK_U64(h->rx.state, WRI_RX_DEAD);
	{
		uint8_t *w = (uint8_t *)1;

		WRT_CHECK_U64(wri_m2_rx_window(&h->rx, &h->ring, &w), 0);
	}
	WRT_CHECK_U64(wri_m2_rx_error(&h->rx)->module, WR_MOD_M2);
	free(h);
}

static void test_negative(void)
{
	static uint8_t f[SCRATCH], g[SCRATCH];
	size_t n, i;
	harness *h;

	/* control frame sanity */
	n = mk(f, WRI_M2_TAG_KEEPALIVE2, 1, 8, 0, 0, 0);
	h = (harness *)malloc(sizeof(*h));
	h_init(h, SEG0_CAP, SEG_MAX);
	h_banner(h);
	WRT_CHECK_U64(h_run(h, f, n, 0), WRI_RXE_FRAME);
	free(h);

	/* preamble level, each fixed up with a valid CRC so only the named defect is present */
	memcpy(g, f, n);
	g[28] ^= 0xFF;
	expect_error("preamble crc", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_FRAME_CRC);
	memcpy(g, f, n);
	g[1] = 0;
	fix_pre(g);
	expect_error("nseg 0", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_FRAME_FORM);
	g[1] = 5;
	fix_pre(g);
	expect_error("nseg 5", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_FRAME_FORM);
	memcpy(g, f, n);
	g[0] = 0;
	fix_pre(g);
	expect_error("tag 0", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_TAG);
	g[0] = 23;
	fix_pre(g);
	expect_error("tag 23", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_TAG);
	memcpy(g, f, n);
	g[26] = 1;
	fix_pre(g);
	expect_error("flags", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_FRAME_FORM);
	memcpy(g, f, n);
	g[27] = 1;
	fix_pre(g);
	expect_error("reserved", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_FRAME_FORM);
	memcpy(g, f, n);
	wri_le32_put(g + 8, 4); /* segment 1 is unused in a 1-segment frame */
	fix_pre(g);
	expect_error("unused segment", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_FRAME_FORM);
	n = mk(f, WRI_M2_TAG_MESSAGE, 2, 41, 20, 0, 0);
	memcpy(g, f, n);
	wri_le32_put(g + 8, 0); /* last segment of 2 emptied */
	fix_pre(g);
	expect_error("empty last segment", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_FRAME_FORM);

	/* inline CRC of segment 0 */
	memcpy(g, f, n);
	g[32 + 41] ^= 1;
	expect_error("inline crc", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_FRAME_CRC);
	memcpy(g, f, n);
	g[32 + 7] ^= 0x10; /* a payload bit, CRC untouched */
	expect_error("segment 0 payload bit", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_FRAME_CRC);

	/* epilogue: late_status */
	{
		static const struct {
			uint8_t late;
			int ev; /* WRI_RXE_* */
		} lt[] = {{0x0E, WRI_RXE_FRAME}, {0x1E, WRI_RXE_FRAME}, {0xFE, WRI_RXE_FRAME}, {0x01, WRI_RXE_ABORTED},
			  {0xF1, WRI_RXE_ABORTED}, {0x03, WRI_RXE_ERROR}, {0x00, WRI_RXE_ERROR}, {0x0F, WRI_RXE_ERROR},
			  {0x0C, WRI_RXE_ERROR}, {0x02, WRI_RXE_ERROR}, {0x10, WRI_RXE_ERROR}};

		for (i = 0; i < sizeof(lt) / sizeof(lt[0]); i++) {
			memcpy(g, f, n);
			g[n - 13] = lt[i].late;
			h = (harness *)malloc(sizeof(*h));
			h_init(h, SEG0_CAP, SEG_MAX);
			h_banner(h);
			WRT_CHECK_U64(h_run(h, g, n, SCRATCH), lt[i].ev);
			if (lt[i].ev == WRI_RXE_ERROR)
				WRT_CHECK_STATUS(WR_E_M2_FRAME_FORM, wri_m2_rx_error(&h->rx)->status);
			free(h);
		}
		/* an aborted frame is dropped without looking at the (possibly garbage) CRC slots */
		memcpy(g, f, n);
		g[n - 13] = 0x01;
		g[n - 12] ^= 0xFF;
		h = (harness *)malloc(sizeof(*h));
		h_init(h, SEG0_CAP, SEG_MAX);
		h_banner(h);
		WRT_CHECK_U64(h_run(h, g, n, SCRATCH), WRI_RXE_ABORTED);
		/* the parser carries on with the next frame after next_frame() */
		wri_m2_rx_next_frame(&h->rx);
		WRT_CHECK_U64(h_run(h, f, n, SCRATCH), WRI_RXE_FRAME);
		free(h);
	}

	/* epilogue CRC slots: used ones are checked (an empty used segment must carry 0xFFFFFFFF), unused ones are not */
	n = mk(f, WRI_M2_TAG_MESSAGE, 4, 41, 30, 0, 50);
	for (i = 0; i < 3; i++) {
		memcpy(g, f, n);
		g[n - 12 + 4 * i] ^= 0x01;
		expect_error("epilogue slot", g, n, SEG0_CAP, SEG_MAX, SCRATCH, WR_E_M2_FRAME_CRC);
	}
	memcpy(g, f, n);
	wri_le32_put(g + n - 12 + 4, 0); /* slot of the empty segment 2 says 0 instead of the seed */
	expect_error("empty segment slot", g, n, SEG0_CAP, SEG_MAX, SCRATCH, WR_E_M2_FRAME_CRC);
	n = mk(f, WRI_M2_TAG_MESSAGE, 2, 41, 30, 0, 0);
	memcpy(g, f, n);
	memset(g + n - 12 + 4, 0xAB, 8); /* unused slots: not checked */
	h = (harness *)malloc(sizeof(*h));
	h_init(h, SEG0_CAP, SEG_MAX);
	h_banner(h);
	WRT_CHECK_U64(h_run(h, g, n, SCRATCH), WRI_RXE_FRAME);
	free(h);
	/* corrupt data bytes land in the sink but the frame is rejected; a discarded segment is checked too */
	memcpy(g, f, n);
	g[32 + 41 + 4 + 3] ^= 0x04;
	expect_error("segment 1 bit (sink)", g, n, SEG0_CAP, SEG_MAX, SCRATCH, WR_E_M2_FRAME_CRC);
	expect_error("segment 1 bit (discard)", g, n, SEG0_CAP, SEG_MAX, 0, WR_E_M2_FRAME_CRC);

	/* caps */
	n = mk(f, WRI_M2_TAG_MESSAGE, 2, 41, 200, 0, 0);
	expect_error("segment above seg_cap_max (discard)", f, n, SEG0_CAP, 199, 0, WR_E_M2_FRAME_TOOBIG);
	expect_error("segment above seg_cap_max (sink)", f, n, SEG0_CAP, 199, SCRATCH, WR_E_M2_FRAME_TOOBIG);
	expect_error("segment above its sink", f, n, SEG0_CAP, SEG_MAX, 199, WR_E_M2_FRAME_TOOBIG);
	expect_error("segment 0 above its buffer", f, n, 40, SEG_MAX, SCRATCH, WR_E_M2_FRAME_TOOBIG);
	h = (harness *)malloc(sizeof(*h));
	h_init(h, 41, 200); /* exactly at the caps: fine */
	h_banner(h);
	WRT_CHECK_U64(h_run(h, f, n, 200), WRI_RXE_FRAME);
	free(h);
	/* a 4 GiB segment in a preamble is refused at the preamble, before any data arrives */
	{
		uint32_t len[4] = {8, 0xFFFFFFFFu, 0, 0};

		raw_pre(g, 17, 2, len, 0, 0);
		h = (harness *)malloc(sizeof(*h));
		h_init(h, SEG0_CAP, SEG_MAX);
		h_banner(h);
		h_feed(h, g, 32);
		WRT_CHECK_U64(h_step(h), WRI_RXE_ERROR);
		WRT_CHECK_STATUS(WR_E_M2_FRAME_TOOBIG, wri_m2_rx_error(&h->rx)->status);
		free(h);
		len[0] = 0xFFFFFFFFu;
		len[1] = 0;
		raw_pre(g, 1, 1, len, 0, 0);
		h = (harness *)malloc(sizeof(*h));
		h_init(h, SEG0_CAP, SEG_MAX);
		h_banner(h);
		h_feed(h, g, 32);
		WRT_CHECK_U64(h_step(h), WRI_RXE_ERROR);
		WRT_CHECK_STATUS(WR_E_M2_FRAME_TOOBIG, wri_m2_rx_error(&h->rx)->status);
		free(h);
	}

	/* banner level through the parser */
	{
		uint8_t b[WRI_M2_BANNER_LEN];

		h = (harness *)malloc(sizeof(*h));
		h_init(h, SEG0_CAP, SEG_MAX);
		wri_m2_banner_build(b);
		wri_le64_put(b + 10, 2); /* supported without REVISION_1 */
		h_feed(h, b, sizeof(b));
		WRT_CHECK_U64(h_step(h), WRI_RXE_ERROR);
		WRT_CHECK_STATUS(WR_E_M2_FEATURES, wri_m2_rx_error(&h->rx)->status);
		free(h);
		h = (harness *)malloc(sizeof(*h));
		h_init(h, SEG0_CAP, SEG_MAX);
		wri_m2_banner_build(b);
		wri_le16_put(b + 8, 15); /* payload shorter than the two masks */
		h_feed(h, b, 25);
		WRT_CHECK_U64(h_step(h), WRI_RXE_ERROR);
		WRT_CHECK_STATUS(WR_E_M2_BANNER, wri_m2_rx_error(&h->rx)->status);
		free(h);
	}
}

/* ---- the builder: argument checks and queue rules ------------------------------------------ */

static void test_builder_args(void)
{
	static uint8_t enc[512];
	static const uint8_t data[64] = {1};
	wri_m2_txq q;
	wri_m2_seg_src s[4];
	size_t i;

	for (i = 0; i < 4; i++) {
		s[i].p = data;
		s[i].len = 8;
		s[i].ref = 0;
	}
	wri_m2_txq_init(&q, enc, sizeof(enc));
	WRT_CHECK(wri_m2_txq_idle(&q));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&q, NULL, 0, s, 1, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&q, NULL, 23, s, 1, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&q, NULL, 1, s, 0, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&q, NULL, 1, s, 5, NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&q, NULL, 1, NULL, 1, NULL, NULL));
	s[1].len = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&q, NULL, 17, s, 2, NULL, NULL)); /* last segment empty */
	s[1].len = 8;
	s[1].p = NULL;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&q, NULL, 17, s, 2, NULL, NULL)); /* NULL with a length */
	WRT_CHECK(wri_m2_txq_idle(&q)); /* nothing was appended by any failure */
	WRT_CHECK_U64(q.used, 0);
	WRT_CHECK_U64(q.niov, 0);
	/* empty frame (WAIT) and a frame whose segment 0 is empty */
	s[0].len = 0;
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_WAIT, s, 1, NULL, NULL));
	WRT_CHECK_U64(q.pending, 32);
	wri_m2_txq_reset(&q);
	s[0].len = 0;
	s[1].p = data;
	s[1].len = 8;
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, 17, s, 2, NULL, NULL));
	WRT_CHECK_U64(q.pending, 32 + 8 + 13); /* no inline CRC for an empty segment 0 */
}

int main(void)
{
	test_banner();
	test_preamble();
	test_vector_frames();
	test_skeleton_shapes();
	test_negative();
	test_builder_args();
	return wrt_finish();
}
