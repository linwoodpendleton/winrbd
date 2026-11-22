/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the secure receive parser (core/src/msgr2/wri_m2_sec_rx.c and wri_m2_sec_rx2.c, design 34.7 and 39.4): encrypt, then
 * parse, with deliberate corruptions, against the independent decoder of the simulator (harness/test/support/sim_m2_sec.c).
 *
 * Input layout (shorter than 48 bytes: ignored):
 *
 *   byte 0       bits 0-1 feeding style (whole, one byte at a time, random pieces, pieces of 16), bit 2 ring only (never window/commit),
 *                bit 3 attach sinks to segments 1..3 (else they are discarded), bits 4-5 ring size (16, 64, 1024, 4096), bits 6-7 work
 *                budget per step (none, 1, 16, 1000)
 *   byte 1       bit 0 flip one bit of the finished bytes, bit 1 ... in a tag when the frame has tags at a place we can name (the last 16 bytes
 *                of part 1), bit 2 cut the stream at a point, bit 3 a second frame follows, bit 4 the second frame is a replay of the
 *                first (else a fresh frame with the next nonces), bit 5 a tiny segment 0 buffer (64 bytes, else 4096), bit 6 a second
 *                flip after the first, bit 7 big segments (up to about 12 KiB, so the direct window is used)
 *   bytes 2-3    where: the byte of the flip (modulo the stream), the point of the cut
 *   byte 4       the bit of the flip (low 3 bits)
 *   bytes 5-6    seg_cap_max (0 = 100000)
 *   byte 7       frame tag (1 + b % 22)
 *   byte 8       segments - 1 (low 2 bits), bit 2 segment 0 is discarded (no buffer: capped by seg_cap_max, nothing stored), bit 3 the sinks
 *                have 50 bytes of room behind the data (the padding must not land there)
 *   bytes 9-16   four u16 lengths (modulo 2048, or 12288 with the big flag)
 *   bytes 17-18  the mask of pre-encryption defects (SIM_SEC_M_LATE .. SIM_SEC_M_KEEP_TAIL and SIM_SEC_M_NONCE, SIM_SEC_M_KEY)
 *   bytes 19-27  late_status, pre_flags, pre_reserved, pre_nseg, pre_tag, pre_crc_xor, slot_junk, pad_fill, pre_len_mask
 *   bytes 28-43  four u32 announced lengths (a lie when the mask says so)
 *   byte 44      the operation the nonce defect hits;  bytes 45-46 its delta (modulo 5, minus 2)
 *   rest         the plaintext of the segments (cycled)
 *
 * Properties: no crash or undefined behaviour; nothing is written outside the sinks and the segment 0 buffer (heap blocks with canary
 * bands, and ASan for the rest); the event sequence is legal (SEG0 before FRAME / ABORTED, nothing but ERROR after an error, ERROR sticky);
 * the parser agrees with the independent decoder on the same bytes: the same number of frames, each with the same tag, segment count,
 * lengths and bytes (segment 0 always, the others when sinks are attached), the same verdict at the end (a frame, an error with the same
 * status, or "need more bytes"); the plaintext of a tampered frame is never accepted: a flipped bit anywhere in the first frame means that
 * frame is never delivered, and SEG0 only if the flip is behind the part that carries segment 0.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test/m2_sec_rx_rig.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define HDR 47u
#define CHECK(c)                                                                                  \
	do {                                                                                      \
		if (!(c)) {                                                                       \
			fprintf(stderr, "fuzz_m2_sec_rx: property failed at %s:%d: %s\n", __FILE__, __LINE__, #c); \
			__builtin_trap();                                                         \
		}                                                                                 \
	} while (0)

static uint32_t u16(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8); }
static uint32_t u32(const uint8_t *p) { return u16(p) | (u16(p + 2) << 16); }

static uint32_t pad16(uint32_t x) { return (x + 15u) & ~15u; }

typedef struct simframe {
	uint8_t aborted;
	uint8_t tag, nseg;
	uint32_t len[4];
	uint8_t *seg[4];
} simframe;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint32_t ring_caps[4] = {16, 64, 1024, 4096};
	static const uint32_t budgets[4] = {0, 1, 16, 1000};
	static const uint32_t mask_lo[8] = {SIM_SEC_M_LATE, SIM_SEC_M_FLAGS, SIM_SEC_M_RESERVED, SIM_SEC_M_PRE_NSEG, SIM_SEC_M_PRE_TAG,
					    SIM_SEC_M_PRE_LEN, SIM_SEC_M_PRE_CRC, SIM_SEC_M_PAD};
	static const uint32_t mask_hi[4] = {SIM_SEC_M_SLOT, SIM_SEC_M_KEEP_TAIL, SIM_SEC_M_NONCE, SIM_SEC_M_KEY};
	uint8_t secret[64];
	sim_sec_ctx srv, cli;
	sim_sec_mut mut;
	sim_sec_spec spec;
	uint8_t *seg[4] = {NULL, NULL, NULL, NULL};
	uint8_t *w1 = NULL, *w2 = NULL, *all = NULL;
	size_t n1 = 0, n2 = 0, alln = 0;
	uint32_t len[4], seg_cap_max, seg0_cap;
	unsigned nseg, i, b0 = 0, b1 = 0, nframes_core;
	size_t content_off = HDR, flip_at = 0, cut_at = 0;
	int attach, big, disc0, roomy;
	sxr rig, *r = &rig;
	sxr_out o;
	sxr_cfg c;
	sim_sec_dec dec;
	simframe sf[SXR_MAX_FRAMES];
	unsigned nsf = 0;
	int sim_end = 0; /* the decoder's last answer: NEED, or ERROR */
	wr_status sim_err = WR_OK;
	size_t seg0_end = 96;

	memset(&rig, 0, sizeof(rig));
	memset(&srv, 0, sizeof(srv));
	memset(&cli, 0, sizeof(cli));
	memset(&o, 0, sizeof(o));
	memset(&dec, 0, sizeof(dec));
	memset(sf, 0, sizeof(sf));
	if (size < HDR + 1u) /* before the first read of the input: an empty input is a buffer of no bytes at all */
		return 0;
	b0 = data[0];
	b1 = data[1];
	attach = (b0 >> 3) & 1;
	big = (b1 >> 7) & 1;
	seg_cap_max = u16(data + 5) != 0 ? u16(data + 5) : 100000u;
	seg0_cap = ((b1 >> 5) & 1) ? 64u : 4096u;
	nseg = 1u + (data[8] & 3u);
	disc0 = (data[8] >> 2) & 1;
	roomy = (data[8] >> 3) & 1;
	for (i = 0; i < 4; i++) {
		len[i] = u16(data + 9 + 2 * i) % (big ? 12288u : 2048u);
		if (i >= nseg)
			len[i] = 0;
	}
	if (nseg > 1 && len[nseg - 1] == 0)
		len[nseg - 1] = 1u + (data[7] & 31u); /* a legal shape; the defects below make it illegal on purpose */

	/* a fixed secret from the input's own bytes (so the corpus can hold other keys), never all equal seeds */
	for (i = 0; i < 64; i++)
		secret[i] = (uint8_t)(data[(i * 7u) % size] + i * 5u);
	secret[16] ^= 0x5a; /* the two seeds differ */
	if (sim_sec_ctx_init(&srv, secret, sizeof(secret), 1) != 0 || sim_sec_ctx_init(&cli, secret, sizeof(secret), 0) != 0)
		return 0;

	/* the plaintext of the segments, cycled from the rest of the input */
	memset(&spec, 0, sizeof(spec));
	spec.tag = (uint8_t)(1u + data[7] % 22u);
	spec.nseg = nseg;
	for (i = 0; i < nseg; i++) {
		size_t k;

		seg[i] = (uint8_t *)malloc((size_t)len[i] + 1u);
		CHECK(seg[i] != NULL);
		for (k = 0; k < len[i]; k++)
			seg[i][k] = (size - HDR) != 0 ? data[HDR + (content_off - HDR + k) % (size - HDR)] : 0;
		content_off += len[i];
		spec.seg[i] = seg[i];
		spec.len[i] = len[i];
	}
	memset(&mut, 0, sizeof(mut));
	for (i = 0; i < 8; i++)
		if ((data[17] >> i) & 1u)
			mut.mask |= mask_lo[i];
	for (i = 0; i < 4; i++)
		if ((data[18] >> i) & 1u)
			mut.mask |= mask_hi[i];
	mut.late_status = data[19];
	mut.pre_flags = data[20];
	mut.pre_reserved = data[21];
	mut.pre_nseg = data[22];
	mut.pre_tag = data[23];
	mut.pre_crc_xor = data[24];
	mut.slot_junk = data[25];
	mut.pad_fill = data[26];
	mut.pre_len_mask = data[27];
	for (i = 0; i < 4; i++)
		mut.pre_len[i] = u32(data + 28 + 4 * i);
	mut.nonce_part = (uint8_t)(data[44] % 4u);
	mut.nonce_delta = (int32_t)(u16(data + 45) % 5u) - 2;

	{
		size_t need = sim_sec_frame_len_m(&spec, &mut, NULL, NULL);

		if (need == 0)
			need = sim_sec_frame_len(&spec, NULL, NULL);
		if (need == 0)
			goto out;
		w1 = (uint8_t *)malloc(need + 64u);
		CHECK(w1 != NULL);
		if (sim_sec_encode(&srv.tx, &spec, &mut, w1, need + 64u, &n1) != 0)
			goto out; /* a shape or a defect the encoder refuses */
	}
	if ((b1 >> 3) & 1u) {
		if ((b1 >> 4) & 1u) { /* replay of the first frame */
			w2 = (uint8_t *)malloc(n1 + 1u);
			CHECK(w2 != NULL);
			memcpy(w2, w1, n1);
			n2 = n1;
		} else { /* a fresh frame with the next nonces, undamaged */
			size_t need = sim_sec_frame_len(&spec, NULL, NULL);

			if (need != 0) {
				w2 = (uint8_t *)malloc(need + 64u);
				CHECK(w2 != NULL);
				if (sim_sec_encode(&srv.tx, &spec, NULL, w2, need + 64u, &n2) != 0) {
					free(w2);
					w2 = NULL;
					n2 = 0;
				}
			}
		}
	}
	alln = n1 + n2;
	all = (uint8_t *)malloc(alln + 1u);
	CHECK(all != NULL);
	memcpy(all, w1, n1);
	if (n2 != 0)
		memcpy(all + n1, w2, n2);

	/* where the first frame's parts end, for the tampering property (honest only for an unmutated shape: the defects may change the layout) */
	if (spec.len[0] > 48u)
		seg0_end = 96u + pad16(spec.len[0]) - 48u + 16u;
	if (spec.len[0] <= 48u)
		seg0_end = 96;

	/* tampering with the finished bytes */
	if ((b1 & 1u) != 0 && alln != 0) {
		flip_at = u16(data + 2) % alln;
		all[flip_at] ^= (uint8_t)(1u << (data[4] & 7u));
	}
	if (((b1 >> 1) & 1u) != 0 && alln >= 96) { /* a bit of part 1's tag */
		size_t at = 80u + (u16(data + 2) % 16u);

		all[at] ^= (uint8_t)(1u << (data[4] & 7u));
		if (flip_at == 0 || at < flip_at)
			flip_at = at;
	}
	if (((b1 >> 6) & 1u) != 0 && alln != 0) {
		all[u16(data + 3) % alln] ^= (uint8_t)(1u << ((data[4] >> 3) & 7u));
	}
	if (((b1 >> 2) & 1u) != 0 && alln > 1) {
		cut_at = 1u + (u16(data + 2) % (alln - 1u));
		alln = cut_at;
	}

	/* the independent decoder on the same bytes */
	sim_sec_dec_init(&dec, &cli.rx, disc0 ? seg_cap_max : seg0_cap, seg_cap_max);
	CHECK(sim_sec_dec_feed(&dec, all, alln) == 0);
	for (;;) {
		sim_sec_frame f;
		int rc = sim_sec_dec_next(&dec, &f);

		if (rc == SIM_SEC_DEC_FRAME || rc == SIM_SEC_DEC_ABORTED) {
			simframe *s;

			if (nsf >= SXR_MAX_FRAMES)
				break;
			s = &sf[nsf++];
			memset(s, 0, sizeof(*s));
			s->aborted = rc == SIM_SEC_DEC_ABORTED;
			s->tag = f.tag;
			s->nseg = f.nseg;
			for (i = 0; i < 4; i++) {
				s->len[i] = f.len[i];
				if (i < f.nseg && f.seg[i] != NULL) {
					s->seg[i] = (uint8_t *)malloc((size_t)f.len[i] + 1u);
					CHECK(s->seg[i] != NULL);
					memcpy(s->seg[i], f.seg[i], f.len[i]);
				}
			}
			continue;
		}
		sim_end = rc;
		sim_err = dec.err;
		break;
	}

	/* the core */
	memset(&c, 0, sizeof(c));
	c.split = b0 & 3u;
	c.chunk = 40;
	c.via_ring = (int)((b0 >> 2) & 1u);
	c.budget = budgets[(b0 >> 6) & 3u];
	c.seed = u32(data + 1) | 1u;
	for (i = 1; i < 4; i++)
		c.sink_mode[i] = attach ? (roomy ? SXR_SINK_BIG : SXR_SINK_EXACT) : SXR_SINK_NONE;
	if (sxr_init(r, NULL, secret, sizeof(secret), 0, seg0_cap, seg_cap_max, ring_caps[(b0 >> 4) & 3u]) != 0)
		goto out;
	if (disc0) { /* the owner does not want segment 0: the parser still verifies and skips it */
		r->rx.sink[0].dst = NULL;
		r->rx.sink[0].cap = 0;
	}
	sxr_run(r, all, alln, &c, &o);

	CHECK(!o.stalled);
	CHECK(o.guard_bad == 0);
	CHECK(o.order_bad == 0);
	nframes_core = o.nframes;
	CHECK(nframes_core == nsf);
	for (i = 0; i < nsf; i++) {
		const sxr_frame *f = &o.fr[i];
		unsigned k;

		CHECK((f->ev == WRI_RXE_ABORTED) == (sf[i].aborted != 0));
		CHECK(f->desc.tag == sf[i].tag && f->desc.nseg == sf[i].nseg);
		for (k = 0; k < 4; k++)
			CHECK(f->desc.len[k] == sf[i].len[k]);
		CHECK(f->stored[0] == (disc0 ? 0u : sf[i].len[0]));
		CHECK(disc0 || sf[i].len[0] == 0 || memcmp(f->seg[0], sf[i].seg[0], sf[i].len[0]) == 0);
		if (f->ev == WRI_RXE_FRAME && attach) {
			for (k = 1; k < sf[i].nseg; k++)
				CHECK(f->stored[k] == sf[i].len[k] && (sf[i].len[k] == 0 || memcmp(f->seg[k], sf[i].seg[k], sf[i].len[k]) == 0));
		}
	}
	if (sim_end == SIM_SEC_DEC_ERROR) {
		/* A preamble with several defects at once is reported by its first one, and the two checkers walk the fields in a different order
		 * (the core's wri_m2_preamble_parse is shared with the crc parser: slots, empty last segment, tag value, flags; the simulator:
		 * nseg, tag value, flags, reserved byte, slots, empty last segment). One defect alone gives the same status in both; with
		 * several, "unknown tag" and "malformed" are one verdict here: a preamble that is wrong behind a right tag. */
		wr_status want = sim_err == WR_E_M2_TAG ? WR_E_M2_FRAME_FORM : sim_err;
		wr_status got = o.err == WR_E_M2_TAG ? WR_E_M2_FRAME_FORM : o.err;

		if (!o.errored || got != want)
			fprintf(stderr, "fuzz_m2_sec_rx: sim says %s (%d), core %s (%d); frames %u\n", wr_status_name(sim_err), (int)sim_err,
				o.errored ? wr_status_name(o.err) : "no error", (int)o.err, o.nframes);
		CHECK(o.errored);
		CHECK(got == want);
	} else {
		CHECK(!o.errored);
	}
	/* a tampered first frame is never delivered, and SEG0 only when the first changed byte is behind the part that carries segment 0
	 * (the bytes of the first frame as sent are w1; two flips may cancel, so the difference itself is what counts) */
	{
		size_t lim = alln < n1 ? alln : n1, first = lim;

		for (i = 0; i < lim; i++) {
			if (all[i] != w1[i]) {
				first = i;
				break;
			}
		}
		if (first < lim && !(mut.mask & (SIM_SEC_M_KEEP_TAIL | SIM_SEC_M_PRE_NSEG | SIM_SEC_M_PRE_LEN | SIM_SEC_M_NONCE | SIM_SEC_M_KEY))) {
			size_t part_end = first < 96u ? 96u : (first < seg0_end ? seg0_end : n1); /* where the tag of the part with the damage ends */

			CHECK(o.nframes == 0);
			if (alln >= part_end) { /* that tag is in the stream: it fails, unless a rule behind an earlier verified tag (a cap) stopped the parser first */
				CHECK(o.errored);
				if (first < 96u) /* nothing before the first tag: only the tag can be what fails */
					CHECK(o.err == WR_E_M2_SEC_TAG);
			}
			if (first < seg0_end)
				CHECK(!(o.nev > 0 && o.evs[0] == WRI_RXE_SEG0));
		}
	}
out:
	sxr_out_free(&o);
	if (r->secure)
		sxr_wipe(r);
	for (i = 0; i < nsf; i++) {
		unsigned k;

		for (k = 0; k < 4; k++)
			free(sf[i].seg[k]);
	}
	sim_sec_dec_free(&dec);
	free(w1);
	free(w2);
	free(all);
	for (i = 0; i < 4; i++)
		free(seg[i]);
	sim_sec_ctx_wipe(&srv);
	sim_sec_ctx_wipe(&cli);
	return 0;
}
