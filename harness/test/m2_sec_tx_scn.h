/* SPDX-License-Identifier: MIT */
/*
 * m2_sec_tx_scn.h - one random scenario of the secure transmit side, driven by a byte string: the shared body of test_m2_sec_tx_diff.c (bytes
 * from a generator, many scenarios) and of the fuzz target fuzz_m2_sec_tx.c (bytes from the fuzzer). Harness code, libc allowed. The includer
 * defines TXR_CHECK first (see m2_sec_tx_rig.h).
 *
 * The bytes choose: the encode buffer size and the bounce size, the secret, and then a list of steps: send a frame (tag, one to four segments,
 * lengths from "empty" and the block edges up to tens of kilobytes), let the host take some bytes (1, 7, 16, 100, 4096 ... or everything it is
 * shown), drain, reset (the connection goes away), release the frames whose last byte the host consumed. Properties held at every step and at
 * the end (a failure is a finding, never a flake):
 *   - the bytes the host consumed are exactly those of the independent encoder (ref_gcm based) for the frames the core accepted, less what a
 *     reset dropped; the independent decoder reads every frame back (when no reset happened);
 *   - the pending count is exact, a peek is repeatable, shows nothing beyond what is pending and never nothing while something is;
 *   - a frame that is refused (BUSY, TOOBIG) takes no nonce: the next accepted frame still matches the encoder's next nonce;
 *   - the caller's memory is freed (and poisoned) as soon as it may be: at once for what the frame copies (segment 0, a segment without `ref`
 *     other than segment 3), when the host consumed the frame's last byte for the rest, so a later read is an address sanitizer
 *     report, and it is never written (the segments are allocated exactly, so an overrun is a report too); guard bytes around the encode and
 *     bounce buffers are intact at the end.
 */
#ifndef M2_SEC_TX_SCN_H
#define M2_SEC_TX_SCN_H

#include "m2_sec_tx_rig.h"

#define SCN_MAX_FRAMES 48u

typedef struct scn_frame {
	uint8_t *buf[4];
	uint32_t len[4];
	uint64_t end; /* the host consumed this frame completely when r->consumed reaches it (wire bytes) */
} scn_frame;

typedef struct scn_cur {
	const uint8_t *d;
	size_t n, pos;
} scn_cur;

static inline unsigned scn_u8(scn_cur *c)
{
	return c->pos < c->n ? c->d[c->pos++] : 0u;
}

static inline uint32_t scn_len(scn_cur *c, size_t *budget)
{
	unsigned b = scn_u8(c);
	uint32_t len;

	if (b < 96u)
		len = b; /* 0 .. 95: every edge of the 48 / 96 / 16 arithmetic */
	else if (b < 176u)
		len = 96u + (b - 96u) * 5u;
	else if (b < 240u)
		len = 500u + (b - 176u) * 60u;
	else
		len = 4000u + (b - 239u) * 1500u;
	if (len > *budget)
		len %= 50u; /* the scenario's data budget is spent: only small ones from now on */
	*budget -= len <= *budget ? len : *budget;
	return len;
}

static inline void scn_release(scn_frame *fr, unsigned *nfr, int all)
{
	unsigned i, k, keep = 0;

	for (i = 0; i < *nfr; i++) {
		if (all || fr[i].end == 0u) { /* end 0: marked done by the caller */
			for (k = 0; k < 4u; k++) {
				if (fr[i].buf[k] != NULL)
					memset(fr[i].buf[k], 0xee, fr[i].len[k]); /* poison, then free */
				free(fr[i].buf[k]);
			}
		} else {
			fr[keep++] = fr[i];
		}
	}
	*nfr = keep;
}

static inline void scn_release_consumed(const txr *r, scn_frame *fr, unsigned *nfr)
{
	unsigned i;

	for (i = 0; i < *nfr; i++)
		if (fr[i].end != 0u && fr[i].end <= r->consumed)
			fr[i].end = 0u;
	scn_release(fr, nfr, 0);
}

/* Run one scenario. wire_out (optional): a malloc'd copy of what the host consumed, for the caller to compare two runs. */
static inline void txr_scenario(const uint8_t *data, size_t size, const wr_prim_ops *prim, size_t budget, uint8_t **wire_out, size_t *wire_len_out)
{
	static const uint32_t encs[8] = {160u, 192u, 256u, 320u, 512u, 1024u, 4096u, 65536u};
	static const uint32_t bounces[7] = {256u, 272u, 288u, 512u, 1024u, 4096u, 16384u};
	static const size_t wants[14] = {1u, 2u, 7u, 15u, 16u, 17u, 64u, 100u, 255u, 256u, 257u, 1000u, 4096u, 0u};
	scn_cur c;
	txr r;
	scn_frame fr[SCN_MAX_FRAMES];
	uint8_t secret[64];
	unsigned nfr = 0, steps = 0, resets = 0, i;
	uint64_t x;
	uint32_t seed_counter = 0;

	if (wire_out != NULL)
		*wire_out = NULL;
	if (wire_len_out != NULL)
		*wire_len_out = 0;
	if (size < 6u)
		return;
	c.d = data;
	c.n = size;
	c.pos = 0;
	memset(fr, 0, sizeof(fr));
	{
		uint32_t enc = encs[scn_u8(&c) % 8u], bn = bounces[scn_u8(&c) % 7u];

		x = 0x9e3779b97f4a7c15ull ^ ((uint64_t)scn_u8(&c) << 8) ^ scn_u8(&c) ^ ((uint64_t)scn_u8(&c) << 24);
		for (i = 0; i < sizeof(secret); i++) {
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
			secret[i] = (uint8_t)(x >> 24);
		}
		if (txr_open(&r, enc, bn, prim, secret) != WR_OK) {
			TXR_CHECK(0);
			return;
		}
	}
	r.keep = 1;
	while (c.pos < c.n && steps < 600u) {
		unsigned op = scn_u8(&c) % 16u;

		steps++;
		if (op < 7u) { /* send a frame */
			wri_m2_seg_src src[4];
			uint32_t len[4] = {0, 0, 0, 0};
			/* bits 2, 3 of the frame byte: segment 1 / 2 is a copy (ref 0), else referenced; bit 4: the ref flag of segment 3, which is
			 * referenced whatever it says. A seed from before these bits had them clear: every segment referenced. */
			unsigned nb = scn_u8(&c), nseg = 1u + nb % 4u, tag = 1u + scn_u8(&c) % 22u;
			scn_frame f;
			wr_status st;
			size_t k, j;

			memset(&f, 0, sizeof(f));
			for (i = 0; i < nseg; i++)
				len[i] = scn_len(&c, &budget);
			if (nseg > 1u && len[nseg - 1u] == 0u)
				len[nseg - 1u] = 1u;
			if (nfr == SCN_MAX_FRAMES) { /* make room: the host takes everything */
				txr_drain(&r, 0, 0);
				scn_release_consumed(&r, fr, &nfr);
				TXR_CHECK(nfr == 0u);
			}
			memset(src, 0, sizeof(src));
			for (i = 0; i < nseg; i++) {
				f.len[i] = len[i];
				if (len[i] != 0u) {
					f.buf[i] = (uint8_t *)malloc(len[i]); /* exactly: an overrun is an address sanitizer report */
					TXR_CHECK(f.buf[i] != NULL);
					if (f.buf[i] == NULL)
						abort();
					for (k = 0; k < len[i]; k++)
						f.buf[i][k] = (uint8_t)(0x5du * (seed_counter + 1u) + k * 29u + (k >> 8) + i);
				}
				src[i].p = f.buf[i];
				src[i].len = len[i];
				src[i].ref = (uint8_t)(i == 3u ? (nb >> 4) & 1u : (i == 0u ? 0u : !((nb >> (1u + i)) & 1u)));
			}
			seed_counter++;
			st = txr_send(&r, (uint8_t)tag, src, nseg);
			if (st == WR_OK) {
				/* What the frame copied (segment 0 always, a segment without `ref` except segment 3) is out of the caller's memory when the call
				 * returns: free it now, poisoned, so that a later read of it is an address sanitizer report (or a wrong byte on the wire). */
				for (i = 0; i < nseg; i++) {
					if (f.buf[i] != NULL && i != 3u && src[i].ref == 0u) {
						memset(f.buf[i], 0xee, len[i]);
						free(f.buf[i]);
						f.buf[i] = NULL;
					}
				}
				f.end = r.queued;
				fr[nfr++] = f;
			} else {
				TXR_CHECK(st == WR_E_BUSY || st == WR_E_TOOBIG);
				for (j = 0; j < 4u; j++)
					free(f.buf[j]);
				if (st == WR_E_BUSY)
					(void)txr_pull(&r, 1u + (size_t)txr_rnd(&r) % 3000u); /* the host makes room */
			}
		} else if (op < 12u) { /* the host takes some bytes */
			size_t want = wants[scn_u8(&c) % 14u];

			if (want == 0u && (scn_u8(&c) & 1u))
				want = 1u + scn_u8(&c) * 3u;
			(void)txr_pull(&r, want);
		} else if (op == 12u) {
			txr_drain(&r, 0, 0);
		} else if (op == 13u && resets < 3u) { /* the connection goes away with frames in flight */
			txr_reset(&r);
			scn_release(fr, &nfr, 1); /* nothing may read the dropped frames' memory from now on */
			resets++;
			r.keep = 0;
		} else {
			txr_check_queue(&r);
		}
		scn_release_consumed(&r, fr, &nfr);
	}
	txr_drain(&r, 0, 0);
	scn_release_consumed(&r, fr, &nfr);
	TXR_CHECK(nfr == 0u);
	TXR_CHECK(txr_wire_matches(&r));
	if (resets == 0u)
		txr_check_decode(&r, (size_t)(1u + (x & 0xffu) * 3u));
	if (wire_out != NULL && wire_len_out != NULL) {
		*wire_out = (uint8_t *)malloc(r.wire_len != 0u ? r.wire_len : 1u);
		TXR_CHECK(*wire_out != NULL);
		if (*wire_out != NULL) {
			if (r.wire_len != 0u)
				memcpy(*wire_out, r.wire, r.wire_len);
			*wire_len_out = r.wire_len;
		}
	}
	txr_close(&r);
}

#endif /* M2_SEC_TX_SCN_H */
