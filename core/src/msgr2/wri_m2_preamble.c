/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_preamble.c - the 32-byte frame preamble (docs/spec/msgr2.md 2.3): parse with full
 * validation, build, and the size of what follows it (2.6.1).
 *
 * Layout: tag, segment count, four (u32 length, u16 alignment) pairs, flags, reserved byte, and
 * a CRC-32C (seed 0) over the first 28 bytes. Everything is read byte-wise through wri_le.h.
 * The alignment fields are advisory and are not validated on receive; on send the caller picks
 * them (8, 8, 8, 4096 for MESSAGE, the transmit queue fills them in).
 */
#include "wri_le.h"
#include "wri_m2_frame.h"
#include "wri_prim.h"

WR_FILE_LICENCE_MIT

#define PRE_NSEG 1u
#define PRE_SEGS 2u
#define PRE_SEG_STRIDE 6u
#define PRE_FLAGS 26u
#define PRE_RESERVED 27u
#define PRE_CRC 28u

wr_status wri_m2_preamble_parse(const wr_prim_ops *prim, const uint8_t p[WRI_M2_PREAMBLE_LEN],
				wri_m2_desc *out)
{
	wri_m2_desc d;
	unsigned i;

	if (p == NULL || out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	if (wri_p_crc32c(prim, 0, p, PRE_CRC) != wri_le32_get(p + PRE_CRC))
		return WR_E_M2_FRAME_CRC;
	WR_MEMSET(&d, 0, sizeof(d));
	d.tag = p[0];
	d.nseg = p[PRE_NSEG];
	d.flags = p[PRE_FLAGS];
	if (d.nseg < 1u || d.nseg > WRI_M2_MAX_SEGS)
		return WR_E_M2_FRAME_FORM;
	for (i = 0; i < WRI_M2_MAX_SEGS; i++) {
		d.len[i] = wri_le32_get(p + PRE_SEGS + i * PRE_SEG_STRIDE);
		d.align[i] = wri_le16_get(p + PRE_SEGS + i * PRE_SEG_STRIDE + 4u);
	}
	for (i = d.nseg; i < WRI_M2_MAX_SEGS; i++) {
		if (d.len[i] != 0 || d.align[i] != 0)
			return WR_E_M2_FRAME_FORM; /* unused segment slots are zero */
	}
	if (d.nseg > 1u && d.len[d.nseg - 1u] == 0)
		return WR_E_M2_FRAME_FORM; /* the last segment of a multi-segment frame is never empty */
	if (d.tag < 1u || d.tag > WRI_M2_TAG_MAX)
		return WR_E_M2_TAG;
	if (d.flags != 0 || p[PRE_RESERVED] != 0)
		return WR_E_M2_FRAME_FORM; /* compression is not negotiated; reserved must be zero */
	*out = d;
	return WR_OK;
}

void wri_m2_preamble_build(const wr_prim_ops *prim, uint8_t out[WRI_M2_PREAMBLE_LEN], const wri_m2_desc *d)
{
	unsigned i;

	WR_MEMSET(out, 0, WRI_M2_PREAMBLE_LEN);
	out[0] = d->tag;
	out[PRE_NSEG] = d->nseg;
	for (i = 0; i < WRI_M2_MAX_SEGS && i < d->nseg; i++) {
		wri_le32_put(out + PRE_SEGS + i * PRE_SEG_STRIDE, d->len[i]);
		wri_le16_put(out + PRE_SEGS + i * PRE_SEG_STRIDE + 4u, d->align[i]);
	}
	out[PRE_FLAGS] = d->flags;
	wri_le32_put(out + PRE_CRC, wri_p_crc32c(prim, 0, out, PRE_CRC));
}

uint64_t wri_m2_frame_body_len(const wri_m2_desc *d)
{
	uint64_t n = 0;
	unsigned i;

	if (d->len[0] != 0)
		n += (uint64_t)d->len[0] + WRI_M2_CRC_LEN;
	for (i = 1; i < WRI_M2_MAX_SEGS && i < d->nseg; i++)
		n += d->len[i];
	if (d->nseg > 1u)
		n += WRI_M2_EPILOGUE_LEN;
	return n;
}
