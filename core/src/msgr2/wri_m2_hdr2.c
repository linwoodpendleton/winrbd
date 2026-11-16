/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_hdr2.c - the 41-byte ceph_msg_header2 (segment 0 of a MESSAGE frame, msgr2.md 2.9).
 *
 *   off  size  field                  off  size  field
 *     0     8  seq                     28     8  ack_seq
 *     8     8  tid                     36     1  flags
 *    16     2  type                    37     2  compat_version
 *    18     2  priority                39     2  reserved (written 0, ignored when read)
 *    20     2  version
 *    22     4  data_pre_padding_len
 *    26     2  data_off
 *
 * The stock code does not check the segment length before reading these fields; we do: fewer than
 * 41 bytes is WR_E_TRUNCATED, more is accepted and the surplus ignored (the frame layer has
 * already bounded and checksummed the segment).
 */
#include "wri_le.h"
#include "wri_m2_ctl.h"

WR_FILE_LICENCE_MIT

wr_status wri_m2_hdr2_decode(const uint8_t *p, size_t len, wri_m2_hdr2 *out)
{
	if (out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	if (p == NULL)
		return WR_E_INVAL;
	if (len < WRI_M2_HDR2_LEN)
		return WR_E_TRUNCATED;
	out->seq = wri_le64_get(p);
	out->tid = wri_le64_get(p + 8);
	out->type = wri_le16_get(p + 16);
	out->priority = wri_le16_get(p + 18);
	out->version = wri_le16_get(p + 20);
	out->data_pre_padding_len = wri_le32_get(p + 22);
	out->data_off = wri_le16_get(p + 26);
	out->ack_seq = wri_le64_get(p + 28);
	out->flags = p[36];
	out->compat_version = wri_le16_get(p + 37);
	return WR_OK;
}

void wri_m2_hdr2_encode(uint8_t out[WRI_M2_HDR2_LEN], const wri_m2_hdr2 *h)
{
	if (out == NULL || h == NULL)
		return;
	wri_le64_put(out, h->seq);
	wri_le64_put(out + 8, h->tid);
	wri_le16_put(out + 16, h->type);
	wri_le16_put(out + 18, h->priority);
	wri_le16_put(out + 20, h->version);
	wri_le32_put(out + 22, h->data_pre_padding_len);
	wri_le16_put(out + 26, h->data_off);
	wri_le64_put(out + 28, h->ack_seq);
	out[36] = h->flags;
	wri_le16_put(out + 37, h->compat_version);
	wri_le16_put(out + 39, 0);
}
