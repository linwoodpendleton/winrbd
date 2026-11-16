/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_banner.c - the msgr2 banner (docs/spec/msgr2.md 2.2): build ours, validate the peer's.
 *
 * The banner is "ceph v2\n", a u16 payload length and, in the payload, two u64: the msgr2
 * feature bits the sender supports and the bits it requires. We advertise exactly REVISION_1
 * (we implement msgr2.1 framing and nothing else) and require nothing. The peer's payload length
 * is capped (the stock code accepts any length) and the legacy v1 prefix is told apart so the
 * caller can report it specifically.
 */
#include "wri_le.h"
#include "wri_m2_frame.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define BANNER_PREFIX_LEN 8u
#define BANNER_V1_PREFIX "ceph v027"
#define BANNER_V1_PREFIX_LEN 9u
#define BANNER_PAYLOAD_MIN 16u

void wri_m2_banner_build(uint8_t out[WRI_M2_BANNER_LEN])
{
	WR_MEMCPY(out, WRI_M2_BANNER_PREFIX, BANNER_PREFIX_LEN);
	wri_le16_put(out + BANNER_PREFIX_LEN, (uint16_t)BANNER_PAYLOAD_MIN);
	wri_le64_put(out + WRI_M2_BANNER_HEAD, WRI_M2_FEATURE_REVISION_1); /* supported */
	wri_le64_put(out + WRI_M2_BANNER_HEAD + 8u, 0); /* required */
}

wr_status wri_m2_banner_head(const uint8_t head[WRI_M2_BANNER_HEAD], uint32_t *payload_len)
{
	uint32_t n;

	if (head == NULL || payload_len == NULL)
		return WR_E_INVAL;
	*payload_len = 0;
	if (!wri_ct_memeq(head, (const uint8_t *)WRI_M2_BANNER_PREFIX, BANNER_PREFIX_LEN)) {
		if (wri_ct_memeq(head, (const uint8_t *)BANNER_V1_PREFIX, BANNER_V1_PREFIX_LEN))
			return WR_E_M2_PEER_V1;
		return WR_E_M2_BANNER;
	}
	n = wri_le16_get(head + BANNER_PREFIX_LEN);
	if (n < BANNER_PAYLOAD_MIN || n > WRI_M2_BANNER_PAYLOAD_MAX)
		return WR_E_M2_BANNER;
	*payload_len = n;
	return WR_OK;
}

wr_status wri_m2_banner_payload(const uint8_t *p, size_t n, wri_m2_banner *out)
{
	wri_m2_banner b;

	if (out == NULL)
		return WR_E_INVAL;
	out->supported = 0;
	out->required = 0;
	if (p == NULL || n < BANNER_PAYLOAD_MIN)
		return WR_E_M2_BANNER;
	b.supported = wri_le64_get(p);
	b.required = wri_le64_get(p + 8);
	*out = b; /* decoded values are kept even when rejected, so the caller can report them */
	if ((b.supported & WRI_M2_FEATURE_REVISION_1) == 0)
		return WR_E_M2_FEATURES; /* we only speak msgr2.1 framing */
	if ((b.required & ~(uint64_t)WRI_M2_FEATURE_REVISION_1) != 0)
		return WR_E_M2_FEATURES; /* the peer insists on something we do not implement */
	return WR_OK;
}
