/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_modes.c - connection-mode policy (see wri_m2_modes.h; docs/design/core-architecture.md 34.2).
 *
 * Everything here is a pure function of its arguments: no state, no memory, nothing secret. An offer is a small bit mask; the
 * canonical masks (the ones wri_m2_offer_for returns) are
 *
 *   crc only            CRC
 *   [crc, secure]       CRC | SECURE
 *   [secure, crc]       CRC | SECURE | SECURE_FIRST
 *   secure only         SECURE
 *
 * Masks that a caller assembles by hand are read leniently and safely: bits we do not know are ignored, SECURE_FIRST only
 * matters when both modes are present, and a mask that offers nothing (0, or only SECURE_FIRST) means crc only, the behaviour of a
 * connection that has no secure slot.
 */
#include "wri_m2_modes.h"

WR_FILE_LICENCE_MIT

/* The mask a policy gives for one peer type, or 0 for a policy value (or peer type) that does not exist. */
static uint8_t offer_of_policy(uint8_t policy, uint8_t peer_type)
{
	if (peer_type != WRI_ENTITY_MON && peer_type != WRI_ENTITY_OSD)
		return 0u;
	switch (policy) {
	case WR_MODE_CRC_ONLY:
		return WRI_M2_OFFER_CRC;
	case WR_MODE_CRC_FIRST:
		return (uint8_t)(WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE);
	case WR_MODE_SECURE_FIRST:
		return (uint8_t)(WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE | WRI_M2_OFFER_SECURE_FIRST);
	case WR_MODE_SECURE_ONLY:
		return WRI_M2_OFFER_SECURE;
	case WR_MODE_STOCK:
		/* what the stock client offers by default (secure-mode spec 2.9): monitors secure first, everything else crc first */
		if (peer_type == WRI_ENTITY_MON)
			return (uint8_t)(WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE | WRI_M2_OFFER_SECURE_FIRST);
		return (uint8_t)(WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE);
	default:
		return 0u;
	}
}

uint8_t wri_m2_offer_for(uint8_t policy, uint8_t policy_osd, uint8_t peer_type)
{
	if (peer_type == WRI_ENTITY_OSD && policy_osd != 0u)
		policy = policy_osd;
	return offer_of_policy(policy, peer_type);
}

int wri_m2_policy_valid(uint8_t policy, uint8_t policy_osd)
{
	if (offer_of_policy(policy, WRI_ENTITY_MON) == 0u)
		return 0;
	return policy_osd == 0u || offer_of_policy(policy_osd, WRI_ENTITY_OSD) != 0u;
}

size_t wri_m2_offer_list(uint8_t offer, uint32_t out[2])
{
	int crc = (offer & WRI_M2_OFFER_CRC) != 0u;
	int sec = (offer & WRI_M2_OFFER_SECURE) != 0u;

	if (!crc && !sec) {
		out[0] = WRI_CONN_MODE_CRC; /* an empty mask is crc only */
		return 1u;
	}
	if (crc && sec) {
		if ((offer & WRI_M2_OFFER_SECURE_FIRST) != 0u) {
			out[0] = WRI_CONN_MODE_SECURE;
			out[1] = WRI_CONN_MODE_CRC;
		} else {
			out[0] = WRI_CONN_MODE_CRC;
			out[1] = WRI_CONN_MODE_SECURE;
		}
		return 2u;
	}
	out[0] = sec ? WRI_CONN_MODE_SECURE : WRI_CONN_MODE_CRC;
	return 1u;
}

int wri_m2_offer_has(uint8_t offer, uint32_t mode)
{
	uint32_t list[2];
	size_t n = wri_m2_offer_list(offer, list);
	size_t i;

	for (i = 0; i < n; i++)
		if (list[i] == mode)
			return 1;
	return 0;
}

int wri_m2_policy_may_secure(uint8_t policy, uint8_t policy_osd)
{
	/* the monitor connection follows `policy`; the OSD connection follows policy_osd when set. An unknown value offers nothing. */
	if ((wri_m2_offer_for(policy, policy_osd, WRI_ENTITY_MON) & WRI_M2_OFFER_SECURE) != 0u)
		return 1;
	if ((wri_m2_offer_for(policy, policy_osd, WRI_ENTITY_OSD) & WRI_M2_OFFER_SECURE) != 0u)
		return 1;
	return 0;
}
