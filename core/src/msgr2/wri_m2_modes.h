/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_modes.h - connection-mode policy: what AUTH_REQUEST offers (preferred_modes) and what AUTH_DONE may answer.
 * Spec: docs/spec/msgr2-secure-mode.md 2.4, 2.9; design: docs/design/core-architecture.md 34.2.
 *
 * Pure functions, no state. The server walks OUR list in order and takes the first mode it allows for this peer type, so the
 * order of the offer is the preference; AUTH_DONE's connection mode must be one of the modes offered (the reference client does not
 * check this, we do: WR_E_M2_MODE).
 */
#ifndef WRI_M2_MODES_H
#define WRI_M2_MODES_H

#include "wr_config.h"
#include "wr_err.h"
#include "wri_m2_ctl.h"

/* Bits of a connection's `offer` mask (stored in the connection; 0 means crc only, the behaviour before secure mode existed). */
#define WRI_M2_OFFER_CRC 0x1u
#define WRI_M2_OFFER_SECURE 0x2u
#define WRI_M2_OFFER_SECURE_FIRST 0x4u /* with both bits above: secure is listed before crc */

/*
 * The offer for a peer. policy is a WR_MODE_* (1 .. 5); peer_type WRI_ENTITY_MON or WRI_ENTITY_OSD; `policy_osd` is
 * wr_config.mode_policy_osd (0 = use `policy`). Returns the offer mask (WRI_M2_OFFER_*), or 0 for a policy value that does not exist
 * (the caller refuses the configuration; 0 is never a valid offer here, unlike the stored default).
 * WR_MODE_STOCK resolves per peer: monitor [secure, crc], OSD [crc, secure].
 */
uint8_t wri_m2_offer_for(uint8_t policy, uint8_t policy_osd, uint8_t peer_type);

/*
 * Is this a configuration the engine may run with? policy must be a WR_MODE_* (1 .. 5) and policy_osd 0 (same as policy) or a WR_MODE_*.
 * This is the one validity rule: wri_m2_offer_for() answers 0 for a bad value, and 0 stored as an offer means crc only, so a caller
 * that skipped this check would turn a bad `mode_policy_osd` next to a secure-only `mode_policy` into a silent crc offer to the OSDs.
 * Returns 1 when valid, 0 when not (the create call refuses with WR_E_INVAL).
 */
int wri_m2_policy_valid(uint8_t policy, uint8_t policy_osd);

/* Write the preferred_modes list for an offer mask (an empty mask means crc only): returns the number of entries (1 or 2), in order. */
size_t wri_m2_offer_list(uint8_t offer, uint32_t out[2]);

/* Is `mode` (WRI_CONN_MODE_*) one of the offered ones? An empty mask offers crc only. */
int wri_m2_offer_has(uint8_t offer, uint32_t mode);

/* Does any connection of this configuration possibly end in secure mode? Decides whether the secure slots are reserved (0 = no). */
int wri_m2_policy_may_secure(uint8_t policy, uint8_t policy_osd);

#endif /* WRI_M2_MODES_H */
