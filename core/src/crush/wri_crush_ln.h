/* SPDX-License-Identifier: MIT */
/*
 * wri_crush_ln.h - the fixed-point logarithm straw2 needs, and the licence seam around its tables.
 *
 * straw2 must pick bit-for-bit the same item as Ceph, and its draw is built on a table-driven
 * approximation of 2^44 * log2(x). One of the two tables has no closed form (crush-and-placement.md
 * 3.4.2), so both live in core/crush_ln/ unchanged, under their original LGPL-2.1 notice. This header
 * is the whole interface between the two licences:
 *
 *   wri_crush_ln_rh_lh() / wri_crush_ln_ll()   in core/crush_ln/wri_crush_lntab.c (LGPL-2.1-only): return
 *                                              the two read-only tables, nothing else;
 *   wri_crush_ln()                             in core/src/crush/wri_crush_ln.c (MIT): the seven-step
 *                                              arithmetic of crush-and-placement.md 3.4.2, our own code.
 */
#ifndef WRI_CRUSH_LN_H
#define WRI_CRUSH_LN_H

#include "wr_port.h"

#define WRI_CRUSH_LN_RH_LH_COUNT 258u /* 129 pairs: [2k] = 1/(1 + k/128) scaled by 2^48, [2k+1] = log2(1 + k/128) scaled by 2^48 */
#define WRI_CRUSH_LN_LL_COUNT 256u

/* The two tables (read-only, 258 and 256 entries). Never NULL. */
const int64_t *wri_crush_ln_rh_lh(void);
const int64_t *wri_crush_ln_ll(void);

/*
 * crush_ln(u) for u in 0..0xffff: an unsigned 64-bit approximation of 2^44 * log2(u + 1).
 * Known answers (crush-and-placement.md 5.1): 0 -> 0, 1 -> 0x100000000000, 0xffff -> 0xfffff0000000.
 * Inputs above 0xffff are masked to 16 bits (the caller always passes hash & 0xffff).
 */
uint64_t wri_crush_ln(uint32_t u);

#endif /* WRI_CRUSH_LN_H */
