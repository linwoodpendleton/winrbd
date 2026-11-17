/* SPDX-License-Identifier: MIT */
/*
 * wri_crush_ln.c - the fixed-point logarithm of straw2: 2^44 * log2(u + 1) for u in 0..0xffff.
 *
 * The arithmetic is written from docs/spec/crush-and-placement.md 3.4.2. The two tables it reads come
 * from core/crush_ln/ (LGPL-2.1-only) only through wri_crush_ln_rh_lh() and wri_crush_ln_ll(); nothing
 * of that directory is included here.
 */
#include "wri_crush_ln.h"

WR_FILE_LICENCE_MIT

uint64_t wri_crush_ln(uint32_t u)
{
	const int64_t *rh_lh = wri_crush_ln_rh_lh();
	const int64_t *ll = wri_crush_ln_ll();
	uint32_t x = (u & 0xffffu) + 1u; /* 1..0x10000 */
	uint32_t iexpon = 15u;
	uint32_t index1;
	uint64_t rh, lh, xl, lo;

	/* Normalise to 0x8000..0x10000: shift left until bit 15 is set (0x10000 already has bit 16 set). */
	while ((x & 0x18000u) == 0u) {
		x <<= 1;
		iexpon--;
	}
	index1 = (x >> 8) << 1; /* even, 256..512 */
	rh = (uint64_t)rh_lh[index1 - 256u];
	lh = (uint64_t)rh_lh[index1 + 1u - 256u];
	xl = ((uint64_t)x * rh) >> 48;
	lo = (uint64_t)ll[xl & 0xffu];
	return ((uint64_t)iexpon << 44) + ((lh + lo) >> 4);
}
