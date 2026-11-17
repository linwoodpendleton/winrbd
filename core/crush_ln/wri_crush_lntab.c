/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * wri_crush_lntab.c - hands the two CRUSH log tables to the rest of the core.
 *
 * This is the whole licence seam: the tables live in crush_ln_table.h, unchanged and under
 * their original LGPL-2.1 notice, and these two accessors are the only way the MIT code in
 * core/src/crush/ sees them. The arithmetic that uses the tables (wri_crush_ln) is our own
 * MIT code in core/src/crush/wri_crush_ln.c, written from docs/spec/crush-and-placement.md 3.4.2.
 */
#include "wri_crush_ln.h"
#include "crush_ln_table.h"

WR_FILE_LICENCE_LGPL21

const int64_t *wri_crush_ln_rh_lh(void)
{
	return __RH_LH_tbl;
}

const int64_t *wri_crush_ln_ll(void)
{
	return __LL_tbl;
}
