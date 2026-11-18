/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_policy.c - the refusal rules of the open (design 24.3, rbd-format2.md 3.3 and 4.2) as one pure function over what the header
 * reads returned. The first rule that fails decides; its status is a stable reason for the host and the numbers that explain it go into
 * the errinfo (module WR_MOD_RBD, `what` names the rule).
 *
 * Order (rbd-format2.md 3.3): feature bits, object size, striping layout, parent, data pool, flags. The snapshot context (rule 4 of
 * the note) is judged by its decoder, and the pool checks that need the map (existence, replicated) by the open state machine.
 */
#include "wri_rbd_cls.h"

#include "wri_ctx.h"

WR_FILE_LICENCE_MIT

#define RBD_PROFILE_READER 0x1ffull /* R1: bits 0 to 8 */
#define RBD_PROFILE_WRITER 0xa1ull  /* P1: layering, deep-flatten, data-pool */
#define RBD_ORDER_MIN 12u           /* what librbd creates: 4 KiB ... */
#define RBD_ORDER_MAX 25u           /* ... to 32 MiB objects */

uint64_t wri_rbd_features_ok(int want_write)
{
	return want_write ? RBD_PROFILE_WRITER : RBD_PROFILE_READER;
}

/* Record the refusal (the first one of an errinfo stays) and return it. */
static wr_status refuse(wr_errinfo *why, wr_status st, unsigned line, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	wri_errinfo_set(why, st, WR_MOD_RBD, line, what, a0, a1, a2);
	return st;
}

#define REFUSE(why, st, what, a0, a1, a2) refuse((why), (st), (unsigned)__LINE__, (what), (uint64_t)(a0), (uint64_t)(a1), (uint64_t)(a2))

wr_status wri_rbd_check_profile(const wri_rbd_hdr *h, int want_write, wr_errinfo *why)
{
	uint64_t bad, obj_size;

	if (h == NULL)
		return WR_E_INVAL;

	/* 1. feature bits: a0 = the offending bits, a1 = all the bits, a2 = 1 for a writer. Bits above 11 are among the offenders. Striping
	 * (0x2) is in the reader's mask and, as a conditional bit, allowed for the writer too: rule 3 judges its layout for both. */
	bad = h->features & ~(wri_rbd_features_ok(want_write) | WRI_RBD_F_STRIPINGV2);
	if (bad != 0)
		return REFUSE(why, WR_E_RBD_FEATURES, "image features outside the profile", bad, h->features, want_write != 0);

	/* 2. object size: a0 = order, a1 = lowest, a2 = highest accepted. */
	if (h->order < RBD_ORDER_MIN || h->order > RBD_ORDER_MAX)
		return REFUSE(why, WR_E_RBD_ORDER, "object size order not in 12 to 25", h->order, RBD_ORDER_MIN, RBD_ORDER_MAX);
	obj_size = 1ull << h->order;

	/* 3. striping: the default form only (what librbd also takes for a zero unit or count). a0 = unit, a1 = count, a2 = object size. */
	if ((h->features & WRI_RBD_F_STRIPINGV2) != 0 && h->stripe_unit != 0 && h->stripe_count != 0 &&
	    (h->stripe_count != 1 || h->stripe_unit != obj_size))
		return REFUSE(why, WR_E_RBD_STRIPING, "non-default striping", h->stripe_unit, h->stripe_count, obj_size);

	/* 4. parent: parent_get found one, or parent_overlap_get answered, or op_features says clone child (only valid with the operations
	 * bit). a0 = bit 0 parent_get, bit 1 overlap present, bit 2 clone-child; a1 = the overlap; a2 = op_features. */
	{
		uint64_t ev = 0;

		if (h->has_parent != 0)
			ev |= 1u;
		if (h->has_overlap != 0)
			ev |= 2u;
		if ((h->features & WRI_RBD_F_OPERATIONS) != 0 && (h->op_features & WRI_RBD_OPF_CLONE_CHILD) != 0)
			ev |= 4u;
		if (ev != 0)
			return REFUSE(why, WR_E_RBD_PARENT, "image is a clone", ev, h->has_overlap != 0 ? h->overlap : 0, h->op_features);
	}

	/* 5. data pool: the bit is set but get_data_pool answered "none". a0 = the id (negative, as a 64-bit value). A pool id without the bit
	 * is not judged here: the open ignores it (data objects stay in the image pool); see the open issues of the module. */
	if ((h->features & WRI_RBD_F_DATA_POOL) != 0 && h->data_pool_id < 0)
		return REFUSE(why, WR_E_RBD_DATA_POOL, "data-pool feature set but no data pool id", (uint64_t)h->data_pool_id, 0, 0);

	/* 6. flags: a reader ignores them, a writer refuses any (object map / fast diff marked invalid). a0 = flags. */
	if (want_write && h->flags != 0)
		return REFUSE(why, WR_E_RBD_FLAGS, "image flags are set", h->flags, 0, 0);

	return WR_OK;
}
