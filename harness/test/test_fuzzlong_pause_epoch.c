/* SPDX-License-Identifier: MIT */
/*
 * test_fuzzlong_pause_epoch.c - the contract the fuzz target fuzz_osd_req relies on when it ends a run (a finding of the long fuzz run, design 40.4):
 * an operation held by a pause looks at the map again only when the engine sees an epoch that differs from the last one it saw. A pause that is lifted
 * without a new epoch, or an epoch that returns to the value the engine saw before (a scripted map that went back and forth between two passes), does not
 * release the operation; a strictly different epoch does. A real cluster only moves forward, so this is not an engine defect, but the quiesce step of the
 * fuzz target must end above every epoch the engine has seen, and this test pins the rule that makes that necessary.
 */
#include "osd_req_rig.h"

static rig R;

static void fill(uint8_t *p, size_t n, unsigned seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed * 29u + i * 11u);
}

/* A write held by PAUSEWR at epoch 12, which the engine has seen. 0 = ok. */
static int open_paused(uint8_t *data, size_t n, uint32_t *w)
{
	if (rig_open(&R, 1, 2, NULL) != 0)
		return -1;
	fill(data, n, 5);
	R.m.flags = WR_MAP_F_PAUSEWR;
	R.m.epoch = 12;
	*w = rq_write(&R, "pe", 0, data, (uint32_t)n, NULL, 0);
	(void)rig_settle(&R);
	return rq_at(&R, *w)->state == WRI_OP_PAUSED && R.o.map_epoch_seen == 12u ? 0 : -2;
}

/* The pause is lifted but the epoch stays: nothing is released; the next epoch releases the write with its first transmission. */
static void test_lift_without_new_epoch(void)
{
	uint8_t data[64];
	uint32_t w;

	WRT_CHECK(open_paused(data, sizeof(data), &w) == 0);
	R.m.flags = 0;
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, w)->state == WRI_OP_PAUSED);
	R.m.epoch = 13;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, w) && rq_at(&R, w)->status == WR_OK && rq_at(&R, w)->retry_attempt == 0);
	WRT_CHECK(rig_take(&R, w) == WR_OK);
	rig_close(&R);
}

/* The scripted map goes back (no pass runs there) and returns to the epoch the engine saw: still held. One epoch above everything seen releases it. */
static void test_epoch_back_and_forth(void)
{
	uint8_t data[64];
	uint32_t w;

	WRT_CHECK(open_paused(data, sizeof(data), &w) == 0);
	R.m.flags = 0;
	R.m.epoch = 5; /* back below what the engine saw: it is not stepped here */
	R.m.epoch = 12; /* and forward again to the epoch it saw */
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, w)->state == WRI_OP_PAUSED && R.o.map_epoch_seen == 12u);
	R.m.epoch = R.o.map_epoch_seen + 10u; /* what the fuzz target's quiesce does: end above the last epoch the engine saw */
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, w) && rq_at(&R, w)->status == WR_OK && rig_take(&R, w) == WR_OK);
	rig_close(&R);
}

/* A pass at the lower epoch is a change like any other: the engine then sees the epoch it returns to as new, and the lifted pause takes effect. */
static void test_pass_at_lower_epoch(void)
{
	uint8_t data[64];
	uint32_t w;

	WRT_CHECK(open_paused(data, sizeof(data), &w) == 0);
	R.m.epoch = 5;
	(void)rig_settle(&R); /* seen = 5, the pause still holds the write */
	WRT_CHECK(rq_at(&R, w)->state == WRI_OP_PAUSED && R.o.map_epoch_seen == 5u);
	R.m.flags = 0;
	R.m.epoch = 12;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, w) && rq_at(&R, w)->status == WR_OK && rig_take(&R, w) == WR_OK);
	rig_close(&R);
}

int main(void)
{
	test_lift_without_new_epoch();
	test_epoch_back_and_forth();
	test_pass_at_lower_epoch();
	return wrt_finish();
}
