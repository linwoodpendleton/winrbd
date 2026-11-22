/* SPDX-License-Identifier: MIT */
/*
 * test_fuzzlong_conn_len_lie.c - a finding of the long fuzz run (design 40.4, target fuzz_m2_conn_sec): a secure frame whose preamble announces other
 * segment lengths than the ones the peer sealed. The segments of a frame are padded to their alignment (8, 8, 8, 4096) and sealed as one part, so:
 *
 *   - a lie that keeps the padded layout (a front of 20 and a middle of 10 bytes announced as 32 and 3: 24 + 16 = 32 + 8 padded bytes) is a frame whose
 *     every tag verifies; the message header carries no length to compare the announced ones with, so the connection delivers it, with the ANNOUNCED
 *     lengths, as it must (an authenticated peer chooses its lengths). The fuzz target used to expect the sent lengths and trapped;
 *   - a lie that makes the announced layout SHORTER than the sealed one shifts everything behind it: the stream then fails its tag (a longer one only waits for
 *     bytes that never come, the tag is checked when the part is complete), nothing reaches the upper layer, the connection
 *     ends with WR_E_M2_SEC_TAG and wipes its slot (the same table as test_m2_conn_sec_fail, here beside the case above so that the two are read together);
 *   - a lie that announces MORE than the frame carries makes the connection wait; the frames behind it are its body (a second finding of the same run: the
 *     fuzz target expected a later tag defect to be caught).
 */
#include "m2_conn_msgs.h"
#include "m2_conn_sec_cx.h"
#include "wri_le.h"
#include "wri_pgcm.h"
#include "wri_prim.h"

#define OFFER_BOTH (WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE | WRI_M2_OFFER_SECURE_FIRST)

static void secure_ready(rig *r)
{
	rig_init(r);
	rig_enable_secure(r, OFFER_BOTH);
	rig_server_modes(r, 2, 1);
	rig_start(r);
	rig_pump(r);
	WRT_CHECK_U64(r->c.state, WRI_M2_READY);
	WRT_CHECK_U64(sim_m2_is_secure(r->s), 1);
}

/* One server message of (front 20, middle 10, data 48) whose preamble announces `ann` (bit i of mask = slot i) instead of the real lengths. */
static void send_lying(rig *r, uint8_t mask, const uint32_t ann[4])
{
	uint8_t front[20], mid[10], data[48];
	unsigned i;

	fill(front, sizeof(front), 5);
	fill(mid, sizeof(mid), 38);
	fill(data, sizeof(data), 71);
	memset(&r->s->cfg.f.sec.mut, 0, sizeof(r->s->cfg.f.sec.mut));
	r->s->cfg.f.sec.mut.mask = SIM_SEC_M_PRE_LEN;
	r->s->cfg.f.sec.mut.pre_len_mask = mask;
	for (i = 0; i < 4; i++)
		r->s->cfg.f.sec.mut.pre_len[i] = ann[i];
	r->s->cfg.f.sec.mut_frame = r->s->n_tx_frames + 1u; /* the next frame the server sends */
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r->s, 0x701, 7, 4, front, sizeof(front), mid, sizeof(mid), data, sizeof(data)));
	r->s->cfg.f.sec.mut_frame = 0;
	rig_pump(r);
}

static void test_lie_keeps_layout(void)
{
	rig r;
	const uint32_t ann[4] = {0, 32, 3, 0};
	uint8_t front[20];

	secure_ready(&r);
	fill(front, sizeof(front), 5);
	send_lying(&r, 1u << 1 | 1u << 2, ann);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.up.n_closed, 0);
	WRT_CHECK_U64(r.up.n_message, 1);
	if (r.up.n_msgs == 1u) {
		WRT_CHECK_U64(r.up.msgs[0].stored[0], 32);
		WRT_CHECK_U64(r.up.msgs[0].stored[1], 3);
		WRT_CHECK_U64(r.up.msgs[0].stored[2], 48);
		WRT_CHECK_MEM(r.up.msgs[0].seg[0], front, sizeof(front)); /* the real front is the start of the announced one */
	}
	rig_free(&r);
}

static void test_lie_shifts_layout(void)
{
	rig r;
	const uint32_t ann[4] = {0, 10, 0, 0};

	secure_ready(&r);
	send_lying(&r, 1u << 1, ann); /* 10 and 10 padded to 16 + 16 announced, 24 + 16 on the wire: the tag of the part covers the wrong bytes */
	rig_check_failed(&r, WR_E_M2_SEC_TAG);
	WRT_CHECK_U64(r.up.n_message, 0);
	WRT_CHECK_U64(r.c.n_msg_in, 0);
	WRT_CHECK(rig_slot_zero(&r));
	rig_free(&r);
}

/* A lie that announces MORE than the frame carries: the connection waits for the bytes, and the frames behind it are swallowed as its body (they are not looked
 * at as frames of their own: a good one is not delivered, a defective one is not caught). Nothing wrong reaches the upper layer, and the connection is not
 * failed until the part is complete (a timeout of the host ends it). */
static void test_lie_longer_waits(void)
{
	rig r;
	const uint32_t ann[4] = {0, 4160, 0, 0};
	uint8_t front[20];

	secure_ready(&r);
	send_lying(&r, 1u << 1, ann);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.up.n_message, 0);
	WRT_CHECK_U64(r.up.n_closed, 0);
	fill(front, sizeof(front), 5);
	r.s->cfg.f.sec.mut_frame = 0;
	memset(&r.s->cfg.f.sec.mut, 0, sizeof(r.s->cfg.f.sec.mut));
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x701, 8, 4, front, sizeof(front), NULL, 0, NULL, 0)); /* a good frame behind it */
	rig_pump(&r);
	WRT_CHECK_U64(r.up.n_message, 0); /* swallowed as the body of the first */
	WRT_CHECK_U64(r.up.n_closed, 0);
	rig_free(&r);
}

int main(void)
{
	test_lie_keeps_layout();
	test_lie_shifts_layout();
	test_lie_longer_waits();
	return wrt_finish();
}
