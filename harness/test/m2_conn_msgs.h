/* SPDX-License-Identifier: MIT */
/*
 * m2_conn_msgs.h - small helpers of the m2-conn tests that deal with MESSAGE and control frames (shared by
 * test_m2_conn_msg.c, test_m2_conn_rx.c, test_m2_conn_rej.c). Harness code, static inline, one copy per test.
 */
#ifndef M2_CONN_MSGS_H
#define M2_CONN_MSGS_H

#include "m2_conn_rig.h"

static inline void ready_rig(rig *r)
{
	rig_start(r);
	rig_pump(r);
	WRT_CHECK_U64(r->c.state, WRI_M2_READY);
	WRT_CHECK_U64(r->up.n_ready, 1);
}

static inline wri_m2_msg_out mk(uint16_t type, uint64_t tid, const uint8_t *front, uint32_t flen, const uint8_t *data,
			 uint32_t dlen)
{
	wri_m2_msg_out m;

	memset(&m, 0, sizeof(m));
	m.type = type;
	m.priority = 127;
	m.version = 3;
	m.compat_version = 1;
	m.tid = tid;
	m.front = front;
	m.front_len = flen;
	m.data = data;
	m.data_len = dlen;
	return m;
}

/* A server MESSAGE built by hand (header2 with the given seq), delivered through the window. */
static inline void inject_msg(rig *r, uint64_t seq, uint64_t tid, uint16_t type, const uint8_t *front, uint32_t flen,
		       const uint8_t *data, uint32_t dlen, uint8_t late_patch)
{
	uint8_t h[SIM_M2_HDR2_LEN], *fr;
	wri_m2_seg_src seg[4];
	unsigned nseg = dlen != 0 ? 4u : flen != 0 ? 2u : 1u;
	size_t fl;

	tc_pay_hdr2(h, seq, tid, type, 0);
	seg[0].p = h, seg[0].len = sizeof(h), seg[0].ref = 0;
	seg[1].p = front != NULL ? front : h, seg[1].len = flen, seg[1].ref = 0;
	seg[2].p = h, seg[2].len = 0, seg[2].ref = 0;
	seg[3].p = data != NULL ? data : h, seg[3].len = dlen, seg[3].ref = 0;
	fr = rig_build_frame(WRI_M2_TAG_MESSAGE, seg, nseg, &fl);
	if (late_patch != 0 && nseg > 1 && fl > WRI_M2_EPILOGUE_LEN)
		fr[fl - WRI_M2_EPILOGUE_LEN] = late_patch;
	rig_inject(r, fr, fl);
	free(fr);
}

static inline void inject_ctl(rig *r, uint8_t tag, const uint8_t *p, uint32_t n)
{
	wri_m2_seg_src seg;
	uint8_t z = 0, *fr;
	size_t fl;

	seg.p = n != 0 ? p : &z, seg.len = n, seg.ref = 0;
	fr = rig_build_frame(tag, &seg, 1, &fl);
	rig_inject(r, fr, fl);
	free(fr);
}

static inline void fill(uint8_t *p, size_t n, uint8_t seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed + i * 7u);
}

#endif /* M2_CONN_MSGS_H */
