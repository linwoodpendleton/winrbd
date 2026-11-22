/* SPDX-License-Identifier: MIT */
/*
 * sim_m2_sess.c - frame dispatch and session handlers of the msgr2 test server: MESSAGE receive with
 * the sequence rules (docs/spec/msgr2.md 2.9), KEEPALIVE2 / ACK, MESSAGE and KEEPALIVE2 send.
 */
#include "sim_m2_int.h"

/* ---- session handlers -------------------------------------------------------------------------- */

static void on_message(sim_m2 *s, const uint8_t *h, size_t hlen)
{
	sim_m2_msg cur, *keep;
	unsigned i;
	uint64_t seq, total;

	if (hlen < SIM_M2_HDR2_LEN) {
		sim_m2_die(s, WR_E_M2_FRAME_FORM, "sim: MESSAGE segment 0 shorter than a header", hlen, 0);
		return;
	}
	memset(&cur, 0, sizeof(cur));
	cur.seq = seq = wri_le64_get(h);
	cur.tid = wri_le64_get(h + 8);
	cur.type = wri_le16_get(h + 16);
	cur.priority = wri_le16_get(h + 18);
	cur.version = wri_le16_get(h + 20);
	cur.pre_padding = wri_le32_get(h + 22);
	cur.data_off = wri_le16_get(h + 26);
	cur.ack_seq = wri_le64_get(h + 28);
	cur.flags = h[36];
	cur.compat_version = wri_le16_get(h + 37);
	cur.reserved = wri_le16_get(h + 39);
	cur.nseg = s->cur.nseg;
	for (i = 0; i < 3; i++) {
		cur.seg_len[i] = s->cur.len[i + 1u];
		cur.seg[i] = cur.seg_len[i] != 0 ? (uint8_t *)s->cur.p[i + 1u] : NULL;
	}
	if (seq != s->in_seq + 1u) {
		if (s->cfg.seq_policy == SIM_M2_SEQ_STRICT) {
			sim_m2_die(s, WR_E_M2_SEQ, "sim: message seq is not in_seq + 1", s->in_seq + 1u, seq);
			return;
		}
		if (seq <= s->in_seq) { /* stock daemon: dropped, and the connection stops being read */
			s->n_seq_dups++;
			s->stall_in = 1;
			return;
		}
		s->n_seq_gaps++;
	}
	s->in_seq = seq;
	s->n_msgs_seen++;
	/* kept only within both budgets: the number of messages and the total bytes they hold */
	total = (uint64_t)cur.seg_len[0] + cur.seg_len[1] + cur.seg_len[2];
	if (s->n_msgs < s->cfg.max_msgs && total <= (uint64_t)s->cfg.msg_bytes_cap - s->msgs_bytes) {
		keep = &s->msgs[s->n_msgs];
		*keep = cur;
		for (i = 0; i < 3; i++) {
			keep->seg[i] = NULL;
			if (cur.seg_len[i] != 0) {
				keep->seg[i] = (uint8_t *)malloc(cur.seg_len[i]);
				if (keep->seg[i] == NULL) {
					while (i-- > 0) { /* nothing half recorded is left behind */
						free(keep->seg[i]);
						keep->seg[i] = NULL;
					}
					sim_m2_die(s, WR_E_BUDGET, "sim: out of memory recording a message", 0, 0);
					return;
				}
				memcpy(keep->seg[i], cur.seg[i], cur.seg_len[i]);
			}
		}
		s->n_msgs++;
		s->msgs_bytes += total;
		cur = *keep;
	}
	if (s->on_message != NULL)
		s->on_message(s->on_message_ctx, s, &cur);
}

static void on_keepalive(sim_m2 *s, const uint8_t *p, size_t n)
{
	sw w;

	if (n != 8) {
		sim_m2_die(s, WR_E_M2_FRAME_FORM, "sim: KEEPALIVE2 is not 8 bytes", n, 0);
		return;
	}
	s->n_keepalive++;
	s->last_ka_sec = wri_le32_get(p);
	s->last_ka_nsec = wri_le32_get(p + 4);
	if (s->cfg.f.no_keepalive_ack)
		return;
	w = sim_m2_ctl_writer(s);
	sw_bytes(&w, p, 8); /* the ACK echoes the stamp */
	sim_m2_emit_ctl(s, WRI_M2_TAG_KEEPALIVE2_ACK, &w);
}

static void note_frame(sim_m2 *s, uint8_t tag)
{
	if (s->n_rx_frames < SIM_M2_TAGLOG)
		s->rx_tags[s->n_rx_frames] = tag;
	s->n_rx_frames++;
	if (tag <= WRI_M2_TAG_MAX)
		s->n_rx_by_tag[tag]++;
}

void sim_m2_on_frame(sim_m2 *s)
{
	uint8_t tag = s->cur.tag;
	const uint8_t *p = s->cur.p[0];
	size_t n = s->cur.len[0];

	note_frame(s, tag);
	if (s->cur.nseg > 1 && tag != WRI_M2_TAG_MESSAGE) {
		sim_m2_die(s, WR_E_M2_FRAME_FORM, "sim: control frame with several segments", tag, 0);
		return;
	}
	if (s->state == SIM_M2_ST_READY) {
		if (tag == WRI_M2_TAG_MESSAGE) {
			on_message(s, p, n);
			return;
		}
		if (tag == WRI_M2_TAG_KEEPALIVE2) {
			on_keepalive(s, p, n);
			return;
		}
		if (tag == WRI_M2_TAG_KEEPALIVE2_ACK && n == 8) {
			s->n_keepalive_ack++;
			s->last_kaack_sec = wri_le32_get(p);
			s->last_kaack_nsec = wri_le32_get(p + 4);
			return;
		}
		if (tag == WRI_M2_TAG_ACK && n == 8) {
			s->n_ack++;
			s->last_ack_seq = wri_le64_get(p);
			return;
		}
	} else if (sim_m2_hs_frame(s, tag, p, n)) {
		return;
	}
	sim_m2_die(s, WR_E_M2_STATE, "sim: frame not allowed in this state", tag, s->state);
}

void sim_m2_msgs_clear(sim_m2 *s)
{
	uint32_t i, j;

	for (i = 0; i < s->n_msgs; i++)
		for (j = 0; j < 3; j++) {
			free(s->msgs[i].seg[j]);
			s->msgs[i].seg[j] = NULL;
		}
	s->n_msgs = 0;
	s->msgs_bytes = 0;
}

wr_status sim_m2_send_message(sim_m2 *s, uint16_t type, uint64_t tid, uint16_t version, const uint8_t *front,
			      uint32_t flen, const uint8_t *middle, uint32_t mlen, const uint8_t *data, uint32_t dlen)
{
	uint8_t h[SIM_M2_HDR2_LEN];
	wri_m2_seg_src seg[4];
	unsigned nseg = dlen != 0 ? 4u : mlen != 0 ? 3u : flen != 0 ? 2u : 1u;
	wr_status st;

	if (s->state != SIM_M2_ST_READY)
		return WR_E_STATE;
	memset(h, 0, sizeof(h));
	wri_le64_put(h, s->out_seq + 1u);
	wri_le64_put(h + 8, tid);
	wri_le16_put(h + 16, type);
	wri_le16_put(h + 18, 127); /* default priority */
	wri_le16_put(h + 20, version);
	wri_le64_put(h + 28, s->in_seq);
	h[36] = 3; /* COMPLETE | NOCRC, what a stock daemon sends */
	wri_le16_put(h + 37, version);
	seg[0].p = h, seg[0].len = sizeof(h);
	seg[1].p = front, seg[1].len = flen;
	seg[2].p = middle, seg[2].len = mlen;
	seg[3].p = data, seg[3].len = dlen;
	seg[0].ref = seg[1].ref = seg[2].ref = seg[3].ref = 0;
	st = sim_m2_send_frame(s, WRI_M2_TAG_MESSAGE, seg, nseg);
	if (st == WR_OK)
		s->out_seq++;
	return st;
}

wr_status sim_m2_send_keepalive(sim_m2 *s, uint32_t sec, uint32_t nsec)
{
	uint8_t b[8];
	wri_m2_seg_src seg;

	if (s->state != SIM_M2_ST_READY)
		return WR_E_STATE;
	wri_le32_put(b, sec);
	wri_le32_put(b + 4, nsec);
	seg.p = b, seg.len = 8, seg.ref = 0;
	return sim_m2_send_frame(s, WRI_M2_TAG_KEEPALIVE2, &seg, 1);
}
