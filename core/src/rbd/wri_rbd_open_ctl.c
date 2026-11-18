/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_open_ctl.c - the control reads of the open machine: building and submitting them from the control reserve (the eight header calls, get_id,
 * the extra stripe / operation reads), and taking their answers: decode, judge, move to the next step, become OPEN, adopt a refresh, or fail the image
 * (design 24.2, 24.4). When to submit and when to look is wri_rbd_open.c's; what a header means is wri_rbd_open_dec.c's.
 */
#include "wri_rbd_open.h"

#include "wri_ctx.h"
#include "wri_rbd_io.h"

WR_FILE_LICENCE_MIT

#define HDR_OPS 8u

/* ---- the control reads: building them ------------------------------------------------------------------------------------- */

#define HEAD WRI_SNAP_NOSNAP

/* The eight calls of the header message (design 24.2), in this order; ops[] are the slot's own records. */
static wr_status put_header(wri_wr *w, wri_osd_opd *ops, int read_only)
{
	wr_status st = wri_rbd_put_get_size(w, &ops[0], HEAD);

	if (st == WR_OK)
		st = wri_rbd_put_get_object_prefix(w, &ops[1]);
	if (st == WR_OK)
		st = wri_rbd_put_get_features(w, &ops[2], HEAD, read_only);
	if (st == WR_OK)
		st = wri_rbd_put_get_flags(w, &ops[3], HEAD);
	if (st == WR_OK)
		st = wri_rbd_put_get_snapcontext(w, &ops[4]);
	if (st == WR_OK)
		st = wri_rbd_put_get_data_pool(w, &ops[5]);
	if (st == WR_OK)
		st = wri_rbd_put_parent_get(w, &ops[6]);
	if (st == WR_OK)
		st = wri_rbd_put_parent_overlap_get(w, &ops[7], HEAD);
	return st;
}

/* The calls of the image's current step into the writer and the slot's records; *n = how many. */
static wr_status build_calls(const wri_rbd_img *m, wri_osd_op *op, wri_wr *w, unsigned *n)
{
	wr_status st = WR_OK;

	*n = 1;
	switch ((wri_ros)m->ros) {
	case WRI_ROS_GET_ID:
		st = wri_rbd_put_get_id(w, &op->ops[0]);
		break;
	case WRI_ROS_HEADER:
	case WRI_ROS_REFRESH:
		*n = HDR_OPS;
		st = put_header(w, op->ops, !m->want_write);
		break;
	case WRI_ROS_EXTRA:
		*n = 0;
		if ((m->hdr.features & WRI_RBD_F_STRIPINGV2) != 0)
			st = wri_rbd_put_get_stripe_unit_count(w, &op->ops[(*n)++]);
		if (st == WR_OK && (m->hdr.features & WRI_RBD_F_OPERATIONS) != 0)
			st = wri_rbd_put_op_features_get(w, &op->ops[(*n)++]);
		break;
	case WRI_ROS_IDLE:
	case WRI_ROS_POOLS:
	case WRI_ROS_READY:
	default:
		st = WR_E_STATE;
		break;
	}
	if (st == WR_OK && !wri_wr_ok(w))
		st = WR_E_TOOBIG;
	if (st == WR_OK && *n == 0)
		st = WR_E_STATE;
	return st;
}

wr_status wri_rbd_open_submit(wri_rbd *r, wri_rbd_img *m)
{
	wri_osd_op *op;
	size_t oid_len;
	uint32_t idx;
	unsigned n = 0;
	wri_wr w;
	wr_status st;

	idx = wri_osdc_alloc(r->osd, 1);
	if (idx == WRI_NIL)
		return WR_E_BUSY;
	op = wri_osdc_at(r->osd, idx);
	/* the object name goes straight into the slot (its buffer holds the longest name the checks allow, 95 bytes and the NUL) */
	if (m->ros == (uint8_t)WRI_ROS_GET_ID)
		oid_len = wri_rbd_id_obj_name((char *)op->oid, sizeof(op->oid), m->name);
	else
		oid_len = wri_rbd_header_obj_name((char *)op->oid, sizeof(op->oid), m->id);
	if (oid_len == 0 || oid_len > WRI_OSD_OID_MAX) {
		wri_osdc_release(r->osd, idx);
		return WR_E_RBD_BAD_ID;
	}
	op->kind = WRI_OPK_READ;
	op->pool = m->pool_h; /* the metadata objects are in the image's pool */
	op->oid_len = (uint8_t)oid_len;
	op->owner = ((uint32_t)m->slot << 16) | (uint32_t)m->gen;
	wri_wr_init(&w, m->ctl_in, WRI_RBD_CTL_IN);
	st = build_calls(m, op, &w, &n);
	if (st != WR_OK) {
		wri_osdc_release(r->osd, idx);
		return st;
	}
	op->n_ops = (uint8_t)n;
	op->data = m->ctl_in;
	op->data_len = (uint32_t)wri_wr_len(&w);
	op->out = m->ctl_out;
	op->out_cap = r->x->cfg.img_ctl_bytes;
	st = wri_osdc_submit(r->osd, idx);
	if (st != WR_OK) {
		wri_osdc_release(r->osd, idx);
		return st;
	}
	if (m->ros == (uint8_t)WRI_ROS_HEADER || m->ros == (uint8_t)WRI_ROS_REFRESH)
		m->refresh_start_ms = r->x->now.mono_ms; /* what the answer is as old as, at most */
	m->ctl_op = idx;
	return WR_OK;
}

/* ---- the control reads: taking the answers ----------------------------------------------------------------------------------- */

/* Errors that end a refresh for good; every other failure of the read (a stalled map, a timeout, an I/O error) is the engine's trouble and the read is
 * tried again later: a transport trouble does not fail an image (design 24.4). */
static int fatal_status(wr_status st)
{
	switch (st) {
	case WR_E_OSD_BLOCKLISTED:
	case WR_E_OSD_NOENT:
	case WR_E_OSD_PERM:
	case WR_E_OSD_REDIRECT:
	case WR_E_OSD_VERSION:
	case WR_E_RBD_NOT_FOUND:
		return 1;
	default:
		return 0;
	}
}

/* Every handler below returns 1 when the image must fail, with the reason in *why (the caller, wri_rbd_open.c, fails it: one frame less on the deepest chain),
 * and 0 when the read was taken (the machine moved on, or a transient refresh failure was absorbed). */
static int note_fail(wr_errinfo *why, wr_status st, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	WRI_ERRINFO(why, st, WR_MOD_RBD, what, a0, a1, a2);
	return 1;
}

/* A refresh read that came back as a failure the cluster may get over (not a fatal one): the refresh stays due (ros REFRESH, so the gate of the I/O half
 * stays shut, also when it was asked for by wri_rbd_open_refresh_now and the last header is still young) and is tried again later. 1 = give up instead:
 * WRI_RBD_PROTO_TRIES protocol errors in a row (the reply never fits the control buffer, an image with very many snapshots, or the OSD sends garbage), and
 * every try costs the session of that OSD. */
static int refresh_retry(wri_rbd *r, wri_rbd_img *m, wr_status st)
{
	uint32_t period = r->x->cfg.hdr_refresh_ms;
	uint64_t retry = period != 0 ? (period / 4u != 0 ? period / 4u : 1u) : 250u; /* with no period the retry is not periodic: still not a busy loop */

	if (st == WR_E_OSD_PROTO && ++m->ctl_fails >= WRI_RBD_PROTO_TRIES)
		return 1;
	if (st != WR_E_OSD_PROTO)
		m->ctl_fails = 0;
	m->hdr_stale = 0;
	m->ros = (uint8_t)WRI_ROS_REFRESH;
	m->next_refresh_ms = r->x->now.mono_ms + retry;
	return 0;
}

/* The read failed as a whole. */
static int read_failed(wri_rbd *r, wri_rbd_img *m, const wri_osd_op *op, wr_errinfo *why)
{
	wr_status st = op->status;
	const char *what = "control read failed";

	if (st == WR_E_OSD_NOENT && op->result == -WRI_ERRNO_ENOENT) {
		st = WR_E_RBD_NOT_FOUND;
		what = m->ros == (uint8_t)WRI_ROS_GET_ID ? "no image id object (no such image, or a format 1 image)" : "image header object does not exist";
	} else if (st == WR_E_OSD_NOENT) {
		what = "the OSD has no rbd class or method (EOPNOTSUPP)";
	} else if (st == WR_E_OSD_PERM) {
		what = "the key may not call the rbd class on this pool (needs class-read)";
	} else if (st == WR_E_OSD_BLOCKLISTED) {
		what = "this client is blocklisted by the cluster";
	} else if (st == WR_E_OSD_PROTO) {
		what = "the OSD's answer to the control read is malformed or longer than the control buffer (img_ctl_bytes; an image with very many snapshots?)";
	}
	if (m->state == (uint8_t)WR_IMG_OPEN && !fatal_status(st) && !refresh_retry(r, m, st))
		return 0;
	(void)note_fail(why, st, what, m->ros, (uint64_t)(int64_t)op->result, 0);
	why->peer_result = op->result;
	return 1;
}

/* The header is complete (after the EXTRA reads, when there were any): judge it and become OPEN. */
static int finish_open(wri_rbd *r, wri_rbd_img *m, wr_errinfo *why)
{
	if (wri_rbd_open_judge(r, m, &m->hdr, why) != WR_OK)
		return 1;
	wri_rbd_open_adopt(m, &m->hdr);
	m->writable = m->want_write != 0;
	m->state = (uint8_t)WR_IMG_OPEN;
	m->ros = (uint8_t)WRI_ROS_READY;
	m->was_open = 1;
	m->hdr_stale = 0;
	m->open_deadline_ms = WR_DEADLINE_NONE;
	m->refreshed_ms = m->refresh_start_ms;
	m->next_refresh_ms = m->writable && r->x->cfg.hdr_refresh_ms != 0 ? m->refreshed_ms + r->x->cfg.hdr_refresh_ms : WR_DEADLINE_NONE;
	if (r->event != NULL)
		r->event(r->event_ctx, WR_EV_IMAGE, m->slot, NULL);
	return 0;
}

static int done_header(wri_rbd *r, wri_rbd_img *m, const wri_osd_op *op, wr_errinfo *why)
{
	wri_rbd_hdr h;
	wr_status st;

	WR_MEMSET(&h, 0, sizeof(h));
	st = wri_rbd_open_decode_header(op->ops, op->n_ops, m->ctl_out, op->out_stored, &h, NULL, NULL);
	if (st != WR_OK)
		return note_fail(why, st, "header read does not decode", m->ros, op->out_stored, 0);
	m->snapc_status = (int32_t)wri_rbd_open_decode_snapc(op->ops, op->n_ops, m->ctl_out, op->out_stored, &m->snapc, &m->snapc_total);
	m->hdr = h;
	/* a feature the profile refuses ends the open at once: the first rule of 24.3, no striping or operation read can change it */
	if (wri_rbd_check_profile(&h, m->want_write, why) == WR_E_RBD_FEATURES)
		return 1;
	WR_MEMSET(why, 0, sizeof(*why)); /* any other refusal is judged later, in its place in the order */
	if ((h.features & (WRI_RBD_F_STRIPINGV2 | WRI_RBD_F_OPERATIONS)) != 0) {
		m->ros = (uint8_t)WRI_ROS_EXTRA;
		return 0;
	}
	return finish_open(r, m, why);
}

/* Decode, judge and take the context of a refresh; 0 = ready to adopt *h. */
static int refresh_check(wri_rbd *r, wri_rbd_img *m, const wri_osd_op *op, wri_rbd_hdr *h, wr_errinfo *why)
{
	uint32_t total = 0;
	wr_status st = wri_rbd_open_decode_header(op->ops, op->n_ops, m->ctl_out, op->out_stored, h, NULL, NULL);

	if (st != WR_OK)
		return note_fail(why, st, "header refresh does not decode", m->ros, op->out_stored, 0);
	h->stripe_unit = m->hdr.stripe_unit; /* these cannot change on an image that exists: carried from the open */
	h->stripe_count = m->hdr.stripe_count;
	h->op_features = m->hdr.op_features;
	m->snapc_status = WR_OK;
	m->snapc_total = 0;
	if (wri_rbd_open_refresh_judge(r, m, h, why) != WR_OK)
		return 1;
	/* adopted together: nothing above changed the image. The context is judged before it is stored: a context that does not decode fails the image, and the
	 * live one must stay what it was (zombies of the image's writes are copies of it, a write on the wire reads it again when it is resent). */
	st = wri_rbd_open_probe_snapc(op->ops, op->n_ops, m->ctl_out, op->out_stored, m->snapc.cap, &total);
	if (st == WR_OK)
		st = wri_rbd_open_decode_snapc(op->ops, op->n_ops, m->ctl_out, op->out_stored, &m->snapc, &total);
	if (st != WR_OK)
		return note_fail(why, st == WR_E_RBD_PROTO ? st : WR_E_RBD_SNAPC, "snapshot context of the refresh is invalid or has too many snapshots", total,
				 m->snapc.cap, 0);
	return 0;
}

static int done_refresh(wri_rbd *r, wri_rbd_img *m, const wri_osd_op *op, wr_errinfo *why)
{
	wri_rbd_hdr h;
	uint64_t now = r->x->now.mono_ms, old_size = m->size;

	WR_MEMSET(&h, 0, sizeof(h));
	if (refresh_check(r, m, op, &h, why) != 0)
		return 1;
	wri_rbd_open_adopt(m, &h);
	m->ctl_fails = 0;
	m->refreshed_ms = m->refresh_start_ms;
	if (m->hdr_stale != 0) { /* marked stale while this read was in flight: it may predate the mark, read again at once */
		m->hdr_stale = 0;
		m->ros = (uint8_t)WRI_ROS_REFRESH;
		m->next_refresh_ms = now;
	} else {
		m->ros = (uint8_t)WRI_ROS_READY;
		m->next_refresh_ms = r->x->cfg.hdr_refresh_ms != 0 ? m->refreshed_ms + r->x->cfg.hdr_refresh_ms : WR_DEADLINE_NONE;
	}
	if (h.size != old_size && r->event != NULL)
		r->event(r->event_ctx, WR_EV_IMAGE, m->slot, NULL);
	return 0;
}

int wri_rbd_open_complete(wri_rbd *r, wri_rbd_img *m, const wri_osd_op *op, wr_errinfo *why)
{
	wr_status st;

	if (op->status != WR_OK)
		return read_failed(r, m, op, why);
	switch ((wri_ros)m->ros) {
	case WRI_ROS_GET_ID:
		if (op->n_ops != 1 || op->ops[0].rval < 0 || op->ops[0].out_len != op->out_stored)
			return note_fail(why, WR_E_RBD_PROTO, "get_id reply does not match its request", op->out_stored, op->n_ops, 0);
		st = wri_rbd_dec_id(m->ctl_out, op->out_stored, m->id);
		if (st != WR_OK)
			return note_fail(why, st, "image id is not valid", op->out_stored, 0, 0);
		m->ros = (uint8_t)WRI_ROS_HEADER;
		return 0;
	case WRI_ROS_HEADER:
		return done_header(r, m, op, why);
	case WRI_ROS_EXTRA:
		st = wri_rbd_open_decode_extra(op->ops, op->n_ops, m->ctl_out, op->out_stored, &m->hdr);
		if (st != WR_OK)
			return note_fail(why, st, "striping / operation features do not decode", op->out_stored, 0, 0);
		return finish_open(r, m, why);
	case WRI_ROS_REFRESH:
		return done_refresh(r, m, op, why);
	case WRI_ROS_IDLE:
	case WRI_ROS_POOLS:
	case WRI_ROS_READY:
	default:
		return note_fail(why, WR_E_STATE, "control read answered in a step that sent none", m->ros, 0, 0);
	}
}
