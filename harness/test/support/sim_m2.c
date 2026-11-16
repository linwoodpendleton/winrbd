/* SPDX-License-Identifier: MIT */
/*
 * sim_m2.c - the scriptable msgr2.1 server of the harness (see sim_m2.h): configuration, the output
 * queue, frame emission with the fault hooks, the receive pump and the public entry points. Written
 * from docs/spec/msgr2.md section 3 and the server behaviour observed there. Test code: libc allowed.
 * The handshake handlers are in sim_m2_hs.c, the session handlers in sim_m2_sess.c.
 */
#include "sim_m2_int.h"

#include "wri_mem.h"

void sim_m2_put_addr4(uint8_t out[SIM_M2_ADDR4_LEN], uint32_t type, uint32_t nonce, const uint8_t ip[4],
		      uint16_t port)
{
	memset(out, 0, SIM_M2_ADDR4_LEN);
	out[0] = 1; /* marker */
	out[1] = 1; /* struct_v */
	out[2] = 1; /* struct_compat */
	wri_le32_put(out + 3, 28);
	wri_le32_put(out + 7, type);
	wri_le32_put(out + 11, nonce);
	wri_le32_put(out + 15, 16); /* elen */
	wri_le16_put(out + 19, 2);  /* AF_INET */
	wri_be16_put(out + 21, port);
	memcpy(out + 23, ip, 4);
}

/* ---- configuration -------------------------------------------------------------------------- */

void sim_m2_cfg_default(sim_m2_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->entity_type = SIM_M2_ENT_MON;
	c->banner_supported = 3;
	c->banner_payload_len = 16;
	c->client_ip[0] = 10, c->client_ip[1] = 77, c->client_ip[2] = 0, c->client_ip[3] = 20;
	c->client_port = 50000;
	c->server_ip[0] = 10, c->server_ip[1] = 77, c->server_ip[2] = 0, c->server_ip[3] = 10;
	c->server_port = 3300;
	c->legacy_port = 6789;
	c->methods[0] = SIM_M2_AUTH_CEPHX, c->n_methods = 1;
	c->modes[0] = SIM_M2_MODE_CRC, c->modes[1] = SIM_M2_MODE_SECURE, c->n_modes = 2;
	c->global_id = 4242;
	c->server_gid = 1;
	c->ident_supported = 0x3f07fffffffdffffull;
	c->ident_required = 0x0800000000000000ull; /* CEPH_FEATUREMASK_MSG_ADDR2 */
	c->ident_flags = 1;
	c->ctl_cap = 16u * 1024u;
	c->seg_cap = 1u << 20;
	c->max_msgs = 128;
	c->msg_bytes_cap = 64u << 20;
	c->seq_policy = SIM_M2_SEQ_STRICT;
	c->preauth_cap = 1u << 20;
	c->out_cap = 16u << 20;
	c->f.out_limit = -1;
}

/* ---- failure and output queue ---------------------------------------------------------------- */

void sim_m2_die(sim_m2 *s, wr_status st, const char *what, uint64_t a0, uint64_t a1)
{
	if (s->err.status == WR_OK) {
		s->err.status = st;
		s->err.module = WR_MOD_M2;
		s->err.what = what;
		s->err.a0 = a0;
		s->err.a1 = a1;
	}
	s->state = SIM_M2_ST_DEAD;
	s->close_pending = 1;
}

static wr_status out_reserve(sim_m2 *s, size_t k)
{
	size_t live = s->out_len - s->out_head, need;
	uint8_t *q;

	if (k > s->cfg.out_cap || live > s->cfg.out_cap - k)
		return WR_E_TOOBIG;
	if (s->out_head != 0) {
		memmove(s->out, s->out + s->out_head, live);
		s->out_head = 0;
		s->out_len = live;
	}
	need = live + k;
	if (need > s->out_cap) {
		size_t nc = s->out_cap != 0 ? s->out_cap : 4096;

		while (nc < need)
			nc *= 2;
		q = (uint8_t *)realloc(s->out, nc);
		if (q == NULL)
			return WR_E_BUDGET;
		s->out = q;
		s->out_cap = nc;
	}
	return WR_OK;
}

/* The bytes went onto the wire: the pre-auth log of what we sent keeps them (until AUTH_DONE). */
static void tx_note(sim_m2 *s, const uint8_t *p, size_t n)
{
	if (!s->tx_log_on || n == 0)
		return;
	if (n > s->cfg.preauth_cap - s->tx_log_len) {
		sim_m2_die(s, WR_E_M2_PREAUTH_TOOBIG, "sim tx pre-auth log full", s->cfg.preauth_cap, 0);
		return;
	}
	memcpy(s->tx_log + s->tx_log_len, p, n);
	s->tx_log_len += (uint32_t)n;
}

static wr_status out_put(sim_m2 *s, const uint8_t *p, size_t n)
{
	wr_status st = out_reserve(s, n);

	if (st != WR_OK)
		return st;
	memcpy(s->out + s->out_len, p, n);
	s->out_len += n;
	tx_note(s, p, n);
	return WR_OK;
}

static wr_status emit_banner(sim_m2 *s)
{
	uint8_t b[WRI_M2_BANNER_HEAD + 1024u], pay[16];
	uint32_t pl = s->cfg.banner_payload_len > 1024u ? 1024u : s->cfg.banner_payload_len, total;

	memset(b, 0, sizeof(b));
	wri_le64_put(pay, s->cfg.banner_supported);
	wri_le64_put(pay + 8, s->cfg.banner_required);
	if (s->cfg.banner_v1) {
		memcpy(b, "ceph v027", 9);
		total = WRI_M2_BANNER_LEN;
		memcpy(b + WRI_M2_BANNER_HEAD, pay, 16);
	} else {
		memcpy(b, WRI_M2_BANNER_PREFIX, 8);
		wri_le16_put(b + 8, (uint16_t)pl);
		memcpy(b + WRI_M2_BANNER_HEAD, pay, pl < 16u ? pl : 16u);
		total = WRI_M2_BANNER_HEAD + pl;
	}
	return out_put(s, b, total);
}

/* ---- frame emission with the fault hooks -------------------------------------------------------- */

static void damage(uint8_t *fb, size_t total, const wri_m2_seg_src *seg, unsigned nseg, uint8_t part)
{
	if (part == SIM_M2_CORRUPT_EPILOGUE && nseg < 2)
		part = SIM_M2_CORRUPT_SEG0;
	if (part == SIM_M2_CORRUPT_SEG0 && seg[0].len == 0)
		part = nseg >= 2 ? SIM_M2_CORRUPT_EPILOGUE : SIM_M2_CORRUPT_PREAMBLE;
	if (part == SIM_M2_CORRUPT_SEG0)
		fb[WRI_M2_PREAMBLE_LEN + seg[0].len] ^= 0x01;
	else if (part == SIM_M2_CORRUPT_EPILOGUE)
		fb[total - WRI_M2_EPILOGUE_LEN + 1u] ^= 0x01;
	else
		fb[28] ^= 0x01; /* the preamble CRC */
}

/* Server frame K that is only a preamble claiming a huge last segment; nothing follows it. */
static wr_status emit_oversize(sim_m2 *s, uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg)
{
	wri_m2_desc d;
	uint8_t pre[WRI_M2_PREAMBLE_LEN];
	unsigned i;
	wr_status st;

	memset(&d, 0, sizeof(d));
	d.tag = tag;
	d.nseg = (uint8_t)nseg;
	for (i = 0; i < nseg; i++) {
		d.len[i] = seg[i].len;
		d.align[i] = (uint16_t)(i == 3u ? 4096u : 8u);
	}
	d.len[nseg - 1u] = s->cfg.f.oversize_len;
	wri_m2_preamble_build(NULL, pre, &d);
	st = out_put(s, pre, sizeof(pre));
	s->out_dead = 1; /* the rest of the claimed frame never comes */
	return st;
}

wr_status sim_m2_send_frame(sim_m2 *s, uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg)
{
	wri_m2_txq q;
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t i, k, total;
	wr_status st;
	uint32_t idx;
	uint8_t *fb;

	if (s == NULL || s->state == SIM_M2_ST_DEAD)
		return WR_E_STATE;
	if (s->out_dead)
		return WR_OK; /* the stream already stalled inside an oversize frame: nothing more gets out */
	idx = ++s->n_tx_frames;
	if (s->cfg.f.oversize_frame == idx && seg != NULL && nseg >= 1 && nseg <= WRI_M2_MAX_SEGS)
		return emit_oversize(s, tag, seg, nseg);
	wri_m2_txq_init(&q, s->enc, s->enc_cap);
	st = wri_m2_tx_frame(&q, NULL, tag, seg, nseg, NULL, NULL);
	if (st != WR_OK)
		return st;
	total = (size_t)q.pending;
	st = out_reserve(s, total);
	if (st != WR_OK)
		return st;
	k = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < k; i++) {
		memcpy(s->out + s->out_len, iov[i].base, iov[i].len);
		s->out_len += iov[i].len;
	}
	fb = s->out + s->out_len - total;
	if (s->cfg.f.corrupt_frame == idx)
		damage(fb, total, seg, nseg, s->cfg.f.corrupt_part);
	tx_note(s, fb, total);
	return s->state == SIM_M2_ST_DEAD ? WR_E_STATE : WR_OK;
}

/* Send the control payload built in scratch; a failure to send ends the connection. */
void sim_m2_emit_ctl(sim_m2 *s, uint8_t tag, const sw *w)
{
	wri_m2_seg_src seg;
	wr_status st;

	if (w->bad) {
		sim_m2_die(s, WR_E_TOOBIG, "sim control payload too large", w->cap, tag);
		return;
	}
	seg.p = s->scratch;
	seg.len = (uint32_t)w->n;
	seg.ref = 0;
	st = sim_m2_send_frame(s, tag, &seg, 1);
	if (st != WR_OK && s->state != SIM_M2_ST_DEAD)
		sim_m2_die(s, st, "sim could not queue a frame", tag, 0);
}

sw sim_m2_ctl_writer(sim_m2 *s)
{
	sw w;

	w.p = s->scratch;
	w.cap = s->cfg.ctl_cap;
	w.n = 0;
	w.bad = 0;
	return w;
}

/* ---- receive pump ------------------------------------------------------------------------------ */

static void rx_tap(void *log, const uint8_t *p, size_t n)
{
	sim_m2 *s = (sim_m2 *)log;

	if (n > s->cfg.preauth_cap - s->rx_log_len) {
		sim_m2_die(s, WR_E_M2_PREAUTH_TOOBIG, "sim rx pre-auth log full", s->cfg.preauth_cap, 0);
		return;
	}
	memcpy(s->rx_log + s->rx_log_len, p, n);
	s->rx_log_len += (uint32_t)n;
}

static int input_closed(const sim_m2 *s)
{
	return s->state == SIM_M2_ST_DEAD || s->state == SIM_M2_ST_REFUSED || s->stall_in;
}

static void pump(sim_m2 *s)
{
	for (;;) {
		wri_m2_rx_ev ev = wri_m2_rx_step(&s->rx, &s->ring, NULL, NULL, s->rx_log_on ? rx_tap : NULL, s);
		unsigned i;

		if (s->state == SIM_M2_ST_DEAD)
			return;
		switch (ev) {
		case WRI_RXE_NONE:
			return;
		case WRI_RXE_BANNER:
			s->client_banner = *wri_m2_rx_banner(&s->rx);
			if ((s->cfg.banner_required & ~s->client_banner.supported) != 0) { /* what we require, the client lacks */
				sim_m2_die(s, WR_E_M2_FEATURES, "sim: client banner lacks features we require",
					   s->cfg.banner_required, s->client_banner.supported);
				return;
			}
			s->expect_compression = (s->client_banner.supported & s->cfg.banner_supported & 2u) != 0;
			s->state = SIM_M2_ST_HELLO;
			s->frame_start = s->rx_log_len;
			break;
		case WRI_RXE_SEG0:
			if (s->state == SIM_M2_ST_READY && s->rx.desc.tag == WRI_M2_TAG_MESSAGE)
				for (i = 1; i < s->rx.desc.nseg; i++)
					wri_m2_rx_sink(&s->rx, i, s->sink[i - 1u], s->cfg.seg_cap);
			break;
		case WRI_RXE_FRAME:
			sim_m2_on_frame(s);
			wri_m2_rx_next_frame(&s->rx);
			s->frame_start = s->rx_log_len;
			break;
		case WRI_RXE_ABORTED: /* the sender dropped the frame: so do we */
			wri_m2_rx_next_frame(&s->rx);
			s->frame_start = s->rx_log_len;
			break;
		case WRI_RXE_ERROR:
		default:
			s->err = *wri_m2_rx_error(&s->rx);
			sim_m2_die(s, s->err.status != WR_OK ? s->err.status : WR_E_M2_FRAME_FORM, "sim: receive error", 0, 0);
			return;
		}
		if (input_closed(s))
			return;
	}
}


/* ---- public entry points ------------------------------------------------------------------------ */

size_t sim_m2_feed(sim_m2 *s, const uint8_t *p, size_t n)
{
	size_t done = 0;

	if (s == NULL || sim_m2_closed(s))
		return 0;
	while (done < n) {
		size_t want = n - done;
		uint32_t k;

		if (input_closed(s))
			return n; /* dropped: the peer is not reading any more */
		k = wri_ring_write(&s->ring, p + done, want > (1u << 30) ? (1u << 30) : (uint32_t)want);
		done += k;
		pump(s);
		if (k == 0)
			break; /* ring full and the parser made no room: cannot happen unless dead */
	}
	return done;
}

size_t sim_m2_pending(const sim_m2 *s) { return s->out_len - s->out_head; }

static int limit_reached(const sim_m2 *s) { return s->cfg.f.out_limit >= 0 && s->delivered >= (uint64_t)s->cfg.f.out_limit; }

size_t sim_m2_drain(sim_m2 *s, uint8_t *out, size_t cap)
{
	size_t n = sim_m2_pending(s);

	if (s->cfg.f.out_limit >= 0) {
		uint64_t room = limit_reached(s) ? 0 : (uint64_t)s->cfg.f.out_limit - s->delivered;

		if (n > room)
			n = (size_t)room;
	}
	if (n > cap)
		n = cap;
	if (s->cfg.f.out_chunk != 0 && n > s->cfg.f.out_chunk)
		n = s->cfg.f.out_chunk;
	if (n != 0) {
		memcpy(out, s->out + s->out_head, n);
		s->out_head += n;
		s->delivered += n;
		if (s->out_head == s->out_len)
			s->out_head = s->out_len = 0;
	}
	return n;
}

int sim_m2_closed(const sim_m2 *s)
{
	if (limit_reached(s))
		return s->cfg.f.out_limit_close != 0;
	return s->close_pending && sim_m2_pending(s) == 0;
}

void sim_m2_close(sim_m2 *s)
{
	s->close_pending = 1;
	s->state = SIM_M2_ST_DEAD;
}

const wr_errinfo *sim_m2_error(const sim_m2 *s) { return &s->err; }

/* ---- creation ------------------------------------------------------------------------------------ */

void sim_m2_free(sim_m2 *s)
{
	if (s == NULL)
		return;
	if (s->msgs != NULL) {
		sim_m2_msgs_clear(s);
		free(s->msgs);
	}
	free(s->seg0);
	free(s->sink[0]);
	free(s->sink[1]);
	free(s->sink[2]);
	free(s->scratch);
	free(s->enc);
	free(s->out);
	free(s->rx_log);
	free(s->tx_log);
	free(s);
}

sim_m2 *sim_m2_new(const sim_m2_cfg *cfg, const sim_m2_auth_ops *auth)
{
	sim_m2 *s;
	sim_m2_cfg c;
	uint64_t enc;

	if (cfg != NULL)
		c = *cfg;
	else
		sim_m2_cfg_default(&c);
	/* a configuration the server cannot honour is refused up front: the lists are read up to their counts */
	enc = (uint64_t)c.ctl_cap + 2u * (uint64_t)c.seg_cap + 512u;
	if (c.n_methods > SIM_M2_LIST_MAX || c.n_modes > SIM_M2_LIST_MAX || c.ctl_cap == 0 || c.seg_cap == 0 ||
	    enc > 0xffffffffu)
		return NULL;
	s = (sim_m2 *)calloc(1, sizeof(*s));
	if (s == NULL)
		return NULL;
	s->cfg = c;
	if (auth != NULL)
		s->auth = *auth;
	s->enc_cap = (uint32_t)enc; /* control frame + two copied segments + preamble / CRC / epilogue; the data segment is referenced */
	s->seg0 = (uint8_t *)malloc(s->cfg.ctl_cap);
	s->scratch = (uint8_t *)malloc(s->cfg.ctl_cap);
	s->sink[0] = (uint8_t *)malloc(s->cfg.seg_cap);
	s->sink[1] = (uint8_t *)malloc(s->cfg.seg_cap);
	s->sink[2] = (uint8_t *)malloc(s->cfg.seg_cap);
	s->enc = (uint8_t *)malloc(s->enc_cap);
	s->rx_log = (uint8_t *)malloc(s->cfg.preauth_cap);
	s->tx_log = (uint8_t *)malloc(s->cfg.preauth_cap);
	s->msgs = (sim_m2_msg *)calloc(s->cfg.max_msgs != 0 ? s->cfg.max_msgs : 1u, sizeof(sim_m2_msg));
	if (!s->seg0 || !s->scratch || !s->sink[0] || !s->sink[1] || !s->sink[2] || !s->enc || !s->rx_log ||
	    !s->tx_log || !s->msgs) {
		sim_m2_free(s);
		return NULL;
	}
	wri_ring_init(&s->ring, s->ring_buf, sizeof(s->ring_buf));
	wri_m2_rx_init(&s->rx, s->seg0, s->cfg.ctl_cap, s->cfg.seg_cap);
	s->rx_log_on = 1;
	s->tx_log_on = 1;
	s->state = SIM_M2_ST_BANNER;
	if (emit_banner(s) != WR_OK) {
		sim_m2_free(s);
		return NULL;
	}
	return s;
}

