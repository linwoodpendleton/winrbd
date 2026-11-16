/* SPDX-License-Identifier: MIT */
/*
 * m2-conn against the frames of harness/vectors/msgr2/frames-crc.json (scrubbed captures of a stock client and
 * a stock v20.2.5 cluster), the oracle that does not come from the simulator or from our own encoders:
 *
 *   - what we send equals the captured client frames byte for byte: a header-only MESSAGE, a four-segment
 *     MESSAGE (front, empty middle, data; alignments 8, 8, 8, 4096), KEEPALIVE2, and the KEEPALIVE2_ACK we
 *     answer a captured KEEPALIVE2 with;
 *   - captured server frames are accepted and delivered: MESSAGE with one, two and four segments (header
 *     fields, segment lengths, segment bytes), KEEPALIVE2_ACK stamps;
 *   - captured SERVER_IDENT frames of a monitor (including the answer to a lossless-intent ident) and of an
 *     OSD (nonce-carrying address, second legacy entry) complete the handshake; captured AUTH_BAD_METHOD and
 *     IDENT_MISSING_FEATURES frames fail it with the details a caller reads from the errinfo.
 * The handshake itself is replayed against preauth-hmac.json in test_m2_conn_hs.c.
 */
#include "m2_conn_msgs.h"

typedef struct vframe {
	uint8_t *b;
	size_t n;
} vframe;

static vframe vec_frame(const wrt_json *j, const char *name)
{
	wrt_tok frames = wrt_json_get(j, wrt_json_root(j), "frames");
	size_t i, n = wrt_json_count(j, frames);
	vframe v = {NULL, 0};

	for (i = 0; i < n; i++) {
		wrt_tok f = wrt_json_at(j, frames, i);
		char *nm = wrt_json_strdup(j, wrt_json_get(j, f, "name"));
		int hit = nm != NULL && strcmp(nm, name) == 0;

		free(nm);
		if (hit) {
			WRT_CHECK(wrt_json_get_hex(j, f, "hex", &v.b, &v.n) == 0);
			return v;
		}
	}
	fprintf(stderr, "vector frame \"%s\" is missing\n", name);
	WRT_CHECK(0);
	return v;
}

/* ---- what we send ------------------------------------------------------------------------------------- */

static void check_sent(rig *r, size_t before, const vframe *f)
{
	(void)rig_flush_tx(r);
	WRT_CHECK_U64(r->sent_len - before, f->n);
	if (r->sent_len - before == f->n)
		WRT_CHECK_MEM(r->sent + before, f->b, f->n);
}

static void test_client_frames(const wrt_json *j)
{
	vframe f;
	rig r;
	size_t before;
	wri_m2_msg_out m;
	rig_fr fr[1];

	/* a header-only monitor MESSAGE (first message of a connection: seq 1, ack_seq 0) */
	f = vec_frame(j, "mon-message-first-client");
	rig_init(&r);
	ready_rig(&r);
	before = r.sent_len;
	m = mk(5, 0, NULL, 0, NULL, 0);
	m.priority = 127, m.version = 1, m.compat_version = 1;
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	check_sent(&r, before, &f);
	rig_free(&r);
	free(f.b);

	/* an OSD write: front 224 bytes, no middle, data 100 bytes (four segments, data aligned to 4096) */
	f = vec_frame(j, "osd-message-four-segments-client");
	WRT_CHECK_U64(rig_split(f.b, f.n, fr, 1, NULL), 1);
	WRT_CHECK_U64(fr[0].nseg, 4);
	WRT_CHECK_U64(fr[0].len[1], 224);
	WRT_CHECK_U64(fr[0].len[2], 0);
	WRT_CHECK_U64(fr[0].len[3], 100);
	rig_init(&r);
	ready_rig(&r);
	before = r.sent_len;
	m = mk(42, 1, fr[0].seg[1], 224, fr[0].seg[3], 100);
	m.priority = 63, m.version = 9, m.compat_version = 3;
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	check_sent(&r, before, &f);
	rig_free(&r);
	free(f.b);

	/* KEEPALIVE2 with the stamp of the capture */
	f = vec_frame(j, "keepalive2-client");
	rig_init(&r);
	ready_rig(&r);
	before = r.sent_len;
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_keepalive(&r.x, &r.c, 1794821231u, 757072124u));
	check_sent(&r, before, &f);
	rig_free(&r);
	free(f.b);
}

/* ---- what we receive ---------------------------------------------------------------------------------- */

static void test_server_messages(const wrt_json *j)
{
	vframe f;
	rig r;
	rig_fr fr[1];
	const rig_msg *m;

	/* two segments: header + front of 152 bytes */
	f = vec_frame(j, "osd-message-two-segments-server");
	WRT_CHECK_U64(rig_split(f.b, f.n, fr, 1, NULL), 1);
	rig_init(&r);
	ready_rig(&r);
	rig_inject(&r, f.b, f.n);
	WRT_CHECK_U64(r.up.n_message, 1);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.c.in_seq, 1);
	WRT_CHECK_U64(r.c.n_seq_gaps, 0);
	WRT_CHECK_U64(r.up.seglen[0], 152);
	WRT_CHECK_U64(r.up.seglen[1], 0);
	WRT_CHECK_U64(r.up.seglen[2], 0);
	m = &r.up.msgs[0];
	WRT_CHECK_U64(m->hdr.seq, 1);
	WRT_CHECK_U64(m->hdr.tid, 1);
	WRT_CHECK_U64(m->hdr.type, 43);
	WRT_CHECK_U64(m->hdr.priority, 127);
	WRT_CHECK_U64(m->hdr.version, 8);
	WRT_CHECK_U64(m->hdr.compat_version, 2);
	WRT_CHECK_U64(m->hdr.ack_seq, 1);
	WRT_CHECK_U64(m->hdr.flags, 3);
	WRT_CHECK_U64(m->hdr.data_pre_padding_len, 0);
	WRT_CHECK_U64(m->hdr.data_off, 0);
	WRT_CHECK_U64(m->stored[0], 152);
	WRT_CHECK_U64(m->stored[1], 0);
	WRT_CHECK_U64(m->stored[2], 0);
	if (m->seg[0] != NULL)
		WRT_CHECK_MEM(m->seg[0], fr[0].seg[1], 152);
	rig_free(&r);
	free(f.b);

	/* four segments (the capture is a client frame; the server side reads the same layout) */
	f = vec_frame(j, "osd-message-four-segments-client");
	WRT_CHECK_U64(rig_split(f.b, f.n, fr, 1, NULL), 1);
	rig_init(&r);
	ready_rig(&r);
	rig_inject(&r, f.b, f.n);
	WRT_CHECK_U64(r.up.n_message, 1);
	WRT_CHECK_U64(r.up.seglen[0], 224);
	WRT_CHECK_U64(r.up.seglen[1], 0);
	WRT_CHECK_U64(r.up.seglen[2], 100);
	m = &r.up.msgs[0];
	WRT_CHECK_U64(m->hdr.type, 42);
	WRT_CHECK_U64(m->hdr.priority, 63);
	WRT_CHECK_U64(m->hdr.version, 9);
	WRT_CHECK_U64(m->hdr.compat_version, 3);
	WRT_CHECK_U64(m->stored[0], 224);
	WRT_CHECK_U64(m->stored[1], 0);
	WRT_CHECK_U64(m->stored[2], 100);
	if (m->seg[0] != NULL && m->seg[2] != NULL) {
		WRT_CHECK_MEM(m->seg[0], fr[0].seg[1], 224);
		WRT_CHECK_MEM(m->seg[2], fr[0].seg[3], 100);
	}
	/* byte by byte as well */
	rig_free(&r);
	rig_init(&r);
	r.rx_chunk = 1;
	ready_rig(&r);
	rig_inject(&r, f.b, f.n);
	WRT_CHECK_U64(r.up.n_message, 1);
	if (r.up.n_message == 1 && r.up.msgs[0].seg[2] != NULL)
		WRT_CHECK_MEM(r.up.msgs[0].seg[2], fr[0].seg[3], 100);
	rig_free(&r);
	free(f.b);

	/* one segment: a header-only message */
	f = vec_frame(j, "mon-message-first-client");
	rig_init(&r);
	ready_rig(&r);
	rig_inject(&r, f.b, f.n);
	WRT_CHECK_U64(r.up.n_message, 1);
	WRT_CHECK_U64(r.up.msgs[0].hdr.type, 5);
	WRT_CHECK_U64(r.up.msgs[0].stored[0], 0);
	WRT_CHECK_U64(r.c.in_seq, 1);
	rig_free(&r);
	free(f.b);
}

static void test_keepalive_frames(const wrt_json *j)
{
	vframe ka, ack;
	rig r;
	size_t before;

	ka = vec_frame(j, "keepalive2-client");
	ack = vec_frame(j, "keepalive2-ack-server");

	/* a KEEPALIVE2 is answered with the captured ACK frame (same stamp) */
	rig_init(&r);
	ready_rig(&r);
	before = r.sent_len;
	rig_inject(&r, ka.b, ka.n);
	check_sent(&r, before, &ack);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	rig_free(&r);

	/* the captured ACK shows up in the counters */
	rig_init(&r);
	ready_rig(&r);
	r.x.now.mono_ms = 4321;
	rig_inject(&r, ack.b, ack.n);
	WRT_CHECK_U64(r.c.n_ka_ack, 1);
	WRT_CHECK_U64(r.c.ka_ack_sec, 1794821231u);
	WRT_CHECK_U64(r.c.ka_ack_nsec, 757072124u);
	WRT_CHECK_U64(r.c.ka_ack_ms, 4321);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	rig_free(&r);
	free(ka.b);
	free(ack.b);
}

/* ---- handshake frames of the capture ------------------------------------------------------------------ */

/* A connection brought by the simulator to the state in which it waits for `limit` bytes' worth of server answers. */
static void rig_at(rig *r, int64_t limit, unsigned want_state)
{
	r->scfg.f.out_limit = limit;
	rig_start(r);
	rig_pump(r);
	WRT_CHECK_U64(r->c.state, want_state);
}

static void test_captured_idents(const wrt_json *j)
{
	static const char *const mon[] = {"mon-server-ident", "mon-server-ident-answer-to-lossless-intent"};
	vframe f;
	rig r;
	size_t i;

	for (i = 0; i < 2; i++) {
		f = vec_frame(j, mon[i]);
		rig_init(&r);
		rig_at(&r, 307, WRI_M2_IDENT);
		rig_inject(&r, f.b, f.n);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.up.n_ready, 1);
		WRT_CHECK_U64((uint64_t)r.c.peer_gid, 0);
		WRT_CHECK_U64(r.c.server_flags, 1);
		WRT_CHECK_U64(r.c.server_cookie, 0);
		WRT_CHECK_U64(r.c.features, 0x3f07fffffffdffffull);
		WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), WR_DEADLINE_NONE);
		rig_free(&r);
		free(f.b);
	}

	/* an OSD: the target carries the daemon's nonce, SERVER_IDENT lists that address and the legacy one */
	f = vec_frame(j, "osd-server-ident");
	rig_init(&r);
	r.role = WRI_ENTITY_OSD;
	r.scfg.entity_type = SIM_M2_ENT_OSD;
	r.scfg.server_port = 6818;
	r.scfg.server_nonce = 1851664350u;
	rig_set_target(&r, 6818);
	r.dial.nonce = 1851664350u;
	wri_eaddr_from_wr(&r.target, &r.dial, WRI_EADDR_TYPE_MSGR2);
	rig_at(&r, 307, WRI_M2_IDENT);
	rig_inject(&r, f.b, f.n);
	if (r.c.state != WRI_M2_READY)
		fprintf(stderr, "osd ident: state %u status %d\n", (unsigned)r.c.state, (int)r.c.err.status);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64((uint64_t)r.c.peer_gid, 2);
	WRT_CHECK_U64(r.c.server_flags, 1);
	rig_free(&r);

	/* the same frame for a connection that dialled another OSD port: refused */
	rig_init(&r);
	r.role = WRI_ENTITY_OSD;
	r.scfg.entity_type = SIM_M2_ENT_OSD;
	r.scfg.server_port = 6820;
	r.scfg.server_nonce = 1851664350u;
	rig_set_target(&r, 6820);
	r.dial.nonce = 1851664350u;
	wri_eaddr_from_wr(&r.target, &r.dial, WRI_EADDR_TYPE_MSGR2);
	rig_at(&r, 307, WRI_M2_IDENT);
	rig_inject(&r, f.b, f.n);
	rig_check_failed(&r, WR_E_M2_ADDR);
	rig_free(&r);
	free(f.b);
}

static void test_captured_refusals(const wrt_json *j)
{
	static const char *const bad[] = {"wrongkey-auth-bad-method", "no-osd-caps-auth-bad-method"};
	vframe f;
	rig r;
	size_t i;

	for (i = 0; i < 2; i++) {
		f = vec_frame(j, bad[i]);
		rig_init(&r);
		rig_at(&r, 98, WRI_M2_AUTH);
		rig_inject(&r, f.b, f.n);
		rig_check_failed(&r, WR_E_M2_BAD_METHOD);
		WRT_CHECK_U64((int64_t)r.c.err.peer_result, -13);
		WRT_CHECK_U64(r.c.err.a0, 1u << 2);               /* allowed methods {2} */
		WRT_CHECK_U64(r.c.err.a1, (1u << 1) | (1u << 2)); /* allowed modes {1, 2} */
		WRT_CHECK_U64(r.c.err.a2, 2);                     /* the method we offered */
		rig_free(&r);
		free(f.b);
	}

	f = vec_frame(j, "ident-missing-features-probe");
	rig_init(&r);
	rig_at(&r, 307, WRI_M2_IDENT);
	rig_inject(&r, f.b, f.n);
	rig_check_failed(&r, WR_E_M2_MISSING_FEATURES);
	WRT_CHECK_U64(r.c.err.a0, 0x0800000000000000ull); /* MSG_ADDR2 */
	rig_free(&r);
	free(f.b);
}

int main(void)
{
	wrt_json j;

	WRT_CHECK(wrt_json_load_vec(&j, "msgr2/frames-crc.json") == 0);
	test_client_frames(&j);
	test_server_messages(&j);
	test_keepalive_frames(&j);
	test_captured_idents(&j);
	test_captured_refusals(&j);
	wrt_json_free(&j);
	return wrt_finish();
}
