/* SPDX-License-Identifier: MIT */
/*
 * m2-conn-sec, failure half (docs/design/core-architecture.md 34.3 to 34.5, 34.8, 39.2): what a secure connection does when the peer, the
 * network or the configuration is wrong, against the secure peer of sim_m2.h and its fault hooks.
 *
 * The rule every case ends with: the connection fails once (up->closed called once, with the status of the FIRST cause), nothing is written after
 * the failure, the codec seam is back to crc, the secure slot and its bounce buffer are ZERO (no key schedule, nonce, staging or ciphertext
 * survives), the auth layer's copy of the secret is gone, and the connection never accepted a byte that failed to authenticate.
 *
 *   - the signature of the server wrong inside a good frame (WR_E_M2_SIGNATURE: the tag first, the HMAC compare second);
 *   - every defect the simulator can put into one server frame, at the signature, SERVER_IDENT (two operations) and a session message (two
 *     operations): flipped bits in each part, wrong tags, a key or a nonce off by one, a repeated nonce, and, behind a good tag, a wrong preamble CRC, the
 *     compressed flag, reserved and unused slot bytes, segment counts 0 and 5, an unknown tag, lying lengths, an empty last segment, garbage in the
 *     epilogue: each with its own status; garbage in the padding is ignored;
 *   - wrong seeds and wrong keys on either side, a frame cut at every byte offset followed by the end of the connection;
 *   - compressed frames and COMPRESSION_REQUEST in crc and in secure mode;
 *   - a frame in crc framing after a secure AUTH_DONE (a downgrade attempt) is a tag failure, never a signature;
 *   - the operation limit lowered by the test: transmit refuses (WR_E_M2_NONCE) before a byte of the frame exists, receive refuses the frame;
 *   - a host GCM that refuses to start an operation after the nonces of the frame were taken (the builder wipes its key: the connection must end,
 *     not stay READY with a transmit side that can never send again), and the same loss seen after the host consumed bytes;
 *   - the real cephx machine: no secret, a short secret, a secret in crc mode;
 *   - the end of the connection at every point of the handshake (close, the transport gone), mid-stream, twice: the slot is zero each time;
 *   - the handshake timeout in secure mode; backpressure at the switch and at CLIENT_IDENT (the auth step is never repeated, no nonce is taken), and a
 *     secure frame that can never fit the encode buffer (WR_E_TOOBIG at once).
 */
#include "m2_conn_msgs.h"
#include "m2_conn_sec_cx.h"
#include "wri_le.h"
#include "wri_pgcm.h"
#include "wri_prim.h"

#define OFFER_BOTH (WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE | WRI_M2_OFFER_SECURE_FIRST)
#define OFFER_SEC_ONLY WRI_M2_OFFER_SECURE
#define OFFER_CRC_ONLY WRI_M2_OFFER_CRC

static void secure_rig(rig *r)
{
	rig_init(r);
	rig_enable_secure(r, OFFER_BOTH);
	rig_server_modes(r, 2, 1);
}

static void secure_ready(rig *r)
{
	secure_rig(r);
	rig_start(r);
	rig_pump(r);
	WRT_CHECK_U64(r->c.state, WRI_M2_READY);
	WRT_CHECK_U64(sim_m2_is_secure(r->s), 1);
}

/* The peer's EOF reaches the connection (what the host does when it reads 0): the closed callback, the wipe. */
static void peer_eof(rig *r)
{
	rig_pump(r);
	if (r->c.state != WRI_M2_FAILED && r->c.state != WRI_M2_CLOSING && r->c.state != WRI_M2_FREE)
		wri_m2_conn_on_closed(&r->x, &r->c, 104);
}

/* After an end that was not a protocol failure: once, wiped, quiet. */
static void check_ended(rig *r, wr_status want_first)
{
	wr_iov iov[WRI_M2_TXQ_IOV];

	WRT_CHECK_U64(r->up.n_closed, 1);
	WRT_CHECK_STATUS(want_first, r->up.closed_err.status);
	WRT_CHECK(r->c.pa == NULL);
	WRT_CHECK(r->c.sec == NULL && r->c.rx.sx == NULL && r->c.tx.sx == NULL);
	WRT_CHECK(rig_slot_zero(r));
	WRT_CHECK_U64(r->au.hand_len, 0);
	WRT_CHECK_U64(wri_m2_conn_tx_peek(&r->c, iov, WRI_M2_TXQ_IOV), 0);
	WRT_CHECK_U64(r->c.tx.pending, 0);
}

/* ---- 1. the server's signature wrong inside a good frame ------------------------------------------------------------- */

static void test_signature(void)
{
	rig r;
	rig_sframe cf[4];
	size_t nf, cused;
	rig_fr f[8];
	wr_status e = WR_OK;
	uint8_t secret[64];

	secure_rig(&r);
	r.scfg.f.bad_signature = 1;
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_SIGNATURE);
	/* all that went out after AUTH_DONE is our own signature: CLIENT_IDENT is never sent to a server that failed to prove itself */
	memcpy(secret, r.s->sec.secret, 64);
	(void)rig_split(r.sent + WRI_M2_BANNER_LEN, r.sent_len - WRI_M2_BANNER_LEN, f, 8, &cused);
	nf = rig_decode_secure(secret, 64, 1, r.sent + WRI_M2_BANNER_LEN + cused, r.sent_len - WRI_M2_BANNER_LEN - cused, cf, 4, &e);
	WRT_CHECK_STATUS(WR_OK, e);
	WRT_CHECK_U64(nf, 1);
	if (nf == 1)
		WRT_CHECK_U64(cf[0].tag, WRI_M2_TAG_AUTH_SIGNATURE);
	rig_sframes_free(cf, nf);
	WRT_CHECK(rig_secret_absent(&r, secret, 64));
	rig_free(&r);
}

/* ---- 2. one defective server frame -------------------------------------------------------------------------------------- */

typedef struct mcase {
	const char *name;
	unsigned frame;      /* server frame number: 4 = AUTH_SIGNATURE, 5 = SERVER_IDENT, 0 = the first session message */
	sim_sec_mut m;
	wr_status want;      /* the status of the failure, WR_OK = the frame is accepted (the defect is one a receiver must ignore) */
	int no_data;         /* the session message has no data segment (two segments: slots 2 and 3 of the preamble are unused) */
} mcase;

static mcase mk_case(const char *name, unsigned frame, uint32_t mask, wr_status want)
{
	mcase c;

	memset(&c, 0, sizeof(c));
	c.name = name, c.frame = frame, c.m.mask = mask, c.want = want;
	return c;
}

static mcase flip(const char *name, unsigned frame, unsigned part, unsigned region, unsigned byte, unsigned bit)
{
	mcase c = mk_case(name, frame, SIM_SEC_M_FLIP, WR_E_M2_SEC_TAG);

	c.m.flip_part = (uint8_t)part, c.m.flip_region = (uint8_t)region, c.m.flip_byte = byte, c.m.flip_bit = (uint8_t)bit;
	return c;
}

static void run_mcase(const mcase *c)
{
	rig r;
	uint8_t front[100], data[100];

	secure_rig(&r);
	fill(front, sizeof(front), 3);
	fill(data, sizeof(data), 4);
	if (c->frame != 0) { /* a handshake frame: the fault is set before the connection starts */
		r.scfg.f.sec.mut = c->m;
		r.scfg.f.sec.mut_frame = c->frame;
		rig_start(&r);
		rig_pump(&r);
	} else {
		rig_start(&r);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		r.s->cfg.f.sec.mut = c->m;
		r.s->cfg.f.sec.mut_frame = r.s->n_tx_frames + 1u;
		if (c->m.mask & SIM_SEC_M_KEEP_TAIL) { /* a frame with an empty last segment: a keepalive with a second, empty segment */
			uint8_t stamp[8] = {1, 2, 3, 4, 5, 6, 7, 8};
			wri_m2_seg_src seg[2];

			seg[0].p = stamp, seg[0].len = 8, seg[0].ref = 0;
			seg[1].p = stamp, seg[1].len = 0, seg[1].ref = 0;
			WRT_CHECK_STATUS(WR_OK, sim_m2_send_frame(r.s, WRI_M2_TAG_KEEPALIVE2, seg, 2));
		} else {
			WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x40, 1, 4, front, sizeof(front), NULL, 0, c->no_data ? NULL : data, c->no_data ? 0u : (uint32_t)sizeof(data)));
		}
		r.s->cfg.f.sec.mut_frame = 0;
		rig_pump(&r);
	}
	if (c->want == WR_OK) {
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.up.n_closed, 0);
		WRT_CHECK_U64(r.up.n_message, c->frame == 0 ? 1u : 0u);
		if (c->frame == 0 && r.up.n_msgs == 1u) {
			WRT_CHECK_U64(r.up.msgs[0].stored[0], sizeof(front));
			WRT_CHECK_MEM(r.up.msgs[0].seg[2], data, sizeof(data));
		}
	} else {
		if (r.c.state != WRI_M2_FAILED)
			fprintf(stderr, "case \"%s\": the connection is in state %d, not FAILED\n", c->name, r.c.state);
		rig_check_failed(&r, c->want);
		WRT_CHECK_U64(r.up.n_message, 0);                         /* nothing that failed to authenticate reached the upper layer */
		WRT_CHECK_U64(r.up.n_ready, c->frame == 5u || c->frame == 4u ? 0u : 1u);
		WRT_CHECK_U64(r.c.n_msg_in, 0);
	}
	rig_free(&r);
}

static void test_defective_frames(void)
{
	mcase t[80];
	size_t n = 0, i;
	/* tag-level: the tag decides before anything else is looked at */
	t[n++] = flip("sig p1 first ciphertext byte", 4, 1, SIM_SEC_R_RAW, 0, 0);
	t[n++] = flip("sig p1 last ciphertext byte", 4, 1, SIM_SEC_R_RAW, 79, 7);
	t[n++] = flip("sig p1 tag byte 0", 4, 1, SIM_SEC_R_TAG, 0, 3);
	t[n++] = flip("sig p1 tag byte 15", 4, 1, SIM_SEC_R_TAG, 15, 0);
	t[n++] = mk_case("sig wrong key", 4, SIM_SEC_M_KEY, WR_E_M2_SEC_TAG);
	t[n] = mk_case("sig tag of other data", 4, SIM_SEC_M_TAG, WR_E_M2_SEC_TAG), t[n].m.tag_part = 1, n++;
	t[n] = mk_case("sig nonce repeated", 4, SIM_SEC_M_NONCE, WR_E_M2_SEC_TAG), t[n].m.nonce_part = 1, t[n].m.nonce_delta = -1, n++;
	t[n] = mk_case("sig nonce skipped", 4, SIM_SEC_M_NONCE, WR_E_M2_SEC_TAG), t[n].m.nonce_part = 1, t[n].m.nonce_delta = 1, n++;
	t[n++] = flip("ident p1 byte 40", 5, 1, SIM_SEC_R_RAW, 40, 1);
	t[n++] = flip("ident p2 first byte", 5, 2, SIM_SEC_R_RAW, 0, 0);
	t[n++] = flip("ident p2 tag byte 3", 5, 2, SIM_SEC_R_TAG, 3, 5);
	t[n] = mk_case("ident tag of p2 over other data", 5, SIM_SEC_M_TAG, WR_E_M2_SEC_TAG), t[n].m.tag_part = 2, n++;
	t[n] = mk_case("ident nonce of p2 skipped", 5, SIM_SEC_M_NONCE, WR_E_M2_SEC_TAG), t[n].m.nonce_part = 2, t[n].m.nonce_delta = 1, n++;
	t[n++] = flip("msg p1 byte 10", 0, 1, SIM_SEC_R_RAW, 10, 2);
	t[n++] = flip("msg p1 preamble crc byte", 0, 1, SIM_SEC_R_RAW, 28, 6);
	t[n++] = flip("msg p3 first ciphertext byte", 0, 3, SIM_SEC_R_RAW, 0, 0);
	t[n++] = flip("msg p3 data byte", 0, 3, SIM_SEC_R_RAW, 200, 4);
	t[n++] = flip("msg p3 epilogue ciphertext", 0, 3, SIM_SEC_R_EPILOGUE, 0, 1);
	t[n++] = flip("msg p3 epilogue pad byte", 0, 3, SIM_SEC_R_EPILOGUE, 9, 7);
	t[n++] = flip("msg p3 tag byte 15", 0, 3, SIM_SEC_R_TAG, 15, 7);
	t[n] = mk_case("msg tag of p3 over other data", 0, SIM_SEC_M_TAG, WR_E_M2_SEC_TAG), t[n].m.tag_part = 3, n++;
	t[n] = mk_case("msg tag of p1 over other data", 0, SIM_SEC_M_TAG, WR_E_M2_SEC_TAG), t[n].m.tag_part = 1, n++;
	t[n++] = mk_case("msg wrong key", 0, SIM_SEC_M_KEY, WR_E_M2_SEC_TAG);
	t[n] = mk_case("msg nonce repeated (p3)", 0, SIM_SEC_M_NONCE, WR_E_M2_SEC_TAG), t[n].m.nonce_part = 2, t[n].m.nonce_delta = -1, n++;
	t[n] = mk_case("msg nonce skipped (p1)", 0, SIM_SEC_M_NONCE, WR_E_M2_SEC_TAG), t[n].m.nonce_part = 1, t[n].m.nonce_delta = 1, n++;
	/* behind a good tag: the preamble rules, each with its status */
	t[n++] = mk_case("msg preamble crc wrong", 0, SIM_SEC_M_PRE_CRC, WR_E_M2_FRAME_CRC);
	t[n] = mk_case("msg compressed flag", 0, SIM_SEC_M_FLAGS, WR_E_M2_FRAME_FORM), t[n].m.pre_flags = 1, n++;
	t[n] = mk_case("msg reserved byte", 0, SIM_SEC_M_RESERVED, WR_E_M2_FRAME_FORM), t[n].m.pre_reserved = 1, n++;
	t[n] = mk_case("msg nseg 0", 0, SIM_SEC_M_PRE_NSEG, WR_E_M2_FRAME_FORM), t[n].m.pre_nseg = 0, n++;
	t[n] = mk_case("msg nseg 5", 0, SIM_SEC_M_PRE_NSEG, WR_E_M2_FRAME_FORM), t[n].m.pre_nseg = 5, n++;
	t[n] = mk_case("msg tag 0", 0, SIM_SEC_M_PRE_TAG, WR_E_M2_TAG), t[n].m.pre_tag = 0, n++;
	t[n] = mk_case("msg tag 23", 0, SIM_SEC_M_PRE_TAG, WR_E_M2_TAG), t[n].m.pre_tag = 23, n++;
	t[n] = mk_case("msg unused slot junk", 0, SIM_SEC_M_SLOT, WR_E_M2_FRAME_FORM), t[n].m.slot_junk = 0x55, t[n].no_data = 1, n++;
	t[n] = mk_case("msg segment 3 length above the cap", 0, SIM_SEC_M_PRE_LEN, WR_E_M2_FRAME_TOOBIG), t[n].m.pre_len_mask = 1u << 3,
	t[n].m.pre_len[3] = 2u << 20, n++;
	t[n] = mk_case("msg segment 0 length above the buffer", 0, SIM_SEC_M_PRE_LEN, WR_E_M2_FRAME_TOOBIG), t[n].m.pre_len_mask = 1u << 0,
	t[n].m.pre_len[0] = 200000, n++;
	t[n++] = mk_case("empty last segment", 0, SIM_SEC_M_KEEP_TAIL, WR_E_M2_FRAME_FORM);
	t[n] = mk_case("msg epilogue late_status 5", 0, SIM_SEC_M_LATE, WR_E_M2_FRAME_FORM), t[n].m.late_status = 0x05, n++;
	t[n] = mk_case("msg epilogue late_status 0x1e", 0, SIM_SEC_M_LATE, WR_E_M2_FRAME_FORM), t[n].m.late_status = 0x1f, n++;
	t[n++] = mk_case("sig preamble crc wrong", 4, SIM_SEC_M_PRE_CRC, WR_E_M2_FRAME_CRC);
	t[n] = mk_case("sig compressed flag", 4, SIM_SEC_M_FLAGS, WR_E_M2_FRAME_FORM), t[n].m.pre_flags = 1, n++;
	t[n] = mk_case("ident compressed flag", 5, SIM_SEC_M_FLAGS, WR_E_M2_FRAME_FORM), t[n].m.pre_flags = 1, n++;
	t[n] = mk_case("ident tag 0", 5, SIM_SEC_M_PRE_TAG, WR_E_M2_TAG), t[n].m.pre_tag = 0, n++;
	/* defects a receiver must ignore: padding is not looked at (sec.md 2.8) */
	t[n] = mk_case("msg padding garbage (accepted)", 0, SIM_SEC_M_PAD, WR_OK), t[n].m.pad_fill = 0xa5, n++;
	for (i = 0; i < n; i++)
		run_mcase(&t[i]);
}

/* ---- 3. wrong keys and seeds, frames cut anywhere --------------------------------------------------------------------------- */

static void test_wrong_keys(void)
{
	rig r;

	/* the server sends with the seed we send with / under another key: its first sealed frame does not authenticate */
	secure_rig(&r);
	r.scfg.f.sec.wrong_seed_tx = 1;
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_SEC_TAG);
	rig_free(&r);

	secure_rig(&r);
	r.scfg.f.sec.wrong_key_tx = 1;
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_SEC_TAG);
	rig_free(&r);

	/* the server reads with the wrong seed: it cannot read our signature and closes; the connection ends with the transport's status */
	secure_rig(&r);
	r.scfg.f.sec.wrong_seed_rx = 1;
	rig_start(&r);
	peer_eof(&r);
	WRT_CHECK_U64(sim_m2_closed(r.s), 1);
	check_ended(&r, WR_E_NET_CLOSED);
	WRT_CHECK_U64(r.c.state, WRI_M2_FREE);
	WRT_CHECK_U64(r.up.n_ready, 0);
	rig_free(&r);
}

static void test_truncation(void)
{
	static const struct {
		unsigned frame;
		size_t wire;
	} k[] = {{4, 96}, {5, 0}, {0, 0}}; /* the signature (96 bytes), SERVER_IDENT, a session message: the length of the last two is measured below */
	size_t i;

	for (i = 0; i < 3; i++) {
		size_t wire = k[i].wire, cut;
		uint8_t front[100], data[100];

		fill(front, sizeof(front), 3);
		fill(data, sizeof(data), 4);
		if (wire == 0) { /* measure: the bytes the server wrote for that frame in an untouched run */
			rig r;
			size_t before;

			secure_rig(&r);
			rig_start(&r);
			rig_pump(&r);
			if (k[i].frame == 5) {
				rig_sframe sf[4];
				rig_fr g[8];
				size_t used, ns, mf;

				ns = rig_split(r.rcvd + WRI_M2_BANNER_LEN, r.rcvd_len - WRI_M2_BANNER_LEN, g, 8, &used);
				WRT_CHECK_U64(ns, 3);
				mf = rig_decode_secure(r.s->sec.secret, 64, 0, r.rcvd + WRI_M2_BANNER_LEN + used, r.rcvd_len - WRI_M2_BANNER_LEN - used, sf, 4, NULL);
				WRT_CHECK_U64(mf, 2);
				wire = mf == 2 ? sf[1].wire : 0;
				rig_sframes_free(sf, mf);
			} else {
				before = r.rcvd_len;
				WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x40, 1, 4, front, sizeof(front), NULL, 0, data, sizeof(data)));
				rig_pump(&r);
				wire = r.rcvd_len - before;
			}
			rig_free(&r);
		}
		WRT_CHECK(wire >= 96);
		for (cut = 1; cut < wire; cut++) {
			rig r;

			secure_rig(&r);
			r.scfg.f.sec.mut.mask = SIM_SEC_M_TRUNC;
			r.scfg.f.sec.mut.truncate_at = (uint32_t)cut;
			r.scfg.f.sec.mut_frame = k[i].frame != 0 ? k[i].frame : 0xffffu;
			rig_start(&r);
			rig_pump(&r);
			if (k[i].frame == 0) {
				WRT_CHECK_U64(r.c.state, WRI_M2_READY);
				r.s->cfg.f.sec.mut_frame = r.s->n_tx_frames + 1u;
				WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x40, 1, 4, front, sizeof(front), NULL, 0, data, sizeof(data)));
				r.s->cfg.f.sec.mut_frame = 0;
				rig_pump(&r);
			}
			/* a frame that is cut waits for its rest: nothing is delivered, nothing fails yet ... */
			WRT_CHECK_U64(r.up.n_message, 0);
			WRT_CHECK_U64(r.up.n_closed, 0);
			WRT_CHECK_U64(r.up.n_ready, k[i].frame == 0 ? 1u : 0u);
			/* ... and when the connection ends the slot is wiped whatever half-frame it held */
			peer_eof(&r);
			check_ended(&r, WR_E_NET_CLOSED);
			WRT_CHECK_U64(r.up.n_message, 0);
			rig_free(&r);
		}
	}
}

/* ---- 4. compression ------------------------------------------------------------------------------------------------------------ */

/* A crc control frame with the compressed flag set in the preamble (and a correct CRC), delivered to a READY crc connection. */
static void test_compressed_crc(void)
{
	rig r;
	wri_m2_desc d;
	uint8_t pre[WRI_M2_PREAMBLE_LEN], frame[WRI_M2_PREAMBLE_LEN + 8 + 4], stamp[8] = {1, 2, 3, 4, 5, 6, 7, 8};

	rig_init(&r);
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	memset(&d, 0, sizeof(d));
	d.tag = WRI_M2_TAG_KEEPALIVE2;
	d.nseg = 1;
	d.len[0] = 8;
	d.align[0] = 8;
	d.flags = 1; /* compressed */
	wri_m2_preamble_build(NULL, pre, &d);
	memcpy(frame, pre, sizeof(pre));
	memcpy(frame + sizeof(pre), stamp, 8);
	wri_le32_put(frame + sizeof(pre) + 8, wri_p_crc32c(NULL, 0xffffffffu, stamp, 8));
	rig_inject(&r, frame, sizeof(frame));
	rig_check_failed(&r, WR_E_M2_FRAME_FORM);
	rig_free(&r);
}

static void test_compression_frames(void)
{
	static const unsigned tags[] = {WRI_M2_TAG_COMPRESSION_REQUEST, WRI_M2_TAG_COMPRESSION_DONE};
	size_t i;
	int secure;

	for (secure = 0; secure < 2; secure++) {
		for (i = 0; i < 2; i++) {
			rig r;
			uint8_t pay[16] = {1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
			wri_m2_seg_src seg;

			rig_init(&r);
			if (secure) {
				rig_enable_secure(&r, OFFER_BOTH);
				rig_server_modes(&r, 2, 1);
			}
			rig_start(&r);
			rig_pump(&r);
			WRT_CHECK_U64(r.c.state, WRI_M2_READY);
			WRT_CHECK_U64(r.s->compression_requested, 0); /* we never advertise compression: there is nothing to ask for */
			seg.p = pay, seg.len = sizeof(pay), seg.ref = 0;
			WRT_CHECK_STATUS(WR_OK, sim_m2_send_frame(r.s, (uint8_t)tags[i], &seg, 1));
			rig_pump(&r);
			rig_check_failed(&r, WR_E_M2_STATE); /* a frame that has no place in READY, in either mode */
			rig_free(&r);
		}
	}
}

/* ---- 5. a downgrade attempt ------------------------------------------------------------------------------------------------------- */

/* After a secure AUTH_DONE the server (or a man in the middle that cannot know the key) sends crc frames: a perfectly formed AUTH_SIGNATURE with the
 * right HMAC, which is what an attacker who could compute it would send. It must be refused as what it is: bytes that do not authenticate. */
static void test_downgrade(void)
{
	rig r;
	uint8_t *buf = NULL, mine[96], sig[32], *fr, *two;
	size_t n = 0, fl, done_len;
	wri_m2_seg_src seg;
	wri_m2_desc d;

	secure_rig(&r);
	rig_start(&r);
	rig_stage_done_and_sig(&r, &buf, &n, mine);
	/* keep AUTH_DONE (a crc frame at the head of the staged bytes), replace what follows it by crc-framed AUTH_SIGNATUREs */
	WRT_CHECK_STATUS(WR_OK, wri_m2_preamble_parse(NULL, buf, &d));
	done_len = WRI_M2_PREAMBLE_LEN + (size_t)wri_m2_frame_body_len(&d);
	tc_hmac(TC_KEY, 32, r.sent, r.sent_len, sig); /* the server's signature: over what we wrote in the clear */
	seg.p = sig, seg.len = 32, seg.ref = 0;
	fr = rig_build_frame(WRI_M2_TAG_AUTH_SIGNATURE, &seg, 1, &fl);
	two = (uint8_t *)malloc(done_len + 2u * fl);
	memcpy(two, buf, done_len);
	memcpy(two + done_len, fr, fl);
	memcpy(two + done_len + fl, fr, fl); /* two copies: enough bytes for the parser to look at a whole first part (96) */
	rig_inject(&r, two, done_len + 2u * fl);
	rig_check_failed(&r, WR_E_M2_SEC_TAG);
	WRT_CHECK_U64(r.up.n_ready, 0);
	free(fr), free(two), free(buf);
	rig_free(&r);
}

/* ---- 6. the operation limit -------------------------------------------------------------------------------------------------------- */

/* A connection that ended inside a send call because its nonce was refused: gone and wiped at once, not yet reported (the report comes at the next
 * step, never from inside the caller's own call), wanting that step now; then the report is made, once, with the cause. */
static void check_nonce_end(rig *r)
{
	WRT_CHECK_U64(r->c.state, WRI_M2_FAILED);
	WRT_CHECK_STATUS(WR_E_M2_NONCE, r->c.err.status);
	WRT_CHECK_U64(r->up.n_closed, 0);
	WRT_CHECK_U64(wri_m2_conn_deadline(&r->c), 0);
	WRT_CHECK(r->c.sec == NULL && r->c.rx.sx == NULL && r->c.tx.sx == NULL && rig_slot_zero(r) && r->c.pa == NULL);
	(void)wri_m2_conn_step(&r->x, &r->c, NULL);
	rig_check_failed(r, WR_E_M2_NONCE);
	WRT_CHECK_U64(wri_m2_conn_deadline(&r->c), WR_DEADLINE_NONE);
}

static void test_limit(void)
{
	rig r;
	uint8_t front[40];
	wri_m2_msg_out m;
	uint64_t lim;
	size_t before;

	fill(front, sizeof(front), 1);

	/* transmit: messages with nothing but a header are one operation each; the third after the limit is refused. The send returns WR_E_STATE (the
	 * connection is gone: an engine waits for a new session), the cause is the connection's error, and the owner hears of it at the next step. */
	secure_ready(&r);
	lim = r.slot->s.tx_n.ops + 2u;
	r.slot->s.ops_limit = lim;
	m = mk(0xa00, 1, NULL, 0, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	m.tid = 2;
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	rig_pump(&r);
	WRT_CHECK_U64(r.s->n_msgs_seen, 2);
	before = r.sent_len;
	m.tid = 3;
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_message(&r.x, &r.c, &m));
	check_nonce_end(&r);
	WRT_CHECK_U64(r.c.out_seq, 2); /* no sequence number burnt */
	WRT_CHECK_U64(r.sent_len, before); /* no byte of the refused frame was produced, let alone written */
	WRT_CHECK_U64(r.s->n_msgs_seen, 2);
	WRT_CHECK_U64(r.up.closed_err.a0, 2); /* (the sequence number the frame would have used minus one: where in the session it happened) */
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_message(&r.x, &r.c, &m)); /* and the connection stays gone */
	rig_free(&r);

	/* a keepalive is refused the same way */
	secure_ready(&r);
	r.slot->s.ops_limit = r.slot->s.tx_n.ops;
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_keepalive(&r.x, &r.c, 1, 2));
	check_nonce_end(&r);
	WRT_CHECK_U64(r.s->n_keepalive, 0);
	rig_free(&r);

	/* a two-operation frame with one operation left: refused before it is written, the first nonce already taken is of no consequence */
	secure_ready(&r);
	r.slot->s.ops_limit = r.slot->s.tx_n.ops + 1u;
	m = mk(0xa01, 9, front, sizeof(front), NULL, 0);
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_message(&r.x, &r.c, &m));
	check_nonce_end(&r);
	WRT_CHECK_U64(r.s->n_msgs_seen, 0);
	rig_free(&r);

	/* receive: ACK frames of the server are one operation each; the second after the limit is refused by the parser */
	secure_ready(&r);
	{
		uint8_t ack[8] = {1, 0, 0, 0, 0, 0, 0, 0};
		wri_m2_seg_src seg;
		int i;

		r.slot->s.ops_limit = r.slot->s.rx_n.ops + 1u;
		seg.p = ack, seg.len = 8, seg.ref = 0;
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_frame(r.s, WRI_M2_TAG_ACK, &seg, 1));
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		for (i = 0; i < 2; i++)
			WRT_CHECK_STATUS(WR_OK, sim_m2_send_frame(r.s, WRI_M2_TAG_ACK, &seg, 1));
		rig_pump(&r);
		rig_check_failed(&r, WR_E_M2_NONCE);
	}
	rig_free(&r);

	/* a message whose first operation is the last one allowed: the frame needs two, the parser refuses at the second, nothing is delivered */
	secure_ready(&r);
	r.slot->s.ops_limit = r.slot->s.rx_n.ops + 1u;
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0xa02, 1, 4, front, sizeof(front), NULL, 0, front, sizeof(front)));
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_NONCE);
	WRT_CHECK_U64(r.up.n_message, 0);
	rig_free(&r);
}

/* ---- 6b. the transmit key lost under a live connection ------------------------------------------------------------------------------ */

static void test_tx_key_lost(void)
{
	rig r;
	hostg h;
	wr_prim_ops t;
	uint8_t front[40], data[600];
	wri_m2_msg_out m;
	size_t before;
	int pass;

	fill(front, sizeof(front), 3);
	fill(data, sizeof(data), 5);
	for (pass = 0; pass < 3; pass++) {
		memset(&h, 0, sizeof(h));
		hg_table(&t, &h);
		secure_rig(&r);
		r.x.host.prim = &t;
		rig_start(&r);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(wri_pgcm_is_host(&r.slot->s.tx), 1); /* the host's GCM really is the one in use, in both directions */
		WRT_CHECK_U64(wri_pgcm_is_host(&r.slot->s.rx), 1);
		/* a frame with no failure first: the session works through the host */
		m = mk(0xb00, 1, front, sizeof(front), NULL, 0);
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
		rig_pump(&r);
		WRT_CHECK_U64(r.s->n_msgs_seen, 1);
		before = r.sent_len;
		/* pass 0: the first operation of the next frame is refused (a header-only message); pass 1: the second (a message with a front: the rest of
		 * the frame has already been sealed when it fails); pass 2: a keepalive */
		h.n_enc_starts = 0;
		h.fail_enc_start = pass == 1 ? 2u : 1u;
		if (pass == 2) {
			WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_keepalive(&r.x, &r.c, 1, 2));
		} else {
			m = pass == 0 ? mk(0xb01, 2, NULL, 0, NULL, 0) : mk(0xb02, 2, front, sizeof(front), data, sizeof(data));
			WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_message(&r.x, &r.c, &m));
		}
		/* the connection is over, not READY with a transmit side that can never send again; the owner hears of it at its next step */
		WRT_CHECK_U64(r.c.state, WRI_M2_FAILED);
		WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, r.c.err.status);
		WRT_CHECK_U64(r.up.n_closed, 0);
		WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), 0);
		WRT_CHECK(r.c.sec == NULL && r.c.rx.sx == NULL && r.c.tx.sx == NULL && rig_slot_zero(&r));
		(void)wri_m2_conn_step(&r.x, &r.c, NULL);
		rig_check_failed(&r, WR_E_CRYPTO_KEY);
		WRT_CHECK_U64(r.sent_len, before); /* nothing of the refused frame reached the wire */
		WRT_CHECK(h.wipes >= 2u);          /* the host's key objects were released */
		rig_free(&r);
	}

	/* the key is lost while bytes of an earlier frame are still queued: the host's next consume ends the connection (what a stream that cannot be refilled
	 * does inside the queue; here the loss is made by the test), and nothing more is sent */
	memset(&h, 0, sizeof(h));
	secure_ready(&r);
	m = mk(0xb03, 3, front, sizeof(front), data, sizeof(data));
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	wri_pgcm_wipe(&r.slot->s.tx);
	{
		wr_iov iov[WRI_M2_TXQ_IOV];
		size_t n = wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV);

		WRT_CHECK(n > 0 && iov[0].len > 0);
		wri_m2_conn_tx_consume(&r.c, 1);
	}
	WRT_CHECK_U64(r.c.state, WRI_M2_FAILED);
	WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), 0);
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	rig_check_failed(&r, WR_E_STATE);
	rig_free(&r);
}

/* The host refuses to set up a key at the switch (the first or the second direction): the connection fails with the host's status, nothing of the
 * secret survives (the slot, the bounce buffer and the auth layer's copy are zero), and the host's key object of the direction that did get one is
 * released. */
static void test_switch_host_refuses(void)
{
	rig r;
	hostg h;
	wr_prim_ops t;
	unsigned which;

	for (which = 1; which <= 2; which++) {
		memset(&h, 0, sizeof(h));
		h.fail_setkey = which;
		hg_table(&t, &h);
		secure_rig(&r);
		r.x.host.prim = &t;
		rig_start(&r);
		rig_pump(&r);
		rig_check_failed(&r, WR_E_CRYPTO_KEY);
		WRT_CHECK_U64(r.c.mode, 2); /* it did get as far as AUTH_DONE's mode */
		WRT_CHECK_U64(r.au.n_secret, 1);
		WRT_CHECK(r.au.n_wiped >= 1 || r.au.n_secret_drop >= 1);
		WRT_CHECK(rig_secret_absent(&r, r.s->sec.secret, r.s->sec.secret_len));
		WRT_CHECK_U64(r.s->n_msgs_seen, 0);
		WRT_CHECK_U64(h.wipes, which); /* the refused object is released (the host's contract), and the first direction's too when the second is refused */
		rig_free(&r);
	}
}

/* ---- 7. the real cephx machine: the secret's rules (34.3) ---------------------------------------------------------------------------- */

static void test_cephx_secret(void)
{
	unsigned kt, c;
	static const struct {
		const char *name;
		uint8_t offer;
		uint8_t srv_modes[2];
		int omit, in_crc;
		uint32_t secret_len;
		wr_status want; /* WR_OK = the connection comes up */
	} k[] = {
		{"no secret in secure mode", OFFER_SEC_ONLY, {2, 1}, 1, 0, 0, WR_E_M2_SECRET},
		{"secret of 39 bytes", OFFER_SEC_ONLY, {2, 1}, 0, 0, 39, WR_E_M2_SECRET},
		{"secret in crc mode", OFFER_CRC_ONLY, {1, 2}, 0, 1, 0, WR_E_AUTH_PROTO},
		{"secret of 128 bytes", OFFER_SEC_ONLY, {2, 1}, 0, 0, 128, WR_OK},
		{"secret of 40 bytes", OFFER_SEC_ONLY, {2, 1}, 0, 0, 40, WR_OK},
	};

	for (kt = WR_KEY_TYPE_AES; kt <= WR_KEY_TYPE_AES256K; kt++) {
		for (c = 0; c < sizeof(k) / sizeof(k[0]); c++) {
			cxw w;
			rig rm;

			WRT_CHECK_U64(cxw_init(&w, kt), 0);
			w.mcfg.m2.n_modes = 2;
			w.mcfg.m2.modes[0] = k[c].srv_modes[0], w.mcfg.m2.modes[1] = k[c].srv_modes[1];
			w.mcfg.m2.f.sec.omit_secret = (uint8_t)k[c].omit;
			w.mcfg.m2.f.sec.secret_in_crc = (uint8_t)k[c].in_crc;
			w.mcfg.m2.f.sec.secret_len = k[c].secret_len;
			WRT_CHECK_U64(cxw_start(&w), 0);
			rig_init(&rm);
			rig_enable_secure(&rm, k[c].offer);
			cxw_mon_rig(&w, &rm);
			rig_start(&rm);
			rig_pump(&rm);
			if (k[c].want == WR_OK) {
				WRT_CHECK_U64(rm.c.state, WRI_M2_READY);
				WRT_CHECK_U64(rm.c.mode, 2);
				WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_keepalive(&rm.x, &rm.c, 1, 2));
				rig_pump(&rm);
				WRT_CHECK_U64(rm.c.n_ka_ack, 1);
			} else {
				rig_check_failed(&rm, k[c].want);
				WRT_CHECK_U64(rm.up.n_ready, 0);
				WRT_CHECK_U64(rm.au.n_wiped, 0); /* (the real machine, not the stub, holds the secret) */
			}
			rig_free(&rm);
			cxw_free(&w);
		}
	}
	/* the OSD: an authorizer reply of version 1 (no secret) with secure mode negotiated */
	for (kt = WR_KEY_TYPE_AES; kt <= WR_KEY_TYPE_AES256K; kt++) {
		cxw w;
		rig rm, ro;

		WRT_CHECK_U64(cxw_init(&w, kt), 0);
		w.mcfg.m2.n_modes = 1, w.mcfg.m2.modes[0] = 1;
		w.ocfg.m2.n_modes = 2, w.ocfg.m2.modes[0] = 2, w.ocfg.m2.modes[1] = 1;
		w.ocfg.m2.f.sec.omit_secret = 1;
		WRT_CHECK_U64(cxw_start(&w), 0);
		rig_init(&rm);
		cxw_mon_rig(&w, &rm); /* the login, in crc: no slot */
		rig_start(&rm);
		rig_pump(&rm);
		WRT_CHECK_U64(rm.c.state, WRI_M2_READY);
		rig_init(&ro);
		rig_enable_secure(&ro, OFFER_SEC_ONLY);
		cxw_osd_rig(&w, &ro);
		rig_start(&ro);
		rig_pump(&ro);
		rig_check_failed(&ro, WR_E_M2_SECRET);
		wri_cx_hs_wipe(&w.hs);
		rig_free(&ro);
		rig_free(&rm);
		cxw_free(&w);
	}
}

/* ---- 8. the end of the connection, anywhere ------------------------------------------------------------------------------------------- */

static void test_ends(void)
{
	rig ref, r;
	size_t total, k;

	/* how many bytes the server writes up to READY in an untouched run */
	secure_ready(&ref);
	total = ref.rcvd_len;
	rig_free(&ref);
	WRT_CHECK(total > 300);
	for (k = 0; k <= total; k += (k < 40u || k + 40u > total) ? 1u : 3u) {
		int how;

		for (how = 0; how < 3; how++) {
			rig_init(&r);
			rig_enable_secure(&r, OFFER_BOTH);
			rig_server_modes(&r, 2, 1);
			r.scfg.f.out_limit = (int64_t)k; /* the server falls silent after k bytes */
			rig_start(&r);
			rig_pump(&r);
			if (how == 0) { /* the owner closes (a timeout above, a request to stop), then the transport reports the socket gone */
				wri_m2_conn_close(&r.x, &r.c, WR_E_TIMEOUT);
				WRT_CHECK(rig_slot_zero(&r));
				WRT_CHECK_U64(r.up.n_closed, 1);
				wri_m2_conn_close(&r.x, &r.c, WR_E_TIMEOUT); /* twice: nothing happens */
				wri_m2_conn_on_closed(&r.x, &r.c, 0);
				check_ended(&r, WR_E_TIMEOUT);
			} else if (how == 1) { /* the transport reports the loss first */
				wri_m2_conn_on_closed(&r.x, &r.c, 104);
				check_ended(&r, WR_E_NET_CLOSED);
				wri_m2_conn_on_closed(&r.x, &r.c, 104);
				WRT_CHECK_U64(r.up.n_closed, 1);
			} else { /* the connection is reopened on the same slot without the old life having ended: the old key is wiped by open() */
				wri_m2_preauth_init(&r.pa, r.pa_rx, r.pa_tx, r.pa_cap);
				wri_m2_conn_open(&r.c, 0x00010007u, r.role, &r.target, &r.dial, r.ops, r.ops_ctx, &up_ops, &r.up, &r.pa, r.nonce, r.gseq + 1u);
				WRT_CHECK(rig_slot_zero(&r));
				WRT_CHECK(r.c.rx.sx == NULL && r.c.tx.sx == NULL && r.c.sec == NULL);
			}
			rig_free(&r);
		}
	}

	/* in the middle of a stream: 200 KiB of data through a 256-byte bounce buffer, the host has taken some of it */
	{
		uint8_t *data = (uint8_t *)malloc(200000);
		uint8_t front[20];
		wri_m2_msg_out m;
		wr_iov iov[WRI_M2_TXQ_IOV];
		size_t n;

		fill(data, 200000, 7);
		fill(front, sizeof(front), 7);
		rig_init(&r);
		r.bounce_cap = 256;
		rig_enable_secure(&r, OFFER_BOTH);
		rig_server_modes(&r, 2, 1);
		rig_start(&r);
		rig_pump(&r);
		m = mk(0xb00, 1, front, sizeof(front), data, 200000);
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
		n = wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV);
		WRT_CHECK(n > 0);
		wri_m2_conn_tx_consume(&r.c, 1000); /* some of it is out, the rest is not even sealed yet */
		WRT_CHECK(r.c.tx.pending > 100000);
		WRT_CHECK(!rig_zero(r.bounce, r.bounce_cap)); /* the bounce buffer holds a piece of ciphertext */
		wri_m2_conn_close(&r.x, &r.c, WR_OK);
		WRT_CHECK(rig_slot_zero(&r)); /* ... and no longer does */
		WRT_CHECK_U64(r.c.tx.pending, 0);
		WRT_CHECK_U64(wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV), 0);
		wri_m2_conn_tx_consume(&r.c, 500); /* a late call of the host on a closed connection: nothing */
		check_ended(&r, WR_OK);
		rig_free(&r);
		free(data);
	}
}

/* The engine is destroyed with connections in every state: wri_m2_conn_wipe erases everything, calls nothing, and may be repeated. */
static void test_wipe(void)
{
	rig ref, r;
	size_t total, k;

	secure_ready(&ref);
	total = ref.rcvd_len;
	rig_free(&ref);
	for (k = 0; k <= total; k += (k < 40u || k + 40u > total) ? 1u : 5u) {
		secure_rig(&r);
		r.scfg.f.out_limit = (int64_t)k;
		rig_start(&r);
		rig_pump(&r);
		wri_m2_conn_wipe(&r.c);
		WRT_CHECK_U64(r.up.n_closed, 0); /* nobody is told */
		WRT_CHECK_U64(r.c.state, WRI_M2_FREE);
		WRT_CHECK(rig_slot_zero(&r));
		WRT_CHECK(r.c.sec == NULL && r.c.rx.sx == NULL && r.c.tx.sx == NULL && r.c.pa == NULL);
		WRT_CHECK_U64(r.au.hand_len, 0);
		WRT_CHECK(rig_zero(r.ring_buf, r.ring_cap) && rig_zero(r.ctl_buf, r.ctl_cap) && rig_zero(r.tx_buf, r.tx_cap));
		wri_m2_conn_wipe(&r.c); /* twice */
		wri_m2_conn_on_closed(&r.x, &r.c, 0);
		WRT_CHECK_U64(r.up.n_closed, 0);
		rig_free(&r);
	}
	/* a connection that was never opened, and NULL */
	wri_m2_conn_wipe(NULL);
	{
		wri_m2_conn c;

		memset(&c, 0, sizeof(c));
		wri_m2_conn_wipe(&c);
		WRT_CHECK_U64(c.state, WRI_M2_FREE);
	}
}

/* ---- 9. the handshake timeout, backpressure at the switch, a frame that can never fit ------------------------------------------------------ */

static void test_timeout(void)
{
	rig ref, r;
	rig_fr g[8];
	size_t used, ns, upto;

	/* the server's bytes up to and including AUTH_DONE in an untouched run */
	secure_ready(&ref);
	ns = rig_split(ref.rcvd + WRI_M2_BANNER_LEN, ref.rcvd_len - WRI_M2_BANNER_LEN, g, 8, &used);
	WRT_CHECK_U64(ns, 3);
	upto = WRI_M2_BANNER_LEN + g[0].total + g[1].total + g[2].total;
	rig_free(&ref);

	secure_rig(&r);
	r.scfg.f.out_limit = (int64_t)upto; /* silence after AUTH_DONE: the server's signature never comes */
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_SIG);
	WRT_CHECK(r.c.sec != NULL && r.slot->s.active == 1); /* switched, waiting for the signature */
	WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), 1000u + 8000u);
	r.x.now.mono_ms = 1000u + 8000u - 1u;
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	WRT_CHECK_U64(r.c.state, WRI_M2_SIG);
	r.x.now.mono_ms = 1000u + 8000u;
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	rig_check_failed(&r, WR_E_M2_HANDSHAKE_TIMEOUT);
	rig_free(&r);
}

/* The host does not consume what the connection queued: at AUTH_DONE the room for our signature (96 sealed bytes) is not there. The frame is held,
 * auth->done() is not called (it cannot be repeated), no nonce is taken; when the host drains, the switch happens exactly once. The identification
 * (192 sealed bytes) then cannot fit this encode buffer at all: WR_E_TOOBIG at once. */
static void backpressure_at_switch(uint32_t cap)
{
	rig r;
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t fed = 0, n, i, got;
	int guard = 0, stuck = 0;

	secure_rig(&r);
	r.tx_cap = cap; /* AUTH_REQUEST_MORE (80 bytes) stays queued: 70 (150) or 90 (170) are left; our crc signature would fit the second, the sealed one
			 * (96, +16 slack) fits neither: the room is judged by the framing of the mode just chosen */
	rig_start(&r);
	/* the host's loop by hand: everything the client writes is shown to the server and consumed, except from the moment AUTH_REQUEST_MORE is built */
	while (r.c.state != WRI_M2_SIG && r.up.n_closed == 0 && guard++ < 2000) {
		uint8_t *w = NULL;
		size_t room;

		n = wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV);
		if (r.c.auth_rounds == 1u && r.c.state == WRI_M2_AUTH) { /* show it to the server, do not consume: the queue keeps its bytes */
			size_t off = 0;

			for (i = 0; i < n; i++) {
				size_t skip = fed > off ? fed - off : 0;

				if (skip < iov[i].len) {
					(void)sim_m2_feed(r.s, iov[i].base + skip, iov[i].len - skip);
					fed += iov[i].len - skip;
				}
				off += iov[i].len;
			}
			stuck = 1;
		} else {
			for (i = 0; i < n; i++)
				(void)sim_m2_feed(r.s, iov[i].base, iov[i].len);
			for (i = 0; i < n; i++)
				wri_m2_conn_tx_consume(&r.c, iov[i].len);
		}
		room = wri_m2_conn_rx_window(&r.c, &w);
		if (room != 0 && w != NULL && sim_m2_pending(r.s) != 0) {
			got = sim_m2_drain(r.s, w, room);
			memcpy(r.rcvd + r.rcvd_len, w, got);
			r.rcvd_len += got;
			wri_m2_conn_rx_commit(&r.c, got);
		}
		(void)wri_m2_conn_step(&r.x, &r.c, NULL);
		if (stuck && r.c.stalled)
			break; /* held at AUTH_DONE for room */
	}
	WRT_CHECK_U64(r.c.state, WRI_M2_AUTH);
	WRT_CHECK(r.c.stalled);
	WRT_CHECK_U64(r.au.n_done, 0); /* the step that cannot be repeated has not run */
	WRT_CHECK_U64(r.au.n_secret, 0);
	WRT_CHECK(r.c.sec != NULL && r.slot->s.active == 0 && r.c.tx.sx == NULL && r.c.rx.sx == NULL);
	WRT_CHECK_U64(r.up.n_closed, 0);
	WRT_CHECK(wri_m2_conn_deadline(&r.c) != WR_DEADLINE_NONE);
	/* the host drains: the retry goes through and switches, once */
	wri_m2_conn_tx_consume(&r.c, (size_t)r.c.tx.pending);
	WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), 0); /* the consume woke the stalled connection */
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);     /* the retry: done() runs now, the switch, our signature is queued */
	rig_pump(&r);
	WRT_CHECK_U64(r.au.n_done, 1);
	WRT_CHECK_U64(r.au.n_secret, 1);
	rig_check_failed(&r, WR_E_TOOBIG); /* CLIENT_IDENT: the largest sealed identification (224 bytes) in a 150- or 170-byte encode buffer */
	rig_free(&r);
}

static void test_backpressure_at_switch(void)
{
	backpressure_at_switch(150);
	backpressure_at_switch(170);
}

/* A secure frame that can never fit the encode buffer: WR_E_TOOBIG at once (not a wait that ends in the timeout). The room for CLIENT_IDENT is judged for
 * the largest identification (IPv6): 196 bytes in crc framing, 224 sealed. An encode buffer of 210 bytes is enough in crc mode and not in secure mode. */
static void test_toobig(void)
{
	rig r;

	secure_rig(&r);
	r.tx_cap = 180;
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_TOOBIG);
	WRT_CHECK_U64(r.up.n_ready, 0);
	rig_free(&r);

	secure_rig(&r);
	r.tx_cap = 210;
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_TOOBIG);
	WRT_CHECK_U64(r.up.n_ready, 0);
	rig_free(&r);

	rig_init(&r); /* no slot: the same buffer is fine for crc */
	r.tx_cap = 210;
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	rig_free(&r);
}

/* BUSY at CLIENT_IDENT: the server's signature arrives, the signature frame of ours is still unconsumed and the identification does not fit next to
 * it: the comparison is repeatable, nothing is wiped, no nonce taken; the retry after the host drained completes. */
static void test_backpressure_at_ident(void)
{
	rig r;
	uint8_t *buf = NULL, mine[96];
	size_t n = 0;

	secure_rig(&r);
	r.tx_cap = 256;
	rig_start(&r);
	rig_stage_done_and_sig(&r, &buf, &n, mine);
	rig_inject(&r, buf, n); /* the switch, our signature queued (96), then the server's signature: the identification (192) does not fit next to it */
	free(buf);
	WRT_CHECK_U64(r.c.state, WRI_M2_SIG);
	WRT_CHECK(r.c.stalled);
	WRT_CHECK_U64(r.slot->s.tx_n.ops, 1); /* only the signature has taken a nonce */
	WRT_CHECK(r.c.pa != NULL);            /* the transcripts are still there: the comparison will be repeated */
	WRT_CHECK_U64(r.up.n_closed, 0);
	r.skip_tx = 96; /* the server already has our signature (the test sent it) */
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.slot->s.tx_n.ops, 3);
	WRT_CHECK(r.c.pa == NULL);
	rig_free(&r);
}

/* A lowered limit never lets a handshake frame through under a refused nonce: set before the first sealed frame is built (the signature),
 * through the slot of a connection that is about to switch. The switch re-keys the slot from zero, so this is only observable as the same
 * behaviour as with the default: the handshake completes. (The limit applies to a slot after the switch: see test_limit.) */
static void test_limit_is_per_connection(void)
{
	rig r;

	secure_rig(&r);
	rig_start(&r);
	r.slot->s.ops_limit = 1; /* before the switch: wri_m2_secure_on starts the slot from zero and sets the default limit */
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.slot->s.ops_limit, WRI_M2S_OPS_LIMIT_DEFAULT);
	rig_free(&r);
}

/* ---- main --------------------------------------------------------------------------------------------------------------------------- */

#define RUN(fn)                                                       \
	do {                                                          \
		if (argc < 2 || strstr(#fn, argv[1]) != NULL) {       \
			fprintf(stderr, "-- %s\n", #fn);               \
			fn();                                         \
		}                                                     \
	} while (0)

int main(int argc, char **argv)
{
	RUN(test_signature);
	RUN(test_defective_frames);
	RUN(test_wrong_keys);
	RUN(test_truncation);
	RUN(test_compressed_crc);
	RUN(test_compression_frames);
	RUN(test_downgrade);
	RUN(test_limit);
	RUN(test_tx_key_lost);
	RUN(test_switch_host_refuses);
	RUN(test_cephx_secret);
	RUN(test_ends);
	RUN(test_wipe);
	RUN(test_timeout);
	RUN(test_backpressure_at_switch);
	RUN(test_toobig);
	RUN(test_backpressure_at_ident);
	RUN(test_limit_is_per_connection);
	return wrt_finish();
}
