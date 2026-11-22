/* SPDX-License-Identifier: MIT */
/*
 * m2-conn-sec, handshake half (docs/design/core-architecture.md 34.2 to 34.4): wri_m2_conn with a secure slot, from the banner to READY, against
 * the secure peer of sim_m2.h (written from the notes with its own codec) and against the fake monitor and OSD with the real cephx machine.
 *
 *   - wri_m2_conn_set_secure: every refusal and what a good call leaves in the slot;
 *   - what AUTH_REQUEST offers, byte by byte, for the five policies and both peer kinds, and what a connection without a slot offers (crc only);
 *   - the mode matrix: every policy x every allowed list of the server (crc / secure / both in either order), for a monitor and an OSD:
 *     the chosen mode, or AUTH_BAD_METHOD with the server's allowed modes in errinfo a1;
 *   - AUTH_DONE with a mode that was not offered (crc after a secure-only offer, secure after crc only, garbage values): WR_E_M2_MODE, and
 *     auth->done() is never called;
 *   - the secret: no conn_secret member, none handed out, 39 / 129 bytes, equal nonce seeds: WR_E_M2_SECRET; never on the wire, never in an
 *     error record, the auth layer's copy wiped; conn_secret is asked after done() and before the session key;
 *   - a full secure handshake read back by the INDEPENDENT decoder of the simulator: our AUTH_SIGNATURE (HMAC over exactly the crc bytes) and
 *     CLIENT_IDENT as sealed frames with the right nonces; the same bytes whatever the chunking of the host's reads and writes, down to one byte
 *     at a time across the switch;
 *   - the signature frame of the server already in the receive ring behind AUTH_DONE: read as secure (and, damaged, refused as a tag failure, not
 *     as a crc error: it was never taken for a crc frame);
 *   - the real cephx machine against sim_mon and sim_osd, key types 1 and 2, crc and secure, a monitor login and an OSD session on top of it.
 * The failure side (tag, signature, nonce limit, faults of the peer) is in test_m2_conn_sec_fail.c, the session in test_m2_conn_sec_msgs.c.
 */
#include "m2_conn_msgs.h"
#include "m2_conn_sec_cx.h"
#include "wri_le.h"

#define OFFER_CRC WRI_M2_OFFER_CRC
#define OFFER_SEC WRI_M2_OFFER_SECURE
#define OFFER_SEC_FIRST WRI_M2_OFFER_SECURE_FIRST
#define OFFER_BOTH (OFFER_CRC | OFFER_SEC)

static const uint8_t SERVER_LISTS[4][2] = {{1, 0}, {2, 0}, {1, 2}, {2, 1}}; /* the server's allowed modes, in its order (0 = none) */

/* ---- 1. set_secure ----------------------------------------------------------------------------------------------- */

static void test_set_secure_api(void)
{
	rig r;
	wri_m2s_slot slot, slot2, zero;
	uint8_t bounce[4096], bounce2[256];
	size_t i;
	static const uint16_t bad_caps[] = {0, 1, 15, 16, 255, 257, 264, 4095};

	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_set_secure(NULL, OFFER_CRC, &slot, bounce, sizeof(bounce)));

	rig_init(&r);
	r.hold_connect = 1;
	rig_start(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_CONNECTING);
	WRT_CHECK(r.c.sec == NULL);
	memset(&slot, 0xab, sizeof(slot));
	/* shape errors: nothing is touched, the connection keeps offering crc */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_set_secure(&r.c, 0x08u, &slot, bounce, sizeof(bounce)));          /* a bit nobody defined */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_set_secure(&r.c, 0x80u | OFFER_CRC, &slot, bounce, sizeof(bounce)));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_set_secure(&r.c, OFFER_SEC_FIRST, &slot, bounce, sizeof(bounce))); /* offers nothing */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_set_secure(&r.c, OFFER_SEC, NULL, bounce, sizeof(bounce)));       /* secure needs a slot */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_set_secure(&r.c, OFFER_BOTH, NULL, NULL, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_set_secure(&r.c, OFFER_BOTH, &slot, NULL, sizeof(bounce)));         /* ... and a bounce buffer */
	for (i = 0; i < sizeof(bad_caps) / sizeof(bad_caps[0]); i++)
		WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_set_secure(&r.c, OFFER_SEC, &slot, bounce, bad_caps[i]));
	WRT_CHECK(r.c.sec == NULL);
	{
		uint8_t pat[sizeof(slot)];

		memset(pat, 0xab, sizeof(pat));
		WRT_CHECK(memcmp(&slot, pat, sizeof(pat)) == 0); /* the refused calls did not touch the slot */
	}
	WRT_CHECK_U64(wri_m2c_offer(&r.c), OFFER_CRC);

	/* the smallest bounce buffer, and a bigger one */
	memset(&slot, 0xab, sizeof(slot));
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_set_secure(&r.c, OFFER_BOTH | OFFER_SEC_FIRST, &slot, bounce2, sizeof(bounce2)));
	WRT_CHECK(r.c.sec == &slot);
	memset(&zero, 0, sizeof(zero));
	zero.offer = OFFER_BOTH | OFFER_SEC_FIRST;
	zero.tx.bounce = bounce2;
	zero.tx.bounce_cap = sizeof(bounce2);
	WRT_CHECK(memcmp(&slot, &zero, sizeof(slot)) == 0); /* what the host left in the slot is gone: zero but the offer and the bounce buffer */
	WRT_CHECK_U64(wri_m2c_offer(&r.c), OFFER_BOTH | OFFER_SEC_FIRST);

	/* a second call (before the TCP connection is reported) replaces the slot and erases the first one */
	memset(&slot2, 0xcd, sizeof(slot2));
	memset(bounce2, 0x77, sizeof(bounce2));
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_set_secure(&r.c, OFFER_SEC, &slot2, bounce, sizeof(bounce)));
	WRT_CHECK(r.c.sec == &slot2);
	WRT_CHECK(rig_zero(&slot, sizeof(slot)));
	WRT_CHECK(rig_zero(bounce2, sizeof(bounce2)));
	WRT_CHECK_U64(wri_m2c_offer(&r.c), OFFER_SEC);

	/* offer 0 with a slot: crc only; offer 0 without: crc only, the slot pointer cleared */
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_set_secure(&r.c, 0, &slot, NULL, 0));
	WRT_CHECK(r.c.sec == &slot && slot.offer == 0 && slot.tx.bounce == NULL);
	WRT_CHECK_U64(wri_m2c_offer(&r.c), OFFER_CRC);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_set_secure(&r.c, OFFER_CRC, &slot, bounce, sizeof(bounce))); /* crc only needs no bounce size rules... */
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_set_secure(&r.c, 0, NULL, NULL, 0));
	WRT_CHECK(r.c.sec == NULL && rig_zero(&slot, sizeof(slot)) && rig_zero(&slot2, sizeof(slot2)));
	WRT_CHECK_U64(wri_m2c_offer(&r.c), OFFER_CRC);

	/* the TCP connection is reported: too late */
	wri_m2_conn_on_connected(&r.x, &r.c);
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_set_secure(&r.c, OFFER_CRC, &slot, bounce, sizeof(bounce)));
	WRT_CHECK(r.c.sec == NULL);
	rig_free(&r);

	/* an open() that was refused leaves the connection FAILED: WR_E_STATE as well */
	rig_init(&r);
	r.role = 0; /* not a monitor, not an OSD */
	rig_start(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_FAILED);
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_set_secure(&r.c, OFFER_CRC, &slot, bounce, sizeof(bounce)));
	rig_free(&r);
}

/* ---- 2. what AUTH_REQUEST offers --------------------------------------------------------------------------------- */

/* The offer lists of docs/design/core-architecture.md 34.2, written out here and not taken from wri_m2_offer_for. */
static unsigned expected_list(unsigned policy, unsigned role_mon, uint32_t out[2])
{
	switch (policy) {
	case WR_MODE_CRC_ONLY:
		out[0] = 1;
		return 1;
	case WR_MODE_CRC_FIRST:
		out[0] = 1, out[1] = 2;
		return 2;
	case WR_MODE_SECURE_FIRST:
		out[0] = 2, out[1] = 1;
		return 2;
	case WR_MODE_SECURE_ONLY:
		out[0] = 2;
		return 1;
	default: /* WR_MODE_STOCK: a monitor secure first, anything else crc first */
		out[0] = role_mon ? 2u : 1u, out[1] = role_mon ? 1u : 2u;
		return 2;
	}
}

static void setup_role(rig *r, unsigned role_mon)
{
	r->role = role_mon ? WRI_ENTITY_MON : WRI_ENTITY_OSD;
	r->scfg.entity_type = role_mon ? SIM_M2_ENT_MON : SIM_M2_ENT_OSD;
}

static void check_auth_request(const rig *r, const uint32_t *want, unsigned nwant)
{
	rig_fr f[8];
	size_t used, n, i;
	const uint8_t *p;

	WRT_CHECK(r->sent_len > WRI_M2_BANNER_LEN);
	n = rig_split(r->sent + WRI_M2_BANNER_LEN, r->sent_len - WRI_M2_BANNER_LEN, f, 8, &used);
	WRT_CHECK(n >= 2);
	if (n < 2)
		return;
	WRT_CHECK_U64(f[1].tag, WRI_M2_TAG_AUTH_REQUEST);
	p = f[1].seg[0];
	WRT_CHECK_U64(f[1].len[0], 4u + 4u + 4u * nwant + 4u + 24u);
	WRT_CHECK_U64(wri_le32_get(p), 2); /* cephx */
	WRT_CHECK_U64(wri_le32_get(p + 4), nwant);
	for (i = 0; i < nwant; i++)
		WRT_CHECK_U64(wri_le32_get(p + 8 + 4 * i), want[i]);
	WRT_CHECK_U64(wri_le32_get(p + 8 + 4 * nwant), 24); /* the payload length is patched behind the (variable) list */
	for (i = 0; i < 24; i++)
		WRT_CHECK_U64(p[12 + 4 * nwant + i], 0x41);
}

static void test_offer_bytes(void)
{
	unsigned policy, role_mon;
	rig r;
	uint32_t want[2], one = 1;

	/* a connection without a slot: crc only, byte for byte what part A wrote */
	for (role_mon = 0; role_mon < 2; role_mon++) {
		rig_init(&r);
		setup_role(&r, role_mon);
		rig_start(&r);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.c.mode, WRI_CONN_MODE_CRC);
		check_auth_request(&r, &one, 1);
		rig_free(&r);

		/* a slot that offers crc only (or nothing): the same bytes, and the slot is never switched */
		rig_init(&r);
		setup_role(&r, role_mon);
		rig_enable_secure(&r, OFFER_CRC);
		rig_start(&r);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		check_auth_request(&r, &one, 1);
		WRT_CHECK(r.slot->s.active == 0 && r.c.rx.sx == NULL && r.c.tx.sx == NULL);
		rig_free(&r);
	}
	for (policy = WR_MODE_CRC_ONLY; policy <= WR_MODE_STOCK; policy++) {
		for (role_mon = 0; role_mon < 2; role_mon++) {
			unsigned nwant = expected_list(policy, role_mon, want);
			uint8_t offer = wri_m2_offer_for((uint8_t)policy, 0, role_mon ? WRI_ENTITY_MON : WRI_ENTITY_OSD);

			rig_init(&r);
			setup_role(&r, role_mon);
			rig_enable_secure(&r, offer);
			rig_start(&r);
			rig_pump(&r);
			WRT_CHECK_STATUS(WR_OK, r.set_secure_st);
			check_auth_request(&r, want, nwant);
			/* the server allows both: it takes the first of our list */
			WRT_CHECK_U64(r.c.state, WRI_M2_READY);
			WRT_CHECK_U64(r.c.mode, want[0]);
			WRT_CHECK_U64(sim_m2_is_secure(r.s), want[0] == 2u);
			rig_free(&r);
		}
	}
}

/* ---- 3. the mode matrix ------------------------------------------------------------------------------------------ */

static void run_matrix_case(unsigned policy, unsigned role_mon, unsigned lst, int with_slot)
{
	rig r;
	uint32_t want[2], chosen = 0;
	unsigned nwant = expected_list(with_slot ? policy : WR_MODE_CRC_ONLY, role_mon, want), i, j;
	uint8_t offer = with_slot ? wri_m2_offer_for((uint8_t)policy, 0, role_mon ? WRI_ENTITY_MON : WRI_ENTITY_OSD) : 0;
	uint32_t smask = 0;

	for (j = 0; j < 2; j++)
		if (SERVER_LISTS[lst][j] != 0)
			smask |= 1u << SERVER_LISTS[lst][j];
	for (i = 0; i < nwant && chosen == 0; i++)
		for (j = 0; j < 2; j++)
			if (SERVER_LISTS[lst][j] == want[i] && chosen == 0)
				chosen = want[i];
	rig_init(&r);
	setup_role(&r, role_mon);
	if (with_slot)
		rig_enable_secure(&r, offer);
	rig_server_modes(&r, SERVER_LISTS[lst][0], SERVER_LISTS[lst][1]);
	rig_start(&r);
	rig_pump(&r);
	if (chosen == 0) { /* the server allows none of what we offered: AUTH_BAD_METHOD, the connection fails, nothing was switched */
		rig_check_failed(&r, WR_E_M2_BAD_METHOD);
		WRT_CHECK_U64(r.c.err.peer_result, -95); /* -EOPNOTSUPP */
		WRT_CHECK_U64(r.c.err.a0, 1u << 2);      /* the server allows method 2 (cephx) */
		WRT_CHECK_U64(r.c.err.a1, smask);        /* ... and these modes: which side's setting to change */
		WRT_CHECK_U64(r.c.err.a2, 2);            /* the method we offered */
		WRT_CHECK_U64(r.au.n_done, 0);
		WRT_CHECK_U64(r.au.n_secret, 0);
	} else {
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.up.n_closed, 0);
		WRT_CHECK_U64(r.c.mode, chosen);
		WRT_CHECK_U64(r.s->conn_mode, chosen);
		WRT_CHECK_U64(r.au.done_mode, chosen);
		WRT_CHECK_U64(sim_m2_is_secure(r.s), chosen == 2u);
		WRT_CHECK_U64(r.au.n_secret, chosen == 2u ? 1 : 0); /* asked for the secret only when the mode needs one */
		WRT_CHECK_U64(r.au.hand_len, 0);
		if (with_slot) {
			WRT_CHECK_U64(r.slot->s.active, chosen == 2u);
			WRT_CHECK_U64(r.c.rx.sx != NULL, chosen == 2u);
			WRT_CHECK_U64(r.c.tx.sx != NULL, chosen == 2u);
			WRT_CHECK_U64(r.slot->offer, offer);
		}
		/* both framings carry a session: a keepalive and its answer */
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_keepalive(&r.x, &r.c, 11, 22));
		rig_pump(&r);
		WRT_CHECK_U64(r.c.n_ka_ack, 1);
		WRT_CHECK_U64(r.c.ka_ack_sec, 11);
		WRT_CHECK_U64(r.c.ka_ack_nsec, 22);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		/* the end of the connection wipes the slot, in either mode */
		wri_m2_conn_close(&r.x, &r.c, WR_OK);
		if (with_slot)
			WRT_CHECK(rig_slot_zero(&r));
		WRT_CHECK(r.c.rx.sx == NULL && r.c.tx.sx == NULL);
	}
	rig_free(&r);
}

static void test_mode_matrix(void)
{
	unsigned policy, role_mon, lst;

	for (role_mon = 0; role_mon < 2; role_mon++) {
		for (lst = 0; lst < 4; lst++) {
			run_matrix_case(WR_MODE_CRC_ONLY, role_mon, lst, 0); /* no slot: crc only whatever the server prefers */
			for (policy = WR_MODE_CRC_ONLY; policy <= WR_MODE_STOCK; policy++)
				run_matrix_case(policy, role_mon, lst, 1);
		}
	}
}

/* ---- 4. AUTH_DONE with a mode we did not offer -------------------------------------------------------------------- */

static void test_done_mode_not_offered(void)
{
	static const struct {
		int with_slot;
		uint8_t offer;
		uint32_t srv_first;  /* server's allowed list head: what it negotiates */
		uint32_t done_mode;  /* what AUTH_DONE says instead */
	} k[] = {
		{1, OFFER_CRC, 1, 2},                /* we offered crc only, the server answers secure */
		{0, 0, 1, 2},                        /* a connection without a slot: the same, as before part D */
		{1, OFFER_SEC, 2, 1},                /* we offered secure only, the server answers crc */
		{1, OFFER_BOTH, 1, 3},               /* a mode that does not exist */
		{1, OFFER_BOTH, 2, 0x80000001u},
		{1, OFFER_CRC, 1, 0},                /* 0 in the sim means "the negotiated one": a valid answer, see below */
	};
	size_t i;

	for (i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
		rig r;
		uint8_t offered;

		rig_init(&r);
		if (k[i].with_slot)
			rig_enable_secure(&r, k[i].offer);
		rig_server_modes(&r, k[i].srv_first, k[i].srv_first == 1u ? 2u : 1u);
		r.scfg.f.done_mode = k[i].done_mode;
		rig_start(&r);
		rig_pump(&r);
		offered = k[i].with_slot ? k[i].offer : OFFER_CRC;
		if (k[i].done_mode == 0) { /* control: no override, the handshake simply succeeds */
			WRT_CHECK_U64(r.c.state, WRI_M2_READY);
			rig_free(&r);
			continue;
		}
		rig_check_failed(&r, WR_E_M2_MODE);
		WRT_CHECK_U64(r.c.err.a0, k[i].done_mode);
		WRT_CHECK_U64(r.c.err.a1, offered); /* our offer mask */
		WRT_CHECK_U64(r.au.n_done, 0);       /* the answer was refused before the auth layer saw it */
		WRT_CHECK_U64(r.au.n_secret, 0);
		WRT_CHECK(r.c.rx.sx == NULL && r.c.tx.sx == NULL);
		rig_free(&r);
	}
}

/* ---- 5. the secret ------------------------------------------------------------------------------------------------- */

static void secure_rig(rig *r, uint8_t offer)
{
	rig_init(r);
	rig_enable_secure(r, offer);
	rig_server_modes(r, 2, 1); /* the server picks secure */
}

static void test_secret_cases(void)
{
	rig r;
	uint8_t sec[256];
	size_t i;

	/* the auth has no conn_secret member: refused before done() consumed anything */
	secure_rig(&r, OFFER_SEC);
	r.ops = &stub_ops;
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_SECRET);
	WRT_CHECK_U64(r.au.n_done, 0);
	rig_free(&r);

	/* a member that hands out nothing */
	secure_rig(&r, OFFER_SEC);
	r.au.secret_kind = STUB_SECRET_NONE;
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_SECRET);
	WRT_CHECK_U64(r.au.n_done, 1);
	WRT_CHECK_U64(r.au.n_secret, 1);
	rig_free(&r);

	/* usable and unusable lengths */
	for (i = 0; i < sizeof(sec); i++)
		sec[i] = (uint8_t)(0x30u + i * 5u);
	{
		static const size_t lens[] = {1, 16, 39, 129, 130, 200};
		size_t k;

		for (k = 0; k < sizeof(lens) / sizeof(lens[0]); k++) {
			secure_rig(&r, OFFER_SEC);
			r.au.secret_kind = STUB_SECRET_FIXED;
			memcpy(r.au.secret, sec, lens[k]);
			r.au.secret_len = lens[k];
			rig_start(&r);
			rig_pump(&r);
			rig_check_failed(&r, WR_E_M2_SECRET);
			WRT_CHECK_U64(r.au.n_secret, 1);
			WRT_CHECK(rig_secret_absent(&r, sec, lens[k]));
			WRT_CHECK(r.au.n_wiped >= 1 || r.au.n_secret_drop >= 1); /* the auth layer was told to forget it */
			rig_free(&r);
		}
	}
	/* equal nonce seeds: both directions would share a nonce stream */
	secure_rig(&r, OFFER_SEC);
	r.au.secret_kind = STUB_SECRET_FIXED;
	memcpy(r.au.secret, sec, 64);
	memcpy(r.au.secret + 28, r.au.secret + 16, 12); /* seed B := seed A */
	r.au.secret_len = 64;
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_SECRET);
	WRT_CHECK(rig_secret_absent(&r, r.au.secret, 64));
	rig_free(&r);

	/* crc negotiated: the connection never asks for a secret, and the slot is never keyed */
	rig_init(&r);
	rig_enable_secure(&r, OFFER_BOTH);
	rig_server_modes(&r, 1, 2);
	r.au.secret_kind = STUB_SECRET_FIXED; /* a provider that would hand one out: it must not be asked */
	memcpy(r.au.secret, sec, 64);
	r.au.secret_len = 64;
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.c.mode, 1);
	WRT_CHECK_U64(r.au.n_secret, 0);
	WRT_CHECK(r.slot->s.active == 0 && r.slot->offer == OFFER_BOTH);
	rig_free(&r);

	/* a good secret: asked after done() and before the session key, wiped in the auth layer once the key schedule exists, never on the wire */
	secure_rig(&r, OFFER_BOTH | OFFER_SEC_FIRST);
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.au.n_secret, 1);
	WRT_CHECK(r.au.seq_done != 0 && r.au.seq_done < r.au.seq_secret && r.au.seq_secret < r.au.seq_key);
	WRT_CHECK_U64(r.au.hand_len, 0);
	WRT_CHECK(r.au.n_wiped >= 1 || r.au.n_secret_drop >= 1);
	WRT_CHECK(rig_secret_absent(&r, r.s->sec.secret, r.s->sec.secret_len));
	rig_free(&r);
}

/* ---- 6. a secure handshake, read back by the independent decoder ---------------------------------------------------- */

static size_t stream_off(const rig_fr *f, size_t n)
{
	size_t i, off = 0;

	for (i = 0; i < n; i++)
		off += f[i].total;
	return off;
}

/* Everything the client wrote after the three crc frames is sealed frames; everything the server wrote after AUTH_DONE as well. `ops_c` / `ops_s`
 * get the GCM operations the decoder counted in each direction (the connection's nonce counters must say the same). */
static void check_secure_handshake_bytes(rig *r, size_t sent_extra_frames, unsigned *ops_c, unsigned *ops_s)
{
	rig_fr f[8], g[8];
	size_t cused, sused, nc, ns, nf, mf = 0, i;
	rig_sframe cf[8], sf[8];
	wr_status e1 = WR_OK, e2 = WR_OK;
	uint8_t sig[32], secret[64];
	tb t;

	*ops_c = *ops_s = 0;
	WRT_CHECK_U64(r->s->sec.secret_len, 64);
	memcpy(secret, r->s->sec.secret, 64);
	/* client -> server: the banner and three crc frames, then sealed frames (the signature, CLIENT_IDENT, whatever the session wrote) */
	nc = rig_split(r->sent + WRI_M2_BANNER_LEN, r->sent_len - WRI_M2_BANNER_LEN, f, 8, &cused);
	WRT_CHECK_U64(nc, 3);
	if (nc != 3)
		return;
	WRT_CHECK_U64(f[0].tag, WRI_M2_TAG_HELLO);
	WRT_CHECK_U64(f[1].tag, WRI_M2_TAG_AUTH_REQUEST);
	WRT_CHECK_U64(f[2].tag, WRI_M2_TAG_AUTH_REQUEST_MORE);
	nf = rig_decode_secure(secret, 64, 1, r->sent + WRI_M2_BANNER_LEN + cused, r->sent_len - WRI_M2_BANNER_LEN - cused, cf, 8, &e1);
	WRT_CHECK_STATUS(WR_OK, e1); /* every tag verified, in the nonce order of the notes, under the crossed seeds */
	WRT_CHECK_U64(nf, 2 + sent_extra_frames);
	for (i = 0; i < nf; i++)
		*ops_c += cf[i].ops;
	ns = rig_split(r->rcvd + WRI_M2_BANNER_LEN, r->rcvd_len - WRI_M2_BANNER_LEN, g, 8, &sused);
	WRT_CHECK_U64(ns, 3); /* HELLO, REPLY_MORE, DONE: then the server's sealed frames */
	if (ns == 3) {
		WRT_CHECK_U64(g[2].tag, WRI_M2_TAG_AUTH_DONE);
		mf = rig_decode_secure(secret, 64, 0, r->rcvd + WRI_M2_BANNER_LEN + sused, r->rcvd_len - WRI_M2_BANNER_LEN - sused, sf, 8, &e2);
		WRT_CHECK_STATUS(WR_OK, e2);
		for (i = 0; i < mf; i++)
			*ops_s += sf[i].ops;
		if (nf >= 2) {
			/* our AUTH_SIGNATURE: HMAC-SHA256 under the session key over exactly the crc bytes the server sent up to AUTH_DONE */
			tc_hmac(TC_KEY, 32, r->rcvd, WRI_M2_BANNER_LEN + stream_off(g, 3), sig);
			WRT_CHECK_U64(cf[0].tag, WRI_M2_TAG_AUTH_SIGNATURE);
			WRT_CHECK_U64(cf[0].nseg, 1);
			WRT_CHECK_U64(cf[0].len[0], 32);
			WRT_CHECK_U64(cf[0].ops, 1);
			WRT_CHECK_U64(cf[0].wire, 96);
			if (cf[0].len[0] == 32)
				WRT_CHECK_MEM(cf[0].seg[0], sig, 32);
		}
		WRT_CHECK(mf >= 2);
		if (mf >= 2) {
			/* the server's signature, which the client verified, is over what WE wrote in the clear */
			WRT_CHECK_U64(sf[0].tag, WRI_M2_TAG_AUTH_SIGNATURE);
			tc_hmac(TC_KEY, 32, r->sent, WRI_M2_BANNER_LEN + stream_off(f, 3), sig);
			if (sf[0].len[0] == 32)
				WRT_CHECK_MEM(sf[0].seg[0], sig, 32);
			WRT_CHECK_U64(sf[1].tag, WRI_M2_TAG_SERVER_IDENT);
		}
	}
	if (nf >= 2) {
		/* CLIENT_IDENT, field for field as in crc mode, now a two-operation frame (123 bytes: part 1 and part 2) */
		tc_pay_ident(&t, 0x3f07fffffffdffffull, r->gseq, r->nonce);
		WRT_CHECK_U64(cf[1].tag, WRI_M2_TAG_CLIENT_IDENT);
		WRT_CHECK_U64(cf[1].len[0], t.n);
		WRT_CHECK_U64(cf[1].ops, t.n > 48u ? 2u : 1u);
		if (cf[1].len[0] == t.n)
			WRT_CHECK_MEM(cf[1].seg[0], t.b, t.n);
	}
	rig_sframes_free(sf, mf);
	rig_sframes_free(cf, nf);
}

static void test_secure_handshake_bytes(void)
{
	rig r;

	secure_rig(&r, OFFER_BOTH | OFFER_SEC_FIRST);
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.c.mode, WRI_CONN_MODE_SECURE);
	WRT_CHECK(r.c.pa == NULL); /* the handshake slot is released as in crc mode */
	WRT_CHECK_U64(r.c.global_id, 4242);
	WRT_CHECK_U64(r.up.n_ready, 1);
	WRT_CHECK_U64(r.s->state, SIM_M2_ST_READY);
	WRT_CHECK_U64(sim_m2_error(r.s)->status, 0);
	WRT_CHECK(r.slot->s.active == 1 && r.c.rx.sx == &r.slot->rx && r.c.tx.sx == &r.slot->tx);
	WRT_CHECK(r.slot->tx.bounce == r.bounce && r.slot->tx.bounce_cap == r.bounce_cap);
	WRT_CHECK_U64(r.s->sec.n_rx_frames, 2); /* the server read exactly two sealed frames: AUTH_SIGNATURE and CLIENT_IDENT */
	WRT_CHECK_U64(r.s->sec.n_tx_frames, 2); /* and sent two: AUTH_SIGNATURE and SERVER_IDENT */
	{
		unsigned oc, os;

		check_secure_handshake_bytes(&r, 0, &oc, &os);
		/* one nonce per GCM operation, in wire order: the counters of the connection are the operations the independent decoder counted */
		WRT_CHECK_U64(r.slot->s.tx_n.ops, oc);
		WRT_CHECK_U64(r.slot->s.rx_n.ops, os);
		WRT_CHECK(oc >= 3 && os >= 2);
	}
	rig_free(&r);
}

/* ---- 7. every chunking of the host, down to one byte at a time ------------------------------------------------------ */

static void test_chunking_across_switch(void)
{
	static const size_t chunks[][2] = {{0, 0}, {1, 0}, {0, 1}, {1, 1}, {2, 3}, {7, 16}, {95, 96}, {96, 97}, {5, 4096}};
	uint8_t *ref = NULL;
	size_t ref_len = 0, i;

	for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
		rig r;

		secure_rig(&r, OFFER_BOTH | OFFER_SEC_FIRST);
		r.tx_chunk = chunks[i][0];
		r.rx_chunk = chunks[i][1];
		rig_start(&r);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.c.mode, 2);
		WRT_CHECK_U64(sim_m2_is_secure(r.s), 1);
		WRT_CHECK_U64(r.s->state, SIM_M2_ST_READY);
		if (ref == NULL) {
			ref = (uint8_t *)malloc(r.sent_len);
			memcpy(ref, r.sent, r.sent_len);
			ref_len = r.sent_len;
		} else {
			/* the sealed bytes are a function of the secret and the frames alone: the host's reads and writes change nothing */
			WRT_CHECK_U64(r.sent_len, ref_len);
			if (r.sent_len == ref_len)
				WRT_CHECK_MEM(r.sent, ref, ref_len);
		}
		rig_free(&r);
	}
	free(ref);
}

/* ---- 8. the server's signature already in the ring behind AUTH_DONE -------------------------------------------------- */

static void test_signature_in_ring(void)
{
	rig r;
	uint8_t *buf = NULL, mine[96];
	size_t n = 0;

	/* (a) intact: the client switches before it takes another byte, reads the server's signature as a sealed frame, and the handshake finishes */
	secure_rig(&r, OFFER_SEC);
	r.ring_cap = 4096u; /* AUTH_DONE and the signature fit one commit */
	rig_start(&r);
	rig_stage_done_and_sig(&r, &buf, &n, mine);
	rig_inject(&r, buf, n); /* one commit of everything: the signature sits in the ring behind AUTH_DONE when the connection handles it */
	free(buf);
	WRT_CHECK_U64(r.c.state, WRI_M2_IDENT);
	r.skip_tx = 96; /* the server already has the client's signature (the test sent it); the client's own copy must be the same bytes */
	{
		size_t before = r.sent_len;

		(void)rig_flush_tx(&r);
		WRT_CHECK(r.sent_len >= before + 96);
		WRT_CHECK_MEM(r.sent + before - 0, mine, 96); /* byte for byte the frame built from the notes: same nonce, same ciphertext, same tag */
	}
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.up.n_closed, 0);
	WRT_CHECK_U64(r.s->state, SIM_M2_ST_READY);
	rig_free(&r);

	/* (b) the signature damaged in the ring: a TAG failure. Had it been taken for a crc frame it would be a preamble CRC error, so this
	 * proves it was read as a sealed frame. */
	secure_rig(&r, OFFER_SEC);
	rig_start(&r);
	rig_stage_done_and_sig(&r, &buf, &n, mine);
	buf[n - 40] ^= 0x04; /* a ciphertext byte of the server's signature frame */
	rig_inject(&r, buf, n);
	free(buf);
	rig_check_failed(&r, WR_E_M2_SEC_TAG);
	rig_free(&r);

	/* (c) the same with the damage in the CRC-covered bytes of what would be a crc preamble: still a tag failure */
	secure_rig(&r, OFFER_SEC);
	rig_start(&r);
	rig_stage_done_and_sig(&r, &buf, &n, mine);
	buf[n - 96] ^= 0x01; /* the first byte of the signature frame */
	rig_inject(&r, buf, n);
	free(buf);
	rig_check_failed(&r, WR_E_M2_SEC_TAG);
	rig_free(&r);
}

/* ---- 9. the real cephx machine over the fake monitor and OSD ----------------------------------------------------------- */

static int mon_getmap(rig *r)
{
	static const uint8_t front[8] = {1, 0, 0, 0, 0, 0, 0, 0}; /* MMonGetMap */
	wri_m2_msg_out m = mk(5, 1, front, sizeof(front), NULL, 0);
	size_t before = r->up.n_msgs;

	if (wri_m2_conn_send_message(&r->x, &r->c, &m) != WR_OK)
		return 0;
	rig_pump(r);
	return r->up.n_msgs == before + 1u && r->up.msgs[before].hdr.type == 4; /* MMonMap */
}

static void test_cephx(void)
{
	unsigned kt, srv, pol;
	/* (server's allowed modes) x (the client's policy): the outcome of each */
	static const uint8_t sm[3][2] = {{1, 0}, {2, 0}, {1, 2}};
	static const unsigned policies[] = {WR_MODE_CRC_ONLY, WR_MODE_SECURE_ONLY, WR_MODE_STOCK};

	for (kt = WR_KEY_TYPE_AES; kt <= WR_KEY_TYPE_AES256K; kt++) {
		for (srv = 0; srv < 3; srv++) {
			for (pol = 0; pol < 3; pol++) {
				cxw w;
				rig rm, ro;
				uint32_t mon_want[2], osd_want[2], mon_mode = 0, osd_mode = 0;
				unsigned nm = expected_list(policies[pol], 1, mon_want), no = expected_list(policies[pol], 0, osd_want), i, j;
				uint8_t mon_off = wri_m2_offer_for((uint8_t)policies[pol], 0, WRI_ENTITY_MON);
				uint8_t osd_off = wri_m2_offer_for((uint8_t)policies[pol], 0, WRI_ENTITY_OSD);

				for (i = 0; i < nm && mon_mode == 0; i++)
					for (j = 0; j < 2; j++)
						if (sm[srv][j] == mon_want[i] && mon_mode == 0)
							mon_mode = mon_want[i];
				for (i = 0; i < no && osd_mode == 0; i++)
					for (j = 0; j < 2; j++)
						if (sm[srv][j] == osd_want[i] && osd_mode == 0)
							osd_mode = osd_want[i];
				WRT_CHECK_U64(cxw_init(&w, kt), 0);
				w.mcfg.m2.n_modes = sm[srv][1] != 0 ? 2u : 1u;
				w.mcfg.m2.modes[0] = sm[srv][0], w.mcfg.m2.modes[1] = sm[srv][1];
				w.ocfg.m2.n_modes = w.mcfg.m2.n_modes;
				w.ocfg.m2.modes[0] = sm[srv][0], w.ocfg.m2.modes[1] = sm[srv][1];
				WRT_CHECK_U64(cxw_start(&w), 0);

				/* the monitor connection */
				rig_init(&rm);
				rig_enable_secure(&rm, mon_off);
				cxw_mon_rig(&w, &rm);
				rig_start(&rm);
				rig_pump(&rm);
				if (mon_mode == 0) {
					rig_check_failed(&rm, WR_E_M2_BAD_METHOD);
				} else {
					WRT_CHECK_U64(rm.c.state, WRI_M2_READY);
					WRT_CHECK_U64(rm.c.mode, mon_mode);
					WRT_CHECK_U64(rm.c.global_id, 4100);
					WRT_CHECK_U64(sim_m2_is_secure(rm.s), mon_mode == 2u);
					WRT_CHECK_U64(sim_mon_secrets(w.mon)->n, mon_mode == 2u ? 1u : 0u);
					WRT_CHECK(mon_getmap(&rm)); /* a message in each direction in the mode we got */
					WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_keepalive(&rm.x, &rm.c, 5, 6));
					rig_pump(&rm);
					WRT_CHECK_U64(rm.c.n_ka_ack, 1);
					WRT_CHECK_U64(rm.c.state, WRI_M2_READY);
					WRT_CHECK(wri_cx_have(&w.e.c, WRI_CX_SERVICE_OSD, w.e.x.now.mono_ms)); /* the OSD ticket came with it */
				}

				/* the OSD connection: authorizer, challenge, reply of version 2 with the secret (secure) or version 1 (crc) */
				if (mon_mode != 0) {
					uint8_t one_msg_front[16];
					wri_m2_msg_out m;

					rig_init(&ro);
					rig_enable_secure(&ro, osd_off);
					cxw_osd_rig(&w, &ro);
					rig_start(&ro);
					rig_pump(&ro);
					if (osd_mode == 0) {
						rig_check_failed(&ro, WR_E_M2_BAD_METHOD);
					} else {
						WRT_CHECK_U64(ro.c.state, WRI_M2_READY);
						WRT_CHECK_U64(ro.c.mode, osd_mode);
						WRT_CHECK_U64(sim_m2_is_secure(ro.s), osd_mode == 2u);
						WRT_CHECK_U64(sim_sec_log_distinct(sim_osd_secrets(w.osd)), 1);
						WRT_CHECK_U64(sim_osd_secrets(w.osd)->n, osd_mode == 2u ? 1u : 0u);
						memset(one_msg_front, 0x5a, sizeof(one_msg_front));
						m = mk(0x7001, 9, one_msg_front, sizeof(one_msg_front), NULL, 0); /* a type the fake OSD counts and ignores */
						WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&ro.x, &ro.c, &m));
						WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_keepalive(&ro.x, &ro.c, 7, 8));
						rig_pump(&ro);
						WRT_CHECK_U64(sim_osd_n_other(w.osd), 1);
						WRT_CHECK_U64(ro.c.n_ka_ack, 1);
						WRT_CHECK_U64(ro.c.state, WRI_M2_READY);
					}
					wri_cx_hs_wipe(&w.hs);
					rig_free(&ro);
				}
				rig_free(&rm);
				cxw_free(&w);
			}
		}
	}
	(void)SERVER_LISTS;
}

int main(void)
{
	test_set_secure_api();
	test_offer_bytes();
	test_mode_matrix();
	test_done_mode_not_offered();
	test_secret_cases();
	test_secure_handshake_bytes();
	test_chunking_across_switch();
	test_signature_in_ring();
	test_cephx();
	return wrt_finish();
}
