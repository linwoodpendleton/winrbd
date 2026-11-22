/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_conn_sec.c - the secure-mode half of the connection: the mode offer, the checks on AUTH_DONE's mode and secret, the switch at
 * the frame boundary, teardown (see wri_m2_conn.h and docs/design/core-architecture.md 34.2 to 34.4, 34.9).
 *
 * What the connection adds to part A, in one place:
 *   - set_secure: the owner hands the connection a secure slot and an offer; both live IN the slot (wri_m2s_slot.offer, .tx.bounce), so the
 *     connection grew by one pointer (`sec`). No slot: the connection offers crc only and a secure answer is refused (WR_E_M2_MODE).
 *   - the mode check: AUTH_DONE's mode must be one that AUTH_REQUEST offered. The reference client does not check this; a server that answers
 *     a mode we did not offer is not one we continue with.
 *   - the switch: the secret comes from the auth layer, the AUTH_DONE FRAME event is released, wri_m2_secure_on binds the codec, and only
 *     then does the handshake go on with our AUTH_SIGNATURE (which the queue now seals). The secret leaves the auth layer in the same
 *     breath: after the key schedule exists, the 64 bytes are nowhere.
 *   - the end: every road out of a connection (failure, close, the transport gone, open() of the same slot again) calls wri_m2_secure_off,
 *     which erases the key schedule, the nonces, the staging and the bounce buffer and zeroes the slot.
 *
 * Nothing here looks at plaintext of the session, takes a nonce, or knows a key: that is wri_m2_sec*.c. A frame is never built or parsed
 * differently by the connection; the seam in the queue and the parser does that.
 */
#include "wri_m2_conn.h"
#include "wri_m2_modes.h"
#include "wri_m2_sec.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define OFFER_KNOWN (WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE | WRI_M2_OFFER_SECURE_FIRST)
#define CRC_FRAME_FIXED (WRI_M2_PREAMBLE_LEN + WRI_M2_CRC_LEN) /* a single-segment frame minus its payload (segment 0 is not empty) */

/* ---- the offer ------------------------------------------------------------------------------------------ */

wr_status wri_m2_conn_set_secure(wri_m2_conn *c, uint8_t offer, struct wri_m2s_slot *sec, uint8_t *bounce, uint32_t bounce_cap)
{
	if (c == NULL)
		return WR_E_INVAL;
	/* Shape first, with nothing touched: a refusal leaves the connection exactly as it was. */
	if ((offer & ~OFFER_KNOWN) != 0u || (offer != 0u && (offer & (WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE)) == 0u))
		return WR_E_INVAL; /* a bit nobody defined, or an offer that offers nothing (SECURE_FIRST alone) */
	if ((offer & WRI_M2_OFFER_SECURE) != 0u) {
		if (sec == NULL)
			return WR_E_INVAL; /* secure without a slot cannot be honoured: say so now, not at the first secure AUTH_DONE */
		if (bounce == NULL || bounce_cap < 256u || (bounce_cap % WRI_M2S_BLOCK) != 0u)
			return WR_E_INVAL;
	}
	if (c->state != WRI_M2_CONNECTING)
		return WR_E_STATE;
	if (c->sec != NULL && c->sec != sec)
		wri_m2_secure_off(&c->rx, &c->tx, c->sec); /* an earlier slot of this connection: erased, never left behind */
	c->sec = sec;
	if (sec == NULL)
		return WR_OK; /* crc only, as before part D */
	/* The slot starts from zero whatever it held (an earlier life, the host's 0xab fill): the key schedule is made at the switch. */
	wri_secure_zero(sec, sizeof(*sec));
	sec->offer = offer;
	if (bounce != NULL && bounce_cap != 0u) {
		sec->tx.bounce = bounce;
		sec->tx.bounce_cap = bounce_cap;
	}
	return WR_OK;
}

uint8_t wri_m2c_offer(const wri_m2_conn *c)
{
	if (c->sec == NULL || (c->sec->offer & (WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE)) == 0u)
		return WRI_M2_OFFER_CRC;
	return c->sec->offer;
}

uint32_t wri_m2c_frame_bytes(int secure, uint32_t len0)
{
	uint32_t len[WRI_M2_MAX_SEGS];
	uint64_t n;

	if (!secure)
		return CRC_FRAME_FIXED + len0;
	len[0] = len0, len[1] = len[2] = len[3] = 0u;
	n = wri_m2s_wire_len(len, 1u, NULL);
	return n > 0xffffffffu ? 0xffffffffu : (uint32_t)n; /* len0 is a control payload (at most a few hundred bytes): never near the limit */
}

wr_status wri_m2c_sec_check_mode(const wri_ctx *x, wri_m2_conn *c, uint32_t mode)
{
	uint8_t offer = wri_m2c_offer(c);

	/* A secure answer needs the slot as well as the offer: without one (which set_secure refuses to combine) the switch has nowhere to go. */
	if (wri_m2_offer_has(offer, mode) && (mode != WRI_CONN_MODE_SECURE || c->sec != NULL))
		return WR_OK;
	WRI_M2C_FAIL(x, c, WR_E_M2_MODE, "connection mode we did not offer", mode, offer, 0);
	return WR_E_M2_MODE;
}

/* ---- the switch ----------------------------------------------------------------------------------------- */

/* Ask the auth layer to forget its copy of the secret (a NULL out pointer wipes without handing out). Only while the handshake slot is still
 * the connection's: after c->pa is gone the slot may belong to another connection. */
static void drop_secret(wri_m2_conn *c)
{
	if (c->pa != NULL && c->auth != NULL && c->auth->conn_secret != NULL)
		c->auth->conn_secret(c->auth_ctx, NULL, NULL);
}

wr_status wri_m2c_sec_switch(const wri_ctx *x, wri_m2_conn *c)
{
	const uint8_t *secret = NULL;
	size_t slen = 0;
	uint8_t *bounce;
	uint32_t bounce_cap;
	uint8_t offer;
	wr_status st;

	if (c->sec == NULL || c->auth == NULL || c->auth->conn_secret == NULL) {
		WRI_M2C_FAIL(x, c, WR_E_M2_SECRET, "secure mode but the authentication has no connection secret", 0, 0, 0);
		return WR_E_M2_SECRET;
	}
	c->auth->conn_secret(c->auth_ctx, &secret, &slen);
	if (secret == NULL || slen == 0u) {
		WRI_M2C_FAIL(x, c, WR_E_M2_SECRET, "secure mode but the server gave no connection secret", slen, 0, 0);
		return WR_E_M2_SECRET;
	}
	bounce = c->sec->tx.bounce;
	bounce_cap = c->sec->tx.bounce_cap;
	offer = c->sec->offer; /* a failed switch zeroes the slot: keep what the failure record says */
	/* The AUTH_DONE frame is spent: release it so the parser is between frames, and switch BEFORE it takes another byte, so a signature
	 * frame that already sits in the ring is read as secure. (The step loop releases the event again after the handler: a no-op.) */
	wri_m2_rx_next_frame(&c->rx);
	st = wri_m2_secure_on(&c->rx, &c->tx, c->sec, x->host.prim, secret, slen, bounce, bounce_cap);
	secret = NULL;
	drop_secret(c); /* the key schedule exists (or the connection is failing): the auth layer's copy goes either way */
	if (st != WR_OK) {
		/* wri_m2_secure_on zeroed the slot, and with it the pointer to the bounce buffer: erase the buffer here (it holds nothing of ours yet, but
		 * nothing of the host's earlier life stays in a buffer that was meant for ciphertext either) */
		wri_secure_zero(bounce, bounce_cap);
		WRI_M2C_FAIL(x, c, st, "secure mode could not be switched on", slen, offer, 0);
		return st;
	}
	return WR_OK;
}

/* ---- the end ---------------------------------------------------------------------------------------------- */

void wri_m2c_sec_end(wri_m2_conn *c)
{
	drop_secret(c);
	if (c->sec != NULL) {
		wri_m2_secure_off(&c->rx, &c->tx, c->sec);
		c->sec = NULL; /* the slot is zero and no longer ours: nothing here may touch the memory again (the owner reuses it, or hands it over anew) */
	}
}

/* 1 when the secure transmit side can never make another frame: its key was wiped because a frame failed half way (the nonces were taken, the bytes
 * did not come out) or a stream could not be refilled. The peer would not decode anything behind such a gap, so the connection is over. */
static int tx_key_gone(const wri_m2_conn *c)
{
	return c->sec != NULL && c->tx.sx == &c->sec->tx && c->sec->s.tx.keyed == 0u;
}

wr_status wri_m2c_tx_status(const wri_ctx *x, wri_m2_conn *c, wr_status st)
{
	if (st == WR_OK || st == WR_E_BUSY)
		return st;
	/* The nonce was refused (34.5), or the builder lost its key after it had taken nonces (a host crypto refusal, a spent stream): nothing of the frame
	 * (or only a part the peer cannot use) was produced, and the connection cannot go on under this key. It ends HERE (the key is wiped, nothing more is
	 * sent), but the owner is told at the next step, not from inside its own send call: a callback of the upper layer that tears its session down
	 * under the caller's feet would be a new kind of re-entrancy. The caller sees what every caller of a connection that went away sees,
	 * WR_E_STATE ("not READY any more": the OSD request engine then waits for a new session instead of failing the I/O); the cause is c->err.
	 * Any other refusal (TOOBIG, INVAL: decided on the lengths before a nonce is taken) leaves the connection as it was and is returned as it is. */
	if (st != WR_E_M2_NONCE && !tx_key_gone(c))
		return st;
	wri_m2c_fail_deferred(x, c, st, (unsigned)__LINE__, "transmit nonce refused or transmit key lost", c->out_seq, 0, 0);
	return WR_E_STATE;
}

void wri_m2c_tx_check(const wri_ctx *x, wri_m2_conn *c)
{
	if (!tx_key_gone(c))
		return;
	/* The bytes the host just consumed may have been the last ones of a stream that could not go on: what was promised will never come, so the connection
	 * ends here as well (c->tx.err has the builder's status). */
	wri_m2c_fail_deferred(x, c, c->tx.err != WR_OK ? c->tx.err : WR_E_STATE, (unsigned)__LINE__, "transmit key lost", c->out_seq, 0, 0);
}
