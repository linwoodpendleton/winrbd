/* SPDX-License-Identifier: MIT */
/*
 * wri_cx_secret.c - the connection secret of secure mode, as the cephx handshakes hold it (docs/design/
 * core-architecture.md 34.3). The monitor's AUTH_DONE (the blob `cbl`) and an OSD's authorizer reply (version 2)
 * carry it; wri_cx_hs.c finds the bytes, wri_cx_hs_take_secret() judges them against the mode and keeps them in the
 * handshake's wri_cx_secret, and the conn_secret member of the two ops tables hands them to the connection once.
 *
 * What is held, for how long, and who wipes it is written at wri_cx_secret in wri_cx.h. Nothing here logs, and an
 * errinfo records the length of a refused secret, never a byte of it.
 */
#include "wri_cx.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

void wri_cx_sec_wipe(wri_cx_secret *s)
{
	if (s != NULL)
		wri_secure_zero(s, sizeof(*s));
}

void wri_cx_sec_hand_out(wri_cx_secret *s, int done, const uint8_t **secret, size_t *len)
{
	if (s == NULL)
		return;
	if (secret != NULL && len != NULL && done && s->len != 0 && !s->taken) {
		s->taken = 1;
		*secret = s->buf;
		*len = s->len;
		return;
	}
	/* nothing to give, or the connection asks again (it is done with the first pointer): nothing stays */
	wri_cx_sec_wipe(s);
	if (secret != NULL)
		*secret = NULL;
	if (len != NULL)
		*len = 0;
}

void wri_cx_sec_release_taken(wri_cx_secret *s)
{
	if (s != NULL && s->taken)
		wri_cx_sec_wipe(s);
}

/*
 * Judge a connection secret of n bytes (at p, inside the decrypt scratch) against the mode and keep it: crc takes
 * none (AUTH_PROTO: a server that sends a key it will not use is not one to continue with); secure takes 40 .. 128
 * bytes (M2_SECRET for none, too few or too many). The failure is recorded in the handshake's own err.
 */
wr_status wri_cx_hs_take_secret(wri_cx_hs *h, uint32_t mode, const uint8_t *p, uint32_t n)
{
	wr_status st = WR_OK;
	const char *what = NULL;

	if (mode == WRI_CONN_MODE_CRC) {
		if (n != 0) {
			st = WR_E_AUTH_PROTO;
			what = "server sent a connection secret in crc mode";
		}
	} else if (n == 0) {
		st = WR_E_M2_SECRET;
		what = "secure mode without a connection secret";
	} else if (n < WRI_CX_SECRET_MIN || n > WRI_CX_SECRET_MAX) {
		st = WR_E_M2_SECRET;
		what = "connection secret has an unusable length";
	}
	if (what != NULL) {
		wri_errinfo_set(&h->err, st, WR_MOD_AUTH, (unsigned)__LINE__, what, n, WRI_CX_SECRET_MIN, WRI_CX_SECRET_MAX);
		return st;
	}
	if (mode == WRI_CONN_MODE_SECURE) {
		wri_cx_sec_wipe(&h->sec);
		WR_MEMCPY(h->sec.buf, p, n);
		h->sec.len = (uint8_t)n;
	}
	return WR_OK;
}
