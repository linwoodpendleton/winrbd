/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_preauth.c - the pre-auth transcripts and the two AUTH_SIGNATURE values (msgr2.md 3.3, 3.4).
 *
 * Two independent byte logs, one for everything received and one for everything sent since the TCP
 * connection opened. Appending is on from init. A log that would exceed its capacity sets the
 * sticky WR_E_M2_PREAUTH_TOOBIG in the shared err field and appends nothing more to either log
 * (the handshake has to fail, so a partial transcript is of no use and is never signed over by
 * mistake: callers check err before computing a signature). stop() only ends appending; the bytes
 * stay for the HMACs until wipe().
 */
#include "wri_m2_ctl.h"
#include "wri_misc.h"
#include "wri_prim.h"

WR_FILE_LICENCE_MIT

void wri_m2_preauth_init(wri_m2_preauth *p, uint8_t *rx_buf, uint8_t *tx_buf, uint32_t cap)
{
	if (p == NULL)
		return;
	p->rx_buf = rx_buf;
	p->tx_buf = tx_buf;
	p->cap = (rx_buf != NULL && tx_buf != NULL) ? cap : 0u;
	p->rx_len = 0;
	p->tx_len = 0;
	p->enabled = 1;
	p->err = WR_OK;
}

static void append(wri_m2_preauth *p, uint8_t *buf, uint32_t *len, const uint8_t *b, size_t n)
{
	if (p == NULL || !p->enabled || p->err != WR_OK || n == 0)
		return;
	if (b == NULL || n > (size_t)(p->cap - *len)) {
		p->err = (b == NULL) ? WR_E_INVAL : WR_E_M2_PREAUTH_TOOBIG;
		return;
	}
	WR_MEMCPY(buf + *len, b, n);
	*len += (uint32_t)n;
}

void wri_m2_preauth_rx(void *p, const uint8_t *b, size_t n)
{
	wri_m2_preauth *pa = (wri_m2_preauth *)p;

	if (pa != NULL)
		append(pa, pa->rx_buf, &pa->rx_len, b, n);
}

void wri_m2_preauth_tx(void *p, const uint8_t *b, size_t n)
{
	wri_m2_preauth *pa = (wri_m2_preauth *)p;

	if (pa != NULL)
		append(pa, pa->tx_buf, &pa->tx_len, b, n);
}

void wri_m2_preauth_stop(wri_m2_preauth *p)
{
	if (p != NULL)
		p->enabled = 0;
}

void wri_m2_preauth_wipe(wri_m2_preauth *p)
{
	if (p == NULL)
		return;
	if (p->rx_buf != NULL)
		wri_secure_zero(p->rx_buf, p->rx_len);
	if (p->tx_buf != NULL)
		wri_secure_zero(p->tx_buf, p->tx_len);
	p->rx_len = 0;
	p->tx_len = 0;
	p->enabled = 0;
}

static void sig_over(const wr_prim_ops *prim, const uint8_t *log, uint32_t len, const uint8_t *key,
		     size_t key_len, uint8_t out[32])
{
	wr_iov iov;

	if (out == NULL)
		return;
	if (key == NULL || key_len == 0) {
		WR_MEMSET(out, 0, 32u);
		return;
	}
	iov.base = log;
	iov.len = len;
	wri_p_hmac_sha256(prim, key, key_len, &iov, len != 0 ? 1u : 0u, out);
}

void wri_m2_sig_ours(const wr_prim_ops *prim, const wri_m2_preauth *p, const uint8_t *key,
		     size_t key_len, uint8_t out[32])
{
	if (out == NULL)
		return;
	if (p == NULL) {
		WR_MEMSET(out, 0, 32u);
		return;
	}
	sig_over(prim, p->rx_buf, p->rx_len, key, key_len, out);
}

void wri_m2_sig_expected(const wr_prim_ops *prim, const wri_m2_preauth *p, const uint8_t *key,
			 size_t key_len, uint8_t out[32])
{
	if (out == NULL)
		return;
	if (p == NULL) {
		WR_MEMSET(out, 0, 32u);
		return;
	}
	sig_over(prim, p->tx_buf, p->tx_len, key, key_len, out);
}

wr_status wri_m2_sig_verify(const wr_prim_ops *prim, const wri_m2_preauth *p, const uint8_t *key,
			    size_t key_len, const uint8_t got[32])
{
	uint8_t want[32];
	int eq;

	if (p == NULL || got == NULL)
		return WR_E_INVAL;
	/* "no key" is spelled NULL with length 0; a NULL key with a length, or a key with length 0, is a
	 * caller bug that would otherwise turn into the all-zero signature a hostile peer can send. */
	if ((key == NULL) != (key_len == 0))
		return WR_E_INVAL;
	if (p->err != WR_OK)
		return p->err; /* the log is incomplete: nothing to compare against */
	if (p->enabled)
		return WR_E_STATE; /* still logging: our own signature frame could end up in the log */
	sig_over(prim, p->tx_buf, p->tx_len, key, key_len, want);
	eq = wri_ct_memeq(want, got, 32u);
	wri_secure_zero(want, sizeof(want));
	return eq ? WR_OK : WR_E_M2_SIGNATURE;
}
