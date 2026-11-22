/* SPDX-License-Identifier: MIT */
/*
 * wri_client_modes.c - the engine's side of secure mode at the connection table (docs/design/core-architecture.md 34.2, 34.8, 36, 37):
 *   - wri_client_conn_secure: hands the slot, the bounce buffer and the offer of the connection's role to a connection that was just opened
 *     (wri_m2_conn_set_secure). A slot is good for ONE connection (it is wiped when the connection ends), so this runs at every open;
 *   - wri_client_conn_account: looks at a connection after it ran and counts, once per connection, the mode it reached READY in (conns_secure,
 *     conns_crc) and its end (sec_failures, and the log record that says which setting to change when a server refused the offered modes);
 *   - wri_client_conn_stats: the connection fields of wr_stats, the three counters included.
 * Nothing here knows a key, a nonce or a secret: that is the connection (wri_m2_conn_sec.c) and the layers under it.
 */
#include "wri_client.h"

WR_FILE_LICENCE_MIT

#define MODE_BIT_CRC ((uint64_t)1 << WRI_CONN_MODE_CRC)       /* the bit layout of the allowed-modes mask of AUTH_BAD_METHOD's errinfo (a1) */
#define MODE_BIT_SECURE ((uint64_t)1 << WRI_CONN_MODE_SECURE)

/* A server refused the AUTH_REQUEST (AUTH_BAD_METHOD, the numeric result is -EOPNOTSUPP on a mode refusal) and its allowed modes show why: say which side's
 * setting to change (design 34.2). There is no second attempt with another mode here: the reference client does not retry modes, and a silent switch
 * of a secure-only policy to crc would be a downgrade. The record carries the server's allowed-modes mask, our offer mask (WRI_M2_OFFER_*) and the role. */
static void bad_method_hint(wr_client *c, const wri_cslot *s)
{
	const wr_errinfo *e = &s->conn.err;
	uint8_t offer = wri_m2_offer_for(c->x.cfg.mode_policy, c->x.cfg.mode_policy_osd, s->conn.role);
	int osd = s->conn.role == WRI_ENTITY_OSD;
	int want_secure = (e->a1 & MODE_BIT_SECURE) != 0u && (e->a1 & MODE_BIT_CRC) == 0u && (offer & WRI_M2_OFFER_SECURE) == 0u;
	int want_crc = (e->a1 & MODE_BIT_CRC) != 0u && (e->a1 & MODE_BIT_SECURE) == 0u && (offer & WRI_M2_OFFER_CRC) == 0u;
	const char *msg;

	if (want_secure)
		msg = osd ? "OSD allows only secure mode: set mode_policy_osd to a policy that offers secure"
			  : "monitor allows only secure mode: set mode_policy to a policy that offers secure";
	else if (want_crc)
		msg = osd ? "OSD allows only crc mode: set mode_policy_osd to a policy that offers crc"
			  : "monitor allows only crc mode: set mode_policy to a policy that offers crc";
	else
		msg = osd ? "OSD refused the offered connection modes (mode_policy_osd)" : "monitor refused the offered connection modes (mode_policy)";
	WRI_LOG(&c->x, WR_LOG_WARN, WR_MOD_CLIENT, s->conn.id, WR_E_M2_BAD_METHOD, msg, e->a1, offer, s->conn.role, 0);
}

/* Look at what a connection did since the last look and count it: READY (in the mode it ended up in) and its end (a secure failure, the mode hint), each at
 * most once per connection (the two flags are cleared when the slot is opened). A connection that is READY and already failed or closed again when the
 * step ends is not counted as READY (its record is in the log): READY is noticed at the end of the step that made it. Cheap enough to call after every step and before a slot is released. */
void wri_client_conn_account(wr_client *c, wri_cslot *s)
{
	unsigned st = s->conn.state;

	if (!(s->flags & WRI_CF_READY_SEEN) && st == WRI_M2_READY) {
		s->flags = (uint8_t)(s->flags | WRI_CF_READY_SEEN);
		if (s->conn.mode == WRI_CONN_MODE_SECURE) {
			if (c->stats.conns_secure != 0xffffffffu)
				c->stats.conns_secure++;
		} else if (c->stats.conns_crc != 0xffffffffu) {
			c->stats.conns_crc++;
		}
	}
	if ((s->flags & WRI_CF_END_SEEN) || st != WRI_M2_FAILED)
		return;
	s->flags = (uint8_t)(s->flags | WRI_CF_END_SEEN);
	switch (s->conn.err.status) {
	case WR_E_M2_SECRET:
	case WR_E_M2_NONCE:
	case WR_E_M2_SEC_TAG:
		if (c->stats.sec_failures != 0xffffffffu)
			c->stats.sec_failures++;
		break;
	case WR_E_M2_BAD_METHOD:
		bad_method_hint(c, s);
		break;
	default:
		break;
	}
}

/* Secure mode at open: connection slot `idx` has the secure slot sec[idx] and the bounce buffer at sec_bounce + idx * sec_chunk (carved at create when the policy may
 * end in secure; NULL otherwise, and nothing happens). Only a connection whose offer has the secure bit gets them: the others are crc only, the behaviour of
 * parts A to C. */
void wri_client_conn_secure(wr_client *c, wri_cslot *s, uint32_t idx, uint8_t role)
{
	uint8_t offer;
	wr_status st;

	if (c->sec == NULL)
		return;
	offer = wri_m2_offer_for(c->x.cfg.mode_policy, c->x.cfg.mode_policy_osd, role);
	if ((offer & WRI_M2_OFFER_SECURE) == 0u)
		return;
	st = wri_m2_conn_set_secure(&s->conn, offer, &c->sec[idx], c->sec_bounce + (size_t)idx * c->sec_chunk, c->sec_chunk);
	/* STATE: open() itself was refused and the connection is already failed, reported as usual. Anything else cannot happen with a configuration that passed
	 * the check at create; it must never leave a connection that was meant to offer secure running as crc only, so it fails with the status. The failure is
	 * recorded now and reported at the next step, exactly like a refused open(): this runs inside the open call, before the slot is in use and before the
	 * upper layer knows the slot, so a synchronous closed() callback from here would reach it too early. */
	if (st != WR_OK && st != WR_E_STATE)
		wri_m2c_fail_deferred(&c->x, &s->conn, st, (unsigned)__LINE__, "secure mode could not be prepared for the connection", offer, c->sec_chunk, role);
}

void wri_client_conn_stats(const wr_client *c, wr_stats *out)
{
	out->conns_in_use = wri_client_conns_in_use(c);
	out->conns_hiwater = c->stats.conns_hiwater;
	out->handshakes_in_use = c->pa_in_use;
	out->handshakes_hiwater = c->stats.handshakes_hiwater;
	out->conns_secure = c->stats.conns_secure; /* the counters of the connection modes (wri_client_conn_account above) */
	out->conns_crc = c->stats.conns_crc;
	out->sec_failures = c->stats.sec_failures;
}
