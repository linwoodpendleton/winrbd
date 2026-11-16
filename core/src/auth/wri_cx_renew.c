/* SPDX-License-Identifier: MIT */
/*
 * wri_cx_renew.c - in-session renewal of the service tickets over an established monitor session
 * (CEPHX_GET_PRINCIPAL_SESSION_KEY, docs/spec/cephx.md 3.6 B, 2.11).
 *
 * Request (the auth_payload of an MAuth message; the message wrapper is the monitor module's job):
 *   u16 0x0200 | authorizer for service AUTH | CephXServiceTicketRequest {u8 1, u32 keys}
 * where the authorizer is u8 1 | u64 global_id | u32 0x20 | the AUTH ticket blob | the sealed
 * CephXAuthorize {v 2, nonce, no challenge} under the AUTH session key (usage 0x10). The mask never
 * contains the AUTH bit: renewing the AUTH ticket itself in-session is not supported (cephx.md 3.6
 * and 6 item 5 leave it unverified); a client that needs it reconnects, reclaiming its global id.
 *
 * Reply (the result_bl of an MAuthReply): u16 0x0200 | s32 status (must be 0) | a ticket reply with
 * ticket_enc 0 and msg_a under the AUTH session key. Each ticket this client keeps (OSD) replaces its
 * slot after it is fully validated; others are skipped. If the request asked for the OSD ticket and
 * the reply did not carry one, the call fails (WR_E_AUTH_PROTO) rather than silently leaving an
 * expiring ticket in place. Tickets already held stay as they are on any failure: a renewal never
 * forgets anything. A reply is accepted only while a request is pending (renew_mask != 0, set by
 * wri_cx_renew_build, cleared by the first reply that is accepted): a replayed or unsolicited reply
 * is WR_E_STATE and changes nothing.
 */
#include "wri_cx.h"

#include "wri_le.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define CX_TICKET_REQ_V 1u

wr_status wri_cx_renew_build(wri_cx_client *c, uint32_t service_mask, wri_wr *payload)
{
	const wri_cx_ticket *t;
	uint8_t rnd[8];
	uint32_t mask;
	uint64_t nonce;
	wr_status st;

	if (c == NULL || c->x == NULL || payload == NULL)
		return WR_E_INVAL;
	t = &c->ticket[WRI_CX_SLOT_AUTH];
	if (!t->have || c->x->now.mono_ms >= t->valid_until_ms)
		return WRI_CX_FAIL(c, WR_E_AUTH_TICKET_EXPIRED, "no usable AUTH ticket to renew with", t->have,
				   t->valid_until_ms, c->x->now.mono_ms);
	if (c->global_id == 0)
		return WRI_CX_FAIL(c, WR_E_AUTH_GID0, "no global id to renew with", 0, 0, 0);
	mask = (service_mask != 0 ? service_mask : c->want_mask) & ~WRI_CX_SERVICE_AUTH;
	if (mask == 0)
		return WRI_CX_FAIL(c, WR_E_INVAL, "renewal asks for no service", service_mask, c->want_mask, 0);
	st = wri_random(c->x, rnd, sizeof(rnd));
	if (st != WR_OK)
		return WRI_CX_FAIL(c, st, "no random for the authorizer nonce", 0, 0, 0);
	nonce = wri_le64_get(rnd);
	wri_secure_zero(rnd, sizeof(rnd));

	wri_wr_u16(payload, (uint16_t)WRI_CX_REQ_GET_PRINCIPAL_SESSION_KEY);
	st = wri_cx_put_authorizer(c, WRI_CX_SERVICE_AUTH, t, nonce, 0, 0, payload);
	if (st != WR_OK)
		return WRI_CX_FAIL(c, st, "renewal authorizer could not be built", 0, 0, 0);
	wri_wr_u8(payload, (uint8_t)CX_TICKET_REQ_V);
	wri_wr_u32(payload, mask);
	if (!wri_wr_ok(payload))
		return WRI_CX_FAIL(c, payload->err, "renewal payload does not fit", 0, 0, 0);
	c->renew_mask = mask;
	return WR_OK;
}

wr_status wri_cx_renew_handle(wri_cx_client *c, const uint8_t *payload, size_t n)
{
	wri_rd r;
	uint16_t rtype;
	int32_t rstatus;
	uint32_t stored = 0, need;
	wr_status st;

	if (c == NULL || c->x == NULL || (payload == NULL && n != 0))
		return WR_E_INVAL;
	/* Only an answer to a request we built: a replayed or unsolicited reply must not replace tickets. */
	if (c->renew_mask == 0)
		return WRI_CX_FAIL(c, WR_E_STATE, "renewal reply without a pending request", 0, 0, 0);
	wri_rd_init(&r, payload, n);
	rtype = wri_rd_u16(&r);
	rstatus = wri_rd_i32(&r);
	if (!wri_rd_ok(&r))
		return WRI_CX_FAIL(c, r.err, "renewal response header truncated", n, 0, 0);
	if (rtype != WRI_CX_REQ_GET_PRINCIPAL_SESSION_KEY)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "response is not for GET_PRINCIPAL_SESSION_KEY", rtype, 0, 0);
	if (rstatus != 0) {
		st = WRI_CX_FAIL(c, WR_E_AUTH_RESULT, "server reported an error status", (uint64_t)(int64_t)rstatus, 0, 0);
		if (c->err.status == WR_E_AUTH_RESULT)
			c->err.peer_result = rstatus;
		return st;
	}
	st = wri_cx_ticket_reply(c, &r, WRI_CX_TR_SERVICES, &stored);
	if (st != WR_OK)
		return st;
	need = c->renew_mask & WRI_CX_SERVICE_OSD;
	if ((need & ~stored) != 0)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "renewal reply lacks the OSD ticket", need, stored, 0);
	c->renew_mask = 0;
	return WR_OK;
}
