/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the cephx client machine's reply decoders (core/src/auth/wri_cx_client.c,
 * wri_cx_ticket.c, wri_cx_renew.c): the AUTH_REPLY_MORE and AUTH_DONE payloads of a monitor and an OSD
 * connection, and the renewal reply, against a machine with fixed keys.
 *
 * Byte 0: bits 0..2 the operation, bit 3 the key type (0: type 1, 1: type 2), bit 7 "sealed".
 *   0  monitor AUTH_DONE      begin + more (fixed challenge) + done(payload)
 *   1  monitor AUTH_REPLY_MORE  begin + more(payload)
 *   2  OSD AUTH_REPLY_MORE    begin + more(payload)           (an OSD ticket is installed first)
 *   3  OSD AUTH_DONE          begin + more(valid challenge) + done(payload)
 *   4  renewal reply          wri_cx_renew_handle(payload)    (an AUTH ticket is installed first)
 *   5  monitor AUTH_DONE with the connection secret blob and the extra ticket reply (sealed only)
 *   6  monitor AUTH_DONE of a reclaim, ticket_enc 1 (sealed only)
 * The rest of the input is the payload, copied to an exact-size heap block so ASan sees any over-read.
 *
 * Sealed (bit 7), for operations 0, 2, 3 and 4: ciphertexts cannot be guessed, so the target builds the
 * envelope and the fuzzer controls what is inside. Op 0 / 4: byte 1 = n, bytes 2 .. 2 + n are the
 * plaintext CephXServiceTicket sealed as msg_a of one ticket (AUTH for op 0, OSD for op 4), the rest is
 * the ticket blob. Op 2: the rest is the challenge item sealed raw (usage 0x11). Op 3: the rest is the
 * reply item sealed (usage 0x12) after its nonce_plus_one field has been set to the right value, so the
 * secret / version handling is reachable.
 * Op 5: byte 1 = n1, the next n1 bytes are the plaintext connection-secret item (sealed with usage 0x03
 * under the new AUTH session key, as cbl), the next byte = n2, the next n2 bytes are the plaintext
 * CephXServiceTicket of an OSD ticket (sealed with usage 0x04 under the AUTH session key, in extra), the
 * rest is that ticket's blob; the AUTH ticket in front of them is valid. Op 6: the client holds an old AUTH
 * ticket and the global id 1000 (so it reclaims); the reply's AUTH ticket is valid, byte 1 = n, the next n
 * bytes are the plaintext of its ticket blob field (sealed with usage 0x05 under the OLD session key),
 * ticket_enc = 1.
 *
 * Properties: no crash, no read or write outside the buffers, the machine ends in a consistent state:
 * a failed monitor AUTH_DONE leaves no ticket and no global id, a successful one holds the AUTH ticket
 * (and the global id 1000), a failed handshake step leaves no session key, and a failed renewal
 * leaves the held tickets as they were. The host random is a fixed counter, so runs are reproducible.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_cx.h"
#include "wri_le.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

static wr_status fuzz_random(void *ctx, uint8_t *out, size_t n)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < n; i++)
		out[i] = (uint8_t)(0x1D * i + 0x42);
	return WR_OK;
}

static uint8_t *heap_copy(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)calloc(n != 0 ? n : 1, 1);

	if (q == NULL)
		exit(2);
	if (n != 0)
		memcpy(q, p, n);
	return q;
}

static wr_key fkey(unsigned type, uint8_t seed)
{
	wr_key k;
	uint8_t s[32];
	size_t i, n = type == WR_KEY_TYPE_AES ? 16u : 32u;

	for (i = 0; i < n; i++)
		s[i] = (uint8_t)(seed + 5u * i);
	check(wr_key_from_raw(&k, type, s, n) == WR_OK);
	return k;
}

/* Install a held ticket the way a finished handshake would leave it. */
static void install(wri_cx_client *c, unsigned slot, uint32_t service, const wr_key *sk)
{
	wri_cx_ticket *t = &c->ticket[slot];

	t->have = 1;
	t->service = service;
	t->session_key = *sk;
	t->blob[0] = 1;
	wri_le64_put(t->blob + 1, 5);
	wri_le32_put(t->blob + 9, 8);
	memset(t->blob + 13, 0x77, 8);
	t->blob_len = 21;
	t->valid_until_ms = UINT64_MAX;
	t->renew_at_ms = UINT64_MAX - 1;
	t->gen++;
}

/* msg_a + ticket blob for one ticket, sealed by the target (sealed mode). Returns the payload length. */
static size_t build_sealed_ticket(const wri_ctx *x, const wr_key *mk, uint32_t service, int with_hdr, const uint8_t *item,
				  size_t ilen, const uint8_t *blob, size_t blen, uint8_t *out, size_t cap)
{
	wri_wr w;
	uint8_t ct[400];
	size_t cn = 0;

	if (ilen + 80 > sizeof(ct) || wri_cx_seal(x, mk, WRI_CX_USAGE_TICKET_SESSION_KEY, item, ilen, ct, sizeof(ct), &cn) != WR_OK)
		return 0;
	wri_wr_init(&w, out, cap);
	if (with_hdr) {
		wri_wr_u16(&w, with_hdr == 1 ? (uint16_t)WRI_CX_REQ_GET_AUTH_SESSION_KEY : (uint16_t)WRI_CX_REQ_GET_PRINCIPAL_SESSION_KEY);
		wri_wr_i32(&w, 0);
	}
	wri_wr_u8(&w, 1);
	wri_wr_u32(&w, 1);
	wri_wr_u32(&w, service);
	wri_wr_u8(&w, 1);
	wri_wr_u32(&w, (uint32_t)cn);
	wri_wr_bytes(&w, ct, cn);
	wri_wr_u8(&w, 0);
	wri_wr_u32(&w, (uint32_t)blen);
	wri_wr_bytes(&w, blob, blen);
	return wri_wr_ok(&w) ? wri_wr_len(&w) : 0;
}

/* The valid AUTH ticket entry of an AUTH_DONE: msg_a under the principal key, a small blob. */
static int put_auth_ticket(const wri_ctx *x, const wr_key *pk, const wr_key *sess, int enc, const wr_key *old_key,
			   const uint8_t *blob_item, size_t blob_item_len, wri_wr *w)
{
	uint8_t item[96], ct[200], blob[21], bl[40], bct[160];
	wri_wr iw;
	size_t cn = 0, bn = 0;

	wri_wr_init(&iw, item, sizeof(item));
	wri_wr_u8(&iw, 1);
	wri_wr_u16(&iw, sess->type);
	wri_wr_zero(&iw, 8);
	wri_wr_u16(&iw, sess->len);
	wri_wr_bytes(&iw, sess->secret, sess->len);
	wri_wr_u32(&iw, 259200);
	wri_wr_u32(&iw, 0);
	if (!wri_wr_ok(&iw) || wri_cx_seal(x, pk, WRI_CX_USAGE_TICKET_SESSION_KEY, item, wri_wr_len(&iw), ct, sizeof(ct), &cn) != WR_OK)
		return 0;
	blob[0] = 1;
	wri_le64_put(blob + 1, 9);
	wri_le32_put(blob + 9, 8);
	memset(blob + 13, 0x66, 8);
	wri_wr_u8(w, 1);
	wri_wr_u32(w, 1);
	wri_wr_u32(w, WRI_CX_SERVICE_AUTH);
	wri_wr_u8(w, 1);
	wri_wr_u32(w, (uint32_t)cn);
	wri_wr_bytes(w, ct, cn);
	wri_wr_u8(w, enc ? 1u : 0u);
	if (!enc) {
		wri_wr_u32(w, sizeof(blob));
		wri_wr_bytes(w, blob, sizeof(blob));
	} else {
		if (blob_item_len > sizeof(bl) || wri_cx_seal(x, old_key, WRI_CX_USAGE_TICKET_BLOB, blob_item, blob_item_len, bct, sizeof(bct), &bn) != WR_OK)
			return 0;
		wri_wr_u32(w, (uint32_t)bn);
		wri_wr_bytes(w, bct, bn);
	}
	return wri_wr_ok(w);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned op, ktype;
	int sealed;
	wri_ctx x;
	wri_arena a;
	wri_cx_client c;
	wr_cluster_spec spec;
	size_t need = 0;
	uint8_t *raw, *mem, *pl, *obuf, chal[9], big[1400];
	size_t pn;
	wr_key pk, ak, ok;
	wri_wr w;
	const wri_auth_ops *ops = wri_cx_ops();
	wr_status st;
	uint64_t nonce;
	size_t ilen, blen;

	if (size < 1)
		return 0;
	op = data[0] & 7u;
	ktype = (data[0] & 8u) != 0 ? WR_KEY_TYPE_AES256K : WR_KEY_TYPE_AES;
	sealed = (data[0] & 0x80u) != 0;
	if (op > 6 || ((op == 5 || op == 6) && !sealed) || (sealed && (op == 0 || op == 4 || op >= 5) && size < 2))
		return 0;

	memset(&x, 0, sizeof(x));
	wr_config_profile_harness(&x.cfg);
	x.cfg.ticket_cap = 512;
	x.host.size = (uint32_t)sizeof(x.host);
	x.host.random = fuzz_random;
	x.now.mono_ms = 1000;
	check(wri_cx_client_mem(&x.cfg, &need) == WR_OK);
	raw = (uint8_t *)calloc(need + 128u, 1); /* a 64-byte aligned start inside an exact-size block */
	if (raw == NULL)
		exit(2);
	mem = (uint8_t *)(((uintptr_t)raw + 63u) & ~(uintptr_t)63u);
	wri_arena_init(&a, mem, need + 64u);
	pk = fkey(ktype, 1);
	ak = fkey(ktype, 40);
	ok = fkey(op == 4 ? ktype : (ktype == 1 ? 2u : 1u), 80); /* the OSD key may be of the other type */
	memset(&spec, 0, sizeof(spec));
	memcpy(spec.user, "fuzz", 5);
	spec.key = pk;
	check(wri_cx_client_init(&c, &x, &a, &spec) == WR_OK);
	{
		uint8_t nb[8];

		(void)fuzz_random(NULL, nb, sizeof(nb)); /* the first draw is the OSD authorizer nonce */
		nonce = wri_le64_get(nb);
	}
	chal[0] = 1;
	wri_le64_put(chal + 1, 0x1122334455667788ull);
	obuf = (uint8_t *)calloc(2048, 1);
	if (obuf == NULL)
		exit(2);
	wri_wr_init(&w, obuf, 2048);

	if (sealed && op >= 5) {
		uint8_t pbuf[1700];
		wri_wr pw;
		const uint8_t *q = data + 2;
		size_t left = size - 2, n1 = data[1], n2 = 0, bl2;
		wr_key old = fkey(ktype, 90);
		int okb;

		wri_wr_init(&pw, pbuf, sizeof(pbuf));
		wri_wr_u16(&pw, WRI_CX_REQ_GET_AUTH_SESSION_KEY);
		wri_wr_i32(&pw, 0);
		if (op == 6) {
			if (n1 > left)
				n1 = left;
			okb = put_auth_ticket(&x, &pk, &ak, 1, &old, q, n1, &pw);
			c.want_mask = WRI_CX_SERVICE_AUTH;
		} else {
			uint8_t cbl_item[200], cbl_ct[320], ext_ct[400], tk[200];
			size_t cn = 0, en = 0;

			okb = put_auth_ticket(&x, &pk, &ak, 0, NULL, NULL, 0, &pw);
			if (n1 > left)
				n1 = left;
			if (n1 > sizeof(cbl_item))
				n1 = sizeof(cbl_item);
			memcpy(cbl_item, q, n1);
			q += n1;
			left -= n1;
			if (left != 0) {
				n2 = q[0];
				q++;
				left--;
			}
			if (n2 > left)
				n2 = left;
			if (n2 > sizeof(tk))
				n2 = sizeof(tk);
			memcpy(tk, q, n2);
			q += n2;
			left -= n2;
			bl2 = left > 600 ? 600 : left;
			okb = okb && wri_cx_seal(&x, &ak, WRI_CX_USAGE_CONN_SECRET, cbl_item, n1, cbl_ct, sizeof(cbl_ct), &cn) == WR_OK &&
			      wri_cx_seal(&x, &ak, WRI_CX_USAGE_TICKET_SESSION_KEY, tk, n2, ext_ct, sizeof(ext_ct), &en) == WR_OK;
			if (okb) {
				wri_wr_u32(&pw, (uint32_t)(cn + 4)); /* cbl: u32 outer | u32 inner | ct */
				wri_wr_u32(&pw, (uint32_t)cn);
				wri_wr_bytes(&pw, cbl_ct, cn);
				wri_wr_u32(&pw, (uint32_t)(1 + 4 + 4 + 1 + 4 + en + 1 + 4 + bl2)); /* extra: one ticket reply */
				wri_wr_u8(&pw, 1);
				wri_wr_u32(&pw, 1);
				wri_wr_u32(&pw, WRI_CX_SERVICE_OSD);
				wri_wr_u8(&pw, 1);
				wri_wr_u32(&pw, (uint32_t)en);
				wri_wr_bytes(&pw, ext_ct, en);
				wri_wr_u8(&pw, 0);
				wri_wr_u32(&pw, (uint32_t)bl2);
				wri_wr_bytes(&pw, q, bl2);
			}
		}
		if (!okb || !wri_wr_ok(&pw))
			goto done;
		pn = wri_wr_len(&pw);
		pl = heap_copy(pbuf, pn);
	} else if (sealed && (op == 0 || op == 4)) {
		ilen = data[1];
		if (ilen > size - 2)
			ilen = size - 2;
		blen = size - 2 - ilen;
		pl = (uint8_t *)calloc(1400, 1);
		if (pl == NULL)
			exit(2);
		pn = build_sealed_ticket(&x, op == 0 ? &pk : &ak, op == 0 ? WRI_CX_SERVICE_AUTH : WRI_CX_SERVICE_OSD, op == 0 ? 1 : 2,
					 data + 2, ilen, data + 2 + ilen, blen > 600 ? 600 : blen, big, sizeof(big));
		free(pl);
		if (pn == 0)
			goto done;
		pl = heap_copy(big, pn); /* exact size, so ASan sees an over-read of the sealed payload too */
	} else {
		pn = size - 1;
		pl = heap_copy(data + 1, pn);
	}

	switch (op) {
	case 5:
	case 6:
	case 0: /* monitor AUTH_DONE */
		if (op == 0 && sealed)
			c.want_mask = WRI_CX_SERVICE_AUTH;
		if (op == 6) { /* the machine holds an AUTH ticket and a global id: the connection reclaims */
			wr_key oldk = fkey(ktype, 90);

			install(&c, WRI_CX_SLOT_AUTH, WRI_CX_SERVICE_AUTH, &oldk);
			c.global_id = 1000;
		}
		check(ops->begin(&c, WRI_ENTITY_MON, &w) == WR_OK);
		check(c.req_new_gid == (op == 6 ? 0u : 1u));
		wri_wr_init(&w, obuf, 2048);
		check(ops->more(&c, chal, sizeof(chal), &w) == WR_OK);
		st = ops->done(&c, 1000, WRI_CONN_MODE_CRC, pl, pn);
		if (st == WR_OK) {
			check(c.st == WRI_CX_DONE && c.global_id == 1000 && c.ticket[WRI_CX_SLOT_AUTH].have);
			check(op != 5 || c.ticket[WRI_CX_SLOT_OSD].have);
			check(c.ticket[0].blob_len >= 13 && c.ticket[0].blob_len <= c.ticket_cap && c.ticket[0].valid_until_ms > 1000);
			check(c.ticket[0].renew_at_ms <= c.ticket[0].valid_until_ms && c.sess_key != NULL);
		} else {
			check(c.st == WRI_CX_FAILED && !c.ticket[0].have && !c.ticket[1].have && c.global_id == 0 && c.sess_key == NULL);
		}
		break;
	case 1: /* monitor AUTH_REPLY_MORE */
		check(ops->begin(&c, WRI_ENTITY_MON, &w) == WR_OK);
		wri_wr_init(&w, obuf, 2048);
		st = ops->more(&c, pl, pn, &w);
		check(st == WR_OK ? c.st == WRI_CX_MON_SENT_AUTH && c.server_challenge != 0 : c.st == WRI_CX_FAILED);
		break;
	case 2:
	case 3: {
		uint8_t item[160], ct[400], rep[420];
		size_t cn = 0;

		install(&c, WRI_CX_SLOT_OSD, WRI_CX_SERVICE_OSD, &ok);
		c.global_id = 1000;
		check(ops->begin(&c, WRI_ENTITY_OSD, &w) == WR_OK);
		wri_wr_init(&w, obuf, 2048);
		if (op == 2) {
			if (sealed) {
				size_t k = pn < sizeof(item) ? pn : sizeof(item);

				memcpy(item, pl, k);
				check(wri_cx_seal(&x, &ok, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, item, k, ct, sizeof(ct), &cn) == WR_OK);
				st = ops->more(&c, ct, cn, &w);
			} else {
				st = ops->more(&c, pl, pn, &w);
			}
			check(st == WR_OK ? c.st == WRI_CX_OSD_SENT_CHALLENGE : c.st == WRI_CX_FAILED && c.authorizer_nonce == 0);
		} else {
			item[0] = 1;
			wri_le64_put(item + 1, 0x0123456789abcdefull);
			check(wri_cx_seal(&x, &ok, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, item, 9, ct, sizeof(ct), &cn) == WR_OK);
			check(ops->more(&c, ct, cn, &w) == WR_OK);
			if (sealed) {
				size_t k = pn < sizeof(item) ? pn : sizeof(item);

				memcpy(item, pl, k);
				if (k >= 9)
					wri_le64_put(item + 1, nonce + 1u);
				check(wri_cx_seal(&x, &ok, WRI_CX_USAGE_AUTHORIZE_REPLY, item, k, ct, sizeof(ct), &cn) == WR_OK);
				wri_le32_put(rep, (uint32_t)cn);
				memcpy(rep + 4, ct, cn);
				st = ops->done(&c, 1000, WRI_CONN_MODE_CRC, rep, cn + 4);
			} else {
				st = ops->done(&c, 1000, WRI_CONN_MODE_CRC, pl, pn);
			}
			if (st == WR_OK)
				check(c.st == WRI_CX_DONE && c.sess_key != NULL && c.authorizer_nonce == 0);
			else
				check(c.st == WRI_CX_FAILED && c.sess_key == NULL && c.authorizer_nonce == 0);
		}
		break;
	}
	default: { /* 4: renewal reply */
		uint8_t before[WR_KEY_MAX + 8];
		uint32_t gen;

		install(&c, WRI_CX_SLOT_AUTH, WRI_CX_SERVICE_AUTH, &ak);
		install(&c, WRI_CX_SLOT_OSD, WRI_CX_SERVICE_OSD, &ok);
		c.global_id = 1000;
		c.renew_mask = WRI_CX_SERVICE_OSD;
		memcpy(before, c.ticket[1].session_key.secret, WR_KEY_MAX);
		gen = c.ticket[1].gen;
		st = wri_cx_renew_handle(&c, pl, pn);
		if (st != WR_OK) /* a failure that stored nothing leaves the ticket as it was */
			check(c.ticket[1].gen == gen ? memcmp(before, c.ticket[1].session_key.secret, WR_KEY_MAX) == 0 : 1);
		check(c.ticket[0].have && c.ticket[1].have);
		check(c.ticket[1].blob_len >= 13 && c.ticket[1].blob_len <= c.ticket_cap);
		break;
	}
	}
	free(pl);
done:
	wri_cx_client_wipe(&c);
	{
		size_t i;

		for (i = 0; i < need; i++) /* every byte of the arena the machine used is zero again */
			check(mem[i] == 0);
	}
	free(obuf);
	free(raw);
	return 0;
}
