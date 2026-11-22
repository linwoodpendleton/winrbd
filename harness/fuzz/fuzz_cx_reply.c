/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the cephx client machine's reply decoders (core/src/auth/wri_cx_client.c,
 * wri_cx_ticket.c, wri_cx_renew.c): the AUTH_REPLY_MORE and AUTH_DONE payloads of a monitor and an OSD
 * connection, and the renewal reply, against a machine with fixed keys.
 *
 * Byte 0: bits 0..2 the operation, bit 3 the key type (0: type 1, 1: type 2), bit 5 "slot" (the handshake runs on a wri_cx_hs
 * of its own through wri_cx_hs_ops() instead of the client's embedded one through wri_cx_ops(); the same checks hold), bit 6 "secure" (the connection
 * mode the AUTH_DONE is given: crc when clear, secure when set; it matters for the operations that end in a
 * done()), bit 7 "sealed".
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
 * Secure mode (architecture 34.3): op 5 and op 3 carry the connection secret (the plaintext item the input
 * controls: op 5 u32 len | bytes under usage 0x03, op 3 the version byte, the secret length and bytes), so the
 * length rules (40 .. 128, none, crc with one) are reached from both sides. Whenever done() succeeds in secure
 * mode conn_secret() hands out a secret of 40 .. 128 bytes exactly once and the held copy is gone after; in crc
 * mode, and whenever done() fails, there never is one and the record is all zero.
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

static int zero_bytes(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != 0)
			return 0;
	return 1;
}

/* The connection secret after a done() that returned st in `mode` (34.3), through the ops the machine ran on: `a` is the
 * handshake the ops table is called with (the client's embedded one, or a slot) and `sec` the record it holds. */
static void check_secret(const wri_auth_ops *ops, void *a, const wri_cx_client *c, const wri_cx_secret *sec, uint32_t mode, wr_status st)
{
	const uint8_t *s = (const uint8_t *)1;
	size_t n = 7;

	check(ops->conn_secret != NULL);
	if (st == WR_OK && mode == WRI_CONN_MODE_SECURE) {
		check(sec->len >= WRI_CX_SECRET_MIN && sec->len <= WRI_CX_SECRET_MAX && !sec->taken);
		ops->conn_secret(a, &s, &n);
		check(s == sec->buf && n == sec->len && sec->taken);
		ops->conn_secret(a, &s, &n); /* read once: the second call gives nothing and wipes */
	} else {
		check(zero_bytes(sec, sizeof(*sec))); /* crc, or a failure: there is no secret */
		ops->conn_secret(a, &s, &n);
	}
	check(s == NULL && n == 0 && zero_bytes(sec, sizeof(*sec)));
	check(zero_bytes(c->scratch, c->scratch_cap)); /* the decrypted item is gone */
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

/* a field of the handshake the run drives: the slot's own, or the client's embedded one */
#define HS(f) (slot ? hs.f : c.f)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	unsigned op, ktype;
	int sealed;
	uint32_t mode;
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
	wri_cx_hs hs;      /* the slot of the run when bit 5 of byte 0 is set: the same machine through wri_cx_hs_ops() */
	void *ah = &c;     /* what the ops are called with */
	int slot;
	wr_status st;
	uint64_t nonce;
	size_t ilen, blen;

	if (size < 1)
		return 0;
	op = data[0] & 7u;
	ktype = (data[0] & 8u) != 0 ? WR_KEY_TYPE_AES256K : WR_KEY_TYPE_AES;
	sealed = (data[0] & 0x80u) != 0;
	mode = (data[0] & 0x40u) != 0 ? WRI_CONN_MODE_SECURE : WRI_CONN_MODE_CRC;
	slot = (data[0] & 0x20u) != 0;
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
	memset(&hs, 0, sizeof(hs));
	if (slot) {
		check(wri_cx_hs_init(&hs, &c) == WR_OK);
		ops = wri_cx_hs_ops();
		ah = &hs;
	}
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
		check(ops->begin(ah, WRI_ENTITY_MON, &w) == WR_OK);
		check(HS(req_new_gid) == (op == 6 ? 0u : 1u));
		wri_wr_init(&w, obuf, 2048);
		check(ops->more(ah, chal, sizeof(chal), &w) == WR_OK);
		st = ops->done(ah, 1000, mode, pl, pn);
		check_secret(ops, ah, &c, slot ? &hs.sec : &c.sec, mode, st);
		if (st == WR_OK) {
			check(HS(st) == WRI_CX_DONE && c.global_id == 1000 && c.ticket[WRI_CX_SLOT_AUTH].have);
			check(op != 5 || c.ticket[WRI_CX_SLOT_OSD].have);
			check(c.ticket[0].blob_len >= 13 && c.ticket[0].blob_len <= c.ticket_cap && c.ticket[0].valid_until_ms > 1000);
			check(c.ticket[0].renew_at_ms <= c.ticket[0].valid_until_ms && HS(sess_key) != NULL);
		} else {
			check(HS(st) == WRI_CX_FAILED && !c.ticket[0].have && !c.ticket[1].have && c.global_id == 0 && HS(sess_key) == NULL);
		}
		break;
	case 1: /* monitor AUTH_REPLY_MORE */
		check(ops->begin(ah, WRI_ENTITY_MON, &w) == WR_OK);
		wri_wr_init(&w, obuf, 2048);
		st = ops->more(ah, pl, pn, &w);
		check(st == WR_OK ? HS(st) == WRI_CX_MON_SENT_AUTH && HS(server_challenge) != 0 : HS(st) == WRI_CX_FAILED);
		break;
	case 2:
	case 3: {
		uint8_t item[160], ct[400], rep[420];
		size_t cn = 0;

		install(&c, WRI_CX_SLOT_OSD, WRI_CX_SERVICE_OSD, &ok);
		c.global_id = 1000;
		check(ops->begin(ah, WRI_ENTITY_OSD, &w) == WR_OK);
		wri_wr_init(&w, obuf, 2048);
		if (op == 2) {
			if (sealed) {
				size_t k = pn < sizeof(item) ? pn : sizeof(item);

				memcpy(item, pl, k);
				check(wri_cx_seal(&x, &ok, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, item, k, ct, sizeof(ct), &cn) == WR_OK);
				st = ops->more(ah, ct, cn, &w);
			} else {
				st = ops->more(ah, pl, pn, &w);
			}
			check(st == WR_OK ? HS(st) == WRI_CX_OSD_SENT_CHALLENGE : HS(st) == WRI_CX_FAILED && HS(authorizer_nonce) == 0);
		} else {
			item[0] = 1;
			wri_le64_put(item + 1, 0x0123456789abcdefull);
			check(wri_cx_seal(&x, &ok, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, item, 9, ct, sizeof(ct), &cn) == WR_OK);
			check(ops->more(ah, ct, cn, &w) == WR_OK);
			if (sealed) {
				size_t k = pn < sizeof(item) ? pn : sizeof(item);

				memcpy(item, pl, k);
				if (k >= 9)
					wri_le64_put(item + 1, nonce + 1u);
				check(wri_cx_seal(&x, &ok, WRI_CX_USAGE_AUTHORIZE_REPLY, item, k, ct, sizeof(ct), &cn) == WR_OK);
				wri_le32_put(rep, (uint32_t)cn);
				memcpy(rep + 4, ct, cn);
				st = ops->done(ah, 1000, mode, rep, cn + 4);
			} else {
				st = ops->done(ah, 1000, mode, pl, pn);
			}
			check_secret(ops, ah, &c, slot ? &hs.sec : &c.sec, mode, st);
			if (st == WR_OK)
				check(HS(st) == WRI_CX_DONE && HS(sess_key) != NULL && HS(authorizer_nonce) == 0);
			else
				check(HS(st) == WRI_CX_FAILED && HS(sess_key) == NULL && HS(authorizer_nonce) == 0);
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
	wri_cx_hs_wipe(&hs);
	check(zero_bytes(&hs, sizeof(hs)));
	{
		size_t i;

		for (i = 0; i < need; i++) /* every byte of the arena the machine used is zero again */
			check(mem[i] == 0);
	}
	free(obuf);
	free(raw);
	return 0;
}
