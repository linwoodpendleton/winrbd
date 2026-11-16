/* SPDX-License-Identifier: MIT */
/*
 * wri_cx_ticket.c - the cephx ticket store and the decoder of a "ticket reply" (docs/spec/cephx.md
 * 2.7, 3.2 step 4, 3.4, 3.5).
 *
 * Store. Two slots, AUTH and OSD (the only services this client ever connects to; MON and MGR
 * tickets a server sends along are skipped). A slot holds the session key (with its own cipher type,
 * which may differ from the principal key's), the opaque ticket blob in arena memory, and two local
 * deadlines: the server sends a validity DURATION, so valid_until = receipt time + validity on the
 * local monotonic clock, and renew_at = valid_until - validity_seconds / 4 with the real-valued
 * quarter (seconds * 250 ms, the nanoseconds of the validity do not count towards the quarter). A
 * ticket is held while now < valid_until; a validity of zero is refused (it would be born expired).
 *
 * Ticket reply:  u8 v | u32 num | per ticket { u32 service | u8 v | u32 len + msg_a | u8 enc | u32
 * len + blob }. msg_a is the sealed CephXServiceTicket (session key + validity) under usage 0x04; the
 * key is the principal key for the AUTH ticket of the first reply and the AUTH session key for every
 * later one. enc = 1 (only on a reconnect that presented the old AUTH ticket) means the blob field is
 * itself sealed with the PREVIOUS AUTH session key under usage 0x05. A ticket is decoded into locals,
 * validated completely, and only then written to its slot, so a bad ticket never leaves a slot
 * half-updated. Decrypted material lives in the client scratch and is wiped right after it was
 * copied out. Every length from the wire is capped before use (ticket_cap, the scratch size, the
 * ticket count); a decrypt, MAC or magic failure of anything is WR_E_AUTH_DECRYPT.
 */
#include "wri_cx.h"

#include "wri_le.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define CX_BLOB_HDR 13u          /* CephXTicketBlob: u8 v | u64 secret_id | u32 len */
#define CX_MAX_TICKETS 8u        /* tickets accepted in one reply (one per service bit at most) */
#define CX_TICKET_MIN_WIRE 14u   /* smallest encoded ticket: 4 + 1 + 4 + 1 + 4 */
#define CX_MSGA_MAX 512u         /* largest msg_a ciphertext accepted */
#define CX_SCRATCH_MIN 512u
#define CX_SCRATCH_SLACK 160u    /* envelope + padding / confounder + MAC around a ticket blob */
#define CX_TICKET_CAP_MAX 65536u
#define CX_KEY_HDR 12u           /* u16 type | utime created | u16 len */

int wri_cx_slot_of(uint32_t service)
{
	if (service == WRI_CX_SERVICE_AUTH)
		return (int)WRI_CX_SLOT_AUTH;
	if (service == WRI_CX_SERVICE_OSD)
		return (int)WRI_CX_SLOT_OSD;
	return -1;
}

wr_status wri_cx_fail(wri_cx_client *c, wr_status st, unsigned line, const char *what, uint64_t a0, uint64_t a1,
		      uint64_t a2)
{
	wri_errinfo_set(&c->err, st, WR_MOD_AUTH, line, what, a0, a1, a2);
	return st;
}

/* ---- memory, init, wipe ---------------------------------------------------------------------- */

static wr_status cx_scratch_size(uint32_t ticket_cap, size_t *out)
{
	size_t n = (size_t)ticket_cap + CX_SCRATCH_SLACK;

	if (n < CX_SCRATCH_MIN)
		n = CX_SCRATCH_MIN;
	return wri_align_up(n, 16u, out);
}

/* The sizes depend only on the config; one routine so mem() and init() cannot disagree. */
static wr_status cx_plan(const wr_config *cfg, size_t *used, size_t *scratch_n)
{
	wr_status st;
	unsigned i;

	if (cfg == NULL || used == NULL)
		return WR_E_INVAL;
	if (cfg->ticket_cap < CX_BLOB_HDR || cfg->ticket_cap > CX_TICKET_CAP_MAX)
		return WR_E_INVAL;
	*used = 0;
	for (i = 0; i < WRI_CX_NTICKETS; i++) {
		st = wri_arena_plan(used, cfg->ticket_cap, 16u);
		if (st != WR_OK)
			return st;
	}
	st = cx_scratch_size(cfg->ticket_cap, scratch_n);
	if (st != WR_OK)
		return st;
	return wri_arena_plan(used, *scratch_n, 16u);
}

wr_status wri_cx_client_mem(const wr_config *cfg, size_t *arena_bytes)
{
	size_t used = 0, sn = 0;
	wr_status st;

	if (arena_bytes == NULL)
		return WR_E_INVAL;
	*arena_bytes = 0;
	st = cx_plan(cfg, &used, &sn);
	if (st == WR_OK)
		*arena_bytes = used;
	return st;
}

void wri_cx_client_wipe(wri_cx_client *c)
{
	unsigned i;

	if (c == NULL)
		return;
	for (i = 0; i < WRI_CX_NTICKETS; i++)
		if (c->ticket[i].blob != NULL)
			wri_secure_zero(c->ticket[i].blob, c->ticket_cap);
	if (c->scratch != NULL)
		wri_secure_zero(c->scratch, c->scratch_cap);
	wri_secure_zero(c, sizeof(*c)); /* keys, challenges, nonce, user, every pointer */
}

/* The id of the user: strip one leading "client.", then 1 .. WR_ENTITY_MAX - 1 bytes before the NUL. */
static wr_status cx_set_user(wri_cx_client *c, const char *user)
{
	static const char pre[] = "client.";
	size_t n = 0, skip = 0, i;

	while (n < WR_ENTITY_MAX && user[n] != '\0')
		n++;
	if (n == WR_ENTITY_MAX)
		return WR_E_INVAL; /* not NUL terminated within the field */
	if (n >= sizeof(pre) - 1u) {
		for (i = 0; i < sizeof(pre) - 1u; i++)
			if (user[i] != pre[i])
				break;
		if (i == sizeof(pre) - 1u)
			skip = i;
	}
	if (n - skip == 0)
		return WR_E_INVAL;
	WR_MEMCPY(c->user, user + skip, n - skip);
	c->user[n - skip] = '\0';
	c->user_len = (uint8_t)(n - skip);
	return WR_OK;
}

wr_status wri_cx_client_init(wri_cx_client *c, const wri_ctx *x, wri_arena *a, const wr_cluster_spec *spec)
{
	size_t used = 0, sn = 0;
	wr_status st;
	unsigned i;

	if (c == NULL)
		return WR_E_INVAL;
	WR_MEMSET(c, 0, sizeof(*c));
	if (x == NULL || a == NULL || spec == NULL)
		return WR_E_INVAL;
	st = cx_plan(&x->cfg, &used, &sn);
	if (st != WR_OK)
		return st;
	st = cx_set_user(c, spec->user);
	if (st == WR_OK)
		st = wr_key_from_raw(&c->principal, spec->key.type, spec->key.secret, spec->key.len);
	if (st == WR_OK) {
		c->ticket_cap = x->cfg.ticket_cap;
		c->scratch_cap = (uint32_t)sn; /* <= 65536 + 176 */
		for (i = 0; i < WRI_CX_NTICKETS && st == WR_OK; i++) {
			c->ticket[i].blob = (uint8_t *)wri_arena_take(a, c->ticket_cap, 16u);
			if (c->ticket[i].blob == NULL)
				st = WR_E_BUDGET;
		}
	}
	if (st == WR_OK) {
		c->scratch = (uint8_t *)wri_arena_take(a, sn, 16u);
		if (c->scratch == NULL)
			st = WR_E_BUDGET;
	}
	if (st != WR_OK) {
		wri_cx_client_wipe(c);
		return st;
	}
	c->x = x;
	c->st = WRI_CX_IDLE;
	c->want_mask = WRI_CX_WANT_MASK;
	return WR_OK;
}

void wri_cx_slot_clear(wri_cx_client *c, unsigned i)
{
	wri_cx_ticket *t = &c->ticket[i];

	wr_key_wipe(&t->session_key);
	if (t->blob != NULL)
		wri_secure_zero(t->blob, c->ticket_cap);
	t->have = 0;
	t->service = 0;
	t->secret_id = 0;
	t->blob_len = 0;
	t->valid_until_ms = 0;
	t->renew_at_ms = 0;
	t->gen++; /* a handshake that held the old ticket must notice */
}

void wri_cx_forget(wri_cx_client *c)
{
	unsigned i;

	if (c == NULL)
		return;
	for (i = 0; i < WRI_CX_NTICKETS; i++)
		wri_cx_slot_clear(c, i);
	if (c->scratch != NULL)
		wri_secure_zero(c->scratch, c->scratch_cap);
	c->global_id = 0;
	c->server_challenge = 0;
	c->client_challenge = 0;
	c->authorizer_nonce = 0;
	c->renew_mask = 0;
	c->sess_key = NULL;
	c->sess_key_len = 0;
	c->req_new_gid = 0;
	c->st = WRI_CX_IDLE;
}

/* ---- queries ----------------------------------------------------------------------------------- */

const wri_cx_ticket *wri_cx_ticket_get(const wri_cx_client *c, uint32_t service)
{
	int s = wri_cx_slot_of(service);

	if (c == NULL || s < 0 || !c->ticket[s].have)
		return NULL;
	return &c->ticket[s];
}

int wri_cx_have(const wri_cx_client *c, uint32_t service, uint64_t now_ms)
{
	const wri_cx_ticket *t = wri_cx_ticket_get(c, service);

	return t != NULL && now_ms < t->valid_until_ms;
}

uint64_t wri_cx_next_renew_ms(const wri_cx_client *c)
{
	uint64_t best = WR_DEADLINE_NONE;
	unsigned i;

	if (c == NULL)
		return best;
	for (i = 0; i < WRI_CX_NTICKETS; i++)
		if (c->ticket[i].have && c->ticket[i].renew_at_ms < best)
			best = c->ticket[i].renew_at_ms;
	return best;
}

/* ---- ticket reply ------------------------------------------------------------------------------ */

/* A decoded, validated ticket waiting to be stored. */
typedef struct cx_pending {
	uint32_t service;
	wr_key key;
	uint32_t validity_s;
	uint64_t validity_ms;
	const uint8_t *blob; /* encoded CephXTicketBlob: wire bytes or the scratch; valid until the next decrypt */
	uint32_t blob_len;
} cx_pending;

static void cx_store(wri_cx_client *c, unsigned slot, const cx_pending *p, uint64_t now)
{
	wri_cx_ticket *t = &c->ticket[slot];
	uint64_t until = now + p->validity_ms;

	if (until < now) /* a validity that would wrap the clock: as far as the clock goes */
		until = UINT64_MAX;
	wri_secure_zero(t->blob, c->ticket_cap); /* nothing of a longer old blob stays behind */
	WR_MEMCPY(t->blob, p->blob, p->blob_len);
	t->blob_len = p->blob_len;
	t->secret_id = wri_le64_get(p->blob + 1);
	t->session_key = p->key;
	t->service = p->service;
	t->valid_until_ms = until;
	t->renew_at_ms = until - (uint64_t)p->validity_s * 250u; /* a quarter of the whole seconds, in ms */
	t->have = 1;
	t->gen++;
}

/* msg_a: sealed CephXServiceTicket {u8 v | CryptoKey session_key | utime validity}. */
static wr_status cx_open_msga(wri_cx_client *c, const wr_key *mk, const uint8_t *ct, uint32_t n, cx_pending *p)
{
	const uint8_t *item = NULL, *sec;
	size_t ilen = 0;
	wri_rd r;
	unsigned ktype;
	uint32_t klen, nsec;
	wr_status st;

	st = wri_cx_open(c->x, mk, WRI_CX_USAGE_TICKET_SESSION_KEY, ct, n, c->scratch, c->scratch_cap, &item, &ilen);
	if (st != WR_OK)
		return WRI_CX_FAIL(c, WR_E_AUTH_DECRYPT, "ticket key does not decrypt", (uint64_t)(-(int64_t)st), n,
				   p->service);
	wri_rd_init(&r, item, ilen);
	(void)wri_rd_u8(&r); /* struct version, not checked (cephx.md 1.3) */
	ktype = wri_rd_u16(&r);
	wri_rd_skip(&r, 8); /* created */
	klen = wri_rd_u16(&r);
	sec = wri_rd_bytes(&r, klen);
	p->validity_s = wri_rd_u32(&r);
	nsec = wri_rd_u32(&r);
	if (!wri_rd_ok(&r)) {
		st = WRI_CX_FAIL(c, r.err, "ticket key structure truncated", ilen, r.pos, p->service);
	} else if (nsec >= 1000000000u) {
		st = WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "ticket validity nanoseconds out of range", nsec, 0, p->service);
	} else {
		p->validity_ms = (uint64_t)p->validity_s * 1000u + nsec / 1000000u;
		st = wr_key_from_raw(&p->key, ktype, sec, klen);
		if (st != WR_OK)
			st = WRI_CX_FAIL(c, st, "ticket carries an unusable session key", ktype, klen, p->service);
		else if (p->validity_ms == 0)
			st = WRI_CX_FAIL(c, WR_E_AUTH_TICKET_EXPIRED, "ticket validity is zero", p->service, 0, 0);
	}
	wri_secure_zero(c->scratch, c->scratch_cap); /* the session key was in there */
	return st;
}

/* The blob of enc = 1: sealed bufferlist (u32 len | bytes) under the previous AUTH session key. */
static wr_status cx_open_blob(wri_cx_client *c, const uint8_t *ct, uint32_t n, cx_pending *p)
{
	const uint8_t *item = NULL;
	size_t ilen = 0;
	wri_rd r;
	uint32_t bl;
	wr_status st;

	if (!c->ticket[WRI_CX_SLOT_AUTH].have)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "encrypted ticket but no previous AUTH key held", p->service, 0, 0);
	if (n > c->scratch_cap)
		return WRI_CX_FAIL(c, WR_E_AUTH_TICKET_TOOBIG, "encrypted ticket larger than the scratch", n,
				   c->scratch_cap, p->service);
	st = wri_cx_open(c->x, &c->ticket[WRI_CX_SLOT_AUTH].session_key, WRI_CX_USAGE_TICKET_BLOB, ct, n,
			 c->scratch, c->scratch_cap, &item, &ilen);
	if (st != WR_OK)
		return WRI_CX_FAIL(c, WR_E_AUTH_DECRYPT, "ticket blob does not decrypt", (uint64_t)(-(int64_t)st), n,
				   p->service);
	wri_rd_init(&r, item, ilen);
	bl = wri_rd_u32(&r);
	p->blob = wri_rd_bytes(&r, bl);
	if (!wri_rd_ok(&r)) {
		wri_secure_zero(c->scratch, c->scratch_cap);
		return WRI_CX_FAIL(c, r.err, "decrypted ticket blob truncated", ilen, bl, p->service);
	}
	p->blob_len = bl;
	return WR_OK;
}

/* The blob must fit the budget and be a well-formed CephXTicketBlob (13 byte header, matching length). */
static wr_status cx_check_blob(wri_cx_client *c, const cx_pending *p)
{
	if (p->blob_len > c->ticket_cap)
		return WRI_CX_FAIL(c, WR_E_AUTH_TICKET_TOOBIG, "ticket larger than ticket_cap", p->blob_len,
				   c->ticket_cap, p->service);
	if (p->blob_len < CX_BLOB_HDR || (uint64_t)wri_le32_get(p->blob + 9) != (uint64_t)p->blob_len - CX_BLOB_HDR)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "ticket blob is not a CephXTicketBlob", p->blob_len, 0,
				   p->service);
	return WR_OK;
}

wr_status wri_cx_ticket_reply(wri_cx_client *c, wri_rd *r, unsigned kind, uint32_t *stored)
{
	const wr_key *mk;
	uint32_t num, i, got = 0;
	wr_status st = WR_OK;
	uint64_t now;

	if (stored != NULL)
		*stored = 0;
	if (c == NULL || c->x == NULL || r == NULL)
		return WR_E_INVAL;
	if (kind == WRI_CX_TR_INITIAL) {
		mk = &c->principal;
	} else {
		if (!c->ticket[WRI_CX_SLOT_AUTH].have)
			return WRI_CX_FAIL(c, WR_E_STATE, "no AUTH session key to open the tickets with", 0, 0, 0);
		mk = &c->ticket[WRI_CX_SLOT_AUTH].session_key;
	}
	now = c->x->now.mono_ms;
	(void)wri_rd_u8(r); /* reply version */
	num = wri_rd_count(r, CX_MAX_TICKETS, CX_TICKET_MIN_WIRE);
	if (!wri_rd_ok(r))
		return WRI_CX_FAIL(c, r->err, "ticket reply header", 0, 0, 0);
	if (kind == WRI_CX_TR_INITIAL && num != 1u)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "first reply must carry exactly one ticket", num, 0, 0);

	for (i = 0; i < num && st == WR_OK; i++) {
		cx_pending p;
		const uint8_t *a, *b;
		uint32_t alen, blen, enc;
		int slot;

		WR_MEMSET(&p, 0, sizeof(p));
		p.service = wri_rd_u32(r);
		(void)wri_rd_u8(r); /* ticket version */
		alen = wri_rd_u32(r);
		if (alen > CX_MSGA_MAX && wri_rd_ok(r)) {
			st = WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "ticket key ciphertext too long", alen, CX_MSGA_MAX, p.service);
			break;
		}
		a = wri_rd_bytes(r, alen);
		enc = wri_rd_u8(r);
		blen = wri_rd_u32(r);
		b = wri_rd_bytes(r, blen);
		if (!wri_rd_ok(r)) {
			st = WRI_CX_FAIL(c, r->err, "ticket entry truncated", i, p.service, r->pos);
			break;
		}
		slot = wri_cx_slot_of(p.service);
		if (kind == WRI_CX_TR_INITIAL ? p.service != WRI_CX_SERVICE_AUTH : p.service == WRI_CX_SERVICE_AUTH) {
			st = WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "ticket for an unexpected service", p.service, kind, 0);
			break;
		}
		if (slot < 0)
			continue; /* MON, MGR, ...: not kept, not decrypted */
		if (enc > 1u || (enc == 1u && kind != WRI_CX_TR_INITIAL)) {
			st = WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "unexpected ticket encryption flag", enc, p.service, 0);
			break;
		}
		st = cx_open_msga(c, mk, a, alen, &p);
		if (st != WR_OK) {
			wr_key_wipe(&p.key); /* a key that parsed but was refused (zero validity) must not stay on the stack */
			break;
		}
		if (enc == 0u) {
			p.blob = b;
			p.blob_len = blen;
		} else {
			st = cx_open_blob(c, b, blen, &p);
			if (st != WR_OK) {
				wr_key_wipe(&p.key);
				break;
			}
		}
		st = cx_check_blob(c, &p);
		if (st == WR_OK) {
			cx_store(c, (unsigned)slot, &p, now);
			got |= p.service;
		}
		wri_secure_zero(c->scratch, c->scratch_cap); /* p.blob may have pointed into it */
		wr_key_wipe(&p.key);
	}
	if (stored != NULL)
		*stored = got;
	return st;
}
