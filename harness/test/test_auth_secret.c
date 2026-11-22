/* SPDX-License-Identifier: MIT */
/*
 * The connection secret of secure mode in the cephx client machine (core/src/auth/wri_cx_hs.c, wri_cx_client.c;
 * architecture 34.3). The monitor's AUTH_DONE carries it in the blob `cbl` (usage 0x03, under the AUTH session
 * key), an OSD's in version 2 of the sealed authorizer reply (usage 0x12, under the service ticket's key); the
 * machine judges it against the mode, keeps it in the handshake and hands it to the connection through the
 * conn_secret member of both ops tables.
 *
 *   - vectors     : harness/vectors/secure/connection-secret-blob-synthetic.json (the real cbl bytes of both key
 *                   types, secure and crc, with their 64-byte secrets) and captured-structure.json (every kind of
 *                   session of the lab captures: peer, mode, key type, secret length, reply version, other_keys)
 *   - sessions    : harness/vectors/cephx/session-type{1,2}-secure.json (three connections each, built by an independent
 *                   generator): the client's bytes equal the vector's, the secret, session key and both signatures come out
 *                   as the vector's, for the monitor and for the OSD reply of version 2, on the embedded handshake and on slots
 *   - table       : every row of the table of 34.3 on both key types and both ops tables, monitor and OSD, with
 *                   servers built from the cipher layer only (wri_cx_seal): 40 .. 128 bytes kept, none / short /
 *                   long M2_SECRET, a secret in crc mode AUTH_PROTO, a mode that is neither M2_MODE, a blob that
 *                   does not decrypt AUTH_DECRYPT, a wrong nonce AUTH_DECRYPT; other_keys is never 0
 *   - truncation  : both payloads cut at every offset, and both plaintext items cut at every offset
 *   - wiping      : after a failed done (also one that failed after the secret was stored), when the connection
 *                   took it, on the next call of the handshake, on forget, on a second done, on hs_init /
 *                   hs_wipe / client_wipe
 *   - isolation   : two OSD handshakes and a monitor handshake advanced in interleaved steps keep their own
 *                   secrets (with the monitor on a slot and on the embedded handshake)
 *   - canary      : no secret byte in an errinfo (raw bytes, text, numbers), the arena, the client or a slot once
 *                   it was taken or the handshake failed or was destroyed; a positive control finds it while held
 * The monitor and the OSD of the tests are the harness's, not the core's.
 */
#include "auth_cx_srv.h"

#include "wri_m2_sec.h"

#define GID 4100u

#if defined(__SANITIZE_ADDRESS__)
#define UNDER_SAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define UNDER_SAN 1
#endif
#endif
#ifndef UNDER_SAN
#define UNDER_SAN 0
#endif

/* the limits the secure codec enforces are the ones this machine enforces */
WRT_UNUSED static const char limits_agree[(WRI_CX_SECRET_MIN == WRI_M2S_SECRET_MIN && WRI_CX_SECRET_MAX == WRI_M2S_SECRET_MAX) ? 1 : -1];

/* ---- secrets and scans ---------------------------------------------------------------------------- */

/* A recognisable secret: no zero bytes, every 4- and 8-byte window is unique and far from any small number. In
 * the printable form (letters and digits) a leak into a message would also be found by a text search. */
static void mk_secret(uint8_t *out, size_t n, unsigned seed, int printable)
{
	static const char alpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	uint32_t s = 0x9E3779B9u * (seed + 1u);
	size_t i;

	for (i = 0; i < n; i++) {
		s = s * 1664525u + 1013904223u;
		if (printable)
			out[i] = (uint8_t)alpha[(s >> 24) % 62u];
		else
			out[i] = (uint8_t)(0x90u | ((s >> 24) & 0x6Fu));
	}
}

static int is_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != 0)
			return 0;
	return 1;
}

static int find_bytes(const uint8_t *hay, size_t hn, const uint8_t *needle, size_t nn)
{
	size_t i;

	if (nn == 0 || hn < nn)
		return 0;
	for (i = 0; i + nn <= hn; i++)
		if (hay[i] == needle[0] && memcmp(hay + i, needle, nn) == 0)
			return 1;
	return 0;
}

/* Does hay hold any 8-byte window of the secret? (a stray copy of any part of it) */
static int has_secret(const void *hay, size_t hn, const uint8_t *sec, size_t sn)
{
	size_t off;

	if (sec == NULL || sn < 8)
		return 0;
	for (off = 0; off + 8 <= sn; off += 4)
		if (find_bytes((const uint8_t *)hay, hn, sec + off, 8))
			return 1;
	return 0;
}

/* An errinfo is what the engine turns into a log record: raw struct bytes, the message, the numbers (as decimal and
 * as hex text, and as values). None of it may carry a window of the secret. */
static int errinfo_leaks(const wr_errinfo *e, const uint8_t *sec, size_t sn)
{
	char text[512];
	uint64_t nums[3];
	size_t off, k;
	int n;

	if (sec == NULL || sn < 8)
		return 0;
	if (has_secret(e, sizeof(*e), sec, sn))
		return 1;
	n = snprintf(text, sizeof(text), "%d %u %u %d %u %s %llu %llu %llu %llx %llx %llx", (int)e->status, (unsigned)e->module,
		     (unsigned)e->line, (int)e->peer_result, (unsigned)e->conn, e->what != NULL ? e->what : "",
		     (unsigned long long)e->a0, (unsigned long long)e->a1, (unsigned long long)e->a2,
		     (unsigned long long)e->a0, (unsigned long long)e->a1, (unsigned long long)e->a2);
	if (n < 0 || (size_t)n >= sizeof(text))
		return 1;
	for (off = 0; off + 8 <= sn; off++)
		if (find_bytes((const uint8_t *)text, (size_t)n, sec + off, 8))
			return 1;
	nums[0] = e->a0;
	nums[1] = e->a1;
	nums[2] = e->a2;
	for (off = 0; off + 4 <= sn; off++) {
		uint32_t le4 = wri_le32_get(sec + off);
		uint32_t be4 = ((uint32_t)sec[off] << 24) | ((uint32_t)sec[off + 1] << 16) | ((uint32_t)sec[off + 2] << 8) | sec[off + 3];

		for (k = 0; k < 3; k++)
			if (nums[k] == le4 || nums[k] == be4)
				return 1;
		if (off + 8 <= sn) {
			uint64_t le8 = wri_le64_get(sec + off), be8 = ((uint64_t)be4 << 32) | (uint64_t)(((uint32_t)sec[off + 4] << 24) |
				((uint32_t)sec[off + 5] << 16) | ((uint32_t)sec[off + 6] << 8) | sec[off + 7]);

			for (k = 0; k < 3; k++)
				if (nums[k] == le8 || nums[k] == be8)
					return 1;
		}
	}
	return 0;
}

/* ---- the world: a client, slots, a handshake driver --------------------------------------------------- */

typedef struct drv {
	const wri_auth_ops *ops;
	void *a;
	int slot;           /* 1: a wri_cx_hs of the world, 0: the embedded handshake of wri_cx_ops() */
	wri_cx_client *c;
} drv;

typedef struct sw {
	cxt_env e;
	wr_key pk, ak, ok;  /* principal, AUTH session key, OSD session key (what the "monitor" hands out) */
	unsigned pt, ot;
	uint8_t *hsraw;
	size_t hsbytes;
	wri_cx_hs *hs;
	uint32_t nhs;
} sw;

/* pk NULL: the principal key of the tests (cxt_key); else the given one (a vector's keyring key) */
static int sw_open_as(sw *w, unsigned pt, unsigned ot, const wr_key *pk, const char *user)
{
	size_t need = 0;
	wri_arena a;
	uint32_t i;

	memset(w, 0, sizeof(*w));
	w->pt = pt;
	w->ot = ot;
	w->pk = pk != NULL ? *pk : cxt_key(pt, 11);
	w->ak = cxt_key(pt, 21);
	w->ok = cxt_key(ot, 31);
	cxt_rng_free();
	if (cxt_env_init(&w->e, user, &w->pk, 0) != 0)
		return -1;
	w->e.x.cfg.max_handshakes = 4;
	if (wri_cx_hs_mem(&w->e.x.cfg, &need) != WR_OK)
		return -1;
	w->hsraw = (uint8_t *)calloc(1, need + WRI_ARENA_SLACK + 64);
	if (w->hsraw == NULL)
		return -1;
	w->hsbytes = need + WRI_ARENA_SLACK;
	wri_arena_init(&a, (uint8_t *)(((uintptr_t)w->hsraw + 63u) & ~(uintptr_t)63u), w->hsbytes);
	if (wri_cx_hs_carve(&a, &w->e.x.cfg, &w->hs, &w->nhs) != WR_OK || w->nhs < 4u)
		return -1;
	for (i = 0; i < w->nhs; i++)
		if (wri_cx_hs_init(&w->hs[i], &w->e.c) != WR_OK)
			return -1;
	return 0;
}

static int sw_open(sw *w, unsigned pt, unsigned ot)
{
	return sw_open_as(w, pt, ot, NULL, "client.sectest");
}

static void sw_close(sw *w)
{
	cxt_env_free(&w->e);
	free(w->hsraw);
	w->hsraw = NULL;
}

/* kind 0: the embedded handshake; 1 + i: slot i */
static drv sw_drv(sw *w, unsigned kind)
{
	drv d;

	d.c = &w->e.c;
	d.slot = kind != 0;
	d.ops = kind == 0 ? wri_cx_ops() : wri_cx_hs_ops();
	d.a = kind == 0 ? (void *)&w->e.c : (void *)&w->hs[kind - 1u];
	return d;
}

static const wri_cx_secret *drv_sec(const drv *d)
{
	return d->slot ? &((const wri_cx_hs *)d->a)->sec : &d->c->sec;
}

static wri_cx_state drv_st(const drv *d)
{
	return d->slot ? ((const wri_cx_hs *)d->a)->st : d->c->st;
}

static const wr_errinfo *drv_err(const drv *d)
{
	return d->slot ? &((const wri_cx_hs *)d->a)->err : &d->c->err;
}

static uint64_t drv_nonce(const drv *d)
{
	return d->slot ? ((const wri_cx_hs *)d->a)->authorizer_nonce : d->c->authorizer_nonce;
}

/* Is any window of the secret in the client, the arena behind it, a slot, or in an errinfo of either? */
static int sw_holds(const sw *w, const uint8_t *sec, size_t sn)
{
	uint32_t i;

	if (has_secret(w->e.mem, w->e.memsz, sec, sn) || has_secret(&w->e.c, sizeof(w->e.c), sec, sn) ||
	    has_secret(w->hsraw, w->hsbytes + 64u, sec, sn) || errinfo_leaks(&w->e.c.err, sec, sn))
		return 1;
	for (i = 0; i < w->nhs; i++)
		if (errinfo_leaks(&w->hs[i].err, sec, sn))
			return 1;
	return 0;
}

/* The same, outside the handshake record that legitimately holds a secret (client or slot struct). */
static int sw_holds_outside_records(const sw *w, const uint8_t *sec, size_t sn)
{
	uint32_t i;

	if (has_secret(w->e.mem, w->e.memsz, sec, sn) || errinfo_leaks(&w->e.c.err, sec, sn))
		return 1;
	for (i = 0; i < w->nhs; i++)
		if (errinfo_leaks(&w->hs[i].err, sec, sn))
			return 1;
	return 0;
}

/* A good crc login (so the OSD handshakes have a ticket and a global id) on the embedded handshake. */
static void sw_login(sw *w)
{
	WRT_CHECK_STATUS(WR_OK, cxt_good_mon(&w->e, &w->ak, &w->ok, GID));
	WRT_CHECK(w->e.c.global_id == GID && w->e.c.ticket[WRI_CX_SLOT_OSD].have);
}

/* ---- server side: the monitor's AUTH_DONE and an OSD's authorizer reply ----------------------------------- */

enum { CBL_NONE, CBL_EMPTY, CBL_SEALED, CBL_RAW };

/* u32 len | secret bytes, the plaintext item of cbl; returns its size */
static size_t item_secret(uint8_t *item, const uint8_t *secret, size_t n)
{
	wri_le32_put(item, (uint32_t)n);
	if (n != 0)
		memcpy(item + 4, secret, n);
	return 4u + n;
}

/*
 * The payload of a monitor's AUTH_DONE: response header, AUTH ticket reply (key w->ak), then per cbl_kind
 *   CBL_NONE   nothing more (a reply that stops after the AUTH ticket)
 *   CBL_EMPTY  a zero-length cbl, then extra
 *   CBL_SEALED cbl = u32 outer | u32 inner | seal(seal_key, usage 0x03, item), then extra
 *   CBL_RAW    cbl = the bytes given (already with their outer length), then extra
 * extra: none (u32 0), or the OSD ticket (sealed under the AUTH session key, or under the principal key when
 * extra_bad). Returns the size.
 */
static size_t mon_payload(sw *w, int cbl_kind, const uint8_t *item, size_t item_n, const wr_key *seal_key, const uint8_t *raw,
			  size_t raw_n, int with_extra, int extra_bad, uint8_t *out, size_t cap)
{
	cxt_dopt o;
	uint8_t tail[4096], ct[2048];
	wri_wr t;
	size_t n, cn = 0;

	cxt_dopt_default(&w->e, &o, &w->ak, &w->ok);
	o.extra[0].msga_key = &w->ak;
	o.tail = 0;
	n = cxt_build_done(&w->e, &o, out, cap);
	WRT_CHECK(n != 0);
	if (cbl_kind == CBL_NONE)
		return n;
	wri_wr_init(&t, tail, sizeof(tail));
	switch (cbl_kind) {
	case CBL_EMPTY:
		wri_wr_u32(&t, 0);
		break;
	case CBL_RAW:
		wri_wr_bytes(&t, raw, raw_n);
		break;
	default:
		WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&w->e.x, seal_key, WRI_CX_USAGE_CONN_SECRET, item, item_n, ct, sizeof(ct), &cn));
		wri_wr_u32(&t, (uint32_t)(cn + 4u));
		wri_wr_u32(&t, (uint32_t)cn);
		wri_wr_bytes(&t, ct, cn);
		break;
	}
	if (with_extra) {
		uint8_t ex[2048];
		wri_wr x;
		cxt_tk tk = o.extra[0];

		if (extra_bad)
			tk.msga_key = &w->e.c.principal;
		wri_wr_init(&x, ex, sizeof(ex));
		wri_wr_u8(&x, 1);
		wri_wr_u32(&x, 1);
		cxt_put_ticket(&w->e, &x, &tk);
		wri_wr_u32(&t, (uint32_t)wri_wr_len(&x));
		wri_wr_bytes(&t, ex, wri_wr_len(&x));
	} else {
		wri_wr_u32(&t, 0);
	}
	WRT_CHECK(wri_wr_ok(&t) && n + wri_wr_len(&t) <= cap);
	memcpy(out + n, tail, wri_wr_len(&t));
	return n + wri_wr_len(&t);
}

/* begin + more of a monitor connection on d; the other_keys the client asked for goes to *other_keys if given */
static wr_status mon_open(drv *d, uint32_t *other_keys)
{
	uint8_t b1[512], b2[512], chal[9];
	wri_wr w;
	wr_status st;

	wri_wr_init(&w, b1, sizeof(b1));
	st = d->ops->begin(d->a, WRI_ENTITY_MON, &w);
	if (st != WR_OK)
		return st;
	chal[0] = 1;
	wri_le64_put(chal + 1, CXT_CHAL);
	wri_wr_init(&w, b2, sizeof(b2));
	st = d->ops->more(d->a, chal, sizeof(chal), &w);
	if (st == WR_OK && other_keys != NULL) {
		WRT_CHECK(wri_wr_len(&w) >= 36u);
		*other_keys = wri_le32_get(b2 + wri_wr_len(&w) - 4u); /* the last field of CephXAuthenticate */
	}
	return st;
}

static void expect_released(const drv *d)
{
	const uint8_t *s = (const uint8_t *)1;
	size_t n = 1;

	WRT_CHECK(is_zero(drv_sec(d), sizeof(wri_cx_secret)));
	d->ops->conn_secret(d->a, &s, &n);
	WRT_CHECK(s == NULL && n == 0);
}

/*
 * One monitor handshake on d against the payload; checks the status and everything that follows from it: a
 * failure leaves nothing (no tickets, no global id, no secret anywhere), a success keeps exactly the secret
 * (exp, exp_n) for the connection and nothing in crc mode.
 */
static void mon_check(sw *w, drv *d, uint32_t mode, const uint8_t *pl, size_t pn, wr_status want, const uint8_t *exp, size_t exp_n,
		      int want_osd)
{
	const uint8_t *s = NULL, *k = NULL;
	size_t sn = 0, kn = 0;
	wr_status st;

	w->e.c.want_mask = want_osd ? WRI_CX_WANT_MASK : WRI_CX_SERVICE_AUTH;
	WRT_CHECK_STATUS(WR_OK, mon_open(d, NULL));
	st = d->ops->done(d->a, GID, mode, pl, pn);
	WRT_CHECK_STATUS(want, st);
	if (want != WR_OK) {
		WRT_CHECK(drv_st(d) == WRI_CX_FAILED && drv_err(d)->status == want && drv_err(d)->what != NULL);
		WRT_CHECK(!w->e.c.ticket[0].have && !w->e.c.ticket[1].have && w->e.c.global_id == 0); /* the shared rule */
		WRT_CHECK(is_zero(drv_sec(d), sizeof(wri_cx_secret)));
		WRT_CHECK(is_zero(w->e.c.scratch, w->e.c.scratch_cap));
		WRT_CHECK(!sw_holds(w, exp, exp_n));
		expect_released(d);
		return;
	}
	WRT_CHECK(drv_st(d) == WRI_CX_DONE && w->e.c.global_id == GID && w->e.c.ticket[WRI_CX_SLOT_AUTH].have);
	WRT_CHECK(is_zero(w->e.c.scratch, w->e.c.scratch_cap));
	if (mode == WRI_CONN_MODE_CRC) {
		expect_released(d);
		return;
	}
	WRT_CHECK(drv_sec(d)->len == exp_n && !drv_sec(d)->taken);
	WRT_CHECK(sw_holds(w, exp, exp_n) && !sw_holds_outside_records(w, exp, exp_n)); /* kept in the handshake only */
	d->ops->conn_secret(d->a, &s, &sn);
	WRT_CHECK(s == drv_sec(d)->buf && sn == exp_n && memcmp(s, exp, exp_n) == 0);
	d->ops->session_key(d->a, &k, &kn); /* the connection keyed itself: the next call wipes */
	WRT_CHECK(k != NULL && kn == w->ak.len && memcmp(k, w->ak.secret, kn) == 0);
	WRT_CHECK(!sw_holds(w, exp, exp_n));
	expect_released(d);
}

/* an OSD item: u8 v | u64 npo | (v >= 2: u32 slen | nbytes of secret) */
static size_t osd_item(uint8_t *item, unsigned v, uint64_t npo, uint32_t slen, const uint8_t *secret, size_t nbytes)
{
	size_t n = 9;

	item[0] = (uint8_t)v;
	wri_le64_put(item + 1, npo);
	if (v >= 2u) {
		wri_le32_put(item + 9, slen);
		if (nbytes != 0)
			memcpy(item + 13, secret, nbytes);
		n = 13u + nbytes;
	}
	return n;
}

static size_t osd_payload(sw *w, const uint8_t *item, size_t n, uint8_t *out, size_t cap)
{
	size_t cn = 0;

	WRT_CHECK(cap > 4u);
	WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&w->e.x, &w->ok, WRI_CX_USAGE_AUTHORIZE_REPLY, item, n, out + 4, cap - 4u, &cn));
	wri_le32_put(out, (uint32_t)cn);
	return 4u + cn;
}

/* begin + the challenge round of an OSD handshake on d; *nonce gets the authorizer nonce */
static wr_status osd_open(sw *w, drv *d, uint64_t *nonce)
{
	uint8_t a1[512], a2[512], ch[128], item[9];
	size_t cn = 0;
	wri_wr wr;
	wr_status st;

	wri_wr_init(&wr, a1, sizeof(a1));
	st = d->ops->begin(d->a, WRI_ENTITY_OSD, &wr);
	if (st != WR_OK)
		return st;
	*nonce = drv_nonce(d);
	item[0] = 1;
	wri_le64_put(item + 1, 0x0123456789ABCDEFull);
	WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&w->e.x, &w->ok, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, item, sizeof(item), ch, sizeof(ch), &cn));
	wri_wr_init(&wr, a2, sizeof(a2));
	return d->ops->more(d->a, ch, cn, &wr);
}

/* One OSD handshake on d against the reply item built from (v, nonce delta, slen field, secret bytes present). */
static void osd_check(sw *w, drv *d, uint32_t mode, unsigned v, int nonce_delta, uint32_t slen_field, const uint8_t *secret,
		      size_t nbytes, wr_status want)
{
	uint8_t item[512], pl[600];
	const uint8_t *s = NULL, *k = NULL;
	size_t sn = 0, kn = 0, n;
	uint64_t nonce = 0;
	wr_status st;

	WRT_CHECK_STATUS(WR_OK, osd_open(w, d, &nonce));
	n = osd_item(item, v, nonce + 1u + (uint64_t)(int64_t)nonce_delta, slen_field, secret, nbytes);
	n = osd_payload(w, item, n, pl, sizeof(pl));
	st = d->ops->done(d->a, GID, mode, pl, n);
	WRT_CHECK_STATUS(want, st);
	if (want != WR_OK) {
		WRT_CHECK(drv_st(d) == WRI_CX_FAILED && drv_err(d)->status == want && drv_err(d)->what != NULL);
		WRT_CHECK(is_zero(drv_sec(d), sizeof(wri_cx_secret)));
		WRT_CHECK(is_zero(w->e.c.scratch, w->e.c.scratch_cap));
		WRT_CHECK(w->e.c.ticket[WRI_CX_SLOT_OSD].have && w->e.c.global_id == GID); /* an OSD failure forgets nothing */
		WRT_CHECK(!sw_holds(w, secret, nbytes));
		expect_released(d);
		return;
	}
	WRT_CHECK(drv_st(d) == WRI_CX_DONE && drv_nonce(d) == 0);
	WRT_CHECK(is_zero(w->e.c.scratch, w->e.c.scratch_cap));
	if (mode == WRI_CONN_MODE_CRC) {
		expect_released(d);
		return;
	}
	WRT_CHECK(drv_sec(d)->len == slen_field && !drv_sec(d)->taken);
	WRT_CHECK(sw_holds(w, secret, nbytes) && !sw_holds_outside_records(w, secret, nbytes));
	d->ops->conn_secret(d->a, &s, &sn);
	WRT_CHECK(s == drv_sec(d)->buf && sn == slen_field && memcmp(s, secret, sn) == 0);
	d->ops->session_key(d->a, &k, &kn);
	WRT_CHECK(k != NULL && kn == w->ok.len && memcmp(k, w->ok.secret, kn) == 0);
	WRT_CHECK(!sw_holds(w, secret, nbytes));
	expect_released(d);
}

/* ---- 1. the vectors --------------------------------------------------------------------------------- */

/* the real cbl bytes of both key types in both modes, delivered through a monitor AUTH_DONE */
static void vec_blob_case(unsigned kt, const uint8_t *key, size_t klen, int secure, const uint8_t *cbl, size_t cbl_n,
			  const uint8_t *secret, size_t slen, unsigned kind)
{
	sw w;
	drv d;
	uint8_t pl[2048];
	size_t pn;

	WRT_CHECK(sw_open(&w, kt, kt) == 0);
	WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&w.ak, kt, key, klen));
	d = sw_drv(&w, kind);
	pn = mon_payload(&w, CBL_RAW, NULL, 0, NULL, cbl, cbl_n, 0, 0, pl, sizeof(pl));
	/* right mode: accepted, the secret of the vector comes out; crc: nothing */
	mon_check(&w, &d, secure ? WRI_CONN_MODE_SECURE : WRI_CONN_MODE_CRC, pl, pn, WR_OK, secret, slen, 0);
	sw_close(&w);
	/* the other mode: a secret in crc mode is a protocol error, no secret in secure mode is M2_SECRET */
	WRT_CHECK(sw_open(&w, kt, kt) == 0);
	WRT_CHECK_STATUS(WR_OK, wr_key_from_raw(&w.ak, kt, key, klen));
	d = sw_drv(&w, kind);
	pn = mon_payload(&w, CBL_RAW, NULL, 0, NULL, cbl, cbl_n, 0, 0, pl, sizeof(pl));
	mon_check(&w, &d, secure ? WRI_CONN_MODE_CRC : WRI_CONN_MODE_SECURE, pl, pn, secure ? WR_E_AUTH_PROTO : WR_E_M2_SECRET, secret,
		  slen, 0);
	sw_close(&w);
}

static void test_vector_blobs(void)
{
	wrt_json j;
	wrt_tok cases;
	size_t i, nc;
	unsigned kind;
	unsigned secure_seen[3] = {0, 0, 0}; /* index: key type */

	if (wrt_json_load_vec(&j, "secure/connection-secret-blob-synthetic.json") != 0) {
		WRT_CHECK(!"vector file loads");
		return;
	}
	cases = wrt_json_get(&j, wrt_json_root(&j), "cases");
	nc = wrt_json_count(&j, cases);
	WRT_CHECK(nc == 4);
	for (i = 0; i < nc; i++) {
		wrt_tok c = wrt_json_at(&j, cases, i);
		uint8_t *key = NULL, *sec = NULL, *cbl = NULL;
		size_t kn = 0, sn = 0, cn = 0;
		char *mode = wrt_json_strdup(&j, wrt_json_get(&j, c, "mode"));
		unsigned kt = (unsigned)wrt_json_int(&j, wrt_json_get(&j, c, "session_key_type"), NULL);
		int secure;

		WRT_CHECK(wrt_json_get_hex(&j, c, "session_key_secret_hex", &key, &kn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, c, "connection_secret_hex", &sec, &sn) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, c, "cbl_hex", &cbl, &cn) == 0);
		WRT_CHECK(mode != NULL && (strcmp(mode, "secure") == 0 || strcmp(mode, "crc") == 0));
		secure = mode != NULL && strcmp(mode, "secure") == 0;
		/* the blob is u32 outer | u32 inner | ciphertext; the lengths agree with each other and with the mode */
		WRT_CHECK(cn >= 8u && wri_le32_get(cbl) + 4u == cn && wri_le32_get(cbl + 4) + 4u == wri_le32_get(cbl));
		WRT_CHECK(secure ? (sn == 64u && sn >= WRI_CX_SECRET_MIN && sn <= WRI_CX_SECRET_MAX) : sn == 0);
		if (key != NULL && sec != NULL && cbl != NULL && (kt == 1u || kt == 2u)) {
			for (kind = 0; kind < 2; kind++) /* the embedded handshake, then a slot */
				vec_blob_case(kt, key, kn, secure, cbl, cn, sec, sn, kind);
			secure_seen[kt] += secure ? 1u : 0u;
		}
		free(key);
		free(sec);
		free(cbl);
		free(mode);
	}
	WRT_CHECK(secure_seen[1] == 1 && secure_seen[2] == 1); /* both key types, with a secret */
	wrt_json_free(&j);
}

/* what a session of the lab captures looks like to the machine: every kind, as the capture says */
static void test_vector_structure(void)
{
	wrt_json j;
	wrt_tok sessions;
	size_t i, ns, secure_mon = 0, secure_osd = 0, crc_n = 0;

	if (wrt_json_load_vec(&j, "secure/captured-structure.json") != 0) {
		WRT_CHECK(!"vector file loads");
		return;
	}
	sessions = wrt_json_get(&j, wrt_json_root(&j), "sessions");
	ns = wrt_json_count(&j, sessions);
	WRT_CHECK(ns >= 6);
	for (i = 0; i < ns; i++) {
		wrt_tok s = wrt_json_at(&j, sessions, i);
		char *peer = wrt_json_strdup(&j, wrt_json_get(&j, s, "peer"));
		char *mode = wrt_json_strdup(&j, wrt_json_get(&j, s, "mode"));
		int ok1 = 0, ok2 = 0, ok3 = 0, ok4 = 0;
		unsigned kt = (unsigned)wrt_json_int(&j, wrt_json_get(&j, s, "cephx_key_type_of_session_key"), &ok1);
		unsigned slen = (unsigned)wrt_json_int(&j, wrt_json_get(&j, s, "connection_secret_len"), &ok2);
		unsigned picked = (unsigned)wrt_json_int(&j, wrt_json_get(&j, s, "server_picked_mode"), &ok3);
		unsigned ver = (unsigned)wrt_json_int(&j, wrt_json_get(&j, s, "authorize_reply_version"), &ok4); /* null: ok4 0 */
		int ok5 = 0;
		unsigned other = (unsigned)wrt_json_int(&j, wrt_json_get(&j, s, "other_keys"), &ok5);
		int secure = mode != NULL && strcmp(mode, "secure") == 0, is_mon = peer != NULL && strcmp(peer, "mon") == 0;
		unsigned kind;

		WRT_CHECK(peer != NULL && mode != NULL && ok1 && ok2 && ok3 && (kt == 1u || kt == 2u));
		WRT_CHECK(secure ? (picked == WRI_CONN_MODE_SECURE && slen == 64u) : (picked == WRI_CONN_MODE_CRC && slen == 0u));
		WRT_CHECK(slen == 0 || (slen >= WRI_CX_SECRET_MIN && slen <= WRI_CX_SECRET_MAX)); /* what the servers really send */
		/* the shape of each peer: a monitor has other_keys and no reply version, an OSD / manager the reverse */
		WRT_CHECK(is_mon ? (ok5 && other != 0 && !ok4) : (!ok5 && ok4 && ver == (secure ? 2u : 1u)));
		for (kind = 0; kind < 2 && (kt == 1u || kt == 2u); kind++) { /* the embedded handshake, then a slot */
			sw w;
			drv d;
			uint8_t secret[128], pl[1024];
			size_t pn;
			uint8_t item[256];

			WRT_CHECK(sw_open(&w, kt, kt == 1u ? 2u : 1u) == 0);
			mk_secret(secret, slen, (unsigned)i + 1u, 0);
			d = sw_drv(&w, kind);
			if (is_mon) {
				pn = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, slen), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
				mon_check(&w, &d, secure ? WRI_CONN_MODE_SECURE : WRI_CONN_MODE_CRC, pl, pn, WR_OK, secret, slen, 1);
			} else {
				sw_login(&w);
				osd_check(&w, &d, secure ? WRI_CONN_MODE_SECURE : WRI_CONN_MODE_CRC, ver, 0, slen, secret, slen, WR_OK);
			}
			sw_close(&w);
		}
		secure_mon += (secure && is_mon) ? 1u : 0u;
		secure_osd += (secure && !is_mon) ? 1u : 0u;
		crc_n += secure ? 0u : 1u;
		free(peer);
		free(mode);
	}
	WRT_CHECK(secure_mon >= 1 && secure_osd >= 1 && crc_n >= 1);
	wrt_json_free(&j);
}

/*
 * The synthetic secure sessions of vectors/cephx/session-type{1,2}-secure.json: three connections each (a monitor with
 * request mask 0x35, a monitor with 0x20, an OSD authorizer with the challenge round trip) whose AUTH_* frames were
 * built by harness/tools/cephx_check.py, an implementation that shares no code with the core. Everything the machine
 * writes (AUTH_REQUEST, AUTH_REQUEST_MORE) must equal the vector's bytes, the server's AUTH_DONE must be accepted in
 * secure mode, and the secret conn_secret() hands out, the session key and both AUTH_SIGNATURE values must be the
 * vector's. This is the independent oracle for the OSD reply of version 2 (the other tests build it with the core's
 * own cipher layer).
 */
typedef struct ses_frame {
	uint8_t tag;
	const uint8_t *seg;
	uint32_t len;
	size_t end;
} ses_frame;

/* The crc frames of one direction up to and including the first one with tag `last` (what follows is encrypted). */
static size_t ses_parse(const uint8_t *b, size_t n, ses_frame *out, size_t max, uint8_t last)
{
	size_t p, k = 0;

	if (n < 10 || memcmp(b, "ceph v2\n", 8) != 0)
		return 0;
	p = 10u + wri_le16_get(b + 8);
	while (p + 32u <= n && k < max) {
		ses_frame *f = &out[k];

		f->tag = b[p];
		f->len = wri_le32_get(b + p + 2);
		f->seg = b + p + 32;
		f->end = p + 32u + f->len + (f->len != 0 ? 4u : 0u);
		if (f->end > n)
			return 0;
		p = f->end;
		k++;
		if (f->tag == last)
			break;
	}
	return k;
}

static const ses_frame *ses_find(const ses_frame *f, size_t n, uint8_t tag)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (f[i].tag == tag)
			return &f[i];
	return NULL;
}

/* a segment that is one u32-length blob and nothing else */
static int ses_blob(const ses_frame *f, const uint8_t **p, size_t *n)
{
	wri_rd r;

	wri_rd_init(&r, f->seg, f->len);
	*n = wri_rd_u32(&r);
	*p = wri_rd_bytes(&r, *n);
	return wri_rd_ok(&r) && wri_rd_left(&r) == 0 ? 0 : -1;
}

/* AUTH_REQUEST: u32 method | u32 n_modes | modes | u32 len | payload */
static int ses_areq(const ses_frame *f, const uint8_t **p, size_t *n)
{
	wri_rd r;
	uint32_t i, nm;

	wri_rd_init(&r, f->seg, f->len);
	(void)wri_rd_u32(&r);
	nm = wri_rd_count(&r, 16, 4);
	for (i = 0; i < nm; i++)
		(void)wri_rd_u32(&r);
	*n = wri_rd_u32(&r);
	*p = wri_rd_bytes(&r, *n);
	return wri_rd_ok(&r) && wri_rd_left(&r) == 0 ? 0 : -1;
}

static uint64_t ses_hex64(const wrt_json *j, wrt_tok o, const char *key)
{
	char *s = wrt_json_strdup(j, wrt_json_get(j, o, key));
	uint64_t v = s != NULL ? strtoull(s, NULL, 16) : 0;

	free(s);
	return v;
}

/* SHA-256("winrbd-vector|<label>|0") truncated: the generator's det(), for the two confounders of a type 2 authorizer */
static void ses_det(const char *label, uint8_t *out, size_t n)
{
	char buf[96];
	uint8_t d[32];
	wri_sha256_ctx c;

	snprintf(buf, sizeof(buf), "winrbd-vector|%s|0", label);
	wri_sha256_init(&c);
	wri_sha256_update(&c, (const uint8_t *)buf, strlen(buf));
	wri_sha256_final(&c, d);
	memcpy(out, d, n);
}

static void ses_sig(const uint8_t *key, size_t kn, const uint8_t *p, size_t n, const uint8_t *want, size_t wn)
{
	uint8_t mac[32];
	wr_iov iov;

	iov.base = p;
	iov.len = n;
	wri_hmac_sha256(key, kn, &iov, 1, mac);
	WRT_CHECK(wn == 32u && memcmp(mac, want, 32) == 0);
}

/* One connection of the vector on d: the client side bytes equal the vector's, the server's AUTH_DONE is taken in
 * secure mode and yields the vector's secret, session key and signatures. */
static void ses_conn(sw *w, drv *d, wrt_json *j, wrt_tok conn, unsigned ktype)
{
	ses_frame cf[8], sf[8];
	uint8_t *cs = NULL, *ss = NULL;
	const uint8_t *want, *pl, *s = NULL, *k = NULL;
	size_t cn = 0, sn = 0, ncf, nsf, wn, pn, secn = 0, sgn = 0, sln = 0, kn = 0;
	uint8_t *sec = NULL, *sig = NULL, *sks = NULL, out[1024];
	const ses_frame *areq, *amore, *rmore, *done;
	wrt_tok ex = wrt_json_get(j, conn, "expect");
	char *kind = wrt_json_strdup(j, wrt_json_get(j, ex, "kind"));
	int is_mon = kind != NULL && strcmp(kind, "mon") == 0;
	uint64_t gid = (uint64_t)wrt_json_int(j, wrt_json_get(j, ex, "global_id"), NULL);
	wri_wr wr;
	uint8_t tmp[16];
	char label[48];

	WRT_CHECK(wrt_json_get_hex(j, conn, "client_stream", &cs, &cn) == 0);
	WRT_CHECK(wrt_json_get_hex(j, conn, "server_stream", &ss, &sn) == 0);
	ncf = cs != NULL ? ses_parse(cs, cn, cf, 8, 5) : 0;
	nsf = ss != NULL ? ses_parse(ss, sn, sf, 8, 6) : 0;
	areq = ses_find(cf, ncf, 2);
	amore = ses_find(cf, ncf, 5);
	rmore = ses_find(sf, nsf, 4);
	done = ses_find(sf, nsf, 6);
	WRT_CHECK(areq && amore && rmore && done && kind != NULL);
	if (!(areq && amore && rmore && done && kind != NULL)) {
		free(cs);
		free(ss);
		free(kind);
		return;
	}
	cxt_rng_free();
	if (is_mon) {
		cxt_rng_push_u64(ses_hex64(j, ex, "client_challenge"));
		w->e.c.want_mask = (uint32_t)wrt_json_int(j, wrt_json_get(j, ex, "request_mask"), NULL);
	} else {
		cxt_rng_push_u64(ses_hex64(j, ex, "nonce"));
		if (ktype == 2) { /* the confounders of the two type 2 authorizers, in the order they are drawn */
			snprintf(label, sizeof(label), "t%u-m2-osd-c1", ktype);
			ses_det(label, tmp, 16);
			cxt_rng_push(tmp, 16);
			snprintf(label, sizeof(label), "t%u-m2-osd-c2", ktype);
			ses_det(label, tmp, 16);
			cxt_rng_push(tmp, 16);
		}
	}
	/* begin and more write the vector's bytes */
	WRT_CHECK(ses_areq(areq, &want, &wn) == 0);
	wri_wr_init(&wr, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, d->ops->begin(d->a, is_mon ? WRI_ENTITY_MON : WRI_ENTITY_OSD, &wr));
	WRT_CHECK(wri_wr_len(&wr) == wn);
	if (wri_wr_len(&wr) == wn)
		WRT_CHECK(memcmp(out, want, wn) == 0);
	WRT_CHECK(ses_blob(rmore, &pl, &pn) == 0 && ses_blob(amore, &want, &wn) == 0);
	wri_wr_init(&wr, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, d->ops->more(d->a, pl, pn, &wr));
	WRT_CHECK(wri_wr_len(&wr) == wn);
	if (wri_wr_len(&wr) == wn)
		WRT_CHECK(memcmp(out, want, wn) == 0);
	WRT_CHECK(g_rng.bad == 0 && g_rng.i == g_rng.n);
	/* AUTH_DONE: u64 global_id | u32 mode | blob payload */
	{
		wri_rd r;
		uint64_t dgid;
		uint32_t mode;

		wri_rd_init(&r, done->seg, done->len);
		dgid = wri_rd_u64(&r);
		mode = wri_rd_u32(&r);
		pn = wri_rd_u32(&r);
		pl = wri_rd_bytes(&r, pn);
		WRT_CHECK(wri_rd_ok(&r) && dgid == gid && mode == WRI_CONN_MODE_SECURE);
		WRT_CHECK_STATUS(WR_OK, d->ops->done(d->a, dgid, mode, pl, pn));
	}
	WRT_CHECK(drv_st(d) == WRI_CX_DONE && drv_sec(d)->len == 64u && !drv_sec(d)->taken);
	WRT_CHECK(wrt_json_get_hex(j, ex, "connection_secret", &sec, &secn) == 0 && secn == 64u);
	d->ops->conn_secret(d->a, &s, &sln);
	WRT_CHECK(s != NULL && sec != NULL && sln == secn && memcmp(s, sec, secn) == 0);
	d->ops->session_key(d->a, &k, &kn);
	WRT_CHECK(k != NULL && kn != 0);
	if (is_mon) {
		WRT_CHECK(wrt_json_get_hex(j, ex, "auth_session_key_secret", &sks, &sgn) == 0);
		WRT_CHECK(k != NULL && kn == sgn && memcmp(k, sks, kn) == 0);
		free(sks);
	}
	expect_released(d); /* the connection keyed itself with it: gone */
	/* the signatures: ours over what the server sent through AUTH_DONE, the server's over what we sent */
	if (k != NULL) {
		WRT_CHECK(wrt_json_get_hex(j, ex, "auth_signature_client", &sig, &sgn) == 0);
		ses_sig(k, kn, ss, done->end, sig, sgn);
		free(sig);
		sig = NULL;
		WRT_CHECK(wrt_json_get_hex(j, ex, "auth_signature_server", &sig, &sgn) == 0);
		ses_sig(k, kn, cs, amore->end, sig, sgn);
		free(sig);
	}
	free(sec);
	free(cs);
	free(ss);
	free(kind);
}

static void test_session_vectors(void)
{
	static const char *const files[2] = {"cephx/session-type1-secure.json", "cephx/session-type2-secure.json"};
	unsigned ktype, variant;

	for (ktype = 1; ktype <= 2; ktype++) {
		wrt_json j;
		wrt_tok root, conns;
		char *b64 = NULL, *ent = NULL;
		wr_key pk;

		if (wrt_json_load_vec(&j, files[ktype - 1u]) != 0) {
			WRT_CHECK(!"vector file loads");
			continue;
		}
		root = wrt_json_root(&j);
		conns = wrt_json_get(&j, root, "connections");
		b64 = wrt_json_strdup(&j, wrt_json_get(&j, root, "keyring_key_base64"));
		ent = wrt_json_strdup(&j, wrt_json_get(&j, root, "entity"));
		WRT_CHECK(b64 && ent && wrt_json_count(&j, conns) == 3);
		WRT_CHECK_STATUS(WR_OK, wr_key_parse_base64(&pk, b64, strlen(b64)));
		WRT_CHECK(pk.type == ktype);
		/* variant 0: the embedded handshake for everything; 1: monitor on slot 0, OSD on slot 1 */
		for (variant = 0; variant < 2; variant++) {
			sw w;
			drv dm, dof, dm2;

			WRT_CHECK(sw_open_as(&w, ktype, ktype, &pk, ent) == 0);
			dm = sw_drv(&w, variant == 0 ? 0u : 1u);
			dof = sw_drv(&w, variant == 0 ? 0u : 2u);
			ses_conn(&w, &dm, &j, wrt_json_at(&j, conns, 0), ktype);   /* the monitor, AUTH | OSD | MGR | MON tickets */
			WRT_CHECK(w.e.c.ticket[WRI_CX_SLOT_OSD].have && w.e.c.global_id != 0);
			ses_conn(&w, &dof, &j, wrt_json_at(&j, conns, 2), ktype);  /* the OSD authorizer with that ticket */
			WRT_CHECK(w.e.c.ticket[WRI_CX_SLOT_OSD].have && w.e.c.ticket[WRI_CX_SLOT_AUTH].have);
			sw_close(&w);
			/* the monitor that asked for AUTH only still gets its connection secret */
			WRT_CHECK(sw_open_as(&w, ktype, ktype, &pk, ent) == 0);
			dm2 = sw_drv(&w, variant == 0 ? 0u : 1u);
			ses_conn(&w, &dm2, &j, wrt_json_at(&j, conns, 1), ktype);
			WRT_CHECK(!w.e.c.ticket[WRI_CX_SLOT_OSD].have && w.e.c.ticket[WRI_CX_SLOT_AUTH].have);
			sw_close(&w);
		}
		free(b64);
		free(ent);
		wrt_json_free(&j);
	}
}

/* ---- 2. other_keys is never 0 ----------------------------------------------------------------------------- */

static void test_other_keys(void)
{
	unsigned pt, kind;

	for (pt = 1; pt <= 2; pt++)
		for (kind = 0; kind < 2; kind++) {
			sw w;
			drv d;
			uint32_t ok_first = 0, ok_reclaim = 0;
			uint8_t b[512], chal[9];
			wri_wr wr;

			WRT_CHECK(sw_open(&w, pt, pt) == 0);
			d = sw_drv(&w, kind);
			/* a new login */
			WRT_CHECK_STATUS(WR_OK, mon_open(&d, &ok_first));
			WRT_CHECK(ok_first != 0 && ok_first == WRI_CX_WANT_MASK && w.e.c.want_mask == WRI_CX_WANT_MASK);
			/* a reclaim of the global id with the held ticket */
			sw_login(&w);
			WRT_CHECK_STATUS(WR_OK, mon_open(&d, &ok_reclaim));
			WRT_CHECK(ok_reclaim != 0 && ok_reclaim == WRI_CX_WANT_MASK);
			sw_close(&w);

			/* nothing can make it 0: a mask of 0 is refused before anything is sent or drawn */
			WRT_CHECK(sw_open(&w, pt, pt) == 0);
			d = sw_drv(&w, kind);
			w.e.c.want_mask = 0;
			wri_wr_init(&wr, b, sizeof(b));
			WRT_CHECK_STATUS(WR_OK, d.ops->begin(d.a, WRI_ENTITY_MON, &wr));
			chal[0] = 1;
			wri_le64_put(chal + 1, CXT_CHAL);
			wri_wr_init(&wr, b, sizeof(b));
			WRT_CHECK_STATUS(WR_E_INVAL, d.ops->more(d.a, chal, sizeof(chal), &wr));
			WRT_CHECK(wri_wr_len(&wr) == 0 && drv_st(&d) == WRI_CX_FAILED && drv_err(&d)->status == WR_E_INVAL);
			sw_close(&w);
		}
}

/* ---- 3. the table of 34.3 --------------------------------------------------------------------------------- */

static void test_mon_table(unsigned pt, unsigned ot, unsigned kind)
{
	static const size_t good[] = {40, 41, 63, 64, 65, 100, 127, 128};
	static const size_t bad[] = {1, 8, 16, 32, 39, 129, 130, 200, 255};
	uint8_t secret[512], item[600], pl[4096];
	size_t i, n;
	sw w;
	drv d;
	uint32_t m;

	mk_secret(secret, sizeof(secret), pt * 16u + ot, 0);
#define FRESH()                                                                                               \
	do {                                                                                                  \
		WRT_CHECK(sw_open(&w, pt, ot) == 0);                                                          \
		d = sw_drv(&w, kind);                                                                         \
	} while (0)

	for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) { /* secure, 40 .. 128: kept, with and without extra tickets */
		FRESH();
		n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, good[i]), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
		mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_OK, secret, good[i], 1);
		WRT_CHECK(w.e.c.ticket[WRI_CX_SLOT_OSD].have);
		sw_close(&w);
		FRESH();
		n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, good[i]), &w.ak, NULL, 0, 0, 0, pl, sizeof(pl));
		mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_OK, secret, good[i], 0);
		sw_close(&w);
	}
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) { /* secure, too short or too long */
		FRESH();
		n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, bad[i]), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
		mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_E_M2_SECRET, secret, bad[i], 1);
		WRT_CHECK(drv_err(&d)->a0 == bad[i]); /* the length, never a byte of the secret */
		sw_close(&w);
	}
	/* secure, no secret: an empty string, an empty cbl, no cbl at all */
	FRESH();
	n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, 0), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
	mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_E_M2_SECRET, NULL, 0, 1);
	sw_close(&w);
	FRESH();
	n = mon_payload(&w, CBL_EMPTY, NULL, 0, NULL, NULL, 0, 1, 0, pl, sizeof(pl));
	mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_E_M2_SECRET, NULL, 0, 1);
	sw_close(&w);
	FRESH();
	n = mon_payload(&w, CBL_NONE, NULL, 0, NULL, NULL, 0, 0, 0, pl, sizeof(pl));
	mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_E_M2_SECRET, NULL, 0, 0);
	sw_close(&w);
	/* crc: no secret in any of those shapes is fine */
	FRESH();
	n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, 0), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
	mon_check(&w, &d, WRI_CONN_MODE_CRC, pl, n, WR_OK, NULL, 0, 1);
	sw_close(&w);
	FRESH();
	n = mon_payload(&w, CBL_EMPTY, NULL, 0, NULL, NULL, 0, 1, 0, pl, sizeof(pl));
	mon_check(&w, &d, WRI_CONN_MODE_CRC, pl, n, WR_OK, NULL, 0, 1);
	sw_close(&w);
	FRESH();
	n = mon_payload(&w, CBL_NONE, NULL, 0, NULL, NULL, 0, 0, 0, pl, sizeof(pl));
	mon_check(&w, &d, WRI_CONN_MODE_CRC, pl, n, WR_OK, NULL, 0, 0);
	sw_close(&w);
	/* crc with a secret of any length: a server that sends a key it will not use */
	for (i = 0; i < sizeof(good) / sizeof(good[0]) + sizeof(bad) / sizeof(bad[0]); i++) {
		size_t sl = i < sizeof(good) / sizeof(good[0]) ? good[i] : bad[i - sizeof(good) / sizeof(good[0])];

		FRESH();
		n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, sl), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
		mon_check(&w, &d, WRI_CONN_MODE_CRC, pl, n, WR_E_AUTH_PROTO, secret, sl, 1);
		sw_close(&w);
	}
	/* a mode that is neither crc nor secure, whatever the payload holds */
	for (m = 0; m < 6; m++) {
		static const uint32_t modes[6] = {0, 3, 4, 7, 99, 0xFFFFFFFFu};

		FRESH();
		n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, 64), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
		mon_check(&w, &d, modes[m], pl, n, WR_E_M2_MODE, secret, 64, 1);
		sw_close(&w);
		FRESH();
		n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, 0), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
		mon_check(&w, &d, modes[m], pl, n, WR_E_M2_MODE, NULL, 0, 1);
		sw_close(&w);
	}
	/* a blob that does not decrypt, in secure mode: sealed under the wrong key, a damaged byte, a wrong usage */
	for (i = 0; i < 3; i++) {
		uint8_t damaged[600];

		FRESH();
		if (i == 0) {
			n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, 64), &w.e.c.principal, NULL, 0, 1, 0, pl, sizeof(pl));
		} else if (i == 1) { /* a flipped bit in the ciphertext of the sealed secret */
			size_t cbl_at;

			n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, 64), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
			cbl_at = mon_payload(&w, CBL_NONE, NULL, 0, NULL, NULL, 0, 0, 0, damaged, sizeof(damaged));
			WRT_CHECK(cbl_at + 12u < n);
			pl[cbl_at + 8u + 3u] ^= 0x04; /* inside the first cipher block: garbles the magic of type 1, the MAC of type 2 */
		} else if (pt == 2) { /* type 2 binds the usage into the key: a secret sealed for another use */
			size_t cn = 0, cbl_at;
			uint8_t ct[400];
			size_t k = item_secret(item, secret, 64);

			n = mon_payload(&w, CBL_SEALED, item, k, &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
			cbl_at = mon_payload(&w, CBL_NONE, NULL, 0, NULL, NULL, 0, 0, 0, damaged, sizeof(damaged));
			WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&w.e.x, &w.ak, WRI_CX_USAGE_TICKET_BLOB, item, k, ct, sizeof(ct), &cn));
			WRT_CHECK(cn == wri_le32_get(pl + cbl_at + 4u)); /* same size: patch in place */
			memcpy(pl + cbl_at + 8u, ct, cn);
		} else {
			sw_close(&w);
			continue;
		}
		mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_E_AUTH_DECRYPT, secret, 64, 1);
		sw_close(&w);
	}
	/* the secret was stored, then a later part of the same reply failed: nothing stays */
	FRESH(); /* the extra tickets under the wrong key */
	n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, 64), &w.ak, NULL, 0, 1, 1, pl, sizeof(pl));
	mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_E_AUTH_DECRYPT, secret, 64, 1);
	sw_close(&w);
	FRESH(); /* the OSD ticket we asked for is missing */
	n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, 64), &w.ak, NULL, 0, 0, 0, pl, sizeof(pl));
	mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_E_AUTH_PROTO, secret, 64, 1);
	sw_close(&w);
	/* malformed: an item too short for the length, a length beyond the item (both modes), a stray byte on the blob */
	for (m = 0; m < 2; m++) {
		uint32_t mode = m == 0 ? WRI_CONN_MODE_SECURE : WRI_CONN_MODE_CRC;

		FRESH();
		n = mon_payload(&w, CBL_SEALED, item, 2, &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
		mon_check(&w, &d, mode, pl, n, WR_E_AUTH_PROTO, NULL, 0, 1);
		sw_close(&w);
		FRESH();
		item_secret(item, secret, 64);
		n = mon_payload(&w, CBL_SEALED, item, 4u + 63u, &w.ak, NULL, 0, 1, 0, pl, sizeof(pl)); /* claims 64, holds 63 */
		mon_check(&w, &d, mode, pl, n, WR_E_AUTH_PROTO, secret, 63, 1);
		sw_close(&w);
		FRESH();
		wri_le32_put(item, 0xFFFFFFFFu);
		memcpy(item + 4, secret, 64);
		n = mon_payload(&w, CBL_SEALED, item, 68, &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
		mon_check(&w, &d, mode, pl, n, WR_E_AUTH_PROTO, secret, 64, 1);
		sw_close(&w);
	}
	/* the blob itself malformed: a stray byte after the sealed part, an inner length beyond the blob (both modes) */
	for (m = 0; m < 4; m++) {
		uint8_t raw[700], ct[500];
		size_t cn = 0, in = item_secret(item, secret, 64);

		FRESH();
		WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&w.e.x, &w.ak, WRI_CX_USAGE_CONN_SECRET, item, in, ct, sizeof(ct), &cn));
		wri_le32_put(raw + 4, (uint32_t)(m < 2 ? cn : cn + 10u)); /* inner: the real size, or ten bytes too many */
		memcpy(raw + 8, ct, cn);
		raw[8 + cn] = 0x77;
		wri_le32_put(raw, (uint32_t)(4u + cn + (m < 2 ? 1u : 0u))); /* outer: with the stray byte, or exactly */
		n = mon_payload(&w, CBL_RAW, NULL, 0, NULL, raw, 8u + cn + (m < 2 ? 1u : 0u), 1, 0, pl, sizeof(pl));
		mon_check(&w, &d, (m & 1u) ? WRI_CONN_MODE_CRC : WRI_CONN_MODE_SECURE, pl, n, WR_E_AUTH_PROTO, secret, 64, 1);
		sw_close(&w);
	}
	/* a stray byte after a valid secret inside the item: the length field decides, the secret is the first 64 bytes */
	FRESH();
	n = item_secret(item, secret, 64);
	item[n++] = 0x77;
	n = mon_payload(&w, CBL_SEALED, item, n, &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
	mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_OK, secret, 64, 1);
	sw_close(&w);
#undef FRESH
}

static void test_osd_table(unsigned pt, unsigned ot, unsigned kind)
{
	static const size_t good[] = {40, 41, 64, 100, 127, 128};
	static const size_t bad[] = {1, 8, 39, 129, 130, 200};
	uint8_t secret[512];
	size_t i;
	sw w;
	drv d;
	uint32_t m;

	mk_secret(secret, sizeof(secret), 40u + pt * 16u + ot, 0);
	WRT_CHECK(sw_open(&w, pt, ot) == 0);
	sw_login(&w);
	d = sw_drv(&w, kind);

	for (i = 0; i < sizeof(good) / sizeof(good[0]); i++)
		osd_check(&w, &d, WRI_CONN_MODE_SECURE, 2, 0, (uint32_t)good[i], secret, good[i], WR_OK);
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		osd_check(&w, &d, WRI_CONN_MODE_SECURE, 2, 0, (uint32_t)bad[i], secret, bad[i], WR_E_M2_SECRET);
		WRT_CHECK(drv_err(&d)->a0 == bad[i]);
	}
	osd_check(&w, &d, WRI_CONN_MODE_SECURE, 2, 0, 0, secret, 0, WR_E_M2_SECRET);  /* version 2, empty secret */
	osd_check(&w, &d, WRI_CONN_MODE_SECURE, 1, 0, 0, secret, 0, WR_E_M2_SECRET);  /* version 1: no secret field at all */
	/* crc: version 1, or version 2 with an empty secret: nothing; any secret at all: a protocol error */
	osd_check(&w, &d, WRI_CONN_MODE_CRC, 1, 0, 0, secret, 0, WR_OK);
	osd_check(&w, &d, WRI_CONN_MODE_CRC, 2, 0, 0, secret, 0, WR_OK);
	for (i = 0; i < sizeof(good) / sizeof(good[0]); i++)
		osd_check(&w, &d, WRI_CONN_MODE_CRC, 2, 0, (uint32_t)good[i], secret, good[i], WR_E_AUTH_PROTO);
	osd_check(&w, &d, WRI_CONN_MODE_CRC, 2, 0, 1, secret, 1, WR_E_AUTH_PROTO);
	osd_check(&w, &d, WRI_CONN_MODE_CRC, 2, 0, 129, secret, 129, WR_E_AUTH_PROTO);
	/* a mode that is neither */
	for (m = 0; m < 6; m++) {
		static const uint32_t modes[6] = {0, 3, 4, 7, 99, 0xFFFFFFFFu};

		osd_check(&w, &d, modes[m], 2, 0, 64, secret, 64, WR_E_M2_MODE);
		osd_check(&w, &d, modes[m], 1, 0, 0, secret, 0, WR_E_M2_MODE);
	}
	/* the nonce is judged before the secret, in either mode: a good secret does not rescue a wrong nonce */
	osd_check(&w, &d, WRI_CONN_MODE_SECURE, 2, 1, 64, secret, 64, WR_E_AUTH_DECRYPT);
	osd_check(&w, &d, WRI_CONN_MODE_SECURE, 2, -1, 64, secret, 64, WR_E_AUTH_DECRYPT);
	osd_check(&w, &d, WRI_CONN_MODE_SECURE, 2, 1, 0, secret, 0, WR_E_AUTH_DECRYPT);
	osd_check(&w, &d, WRI_CONN_MODE_CRC, 2, 1, 64, secret, 64, WR_E_AUTH_DECRYPT);
	/* a length beyond the item, in both modes */
	osd_check(&w, &d, WRI_CONN_MODE_SECURE, 2, 0, 64, secret, 63, WR_E_TRUNCATED);
	osd_check(&w, &d, WRI_CONN_MODE_CRC, 2, 0, 64, secret, 10, WR_E_TRUNCATED);
	osd_check(&w, &d, WRI_CONN_MODE_SECURE, 2, 0, 0xFFFFFFFFu, secret, 64, WR_E_TRUNCATED);
	sw_close(&w);
}

static void test_tables(void)
{
	static const unsigned combo[4][2] = {{1, 1}, {2, 2}, {2, 1}, {1, 2}}; /* principal / AUTH key type, OSD key type */
	unsigned i, kind;

	for (i = 0; i < 4; i++)
		for (kind = 0; kind < 2; kind++) { /* the embedded handshake of wri_cx_ops(), a slot of wri_cx_hs_ops() */
			test_mon_table(combo[i][0], combo[i][1], kind);
			test_osd_table(combo[i][0], combo[i][1], kind);
		}
}

/* ---- 4. truncation at every offset ------------------------------------------------------------------------ */

static void test_truncation(unsigned pt, unsigned ot, unsigned kind)
{
	uint8_t secret[128], item[200], pl[4096], cut[4096];
	size_t full, i;
	uint32_t mode;
	sw w;
	drv d;

	mk_secret(secret, sizeof(secret), 77u + pt, 0);
	/* the monitor's payload, secure and crc */
	for (mode = WRI_CONN_MODE_CRC; mode <= WRI_CONN_MODE_SECURE; mode++) {
		size_t slen = mode == WRI_CONN_MODE_SECURE ? 64u : 0u;

		WRT_CHECK(sw_open(&w, pt, ot) == 0);
		d = sw_drv(&w, kind);
		full = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, slen), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
		for (i = 0; i < full; i++) { /* every proper prefix fails and leaves nothing (one login per prefix, one world) */
			wr_status st;

			memcpy(cut, pl, i);
			w.e.c.want_mask = WRI_CX_WANT_MASK;
			WRT_CHECK_STATUS(WR_OK, mon_open(&d, NULL));
			st = d.ops->done(d.a, GID, mode, cut, i);
			WRT_CHECK(st != WR_OK);
			WRT_CHECK(drv_st(&d) == WRI_CX_FAILED && drv_err(&d)->status == st);
			WRT_CHECK(is_zero(drv_sec(&d), sizeof(wri_cx_secret)) && is_zero(w.e.c.scratch, w.e.c.scratch_cap));
			WRT_CHECK(!w.e.c.ticket[0].have && !w.e.c.ticket[1].have && w.e.c.global_id == 0);
			WRT_CHECK(!sw_holds(&w, secret, slen));
		}
		sw_close(&w);
		/* and the whole payload is accepted */
		WRT_CHECK(sw_open(&w, pt, ot) == 0);
		d = sw_drv(&w, kind);
		full = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, slen), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
		mon_check(&w, &d, mode, pl, full, WR_OK, secret, slen, 1);
		sw_close(&w);
		/* the plaintext item cut at every offset (sealed correctly, so the cut is the machine's to find) */
		{
			size_t in = item_secret(item, secret, slen);

			WRT_CHECK(sw_open(&w, pt, ot) == 0);
			d = sw_drv(&w, kind);
			for (i = 0; i < in; i++) {
				full = mon_payload(&w, CBL_SEALED, item, i, &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
				mon_check(&w, &d, mode, pl, full, WR_E_AUTH_PROTO, secret, slen, 1);
			}
			sw_close(&w);
		}
	}
	/* an OSD's payload (u32 len | sealed reply), secure and crc, cut at every offset, and its item cut at every offset */
	for (mode = WRI_CONN_MODE_CRC; mode <= WRI_CONN_MODE_SECURE; mode++) {
		unsigned v = mode == WRI_CONN_MODE_SECURE ? 2u : 1u;
		size_t slen = mode == WRI_CONN_MODE_SECURE ? 64u : 0u;
		uint64_t nonce = 0;
		uint8_t rep[600];
		size_t in, in_full;

		WRT_CHECK(sw_open(&w, pt, ot) == 0);
		sw_login(&w);
		d = sw_drv(&w, kind);
		WRT_CHECK_STATUS(WR_OK, osd_open(&w, &d, &nonce));
		in = osd_item(item, v, nonce + 1u, (uint32_t)slen, secret, slen);
		full = osd_payload(&w, item, in, rep, sizeof(rep));
		in_full = in;
		for (i = 0; i < full; i++) { /* the same begin / more each time: the machine is re-begun in place */
			wr_status st;

			WRT_CHECK_STATUS(WR_OK, osd_open(&w, &d, &nonce));
			in = osd_item(item, v, nonce + 1u, (uint32_t)slen, secret, slen);
			WRT_CHECK(osd_payload(&w, item, in, rep, sizeof(rep)) == full);
			st = d.ops->done(d.a, GID, mode, rep, i);
			WRT_CHECK_STATUS(WR_E_AUTH_PROTO, st);
			WRT_CHECK(is_zero(drv_sec(&d), sizeof(wri_cx_secret)) && !sw_holds(&w, secret, slen));
		}
		for (i = 0; i < in_full; i++) { /* the item, cut */
			uint64_t nn = 0;
			uint8_t pl2[700];
			size_t pn2;
			wr_status st;

			WRT_CHECK_STATUS(WR_OK, osd_open(&w, &d, &nn));
			osd_item(item, v, nn + 1u, (uint32_t)slen, secret, slen);
			pn2 = osd_payload(&w, item, i, pl2, sizeof(pl2));
			st = d.ops->done(d.a, GID, mode, pl2, pn2);
			WRT_CHECK_STATUS(WR_E_TRUNCATED, st);
			WRT_CHECK(is_zero(drv_sec(&d), sizeof(wri_cx_secret)) && !sw_holds(&w, secret, slen));
		}
		sw_close(&w);
	}
}

/* ---- 5. wiping -------------------------------------------------------------------------------------------- */

/* a successful secure monitor done on d, leaving the secret held and not yet taken */
static void hold_mon(sw *w, drv *d, const uint8_t *secret, size_t slen)
{
	uint8_t item[200], pl[4096];
	size_t n = mon_payload(w, CBL_SEALED, item, item_secret(item, secret, slen), &w->ak, NULL, 0, 1, 0, pl, sizeof(pl));

	w->e.c.want_mask = WRI_CX_WANT_MASK;
	WRT_CHECK_STATUS(WR_OK, mon_open(d, NULL));
	WRT_CHECK_STATUS(WR_OK, d->ops->done(d->a, GID, WRI_CONN_MODE_SECURE, pl, n));
	WRT_CHECK(drv_sec(d)->len == slen && !drv_sec(d)->taken && memcmp(drv_sec(d)->buf, secret, slen) == 0);
}

static void hold_osd(sw *w, drv *d, const uint8_t *secret, size_t slen)
{
	uint64_t nonce = 0;
	uint8_t item[300], pl[400];
	size_t n;

	WRT_CHECK_STATUS(WR_OK, osd_open(w, d, &nonce));
	n = osd_item(item, 2, nonce + 1u, (uint32_t)slen, secret, slen);
	n = osd_payload(w, item, n, pl, sizeof(pl));
	WRT_CHECK_STATUS(WR_OK, d->ops->done(d->a, GID, WRI_CONN_MODE_SECURE, pl, n));
	WRT_CHECK(drv_sec(d)->len == slen && !drv_sec(d)->taken);
}

static void test_wiping(unsigned pt, unsigned ot, unsigned kind, int mon)
{
	uint8_t secret[128];
	const uint8_t *s = NULL, *k = NULL;
	size_t sn = 0, kn = 0, i;
	sw w;
	drv d;
	uint8_t b[512];
	wri_wr wr;

	memset(b, 0, sizeof(b));
	mk_secret(secret, sizeof(secret), 5u + pt, 1); /* printable */
#define HOLD()                                                                                                \
	do {                                                                                                  \
		WRT_CHECK(sw_open(&w, pt, ot) == 0);                                                          \
		if (!mon)                                                                                     \
			sw_login(&w);                                                                         \
		d = sw_drv(&w, kind);                                                                         \
		if (mon)                                                                                      \
			hold_mon(&w, &d, secret, 64);                                                         \
		else                                                                                          \
			hold_osd(&w, &d, secret, 64);                                                         \
	} while (0)

	/* positive control: it is held, in the handshake only, and handed out once */
	HOLD();
	WRT_CHECK(sw_holds(&w, secret, 64) && !sw_holds_outside_records(&w, secret, 64));
	d.ops->conn_secret(d.a, &s, &sn);
	WRT_CHECK(s == drv_sec(&d)->buf && sn == 64 && memcmp(s, secret, 64) == 0 && drv_sec(&d)->taken);
	WRT_CHECK(memcmp(s, secret, 64) == 0); /* still readable until the next call of the handshake */
	d.ops->conn_secret(d.a, &s, &sn);       /* a second read: nothing, and nothing stays */
	WRT_CHECK(s == NULL && sn == 0 && is_zero(drv_sec(&d), sizeof(wri_cx_secret)) && !sw_holds(&w, secret, 64));
	sw_close(&w);

	/* the connection asks for the session key (its next step), and for the gid: the secret goes at once */
	HOLD();
	d.ops->session_key(d.a, &k, &kn); /* before the secret was handed out: it stays */
	WRT_CHECK(k != NULL && drv_sec(&d)->len == 64 && !drv_sec(&d)->taken);
	d.ops->conn_secret(d.a, &s, &sn);
	WRT_CHECK(s != NULL && sn == 64);
	d.ops->session_key(d.a, &k, &kn);
	WRT_CHECK(k != NULL);
	expect_released(&d);
	sw_close(&w);
	HOLD();
	d.ops->conn_secret(d.a, &s, &sn);
	(void)d.ops->ident_gid(d.a, mon ? WRI_ENTITY_MON : WRI_ENTITY_OSD);
	expect_released(&d);
	WRT_CHECK(!sw_holds(&w, secret, 64));
	sw_close(&w);

	/* conn_secret with no out pointers releases */
	HOLD();
	d.ops->conn_secret(d.a, NULL, NULL);
	WRT_CHECK(is_zero(drv_sec(&d), sizeof(wri_cx_secret)) && !sw_holds(&w, secret, 64));
	sw_close(&w);

	/* it never leaves the handshake un-taken either: a new begin, a late more, a second done wipe it */
	HOLD();
	wri_wr_init(&wr, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, d.ops->begin(d.a, mon ? WRI_ENTITY_MON : WRI_ENTITY_OSD, &wr));
	WRT_CHECK(is_zero(drv_sec(&d), sizeof(wri_cx_secret)) && !sw_holds(&w, secret, 64));
	expect_released(&d);
	sw_close(&w);
	HOLD();
	wri_wr_init(&wr, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, d.ops->more(d.a, b, 9, &wr)); /* not in a state to receive a reply */
	WRT_CHECK(is_zero(drv_sec(&d), sizeof(wri_cx_secret)) && !sw_holds(&w, secret, 64));
	WRT_CHECK(drv_st(&d) == WRI_CX_FAILED);
	expect_released(&d);
	sw_close(&w);
	HOLD();
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, d.ops->done(d.a, GID, WRI_CONN_MODE_SECURE, b, 4));
	WRT_CHECK(is_zero(drv_sec(&d), sizeof(wri_cx_secret)) && !sw_holds(&w, secret, 64));
	if (mon) /* the shared rule: a failed monitor done forgets everything */
		WRT_CHECK(!w.e.c.ticket[0].have && !w.e.c.ticket[1].have && w.e.c.global_id == 0);
	expect_released(&d);
	sw_close(&w);

	/* forget: the embedded handshake is idle again and its secret gone; a slot's connection could no longer sign
	 * with the key it was keyed for, so it hands out nothing and drops it on that call */
	HOLD();
	wri_cx_forget(&w.e.c);
	if (!d.slot)
		WRT_CHECK(is_zero(drv_sec(&d), sizeof(wri_cx_secret)) && !sw_holds(&w, secret, 64));
	d.ops->conn_secret(d.a, &s, &sn);
	WRT_CHECK(s == NULL && sn == 0 && is_zero(drv_sec(&d), sizeof(wri_cx_secret)) && !sw_holds(&w, secret, 64));
	sw_close(&w);

	/* a swap of the ticket the key lives in (renewal, forget by another handshake) does the same */
	HOLD();
	wri_cx_slot_clear(&w.e.c, mon ? WRI_CX_SLOT_AUTH : WRI_CX_SLOT_OSD);
	d.ops->conn_secret(d.a, &s, &sn);
	WRT_CHECK(s == NULL && sn == 0 && is_zero(drv_sec(&d), sizeof(wri_cx_secret)) && !sw_holds(&w, secret, 64));
	sw_close(&w);

	/* wipe of the slot / client, init of the slot: all zero */
	HOLD();
	if (d.slot) {
		wri_cx_hs *h = (wri_cx_hs *)d.a;

		wri_cx_hs_wipe(h);
		WRT_CHECK(is_zero(h, sizeof(*h)));
		d.ops->conn_secret(h, &s, &sn);
		WRT_CHECK(s == NULL && sn == 0);
		WRT_CHECK(!sw_holds(&w, secret, 64));
	}
	sw_close(&w);
	HOLD();
	if (d.slot) {
		wri_cx_hs *h = (wri_cx_hs *)d.a;

		WRT_CHECK_STATUS(WR_OK, wri_cx_hs_init(h, &w.e.c)); /* re-binding a slot wipes what it held */
		WRT_CHECK(is_zero(&h->sec, sizeof(h->sec)) && !sw_holds(&w, secret, 64));
	}
	sw_close(&w);
	HOLD();
	{
		size_t mem_n = w.e.memsz;
		uint8_t *mem = w.e.mem;

		wri_cx_client_wipe(&w.e.c); /* destroy: the client, its principal, tickets, scratch and the embedded secret */
		if (d.slot)
			wri_cx_hs_wipe((wri_cx_hs *)d.a);
		WRT_CHECK(is_zero(&w.e.c, sizeof(w.e.c)));
		for (i = 0; i < mem_n; i++)
			if (mem[i] != 0) {
				WRT_CHECK(!"arena is zero after the client was wiped");
				break;
			}
		WRT_CHECK(!sw_holds(&w, secret, 64));
	}
	sw_close(&w);
#undef HOLD
}

static void test_wipe_matrix(void)
{
	static const unsigned combo[2][2] = {{2, 2}, {1, 1}};
	unsigned i, kind, mon;

	for (i = 0; i < 2; i++)
		for (kind = 0; kind < 2; kind++)
			for (mon = 0; mon < 2; mon++)
				test_wiping(combo[i][0], combo[i][1], kind, (int)mon);
}

/* ---- 6. the edges of conn_secret ---------------------------------------------------------------------------- */

static void test_edges(void)
{
	const wri_auth_ops *tab[2];
	unsigned t;
	const uint8_t *s = (const uint8_t *)1;
	size_t n = 1;
	sw w;
	drv d;
	wri_cx_hs unbound;
	uint8_t b[256];
	wri_wr wr;

	tab[0] = wri_cx_ops();
	tab[1] = wri_cx_hs_ops();
	for (t = 0; t < 2; t++) {
		WRT_CHECK(tab[t]->conn_secret != NULL);
		/* no handshake, an unbound slot: nothing, and no crash */
		s = (const uint8_t *)1;
		n = 1;
		tab[t]->conn_secret(NULL, &s, &n);
		WRT_CHECK(s == NULL && n == 0);
		memset(&unbound, 0, sizeof(unbound));
		s = (const uint8_t *)1;
		n = 1;
		tab[t]->conn_secret(&unbound, &s, &n);
		WRT_CHECK(s == NULL && n == 0);
		tab[t]->conn_secret(NULL, NULL, NULL);
		tab[t]->conn_secret(&unbound, NULL, NULL);
	}
	/* before begin, in the middle of a handshake, after a crc done, after a failure: nothing */
	for (t = 0; t < 2; t++) {
		uint8_t item[100], pl[4096];
		size_t pn;

		WRT_CHECK(sw_open(&w, 2, 2) == 0);
		d = sw_drv(&w, t);
		d.ops->conn_secret(d.a, &s, &n);
		WRT_CHECK(s == NULL && n == 0);
		WRT_CHECK_STATUS(WR_OK, mon_open(&d, NULL));
		d.ops->conn_secret(d.a, &s, &n);
		WRT_CHECK(s == NULL && n == 0);
		pn = mon_payload(&w, CBL_SEALED, item, item_secret(item, item, 0), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
		WRT_CHECK_STATUS(WR_OK, d.ops->done(d.a, GID, WRI_CONN_MODE_CRC, pl, pn));
		d.ops->conn_secret(d.a, &s, &n);
		WRT_CHECK(s == NULL && n == 0 && is_zero(drv_sec(&d), sizeof(wri_cx_secret)));
		WRT_CHECK_STATUS(WR_E_INVAL, d.ops->done(d.a, GID, WRI_CONN_MODE_SECURE, NULL, 1)); /* argument check, state kept */
		sw_close(&w);
	}
	/* a secret never survives into the next login: begin starts from none even if the last one was never taken */
	for (t = 0; t < 2; t++) {
		uint8_t secret[64];

		WRT_CHECK(sw_open(&w, 1, 1) == 0);
		d = sw_drv(&w, t);
		mk_secret(secret, sizeof(secret), 3, 0);
		hold_mon(&w, &d, secret, 64);
		wri_wr_init(&wr, b, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, d.ops->begin(d.a, WRI_ENTITY_MON, &wr));
		d.ops->conn_secret(d.a, &s, &n);
		WRT_CHECK(s == NULL && n == 0 && !sw_holds(&w, secret, 64));
		sw_close(&w);
	}
}

/* ---- 7. two handshakes, interleaved ------------------------------------------------------------------------- */

#define NACT 3u
#define NSTEP 4u /* begin, more, done, take */

typedef struct act {
	int is_mon;
	drv d;
	uint8_t secret[128];
	size_t slen;
	unsigned step;
	uint64_t nonce;
} act;

typedef struct ilw {
	sw w;
	act a[NACT];
} ilw;

static void act_step(ilw *x, unsigned ai)
{
	act *a = &x->a[ai];
	sw *w = &x->w;
	uint8_t b[512], pl[4096], item[300], ch[128], chi[9];
	wri_wr wr;
	size_t n, cn = 0;
	const uint8_t *s = NULL, *k = NULL;
	size_t sn = 0, kn = 0;

	switch (a->step) {
	case 0:
		wri_wr_init(&wr, b, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, a->d.ops->begin(a->d.a, a->is_mon ? WRI_ENTITY_MON : WRI_ENTITY_OSD, &wr));
		a->nonce = a->is_mon ? 0 : drv_nonce(&a->d);
		break;
	case 1:
		wri_wr_init(&wr, b, sizeof(b));
		if (a->is_mon) {
			chi[0] = 1;
			wri_le64_put(chi + 1, CXT_CHAL + ai);
			WRT_CHECK_STATUS(WR_OK, a->d.ops->more(a->d.a, chi, sizeof(chi), &wr));
		} else {
			chi[0] = 1;
			wri_le64_put(chi + 1, 0xABCD0000ull + ai);
			WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&w->e.x, &w->ok, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, chi, sizeof(chi), ch, sizeof(ch), &cn));
			WRT_CHECK_STATUS(WR_OK, a->d.ops->more(a->d.a, ch, cn, &wr));
		}
		break;
	case 2:
		if (a->is_mon) {
			n = mon_payload(w, CBL_SEALED, item, item_secret(item, a->secret, a->slen), &w->ak, NULL, 0, 0, 0, pl, sizeof(pl));
		} else {
			n = osd_item(item, 2, a->nonce + 1u, (uint32_t)a->slen, a->secret, a->slen);
			n = osd_payload(w, item, n, pl, sizeof(pl));
		}
		WRT_CHECK_STATUS(WR_OK, a->d.ops->done(a->d.a, GID, WRI_CONN_MODE_SECURE, pl, n));
		WRT_CHECK(drv_sec(&a->d)->len == a->slen && memcmp(drv_sec(&a->d)->buf, a->secret, a->slen) == 0);
		break;
	default:
		a->d.ops->conn_secret(a->d.a, &s, &sn);
		WRT_CHECK(s == drv_sec(&a->d)->buf && sn == a->slen && memcmp(s, a->secret, sn) == 0); /* its own, not another's */
		a->d.ops->session_key(a->d.a, &k, &kn);
		WRT_CHECK(k != NULL);
		WRT_CHECK(is_zero(drv_sec(&a->d), sizeof(wri_cx_secret)));
		break;
	}
	a->step++;
	/* every other handshake that holds a secret still holds exactly its own */
	{
		unsigned j;

		for (j = 0; j < NACT; j++) {
			act *o = &x->a[j];

			if (o->step == 3u) /* finished, not yet taken: exactly its own secret */
				WRT_CHECK(drv_sec(&o->d)->len == o->slen && memcmp(drv_sec(&o->d)->buf, o->secret, o->slen) == 0 &&
					  !drv_sec(&o->d)->taken);
			else /* not finished, or taken */
				WRT_CHECK(is_zero(drv_sec(&o->d), sizeof(wri_cx_secret)));
		}
	}
}

static unsigned long g_il_run, g_il_seen, g_il_stride;

static void il_run(unsigned pt, unsigned ot, int mon_embedded, const unsigned *order)
{
	ilw x;
	unsigned i;
	static const size_t lens[NACT] = {64, 100, 40};

	memset(&x, 0, sizeof(x));
	WRT_CHECK(sw_open(&x.w, pt, ot) == 0);
	sw_login(&x.w);
	for (i = 0; i < NACT; i++) {
		x.a[i].is_mon = i == 2;
		x.a[i].slen = lens[i];
		mk_secret(x.a[i].secret, lens[i], 200u + i, i == 1);
		x.a[i].d = sw_drv(&x.w, i == 2 ? (mon_embedded ? 0u : 3u) : i + 1u);
	}
	for (i = 0; i < NACT * NSTEP; i++)
		act_step(&x, order[i]);
	for (i = 0; i < NACT; i++) {
		WRT_CHECK(x.a[i].step == NSTEP);
		expect_released(&x.a[i].d);
	}
	for (i = 0; i < NACT; i++)
		WRT_CHECK(!sw_holds(&x.w, x.a[i].secret, x.a[i].slen));
	sw_close(&x.w);
	g_il_run++;
}

/* every interleaving of NACT actors of NSTEP steps; one in g_il_stride is run */
static void il_walk(unsigned pt, unsigned ot, int mon_embedded, unsigned *order, unsigned depth, unsigned *used)
{
	unsigned a;

	if (depth == NACT * NSTEP) {
		if (g_il_seen++ % g_il_stride == 0)
			il_run(pt, ot, mon_embedded, order);
		return;
	}
	for (a = 0; a < NACT; a++) {
		if (used[a] == NSTEP)
			continue;
		used[a]++;
		order[depth] = a;
		il_walk(pt, ot, mon_embedded, order, depth + 1u, used);
		used[a]--;
	}
}

static void test_interleave(void)
{
	static const unsigned combo[2][2] = {{2, 2}, {1, 2}};
	unsigned i, emb, order[NACT * NSTEP], used[NACT];
	/* 12! / (4!)^3 = 34650 interleavings per world kind; a fixed stride picks a spread of them (all of them are
	 * the same machine, the sample is for the run time under a sanitizer) */
	g_il_stride = UNDER_SAN ? 463u : 151u;
	for (i = 0; i < 2; i++)
		for (emb = 0; emb < 2; emb++) {
			memset(used, 0, sizeof(used));
			g_il_seen = 0;
			il_walk(combo[i][0], combo[i][1], (int)emb, order, 0, used);
			WRT_CHECK(g_il_seen == 34650ul);
		}
	WRT_CHECK(g_il_run >= 4ul * (34650ul / g_il_stride));
	printf("interleaved secure handshakes: %lu orders of 4 x %lu run\n", g_il_run, 34650ul);
}

/* ---- 8. the canary: a printable secret, whole handshakes, nothing leaks ----------------------------------------- */

static void test_canary(void)
{
	static const unsigned combo[2][2] = {{1, 1}, {2, 2}};
	unsigned i, kind, mon;

	for (i = 0; i < 2; i++)
		for (kind = 0; kind < 2; kind++)
			for (mon = 0; mon < 2; mon++) {
				uint8_t secret[128], item[200], pl[4096];
				sw w;
				drv d;
				size_t n;
				const uint8_t *s = NULL, *k = NULL;
				size_t sn = 0, kn = 0;

				memcpy(secret, "CANARYSECRET-0123456789-abcdefghijklmnopqrstuvwxyz-", 51);
				mk_secret(secret + 51, 128 - 51, 9, 1);
				WRT_CHECK(sw_open(&w, combo[i][0], combo[i][1]) == 0);
				if (!mon)
					sw_login(&w);
				d = sw_drv(&w, kind);
				WRT_CHECK(!sw_holds(&w, secret, 128)); /* nothing before */
				if (mon) {
					n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, 128), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
					w.e.c.want_mask = WRI_CX_WANT_MASK;
					WRT_CHECK_STATUS(WR_OK, mon_open(&d, NULL));
					WRT_CHECK_STATUS(WR_OK, d.ops->done(d.a, GID, WRI_CONN_MODE_SECURE, pl, n));
				} else {
					hold_osd(&w, &d, secret, 128);
				}
				/* positive control: while held it is in the handshake's own record and nowhere else */
				WRT_CHECK(sw_holds(&w, secret, 128) && !sw_holds_outside_records(&w, secret, 128));
				WRT_CHECK(has_secret(drv_sec(&d), sizeof(wri_cx_secret), secret, 128));
				d.ops->conn_secret(d.a, &s, &sn);
				WRT_CHECK(s != NULL && sn == 128);
				d.ops->session_key(d.a, &k, &kn);
				/* after the connection took it: in no record, no arena byte, no errinfo */
				WRT_CHECK(!sw_holds(&w, secret, 128));
				WRT_CHECK(!errinfo_leaks(drv_err(&d), secret, 128) && !errinfo_leaks(&w.e.c.err, secret, 128));
				/* after destroy: every byte of the arena, the client and the slots is zero */
				wri_cx_client_wipe(&w.e.c);
				{
					uint32_t j;

					for (j = 0; j < w.nhs; j++)
						wri_cx_hs_wipe(&w.hs[j]);
				}
				WRT_CHECK(is_zero(w.e.mem, w.e.memsz) && is_zero(&w.e.c, sizeof(w.e.c)) && is_zero(w.hsraw, w.hsbytes));
				sw_close(&w);
			}
	/* failures: every refusal of the monitor and the OSD, with a secret that is printable, leaves no trace */
	for (i = 0; i < 2; i++) {
		uint8_t secret[512], item[600], pl[4096];
		size_t j, n;
		sw w;
		drv d;

		memset(secret, 0, sizeof(secret));
		memcpy(secret, "CANARYSECRET-0123456789-abcdefghijklmnopqrstuvwxyz-", 51);
		mk_secret(secret + 51, sizeof(secret) - 51, 11, 1);
		for (j = 0; j < 5; j++) {
			static const size_t lens[5] = {39, 129, 64, 64, 64};

			WRT_CHECK(sw_open(&w, combo[i][0], combo[i][1]) == 0);
			d = sw_drv(&w, (unsigned)(j & 1u));
			if (j == 2) { /* crc with a secret */
				n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, lens[j]), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
				mon_check(&w, &d, WRI_CONN_MODE_CRC, pl, n, WR_E_AUTH_PROTO, secret, lens[j], 1);
			} else if (j == 3) { /* decrypts, then a later part fails */
				n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, lens[j]), &w.ak, NULL, 0, 1, 1, pl, sizeof(pl));
				mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_E_AUTH_DECRYPT, secret, lens[j], 1);
			} else if (j == 4) {
				sw_login(&w);
				osd_check(&w, &d, WRI_CONN_MODE_SECURE, 2, 1, 64, secret, 64, WR_E_AUTH_DECRYPT);
			} else {
				n = mon_payload(&w, CBL_SEALED, item, item_secret(item, secret, lens[j]), &w.ak, NULL, 0, 1, 0, pl, sizeof(pl));
				mon_check(&w, &d, WRI_CONN_MODE_SECURE, pl, n, WR_E_M2_SECRET, secret, lens[j], 1);
			}
			wri_cx_client_wipe(&w.e.c);
			WRT_CHECK(is_zero(w.e.mem, w.e.memsz));
			sw_close(&w);
		}
	}
}

int main(void)
{
	static const unsigned combo[4][2] = {{1, 1}, {2, 2}, {2, 1}, {1, 2}};
	unsigned i, kind;

	test_vector_blobs();
	test_vector_structure();
	test_session_vectors();
	test_other_keys();
	test_tables();
	for (i = 0; i < 4; i++)
		for (kind = 0; kind < 2; kind++)
			test_truncation(combo[i][0], combo[i][1], kind);
	test_wipe_matrix();
	test_edges();
	test_interleave();
	test_canary();
	return wrt_finish();
}
