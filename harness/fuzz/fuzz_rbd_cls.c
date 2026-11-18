/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the RBD class-call decoders (core/src/rbd/wri_rbd_cls_dec.c) and the refusal rules (wri_rbd_policy.c).
 *
 * Byte 0 selects what runs (mode % 13), byte 1 is a parameter, the rest is the payload as an exact-size heap copy so ASan sees any
 * over-read. Every decoder consumes its payload exactly or fails with its own statuses and leaves its outputs cleared; a violated
 * property traps.
 *
 *   0  wri_rbd_dec_id          success: 1..63 ASCII letters / digits and a NUL; failure: BAD_ID or PROTO, buffer zero
 *   1  wri_rbd_dec_size        failure: both outputs zero
 *   2  wri_rbd_dec_prefix      success: 1..WRI_RBD_PREFIX_LEN_MAX visible ASCII bytes and a NUL; failure: buffer zero
 *   3  wri_rbd_dec_features    failure: both outputs zero
 *   4  wri_rbd_dec_u64 and wri_rbd_dec_i64 (byte 1 odd: i64)
 *   5  wri_rbd_dec_snapcontext, cap = byte 1 % 10: success: n <= cap, valid (descending, first <= seq, seq <= max), n_total == n;
 *                              SNAPC with more ids than the cap: nothing stored, n_total = the count; failure: seq 0, n 0
 *   6  wri_rbd_dec_parent      has_parent is 0 or 1; failure: 0
 *   7  wri_rbd_dec_overlap     present is 0 or 1 (absent: overlap 0); failure: both 0
 *   8  wri_rbd_dec_stripe      failure: both zero
 *   9  wri_rbd_dec_lock_info, tag_cap = byte 1 % 20: lockers <= 64, type <= 3, the tag NUL terminated inside the capacity; failure: cleared
 *   10 wri_rbd_check_profile on a header made from the payload (byte 1 odd: writer): the status is one of the six refusals or OK, an
 *                              OK header satisfies every rule of the note, a refusal fills the errinfo
 *   11 every decoder above on the same payload (no property beyond "does not crash")
 *   12 the encoders (rbd and lock classes) with strings of 0 to 319 bytes into a writer of 0 to 1020 bytes (byte 1 * 4): a string above
 *      255 bytes is WR_E_TOOBIG and leaves the writer untouched, a writer that is too small is WR_E_TOOBIG with the writer in error, the
 *      record is cleared on any failure, and what a successful call wrote parses back to the arguments, with in_len exact
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_denc.h"
#include "wri_rbd_cls.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

static uint8_t *heap_copy(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n ? n : 1);

	if (q != NULL && n != 0)
		memcpy(q, p, n);
	return q;
}

static int all_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != 0)
			return 0;
	return 1;
}

static int status_ok_for_decoder(wr_status st)
{
	return st == WR_OK || st == WR_E_RBD_PROTO || st == WR_E_RBD_BAD_ID || st == WR_E_RBD_SNAPC;
}

static void fuzz_id(const uint8_t *p, uint32_t n)
{
	char id[WRI_RBD_ID_MAX];
	wr_status st;
	size_t i, len;

	memset(id, 0x5a, sizeof(id));
	st = wri_rbd_dec_id(p, n, id);
	check(status_ok_for_decoder(st) && st != WR_E_RBD_SNAPC);
	if (st != WR_OK) {
		check(all_zero(id, sizeof(id)));
		return;
	}
	len = strlen(id);
	check(len >= 1 && len < WRI_RBD_ID_MAX && (size_t)n == len + 4);
	for (i = 0; i < len; i++)
		check((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'z') || (id[i] >= 'A' && id[i] <= 'Z'));
}

static void fuzz_prefix(const uint8_t *p, uint32_t n)
{
	char px[WRI_RBD_PREFIX_MAX];
	wr_status st;
	size_t i, len;

	memset(px, 0x5a, sizeof(px));
	st = wri_rbd_dec_prefix(p, n, px);
	check(status_ok_for_decoder(st) && st != WR_E_RBD_SNAPC);
	if (st != WR_OK) {
		check(all_zero(px, sizeof(px)));
		return;
	}
	len = strlen(px);
	check(len >= 1 && len <= WRI_RBD_PREFIX_LEN_MAX && (size_t)n == len + 4);
	for (i = 0; i < len; i++)
		check((uint8_t)px[i] >= 0x21 && (uint8_t)px[i] <= 0x7e);
}

static void fuzz_snapc(const uint8_t *p, uint32_t n, unsigned cap)
{
	uint64_t store[10];
	wri_snapc s;
	uint32_t tot = 0xdeadbeefu, i;
	wr_status st;

	memset(store, 0x5a, sizeof(store));
	s.seq = 0x1234;
	s.n = 77;
	s.cap = cap;
	s.snaps = store;
	st = wri_rbd_dec_snapcontext(p, n, &s, &tot);
	check(status_ok_for_decoder(st) && st != WR_E_RBD_BAD_ID);
	check(s.cap == cap && s.snaps == store);
	if (st != WR_OK) {
		check(s.seq == 0 && s.n == 0);
		if (st == WR_E_RBD_PROTO)
			check(tot == 0);
		return;
	}
	check(s.n <= cap && tot == s.n && s.seq <= WRI_SNAP_MAX && (size_t)n == 12u + 8u * (size_t)s.n);
	check(wri_snapc_valid(&s)); /* the decoder and the validator of the message layer agree */
	for (i = 0; i < s.n; i++) {
		check(store[i] <= s.seq);
		if (i != 0)
			check(store[i] < store[i - 1]);
	}
}

static void fuzz_lock(const uint8_t *p, uint32_t n, unsigned tag_cap)
{
	char tag[20];
	uint32_t nl = 0xdeadbeefu;
	uint8_t ty = 0xee;
	wr_status st;

	memset(tag, 0x5a, sizeof(tag));
	st = wri_rbd_dec_lock_info(p, n, &nl, &ty, tag_cap != 0 ? tag : NULL, tag_cap);
	check(st == WR_OK || st == WR_E_RBD_PROTO);
	if (st != WR_OK) {
		check(nl == 0 && ty == 0);
		if (tag_cap != 0)
			check(all_zero(tag, tag_cap));
		return;
	}
	check(nl <= 64 && ty <= 3);
	if (tag_cap != 0) {
		check(memchr(tag, 0, tag_cap) != NULL);
		check(tag_cap >= sizeof(tag) || tag[tag_cap] == 0x5a); /* nothing written past the capacity */
	}
}

static void fuzz_policy(const uint8_t *p, size_t n, int writer)
{
	wri_rbd_hdr h;
	wr_errinfo why;
	wr_status st;
	uint64_t mask;
	uint8_t raw[56];

	memset(raw, 0, sizeof(raw));
	memcpy(raw, p, n < sizeof(raw) ? n : sizeof(raw));
	memset(&h, 0, sizeof(h));
	h.order = raw[0];
	h.has_parent = raw[1] & 1u;
	h.has_overlap = (raw[1] >> 1) & 1u;
	memcpy(&h.features, raw + 2, 8);
	memcpy(&h.flags, raw + 10, 8);
	memcpy(&h.op_features, raw + 18, 8);
	memcpy(&h.overlap, raw + 26, 8);
	memcpy(&h.stripe_unit, raw + 34, 8);
	memcpy(&h.stripe_count, raw + 42, 4); /* small counts reach the interesting values */
	memcpy(&h.data_pool_id, raw + 46, 8);
	memset(&why, 0, sizeof(why));
	st = wri_rbd_check_profile(&h, writer, &why);
	check(st == WR_OK || st == WR_E_RBD_FEATURES || st == WR_E_RBD_ORDER || st == WR_E_RBD_STRIPING || st == WR_E_RBD_PARENT ||
	      st == WR_E_RBD_DATA_POOL || st == WR_E_RBD_FLAGS);
	check(why.status == st);
	if (st != WR_OK) {
		check(why.module == WR_MOD_RBD && why.what != NULL);
		return;
	}
	/* an accepted header satisfies every rule */
	mask = writer ? (0xa1ull | 0x2ull) : 0x1ffull;
	check((h.features & ~mask) == 0);
	check(h.order >= 12 && h.order <= 25);
	if ((h.features & 0x2) != 0 && h.stripe_unit != 0 && h.stripe_count != 0)
		check(h.stripe_count == 1 && h.stripe_unit == (1ull << h.order));
	check(!h.has_parent && !h.has_overlap);
	if ((h.features & 0x100) != 0)
		check((h.op_features & 2) == 0);
	if ((h.features & 0x80) != 0)
		check(h.data_pool_id >= 0);
	if (writer)
		check(h.flags == 0);
}

/* ---- the encoders ------------------------------------------------------------------------------------------------------ */

static char *mk_str(const uint8_t *src, size_t srcn, size_t len, unsigned salt)
{
	char *s = (char *)malloc(len + 1u);
	size_t i;

	if (s == NULL)
		return NULL;
	for (i = 0; i < len; i++) /* printable, never a NUL: the encoders take C strings */
		s[i] = (char)(33u + ((srcn != 0 ? src[i % srcn] : 0u) + salt + (unsigned)i) % 94u);
	s[len] = '\0';
	return s;
}

static int op_is_zero(const wri_osd_opd *op)
{
	return all_zero(op, sizeof(*op));
}

/* One string field of a lock argument: u32 length + bytes, equal to `want`. */
static int rd_lstr(wri_rd *r, const char *want)
{
	uint32_t n = 0;
	const uint8_t *q = wri_denc_str(r, &n, 0xffffu);

	return q != NULL && n == strlen(want) && memcmp(q, want, n) == 0;
}

/* What a successful call left in the writer, from `start`: class | method | argument, the record agreeing with it. */
static void parse_call(const wri_wr *w, size_t start, const wri_osd_opd *op, const char *cls, const char *meth, size_t arg_len,
		       const char *s1, const char *s2, const char *s3, int has_type, uint8_t type)
{
	size_t cl = strlen(cls), ml = strlen(meth);
	const uint8_t *b = w->p + start;
	size_t n = w->pos - start;
	wri_rd r;

	check(op->code == WRI_OSD_OP_CALL && op->flags == 0 && op->off == 0 && op->len == 0 && op->out_len == 0 && op->rval == 0);
	check(op->in_len == n && op->cls_class_len == cl && op->cls_method_len == ml);
	check(n >= cl + ml && memcmp(b, cls, cl) == 0 && memcmp(b + cl, meth, ml) == 0);
	if (arg_len != (size_t)-1)
		check(n == cl + ml + arg_len);
	if (s1 != NULL) { /* a lock argument: the envelope v1 / compat 1 around the fields, exactly its length */
		wri_env e;

		wri_rd_init(&r, b + cl + ml, n - cl - ml);
		check(wri_env_open(&r, 1u, &e) == WR_OK && e.v == 1 && e.compat == 1 && wri_rd_left(&r) == 0);
		check(rd_lstr(&e.body, s1));
		if (has_type)
			check(wri_rd_u8(&e.body) == type);
		if (s2 != NULL)
			check(rd_lstr(&e.body, s2));
		if (s3 != NULL) {
			uint32_t sec = 1, nsec = 1;

			check(rd_lstr(&e.body, s3)); /* the tag */
			check(rd_lstr(&e.body, ""));  /* description */
			wri_denc_utime(&e.body, &sec, &nsec);
			check(sec == 0 && nsec == 0 && wri_rd_u8(&e.body) == 0);
		}
		check(wri_rd_ok(&e.body) && wri_rd_left(&e.body) == 0);
	}
}

static void fuzz_enc(const uint8_t *p, size_t n, uint8_t param)
{
	static const struct {
		const char *meth;
		size_t arg;
	} plain[9] = {{"get_id", 0},          {"get_object_prefix", 0}, {"get_flags", 8},      {"get_snapcontext", 0},
		      {"get_data_pool", 0},    {"parent_get", 0},        {"parent_overlap_get", 8}, {"get_stripe_unit_count", 0},
		      {"op_features_get", 0}};
	size_t cap = (size_t)param * 4u, start, l1, l2, l3, srcn, k;
	uint8_t *mem, kind, sel;
	char *s1, *s2, *s3;
	wri_wr w;
	wri_osd_opd op;
	wr_status st = WR_E_INVAL;
	int too_long, snap_call = 0;
	uint64_t snap = 0;

	if (n < 6)
		return;
	kind = p[0] % 6u;
	sel = p[1];
	l1 = (size_t)p[2] + ((p[5] & 1u) != 0 ? 64u : 0u); /* 0 .. 319: the limit of 255 is in the middle of the range */
	l2 = (size_t)p[3] + ((p[5] & 2u) != 0 ? 64u : 0u);
	l3 = (size_t)p[4] + ((p[5] & 4u) != 0 ? 64u : 0u);
	p += 6;
	n -= 6;
	srcn = n;
	for (k = 0; k < 8 && k < n; k++)
		snap |= (uint64_t)p[k] << (8u * k);
	s1 = mk_str(p, srcn, l1, 1);
	s2 = mk_str(p, srcn, l2, 7);
	s3 = mk_str(p, srcn, l3, 13);
	mem = (uint8_t *)malloc(cap != 0 ? cap : 1u);
	if (s1 == NULL || s2 == NULL || s3 == NULL || mem == NULL)
		goto out;
	wri_wr_init(&w, mem, cap);
	if (cap >= 4)
		wri_wr_u32(&w, 0xa5a5a5a5u); /* something already in the message: the call starts at a non-zero offset */
	start = w.pos;
	memset(&op, 0xa5, sizeof(op));
	switch (kind) {
	case 0:
		too_long = l1 > 255 || l2 > 255 || l3 > 255; /* name, cookie, tag */
		st = wri_rbd_put_lock_lock(&w, &op, s1, (uint8_t)(sel >> 4), s2, s3);
		break;
	case 1:
		too_long = l1 > 255 || l2 > 255;
		st = wri_rbd_put_lock_unlock(&w, &op, s1, s2);
		break;
	case 2:
		too_long = l1 > 255;
		st = wri_rbd_put_lock_get_info(&w, &op, s1);
		break;
	case 3:
		too_long = 0;
		snap_call = 1;
		st = wri_rbd_put_get_features(&w, &op, snap, (int)(int8_t)sel);
		break;
	case 4:
		too_long = 0;
		snap_call = 1;
		st = wri_rbd_put_get_size(&w, &op, snap);
		break;
	default:
		too_long = 0;
		st = sel % 9u == 2u ? wri_rbd_put_get_flags(&w, &op, snap)
		     : sel % 9u == 6u ? wri_rbd_put_parent_overlap_get(&w, &op, snap)
		     : sel % 9u == 0u ? wri_rbd_put_get_id(&w, &op)
		     : sel % 9u == 1u ? wri_rbd_put_get_object_prefix(&w, &op)
		     : sel % 9u == 3u ? wri_rbd_put_get_snapcontext(&w, &op)
		     : sel % 9u == 4u ? wri_rbd_put_get_data_pool(&w, &op)
		     : sel % 9u == 5u ? wri_rbd_put_parent_get(&w, &op)
		     : sel % 9u == 7u ? wri_rbd_put_get_stripe_unit_count(&w, &op)
					: wri_rbd_put_op_features_get(&w, &op);
		break;
	}
	check(w.pos <= cap);
	if (too_long) {
		check(st == WR_E_TOOBIG && op_is_zero(&op) && w.pos == start); /* nothing was written for a refused string */
		goto out;
	}
	if (st != WR_OK) {
		check(st == WR_E_TOOBIG && w.err == WR_E_TOOBIG && op_is_zero(&op)); /* the writer was too small: it holds the error */
		goto out;
	}
	check(w.err == WR_OK);
	switch (kind) {
	case 0:
		parse_call(&w, start, &op, "lock", "lock", (size_t)-1, s1, s2, s3, 1, (uint8_t)(sel >> 4));
		break;
	case 1:
		parse_call(&w, start, &op, "lock", "unlock", (size_t)-1, s1, s2, NULL, 0, 0);
		break;
	case 2:
		parse_call(&w, start, &op, "lock", "get_info", 6u + 4u + l1, s1, NULL, NULL, 0, 0);
		break;
	case 3:
		parse_call(&w, start, &op, "rbd", "get_features", (int8_t)sel >= 0 ? 9u : 8u, NULL, NULL, NULL, 0, 0);
		break;
	case 4:
		parse_call(&w, start, &op, "rbd", "get_size", 8u, NULL, NULL, NULL, 0, 0);
		break;
	default:
		parse_call(&w, start, &op, "rbd", plain[sel % 9u].meth, plain[sel % 9u].arg, NULL, NULL, NULL, 0, 0);
		break;
	}
	if (snap_call || (kind == 5 && plain[sel % 9u].arg == 8)) { /* the snapshot id is the first (or only) argument, little-endian */
		const uint8_t *a = w.p + start + op.cls_class_len + op.cls_method_len;

		for (k = 0; k < 8; k++)
			check(a[k] == (uint8_t)(snap >> (8u * k)));
	}
out:
	free(s1);
	free(s2);
	free(s3);
	free(mem);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t mode, param;
	const uint8_t *payload;
	size_t pn;
	uint8_t *buf;

	if (size < 2)
		return 0;
	mode = (uint8_t)(data[0] % 13u);
	param = data[1];
	payload = data + 2;
	pn = size - 2;
	if (pn > 0xffffffu)
		pn = 0xffffffu;
	buf = heap_copy(payload, pn);
	if (buf == NULL)
		return 0;

	if (mode == 10) {
		fuzz_policy(buf, pn, param & 1);
	} else if (mode == 12) {
		fuzz_enc(buf, pn, param);
	} else if (mode == 11) {
		/* every decoder on the same bytes */
		fuzz_id(buf, (uint32_t)pn);
		fuzz_prefix(buf, (uint32_t)pn);
		fuzz_snapc(buf, (uint32_t)pn, param % 10u);
		fuzz_lock(buf, (uint32_t)pn, param % 20u);
	} else {
		uint8_t order = 0xee, has = 0xee, pres = 0xee;
		uint64_t a = 0xdead, b = 0xbeef;
		int64_t iv = 0x1234;
		wr_status st = WR_OK;

		switch (mode) {
		case 0:
			fuzz_id(buf, (uint32_t)pn);
			break;
		case 1:
			st = wri_rbd_dec_size(buf, (uint32_t)pn, &order, &a);
			check(st == WR_OK ? pn == 9 : (st == WR_E_RBD_PROTO && order == 0 && a == 0));
			break;
		case 2:
			fuzz_prefix(buf, (uint32_t)pn);
			break;
		case 3:
			st = wri_rbd_dec_features(buf, (uint32_t)pn, &a, &b);
			check(st == WR_OK ? pn == 16 : (st == WR_E_RBD_PROTO && a == 0 && b == 0));
			break;
		case 4:
			if ((param & 1u) != 0) {
				st = wri_rbd_dec_i64(buf, (uint32_t)pn, &iv);
				check(st == WR_OK ? pn == 8 : (st == WR_E_RBD_PROTO && iv == 0));
			} else {
				st = wri_rbd_dec_u64(buf, (uint32_t)pn, &a);
				check(st == WR_OK ? pn == 8 : (st == WR_E_RBD_PROTO && a == 0));
			}
			break;
		case 5:
			fuzz_snapc(buf, (uint32_t)pn, param % 10u);
			break;
		case 6:
			st = wri_rbd_dec_parent(buf, (uint32_t)pn, &has);
			check(st == WR_OK ? has <= 1 : (st == WR_E_RBD_PROTO && has == 0));
			break;
		case 7:
			st = wri_rbd_dec_overlap(buf, (uint32_t)pn, &pres, &a);
			check(st == WR_OK ? (pres <= 1 && (pres == 1 || a == 0)) : (st == WR_E_RBD_PROTO && pres == 0 && a == 0));
			break;
		case 8:
			st = wri_rbd_dec_stripe(buf, (uint32_t)pn, &a, &b);
			check(st == WR_OK ? pn == 16 : (st == WR_E_RBD_PROTO && a == 0 && b == 0));
			break;
		default:
			fuzz_lock(buf, (uint32_t)pn, param % 20u);
			break;
		}
	}
	free(buf);
	return 0;
}
