/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the rbd:// URL parser (core/src/rburl, wr_rburl.h).
 *
 * Input: byte 0 is a set of flags (0xff selects mode 1), the rest is cut into the six texts of a wr_rburl_in by two-byte
 * little-endian lengths (a length is cut to what is left). Flag bits 0x01 .. 0x10: the user, authority, path, query and
 * set_user pointers are NULL (absent); 0x20: the key text is a real key instead of field 6 (type by bit 0x40);
 * 0x80: the URL had a password. Every text is an
 * exact-size heap copy with no terminator, so ASan sees any over-read.
 *
 *   mode 0 (the whole parser). Properties, each of which traps when violated:
 *     - the status is one of the known set (the module's own block, WR_E_UNSUPPORTED, WR_E_INVAL and the two monitor-list
 *       statuses); a failure leaves the spec all zero and an errinfo whose status is the returned one, with a static
 *       `what`, module WR_MOD_HOST, and, for the statuses that point into the query, a place that lies inside it;
 *     - the result is a function of the input only: the same input with the spec and the errinfo pre-filled with other
 *       bytes gives bit-identical results (a decision taken on an uninitialised byte shows up as a difference);
 *     - a success holds the documented invariants (counts, ranges, NUL-terminated names that pass the name rules, a
 *       valid key) and survives a round trip: the spec is written out again as a canonical URL and parsed to the same
 *       spec, byte for byte.
 *   mode 1 (the percent decoder): compared with an independent decoder written here, for caps from 1 to 40.
 *
 * Seeds: harness/fuzz/seeds/fuzz_rburl/ (the committed corpus ctest replays).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wri_rburl.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define KEY_AES "AQAA8VNlAAAAABAAAAECAwQFBgcICQoLDA0ODw=="
#define KEY_256 "AgAA8VNlAAAAACAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

static uint8_t *heap_copy(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n ? n : 1u);

	if (q != NULL && n != 0)
		memcpy(q, p, n);
	return q;
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

static int known_status(wr_status st)
{
	return st == WR_OK || st == WR_E_INVAL || st == WR_E_UNSUPPORTED || st == WR_E_MON_HOSTS_SYNTAX || st == WR_E_MON_NO_V2_ADDR ||
	       (st <= -260 && st >= -276);
}

static size_t blen(const char *s, size_t cap)
{
	size_t n = 0;

	while (n < cap && s[n] != '\0')
		n++;
	return n;
}

static int name_ok(const char *s, size_t cap)
{
	size_t n = blen(s, cap);
	size_t i;

	if (n == 0 || n >= cap)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)s[i];

		if (c < 0x21u || c > 0x7eu || c == '/' || c == '@')
			return 0;
	}
	return 1;
}

/* ---- the canonical form of a spec, for the round trip ------------------------------------------------------- */

static void app_c(char *out, size_t *o, size_t cap, char c)
{
	check(*o + 1u < cap);
	out[(*o)++] = c;
	out[*o] = '\0';
}

static void app_num(char *out, size_t *o, size_t cap, unsigned long v, unsigned base)
{
	char tmp[24];
	size_t n = 0;

	do {
		unsigned d = (unsigned)(v % base);

		tmp[n++] = (char)(d < 10u ? '0' + d : 'a' + (d - 10u));
		v /= base;
	} while (v != 0);
	while (n != 0)
		app_c(out, o, cap, tmp[--n]);
}

static void app_s(char *out, size_t *o, size_t cap, const char *s)
{
	while (*s != '\0')
		app_c(out, o, cap, *s++);
}

/* "v2:a.b.c.d:port[/nonce]" or "v2:[g:g:g:g:g:g:g:g]:port[/nonce]", comma separated (the explicit v2 keeps a port of 6789) */
static size_t write_mons(const wr_rburl_spec *sp, char *out, size_t cap)
{
	size_t o = 0, i, k;

	out[0] = '\0';
	for (i = 0; i < sp->n_mons; i++) {
		const wr_addr *a = &sp->mons[i];

		if (i != 0)
			app_c(out, &o, cap, ',');
		app_s(out, &o, cap, "v2:");
		if (a->family == WR_AF_IPV4) {
			for (k = 0; k < 4; k++) {
				if (k != 0)
					app_c(out, &o, cap, '.');
				app_num(out, &o, cap, a->ip[k], 10);
			}
		} else {
			check(a->family == WR_AF_IPV6);
			app_c(out, &o, cap, '[');
			for (k = 0; k < 8; k++) {
				if (k != 0)
					app_c(out, &o, cap, ':');
				app_num(out, &o, cap, (unsigned long)((a->ip[2 * k] << 8) | a->ip[2 * k + 1]), 16);
			}
			app_c(out, &o, cap, ']');
		}
		app_c(out, &o, cap, ':');
		app_num(out, &o, cap, a->port, 10);
		if (a->nonce != 0) {
			app_c(out, &o, cap, '/');
			app_num(out, &o, cap, a->nonce, 10);
		}
	}
	return o;
}

static const char *mode_word(unsigned m)
{
	return m == WR_MODE_CRC_ONLY ? "crc" : m == WR_MODE_CRC_FIRST ? "crc-first" : m == WR_MODE_SECURE_FIRST ? "secure-first" : "secure";
}

static size_t write_query(const wr_rburl_spec *sp, char *out, size_t cap)
{
	static const char *const dp[] = {"vendor", "uri", "sata"};
	static const char *const ho[] = {"nokey", "key", "none"};
	size_t o = 0, i;
	int n;

	n = snprintf(out, cap, "mode=%s&ro=%u&timeout=%u&readahead=%u&devpath=%s&handoff=%s", mode_word(sp->mode), (unsigned)sp->read_only,
		     (unsigned)(sp->open_timeout_ms / 1000u), (unsigned)sp->readahead_kib, dp[sp->devpath], ho[sp->handoff]);
	check(n > 0 && (size_t)n < cap);
	o = (size_t)n;
	if (sp->mapmem_kib != 0) {
		n = snprintf(out + o, cap - o, "&mapmem=%u", (unsigned)sp->mapmem_kib);
		check(n > 0 && (size_t)n < cap - o);
		o += (size_t)n;
	}
	if (sp->monmsg_kib != 0) {
		n = snprintf(out + o, cap - o, "&monmsg=%u", (unsigned)sp->monmsg_kib);
		check(n > 0 && (size_t)n < cap - o);
		o += (size_t)n;
	}
	if (sp->fsid_known != 0) {
		n = snprintf(out + o, cap - o, "&fsid=");
		check(n > 0 && (size_t)n < cap - o);
		o += (size_t)n;
		for (i = 0; i < 16; i++) {
			n = snprintf(out + o, cap - o, "%s%02x", (i == 4 || i == 6 || i == 8 || i == 10) ? "-" : "", (unsigned)sp->fsid[i]);
			check(n > 0 && (size_t)n < cap - o);
			o += (size_t)n;
		}
	}
	return o;
}

static void round_trip(const wr_rburl_spec *sp, const char *key_text, size_t key_len)
{
	char mons[WR_MAX_MONS * 100u];
	char path[WR_RBURL_NAME_MAX * 2u + 4u];
	char query[256];
	wr_rburl_in in;
	wr_rburl_spec again;
	wr_errinfo e;
	size_t mn, qn;
	int pn;

	mn = write_mons(sp, mons, sizeof(mons));
	qn = write_query(sp, query, sizeof(query));
	pn = snprintf(path, sizeof(path), "/%s/%s", sp->pool, sp->image);
	check(pn > 0 && (size_t)pn < sizeof(path));
	memset(&in, 0, sizeof(in));
	in.user = sp->user;
	in.user_len = strlen(sp->user);
	in.authority = mons;
	in.authority_len = mn;
	in.path = path;
	in.path_len = (size_t)pn;
	in.query = query;
	in.query_len = qn;
	in.set_key = key_text;
	in.set_key_len = key_len;
	check(wr_rburl_parse(&in, &again, &e) == WR_OK);
	check(memcmp(&again, sp, sizeof(again)) == 0);
}

/* ---- mode 0 ---------------------------------------------------------------------------------------------------- */

static void fuzz_parse(uint8_t flags, const uint8_t *p, size_t n)
{
	uint8_t *copy[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
	size_t len[6] = {0, 0, 0, 0, 0, 0}, i, pos = 0;
	wr_rburl_in in;
	wr_rburl_spec s1, s2;
	wr_errinfo e1, e2;
	wr_status st1, st2;
	const char *key_default = (flags & 0x40u) ? KEY_256 : KEY_AES;

	for (i = 0; i < 6; i++) {
		size_t l = 0;

		if (n - pos >= 2u) {
			l = (size_t)p[pos] | ((size_t)p[pos + 1u] << 8);
			pos += 2u;
		}
		if (l > n - pos)
			l = n - pos;
		len[i] = l;
		copy[i] = heap_copy(p + pos, l);
		pos += l;
		if (copy[i] == NULL)
			goto out;
	}
	memset(&in, 0, sizeof(in));
	in.user = (flags & 0x01u) ? NULL : (const char *)copy[0];
	in.authority = (flags & 0x02u) ? NULL : (const char *)copy[1];
	in.path = (flags & 0x04u) ? NULL : (const char *)copy[2];
	in.query = (flags & 0x08u) ? NULL : (const char *)copy[3];
	in.set_user = (flags & 0x10u) ? NULL : (const char *)copy[4];
	in.set_key = (const char *)copy[5];
	in.user_len = in.user ? len[0] : 0;
	in.authority_len = in.authority ? len[1] : 0;
	in.path_len = in.path ? len[2] : 0;
	in.query_len = in.query ? len[3] : 0;
	in.set_user_len = in.set_user ? len[4] : 0;
	in.set_key_len = len[5];
	in.has_password = (uint8_t)((flags & 0x80u) != 0);
	/* bit 0x20: the key text is a real key (type by bit 0x40) instead of the hostile field, so the parts after it are reached */
	if ((flags & 0x20u) != 0) {
		in.set_key = key_default;
		in.set_key_len = strlen(key_default);
	}

	memset(&s1, 0x00, sizeof(s1));
	memset(&e1, 0x00, sizeof(e1));
	memset(&s2, 0xa5, sizeof(s2));
	memset(&e2, 0xa5, sizeof(e2));
	st1 = wr_rburl_parse(&in, &s1, &e1);
	st2 = wr_rburl_parse(&in, &s2, &e2);
	check(st1 == st2 && known_status(st1));
	check(memcmp(&s1, &s2, sizeof(s1)) == 0 && memcmp(&e1, &e2, sizeof(e1)) == 0);
	check(strlen(wr_rburl_strerror(st1)) > 3u && wr_rburl_status_name(st1) != NULL);
	if (st1 != WR_OK) {
		check(is_zero(&s1, sizeof(s1)));
		check(e1.status == st1 && e1.what != NULL && e1.module == WR_MOD_HOST && e1.conn == 0 && e1.peer_result == 0);
		if (st1 <= -271 && st1 >= -276) { /* ESCAPE .. OPT_RANGE: the place is in the query */
			check(in.query != NULL && e1.a0 <= in.query_len && e1.a1 <= in.query_len - e1.a0);
			check(e1.a2 == 0 || (e1.a2 <= in.query_len && e1.a2 > e1.a0));
		}
		goto out;
	}
	check(is_zero(&e1, sizeof(e1)));
	check(s1.n_mons >= 1 && s1.n_mons <= WR_MAX_MONS);
	for (i = 0; i < WR_MAX_MONS + 1u; i++) /* the scratch slot after the last one is zero too */
		check(i < s1.n_mons ? (s1.mons[i].family == WR_AF_IPV4 || s1.mons[i].family == WR_AF_IPV6) && s1.mons[i].port != 0
				    : is_zero(&s1.mons[i], sizeof(s1.mons[i])));
	check(name_ok(s1.pool, sizeof(s1.pool)) && name_ok(s1.image, sizeof(s1.image)) && s1.snap[0] == '\0');
	check(blen(s1.user, sizeof(s1.user)) > 0 && blen(s1.user, sizeof(s1.user)) < sizeof(s1.user));
	check(s1.mode >= WR_MODE_CRC_ONLY && s1.mode <= WR_MODE_SECURE_ONLY && s1.read_only <= 1 && s1.devpath <= 2 && s1.handoff <= 2);
	check(s1.fsid_known <= 1 && (s1.fsid_known != 0 || is_zero(s1.fsid, 16)));
	check(s1.open_timeout_ms >= 1000u && s1.open_timeout_ms <= 600000u && s1.open_timeout_ms % 1000u == 0);
	check(s1.readahead_kib <= WR_RBURL_READAHEAD_MAX_KIB);
	check(s1.mapmem_kib == 0 || (s1.mapmem_kib >= WR_RBURL_MAPMEM_MIN_KIB && s1.mapmem_kib <= WR_RBURL_MAPMEM_MAX_KIB));
	check(s1.monmsg_kib == 0 || (s1.monmsg_kib >= WR_RBURL_MONMSG_MIN_KIB && s1.monmsg_kib <= WR_RBURL_MONMSG_MAX_KIB));
	check((s1.key.type == WR_KEY_TYPE_AES && s1.key.len >= 16) || (s1.key.type == WR_KEY_TYPE_AES256K && s1.key.len >= 32));
	check(is_zero(s1.reserved8, sizeof(s1.reserved8)));
	round_trip(&s1, (const char *)in.set_key, in.set_key_len);
	wr_rburl_spec_wipe(&s1);
	check(is_zero(&s1, sizeof(s1)));
out:
	for (i = 0; i < 6; i++)
		free(copy[i]);
}

/* ---- mode 1: the percent decoder against an independent one -------------------------------------------------- */

static int hexv(int c)
{
	const char *d = "0123456789abcdef", *D = "0123456789ABCDEF";
	int i;

	for (i = 0; i < 16; i++)
		if (c == d[i] || c == D[i])
			return i;
	return -1;
}

static void fuzz_unescape(uint8_t capb, const uint8_t *p, size_t n)
{
	uint8_t *raw = heap_copy(p, n);
	size_t cap = 1u + (size_t)(capb % 40u), i = 0, o = 0, len = 77;
	char out[48], want[48];
	int rc, wrc = WRI_RBURL_ESC_OK;

	if (raw == NULL)
		return;
	while (i < n && wrc == WRI_RBURL_ESC_OK) {
		unsigned c = raw[i];

		if (c < 0x21u || c > 0x7eu) {
			wrc = WRI_RBURL_ESC_BAD;
			break;
		}
		if (c == '%') {
			int h = -1, l = -1;

			if (i + 2u < n) { /* "%XX" needs two bytes after the percent sign */
				h = hexv(raw[i + 1u]);
				l = hexv(raw[i + 2u]);
			}
			if (h < 0 || l < 0 || (h == 0 && l == 0)) {
				wrc = WRI_RBURL_ESC_BAD;
				break;
			}
			c = (unsigned)(h * 16 + l);
			i += 3u;
		} else {
			i++;
		}
		if (o + 1u >= cap) {
			wrc = WRI_RBURL_ESC_TOO_LONG;
			break;
		}
		want[o++] = (char)c;
	}
	if (wrc != WRI_RBURL_ESC_OK)
		o = 0;
	want[o] = '\0';
	memset(out, 0x5a, sizeof(out));
	rc = wri_rburl_unescape((const char *)raw, n, out, cap, &len);
	check(rc == wrc && len == o && memcmp(out, want, o + 1u) == 0);
	free(raw);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size == 0)
		return 0;
	if (data[0] == 0xffu && size >= 2u) { /* only this one first byte selects the decoder: the rest of the byte space is the parser's */
		fuzz_unescape(data[1], data + 2, size - 2u);
		return 0;
	}
	fuzz_parse(data[0], data + 1, size - 1u);
	return 0;
}
