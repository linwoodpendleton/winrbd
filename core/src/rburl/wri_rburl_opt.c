/* SPDX-License-Identifier: MIT */
/*
 * wri_rburl_opt.c - the query of an rbd:// URL: "name=value&name=value", percent-decoded, one pass, no allocation.
 *
 * Rules (docs/design/ipxe-driver.md section 8, all of them fail closed):
 *
 *   - the raw query is split at "&" and then at the first "=", and only then are name and value percent-decoded
 *     ("%26" and "%3D" are ordinary characters inside a name or a value); "+" is a plus, not a space;
 *   - an empty pair ("a=1&&b=2", a trailing "&"), a pair with no "=" or an empty name is OPT_SYNTAX;
 *   - an unknown name is OPT_UNKNOWN, a name given twice OPT_DUP (checked before the value is looked at);
 *   - a value that is not one of the words of the option, not all digits, or not a canonical UUID is OPT_VALUE, a number
 *     outside the range of the option OPT_RANGE; numbers are decimal digits only (no sign, no space, no hex);
 *   - a raw byte outside 0x21 .. 0x7e or a bad "%" is ESCAPE; a decoded NUL is ESCAPE too.
 *
 * Every error names the option in err->what (a static string; "option" when no name could be identified) and its
 * place in the raw query in err->a0 (offset of the name), a1 (length of the name) and, for value errors, a2 (offset of
 * the value). No option is order dependent: the options set disjoint fields.
 */
#include "wri_rburl.h"

WR_FILE_LICENCE_MIT

/* option numbers, also the bit positions of the "seen" mask */
enum {
	OPT_MODE = 0,
	OPT_RO,
	OPT_TIMEOUT,
	OPT_READAHEAD,
	OPT_FSID,
	OPT_DEVPATH,
	OPT_HANDOFF,
	OPT_MAPMEM,
	OPT_MONMSG,
	OPT_NONE = -1
};

/* ---- percent decoding ---------------------------------------------------------------------------------------- */

static int hex_val(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int wri_rburl_unescape(const char *raw, size_t n, char *dst, size_t cap, size_t *len)
{
	size_t i = 0, o = 0;
	int rc = WRI_RBURL_ESC_OK;

	while (i < n) {
		unsigned char c = (unsigned char)raw[i];

		if (c < 0x21u || c > 0x7eu) {
			rc = WRI_RBURL_ESC_BAD;
			break;
		}
		if (c == (unsigned char)'%') {
			int h, l;

			if (n - i < 3u || (h = hex_val(raw[i + 1u])) < 0 || (l = hex_val(raw[i + 2u])) < 0 || (h == 0 && l == 0)) {
				rc = WRI_RBURL_ESC_BAD;
				break;
			}
			c = (unsigned char)(h * 16 + l);
			i += 3u;
		} else {
			i++;
		}
		if (o + 1u >= cap) {
			rc = WRI_RBURL_ESC_TOO_LONG;
			break;
		}
		dst[o++] = (char)c;
	}
	if (rc != WRI_RBURL_ESC_OK)
		o = 0;
	dst[o] = '\0';
	*len = o;
	return rc;
}

/* ---- names and values ---------------------------------------------------------------------------------------- */

static int eq(const char *s, size_t n, const char *lit)
{
	size_t i = 0;

	while (lit[i] != '\0') {
		if (i >= n || s[i] != lit[i])
			return 0;
		i++;
	}
	return i == n;
}

static int opt_find(const char *name, size_t n)
{
	if (eq(name, n, "mode"))
		return OPT_MODE;
	if (eq(name, n, "ro"))
		return OPT_RO;
	if (eq(name, n, "timeout"))
		return OPT_TIMEOUT;
	if (eq(name, n, "readahead"))
		return OPT_READAHEAD;
	if (eq(name, n, "fsid"))
		return OPT_FSID;
	if (eq(name, n, "devpath"))
		return OPT_DEVPATH;
	if (eq(name, n, "handoff"))
		return OPT_HANDOFF;
	if (eq(name, n, "mapmem"))
		return OPT_MAPMEM;
	if (eq(name, n, "monmsg"))
		return OPT_MONMSG;
	return OPT_NONE;
}

static const char *opt_name(int opt)
{
	switch (opt) {
	case OPT_MODE:
		return "mode";
	case OPT_RO:
		return "ro";
	case OPT_TIMEOUT:
		return "timeout";
	case OPT_READAHEAD:
		return "readahead";
	case OPT_FSID:
		return "fsid";
	case OPT_DEVPATH:
		return "devpath";
	case OPT_HANDOFF:
		return "handoff";
	case OPT_MAPMEM:
		return "mapmem";
	case OPT_MONMSG:
		return "monmsg";
	default:
		return "option";
	}
}

/* 0 = ok, 1 = not all digits (or empty), 2 = above max. */
static int parse_uint(const char *v, size_t n, uint32_t max, uint32_t *out)
{
	uint32_t val = 0;
	size_t i;

	if (n == 0)
		return 1;
	for (i = 0; i < n; i++)
		if (v[i] < '0' || v[i] > '9')
			return 1;
	for (i = 0; i < n && val <= max; i++)
		val = val * 10u + (uint32_t)(v[i] - '0'); /* stops one step after passing max: no overflow (max <= 16384) */
	if (val > max)
		return 2;
	*out = val;
	return 0;
}

/* a UUID in its 36-byte form (8-4-4-4-12), hex of either case; out is written only for a complete match */
static int parse_uuid(const char *v, size_t n, uint8_t out[16])
{
	uint8_t tmp[16];
	size_t i, nib = 0;

	if (n != 36u)
		return 0;
	for (i = 0; i < n; i++) {
		int h;

		if (i == 8u || i == 13u || i == 18u || i == 23u) {
			if (v[i] != '-')
				return 0;
			continue;
		}
		h = hex_val(v[i]);
		if (h < 0)
			return 0;
		if ((nib & 1u) == 0u)
			tmp[nib / 2u] = (uint8_t)(h << 4);
		else
			tmp[nib / 2u] = (uint8_t)(tmp[nib / 2u] | (uint8_t)h);
		nib++;
	}
	WR_MEMCPY(out, tmp, sizeof(tmp));
	return 1;
}

/* 0 = ok, 1 = bad value, 2 = out of range */
static int apply_value(int opt, const char *v, size_t n, wr_rburl_spec *out)
{
	uint32_t u = 0;
	int rc;

	switch (opt) {
	case OPT_MODE:
		if (eq(v, n, "crc"))
			out->mode = (uint8_t)WR_MODE_CRC_ONLY;
		else if (eq(v, n, "crc-first"))
			out->mode = (uint8_t)WR_MODE_CRC_FIRST;
		else if (eq(v, n, "secure-first"))
			out->mode = (uint8_t)WR_MODE_SECURE_FIRST;
		else if (eq(v, n, "secure"))
			out->mode = (uint8_t)WR_MODE_SECURE_ONLY;
		else
			return 1;
		return 0;
	case OPT_RO:
		if (!eq(v, n, "0") && !eq(v, n, "1"))
			return 1;
		out->read_only = (uint8_t)(v[0] - '0');
		return 0;
	case OPT_TIMEOUT:
		rc = parse_uint(v, n, WR_RBURL_TIMEOUT_MAX_S, &u);
		if (rc == 0 && u < WR_RBURL_TIMEOUT_MIN_S)
			rc = 2;
		if (rc == 0)
			out->open_timeout_ms = u * 1000u;
		return rc;
	case OPT_READAHEAD:
		rc = parse_uint(v, n, WR_RBURL_READAHEAD_MAX_KIB, &u);
		if (rc == 0)
			out->readahead_kib = u;
		return rc;
	case OPT_FSID:
		if (!parse_uuid(v, n, out->fsid))
			return 1;
		out->fsid_known = 1;
		return 0;
	case OPT_DEVPATH:
		if (eq(v, n, "vendor"))
			out->devpath = (uint8_t)WR_RBURL_DEVPATH_VENDOR;
		else if (eq(v, n, "uri"))
			out->devpath = (uint8_t)WR_RBURL_DEVPATH_URI;
		else if (eq(v, n, "sata"))
			out->devpath = (uint8_t)WR_RBURL_DEVPATH_SATA;
		else
			return 1;
		return 0;
	case OPT_HANDOFF:
		if (eq(v, n, "nokey"))
			out->handoff = (uint8_t)WR_RBURL_HANDOFF_NOKEY;
		else if (eq(v, n, "key"))
			out->handoff = (uint8_t)WR_RBURL_HANDOFF_KEY;
		else if (eq(v, n, "none"))
			out->handoff = (uint8_t)WR_RBURL_HANDOFF_NONE;
		else
			return 1;
		return 0;
	case OPT_MAPMEM:
		rc = parse_uint(v, n, WR_RBURL_MAPMEM_MAX_KIB, &u);
		if (rc == 0 && u < WR_RBURL_MAPMEM_MIN_KIB)
			rc = 2;
		if (rc == 0)
			out->mapmem_kib = u;
		return rc;
	case OPT_MONMSG:
		rc = parse_uint(v, n, WR_RBURL_MONMSG_MAX_KIB, &u);
		if (rc == 0 && u < WR_RBURL_MONMSG_MIN_KIB)
			rc = 2;
		if (rc == 0)
			out->monmsg_kib = u;
		return rc;
	default:
		return 1;
	}
}

/* ---- one pair and the whole query ---------------------------------------------------------------------------- */

/* q[pos .. end) is one "name=value" pair; *seen collects the options already given. */
static wr_status one_pair(const char *q, size_t pos, size_t end, uint32_t *seen, wr_rburl_spec *out, wr_errinfo *err)
{
	char nbuf[WRI_RBURL_NAME_TOKEN_MAX], vbuf[WRI_RBURL_VALUE_TOKEN_MAX];
	size_t eqp = pos, nlen = 0, vlen = 0;
	int opt, rc;

	while (eqp < end && q[eqp] != '=')
		eqp++;
	if (eqp == pos || eqp >= end) /* empty pair, empty name, or no "=" */
		return WRI_RBURL_FAIL(err, WR_E_RBURL_OPT_SYNTAX, "option", pos, eqp - pos, 0);
	rc = wri_rburl_unescape(q + pos, eqp - pos, nbuf, sizeof(nbuf), &nlen);
	if (rc == WRI_RBURL_ESC_BAD)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_ESCAPE, "option", pos, eqp - pos, 0);
	opt = rc == WRI_RBURL_ESC_OK ? opt_find(nbuf, nlen) : OPT_NONE; /* a name too long for any option is unknown */
	if (opt == OPT_NONE)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_OPT_UNKNOWN, "option", pos, eqp - pos, 0);
	if ((*seen & (1u << (unsigned)opt)) != 0u)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_OPT_DUP, opt_name(opt), pos, eqp - pos, 0);
	*seen |= 1u << (unsigned)opt;
	rc = wri_rburl_unescape(q + eqp + 1u, end - (eqp + 1u), vbuf, sizeof(vbuf), &vlen);
	if (rc == WRI_RBURL_ESC_BAD)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_ESCAPE, opt_name(opt), pos, eqp - pos, eqp + 1u);
	if (rc == WRI_RBURL_ESC_TOO_LONG) /* longer than any legal value */
		return WRI_RBURL_FAIL(err, WR_E_RBURL_OPT_VALUE, opt_name(opt), pos, eqp - pos, eqp + 1u);
	rc = apply_value(opt, vbuf, vlen, out);
	if (rc != 0)
		return WRI_RBURL_FAIL(err, rc == 2 ? WR_E_RBURL_OPT_RANGE : WR_E_RBURL_OPT_VALUE, opt_name(opt), pos, eqp - pos,
				      eqp + 1u);
	return WR_OK;
}

wr_status wri_rburl_query(const char *q, size_t n, wr_rburl_spec *out, wr_errinfo *err)
{
	size_t pos = 0, end;
	uint32_t seen = 0;
	wr_status st;

	if (n == 0) /* "rbd://...?" with nothing after the question mark */
		return WR_OK;
	for (;;) {
		end = pos;
		while (end < n && q[end] != '&')
			end++;
		st = one_pair(q, pos, end, &seen, out, err);
		if (st != WR_OK)
			return st;
		if (end >= n)
			return WR_OK;
		pos = end + 1u; /* a trailing "&" leaves an empty pair, which one_pair refuses */
	}
}
