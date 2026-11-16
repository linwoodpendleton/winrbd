/* SPDX-License-Identifier: MIT */
/*
 * wri_mon_hosts.c - parser of a literal mon_host list (docs/spec/mon-client.md 3.1).
 *
 * Accepted items, separated by comma, space, semicolon, tab or newline:
 *
 *   10.77.0.10            IPv4, v2 on 3300
 *   10.77.0.10:3300       v2 on that port (any port but 6789)
 *   [fd00::1]  [fd00::1]:3300      bracketed IPv6
 *   v2:ADDR[:port]        explicit v2, port defaults to 3300
 *   v1:ADDR[:port]        explicit v1 (dropped: this client speaks msgr2 only)
 *   ADDR:6789             an unprefixed address on the legacy port is a v1 address (dropped)
 *   [v2:ADDR:port,v1:ADDR:port]   one monitor with several addresses; the first v2 entry is kept
 *   ... followed by /nonce        decimal u32, copied into wr_addr.nonce
 *
 * Host names are not resolved, and an IPv6 literal must be bracketed (without brackets a trailing
 * group cannot be told from a port). Everything is parsed without libc; no state is kept.
 * More v2 addresses than the caller has room for: the first `max` are returned and the rest of the
 * text is still checked for syntax.
 */
#include "wr_key.h"

WR_FILE_LICENCE_MIT

#define PORT_V2 3300u
#define PORT_V1 6789u
#define NEST_MAX 2 /* brackets inside brackets: "[v2:[fd00::1]:3300,...]" */

#define T_ANY 0
#define T_V1 1
#define T_V2 2

typedef struct parsed {
	int type;
	uint8_t family;
	uint8_t ip[16];
	uint32_t port; /* 0 = absent */
	uint32_t nonce;
} parsed;

static int is_sep(char c)
{
	return c == ' ' || c == ',' || c == ';' || c == '\t' || c == '\n' || c == '\r';
}

static int starts_with(const char *p, const char *e, const char *lit)
{
	while (*lit != '\0') {
		if (p >= e || *p != *lit)
			return 0;
		p++;
		lit++;
	}
	return 1;
}

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

/* Decimal number of 1 to 10 digits that fits in max; leading zeros are fine here (ports, nonces). */
static int parse_dec(const char **pp, const char *e, uint32_t max, uint32_t *v)
{
	const char *p = *pp;
	uint64_t acc = 0;
	int digits = 0;

	while (p < e && *p >= '0' && *p <= '9') {
		acc = acc * 10u + (uint64_t)(*p - '0');
		if (++digits > 10 || acc > max)
			return 0;
		p++;
	}
	if (digits == 0)
		return 0;
	*v = (uint32_t)acc;
	*pp = p;
	return 1;
}

/* Dotted quad; an octet has no leading zero (so "010" is not read as octal by anybody). */
static int parse_ipv4(const char **pp, const char *e, uint8_t ip[4])
{
	const char *p = *pp;
	int i;

	for (i = 0; i < 4; i++) {
		const char *start = p;
		uint32_t v;

		if (!parse_dec(&p, e, 255u, &v))
			return 0;
		if (p - start > 1 && *start == '0')
			return 0;
		ip[i] = (uint8_t)v;
		if (i < 3) {
			if (p >= e || *p != '.')
				return 0;
			p++;
		}
	}
	*pp = p;
	return 1;
}

/* The whole range [p, e) must be one IPv6 literal (no brackets, no zone, no port). */
static int parse_ipv6(const char *p, const char *e, uint8_t ip[16])
{
	uint16_t g[8];
	int ng = 0, gap = -1, i;

	if (p < e && *p == ':') {
		if (p + 1 >= e || p[1] != ':')
			return 0;
		gap = 0;
		p += 2;
	}
	while (p < e) {
		const char *q;
		int dots = 0;

		for (q = p; q < e && *q != ':'; q++)
			dots |= (*q == '.');
		if (dots) { /* embedded IPv4 tail, must be the end and takes two groups */
			uint8_t v4[4];

			if (ng > 6 || !parse_ipv4(&p, e, v4) || p != e)
				return 0;
			g[ng++] = (uint16_t)((v4[0] << 8) | v4[1]);
			g[ng++] = (uint16_t)((v4[2] << 8) | v4[3]);
			break;
		} else {
			uint32_t v = 0;
			int digits = 0;

			while (p < e && hex_val(*p) >= 0) {
				v = (v << 4) | (uint32_t)hex_val(*p);
				if (++digits > 4)
					return 0;
				p++;
			}
			if (digits == 0 || ng >= 8)
				return 0;
			g[ng++] = (uint16_t)v;
		}
		if (p >= e)
			break;
		if (*p != ':')
			return 0;
		p++;
		if (p < e && *p == ':') {
			if (gap >= 0)
				return 0;
			gap = ng;
			p++;
		} else if (p >= e) {
			return 0; /* a single trailing colon */
		}
	}
	if (gap < 0 ? ng != 8 : ng > 7)
		return 0;
	{
		int pos = 0, fill = gap < 0 ? 0 : 8 - ng;

		for (i = 0; i < ng + fill; i++) {
			uint16_t v = 0;

			if (gap < 0 || i < gap)
				v = g[i];
			else if (i >= gap + fill)
				v = g[i - fill];
			ip[pos++] = (uint8_t)(v >> 8);
			ip[pos++] = (uint8_t)v;
		}
	}
	return 1;
}

/*
 * One address: [v1:|v2:|any:]IP[:port][/nonce], IPv6 in brackets. With need_prefix (the entries of a
 * bracketed vector) the prefix must be v1: or v2:, because nothing there may be guessed.
 */
static int parse_addr(const char *p, const char *e, int need_prefix, parsed *o)
{
	uint32_t v;

	WR_MEMSET(o, 0, sizeof(*o));
	if (starts_with(p, e, "v2:")) {
		o->type = T_V2;
		p += 3;
	} else if (starts_with(p, e, "v1:")) {
		o->type = T_V1;
		p += 3;
	} else if (!need_prefix && starts_with(p, e, "any:")) {
		p += 4;
	} else if (need_prefix) {
		return 0;
	}

	if (p < e && *p == '[') {
		const char *q = p + 1;

		while (q < e && *q != ']')
			q++;
		if (q >= e || !parse_ipv6(p + 1, q, o->ip))
			return 0;
		o->family = WR_AF_IPV6;
		p = q + 1;
	} else {
		if (!parse_ipv4(&p, e, o->ip))
			return 0;
		o->family = WR_AF_IPV4;
	}
	if (p < e && *p == ':') {
		p++;
		if (!parse_dec(&p, e, 65535u, &v) || v == 0)
			return 0;
		o->port = v;
	}
	if (p < e && *p == '/') {
		p++;
		if (!parse_dec(&p, e, 0xFFFFFFFFu, &v))
			return 0;
		o->nonce = v;
	}
	return p == e;
}

/* Is this a msgr2 address; fills the port default. Unprefixed: 6789 is the legacy v1 port, anything else v2. */
static int is_v2(parsed *o)
{
	if (o->type == T_V1)
		return 0;
	if (o->type == T_ANY && o->port == PORT_V1)
		return 0;
	if (o->port == 0)
		o->port = PORT_V2;
	return 1;
}

static void to_wr(wr_addr *out, const parsed *a)
{
	out->family = a->family;
	WR_MEMCPY(out->ip, a->ip, 16);
	out->port = (uint16_t)a->port;
	out->nonce = a->nonce;
}

/*
 * Next token of [*pp, e): skips separators, then runs to the next separator that is outside
 * brackets. 1 = token in [*ts, *te), 0 = end of input, -1 = unbalanced or too deeply nested brackets.
 */
static int next_token(const char **pp, const char *e, int max_depth, const char **ts, const char **te)
{
	const char *p = *pp;
	int depth = 0;

	while (p < e && is_sep(*p))
		p++;
	if (p >= e) {
		*pp = p;
		return 0;
	}
	*ts = p;
	while (p < e && (depth > 0 || !is_sep(*p))) {
		if (*p == '[') {
			if (++depth > max_depth)
				return -1;
		} else if (*p == ']') {
			if (--depth < 0)
				return -1;
		}
		p++;
	}
	if (depth != 0)
		return -1;
	*te = p;
	*pp = p;
	return 1;
}

/* One top-level item: a single address or a bracketed vector. 1 = keep *out, 0 = dropped, -1 = syntax. */
static int parse_item(const char *s, const char *e, wr_addr *out)
{
	parsed a;
	int found = 0;

	if (*s == '[' && e[-1] == ']' && (starts_with(s + 1, e, "v1:") || starts_with(s + 1, e, "v2:"))) {
		const char *p = s + 1, *ts, *te, *inner_end = e - 1;
		int rc, count = 0;

		for (;;) {
			rc = next_token(&p, inner_end, NEST_MAX - 1, &ts, &te);
			if (rc < 0)
				return -1;
			if (rc == 0)
				break;
			if (!parse_addr(ts, te, 1, &a))
				return -1;
			count++;
			if (!found && is_v2(&a)) {
				found = 1;
				to_wr(out, &a);
			}
		}
		return count == 0 ? -1 : found;
	}
	if (!parse_addr(s, e, 0, &a))
		return -1;
	if (!is_v2(&a))
		return 0;
	to_wr(out, &a);
	return 1;
}

wr_status wr_mon_parse_hosts(const char *text, size_t n, wr_addr *out, size_t max, size_t *n_out)
{
	const char *p, *e, *ts, *te;
	size_t stored = 0, items = 0, dropped = 0;

	if (n_out != NULL)
		*n_out = 0;
	if ((text == NULL && n != 0) || (out == NULL && max != 0))
		return WR_E_INVAL;
	if (text == NULL) /* an absent list is an empty list (and NULL + 0 is not defined in C) */
		return WR_E_MON_HOSTS_SYNTAX;
	p = text;
	e = text + n;
	for (;;) {
		wr_addr a;
		int rc = next_token(&p, e, NEST_MAX, &ts, &te);

		if (rc < 0)
			return WR_E_MON_HOSTS_SYNTAX;
		if (rc == 0)
			break;
		WR_MEMSET(&a, 0, sizeof(a));
		rc = parse_item(ts, te, &a);
		if (rc < 0)
			return WR_E_MON_HOSTS_SYNTAX;
		items++;
		if (rc == 1 && stored < max) /* beyond max: syntax-checked above, not kept */
			out[stored++] = a;
		else if (rc == 1)
			dropped++;
	}
	if (items == 0)
		return WR_E_MON_HOSTS_SYNTAX;
	if (stored == 0 && dropped == 0)
		return WR_E_MON_NO_V2_ADDR;
	if (n_out != NULL)
		*n_out = stored;
	return WR_OK;
}
