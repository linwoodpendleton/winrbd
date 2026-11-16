/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of wr_mon_parse_hosts (core/src/mon/wri_mon_hosts.c; docs/spec/mon-client.md 3.1):
 * every accepted form (bare IPv4, IP:port, bracketed IPv6, v1:/v2:/any: prefixes, bracketed address
 * vectors, /nonce, the four separator kinds), the v1 and legacy-port rules, the capacity limit, and
 * every rejection (syntax and "no msgr2 address left"). Texts are handed over as exact-size heap
 * copies without a terminating NUL, so ASan sees any read past the given length.
 */
#include "wrt.h"

#include "wr_key.h"

#define MAXA 8

static wr_status parse_n(const char *text, size_t n, wr_addr *out, size_t max, size_t *cnt)
{
	char *q = (char *)malloc(n ? n : 1);
	wr_status st;

	if (!q) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	if (n)
		memcpy(q, text, n);
	st = wr_mon_parse_hosts(q, n, out, max, cnt);
	free(q);
	return st;
}

static wr_status parse(const char *text, wr_addr *out, size_t *cnt)
{
	return parse_n(text, strlen(text), out, MAXA, cnt);
}

static wr_status parse_max(const char *text, wr_addr *out, size_t max, size_t *cnt)
{
	return parse_n(text, strlen(text), out, max, cnt);
}

static void want4(const wr_addr *a, uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, uint16_t port, uint32_t nonce)
{
	static const uint8_t zero[12] = {0};

	WRT_CHECK_U64(a->family, WR_AF_IPV4);
	WRT_CHECK_U64(a->ip[0], b0);
	WRT_CHECK_U64(a->ip[1], b1);
	WRT_CHECK_U64(a->ip[2], b2);
	WRT_CHECK_U64(a->ip[3], b3);
	WRT_CHECK_MEM(a->ip + 4, zero, 12);
	WRT_CHECK_U64(a->port, port);
	WRT_CHECK_U64(a->nonce, nonce);
}

static void want6(const wr_addr *a, const uint8_t ip[16], uint16_t port)
{
	WRT_CHECK_U64(a->family, WR_AF_IPV6);
	WRT_CHECK_MEM(a->ip, ip, 16);
	WRT_CHECK_U64(a->port, port);
	WRT_CHECK_U64(a->nonce, 0);
}

/* parse a text that must give exactly one IPv4 address */
static void one4(const char *text, uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, uint16_t port, uint32_t nonce)
{
	wr_addr a[MAXA];
	size_t n = 99;
	wr_status st = parse(text, a, &n);

	if (st != WR_OK || n != 1) {
		fprintf(stderr, "text '%s': status %d count %zu\n", text, (int)st, n);
		WRT_CHECK(0 && "one4");
		return;
	}
	want4(&a[0], b0, b1, b2, b3, port, nonce);
}

static void one6(const char *text, const uint8_t ip[16], uint16_t port)
{
	wr_addr a[MAXA];
	size_t n = 99;
	wr_status st = parse(text, a, &n);

	if (st != WR_OK || n != 1) {
		fprintf(stderr, "text '%s': status %d count %zu\n", text, (int)st, n);
		WRT_CHECK(0 && "one6");
		return;
	}
	want6(&a[0], ip, port);
}

static void bad(const char *text, wr_status want)
{
	wr_addr a[MAXA];
	size_t n = 99;
	wr_status st = parse(text, a, &n);

	if (st != want) {
		fprintf(stderr, "text '%s': status %d (%s), want %d (%s)\n", text, (int)st, wrt_status_name_((int32_t)st),
			(int)want, wrt_status_name_((int32_t)want));
		WRT_CHECK(0 && "bad");
	}
	WRT_CHECK_U64(n, 0); /* a failed parse reports no addresses */
}

static void test_ipv4(void)
{
	one4("10.77.0.10", 10, 77, 0, 10, 3300, 0);
	one4("10.77.0.10:3300", 10, 77, 0, 10, 3300, 0);
	one4("10.77.0.10:4000", 10, 77, 0, 10, 4000, 0);
	one4("10.77.0.10:1", 10, 77, 0, 10, 1, 0);
	one4("10.77.0.10:65535", 10, 77, 0, 10, 65535, 0);
	one4("0.0.0.0", 0, 0, 0, 0, 3300, 0);
	one4("255.255.255.255:3300", 255, 255, 255, 255, 3300, 0);
	one4("v2:10.0.0.1", 10, 0, 0, 1, 3300, 0);
	one4("v2:10.0.0.1:3301", 10, 0, 0, 1, 3301, 0);
	one4("v2:10.0.0.1:6789", 10, 0, 0, 1, 6789, 0); /* an explicit v2 may use any port */
	one4("any:10.0.0.1", 10, 0, 0, 1, 3300, 0);
	one4("any:10.0.0.1:3300", 10, 0, 0, 1, 3300, 0);
	one4("10.0.0.1:3300/42", 10, 0, 0, 1, 3300, 42);
	one4("10.0.0.1/7", 10, 0, 0, 1, 3300, 7);
	one4("v2:10.0.0.1:3300/4294967295", 10, 0, 0, 1, 3300, 4294967295u);
	one4("  10.0.0.1  ", 10, 0, 0, 1, 3300, 0);
}

static void test_ipv6(void)
{
	static const uint8_t fd1[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	static const uint8_t lo[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	static const uint8_t any[16] = {0};
	static const uint8_t one_end[16] = {0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	static const uint8_t full[16] = {0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8};
	static const uint8_t mid[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a};
	static const uint8_t v4m[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1};
	static const uint8_t cap[16] = {0xAB, 0xCD, 0xEF, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	static const uint8_t tail[16] = {0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 6, 0, 7};

	one6("[fd00::1]", fd1, 3300);
	one6("[fd00::1]:3300", fd1, 3300);
	one6("[fd00::1]:4567", fd1, 4567);
	one6("[FD00::1]:3300", fd1, 3300);
	one6("[::1]", lo, 3300);
	one6("[::]", any, 3300);
	one6("[1::]", one_end, 3300);
	one6("[1:2:3:4:5:6:7:8]", full, 3300);
	one6("[0001:0002:0003:0004:0005:0006:0007:0008]", full, 3300);
	one6("[2001:db8::2a]", mid, 3300);
	one6("[::ffff:10.0.0.1]", v4m, 3300);
	one6("[abcd:ef01::1]", cap, 3300);
	one6("[::5:0:0:6:7]", tail, 3300); /* only the 7-group layouts with a gap in front */
	one6("v2:[fd00::1]", fd1, 3300);
	one6("v2:[fd00::1]:3300", fd1, 3300);
	one6("any:[fd00::1]:3300", fd1, 3300);
	{
		wr_addr a[MAXA];
		size_t n = 0;

		WRT_CHECK_STATUS(WR_OK, parse("[fd00::1]:3300/9", a, &n));
		WRT_CHECK_U64(n, 1);
		WRT_CHECK_U64(a[0].nonce, 9);
		WRT_CHECK_MEM(a[0].ip, fd1, 16);
	}
}

static void test_vectors(void)
{
	static const uint8_t fd1[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	wr_addr a[MAXA];
	size_t n;

	/* the documented vector: v2 and v1 of one monitor give one address */
	one4("[v2:10.77.0.10:3300,v1:10.77.0.10:6789]", 10, 77, 0, 10, 3300, 0);
	one4("[v1:10.77.0.10:6789,v2:10.77.0.10:3300]", 10, 77, 0, 10, 3300, 0);
	one4("[v2:10.0.0.1:3301/5, v1:10.0.0.1:6789]", 10, 0, 0, 1, 3301, 5);
	one4("[v2:10.0.0.1 v1:10.0.0.1]", 10, 0, 0, 1, 3300, 0);
	one4("[v2:10.0.0.1]", 10, 0, 0, 1, 3300, 0);
	one4("[v2:10.0.0.1,,v1:10.0.0.1:6789,]", 10, 0, 0, 1, 3300, 0);
	/* the first v2 entry wins, later ones are only checked */
	one4("[v2:10.0.0.1:3300,v2:10.0.0.2:3300]", 10, 0, 0, 1, 3300, 0);
	one6("[v2:[fd00::1]:3300,v1:[fd00::1]:6789]", fd1, 3300);
	one6("[v1:[fd00::1]:6789,v2:[fd00::1]]", fd1, 3300);
	/* a vector next to other items */
	WRT_CHECK_STATUS(WR_OK, parse("[v2:10.0.0.1:3300,v1:10.0.0.1:6789] 10.0.0.2 [v2:[fd00::1]:3300]", a, &n));
	WRT_CHECK_U64(n, 3);
	want4(&a[0], 10, 0, 0, 1, 3300, 0);
	want4(&a[1], 10, 0, 0, 2, 3300, 0);
	want6(&a[2], fd1, 3300);
}

static void test_lists(void)
{
	wr_addr a[MAXA];
	size_t n;

	/* the four separators, in any mix, with extra and leading / trailing ones */
	WRT_CHECK_STATUS(WR_OK, parse("10.0.0.1,10.0.0.2 10.0.0.3;10.0.0.4\n10.0.0.5\t10.0.0.6\r\n10.0.0.7", a, &n));
	WRT_CHECK_U64(n, 7);
	want4(&a[0], 10, 0, 0, 1, 3300, 0);
	want4(&a[3], 10, 0, 0, 4, 3300, 0);
	want4(&a[6], 10, 0, 0, 7, 3300, 0);
	WRT_CHECK_STATUS(WR_OK, parse(" ,;\n 10.0.0.1 ,, ; 10.0.0.2 ;;", a, &n));
	WRT_CHECK_U64(n, 2);
	want4(&a[1], 10, 0, 0, 2, 3300, 0);
	WRT_CHECK_STATUS(WR_OK, parse("10.0.0.1:3300, 10.0.0.2:3301, 10.0.0.3:3302", a, &n));
	WRT_CHECK_U64(n, 3);
	want4(&a[2], 10, 0, 0, 3, 3302, 0);

	/* v1 addresses are dropped, v2 ones around them stay, in order of appearance */
	WRT_CHECK_STATUS(WR_OK, parse("10.0.0.1:6789 10.0.0.2 v1:10.0.0.3 10.0.0.4:3300 [fd00::9]:6789 v1:10.0.0.5:3300", a, &n));
	WRT_CHECK_U64(n, 2);
	want4(&a[0], 10, 0, 0, 2, 3300, 0);
	want4(&a[1], 10, 0, 0, 4, 3300, 0);

	/* duplicates are kept as given */
	WRT_CHECK_STATUS(WR_OK, parse("10.0.0.1 10.0.0.1", a, &n));
	WRT_CHECK_U64(n, 2);

	/* the length is honoured, not a NUL: only the first 8 bytes are the text */
	WRT_CHECK_STATUS(WR_OK, parse_n("10.0.0.1:99999", 8, a, MAXA, &n));
	WRT_CHECK_U64(n, 1);
	want4(&a[0], 10, 0, 0, 1, 3300, 0);
	WRT_CHECK_STATUS(WR_OK, parse_n("10.0.0.1:3301x", 13, a, MAXA, &n));
	want4(&a[0], 10, 0, 0, 1, 3301, 0);

	/* capacity: the first `max` come back, later items are still syntax checked */
	WRT_CHECK_STATUS(WR_OK, parse_max("10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5", a, 3, &n));
	WRT_CHECK_U64(n, 3);
	want4(&a[2], 10, 0, 0, 3, 3300, 0);
	WRT_CHECK_STATUS(WR_E_MON_HOSTS_SYNTAX, parse_max("10.0.0.1 10.0.0.2 nonsense", a, 1, &n));
	WRT_CHECK_U64(n, 0);
	WRT_CHECK_STATUS(WR_OK, parse_max("10.0.0.1 10.0.0.2 10.0.0.3", a, 2, &n));
	WRT_CHECK_U64(n, 2);
	/* a v1-only list stays "no address" however small max is */
	WRT_CHECK_STATUS(WR_E_MON_NO_V2_ADDR, parse_max("v1:10.0.0.1", a, 1, &n));

	/* a long list of one-address items: eight kept of 40 */
	{
		size_t i, len = 0;
		char big[40 * 16];

		for (i = 0; i < 40; i++)
			len += (size_t)snprintf(big + len, sizeof(big) - len, "10.0.0.%u ", (unsigned)i + 1u);
		WRT_CHECK_STATUS(WR_OK, parse_n(big, len, a, MAXA, &n));
		WRT_CHECK_U64(n, MAXA);
		want4(&a[7], 10, 0, 0, 8, 3300, 0);
	}
}

static void test_rejections(void)
{
	static const struct {
		const char *text;
		wr_status st;
	} cases[] = {
		/* empty */
		{"", WR_E_MON_HOSTS_SYNTAX},
		{"   ", WR_E_MON_HOSTS_SYNTAX},
		{",;\n", WR_E_MON_HOSTS_SYNTAX},
		/* names are not resolved */
		{"host.example.com", WR_E_MON_HOSTS_SYNTAX},
		{"mon1:3300", WR_E_MON_HOSTS_SYNTAX},
		{"localhost", WR_E_MON_HOSTS_SYNTAX},
		/* IPv4 */
		{"10.0.0", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.256", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1.1", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.-1", WR_E_MON_HOSTS_SYNTAX},
		{"010.0.0.1", WR_E_MON_HOSTS_SYNTAX},
		{"10..0.1", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1 10.0.0.2.3", WR_E_MON_HOSTS_SYNTAX},
		{"0x0a.0.0.1", WR_E_MON_HOSTS_SYNTAX},
		/* ports and nonces */
		{"10.0.0.1:", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1:0", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1:65536", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1:99999999999", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1:abc", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1:-1", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1:3300:3300", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1/", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1/abc", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1/4294967296", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1:3300/1/2", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1 : 3300", WR_E_MON_HOSTS_SYNTAX},
		/* prefixes */
		{"v3:10.0.0.1", WR_E_MON_HOSTS_SYNTAX},
		{"v2:", WR_E_MON_HOSTS_SYNTAX},
		{"v2", WR_E_MON_HOSTS_SYNTAX},
		{"V2:10.0.0.1", WR_E_MON_HOSTS_SYNTAX},
		{"v2:v2:10.0.0.1", WR_E_MON_HOSTS_SYNTAX},
		/* IPv6 */
		{"fd00::1", WR_E_MON_HOSTS_SYNTAX}, /* must be bracketed */
		{"v2:fd00::1", WR_E_MON_HOSTS_SYNTAX},
		{"::1", WR_E_MON_HOSTS_SYNTAX},
		{"[fd00::1", WR_E_MON_HOSTS_SYNTAX},
		{"fd00::1]", WR_E_MON_HOSTS_SYNTAX},
		{"[fd00::1]:", WR_E_MON_HOSTS_SYNTAX},
		{"[fd00::1]:0", WR_E_MON_HOSTS_SYNTAX},
		{"[fd00::1]x", WR_E_MON_HOSTS_SYNTAX},
		{"[]", WR_E_MON_HOSTS_SYNTAX},
		{"[fd00::g]", WR_E_MON_HOSTS_SYNTAX},
		{"[fd00:::1]", WR_E_MON_HOSTS_SYNTAX},
		{"[1:2:3:4:5:6:7:8:9]", WR_E_MON_HOSTS_SYNTAX},
		{"[1:2:3:4:5:6:7]", WR_E_MON_HOSTS_SYNTAX},
		{"[1:2:3:4:5:6:7:8::]", WR_E_MON_HOSTS_SYNTAX},
		{"[1::2::3]", WR_E_MON_HOSTS_SYNTAX},
		{"[:1]", WR_E_MON_HOSTS_SYNTAX},
		{"[1:]", WR_E_MON_HOSTS_SYNTAX},
		{"[:::]", WR_E_MON_HOSTS_SYNTAX},
		{"[12345::]", WR_E_MON_HOSTS_SYNTAX},
		{"[::1%eth0]", WR_E_MON_HOSTS_SYNTAX},
		{"[::ffff:10.0.0]", WR_E_MON_HOSTS_SYNTAX},
		{"[::10.0.0.1:1]", WR_E_MON_HOSTS_SYNTAX},
		{"[1:2:3:4:5:6:7:10.0.0.1]", WR_E_MON_HOSTS_SYNTAX}, /* the v4 tail needs two groups */
		{"[10.0.0.1]", WR_E_MON_HOSTS_SYNTAX},
		{"[[fd00::1]]", WR_E_MON_HOSTS_SYNTAX},
		{"[[[fd00::1]]]", WR_E_MON_HOSTS_SYNTAX},
		/* vectors */
		{"[v2:10.0.0.1:3300", WR_E_MON_HOSTS_SYNTAX},
		{"[v2:10.0.0.1:3300]x", WR_E_MON_HOSTS_SYNTAX},
		{"x[v2:10.0.0.1:3300]", WR_E_MON_HOSTS_SYNTAX},
		{"[v2:10.0.0.1,10.0.0.2]", WR_E_MON_HOSTS_SYNTAX}, /* nothing inside a vector is guessed */
		{"[v2:10.0.0.1:3300,any:10.0.0.1]", WR_E_MON_HOSTS_SYNTAX},
		{"[v2:10.0.0.1:3300,v1:10.0.0.256]", WR_E_MON_HOSTS_SYNTAX},
		{"[v2:10.0.0.1:3300,v1:[fd00::1]", WR_E_MON_HOSTS_SYNTAX},
		{"[v2:[[fd00::1]]:3300]", WR_E_MON_HOSTS_SYNTAX},
		{"[v2:", WR_E_MON_HOSTS_SYNTAX},
		{"[v2:]", WR_E_MON_HOSTS_SYNTAX},
		{"v2:10.0.0.1]", WR_E_MON_HOSTS_SYNTAX},
		/* one bad item spoils the list, wherever it is */
		{"10.0.0.1 bad", WR_E_MON_HOSTS_SYNTAX},
		{"bad 10.0.0.1", WR_E_MON_HOSTS_SYNTAX},
		{"10.0.0.1:6789 bad", WR_E_MON_HOSTS_SYNTAX},
		/* nothing but v1 left */
		{"10.0.0.1:6789", WR_E_MON_NO_V2_ADDR},
		{"v1:10.0.0.1", WR_E_MON_NO_V2_ADDR},
		{"v1:10.0.0.1:3300", WR_E_MON_NO_V2_ADDR},
		{"any:10.0.0.1:6789", WR_E_MON_NO_V2_ADDR},
		{"[v1:10.0.0.1:6789]", WR_E_MON_NO_V2_ADDR},
		{"[v1:10.0.0.1,v1:10.0.0.2:6789]", WR_E_MON_NO_V2_ADDR},
		{"[fd00::1]:6789", WR_E_MON_NO_V2_ADDR},
		{"v1:[fd00::1]", WR_E_MON_NO_V2_ADDR},
		{"10.0.0.1:6789, v1:10.0.0.2, [v1:10.0.0.3:6789]", WR_E_MON_NO_V2_ADDR},
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		bad(cases[i].text, cases[i].st);

	/* a control byte or NUL inside the text is not an address character */
	{
		wr_addr a[MAXA];
		size_t n = 7;

		WRT_CHECK_STATUS(WR_E_MON_HOSTS_SYNTAX, parse_n("10.0.0.1\0x", 10, a, MAXA, &n));
		WRT_CHECK_U64(n, 0);
		WRT_CHECK_STATUS(WR_E_MON_HOSTS_SYNTAX, parse_n("10.0.\0.1", 8, a, MAXA, &n));
		WRT_CHECK_STATUS(WR_E_MON_HOSTS_SYNTAX, parse_n("\x01", 1, a, MAXA, &n));
		WRT_CHECK_STATUS(WR_E_MON_HOSTS_SYNTAX, parse_n("\xff\xfe", 2, a, MAXA, &n));
	}
}

static void test_arguments(void)
{
	wr_addr a[2];
	size_t n = 5;

	WRT_CHECK_STATUS(WR_E_INVAL, wr_mon_parse_hosts(NULL, 3, a, 2, &n));
	WRT_CHECK_U64(n, 0);
	WRT_CHECK_STATUS(WR_E_MON_HOSTS_SYNTAX, wr_mon_parse_hosts(NULL, 0, a, 2, &n));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_mon_parse_hosts("10.0.0.1", 8, NULL, 2, &n));
	/* n_out is optional */
	WRT_CHECK_STATUS(WR_OK, wr_mon_parse_hosts("10.0.0.1", 8, a, 2, NULL));
	/* the wr_addr that comes back is fully defined: bytes past the IPv4 address are zero */
	{
		wr_addr b[1];

		memset(b, 0xAA, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, wr_mon_parse_hosts("10.0.0.1", 8, b, 1, &n));
		want4(&b[0], 10, 0, 0, 1, 3300, 0);
	}
}

/* every prefix of a few valid texts either parses or is refused, never crashes or reads past the end */
static void test_prefixes(void)
{
	static const char *const texts[] = {
		"[v2:10.77.0.10:3300,v1:10.77.0.10:6789] [fd00::1]:3300/12 v2:[::ffff:1.2.3.4]:3301 10.0.0.1;",
		"any:10.0.0.1:3300/4294967295\n[v1:[fd00::1]:6789,v2:[fd00::2]]",
	};
	size_t t, i;

	for (t = 0; t < sizeof(texts) / sizeof(texts[0]); t++) {
		size_t len = strlen(texts[t]);

		for (i = 0; i <= len; i++) {
			wr_addr a[MAXA];
			size_t n = 99;
			wr_status st = parse_n(texts[t], i, a, MAXA, &n);

			WRT_CHECK(st == WR_OK ? (n >= 1 && n <= MAXA) : n == 0);
		}
	}
}

int main(void)
{
	test_ipv4();
	test_ipv6();
	test_vectors();
	test_lists();
	test_rejections();
	test_arguments();
	test_prefixes();
	return wrt_finish();
}
