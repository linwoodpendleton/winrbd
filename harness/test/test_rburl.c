/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of core/src/rburl (the rbd:// URL parser, wr_rburl.h).
 *
 *   - the defaults, then every option on its own (accepted values, bounds, the number it sets), IPv6 and several
 *     monitors, default ports, percent escapes in the query (upper and lower case hex, %26 and %3D inside a token, "+");
 *   - the monitor list as a host that splits at the last colon (iPXE's parse_uri) hands it over, and rebuilds it;
 *   - every refusal, each with its own status and the errinfo that names the offending part or option and its place in
 *     the query; the order in which the first mistake wins;
 *   - length limits on both sides of every cap; the password and its distinct status; the key from the setting (base64,
 *     keyring line, garbage) and that no failure leaves key bytes or key text anywhere;
 *   - the user from the URL and from the setting, "client." stripped;
 *   - the status block: unique codes inside 260 .. 279, names, texts, free in wr_err.h;
 *   - the helpers white-box (percent decoder, path split with a snapshot);
 *   - a deterministic mutation loop over valid URLs: a failure wipes the spec, a success holds the invariants.
 *
 * Every text handed to the parser is an exact-size heap copy without a terminator, so ASan sees any over-read.
 */
#include "wrt.h"

#include "wri_rburl.h"

/* a throw-away key made for these tests: type 1 (AES), secret 00 01 02 .. 0f, and the type 2 (aes256k) one, secret 00 .. 1f */
#define KEY_AES "AQAA8VNlAAAAABAAAAECAwQFBgcICQoLDA0ODw=="
#define KEY_256 "AgAA8VNlAAAAACAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

/* ---- helpers --------------------------------------------------------------------------------------------- */

static char *dupn(const char *s)
{
	size_t n = strlen(s);
	char *p = (char *)malloc(n ? n : 1u);

	if (p == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	if (n != 0)
		memcpy(p, s, n);
	return p;
}

typedef struct urlcase {
	const char *user, *auth, *path, *query, *set_user, *set_key;
	int has_password;
} urlcase;

static urlcase base(void)
{
	urlcase c;

	memset(&c, 0, sizeof(c));
	c.user = "winrbd";
	c.auth = "10.77.0.10";
	c.path = "/rbd/img";
	c.set_key = KEY_AES;
	return c;
}

static wr_status run(const urlcase *c, wr_rburl_spec *sp, wr_errinfo *e)
{
	wr_rburl_in in;
	char *u = NULL, *a = NULL, *p = NULL, *q = NULL, *su = NULL, *sk = NULL;
	wr_status st;

	memset(&in, 0, sizeof(in));
	if (c->user != NULL)
		in.user = u = dupn(c->user), in.user_len = strlen(c->user);
	if (c->auth != NULL)
		in.authority = a = dupn(c->auth), in.authority_len = strlen(c->auth);
	if (c->path != NULL)
		in.path = p = dupn(c->path), in.path_len = strlen(c->path);
	if (c->query != NULL)
		in.query = q = dupn(c->query), in.query_len = strlen(c->query);
	if (c->set_user != NULL)
		in.set_user = su = dupn(c->set_user), in.set_user_len = strlen(c->set_user);
	if (c->set_key != NULL)
		in.set_key = sk = dupn(c->set_key), in.set_key_len = strlen(c->set_key);
	in.has_password = (uint8_t)(c->has_password != 0);
	memset(e, 0x5a, sizeof(*e)); /* the parser must clear it */
	memset(sp, 0x5a, sizeof(*sp));
	st = wr_rburl_parse(&in, sp, e);
	free(u);
	free(a);
	free(p);
	free(q);
	free(su);
	free(sk);
	return st;
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

/* status check printing the module's own names */
static void check_st(int line, const char *what, wr_status got, wr_status want)
{
	wrt_checks++;
	if (got != want) {
		wrt_failures++;
		fprintf(stderr, "%s:%d: %s returned %d (%s), want %d (%s)\n", __FILE__, line, what, (int)got, wr_rburl_status_name(got),
			(int)want, wr_rburl_status_name(want));
	}
}
#define CHECK_ST(want, expr) check_st(__LINE__, #expr, (expr), (want))

/* parse a case that must succeed; returns the status */
static wr_status ok(const urlcase *c, wr_rburl_spec *sp)
{
	wr_errinfo e;
	wr_status st = run(c, sp, &e);

	if (st != WR_OK)
		fprintf(stderr, "   (expected success, got %s: %s, what=%s a0=%d a1=%d)\n", wr_rburl_status_name(st),
			wr_rburl_strerror(st), e.what ? e.what : "-", (int)e.a0, (int)e.a1);
	return st;
}

/* a case that must fail with `want`; checks the errinfo, the wiped spec; returns the errinfo for more checks */
static wr_errinfo bad(int line, const urlcase *c, wr_status want, const char *what)
{
	wr_rburl_spec sp;
	wr_errinfo e;
	wr_status st = run(c, &sp, &e);

	check_st(line, "parse", st, want);
	wrt_checks++;
	if (!is_zero(&sp, sizeof(sp))) {
		wrt_failures++;
		fprintf(stderr, "%s:%d: failed parse left the spec filled\n", __FILE__, line);
	}
	wrt_checks++;
	if (e.status != st || e.module != WR_MOD_HOST || e.what == NULL || strcmp(e.what, what) != 0) {
		wrt_failures++;
		fprintf(stderr, "%s:%d: errinfo status %d module %d what \"%s\", want status %d module %d what \"%s\"\n", __FILE__, line,
			(int)e.status, (int)e.module, e.what ? e.what : "(null)", (int)st, (int)WR_MOD_HOST, what);
	}
	return e;
}
#define BAD(c, want, what) bad(__LINE__, (c), (want), (what))

static void mon4(const wr_addr *a, uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, unsigned port)
{
	WRT_CHECK(a->family == WR_AF_IPV4);
	WRT_CHECK(a->ip[0] == b0 && a->ip[1] == b1 && a->ip[2] == b2 && a->ip[3] == b3);
	WRT_CHECK(a->port == port);
}

/* ---- the defaults and the plain parts ---------------------------------------------------------------------- */

static void test_defaults(void)
{
	urlcase c = base();
	wr_rburl_spec sp;

	WRT_CHECK(sizeof(wr_rburl_spec) <= 800u); /* the header promises 772 bytes: a spec is kept on the heap, never on a 4 KiB stack */
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strcmp(sp.user, "winrbd") == 0);
	WRT_CHECK(strcmp(sp.pool, "rbd") == 0 && strcmp(sp.image, "img") == 0 && sp.snap[0] == '\0');
	WRT_CHECK(sp.n_mons == 1);
	mon4(&sp.mons[0], 10, 77, 0, 10, 3300);
	WRT_CHECK(sp.fsid_known == 0 && is_zero(sp.fsid, 16));
	WRT_CHECK(sp.mode == WR_MODE_CRC_ONLY && sp.read_only == 0 && sp.devpath == WR_RBURL_DEVPATH_VENDOR &&
		  sp.handoff == WR_RBURL_HANDOFF_NOKEY);
	WRT_CHECK(sp.open_timeout_ms == 20000u && sp.readahead_kib == 2048u && sp.mapmem_kib == 0 && sp.monmsg_kib == 0);
	WRT_CHECK(sp.key.type == WR_KEY_TYPE_AES && sp.key.len == 16 && sp.key.secret[0] == 0 && sp.key.secret[15] == 15);
	WRT_CHECK(is_zero(sp.reserved8, sizeof(sp.reserved8)));
	/* the unused tail of every string is zero too (no stack bytes leak through the spec) */
	WRT_CHECK(is_zero(sp.user + 7, sizeof(sp.user) - 7) && is_zero(sp.pool + 4, sizeof(sp.pool) - 4));
	WRT_CHECK(is_zero(&sp.mons[1], sizeof(sp.mons) - sizeof(sp.mons[0])));

	/* an empty query ("rbd://...?") is no options */
	c.query = "";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.mode == WR_MODE_CRC_ONLY && sp.open_timeout_ms == 20000u);

	/* the second key type */
	c.set_key = KEY_256;
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.key.type == WR_KEY_TYPE_AES256K && sp.key.len == 32 && sp.key.secret[31] == 31);
	wr_rburl_spec_wipe(&sp);
	WRT_CHECK(is_zero(&sp, sizeof(sp)));
	wr_rburl_spec_wipe(NULL); /* ignored */
}

static void test_user(void)
{
	urlcase c = base();
	wr_rburl_spec sp;
	wr_errinfo e;
	char big[200];

	c.user = "client.rbduser";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strcmp(sp.user, "rbduser") == 0);
	/* only one prefix is dropped, and an id that would still start with one is refused: the core strips "client." once
	 * more when it opens the client, so "client.client.x" would reach the cluster as entity "x" (a different one) */
	c.user = "client.client.x";
	e = BAD(&c, WR_E_RBURL_BAD_USER, "user");
	WRT_CHECK(e.a0 == 7 && e.a1 == 7);
	c.user = "client.client.";
	BAD(&c, WR_E_RBURL_BAD_USER, "user");
	c.user = "client.client.client.x";
	BAD(&c, WR_E_RBURL_BAD_USER, "user");
	c.user = "client.clientx"; /* "clientx" is not the prefix */
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strcmp(sp.user, "clientx") == 0);
	c.user = "client.Client.x"; /* the prefix is lower case only, as in the core */
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strcmp(sp.user, "Client.x") == 0);
	c.user = "xclient.x"; /* only at the front */
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strcmp(sp.user, "xclient.x") == 0);
	c.user = NULL; /* the same rule for the setting */
	c.set_user = "client.client.x";
	e = BAD(&c, WR_E_RBURL_BAD_USER, "rbd-user");
	WRT_CHECK(e.a0 == 7 && e.a1 == 7);
	c.set_user = NULL;
	c.user = "winrbd";
	c.user = "clientx"; /* not the prefix */
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strcmp(sp.user, "clientx") == 0);
	c.user = "Ab9._-z";
	CHECK_ST(WR_OK, ok(&c, &sp));

	/* from the setting when the URL has none; the URL wins when both are there */
	c.user = NULL;
	c.set_user = "setuser";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strcmp(sp.user, "setuser") == 0);
	c.set_user = "client.setuser2";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strcmp(sp.user, "setuser2") == 0);
	c.user = "urluser";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strcmp(sp.user, "urluser") == 0);
	c.set_user = "bad user!"; /* never looked at when the URL has a user */
	CHECK_ST(WR_OK, ok(&c, &sp));

	/* none at all */
	c.user = NULL;
	c.set_user = NULL;
	e = BAD(&c, WR_E_RBURL_NO_USER, "user");
	WRT_CHECK(e.a0 == 0 && e.a1 == 0);

	/* length: 63 bytes fit (WR_ENTITY_MAX is 64 with the NUL), 64 do not; "client." does not count */
	memset(big, 'u', sizeof(big));
	big[63] = '\0';
	c.user = big;
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strlen(sp.user) == 63);
	big[63] = 'u';
	big[64] = '\0';
	BAD(&c, WR_E_RBURL_BAD_USER, "user");
	memset(big, 'u', sizeof(big));
	memcpy(big, "client.", 7);
	big[7 + 63] = '\0';
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strlen(sp.user) == 63);
	memset(big, 'u', sizeof(big));
	memcpy(big, "client.", 7);
	big[7 + 64] = '\0';
	BAD(&c, WR_E_RBURL_BAD_USER, "user");
	/* a long user below the text cap is still just a bad id (the text cap is tested in test_caps) */
	memset(big, 'u', sizeof(big) - 1u);
	big[sizeof(big) - 1u] = '\0'; /* 199 < 256 */
	BAD(&c, WR_E_RBURL_BAD_USER, "user");

	/* empty, only the prefix, bad characters (the first bad byte is reported) */
	c.user = "";
	BAD(&c, WR_E_RBURL_BAD_USER, "user");
	c.user = "client.";
	BAD(&c, WR_E_RBURL_BAD_USER, "user");
	c.user = "ab c";
	e = BAD(&c, WR_E_RBURL_BAD_USER, "user");
	WRT_CHECK(e.a0 == 2 && e.a1 == 1);
	c.user = "ab/c";
	BAD(&c, WR_E_RBURL_BAD_USER, "user");
	c.user = "a:b";
	BAD(&c, WR_E_RBURL_BAD_USER, "user");
	c.user = "a@b";
	BAD(&c, WR_E_RBURL_BAD_USER, "user");
	c.user = "a\tb";
	BAD(&c, WR_E_RBURL_BAD_USER, "user");
	c.user = "\xc3\xa9";
	BAD(&c, WR_E_RBURL_BAD_USER, "user");
	/* the setting is named when it is the one that is wrong */
	c.user = NULL;
	c.set_user = "bad user";
	BAD(&c, WR_E_RBURL_BAD_USER, "rbd-user");
	c.set_user = "";
	BAD(&c, WR_E_RBURL_BAD_USER, "rbd-user");
}

/* ---- monitors --------------------------------------------------------------------------------------------- */

static void test_monitors(void)
{
	urlcase c = base();
	wr_rburl_spec sp;
	wr_errinfo e;

	c.auth = "10.77.0.10:3300";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.n_mons == 1);
	mon4(&sp.mons[0], 10, 77, 0, 10, 3300);
	c.auth = "10.77.0.10:3301"; /* any port but the v1 one */
	CHECK_ST(WR_OK, ok(&c, &sp));
	mon4(&sp.mons[0], 10, 77, 0, 10, 3301);
	c.auth = "10.0.0.1:3300,10.0.0.2:3300,10.0.0.3";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.n_mons == 3);
	mon4(&sp.mons[0], 10, 0, 0, 1, 3300);
	mon4(&sp.mons[1], 10, 0, 0, 2, 3300);
	mon4(&sp.mons[2], 10, 0, 0, 3, 3300);
	WRT_CHECK(is_zero(&sp.mons[3], sizeof(sp.mons) - 3 * sizeof(sp.mons[0])));
	c.auth = "[fd00::1]:3300";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.n_mons == 1 && sp.mons[0].family == WR_AF_IPV6 && sp.mons[0].port == 3300);
	WRT_CHECK(sp.mons[0].ip[0] == 0xfd && sp.mons[0].ip[1] == 0 && sp.mons[0].ip[15] == 1);
	c.auth = "[fd00::1]"; /* default port */
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.mons[0].family == WR_AF_IPV6 && sp.mons[0].port == 3300);
	c.auth = "[fd00::1],[fd00::2]:3301,10.0.0.9";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.n_mons == 3 && sp.mons[1].family == WR_AF_IPV6 && sp.mons[1].port == 3301 && sp.mons[1].ip[15] == 2);
	mon4(&sp.mons[2], 10, 0, 0, 9, 3300);
	c.auth = "[v2:10.0.0.1:3300,v1:10.0.0.1:6789],[v2:10.0.0.2:3300,v1:10.0.0.2:6789]"; /* mon_host style: the v2 half is kept */
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.n_mons == 2);
	mon4(&sp.mons[1], 10, 0, 0, 2, 3300);
	c.auth = "10.0.0.1:6789,10.0.0.2"; /* a v1 address is dropped, the v2 one stays */
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.n_mons == 1);
	mon4(&sp.mons[0], 10, 0, 0, 2, 3300);

	/* exactly WR_MAX_MONS (8) fit, a ninth is refused, never dropped without a word */
	c.auth = "10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.n_mons == WR_MAX_MONS);
	mon4(&sp.mons[7], 10, 0, 0, 8, 3300);
	WRT_CHECK(is_zero(&sp.mons[WR_MAX_MONS], sizeof(sp.mons[0]))); /* the scratch slot is zero */
	c.auth = "10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8,10.0.0.9";
	e = BAD(&c, WR_E_RBURL_MANY_MONS, "monitors");
	WRT_CHECK(e.a0 == 9 && e.a1 == WR_MAX_MONS);
	c.auth = "10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7,10.0.0.8,10.0.0.9,10.0.0.10,10.0.0.11";
	BAD(&c, WR_E_RBURL_MANY_MONS, "monitors");

	/* refusals */
	c.auth = NULL;
	BAD(&c, WR_E_RBURL_NO_MONS, "monitors");
	c.auth = "";
	BAD(&c, WR_E_RBURL_NO_MONS, "monitors");
	c.auth = "mon1.example.org"; /* a name is not a literal */
	BAD(&c, WR_E_MON_HOSTS_SYNTAX, "monitors");
	c.auth = "mon1.example.org:3300";
	BAD(&c, WR_E_MON_HOSTS_SYNTAX, "monitors");
	c.auth = "10.0.0.1,mon2";
	BAD(&c, WR_E_MON_HOSTS_SYNTAX, "monitors");
	c.auth = "10.0.0.1:";
	BAD(&c, WR_E_MON_HOSTS_SYNTAX, "monitors");
	c.auth = "10.0.0.1:99999";
	BAD(&c, WR_E_MON_HOSTS_SYNTAX, "monitors");
	c.auth = "fd00::1"; /* an IPv6 literal must be bracketed */
	BAD(&c, WR_E_MON_HOSTS_SYNTAX, "monitors");
	c.auth = "10.0.0.256";
	BAD(&c, WR_E_MON_HOSTS_SYNTAX, "monitors");
	c.auth = "10.0.0.1:6789"; /* v1 only: nothing this client can dial */
	BAD(&c, WR_E_MON_NO_V2_ADDR, "monitors");
	c.auth = ",";
	BAD(&c, WR_E_MON_HOSTS_SYNTAX, "monitors");
}

/* What iPXE's parse_uri does to the authority: split at the LAST colon unless the text ends in "]" (host, port). The
 * glue puts host + ":" + port back together; the parser must give the same answer for the rebuilt text as for the
 * original. Fixed buffers with explicit length checks, so the compilers have nothing to truncate. */
typedef struct split {
	char host[256], port[64];
	size_t host_n, port_n;
	int has_port;
} split;

static void ipxe_split(const char *authority, split *sp)
{
	size_t n = strlen(authority), i, colon = n;
	int has_colon = 0;

	for (i = 0; i < n; i++)
		if (authority[i] == ':') {
			colon = i;
			has_colon = 1;
		}
	memset(sp, 0, sizeof(*sp));
	if (has_colon && authority[n - 1] != ']') {
		sp->host_n = colon;
		sp->port_n = n - colon - 1u;
		sp->has_port = 1;
	} else {
		sp->host_n = n;
	}
	if (sp->host_n >= sizeof(sp->host) || sp->port_n >= sizeof(sp->port)) {
		fprintf(stderr, "ipxe_split: list too long for the test\n");
		exit(2);
	}
	memcpy(sp->host, authority, sp->host_n);
	if (sp->has_port)
		memcpy(sp->port, authority + colon + 1u, sp->port_n);
}

/* the glue's rebuild: host + ":" + port (just host without a port) */
static size_t ipxe_rebuild(const split *sp, char *out, size_t cap)
{
	size_t n = sp->host_n;

	if (n + 1u + sp->port_n + 1u > cap) {
		fprintf(stderr, "ipxe_rebuild: buffer too small\n");
		exit(2);
	}
	memcpy(out, sp->host, sp->host_n);
	if (sp->has_port) {
		out[n++] = ':';
		memcpy(out + n, sp->port, sp->port_n);
		n += sp->port_n;
	}
	out[n] = '\0';
	return n;
}

static void test_broken_by_parse_uri(void)
{
	static const char *const lists[] = {"10.0.0.1:3300,10.0.0.2:3300", "10.0.0.1:3300,10.0.0.2", "10.0.0.1,10.0.0.2:3300",
					    "[fd00::1]:3300,[fd00::2]:3300", "[fd00::1]:3300,[fd00::2]", "10.0.0.1,[fd00::2]:3300",
					    "10.0.0.1:3300,10.0.0.2:3300,10.0.0.3:3300,10.0.0.4:3300"};
	size_t i;

	for (i = 0; i < sizeof(lists) / sizeof(lists[0]); i++) {
		urlcase c = base();
		wr_rburl_spec direct, rebuilt;
		char text[300];
		split sp;

		ipxe_split(lists[i], &sp);
		(void)ipxe_rebuild(&sp, text, sizeof(text));
		WRT_CHECK(strcmp(text, lists[i]) == 0); /* the rebuilt authority is exactly the original */
		c.auth = lists[i];
		CHECK_ST(WR_OK, ok(&c, &direct));
		c.auth = text;
		CHECK_ST(WR_OK, ok(&c, &rebuilt));
		WRT_CHECK(direct.n_mons == rebuilt.n_mons && memcmp(direct.mons, rebuilt.mons, sizeof(direct.mons)) == 0);
	}
	{
		split sp0;

		/* iPXE really does break a list: host "10.0.0.1:3300,10.0.0.2" and port "3300" */
		ipxe_split("10.0.0.1:3300,10.0.0.2:3300", &sp0);
		WRT_CHECK(sp0.has_port && strcmp(sp0.host, "10.0.0.1:3300,10.0.0.2") == 0 && strcmp(sp0.port, "3300") == 0);
		ipxe_split("[fd00::1]:3300,[fd00::2]", &sp0); /* ends in "]": no split at all */
		WRT_CHECK(!sp0.has_port && strcmp(sp0.host, "[fd00::1]:3300,[fd00::2]") == 0);
	}
	{
		/* what the split alone gives (host "10.0.0.1:3300,10.0.0.2", port "3300") is NOT what the parser may be fed:
		 * the host part alone is a list whose last entry lost its port, still valid, and the port alone is garbage */
		urlcase c = base();
		wr_rburl_spec sp;

		c.auth = "10.0.0.1:3300,10.0.0.2";
		CHECK_ST(WR_OK, ok(&c, &sp));
		WRT_CHECK(sp.n_mons == 2);
		c.auth = "3300";
		BAD(&c, WR_E_MON_HOSTS_SYNTAX, "monitors");
	}
}

/* "/" + pool_n 'p' + "/" + image_n 'i' [+ "@" + snap_n 's' when snap_n != 0] */
static void mkpath(char *buf, size_t cap, size_t pool_n, size_t image_n, size_t snap_n)
{
	size_t o = 0, i;

	if (cap < pool_n + image_n + snap_n + 4u) {
		fprintf(stderr, "mkpath: buffer too small\n");
		exit(2);
	}
	buf[o++] = '/';
	for (i = 0; i < pool_n; i++)
		buf[o++] = 'p';
	buf[o++] = '/';
	for (i = 0; i < image_n; i++)
		buf[o++] = 'i';
	if (snap_n != 0) {
		buf[o++] = '@';
		for (i = 0; i < snap_n; i++)
			buf[o++] = 's';
	}
	buf[o] = '\0';
}

/* ---- the path ----------------------------------------------------------------------------------------------- */

static void test_path(void)
{
	urlcase c = base();
	wr_rburl_spec sp;
	wr_errinfo e;
	char big[600];

	c.path = "/mypool/disk-01.img";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strcmp(sp.pool, "mypool") == 0 && strcmp(sp.image, "disk-01.img") == 0);
	c.path = "/p.o_ol/i-m_g.1";
	CHECK_ST(WR_OK, ok(&c, &sp));
	c.path = "/p/%41"; /* the host decoded the path already: a % is a plain character here */
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strcmp(sp.image, "%41") == 0);

	/* a snapshot is parsed (white-box below) and then refused with the shared status */
	c.path = "/rbd/img@snap1";
	e = BAD(&c, WR_E_UNSUPPORTED, "snapshot");
	WRT_CHECK(e.status == WR_E_UNSUPPORTED);

	c.path = NULL;
	BAD(&c, WR_E_RBURL_PATH, "path");
	c.path = "";
	BAD(&c, WR_E_RBURL_PATH, "path");
	c.path = "rbd/img"; /* no leading slash */
	BAD(&c, WR_E_RBURL_PATH, "path");
	c.path = "/";
	BAD(&c, WR_E_RBURL_PATH, "path");
	c.path = "/rbd";
	BAD(&c, WR_E_RBURL_PATH, "path");
	c.path = "/rbd/img/extra"; /* a namespace is not supported */
	e = BAD(&c, WR_E_RBURL_PATH, "path");
	WRT_CHECK(e.a0 == 8);
	c.path = "/rbd/img/";
	BAD(&c, WR_E_RBURL_PATH, "path");
	c.path = "/rbd/ns/img";
	BAD(&c, WR_E_RBURL_PATH, "path");

	c.path = "//img";
	e = BAD(&c, WR_E_RBURL_NAME, "pool");
	WRT_CHECK(e.a0 == 1 && e.a1 == 0);
	c.path = "/rbd/";
	e = BAD(&c, WR_E_RBURL_NAME, "image");
	WRT_CHECK(e.a0 == 5);
	c.path = "/rbd/@snap";
	BAD(&c, WR_E_RBURL_NAME, "image");
	c.path = "/rbd/img@";
	BAD(&c, WR_E_RBURL_NAME, "snapshot");
	c.path = "/rbd/img@a@b";
	BAD(&c, WR_E_RBURL_NAME, "snapshot");
	c.path = "/r bd/img";
	e = BAD(&c, WR_E_RBURL_NAME, "pool");
	WRT_CHECK(e.a0 == 2 && e.a1 == 1);
	c.path = "/rbd/im\tg";
	BAD(&c, WR_E_RBURL_NAME, "image");
	c.path = "/rbd/im\x7f";
	BAD(&c, WR_E_RBURL_NAME, "image");
	c.path = "/rbd/im\xc3\xa9g";
	BAD(&c, WR_E_RBURL_NAME, "image");
	c.path = "/p@x/img";
	BAD(&c, WR_E_RBURL_NAME, "pool");

	/* 127 bytes fit, 128 do not: pool, image and snapshot alike */
	c.path = big;
	mkpath(big, sizeof(big), 127, 1, 0);
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strlen(sp.pool) == 127);
	mkpath(big, sizeof(big), 128, 1, 0);
	e = BAD(&c, WR_E_RBURL_NAME_LONG, "pool");
	WRT_CHECK(e.a0 == 1 && e.a1 == 128 && e.a2 == 127);
	mkpath(big, sizeof(big), 1, 127, 0);
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(strlen(sp.image) == 127);
	mkpath(big, sizeof(big), 1, 128, 0);
	BAD(&c, WR_E_RBURL_NAME_LONG, "image");
	mkpath(big, sizeof(big), 1, 1, 128);
	BAD(&c, WR_E_RBURL_NAME_LONG, "snapshot");
	{
		wr_rburl_spec sp2;

		memset(&sp2, 0, sizeof(sp2));
		mkpath(big, sizeof(big), 127, 127, 127); /* the longest path of all three: 127 + 127 + 127 + 3 = 384 bytes */
		CHECK_ST(WR_OK, wri_rburl_path(big, strlen(big), &sp2, NULL));
		WRT_CHECK(strlen(sp2.pool) == 127 && strlen(sp2.image) == 127 && strlen(sp2.snap) == 127);
	}

	/* the whole path is capped before it is looked at */
	memset(big, 'x', sizeof(big));
	big[0] = '/';
	big[WR_RBURL_PATH_MAX + 1] = '\0';
	c.path = big;
	e = BAD(&c, WR_E_RBURL_TOO_LONG, "path");
	WRT_CHECK(e.a1 == WR_RBURL_PATH_MAX + 1u && e.a2 == WR_RBURL_PATH_MAX);
}

/* the path split with a snapshot, white-box (the public call refuses the snapshot, so it is seen here) */
static void test_path_split(void)
{
	wr_rburl_spec sp;
	wr_errinfo e;
	static const char p1[] = "/pool/image@snap.1";

	memset(&sp, 0, sizeof(sp));
	memset(&e, 0, sizeof(e));
	CHECK_ST(WR_OK, wri_rburl_path(p1, sizeof(p1) - 1, &sp, &e));
	WRT_CHECK(strcmp(sp.pool, "pool") == 0 && strcmp(sp.image, "image") == 0 && strcmp(sp.snap, "snap.1") == 0);
	memset(&sp, 0, sizeof(sp));
	CHECK_ST(WR_OK, wri_rburl_path("/a/b", 4, &sp, NULL));
	WRT_CHECK(strcmp(sp.pool, "a") == 0 && strcmp(sp.image, "b") == 0 && sp.snap[0] == '\0');
	CHECK_ST(WR_E_RBURL_PATH, wri_rburl_path(NULL, 0, &sp, NULL));
	CHECK_ST(WR_E_RBURL_NAME, wri_rburl_path("/a/b@", 5, &sp, &e));
	WRT_CHECK(e.what != NULL && strcmp(e.what, "snapshot") == 0);
	/* the length is the text: a longer buffer behind it is never read */
	CHECK_ST(WR_E_RBURL_NAME, wri_rburl_path("/a/b@c", 5, &sp, &e)); /* "/a/b@" */
	CHECK_ST(WR_OK, wri_rburl_path("/a/bcd", 4, &sp, &e));           /* "/a/b" */
	WRT_CHECK(strcmp(sp.image, "b") == 0);
}

/* ---- options ------------------------------------------------------------------------------------------------ */

static wr_status opt(const char *query, wr_rburl_spec *sp)
{
	urlcase c = base();

	c.query = query;
	return ok(&c, sp);
}

static wr_errinfo opt_bad(int line, const char *query, wr_status want, const char *what)
{
	urlcase c = base();

	c.query = query;
	return bad(line, &c, want, what);
}
#define OPT_BAD(q, want, what) opt_bad(__LINE__, (q), (want), (what))

static void test_options_mode_ro(void)
{
	wr_rburl_spec sp;

	CHECK_ST(WR_OK, opt("mode=crc", &sp));
	WRT_CHECK(sp.mode == WR_MODE_CRC_ONLY);
	CHECK_ST(WR_OK, opt("mode=crc-first", &sp));
	WRT_CHECK(sp.mode == WR_MODE_CRC_FIRST);
	CHECK_ST(WR_OK, opt("mode=secure-first", &sp));
	WRT_CHECK(sp.mode == WR_MODE_SECURE_FIRST);
	CHECK_ST(WR_OK, opt("mode=secure", &sp));
	WRT_CHECK(sp.mode == WR_MODE_SECURE_ONLY);
	OPT_BAD("mode=stock", WR_E_RBURL_OPT_VALUE, "mode"); /* a policy of the core, not offered by URL */
	OPT_BAD("mode=CRC", WR_E_RBURL_OPT_VALUE, "mode");
	OPT_BAD("mode=", WR_E_RBURL_OPT_VALUE, "mode");
	OPT_BAD("mode=crc-", WR_E_RBURL_OPT_VALUE, "mode");
	OPT_BAD("mode=secur", WR_E_RBURL_OPT_VALUE, "mode");
	OPT_BAD("mode=3", WR_E_RBURL_OPT_VALUE, "mode");

	CHECK_ST(WR_OK, opt("ro=1", &sp));
	WRT_CHECK(sp.read_only == 1);
	CHECK_ST(WR_OK, opt("ro=0", &sp));
	WRT_CHECK(sp.read_only == 0);
	OPT_BAD("ro=2", WR_E_RBURL_OPT_VALUE, "ro");
	OPT_BAD("ro=true", WR_E_RBURL_OPT_VALUE, "ro");
	OPT_BAD("ro=01", WR_E_RBURL_OPT_VALUE, "ro");
	OPT_BAD("ro=", WR_E_RBURL_OPT_VALUE, "ro");
	OPT_BAD("ro=-1", WR_E_RBURL_OPT_VALUE, "ro");
}

static void test_options_numbers(void)
{
	wr_rburl_spec sp;

	/* timeout: 1 .. 600 seconds, in ms */
	CHECK_ST(WR_OK, opt("timeout=1", &sp));
	WRT_CHECK(sp.open_timeout_ms == 1000u);
	CHECK_ST(WR_OK, opt("timeout=20", &sp));
	WRT_CHECK(sp.open_timeout_ms == 20000u);
	CHECK_ST(WR_OK, opt("timeout=600", &sp));
	WRT_CHECK(sp.open_timeout_ms == 600000u);
	CHECK_ST(WR_OK, opt("timeout=007", &sp)); /* leading zeros are digits */
	WRT_CHECK(sp.open_timeout_ms == 7000u);
	OPT_BAD("timeout=0", WR_E_RBURL_OPT_RANGE, "timeout");
	OPT_BAD("timeout=601", WR_E_RBURL_OPT_RANGE, "timeout");
	OPT_BAD("timeout=99999999999999999999", WR_E_RBURL_OPT_RANGE, "timeout");
	OPT_BAD("timeout=4294967297", WR_E_RBURL_OPT_RANGE, "timeout");
	OPT_BAD("timeout=-1", WR_E_RBURL_OPT_VALUE, "timeout");
	OPT_BAD("timeout=+5", WR_E_RBURL_OPT_VALUE, "timeout");
	OPT_BAD("timeout=5s", WR_E_RBURL_OPT_VALUE, "timeout");
	OPT_BAD("timeout=0x10", WR_E_RBURL_OPT_VALUE, "timeout");
	OPT_BAD("timeout=1.5", WR_E_RBURL_OPT_VALUE, "timeout");
	OPT_BAD("timeout=", WR_E_RBURL_OPT_VALUE, "timeout");
	CHECK_ST(WR_OK, opt("timeout=%35", &sp)); /* an escaped digit */
	WRT_CHECK(sp.open_timeout_ms == 5000u);
}

static void test_options_numbers2(void)
{
	wr_rburl_spec sp;
	wr_errinfo e;

	CHECK_ST(WR_OK, opt("readahead=0", &sp));
	WRT_CHECK(sp.readahead_kib == 0u);
	CHECK_ST(WR_OK, opt("readahead=2048", &sp));
	WRT_CHECK(sp.readahead_kib == 2048u);
	CHECK_ST(WR_OK, opt("readahead=16384", &sp));
	WRT_CHECK(sp.readahead_kib == 16384u);
	e = OPT_BAD("readahead=16385", WR_E_RBURL_OPT_RANGE, "readahead");
	WRT_CHECK(e.a0 == 0 && e.a1 == 9 && e.a2 == 10);
	OPT_BAD("readahead=-1", WR_E_RBURL_OPT_VALUE, "readahead");
	OPT_BAD("readahead=1k", WR_E_RBURL_OPT_VALUE, "readahead");
	OPT_BAD("readahead=", WR_E_RBURL_OPT_VALUE, "readahead");

	CHECK_ST(WR_OK, opt("mapmem=16", &sp));
	WRT_CHECK(sp.mapmem_kib == 16u);
	CHECK_ST(WR_OK, opt("mapmem=16384", &sp));
	WRT_CHECK(sp.mapmem_kib == 16384u);
	OPT_BAD("mapmem=15", WR_E_RBURL_OPT_RANGE, "mapmem");
	OPT_BAD("mapmem=0", WR_E_RBURL_OPT_RANGE, "mapmem");
	OPT_BAD("mapmem=16385", WR_E_RBURL_OPT_RANGE, "mapmem");
	OPT_BAD("mapmem=x", WR_E_RBURL_OPT_VALUE, "mapmem");

	CHECK_ST(WR_OK, opt("monmsg=64", &sp));
	WRT_CHECK(sp.monmsg_kib == 64u);
	CHECK_ST(WR_OK, opt("monmsg=16384", &sp));
	WRT_CHECK(sp.monmsg_kib == 16384u);
	OPT_BAD("monmsg=63", WR_E_RBURL_OPT_RANGE, "monmsg");
	OPT_BAD("monmsg=16385", WR_E_RBURL_OPT_RANGE, "monmsg");
	OPT_BAD("monmsg=", WR_E_RBURL_OPT_VALUE, "monmsg");
}

static void test_options_words(void)
{
	wr_rburl_spec sp;

	CHECK_ST(WR_OK, opt("devpath=vendor", &sp));
	WRT_CHECK(sp.devpath == WR_RBURL_DEVPATH_VENDOR);
	CHECK_ST(WR_OK, opt("devpath=uri", &sp));
	WRT_CHECK(sp.devpath == WR_RBURL_DEVPATH_URI);
	CHECK_ST(WR_OK, opt("devpath=sata", &sp));
	WRT_CHECK(sp.devpath == WR_RBURL_DEVPATH_SATA);
	OPT_BAD("devpath=ata", WR_E_RBURL_OPT_VALUE, "devpath");
	OPT_BAD("devpath=Vendor", WR_E_RBURL_OPT_VALUE, "devpath");
	OPT_BAD("devpath=", WR_E_RBURL_OPT_VALUE, "devpath");

	CHECK_ST(WR_OK, opt("handoff=nokey", &sp));
	WRT_CHECK(sp.handoff == WR_RBURL_HANDOFF_NOKEY);
	CHECK_ST(WR_OK, opt("handoff=key", &sp));
	WRT_CHECK(sp.handoff == WR_RBURL_HANDOFF_KEY);
	CHECK_ST(WR_OK, opt("handoff=none", &sp));
	WRT_CHECK(sp.handoff == WR_RBURL_HANDOFF_NONE);
	OPT_BAD("handoff=yes", WR_E_RBURL_OPT_VALUE, "handoff");
	OPT_BAD("handoff=keys", WR_E_RBURL_OPT_VALUE, "handoff");
	OPT_BAD("handoff=", WR_E_RBURL_OPT_VALUE, "handoff");
}

static void test_options_fsid(void)
{
	wr_rburl_spec sp;
	static const uint8_t want[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

	CHECK_ST(WR_OK, opt("fsid=01234567-89ab-cdef-fedc-ba9876543210", &sp));
	WRT_CHECK(sp.fsid_known == 1);
	WRT_CHECK_MEM(sp.fsid, want, 16);
	CHECK_ST(WR_OK, opt("fsid=01234567-89AB-CDEF-FEDC-BA9876543210", &sp)); /* either case */
	WRT_CHECK_MEM(sp.fsid, want, 16);
	CHECK_ST(WR_OK, opt("fsid=01234567-89ab-cdef-fedc-ba98765432%31%30", &sp)); /* escaped digits */
	WRT_CHECK_MEM(sp.fsid, want, 16);
	CHECK_ST(WR_OK, opt("fsid=00000000-0000-0000-0000-000000000000", &sp)); /* a nil id is well formed (it simply matches no cluster) */
	WRT_CHECK(sp.fsid_known == 1 && is_zero(sp.fsid, 16));

	OPT_BAD("fsid=", WR_E_RBURL_OPT_VALUE, "fsid");
	OPT_BAD("fsid=01234567-89ab-cdef-fedc-ba987654321", WR_E_RBURL_OPT_VALUE, "fsid");   /* 35 */
	OPT_BAD("fsid=01234567-89ab-cdef-fedc-ba98765432100", WR_E_RBURL_OPT_VALUE, "fsid"); /* 37 */
	OPT_BAD("fsid=0123456789abcdeffedcba9876543210", WR_E_RBURL_OPT_VALUE, "fsid");      /* no dashes */
	OPT_BAD("fsid=01234567_89ab-cdef-fedc-ba9876543210", WR_E_RBURL_OPT_VALUE, "fsid");
	OPT_BAD("fsid=0123456-789ab-cdef-fedc-ba9876543210", WR_E_RBURL_OPT_VALUE, "fsid");
	OPT_BAD("fsid=01234567-89ab-cdef-fedc-ba987654321g", WR_E_RBURL_OPT_VALUE, "fsid");
	OPT_BAD("fsid={01234567-89ab-cdef-fedc-ba9876543210}", WR_E_RBURL_OPT_VALUE, "fsid");
	/* a value longer than any legal one is a value error, never a buffer problem */
	OPT_BAD("fsid=01234567-89ab-cdef-fedc-ba9876543210-01234567-89ab-cdef-fedc-ba9876543210", WR_E_RBURL_OPT_VALUE, "fsid");
}

static void test_options_combined(void)
{
	wr_rburl_spec sp;
	urlcase c = base();

	c.query = "mode=secure-first&ro=1&timeout=45&readahead=512&fsid=01234567-89ab-cdef-fedc-ba9876543210&devpath=sata&handoff=key&mapmem=2048&monmsg=4096";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.mode == WR_MODE_SECURE_FIRST && sp.read_only == 1 && sp.open_timeout_ms == 45000u && sp.readahead_kib == 512u);
	WRT_CHECK(sp.fsid_known == 1 && sp.fsid[0] == 0x01 && sp.devpath == WR_RBURL_DEVPATH_SATA && sp.handoff == WR_RBURL_HANDOFF_KEY);
	WRT_CHECK(sp.mapmem_kib == 2048u && sp.monmsg_kib == 4096u);
	/* the order of the options does not matter */
	c.query = "monmsg=4096&mapmem=2048&handoff=key&devpath=sata&fsid=01234567-89ab-cdef-fedc-ba9876543210&readahead=512&timeout=45&ro=1&mode=secure-first";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.mode == WR_MODE_SECURE_FIRST && sp.mapmem_kib == 2048u && sp.open_timeout_ms == 45000u);
	/* options and the other parts together */
	c.auth = "[fd00::1]:3300,10.0.0.2";
	c.user = "client.me";
	c.path = "/pool/image";
	c.query = "ro=1";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.n_mons == 2 && strcmp(sp.user, "me") == 0 && sp.read_only == 1);
}

/* ---- percent escapes and the query grammar ------------------------------------------------------------------ */

static void test_escapes(void)
{
	wr_rburl_spec sp;
	wr_errinfo e;

	CHECK_ST(WR_OK, opt("%6dode=%63rc", &sp)); /* name and value escaped, lower-case hex */
	WRT_CHECK(sp.mode == WR_MODE_CRC_ONLY);
	CHECK_ST(WR_OK, opt("mode=secure%2Dfirst", &sp)); /* %2D is "-", upper-case hex */
	WRT_CHECK(sp.mode == WR_MODE_SECURE_FIRST);
	CHECK_ST(WR_OK, opt("mode=secure%2dfirst", &sp));
	WRT_CHECK(sp.mode == WR_MODE_SECURE_FIRST);
	OPT_BAD("%52%4F=1", WR_E_RBURL_OPT_UNKNOWN, "option");
	CHECK_ST(WR_OK, opt("ro=%31&timeout=%32%30", &sp));
	WRT_CHECK(sp.read_only == 1 && sp.open_timeout_ms == 20000u);

	/* %26 and %3D are characters of the token, not separators */
	OPT_BAD("mode%3Dcrc", WR_E_RBURL_OPT_SYNTAX, "option"); /* no raw "=": not a pair */
	OPT_BAD("mode=crc%26ro=1", WR_E_RBURL_OPT_VALUE, "mode");
	OPT_BAD("mode=crc%3Dx", WR_E_RBURL_OPT_VALUE, "mode");
	e = OPT_BAD("a%26b=1", WR_E_RBURL_OPT_UNKNOWN, "option");
	WRT_CHECK(e.a0 == 0 && e.a1 == 5);
	/* "+" is a plus */
	OPT_BAD("mode=crc+first", WR_E_RBURL_OPT_VALUE, "mode");

	/* bad escapes: truncated, not hex, decoded NUL, in the name and in the value */
	e = OPT_BAD("mode=crc%", WR_E_RBURL_ESCAPE, "mode");
	WRT_CHECK(e.a0 == 0 && e.a1 == 4 && e.a2 == 5);
	OPT_BAD("mode=crc%6", WR_E_RBURL_ESCAPE, "mode");
	OPT_BAD("mode=%zz", WR_E_RBURL_ESCAPE, "mode");
	OPT_BAD("mode=%0g", WR_E_RBURL_ESCAPE, "mode");
	OPT_BAD("mode=cr%00", WR_E_RBURL_ESCAPE, "mode");
	e = OPT_BAD("%00=1", WR_E_RBURL_ESCAPE, "option");
	WRT_CHECK(e.a0 == 0 && e.a1 == 3);
	OPT_BAD("mo%=1", WR_E_RBURL_ESCAPE, "option");
	e = OPT_BAD("ro=1&mo%de%=1", WR_E_RBURL_ESCAPE, "option");
	WRT_CHECK(e.a0 == 5);
	/* raw bytes that must have been encoded */
	OPT_BAD("mode=cr c", WR_E_RBURL_ESCAPE, "mode");
	OPT_BAD("mode=crc\n", WR_E_RBURL_ESCAPE, "mode");
	OPT_BAD("mode=cr\xc3\xa9", WR_E_RBURL_ESCAPE, "mode");
	OPT_BAD("mo de=crc", WR_E_RBURL_ESCAPE, "option");
	/* an unknown name wins over a bad value; a bad name escape over everything after it */
	OPT_BAD("zzz=%", WR_E_RBURL_OPT_UNKNOWN, "option");
}

static void test_query_grammar(void)
{
	wr_errinfo e;
	char big[WR_RBURL_QUERY_MAX + 8u];
	wr_rburl_spec sp;
	urlcase c = base();

	e = OPT_BAD("mode", WR_E_RBURL_OPT_SYNTAX, "option"); /* no "=" */
	WRT_CHECK(e.a0 == 0 && e.a1 == 4);
	OPT_BAD("ro", WR_E_RBURL_OPT_SYNTAX, "option");
	OPT_BAD("=crc", WR_E_RBURL_OPT_SYNTAX, "option"); /* empty name */
	OPT_BAD("=", WR_E_RBURL_OPT_SYNTAX, "option");
	OPT_BAD("&", WR_E_RBURL_OPT_SYNTAX, "option"); /* two empty pairs */
	OPT_BAD("&mode=crc", WR_E_RBURL_OPT_SYNTAX, "option");
	OPT_BAD("mode=crc&", WR_E_RBURL_OPT_SYNTAX, "option"); /* trailing & */
	e = OPT_BAD("mode=crc&&ro=1", WR_E_RBURL_OPT_SYNTAX, "option");
	WRT_CHECK(e.a0 == 9 && e.a1 == 0);
	OPT_BAD("mode=crc;ro=1", WR_E_RBURL_OPT_VALUE, "mode"); /* ";" is no separator */
	/* the first "=" splits: a second one belongs to the value */
	OPT_BAD("mode=crc=crc", WR_E_RBURL_OPT_VALUE, "mode");
	OPT_BAD("ro=1=", WR_E_RBURL_OPT_VALUE, "ro");

	/* unknown names: every option is known by its exact name only */
	e = OPT_BAD("ro=1&frobnicate=1", WR_E_RBURL_OPT_UNKNOWN, "option");
	WRT_CHECK(e.a0 == 5 && e.a1 == 10);
	OPT_BAD("Mode=crc", WR_E_RBURL_OPT_UNKNOWN, "option");
	OPT_BAD("mode =crc", WR_E_RBURL_ESCAPE, "option");
	OPT_BAD("modes=crc", WR_E_RBURL_OPT_UNKNOWN, "option");
	OPT_BAD("mod=crc", WR_E_RBURL_OPT_UNKNOWN, "option");
	OPT_BAD("user=x", WR_E_RBURL_OPT_UNKNOWN, "option"); /* the identity is not an option */
	OPT_BAD("key=AQ", WR_E_RBURL_OPT_UNKNOWN, "option");   /* and the key never travels in the URL */
	OPT_BAD("password=x", WR_E_RBURL_OPT_UNKNOWN, "option");
	OPT_BAD("snap=x", WR_E_RBURL_OPT_UNKNOWN, "option");
	OPT_BAD("namespace=x", WR_E_RBURL_OPT_UNKNOWN, "option");
	OPT_BAD("ro=1&mode=crc&nosuch=1", WR_E_RBURL_OPT_UNKNOWN, "option");
	/* a name longer than any option is unknown, even with a long value */
	OPT_BAD("averyveryveryveryveryveryveryveryveryveryveryverylongname=1", WR_E_RBURL_OPT_UNKNOWN, "option");

	/* duplicates, also with different values, and also when the second one is spelled with an escape */
	e = OPT_BAD("mode=crc&mode=crc", WR_E_RBURL_OPT_DUP, "mode");
	WRT_CHECK(e.a0 == 9 && e.a1 == 4);
	OPT_BAD("mode=crc&ro=1&mode=secure", WR_E_RBURL_OPT_DUP, "mode");
	OPT_BAD("ro=1&r%6f=1", WR_E_RBURL_OPT_DUP, "ro");
	OPT_BAD("ro=0&ro=bogus", WR_E_RBURL_OPT_DUP, "ro"); /* the repeat is refused before its value is judged */
	OPT_BAD("fsid=01234567-89ab-cdef-fedc-ba9876543210&fsid=01234567-89ab-cdef-fedc-ba9876543210", WR_E_RBURL_OPT_DUP, "fsid");
	OPT_BAD("timeout=5&timeout=6", WR_E_RBURL_OPT_DUP, "timeout");
	OPT_BAD("readahead=5&readahead=6", WR_E_RBURL_OPT_DUP, "readahead");
	OPT_BAD("devpath=uri&devpath=uri", WR_E_RBURL_OPT_DUP, "devpath");
	OPT_BAD("handoff=key&handoff=key", WR_E_RBURL_OPT_DUP, "handoff");
	OPT_BAD("mapmem=16&mapmem=16", WR_E_RBURL_OPT_DUP, "mapmem");
	OPT_BAD("monmsg=64&monmsg=64", WR_E_RBURL_OPT_DUP, "monmsg");

	/* the first mistake, left to right, wins */
	OPT_BAD("ro=9&bogus=1", WR_E_RBURL_OPT_VALUE, "ro");
	OPT_BAD("bogus=1&ro=9", WR_E_RBURL_OPT_UNKNOWN, "option");

	/* the query cap: exactly WR_RBURL_QUERY_MAX bytes are looked at, one more is refused whatever it says */
	memset(big, 0, sizeof(big));
	strcpy(big, "ro=1&mode=crc");
	{
		size_t n = strlen(big);

		big[n++] = '&';
		while (n < WR_RBURL_QUERY_MAX) /* padding made of an unknown option would fail; use one long escaped-free duplicate-free tail */
			big[n++] = 'x';
		big[n] = '\0';
	}
	/* "...&xxxx" has no "=": it is a syntax error at the tail, but only because the cap let it get that far */
	c.query = big;
	{
		wr_errinfo e2 = bad(__LINE__, &c, WR_E_RBURL_OPT_SYNTAX, "option");

		WRT_CHECK(e2.a0 == 14);
	}
	big[WR_RBURL_QUERY_MAX] = 'x';
	big[WR_RBURL_QUERY_MAX + 1] = '\0';
	e = bad(__LINE__, &c, WR_E_RBURL_TOO_LONG, "query");
	WRT_CHECK(e.a1 == WR_RBURL_QUERY_MAX + 1u && e.a2 == WR_RBURL_QUERY_MAX);
	(void)sp;
}

/* ---- password, key ----------------------------------------------------------------------------------------- */

static void test_password_and_key(void)
{
	urlcase c = base();
	wr_rburl_spec sp;
	wr_errinfo e;
	char big[WR_RBURL_KEY_TEXT_MAX + 8u];

	c.has_password = 1;
	e = BAD(&c, WR_E_RBURL_PASSWORD, "password");
	WRT_CHECK(e.a0 == 0 && e.a1 == 0 && e.a2 == 0);
	/* it comes before everything else: with a missing user, no monitors, a bad path and a bad query, still the password */
	c.user = NULL;
	c.auth = NULL;
	c.path = "bad";
	c.query = "bogus";
	c.set_key = NULL;
	BAD(&c, WR_E_RBURL_PASSWORD, "password");
	c = base();
	c.has_password = 0;
	CHECK_ST(WR_OK, ok(&c, &sp));

	/* the key: base64 */
	c.set_key = NULL;
	BAD(&c, WR_E_RBURL_NO_KEY, "key");
	c.set_key = "";
	BAD(&c, WR_E_RBURL_BAD_KEY, "key");
	c.set_key = "   ";
	BAD(&c, WR_E_RBURL_BAD_KEY, "key");
	c.set_key = "not a key";
	BAD(&c, WR_E_RBURL_BAD_KEY, "key");
	c.set_key = "AQAA8VNlAAAAABAAAAECAwQFBgcICQoLDA0O"; /* too short for its own length field */
	BAD(&c, WR_E_RBURL_BAD_KEY, "key");
	c.set_key = "AQAA8VNlAAAAABAAAAECAwQFBgcICQoLDA0ODw==AAAA"; /* trailing junk */
	BAD(&c, WR_E_RBURL_BAD_KEY, "key");
	c.set_key = "  " KEY_AES "  \n"; /* whitespace around is fine */
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.key.len == 16);

	/* the keyring forms */
	c.set_key = "[client.winrbd]\n\tkey = " KEY_AES "\n\tcaps mon = \"allow r\"\n";
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.key.type == WR_KEY_TYPE_AES && sp.key.secret[3] == 3);
	c.set_key = "key = " KEY_256;
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.key.type == WR_KEY_TYPE_AES256K);
	c.set_key = "key=" KEY_256 "\r\n";
	CHECK_ST(WR_OK, ok(&c, &sp));
	c.set_key = "[client.x]\n\tcaps mon = \"allow r\"\n"; /* no key line */
	BAD(&c, WR_E_RBURL_BAD_KEY, "key");
	c.set_key = "key = AQAA8VNlAAAA"; /* a key line that does not decode */
	BAD(&c, WR_E_RBURL_BAD_KEY, "key");
	c.set_key = "key ="; /* empty */
	BAD(&c, WR_E_RBURL_BAD_KEY, "key");

	/* the text cap: 1024 bytes are looked at (a keyring with room for comments), 1025 are not */
	memset(big, ' ', sizeof(big));
	memcpy(big, KEY_AES, strlen(KEY_AES));
	big[WR_RBURL_KEY_TEXT_MAX] = '\0';
	c.set_key = big;
	CHECK_ST(WR_OK, ok(&c, &sp));
	big[WR_RBURL_KEY_TEXT_MAX] = ' ';
	big[WR_RBURL_KEY_TEXT_MAX + 1] = '\0';
	e = BAD(&c, WR_E_RBURL_TOO_LONG, "key");
	WRT_CHECK(e.a1 == WR_RBURL_KEY_TEXT_MAX + 1u && e.a2 == WR_RBURL_KEY_TEXT_MAX);

	/* no failure holds key material: every refusal that comes after the key was parsed leaves the spec zero (checked by
	 * BAD), and the errinfo has no pointer to the text and no number that is a byte of the key */
	c = base();
	c.path = "/rbd/img@snap";
	e = BAD(&c, WR_E_UNSUPPORTED, "snapshot");
	WRT_CHECK(e.a0 == 0 && e.a1 == 0 && e.a2 == 0 && e.peer_result == 0 && e.conn == 0);
	c = base();
	c.query = "ro=9";
	BAD(&c, WR_E_RBURL_OPT_VALUE, "ro");
}

/* ---- the first mistake wins ------------------------------------------------------------------------------- */

static void test_error_order(void)
{
	urlcase c;
	wr_errinfo e;

	/* every part wrong at once: user first, then monitors, path, query, key */
	c = base();
	c.user = NULL;
	c.auth = "name";
	c.path = "x";
	c.query = "bogus=1";
	c.set_key = "junk";
	BAD(&c, WR_E_RBURL_NO_USER, "user");
	c.user = "ok";
	BAD(&c, WR_E_MON_HOSTS_SYNTAX, "monitors");
	c.auth = "10.0.0.1";
	BAD(&c, WR_E_RBURL_PATH, "path");
	c.path = "/p/i";
	e = BAD(&c, WR_E_RBURL_OPT_UNKNOWN, "option");
	WRT_CHECK(e.a0 == 0 && e.a1 == 5);
	c.query = NULL;
	BAD(&c, WR_E_RBURL_BAD_KEY, "key");
	c.set_key = KEY_AES;
	{
		wr_rburl_spec sp;

		CHECK_ST(WR_OK, ok(&c, &sp));
	}

	/* a snapshot is the very last gate: any other mistake is reported first */
	c = base();
	c.path = "/p/i@s";
	c.set_key = NULL;
	BAD(&c, WR_E_RBURL_NO_KEY, "key");
	c.set_key = KEY_AES;
	c.query = "mode=x";
	BAD(&c, WR_E_RBURL_OPT_VALUE, "mode");
	c.query = NULL;
	BAD(&c, WR_E_UNSUPPORTED, "snapshot");
}

/* ---- argument checks and length caps ------------------------------------------------------------------------ */

static void test_arguments(void)
{
	wr_rburl_in in;
	wr_rburl_spec sp;
	wr_errinfo e;

	memset(&in, 0, sizeof(in));
	memset(&sp, 0x77, sizeof(sp));
	CHECK_ST(WR_E_INVAL, wr_rburl_parse(&in, NULL, NULL)); /* no output: nothing to wipe */
	CHECK_ST(WR_E_INVAL, wr_rburl_parse(NULL, &sp, &e));
	WRT_CHECK(is_zero(&sp, sizeof(sp)) && e.status == WR_E_INVAL && strcmp(e.what, "input") == 0);
	/* a NULL text with a length is a bad argument, not "absent" */
	in.user = NULL;
	in.user_len = 3;
	CHECK_ST(WR_E_INVAL, wr_rburl_parse(&in, &sp, &e));
	in.user_len = 0;
	in.authority_len = 1;
	CHECK_ST(WR_E_INVAL, wr_rburl_parse(&in, &sp, &e));
	in.authority_len = 0;
	in.path_len = 1;
	CHECK_ST(WR_E_INVAL, wr_rburl_parse(&in, &sp, &e));
	in.path_len = 0;
	in.query_len = 1;
	CHECK_ST(WR_E_INVAL, wr_rburl_parse(&in, &sp, &e));
	in.query_len = 0;
	in.set_user_len = 1;
	CHECK_ST(WR_E_INVAL, wr_rburl_parse(&in, &sp, &e));
	in.set_user_len = 0;
	in.set_key_len = 1;
	CHECK_ST(WR_E_INVAL, wr_rburl_parse(&in, &sp, &e));
	in.set_key_len = 0;
	/* an all-absent input is the first missing thing: the user */
	CHECK_ST(WR_E_RBURL_NO_USER, wr_rburl_parse(&in, &sp, NULL));
	WRT_CHECK(is_zero(&sp, sizeof(sp)));
	/* err may be NULL on success too */
	{
		urlcase c = base();
		wr_rburl_in in2;

		memset(&in2, 0, sizeof(in2));
		in2.user = c.user;
		in2.user_len = strlen(c.user);
		in2.authority = c.auth;
		in2.authority_len = strlen(c.auth);
		in2.path = c.path;
		in2.path_len = strlen(c.path);
		in2.set_key = c.set_key;
		in2.set_key_len = strlen(c.set_key);
		CHECK_ST(WR_OK, wr_rburl_parse(&in2, &sp, NULL));
	}
}

/* The texts are pointer + length and nothing looks for a terminator: a NUL byte inside one is just a byte that no part accepts.
 * Every text is an exact-size heap copy (ASan), the NUL is the last byte of a longer text or in the middle of it. */
static void test_embedded_nul(void)
{
	static const struct {
		const char *user, *auth, *path, *query, *key;
		size_t user_n, auth_n, path_n, query_n, key_n;
		int has_query;
		wr_status want;
		const char *what;
	} rows[] = {
		/* user: in the middle, and as the last byte */
		{"ab\0c", "10.0.0.1", "/a/b", "", KEY_AES, 4, 8, 4, 0, sizeof(KEY_AES) - 1, 0, WR_E_RBURL_BAD_USER, "user"},
		{"abc\0", "10.0.0.1", "/a/b", "", KEY_AES, 4, 8, 4, 0, sizeof(KEY_AES) - 1, 0, WR_E_RBURL_BAD_USER, "user"},
		/* path: a name with a NUL in it, a NUL where the image name should start */
		{"u", "10.0.0.1", "/a/b\0c", "", KEY_AES, 1, 8, 6, 0, sizeof(KEY_AES) - 1, 0, WR_E_RBURL_NAME, "image"},
		{"u", "10.0.0.1", "/a\0/b", "", KEY_AES, 1, 8, 5, 0, sizeof(KEY_AES) - 1, 0, WR_E_RBURL_NAME, "pool"},
		/* query: a NUL in a value is a raw byte outside 0x21 .. 0x7e; in a name too */
		{"u", "10.0.0.1", "/a/b", "ro=1\0", KEY_AES, 1, 8, 4, 5, sizeof(KEY_AES) - 1, 1, WR_E_RBURL_ESCAPE, "ro"},
		{"u", "10.0.0.1", "/a/b", "r\0o=1", KEY_AES, 1, 8, 4, 6, sizeof(KEY_AES) - 1, 1, WR_E_RBURL_ESCAPE, "option"},
		/* key setting: a NUL is not base64 and not whitespace */
		{"u", "10.0.0.1", "/a/b", "", KEY_AES "\0", 1, 8, 4, 0, sizeof(KEY_AES), 0, WR_E_RBURL_BAD_KEY, "key"},
	};
	size_t i;

	for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
		wr_rburl_in in;
		wr_rburl_spec sp;
		wr_errinfo e;
		char *u, *a, *p, *q, *k;
		wr_status st;

		memset(&in, 0, sizeof(in));
		u = (char *)malloc(rows[i].user_n);
		a = (char *)malloc(rows[i].auth_n);
		p = (char *)malloc(rows[i].path_n);
		q = (char *)malloc(rows[i].query_n ? rows[i].query_n : 1u);
		k = (char *)malloc(rows[i].key_n);
		if (u == NULL || a == NULL || p == NULL || q == NULL || k == NULL) {
			fprintf(stderr, "out of memory\n");
			exit(2);
		}
		memcpy(u, rows[i].user, rows[i].user_n);
		memcpy(a, rows[i].auth, rows[i].auth_n);
		memcpy(p, rows[i].path, rows[i].path_n);
		memcpy(q, rows[i].query, rows[i].query_n);
		memcpy(k, rows[i].key, rows[i].key_n);
		in.user = u, in.user_len = rows[i].user_n;
		in.authority = a, in.authority_len = rows[i].auth_n;
		in.path = p, in.path_len = rows[i].path_n;
		if (rows[i].has_query)
			in.query = q, in.query_len = rows[i].query_n;
		in.set_key = k, in.set_key_len = rows[i].key_n;
		memset(&sp, 0x5a, sizeof(sp));
		st = wr_rburl_parse(&in, &sp, &e);
		check_st(__LINE__, "embedded NUL", st, rows[i].want);
		WRT_CHECK(is_zero(&sp, sizeof(sp)));
		WRT_CHECK(e.what != NULL && strcmp(e.what, rows[i].what) == 0);
		free(u);
		free(a);
		free(p);
		free(q);
		free(k);
	}
}

static void test_caps(void)
{
	urlcase c = base();
	wr_rburl_spec sp;
	wr_errinfo e;
	char big[WR_RBURL_AUTHORITY_MAX + 16u];
	size_t n;

	/* the monitor list: 1024 bytes are parsed (here a list full of separators and one address), 1025 are refused */
	memset(big, ',', sizeof(big));
	memcpy(big, "10.0.0.1", 8);
	big[WR_RBURL_AUTHORITY_MAX] = '\0';
	c.auth = big;
	CHECK_ST(WR_OK, ok(&c, &sp));
	WRT_CHECK(sp.n_mons == 1);
	big[WR_RBURL_AUTHORITY_MAX] = ',';
	big[WR_RBURL_AUTHORITY_MAX + 1] = '\0';
	e = BAD(&c, WR_E_RBURL_TOO_LONG, "monitors");
	WRT_CHECK(e.a1 == WR_RBURL_AUTHORITY_MAX + 1u && e.a2 == WR_RBURL_AUTHORITY_MAX);

	/* the user text */
	c = base();
	memset(big, 'u', sizeof(big));
	n = WR_RBURL_USER_TEXT_MAX + 1u;
	big[n] = '\0';
	c.user = big;
	e = BAD(&c, WR_E_RBURL_TOO_LONG, "user");
	WRT_CHECK(e.a1 == n && e.a2 == WR_RBURL_USER_TEXT_MAX);
	c.user = NULL;
	c.set_user = big;
	BAD(&c, WR_E_RBURL_TOO_LONG, "rbd-user");
}

/* ---- the status block ------------------------------------------------------------------------------------- */

static void test_status_block(void)
{
	static const struct {
		wr_status st;
		const char *name;
	} rows[] = {
#define WR_X_T(name, code, text) {name, #name},
		WR_RBURL_STATUS_LIST(WR_X_T)
#undef WR_X_T
	};
	size_t i, j;
	wr_status other;

	WRT_CHECK(sizeof(rows) / sizeof(rows[0]) == 17u);
	for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
		WRT_CHECK(rows[i].st <= -260 && rows[i].st >= -279);
		WRT_CHECK(strcmp(wr_rburl_status_name(rows[i].st), rows[i].name) == 0);
		WRT_CHECK(strlen(wr_rburl_strerror(rows[i].st)) > 10u && strcmp(wr_rburl_strerror(rows[i].st), "unknown status") != 0);
		for (j = i + 1u; j < sizeof(rows) / sizeof(rows[0]); j++)
			WRT_CHECK(rows[i].st != rows[j].st);
		/* no clash with the shared table: it either does not know the code or (once this block has moved into
		 * WR_STATUS_LIST) says exactly the same */
		WRT_CHECK(strcmp(wr_strerror(rows[i].st), "unknown status") == 0 ||
			  strcmp(wr_strerror(rows[i].st), wr_rburl_strerror(rows[i].st)) == 0);
		WRT_CHECK(strcmp(wr_status_name(rows[i].st), "WR_E_UNKNOWN") == 0 ||
			  strcmp(wr_status_name(rows[i].st), rows[i].name) == 0);
		WRT_CHECK(strncmp(wr_rburl_status_name(rows[i].st), "WR_E_RBURL_", 11) == 0);
	}
	/* other statuses fall through to the shared table */
	for (other = 1; other <= 13; other++)
		WRT_CHECK(strcmp(wr_rburl_status_name(-other), wr_status_name(-other)) == 0 &&
			  strcmp(wr_rburl_strerror(-other), wr_strerror(-other)) == 0);
	WRT_CHECK(strcmp(wr_rburl_strerror(WR_E_UNSUPPORTED), wr_strerror(WR_E_UNSUPPORTED)) == 0);
	WRT_CHECK(strcmp(wr_rburl_strerror(WR_OK), "success") == 0 && strcmp(wr_rburl_status_name(WR_OK), "WR_OK") == 0);
	WRT_CHECK(strcmp(wr_rburl_status_name(-999), "WR_E_UNKNOWN") == 0);
	/* every status the parser can return is in a known set: the module's own, the three shared ones it passes on */
}

/* ---- the percent decoder, white-box ------------------------------------------------------------------------- */

static int unesc(const char *raw, size_t cap, char *out, size_t *len)
{
	char *c = dupn(raw);
	int rc = wri_rburl_unescape(c, strlen(raw), out, cap, len);

	free(c);
	return rc;
}

static void test_unescape(void)
{
	char out[16];
	size_t n = 99;

	WRT_CHECK(unesc("", sizeof(out), out, &n) == WRI_RBURL_ESC_OK && n == 0 && out[0] == '\0');
	WRT_CHECK(unesc("abc", sizeof(out), out, &n) == WRI_RBURL_ESC_OK && n == 3 && strcmp(out, "abc") == 0);
	WRT_CHECK(unesc("a%41%7e%7E", sizeof(out), out, &n) == WRI_RBURL_ESC_OK && n == 4 && strcmp(out, "aA~~") == 0);
	WRT_CHECK(unesc("%25", sizeof(out), out, &n) == WRI_RBURL_ESC_OK && n == 1 && strcmp(out, "%") == 0);
	WRT_CHECK(unesc("%2541", sizeof(out), out, &n) == WRI_RBURL_ESC_OK && n == 3 && strcmp(out, "%41") == 0); /* decoded once only */
	WRT_CHECK(unesc("a+b", sizeof(out), out, &n) == WRI_RBURL_ESC_OK && strcmp(out, "a+b") == 0);
	WRT_CHECK(unesc("%01%1f%7f", sizeof(out), out, &n) == WRI_RBURL_ESC_OK && n == 3 && out[0] == 1 && out[1] == 0x1f && out[2] == 0x7f);
	WRT_CHECK(unesc("%ff", sizeof(out), out, &n) == WRI_RBURL_ESC_OK && n == 1 && (unsigned char)out[0] == 0xffu);
	/* failures leave an empty string and a zero length */
	WRT_CHECK(unesc("ab%", sizeof(out), out, &n) == WRI_RBURL_ESC_BAD && n == 0 && out[0] == '\0');
	WRT_CHECK(unesc("ab%4", sizeof(out), out, &n) == WRI_RBURL_ESC_BAD && n == 0);
	WRT_CHECK(unesc("%g0", sizeof(out), out, &n) == WRI_RBURL_ESC_BAD);
	WRT_CHECK(unesc("%0g", sizeof(out), out, &n) == WRI_RBURL_ESC_BAD);
	WRT_CHECK(unesc("%00", sizeof(out), out, &n) == WRI_RBURL_ESC_BAD);
	WRT_CHECK(unesc("a b", sizeof(out), out, &n) == WRI_RBURL_ESC_BAD);
	WRT_CHECK(unesc("a\x7f", sizeof(out), out, &n) == WRI_RBURL_ESC_BAD);
	WRT_CHECK(unesc("a\x80", sizeof(out), out, &n) == WRI_RBURL_ESC_BAD);
	/* the cap counts the NUL: 7 bytes fit in 8 */
	WRT_CHECK(unesc("1234567", 8, out, &n) == WRI_RBURL_ESC_OK && n == 7 && strcmp(out, "1234567") == 0);
	WRT_CHECK(unesc("12345678", 8, out, &n) == WRI_RBURL_ESC_TOO_LONG && n == 0 && out[0] == '\0');
	WRT_CHECK(unesc("%31%32%33%34%35%36%37", 8, out, &n) == WRI_RBURL_ESC_OK && n == 7);
	WRT_CHECK(unesc("%31%32%33%34%35%36%37%38", 8, out, &n) == WRI_RBURL_ESC_TOO_LONG);
	WRT_CHECK(unesc("a", 2, out, &n) == WRI_RBURL_ESC_OK && n == 1);
	WRT_CHECK(unesc("ab", 2, out, &n) == WRI_RBURL_ESC_TOO_LONG);
}

/* ---- a deterministic mutation loop ------------------------------------------------------------------------- */

static uint32_t rng_state = 0x12345678u;

static uint32_t rnd(void)
{
	rng_state = rng_state * 1664525u + 1013904223u;
	return rng_state >> 8;
}

static int known_status(wr_status st)
{
	return st == WR_OK || st == WR_E_INVAL || st == WR_E_UNSUPPORTED || st == WR_E_MON_HOSTS_SYNTAX || st == WR_E_MON_NO_V2_ADDR ||
	       (st <= -260 && st >= -276);
}

static void test_mutations(void)
{
	static const char alphabet[] = "abcmodero=&%0123456789ABCDEF-.,:/@[]!\"' \t\x7f\x80";
	static const char *const seeds[][3] = {
		{"10.0.0.1:3300,10.0.0.2", "/pool/image", "mode=crc-first&ro=1&timeout=30"},
		{"[fd00::1]:3300", "/p/i", "fsid=01234567-89ab-cdef-fedc-ba9876543210&readahead=0"},
		{"10.0.0.1", "/rbd/disk", "devpath=uri&handoff=none&mapmem=64&monmsg=128"},
		{"10.0.0.1", "/rbd/disk", "%6dode=secure"},
	};
	size_t iter, ok_count = 0, fail_count = 0;

	for (iter = 0; iter < 60000u; iter++) {
		const char *const *sd = seeds[rnd() % 4u];
		char a[64], p[48], q[160];
		urlcase c = base();
		wr_rburl_spec sp;
		wr_errinfo e;
		wr_status st;
		char *targets[3] = {a, p, q};
		unsigned t, nmut;

		snprintf(a, sizeof(a), "%s", sd[0]);
		snprintf(p, sizeof(p), "%s", sd[1]);
		snprintf(q, sizeof(q), "%s", sd[2]);
		nmut = rnd() % 4u;
		for (t = 0; t < nmut; t++) {
			char *s = targets[rnd() % 3u];
			size_t n = strlen(s), at;
			unsigned kind = rnd() % 4u;

			if (n == 0)
				continue;
			at = rnd() % n;
			if (kind == 0)
				s[at] = alphabet[rnd() % (sizeof(alphabet) - 1u)];
			else if (kind == 1)
				memmove(s + at, s + at + 1, n - at); /* delete */
			else if (kind == 2 && n + 1u < 40u) {
				memmove(s + at + 1, s + at, n - at + 1u); /* insert */
				s[at] = alphabet[rnd() % (sizeof(alphabet) - 1u)];
			} else
				s[at] = '\0'; /* truncate */
		}
		c.auth = a;
		c.path = p;
		c.query = q;
		if ((rnd() & 15u) == 0)
			c.set_key = NULL;
		st = run(&c, &sp, &e);
		WRT_CHECK(known_status(st));
		if (st != WR_OK) {
			fail_count++;
			WRT_CHECK(is_zero(&sp, sizeof(sp)));
			WRT_CHECK(e.status == st && e.what != NULL && e.module == WR_MOD_HOST);
			WRT_CHECK(strlen(wr_rburl_strerror(st)) > 5u);
			continue;
		}
		ok_count++;
		WRT_CHECK(e.status == WR_OK && is_zero(&e, sizeof(e)));
		WRT_CHECK(sp.n_mons >= 1 && sp.n_mons <= WR_MAX_MONS);
		WRT_CHECK(sp.user[0] != '\0' && sp.pool[0] != '\0' && sp.image[0] != '\0' && sp.snap[0] == '\0');
		WRT_CHECK(sp.mode >= WR_MODE_CRC_ONLY && sp.mode <= WR_MODE_SECURE_ONLY && sp.read_only <= 1 && sp.devpath <= 2 && sp.handoff <= 2);
		WRT_CHECK(sp.open_timeout_ms >= 1000u && sp.open_timeout_ms <= 600000u && sp.open_timeout_ms % 1000u == 0);
		WRT_CHECK(sp.readahead_kib <= 16384u && (sp.mapmem_kib == 0 || sp.mapmem_kib >= 16u) && (sp.monmsg_kib == 0 || sp.monmsg_kib >= 64u));
		WRT_CHECK(sp.key.len >= 16);
		wr_rburl_spec_wipe(&sp);
	}
	WRT_CHECK(ok_count > 1000 && fail_count > 1000); /* the loop reaches both sides */
}

int main(void)
{
	test_defaults();
	test_user();
	test_monitors();
	test_broken_by_parse_uri();
	test_path();
	test_path_split();
	test_options_mode_ro();
	test_options_numbers();
	test_options_numbers2();
	test_options_words();
	test_options_fsid();
	test_options_combined();
	test_escapes();
	test_query_grammar();
	test_password_and_key();
	test_error_order();
	test_arguments();
	test_embedded_nul();
	test_caps();
	test_status_block();
	test_unescape();
	test_mutations();
	return wrt_finish();
}
