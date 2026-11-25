/* SPDX-License-Identifier: MIT */
/*
 * wri_rburl.c - the parts of an rbd:// URL: user, monitors, path, key, and the entry point (wr_rburl.h).
 *
 * The query and its options are in wri_rburl_opt.c. Every function keeps its frame small (a firmware stack can be 4 KiB),
 * allocates nothing and writes only into the spec it is given; wr_rburl_parse wipes that spec on any failure.
 */
#include "wri_rburl.h"

WR_FILE_LICENCE_MIT

/* ---- statuses ------------------------------------------------------------------------------------------------ */

typedef struct wri_rburl_row {
	wr_status status;
	const char *name;
	const char *text;
} wri_rburl_row;

static const wri_rburl_row wri_rburl_table[] = {
#define WR_X_RBURL_ROW(name, code, text) {name, #name, text},
	WR_RBURL_STATUS_LIST(WR_X_RBURL_ROW)
#undef WR_X_RBURL_ROW
};

#define WRI_RBURL_ROWS (sizeof(wri_rburl_table) / sizeof(wri_rburl_table[0]))

static const wri_rburl_row *rburl_row(wr_status st)
{
	size_t i;

	for (i = 0; i < WRI_RBURL_ROWS; i++)
		if (wri_rburl_table[i].status == st)
			return &wri_rburl_table[i];
	return NULL;
}

const char *wr_rburl_strerror(wr_status st)
{
	const wri_rburl_row *r = rburl_row(st);

	return r != NULL ? r->text : wr_strerror(st);
}

const char *wr_rburl_status_name(wr_status st)
{
	const wri_rburl_row *r = rburl_row(st);

	return r != NULL ? r->name : wr_status_name(st);
}

wr_status wri_rburl_fail(wr_errinfo *err, wr_status st, const char *what, uint64_t a0, uint64_t a1, uint64_t a2,
			 unsigned line)
{
	if (err != NULL) {
		WR_MEMSET(err, 0, sizeof(*err));
		err->status = st;
		err->module = (uint8_t)WR_MOD_HOST;
		err->line = (uint16_t)line;
		err->a0 = a0;
		err->a1 = a1;
		err->a2 = a2;
		err->what = what;
	}
	return st;
}

/* ---- spec ---------------------------------------------------------------------------------------------------- */

void wr_rburl_spec_wipe(wr_rburl_spec *spec)
{
	if (spec == NULL)
		return;
	wr_key_wipe(&spec->key); /* the secret first, with the wipe the compiler cannot remove */
	WR_MEMSET(spec, 0, sizeof(*spec));
}

void wri_rburl_defaults(wr_rburl_spec *out)
{
	out->mode = (uint8_t)WR_MODE_CRC_ONLY;
	out->devpath = (uint8_t)WR_RBURL_DEVPATH_VENDOR;
	out->handoff = (uint8_t)WR_RBURL_HANDOFF_NOKEY;
	out->open_timeout_ms = WR_RBURL_TIMEOUT_DEFAULT_MS;
	out->readahead_kib = WR_RBURL_READAHEAD_DEFAULT_KIB;
}

/* ---- the user ------------------------------------------------------------------------------------------------ */

static int is_user_byte(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '_' || c == '-';
}

static int starts_with(const char *s, size_t n, const char *lit, size_t lit_n)
{
	size_t i;

	if (n < lit_n)
		return 0;
	for (i = 0; i < lit_n; i++)
		if (s[i] != lit[i])
			return 0;
	return 1;
}

/* The URL's user, else the rbd-user setting; "client." in front is dropped (once; a second one is refused, see below). */
static wr_status parse_user(const wr_rburl_in *in, wr_rburl_spec *out, wr_errinfo *err)
{
	const char *s, *what;
	size_t n, i;

	if (in->user != NULL) {
		s = in->user;
		n = in->user_len;
		what = "user";
	} else if (in->set_user != NULL) {
		s = in->set_user;
		n = in->set_user_len;
		what = "rbd-user";
	} else {
		return WRI_RBURL_FAIL(err, WR_E_RBURL_NO_USER, "user", 0, 0, 0);
	}
	if (n > WR_RBURL_USER_TEXT_MAX)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_TOO_LONG, what, 0, n, WR_RBURL_USER_TEXT_MAX);
	if (starts_with(s, n, "client.", 7u)) {
		s += 7;
		n -= 7u;
		/* The core strips one "client." again when it opens the client (wr_cluster_spec.user). An id that still starts
		 * with it ("client.client.x") would therefore be sent as another entity ("x") than the one written: refuse it
		 * rather than authenticate as somebody else. */
		if (starts_with(s, n, "client.", 7u))
			return WRI_RBURL_FAIL(err, WR_E_RBURL_BAD_USER, what, 7, 7, 0);
	}
	if (n == 0 || n >= WR_ENTITY_MAX)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_BAD_USER, what, 0, n, WR_ENTITY_MAX - 1u);
	for (i = 0; i < n; i++)
		if (!is_user_byte(s[i]))
			return WRI_RBURL_FAIL(err, WR_E_RBURL_BAD_USER, what, i, 1, 0);
	WR_MEMCPY(out->user, s, n);
	out->user[n] = '\0';
	return WR_OK;
}

/* ---- the monitors -------------------------------------------------------------------------------------------- */

/* The spec has one slot more than it keeps (mons[WR_MAX_MONS], scratch), so a ninth address shows as "too many" instead of
 * being dropped without a word, and no address array lives on the stack. */
static wr_status parse_mons(const wr_rburl_in *in, wr_rburl_spec *out, wr_errinfo *err)
{
	size_t n = 0;
	wr_status st;

	if (in->authority == NULL || in->authority_len == 0)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_NO_MONS, "monitors", 0, 0, 0);
	if (in->authority_len > WR_RBURL_AUTHORITY_MAX)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_TOO_LONG, "monitors", 0, in->authority_len, WR_RBURL_AUTHORITY_MAX);
	st = wr_mon_parse_hosts(in->authority, in->authority_len, out->mons, WR_MAX_MONS + 1u, &n);
	if (st != WR_OK)
		return WRI_RBURL_FAIL(err, st, "monitors", 0, in->authority_len, 0);
	if (n == 0 || n > WR_MAX_MONS)
		return WRI_RBURL_FAIL(err, n == 0 ? WR_E_RBURL_NO_MONS : WR_E_RBURL_MANY_MONS, "monitors", n, WR_MAX_MONS, 0);
	out->n_mons = (uint8_t)n;
	return WR_OK;
}

/* ---- the path ------------------------------------------------------------------------------------------------ */

/* Visible ASCII (what the core accepts in an image name or a pool: no space, no control byte) except the two separators. */
static int is_name_byte(char c)
{
	unsigned char u = (unsigned char)c;

	return u >= 0x21u && u <= 0x7eu && c != '/' && c != '@';
}

/* s[0 .. n) at path offset `off` into dst (WR_RBURL_NAME_MAX bytes). */
static wr_status copy_name(const char *s, size_t n, size_t off, char *dst, const char *what, wr_errinfo *err)
{
	size_t i;

	if (n == 0)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_NAME, what, off, 0, 0);
	if (n >= WR_RBURL_NAME_MAX)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_NAME_LONG, what, off, n, WR_RBURL_NAME_MAX - 1u);
	for (i = 0; i < n; i++)
		if (!is_name_byte(s[i]))
			return WRI_RBURL_FAIL(err, WR_E_RBURL_NAME, what, off + i, 1, 0);
	WR_MEMCPY(dst, s, n);
	dst[n] = '\0';
	return WR_OK;
}

wr_status wri_rburl_path(const char *p, size_t n, wr_rburl_spec *out, wr_errinfo *err)
{
	size_t slash = 1, at, i;
	wr_status st;

	if (p == NULL || n == 0 || p[0] != '/')
		return WRI_RBURL_FAIL(err, WR_E_RBURL_PATH, "path", 0, n, 0);
	if (n > WR_RBURL_PATH_MAX)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_TOO_LONG, "path", 0, n, WR_RBURL_PATH_MAX);
	while (slash < n && p[slash] != '/')
		slash++;
	if (slash >= n) /* "/pool" alone */
		return WRI_RBURL_FAIL(err, WR_E_RBURL_PATH, "path", slash, n, 0);
	for (i = slash + 1u; i < n; i++) /* a third component (an RBD namespace, not supported) or a trailing slash */
		if (p[i] == '/')
			return WRI_RBURL_FAIL(err, WR_E_RBURL_PATH, "path", i, n, 0);
	at = slash + 1u;
	while (at < n && p[at] != '@')
		at++;
	st = copy_name(p + 1, slash - 1u, 1, out->pool, "pool", err);
	if (st == WR_OK)
		st = copy_name(p + slash + 1u, at - (slash + 1u), slash + 1u, out->image, "image", err);
	if (st == WR_OK && at < n)
		st = copy_name(p + at + 1u, n - (at + 1u), at + 1u, out->snap, "snapshot", err);
	return st;
}

/* ---- the key ------------------------------------------------------------------------------------------------- */

/* A real base64 key starts with "AQ" or "Ag", never with "key", so trying the keyring line first cannot misread one. */
static wr_status parse_key(const wr_rburl_in *in, wr_rburl_spec *out, wr_errinfo *err)
{
	if (in->set_key == NULL)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_NO_KEY, "key", 0, 0, 0);
	if (in->set_key_len > WR_RBURL_KEY_TEXT_MAX)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_TOO_LONG, "key", 0, in->set_key_len, WR_RBURL_KEY_TEXT_MAX);
	if (wr_key_parse_keyring(&out->key, in->set_key, in->set_key_len) == WR_OK)
		return WR_OK;
	if (wr_key_parse_base64(&out->key, in->set_key, in->set_key_len) == WR_OK)
		return WR_OK;
	return WRI_RBURL_FAIL(err, WR_E_RBURL_BAD_KEY, "key", 0, 0, 0); /* nothing of the text goes into the error */
}

/* ---- the entry point ----------------------------------------------------------------------------------------- */

static int text_ok(const char *p, size_t n)
{
	return p != NULL || n == 0;
}

static wr_status parse_parts(const wr_rburl_in *in, wr_rburl_spec *out, wr_errinfo *err)
{
	wr_status st;

	if (!text_ok(in->user, in->user_len) || !text_ok(in->authority, in->authority_len) ||
	    !text_ok(in->path, in->path_len) || !text_ok(in->query, in->query_len) ||
	    !text_ok(in->set_user, in->set_user_len) || !text_ok(in->set_key, in->set_key_len))
		return WRI_RBURL_FAIL(err, WR_E_INVAL, "input", 0, 0, 0);
	if (in->has_password != 0)
		return WRI_RBURL_FAIL(err, WR_E_RBURL_PASSWORD, "password", 0, 0, 0);
	st = parse_user(in, out, err);
	if (st == WR_OK)
		st = parse_mons(in, out, err);
	if (st == WR_OK)
		st = wri_rburl_path(in->path, in->path_len, out, err);
	if (st == WR_OK && in->query != NULL) {
		if (in->query_len > WR_RBURL_QUERY_MAX)
			return WRI_RBURL_FAIL(err, WR_E_RBURL_TOO_LONG, "query", 0, in->query_len, WR_RBURL_QUERY_MAX);
		st = wri_rburl_query(in->query, in->query_len, out, err);
	}
	if (st == WR_OK)
		st = parse_key(in, out, err);
	/* the last gate: a snapshot is understood and validated above, and refused here until the core can open one */
	if (st == WR_OK && out->snap[0] != '\0')
		st = WRI_RBURL_FAIL(err, WR_E_UNSUPPORTED, "snapshot", 0, 0, 0);
	return st;
}

wr_status wr_rburl_parse(const wr_rburl_in *in, wr_rburl_spec *out, wr_errinfo *err)
{
	wr_status st;

	if (err != NULL)
		WR_MEMSET(err, 0, sizeof(*err));
	if (out == NULL)
		return WR_E_INVAL;
	wr_rburl_spec_wipe(out);
	if (in == NULL)
		return WRI_RBURL_FAIL(err, WR_E_INVAL, "input", 0, 0, 0);
	wri_rburl_defaults(out);
	st = parse_parts(in, out, err);
	if (st != WR_OK)
		wr_rburl_spec_wipe(out);
	return st;
}
