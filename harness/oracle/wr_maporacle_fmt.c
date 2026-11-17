/* SPDX-License-Identifier: MIT */
/*
 * wr_maporacle_fmt.c - the text wr-maporacle prints and the readers of its inputs. See wr_maporacle_fmt.h.
 * Harness code: libc allowed, never shipped.
 */
#include "wr_maporacle_fmt.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "wri_crc32c.h"

#define NONE_ITEM 0x7fffffff

/* ---- output ---------------------------------------------------------------------------------------------- */

void wrm_put_list(FILE *o, const int32_t *v, uint32_t n, int none_text)
{
	uint32_t i;

	fputc('[', o);
	for (i = 0; i < n; i++) {
		if (i != 0)
			fputc(',', o);
		if (none_text && v[i] == NONE_ITEM)
			fputs("NONE", o);
		else
			fprintf(o, "%d", (int)v[i]);
	}
	fputc(']', o);
}

void wrm_put_escaped(FILE *o, const uint8_t *s, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		uint8_t c = s[i];

		if (c == '\\')
			fputs("\\\\", o);
		else if (c >= 0x20u && c <= 0x7eu)
			fputc((int)c, o);
		else
			fprintf(o, "\\x%02x", (unsigned)c);
	}
}

static void put_objname(FILE *o, const uint8_t *ns, size_t ns_len, const uint8_t *name, size_t name_len)
{
	fputc('\'', o);
	if (ns_len != 0) {
		wrm_put_escaped(o, ns, ns_len);
		fputc('/', o);
	}
	wrm_put_escaped(o, name, name_len);
	fputc('\'', o);
}

static void put_object_head(FILE *o, uint32_t epoch, const uint8_t *pool_name, size_t pool_name_len, int64_t pool_id, const uint8_t *name,
			    size_t name_len, const uint8_t *ns, size_t ns_len)
{
	fprintf(o, "osdmap e%u pool '", (unsigned)epoch);
	wrm_put_escaped(o, pool_name, pool_name_len);
	fprintf(o, "' (%" PRId64 ") object ", pool_id);
	put_objname(o, ns, ns_len, name, name_len);
	fputs(" -> ", o);
}

static void put_set(FILE *o, const int32_t *v, uint32_t n, int32_t primary, int none_text)
{
	fputc('(', o);
	wrm_put_list(o, v, n, none_text);
	fprintf(o, ", p%d)", (int)primary);
}

void wrm_put_object_line(FILE *o, uint32_t epoch, const uint8_t *pool_name, size_t pool_name_len, int64_t pool_id, const uint8_t *name,
			 size_t name_len, const uint8_t *ns, size_t ns_len, uint32_t ps, uint32_t seed, const wri_pg_result *r)
{
	put_object_head(o, epoch, pool_name, pool_name_len, pool_id, name, name_len, ns, ns_len);
	fprintf(o, "pg %" PRId64 ".%x (%" PRId64 ".%x) -> up ", pool_id, (unsigned)ps, pool_id, (unsigned)seed);
	put_set(o, r->up, r->n_up, r->up_primary, 1);
	fputs(" acting ", o);
	put_set(o, r->acting, r->n_acting, r->acting_primary, 1);
	fputc('\n', o);
}

void wrm_put_object_error(FILE *o, uint32_t epoch, const uint8_t *pool_name, size_t pool_name_len, int64_t pool_id, const uint8_t *name,
			  size_t name_len, const uint8_t *ns, size_t ns_len, wr_status st, const wr_errinfo *why)
{
	put_object_head(o, epoch, pool_name, pool_name_len, pool_id, name, name_len, ns, ns_len);
	fprintf(o, "ERROR %s", wr_status_name(st));
	if (why != NULL && why->what != NULL)
		fprintf(o, " (%s)", why->what);
	fputc('\n', o);
}

/* The first member that is not NONE, as osdmaptool reports the raw primary; -1 for none. */
static int32_t raw_primary(const wri_pg_result *r)
{
	uint32_t i;

	for (i = 0; i < r->n_raw; i++)
		if (r->raw[i] != NONE_ITEM)
			return r->raw[i];
	return -1;
}

void wrm_put_pg_line(FILE *o, int64_t pool, uint32_t seed, const wri_pg_result *r)
{
	fprintf(o, "%" PRId64 ".%x raw ", pool, (unsigned)seed);
	put_set(o, r->raw, r->n_raw, raw_primary(r), 0);
	fputs(" up ", o);
	put_set(o, r->up, r->n_up, r->up_primary, 0);
	fputs(" acting ", o);
	put_set(o, r->acting, r->n_acting, r->acting_primary, 0);
	fputc('\n', o);
}

void wrm_put_pg_error(FILE *o, int64_t pool, uint32_t seed, wr_status st, const wr_errinfo *why)
{
	fprintf(o, "%" PRId64 ".%x ERROR %s", pool, (unsigned)seed, wr_status_name(st));
	if (why != NULL && why->what != NULL)
		fprintf(o, " (%s)", why->what);
	fputc('\n', o);
}

void wrm_put_pool_error(FILE *o, int64_t pool, wr_status st)
{
	fprintf(o, "pool %" PRId64 " ERROR %s\n", pool, wr_status_name(st));
}

void wrm_put_crush_line(FILE *o, uint32_t rule, uint32_t x, const int32_t *v, uint32_t n)
{
	fprintf(o, "CRUSH rule %u x %u ", (unsigned)rule, (unsigned)x);
	wrm_put_list(o, v, n, 0);
	fputc('\n', o);
}

void wrm_put_crush_error(FILE *o, uint32_t rule, uint32_t x, wr_status st, const wr_errinfo *why)
{
	fprintf(o, "CRUSH rule %u x %u ERROR %s", (unsigned)rule, (unsigned)x, wr_status_name(st));
	if (why != NULL && why->what != NULL)
		fprintf(o, " (%s)", why->what);
	fputc('\n', o);
}

void wrm_put_status(FILE *o, wr_status st, const wr_errinfo *why)
{
	fprintf(o, "%s (%s", wr_status_name(st), wr_strerror(st));
	if (why != NULL && why->what != NULL)
		fprintf(o, "; %s; %" PRIu64 " %" PRIu64 " %" PRIu64, why->what, why->a0, why->a1, why->a2);
	fputc(')', o);
}

/* ---- the compact state ------------------------------------------------------------------------------------ */

static void put_addr(FILE *o, const wri_osd_addr *a)
{
	unsigned i;

	if (a->family == WR_AF_IPV4) {
		fprintf(o, "v4 %u.%u.%u.%u:%u/%u", (unsigned)a->ip[0], (unsigned)a->ip[1], (unsigned)a->ip[2], (unsigned)a->ip[3], (unsigned)a->port,
			(unsigned)a->nonce);
	} else if (a->family == WR_AF_IPV6) {
		fputs("v6 [", o);
		for (i = 0; i < 8u; i++)
			fprintf(o, "%s%x", i ? ":" : "", ((unsigned)a->ip[2u * i] << 8) | (unsigned)a->ip[2u * i + 1u]);
		fprintf(o, "]:%u/%u", (unsigned)a->port, (unsigned)a->nonce);
	} else {
		fputs("none", o);
	}
}

static void put_table(FILE *o, const wri_osdmap *m, unsigned kind, const char *label)
{
	const uint64_t *key = wri_pgtab_keys(m, kind);
	const uint32_t *off = wri_pgtab_offs(m, kind);
	const int32_t *val = wri_pgtab_vals(m, kind);
	uint32_t i;

	for (i = 0; i < m->tab[kind].n; i++) {
		fprintf(o, "%s %u.%x ", label, (unsigned)(key[i] >> 32), (unsigned)(key[i] & 0xffffffffu));
		wrm_put_list(o, val + off[i], off[i + 1u] - off[i], 0);
		fputc('\n', o);
	}
}

void wrm_put_state(FILE *o, const wri_osdmap *m, const wri_mapcfg *cfg)
{
	const uint8_t *st = wri_map_state(m);
	const uint32_t *wt = wri_map_weight(m);
	const wri_osd_addr *ad = wri_map_addr(m);
	const wri_map_pool *pl = wri_map_pools(m);
	const wri_crush *c = wri_map_crush(m);
	uint32_t i, buckets = 0, rules = 0;
	unsigned k;

	fprintf(o, "== epoch %u\n", (unsigned)m->epoch);
	fprintf(o, "fsid %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n", m->fsid[0], m->fsid[1], m->fsid[2], m->fsid[3],
		m->fsid[4], m->fsid[5], m->fsid[6], m->fsid[7], m->fsid[8], m->fsid[9], m->fsid[10], m->fsid[11], m->fsid[12], m->fsid[13],
		m->fsid[14], m->fsid[15]);
	fprintf(o, "flags 0x%08x\n", (unsigned)m->flags);
	fprintf(o, "max_osd %u\n", (unsigned)m->max_osd);
	for (i = 0; i < m->max_osd; i++) {
		fprintf(o, "osd.%u state %u weight %u affinity %u addr ", (unsigned)i, (unsigned)st[i], (unsigned)wt[i], (unsigned)wri_osd_aff(m, (int32_t)i));
		put_addr(o, &ad[i]);
		fputc('\n', o);
	}
	for (k = 0; k < m->n_pools; k++) {
		fputs("pool ", o);
		if (!pl[k].present) {
			fputc('\'', o);
			if (cfg != NULL && k < cfg->n_pools)
				wrm_put_escaped(o, cfg->name[k], cfg->name_len[k]);
			fputs("' absent\n", o);
			continue;
		}
		fprintf(o, "%" PRId64 " '", pl[k].id);
		if (cfg != NULL && k < cfg->n_pools)
			wrm_put_escaped(o, cfg->name[k], cfg->name_len[k]);
		fprintf(o, "' present type %u size %u min_size %u rule %u hash %u flags 0x%" PRIx64 " pg_num %u pgp_num %u pg_num_pending %u status %s\n",
			(unsigned)pl[k].type, (unsigned)pl[k].size, (unsigned)pl[k].min_size, (unsigned)pl[k].crush_rule, (unsigned)pl[k].object_hash,
			pl[k].flags, (unsigned)pl[k].pg_num, (unsigned)pl[k].pgp_num, (unsigned)pl[k].pg_num_pending, wr_status_name((wr_status)pl[k].status));
	}
	put_table(o, m, WRI_TAB_PG_TEMP, "pg_temp");
	put_table(o, m, WRI_TAB_PRIMARY_TEMP, "primary_temp");
	put_table(o, m, WRI_TAB_PG_UPMAP, "pg_upmap");
	put_table(o, m, WRI_TAB_PG_UPMAP_ITEMS, "pg_upmap_items");
	put_table(o, m, WRI_TAB_PG_UPMAP_PRIMARY, "pg_upmap_primary");
	if (c == NULL) {
		fputs("crush none\n", o);
		return;
	}
	for (i = 0; i < c->max_buckets; i++)
		if (wri_crush_bucket_at(c, i) != NULL)
			buckets++;
	for (i = 0; i < c->max_rules; i++)
		if (wri_crush_rule_kind(c, i) != 0u)
			rules++;
	fprintf(o, "crush buckets %u rules %u max_devices %d bytes %u crc32c 0x%08x\n", (unsigned)buckets, (unsigned)rules, (int)c->max_devices,
		(unsigned)c->bytes, (unsigned)wri_crc32c(0, (const uint8_t *)c, c->bytes));
}

/* ---- input ----------------------------------------------------------------------------------------------- */

static int hexval(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int wrm_hex_decode(const char *s, size_t len, uint8_t **out, size_t *n)
{
	uint8_t *b;
	size_t i, k = 0;
	int hi = -1;

	*out = NULL;
	*n = 0;
	b = (uint8_t *)malloc(len / 2u + 1u);
	if (b == NULL)
		return -1;
	for (i = 0; i < len; i++) {
		int v;

		if (isspace((unsigned char)s[i]))
			continue;
		v = hexval((unsigned char)s[i]);
		if (v < 0) {
			free(b);
			return -1;
		}
		if (hi < 0) {
			hi = v;
		} else {
			b[k++] = (uint8_t)((hi << 4) | v);
			hi = -1;
		}
	}
	if (hi >= 0) {
		free(b);
		return -1;
	}
	if (k == 0) {
		free(b);
		return 0;
	}
	*out = b;
	*n = k;
	return 0;
}

int wrm_parse_u64(const char *s, uint64_t *v)
{
	char *end = NULL;
	unsigned long long x;

	if (s == NULL || *s == '\0' || *s == '-' || *s == '+' || isspace((unsigned char)*s))
		return -1;
	errno = 0;
	x = strtoull(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0')
		return -1;
	*v = (uint64_t)x;
	return 0;
}

int wrm_parse_i64(const char *s, int64_t *v)
{
	char *end = NULL;
	long long x;

	if (s == NULL || *s == '\0' || isspace((unsigned char)*s))
		return -1;
	errno = 0;
	x = strtoll(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0')
		return -1;
	*v = (int64_t)x;
	return 0;
}

int wrm_parse_weight(const char *s, uint32_t *w16)
{
	char *end = NULL;
	double d;
	float f;
	int w;

	if (s == NULL || *s == '\0')
		return -1;
	errno = 0;
	d = strtod(s, &end);
	if (errno != 0 || end == s || *end != '\0' || d != d)
		return -1;
	if (d > 4.0)
		d = 4.0;
	if (d < -4.0)
		d = -4.0;
	f = (float)d;
	w = (int)(f * 65536.0f);
	if (w < 0)
		w = 0;
	if (w > 0x10000)
		w = 0x10000;
	*w16 = (uint32_t)w;
	return 0;
}

static int read_all(const char *path, uint8_t **buf, size_t *n, const char **err)
{
	FILE *f = fopen(path, "rb");
	uint8_t *b = NULL;
	size_t cap = 0, len = 0;

	if (f == NULL) {
		*err = "cannot open file";
		return -1;
	}
	for (;;) {
		size_t got;

		if (cap - len < 65536u) {
			uint8_t *nb;

			cap = cap ? cap * 2u : 262144u;
			nb = (uint8_t *)realloc(b, cap);
			if (nb == NULL) {
				free(b);
				fclose(f);
				*err = "out of memory";
				return -1;
			}
			b = nb;
		}
		got = fread(b + len, 1, cap - len, f);
		len += got;
		if (got == 0)
			break;
	}
	if (ferror(f)) {
		free(b);
		fclose(f);
		*err = "read error";
		return -1;
	}
	fclose(f);
	if (b == NULL) {
		b = (uint8_t *)malloc(1);
		if (b == NULL) {
			*err = "out of memory";
			return -1;
		}
	}
	*buf = b;
	*n = len;
	return 0;
}

static int is_text(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (!(p[i] == '\t' || p[i] == '\n' || p[i] == '\r' || (p[i] >= 0x20u && p[i] < 0x7fu)))
			return 0;
	return 1;
}

/* Next line of text[pos..n): [*b, *e) without the comment and the surrounding white space; returns 0 at the end of the text. */
static int next_line(const uint8_t *t, size_t n, size_t *pos, size_t *b, size_t *e)
{
	size_t i, s, f;

	if (*pos >= n)
		return 0;
	s = *pos;
	for (i = s; i < n && t[i] != '\n'; i++)
		;
	*pos = i < n ? i + 1u : n;
	f = i;
	{
		size_t k;

		for (k = s; k < i; k++)
			if (t[k] == '#') {
				f = k;
				break;
			}
	}
	while (s < f && isspace((int)t[s]))
		s++;
	while (f > s && isspace((int)t[f - 1u]))
		f--;
	*b = s;
	*e = f;
	return 1;
}

int wrm_load_blob(const char *path, uint8_t **buf, size_t *n, const char **err)
{
	uint8_t *raw = NULL, *out = NULL;
	size_t rn = 0, pos = 0, b, e, on = 0;
	char *joined;
	size_t jl = 0;

	if (read_all(path, &raw, &rn, err) != 0)
		return -1;
	if (!is_text(raw, rn)) {
		*buf = raw;
		*n = rn;
		return 0;
	}
	joined = (char *)malloc(rn + 1u);
	if (joined == NULL) {
		free(raw);
		*err = "out of memory";
		return -1;
	}
	while (next_line(raw, rn, &pos, &b, &e)) {
		memcpy(joined + jl, raw + b, e - b);
		jl += e - b;
	}
	free(raw);
	if (wrm_hex_decode(joined, jl, &out, &on) != 0) {
		free(joined);
		*err = "text file is not hex (use # for comments)";
		return -1;
	}
	free(joined);
	if (out == NULL) {
		out = (uint8_t *)malloc(1);
		if (out == NULL) {
			*err = "out of memory";
			return -1;
		}
	}
	*buf = out;
	*n = on;
	return 0;
}

void wrm_items_free(wrm_item *items, size_t count)
{
	size_t i;

	if (items == NULL)
		return;
	for (i = 0; i < count; i++)
		free(items[i].p);
	free(items);
}

static int push_item(wrm_item **items, size_t *count, size_t *cap, uint8_t *p, size_t n)
{
	if (*count == *cap) {
		size_t nc = *cap ? *cap * 2u : 64u;
		wrm_item *ni = (wrm_item *)realloc(*items, nc * sizeof(**items));

		if (ni == NULL)
			return -1;
		*items = ni;
		*cap = nc;
	}
	(*items)[*count].p = p;
	(*items)[*count].n = n;
	(*count)++;
	return 0;
}

int wrm_load_items(const char *path, wrm_item **items, size_t *count, const char **err)
{
	uint8_t *raw = NULL;
	size_t rn = 0, pos = 0, b, e, cap = 0;
	size_t lines = 0, labelled = 0;
	wrm_item *list = NULL;
	size_t cnt = 0;

	*items = NULL;
	*count = 0;
	if (read_all(path, &raw, &rn, err) != 0)
		return -1;
	if (is_text(raw, rn)) {
		/* a list file when every non-empty line is "<digits> <hex>" */
		while (next_line(raw, rn, &pos, &b, &e)) {
			size_t i = b;

			if (e == b)
				continue;
			lines++;
			while (i < e && raw[i] >= '0' && raw[i] <= '9')
				i++;
			/* a label is a plain epoch (at most ten digits, no leading zero): a hex dump written as "08 07 ..." is a blob, not a list */
			if (i > b && i - b <= 10u && (raw[b] != '0' || i - b == 1u) && i < e && isspace((int)raw[i]))
				labelled++;
		}
		if (lines != 0 && labelled == lines) {
			pos = 0;
			while (next_line(raw, rn, &pos, &b, &e)) {
				size_t i = b;
				uint8_t *blob = NULL;
				size_t bn = 0;

				if (e == b)
					continue;
				while (i < e && raw[i] >= '0' && raw[i] <= '9')
					i++;
				if (wrm_hex_decode((const char *)raw + i, e - i, &blob, &bn) != 0 || blob == NULL ||
				    push_item(&list, &cnt, &cap, blob, bn) != 0) {
					free(blob);
					wrm_items_free(list, cnt);
					free(raw);
					*err = "bad line in the incremental list (want \"<epoch> <hex>\")";
					return -1;
				}
			}
			free(raw);
			*items = list;
			*count = cnt;
			return 0;
		}
	}
	free(raw);
	/* a single incremental: raw bytes or hex text */
	{
		uint8_t *blob = NULL;
		size_t bn = 0;

		if (wrm_load_blob(path, &blob, &bn, err) != 0)
			return -1;
		if (push_item(&list, &cnt, &cap, blob, bn) != 0) {
			free(blob);
			*err = "out of memory";
			return -1;
		}
		*items = list;
		*count = cnt;
	}
	return 0;
}
