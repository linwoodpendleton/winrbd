/* SPDX-License-Identifier: MIT */
/*
 * wrt_json.c - a small JSON reader for test vectors. Own code, test-only (recursion and malloc are fine
 * here, unlike in core/). It parses the whole document into a flat token array; every token knows the
 * index just past its subtree, so lookups are linear walks. Strings keep their raw (escaped) slice and
 * are unescaped on demand.
 */
#include <ctype.h>

#include "wrt.h"

enum { J_OBJ = 1, J_ARR, J_STR, J_NUM, J_BOOL, J_NULL };

typedef struct jtok {
	int type;
	size_t start, end; /* STR: contents without quotes; NUM/BOOL/NULL: literal text */
	size_t count;      /* OBJ: members, ARR: elements */
	int next;          /* index just past this token's subtree */
} jtok;

typedef struct jparse {
	const char *s;
	size_t n, pos;
	jtok *tok;
	size_t ntok, cap;
	int err;
} jparse;

static void j_ws(jparse *p)
{
	while (p->pos < p->n && isspace((unsigned char)p->s[p->pos]))
		p->pos++;
}

static int j_new(jparse *p, int type)
{
	if (p->ntok == p->cap) {
		size_t ncap = p->cap ? p->cap * 2 : 256;
		jtok *t = (jtok *)realloc(p->tok, ncap * sizeof(*t));

		if (!t) {
			p->err = 1;
			return -1;
		}
		p->tok = t;
		p->cap = ncap;
	}
	memset(&p->tok[p->ntok], 0, sizeof(jtok));
	p->tok[p->ntok].type = type;
	return (int)p->ntok++;
}

static int j_value(jparse *p, int depth);

static int j_string(jparse *p)
{
	int t;
	size_t start;

	if (p->pos >= p->n || p->s[p->pos] != '"') {
		p->err = 1;
		return -1;
	}
	p->pos++;
	start = p->pos;
	while (p->pos < p->n && p->s[p->pos] != '"') {
		if (p->s[p->pos] == '\\')
			p->pos++;
		p->pos++;
	}
	if (p->pos >= p->n) {
		p->err = 1;
		return -1;
	}
	t = j_new(p, J_STR);
	if (t < 0)
		return -1;
	p->tok[t].start = start;
	p->tok[t].end = p->pos;
	p->pos++;
	p->tok[t].next = t + 1;
	return t;
}

static int j_value(jparse *p, int depth)
{
	int t;

	if (depth > 64) {
		p->err = 1;
		return -1;
	}
	j_ws(p);
	if (p->pos >= p->n) {
		p->err = 1;
		return -1;
	}
	if (p->s[p->pos] == '{' || p->s[p->pos] == '[') {
		int is_obj = p->s[p->pos] == '{';
		char close = is_obj ? '}' : ']';
		size_t count = 0;

		p->pos++;
		t = j_new(p, is_obj ? J_OBJ : J_ARR);
		if (t < 0)
			return -1;
		j_ws(p);
		if (p->pos < p->n && p->s[p->pos] == close) {
			p->pos++;
		} else {
			for (;;) {
				if (is_obj) {
					j_ws(p);
					if (j_string(p) < 0)
						return -1;
					j_ws(p);
					if (p->pos >= p->n || p->s[p->pos] != ':') {
						p->err = 1;
						return -1;
					}
					p->pos++;
				}
				if (j_value(p, depth + 1) < 0)
					return -1;
				count++;
				j_ws(p);
				if (p->pos < p->n && p->s[p->pos] == ',') {
					p->pos++;
					continue;
				}
				if (p->pos < p->n && p->s[p->pos] == close) {
					p->pos++;
					break;
				}
				p->err = 1;
				return -1;
			}
		}
		p->tok[t].count = count;
		p->tok[t].next = (int)p->ntok;
		return t;
	}
	if (p->s[p->pos] == '"')
		return j_string(p);
	{
		size_t start = p->pos;
		int type = J_NUM;

		while (p->pos < p->n && !strchr(",]} \t\r\n", p->s[p->pos]))
			p->pos++;
		if (p->pos == start) {
			p->err = 1;
			return -1;
		}
		if (p->s[start] == 't' || p->s[start] == 'f')
			type = J_BOOL;
		else if (p->s[start] == 'n')
			type = J_NULL;
		t = j_new(p, type);
		if (t < 0)
			return -1;
		p->tok[t].start = start;
		p->tok[t].end = p->pos;
		p->tok[t].next = t + 1;
		return t;
	}
}

int wrt_json_parse(wrt_json *j, const char *text, size_t n)
{
	jparse p;

	memset(j, 0, sizeof(*j));
	j->text = (char *)malloc(n + 1);
	if (!j->text)
		return -1;
	memcpy(j->text, text, n);
	j->text[n] = 0;
	j->text_len = n;
	memset(&p, 0, sizeof(p));
	p.s = j->text;
	p.n = n;
	if (j_value(&p, 0) < 0 || p.err) {
		free(p.tok);
		free(j->text);
		memset(j, 0, sizeof(*j));
		return -1;
	}
	j->tok = p.tok;
	j->ntok = p.ntok;
	return 0;
}

int wrt_json_load(wrt_json *j, const char *path)
{
	uint8_t *b;
	size_t n;
	int rc;

	if (wrt_read_file(path, &b, &n) != 0)
		return -1;
	rc = wrt_json_parse(j, (const char *)b, n);
	free(b);
	if (rc != 0)
		fprintf(stderr, "cannot parse JSON %s\n", path);
	return rc;
}

int wrt_json_load_vec(wrt_json *j, const char *rel)
{
	return wrt_json_load(j, wrt_vec_path(rel));
}

void wrt_json_free(wrt_json *j)
{
	free(j->tok);
	free(j->text);
	memset(j, 0, sizeof(*j));
}

static const jtok *J(const wrt_json *j, wrt_tok t)
{
	if (t < 0 || (size_t)t >= j->ntok)
		return NULL;
	return &((const jtok *)j->tok)[t];
}

wrt_tok wrt_json_root(const wrt_json *j)
{
	return j->ntok ? 0 : WRT_NONE;
}

static int j_key_is(const wrt_json *j, const jtok *k, const char *key)
{
	size_t n = strlen(key);

	return k->end - k->start == n && memcmp(j->text + k->start, key, n) == 0;
}

wrt_tok wrt_json_get(const wrt_json *j, wrt_tok obj, const char *key)
{
	const jtok *o = J(j, obj);
	int idx;
	size_t i;

	if (!o || o->type != J_OBJ)
		return WRT_NONE;
	idx = obj + 1;
	for (i = 0; i < o->count; i++) {
		const jtok *k = J(j, idx);
		const jtok *v = J(j, idx + 1);

		if (!k || !v)
			return WRT_NONE;
		if (j_key_is(j, k, key))
			return idx + 1;
		idx = v->next;
	}
	return WRT_NONE;
}

wrt_tok wrt_json_at(const wrt_json *j, wrt_tok arr, size_t i)
{
	const jtok *a = J(j, arr);
	int idx;
	size_t k;

	if (!a || a->type != J_ARR || i >= a->count)
		return WRT_NONE;
	idx = arr + 1;
	for (k = 0; k < i; k++) {
		const jtok *e = J(j, idx);

		if (!e)
			return WRT_NONE;
		idx = e->next;
	}
	return idx;
}

size_t wrt_json_count(const wrt_json *j, wrt_tok t)
{
	const jtok *x = J(j, t);

	return (x && (x->type == J_OBJ || x->type == J_ARR)) ? x->count : 0;
}

int wrt_json_is_string(const wrt_json *j, wrt_tok t)
{
	const jtok *x = J(j, t);

	return x && x->type == J_STR;
}

int wrt_json_is_number(const wrt_json *j, wrt_tok t)
{
	const jtok *x = J(j, t);

	return x && x->type == J_NUM;
}

int wrt_json_is_bool(const wrt_json *j, wrt_tok t)
{
	const jtok *x = J(j, t);

	return x && x->type == J_BOOL;
}

const char *wrt_json_key_at(const wrt_json *j, wrt_tok obj, size_t i, wrt_tok *value)
{
	const jtok *o = J(j, obj);
	int idx;
	size_t k;
	static char keybuf[256];
	const jtok *key;
	size_t n;

	if (!o || o->type != J_OBJ || i >= o->count)
		return NULL;
	idx = obj + 1;
	for (k = 0; k < i; k++) {
		const jtok *v = J(j, idx + 1);

		if (!v)
			return NULL;
		idx = v->next;
	}
	key = J(j, idx);
	if (!key)
		return NULL;
	n = key->end - key->start;
	if (n >= sizeof(keybuf))
		n = sizeof(keybuf) - 1;
	memcpy(keybuf, j->text + key->start, n);
	keybuf[n] = 0;
	if (value)
		*value = idx + 1;
	return keybuf;
}

char *wrt_json_strdup(const wrt_json *j, wrt_tok t)
{
	const jtok *x = J(j, t);
	char *out;
	size_t i, k = 0;

	if (!x || x->type != J_STR)
		return NULL;
	out = (char *)malloc(x->end - x->start + 1);
	if (!out)
		return NULL;
	for (i = x->start; i < x->end; i++) {
		char c = j->text[i];

		if (c == '\\' && i + 1 < x->end) {
			c = j->text[++i];
			switch (c) {
			case 'n': c = '\n'; break;
			case 't': c = '\t'; break;
			case 'r': c = '\r'; break;
			case 'b': c = '\b'; break;
			case 'f': c = '\f'; break;
			case 'u': /* BMP code point below 0x80 only; vectors are ASCII */
				if (i + 4 < x->end + 0u) {
					unsigned v = 0;
					int d;

					for (d = 1; d <= 4; d++)
						v = v * 16 + (unsigned)(isdigit((unsigned char)j->text[i + (size_t)d]) ?
									 j->text[i + (size_t)d] - '0' :
									 (tolower((unsigned char)j->text[i + (size_t)d]) - 'a' + 10));
					i += 4;
					c = v < 0x80 ? (char)v : '?';
				}
				break;
			default: break; /* \" \\ \/ : the character itself */
			}
		}
		out[k++] = c;
	}
	out[k] = 0;
	return out;
}

int64_t wrt_json_int(const wrt_json *j, wrt_tok t, int *ok)
{
	const jtok *x = J(j, t);
	char buf[64];
	char *end;
	size_t n;
	long long v;

	if (ok)
		*ok = 0;
	if (!x || (x->type != J_NUM && x->type != J_STR))
		return 0;
	n = x->end - x->start;
	if (n == 0 || n >= sizeof(buf))
		return 0;
	memcpy(buf, j->text + x->start, n);
	buf[n] = 0;
	v = strtoll(buf, &end, 0);
	if (*end != 0)
		return 0;
	if (ok)
		*ok = 1;
	return (int64_t)v;
}

int wrt_json_hex(const wrt_json *j, wrt_tok t, uint8_t **out, size_t *n)
{
	const jtok *x = J(j, t);

	if (!x || x->type != J_STR)
		return -1;
	return wrt_hex_decode(j->text + x->start, x->end - x->start, out, n);
}

int wrt_json_get_hex(const wrt_json *j, wrt_tok obj, const char *key, uint8_t **out, size_t *n)
{
	wrt_tok v = wrt_json_get(j, obj, key);

	if (v == WRT_NONE)
		return -1;
	return wrt_json_hex(j, v, out, n);
}
