/* SPDX-License-Identifier: MIT */
/*
 * wrt_mapgen.c - writes (and reads back) the wire bytes of part B from plain description structs, builds
 * clusters, and holds the independent model. See wrt_mapgen.h for the design; docs/spec/osdmap.md for the layouts.
 *
 * Every wire structure has ONE walker function that serves encode, decode and free through a small codec
 * (wrt_mg_cx): the layout is written once, so the encoder and the reader can never drift apart. That makes a
 * symmetric layout mistake invisible to a round trip, which is why the self test checks the walkers against the
 * real bytes of harness/vectors/osdmap/ and against an independent reader in the test, and why
 * harness/tools/mapgen_dencoder_check.sh feeds the output to Ceph's own decoder.
 */
#include "wrt_mapgen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wri_crc32c.h"

static void oom(void)
{
	fprintf(stderr, "wrt_mapgen: out of memory\n");
	abort();
}

/* ---- buffers, vectors, PRNG -------------------------------------------------------------------------------- */

void wrt_mg_buf_free(wrt_mg_buf *b)
{
	free(b->p);
	b->p = NULL;
	b->len = b->cap = 0;
}

void wrt_mg_buf_put(wrt_mg_buf *b, const void *p, size_t n)
{
	if (b->len + n > b->cap) {
		size_t cap = b->cap ? b->cap : 256;
		uint8_t *q;

		while (cap < b->len + n)
			cap *= 2;
		q = (uint8_t *)realloc(b->p, cap);
		if (!q)
			oom();
		b->p = q;
		b->cap = cap;
	}
	if (n)
		memcpy(b->p + b->len, p, n);
	b->len += n;
}

void wrt_mg_vec_grow_(wrt_mg_vec *v, size_t esz)
{
	if (v->n == v->cap) {
		uint32_t cap = v->cap ? v->cap * 2 : 4;
		void *q = realloc(v->v, (size_t)cap * esz);

		if (!q)
			oom();
		v->v = q;
		v->cap = cap;
	}
}

void wrt_mg_vec_del(wrt_mg_vec *v, size_t esz, uint32_t i)
{
	uint8_t *b = (uint8_t *)v->v;

	if (i >= v->n)
		return;
	memmove(b + (size_t)i * esz, b + ((size_t)i + 1) * esz, ((size_t)v->n - i - 1) * esz);
	v->n--;
}

void wrt_mg_vec_resize0(wrt_mg_vec *v, size_t esz, uint32_t n)
{
	if (n > v->cap) {
		void *q = realloc(v->v, (size_t)n * esz);

		if (!q)
			oom();
		v->v = q;
		v->cap = n;
	}
	if (n > v->n)
		memset((uint8_t *)v->v + (size_t)v->n * esz, 0, ((size_t)n - v->n) * esz);
	v->n = n;
}

void wrt_mg_rng_seed(wrt_mg_rng *r, uint64_t seed)
{
	r->s = seed;
}

uint64_t wrt_mg_rng_next(wrt_mg_rng *r)
{
	uint64_t z = (r->s += 0x9e3779b97f4a7c15ull);

	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
	return z ^ (z >> 31);
}

uint32_t wrt_mg_rng_below(wrt_mg_rng *r, uint32_t n)
{
	return n ? (uint32_t)((wrt_mg_rng_next(r) >> 11) % n) : 0u;
}

/* ---- the codec ---------------------------------------------------------------------------------------------- */

static size_t limit(const wrt_mg_cx *cx)
{
	return cx->depth ? cx->mark[cx->depth - 1] : cx->len;
}

void wrt_mg_cx_fail(wrt_mg_cx *cx)
{
	cx->err = 1;
}

int wrt_mg_cx_more(const wrt_mg_cx *cx)
{
	return cx->mode == WRT_MG_DEC && !cx->err && cx->pos < limit(cx);
}

/* Fixed-width fields, little-endian. */
static void prim(wrt_mg_cx *cx, void *v, unsigned w)
{
	uint64_t x = 0;
	unsigned i;
	uint8_t b[8];

	if (cx->mode == WRT_MG_FREE)
		return;
	if (cx->mode == WRT_MG_ENC) {
		switch (w) {
		case 1:
			x = *(const uint8_t *)v;
			break;
		case 2:
			x = *(const uint16_t *)v;
			break;
		case 4:
			x = *(const uint32_t *)v;
			break;
		default:
			x = *(const uint64_t *)v;
			break;
		}
		for (i = 0; i < w; i++)
			b[i] = (uint8_t)(x >> (8 * i));
		wrt_mg_buf_put(cx->out, b, w);
		return;
	}
	if (cx->err || limit(cx) < cx->pos || w > limit(cx) - cx->pos) {
		cx->err = 1;
		return;
	}
	for (i = 0; i < w; i++)
		x |= (uint64_t)cx->in[cx->pos + i] << (8 * i);
	cx->pos += w;
	switch (w) {
	case 1:
		*(uint8_t *)v = (uint8_t)x;
		break;
	case 2:
		*(uint16_t *)v = (uint16_t)x;
		break;
	case 4:
		*(uint32_t *)v = (uint32_t)x;
		break;
	default:
		*(uint64_t *)v = x;
		break;
	}
}

void wrt_mg_cx_u8(wrt_mg_cx *cx, uint8_t *v)
{
	prim(cx, v, 1);
}
void wrt_mg_cx_u16(wrt_mg_cx *cx, uint16_t *v)
{
	prim(cx, v, 2);
}
void wrt_mg_cx_u32(wrt_mg_cx *cx, uint32_t *v)
{
	prim(cx, v, 4);
}
void wrt_mg_cx_s32(wrt_mg_cx *cx, int32_t *v)
{
	prim(cx, v, 4);
}
void wrt_mg_cx_u64(wrt_mg_cx *cx, uint64_t *v)
{
	prim(cx, v, 8);
}
void wrt_mg_cx_s64(wrt_mg_cx *cx, int64_t *v)
{
	prim(cx, v, 8);
}

void wrt_mg_cx_bytes(wrt_mg_cx *cx, void *p, size_t n)
{
	if (cx->mode == WRT_MG_FREE)
		return;
	if (cx->mode == WRT_MG_ENC) {
		wrt_mg_buf_put(cx->out, p, n);
		return;
	}
	if (cx->err || limit(cx) < cx->pos || n > limit(cx) - cx->pos) {
		cx->err = 1;
		return;
	}
	if (n)
		memcpy(p, cx->in + cx->pos, n);
	cx->pos += n;
}

void wrt_mg_cx_blob(wrt_mg_cx *cx, uint8_t **p, uint32_t *n)
{
	uint32_t len = *n;

	if (cx->mode == WRT_MG_FREE) {
		free(*p);
		*p = NULL;
		*n = 0;
		return;
	}
	wrt_mg_cx_u32(cx, &len);
	if (cx->mode == WRT_MG_ENC) {
		wrt_mg_buf_put(cx->out, *p, len);
		return;
	}
	if (cx->err)
		return;
	if (limit(cx) < cx->pos || len > limit(cx) - cx->pos) {
		cx->err = 1;
		return;
	}
	free(*p);
	*p = NULL;
	*n = 0;
	if (len) {
		*p = (uint8_t *)malloc(len);
		if (!*p)
			oom();
		memcpy(*p, cx->in + cx->pos, len);
	}
	*n = len;
	cx->pos += len;
}

void wrt_mg_cx_str(wrt_mg_cx *cx, char *s, size_t cap)
{
	uint32_t len = 0;

	if (cx->mode == WRT_MG_FREE)
		return;
	if (cx->mode == WRT_MG_ENC)
		len = (uint32_t)strlen(s);
	wrt_mg_cx_u32(cx, &len);
	if (cx->mode == WRT_MG_DEC && (cx->err || len >= cap)) {
		cx->err = 1;
		return;
	}
	wrt_mg_cx_bytes(cx, s, len);
	if (cx->mode == WRT_MG_DEC && !cx->err)
		s[len] = 0;
}

void wrt_mg_cx_varint(wrt_mg_cx *cx, uint64_t *v)
{
	if (cx->mode == WRT_MG_FREE)
		return;
	if (cx->mode == WRT_MG_ENC) {
		uint64_t x = *v;

		do {
			uint8_t b = (uint8_t)(x & 0x7f);

			x >>= 7;
			if (x)
				b |= 0x80;
			wrt_mg_buf_put(cx->out, &b, 1);
		} while (x);
		return;
	} else {
		uint64_t x = 0;
		unsigned shift = 0;

		for (;;) {
			uint8_t b = 0;

			wrt_mg_cx_u8(cx, &b);
			if (cx->err || shift > 63) {
				cx->err = 1;
				return;
			}
			x |= (uint64_t)(b & 0x7f) << shift;
			shift += 7;
			if (!(b & 0x80))
				break;
		}
		*v = x;
	}
}

void wrt_mg_cx_env_begin(wrt_mg_cx *cx, uint8_t *v, uint8_t *compat)
{
	uint32_t len = 0;

	if (cx->mode == WRT_MG_FREE)
		return;
	wrt_mg_cx_u8(cx, v);
	wrt_mg_cx_u8(cx, compat);
	if (cx->depth >= WRT_MG_DEPTH) {
		cx->err = 1;
		return;
	}
	if (cx->mode == WRT_MG_ENC) {
		cx->mark[cx->depth++] = cx->out->len;
		wrt_mg_buf_put(cx->out, &len, 4); /* placeholder (the bytes are overwritten at the end) */
		return;
	}
	wrt_mg_cx_u32(cx, &len);
	if (cx->err)
		return;
	if (limit(cx) < cx->pos || len > limit(cx) - cx->pos) {
		cx->err = 1;
		return;
	}
	cx->mark[cx->depth++] = cx->pos + len;
}

void wrt_mg_cx_env_end(wrt_mg_cx *cx, uint32_t *tail)
{
	if (cx->mode == WRT_MG_FREE || cx->depth == 0)
		return;
	if (cx->mode == WRT_MG_ENC) {
		size_t at = cx->mark[--cx->depth];
		uint32_t len;
		uint8_t zero[64];
		uint32_t t = *tail;

		memset(zero, 0, sizeof(zero));
		while (t) {
			uint32_t k = t > sizeof(zero) ? (uint32_t)sizeof(zero) : t;

			wrt_mg_buf_put(cx->out, zero, k);
			t -= k;
		}
		len = (uint32_t)(cx->out->len - (at + 4));
		cx->out->p[at] = (uint8_t)len;
		cx->out->p[at + 1] = (uint8_t)(len >> 8);
		cx->out->p[at + 2] = (uint8_t)(len >> 16);
		cx->out->p[at + 3] = (uint8_t)(len >> 24);
		return;
	}
	{
		size_t end = cx->mark[--cx->depth];

		if (cx->pos > end) {
			cx->err = 1;
			return;
		}
		*tail = (uint32_t)(end - cx->pos);
		cx->pos = end;
	}
}

void wrt_mg_cx_vec_n(wrt_mg_cx *cx, wrt_mg_vec *v, uint32_t n, size_t esz, wrt_mg_walk_fn fn)
{
	uint32_t i;
	uint8_t *zero;

	if (cx->mode == WRT_MG_FREE) {
		for (i = 0; i < v->n; i++)
			fn(cx, (uint8_t *)v->v + (size_t)i * esz);
		free(v->v);
		memset(v, 0, sizeof(*v));
		return;
	}
	if (cx->mode == WRT_MG_DEC) {
		/* every element is at least one byte on the wire; also refuse a count whose room would be absurd */
		if (cx->err || limit(cx) < cx->pos || n > limit(cx) - cx->pos || (uint64_t)n * esz > (256ull << 20)) {
			cx->err = 1;
			return;
		}
		wrt_mg_vec_resize0(v, esz, n);
		for (i = 0; i < n && !cx->err; i++)
			fn(cx, (uint8_t *)v->v + (size_t)i * esz);
		return;
	}
	zero = n > v->n ? (uint8_t *)calloc(1, esz) : NULL; /* elements past the end of the vector are written as zeros */
	if (n > v->n && !zero)
		oom();
	for (i = 0; i < n; i++)
		fn(cx, i < v->n ? (uint8_t *)v->v + (size_t)i * esz : zero);
	free(zero);
}

void wrt_mg_cx_vec(wrt_mg_cx *cx, wrt_mg_vec *v, size_t esz, wrt_mg_walk_fn fn)
{
	uint32_t n = v->n;

	if (cx->mode == WRT_MG_FREE) {
		wrt_mg_cx_vec_n(cx, v, 0, esz, fn);
		return;
	}
	wrt_mg_cx_u32(cx, &n);
	if (cx->err)
		return;
	wrt_mg_cx_vec_n(cx, v, n, esz, fn);
}

/* ---- element walkers ---------------------------------------------------------------------------------------- */

void wrt_mg_walk_utime(wrt_mg_cx *cx, void *e)
{
	wrt_mg_utime *t = (wrt_mg_utime *)e;

	wrt_mg_cx_u32(cx, &t->sec);
	wrt_mg_cx_u32(cx, &t->nsec);
}
void wrt_mg_walk_s32(wrt_mg_cx *cx, void *e)
{
	wrt_mg_cx_s32(cx, (int32_t *)e);
}
void wrt_mg_walk_u32(wrt_mg_cx *cx, void *e)
{
	wrt_mg_cx_u32(cx, (uint32_t *)e);
}
void wrt_mg_walk_u64(wrt_mg_cx *cx, void *e)
{
	wrt_mg_cx_u64(cx, (uint64_t *)e);
}
void wrt_mg_walk_s64(wrt_mg_cx *cx, void *e)
{
	wrt_mg_cx_s64(cx, (int64_t *)e);
}

/* pg_t: u8 version (1), u64 pool, u32 seed, s32 preferred (-1) */
void wrt_mg_walk_pg(wrt_mg_cx *cx, void *e)
{
	wrt_mg_pg *pg = (wrt_mg_pg *)e;
	uint8_t one = 1;
	int32_t pref = -1;

	wrt_mg_cx_u8(cx, &one);
	wrt_mg_cx_u64(cx, &pg->pool);
	wrt_mg_cx_u32(cx, &pg->seed);
	wrt_mg_cx_s32(cx, &pref);
}

void wrt_mg_walk_pair(wrt_mg_cx *cx, void *e)
{
	wrt_mg_pair *p = (wrt_mg_pair *)e;

	wrt_mg_cx_s32(cx, &p->from);
	wrt_mg_cx_s32(cx, &p->to);
}

void wrt_mg_walk_iv(wrt_mg_cx *cx, void *e)
{
	wrt_mg_iv *iv = (wrt_mg_iv *)e;

	wrt_mg_cx_u64(cx, &iv->start);
	wrt_mg_cx_u64(cx, &iv->len);
}

void wrt_mg_walk_kv(wrt_mg_cx *cx, void *e)
{
	wrt_mg_kv *kv = (wrt_mg_kv *)e;

	wrt_mg_cx_str(cx, kv->k, sizeof(kv->k));
	wrt_mg_cx_str(cx, kv->v, sizeof(kv->v));
}

void wrt_mg_walk_str(wrt_mg_cx *cx, void *e)
{
	wrt_mg_cx_str(cx, ((wrt_mg_str *)e)->s, sizeof(((wrt_mg_str *)e)->s));
}

/* ---- addresses ----------------------------------------------------------------------------------------------- */

void wrt_mg_addr_v4(wrt_mg_addr *a, uint32_t type, uint32_t ip, uint16_t port, uint32_t nonce)
{
	memset(a, 0, sizeof(*a));
	a->type = type;
	a->nonce = nonce;
	a->elen = 16;
	a->family = 2;
	a->sa[0] = (uint8_t)(port >> 8);
	a->sa[1] = (uint8_t)port;
	a->sa[2] = (uint8_t)(ip >> 24);
	a->sa[3] = (uint8_t)(ip >> 16);
	a->sa[4] = (uint8_t)(ip >> 8);
	a->sa[5] = (uint8_t)ip;
}

void wrt_mg_addr_v6(wrt_mg_addr *a, uint32_t type, const uint8_t ip[16], uint16_t port, uint32_t nonce)
{
	memset(a, 0, sizeof(*a));
	a->type = type;
	a->nonce = nonce;
	a->elen = 28;
	a->family = 10;
	a->sa[0] = (uint8_t)(port >> 8);
	a->sa[1] = (uint8_t)port;
	memcpy(a->sa + 6, ip, 16);
}

void wrt_mg_addr_blank(wrt_mg_addr *a)
{
	memset(a, 0, sizeof(*a));
	a->elen = 28;
}

void wrt_mg_av_v2v1(wrt_mg_addrvec *av, uint32_t ip, uint16_t port, uint32_t nonce)
{
	memset(av, 0, sizeof(*av));
	av->marker = 2;
	av->n = 2;
	wrt_mg_addr_v4(&av->a[0], 2, ip, port, nonce);
	wrt_mg_addr_v4(&av->a[1], 1, ip, (uint16_t)(port + 1), nonce);
}

void wrt_mg_av_v2(wrt_mg_addrvec *av, uint32_t ip, uint16_t port, uint32_t nonce)
{
	memset(av, 0, sizeof(*av));
	av->marker = 2;
	av->n = 1;
	wrt_mg_addr_v4(&av->a[0], 2, ip, port, nonce);
}

void wrt_mg_av_v1(wrt_mg_addrvec *av, uint32_t ip, uint16_t port, uint32_t nonce)
{
	memset(av, 0, sizeof(*av));
	av->marker = 2;
	av->n = 1;
	wrt_mg_addr_v4(&av->a[0], 1, ip, port, nonce);
}

void wrt_mg_av_v6(wrt_mg_addrvec *av, const uint8_t ip[16], uint16_t port, uint32_t nonce)
{
	memset(av, 0, sizeof(*av));
	av->marker = 2;
	av->n = 2;
	wrt_mg_addr_v6(&av->a[0], 2, ip, port, nonce);
	wrt_mg_addr_v6(&av->a[1], 1, ip, (uint16_t)(port + 1), nonce);
}

void wrt_mg_av_empty(wrt_mg_addrvec *av)
{
	memset(av, 0, sizeof(*av));
	av->marker = 2;
}

void wrt_mg_av_blank(wrt_mg_addrvec *av)
{
	memset(av, 0, sizeof(*av));
	av->marker = 2;
	av->n = 1;
	wrt_mg_addr_blank(&av->a[0]);
}

void wrt_mg_av_legacy(wrt_mg_addrvec *av, uint32_t ip, uint16_t port, uint32_t nonce)
{
	memset(av, 0, sizeof(*av));
	av->marker = 0;
	av->n = 1;
	wrt_mg_addr_v4(&av->a[0], 1, ip, port, nonce);
}

void wrt_mg_addr_str(const wrt_mg_addr *a, char *out, size_t cap)
{
	unsigned port;

	if (cap == 0)
		return;
	out[0] = 0;
	if (a->elen < 2)
		return;
	port = ((unsigned)a->sa[0] << 8) | a->sa[1];
	if (a->family == 2) {
		snprintf(out, cap, "%u.%u.%u.%u:%u", a->sa[2], a->sa[3], a->sa[4], a->sa[5], port);
	} else if (a->family == 10) {
		char g[64];
		int i, k = 0;

		for (i = 0; i < 8; i++)
			k += snprintf(g + k, sizeof(g) - (size_t)k, "%s%x", i ? ":" : "",
				      ((unsigned)a->sa[6 + 2 * i] << 8) | a->sa[7 + 2 * i]);
		snprintf(out, cap, "[%s]:%u", g, port);
	}
}

/* entity_addr_t in the MSG_ADDR2 form: marker 1, envelope (1, 1), type, nonce, elen, family, sockaddr tail. */
static void walk_addr(wrt_mg_cx *cx, void *e)
{
	wrt_mg_addr *a = (wrt_mg_addr *)e;
	uint8_t marker = 1, v = 1, compat = 1;
	uint32_t tail = 0;

	if (cx->mode == WRT_MG_FREE)
		return;
	wrt_mg_cx_u8(cx, &marker);
	if (cx->mode == WRT_MG_DEC && marker != 1) {
		cx->err = 1;
		return;
	}
	wrt_mg_cx_env_begin(cx, &v, &compat);
	wrt_mg_cx_u32(cx, &a->type);
	wrt_mg_cx_u32(cx, &a->nonce);
	wrt_mg_cx_u32(cx, &a->elen);
	if (cx->err)
		return;
	if (a->elen == 1 || a->elen > 28) {
		cx->err = 1;
		return;
	}
	if (a->elen >= 2) {
		wrt_mg_cx_u16(cx, &a->family);
		wrt_mg_cx_bytes(cx, a->sa, a->elen - 2u);
	}
	wrt_mg_cx_env_end(cx, &tail);
}

/* The legacy form after the marker byte: u8 marker2, u16 rest, u32 nonce, 128-byte sockaddr_storage (family big-endian). */
static void walk_legacy(wrt_mg_cx *cx, wrt_mg_addr *a)
{
	uint8_t zero8 = 0, ss[128];
	uint16_t zero16 = 0;

	memset(ss, 0, sizeof(ss));
	wrt_mg_cx_u8(cx, &zero8);
	wrt_mg_cx_u16(cx, &zero16);
	wrt_mg_cx_u32(cx, &a->nonce);
	if (cx->mode == WRT_MG_ENC) {
		ss[0] = (uint8_t)(a->family >> 8);
		ss[1] = (uint8_t)a->family;
		if (a->elen >= 2)
			memcpy(ss + 2, a->sa, a->elen - 2u);
	}
	wrt_mg_cx_bytes(cx, ss, sizeof(ss));
	if (cx->mode == WRT_MG_DEC && !cx->err) {
		a->family = (uint16_t)(((unsigned)ss[0] << 8) | ss[1]);
		if (a->family == 2) {
			a->elen = 16;
			memcpy(a->sa, ss + 2, 14);
			a->type = 1;
		} else if (a->family == 10) {
			a->elen = 28;
			memcpy(a->sa, ss + 2, 26);
			a->type = 1;
		} else {
			a->elen = 28;
			a->type = 0;
		}
	}
}

static void walk_av(wrt_mg_cx *cx, void *e)
{
	wrt_mg_addrvec *av = (wrt_mg_addrvec *)e;
	uint8_t marker = av->marker;
	uint32_t i;

	if (cx->mode == WRT_MG_FREE)
		return;
	if (cx->mode == WRT_MG_DEC) {
		if (!wrt_mg_cx_more(cx)) {
			cx->err = 1;
			return;
		}
		marker = cx->in[cx->pos];
		memset(av, 0, sizeof(*av));
		av->marker = marker;
	}
	switch (marker) {
	case 2:
		wrt_mg_cx_u8(cx, &marker);
		wrt_mg_cx_u32(cx, &av->n);
		if (av->n > WRT_MG_AV_MAX) {
			cx->err = 1;
			return;
		}
		for (i = 0; i < av->n && !cx->err; i++)
			walk_addr(cx, &av->a[i]);
		break;
	case 1:
		av->n = 1;
		walk_addr(cx, &av->a[0]); /* its own marker byte is the vector's */
		break;
	case 0:
		wrt_mg_cx_u8(cx, &marker);
		av->n = 1;
		walk_legacy(cx, &av->a[0]);
		break;
	default:
		cx->err = 1;
		break;
	}
}

int wrt_mg_addrvec_encode(const wrt_mg_addrvec *av, wrt_mg_buf *out)
{
	wrt_mg_cx cx;

	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_ENC;
	cx.out = out;
	walk_av(&cx, (void *)av);
	return cx.err ? -1 : 0;
}

int wrt_mg_addrvec_parse(const uint8_t *p, size_t n, wrt_mg_addrvec *av)
{
	wrt_mg_cx cx;

	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_DEC;
	cx.in = p;
	cx.len = n;
	walk_av(&cx, av);
	return cx.err || cx.pos != n ? -1 : 0;
}

/* ---- pg_pool_t ----------------------------------------------------------------------------------------------- */

static void walk_snap(wrt_mg_cx *cx, void *e)
{
	wrt_mg_snap *s = (wrt_mg_snap *)e;
	uint8_t v = 2, compat = 2;
	uint32_t tail = 0;

	if (cx->mode == WRT_MG_FREE)
		return;
	wrt_mg_cx_u64(cx, &s->id);
	wrt_mg_cx_env_begin(cx, &v, &compat);
	wrt_mg_cx_u64(cx, &s->id);
	wrt_mg_walk_utime(cx, &s->stamp);
	wrt_mg_cx_str(cx, s->name, sizeof(s->name));
	wrt_mg_cx_env_end(cx, &tail);
}

static void walk_app(wrt_mg_cx *cx, void *e)
{
	wrt_mg_app *a = (wrt_mg_app *)e;

	wrt_mg_cx_str(cx, a->app, sizeof(a->app));
	wrt_mg_cx_vec(cx, &a->kv, sizeof(wrt_mg_kv), wrt_mg_walk_kv);
}

static void walk_opt(wrt_mg_cx *cx, void *e)
{
	wrt_mg_opt *o = (wrt_mg_opt *)e;
	int32_t type = 1; /* INT */

	wrt_mg_cx_s32(cx, &o->key);
	wrt_mg_cx_s32(cx, &type);
	if (cx->mode == WRT_MG_DEC && type != 1) {
		cx->err = 1;
		return;
	}
	wrt_mg_cx_s64(cx, &o->val);
}

static void walk_pool(wrt_mg_cx *cx, void *e)
{
	wrt_mg_pool *p = (wrt_mg_pool *)e;
	uint8_t hv = 1, hc = 1, ov = 2, oc = 1, mv = 1, mc = 1;
	uint32_t zero_tail = 0;

	wrt_mg_cx_env_begin(cx, &p->v, &p->compat);
	wrt_mg_cx_u8(cx, &p->type);
	wrt_mg_cx_u8(cx, &p->size);
	wrt_mg_cx_u8(cx, &p->crush_rule);
	wrt_mg_cx_u8(cx, &p->object_hash);
	wrt_mg_cx_u32(cx, &p->pg_num);
	wrt_mg_cx_u32(cx, &p->pgp_num);
	wrt_mg_cx_u32(cx, &p->lpg_num);
	wrt_mg_cx_u32(cx, &p->lpgp_num);
	wrt_mg_cx_u32(cx, &p->last_change);
	wrt_mg_cx_u64(cx, &p->snap_seq);
	wrt_mg_cx_u32(cx, &p->snap_epoch);
	wrt_mg_cx_vec(cx, &p->snaps, sizeof(wrt_mg_snap), walk_snap);
	wrt_mg_cx_vec(cx, &p->removed_snaps, sizeof(wrt_mg_iv), wrt_mg_walk_iv);
	wrt_mg_cx_u64(cx, &p->auid);
	wrt_mg_cx_u64(cx, &p->flags);
	wrt_mg_cx_u32(cx, &p->crash_replay_interval);
	wrt_mg_cx_u8(cx, &p->min_size);
	wrt_mg_cx_u64(cx, &p->quota_max_bytes);
	wrt_mg_cx_u64(cx, &p->quota_max_objects);
	wrt_mg_cx_vec(cx, &p->tiers, sizeof(uint64_t), wrt_mg_walk_u64);
	wrt_mg_cx_s64(cx, &p->tier_of);
	wrt_mg_cx_u8(cx, &p->cache_mode);
	wrt_mg_cx_s64(cx, &p->read_tier);
	wrt_mg_cx_s64(cx, &p->write_tier);
	wrt_mg_cx_vec(cx, &p->properties, sizeof(wrt_mg_kv), wrt_mg_walk_kv);
	wrt_mg_cx_env_begin(cx, &hv, &hc); /* hit_set_params */
	wrt_mg_cx_u8(cx, &p->hit_set_type);
	wrt_mg_cx_env_end(cx, &zero_tail);
	wrt_mg_cx_u32(cx, &p->hit_set_period);
	wrt_mg_cx_u32(cx, &p->hit_set_count);
	wrt_mg_cx_u32(cx, &p->stripe_width);
	wrt_mg_cx_u64(cx, &p->target_max_bytes);
	wrt_mg_cx_u64(cx, &p->target_max_objects);
	wrt_mg_cx_u32(cx, &p->cache_target_dirty_ratio_micro);
	wrt_mg_cx_u32(cx, &p->cache_target_full_ratio_micro);
	wrt_mg_cx_u32(cx, &p->cache_min_flush_age);
	wrt_mg_cx_u32(cx, &p->cache_min_evict_age);
	wrt_mg_cx_str(cx, p->erasure_code_profile, sizeof(p->erasure_code_profile));
	wrt_mg_cx_u32(cx, &p->last_force_op_resend_preluminous);
	wrt_mg_cx_u32(cx, &p->min_read_recency_for_promote);
	wrt_mg_cx_u64(cx, &p->expected_num_objects);
	if (p->v >= 19)
		wrt_mg_cx_u32(cx, &p->cache_target_dirty_high_ratio_micro);
	if (p->v >= 20)
		wrt_mg_cx_u32(cx, &p->min_write_recency_for_promote);
	if (p->v >= 21)
		wrt_mg_cx_u8(cx, &p->use_gmt_hitset);
	if (p->v >= 22)
		wrt_mg_cx_u8(cx, &p->fast_read);
	if (p->v >= 23) {
		wrt_mg_cx_u32(cx, &p->hit_set_grade_decay_rate);
		wrt_mg_cx_u32(cx, &p->hit_set_search_last_n);
	}
	if (p->v >= 24) {
		zero_tail = 0;
		wrt_mg_cx_env_begin(cx, &ov, &oc); /* opts */
		wrt_mg_cx_vec(cx, &p->opts, sizeof(wrt_mg_opt), walk_opt);
		wrt_mg_cx_env_end(cx, &zero_tail);
	}
	if (p->v >= 25)
		wrt_mg_cx_u32(cx, &p->last_force_op_resend_prenautilus);
	if (p->v >= 26)
		wrt_mg_cx_vec(cx, &p->application_metadata, sizeof(wrt_mg_app), walk_app);
	if (p->v >= 27)
		wrt_mg_walk_utime(cx, &p->create_time);
	if (p->v >= 28) {
		wrt_mg_cx_u32(cx, &p->pg_num_target);
		wrt_mg_cx_u32(cx, &p->pgp_num_target);
		wrt_mg_cx_u32(cx, &p->pg_num_pending);
		wrt_mg_cx_u32(cx, &p->pg_num_dec_a);
		wrt_mg_cx_u32(cx, &p->pg_num_dec_b);
		wrt_mg_cx_u32(cx, &p->last_force_op_resend);
		wrt_mg_cx_u8(cx, &p->pg_autoscale_mode);
	}
	if (p->v >= 29) {
		zero_tail = 0;
		wrt_mg_cx_env_begin(cx, &mv, &mc); /* last_pg_merge_meta */
		wrt_mg_cx_bytes(cx, p->merge_meta, sizeof(p->merge_meta));
		wrt_mg_cx_env_end(cx, &zero_tail);
	}
	if (p->v == 30) {
		wrt_mg_cx_u32(cx, &p->stretch_count);
		wrt_mg_cx_u32(cx, &p->stretch_target);
		wrt_mg_cx_u32(cx, &p->stretch_barrier);
		wrt_mg_cx_s32(cx, &p->stretch_mandatory);
	}
	if (p->v >= 31) {
		wrt_mg_cx_u8(cx, &p->peering_present);
		if (p->peering_present) {
			wrt_mg_cx_u32(cx, &p->peering_count);
			wrt_mg_cx_u32(cx, &p->peering_target);
			wrt_mg_cx_u32(cx, &p->peering_barrier);
			wrt_mg_cx_u32(cx, &p->peering_mandatory);
		}
	}
	if (p->v >= 32) {
		wrt_mg_cx_varint(cx, &p->nonprimary_lo);
		wrt_mg_cx_varint(cx, &p->nonprimary_hi);
	}
	wrt_mg_cx_env_end(cx, &p->tail);
}

void wrt_mg_pool_free(wrt_mg_pool *p)
{
	wrt_mg_cx cx;

	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_FREE;
	walk_pool(&cx, p);
	memset(p, 0, sizeof(*p));
}

void wrt_mg_pool_init(wrt_mg_pool *p, uint8_t v)
{
	memset(p, 0, sizeof(*p));
	p->v = v;
	p->compat = 5;
	p->type = 1;
	p->size = 3;
	p->crush_rule = 0;
	p->object_hash = 2;
	p->pg_num = p->pgp_num = 32;
	p->last_change = 1;
	p->flags = WRT_MG_POOL_HASHPSPOOL;
	p->min_size = 2;
	p->tier_of = -1;
	p->read_tier = -1;
	p->write_tier = -1;
	p->use_gmt_hitset = 1;
	p->create_time.sec = 1;
	p->pg_num_target = p->pgp_num_target = p->pg_num_pending = 32;
	p->pg_autoscale_mode = 2;
	p->stretch_mandatory = WRT_MG_NONE;
}

void wrt_mg_pool_shape(wrt_mg_pool *p, int shape)
{
	switch (shape) {
	case WRT_MG_SHAPE_STRETCH:
		p->v = 30;
		p->stretch_count = 2;
		p->stretch_target = 2;
		p->stretch_barrier = 1;
		p->stretch_mandatory = 0;
		break;
	case WRT_MG_SHAPE_STRETCH_V31:
		p->v = 31;
		p->peering_present = 1;
		p->peering_count = 2;
		p->peering_target = 2;
		p->peering_barrier = 1;
		p->peering_mandatory = 0;
		break;
	case WRT_MG_SHAPE_ERASURE:
		p->type = 3;
		p->size = 6;
		p->min_size = 5;
		p->stripe_width = 4096;
		snprintf(p->erasure_code_profile, sizeof(p->erasure_code_profile), "default");
		break;
	case WRT_MG_SHAPE_TIER_OF:
		p->tier_of = 5;
		break;
	case WRT_MG_SHAPE_TIERS:
		WRT_MG_PUSH(p->tiers, uint64_t, 7);
		break;
	case WRT_MG_SHAPE_READ_TIER:
		p->read_tier = 9;
		break;
	case WRT_MG_SHAPE_WRITE_TIER:
		p->write_tier = 9;
		break;
	case WRT_MG_SHAPE_EC_PROFILE:
		snprintf(p->erasure_code_profile, sizeof(p->erasure_code_profile), "myprofile");
		break;
	case WRT_MG_SHAPE_HASH3:
		p->object_hash = 3;
		break;
	case WRT_MG_SHAPE_SIZE0:
		p->size = 0;
		break;
	case WRT_MG_SHAPE_SIZE17:
		p->size = 17;
		break;
	case WRT_MG_SHAPE_PGNUM0:
		p->pg_num = 0;
		break;
	case WRT_MG_SHAPE_PGPNUM0:
		p->pgp_num = 0;
		break;
	case WRT_MG_SHAPE_POOL_SNAPS:
		p->flags |= 1ull << 14;
		break;
	case WRT_MG_SHAPE_EIO:
		p->flags |= 1ull << 16;
		break;
	case WRT_MG_SHAPE_LINUX_HASH:
		p->object_hash = 1;
		break;
	case WRT_MG_SHAPE_NO_HASHPSPOOL:
		p->flags &= ~(uint64_t)WRT_MG_POOL_HASHPSPOOL;
		break;
	default:
		break;
	}
}

int wrt_mg_pool_encode(const wrt_mg_pool *p, wrt_mg_buf *out)
{
	wrt_mg_cx cx;

	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_ENC;
	cx.out = out;
	walk_pool(&cx, (void *)p);
	return cx.err ? -1 : 0;
}

int wrt_mg_pool_parse(const uint8_t *b, size_t n, wrt_mg_pool *p)
{
	wrt_mg_cx cx;

	memset(p, 0, sizeof(*p));
	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_DEC;
	cx.in = b;
	cx.len = n;
	walk_pool(&cx, p);
	if (cx.err || cx.pos != n) {
		wrt_mg_pool_free(p);
		return -1;
	}
	return 0;
}

/* a pool_ent is (s64 id, pool) */
static void walk_pool_ent(wrt_mg_cx *cx, void *e)
{
	wrt_mg_pool_ent *pe = (wrt_mg_pool_ent *)e;

	wrt_mg_cx_s64(cx, &pe->id);
	walk_pool(cx, &pe->p);
}

/* ---- table entry walkers ------------------------------------------------------------------------------------- */

static void walk_osd_u32(wrt_mg_cx *cx, void *e)
{
	wrt_mg_osd_u32 *x = (wrt_mg_osd_u32 *)e;

	wrt_mg_cx_s32(cx, &x->osd);
	wrt_mg_cx_u32(cx, &x->val);
}

static void walk_osd_pair(wrt_mg_cx *cx, void *e)
{
	wrt_mg_osd_pair *x = (wrt_mg_osd_pair *)e;

	wrt_mg_cx_s32(cx, &x->osd);
	wrt_mg_cx_u32(cx, &x->a);
	wrt_mg_cx_u32(cx, &x->b);
}

static void walk_osd_uuid(wrt_mg_cx *cx, void *e)
{
	wrt_mg_cx_bytes(cx, ((wrt_mg_osd_uuid *)e)->uuid, 16); /* inside a map: the bare 16 bytes */
}

static void walk_osd_uuid_keyed(wrt_mg_cx *cx, void *e)
{
	wrt_mg_osd_uuid *x = (wrt_mg_osd_uuid *)e;

	wrt_mg_cx_s32(cx, &x->osd);
	wrt_mg_cx_bytes(cx, x->uuid, 16);
}

static void walk_osd_av(wrt_mg_cx *cx, void *e)
{
	wrt_mg_osd_av *x = (wrt_mg_osd_av *)e;

	wrt_mg_cx_s32(cx, &x->osd);
	walk_av(cx, &x->av);
}

static void walk_xinfo(wrt_mg_cx *cx, wrt_mg_xinfo *x)
{
	uint32_t tail = 0;

	wrt_mg_cx_env_begin(cx, &x->v, &x->compat);
	wrt_mg_walk_utime(cx, &x->down_stamp);
	wrt_mg_cx_u32(cx, &x->laggy_probability);
	wrt_mg_cx_u32(cx, &x->laggy_interval);
	wrt_mg_cx_u64(cx, &x->features);
	wrt_mg_cx_u32(cx, &x->old_weight);
	if (x->v >= 4) {
		wrt_mg_walk_utime(cx, &x->last_purged_snaps_scrub);
		wrt_mg_cx_u32(cx, &x->dead_epoch);
	}
	wrt_mg_cx_env_end(cx, &tail);
}

static void walk_xinfo_elem(wrt_mg_cx *cx, void *e)
{
	walk_xinfo(cx, &((wrt_mg_osd_xinfo *)e)->x);
}

static void walk_osd_xinfo(wrt_mg_cx *cx, void *e)
{
	wrt_mg_osd_xinfo *x = (wrt_mg_osd_xinfo *)e;

	wrt_mg_cx_s32(cx, &x->osd);
	walk_xinfo(cx, &x->x);
}

static void walk_info(wrt_mg_cx *cx, void *e)
{
	wrt_mg_info *i = (wrt_mg_info *)e;
	uint8_t one = 1; /* osd_info_t has a version byte and no envelope */

	wrt_mg_cx_u8(cx, &one);
	wrt_mg_cx_u32(cx, &i->last_clean_begin);
	wrt_mg_cx_u32(cx, &i->last_clean_end);
	wrt_mg_cx_u32(cx, &i->up_from);
	wrt_mg_cx_u32(cx, &i->up_thru);
	wrt_mg_cx_u32(cx, &i->down_at);
	wrt_mg_cx_u32(cx, &i->lost_at);
}

static void walk_pg_list(wrt_mg_cx *cx, void *e)
{
	wrt_mg_pg_list *x = (wrt_mg_pg_list *)e;

	wrt_mg_walk_pg(cx, &x->pg);
	wrt_mg_cx_vec(cx, &x->osds, sizeof(int32_t), wrt_mg_walk_s32);
}

static void walk_pg_items(wrt_mg_cx *cx, void *e)
{
	wrt_mg_pg_items *x = (wrt_mg_pg_items *)e;

	wrt_mg_walk_pg(cx, &x->pg);
	wrt_mg_cx_vec(cx, &x->items, sizeof(wrt_mg_pair), wrt_mg_walk_pair);
}

static void walk_pg_osd(wrt_mg_cx *cx, void *e)
{
	wrt_mg_pg_osd *x = (wrt_mg_pg_osd *)e;

	wrt_mg_walk_pg(cx, &x->pg);
	wrt_mg_cx_s32(cx, &x->osd);
}

static void walk_snapset(wrt_mg_cx *cx, void *e)
{
	wrt_mg_snapset *x = (wrt_mg_snapset *)e;

	wrt_mg_cx_s64(cx, &x->pool);
	wrt_mg_cx_vec(cx, &x->iv, sizeof(wrt_mg_iv), wrt_mg_walk_iv);
}

static void walk_blk(wrt_mg_cx *cx, void *e)
{
	wrt_mg_blk *x = (wrt_mg_blk *)e;

	walk_addr(cx, &x->addr);
	wrt_mg_walk_utime(cx, &x->until);
}

static void walk_addr_elem(wrt_mg_cx *cx, void *e)
{
	walk_addr(cx, e);
}

static void walk_ecprof(wrt_mg_cx *cx, void *e)
{
	wrt_mg_ecprof *x = (wrt_mg_ecprof *)e;

	wrt_mg_cx_str(cx, x->name, sizeof(x->name));
	wrt_mg_cx_vec(cx, &x->kv, sizeof(wrt_mg_kv), wrt_mg_walk_kv);
}

static void walk_pname(wrt_mg_cx *cx, void *e)
{
	wrt_mg_pname *x = (wrt_mg_pname *)e;

	wrt_mg_cx_s64(cx, &x->id);
	wrt_mg_cx_str(cx, x->name, sizeof(x->name));
}

static void walk_pg_elem(wrt_mg_cx *cx, void *e)
{
	wrt_mg_walk_pg(cx, e);
}

/* ---- CRC helpers ----------------------------------------------------------------------------------------------- */

/* osdmap.md 2.4.5: raw CRC-32C, start 0xFFFFFFFF, over [start, field) and then over the bytes after the field. */
static uint32_t wrapper_crc(const uint8_t *p, size_t start, size_t field, size_t end)
{
	uint32_t c = wri_crc32c(0xffffffffu, p + start, field - start);

	return wri_crc32c(c, p + field + 4, end - (field + 4));
}

static void put_u32_at(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/* ---- full map ------------------------------------------------------------------------------------------------ */

static void walk_map(wrt_mg_cx *cx, wrt_mg_map *m)
{
	size_t start = cx->mode == WRT_MG_ENC ? cx->out->len : cx->pos, crc_at = 0;
	uint8_t cv, ov;

	wrt_mg_cx_env_begin(cx, &m->wrapper_v, &m->wrapper_compat);
	wrt_mg_cx_env_begin(cx, &m->client_v, &m->client_compat);
	cv = m->client_v;
	wrt_mg_cx_bytes(cx, m->fsid, 16);
	wrt_mg_cx_u32(cx, &m->epoch);
	wrt_mg_walk_utime(cx, &m->created);
	wrt_mg_walk_utime(cx, &m->modified);
	wrt_mg_cx_vec(cx, &m->pools, sizeof(wrt_mg_pool_ent), walk_pool_ent);
	wrt_mg_cx_vec(cx, &m->pool_names, sizeof(wrt_mg_pname), walk_pname);
	wrt_mg_cx_s32(cx, &m->pool_max);
	wrt_mg_cx_u32(cx, &m->flags);
	wrt_mg_cx_s32(cx, &m->max_osd);
	wrt_mg_cx_vec(cx, &m->osd_state, sizeof(uint32_t), wrt_mg_walk_u32);
	wrt_mg_cx_vec(cx, &m->osd_weight, sizeof(uint32_t), wrt_mg_walk_u32);
	wrt_mg_cx_vec(cx, &m->client_addrs, sizeof(wrt_mg_addrvec), walk_av);
	wrt_mg_cx_vec(cx, &m->pg_temp, sizeof(wrt_mg_pg_list), walk_pg_list);
	wrt_mg_cx_vec(cx, &m->primary_temp, sizeof(wrt_mg_pg_osd), walk_pg_osd);
	wrt_mg_cx_vec(cx, &m->osd_primary_affinity, sizeof(uint32_t), wrt_mg_walk_u32);
	wrt_mg_cx_blob(cx, &m->crush, &m->crush_len);
	wrt_mg_cx_vec(cx, &m->erasure_code_profiles, sizeof(wrt_mg_ecprof), walk_ecprof);
	wrt_mg_cx_vec(cx, &m->pg_upmap, sizeof(wrt_mg_pg_list), walk_pg_list);
	wrt_mg_cx_vec(cx, &m->pg_upmap_items, sizeof(wrt_mg_pg_items), walk_pg_items);
	if (cv >= 6)
		wrt_mg_cx_u32(cx, &m->crush_version);
	if (cv >= 7) {
		wrt_mg_cx_vec(cx, &m->new_removed_snaps, sizeof(wrt_mg_snapset), walk_snapset);
		wrt_mg_cx_vec(cx, &m->new_purged_snaps, sizeof(wrt_mg_snapset), walk_snapset);
	}
	if (cv >= 9) {
		wrt_mg_walk_utime(cx, &m->last_up_change);
		wrt_mg_walk_utime(cx, &m->last_in_change);
	}
	if (cv >= 10)
		wrt_mg_cx_vec(cx, &m->pg_upmap_primaries, sizeof(wrt_mg_pg_osd), walk_pg_osd);
	wrt_mg_cx_env_end(cx, &m->client_tail);

	wrt_mg_cx_env_begin(cx, &m->osd_v, &m->osd_compat);
	ov = m->osd_v;
	wrt_mg_cx_vec(cx, &m->hb_back_addrs, sizeof(wrt_mg_addrvec), walk_av);
	wrt_mg_cx_vec(cx, &m->osd_info, sizeof(wrt_mg_info), walk_info);
	wrt_mg_cx_vec(cx, &m->blocklist, sizeof(wrt_mg_blk), walk_blk);
	wrt_mg_cx_vec(cx, &m->cluster_addrs, sizeof(wrt_mg_addrvec), walk_av);
	wrt_mg_cx_u32(cx, &m->cluster_snapshot_epoch);
	wrt_mg_cx_str(cx, m->cluster_snapshot, sizeof(m->cluster_snapshot));
	wrt_mg_cx_vec(cx, &m->osd_uuid, sizeof(wrt_mg_osd_uuid), walk_osd_uuid);
	wrt_mg_cx_vec(cx, &m->osd_xinfo, sizeof(wrt_mg_osd_xinfo), walk_xinfo_elem);
	wrt_mg_cx_vec(cx, &m->hb_front_addrs, sizeof(wrt_mg_addrvec), walk_av);
	if (ov >= 2) {
		wrt_mg_cx_u32(cx, &m->nearfull_bits);
		wrt_mg_cx_u32(cx, &m->full_bits);
	}
	if (ov >= 3)
		wrt_mg_cx_u32(cx, &m->backfillfull_bits);
	if (ov >= 5) {
		wrt_mg_cx_u8(cx, &m->require_min_compat_client);
		wrt_mg_cx_u8(cx, &m->require_osd_release);
	}
	if (ov >= 6)
		wrt_mg_cx_vec(cx, &m->removed_snaps_queue, sizeof(wrt_mg_snapset), walk_snapset);
	if (ov >= 8)
		wrt_mg_cx_vec(cx, &m->crush_node_flags, sizeof(wrt_mg_osd_u32), walk_osd_u32);
	if (ov >= 9)
		wrt_mg_cx_vec(cx, &m->device_class_flags, sizeof(wrt_mg_osd_u32), walk_osd_u32);
	if (ov >= 10) {
		wrt_mg_cx_u8(cx, &m->stretch_mode_enabled);
		wrt_mg_cx_u32(cx, &m->stretch_bucket_count);
		wrt_mg_cx_u32(cx, &m->degraded_stretch_mode);
		wrt_mg_cx_u32(cx, &m->recovering_stretch_mode);
		wrt_mg_cx_s32(cx, &m->stretch_mode_bucket);
	}
	if (ov >= 11)
		wrt_mg_cx_vec(cx, &m->range_blocklist, sizeof(wrt_mg_blk), walk_blk);
	if (ov >= 12)
		wrt_mg_cx_u8(cx, &m->allow_crimson);
	wrt_mg_cx_env_end(cx, &m->osd_tail);

	if (m->wrapper_v >= 8) {
		crc_at = cx->mode == WRT_MG_ENC ? cx->out->len : cx->pos;
		if (cx->mode == WRT_MG_ENC && m->crc_override)
			wrt_mg_cx_u32(cx, &m->crc);
		else if (cx->mode == WRT_MG_ENC) {
			uint32_t zero = 0;

			wrt_mg_cx_u32(cx, &zero);
		} else {
			wrt_mg_cx_u32(cx, &m->crc);
		}
	}
	wrt_mg_cx_env_end(cx, &m->wrapper_tail);
	if (m->wrapper_v >= 8 && !cx->err) {
		if (cx->mode == WRT_MG_ENC) {
			if (!m->crc_override)
				put_u32_at(cx->out->p + crc_at, wrapper_crc(cx->out->p, start, crc_at, cx->out->len));
		} else if (cx->mode == WRT_MG_DEC) {
			m->crc_ok = wrapper_crc(cx->in, start, crc_at, cx->pos) == m->crc;
		}
	}
}

void wrt_mg_map_init(wrt_mg_map *m)
{
	memset(m, 0, sizeof(*m));
	m->wrapper_v = 8;
	m->wrapper_compat = 7;
	m->client_v = 10;
	m->client_compat = 1;
	m->osd_v = 9;
	m->osd_compat = 1;
	m->epoch = 1;
	{
		static const uint8_t fsid[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
						 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

		memcpy(m->fsid, fsid, 16);
	}
	m->flags = 0x588000u; /* SORTBITWISE | RECOVERY_DELETES | PURGED_SNAPDIRS | PGLOG_HARDLIMIT: a tentacle cluster */
	m->pool_max = 0;
	m->nearfull_bits = 0x3f59999au;     /* 0.85f */
	m->full_bits = 0x3f733333u;         /* 0.95f */
	m->backfillfull_bits = 0x3f666666u; /* 0.9f */
	m->require_min_compat_client = 16;
	m->require_osd_release = 20;
	m->stretch_mode_bucket = 0;
}

void wrt_mg_map_free(wrt_mg_map *m)
{
	wrt_mg_cx cx;

	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_FREE;
	walk_map(&cx, m);
	free(m->crush);
	memset(m, 0, sizeof(*m));
}

int wrt_mg_map_encode(const wrt_mg_map *m, wrt_mg_buf *out)
{
	wrt_mg_cx cx;

	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_ENC;
	cx.out = out;
	walk_map(&cx, (wrt_mg_map *)m);
	return cx.err ? -1 : 0;
}

int wrt_mg_map_parse(const uint8_t *p, size_t n, wrt_mg_map *m)
{
	wrt_mg_cx cx;

	memset(m, 0, sizeof(*m));
	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_DEC;
	cx.in = p;
	cx.len = n;
	walk_map(&cx, m);
	if (cx.err || cx.pos != n) {
		wrt_mg_map_free(m);
		return -1;
	}
	return 0;
}

int wrt_mg_map_clone(const wrt_mg_map *src, wrt_mg_map *dst)
{
	wrt_mg_buf b;
	int rc;

	memset(&b, 0, sizeof(b));
	wrt_mg_map_encode(src, &b);
	rc = wrt_mg_map_parse(b.p, b.len, dst);
	wrt_mg_buf_free(&b);
	return rc;
}

void wrt_mg_map_set_crush(wrt_mg_map *m, const wrt_mg_crush *c)
{
	wrt_mg_buf b;

	memset(&b, 0, sizeof(b));
	wrt_mg_crush_encode(c, &b);
	free(m->crush);
	m->crush = b.p; /* ownership moves */
	m->crush_len = (uint32_t)b.len;
}

/* ---- sorted table setters ---------------------------------------------------------------------------------- */

static int pg_cmp(wrt_mg_pg a, wrt_mg_pg b)
{
	if (a.pool != b.pool)
		return a.pool < b.pool ? -1 : 1;
	return a.seed < b.seed ? -1 : a.seed > b.seed;
}

/* The slot of key `pg` in a vector whose elements start with a wrt_mg_pg: *found tells whether it is there. */
static uint32_t pg_slot(const wrt_mg_vec *v, size_t esz, wrt_mg_pg pg, int *found)
{
	uint32_t lo = 0, hi = v->n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2;
		wrt_mg_pg k;
		int c;

		memcpy(&k, (const uint8_t *)v->v + (size_t)mid * esz, sizeof(k));
		c = pg_cmp(k, pg);
		if (c < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	*found = 0;
	if (lo < v->n) {
		wrt_mg_pg k;

		memcpy(&k, (const uint8_t *)v->v + (size_t)lo * esz, sizeof(k));
		*found = pg_cmp(k, pg) == 0;
	}
	return lo;
}

static void insert_at(wrt_mg_vec *v, size_t esz, uint32_t at, const void *elem)
{
	wrt_mg_vec_grow_(v, esz);
	memmove((uint8_t *)v->v + ((size_t)at + 1) * esz, (uint8_t *)v->v + (size_t)at * esz, ((size_t)v->n - at) * esz);
	memcpy((uint8_t *)v->v + (size_t)at * esz, elem, esz);
	v->n++;
}

void wrt_mg_map_set_pg_temp(wrt_mg_map *m, wrt_mg_pg pg, const int32_t *osds, uint32_t n)
{
	wrt_mg_pg_list e;
	int found;
	uint32_t at = pg_slot(&m->pg_temp, sizeof(e), pg, &found);

	memset(&e, 0, sizeof(e));
	e.pg = pg;
	wrt_mg_vec_resize0(&e.osds, sizeof(int32_t), n);
	if (n)
		memcpy(e.osds.v, osds, n * sizeof(int32_t));
	if (found) {
		free(WRT_MG_E(m->pg_temp, wrt_mg_pg_list, at).osds.v);
		WRT_MG_E(m->pg_temp, wrt_mg_pg_list, at) = e;
	} else {
		insert_at(&m->pg_temp, sizeof(e), at, &e);
	}
}

void wrt_mg_map_set_primary_temp(wrt_mg_map *m, wrt_mg_pg pg, int32_t osd)
{
	wrt_mg_pg_osd e;
	int found;
	uint32_t at = pg_slot(&m->primary_temp, sizeof(e), pg, &found);

	e.pg = pg;
	e.osd = osd;
	if (found)
		WRT_MG_E(m->primary_temp, wrt_mg_pg_osd, at) = e;
	else
		insert_at(&m->primary_temp, sizeof(e), at, &e);
}

void wrt_mg_map_set_pg_upmap(wrt_mg_map *m, wrt_mg_pg pg, const int32_t *osds, uint32_t n)
{
	wrt_mg_pg_list e;
	int found;
	uint32_t at = pg_slot(&m->pg_upmap, sizeof(e), pg, &found);

	memset(&e, 0, sizeof(e));
	e.pg = pg;
	wrt_mg_vec_resize0(&e.osds, sizeof(int32_t), n);
	if (n)
		memcpy(e.osds.v, osds, n * sizeof(int32_t));
	if (found) {
		free(WRT_MG_E(m->pg_upmap, wrt_mg_pg_list, at).osds.v);
		WRT_MG_E(m->pg_upmap, wrt_mg_pg_list, at) = e;
	} else {
		insert_at(&m->pg_upmap, sizeof(e), at, &e);
	}
}

void wrt_mg_map_set_pg_upmap_items(wrt_mg_map *m, wrt_mg_pg pg, const wrt_mg_pair *items, uint32_t n)
{
	wrt_mg_pg_items e;
	int found;
	uint32_t at = pg_slot(&m->pg_upmap_items, sizeof(e), pg, &found);

	memset(&e, 0, sizeof(e));
	e.pg = pg;
	wrt_mg_vec_resize0(&e.items, sizeof(wrt_mg_pair), n);
	if (n)
		memcpy(e.items.v, items, n * sizeof(wrt_mg_pair));
	if (found) {
		free(WRT_MG_E(m->pg_upmap_items, wrt_mg_pg_items, at).items.v);
		WRT_MG_E(m->pg_upmap_items, wrt_mg_pg_items, at) = e;
	} else {
		insert_at(&m->pg_upmap_items, sizeof(e), at, &e);
	}
}

void wrt_mg_map_set_upmap_primary(wrt_mg_map *m, wrt_mg_pg pg, int32_t osd)
{
	wrt_mg_pg_osd e;
	int found;
	uint32_t at = pg_slot(&m->pg_upmap_primaries, sizeof(e), pg, &found);

	e.pg = pg;
	e.osd = osd;
	if (found)
		WRT_MG_E(m->pg_upmap_primaries, wrt_mg_pg_osd, at) = e;
	else
		insert_at(&m->pg_upmap_primaries, sizeof(e), at, &e);
}

static uint32_t id_slot(const wrt_mg_vec *v, size_t esz, int64_t id, int *found)
{
	uint32_t i;

	*found = 0;
	for (i = 0; i < v->n; i++) {
		int64_t k;

		memcpy(&k, (const uint8_t *)v->v + (size_t)i * esz, sizeof(k));
		if (k == id) {
			*found = 1;
			return i;
		}
		if (k > id)
			return i;
	}
	return v->n;
}

void wrt_mg_map_add_pool(wrt_mg_map *m, int64_t id, const char *name, const wrt_mg_pool *p)
{
	wrt_mg_pool_ent pe;
	wrt_mg_pname pn;
	wrt_mg_buf b;
	int found;
	uint32_t at;

	/* copy the pool through its wire form so the caller keeps ownership of its own vectors */
	memset(&b, 0, sizeof(b));
	wrt_mg_pool_encode(p, &b);
	pe.id = id;
	if (wrt_mg_pool_parse(b.p, b.len, &pe.p) != 0)
		abort();
	wrt_mg_buf_free(&b);
	at = id_slot(&m->pools, sizeof(pe), id, &found);
	if (found) {
		wrt_mg_pool_free(&WRT_MG_E(m->pools, wrt_mg_pool_ent, at).p);
		WRT_MG_E(m->pools, wrt_mg_pool_ent, at) = pe;
	} else {
		insert_at(&m->pools, sizeof(pe), at, &pe);
	}
	memset(&pn, 0, sizeof(pn));
	pn.id = id;
	snprintf(pn.name, sizeof(pn.name), "%s", name ? name : "");
	at = id_slot(&m->pool_names, sizeof(pn), id, &found);
	if (found)
		WRT_MG_E(m->pool_names, wrt_mg_pname, at) = pn;
	else
		insert_at(&m->pool_names, sizeof(pn), at, &pn);
	if (id > m->pool_max)
		m->pool_max = (int32_t)id;
}

const wrt_mg_pool *wrt_mg_map_pool(const wrt_mg_map *m, int64_t id)
{
	uint32_t i;

	for (i = 0; i < m->pools.n; i++)
		if (WRT_MG_E(m->pools, wrt_mg_pool_ent, i).id == id)
			return &WRT_MG_E(m->pools, wrt_mg_pool_ent, i).p;
	return NULL;
}

void wrt_mg_map_resize(wrt_mg_map *m, int32_t n)
{
	uint32_t old, u = n < 0 ? 0u : (uint32_t)n, i;
	wrt_mg_addrvec empty;
	wrt_mg_osd_xinfo xi;
	wrt_mg_osd_uuid uu;

	wrt_mg_av_empty(&empty);
	memset(&xi, 0, sizeof(xi));
	xi.x.v = 4;
	xi.x.compat = 1;
	memset(&uu, 0, sizeof(uu));
	wrt_mg_vec_resize0(&m->osd_state, sizeof(uint32_t), u);
	old = m->osd_weight.n;
	wrt_mg_vec_resize0(&m->osd_weight, sizeof(uint32_t), u);
	(void)old;
	if (m->osd_primary_affinity.n) {
		old = m->osd_primary_affinity.n;
		wrt_mg_vec_resize0(&m->osd_primary_affinity, sizeof(uint32_t), u);
		for (i = old; i < u; i++)
			WRT_MG_E(m->osd_primary_affinity, uint32_t, i) = WRT_MG_W_IN;
	}
	{
		wrt_mg_vec *avs[4];
		unsigned k;

		avs[0] = &m->client_addrs;
		avs[1] = &m->hb_back_addrs;
		avs[2] = &m->cluster_addrs;
		avs[3] = &m->hb_front_addrs;
		for (k = 0; k < 4; k++) {
			old = avs[k]->n;
			wrt_mg_vec_resize0(avs[k], sizeof(wrt_mg_addrvec), u);
			for (i = old; i < u; i++)
				WRT_MG_E(*avs[k], wrt_mg_addrvec, i) = empty;
		}
	}
	wrt_mg_vec_resize0(&m->osd_info, sizeof(wrt_mg_info), u);
	wrt_mg_vec_resize0(&m->osd_uuid, sizeof(wrt_mg_osd_uuid), u);
	old = m->osd_xinfo.n;
	wrt_mg_vec_resize0(&m->osd_xinfo, sizeof(wrt_mg_osd_xinfo), u);
	for (i = old; i < u; i++)
		WRT_MG_E(m->osd_xinfo, wrt_mg_osd_xinfo, i) = xi;
	m->max_osd = n;
}

/* ---- Incremental ---------------------------------------------------------------------------------------------- */

static void walk_inc(wrt_mg_cx *cx, wrt_mg_inc *d)
{
	size_t start = cx->mode == WRT_MG_ENC ? cx->out->len : cx->pos, crc_at = 0;
	uint8_t cv, ov;

	wrt_mg_cx_env_begin(cx, &d->wrapper_v, &d->wrapper_compat);
	wrt_mg_cx_env_begin(cx, &d->client_v, &d->client_compat);
	cv = d->client_v;
	wrt_mg_cx_bytes(cx, d->fsid, 16);
	wrt_mg_cx_u32(cx, &d->epoch);
	wrt_mg_walk_utime(cx, &d->modified);
	wrt_mg_cx_s64(cx, &d->new_pool_max);
	wrt_mg_cx_s32(cx, &d->new_flags);
	wrt_mg_cx_blob(cx, &d->fullmap, &d->fullmap_len);
	wrt_mg_cx_blob(cx, &d->crush, &d->crush_len);
	wrt_mg_cx_s32(cx, &d->new_max_osd);
	wrt_mg_cx_vec(cx, &d->new_pools, sizeof(wrt_mg_pool_ent), walk_pool_ent);
	wrt_mg_cx_vec(cx, &d->new_pool_names, sizeof(wrt_mg_pname), walk_pname);
	wrt_mg_cx_vec(cx, &d->old_pools, sizeof(int64_t), wrt_mg_walk_s64);
	wrt_mg_cx_vec(cx, &d->new_up_client, sizeof(wrt_mg_osd_av), walk_osd_av);
	wrt_mg_cx_vec(cx, &d->new_state, sizeof(wrt_mg_osd_u32), walk_osd_u32);
	wrt_mg_cx_vec(cx, &d->new_weight, sizeof(wrt_mg_osd_u32), walk_osd_u32);
	wrt_mg_cx_vec(cx, &d->new_pg_temp, sizeof(wrt_mg_pg_list), walk_pg_list);
	wrt_mg_cx_vec(cx, &d->new_primary_temp, sizeof(wrt_mg_pg_osd), walk_pg_osd);
	wrt_mg_cx_vec(cx, &d->new_primary_affinity, sizeof(wrt_mg_osd_u32), walk_osd_u32);
	wrt_mg_cx_vec(cx, &d->new_erasure_code_profiles, sizeof(wrt_mg_ecprof), walk_ecprof);
	wrt_mg_cx_vec(cx, &d->old_erasure_code_profiles, sizeof(wrt_mg_str), wrt_mg_walk_str);
	if (cv >= 4) {
		wrt_mg_cx_vec(cx, &d->new_pg_upmap, sizeof(wrt_mg_pg_list), walk_pg_list);
		wrt_mg_cx_vec(cx, &d->old_pg_upmap, sizeof(wrt_mg_pg), walk_pg_elem);
		wrt_mg_cx_vec(cx, &d->new_pg_upmap_items, sizeof(wrt_mg_pg_items), walk_pg_items);
		wrt_mg_cx_vec(cx, &d->old_pg_upmap_items, sizeof(wrt_mg_pg), walk_pg_elem);
	}
	if (cv >= 6) {
		wrt_mg_cx_vec(cx, &d->new_removed_snaps, sizeof(wrt_mg_snapset), walk_snapset);
		wrt_mg_cx_vec(cx, &d->new_purged_snaps, sizeof(wrt_mg_snapset), walk_snapset);
	}
	if (cv >= 8) {
		wrt_mg_walk_utime(cx, &d->new_last_up_change);
		wrt_mg_walk_utime(cx, &d->new_last_in_change);
	}
	if (cv >= 9) {
		wrt_mg_cx_vec(cx, &d->new_pg_upmap_primary, sizeof(wrt_mg_pg_osd), walk_pg_osd);
		wrt_mg_cx_vec(cx, &d->old_pg_upmap_primary, sizeof(wrt_mg_pg), walk_pg_elem);
	}
	wrt_mg_cx_env_end(cx, &d->client_tail);

	wrt_mg_cx_env_begin(cx, &d->osd_v, &d->osd_compat);
	ov = d->osd_v;
	wrt_mg_cx_vec(cx, &d->new_hb_back_up, sizeof(wrt_mg_osd_av), walk_osd_av);
	wrt_mg_cx_vec(cx, &d->new_up_thru, sizeof(wrt_mg_osd_u32), walk_osd_u32);
	wrt_mg_cx_vec(cx, &d->new_last_clean_interval, sizeof(wrt_mg_osd_pair), walk_osd_pair);
	wrt_mg_cx_vec(cx, &d->new_lost, sizeof(wrt_mg_osd_u32), walk_osd_u32);
	wrt_mg_cx_vec(cx, &d->new_blocklist, sizeof(wrt_mg_blk), walk_blk);
	wrt_mg_cx_vec(cx, &d->old_blocklist, sizeof(wrt_mg_addr), walk_addr_elem);
	wrt_mg_cx_vec(cx, &d->new_up_cluster, sizeof(wrt_mg_osd_av), walk_osd_av);
	wrt_mg_cx_str(cx, d->cluster_snapshot, sizeof(d->cluster_snapshot));
	wrt_mg_cx_vec(cx, &d->new_uuid, sizeof(wrt_mg_osd_uuid), walk_osd_uuid_keyed);
	wrt_mg_cx_vec(cx, &d->new_xinfo, sizeof(wrt_mg_osd_xinfo), walk_osd_xinfo);
	wrt_mg_cx_vec(cx, &d->new_hb_front_up, sizeof(wrt_mg_osd_av), walk_osd_av);
	wrt_mg_cx_u64(cx, &d->features);
	if (ov >= 3) {
		wrt_mg_cx_u32(cx, &d->new_nearfull_bits);
		wrt_mg_cx_u32(cx, &d->new_full_bits);
		wrt_mg_cx_u32(cx, &d->new_backfillfull_bits);
	}
	if (ov >= 6) {
		wrt_mg_cx_u8(cx, &d->new_require_min_compat_client);
		wrt_mg_cx_u8(cx, &d->new_require_osd_release);
	}
	if (ov >= 8)
		wrt_mg_cx_vec(cx, &d->new_crush_node_flags, sizeof(wrt_mg_osd_u32), walk_osd_u32);
	if (ov >= 9)
		wrt_mg_cx_vec(cx, &d->new_device_class_flags, sizeof(wrt_mg_osd_u32), walk_osd_u32);
	if (ov >= 10) {
		wrt_mg_cx_u8(cx, &d->change_stretch_mode);
		wrt_mg_cx_u32(cx, &d->new_stretch_bucket_count);
		wrt_mg_cx_u32(cx, &d->new_degraded_stretch_mode);
		wrt_mg_cx_u32(cx, &d->new_recovering_stretch_mode);
		wrt_mg_cx_s32(cx, &d->new_stretch_mode_bucket);
		wrt_mg_cx_u8(cx, &d->stretch_mode_enabled);
	}
	if (ov >= 11) {
		wrt_mg_cx_vec(cx, &d->new_range_blocklist, sizeof(wrt_mg_blk), walk_blk);
		wrt_mg_cx_vec(cx, &d->old_range_blocklist, sizeof(wrt_mg_addr), walk_addr_elem);
	}
	if (ov >= 12)
		wrt_mg_cx_u8(cx, &d->mutate_allow_crimson);
	wrt_mg_cx_env_end(cx, &d->osd_tail);

	if (d->wrapper_v >= 8) {
		crc_at = cx->mode == WRT_MG_ENC ? cx->out->len : cx->pos;
		if (cx->mode == WRT_MG_ENC) {
			uint32_t zero = 0;

			wrt_mg_cx_u32(cx, d->inc_crc_override ? &d->inc_crc : &zero);
		} else {
			wrt_mg_cx_u32(cx, &d->inc_crc);
		}
		wrt_mg_cx_u32(cx, &d->full_crc);
	}
	wrt_mg_cx_env_end(cx, &d->wrapper_tail);
	if (d->wrapper_v >= 8 && !cx->err) {
		if (cx->mode == WRT_MG_ENC) {
			if (!d->inc_crc_override)
				put_u32_at(cx->out->p + crc_at, wrapper_crc(cx->out->p, start, crc_at, cx->out->len));
		} else if (cx->mode == WRT_MG_DEC) {
			d->inc_crc_ok = wrapper_crc(cx->in, start, crc_at, cx->pos) == d->inc_crc;
		}
	}
}

void wrt_mg_inc_init(wrt_mg_inc *d, const uint8_t fsid[16], uint32_t epoch)
{
	memset(d, 0, sizeof(*d));
	d->wrapper_v = 8;
	d->wrapper_compat = 7;
	d->client_v = 9;
	d->client_compat = 1;
	d->osd_v = 9;
	d->osd_compat = 1;
	memcpy(d->fsid, fsid, 16);
	d->epoch = epoch;
	d->new_pool_max = -1;
	d->new_flags = -1;
	d->new_max_osd = -1;
	d->features = WRT_MG_FEATURES_ALL;
	d->new_nearfull_bits = d->new_full_bits = d->new_backfillfull_bits = 0xbf800000u; /* -1.0f */
	d->new_require_min_compat_client = 0xff;
	d->new_require_osd_release = 0xff;
}

void wrt_mg_inc_free(wrt_mg_inc *d)
{
	wrt_mg_cx cx;

	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_FREE;
	walk_inc(&cx, d);
	memset(d, 0, sizeof(*d));
}

int wrt_mg_inc_encode(const wrt_mg_inc *d, wrt_mg_buf *out)
{
	wrt_mg_cx cx;

	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_ENC;
	cx.out = out;
	walk_inc(&cx, (wrt_mg_inc *)d);
	return cx.err ? -1 : 0;
}

int wrt_mg_inc_parse(const uint8_t *p, size_t n, wrt_mg_inc *d)
{
	wrt_mg_cx cx;

	memset(d, 0, sizeof(*d));
	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_DEC;
	cx.in = p;
	cx.len = n;
	walk_inc(&cx, d);
	if (cx.err || cx.pos != n) {
		wrt_mg_inc_free(d);
		return -1;
	}
	return 0;
}

static uint32_t le32_at(const uint8_t *p);

/* The full_crc of an incremental that embeds a map is the CRC that map carries. */
void wrt_mg_inc_set_fullmap(wrt_mg_inc *d, const wrt_mg_map *m)
{
	wrt_mg_buf b;

	memset(&b, 0, sizeof(b));
	wrt_mg_map_encode(m, &b);
	free(d->fullmap);
	d->fullmap = b.p;
	d->fullmap_len = (uint32_t)b.len;
	{
		/* the CRC field sits right after the OSD-only block (a wrapper tail, if any, follows it) */
		wrt_mg_layout l;

		if (m->wrapper_v >= 8 && wrt_mg_wrapper_layout(b.p, b.len, &l) == 0 && l.osd_end + 4 <= l.wrapper_end)
			d->full_crc = le32_at(b.p + l.osd_end);
	}
}

void wrt_mg_inc_set_crush(wrt_mg_inc *d, const wrt_mg_crush *c)
{
	wrt_mg_buf b;

	memset(&b, 0, sizeof(b));
	wrt_mg_crush_encode(c, &b);
	free(d->crush);
	d->crush = b.p;
	d->crush_len = (uint32_t)b.len;
}

/* Insert into an osd-keyed vector keeping it ascending; an existing key is replaced. */
static void osd_u32_put(wrt_mg_vec *v, int32_t osd, uint32_t val)
{
	wrt_mg_osd_u32 e;
	uint32_t i;

	e.osd = osd;
	e.val = val;
	for (i = 0; i < v->n; i++) {
		if (WRT_MG_E(*v, wrt_mg_osd_u32, i).osd == osd) {
			WRT_MG_E(*v, wrt_mg_osd_u32, i) = e;
			return;
		}
		if (WRT_MG_E(*v, wrt_mg_osd_u32, i).osd > osd)
			break;
	}
	insert_at(v, sizeof(e), i, &e);
}

static void osd_av_put(wrt_mg_vec *v, int32_t osd, const wrt_mg_addrvec *av)
{
	wrt_mg_osd_av e;
	uint32_t i;

	e.osd = osd;
	e.av = *av;
	for (i = 0; i < v->n; i++) {
		if (WRT_MG_E(*v, wrt_mg_osd_av, i).osd == osd) {
			WRT_MG_E(*v, wrt_mg_osd_av, i) = e;
			return;
		}
		if (WRT_MG_E(*v, wrt_mg_osd_av, i).osd > osd)
			break;
	}
	insert_at(v, sizeof(e), i, &e);
}

void wrt_mg_inc_mark_down(wrt_mg_inc *d, int32_t osd)
{
	osd_u32_put(&d->new_state, osd, WRT_MG_OSD_UP);
}

void wrt_mg_inc_mark_up(wrt_mg_inc *d, int32_t osd, const wrt_mg_addrvec *client)
{
	osd_av_put(&d->new_up_client, osd, client);
	osd_av_put(&d->new_hb_back_up, osd, client);
	osd_av_put(&d->new_up_cluster, osd, client);
	osd_av_put(&d->new_hb_front_up, osd, client);
}

void wrt_mg_inc_set_weight(wrt_mg_inc *d, int32_t osd, uint32_t w)
{
	osd_u32_put(&d->new_weight, osd, w);
}

void wrt_mg_inc_set_affinity(wrt_mg_inc *d, int32_t osd, uint32_t a)
{
	osd_u32_put(&d->new_primary_affinity, osd, a);
}

/* ---- layout helpers for tests that patch bytes ------------------------------------------------------------------ */

static uint32_t le32_at(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int wrt_mg_wrapper_layout(const uint8_t *p, size_t n, wrt_mg_layout *o)
{
	wrt_mg_layout l;

	if (n < 6 + 6 + 6)
		return -1;
	l.wrapper_end = 6 + (size_t)le32_at(p + 2);
	l.client_off = 6;
	l.client_body = 12;
	l.client_end = l.client_body + (size_t)le32_at(p + 8);
	if (l.wrapper_end > n || l.client_end + 6 > l.wrapper_end)
		return -1;
	l.osd_off = l.client_end;
	l.osd_body = l.osd_off + 6;
	l.osd_end = l.osd_body + (size_t)le32_at(p + l.osd_off + 2);
	if (l.osd_end > l.wrapper_end)
		return -1;
	*o = l;
	return 0;
}

int wrt_mg_fix_crc(uint8_t *p, size_t n, int is_inc)
{
	wrt_mg_layout l;

	(void)is_inc; /* the field starts at osd_end in both; only that CRC is recomputed */
	if (wrt_mg_wrapper_layout(p, n, &l) != 0 || p[0] < 8 || l.osd_end + 4 > l.wrapper_end)
		return -1;
	put_u32_at(p + l.osd_end, wrapper_crc(p, 0, l.osd_end, l.wrapper_end));
	return 0;
}

/* ---- MOSDMap front ------------------------------------------------------------------------------------------- */

static void put32(wrt_mg_buf *b, uint32_t v)
{
	uint8_t x[4];

	put_u32_at(x, v);
	wrt_mg_buf_put(b, x, 4);
}

int wrt_mg_mosdmap_front(wrt_mg_buf *out, const uint8_t fsid[16], const wrt_mg_mitem *items, uint32_t nitems,
			 uint32_t oldest, uint32_t newest, int hv, uint32_t ngaps)
{
	uint32_t i, k, cnt;

	wrt_mg_buf_put(out, fsid, 16);
	for (k = 0; k < 2; k++) { /* k == 0: incrementals, k == 1: full maps */
		cnt = 0;
		for (i = 0; i < nitems; i++)
			cnt += items[i].is_full == (int)k;
		put32(out, cnt);
		for (i = 0; i < nitems; i++) {
			if (items[i].is_full != (int)k)
				continue;
			put32(out, items[i].epoch);
			put32(out, (uint32_t)items[i].n);
			wrt_mg_buf_put(out, items[i].p, items[i].n);
		}
	}
	if (hv >= 2) {
		put32(out, oldest);
		put32(out, newest);
	}
	if (hv >= 4) {
		put32(out, ngaps);
		for (i = 0; i < ngaps; i++) {
			uint8_t pool[8], iv[16];

			memset(pool, 0, sizeof(pool));
			pool[0] = (uint8_t)(i + 1);
			wrt_mg_buf_put(out, pool, 8);
			put32(out, 1);
			memset(iv, 0, sizeof(iv));
			iv[0] = 1;
			iv[8] = 1;
			wrt_mg_buf_put(out, iv, 16);
		}
	}
	return 0;
}

/* ---- cluster builder ----------------------------------------------------------------------------------------- */

void wrt_mg_cluster_spec_init(wrt_mg_cluster_spec *s, uint32_t n_osds)
{
	memset(s, 0, sizeof(*s));
	s->n_osds = n_osds;
	s->osds_per_host = 4;
	s->bucket_alg = WRT_MG_ALG_STRAW2;
	s->dev_weight = WRT_MG_W_IN;
	s->tunables = WRT_MG_TUN_JEWEL;
	s->crush_upto = WRT_MG_UPTO_CARGS;
	s->n_pools = 1;
	s->pg_num = 32;
	s->pool_size = 3;
	s->up_pct = 100;
	s->epoch = 1;
	s->seed = 1;
}

static int cmp_pg_key(const void *a, const void *b)
{
	return pg_cmp(*(const wrt_mg_pg *)a, *(const wrt_mg_pg *)b);
}

/* n distinct PGs of pool 1, ascending (fewer if the pool is too small). */
static uint32_t pick_pgs(wrt_mg_rng *r, uint32_t pg_num, uint32_t n, wrt_mg_pg *out)
{
	uint32_t i, k = 0;

	if (n > pg_num)
		n = pg_num;
	for (i = 0; i < n; i++) {
		out[i].pool = 1;
		out[i].seed = wrt_mg_rng_below(r, pg_num);
	}
	if (n > 1)
		qsort(out, n, sizeof(out[0]), cmp_pg_key);
	for (i = 0; i < n; i++)
		if (k == 0 || pg_cmp(out[k - 1], out[i]) != 0)
			out[k++] = out[i];
	return k;
}

int wrt_mg_build_map(wrt_mg_map *m, const wrt_mg_cluster_spec *s)
{
	wrt_mg_rng r;
	wrt_mg_crush c;
	uint32_t n = s->n_osds, i, k, pg_num = s->pg_num ? s->pg_num : 32, epoch = s->epoch ? s->epoch : 1;
	uint32_t size = s->pool_size ? s->pool_size : 3;
	wrt_mg_pg *keys;
	int32_t lst[WRT_MG_MAX_REPL];

	wrt_mg_rng_seed(&r, s->seed);
	wrt_mg_map_init(m);
	m->epoch = epoch;
	m->created.sec = 1700000000u;
	m->modified.sec = 1700000000u + epoch;
	if (wrt_mg_build_crush(&c, s) != 0)
		return -1;
	wrt_mg_map_set_crush(m, &c);
	wrt_mg_crush_free(&c);
	m->crush_version = 1 + epoch / 2;
	for (k = 1; k <= (s->n_pools ? s->n_pools : 0); k++) {
		wrt_mg_pool p;
		char nm[32];

		wrt_mg_pool_init(&p, 32);
		p.size = (uint8_t)size;
		p.min_size = (uint8_t)(size > 1 ? size - 1 : 1);
		p.pg_num = p.pgp_num = p.pg_num_target = p.pgp_num_target = p.pg_num_pending = pg_num;
		p.flags |= 1ull << 13; /* selfmanaged snaps, as an RBD pool */
		p.last_change = epoch;
		p.last_force_op_resend = 0;
		snprintf(nm, sizeof(nm), "pool%u", k);
		wrt_mg_map_add_pool(m, (int64_t)k, nm, &p);
		wrt_mg_pool_free(&p);
	}
	wrt_mg_map_resize(m, (int32_t)n);
	for (i = 0; i < n; i++) {
		uint32_t nonce = (uint32_t)wrt_mg_rng_next(&r);
		uint32_t ip = 0x0a4d0000u | (((i / 200u) & 0xffu) << 8) | (10u + i % 200u);
		uint16_t port = (uint16_t)(6802u + 8u * (i % 1000u));
		int never = (int)wrt_mg_rng_below(&r, 100) < (int)s->never_up_pct;
		int up = (int)wrt_mg_rng_below(&r, 100) < (int)s->up_pct;
		int out = (int)wrt_mg_rng_below(&r, 100) < (int)s->out_pct;
		wrt_mg_info *inf = &WRT_MG_E(m->osd_info, wrt_mg_info, i);
		wrt_mg_xinfo *xi = &WRT_MG_E(m->osd_xinfo, wrt_mg_osd_xinfo, i).x;
		wrt_mg_osd_uuid *uu = &WRT_MG_E(m->osd_uuid, wrt_mg_osd_uuid, i);
		uint32_t b;

		for (b = 0; b < 16; b++)
			uu->uuid[b] = (uint8_t)wrt_mg_rng_next(&r);
		WRT_MG_E(m->osd_weight, uint32_t, i) = out ? 0u : WRT_MG_W_IN;
		if (never) {
			WRT_MG_E(m->osd_state, uint32_t, i) = WRT_MG_OSD_EXISTS | WRT_MG_OSD_NEW;
			continue; /* addresses stay the 5-byte empty vector */
		}
		WRT_MG_E(m->osd_state, uint32_t, i) = WRT_MG_OSD_EXISTS | (up ? WRT_MG_OSD_UP : 0u);
		{
			wrt_mg_addrvec *av[4];
			unsigned q;

			av[0] = &WRT_MG_E(m->client_addrs, wrt_mg_addrvec, i);
			av[1] = &WRT_MG_E(m->cluster_addrs, wrt_mg_addrvec, i);
			av[2] = &WRT_MG_E(m->hb_back_addrs, wrt_mg_addrvec, i);
			av[3] = &WRT_MG_E(m->hb_front_addrs, wrt_mg_addrvec, i);
			for (q = 0; q < 4; q++) {
				uint16_t pt = (uint16_t)(port + 2 * q);

				if (s->ipv6_every > 0 && (int)(i % (uint32_t)s->ipv6_every) == s->ipv6_every - 1) {
					uint8_t ip6[16];

					memset(ip6, 0, sizeof(ip6));
					ip6[0] = 0xfd;
					ip6[14] = (uint8_t)(i >> 8);
					ip6[15] = (uint8_t)i;
					wrt_mg_av_v6(av[q], ip6, pt, nonce);
				} else if (s->v1_only_every > 0 && (int)(i % (uint32_t)s->v1_only_every) == s->v1_only_every - 1) {
					wrt_mg_av_v1(av[q], ip, pt, nonce);
				} else {
					wrt_mg_av_v2v1(av[q], ip, pt, nonce);
				}
			}
		}
		inf->up_from = 1 + wrt_mg_rng_below(&r, epoch);
		inf->up_thru = inf->up_from + wrt_mg_rng_below(&r, 3);
		inf->down_at = 0;
		xi->features = WRT_MG_FEATURES_ALL;
		if (!up) {
			inf->down_at = inf->up_thru + 1;
			xi->down_stamp.sec = 1700000000u + inf->down_at;
		}
	}
	if (s->n_affinity) {
		wrt_mg_vec_resize0(&m->osd_primary_affinity, sizeof(uint32_t), n);
		for (i = 0; i < n; i++)
			WRT_MG_E(m->osd_primary_affinity, uint32_t, i) = WRT_MG_W_IN;
		for (k = 0; k < s->n_affinity && n; k++)
			WRT_MG_E(m->osd_primary_affinity, uint32_t, wrt_mg_rng_below(&r, n)) = wrt_mg_rng_below(&r, 0x10000u);
	}
	if (n == 0)
		return 0;
	keys = (wrt_mg_pg *)calloc(pg_num + 1u, sizeof(wrt_mg_pg));
	if (!keys)
		abort();
	k = pick_pgs(&r, pg_num, s->n_upmap_items, keys);
	for (i = 0; i < k; i++) {
		wrt_mg_pair pr[3];
		uint32_t np = 1 + wrt_mg_rng_below(&r, 3), q;

		for (q = 0; q < np; q++) {
			pr[q].from = (int32_t)wrt_mg_rng_below(&r, n);
			pr[q].to = (int32_t)wrt_mg_rng_below(&r, n);
		}
		wrt_mg_map_set_pg_upmap_items(m, keys[i], pr, np);
	}
	k = pick_pgs(&r, pg_num, s->n_upmap, keys);
	for (i = 0; i < k; i++) {
		uint32_t q;

		for (q = 0; q < size && q < WRT_MG_MAX_REPL; q++)
			lst[q] = (int32_t)wrt_mg_rng_below(&r, n);
		wrt_mg_map_set_pg_upmap(m, keys[i], lst, size < WRT_MG_MAX_REPL ? size : WRT_MG_MAX_REPL);
	}
	k = pick_pgs(&r, pg_num, s->n_pg_temp, keys);
	for (i = 0; i < k; i++) {
		uint32_t q, len = 2 + wrt_mg_rng_below(&r, 2);

		for (q = 0; q < len; q++)
			lst[q] = (int32_t)wrt_mg_rng_below(&r, n);
		wrt_mg_map_set_pg_temp(m, keys[i], lst, len);
	}
	k = pick_pgs(&r, pg_num, s->n_primary_temp, keys);
	for (i = 0; i < k; i++)
		wrt_mg_map_set_primary_temp(m, keys[i], (int32_t)wrt_mg_rng_below(&r, n));
	k = pick_pgs(&r, pg_num, s->n_upmap_primaries, keys);
	for (i = 0; i < k; i++)
		wrt_mg_map_set_upmap_primary(m, keys[i], (int32_t)wrt_mg_rng_below(&r, n));
	free(keys);
	return 0;
}

/* ---- the model ------------------------------------------------------------------------------------------------ */

void wrt_mg_model_init(wrt_mg_map *m)
{
	wrt_mg_map_init(m);
	m->epoch = 0;
}

int wrt_mg_exists(const wrt_mg_map *m, int32_t osd)
{
	return osd >= 0 && osd < m->max_osd && (uint32_t)osd < m->osd_state.n &&
	       (WRT_MG_E(m->osd_state, uint32_t, osd) & WRT_MG_OSD_EXISTS) != 0;
}

int wrt_mg_is_up(const wrt_mg_map *m, int32_t osd)
{
	return wrt_mg_exists(m, osd) && (WRT_MG_E(m->osd_state, uint32_t, osd) & WRT_MG_OSD_UP) != 0;
}

uint32_t wrt_mg_weight(const wrt_mg_map *m, int32_t osd)
{
	return osd >= 0 && osd < m->max_osd && (uint32_t)osd < m->osd_weight.n ? WRT_MG_E(m->osd_weight, uint32_t, osd) : 0u;
}

uint32_t wrt_mg_affinity(const wrt_mg_map *m, int32_t osd)
{
	if (m->osd_primary_affinity.n == 0 || osd < 0 || (uint32_t)osd >= m->osd_primary_affinity.n)
		return WRT_MG_W_IN;
	return WRT_MG_E(m->osd_primary_affinity, uint32_t, osd);
}

/* crush note 3.2.1: nine rounds; (a, b, c) play the roles of the table by reference. */
static void mix(uint32_t *a, uint32_t *b, uint32_t *c)
{
	*a = *a - *b - *c;
	*a ^= *c >> 13;
	*b = *b - *c - *a;
	*b ^= *a << 8;
	*c = *c - *a - *b;
	*c ^= *b >> 13;
	*a = *a - *b - *c;
	*a ^= *c >> 12;
	*b = *b - *c - *a;
	*b ^= *a << 16;
	*c = *c - *a - *b;
	*c ^= *b >> 5;
	*a = *a - *b - *c;
	*a ^= *c >> 3;
	*b = *b - *c - *a;
	*b ^= *a << 10;
	*c = *c - *a - *b;
	*c ^= *b >> 15;
}

uint32_t wrt_mg_hash32_2(uint32_t a, uint32_t b)
{
	uint32_t h = 1315423911u ^ a ^ b, x = 231232u, y = 1232u;

	mix(&a, &b, &h);
	mix(&x, &a, &h);
	mix(&b, &y, &h);
	return h;
}

uint32_t wrt_mg_pg_mask(uint32_t n)
{
	uint32_t v = n > 1 ? n - 1 : 0, bits = 0;

	while (v) {
		bits++;
		v >>= 1;
	}
	return bits >= 32 ? 0xffffffffu : (1u << bits) - 1u;
}

uint32_t wrt_mg_stable_mod(uint32_t x, uint32_t b, uint32_t bmask)
{
	return (x & bmask) < b ? (x & bmask) : (x & (bmask >> 1));
}

uint32_t wrt_mg_pg_seed(const wrt_mg_pool *p, uint32_t ps)
{
	return wrt_mg_stable_mod(ps, p->pg_num, wrt_mg_pg_mask(p->pg_num));
}

uint32_t wrt_mg_pps(const wrt_mg_pool *p, int64_t pool_id, uint32_t ps)
{
	uint32_t m = wrt_mg_stable_mod(ps, p->pgp_num, wrt_mg_pg_mask(p->pgp_num));

	if (p->flags & WRT_MG_POOL_HASHPSPOOL)
		return wrt_mg_hash32_2(m, (uint32_t)pool_id);
	return m + (uint32_t)pool_id;
}

/* ---- the model: placement stages after CRUSH --------------------------------------------------------------- */

static const wrt_mg_pg_list *find_list(const wrt_mg_vec *v, wrt_mg_pg pg)
{
	uint32_t i;

	for (i = 0; i < v->n; i++)
		if (pg_cmp(WRT_MG_E(*v, wrt_mg_pg_list, i).pg, pg) == 0)
			return &WRT_MG_E(*v, wrt_mg_pg_list, i);
	return NULL;
}

static const wrt_mg_pg_osd *find_osd(const wrt_mg_vec *v, wrt_mg_pg pg)
{
	uint32_t i;

	for (i = 0; i < v->n; i++)
		if (pg_cmp(WRT_MG_E(*v, wrt_mg_pg_osd, i).pg, pg) == 0)
			return &WRT_MG_E(*v, wrt_mg_pg_osd, i);
	return NULL;
}

static int valid_id(const wrt_mg_map *m, int32_t osd)
{
	return osd >= 0 && osd < m->max_osd;
}

int wrt_mg_model_stages(const wrt_mg_map *m, int64_t pool_id, uint32_t pg_seed, uint32_t pps, const int32_t *raw,
			uint32_t nraw, wrt_mg_place *out)
{
	int32_t cur[WRT_MG_MAX_REPL], tmp[WRT_MG_MAX_REPL];
	uint32_t ncur = 0, i, j, ntmp = 0;
	wrt_mg_pg pg;
	const wrt_mg_pg_list *ul;
	const wrt_mg_pg_items *ui = NULL;
	const wrt_mg_pg_osd *up_prim;
	int abandon = 0;

	memset(out, 0, sizeof(*out));
	out->up_primary = -1;
	out->acting_primary = -1;
	if (nraw > WRT_MG_MAX_REPL)
		return -1;
	pg.pool = (uint64_t)pool_id;
	pg.seed = pg_seed;

	/* 1. drop OSDs that do not exist (and the NONE marker) */
	for (i = 0; i < nraw; i++)
		if (wrt_mg_exists(m, raw[i]))
			cur[ncur++] = raw[i];

	/* 2. upmap: the list, then the pairs, then the primary */
	ul = find_list(&m->pg_upmap, pg);
	if (ul) {
		for (i = 0; i < ul->osds.n; i++) {
			int32_t o = WRT_MG_E(ul->osds, int32_t, i);

			if (o != WRT_MG_NONE && valid_id(m, o) && wrt_mg_weight(m, o) == 0)
				abandon = 1;
		}
		if (!abandon) {
			ncur = 0;
			for (i = 0; i < ul->osds.n && ncur < WRT_MG_MAX_REPL; i++)
				cur[ncur++] = WRT_MG_E(ul->osds, int32_t, i);
		}
	}
	for (i = 0; i < m->pg_upmap_items.n; i++)
		if (pg_cmp(WRT_MG_E(m->pg_upmap_items, wrt_mg_pg_items, i).pg, pg) == 0)
			ui = &WRT_MG_E(m->pg_upmap_items, wrt_mg_pg_items, i);
	if (!abandon && ui) {
		for (i = 0; i < ui->items.n; i++) {
			wrt_mg_pair pr = WRT_MG_E(ui->items, wrt_mg_pair, i);
			int has_to = 0, pos = -1;

			for (j = 0; j < ncur; j++)
				if (cur[j] == pr.to)
					has_to = 1;
			if (has_to)
				continue;
			if (pr.to != WRT_MG_NONE && valid_id(m, pr.to) && wrt_mg_weight(m, pr.to) == 0)
				continue;
			for (j = 0; j < ncur; j++)
				if (cur[j] == pr.from) {
					pos = (int)j;
					break;
				}
			if (pos >= 0)
				cur[pos] = pr.to;
		}
	}
	up_prim = find_osd(&m->pg_upmap_primaries, pg);
	if (!abandon && up_prim) {
		int32_t p = up_prim->osd;

		if (valid_id(m, p) && wrt_mg_weight(m, p) != 0)
			for (j = 1; j < ncur; j++)
				if (cur[j] == p) {
					cur[j] = cur[0];
					cur[0] = p;
					break;
				}
	}

	/* 3. the up set: members that exist and are up, in order */
	for (i = 0; i < ncur; i++)
		if (wrt_mg_is_up(m, cur[i]))
			tmp[ntmp++] = cur[i];
	for (i = 0; i < ntmp; i++)
		out->up[i] = tmp[i];
	out->nup = ntmp;
	out->up_primary = ntmp ? out->up[0] : -1;

	/* 4. primary affinity */
	if (m->osd_primary_affinity.n != 0 && ntmp != 0) {
		int any = 0, pos = -1;

		for (i = 0; i < ntmp; i++)
			if (wrt_mg_affinity(m, out->up[i]) != WRT_MG_W_IN)
				any = 1;
		if (any) {
			for (i = 0; i < ntmp; i++) {
				uint32_t a = wrt_mg_affinity(m, out->up[i]);

				if (a < WRT_MG_W_IN && (wrt_mg_hash32_2(pps, (uint32_t)out->up[i]) >> 16) >= a) {
					if (pos < 0)
						pos = (int)i; /* the fallback: the first one that was only a candidate */
				} else {
					pos = (int)i;
					break;
				}
			}
			if (pos >= 0) {
				int32_t pri = out->up[pos];

				out->up_primary = pri;
				for (j = (uint32_t)pos; j > 0; j--)
					out->up[j] = out->up[j - 1];
				out->up[0] = pri;
			}
		}
	}

	/* 5. temp: pg_temp members that exist and are up, primary_temp, then the acting set */
	{
		int32_t temp_primary = -1;
		uint32_t ntemp = 0;
		int32_t temp[WRT_MG_MAX_REPL];
		const wrt_mg_pg_list *tl = find_list(&m->pg_temp, pg);
		const wrt_mg_pg_osd *tp = find_osd(&m->primary_temp, pg);

		if (tl)
			for (i = 0; i < tl->osds.n && ntemp < WRT_MG_MAX_REPL; i++) {
				int32_t o = WRT_MG_E(tl->osds, int32_t, i);

				if (wrt_mg_is_up(m, o))
					temp[ntemp++] = o;
			}
		if (tp)
			temp_primary = tp->osd;
		else if (ntemp)
			temp_primary = temp[0];
		if (ntemp) {
			for (i = 0; i < ntemp; i++)
				out->acting[i] = temp[i];
			out->nacting = ntemp;
			out->acting_primary = temp_primary;
		} else {
			for (i = 0; i < out->nup; i++)
				out->acting[i] = out->up[i];
			out->nacting = out->nup;
			/* a temp primary of -1 (a stored entry that says "none") falls back to the up primary, like no entry */
			out->acting_primary = temp_primary != -1 ? temp_primary : out->up_primary;
		}
	}
	return 0;
}

/* ---- the model: applying an incremental ---------------------------------------------------------------------- */

static int8_t rel(uint8_t r)
{
	return (int8_t)r;
}

static void pool_copy(const wrt_mg_pool *src, wrt_mg_pool *dst)
{
	wrt_mg_buf b;

	memset(&b, 0, sizeof(b));
	wrt_mg_pool_encode(src, &b);
	if (wrt_mg_pool_parse(b.p, b.len, dst) != 0)
		abort();
	wrt_mg_buf_free(&b);
}

static void erase_keyed(wrt_mg_vec *v, size_t esz, wrt_mg_pg pg, void (*inner_free)(void *))
{
	uint32_t i;

	for (i = 0; i < v->n; i++) {
		wrt_mg_pg k;

		memcpy(&k, (uint8_t *)v->v + (size_t)i * esz, sizeof(k));
		if (pg_cmp(k, pg) == 0) {
			if (inner_free)
				inner_free((uint8_t *)v->v + (size_t)i * esz);
			wrt_mg_vec_del(v, esz, i);
			return;
		}
	}
}

static void free_pg_list(void *e)
{
	free(((wrt_mg_pg_list *)e)->osds.v);
}

static void free_pg_items(void *e)
{
	free(((wrt_mg_pg_items *)e)->items.v);
}

/* interval_set<snapid>: a sorted list of disjoint, non-adjacent [start, start + len). */
static void iv_add(wrt_mg_vec *v, uint64_t s, uint64_t l)
{
	uint32_t i;
	uint64_t e = s + l;

	if (l == 0)
		return;
	for (i = 0; i < v->n;) {
		wrt_mg_iv *x = &WRT_MG_E(*v, wrt_mg_iv, i);
		uint64_t xe = x->start + x->len;

		if (xe < s) {
			i++;
			continue;
		}
		if (x->start > e)
			break;
		/* overlapping or adjacent: absorb */
		if (x->start < s)
			s = x->start;
		if (xe > e)
			e = xe;
		wrt_mg_vec_del(v, sizeof(wrt_mg_iv), i);
	}
	{
		wrt_mg_iv nv;

		nv.start = s;
		nv.len = e - s;
		insert_at(v, sizeof(nv), i, &nv);
	}
}

static void iv_sub(wrt_mg_vec *v, uint64_t s, uint64_t l)
{
	uint32_t i;
	uint64_t e = s + l;

	for (i = 0; i < v->n;) {
		wrt_mg_iv x = WRT_MG_E(*v, wrt_mg_iv, i);
		uint64_t xe = x.start + x.len;

		if (xe <= s || x.start >= e) {
			i++;
			continue;
		}
		wrt_mg_vec_del(v, sizeof(wrt_mg_iv), i);
		if (x.start < s) {
			wrt_mg_iv a;

			a.start = x.start;
			a.len = s - x.start;
			insert_at(v, sizeof(a), i++, &a);
		}
		if (xe > e) {
			wrt_mg_iv b;

			b.start = e;
			b.len = xe - e;
			insert_at(v, sizeof(b), i++, &b);
		}
	}
}

static void snapsets_assign(wrt_mg_vec *dst, const wrt_mg_vec *src)
{
	uint32_t i;

	for (i = 0; i < dst->n; i++)
		free(WRT_MG_E(*dst, wrt_mg_snapset, i).iv.v);
	free(dst->v);
	memset(dst, 0, sizeof(*dst));
	for (i = 0; i < src->n; i++) {
		wrt_mg_snapset s = WRT_MG_E(*src, wrt_mg_snapset, i);

		memset(&s.iv, 0, sizeof(s.iv));
		wrt_mg_vec_resize0(&s.iv, sizeof(wrt_mg_iv), WRT_MG_E(*src, wrt_mg_snapset, i).iv.n);
		if (s.iv.n)
			memcpy(s.iv.v, WRT_MG_E(*src, wrt_mg_snapset, i).iv.v, s.iv.n * sizeof(wrt_mg_iv));
		wrt_mg_vec_grow_(dst, sizeof(s));
		WRT_MG_E(*dst, wrt_mg_snapset, dst->n++) = s;
	}
}

static wrt_mg_snapset *snapset_find(wrt_mg_vec *v, int64_t pool, int create)
{
	uint32_t i;
	wrt_mg_snapset s;

	for (i = 0; i < v->n; i++) {
		if (WRT_MG_E(*v, wrt_mg_snapset, i).pool == pool)
			return &WRT_MG_E(*v, wrt_mg_snapset, i);
		if (WRT_MG_E(*v, wrt_mg_snapset, i).pool > pool)
			break;
	}
	if (!create)
		return NULL;
	memset(&s, 0, sizeof(s));
	s.pool = pool;
	insert_at(v, sizeof(s), i, &s);
	return &WRT_MG_E(*v, wrt_mg_snapset, i);
}

/* The in-memory ordering of entity_addr_t (a memcmp of the struct on a little-endian host): type, nonce, sockaddr. */
static void addr_key(const wrt_mg_addr *a, uint8_t k[36])
{
	memset(k, 0, 36);
	k[0] = (uint8_t)a->type;
	k[1] = (uint8_t)(a->type >> 8);
	k[2] = (uint8_t)(a->type >> 16);
	k[3] = (uint8_t)(a->type >> 24);
	k[4] = (uint8_t)a->nonce;
	k[5] = (uint8_t)(a->nonce >> 8);
	k[6] = (uint8_t)(a->nonce >> 16);
	k[7] = (uint8_t)(a->nonce >> 24);
	k[8] = (uint8_t)a->family;
	k[9] = (uint8_t)(a->family >> 8);
	if (a->elen >= 2)
		memcpy(k + 10, a->sa, a->elen - 2u);
}

static int addr_cmp(const wrt_mg_addr *a, const wrt_mg_addr *b)
{
	uint8_t x[36], y[36];

	addr_key(a, x);
	addr_key(b, y);
	return memcmp(x, y, 36);
}

static void blk_insert(wrt_mg_vec *v, const wrt_mg_blk *e)
{
	uint32_t i;

	for (i = 0; i < v->n; i++) {
		int c = addr_cmp(&WRT_MG_E(*v, wrt_mg_blk, i).addr, &e->addr);

		if (c == 0)
			return; /* std::map::insert keeps the existing entry */
		if (c > 0)
			break;
	}
	insert_at(v, sizeof(*e), i, e);
}

static void blk_erase(wrt_mg_vec *v, const wrt_mg_addr *a)
{
	uint32_t i;

	for (i = 0; i < v->n; i++)
		if (addr_cmp(&WRT_MG_E(*v, wrt_mg_blk, i).addr, a) == 0) {
			wrt_mg_vec_del(v, sizeof(wrt_mg_blk), i);
			return;
		}
}

/* Every entry of an osd-keyed vector starts with its int32 OSD id. */
static int osd_range_ok(const wrt_mg_vec *v, size_t esz, int32_t max)
{
	uint32_t i;

	for (i = 0; i < v->n; i++) {
		int32_t o;

		memcpy(&o, (const uint8_t *)v->v + (size_t)i * esz, sizeof(o));
		if (o < 0 || o >= max)
			return 0;
	}
	return 1;
}

/* `x >= 0` for the float with these bits: false for a negative value and for a NaN, true for -0.0 */
static int float_nonneg(uint32_t bits)
{
	if ((bits & 0x7f800000u) == 0x7f800000u && (bits & 0x007fffffu) != 0)
		return 0;
	return (bits & 0x80000000u) == 0 || bits == 0x80000000u;
}

/* Every per-OSD vector of the model holds max_osd entries, so the indexing below stays inside them. */
static int model_shape_ok(const wrt_mg_map *m)
{
	uint32_t n;

	if (m->max_osd < 0)
		return 0;
	n = (uint32_t)m->max_osd;
	return m->osd_state.n >= n && m->osd_weight.n >= n && m->client_addrs.n >= n && m->hb_back_addrs.n >= n &&
	       m->cluster_addrs.n >= n && m->hb_front_addrs.n >= n && m->osd_info.n >= n && m->osd_uuid.n >= n &&
	       m->osd_xinfo.n >= n && (m->osd_primary_affinity.n == 0 || m->osd_primary_affinity.n >= n);
}

int wrt_mg_model_apply(wrt_mg_map *m, const wrt_mg_inc *inc)
{
	int32_t max;
	uint32_t i, j;
	wrt_mg_map full;
	wrt_mg_crush cr;
	int have_full = 0, have_crush = 0;

	memset(&full, 0, sizeof(full));
	memset(&cr, 0, sizeof(cr));
	max = m->max_osd;

	/* ---- validation: nothing is touched before this passes ---- */
	if (!model_shape_ok(m) || inc->new_max_osd > WRT_MG_MAX_OSD_MODEL)
		return WRT_MG_E_SHAPE;
	if (inc->epoch == 1) {
		/* adopt the fsid below */
	} else if (memcmp(inc->fsid, m->fsid, 16) != 0) {
		return WRT_MG_E_FSID;
	}
	if (inc->epoch != m->epoch + 1u)
		return WRT_MG_E_EPOCH;
	if (inc->fullmap_len != 0) {
		if (wrt_mg_map_parse(inc->fullmap, inc->fullmap_len, &full) != 0)
			return WRT_MG_E_PARSE;
		have_full = 1;
	} else {
		max = inc->new_max_osd >= 0 ? inc->new_max_osd : m->max_osd;
		if (!osd_range_ok(&inc->new_state, sizeof(wrt_mg_osd_u32), max) ||
		    !osd_range_ok(&inc->new_weight, sizeof(wrt_mg_osd_u32), max) ||
		    !osd_range_ok(&inc->new_primary_affinity, sizeof(wrt_mg_osd_u32), max) ||
		    !osd_range_ok(&inc->new_up_thru, sizeof(wrt_mg_osd_u32), max) ||
		    !osd_range_ok(&inc->new_lost, sizeof(wrt_mg_osd_u32), max) ||
		    !osd_range_ok(&inc->new_last_clean_interval, sizeof(wrt_mg_osd_pair), max) ||
		    !osd_range_ok(&inc->new_up_client, sizeof(wrt_mg_osd_av), max) ||
		    !osd_range_ok(&inc->new_up_cluster, sizeof(wrt_mg_osd_av), max) ||
		    !osd_range_ok(&inc->new_hb_back_up, sizeof(wrt_mg_osd_av), max) ||
		    !osd_range_ok(&inc->new_hb_front_up, sizeof(wrt_mg_osd_av), max) ||
		    !osd_range_ok(&inc->new_uuid, sizeof(wrt_mg_osd_uuid), max) ||
		    !osd_range_ok(&inc->new_xinfo, sizeof(wrt_mg_osd_xinfo), max))
			return WRT_MG_E_OSD_RANGE;
		if (inc->crush_len != 0) {
			if (wrt_mg_crush_parse(inc->crush, inc->crush_len, &cr) != 0)
				return WRT_MG_E_PARSE;
			have_crush = 1;
		}
	}

	/* ---- 1 to 4: identity, epoch, the embedded full map ---- */
	if (inc->epoch == 1)
		memcpy(m->fsid, inc->fsid, 16);
	if (have_full) {
		wrt_mg_map_free(m);
		*m = full;
		return WRT_MG_E_OK;
	}
	m->epoch = inc->epoch;
	m->modified = inc->modified;

	/* ---- 5 to 7: flags, size, pool ceiling ---- */
	if (inc->new_flags >= 0) {
		m->flags = (uint32_t)inc->new_flags;
		if ((m->flags & (1u << 17)) && rel(m->require_osd_release) < 11)
			m->require_osd_release = 11;
		else if ((m->flags & (1u << 16)) && rel(m->require_osd_release) < 10)
			m->require_osd_release = 10;
	}
	if (inc->new_max_osd >= 0)
		wrt_mg_map_resize(m, inc->new_max_osd);
	max = m->max_osd;
	if (inc->new_pool_max != -1)
		m->pool_max = (int32_t)inc->new_pool_max;

	/* ---- 8: pools ---- */
	for (i = 0; i < inc->new_pools.n; i++) {
		const wrt_mg_pool_ent *pe = &WRT_MG_E(inc->new_pools, wrt_mg_pool_ent, i);
		wrt_mg_pool_ent ne;
		int found;
		uint32_t at = id_slot(&m->pools, sizeof(ne), pe->id, &found);

		ne.id = pe->id;
		pool_copy(&pe->p, &ne.p);
		ne.p.last_change = inc->epoch;
		if (found) {
			wrt_mg_pool_free(&WRT_MG_E(m->pools, wrt_mg_pool_ent, at).p);
			WRT_MG_E(m->pools, wrt_mg_pool_ent, at) = ne;
		} else {
			insert_at(&m->pools, sizeof(ne), at, &ne);
		}
	}
	snapsets_assign(&m->new_removed_snaps, &inc->new_removed_snaps);
	snapsets_assign(&m->new_purged_snaps, &inc->new_purged_snaps);
	for (i = 0; i < m->new_removed_snaps.n; i++) {
		wrt_mg_snapset *src = &WRT_MG_E(m->new_removed_snaps, wrt_mg_snapset, i);
		wrt_mg_snapset *q = snapset_find(&m->removed_snaps_queue, src->pool, 1);

		for (j = 0; j < src->iv.n; j++)
			iv_add(&q->iv, WRT_MG_E(src->iv, wrt_mg_iv, j).start, WRT_MG_E(src->iv, wrt_mg_iv, j).len);
	}
	for (i = 0; i < m->new_purged_snaps.n; i++) {
		wrt_mg_snapset *src = &WRT_MG_E(m->new_purged_snaps, wrt_mg_snapset, i);
		wrt_mg_snapset *q = snapset_find(&m->removed_snaps_queue, src->pool, 0);

		if (!q)
			continue;
		for (j = 0; j < src->iv.n; j++)
			iv_sub(&q->iv, WRT_MG_E(src->iv, wrt_mg_iv, j).start, WRT_MG_E(src->iv, wrt_mg_iv, j).len);
		if (q->iv.n == 0) {
			free(q->iv.v);
			wrt_mg_vec_del(&m->removed_snaps_queue, sizeof(wrt_mg_snapset),
				       (uint32_t)(q - (wrt_mg_snapset *)m->removed_snaps_queue.v));
		}
	}
	if (inc->new_last_up_change.sec || inc->new_last_up_change.nsec)
		m->last_up_change = inc->new_last_up_change;
	if (inc->new_last_in_change.sec || inc->new_last_in_change.nsec)
		m->last_in_change = inc->new_last_in_change;

	/* ---- 9, 10: names, removals ---- */
	for (i = 0; i < inc->new_pool_names.n; i++) {
		wrt_mg_pname pn = WRT_MG_E(inc->new_pool_names, wrt_mg_pname, i);
		int found;
		uint32_t at = id_slot(&m->pool_names, sizeof(pn), pn.id, &found);

		if (found)
			WRT_MG_E(m->pool_names, wrt_mg_pname, at) = pn;
		else
			insert_at(&m->pool_names, sizeof(pn), at, &pn);
	}
	for (i = 0; i < inc->old_pools.n; i++) {
		int64_t id = WRT_MG_E(inc->old_pools, int64_t, i);
		int found;
		uint32_t at = id_slot(&m->pools, sizeof(wrt_mg_pool_ent), id, &found);

		if (found) {
			wrt_mg_pool_free(&WRT_MG_E(m->pools, wrt_mg_pool_ent, at).p);
			wrt_mg_vec_del(&m->pools, sizeof(wrt_mg_pool_ent), at);
		}
		at = id_slot(&m->pool_names, sizeof(wrt_mg_pname), id, &found);
		if (found)
			wrt_mg_vec_del(&m->pool_names, sizeof(wrt_mg_pname), at);
	}

	/* ---- 11: weights; 12: primary affinity ---- */
	for (i = 0; i < inc->new_weight.n; i++) {
		wrt_mg_osd_u32 w = WRT_MG_E(inc->new_weight, wrt_mg_osd_u32, i);
		uint32_t *st = &WRT_MG_E(m->osd_state, uint32_t, w.osd);

		WRT_MG_E(m->osd_weight, uint32_t, w.osd) = w.val;
		if (w.val) {
			*st |= WRT_MG_OSD_EXISTS;
			*st &= ~(WRT_MG_OSD_AUTOOUT | WRT_MG_OSD_NEW);
			WRT_MG_E(m->osd_xinfo, wrt_mg_osd_xinfo, w.osd).x.old_weight = 0;
		}
	}
	for (i = 0; i < inc->new_primary_affinity.n; i++) {
		wrt_mg_osd_u32 a = WRT_MG_E(inc->new_primary_affinity, wrt_mg_osd_u32, i);

		if (m->osd_primary_affinity.n == 0) {
			wrt_mg_vec_resize0(&m->osd_primary_affinity, sizeof(uint32_t), (uint32_t)max);
			for (j = 0; j < (uint32_t)max; j++)
				WRT_MG_E(m->osd_primary_affinity, uint32_t, j) = WRT_MG_W_IN;
		}
		WRT_MG_E(m->osd_primary_affinity, uint32_t, a.osd) = a.val;
	}

	/* ---- 13: state changes ---- */
	for (i = 0; i < inc->new_state.n; i++) {
		wrt_mg_osd_u32 s = WRT_MG_E(inc->new_state, wrt_mg_osd_u32, i);
		uint32_t mask = s.val ? s.val : WRT_MG_OSD_UP;
		uint32_t *st = &WRT_MG_E(m->osd_state, uint32_t, s.osd);
		wrt_mg_addrvec empty;

		if ((*st & WRT_MG_OSD_UP) && (mask & WRT_MG_OSD_UP)) {
			WRT_MG_E(m->osd_info, wrt_mg_info, s.osd).down_at = inc->epoch;
			WRT_MG_E(m->osd_xinfo, wrt_mg_osd_xinfo, s.osd).x.down_stamp = inc->modified;
		}
		if ((*st & WRT_MG_OSD_EXISTS) && (mask & WRT_MG_OSD_EXISTS)) {
			/* destroyed: everything about it is reset */
			wrt_mg_osd_xinfo xi;

			wrt_mg_av_empty(&empty);
			memset(&xi, 0, sizeof(xi));
			xi.x.v = 4;
			xi.x.compat = 1;
			memset(WRT_MG_E(m->osd_uuid, wrt_mg_osd_uuid, s.osd).uuid, 0, 16);
			memset(&WRT_MG_E(m->osd_info, wrt_mg_info, s.osd), 0, sizeof(wrt_mg_info));
			WRT_MG_E(m->osd_xinfo, wrt_mg_osd_xinfo, s.osd) = xi;
			if (m->osd_primary_affinity.n == 0) {
				wrt_mg_vec_resize0(&m->osd_primary_affinity, sizeof(uint32_t), (uint32_t)max);
				for (j = 0; j < (uint32_t)max; j++)
					WRT_MG_E(m->osd_primary_affinity, uint32_t, j) = WRT_MG_W_IN;
			}
			WRT_MG_E(m->osd_primary_affinity, uint32_t, s.osd) = WRT_MG_W_IN;
			WRT_MG_E(m->client_addrs, wrt_mg_addrvec, s.osd) = empty;
			WRT_MG_E(m->cluster_addrs, wrt_mg_addrvec, s.osd) = empty;
			WRT_MG_E(m->hb_front_addrs, wrt_mg_addrvec, s.osd) = empty;
			WRT_MG_E(m->hb_back_addrs, wrt_mg_addrvec, s.osd) = empty;
			*st = 0;
		} else {
			*st ^= mask;
		}
	}

	/* ---- 14: new up OSDs ---- */
	for (i = 0; i < inc->new_up_client.n; i++) {
		const wrt_mg_osd_av *c = &WRT_MG_E(inc->new_up_client, wrt_mg_osd_av, i);
		wrt_mg_addrvec hb_back, hb_front;
		uint32_t *st = &WRT_MG_E(m->osd_state, uint32_t, c->osd);

		wrt_mg_av_empty(&hb_back);
		wrt_mg_av_empty(&hb_front);
		for (j = 0; j < inc->new_hb_back_up.n; j++)
			if (WRT_MG_E(inc->new_hb_back_up, wrt_mg_osd_av, j).osd == c->osd)
				hb_back = WRT_MG_E(inc->new_hb_back_up, wrt_mg_osd_av, j).av;
		for (j = 0; j < inc->new_hb_front_up.n; j++)
			if (WRT_MG_E(inc->new_hb_front_up, wrt_mg_osd_av, j).osd == c->osd)
				hb_front = WRT_MG_E(inc->new_hb_front_up, wrt_mg_osd_av, j).av;
		*st |= WRT_MG_OSD_EXISTS | WRT_MG_OSD_UP;
		*st &= ~WRT_MG_OSD_STOP;
		WRT_MG_E(m->client_addrs, wrt_mg_addrvec, c->osd) = c->av;
		WRT_MG_E(m->hb_back_addrs, wrt_mg_addrvec, c->osd) = hb_back;
		WRT_MG_E(m->hb_front_addrs, wrt_mg_addrvec, c->osd) = hb_front;
		WRT_MG_E(m->osd_info, wrt_mg_info, c->osd).up_from = inc->epoch;
	}
	for (i = 0; i < inc->new_up_cluster.n; i++)
		WRT_MG_E(m->cluster_addrs, wrt_mg_addrvec, WRT_MG_E(inc->new_up_cluster, wrt_mg_osd_av, i).osd) =
			WRT_MG_E(inc->new_up_cluster, wrt_mg_osd_av, i).av;
	for (i = 0; i < inc->new_up_thru.n; i++)
		WRT_MG_E(m->osd_info, wrt_mg_info, WRT_MG_E(inc->new_up_thru, wrt_mg_osd_u32, i).osd).up_thru =
			WRT_MG_E(inc->new_up_thru, wrt_mg_osd_u32, i).val;
	for (i = 0; i < inc->new_last_clean_interval.n; i++) {
		wrt_mg_osd_pair p = WRT_MG_E(inc->new_last_clean_interval, wrt_mg_osd_pair, i);

		WRT_MG_E(m->osd_info, wrt_mg_info, p.osd).last_clean_begin = p.a;
		WRT_MG_E(m->osd_info, wrt_mg_info, p.osd).last_clean_end = p.b;
	}
	for (i = 0; i < inc->new_lost.n; i++)
		WRT_MG_E(m->osd_info, wrt_mg_info, WRT_MG_E(inc->new_lost, wrt_mg_osd_u32, i).osd).lost_at =
			WRT_MG_E(inc->new_lost, wrt_mg_osd_u32, i).val;
	for (i = 0; i < inc->new_xinfo.n; i++)
		WRT_MG_E(m->osd_xinfo, wrt_mg_osd_xinfo, WRT_MG_E(inc->new_xinfo, wrt_mg_osd_xinfo, i).osd) =
			WRT_MG_E(inc->new_xinfo, wrt_mg_osd_xinfo, i);
	for (i = 0; i < inc->new_uuid.n; i++)
		memcpy(WRT_MG_E(m->osd_uuid, wrt_mg_osd_uuid, WRT_MG_E(inc->new_uuid, wrt_mg_osd_uuid, i).osd).uuid,
		       WRT_MG_E(inc->new_uuid, wrt_mg_osd_uuid, i).uuid, 16);

	/* ---- 15 to 17: the PG tables ---- */
	for (i = 0; i < inc->new_pg_temp.n; i++) {
		const wrt_mg_pg_list *e = &WRT_MG_E(inc->new_pg_temp, wrt_mg_pg_list, i);

		if (e->osds.n == 0)
			erase_keyed(&m->pg_temp, sizeof(wrt_mg_pg_list), e->pg, free_pg_list);
		else
			wrt_mg_map_set_pg_temp(m, e->pg, (const int32_t *)e->osds.v, e->osds.n);
	}
	for (i = 0; i < inc->new_primary_temp.n; i++) {
		const wrt_mg_pg_osd *e = &WRT_MG_E(inc->new_primary_temp, wrt_mg_pg_osd, i);

		if (e->osd == -1)
			erase_keyed(&m->primary_temp, sizeof(wrt_mg_pg_osd), e->pg, NULL);
		else
			wrt_mg_map_set_primary_temp(m, e->pg, e->osd);
	}
	for (i = 0; i < inc->new_pg_upmap.n; i++)
		wrt_mg_map_set_pg_upmap(m, WRT_MG_E(inc->new_pg_upmap, wrt_mg_pg_list, i).pg,
					(const int32_t *)WRT_MG_E(inc->new_pg_upmap, wrt_mg_pg_list, i).osds.v,
					WRT_MG_E(inc->new_pg_upmap, wrt_mg_pg_list, i).osds.n);
	for (i = 0; i < inc->old_pg_upmap.n; i++)
		erase_keyed(&m->pg_upmap, sizeof(wrt_mg_pg_list), WRT_MG_E(inc->old_pg_upmap, wrt_mg_pg, i), free_pg_list);
	for (i = 0; i < inc->new_pg_upmap_items.n; i++)
		wrt_mg_map_set_pg_upmap_items(m, WRT_MG_E(inc->new_pg_upmap_items, wrt_mg_pg_items, i).pg,
					      (const wrt_mg_pair *)WRT_MG_E(inc->new_pg_upmap_items, wrt_mg_pg_items, i).items.v,
					      WRT_MG_E(inc->new_pg_upmap_items, wrt_mg_pg_items, i).items.n);
	for (i = 0; i < inc->old_pg_upmap_items.n; i++)
		erase_keyed(&m->pg_upmap_items, sizeof(wrt_mg_pg_items), WRT_MG_E(inc->old_pg_upmap_items, wrt_mg_pg, i),
			    free_pg_items);
	for (i = 0; i < inc->new_pg_upmap_primary.n; i++)
		wrt_mg_map_set_upmap_primary(m, WRT_MG_E(inc->new_pg_upmap_primary, wrt_mg_pg_osd, i).pg,
					     WRT_MG_E(inc->new_pg_upmap_primary, wrt_mg_pg_osd, i).osd);
	for (i = 0; i < inc->old_pg_upmap_primary.n; i++)
		erase_keyed(&m->pg_upmap_primaries, sizeof(wrt_mg_pg_osd), WRT_MG_E(inc->old_pg_upmap_primary, wrt_mg_pg, i),
			    NULL);

	/* ---- the rest of the OSD-only state ---- */
	for (i = 0; i < inc->new_blocklist.n; i++)
		blk_insert(&m->blocklist, &WRT_MG_E(inc->new_blocklist, wrt_mg_blk, i));
	for (i = 0; i < inc->old_blocklist.n; i++)
		blk_erase(&m->blocklist, &WRT_MG_E(inc->old_blocklist, wrt_mg_addr, i));
	for (i = 0; i < inc->new_range_blocklist.n; i++)
		blk_insert(&m->range_blocklist, &WRT_MG_E(inc->new_range_blocklist, wrt_mg_blk, i));
	for (i = 0; i < inc->old_range_blocklist.n; i++)
		blk_erase(&m->range_blocklist, &WRT_MG_E(inc->old_range_blocklist, wrt_mg_addr, i));
	for (i = 0; i < inc->new_crush_node_flags.n; i++) {
		wrt_mg_osd_u32 f = WRT_MG_E(inc->new_crush_node_flags, wrt_mg_osd_u32, i);
		uint32_t at;

		for (at = 0; at < m->crush_node_flags.n; at++)
			if (WRT_MG_E(m->crush_node_flags, wrt_mg_osd_u32, at).osd >= f.osd)
				break;
		if (at < m->crush_node_flags.n && WRT_MG_E(m->crush_node_flags, wrt_mg_osd_u32, at).osd == f.osd) {
			if (f.val)
				WRT_MG_E(m->crush_node_flags, wrt_mg_osd_u32, at) = f;
			else
				wrt_mg_vec_del(&m->crush_node_flags, sizeof(f), at);
		} else if (f.val) {
			insert_at(&m->crush_node_flags, sizeof(f), at, &f);
		}
	}
	for (i = 0; i < inc->new_device_class_flags.n; i++) {
		wrt_mg_osd_u32 f = WRT_MG_E(inc->new_device_class_flags, wrt_mg_osd_u32, i);
		uint32_t at;

		for (at = 0; at < m->device_class_flags.n; at++)
			if (WRT_MG_E(m->device_class_flags, wrt_mg_osd_u32, at).osd >= f.osd)
				break;
		if (at < m->device_class_flags.n && WRT_MG_E(m->device_class_flags, wrt_mg_osd_u32, at).osd == f.osd) {
			if (f.val)
				WRT_MG_E(m->device_class_flags, wrt_mg_osd_u32, at) = f;
			else
				wrt_mg_vec_del(&m->device_class_flags, sizeof(f), at);
		} else if (f.val) {
			insert_at(&m->device_class_flags, sizeof(f), at, &f);
		}
	}
	if (inc->cluster_snapshot[0]) {
		snprintf(m->cluster_snapshot, sizeof(m->cluster_snapshot), "%s", inc->cluster_snapshot);
		m->cluster_snapshot_epoch = inc->epoch;
	} else {
		m->cluster_snapshot[0] = 0;
		m->cluster_snapshot_epoch = 0;
	}
	if (float_nonneg(inc->new_nearfull_bits))
		m->nearfull_bits = inc->new_nearfull_bits;
	if (float_nonneg(inc->new_backfillfull_bits))
		m->backfillfull_bits = inc->new_backfillfull_bits;
	if (float_nonneg(inc->new_full_bits))
		m->full_bits = inc->new_full_bits;
	if (rel(inc->new_require_min_compat_client) > 0)
		m->require_min_compat_client = inc->new_require_min_compat_client;
	if (rel(inc->new_require_osd_release) >= 0) {
		m->require_osd_release = inc->new_require_osd_release;
		if (rel(m->require_osd_release) >= 12) {
			m->flags &= ~((1u << 16) | (1u << 17) | (1u << 18));
			m->flags |= 1u << 19;
		}
		if (rel(m->require_osd_release) >= 14)
			m->flags |= 1u << 22;
	}

	/* ---- 18: CRUSH last ---- */
	if (have_crush) {
		free(m->crush);
		m->crush = (uint8_t *)malloc(inc->crush_len);
		if (!m->crush)
			abort();
		memcpy(m->crush, inc->crush, inc->crush_len);
		m->crush_len = inc->crush_len;
		if (rel(m->require_osd_release) >= 12)
			m->crush_version++;
		for (i = 0; i < m->device_class_flags.n;) {
			int32_t cls = WRT_MG_E(m->device_class_flags, wrt_mg_osd_u32, i).osd;
			int found = 0;

			for (j = 0; j < cr.class_names.n; j++)
				if (WRT_MG_E(cr.class_names, wrt_mg_cls_name, j).id == cls)
					found = 1;
			if (found)
				i++;
			else
				wrt_mg_vec_del(&m->device_class_flags, sizeof(wrt_mg_osd_u32), i);
		}
		wrt_mg_crush_free(&cr);
	}
	if (inc->change_stretch_mode) {
		m->stretch_mode_enabled = inc->stretch_mode_enabled;
		m->stretch_bucket_count = inc->new_stretch_bucket_count;
		m->degraded_stretch_mode = inc->new_degraded_stretch_mode;
		m->recovering_stretch_mode = inc->new_recovering_stretch_mode;
		m->stretch_mode_bucket = inc->new_stretch_mode_bucket;
	}
	if (inc->mutate_allow_crimson == 1)
		m->allow_crimson = 1;
	else if (inc->mutate_allow_crimson == 2)
		m->allow_crimson = 0;
	return WRT_MG_E_OK;
}

/* ---- loaders --------------------------------------------------------------------------------------------------- */

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

/* Hex digits of s[0, n) (whitespace skipped) into a malloc'd buffer; -1 on a stray character or an odd count. */
static int hex_to_bytes(const char *s, size_t n, uint8_t **out, size_t *outn)
{
	uint8_t *b = (uint8_t *)malloc(n / 2 + 1);
	size_t i, k = 0;
	int hi = -1;

	if (!b)
		abort();
	for (i = 0; i < n; i++) {
		int v;

		if (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t')
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
	*out = b;
	*outn = k;
	return 0;
}

static char *read_text(const char *path, size_t *n)
{
	FILE *f = fopen(path, "rb");
	long len;
	char *b;

	if (!f)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (len = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return NULL;
	}
	b = (char *)malloc((size_t)len + 1);
	if (!b || fread(b, 1, (size_t)len, f) != (size_t)len) {
		free(b);
		fclose(f);
		return NULL;
	}
	fclose(f);
	b[len] = 0;
	*n = (size_t)len;
	return b;
}

int wrt_mg_load_hex_file(const char *path, uint8_t **out, size_t *n)
{
	size_t len, i, k = 0;
	char *t = read_text(path, &len), *clean;
	int rc;

	if (!t)
		return -1;
	clean = (char *)malloc(len + 1);
	if (!clean)
		abort();
	for (i = 0; i < len; i++) {
		if (t[i] == '#') { /* a comment runs to the end of the line */
			while (i < len && t[i] != '\n')
				i++;
			continue;
		}
		clean[k++] = t[i];
	}
	rc = hex_to_bytes(clean, k, out, n);
	free(clean);
	free(t);
	return rc;
}

int wrt_mg_load_epoch_lines(const char *path, wrt_mg_line **lines, size_t *nlines)
{
	size_t len, pos = 0, cnt = 0, cap = 0;
	char *t = read_text(path, &len);
	wrt_mg_line *ls = NULL;

	if (!t)
		return -1;
	while (pos < len) {
		size_t eol = pos;
		char *end;
		unsigned long ep;

		while (eol < len && t[eol] != '\n')
			eol++;
		if (t[pos] != '#' && eol > pos) {
			ep = strtoul(t + pos, &end, 10);
			if (end != t + pos) {
				wrt_mg_line l;

				if (hex_to_bytes(end, eol - (size_t)(end - t), &l.p, &l.n) != 0) {
					wrt_mg_free_lines(ls, cnt);
					free(t);
					return -1;
				}
				l.epoch = (uint32_t)ep;
				if (cnt == cap) {
					cap = cap ? cap * 2 : 128;
					ls = (wrt_mg_line *)realloc(ls, cap * sizeof(*ls));
					if (!ls)
						abort();
				}
				ls[cnt++] = l;
			}
		}
		pos = eol + 1;
	}
	free(t);
	*lines = ls;
	*nlines = cnt;
	return 0;
}

void wrt_mg_free_lines(wrt_mg_line *lines, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		free(lines[i].p);
	free(lines);
}
