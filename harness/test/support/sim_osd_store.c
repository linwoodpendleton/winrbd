/* SPDX-License-Identifier: MIT */
/*
 * sim_osd_store.c - the object store shared by the fake OSDs of a cluster (sim_osd.h): sparse objects kept as 4 KiB pages with reference counts
 * (a clone or a rollback copy shares the pages and the first write copies one), omap and xattrs as sorted key arrays, self-managed snapshot
 * clones and whiteouts (rbd-format2.md 3.6, osd-ops.md 3.9), and the duplicate-detection log. The direct access for tests is at the end.
 * Test code: libc allowed.
 */
#include "sim_osd_int.h"

/* ---- growable buffer ----------------------------------------------------------------------------------------------- */

void so_buf_free(so_buf *b)
{
	free(b->p);
	memset(b, 0, sizeof(*b));
}

uint8_t *so_buf_grow(so_buf *b, size_t n)
{
	if (b->oom)
		return NULL;
	if (n > b->cap - b->len) {
		size_t nc = b->cap != 0 ? b->cap : 256u;
		uint8_t *q;

		while (nc < b->len + n)
			nc *= 2;
		q = (uint8_t *)realloc(b->p, nc);
		if (q == NULL) {
			b->oom = 1;
			return NULL;
		}
		b->p = q;
		b->cap = nc;
	}
	b->len += n;
	return b->p + (b->len - n);
}

void so_buf_put(so_buf *b, const void *p, size_t n)
{
	uint8_t *d;

	if (n == 0)
		return;
	d = so_buf_grow(b, n);
	if (d != NULL)
		memcpy(d, p, n);
}

void so_buf_u8(so_buf *b, uint8_t v) { so_buf_put(b, &v, 1); }

void so_buf_u32(so_buf *b, uint32_t v)
{
	uint8_t t[4];

	wri_le32_put(t, v);
	so_buf_put(b, t, 4);
}

void so_buf_u64(so_buf *b, uint64_t v)
{
	uint8_t t[8];

	wri_le64_put(t, v);
	so_buf_put(b, t, 8);
}

void so_buf_str(so_buf *b, const void *p, size_t n)
{
	so_buf_u32(b, (uint32_t)n);
	so_buf_put(b, p, n);
}

/* ---- pages --------------------------------------------------------------------------------------------------------- */

static so_page *page_new(void)
{
	so_page *p = (so_page *)calloc(1, sizeof(*p));

	if (p != NULL)
		p->refs = 1;
	return p;
}

static void page_put(so_page *p)
{
	if (p != NULL && --p->refs == 0)
		free(p);
}

/* the page at index pi made private (allocated when absent if `create`, copied when shared); NULL when absent and not created, or oom */
static so_page *page_own(so_body *b, uint64_t pi, int create)
{
	so_page *p = b->pg[pi];

	if (p == NULL) {
		if (!create)
			return NULL;
		p = page_new();
		b->pg[pi] = p;
		return p;
	}
	if (p->refs > 1) {
		so_page *q = page_new();

		if (q == NULL)
			return NULL;
		memcpy(q->d, p->d, SO_PAGE);
		p->refs--;
		b->pg[pi] = q;
		return q;
	}
	return p;
}

static int pages_reserve(so_body *b, uint64_t npages)
{
	so_page **q;
	uint32_t nc;

	if (npages > (SO_MAX_STORE_OBJECT / SO_PAGE))
		return -1;
	if (npages <= b->npg)
		return 0;
	nc = b->npg != 0 ? b->npg : 16u;
	while (nc < npages)
		nc *= 2;
	q = (so_page **)realloc(b->pg, (size_t)nc * sizeof(*q));
	if (q == NULL)
		return -1;
	memset(q + b->npg, 0, (size_t)(nc - b->npg) * sizeof(*q));
	b->pg = q;
	b->npg = nc;
	return 0;
}

/* ---- sorted key / value arrays ------------------------------------------------------------------------------------- */

static int kv_cmp(const uint8_t *a, uint32_t al, const uint8_t *b, uint32_t bl)
{
	uint32_t m = al < bl ? al : bl;
	int c = m != 0 ? memcmp(a, b, m) : 0;

	if (c != 0)
		return c;
	return al < bl ? -1 : al > bl ? 1 : 0;
}

uint32_t so_kv_lower(const so_kvs *s, const void *k, uint32_t kl, int *found)
{
	uint32_t lo = 0, hi = s->n;

	while (lo < hi) {
		uint32_t mid = lo + (hi - lo) / 2;

		if (kv_cmp(s->a[mid].k, s->a[mid].kl, (const uint8_t *)k, kl) < 0)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (found != NULL)
		*found = lo < s->n && kv_cmp(s->a[lo].k, s->a[lo].kl, (const uint8_t *)k, kl) == 0;
	return lo;
}

const so_kv *so_kv_get(const so_kvs *s, const void *k, uint32_t kl)
{
	int f = 0;
	uint32_t i = so_kv_lower(s, k, kl, &f);

	return f ? &s->a[i] : NULL;
}

int so_kv_set(so_kvs *s, const void *k, uint32_t kl, const void *v, uint32_t vl)
{
	int f = 0;
	uint32_t i = so_kv_lower(s, k, kl, &f);
	uint8_t *nv = (uint8_t *)malloc(vl != 0 ? vl : 1u);

	if (nv == NULL)
		return -1;
	if (vl != 0)
		memcpy(nv, v, vl);
	if (f) {
		free(s->a[i].v);
		s->a[i].v = nv;
		s->a[i].vl = vl;
		return 0;
	} else {
		uint8_t *nk = (uint8_t *)malloc(kl != 0 ? kl : 1u);

		if (nk == NULL) {
			free(nv);
			return -1;
		}
		if (s->n == s->cap) {
			uint32_t nc = s->cap != 0 ? s->cap * 2u : 8u;
			so_kv *q = (so_kv *)realloc(s->a, (size_t)nc * sizeof(*q));

			if (q == NULL) {
				free(nv);
				free(nk);
				return -1;
			}
			s->a = q;
			s->cap = nc;
		}
		if (kl != 0)
			memcpy(nk, k, kl);
		memmove(&s->a[i + 1], &s->a[i], (size_t)(s->n - i) * sizeof(*s->a));
		s->a[i].k = nk;
		s->a[i].kl = kl;
		s->a[i].v = nv;
		s->a[i].vl = vl;
		s->n++;
		return 0;
	}
}

int so_kv_del(so_kvs *s, const void *k, uint32_t kl)
{
	int f = 0;
	uint32_t i = so_kv_lower(s, k, kl, &f);

	if (!f)
		return -1;
	free(s->a[i].k);
	free(s->a[i].v);
	memmove(&s->a[i], &s->a[i + 1], (size_t)(s->n - i - 1u) * sizeof(*s->a));
	s->n--;
	return 0;
}

static void kvs_free(so_kvs *s)
{
	uint32_t i;

	for (i = 0; i < s->n; i++) {
		free(s->a[i].k);
		free(s->a[i].v);
	}
	free(s->a);
	memset(s, 0, sizeof(*s));
}

static int kvs_dup(so_kvs *d, const so_kvs *s)
{
	uint32_t i;

	memset(d, 0, sizeof(*d));
	for (i = 0; i < s->n; i++)
		if (so_kv_set(d, s->a[i].k, s->a[i].kl, s->a[i].v, s->a[i].vl) != 0) {
			kvs_free(d);
			return -1;
		}
	return 0;
}

/* ---- the ranges that hold data ------------------------------------------------------------------------------------- */

static int ex_reserve(so_body *b, uint32_t want)
{
	uint64_t *q;
	uint32_t nc;

	if (want <= b->excap)
		return 0;
	nc = b->excap != 0 ? b->excap : 8u;
	while (nc < want)
		nc *= 2u;
	q = (uint64_t *)realloc(b->ex, (size_t)nc * 2u * sizeof(*q));
	if (q == NULL)
		return -1;
	b->ex = q;
	b->excap = nc;
	return 0;
}

/* [s, e) now holds data: it absorbs every range it touches or overlaps */
static int ex_add(so_body *b, uint64_t s, uint64_t e)
{
	uint32_t i = 0, j;

	if (s >= e)
		return 0;
	while (i < b->nex && b->ex[2u * i + 1u] < s)
		i++;
	j = i;
	while (j < b->nex && b->ex[2u * j] <= e) {
		if (b->ex[2u * j] < s)
			s = b->ex[2u * j];
		if (b->ex[2u * j + 1u] > e)
			e = b->ex[2u * j + 1u];
		j++;
	}
	if (ex_reserve(b, b->nex - (j - i) + 1u) != 0)
		return -1;
	memmove(&b->ex[2u * (i + 1u)], &b->ex[2u * j], (size_t)(b->nex - j) * 2u * sizeof(*b->ex));
	b->ex[2u * i] = s;
	b->ex[2u * i + 1u] = e;
	b->nex = b->nex - (j - i) + 1u;
	return 0;
}

/* [s, e) is a hole now (zeroed, truncated away) */
static int ex_sub(so_body *b, uint64_t s, uint64_t e)
{
	uint32_t i, k = 0;
	uint64_t *n;

	if (s >= e || b->nex == 0)
		return 0;
	if (ex_reserve(b, b->nex + 1u) != 0)
		return -1;
	n = (uint64_t *)malloc(((size_t)b->nex + 1u) * 2u * sizeof(*n)); /* a range inside one that splits it needs one slot more */
	if (n == NULL)
		return -1;
	for (i = 0; i < b->nex; i++) {
		uint64_t a = b->ex[2u * i], z = b->ex[2u * i + 1u];

		if (z <= s || a >= e) { /* untouched */
			n[2u * k] = a;
			n[2u * k + 1u] = z;
			k++;
			continue;
		}
		if (a < s) { /* the part before the hole */
			n[2u * k] = a;
			n[2u * k + 1u] = s;
			k++;
		}
		if (z > e) { /* the part after it */
			n[2u * k] = e;
			n[2u * k + 1u] = z;
			k++;
		}
	}
	memcpy(b->ex, n, (size_t)k * 2u * sizeof(*n)); /* k <= nex + 1, and excap > nex is guaranteed below */
	free(n);
	b->nex = k;
	return 0;
}

/* ---- bodies -------------------------------------------------------------------------------------------------------- */

void so_body_init(so_body *b) { memset(b, 0, sizeof(*b)); }

void so_body_clear_data(so_body *b)
{
	uint32_t i;

	free(b->ex);
	b->ex = NULL;
	b->nex = b->excap = 0;
	for (i = 0; i < b->npg; i++)
		page_put(b->pg[i]);
	free(b->pg);
	b->pg = NULL;
	b->npg = 0;
	b->size = 0;
}

void so_body_free(so_body *b)
{
	so_body_clear_data(b);
	kvs_free(&b->omap);
	kvs_free(&b->xattr);
	memset(b, 0, sizeof(*b));
}

int so_body_dup(so_body *d, const so_body *s)
{
	uint32_t i;

	memset(d, 0, sizeof(*d));
	d->size = s->size;
	d->mtime_s = s->mtime_s;
	d->mtime_ns = s->mtime_ns;
	d->user_version = s->user_version;
	if (s->nex != 0) {
		d->ex = (uint64_t *)malloc((size_t)s->nex * 2u * sizeof(*d->ex));
		if (d->ex == NULL)
			return -1; /* nothing else is allocated yet */
		memcpy(d->ex, s->ex, (size_t)s->nex * 2u * sizeof(*d->ex));
		d->nex = d->excap = s->nex;
	}
	if (s->npg != 0) {
		d->pg = (so_page **)malloc((size_t)s->npg * sizeof(*d->pg));
		if (d->pg == NULL) {
			so_body_free(d);
			return -1;
		}
		d->npg = s->npg;
		for (i = 0; i < s->npg; i++) {
			d->pg[i] = s->pg[i];
			if (d->pg[i] != NULL)
				d->pg[i]->refs++;
		}
	}
	if (kvs_dup(&d->omap, &s->omap) != 0 || kvs_dup(&d->xattr, &s->xattr) != 0) {
		so_body_free(d);
		return -1;
	}
	return 0;
}

int so_body_write(so_body *b, uint64_t off, const uint8_t *data, uint64_t n)
{
	uint64_t end = off + n, off0 = off;

	if (n == 0)
		return 0;
	if (end < off || pages_reserve(b, (end + SO_PAGE - 1u) / SO_PAGE) != 0)
		return -1;
	while (n != 0) {
		uint64_t pi = off / SO_PAGE;
		uint32_t po = (uint32_t)(off % SO_PAGE);
		uint32_t k = SO_PAGE - po;
		so_page *p;

		if (k > n)
			k = (uint32_t)n;
		p = page_own(b, pi, 1);
		if (p == NULL)
			return -1;
		memcpy(p->d + po, data, k);
		off += k;
		data += k;
		n -= k;
	}
	if (end > b->size)
		b->size = end;
	return ex_add(b, off0, end);
}

int so_body_zero(so_body *b, uint64_t off, uint64_t n)
{
	uint64_t end;

	if (off >= b->size || n == 0)
		return 0;
	end = off + n;
	if (end < off || end > b->size)
		end = b->size;
	if (ex_sub(b, off, end) != 0)
		return -1;
	while (off < end) {
		uint64_t pi = off / SO_PAGE;
		uint32_t po = (uint32_t)(off % SO_PAGE);
		uint64_t k = SO_PAGE - po;

		if (k > end - off)
			k = end - off;
		if (po == 0 && k == SO_PAGE) {
			if (pi < b->npg) {
				page_put(b->pg[pi]);
				b->pg[pi] = NULL;
			}
		} else if (pi < b->npg && b->pg[pi] != NULL) {
			so_page *p = page_own(b, pi, 0);

			if (p == NULL)
				return -1;
			memset(p->d + po, 0, (size_t)k);
		}
		off += k;
	}
	return 0;
}

int so_body_truncate(so_body *b, uint64_t size)
{
	uint64_t first, pi;

	if (size >= b->size) {
		b->size = size;
		return 0;
	}
	if (ex_sub(b, size, UINT64_MAX) != 0)
		return -1;
	first = (size + SO_PAGE - 1u) / SO_PAGE;
	for (pi = first; pi < b->npg; pi++) {
		page_put(b->pg[pi]);
		b->pg[pi] = NULL;
	}
	if (size % SO_PAGE != 0 && size / SO_PAGE < b->npg && b->pg[size / SO_PAGE] != NULL) {
		so_page *p = page_own(b, size / SO_PAGE, 0);

		if (p == NULL)
			return -1;
		memset(p->d + size % SO_PAGE, 0, SO_PAGE - (size_t)(size % SO_PAGE));
	}
	b->size = size;
	return 0;
}

void so_body_read(const so_body *b, uint64_t off, uint8_t *out, uint64_t n)
{
	while (n != 0) {
		uint64_t pi = off / SO_PAGE;
		uint32_t po = (uint32_t)(off % SO_PAGE);
		uint64_t k = SO_PAGE - po;

		if (k > n)
			k = n;
		if (pi < b->npg && b->pg[pi] != NULL && off < b->size)
			memcpy(out, b->pg[pi]->d + po, (size_t)k);
		else
			memset(out, 0, (size_t)k);
		off += k;
		out += k;
		n -= k;
	}
}

uint64_t *so_body_extents(const so_body *b, uint64_t off, uint64_t len, uint32_t *n)
{
	uint64_t end;
	uint64_t *ex;
	uint32_t i, cnt = 0;

	*n = 0;
	ex = (uint64_t *)calloc((size_t)b->nex * 2u + 2u, sizeof(uint64_t));
	if (ex == NULL || off >= b->size || len == 0)
		return ex;
	end = off + len;
	if (end < off || end > b->size)
		end = b->size;
	for (i = 0; i < b->nex; i++) { /* the ranges that hold data, clipped to the request and the size */
		uint64_t s = b->ex[2u * i], e = b->ex[2u * i + 1u];

		if (e <= off || s >= end)
			continue;
		if (s < off)
			s = off;
		if (e > end)
			e = end;
		ex[2u * cnt] = s;
		ex[2u * cnt + 1u] = e - s;
		cnt++;
	}
	*n = cnt;
	return ex;
}

/* ---- objects ------------------------------------------------------------------------------------------------------- */

void so_key_build(uint8_t *out, uint32_t *klen, const uint8_t *nspace, uint32_t nl, const uint8_t *oid, uint32_t ol)
{
	uint32_t k = 0;

	if (nl != 0) {
		memcpy(out, nspace, nl);
		k = nl;
		out[k++] = 0x1f;
	}
	if (ol != 0)
		memcpy(out + k, oid, ol);
	*klen = k + ol;
}

static uint32_t key_hash(int64_t pool, const uint8_t *key, uint32_t klen)
{
	uint32_t h = 2166136261u ^ (uint32_t)pool;
	uint32_t i;

	for (i = 0; i < klen; i++)
		h = (h ^ key[i]) * 16777619u;
	return h;
}

so_obj *so_obj_find(const sim_store *s, int64_t pool, const uint8_t *key, uint32_t klen)
{
	so_obj *o;

	if (s->nb == 0)
		return NULL;
	for (o = s->bucket[key_hash(pool, key, klen) % s->nb]; o != NULL; o = o->next)
		if (o->pool == pool && o->klen == klen && (klen == 0 || memcmp(o->key, key, klen) == 0))
			return o;
	return NULL;
}

static int store_rehash(sim_store *s, uint32_t nb)
{
	so_obj **nbk = (so_obj **)calloc(nb, sizeof(*nbk));
	uint32_t i;

	if (nbk == NULL)
		return -1;
	for (i = 0; i < s->nb; i++) {
		so_obj *o = s->bucket[i], *nx;

		for (; o != NULL; o = nx) {
			uint32_t h = key_hash(o->pool, o->key, o->klen) % nb;

			nx = o->next;
			o->next = nbk[h];
			nbk[h] = o;
		}
	}
	free(s->bucket);
	s->bucket = nbk;
	s->nb = nb;
	return 0;
}

so_obj *so_obj_get(sim_store *s, int64_t pool, const uint8_t *key, uint32_t klen)
{
	so_obj *o = so_obj_find(s, pool, key, klen);
	uint32_t h;

	if (o != NULL)
		return o;
	if (s->nb == 0 || s->nobj > s->nb * 2u)
		if (store_rehash(s, s->nb != 0 ? s->nb * 4u : 64u) != 0 && s->nb == 0)
			return NULL;
	o = (so_obj *)calloc(1, sizeof(*o));
	if (o == NULL)
		return NULL;
	o->key = (uint8_t *)malloc(klen != 0 ? klen : 1u);
	if (o->key == NULL) {
		free(o);
		return NULL;
	}
	if (klen != 0)
		memcpy(o->key, key, klen);
	o->klen = klen;
	o->pool = pool;
	h = key_hash(pool, key, klen) % s->nb;
	o->next = s->bucket[h];
	s->bucket[h] = o;
	s->nobj++;
	return o;
}

static void clones_free(so_obj *o)
{
	uint32_t i;

	for (i = 0; i < o->nclones; i++) {
		free(o->clones[i].snaps);
		so_body_free(&o->clones[i].b);
	}
	free(o->clones);
	o->clones = NULL;
	o->nclones = o->ccap = 0;
}

void so_obj_wipe(so_obj *o)
{
	so_body_free(&o->head);
	clones_free(o);
	o->exists = o->whiteout = 0;
	o->snapseq = 0;
}

void so_obj_purge(sim_store *s, so_obj *o)
{
	so_obj **pp;

	if (s->nb != 0)
		for (pp = &s->bucket[key_hash(o->pool, o->key, o->klen) % s->nb]; *pp != NULL; pp = &(*pp)->next)
			if (*pp == o) {
				*pp = o->next;
				break;
			}
	so_obj_wipe(o);
	free(o->key);
	free(o);
	s->nobj--;
}

int so_obj_copy_state(so_obj *dst, const so_obj *src)
{
	uint32_t i;

	so_obj_wipe(dst);
	dst->exists = src->exists;
	dst->whiteout = src->whiteout;
	dst->snapseq = src->snapseq;
	if (so_body_dup(&dst->head, &src->head) != 0)
		return -1;
	if (src->nclones != 0) {
		dst->clones = (so_clone *)calloc(src->nclones, sizeof(*dst->clones));
		if (dst->clones == NULL) {
			so_obj_wipe(dst);
			return -1;
		}
		dst->ccap = src->nclones;
		for (i = 0; i < src->nclones; i++) {
			so_clone *d = &dst->clones[i];
			const so_clone *c = &src->clones[i];

			d->id = c->id;
			d->nsnaps = c->nsnaps;
			d->snaps = (uint64_t *)malloc((size_t)(c->nsnaps != 0 ? c->nsnaps : 1u) * sizeof(uint64_t));
			if (d->snaps == NULL || so_body_dup(&d->b, &c->b) != 0) {
				free(d->snaps);
				d->snaps = NULL;
				dst->nclones = i;
				so_obj_wipe(dst);
				return -1;
			}
			memcpy(d->snaps, c->snaps, (size_t)c->nsnaps * sizeof(uint64_t));
			dst->nclones = i + 1u;
		}
	}
	return 0;
}

void so_obj_move_state(so_obj *dst, so_obj *src)
{
	so_obj_wipe(dst);
	dst->exists = src->exists;
	dst->whiteout = src->whiteout;
	dst->snapseq = src->snapseq;
	dst->head = src->head;
	dst->clones = src->clones;
	dst->nclones = src->nclones;
	dst->ccap = src->ccap;
	memset(&src->head, 0, sizeof(src->head));
	src->clones = NULL;
	src->nclones = src->ccap = 0;
	src->exists = src->whiteout = 0;
}

int so_obj_add_clone(so_obj *o, uint64_t id, const uint64_t *snaps, uint32_t n, const so_body *from)
{
	so_clone *c;

	if (o->nclones == o->ccap) {
		uint32_t nc = o->ccap != 0 ? o->ccap * 2u : 4u;
		so_clone *q = (so_clone *)realloc(o->clones, (size_t)nc * sizeof(*q));

		if (q == NULL)
			return -1;
		o->clones = q;
		o->ccap = nc;
	}
	c = &o->clones[o->nclones];
	memset(c, 0, sizeof(*c));
	c->id = id;
	c->snaps = (uint64_t *)malloc((size_t)(n != 0 ? n : 1u) * sizeof(uint64_t));
	if (c->snaps == NULL)
		return -1;
	memcpy(c->snaps, snaps, (size_t)n * sizeof(uint64_t));
	c->nsnaps = n;
	if (so_body_dup(&c->b, from) != 0) {
		free(c->snaps);
		return -1;
	}
	o->nclones++;
	return 0;
}

const so_body *so_obj_at(const so_obj *o, uint64_t snapid)
{
	uint32_t i;

	if (snapid == SO_SNAP_NOSNAP || snapid > o->snapseq)
		return o->exists ? &o->head : NULL;
	for (i = 0; i < o->nclones; i++)
		if (o->clones[i].id >= snapid) {
			const so_clone *c = &o->clones[i];
			uint32_t k;

			for (k = 0; k < c->nsnaps; k++)
				if (c->snaps[k] == snapid)
					return &c->b;
			return NULL;
		}
	return NULL;
}

/* ---- duplicate log ------------------------------------------------------------------------------------------------- */

static uint32_t dd_hash(uint64_t gid, uint64_t tid)
{
	uint64_t x = gid * 0x9e3779b97f4a7c15ull ^ (tid + 0x7f4a7c15ull) * 0xbf58476d1ce4e5b9ull;

	return (uint32_t)(x >> 32) & (SO_DEDUP_N - 1u);
}

const so_dedup *so_dedup_find(const sim_store *s, uint64_t gid, uint64_t tid, uint32_t inc)
{
	uint32_t i = s->dd_head[dd_hash(gid, tid)];

	while (i != 0) {
		const so_dedup *e = &s->dd[i - 1u];

		if (e->valid && e->gid == gid && e->tid == tid && e->inc == inc)
			return e;
		i = e->next;
	}
	return NULL;
}

void so_dedup_add(sim_store *s, const so_dedup *e)
{
	uint32_t slot = s->dd_pos++ & (SO_DEDUP_N - 1u);
	so_dedup *d = &s->dd[slot];

	if (d->valid) { /* the oldest entry leaves the log: unlink it from its chain */
		uint32_t *pp = &s->dd_head[dd_hash(d->gid, d->tid)];

		while (*pp != 0 && *pp != slot + 1u)
			pp = &s->dd[*pp - 1u].next;
		if (*pp == slot + 1u)
			*pp = d->next;
		s->dd_count--;
	}
	*d = *e;
	d->valid = 1;
	d->next = s->dd_head[dd_hash(e->gid, e->tid)];
	s->dd_head[dd_hash(e->gid, e->tid)] = slot + 1u;
	s->dd_count++;
}

/* ---- the public store ---------------------------------------------------------------------------------------------- */

sim_store *sim_store_new(void)
{
	sim_store *s = (sim_store *)calloc(1, sizeof(*s));

	if (s == NULL)
		return NULL;
	s->dd = (so_dedup *)calloc(SO_DEDUP_N, sizeof(*s->dd));
	s->dd_head = (uint32_t *)calloc(SO_DEDUP_N, sizeof(*s->dd_head));
	s->now_s = 1700000000u;
	if (s->dd == NULL || s->dd_head == NULL || store_rehash(s, 64u) != 0) {
		sim_store_free(s);
		return NULL;
	}
	return s;
}

void sim_store_free(sim_store *s)
{
	uint32_t i;

	if (s == NULL)
		return;
	for (i = 0; i < s->nb; i++)
		while (s->bucket[i] != NULL)
			so_obj_purge(s, s->bucket[i]);
	free(s->bucket);
	free(s->dd);
	free(s->dd_head);
	free(s);
}

static so_obj *lookup(const sim_store *s, int64_t pool, const char *oid)
{
	return so_obj_find(s, pool, (const uint8_t *)oid, (uint32_t)strlen(oid));
}

static so_obj *lookup_live(const sim_store *s, int64_t pool, const char *oid)
{
	so_obj *o = lookup(s, pool, oid);

	return o != NULL && o->exists ? o : NULL;
}

/* the head, created on a direct write */
static so_obj *head_for_write(sim_store *s, int64_t pool, const char *oid)
{
	so_obj *o = so_obj_get(s, pool, (const uint8_t *)oid, (uint32_t)strlen(oid));

	if (o != NULL && !o->exists) {
		o->exists = 1;
		o->whiteout = 0;
	}
	return o;
}

wr_status sim_store_write(sim_store *s, int64_t pool, const char *oid, uint64_t off, const uint8_t *data, size_t n)
{
	so_obj *o = head_for_write(s, pool, oid);

	if (o == NULL)
		return WR_E_BUDGET;
	if (so_body_write(&o->head, off, data, n) != 0)
		return WR_E_BUDGET;
	o->head.user_version++;
	return WR_OK;
}

wr_status sim_store_read(sim_store *s, int64_t pool, const char *oid, uint64_t off, uint8_t *out, size_t n, int *exists)
{
	return sim_store_read_snap(s, pool, oid, SO_SNAP_NOSNAP, off, out, n, exists);
}

wr_status sim_store_read_snap(sim_store *s, int64_t pool, const char *oid, uint64_t snapid, uint64_t off, uint8_t *out, size_t n, int *exists)
{
	so_obj *o = lookup(s, pool, oid);
	const so_body *b = o != NULL ? so_obj_at(o, snapid) : NULL;

	if (exists != NULL)
		*exists = b != NULL;
	if (b == NULL) {
		memset(out, 0, n);
		return WR_OK;
	}
	so_body_read(b, off, out, n);
	return WR_OK;
}

wr_status sim_store_size(sim_store *s, int64_t pool, const char *oid, uint64_t *size)
{
	so_obj *o = lookup_live(s, pool, oid);

	if (o == NULL)
		return WR_E_RANGE;
	*size = o->head.size;
	return WR_OK;
}

uint32_t sim_store_n_objects(const sim_store *s)
{
	uint32_t i, n = 0;

	for (i = 0; i < s->nb; i++) {
		const so_obj *o;

		for (o = s->bucket[i]; o != NULL; o = o->next)
			n += o->exists;
	}
	return n;
}

int sim_store_exists(const sim_store *s, int64_t pool, const char *oid) { return lookup_live(s, pool, oid) != NULL; }

int sim_store_is_whiteout(const sim_store *s, int64_t pool, const char *oid)
{
	const so_obj *o = lookup(s, pool, oid);

	return o != NULL && o->whiteout;
}

uint32_t sim_store_n_clones(const sim_store *s, int64_t pool, const char *oid)
{
	const so_obj *o = lookup(s, pool, oid);

	return o != NULL ? o->nclones : 0;
}

wr_status sim_store_remove(sim_store *s, int64_t pool, const char *oid)
{
	so_obj *o = lookup(s, pool, oid);

	if (o == NULL || (!o->exists && !o->whiteout))
		return WR_E_RANGE;
	so_obj_purge(s, o);
	return WR_OK;
}

wr_status sim_store_omap_set(sim_store *s, int64_t pool, const char *oid, const char *key, const uint8_t *val, size_t n)
{
	so_obj *o = head_for_write(s, pool, oid);

	if (o == NULL || so_kv_set(&o->head.omap, key, (uint32_t)strlen(key), val, (uint32_t)n) != 0)
		return WR_E_BUDGET;
	o->head.user_version++;
	return WR_OK;
}

wr_status sim_store_omap_rm(sim_store *s, int64_t pool, const char *oid, const char *key)
{
	so_obj *o = lookup_live(s, pool, oid);

	if (o == NULL || so_kv_del(&o->head.omap, key, (uint32_t)strlen(key)) != 0)
		return WR_E_RANGE;
	o->head.user_version++;
	return WR_OK;
}

static wr_status kv_out(const so_kv *kv, uint8_t *out, size_t cap, size_t *n)
{
	if (kv == NULL)
		return WR_E_RANGE;
	if (n != NULL)
		*n = kv->vl;
	if (out != NULL && cap >= kv->vl && kv->vl != 0)
		memcpy(out, kv->v, kv->vl);
	return out != NULL && cap < kv->vl ? WR_E_TOOBIG : WR_OK;
}

wr_status sim_store_omap_get(sim_store *s, int64_t pool, const char *oid, const char *key, uint8_t *out, size_t cap, size_t *n)
{
	so_obj *o = lookup_live(s, pool, oid);

	return kv_out(o != NULL ? so_kv_get(&o->head.omap, key, (uint32_t)strlen(key)) : NULL, out, cap, n);
}

wr_status sim_store_xattr_set(sim_store *s, int64_t pool, const char *oid, const char *name, const uint8_t *val, size_t n)
{
	so_obj *o = head_for_write(s, pool, oid);

	if (o == NULL || so_kv_set(&o->head.xattr, name, (uint32_t)strlen(name), val, (uint32_t)n) != 0)
		return WR_E_BUDGET;
	o->head.user_version++;
	return WR_OK;
}

wr_status sim_store_xattr_get(sim_store *s, int64_t pool, const char *oid, const char *name, uint8_t *out, size_t cap, size_t *n)
{
	so_obj *o = lookup_live(s, pool, oid);

	return kv_out(o != NULL ? so_kv_get(&o->head.xattr, name, (uint32_t)strlen(name)) : NULL, out, cap, n);
}

uint64_t sim_store_version(const sim_store *s, int64_t pool, const char *oid)
{
	const so_obj *o = lookup_live(s, pool, oid);

	return o != NULL ? o->head.user_version : 0;
}

void sim_store_set_time(sim_store *s, uint64_t sec) { s->now_s = sec; }

int sim_store_dedup_has(const sim_store *s, uint64_t global_id, uint64_t tid)
{
	uint32_t i = s->dd_head[dd_hash(global_id, tid)];

	while (i != 0) {
		const so_dedup *e = &s->dd[i - 1u];

		if (e->valid && e->gid == global_id && e->tid == tid)
			return 1;
		i = e->next;
	}
	return 0;
}

uint32_t sim_store_dedup_count(const sim_store *s) { return s->dd_count; }
