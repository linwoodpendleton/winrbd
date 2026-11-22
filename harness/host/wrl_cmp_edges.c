/* SPDX-License-Identifier: MIT */
/*
 * wrl_cmp_edges.c - the deterministic edge list of the krbd comparison (docs/design/core-architecture.md 33.3, phase "edges").
 *
 * A pure function of the geometry (image size, object order, device sector): the same input gives the same ordered list, so a
 * difference found in an edge op is reproducible without a seed, and the test can check that every class listed in wrl_cmp.h is
 * covered at every order. The classes of an op are derived from its numbers (a range that ends one byte past a boundary is
 * END_AFTER whichever code emitted it), so the coverage claim cannot drift from the list.
 *
 * The order matters: the model, not the generator, decides what a read must return, but the classes name the state the image is
 * in ("a hole", "written before"). So the list begins with the reads of a never-written image, writes to a fresh object before
 * it is rewritten, and fills an object before it discards or zeroes it. Object numbers are clamped to the image, so a very small
 * image still gets a valid (if less varied) list.
 */
#include <string.h>

#include "wrl_cmp.h"

typedef struct ectx {
	const wrl_cmp_geom *g;
	wrl_cmp_edge *out;
	uint32_t cap, n;
	uint64_t obj, nobj, last_start, last_len;
} ectx;

static const char *const g_class_names[WRL_EC_COUNT] = {
	"read_hole", "obj_first", "obj_last", "img_first", "img_last", "lastobj_first", "lastobj_last", "lastobj_whole",
	"end_at", "end_before", "end_after", "start_at", "start_before", "start_after",
	"len_1", "len_512", "len_4095", "len_4096", "len_4097", "len_obj1", "len_obj2", "len_obj3",
	"zero_obj", "discard_obj", "discard_part", "zeroes", "over_hole", "over_written", "over_half", "past_end", "unaligned", "flush"};

const char *wrl_cmp_class_name(unsigned cls)
{
	return cls < WRL_EC_COUNT ? g_class_names[cls] : "?";
}

#define BIT(c) (1ull << (c))

/* The classes an op has by its numbers alone. */
static uint64_t auto_classes(const ectx *x, unsigned kind, uint64_t off, uint64_t len)
{
	uint64_t c = 0, end = off + len, o = x->obj;

	if (kind == WRL_CMP_K_FLUSH)
		return BIT(WRL_EC_FLUSH);
	if (kind == WRL_CMP_K_PAST)
		return BIT(WRL_EC_PAST_END) | (off % x->g->sector != 0u ? BIT(WRL_EC_UNALIGNED) : 0u);
	if (len == 1u) {
		c |= BIT(WRL_EC_LEN_1);
		if (off % o == 0u)
			c |= BIT(WRL_EC_OBJ_FIRST);
		if (off % o == o - 1u)
			c |= BIT(WRL_EC_OBJ_LAST);
		if (off == 0u)
			c |= BIT(WRL_EC_IMG_FIRST);
		if (off == x->g->size - 1u)
			c |= BIT(WRL_EC_IMG_LAST) | BIT(WRL_EC_LASTOBJ_LAST);
		if (off == x->last_start)
			c |= BIT(WRL_EC_LASTOBJ_FIRST);
	}
	if (len == 512u)
		c |= BIT(WRL_EC_LEN_512);
	if (len == 4095u)
		c |= BIT(WRL_EC_LEN_4095);
	if (len == 4096u)
		c |= BIT(WRL_EC_LEN_4096);
	if (len == 4097u)
		c |= BIT(WRL_EC_LEN_4097);
	if (len == o)
		c |= BIT(WRL_EC_LEN_OBJ1);
	if (len == 2u * o)
		c |= BIT(WRL_EC_LEN_OBJ2);
	if (len == 3u * o)
		c |= BIT(WRL_EC_LEN_OBJ3);
	if (off == x->last_start && len == x->last_len)
		c |= BIT(WRL_EC_LASTOBJ_WHOLE);
	if (end % o == 0u)
		c |= BIT(WRL_EC_END_AT);
	if (end % o == o - 1u)
		c |= BIT(WRL_EC_END_BEFORE);
	if (end % o == 1u)
		c |= BIT(WRL_EC_END_AFTER);
	if (off % o == 0u)
		c |= BIT(WRL_EC_START_AT);
	if (off % o == o - 1u)
		c |= BIT(WRL_EC_START_BEFORE);
	if (off % o == 1u)
		c |= BIT(WRL_EC_START_AFTER);
	if (off % x->g->sector != 0u)
		c |= BIT(WRL_EC_UNALIGNED);
	if (kind == WRL_CMP_K_ZEROES)
		c |= BIT(WRL_EC_ZEROES);
	if (kind == WRL_CMP_K_DISCARD) {
		int whole = (off % o == 0u && len == o) || (off == x->last_start && len == x->last_len);

		c |= whole ? BIT(WRL_EC_DISCARD_OBJ) : BIT(WRL_EC_DISCARD_PART);
	}
	return c;
}

/* Add an op; ranges outside the image are skipped (never an error: a small image just has a shorter list). */
static void emit(ectx *x, unsigned kind, uint64_t off, uint64_t len, unsigned pat, uint64_t extra)
{
	uint64_t cls;

	if (kind != WRL_CMP_K_FLUSH && kind != WRL_CMP_K_PAST) {
		if (len == 0u || off > x->g->size || len > x->g->size - off)
			return;
	}
	cls = auto_classes(x, kind, off, len) | extra;
	if (kind == WRL_CMP_K_WRITE && pat == 1u && off % x->obj == 0u && (len == x->obj || (off == x->last_start && len == x->last_len)))
		cls |= BIT(WRL_EC_ZERO_OBJ);
	if (x->out != NULL && x->n < x->cap) {
		wrl_cmp_edge *e = &x->out[x->n];

		memset(e, 0, sizeof(*e));
		e->kind = (uint8_t)kind;
		e->pat = (uint8_t)pat;
		e->off = off;
		e->len = len;
		e->classes = cls;
	}
	x->n++;
}

static uint64_t objc(const ectx *x, uint64_t k)
{
	return k < x->nobj ? k : x->nobj - 1u;
}

/* The whole object k (the last one is partial: its real length). */
static void obj_range(const ectx *x, uint64_t k, uint64_t *off, uint64_t *len)
{
	k = objc(x, k);
	*off = k * x->obj;
	*len = k == x->nobj - 1u ? x->last_len : x->obj;
}

static void fill_obj(ectx *x, uint64_t k, uint64_t extra)
{
	uint64_t off, len;

	obj_range(x, k, &off, &len);
	emit(x, WRL_CMP_K_WRITE, off, len, 0, extra);
}

uint32_t wrl_cmp_edges_build(const wrl_cmp_geom *g, wrl_cmp_edge *out, uint32_t cap)
{
	static const uint64_t small[5] = {1, 512, 4095, 4096, 4097};
	ectx x;
	uint64_t bnd[3], mid, h, k, off, len, s = 0, e = 0;
	unsigned i, j, nb, v;

	if (g == NULL || g->size == 0u || g->order < 9u || g->order > 30u || g->sector < 512u || (g->sector & (g->sector - 1u)) != 0u)
		return 0;
	memset(&x, 0, sizeof(x));
	x.g = g;
	x.out = out;
	x.cap = cap;
	x.obj = 1ull << g->order;
	x.nobj = (g->size + x.obj - 1u) / x.obj;
	x.last_start = (x.nobj - 1u) * x.obj;
	x.last_len = g->size - x.last_start;
	mid = x.nobj / 2u;
	h = mid; /* the object no edge writes before section E: reads of it are reads of a hole */

	/* A. reads of an image nobody has written */
	emit(&x, WRL_CMP_K_READ, 0, 1, 0, BIT(WRL_EC_READ_HOLE));
	emit(&x, WRL_CMP_K_READ, 0, g->size < 4096u ? g->size : 4096u, 0, BIT(WRL_EC_READ_HOLE));
	obj_range(&x, 0, &off, &len);
	emit(&x, WRL_CMP_K_READ, off, len, 0, BIT(WRL_EC_READ_HOLE));
	obj_range(&x, h, &off, &len);
	emit(&x, WRL_CMP_K_READ, off, len, 0, BIT(WRL_EC_READ_HOLE));
	emit(&x, WRL_CMP_K_READ, h * x.obj + x.obj - 1u, 1, 0, BIT(WRL_EC_READ_HOLE));
	if (h > 0u)
		emit(&x, WRL_CMP_K_READ, h * x.obj - 1u, x.obj < 8192u ? x.obj + 2u : 8194u, 0, BIT(WRL_EC_READ_HOLE));
	emit(&x, WRL_CMP_K_READ, x.last_start, x.last_len, 0, BIT(WRL_EC_READ_HOLE));
	emit(&x, WRL_CMP_K_READ, g->size - 1u, 1, 0, BIT(WRL_EC_READ_HOLE));
	if (g->size > 4097u)
		emit(&x, WRL_CMP_K_READ, g->size - 4097u, 4097, 0, BIT(WRL_EC_READ_HOLE));
	for (i = 1; i <= 3u; i++) { /* one, two and three objects long, from a boundary and from one byte before it */
		k = objc(&x, mid / 2u);
		emit(&x, WRL_CMP_K_READ, k * x.obj, i * x.obj, 0, BIT(WRL_EC_READ_HOLE));
		if (k > 0u)
			emit(&x, WRL_CMP_K_READ, k * x.obj - 1u, i * x.obj + 2u, 0, BIT(WRL_EC_READ_HOLE));
	}

	/* B. the first and the last byte of the image, of objects, of the last object (random and offset patterns) */
	emit(&x, WRL_CMP_K_WRITE, 0, 1, 2, 0);
	emit(&x, WRL_CMP_K_WRITE, x.obj - 1u, 1, 0, 0);
	emit(&x, WRL_CMP_K_WRITE, x.obj, 1, 2, 0);
	emit(&x, WRL_CMP_K_WRITE, 2u * x.obj - 1u, 1, 0, 0);
	emit(&x, WRL_CMP_K_WRITE, objc(&x, 3) * x.obj, 1, 0, 0);
	emit(&x, WRL_CMP_K_WRITE, objc(&x, 4) * x.obj - 1u, 1, 2, 0);
	emit(&x, WRL_CMP_K_WRITE, x.last_start, 1, 0, 0);
	emit(&x, WRL_CMP_K_WRITE, g->size - 1u, 1, 2, 0);
	if (g->size >= 2u)
		emit(&x, WRL_CMP_K_WRITE, g->size - 2u, 1, 0, 0);

	/* C. ranges around boundaries: ending at / one before / one after, starting at / one before / one after, at every length */
	nb = 0;
	if (x.nobj >= 2u)
		bnd[nb++] = x.obj;
	if (x.nobj >= 6u)
		bnd[nb++] = (mid + 1u) * x.obj; /* above the hole object, which stays untouched until E */
	if (x.nobj >= 3u)
		bnd[nb++] = x.last_start;
	for (i = 0; i < nb; i++) {
		uint64_t b = bnd[i];

		for (j = 0; j < 5u; j++) {
			len = small[j];
			for (v = 0; v < 3u; v++) {
				s = v == 0u ? b : (v == 1u ? b - 1u : b + 1u);   /* start at / one before / one after */
				e = v == 0u ? b : (v == 1u ? b - 1u : b + 1u);   /* end   at / one before / one after */
				emit(&x, WRL_CMP_K_WRITE, s, len, 0, 0);
				if (e >= len)
					emit(&x, WRL_CMP_K_WRITE, e - len, len, 0, 0);
			}
		}
		if (i == 0u || i + 1u == nb) { /* one, two and three objects, starting and ending around the first and the last boundary */
			for (j = 1; j <= 3u; j++) {
				len = j * x.obj;
				for (v = 0; v < 3u; v++) {
					s = v == 0u ? b : (v == 1u ? b - 1u : b + 1u);
					e = s;
					emit(&x, WRL_CMP_K_WRITE, s, len, 0, 0);
					if (e >= len)
						emit(&x, WRL_CMP_K_WRITE, e - len, len, 0, 0);
				}
			}
		}
	}

	/* D. the last (partial) object */
	emit(&x, WRL_CMP_K_WRITE, x.last_start, x.last_len, 0, 0);
	emit(&x, WRL_CMP_K_WRITE, g->size - 1u, 1, 0, 0);
	emit(&x, WRL_CMP_K_WRITE, g->size >= 512u ? g->size - 512u : 0u, g->size >= 512u ? 512u : g->size, 0, 0);
	emit(&x, WRL_CMP_K_WRITE, g->size >= 4097u ? g->size - 4097u : 0u, g->size >= 4097u ? 4097u : g->size, 0, 0);
	if (x.last_start >= 100u)
		emit(&x, WRL_CMP_K_WRITE, x.last_start - 100u, x.last_len + 100u < 200u ? x.last_len + 100u : 200u, 0, 0);
	emit(&x, WRL_CMP_K_WRITE, x.last_start + (x.last_len > 3u ? 3u : 0u), x.last_len > 3u ? x.last_len - 3u : x.last_len, 0, 0);
	emit(&x, WRL_CMP_K_READ, x.last_start, x.last_len, 0, 0);

	/* E. over a hole, over what was written, over half of it */
	obj_range(&x, h, &off, &len);
	if (len > 2100u) {
		emit(&x, WRL_CMP_K_WRITE, off + 100u, 1000u, 0, BIT(WRL_EC_OVER_HOLE));
		emit(&x, WRL_CMP_K_WRITE, off + 100u, 1000u, 0, BIT(WRL_EC_OVER_WRITTEN));
		emit(&x, WRL_CMP_K_WRITE, off + 600u, 1000u, 0, BIT(WRL_EC_OVER_HALF));
		emit(&x, WRL_CMP_K_WRITE, off + 1u, 2099u, 0, BIT(WRL_EC_OVER_WRITTEN));
	} else if (len > 4u) {
		emit(&x, WRL_CMP_K_WRITE, off, len / 2u, 0, BIT(WRL_EC_OVER_HOLE));
		emit(&x, WRL_CMP_K_WRITE, off, len / 2u, 0, BIT(WRL_EC_OVER_WRITTEN));
		emit(&x, WRL_CMP_K_WRITE, off + len / 4u, len / 2u, 0, BIT(WRL_EC_OVER_HALF));
	}
	k = objc(&x, mid + 3u); /* a whole object: first over a hole, then over itself, then half of it again */
	obj_range(&x, k, &off, &len);
	emit(&x, WRL_CMP_K_WRITE, off, len, 0, BIT(WRL_EC_OVER_HOLE));
	emit(&x, WRL_CMP_K_WRITE, off, len, 0, BIT(WRL_EC_OVER_WRITTEN));
	if (len >= 2u) {
		emit(&x, WRL_CMP_K_WRITE, off + len / 2u, len / 2u, 0, BIT(WRL_EC_OVER_HALF));
		emit(&x, WRL_CMP_K_WRITE, off, len / 2u + 1u, 0, BIT(WRL_EC_OVER_HALF));
	}

	/* F. whole-object zero writes, discards and write-zeroes of data that is there */
	k = 5;
	fill_obj(&x, k, 0);
	obj_range(&x, k, &off, &len);
	emit(&x, WRL_CMP_K_WRITE, off, len, 1, 0);                              /* a write of zeros over a whole object */
	k = 6;
	fill_obj(&x, k, 0);
	obj_range(&x, k, &off, &len);
	emit(&x, WRL_CMP_K_DISCARD, off, len, 0, 0);                           /* a whole object */
	k = 7;
	fill_obj(&x, k, 0);
	obj_range(&x, k, &off, &len);
	emit(&x, WRL_CMP_K_DISCARD, off, len / 2u, 0, 0);                      /* the head */
	k = 8;
	fill_obj(&x, k, 0);
	obj_range(&x, k, &off, &len);
	emit(&x, WRL_CMP_K_DISCARD, off + len / 2u, len - len / 2u, 0, 0);     /* the tail */
	k = 9;
	fill_obj(&x, k, 0);
	obj_range(&x, k, &off, &len);
	if (len > 2u * g->sector)
		emit(&x, WRL_CMP_K_DISCARD, off + g->sector, len - 2u * g->sector, 0, 0); /* the middle, sector aligned */
	emit(&x, WRL_CMP_K_DISCARD, off + 3u, len > 9u ? len - 9u : 1u, 0, 0); /* the middle, ragged: the device side rounds */
	fill_obj(&x, 10, 0);
	fill_obj(&x, 11, 0);
	obj_range(&x, objc(&x, 10), &off, &len);
	emit(&x, WRL_CMP_K_DISCARD, off + len / 2u, len, 0, 0);                 /* across two objects: half of one, half of the next */
	obj_range(&x, objc(&x, 12), &off, &len);
	fill_obj(&x, 12, 0);
	emit(&x, WRL_CMP_K_DISCARD, off + 5u, 1, 0, 0);                         /* one byte */
	emit(&x, WRL_CMP_K_DISCARD, off + 8u, 4097u < len - 8u ? 4097u : len - 8u, 0, 0);
	fill_obj(&x, x.nobj - 1u, 0);
	emit(&x, WRL_CMP_K_DISCARD, x.last_start, x.last_len, 0, 0);            /* the last, partial object, whole */
	fill_obj(&x, 13, 0);
	obj_range(&x, 13, &off, &len);
	emit(&x, WRL_CMP_K_ZEROES, off, len, 0, 0);                             /* write-zeroes of a whole object */
	fill_obj(&x, 14, 0);
	obj_range(&x, 14, &off, &len);
	emit(&x, WRL_CMP_K_ZEROES, off + 100u, len > 400u ? 300u : len / 2u + 1u, 0, 0);
	fill_obj(&x, 15, 0);
	fill_obj(&x, 16, 0);
	obj_range(&x, objc(&x, 16), &off, &len);
	if (off >= 50u)
		emit(&x, WRL_CMP_K_ZEROES, off - 50u, 100, 0, 0);                    /* across a boundary */
	emit(&x, WRL_CMP_K_ZEROES, x.last_start, x.last_len, 0, 0);

	/* G. sector aligned and ragged ranges side by side (the device side always rounds out to sectors) */
	k = objc(&x, 20);
	emit(&x, WRL_CMP_K_WRITE, k * x.obj + g->sector, 4u * g->sector, 0, 0);
	emit(&x, WRL_CMP_K_WRITE, k * x.obj + g->sector + 1u, 4u * g->sector + 3u, 0, 0);
	emit(&x, WRL_CMP_K_WRITE, k * x.obj + g->sector - 1u, 2, 0, 0);
	emit(&x, WRL_CMP_K_READ, k * x.obj, 8u * g->sector, 0, 0);

	/* H. past the end: the core and the device must refuse every one of them */
	emit(&x, WRL_CMP_K_PAST, g->size, 1, 0, 0);
	emit(&x, WRL_CMP_K_PAST, g->size, g->sector, 0, 0);
	emit(&x, WRL_CMP_K_PAST, g->size - 1u, 2, 0, 0);
	emit(&x, WRL_CMP_K_PAST, g->size + x.obj, 1, 0, 0);

	/* I. a flush, and the last bytes again after it */
	emit(&x, WRL_CMP_K_FLUSH, 0, 0, 0, 0);
	emit(&x, WRL_CMP_K_READ, g->size - 1u, 1, 0, 0);
	return x.n;
}
