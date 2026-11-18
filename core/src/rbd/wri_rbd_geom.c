/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_geom.c - the pure part of image I/O: geometry of the default layout (byte range to object extents), the object name
 * builders, the overlap test of the fence, the discard shape and the mapping of an object operation's result (design 25.2, 25.3,
 * 25.6; spec: rbd-format2.md 2.1, 2.9 to 2.11, 3.5, 3.7).
 *
 * Nothing here allocates, keeps state or calls the host: every function is a computation over its arguments, so the whole module
 * is callable from any context (the I/O path of a kernel driver included) and is tested exhaustively against a per-byte model.
 */
#include "wri_rbd_io.h"

WR_FILE_LICENCE_MIT

#define GEOM_ORDER_MIN 12u
#define GEOM_ORDER_MAX 25u
#define NAME_LIMIT (WRI_RBD_OBJNAME_MAX - 1u) /* longest object name in bytes, without the NUL */

/* ---- geometry ----------------------------------------------------------------------------------------------------- */

/* A geometry is usable only if it is what wri_rbd_geom_init produces: the two fields describe the same power of two inside the accepted
 * orders. A struct that was never initialised, was zeroed by a failed init, or was damaged yields empty answers instead of a shift by an
 * order of 64 or more (undefined) or a mask that is not a mask. */
static int geom_ok(const wri_rbd_geom *g)
{
	return g != NULL && g->order >= GEOM_ORDER_MIN && g->order <= GEOM_ORDER_MAX && g->object_size == ((uint64_t)1 << g->order);
}

wr_status wri_rbd_geom_init(wri_rbd_geom *g, uint8_t order)
{
	unsigned i;

	if (g == NULL)
		return WR_E_INVAL;
	g->object_size = 0;
	g->order = 0;
	for (i = 0; i < sizeof(g->reserved8); i++)
		g->reserved8[i] = 0;
	if (order < GEOM_ORDER_MIN || order > GEOM_ORDER_MAX)
		return WR_E_RBD_ORDER;
	g->order = order;
	g->object_size = (uint64_t)1 << order;
	return WR_OK;
}

uint64_t wri_rbd_geom_objects(const wri_rbd_geom *g, uint64_t size)
{
	if (!geom_ok(g))
		return 0;
	/* ceil without an addition that could wrap near 2^64 */
	return (size >> g->order) + ((size & (g->object_size - 1u)) != 0u ? 1u : 0u);
}

void wri_rbd_geom_extent(const wri_rbd_geom *g, uint64_t off, uint64_t len, uint32_t max_run, uint64_t *objno, uint64_t *obj_off,
			 uint32_t *run)
{
	uint64_t in_obj, room, n;

	/* A broken call (no geometry, nothing to cover, no room to run) yields an empty extent rather than a run that never advances. */
	if (!geom_ok(g) || len == 0 || max_run == 0) {
		*objno = 0;
		*obj_off = 0;
		*run = 0;
		return;
	}
	in_obj = off & (g->object_size - 1u);
	room = g->object_size - in_obj; /* 1 .. object_size */
	n = len < room ? len : room;
	if (n > max_run)
		n = max_run;
	*objno = off >> g->order;
	*obj_off = in_obj;
	*run = (uint32_t)n; /* n <= max_run */
}

/* ---- names -------------------------------------------------------------------------------------------------------- */

/* Length of s up to `limit` bytes; limit + 1 if it is longer (or s is NULL: reported as empty, 0). */
static size_t bounded_len(const char *s, size_t limit)
{
	size_t n = 0;

	if (s == NULL)
		return 0;
	while (n <= limit && s[n] != '\0')
		n++;
	return n;
}

/* out = lead + body, as one NUL-terminated name of at most NAME_LIMIT bytes; the body must not be empty. */
static size_t cat_name(char *out, size_t cap, const char *lead, size_t lead_len, const char *body)
{
	size_t blen, total, i;

	if (out == NULL || cap == 0)
		return 0;
	out[0] = '\0';
	blen = bounded_len(body, NAME_LIMIT);
	if (blen == 0 || blen > NAME_LIMIT - lead_len)
		return 0;
	total = lead_len + blen;
	if (total >= cap)
		return 0;
	for (i = 0; i < lead_len; i++)
		out[i] = lead[i];
	for (i = 0; i < blen; i++)
		out[lead_len + i] = body[i];
	out[total] = '\0';
	return total;
}

size_t wri_rbd_obj_name(char *out, size_t cap, const char *prefix, uint64_t objno)
{
	static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	size_t plen, total, i;
	unsigned d;

	if (out == NULL || cap == 0)
		return 0;
	out[0] = '\0';
	plen = bounded_len(prefix, NAME_LIMIT);
	/* an empty prefix is no prefix; the name is prefix + '.' + 16 digits and must fit 95 bytes (and the caller's buffer) */
	if (plen == 0 || plen + 17u > NAME_LIMIT)
		return 0;
	total = plen + 17u;
	if (total >= cap)
		return 0;
	for (i = 0; i < plen; i++)
		out[i] = prefix[i];
	out[plen] = '.';
	for (d = 0; d < 16u; d++)
		out[plen + 1u + d] = hex[(unsigned)((objno >> (60u - 4u * d)) & 0xfu)];
	out[total] = '\0';
	return total;
}

size_t wri_rbd_id_obj_name(char *out, size_t cap, const char *name)
{
	return cat_name(out, cap, "rbd_id.", 7u, name);
}

size_t wri_rbd_header_obj_name(char *out, size_t cap, const char *id)
{
	return cat_name(out, cap, "rbd_header.", 11u, id);
}

/* ---- fence -------------------------------------------------------------------------------------------------------- */

int wri_rbd_overlap(uint64_t a_off, uint64_t a_len, uint64_t b_off, uint64_t b_len)
{
	if (a_len == 0 || b_len == 0)
		return 0;
	/* The range that starts first must reach the start of the other. The distance of the two starts is exact (a subtraction of
	 * the smaller from the larger), so no end offset is ever formed and a range that runs to or past 2^64 cannot wrap. */
	if (a_off <= b_off)
		return (b_off - a_off) < a_len ? 1 : 0;
	return (a_off - b_off) < b_len ? 1 : 0;
}

/* ---- discard and results ------------------------------------------------------------------------------------------ */

uint16_t wri_rbd_discard_op(const wri_rbd_geom *g, uint64_t obj_off, uint32_t run)
{
	uint64_t os;

	if (!geom_ok(g) || run == 0 || obj_off >= g->object_size)
		return WRI_OSD_OP_ZERO; /* not an extent of this geometry: the harmless shape */
	os = g->object_size;
	if (obj_off == 0 && (uint64_t)run == os)
		return WRI_OSD_OP_DELETE;
	if ((uint64_t)run == os - obj_off)
		return WRI_OSD_OP_TRUNCATE; /* reaches the object's end, and obj_off > 0 here */
	return WRI_OSD_OP_ZERO;
}

wr_status wri_rbd_op_status(uint16_t code, int32_t result, int *zero_fill)
{
	if (zero_fill != NULL)
		*zero_fill = 0;
	if (result == -WRI_ERRNO_ENOENT) {
		/* A missing object is a hole: reads see zeros, the others have nothing to remove or clear (no parent, design 25.3). */
		if (code == WRI_OSD_OP_READ) {
			if (zero_fill != NULL)
				*zero_fill = 1;
			return WR_OK;
		}
		if (code == WRI_OSD_OP_DELETE || code == WRI_OSD_OP_ZERO || code == WRI_OSD_OP_TRUNCATE)
			return WR_OK;
	}
	return wri_osd_errno_status(result);
}
