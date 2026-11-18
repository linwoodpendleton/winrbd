/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_open_dec.c - what the open does with the replies and the map: the header reads cut into their eight outputs and decoded, the EXTRA
 * reads, the pools of an image, the judgement against the profile (design 24.3) and the rules of a refresh (24.4). Spec: rbd-format2.md 3.2, 3.3.
 *
 * Nothing here talks to the object engine; the map is read through the engine's map ops (wri_osd_map_ops) and the host's full-map counter.
 */
#include "wri_rbd_open.h"

#include "wri_ctx.h"
#include "wri_rbd_io.h"

WR_FILE_LICENCE_MIT

#define HDR_OPS 8u
enum { H_SIZE = 0, H_PREFIX, H_FEATURES, H_FLAGS, H_SNAPC, H_DATAPOOL, H_PARENT, H_OVERLAP };

#define FAIL(why, st, what, a0, a1, a2) \
	wri_errinfo_set((why), (st), WR_MOD_RBD, (unsigned)__LINE__, (what), (uint64_t)(a0), (uint64_t)(a1), (uint64_t)(a2))

/* ---- cutting a reply into its outputs ------------------------------------------------------------------------------------- */

/*
 * The outputs of the operations of one reply lie one after another in `out`. A failed operation (rval < 0) ends the message: its status is the
 * answer. Otherwise the lengths must add up to out_len exactly, so a reply that is short or longer than its records is refused before any
 * decoder looks at a byte.
 */
static wr_status split_check(const wri_osd_opd *ops, unsigned n_ops, unsigned want, uint32_t out_len)
{
	uint64_t sum = 0;
	unsigned i;

	if (ops == NULL || n_ops != want || want > HDR_OPS)
		return WR_E_RBD_PROTO;
	for (i = 0; i < n_ops; i++) {
		if (ops[i].rval < 0) {
			wr_status st = wri_osd_errno_status(ops[i].rval);

			return st != WR_OK ? st : WR_E_RBD_PROTO;
		}
	}
	for (i = 0; i < n_ops; i++)
		sum += ops[i].out_len;
	return sum == (uint64_t)out_len ? WR_OK : WR_E_RBD_PROTO;
}

/* The bytes of operation i (after split_check: the lengths add up to what `out` holds). */
static const uint8_t *slice(const wri_osd_opd *ops, const uint8_t *out, unsigned i, uint32_t *len)
{
	uint32_t pos = 0;
	unsigned k;

	for (k = 0; k < i; k++)
		pos += ops[k].out_len;
	*len = ops[i].out_len;
	return out != NULL ? out + pos : out;
}

static void hdr_clear(wri_rbd_hdr *h)
{
	WR_MEMSET(h, 0, sizeof(*h));
	h->data_pool_id = -1;
}

/* size, prefix, features, flags */
static wr_status dec_first(const wri_osd_opd *ops, const uint8_t *out, wri_rbd_hdr *h)
{
	uint64_t incompat = 0;
	const uint8_t *p;
	uint32_t n;
	wr_status st;

	p = slice(ops, out, H_SIZE, &n);
	st = wri_rbd_dec_size(p, n, &h->order, &h->size);
	if (st == WR_OK) {
		p = slice(ops, out, H_PREFIX, &n);
		st = wri_rbd_dec_prefix(p, n, h->prefix);
	}
	if (st == WR_OK) {
		p = slice(ops, out, H_FEATURES, &n);
		st = wri_rbd_dec_features(p, n, &h->features, &incompat);
	}
	if (st == WR_OK) {
		p = slice(ops, out, H_FLAGS, &n);
		st = wri_rbd_dec_u64(p, n, &h->flags);
	}
	return st;
}

/* data pool, parent, overlap */
static wr_status dec_second(const wri_osd_opd *ops, const uint8_t *out, wri_rbd_hdr *h)
{
	uint64_t overlap = 0;
	uint8_t present = 0, parent = 0;
	const uint8_t *p;
	uint32_t n;
	wr_status st;

	p = slice(ops, out, H_DATAPOOL, &n);
	st = wri_rbd_dec_i64(p, n, &h->data_pool_id);
	if (st == WR_OK) {
		p = slice(ops, out, H_PARENT, &n);
		st = wri_rbd_dec_parent(p, n, &parent);
	}
	if (st == WR_OK) {
		p = slice(ops, out, H_OVERLAP, &n);
		st = wri_rbd_dec_overlap(p, n, &present, &overlap);
	}
	if (st == WR_OK) {
		h->has_parent = parent != 0;
		h->has_overlap = present != 0;
		h->overlap = present != 0 ? overlap : 0;
	}
	return st;
}

wr_status wri_rbd_open_decode_header(const wri_osd_opd *ops, unsigned n_ops, const uint8_t *out, uint32_t out_len, wri_rbd_hdr *h,
				     wri_snapc *snapc, uint32_t *n_snaps_total)
{
	wr_status st;

	if (h == NULL)
		return WR_E_INVAL;
	hdr_clear(h);
	if (n_snaps_total != NULL)
		*n_snaps_total = 0;
	if (snapc != NULL) {
		snapc->seq = 0;
		snapc->n = 0;
	}
	st = split_check(ops, n_ops, HDR_OPS, out_len);
	if (st == WR_OK)
		st = dec_first(ops, out, h);
	if (st == WR_OK && snapc != NULL) {
		uint32_t n;
		const uint8_t *p = slice(ops, out, H_SNAPC, &n);

		st = wri_rbd_dec_snapcontext(p, n, snapc, n_snaps_total);
	}
	if (st == WR_OK)
		st = dec_second(ops, out, h);
	if (st != WR_OK) {
		hdr_clear(h);
		if (snapc != NULL) { /* the context decoded before the failing record is no better than the rest */
			snapc->seq = 0;
			snapc->n = 0;
		}
	}
	return st;
}

wr_status wri_rbd_open_decode_snapc(const wri_osd_opd *ops, unsigned n_ops, const uint8_t *out, uint32_t out_len, wri_snapc *snapc,
				    uint32_t *n_snaps_total)
{
	const uint8_t *p;
	uint32_t n;
	wr_status st;

	if (snapc == NULL)
		return WR_E_INVAL;
	snapc->seq = 0;
	snapc->n = 0;
	if (n_snaps_total != NULL)
		*n_snaps_total = 0;
	st = split_check(ops, n_ops, HDR_OPS, out_len);
	if (st != WR_OK)
		return st;
	p = slice(ops, out, H_SNAPC, &n);
	return wri_rbd_dec_snapcontext(p, n, snapc, n_snaps_total);
}

wr_status wri_rbd_open_probe_snapc(const wri_osd_opd *ops, unsigned n_ops, const uint8_t *out, uint32_t out_len, uint32_t cap, uint32_t *n_total)
{
	wri_rd r;
	const uint8_t *p;
	uint64_t seq, prev = 0, v;
	uint32_t n, cnt, i;
	wr_status st;

	if (n_total != NULL)
		*n_total = 0;
	st = split_check(ops, n_ops, HDR_OPS, out_len);
	if (st != WR_OK)
		return st;
	p = slice(ops, out, H_SNAPC, &n);
	wri_rd_init(&r, p, n);
	seq = wri_rd_u64(&r);
	cnt = wri_rd_u32(&r);
	if (!wri_rd_ok(&r) || (uint64_t)cnt * 8u != (uint64_t)wri_rd_left(&r))
		return WR_E_RBD_PROTO;
	if (n_total != NULL)
		*n_total = cnt;
	if (cnt > cap || seq > WRI_SNAP_MAX)
		return WR_E_RBD_SNAPC;
	for (i = 0; i < cnt; i++) {
		v = wri_rd_u64(&r);
		if (i == 0 ? v > seq : v >= prev)
			return WR_E_RBD_SNAPC;
		prev = v;
	}
	return WR_OK;
}

wr_status wri_rbd_open_decode_extra(const wri_osd_opd *ops, unsigned n_ops, const uint8_t *out, uint32_t out_len, wri_rbd_hdr *h)
{
	unsigned want = 0, k = 0;
	uint64_t unit = 0, count = 0, opf = 0;
	const uint8_t *p;
	uint32_t n;
	wr_status st;

	if (h == NULL)
		return WR_E_INVAL;
	want += (h->features & WRI_RBD_F_STRIPINGV2) != 0;
	want += (h->features & WRI_RBD_F_OPERATIONS) != 0;
	st = split_check(ops, n_ops, want, out_len);
	if (st != WR_OK)
		return st;
	if ((h->features & WRI_RBD_F_STRIPINGV2) != 0) {
		p = slice(ops, out, k++, &n);
		st = wri_rbd_dec_stripe(p, n, &unit, &count);
	}
	if (st == WR_OK && (h->features & WRI_RBD_F_OPERATIONS) != 0) {
		p = slice(ops, out, k, &n);
		st = wri_rbd_dec_u64(p, n, &opf);
	}
	if (st != WR_OK)
		return st;
	h->stripe_unit = unit;
	h->stripe_count = count;
	h->op_features = opf;
	return WR_OK;
}

/* ---- pools ---------------------------------------------------------------------------------------------------------------- */

static uint32_t full_count(const wri_rbd *r)
{
	const wri_rbd_pools *p = r->pools;

	return p != NULL && p->n_full != NULL ? p->n_full(p->ctx) : 0;
}

/* The wait for the full map ends by itself after map_stale_ms (0 = never), as the engine's wait of an operation for a pool does: tracking a pool that an
 * earlier open already tracked asks for no new full map, so "absent" would otherwise wait for one that never comes. refresh_start_ms is the start of the
 * open while the image is in POOLS. */
static int full_wait_over(const wri_rbd *r, const wri_rbd_img *m)
{
	uint32_t stale = r->x->cfg.map_stale_ms;

	return stale != 0 && r->x->now.mono_ms - m->refresh_start_ms >= stale;
}

/* One tracked pool: 0 usable, 1 wait, -1 failed. *id gets the pool id when it is found. */
static int one_pool(const wri_rbd *r, const wri_rbd_img *m, wr_pool_h h, unsigned which, int mode, wr_pool_info *pi, wr_errinfo *why)
{
	const wri_osd_map_ops *mo = &r->osd->map;
	wr_status st = mo->pool_info(mo->ctx, h, pi);

	if (st == WR_E_MAP_NONE)
		return 1;
	if (st == WR_E_POOL_NOT_FOUND) {
		/* a pool tracked after the first map reads as absent until the full map the engine asks for is adopted */
		if (mode == 0 && m->full_need != 0 && (int32_t)(full_count(r) - m->full_need) < 0 && !full_wait_over(r, m))
			return 1;
		FAIL(why, WR_E_POOL_NOT_FOUND, which == 0 ? "image pool is not in the OSD map" : "data pool is not in the OSD map", which, 0, 0);
		return -1;
	}
	if (st != WR_OK) {
		FAIL(why, st, "pool lookup failed", which, 0, 0);
		return -1;
	}
	if (mode == 0 && pi->status != WR_OK) {
		FAIL(why, pi->status, which == 0 ? "image pool cannot be used by this client" : "data pool cannot be used by this client", which,
		     (uint64_t)pi->id, pi->flags);
		return -1;
	}
	return 0;
}

int wri_rbd_open_pools(wri_rbd *r, wri_rbd_img *m, int mode, wr_errinfo *why)
{
	wr_pool_info pi, dpi;
	int rc;

	WR_MEMSET(&pi, 0, sizeof(pi));
	WR_MEMSET(&dpi, 0, sizeof(dpi));
	rc = one_pool(r, m, m->pool_h, 0, mode, &pi, why);
	if (rc != 0)
		return rc;
	if (mode != 0 && pi.id != m->pool_id) {
		FAIL(why, WR_E_POOL_NOT_FOUND, "image pool was replaced (its id changed)", 0, (uint64_t)m->pool_id, (uint64_t)pi.id);
		return -1;
	}
	if (m->has_data_pool) {
		rc = one_pool(r, m, m->data_pool_h, 1, mode, &dpi, why);
		if (rc != 0)
			return rc;
		if (mode != 0 && dpi.id != m->data_pool_id) {
			FAIL(why, WR_E_POOL_NOT_FOUND, "data pool was replaced (its id changed)", 1, (uint64_t)m->data_pool_id, (uint64_t)dpi.id);
			return -1;
		}
	}
	if (mode != 0)
		return 0;
	/* a writer needs a pool that keeps its snapshot context: with POOL_SNAPS the OSD would replace it with the pool's own (osd-ops.md 3.9).
	 * With a named data pool the one that matters is only known after the header (judge); without it the image pool takes the data. */
	if (m->want_write && !m->has_data_pool && (pi.flags & WR_POOL_F_POOL_SNAPS) != 0) {
		FAIL(why, WR_E_POOL_UNSUPPORTED, "pool is in pool-snapshot mode, a writer needs self-managed snapshots", 0, pi.flags, 0);
		return -1;
	}
	m->pool_id = pi.id;
	m->data_pool_id = m->has_data_pool ? dpi.id : pi.id;
	return 0;
}

/* ---- the judgement ---------------------------------------------------------------------------------------------------------- */

wr_status wri_rbd_open_judge(const wri_rbd *r, const wri_rbd_img *m, const wri_rbd_hdr *h, wr_errinfo *why)
{
	wr_errinfo pre; /* the profile's own refusal: kept aside, the snapshot context ranks between its first rule and the others */
	wr_status st;

	WR_MEMSET(&pre, 0, sizeof(pre));
	st = wri_rbd_check_profile(h, m->want_write, &pre);
	/* The order of rbd-format2.md 3.3: the feature bits first, then the snapshot context, then the rest. A reader does not use the context and
	 * lives with one that is only too long for this profile; one that does not decode as a valid context is refused for both. */
	if (st == WR_E_RBD_FEATURES) {
		if (why != NULL)
			*why = pre;
		return st;
	}
	if (m->snapc_status != WR_OK && (m->want_write || m->snapc_total <= m->snapc.cap)) {
		FAIL(why, WR_E_RBD_SNAPC, "snapshot context is invalid or has more snapshots than this profile holds", m->snapc_total, m->snapc.cap,
		     m->want_write != 0);
		return WR_E_RBD_SNAPC;
	}
	if (st != WR_OK) {
		if (why != NULL && why->status == WR_OK)
			*why = pre;
		return st;
	}
	if ((h->features & WRI_RBD_F_DATA_POOL) != 0) {
		if (!m->has_data_pool) {
			FAIL(why, WR_E_RBD_DATA_POOL, "image has a data pool: name it in the open parameters (a0 = its id)", h->data_pool_id,
			     (uint64_t)-1, 0);
			return WR_E_RBD_DATA_POOL;
		}
		if (m->data_pool_id != h->data_pool_id) {
			FAIL(why, WR_E_RBD_DATA_POOL, "the data pool named by the host is not the image's data pool (a0 = image's, a1 = named)",
			     h->data_pool_id, m->data_pool_id, 0);
			return WR_E_RBD_DATA_POOL;
		}
	}
	if (m->want_write) { /* the pool that takes the data objects must keep a snapshot context */
		const wri_osd_map_ops *mo = &r->osd->map;
		wr_pool_info pi;
		wr_status ps;
		wr_pool_h target = (h->features & WRI_RBD_F_DATA_POOL) != 0 ? m->data_pool_h : m->pool_h;

		WR_MEMSET(&pi, 0, sizeof(pi));
		ps = mo->pool_info(mo->ctx, target, &pi);
		if (ps != WR_OK) {
			FAIL(why, ps, "pool lookup failed", 0, 0, 0);
			return ps;
		}
		if ((pi.flags & WR_POOL_F_POOL_SNAPS) != 0) {
			FAIL(why, WR_E_POOL_UNSUPPORTED, "pool is in pool-snapshot mode, a writer needs self-managed snapshots", 0, pi.flags, 0);
			return WR_E_POOL_UNSUPPORTED;
		}
	}
	return WR_OK;
}

static int same_str(const char *a, const char *b, size_t cap)
{
	size_t i;

	for (i = 0; i < cap; i++) {
		if (a[i] != b[i])
			return 0;
		if (a[i] == '\0')
			return 1;
	}
	return 1;
}

wr_status wri_rbd_open_refresh_judge(const wri_rbd *r, const wri_rbd_img *m, const wri_rbd_hdr *h, wr_errinfo *why)
{
	uint64_t changed = (h->features ^ m->features) & (WRI_RBD_F_STRIPINGV2 | WRI_RBD_F_DATA_POOL);
	wr_status st = wri_rbd_open_judge(r, m, h, why);

	if (st != WR_OK)
		return st;
	if (h->order != m->order || !same_str(h->prefix, m->prefix, sizeof(h->prefix))) {
		FAIL(why, WR_E_RBD_PROTO, "image header changed its identity (object size or prefix) behind our back", h->order, m->order, 0);
		return WR_E_RBD_PROTO;
	}
	if (changed != 0) { /* neither can change on an image that exists; if one did, the geometry or the data pool we use is wrong */
		FAIL(why, WR_E_RBD_FEATURES, "striping or data-pool feature changed behind our back", changed, h->features, m->features);
		return WR_E_RBD_FEATURES;
	}
	if ((h->features & WRI_RBD_F_DATA_POOL) != 0 && h->data_pool_id != m->hdr.data_pool_id) {
		FAIL(why, WR_E_RBD_DATA_POOL, "data pool changed behind our back", h->data_pool_id, m->hdr.data_pool_id, 0);
		return WR_E_RBD_DATA_POOL;
	}
	return WR_OK;
}

void wri_rbd_open_adopt(wri_rbd_img *m, const wri_rbd_hdr *h)
{
	m->order = h->order;
	m->size = h->size;
	m->features = h->features;
	m->flags = h->flags;
	m->op_features = h->op_features;
	WR_MEMCPY(m->prefix, h->prefix, sizeof(m->prefix));
	m->hdr = *h;
}

/* ---- the parameters of wri_rbd_open_start ---------------------------------------------------------------------------------------- */

/* A name or id: its length up to `max` (max + 1 means "longer"), and whether it is alphanumeric. */
static size_t bounded_len(const char *s, size_t max)
{
	size_t n = 0;

	while (n <= max && s[n] != '\0')
		n++;
	return n;
}

static int alnum_str(const char *s, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		char c = s[i];

		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')))
			return 0;
	}
	return 1;
}

/* The parameters that need no slot and no map: lengths and characters. */
wr_status wri_rbd_open_check_params(const wr_image_params *p, size_t *name_n, size_t *id_n)
{
	*name_n = 0;
	*id_n = 0;
	if (p->size != (uint32_t)sizeof(*p))
		return WR_E_ABI;
	if (p->pool == NULL || p->pool[0] == '\0' || (p->name == NULL && p->id == NULL))
		return WR_E_INVAL;
	if (p->snap_id != WR_SNAP_HEAD)
		return WR_E_UNSUPPORTED;
	if (p->id != NULL) {
		*id_n = bounded_len(p->id, WRI_RBD_ID_MAX);
		if (*id_n >= WRI_RBD_ID_MAX)
			return WR_E_TOOBIG;
		if (*id_n == 0 || !alnum_str(p->id, *id_n))
			return WR_E_RBD_BAD_ID;
	}
	if (p->name != NULL) {
		*name_n = bounded_len(p->name, WRI_RBD_NAME_MAX);
		if (*name_n >= WRI_RBD_NAME_MAX)
			return WR_E_TOOBIG;
		if (*name_n == 0 && p->id == NULL)
			return WR_E_INVAL;
	}
	return WR_OK;
}
