/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_cls.c - encoders of the object-class calls an RBD client makes (see wri_rbd_cls.h; spec rbd-format2.md 2.2, 2.3, 2.7).
 *
 * One call is the bytes `class | method | argument` appended to the data writer, plus the operation record the message encoder
 * needs (code CALL, in_len = all three parts, the two name lengths). The argument layouts are those of the notes: a plain u64 for the
 * snapshot-taking read methods, nothing for the others, and for the lock class a versioned structure (v1, compat 1) around the fields.
 * Strings handed in by the caller are checked before anything is written, so a refused string leaves the writer untouched.
 */
#include "wri_rbd_cls.h"

#include "wri_denc.h"

WR_FILE_LICENCE_MIT

#define RBD_STR_MAX 255u /* longest class, method, lock name, cookie or tag (the call op carries the first two in one byte each) */

/* Length of a NUL-terminated string, looking at no more than RBD_STR_MAX + 1 bytes: RBD_STR_MAX + 1 means "too long". */
static size_t str_len(const char *s)
{
	size_t n = 0;

	while (n <= RBD_STR_MAX && s[n] != '\0')
		n++;
	return n;
}

/* A string argument: not NULL, at most RBD_STR_MAX bytes. */
static wr_status str_check(const char *s, size_t *n)
{
	if (s == NULL)
		return WR_E_INVAL;
	*n = str_len(s);
	return *n > RBD_STR_MAX ? WR_E_TOOBIG : WR_OK;
}

/* Clear the record, refuse a dead writer, append class and method; *start is where the call's bytes begin. */
static wr_status call_begin(wri_wr *w, wri_osd_opd *op, const char *cls, size_t cls_n, const char *meth, size_t meth_n,
			    size_t *start)
{
	if (op != NULL)
		WR_MEMSET(op, 0, sizeof(*op));
	if (w == NULL || op == NULL)
		return WR_E_INVAL;
	if (w->err != WR_OK)
		return w->err;
	*start = w->pos;
	wri_wr_bytes(w, (const uint8_t *)cls, cls_n);
	wri_wr_bytes(w, (const uint8_t *)meth, meth_n);
	if (w->err != WR_OK) { /* the class and method did not fit */
		WR_MEMSET(op, 0, sizeof(*op));
		return w->err;
	}
	op->cls_class_len = (uint8_t)cls_n;
	op->cls_method_len = (uint8_t)meth_n;
	return WR_OK;
}

/* The writer holds the whole call: fill the record. On any failure the record is cleared again. */
static wr_status call_end(wri_wr *w, wri_osd_opd *op, size_t start)
{
	size_t n;

	if (w->err != WR_OK) {
		WR_MEMSET(op, 0, sizeof(*op));
		return w->err;
	}
	n = w->pos - start;
	if ((size_t)(uint32_t)n != n) {
		WR_MEMSET(op, 0, sizeof(*op));
		wri_wr_fail(w, WR_E_TOOBIG);
		return WR_E_TOOBIG;
	}
	op->code = WRI_OSD_OP_CALL;
	op->in_len = (uint32_t)n;
	return WR_OK;
}

#define CALL_BEGIN(w, op, cls, meth, start) call_begin((w), (op), (cls), sizeof(cls) - 1u, (meth), sizeof(meth) - 1u, (start))

/* A call with no argument. */
static wr_status put_plain(wri_wr *w, wri_osd_opd *op, const char *cls, size_t cls_n, const char *meth, size_t meth_n)
{
	size_t at = 0;
	wr_status st = call_begin(w, op, cls, cls_n, meth, meth_n, &at);

	if (st != WR_OK)
		return st;
	return call_end(w, op, at);
}

/* A call whose argument is one u64 (the snapshot id). */
static wr_status put_snap(wri_wr *w, wri_osd_opd *op, const char *meth, size_t meth_n, uint64_t snap_id)
{
	size_t at = 0;
	wr_status st = call_begin(w, op, "rbd", 3u, meth, meth_n, &at);

	if (st != WR_OK)
		return st;
	wri_wr_u64(w, snap_id);
	return call_end(w, op, at);
}

/* ---- the id object ----------------------------------------------------------------------------------------------- */

wr_status wri_rbd_put_get_id(wri_wr *data, wri_osd_opd *op)
{
	return put_plain(data, op, "rbd", 3u, "get_id", 6u);
}

/* ---- the header object ------------------------------------------------------------------------------------------- */

wr_status wri_rbd_put_get_size(wri_wr *data, wri_osd_opd *op, uint64_t snap_id)
{
	return put_snap(data, op, "get_size", 8u, snap_id);
}

wr_status wri_rbd_put_get_object_prefix(wri_wr *data, wri_osd_opd *op)
{
	return put_plain(data, op, "rbd", 3u, "get_object_prefix", 17u);
}

wr_status wri_rbd_put_get_features(wri_wr *data, wri_osd_opd *op, uint64_t snap_id, int read_only)
{
	size_t at = 0;
	wr_status st = CALL_BEGIN(data, op, "rbd", "get_features", &at);

	if (st != WR_OK)
		return st;
	wri_wr_u64(data, snap_id);
	if (read_only >= 0)
		wri_wr_u8(data, read_only != 0 ? 1u : 0u);
	return call_end(data, op, at);
}

wr_status wri_rbd_put_get_flags(wri_wr *data, wri_osd_opd *op, uint64_t snap_id)
{
	return put_snap(data, op, "get_flags", 9u, snap_id);
}

wr_status wri_rbd_put_get_snapcontext(wri_wr *data, wri_osd_opd *op)
{
	return put_plain(data, op, "rbd", 3u, "get_snapcontext", 15u);
}

wr_status wri_rbd_put_get_data_pool(wri_wr *data, wri_osd_opd *op)
{
	return put_plain(data, op, "rbd", 3u, "get_data_pool", 13u);
}

wr_status wri_rbd_put_parent_get(wri_wr *data, wri_osd_opd *op)
{
	return put_plain(data, op, "rbd", 3u, "parent_get", 10u);
}

wr_status wri_rbd_put_parent_overlap_get(wri_wr *data, wri_osd_opd *op, uint64_t snap_id)
{
	return put_snap(data, op, "parent_overlap_get", 18u, snap_id);
}

wr_status wri_rbd_put_get_stripe_unit_count(wri_wr *data, wri_osd_opd *op)
{
	return put_plain(data, op, "rbd", 3u, "get_stripe_unit_count", 21u);
}

wr_status wri_rbd_put_op_features_get(wri_wr *data, wri_osd_opd *op)
{
	return put_plain(data, op, "rbd", 3u, "op_features_get", 15u);
}

/* ---- the lock class (rbd-format2.md 2.7) --------------------------------------------------------------------------- */

/* A lock string field: u32 length + bytes (the caller has checked the length). */
static void put_lstr(wri_wr *w, const char *s, size_t n)
{
	wri_denc_put_str(w, (const uint8_t *)s, n);
}

wr_status wri_rbd_put_lock_get_info(wri_wr *data, wri_osd_opd *op, const char *name)
{
	size_t at = 0, mark, nn = 0;
	wr_status st;

	if (op != NULL)
		WR_MEMSET(op, 0, sizeof(*op));
	st = str_check(name, &nn);
	if (st != WR_OK)
		return st;
	st = CALL_BEGIN(data, op, "lock", "get_info", &at);
	if (st != WR_OK)
		return st;
	mark = wri_env_begin(data, 1u, 1u);
	put_lstr(data, name, nn);
	wri_env_end(data, mark);
	return call_end(data, op, at);
}

wr_status wri_rbd_put_lock_lock(wri_wr *data, wri_osd_opd *op, const char *name, uint8_t type, const char *cookie, const char *tag)
{
	size_t at = 0, mark, nn = 0, cn = 0, tn = 0;
	wr_status st;

	if (op != NULL)
		WR_MEMSET(op, 0, sizeof(*op));
	st = str_check(name, &nn);
	if (st == WR_OK)
		st = str_check(cookie, &cn);
	if (st == WR_OK)
		st = str_check(tag, &tn);
	if (st != WR_OK)
		return st;
	st = CALL_BEGIN(data, op, "lock", "lock", &at);
	if (st != WR_OK)
		return st;
	mark = wri_env_begin(data, 1u, 1u);
	put_lstr(data, name, nn);
	wri_wr_u8(data, type);
	put_lstr(data, cookie, cn);
	put_lstr(data, tag, tn);
	put_lstr(data, "", 0u);         /* description: empty */
	wri_denc_put_utime(data, 0u, 0u); /* duration: none, the lock never expires on its own */
	wri_wr_u8(data, 0u);            /* flags: no renew */
	wri_env_end(data, mark);
	return call_end(data, op, at);
}

wr_status wri_rbd_put_lock_unlock(wri_wr *data, wri_osd_opd *op, const char *name, const char *cookie)
{
	size_t at = 0, mark, nn = 0, cn = 0;
	wr_status st;

	if (op != NULL)
		WR_MEMSET(op, 0, sizeof(*op));
	st = str_check(name, &nn);
	if (st == WR_OK)
		st = str_check(cookie, &cn);
	if (st != WR_OK)
		return st;
	st = CALL_BEGIN(data, op, "lock", "unlock", &at);
	if (st != WR_OK)
		return st;
	mark = wri_env_begin(data, 1u, 1u);
	put_lstr(data, name, nn);
	put_lstr(data, cookie, cn);
	wri_env_end(data, mark);
	return call_end(data, op, at);
}
