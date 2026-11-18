/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_io.h - image block I/O: the geometry (byte range to object extents, object names), the request table, the overlap fence,
 * the cutting of requests into object operations, completion, flush, timeouts and cancellation. Design: section 25;
 * spec: docs/spec/rbd-format2.md 2.9 to 2.11, 3.5 to 3.7.
 *
 * Module rbd-geom (wri_rbd_geom.c): the pure part (geometry, names, extent iteration, overlap test, error mapping).
 * Module rbd-io (wri_rbd_io.c, wri_rbd_io_split.c, wri_rbd_io_fence.c, wri_rbd_io_cancel.c): the machinery over the object engine.
 */
#ifndef WRI_RBD_IO_H
#define WRI_RBD_IO_H

#include "wr_image.h"
#include "wri_rbd.h"

/* ---- geometry (module rbd-geom) ------------------------------------------------------------------------------------- */

/* Default striping only (stripe_unit = object size, stripe_count 1): the general formula of rbd-format2.md 2.10 is for a later phase. */
typedef struct wri_rbd_geom {
	uint64_t object_size;   /* 1 << order */
	uint8_t order;
	uint8_t reserved8[7];
} wri_rbd_geom;

/* order 12 .. 25 (WR_E_RBD_ORDER otherwise). */
WR_MUST_CHECK wr_status wri_rbd_geom_init(wri_rbd_geom *g, uint8_t order);
/* Number of data objects of an image of `size` bytes: ceil(size / object_size). */
uint64_t wri_rbd_geom_objects(const wri_rbd_geom *g, uint64_t size);
/* The first extent of the byte range [off, off + len): object number, offset inside it, run length (at most the object's end and at most
 * `max_run`); the caller advances by *run and calls again. len must be non-zero and max_run non-zero. */
void wri_rbd_geom_extent(const wri_rbd_geom *g, uint64_t off, uint64_t len, uint32_t max_run, uint64_t *objno, uint64_t *obj_off,
			 uint32_t *run);
/* "<prefix>.<objno as 16 lower-case hex digits>" into out (cap bytes, NUL terminated); returns the length without the NUL, or 0 if it does
 * not fit WRI_RBD_OBJNAME_MAX (design 24.4). */
size_t wri_rbd_obj_name(char *out, size_t cap, const char *prefix, uint64_t objno);
/* "rbd_id.<name>" and "rbd_header.<id>"; 0 if it does not fit or the input is empty. */
size_t wri_rbd_id_obj_name(char *out, size_t cap, const char *name);
size_t wri_rbd_header_obj_name(char *out, size_t cap, const char *id);
/* 1 if the byte ranges [a_off, a_off + a_len) and [b_off, b_off + b_len) intersect (overflow safe; an empty range intersects nothing). */
int wri_rbd_overlap(uint64_t a_off, uint64_t a_len, uint64_t b_off, uint64_t b_len);
/* The operation shape of a discard of one object extent (rbd-format2.md 3.7): whole object DELETE, tail TRUNCATE(off), else ZERO(off, len). */
uint16_t wri_rbd_discard_op(const wri_rbd_geom *g, uint64_t obj_off, uint32_t run);
/* The final status of an image request from an object operation's result: -ENOENT of a READ / DISCARD / ZERO / TRUNCATE / DELETE is success (no
 * parent, design 25.3); everything else through wri_osd_errno_status. `*zero_fill` is set for a READ that must zero its buffer (ENOENT). */
wr_status wri_rbd_op_status(uint16_t code, int32_t result, int *zero_fill);

/* ---- the I/O half of the layer (module rbd-io) -------------------------------------------------------------------- */

/* The public calls of wr_image.h, on the layer: image slot and request pointer already resolved by the glue. Statuses as documented there. */
WR_MUST_CHECK wr_status wri_rbd_submit(wri_rbd *r, uint32_t img, wr_io_req *req);
WR_MUST_CHECK wr_status wri_rbd_cancel(wri_rbd *r, uint32_t img, wr_io_req *req);
/* The next finished request in completion order, NULL if none; releases its table slot. */
wr_io_req *wri_rbd_next_done(wri_rbd *r);

/* Collect finished object operations (called by wri_rbd_step before it cuts new ones): applies results to their requests, marks a request FINISH
 * when its last extent is answered, resolves zombies. Returns the number of operations handled. */
uint32_t wri_rbd_io_collect(wri_rbd *r);
/* Admit WAIT requests that no earlier conflicting request blocks and cut RUN requests into operations while the op table, the bytes in flight
 * and the control reserve allow. Returns 1 if more is ready. */
int wri_rbd_io_cut(wri_rbd *r, uint32_t budget);
/* Expire request timeouts (cancel + WR_E_TIMEOUT) and flush completions. *deadline is lowered to the next expiry. */
void wri_rbd_io_timeouts(wri_rbd *r, uint64_t *deadline);
/* Complete every request of an image with `st` (the image failed or closed): reads drop, writes are handled as the close flags say. */
void wri_rbd_io_fail_image(wri_rbd *r, uint32_t img, wr_status st, uint32_t close_flags);

#endif /* WRI_RBD_IO_H */
