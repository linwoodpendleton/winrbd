/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_cls.h - the object-class calls an RBD client makes (class `rbd` and class `lock`) as pure encoders and decoders:
 * what goes into the data segment of an OSD CALL operation, and how its output is read. Spec: docs/spec/rbd-format2.md 2.2, 2.3, 2.5,
 * 2.7, 2.8; design: docs/design/core-architecture.md section 24.
 *
 * Encoders append `class | method | argument` to the data writer and fill the operation record (code CALL, in_len, the two name
 * lengths). Several calls into one message share the writer, in operation order: the data segment of the message is whatever the
 * writer holds afterwards. Decoders take the output bytes of ONE operation (the owner cuts the reply data segment by the operations'
 * out_len) and check that they consume it exactly. All counts are capped; a decoder that fails leaves its output cleared and returns
 * WR_E_RBD_PROTO.
 *
 * Module rbd-cls: wri_rbd_cls.c (encoders), wri_rbd_cls_dec.c (decoders), wri_rbd_policy.c (the refusal rules of design 24.3).
 */
#ifndef WRI_RBD_CLS_H
#define WRI_RBD_CLS_H

#include "wr_err.h"
#include "wr_types.h"
#include "wri_cursor.h"
#include "wri_osd_msg.h"

/* ---- feature and flag bits (rbd-format2.md 2.8) ------------------------------------------------------------------- */

#define WRI_RBD_F_LAYERING 0x1ull
#define WRI_RBD_F_STRIPINGV2 0x2ull
#define WRI_RBD_F_EXCLUSIVE_LOCK 0x4ull
#define WRI_RBD_F_OBJECT_MAP 0x8ull
#define WRI_RBD_F_FAST_DIFF 0x10ull
#define WRI_RBD_F_DEEP_FLATTEN 0x20ull
#define WRI_RBD_F_JOURNALING 0x40ull
#define WRI_RBD_F_DATA_POOL 0x80ull
#define WRI_RBD_F_OPERATIONS 0x100ull
#define WRI_RBD_F_MIGRATING 0x200ull
#define WRI_RBD_F_NON_PRIMARY 0x400ull
#define WRI_RBD_F_DIRTY_CACHE 0x800ull
#define WRI_RBD_F_ALL 0xfffull       /* bits 0 to 11: what the stock client knows */
#define WRI_RBD_OPF_CLONE_CHILD 0x2ull /* op_features bit: the image is a clone */

/* Limits of the decoded header (an id of 64 bytes or more, or a prefix longer than WRI_RBD_PREFIX_LEN_MAX, is refused: the names built
 * from them would exceed 95 bytes). */
#define WRI_RBD_ID_MAX 64u
#define WRI_RBD_PREFIX_MAX 96u    /* with the NUL */
#define WRI_RBD_PREFIX_LEN_MAX 78u /* longest prefix the decoder accepts: prefix + '.' + 16 hex digits is at most 95 bytes */
#define WRI_RBD_NAME_MAX 88u      /* image name: "rbd_id." + name must fit 95 bytes */
#define WRI_RBD_OBJNAME_MAX 96u   /* prefix + '.' + 16 hex digits + NUL, and every metadata object name */

/* ---- encoders ---------------------------------------------------------------------------------------------------- */

/*
 * Each appends one CALL to `data` and fills *op (the whole record is cleared first; out_len and rval stay 0 for the reply decoder).
 * WR_E_TOOBIG (data too small, a class / method / lock string above 255 bytes) is the only failure of a valid call; a NULL pointer is
 * WR_E_INVAL. A failing call returns the status and leaves *op cleared; the writer then holds an error (data too small) or is untouched
 * (a string too long: nothing was written), so a failed message is discarded whole. get_features sends the read_only byte (0 or 1);
 * a negative read_only leaves the byte out (the form the stock tools send when they do not care: only tests and diagnostics use it).
 *   id object:      get_id
 *   header object:  get_size(snap) get_object_prefix get_features(snap, read_only) get_flags(snap) get_snapcontext get_data_pool
 *                   parent_get parent_overlap_get(snap) get_stripe_unit_count op_features_get
 *   lock class:     get_info(name), lock(...), unlock(name, cookie): get_info is used by diagnostics, lock / unlock are the hooks of writer
 *                   policy L2 (rbd-format2.md 3.9), encoded and tested but not wired in this phase
 */
WR_MUST_CHECK wr_status wri_rbd_put_get_id(wri_wr *data, wri_osd_opd *op);
WR_MUST_CHECK wr_status wri_rbd_put_get_size(wri_wr *data, wri_osd_opd *op, uint64_t snap_id);
WR_MUST_CHECK wr_status wri_rbd_put_get_object_prefix(wri_wr *data, wri_osd_opd *op);
WR_MUST_CHECK wr_status wri_rbd_put_get_features(wri_wr *data, wri_osd_opd *op, uint64_t snap_id, int read_only);
WR_MUST_CHECK wr_status wri_rbd_put_get_flags(wri_wr *data, wri_osd_opd *op, uint64_t snap_id);
WR_MUST_CHECK wr_status wri_rbd_put_get_snapcontext(wri_wr *data, wri_osd_opd *op);
WR_MUST_CHECK wr_status wri_rbd_put_get_data_pool(wri_wr *data, wri_osd_opd *op);
WR_MUST_CHECK wr_status wri_rbd_put_parent_get(wri_wr *data, wri_osd_opd *op);
WR_MUST_CHECK wr_status wri_rbd_put_parent_overlap_get(wri_wr *data, wri_osd_opd *op, uint64_t snap_id);
WR_MUST_CHECK wr_status wri_rbd_put_get_stripe_unit_count(wri_wr *data, wri_osd_opd *op);
WR_MUST_CHECK wr_status wri_rbd_put_op_features_get(wri_wr *data, wri_osd_opd *op);
WR_MUST_CHECK wr_status wri_rbd_put_lock_get_info(wri_wr *data, wri_osd_opd *op, const char *name);
WR_MUST_CHECK wr_status wri_rbd_put_lock_lock(wri_wr *data, wri_osd_opd *op, const char *name, uint8_t type, const char *cookie,
					      const char *tag);
WR_MUST_CHECK wr_status wri_rbd_put_lock_unlock(wri_wr *data, wri_osd_opd *op, const char *name, const char *cookie);

/* ---- decoders ---------------------------------------------------------------------------------------------------- */

/*
 * Every decoder reads the output bytes of ONE operation and consumes them exactly. WR_E_RBD_PROTO: the bytes are short, longer than the
 * layout, an envelope claims more than there is, a flag byte or count is out of range (lockers above 64, a lock type above 3, an overlap
 * marker above 1). The decoders that judge content have their own statuses (WR_E_RBD_BAD_ID, WR_E_RBD_SNAPC). A NULL output pointer is
 * WR_E_INVAL. Whatever fails leaves the outputs cleared (zero, empty string, empty context).
 */

/* get_id and the id object's own data: u32 length + id, 1 to WRI_RBD_ID_MAX - 1 alphanumeric bytes (WR_E_RBD_BAD_ID otherwise). */
WR_MUST_CHECK wr_status wri_rbd_dec_id(const uint8_t *out, uint32_t n, char id[WRI_RBD_ID_MAX]);
/* get_size: u8 order, u64 size (order first). The order is not judged here (wri_rbd_check_profile). */
WR_MUST_CHECK wr_status wri_rbd_dec_size(const uint8_t *out, uint32_t n, uint8_t *order, uint64_t *size);
/* get_object_prefix: string, 1 .. WRI_RBD_PREFIX_LEN_MAX visible ASCII bytes, so that prefix + '.' + 16 hex digits is a valid object name
 * (WR_E_RBD_BAD_ID otherwise). */
WR_MUST_CHECK wr_status wri_rbd_dec_prefix(const uint8_t *out, uint32_t n, char prefix[WRI_RBD_PREFIX_MAX]);
/* get_features: u64 features, u64 incompatible (what the server computed from its own masks; logged, never trusted). */
WR_MUST_CHECK wr_status wri_rbd_dec_features(const uint8_t *out, uint32_t n, uint64_t *features, uint64_t *incompatible);
/* get_flags, op_features_get: one u64. get_data_pool: one i64 (-1 = none). */
WR_MUST_CHECK wr_status wri_rbd_dec_u64(const uint8_t *out, uint32_t n, uint64_t *v);
WR_MUST_CHECK wr_status wri_rbd_dec_i64(const uint8_t *out, uint32_t n, int64_t *v);
/*
 * get_snapcontext: u64 seq, u32 count, count x u64 (strictly descending, the first at most seq, seq at most WRI_SNAP_MAX). Stores at most
 * s->cap ids into s->snaps and sets s->seq / s->n (cap and snaps are the owner's and are not touched). *n_total (optional) gets the count
 * the server sent. WR_E_RBD_SNAPC: the context is not valid, or the count is above s->cap (nothing is stored then, *n_total says how many);
 * the count is checked against the bytes that are there before anything is read, so a hostile count is WR_E_RBD_PROTO and costs nothing.
 */
WR_MUST_CHECK wr_status wri_rbd_dec_snapcontext(const uint8_t *out, uint32_t n, wri_snapc *s, uint32_t *n_total);
/* parent_get: struct v1 { i64 pool_id, string pool_namespace, string image_id, u64 snap_id }, trailing fields of a later version skipped by
 * the struct length; the strings are not kept, only whether a parent exists (pool_id >= 0, image_id non-empty, snap_id != NOSNAP:
 * rbd-format2.md 2.3). */
WR_MUST_CHECK wr_status wri_rbd_dec_parent(const uint8_t *out, uint32_t n, uint8_t *has_parent);
/* parent_overlap_get: optional<u64>: *present 0 or 1 and the overlap (0 when absent). */
WR_MUST_CHECK wr_status wri_rbd_dec_overlap(const uint8_t *out, uint32_t n, uint8_t *present, uint64_t *overlap);
/* get_stripe_unit_count: u64 unit, u64 count. */
WR_MUST_CHECK wr_status wri_rbd_dec_stripe(const uint8_t *out, uint32_t n, uint64_t *unit, uint64_t *count);
/*
 * lock get_info: struct v1 { map<locker_id_t, locker_info_t>, u8 type, string tag }: the number of lockers (at most 64, more is
 * WR_E_RBD_PROTO; each entry is read as two structures and skipped by their lengths, so the address encoding does not matter), the lock
 * type (0 to 3) and the tag, truncated to tag_cap - 1 bytes and NUL terminated (tag may be NULL with tag_cap 0). Decide "locked" from
 * *n_lockers only: a released lock keeps its type and tag (rbd-format2.md 2.7).
 */
WR_MUST_CHECK wr_status wri_rbd_dec_lock_info(const uint8_t *out, uint32_t n, uint32_t *n_lockers, uint8_t *type, char *tag,
					      size_t tag_cap);

/* ---- the refusal rules (rbd-format2.md 3.3, 4.2; design 24.3) -------------------------------------------------------- */

/* Everything the open reads decide on. */
typedef struct wri_rbd_hdr {
	uint8_t order;
	uint8_t has_parent;
	uint8_t has_overlap;
	uint8_t reserved8;
	uint64_t size, features, flags, op_features, overlap;
	uint64_t stripe_unit, stripe_count;   /* 0 = not read (feature bit clear): default layout */
	int64_t data_pool_id;                 /* -1 = none */
	char prefix[WRI_RBD_PREFIX_MAX];
} wri_rbd_hdr;

/*
 * Judge a header against the profile of the open: the reader profile R1 or the writer profile P1 (design 24.3), in the order of
 * rbd-format2.md 3.3: feature bits, order, striping, parent, data pool, flags. WR_OK or the first refusal, with its numbers in `why`
 * (first-failure errinfo, module WR_MOD_RBD; `why` may be NULL):
 *   WR_E_RBD_FEATURES   bits outside the profile, including every bit above 11: a0 = the offending bits, a1 = all bits, a2 = 1 for a writer
 *   WR_E_RBD_ORDER      order not in 12 .. 25: a0 = order
 *   WR_E_RBD_STRIPING   bit 0x2 with a layout other than (unit == object size, count == 1; a zero unit or count means that too): a0 unit,
 *                       a1 count, a2 object size
 *   WR_E_RBD_PARENT     has_parent, or has_overlap, or (operations bit and op_features clone-child): a0 = bit 0 / 1 / 2 for which of the
 *                       three fired, a1 = the overlap, a2 = op_features
 *   WR_E_RBD_DATA_POOL  the data-pool bit is set and data_pool_id < 0: a0 = the id
 *   WR_E_RBD_FLAGS      a writer and flags != 0: a0 = flags
 * Pool existence and the replicated check are the open state machine's, they need the map; so is the comparison of data_pool_id with the
 * pool the host named. WR_E_INVAL for a NULL header.
 */
WR_MUST_CHECK wr_status wri_rbd_check_profile(const wri_rbd_hdr *h, int want_write, wr_errinfo *why);
/* The feature bits a profile accepts outright: the reader profile R1 0x1ff, the writer profile P1 0xa1 (layering, deep-flatten, data-pool).
 * Bit 0x2 (striping) is conditional for both profiles: wri_rbd_check_profile lets it through in the default layout form only (design
 * 24.3: "writer: same"), so a writer's effective mask is 0xa3 and a striped image is refused as WR_E_RBD_STRIPING, not as a feature. */
uint64_t wri_rbd_features_ok(int want_write);

#endif /* WRI_RBD_CLS_H */
