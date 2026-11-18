/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_open.h - opening an RBD image: the state machine of design 24.2 (track pools, resolve the name, read the header, judge it
 * against the profile, become OPEN), the periodic header refresh of a writer, and close. Spec: docs/spec/rbd-format2.md 3.1 to 3.4, 3.8.
 *
 * The machine talks to the cluster only through control operations on the object engine (wri_osd_req.h): one op slot per read, taken
 * from the control reserve, with the call inputs laid out in the image's ctl_in and the replies landing in its ctl_out. A step
 * advances every image that waits for something; it never blocks and never loops on a failure: a refusal ends the open with the status
 * of design 24.3 (WR_IMG_FAILED), a transport-level trouble is the object engine's to retry.
 *
 * What the machine and the I/O half agree on (rbd-io, wri_rbd.h):
 *   - a control operation carries the owner tag (image slot << 16) | image generation; wri_rbd_io_collect pops it from the engine's done ring
 *     and leaves it DONE and unreleased, and THIS module releases it (the step finds it through the image's ctl_op). An operation that was
 *     cancelled with its image is released by the same step (an "orphan": a control op that is DONE, popped and claimed by no image);
 *   - a writer's gate is wri_rio_gate_closed: writes wait while ros == WRI_ROS_REFRESH or the last read is older than hdr_refresh_ms
 *     (refreshed_ms). This module sets refreshed_ms to the time the adopted header read was SUBMITTED (the safe bound), next_refresh_ms to
 *     WR_DEADLINE_NONE for a reader and for hdr_refresh_ms == 0, and enters WRI_ROS_REFRESH (read pending or in flight) from the moment a
 *     refresh is due or wri_rbd_open_refresh_now was called until the read has been adopted;
 *   - an I/O answer that is fatal for the image (blocklisted: wri_rbd_io_take_fatal) reaches wri_rbd_img_fail through the step glue; an
 *     -EOLDSNAPC answer reaches wri_rbd_open_refresh_now and the write is resent after the refresh (under a new tid: the I/O half's part);
 *   - the image's failure and close complete the requests through wri_rbd_io_fail_image (wri_rbd_io.h);
 *   - a refresh read that fails with something the cluster may get over (an I/O error, a stalled map, a protocol error) is not dropped: the image stays in
 *     WRI_ROS_REFRESH (the gate stays shut, also for a refresh that was asked for) and the read is tried again a quarter of the period later (250 ms with no
 *     period). Only a protocol error WRI_RBD_PROTO_TRIES times in a row (an image whose header reply never fits img_ctl_bytes, every try resets the OSD session)
 *     fails the image; the other failures of 24.4 (blocklisted, header gone, no class, no permission, redirect) fail it at once.
 *
 * Module rbd-open: wri_rbd_open.c (start, close, fail, the state machine and its events), wri_rbd_open_dec.c (decode of the header reads into
 * wri_rbd_hdr, pool checks, the judgement and the refresh adoption rules).
 */
#ifndef WRI_RBD_OPEN_H
#define WRI_RBD_OPEN_H

#include "wr_image.h"
#include "wri_rbd.h"

/*
 * How the open reaches the map module. `track` is wr_client_pool_track (a function table so tests can run without an engine); `n_full`
 * (optional, NULL = no gating) returns wr_map_stats.n_full, the number of full maps adopted so far: a pool tracked AFTER the first map reads
 * as absent until the full map the engine then asks for has been adopted, so the open waits for n_full to pass the value it had at the track
 * call before it believes "absent" (design 24.2, R-B9). That wait ends by itself after wr_config.map_stale_ms (0 = no bound), like the engine's wait of an
 * operation for a pool: tracking a pool that an earlier open already tracked asks for no new full map. The table is the host's / the glue's and must outlive the layer.
 */
typedef struct wri_rbd_pools {
	void *ctx;
	wr_status (*track)(void *ctx, const char *name, wr_pool_h *h);
	uint32_t (*n_full)(void *ctx);
} wri_rbd_pools;

/*
 * Start opening an image in a free slot (the public wr_image_open validates and calls this): copy the strings, track the pool(s) through
 * `pools`, set the deadline. *slot is the image. The image is OPENING; wri_rbd_open_step moves it on. Also checked here (the glue need not):
 * WR_E_ABI (p->size), WR_E_INVAL (NULL, no pool, neither name nor id, an empty name), WR_E_UNSUPPORTED (snap_id), WR_E_TOOBIG (a name of 88
 * bytes or more, an id of 64 or more), WR_E_RBD_BAD_ID (an id that is not alphanumeric), WR_E_BUSY (no free slot), and what `track` returns
 * (nothing is changed then). Both name and id given: the id is used. An empty data_pool is no data pool.
 */
WR_MUST_CHECK wr_status wri_rbd_open_start(wri_rbd *r, const wri_rbd_pools *pools, const wr_image_params *p, uint32_t *slot);

/*
 * Advance every OPENING / OPEN (writer refresh) / CLOSING image one step: check pools, submit the next control read, decode a finished one,
 * start a due refresh, free a drained slot, reap orphaned control operations, expire open_timeout_ms (WR_E_TIMEOUT, the step in errinfo.what).
 * Returns 1 if more is ready (an operation was submitted, a state advanced, a finished operation waits to be popped, or the finished read of an image that is
 * gone waits in the done ring to be released); *deadline is lowered to the next time the machine wants to run.
 */
int wri_rbd_open_step(wri_rbd *r, uint64_t *deadline);

/* Close: DRAIN lets the writes finish (CLOSING until they did, then the slot is freed and WR_EV_IMAGE raised), ABANDON cancels all at once.
 * A DRAIN close of a CLOSING image is a no-op, an ABANDON one makes it abandon. WR_E_INVAL: a slot that is not an image, flags other than the
 * two. An image that is still OPENING or already FAILED has no writes to wait for: it is freed at once. */
WR_MUST_CHECK wr_status wri_rbd_close(wri_rbd *r, uint32_t slot, uint32_t flags);

/* A fatal event for an image from below or above (blocklisted, pool gone, features changed): FAILED, every request completes with it. The first
 * failure of an image stays (a second call changes nothing). *why may be NULL (WR_E_STATE). A CLOSING image only records it. */
void wri_rbd_img_fail(wri_rbd *r, uint32_t slot, const wr_errinfo *why);

/* A write was answered -EOLDSNAPC (or the host knows a snapshot was taken): the snapshot context is out of date. The writer reads its header at
 * once and holds writes until that read is adopted (a read already in flight is not enough: it may predate the snapshot, so another follows).
 * Ignored for a reader and for an image that is not OPEN. */
void wri_rbd_open_refresh_now(wri_rbd *r, uint32_t slot);

/* The header reads of one message, decoded from the raw reply (exposed for the decode tests): the ops sent were get_size, get_object_prefix,
 * get_features, get_flags, get_snapcontext, get_data_pool, parent_get, parent_overlap_get, in that order (design 24.2); `ops` are the
 * echoed records with their out_len and rval, `out` the concatenated outputs (out_len bytes: the sum of the ops' out_len, exactly). Fills *h
 * and, when `snapc` is not NULL, the snapshot context (the array and cap are the owner's) and the count the server sent. WR_E_RBD_PROTO on
 * anything that does not decode or whose lengths do not add up; the first op with a negative rval gives wri_osd_errno_status of it. On a
 * failure *h is cleared (data_pool_id -1). The stripe fields and op_features stay 0: the EXTRA step fills them. */
WR_MUST_CHECK wr_status wri_rbd_open_decode_header(const wri_osd_opd *ops, unsigned n_ops, const uint8_t *out, uint32_t out_len,
						   wri_rbd_hdr *h, wri_snapc *snapc, uint32_t *n_snaps_total);

/* Only the snapshot context of the same reply (the refresh decodes it last, after the rest was judged). Statuses of wri_rbd_dec_snapcontext;
 * *snapc is cleared on a failure. */
WR_MUST_CHECK wr_status wri_rbd_open_decode_snapc(const wri_osd_opd *ops, unsigned n_ops, const uint8_t *out, uint32_t out_len, wri_snapc *snapc,
						  uint32_t *n_snaps_total);

/* The snapshot context of the same reply judged WITHOUT storing anything (the rules of wri_rbd_dec_snapcontext, for a context of at most `cap` ids): WR_OK, or
 * WR_E_RBD_PROTO / WR_E_RBD_SNAPC with *n_total = the count the server sent (0 when the bytes do not even give one). wri_rbd_dec_snapcontext clears the context it is
 * given as soon as it starts, so a refresh asks here first: the live context of a writer is never emptied (a write that is already on the wire, or a zombie
 * of an image that fails, would carry "no snapshots" to the cluster). */
WR_MUST_CHECK wr_status wri_rbd_open_probe_snapc(const wri_osd_opd *ops, unsigned n_ops, const uint8_t *out, uint32_t out_len, uint32_t cap,
						 uint32_t *n_total);

/* The EXTRA reads: get_stripe_unit_count when features has bit 0x2, then op_features_get when it has bit 0x100 (one or two ops, in that order).
 * Fills h->stripe_unit / stripe_count / op_features; the other fields of *h are not touched. Same error rules as the header decode. */
WR_MUST_CHECK wr_status wri_rbd_open_decode_extra(const wri_osd_opd *ops, unsigned n_ops, const uint8_t *out, uint32_t out_len, wri_rbd_hdr *h);

/* ---- internal to the rbd-open sources (wri_rbd_open*.c); no other module calls these ---------------------------------------- */

/* The pools of an image. mode 0 (POOLS): wait for the map and for the full-map rule, record the pool ids, refuse what a writer cannot use;
 * mode 1: the image is past that step, only a pool that left the map (or was replaced under the same name) matters. Returns 0 ready, 1 wait,
 * -1 failed (*why set). */
int wri_rbd_open_pools(wri_rbd *r, wri_rbd_img *m, int mode, wr_errinfo *why);
/* The judgement of a header (after the EXTRA reads): the profile, the snapshot context at its place in the order of 24.3, the data pool and the
 * pool-snapshot mode. WR_OK or the refusal with its numbers in *why (zeroed by the caller). */
wr_status wri_rbd_open_judge(const wri_rbd *r, const wri_rbd_img *m, const wri_rbd_hdr *h, wr_errinfo *why);
/* A refresh: what must not have changed since the open (identity, striping and data-pool bits, the data pool), then the judgement. */
wr_status wri_rbd_open_refresh_judge(const wri_rbd *r, const wri_rbd_img *m, const wri_rbd_hdr *h, wr_errinfo *why);
/* The parameters of wri_rbd_open_start that need no slot and no map (lengths, characters, ABI, snapshot id): WR_OK or the status it returns. */
WR_MUST_CHECK wr_status wri_rbd_open_check_params(const wr_image_params *p, size_t *name_n, size_t *id_n);
/* The open succeeded: copy a judged header into the image (size, features, flags, prefix, order, pools). */
void wri_rbd_open_adopt(wri_rbd_img *m, const wri_rbd_hdr *h);
/* Build and submit the control read of the image's current step (GET_ID, HEADER, EXTRA, REFRESH) from the control reserve; img->ctl_op is the slot.
 * WR_E_BUSY: no control slot or no byte budget now (nothing was taken); another status: the read cannot be built (the image fails). */
WR_MUST_CHECK wr_status wri_rbd_open_submit(wri_rbd *r, wri_rbd_img *m);
/* The answer of the image's control read (DONE, popped; img->ctl_op already cleared; the caller releases the slot afterwards): decode, judge,
 * move the machine to its next step, become OPEN, adopt a refresh. Returns 1 when the image must fail, with the reason in *why (zeroed by the caller;
 * the caller fails the image), 0 otherwise. */
int wri_rbd_open_complete(wri_rbd *r, wri_rbd_img *m, const wri_osd_op *op, wr_errinfo *why);

#endif /* WRI_RBD_OPEN_H */
