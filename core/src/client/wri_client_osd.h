/* SPDX-License-Identifier: MIT */
/*
 * wri_client_osd.h - the glue between the engine (wri_client.h) and the OSD client / image layer (wri_osd_req.h, wri_rbd.h): memory planning
 * and carving, the OSD connection link, the stage of wr_client_run, the engine's side of the public image API. Design: section 27 and 28.
 *
 * Module client-glue-osd. The engine struct gets three pointers, `wri_osdc *osd`, `wri_rbd *rbd` and `wri_cosd *og` (all NULL while osd_sessions == 0),
 * and the connection slots stay what they are: a session only remembers a slot number. With the OSD client off nothing here runs and the footprint of
 * the engine does not change by a byte except the three pointers (README footprint rows are updated by this module).
 *
 *   wr_client_run:  ... monitor step, map step, then
 *                   wri_client_osd_begin()  osd table pass (wri_osdc_step), wri_rbd_step() the image pass, wri_client_osd_end()
 *                   derive actions
 *
 * The connections of OSD sessions are ordinary slots of the engine's table, opened with role WRI_ENTITY_OSD, the OSD upper-layer table and a per-slot
 * auth context (design 21.2: the cephx client is per handshake after module cx-hs; one wri_cx_hs per CONNECTION slot, not per handshake slot, because the
 * context is read for the gid of CLIENT_IDENT after the handshake slot has gone back to the pool). The action of such a connection carries
 * osd_connect_timeout_ms as its timeout.
 *
 * The public wr_image is a small handle of this module (`struct wr_image`): it names the client and the slot of the image table, so the calls of
 * wr_image.h, which take no client argument, reach the layer, and a handle of a destroyed client or a closed image is recognised.
 */
#ifndef WRI_CLIENT_OSD_H
#define WRI_CLIENT_OSD_H

#include "wri_client.h"
#include "wri_osd_req.h"
#include "wri_rbd.h"
#include "wri_rbd_open.h"

#define WRI_IMG_MAGIC 0x57524931u /* "WRI1" */

/* What wr_image points at: lives in the arena (max_images of them), set at create, zero after destroy. */
struct wr_image {
	wr_client *c;
	uint16_t slot;  /* index in the image table of the layer (max_images is 16 bits) */
	uint8_t fresh;  /* the open began after the engine's last run: its deadlines are re-based at the next run (wri_client_osd_rebase) */
	uint8_t reserved8;
	uint32_t magic; /* WRI_IMG_MAGIC */
};

/* The OSD client's own state, one block in the arena (the engine's `og`): the object engine and the image layer are embedded, so the pointers `osd` and
 * `rbd` of the engine point into it. */
struct wri_cosd {
	wri_osdc osd;
	wri_rbd rbd;
	wri_rbd_pools pools;    /* how the image open reaches the map module (the layer keeps a pointer to it) */
	wri_cx_hs *hs;          /* max_conns auth contexts: the handshake of the OSD connection in slot i uses hs[i] */
	struct wr_image *h;     /* max_images handles */
	uint64_t rbd_deadline;  /* what the last image pass wanted (WR_DEADLINE_NONE if nothing) */
	wr_errinfo fatal;       /* the error of the WR_EV_FATAL event, the root cause the images end with (c->last_err keeps the FIRST failure, which may be an earlier, milder one) */
	uint32_t n_hs, n_h;
	uint8_t failed;         /* the images were failed after the engine ended (fatal error): done once */
	uint8_t fresh_img;      /* an image was opened since the last run (wr_image.fresh): the next run re-bases its deadlines */
	uint8_t fresh_req;      /* a request with a timeout was accepted since the last run (wri_rbd_rqpriv.fresh): the next run re-bases its deadline */
	uint8_t reserved8[5];
};

/* Plan (arena, bulk) of the whole OSD client and image layer; (0, 0) when osd_sessions == 0. WR_E_INVAL for a configuration the layer cannot use:
 * a missing map module (map_slot_bytes == 0), max_conns below osd_sessions + 2, max_ops not above ctl_ops or ctl_ops 0, op_bytes_max above the segment
 * cap of a connection or above inflight_bytes_max, max_images / max_reqs / backoff_slots / osd_front_cap (below WRI_OSD_FRONT_MIN) / op_bytes_max /
 * inflight_bytes_max / op_timeout_ms / osd_connect_timeout_ms / img_ctl_bytes zero, an encode buffer (tx_buf_bytes) without room for an OSD message
 * front. Zero is allowed for max_snaps (a writer of an image that has any snapshot is then refused), zombie_bytes (a cancel of a sent write is then
 * WR_E_BUSY), hdr_refresh_ms, map_stale_ms and osd_idle_ms ("never"). Called by wri_client_layout. */
WR_MUST_CHECK wr_status wri_client_osd_mem(const wr_config *cfg, size_t *arena_bytes, size_t *bulk_bytes);

/* Carve and initialise (create time, after the map store): sets c->osd, c->rbd and c->og, binds the link, the map ops and the event hooks. */
WR_MUST_CHECK wr_status wri_client_osd_init(wr_client *c, wri_arena *arena, wri_arena *bulk);

/* The OSD session layer's link over the engine's connection table (wri_client_osd_conn.c): open (role OSD, via wri_client_conn_open), close, send, tx_idle,
 * features, have_ticket (an unexpired OSD ticket), handshake_free (a handshake slot is free). */
void wri_client_osd_link(wr_client *c, wri_osd_link *out);

/* Open a connection with role OSD in a free slot and handshake slot (the osd link's `open`). WR_E_BUSY when none is free, no OSD ticket is held or the
 * engine has failed. wri_client_conn.c owns the slot handling (wri_client_conn_open), this only adds the ticket gate. */
WR_MUST_CHECK wr_status wri_client_conn_open_osd(wr_client *c, const wri_eaddr *addr, const wri_m2_upper *up, void *up_ctx, uint16_t *slot);

/* The stage of wr_client_run, in two halves around the image pass (wri_rbd_step), which wr_client_run calls ITSELF: the stage is one frame less deep in the call
 * graph that way (the deepest chain of the core is 14 frames and goes through the image pass; check_callgraph.py).
 *   wri_client_osd_begin  the object engine's pass (retarget on a new epoch, sessions, sends, timeouts); returns the number of messages / extents one pass of the
 *                         layer may handle (the work budget scaled down, never 0), or 0 when the OSD client is off or the engine has failed (then the image pass
 *                         and wri_client_osd_end are not called); *more is set when the engine has more to do
 *   wri_rbd_step          called by wr_client_run with that number and a deadline (starting at WR_DEADLINE_NONE) it lowers
 *   wri_client_osd_end    remembers that deadline for wri_client_osd_deadline; *more is set when an operation waits to be targeted or sent (the image pass just cut one,
 *                         a session just came up, a map just arrived): the host's loop runs again before it sleeps */
uint32_t wri_client_osd_begin(wr_client *c, uint32_t budget, int *more);
void wri_client_osd_end(wr_client *c, uint64_t rbd_deadline, int *more);
/* Earliest time the OSD client wants to run, WR_DEADLINE_NONE if none or off. */
uint64_t wri_client_osd_deadline(const wr_client *c);
/* The engine has ended (fatal error, state WR_CS_FAILED): every image fails with the engine's first failure, once (the requests complete with it and
 * the host pulls them). No effect when the OSD client is off. */
void wri_client_osd_on_fatal(wr_client *c);
/* The engine only knows the time of its last run, and an open or a submit that comes after a quiet period is timed against that old clock: the deadline
 * would be too early by the whole quiet period (an engine that has never run counts from 0). wr_client_run calls this first thing, with the number of
 * milliseconds the clock moved since the run before (0 if it did not), and every open and every request accepted since then (marked fresh by wr_image_open /
 * wr_image_submit) gets its deadline moved by that amount: it counts from the run that first sees it, the earliest moment the core can act on it. */
void wri_client_osd_rebase(wr_client *c, uint64_t delta_ms);
/* wr_image_open / wr_image_submit: note that image slot `slot` / request `req` (accepted, with a timeout) was timed against the clock of the last run. */
void wri_client_osd_note_open(wr_client *c, uint32_t slot);
void wri_client_osd_note_request(wr_client *c, wr_io_req *req);
/* The OSD client's wipe at destroy: the zombie area of the bulk region holds copies of written data (the arena part is wiped by the engine). */
void wri_client_osd_wipe(wr_client *c);
/* Fill a wr_osd_stats (zeros when off). */
void wri_client_osd_stats(const wr_client *c, wr_osd_stats *out);

#endif /* WRI_CLIENT_OSD_H */
