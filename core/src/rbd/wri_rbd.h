/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd.h - the RBD image layer: the image object, the request table, and the entry points of its two halves (open: wri_rbd_open.h,
 * I/O: wri_rbd_io.h). Design: docs/design/core-architecture.md sections 24 and 25.
 *
 * The layer sits on the object operation engine (wri_osd_req.h): an image submits object operations and pulls them when they are
 * done. Nothing here knows connections or the monitor. Everything is carved from the arena at create time (wri_rbd_mem), nothing is
 * allocated afterwards; images and requests are fixed tables addressed by index, ops carry (image, request slot, generation) as their
 * owner tag.
 *
 * The state a host sees as wr_image is a wri_rbd_img; the structure it embeds per request, wr_io_req.priv, is a wri_rbd_rqpriv.
 *
 * Module split: rbd-open owns wri_rbd_open.c, wri_rbd_open_dec.c (the open, refresh and close state machines); rbd-io owns
 * wri_rbd.c (wri_rbd_mem, wri_rbd_init), wri_rbd_io.c, wri_rbd_io_split.c, wri_rbd_io_fence.c, wri_rbd_io_cancel.c; rbd-geom owns wri_rbd_geom.c; client-glue-osd owns wr_image.c and wri_rbd_step.c.
 */
#ifndef WRI_RBD_H
#define WRI_RBD_H

#include "wr_image.h"
#include "wri_osd_req.h"
#include "wri_rbd_cls.h"

/* ---- image ------------------------------------------------------------------------------------------------------- */

typedef enum wri_ros { /* the open state machine: what the image waits for (design 24.2) */
	WRI_ROS_IDLE = 0,
	WRI_ROS_POOLS,       /* map not here yet, or the pools were tracked after it and wait for the full map that has them */
	WRI_ROS_GET_ID,      /* rbd get_id on rbd_id.<name> */
	WRI_ROS_HEADER,      /* the eight header calls in one message */
	WRI_ROS_EXTRA,       /* get_stripe_unit_count / op_features_get, only when their feature bits are set */
	WRI_ROS_READY,
	WRI_ROS_REFRESH      /* header re-read of a writer (state stays OPEN for reads; writes wait) */
} wri_ros;

typedef struct wri_rbd_img {
	uint8_t state;                 /* wr_image_state */
	uint8_t ros;                   /* wri_ros */
	uint8_t want_write;
	uint8_t writable;              /* accepted as writer by the profile check */
	uint8_t close_flags;           /* WR_CLOSE_* once CLOSING */
	uint8_t was_open;              /* reached OPEN at least once (wr_image_get_info answers after a failure) */
	uint8_t order;
	uint8_t reserved8;
	uint16_t slot;                 /* index in the table: carried by WR_EV_IMAGE */
	uint16_t gen;                  /* bumped when the slot is reused: a stale op owner tag never matches */
	wr_pool_h pool_h, data_pool_h; /* tracked pools */
	int64_t pool_id, data_pool_id;
	char name[WRI_RBD_NAME_MAX];   /* copy; "" when opened by id */
	char id[WRI_RBD_ID_MAX];
	char prefix[WRI_RBD_PREFIX_MAX];
	uint64_t size, features, flags, op_features;
	wri_snapc snapc;               /* the write snapshot context; `snaps` has max_snaps entries in the arena */
	uint8_t *ctl_in;               /* control call input (WRI_RBD_CTL_IN bytes), laid out by the open, stays valid while an op uses it */
	uint8_t *ctl_out;              /* control call output (img_ctl_bytes), where the reply data segment of a header read lands */
	uint32_t ctl_op;               /* op slot of the control read in flight, WRI_NIL if none */
	uint64_t open_deadline_ms;     /* open_timeout_ms as an absolute mono time, WR_DEADLINE_NONE = none */
	uint64_t refreshed_ms;         /* mono time of the last header read */
	uint64_t next_refresh_ms;      /* WR_DEADLINE_NONE when hdr_refresh_ms is 0 or the image is read-only */
	uint32_t n_reqs;               /* requests in flight on this image */
	uint32_t n_writes_unfinished;  /* writes accepted and not completed: the flush barrier counts these */
	uint64_t seq;                  /* next request sequence number (flush and fence order) */
	wr_errinfo err;                /* first failure */
	/* ---- added by rbd-open (design 24.2, 24.4): only wri_rbd_open*.c writes these ---- */
	wri_rbd_hdr hdr;               /* the last accepted header read, with the stripe unit / count and op_features of the EXTRA step; during the open, the header waiting for its EXTRA read */
	uint64_t refresh_start_ms;     /* mono time at which the header read in flight was submitted (refreshed_ms becomes this when it is adopted); while POOLS, the time the open began */
	uint32_t full_need;            /* POOLS: the full-map count (wr_map_stats.n_full) a pool that reads as absent waits for; 0 = no wait */
	int32_t snapc_status;          /* WR_OK, or what the snapshot-context decode of the header read said (judged at its place in the order of 24.3) */
	uint32_t snapc_total;          /* snapshots the server sent in that read */
	uint8_t hdr_stale;             /* 0 fresh; 1 marked stale (a header read submitted after the mark is needed); 2 stale and that read is in flight */
	uint8_t has_data_pool;         /* the host named a data pool: data_pool_h is tracked */
	uint8_t ctl_fails;             /* OPEN: consecutive refresh reads that came back as a protocol error (a reply that does not fit img_ctl_bytes, or garbage); WRI_RBD_PROTO_TRIES ends the image */
	uint8_t reserved8b;
} wri_rbd_img;

#define WRI_RBD_PROTO_TRIES 3u     /* refresh reads of an open image that may fail with a protocol error one after the other before the image fails (each one costs the OSD session) */
#define WRI_RBD_CTL_IN 512u        /* bytes of control call input per image (eight calls with their arguments are about 120) */

/* ---- request ------------------------------------------------------------------------------------------------------ */

typedef enum wri_rq_state {
	WRI_RQ_FREE = 0,
	WRI_RQ_WAIT,        /* accepted, not admitted yet: an earlier overlapping request or a header refresh holds it */
	WRI_RQ_RUN,         /* admitted: its extents are being cut into operations as the op table has room */
	WRI_RQ_FINISH,      /* every extent answered, the completion is queued for wr_client_next_done */
	WRI_RQ_ZOMBIE       /* cancelled while a sent write is unanswered: only the fence entry stays (range, seq) until it is resolved */
} wri_rq_state;

/* The table entry of one request; the host's wr_io_req holds only (slot, gen) in its priv words (still 80 bytes: the fields added by
 * module rbd-io sit in what was padding). */
typedef struct wri_rbd_rq {
	wr_io_req *req;                /* NULL for a zombie and for a free slot (a FINISH entry keeps it until the host pulls the completion) */
	uint16_t img;                  /* image slot */
	uint16_t gen;                  /* generation of the slot: part of every owner tag, bumped when the slot is freed */
	uint8_t state;                 /* wri_rq_state */
	uint8_t kind;                  /* wr_io_kind */
	uint8_t cancelling;            /* a cancel found a write whose copy does not fit the zombie area (WR_E_BUSY was returned): retried every pass; a request that dropped an
	                                * operation meanwhile already carries the cancel's status as its first failure (the dropped extent will never be written) */
	uint8_t zomb;                  /* FINISH: the request also leaves a fence entry behind (an operation lives on as a zombie in the engine); the entry
	                                * becomes ZOMBIE when the host pulls the completion and goes when the engine has answered the zombie */
	uint64_t seq;                  /* image-wide submission sequence */
	uint64_t off, len;             /* the byte range (flush: none) */
	uint64_t cur;                  /* next byte of the range to cut into an operation */
	uint16_t ops_out;              /* object operations in flight (at most max_ops, which is 16 bits) */
	uint8_t resnap;                /* writes: how many times an -EOLDSNAPC answer sent this request back to the header refresh (at most WRI_RBD_RESNAP_MAX) */
	uint8_t held;                  /* writes: an -EOLDSNAPC answer rewound the cursor; no extent is cut until the refresh it asked for is adopted */
	uint32_t bytes_out;            /* payload bytes of those */
	wr_status status;              /* first failure; WR_OK while healthy */
	uint16_t img_gen;              /* generation of the image slot at submit: a request outlives a closed image only as a zombie or a late answer */
	uint16_t zops;                 /* operations of this request that were handed to the engine as zombies */
	uint64_t deadline_ms;          /* timeout_ms as an absolute time, WR_DEADLINE_NONE = none */
	uint32_t done_next;            /* a cancel that answered WR_E_BUSY (cancelling): the status the request ends with when the cancel goes through */
	uint32_t link;                 /* free list of the table */
} wri_rbd_rq;
WR_STATIC_ASSERT(sizeof(wri_rbd_rq) <= 80, wri_rbd_rq_80_bytes);

/* The part of wr_io_req.priv the core uses (64 bytes in all). */
typedef struct wri_rbd_rqpriv {
	uint16_t img, slot;
	uint16_t gen;
	uint16_t used;                 /* 0x5242 once the core owns the structure: a second submit of the same structure is refused */
	uint32_t fresh;                /* client-glue-osd: 1 while the deadline was set against the clock of the engine's last run (wri_client_osd_rebase moves it at the next one) */
	uint64_t pad[6];
} wri_rbd_rqpriv;
WR_STATIC_ASSERT(sizeof(wri_rbd_rqpriv) <= sizeof(((wr_io_req *)0)->priv), wri_rbd_rqpriv_fits);

/* ---- the layer ---------------------------------------------------------------------------------------------------- */

struct wri_rbd_pools; /* wri_rbd_open.h: how the open tracks pools and reads the full-map count (the table is the host's / the glue's and outlives the layer) */

typedef struct wri_rbd {
	const wri_ctx *x;
	wri_osdc *osd;
	wri_rbd_img *img;              /* max_images */
	uint32_t n_img;
	wri_rbd_rq *rq;                /* max_reqs */
	uint32_t n_rq;
	uint32_t *done_ring;           /* max_reqs completed request slots, completion order */
	uint32_t done_len, done_pos;
	uint64_t *snap_mem;            /* max_images * max_snaps snapshot ids */
	uint8_t *ctl_mem;              /* max_images * (WRI_RBD_CTL_IN + img_ctl_bytes) */
	uint32_t reqs_inflight, reqs_hiwater;
	void (*event)(void *ctx, wr_ev_kind kind, uint32_t arg, const wr_errinfo *err); /* WR_EV_IMAGE / WR_EV_IO_* into the engine's ring */
	void *event_ctx;
	const struct wri_rbd_pools *pools; /* rbd-open: set by wri_rbd_open_start; wri_rbd_init keeps it */
	/* ---- added by module rbd-io (the part above is the skeleton's) ---- */
	uint32_t rq_free;              /* head of the free list of the request table (linked through wri_rbd_rq.link), WRI_NIL = none */
	uint32_t cut_pos;              /* where the next cutting pass starts its round (fairness) */
	uint32_t zd_seen;              /* osd->n_zombies_done at the last look at the zombie entries */
	uint32_t dirty;                /* WRI_RIO_DIRTY_*: what a pass over the table has to look at again */
	uint32_t fatal_img;            /* image slot whose request got a fatal answer (blocklisted), WRI_NIL = none: see wri_rbd_io_take_fatal */
	wr_status fatal_st;
	uint64_t n_submitted, n_completed, n_zombie_entries; /* counters: requests accepted, completions queued, fence entries left behind */
} wri_rbd;

WR_MUST_CHECK wr_status wri_rbd_mem(const wr_config *cfg, size_t *arena_bytes);
WR_MUST_CHECK wr_status wri_rbd_init(wri_rbd *r, const wri_ctx *x, wri_arena *arena, wri_osdc *osd);
/* Everything the layer does in one pass, after wri_osdc_step: advance opens and refreshes (wri_rbd_open_step), collect finished operations,
 * admit and cut requests, queue completions, expire request timeouts (wri_rbd_io_*). Returns 1 if more is ready; *deadline is lowered to the
 * next time it wants to run. Defined in wri_rbd_step.c (module client-glue-osd, so rbd-open and rbd-io are testable apart). */
int wri_rbd_step(wri_rbd *r, uint32_t budget, uint64_t *deadline);

/* ---- module rbd-io: what the I/O half adds to the layer (design 25) ---------------------------------------------------------- */

/* A function with many temporaries is kept out of its caller's frame: the sanitizer builds at -O0 give every temporary its own slot and the 1 KiB frame limit counts them. */
#if defined(__GNUC__) || defined(__clang__)
#define WRI_RIO_NOINLINE __attribute__((noinline))
#else
#define WRI_RIO_NOINLINE
#endif

#define WRI_RBD_IO_MAX 0x40000000u     /* largest READ / WRITE length wri_rbd_submit accepts (wr_image_info.max_io_bytes) */
#define WRI_RBD_RQ_QUANTUM 4u          /* object operations a request may cut in one visit of a cutting round (fairness between requests) */
#define WRI_RBD_RESNAP_MAX 8u          /* -EOLDSNAPC answers one write request survives (each costs a header refresh); the next one fails the request with the OSD's status */
#define WRI_RBD_PRIV_MAGIC 0x5242u     /* wri_rbd_rqpriv.used of a request the core owns */
#define WRI_RIO_DIRTY_ADMIT 1u         /* a request finished, was cancelled or arrived: WAIT requests may be admitted now */
#define WRI_RIO_DIRTY_BARRIER 2u       /* a write finished: a flush may be complete */
#define WRI_RIO_DIRTY_ZOMB 4u          /* a fence entry of a zombie exists that has not been looked at since the engine's last answer */

/*
 * The owner tag of a data operation is (request slot << 16) | request generation; the image is the request's own. Only wri_rbd_io_collect pops
 * the engine's done ring: an operation taken from the control reserve (WRI_OPF_CONTROL: the open and the refresh) is popped and left in state DONE,
 * unreleased, for the open machine to find through its image's ctl_op and to release itself; every data operation is released by collect.
 * The owner tag of a control operation is the open machine's business.
 */
#define WRI_RBD_TAG(slot, gen) (((uint32_t)(slot) << 16) | (uint32_t)(gen))

/*
 * The order in which wri_rbd_step runs the I/O half in one pass (after wri_osdc_step and wri_rbd_open_step): wri_rbd_io_collect (applies answers,
 * retries cancels that found no zombie room, releases answered zombies and complete flushes), wri_rbd_io_cut (admission by the fence, then the cutting
 * loop with the pass budget), wri_rbd_io_timeouts (request deadlines; *deadline is lowered to the next one), then wri_rbd_io_take_fatal in a loop:
 * every image it names gets wri_rbd_img_fail. The pass wants to run again at once when wri_rbd_io_cut returned 1 or a completion was queued
 * (done_len != 0 is the host's to pull, not a reason to run).
 */

/* The image behind a request, NULL if the slot was freed or reused since the request was accepted. */
wri_rbd_img *wri_rio_img(const wri_rbd *r, const wri_rbd_rq *q);
/* Writes (WRITE, DISCARD, WRITE_ZEROES) and everything else: 1 for a kind that changes the image. */
int wri_rio_is_write(uint8_t kind);
/* A request leaves RUN / WAIT for the completion queue with `st` (the first failure of the request wins); `zops != 0` leaves a fence entry. */
void wri_rio_finish(wri_rbd *r, uint32_t slot, wr_status st);
/* Free a table slot (generation + 1, free list). */
void wri_rio_free(wri_rbd *r, uint32_t slot);
/* First failure of a request: stops its cutting; a read drops its other operations and ends at once, a write ends when its operations were answered. */
void wri_rio_fail(wri_rbd *r, uint32_t slot, wr_status st);
/* The three cases of design 25.5 for one request in WAIT / RUN: WR_OK (finished with `st`), WR_E_BUSY (the request keeps running and is cancelled by
 * itself later), WR_E_STATE (not in WAIT / RUN). */
wr_status wri_rio_cancel_rq(wri_rbd *r, uint32_t slot, wr_status st);
/* Fence (design 25.4): 1 if an earlier request of the image that is still in the table blocks `slot`; the writer gate of the header refresh. */
int wri_rio_blocked(const wri_rbd *r, uint32_t slot);
int wri_rio_gate_closed(const wri_rbd *r, const wri_rbd_img *im);
/* Operations of the engine still alive for a request tag (zombies included, finished ones in the done ring not). */
uint32_t wri_rio_live_ops(const wri_rbd *r, uint32_t tag);
/* Resolve what completions leave open: answered zombies release their fence entries, flushes whose earlier writes are done complete. */
void wri_rio_settle(wri_rbd *r);
/* Retry the cancels that found no room for a write's copy (WR_E_BUSY): finished with their cancellation, or left running if the answers came first. */
void wri_rio_retry_cancels(wri_rbd *r);
/* WAIT -> RUN for every request nothing blocks any more (called by wri_rbd_io_cut). */
void wri_rio_admit(wri_rbd *r);
/* The next fatal answer of the I/O half: an image whose request was answered "blocklisted" (the cluster refuses this client for good). 1 and *img /
 * *st set, once per event; the step glue calls wri_rbd_img_fail with it (the I/O half cannot, rbd-open is a separate module). */
int wri_rbd_io_take_fatal(wri_rbd *r, uint32_t *img, wr_status *st);

#endif /* WRI_RBD_H */
