/* SPDX-License-Identifier: MIT */
/*
 * wr_image.h - RBD images and block I/O on top of the client engine (Phase 1, milestones 7 and 8).
 *
 * The engine owns the cluster session (monitor, OSD map, OSD sessions); an image is a layer on top of it
 * (docs/design/core-architecture.md sections 20 to 29, part C). Everything is sans-IO like the rest of the core: the calls here never
 * block, never allocate, never call the host. Open and every I/O request complete later; the host runs the engine
 * (wr_client_run, then moves bytes as wr_client.h says) and PULLS the results:
 *
 *   wr_image_open()              returns at once with an image in state WR_IMG_OPENING; WR_EV_IMAGE is raised when it is
 *                                WR_IMG_OPEN (or WR_IMG_FAILED: wr_image_error says why)
 *   wr_image_submit(req)         queues a request; WR_E_BUSY when the request table is full (retry after a completion)
 *   wr_client_next_done(c)       the oldest finished request, or NULL; its status is final and its buffer is the host's again
 *
 * A call that changes what the engine has to do (open, submit, cancel, close) does no I/O and cannot wake the host: call
 * wr_client_run() after it (the next run reports more_work = 1), exactly as after wr_client_pool_track().
 *
 * Threading: one owner, not re-entrant, like wr_client.h. wr_io_req structures are owned by the host and must stay valid
 * and unmoved from submit until the request is pulled with wr_client_next_done (or wr_image_cancel said so, see below).
 *
 * What an image is, and what is refused (section 24): RBD format 2, default striping, no parent, no encryption detection, head
 * only (no snapshot open in this phase), features within the profile of wr_image_open. Writes carry the image's snapshot context.
 * A write that has completed is durable: the OSD answers after every replica committed it, so there is nothing to flush at the OSD;
 * WR_IO_FLUSH is an ordering barrier over the writes accepted before it (section 25.4).
 */
#ifndef WR_IMAGE_H
#define WR_IMAGE_H

#include "wr_client.h"
#include "wr_err.h"
#include "wr_types.h"

typedef struct wr_image wr_image; /* lives in the client's arena; the pointer is stable until the image is closed */

#define WR_SNAP_HEAD 0xfffffffffffffffeull /* the live image: the only snapshot id wr_image_open accepts in this phase */

typedef enum wr_image_state {
	WR_IMG_FREE = 0,    /* not a live image (a slot the host holds no pointer to) */
	WR_IMG_OPENING = 1, /* waiting for the OSD map and the header reads */
	WR_IMG_OPEN = 2,
	WR_IMG_FAILED = 3,  /* wr_image_error says why; every request completes with that status; close it */
	WR_IMG_CLOSING = 4  /* wr_image_close was called, writes are draining or cancelled */
} wr_image_state;

typedef struct wr_image_params {
	uint32_t size;          /* sizeof(wr_image_params); checked (WR_E_ABI) */
	const char *pool;       /* pool that holds the image's metadata objects (required); tracked by name */
	const char *name;       /* image name; NULL if id is given */
	const char *id;         /* image id (skips the name lookup); NULL if name is given. Both given: the id is used and name only shown */
	const char *data_pool;  /* name of the data pool: REQUIRED when the image has the data-pool feature (the header only holds the
				 * pool id and the map module tracks pools by name; a name whose id differs is WR_E_RBD_DATA_POOL), else NULL */
	uint64_t snap_id;       /* WR_SNAP_HEAD; anything else is WR_E_UNSUPPORTED in this phase */
	uint32_t open_timeout_ms; /* 0 = wait for ever; else the open fails with WR_E_TIMEOUT after this long (counted from the first wr_client_run after the open call) */
	uint8_t want_write;     /* 0 = read-only profile R1, 1 = writer profile P1 (section 24.3) */
	uint8_t reserved8[3];
	uint32_t reserved[6];   /* zero */
} wr_image_params;

/* Strings are copied during the call. WR_E_INVAL (NULL client, pool, both or neither of name and id), WR_E_TOOBIG (name, id or
 * pool too long), WR_E_UNSUPPORTED (snap_id), WR_E_ABI, WR_E_BUSY (max_images images are open), WR_E_STATE (a client that is
 * failed), and what wr_client_pool_track returns. A configuration without the OSD client (osd_sessions == 0) is WR_E_INVAL. */
WR_MUST_CHECK wr_status wr_image_open(wr_client *c, const wr_image_params *p, wr_image **out);

typedef struct wr_image_info {
	uint64_t size_bytes;    /* the image size as the header says (not rounded to a sector size: that is the host's choice) */
	uint64_t features;      /* RBD feature bits, raw (rbd-format2.md 2.8) */
	uint64_t flags;
	uint64_t snap_seq;      /* the write snapshot context: highest snapshot id ever used, and */
	uint32_t n_snaps;       /* how many snapshots exist (the ids are not exposed) */
	uint32_t object_size;   /* 1 << order */
	uint8_t order;
	uint8_t writable;       /* opened for writing and accepted as a writer */
	uint8_t reserved8[2];
	int64_t pool_id;        /* pool of the metadata objects */
	int64_t data_pool_id;   /* pool of the data objects (equal to pool_id without the data-pool feature) */
	uint32_t max_io_bytes;  /* largest READ / WRITE length wr_image_submit accepts (1 GiB; larger requests are WR_E_TOOBIG) */
	uint32_t reserved[3];
	char image_id[64];      /* NUL terminated */
	char object_prefix[96]; /* NUL terminated: data object i is "<prefix>.<i as 16 lower-case hex digits>" */
} wr_image_info;

/* WR_E_INVAL for a NULL or closed image; WR_E_STATE unless the image is WR_IMG_OPEN (or FAILED after having been open: the last values). */
WR_MUST_CHECK wr_status wr_image_get_info(const wr_image *img, wr_image_info *out);
wr_image_state wr_image_get_state(const wr_image *img);
/* Why the image failed or its open failed: the first failure (never NULL; status 0 while healthy). */
const wr_errinfo *wr_image_error(const wr_image *img);
/* Slot number as carried by WR_EV_IMAGE, and back. wr_client_image_at returns NULL for a free slot. */
uint32_t wr_image_slot(const wr_image *img);
wr_image *wr_client_image_at(wr_client *c, uint32_t slot);

/* ---- block I/O ------------------------------------------------------------------------------------------------ */

typedef enum wr_io_kind {
	WR_IO_READ = 1,         /* buf <- bytes [offset, offset + length); holes and missing objects read as zeros */
	WR_IO_WRITE = 2,        /* bytes [offset, offset + length) <- buf (read by the core until the request completes) */
	WR_IO_FLUSH = 3,        /* completes when every write accepted before it has completed; offset, length, buf unused */
	WR_IO_DISCARD = 4,      /* best effort, reads back as zeros afterwards: whole objects are removed, the rest truncated or zeroed */
	WR_IO_WRITE_ZEROES = 5  /* [offset, offset + length) reads back as zeros; frees space where it can */
} wr_io_kind;

typedef struct wr_io_req {
	wr_io_kind kind;
	uint32_t timeout_ms;    /* 0 = none. After this long (counted from the first wr_client_run after the submit: the engine knows no time between runs) the core
				 * cancels the request (wr_image_cancel) and completes it with WR_E_TIMEOUT */
	uint64_t offset;        /* bytes; with length inside the image or the request fails with WR_E_RANGE */
	uint64_t length;        /* bytes; READ and WRITE at most max_io_bytes, a zero length completes at once */
	void *buf;              /* READ: destination, WRITE: source. Must stay valid until completion (or until wr_image_cancel allows) */
	void *user;             /* the host's cookie, never touched */
	wr_status status;       /* set at completion; the buffer of a failed READ holds unspecified bytes (zero-copy contract, 3.3) */
	uint32_t reserved;
	uint64_t priv[8];       /* private to the core; the host zeroes the whole structure before wr_image_submit */
} wr_io_req;

/*
 * Queue a request. Never blocks, never allocates; the request is cut into object operations as the op table has room.
 * Errors that need no I/O are returned here and the request is NOT queued: WR_E_INVAL (NULL, unknown kind, a buf missing for READ
 * or WRITE), WR_E_STATE (image not WR_IMG_OPEN: WR_E_RBD_CLOSED once failed or closing), WR_E_RBD_READONLY (a write kind on a
 * read-only image), WR_E_TOOBIG (length above max_io_bytes), WR_E_RANGE (outside the image), WR_E_BUSY (max_reqs requests in
 * flight: retry after a completion). Everything else completes later through wr_client_next_done().
 */
WR_MUST_CHECK wr_status wr_image_submit(wr_image *img, wr_io_req *req);

/* The oldest request the core is finished with, NULL if none. Order is completion order, not submit order. The structure may be
 * reused or freed by the host as soon as it is returned. */
wr_io_req *wr_client_next_done(wr_client *c);

/*
 * Cancel a request the host no longer wants (a timeout of its own, a storport abort). Semantics (section 25.5):
 *   - WR_OK: the request is finished at once with status WR_E_CANCELLED; it is returned by wr_client_next_done() like any other
 *     and its buffer is the host's again from then on. A write whose operations were already sent stays alive inside the core
 *     (a copy of the unanswered data, section 25.5) until the cluster answered it, and later requests overlapping its range wait
 *     for it: abandoning a write never reorders it behind a later write;
 *   - WR_E_BUSY: the buffer is still referenced (a transmit queue holds it, or a reply is landing in it, or the zombie budget
 *     zombie_bytes is full): the core has started resetting the session that references it; the request is cancelled by itself
 *     when that finished and then completes through wr_client_next_done() with WR_E_CANCELLED (or its own status if it won the race);
 *     the host keeps the buffer until then;
 *   - WR_E_STATE: not a request in flight (already completed or never submitted).
 */
WR_MUST_CHECK wr_status wr_image_cancel(wr_image *img, wr_io_req *req);

/* Flags of wr_image_close. */
#define WR_CLOSE_DRAIN 0u    /* wait for the writes in flight to complete, then free the slot (WR_EV_IMAGE tells when) */
#define WR_CLOSE_ABANDON 1u  /* cancel everything: reads are dropped, unanswered writes continue as zombies, the slot is freed at once */

/* WR_E_INVAL for a NULL or already closed image. Requests in flight complete with WR_E_CANCELLED (reads) or finish (DRAIN writes). */
WR_MUST_CHECK wr_status wr_image_close(wr_image *img, uint32_t flags);

/* Counters, to tune budgets and for diagnostics. */
typedef struct wr_osd_stats {
	uint32_t ops_inflight, ops_hiwater;
	uint32_t reqs_inflight, reqs_hiwater;
	uint32_t sessions_open, sessions_hiwater;
	uint64_t ops_done, ops_resent, ops_failed;
	uint32_t n_session_resets;     /* sessions closed by a timeout or a protocol error */
	uint32_t n_backoff_blocks;     /* MOSDBackoff BLOCK messages honoured */
	uint32_t n_backoff_overflow;   /* ... that did not fit the table (the PG is held whole then) */
	uint32_t n_osdmap_discarded;   /* MOSDMap messages an OSD pushed and the core ignored (the monitor subscription is the source) */
	uint32_t zombie_bytes_used, zombie_bytes_max;
	uint32_t reserved[4];
} wr_osd_stats;

void wr_client_osd_stats(const wr_client *c, wr_osd_stats *out);

#endif /* WR_IMAGE_H */
