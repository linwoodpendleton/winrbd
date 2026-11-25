/* SPDX-License-Identifier: MIT */
/*
 * wr_ra.h - the readahead cache of a block device on top of an RBD image (docs/design/ipxe-driver.md section 10).
 *
 * A pure state machine over memory the host supplies: it never allocates, never calls the host, never copies a byte of image
 * data and never talks to the cluster. The host owns the I/O: it asks the module what to do with each read, performs that, and
 * reports what happened. One owner, not re-entrant, like wr_client.h.
 *
 * The cache is `lines` slots of `line_bytes` each (256 KiB by default; the line size is a field). A slot holds the line
 * number `lno` (image offset >> log2(line_bytes)) of the data it is meant to hold; line `lno` lives in slot `lno % lines`
 * (direct mapped, so a window that is larger than the cache simply wraps around it: a ring). A slot is
 *
 *   EMPTY     no data (a slot that never held anything, was invalidated, or whose prefetch failed)
 *   PENDING   the host has a wr_io_req in flight that fills the slot's memory; the bytes are not usable yet
 *   VALID     the whole line is in the slot's memory and equals the image (as far as the host's writes are concerned)
 *
 * The host's side of the contract, per block command:
 *
 *   READ    wr_ra_read(off, len, &act), then by act.kind
 *             WR_RA_HIT   every byte is in VALID lines: copy it out with wr_ra_span() (a loop over contiguous spans) and complete the
 *                         command in the same step. No network.
 *             WR_RA_WAIT  the bytes will be here when line act.line (a slot number) is done: park the command, and when the host has
 *                         reported that line (wr_ra_line_done or wr_ra_line_failed) call wr_ra_read again with the same arguments (the
 *                         call is a pure re-query; the detector below does not count a repeat of the previous arguments twice).
 *             WR_RA_MISS  read straight into the caller's buffer (zero copy), exactly as without a cache.
 *           Then, in this order and before the engine is allowed to run: copy the hit, then drain the prefetches
 *           (wr_ra_prefetch_next until it returns 0), submitting each as a WR_IO_READ of pf.len bytes at pf.offset into pf.buf.
 *           demand_bytes is the length of the demand read the host has in flight at that moment (0 for a hit or a wait): a prefetch
 *           that would push prefetch + demand bytes in flight above inflight_max is not listed, nor one that would leave fewer than one free
 *           request (max_reqs) for the demand read.
 *           A prefetch listed is a slot that is PENDING from then on. Give every prefetch a request timeout well below the SAN command timeout
 *           (a few seconds): a command parked on a line has nothing but that request to wait for, so a prefetch aimed at an OSD that does not
 *           answer holds the command until the request times out (it then fails silently and the retry of the read is a plain miss). If wr_image_submit refuses it, call wr_ra_line_unissued for
 *           that slot and stop draining (the next completion is the time to try again).
 *   WRITE   submit the write, and right after it was accepted call wr_ra_write (no prefetch drained in between: the image layer
 *           orders a read submitted after a write behind it and one submitted before it ahead of it, and the module has to know
 *           which prefetches were ahead). Every VALID line the write overlaps goes EMPTY; a PENDING one stays reserved (its memory is
 *           still the target of a request) and is dropped when it lands. A write is never delayed by the cache.
 *   DONE    when a prefetch request completes: wr_ra_line_done (status OK) or wr_ra_line_failed (any other status, including
 *           cancelled). A failed prefetch is silent: the line returns to EMPTY and only demand reads report errors. Then drain
 *           prefetches again (a landed line frees in-flight room; the window slides).
 *   REOPEN  wr_ra_reset(new size): drops every VALID line, forgets the stream, and keeps the PENDING slots reserved as dropped until
 *           the host has reported them (they still own their memory); cancel or let the requests finish, then report each.
 *
 * The window. A read that starts where the previous one ended (a forward gap of at most seq_gap bytes, one line by default, or a
 * jump forward inside what the window already covers), seq_trigger times in a row (default 2), opens a window of window_bytes: the
 * module then lists the lines that cover [end of the last read, end + window_bytes) that are not cached, up to the in-flight limit
 * and never more lines than the cache has. A read that does not continue the stream closes the window (lines already cached or in
 * flight stay and still serve hits).
 *
 * Contract details the module relies on: the host copies a hit before it submits prefetches (a prefetch may take the slot of a
 * line behind the stream; the lines of a read that was answered WR_RA_WAIT are the exception: they are kept until the host asks again); a line is only ever reported done or failed once; reads and writes are inside the image.
 *
 * No globals, no recursion, no 64-bit division (i386 iPXE has no __udivdi3), frames of a few dozen bytes (BIOS stack: 4 KiB).
 */
#ifndef WR_RA_H
#define WR_RA_H

#include "wr_err.h"
#include "wr_types.h"

#define WR_RA_LINE_DEFAULT (256u * 1024u)   /* line_bytes = 0 */
#define WR_RA_LINE_MIN 4096u                /* line sizes are powers of two in [WR_RA_LINE_MIN, WR_RA_LINE_MAX] */
#define WR_RA_LINE_MAX (4u * 1024u * 1024u)
#define WR_RA_LINES_MAX 1024u               /* slots */
#define WR_RA_CACHE_MAX (1024u * 1024u * 1024u) /* lines * line_bytes */
#define WR_RA_INFLIGHT_DEFAULT (4u * 1024u * 1024u) /* inflight_max = 0: the iPXE profile's inflight_bytes_max */
#define WR_RA_TRIGGER_DEFAULT 2u            /* seq_trigger = 0 */

typedef struct wr_ra wr_ra; /* lives at the start of the region the host supplied; stable until the region is released */

typedef struct wr_ra_cfg {
	uint32_t size;          /* sizeof(wr_ra_cfg); checked (WR_E_ABI) */
	uint32_t line_bytes;    /* 0 = WR_RA_LINE_DEFAULT; else a power of two in [WR_RA_LINE_MIN, WR_RA_LINE_MAX] */
	uint32_t lines;         /* number of slots, 1 .. WR_RA_LINES_MAX; the cache is lines * line_bytes (at most WR_RA_CACHE_MAX) */
	uint32_t window_bytes;  /* the window W; 0 = no readahead (the module then never lists a prefetch and only serves what is in it) */
	uint32_t inflight_max;  /* bytes of prefetch plus the demand read in flight at once; 0 = WR_RA_INFLIGHT_DEFAULT */
	uint32_t seq_trigger;   /* sequential reads in a row that open the window; 0 = WR_RA_TRIGGER_DEFAULT */
	uint32_t seq_gap;       /* forward gap that still counts as "where the previous ended"; 0 = line_bytes */
	uint32_t max_reqs;      /* requests the host's table holds (wr_config.max_reqs); the module keeps one free for the demand read, so at most
				 * max_reqs - 1 prefetches are ever in flight (max_reqs 1 lists none); 0 = no such limit */
	uint64_t image_bytes;   /* the usable size of the device, at least 1; reads and writes beyond it are refused */
	uint32_t reserved[4];   /* zero */
} wr_ra_cfg;

/*
 * Fill cfg for a cache of readahead_kib KiB (the `readahead=` option): 256 KiB lines, as many as fit (at least one), window =
 * readahead_kib KiB, defaults for the rest. WR_E_INVAL for readahead_kib == 0 (the host then simply has no cache) or image_bytes == 0,
 * WR_E_TOOBIG above WR_RA_CACHE_MAX or more than WR_RA_LINES_MAX lines. inflight_max 0 = default. cfg is zeroed first.
 */
WR_MUST_CHECK wr_status wr_ra_cfg_from_kib(wr_ra_cfg *cfg, uint64_t image_bytes, uint32_t readahead_kib, uint32_t inflight_max);

/*
 * Pure arithmetic, overflow checked: the bytes of the region wr_ra_init needs (the wr_ra header, the slot table and the line memory,
 * in that order, every part 16-byte aligned). WR_E_INVAL / WR_E_ABI / WR_E_TOOBIG for a configuration the module refuses.
 */
WR_MUST_CHECK wr_status wr_ra_mem_required(const wr_ra_cfg *cfg, size_t *out);

/*
 * Set up the module in mem (base 16-byte aligned, size >= wr_ra_mem_required; else WR_E_INVAL / WR_E_BUDGET). Nothing is allocated
 * afterwards, ever. The line memory is not written (it only ever holds bytes the host landed there). *out is the module's handle.
 */
WR_MUST_CHECK wr_status wr_ra_init(const wr_ra_cfg *cfg, wr_mem_region mem, wr_ra **out);

/* ---- reads ---------------------------------------------------------------------------------------------------- */

typedef enum wr_ra_kind {
	WR_RA_HIT = 1,  /* complete from the cache now (wr_ra_span) */
	WR_RA_WAIT = 2, /* wait for line `line`, then ask again */
	WR_RA_MISS = 3  /* demand read straight into the caller's buffer */
} wr_ra_kind;

typedef struct wr_ra_act {
	wr_ra_kind kind;
	uint32_t line;  /* WR_RA_WAIT: the slot to wait for (the first PENDING one of the range); otherwise 0 */
} wr_ra_act;

/*
 * Classify a read of len bytes at off and feed the sequential detector. WR_E_INVAL (NULL, len 0 is answered WR_RA_HIT with nothing to
 * copy and does not touch the detector), WR_E_RANGE (outside the image). A range needs every one of its lines VALID for a hit; a range
 * with a line that is neither VALID nor a live PENDING one (EMPTY, dropped, or evicted) is a miss even if other lines are cached, and so is a
 * range wider than the cache.
 */
WR_MUST_CHECK wr_status wr_ra_read(wr_ra *ra, uint64_t off, uint32_t len, wr_ra_act *act);

/*
 * The contiguous bytes at off that a hit holds: sets *p to them and returns how many (at most len, never past the end of the line, 0
 * when the line at off is not VALID). A hit is copied by a loop: while (len) { n = wr_ra_span(ra, off, len, &p); copy(p, n); off += n; len -= n; }
 * The pointer is good until the host next reports a line, drains a prefetch or resets.
 */
size_t wr_ra_span(const wr_ra *ra, uint64_t off, uint32_t len, const uint8_t **p);

/* ---- prefetch ------------------------------------------------------------------------------------------------- */

typedef struct wr_ra_pf {
	uint64_t offset;  /* image offset of the line (a multiple of line_bytes) */
	uint32_t len;     /* bytes to read: line_bytes, less for the last line of the image */
	uint32_t line;    /* the slot; pass it back to wr_ra_line_done / _failed / _unissued */
	void *buf;        /* the slot's memory: the destination of the read */
} wr_ra_pf;

/*
 * The next prefetch to submit, or 0 when there is none (no window, everything the window covers is cached or in flight or failed, the
 * in-flight limit is reached, or the slots the rest would need are busy). Returns 1 and fills *pf, and the slot is PENDING from now on.
 * demand_bytes: see the header comment. Cheap enough to call after every read and every completion.
 */
WR_MUST_CHECK int wr_ra_prefetch_next(wr_ra *ra, uint32_t demand_bytes, wr_ra_pf *pf);

/*
 * The prefetch of slot `line` finished. wr_ra_line_done: its data is in the memory; *kept (may be NULL) is 1 when the line became VALID,
 * 0 when it was dropped because a write or a reset came after the request was submitted. wr_ra_line_failed: it failed or was cancelled; the
 * slot goes back to EMPTY and the module does not try that line again until the stream restarts. wr_ra_line_unissued: the host could not
 * submit it at all (the request table was full): back to EMPTY, no mark, not counted as issued. WR_E_INVAL for a slot that does not exist,
 * WR_E_STATE for a slot that is not PENDING.
 */
WR_MUST_CHECK wr_status wr_ra_line_done(wr_ra *ra, uint32_t line, uint32_t *kept);
WR_MUST_CHECK wr_status wr_ra_line_failed(wr_ra *ra, uint32_t line);
WR_MUST_CHECK wr_status wr_ra_line_unissued(wr_ra *ra, uint32_t line);

/* ---- writes, reopen, counters --------------------------------------------------------------------------------- */

/* A write of len bytes at off was submitted (see the header comment for when). Returns how many lines it invalidated (VALID dropped plus
 * PENDING marked for dropping). Bytes outside the image are ignored; len 0 does nothing. */
uint32_t wr_ra_write(wr_ra *ra, uint64_t off, uint64_t len);

/* Drop everything and forget the stream (the host reopened the image, which may have changed size). PENDING slots stay reserved until
 * reported. WR_E_INVAL for NULL or image_bytes 0. */
WR_MUST_CHECK wr_status wr_ra_reset(wr_ra *ra, uint64_t image_bytes);

typedef struct wr_ra_stats {
	uint64_t reads;          /* wr_ra_read calls that were answered */
	uint64_t hits, waits, misses; /* ... by kind (a wait that is asked again counts again) */
	uint64_t windows;        /* times the detector opened the window */
	uint64_t pf_issued;      /* prefetches listed and not taken back (wr_ra_line_unissued) */
	uint64_t pf_landed;      /* ... that became VALID */
	uint64_t pf_failed;      /* ... that failed */
	uint64_t pf_dropped;     /* ... that landed or failed after a write or reset made them stale */
	uint64_t writes;         /* wr_ra_write calls that touched the image */
	uint64_t lines_invalidated; /* lines a write or a reset dropped or marked */
	uint32_t pend_lines;     /* PENDING slots now (stale ones included: their memory is still a request's target) */
	uint32_t pend_bytes;     /* bytes of prefetch in flight now */
	uint32_t pend_hiwater_bytes; /* the most pend_bytes ever reached */
	uint32_t valid_lines;    /* VALID slots now */
	uint32_t reserved[4];
} wr_ra_stats;

void wr_ra_get_stats(const wr_ra *ra, wr_ra_stats *out);

#endif /* WR_RA_H */
