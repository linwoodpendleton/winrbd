/* SPDX-License-Identifier: MIT */
/*
 * wrl_cmp.h - the krbd comparison engine (Phase 1 milestone 9, docs/design/core-architecture.md section 33).
 *
 * One engine, three witnesses. The core (wr_image_*, byte granularity, requests in flight up to depth) and a block device
 * (an operations table: pread / pwrite / discard / write-zeroes / flush on an O_DIRECT fd of /dev/rbdN in the lab, a regular
 * file in the tool's self test, a function over the simulator's object store in ctest) are two readers and two writers of the
 * same image; a flat in-memory model, chunked in 64 KiB pieces allocated when first written, is the third. After every
 * operation both clients read the range back (and the bytes around it, which must be unchanged) and the three results are
 * compared. When they differ, a fresh read by both says who is alone (the attribution table):
 *
 *   core = model, device = model     ok
 *   device = model, core differs     "core"    a core bug (fail)
 *   core = model, device differs     "device"  a krbd or lab fault: re-run once, two in a row fail
 *   core = device, model differs     "model"   a tool bug, or a write fault that both readers see (fail; the record names the writer)
 *   none equal                       "both"    fail, both digests recorded
 *
 * Phases: edges (deterministic object boundary, hole, last partial object, past the end, unaligned classes at the image's
 * order: wrl_cmp_edges_build), random (seeded, boundary biased, read / write / discard / write-zeroes / flush) and scan (a
 * full read by both clients, in different chunk sizes, against the model; at the end of every phase and every checkpoint
 * operations). Directions: core-to-krbd, krbd-to-core, interleave, all.
 *
 * Records are "@<ms> <kind> key=value ..." lines like wr-rbd's, on cfg->out. They never carry key material (the engine never
 * sees any) or payload bytes. The exit code of wrl_cmp_run is the exit status of the wr-krbdcmp tool: 0 no difference,
 * 1 a difference, 3 a client failed (the image went FAILED, the loop failed), 4 a request failed with no difference (an I/O
 * error, a short transfer, a hang past stall_ms); 2 (usage, setup) is the caller's.
 *
 * Threading: the engine runs the device's blocking calls in one worker thread of its own, so a hung device cannot hold the
 * watchdog. The core, the loop and everything else are used from the calling thread only. A device call that has not returned
 * when the run ends (a hang) is abandoned: its thread and buffers are left behind on purpose, the process is about to exit.
 *
 * Harness code: libc, POSIX and malloc are allowed.
 */
#ifndef WRL_CMP_H
#define WRL_CMP_H

#include <stdint.h>
#include <stdio.h>

#include "wrl_host.h"

/* ---- the device ------------------------------------------------------------------------------------------------------ */

/*
 * Every call is blocking, runs on the engine's worker thread (never two at once) and returns what the system call would: a
 * byte count (pread, pwrite; a short count is reported as an error by the engine, except for the single refusal checks at
 * the end of the device) or 0 (the others), or -errno. offset, length and the buffer are aligned to `sector` (the buffer to
 * 4096) as O_DIRECT needs, except in the tool's self test where the "device" is a regular file.
 */
typedef struct wrl_cmp_dev {
	void *ctx;
	long (*pread)(void *ctx, void *buf, size_t n, uint64_t off);
	long (*pwrite)(void *ctx, const void *buf, size_t n, uint64_t off);
	int (*discard)(void *ctx, uint64_t off, uint64_t len);   /* BLKDISCARD */
	int (*zeroes)(void *ctx, uint64_t off, uint64_t len);    /* BLKZEROOUT */
	int (*flush)(void *ctx);                                 /* BLKFLSBUF, then fsync */
	int (*size)(void *ctx, uint64_t *bytes);                 /* capacity in bytes, a multiple of sector */
	uint32_t sector;                                         /* logical sector size, a power of two, 512 .. 4096 */
} wrl_cmp_dev;

/* ---- the edge generator (harness/host/wrl_cmp_edges.c) ---------------------------------------------------------------- */

/* The classes the deterministic phase covers; every edge carries a mask of them (an op is usually in several). */
enum {
	WRL_EC_READ_HOLE = 0,      /* a read of bytes no operation has written (a never-written object, the hole beyond a short object) */
	WRL_EC_OBJ_FIRST,          /* the first byte of an object */
	WRL_EC_OBJ_LAST,           /* the last byte of an object */
	WRL_EC_IMG_FIRST,          /* the first byte of the image */
	WRL_EC_IMG_LAST,           /* the last byte of the image */
	WRL_EC_LASTOBJ_FIRST,      /* the first byte of the last (usually partial) object */
	WRL_EC_LASTOBJ_LAST,       /* its last byte */
	WRL_EC_LASTOBJ_WHOLE,      /* all of it, partial or not */
	WRL_EC_END_AT,             /* a range ending exactly at an object boundary */
	WRL_EC_END_BEFORE,         /* ... one byte before it */
	WRL_EC_END_AFTER,          /* ... one byte after it */
	WRL_EC_START_AT,           /* a range starting exactly at a boundary */
	WRL_EC_START_BEFORE,       /* ... one byte before it */
	WRL_EC_START_AFTER,        /* ... one byte after it */
	WRL_EC_LEN_1,              /* lengths */
	WRL_EC_LEN_512,
	WRL_EC_LEN_4095,
	WRL_EC_LEN_4096,
	WRL_EC_LEN_4097,
	WRL_EC_LEN_OBJ1,           /* one, two and three objects long */
	WRL_EC_LEN_OBJ2,
	WRL_EC_LEN_OBJ3,
	WRL_EC_ZERO_OBJ,           /* a write of zeros over a whole object that holds data */
	WRL_EC_DISCARD_OBJ,        /* a discard of a whole object that holds data */
	WRL_EC_DISCARD_PART,       /* a discard of part of an object (head, middle, tail, across two objects) */
	WRL_EC_ZEROES,             /* a write-zeroes, whole or partial */
	WRL_EC_OVER_HOLE,          /* a write over a hole */
	WRL_EC_OVER_WRITTEN,       /* a write over a range written before, exactly */
	WRL_EC_OVER_HALF,          /* a write over a range of which half was written before */
	WRL_EC_PAST_END,           /* a request that begins at or crosses the end of the image: refused by the core and by the device */
	WRL_EC_UNALIGNED,          /* the byte start of the core side is not a multiple of the sector (the device side rounds out) */
	WRL_EC_FLUSH,              /* a flush */
	WRL_EC_COUNT
};

const char *wrl_cmp_class_name(unsigned cls);

enum { WRL_CMP_K_READ = 1, WRL_CMP_K_WRITE = 2, WRL_CMP_K_DISCARD = 3, WRL_CMP_K_ZEROES = 4, WRL_CMP_K_FLUSH = 5, WRL_CMP_K_PAST = 6 };

typedef struct wrl_cmp_geom {
	uint64_t size;    /* image size in bytes */
	uint8_t order;    /* object size = 1 << order */
	uint32_t sector;  /* the device's sector size (the unaligned class and the rounding depend on it) */
} wrl_cmp_geom;

typedef struct wrl_cmp_edge {
	uint8_t kind;       /* WRL_CMP_K_*; PAST: [off, off + len) crosses or lies beyond the end and every client must refuse it */
	uint8_t pat;        /* 0 = random pattern of the op, 1 = zeros, 2 = offset pattern (the write kinds only) */
	uint64_t off, len;  /* bytes, byte exact (the device side rounds out to sectors) */
	uint64_t classes;   /* bit WRL_EC_* */
} wrl_cmp_edge;

#define WRL_CMP_EDGES_MAX 4096u

/* The whole ordered list for a geometry, a pure function of it (the same input gives the same list). Writes at most cap entries
 * into out (which may be NULL to count) and returns how many there are in all (more than cap means truncated: never for cap >=
 * WRL_CMP_EDGES_MAX). 0 for a geometry that is unusable (size 0, order outside 9 .. 30, sector not a power of two). The ranges
 * of the non-PAST kinds lie inside [0, size). */
uint32_t wrl_cmp_edges_build(const wrl_cmp_geom *g, wrl_cmp_edge *out, uint32_t cap);

/* ---- the engine ------------------------------------------------------------------------------------------------------ */

#define WRL_CMP_DIR_C2K 1u   /* core-to-krbd: the core writes, the device reads (and the core reads back) */
#define WRL_CMP_DIR_K2C 2u   /* krbd-to-core: the device writes (sector aligned), the core reads */
#define WRL_CMP_DIR_INTER 4u /* interleave: the writer alternates per operation, ranges overlap on purpose */
#define WRL_CMP_DIR_ALL 7u

#define WRL_CMP_PH_EDGES 1u
#define WRL_CMP_PH_RANDOM 2u
#define WRL_CMP_PH_SCAN 4u
#define WRL_CMP_PH_ALL 7u

/* Who a test-only corruption hits. */
#define WRL_CMP_CORRUPT_NONE 0u
#define WRL_CMP_CORRUPT_CORE 1u   /* a byte of every core read that covers the offset is flipped (persistent) */
#define WRL_CMP_CORRUPT_DEV 2u    /* the same for the device's reads */
#define WRL_CMP_CORRUPT_MODEL 3u  /* a byte of the model is flipped once, at the first verification that covers it */

typedef struct wrl_cmp_cfg {
	wr_client *client;
	wrl_loop *loop;
	wr_image *img;             /* open, writable (the engine reads its geometry from wr_image_get_info) */
	wrl_cmp_dev dev;
	unsigned dirs;             /* WRL_CMP_DIR_* mask */
	unsigned phases;           /* WRL_CMP_PH_* mask */
	uint64_t seed;             /* printed in the plan record; every random choice is a function of it and the op number */
	uint64_t ops;              /* random phase: operations in all (split over the directions); 0 with time_ms == 0 = 20,000 */
	uint64_t time_ms;          /* random phase: stop issuing after this long (split over the directions); 0 = no limit */
	uint64_t max_len;          /* random: largest length; 0 = 1.5 objects, at most 8 MiB */
	uint64_t chunk;            /* scan: bytes per core read; 0 = 1 MiB. The device reads in another size (3/2 of it, in sectors) */
	uint64_t checkpoint;       /* random: a scan every this many operations; 0 = 5,000, UINT64_MAX = never */
	uint64_t stall_ms;         /* watchdog: nothing completed for this long with requests in flight is exit 4; 0 = 180,000 */
	uint64_t mem_max;          /* bytes of request buffers in flight at most (a single larger operation runs alone); 0 = 1 GiB */
	uint32_t depth;            /* lanes: operations in flight at once, 1 .. 64; 0 = 8 */
	uint32_t discard_gran;     /* the device honours a discard inward to this granularity (krbd alloc_size); 0 = the sector */
	FILE *out;                 /* records; NULL = stdout */
	const char *label;         /* shown in the plan and result records (a case name); may be NULL */
	int verbose;               /* one record per operation that is not ok-and-routine is always printed; this adds progress lines */
	/* The clock of the watchdog, the time limit and the record stamps (ms, monotonic). NULL = CLOCK_MONOTONIC. A test passes a
	 * virtual clock, so a hang is decided by counting engine iterations, not by how fast the machine is. */
	uint64_t (*now_ms)(void *ctx);
	void *clock_ctx;
	/* test-only (the tool's --self-test-mirror and --corrupt-at; documented there): */
	int mirror;                /* the "device" is a regular file with no connection to the image: every write goes to both */
	unsigned corrupt;          /* WRL_CMP_CORRUPT_* */
	uint64_t corrupt_off;
	int corrupt_once;          /* CORE / DEV: only the first read that covers the offset is damaged (a transient fault) */
} wrl_cmp_cfg;

typedef struct wrl_cmp_result {
	int exit_code;             /* 0, 1, 3, 4 */
	char verdict[8];           /* "", "core", "device", "model", "both" */
	uint64_t ops[7];           /* operations finished, indexed by WRL_CMP_K_* (0 unused) */
	uint64_t writes_core, writes_dev;  /* write-class operations (write, discard, zeroes) by writer */
	uint64_t bytes_written_core, bytes_written_dev, bytes_read_core, bytes_read_dev;
	uint64_t checkpoints, scans, scan_bytes_core, scan_bytes_dev;
	uint64_t edges_run, refusals_ok;
	uint64_t diffs;            /* differences found (at most 1: the run stops at the first one that fails) */
	uint64_t transients;       /* "device" verdicts that did not repeat: counted, not failed */
	uint64_t errors;           /* requests that failed with no difference */
	uint64_t max_gap_ms;       /* the longest time with requests in flight and no completion */
	uint64_t diff_op, diff_off, diff_len, diff_first;   /* where (the op number, its range, the first differing byte) */
	uint64_t dig_core, dig_dev, dig_model;               /* the three digests of the failing range */
	unsigned barrier_violations, bad_completions;        /* the core broke its contract (a flush overtook a write; a request came back twice) */
	unsigned n_stall, n_resume;                           /* WR_EV_IO_STALL / WR_EV_IO_RESUME events seen */
	uint64_t seed;
} wrl_cmp_result;

/*
 * Run the plan. Returns the exit code (also in res->exit_code); res may be NULL. The image must be open. The engine never closes
 * or destroys anything it was given. A fatal client failure is exit 3, a request error or a stall exit 4, the first difference
 * that is a failure exit 1 (the engine stops there; one "diff" record has the details).
 */
int wrl_cmp_run(const wrl_cmp_cfg *cfg, wrl_cmp_result *res);

/* The digest of the records and the model: 64-bit FNV-1a, exported for the tests. */
uint64_t wrl_cmp_digest(const uint8_t *p, size_t n, uint64_t seed);

/* The byte the engine writes at absolute offset x for pattern `kind` (0 random, 1 zero, 2 offset) and salt, exported so a test can
 * rebuild what an operation wrote. */
uint8_t wrl_cmp_pattern_byte(unsigned kind, uint64_t salt, uint64_t x);

#endif /* WRL_CMP_H */
