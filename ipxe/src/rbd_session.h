#ifndef _RBD_SESSION_H
#define _RBD_SESSION_H
/* SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL */
/** @file
 *
 * RBD (Ceph) SAN protocol: the session (private declarations of rbd_session.c, shared with rbd_block.c, rbd_stack.c and the
 * self-tests)
 *
 * rbd_priv.h is the contract with the other glue files and keeps the session opaque. This header is for the three files that
 * are the one state machine of the driver (the session, the block device, the diagnostics) and for their tests: the full
 * structure, the table of core entry points (so that a test can put a scripted core underneath) and the few functions the
 * files call on each other.
 *
 * Who does what (docs/design/ipxe-driver.md, sections 4, 10, 11):
 *
 *	rbd_session.c	owns the memory, the wr_client, the image, the connection table, the one process, the timers; the only file
 *			that calls wr_client_run and the only one that pulls events and finished requests out of the core
 *	rbd_block.c	owns the SAN commands and the readahead glue; it submits requests through rbd_session_submit() and gets them back
 *			through the "done" function of the request
 *	rbd_stack.c	the stack watermark and the "rbd-info" command
 *
 * Licence: GPL2_OR_LATER_OR_UBDL, like iPXE's own SAN code.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

#include <stdint.h>
#include <stddef.h>
#include <ipxe/refcnt.h>
#include <ipxe/list.h>
#include <ipxe/process.h>
#include <ipxe/retry.h>
#include "rbd_priv.h"
#include "rbd_conn.h"
#include "wr_ra.h"

/** Pump rounds of one pass of the process (one round = run the core, move the bytes, pull events and finished requests) */
#define RBD_PUMP_ROUNDS 16

/** Rounds of the synchronous cancel (the settle loop of rbd_session_cancel()) before the session is torn down */
#define RBD_CANCEL_ROUNDS 32

/** Granularity of the stack watermark's console report (bytes) */
#define RBD_STACK_REPORT_STEP 128

/** The core's run step is the deepest chain in the driver (2,632 bytes of stack on i386) and iPXE's own stack on i386 BIOS is 4,096 bytes: measured, the
 * margin with the core on that stack was 84 bytes while GRUB read the disk through INT 13h. On i386 BIOS builds the run step therefore executes on a stack of
 * its own, in the session's memory block (docs/design/ipxe-driver.md, section 5.2, layer 3). The Linux self-test program for i386 does the same, so that the
 * switch is tested on every run; every other platform (EFI: the firmware's stack is large; x86_64: iPXE's own stack is 8,192 bytes) runs it where it is called.
 */
#if defined ( __i386__ ) && ( defined ( PLATFORM_pcbios ) || defined ( PLATFORM_linux ) )
#define RBD_CORE_STACK_BYTES 16384
#else
#define RBD_CORE_STACK_BYTES 0
#endif

/** State of a session */
enum rbd_session_state {
	/** The image is being opened */
	RBD_SESSION_OPENING = 0,
	/** The image is open: devices are active */
	RBD_SESSION_OPEN,
	/** The image failed (or its open timed out): it is reopened by the next open of the session */
	RBD_SESSION_FAILED,
	/** The session is destroyed: no client, no memory, no sockets; only the structure is left until the last reference goes */
	RBD_SESSION_DEAD,
};

/**
 * The entry points of the core that the session calls
 *
 * One table, so that the self-tests can put a scripted core under the session (the same seam as struct rbd_conn_ops).
 * Production code uses rbd_core_default_ops, which is the core's own functions.
 */
struct rbd_core_ops {
	wr_status ( * mem_required ) ( const wr_config *cfg, wr_mem_req *out );
	wr_status ( * create ) ( const wr_config *cfg, const wr_host_ops *host,
				 const wr_cluster_spec *cluster,
				 wr_mem_region arena, wr_mem_region bulk,
				 wr_client **out );
	void ( * destroy ) ( wr_client *c );
	wr_run_result ( * run ) ( wr_client *c, const wr_clock *now,
				  uint32_t work_budget );
	int ( * next_event ) ( wr_client *c, wr_event *out );
	wr_io_req * ( * next_done ) ( wr_client *c );
	wr_client_state ( * client_state ) ( const wr_client *c );
	const wr_errinfo * ( * last_error ) ( const wr_client *c );
	void ( * stats ) ( const wr_client *c, wr_stats *out );
	void ( * osd_stats ) ( const wr_client *c, wr_osd_stats *out );
	wr_status ( * image_open ) ( wr_client *c, const wr_image_params *p,
				     wr_image **out );
	wr_status ( * image_close ) ( wr_image *img, uint32_t flags );
	wr_image_state ( * image_state ) ( const wr_image *img );
	const wr_errinfo * ( * image_error ) ( const wr_image *img );
	wr_status ( * image_info ) ( const wr_image *img, wr_image_info *out );
	wr_status ( * submit ) ( wr_image *img, wr_io_req *req );
	wr_status ( * cancel ) ( wr_image *img, wr_io_req *req );
};

/** The core's own functions */
extern const struct rbd_core_ops rbd_core_default_ops;

struct rbd_session;

/**
 * What a session runs on
 *
 * The seams of the self-tests; production code passes NULL for all of it (rbd_session_open()).
 */
struct rbd_session_env {
	/** The core (NULL: rbd_core_default_ops) */
	const struct rbd_core_ops *core;
	/** The sockets, the random source and the core's connection calls (NULL: rbd_conn_default_ops) */
	const struct rbd_conn_ops *conn;
	/** Get the time for the core (NULL: rbd_conn_now) */
	void ( * now ) ( struct rbd_session *session, wr_clock *now );
};

/** What identifies a session (the key by a fingerprint: the key itself is not kept for comparison) */
struct rbd_session_id {
	/** Monitors, as the request gave them (family 0 entries are unused) */
	wr_addr mons[WR_MAX_MONS];
	/** cephx user id without the "client." prefix */
	char user[WR_ENTITY_MAX];
	/** Pool */
	char pool[RBD_NAME_MAX];
	/** Image */
	char image[RBD_NAME_MAX];
	/** SHA-256 of the key (type, length, secret), cut to 16 bytes: a different key is a different session */
	uint8_t key_fp[16];
	/** Cluster id */
	uint8_t fsid[16];
	/** Number of monitors */
	uint8_t n_mons;
	/** The cluster id is checked */
	uint8_t fsid_known;
	/** Connection mode policy, WR_MODE_* */
	uint8_t mode;
	/** Opened read-only */
	uint8_t read_only;
	/** Readahead window (KiB; the cache is part of the session's memory, so it is part of its identity) */
	uint32_t readahead_kib;
};

/** A request of the glue in the core: a SAN command's or a prefetch (wr_io_req first, so that the core's pointer is ours) */
struct rbd_request {
	/** The core's request (its "user" is this structure) */
	wr_io_req req;
	/** Session's list of submitted requests */
	struct list_head list;
	/**
	 * The core has finished with the request
	 *
	 * @v session		Session
	 * @v rq		Request (its req.status is final; the buffer is the glue's again)
	 *
	 * Called by the session's pump when it pulls the request out of the core, and only then.
	 */
	void ( * done ) ( struct rbd_session *session, struct rbd_request *rq );
	/** The request is in the core and has not been pulled out yet */
	uint8_t pending;
};

/** A readahead prefetch (one per cache line) */
struct rbd_prefetch {
	/** The request */
	struct rbd_request rq;
	/** The cache slot it fills */
	uint32_t line;
};

/** Everything that is only needed to create the client: off the stack (the BIOS runs on 4 kB), zeroed afterwards (the key) */
struct rbd_create_work {
	/** Configuration */
	wr_config cfg;
	/** Memory plan */
	wr_mem_req req;
	/** Host table */
	wr_host_ops host;
	/** What to connect to, and the key */
	wr_cluster_spec cluster;
	/** Readahead configuration */
	wr_ra_cfg ra;
};

/** A shared cluster session */
struct rbd_session {
	/** Reference count (devices, commands, sockets, timers and the process hold references; the registry holds the first one) */
	struct refcnt refcnt;
	/** List of sessions */
	struct list_head list;
	/** Identity */
	struct rbd_session_id id;
	/** The environment (seams of the tests) */
	struct rbd_session_env env;
	/** The core's entry points (env.core, never NULL) */
	const struct rbd_core_ops *core;

	/** The one block of memory (umalloc), with room to place the parts on page boundaries wherever umalloc put it */
	void *mem;
	/** Page aligned start of the parts inside it: arena, bulk, readahead cache, core stack */
	void *base;
	/** The core's private stack (RBD_CORE_STACK_BYTES, behind the cache; NULL when the platform does not use one) and its top */
	void *core_stack;
	void *core_stack_top;
	/** Bytes of the parts (arena_len + bulk_len + ra_len + RBD_CORE_STACK_BYTES) */
	size_t mem_len;
	size_t arena_len;
	size_t bulk_len;
	size_t ra_len;
	/** The core's client (NULL once the session is destroyed) */
	wr_client *client;
	/** The open image (NULL before the first open and once destroyed) */
	wr_image *image;
	/** The readahead cache (NULL: none) */
	wr_ra *ra;
	/** One prefetch request per cache line */
	struct rbd_prefetch *pf;
	unsigned int n_pf;
	/** The connection table (the sockets of the core's connections) */
	struct rbd_conn_table conn;

	/** The process that runs the core */
	struct process proc;
	/** Wakes the process at the core's next deadline (or at the next stall check) */
	struct retry_timer timer;
	/** Destroys the session when it has had no device for RBD_SESSION_GRACE_MS */
	struct retry_timer grace;

	/** State, enum rbd_session_state */
	uint8_t state;
	/** The process is inside rbd_session_pump() (a pump called from there only notes that there is more to do) */
	uint8_t in_pump;
	/** Something happened while in_pump */
	uint8_t dirty;
	/** The image was reported open to the devices (and the cache sized for it) */
	uint8_t announced;
	/** Cache lines were reported done or failed: parked commands ask again */
	uint8_t ra_dirty;
	/** Completions are held back (the pump was asked for from inside the call that started a command: the SAN layer must have the
	 * call back before it is told that the command is done) */
	uint8_t hold;
	/** The cephx key is kept in key (a device asked for handoff=key) */
	uint8_t key_kept;
	/** Why the session failed, if it did (an iPXE error code) */
	int fail_rc;
	/** The status of that failure, for rbd-info */
	wr_status fail_status;

	/** Attached devices */
	struct list_head devices;
	unsigned int ndev;
	/** Commands (all states) */
	struct list_head cmds;
	/** Requests in the core */
	struct list_head reqs;
	/** Bytes of demand reads in flight (the readahead planner leaves room for them) */
	uint32_t demand_bytes;

	/** The time of the first sign of an unreachable cluster, or 0 (monotonic ms + 1: 0 is "none") */
	uint64_t trouble_since;
	/** What it was */
	wr_status trouble_status;
	/** What the peer answered when it refused us (the negative Linux errno of its AUTH_BAD_METHOD), 0 if nothing */
	int32_t trouble_peer;
	/** The time an operation stall began, or 0 */
	uint64_t stall_since;
	/** The deadline the core asked for in the last run (WR_DEADLINE_NONE: none) */
	uint64_t next_deadline;
	/** The last time given to the core (monotonic ms), for the timer */
	uint64_t last_now;
	/** The core wants to run again at once */
	uint8_t more_work;
	/** What the stall was */
	wr_status stall_status;
	/** The image reported a change (size, state): its information is read again */
	uint8_t info_stale;

	/** What the image is (valid when the state is OPEN) */
	wr_image_info info;
	/** Size of the image in blocks of RBD_BLKSIZE (a size that is not a multiple is truncated down) */
	uint64_t blocks;

	/** The URI of the request (devpath=uri), or NULL */
	char *uri;
	/** The cephx key, when a device asked for handoff=key (see key_kept) */
	wr_key key;
	/** Scratch of the creation (holds the key until it has been copied into the core and wiped) */
	struct rbd_create_work work;

	/** Counters for rbd-info */
	uint32_t n_pumps;
	uint32_t n_cancels;
	uint32_t n_cancel_rounds_max;
	uint32_t n_reopens;
	uint32_t n_stall_closes;
	/** Stack watermarks seen at the last report (RBD_STACK_MONITOR builds): iPXE's stack, and the core's own */
	uint32_t stack_reported;
	uint32_t core_reported;
	/** The next time a counters line may be printed (monotonic ms) and the operations counted at the last one (RBD_STACK_MONITOR builds) */
	uint64_t counters_next;
	uint32_t counters_ops;
};

/** The sessions (rbd_session.c) */
extern struct list_head rbd_sessions;

/* rbd_session.c */
extern int rbd_session_open_with ( const struct rbd_session_env *env,
				   const struct rbd_spec *spec,
				   struct rbd_session **session );
extern struct rbd_session * rbd_session_get ( struct rbd_session *session );
extern void rbd_session_wake ( struct rbd_session *session );
extern void rbd_session_pump ( struct rbd_session *session );
extern int rbd_session_submit ( struct rbd_session *session,
				struct rbd_request *rq );
extern void rbd_session_cancel ( struct rbd_session *session,
				 struct rbd_request *rq );
extern void rbd_session_attach ( struct rbd_session *session,
				 struct rbd_device *rbd,
				 const struct rbd_spec *spec );
extern void rbd_session_detach ( struct rbd_session *session,
				 struct rbd_device *rbd );
extern void rbd_session_destroy ( struct rbd_session *session );
extern void rbd_session_scrub_stack ( void *stack );
extern void rbd_session_fail ( struct rbd_session *session, int rc );
extern int rbd_session_usable ( const struct rbd_session *session );
extern void rbd_session_grace_expired ( struct retry_timer *timer, int over );
extern void rbd_session_timer_expired ( struct retry_timer *timer, int over );
extern void rbd_session_now ( struct rbd_session *session, wr_clock *now );

/* rbd_stack.c: the stack pattern (always built: it is plain memory logic, and it is tested) */
extern void rbd_stack_fill ( void *low, void *high );
extern size_t rbd_stack_untouched ( const void *low, const void *high );

/* rbd_stack.c: the core's private stack (RBD_CORE_STACK_BYTES): call a function on it, and measure how much of it was used */
#if RBD_CORE_STACK_BYTES
extern void rbd_call_on_stack ( void *top, void ( * fn ) ( void *arg ), void *arg );
#else
static inline void rbd_call_on_stack ( void *top __unused,
				       void ( * fn ) ( void *arg ), void *arg ) {
	fn ( arg );
}
#endif
extern unsigned int rbd_core_stack_used ( const struct rbd_session *session );

/* rbd_stack.c: what a boot cannot show afterwards (the "rbd-info" command is gone once the boot loader runs): one line of counters
 * and of the heap every RBD_COUNTERS_INTERVAL_MS while the session works, and a heap probe when the path is closed because the
 * cluster did not answer. Only a build with RBD_STACK_MONITOR (any platform) has them; every other build has these as nothing.
 */
#define RBD_COUNTERS_INTERVAL_MS 5000U
#ifdef RBD_STACK_MONITOR
extern void rbd_counters_note ( struct rbd_session *session );
extern void rbd_heap_note ( const char *what );
#else
static inline void rbd_counters_note ( struct rbd_session *session __unused ) {
}
static inline void rbd_heap_note ( const char *what __unused ) {
}
#endif

/* rbd_stack.c: the watermark of iPXE's own stack. Only a build with RBD_STACK_MONITOR (make EXTRA_CFLAGS=-DRBD_STACK_MONITOR) on a
 * BIOS platform (the one with an internal stack; EFI runs on the firmware's) has it; every other build has these as nothing, so that
 * no release build carries any of it.
 */
#if defined ( RBD_STACK_MONITOR ) && defined ( PLATFORM_pcbios )
extern void rbd_stack_paint ( void );
extern void rbd_stack_note ( struct rbd_session *session );
extern void rbd_stack_report ( void );
extern int rbd_stack_usage ( unsigned int *used, unsigned int *total );
#else
static inline void rbd_stack_paint ( void ) {
}
static inline void rbd_stack_note ( struct rbd_session *session __unused ) {
}
static inline void rbd_stack_report ( void ) {
}
static inline int rbd_stack_usage ( unsigned int *used __unused,
				    unsigned int *total __unused ) {
	return 0;
}
#endif

#endif /* _RBD_SESSION_H */
