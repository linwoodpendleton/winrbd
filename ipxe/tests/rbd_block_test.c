/*
 * Copyright (C) 2026 the winrbd authors.
 * SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

/** @file
 *
 * RBD (Ceph) SAN protocol: self-tests of the block device (ipxe/src/rbd_block.c), and the fakes that this file and
 * rbd_session_test.c share
 *
 * Built into bin-x86_64-linux/tests.linux (and the 32-bit program) by "ipxe/tools/build.sh test" (see ipxe/tests/README.md). No
 * network, no QEMU, no cluster, no waiting on the clock.
 *
 * The device and its commands run against a scripted core (a struct rbd_core_ops that the test controls: when a request finishes
 * and how, what a cancel answers, what the image's state is) and the SAN layer's two interfaces (a path and a command that record
 * what they hear). The data is a pattern the fake core "reads" into the caller's buffer, so a test can tell where every byte
 * came from. What is checked:
 *
 *   - capacity: 512-byte blocks, 8,192 blocks per command, the size truncated down to a multiple of 512, an image smaller than one
 *     block refused, the capacity heard before the close and never from inside the call;
 *   - commands: the request carries the SAN layer's buffer itself (zero copy), the right kind, offset and length; a completion is
 *     never made from inside the call that started the command (the SAN layer starts its timer when the call returns); every status
 *     of the table becomes the right error; argument checks (length, count, range); a refused submit leaves nothing behind;
 *   - window: the path is not active until the image is open, commands are refused until then, the path is told when the image opens;
 *   - cancel: the SAN layer closing a command cancels the request SYNCHRONOUSLY; with a busy answer the core is run until it lets
 *     go; when it never does, the session is destroyed and the core is never called again (no buffer can be written after the SAN
 *     layer got it back); a request already finished is retired; late data for a revoked request has nowhere to go;
 *   - devices: closing a path stops its commands, the session survives for its grace period, a reopen finds it (no second client);
 *     a failure of the session closes the paths with the right error;
 *   - readahead: a hit is copied and completed at the next step, a read behind a pending line waits and completes when the line has
 *     landed, a miss goes into the caller's buffer, a write drops the lines it overlaps, a failed prefetch is silent, the prefetch
 *     requests are bounded and time out well before the SAN layer's timeout;
 *   - a request that outlives its image (a failed reopen): the close of the command still waits for the core to let go of the buffer;
 *   - a path that is closed with status 0 does not tell its commands "success" (a command that was stopped did not finish);
 *   - randomised interleavings (blk_test_stress): 90 deterministic runs of a mixed sequence of commands, completions, timeouts, failures,
 *     reopens, time and busy or never-ending cancels, against a core that finishes its requests when the image is closed and forgets them
 *     when it is destroyed, with the invariants of the driver checked after every step (see there);
 *   - memory: nothing is left in the heap after a test.
 *
 * Secure Boot: FILE_SECBOOT ( FORBIDDEN ), like every file of the driver (docs/design/ipxe-driver.md, section 13).
 *
 * Nothing secret is used: the cephx key is a counting pattern.
 */

/* iPXE's error macros (-EINVAL ...) carry the identifier of the file that uses them (ipxe/tests/README.md): this one is local to
 * the test program. Error codes are compared by rbd_ft_error_kind(), never by their file part.
 */
#include <ipxe/errfile.h>
#define ERRFILE_rbd_block_test ( ERRFILE_OTHER | 0x007d0000 )

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ipxe/malloc.h>
#include <ipxe/umalloc.h>
#include <ipxe/interface.h>
#include <ipxe/blockdev.h>
#include <ipxe/xfer.h>
#include <ipxe/retry.h>
#include <ipxe/test.h>
#include "winrbd/rbd_priv.h"
#include "winrbd/rbd_session.h"
#include "winrbd/rbd_block.h"

/** An error code as a constant expression, as seen from this file (the iPXE macros -EINVAL ... are not constant expressions) */
#define RBD_ERR( name ) ( -__einfo_errno ( EINFO_ ## name ) )

/** The part of an error code that says which error it is: the POSIX code (bits 30-24) and the platform code (bits 7-0) */
#define RBD_FT_KIND( rc ) ( ( unsigned int ) ( -( rc ) ) & 0x7f0000ffU )

/** Most probe blocks taken when measuring the free heap */
#define RBD_FT_PROBE_MAX 600000

/* ---- the fakes shared by rbd_block_test.c and rbd_session_test.c ----------------------------------------------------------
 *
 * The fakes live in rbd_block_test.c; rbd_session_test.c declares the same structures (this block is the same text in both
 * files, and rbd_ft_size() lets the second check it against the first) and uses the functions through extern declarations.
 *
 * rbd_ft: a scripted core (struct rbd_core_ops), a fake connection API (struct rbd_conn_ops), a clock, and the SAN layer's two
 * sides: a path (the parent interface of a device: it hears xfer_window_changed and intf_close) and a command (the data interface
 * of a block_read: it hears block_capacity and intf_close).
 */

/** Requests the fake core can hold */
#define FT_MAX_REQS 256

/** Events the fake core can queue */
#define FT_MAX_EVENTS 16

/** Where a request of the fake core is */
enum ft_req_state {
	/** Not used */
	FT_NONE = 0,
	/** In the core: the core owns the buffer */
	FT_FLIGHT,
	/** Finished and waiting in the done queue: the buffer is the host's */
	FT_DONE,
	/** A cancel answered WR_E_BUSY: the core owns the buffer until it has reset the session that references it */
	FT_BUSY,
	/** Handed back by wr_client_next_done */
	FT_RETIRED,
};

/** A request in the fake core */
struct ft_req {
	/** The host's structure */
	wr_io_req *req;
	/** enum ft_req_state */
	uint8_t state;
	/** Runs left before a busy cancel finishes */
	unsigned int busy_runs;
	/** The buffer, kept for the data model (the host's pointer) */
	void *buf;
};

/** The parent interface of a device: the SAN layer's path */
struct ft_path {
	/** Interface (plugged into the device's block interface) */
	struct interface intf;
	/** xfer_window_changed heard */
	unsigned int window_changed;
	/** intf_close heard */
	unsigned int closed;
	/** Reason of the last close */
	int close_rc;
};

/** The data interface of a command: the SAN layer's command */
struct ft_san {
	/** Interface (plugged into the command's block interface) */
	struct interface command;
	/** block_capacity heard */
	unsigned int cap_n;
	/** Capacity heard last */
	struct block_device_capacity cap;
	/** intf_close heard */
	unsigned int closed;
	/** Reason of the last close */
	int close_rc;
};

/** The fake core, its script, and what it recorded */
struct rbd_ft {
	/* Script */
	/** Size of the fake image */
	uint64_t image_bytes;
	/** State the fake core reports for the image */
	wr_image_state istate;
	/** Status of the image's error */
	wr_status ierr;
	/** State the fake core reports for the client */
	wr_client_state cstate;
	/** Status returned by mem_required, create, image_open (0 = ok) */
	wr_status mem_rc;
	wr_status create_rc;
	wr_status open_rc;
	/** Status of wr_image_get_info */
	wr_status info_rc;
	/** The next submit_fail_n submits fail with submit_rc */
	unsigned int submit_fail_n;
	wr_status submit_rc;
	/** What wr_image_cancel answers (WR_OK, WR_E_BUSY, WR_E_STATE) */
	wr_status cancel_rc;
	/** Runs a busy cancel needs before it finishes (RBD_FT_NEVER: never) */
	unsigned int busy_runs;
	/** Complete every request on the next run, with this status (0 = leave them) */
	uint8_t auto_complete;
	wr_status auto_status;
	/** The clock */
	uint64_t now_ms;
	/** What wr_client_run answers */
	uint64_t next_deadline;
	uint32_t more_work;
	/** Seed of the image's content */
	uint8_t seed;
	/** Events to deliver */
	wr_event ev[FT_MAX_EVENTS];
	unsigned int ev_head;
	unsigned int ev_tail;
	/* Requests */
	struct ft_req r[FT_MAX_REQS];
	unsigned int n_r;
	wr_io_req *done[FT_MAX_REQS];
	unsigned int done_head;
	unsigned int done_tail;
	/* Record */
	unsigned int n_create;
	unsigned int n_destroy;
	unsigned int n_run;
	unsigned int n_open;
	unsigned int n_close;
	unsigned int n_submit;
	unsigned int n_cancel;
	unsigned int n_stats;
	/** A call came after wr_client_destroy */
	unsigned int n_after_destroy;
	/** Flags of the last wr_image_close */
	uint32_t close_flags;
	/** The core was destroyed (and not created again) */
	uint8_t destroyed;
	/** What create saw: the configuration, the cluster (key included), the regions */
	wr_config cfg;
	wr_cluster_spec cluster;
	wr_mem_region arena;
	wr_mem_region bulk;
	/** What image_open saw (the strings are copied) */
	wr_image_params params;
	char pool[RBD_NAME_MAX];
	char name[RBD_NAME_MAX];
	/** The image token the fake core hands out */
	uint8_t token;
	/** The size the arena and bulk of mem_required are */
	size_t arena_need;
	size_t bulk_need;
	/** The frame address of the last wr_client_run (where the core's run step executed) */
	void *run_frame;
	/** The last write the fake core completed OK (offset, length), and how many writes */
	uint64_t wr_off;
	uint64_t wr_len;
	unsigned int n_writes;
};

/** A request that never finishes (a busy cancel) */
#define RBD_FT_NEVER 0xffffffffU

extern struct rbd_ft *rbd_ft_cur;
extern const struct rbd_core_ops rbd_ft_core;
extern const struct rbd_conn_ops rbd_ft_conn;
extern size_t rbd_ft_size ( void );
extern void rbd_ft_init ( struct rbd_ft *ft );
extern void rbd_ft_env ( struct rbd_ft *ft, struct rbd_session_env *env );
extern struct rbd_spec * rbd_ft_spec ( void );
extern void rbd_ft_path_init ( struct ft_path *path );
extern void rbd_ft_san_init ( struct ft_san *san );
extern int rbd_ft_attach ( struct rbd_ft *ft, struct rbd_spec *spec,
			   struct rbd_session **session, struct ft_path *path );
extern void rbd_ft_image_open ( struct rbd_ft *ft );
extern void rbd_ft_event ( struct rbd_ft *ft, wr_ev_kind kind, wr_status status );
extern void rbd_ft_complete ( struct rbd_ft *ft, unsigned int idx, wr_status status );
extern int rbd_ft_owns ( struct rbd_ft *ft, unsigned int idx );
extern int rbd_ft_late_data ( struct rbd_ft *ft, unsigned int idx );
extern uint8_t rbd_ft_byte ( const struct rbd_ft *ft, uint64_t offset );
extern int rbd_ft_check ( const struct rbd_ft *ft, uint64_t offset, const void *data, size_t len );
extern void rbd_ft_cleanup ( struct ft_path *path );
extern size_t rbd_ft_heap ( void );
extern int rbd_ft_leak ( size_t before );
extern unsigned int rbd_ft_error_kind ( int rc );


/******************************************************************************
 *
 * The fakes
 *
 ******************************************************************************
 */

/** The fake of the running test (the tests run one after the other) */
struct rbd_ft *rbd_ft_cur;

/**
 * Get the size of the fake's structure (the second file compares it with its own copy of the declaration)
 *
 * @ret size		Size
 */
size_t rbd_ft_size ( void ) {

	return sizeof ( struct rbd_ft );
}

/**
 * Get the kind of an error code
 *
 * @v rc		Return status code
 * @ret kind		POSIX and platform part of the code
 */
unsigned int rbd_ft_error_kind ( int rc ) {

	return RBD_FT_KIND ( rc );
}

/**
 * Measure the free heap
 *
 * @ret blocks		Number of small blocks that fit in the free heap
 */
size_t rbd_ft_heap ( void ) {
	void *head = NULL;
	void *block;
	size_t blocks = 0;

	while ( blocks < RBD_FT_PROBE_MAX ) {
		block = malloc ( 16 );
		if ( ! block )
			break;
		*( ( void ** ) block ) = head;
		head = block;
		blocks++;
	}
	while ( head ) {
		block = head;
		head = *( ( void ** ) block );
		free ( block );
	}
	return blocks;
}

/**
 * Check whether memory was lost since a measurement
 *
 * @v before		Measurement of rbd_ft_heap() before the test
 * @ret leaked		The free heap is smaller than it was
 *
 * The measure packs 16-byte blocks into whatever free pieces there are, so the way the free space is cut up can move it by a block
 * or two in either direction; anything that stays allocated (a command, a session, a timer, a string) costs more than that.
 */
int rbd_ft_leak ( size_t before ) {

	return ( ( rbd_ft_heap() + 4 ) < before );
}

/**
 * Get a byte of the fake image
 *
 * @v ft		Fake
 * @v offset		Byte offset
 * @ret byte		The byte
 */
uint8_t rbd_ft_byte ( const struct rbd_ft *ft, uint64_t offset ) {

	return ( ( uint8_t ) ( ( offset * 31 ) ^ ( offset >> 9 ) ^ ft->seed ) );
}

/**
 * Check data against the fake image
 *
 * @v ft		Fake
 * @v offset		Byte offset of the data
 * @v data		Data
 * @v len		Length
 * @ret ok		The data is what the image holds there
 */
int rbd_ft_check ( const struct rbd_ft *ft, uint64_t offset, const void *data,
		   size_t len ) {
	const uint8_t *byte = data;
	size_t i;

	for ( i = 0 ; i < len ; i++ ) {
		if ( byte[i] != rbd_ft_byte ( ft, ( offset + i ) ) )
			return 0;
	}
	return 1;
}

/**
 * Find a request of the fake core
 *
 * @v ft		Fake
 * @v req		The host's request
 * @ret idx		Index, or FT_MAX_REQS
 */
static unsigned int ft_find ( struct rbd_ft *ft, const wr_io_req *req ) {
	unsigned int i;

	/* The newest first: the host reuses the memory of a retired request for the next one */
	for ( i = ft->n_r ; i-- ; ) {
		if ( ft->r[i].req == req )
			return i;
	}
	return FT_MAX_REQS;
}

/**
 * Count a call that must not come after the core was destroyed
 *
 * @v ft		Fake
 */
static void ft_alive ( struct rbd_ft *ft ) {

	if ( ft->destroyed )
		ft->n_after_destroy++;
}

/**
 * Finish a request: the buffer is the host's again, and the request waits in the done queue
 *
 * @v ft		Fake
 * @v idx		Request
 * @v status		Status to finish with
 */
static void ft_finish ( struct rbd_ft *ft, unsigned int idx, wr_status status ) {
	struct ft_req *r = &ft->r[idx];
	wr_io_req *req = r->req;

	if ( ( status == WR_OK ) && ( req->kind == WR_IO_READ ) ) {
		uint8_t *buf = req->buf;
		uint64_t i;

		for ( i = 0 ; i < req->length ; i++ )
			buf[i] = rbd_ft_byte ( ft, ( req->offset + i ) );
	}
	if ( ( status == WR_OK ) && ( req->kind == WR_IO_WRITE ) ) {
		ft->wr_off = req->offset;
		ft->wr_len = req->length;
		ft->n_writes++;
	}
	req->status = status;
	r->state = FT_DONE;
	ft->done[ft->done_tail++ % FT_MAX_REQS] = req;
}

/**
 * Complete a request of the fake core (the test's script)
 *
 * @v ft		Fake
 * @v idx		Request
 * @v status		Status
 */
void rbd_ft_complete ( struct rbd_ft *ft, unsigned int idx, wr_status status ) {

	ok ( ( idx < ft->n_r ) && ( ( ft->r[idx].state == FT_FLIGHT ) ||
				    ( ft->r[idx].state == FT_BUSY ) ) );
	if ( ( idx < ft->n_r ) && ( ( ft->r[idx].state == FT_FLIGHT ) ||
				    ( ft->r[idx].state == FT_BUSY ) ) )
		ft_finish ( ft, idx, status );
}

/**
 * Check whether the fake core still owns the buffer of a request
 *
 * @v ft		Fake
 * @v idx		Request
 * @ret owns		The core may still touch the buffer
 */
int rbd_ft_owns ( struct rbd_ft *ft, unsigned int idx ) {

	return ( ( idx < ft->n_r ) && ( ( ft->r[idx].state == FT_FLIGHT ) ||
					( ft->r[idx].state == FT_BUSY ) ) );
}

/**
 * Let a reply arrive for a request (the network side of the script)
 *
 * @v ft		Fake
 * @v idx		Request
 * @ret wrote		Data was written into the buffer (only if the core still owned it)
 */
int rbd_ft_late_data ( struct rbd_ft *ft, unsigned int idx ) {
	wr_io_req *req;

	if ( ! rbd_ft_owns ( ft, idx ) )
		return 0;
	req = ft->r[idx].req;
	if ( req->buf && ( req->kind == WR_IO_READ ) )
		memset ( req->buf, 0xee, req->length );
	return 1;
}

/**
 * Queue an event
 *
 * @v ft		Fake
 * @v kind		Event kind
 * @v status		Status of its error
 */
void rbd_ft_event ( struct rbd_ft *ft, wr_ev_kind kind, wr_status status ) {
	wr_event *ev = &ft->ev[ft->ev_tail++ % FT_MAX_EVENTS];

	memset ( ev, 0, sizeof ( *ev ) );
	ev->kind = kind;
	ev->err.status = status;
}

/**
 * Open the image in the fake core
 *
 * @v ft		Fake
 */
void rbd_ft_image_open ( struct rbd_ft *ft ) {

	ft->istate = WR_IMG_OPEN;
	rbd_ft_event ( ft, WR_EV_IMAGE, 0 );
}

/* ---- the core ---------------------------------------------------------------------------------------------------------- */

static wr_status ft_mem_required ( const wr_config *cfg __unused,
				   wr_mem_req *out ) {
	struct rbd_ft *ft = rbd_ft_cur;

	out->arena = ft->arena_need;
	out->bulk = ft->bulk_need;
	return ft->mem_rc;
}

static wr_status ft_create ( const wr_config *cfg, const wr_host_ops *host,
			     const wr_cluster_spec *cluster, wr_mem_region arena,
			     wr_mem_region bulk, wr_client **out ) {
	struct rbd_ft *ft = rbd_ft_cur;

	ft->n_create++;
	ft->destroyed = 0;
	ft->cstate = WR_CS_ACTIVE;
	ft->cfg = *cfg;
	ft->cluster = *cluster;
	ft->arena = arena;
	ft->bulk = bulk;
	ok ( host->size == sizeof ( *host ) );
	ok ( host->random != NULL );
	if ( ft->create_rc )
		return ft->create_rc;
	*out = ( ( wr_client * ) ft );
	return WR_OK;
}

static void ft_destroy ( wr_client *c ) {
	struct rbd_ft *ft = ( ( struct rbd_ft * ) c );

	ft_alive ( ft );
	ft->n_destroy++;
	ft->destroyed = 1;
}

static wr_run_result ft_run ( wr_client *c, const wr_clock *now __unused,
			      uint32_t budget __unused ) {
	struct rbd_ft *ft = ( ( struct rbd_ft * ) c );
	wr_run_result res;
	unsigned int i;

	ft_alive ( ft );
	ft->n_run++;
	ft->run_frame = __builtin_frame_address ( 0 );
	for ( i = 0 ; i < ft->n_r ; i++ ) {
		struct ft_req *r = &ft->r[i];

		if ( ( r->state == FT_BUSY ) && ( r->busy_runs != RBD_FT_NEVER ) &&
		     ( --r->busy_runs == 0 ) )
			ft_finish ( ft, i, WR_E_CANCELLED );
		else if ( ( r->state == FT_FLIGHT ) && ft->auto_complete )
			ft_finish ( ft, i, ft->auto_status );
	}
	res.next_deadline_ms = ft->next_deadline;
	res.more_work = ft->more_work;
	return res;
}

static int ft_next_event ( wr_client *c, wr_event *out ) {
	struct rbd_ft *ft = ( ( struct rbd_ft * ) c );

	ft_alive ( ft );
	if ( ft->ev_head == ft->ev_tail )
		return 0;
	*out = ft->ev[ft->ev_head++ % FT_MAX_EVENTS];
	return 1;
}

static wr_io_req * ft_next_done ( wr_client *c ) {
	struct rbd_ft *ft = ( ( struct rbd_ft * ) c );
	wr_io_req *req;

	ft_alive ( ft );
	if ( ft->done_head == ft->done_tail )
		return NULL;
	req = ft->done[ft->done_head++ % FT_MAX_REQS];
	ft->r[ft_find ( ft, req )].state = FT_RETIRED;
	return req;
}

static wr_client_state ft_client_state ( const wr_client *c ) {
	const struct rbd_ft *ft = ( ( const struct rbd_ft * ) c );

	return ft->cstate;
}

static const wr_errinfo ft_no_error;

static const wr_errinfo * ft_last_error ( const wr_client *c __unused ) {

	return &ft_no_error;
}

static void ft_stats ( const wr_client *c, wr_stats *out ) {
	struct rbd_ft *ft = ( ( struct rbd_ft * ) c );

	ft->n_stats++;
	memset ( out, 0, sizeof ( *out ) );
}

static void ft_osd_stats ( const wr_client *c __unused, wr_osd_stats *out ) {

	memset ( out, 0, sizeof ( *out ) );
}

static wr_status ft_image_open ( wr_client *c, const wr_image_params *p,
				 wr_image **out ) {
	struct rbd_ft *ft = ( ( struct rbd_ft * ) c );

	ft_alive ( ft );
	ft->n_open++;
	ft->params = *p;
	strncpy ( ft->pool, p->pool, ( sizeof ( ft->pool ) - 1 ) );
	strncpy ( ft->name, p->name, ( sizeof ( ft->name ) - 1 ) );
	if ( ft->open_rc )
		return ft->open_rc;
	ft->istate = WR_IMG_OPENING;
	ft->ierr = WR_OK;
	*out = ( ( wr_image * ) &ft->token );
	return WR_OK;
}

static wr_status ft_image_close ( wr_image *img __unused, uint32_t flags ) {
	struct rbd_ft *ft = rbd_ft_cur;

	ft_alive ( ft );
	ft->n_close++;
	ft->close_flags = flags;
	return WR_OK;
}

static wr_image_state ft_image_state ( const wr_image *img __unused ) {

	return rbd_ft_cur->istate;
}

static const wr_errinfo * ft_image_error ( const wr_image *img __unused ) {
	static wr_errinfo err;

	memset ( &err, 0, sizeof ( err ) );
	err.status = rbd_ft_cur->ierr;
	return &err;
}

static wr_status ft_image_info ( const wr_image *img __unused,
				 wr_image_info *out ) {
	struct rbd_ft *ft = rbd_ft_cur;

	memset ( out, 0, sizeof ( *out ) );
	out->size_bytes = ft->image_bytes;
	out->object_size = 4194304;
	out->order = 22;
	out->writable = 1;
	strcpy ( out->image_id, "10a1b2c3d4e5" );
	return ft->info_rc;
}

static wr_status ft_submit ( wr_image *img __unused, wr_io_req *req ) {
	struct rbd_ft *ft = rbd_ft_cur;

	ft_alive ( ft );
	ft->n_submit++;
	if ( ft->submit_fail_n ) {
		ft->submit_fail_n--;
		return ft->submit_rc;
	}
	if ( ft->n_r >= FT_MAX_REQS )
		return WR_E_BUSY;
	ft->r[ft->n_r].req = req;
	ft->r[ft->n_r].state = FT_FLIGHT;
	ft->r[ft->n_r].buf = req->buf;
	ft->n_r++;
	return WR_OK;
}

static wr_status ft_cancel ( wr_image *img __unused, wr_io_req *req ) {
	struct rbd_ft *ft = rbd_ft_cur;
	unsigned int idx = ft_find ( ft, req );

	ft_alive ( ft );
	ft->n_cancel++;
	if ( ( idx == FT_MAX_REQS ) || ( ( ft->r[idx].state != FT_FLIGHT ) &&
					 ( ft->r[idx].state != FT_BUSY ) ) )
		return WR_E_STATE;
	if ( ft->cancel_rc == WR_E_BUSY ) {
		ft->r[idx].state = FT_BUSY;
		ft->r[idx].busy_runs = ft->busy_runs;
		return WR_E_BUSY;
	}
	ft_finish ( ft, idx, WR_E_CANCELLED );
	return WR_OK;
}

/** The fake core */
const struct rbd_core_ops rbd_ft_core = {
	.mem_required = ft_mem_required,
	.create = ft_create,
	.destroy = ft_destroy,
	.run = ft_run,
	.next_event = ft_next_event,
	.next_done = ft_next_done,
	.client_state = ft_client_state,
	.last_error = ft_last_error,
	.stats = ft_stats,
	.osd_stats = ft_osd_stats,
	.image_open = ft_image_open,
	.image_close = ft_image_close,
	.image_state = ft_image_state,
	.image_error = ft_image_error,
	.image_info = ft_image_info,
	.submit = ft_submit,
	.cancel = ft_cancel,
};

/* ---- the connection API: no connections ---------------------------------------------------------------------------------- */

static int ft_conn_open ( struct interface *intf __unused,
			  struct sockaddr *peer __unused ) {

	return -ENETUNREACH;
}

static int ft_conn_generate ( void *out, size_t len ) {

	memset ( out, 0x5a, len );
	return 0;
}

static int ft_conn_next_action ( wr_client *c __unused, wr_action *out __unused ) {

	return 0;
}

static void ft_conn_connected ( wr_client *c __unused, wr_conn_id id __unused ) {

}

static void ft_conn_closed ( wr_client *c __unused, wr_conn_id id __unused,
			     int host_errno __unused ) {

}

static size_t ft_conn_rx_window ( wr_client *c __unused,
				  wr_conn_id id __unused,
				  uint8_t **ptr __unused ) {

	return 0;
}

static size_t ft_conn_rx_push ( wr_client *c __unused, wr_conn_id id __unused,
				const uint8_t *data __unused, size_t n __unused ) {

	return 0;
}

static size_t ft_conn_tx_peek ( wr_client *c __unused, wr_conn_id id __unused,
				wr_iov *iov __unused, size_t max_iov __unused ) {

	return 0;
}

static void ft_conn_tx_consume ( wr_client *c __unused, wr_conn_id id __unused,
				 size_t n __unused ) {

}

/** The fake connection API */
const struct rbd_conn_ops rbd_ft_conn = {
	.open = ft_conn_open,
	.generate = ft_conn_generate,
	.next_action = ft_conn_next_action,
	.connected = ft_conn_connected,
	.closed = ft_conn_closed,
	.rx_window = ft_conn_rx_window,
	.rx_push = ft_conn_rx_push,
	.tx_peek = ft_conn_tx_peek,
	.tx_consume = ft_conn_tx_consume,
};

/* ---- time ---------------------------------------------------------------------------------------------------------------- */

static void ft_now ( struct rbd_session *session __unused, wr_clock *now ) {

	now->mono_ms = rbd_ft_cur->now_ms;
	now->wall_ms = 0;
}

/**
 * Initialise a fake
 *
 * @v ft		Fake
 */
void rbd_ft_init ( struct rbd_ft *ft ) {

	memset ( ft, 0, sizeof ( *ft ) );
	ft->image_bytes = ( 64ULL * 1024 * 1024 );
	ft->istate = WR_IMG_OPENING;
	ft->cstate = WR_CS_ACTIVE;
	ft->cancel_rc = WR_OK;
	ft->busy_runs = 3;
	ft->next_deadline = WR_DEADLINE_NONE;
	ft->now_ms = 1000;
	ft->seed = 0x37;
	ft->arena_need = 10000;
	ft->bulk_need = 20000;
	rbd_ft_cur = ft;
}

/**
 * Fill in the environment of a session
 *
 * @v ft		Fake
 * @v env		Environment
 */
void rbd_ft_env ( struct rbd_ft *ft __unused, struct rbd_session_env *env ) {

	env->core = &rbd_ft_core;
	env->conn = &rbd_ft_conn;
	env->now = ft_now;
}

/**
 * Make a request specification (heap: it holds a key)
 *
 * @ret spec		Specification (the caller wipes and frees it)
 */
struct rbd_spec * rbd_ft_spec ( void ) {
	struct rbd_spec *spec;
	unsigned int i;

	spec = zalloc ( sizeof ( *spec ) );
	assert ( spec != NULL );
	strcpy ( spec->user, "wrtest" );
	strcpy ( spec->pool, "pool" );
	strcpy ( spec->image, "img" );
	spec->mons[0].family = WR_AF_IPV4;
	spec->mons[0].ip[0] = 10;
	spec->mons[0].ip[1] = 77;
	spec->mons[0].ip[3] = 10;
	spec->mons[0].port = 3300;
	spec->n_mons = 1;
	spec->mode = WR_MODE_CRC_ONLY;
	spec->open_timeout_ms = RBD_DEFAULT_OPEN_TIMEOUT_MS;
	spec->readahead_kib = 0;
	spec->devpath = RBD_DEVPATH_VENDOR;
	spec->handoff = RBD_HANDOFF_NOKEY;
	spec->key.type = WR_KEY_TYPE_AES256K;
	spec->key.len = 32;
	for ( i = 0 ; i < 32 ; i++ )
		spec->key.secret[i] = ( 0x40 + i );
	return spec;
}

/* ---- the SAN layer ------------------------------------------------------------------------------------------------------- */

static void ft_path_close ( struct ft_path *path, int rc ) {

	path->closed++;
	path->close_rc = rc;

	/* Like sanpath_block_close(): the path lets go of its end of the interface */
	intf_restart ( &path->intf, rc );
}

static void ft_path_window_changed ( struct ft_path *path ) {

	path->window_changed++;
}

static struct interface_operation ft_path_ops[] = {
	INTF_OP ( intf_close, struct ft_path *, ft_path_close ),
	INTF_OP ( xfer_window_changed, struct ft_path *, ft_path_window_changed ),
};

static struct interface_descriptor ft_path_desc =
	INTF_DESC ( struct ft_path, intf, ft_path_ops );

/**
 * Initialise a path
 *
 * @v path		Path
 */
void rbd_ft_path_init ( struct ft_path *path ) {

	memset ( path, 0, sizeof ( *path ) );
	intf_init ( &path->intf, &ft_path_desc, NULL );
}

static void ft_san_close ( struct ft_san *san, int rc ) {

	san->closed++;
	san->close_rc = rc;

	/* Like sandev_command_close(): the command interface is restarted */
	intf_restart ( &san->command, rc );
}

static void ft_san_capacity ( struct ft_san *san,
			      struct block_device_capacity *cap ) {

	san->cap_n++;
	san->cap = *cap;
}

static struct interface_operation ft_san_ops[] = {
	INTF_OP ( intf_close, struct ft_san *, ft_san_close ),
	INTF_OP ( block_capacity, struct ft_san *, ft_san_capacity ),
};

static struct interface_descriptor ft_san_desc =
	INTF_DESC ( struct ft_san, command, ft_san_ops );

/**
 * Initialise a SAN command
 *
 * @v san		SAN command
 */
void rbd_ft_san_init ( struct ft_san *san ) {

	memset ( san, 0, sizeof ( *san ) );
	intf_init ( &san->command, &ft_san_desc, NULL );
}

/**
 * Open a session and attach a device to a path
 *
 * @v ft		Fake
 * @v spec		Specification
 * @v session		Session (the caller's reference)
 * @v path		Path (initialised here)
 * @ret rc		Return status code
 */
int rbd_ft_attach ( struct rbd_ft *ft, struct rbd_spec *spec,
		    struct rbd_session **session, struct ft_path *path ) {
	struct rbd_session_env env;
	int rc;

	rbd_ft_env ( ft, &env );
	rbd_ft_path_init ( path );
	if ( ( rc = rbd_session_open_with ( &env, spec, session ) ) != 0 )
		return rc;
	if ( ( rc = rbd_device_open ( &path->intf, *session, spec ) ) != 0 )
		return rc;
	return 0;
}

/**
 * Close a path the way the SAN layer does, and destroy every session
 *
 * @v path		Path
 */
void rbd_ft_cleanup ( struct ft_path *path ) {
	struct rbd_session *session;
	struct rbd_session *tmp;

	intf_restart ( &path->intf, 0 );
	list_for_each_entry_safe ( session, tmp, &rbd_sessions, list )
		rbd_session_destroy ( session );
}

/******************************************************************************
 *
 * The tests
 *
 ******************************************************************************
 */

/** Size of the buffers of the small commands */
#define BLK_BUF 65536

/** The pieces of one test (static: the fake is large, and the tests run one after the other) */
struct blk_fix {
	/** Free heap before the test */
	size_t heap;
	/** The fake core */
	struct rbd_ft ft;
	/** Specification */
	struct rbd_spec *spec;
	/** The session (the test's reference) */
	struct rbd_session *s;
	/** The path */
	struct ft_path path;
	/** The command */
	struct ft_san san;
	/** A buffer */
	uint8_t buf[BLK_BUF];
};

static struct blk_fix blk_fix;

/** The test that is running */
static const char *blk_current;

/** Check two error codes are the same error */
#define BLK_ERR( rc, expected ) \
	( rbd_ft_error_kind ( rc ) == rbd_ft_error_kind ( expected ) )

/**
 * Open a session with a device on a fixture
 *
 * @v f			Fixture
 * @v readahead_kib	Readahead window (KiB)
 * @v open		Open the image as well
 */
static void blk_open ( struct blk_fix *f, unsigned int readahead_kib, int open ) {

	f->heap = rbd_ft_heap();
	rbd_ft_init ( &f->ft );
	rbd_ft_san_init ( &f->san );
	f->spec = rbd_ft_spec();
	f->spec->readahead_kib = readahead_kib;
	ok ( rbd_ft_attach ( &f->ft, f->spec, &f->s, &f->path ) == 0 );
	if ( open ) {
		rbd_session_pump ( f->s );
		rbd_ft_image_open ( &f->ft );
		rbd_session_pump ( f->s );
	}
}

/**
 * Close a fixture: the path, the session, and check that nothing is left
 *
 * @v f			Fixture
 */
static void blk_close ( struct blk_fix *f ) {

	rbd_ft_cleanup ( &f->path );
	if ( f->s )
		rbd_session_put ( f->s );
	f->s = NULL;
	rbd_spec_wipe ( f->spec );
	free ( f->spec );
	f->spec = NULL;
	ok ( list_empty ( &rbd_sessions ) );
	ok ( f->ft.n_after_destroy == 0 );
	if ( rbd_ft_leak ( f->heap ) )
		printf ( "rbd_block_test: %ld blocks of heap lost by %s\n",
			 ( long ) ( f->heap - rbd_ft_heap() ), blk_current );
	ok ( ! rbd_ft_leak ( f->heap ) );
}

/**
 * Issue a read of a fixture
 *
 * @v f			Fixture
 * @v lba		Block
 * @v count		Blocks
 * @ret rc		Return status code
 */
static int blk_read ( struct blk_fix *f, uint64_t lba, unsigned int count ) {

	rbd_ft_san_init ( &f->san );
	return block_read ( &f->path.intf, &f->san.command, lba, count, f->buf,
			    ( ( size_t ) count * 512 ) );
}

/**
 * Pump the session
 *
 * @v f			Fixture
 */
static void blk_pump ( struct blk_fix *f ) {

	rbd_session_pump ( f->s );
}

/* ---- capacity -------------------------------------------------------------------------------------------------------------- */

static void blk_test_capacity ( void ) {
	struct blk_fix *f = &blk_fix;
	static const struct {
		uint64_t bytes;
		uint64_t blocks;
	} cases[] = {
		{ 1024 * 1024, 2048 }, { 1024 * 1024 + 511, 2048 },
		{ 1024 * 1024 + 512, 2049 }, { 1024 * 1024 - 1, 2047 },
		{ 512, 1 }, { 1023, 1 }, { 4096ULL * 1024 * 1024 * 1024, 8589934592ULL },
		{ 2ULL * 1024 * 1024 * 1024 * 1024 + 1000, 4294967296ULL + 1 },
	};
	unsigned int i;

	for ( i = 0 ; i < ( sizeof ( cases ) / sizeof ( cases[0] ) ) ; i++ ) {
		blk_open ( f, 0, 0 );
		f->ft.image_bytes = cases[i].bytes;
		blk_pump ( f );
		rbd_ft_image_open ( &f->ft );
		blk_pump ( f );
		ok ( f->s->blocks == cases[i].blocks );
		rbd_ft_san_init ( &f->san );
		ok ( block_read_capacity ( &f->path.intf, &f->san.command ) == 0 );

		/* Not from inside the call; at the next step */
		ok ( f->san.closed == 0 );
		ok ( f->san.cap_n == 0 );
		blk_pump ( f );
		ok ( f->san.closed == 1 );
		ok ( f->san.close_rc == 0 );
		ok ( f->san.cap_n == 1 );
		ok ( f->san.cap.blocks == cases[i].blocks );
		ok ( f->san.cap.blksize == 512 );
		ok ( f->san.cap.max_count == 8192 );
		blk_close ( f );
	}
}

static void blk_test_too_small ( void ) {
	struct blk_fix *f = &blk_fix;

	/* An image smaller than one block cannot be a disk: the path is closed, the reason is "no such device" */
	blk_open ( f, 0, 0 );
	f->ft.image_bytes = 511;
	blk_pump ( f );
	rbd_ft_image_open ( &f->ft );
	blk_pump ( f );
	ok ( f->path.closed == 1 );
	ok ( BLK_ERR ( f->path.close_rc, -ENODEV ) );
	ok ( f->s->state == RBD_SESSION_FAILED );
	ok ( rbd_ft_error_kind ( f->s->fail_rc ) == rbd_ft_error_kind ( -ENODEV ) );
	blk_close ( f );
}

/* ---- window ---------------------------------------------------------------------------------------------------------------- */

static void blk_test_window ( void ) {
	struct blk_fix *f = &blk_fix;
	struct rbd_device *rbd;

	blk_open ( f, 0, 0 );
	rbd = list_first_entry ( &f->s->devices, struct rbd_device, list );
	ok ( rbd != NULL );
	blk_pump ( f );

	/* Not active while the image opens: no window, no commands */
	ok ( f->s->state == RBD_SESSION_OPENING );
	ok ( xfer_window ( &f->path.intf ) == 0 );
	ok ( f->path.window_changed == 0 );
	ok ( BLK_ERR ( blk_read ( f, 0, 8 ), -ENOTCONN ) );
	rbd_ft_san_init ( &f->san );
	ok ( BLK_ERR ( block_read_capacity ( &f->path.intf, &f->san.command ),
		       -ENOTCONN ) );
	ok ( f->ft.n_submit == 0 );

	/* The image opens: the path is told, the window is the largest command */
	rbd_ft_image_open ( &f->ft );
	blk_pump ( f );
	ok ( f->s->state == RBD_SESSION_OPEN );
	ok ( f->path.window_changed == 1 );
	ok ( xfer_window ( &f->path.intf ) == ( 8192UL * 512 ) );
	ok ( f->path.closed == 0 );

	/* The image's parameters: the pool and the name, the head, a writer, the open timeout of the request */
	ok ( f->ft.n_open == 1 );
	ok ( strcmp ( f->ft.pool, "pool" ) == 0 );
	ok ( strcmp ( f->ft.name, "img" ) == 0 );
	ok ( f->ft.params.snap_id == WR_SNAP_HEAD );
	ok ( f->ft.params.want_write == 1 );
	ok ( f->ft.params.open_timeout_ms == RBD_DEFAULT_OPEN_TIMEOUT_MS );
	blk_close ( f );

	/* A path with no session has no window */
	blk_open ( f, 0, 1 );
	rbd = list_first_entry ( &f->s->devices, struct rbd_device, list );
	ok ( xfer_window ( &rbd->block ) != 0 );
	rbd_device_fail ( rbd, -EIO );
	ok ( f->path.closed == 1 );
	ok ( BLK_ERR ( f->path.close_rc, -EIO ) );
	blk_close ( f );
}

/* ---- commands -------------------------------------------------------------------------------------------------------------- */

static void blk_test_read ( void ) {
	struct blk_fix *f = &blk_fix;
	wr_io_req *req;

	blk_open ( f, 0, 1 );
	memset ( f->buf, 0xa5, sizeof ( f->buf ) );
	ok ( blk_read ( f, 10, 8 ) == 0 );
	ok ( f->ft.n_submit == 1 );
	req = f->ft.r[0].req;
	ok ( req->kind == WR_IO_READ );
	ok ( req->offset == 5120 );
	ok ( req->length == 4096 );
	ok ( req->buf == f->buf );		/* zero copy: the SAN layer's own buffer */
	ok ( req->timeout_ms == 0 );
	ok ( req->user != NULL );
	ok ( rbd_ft_owns ( &f->ft, 0 ) );

	/* Not completed from inside the call, nor by a pump that has nothing to report */
	ok ( f->san.closed == 0 );
	blk_pump ( f );
	ok ( f->san.closed == 0 );
	ok ( f->s->demand_bytes == 4096 );

	/* The core finishes it: the SAN layer hears it at the next step, once, with success, and has the data */
	rbd_ft_complete ( &f->ft, 0, WR_OK );
	ok ( f->san.closed == 0 );
	blk_pump ( f );
	ok ( f->san.closed == 1 );
	ok ( f->san.close_rc == 0 );
	ok ( rbd_ft_check ( &f->ft, 5120, f->buf, 4096 ) );
	ok ( f->s->demand_bytes == 0 );
	ok ( list_empty ( &f->s->cmds ) );
	ok ( list_empty ( &f->s->reqs ) );
	blk_close ( f );
}

static void blk_test_write ( void ) {
	struct blk_fix *f = &blk_fix;
	wr_io_req *req;
	unsigned int i;

	blk_open ( f, 0, 1 );
	for ( i = 0 ; i < BLK_BUF ; i++ )
		f->buf[i] = ( uint8_t ) i;
	rbd_ft_san_init ( &f->san );
	ok ( block_write ( &f->path.intf, &f->san.command, 100, 16, f->buf, 8192 ) == 0 );
	ok ( f->ft.n_submit == 1 );
	req = f->ft.r[0].req;
	ok ( req->kind == WR_IO_WRITE );
	ok ( req->offset == 51200 );
	ok ( req->length == 8192 );
	ok ( req->buf == f->buf );
	ok ( f->san.closed == 0 );
	rbd_ft_complete ( &f->ft, 0, WR_OK );
	blk_pump ( f );
	ok ( f->san.closed == 1 );
	ok ( f->san.close_rc == 0 );
	ok ( f->ft.n_writes == 1 );
	ok ( f->ft.wr_off == 51200 );
	ok ( f->ft.wr_len == 8192 );
	blk_close ( f );
}

static void blk_test_status ( void ) {
	struct blk_fix *f = &blk_fix;
	static const struct {
		wr_status status;
		int rc;
	} table[] = {
		{ WR_E_OSD_IO, RBD_ERR ( EPROTO ) },
		{ WR_E_TIMEOUT, RBD_ERR ( ETIMEDOUT ) },
		{ WR_E_OSD_BLOCKLISTED, RBD_ERR ( EACCES ) },
		{ WR_E_RBD_NOT_FOUND, RBD_ERR ( ENOENT ) },
		{ WR_E_OSD_NOSPC, RBD_ERR ( ENOSPC ) },
		{ WR_E_RBD_READONLY, RBD_ERR ( EROFS ) },
		{ WR_E_CANCELLED, RBD_ERR ( ECANCELED ) },
		{ WR_E_RANGE, RBD_ERR ( EINVAL ) },
		{ WR_E_BUDGET, RBD_ERR ( ENOMEM ) },
		{ WR_E_NET_CLOSED, RBD_ERR ( ECONNRESET ) },
	};
	unsigned int i;

	blk_open ( f, 0, 1 );
	for ( i = 0 ; i < ( sizeof ( table ) / sizeof ( table[0] ) ) ; i++ ) {
		ok ( blk_read ( f, 0, 1 ) == 0 );
		rbd_ft_complete ( &f->ft, ( f->ft.n_r - 1 ), table[i].status );
		blk_pump ( f );
		ok ( f->san.closed == 1 );
		ok ( BLK_ERR ( f->san.close_rc, table[i].rc ) );
	}

	/* A write that fails the same way */
	rbd_ft_san_init ( &f->san );
	ok ( block_write ( &f->path.intf, &f->san.command, 0, 1, f->buf, 512 ) == 0 );
	rbd_ft_complete ( &f->ft, ( f->ft.n_r - 1 ), WR_E_RBD_READONLY );
	blk_pump ( f );
	ok ( f->san.closed == 1 );
	ok ( BLK_ERR ( f->san.close_rc, -EROFS ) );
	ok ( f->ft.n_writes == 0 );
	blk_close ( f );
}

static void blk_test_arguments ( void ) {
	struct blk_fix *f = &blk_fix;
	uint64_t blocks;

	blk_open ( f, 0, 1 );
	blocks = f->s->blocks;
	rbd_ft_san_init ( &f->san );

	/* Length that is not count * 512, a zero count, more than the largest command */
	ok ( BLK_ERR ( block_read ( &f->path.intf, &f->san.command, 0, 8, f->buf, 4095 ), -EINVAL ) );
	ok ( BLK_ERR ( block_read ( &f->path.intf, &f->san.command, 0, 8, f->buf, 4097 ), -EINVAL ) );
	ok ( BLK_ERR ( block_read ( &f->path.intf, &f->san.command, 0, 0, f->buf, 0 ), -EINVAL ) );
	ok ( BLK_ERR ( block_read ( &f->path.intf, &f->san.command, 0, 8193, f->buf, ( 8193UL * 512 ) ), -EINVAL ) );
	ok ( BLK_ERR ( block_write ( &f->path.intf, &f->san.command, 0, 8, f->buf, 100 ), -EINVAL ) );

	/* Outside the image: the last block fits, the one behind it does not, nor does a start that wraps */
	ok ( BLK_ERR ( blk_read ( f, blocks, 1 ), -EINVAL ) );
	ok ( BLK_ERR ( blk_read ( f, ( blocks - 1 ), 2 ), -EINVAL ) );
	ok ( BLK_ERR ( blk_read ( f, 0xffffffffffffffffULL, 2 ), -EINVAL ) );
	ok ( BLK_ERR ( blk_read ( f, ( 0xffffffffffffffffULL - 1 ), 1 ), -EINVAL ) );
	ok ( BLK_ERR ( blk_read ( f, ( blocks + 1000 ), 1 ), -EINVAL ) );
	ok ( f->ft.n_submit == 0 );
	ok ( list_empty ( &f->s->cmds ) );
	ok ( blk_read ( f, ( blocks - 1 ), 1 ) == 0 );
	ok ( f->ft.n_submit == 1 );
	ok ( f->ft.r[0].req->offset == ( ( blocks - 1 ) * 512 ) );
	rbd_ft_complete ( &f->ft, 0, WR_OK );
	blk_pump ( f );
	blk_close ( f );
}

static void blk_test_refused ( void ) {
	struct blk_fix *f = &blk_fix;

	/* A submit the core refuses: the error comes back from the call, the SAN layer is not plugged, nothing is left behind */
	blk_open ( f, 0, 1 );
	f->ft.submit_fail_n = 2;
	f->ft.submit_rc = WR_E_BUSY;
	ok ( BLK_ERR ( blk_read ( f, 0, 1 ), -EBUSY ) );
	ok ( list_empty ( &f->s->cmds ) );
	ok ( f->san.closed == 0 );
	f->ft.submit_rc = WR_E_RBD_READONLY;
	rbd_ft_san_init ( &f->san );
	ok ( BLK_ERR ( block_write ( &f->path.intf, &f->san.command, 0, 1, f->buf, 512 ), -EROFS ) );
	ok ( list_empty ( &f->s->cmds ) );
	ok ( f->s->demand_bytes == 0 );

	/* ... and the next command is not affected */
	ok ( blk_read ( f, 0, 1 ) == 0 );
	rbd_ft_complete ( &f->ft, 0, WR_OK );
	blk_pump ( f );
	ok ( f->san.closed == 1 );
	ok ( f->san.close_rc == 0 );
	blk_close ( f );
}

/* ---- cancel ---------------------------------------------------------------------------------------------------------------- */

static void blk_test_cancel_ok ( void ) {
	struct blk_fix *f = &blk_fix;

	blk_open ( f, 0, 1 );
	memset ( f->buf, 0xa5, sizeof ( f->buf ) );
	ok ( blk_read ( f, 0, 8 ) == 0 );
	ok ( rbd_ft_owns ( &f->ft, 0 ) );

	/* The SAN layer's 15 s timeout: it closes the command interface. The call returns when the core has let go. */
	intf_restart ( &f->san.command, -ETIMEDOUT );
	ok ( f->ft.n_cancel == 1 );
	ok ( ! rbd_ft_owns ( &f->ft, 0 ) );
	ok ( f->ft.r[0].state == FT_RETIRED );
	ok ( f->ft.r[0].req->status == WR_E_CANCELLED );
	ok ( f->s->demand_bytes == 0 );
	ok ( list_empty ( &f->s->cmds ) );
	ok ( list_empty ( &f->s->reqs ) );

	/* A reply that arrives afterwards has no buffer to land in */
	ok ( rbd_ft_late_data ( &f->ft, 0 ) == 0 );
	ok ( f->buf[0] == 0xa5 );
	ok ( f->ft.n_destroy == 0 );

	/* The session carries on: the next command works */
	ok ( blk_read ( f, 8, 8 ) == 0 );
	rbd_ft_complete ( &f->ft, 1, WR_OK );
	blk_pump ( f );
	ok ( f->san.closed == 1 );
	ok ( f->san.close_rc == 0 );
	blk_close ( f );
}

static void blk_test_cancel_write ( void ) {
	struct blk_fix *f = &blk_fix;

	blk_open ( f, 0, 1 );
	rbd_ft_san_init ( &f->san );
	ok ( block_write ( &f->path.intf, &f->san.command, 0, 8, f->buf, 4096 ) == 0 );
	intf_restart ( &f->san.command, -ETIMEDOUT );
	ok ( f->ft.n_cancel == 1 );
	ok ( ! rbd_ft_owns ( &f->ft, 0 ) );
	ok ( f->ft.n_writes == 0 );
	blk_close ( f );
}

static void blk_test_cancel_busy ( void ) {
	struct blk_fix *f = &blk_fix;
	unsigned int runs;

	/* Busy: the core runs until it lets go. The call to the SAN layer returns only after that. */
	blk_open ( f, 0, 1 );
	f->ft.cancel_rc = WR_E_BUSY;
	f->ft.busy_runs = 3;
	ok ( blk_read ( f, 0, 8 ) == 0 );
	runs = f->ft.n_run;
	intf_restart ( &f->san.command, -ETIMEDOUT );
	ok ( ! rbd_ft_owns ( &f->ft, 0 ) );
	ok ( f->ft.r[0].state == FT_RETIRED );
	ok ( ( f->ft.n_run - runs ) >= 3 );
	ok ( f->ft.n_destroy == 0 );
	ok ( list_empty ( &f->s->cmds ) );
	ok ( f->s->n_cancel_rounds_max >= 3 );
	ok ( rbd_ft_late_data ( &f->ft, 0 ) == 0 );
	blk_close ( f );
}

static void blk_test_cancel_never ( void ) {
	struct blk_fix *f = &blk_fix;

	/* A write whose copy does not fit the zombie area waits for the cluster, and nothing here gives it the network: the session is
	 * destroyed, so that nothing can read or write any buffer of the SAN layer after the call returns
	 */
	blk_open ( f, 0, 1 );
	f->ft.cancel_rc = WR_E_BUSY;
	f->ft.busy_runs = RBD_FT_NEVER;
	rbd_ft_san_init ( &f->san );
	ok ( block_write ( &f->path.intf, &f->san.command, 0, 8, f->buf, 4096 ) == 0 );
	intf_restart ( &f->san.command, -ETIMEDOUT );
	ok ( f->ft.destroyed == 1 );
	ok ( f->ft.n_destroy == 1 );
	ok ( f->ft.n_after_destroy == 0 );
	ok ( f->s->state == RBD_SESSION_DEAD );
	ok ( f->s->client == NULL );
	ok ( f->s->mem == NULL );
	ok ( f->ft.n_run <= ( RBD_CANCEL_ROUNDS + 4 ) );
	ok ( list_empty ( &rbd_sessions ) );

	/* The path is closed with a reason, the device holds no session, and nothing can be issued on it */
	ok ( f->path.closed == 1 );
	ok ( f->path.close_rc != 0 );
	ok ( list_empty ( &f->s->cmds ) );
	blk_close ( f );
}

static void blk_test_cancel_state ( void ) {
	struct blk_fix *f = &blk_fix;

	/* The request finished just before the SAN layer's timeout, and has not been pulled yet: the core says "not in flight", the
	 * request is retired from the done queue, and the structure is not freed while the core still lists it
	 */
	blk_open ( f, 0, 1 );
	ok ( blk_read ( f, 0, 8 ) == 0 );
	rbd_ft_complete ( &f->ft, 0, WR_OK );
	intf_restart ( &f->san.command, -ETIMEDOUT );
	ok ( f->ft.r[0].state == FT_RETIRED );
	ok ( list_empty ( &f->s->reqs ) );
	ok ( list_empty ( &f->s->cmds ) );
	ok ( f->ft.n_destroy == 0 );
	blk_close ( f );
}

/* ---- devices and the session ----------------------------------------------------------------------------------------------- */

static void blk_test_device_close ( void ) {
	struct blk_fix *f = &blk_fix;
	struct rbd_session *again;
	struct ft_path path2;

	/* The SAN layer closes the path (a reopen): the command in flight is stopped and told, the session stays for its grace period */
	blk_open ( f, 0, 1 );
	ok ( blk_read ( f, 0, 8 ) == 0 );
	ok ( ! timer_running ( &f->s->grace ) );
	ok ( f->s->ndev == 1 );
	intf_restart ( &f->path.intf, -ECONNRESET );
	ok ( f->ft.n_cancel == 1 );
	ok ( ! rbd_ft_owns ( &f->ft, 0 ) );
	ok ( f->san.closed == 1 );
	ok ( BLK_ERR ( f->san.close_rc, -ECONNRESET ) );
	ok ( f->s->ndev == 0 );
	ok ( list_empty ( &f->s->devices ) );
	ok ( timer_running ( &f->s->grace ) );
	ok ( f->ft.n_destroy == 0 );
	ok ( f->s->state == RBD_SESSION_OPEN );

	/* The reopen: the same session, no second client, the path is active at once */
	ok ( rbd_ft_attach ( &f->ft, f->spec, &again, &path2 ) == 0 );
	ok ( again == f->s );
	ok ( f->ft.n_create == 1 );
	ok ( f->ft.n_open == 1 );
	ok ( f->s->ndev == 1 );
	ok ( ! timer_running ( &f->s->grace ) );
	ok ( path2.window_changed == 1 );
	ok ( xfer_window ( &path2.intf ) == ( 8192UL * 512 ) );
	rbd_session_put ( again );

	intf_restart ( &path2.intf, 0 );
	blk_close ( f );
}

static void blk_test_device_close_graceful ( void ) {
	struct blk_fix *f = &blk_fix;

	/* The path is closed with status 0 (a graceful close) while a command is in flight: the command did not finish, and the SAN layer
	 * must not hear "success" (its read buffer holds nothing). The core has let go of the buffer by then.
	 */
	blk_open ( f, 0, 1 );
	memset ( f->buf, 0xa5, sizeof ( f->buf ) );
	ok ( blk_read ( f, 0, 8 ) == 0 );
	intf_restart ( &f->path.intf, 0 );
	ok ( f->san.closed == 1 );
	ok ( f->san.close_rc != 0 );
	ok ( ! rbd_ft_owns ( &f->ft, 0 ) );
	ok ( f->buf[0] == 0xa5 );
	blk_close ( f );

	/* The same for a capacity command that was not answered yet */
	blk_open ( f, 0, 1 );
	rbd_ft_san_init ( &f->san );
	ok ( block_read_capacity ( &f->path.intf, &f->san.command ) == 0 );
	intf_restart ( &f->path.intf, 0 );
	ok ( f->san.closed == 1 );
	ok ( f->san.close_rc != 0 );
	ok ( f->san.cap_n == 0 );
	blk_close ( f );
}

static void blk_test_session_failure ( void ) {
	struct blk_fix *f = &blk_fix;
	struct rbd_session *again;
	struct ft_path path2;

	/* The image fails (blocklisted): the paths are closed with the right error, the command in flight is told the same */
	blk_open ( f, 0, 1 );
	ok ( blk_read ( f, 0, 8 ) == 0 );
	f->ft.istate = WR_IMG_FAILED;
	f->ft.ierr = WR_E_OSD_BLOCKLISTED;
	blk_pump ( f );
	ok ( f->path.closed == 1 );
	ok ( BLK_ERR ( f->path.close_rc, -EACCES ) );
	ok ( f->san.closed == 1 );
	ok ( BLK_ERR ( f->san.close_rc, -EACCES ) );
	ok ( ! rbd_ft_owns ( &f->ft, 0 ) );
	ok ( f->s->state == RBD_SESSION_FAILED );
	ok ( f->s->ndev == 0 );
	ok ( f->ft.n_destroy == 0 );

	/* The reopen finds the session; its image is closed (abandoned) and opened again, the path waits until it is open */
	f->ft.istate = WR_IMG_FAILED;
	ok ( rbd_ft_attach ( &f->ft, f->spec, &again, &path2 ) == 0 );
	ok ( again == f->s );
	ok ( f->ft.n_create == 1 );
	ok ( f->ft.n_close == 1 );
	ok ( f->ft.close_flags == WR_CLOSE_ABANDON );
	ok ( f->ft.n_open == 2 );
	ok ( f->s->n_reopens == 1 );
	ok ( f->s->state == RBD_SESSION_OPENING );
	ok ( xfer_window ( &path2.intf ) == 0 );
	rbd_session_pump ( f->s );
	rbd_ft_image_open ( &f->ft );
	rbd_session_pump ( f->s );
	ok ( f->s->state == RBD_SESSION_OPEN );
	ok ( path2.window_changed == 1 );
	ok ( xfer_window ( &path2.intf ) != 0 );
	rbd_session_put ( again );
	intf_restart ( &path2.intf, 0 );
	blk_close ( f );
}

static void blk_test_fatal ( void ) {
	struct blk_fix *f = &blk_fix;
	struct rbd_session *again;
	struct ft_path path2;

	/* The core reports a fatal error: the path is closed with its error, and the session is replaced at the next open */
	blk_open ( f, 0, 1 );
	rbd_ft_event ( &f->ft, WR_EV_FATAL, WR_E_AUTH_DENIED );
	f->ft.cstate = WR_CS_FAILED;
	blk_pump ( f );
	ok ( f->path.closed == 1 );
	ok ( BLK_ERR ( f->path.close_rc, -EACCES ) );
	ok ( f->s->state == RBD_SESSION_FAILED );
	ok ( rbd_ft_attach ( &f->ft, f->spec, &again, &path2 ) == 0 );	/* the client is failed: replaced */
	ok ( again != f->s );
	ok ( f->ft.n_create == 2 );
	ok ( f->ft.n_destroy == 1 );
	f->ft.cstate = WR_CS_ACTIVE;
	rbd_session_put ( again );
	intf_restart ( &path2.intf, 0 );
	blk_close ( f );
}

/* ---- readahead ------------------------------------------------------------------------------------------------------------- */

/** One sector count of an INT 13h read */
#define RA_STEP 127

/**
 * Find the prefetch requests that are in flight
 *
 * @v f			Fixture
 * @v idx		Array of request indices to fill
 * @v max		Size of the array
 * @ret n		Number found
 */
static unsigned int blk_prefetches ( struct blk_fix *f, unsigned int *idx,
				     unsigned int max ) {
	unsigned int i;
	unsigned int n = 0;
	const uint8_t *low = ( f->s->base + f->s->arena_len + f->s->bulk_len );
	const uint8_t *high = ( low + f->s->ra_len );

	for ( i = 0 ; ( i < f->ft.n_r ) && ( n < max ) ; i++ ) {
		wr_io_req *req = f->ft.r[i].req;

		if ( ( f->ft.r[i].state == FT_FLIGHT ) &&
		     ( ( ( const uint8_t * ) req->buf ) >= low ) &&
		     ( ( ( const uint8_t * ) req->buf ) < high ) )
			idx[n++] = i;
	}
	return n;
}

/**
 * Read RA_STEP blocks, complete the demand request at once, and let the SAN layer hear it
 *
 * @v f			Fixture
 * @v lba		Block
 * @ret hit		The read made no request of its own (it was served from the cache)
 */
static int blk_ra_read ( struct blk_fix *f, uint64_t lba ) {
	unsigned int before = f->ft.n_submit;
	unsigned int first = f->ft.n_r;
	unsigned int i;
	int hit;

	ok ( blk_read ( f, lba, RA_STEP ) == 0 );
	/* The demand request, if there is one, is the first new request whose buffer is the caller's */
	hit = 1;
	for ( i = first ; i < f->ft.n_r ; i++ ) {
		if ( f->ft.r[i].req->buf == f->buf ) {
			hit = 0;
			rbd_ft_complete ( &f->ft, i, WR_OK );
		}
	}
	ok ( f->ft.n_submit >= before );
	ok ( f->san.closed == 0 );
	blk_pump ( f );
	ok ( f->san.closed == 1 );
	ok ( f->san.close_rc == 0 );
	ok ( rbd_ft_check ( &f->ft, ( lba * 512 ), f->buf,
			    ( ( size_t ) RA_STEP * 512 ) ) );
	return hit;
}

static void blk_test_readahead ( void ) {
	struct blk_fix *f = &blk_fix;
	unsigned int idx[16];
	unsigned int n;
	unsigned int i;
	unsigned int line0 = 0;
	int found0;
	wr_ra_stats st;

	blk_open ( f, 2048, 1 );
	ok ( f->s->ra != NULL );
	ok ( f->s->n_pf == 8 );
	ok ( f->s->ra_len >= ( 2048 * 1024 ) );

	/* The first reads are misses straight into the caller's buffer, and make no prefetch until the stream is recognised */
	ok ( blk_ra_read ( f, 0 ) == 0 );
	ok ( blk_prefetches ( f, idx, 16 ) == 0 );
	ok ( blk_ra_read ( f, RA_STEP ) == 0 );

	/* The third sequential read opens the window: prefetches of whole lines are submitted, with a timeout well below the SAN layer's */
	ok ( blk_ra_read ( f, ( 2 * RA_STEP ) ) == 0 );
	n = blk_prefetches ( f, idx, 16 );
	ok ( n >= 1 );
	ok ( n <= 7 );		/* one request stays free for a demand read */
	found0 = 0;
	for ( i = 0 ; i < n ; i++ ) {
		wr_io_req *req = f->ft.r[idx[i]].req;

		ok ( req->kind == WR_IO_READ );
		ok ( req->length == ( 256 * 1024 ) );
		ok ( ( req->offset % ( 256 * 1024 ) ) == 0 );
		ok ( req->timeout_ms == RBD_PREFETCH_TIMEOUT_MS );
		ok ( req->timeout_ms < ( 15 * 1000 ) );
		if ( req->offset == 0 ) {
			found0 = 1;
			line0 = idx[i];
		}
	}
	ok ( found0 );
	ok ( f->s->demand_bytes == 0 );

	/* A read behind a pending line waits (no request of its own, the SAN layer hears nothing) ... */
	rbd_ft_san_init ( &f->san );
	ok ( blk_read ( f, ( 3 * RA_STEP ), RA_STEP ) == 0 );
	ok ( f->san.closed == 0 );
	ok ( list_first_entry ( &f->s->cmds, struct rbd_cmd, list )->state == RBD_CMD_WAIT );
	ok ( f->ft.r[( f->ft.n_r - 1 )].req->buf != f->buf );

	/* ... and completes, from the cache, when the line has landed */
	rbd_ft_complete ( &f->ft, line0, WR_OK );
	ok ( f->san.closed == 0 );
	blk_pump ( f );
	ok ( f->san.closed == 1 );
	ok ( f->san.close_rc == 0 );
	ok ( rbd_ft_check ( &f->ft, ( 3 * RA_STEP * 512 ), f->buf,
			    ( ( size_t ) RA_STEP * 512 ) ) );
	wr_ra_get_stats ( f->s->ra, &st );
	ok ( st.windows >= 1 );
	ok ( st.waits >= 1 );
	ok ( st.pf_landed >= 1 );

	/* The next read in that line is a hit: no demand request, the data is right, the SAN layer hears it at the step after the call */
	i = f->ft.n_submit;
	ok ( blk_read ( f, ( 3 * RA_STEP ), 1 ) == 0 );
	ok ( f->san.closed == 0 );
	blk_pump ( f );
	ok ( f->san.closed == 1 );
	ok ( rbd_ft_check ( &f->ft, ( 3 * RA_STEP * 512 ), f->buf, 512 ) );
	wr_ra_get_stats ( f->s->ra, &st );
	ok ( st.hits >= 1 );
	( void ) i;

	/* A write over the line drops it: the same read is a miss again, straight into the buffer */
	rbd_ft_san_init ( &f->san );
	ok ( block_write ( &f->path.intf, &f->san.command, 8, 8, f->buf, 4096 ) == 0 );
	rbd_ft_complete ( &f->ft, ( f->ft.n_r - 1 ), WR_OK );
	blk_pump ( f );
	ok ( f->san.closed == 1 );
	ok ( blk_read ( f, ( 3 * RA_STEP ), 1 ) == 0 );
	ok ( f->ft.r[( f->ft.n_r - 1 )].req->buf == f->buf );
	rbd_ft_complete ( &f->ft, ( f->ft.n_r - 1 ), WR_OK );
	blk_pump ( f );
	ok ( f->san.closed == 1 );

	/* Close with prefetches in flight: nothing is left (blk_close checks the heap and the sessions) */
	blk_close ( f );
}

static void blk_test_prefetch_failure ( void ) {
	struct blk_fix *f = &blk_fix;
	unsigned int idx[16];
	unsigned int n;
	unsigned int i;

	/* A prefetch that fails is silent: the SAN layer hears nothing, the line is read again by the demand read */
	blk_open ( f, 2048, 1 );
	ok ( blk_ra_read ( f, 0 ) == 0 );
	ok ( blk_ra_read ( f, RA_STEP ) == 0 );
	ok ( blk_ra_read ( f, ( 2 * RA_STEP ) ) == 0 );
	n = blk_prefetches ( f, idx, 16 );
	ok ( n >= 1 );
	for ( i = 0 ; i < n ; i++ )
		rbd_ft_complete ( &f->ft, idx[i], WR_E_OSD_IO );
	rbd_ft_san_init ( &f->san );
	blk_pump ( f );
	ok ( f->san.closed == 0 );
	ok ( f->path.closed == 0 );
	ok ( blk_ra_read ( f, ( 3 * RA_STEP ) ) == 0 );
	blk_close ( f );
}

static void blk_test_readahead_cancel ( void ) {
	struct blk_fix *f = &blk_fix;
	unsigned int idx[16];

	/* A command parked on a line that the SAN layer gives up on: closing it stops waiting, the line stays in flight */
	blk_open ( f, 2048, 1 );
	ok ( blk_ra_read ( f, 0 ) == 0 );
	ok ( blk_ra_read ( f, RA_STEP ) == 0 );
	ok ( blk_ra_read ( f, ( 2 * RA_STEP ) ) == 0 );
	ok ( blk_prefetches ( f, idx, 16 ) >= 1 );
	rbd_ft_san_init ( &f->san );
	ok ( block_read ( &f->path.intf, &f->san.command, ( 3 * RA_STEP ), RA_STEP, f->buf,
			  ( RA_STEP * 512UL ) ) == 0 );
	ok ( list_first_entry ( &f->s->cmds, struct rbd_cmd, list )->state == RBD_CMD_WAIT );
	intf_restart ( &f->san.command, -ETIMEDOUT );
	ok ( list_empty ( &f->s->cmds ) );
	ok ( blk_prefetches ( f, idx, 16 ) >= 1 );
	ok ( f->ft.n_destroy == 0 );
	blk_close ( f );
}

static void blk_test_cancel_no_image ( void ) {
	struct blk_fix *f = &blk_fix;
	unsigned int runs;

	/* A session that has lost its image (a reopen whose open was refused) while a request is still in the core: the core has no
	 * image to cancel it against, but it may still own the buffer (it finishes the request by itself when it has reset the
	 * connection). The close of the command must wait for that, and not give the buffer back while the core can write into it.
	 */
	blk_open ( f, 0, 1 );
	memset ( f->buf, 0xa5, sizeof ( f->buf ) );
	ok ( blk_read ( f, 0, 8 ) == 0 );
	ok ( rbd_ft_owns ( &f->ft, 0 ) );
	f->s->image = NULL;
	f->ft.r[0].state = FT_BUSY;
	f->ft.r[0].busy_runs = 3;
	runs = f->ft.n_run;
	intf_restart ( &f->san.command, -ETIMEDOUT );
	ok ( f->ft.n_cancel == 0 );		/* nothing to cancel against */
	ok ( ! rbd_ft_owns ( &f->ft, 0 ) );
	ok ( ( f->ft.n_run - runs ) >= 3 );
	ok ( f->ft.n_destroy == 0 );
	ok ( list_empty ( &f->s->cmds ) );
	ok ( list_empty ( &f->s->reqs ) );
	ok ( rbd_ft_late_data ( &f->ft, 0 ) == 0 );
	ok ( f->buf[0] == 0xa5 );
	blk_close ( f );

	/* A request that the core never gives back: the session is destroyed instead, as for a cancel that never finishes */
	blk_open ( f, 0, 1 );
	ok ( blk_read ( f, 0, 8 ) == 0 );
	f->s->image = NULL;
	intf_restart ( &f->san.command, -ETIMEDOUT );
	ok ( f->ft.destroyed == 1 );
	ok ( f->ft.n_after_destroy == 0 );
	ok ( f->ft.n_run <= ( RBD_CANCEL_ROUNDS + 4 ) );
	blk_close ( f );
}

/* ---- randomised interleavings ---------------------------------------------------------------------------------------------- */

/*
 * What the tests above cannot reach is the order things happen in: a command that is cancelled while the image reopens, a prefetch that
 * lands behind a failure, a path that closes between two pumps. This runs the device, the session and the readahead cache against the
 * scripted core with a deterministic pseudo-random sequence of events (a command issued, a request finished with some status, the SAN
 * layer's timeout, a failure of the image, the client or the cluster, the path closed and opened again, time passing, the grace period
 * ending, an image that changed size, a cancel that is busy for a few runs or for ever) and checks after every step what must hold in
 * every order:
 *
 *   - the SAN layer hears every command exactly once, and always by the time the path or the session is gone (no interface is left
 *     plugged to something that will never close it);
 *   - the core never owns the buffer of a command after the SAN layer has been told that it is over (a revoked request has no
 *     buffer to write into); the core is never called after it was destroyed;
 *   - the data of a read that succeeded is the data of the image, whether it came from the core or from the cache;
 *   - at the end nothing is left: no session, no timer, no heap.
 *
 * The core's side is the scripted one with two additions that the real core has: closing the image finishes the requests that are in
 * flight, and destroying the client forgets all of them.
 */

/** Runs and steps of the randomised test */
#define STRESS_RUNS 90
#define STRESS_STEPS 150

/** The state of a randomised run */
struct blk_stress {
	/** The fake core */
	struct rbd_ft ft;
	/** Free heap before the run */
	size_t heap;
	/** Specification */
	struct rbd_spec *spec;
	/** The session (the test's reference) */
	struct rbd_session *s;
	/** The path (the SAN layer's end of the device) */
	struct ft_path path;
	/** A device is open on the path */
	int dev_up;
	/** The SAN command */
	struct ft_san san;
	/** A command is out (issued, and the SAN layer has not heard that it is over) */
	int busy;
	/** What the command was */
	unsigned int kind;
	uint64_t lba;
	unsigned int count;
	/** Where the next sequential read starts */
	uint64_t next_lba;
	/** Random state */
	uint32_t rng;
	/** The run and the step (for the message of a failure) */
	unsigned int run;
	unsigned int step;
	unsigned int action;
	/** Failures seen (only the first few are printed) */
	unsigned int bad;
	/** Commands the SAN layer heard of, by outcome */
	unsigned int n_ok;
	unsigned int n_err;
	/** The command's buffer */
	uint8_t buf[BLK_BUF];
};

static struct blk_stress blk_stress;

/** The scripted core with the two additions */
static struct rbd_core_ops stress_core;

/**
 * Close the image like the real core: every request that is in flight is finished
 *
 * @v img		Image
 * @v flags		Flags
 * @ret st		Status
 */
static wr_status stress_image_close ( wr_image *img, uint32_t flags ) {
	struct rbd_ft *ft = rbd_ft_cur;
	unsigned int i;

	for ( i = 0 ; i < ft->n_r ; i++ ) {
		if ( ft->r[i].state == FT_FLIGHT )
			rbd_ft_complete ( ft, i, WR_E_CANCELLED );
	}
	return rbd_ft_core.image_close ( img, flags );
}

/**
 * Destroy the client like the real core: whatever it held is gone with it
 *
 * @v c			Client
 */
static void stress_destroy ( wr_client *c ) {
	struct rbd_ft *ft = rbd_ft_cur;
	unsigned int i;

	rbd_ft_core.destroy ( c );
	for ( i = 0 ; i < ft->n_r ; i++ ) {
		if ( ft->r[i].state != FT_NONE )
			ft->r[i].state = FT_RETIRED;
	}
	ft->done_head = ft->done_tail;
}

/**
 * Get a random number
 *
 * @v st		Run
 * @v n			Limit
 * @ret r		Number from 0 to n - 1
 */
static unsigned int stress_rand ( struct blk_stress *st, unsigned int n ) {
	uint32_t x = st->rng;

	x ^= ( x << 13 );
	x ^= ( x >> 17 );
	x ^= ( x << 5 );
	st->rng = x;
	return ( ( x >> 8 ) % n );
}

/** Check a property of a run, and say where the run was when it failed */
#define STRESS_CHECK( st, cond ) do {					\
		int stress_ok = ( cond );				\
		if ( ( ! stress_ok ) && ( ( st )->bad++ < 6 ) )		\
			printf ( "rbd_block_test: stress run %d step %d "	\
				 "action %d: %s\n", ( int ) ( st )->run,	\
				 ( int ) ( st )->step,			\
				 ( int ) ( st )->action, #cond );	\
		ok ( stress_ok );					\
	} while ( 0 )

/**
 * Open a device on the path (and the session, found by identity or created)
 *
 * @v st		Run
 * @ret rc		Return status code
 */
static int stress_attach ( struct blk_stress *st ) {
	struct rbd_session_env env;
	struct rbd_session *session;
	int rc;

	rbd_ft_env ( &st->ft, &env );
	env.core = &stress_core;
	rbd_ft_path_init ( &st->path );
	st->dev_up = 0;
	if ( ( rc = rbd_session_open_with ( &env, st->spec, &session ) ) != 0 )
		return rc;
	if ( ( rc = rbd_device_open ( &st->path.intf, session, st->spec ) ) != 0 ) {
		rbd_session_put ( session );
		return rc;
	}
	if ( st->s )
		rbd_session_put ( st->s );
	st->s = session;
	st->dev_up = 1;
	return 0;
}

/**
 * Check that the core does not own a buffer of the SAN layer
 *
 * @v st		Run
 */
static void stress_check_buffer ( struct blk_stress *st ) {
	unsigned int i;

	for ( i = 0 ; i < st->ft.n_r ; i++ ) {
		if ( ( st->ft.r[i].req->buf == st->buf ) &&
		     rbd_ft_owns ( &st->ft, i ) ) {
			STRESS_CHECK ( st, ! "the core owns the buffer of a command the SAN layer has heard the end of" );
		}
	}
}

/**
 * Check what the SAN layer heard of the command, once it is over
 *
 * @v st		Run
 */
static void stress_check_command ( struct blk_stress *st ) {

	STRESS_CHECK ( st, st->san.closed <= 1 );
	if ( ( ! st->busy ) || ( st->san.closed == 0 ) )
		return;
	st->busy = 0;
	if ( st->san.close_rc == 0 )
		st->n_ok++;
	else
		st->n_err++;
	if ( st->kind != RBD_CMD_CAPACITY )
		stress_check_buffer ( st );
	if ( st->san.close_rc != 0 )
		return;
	if ( st->kind == RBD_CMD_READ ) {
		STRESS_CHECK ( st, rbd_ft_check ( &st->ft, ( st->lba * 512 ), st->buf,
						  ( ( size_t ) st->count * 512 ) ) );
	} else if ( st->kind == RBD_CMD_CAPACITY ) {
		STRESS_CHECK ( st, st->san.cap_n == 1 );
		STRESS_CHECK ( st, st->san.cap.blksize == 512 );
		STRESS_CHECK ( st, st->san.cap.max_count == 8192 );
		STRESS_CHECK ( st, st->san.cap.blocks > 0 );
	}
}

/**
 * Issue a command
 *
 * @v st		Run
 */
static void stress_issue ( struct blk_stress *st ) {
	unsigned int pick = stress_rand ( st, 100 );
	uint64_t blocks = st->s->blocks;
	unsigned int count = ( stress_rand ( st, 2 ) ? 127 : ( 1 + stress_rand ( st, 128 ) ) );
	uint64_t lba;
	int rc;

	if ( blocks < 256 )
		return;
	lba = ( stress_rand ( st, 10 ) < 7 ) ? st->next_lba :
		( ( uint64_t ) stress_rand ( st, 0x7fffffff ) % ( blocks - count ) );
	if ( ( lba + count ) > blocks )
		lba = 0;
	rbd_ft_san_init ( &st->san );
	memset ( st->buf, 0xa5, sizeof ( st->buf ) );
	st->lba = lba;
	st->count = count;
	if ( pick < 60 ) {
		st->kind = RBD_CMD_READ;
		rc = block_read ( &st->path.intf, &st->san.command, lba, count,
				  st->buf, ( ( size_t ) count * 512 ) );
	} else if ( pick < 85 ) {
		st->kind = RBD_CMD_WRITE;
		rc = block_write ( &st->path.intf, &st->san.command, lba, count,
				   st->buf, ( ( size_t ) count * 512 ) );
	} else {
		st->kind = RBD_CMD_CAPACITY;
		rc = block_read_capacity ( &st->path.intf, &st->san.command );
	}
	if ( rc != 0 ) {
		STRESS_CHECK ( st, st->san.closed == 0 );	/* a refused command is not "told" */
		return;
	}
	st->busy = 1;
	st->next_lba = ( lba + count );
}

/**
 * Finish a random request of the core
 *
 * @v st		Run
 */
static void stress_complete ( struct blk_stress *st ) {
	unsigned int live[FT_MAX_REQS];
	unsigned int n = 0;
	unsigned int i;
	unsigned int pick;
	wr_status status;

	for ( i = 0 ; i < st->ft.n_r ; i++ ) {
		if ( rbd_ft_owns ( &st->ft, i ) )
			live[n++] = i;
	}
	if ( ! n )
		return;
	pick = stress_rand ( st, 100 );
	status = ( ( pick < 85 ) ? WR_OK : ( ( pick < 93 ) ? WR_E_OSD_IO :
					     ( ( pick < 97 ) ? WR_E_TIMEOUT :
					       WR_E_CANCELLED ) ) );
	rbd_ft_complete ( &st->ft, live[stress_rand ( st, n )], status );
}

/**
 * Inject a failure
 *
 * @v st		Run
 */
static void stress_fail ( struct blk_stress *st ) {

	switch ( stress_rand ( st, 5 ) ) {
	case 0:
		rbd_ft_event ( &st->ft, WR_EV_FATAL, WR_E_AUTH_DENIED );
		if ( stress_rand ( st, 2 ) )
			st->ft.cstate = WR_CS_FAILED;
		break;
	case 1:
		st->ft.istate = WR_IMG_FAILED;
		st->ft.ierr = WR_E_OSD_BLOCKLISTED;
		break;
	case 2:
		rbd_ft_event ( &st->ft, WR_EV_CLUSTER_UNREACHABLE, WR_E_MON_UNREACHABLE );
		st->ft.now_ms += ( RBD_STALL_CLOSE_MS + 1 );
		break;
	case 3:
		rbd_ft_event ( &st->ft, WR_EV_IO_STALL, WR_E_TIMEOUT );
		st->ft.now_ms += ( RBD_STALL_CLOSE_MS + 1 );
		break;
	default:
		st->ft.image_bytes = ( ( 32ULL + stress_rand ( st, 33 ) ) * 1024 * 1024 );
		rbd_ft_event ( &st->ft, WR_EV_IMAGE, 0 );
		break;
	}
	rbd_session_pump ( st->s );
}

/**
 * Do one random thing
 *
 * @v st		Run
 */
static void stress_action ( struct blk_stress *st ) {
	unsigned int action = stress_rand ( st, 28 );

	st->action = action;
	switch ( action ) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
		if ( st->dev_up && ( ! st->busy ) )
			stress_issue ( st );
		break;
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
		stress_complete ( st );
		break;
	case 11:
	case 12:
		rbd_session_pump ( st->s );
		break;
	case 13:
		/* The SAN layer's timeout: it closes its own end, and hears nothing back (the call returns when the core has let go) */
		if ( st->busy && ( st->san.closed == 0 ) && stress_rand ( st, 2 ) ) {
			intf_restart ( &st->san.command, -ETIMEDOUT );
			st->busy = 0;
			st->n_err++;
			stress_check_buffer ( st );
		}
		break;
	case 14:
		st->ft.cancel_rc = ( stress_rand ( st, 2 ) ? WR_E_BUSY : WR_OK );
		st->ft.busy_runs = ( stress_rand ( st, 20 ) ? stress_rand ( st, 5 ) :
				     RBD_FT_NEVER );
		break;
	case 15:
		if ( stress_rand ( st, 6 ) == 0 )
			stress_fail ( st );
		break;
	case 16:
		/* The path closes (the SAN layer's reopen) and is opened again */
		if ( st->dev_up && ( st->path.closed == 0 ) && stress_rand ( st, 4 ) == 0 )
			intf_restart ( &st->path.intf, -ECONNRESET );
		break;
	case 17:
	case 18:
		st->ft.now_ms += stress_rand ( st, 3000 );
		rbd_session_pump ( st->s );
		break;
	case 19:
		if ( ! st->dev_up )
			rbd_session_grace_expired ( &st->s->grace, 0 );
		break;
	default:
		/* Nothing: the sequence has gaps, a request may be in flight for several steps */
		break;
	}

	/* A path the session closed is opened again (the SAN layer reopens it), and a new or reopened image is opened by the cluster */
	if ( st->dev_up && st->path.closed )
		st->dev_up = 0;
	if ( ( ! st->dev_up ) && stress_rand ( st, 2 ) ) {
		if ( stress_attach ( st ) == 0 ) {
			if ( ( st->ft.istate == WR_IMG_OPENING ) &&
			     stress_rand ( st, 8 ) ) {
				rbd_session_pump ( st->s );
				rbd_ft_image_open ( &st->ft );
			}
			rbd_session_pump ( st->s );
		}
	}
	if ( st->s->state == RBD_SESSION_DEAD )
		st->dev_up = 0;
	stress_check_command ( st );
	if ( ( ! st->busy ) && ( st->san.closed != 0 ) )
		stress_check_buffer ( st );
	STRESS_CHECK ( st, st->ft.n_after_destroy == 0 );

	/* The bytes of demand reads in flight (what the readahead planner leaves room for) are those of the commands that are in the core */
	if ( st->s->client && list_empty ( &st->s->cmds ) )
		STRESS_CHECK ( st, st->s->demand_bytes == 0 );
}

/**
 * Run one randomised test
 *
 * @v st		Run
 * @v seed		Random seed
 * @v readahead_kib	Readahead window
 */
static void stress_run ( struct blk_stress *st, unsigned int run,
			 unsigned int readahead_kib ) {
	struct rbd_session *session;
	struct rbd_session *tmp;

	st->heap = rbd_ft_heap();
	rbd_ft_init ( &st->ft );
	st->rng = ( 0x9e3779b9U * ( run + 1 ) );
	st->run = run;
	st->busy = 0;
	st->bad = 0;
	st->n_ok = 0;
	st->n_err = 0;
	st->next_lba = 0;
	st->s = NULL;
	st->spec = rbd_ft_spec();
	st->spec->readahead_kib = readahead_kib;
	rbd_ft_san_init ( &st->san );
	STRESS_CHECK ( st, stress_attach ( st ) == 0 );
	rbd_session_pump ( st->s );
	rbd_ft_image_open ( &st->ft );
	rbd_session_pump ( st->s );
	for ( st->step = 0 ; st->step < STRESS_STEPS ; st->step++ ) {
		if ( st->ft.n_r >= ( FT_MAX_REQS - 12 ) )
			break;
		stress_action ( st );
	}

	/* The end: the SAN layer lets go of the path, the sessions go, and nothing is left */
	st->action = 99;
	intf_restart ( &st->path.intf, 0 );
	stress_check_command ( st );
	STRESS_CHECK ( st, ! ( st->busy && ( st->san.closed == 0 ) ) );	/* a command nobody was told about */
	list_for_each_entry_safe ( session, tmp, &rbd_sessions, list )
		rbd_session_destroy ( session );
	if ( st->s )
		rbd_session_put ( st->s );
	st->s = NULL;
	rbd_spec_wipe ( st->spec );
	free ( st->spec );
	st->spec = NULL;
	STRESS_CHECK ( st, list_empty ( &rbd_sessions ) );
	STRESS_CHECK ( st, st->ft.n_after_destroy == 0 );
	STRESS_CHECK ( st, ! rbd_ft_leak ( st->heap ) );
}

static void blk_test_stress ( void ) {
	struct blk_stress *st = &blk_stress;
	static const unsigned int readahead[] = { 0, 2048, 1024 };
	unsigned int run;
	unsigned int ok_total = 0;
	unsigned int err_total = 0;

	stress_core = rbd_ft_core;
	stress_core.image_close = stress_image_close;
	stress_core.destroy = stress_destroy;
	for ( run = 0 ; run < STRESS_RUNS ; run++ ) {
		stress_run ( st, run, readahead[( run % 3 )] );
		ok_total += st->n_ok;
		err_total += st->n_err;
	}

	/* The runs did something: commands finished both ways (a run in which nothing happens proves nothing) */
	printf ( "rbd_block_test: stress: %d commands succeeded, %d failed or were cancelled\n", ( int ) ok_total, ( int ) err_total );
	ok ( ok_total >= 100 );
	ok ( err_total >= 20 );
}

/** Run a test and remember its name */
#define BLK_RUN( test ) do { blk_current = #test; test(); } while ( 0 )

static void blk_test_run ( void ) {

	BLK_RUN ( blk_test_capacity );
	BLK_RUN ( blk_test_too_small );
	BLK_RUN ( blk_test_window );
	BLK_RUN ( blk_test_read );
	BLK_RUN ( blk_test_write );
	BLK_RUN ( blk_test_status );
	BLK_RUN ( blk_test_arguments );
	BLK_RUN ( blk_test_refused );
	BLK_RUN ( blk_test_cancel_ok );
	BLK_RUN ( blk_test_cancel_write );
	BLK_RUN ( blk_test_cancel_busy );
	BLK_RUN ( blk_test_cancel_never );
	BLK_RUN ( blk_test_cancel_state );
	BLK_RUN ( blk_test_device_close );
	BLK_RUN ( blk_test_device_close_graceful );
	BLK_RUN ( blk_test_session_failure );
	BLK_RUN ( blk_test_fatal );
	BLK_RUN ( blk_test_readahead );
	BLK_RUN ( blk_test_prefetch_failure );
	BLK_RUN ( blk_test_readahead_cancel );
	BLK_RUN ( blk_test_cancel_no_image );
	BLK_RUN ( blk_test_stress );
}

/** RBD block device self-test set */
struct self_test rbd_block_test __self_test = {
	.name = "rbd_block_test",
	.exec = blk_test_run,
};
