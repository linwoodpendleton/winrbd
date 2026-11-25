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
 * RBD (Ceph) SAN protocol: self-tests of the session (ipxe/src/rbd_session.c) and the stack watermark (ipxe/src/rbd_stack.c)
 *
 * Built into bin-x86_64-linux/tests.linux (and the 32-bit program) by "ipxe/tools/build.sh test" (see ipxe/tests/README.md). No
 * network, no QEMU, no cluster, no waiting on the clock: time is a number the test sets (the session's environment has a clock
 * hook), and the core is the scripted fake of rbd_block_test.c (the fakes are shared, see there) or, in one test, the real core
 * with a connection API that refuses every connection.
 *
 * What is checked:
 *
 *   - creation: what the core is created with (the iPXE profile with the maps, the OSD client and the policy of the request; the
 *     user, the key, the monitors, the cluster id), the memory (ONE block: arena, bulk, readahead cache, each page aligned, in that
 *     order), the image parameters, the key wiped from the scratch at once, the failure of each step leaving nothing behind;
 *   - identity: the same request finds the same session; a different monitor list, user, pool, image, mode, access, cluster id,
 *     readahead size or KEY (by its fingerprint) is a different session;
 *   - the process: scheduled only when there is work (a deadline arms the timer, no deadline stops it), a pump asked for from inside
 *     a pump only notes that there is more to do;
 *   - failures: an open that times out says what the cluster did (authentication refused, unreachable) and not that time ran out;
 *     the cluster unreachable (or the operations stalled) for 30 s closes the paths, but only while something waits; a fatal
 *     error closes the paths and the session is replaced at the next open;
 *   - grace: a session with no device is destroyed when its period ends and not before; a session with a device is never destroyed
 *     by it;
 *   - destruction with a device and a command: both are told, the core is destroyed before anything else is freed, the key is wiped;
 *   - the handoff table's source and the EFI path's source: "in progress" until the image is open, the session's error once it
 *     failed, the key only for handoff=key and wiped when the last such device lets go;
 *   - the real core: the memory plan of the design (arena and bulk measured by the skeleton), the image parameters accepted by the
 *     real image layer, an open that times out against a cluster that cannot be reached, the reopen of that session;
 *   - the stall rules close the path only while a command waits, and an idle path does not keep the process on the run queue however
 *     long the cluster stays away; the core's private stack is wiped when the session goes; the stack switch survives a callee that
 *     changes every register a call may change;
 *   - the stack pattern (fill and measure on a plain buffer) and the "rbd-info" command.
 *
 * Secure Boot: FILE_SECBOOT ( FORBIDDEN ), like every file of the driver (docs/design/ipxe-driver.md, section 13).
 *
 * Nothing secret is used: the cephx key is a counting pattern.
 */

/* iPXE's error macros (-EINVAL ...) carry the identifier of the file that uses them (ipxe/tests/README.md): this one is local to
 * the test program. Error codes are compared by rbd_ft_error_kind(), never by their file part.
 */
#include <ipxe/errfile.h>
#define ERRFILE_rbd_session_test ( ERRFILE_OTHER | 0x007c0000 )

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
#include <ipxe/process.h>
#include <ipxe/command.h>
#include <ipxe/test.h>
#include "winrbd/rbd_priv.h"
#include "winrbd/rbd_session.h"
#include "winrbd/rbd_block.h"
#include "winrbd/rbd_acpi.h"
#include "winrbd/rbd_efi.h"

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


/** An error code as a constant expression, as seen from this file (the iPXE macros -EINVAL ... are not constant expressions) */
#define RBD_ERR( name ) ( -__einfo_errno ( EINFO_ ## name ) )

/** Check two error codes are the same error */
#define SES_ERR( rc, expected ) \
	( rbd_ft_error_kind ( rc ) == rbd_ft_error_kind ( expected ) )

/** The command of rbd_stack.c */
extern struct command rbd_info_command;

/** The pieces of one test (static: the fake is large, and the tests run one after the other) */
struct ses_fix {
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
	uint8_t buf[8192];
};

static struct ses_fix ses_fix;

/**
 * Open a session with a device
 *
 * @v f			Fixture
 * @v open		Open the image as well
 */
static void ses_open ( struct ses_fix *f, int open ) {

	f->heap = rbd_ft_heap();
	ok ( rbd_ft_size() == sizeof ( struct rbd_ft ) );
	rbd_ft_init ( &f->ft );
	rbd_ft_san_init ( &f->san );
	f->spec = rbd_ft_spec();
	ok ( rbd_ft_attach ( &f->ft, f->spec, &f->s, &f->path ) == 0 );
	if ( open ) {
		rbd_session_pump ( f->s );
		rbd_ft_image_open ( &f->ft );
		rbd_session_pump ( f->s );
	}
}

/**
 * Close a fixture and check that nothing is left
 *
 * @v f			Fixture
 */
static void ses_close ( struct ses_fix *f ) {

	rbd_ft_cleanup ( &f->path );
	if ( f->s )
		rbd_session_put ( f->s );
	f->s = NULL;
	rbd_spec_wipe ( f->spec );
	free ( f->spec );
	f->spec = NULL;
	ok ( list_empty ( &rbd_sessions ) );
	ok ( f->ft.n_after_destroy == 0 );
	ok ( ! rbd_ft_leak ( f->heap ) );
}

/**
 * Check that memory is all zero
 *
 * @v data		Memory
 * @v len		Length
 * @ret zero		All zero
 */
static int ses_zero ( const void *data, size_t len ) {
	const uint8_t *byte = data;

	while ( len-- ) {
		if ( *(byte++) )
			return 0;
	}
	return 1;
}

/* ---- creation -------------------------------------------------------------------------------------------------------------- */

static void ses_test_create ( void ) {
	struct ses_fix *f = &ses_fix;
	uintptr_t base;

	ses_open ( f, 0 );
	ok ( f->s->state == RBD_SESSION_OPENING );
	ok ( f->ft.n_create == 1 );
	ok ( f->ft.n_open == 1 );
	ok ( ! list_empty ( &rbd_sessions ) );
	ok ( timer_running ( &f->s->grace ) == 0 );	/* a device is attached */
	ok ( f->s->ndev == 1 );

	/* What the client is created with: the iPXE profile with maps and the OSD client, the request's policy */
	ok ( f->ft.cfg.map_slot_bytes != 0 );
	ok ( f->ft.cfg.osd_sessions != 0 );
	ok ( f->ft.cfg.mode_policy == WR_MODE_CRC_ONLY );
	ok ( strcmp ( f->ft.cluster.user, "wrtest" ) == 0 );
	ok ( f->ft.cluster.key.type == WR_KEY_TYPE_AES256K );
	ok ( f->ft.cluster.key.len == 32 );
	ok ( f->ft.cluster.key.secret[0] == 0x40 );
	ok ( f->ft.cluster.key.secret[31] == 0x5f );
	ok ( f->ft.cluster.n_mons == 1 );
	ok ( f->ft.cluster.mons[0].family == WR_AF_IPV4 );
	ok ( f->ft.cluster.mons[0].ip[3] == 10 );
	ok ( f->ft.cluster.mons[0].port == 3300 );
	ok ( f->ft.cluster.fsid_known == 0 );

	/* One block, page aligned: arena, then bulk right behind it */
	base = ( ( uintptr_t ) f->ft.arena.base );
	ok ( ( base % 4096 ) == 0 );
	ok ( f->ft.arena.size == 12288 );
	ok ( f->ft.bulk.base == ( f->ft.arena.base + f->ft.arena.size ) );
	ok ( f->ft.bulk.size == 20480 );
	ok ( f->s->base == f->ft.arena.base );
	ok ( ( ( ( uintptr_t ) f->s->mem ) <= ( ( uintptr_t ) f->s->base ) ) &&
	     ( ( ( uintptr_t ) f->s->base ) < ( ( ( uintptr_t ) f->s->mem ) + 4096 ) ) );
	ok ( f->s->mem_len == ( 12288 + 20480 + RBD_CORE_STACK_BYTES ) );
	ok ( f->s->ra == NULL );
	ok ( f->s->pf == NULL );

	/* The key was in the creation scratch only until the core had copied it */
	ok ( ses_zero ( &f->s->work.cluster, sizeof ( f->s->work.cluster ) ) );
	ok ( f->s->key_kept == 0 );
	ok ( ses_zero ( &f->s->key, sizeof ( f->s->key ) ) );
	ses_close ( f );
}

static void ses_test_memory_plan ( void ) {
	struct ses_fix *f = &ses_fix;
	uint8_t *ra_base;

	/* With the readahead cache: arena, bulk, cache in one block, each part page aligned */
	f->heap = rbd_ft_heap();
	rbd_ft_init ( &f->ft );
	f->spec = rbd_ft_spec();
	f->spec->readahead_kib = 2048;
	ok ( rbd_ft_attach ( &f->ft, f->spec, &f->s, &f->path ) == 0 );
	ok ( f->s->ra != NULL );
	ok ( f->s->ra_len >= ( 2048UL * 1024 ) );
	ok ( f->s->ra_len < ( 2048UL * 1024 + 8192 ) );
	ok ( ( f->s->ra_len % 4096 ) == 0 );
	ok ( f->s->mem_len == ( f->s->arena_len + f->s->bulk_len + f->s->ra_len +
	                       RBD_CORE_STACK_BYTES ) );
	ra_base = ( ( uint8_t * ) f->s->base + f->s->arena_len + f->s->bulk_len );
	ok ( ( ( ( uintptr_t ) ra_base ) % 4096 ) == 0 );
	ok ( ( ( void * ) f->s->ra ) == ( ( void * ) ra_base ) );
	ok ( f->s->n_pf == 8 );
	ok ( f->s->pf != NULL );
	ses_close ( f );

	/* Smaller windows: one line at least */
	f->heap = rbd_ft_heap();
	rbd_ft_init ( &f->ft );
	f->spec = rbd_ft_spec();
	f->spec->readahead_kib = 100;
	ok ( rbd_ft_attach ( &f->ft, f->spec, &f->s, &f->path ) == 0 );
	ok ( f->s->n_pf == 1 );
	ses_close ( f );
}

static void ses_test_step_failures ( void ) {
	struct ses_fix *f = &ses_fix;
	struct rbd_session *s;
	struct rbd_session_env env;
	struct ft_path path;

	/* Each step of the creation that can fail, and what it leaves behind (nothing: no session, no core, no heap) */
	f->heap = rbd_ft_heap();
	rbd_ft_init ( &f->ft );
	f->spec = rbd_ft_spec();
	rbd_ft_env ( &f->ft, &env );

	f->ft.mem_rc = WR_E_BUDGET;
	ok ( SES_ERR ( rbd_session_open_with ( &env, f->spec, &s ), -ENOMEM ) );
	ok ( s == NULL );
	ok ( list_empty ( &rbd_sessions ) );
	ok ( f->ft.n_create == 0 );
	f->ft.mem_rc = 0;

	f->ft.create_rc = WR_E_INVAL;
	ok ( SES_ERR ( rbd_session_open_with ( &env, f->spec, &s ), -EINVAL ) );
	ok ( s == NULL );
	ok ( list_empty ( &rbd_sessions ) );
	ok ( f->ft.n_create == 1 );
	ok ( f->ft.n_destroy == 0 );
	f->ft.create_rc = 0;

	f->ft.open_rc = WR_E_RBD_BAD_ID;
	ok ( SES_ERR ( rbd_session_open_with ( &env, f->spec, &s ), -EINVAL ) );
	ok ( s == NULL );
	ok ( list_empty ( &rbd_sessions ) );
	ok ( f->ft.n_destroy == 1 );
	f->ft.open_rc = 0;

	/* A device for a session that is gone is refused */
	ok ( rbd_ft_attach ( &f->ft, f->spec, &s, &path ) == 0 );
	rbd_session_destroy ( s );
	ok ( SES_ERR ( rbd_device_open ( &path.intf, s, f->spec ), -ENOTCONN ) );
	rbd_session_put ( s );
	ok ( list_empty ( &rbd_sessions ) );
	rbd_ft_cleanup ( &path );

	rbd_spec_wipe ( f->spec );
	free ( f->spec );
	f->spec = NULL;
	ok ( ! rbd_ft_leak ( f->heap ) );
}

/* ---- identity -------------------------------------------------------------------------------------------------------------- */

static void ses_test_identity ( void ) {
	struct ses_fix *f = &ses_fix;
	struct rbd_session_env env;
	struct rbd_session *s;
	struct rbd_session *t;
	struct rbd_spec *other;
	unsigned int n;
	unsigned int i;
	struct list_head *entry;

	f->heap = rbd_ft_heap();
	rbd_ft_init ( &f->ft );
	rbd_ft_env ( &f->ft, &env );
	f->spec = rbd_ft_spec();
	ok ( rbd_session_open_with ( &env, f->spec, &s ) == 0 );

	/* The same request is the same session; a changed timeout or device path option is not part of the identity */
	other = rbd_ft_spec();
	other->open_timeout_ms = 5000;
	other->devpath = RBD_DEVPATH_SATA;
	other->handoff = RBD_HANDOFF_NONE;
	ok ( rbd_session_open_with ( &env, other, &t ) == 0 );
	ok ( t == s );
	ok ( f->ft.n_create == 1 );
	rbd_session_put ( t );
	rbd_spec_wipe ( other );
	free ( other );

	/* Everything that makes another session */
	for ( i = 0 ; i < 13 ; i++ ) {
		other = rbd_ft_spec();
		switch ( i ) {
		case 0:
			other->mons[0].port = 3301;
			break;
		case 1:
			other->mons[0].ip[3] = 11;
			break;
		case 2:
			other->mons[1] = other->mons[0];
			other->n_mons = 2;
			break;
		case 3:
			strcpy ( other->user, "other" );
			break;
		case 4:
			strcpy ( other->pool, "other" );
			break;
		case 5:
			strcpy ( other->image, "other" );
			break;
		case 6:
			other->mode = WR_MODE_SECURE_ONLY;
			break;
		case 7:
			other->read_only = 1;
			break;
		case 8:
			other->fsid_known = 1;
			break;
		case 9:
			other->readahead_kib = 1024;
			break;
		case 10:
			other->key.secret[31] ^= 1;	/* a changed rbd-key setting */
			break;
		case 11:
			other->key.type = WR_KEY_TYPE_AES;
			other->key.len = 16;
			break;
		case 12:
			other->mons[0].family = WR_AF_IPV6;
			break;
		}
		ok ( rbd_session_open_with ( &env, other, &t ) == 0 );
		ok ( t != s );
		rbd_session_put ( t );
		rbd_spec_wipe ( other );
		free ( other );
	}
	ok ( f->ft.n_create == 14 );
	n = 0;
	list_for_each ( entry, &rbd_sessions )
		n++;
	ok ( n == 14 );

	/* The first one is still found */
	ok ( rbd_session_open_with ( &env, f->spec, &t ) == 0 );
	ok ( t == s );
	rbd_session_put ( t );
	rbd_session_put ( s );

	/* None has a device: all go at the end of their grace period (here: destroyed by hand) */
	ok ( rbd_ft_heap() != 0 );
	while ( ! list_empty ( &rbd_sessions ) ) {
		s = list_first_entry ( &rbd_sessions, struct rbd_session, list );
		ok ( timer_running ( &s->grace ) );
		rbd_session_destroy ( s );
	}
	rbd_spec_wipe ( f->spec );
	free ( f->spec );
	f->spec = NULL;
	ok ( f->ft.n_destroy == 14 );
	ok ( ! rbd_ft_leak ( f->heap ) );
}

/* ---- the process ------------------------------------------------------------------------------------------------------------ */

static void ses_test_schedule ( void ) {
	struct ses_fix *f = &ses_fix;
	unsigned int runs;

	ses_open ( f, 1 );
	process_del ( &f->s->proc );
	f->ft.next_deadline = WR_DEADLINE_NONE;
	rbd_session_pump ( f->s );
	ok ( ! process_running ( &f->s->proc ) );
	ok ( ! timer_running ( &f->s->timer ) );

	/* A deadline arms the timer (and the process stays off the queue) */
	f->ft.next_deadline = ( f->ft.now_ms + 5000 );
	rbd_session_pump ( f->s );
	ok ( ! process_running ( &f->s->proc ) );
	ok ( timer_running ( &f->s->timer ) );
	ok ( f->s->next_deadline == ( f->ft.now_ms + 5000 ) );

	/* ... and when the timer expires the process is woken */
	rbd_session_timer_expired ( &f->s->timer, 0 );
	ok ( process_running ( &f->s->proc ) );
	process_del ( &f->s->proc );

	/* No deadline stops the timer */
	f->ft.next_deadline = WR_DEADLINE_NONE;
	rbd_session_pump ( f->s );
	ok ( ! timer_running ( &f->s->timer ) );

	/* A deadline that has passed, or more work: the process is scheduled at once */
	f->ft.next_deadline = ( f->ft.now_ms - 1 );
	rbd_session_pump ( f->s );
	ok ( process_running ( &f->s->proc ) );
	process_del ( &f->s->proc );
	f->ft.next_deadline = WR_DEADLINE_NONE;
	f->ft.more_work = 1;
	runs = f->ft.n_run;
	rbd_session_pump ( f->s );
	ok ( ( f->ft.n_run - runs ) == RBD_PUMP_ROUNDS );	/* bounded: one pass does not hog the CPU */
	ok ( process_running ( &f->s->proc ) );
	process_del ( &f->s->proc );
	f->ft.more_work = 0;

	/* A pump asked for from inside a pump only notes that there is more to do */
	runs = f->ft.n_run;
	f->s->in_pump = 1;
	rbd_session_pump ( f->s );
	f->s->in_pump = 0;
	ok ( f->ft.n_run == runs );
	ok ( f->s->dirty == 1 );
	f->s->dirty = 0;

	/* The time the core is given is the clock's */
	f->ft.now_ms = 424242;
	rbd_session_pump ( f->s );
	ok ( f->s->last_now == 424242 );
	ses_close ( f );
}

static void ses_test_submit_gating ( void ) {
	struct ses_fix *f = &ses_fix;
	struct rbd_request rq;

	/* No request before the image is open */
	ses_open ( f, 0 );
	memset ( &rq, 0, sizeof ( rq ) );
	ok ( SES_ERR ( rbd_session_submit ( f->s, &rq ), -ENOTCONN ) );
	ok ( f->ft.n_submit == 0 );
	ok ( ! rq.pending );
	ses_close ( f );
}

/* ---- failures -------------------------------------------------------------------------------------------------------------- */

static void ses_test_open_timeout ( void ) {
	struct ses_fix *f = &ses_fix;
	static const struct {
		wr_ev_kind kind;
		wr_status status;
		int rc;
	} table[] = {
		{ WR_EV_AUTH_FAILED, WR_E_AUTH_DENIED, RBD_ERR ( EACCES ) },
		{ WR_EV_CLUSTER_UNREACHABLE, WR_E_MON_UNREACHABLE,
		  RBD_ERR ( ENETUNREACH ) },
		{ WR_EV_NONE, WR_OK, RBD_ERR ( ETIMEDOUT ) },
	};
	unsigned int i;

	/* An open that times out says what the cluster did, not that time ran out: the right error number for the SAN layer */
	for ( i = 0 ; i < ( sizeof ( table ) / sizeof ( table[0] ) ) ; i++ ) {
		ses_open ( &ses_fix, 0 );
		rbd_session_pump ( f->s );
		if ( table[i].kind != WR_EV_NONE )
			rbd_ft_event ( &f->ft, table[i].kind, table[i].status );
		rbd_session_pump ( f->s );
		ok ( f->path.closed == 0 );
		f->ft.istate = WR_IMG_FAILED;
		f->ft.ierr = WR_E_TIMEOUT;
		rbd_session_pump ( f->s );
		ok ( f->path.closed == 1 );
		ok ( SES_ERR ( f->path.close_rc, table[i].rc ) );
		ok ( f->s->state == RBD_SESSION_FAILED );
		ses_close ( f );
	}

	/* An image that is not there, or a pool that is not: their own errors */
	ses_open ( f, 0 );
	f->ft.istate = WR_IMG_FAILED;
	f->ft.ierr = WR_E_RBD_NOT_FOUND;
	rbd_session_pump ( f->s );
	ok ( SES_ERR ( f->path.close_rc, -ENOENT ) );
	ses_close ( f );
	ses_open ( f, 0 );
	f->ft.istate = WR_IMG_FAILED;
	f->ft.ierr = WR_E_POOL_NOT_FOUND;
	rbd_session_pump ( f->s );
	ok ( SES_ERR ( f->path.close_rc, -ENOENT ) );
	ses_close ( f );
}

static void ses_test_stall ( void ) {
	struct ses_fix *f = &ses_fix;
	uint64_t t0;

	/* The monitors are not reachable: nothing happens while nothing waits, however long it takes */
	ses_open ( f, 1 );
	t0 = f->ft.now_ms;
	rbd_ft_event ( &f->ft, WR_EV_CLUSTER_UNREACHABLE, WR_E_MON_UNREACHABLE );
	rbd_session_pump ( f->s );
	ok ( f->s->trouble_since != 0 );
	f->ft.now_ms = ( t0 + 600000 );
	rbd_session_pump ( f->s );
	ok ( f->path.closed == 0 );
	ses_close ( f );

	/* With a command waiting: not before 30 s, then the path is closed with the reason and the command is stopped */
	ses_open ( f, 1 );
	t0 = f->ft.now_ms;
	ok ( block_read ( &f->path.intf, &f->san.command, 0, 8, f->buf, 4096 ) == 0 );
	rbd_ft_event ( &f->ft, WR_EV_CLUSTER_UNREACHABLE, WR_E_MON_UNREACHABLE );
	rbd_session_pump ( f->s );
	f->ft.now_ms = ( t0 + RBD_STALL_CLOSE_MS - 1 );
	rbd_session_pump ( f->s );
	ok ( f->path.closed == 0 );
	ok ( f->s->n_stall_closes == 0 );
	f->ft.now_ms = ( t0 + RBD_STALL_CLOSE_MS );
	rbd_session_pump ( f->s );
	ok ( f->path.closed == 1 );
	ok ( SES_ERR ( f->path.close_rc, -ENETUNREACH ) );
	ok ( f->s->n_stall_closes == 1 );
	ok ( f->san.closed == 1 );
	ok ( ! rbd_ft_owns ( &f->ft, 0 ) );
	ok ( f->s->state == RBD_SESSION_OPEN );		/* the session stays: the reopen finds it */
	ok ( f->s->ndev == 0 );
	ses_close ( f );

	/* A monitor session that comes back clears the trouble */
	ses_open ( f, 1 );
	t0 = f->ft.now_ms;
	ok ( block_read ( &f->path.intf, &f->san.command, 0, 8, f->buf, 4096 ) == 0 );
	rbd_ft_event ( &f->ft, WR_EV_AUTH_FAILED, WR_E_AUTH_DENIED );
	rbd_session_pump ( f->s );
	rbd_ft_event ( &f->ft, WR_EV_MON_SESSION_UP, 0 );
	rbd_session_pump ( f->s );
	ok ( f->s->trouble_since == 0 );
	f->ft.now_ms = ( t0 + 3 * RBD_STALL_CLOSE_MS );
	rbd_session_pump ( f->s );
	ok ( f->path.closed == 0 );
	ses_close ( f );

	/* The operations stall: the same rule, its own error; a resume clears it */
	ses_open ( f, 1 );
	t0 = f->ft.now_ms;
	ok ( block_read ( &f->path.intf, &f->san.command, 0, 8, f->buf, 4096 ) == 0 );
	rbd_ft_event ( &f->ft, WR_EV_IO_STALL, WR_E_TIMEOUT );
	rbd_session_pump ( f->s );
	ok ( f->s->stall_since != 0 );
	f->ft.now_ms = ( t0 + RBD_STALL_CLOSE_MS );
	rbd_session_pump ( f->s );
	ok ( f->path.closed == 1 );
	ok ( SES_ERR ( f->path.close_rc, -ETIMEDOUT ) );
	ses_close ( f );
	ses_open ( f, 1 );
	t0 = f->ft.now_ms;
	ok ( block_read ( &f->path.intf, &f->san.command, 0, 8, f->buf, 4096 ) == 0 );
	rbd_ft_event ( &f->ft, WR_EV_IO_STALL, WR_E_TIMEOUT );
	rbd_ft_event ( &f->ft, WR_EV_IO_RESUME, 0 );
	rbd_session_pump ( f->s );
	ok ( f->s->stall_since == 0 );
	f->ft.now_ms = ( t0 + 2 * RBD_STALL_CLOSE_MS );
	rbd_session_pump ( f->s );
	ok ( f->path.closed == 0 );
	ses_close ( f );

	/* The deadline of the rule is a wake-up of the process while a command waits (no timer needed from the core) */
	ses_open ( f, 1 );
	ok ( block_read ( &f->path.intf, &f->san.command, 0, 8, f->buf, 4096 ) == 0 );
	process_del ( &f->s->proc );
	rbd_ft_event ( &f->ft, WR_EV_CLUSTER_UNREACHABLE, WR_E_MON_UNREACHABLE );
	rbd_session_pump ( f->s );
	ok ( timer_running ( &f->s->timer ) );
	ok ( ! process_running ( &f->s->proc ) );
	ses_close ( f );

	/* ... and not while the path is idle: the rule would ignore a deadline then, so it must neither arm the timer nor, once the
	 * deadline has passed, keep the process on the run queue (it would spin for as long as the cluster stays away)
	 */
	ses_open ( f, 1 );
	process_del ( &f->s->proc );
	rbd_ft_event ( &f->ft, WR_EV_CLUSTER_UNREACHABLE, WR_E_MON_UNREACHABLE );
	rbd_session_pump ( f->s );
	ok ( f->s->trouble_since != 0 );
	ok ( ! timer_running ( &f->s->timer ) );
	ok ( ! process_running ( &f->s->proc ) );
	f->ft.now_ms += ( 10 * RBD_STALL_CLOSE_MS );
	rbd_session_pump ( f->s );
	ok ( ! process_running ( &f->s->proc ) );
	ok ( ! timer_running ( &f->s->timer ) );
	ok ( f->path.closed == 0 );

	/* The first command after the gap finds the rule due at once, as it always did */
	ok ( block_read ( &f->path.intf, &f->san.command, 0, 8, f->buf, 4096 ) == 0 );
	ok ( f->path.closed == 1 );
	ok ( f->s->n_stall_closes == 1 );
	ses_close ( f );

	/* A session that no device is attached to (the grace period: the SAN layer is between two opens) has no path to close: the rule
	 * must not fire for it, whatever its state (an image that is still opening and a cluster that is not there), or it would print
	 * its "closing the path" line every 30 s for as long as the grace period lasts, with nobody to tell
	 */
	ses_open ( f, 0 );
	rbd_ft_event ( &f->ft, WR_EV_CLUSTER_UNREACHABLE, WR_E_MON_UNREACHABLE );
	rbd_session_pump ( f->s );
	ok ( f->s->trouble_since != 0 );
	intf_restart ( &f->path.intf, 0 );
	ok ( f->s->ndev == 0 );
	f->ft.now_ms += ( 3 * RBD_STALL_CLOSE_MS );
	rbd_session_pump ( f->s );
	f->ft.now_ms += ( 3 * RBD_STALL_CLOSE_MS );
	rbd_session_pump ( f->s );
	ok ( f->s->n_stall_closes == 0 );
	ok ( f->s->state == RBD_SESSION_OPENING );
	ses_close ( f );
}

/* ---- grace and destruction --------------------------------------------------------------------------------------------------- */

static void ses_test_grace ( void ) {
	struct ses_fix *f = &ses_fix;
	struct rbd_session *s;

	ses_open ( f, 1 );
	s = rbd_session_get ( f->s );

	/* A device is attached: the period does not end the session, it only starts again */
	rbd_session_grace_expired ( &s->grace, 0 );
	ok ( s->state == RBD_SESSION_OPEN );
	ok ( f->ft.n_destroy == 0 );
	ok ( timer_running ( &s->grace ) );
	stop_timer ( &s->grace );

	/* No device: the period ends the session */
	intf_restart ( &f->path.intf, 0 );
	ok ( timer_running ( &s->grace ) );
	ok ( f->ft.n_destroy == 0 );
	rbd_session_grace_expired ( &s->grace, 0 );
	ok ( s->state == RBD_SESSION_DEAD );
	ok ( f->ft.n_destroy == 1 );
	ok ( f->ft.destroyed == 1 );
	ok ( s->client == NULL );
	ok ( s->mem == NULL );
	ok ( list_empty ( &rbd_sessions ) );
	ok ( ! timer_running ( &s->grace ) );
	ok ( ! timer_running ( &s->timer ) );
	ok ( ! process_running ( &s->proc ) );
	rbd_session_put ( s );
	ses_close ( f );
}

static void ses_test_destroy_busy ( void ) {
	struct ses_fix *f = &ses_fix;
	struct rbd_session *s;
	struct rbd_session *again;
	struct rbd_spec *spec2;
	struct ft_path path2;

	/* A device that asked for the key: the session keeps it, and wipes it when the last device that asked has gone, even if
	 * another device is still attached
	 */
	f->heap = rbd_ft_heap();
	rbd_ft_init ( &f->ft );
	rbd_ft_san_init ( &f->san );
	f->spec = rbd_ft_spec();
	f->spec->handoff = RBD_HANDOFF_KEY;
	ok ( rbd_ft_attach ( &f->ft, f->spec, &f->s, &f->path ) == 0 );
	s = f->s;
	rbd_session_pump ( s );
	rbd_ft_image_open ( &f->ft );
	rbd_session_pump ( s );
	ok ( s->key_kept == 1 );
	ok ( s->key.len == 32 );
	ok ( s->key.secret[0] == 0x40 );
	spec2 = rbd_ft_spec();		/* the same session, a device that does not ask for the key */
	ok ( rbd_ft_attach ( &f->ft, spec2, &again, &path2 ) == 0 );
	ok ( again == s );
	ok ( s->ndev == 2 );
	ok ( s->key_kept == 1 );
	intf_restart ( &f->path.intf, 0 );
	ok ( s->ndev == 1 );
	ok ( s->key_kept == 0 );
	ok ( ses_zero ( &s->key, sizeof ( s->key ) ) );
	ok ( ! timer_running ( &s->grace ) );

	/* A session destroyed with a device attached and a command in flight (the cancel that never finishes does this): both are
	 * told, the core is destroyed first, nothing is called afterwards
	 */
	ok ( block_read ( &path2.intf, &f->san.command, 0, 8, f->buf, 4096 ) == 0 );
	ok ( rbd_ft_owns ( &f->ft, 0 ) );
	rbd_session_destroy ( s );
	ok ( f->ft.destroyed == 1 );
	ok ( f->ft.n_destroy == 1 );
	ok ( f->san.closed == 1 );
	ok ( f->san.close_rc != 0 );
	ok ( path2.closed == 1 );
	ok ( list_empty ( &s->cmds ) );
	ok ( list_empty ( &s->devices ) );
	ok ( s->ndev == 0 );
	ok ( list_empty ( &rbd_sessions ) );
	ok ( ! timer_running ( &s->grace ) );

	/* Destroying it again does nothing */
	rbd_session_destroy ( s );
	ok ( f->ft.n_destroy == 1 );
	rbd_session_put ( again );
	rbd_spec_wipe ( spec2 );
	free ( spec2 );
	ses_close ( f );
}

/* ---- the handoff table's and the EFI path's source ------------------------------------------------------------------------- */

static void ses_test_sources ( void ) {
	struct ses_fix *f = &ses_fix;
	struct rbd_handoff_source *src;
	struct rbd_efi_source *efi;
	struct rbd_device *rbd;
	uint8_t zero[16];

	f->heap = rbd_ft_heap();
	memset ( zero, 0, sizeof ( zero ) );
	src = zalloc ( sizeof ( *src ) );
	efi = zalloc ( sizeof ( *efi ) );
	ok ( src != NULL );
	ok ( efi != NULL );

	/* While the image opens, the describe loop of the SAN layer waits */
	rbd_ft_init ( &f->ft );
	f->spec = rbd_ft_spec();
	f->spec->fsid_known = 1;
	memset ( f->spec->fsid, 0x77, 16 );
	f->spec->handoff = RBD_HANDOFF_KEY;
	f->spec->devpath = RBD_DEVPATH_URI;
	f->spec->uri = "rbd://10.77.0.10/pool/img?devpath=uri";
	ok ( rbd_ft_attach ( &f->ft, f->spec, &f->s, &f->path ) == 0 );
	ok ( SES_ERR ( rbd_session_handoff ( f->s, src ), -EINPROGRESS ) );
	rbd_session_pump ( f->s );
	rbd_ft_image_open ( &f->ft );
	rbd_session_pump ( f->s );

	/* Open: the identity, the monitors, the image's id, and the key because the device asked for it */
	ok ( rbd_session_handoff ( f->s, src ) == 0 );
	ok ( strcmp ( src->user, "wrtest" ) == 0 );
	ok ( strcmp ( src->pool, "pool" ) == 0 );
	ok ( strcmp ( src->image, "img" ) == 0 );
	ok ( strcmp ( src->image_id, "10a1b2c3d4e5" ) == 0 );
	ok ( src->snap == NULL );
	ok ( src->n_mons == 1 );
	ok ( src->mons[0].family == WR_AF_IPV4 );
	ok ( src->mons[0].port == 3300 );
	ok ( src->mons[0].ip[3] == 10 );
	ok ( src->fsid_known == 1 );
	ok ( src->fsid[0] == 0x77 );
	ok ( src->mode == WR_MODE_CRC_ONLY );
	ok ( src->read_only == 0 );
	ok ( src->key != NULL );
	ok ( src->key->len == 32 );
	ok ( src->key->secret[0] == 0x40 );

	/* The EFI path: the identity, the first monitor, the URI (a copy that is the session's own) */
	ok ( rbd_session_efi_source ( f->s, efi ) == 0 );
	ok ( efi->ident.fsid_known == 1 );
	ok ( efi->ident.fsid[15] == 0x77 );
	ok ( strcmp ( efi->ident.pool, "pool" ) == 0 );
	ok ( strcmp ( efi->ident.image, "img" ) == 0 );
	ok ( efi->ident.snap == NULL );
	ok ( efi->mon.family == WR_AF_IPV4 );
	ok ( efi->mon.ip[3] == 10 );
	ok ( efi->ident.uri != NULL );
	ok ( efi->ident.uri != f->spec->uri );
	ok ( strcmp ( efi->ident.uri, f->spec->uri ) == 0 );

	/* The key goes when the last device that wanted it lets go */
	rbd = list_first_entry ( &f->s->devices, struct rbd_device, list );
	ok ( rbd != NULL );
	intf_restart ( &f->path.intf, 0 );
	ok ( f->s->key_kept == 0 );
	ok ( ses_zero ( &f->s->key, sizeof ( f->s->key ) ) );

	/* A device that did not ask for it gets none, even from a session that was opened by one that did */
	f->spec->handoff = RBD_HANDOFF_NOKEY;
	rbd_spec_wipe ( f->spec );
	free ( f->spec );
	f->spec = rbd_ft_spec();
	f->spec->fsid_known = 1;
	memset ( f->spec->fsid, 0x77, 16 );
	f->spec->devpath = RBD_DEVPATH_URI;
	{
		struct rbd_session *again;
		struct ft_path path2;

		ok ( rbd_ft_attach ( &f->ft, f->spec, &again, &path2 ) == 0 );
		ok ( again == f->s );
		ok ( rbd_session_handoff ( again, src ) == 0 );
		ok ( src->key == NULL );
		rbd_session_put ( again );
		intf_restart ( &path2.intf, 0 );
	}

	/* The session's error once it has failed; "not connected" once it is gone */
	f->s->state = RBD_SESSION_FAILED;
	f->s->fail_rc = -EACCES;
	ok ( SES_ERR ( rbd_session_handoff ( f->s, src ), -EACCES ) );
	f->s->fail_rc = 0;
	ok ( SES_ERR ( rbd_session_handoff ( f->s, src ), -ENOTCONN ) );
	f->s->state = RBD_SESSION_OPEN;
	rbd_session_destroy ( f->s );
	ok ( SES_ERR ( rbd_session_handoff ( f->s, src ), -ENOTCONN ) );
	ok ( SES_ERR ( rbd_session_efi_source ( f->s, efi ), -ENOTCONN ) );
	ok ( SES_ERR ( rbd_session_handoff ( NULL, src ), -ENOTCONN ) );
	ok ( SES_ERR ( rbd_session_efi_source ( NULL, efi ), -ENOTCONN ) );
	rbd_session_put ( f->s );
	f->s = NULL;
	free ( src );
	free ( efi );
	rbd_spec_wipe ( f->spec );
	free ( f->spec );
	f->spec = NULL;
	ok ( list_empty ( &rbd_sessions ) );
	ok ( f->ft.n_after_destroy == 0 );
	ok ( ! rbd_ft_leak ( f->heap ) );
}

/* ---- the real core ----------------------------------------------------------------------------------------------------------- */

/** Open a TCP connection: there is no network */
static int ses_real_open ( struct interface *intf __unused,
			   struct sockaddr *peer __unused ) {

	return -ENETUNREACH;
}

static void ses_test_real_core ( void ) {
	struct ses_fix *f = &ses_fix;
	struct rbd_session_env env;
	struct rbd_conn_ops conn;
	struct rbd_session *s;
	struct rbd_session *again;
	struct ft_path path;
	struct ft_path path2;
	wr_config cfg;
	wr_mem_req req;
	unsigned int second;
	size_t heap;

	/* The memory plan of the design: what the core says for the iPXE profile with the maps, the OSD client and the crc policy */
	wr_config_profile_ipxe ( &cfg );
	wr_config_enable_maps ( &cfg, WR_MAPS_IPXE );
	wr_config_enable_osd ( &cfg, WR_MAPS_IPXE );
	wr_config_enable_secure ( &cfg, WR_MAPS_IPXE, WR_MODE_CRC_ONLY );
	ok ( wr_client_mem_required ( &cfg, &req ) == WR_OK );
	printf ( "rbd_session_test: the memory plan of this build: arena %zd bytes, bulk %zd bytes\n", req.arena, req.bulk );
	if ( sizeof ( void * ) == 8 ) {
		ok ( req.arena == 263392 );
		ok ( req.bulk == 2627584 );
	}

	/* A real core, a connection API that fails every connection, a clock the test sets */
	heap = rbd_ft_heap();
	rbd_ft_init ( &f->ft );
	f->ft.now_ms = 100000;
	conn = rbd_conn_default_ops;
	conn.open = ses_real_open;
	rbd_ft_env ( &f->ft, &env );
	env.core = &rbd_core_default_ops;
	env.conn = &conn;
	f->spec = rbd_ft_spec();
	f->spec->readahead_kib = 2048;
	f->spec->open_timeout_ms = 20000;
	rbd_ft_path_init ( &path );
	ok ( rbd_session_open_with ( &env, f->spec, &s ) == 0 );
	ok ( rbd_device_open ( &path.intf, s, f->spec ) == 0 );
	ok ( s->state == RBD_SESSION_OPENING );
	ok ( s->arena_len == ( ( req.arena + 4095 ) & ~4095UL ) );
	ok ( s->bulk_len == ( ( req.bulk + 4095 ) & ~4095UL ) );
	if ( sizeof ( void * ) == 8 ) {
		ok ( s->arena_len == 266240 );		/* 263,392 rounded up to 4,096 */
		ok ( s->bulk_len == 2629632 );		/* 2,627,584 rounded up */
	}
	ok ( s->mem_len == ( s->arena_len + s->bulk_len + s->ra_len +
	                    RBD_CORE_STACK_BYTES ) );
	ok ( s->ra_len >= ( 2048UL * 1024 ) );
	ok ( ses_zero ( &s->work.cluster, sizeof ( s->work.cluster ) ) );
	ok ( s->image != NULL );
	ok ( xfer_window ( &path.intf ) == 0 );

	/* The core works offline: it tries to connect, the connection API refuses, it backs off. After the open timeout the image fails
	 * and the path is closed with a reason (no cluster to talk to: unreachable or timed out, whichever the core says first)
	 */
	for ( second = 0 ; ( second < 30 ) && ( ! path.closed ) ; second++ ) {
		f->ft.now_ms += 1000;
		rbd_session_pump ( s );
	}
	ok ( path.closed == 1 );
	ok ( ( second >= 19 ) && ( second <= 26 ) );
	ok ( ( SES_ERR ( path.close_rc, -ETIMEDOUT ) ) ||
	     ( SES_ERR ( path.close_rc, -ENETUNREACH ) ) );
	ok ( s->state == RBD_SESSION_FAILED );

	/* The reopen finds the session and reopens the image in the same real core */
	rbd_ft_path_init ( &path2 );
	ok ( rbd_session_open_with ( &env, f->spec, &again ) == 0 );
	ok ( again == s );
	ok ( s->n_reopens == 1 );
	ok ( s->state == RBD_SESSION_OPENING );
	ok ( rbd_device_open ( &path2.intf, again, f->spec ) == 0 );
	rbd_session_put ( again );
	rbd_session_put ( s );
	rbd_ft_cleanup ( &path2 );
	rbd_spec_wipe ( f->spec );
	free ( f->spec );
	f->spec = NULL;
	ok ( list_empty ( &rbd_sessions ) );
	ok ( ! rbd_ft_leak ( heap ) );
}

/* ---- the stack pattern and rbd-info ------------------------------------------------------------------------------------------ */

static void ses_test_stack ( void ) {
	static uint32_t area[64];
	uint8_t *base = ( ( uint8_t * ) area );

	/* Painted memory is untouched until something is written into it, and the measure stops at the first written word */
	memset ( area, 0, sizeof ( area ) );
	rbd_stack_fill ( ( base + 16 ), ( base + 240 ) );
	ok ( rbd_stack_untouched ( ( base + 16 ), ( base + 240 ) ) == 224 );
	ok ( rbd_stack_untouched ( base, ( base + 240 ) ) == 0 );	/* what was not painted is not pattern */
	ok ( area[3] == 0 );
	ok ( area[4] != 0 );
	ok ( area[59] != 0 );
	ok ( area[60] == 0 );
	area[40] = 0x12345678;
	ok ( rbd_stack_untouched ( ( base + 16 ), ( base + 240 ) ) == ( ( 40 * 4 ) - 16 ) );
	area[4] = 1;
	ok ( rbd_stack_untouched ( ( base + 16 ), ( base + 240 ) ) == 0 );

	/* Ends that are not word aligned: the painted part is the words inside */
	memset ( area, 0, sizeof ( area ) );
	rbd_stack_fill ( ( base + 17 ), ( base + 63 ) );
	ok ( area[4] == 0 );
	ok ( area[5] != 0 );
	ok ( area[14] != 0 );
	ok ( area[15] == 0 );
	ok ( rbd_stack_untouched ( ( base + 17 ), ( base + 63 ) ) == 40 );

	/* Nothing to paint */
	memset ( area, 0, sizeof ( area ) );
	rbd_stack_fill ( ( base + 32 ), ( base + 32 ) );
	rbd_stack_fill ( ( base + 40 ), ( base + 36 ) );
	ok ( area[8] == 0 );
	ok ( area[9] == 0 );
	ok ( rbd_stack_untouched ( ( base + 32 ), ( base + 32 ) ) == 0 );
}

#if RBD_CORE_STACK_BYTES

/** What the probe function of the stack test saw */
struct ses_probe {
	void *frame;
	unsigned long result;
};

/** A function that uses a kilobyte of stack and says where its frame is */
static void ses_probe_fn ( void *arg ) {
	struct ses_probe *probe = arg;
	volatile uint8_t buf[1024];
	unsigned int i;

	for ( i = 0 ; i < sizeof ( buf ) ; i++ )
		buf[i] = ( uint8_t ) i;
	probe->frame = __builtin_frame_address ( 0 );
	probe->result = ( buf[1] + buf[1023] + 1000 );
}

/** A function that destroys the registers that a call is allowed to destroy */
static void ses_clobber_fn ( void *arg ) {
	struct ses_probe *probe = arg;

	probe->frame = __builtin_frame_address ( 0 );
	probe->result = 0x1234;
	__asm__ __volatile__ ( "xorl %%ecx, %%ecx\n\t"
			       "xorl %%edx, %%edx\n\t"
			       : : : "ecx", "edx", "cc" );
}

#endif /* RBD_CORE_STACK_BYTES */

static void ses_test_core_stack ( void ) {
	struct ses_fix *f = &ses_fix;

#if RBD_CORE_STACK_BYTES
	static uint32_t region[2048];
	struct ses_probe probe;
	uint8_t *low = ( ( uint8_t * ) region );
	uint8_t *high = ( low + sizeof ( region ) );
	size_t untouched;
	unsigned int i;
	void *here = __builtin_frame_address ( 0 );

	/* A function called on another stack runs there, uses it from the top, and comes back to the old one */
	memset ( &probe, 0, sizeof ( probe ) );
	rbd_stack_fill ( low, high );
	rbd_call_on_stack ( high, ses_probe_fn, &probe );
	ok ( probe.result == ( 1 + 255 + 1000 ) );
	ok ( ( ( uint8_t * ) probe.frame ) >= low );
	ok ( ( ( uint8_t * ) probe.frame ) < high );
	untouched = rbd_stack_untouched ( low, high );
	ok ( untouched <= ( sizeof ( region ) - 1024 ) );
	ok ( untouched >= ( sizeof ( region ) - 1024 - 256 ) );
	ok ( __builtin_frame_address ( 0 ) == here );

	/* Twice, nested: the second call is on the same stack, below the first */
	memset ( &probe, 0, sizeof ( probe ) );
	rbd_call_on_stack ( high, ses_probe_fn, &probe );
	ok ( probe.result == ( 1 + 255 + 1000 ) );
	ok ( __builtin_frame_address ( 0 ) == here );

	/* A function that changes every register a call may change (%eax, %ecx, %edx), called again and again with the same stack: the
	 * stack is where the caller said it is each time (the caller may not assume that %ecx, which carries it, survived the call)
	 */
	for ( i = 0 ; i < 16 ; i++ ) {
		memset ( &probe, 0, sizeof ( probe ) );
		rbd_call_on_stack ( high, ses_clobber_fn, &probe );
		ok ( probe.result == 0x1234 );
		ok ( ( ( uint8_t * ) probe.frame ) >= low );
		ok ( ( ( uint8_t * ) probe.frame ) < high );
		ok ( __builtin_frame_address ( 0 ) == here );
	}

	/* The session runs the core's step there: the frame the fake core saw is inside the session's own stack, and it is measured */
	ses_open ( f, 1 );
	ok ( f->s->core_stack != NULL );
	ok ( f->s->core_stack_top == ( f->s->core_stack + RBD_CORE_STACK_BYTES ) );
	ok ( ( ( uintptr_t ) f->s->core_stack % 4096 ) == 0 );
	ok ( ( ( uint8_t * ) f->ft.run_frame ) >= ( ( uint8_t * ) f->s->core_stack ) );
	ok ( ( ( uint8_t * ) f->ft.run_frame ) < ( ( uint8_t * ) f->s->core_stack_top ) );
	ok ( rbd_core_stack_used ( f->s ) > 0 );
	ok ( rbd_core_stack_used ( f->s ) < 1024 );		/* the fake core's step is small */
	ses_close ( f );
#else
	/* No private stack on this platform: the core runs where it is called */
	ses_open ( f, 1 );
	ok ( f->s->core_stack == NULL );
	ok ( rbd_core_stack_used ( f->s ) == 0 );
	ses_close ( f );
#endif
}

static void ses_test_scrub ( void ) {
#if RBD_CORE_STACK_BYTES
	uint8_t *stack = malloc ( RBD_CORE_STACK_BYTES );
	size_t i;
	int zero = 1;

	/* The core's private stack is wiped when the session goes (what the core ran on may hold the temporaries of key handling) */
	ok ( stack != NULL );
	if ( ! stack )
		return;
	memset ( stack, 0xa5, RBD_CORE_STACK_BYTES );
	rbd_session_scrub_stack ( stack );
	for ( i = 0 ; i < RBD_CORE_STACK_BYTES ; i++ ) {
		if ( stack[i] )
			zero = 0;
	}
	ok ( zero );
	free ( stack );
#endif
	/* No stack (the platform has none): nothing to do */
	rbd_session_scrub_stack ( NULL );
	ok ( 1 );
}

static void ses_test_info ( void ) {
	struct ses_fix *f = &ses_fix;
	char *argv[] = { ( char * ) "rbd-info", NULL };

	ok ( strcmp ( rbd_info_command.name, "rbd-info" ) == 0 );

	/* No session, then one session with and without a cache (it prints names and numbers: never an address, a user or a key) */
	ok ( rbd_info_command.exec ( 1, argv ) == 0 );
	ses_open ( f, 1 );
	ok ( rbd_info_command.exec ( 1, argv ) == 0 );
	ok ( f->ft.n_stats >= 1 );
	ses_close ( f );
	f->heap = rbd_ft_heap();
	rbd_ft_init ( &f->ft );
	f->spec = rbd_ft_spec();
	f->spec->readahead_kib = 2048;
	ok ( rbd_ft_attach ( &f->ft, f->spec, &f->s, &f->path ) == 0 );
	ok ( rbd_info_command.exec ( 1, argv ) == 0 );
	ses_close ( f );
}

static void ses_test_run ( void ) {

	ses_test_create();
	ses_test_memory_plan();
	ses_test_step_failures();
	ses_test_identity();
	ses_test_schedule();
	ses_test_submit_gating();
	ses_test_open_timeout();
	ses_test_stall();
	ses_test_grace();
	ses_test_destroy_busy();
	ses_test_sources();
	ses_test_real_core();
	ses_test_stack();
	ses_test_core_stack();
	ses_test_scrub();
	ses_test_info();
}

/** RBD session self-test set */
struct self_test rbd_session_test __self_test = {
	.name = "rbd_session_test",
	.exec = ses_test_run,
};
