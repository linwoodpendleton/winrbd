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

/* Secure Boot: FORBIDDEN, like every file of the driver (docs/design/ipxe-driver.md, section 13). This file owns the core
 * instance, the cephx key and the process that runs them. It is only ever linked with the rest of the driver, none of which
 * has had the security review iPXE requires for PERMITTED.
 */
FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

/** @file
 *
 * RBD (Ceph) SAN protocol: the shared cluster session
 *
 * A session owns the memory of one wr_client, the client itself, the open image, the connection table and the one process
 * that runs the core (docs/design/ipxe-driver.md, sections 4, 5 and 11). It is reference counted and outlives the block device
 * that opened it: when the SAN layer reopens a failed path (sandev_reopen closes the block interface and opens the URI again)
 * the new device finds the session by its identity (monitors, user, pool, image, mode, ...), and the OSD map, the CRUSH map and
 * the tickets are still there. A session with no device is kept for RBD_SESSION_GRACE_MS and then destroyed.
 *
 * The memory is ONE umalloc() block: the core's arena, the core's bulk region and the readahead cache, in that order, each part
 * page aligned (EFI and BIOS hand out page aligned memory, but the Linux test platform does not, and the core wants 16 bytes, so
 * the block is taken one page larger and the parts are placed on the first page boundary inside it). The 4 MiB malloc() heap holds
 * only the small objects (this structure, devices, commands).
 *
 * The process.  One struct process per session, scheduled only when there is something to do: a socket event (the connection
 * table calls rbd_session_wake), a new request, a deadline of the core (a retry timer), a stall check. A pass (rbd_session_pump)
 * runs rounds of: wr_client_run, the core's connect and close actions, the connection table's receive and transmit service,
 * the core's events, the requests the core has finished, the image state, the stall rules, the block device's service.
 * This is the ONLY file that calls wr_client_run and the only one that pulls events and finished requests out of the core.
 * Nothing in the glue calls into the core from inside a call into the core: the core's own calls into the host are the leaf
 * callbacks of the host table, and a pump that is asked for from inside a pump only notes that there is more to do.
 *
 * Closing the path.  The session closes the paths of its devices (with an iPXE error code, rbd_rc()) when the image fails (open
 * timeout, blocklisted, header refresh failed...), when the core reports a fatal error, and when the cluster has been
 * unreachable (or the operations stalled) for RBD_STALL_CLOSE_MS while something waits. The SAN layer then reopens the URI and
 * finds this session again; an image that failed is reopened (wr_image_close ABANDON + wr_image_open), a session whose client
 * failed fatally is replaced.
 *
 * Cancel.  rbd_session_cancel() is synchronous: it returns only when the core has handed the request back, so that no buffer can
 * be touched after the SAN layer got it back. If the core cannot do that within RBD_CANCEL_ROUNDS rounds (a write whose copy does
 * not fit the zombie area waits for the cluster, which this loop does not service), the session is destroyed: the core is gone,
 * and nothing can write into, or read from, any buffer of the SAN layer any more. The path then fails and is reopened cold.
 *
 * Secrets.  The cephx key reaches this file in the caller's spec. It is copied into the core's arena by wr_client_create() and
 * the copy in the creation scratch is wiped at once. A key is kept in the session only when a device asked for handoff=key (the
 * table then carries it), and is wiped when the last such device lets go and when the session is destroyed. Sessions are told
 * apart by a SHA-256 fingerprint of the key, so that a changed rbd-key setting is not served by a session that authenticated
 * with the old one.
 *
 * Credit: the shape of the process / retry timer / reference counting follows iPXE's own protocols (net/tcp/iscsi.c,
 * net/aoe.c); no code of those files, of Linux libceph / rbd or of Ceph is used here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/umalloc.h>
#include <ipxe/crypto.h>
#include <ipxe/sha256.h>
#include "rbd_priv.h"
#include "rbd_session.h"
#include "rbd_block.h"
#include "rbd_efi.h"
#include "rbd_acpi.h"
#include "rbd_uri.h"

/* The diagnostics (the stack watermark and the "rbd-info" command) are in rbd_stack.c: nothing else refers to that object in a build
 * without the watermark, so say that it is wanted
 */
PROVIDE_REQUIRING_SYMBOL();
REQUIRE_OBJECT ( rbd_stack );

/** Page size for placing the parts of the memory block */
#define RBD_ALIGN 4096

/** The sessions */
LIST_HEAD ( rbd_sessions );

/******************************************************************************
 *
 * The core
 *
 ******************************************************************************
 */

/** The core's own functions */
const struct rbd_core_ops rbd_core_default_ops = {
	.mem_required = wr_client_mem_required,
	.create = wr_client_create,
	.destroy = wr_client_destroy,
	.run = wr_client_run,
	.next_event = wr_client_next_event,
	.next_done = wr_client_next_done,
	.client_state = wr_client_get_state,
	.last_error = wr_client_last_error,
	.stats = wr_client_get_stats,
	.osd_stats = wr_client_osd_stats,
	.image_open = wr_image_open,
	.image_close = wr_image_close,
	.image_state = wr_image_get_state,
	.image_error = wr_image_error,
	.image_info = wr_image_get_info,
	.submit = wr_image_submit,
	.cancel = wr_image_cancel,
};

/**
 * Fill in the core's configuration for the iPXE profile
 *
 * @v spec		Request specification
 * @v cfg		Configuration to fill in
 */
static void rbd_session_config ( const struct rbd_spec *spec,
				 wr_config *cfg ) {

	wr_config_profile_ipxe ( cfg );
	wr_config_enable_maps ( cfg, WR_MAPS_IPXE );
	wr_config_enable_osd ( cfg, WR_MAPS_IPXE );
	wr_config_enable_secure ( cfg, WR_MAPS_IPXE, spec->mode );
}

/**
 * Round a size up to the placement granularity
 *
 * @v len		Size
 * @ret len		Size rounded up
 */
static inline size_t rbd_round ( size_t len ) {

	return ( ( len + RBD_ALIGN - 1 ) & ~( ( size_t ) RBD_ALIGN - 1 ) );
}

/******************************************************************************
 *
 * Identity
 *
 ******************************************************************************
 */

/**
 * Copy a name into an identity field
 *
 * @v dest		Field
 * @v len		Size of the field
 * @v src		Name
 */
static void rbd_copy_name ( char *dest, size_t len, const char *src ) {
	size_t n = strnlen ( src, ( len - 1 ) );

	memcpy ( dest, src, n );
	dest[n] = '\0';
}

/**
 * Fingerprint a key
 *
 * @v key		Key
 * @v out		16 bytes of fingerprint
 * @ret rc		Return status code
 */
static int rbd_key_fingerprint ( const wr_key *key, uint8_t *out ) {
	static const char domain[] = "winrbd-session-key-v1";
	struct digest_algorithm *digest = &sha256_algorithm;
	size_t len = ( digest->ctxsize + digest->digestsize );
	uint8_t *ctx;
	uint8_t *sum;

	ctx = zalloc ( len );
	if ( ! ctx )
		return -ENOMEM;
	sum = ( ctx + digest->ctxsize );
	digest_init ( digest, ctx );
	digest_update ( digest, ctx, domain, sizeof ( domain ) );
	digest_update ( digest, ctx, &key->type, sizeof ( key->type ) );
	digest_update ( digest, ctx, &key->len, sizeof ( key->len ) );
	digest_update ( digest, ctx, key->secret, key->len );
	digest_final ( digest, ctx, sum );
	memcpy ( out, sum, 16 );
	rbd_uri_wipe ( ctx, len );
	free ( ctx );
	return 0;
}

/**
 * Build the identity of a request
 *
 * @v id		Identity to fill in
 * @v spec		Request specification
 * @ret rc		Return status code
 */
static int rbd_id_build ( struct rbd_session_id *id,
			  const struct rbd_spec *spec ) {
	unsigned int i;
	int rc;

	memset ( id, 0, sizeof ( *id ) );
	rbd_copy_name ( id->user, sizeof ( id->user ), spec->user );
	rbd_copy_name ( id->pool, sizeof ( id->pool ), spec->pool );
	rbd_copy_name ( id->image, sizeof ( id->image ), spec->image );
	id->n_mons = spec->n_mons;
	if ( id->n_mons > WR_MAX_MONS )
		id->n_mons = WR_MAX_MONS;
	for ( i = 0 ; i < id->n_mons ; i++ ) {
		id->mons[i].family = spec->mons[i].family;
		memcpy ( id->mons[i].ip, spec->mons[i].ip,
			 sizeof ( id->mons[i].ip ) );
		id->mons[i].port = spec->mons[i].port;
	}
	id->fsid_known = spec->fsid_known;
	if ( id->fsid_known )
		memcpy ( id->fsid, spec->fsid, sizeof ( id->fsid ) );
	id->mode = spec->mode;
	id->read_only = spec->read_only;
	id->readahead_kib = spec->readahead_kib;
	if ( ( rc = rbd_key_fingerprint ( &spec->key, id->key_fp ) ) != 0 )
		return rc;
	return 0;
}

/**
 * Compare two identities
 *
 * @v a			Identity
 * @v b			Identity
 * @ret same		The identities are the same
 */
static int rbd_id_same ( const struct rbd_session_id *a,
			 const struct rbd_session_id *b ) {
	unsigned int i;

	if ( ( a->n_mons != b->n_mons ) || ( a->fsid_known != b->fsid_known ) ||
	     ( a->mode != b->mode ) || ( a->read_only != b->read_only ) ||
	     ( a->readahead_kib != b->readahead_kib ) )
		return 0;
	if ( strcmp ( a->user, b->user ) || strcmp ( a->pool, b->pool ) ||
	     strcmp ( a->image, b->image ) )
		return 0;
	if ( memcmp ( a->key_fp, b->key_fp, sizeof ( a->key_fp ) ) )
		return 0;
	if ( a->fsid_known && memcmp ( a->fsid, b->fsid, sizeof ( a->fsid ) ) )
		return 0;
	for ( i = 0 ; i < a->n_mons ; i++ ) {
		if ( ( a->mons[i].family != b->mons[i].family ) ||
		     ( a->mons[i].port != b->mons[i].port ) ||
		     memcmp ( a->mons[i].ip, b->mons[i].ip,
			      sizeof ( a->mons[i].ip ) ) )
			return 0;
	}
	return 1;
}

/******************************************************************************
 *
 * Time and timers
 *
 ******************************************************************************
 */

/**
 * Get the time for the core
 *
 * @v session		Session
 * @v now		Clock to fill in
 */
void rbd_session_now ( struct rbd_session *session, wr_clock *now ) {

	if ( session->env.now ) {
		session->env.now ( session, now );
	} else {
		rbd_conn_now ( &session->conn, now );
	}
	session->last_now = now->mono_ms;
}

/**
 * Get the time at which a stall rule closes the path
 *
 * @v since		Start of the trouble (monotonic ms + 1), or 0
 * @ret when		Time at which the rule fires, or WR_DEADLINE_NONE
 */
static uint64_t rbd_stall_deadline ( uint64_t since ) {

	if ( ! since )
		return WR_DEADLINE_NONE;
	return ( ( since - 1 ) + RBD_STALL_CLOSE_MS );
}

/**
 * Check whether the stall rules can act now
 *
 * @v session		Session
 * @ret armed		The stall rules apply
 *
 * They apply only to a path that exists and is not already failed, and, once the image is open, only while a command waits (an idle
 * path is allowed to find the cluster gone: the next command finds out). The same test arms the wake-up timer and decides whether
 * a pass closes the path: a deadline that the rules would ignore must not keep the process on the run queue.
 */
static int rbd_session_stall_armed ( const struct rbd_session *session ) {

	if ( ( ! session->ndev ) || ( session->state == RBD_SESSION_FAILED ) )
		return 0;
	if ( ( session->state == RBD_SESSION_OPEN ) &&
	     list_empty ( &session->cmds ) )
		return 0;
	return 1;
}

/**
 * Schedule the next pass of the process
 *
 * @v session		Session
 * @v stay		Stay on the run queue: there is work that no event will announce
 */
static void rbd_session_schedule ( struct rbd_session *session, int stay ) {
	uint64_t deadline;
	uint64_t when;
	uint64_t delay;

	/* Work that cannot wait: run at once */
	if ( stay || session->dirty || session->more_work ) {
		process_add ( &session->proc );
		return;
	}

	/* Next deadline of the core, and of the stall rules (only while they can act) */
	deadline = session->next_deadline;
	if ( rbd_session_stall_armed ( session ) ) {
		when = rbd_stall_deadline ( session->trouble_since );
		if ( when < deadline )
			deadline = when;
		when = rbd_stall_deadline ( session->stall_since );
		if ( when < deadline )
			deadline = when;
	}
	if ( deadline == WR_DEADLINE_NONE ) {
		stop_timer ( &session->timer );
		return;
	}
	if ( deadline <= session->last_now ) {
		process_add ( &session->proc );
		return;
	}
	delay = ( deadline - session->last_now );
	if ( delay > RBD_CONN_TIMEOUT_MAX_MS )
		delay = RBD_CONN_TIMEOUT_MAX_MS;
	start_timer_fixed ( &session->timer,
			    rbd_conn_ms_to_ticks ( ( uint32_t ) delay ) );
}

/**
 * Handle the wake-up timer
 *
 * @v timer		Retry timer
 * @v over		Failure indicator (unused)
 */
void rbd_session_timer_expired ( struct retry_timer *timer, int over __unused ) {
	struct rbd_session *session =
		container_of ( timer, struct rbd_session, timer );

	rbd_session_wake ( session );
}

/**
 * Wake the session's process
 *
 * @v session		Session
 */
void rbd_session_wake ( struct rbd_session *session ) {

	if ( session->state != RBD_SESSION_DEAD )
		process_add ( &session->proc );
}

/**
 * Wake the session's process (the connection table's wake function)
 *
 * @v ctx		Session
 */
static void rbd_session_wake_cb ( void *ctx ) {

	rbd_session_wake ( ctx );
}

/******************************************************************************
 *
 * Events, finished requests, image state
 *
 ******************************************************************************
 */

/**
 * Tell the readahead cache the size of the image (it forgets what it holds)
 *
 * @v session		Session
 * @v bytes		Usable size of the device in bytes (at least 1)
 */
static void rbd_session_ra_reset ( struct rbd_session *session,
				   uint64_t bytes ) {

	if ( session->ra && ( wr_ra_reset ( session->ra, bytes ) != WR_OK ) )
		DBGC ( session, "RBD %p readahead reset refused\n", session );
}

/**
 * Take a core event
 *
 * @v session		Session
 * @v ev		Event
 * @v mono		Monotonic time (ms)
 */
static void rbd_session_event ( struct rbd_session *session,
				const wr_event *ev, uint64_t mono ) {

	switch ( ev->kind ) {
	case WR_EV_MON_SESSION_UP:
		session->trouble_since = 0;
		session->trouble_status = 0;
		session->trouble_peer = 0;
		break;
	case WR_EV_AUTH_FAILED:
	case WR_EV_CLUSTER_UNREACHABLE:
		if ( ! session->trouble_since )
			session->trouble_since = ( mono + 1 );
		session->trouble_status = ev->err.status;
		session->trouble_peer = ev->err.peer_result;
		DBGC ( session, "RBD %p cluster trouble: %s\n", session,
		       wr_status_name ( ev->err.status ) );
		break;
	case WR_EV_IO_STALL:
		if ( ! session->stall_since )
			session->stall_since = ( mono + 1 );
		session->stall_status = ev->err.status;
		break;
	case WR_EV_IO_RESUME:
		session->stall_since = 0;
		break;
	case WR_EV_IMAGE:
		session->info_stale = 1;
		break;
	case WR_EV_FATAL:
		session->fail_status = ev->err.status;
		rbd_report_peer ( "cluster session", ev->err.status,
				  ev->err.peer_result, ev->err.a0 );
		rbd_session_fail ( session, rbd_rc_peer ( ev->err.status,
							  ev->err.peer_result ) );
		break;
	default:
		break;
	}
}

/**
 * Pull the events out of the core
 *
 * @v session		Session
 * @v mono		Monotonic time (ms)
 */
static void rbd_session_events ( struct rbd_session *session, uint64_t mono ) {
	wr_event ev;

	while ( session->client &&
		session->core->next_event ( session->client, &ev ) )
		rbd_session_event ( session, &ev, mono );
}

/**
 * Pull the finished requests out of the core
 *
 * @v session		Session
 */
static void rbd_session_collect ( struct rbd_session *session ) {
	wr_io_req *req;
	struct rbd_request *rq;

	while ( session->client &&
		( ( req = session->core->next_done ( session->client ) ) ) ) {
		rq = req->user;
		list_del ( &rq->list );
		INIT_LIST_HEAD ( &rq->list );
		rq->pending = 0;
		rq->done ( session, rq );
	}
}

/**
 * Take note of the image having been opened
 *
 * @v session		Session
 */
static void rbd_session_opened ( struct rbd_session *session ) {
	uint64_t blocks;

	if ( session->core->image_info ( session->image, &session->info ) != WR_OK ||
	     ( ( blocks = ( session->info.size_bytes / RBD_BLKSIZE ) ) == 0 ) ) {
		printf ( "rbd: open failed: the image is smaller than one block\n" );
		session->fail_status = WR_E_RANGE;
		rbd_session_fail ( session, -ENODEV );
		return;
	}
	session->blocks = blocks;
	session->info_stale = 0;
	rbd_session_ra_reset ( session, ( blocks * RBD_BLKSIZE ) );
	session->state = RBD_SESSION_OPEN;
	session->announced = 1;
	DBGC ( session, "RBD %p image open, %#llx blocks\n", session,
	       ( ( unsigned long long ) blocks ) );
	rbd_block_window_changed ( session );
}

/**
 * Take note of the image having been resized
 *
 * @v session		Session
 */
static void rbd_session_resized ( struct rbd_session *session ) {
	wr_image_info *info = &session->info;
	uint64_t blocks;

	session->info_stale = 0;
	if ( session->core->image_info ( session->image, info ) != WR_OK )
		return;
	blocks = ( info->size_bytes / RBD_BLKSIZE );
	if ( ( blocks == 0 ) || ( blocks == session->blocks ) )
		return;
	session->blocks = blocks;
	rbd_session_ra_reset ( session, ( blocks * RBD_BLKSIZE ) );
	DBGC ( session, "RBD %p image resized to %#llx blocks\n", session,
	       ( ( unsigned long long ) blocks ) );
}

/**
 * Check the state of the image
 *
 * @v session		Session
 */
static void rbd_session_check_image ( struct rbd_session *session ) {
	const wr_errinfo *err;
	wr_status status;
	int32_t peer;
	uint64_t detail;

	if ( ( ! session->image ) || ( session->state == RBD_SESSION_FAILED ) )
		return;
	switch ( session->core->image_state ( session->image ) ) {
	case WR_IMG_OPEN:
		if ( session->state != RBD_SESSION_OPEN )
			rbd_session_opened ( session );
		else if ( session->info_stale )
			rbd_session_resized ( session );
		return;
	case WR_IMG_OPENING:
		return;
	default:
		break;
	}

	/* Failed, closing or gone: say why, once, and close the paths. An open that timed out while the cluster was refusing us or
	 * was not there says what the cluster did, not that time ran out.
	 */
	err = session->core->image_error ( session->image );
	status = ( err ? err->status : WR_OK );
	peer = ( err ? err->peer_result : 0 );
	detail = ( err ? err->a0 : 0 );
	if ( status == WR_OK )
		status = WR_E_RBD_CLOSED;
	if ( ( status == WR_E_TIMEOUT ) && session->trouble_status ) {
		status = session->trouble_status;
		peer = session->trouble_peer;
		detail = 0;
	}
	session->fail_status = status;
	rbd_report_peer ( ( session->announced ? "image" : "open" ), status,
			  peer, detail );
	rbd_session_fail ( session, rbd_rc_peer ( status, peer ) );
}

/**
 * Apply the stall rules: close the paths when the cluster has been gone for too long while something waits
 *
 * @v session		Session
 * @v mono		Monotonic time (ms)
 */
static void rbd_session_check_stall ( struct rbd_session *session,
				      uint64_t mono ) {
	wr_status status;
	int32_t peer;
	int rc;

	if ( ! rbd_session_stall_armed ( session ) )
		return;

	/* The monitors are not answering (or refuse us) */
	if ( mono >= rbd_stall_deadline ( session->trouble_since ) ) {
		status = session->trouble_status;
		peer = session->trouble_peer;
		session->trouble_since = ( mono + 1 );
		goto close;
	}

	/* The operations are not being answered */
	if ( mono >= rbd_stall_deadline ( session->stall_since ) ) {
		status = session->stall_status;
		peer = 0;
		session->stall_since = ( mono + 1 );
		goto close;
	}
	return;

 close:
	rc = ( status ? rbd_rc_peer ( status, peer ) : -ENOTCONN );
	session->n_stall_closes++;
	printf ( "rbd: the cluster has not answered for %d seconds, closing "
		 "the path: %s (%s)\n", ( int ) ( RBD_STALL_CLOSE_MS / 1000 ),
		 wr_strerror ( status ), wr_status_name ( status ) );
	rbd_heap_note ( "closing the path" );
	rbd_block_fail ( session, rc );
}

/******************************************************************************
 *
 * The pump
 *
 ******************************************************************************
 */

/** The round is to be run again at once */
#define RBD_ROUND_AGAIN 0x01
/** The process stays on the run queue (work that no event announces is left) */
#define RBD_ROUND_STAY 0x02

/** What the core's run step is called with, and what it answers (it runs on the core's own stack where there is one) */
struct rbd_run_args {
	/** Session */
	struct rbd_session *session;
	/** Time */
	const wr_clock *now;
	/** Answer */
	wr_run_result res;
};

/**
 * Run the core's run step (on the core's own stack where there is one)
 *
 * @v arg		Arguments
 */
static void rbd_run_thunk ( void *arg ) {
	struct rbd_run_args *args = arg;
	struct rbd_session *session = args->session;

	args->res = session->core->run ( session->client, args->now, 0 );
}

/**
 * Advance the core
 *
 * @v session		Session
 * @v now		Time
 * @ret res		What the core says
 */
static wr_run_result rbd_session_run ( struct rbd_session *session,
				       const wr_clock *now ) {
	struct rbd_run_args args;

	args.session = session;
	args.now = now;
	if ( RBD_CORE_STACK_BYTES && ! session->core_stack_top )
		rbd_run_thunk ( &args );
	else
		rbd_call_on_stack ( session->core_stack_top, rbd_run_thunk,
				    &args );
	return args.res;
}

/**
 * Run one round
 *
 * @v session		Session
 * @ret flags		RBD_ROUND_* flags
 */
static int rbd_session_round ( struct rbd_session *session ) {
	wr_run_result res;
	wr_clock now;
	unsigned int count;
	int work;
	int flags = 0;

	/* Advance the core */
	rbd_session_now ( session, &now );
	DBGC2 ( session, "RBD %p round at %#llx ms\n", session,
		( ( long long ) now.mono_ms ) );
	res = rbd_session_run ( session, &now );
	session->next_deadline = res.next_deadline_ms;
	session->more_work = res.more_work;

	/* Carry out its connect and close actions */
	do {
		count = rbd_conn_drain ( &session->conn );
	} while ( ( count >= RBD_CONN_ACTION_MAX ) && session->client );

	/* Receive backlog into the core, core output to the sockets */
	work = rbd_conn_service ( &session->conn );
	DBGC2 ( session, "RBD %p ran: more %d, deadline %#llx, work %#x, "
		"actions %d\n", session, res.more_work,
		( ( long long ) res.next_deadline_ms ), work, count );

	/* What the core says, what it has finished, what became of the image */
	rbd_session_events ( session, now.mono_ms );
	if ( ! session->client )
		return 0;
	rbd_session_collect ( session );
	if ( ! session->client )
		return 0;
	rbd_session_check_image ( session );
	if ( ! session->client )
		return 0;
	rbd_session_check_stall ( session, now.mono_ms );
	if ( ! session->client )
		return 0;

	/* The block device: finish commands, ask parked commands again, start prefetches */
	rbd_block_service ( session );
	if ( ! session->client )
		return 0;

	if ( res.more_work || ( work & RBD_CONN_PROGRESS ) )
		flags |= RBD_ROUND_AGAIN;
	if ( work & RBD_CONN_MORE )
		flags |= RBD_ROUND_STAY;
	return flags;
}

/**
 * Pump the session: run the core and move everything it has to say
 *
 * @v session		Session
 *
 * Called by the process, and by the block device after it has submitted a request (a submit does no I/O). Not re-entrant: called
 * from inside a pump (a completion that starts the next command), it only notes that the pump is to go round again.
 */
void rbd_session_pump ( struct rbd_session *session ) {
	unsigned int rounds;
	int flags = 0;

	if ( ! session->client )
		return;
	if ( session->in_pump ) {
		session->dirty = 1;
		return;
	}
	ref_get ( &session->refcnt );
	session->in_pump = 1;
	session->n_pumps++;
	for ( rounds = 0 ; rounds < RBD_PUMP_ROUNDS ; rounds++ ) {
		session->dirty = 0;
		flags = rbd_session_round ( session );
		if ( ! session->client )
			break;
		if ( ! ( flags & RBD_ROUND_AGAIN ) && ! session->dirty )
			break;
	}
	session->in_pump = 0;
	if ( session->client ) {
		rbd_stack_note ( session );
		rbd_counters_note ( session );
		rbd_session_schedule ( session,
				       ( flags & ( RBD_ROUND_AGAIN |
						   RBD_ROUND_STAY ) ) );
	}
	ref_put ( &session->refcnt );
}

/**
 * Single-step the session's process
 *
 * @v session		Session
 */
static void rbd_session_step ( struct rbd_session *session ) {

	rbd_session_pump ( session );
}

/** Session process descriptor */
static struct process_descriptor rbd_session_proc_desc =
	PROC_DESC_ONCE ( struct rbd_session, proc, rbd_session_step );

/******************************************************************************
 *
 * Requests
 *
 ******************************************************************************
 */

/**
 * Submit a request to the core
 *
 * @v session		Session
 * @v rq		Request (the caller has filled in req.kind, offset, length, buf, timeout_ms and done)
 * @ret rc		Return status code
 *
 * Does no I/O: the caller pumps the session afterwards.
 */
int rbd_session_submit ( struct rbd_session *session,
			 struct rbd_request *rq ) {
	wr_status st;

	if ( ( ! session->client ) || ( ! session->image ) ||
	     ( session->state != RBD_SESSION_OPEN ) )
		return -ENOTCONN;
	rq->req.user = rq;
	rq->req.status = WR_OK;
	rq->req.reserved = 0;
	memset ( rq->req.priv, 0, sizeof ( rq->req.priv ) );
	if ( ( st = session->core->submit ( session->image,
					    &rq->req ) ) != WR_OK )
		return rbd_rc ( st );
	rq->pending = 1;
	list_add_tail ( &rq->list, &session->reqs );
	return 0;
}

/**
 * Cancel a request and wait until the core has handed it back
 *
 * @v session		Session
 * @v rq		Request
 *
 * Synchronous (docs/design/ipxe-driver.md, section 4): when this returns the core holds no reference to the request or to its
 * buffer. The finished request is delivered to its done() like any other, so the caller has marked its own state first (the
 * done() of a command that is closing does nothing).
 */
void rbd_session_cancel ( struct rbd_session *session,
			  struct rbd_request *rq ) {
	wr_clock now;
	unsigned int round;

	if ( ! rq->pending )
		return;
	session->n_cancels++;
	DBGC ( session, "RBD %p cancels request %p\n", session, rq );
	if ( ! session->client ) {
		rq->pending = 0;
		list_del ( &rq->list );
		INIT_LIST_HEAD ( &rq->list );
		return;
	}

	/* WR_OK: finished at once, waiting in the core's done queue. WR_E_STATE: it is there already. WR_E_BUSY: the core retries the
	 * cancel on every run. Either way the loop below pulls finished requests, and runs the core while this one is not back. A session
	 * with no image (a failed reopen) has nothing to cancel against, but the core may still hold the request (an image that was closed
	 * with a reply landing in a buffer finishes the request when it has reset the connection): the loop waits for it all the same,
	 * so that the buffer is never given back while the core can write into it.
	 */
	if ( session->image )
		( void ) session->core->cancel ( session->image, &rq->req );
	for ( round = 0 ; ; round++ ) {
		rbd_session_collect ( session );
		if ( ( ! session->client ) || ( ! rq->pending ) )
			break;
		if ( round >= RBD_CANCEL_ROUNDS ) {
			printf ( "rbd: a cancelled request did not finish; "
				 "closing the cluster session\n" );
			session->fail_status = WR_E_BUSY;
			rbd_session_destroy ( session );
			break;
		}
		/* No network service here: nothing is received into the core while a buffer is being taken back */
		rbd_session_now ( session, &now );
		( void ) rbd_session_run ( session, &now );
		while ( session->client &&
			( rbd_conn_drain ( &session->conn ) >=
			  RBD_CONN_ACTION_MAX ) ) {
			/* more actions */
		}
		if ( ! session->client )
			break;
	}
	if ( round > session->n_cancel_rounds_max )
		session->n_cancel_rounds_max = round;
}

/******************************************************************************
 *
 * Creation and destruction
 *
 ******************************************************************************
 */

/**
 * Free a session
 *
 * @v refcnt		Reference count
 */
static void rbd_session_free ( struct refcnt *refcnt ) {
	struct rbd_session *session =
		container_of ( refcnt, struct rbd_session, refcnt );

	assert ( session->mem == NULL );
	assert ( session->client == NULL );
	assert ( list_empty ( &session->devices ) );
	assert ( list_empty ( &session->cmds ) );
	free ( session->pf );
	free ( session->uri );
	rbd_uri_wipe ( &session->key, sizeof ( session->key ) );
	rbd_uri_wipe ( &session->work, sizeof ( session->work ) );
	free ( session );
}

/**
 * Wipe the core's private stack
 *
 * @v stack		The stack (RBD_CORE_STACK_BYTES bytes), or NULL when the platform has none
 *
 * The core wipes its own working memory (wr_client_destroy), but its temporaries live on the stack it ran on, and that memory
 * goes back to the system with the rest of the session's block: the key schedule of a connection, a nonce, a decrypted ticket may
 * have been there. The stack is a small part of the block, so it is wiped; the rest (maps, the readahead cache) holds nothing
 * secret.
 */
void rbd_session_scrub_stack ( void *stack ) {

	if ( stack )
		rbd_uri_wipe ( stack, RBD_CORE_STACK_BYTES );
}

/**
 * Destroy a session: stop everything, close every socket, wipe and free the memory
 *
 * @v session		Session
 *
 * The structure itself lives until the last reference is gone (devices that are still being closed, commands, timers that are
 * running down). After this the session has no client: nothing can touch a buffer of the SAN layer or send a byte. Devices that
 * are still attached are failed.
 */
void rbd_session_destroy ( struct rbd_session *session ) {
	wr_client *client;
	void *stack;
	struct rbd_request *rq;
	struct rbd_request *tmp;
	int rc;

	if ( session->state == RBD_SESSION_DEAD )
		return;
	ref_get ( &session->refcnt );
	rc = ( session->fail_rc ? session->fail_rc : -ECANCELED );
	DBGC ( session, "RBD %p destroyed\n", session );
	rbd_stack_report();

	/* Nothing starts from here on */
	session->state = RBD_SESSION_DEAD;
	list_del ( &session->list );
	INIT_LIST_HEAD ( &session->list );
	stop_timer ( &session->timer );
	stop_timer ( &session->grace );
	process_del ( &session->proc );

	/* No more sockets, then no more core: it can no longer touch any buffer */
	rbd_conn_shutdown ( &session->conn );
	client = session->client;
	stack = session->core_stack;
	session->client = NULL;
	session->image = NULL;
	session->ra = NULL;
	session->core_stack = NULL;
	session->core_stack_top = NULL;
	if ( client )
		session->core->destroy ( client );
	rbd_session_scrub_stack ( stack );
	list_for_each_entry_safe ( rq, tmp, &session->reqs, list ) {
		list_del ( &rq->list );
		INIT_LIST_HEAD ( &rq->list );
		rq->pending = 0;
	}
	if ( session->mem ) {
		ufree ( session->mem );
		session->mem = NULL;
		session->base = NULL;
	}
	rbd_uri_wipe ( &session->key, sizeof ( session->key ) );
	session->key_kept = 0;

	/* The devices and commands that are left are told why */
	rbd_block_teardown ( session, rc );

	/* The registry's reference, and ours */
	ref_put ( &session->refcnt );
	ref_put ( &session->refcnt );
}

/**
 * Handle the grace period ending
 *
 * @v timer		Retry timer
 * @v over		Failure indicator (unused)
 */
void rbd_session_grace_expired ( struct retry_timer *timer, int over __unused ) {
	struct rbd_session *session =
		container_of ( timer, struct rbd_session, grace );

	if ( session->ndev || ( ! list_empty ( &session->cmds ) ) ) {
		start_timer_fixed ( &session->grace,
				    rbd_conn_ms_to_ticks ( RBD_SESSION_GRACE_MS ) );
		return;
	}
	DBGC ( session, "RBD %p idle for the grace period\n", session );
	rbd_session_destroy ( session );
}

/**
 * Open the image of a session
 *
 * @v session		Session
 * @v spec		Request specification
 * @ret rc		Return status code
 */
static int rbd_session_open_image ( struct rbd_session *session,
				    const struct rbd_spec *spec ) {
	wr_image_params params;
	wr_status st;

	memset ( &params, 0, sizeof ( params ) );
	params.size = sizeof ( params );
	params.pool = session->id.pool;
	params.name = session->id.image;
	params.snap_id = WR_SNAP_HEAD;
	params.open_timeout_ms = spec->open_timeout_ms;
	params.want_write = ( spec->read_only ? 0 : 1 );
	session->image = NULL;
	if ( ( st = session->core->image_open ( session->client, &params,
						&session->image ) ) != WR_OK ) {
		session->image = NULL;
		rbd_report ( "open the image", st );
		return rbd_rc ( st );
	}
	session->state = RBD_SESSION_OPENING;
	session->announced = 0;
	session->info_stale = 0;
	session->fail_rc = 0;
	session->fail_status = WR_OK;
	session->trouble_since = 0;
	session->trouble_status = 0;
	session->trouble_peer = 0;
	session->stall_since = 0;
	return 0;
}

/**
 * Plan the memory, take it, and create the client in it
 *
 * @v session		Session
 * @v spec		Request specification
 * @ret rc		Return status code
 */
static int rbd_session_create_client ( struct rbd_session *session,
				       const struct rbd_spec *spec ) {
	struct rbd_create_work *work = &session->work;
	const struct rbd_core_ops *core = session->core;
	wr_status st;
	size_t ra_need;
	size_t total;
	unsigned int i;

	/* Plan the memory: arena and bulk from the core, the cache from the readahead module */
	rbd_session_config ( spec, &work->cfg );
	if ( ( st = core->mem_required ( &work->cfg, &work->req ) ) != WR_OK ) {
		rbd_report ( "plan memory", st );
		return rbd_rc ( st );
	}
	session->arena_len = rbd_round ( work->req.arena );
	session->bulk_len = rbd_round ( work->req.bulk );
	session->ra_len = 0;
	if ( spec->readahead_kib ) {
		if ( ( ( st = wr_ra_cfg_from_kib ( &work->ra, 1,
						   spec->readahead_kib,
						   0 ) ) != WR_OK ) ||
		     ( ( work->ra.max_reqs = work->cfg.max_reqs ),
		       ( ( st = wr_ra_mem_required ( &work->ra,
						     &ra_need ) ) != WR_OK ) ) ) {
			rbd_report ( "plan the readahead cache", st );
			return rbd_rc ( st );
		}
		session->ra_len = rbd_round ( ra_need );
	}
	total = ( session->arena_len + session->bulk_len + session->ra_len +
		  RBD_CORE_STACK_BYTES );
	DBGC ( session, "RBD %p needs %zd + %zd + %zd + %d bytes\n", session,
	       session->arena_len, session->bulk_len, session->ra_len,
	       RBD_CORE_STACK_BYTES );

	/* One block: arena first, bulk behind it, the cache behind that, each on a page boundary */
	session->mem = umalloc ( total + RBD_ALIGN );
	if ( ! session->mem ) {
		printf ( "rbd: open failed: out of memory (%zd bytes of "
			 "extended memory wanted)\n", ( total + RBD_ALIGN ) );
		return -ENOMEM;
	}
	session->base = ( ( void * ) ( ( ( ( unsigned long ) session->mem ) +
					 RBD_ALIGN - 1 ) &
				       ~( ( unsigned long ) RBD_ALIGN - 1 ) ) );
	session->mem_len = total;
	if ( RBD_CORE_STACK_BYTES ) {
		session->core_stack = ( session->base + session->arena_len +
					session->bulk_len + session->ra_len );
		session->core_stack_top = ( session->core_stack +
					    RBD_CORE_STACK_BYTES );
		rbd_stack_fill ( session->core_stack, session->core_stack_top );
	}

	/* Describe the cluster, and create the client. The key is in the scratch only until the core has copied it. */
	rbd_conn_host_ops ( &session->conn, &work->host );
	rbd_copy_name ( work->cluster.user, sizeof ( work->cluster.user ),
			spec->user );
	work->cluster.key = spec->key;
	work->cluster.n_mons = session->id.n_mons;
	for ( i = 0 ; i < session->id.n_mons ; i++ )
		work->cluster.mons[i] = spec->mons[i];
	work->cluster.fsid_known = spec->fsid_known;
	if ( spec->fsid_known )
		memcpy ( work->cluster.fsid, spec->fsid,
			 sizeof ( work->cluster.fsid ) );
	st = core->create ( &work->cfg, &work->host, &work->cluster,
			    ( wr_mem_region ) { session->base,
						session->arena_len },
			    ( wr_mem_region ) { ( session->base +
						  session->arena_len ),
						session->bulk_len },
			    &session->client );
	rbd_uri_wipe ( &work->cluster, sizeof ( work->cluster ) );
	if ( st != WR_OK ) {
		session->client = NULL;
		rbd_report ( "create the client", st );
		return rbd_rc ( st );
	}
	rbd_conn_attach ( &session->conn, session->client );

	/* The cache, empty (image size 1: nothing can be read from it until the image is open) */
	if ( session->ra_len ) {
		st = wr_ra_init ( &work->ra,
				  ( wr_mem_region ) {
					  ( session->base + session->arena_len +
					    session->bulk_len ),
					  session->ra_len },
				  &session->ra );
		if ( st != WR_OK ) {
			session->ra = NULL;
			rbd_report ( "set up the readahead cache", st );
			return rbd_rc ( st );
		}
		session->n_pf = work->ra.lines;
		session->pf = zalloc ( session->n_pf * sizeof ( session->pf[0] ) );
		if ( ! session->pf ) {
			session->n_pf = 0;
			session->ra = NULL;
			return -ENOMEM;
		}
	}
	return 0;
}

/**
 * Create a session
 *
 * @v env		Environment (NULL entries: production)
 * @v spec		Request specification
 * @ret session		Session (the caller's reference; the registry holds its own), or NULL
 * @ret rc		Return status code
 */
static int rbd_session_create ( const struct rbd_session_env *env,
				const struct rbd_spec *spec,
				struct rbd_session **session ) {
	struct rbd_session *s;
	int rc;

	*session = NULL;
	s = zalloc ( sizeof ( *s ) );
	if ( ! s ) {
		printf ( "rbd: open failed: out of memory\n" );
		return -ENOMEM;
	}
	ref_init ( &s->refcnt, rbd_session_free );
	INIT_LIST_HEAD ( &s->list );
	INIT_LIST_HEAD ( &s->devices );
	INIT_LIST_HEAD ( &s->cmds );
	INIT_LIST_HEAD ( &s->reqs );
	s->env.core = ( ( env && env->core ) ? env->core :
			&rbd_core_default_ops );
	s->env.conn = ( env ? env->conn : NULL );
	s->env.now = ( env ? env->now : NULL );
	s->core = s->env.core;
	s->state = RBD_SESSION_OPENING;
	s->next_deadline = WR_DEADLINE_NONE;
	rbd_conn_init ( &s->conn, &s->refcnt, rbd_session_wake_cb, s );
	if ( s->env.conn )
		s->conn.ops = s->env.conn;
	timer_init ( &s->timer, rbd_session_timer_expired, &s->refcnt );
	timer_init ( &s->grace, rbd_session_grace_expired, &s->refcnt );
	process_init_stopped ( &s->proc, &rbd_session_proc_desc, &s->refcnt );

	if ( ( rc = rbd_id_build ( &s->id, spec ) ) != 0 )
		goto err;
	if ( ( rc = rbd_session_create_client ( s, spec ) ) != 0 )
		goto err;
	if ( ( rc = rbd_session_open_image ( s, spec ) ) != 0 )
		goto err;

	/* Registered; unused until a device attaches, so the grace period starts now */
	list_add ( &s->list, &rbd_sessions );
	start_timer_fixed ( &s->grace,
			    rbd_conn_ms_to_ticks ( RBD_SESSION_GRACE_MS ) );
	rbd_session_wake ( s );
	ref_get ( &s->refcnt );
	*session = s;
	return 0;

 err:
	/* Never registered: take it down (this drops the registry's reference, the only one there is) */
	rbd_session_destroy ( s );
	return rc;
}

/**
 * Check whether a session can serve a new device
 *
 * @v session		Session
 * @ret usable		Session is usable
 */
int rbd_session_usable ( const struct rbd_session *session ) {

	if ( ( session->state == RBD_SESSION_DEAD ) || ( ! session->client ) )
		return 0;
	return ( session->core->client_state ( session->client ) !=
		 WR_CS_FAILED );
}

/**
 * Reopen the image of a session if it has failed
 *
 * @v session		Session
 * @v spec		Request specification
 * @ret rc		Return status code
 */
static int rbd_session_reopen ( struct rbd_session *session,
				const struct rbd_spec *spec ) {
	wr_image_state state;

	state = ( session->image ? session->core->image_state ( session->image ) :
		  WR_IMG_FREE );
	if ( ( session->state != RBD_SESSION_FAILED ) &&
	     ( state != WR_IMG_FAILED ) && ( state != WR_IMG_CLOSING ) &&
	     ( state != WR_IMG_FREE ) )
		return 0;

	/* The old image goes (in-flight requests were completed when the path failed); the cache forgets its contents */
	DBGC ( session, "RBD %p reopens its image\n", session );
	if ( session->image ) {
		( void ) session->core->image_close ( session->image,
						      WR_CLOSE_ABANDON );
		session->image = NULL;
	}
	rbd_session_ra_reset ( session, RBD_BLKSIZE );
	session->blocks = 0;
	session->n_reopens++;
	rbd_session_wake ( session );
	return rbd_session_open_image ( session, spec );
}

/**
 * Open (or find) the session for a request
 *
 * @v env		Environment (NULL: production)
 * @v spec		Request specification
 * @ret session		Session (reference held by the caller)
 * @ret rc		Return status code
 */
int rbd_session_open_with ( const struct rbd_session_env *env,
			    const struct rbd_spec *spec,
			    struct rbd_session **session ) {
	struct rbd_session_id *id;
	struct rbd_session *s;
	struct rbd_session *tmp;
	int rc;

	*session = NULL;
	rbd_stack_paint();

	/* A session with this identity: use it, unless its client is gone for good (the identity is 650 bytes: heap, not stack) */
	id = zalloc ( sizeof ( *id ) );
	if ( ! id )
		return -ENOMEM;
	if ( ( rc = rbd_id_build ( id, spec ) ) != 0 )
		goto out;
	list_for_each_entry_safe ( s, tmp, &rbd_sessions, list ) {
		if ( ! rbd_id_same ( id, &s->id ) )
			continue;
		if ( ! rbd_session_usable ( s ) ) {
			if ( ( ! s->ndev ) && list_empty ( &s->cmds ) )
				rbd_session_destroy ( s );
			continue;
		}
		if ( ( rc = rbd_session_reopen ( s, spec ) ) != 0 ) {
			if ( ( ! s->ndev ) && list_empty ( &s->cmds ) )
				rbd_session_destroy ( s );
			goto out;
		}
		DBGC ( s, "RBD %p found by identity\n", s );
		*session = rbd_session_get ( s );
		rbd_session_wake ( s );
		rc = 0;
		goto out;
	}

	/* None: create one */
	rc = rbd_session_create ( env, spec, session );

 out:
	rbd_uri_wipe ( id, sizeof ( *id ) );	/* the fingerprint of the key is no use to anyone else */
	free ( id );
	return rc;
}

/**
 * Open (or find) the session for a request
 *
 * @v spec		Request specification
 * @ret session		Session (reference held by the caller)
 * @ret rc		Return status code
 */
int rbd_session_open ( const struct rbd_spec *spec,
		       struct rbd_session **session ) {

	return rbd_session_open_with ( NULL, spec, session );
}

/**
 * Get a reference to a session
 *
 * @v session		Session
 * @ret session		Session
 */
struct rbd_session * rbd_session_get ( struct rbd_session *session ) {

	ref_get ( &session->refcnt );
	return session;
}

/**
 * Drop a reference to a session
 *
 * @v session		Session
 */
void rbd_session_put ( struct rbd_session *session ) {

	ref_put ( &session->refcnt );
}

/**
 * Fail a session: remember why, close the paths of its devices
 *
 * @v session		Session
 * @v rc		Return status code (an iPXE error code)
 *
 * The session stays in the registry: the next open of the same identity reopens the image (or replaces a client that failed for
 * good) and costs no cold start of the monitor session.
 */
void rbd_session_fail ( struct rbd_session *session, int rc ) {

	if ( ( session->state == RBD_SESSION_DEAD ) ||
	     ( session->state == RBD_SESSION_FAILED ) )
		return;
	session->state = RBD_SESSION_FAILED;
	session->fail_rc = rc;
	rbd_block_fail ( session, rc );
}

/******************************************************************************
 *
 * Devices
 *
 ******************************************************************************
 */

/**
 * Attach a device to a session
 *
 * @v session		Session
 * @v rbd		Device (takes a reference on the session)
 * @v spec		Request specification
 */
void rbd_session_attach ( struct rbd_session *session, struct rbd_device *rbd,
			  const struct rbd_spec *spec ) {

	rbd->session = rbd_session_get ( session );
	rbd->attached = 1;
	list_add_tail ( &rbd->list, &session->devices );
	session->ndev++;
	stop_timer ( &session->grace );

	/* The key is kept only when this device's table is to carry it */
	if ( spec->handoff == RBD_HANDOFF_KEY ) {
		session->key = spec->key;
		session->key_kept = 1;
	}
	if ( spec->uri && ( spec->devpath == RBD_DEVPATH_URI ) &&
	     ( ! session->uri ) && ( strlen ( spec->uri ) <= RBD_EFI_URI_MAX ) )
		session->uri = strdup ( spec->uri );
	rbd_session_wake ( session );
}

/**
 * Detach a device from its session (the device keeps its reference until it is freed or lets go)
 *
 * @v session		Session
 * @v rbd		Device
 */
void rbd_session_detach ( struct rbd_session *session, struct rbd_device *rbd ) {
	struct rbd_device *other;
	int wanted = 0;

	if ( ! rbd->attached )
		return;
	rbd->attached = 0;
	list_del ( &rbd->list );
	INIT_LIST_HEAD ( &rbd->list );
	session->ndev--;

	/* Nobody needs the key when no device that is left asked for it */
	list_for_each_entry ( other, &session->devices, list ) {
		if ( other->handoff == RBD_HANDOFF_KEY )
			wanted = 1;
	}
	if ( ! wanted ) {
		rbd_uri_wipe ( &session->key, sizeof ( session->key ) );
		session->key_kept = 0;
	}

	/* The session waits for a reopen */
	if ( ( ! session->ndev ) && ( session->state != RBD_SESSION_DEAD ) )
		start_timer_fixed ( &session->grace,
				    rbd_conn_ms_to_ticks ( RBD_SESSION_GRACE_MS ) );
}

/******************************************************************************
 *
 * What the other glue files ask of the session
 *
 ******************************************************************************
 */

/**
 * Get the data of the handoff table from a session
 *
 * @v session		Cluster session
 * @v source		Handoff data to fill in
 * @ret rc		Return status code
 *
 * -EINPROGRESS until the image is open (the SAN layer's describe loop waits), the session's error once it has failed.
 */
int rbd_session_handoff ( struct rbd_session *session,
			  struct rbd_handoff_source *source ) {
	unsigned int i;

	/* A device that has let go of its session asks with NULL */
	if ( ( ! session ) || ( session->state == RBD_SESSION_DEAD ) )
		return -ENOTCONN;
	if ( session->state == RBD_SESSION_FAILED )
		return ( session->fail_rc ? session->fail_rc : -ENOTCONN );
	if ( session->state != RBD_SESSION_OPEN )
		return -EINPROGRESS;
	memset ( source, 0, sizeof ( *source ) );
	source->user = session->id.user;
	source->pool = session->id.pool;
	source->image = session->id.image;
	source->image_id = session->info.image_id;
	source->snap = NULL;
	source->key = ( session->key_kept ? &session->key : NULL );
	source->n_mons = session->id.n_mons;
	for ( i = 0 ; i < session->id.n_mons ; i++ )
		source->mons[i] = session->id.mons[i];
	source->fsid_known = session->id.fsid_known;
	memcpy ( source->fsid, session->id.fsid, sizeof ( source->fsid ) );
	source->mode = session->id.mode;
	source->read_only = session->id.read_only;
	return 0;
}

/**
 * Get the identity of a session's image for the EFI device path
 *
 * @v session		Cluster session
 * @v source		Structure to fill in
 * @ret rc		Return status code
 */
int rbd_session_efi_source ( struct rbd_session *session,
			     struct rbd_efi_source *source ) {
	unsigned int i;

	if ( ( ! session ) || ( session->state == RBD_SESSION_DEAD ) )
		return -ENOTCONN;
	memset ( source, 0, sizeof ( *source ) );
	source->ident.fsid_known = session->id.fsid_known;
	memcpy ( source->ident.fsid, session->id.fsid,
		 sizeof ( source->ident.fsid ) );
	source->ident.pool = session->id.pool;
	source->ident.image = session->id.image;
	source->ident.snap = NULL;
	source->ident.uri = session->uri;
	for ( i = 0 ; i < session->id.n_mons ; i++ ) {
		if ( session->id.mons[i].family ) {
			source->mon = session->id.mons[i];
			break;
		}
	}
	return 0;
}
