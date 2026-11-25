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

/* Secure Boot: FORBIDDEN, like every file of the driver (docs/design/ipxe-driver.md, section 13). This file turns SAN
 * commands into requests of the core and moves the data of a disk image into and out of the SAN layer's buffers; what is on
 * that disk is chosen by whoever wrote the image. It is only ever linked with the rest of the driver, none of which has had
 * the security review iPXE requires for PERMITTED.
 */
FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

/** @file
 *
 * RBD (Ceph) SAN protocol: the block device
 *
 * The device implements iPXE's block interface directly (block_read, block_write, block_read_capacity), the way the HTTP SAN
 * protocol does, and not through the SCSI layer (docs/design/ipxe-driver.md, section 2). It also answers xfer_window (the SAN path
 * is "active" once the image is open), acpi_describe (the handoff table) and efi_describe (the EFI device path), and closes when
 * the cluster session fails so that the SAN layer reopens the path.
 *
 * Commands.  Every SAN command is a refcounted object plugged into the SAN layer's command interface (intf_plug_plug, as
 * drivers/block/ata.c does). The core's request is part of it, and its buffer is the SAN layer's buffer: the core reads a write's
 * data from it and lands a read's data in it, with no copy. A command is never completed from inside the call that started it (the
 * SAN layer starts its 15 s timer after the call returns, and would wait the whole time for a completion it had already been
 * given): the session's next step completes it, with intf_shutdown(), which is intf_close(rc) on the SAN layer's interface.
 *
 * Cancel.  When the SAN layer closes a command (its timeout, or the reopen of the path) the request is cancelled synchronously
 * (rbd_session_cancel): the close returns to the SAN layer only when the core has handed the request back.
 *
 * Capacity.  512-byte blocks, 8,192 blocks per command; an image whose size is not a multiple of 512 loses its tail (it is
 * truncated down and the tail is unreachable).
 *
 * Readahead.  A cache of lines in the session's memory (the core-readahead module, wr_ra.h, a pure state machine) turns the 127-sector
 * reads of INT 13h into window-sized requests. This file does what the module says: a hit is copied (and completed at the next
 * step), a read that waits for a line is parked and asked again when a line has landed, a miss goes straight into the SAN layer's
 * buffer, a write invalidates the lines it overlaps right after it was accepted, and after every read and every completion the
 * prefetches the module lists are submitted. A prefetch that fails is silent: only demand reads report errors.
 *
 * Credit: the shape of the command object (refcount, plugged interface, mortalised by the creator) is that of
 * drivers/block/ata.c and net/aoe.c; no code of those files, of Linux libceph / rbd or of Ceph is used here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/interface.h>
#include <ipxe/xfer.h>
#include <ipxe/blockdev.h>
#include <ipxe/acpi.h>
#include <ipxe/efi/efi_path.h>
#include <ipxe/efi/efi.h>
#include "rbd_priv.h"
#include "rbd_session.h"
#include "rbd_block.h"
#include "rbd_acpi.h"

/******************************************************************************
 *
 * Commands
 *
 ******************************************************************************
 */

/**
 * Free a command
 *
 * @v refcnt		Reference count
 */
static void rbd_cmd_free ( struct refcnt *refcnt ) {
	struct rbd_cmd *cmd = container_of ( refcnt, struct rbd_cmd, refcnt );

	assert ( list_empty ( &cmd->list ) );
	assert ( ! cmd->rq.pending );
	rbd_session_put ( cmd->session );
	free ( cmd );
}

/**
 * Take a command off its session's list (and let go of the list's reference)
 *
 * @v cmd		Command
 */
static void rbd_cmd_unlink ( struct rbd_cmd *cmd ) {

	if ( list_empty ( &cmd->list ) )
		return;
	list_del ( &cmd->list );
	INIT_LIST_HEAD ( &cmd->list );
	ref_put ( &cmd->refcnt );
}

/**
 * Get the status to tell the SAN layer about a command that is stopped
 *
 * @v rc		Reason for the close of the path or session
 * @ret rc		Status for the command: never success
 *
 * A command that is stopped did not finish: its read buffer holds nothing and its write may not have happened. A graceful close of
 * the path (status 0) is still an error from the command's point of view (iPXE's iSCSI does the same with a TCP close); telling the
 * SAN layer "success" would hand it a buffer of garbage.
 */
static int rbd_cmd_stop_rc ( int rc ) {

	return ( rc ? rc : -ECONNRESET );
}

/**
 * Stop a command: cancel its request (synchronously) and take it off the session's list
 *
 * @v cmd		Command
 *
 * The command is CLOSING from here on: the done function of its request does nothing, and whoever stops it completes the interface.
 */
static void rbd_cmd_stop ( struct rbd_cmd *cmd ) {

	cmd->state = RBD_CMD_CLOSING;
	if ( cmd->rq.pending )
		rbd_session_cancel ( cmd->session, &cmd->rq );
	rbd_cmd_unlink ( cmd );
}

/**
 * Handle the SAN layer closing a command (its timeout, or the reopen of the path)
 *
 * @v cmd		Command
 * @v rc		Reason for close
 */
static void rbd_cmd_close ( struct rbd_cmd *cmd, int rc ) {

	DBGC ( cmd->session, "RBD %p cmd %p closed by the SAN layer (state %d): "
	       "%s\n", cmd->session, cmd, cmd->state, strerror ( rc ) );
	rbd_cmd_stop ( cmd );
	intf_shutdown ( &cmd->block, rc );
}

/** Command interface operations */
static struct interface_operation rbd_cmd_operations[] = {
	INTF_OP ( intf_close, struct rbd_cmd *, rbd_cmd_close ),
};

/** Command interface descriptor */
static struct interface_descriptor rbd_cmd_desc =
	INTF_DESC ( struct rbd_cmd, block, rbd_cmd_operations );

/**
 * Handle the core having finished a command's request
 *
 * @v session		Session
 * @v rq		Request
 */
static void rbd_cmd_req_done ( struct rbd_session *session,
			       struct rbd_request *rq ) {
	struct rbd_cmd *cmd = container_of ( rq, struct rbd_cmd, rq );

	if ( session->demand_bytes >= cmd->len )
		session->demand_bytes -= cmd->len;
	else
		session->demand_bytes = 0;
	if ( cmd->state == RBD_CMD_CLOSING )
		return;
	cmd->rc = rbd_rc ( rq->req.status );
	cmd->state = RBD_CMD_READY;
}

/**
 * Submit a command's request
 *
 * @v session		Session
 * @v cmd		Command
 * @ret rc		Return status code
 */
static int rbd_cmd_submit ( struct rbd_session *session, struct rbd_cmd *cmd ) {
	int rc;

	cmd->rq.req.kind = ( ( cmd->kind == RBD_CMD_WRITE ) ? WR_IO_WRITE :
			     WR_IO_READ );
	cmd->rq.req.timeout_ms = 0;
	cmd->rq.req.offset = cmd->offset;
	cmd->rq.req.length = cmd->len;
	cmd->rq.req.buf = cmd->buffer;
	cmd->rq.done = rbd_cmd_req_done;
	if ( ( rc = rbd_session_submit ( session, &cmd->rq ) ) != 0 )
		return rc;
	cmd->state = RBD_CMD_FLIGHT;
	session->demand_bytes += cmd->len;
	return 0;
}

/**
 * Complete a command that is ready
 *
 * @v cmd		Command (off the session's list; the caller holds a reference)
 */
static void rbd_cmd_complete ( struct rbd_cmd *cmd ) {
	struct block_device_capacity capacity;

	DBGC2 ( cmd->session, "RBD %p cmd %p done (kind %d): %s\n",
		cmd->session, cmd, cmd->kind, strerror ( cmd->rc ) );

	if ( ( cmd->kind == RBD_CMD_CAPACITY ) && ( cmd->rc == 0 ) ) {
		capacity.blocks = cmd->session->blocks;
		capacity.blksize = RBD_BLKSIZE;
		capacity.max_count = RBD_MAX_COUNT;
		block_capacity ( &cmd->block, &capacity );
	}
	intf_shutdown ( &cmd->block, cmd->rc );
}

/**
 * Find a command that is ready
 *
 * @v session		Session
 * @ret cmd		Command, or NULL
 */
static struct rbd_cmd * rbd_cmd_ready ( struct rbd_session *session ) {
	struct rbd_cmd *cmd;

	list_for_each_entry ( cmd, &session->cmds, list ) {
		if ( cmd->state == RBD_CMD_READY )
			return cmd;
	}
	return NULL;
}

/**
 * Find a command that is not being closed
 *
 * @v session		Session
 * @v rbd		Device whose command to find, or NULL for any device
 * @ret cmd		Command, or NULL
 */
static struct rbd_cmd * rbd_cmd_live ( struct rbd_session *session,
				       struct rbd_device *rbd ) {
	struct rbd_cmd *cmd;

	list_for_each_entry ( cmd, &session->cmds, list ) {
		if ( ( cmd->state != RBD_CMD_CLOSING ) &&
		     ( ( ! rbd ) || ( cmd->rbd == rbd ) ) )
			return cmd;
	}
	return NULL;
}

/******************************************************************************
 *
 * Readahead
 *
 ******************************************************************************
 */

/**
 * Handle the core having finished a prefetch
 *
 * @v session		Session
 * @v rq		Request
 */
static void rbd_pf_done ( struct rbd_session *session, struct rbd_request *rq ) {
	struct rbd_prefetch *pf = container_of ( rq, struct rbd_prefetch, rq );
	wr_status st = WR_OK;

	/* A failed prefetch is silent: the line is empty again, and only demand reads report errors */
	if ( session->ra ) {
		if ( rq->req.status == WR_OK )
			st = wr_ra_line_done ( session->ra, pf->line, NULL );
		else
			st = wr_ra_line_failed ( session->ra, pf->line );
		if ( st != WR_OK )
			DBGC ( session, "RBD %p line %d: %s\n", session,
			       pf->line, wr_status_name ( st ) );
	}
	session->ra_dirty = 1;
}

/**
 * Submit the prefetches the readahead module lists
 *
 * @v session		Session
 */
static void rbd_ra_prefetch ( struct rbd_session *session ) {
	struct rbd_prefetch *pf;
	wr_ra_pf item;

	if ( ( ! session->ra ) || ( session->state != RBD_SESSION_OPEN ) )
		return;
	while ( wr_ra_prefetch_next ( session->ra, session->demand_bytes,
				      &item ) ) {
		if ( item.line >= session->n_pf ) {
			/* Not a slot the glue has a request for: the module must not keep it reserved */
			if ( wr_ra_line_unissued ( session->ra, item.line ) != WR_OK )
				DBGC ( session, "RBD %p line %d unissued refused\n",
				       session, item.line );
			break;
		}
		pf = &session->pf[item.line];
		pf->line = item.line;
		pf->rq.req.kind = WR_IO_READ;
		pf->rq.req.timeout_ms = RBD_PREFETCH_TIMEOUT_MS;
		pf->rq.req.offset = item.offset;
		pf->rq.req.length = item.len;
		pf->rq.req.buf = item.buf;
		pf->rq.done = rbd_pf_done;
		if ( rbd_session_submit ( session, &pf->rq ) != 0 ) {
			/* The request table is full (or the image is going away): try again at the next completion */
			if ( wr_ra_line_unissued ( session->ra,
						   item.line ) != WR_OK )
				DBGC ( session, "RBD %p line %d unissued "
				       "refused\n", session, item.line );
			break;
		}
	}
}

/**
 * Copy a cache hit into a command's buffer
 *
 * @v session		Session
 * @v cmd		Command
 * @ret rc		Return status code
 */
static int rbd_cmd_copy_hit ( struct rbd_session *session,
			      struct rbd_cmd *cmd ) {
	const uint8_t *data;
	uint8_t *dest = cmd->buffer;
	uint64_t offset = cmd->offset;
	uint32_t left = cmd->len;
	size_t len;

	while ( left ) {
		len = wr_ra_span ( session->ra, offset, left, &data );
		if ( ! len )
			return -EIO;
		memcpy ( dest, data, len );
		dest += len;
		offset += len;
		left -= len;
	}
	return 0;
}

/**
 * Start (or ask again) a read of a command
 *
 * @v session		Session
 * @v cmd		Command
 * @ret rc		Return status code
 *
 * With a cache: a hit is copied and the command is ready; a read that waits for a line is parked; a miss is submitted into the
 * caller's buffer. Without one: submitted.
 */
static int rbd_cmd_read_start ( struct rbd_session *session,
				struct rbd_cmd *cmd ) {
	wr_ra_act act;
	wr_status st;

	if ( ! session->ra )
		return rbd_cmd_submit ( session, cmd );
	if ( ( st = wr_ra_read ( session->ra, cmd->offset, cmd->len,
				 &act ) ) != WR_OK )
		return rbd_rc ( st );
	switch ( act.kind ) {
	case WR_RA_HIT:
		cmd->rc = rbd_cmd_copy_hit ( session, cmd );
		cmd->state = RBD_CMD_READY;
		return 0;
	case WR_RA_WAIT:
		cmd->state = RBD_CMD_WAIT;
		cmd->wait_line = act.line;
		return 0;
	default:
		return rbd_cmd_submit ( session, cmd );
	}
}

/**
 * Ask the commands that wait for a cache line again
 *
 * @v session		Session
 */
static void rbd_ra_requery ( struct rbd_session *session ) {
	struct rbd_cmd *cmd;
	struct rbd_cmd *tmp;
	int rc;

	list_for_each_entry_safe ( cmd, tmp, &session->cmds, list ) {
		if ( cmd->state != RBD_CMD_WAIT )
			continue;
		if ( ( rc = rbd_cmd_read_start ( session, cmd ) ) != 0 ) {
			cmd->rc = rc;
			cmd->state = RBD_CMD_READY;
		}
	}
}

/******************************************************************************
 *
 * What the session calls
 *
 ******************************************************************************
 */

/**
 * Serve the commands: ask parked commands again, start the next prefetches, complete the commands that are done
 *
 * @v session		Session
 */
void rbd_block_service ( struct rbd_session *session ) {
	struct rbd_cmd *cmd;

	/* A hit is copied before any prefetch is submitted (a prefetch may take the slot of a line behind the stream) */
	if ( session->ra_dirty ) {
		session->ra_dirty = 0;
		rbd_ra_requery ( session );
	}
	rbd_ra_prefetch ( session );

	/* Complete the commands that are done, unless this pump was started by the call that issued a command (the SAN layer starts
	 * its timer when that call returns: a completion before that would never be seen). A completion can start the next command,
	 * which changes the list: look again from the head each time. The command is off the list (and held by us) before its
	 * interface is told.
	 */
	while ( ( ! session->hold ) &&
		( ( cmd = rbd_cmd_ready ( session ) ) != NULL ) ) {
		list_del ( &cmd->list );
		INIT_LIST_HEAD ( &cmd->list );
		rbd_cmd_complete ( cmd );
		ref_put ( &cmd->refcnt );
	}
}

/**
 * Find an attached device
 *
 * @v session		Session
 * @v index		Index in the list of attached devices
 * @ret rbd		Device, or NULL
 */
static struct rbd_device * rbd_device_nth ( struct rbd_session *session,
					    unsigned int index ) {
	struct rbd_device *rbd;

	list_for_each_entry ( rbd, &session->devices, list ) {
		if ( ! index-- )
			return rbd;
	}
	return NULL;
}

/**
 * Tell the SAN layer that the image can (or can no longer) be used
 *
 * @v session		Session
 *
 * A path is active when its xfer_window is non-zero: the SAN layer looks again when told that it changed.
 */
void rbd_block_window_changed ( struct rbd_session *session ) {
	struct rbd_device *rbd;
	unsigned int index;

	/* A callback can close another device (a multipath SAN layer closing a duplicate path): index again every time */
	for ( index = 0 ; ( rbd = rbd_device_nth ( session, index ) ) ; index++ ) {
		ref_get ( &rbd->refcnt );
		xfer_window_changed ( &rbd->block );
		ref_put ( &rbd->refcnt );
	}
}

/**
 * Close the path of every device of a session
 *
 * @v session		Session
 * @v rc		Reason for close
 */
void rbd_block_fail ( struct rbd_session *session, int rc ) {
	struct rbd_device *rbd;

	/* Every close takes the device off the list: this ends */
	while ( ( rbd = rbd_device_nth ( session, 0 ) ) != NULL )
		rbd_device_fail ( rbd, rc );
}

/**
 * Finish what is left of a session that has been destroyed
 *
 * @v session		Session (no client any more: no buffer can be touched)
 * @v rc		Reason
 */
void rbd_block_teardown ( struct rbd_session *session, int rc ) {
	struct rbd_cmd *cmd;

	rbd_block_fail ( session, rc );

	/* Commands of a device that has already let go; those being closed are finished by whoever is closing them */
	while ( ( cmd = rbd_cmd_live ( session, NULL ) ) != NULL ) {
		ref_get ( &cmd->refcnt );
		rbd_cmd_stop ( cmd );
		intf_shutdown ( &cmd->block, rbd_cmd_stop_rc ( rc ) );
		ref_put ( &cmd->refcnt );
	}
}

/******************************************************************************
 *
 * Block interface
 *
 ******************************************************************************
 */

/**
 * Create a command
 *
 * @v rbd		RBD device
 * @v kind		Kind of command
 * @v lba		Starting logical block address
 * @v count		Number of logical blocks
 * @v buffer		Data buffer
 * @v len		Length of data buffer
 * @ret cmd		Command (one reference: the creator's; one more is held by the session's list), or NULL
 * @ret rc		Return status code
 */
static int rbd_cmd_create ( struct rbd_device *rbd, unsigned int kind,
			    uint64_t lba, unsigned int count, void *buffer,
			    size_t len, struct rbd_cmd **cmd ) {
	struct rbd_session *session = rbd->session;

	*cmd = NULL;
	if ( ( ! session ) || ( ! rbd->attached ) ||
	     ( session->state != RBD_SESSION_OPEN ) )
		return -ENOTCONN;
	if ( kind != RBD_CMD_CAPACITY ) {
		if ( ( count == 0 ) || ( count > RBD_MAX_COUNT ) ||
		     ( len != ( ( size_t ) count * RBD_BLKSIZE ) ) )
			return -EINVAL;
		if ( ( lba >= session->blocks ) ||
		     ( count > ( session->blocks - lba ) ) )
			return -EINVAL;
	}
	*cmd = zalloc ( sizeof ( **cmd ) );
	if ( ! *cmd )
		return -ENOMEM;
	ref_init ( &( *cmd )->refcnt, rbd_cmd_free );
	intf_init ( &( *cmd )->block, &rbd_cmd_desc, &( *cmd )->refcnt );
	INIT_LIST_HEAD ( &( *cmd )->list );
	INIT_LIST_HEAD ( &( *cmd )->rq.list );
	( *cmd )->session = rbd_session_get ( session );
	( *cmd )->rbd = rbd;
	( *cmd )->kind = kind;
	( *cmd )->buffer = buffer;
	( *cmd )->offset = ( lba * RBD_BLKSIZE );
	( *cmd )->len = len;
	( *cmd )->state = RBD_CMD_READY;
	ref_get ( &( *cmd )->refcnt );
	list_add_tail ( &( *cmd )->list, &session->cmds );
	return 0;
}

/**
 * Start a read or write
 *
 * @v session		Session
 * @v cmd		Command
 * @ret rc		Return status code
 */
static int rbd_cmd_start ( struct rbd_session *session, struct rbd_cmd *cmd ) {
	int rc;

	if ( cmd->kind == RBD_CMD_READ ) {
		rc = rbd_cmd_read_start ( session, cmd );
	} else {
		/* A write is never delayed by the cache; the lines it overlaps are dropped right after it was accepted (no prefetch is
		 * submitted in between: the image layer orders a read submitted after a write behind it)
		 */
		rc = rbd_cmd_submit ( session, cmd );
		if ( ( rc == 0 ) && session->ra )
			( void ) wr_ra_write ( session->ra, cmd->offset,
					       cmd->len );
	}
	return rc;
}

/**
 * Issue a command and attach it to the SAN layer
 *
 * @v rbd		RBD device
 * @v data		Data interface (the SAN command)
 * @v kind		Kind of command
 * @v lba		Starting logical block address
 * @v count		Number of logical blocks
 * @v buffer		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
static int rbd_block_command ( struct rbd_device *rbd, struct interface *data,
			       unsigned int kind, uint64_t lba,
			       unsigned int count, void *buffer, size_t len ) {
	struct rbd_session *session = rbd->session;
	struct rbd_cmd *cmd;
	int rc;

	if ( ( rc = rbd_cmd_create ( rbd, kind, lba, count, buffer, len,
				     &cmd ) ) != 0 )
		goto err_create;
	if ( kind != RBD_CMD_CAPACITY ) {
		if ( ( rc = rbd_cmd_start ( session, cmd ) ) != 0 )
			goto err_start;
	}

	DBGC2 ( session, "RBD %p cmd %p kind %d lba %#llx count %d state %d\n",
		session, cmd, kind, ( ( unsigned long long ) lba ), count,
		cmd->state );

	/* Attach to the SAN layer's command interface, mortalise ourselves, and let the core go: the pump may finish the command at
	 * once, and the SAN layer must be plugged in to hear it
	 */
	ref_get ( &session->refcnt );
	intf_plug_plug ( &cmd->block, data );
	ref_put ( &cmd->refcnt );
	session->hold++;
	rbd_session_pump ( session );
	session->hold--;
	if ( rbd_cmd_ready ( session ) )
		rbd_session_wake ( session );
	ref_put ( &session->refcnt );
	return 0;

 err_start:
	rbd_cmd_unlink ( cmd );
	ref_put ( &cmd->refcnt );
 err_create:
	return rc;
}

/**
 * Read from the device
 *
 * @v rbd		RBD device
 * @v data		Data interface (the SAN command)
 * @v lba		Starting logical block address
 * @v count		Number of logical blocks
 * @v buffer		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
static int rbd_block_read ( struct rbd_device *rbd, struct interface *data,
			    uint64_t lba, unsigned int count, void *buffer,
			    size_t len ) {

	return rbd_block_command ( rbd, data, RBD_CMD_READ, lba, count, buffer,
				   len );
}

/**
 * Write to the device
 *
 * @v rbd		RBD device
 * @v data		Data interface (the SAN command)
 * @v lba		Starting logical block address
 * @v count		Number of logical blocks
 * @v buffer		Data buffer
 * @v len		Length of data buffer
 * @ret rc		Return status code
 */
static int rbd_block_write ( struct rbd_device *rbd, struct interface *data,
			     uint64_t lba, unsigned int count, void *buffer,
			     size_t len ) {

	return rbd_block_command ( rbd, data, RBD_CMD_WRITE, lba, count, buffer,
				   len );
}

/**
 * Read the device capacity
 *
 * @v rbd		RBD device
 * @v data		Data interface (the SAN command)
 * @ret rc		Return status code
 */
static int rbd_block_read_capacity ( struct rbd_device *rbd,
				     struct interface *data ) {

	return rbd_block_command ( rbd, data, RBD_CMD_CAPACITY, 0, 0, NULL, 0 );
}

/**
 * Check the device window
 *
 * @v rbd		RBD device
 * @ret len		Window length (non-zero once the image is open)
 */
static size_t rbd_block_window ( struct rbd_device *rbd ) {

	if ( rbd->session && rbd->attached &&
	     ( rbd->session->state == RBD_SESSION_OPEN ) )
		return ( ( size_t ) RBD_MAX_COUNT * RBD_BLKSIZE );
	return 0;
}

/**
 * Let go of the session: stop and fail the device's commands, detach, drop the reference
 *
 * @v rbd		RBD device
 * @v rc		Reason
 */
static void rbd_device_release ( struct rbd_device *rbd, int rc ) {
	struct rbd_session *session = rbd->session;
	struct rbd_cmd *cmd;

	if ( ! session )
		return;
	ref_get ( &rbd->refcnt );
	ref_get ( &session->refcnt );

	/* The commands of this device (the SAN layer closes them before the path; a failure of the session does not): stop each one
	 * and tell the SAN layer. Look again from the start each time; a command that is being closed further up the stack is
	 * finished by whoever is closing it.
	 */
	while ( ( cmd = rbd_cmd_live ( session, rbd ) ) != NULL ) {
		ref_get ( &cmd->refcnt );
		rbd_cmd_stop ( cmd );
		intf_shutdown ( &cmd->block, rbd_cmd_stop_rc ( rc ) );
		ref_put ( &cmd->refcnt );
	}
	list_for_each_entry ( cmd, &session->cmds, list ) {
		if ( cmd->rbd == rbd )
			cmd->rbd = NULL;
	}

	/* The callbacks above may have released the device already (a failed session destroys itself) */
	if ( rbd->session == session ) {
		rbd_session_detach ( session, rbd );
		rbd->session = NULL;
		rbd_session_put ( session );
	}
	rbd_session_put ( session );
	ref_put ( &rbd->refcnt );
}

/**
 * Fail the device: close its path with an error
 *
 * @v rbd		RBD device
 * @v rc		Reason
 */
void rbd_device_fail ( struct rbd_device *rbd, int rc ) {

	ref_get ( &rbd->refcnt );
	rbd_device_release ( rbd, rc );
	intf_shutdown ( &rbd->block, rc );
	ref_put ( &rbd->refcnt );
}

/**
 * Close the device
 *
 * @v rbd		RBD device
 * @v rc		Reason for close
 */
static void rbd_block_close ( struct rbd_device *rbd, int rc ) {

	rbd_device_fail ( rbd, rc );
}

/**
 * Free a device
 *
 * @v refcnt		Reference count
 */
static void rbd_device_free ( struct refcnt *refcnt ) {
	struct rbd_device *rbd = container_of ( refcnt, struct rbd_device,
						refcnt );

	/* Normally let go at close; a device freed with its session still held lets go now */
	if ( rbd->session ) {
		rbd_session_detach ( rbd->session, rbd );
		rbd_session_put ( rbd->session );
	}
	free ( rbd );
}

/** RBD device block interface operations */
static struct interface_operation rbd_block_operations[] = {
	INTF_OP ( block_read, struct rbd_device *, rbd_block_read ),
	INTF_OP ( block_write, struct rbd_device *, rbd_block_write ),
	INTF_OP ( block_read_capacity, struct rbd_device *,
		  rbd_block_read_capacity ),
	INTF_OP ( xfer_window, struct rbd_device *, rbd_block_window ),
	INTF_OP ( intf_close, struct rbd_device *, rbd_block_close ),
	INTF_OP ( acpi_describe, struct rbd_device *, rbd_acpi_describe ),
	EFI_INTF_OP ( efi_describe, struct rbd_device *, rbd_efi_path ),
};

/** RBD device block interface descriptor */
static struct interface_descriptor rbd_block_desc =
	INTF_DESC ( struct rbd_device, block, rbd_block_operations );

/**
 * Attach a block device to a SAN path
 *
 * @v parent		Parent interface
 * @v session		Cluster session
 * @v spec		Request specification
 * @ret rc		Return status code
 */
int rbd_device_open ( struct interface *parent, struct rbd_session *session,
		      const struct rbd_spec *spec ) {
	struct rbd_device *rbd;

	if ( ! rbd_session_usable ( session ) )
		return -ENOTCONN;
	rbd = zalloc ( sizeof ( *rbd ) );
	if ( ! rbd )
		return -ENOMEM;
	ref_init ( &rbd->refcnt, rbd_device_free );
	intf_init ( &rbd->block, &rbd_block_desc, &rbd->refcnt );
	INIT_LIST_HEAD ( &rbd->list );
	rbd->devpath = spec->devpath;
	rbd->handoff = spec->handoff;
	rbd_session_attach ( session, rbd, spec );

	/* Attach to the parent interface and mortalise ourselves. If the image is open already (a reopen finding the cached session)
	 * the path is active at once: tell the SAN layer.
	 */
	intf_plug_plug ( &rbd->block, parent );
	if ( session->state == RBD_SESSION_OPEN )
		xfer_window_changed ( &rbd->block );
	ref_put ( &rbd->refcnt );
	return 0;
}
