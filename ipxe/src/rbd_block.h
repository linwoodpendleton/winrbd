#ifndef _RBD_BLOCK_H
#define _RBD_BLOCK_H
/* SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL */
/** @file
 *
 * RBD (Ceph) SAN protocol: the block device (private declarations of rbd_block.c, shared with rbd_session.c and the self-tests)
 *
 * The session calls into the block device at three moments: at the end of every pump round (rbd_block_service: finish the
 * commands that are done, ask the commands that wait for a cache line again, start the next prefetches), when the image becomes
 * usable or unusable (rbd_block_window_changed, rbd_block_fail), and when the session is torn down (rbd_block_teardown).
 *
 * Licence: GPL2_OR_LATER_OR_UBDL, like iPXE's own SAN code.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

#include <stdint.h>
#include <stddef.h>
#include "rbd_session.h"

/** What a command does */
enum rbd_cmd_kind {
	RBD_CMD_READ = 0,
	RBD_CMD_WRITE,
	RBD_CMD_CAPACITY,
};

/** Where a command is */
enum rbd_cmd_state {
	/** Finished: rc is set, the session's next step completes it (a completion is never made from inside the call that started the
	 * command: the SAN layer starts its timer after the call returns) */
	RBD_CMD_READY = 0,
	/** Waiting for a cache line to land */
	RBD_CMD_WAIT,
	/** Its request is in the core */
	RBD_CMD_FLIGHT,
	/** The SAN layer is closing it (or the device is): whoever is closing it completes the interface */
	RBD_CMD_CLOSING,
};

/** A SAN command */
struct rbd_cmd {
	/** Reference count */
	struct refcnt refcnt;
	/** The session (reference held) */
	struct rbd_session *session;
	/** The device it came from (no reference: cleared when the device lets go of the session) */
	struct rbd_device *rbd;
	/** The session's list of commands (a reference is held while on it) */
	struct list_head list;
	/** The data interface (plugged into the SAN layer's command interface) */
	struct interface block;
	/** The request in the core (READ and WRITE) */
	struct rbd_request rq;
	/** Where the data is (the SAN layer's buffer: the core reads and writes it directly) */
	void *buffer;
	/** Byte offset and length */
	uint64_t offset;
	uint32_t len;
	/** The cache line the command waits for (WAIT) */
	uint32_t wait_line;
	/** Result, once READY */
	int rc;
	/** enum rbd_cmd_kind */
	uint8_t kind;
	/** enum rbd_cmd_state */
	uint8_t state;
};

/* rbd_block.c: what the session calls */
extern void rbd_block_service ( struct rbd_session *session );
extern void rbd_block_window_changed ( struct rbd_session *session );
extern void rbd_block_fail ( struct rbd_session *session, int rc );
extern void rbd_block_teardown ( struct rbd_session *session, int rc );

/* rbd_block.c: the device */
extern void rbd_device_fail ( struct rbd_device *rbd, int rc );

#endif /* _RBD_BLOCK_H */
