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

/* Secure Boot: FORBIDDEN, like every file of the driver (docs/design/ipxe-driver.md, section 13). This file only maps
 * statuses to iPXE error codes and console lines and is logically harmless, but it is only ever linked with the rest of the
 * driver, and the licence and Secure Boot checks look at the whole binary: a file that "looks harmless" does not change
 * that.
 */
FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

/** @file
 *
 * RBD (Ceph) SAN protocol: status codes
 *
 * The core reports a wr_status (core/include/winrbd/wr_err.h); the SAN layer wants an iPXE error code. The mapping
 * is many-to-one on purpose: iPXE prints the errno text ("Permission denied") and the SAN layer only cares about
 * success or failure, so the useful detail travels on the console line rbd_report() prints, with the core's own
 * English text and its symbolic name, at the point where the failure ends an open (never from a hot path, never the
 * URI, never key material).
 */

#include <stdio.h>
#include <errno.h>
#include "rbd_priv.h"

/**
 * Convert a core status to an iPXE error code
 *
 * @v status		Core status (WR_OK or a negative WR_E_*)
 * @ret rc		iPXE return status code (0 on success)
 */
int rbd_rc ( wr_status status ) {

	if ( status == WR_OK )
		return 0;

	switch ( status ) {

	case WR_E_INVAL:
	case WR_E_ENCODING:
	case WR_E_RANGE:
	case WR_E_TOOBIG:
	case WR_E_RBD_BAD_ID:
		return -EINVAL;

	case WR_E_BUSY:
		return -EBUSY;
	case WR_E_BUDGET:
	case WR_E_MAP_BUDGET:
		return -ENOMEM;
	case WR_E_UNSUPPORTED:
	case WR_E_MON_MAP_VERSION:
	case WR_E_MAP_VERSION:
	case WR_E_POOL_UNSUPPORTED:
	case WR_E_CRUSH_UNSUPPORTED:
	case WR_E_OSD_VERSION:
	case WR_E_OSD_REDIRECT:
	case WR_E_RBD_FEATURES:
	case WR_E_RBD_STRIPING:
	case WR_E_RBD_PARENT:
	case WR_E_RBD_ORDER:
		return -ENOTSUP;
	case WR_E_CANCELLED:
		return -ECANCELED;
	case WR_E_TIMEOUT:
	case WR_E_M2_HANDSHAKE_TIMEOUT:
		return -ETIMEDOUT;

	case WR_E_HOST_RANDOM:
		return -ENODEV;

	case WR_E_NET_CONNECT:
	case WR_E_MON_UNREACHABLE:
		return -ENETUNREACH;
	case WR_E_NET_CLOSED:
		return -ECONNRESET;

	case WR_E_AUTH_DENIED:
	case WR_E_AUTH_DECRYPT:
	case WR_E_AUTH_KEY_TYPE:
	case WR_E_AUTH_RESULT:
	case WR_E_OSD_PERM:
	case WR_E_OSD_BLOCKLISTED:
		return -EACCES;

	case WR_E_POOL_NOT_FOUND:
	case WR_E_RBD_NOT_FOUND:
	case WR_E_OSD_NOENT:
		return -ENOENT;

	case WR_E_OSD_NOSPC:
		return -ENOSPC;
	case WR_E_RBD_READONLY:
		return -EROFS;
	case WR_E_RBD_LOCKED:
		return -EBUSY;

	case WR_E_OSD_IO:
	case WR_E_RBD_PROTO:
	case WR_E_OSD_PROTO:
	default:
		break;
	}

	/* Everything else is a protocol or integrity failure of the
	 * conversation with the cluster
	 */
	return -EPROTO;
}

/**
 * Print why an open failed
 *
 * @v what		What was being done ("open", "authenticate", ...)
 * @v status		Core status
 *
 * One line on the console. The core's text is a static English string
 * and never contains the URI, the key or any payload.
 */
void rbd_report ( const char *what, wr_status status ) {

	printf ( "rbd: %s failed: %s (%s)\n", what, wr_strerror ( status ),
		 wr_status_name ( status ) );
}

/** The peer's answer to a refused authentication when the offered connection mode was the problem (Linux EOPNOTSUPP, msgr2 AUTH_BAD_METHOD) */
#define RBD_PEER_EOPNOTSUPP ( -95 )

/**
 * Convert a core status to an iPXE error code, with what the peer answered
 *
 * @v status		Core status (WR_OK or a negative WR_E_*)
 * @v peer_result	The peer's own result (the negative Linux errno of its AUTH_BAD_METHOD), 0 if none
 * @ret rc		iPXE return status code (0 on success)
 *
 * A cluster that refuses the login says so with the one frame, AUTH_BAD_METHOD, whatever it did not like: the key, the user, or
 * the connection mode. Its result tells them apart: "operation not supported" is the mode, anything else is the login. The login
 * is permission denied (-EACCES); only the mode is "not supported". The first measured runs showed a wrong key as -EPROTO, which
 * reads as a broken cluster.
 */
int rbd_rc_peer ( wr_status status, int32_t peer_result ) {

	if ( status == WR_E_M2_BAD_METHOD )
		return ( ( peer_result == RBD_PEER_EOPNOTSUPP ) ? -ENOTSUP :
			 -EACCES );
	return rbd_rc ( status );
}

/** The names of the RBD image feature bits (the order of the bits: layering is bit 0) */
static const char * const rbd_feature_names[] = {
	"layering", "striping", "exclusive-lock", "object-map", "fast-diff",
	"deep-flatten", "journaling", "data-pool", "operations", "migrating",
	"non-primary", "snap-mirror",
};

/**
 * Print why an open failed, with what the peer answered
 *
 * @v what		What was being done ("open", "authenticate", ...)
 * @v status		Core status
 * @v peer_result	The peer's own result (negative Linux errno), 0 if none
 * @v detail		The core's first detail word (a0 of its error record), 0 if none
 *
 * Like rbd_report(), one line; for a refused login it also says which of the two the answer points at, and for an image with
 * features the client does not support it names them (the core's text only says "mask in a0").
 */
void rbd_report_peer ( const char *what, wr_status status,
		       int32_t peer_result, uint64_t detail ) {
	unsigned int bit;

	if ( status == WR_E_RBD_FEATURES ) {
		printf ( "rbd: %s failed: %s (%s):", what, wr_strerror ( status ),
			 wr_status_name ( status ) );
		for ( bit = 0 ; bit < 64 ; bit++ ) {
			if ( ! ( ( detail >> bit ) & 1 ) )
				continue;
			if ( bit < ( sizeof ( rbd_feature_names ) /
				     sizeof ( rbd_feature_names[0] ) ) )
				printf ( " %s", rbd_feature_names[bit] );
			else
				printf ( " bit%d", ( int ) bit );
		}
		printf ( " (create the image with the layering feature only)\n" );
		return;
	}
	if ( status != WR_E_M2_BAD_METHOD ) {
		rbd_report ( what, status );
		return;
	}
	printf ( "rbd: %s failed: %s (%s; the cluster answered %ld): %s\n",
		 what, wr_strerror ( status ), wr_status_name ( status ),
		 ( long ) peer_result,
		 ( peer_result == RBD_PEER_EOPNOTSUPP ) ?
		 "it does not allow the connection mode of the URI (option mode)" :
		 "check the key (rbd-key), the user and its capabilities" );
}
