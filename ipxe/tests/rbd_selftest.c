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
 * RBD (Ceph) SAN protocol: self-tests of the glue that needs no network
 *
 * Built into bin-x86_64-linux/tests.linux by "ipxe/tools/build.sh test" (see ipxe/tests/README.md): the file is imported
 * into src/tests/ of the prepared iPXE copy and wired in by patch 0003, so the tests run as a Linux program with
 * iPXE's own test runner. No QEMU, no cluster, no secret.
 *
 * What this file covers (the skeleton's logic that does not depend on the session or the block device):
 *
 *   - the URI opener's first rule: a password in the URI is refused (docs/design/ipxe-driver.md, section 8);
 *   - the specification a parse produces: the documented defaults, and no state left over from an earlier use;
 *   - rbd_spec_wipe(): the specification (and the cephx key in it) is zeroed;
 *   - rbd_rc(): the wr_status -> iPXE error code table of section 12, every mapped status, the default for the rest,
 *     and the rule that a failure never becomes success;
 *   - the constants of the SAN presentation (block size, command size, default timeouts).
 *
 * Secure Boot: FILE_SECBOOT ( FORBIDDEN ), like every file of the driver (docs/design/ipxe-driver.md, section 13). A test
 * object is only ever linked into a self-test program, never into a bootable image, so the declaration costs nothing; nothing
 * here is a candidate for PERMITTED, which iPXE reserves for code that has had its security review.
 *
 * Rules for the next modules (ipxe/tests/README.md): one rbd_<module>_test.c per module, its tests named after the
 * object, a self_test entry whose .name is the object name (build.sh test looks for "OK: <name>" in the run).
 *
 * When the parser of the URI options (module ipxe-uri) lands, the "defaults" tests below keep their meaning (they only
 * assert what the design fixes for every URI); the tests that parse pool, image, monitors and options are added there.
 */

/* iPXE's error macros (-EINVAL ...) carry the identifier of the file that uses them, and the identifiers are listed in
 * <ipxe/errfile.h>; a test object has no entry there. This one is local to the test program (an error code is compared by
 * rbd_same_error() below, never by its file part).
 */
#include <ipxe/errfile.h>
#define ERRFILE_rbd_selftest ( ERRFILE_OTHER | 0x00770000 )

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <ipxe/uri.h>
#include <ipxe/malloc.h>
#include <ipxe/test.h>
#include "winrbd/rbd_priv.h"

/* ---- error codes ------------------------------------------------------------------------------------------------------ */

/** An error code as a constant expression, as seen from this file (the iPXE macros -EINVAL ... are not constant expressions) */
#define RBD_ERR( name ) ( -__einfo_errno ( EINFO_ ## name ) )

/** The part of an error code that says which error it is: the POSIX code (bits 30-24) and the platform code (bits 7-0) */
#define RBD_ERROR_KIND( rc ) ( ( unsigned int ) ( -( rc ) ) & 0x7f0000ffU )

/**
 * Check that two return status codes are the same error
 *
 * @v rc		Return status code
 * @v expected		Expected return status code
 * @ret same		Both are zero, or both are the same error (the file identifier and the call site do not count)
 *
 * rbd_rc() returns -EINVAL as seen from rbd_errors.c; the test writes -EINVAL as seen from this file.
 */
static int rbd_same_error ( int rc, int expected ) {

	if ( ( rc == 0 ) || ( expected == 0 ) )
		return ( rc == expected );
	return ( ( rc < 0 ) && ( expected < 0 ) &&
		 ( RBD_ERROR_KIND ( rc ) == RBD_ERROR_KIND ( expected ) ) );
}

/* ---- URIs ------------------------------------------------------------------------------------------------------------- */

/** A URI test */
struct rbd_uri_test {
	/** URI string */
	const char *string;
	/** Expected return status code of rbd_parse_uri() */
	int rc;
};

/** Define a URI test */
#define RBD_URI_TEST( name, STRING, RC )				\
	static struct rbd_uri_test name = {				\
		.string = STRING,					\
		.rc = RC,						\
	}

/* Refused: a password component, whatever else the URI says. Key material never travels in a URI (it is printed by
 * errors, by DBG output and by menus); the rbd-key setting is the only source.
 */
RBD_URI_TEST ( rbd_uri_password,
	       "rbd://client.admin:AQDjunkjunkjunkjunkjunkjunkjunkjunk0A==@10.77.0.10/pool/img",
	       RBD_ERR ( EINVAL ) );
RBD_URI_TEST ( rbd_uri_password_short, "rbd://admin:pw@10.77.0.10/pool/img", RBD_ERR ( EINVAL ) );
RBD_URI_TEST ( rbd_uri_password_empty, "rbd://admin:@10.77.0.10/pool/img", RBD_ERR ( EINVAL ) );
RBD_URI_TEST ( rbd_uri_password_no_user, "rbd://:pw@10.77.0.10/pool/img", RBD_ERR ( EINVAL ) );
RBD_URI_TEST ( rbd_uri_password_mons, "rbd://admin:pw@10.77.0.10:3300,10.77.0.11:3300/pool/img", RBD_ERR ( EINVAL ) );
RBD_URI_TEST ( rbd_uri_password_options, "rbd://admin:pw@10.77.0.10/pool/img?mode=secure&ro=1", RBD_ERR ( EINVAL ) );
RBD_URI_TEST ( rbd_uri_password_v6, "rbd://admin:pw@[fd00::10]:3300/pool/img", RBD_ERR ( EINVAL ) );

/* No password, but also no "rbd-user" / "rbd-key" setting in this test set (rbd_uri_test.c sets them and covers the accepted
 * URIs): the core's parser refuses each of these for the missing user or key, with the same error code as a password
 */
RBD_URI_TEST ( rbd_uri_plain, "rbd://10.77.0.10/pool/img", RBD_ERR ( EINVAL ) );
RBD_URI_TEST ( rbd_uri_user, "rbd://client.admin@10.77.0.10/pool/img", RBD_ERR ( EINVAL ) );
RBD_URI_TEST ( rbd_uri_user_mons, "rbd://winrbd@10.77.0.10:3300,10.77.0.11:3300/pool/img", RBD_ERR ( EINVAL ) );
RBD_URI_TEST ( rbd_uri_user_v6, "rbd://winrbd@[fd00::10]:3300/pool/img", RBD_ERR ( EINVAL ) );

/**
 * Fill a specification with a pattern that no default equals
 *
 * @v spec		Specification
 */
static void rbd_spec_dirty ( struct rbd_spec *spec ) {

	memset ( spec, 0xa5, sizeof ( *spec ) );
}

/**
 * Check the defaults that the design fixes for every URI
 *
 * @v spec		Specification as built by rbd_parse_uri()
 * @v file		Test code file
 * @v line		Test code line
 */
static void rbd_spec_defaults_okx ( const struct rbd_spec *spec,
				    const char *file, unsigned int line ) {

	/* Connection mode policy: offer crc only, secure mode is opt-in */
	okx ( spec->mode == WR_MODE_CRC_ONLY, file, line );

	/* Writer, not read-only */
	okx ( spec->read_only == 0, file, line );

	/* Wait 20 s for the image, readahead 2 MiB */
	okx ( spec->open_timeout_ms == 20000, file, line );
	okx ( spec->open_timeout_ms == RBD_DEFAULT_OPEN_TIMEOUT_MS, file, line );
	okx ( spec->readahead_kib == 2048, file, line );
	okx ( spec->readahead_kib == RBD_DEFAULT_READAHEAD_KIB, file, line );

	/* Vendor-node EFI device path, handoff table without the key */
	okx ( spec->devpath == RBD_DEVPATH_VENDOR, file, line );
	okx ( spec->handoff == RBD_HANDOFF_NOKEY, file, line );

	/* No cluster id check unless asked for */
	okx ( spec->fsid_known == 0, file, line );

	/* No key unless the rbd-key setting supplies one: the URI cannot */
	okx ( spec->key.len == 0, file, line );

	/* Head of the image, not a snapshot */
	okx ( spec->snap[0] == '\0', file, line );
}
#define rbd_spec_defaults_ok( spec ) \
	rbd_spec_defaults_okx ( spec, __FILE__, __LINE__ )

/**
 * Report URI test result
 *
 * @v test		URI test
 * @v file		Test code file
 * @v line		Test code line
 */
static void rbd_uri_okx ( struct rbd_uri_test *test, const char *file,
			  unsigned int line ) {
	struct rbd_spec *spec;
	struct uri *uri;
	int rc;

	/* Parse URI */
	uri = parse_uri ( test->string );
	okx ( uri != NULL, file, line );
	if ( ! uri )
		return;

	/* The specification holds a key and is large: heap, like the opener */
	spec = zalloc ( sizeof ( *spec ) );
	okx ( spec != NULL, file, line );
	if ( ! spec ) {
		uri_put ( uri );
		return;
	}
	rbd_spec_dirty ( spec );

	/* Check the result */
	rc = rbd_parse_uri ( uri, spec );
	okx ( rbd_same_error ( rc, test->rc ), file, line );

	/* A successful parse builds the whole specification: nothing of the
	 * previous contents survives, and the defaults are the design's
	 */
	if ( ( test->rc == 0 ) && ( rc == 0 ) )
		rbd_spec_defaults_okx ( spec, file, line );

	/* Wiping works on whatever state the parse left */
	rbd_spec_wipe ( spec );
	free ( spec );
	uri_put ( uri );
}
#define rbd_uri_ok( test ) rbd_uri_okx ( test, __FILE__, __LINE__ )

/**
 * Check that rbd_spec_wipe() zeroes everything, the key included
 *
 */
static void rbd_wipe_ok ( void ) {
	struct rbd_spec *spec;
	uint8_t *bytes;
	size_t i;
	int nonzero = 0;

	spec = zalloc ( sizeof ( *spec ) );
	ok ( spec != NULL );
	if ( ! spec )
		return;

	/* Every byte non-zero, including the secret and its length */
	rbd_spec_dirty ( spec );
	ok ( spec->key.len != 0 );
	rbd_spec_wipe ( spec );

	bytes = ( ( uint8_t * ) spec );
	for ( i = 0 ; i < sizeof ( *spec ) ; i++ ) {
		if ( bytes[i] )
			nonzero++;
	}
	ok ( nonzero == 0 );
	ok ( spec->key.len == 0 );
	ok ( spec->key.type == 0 );

	/* Wiping a wiped (or never filled) specification is harmless */
	rbd_spec_wipe ( spec );
	ok ( spec->n_mons == 0 );
	free ( spec );
}

/* ---- status mapping --------------------------------------------------------------------------------------------------- */

/** A status mapping test: one explicitly mapped core status */
struct rbd_rc_test {
	/** Core status */
	wr_status status;
	/** Expected iPXE return status code */
	int rc;
};

/** Define a status mapping test */
#define RBD_RC( STATUS, RC ) { .status = STATUS, .rc = RC }

/**
 * The status mapping table of docs/design/ipxe-driver.md, section 12
 *
 * One row for every status that rbd_rc() maps explicitly. A status that is in WR_STATUS_LIST but not here must map to
 * -EPROTO (the default of the table); a status that moves to another code is a deliberate change of the table and of
 * the design, made in both places. The three -EPROTO rows (WR_E_OSD_IO, WR_E_RBD_PROTO, WR_E_OSD_PROTO) are listed
 * because the design names them.
 */
static const struct rbd_rc_test rbd_rc_table[] = {
	/* -EINVAL */
	RBD_RC ( WR_E_INVAL, RBD_ERR ( EINVAL ) ),
	RBD_RC ( WR_E_ENCODING, RBD_ERR ( EINVAL ) ),
	RBD_RC ( WR_E_RANGE, RBD_ERR ( EINVAL ) ),
	RBD_RC ( WR_E_TOOBIG, RBD_ERR ( EINVAL ) ),
	RBD_RC ( WR_E_RBD_BAD_ID, RBD_ERR ( EINVAL ) ),
	/* -ENOMEM */
	RBD_RC ( WR_E_BUDGET, RBD_ERR ( ENOMEM ) ),
	RBD_RC ( WR_E_MAP_BUDGET, RBD_ERR ( ENOMEM ) ),
	/* -ENOTSUP */
	RBD_RC ( WR_E_UNSUPPORTED, RBD_ERR ( ENOTSUP ) ),
	RBD_RC ( WR_E_MON_MAP_VERSION, RBD_ERR ( ENOTSUP ) ),
	RBD_RC ( WR_E_MAP_VERSION, RBD_ERR ( ENOTSUP ) ),
	RBD_RC ( WR_E_POOL_UNSUPPORTED, RBD_ERR ( ENOTSUP ) ),
	RBD_RC ( WR_E_CRUSH_UNSUPPORTED, RBD_ERR ( ENOTSUP ) ),
	RBD_RC ( WR_E_OSD_VERSION, RBD_ERR ( ENOTSUP ) ),
	RBD_RC ( WR_E_OSD_REDIRECT, RBD_ERR ( ENOTSUP ) ),
	RBD_RC ( WR_E_RBD_FEATURES, RBD_ERR ( ENOTSUP ) ),
	RBD_RC ( WR_E_RBD_STRIPING, RBD_ERR ( ENOTSUP ) ),
	RBD_RC ( WR_E_RBD_PARENT, RBD_ERR ( ENOTSUP ) ),
	RBD_RC ( WR_E_RBD_ORDER, RBD_ERR ( ENOTSUP ) ),
	/* -ETIMEDOUT */
	RBD_RC ( WR_E_TIMEOUT, RBD_ERR ( ETIMEDOUT ) ),
	RBD_RC ( WR_E_M2_HANDSHAKE_TIMEOUT, RBD_ERR ( ETIMEDOUT ) ),
	/* -ENETUNREACH, -ECONNRESET */
	RBD_RC ( WR_E_NET_CONNECT, RBD_ERR ( ENETUNREACH ) ),
	RBD_RC ( WR_E_MON_UNREACHABLE, RBD_ERR ( ENETUNREACH ) ),
	RBD_RC ( WR_E_NET_CLOSED, RBD_ERR ( ECONNRESET ) ),
	/* -EACCES */
	RBD_RC ( WR_E_AUTH_DENIED, RBD_ERR ( EACCES ) ),
	RBD_RC ( WR_E_AUTH_DECRYPT, RBD_ERR ( EACCES ) ),
	RBD_RC ( WR_E_AUTH_KEY_TYPE, RBD_ERR ( EACCES ) ),
	RBD_RC ( WR_E_AUTH_RESULT, RBD_ERR ( EACCES ) ),
	RBD_RC ( WR_E_OSD_PERM, RBD_ERR ( EACCES ) ),
	RBD_RC ( WR_E_OSD_BLOCKLISTED, RBD_ERR ( EACCES ) ),
	/* -ENOENT */
	RBD_RC ( WR_E_POOL_NOT_FOUND, RBD_ERR ( ENOENT ) ),
	RBD_RC ( WR_E_RBD_NOT_FOUND, RBD_ERR ( ENOENT ) ),
	RBD_RC ( WR_E_OSD_NOENT, RBD_ERR ( ENOENT ) ),
	/* -ENOSPC, -EROFS, -EBUSY */
	RBD_RC ( WR_E_OSD_NOSPC, RBD_ERR ( ENOSPC ) ),
	RBD_RC ( WR_E_RBD_READONLY, RBD_ERR ( EROFS ) ),
	RBD_RC ( WR_E_BUSY, RBD_ERR ( EBUSY ) ),
	RBD_RC ( WR_E_RBD_LOCKED, RBD_ERR ( EBUSY ) ),
	/* -ECANCELED, -ENODEV */
	RBD_RC ( WR_E_CANCELLED, RBD_ERR ( ECANCELED ) ),
	RBD_RC ( WR_E_HOST_RANDOM, RBD_ERR ( ENODEV ) ),
	/* -EPROTO: named by the design */
	RBD_RC ( WR_E_OSD_IO, RBD_ERR ( EPROTO ) ),
	RBD_RC ( WR_E_RBD_PROTO, RBD_ERR ( EPROTO ) ),
	RBD_RC ( WR_E_OSD_PROTO, RBD_ERR ( EPROTO ) ),
};

/** Number of statuses the table maps explicitly */
#define RBD_RC_TABLE_COUNT ( sizeof ( rbd_rc_table ) / sizeof ( rbd_rc_table[0] ) )

/**
 * Find a status in the mapping table
 *
 * @v status		Core status
 * @ret test		Table row, or NULL if the status is not mapped explicitly
 */
static const struct rbd_rc_test * rbd_rc_find ( wr_status status ) {
	unsigned int i;

	for ( i = 0 ; i < RBD_RC_TABLE_COUNT ; i++ ) {
		if ( rbd_rc_table[i].status == status )
			return &rbd_rc_table[i];
	}
	return NULL;
}

/**
 * Check that one core status maps as the design says
 *
 * @v status		Core status
 * @v file		Test code file
 * @v line		Test code line
 * @ret mapped		The status has an explicit row in the table
 */
static int rbd_rc_okx ( wr_status status, const char *file,
			unsigned int line ) {
	const struct rbd_rc_test *test = rbd_rc_find ( status );
	int expected = ( test ? test->rc : RBD_ERR ( EPROTO ) );
	int rc = rbd_rc ( status );

	/* The expected code, and never success for a failure */
	okx ( rbd_same_error ( rc, expected ), file, line );
	okx ( rc < 0, file, line );

	return ( test != NULL );
}
#define rbd_rc_ok( status ) rbd_rc_okx ( status, __FILE__, __LINE__ )

/**
 * Check the status mapping
 *
 */
static void rbd_rc_all_ok ( void ) {
	unsigned int listed = 0;
	unsigned int mapped = 0;

	/* Success is success */
	ok ( rbd_rc ( WR_OK ) == 0 );

	/* Every status of the core's list: the table's code, or -EPROTO */
#define RBD_RC_LIST_ONE( name, code, text )				\
	do {								\
		listed++;						\
		mapped += rbd_rc_ok ( name );				\
	} while ( 0 );
	WR_STATUS_LIST ( RBD_RC_LIST_ONE )
#undef RBD_RC_LIST_ONE

	/* Every row of the table is a status of the list, once: the rows
	 * name enumerators of the list (the compiler checks the names), and
	 * the walk found each row's status exactly once, so a status that
	 * appears twice in the table would leave "mapped" short
	 */
	ok ( listed > 0 );
	ok ( mapped == RBD_RC_TABLE_COUNT );

	/* A cluster that refuses the login with AUTH_BAD_METHOD says why in its result: "operation not supported" is the
	 * connection mode, anything else (a wrong key, an unknown user: -EACCES, -EPERM, nothing) is the login, which is
	 * permission denied and not a broken conversation. The table above stays what the status alone says.
	 */
	ok ( rbd_same_error ( rbd_rc ( WR_E_M2_BAD_METHOD ), RBD_ERR ( EPROTO ) ) );
	ok ( rbd_same_error ( rbd_rc_peer ( WR_E_M2_BAD_METHOD, -13 ), RBD_ERR ( EACCES ) ) );
	ok ( rbd_same_error ( rbd_rc_peer ( WR_E_M2_BAD_METHOD, -1 ), RBD_ERR ( EACCES ) ) );
	ok ( rbd_same_error ( rbd_rc_peer ( WR_E_M2_BAD_METHOD, 0 ), RBD_ERR ( EACCES ) ) );
	ok ( rbd_same_error ( rbd_rc_peer ( WR_E_M2_BAD_METHOD, -95 ), RBD_ERR ( ENOTSUP ) ) );
	ok ( rbd_same_error ( rbd_rc_peer ( WR_E_M2_BAD_METHOD, ( int32_t ) 0x80000000 ), RBD_ERR ( EACCES ) ) );
	ok ( rbd_rc_peer ( WR_OK, 0 ) == 0 );
	ok ( rbd_same_error ( rbd_rc_peer ( WR_E_TIMEOUT, -13 ), rbd_rc ( WR_E_TIMEOUT ) ) );
	ok ( rbd_same_error ( rbd_rc_peer ( WR_E_AUTH_DENIED, -95 ), rbd_rc ( WR_E_AUTH_DENIED ) ) );
	ok ( rbd_same_error ( rbd_rc_peer ( -9999, -95 ), RBD_ERR ( EPROTO ) ) );

	/* A status the core does not define is a failure of the
	 * conversation, never success
	 */
	ok ( rbd_same_error ( rbd_rc ( -9999 ), RBD_ERR ( EPROTO ) ) );
	ok ( rbd_same_error ( rbd_rc ( ( wr_status ) 1 ), RBD_ERR ( EPROTO ) ) );
	ok ( rbd_same_error ( rbd_rc ( ( wr_status ) -32768 ), RBD_ERR ( EPROTO ) ) );

	/* The comparison itself tells different errors apart */
	ok ( ! rbd_same_error ( RBD_ERR ( EINVAL ), RBD_ERR ( ENOENT ) ) );
	ok ( ! rbd_same_error ( RBD_ERR ( EINVAL ), 0 ) );
	ok ( ! rbd_same_error ( 0, RBD_ERR ( EINVAL ) ) );
	ok ( rbd_same_error ( RBD_ERR ( EACCES ), RBD_ERR ( EACCES ) ) );
}

/* ---- constants -------------------------------------------------------------------------------------------------------- */

/**
 * Check the constants of the SAN presentation
 *
 */
static void rbd_constants_ok ( void ) {
	uint32_t sig;

	/* BIOS and UEFI want 512-byte blocks; one command moves at most
	 * 4 MiB (the iPXE profile's inflight limit of the core)
	 */
	ok ( RBD_BLKSIZE == 512 );
	ok ( ( ( size_t ) RBD_MAX_COUNT * RBD_BLKSIZE ) == ( 4UL * 1024 * 1024 ) );

	/* Names: pool, image and snapshot fit WR_ENTITY_MAX-sized ids */
	ok ( RBD_NAME_MAX >= 64 );

	/* The signature of the handoff table is the four characters "rBFT"
	 * in this order in memory (docs/design/handoff-table.md)
	 */
	sig = RBFT_SIG;
	ok ( memcmp ( &sig, "rBFT", 4 ) == 0 );
}

/**
 * Perform RBD self-tests
 *
 */
static void rbd_selftest_exec ( void ) {

	/* URIs */
	rbd_uri_ok ( &rbd_uri_password );
	rbd_uri_ok ( &rbd_uri_password_short );
	rbd_uri_ok ( &rbd_uri_password_empty );
	rbd_uri_ok ( &rbd_uri_password_no_user );
	rbd_uri_ok ( &rbd_uri_password_mons );
	rbd_uri_ok ( &rbd_uri_password_options );
	rbd_uri_ok ( &rbd_uri_password_v6 );
	rbd_uri_ok ( &rbd_uri_plain );
	rbd_uri_ok ( &rbd_uri_user );
	rbd_uri_ok ( &rbd_uri_user_mons );
	rbd_uri_ok ( &rbd_uri_user_v6 );

	/* Specification */
	rbd_wipe_ok();

	/* Status mapping */
	rbd_rc_all_ok();

	/* Constants */
	rbd_constants_ok();

#ifdef RBD_SELFTEST_NEGATIVE_CONTROL
	/* The negative control of "ipxe/tools/build.sh test --negative-control":
	 * a failing assertion that the runner and the script must report as a
	 * failure. Only ever compiled in by that command (CFLAGS_rbd_selftest).
	 */
	ok ( 0 /* deliberate failure: negative control */ );
#endif
}

/** RBD self-test set */
struct self_test rbd_selftest __self_test = {
	.name = "rbd_selftest",
	.exec = rbd_selftest_exec,
};
