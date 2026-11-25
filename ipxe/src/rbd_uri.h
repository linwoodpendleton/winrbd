#ifndef _RBD_URI_H
#define _RBD_URI_H
/* SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL */
/** @file
 *
 * RBD (Ceph) SAN protocol: URI opener and settings, private declarations
 *
 * Declarations of rbd_uri.c that no other glue file needs (the ones they do need are in rbd_priv.h, which is frozen:
 * rbd_parse_uri() and rbd_spec_wipe()). They are here so that the self-test (ipxe/tests/rbd_uri_test.c) can reach the
 * pieces it checks without the opener having to export them to the whole driver.
 *
 * What is untrusted text here: the URI (typed by an administrator into a boot script, or served by a menu or a DHCP
 * server) and the two settings. The URI is split by iPXE's parse_uri() and then handed, as pointer + length pieces, to the
 * core's parser (wr_rburl_parse(), core/include/winrbd/wr_rburl.h), which owns every rule about what those pieces may
 * contain. This file only moves text between the two and decides what the console says.
 *
 * Licence: GPL2_OR_LATER_OR_UBDL, like iPXE's own SAN code.  Secure Boot: FORBIDDEN, like every file of the driver, and not a
 * candidate for PERMITTED: the code behind these declarations parses text an outside party may control (see rbd_uri.c).
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

#include <stddef.h>
#include <stdint.h>
#include <ipxe/settings.h>
#include <ipxe/uri.h>
#include "rbd_priv.h"
#include "wr_rburl.h"

/** The "rbd-key" setting: the cephx key (base64, or a keyring "key = ..." line) */
extern const struct setting
rbd_key_setting __setting ( SETTING_AUTH_EXTRA, rbd-key );

/** The "rbd-user" setting: the cephx user id, when the URI has none */
extern const struct setting
rbd_user_setting __setting ( SETTING_AUTH_EXTRA, rbd-user );

/**
 * The working area of one URI parse
 *
 * About 3.3 kB, and it holds the text of the key: the caller allocates it on the heap (the BIOS builds run on a 4 kB
 * stack) and rbd_uri_parse() zeroes all of it before it returns, whatever the outcome. The test allocates its own so that
 * it can look at it afterwards.
 */
struct rbd_uri_work {
	/** What the core's parser is given */
	wr_rburl_in in;
	/** What the core's parser says about a failure */
	wr_errinfo err;
	/** What the core's parser returns (holds the cephx key) */
	wr_rburl_spec parsed;
	/** The monitor list as the URI wrote it: host + ":" + port, rebuilt from iPXE's split (NUL-terminated) */
	char authority[ WR_RBURL_AUTHORITY_MAX + 1 ];
	/** Text of the "rbd-user" setting (one byte more than the parser accepts, so that "too long" is seen) */
	char user[ WR_RBURL_USER_TEXT_MAX + 1 ];
	/** Text of the "rbd-key" setting (the secret: wiped with the rest) */
	char key[ WR_RBURL_KEY_TEXT_MAX + 1 ];
};

/**
 * Parse an RBD URI and the settings, in a working area of the caller's
 *
 * @v uri		URI
 * @v work		Working area (any contents; zero on return)
 * @v spec		Request specification to fill in (all of it is replaced; zero on failure)
 * @ret rc		Return status code
 *
 * Prints one console line on failure (and none on success).
 */
extern int rbd_uri_parse ( struct uri *uri, struct rbd_uri_work *work,
			   struct rbd_spec *spec );

/**
 * Take the text of the URI for the "uri" device path (only when the specification asks for devpath=uri)
 *
 * @v uri		URI
 * @v spec		Request specification: spec->uri is set to the text, or NULL
 * @v text		The text to free() when the open is over, or NULL
 * @ret rc		Return status code
 */
extern int rbd_uri_text ( const struct uri *uri, struct rbd_spec *spec,
			  char **text );

/**
 * Open an RBD URI, on a session environment
 *
 * @v env		Session environment (NULL: production), see rbd_session.h
 * @v parent		Parent interface
 * @v uri		URI
 * @ret rc		Return status code
 *
 * The URI opener of the "rbd" scheme is this with a NULL environment. The self-tests give an environment so that the whole opener
 * (parse, session, device, and every wipe and free on the way out) runs without a cluster.
 */
struct rbd_session_env;
extern int rbd_open_with ( const struct rbd_session_env *env,
			   struct interface *parent, struct uri *uri );

/**
 * Convert the status of a URI parse to an iPXE error code
 *
 * @v status		Status of wr_rburl_parse() (or of the glue's own checks)
 * @ret rc		Return status code (-EINVAL for anything the URI or the settings got wrong)
 */
extern int rbd_uri_rc ( wr_status status );

/**
 * Zero memory in a way the compiler may not remove
 *
 * @v data		Memory
 * @v len		Length
 */
extern void rbd_uri_wipe ( void *data, size_t len );

#endif /* _RBD_URI_H */
