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
 * RBD (Ceph) SAN protocol: URI opener and settings
 *
 * URI syntax (docs/design/ipxe-driver.md, section 8):
 *
 *   rbd://[user@]mon[:port][,mon[:port]...]/pool/image[@snap][?option=value[&option=value...]]
 *
 * Key material is never part of the URI (it would be printed, logged and stored in boot menus): the cephx key
 * comes from the "rbd-key" setting, the user id from the URI or the "rbd-user" setting. A URI that carries a
 * password is refused.
 *
 * Division of labour.  iPXE's parse_uri() splits the URI string.  This file hands the pieces, as pointer + length
 * texts, to the core's parser (wr_rburl_parse(): the user, the monitor list, the path, the options and their values,
 * the key text), and copies the answer into the glue's struct rbd_spec.  Every rule about what the text may contain is
 * the core's (and is tested there); what is here is what only the host can know:
 *
 *   - parse_uri() splits "host[:port]" at the LAST colon, so a monitor list "10.0.0.1:3300,10.0.0.2:3300" arrives as
 *     host "10.0.0.1:3300,10.0.0.2" and port "3300"; the list is rebuilt as host + ":" + port first;
 *   - the two settings are read from iPXE's settings tree (global scope, like the iSCSI CHAP credentials);
 *   - what the console says, and which iPXE error code a failure becomes.
 *
 * What the console says.  A failed parse prints ONE line, "rbd: parse URI (<part>) failed: <core text> (<WR_E_NAME>)":
 * the part is the core's static name for what was wrong ("monitors", "path", "mode", "key" ...), the text and the name
 * are the core's static strings.  The line never holds the URI, any piece of it, the user, the key or the text of an
 * option, so a boot script with a typo in the middle of a key cannot print the key.  (rbd_report() of rbd_errors.c is
 * the same line for the statuses of the core's main table; it does not know the parser's block of statuses, 260 to 279,
 * and would print "unknown status", so the line is formatted here with the parser's own text functions.)  The one
 * exception is the refusal of a password, which keeps the wording the design promised.
 *
 * Secrets.  The key text lives in the working area (struct rbd_uri_work), then in the parsed spec; both are zeroed on
 * every path out of rbd_uri_parse(), and the caller's spec is zeroed on failure (rbd_spec_wipe() when the caller is done).
 * Neither is ever on the stack: the BIOS builds have 4 kB of it.
 *
 * Secure Boot.  FILE_SECBOOT ( FORBIDDEN ), like every file of the driver, and not a candidate for PERMITTED: this file is the
 * first code that looks at text an outside party may control (a URI served by a menu, DHCP or a script fetched over the
 * network, and the two settings), it hands that text to a parser nobody outside this project has reviewed, and iPXE's rule
 * (include/compiler.h) is that a third-party file is marked PERMITTED only after an approved security review.  The tag is
 * written out, not left missing, so that a Secure Boot build which contains the driver fails naming the reason
 * (docs/design/ipxe-driver.md, section 13).
 *
 * Credit.  The shape of the opener (a struct uri_opener that allocates, parses, opens and releases on every path with
 * labelled gotos) is the one iPXE's own protocols use (net/tcp/iscsi.c, net/aoe.c); no code of those files, of Linux
 * libceph / rbd or of Ceph is used here.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/interface.h>
#include <ipxe/open.h>
#include <ipxe/uri.h>
#include <ipxe/settings.h>
#include "rbd_priv.h"
#include "rbd_session.h"
#include "rbd_uri.h"

/** The "rbd-key" setting: the cephx key, base64 as printed by "ceph auth get-key" or the "key =" line of a keyring */
const struct setting rbd_key_setting __setting ( SETTING_AUTH_EXTRA,
						 rbd-key ) = {
	.name = "rbd-key",
	.description = "RBD cephx key (base64)",
	.type = &setting_type_string,
};

/** The "rbd-user" setting: the cephx user id (without "client."), when the URI has none */
const struct setting rbd_user_setting __setting ( SETTING_AUTH_EXTRA,
						  rbd-user ) = {
	.name = "rbd-user",
	.description = "RBD cephx user id",
	.type = &setting_type_string,
};

/* The glue's specification and the core's parsed one are copied field by field; the pieces that are copied as arrays
 * or that carry the same numbers must stay the same size and meaning (a mismatch is a build error, not a truncation)
 */
#define RBD_URI_ASSERT( name, cond ) \
	typedef char rbd_uri_assert_ ## name [ ( cond ) ? 1 : -1 ]
RBD_URI_ASSERT ( user, sizeof ( ( ( struct rbd_spec * ) 0 )->user ) ==
		       sizeof ( ( ( wr_rburl_spec * ) 0 )->user ) );
RBD_URI_ASSERT ( pool, sizeof ( ( ( struct rbd_spec * ) 0 )->pool ) ==
		       sizeof ( ( ( wr_rburl_spec * ) 0 )->pool ) );
RBD_URI_ASSERT ( image, sizeof ( ( ( struct rbd_spec * ) 0 )->image ) ==
			sizeof ( ( ( wr_rburl_spec * ) 0 )->image ) );
RBD_URI_ASSERT ( snap, sizeof ( ( ( struct rbd_spec * ) 0 )->snap ) ==
		       sizeof ( ( ( wr_rburl_spec * ) 0 )->snap ) );
RBD_URI_ASSERT ( mons, sizeof ( ( ( struct rbd_spec * ) 0 )->mons[0] ) ==
		       sizeof ( ( ( wr_rburl_spec * ) 0 )->mons[0] ) );
RBD_URI_ASSERT ( mons_max, WR_MAX_MONS == sizeof ( ( ( struct rbd_spec * ) 0 )->mons ) /
			   sizeof ( ( ( struct rbd_spec * ) 0 )->mons[0] ) );
RBD_URI_ASSERT ( fsid, sizeof ( ( ( struct rbd_spec * ) 0 )->fsid ) ==
		       sizeof ( ( ( wr_rburl_spec * ) 0 )->fsid ) );
RBD_URI_ASSERT ( devpath, RBD_DEVPATH_VENDOR == WR_RBURL_DEVPATH_VENDOR &&
			  RBD_DEVPATH_URI == WR_RBURL_DEVPATH_URI &&
			  RBD_DEVPATH_SATA == WR_RBURL_DEVPATH_SATA );
RBD_URI_ASSERT ( handoff, RBD_HANDOFF_NOKEY == WR_RBURL_HANDOFF_NOKEY &&
			  RBD_HANDOFF_KEY == WR_RBURL_HANDOFF_KEY &&
			  RBD_HANDOFF_NONE == WR_RBURL_HANDOFF_NONE );
RBD_URI_ASSERT ( defaults, RBD_DEFAULT_OPEN_TIMEOUT_MS == WR_RBURL_TIMEOUT_DEFAULT_MS &&
			   RBD_DEFAULT_READAHEAD_KIB == WR_RBURL_READAHEAD_DEFAULT_KIB );

/** First and last status of the parser's block (wr_rburl.h: codes 260 to 279 are reserved for it) */
#define RBD_URI_RBURL_FIRST 260
#define RBD_URI_RBURL_LAST 279
RBD_URI_ASSERT ( block, WR_E_RBURL_PASSWORD == -RBD_URI_RBURL_FIRST &&
			WR_E_RBURL_OPT_RANGE >= -RBD_URI_RBURL_LAST &&
			WR_E_RBURL_OPT_RANGE < WR_E_RBURL_PASSWORD );

/**
 * Zero memory in a way the compiler may not remove
 *
 * @v data		Memory
 * @v len		Length
 *
 * A plain memset() before free(), or before the end of a function whose argument is not used again, may be deleted as a
 * dead store.
 */
void rbd_uri_wipe ( void *data, size_t len ) {
	volatile uint8_t *byte = data;

	while ( len-- )
		*(byte++) = 0;
	__asm__ __volatile__ ( "" : : "r" ( data ) : "memory" );
}

/**
 * Wipe a request specification (it may hold the cephx key)
 *
 * @v spec		Request specification
 */
void rbd_spec_wipe ( struct rbd_spec *spec ) {

	wr_key_wipe ( &spec->key );
	rbd_uri_wipe ( spec, sizeof ( *spec ) );
}

/**
 * Convert the status of a URI parse to an iPXE error code
 *
 * @v status		Status of wr_rburl_parse() (or of the glue's own checks)
 * @ret rc		Return status code
 *
 * Anything the URI or the settings got wrong is -EINVAL (the parser's whole block of statuses, and the monitor-list
 * statuses it passes through); a snapshot, which the core cannot open yet, is -ENOTSUP, and the rest (nothing else is
 * expected here) goes through the table of rbd_errors.c.
 */
int rbd_uri_rc ( wr_status status ) {

	if ( status == WR_OK )
		return 0;
	if ( ( status <= -RBD_URI_RBURL_FIRST ) &&
	     ( status >= -RBD_URI_RBURL_LAST ) )
		return -EINVAL;
	if ( ( status == WR_E_MON_HOSTS_SYNTAX ) ||
	     ( status == WR_E_MON_NO_V2_ADDR ) )
		return -EINVAL;
	return rbd_rc ( status );
}

/**
 * Print why a URI was refused
 *
 * @v status		Status
 * @v what		Static name of the part that was wrong, or NULL
 *
 * One line; see the file comment for what it never contains.
 */
static void rbd_uri_report ( wr_status status, const char *what ) {
	const char *hint = "";

	/* The commonest mistake deserves its remedy on the same line */
	if ( status == WR_E_MON_HOSTS_SYNTAX )
		hint = "; monitor addresses must be IP literals";

	if ( what ) {
		printf ( "rbd: parse URI (%s) failed: %s (%s)%s\n", what,
			 wr_rburl_strerror ( status ),
			 wr_rburl_status_name ( status ), hint );
	} else {
		printf ( "rbd: parse URI failed: %s (%s)%s\n",
			 wr_rburl_strerror ( status ),
			 wr_rburl_status_name ( status ), hint );
	}
}

/**
 * Check for "no such setting"
 *
 * @v rc		Return status code of a failed fetch
 * @ret is_enoent	The setting is not set
 *
 * iPXE return status codes carry the identifier of the file that raised them (settings.c here), so "rc == -ENOENT" written in
 * this file is never true.  What identifies the error itself is the POSIX code (bits 30-24) and the platform code (bits 7-0).
 */
static int rbd_uri_is_enoent ( int rc ) {
	const unsigned int kind = 0x7f0000ffU;

	return ( ( ( ( unsigned int ) -rc ) & kind ) ==
		 ( ( ( unsigned int ) ENOENT ) & kind ) );
}

/**
 * Read the text of a setting into a buffer
 *
 * @v setting		Setting
 * @v buf		Buffer, one byte longer than the longest text the parser accepts
 * @v max		Longest text the parser accepts
 * @v text		Text (NULL if the setting is not set) to fill in
 * @v len		Length of the text to fill in (more than max if it is longer)
 * @ret rc		Return status code
 *
 * The raw bytes are used, with their length: the text is not required to be free of NULs, and the parser looks at the
 * length, never for a terminator.  A text longer than the buffer is cut at max + 1 bytes, which is all the parser needs
 * to see that it is too long, and never more than the buffer holds.
 */
static int rbd_uri_fetch ( const struct setting *setting, char *buf,
			   size_t max, const char **text, size_t *len ) {
	int rc;

	*text = NULL;
	*len = 0;

	rc = fetch_raw_setting ( NULL, setting, buf, ( max + 1 ) );
	if ( ( rc < 0 ) && rbd_uri_is_enoent ( rc ) )
		return 0;
	if ( rc < 0 ) {
		printf ( "rbd: cannot read the %s setting: %s\n",
			 setting->name, strerror ( rc ) );
		return rc;
	}
	*text = buf;
	*len = ( ( ( size_t ) rc > ( max + 1 ) ) ? ( max + 1 ) : ( size_t ) rc );
	return 0;
}

/**
 * Rebuild the monitor list from iPXE's split of the authority
 *
 * @v uri		URI
 * @v work		Working area
 * @ret ok		The list fits
 *
 * parse_uri() splits "host[:port]" at the last colon (unless the text ends in "]"), so a list of monitors, each with
 * its own port, is cut inside the list.  host + ":" + port is the text the URI had between the "@" and the first "/".
 */
static int rbd_uri_authority ( struct uri *uri, struct rbd_uri_work *work ) {
	wr_rburl_in *in = &work->in;
	size_t host_len;
	size_t port_len = 0;
	size_t len;

	if ( ! uri->host )
		return 1;
	host_len = strlen ( uri->host );
	len = host_len;
	if ( uri->port ) {
		port_len = strlen ( uri->port );
		len += ( 1 /* ":" */ + port_len );
	}
	if ( len > WR_RBURL_AUTHORITY_MAX )
		return 0;
	memcpy ( work->authority, uri->host, host_len );
	if ( uri->port ) {
		work->authority[host_len] = ':';
		memcpy ( &work->authority[ host_len + 1 ], uri->port,
			 port_len );
	}
	work->authority[len] = '\0';
	in->authority = work->authority;
	in->authority_len = len;
	return 1;
}

/**
 * Parse an RBD URI and the settings, in a working area of the caller's
 *
 * @v uri		URI
 * @v work		Working area (any contents; zero on return)
 * @v spec		Request specification to fill in (all of it is replaced; zero on failure)
 * @ret rc		Return status code
 */
int rbd_uri_parse ( struct uri *uri, struct rbd_uri_work *work,
		    struct rbd_spec *spec ) {
	wr_rburl_in *in = &work->in;
	const wr_rburl_spec *parsed = &work->parsed;
	const char *what = NULL;
	wr_status status;
	unsigned int i;
	int rc;

	/* Start from nothing: neither the working area nor the
	 * specification keeps anything of an earlier use
	 */
	rbd_uri_wipe ( work, sizeof ( *work ) );
	rbd_spec_wipe ( spec );

	/* A password in the URI would be echoed by the console, by
	 * "uri_dump" in debug builds and by menus: refuse it, before
	 * anything else is looked at (and before the key is read)
	 */
	if ( uri->password ) {
		printf ( "rbd: key material must not be part of the URI "
			 "(use the rbd-key setting)\n" );
		rc = -EINVAL;
		goto out;
	}

	/* The pieces of the URI.  Text that is not there is NULL with a
	 * length of zero; text that is there and empty is not NULL.
	 */
	if ( uri->user ) {
		in->user = uri->user;
		in->user_len = strlen ( uri->user );
	}
	if ( ! rbd_uri_authority ( uri, work ) ) {
		status = WR_E_RBURL_TOO_LONG;
		what = "monitors";
		goto refused;
	}
	if ( uri->path ) {
		in->path = uri->path;
		in->path_len = strlen ( uri->path );
	}
	if ( uri->equery ) {
		/* The query as written: the parser splits and decodes it */
		in->query = uri->equery;
		in->query_len = strlen ( uri->equery );
	}

	/* The settings: the user only when the URI has none */
	if ( ! uri->user ) {
		if ( ( rc = rbd_uri_fetch ( &rbd_user_setting, work->user,
					    WR_RBURL_USER_TEXT_MAX,
					    &in->set_user,
					    &in->set_user_len ) ) != 0 )
			goto out;
	}
	if ( ( rc = rbd_uri_fetch ( &rbd_key_setting, work->key,
				    WR_RBURL_KEY_TEXT_MAX, &in->set_key,
				    &in->set_key_len ) ) != 0 )
		goto out;

	/* Everything else is the core's */
	status = wr_rburl_parse ( in, &work->parsed, &work->err );
	if ( status != WR_OK ) {
		what = work->err.what;
		goto refused;
	}

	/* The two sizing options have no field in the specification yet
	 * (struct rbd_spec is the contract with the session, which owns
	 * the memory plan): refuse them rather than accept and ignore
	 * them.  rbd_priv.h defines RBD_SPEC_HAS_MEM_OPTIONS together with
	 * the two fields that carry them.
	 */
#ifdef RBD_SPEC_HAS_MEM_OPTIONS
	spec->mapmem_kib = parsed->mapmem_kib;
	spec->monmsg_kib = parsed->monmsg_kib;
#else
	if ( parsed->mapmem_kib || parsed->monmsg_kib ) {
		status = WR_E_UNSUPPORTED;
		what = parsed->mapmem_kib ? "mapmem" : "monmsg";
		goto refused;
	}
#endif

	/* The core promises 1 to WR_MAX_MONS monitors; the copy below
	 * writes into the caller's (heap) specification, so the promise
	 * is checked here as well rather than trusted
	 */
	if ( ( parsed->n_mons == 0 ) || ( parsed->n_mons > WR_MAX_MONS ) ) {
		status = WR_E_INVAL;
		what = "monitors";
		goto refused;
	}

	/* The specification, with the design's defaults where the URI
	 * says nothing (the core's parser filled them in)
	 */
	memcpy ( spec->user, parsed->user, sizeof ( spec->user ) );
	memcpy ( spec->pool, parsed->pool, sizeof ( spec->pool ) );
	memcpy ( spec->image, parsed->image, sizeof ( spec->image ) );
	memcpy ( spec->snap, parsed->snap, sizeof ( spec->snap ) );
	for ( i = 0 ; i < parsed->n_mons ; i++ )
		spec->mons[i] = parsed->mons[i];
	spec->n_mons = parsed->n_mons;
	spec->fsid_known = parsed->fsid_known;
	memcpy ( spec->fsid, parsed->fsid, sizeof ( spec->fsid ) );
	spec->mode = parsed->mode;
	spec->read_only = parsed->read_only;
	spec->devpath = parsed->devpath;
	spec->handoff = parsed->handoff;
	spec->open_timeout_ms = parsed->open_timeout_ms;
	spec->readahead_kib = parsed->readahead_kib;
	spec->key = parsed->key;
	rc = 0;
	goto out;

 refused:
	rbd_uri_report ( status, what );
	rc = rbd_uri_rc ( status );
 out:
	/* The working area held the key text and the parsed key; the
	 * specification holds nothing unless it is complete
	 */
	rbd_uri_wipe ( work, sizeof ( *work ) );
	if ( rc != 0 )
		rbd_spec_wipe ( spec );
	return rc;
}

/**
 * Parse an RBD URI
 *
 * @v uri		URI
 * @v spec		Request specification to fill in
 * @ret rc		Return status code
 */
int rbd_parse_uri ( struct uri *uri, struct rbd_spec *spec ) {
	struct rbd_uri_work *work;
	int rc;

	/* The working area holds key text and is large: heap, not stack */
	work = zalloc ( sizeof ( *work ) );
	if ( ! work ) {
		printf ( "rbd: parse URI failed: out of memory\n" );
		rbd_spec_wipe ( spec );
		return -ENOMEM;
	}
	rc = rbd_uri_parse ( uri, work, spec );
	free ( work );
	return rc;
}

/**
 * Take the text of the URI for the "uri" device path
 *
 * @v uri		URI (it has no password: rbd_parse_uri() refuses one)
 * @v spec		Request specification, as parsed
 * @v text		Text to free with free() when the open is over, or NULL (set)
 * @ret rc		Return status code
 *
 * Only a device that asked for devpath=uri needs it: spec->uri then borrows the text, and the session keeps a copy of
 * what it needs (rbd_session_attach). The text is the URI as iPXE prints it back (every option the user wrote); the
 * device path code removes the options it does not know and the password component before anything goes into the path
 * (rbd_efi_uri_redact). Without this the "uri" flavour could never be built: the specification had no URI to give.
 */
int rbd_uri_text ( const struct uri *uri, struct rbd_spec *spec,
		   char **text ) {

	*text = NULL;
	spec->uri = NULL;
	if ( spec->devpath != RBD_DEVPATH_URI )
		return 0;
	*text = format_uri_alloc ( uri );
	if ( ! *text ) {
		printf ( "rbd: open failed: out of memory\n" );
		return -ENOMEM;
	}
	spec->uri = *text;
	return 0;
}

/**
 * Open an RBD URI, on a session environment
 *
 * @v env		Session environment (NULL: production; the self-tests put a scripted cluster under the opener)
 * @v parent		Parent interface
 * @v uri		URI
 * @ret rc		Return status code
 */
int rbd_open_with ( const struct rbd_session_env *env, struct interface *parent,
		    struct uri *uri ) {
	struct rbd_spec *spec;
	struct rbd_session *session;
	char *text = NULL;
	int rc;

	/* The specification holds the key and is large: heap, not stack
	 * (the BIOS build runs on a 4 kB stack)
	 */
	spec = zalloc ( sizeof ( *spec ) );
	if ( ! spec ) {
		printf ( "rbd: open failed: out of memory\n" );
		rc = -ENOMEM;
		goto err_alloc;
	}

	/* Parse URI and settings */
	if ( ( rc = rbd_parse_uri ( uri, spec ) ) != 0 )
		goto err_parse;

	/* The text of the URI, for the "uri" device path only */
	if ( ( rc = rbd_uri_text ( uri, spec, &text ) ) != 0 )
		goto err_text;

	/* Open (or find) the cluster session */
	if ( ( rc = rbd_session_open_with ( env, spec, &session ) ) != 0 )
		goto err_session;

	/* Attach a block device to the parent interface */
	if ( ( rc = rbd_device_open ( parent, session, spec ) ) != 0 )
		goto err_device;

	rbd_session_put ( session );
	rbd_spec_wipe ( spec );
	free ( text );
	free ( spec );
	return 0;

 err_device:
	rbd_session_put ( session );
 err_session:
	free ( text );
 err_text:
 err_parse:
	rbd_spec_wipe ( spec );
	free ( spec );
 err_alloc:
	return rc;
}

/**
 * Open an RBD URI
 *
 * @v parent		Parent interface
 * @v uri		URI
 * @ret rc		Return status code
 */
static int rbd_open ( struct interface *parent, struct uri *uri ) {

	return rbd_open_with ( NULL, parent, uri );
}

/** RBD URI opener */
struct uri_opener rbd_uri_opener __uri_opener = {
	.scheme = "rbd",
	.open = rbd_open,
};
