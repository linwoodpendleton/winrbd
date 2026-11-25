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
 * RBD (Ceph) SAN protocol: self-tests of the URI opener and the settings
 *
 * Built into bin-x86_64-linux/tests.linux by "ipxe/tools/build.sh test" (ipxe/tests/README.md): no network, no QEMU, no
 * cluster, no real secret.  The URIs go through iPXE's real parse_uri(), the settings through iPXE's real settings tree
 * (the "rbd-key" and "rbd-user" settings are stored and fetched exactly as a boot script's "set" does), and the result is the
 * specification the session layer would get.
 *
 * What this file covers (docs/design/ipxe-driver.md, section 8):
 *
 *   - monitor lists with and without ports (the split that parse_uri() makes at the last colon, rebuilt), IPv6, many monitors;
 *   - the user in the URI against the user in the "rbd-user" setting, the "client." prefix;
 *   - the key: base64, a keyring "key =" line, a whole keyring, both cephx key types, the failures;
 *   - every option, every accepted word and every refusal (unknown, repeated, malformed, out of range);
 *   - the path, the snapshot refusal, the password refusal (and that it comes first);
 *   - the console: exactly one line per refusal, none on success, with the core's reason, and a canary test that no byte of
 *     a key, and no piece of the URI, ever reaches printf output (captured through a console driver of this test program);
 *   - secrets: the working area is zero on every path out, the specification is zero on every failure, rbd_spec_wipe();
 *     and, by walking the whole free heap afterwards, that no byte of a decoded key is left in memory the opener freed;
 *   - the opener itself (scheme matched like iPXE does, every refusal before a session is asked for), and that a run of
 *     parses and refusals leaks nothing from the heap;
 *   - the status -> error code mapping of the parser's statuses, the limits of every text.
 *
 * Secure Boot: FILE_SECBOOT ( FORBIDDEN ), like every file of the driver (docs/design/ipxe-driver.md, section 13).  A test
 * object is only ever linked into a self-test program.
 */

/* iPXE's error macros (-EINVAL ...) carry the identifier of the file that uses them (see rbd_selftest.c) */
#include <ipxe/errfile.h>
#define ERRFILE_rbd_uri_test ( ERRFILE_OTHER | 0x00780000 )

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ipxe/uri.h>
#include <ipxe/malloc.h>
#include <ipxe/interface.h>
#include <ipxe/open.h>
#include <ipxe/settings.h>
#include <ipxe/console.h>
#include <ipxe/base64.h>
#include <ipxe/test.h>
#include "winrbd/rbd_uri.h"
#include "winrbd/rbd_efi.h"
#include "winrbd/rbd_session.h"

/* ---- error codes ------------------------------------------------------------------------------------------------------ */

/** The part of an error code that says which error it is: the POSIX code (bits 30-24) and the platform code (bits 7-0) */
#define RBD_ERROR_KIND( rc ) ( ( unsigned int ) ( -( rc ) ) & 0x7f0000ffU )

/**
 * Check that two return status codes are the same error
 *
 * @v rc		Return status code
 * @v expected		Expected return status code
 * @ret same		Both are zero, or both are the same error (the file identifier does not count)
 */
static int rbd_same_error ( int rc, int expected ) {

	if ( ( rc == 0 ) || ( expected == 0 ) )
		return ( rc == expected );
	return ( ( rc < 0 ) && ( expected < 0 ) &&
		 ( RBD_ERROR_KIND ( rc ) == RBD_ERROR_KIND ( expected ) ) );
}

/* ---- the console ------------------------------------------------------------------------------------------------------ */

/** Size of the capture buffer (the longest legitimate output of a run is one line of about 200 bytes) */
#define CAP_MAX 4096

/** Captured console output (CRs dropped; always NUL-terminated while a capture is not running) */
static char cap_buf[CAP_MAX];

/** Length of the captured output */
static size_t cap_len;

/** The capture ran out of room */
static int cap_full;

/**
 * Capture a console character
 *
 * @v character		Character
 */
static void cap_putchar ( int character ) {

	if ( character == '\r' )
		return;
	if ( cap_len < ( CAP_MAX - 1 ) ) {
		cap_buf[cap_len++] = character;
		cap_buf[cap_len] = '\0';
	} else {
		cap_full = 1;
	}
}

/** A console that only copies what printf() writes (disabled except while a capture runs; the real console still prints) */
struct console_driver rbd_uri_test_console __console_driver = {
	.disabled = CONSOLE_DISABLED,
	.putchar = cap_putchar,
	.usage = ( CONSOLE_USAGE_STDOUT | CONSOLE_USAGE_LOG ),
};

/** Console usage to restore when a quiet capture ends */
static int cap_usage;

/** Start capturing */
static void cap_start ( void ) {

	cap_len = 0;
	cap_buf[0] = '\0';
	cap_full = 0;
	rbd_uri_test_console.disabled = 0;
}

/**
 * Start capturing, and keep the real console (which every other console driver serves) silent
 *
 * For the checks that print a window of a test key on purpose, to show that the canary can fail: the capture sees it, no
 * console shows it.
 */
static void cap_start_quiet ( void ) {

	cap_usage = console_set_usage ( CONSOLE_USAGE_LOG );
	cap_start();
}

/** Stop capturing */
static void cap_stop ( void ) {

	rbd_uri_test_console.disabled = CONSOLE_DISABLED;
	if ( cap_usage ) {
		console_set_usage ( cap_usage );
		cap_usage = 0;
	}
}

/**
 * Count the lines of the captured output
 *
 * @ret lines		Number of newline characters
 */
static unsigned int cap_lines ( void ) {
	unsigned int lines = 0;
	size_t i;

	for ( i = 0 ; i < cap_len ; i++ ) {
		if ( cap_buf[i] == '\n' )
			lines++;
	}
	return lines;
}

/**
 * Check whether the captured output contains a text
 *
 * @v text		Text
 * @ret found		The text is in the output
 */
static int cap_has ( const char *text ) {

	return ( strstr ( cap_buf, text ) != NULL );
}

/**
 * Build a text from a prefix and the first bytes of another
 *
 * @v dst		Destination
 * @v size		Size of destination
 * @v prefix		Prefix (may be empty)
 * @v src		Source text
 * @v n			Number of bytes of the source to copy (fewer if the source is shorter)
 * @v suffix		Suffix (may be empty)
 *
 * iPXE's printf() has no precision ("%.30s" would print ".30s"), so a cut is made by hand.
 */
static void rbd_text_cut ( char *dst, size_t size, const char *prefix,
			   const char *src, size_t n, const char *suffix ) {
	size_t src_len = strlen ( src );
	size_t len = strlen ( prefix );

	if ( n > src_len )
		n = src_len;
	if ( ( len + n + strlen ( suffix ) + 1 ) > size ) {
		dst[0] = '\0';
		return;
	}
	memcpy ( dst, prefix, len );
	memcpy ( &dst[len], src, n );
	strcpy ( &dst[ len + n ], suffix );
}

/* ---- keys and secrets ------------------------------------------------------------------------------------------------- */

/** A cephx key made for these tests: the text the setting holds, and the secret in it */
struct rbd_test_key {
	/** Key type (WR_KEY_TYPE_*) */
	unsigned int type;
	/** The secret (printable ASCII, so that a leak of it as text would show) */
	const char *secret;
	/** Length of the secret */
	size_t len;
	/** base64 text, as "ceph auth get-key" prints it */
	char b64[96];
};

/** The AES key: 18 secret bytes (a whole number of base64 groups with the header, so that the text has no padding) */
static struct rbd_test_key key_aes = {
	.type = WR_KEY_TYPE_AES,
	.secret = "QZ8canary4secretXY",
	.len = 18,
};

/** The AES-256-CTS key: 33 secret bytes */
static struct rbd_test_key key_256 = {
	.type = WR_KEY_TYPE_AES256K,
	.secret = "Hq2canary9AES256secretkey0123456Z",
	.len = 33,
};

/**
 * Build the base64 text of a key
 *
 * @v key		Test key
 *
 * The layout of the text of a key (docs/spec/cephx.md): a 16-bit type, the creation time (8 bytes), a 16-bit length and the
 * secret.  Only the secret is secret: the header is the same for every key, which is why the leak search below skips it.
 */
static void rbd_test_key_build ( struct rbd_test_key *key ) {
	uint8_t raw[ 12 + 40 ];
	size_t len = key->len;

	memset ( raw, 0, sizeof ( raw ) );
	raw[0] = key->type;
	raw[3] = 0xf1;
	raw[4] = 0x53;
	raw[5] = 0x65;
	raw[10] = len;
	memcpy ( &raw[12], key->secret, len );
	base64_encode ( raw, ( 12 + len ), key->b64, sizeof ( key->b64 ) );
}

/**
 * Check a key that the parse produced against its test key
 *
 * @v spec		Specification
 * @v key		Test key
 * @v file		Test code file
 * @v line		Test code line
 */
static void rbd_key_is_okx ( const struct rbd_spec *spec,
			     const struct rbd_test_key *key,
			     const char *file, unsigned int line ) {

	okx ( spec->key.type == key->type, file, line );
	okx ( spec->key.len == key->len, file, line );
	okx ( memcmp ( spec->key.secret, key->secret, key->len ) == 0, file,
	      line );
}
#define rbd_key_is( spec, key ) rbd_key_is_okx ( spec, key, __FILE__, __LINE__ )

/**
 * Copy a few bytes, one at a time
 *
 * @v dst		Destination
 * @v src		Source
 * @v len		Number of bytes
 *
 * iPXE's memcpy() of a constant length is inlined as loads and stores of whole words, which on a source or destination of
 * any alignment is what the UBSan build of the self-tests (build.sh test -u) rightly traps on.
 */
static void rbd_copy_bytes ( char *dst, const char *src, size_t len ) {
	size_t i;

	for ( i = 0 ; i < len ; i++ )
		dst[i] = src[i];
}

/**
 * Check that the captured output holds nothing of a key
 *
 * @v key		Test key
 * @ret clean		No window of the secret, of its text or of its base64 form is in the output
 *
 * The windows are 6 bytes of the secret and 8 characters of the base64 text, taken after the header (which is not secret and
 * is the same in every key: 12 bytes are 16 base64 characters): a line that prints a prefix, a suffix or the middle of a key shows up.
 */
static int cap_free_of_key ( const struct rbd_test_key *key ) {
	char window[16];
	size_t i;
	size_t b64_len = strlen ( key->b64 );

	for ( i = 0 ; ( i + 6 ) <= key->len ; i++ ) {
		rbd_copy_bytes ( window, &key->secret[i], 6 );
		window[6] = '\0';
		if ( cap_has ( window ) )
			return 0;
	}
	for ( i = 20 ; ( i + 8 ) <= b64_len ; i++ ) {
		rbd_copy_bytes ( window, &key->b64[i], 8 );
		window[8] = '\0';
		if ( cap_has ( window ) )
			return 0;
	}
	return 1;
}

/** Words that appear in the URIs of the failing runs and must never be printed back (the URI, the user, the host, the names) */
static const char * const rbd_leak_words[] = {
	"zuser-leak", "zpool-leak", "zimg-leak", "zsnap-leak", "10.77.9.9",
	"zhost-leak", "zlistmon-leak",
};

/* ---- settings ---------------------------------------------------------------------------------------------------------- */

/**
 * Store the text of a setting, as a boot script's "set" would
 *
 * @v setting		Setting
 * @v text		Text
 */
static void rbd_set_text ( const struct setting *setting, const char *text ) {

	ok ( store_setting ( NULL, setting, text, strlen ( text ) ) == 0 );
}

/** Delete both settings */
static void rbd_set_none ( void ) {

	delete_setting ( NULL, &rbd_key_setting );
	delete_setting ( NULL, &rbd_user_setting );
}

/** The user of most tests */
#define TEST_USER "winrbd"

/** Set the settings most tests use: the user and the AES key */
static void rbd_set_default ( void ) {

	rbd_set_none();
	rbd_set_text ( &rbd_user_setting, TEST_USER );
	rbd_set_text ( &rbd_key_setting, key_aes.b64 );
}

/* ---- running a parse --------------------------------------------------------------------------------------------------- */

/** The specification and working area of the runs (heap, like the opener's) */
static struct rbd_spec *t_spec;
static struct rbd_uri_work *t_work;

/** Number of bytes of memory that are not zero */
static size_t rbd_nonzero ( const void *data, size_t len ) {
	const uint8_t *bytes = data;
	size_t count = 0;
	size_t i;

	for ( i = 0 ; i < len ; i++ ) {
		if ( bytes[i] )
			count++;
	}
	return count;
}

/** Check that a key is all zero bytes */
static int ses_key_is_zero ( const wr_key *key ) {

	return ( rbd_nonzero ( key, sizeof ( *key ) ) == 0 );
}

/**
 * Parse a URI string with the settings as they are, and check what is true of every run
 *
 * @v string		URI string
 * @v rc		Return status code to fill in
 * @v file		Test code file
 * @v line		Test code line
 *
 * Every run starts from a specification and a working area full of 0xa5, so that nothing that is not written by the parse can
 * look right.  After every run, whatever the outcome:
 *
 *   - the working area (it held the key text) is zero;
 *   - the specification is zero if the parse failed;
 *   - a refusal printed exactly one line, starting with "rbd: ", ending in a newline, and a success printed nothing;
 *   - the output holds no word of the leak list and nothing of either test key.
 */
static void rbd_runx ( const char *string, int *rc, const char *file,
		       unsigned int line ) {
	struct uri *uri;
	size_t i;

	*rc = -EFAULT;
	memset ( t_spec, 0xa5, sizeof ( *t_spec ) );
	memset ( t_work, 0xa5, sizeof ( *t_work ) );
	uri = parse_uri ( string );
	okx ( uri != NULL, file, line );
	if ( ! uri )
		return;

	cap_start();
	*rc = rbd_uri_parse ( uri, t_work, t_spec );
	cap_stop();
	uri_put ( uri );

	okx ( rbd_nonzero ( t_work, sizeof ( *t_work ) ) == 0, file, line );
	if ( *rc != 0 ) {
		okx ( rbd_nonzero ( t_spec, sizeof ( *t_spec ) ) == 0, file,
		      line );
		okx ( cap_lines() == 1, file, line );
		okx ( strncmp ( cap_buf, "rbd: ", 5 ) == 0, file, line );
		okx ( cap_len > 0 && cap_buf[ cap_len - 1 ] == '\n', file,
		      line );

		/* The remedy for a host name is on the line of a host name and on no other */
		okx ( ( ! cap_has ( "must be IP literals" ) ) ||
		      cap_has ( "(WR_E_MON_HOSTS_SYNTAX)" ), file, line );
	} else {
		okx ( cap_len == 0, file, line );
	}
	okx ( ! cap_full, file, line );
	for ( i = 0 ; i < ( sizeof ( rbd_leak_words ) /
			    sizeof ( rbd_leak_words[0] ) ) ; i++ )
		okx ( ! cap_has ( rbd_leak_words[i] ), file, line );
	okx ( cap_free_of_key ( &key_aes ), file, line );
	okx ( cap_free_of_key ( &key_256 ), file, line );
}

/** Expect a successful parse */
#define RBD_OK( string ) do {						\
		int rbd_status;					\
		rbd_runx ( string, &rbd_status, __FILE__, __LINE__ );	\
		ok ( rbd_status == 0 );					\
	} while ( 0 )

/**
 * Expect a refusal
 *
 * @v string		URI string
 * @v rc		Expected error code (as seen from this file)
 * @v name		Symbolic name of the status the line must show, or NULL
 * @v part		The part the line must name ("monitors", "path" ...), or NULL for none
 */
#define RBD_BAD( string, rc, name, part ) do {				\
		int rbd_status;					\
		rbd_runx ( string, &rbd_status, __FILE__, __LINE__ );	\
		ok ( rbd_same_error ( rbd_status, rc ) );		\
		rbd_line_okx ( name, part, __FILE__, __LINE__ );	\
	} while ( 0 )

/**
 * Check the console line of the last run
 *
 * @v name		Symbolic name, in brackets, or NULL
 * @v part		Part named in the line, or NULL
 * @v file		Test code file
 * @v line		Test code line
 */
static void rbd_line_okx ( const char *name, const char *part,
			   const char *file, unsigned int line ) {
	char text[96];

	if ( name ) {
		snprintf ( text, sizeof ( text ), "(%s)", name );
		okx ( cap_has ( text ), file, line );
	}
	if ( part ) {
		snprintf ( text, sizeof ( text ), "parse URI (%s) failed: ",
			   part );
		okx ( cap_has ( text ), file, line );
	}
}

/** One monitor, IPv4: address and port */
static int rbd_mon_v4 ( const wr_addr *mon, unsigned int a, unsigned int b,
			unsigned int c, unsigned int d, unsigned int port ) {
	size_t i;

	if ( ( mon->family != WR_AF_IPV4 ) || ( mon->port != port ) ||
	     ( mon->nonce != 0 ) )
		return 0;
	if ( ( mon->ip[0] != a ) || ( mon->ip[1] != b ) ||
	     ( mon->ip[2] != c ) || ( mon->ip[3] != d ) )
		return 0;
	for ( i = 4 ; i < sizeof ( mon->ip ) ; i++ ) {
		if ( mon->ip[i] )
			return 0;
	}
	return 1;
}

/** One monitor, IPv6: the last two bytes of the address, which is fd00:: followed by zeros */
static int rbd_mon_v6 ( const wr_addr *mon, unsigned int tail,
			unsigned int port ) {
	size_t i;

	if ( ( mon->family != WR_AF_IPV6 ) || ( mon->port != port ) ||
	     ( mon->nonce != 0 ) )
		return 0;
	if ( ( mon->ip[0] != 0xfd ) || ( mon->ip[14] != ( tail >> 8 ) ) ||
	     ( mon->ip[15] != ( tail & 0xff ) ) )
		return 0;
	for ( i = 1 ; i < 14 ; i++ ) {
		if ( mon->ip[i] )
			return 0;
	}
	return 1;
}

/** Everything after the last monitor in the array is zero (nothing of the 0xa5 fill survives) */
static int rbd_mons_tail_zero ( const struct rbd_spec *spec ) {

	return ( rbd_nonzero ( &spec->mons[ spec->n_mons ],
			       ( sizeof ( spec->mons ) -
				 ( spec->n_mons * sizeof ( spec->mons[0] ) ) ) )
		 == 0 );
}

/* ---- defaults, the plain URI ------------------------------------------------------------------------------------------ */

/** The URI of most tests: user from the setting, one monitor, no options */
#define PLAIN "rbd://10.77.0.10/zpool-leak/zimg-leak"

/** The defaults the design fixes (section 8), and the parts of a plain URI */
static void rbd_test_defaults ( void ) {
	struct rbd_spec *spec = t_spec;

	rbd_set_default();
	RBD_OK ( PLAIN );
	ok ( strcmp ( spec->user, TEST_USER ) == 0 );
	ok ( strcmp ( spec->pool, "zpool-leak" ) == 0 );
	ok ( strcmp ( spec->image, "zimg-leak" ) == 0 );
	ok ( spec->snap[0] == '\0' );
	ok ( spec->n_mons == 1 );
	ok ( rbd_mon_v4 ( &spec->mons[0], 10, 77, 0, 10, 3300 ) );
	ok ( rbd_mons_tail_zero ( spec ) );
	ok ( spec->mode == WR_MODE_CRC_ONLY );
	ok ( spec->read_only == 0 );
	ok ( spec->open_timeout_ms == RBD_DEFAULT_OPEN_TIMEOUT_MS );
	ok ( spec->open_timeout_ms == 20000 );
	ok ( spec->readahead_kib == RBD_DEFAULT_READAHEAD_KIB );
	ok ( spec->readahead_kib == 2048 );
	ok ( spec->devpath == RBD_DEVPATH_VENDOR );
	ok ( spec->handoff == RBD_HANDOFF_NOKEY );
	ok ( spec->fsid_known == 0 );
	ok ( rbd_nonzero ( spec->fsid, sizeof ( spec->fsid ) ) == 0 );
	rbd_key_is ( spec, &key_aes );

	/* A trailing "?" with nothing after it asks for nothing */
	RBD_OK ( PLAIN "?" );
	ok ( spec->mode == WR_MODE_CRC_ONLY );

	/* A fragment is not part of the request */
	RBD_OK ( PLAIN "#frag" );
	ok ( strcmp ( spec->image, "zimg-leak" ) == 0 );

	/* Percent escapes in the path are decoded by iPXE before the core sees them */
	RBD_OK ( "rbd://10.77.0.10/zp%6fol-leak/zimg%2dleak" );
	ok ( strcmp ( spec->pool, "zpool-leak" ) == 0 );
	ok ( strcmp ( spec->image, "zimg-leak" ) == 0 );

	rbd_set_none();
}

/* ---- monitors ---------------------------------------------------------------------------------------------------------- */

/** The monitor list: parse_uri() cuts it at the last colon; the glue puts it back */
static void rbd_test_monitors ( void ) {
	struct rbd_spec *spec = t_spec;
	char uri[256];
	unsigned int i;

	rbd_set_default();

	/* One monitor with a port: the split is exactly host and port */
	RBD_OK ( "rbd://10.77.0.10:3301/zpool-leak/zimg-leak" );
	ok ( spec->n_mons == 1 );
	ok ( rbd_mon_v4 ( &spec->mons[0], 10, 77, 0, 10, 3301 ) );

	/* An unprefixed address on the legacy port 6789 is a v1 address, which this client does not speak: no usable monitor */
	RBD_BAD ( "rbd://10.77.0.10:6789/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_MON_NO_V2_ADDR", "monitors" );

	/* A list, each with a port: the cut is inside the list, at its last colon */
	RBD_OK ( "rbd://10.77.0.10:3300,10.77.0.11:3300,10.77.0.12:3300/zpool-leak/zimg-leak" );
	ok ( spec->n_mons == 3 );
	ok ( rbd_mon_v4 ( &spec->mons[0], 10, 77, 0, 10, 3300 ) );
	ok ( rbd_mon_v4 ( &spec->mons[1], 10, 77, 0, 11, 3300 ) );
	ok ( rbd_mon_v4 ( &spec->mons[2], 10, 77, 0, 12, 3300 ) );
	ok ( rbd_mons_tail_zero ( spec ) );

	/* Different ports, and some without a port (the default is 3300), in the order written */
	RBD_OK ( "rbd://10.77.0.10:3301,10.77.0.11,10.77.0.12:3303/zpool-leak/zimg-leak" );
	ok ( spec->n_mons == 3 );
	ok ( rbd_mon_v4 ( &spec->mons[0], 10, 77, 0, 10, 3301 ) );
	ok ( rbd_mon_v4 ( &spec->mons[1], 10, 77, 0, 11, 3300 ) );
	ok ( rbd_mon_v4 ( &spec->mons[2], 10, 77, 0, 12, 3303 ) );

	/* A list without a single port: iPXE finds no colon to cut at */
	RBD_OK ( "rbd://10.77.0.10,10.77.0.11/zpool-leak/zimg-leak" );
	ok ( spec->n_mons == 2 );
	ok ( rbd_mon_v4 ( &spec->mons[1], 10, 77, 0, 11, 3300 ) );

	/* IPv6: brackets, with and without a port, alone and in a list with IPv4 */
	RBD_OK ( "rbd://[fd00::10]:3300/zpool-leak/zimg-leak" );
	ok ( spec->n_mons == 1 );
	ok ( rbd_mon_v6 ( &spec->mons[0], 0x10, 3300 ) );
	RBD_OK ( "rbd://[fd00::11]/zpool-leak/zimg-leak" );
	ok ( rbd_mon_v6 ( &spec->mons[0], 0x11, 3300 ) );
	RBD_OK ( "rbd://[fd00::10]:3301,10.77.0.11:3302/zpool-leak/zimg-leak" );
	ok ( spec->n_mons == 2 );
	ok ( rbd_mon_v6 ( &spec->mons[0], 0x10, 3301 ) );
	ok ( rbd_mon_v4 ( &spec->mons[1], 10, 77, 0, 11, 3302 ) );
	RBD_OK ( "rbd://10.77.0.10:3300,[fd00::12]/zpool-leak/zimg-leak" );
	ok ( spec->n_mons == 2 );
	ok ( rbd_mon_v6 ( &spec->mons[1], 0x12, 3300 ) );

	/* The most the client keeps: WR_MAX_MONS; one more is refused, never dropped */
	for ( i = 1 ; i <= ( WR_MAX_MONS + 1 ) ; i++ ) {
		size_t len = snprintf ( uri, sizeof ( uri ), "rbd://" );
		unsigned int j;

		for ( j = 1 ; j <= i ; j++ )
			len += snprintf ( &uri[len], ( sizeof ( uri ) - len ),
					  "%s10.77.0.%d:3300", j > 1 ? "," : "",
					  ( int ) j );
		snprintf ( &uri[len], ( sizeof ( uri ) - len ),
			   "/zpool-leak/zimg-leak" );
		if ( i <= WR_MAX_MONS ) {
			RBD_OK ( uri );
			ok ( spec->n_mons == i );
			ok ( rbd_mon_v4 ( &spec->mons[ i - 1 ], 10, 77, 0, i,
					  3300 ) );
		} else {
			RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_MANY_MONS",
				  "monitors" );
		}
	}

	/* No monitor at all */
	RBD_BAD ( "rbd:///zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_NO_MONS", "monitors" );
	RBD_BAD ( "rbd:/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_NO_MONS", "monitors" );
	RBD_BAD ( "rbd:zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_NO_MONS", "monitors" );

	/* A host name is not an address: the line says what to do about it, on the same line */
	RBD_BAD ( "rbd://zhost-leak/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_MON_HOSTS_SYNTAX", "monitors" );
	ok ( cap_has ( "must be IP literals" ) );
	RBD_BAD ( "rbd://zhost-leak:3300/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_MON_HOSTS_SYNTAX", "monitors" );
	RBD_BAD ( "rbd://10.77.0.10,zlistmon-leak/zpool-leak/zimg-leak",
		  -EINVAL, "WR_E_MON_HOSTS_SYNTAX", "monitors" );
	RBD_BAD ( "rbd://10.77.0.10:99999/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_MON_HOSTS_SYNTAX", "monitors" );
	RBD_BAD ( "rbd://10.77.0.10:/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_MON_HOSTS_SYNTAX", "monitors" );
	RBD_BAD ( "rbd://:3300/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_MON_HOSTS_SYNTAX", "monitors" );
	RBD_BAD ( "rbd://10.77.0.10,;10.77.0.11x/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_MON_HOSTS_SYNTAX", "monitors" );

	/* iPXE cuts "host:port" before it decodes the escapes, so an escaped comma or colon is part of the host text: the list is
	 * still the list the URI spells
	 */
	RBD_OK ( "rbd://10.77.0.10%2c10.77.0.11/zpool-leak/zimg-leak" );
	ok ( spec->n_mons == 2 );
	ok ( rbd_mon_v4 ( &spec->mons[1], 10, 77, 0, 11, 3300 ) );
	RBD_OK ( "rbd://10.77.0.10%3a3301/zpool-leak/zimg-leak" );
	ok ( spec->n_mons == 1 );
	ok ( rbd_mon_v4 ( &spec->mons[0], 10, 77, 0, 10, 3301 ) );

	/* Empty items between separators are skipped by the core's list parser (a doubled comma is not an error) */
	RBD_OK ( "rbd://10.77.0.10,,10.77.0.11/zpool-leak/zimg-leak" );
	ok ( spec->n_mons == 2 );

	rbd_set_none();
}

/** The monitor list is the one text the glue copies itself: its length is checked on both sides of the limit */
static void rbd_test_authority_limit ( void ) {
	static char uri[ 8 + WR_RBURL_AUTHORITY_MAX + 64 + 32 ];
	size_t host_len;
	size_t len;

	rbd_set_default();

	/* Exactly at the limit: the glue passes it on (the core then says it is not a monitor address) */
	host_len = WR_RBURL_AUTHORITY_MAX;
	len = snprintf ( uri, sizeof ( uri ), "rbd://" );
	memset ( &uri[len], '1', host_len );
	len += host_len;
	snprintf ( &uri[len], ( sizeof ( uri ) - len ),
		   "/zpool-leak/zimg-leak" );
	RBD_BAD ( uri, -EINVAL, "WR_E_MON_HOSTS_SYNTAX", "monitors" );

	/* One more: refused by the glue, which cannot copy it */
	len = snprintf ( uri, sizeof ( uri ), "rbd://" );
	memset ( &uri[len], '1', ( host_len + 1 ) );
	len += ( host_len + 1 );
	snprintf ( &uri[len], ( sizeof ( uri ) - len ),
		   "/zpool-leak/zimg-leak" );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_TOO_LONG", "monitors" );

	/* The port counts: host + ":" + port is what is measured */
	len = snprintf ( uri, sizeof ( uri ), "rbd://" );
	memset ( &uri[len], '1', ( host_len - 5 ) );
	len += ( host_len - 5 );
	snprintf ( &uri[len], ( sizeof ( uri ) - len ),
		   ":3300/zpool-leak/zimg-leak" );
	RBD_BAD ( uri, -EINVAL, "WR_E_MON_HOSTS_SYNTAX", "monitors" );
	len = snprintf ( uri, sizeof ( uri ), "rbd://" );
	memset ( &uri[len], '1', ( host_len - 4 ) );
	len += ( host_len - 4 );
	snprintf ( &uri[len], ( sizeof ( uri ) - len ),
		   ":3300/zpool-leak/zimg-leak" );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_TOO_LONG", "monitors" );

	rbd_set_none();
}

/**
 * The copy of the monitor list never writes outside the working area, however long the host is
 *
 * The host of a URI is text an outside party controls (a menu, a DHCP option, a script fetched over the network). The glue copies
 * it into the working area's fixed field, so the length check is the only thing between a long host and a heap overflow; the
 * core's own length check comes after the copy and cannot help. The tests above stop one byte past the limit, which is too little to
 * see (the byte lands in the next field, which is zero and is overwritten later): this one passes hosts of several times the size of the
 * whole working area, with a guard after the working area, and asks that the guard is untouched and the parse refuses.
 */
static void rbd_test_authority_overflow ( void ) {
	static const size_t host_lens[] = { ( WR_RBURL_AUTHORITY_MAX + 1 ), ( 2 * WR_RBURL_AUTHORITY_MAX ), 8192, 20000 };
	struct {
		struct rbd_uri_work work;
		uint8_t guard[256];
	} *area;
	struct rbd_spec *spec;
	struct uri *uri;
	char *string;
	size_t string_size;
	size_t len;
	unsigned int i;
	int rc;

	rbd_set_default();
	area = zalloc ( sizeof ( *area ) );
	spec = zalloc ( sizeof ( *spec ) );
	string_size = ( 8 + 20000 + 32 );
	string = zalloc ( string_size );
	ok ( area != NULL );
	ok ( spec != NULL );
	ok ( string != NULL );
	if ( ! ( area && spec && string ) )
		goto done;

	for ( i = 0 ; i < ( sizeof ( host_lens ) / sizeof ( host_lens[0] ) ) ; i++ ) {
		memset ( area->guard, 0xa5, sizeof ( area->guard ) );
		len = snprintf ( string, string_size, "rbd://" );
		memset ( &string[len], '1', host_lens[i] );
		len += host_lens[i];
		snprintf ( &string[len], ( string_size - len ), "/zpool-leak/zimg-leak" );
		uri = parse_uri ( string );
		ok ( uri != NULL );
		if ( ! uri )
			continue;
		cap_start();
		rc = rbd_uri_parse ( uri, &area->work, spec );
		cap_stop();
		uri_put ( uri );
		ok ( rbd_same_error ( rc, -EINVAL ) );
		ok ( rbd_nonzero ( spec, sizeof ( *spec ) ) == 0 );
		ok ( rbd_nonzero ( &area->work, sizeof ( area->work ) ) == 0 );
		ok ( cap_has ( "WR_E_RBURL_TOO_LONG" ) );
		ok ( cap_lines() == 1 );
		/* Nothing was written after the working area */
		ok ( ( area->guard[0] == 0xa5 ) && ( area->guard[sizeof ( area->guard ) - 1] == 0xa5 ) &&
		     ( memcmp ( area->guard, area->guard + 1, ( sizeof ( area->guard ) - 1 ) ) == 0 ) );
	}

 done:
	free ( string );
	free ( spec );
	free ( area );
	rbd_set_none();
}

/* ---- the user ---------------------------------------------------------------------------------------------------------- */

/** The user: in the URI, else the setting; "client." is dropped once */
static void rbd_test_user ( void ) {
	struct rbd_spec *spec = t_spec;
	static char uri[ 256 ];
	static char name[ WR_ENTITY_MAX + 8 ];

	/* In the URI, no setting */
	rbd_set_none();
	rbd_set_text ( &rbd_key_setting, key_aes.b64 );
	RBD_OK ( "rbd://admin@10.77.0.10/zpool-leak/zimg-leak" );
	ok ( strcmp ( spec->user, "admin" ) == 0 );
	RBD_OK ( "rbd://client.admin@10.77.0.10/zpool-leak/zimg-leak" );
	ok ( strcmp ( spec->user, "admin" ) == 0 );
	RBD_OK ( "rbd://ad%6din@10.77.0.10/zpool-leak/zimg-leak" );
	ok ( strcmp ( spec->user, "admin" ) == 0 );
	RBD_OK ( "rbd://win-rbd_1.x@10.77.0.10/zpool-leak/zimg-leak" );
	ok ( strcmp ( spec->user, "win-rbd_1.x" ) == 0 );

	/* No user anywhere */
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_NO_USER", "user" );

	/* The setting, with and without the prefix */
	rbd_set_text ( &rbd_user_setting, "setuser" );
	RBD_OK ( PLAIN );
	ok ( strcmp ( spec->user, "setuser" ) == 0 );
	rbd_set_text ( &rbd_user_setting, "client.setuser" );
	RBD_OK ( PLAIN );
	ok ( strcmp ( spec->user, "setuser" ) == 0 );

	/* The URI wins over the setting, even when the URI's user is the wrong one */
	RBD_OK ( "rbd://admin@10.77.0.10/zpool-leak/zimg-leak" );
	ok ( strcmp ( spec->user, "admin" ) == 0 );
	RBD_BAD ( "rbd://ad%20min@10.77.0.10/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_BAD_USER", "user" );

	/* What is not an id: empty, the prefix twice, a character outside the set, too long */
	RBD_BAD ( "rbd://@10.77.0.10/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_BAD_USER", "user" );
	RBD_BAD ( "rbd://client.@10.77.0.10/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_BAD_USER", "user" );
	RBD_BAD ( "rbd://client.client.x@10.77.0.10/zpool-leak/zimg-leak",
		  -EINVAL, "WR_E_RBURL_BAD_USER", "user" );
	RBD_BAD ( "rbd://a%2fb@10.77.0.10/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_BAD_USER", "user" );
	RBD_BAD ( "rbd://a%3ab@10.77.0.10/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_BAD_USER", "user" );
	memset ( name, 'a', WR_ENTITY_MAX );
	name[ WR_ENTITY_MAX - 1 ] = '\0';
	snprintf ( uri, sizeof ( uri ), "rbd://%s@10.77.0.10/zpool-leak/zimg-leak", name );
	RBD_OK ( uri );
	ok ( strlen ( spec->user ) == ( WR_ENTITY_MAX - 1 ) );
	name[ WR_ENTITY_MAX - 1 ] = 'a';
	name[ WR_ENTITY_MAX ] = '\0';
	snprintf ( uri, sizeof ( uri ), "rbd://%s@10.77.0.10/zpool-leak/zimg-leak", name );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_BAD_USER", "user" );

	/* A bad user in the setting is the setting's fault, and says so */
	rbd_set_text ( &rbd_user_setting, "bad user" );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_BAD_USER", "rbd-user" );
	rbd_set_text ( &rbd_user_setting, "client.client.x" );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_BAD_USER", "rbd-user" );

	rbd_set_none();
}

/* ---- the key ----------------------------------------------------------------------------------------------------------- */

/** The key: base64, a keyring line, a whole keyring; both types; and what is refused */
static void rbd_test_key ( void ) {
	struct rbd_spec *spec = t_spec;
	static char text[ WR_RBURL_KEY_TEXT_MAX + 64 ];
	size_t pad;

	rbd_set_none();
	rbd_set_text ( &rbd_user_setting, TEST_USER );

	/* No key */
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_NO_KEY", "key" );

	/* The base64 text of either type */
	rbd_set_text ( &rbd_key_setting, key_aes.b64 );
	RBD_OK ( PLAIN );
	rbd_key_is ( spec, &key_aes );
	rbd_set_text ( &rbd_key_setting, key_256.b64 );
	RBD_OK ( PLAIN );
	rbd_key_is ( spec, &key_256 );

	/* The line of a keyring */
	snprintf ( text, sizeof ( text ), "key = %s", key_aes.b64 );
	rbd_set_text ( &rbd_key_setting, text );
	RBD_OK ( PLAIN );
	rbd_key_is ( spec, &key_aes );
	snprintf ( text, sizeof ( text ), "key=%s\r\n", key_256.b64 );
	rbd_set_text ( &rbd_key_setting, text );
	RBD_OK ( PLAIN );
	rbd_key_is ( spec, &key_256 );

	/* A whole keyring, as "ceph auth get client.x" prints it */
	snprintf ( text, sizeof ( text ),
		   "[client.winrbd]\n\tkey = %s\n\tcaps mon = \"allow r\"\n",
		   key_aes.b64 );
	rbd_set_text ( &rbd_key_setting, text );
	RBD_OK ( PLAIN );
	rbd_key_is ( spec, &key_aes );

	/* Whitespace around the base64 text is fine */
	snprintf ( text, sizeof ( text ), "  %s \n", key_256.b64 );
	rbd_set_text ( &rbd_key_setting, text );
	RBD_OK ( PLAIN );
	rbd_key_is ( spec, &key_256 );

	/* Set the way a script does: "set rbd-key <text>" goes through the setting's type */
	ok ( storef_setting ( NULL, &rbd_key_setting, key_aes.b64 ) == 0 );
	RBD_OK ( PLAIN );
	rbd_key_is ( spec, &key_aes );

	/* Not a key: nothing of the text is in the line, which names the part and the status only */
	rbd_set_text ( &rbd_key_setting, "not a key" );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_BAD_KEY", "key" );
	rbd_set_text ( &rbd_key_setting, "key = AQAA8VNlAAAA" );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_BAD_KEY", "key" );
	snprintf ( text, sizeof ( text ), "%s!", key_aes.b64 );
	rbd_set_text ( &rbd_key_setting, text );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_BAD_KEY", "key" );
	snprintf ( text, sizeof ( text ), "[client.x]\n\tcaps mon = \"allow r\"\n" );
	rbd_set_text ( &rbd_key_setting, text );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_BAD_KEY", "key" );

	/* The text cap: 1,024 bytes are looked at (a keyring with room for comments), 1,025 are too long */
	memset ( text, '#', sizeof ( text ) );
	pad = ( WR_RBURL_KEY_TEXT_MAX - 1 - 6 - strlen ( key_aes.b64 ) );
	snprintf ( &text[pad], ( sizeof ( text ) - pad ), "\nkey = %s", key_aes.b64 );
	rbd_set_text ( &rbd_key_setting, text );
	ok ( strlen ( text ) == WR_RBURL_KEY_TEXT_MAX );
	RBD_OK ( PLAIN );
	rbd_key_is ( spec, &key_aes );
	memset ( text, '#', sizeof ( text ) );
	pad++;
	snprintf ( &text[pad], ( sizeof ( text ) - pad ), "\nkey = %s", key_aes.b64 );
	rbd_set_text ( &rbd_key_setting, text );
	ok ( strlen ( text ) == ( WR_RBURL_KEY_TEXT_MAX + 1 ) );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_TOO_LONG", "key" );
	memset ( text, '#', WR_RBURL_KEY_TEXT_MAX );
	text[ WR_RBURL_KEY_TEXT_MAX ] = '\0';
	rbd_set_text ( &rbd_key_setting, text );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_BAD_KEY", "key" );
	memset ( text, '#', ( WR_RBURL_KEY_TEXT_MAX + 60 ) );
	text[ WR_RBURL_KEY_TEXT_MAX + 60 ] = '\0';
	rbd_set_text ( &rbd_key_setting, text );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_TOO_LONG", "key" );

	/* The key is never read from the URI: a password is refused, an option called "key" is unknown */
	rbd_set_text ( &rbd_key_setting, key_aes.b64 );
	RBD_BAD ( PLAIN "?key=AQAA", -EINVAL, "WR_E_RBURL_OPT_UNKNOWN",
		  "option" );

	rbd_set_none();
}

/* ---- the password ------------------------------------------------------------------------------------------------------ */

/** A password in the URI: refused, with the line the design promised, before anything else is looked at */
static void rbd_test_password ( void ) {
	static const char * const uris[] = {
		"rbd://zuser-leak:pw@10.77.9.9/zpool-leak/zimg-leak",
		"rbd://zuser-leak:@10.77.9.9/zpool-leak/zimg-leak",
		"rbd://:pw@10.77.9.9/zpool-leak/zimg-leak",
		"rbd://zuser-leak:pw@10.77.9.9:3300,10.77.0.11:3300/zpool-leak/zimg-leak",
		"rbd://zuser-leak:pw@10.77.9.9/zpool-leak/zimg-leak?mode=secure&ro=1",
		"rbd://zuser-leak:pw@[fd00::10]:3300/zpool-leak/zimg-leak",
		/* everything else wrong too: the password is still what is reported */
		"rbd://zuser-leak:pw@zhost-leak/",
		"rbd://zuser-leak:pw@zhost-leak/a/b/c?nonsense",
	};
	unsigned int i;

	/* With the settings in place, and with none: the refusal does not depend on them */
	rbd_set_default();
	for ( i = 0 ; i < ( sizeof ( uris ) / sizeof ( uris[0] ) ) ; i++ ) {
		RBD_BAD ( uris[i], -EINVAL, NULL, NULL );
		ok ( strcmp ( cap_buf, "rbd: key material must not be part of "
			      "the URI (use the rbd-key setting)\n" ) == 0 );
	}
	rbd_set_none();
	for ( i = 0 ; i < ( sizeof ( uris ) / sizeof ( uris[0] ) ) ; i++ ) {
		RBD_BAD ( uris[i], -EINVAL, NULL, NULL );
		ok ( strcmp ( cap_buf, "rbd: key material must not be part of "
			      "the URI (use the rbd-key setting)\n" ) == 0 );
	}
}

/* ---- the path ---------------------------------------------------------------------------------------------------------- */

/** The path: /pool/image, nothing else; a snapshot is understood and refused */
static void rbd_test_path ( void ) {
	struct rbd_spec *spec = t_spec;
	static char uri[ 64 + 3 * 200 ];
	static char name[ 200 ];

	rbd_set_default();

	RBD_OK ( "rbd://10.77.0.10/p/i" );
	ok ( strcmp ( spec->pool, "p" ) == 0 && strcmp ( spec->image, "i" ) == 0 );
	RBD_OK ( "rbd://10.77.0.10/pool.with-chars_1/image.with-chars_2" );
	ok ( strcmp ( spec->pool, "pool.with-chars_1" ) == 0 );
	ok ( strcmp ( spec->image, "image.with-chars_2" ) == 0 );

	/* The longest names the specification holds: 127 bytes, then 128 */
	memset ( name, 'n', ( RBD_NAME_MAX - 1 ) );
	name[ RBD_NAME_MAX - 1 ] = '\0';
	snprintf ( uri, sizeof ( uri ), "rbd://10.77.0.10/%s/%s", name, name );
	RBD_OK ( uri );
	ok ( strlen ( spec->pool ) == ( RBD_NAME_MAX - 1 ) );
	ok ( strlen ( spec->image ) == ( RBD_NAME_MAX - 1 ) );
	name[ RBD_NAME_MAX - 1 ] = 'n';
	name[ RBD_NAME_MAX ] = '\0';
	snprintf ( uri, sizeof ( uri ), "rbd://10.77.0.10/%s/zimg-leak", name );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_NAME_LONG", "pool" );
	snprintf ( uri, sizeof ( uri ), "rbd://10.77.0.10/zpool-leak/%s", name );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_NAME_LONG", "image" );

	/* Not /pool/image */
	RBD_BAD ( "rbd://10.77.0.10", -EINVAL, "WR_E_RBURL_PATH", "path" );
	RBD_BAD ( "rbd://10.77.0.10/", -EINVAL, "WR_E_RBURL_PATH", "path" );
	RBD_BAD ( "rbd://10.77.0.10/zpool-leak", -EINVAL, "WR_E_RBURL_PATH",
		  "path" );
	RBD_BAD ( "rbd://10.77.0.10/zpool-leak/", -EINVAL,
		  "WR_E_RBURL_NAME", "image" );
	RBD_BAD ( "rbd://10.77.0.10//zimg-leak", -EINVAL, "WR_E_RBURL_NAME",
		  "pool" );
	RBD_BAD ( "rbd://10.77.0.10/zpool-leak/zimg-leak/", -EINVAL,
		  "WR_E_RBURL_PATH", "path" );
	RBD_BAD ( "rbd://10.77.0.10/zpool-leak/ns/zimg-leak", -EINVAL,
		  "WR_E_RBURL_PATH", "path" );
	RBD_BAD ( "rbd://10.77.0.10/zpool-leak/zimg%20leak", -EINVAL,
		  "WR_E_RBURL_NAME", "image" );
	RBD_BAD ( "rbd://10.77.0.10/zpool-leak/zimg%2fleak", -EINVAL,
		  "WR_E_RBURL_PATH", "path" );

	/* A snapshot is parsed and validated, then refused: -ENOTSUP, not "bad URI" */
	RBD_BAD ( "rbd://10.77.0.10/zpool-leak/zimg-leak@zsnap-leak",
		  -ENOTSUP, "WR_E_UNSUPPORTED", "snapshot" );
	RBD_BAD ( "rbd://10.77.0.10/zpool-leak/zimg-leak@", -EINVAL,
		  "WR_E_RBURL_NAME", "snapshot" );
	RBD_BAD ( "rbd://10.77.0.10/zpool-leak/@zsnap-leak", -EINVAL,
		  "WR_E_RBURL_NAME", "image" );

	rbd_set_none();
}

/* ---- the options ------------------------------------------------------------------------------------------------------- */

/** A parse of the plain URI with one query */
#define OPT( query ) PLAIN "?" query

/** Every option, every accepted word and number; then what is refused */
static void rbd_test_options ( void ) {
	struct rbd_spec *spec = t_spec;

	rbd_set_default();

	/* mode */
	RBD_OK ( OPT ( "mode=crc" ) );
	ok ( spec->mode == WR_MODE_CRC_ONLY );
	RBD_OK ( OPT ( "mode=crc-first" ) );
	ok ( spec->mode == WR_MODE_CRC_FIRST );
	RBD_OK ( OPT ( "mode=secure-first" ) );
	ok ( spec->mode == WR_MODE_SECURE_FIRST );
	RBD_OK ( OPT ( "mode=secure" ) );
	ok ( spec->mode == WR_MODE_SECURE_ONLY );
	RBD_BAD ( OPT ( "mode=Secure" ), -EINVAL, "WR_E_RBURL_OPT_VALUE", "mode" );
	RBD_BAD ( OPT ( "mode=" ), -EINVAL, "WR_E_RBURL_OPT_VALUE", "mode" );

	/* ro */
	RBD_OK ( OPT ( "ro=1" ) );
	ok ( spec->read_only == 1 );
	RBD_OK ( OPT ( "ro=0" ) );
	ok ( spec->read_only == 0 );
	RBD_BAD ( OPT ( "ro=2" ), -EINVAL, "WR_E_RBURL_OPT_VALUE", "ro" );
	RBD_BAD ( OPT ( "ro=true" ), -EINVAL, "WR_E_RBURL_OPT_VALUE", "ro" );

	/* timeout, seconds, 1 to 600 */
	RBD_OK ( OPT ( "timeout=1" ) );
	ok ( spec->open_timeout_ms == 1000 );
	RBD_OK ( OPT ( "timeout=45" ) );
	ok ( spec->open_timeout_ms == 45000 );
	RBD_OK ( OPT ( "timeout=600" ) );
	ok ( spec->open_timeout_ms == 600000 );
	RBD_BAD ( OPT ( "timeout=0" ), -EINVAL, "WR_E_RBURL_OPT_RANGE", "timeout" );
	RBD_BAD ( OPT ( "timeout=601" ), -EINVAL, "WR_E_RBURL_OPT_RANGE", "timeout" );
	RBD_BAD ( OPT ( "timeout=-1" ), -EINVAL, "WR_E_RBURL_OPT_VALUE", "timeout" );
	RBD_BAD ( OPT ( "timeout=20s" ), -EINVAL, "WR_E_RBURL_OPT_VALUE", "timeout" );
	RBD_BAD ( OPT ( "timeout=" ), -EINVAL, "WR_E_RBURL_OPT_VALUE", "timeout" );

	/* readahead, KiB, 0 (off) to 16,384 */
	RBD_OK ( OPT ( "readahead=0" ) );
	ok ( spec->readahead_kib == 0 );
	RBD_OK ( OPT ( "readahead=512" ) );
	ok ( spec->readahead_kib == 512 );
	RBD_OK ( OPT ( "readahead=16384" ) );
	ok ( spec->readahead_kib == 16384 );
	RBD_BAD ( OPT ( "readahead=16385" ), -EINVAL, "WR_E_RBURL_OPT_RANGE",
		  "readahead" );
	RBD_BAD ( OPT ( "readahead=99999999999" ), -EINVAL,
		  "WR_E_RBURL_OPT_RANGE", "readahead" );

	/* fsid */
	RBD_OK ( OPT ( "fsid=01234567-89ab-cdef-fedc-ba9876543210" ) );
	ok ( spec->fsid_known == 1 );
	ok ( spec->fsid[0] == 0x01 && spec->fsid[1] == 0x23 &&
	     spec->fsid[7] == 0xef && spec->fsid[8] == 0xfe &&
	     spec->fsid[15] == 0x10 );
	RBD_OK ( OPT ( "fsid=01234567-89AB-CDEF-FEDC-BA9876543210" ) );
	ok ( spec->fsid_known == 1 && spec->fsid[1] == 0x23 &&
	     spec->fsid[15] == 0x10 );
	RBD_BAD ( OPT ( "fsid=01234567-89ab-cdef-fedc-ba987654321" ), -EINVAL,
		  "WR_E_RBURL_OPT_VALUE", "fsid" );
	RBD_BAD ( OPT ( "fsid=0123456789abcdeffedcba9876543210" ), -EINVAL,
		  "WR_E_RBURL_OPT_VALUE", "fsid" );
	RBD_BAD ( OPT ( "fsid=01234567-89ab-cdef-fedc-ba987654321g" ), -EINVAL,
		  "WR_E_RBURL_OPT_VALUE", "fsid" );

	/* devpath */
	RBD_OK ( OPT ( "devpath=vendor" ) );
	ok ( spec->devpath == RBD_DEVPATH_VENDOR );
	RBD_OK ( OPT ( "devpath=uri" ) );
	ok ( spec->devpath == RBD_DEVPATH_URI );
	RBD_OK ( OPT ( "devpath=sata" ) );
	ok ( spec->devpath == RBD_DEVPATH_SATA );
	RBD_BAD ( OPT ( "devpath=scsi" ), -EINVAL, "WR_E_RBURL_OPT_VALUE",
		  "devpath" );

	/* handoff */
	RBD_OK ( OPT ( "handoff=nokey" ) );
	ok ( spec->handoff == RBD_HANDOFF_NOKEY );
	RBD_OK ( OPT ( "handoff=key" ) );
	ok ( spec->handoff == RBD_HANDOFF_KEY );
	RBD_OK ( OPT ( "handoff=none" ) );
	ok ( spec->handoff == RBD_HANDOFF_NONE );
	RBD_BAD ( OPT ( "handoff=keys" ), -EINVAL, "WR_E_RBURL_OPT_VALUE",
		  "handoff" );

	/* The two sizing options: the core checks the numbers, the specification carries them when it has the room */
	RBD_BAD ( OPT ( "mapmem=15" ), -EINVAL, "WR_E_RBURL_OPT_RANGE", "mapmem" );
	RBD_BAD ( OPT ( "mapmem=16385" ), -EINVAL, "WR_E_RBURL_OPT_RANGE", "mapmem" );
	RBD_BAD ( OPT ( "monmsg=63" ), -EINVAL, "WR_E_RBURL_OPT_RANGE", "monmsg" );
	RBD_BAD ( OPT ( "monmsg=16385" ), -EINVAL, "WR_E_RBURL_OPT_RANGE", "monmsg" );
	RBD_BAD ( OPT ( "mapmem=abc" ), -EINVAL, "WR_E_RBURL_OPT_VALUE", "mapmem" );
#ifdef RBD_SPEC_HAS_MEM_OPTIONS
	RBD_OK ( OPT ( "mapmem=2048&monmsg=4096" ) );
	ok ( spec->mapmem_kib == 2048 && spec->monmsg_kib == 4096 );
	RBD_OK ( OPT ( "mapmem=16&monmsg=64" ) );
	ok ( spec->mapmem_kib == 16 && spec->monmsg_kib == 64 );
	RBD_OK ( OPT ( "mapmem=16384&monmsg=16384" ) );
	ok ( spec->mapmem_kib == 16384 && spec->monmsg_kib == 16384 );
	RBD_OK ( PLAIN );
	ok ( spec->mapmem_kib == 0 && spec->monmsg_kib == 0 );
#else
	/* Until struct rbd_spec has the two fields the options are refused, never accepted and ignored */
	RBD_BAD ( OPT ( "mapmem=2048" ), -ENOTSUP, "WR_E_UNSUPPORTED", "mapmem" );
	RBD_BAD ( OPT ( "monmsg=4096" ), -ENOTSUP, "WR_E_UNSUPPORTED", "monmsg" );
	RBD_BAD ( OPT ( "mapmem=16&monmsg=64" ), -ENOTSUP, "WR_E_UNSUPPORTED",
		  "mapmem" );
#endif

	/* Every option at once, in either order */
	RBD_OK ( OPT ( "mode=secure-first&ro=1&timeout=45&readahead=512&fsid=01234567-89ab-cdef-fedc-ba9876543210&devpath=sata&handoff=key" ) );
	ok ( spec->mode == WR_MODE_SECURE_FIRST && spec->read_only == 1 &&
	     spec->open_timeout_ms == 45000 && spec->readahead_kib == 512 &&
	     spec->fsid_known == 1 && spec->devpath == RBD_DEVPATH_SATA &&
	     spec->handoff == RBD_HANDOFF_KEY );
	RBD_OK ( OPT ( "handoff=key&devpath=sata&fsid=01234567-89ab-cdef-fedc-ba9876543210&readahead=512&timeout=45&ro=1&mode=secure-first" ) );
	ok ( spec->mode == WR_MODE_SECURE_FIRST && spec->read_only == 1 &&
	     spec->open_timeout_ms == 45000 && spec->readahead_kib == 512 &&
	     spec->handoff == RBD_HANDOFF_KEY );

	/* Names and values may be percent-encoded */
	RBD_OK ( OPT ( "%6dode=secure%2dfirst&r%6f=%31" ) );
	ok ( spec->mode == WR_MODE_SECURE_FIRST && spec->read_only == 1 );

	/* Fail closed: unknown, repeated, malformed */
	RBD_BAD ( OPT ( "nonsense=1" ), -EINVAL, "WR_E_RBURL_OPT_UNKNOWN", "option" );
	RBD_BAD ( OPT ( "Mode=crc" ), -EINVAL, "WR_E_RBURL_OPT_UNKNOWN", "option" );
	RBD_BAD ( OPT ( "ro=1&ro=1" ), -EINVAL, "WR_E_RBURL_OPT_DUP", "ro" );
	RBD_BAD ( OPT ( "mode=crc&timeout=5&mode=secure" ), -EINVAL,
		  "WR_E_RBURL_OPT_DUP", "mode" );
	RBD_BAD ( OPT ( "ro" ), -EINVAL, "WR_E_RBURL_OPT_SYNTAX", "option" );
	RBD_BAD ( OPT ( "=1" ), -EINVAL, "WR_E_RBURL_OPT_SYNTAX", "option" );
	RBD_BAD ( OPT ( "ro=1&" ), -EINVAL, "WR_E_RBURL_OPT_SYNTAX", "option" );
	RBD_BAD ( OPT ( "&ro=1" ), -EINVAL, "WR_E_RBURL_OPT_SYNTAX", "option" );
	RBD_BAD ( OPT ( "ro=%3" ), -EINVAL, "WR_E_RBURL_ESCAPE", "ro" );
	RBD_BAD ( OPT ( "ro=%zz" ), -EINVAL, "WR_E_RBURL_ESCAPE", "ro" );
	RBD_BAD ( OPT ( "ro=%00" ), -EINVAL, "WR_E_RBURL_ESCAPE", "ro" );

	/* The first mistake wins, whatever follows it, and nothing of the options before it is half applied */
	RBD_BAD ( OPT ( "mode=secure&timeout=0&nonsense=1" ), -EINVAL,
		  "WR_E_RBURL_OPT_RANGE", "timeout" );

	rbd_set_none();
}

/** A query longer than the parser accepts (1,024 bytes) */
static void rbd_test_query_limit ( void ) {
	static char uri[ 64 + WR_RBURL_QUERY_MAX + 64 ];
	size_t len;

	rbd_set_default();

	/* 1,024 bytes: a long run of repeated pairs reaches the option parser, which refuses the repeat... */
	len = snprintf ( uri, sizeof ( uri ), PLAIN "?" );
	memset ( &uri[len], 'x', WR_RBURL_QUERY_MAX );
	uri[ len + WR_RBURL_QUERY_MAX ] = '\0';
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_OPT_SYNTAX", "option" );

	/* ... 1,025 do not get that far */
	memset ( &uri[len], 'x', ( WR_RBURL_QUERY_MAX + 1 ) );
	uri[ len + WR_RBURL_QUERY_MAX + 1 ] = '\0';
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_TOO_LONG", "query" );

	rbd_set_none();
}

/* ---- the settings ------------------------------------------------------------------------------------------------------ */

/** The two settings are the ones iPXE knows by name, of the string type, and have the limits the parser says */
static void rbd_test_settings ( void ) {
	static char text[ WR_RBURL_KEY_TEXT_MAX + 64 ];
	struct setting *setting;

	/* Registered in iPXE's settings table, under their names */
	setting = find_setting ( "rbd-key" );
	ok ( setting == &rbd_key_setting );
	ok ( setting && ( setting->type == &setting_type_string ) );
	setting = find_setting ( "rbd-user" );
	ok ( setting == &rbd_user_setting );
	ok ( setting && ( setting->type == &setting_type_string ) );

	/* The user text is limited: 256 bytes are looked at, 257 are too long (and the error names the setting) */
	rbd_set_none();
	rbd_set_text ( &rbd_key_setting, key_aes.b64 );
	memset ( text, 'u', ( WR_RBURL_USER_TEXT_MAX + 1 ) );
	text[ WR_RBURL_USER_TEXT_MAX ] = '\0';
	rbd_set_text ( &rbd_user_setting, text );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_BAD_USER", "rbd-user" );
	memset ( text, 'u', ( WR_RBURL_USER_TEXT_MAX + 1 ) );
	text[ WR_RBURL_USER_TEXT_MAX + 1 ] = '\0';
	rbd_set_text ( &rbd_user_setting, text );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_TOO_LONG", "rbd-user" );
	memset ( text, 'u', ( WR_RBURL_USER_TEXT_MAX + 50 ) );
	text[ WR_RBURL_USER_TEXT_MAX + 50 ] = '\0';
	rbd_set_text ( &rbd_user_setting, text );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_TOO_LONG", "rbd-user" );

	/* The setting is only read when the URI has no user: a URI user hides a bad setting */
	RBD_OK ( "rbd://admin@10.77.0.10/zpool-leak/zimg-leak" );

	/* An empty value deletes a setting in iPXE: it is "not set" */
	rbd_set_text ( &rbd_user_setting, "" );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_NO_USER", "user" );
	rbd_set_text ( &rbd_user_setting, TEST_USER );
	rbd_set_text ( &rbd_key_setting, "" );
	RBD_BAD ( PLAIN, -EINVAL, "WR_E_RBURL_NO_KEY", "key" );

	/* Parsing leaves the settings as they were (the key is not consumed) */
	rbd_set_text ( &rbd_key_setting, key_aes.b64 );
	RBD_OK ( PLAIN );
	RBD_OK ( PLAIN );

	rbd_set_none();
}

/* ---- the canary ------------------------------------------------------------------------------------------------------- */

/**
 * No byte of a key, and no piece of the URI, reaches printf output
 *
 * Hostile input of every kind, with a real key in the settings and its text in places a careless message could echo it: in
 * the URI's password, user, host, path, options, as the user setting, as a corrupt key, as an over-long key.  rbd_runx()
 * checks, after every one of them, that exactly one line was printed (or none) and that the output holds no window of
 * either key and none of the leak words.
 */
static void rbd_test_canary ( void ) {
	static char uri[ 512 ];
	static char text[ WR_RBURL_KEY_TEXT_MAX + 64 ];
	const char *b64 = key_aes.b64;
	const char *b64_256 = key_256.b64;
	size_t i;

	rbd_set_none();
	rbd_set_text ( &rbd_user_setting, TEST_USER );
	rbd_set_text ( &rbd_key_setting, b64 );

	/* The key as the URI's password: refused with the fixed line, the key is not in it */
	snprintf ( uri, sizeof ( uri ), "rbd://client.admin:%s@10.77.9.9/zpool-leak/zimg-leak", b64 );
	RBD_BAD ( uri, -EINVAL, NULL, NULL );
	snprintf ( uri, sizeof ( uri ), "rbd://:%s@zhost-leak/zpool-leak", b64_256 );
	RBD_BAD ( uri, -EINVAL, NULL, NULL );

	/* The key where the user, the host, the path, an option name or a value goes */
	snprintf ( uri, sizeof ( uri ), "rbd://%s@10.77.9.9/zpool-leak", b64 );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_PATH", "path" );
	snprintf ( uri, sizeof ( uri ), "rbd://zuser-leak@%s/zpool-leak/zimg-leak", b64 );
	RBD_BAD ( uri, -EINVAL, "WR_E_MON_HOSTS_SYNTAX", "monitors" );
	snprintf ( uri, sizeof ( uri ), "rbd://zuser-leak@%s:3300,10.77.9.9/zpool-leak/zimg-leak", b64_256 );
	RBD_BAD ( uri, -EINVAL, "WR_E_MON_HOSTS_SYNTAX", "monitors" );
	snprintf ( uri, sizeof ( uri ), "rbd://zuser-leak@10.77.9.9/%s", b64 );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_PATH", "path" );
	snprintf ( uri, sizeof ( uri ), "rbd://zuser-leak@10.77.9.9/%s/%s@zsnap-leak", b64, b64_256 );
	RBD_BAD ( uri, -ENOTSUP, "WR_E_UNSUPPORTED", "snapshot" );
	snprintf ( uri, sizeof ( uri ), "rbd://zuser-leak@10.77.9.9/zpool-leak/zimg-leak?key=%s", b64 );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_OPT_UNKNOWN", "option" );
	snprintf ( uri, sizeof ( uri ), "rbd://zuser-leak@10.77.9.9/zpool-leak/zimg-leak?%s", b64 );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_OPT_SYNTAX", "option" );
	snprintf ( uri, sizeof ( uri ), "rbd://zuser-leak@10.77.9.9/zpool-leak/zimg-leak?mode=%s", b64 );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_OPT_VALUE", "mode" );
	snprintf ( uri, sizeof ( uri ), "rbd://zuser-leak@10.77.9.9/zpool-leak/zimg-leak?timeout=%s&ro=%s", b64, b64_256 );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_OPT_VALUE", "timeout" );
	snprintf ( uri, sizeof ( uri ), "rbd://zuser-leak@10.77.9.9/zpool-leak/zimg-leak?fsid=%s", b64 );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_OPT_VALUE", "fsid" );
	snprintf ( uri, sizeof ( uri ), "rbd://zuser-leak@10.77.9.9/zpool-leak/zimg-leak?%s=1", b64_256 );
	RBD_BAD ( uri, -EINVAL, "WR_E_RBURL_OPT_UNKNOWN", "option" );

	/* A key used as the user id is a valid id: the parse works, and says nothing (the user is not printed on success either) */
	snprintf ( uri, sizeof ( uri ), "rbd://%s@10.77.9.9/zpool-leak/zimg-leak", b64 );
	RBD_OK ( uri );

	/* The key in the user setting, in a form the user parser refuses */
	snprintf ( text, sizeof ( text ), "%s!", b64 );
	rbd_set_text ( &rbd_user_setting, text );
	RBD_BAD ( "rbd://10.77.9.9/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_BAD_USER", "rbd-user" );
	memset ( text, 0, sizeof ( text ) );
	for ( i = 0 ; i < 6 ; i++ )
		strcat ( text, b64 );
	rbd_set_text ( &rbd_user_setting, text );
	RBD_BAD ( "rbd://10.77.9.9/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_BAD_USER", "rbd-user" );
	rbd_set_text ( &rbd_user_setting, TEST_USER );

	/* A corrupt key, a truncated key, a keyring that does not decode, a key followed by junk, too much text */
	rbd_text_cut ( text, sizeof ( text ), "", b64, 30, "" );
	rbd_set_text ( &rbd_key_setting, text );
	RBD_BAD ( "rbd://10.77.9.9/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_BAD_KEY", "key" );
	rbd_text_cut ( text, sizeof ( text ), "key = ", b64_256, 44, "" );
	rbd_set_text ( &rbd_key_setting, text );
	RBD_BAD ( "rbd://10.77.9.9/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_BAD_KEY", "key" );
	snprintf ( text, sizeof ( text ), "%s %s junk", b64, b64_256 );
	rbd_set_text ( &rbd_key_setting, text );
	RBD_BAD ( "rbd://10.77.9.9/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_BAD_KEY", "key" );
	memset ( text, 0, sizeof ( text ) );
	for ( i = 0 ; i < 27 ; i++ )
		strcat ( text, b64 );
	rbd_set_text ( &rbd_key_setting, text );
	RBD_BAD ( "rbd://10.77.9.9/zpool-leak/zimg-leak", -EINVAL,
		  "WR_E_RBURL_TOO_LONG", "key" );

	/* And the valid key, with every success path, prints nothing at all (rbd_runx checks it) */
	rbd_set_text ( &rbd_key_setting, b64_256 );
	RBD_OK ( "rbd://10.77.9.9/zpool-leak/zimg-leak" );
	rbd_key_is ( t_spec, &key_256 );
	rbd_set_text ( &rbd_key_setting, b64 );
	RBD_OK ( "rbd://10.77.9.9,10.77.0.11/zpool-leak/zimg-leak?mode=secure&ro=1" );
	rbd_key_is ( t_spec, &key_aes );

	/* The canary must be able to fail: a line that holds a window of the key is seen by cap_free_of_key() */
	rbd_text_cut ( text, sizeof ( text ), "rbd: oops ", &b64[22], 30, "\n" );
	cap_start_quiet();
	printf ( "%s", text );
	cap_stop();
	ok ( ! cap_free_of_key ( &key_aes ) );
	rbd_text_cut ( text, sizeof ( text ), "rbd: oops ", key_256.secret, 12, "\n" );
	cap_start_quiet();
	printf ( "%s", text );
	cap_stop();
	ok ( ! cap_free_of_key ( &key_256 ) );
	cap_start();
	printf ( "rbd: nothing of the key\n" );
	cap_stop();
	ok ( cap_free_of_key ( &key_aes ) && cap_free_of_key ( &key_256 ) );

	rbd_set_none();
}

/* ---- wiping ------------------------------------------------------------------------------------------------------------ */

/** The specification and the working area are zeroed: rbd_spec_wipe(), rbd_uri_wipe(), every path of rbd_uri_parse() */
static void rbd_test_wipe ( void ) {
	struct rbd_spec *spec = t_spec;
	uint8_t buf[ 37 ];
	size_t i;

	/* rbd_uri_wipe() zeroes exactly what it is given, of any length and alignment */
	for ( i = 0 ; i < sizeof ( buf ) ; i++ ) {
		memset ( buf, 0xa5, sizeof ( buf ) );
		rbd_uri_wipe ( &buf[1], i );
		ok ( rbd_nonzero ( &buf[1], i ) == 0 );
		ok ( buf[0] == 0xa5 );
		if ( ( 1 + i ) < sizeof ( buf ) )
			ok ( buf[ 1 + i ] == 0xa5 );
	}

	/* A successful parse holds the key; wiping the specification takes all of it */
	rbd_set_default();
	RBD_OK ( PLAIN "?mode=secure&ro=1" );
	rbd_key_is ( spec, &key_aes );
	ok ( rbd_nonzero ( spec, sizeof ( *spec ) ) != 0 );
	rbd_spec_wipe ( spec );
	ok ( rbd_nonzero ( spec, sizeof ( *spec ) ) == 0 );
	ok ( spec->key.len == 0 && spec->key.type == 0 );
	rbd_spec_wipe ( spec );
	ok ( rbd_nonzero ( spec, sizeof ( *spec ) ) == 0 );

	/* Whatever was in the specification before the parse is gone, on success and on failure (rbd_runx starts from 0xa5) */
	RBD_OK ( PLAIN );
	ok ( rbd_nonzero ( spec->snap, sizeof ( spec->snap ) ) == 0 );
	ok ( rbd_nonzero ( spec->pool + strlen ( spec->pool ),
			   ( sizeof ( spec->pool ) - strlen ( spec->pool ) ) ) == 0 );
	ok ( rbd_nonzero ( spec->user + strlen ( spec->user ),
			   ( sizeof ( spec->user ) - strlen ( spec->user ) ) ) == 0 );

	/* Failures after the key was parsed (the key text was in the working area, the key in the parsed spec) */
	RBD_BAD ( PLAIN "?nonsense=1", -EINVAL, "WR_E_RBURL_OPT_UNKNOWN", "option" );
	RBD_BAD ( "rbd://10.77.0.10/zpool-leak/zimg-leak@zsnap-leak", -ENOTSUP,
		  "WR_E_UNSUPPORTED", "snapshot" );
	RBD_BAD ( "rbd://zuser-leak:pw@10.77.0.10/zpool-leak/zimg-leak", -EINVAL,
		  NULL, NULL );

	/* The opener's entry point: the same parse in a working area of its own (heap), nothing left in the result on failure */
	{
		struct uri *uri;

		memset ( spec, 0xa5, sizeof ( *spec ) );
		uri = parse_uri ( PLAIN );
		ok ( uri != NULL );
		if ( uri ) {
			cap_start();
			ok ( rbd_parse_uri ( uri, spec ) == 0 );
			cap_stop();
			ok ( cap_len == 0 );
			rbd_key_is ( spec, &key_aes );
			ok ( strcmp ( spec->pool, "zpool-leak" ) == 0 );
			uri_put ( uri );
		}
		memset ( spec, 0xa5, sizeof ( *spec ) );
		uri = parse_uri ( "rbd://10.77.0.10/zpool-leak" );
		ok ( uri != NULL );
		if ( uri ) {
			cap_start();
			ok ( rbd_same_error ( rbd_parse_uri ( uri, spec ),
					      -EINVAL ) );
			cap_stop();
			ok ( cap_lines() == 1 );
			ok ( rbd_nonzero ( spec, sizeof ( *spec ) ) == 0 );
			uri_put ( uri );
		}
		rbd_spec_wipe ( spec );
	}

	rbd_set_none();
}

/* ---- the heap, and the opener ----------------------------------------------------------------------------------------- */

/** Size of the chunks the heap walk takes (a multiple of the allocator's alignment) */
#define HEAP_CHUNK 4096

/** A chunk taken by the heap walk (only the first bytes are used, after the chunk has been looked at) */
struct heap_chunk {
	/** Next chunk taken */
	struct heap_chunk *next;
};

/** Length of the pieces of a secret that the heap walk looks for (a header the allocator writes may cut some, never all) */
#define HEAP_WINDOW 6

/**
 * Check whether a chunk holds a window of a secret
 *
 * @v chunk		Chunk
 * @v key		Test key
 * @ret found		A window of the secret is in the chunk
 */
static int rbd_chunk_has_key ( const uint8_t *chunk,
			       const struct rbd_test_key *key ) {
	size_t i;
	size_t w;

	for ( w = 0 ; ( w + HEAP_WINDOW ) <= key->len ; w++ ) {
		for ( i = 0 ; ( i + HEAP_WINDOW ) <= HEAP_CHUNK ; i++ ) {
			if ( ( chunk[i] == ( uint8_t ) key->secret[w] ) &&
			     ( memcmp ( &chunk[i], &key->secret[w],
					HEAP_WINDOW ) == 0 ) )
				return 1;
		}
	}
	return 0;
}

/**
 * Take all the free memory of the heap in chunks, look at it, and give it back
 *
 * @v found		Number of chunks that hold a window of either test key's (decoded) secret
 * @v clear		Zero every chunk before it is given back
 * @ret chunks		Number of chunks the heap could give
 *
 * malloc() does not clear what it hands out, so what a free() left behind is what this reads.  The base64 text of a key
 * is not looked for: the settings store keeps it by design (and iPXE does not wipe a deleted setting); the decoded secret
 * exists only in the specification and in the working area, and must exist nowhere once they are wiped and freed.
 * The count is the heap's free space in 4 kB steps, which is how a run is shown to leak nothing.
 */
static size_t rbd_heap_walk ( unsigned int *found, int clear ) {
	struct heap_chunk *list = NULL;
	struct heap_chunk *chunk;
	size_t chunks = 0;

	*found = 0;
	while ( ( chunk = malloc ( HEAP_CHUNK ) ) != NULL ) {
		if ( rbd_chunk_has_key ( ( const uint8_t * ) chunk, &key_aes ) ||
		     rbd_chunk_has_key ( ( const uint8_t * ) chunk, &key_256 ) )
			( *found )++;
		if ( clear )
			memset ( chunk, 0, HEAP_CHUNK );
		chunk->next = list;
		list = chunk;
		chunks++;
	}
	while ( list ) {
		chunk = list;
		list = chunk->next;
		free ( chunk );
	}
	return chunks;
}

/**
 * Take every chunk of a size that the heap can still give
 *
 * @v size		Chunk size
 * @v list		List of chunks taken so far (the new ones are added in front)
 * @ret list		Chunks taken (give them back with rbd_heap_release())
 */
static struct heap_chunk * rbd_heap_take ( size_t size,
					   struct heap_chunk *list ) {
	struct heap_chunk *chunk;

	while ( ( chunk = malloc ( size ) ) != NULL ) {
		chunk->next = list;
		list = chunk;
	}
	return list;
}

/**
 * Give back chunks taken by rbd_heap_take()
 *
 * @v list		Chunks
 */
static void rbd_heap_release ( struct heap_chunk *list ) {
	struct heap_chunk *chunk;

	while ( list ) {
		chunk = list;
		list = chunk->next;
		free ( chunk );
	}
}

/**
 * Open a URI string through iPXE's opener table, as "sanhook" does
 *
 * @v string		URI string
 * @ret rc		Return status code
 *
 * Only for URIs that the opener refuses before it asks for a session: a URI that parses reaches rbd_session_open(), which
 * is the cluster session's (and, in the finished driver, opens connections).
 */
static int rbd_open_string ( const char *string ) {

	return xfer_open_uri_string ( &null_intf, string );
}

/** The opener: found by its scheme the way iPXE finds it, and every refusal ends the open with nothing left behind */
static void rbd_test_open ( void ) {
	unsigned int found;
	size_t base;
	size_t after;
	unsigned int i;
	int rc;

	rbd_set_default();
	rbd_spec_wipe ( t_spec );
	rbd_uri_wipe ( t_work, sizeof ( *t_work ) );

	/* The heap walk can see what it looks for: a secret left in freed memory is found, and clearing removes it */
	{
		uint8_t *plant = malloc ( ( 2 * HEAP_CHUNK ) );

		ok ( plant != NULL );
		if ( plant ) {
			memset ( plant, 0x5a, ( 2 * HEAP_CHUNK ) );
			memcpy ( &plant[ 1000 ], key_256.secret, key_256.len );
			memcpy ( &plant[ HEAP_CHUNK + 1500 ], key_aes.secret,
				 key_aes.len );
			free ( plant );
		}
	}
	base = rbd_heap_walk ( &found, 1 );
	ok ( found >= 1 );
	ok ( base > 16 );
	ok ( rbd_heap_walk ( &found, 0 ) == base );
	ok ( found == 0 );

	/* The scheme is found the way iPXE finds every one: without regard to case.  Both reach the parser (the refusal
	 * is the opener's own line, not "unsupported"); the status is the parser's, and the line is the one line
	 */
	cap_start();
	rc = rbd_open_string ( "rbd://zuser-leak:pw@10.77.9.9/zpool-leak/zimg-leak" );
	cap_stop();
	ok ( rbd_same_error ( rc, -EINVAL ) );
	ok ( cap_lines() == 1 );
	ok ( cap_has ( "key material must not be part of the URI" ) );
	cap_start();
	rc = rbd_open_string ( "RBD://zuser-leak:pw@10.77.9.9/zpool-leak/zimg-leak" );
	cap_stop();
	ok ( rbd_same_error ( rc, -EINVAL ) );
	ok ( cap_lines() == 1 );
	ok ( cap_has ( "key material must not be part of the URI" ) );
	cap_start();
	rc = rbd_open_string ( "rbd://10.77.0.10/zpool-leak" );
	cap_stop();
	ok ( rbd_same_error ( rc, -EINVAL ) );
	ok ( cap_lines() == 1 );
	ok ( cap_has ( "(WR_E_RBURL_PATH)" ) );
	cap_start();
	rc = rbd_open_string ( "rbd://10.77.0.10/zpool-leak/zimg-leak@zsnap-leak" );
	cap_stop();
	ok ( rbd_same_error ( rc, -ENOTSUP ) );
	ok ( cap_lines() == 1 );
	ok ( cap_has ( "(WR_E_UNSUPPORTED)" ) );

	/* A scheme that is not ours is not ours (the stock iPXE answer, and no line from this driver) */
	cap_start();
	rc = rbd_open_string ( "rbdx://10.77.0.10/zpool-leak/zimg-leak" );
	cap_stop();
	ok ( rbd_same_error ( rc, -ENOTSUP ) );
	ok ( cap_len == 0 );

	/* A run of parses and refusals (the key is parsed, then something after it is wrong, or everything is right):
	 * the heap is the size it was, and none of the freed memory holds a byte of either decoded key
	 */
	for ( i = 0 ; i < 64 ; i++ ) {
		struct uri *uri_parsed;

		cap_start();
		uri_parsed = parse_uri ( PLAIN "?mode=secure&ro=1" );
		if ( uri_parsed ) {
			ok ( rbd_parse_uri ( uri_parsed, t_spec ) == 0 );
			rbd_spec_wipe ( t_spec );
			uri_put ( uri_parsed );
		}
		uri_parsed = parse_uri ( PLAIN "@zsnap-leak" );
		if ( uri_parsed ) {
			ok ( rbd_parse_uri ( uri_parsed, t_spec ) != 0 );
			uri_put ( uri_parsed );
		}
		( void ) rbd_open_string ( PLAIN "?nonsense=1" );
		( void ) rbd_open_string ( PLAIN "@zsnap-leak" );
		( void ) rbd_open_string ( "rbd://10.77.0.10/zpool-leak" );
		( void ) rbd_open_string ( "rbd://zuser-leak:pw@10.77.9.9/zpool-leak/zimg-leak" );
		( void ) rbd_open_string ( "rbd://zhost-leak/zpool-leak/zimg-leak" );
		cap_stop();
		ok ( ! cap_full );
		ok ( cap_lines() == 6 );
	}
	rbd_set_text ( &rbd_key_setting, key_256.b64 );
	for ( i = 0 ; i < 16 ; i++ ) {
		struct uri *uri_parsed;

		cap_start();
		uri_parsed = parse_uri ( PLAIN "?devpath=uri" );
		if ( uri_parsed ) {
			ok ( rbd_parse_uri ( uri_parsed, t_spec ) == 0 );
			rbd_spec_wipe ( t_spec );
			uri_put ( uri_parsed );
		}
		( void ) rbd_open_string ( PLAIN "@zsnap-leak" );
		cap_stop();
		ok ( ! cap_full );
		ok ( cap_lines() == 1 );
	}
	after = rbd_heap_walk ( &found, 0 );
	ok ( found == 0 );
	ok ( after + 4 >= base );

	/* Out of memory: the parse and the opener each say so, with one line, a status that is -ENOMEM, and nothing
	 * left in the specification.  The URI is parsed first (the opener needs no memory to be handed an absolute URI);
	 * then the heap is taken, so that the first allocation of each entry point fails.
	 */
	{
		struct uri *uri_parsed = parse_uri ( PLAIN );
		struct heap_chunk *big;
		struct heap_chunk *small;
		void *pad;

		ok ( uri_parsed != NULL );
		if ( uri_parsed ) {
			big = rbd_heap_take ( HEAP_CHUNK, NULL );
			small = rbd_heap_take ( 64, NULL );
			memset ( t_spec, 0xa5, sizeof ( *t_spec ) );
			cap_start();
			rc = rbd_parse_uri ( uri_parsed, t_spec );
			cap_stop();
			ok ( rbd_same_error ( rc, -ENOMEM ) );
			ok ( cap_lines() == 1 );
			ok ( cap_has ( "out of memory" ) );
			ok ( rbd_nonzero ( t_spec, sizeof ( *t_spec ) ) == 0 );
			cap_start();
			rc = xfer_open_uri ( &null_intf, uri_parsed );
			cap_stop();
			ok ( rbd_same_error ( rc, -ENOMEM ) );
			ok ( cap_lines() == 1 );
			ok ( cap_has ( "out of memory" ) );

			/* Room for the opener's specification (about 0.8 kB) but not for the parser's working area
			 * (about 3.3 kB): one 4 kB chunk comes back, 2.3 kB of it is held, 1.7 kB is free.  The
			 * opener's own allocation is released and the status is the parser's.
			 */
			ok ( big != NULL );
			if ( big ) {
				struct heap_chunk *one = big;

				big = big->next;
				free ( one );
				pad = malloc ( 2300 );
				ok ( pad != NULL );
				memset ( t_spec, 0xa5, sizeof ( *t_spec ) );
				cap_start();
				rc = xfer_open_uri ( &null_intf, uri_parsed );
				cap_stop();
				ok ( rbd_same_error ( rc, -ENOMEM ) );
				ok ( cap_lines() == 1 );
				ok ( cap_has ( "parse URI failed: out of memory" ) );
				free ( pad );
			}
			rbd_heap_release ( small );
			rbd_heap_release ( big );
			uri_put ( uri_parsed );
		}
	}
	after = rbd_heap_walk ( &found, 0 );
	ok ( found == 0 );
	ok ( after + 4 >= base );

	rbd_set_none();
}

/** Connect attempts of the fake sockets of the success-path test (the session is never run: no attempt is expected) */
static unsigned int rbd_test_connects;

/**
 * Open a socket (fake: there is no network in a self-test)
 *
 * @v intf		Socket interface (unused)
 * @v peer		Peer (unused)
 * @ret rc		Return status code
 */
static int rbd_test_conn_open ( struct interface *intf __unused, struct sockaddr *peer __unused ) {

	rbd_test_connects++;
	return -ENETUNREACH;
}

/**
 * Close the parent interface of the success-path test
 *
 * @v intf		Parent interface
 * @v rc		Reason
 */
static void rbd_test_parent_close ( struct interface *intf, int rc __unused ) {

	/* Nothing hangs off the parent: the device's close ends here */
	intf_restart ( intf, 0 );
}

/** Operations of the parent interface */
static struct interface_operation rbd_test_parent_ops[] = {
	INTF_OP ( intf_close, struct interface *, rbd_test_parent_close ),
};

/** Descriptor of the parent interface: a pure interface, standing in for the SAN path's */
static struct interface_descriptor rbd_test_parent_desc = INTF_DESC_PURE ( rbd_test_parent_ops );

/** Rounds of the success-path test per handoff mode */
#define RBD_OPEN_ROUNDS 8

/**
 * The opener's success path: the real parse, the real session on the real core, a device, and everything it frees on the way out
 *
 * Every other test of the opener stops at a refusal, before a session is asked for, so the code after a successful open (the
 * specification, which holds the decoded cephx key, is wiped and freed) was never run by a test: a wipe taken out of it left every
 * test green. Here the opener runs on a session environment whose sockets are fake (the session is created, the image opens, no
 * byte is sent), the device is attached to a stand-in for the SAN path, and then the path is closed, the session destroyed, and the free
 * heap searched for a window of the key's secret. A key that is kept for the table (handoff=key) must be gone too once the device lets go.
 */
static void rbd_test_open_success ( void ) {
	static const char * const handoffs[] = { "nokey", "key" };
	struct rbd_session_env env;
	struct rbd_conn_ops conn_ops = rbd_conn_default_ops;
	struct interface parent;
	struct rbd_session *session;
	struct rbd_session *tmp;
	struct uri *uri;
	char string[128];
	unsigned int found;
	unsigned int n_sessions;
	unsigned int i;
	size_t base;
	size_t after = 0;
	int rc;

	rbd_set_default();
	memset ( &env, 0, sizeof ( env ) );
	conn_ops.open = rbd_test_conn_open;
	env.conn = &conn_ops;
	rbd_test_connects = 0;

	/* What the heap holds before: anything an earlier test left is cleared first */
	base = rbd_heap_walk ( &found, 1 );
	ok ( base > 16 );

	/* Several rounds of each: a reference or a block that one open leaks is too small to see in the heap once, not eight times */
	for ( i = 0 ; i < ( 2 * RBD_OPEN_ROUNDS ) ; i++ ) {
		snprintf ( string, sizeof ( string ),
			   "rbd://" TEST_USER "@10.77.0.10:3300/zpool-leak/zimg-leak?handoff=%s",
			   handoffs[ i / RBD_OPEN_ROUNDS ] );
		uri = parse_uri ( string );
		ok ( uri != NULL );
		if ( ! uri )
			continue;
		intf_init ( &parent, &rbd_test_parent_desc, NULL );
		cap_start();
		rc = rbd_open_with ( &env, &parent, uri );
		cap_stop();
		uri_put ( uri );
		ok ( rc == 0 );
		ok ( cap_len == 0 );

		/* One session, one device on it; the key is held by the session only for the table */
		n_sessions = 0;
		list_for_each_entry ( session, &rbd_sessions, list ) {
			n_sessions++;
			ok ( session->ndev == 1 );
			ok ( session->key_kept == ( ( i / RBD_OPEN_ROUNDS ) == 1 ) );
		}
		ok ( n_sessions == 1 );

		/* The SAN layer lets go of the path: the device detaches (and the key kept for the table is wiped) */
		intf_shutdown ( &parent, 0 );
		list_for_each_entry ( session, &rbd_sessions, list ) {
			ok ( session->ndev == 0 );
			ok ( session->key_kept == 0 );
			ok ( ses_key_is_zero ( &session->key ) );
		}

		/* Destroyed at once (the grace period is 120 s): nothing is left of the session */
		list_for_each_entry_safe ( session, tmp, &rbd_sessions, list )
			rbd_session_destroy ( session );
		ok ( list_empty ( &rbd_sessions ) );
		after = rbd_heap_walk ( &found, 0 );
		ok ( found == 0 );
		ok ( after + 4 >= base );
	}
	ok ( after == base );
	ok ( rbd_test_connects == 0 );

	rbd_set_none();
}

/* ---- status mapping ---------------------------------------------------------------------------------------------------- */

/**
 * The text of the URI for the "uri" device path: taken only when asked for, and a path can be built from it
 *
 * The first measured UEFI run found that "devpath=uri" could never work: the opener never gave the specification a URI, so the
 * device path code had nothing to put into its node and the SAN hook failed with "cannot build the EFI device path".
 */
static void rbd_test_uri_text ( void ) {
	struct uri *uri_parsed;
	struct rbd_efi_ident ident;
	char *text;
	char *keep;
	char red[ 256 ];
	size_t len;
	size_t node_len;
	uint8_t node[ 512 ];

	rbd_set_default();
	rbd_set_text ( &rbd_key_setting, key_256.b64 );

	/* The default flavour needs no text: nothing is allocated, the specification borrows nothing */
	uri_parsed = parse_uri ( PLAIN );
	ok ( uri_parsed != NULL );
	if ( uri_parsed ) {
		ok ( rbd_parse_uri ( uri_parsed, t_spec ) == 0 );
		t_spec->uri = ( const char * ) t_spec;	/* (must be reset, not kept) */
		text = ( char * ) t_spec;
		ok ( rbd_uri_text ( uri_parsed, t_spec, &text ) == 0 );
		ok ( text == NULL );
		ok ( t_spec->uri == NULL );
		rbd_spec_wipe ( t_spec );
		uri_put ( uri_parsed );
	}

	/* devpath=uri: the text is the URI with what the user wrote, no key, and the specification borrows it */
	uri_parsed = parse_uri ( "rbd://wruser@10.77.0.10:3300,10.77.0.11:3300/zpool-leak/zimg-leak?devpath=uri&mode=crc&timeout=20" );
	ok ( uri_parsed != NULL );
	if ( uri_parsed ) {
		ok ( rbd_parse_uri ( uri_parsed, t_spec ) == 0 );
		ok ( t_spec->devpath == RBD_DEVPATH_URI );
		text = NULL;
		ok ( rbd_uri_text ( uri_parsed, t_spec, &text ) == 0 );
		ok ( text != NULL );
		ok ( t_spec->uri == text );
		if ( text ) {
			ok ( strncmp ( text, "rbd://wruser@10.77.0.10:3300,10.77.0.11:3300/zpool-leak/zimg-leak?", 66 ) == 0 );
			ok ( strstr ( text, key_256.b64 ) == NULL );
			ok ( strstr ( text, "devpath=uri" ) != NULL );

			/* The device path can be built from it: the node is long enough for the URI, the redaction keeps the known
			 * options (and would drop one it does not know) */
			len = rbd_efi_uri_redact ( text, red, sizeof ( red ) );
			ok ( len > 0 );
			ok ( strncmp ( red, "rbd://wruser@", 13 ) == 0 );
			ok ( strstr ( red, "timeout=20" ) != NULL );
			ok ( strstr ( red, "mode=crc" ) != NULL );
			memset ( &ident, 0, sizeof ( ident ) );
			ident.devpath = RBD_DEVPATH_URI;
			ident.pool = t_spec->pool;
			ident.image = t_spec->image;
			ident.uri = t_spec->uri;
			node_len = rbd_efi_node_len ( &ident );
			ok ( node_len > ( len + 1 ) );
			ok ( rbd_efi_node_build ( &ident, node, sizeof ( node ) ) == node_len );

			/* Without the text (what every build before this fix did) the node cannot be described */
			ident.uri = NULL;
			ok ( rbd_efi_node_len ( &ident ) == 0 );
		}
		keep = text;
		rbd_spec_wipe ( t_spec );
		ok ( t_spec->uri == NULL );
		free ( keep );
		uri_put ( uri_parsed );
	}

	/* Out of memory is an error with its one line, and nothing is left borrowed */
	uri_parsed = parse_uri ( PLAIN "?devpath=uri" );
	ok ( uri_parsed != NULL );
	if ( uri_parsed ) {
		struct heap_chunk *big;
		struct heap_chunk *small;

		ok ( rbd_parse_uri ( uri_parsed, t_spec ) == 0 );
		big = rbd_heap_take ( HEAP_CHUNK, NULL );
		small = rbd_heap_take ( 64, NULL );
		cap_start();
		text = ( char * ) t_spec;
		ok ( rbd_same_error ( rbd_uri_text ( uri_parsed, t_spec, &text ), -ENOMEM ) );
		cap_stop();
		ok ( text == NULL );
		ok ( t_spec->uri == NULL );
		ok ( cap_lines() == 1 );
		ok ( cap_has ( "out of memory" ) );
		rbd_heap_release ( small );
		rbd_heap_release ( big );
		rbd_spec_wipe ( t_spec );
		uri_put ( uri_parsed );
	}
	rbd_set_none();
}

/**
 * The console lines of a failed open that need what the cluster answered (a refused login, an image with features we cannot use)
 *
 * One line each, and the line says what to do about it: the first measured runs gave "mask in a0" for an image made with the
 * default features, and a wrong key looked like a broken conversation.
 */
static void rbd_test_report ( void ) {

	/* A refused login: the answer tells the key from the mode */
	cap_start();
	rbd_report_peer ( "open", WR_E_M2_BAD_METHOD, -13, 0 );
	cap_stop();
	ok ( cap_lines() == 1 );
	ok ( cap_has ( "(WR_E_M2_BAD_METHOD; the cluster answered -13)" ) );
	ok ( cap_has ( "check the key" ) );
	cap_start();
	rbd_report_peer ( "open", WR_E_M2_BAD_METHOD, -95, 0 );
	cap_stop();
	ok ( cap_lines() == 1 );
	ok ( cap_has ( "answered -95" ) );
	ok ( cap_has ( "connection mode" ) );
	ok ( ! cap_has ( "check the key" ) );

	/* The default features of a new image: named, one line */
	cap_start();
	rbd_report_peer ( "open", WR_E_RBD_FEATURES, 0, ( 4 | 8 | 16 ) );
	cap_stop();
	ok ( cap_lines() == 1 );
	ok ( cap_has ( "exclusive-lock object-map fast-diff" ) );
	ok ( cap_has ( "layering feature only" ) );
	ok ( ! cap_has ( ": layering" ) );
	cap_start();
	rbd_report_peer ( "open", WR_E_RBD_FEATURES, 0, ( ( uint64_t ) 1 << 40 ) | 128 );
	cap_stop();
	ok ( cap_lines() == 1 );
	ok ( cap_has ( "data-pool bit40" ) );

	/* Every other status is the plain line of rbd_report() */
	cap_start();
	rbd_report_peer ( "open", WR_E_TIMEOUT, -13, 4 );
	cap_stop();
	ok ( cap_lines() == 1 );
	ok ( cap_has ( "(WR_E_TIMEOUT)" ) );
	ok ( ! cap_has ( "answered" ) );
}

/** The parser's statuses are all "bad URI"; the others keep the table of rbd_errors.c */
static void rbd_test_rc ( void ) {
	wr_status status;

	ok ( rbd_uri_rc ( WR_OK ) == 0 );

	/* Every status of the parser's block, including the reserved numbers after the last one */
#define RBD_URI_TEST_STATUS( name, code, text )				\
	ok ( rbd_same_error ( rbd_uri_rc ( name ), -EINVAL ) );
	WR_RBURL_STATUS_LIST ( RBD_URI_TEST_STATUS )
#undef RBD_URI_TEST_STATUS
	for ( status = -260 ; status >= -279 ; status-- )
		ok ( rbd_same_error ( rbd_uri_rc ( status ), -EINVAL ) );

	/* The monitor list's statuses, which the parser passes through unchanged, and the generic bad argument */
	ok ( rbd_same_error ( rbd_uri_rc ( WR_E_MON_HOSTS_SYNTAX ), -EINVAL ) );
	ok ( rbd_same_error ( rbd_uri_rc ( WR_E_MON_NO_V2_ADDR ), -EINVAL ) );
	ok ( rbd_same_error ( rbd_uri_rc ( WR_E_INVAL ), -EINVAL ) );

	/* A snapshot (the core cannot open one yet) is "not supported", not "bad" */
	ok ( rbd_same_error ( rbd_uri_rc ( WR_E_UNSUPPORTED ), -ENOTSUP ) );

	/* The rest is the table of rbd_errors.c, unchanged */
	ok ( rbd_same_error ( rbd_uri_rc ( WR_E_BUDGET ), -ENOMEM ) );
	ok ( rbd_same_error ( rbd_uri_rc ( WR_E_AUTH_DENIED ), -EACCES ) );
	ok ( rbd_same_error ( rbd_uri_rc ( WR_E_TIMEOUT ), -ETIMEDOUT ) );

	/* The status just outside the block is not swallowed by it */
	ok ( rbd_same_error ( rbd_uri_rc ( -259 ), -EPROTO ) );
	ok ( rbd_same_error ( rbd_uri_rc ( -280 ), -EPROTO ) );

	/* The parser's own text functions know every one of them (the console line is made of them) */
#define RBD_URI_TEST_TEXT( name, code, text )				\
	ok ( strcmp ( wr_rburl_strerror ( name ), text ) == 0 );	\
	ok ( strcmp ( wr_rburl_status_name ( name ), #name ) == 0 );
	WR_RBURL_STATUS_LIST ( RBD_URI_TEST_TEXT )
#undef RBD_URI_TEST_TEXT
}

/* ---- the entry ---------------------------------------------------------------------------------------------------------- */

/**
 * Perform the URI opener self-tests
 *
 */
static void rbd_uri_test_exec ( void ) {

	/* The test keys, and the specification and working area every run uses (heap: they are large) */
	rbd_test_key_build ( &key_aes );
	rbd_test_key_build ( &key_256 );
	ok ( strlen ( key_aes.b64 ) == 40 );
	ok ( strlen ( key_256.b64 ) == 60 );
	ok ( strpbrk ( key_aes.b64, "+/=" ) == NULL );
	ok ( strpbrk ( key_256.b64, "+/=" ) == NULL );
	t_spec = zalloc ( sizeof ( *t_spec ) );
	t_work = zalloc ( sizeof ( *t_work ) );
	ok ( t_spec != NULL );
	ok ( t_work != NULL );
	if ( ! ( t_spec && t_work ) )
		goto done;

	rbd_test_defaults();
	rbd_test_monitors();
	rbd_test_authority_limit();
	rbd_test_authority_overflow();
	rbd_test_user();
	rbd_test_key();
	rbd_test_password();
	rbd_test_path();
	rbd_test_options();
	rbd_test_query_limit();
	rbd_test_settings();
	rbd_test_canary();
	rbd_test_wipe();
	rbd_test_open();
	rbd_test_open_success();
	rbd_test_uri_text();
	rbd_test_report();
	rbd_test_rc();

 done:
	/* Leave no setting and no key behind for the other test sets */
	rbd_set_none();
	if ( t_spec )
		rbd_spec_wipe ( t_spec );
	free ( t_spec );
	free ( t_work );
	t_spec = NULL;
	t_work = NULL;
}

/** URI opener self-test */
struct self_test rbd_uri_test __self_test = {
	.name = "rbd_uri_test",
	.exec = rbd_uri_test_exec,
};
