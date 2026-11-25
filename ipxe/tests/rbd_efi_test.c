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
 * RBD (Ceph) SAN protocol: self-tests of the EFI device path
 *
 * Built into bin-x86_64-linux/tests.linux (and the 32-bit program) by "ipxe/tools/build.sh test" (see ipxe/tests/README.md):
 * imported into src/tests/ of the prepared iPXE copy and wired in by patch 0003. There is no firmware here and no network
 * device: what is tested is the part of ipxe/src/rbd_efi.c that decides the bytes, which is written as pure functions over
 * plain buffers for exactly this reason (rbd_efi_node_build(), rbd_efi_uri_redact(), rbd_efi_prefix_len(),
 * rbd_efi_compose()). The firmware half (efi_netdev_path(), the route lookup, efi_describe) is the live check of module
 * qemu-uefi (UEFI shell "devices" / "dh -d" showing the node).
 *
 * What is checked, with the expected bytes written out by hand below (not computed by the code under test):
 *
 *   - the vendor node: header, GUID (also spelled from its text form), version, reserved byte, fsid (known and unknown: the
 *     bytes of an unknown fsid are zero whatever the structure held), "pool/image[@snap]" and its NUL, the length field,
 *     the end node;
 *   - the URI node: the redacted URI byte for byte, with the password, the fragment and the unknown query parameters gone
 *     (and a search of every produced path for the planted secrets);
 *   - the SATA node: header, 16-bit port from the identity hash, 0xffff port multiplier, LUN 0, the end node;
 *   - a path of the longest names (127 + 127 + 127 characters), one character more, empty and control-character names;
 *   - a buffer that is one byte too small: nothing is written, the answer is 0;
 *   - rbd_efi_prefix_len() against every way a path can be malformed;
 *   - rbd_efi_compose(): prefix + node + end node, nothing of the bytes behind the prefix's end node, bad inputs, the
 *     RBD_EFI_PATH_MAX limit;
 *   - alignment: the same bytes whatever the offset of the buffer (the driver copies with its own byte loops, because iPXE's
 *     inline memcpy() would use misaligned 32-bit stores, which the UBSan run traps on);
 *   - determinism: two builds from the same identity are byte-identical.
 *
 * Secure Boot: FILE_SECBOOT ( FORBIDDEN ), like every file of the driver (docs/design/ipxe-driver.md, section 13): a test
 * object is only ever linked into a self-test program.
 *
 * No key and no real URI is used: the "secrets" below are made-up strings.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ipxe/malloc.h>
#include <ipxe/test.h>
#include "winrbd/rbd_priv.h"
#include "winrbd/rbd_efi.h"

/** A made-up password and key that must never appear in any path */
#define RBD_EFI_TEST_PW "SECRETPW"
#define RBD_EFI_TEST_KEY "AQDfakefakefakefakefakefakefakefakefake=="

/** The end node */
#define END_NODE 0x7f, 0xff, 0x04, 0x00

/** The vendor node's fixed part up to and including the GUID (type, sub-type, length filled in by the test) */
#define GUID_BYTES 0xe5, 0xfc, 0x41, 0x90, 0x02, 0x04, 0xae, 0x4e, \
		   0xb3, 0xc1, 0xbd, 0x75, 0xad, 0xf5, 0x04, 0x55

/** A fake network device path: ACPI PciRoot, PCI function, MAC address node, end node (what efi_netdev_path() returns) */
static const uint8_t fake_netpath[] = {
	0x02, 0x01, 0x0c, 0x00, 0xd0, 0x41, 0x03, 0x0a, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x06, 0x00, 0x00, 0x03,
	0x03, 0x0b, 0x25, 0x00,
	0x52, 0x54, 0x00, 0x12, 0x34, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0x01,
	END_NODE
};
/** The part of it in front of the end node */
#define FAKE_NETPATH_LEN ( sizeof ( fake_netpath ) - 4 )

/** The fsid used by the tests: 10 11 ... 1f */
static const uint8_t fsid16[16] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

/**
 * Copy bytes, one at a time
 *
 * @v dest		Destination
 * @v src		Source
 * @v len		Length
 *
 * Not memcpy(): iPXE's inline memcpy() copies a small constant length through uint32_t pointers, and the destinations and
 * the string literals used as sources here have any alignment, which the UBSan run ("build.sh test -u") rightly traps on.
 * (The driver's own code has the same rule: rbd_efi.c, rbd_efi_copy().)
 */
static void put ( void *dest, const void *src, size_t len ) {
	uint8_t *to = dest;
	const uint8_t *from = src;

	while ( len-- )
		*(to++) = *(from++);
}

/**
 * Compare bytes
 *
 * @v got		Bytes produced
 * @v got_len		Length produced
 * @v want		Bytes expected
 * @v want_len		Length expected
 * @ret same		Same length and same bytes
 */
static int same ( const void *got, size_t got_len, const void *want,
		  size_t want_len ) {

	return ( ( got_len == want_len ) &&
		 ( memcmp ( got, want, want_len ) == 0 ) );
}

/**
 * Check that a buffer holds no trace of the planted secrets
 *
 * @v data		Bytes
 * @v len		Length
 * @ret clean		Neither the password nor the key occurs
 */
static int no_secret ( const void *data, size_t len ) {
	const uint8_t *byte = data;
	size_t i;

	for ( i = 0 ; i < len ; i++ ) {
		if ( ( ( len - i ) >= ( sizeof ( RBD_EFI_TEST_PW ) - 1 ) ) &&
		     ( memcmp ( ( byte + i ), RBD_EFI_TEST_PW,
				( sizeof ( RBD_EFI_TEST_PW ) - 1 ) ) == 0 ) )
			return 0;
		if ( ( ( len - i ) >= 8 ) &&
		     ( memcmp ( ( byte + i ), "AQDfakef", 8 ) == 0 ) )
			return 0;
	}
	return 1;
}

/**
 * Build the node, and check the buffer's edges
 *
 * @v ident		Identity
 * @v out		Output (at least len + 8 bytes)
 * @v len		Expected length of node + end node
 * @ret ok		node_len, build (exact size) and the bytes around the buffer are as they should be
 *
 * The buffer is poisoned first; a build that writes past its length, or a build into a buffer one byte too small that writes
 * anything, shows up here.
 */
static int build_exact ( const struct rbd_efi_ident *ident, uint8_t *out,
			 size_t len ) {
	size_t i;

	if ( rbd_efi_node_len ( ident ) != len )
		return 0;
	memset ( out, 0xee, ( len + 8 ) );
	if ( len && ( rbd_efi_node_build ( ident, out, ( len - 1 ) ) != 0 ) )
		return 0;
	for ( i = 0 ; i < ( len + 8 ) ; i++ ) {
		if ( out[i] != 0xee )
			return 0;
	}
	if ( rbd_efi_node_build ( ident, out, len ) != len )
		return 0;
	for ( i = len ; i < ( len + 8 ) ; i++ ) {
		if ( out[i] != 0xee )
			return 0;
	}
	return 1;
}

/** The node and end node of a built path, as the end of the bytes: end node is last, and the node's length field fits */
static int well_formed ( const uint8_t *node, size_t len ) {

	return ( ( len >= 8 ) &&
		 ( rbd_efi_prefix_len ( node, len ) == ( len - 4 ) ) &&
		 ( node[0] == 0x03 ) &&
		 ( ( node[2] | ( node[3] << 8 ) ) == ( int ) ( len - 4 ) ) );
}

/* ---- the vendor node -------------------------------------------------------------------------------------------------- */

/** "rbd/win11" with a known fsid */
static const uint8_t vendor_known[] = {
	0x03, 0x0a, 0x30, 0x00,
	GUID_BYTES,
	0x01, 0x00,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	'r', 'b', 'd', '/', 'w', 'i', 'n', '1', '1', 0x00,
	END_NODE
};

/** "p/i@s", fsid unknown (zero) */
static const uint8_t vendor_snap[] = {
	0x03, 0x0a, 0x2c, 0x00,
	GUID_BYTES,
	0x01, 0x00,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	'p', '/', 'i', '@', 's', 0x00,
	END_NODE
};

/** The vendor node: exact bytes */
static void vendor_node_test ( void ) {
	struct rbd_efi_ident ident;
	uint8_t out[512];
	uint8_t guid[16];
	const char *text = "9041fce5-0402-4eae-b3c1-bd75adf50455";
	unsigned int i;
	unsigned int v;
	unsigned int n;

	/* Known fsid */
	memset ( &ident, 0, sizeof ( ident ) );
	ident.devpath = RBD_DEVPATH_VENDOR;
	ident.fsid_known = 1;
	put ( ident.fsid, fsid16, sizeof ( fsid16 ) );
	ident.pool = "rbd";
	ident.image = "win11";
	ok ( build_exact ( &ident, out, sizeof ( vendor_known ) ) );
	ok ( same ( out, sizeof ( vendor_known ), vendor_known, sizeof ( vendor_known ) ) );
	ok ( well_formed ( out, sizeof ( vendor_known ) ) );

	/* Snapshot, fsid unknown: the 16 bytes are zero whatever the structure held (nothing stale leaks into the path) */
	memset ( &ident, 0, sizeof ( ident ) );
	ident.devpath = RBD_DEVPATH_VENDOR;
	ident.fsid_known = 0;
	put ( ident.fsid, fsid16, sizeof ( fsid16 ) );
	ident.pool = "p";
	ident.image = "i";
	ident.snap = "s";
	ok ( build_exact ( &ident, out, sizeof ( vendor_snap ) ) );
	ok ( same ( out, sizeof ( vendor_snap ), vendor_snap, sizeof ( vendor_snap ) ) );

	/* An empty snapshot is no snapshot */
	ident.snap = "";
	ok ( rbd_efi_node_len ( &ident ) == ( sizeof ( vendor_snap ) - 2 ) );
	ident.snap = NULL;
	ok ( rbd_efi_node_len ( &ident ) == ( sizeof ( vendor_snap ) - 2 ) );

	/* The GUID, spelled from its text: 9041fce5-0402-4eae-b3c1-bd75adf50455. The first three fields are little endian, the
	 * rest is in text order (EFI_GUID)
	 */
	n = 0;
	for ( i = 0 ; text[i] ; i++ ) {
		if ( text[i] == '-' )
			continue;
		v = ( ( text[i] <= '9' ) ? ( text[i] - '0' ) : ( text[i] - 'a' + 10 ) );
		v = ( ( v << 4 ) | ( ( text[i + 1] <= '9' ) ? ( text[i + 1] - '0' )
				     : ( text[i + 1] - 'a' + 10 ) ) );
		i++;
		guid[n++] = v;
	}
	ok ( n == 16 );
	ok ( ( guid[0] == 0x90 ) && ( guid[1] == 0x41 ) && ( guid[2] == 0xfc ) && ( guid[3] == 0xe5 ) );
	{
		/* Data1 (4 bytes), Data2 (2), Data3 (2) reversed into wire order */
		uint8_t wire[16];

		wire[0] = guid[3]; wire[1] = guid[2]; wire[2] = guid[1]; wire[3] = guid[0];
		wire[4] = guid[5]; wire[5] = guid[4];
		wire[6] = guid[7]; wire[7] = guid[6];
		put ( &wire[8], &guid[8], 8 );
		ok ( same ( wire, 16, rbd_efi_vendor_guid, 16 ) );
		ok ( same ( wire, 16, &vendor_known[4], 16 ) );
	}
}

/** Longest names: 127 characters each (RBD_NAME_MAX includes the NUL), and one more */
static void vendor_limits_test ( void ) {
	struct rbd_efi_ident ident;
	char pool[RBD_NAME_MAX + 1];
	char image[RBD_NAME_MAX + 1];
	char snap[RBD_NAME_MAX + 1];
	uint8_t *out;
	size_t want;
	size_t i;
	int shape;

	out = zalloc ( 1024 );
	ok ( out != NULL );
	if ( ! out )
		return;
	memset ( pool, 'a', ( RBD_NAME_MAX - 1 ) );
	pool[RBD_NAME_MAX - 1] = '\0';
	memset ( image, 'b', ( RBD_NAME_MAX - 1 ) );
	image[RBD_NAME_MAX - 1] = '\0';
	memset ( snap, 'c', ( RBD_NAME_MAX - 1 ) );
	snap[RBD_NAME_MAX - 1] = '\0';
	ok ( strlen ( pool ) == 127 );

	memset ( &ident, 0, sizeof ( ident ) );
	ident.devpath = RBD_DEVPATH_VENDOR;
	ident.fsid_known = 1;
	put ( ident.fsid, fsid16, sizeof ( fsid16 ) );
	ident.pool = pool;
	ident.image = image;
	ident.snap = snap;

	/* 4 + 16 + 2 + 16 + (127 + 1 + 127 + 1 + 127) + NUL = 422 = 0x01a6, and the end node */
	want = ( 422 + 4 );
	ok ( build_exact ( &ident, out, want ) );
	ok ( out[0] == 0x03 );
	ok ( out[1] == 0x0a );
	ok ( out[2] == 0xa6 );
	ok ( out[3] == 0x01 );
	ok ( same ( &out[4], 16, rbd_efi_vendor_guid, 16 ) );
	ok ( out[20] == 1 );
	ok ( out[21] == 0 );
	ok ( same ( &out[22], 16, fsid16, 16 ) );
	shape = 1;
	for ( i = 0 ; i < 127 ; i++ ) {
		if ( ( out[38 + i] != 'a' ) || ( out[38 + 128 + i] != 'b' ) ||
		     ( out[38 + 256 + i] != 'c' ) )
			shape = 0;
	}
	ok ( shape );
	ok ( out[38 + 127] == '/' );
	ok ( out[38 + 255] == '@' );
	ok ( out[38 + 383] == 0x00 );
	ok ( same ( &out[422], 4, "\x7f\xff\x04\x00", 4 ) );
	ok ( well_formed ( out, want ) );

	/* One character more in any of the three: refused (cut names would name another image) */
	pool[127] = 'a';
	pool[128] = '\0';
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ok ( rbd_efi_node_build ( &ident, out, 1024 ) == 0 );
	pool[127] = '\0';
	image[127] = 'b';
	image[128] = '\0';
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	image[127] = '\0';
	snap[127] = 'c';
	snap[128] = '\0';
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	snap[127] = '\0';
	ok ( rbd_efi_node_len ( &ident ) == want );

	/* Names that are missing, empty or hold a control character */
	ident.pool = NULL;
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.pool = "";
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.pool = "p";
	ident.image = NULL;
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.image = "";
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.image = "i\n";
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.image = "i";
	ident.snap = "s\x7f";
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.snap = "s\t";
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.snap = NULL;
	ok ( rbd_efi_node_len ( &ident ) == ( 38 + 3 + 1 + 4 ) );	/* header..fsid, "p/i", NUL, end node */

	free ( out );
}

/** One name that must be refused, in the pool, the image or the snapshot */
struct bad_name_test {
	/** The name */
	const char *name;
};

/** Names the opener never produces: the text "pool/image[@snap]" would be ambiguous, or the name not printable ASCII */
static const struct bad_name_test bad_names[] = {
	{ "a/b" }, { "/" }, { "a/" }, { "/a" },		/* "/" separates pool and image */
	{ "a@b" }, { "@" }, { "a@" }, { "@a" },		/* "@" separates image and snapshot */
	{ "a b" }, { " " }, { "a " },			/* space: not a name byte (0x21 to 0x7e) */
	{ "a\xc3\xa9" }, { "\x80" }, { "\xff" },	/* not ASCII */
	{ "a\x01" }, { "a\x1f" },			/* control characters */
};

/**
 * One image, one path: two different identities never give the same node
 *
 * "pool/image[@snap]" is only a name if no part can hold "/" or "@" (see rbd_efi_text_len()): pool "a/b" with image "c" and pool
 * "a" with image "b/c" would otherwise be the same vendor node, the same hash and the same path. They are refused instead, in
 * every position and in every flavour that looks at the names (vendor, sata).
 */
static void names_test ( void ) {
	struct rbd_efi_ident ident;
	unsigned int i;
	unsigned int flavour;
	unsigned int bad;

	bad = 0;
	for ( flavour = RBD_DEVPATH_VENDOR ; flavour <= RBD_DEVPATH_SATA ; flavour += 2 ) {
		for ( i = 0 ; i < ( sizeof ( bad_names ) / sizeof ( bad_names[0] ) ) ; i++ ) {
			memset ( &ident, 0, sizeof ( ident ) );
			ident.devpath = flavour;
			ident.pool = "p";
			ident.image = "i";
			ident.snap = "s";
			ok ( rbd_efi_node_len ( &ident ) != 0 );
			ident.pool = bad_names[i].name;
			if ( rbd_efi_node_len ( &ident ) != 0 )
				bad++;
			ident.pool = "p";
			ident.image = bad_names[i].name;
			if ( rbd_efi_node_len ( &ident ) != 0 )
				bad++;
			ident.image = "i";
			ident.snap = bad_names[i].name;
			if ( rbd_efi_node_len ( &ident ) != 0 )
				bad++;
		}
	}
	ok ( bad == 0 );

	/* The two identities of the example above are both refused (one of them must be, to keep the other's path its own) */
	memset ( &ident, 0, sizeof ( ident ) );
	ident.devpath = RBD_DEVPATH_VENDOR;
	ident.pool = "a/b";
	ident.image = "c";
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.pool = "a";
	ident.image = "b/c";
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.pool = "a";
	ident.image = "b@c";
	ok ( rbd_efi_node_len ( &ident ) == 0 );

	/* The characters the opener accepts besides letters and digits are fine */
	ident.pool = "pool-1_x.y";
	ident.image = "!#$%&'()*+,-.:;<=>?[\\]^_`{|}~";
	ident.snap = "snap~1";
	ok ( rbd_efi_node_len ( &ident ) != 0 );
}

/* ---- the URI node and the redaction ------------------------------------------------------------------------------------ */

/** A redaction test */
struct redact_test {
	/** Input URI */
	const char *in;
	/** Redacted URI, or NULL for an error */
	const char *out;
};

/** The redaction table */
static const struct redact_test redact_tests[] = {
	/* Nothing to remove: byte for byte */
	{ "rbd://10.77.0.10/pool/img", "rbd://10.77.0.10/pool/img" },
	{ "rbd://client.admin@10.77.0.10:3300,10.77.0.11:3300/pool/img?mode=crc&ro=1",
	  "rbd://client.admin@10.77.0.10:3300,10.77.0.11:3300/pool/img?mode=crc&ro=1" },
	{ "rbd://winrbd@[fd00::10]:3300/pool/img", "rbd://winrbd@[fd00::10]:3300/pool/img" },
	{ "rbd://h", "rbd://h" },
	{ "rbd://h?ro=1", "rbd://h?ro=1" },
	/* The '@' of a snapshot is not user information, a ':' in the path is not a password */
	{ "rbd://h/pool/img@snap", "rbd://h/pool/img@snap" },
	{ "rbd://h/pool/im:g@snap", "rbd://h/pool/im:g@snap" },
	{ "rbd://h/pool/img?fsid=ab:cd@ef", "rbd://h/pool/img?fsid=ab:cd@ef" },
	/* The password goes, the user stays; the last '@' ends the user information */
	{ "rbd://admin:" RBD_EFI_TEST_PW "@10.77.0.10/pool/img", "rbd://admin@10.77.0.10/pool/img" },
	{ "rbd://admin:@h/p/i", "rbd://admin@h/p/i" },
	{ "rbd://:" RBD_EFI_TEST_PW "@h/p/i", "rbd://@h/p/i" },
	{ "rbd://u:" RBD_EFI_TEST_PW "@x@h/p/i", "rbd://u@h/p/i" },
	{ "rbd://u:a:b:c@h:3300/p/i", "rbd://u@h:3300/p/i" },
	{ "rbd://admin:" RBD_EFI_TEST_PW "@[fd00::10]:3300/p/i?ro=1", "rbd://admin@[fd00::10]:3300/p/i?ro=1" },
	{ "rbd://admin:" RBD_EFI_TEST_PW "@h", "rbd://admin@h" },
	/* The fragment goes, with everything in it */
	{ "rbd://h/p/i#frag", "rbd://h/p/i" },
	{ "rbd://h/p#f?ro=1&key=1", "rbd://h/p" },
	{ "rbd://h/p/i?ro=1#frag", "rbd://h/p/i?ro=1" },
	{ "rbd://h#x", "rbd://h" },
	/* The query keeps the known options only (an allow list) */
	{ "rbd://h/p/i?key=" RBD_EFI_TEST_KEY, "rbd://h/p/i" },
	{ "rbd://h/p/i?rbd-key=" RBD_EFI_TEST_KEY "&ro=1", "rbd://h/p/i?ro=1" },
	{ "rbd://h/p/i?ro=1&secret=x&mode=secure&Key=y&KEY=z&k%65y=w", "rbd://h/p/i?ro=1&mode=secure" },
	{ "rbd://h/p/i?mode=crc&timeout=20&readahead=2048&fsid=u&devpath=uri&handoff=nokey&mapmem=1&monmsg=2&ro=0",
	  "rbd://h/p/i?mode=crc&timeout=20&readahead=2048&fsid=u&devpath=uri&handoff=nokey&mapmem=1&monmsg=2&ro=0" },
	{ "rbd://h/p/i?ro=1&&mode=crc", "rbd://h/p/i?ro=1&mode=crc" },
	{ "rbd://h/p/i?&ro=1&", "rbd://h/p/i?ro=1" },
	{ "rbd://h/p/i?", "rbd://h/p/i" },
	{ "rbd://h/p/i?x=1", "rbd://h/p/i" },
	{ "rbd://h/p/i?ro", "rbd://h/p/i?ro" },
	{ "rbd://h/p/i?rox=1&r=1&ro=1&roo", "rbd://h/p/i?ro=1" },
	{ "rbd://h/p/i?ro=1?key=1", "rbd://h/p/i?ro=1?key=1" },	/* a second '?' is part of a value: kept with its parameter */
	/* Everything together */
	{ "rbd://client.admin:" RBD_EFI_TEST_PW "@10.77.0.10:3300,10.77.0.11:3300/rbd/win11@snap1?mode=secure&key="
	  RBD_EFI_TEST_KEY "&ro=1#top",
	  "rbd://client.admin@10.77.0.10:3300,10.77.0.11:3300/rbd/win11@snap1?mode=secure&ro=1" },
	/* Errors: no URI, no scheme, bad scheme, bytes a URI cannot have */
	{ NULL, NULL },
	{ "", NULL },
	{ "10.77.0.10/pool/img", NULL },
	{ "://h/p/i", NULL },
	{ "rbd:/h/p/i", NULL },
	{ "rbd//h/p/i", NULL },
	{ "r bd://h/p/i", NULL },
	{ "a:b://h/p/i", NULL },
	{ "rbd/x://h/p/i", NULL },
	{ "rbd://h/p/i img", NULL },
	{ "rbd://h/p/i\n", NULL },
	{ "rbd://h/p/\xc3\xa9", NULL },
	{ "rbd://h/p/i\x7f", NULL },
};

/** Redaction: the table, in both modes (measure and write) */
static void redact_test ( void ) {
	char out[RBD_EFI_URI_MAX + 8];
	char *big;
	size_t want_len;
	size_t len;
	size_t i;

	for ( i = 0 ; i < ( sizeof ( redact_tests ) / sizeof ( redact_tests[0] ) ) ; i++ ) {
		const struct redact_test *t = &redact_tests[i];

		memset ( out, 0xee, sizeof ( out ) );
		want_len = ( t->out ? strlen ( t->out ) : 0 );
		/* Measure: no buffer */
		ok ( rbd_efi_uri_redact ( t->in, NULL, 0 ) == want_len );
		/* Write: exact size (with the NUL) */
		if ( t->out ) {
			len = rbd_efi_uri_redact ( t->in, out, ( want_len + 1 ) );
			ok ( len == want_len );
			ok ( strcmp ( out, t->out ) == 0 );
			ok ( no_secret ( out, ( len + 1 ) ) );
			/* One byte too small: an error, never a cut URI, and not a byte stored at or after the end of the buffer */
			memset ( out, 0xee, sizeof ( out ) );
			ok ( rbd_efi_uri_redact ( t->in, out, want_len ) == 0 );
			ok ( ( ( uint8_t ) out[want_len] == 0xee ) && ( ( uint8_t ) out[sizeof ( out ) - 1] == 0xee ) );
			/* A buffer of 0 bytes: nothing stored */
			memset ( out, 0xee, sizeof ( out ) );
			ok ( rbd_efi_uri_redact ( t->in, out, 0 ) == 0 );
			ok ( ( uint8_t ) out[0] == 0xee );
		} else {
			ok ( rbd_efi_uri_redact ( t->in, out, sizeof ( out ) ) == 0 );
		}
	}

	/* The length limit: 1024 characters are fine, 1025 are not */
	big = zalloc ( RBD_EFI_URI_MAX + 16 );
	ok ( big != NULL );
	if ( ! big )
		return;
	memset ( big, 'x', ( RBD_EFI_URI_MAX + 1 ) );
	put ( big, "rbd://h/", 8 );
	big[RBD_EFI_URI_MAX] = '\0';
	ok ( rbd_efi_uri_redact ( big, NULL, 0 ) == RBD_EFI_URI_MAX );
	big[RBD_EFI_URI_MAX] = 'x';
	big[RBD_EFI_URI_MAX + 1] = '\0';
	ok ( rbd_efi_uri_redact ( big, NULL, 0 ) == 0 );
	free ( big );
}

/** The URI node: exact bytes, the secrets gone */
static void uri_node_test ( void ) {
	static const char uri[] = "rbd://client.admin@10.77.0.10:3300/rbd/win11?mode=crc&ro=1";
	static const char dirty[] = "rbd://client.admin:" RBD_EFI_TEST_PW "@10.77.0.10:3300/rbd/win11?mode=crc&key="
				    RBD_EFI_TEST_KEY "&ro=1#frag";
	struct rbd_efi_ident ident;
	uint8_t out[RBD_EFI_URI_MAX + 64];
	uint8_t want[RBD_EFI_URI_MAX + 64];
	size_t node;

	memset ( &ident, 0, sizeof ( ident ) );
	ident.devpath = RBD_DEVPATH_URI;
	ident.uri = uri;
	ident.pool = "unused";	/* the URI node does not look at the names */

	/* Clean URI: type 3, sub-type 0x18, length, the bytes, NUL, end node */
	node = ( 4 + sizeof ( uri ) );	/* sizeof counts the NUL */
	want[0] = 0x03;
	want[1] = 0x18;
	want[2] = ( node & 0xff );
	want[3] = ( node >> 8 );
	put ( &want[4], uri, sizeof ( uri ) );
	put ( &want[node], "\x7f\xff\x04\x00", 4 );
	ok ( build_exact ( &ident, out, ( node + 4 ) ) );
	ok ( same ( out, ( node + 4 ), want, ( node + 4 ) ) );
	ok ( well_formed ( out, ( node + 4 ) ) );
	ok ( out[1] == 0x18 );

	/* Dirty URI: the same bytes as the clean one (password, key parameter and fragment removed) */
	ident.uri = dirty;
	ok ( build_exact ( &ident, out, ( node + 4 ) ) );
	ok ( same ( out, ( node + 4 ), want, ( node + 4 ) ) );
	ok ( no_secret ( out, ( node + 4 ) ) );

	/* The longest URI (1,024 characters): the node is 4 + 1,025 bytes, the length field 0x0405, and 1,025 characters are refused */
	{
		char *big = zalloc ( RBD_EFI_URI_MAX + 16 );
		uint8_t *node_out = zalloc ( RBD_EFI_URI_MAX + 64 );

		ok ( ( big != NULL ) && ( node_out != NULL ) );
		if ( big && node_out ) {
			memset ( big, 'x', RBD_EFI_URI_MAX );
			put ( big, "rbd://h/", 8 );
			ident.uri = big;
			ok ( rbd_efi_node_len ( &ident ) == ( 4 + RBD_EFI_URI_MAX + 1 + 4 ) );
			ok ( rbd_efi_node_build ( &ident, node_out, ( RBD_EFI_URI_MAX + 64 ) ) ==
			     ( size_t ) ( 4 + RBD_EFI_URI_MAX + 1 + 4 ) );
			ok ( ( node_out[0] == 0x03 ) && ( node_out[1] == 0x18 ) && ( node_out[2] == 0x05 ) &&
			     ( node_out[3] == 0x04 ) );
			ok ( node_out[4 + RBD_EFI_URI_MAX] == 0x00 );
			ok ( same ( &node_out[4 + RBD_EFI_URI_MAX + 1], 4, "\x7f\xff\x04\x00", 4 ) );
			big[RBD_EFI_URI_MAX + 1] = '\0';
			big[RBD_EFI_URI_MAX] = 'x';
			ok ( rbd_efi_node_len ( &ident ) == 0 );
		}
		free ( big );
		free ( node_out );
	}

	/* A URI that cannot be redacted gives no node (and the names are not a substitute) */
	ident.uri = NULL;
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.uri = "";
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.uri = "not a uri";
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ok ( rbd_efi_node_build ( &ident, out, sizeof ( out ) ) == 0 );
}

/* ---- the SATA node ----------------------------------------------------------------------------------------------------- */

/** "rbd/win11", fsid unknown: FNV-1a (16 zero bytes, "rbd/win11") = 0x4931c2d0, mod 0xffff = 0x0c02 */
static const uint8_t sata_a[] = {
	0x03, 0x12, 0x0a, 0x00, 0x02, 0x0c, 0xff, 0xff, 0x00, 0x00,
	END_NODE
};

/** "p/i@s", fsid 10..1f: FNV-1a = 0xe9f2e1f6, mod 0xffff = 0xcbe9 */
static const uint8_t sata_b[] = {
	0x03, 0x12, 0x0a, 0x00, 0xe9, 0xcb, 0xff, 0xff, 0x00, 0x00,
	END_NODE
};

/** The SATA node: exact bytes, the port never 0xffff, different images, different ports (almost always) */
static void sata_node_test ( void ) {
	struct rbd_efi_ident ident;
	uint8_t out[64];
	char name[32];
	unsigned int port;
	unsigned int bad = 0;
	unsigned int first = 0;
	unsigned int same_port = 0;
	unsigned int i;

	memset ( &ident, 0, sizeof ( ident ) );
	ident.devpath = RBD_DEVPATH_SATA;
	ident.pool = "rbd";
	ident.image = "win11";
	ok ( build_exact ( &ident, out, sizeof ( sata_a ) ) );
	ok ( same ( out, sizeof ( sata_a ), sata_a, sizeof ( sata_a ) ) );
	ok ( well_formed ( out, sizeof ( sata_a ) ) );

	memset ( &ident, 0, sizeof ( ident ) );
	ident.devpath = RBD_DEVPATH_SATA;
	ident.fsid_known = 1;
	put ( ident.fsid, fsid16, sizeof ( fsid16 ) );
	ident.pool = "p";
	ident.image = "i";
	ident.snap = "s";
	ok ( build_exact ( &ident, out, sizeof ( sata_b ) ) );
	ok ( same ( out, sizeof ( sata_b ), sata_b, sizeof ( sata_b ) ) );

	/* The URI is no input of the SATA node, and a bad name gives no node */
	ident.uri = "rbd://h/p/i";
	ok ( rbd_efi_node_build ( &ident, out, sizeof ( out ) ) == sizeof ( sata_b ) );
	ok ( same ( out, sizeof ( sata_b ), sata_b, sizeof ( sata_b ) ) );
	ident.image = "";
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.image = "i";

	/* 0xffff is reserved for the HBA port; the port multiplier is always "directly connected" and the LUN 0 */
	ident.uri = NULL;
	ident.snap = NULL;
	ident.pool = name;
	ident.image = "disk";
	for ( i = 0 ; i < 70000 ; i++ ) {
		name[0] = 'p';
		name[1] = ( '0' + ( i % 10 ) );
		name[2] = ( '0' + ( ( i / 10 ) % 10 ) );
		name[3] = ( '0' + ( ( i / 100 ) % 10 ) );
		name[4] = ( '0' + ( ( i / 1000 ) % 10 ) );
		name[5] = ( '0' + ( ( i / 10000 ) % 10 ) );
		name[6] = '\0';
		if ( rbd_efi_node_build ( &ident, out, sizeof ( out ) ) != sizeof ( sata_a ) ) {
			bad++;
			continue;
		}
		port = ( out[4] | ( out[5] << 8 ) );
		if ( ( port == 0xffff ) || ( out[6] != 0xff ) || ( out[7] != 0xff ) ||
		     ( out[8] != 0 ) || ( out[9] != 0 ) )
			bad++;
		if ( i == 0 )
			first = port;
		else if ( port == first )
			same_port++;
	}
	ok ( bad == 0 );
	/* 70,000 names into 65,535 ports: a hash that ignored the name would give 69,999 hits; a good one about 1 */
	ok ( same_port < 20 );
}

/* ---- bad inputs ------------------------------------------------------------------------------------------------------ */

/** Unknown flavours, and the buffer limits */
static void flavour_test ( void ) {
	struct rbd_efi_ident ident;
	uint8_t out[128];

	memset ( &ident, 0, sizeof ( ident ) );
	ident.pool = "p";
	ident.image = "i";
	ident.uri = "rbd://h/p/i";
	ident.devpath = 3;
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ok ( rbd_efi_node_build ( &ident, out, sizeof ( out ) ) == 0 );
	ident.devpath = 255;
	ok ( rbd_efi_node_len ( &ident ) == 0 );
	ident.devpath = RBD_DEVPATH_VENDOR;
	ok ( rbd_efi_node_len ( &ident ) != 0 );

	/* The numbers in the design: vendor = 0, uri = 1, sata = 2 (the enum is the URI option's meaning) */
	ok ( RBD_DEVPATH_VENDOR == 0 );
	ok ( RBD_DEVPATH_URI == 1 );
	ok ( RBD_DEVPATH_SATA == 2 );
}

/* ---- alignment --------------------------------------------------------------------------------------------------------- */

/** A node inside a device path sits at any offset: the same bytes at every alignment (and nothing stored out of bounds) */
static void alignment_test ( void ) {
	struct rbd_efi_ident ident;
	uint8_t base[512];
	uint8_t raw[512 + 8];
	size_t len;
	unsigned int flavour;
	unsigned int shift;

	memset ( &ident, 0, sizeof ( ident ) );
	ident.fsid_known = 1;
	put ( ident.fsid, fsid16, sizeof ( fsid16 ) );
	ident.pool = "rbd";
	ident.image = "win11";
	ident.snap = "snap";
	ident.uri = "rbd://client.admin@10.77.0.10:3300/rbd/win11?mode=crc&ro=1";
	for ( flavour = RBD_DEVPATH_VENDOR ; flavour <= RBD_DEVPATH_SATA ; flavour++ ) {
		ident.devpath = flavour;
		len = rbd_efi_node_len ( &ident );
		ok ( ( len != 0 ) && ( len <= sizeof ( base ) ) );
		if ( ( len == 0 ) || ( len > sizeof ( base ) ) )
			continue;
		memset ( base, 0xee, sizeof ( base ) );
		ok ( rbd_efi_node_build ( &ident, base, len ) == len );
		for ( shift = 1 ; shift < 8 ; shift++ ) {
			memset ( raw, 0xee, sizeof ( raw ) );
			ok ( rbd_efi_node_build ( &ident, &raw[shift], len ) == len );
			ok ( same ( &raw[shift], len, base, len ) );
			ok ( ( raw[shift - 1] == 0xee ) && ( raw[shift + len] == 0xee ) );
		}
	}
}

/* ---- prefix check and composition -------------------------------------------------------------------------------------- */

/** rbd_efi_prefix_len(): the good path and every malformed shape */
static void prefix_test ( void ) {
	uint8_t path[64];
	uint8_t *big;
	size_t off;
	size_t i;

	ok ( rbd_efi_prefix_len ( fake_netpath, sizeof ( fake_netpath ) ) == FAKE_NETPATH_LEN );
	/* Bytes behind the end node are not looked at */
	memset ( path, 0xaa, sizeof ( path ) );
	put ( path, "\x03\x0b\x08\x00\x01\x02\x03\x04\x7f\xff\x04\x00", 12 );
	ok ( rbd_efi_prefix_len ( path, sizeof ( path ) ) == 8 );
	ok ( rbd_efi_prefix_len ( path, 12 ) == 8 );

	/* Not there, too short, not terminated */
	ok ( rbd_efi_prefix_len ( NULL, 100 ) == 0 );
	ok ( rbd_efi_prefix_len ( path, 0 ) == 0 );
	ok ( rbd_efi_prefix_len ( path, 3 ) == 0 );
	ok ( rbd_efi_prefix_len ( path, 4 ) == 0 );
	ok ( rbd_efi_prefix_len ( path, 11 ) == 0 );
	for ( i = 0 ; i < sizeof ( fake_netpath ) ; i++ )
		ok ( rbd_efi_prefix_len ( fake_netpath, i ) == 0 );

	/* Only the end node: nothing to prefix */
	ok ( rbd_efi_prefix_len ( "\x7f\xff\x04\x00", 4 ) == 0 );

	/* A node shorter than its header, or running beyond the buffer */
	ok ( rbd_efi_prefix_len ( "\x03\x0b\x03\x00\x7f\xff\x04\x00", 8 ) == 0 );
	ok ( rbd_efi_prefix_len ( "\x03\x0b\x00\x00\x7f\xff\x04\x00", 8 ) == 0 );
	ok ( rbd_efi_prefix_len ( "\x03\x0b\x09\x00\x7f\xff\x04\x00", 8 ) == 0 );
	ok ( rbd_efi_prefix_len ( "\x03\x0b\xff\xff\x7f\xff\x04\x00", 8 ) == 0 );

	/* An instance end node (several paths in one), an end node with another length or sub-type */
	ok ( rbd_efi_prefix_len ( "\x03\x0b\x04\x00\x7f\x01\x04\x00", 8 ) == 0 );
	ok ( rbd_efi_prefix_len ( "\x03\x0b\x04\x00\x7f\xff\x05\x00\x00", 9 ) == 0 );
	ok ( rbd_efi_prefix_len ( "\x03\x0b\x04\x00\x7f\xff\x03\x00", 8 ) == 0 );
	ok ( rbd_efi_prefix_len ( "\x03\x0b\x04\x00\x7f\x02\x04\x00", 8 ) == 0 );

	/* The limit: nodes of 4 bytes up to RBD_EFI_PATH_MAX - 4, then the end node, is accepted; one node more is not */
	big = zalloc ( RBD_EFI_PATH_MAX + 64 );
	ok ( big != NULL );
	if ( ! big )
		return;
	for ( off = 0 ; off < ( RBD_EFI_PATH_MAX - 4 ) ; off += 4 )
		put ( &big[off], "\x03\x0b\x04\x00", 4 );
	put ( &big[off], "\x7f\xff\x04\x00", 4 );
	ok ( off == ( RBD_EFI_PATH_MAX - 4 ) );
	ok ( rbd_efi_prefix_len ( big, RBD_EFI_PATH_MAX ) == ( RBD_EFI_PATH_MAX - 4 ) );
	ok ( rbd_efi_prefix_len ( big, ( RBD_EFI_PATH_MAX + 64 ) ) == ( RBD_EFI_PATH_MAX - 4 ) );
	put ( &big[off], "\x03\x0b\x04\x00", 4 );
	put ( &big[off + 4], "\x7f\xff\x04\x00", 4 );
	ok ( rbd_efi_prefix_len ( big, ( RBD_EFI_PATH_MAX + 64 ) ) == 0 );
	free ( big );
}

/** Composition of the whole path, all three flavours */
static void compose_test ( void ) {
	struct rbd_efi_ident ident;
	uint8_t *want;
	uint8_t *a;
	uint8_t *b;
	uint8_t padded[sizeof ( fake_netpath ) + 16];
	size_t node;
	size_t total;
	unsigned int flavour;

	memset ( &ident, 0, sizeof ( ident ) );
	ident.fsid_known = 1;
	put ( ident.fsid, fsid16, sizeof ( fsid16 ) );
	ident.pool = "rbd";
	ident.image = "win11";
	ident.uri = "rbd://admin:" RBD_EFI_TEST_PW "@10.77.0.10/rbd/win11?ro=1&key=" RBD_EFI_TEST_KEY;
	want = zalloc ( 1024 );
	ok ( want != NULL );
	if ( ! want )
		return;

	for ( flavour = RBD_DEVPATH_VENDOR ; flavour <= RBD_DEVPATH_SATA ; flavour++ ) {
		ident.devpath = flavour;
		node = rbd_efi_node_len ( &ident );
		ok ( node != 0 );
		total = ( FAKE_NETPATH_LEN + node );
		put ( want, fake_netpath, FAKE_NETPATH_LEN );
		ok ( rbd_efi_node_build ( &ident, ( want + FAKE_NETPATH_LEN ), node ) == node );

		/* prefix + node + end node, and nothing else */
		a = ( ( uint8_t * ) rbd_efi_compose ( fake_netpath, sizeof ( fake_netpath ), &ident ) );
		ok ( a != NULL );
		if ( ! a )
			continue;
		ok ( same ( a, total, want, total ) );
		ok ( rbd_efi_prefix_len ( a, total ) == ( total - 4 ) );
		ok ( same ( &a[total - 4], 4, "\x7f\xff\x04\x00", 4 ) );
		ok ( no_secret ( a, total ) );

		/* Twice from the same identity: byte-identical (nothing is accumulated between calls) */
		b = ( ( uint8_t * ) rbd_efi_compose ( fake_netpath, sizeof ( fake_netpath ), &ident ) );
		ok ( b != NULL );
		if ( b )
			ok ( same ( a, total, b, total ) );
		free ( b );

		/* Garbage behind the prefix's end node is not copied: same bytes, same length */
		memset ( padded, 0xaa, sizeof ( padded ) );
		put ( padded, fake_netpath, sizeof ( fake_netpath ) );
		b = ( ( uint8_t * ) rbd_efi_compose ( padded, sizeof ( padded ), &ident ) );
		ok ( b != NULL );
		if ( b ) {
			ok ( same ( a, total, b, total ) );
			ok ( rbd_efi_prefix_len ( b, total ) == ( total - 4 ) );
		}
		free ( b );
		free ( a );
	}

	/* Bad prefix, bad identity */
	ident.devpath = RBD_DEVPATH_VENDOR;
	ok ( rbd_efi_compose ( NULL, 100, &ident ) == NULL );
	ok ( rbd_efi_compose ( fake_netpath, ( sizeof ( fake_netpath ) - 1 ), &ident ) == NULL );
	ok ( rbd_efi_compose ( "\x7f\xff\x04\x00", 4, &ident ) == NULL );
	ident.image = "";
	ok ( rbd_efi_compose ( fake_netpath, sizeof ( fake_netpath ), &ident ) == NULL );
	ident.image = "win11";
	ident.devpath = 9;
	ok ( rbd_efi_compose ( fake_netpath, sizeof ( fake_netpath ), &ident ) == NULL );

	/* The path limit: a prefix of 15 x 256 bytes and a vendor node + end node of 256 bytes (213 characters of name:
	 * 4 + 16 + 2 + 16 + 213 + 1 + 4) make exactly RBD_EFI_PATH_MAX; one character more is refused
	 */
	{
		uint8_t *prefix = zalloc ( 15 * 256 + 4 );
		char pool[101];
		char image[114];
		unsigned int i;

		ok ( prefix != NULL );
		if ( prefix ) {
			for ( i = 0 ; i < 15 ; i++ )
				put ( &prefix[i * 256], "\x03\x0b\x00\x01", 4 );
			put ( &prefix[15 * 256], "\x7f\xff\x04\x00", 4 );
			memset ( pool, 'n', 100 );
			pool[100] = '\0';
			memset ( image, 'm', 112 );
			image[112] = '\0';
			ident.devpath = RBD_DEVPATH_VENDOR;
			ident.pool = pool;
			ident.image = image;
			ident.snap = NULL;
			ok ( rbd_efi_node_len ( &ident ) == 256 );
			a = ( ( uint8_t * ) rbd_efi_compose ( prefix, ( 15 * 256 + 4 ), &ident ) );
			ok ( a != NULL );
			if ( a )
				ok ( rbd_efi_prefix_len ( a, RBD_EFI_PATH_MAX ) == ( RBD_EFI_PATH_MAX - 4 ) );
			free ( a );
			image[112] = 'm';
			image[113] = '\0';
			ok ( rbd_efi_node_len ( &ident ) == 257 );
			ok ( rbd_efi_compose ( prefix, ( 15 * 256 + 4 ), &ident ) == NULL );
			free ( prefix );
		}
	}
	free ( want );
}

/** The constants against iPXE's own headers (the build asserts them too) */
static void constants_test ( void ) {

	ok ( MESSAGING_DEVICE_PATH == 0x03 );
	ok ( MSG_VENDOR_DP == 0x0a );
	ok ( MSG_URI_DP == 0x18 );
	ok ( MSG_SATA_DP == 0x12 );
	ok ( END_DEVICE_PATH_TYPE == 0x7f );
	ok ( END_ENTIRE_DEVICE_PATH_SUBTYPE == 0xff );
	ok ( sizeof ( EFI_DEVICE_PATH_PROTOCOL ) == 4 );
	ok ( sizeof ( SATA_DEVICE_PATH ) == 10 );
	ok ( sizeof ( VENDOR_DEVICE_PATH ) == 20 );
	ok ( sizeof ( EFI_GUID ) == 16 );
	ok ( RBD_EFI_URI_MAX == 1024 );
	ok ( RBD_EFI_PATH_MAX == 4096 );
}

/** Outside an EFI build there is no device path to describe: the firmware half answers NULL (and is never an interface operation) */
static void non_efi_test ( void ) {

#ifndef PLATFORM_efi
	ok ( rbd_efi_path ( NULL ) == NULL );
#endif
}

/**
 * Perform the EFI device path self-tests
 */
static void rbd_efi_test_exec ( void ) {

	constants_test();
	vendor_node_test();
	vendor_limits_test();
	names_test();
	redact_test();
	uri_node_test();
	sata_node_test();
	flavour_test();
	alignment_test();
	prefix_test();
	compose_test();
	non_efi_test();
}

/** EFI device path self-test */
struct self_test rbd_efi_test __self_test = {
	.name = "rbd_efi_test",
	.exec = rbd_efi_test_exec,
};
