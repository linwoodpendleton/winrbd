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
 * RBD (Ceph) SAN protocol: EFI device path
 *
 * The EFI SAN backend (efi_block.c) asks the block interface to describe itself with efi_describe() and installs the answer
 * next to EFI_BLOCK_IO. The path is the network device's path (parent PCI device, MAC address, VLAN: efi_netdev_path(), of
 * the device that routes to the first monitor) followed by one node that names the image, then the end node. The node's
 * shape is chosen by the "devpath" URI option (docs/design/ipxe-driver.md, section 6):
 *
 *   vendor (default)  MSG_VENDOR_DP, GUID 9041fce5-0402-4eae-b3c1-bd75adf50455, data = { u8 version = 1, u8 reserved = 0,
 *                     u8 fsid[16] (zero if unknown), "pool/image[@snap]" NUL-terminated }. It names the image, so two RBD
 *                     disks have two different paths, and it claims no standard device class.
 *   uri               MSG_URI_DP carrying the URI with its password and its non-option query parameters removed: the node
 *                     the HTTP SAN protocol installs (efi_uri_path()), but behind the network prefix.
 *   sata              MSG_SATA_DP (what AoE installs, efi_aoe_path()), for firmware or loaders that only accept known
 *                     classes. HBA port = a 16-bit hash of (fsid, name), port multiplier 0xFFFF ("directly connected"),
 *                     LUN 0. A hash is not unique: two images that hash alike on one machine would get one path (about
 *                     1 in 65,535 for a pair); only the vendor shape is collision-free.
 *
 * The code is in two layers (see rbd_efi.h). The node and the whole path are built by PURE functions over plain buffers,
 * compiled into every build, so that ipxe/tests/rbd_efi_test.c checks the exact bytes on a Linux host. The firmware part,
 * rbd_efi_path(), exists only in an EFI build (on BIOS efi_describe is not an interface operation and nothing calls it; the
 * function returns NULL there).
 *
 * Credit: the shape of the composition (the network device's path without its end node, one messaging node, a new end node, one
 * allocation the caller frees with free()) follows efi_aoe_path() and efi_iscsi_path() in iPXE's src/interface/efi/efi_path.c
 * (GPL2_OR_LATER_OR_UBDL); the code is written for this driver.
 *
 * Secrets: the path never holds the cephx key (it is not in the identity at all) and never the password of a URI (the
 * opener refuses one, and rbd_efi_uri_redact() removes it again as a second line of defence). The path is readable by every
 * driver and by the booted loader.
 *
 * UNVERIFIED (docs/design/ipxe-driver.md, sections 6 and 16, risk R3): whether the Windows boot manager and loader
 * (bootmgfw.efi, winload.efi) accept a parent path that ends in an unknown vendor node, in a URI node or in a SATA node with
 * no controller behind it. What is established is only how UEFI itself treats the path (the partition driver appends HD(...)
 * to any valid parent path). The three shapes exist so that the first run with a real WinPE image can try each without a
 * rebuild. The live check in a firmware shell ("devices", "dh -d") is the matrix row of module qemu-uefi.
 *
 * Secure Boot: FILE_SECBOOT ( FORBIDDEN ), like every file of the driver and for the same reason (section 13). The functions
 * here are logically harmless, but the file is only ever linked together with the rest of the driver, which parses network
 * data in the pre-boot environment and has had no review that would let any part of it be signed.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <ipxe/malloc.h>
#include <ipxe/efi/efi_path.h>
#include "rbd_priv.h"
#include "rbd_efi.h"

/** Device path node header: type, sub-type, length (16 bits, little endian) */
#define RBD_EFI_HDR 4

/** Device path types and sub-types (UEFI specification, "Device Path Protocol"); checked against iPXE's headers below */
#define RBD_EFI_TYPE_MESSAGING 0x03
#define RBD_EFI_SUB_SATA 0x12
#define RBD_EFI_SUB_VENDOR 0x0a
#define RBD_EFI_SUB_URI 0x18
#define RBD_EFI_TYPE_END 0x7f
#define RBD_EFI_SUB_END_ENTIRE 0xff

/** Version of the vendor node's data layout */
#define RBD_EFI_VENDOR_VERSION 1

/** Bytes of the vendor node before the name: header, GUID, version, reserved, fsid */
#define RBD_EFI_VENDOR_FIXED ( RBD_EFI_HDR + 16 + 1 + 1 + 16 )

/** Bytes of the SATA node (HBA port, port multiplier port, LUN: three 16-bit fields) */
#define RBD_EFI_SATA_LEN ( RBD_EFI_HDR + 2 + 2 + 2 )

/** Not a valid length */
#define RBD_EFI_BAD ( ( size_t ) -1 )

/** The vendor node's GUID: 9041fce5-0402-4eae-b3c1-bd75adf50455 as an EFI_GUID (the first three fields little endian) */
const uint8_t rbd_efi_vendor_guid[16] = {
	0xe5, 0xfc, 0x41, 0x90, 0x02, 0x04, 0xae, 0x4e,
	0xb3, 0xc1, 0xbd, 0x75, 0xad, 0xf5, 0x04, 0x55
};

/** The URI options the redacted URI keeps (the names of docs/design/ipxe-driver.md, section 8); anything else is dropped */
static const char * const rbd_efi_uri_options[] = {
	"mode", "ro", "timeout", "readahead", "fsid", "devpath", "handoff",
	"mapmem", "monmsg",
};

/**
 * Check that the constants above are what iPXE's own headers say (compiled away if they are)
 */
static inline void rbd_efi_check_constants ( void ) {

	build_assert ( RBD_EFI_HDR == sizeof ( EFI_DEVICE_PATH_PROTOCOL ) );
	build_assert ( RBD_EFI_TYPE_MESSAGING == MESSAGING_DEVICE_PATH );
	build_assert ( RBD_EFI_SUB_SATA == MSG_SATA_DP );
	build_assert ( RBD_EFI_SUB_VENDOR == MSG_VENDOR_DP );
	build_assert ( RBD_EFI_SUB_URI == MSG_URI_DP );
	build_assert ( RBD_EFI_TYPE_END == END_DEVICE_PATH_TYPE );
	build_assert ( RBD_EFI_SUB_END_ENTIRE ==
		       END_ENTIRE_DEVICE_PATH_SUBTYPE );
	build_assert ( sizeof ( EFI_GUID ) == sizeof ( rbd_efi_vendor_guid ) );
	build_assert ( RBD_EFI_VENDOR_FIXED == sizeof ( VENDOR_DEVICE_PATH ) +
		       1 + 1 + 16 );
	build_assert ( RBD_EFI_SATA_LEN == sizeof ( SATA_DEVICE_PATH ) );
	build_assert ( RBD_EFI_HDR == sizeof ( URI_DEVICE_PATH ) );
}

/**
 * Copy bytes, one at a time
 *
 * @v dest		Destination (any alignment)
 * @v src		Source (any alignment)
 * @v len		Length
 *
 * Used instead of memcpy() / memset() wherever the length is a small compile-time constant and either end may sit at an odd
 * address (a node inside a device path is only byte aligned): iPXE's inline memcpy() and memset() turn such a call into
 * stores through uint32_t pointers, which is a misaligned access as far as the language is concerned (UBSan, "ipxe/tools/
 * build.sh test -u", traps on it) and a fault on a CPU that does not tolerate it.
 */
static void rbd_efi_copy ( void *dest, const void *src, size_t len ) {
	uint8_t *to = dest;
	const uint8_t *from = src;

	while ( len-- )
		*(to++) = *(from++);
}

/**
 * Zero bytes, one at a time
 *
 * @v dest		Destination (any alignment)
 * @v len		Length
 */
static void rbd_efi_zero ( void *dest, size_t len ) {
	uint8_t *to = dest;

	while ( len-- )
		*(to++) = 0;
}

/**
 * Write a device path node header
 *
 * @v out		Where to write (at least RBD_EFI_HDR bytes)
 * @v type		Node type
 * @v subtype		Node sub-type
 * @v len		Node length, header included (at most 0xffff)
 * @ret next		The byte after the header
 */
static uint8_t * rbd_efi_header ( uint8_t *out, unsigned int type,
				  unsigned int subtype, size_t len ) {

	out[0] = type;
	out[1] = subtype;
	out[2] = ( len & 0xff );
	out[3] = ( ( len >> 8 ) & 0xff );
	return ( out + RBD_EFI_HDR );
}

/**
 * Write the end node
 *
 * @v out		Where to write (RBD_EFI_HDR bytes)
 */
static void rbd_efi_end ( uint8_t *out ) {

	rbd_efi_header ( out, RBD_EFI_TYPE_END, RBD_EFI_SUB_END_ENTIRE,
			 RBD_EFI_HDR );
}

/**
 * Measure a text and check that it is printable
 *
 * @v text		Text, or NULL (the empty text)
 * @v max		Longest allowed text
 * @v name		The text is a pool, image or snapshot name (see below)
 * @ret len		Length, or RBD_EFI_BAD if too long or if it holds a character that is not allowed
 *
 * Any text: no control character (below 0x20, 0x7f). A name: the opener's own character set (core/src/rburl: 0x21 to 0x7e,
 * and neither "/" nor "@"), so that "pool/image[@snap]" can be read back in one way only. If "/" were allowed in a pool name,
 * or "@" in an image name, two different images could produce the same text (pool "a/b" and image "c" against pool "a" and
 * image "b/c"), hence the same vendor node, the same hash and the same device path, and the firmware could not tell their
 * handles apart. The opener never lets such a name through; this keeps the promise "one image, one path" true for any caller.
 */
static size_t rbd_efi_text_len ( const char *text, size_t max, int name ) {
	size_t len;
	uint8_t c;

	if ( ! text )
		return 0;
	for ( len = 0 ; ( c = text[len] ) != 0 ; len++ ) {
		if ( ( len >= max ) || ( c < 0x20 ) || ( c == 0x7f ) )
			return RBD_EFI_BAD;
		if ( name && ( ( c <= 0x20 ) || ( c >= 0x7f ) || ( c == '/' ) ||
			       ( c == '@' ) ) )
			return RBD_EFI_BAD;
	}
	return len;
}

/**
 * Measure "pool/image[@snap]"
 *
 * @v ident		Identity
 * @ret len		Length of the name (without the NUL), or 0 if the identity does not name an image
 */
static size_t rbd_efi_name_len ( const struct rbd_efi_ident *ident ) {
	size_t pool;
	size_t image;
	size_t snap;

	pool = rbd_efi_text_len ( ident->pool, ( RBD_NAME_MAX - 1 ), 1 );
	image = rbd_efi_text_len ( ident->image, ( RBD_NAME_MAX - 1 ), 1 );
	snap = rbd_efi_text_len ( ident->snap, ( RBD_NAME_MAX - 1 ), 1 );
	if ( ( pool == RBD_EFI_BAD ) || ( image == RBD_EFI_BAD ) ||
	     ( snap == RBD_EFI_BAD ) || ( pool == 0 ) || ( image == 0 ) )
		return 0;
	return ( pool + 1 /* "/" */ + image + ( snap ? ( 1 /* "@" */ + snap ) : 0 ) );
}

/**
 * Write "pool/image[@snap]" and a NUL (the identity has been measured: rbd_efi_name_len() is not 0)
 *
 * @v ident		Identity
 * @v out		Where to write (rbd_efi_name_len() + 1 bytes)
 * @ret end		The byte after the NUL
 */
static uint8_t * rbd_efi_name_put ( const struct rbd_efi_ident *ident,
				    uint8_t *out ) {
	size_t len;

	len = strlen ( ident->pool );
	memcpy ( out, ident->pool, len );
	out += len;
	*(out++) = '/';
	len = strlen ( ident->image );
	memcpy ( out, ident->image, len );
	out += len;
	if ( ident->snap && ident->snap[0] ) {
		*(out++) = '@';
		len = strlen ( ident->snap );
		memcpy ( out, ident->snap, len );
		out += len;
	}
	*(out++) = '\0';
	return out;
}

/**
 * Add bytes to an FNV-1a hash
 *
 * @v hash		Hash so far
 * @v data		Data
 * @v len		Length of data
 * @ret hash		New hash
 */
static uint32_t rbd_efi_fnv ( uint32_t hash, const void *data, size_t len ) {
	const uint8_t *byte = data;

	while ( len-- ) {
		hash ^= *(byte++);
		hash *= 16777619U;
	}
	return hash;
}

/**
 * Hash the identity for the SATA node (FNV-1a over the cluster id, the pool, the image and the snapshot)
 *
 * @v ident		Identity (valid: rbd_efi_name_len() is not 0)
 * @ret port		Port number, 0 to 0xfffe (0xffff is reserved by the specification)
 */
static unsigned int rbd_efi_sata_port ( const struct rbd_efi_ident *ident ) {
	static const uint8_t zero[16];
	uint32_t hash = 2166136261U;

	/* The fsid first (as 16 zero bytes if unknown), then the name as the vendor node spells it */
	hash = rbd_efi_fnv ( hash, ( ident->fsid_known ? ident->fsid : zero ),
			     16 );
	hash = rbd_efi_fnv ( hash, ident->pool, strlen ( ident->pool ) );
	hash = rbd_efi_fnv ( hash, "/", 1 );
	hash = rbd_efi_fnv ( hash, ident->image, strlen ( ident->image ) );
	if ( ident->snap && ident->snap[0] ) {
		hash = rbd_efi_fnv ( hash, "@", 1 );
		hash = rbd_efi_fnv ( hash, ident->snap, strlen ( ident->snap ) );
	}
	return ( hash % 0xffffU );
}

/**
 * Check whether a URI query parameter is one of the known options
 *
 * @v name		Parameter name (not NUL-terminated)
 * @v len		Length of name
 * @ret known		The name is a known option
 */
static int rbd_efi_known_option ( const char *name, size_t len ) {
	unsigned int i;

	for ( i = 0 ; i < ( sizeof ( rbd_efi_uri_options ) /
			    sizeof ( rbd_efi_uri_options[0] ) ) ; i++ ) {
		if ( ( strlen ( rbd_efi_uri_options[i] ) == len ) &&
		     ( memcmp ( rbd_efi_uri_options[i], name, len ) == 0 ) )
			return 1;
	}
	return 0;
}

/** A redacted URI being written (or only measured, if out is NULL) */
struct rbd_efi_redaction {
	/** Output buffer, or NULL to only count */
	char *out;
	/** Size of the output buffer */
	size_t max;
	/** Bytes produced so far */
	size_t len;
	/** The output would not fit */
	int overflow;
};

/**
 * Append to a redacted URI
 *
 * @v red		Redaction
 * @v data		Data
 * @v len		Length of data
 */
static void rbd_efi_redact_put ( struct rbd_efi_redaction *red,
				 const char *data, size_t len ) {

	if ( len > ( RBD_EFI_URI_MAX - red->len ) ) {
		red->overflow = 1;
		return;
	}
	if ( red->out ) {
		if ( len > ( red->max - red->len ) ) {
			red->overflow = 1;
			return;
		}
		memcpy ( ( red->out + red->len ), data, len );
	}
	red->len += len;
}

/**
 * Redact a URI for a device path
 *
 * @v uri		URI: scheme "://" [userinfo "@"] host ["/" path] ["?" query] ["#" fragment]
 * @v out		Output buffer (NUL-terminated on success), or NULL to only measure
 * @v max		Size of the output buffer (a result that does not fit with its NUL is an error)
 * @ret len		Length of the redacted URI (without the NUL), or 0 on error
 *
 * Removed: the password ("user:password@" becomes "user@"), the fragment, and every query parameter whose name is not one
 * of the known URI options (an allow list, not a block list: a key hidden under any other name or spelling is dropped
 * too). Kept byte for byte: everything else. An input that is empty, longer than RBD_EFI_URI_MAX, holds a byte outside
 * 0x21-0x7e (spaces, controls and non-ASCII are percent-encoded by a correct URI formatter) or has no scheme and "://" is an
 * error (nothing is written to be used): the caller then has no path, which fails the boot closed. The result is never
 * longer than the input.
 */
size_t rbd_efi_uri_redact ( const char *uri, char *out, size_t max ) {
	struct rbd_efi_redaction red;
	const char *scheme_end;
	const char *auth;
	const char *auth_end;
	const char *at;
	const char *colon;
	const char *frag;
	const char *path_end;
	const char *query;
	const char *param;
	const char *param_end;
	const char *eq;
	const char *p;
	size_t len;
	int first;

	/* Check the input */
	len = rbd_efi_text_len ( uri, RBD_EFI_URI_MAX, 0 );
	if ( ( len == 0 ) || ( len == RBD_EFI_BAD ) )
		return 0;
	for ( p = uri ; *p ; p++ ) {
		if ( ( ( uint8_t ) *p < 0x21 ) || ( ( uint8_t ) *p > 0x7e ) )
			return 0;
	}

	/* Scheme: at least one character, then "://" */
	scheme_end = strstr ( uri, "://" );
	if ( ( ! scheme_end ) || ( scheme_end == uri ) )
		return 0;
	for ( p = uri ; p < scheme_end ; p++ ) {
		if ( ! ( ( ( *p >= 'a' ) && ( *p <= 'z' ) ) ||
			 ( ( *p >= 'A' ) && ( *p <= 'Z' ) ) ||
			 ( ( *p >= '0' ) && ( *p <= '9' ) ) ||
			 ( *p == '+' ) || ( *p == '-' ) || ( *p == '.' ) ) )
			return 0;
	}
	auth = ( scheme_end + 3 );

	/* The fragment ends the URI; the authority ends at "/", "?" or "#" */
	frag = strchr ( auth, '#' );
	path_end = ( frag ? frag : ( uri + len ) );
	auth_end = auth;
	while ( ( auth_end < path_end ) && ( *auth_end != '/' ) &&
		( *auth_end != '?' ) )
		auth_end++;

	/* Authority: drop the password of "user:password@host" (the last "@" ends the user information) */
	red.out = out;
	red.max = max;
	red.len = 0;
	red.overflow = 0;
	at = NULL;
	for ( p = auth ; p < auth_end ; p++ ) {
		if ( *p == '@' )
			at = p;
	}
	colon = NULL;
	if ( at ) {
		for ( p = auth ; p < at ; p++ ) {
			if ( *p == ':' ) {
				colon = p;
				break;
			}
		}
	}
	if ( colon ) {
		rbd_efi_redact_put ( &red, uri, ( colon - uri ) );
		rbd_efi_redact_put ( &red, at, ( auth_end - at ) );
	} else {
		rbd_efi_redact_put ( &red, uri, ( auth_end - uri ) );
	}

	/* Path, up to the query */
	query = auth_end;
	while ( ( query < path_end ) && ( *query != '?' ) )
		query++;
	rbd_efi_redact_put ( &red, auth_end, ( query - auth_end ) );

	/* Query: the known options only */
	if ( query < path_end ) {
		first = 1;
		param = ( query + 1 );
		for ( ; ; ) {
			param_end = param;
			while ( ( param_end < path_end ) && ( *param_end != '&' ) )
				param_end++;
			eq = param;
			while ( ( eq < param_end ) && ( *eq != '=' ) )
				eq++;
			if ( ( param_end > param ) &&
			     rbd_efi_known_option ( param, ( eq - param ) ) ) {
				rbd_efi_redact_put ( &red, ( first ? "?" : "&" ),
						     1 );
				rbd_efi_redact_put ( &red, param,
						     ( param_end - param ) );
				first = 0;
			}
			if ( param_end >= path_end )
				break;
			param = ( param_end + 1 );
		}
	}

	/* Terminate */
	if ( red.overflow || ( red.len == 0 ) )
		return 0;
	if ( out ) {
		if ( red.len >= max )
			return 0;
		out[red.len] = '\0';
	}
	return red.len;
}

/**
 * Measure the node (or the node's data) of a path flavour
 *
 * @v ident		Identity
 * @ret len		Length of the node without the end node, or 0 if the identity cannot be described
 */
static size_t rbd_efi_node_size ( const struct rbd_efi_ident *ident ) {
	size_t name;
	size_t uri;

	rbd_efi_check_constants();
	switch ( ident->devpath ) {
	case RBD_DEVPATH_VENDOR:
		name = rbd_efi_name_len ( ident );
		if ( ! name )
			return 0;
		return ( RBD_EFI_VENDOR_FIXED + name + 1 /* NUL */ );
	case RBD_DEVPATH_URI:
		uri = rbd_efi_uri_redact ( ident->uri, NULL, 0 );
		if ( ! uri )
			return 0;
		return ( RBD_EFI_HDR + uri + 1 /* NUL */ );
	case RBD_DEVPATH_SATA:
		if ( ! rbd_efi_name_len ( ident ) )
			return 0;
		return RBD_EFI_SATA_LEN;
	default:
		return 0;
	}
}

/**
 * Measure the node and the end node of a device path
 *
 * @v ident		Identity
 * @ret len		Length of the node plus the end node, or 0 if the identity cannot be described
 */
size_t rbd_efi_node_len ( const struct rbd_efi_ident *ident ) {
	size_t len;

	len = rbd_efi_node_size ( ident );
	return ( len ? ( len + RBD_EFI_HDR ) : 0 );
}

/**
 * Build the node and the end node of a device path
 *
 * @v ident		Identity
 * @v out		Output buffer
 * @v max		Size of the output buffer
 * @ret len		Bytes written (rbd_efi_node_len()), or 0 if the identity cannot be described or the buffer is too small
 *			(nothing is written then)
 */
size_t rbd_efi_node_build ( const struct rbd_efi_ident *ident, void *out,
			    size_t max ) {
	uint8_t *start = out;
	uint8_t *data;
	size_t size;
	size_t len;
	unsigned int port;

	size = rbd_efi_node_size ( ident );
	if ( ( size == 0 ) || ( max < ( size + RBD_EFI_HDR ) ) )
		return 0;

	switch ( ident->devpath ) {
	case RBD_DEVPATH_VENDOR:
		data = rbd_efi_header ( start, RBD_EFI_TYPE_MESSAGING,
					RBD_EFI_SUB_VENDOR, size );
		rbd_efi_copy ( data, rbd_efi_vendor_guid,
			       sizeof ( rbd_efi_vendor_guid ) );
		data += sizeof ( rbd_efi_vendor_guid );
		*(data++) = RBD_EFI_VENDOR_VERSION;
		*(data++) = 0;
		if ( ident->fsid_known ) {
			rbd_efi_copy ( data, ident->fsid, 16 );
		} else {
			rbd_efi_zero ( data, 16 );
		}
		data += 16;
		data = rbd_efi_name_put ( ident, data );
		break;
	case RBD_DEVPATH_URI:
		data = rbd_efi_header ( start, RBD_EFI_TYPE_MESSAGING,
					RBD_EFI_SUB_URI, size );
		len = rbd_efi_uri_redact ( ident->uri, ( ( char * ) data ),
					   ( size - RBD_EFI_HDR ) );
		if ( ( len + 1 + RBD_EFI_HDR ) != size )
			return 0;
		data += ( len + 1 );
		break;
	case RBD_DEVPATH_SATA:
		port = rbd_efi_sata_port ( ident );
		data = rbd_efi_header ( start, RBD_EFI_TYPE_MESSAGING,
					RBD_EFI_SUB_SATA, size );
		data[0] = ( port & 0xff );
		data[1] = ( ( port >> 8 ) & 0xff );
		data[2] = 0xff;		/* port multiplier port: 0xffff = directly connected */
		data[3] = 0xff;
		data[4] = 0;		/* LUN 0 */
		data[5] = 0;
		data += 6;
		break;
	default:
		return 0;
	}

	/* The node ends where the size says it does */
	if ( ( size_t ) ( data - start ) != size )
		return 0;
	rbd_efi_end ( data );
	return ( size + RBD_EFI_HDR );
}

/**
 * Measure a device path up to its end node, and check that it is well formed
 *
 * @v path		Device path
 * @v max		Size of the buffer that holds it
 * @ret len		Length of the nodes in front of the end node, or 0 if there is no node, a node is shorter than its header
 *			or runs beyond the buffer, an instance end node (several paths in one) is found, the end node is not
 *			the end of the entire path, or the path is not terminated or is longer than RBD_EFI_PATH_MAX
 */
size_t rbd_efi_prefix_len ( const void *path, size_t max ) {
	const uint8_t *node = path;
	size_t off = 0;
	size_t len;

	if ( ( ! path ) || ( max > RBD_EFI_PATH_MAX ) )
		max = ( path ? RBD_EFI_PATH_MAX : 0 );
	for ( ; ; ) {
		if ( ( max - off ) < RBD_EFI_HDR )
			return 0;
		len = ( node[off + 2] | ( node[off + 3] << 8 ) );
		if ( node[off] == RBD_EFI_TYPE_END ) {
			if ( ( node[off + 1] != RBD_EFI_SUB_END_ENTIRE ) ||
			     ( len != RBD_EFI_HDR ) )
				return 0;
			return off;
		}
		if ( ( len < RBD_EFI_HDR ) || ( len > ( max - off ) ) )
			return 0;
		off += len;
	}
}

/**
 * Compose the device path of the image: the network device's path (without its end node), the node, the end node
 *
 * @v prefix		Device path of the network device (as efi_netdev_path() returns it)
 * @v prefix_max	Size of the buffer that holds it
 * @v ident		Identity of the image
 * @ret path		Device path, or NULL (the prefix is malformed or empty, the identity cannot be described, the path
 *			would be longer than RBD_EFI_PATH_MAX, or out of memory); the caller frees it with free()
 */
EFI_DEVICE_PATH_PROTOCOL * rbd_efi_compose ( const void *prefix,
					     size_t prefix_max,
					     const struct rbd_efi_ident *ident ) {
	size_t prefix_len;
	size_t node_len;
	uint8_t *path;

	prefix_len = rbd_efi_prefix_len ( prefix, prefix_max );
	node_len = rbd_efi_node_len ( ident );
	if ( ( prefix_len == 0 ) || ( node_len == 0 ) ||
	     ( node_len > RBD_EFI_PATH_MAX ) ||
	     ( prefix_len > ( RBD_EFI_PATH_MAX - node_len ) ) )
		return NULL;
	path = zalloc ( prefix_len + node_len );
	if ( ! path )
		return NULL;
	memcpy ( path, prefix, prefix_len );
	if ( rbd_efi_node_build ( ident, ( path + prefix_len ),
				  node_len ) != node_len ) {
		free ( path );
		return NULL;
	}
	return ( ( EFI_DEVICE_PATH_PROTOCOL * ) path );
}

#ifdef PLATFORM_efi

#include <errno.h>
#include <stdio.h>
#include <byteswap.h>
#include <ipxe/in.h>
#include <ipxe/tcpip.h>
#include <ipxe/netdevice.h>

/**
 * Get the identity of a session's image (default: there is none)
 *
 * @v session		Cluster session
 * @v source		Structure to fill in
 * @ret rc		Return status code
 *
 * Weak: the session module defines the real one (rbd_efi.h) and the linker takes it instead of this. Until then the SAN hook
 * fails with "no device path" and nothing is installed.
 */
__weak int rbd_session_efi_source ( struct rbd_session *session __unused,
				    struct rbd_efi_source *source __unused ) {

	return -ENOTSUP;
}

/**
 * Find the network device that routes to a monitor
 *
 * @v mon		Monitor address
 * @ret netdev		Network device, or NULL
 *
 * (The connection table of rbd_conn.c turns a wr_addr into a socket address as well; no pointer to a socket is needed here,
 * only the route, so the few lines are repeated instead of widening rbd_priv.h. The link-local scope of an IPv6 monitor is
 * not part of a wr_addr: such a monitor routes by its address alone, like in the connection table.)
 */
static struct net_device * rbd_efi_netdev ( const wr_addr *mon ) {
	struct sockaddr_tcpip st;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	memset ( &st, 0, sizeof ( st ) );
	switch ( mon->family ) {
	case WR_AF_IPV4:
		sin = ( ( struct sockaddr_in * ) &st );
		sin->sin_family = AF_INET;
		sin->sin_port = htons ( mon->port );
		rbd_efi_copy ( &sin->sin_addr, mon->ip, sizeof ( sin->sin_addr ) );
		break;
	case WR_AF_IPV6:
		sin6 = ( ( struct sockaddr_in6 * ) &st );
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons ( mon->port );
		rbd_efi_copy ( &sin6->sin6_addr, mon->ip, sizeof ( sin6->sin6_addr ) );
		break;
	default:
		return NULL;
	}
	return tcpip_netdev ( &st );
}

/**
 * Describe the device as an EFI device path
 *
 * @v rbd		RBD device
 * @ret path		EFI device path, or NULL (caller frees it with free())
 *
 * NULL fails the whole SAN hook (efi_block_hook(): no device path), which is the intended way to fail: a disk the firmware
 * cannot tell from another must not be presented. The console line says which of the causes it was; it never prints the
 * image, the URI or anything secret.
 */
EFI_DEVICE_PATH_PROTOCOL * rbd_efi_path ( struct rbd_device *rbd ) {
	struct rbd_efi_source source;
	struct net_device *netdev;
	EFI_DEVICE_PATH_PROTOCOL *netpath;
	EFI_DEVICE_PATH_PROTOCOL *path;

	/* What the session knows of the image */
	memset ( &source, 0, sizeof ( source ) );
	if ( rbd_session_efi_source ( rbd->session, &source ) != 0 ) {
		printf ( "rbd: the image's identity is not available for the "
			 "EFI device path\n" );
		return NULL;
	}
	source.ident.devpath = rbd->devpath;

	/* The network device that routes to the first monitor, and its path */
	netdev = rbd_efi_netdev ( &source.mon );
	if ( ! netdev ) {
		printf ( "rbd: no network device routes to the first monitor "
			 "(EFI device path)\n" );
		return NULL;
	}
	netpath = efi_netdev_path ( netdev );
	if ( ! netpath ) {
		printf ( "rbd: could not describe the network device (EFI "
			 "device path)\n" );
		return NULL;
	}

	/* Network path + node + end node */
	path = rbd_efi_compose ( netpath,
				 ( efi_path_len ( netpath ) +
				   sizeof ( EFI_DEVICE_PATH_PROTOCOL ) ),
				 &source.ident );
	free ( netpath );
	if ( ! path ) {
		printf ( "rbd: cannot build the EFI device path (devpath "
			 "option, names or URI not usable)\n" );
		return NULL;
	}
	return path;
}

#else /* PLATFORM_efi */

/**
 * Describe the device as an EFI device path (not an EFI build: there is none)
 *
 * @v rbd		RBD device
 * @ret path		NULL
 */
EFI_DEVICE_PATH_PROTOCOL * rbd_efi_path ( struct rbd_device *rbd __unused ) {

	return NULL;
}

#endif /* PLATFORM_efi */
