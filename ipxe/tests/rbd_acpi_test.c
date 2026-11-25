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
 * RBD (Ceph) SAN protocol: self-tests of the handoff ACPI table (rbd_acpi.c)
 *
 * Built into bin-x86_64-linux/tests.linux by "ipxe/tools/build.sh test" (see ipxe/tests/README.md): no network, no QEMU, no
 * cluster. The descriptor is a real struct rbd_device over a fake session (a function that hands the model whatever the test
 * wants it to see), registered on the real model with acpi_add() the way the SAN layer does; the network device is a real iPXE
 * net_device (the test network devices of src/tests/netdev_test.c) with real settings and real routes. install() is run against
 * a fake backend that behaves like iPXE's EFI and BIOS backends (it takes the table, writes its own OEM ID and OEM table ID,
 * fixes the checksum), and its output is compared with the design (docs/design/ipxe-driver.md section 9,
 * docs/design/handoff-table.md) FIELD BY FIELD, by a reader of the layout written here from the design's offsets: it does not
 * use the core's codec to say what the table should be, and the core's decoder is then run over the same bytes as a second,
 * independent opinion.
 *
 * What this covers: the content (identity, monitors in order, the default port, family-less entries skipped, the "client."
 * prefix, mode, cluster id, read-only, image id, snapshot, an absent namespace), the NIC of the first monitor (MAC, MTU, address,
 * prefix, gateway, DNS) for IPv4 and IPv6, static against learnt addresses, a VLAN device; the key only for handoff=key and
 * nowhere else in the table; handoff=none (no descriptor, no table); the 1,024-byte limit (1,024 accepted, 1,025 refused with
 * the callback never called); complete() (in progress until the image is open and the route is known, a failed session's error
 * passes); two installs byte for byte the same, a changed world in the next table, two devices two tables in order; the
 * OEM fields do not matter; an install failure ends the pass with its error.
 *
 * Secure Boot: FILE_SECBOOT ( FORBIDDEN ), like every file of the driver (docs/design/ipxe-driver.md, section 13). A test object
 * is only ever linked into a self-test program, never into a bootable image.
 */

/* iPXE's error macros carry the identifier of the file that uses them (see rbd_selftest.c) */
#include <ipxe/errfile.h>
#define ERRFILE_rbd_acpi_test ( ERRFILE_OTHER | 0x007a0000 )

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ipxe/netdevice.h>
#include <ipxe/vlan.h>
#include <ipxe/acpi.h>
#include <ipxe/test.h>
#include "netdev_test.h"
#include "winrbd/rbd_acpi.h"

/* ---- error codes ------------------------------------------------------------------------------------------------------ */

/** An error code as a constant expression, as seen from this file */
#define RBD_ERR( name ) ( -__einfo_errno ( EINFO_ ## name ) )

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

/**
 * Copy bytes, whatever their alignment (see rbd_acpi_copy() in rbd_acpi.c: iPXE's memcpy() of a constant length assumes alignment)
 *
 * @v dest		Destination
 * @v src		Source
 * @v len		Length
 */
static void rbd_copy ( void *dest, const void *src, size_t len ) {
	uint8_t *dest_bytes = dest;
	const uint8_t *src_bytes = src;

	while ( len-- )
		*(dest_bytes++) = *(src_bytes++);
}

/* ---- the fake session and the fake devices ------------------------------------------------------------------------------ */

/** A fake session: what the model sees of a cluster session */
struct rbd_fake {
	/** What the source returns: 0 (the image is open and *src is real), -EINPROGRESS, or a failure */
	int rc;
	/** What it provides when rc is 0 */
	struct rbd_handoff_source src;
	/** Times the model asked */
	unsigned int asked;
};

/**
 * Provide the handoff data of a fake session
 *
 * @v session		The session (really a struct rbd_fake)
 * @v source		Handoff data to fill in
 * @ret rc		Return status code
 */
static int rbd_fake_source ( struct rbd_session *session,
			     struct rbd_handoff_source *source ) {
	struct rbd_fake *fake = ( ( struct rbd_fake * ) session );

	fake->asked++;
	if ( fake->rc )
		return fake->rc;
	rbd_copy ( source, &fake->src, sizeof ( *source ) );
	return 0;
}

/** The cephx key of the fake sessions (a pattern that cannot be mistaken for anything else in a table) */
static wr_key rbd_fake_key;

/**
 * Create a device over a fake session
 *
 * @v fake		Fake session
 * @v handoff		RBD_HANDOFF_*
 * @ret rbd		Device (free() it)
 */
static struct rbd_device * rbd_fake_device ( struct rbd_fake *fake,
					     unsigned int handoff ) {
	struct rbd_device *rbd;

	rbd = zalloc ( sizeof ( *rbd ) );
	assert ( rbd != NULL );
	ref_init ( &rbd->refcnt, NULL );
	rbd->session = ( ( struct rbd_session * ) fake );
	rbd->handoff = handoff;
	return rbd;
}

/**
 * Fill in a fake session with an ordinary open image
 *
 * @v fake		Fake session
 * @v mon0		First monitor address (dotted quad)
 */
static void rbd_fake_open ( struct rbd_fake *fake, const uint8_t *mon0,
			    unsigned int mon0_family ) {
	struct rbd_handoff_source *src = &fake->src;
	unsigned int i;

	memset ( fake, 0, sizeof ( *fake ) );
	src->user = "winrbd-boot";
	src->pool = "winrbd";
	src->image = "wrtest-acpi";
	src->mode = WR_MODE_CRC_ONLY;
	src->key = &rbd_fake_key;
	src->n_mons = 1;
	src->mons[0].family = mon0_family;
	for ( i = 0 ; i < ( ( mon0_family == WR_AF_IPV4 ) ? 4 : 16 ) ; i++ )
		src->mons[0].ip[i] = mon0[i];
	src->mons[0].port = 3300;
}

/* ---- the fake backend --------------------------------------------------------------------------------------------------- */

/** What the fake backend saw */
struct rbd_capture {
	/** Number of tables installed */
	unsigned int count;
	/** Return status code of the next installs (0 = succeed) */
	int rc;
	/** Length of each table */
	size_t len[4];
	/** The table of the last call, where the model built it (read AFTER the model has freed it, see the wipe tests) */
	const uint8_t *last;
	/** Length of the table of the last call */
	size_t last_len;
	/** Each table as the model gave it to the backend */
	uint8_t raw[4][WR_HANDOFF_MAX_TABLE + 64];
	/** Each table after the backend wrote its OEM fields and fixed the checksum, as iPXE's backends do */
	uint8_t fixed[4][WR_HANDOFF_MAX_TABLE + 64];
};

/** The backend's record (the install callback has no context argument, like iPXE's) */
static struct rbd_capture rbd_capture;

/**
 * Install a table, as iPXE's EFI and BIOS backends do (efi_block_install(), int13_install())
 *
 * @v acpi		The table
 * @ret rc		Return status code
 */
static int rbd_fake_install ( struct acpi_header *acpi ) {
	unsigned int n = rbd_capture.count;
	size_t len = le32_to_cpu ( acpi->length );

	rbd_capture.last = ( ( const uint8_t * ) acpi );
	rbd_capture.last_len = len;
	if ( rbd_capture.rc )
		return rbd_capture.rc;
	assert ( n < 4 );
	assert ( len <= WR_HANDOFF_MAX_TABLE );
	rbd_capture.len[n] = len;
	memcpy ( rbd_capture.raw[n], acpi, len );
	strncpy ( acpi->oem_id, "FENSYS", sizeof ( acpi->oem_id ) );
	strncpy ( acpi->oem_table_id, "iPXE", sizeof ( acpi->oem_table_id ) );
	acpi_fix_checksum ( acpi );
	memcpy ( rbd_capture.fixed[n], acpi, len );
	rbd_capture.count++;
	return 0;
}

/** Forget what the backend saw (and make it succeed again) */
static void rbd_capture_reset ( void ) {

	memset ( &rbd_capture, 0, sizeof ( rbd_capture ) );
}

/* ---- a reader of the layout, from the design's offsets ------------------------------------------------------------------ */

/** Size of the ACPI header */
#define T_HDR 36

/** Size of the fixed part of the body (header_len) */
#define T_FIXED 116

/** Value of an absent offset */
#define T_ABSENT 0xffff

/** Read a little-endian 16-bit field */
static unsigned int rbd_le16 ( const uint8_t *p ) {

	return ( p[0] | ( p[1] << 8 ) );
}

/** Read a little-endian 32-bit field */
static unsigned long rbd_le32 ( const uint8_t *p ) {

	return ( ( unsigned long ) p[0] | ( ( unsigned long ) p[1] << 8 ) |
		 ( ( unsigned long ) p[2] << 16 ) |
		 ( ( unsigned long ) p[3] << 24 ) );
}

/** One monitor in an expectation */
struct rbd_exp_mon {
	/** Family: 4 or 6 */
	uint8_t family;
	/** Port */
	uint16_t port;
	/** Address */
	uint8_t ip[16];
};

/** What a table must contain (the design's fields) */
struct rbd_expect {
	uint32_t flags;
	uint8_t mode;
	uint8_t nic_family;
	uint8_t nic_prefix;
	uint16_t nic_vlan;
	uint16_t nic_mtu;
	uint8_t mac[6];
	uint8_t ip[16];
	uint8_t gateway[16];
	uint8_t dns[16];
	uint8_t fsid[16];
	const char *entity;
	const char *pool;
	const char *image;
	const char *image_id;
	const char *snap;
	unsigned int n_mons;
	struct rbd_exp_mon mons[WR_MAX_MONS];
	/** The key bytes expected in the table, or NULL (no key) */
	const uint8_t *key;
	unsigned int key_len;
	unsigned int key_type;
};

/** Is s non-empty (the table's notion of "present") */
static int rbd_present ( const char *s ) {

	return ( s && s[0] );
}

/**
 * Check one string field of a table
 *
 * @v t			Table
 * @v var		Start of the variable area
 * @v off		Offset field
 * @v want		Expected string, or NULL / "" for absent
 * @v end		End of the table
 * @v file		Test code file
 * @v line		Test code line
 */
static void rbd_check_stringx ( const uint8_t *t, const uint8_t *var,
				unsigned int off, const char *want,
				const uint8_t *end, const char *file,
				unsigned int line ) {

	if ( ! rbd_present ( want ) ) {
		okx ( off == T_ABSENT, file, line );
		return;
	}
	okx ( off != T_ABSENT, file, line );
	if ( off == T_ABSENT )
		return;
	okx ( ( var + off + strlen ( want ) + 1 ) <= end, file, line );
	okx ( memcmp ( var + off, want, strlen ( want ) + 1 ) == 0, file, line );
	( void ) t;
}

/**
 * Check a table against the design, field by field
 *
 * @v t			Table (as the backend saw it, after it wrote its OEM fields: oem is true) or raw (oem is false)
 * @v len		Length of the table as the backend reports it
 * @v e			Expectation
 * @v oem		The backend's OEM fields are in the table
 * @v file		Test code file
 * @v line		Test code line
 */
static void rbd_check_tablex ( const uint8_t *t, size_t len,
			       const struct rbd_expect *e, int oem,
			       const char *file, unsigned int line ) {
	const uint8_t *body = ( t + T_HDR );
	const uint8_t *var = ( body + T_FIXED );
	const uint8_t *end = ( t + len );
	unsigned int sum = 0;
	size_t area = 0;
	unsigned int i;
	size_t k;

	/* ACPI header: signature, length, revision, checksum; the OEM and creator fields are the backend's or zero */
	okx ( len >= ( T_HDR + T_FIXED ), file, line );
	okx ( len <= 1024, file, line );
	if ( len < ( T_HDR + T_FIXED ) )
		return;
	okx ( memcmp ( t, "rBFT", 4 ) == 0, file, line );
	okx ( rbd_le32 ( t + 4 ) == len, file, line );
	okx ( t[8] == 1, file, line );
	for ( k = 0 ; k < len ; k++ )
		sum += t[k];
	okx ( ( sum & 0xff ) == 0, file, line );
	if ( oem ) {
		okx ( memcmp ( t + 10, "FENSYS", 6 ) == 0, file, line );
		okx ( memcmp ( t + 16, "iPXE\0\0\0\0", 8 ) == 0, file, line );
	} else {
		for ( k = 10 ; k < T_HDR ; k++ )
			okx ( t[k] == 0, file, line );
	}

	/* Body, fixed part */
	okx ( memcmp ( body + 0, "WRBT", 4 ) == 0, file, line );
	okx ( rbd_le16 ( body + 4 ) == 1, file, line );
	okx ( rbd_le16 ( body + 6 ) == T_FIXED, file, line );
	okx ( rbd_le32 ( body + 8 ) == e->flags, file, line );
	okx ( body[12] == 1, file, line );			/* auth: cephx */
	okx ( body[13] == e->mode, file, line );
	okx ( body[14] == ( e->key ? e->key_type : 0 ), file, line );
	okx ( body[15] == ( e->key ? e->key_len : 0 ), file, line );
	okx ( body[16] == e->n_mons, file, line );
	okx ( body[17] == e->nic_family, file, line );
	okx ( body[18] == e->nic_prefix, file, line );
	okx ( body[19] == 0, file, line );
	okx ( memcmp ( body + 20, e->fsid, 16 ) == 0, file, line );
	okx ( memcmp ( body + 36, e->mac, 6 ) == 0, file, line );
	okx ( rbd_le16 ( body + 42 ) == e->nic_vlan, file, line );
	okx ( rbd_le16 ( body + 44 ) == e->nic_mtu, file, line );
	okx ( rbd_le16 ( body + 46 ) == 0, file, line );
	okx ( memcmp ( body + 48, e->ip, 16 ) == 0, file, line );
	okx ( memcmp ( body + 64, e->gateway, 16 ) == 0, file, line );
	okx ( memcmp ( body + 80, e->dns, 16 ) == 0, file, line );
	for ( k = 112 ; k < T_FIXED ; k++ )
		okx ( body[k] == 0, file, line );

	/* Strings (offsets from the start of the variable area), the namespace absent in version 1 */
	rbd_check_stringx ( t, var, rbd_le16 ( body + 96 ), e->entity, end, file, line );
	rbd_check_stringx ( t, var, rbd_le16 ( body + 98 ), e->pool, end, file, line );
	okx ( rbd_le16 ( body + 100 ) == T_ABSENT, file, line );
	rbd_check_stringx ( t, var, rbd_le16 ( body + 102 ), e->image, end, file, line );
	rbd_check_stringx ( t, var, rbd_le16 ( body + 104 ), e->image_id, end, file, line );
	rbd_check_stringx ( t, var, rbd_le16 ( body + 106 ), e->snap, end, file, line );

	/* Monitor records: {u8 family, u8 reserved, u16 port, u8 ip[16]}, in the order given */
	okx ( rbd_le16 ( body + 108 ) != T_ABSENT, file, line );
	for ( i = 0 ; i < e->n_mons ; i++ ) {
		const uint8_t *rec = ( var + rbd_le16 ( body + 108 ) +
				       ( i * WR_HANDOFF_MON_REC_LEN ) );

		okx ( ( rec + WR_HANDOFF_MON_REC_LEN ) <= end, file, line );
		if ( ( rec + WR_HANDOFF_MON_REC_LEN ) > end )
			break;
		okx ( rec[0] == e->mons[i].family, file, line );
		okx ( rec[1] == 0, file, line );
		okx ( rbd_le16 ( rec + 2 ) == e->mons[i].port, file, line );
		okx ( memcmp ( rec + 4, e->mons[i].ip, 16 ) == 0, file, line );
	}

	/* The key, only when it is meant to be there */
	if ( e->key ) {
		okx ( rbd_le16 ( body + 110 ) != T_ABSENT, file, line );
		okx ( ( var + rbd_le16 ( body + 110 ) + e->key_len ) <= end,
		      file, line );
		if ( ( var + rbd_le16 ( body + 110 ) + e->key_len ) <= end )
			okx ( memcmp ( var + rbd_le16 ( body + 110 ), e->key,
				       e->key_len ) == 0, file, line );
	} else {
		okx ( rbd_le16 ( body + 110 ) == T_ABSENT, file, line );
	}

	/* No padding, no trailing bytes: the table is exactly the fixed part and what the fields describe */
	area += rbd_present ( e->entity ) ? ( strlen ( e->entity ) + 1 ) : 0;
	area += rbd_present ( e->pool ) ? ( strlen ( e->pool ) + 1 ) : 0;
	area += rbd_present ( e->image ) ? ( strlen ( e->image ) + 1 ) : 0;
	area += rbd_present ( e->image_id ) ? ( strlen ( e->image_id ) + 1 ) : 0;
	area += rbd_present ( e->snap ) ? ( strlen ( e->snap ) + 1 ) : 0;
	area += ( e->n_mons * WR_HANDOFF_MON_REC_LEN );
	area += ( e->key ? e->key_len : 0 );
	okx ( len == ( T_HDR + T_FIXED + area ), file, line );
}
#define rbd_check_table( t, len, e, oem ) \
	rbd_check_tablex ( t, len, e, oem, __FILE__, __LINE__ )

/**
 * Check that a byte pattern does not occur anywhere in a table
 *
 * @v t			Table
 * @v len		Length of the table
 * @v pattern		Pattern
 * @v plen		Length of the pattern
 * @ret found		The pattern occurs
 */
static int rbd_contains ( const uint8_t *t, size_t len, const uint8_t *pattern,
			  size_t plen ) {
	size_t i;

	for ( i = 0 ; ( i + plen ) <= len ; i++ ) {
		if ( memcmp ( t + i, pattern, plen ) == 0 )
			return 1;
	}
	return 0;
}

/**
 * Check a table with the core's decoder (a second opinion on the same bytes)
 *
 * @v t			Table
 * @v len		Length of the table
 * @v e			Expectation
 * @v file		Test code file
 * @v line		Test code line
 */
static void rbd_decode_okx ( const uint8_t *t, size_t len,
			     const struct rbd_expect *e, const char *file,
			     unsigned int line ) {
	wr_handoff_info *info;
	unsigned int i;

	info = zalloc ( sizeof ( *info ) );
	okx ( info != NULL, file, line );
	if ( ! info )
		return;
	okx ( wr_handoff_decode_table ( t, len, info ) == WR_OK, file, line );
	okx ( info->flags == e->flags, file, line );
	okx ( info->msgr_mode == e->mode, file, line );
	okx ( info->mon_count == e->n_mons, file, line );
	okx ( info->nic_family == e->nic_family, file, line );
	okx ( info->nic_vlan == e->nic_vlan, file, line );
	okx ( info->nic_mtu == e->nic_mtu, file, line );
	okx ( memcmp ( info->nic_ip, e->ip, 16 ) == 0, file, line );
	okx ( info->entity && ( strcmp ( info->entity, e->entity ) == 0 ),
	      file, line );
	okx ( info->pool && ( strcmp ( info->pool, e->pool ) == 0 ), file, line );
	okx ( info->image && ( strcmp ( info->image, e->image ) == 0 ),
	      file, line );
	okx ( rbd_present ( e->image_id ) ==
	      ( info->image_id && info->image_id[0] ), file, line );
	okx ( rbd_present ( e->snap ) ==
	      ( info->snapshot && info->snapshot[0] ), file, line );
	for ( i = 0 ; ( ( i < e->n_mons ) && ( i < info->mon_count ) ) ; i++ ) {
		okx ( info->mons[i].family == e->mons[i].family, file, line );
		okx ( info->mons[i].port == e->mons[i].port, file, line );
		okx ( memcmp ( info->mons[i].ip, e->mons[i].ip, 16 ) == 0,
		      file, line );
	}
	okx ( ( info->key != NULL ) == ( e->key != NULL ), file, line );
	free ( info );
}
#define rbd_decode_ok( t, len, e ) \
	rbd_decode_okx ( t, len, e, __FILE__, __LINE__ )

/* ---- running the model -------------------------------------------------------------------------------------------------- */

/**
 * Register a device with the model, as the SAN layer does for a path
 *
 * @v rbd		Device
 * @ret desc		Descriptor, or NULL
 */
static struct acpi_descriptor * rbd_register ( struct rbd_device *rbd ) {
	struct acpi_descriptor *desc;

	desc = rbd_acpi_describe ( rbd );
	if ( desc )
		acpi_add ( desc );
	return desc;
}

/**
 * Remove a device from the model
 *
 * @v desc		Descriptor, or NULL
 */
static void rbd_unregister ( struct acpi_descriptor *desc ) {

	if ( desc )
		acpi_del ( desc );
}

/**
 * Install through the model's own function with the fake session
 *
 * @ret rc		Return status code
 */
static int rbd_run_install ( void ) {

	return rbd_acpi_install_with ( rbd_fake_install, rbd_fake_source );
}

/* ---- the test networks -------------------------------------------------------------------------------------------------- */

/** 10.77.0.20/24 by hand, a gateway and a DNS server by hand */
TESTNET ( rbdn4, "52:54:00:77:10:01",
	  { "ip", "10.77.0.20" },
	  { "netmask", "255.255.255.0" },
	  { "gateway", "10.77.0.1" },
	  { "dns", "10.77.0.2" } );

/** 10.78.0.30/16 learnt (a DHCP block of the device), the gateway and the DNS server too */
TESTNET ( rbdn4d, "52:54:00:77:10:02",
	  { "dhcp/ip", "10.78.0.30" },
	  { "dhcp/netmask", "255.255.0.0" },
	  { "dhcp/gateway", "10.78.255.254" },
	  { "dhcp/dns", "10.78.0.53" } );

/** An IPv6 address, prefix, router and DNS server by hand */
TESTNET ( rbdn6, "52:54:00:77:10:03",
	  { "ip6", "2001:db8:77::20" },
	  { "len6", "64" },
	  { "gateway6", "2001:db8:77::1" },
	  { "dns6", "2001:db8:77::2" } );

/** The trunk of the VLAN device (no address of its own) */
TESTNET ( rbdn4t, "52:54:00:77:10:04" );

/** 172.20.0.5 by hand, no netmask (iPXE then uses the class B default, /16), no gateway, no DNS server of its own */
TESTNET ( rbdn4c, "52:54:00:77:10:05",
	  { "ip", "172.20.0.5" } );

/** Monitor 10.77.0.10 (on rbdn4) */
static const uint8_t rbd_mon_a[4] = { 10, 77, 0, 10 };

/** Monitor 10.77.0.11 */
static const uint8_t rbd_mon_b[4] = { 10, 77, 0, 11 };

/** Monitor 10.77.0.12 */
static const uint8_t rbd_mon_c[4] = { 10, 77, 0, 12 };

/** Monitor 10.78.0.10 (on rbdn4d) */
static const uint8_t rbd_mon_d[4] = { 10, 78, 0, 10 };

/** Monitor 10.99.0.10 (no route) */
static const uint8_t rbd_mon_none[4] = { 10, 99, 0, 10 };

/** Monitor 172.20.0.9 (on rbdn4c) */
static const uint8_t rbd_mon_cls[4] = { 172, 20, 0, 9 };

/** Monitor [2001:db8:99::10] (beyond the prefix of rbdn6: reached through its router) */
static const uint8_t rbd_mon_6far[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x99, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x10 };

/** Monitor [2001:db8:77::10] (on rbdn6) */
static const uint8_t rbd_mon_6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x77, 0, 0,
				       0, 0, 0, 0, 0, 0, 0, 0x10 };

/**
 * Fill in the expectation of an IPv4 NIC
 *
 * @v e			Expectation to fill in (identity left alone)
 * @v mac		MAC address
 * @v ip		Address (4 bytes)
 * @v prefix		Prefix length
 * @v gw		Gateway
 * @v dns		DNS server
 * @v mtu		MTU
 */
static void rbd_exp_nic4 ( struct rbd_expect *e, const uint8_t *mac,
			   const uint8_t *ip, unsigned int prefix,
			   const uint8_t *gw, const uint8_t *dns,
			   unsigned int mtu ) {

	e->nic_family = 4;
	e->nic_prefix = prefix;
	e->nic_mtu = mtu;
	rbd_copy ( e->mac, mac, 6 );
	memset ( e->ip, 0, 16 );
	memset ( e->gateway, 0, 16 );
	memset ( e->dns, 0, 16 );
	rbd_copy ( e->ip, ip, 4 );
	rbd_copy ( e->gateway, gw, 4 );
	rbd_copy ( e->dns, dns, 4 );
}

/**
 * Fill in the identity of the ordinary fake session in an expectation
 *
 * @v e			Expectation
 * @v mon0		First monitor (IPv4)
 */
static void rbd_exp_identity ( struct rbd_expect *e, const uint8_t *mon0 ) {

	memset ( e, 0, sizeof ( *e ) );
	e->mode = WR_MODE_CRC_ONLY;
	e->entity = "winrbd-boot";
	e->pool = "winrbd";
	e->image = "wrtest-acpi";
	e->n_mons = 1;
	e->mons[0].family = 4;
	e->mons[0].port = 3300;
	rbd_copy ( e->mons[0].ip, mon0, 4 );
}

/* ---- tests -------------------------------------------------------------------------------------------------------------- */

/**
 * Perform handoff table self-tests
 *
 */
static void rbd_acpi_test_exec ( void ) {
	static const uint8_t mac_4[6] = { 0x52, 0x54, 0x00, 0x77, 0x10, 0x01 };
	static const uint8_t mac_4d[6] = { 0x52, 0x54, 0x00, 0x77, 0x10, 0x02 };
	static const uint8_t mac_6[6] = { 0x52, 0x54, 0x00, 0x77, 0x10, 0x03 };
	static const uint8_t mac_4t[6] = { 0x52, 0x54, 0x00, 0x77, 0x10, 0x04 };
	static const uint8_t ip_4[4] = { 10, 77, 0, 20 };
	static const uint8_t gw_4[4] = { 10, 77, 0, 1 };
	static const uint8_t dns_4[4] = { 10, 77, 0, 2 };
	static const uint8_t ip_4d[4] = { 10, 78, 0, 30 };
	static const uint8_t gw_4d[4] = { 10, 78, 255, 254 };
	static const uint8_t dns_4d[4] = { 10, 78, 0, 53 };
	static const uint8_t mac_4c[6] = { 0x52, 0x54, 0x00, 0x77, 0x10, 0x05 };
	static const uint8_t ip_4c[4] = { 172, 20, 0, 5 };
	static const uint8_t none_4[4] = { 0, 0, 0, 0 };
	static const uint8_t ip_6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x77, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x20 };
	static const uint8_t gw_6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x77, 0, 0,
					  0, 0, 0, 0, 0, 0, 0, 0x01 };
	static const uint8_t dns_6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x77, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 0x02 };
	struct rbd_expect *e;
	struct rbd_fake *fake;
	struct rbd_fake *fake2;
	struct rbd_device *rbd;
	struct rbd_device *rbd2;
	struct acpi_descriptor *desc;
	struct acpi_descriptor *desc2;
	uint8_t first[WR_HANDOFF_MAX_TABLE];
	size_t first_len;
	unsigned int i;
	unsigned int mtu;

	e = zalloc ( sizeof ( *e ) );
	fake = zalloc ( sizeof ( *fake ) );
	fake2 = zalloc ( sizeof ( *fake2 ) );
	okx ( e && fake && fake2, __FILE__, __LINE__ );
	if ( ! ( e && fake && fake2 ) )
		return;

	/* The key of the fake sessions: a pattern no other field of a table can contain */
	for ( i = 0 ; i < 32 ; i++ )
		rbd_fake_key.secret[i] = ( 0xc0 + i );
	rbd_fake_key.type = WR_KEY_TYPE_AES256K;
	rbd_fake_key.len = 32;

	/* The model is registered and its signature is "rBFT" in table byte order */
	ok ( rbd_model.complete != NULL );
	ok ( rbd_model.install != NULL );
	ok ( list_empty ( &rbd_model.descs ) );
	ok ( RBFT_SIG == ( ( 'r' << 0 ) | ( 'B' << 8 ) | ( 'F' << 16 ) |
			   ( 'T' << 24 ) ) );

	/* Create the test network devices */
	testnet_ok ( &rbdn4 );
	testnet_ok ( &rbdn4d );
	testnet_ok ( &rbdn6 );
	testnet_ok ( &rbdn4t );
	mtu = rbdn4.netdev->mtu;
	ok ( mtu == 1500 );

	/* ---- IPv4 by hand: the whole table, field by field, three monitors, no key ---------------------------------------- */
	rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
	fake->src.n_mons = 4;
	fake->src.mons[1].family = 0;				/* skipped */
	fake->src.mons[1].port = 1234;
	fake->src.mons[2].family = WR_AF_IPV4;			/* port 0: the default */
	rbd_copy ( fake->src.mons[2].ip, rbd_mon_b, 4 );
	fake->src.mons[3].family = WR_AF_IPV4;
	rbd_copy ( fake->src.mons[3].ip, rbd_mon_c, 4 );
	fake->src.mons[3].port = 3301;
	fake->src.mons[3].nonce = 0xdeadbeef;			/* not carried */
	rbd_exp_identity ( e, rbd_mon_a );
	e->n_mons = 3;
	e->mons[1].family = 4;
	e->mons[1].port = 3300;
	rbd_copy ( e->mons[1].ip, rbd_mon_b, 4 );
	e->mons[2].family = 4;
	e->mons[2].port = 3301;
	rbd_copy ( e->mons[2].ip, rbd_mon_c, 4 );
	rbd_exp_nic4 ( e, mac_4, ip_4, 24, gw_4, dns_4, mtu );
	e->flags = WR_HANDOFF_F_NIC_STATIC;

	rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
	desc = rbd_register ( rbd );
	ok ( desc != NULL );
	ok ( desc == &rbd->desc );
	ok ( desc->model == &rbd_model );
	ok ( desc->refcnt == &rbd->refcnt );
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 1 );
	rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	rbd_check_table ( rbd_capture.fixed[0], rbd_capture.len[0], e, 1 );
	rbd_decode_ok ( rbd_capture.raw[0], rbd_capture.len[0], e );
	rbd_decode_ok ( rbd_capture.fixed[0], rbd_capture.len[0], e );

	/* The key is in the session but handoff=nokey: no byte of it anywhere in the table */
	ok ( ! rbd_contains ( rbd_capture.raw[0], rbd_capture.len[0],
			      rbd_fake_key.secret, 8 ) );
	ok ( ! rbd_contains ( rbd_capture.raw[0], rbd_capture.len[0],
			      rbd_fake_key.secret, 32 ) );

	/* The OEM fields iPXE writes change nothing but their own bytes and the checksum */
	for ( i = 0 ; i < rbd_capture.len[0] ; i++ ) {
		if ( ( i == 9 ) || ( ( i >= 10 ) && ( i < 36 ) ) )
			continue;
		okx ( rbd_capture.raw[0][i] == rbd_capture.fixed[0][i],
		      __FILE__, __LINE__ );
	}

	/* ---- two installs of an unchanged world are byte for byte the same ------------------------------------------------ */
	memcpy ( first, rbd_capture.raw[0], rbd_capture.len[0] );
	first_len = rbd_capture.len[0];
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 2 );
	ok ( rbd_capture.len[0] == first_len );
	ok ( rbd_capture.len[1] == first_len );
	ok ( memcmp ( rbd_capture.raw[0], first, first_len ) == 0 );
	ok ( memcmp ( rbd_capture.raw[1], first, first_len ) == 0 );
	ok ( memcmp ( rbd_capture.fixed[0], rbd_capture.fixed[1],
		      first_len ) == 0 );

	/* ---- a changed world shows in the next table: nothing is kept between calls --------------------------------------- */
	testnet_set_ok ( &rbdn4, "ip", "10.77.0.21" );
	testnet_set_ok ( &rbdn4, "gateway", "10.77.0.254" );
	testnet_set_ok ( &rbdn4, "dns", "10.77.0.3" );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 1 );
	ok ( rbd_capture.len[0] == first_len );
	ok ( memcmp ( rbd_capture.raw[0], first, first_len ) != 0 );
	{
		static const uint8_t ip2[4] = { 10, 77, 0, 21 };
		static const uint8_t gw2[4] = { 10, 77, 0, 254 };
		static const uint8_t dns2[4] = { 10, 77, 0, 3 };

		rbd_exp_nic4 ( e, mac_4, ip2, 24, gw2, dns2, mtu );
		rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	}
	testnet_set_ok ( &rbdn4, "ip", "10.77.0.20" );
	testnet_set_ok ( &rbdn4, "gateway", "10.77.0.1" );
	testnet_set_ok ( &rbdn4, "dns", "10.77.0.2" );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.len[0] == first_len );
	ok ( memcmp ( rbd_capture.raw[0], first, first_len ) == 0 );

	rbd_unregister ( desc );
	free ( rbd );

	/* ---- every flag, the key on request, identity extras ---------------------------------------------------------------- */
	rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
	fake->src.user = "client.winrbd-boot";			/* one leading "client." is not part of the id */
	fake->src.image_id = "10a3b2c1d4e5";
	fake->src.snap = "snap1";
	fake->src.mode = WR_MODE_SECURE_ONLY;
	fake->src.read_only = 1;
	fake->src.fsid_known = 1;
	for ( i = 0 ; i < 16 ; i++ )
		fake->src.fsid[i] = ( 0x10 + i );
	rbd_exp_identity ( e, rbd_mon_a );
	e->image_id = "10a3b2c1d4e5";
	e->snap = "snap1";
	e->mode = WR_MODE_SECURE_ONLY;
	for ( i = 0 ; i < 16 ; i++ )
		e->fsid[i] = ( 0x10 + i );
	rbd_exp_nic4 ( e, mac_4, ip_4, 24, gw_4, dns_4, mtu );
	e->flags = ( WR_HANDOFF_F_READONLY | WR_HANDOFF_F_KEY |
		     WR_HANDOFF_F_NIC_STATIC | WR_HANDOFF_F_FSID |
		     WR_HANDOFF_F_SECURE_REQUIRED );
	e->key = rbd_fake_key.secret;
	e->key_len = 32;
	e->key_type = WR_KEY_TYPE_AES256K;
	rbd = rbd_fake_device ( fake, RBD_HANDOFF_KEY );
	desc = rbd_register ( rbd );
	ok ( desc != NULL );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 1 );
	rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	rbd_check_table ( rbd_capture.fixed[0], rbd_capture.len[0], e, 1 );
	rbd_decode_ok ( rbd_capture.raw[0], rbd_capture.len[0], e );
	ok ( rbd_contains ( rbd_capture.raw[0], rbd_capture.len[0],
			    rbd_fake_key.secret, 32 ) );

	/* The object the table was built in held the key and was freed: it was wiped first. The memory is read after the free() on
	 * purpose (iPXE's heap neither unmaps nor poisons it, and the table lies far behind the first bytes an allocator reuses
	 * for its own bookkeeping); the copy above proves the key was in it at the time of the call.
	 */
	ok ( rbd_capture.last != NULL );
	ok ( rbd_capture.last_len == rbd_capture.len[0] );
	ok ( ! rbd_contains ( rbd_capture.last, rbd_capture.last_len,
			      rbd_fake_key.secret, 8 ) );
	ok ( ! rbd_contains ( rbd_capture.last, rbd_capture.last_len,
			      rbd_fake_key.secret, 32 ) );
	for ( i = 0 ; i < rbd_capture.last_len ; i++ )
		okx ( rbd_capture.last[i] == 0, __FILE__, __LINE__ );
	/* ... and the same when the backend refuses the table */
	rbd_capture_reset();
	rbd_capture.rc = RBD_ERR ( ENOSPC );
	ok ( rbd_same_error ( rbd_run_install(), RBD_ERR ( ENOSPC ) ) );
	ok ( rbd_capture.last != NULL );
	ok ( ! rbd_contains ( rbd_capture.last, rbd_capture.last_len,
			      rbd_fake_key.secret, 8 ) );
	for ( i = 0 ; i < rbd_capture.last_len ; i++ )
		okx ( rbd_capture.last[i] == 0, __FILE__, __LINE__ );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );

	/* A legacy "aes" key of 16 bytes travels with its type */
	fake->src.key = NULL;
	rbd_capture_reset();
	ok ( rbd_same_error ( rbd_run_install(), RBD_ERR ( EINVAL ) ) );
	ok ( rbd_capture.count == 0 );
	{
		static wr_key aes;

		aes.type = WR_KEY_TYPE_AES;
		aes.len = 16;
		for ( i = 0 ; i < 16 ; i++ )
			aes.secret[i] = ( 0x30 + i );
		fake->src.key = &aes;
		e->key = aes.secret;
		e->key_len = 16;
		e->key_type = WR_KEY_TYPE_AES;
		rbd_capture_reset();
		ok ( rbd_run_install() == 0 );
		ok ( rbd_capture.count == 1 );
		rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	}
	rbd_unregister ( desc );
	free ( rbd );

	/* ---- handoff=none: no descriptor, so no table ------------------------------------------------------------------------ */
	rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
	rbd = rbd_fake_device ( fake, RBD_HANDOFF_NONE );
	ok ( rbd_acpi_describe ( rbd ) == NULL );
	ok ( list_empty ( &rbd_model.descs ) );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 0 );
	ok ( fake->asked == 0 );
	/* a device of that kind that was registered anyway needs nothing and installs nothing */
	acpi_init ( &rbd->desc, &rbd_model, &rbd->refcnt );
	acpi_add ( &rbd->desc );
	fake->rc = -EINPROGRESS;
	ok ( rbd_acpi_complete_with ( &rbd->desc, rbd_fake_source ) == 0 );
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 0 );
	ok ( fake->asked == 0 );
	acpi_del ( &rbd->desc );
	free ( rbd );

	/* ---- complete(): in progress until the image is open and the route is known ----------------------------------------- */
	rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
	rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
	desc = rbd_register ( rbd );
	fake->rc = -EINPROGRESS;				/* the image is still opening */
	ok ( rbd_same_error ( rbd_acpi_complete_with ( desc, rbd_fake_source ),
			      RBD_ERR ( EINPROGRESS ) ) );
	fake->rc = -EACCES;					/* the session failed: its error, not "in progress" */
	ok ( rbd_same_error ( rbd_acpi_complete_with ( desc, rbd_fake_source ),
			      RBD_ERR ( EACCES ) ) );
	fake->rc = 0;						/* open, and 10.77.0.10 is routed */
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );
	fake->src.mons[0].family = 0;				/* nothing usable to route to: waiting cannot help */
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );	/* (not -EINPROGRESS: that would hang sanhook) */
	rbd_capture_reset();
	ok ( rbd_same_error ( rbd_run_install(), RBD_ERR ( EINVAL ) ) );	/* install() names it and fails */
	ok ( rbd_capture.count == 0 );
	/* a monitor beyond the subnets is routed through a default gateway: that device is the NIC */
	rbd_fake_open ( fake, rbd_mon_none, WR_AF_IPV4 );
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );
	/* no open device has a route (both devices with an IPv4 route are closed): not ready yet */
	rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
	testnet_close_ok ( &rbdn4 );
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );	/* rbdn4d's default gateway still serves it */
	testnet_close_ok ( &rbdn4d );
	ok ( rbd_same_error ( rbd_acpi_complete_with ( desc, rbd_fake_source ),
			      RBD_ERR ( EINPROGRESS ) ) );
	/* install() with no route ends the pass with -EHOSTUNREACH and installs nothing */
	rbd_capture_reset();
	ok ( rbd_same_error ( rbd_run_install(), RBD_ERR ( EHOSTUNREACH ) ) );
	ok ( rbd_capture.count == 0 );
	testnet_open_ok ( &rbdn4 );
	testnet_open_ok ( &rbdn4d );
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );
	/* install() with a failed session ends the pass with that error and installs nothing */
	fake->rc = -EACCES;
	rbd_capture_reset();
	ok ( rbd_same_error ( rbd_run_install(), RBD_ERR ( EACCES ) ) );
	ok ( rbd_capture.count == 0 );
	/* a backend that cannot install: its error ends the pass */
	rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
	rbd_capture_reset();
	rbd_capture.rc = RBD_ERR ( ENOSPC );
	ok ( rbd_same_error ( rbd_run_install(), RBD_ERR ( ENOSPC ) ) );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 1 );
	rbd_unregister ( desc );
	free ( rbd );

	/* ---- an address learnt from DHCP is not "static", the other NIC of another monitor ---------------------------------- */
	rbd_fake_open ( fake, rbd_mon_d, WR_AF_IPV4 );
	rbd_exp_identity ( e, rbd_mon_d );
	rbd_exp_nic4 ( e, mac_4d, ip_4d, 16, gw_4d, dns_4d, mtu );
	e->flags = 0;
	rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
	desc = rbd_register ( rbd );
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 1 );
	rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	rbd_decode_ok ( rbd_capture.raw[0], rbd_capture.len[0], e );
	rbd_unregister ( desc );
	free ( rbd );

	/* ---- IPv6 ------------------------------------------------------------------------------------------------------------ */
	rbd_fake_open ( fake, rbd_mon_6, WR_AF_IPV6 );
	rbd_exp_identity ( e, rbd_mon_a );
	e->mons[0].family = 6;
	rbd_copy ( e->mons[0].ip, rbd_mon_6, 16 );
	e->nic_family = 6;
	e->nic_prefix = 64;
	e->nic_mtu = mtu;
	rbd_copy ( e->mac, mac_6, 6 );
	rbd_copy ( e->ip, ip_6, 16 );
	rbd_copy ( e->gateway, gw_6, 16 );
	rbd_copy ( e->dns, dns_6, 16 );
	e->flags = WR_HANDOFF_F_NIC_STATIC;
	rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
	desc = rbd_register ( rbd );
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 1 );
	rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	rbd_decode_ok ( rbd_capture.raw[0], rbd_capture.len[0], e );
	/* a monitor beyond the prefix: the same NIC, the gateway is the router of the route that was chosen */
	rbd_copy ( fake->src.mons[0].ip, rbd_mon_6far, 16 );
	rbd_copy ( e->mons[0].ip, rbd_mon_6far, 16 );
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 1 );
	rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	rbd_decode_ok ( rbd_capture.raw[0], rbd_capture.len[0], e );
	rbd_unregister ( desc );
	free ( rbd );

	/* ---- a monitor beyond the local subnet: the NIC is the device of the default route that carries it, and the prefix is
	 * that of the device's own network (the default route's netmask is 0: the first version of the glue wrote /0)
	 */
	testnet_close_ok ( &rbdn4d );				/* one default route only: the one of rbdn4 */
	rbd_fake_open ( fake, rbd_mon_none, WR_AF_IPV4 );
	rbd_exp_identity ( e, rbd_mon_none );
	rbd_exp_nic4 ( e, mac_4, ip_4, 24, gw_4, dns_4, mtu );
	e->flags = WR_HANDOFF_F_NIC_STATIC;
	rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
	desc = rbd_register ( rbd );
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 1 );
	rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	rbd_decode_ok ( rbd_capture.raw[0], rbd_capture.len[0], e );
	testnet_close_ok ( &rbdn4 );				/* now the one of rbdn4d, learnt from DHCP */
	testnet_open_ok ( &rbdn4d );
	rbd_exp_nic4 ( e, mac_4d, ip_4d, 16, gw_4d, dns_4d, mtu );
	e->flags = 0;
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 1 );
	rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	rbd_decode_ok ( rbd_capture.raw[0], rbd_capture.len[0], e );
	testnet_open_ok ( &rbdn4 );
	rbd_unregister ( desc );
	free ( rbd );

	/* ---- no netmask setting: the class default of iPXE's own routing table (172.20.0.5 is class B, /16); no gateway of its own,
	 * and the DNS server of the first block that has one (what iPXE's resolver would use)
	 */
	testnet_ok ( &rbdn4c );
	rbd_fake_open ( fake, rbd_mon_cls, WR_AF_IPV4 );
	rbd_exp_identity ( e, rbd_mon_cls );
	rbd_exp_nic4 ( e, mac_4c, ip_4c, 16, none_4, dns_4, mtu );
	e->flags = WR_HANDOFF_F_NIC_STATIC;
	rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
	desc = rbd_register ( rbd );
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 1 );
	rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	rbd_decode_ok ( rbd_capture.raw[0], rbd_capture.len[0], e );
	rbd_unregister ( desc );
	free ( rbd );
	testnet_remove_ok ( &rbdn4c );

	/* ---- a netmask that is not a prefix (a 0 bit before a 1 bit) cannot be written as a prefix length: refused, named, and
	 * waiting for it would not help, so complete() does not hang the hook
	 */
	testnet_set_ok ( &rbdn4, "netmask", "255.0.255.0" );
	rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
	rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
	desc = rbd_register ( rbd );
	ok ( rbd_acpi_complete_with ( desc, rbd_fake_source ) == 0 );
	rbd_capture_reset();
	ok ( rbd_same_error ( rbd_run_install(), RBD_ERR ( EINVAL ) ) );
	ok ( rbd_capture.count == 0 );
	testnet_set_ok ( &rbdn4, "netmask", "255.255.255.0" );
	rbd_exp_identity ( e, rbd_mon_a );
	rbd_exp_nic4 ( e, mac_4, ip_4, 24, gw_4, dns_4, mtu );
	e->flags = WR_HANDOFF_F_NIC_STATIC;
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 1 );
	rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	rbd_unregister ( desc );
	free ( rbd );

	/* ---- a device that has let go of its session: ENOTCONN, and the source is never called with NULL ------------------------- */
	rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
	rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
	desc = rbd_register ( rbd );
	rbd->session = NULL;
	ok ( rbd_same_error ( rbd_acpi_complete_with ( desc, rbd_fake_source ),
			      RBD_ERR ( ENOTCONN ) ) );
	rbd_capture_reset();
	ok ( rbd_same_error ( rbd_run_install(), RBD_ERR ( ENOTCONN ) ) );
	ok ( rbd_capture.count == 0 );
	ok ( fake->asked == 0 );
	rbd_unregister ( desc );
	free ( rbd );

	/* ---- a VLAN device: the tag, the MAC of the trunk -------------------------------------------------------------------- */
	ok ( vlan_create ( rbdn4t.netdev, 42, 0 ) == 0 );
	{
		struct net_device *vlan = vlan_find ( rbdn4t.netdev, 42 );
		struct testnet vlan_net;
		static const uint8_t ip_v[4] = { 10, 80, 42, 5 };
		static const uint8_t gw_v[4] = { 10, 80, 42, 1 };
		static const uint8_t dns_v[4] = { 10, 80, 42, 2 };
		static const uint8_t mon_v[4] = { 10, 80, 42, 10 };

		ok ( vlan != NULL );
		if ( vlan ) {
			/* the VLAN device is a net_device like the others: a shell to set its settings with the test helpers */
			memset ( &vlan_net, 0, sizeof ( vlan_net ) );
			snprintf ( vlan_net.dev.name, sizeof ( vlan_net.dev.name ), "%s",
				   vlan->name );
			vlan_net.netdev = vlan;
			ok ( netdev_open ( vlan ) == 0 );
			ok ( vlan->mtu != 0 );
			testnet_set_ok ( &vlan_net, "ip", "10.80.42.5" );
			testnet_set_ok ( &vlan_net, "netmask", "255.255.255.0" );
			testnet_set_ok ( &vlan_net, "gateway", "10.80.42.1" );
			testnet_set_ok ( &vlan_net, "dns", "10.80.42.2" );

			rbd_fake_open ( fake, mon_v, WR_AF_IPV4 );
			rbd_exp_identity ( e, mon_v );
			rbd_exp_nic4 ( e, mac_4t, ip_v, 24, gw_v, dns_v,
				       vlan->mtu );
			e->nic_vlan = 42;
			e->flags = ( WR_HANDOFF_F_VLAN |
				     WR_HANDOFF_F_NIC_STATIC );
			rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
			desc = rbd_register ( rbd );
			ok ( rbd_acpi_complete_with ( desc,
						      rbd_fake_source ) == 0 );
			rbd_capture_reset();
			ok ( rbd_run_install() == 0 );
			ok ( rbd_capture.count == 1 );
			rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0],
					  e, 0 );
			rbd_decode_ok ( rbd_capture.raw[0], rbd_capture.len[0],
					e );
			rbd_unregister ( desc );
			free ( rbd );
			netdev_close ( vlan );
			ok ( vlan_destroy ( vlan ) == 0 );
		}
	}

	/* ---- two devices, two tables, in the order of registration ------------------------------------------------------------ */
	rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
	rbd_fake_open ( fake2, rbd_mon_d, WR_AF_IPV4 );
	fake2->src.image = "wrtest-two";
	rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
	rbd2 = rbd_fake_device ( fake2, RBD_HANDOFF_KEY );
	desc = rbd_register ( rbd );
	desc2 = rbd_register ( rbd2 );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 2 );
	rbd_exp_identity ( e, rbd_mon_a );
	rbd_exp_nic4 ( e, mac_4, ip_4, 24, gw_4, dns_4, mtu );
	e->flags = WR_HANDOFF_F_NIC_STATIC;
	rbd_check_table ( rbd_capture.raw[0], rbd_capture.len[0], e, 0 );
	rbd_exp_identity ( e, rbd_mon_d );
	e->image = "wrtest-two";
	rbd_exp_nic4 ( e, mac_4d, ip_4d, 16, gw_4d, dns_4d, mtu );
	e->flags = ( WR_HANDOFF_F_KEY );
	e->key = rbd_fake_key.secret;
	e->key_len = 32;
	e->key_type = WR_KEY_TYPE_AES256K;
	rbd_check_table ( rbd_capture.raw[1], rbd_capture.len[1], e, 0 );
	/* the key of the second device is not in the first table */
	ok ( ! rbd_contains ( rbd_capture.raw[0], rbd_capture.len[0],
			      rbd_fake_key.secret, 8 ) );
	/* the first device failing keeps the second out of the pass */
	fake->rc = -EACCES;
	rbd_capture_reset();
	ok ( rbd_same_error ( rbd_run_install(), RBD_ERR ( EACCES ) ) );
	ok ( rbd_capture.count == 0 );
	rbd_unregister ( desc2 );
	rbd_unregister ( desc );
	free ( rbd2 );
	free ( rbd );

	/* ---- the limit: 1,024 bytes are accepted, 1,025 refused and never truncated ------------------------------------------ */
	{
		/* 152 fixed bytes, one monitor (20), "u" (2), and four strings: pool, image, image id, snapshot. With
		 * 255 + 255 + 255 + 81 characters and four terminators the table is 152 + 20 + 2 + 846 + 4 = 1024.
		 */
		char *pool = zalloc ( 256 );
		char *image = zalloc ( 256 );
		char *image_id = zalloc ( 256 );
		char *snap = zalloc ( 256 );

		ok ( pool && image && image_id && snap );
		if ( pool && image && image_id && snap ) {
			memset ( pool, 'p', 255 );
			memset ( image, 'i', 255 );
			memset ( snap, 's', 255 );
			memset ( image_id, 'd', 81 );
			rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
			fake->src.user = "u";
			fake->src.pool = pool;
			fake->src.image = image;
			fake->src.image_id = image_id;
			fake->src.snap = snap;
			rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
			desc = rbd_register ( rbd );
			rbd_capture_reset();
			ok ( rbd_run_install() == 0 );
			ok ( rbd_capture.count == 1 );
			ok ( rbd_capture.len[0] == 1024 );
			ok ( rbd_le32 ( rbd_capture.raw[0] + 4 ) == 1024 );
			/* one more character: refused with a console line, the backend is never called */
			image_id[81] = 'd';
			rbd_capture_reset();
			ok ( rbd_same_error ( rbd_run_install(),
					      RBD_ERR ( ENOSPC ) ) );
			ok ( rbd_capture.count == 0 );
			/* and back under the limit: accepted again, nothing was kept from the refusal */
			image_id[81] = '\0';
			rbd_capture_reset();
			ok ( rbd_run_install() == 0 );
			ok ( rbd_capture.len[0] == 1024 );
			rbd_unregister ( desc );
			free ( rbd );
		}
		free ( pool );
		free ( image );
		free ( image_id );
		free ( snap );
	}

	/* ---- the limit with a key: 32 key bytes on top of a table that fits without it --------------------------------------- */
	{
		char *pool = zalloc ( 256 );
		char *image = zalloc ( 256 );
		char *snap = zalloc ( 256 );

		ok ( pool && image && snap );
		if ( pool && image && snap ) {
			memset ( pool, 'p', 255 );
			memset ( image, 'i', 255 );
			memset ( snap, 's', 255 );
			rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
			fake->src.pool = pool;
			fake->src.image = image;
			fake->src.snap = snap;
			/* 152 + 20 + 12 + 765 + 3 = 952 without the key, 984 with a 32-byte key: both fit */
			rbd = rbd_fake_device ( fake, RBD_HANDOFF_KEY );
			desc = rbd_register ( rbd );
			rbd_capture_reset();
			ok ( rbd_run_install() == 0 );
			ok ( rbd_capture.len[0] == 984 );
			/* eight monitors: 152 + 160 + 12 + 765 + 3 + 32 = 1124: refused */
			fake->src.n_mons = 8;
			for ( i = 1 ; i < 8 ; i++ ) {
				fake->src.mons[i] = fake->src.mons[0];
				fake->src.mons[i].ip[3] = ( 20 + i );
			}
			rbd_capture_reset();
			ok ( rbd_same_error ( rbd_run_install(),
					      RBD_ERR ( ENOSPC ) ) );
			ok ( rbd_capture.count == 0 );
			rbd_unregister ( desc );
			free ( rbd );
		}
		free ( pool );
		free ( image );
		free ( snap );
	}

	/* ---- a refused field: no user is refused (the core would not have opened it either) ---------------------------------- */
	rbd_fake_open ( fake, rbd_mon_a, WR_AF_IPV4 );
	fake->src.user = "client.";
	rbd = rbd_fake_device ( fake, RBD_HANDOFF_NOKEY );
	desc = rbd_register ( rbd );
	rbd_capture_reset();
	ok ( rbd_same_error ( rbd_run_install(), RBD_ERR ( EINVAL ) ) );
	ok ( rbd_capture.count == 0 );
	rbd_unregister ( desc );
	free ( rbd );

	/* ---- nothing registered: nothing to do ---------------------------------------------------------------------------------- */
	ok ( list_empty ( &rbd_model.descs ) );
	rbd_capture_reset();
	ok ( rbd_run_install() == 0 );
	ok ( rbd_capture.count == 0 );

	/* Remove the test network devices */
	testnet_remove_ok ( &rbdn4t );
	testnet_remove_ok ( &rbdn6 );
	testnet_remove_ok ( &rbdn4d );
	testnet_remove_ok ( &rbdn4 );

	/* The key pattern is not left lying around in the test either */
	memset ( &rbd_fake_key, 0, sizeof ( rbd_fake_key ) );
	free ( fake2 );
	free ( fake );
	free ( e );
}

/** Handoff table self-test */
struct self_test rbd_acpi_test __self_test = {
	.name = "rbd_acpi_test",
	.exec = rbd_acpi_test_exec,
};
