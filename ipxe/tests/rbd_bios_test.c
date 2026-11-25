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
 * RBD (Ceph) SAN protocol: self-tests of the BIOS helpers (rbd_bios.c)
 *
 * Built into bin-x86_64-linux/tests.linux and bin-i386-linux/tests.linux by "ipxe/tools/build.sh test" (see
 * ipxe/tests/README.md): no network, no QEMU, no cluster. Only the pure part of rbd_bios.c is linked into the test program
 * (the "rbd-xbft" command and the shutdown hook exist in BIOS builds only; their live behaviour is rows B0 to B3 of the matrix,
 * harness/lab/p2/results/bios2).
 *
 * What this covers:
 *   - the arithmetic of the boot firmware table area (docs/design/ipxe-driver.md section 7): the entry length, the fit rule of
 *     int13_install() against a literal copy of its steps (also over many random sequences), the size of an iBFT from the real
 *     iPXE structures against the steps of ibft_install(), and the numbers the 2,048-byte area rests on: the stock 768 bytes do not
 *     hold a typical iBFT next to a typical handoff table, 2,048 hold the largest handoff table next to the reference iBFT with
 *     16 bytes to spare, three tables of the largest size do not fit;
 *   - the scan: tables built by the core's encoder, rewritten by an install the way int13_install() does it (OEM fields,
 *     checksum), found at the right addresses next to an iBFT; every way a candidate can be wrong is refused and counted (bad
 *     checksum, a right checksum over a broken body, lengths that are too small, too large or past the end, a misaligned
 *     signature, an unknown signature); a flipped bit anywhere in the handoff table makes it disappear; the model of a BIOS
 *     machine: an area at the top of base memory is inside the window an operating system scans, an area below 512 KiB is not (the
 *     window scan finds nothing there, the command's low scan finds the tables, and the window test calls them OUTSIDE);
 *   - the window test at its edges, the names, and the exit warning's decision (undionly with a hooked drive on exit, nothing
 *     else).
 *
 * Secure Boot: FILE_SECBOOT ( FORBIDDEN ), like every file of the driver (docs/design/ipxe-driver.md, section 13). A test
 * object is only ever linked into a self-test program, never into a bootable image, so the declaration costs nothing; nothing
 * here is a candidate for PERMITTED, which iPXE reserves for code that has had its security review.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ipxe/acpi.h>
#include <ipxe/ibft.h>
#include <ipxe/test.h>
#include "winrbd/rbd_bios.h"

/** A buffer that is not the stack (the window is 512 KiB) */
static uint8_t *rbd_area;

/** The window's length */
#define T_WINDOW ( RBD_BIOS_WINDOW_HI - RBD_BIOS_WINDOW_LO )

/** The reference iBFT's strings, from the arithmetic of ibft_install(): an initiator IQN, a target IQN, a host name, each with its NUL */
#define T_TYPICAL_STRINGS ( 57 + 1 + 40 + 1 + 10 + 1 )

/** Length of the iBFT of ibft_install() for a number of targets, step by step as that function does it (a second derivation of RBD_BIOS_IBFT_FIXED) */
static size_t ibft_fixed ( unsigned int targets ) {
	unsigned int pairs = 2;	/* sizeof ( table->control.pair ) / sizeof ( table->control.pair[0] ) */
	size_t offset;

	if ( pairs < targets )
		pairs = targets;
	offset = offsetof ( struct ibft_table, control.pair );
	offset += ( pairs * sizeof ( ( ( struct ibft_table * ) 0 )->control.pair[0] ) );
	offset = ( ( offset + IBFT_ALIGN - 1 ) & ~( IBFT_ALIGN - 1 ) );
	offset += ( ( sizeof ( struct ibft_initiator ) + IBFT_ALIGN - 1 ) & ~( IBFT_ALIGN - 1 ) );
	offset += ( pairs * ( ( sizeof ( struct ibft_nic ) + IBFT_ALIGN - 1 ) & ~( IBFT_ALIGN - 1 ) ) );
	offset += ( pairs * ( ( sizeof ( struct ibft_target ) + IBFT_ALIGN - 1 ) & ~( IBFT_ALIGN - 1 ) ) );
	return offset;
}

/** int13_install()'s steps, copied: the length check and the update of the used length. @ret rc 0 or -1 for -ENOSPC */
static int install_model ( size_t size, size_t *used, size_t len ) {

	if ( len > ( size - *used ) )
		return -1;
	*used = ( ( *used + len + 16 - 1 ) & ~( ( size_t ) 16 - 1 ) );
	return 0;
}

/** Fix the checksum of a table at p (as acpi_fix_checksum() does after the OEM fields are written) */
static void fix ( uint8_t *p ) {

	acpi_fix_checksum ( ( struct acpi_header * ) p );
}

/** Make an ACPI-style table (signature, length, revision 1, checksum fixed) of a given length at p, the body filled with a byte */
static void make_table ( uint8_t *p, const char *sig, size_t len, uint8_t fill ) {
	uint32_t le = ( uint32_t ) len;

	memset ( p, fill, len );
	memcpy ( p, sig, 4 );
	p[4] = ( uint8_t ) le;
	p[5] = ( uint8_t ) ( le >> 8 );
	p[6] = ( uint8_t ) ( le >> 16 );
	p[7] = ( uint8_t ) ( le >> 24 );
	p[8] = 1;
	p[9] = 0;
	fix ( p );
}

/** Make a real handoff table with the core's encoder and install it the way int13_install() does (OEM fields rewritten, checksum fixed) */
static size_t make_rbft ( uint8_t *p, size_t cap, unsigned int mons, int key ) {
	static const uint8_t k16[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
	wr_handoff_info info;
	size_t len = 0;
	unsigned int i;

	memset ( &info, 0, sizeof ( info ) );
	info.auth = WR_HANDOFF_AUTH_CEPHX;
	info.msgr_mode = WR_MODE_CRC_ONLY;
	info.mon_count = ( uint8_t ) mons;
	for ( i = 0 ; i < mons ; i++ ) {
		info.mons[i].family = 4;
		info.mons[i].port = 3300;
		info.mons[i].ip[0] = 10;
		info.mons[i].ip[1] = 77;
		info.mons[i].ip[3] = ( uint8_t ) ( 10 + i );
	}
	info.nic_family = 4;
	info.nic_prefix = 24;
	info.nic_mtu = 1500;
	info.nic_mac[0] = 0x52;
	info.nic_mac[5] = 0x56;
	info.nic_ip[0] = 10;
	info.nic_ip[1] = 77;
	info.nic_ip[3] = 50;
	info.entity = "wrtest";
	info.pool = "winrbd";
	info.image = "boot";
	if ( key ) {
		info.flags |= WR_HANDOFF_F_KEY;
		info.key_type = WR_KEY_TYPE_AES;
		info.key_len = 16;
		info.key = k16;
	}
	if ( wr_handoff_encode_table ( &info, p, cap, &len ) != WR_OK )
		return 0;
	strncpy ( ( char * ) ( p + 10 ), "FENSYS", 6 );
	strncpy ( ( char * ) ( p + 16 ), "iPXE", 8 );
	fix ( p );
	return len;
}

/* ---- the constants and the arithmetic ----------------------------------------------------------------------------------- */

/** The numbers the area rests on */
static void constants_test ( void ) {
	size_t fixed1 = ibft_fixed ( 1 );

	ok ( RBD_BIOS_XBFT_ALIGN == IBFT_ALIGN );
	ok ( RBD_BIOS_WINDOW_LO == 0x80000UL );
	ok ( RBD_BIOS_WINDOW_HI == 0x100000UL );
	ok ( RBD_BIOS_XBFT_SIZE == 2048 );

	/* the low scan of "rbd-xbft": after the BIOS data area (0x400 - 0x4ff), 16-byte aligned like every scan, and below the window */
	ok ( RBD_BIOS_LOW_START == 0x500UL );
	ok ( ( RBD_BIOS_LOW_START % RBD_BIOS_XBFT_ALIGN ) == 0 );
	ok ( RBD_BIOS_LOW_START < RBD_BIOS_WINDOW_LO );

	/* the macro and the step-by-step derivation agree for any number of targets */
	ok ( RBD_BIOS_IBFT_FIXED ( 1 ) == fixed1 );
	ok ( RBD_BIOS_IBFT_FIXED ( 2 ) == ibft_fixed ( 2 ) );
	ok ( RBD_BIOS_IBFT_FIXED ( 3 ) == ibft_fixed ( 3 ) );
	ok ( RBD_BIOS_IBFT_FIXED ( 4 ) == ibft_fixed ( 4 ) );
	ok ( RBD_BIOS_IBFT_FIXED ( 3 ) > RBD_BIOS_IBFT_FIXED ( 2 ) );
	ok ( RBD_BIOS_IBFT_FIXED ( 1 ) == RBD_BIOS_IBFT_FIXED ( 2 ) );	/* at least two pairs, always */

	/* the pinned iPXE's iBFT is 16-byte aligned blocks: 512 bytes for one target (a change of the pin changes this, on purpose) */
	ok ( fixed1 == 512 );
	ok ( ( fixed1 % IBFT_ALIGN ) == 0 );

	/* the reference iBFT: the longest IQNs RFC 3720 allows and a 63-character host name, no CHAP */
	ok ( RBD_BIOS_IBFT_STRINGS == 512 );
	ok ( RBD_BIOS_IBFT_REFERENCE == ( 512 + 512 ) );

	/* what the area has to hold, and what is left of it */
	ok ( RBD_BIOS_XBFT_NEED == 2048 );
	ok ( RBD_BIOS_XBFT_NEED <= RBD_BIOS_XBFT_SIZE );
	ok ( RBD_BIOS_XBFT_SIZE == RBD_BIOS_XBFT_NEED );	/* sized exactly: no spare byte for the worst case */
	ok ( RBD_BIOS_XBFT_NEED > 768 );

	/* the maximum handoff table is the design's 1,024 bytes and is itself a multiple of the alignment */
	ok ( WR_HANDOFF_MAX_TABLE == 1024 );
	ok ( ( WR_HANDOFF_MAX_TABLE % RBD_BIOS_XBFT_ALIGN ) == 0 );
}

/** The entry length */
static void entry_test ( void ) {
	const size_t max = ( ( size_t ) 0 - 1 );

	ok ( rbd_bios_xbft_entry ( 0 ) == 0 );
	ok ( rbd_bios_xbft_entry ( 1 ) == 16 );
	ok ( rbd_bios_xbft_entry ( 15 ) == 16 );
	ok ( rbd_bios_xbft_entry ( 16 ) == 16 );
	ok ( rbd_bios_xbft_entry ( 17 ) == 32 );
	ok ( rbd_bios_xbft_entry ( 234 ) == 240 );
	ok ( rbd_bios_xbft_entry ( 1024 ) == 1024 );
	ok ( RBD_BIOS_ALIGN ( ( size_t ) 234 ) == 240 );

	/* a length that cannot be rounded up without wrapping around saturates (the plain sum would give 0 for SIZE_MAX), and the last length that can is exact */
	ok ( rbd_bios_xbft_entry ( max - 15 ) == ( max - 15 ) );
	ok ( rbd_bios_xbft_entry ( max - 14 ) == max );
	ok ( rbd_bios_xbft_entry ( max - 1 ) == max );
	ok ( rbd_bios_xbft_entry ( max ) == max );
	ok ( rbd_bios_xbft_entry ( max ) > 2048 );	/* so that it never fits any area */
}

/** The fit rule, with named cases */
static void fit_test ( void ) {
	size_t typical_ibft = ( ibft_fixed ( 1 ) + T_TYPICAL_STRINGS );
	size_t used;
	size_t lens[4];

	/* nothing to install */
	used = 99;
	ok ( rbd_bios_xbft_fit ( lens, 0, 2048, &used ) == 1 );
	ok ( used == 0 );
	ok ( rbd_bios_xbft_fit ( lens, 0, 0, NULL ) == 1 );

	/* a typical handoff table (218 to 330 bytes) alone: fits even the stock 768 */
	lens[0] = 234;
	ok ( rbd_bios_xbft_fit ( lens, 1, 768, &used ) == 1 );
	ok ( used == 240 );
	lens[0] = 330;
	ok ( rbd_bios_xbft_fit ( lens, 1, 768, &used ) == 1 );
	ok ( used == 336 );

	/* a typical iBFT next to a typical handoff table: does NOT fit the stock 768 (why patch 0002 exists), and does fit 2,048 */
	ok ( typical_ibft > 560 );
	ok ( typical_ibft < 680 );
	lens[0] = typical_ibft;
	lens[1] = 234;
	ok ( ( rbd_bios_xbft_entry ( typical_ibft ) + 234 ) > 768 );
	ok ( rbd_bios_xbft_fit ( lens, 2, 768, &used ) == 0 );
	ok ( used == rbd_bios_xbft_entry ( typical_ibft ) );	/* the first one was installed, the second was refused */
	ok ( rbd_bios_xbft_fit ( lens, 2, 2048, &used ) == 1 );
	ok ( used == ( rbd_bios_xbft_entry ( typical_ibft ) + 240 ) );

	/* the other order: the handoff table first (the SAN devices describe themselves in the order they were hooked) */
	lens[0] = 234;
	lens[1] = typical_ibft;
	ok ( rbd_bios_xbft_fit ( lens, 2, 2048, &used ) == 1 );

	/* the largest handoff table (1,024) alone does not fit 768, fits 2,048 */
	lens[0] = WR_HANDOFF_MAX_TABLE;
	ok ( rbd_bios_xbft_fit ( lens, 1, 768, &used ) == 0 );
	ok ( used == 0 );
	ok ( rbd_bios_xbft_fit ( lens, 1, 2048, &used ) == 1 );
	ok ( used == 1024 );

	/* the largest handoff table next to the reference iBFT: exactly what the area is sized for, no byte to spare */
	lens[0] = WR_HANDOFF_MAX_TABLE;
	lens[1] = RBD_BIOS_IBFT_REFERENCE;
	ok ( rbd_bios_xbft_fit ( lens, 2, 2048, &used ) == 1 );
	ok ( used == RBD_BIOS_XBFT_NEED );
	ok ( used == 2048 );
	lens[0] = RBD_BIOS_IBFT_REFERENCE;
	lens[1] = WR_HANDOFF_MAX_TABLE;
	ok ( rbd_bios_xbft_fit ( lens, 2, 2048, &used ) == 1 );
	ok ( used == 2048 );
	ok ( rbd_bios_xbft_fit ( lens, 2, 2032, &used ) == 0 );	/* 2,032 (the stock size plus 1,264) would not do */

	/* two largest handoff tables fit exactly; a third table of any size does not */
	lens[0] = WR_HANDOFF_MAX_TABLE;
	lens[1] = WR_HANDOFF_MAX_TABLE;
	lens[2] = 1;
	ok ( rbd_bios_xbft_fit ( lens, 2, 2048, &used ) == 1 );
	ok ( used == 2048 );
	ok ( rbd_bios_xbft_fit ( lens, 3, 2048, &used ) == 0 );
	ok ( used == 2048 );

	/* the handoff table at its maximum next to an iBFT with CHAP names and secrets (four more strings of up to 255) does not fit: stated, not hidden */
	lens[0] = WR_HANDOFF_MAX_TABLE;
	lens[1] = ( RBD_BIOS_IBFT_REFERENCE + 4 * 256 );
	ok ( rbd_bios_xbft_fit ( lens, 2, 2048, &used ) == 0 );

	/* edges: one table that is exactly the area, one byte more, a length that would underflow the subtraction */
	lens[0] = 2048;
	ok ( rbd_bios_xbft_fit ( lens, 1, 2048, &used ) == 1 );
	ok ( used == 2048 );
	lens[0] = 2049;
	ok ( rbd_bios_xbft_fit ( lens, 1, 2048, &used ) == 0 );
	lens[0] = 2047;
	lens[1] = 1;
	ok ( rbd_bios_xbft_fit ( lens, 2, 2048, &used ) == 0 );	/* the first takes 2,048: no room for one byte more */
	lens[0] = ( ( size_t ) 0 - 1 );
	ok ( rbd_bios_xbft_fit ( lens, 1, 2048, &used ) == 0 );
	ok ( rbd_bios_xbft_fit ( lens, 1, 0, &used ) == 0 );
	lens[0] = 0;
	ok ( rbd_bios_xbft_fit ( lens, 1, 0, &used ) == 1 );	/* an empty table in an empty area is not an error */
}

/** The fit rule against a literal copy of int13_install()'s steps, over many sequences of lengths (deterministic) */
static void fit_property_test ( void ) {
	uint32_t seed = 0x2545f491;
	unsigned int round;
	size_t lens[6];
	size_t used;
	size_t model_used;
	size_t area;
	unsigned int count;
	unsigned int i;
	int model_fit;
	int fits;

	for ( round = 0 ; round < 5000 ; round++ ) {
		seed = ( seed * 1664525U + 1013904223U );
		/* the real area is a multiple of the alignment (iPXE's xbftab is 2,048 bytes); so is every area here */
		area = ( ( seed >> 8 ) % 2 ) ? 2048 : ( ( ( seed >> 12 ) % 3000 ) & ~( ( size_t ) 15 ) );
		count = ( ( seed >> 4 ) % 6 );
		for ( i = 0 ; i < count ; i++ ) {
			seed = ( seed * 1664525U + 1013904223U );
			lens[i] = ( ( seed >> 10 ) % 1300 );
		}
		model_used = 0;
		model_fit = 1;
		for ( i = 0 ; i < count ; i++ ) {
			if ( install_model ( area, &model_used, lens[i] ) != 0 ) {
				model_fit = 0;
				break;
			}
		}
		fits = rbd_bios_xbft_fit ( lens, count, area, &used );
		ok ( fits == model_fit );
		ok ( used == model_used );
		ok ( used <= area );
	}
}

/* ---- the scan ----------------------------------------------------------------------------------------------------------- */

/** A handoff table is found next to an iBFT, at its address, and nothing else is */
static void scan_find_test ( void ) {
	struct rbd_bios_hit hits[4];
	unsigned int refused = 99;
	unsigned int n;
	size_t rlen;
	size_t ilen = 640;

	memset ( rbd_area, 0, 8192 );
	rlen = make_rbft ( rbd_area + 0x1230, 1024, 3, 0 );
	ok ( rlen > 150 );
	ok ( rlen < 330 );
	make_table ( rbd_area + 0x0400, "iBFT", ilen, 0x5a );

	n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
	ok ( n == 2 );
	ok ( refused == 0 );
	ok ( hits[0].kind == RBD_BIOS_IBFT );
	ok ( hits[0].offset == 0x400 );
	ok ( hits[0].len == ilen );
	ok ( hits[1].kind == RBD_BIOS_RBFT );
	ok ( hits[1].offset == 0x1230 );
	ok ( hits[1].len == rlen );
	ok ( strcmp ( rbd_bios_kind_name ( hits[0].kind ), "iBFT" ) == 0 );
	ok ( strcmp ( rbd_bios_kind_name ( hits[1].kind ), "rBFT" ) == 0 );

	/* with the key in the table it is found just the same, and the scan only reads */
	memset ( rbd_area, 0, 8192 );
	rlen = make_rbft ( rbd_area + 0x20, 1024, 1, 1 );
	ok ( rlen > 150 );
	{
		uint8_t before[8192];

		memcpy ( before, rbd_area, 8192 );
		n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
		ok ( memcmp ( before, rbd_area, 8192 ) == 0 );
	}
	ok ( n == 1 );
	ok ( hits[0].kind == RBD_BIOS_RBFT );
	ok ( hits[0].offset == 0x20 );

	/* NULL refused is fine, and nothing is stored when max is 0 (but the tables are counted) */
	n = rbd_bios_scan ( rbd_area, 8192, NULL, 0, NULL );
	ok ( n == 1 );

	/* a table that ends exactly at the end of the memory is found, one that would run one byte past it is not */
	{
		uint8_t tmp[WR_HANDOFF_MAX_TABLE];
		size_t start;

		rlen = make_rbft ( tmp, sizeof ( tmp ), 1, 0 );
		ok ( rlen > 150 );
		start = ( 8192 - ( ( rlen + 15 ) & ~( size_t ) 15 ) );
		memset ( rbd_area, 0, 8192 );
		memcpy ( rbd_area + start, tmp, rlen );
		n = rbd_bios_scan ( rbd_area, ( start + rlen ), hits, 4, &refused );
		ok ( n == 1 );
		ok ( refused == 0 );
		ok ( hits[0].offset == start );
		n = rbd_bios_scan ( rbd_area, ( start + rlen - 1 ), hits, 4, &refused );
		ok ( n == 0 );
		ok ( refused == 1 );
	}

	/* nothing at all */
	memset ( rbd_area, 0, 8192 );
	n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
	ok ( n == 0 );
	ok ( refused == 0 );
	n = rbd_bios_scan ( rbd_area, 0, hits, 4, &refused );
	ok ( n == 0 );
	n = rbd_bios_scan ( rbd_area, 3, hits, 4, &refused );
	ok ( n == 0 );
}

/** Every way a candidate can be wrong */
static void scan_refuse_test ( void ) {
	struct rbd_bios_hit hits[4];
	unsigned int refused;
	unsigned int n;
	size_t rlen;
	uint8_t *p;

	/* bad checksum */
	memset ( rbd_area, 0, 8192 );
	rlen = make_rbft ( rbd_area + 0x100, 1024, 2, 0 );
	rbd_area[ 0x100 + 8 ] ^= 0x40;	/* a body byte (the revision): the sum is off */
	n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
	ok ( n == 0 );
	ok ( refused == 1 );

	/* a right checksum over a broken body: the magic is wrong (the consumer would refuse it) */
	memset ( rbd_area, 0, 8192 );
	rlen = make_rbft ( rbd_area + 0x100, 1024, 2, 0 );
	rbd_area[ 0x100 + 36 ] = 'X';	/* the "WRBT" magic */
	fix ( rbd_area + 0x100 );
	n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
	ok ( n == 0 );
	ok ( refused == 1 );

	/* a right checksum over a body with a field out of range (the mode byte at body offset 9 is 0 .. 4; make it 99) */
	memset ( rbd_area, 0, 8192 );
	rlen = make_rbft ( rbd_area + 0x100, 1024, 2, 0 );
	{
		unsigned int k;
		unsigned int changed = 0;

		/* try every body byte of the fixed part: set it to 0xff and keep the checksum right; whatever the core refuses is not reported,
		 * and the scan agrees with the core's decoder for every one of them */
		for ( k = 36 ; k < ( 36 + 116 ) ; k++ ) {
			uint8_t saved = rbd_area[ 0x100 + k ];
			wr_status st;

			rbd_area[ 0x100 + k ] = 0xff;
			fix ( rbd_area + 0x100 );
			st = wr_handoff_decode_table ( rbd_area + 0x100, rlen, NULL );
			n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
			ok ( n == ( ( st == WR_OK ) ? 1U : 0U ) );
			ok ( refused == ( ( st == WR_OK ) ? 0U : 1U ) );
			if ( st != WR_OK )
				changed++;
			rbd_area[ 0x100 + k ] = saved;
		}
		fix ( rbd_area + 0x100 );
		ok ( changed > 0 );	/* the decoder refuses some of them (the scan agreed with it in every case above) */
		n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
		ok ( n == 1 );
	}

	/* lengths: too small (under the 36-byte header), 0, huge, past the end of the memory, over the scan's cap */
	{
		static const uint32_t bad_len[] = { 0, 35, 0xffffffffU, 0x80000000U, 8192, 4097, 100000 };
		unsigned int i;

		for ( i = 0 ; i < ( sizeof ( bad_len ) / sizeof ( bad_len[0] ) ) ; i++ ) {
			memset ( rbd_area, 0, 8192 );
			make_table ( rbd_area + 0x200, "iBFT", 600, 0x33 );
			p = rbd_area + 0x200;
			p[4] = ( uint8_t ) bad_len[i];
			p[5] = ( uint8_t ) ( bad_len[i] >> 8 );
			p[6] = ( uint8_t ) ( bad_len[i] >> 16 );
			p[7] = ( uint8_t ) ( bad_len[i] >> 24 );
			n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
			ok ( n == 0 );
			ok ( refused == 1 );
		}
	}

	/* the cap of the scan: a table of 4,096 bytes with a right checksum is found, one of 4,097 (also with a right checksum, and well inside the memory) is not */
	memset ( rbd_area, 0, 16384 );
	make_table ( rbd_area + 0x100, "iBFT", RBD_BIOS_SCAN_TABLE_MAX, 0x21 );
	n = rbd_bios_scan ( rbd_area, 16384, hits, 4, &refused );
	ok ( n == 1 );
	ok ( hits[0].len == RBD_BIOS_SCAN_TABLE_MAX );
	ok ( refused == 0 );
	memset ( rbd_area, 0, 16384 );
	make_table ( rbd_area + 0x100, "iBFT", ( RBD_BIOS_SCAN_TABLE_MAX + 1 ), 0x21 );
	n = rbd_bios_scan ( rbd_area, 16384, hits, 4, &refused );
	ok ( n == 0 );
	ok ( refused == 1 );
	memset ( rbd_area, 0, 16384 );
	make_table ( rbd_area + 0x100, "iBFT", 9000, 0x21 );
	n = rbd_bios_scan ( rbd_area, 16384, hits, 4, &refused );
	ok ( n == 0 );
	ok ( refused == 1 );

	/* a signature that is not aligned to 16 bytes is not a candidate at all (not even counted as refused) */
	memset ( rbd_area, 0, 8192 );
	make_table ( rbd_area + 0x208, "iBFT", 600, 0x33 );
	n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
	ok ( n == 0 );
	ok ( refused == 0 );
	memset ( rbd_area, 0, 8192 );
	rlen = make_rbft ( rbd_area + 0x101, 1024, 1, 0 );
	n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
	ok ( n == 0 );
	ok ( refused == 0 );

	/* an unknown signature, a lower-case one, and a signature cut short at the end of the memory */
	memset ( rbd_area, 0, 8192 );
	make_table ( rbd_area + 0x200, "DSDT", 300, 0x44 );
	make_table ( rbd_area + 0x400, "ibft", 300, 0x44 );
	make_table ( rbd_area + 0x600, "RBFT", 300, 0x44 );
	/* the signature is all four characters: the first three of each known signature are not enough */
	make_table ( rbd_area + 0x800, "iBFX", 300, 0x44 );
	make_table ( rbd_area + 0xa00, "aBFX", 300, 0x44 );
	make_table ( rbd_area + 0xc00, "sBFX", 300, 0x44 );
	make_table ( rbd_area + 0xe00, "rBFX", 300, 0x44 );
	make_table ( rbd_area + 0x1000, "xBFT", 300, 0x44 );
	n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
	ok ( n == 0 );
	ok ( refused == 0 );
	memset ( rbd_area, 0, 8192 );
	memcpy ( rbd_area + 8176, "aBFT", 4 );
	n = rbd_bios_scan ( rbd_area, 8180, hits, 4, &refused );	/* the header does not fit in what is left */
	ok ( n == 0 );
	ok ( refused == 1 );

	/* the other tables iPXE installs: aBFT and sBFT are found as such */
	memset ( rbd_area, 0, 8192 );
	make_table ( rbd_area + 0x300, "aBFT", 80, 0x11 );
	make_table ( rbd_area + 0x400, "sBFT", 100, 0x22 );
	n = rbd_bios_scan ( rbd_area, 8192, hits, 4, &refused );
	ok ( n == 2 );
	ok ( hits[0].kind == RBD_BIOS_ABFT );
	ok ( hits[1].kind == RBD_BIOS_SBFT );
	ok ( refused == 0 );

	/* more tables than the array holds: all are counted, the array has the first ones */
	memset ( rbd_area, 0, 8192 );
	make_table ( rbd_area + 0x100, "aBFT", 80, 1 );
	make_table ( rbd_area + 0x200, "sBFT", 80, 2 );
	make_table ( rbd_area + 0x300, "iBFT", 80, 3 );
	n = rbd_bios_scan ( rbd_area, 8192, hits, 2, &refused );
	ok ( n == 3 );
	ok ( hits[0].offset == 0x100 );
	ok ( hits[1].offset == 0x200 );
}

/** A flipped bit anywhere in the handoff table makes it disappear from the scan, whatever the bit */
static void scan_bitflip_test ( void ) {
	struct rbd_bios_hit hits[4];
	unsigned int refused;
	size_t rlen;
	size_t bit;
	unsigned int found = 0;
	unsigned int refused_count = 0;

	memset ( rbd_area, 0, 4096 );
	rlen = make_rbft ( rbd_area + 0x40, 1024, 3, 1 );
	ok ( rlen > 150 );
	ok ( rbd_bios_scan ( rbd_area, 4096, hits, 4, &refused ) == 1 );
	for ( bit = 0 ; bit < ( rlen * 8 ) ; bit++ ) {
		rbd_area[ 0x40 + ( bit / 8 ) ] ^= ( uint8_t ) ( 1U << ( bit % 8 ) );
		if ( rbd_bios_scan ( rbd_area, 4096, hits, 4, &refused ) != 0 )
			found++;
		else
			refused_count += refused;
		rbd_area[ 0x40 + ( bit / 8 ) ] ^= ( uint8_t ) ( 1U << ( bit % 8 ) );
	}
	ok ( found == 0 );
	/* a flip in the signature usually leaves no candidate (4 * 8 of them; one, 'r' to 's', makes the signature of an sBFT, which the checksum then refuses); every other flip is a refusal */
	ok ( refused_count >= ( ( rlen * 8 ) - 32 ) );
	ok ( refused_count <= ( rlen * 8 ) );
	ok ( rbd_bios_scan ( rbd_area, 4096, hits, 4, &refused ) == 1 );
}

/* ---- the model of a BIOS machine: where the area is, and what a guest finds --------------------------------------------- */

/**
 * Install a table into the area model the way int13_install() does
 *
 * @v area		The area
 * @v size		Its size
 * @v used		Used length
 * @v table		The table
 * @v len		Its length
 * @ret rc		0, or -1 if it does not fit
 */
static int area_install ( uint8_t *area, size_t size, size_t *used, const uint8_t *table, size_t len ) {

	if ( install_model ( size, used, len ) != 0 )
		return -1;
	/* install_model() has already advanced *used: the table went to the old end, which is the new end minus the aligned length */
	memcpy ( area + ( *used - rbd_bios_xbft_entry ( len ) ), table, len );
	return 0;
}

/** An area at the top of base memory is inside the window; one under 512 KiB is not */
static void machine_test ( void ) {
	struct rbd_bios_hit hits[4];
	unsigned int refused;
	uint8_t rbft[WR_HANDOFF_MAX_TABLE];
	uint8_t ibft[800];
	size_t rlen;
	size_t used = 0;
	unsigned long area_phys;
	unsigned long phys;
	unsigned int n;

	rlen = make_rbft ( rbft, sizeof ( rbft ), 2, 1 );
	ok ( rlen > 150 );
	make_table ( ibft, "iBFT", 700, 0x6b );

	/* the live rows: the area was at 0x9a800 (undionly) and 0x9e100 (native drivers); both leave the table inside the window */
	{
		static const unsigned long where[] = { 0x9a800UL, 0x9e100UL, 0x80000UL, 0x9f800UL };
		unsigned int w;

		for ( w = 0 ; w < ( sizeof ( where ) / sizeof ( where[0] ) ) ; w++ ) {
			area_phys = where[w];
			memset ( rbd_area, 0, T_WINDOW );
			used = 0;
			ok ( area_install ( rbd_area + ( area_phys - RBD_BIOS_WINDOW_LO ), 2048, &used, ibft, 700 ) == 0 );
			ok ( area_install ( rbd_area + ( area_phys - RBD_BIOS_WINDOW_LO ), 2048, &used, rbft, rlen ) == 0 );
			n = rbd_bios_scan ( rbd_area, T_WINDOW, hits, 4, &refused );
			ok ( n == 2 );
			ok ( refused == 0 );
			ok ( hits[0].kind == RBD_BIOS_IBFT );
			ok ( hits[0].offset == ( area_phys - RBD_BIOS_WINDOW_LO ) );
			ok ( hits[1].kind == RBD_BIOS_RBFT );
			phys = ( RBD_BIOS_WINDOW_LO + hits[1].offset );
			ok ( phys == ( area_phys + rbd_bios_xbft_entry ( 700 ) ) );
			ok ( rbd_bios_in_window ( phys, hits[1].len ) == 1 );
			ok ( rbd_bios_in_window ( RBD_BIOS_WINDOW_LO + hits[0].offset, hits[0].len ) == 1 );
		}
	}

	/* the iBFT alone fills the first 704 bytes; a handoff table of the largest size and the reference iBFT fill the 2,048-byte area up to 16 bytes; both found */
	{
		uint8_t big_ibft[RBD_BIOS_IBFT_REFERENCE];
		uint8_t big_rbft[WR_HANDOFF_MAX_TABLE];

		make_table ( big_ibft, "iBFT", RBD_BIOS_IBFT_REFERENCE, 0x77 );
		/* a handoff table at the 1,024-byte maximum cannot be made by the encoder without 255-byte names: build it by hand as a table of
		 * the right length that the scan treats as an unknown-body table, and check only the area arithmetic and the window */
		memset ( big_rbft, 0, sizeof ( big_rbft ) );
		memset ( rbd_area, 0, T_WINDOW );
		used = 0;
		ok ( area_install ( rbd_area, 2048, &used, big_rbft, sizeof ( big_rbft ) ) == 0 );
		ok ( area_install ( rbd_area, 2048, &used, big_ibft, sizeof ( big_ibft ) ) == 0 );
		ok ( used == 2048 );
		n = rbd_bios_scan ( rbd_area, 2048, hits, 4, &refused );
		ok ( n == 1 );
		ok ( hits[0].kind == RBD_BIOS_IBFT );
		ok ( hits[0].offset == 1024 );
	}

	/* an area that ended up below 512 KiB is not seen by a scan of the window (why the layout matters): the window scan finds nothing, the low
	 * scan of "rbd-xbft" finds the tables (the way the command runs the two scans over one machine's memory), and the window test says OUTSIDE */
	area_phys = 0x7f800UL;
	{
		/* base memory as one buffer, from RBD_BIOS_LOW_START to the end of the window: the first part is the low scan's range */
		uint8_t *mem = malloc ( RBD_BIOS_WINDOW_HI - RBD_BIOS_LOW_START );
		struct rbd_bios_hit low[4];
		size_t lowlen = ( RBD_BIOS_WINDOW_LO - RBD_BIOS_LOW_START );

		ok ( mem != NULL );
		if ( mem ) {
			memset ( mem, 0, ( RBD_BIOS_WINDOW_HI - RBD_BIOS_LOW_START ) );
			/* the area as the machine has it: 2,048 bytes at 0x7f800, which end at 0x80000 */
			used = 0;
			ok ( area_install ( mem + ( area_phys - RBD_BIOS_LOW_START ), 2048, &used, ibft, 700 ) == 0 );
			ok ( area_install ( mem + ( area_phys - RBD_BIOS_LOW_START ), 2048, &used, rbft, rlen ) == 0 );
			n = rbd_bios_scan ( mem + lowlen, T_WINDOW, hits, 4, &refused );
			ok ( n == 0 );
			ok ( refused == 0 );
			n = rbd_bios_scan ( mem, lowlen, low, 4, &refused );
			ok ( n == 2 );
			ok ( refused == 0 );
			ok ( low[0].kind == RBD_BIOS_IBFT );
			ok ( low[1].kind == RBD_BIOS_RBFT );
			phys = ( RBD_BIOS_LOW_START + low[0].offset );
			ok ( phys == area_phys );
			ok ( rbd_bios_in_window ( phys, low[0].len ) == 0 );
			phys = ( RBD_BIOS_LOW_START + low[1].offset );
			ok ( phys == ( area_phys + rbd_bios_xbft_entry ( 700 ) ) );
			ok ( rbd_bios_in_window ( phys, low[1].len ) == 0 );
			/* a table that begins below the window and ends in it: the low scan stops at the window, so it refuses it (counted, not listed) */
			memset ( mem, 0, ( RBD_BIOS_WINDOW_HI - RBD_BIOS_LOW_START ) );
			memcpy ( mem + ( 0x7ff80UL - RBD_BIOS_LOW_START ), rbft, rlen );
			n = rbd_bios_scan ( mem, lowlen, low, 4, &refused );
			ok ( n == 0 );
			ok ( refused == 1 );
			free ( mem );
		}
	}
	ok ( rbd_bios_in_window ( area_phys, rlen ) == 0 );
	ok ( rbd_bios_in_window ( area_phys + 2048, 16 ) == 1 );	/* 0x80000 */
	ok ( rbd_bios_in_window ( area_phys + 2040, 16 ) == 0 );	/* straddles the low edge: misaligned */
	ok ( rbd_bios_in_window ( 0x7fff0UL, 32 ) == 0 );		/* straddles it, aligned */
}

/** The window test at its edges */
static void window_test ( void ) {

	ok ( rbd_bios_in_window ( 0x9a880UL, 234 ) == 1 );
	ok ( rbd_bios_in_window ( 0x80000UL, 16 ) == 1 );
	ok ( rbd_bios_in_window ( 0x7fff0UL, 16 ) == 0 );
	ok ( rbd_bios_in_window ( 0xffff0UL, 16 ) == 1 );
	ok ( rbd_bios_in_window ( 0xffff0UL, 17 ) == 0 );
	ok ( rbd_bios_in_window ( 0x100000UL, 16 ) == 0 );
	ok ( rbd_bios_in_window ( 0x100000UL, 0 ) == 0 );		/* an empty table at the end is outside, too */
	ok ( rbd_bios_in_window ( 0x7fff0UL, 0 ) == 0 );
	ok ( rbd_bios_in_window ( 0x9a881UL, 16 ) == 0 );		/* not 16-byte aligned: a scan steps by 16 */
	ok ( rbd_bios_in_window ( 0x9a88fUL, 16 ) == 0 );
	ok ( rbd_bios_in_window ( 0x9a880UL, 0 ) == 1 );
	ok ( rbd_bios_in_window ( 0x9a880UL, ( ( size_t ) 0 - 1 ) ) == 0 );	/* no wrap-around */
	ok ( rbd_bios_in_window ( 0UL, 16 ) == 0 );
	ok ( rbd_bios_in_window ( ( ( unsigned long ) 0 - 16 ), 16 ) == 0 );
}

/** The names */
static void names_test ( void ) {

	ok ( strcmp ( rbd_bios_kind_name ( RBD_BIOS_IBFT ), "iBFT" ) == 0 );
	ok ( strcmp ( rbd_bios_kind_name ( RBD_BIOS_ABFT ), "aBFT" ) == 0 );
	ok ( strcmp ( rbd_bios_kind_name ( RBD_BIOS_SBFT ), "sBFT" ) == 0 );
	ok ( strcmp ( rbd_bios_kind_name ( RBD_BIOS_RBFT ), "rBFT" ) == 0 );
	ok ( strcmp ( rbd_bios_kind_name ( RBD_BIOS_NONE ), "none" ) == 0 );
	ok ( strcmp ( rbd_bios_kind_name ( ( enum rbd_bios_kind ) 99 ), "none" ) == 0 );
}

/** The exit warning's decision */
static void warning_test ( void ) {
	const char *w;

	/* exiting with a drive over undionly: the one case */
	w = rbd_bios_exit_warning ( 0, "undionly", 1 );
	ok ( w != NULL );
	ok ( w && strstr ( w, "sanboot" ) != NULL );
	ok ( w && strstr ( w, "ipxe.pxe" ) != NULL );
	ok ( w && strchr ( w, '\n' ) == NULL );
	ok ( rbd_bios_exit_warning ( 0, "undionly", 3 ) == w );

	/* booting an operating system: iPXE does not exit to the ROM, the stack is shut down on purpose */
	ok ( rbd_bios_exit_warning ( 1, "undionly", 1 ) == NULL );
	/* no hooked drive */
	ok ( rbd_bios_exit_warning ( 0, "undionly", 0 ) == NULL );
	/* no driver name */
	ok ( rbd_bios_exit_warning ( 0, NULL, 1 ) == NULL );
	/* every other driver: native NIC drivers keep the NIC (row B0 with ipxe.pxe), and the other UNDI drivers are not the ROM's preloaded stack */
	ok ( rbd_bios_exit_warning ( 0, "e1000", 1 ) == NULL );
	ok ( rbd_bios_exit_warning ( 0, "virtio-net", 1 ) == NULL );
	ok ( rbd_bios_exit_warning ( 0, "undipci", 1 ) == NULL );
	ok ( rbd_bios_exit_warning ( 0, "undirom", 1 ) == NULL );
	ok ( rbd_bios_exit_warning ( 0, "Undionly", 1 ) == NULL );
	ok ( rbd_bios_exit_warning ( 0, "undionly2", 1 ) == NULL );
	ok ( rbd_bios_exit_warning ( 0, "", 1 ) == NULL );
}

/**
 * Perform the BIOS helpers self-test
 *
 */
static void rbd_bios_test_exec ( void ) {

	rbd_area = malloc ( T_WINDOW );
	ok ( rbd_area != NULL );
	if ( ! rbd_area )
		return;

	constants_test();
	entry_test();
	fit_test();
	fit_property_test();
	scan_find_test();
	scan_refuse_test();
	scan_bitflip_test();
	machine_test();
	window_test();
	names_test();
	warning_test();

	free ( rbd_area );
	rbd_area = NULL;
}

/** BIOS helpers self-test */
struct self_test rbd_bios_test __self_test = {
	.name = "rbd_bios_test",
	.exec = rbd_bios_test_exec,
};
