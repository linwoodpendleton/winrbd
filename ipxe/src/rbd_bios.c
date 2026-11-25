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
/* FILE_SECBOOT ( FORBIDDEN ): the BIOS part of this file reads raw physical memory below 1 MiB (the "rbd-xbft" command), the pure
 * part is only ever linked into BIOS images (patch 0004 requires the object there and nowhere else) and the Linux self-test
 * program (a BIOS machine has no Secure Boot), and the file belongs to a driver whose every other file is FORBIDDEN (nothing of
 * the driver has been reviewed for a signed build). Nothing here is PERMITTED, and nothing needs to be: EFI builds do not link
 * this object.
 */
FILE_SECBOOT ( FORBIDDEN );

/** @file
 *
 * RBD (Ceph) SAN protocol: the BIOS (INT 13h) side
 *
 * What the BIOS measurements of the live matrix (harness/lab/p2/results/bios, 2026-11-23, and the re-run of this module in
 * harness/lab/p2/results/bios2) asked for, and nothing more. The stack decision of docs/design/ipxe-driver.md section 5.2 is in
 * rbd_session.c (the core runs on its own stack on i386); the device path of INT 13h AH=48h (edd_describe) is NOT provided, see
 * "edd_describe" below.
 *
 * The boot firmware tables.  iPXE keeps every table of every SAN device in ONE area of data16, XBFTAB_SIZE bytes, 16-byte
 * aligned entries, installed in the order the SAN devices describe themselves (src/arch/x86/interface/pcbios/int13.c,
 * int13_install(): a table that does not fit makes the whole description fail with -ENOSPC, and sanhook / sanboot with it). The
 * stock size is 768 bytes. The handoff table ("rBFT") is at most WR_HANDOFF_MAX_TABLE (1,024) bytes, and a machine that boots from
 * an RBD image and also hooks an iSCSI disk has an iBFT in the same area. Patch 0002 raised the area to 2,048 bytes; patch 0004
 * moves the two constants into int13.h so that this file can refuse to compile when they are lowered (the check at the end).
 * The numbers: the reference iBFT (one target, longest IQNs, no CHAP) is RBD_BIOS_IBFT_REFERENCE bytes, a typical iBFT about
 * 620 and a typical handoff table 218 to 330; the area needs RBD_BIOS_XBFT_NEED (2,048) with the worst of both, so it has no
 * byte to spare for that case, and the typical case (an iBFT of 620 next to a handoff table of 240) uses 864 of 2,048.
 * What does NOT fit, and fails with -ENOSPC and one DBG line: three tables of the maximum size, or the maximum handoff table
 * next to an iBFT that has CHAP names and secrets as well.
 *
 * Where a guest finds them.  An operating system does not look in an RSDT on BIOS (there is none): it scans memory for the
 * signature, 16-byte aligned, and keeps what has a valid length and checksum. The iBFT window of Linux and Windows is
 * 512 KiB to 1 MiB (0x80000 - 0xfffff); the area is in data16, which iPXE puts at the top of base memory (below 0xa0000), so
 * it is inside the window as long as the resident BIOS part of iPXE (text16 and data16) is smaller than 128 KiB. The self-test
 * checks the scan against tables built by the core's encoder, with the OEM fields rewritten and the checksum fixed the way
 * int13_install() does; the "rbd-xbft" command runs the same scan over the machine's memory so that a boot script (and the
 * live matrix) can print where the tables are after sanhook. It also scans the rest of base memory (RBD_BIOS_LOW_START up to the
 * window) and lists what it finds there as OUTSIDE: a scan of the window alone could only ever answer "inside" or "no table", and
 * the one failure this check exists for (the area sits below 512 KiB, an operating system does not see it) would look like "the
 * driver installed nothing".
 *
 * edd_describe.  Not provided. INT 13h AH=48h asks the block interface for edd_describe to fill the device path part of the
 * EDD parameters; without it iPXE returns the parameters without that part (len = offsetof ( dpi )), which is valid EDD 2.0.
 * The rows that boot an operating system through this driver on BIOS (Linux through GRUB, the Windows Preinstallation
 * Environment through bootmgr: PXE and USB stick, i386 and x86_64 images) all reach their system without it, and the hooked
 * drive shows up in the kernel's EDD list as a plain int13 device. Adding an ATA-style path ("ATA" interface type, master) would
 * make this driver claim a controller that does not exist; it is added only when a Windows boot is shown to need it.
 *
 * The exit warning.  "sanhook" followed by "exit" with the stock UNDI driver (undionly.kpxe) leaves a drive that is visible to
 * the BIOS but unreadable: iPXE keeps its network devices when a SAN drive is hooked (devices_get() in int13_hook()), but the
 * NIC is driven through the PXE ROM's UNDI stack, and the ROM stops that stack when iPXE returns to it. Every command of the
 * drive then waits for the driver's stall deadline (RBD_STALL_CLOSE_MS) and fails; a guest that probes the drive pays that
 * wait per probe (row B0 of the live matrix: 130 s instead of 20 s). A native driver (ipxe.pxe) is not affected, "sanboot" does
 * not exit. The cause is an inference from the sources and from B0 against its control with a native NIC; the warning is printed
 * once, by the shutdown hook, when iPXE is about to exit (not boot), has an RBD drive, and a network device runs on undionly.
 *
 * The pure functions (the area arithmetic, the scan, the window test, the warning's decision) are built on every platform and
 * tested in ipxe/tests/rbd_bios_test.c; the command and the shutdown hook exist only in a BIOS build (PLATFORM_pcbios).
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ipxe/acpi.h>
#include <ipxe/ibft.h>
#include "rbd_priv.h"
#include "rbd_bios.h"

/** Read a little-endian 32-bit value (the scan may be pointed at any address: no alignment is assumed) */
static uint32_t rbd_bios_le32 ( const uint8_t *p ) {
	return ( ( uint32_t ) p[0] | ( ( uint32_t ) p[1] << 8 ) |
		 ( ( uint32_t ) p[2] << 16 ) | ( ( uint32_t ) p[3] << 24 ) );
}

/**
 * Length of an area entry
 *
 * @v len		Length of the table
 * @ret len		Length it takes in the area (rounded up to the alignment, the rule of int13_install()); SIZE_MAX for a length
 *			that cannot be rounded up without wrapping around (no area is that big, so it never fits; the plain sum
 *			would come out as a small number, 0 for SIZE_MAX)
 */
size_t rbd_bios_xbft_entry ( size_t len ) {

	if ( len > ( ( ( size_t ) 0 - 1 ) - ( RBD_BIOS_XBFT_ALIGN - 1 ) ) )
		return ( ( size_t ) 0 - 1 );
	return ( ( len + RBD_BIOS_XBFT_ALIGN - 1 ) &
		 ~( ( size_t ) RBD_BIOS_XBFT_ALIGN - 1 ) );
}

/**
 * Check whether tables fit into the boot firmware table area
 *
 * @v lens		Lengths of the tables, in the order they are installed
 * @v count		Number of tables
 * @v area		Size of the area
 * @v used		Bytes of the area the tables use (after the last one that fit), or NULL
 * @ret fit		1 if all of them fit, 0 if one does not (the rule of int13_install(): a table is refused when its length is more
 *			than what is left, and an entry always takes a multiple of the alignment)
 */
int rbd_bios_xbft_fit ( const size_t *lens, unsigned int count, size_t area,
			size_t *used ) {
	size_t pos = 0;
	unsigned int i;

	for ( i = 0 ; i < count ; i++ ) {
		if ( lens[i] > ( area - pos ) )
			break;
		pos = rbd_bios_xbft_entry ( pos + lens[i] );
		if ( pos > area )
			pos = area;
	}
	if ( used )
		*used = pos;
	return ( i == count );
}

/**
 * Name of a table kind
 *
 * @v kind		Kind
 * @ret name		Its four-character signature
 */
const char * rbd_bios_kind_name ( enum rbd_bios_kind kind ) {

	switch ( kind ) {
	case RBD_BIOS_IBFT:	return "iBFT";
	case RBD_BIOS_ABFT:	return "aBFT";
	case RBD_BIOS_SBFT:	return "sBFT";
	case RBD_BIOS_RBFT:	return "rBFT";
	default:		return "none";
	}
}

/**
 * Classify a signature
 *
 * @v sig		The first four bytes of a candidate
 * @ret kind		Its kind, or RBD_BIOS_NONE
 */
static enum rbd_bios_kind rbd_bios_kind ( const uint8_t *sig ) {

	if ( memcmp ( sig, "iBFT", 4 ) == 0 )
		return RBD_BIOS_IBFT;
	if ( memcmp ( sig, "aBFT", 4 ) == 0 )
		return RBD_BIOS_ABFT;
	if ( memcmp ( sig, "sBFT", 4 ) == 0 )
		return RBD_BIOS_SBFT;
	if ( memcmp ( sig, WR_HANDOFF_SIGNATURE, 4 ) == 0 )
		return RBD_BIOS_RBFT;
	return RBD_BIOS_NONE;
}

/**
 * Find the boot firmware tables in memory, the way a guest operating system does
 *
 * @v mem		Memory (address 0 of the scan)
 * @v len		Length of the memory
 * @v hits		Array to fill
 * @v max		Size of the array
 * @v refused		Number of candidates that had a signature but no valid length, checksum or (for the handoff table) content, or NULL
 * @ret count		Number of valid tables found (more than max are counted but not stored)
 *
 * Every 16-byte aligned offset is a candidate when its first four bytes are the signature of a table iPXE installs. It is a
 * table when the length field (offset 4) is at least the 36-byte ACPI header, at most RBD_BIOS_SCAN_TABLE_MAX and at most what
 * is left of the memory, and the bytes of the table add up to zero. The handoff table must also pass the core's own decoder over
 * all its fields (the consumer does the same; a table with the right checksum and a broken body is refused, not reported).
 * The memory is only read. Nothing is copied, so no secret is: the key of a handoff table stays where it is.
 */
unsigned int rbd_bios_scan ( const void *mem, size_t len,
			     struct rbd_bios_hit *hits, unsigned int max,
			     unsigned int *refused ) {
	const uint8_t *bytes = mem;
	unsigned int count = 0;
	unsigned int bad = 0;
	size_t off;
	size_t tlen;
	size_t i;
	uint8_t sum;
	enum rbd_bios_kind kind;

	for ( off = 0 ; ( off + 4 ) <= len ; off += RBD_BIOS_XBFT_ALIGN ) {
		kind = rbd_bios_kind ( bytes + off );
		if ( kind == RBD_BIOS_NONE )
			continue;
		if ( ( len - off ) < sizeof ( struct acpi_header ) ) {
			bad++;
			continue;
		}
		tlen = rbd_bios_le32 ( bytes + off + 4 );
		if ( ( tlen < sizeof ( struct acpi_header ) ) ||
		     ( tlen > RBD_BIOS_SCAN_TABLE_MAX ) ||
		     ( tlen > ( len - off ) ) ) {
			bad++;
			continue;
		}
		for ( sum = 0, i = 0 ; i < tlen ; i++ )
			sum = ( uint8_t ) ( sum + bytes[ off + i ] );
		if ( sum != 0 ) {
			bad++;
			continue;
		}
		if ( ( kind == RBD_BIOS_RBFT ) &&
		     ( wr_handoff_decode_table ( bytes + off, tlen,
						 NULL ) != WR_OK ) ) {
			bad++;
			continue;
		}
		if ( count < max ) {
			hits[count].kind = kind;
			hits[count].offset = off;
			hits[count].len = tlen;
		}
		count++;
	}
	if ( refused )
		*refused = bad;
	return count;
}

/**
 * Check whether a table lies inside the memory window that operating systems scan
 *
 * @v phys		Physical address of the table
 * @v len		Length of the table
 * @ret inside		1 if all of it is inside RBD_BIOS_WINDOW_LO .. RBD_BIOS_WINDOW_HI, and 16-byte aligned
 */
int rbd_bios_in_window ( unsigned long phys, size_t len ) {

	if ( ( phys % RBD_BIOS_XBFT_ALIGN ) != 0 )
		return 0;
	if ( ( phys < RBD_BIOS_WINDOW_LO ) || ( phys >= RBD_BIOS_WINDOW_HI ) )
		return 0;
	return ( len <= ( RBD_BIOS_WINDOW_HI - phys ) );
}

/**
 * Decide on the exit warning
 *
 * @v booting		iPXE is shutting down to boot an operating system (not to exit)
 * @v driver		Driver name of a network device, or NULL
 * @v drives		Number of hooked RBD drives
 * @ret text		The warning, or NULL if there is nothing to warn about
 */
const char * rbd_bios_exit_warning ( int booting, const char *driver,
				     unsigned int drives ) {

	if ( booting || ! drives || ! driver )
		return NULL;
	if ( strcmp ( driver, "undionly" ) != 0 )
		return NULL;
	return "an RBD drive is hooked and iPXE is exiting over a UNDI network "
	       "device: the PXE ROM stops its network stack when iPXE returns, "
	       "and reads of the drive will then stall (boot with sanboot, or "
	       "use ipxe.pxe with a native driver)";
}

/******************************************************************************
 *
 * BIOS only: the command and the shutdown hook
 *
 ******************************************************************************
 */

#if defined ( PLATFORM_pcbios )

#include <int13.h>
#include <ipxe/io.h>
#include <ipxe/init.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include <ipxe/netdevice.h>
#include <ipxe/device.h>
#include "rbd_session.h"

/* The driver sizes its tables for an area of RBD_BIOS_XBFT_NEED bytes: lowering XBFTAB_SIZE below it (dropping patch 0002 or 0004)
 * would turn a boot with an iBFT into a -ENOSPC at run time, so it is a compile error instead. Compiled out of every other platform.
 */
typedef char rbd_bios_area_fits[ ( XBFTAB_SIZE >= RBD_BIOS_XBFT_NEED ) ? 1 : -1 ];

/* ... and the number this file documents, the self-test's, and the real one are the same number */
typedef char rbd_bios_area_is_documented[ ( XBFTAB_SIZE == RBD_BIOS_XBFT_SIZE ) ? 1 : -1 ];

/* ... and the alignment of the entries is the one the arithmetic above assumes */
typedef char rbd_bios_align_is_iPXEs[ ( XBFTAB_ALIGN == RBD_BIOS_XBFT_ALIGN ) ? 1 : -1 ];

/** "rbd-xbft" options */
struct rbd_xbft_options {};

/** "rbd-xbft" option list */
static struct option_descriptor rbd_xbft_opts[] = {};

/** "rbd-xbft" command descriptor */
static struct command_descriptor rbd_xbft_cmd =
	COMMAND_DESC ( struct rbd_xbft_options, rbd_xbft_opts, 0, 0, NULL );

/** Most tables the command lists per scan (a handful is all a BIOS machine holds) */
#define RBD_XBFT_MAX 8

/**
 * List the tables of one scan
 *
 * @v hits		Tables found
 * @v count		Number of tables the scan counted
 * @v base		Physical address of the start of the scanned memory
 * @v lens		Array for the lengths of the tables listed (RBD_XBFT_MAX entries), or NULL
 * @ret shown		Number of tables listed
 *
 * Prints signature, address, length and whether the table is inside the window an operating system scans. No table content.
 */
static unsigned int rbd_xbft_list ( const struct rbd_bios_hit *hits,
				    unsigned int count, unsigned long base,
				    size_t *lens ) {
	unsigned int shown = ( ( count < RBD_XBFT_MAX ) ? count : RBD_XBFT_MAX );
	unsigned int i;

	for ( i = 0 ; i < shown ; i++ ) {
		unsigned long phys = ( base + hits[i].offset );

		if ( lens )
			lens[i] = hits[i].len;
		printf ( "xbft: %s at %#lx, %ld bytes, %s the %#lx-%#lx window\n",
			 rbd_bios_kind_name ( hits[i].kind ), phys,
			 ( ( long ) hits[i].len ),
			 ( rbd_bios_in_window ( phys, hits[i].len ) ?
			   "inside" : "OUTSIDE" ),
			 RBD_BIOS_WINDOW_LO, ( RBD_BIOS_WINDOW_HI - 1 ) );
	}
	if ( count > shown )
		printf ( "xbft: %ld more tables not listed\n",
			 ( ( long ) ( count - shown ) ) );
	return shown;
}

/**
 * The "rbd-xbft" command: where are the boot firmware tables?
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code (-ENOENT: no table found in the window)
 *
 * Scans the window an operating system scans and prints, for every table, its signature, physical address, length and
 * whether it is inside the window; then how much of the area the tables of the window use. The rest of base memory is scanned
 * as well and its tables are listed as OUTSIDE (an operating system does not see them: the command then still fails with
 * -ENOENT, and says so). It prints no table content (the handoff table can hold the key) and only reads memory.
 */
static int rbd_xbft_exec ( int argc, char **argv ) {
	struct rbd_xbft_options opts;
	struct rbd_bios_hit hits[RBD_XBFT_MAX];
	struct rbd_bios_hit low[RBD_XBFT_MAX];
	size_t lens[RBD_XBFT_MAX];
	size_t used;
	unsigned int refused;
	unsigned int count;
	unsigned int lowcount;
	unsigned int shown;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &rbd_xbft_cmd, &opts ) ) != 0 )
		return rc;

	/* Scan the window, in place, and the rest of base memory */
	count = rbd_bios_scan ( phys_to_virt ( RBD_BIOS_WINDOW_LO ),
				( RBD_BIOS_WINDOW_HI - RBD_BIOS_WINDOW_LO ),
				hits, RBD_XBFT_MAX, &refused );
	lowcount = rbd_bios_scan ( phys_to_virt ( RBD_BIOS_LOW_START ),
				   ( RBD_BIOS_WINDOW_LO - RBD_BIOS_LOW_START ),
				   low, RBD_XBFT_MAX, NULL );
	shown = rbd_xbft_list ( hits, count, RBD_BIOS_WINDOW_LO, lens );
	( void ) rbd_xbft_list ( low, lowcount, RBD_BIOS_LOW_START, NULL );
	if ( ! count ) {
		printf ( "xbft: no boot firmware table in %#lx-%#lx (%ld refused)%s\n",
			 RBD_BIOS_WINDOW_LO, ( RBD_BIOS_WINDOW_HI - 1 ),
			 ( ( long ) refused ),
			 ( lowcount ? ", an operating system will not find "
			   "the ones below it" : "" ) );
		return -ENOENT;
	}
	( void ) rbd_bios_xbft_fit ( lens, shown, XBFTAB_SIZE, &used );
	printf ( "xbft: %ld table(s) use %ld of the %d bytes of the area (%ld "
		 "refused)\n", ( ( long ) count ), ( ( long ) used ),
		 XBFTAB_SIZE, ( ( long ) refused ) );
	return 0;
}

/** The "rbd-xbft" command */
struct command rbd_xbft_command __command ( rbd_xbft ) = {
	.name = "rbd-xbft",
	.exec = rbd_xbft_exec,
};

/**
 * Warn when iPXE exits with an RBD drive hooked over the PXE ROM's network stack
 *
 * @v booting		System is shutting down for OS boot
 */
static void rbd_bios_shutdown ( int booting ) {
	struct rbd_session *session;
	struct net_device *netdev;
	const char *text = NULL;
	unsigned int drives = 0;

	if ( booting )
		return;
	list_for_each_entry ( session, &rbd_sessions, list )
		drives += session->ndev;
	if ( ! drives )
		return;
	for_each_netdev ( netdev ) {
		if ( ! netdev->dev )
			continue;
		text = rbd_bios_exit_warning ( booting,
					       netdev->dev->driver_name,
					       drives );
		if ( text ) {
			printf ( "rbd: %s: %s\n", netdev->name, text );
			return;
		}
	}
}

/** The shutdown hook (before the devices are removed) */
struct startup_fn rbd_bios_startup_fn __startup_fn ( STARTUP_LATE ) = {
	.name = "rbd_bios",
	.shutdown = rbd_bios_shutdown,
};

#endif /* PLATFORM_pcbios */
