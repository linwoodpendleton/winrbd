#ifndef _RBD_BIOS_H
#define _RBD_BIOS_H
/* SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL */
/** @file
 *
 * RBD (Ceph) SAN protocol: the BIOS (INT 13h) side, private declarations
 *
 * rbd_bios.c holds what is specific to the BIOS platform and has no place in the session or the block device:
 *
 *   - the arithmetic of the boot firmware table area (the rule int13_install() applies, the size of an iBFT, what the driver
 *     needs next to one), as plain functions that a self-test can run on a Linux host;
 *   - a scan of low memory for the boot firmware tables, written the way a guest operating system finds them, with the same
 *     acceptance rules for the handoff table as the core's decoder;
 *   - the "rbd-xbft" command, which prints what that scan finds, and what the same scan finds below the window (BIOS builds only);
 *   - a warning, printed when iPXE exits to the PXE ROM with an RBD drive hooked over the ROM's own network stack (BIOS builds
 *     only): the ROM stops the NIC when iPXE returns, which is what the hooked drive then needs.
 *
 * Licence: GPL2_OR_LATER_OR_UBDL, like iPXE's own SAN code. Secure Boot: FORBIDDEN, for the reasons given in rbd_bios.c.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

#include <stdint.h>
#include <stddef.h>
#include <ipxe/ibft.h>
#include "wr_handoff.h"

/** Alignment of the entries of the boot firmware table area (XBFTAB_ALIGN of int13.c) */
#define RBD_BIOS_XBFT_ALIGN 16

/** Start of the low scan of the "rbd-xbft" command: the end of the BIOS data area. Below the window an operating system does not look; the
 * command looks there too, only to say that a table that is there is OUTSIDE (the real mode interrupt vectors and the BIOS data area
 * before it hold no tables) */
#define RBD_BIOS_LOW_START 0x500UL

/** Start of the memory window in which an operating system looks for the boot firmware tables (the iBFT window: 512 KiB) */
#define RBD_BIOS_WINDOW_LO 0x80000UL

/** End of that window (1 MiB) */
#define RBD_BIOS_WINDOW_HI 0x100000UL

/** Round a length up to the alignment of the area's entries */
#define RBD_BIOS_ALIGN( len ) \
	( ( ( len ) + RBD_BIOS_XBFT_ALIGN - 1 ) & ~( ( size_t ) RBD_BIOS_XBFT_ALIGN - 1 ) )

/** Number of target and NIC pairs of an iBFT with the given number of targets (iBFT_install: at least two) */
#define RBD_BIOS_IBFT_PAIRS( targets ) ( ( targets ) > 2 ? ( targets ) : 2 )

/**
 * Length of the iBFT that iPXE builds, without its strings
 *
 * The same arithmetic as ibft_install() of drivers/block/ibft.c, over the same structures (ipxe/ibft.h), so that a change of
 * the pinned iPXE changes the number: the control part (the 16-byte aligned offset of the pair array and the pairs), the
 * initiator block, a NIC block and a target block for every pair, each aligned.
 */
#define RBD_BIOS_IBFT_FIXED( targets ) \
	( RBD_BIOS_ALIGN ( offsetof ( struct ibft_table, control.pair ) + \
			   RBD_BIOS_IBFT_PAIRS ( targets ) * \
			   sizeof ( ( ( struct ibft_table * ) 0 )->control.pair[0] ) ) + \
	  RBD_BIOS_ALIGN ( sizeof ( struct ibft_initiator ) ) + \
	  RBD_BIOS_IBFT_PAIRS ( targets ) * \
		( RBD_BIOS_ALIGN ( sizeof ( struct ibft_nic ) ) + \
		  RBD_BIOS_ALIGN ( sizeof ( struct ibft_target ) ) ) )

/** The strings of the reference iBFT (bytes with their NULs): an initiator and a target IQN of the longest length RFC 3720 allows (223 characters), a host name of up to 63 characters */
#define RBD_BIOS_IBFT_STRINGS ( 223 + 1 + 223 + 1 + 63 + 1 )

/** Length of the reference iBFT: one target, the strings above, no CHAP names or secrets (the largest iBFT this area is sized for) */
#define RBD_BIOS_IBFT_REFERENCE ( RBD_BIOS_IBFT_FIXED ( 1 ) + RBD_BIOS_IBFT_STRINGS )

/** What the area has to hold: one handoff table of the design maximum next to the reference iBFT, each at its aligned length (2,048 bytes with the pinned iPXE: the area is exactly this big) */
#define RBD_BIOS_XBFT_NEED \
	( RBD_BIOS_ALIGN ( ( size_t ) WR_HANDOFF_MAX_TABLE ) + \
	  RBD_BIOS_ALIGN ( ( size_t ) RBD_BIOS_IBFT_REFERENCE ) )

/** The boot firmware table area that patch 0002 and 0004 give iPXE (XBFTAB_SIZE) */
#define RBD_BIOS_XBFT_SIZE 2048

/** Longest table the scan accepts (an iBFT with many targets stays far below it) */
#define RBD_BIOS_SCAN_TABLE_MAX 4096U

/** The kinds of table the scan reports */
enum rbd_bios_kind {
	RBD_BIOS_NONE = 0,
	/** iSCSI boot firmware table */
	RBD_BIOS_IBFT,
	/** AoE boot firmware table */
	RBD_BIOS_ABFT,
	/** SRP boot firmware table */
	RBD_BIOS_SBFT,
	/** The handoff table of this driver */
	RBD_BIOS_RBFT,
};

/** A table found by the scan */
struct rbd_bios_hit {
	/** What it is */
	enum rbd_bios_kind kind;
	/** Offset of the table from the start of the scanned memory (16-byte aligned) */
	size_t offset;
	/** Length of the table (the length field of its header) */
	size_t len;
};

/* rbd_bios.c: pure functions (every platform) */
extern size_t rbd_bios_xbft_entry ( size_t len );
extern int rbd_bios_xbft_fit ( const size_t *lens, unsigned int count,
			       size_t area, size_t *used );
extern unsigned int rbd_bios_scan ( const void *mem, size_t len,
				    struct rbd_bios_hit *hits,
				    unsigned int max, unsigned int *refused );
extern int rbd_bios_in_window ( unsigned long phys, size_t len );
extern const char * rbd_bios_kind_name ( enum rbd_bios_kind kind );
extern const char * rbd_bios_exit_warning ( int booting, const char *driver,
					    unsigned int drives );

#endif /* _RBD_BIOS_H */
