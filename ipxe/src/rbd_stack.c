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

/* Secure Boot: FORBIDDEN, like every file of the driver (docs/design/ipxe-driver.md, section 13). This file only measures
 * the stack and prints counters (diagnostics), and is logically harmless, but it is only ever linked with the rest of the
 * driver, and the Secure Boot check looks at the whole binary: a file that "looks harmless" does not change that.
 */
FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

/** @file
 *
 * RBD (Ceph) SAN protocol: the stack watermark and the "rbd-info" command
 *
 * The BIOS builds run on iPXE's own 4,096-byte stack (8,192 on x86_64), and the core alone needs up to 2,632 bytes of it
 * (docs/design/ipxe-driver.md, section 5.2). Whether the glue's frames on top of iPXE's own leave enough is a measurement, not
 * a guess, and this file makes it part of every BIOS test run: the session paints the free part of the stack with a pattern when
 * a session is opened and the high-water mark is the part of it that no longer holds the pattern. It is printed when the session
 * is destroyed, by "rbd-info", and whenever it has grown by RBD_STACK_REPORT_STEP bytes since the last time (the INT 13h path
 * keeps running after iPXE's shell is gone, so a mark that is only printed at close would never be seen on a booted machine).
 *
 * The watermark is a build option, off in release builds: make EXTRA_CFLAGS=-DRBD_STACK_MONITOR. It exists only on BIOS
 * platforms (iPXE's internal stack, the linker symbols _stack and _estack); an EFI build runs on the firmware's stack, which
 * is hundreds of kilobytes. Everywhere else the entry points are empty inline functions (rbd_session.h).
 *
 * The two functions that do the pattern work, rbd_stack_fill() and rbd_stack_untouched(), take plain memory and are built in
 * every configuration, so that the self-tests exercise them on an ordinary buffer.
 *
 * "rbd-info" prints, for every session, what the core counts (wr_stats, wr_client_osd_stats), what the readahead cache did, and
 * the stack watermark. It prints names and numbers only: never the URI, the monitor addresses, the user or the key. It is meant
 * for the test logs ("rbd-info" at the end of a boot script).
 *
 * This file uses no error number: it is not registered in include/ipxe/errfile.h (patch 0001) and needs no entry there.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ipxe/uaccess.h>
#include <ipxe/command.h>
#include <ipxe/parseopt.h>
#include "rbd_priv.h"
#include "rbd_session.h"

/** A counter as a signed long for iPXE's printf (it has no %u, and prints a long long as a long): saturated, so that it never goes negative */
#define RBD_N( value ) ( ( long ) ( ( ( uint64_t ) ( value ) > 0x7fffffffULL ) ? 0x7fffffffUL : ( unsigned long ) ( value ) ) )

/** Pattern the free stack is painted with (a word that code and data rarely hold) */
#define RBD_STACK_PATTERN 0xa5c35a3cU

/**
 * Paint memory with the stack pattern
 *
 * @v low		Start of the memory (rounded up to a word)
 * @v high		End of the memory (rounded down to a word)
 */
void rbd_stack_fill ( void *low, void *high ) {
	uint32_t *word = ( ( uint32_t * ) ( ( ( unsigned long ) low + 3 ) &
					     ~3UL ) );
	uint32_t *end = ( ( uint32_t * ) ( ( unsigned long ) high & ~3UL ) );

	while ( word < end )
		*(word++) = RBD_STACK_PATTERN;
}

/**
 * Measure how much of painted memory is still untouched
 *
 * @v low		Start of the memory (the end the stack grows towards)
 * @v high		End of the memory
 * @ret len		Bytes from the start that still hold the pattern (a stack that grows down uses the memory from its high end)
 */
size_t rbd_stack_untouched ( const void *low, const void *high ) {
	const uint32_t *start = ( ( const uint32_t * ) ( ( ( unsigned long ) low +
							   3 ) & ~3UL ) );
	const uint32_t *end = ( ( const uint32_t * ) ( ( unsigned long ) high &
						       ~3UL ) );
	const uint32_t *word = start;

	while ( ( word < end ) && ( *word == RBD_STACK_PATTERN ) )
		word++;
	return ( ( size_t ) ( ( const char * ) word - ( const char * ) start ) );
}

#if RBD_CORE_STACK_BYTES

/**
 * Call a function on another stack
 *
 * @v top		Top of the stack to run on (the highest address; the stack grows down from it)
 * @v fn		Function to call, with one argument
 * @v arg		Argument
 *
 * The old stack pointer is kept on the new stack, below nothing else: the function returns to the same place on the new stack, and
 * the pointer is restored from there (the registers that a call preserves are the callee's to preserve). iPXE builds i386 with
 * -mregparm=3 -mrtd: the one argument goes in %eax and nothing is popped. Interrupts are not touched: iPXE runs this code with
 * them off (BIOS) or does not care (the Linux self-test program).
 */
void rbd_call_on_stack ( void *top, void ( * fn ) ( void *arg ), void *arg ) {

	/* The callee is free to change %eax, %ecx and %edx (a call preserves %ebx, %esi, %edi and %ebp): %ecx is therefore an operand that is
	 * read AND written (an input operand is assumed to survive the asm, and a compiler that inlines this function could rely on it), and
	 * %edx is clobbered. %esi and the stack pointer come back unchanged.
	 */
	__asm__ __volatile__ ( "movl %%esp, %%edx\n\t"
			       "movl %%ecx, %%esp\n\t"
			       "pushl %%edx\n\t"
			       "call *%%esi\n\t"
			       "popl %%esp\n\t"
			       : "+a" ( arg ), "+c" ( top )
			       : "S" ( fn )
			       : "edx", "cc", "memory" );
}

#endif /* RBD_CORE_STACK_BYTES */

/**
 * Measure the use of the core's private stack
 *
 * @v session		Session
 * @ret used		Bytes of the stack that the core has used (0 when the platform has no such stack)
 */
unsigned int rbd_core_stack_used ( const struct rbd_session *session ) {

	if ( ! session->core_stack )
		return 0;
	return ( RBD_CORE_STACK_BYTES -
		 rbd_stack_untouched ( session->core_stack,
				       session->core_stack_top ) );
}

#if defined ( RBD_STACK_MONITOR ) && defined ( PLATFORM_pcbios )

/** iPXE's internal stack (arch/x86/core/stack.S) */
extern char _stack[];
extern char _estack[];

/** Margin below the frame that paints (its own frame and what a callee pushes while painting) */
#define RBD_STACK_MARGIN 256

/** End of the painted memory (NULL: not painted yet) */
static char *rbd_stack_painted;

/** Highest use seen before the last repaint (bytes) */
static size_t rbd_stack_peak;

/**
 * Get the current use of the stack
 *
 * @ret used		Bytes used at the deepest point so far
 */
static size_t rbd_stack_used ( void ) {
	size_t total = ( _estack - _stack );
	size_t used = rbd_stack_peak;
	size_t now;

	if ( rbd_stack_painted ) {
		now = ( total - rbd_stack_untouched ( _stack,
						     rbd_stack_painted ) );
		if ( now > used )
			used = now;
	}
	return used;
}

/**
 * Paint the free part of the stack
 *
 * Called at every open of a session, and after every report (the report's own printing goes deep: what it dirtied must not be
 * counted as the driver's). The high-water mark so far is kept across a repaint: a later open starts from a shallower stack, but
 * the deepest point that was seen stays the answer.
 */
void rbd_stack_paint ( void ) {
	char *frame = __builtin_frame_address ( 0 );
	unsigned long pframe = ( ( unsigned long ) virt_to_phys ( frame ) );
	unsigned long plow = ( ( unsigned long ) virt_to_phys ( _stack ) );
	unsigned long phigh = ( ( unsigned long ) virt_to_phys ( _estack ) );
	char *high;

	/* The frame and the linker symbols can be in different address spaces (x86_64 BIOS: the stack pointer is a physical address, the
	 * image's symbols are in the high virtual half): compare physical addresses, and paint through the symbols' own mapping
	 */
	if ( ( pframe <= plow ) || ( pframe > phigh ) ||
	     ( ( pframe - RBD_STACK_MARGIN ) <= plow ) ) {
		printf ( "rbd: stack monitor: the stack is not iPXE's own "
			 "(frame %p, internal stack %p to %p): not painted\n",
			 frame, _stack, _estack );
		return;
	}
	high = ( _stack + ( ( pframe - RBD_STACK_MARGIN ) - plow ) );
	rbd_stack_peak = rbd_stack_used();
	rbd_stack_fill ( _stack, high );
	rbd_stack_painted = high;
	DBGC ( &rbd_stack_peak, "RBD stack %p to %p painted up to %p\n", _stack,
	       _estack, high );
}

/**
 * Get the high-water mark of the stack
 *
 * @v used		Bytes used (set if painted)
 * @v total		Size of the stack
 * @ret painted		The stack has been painted
 */
int rbd_stack_usage ( unsigned int *used, unsigned int *total ) {

	if ( ! rbd_stack_painted )
		return 0;
	*used = rbd_stack_used();
	*total = ( _estack - _stack );
	return 1;
}

/**
 * Print the high-water mark of the stack
 */
void rbd_stack_report ( void ) {
	unsigned int used;
	unsigned int total;

	if ( rbd_stack_usage ( &used, &total ) )
		printf ( "rbd: stack high-water %ld of %ld bytes (%ld left)\n",
			 RBD_N ( used ), RBD_N ( total ),
			 RBD_N ( total - used ) );
}

/**
 * Note the high-water mark: print it when it has grown noticeably
 *
 * @v session		Session
 */
void rbd_stack_note ( struct rbd_session *session ) {
	unsigned int used;
	unsigned int total;
	unsigned int core;

	if ( ! rbd_stack_usage ( &used, &total ) )
		return;
	core = rbd_core_stack_used ( session );
	if ( ( used >= ( session->stack_reported + RBD_STACK_REPORT_STEP ) ) ||
	     ( core >= ( session->core_reported + RBD_STACK_REPORT_STEP ) ) ) {
		session->stack_reported = used;
		session->core_reported = core;
		rbd_stack_report();
		if ( session->core_stack )
			printf ( "rbd: core stack high-water %ld of %d bytes\n",
				 RBD_N ( core ), RBD_CORE_STACK_BYTES );

		/* Printing is deep (iPXE's formatted output and the console drivers): forget what it touched, keep the mark */
		rbd_stack_paint();
	}
}

#endif /* RBD_STACK_MONITOR && PLATFORM_pcbios */

/******************************************************************************
 *
 * Counters and heap, for the test builds (RBD_STACK_MONITOR)
 *
 ******************************************************************************
 */

/** What one session's report reads (static: the command is single threaded, and the BIOS stack is small) */
static struct {
	wr_stats stats;
	wr_osd_stats osd;
	wr_ra_stats ra;
} rbd_info_work;

#ifdef RBD_STACK_MONITOR

/**
 * Probe the heap: the largest block that malloc() gives now, in KiB, to the nearest power of two
 *
 * @ret kib		Largest power-of-two size (KiB) that could be allocated, 0 if not even 4 KiB
 *
 * iPXE keeps its heap's counters private, so this asks: it takes a block and gives it back at once, from 2 MiB down. (A failed
 * attempt makes iPXE discard its caches, which is harmless.) A heap that is full of small I/O buffers answers a few KiB, and
 * that is what a boot that "cannot parse its URI: out of memory" looked like.
 */
static unsigned int rbd_heap_probe ( void ) {
	size_t size;
	void *block;

	for ( size = ( 2048UL * 1024 ) ; size >= 4096 ; size >>= 1 ) {
		block = malloc ( size );
		if ( block ) {
			free ( block );
			return ( size >> 10 );
		}
	}
	return 0;
}

/**
 * Print what the heap looks like
 *
 * @v what		What happened (a static string)
 */
void rbd_heap_note ( const char *what ) {

	printf ( "rbd: heap (%s): a block of %ld KiB can still be allocated\n",
		 what, RBD_N ( rbd_heap_probe() ) );
}

/**
 * Print a line of counters now and then
 *
 * @v session		Session
 *
 * At most every RBD_COUNTERS_INTERVAL_MS, and only when the core has done operations since the last line.
 */
void rbd_counters_note ( struct rbd_session *session ) {
	wr_osd_stats *osd = &rbd_info_work.osd;
	wr_ra_stats *ra = &rbd_info_work.ra;

	if ( ( ! session->client ) || ( session->last_now < session->counters_next ) )
		return;
	session->counters_next = ( session->last_now + RBD_COUNTERS_INTERVAL_MS );
	session->core->osd_stats ( session->client, osd );
	if ( osd->ops_done == session->counters_ops )
		return;
	session->counters_ops = osd->ops_done;
	printf ( "rbd: counters: %ld ops done, %ld resent, %ld failed, %ld resets, %ld reopens, %ld stall closes",
		 RBD_N ( osd->ops_done ), RBD_N ( osd->ops_resent ), RBD_N ( osd->ops_failed ),
		 RBD_N ( osd->n_session_resets ), RBD_N ( session->n_reopens ),
		 RBD_N ( session->n_stall_closes ) );
	if ( session->ra ) {
		wr_ra_get_stats ( session->ra, ra );
		printf ( "; readahead %ld reads, %ld hits, %ld waits, %ld misses",
			 RBD_N ( ra->reads ), RBD_N ( ra->hits ), RBD_N ( ra->waits ),
			 RBD_N ( ra->misses ) );
	}
	printf ( "; heap block %ld KiB\n", RBD_N ( rbd_heap_probe() ) );
}

#endif /* RBD_STACK_MONITOR */

/******************************************************************************
 *
 * The "rbd-info" command
 *
 ******************************************************************************
 */

/** "rbd-info" options */
struct rbd_info_options {};

/** "rbd-info" option list */
static struct option_descriptor rbd_info_opts[] = {};

/** "rbd-info" command descriptor */
static struct command_descriptor rbd_info_cmd =
	COMMAND_DESC ( struct rbd_info_options, rbd_info_opts, 0, 0, NULL );

/** Names of the session states */
static const char * const rbd_info_state[] = {
	[RBD_SESSION_OPENING] = "opening",
	[RBD_SESSION_OPEN] = "open",
	[RBD_SESSION_FAILED] = "failed",
	[RBD_SESSION_DEAD] = "destroyed",
};

/**
 * Print the report of one session
 *
 * @v session		Session
 */
static void rbd_info_session ( struct rbd_session *session ) {
	wr_stats *stats = &rbd_info_work.stats;
	wr_osd_stats *osd = &rbd_info_work.osd;
	wr_ra_stats *ra = &rbd_info_work.ra;

	printf ( "rbd: image %s/%s: %s, %ld device(s), %ld blocks of %d bytes\n",
		 session->id.pool, session->id.image,
		 rbd_info_state[session->state], RBD_N ( session->ndev ),
		 RBD_N ( session->blocks ), RBD_BLKSIZE );
	printf ( "rbd:   session: %ld pumps, %ld cancels (most rounds %ld), "
		 "%ld reopens, %ld stall closes\n", RBD_N ( session->n_pumps ),
		 RBD_N ( session->n_cancels ),
		 RBD_N ( session->n_cancel_rounds_max ),
		 RBD_N ( session->n_reopens ), RBD_N ( session->n_stall_closes ) );
	if ( session->core_stack )
		printf ( "rbd:   core stack: %ld of %d bytes used\n",
			 RBD_N ( rbd_core_stack_used ( session ) ),
			 RBD_CORE_STACK_BYTES );
	if ( ! session->client )
		return;
	session->core->stats ( session->client, stats );
	session->core->osd_stats ( session->client, osd );
	printf ( "rbd:   core: connections %ld (most %ld), arena %ld bytes, "
		 "bulk %ld bytes; modes: %ld crc, %ld secure, %ld secure "
		 "failures\n", RBD_N ( stats->conns_in_use ),
		 RBD_N ( stats->conns_hiwater ), RBD_N ( stats->arena_used ),
		 RBD_N ( stats->bulk_used ), RBD_N ( stats->conns_crc ),
		 RBD_N ( stats->conns_secure ), RBD_N ( stats->sec_failures ) );
	printf ( "rbd:   osd: %ld ops done, %ld resent, %ld failed; in flight "
		 "%ld (most %ld), requests %ld (most %ld); %ld session resets, "
		 "zombies %ld of %ld bytes\n", RBD_N ( osd->ops_done ),
		 RBD_N ( osd->ops_resent ), RBD_N ( osd->ops_failed ),
		 RBD_N ( osd->ops_inflight ), RBD_N ( osd->ops_hiwater ),
		 RBD_N ( osd->reqs_inflight ), RBD_N ( osd->reqs_hiwater ),
		 RBD_N ( osd->n_session_resets ),
		 RBD_N ( osd->zombie_bytes_used ),
		 RBD_N ( osd->zombie_bytes_max ) );
	if ( session->ra ) {
		wr_ra_get_stats ( session->ra, ra );
		printf ( "rbd:   readahead: %ld reads: %ld hits, %ld waits, %ld "
			 "misses; %ld windows, %ld prefetches (%ld landed, %ld "
			 "failed, %ld dropped), %ld lines valid\n",
			 RBD_N ( ra->reads ), RBD_N ( ra->hits ),
			 RBD_N ( ra->waits ), RBD_N ( ra->misses ),
			 RBD_N ( ra->windows ), RBD_N ( ra->pf_issued ),
			 RBD_N ( ra->pf_landed ), RBD_N ( ra->pf_failed ),
			 RBD_N ( ra->pf_dropped ), RBD_N ( ra->valid_lines ) );
	} else {
		printf ( "rbd:   readahead: off\n" );
	}
}

/**
 * The "rbd-info" command
 *
 * @v argc		Argument count
 * @v argv		Argument list
 * @ret rc		Return status code
 */
static int rbd_info_exec ( int argc, char **argv ) {
	struct rbd_info_options opts;
	struct rbd_session *session;
	unsigned int used;
	unsigned int total;
	unsigned int count = 0;
	int rc;

	/* Parse options */
	if ( ( rc = parse_options ( argc, argv, &rbd_info_cmd, &opts ) ) != 0 )
		return rc;

	list_for_each_entry ( session, &rbd_sessions, list ) {
		rbd_info_session ( session );
		count++;
	}
	if ( ! count )
		printf ( "rbd: no session\n" );
	if ( rbd_stack_usage ( &used, &total ) )
		printf ( "rbd: stack high-water %ld of %ld bytes (%ld left)\n",
			 RBD_N ( used ), RBD_N ( total ),
			 RBD_N ( total - used ) );
	return 0;
}

/** The "rbd-info" command */
struct command rbd_info_command __command ( rbd_info ) = {
	.name = "rbd-info",
	.exec = rbd_info_exec,
};
