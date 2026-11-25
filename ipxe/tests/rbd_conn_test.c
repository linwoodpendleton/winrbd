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
 * RBD (Ceph) SAN protocol: self-tests of the pump host (ipxe/src/rbd_conn.c)
 *
 * Built into bin-x86_64-linux/tests.linux (and the 32-bit program) by "ipxe/tools/build.sh test" (see
 * ipxe/tests/README.md). No network, no QEMU, no cluster, no waiting on the clock.
 *
 * The connection table is driven through its public entry points against three fakes, which are the seams of
 * struct rbd_conn_ops:
 *
 *   - a fake socket: an object on the far end of the table's struct interface. It answers xfer_window with a window
 *     the test sets, takes what the table delivers (and, like iPXE's TCP, drops its window to zero after each packet
 *     unless the test says otherwise), can refuse to allocate, can fail or close from inside a delivery, and can close
 *     itself, exactly the calls iPXE's TCP makes on its consumer;
 *   - a fake core: the connection API of wr_client.h with a receive room, a transmit queue and an action queue that
 *     the test controls, so that a core window of three bytes or a gather list of seven one-byte pieces is as easy to
 *     produce as a large one;
 *   - a fake random source.
 *
 * What is checked:
 *
 *   - time: ticks to milliseconds (exact values, the period of 128 ticks = 125 ms, the extremes of 64 bits, no
 *     overflow), milliseconds to ticks (rounding up, never zero, the clamp), the 64-bit tick count across the wrap of
 *     a 32-bit counter and across a clock that steps back, the wall clock (platform reading, extrapolation, no clock,
 *     absurd readings, saturation near the end of the range), rbd_conn_now();
 *   - random: a failing source is WR_E_HOST_RANDOM (through the host table too), the DRBG answers on the platform;
 *   - connect: IPv4 and IPv6 addresses, the connect timer (armed with the action's timeout, none for zero, stopped
 *     when established, a stale expiry ignored), established only when the window is non-zero, refusal at open, a bad
 *     address, a close from the socket while connecting, a timeout;
 *   - transmit: partial acceptance (a window smaller than the pending bytes, across gather pieces), the window at
 *     zero, the burst limit, an allocation failure, a send that fails, a socket that closes inside the send, a
 *     transmit list that is larger than the window;
 *   - receive: the window the socket reports (the core's room less the backlog), data the core cannot take parked in
 *     order and handed over later, data behind a backlog never overtaking it, a backlog that would exceed what was
 *     announced closes the connection, empty buffers, data that arrives before the "established" event;
 *   - close from either side, stale and out-of-range ids, a new connection in a slot whose old socket is still there,
 *     all eight slots, shutdown with live sockets, backlogs and timers (and no heap left over in any of it);
 *   - the real core: a real wr_client is driven through the table with a fake socket. The first bytes it sends are the
 *     msgr2 banner; they are the same whatever window the socket gives (the whole flight in one call, or seven bytes
 *     per ACK), and a peer that sends garbage ends with a close the core asked for. A peer with a proper banner,
 *     delivered whole, three bytes or one byte at a time (never more than the window the table reports), is accepted:
 *     the client carries on with its HELLO frame, and the bytes it sends do not depend on how the peer's came;
 *   - references (the owner is a reference counted object, as the session is): every path that ends a connection gives
 *     back the references of its socket and its timer; an owner that dropped its own reference is freed at the end of
 *     rbd_conn_shutdown(), not in the middle of it;
 *   - the table with no core (never attached, shut down) opens no socket; a core that miscounts (more gather elements
 *     than it was given room for, more bytes taken than offered) cannot make the table read or free past what it has; a
 *     status of INT_MIN; a slot used again starts with nothing announced; a transport that is ready when it is opened;
 *     a socket that closes while its window is asked; the limit of one drain; the core is never called for an id it
 *     does not know (a connection already reported closed, or never opened).
 *
 * Secure Boot: FILE_SECBOOT ( FORBIDDEN ), like every file of the driver (docs/design/ipxe-driver.md, section 13): a test
 * object is only ever linked into a self-test program.
 *
 * Nothing secret is used: the cephx key of the real-core test is made up (a counting pattern).
 */

/* iPXE's error macros (-EINVAL ...) carry the identifier of the file that uses them (ipxe/tests/README.md): this one is local to
 * the test program. Error codes are compared by rbd_conn_error_kind(), never by their file part.
 */
#include <ipxe/errfile.h>
#define ERRFILE_rbd_conn_test ( ERRFILE_OTHER | 0x007b0000 )

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <byteswap.h>
#include <ipxe/malloc.h>
#include <ipxe/umalloc.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/interface.h>
#include <ipxe/socket.h>
#include <ipxe/in.h>
#include <ipxe/tcpip.h>
#include <ipxe/retry.h>
#include <ipxe/time.h>
#include <ipxe/rbg.h>
#include <ipxe/test.h>
#include "winrbd/rbd_conn.h"

/** The largest unsigned long */
#define ULONG_ALL ( ~0UL )

/** Most probe blocks taken when measuring the free heap (a heap that grows on demand would otherwise never end) */
#define HEAP_PROBE_MAX 600000

/**
 * Measure the free heap
 *
 * @ret blocks		Number of small blocks that fit in the free heap
 *
 * iPXE's heap is private to its allocator and keeps no counter a test can read, so the free space is measured by taking
 * small blocks until there are none (and giving them back). A test that leaves a buffer behind (an I/O buffer in a
 * backlog that was not freed, a half-built packet) leaves fewer blocks for the next measurement. One block is 16 bytes of
 * payload and the allocator's own header, so an I/O buffer is several blocks.
 */
static size_t heap_probe ( void ) {
	void *head = NULL;
	void *block;
	size_t blocks = 0;

	while ( blocks < HEAP_PROBE_MAX ) {
		block = malloc ( 16 );
		if ( ! block )
			break;
		*( ( void ** ) block ) = head;
		head = block;
		blocks++;
	}
	while ( head ) {
		block = head;
		head = *( ( void ** ) block );
		free ( block );
	}
	return blocks;
}

/** The part of an error code that says which error it is: the POSIX code (bits 30-24) and the platform code (bits 7-0) */
#define RBD_ERROR_KIND( rc ) ( ( unsigned int ) ( -( rc ) ) & 0x7f0000ffU )

/**
 * Get the kind of an error, from either sign convention
 *
 * @v rc		Return status code, negative (iPXE) or positive (what the table hands the core)
 * @ret kind		POSIX and platform part of the code
 */
static unsigned int rbd_conn_error_kind ( int rc ) {

	return RBD_ERROR_KIND ( ( rc > 0 ) ? -rc : rc );
}

/****************************************************************************
 *
 * Time
 *
 ****************************************************************************
 */

/** A tick count and the milliseconds it is worth (worked out by hand: ticks * 125 / 128, rounded down) */
static const struct {
	uint64_t ticks;
	uint64_t ms;
} rbd_conn_tick_cases[] = {
	{ 0, 0 }, { 1, 0 }, { 2, 1 }, { 127, 124 }, { 128, 125 }, { 129, 125 },
	{ 255, 249 }, { 256, 250 }, { 1023, 999 }, { 1024, 1000 }, { 1025, 1000 },
	{ 2048, 2000 }, { 1000000, 976562 }, { 0x7fffffffULL, 2097151999ULL },
	{ 0xffffffffULL, 4194303999ULL }, { 0x100000000ULL, 4194304000ULL },
	{ 0x8000000000000000ULL, 9007199254740992000ULL },
	{ 0xffffffffffffffffULL, 18014398509481983999ULL },
};

/** A duration and the ticks that cover it (ceil ( ms * 128 / 125 ), at least one) */
static const struct {
	uint32_t ms;
	unsigned long ticks;
} rbd_conn_ms_cases[] = {
	{ 0, 1 }, { 1, 2 }, { 7, 8 }, { 124, 127 }, { 125, 128 }, { 126, 130 },
	{ 1000, 1024 }, { 5000, 5120 }, { 20000, 20480 }, { 86400000UL, 88473600UL },
	/* clamped to a day */
	{ 86400001UL, 88473600UL }, { 0xffffffffUL, 88473600UL },
};

/**
 * Copy address bytes (not memcpy(): see rbd_conn_copy_ip() in rbd_conn.c; the core's address bytes are misaligned for the
 * word-sized loads of iPXE's constant-length memcpy(), and the UBSan run of the self-tests would say so)
 *
 * @v dest		Destination
 * @v src		Source
 * @v len		Length
 */
static void rbd_conn_test_copy ( void *dest, const void *src, size_t len ) {
	uint8_t *out = dest;
	const uint8_t *in = src;
	size_t i;

	for ( i = 0 ; i < len ; i++ )
		out[i] = in[i];
}

/**
 * Check the conversions between ticks and milliseconds
 *
 */
static void rbd_conn_convert_ok ( void ) {
	uint64_t prev_ms = 0;
	unsigned long prev_ticks = 0;
	unsigned long ticks;
	uint64_t ms;
	uint64_t t;
	unsigned int i;
	uint32_t n;

	/* Exact values */
	for ( i = 0 ; i < ( sizeof ( rbd_conn_tick_cases ) /
			    sizeof ( rbd_conn_tick_cases[0] ) ) ; i++ ) {
		ok ( rbd_conn_ticks_to_ms ( rbd_conn_tick_cases[i].ticks ) ==
		     rbd_conn_tick_cases[i].ms );
	}
	for ( i = 0 ; i < ( sizeof ( rbd_conn_ms_cases ) /
			    sizeof ( rbd_conn_ms_cases[0] ) ) ; i++ ) {
		ok ( rbd_conn_ms_to_ticks ( rbd_conn_ms_cases[i].ms ) ==
		     rbd_conn_ms_cases[i].ticks );
	}

	/* One second is 1024 ticks, whatever the starting point: 128 ticks are exactly 125 ms, with no rounding drift (the
	 * conversion is exact, so the period is exact for every start, also near the top of the range, where a naive
	 * ticks * 125 would have overflowed)
	 */
	for ( i = 0 ; i < 200 ; i++ ) {
		t = ( ( uint64_t ) i * 0x0123456789abcdefULL );
		if ( t > ( 0xffffffffffffffffULL - 128 ) )
			t >>= 1;
		ok ( rbd_conn_ticks_to_ms ( t + 128 ) ==
		     ( rbd_conn_ticks_to_ms ( t ) + 125 ) );
		ok ( rbd_conn_ticks_to_ms ( t ) <= t );
	}
	for ( t = ( 0xffffffffffffffffULL - 600 ) ;
	      t < ( 0xffffffffffffffffULL - 128 ) ; t += 7 ) {
		ok ( rbd_conn_ticks_to_ms ( t + 128 ) ==
		     ( rbd_conn_ticks_to_ms ( t ) + 125 ) );
	}

	/* Monotonic, one step at a time, across a stretch that crosses 2^32 */
	prev_ms = rbd_conn_ticks_to_ms ( 0xffffff00ULL );
	for ( t = ( 0xffffff01ULL ) ; t < ( 0x100000200ULL ) ; t++ ) {
		ms = rbd_conn_ticks_to_ms ( t );
		ok ( ms >= prev_ms );
		ok ( ( ms - prev_ms ) <= 1 );
		prev_ms = ms;
	}

	/* A duration that is converted to ticks and back is the same duration (ceil then floor), never shorter than asked */
	for ( n = 1 ; n <= 3000 ; n++ ) {
		ticks = rbd_conn_ms_to_ticks ( n );
		ok ( ticks >= prev_ticks );
		ok ( rbd_conn_ticks_to_ms ( ticks ) == n );
		prev_ticks = ticks;
	}
	ok ( rbd_conn_ms_to_ticks ( 0 ) >= 1 );
}

/**
 * Check the 64-bit tick count
 *
 */
static void rbd_conn_clock_ok ( void ) {
	struct rbd_clock clock;
	uint64_t base;
	uint64_t ticks;
	unsigned long raw;
	unsigned int i;

	/* The first reading starts the count a little after zero, and the same reading again adds nothing */
	memset ( &clock, 0, sizeof ( clock ) );
	base = rbd_clock_advance ( &clock, 5000 );
	ok ( base == ( 5000 + RBD_CLOCK_EPOCH_TICKS ) );
	ok ( rbd_clock_advance ( &clock, 5000 ) == base );
	ok ( rbd_clock_advance ( &clock, 5010 ) == ( base + 10 ) );

	/* A reading behind the last one counts as no time, and counting goes on from the new reading */
	ok ( rbd_clock_advance ( &clock, 5000 ) == ( base + 10 ) );
	ok ( rbd_clock_advance ( &clock, 5004 ) == ( base + 14 ) );
	ok ( rbd_clock_advance ( &clock, 0 ) == ( base + 14 ) );
	ok ( rbd_clock_advance ( &clock, 1 ) == ( base + 15 ) );

	/* The counter wraps (32 bits on i386, 64 elsewhere: the width of unsigned long) */
	memset ( &clock, 0, sizeof ( clock ) );
	base = rbd_clock_advance ( &clock, ( ULONG_ALL - 4 ) );
	ok ( rbd_clock_advance ( &clock, ULONG_ALL ) == ( base + 4 ) );
	ok ( rbd_clock_advance ( &clock, 3 ) == ( base + 8 ) );
	ok ( rbd_clock_advance ( &clock, 4 ) == ( base + 9 ) );

	/* A jump of more than half the range is a step back, not a long time */
	memset ( &clock, 0, sizeof ( clock ) );
	base = rbd_clock_advance ( &clock, 100 );
	raw = ( 100 + ( ULONG_ALL / 2 ) + 2 );
	ok ( rbd_clock_advance ( &clock, raw ) == base );
	/* ... and the largest jump that is a forward one is counted in full */
	memset ( &clock, 0, sizeof ( clock ) );
	base = rbd_clock_advance ( &clock, 100 );
	raw = ( 100 + ( ULONG_ALL / 2 ) );
	ok ( rbd_clock_advance ( &clock, raw ) == ( base + ( ULONG_ALL / 2 ) ) );

	/* The count has more than 32 bits: four steps of 0x70000000 ticks, the counter wrapping if it is 32 bits wide */
	memset ( &clock, 0, sizeof ( clock ) );
	raw = 0x1000;
	( void ) rbd_clock_advance ( &clock, raw );
	ticks = 0;
	for ( i = 0 ; i < 4 ; i++ ) {
		raw += 0x70000000UL;
		ticks = rbd_clock_advance ( &clock, raw );
	}
	ok ( ticks == ( 0x1000ULL + RBD_CLOCK_EPOCH_TICKS +
			( 4 * 0x70000000ULL ) ) );
	ok ( ticks > 0xffffffffULL );
	ok ( rbd_conn_ticks_to_ms ( ticks ) > 0xffffffffULL );
}

/**
 * Check the wall clock
 *
 */
static void rbd_conn_wall_ok ( void ) {
	struct rbd_clock clock;

	/* The platform's reading becomes the base; the milliseconds since the Unix epoch are exact */
	memset ( &clock, 0, sizeof ( clock ) );
	ok ( rbd_clock_wall_at ( &clock, 1000, 1700000000 ) == 1700000000000ULL );
	ok ( clock.wall_valid == 1 );
	ok ( clock.wall_next_ms == ( 1000 + RBD_CLOCK_WALL_REFRESH_MS ) );

	/* A later reading in which the platform has no clock (zero) keeps extrapolating from the base: the wall clock does
	 * not fall back to "no clock" once it has been known
	 */
	ok ( rbd_clock_wall_at ( &clock, 5000, 0 ) == 1700000004000ULL );
	ok ( clock.wall_valid == 1 );
	ok ( rbd_clock_wall_at ( &clock, 6000, -1 ) == 1700000005000ULL );

	/* A new reading re-bases (a platform clock that was set) */
	ok ( rbd_clock_wall_at ( &clock, 7000, 1800000000 ) == 1800000000000ULL );
	ok ( rbd_clock_wall_at ( &clock, 8500, 0 ) == 1800000001500ULL );

	/* No clock at all: zero, which is what the core takes as "no wall clock" */
	memset ( &clock, 0, sizeof ( clock ) );
	ok ( rbd_clock_wall_at ( &clock, 1000, 0 ) == 0 );
	ok ( clock.wall_valid == 0 );
	ok ( rbd_clock_wall_at ( &clock, 2000, -5 ) == 0 );
	ok ( clock.wall_valid == 0 );

	/* A reading that cannot be milliseconds in 64 bits is no reading */
	ok ( rbd_clock_wall_at ( &clock, 3000, ( int64_t ) 0x7fffffffffffffffLL ) == 0 );
	ok ( clock.wall_valid == 0 );
	ok ( rbd_clock_wall_at ( &clock, 3000,
				 ( int64_t ) ( 0xffffffffffffffffULL / 1000 ) + 1 ) == 0 );
	ok ( clock.wall_valid == 0 );
	ok ( rbd_clock_wall_at ( &clock, 3000,
				 ( int64_t ) ( 0xffffffffffffffffULL / 1000 ) ) != 0 );

	/* The monotonic clock near the end of its range: the next refresh time saturates instead of wrapping to the past */
	memset ( &clock, 0, sizeof ( clock ) );
	ok ( rbd_clock_wall_at ( &clock, ( 0xffffffffffffffffULL - 10 ), 100 ) ==
	     100000ULL );
	ok ( clock.wall_next_ms == 0xffffffffffffffffULL );
	ok ( clock.wall_next_ms > ( 0xffffffffffffffffULL - 10 ) );
	memset ( &clock, 0, sizeof ( clock ) );
	( void ) rbd_clock_wall_at ( &clock, ( 0xffffffffffffffffULL -
					       RBD_CLOCK_WALL_REFRESH_MS ), 100 );
	ok ( clock.wall_next_ms == 0xffffffffffffffffULL );
	memset ( &clock, 0, sizeof ( clock ) );
	( void ) rbd_clock_wall_at ( &clock, ( 0xffffffffffffffffULL -
					       RBD_CLOCK_WALL_REFRESH_MS - 1 ),
				     100 );
	ok ( clock.wall_next_ms == ( 0xffffffffffffffffULL - 1 ) );
}

/**
 * Check the clock for the core
 *
 */
static void rbd_conn_now_ok ( void ) {
	struct rbd_conn_table *table;
	wr_clock a;
	wr_clock b;
	wr_clock c;
	signed long saved;
	unsigned int i;

	table = zalloc ( sizeof ( *table ) );
	ok ( table != NULL );
	if ( ! table )
		return;
	rbd_conn_init ( table, NULL, NULL, NULL );
	rbd_conn_now ( table, &a );

	/* Never zero (a deadline computed from it is never "none"), never backwards, and the wall clock is either absent or
	 * a plausible time (after 2020)
	 */
	ok ( a.mono_ms >= 1000 );
	ok ( ( a.wall_ms == 0 ) || ( a.wall_ms > 1577836800000ULL ) );
	for ( i = 0 ; i < 50 ; i++ ) {
		rbd_conn_now ( table, &b );
		ok ( b.mono_ms >= a.mono_ms );
		ok ( ( b.wall_ms == 0 ) == ( a.wall_ms == 0 ) );
		a = b;
	}

	/* Between refreshes the wall clock follows the monotonic one, millisecond for millisecond */
	if ( a.wall_ms ) {
		rbd_conn_now ( table, &b );
		ok ( ( b.wall_ms - a.wall_ms ) == ( b.mono_ms - a.mono_ms ) );
	}
	rbd_conn_shutdown ( table );
	free ( table );

	/* The platform's clock is read when it is due, not on every call: the platform clock is moved by 5000 s (iPXE's own
	 * time offset), which the table does not see until the refresh is due, and then does
	 */
	saved = time_offset;
	table = zalloc ( sizeof ( *table ) );
	ok ( table != NULL );
	if ( ! table )
		return;
	rbd_conn_init ( table, NULL, NULL, NULL );
	rbd_conn_now ( table, &a );
	ok ( a.wall_ms > 1577836800000ULL );
	time_offset += 5000;
	rbd_conn_now ( table, &b );
	ok ( ( b.wall_ms - a.wall_ms ) == ( b.mono_ms - a.mono_ms ) );
	table->clock.wall_next_ms = 0;
	rbd_conn_now ( table, &c );
	ok ( c.wall_ms >= ( b.wall_ms + 4999000 ) );
	ok ( c.wall_ms <= ( b.wall_ms + 5001000 + ( c.mono_ms - b.mono_ms ) ) );
	rbd_conn_shutdown ( table );
	free ( table );

	/* A platform with no clock (it says a time before 1970): wall_ms is zero, and a clock that appears is not looked for
	 * on every call either, only when the refresh is due
	 */
	time_offset = saved;
	table = zalloc ( sizeof ( *table ) );
	ok ( table != NULL );
	if ( ! table )
		return;
	rbd_conn_init ( table, NULL, NULL, NULL );
	time_offset = ( - ( signed long ) time_now() - 100000 );
	rbd_conn_now ( table, &a );
	ok ( a.wall_ms == 0 );
	time_offset = saved;
	rbd_conn_now ( table, &b );
	ok ( b.wall_ms == 0 );
	ok ( b.mono_ms >= a.mono_ms );
	table->clock.wall_next_ms = 0;
	rbd_conn_now ( table, &c );
	ok ( c.wall_ms > 1577836800000ULL );
	time_offset = saved;
	rbd_conn_shutdown ( table );
	free ( table );
}

/****************************************************************************
 *
 * Random, log and the host table
 *
 ****************************************************************************
 */

/** A random source that never has bytes */
static int rbd_conn_generate_fail ( void *out __unused, size_t len __unused ) {

	return -ENODEV;
}

/** A random source with a counting pattern (the same sequence every run) */
static uint8_t rbd_conn_pattern;

static int rbd_conn_generate_pattern ( void *out, size_t len ) {
	uint8_t *byte = out;
	size_t i;

	for ( i = 0 ; i < len ; i++ )
		byte[i] = rbd_conn_pattern++;
	return 0;
}

/**
 * Check the random source and the host table
 *
 */
static void rbd_conn_random_ok ( void ) {
	struct rbd_conn_table *table;
	struct rbd_conn_ops ops;
	wr_host_ops host;
	uint8_t buf[2600];
	uint8_t buf2[2600];
	unsigned int zeros;
	unsigned int same;
	size_t i;

	table = zalloc ( sizeof ( *table ) );
	ok ( table != NULL );
	if ( ! table )
		return;
	rbd_conn_init ( table, NULL, NULL, NULL );

	/* The default source is what iPXE has: the DRBG, in chunks of any size */
	ok ( table->ops == &rbd_conn_default_ops );
	ok ( rbd_conn_random ( NULL, buf, 0 ) == WR_OK );
	ok ( rbd_conn_random ( NULL, buf, sizeof ( buf ) ) == WR_OK );
	ok ( rbd_conn_random ( table, buf2, sizeof ( buf2 ) ) == WR_OK );
	zeros = 0;
	same = 0;
	for ( i = 0 ; i < sizeof ( buf ) ; i++ ) {
		if ( buf[i] == 0 )
			zeros++;
		if ( buf[i] == buf2[i] )
			same++;
	}
	/* 2600 random bytes: some zeros, but not mostly zeros (about 10 expected); two draws are not the same bytes (about 10
	 * of 2600 positions agree by chance)
	 */
	ok ( zeros < 100 );
	ok ( same < 100 );
	ok ( memcmp ( buf + 1500, buf2 + 1500, 1000 ) != 0 );

	/* The real DRBG that is not instantiated (iPXE could not seed it) gives the core an error, and no byte of the buffer is
	 * made up: there is no fallback in the table either. (The generator is iPXE's own; its state is put back.)
	 */
	{
		struct random_bit_generator saved = rbg;

		rbg.started = 1;
		rbg.state.valid = 0;
		memset ( buf, 0x55, sizeof ( buf ) );
		ok ( rbd_conn_random ( NULL, buf, 32 ) == WR_E_HOST_RANDOM );
		ok ( rbd_conn_random ( table, buf, sizeof ( buf ) ) == WR_E_HOST_RANDOM );
		for ( i = 0 ; i < sizeof ( buf ) ; i++ ) {
			if ( buf[i] != 0x55 )
				break;
		}
		ok ( i == sizeof ( buf ) );
		rbg = saved;
		ok ( rbd_conn_random ( table, buf, 32 ) == WR_OK );
	}

	/* A source with no bytes is an error the core understands, and never a fallback */
	ops = rbd_conn_default_ops;
	ops.generate = rbd_conn_generate_fail;
	table->ops = &ops;
	memset ( buf, 0x55, sizeof ( buf ) );
	ok ( rbd_conn_random ( table, buf, 32 ) == WR_E_HOST_RANDOM );
	ok ( rbd_conn_random ( table, buf, sizeof ( buf ) ) == WR_E_HOST_RANDOM );

	/* The host table that goes to wr_client_create(): size, context, the random and log callbacks, no primitive overrides */
	memset ( &host, 0xa5, sizeof ( host ) );
	rbd_conn_host_ops ( table, &host );
	ok ( host.size == sizeof ( host ) );
	ok ( host.ctx == table );
	ok ( host.random == rbd_conn_random );
	ok ( host.log == rbd_conn_log );
	ok ( host.prim == NULL );
	ok ( host.random ( host.ctx, buf, 16 ) == WR_E_HOST_RANDOM );

	/* ... and with a working source it fills the buffer with what the source gave, in order */
	ops.generate = rbd_conn_generate_pattern;
	rbd_conn_pattern = 0;
	ok ( host.random ( host.ctx, buf, 5 ) == WR_OK );
	ok ( buf[0] == 0 );
	ok ( buf[4] == 4 );
	ok ( rbd_conn_pattern == 5 );

	/* The log callback takes anything the core can hand it (it prints only in a build that has debugging on) */
	{
		wr_log_rec rec;

		memset ( &rec, 0, sizeof ( rec ) );
		rbd_conn_log ( table, NULL );
		rbd_conn_log ( table, &rec );
		rec.level = 200;
		rec.msg = "a message";
		rbd_conn_log ( NULL, &rec );
		rec.level = WR_LOG_ERR;
		rec.a0 = rec.a1 = rec.a2 = rec.a3 = 0xffffffffffffffffULL;
		rbd_conn_log ( table, &rec );
	}
	rbd_conn_shutdown ( table );
	free ( table );
}

/****************************************************************************
 *
 * Gather lists
 *
 ****************************************************************************
 */

/**
 * Check the transmit helpers
 *
 */
static void rbd_conn_gather_ok ( void ) {
	static const uint8_t a[] = { 1, 2, 3 };
	static const uint8_t b[] = { 4 };
	static const uint8_t c[] = { 5, 6, 7, 8, 9 };
	wr_iov iov[3] = { { a, 3 }, { b, 1 }, { c, 5 } };
	wr_iov huge[3];
	uint8_t out[16];

	/* Length, limited */
	ok ( rbd_conn_gather_len ( iov, 3, 100 ) == 9 );
	ok ( rbd_conn_gather_len ( iov, 3, 9 ) == 9 );
	ok ( rbd_conn_gather_len ( iov, 3, 8 ) == 8 );
	ok ( rbd_conn_gather_len ( iov, 3, 4 ) == 4 );
	ok ( rbd_conn_gather_len ( iov, 3, 3 ) == 3 );
	ok ( rbd_conn_gather_len ( iov, 3, 1 ) == 1 );
	ok ( rbd_conn_gather_len ( iov, 3, 0 ) == 0 );
	ok ( rbd_conn_gather_len ( iov, 0, 100 ) == 0 );
	ok ( rbd_conn_gather_len ( iov, 1, 100 ) == 3 );
	ok ( rbd_conn_gather_len ( iov, 2, 100 ) == 4 );

	/* Lengths that would overflow a sum never do */
	huge[0].base = a;
	huge[0].len = ( ( size_t ) -1 );
	huge[1].base = b;
	huge[1].len = ( ( size_t ) -1 );
	huge[2].base = c;
	huge[2].len = 5;
	ok ( rbd_conn_gather_len ( huge, 3, 1460 ) == 1460 );
	ok ( rbd_conn_gather_len ( huge, 3, ( ( size_t ) -1 ) ) == ( ( size_t ) -1 ) );
	huge[0].len = ( ( ( size_t ) -1 ) - 2 );
	huge[1].len = 1;
	ok ( rbd_conn_gather_len ( huge, 2, ( ( size_t ) -1 ) ) ==
	     ( ( ( size_t ) -1 ) - 1 ) );
	huge[1].len = 2;
	ok ( rbd_conn_gather_len ( huge, 2, ( ( size_t ) -1 ) ) == ( ( size_t ) -1 ) );
	/* a sum that would wrap past zero to a small number (a count of 5 after ( 2^N - 3 )) is not small */
	huge[1].len = 5;
	ok ( rbd_conn_gather_len ( huge, 2, ( ( size_t ) -1 ) ) == ( ( size_t ) -1 ) );
	huge[1].len = 3;
	ok ( rbd_conn_gather_len ( huge, 2, ( ( size_t ) -1 ) ) == ( ( size_t ) -1 ) );

	/* Copy across the pieces, exactly the length asked for */
	memset ( out, 0xee, sizeof ( out ) );
	rbd_conn_gather_copy ( out, iov, 3, 9 );
	ok ( memcmp ( out, "\x01\x02\x03\x04\x05\x06\x07\x08\x09", 9 ) == 0 );
	ok ( out[9] == 0xee );
	memset ( out, 0xee, sizeof ( out ) );
	rbd_conn_gather_copy ( out, iov, 3, 5 );
	ok ( memcmp ( out, "\x01\x02\x03\x04\x05", 5 ) == 0 );
	ok ( out[5] == 0xee );
	memset ( out, 0xee, sizeof ( out ) );
	rbd_conn_gather_copy ( out, iov, 3, 3 );
	ok ( memcmp ( out, "\x01\x02\x03", 3 ) == 0 );
	ok ( out[3] == 0xee );
	memset ( out, 0xee, sizeof ( out ) );
	rbd_conn_gather_copy ( out, iov, 3, 0 );
	ok ( out[0] == 0xee );
	/* ... and not past the pieces that are there, if asked for more */
	memset ( out, 0xee, sizeof ( out ) );
	rbd_conn_gather_copy ( out, iov, 2, 9 );
	ok ( memcmp ( out, "\x01\x02\x03\x04", 4 ) == 0 );
	ok ( out[4] == 0xee );
}

/****************************************************************************
 *
 * The fake core
 *
 ****************************************************************************
 */

/** Slots of the fake core (the table's) */
#define FC_CONNS RBD_CONN_SLOTS

/** Bytes a fake keeps */
#define FAKE_BUF 8192

/** Entries in the fake core's logs */
#define FC_LOG 64

/** Actions the fake core can have queued (more than RBD_CONN_ACTION_MAX, so that the limit of one drain can be seen) */
#define FC_ACTIONS 128

/** A connection of the fake core */
struct fake_conn {
	/** The id the core gave it (0: no such connection, as after wr_conn_closed) */
	wr_conn_id id;
	/** Room for received bytes (what wr_conn_rx_window reports) */
	size_t rx_room;
	/** Bytes taken so far */
	uint8_t rx[FAKE_BUF];
	size_t rx_len;
	/** Pending output */
	uint8_t tx[FAKE_BUF];
	size_t tx_len;
	size_t tx_pos;
	/** Size of the pieces the gather list is cut into */
	size_t tx_piece;
	/** Number of wr_conn_tx_consume calls */
	unsigned int tx_consumes;
};

/** The fake core */
struct fake_core {
	/** Actions the test queued for the table */
	wr_action actions[FC_ACTIONS];
	unsigned int act_head;
	unsigned int act_tail;
	/** Connections */
	struct fake_conn conn[FC_CONNS];
	/** wr_conn_connected calls */
	wr_conn_id connected[FC_LOG];
	unsigned int connected_n;
	/** wr_conn_closed calls */
	wr_conn_id closed_id[FC_LOG];
	int closed_errno[FC_LOG];
	unsigned int closed_n;
	/** Calls of wr_conn_rx_window */
	unsigned int window_calls;
	/** Calls of rx_window, rx_push, tx_peek and tx_consume for an id the core does not know (a connection that is gone: the
	 * table must not use an id after it told the core the connection was closed, or before the core asked for it)
	 */
	unsigned int stale_calls;
	/** Calls of the table's wake function */
	unsigned int wakes;
};

/** The fake core of the running test (the tests run one after the other) */
static struct fake_core *fc;

/**
 * Find a connection of the fake core by id
 *
 * @v id		Connection id
 * @ret conn		Connection, or NULL for an id the core does not know (stale, out of range)
 */
static struct fake_conn * fc_conn ( wr_conn_id id ) {
	unsigned int index = ( id & 0xffff );

	if ( ( index == 0 ) || ( index > FC_CONNS ) )
		return NULL;
	if ( fc->conn[ index - 1 ].id != id )
		return NULL;
	return &fc->conn[ index - 1 ];
}

/** Make a connection id */
static wr_conn_id fc_id ( unsigned int slot, unsigned int generation ) {

	return ( ( generation << 16 ) | ( slot + 1 ) );
}

/** The fake core's next_action */
static int fc_next_action ( wr_client *c __unused, wr_action *out ) {

	if ( fc->act_head == fc->act_tail )
		return 0;
	*out = fc->actions[ fc->act_head++ % FC_ACTIONS ];
	return 1;
}

/** The fake core's connected */
static void fc_connected ( wr_client *c __unused, wr_conn_id id ) {

	if ( fc->connected_n < FC_LOG )
		fc->connected[ fc->connected_n ] = id;
	fc->connected_n++;
}

/** The fake core's closed: the connection is gone from the core, a stale id is ignored (but logged) */
static void fc_closed ( wr_client *c __unused, wr_conn_id id, int host_errno ) {
	struct fake_conn *conn = fc_conn ( id );

	if ( fc->closed_n < FC_LOG ) {
		fc->closed_id[ fc->closed_n ] = id;
		fc->closed_errno[ fc->closed_n ] = host_errno;
	}
	fc->closed_n++;
	if ( conn )
		conn->id = 0;
}

/** The fake core's rx_window */
static size_t fc_rx_window ( wr_client *c __unused, wr_conn_id id,
			     uint8_t **ptr ) {
	struct fake_conn *conn = fc_conn ( id );

	if ( ptr )
		*ptr = NULL;
	fc->window_calls++;
	if ( ! conn )
		fc->stale_calls++;
	return ( conn ? conn->rx_room : 0 );
}

/** The fake core's rx_push */
static size_t fc_rx_push ( wr_client *c __unused, wr_conn_id id,
			   const uint8_t *data, size_t n ) {
	struct fake_conn *conn = fc_conn ( id );
	size_t len;

	if ( ! conn ) {
		fc->stale_calls++;
		return 0;
	}
	len = ( ( n < conn->rx_room ) ? n : conn->rx_room );
	if ( ( conn->rx_len + len ) > sizeof ( conn->rx ) )
		len = ( sizeof ( conn->rx ) - conn->rx_len );
	memcpy ( ( conn->rx + conn->rx_len ), data, len );
	conn->rx_len += len;
	conn->rx_room -= len;
	return len;
}

/** The fake core's tx_peek: the pending bytes, in pieces of tx_piece */
static size_t fc_tx_peek ( wr_client *c __unused, wr_conn_id id, wr_iov *iov,
			   size_t max_iov ) {
	struct fake_conn *conn = fc_conn ( id );
	size_t pos;
	size_t piece;
	size_t count = 0;

	if ( ! conn ) {
		fc->stale_calls++;
		return 0;
	}
	pos = conn->tx_pos;
	while ( ( count < max_iov ) && ( pos < conn->tx_len ) ) {
		piece = ( conn->tx_len - pos );
		if ( piece > conn->tx_piece )
			piece = conn->tx_piece;
		iov[count].base = ( conn->tx + pos );
		iov[count].len = piece;
		pos += piece;
		count++;
	}
	return count;
}

/** The fake core's tx_consume */
static void fc_tx_consume ( wr_client *c __unused, wr_conn_id id, size_t n ) {
	struct fake_conn *conn = fc_conn ( id );

	if ( ! conn ) {
		fc->stale_calls++;
		return;
	}
	conn->tx_pos += n;
	if ( conn->tx_pos > conn->tx_len )
		conn->tx_pos = conn->tx_len;
	conn->tx_consumes++;
}

/** Queue an action for the table */
static void fc_push ( const wr_action *action ) {

	fc->actions[ fc->act_tail++ % FC_ACTIONS ] = *action;
}

/**
 * Queue a CONNECT action for an IPv4 address
 *
 * @v id		Connection id (the fake core starts to know it)
 * @v a			Address, four bytes
 * @v port		Port
 * @v timeout_ms	Connect timeout
 */
static void fc_push_connect4 ( wr_conn_id id, const uint8_t a[4], unsigned int port,
			       uint32_t timeout_ms ) {
	wr_action action;
	struct fake_conn *conn;
	unsigned int index = ( id & 0xffff );

	memset ( &action, 0, sizeof ( action ) );
	action.kind = WR_ACT_CONNECT;
	action.conn = id;
	action.addr.family = WR_AF_IPV4;
	rbd_conn_test_copy ( action.addr.ip, a, 4 );
	action.addr.port = port;
	action.timeout_ms = timeout_ms;
	if ( ( index >= 1 ) && ( index <= FC_CONNS ) ) {
		conn = &fc->conn[ index - 1 ];
		memset ( conn, 0, sizeof ( *conn ) );
		conn->id = id;
		conn->rx_room = 100;
		conn->tx_piece = FAKE_BUF;
	}
	fc_push ( &action );
}

/** Queue a CLOSE action */
static void fc_push_close ( wr_conn_id id ) {
	wr_action action;

	memset ( &action, 0, sizeof ( action ) );
	action.kind = WR_ACT_CLOSE;
	action.conn = id;
	fc_push ( &action );
}

/** The fake core's wake callback */
static void fc_wake ( void *ctx __unused ) {

	fc->wakes++;
}

/****************************************************************************
 *
 * The fake socket
 *
 ****************************************************************************
 */

/** Sockets the fake can open in one test */
#define FAKE_SOCKS 16

/** A fake TCP connection: the far end of one struct rbd_conn's interface */
struct fake_sock {
	/** The interface the table's is plugged into */
	struct interface intf;
	/** The socket has been opened (and not yet closed on our side) */
	int open;
	/** The window xfer_window reports */
	size_t window;
	/** Keep the window after a delivery (a fast transport), instead of dropping it to zero (TCP: one packet in flight) */
	int keep_open;
	/** Bytes delivered to the socket */
	uint8_t sent[FAKE_BUF];
	size_t sent_len;
	/** Number of deliveries */
	unsigned int deliveries;
	/** Sizes of the first deliveries */
	size_t packet[32];
	/** Return value of a delivery (the buffer is taken anyway) */
	int deliver_rc;
	/** Shut down from inside the next delivery, with this status */
	int deliver_closes;
	int deliver_closes_rc;
	/** Refuse to allocate a buffer */
	int no_alloc;
	/** Shut down from inside the next window query (and still report the window: the caller must look again) */
	int window_closes;
	/** The table closed the interface */
	int closed;
	int close_rc;
	/** The address the table opened */
	struct sockaddr_tcpip peer;
};

/** The fake sockets of the running test, in the order they were opened */
static struct fake_sock *socks;
static unsigned int socks_n;

/** Make the next open fail with this status */
static int fake_open_rc;

/** The window a socket has from the moment it is opened (TCP: zero; a transport that is ready at once: not) */
static size_t fake_open_window;

/** The interface descriptor of a fake socket (defined below) */
static struct interface_descriptor fake_desc;

/** The fake socket's window */
static size_t fake_window ( struct fake_sock *sock ) {
	size_t window = sock->window;

	if ( sock->window_closes ) {
		sock->window_closes = 0;
		sock->open = 0;
		intf_shutdown ( &sock->intf, -ECONNRESET );
	}
	return window;
}

/** The fake socket's allocation */
static struct io_buffer * fake_alloc_iob ( struct fake_sock *sock, size_t len ) {

	if ( sock->no_alloc )
		return NULL;
	return alloc_iob ( len );
}

/** The fake socket's delivery */
static int fake_deliver ( struct fake_sock *sock, struct io_buffer *iobuf,
			  struct xfer_metadata *meta __unused ) {
	size_t len = iob_len ( iobuf );

	if ( ( sock->sent_len + len ) <= sizeof ( sock->sent ) )
		memcpy ( ( sock->sent + sock->sent_len ), iobuf->data, len );
	sock->sent_len += len;
	if ( sock->deliveries < ( sizeof ( sock->packet ) /
				  sizeof ( sock->packet[0] ) ) )
		sock->packet[ sock->deliveries ] = len;
	sock->deliveries++;
	free_iob ( iobuf );
	if ( ! sock->keep_open )
		sock->window = 0;
	if ( sock->deliver_closes ) {
		sock->deliver_closes = 0;
		sock->open = 0;
		intf_shutdown ( &sock->intf, sock->deliver_closes_rc );
	}
	return sock->deliver_rc;
}

/** The fake socket's close (the table closed its end) */
static void fake_close ( struct fake_sock *sock, int rc ) {

	sock->closed++;
	sock->close_rc = rc;
	sock->open = 0;
	intf_shutdown ( &sock->intf, rc );
}

/** The fake socket's operations */
static struct interface_operation fake_ops[] = {
	INTF_OP ( xfer_window, struct fake_sock *, fake_window ),
	INTF_OP ( xfer_alloc_iob, struct fake_sock *, fake_alloc_iob ),
	INTF_OP ( xfer_deliver, struct fake_sock *, fake_deliver ),
	INTF_OP ( intf_close, struct fake_sock *, fake_close ),
};

/** The fake socket's interface descriptor */
static struct interface_descriptor fake_desc =
	INTF_DESC ( struct fake_sock, intf, fake_ops );

/** The fake open: plug the next fake socket into the table's interface */
static int fake_open ( struct interface *intf, struct sockaddr *peer ) {
	struct fake_sock *sock;

	if ( fake_open_rc )
		return fake_open_rc;
	if ( socks_n >= FAKE_SOCKS )
		return -ENOBUFS;
	sock = &socks[ socks_n++ ];
	memset ( sock, 0, sizeof ( *sock ) );
	intf_init ( &sock->intf, &fake_desc, NULL );
	memcpy ( &sock->peer, peer, sizeof ( sock->peer ) );
	sock->open = 1;
	sock->window = fake_open_window;
	intf_plug_plug ( intf, &sock->intf );
	return 0;
}

/** The ops of the tests: the fake socket, a counting source, the fake core */
static struct rbd_conn_ops fake_conn_ops = {
	.open = fake_open,
	.generate = rbd_conn_generate_pattern,
	.next_action = fc_next_action,
	.connected = fc_connected,
	.closed = fc_closed,
	.rx_window = fc_rx_window,
	.rx_push = fc_rx_push,
	.tx_peek = fc_tx_peek,
	.tx_consume = fc_tx_consume,
};

/** The pieces of one test: heap measurement, the table, the fakes */
struct fixture {
	/** Unused (the free heap is measured by the test function around the fixture) */
	size_t unused;
	/** The table under test */
	struct rbd_conn_table *table;
};

/**
 * Start a test
 *
 * @v fix		Fixture
 * @ret ok		The fixture is ready
 */
static int fixture_start ( struct fixture *fix ) {

	memset ( fix, 0, sizeof ( *fix ) );
	fc = zalloc ( sizeof ( *fc ) );
	socks = zalloc ( FAKE_SOCKS * sizeof ( socks[0] ) );
	fix->table = zalloc ( sizeof ( *fix->table ) );
	if ( ! ( fc && socks && fix->table ) ) {
		free ( fc );
		free ( socks );
		free ( fix->table );
		fc = NULL;
		socks = NULL;
		ok ( 0 );
		return 0;
	}
	socks_n = 0;
	fake_open_rc = 0;
	fake_open_window = 0;
	rbd_conn_init ( fix->table, NULL, fc_wake, NULL );
	fix->table->ops = &fake_conn_ops;
	rbd_conn_attach ( fix->table, ( wr_client * ) fc );
	return 1;
}

/**
 * Finish a test: the table is shut down, everything is freed
 *
 * @v fix		Fixture
 * @v heap_before	Free heap measured before the fixture (and its allocations) existed
 */
static void fixture_end ( struct fixture *fix, size_t heap_before ) {
	size_t heap_after;
	unsigned int i;

	/* The core was never called for a connection it did not know */
	ok ( fc->stale_calls == 0 );
	rbd_conn_shutdown ( fix->table );
	ok ( rbd_conn_live ( fix->table ) == 0 );
	for ( i = 0 ; i < RBD_CONN_SLOTS ; i++ ) {
		ok ( ! timer_running ( &fix->table->conn[i].timer ) );
		ok ( list_empty ( &fix->table->conn[i].backlog ) );
	}
	free ( fix->table );
	free ( socks );
	free ( fc );
	fc = NULL;
	socks = NULL;
	/* Nothing of the test left in the heap: no buffer of a backlog, no half-sent packet */
	heap_after = heap_probe();
	if ( ( heap_after + 1 ) < heap_before )
		printf ( "rbd_conn_test: free heap measured %zd blocks before the test, %zd after\n",
			 heap_before, heap_after );
	/* (more free blocks than before is not a leak: the free list of an earlier test may have been in pieces that came together) */
	ok ( ( heap_after + 1 ) >= heap_before );
}

/** Get the fake socket of a slot of the table */
static struct fake_sock * sock_of ( struct fixture *fix, unsigned int slot ) {
	struct interface *dest = fix->table->conn[slot].intf.dest;

	if ( ( dest == NULL ) || ( dest->desc != &fake_desc ) )
		return NULL;
	return container_of ( dest, struct fake_sock, intf );
}

/** Test addresses (TEST-NET-1, RFC 5737) */
static const uint8_t addr_a[4] = { 192, 0, 2, 10 };
static const uint8_t addr_b[4] = { 192, 0, 2, 11 };

/**
 * Open a connection in a slot and make it established
 *
 * @v fix		Fixture
 * @v slot		Slot
 * @v generation	Generation of the id
 * @ret sock		The fake socket
 */
static struct fake_sock * connect_up ( struct fixture *fix, unsigned int slot,
				       unsigned int generation ) {
	struct fake_sock *sock;

	fc_push_connect4 ( fc_id ( slot, generation ), addr_a, 3300, 5000 );
	rbd_conn_drain ( fix->table );
	sock = sock_of ( fix, slot );
	ok ( sock != NULL );
	if ( ! sock )
		return NULL;
	sock->window = 1460;
	xfer_window_changed ( &sock->intf );
	ok ( fix->table->conn[slot].state == RBD_CONN_UP );
	return sock;
}

/****************************************************************************
 *
 * Connect, close, timeouts, stale ids
 *
 ****************************************************************************
 */

/**
 * Check opening a connection
 *
 */
static void rbd_conn_connect_ok ( void ) {
	static const uint8_t v6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
					0, 0, 0, 0, 0, 0, 0, 1 };
	struct fixture fix;
	struct rbd_conn *conn;
	struct fake_sock *sock;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	wr_action action;
	size_t heap = heap_probe();
	wr_conn_id id;

	if ( ! fixture_start ( &fix ) )
		return;
	ok ( rbd_conn_live ( fix.table ) == 0 );
	conn = &fix.table->conn[2];

	/* A CONNECT: one socket, the right address, the timer armed with the action's timeout, the core not told yet */
	id = fc_id ( 2, 1 );
	fc_push_connect4 ( id, addr_a, 3300, 5000 );
	ok ( rbd_conn_drain ( fix.table ) == 1 );
	ok ( socks_n == 1 );
	sock = sock_of ( &fix, 2 );
	ok ( sock != NULL );
	if ( ! sock )
		goto out;
	sin = ( struct sockaddr_in * ) &sock->peer;
	ok ( sin->sin_family == AF_INET );
	ok ( sin->sin_port == htons ( 3300 ) );
	ok ( memcmp ( &sin->sin_addr, addr_a, 4 ) == 0 );
	ok ( conn->state == RBD_CONN_CONNECTING );
	ok ( conn->id == id );
	ok ( rbd_conn_live ( fix.table ) == 1 );
	ok ( timer_running ( &conn->timer ) );
	ok ( conn->timer.timeout == rbd_conn_ms_to_ticks ( 5000 ) );
	ok ( fc->connected_n == 0 );
	ok ( fc->closed_n == 0 );

	/* A window of zero is "not established yet": a change that leaves it at zero does nothing */
	sock->window = 0;
	xfer_window_changed ( &sock->intf );
	ok ( conn->state == RBD_CONN_CONNECTING );
	ok ( fc->connected_n == 0 );
	ok ( timer_running ( &conn->timer ) );

	/* The window opens: established, the core told once, the timer stopped, the session woken */
	fc->wakes = 0;
	sock->window = 1460;
	xfer_window_changed ( &sock->intf );
	ok ( conn->state == RBD_CONN_UP );
	ok ( fc->connected_n == 1 );
	ok ( fc->connected[0] == id );
	ok ( ! timer_running ( &conn->timer ) );
	ok ( fc->wakes >= 1 );

	/* Another change of the window does not tell the core again */
	xfer_window_changed ( &sock->intf );
	xfer_window_changed ( &sock->intf );
	ok ( fc->connected_n == 1 );

	/* The timer's expiry after the fact (a stale callback) does nothing to an established connection */
	conn->timer.expired ( &conn->timer, 0 );
	ok ( conn->state == RBD_CONN_UP );
	ok ( fc->closed_n == 0 );
	ok ( sock->closed == 0 );

	/* IPv6: the family, the port and all sixteen bytes */
	memset ( &action, 0, sizeof ( action ) );
	action.kind = WR_ACT_CONNECT;
	action.conn = fc_id ( 5, 7 );
	action.addr.family = WR_AF_IPV6;
	rbd_conn_test_copy ( action.addr.ip, v6, 16 );
	action.addr.port = 6789;
	action.timeout_ms = 1000;
	fc->conn[5].id = action.conn;
	fc_push ( &action );
	ok ( rbd_conn_drain ( fix.table ) == 1 );
	sock = sock_of ( &fix, 5 );
	ok ( sock != NULL );
	if ( sock ) {
		sin6 = ( struct sockaddr_in6 * ) &sock->peer;
		ok ( sin6->sin6_family == AF_INET6 );
		ok ( sin6->sin6_port == htons ( 6789 ) );
		ok ( memcmp ( &sin6->sin6_addr, v6, 16 ) == 0 );
		ok ( fix.table->conn[5].state == RBD_CONN_CONNECTING );
		ok ( fix.table->conn[5].timer.timeout ==
		     rbd_conn_ms_to_ticks ( 1000 ) );
	}
	ok ( rbd_conn_live ( fix.table ) == 2 );

	/* A timeout of zero is "no limit": no timer */
	fc_push_connect4 ( fc_id ( 6, 1 ), addr_b, 3300, 0 );
	ok ( rbd_conn_drain ( fix.table ) == 1 );
	ok ( fix.table->conn[6].state == RBD_CONN_CONNECTING );
	ok ( ! timer_running ( &fix.table->conn[6].timer ) );

	/* An action that is not for the table's sockets is ignored (TX_READY: every connection is looked at anyway) */
	memset ( &action, 0, sizeof ( action ) );
	action.kind = WR_ACT_TX_READY;
	action.conn = id;
	fc_push ( &action );
	action.kind = WR_ACT_NONE;
	fc_push ( &action );
	action.kind = ( wr_act_kind ) 99;
	fc_push ( &action );
	ok ( rbd_conn_drain ( fix.table ) == 3 );
	ok ( rbd_conn_live ( fix.table ) == 3 );
	ok ( fc->closed_n == 0 );

 out:
	fixture_end ( &fix, heap );
}

/**
 * Check the connect timeout
 *
 */
static void rbd_conn_timeout_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	size_t heap = heap_probe();
	wr_conn_id id = fc_id ( 0, 3 );

	if ( ! fixture_start ( &fix ) )
		return;
	fc_push_connect4 ( id, addr_a, 3300, 2500 );
	rbd_conn_drain ( fix.table );
	sock = sock_of ( &fix, 0 );
	ok ( sock != NULL );
	if ( ! sock )
		goto out;
	ok ( timer_running ( &fix.table->conn[0].timer ) );

	/* The timer fires while the connection is still being made: the socket is closed (and told why), the core is told the
	 * connection is gone with a timeout, the slot is free, the session woken
	 */
	fc->wakes = 0;
	fix.table->conn[0].timer.expired ( &fix.table->conn[0].timer, 0 );
	ok ( fix.table->conn[0].state == RBD_CONN_FREE );
	ok ( fix.table->conn[0].id == WR_CONN_NONE );
	ok ( rbd_conn_live ( fix.table ) == 0 );
	ok ( sock->closed == 1 );
	ok ( rbd_conn_error_kind ( sock->close_rc ) ==
	     rbd_conn_error_kind ( -ETIMEDOUT ) );
	ok ( fc->closed_n == 1 );
	ok ( fc->closed_id[0] == id );
	ok ( fc->closed_errno[0] > 0 );
	ok ( rbd_conn_error_kind ( fc->closed_errno[0] ) ==
	     rbd_conn_error_kind ( -ETIMEDOUT ) );
	ok ( fc->wakes >= 1 );
	ok ( ! timer_running ( &fix.table->conn[0].timer ) );

	/* The slot can be used again, by a new id */
	fc_push_connect4 ( fc_id ( 0, 4 ), addr_b, 3300, 1000 );
	rbd_conn_drain ( fix.table );
	ok ( fix.table->conn[0].state == RBD_CONN_CONNECTING );
	ok ( fix.table->conn[0].id == fc_id ( 0, 4 ) );
	ok ( socks_n == 2 );

	/* An expiry that arrives for a slot that is free does nothing (and does not tell the core of an id it does not have) */
	rbd_conn_shutdown ( fix.table );
	fc->closed_n = 0;
	fix.table->conn[0].timer.expired ( &fix.table->conn[0].timer, 0 );
	ok ( fc->closed_n == 0 );
 out:
	fixture_end ( &fix, heap );
}

/**
 * Check connections that fail
 *
 */
static void rbd_conn_fail_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	wr_action action;
	size_t heap = heap_probe();
	wr_conn_id id;

	if ( ! fixture_start ( &fix ) )
		return;

	/* The socket cannot be opened (no route): the core is told at once, with the reason; nothing stays allocated */
	fake_open_rc = -ENETUNREACH;
	id = fc_id ( 1, 1 );
	fc_push_connect4 ( id, addr_a, 3300, 5000 );
	ok ( rbd_conn_drain ( fix.table ) == 1 );
	ok ( socks_n == 0 );
	ok ( rbd_conn_live ( fix.table ) == 0 );
	ok ( ! timer_running ( &fix.table->conn[1].timer ) );
	ok ( fc->closed_n == 1 );
	ok ( fc->closed_id[0] == id );
	ok ( rbd_conn_error_kind ( fc->closed_errno[0] ) ==
	     rbd_conn_error_kind ( -ENETUNREACH ) );
	ok ( fc->connected_n == 0 );
	fake_open_rc = 0;

	/* The same through the single-action entry point: the status comes back */
	fake_open_rc = -ECONNREFUSED;
	memset ( &action, 0, sizeof ( action ) );
	action.kind = WR_ACT_CONNECT;
	action.conn = fc_id ( 1, 2 );
	action.addr.family = WR_AF_IPV4;
	rbd_conn_test_copy ( action.addr.ip, addr_a, 4 );
	action.addr.port = 3300;
	action.timeout_ms = 100;
	ok ( rbd_conn_action ( fix.table, &action ) != 0 );
	ok ( fc->closed_n == 2 );
	fake_open_rc = 0;

	/* A bad address: no port, no family, a family that is not IP: refused, and the core is told */
	action.addr.port = 0;
	action.conn = fc_id ( 1, 3 );
	ok ( rbd_conn_action ( fix.table, &action ) != 0 );
	ok ( fc->closed_n == 3 );
	ok ( fc->closed_id[2] == fc_id ( 1, 3 ) );
	ok ( rbd_conn_error_kind ( fc->closed_errno[2] ) ==
	     rbd_conn_error_kind ( -EINVAL ) );
	action.addr.port = 3300;
	action.addr.family = 0;
	action.conn = fc_id ( 1, 4 );
	ok ( rbd_conn_action ( fix.table, &action ) != 0 );
	ok ( fc->closed_n == 4 );
	ok ( rbd_conn_error_kind ( fc->closed_errno[3] ) ==
	     rbd_conn_error_kind ( -EAFNOSUPPORT ) );
	action.addr.family = 9;
	action.conn = fc_id ( 1, 5 );
	ok ( rbd_conn_action ( fix.table, &action ) != 0 );
	ok ( fc->closed_n == 5 );
	ok ( socks_n == 0 );
	ok ( rbd_conn_live ( fix.table ) == 0 );

	/* An id that names no slot (index 0, one past the end): refused, the core is told */
	action.addr.family = WR_AF_IPV4;
	action.conn = 0x00050000;
	ok ( rbd_conn_action ( fix.table, &action ) != 0 );
	action.conn = fc_id ( RBD_CONN_SLOTS, 1 );
	ok ( rbd_conn_action ( fix.table, &action ) != 0 );
	ok ( fc->closed_n == 7 );
	ok ( socks_n == 0 );
	action.conn = 0x00000103;	/* (the whole low half is the slot number: 259, not slot 3) */
	ok ( rbd_conn_action ( fix.table, &action ) != 0 );
	ok ( fc->closed_n == 8 );
	ok ( socks_n == 0 );
	ok ( rbd_conn_live ( fix.table ) == 0 );

	/* The socket closes while it is connecting (refused, reset, TCP's own timeout): the core is told, with the reason */
	id = fc_id ( 3, 1 );
	fc_push_connect4 ( id, addr_a, 3300, 5000 );
	rbd_conn_drain ( fix.table );
	sock = sock_of ( &fix, 3 );
	ok ( sock != NULL );
	if ( sock ) {
		fc->closed_n = 0;
		fc->wakes = 0;
		sock->open = 0;
		intf_shutdown ( &sock->intf, -ECONNREFUSED );
		ok ( fix.table->conn[3].state == RBD_CONN_FREE );
		ok ( ! timer_running ( &fix.table->conn[3].timer ) );
		ok ( fc->closed_n == 1 );
		ok ( fc->closed_id[0] == id );
		ok ( rbd_conn_error_kind ( fc->closed_errno[0] ) ==
		     rbd_conn_error_kind ( -ECONNREFUSED ) );
		ok ( fc->connected_n == 0 );
		ok ( fc->wakes >= 1 );
		/* the table did not close what was already closed */
		ok ( sock->closed == 0 );
	}
	fixture_end ( &fix, heap );
}

/**
 * Check closing, from either side, and stale ids
 *
 */
static void rbd_conn_close_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	struct fake_sock *sock2;
	size_t heap = heap_probe();
	wr_conn_id id;
	wr_conn_id old;
	unsigned int i;

	if ( ! fixture_start ( &fix ) )
		return;

	/* Close from the core: the socket is closed with status 0 (orderly), the core is told with errno 0 */
	id = fc_id ( 0, 1 );
	sock = connect_up ( &fix, 0, 1 );
	if ( ! sock )
		goto out;
	fc_push_close ( id );
	ok ( rbd_conn_drain ( fix.table ) == 1 );
	ok ( sock->closed == 1 );
	ok ( sock->close_rc == 0 );
	ok ( fix.table->conn[0].state == RBD_CONN_FREE );
	ok ( fc->closed_n == 1 );
	ok ( fc->closed_id[0] == id );
	ok ( fc->closed_errno[0] == 0 );

	/* A second CLOSE for the same id (the core asked twice, or the socket already went): told again, nothing else happens
	 * (the core ignores a stale id)
	 */
	fc_push_close ( id );
	rbd_conn_drain ( fix.table );
	ok ( fc->closed_n == 2 );
	ok ( fc->closed_errno[1] == 0 );
	ok ( sock->closed == 1 );

	/* Close from the socket while established (the peer closed or reset): the core is told, with the status as errno */
	id = fc_id ( 1, 1 );
	sock = connect_up ( &fix, 1, 1 );
	if ( ! sock )
		goto out;
	fc->closed_n = 0;
	sock->open = 0;
	intf_shutdown ( &sock->intf, -ECONNRESET );
	ok ( fix.table->conn[1].state == RBD_CONN_FREE );
	ok ( fc->closed_n == 1 );
	ok ( fc->closed_id[0] == id );
	ok ( rbd_conn_error_kind ( fc->closed_errno[0] ) ==
	     rbd_conn_error_kind ( -ECONNRESET ) );

	/* An orderly close from the peer (a FIN): errno 0 */
	id = fc_id ( 2, 1 );
	sock = connect_up ( &fix, 2, 1 );
	if ( ! sock )
		goto out;
	fc->closed_n = 0;
	sock->open = 0;
	intf_shutdown ( &sock->intf, 0 );
	ok ( fc->closed_n == 1 );
	ok ( fc->closed_errno[0] == 0 );
	ok ( fix.table->conn[2].state == RBD_CONN_FREE );

	/* Stale ids: a CLOSE for a connection that is not in the table (never opened, a slot that is free) is passed on to the
	 * core, which ignores it; nothing in the table changes
	 */
	fc->closed_n = 0;
	fc_push_close ( fc_id ( 4, 9 ) );
	fc_push_close ( 0x00090000 );
	fc_push_close ( 0 );
	fc_push_close ( 0xffffffff );
	rbd_conn_drain ( fix.table );
	ok ( fc->closed_n == 4 );
	ok ( rbd_conn_live ( fix.table ) == 0 );

	/* A new connection in a slot, then a CLOSE with the old generation of that slot's id: the new connection survives (the
	 * core is told of the stale id, which it ignores)
	 */
	old = fc_id ( 3, 1 );
	id = fc_id ( 3, 2 );
	sock = connect_up ( &fix, 3, 2 );
	if ( ! sock )
		goto out;
	fc->closed_n = 0;
	fc_push_close ( old );
	rbd_conn_drain ( fix.table );
	ok ( fix.table->conn[3].state == RBD_CONN_UP );
	ok ( fix.table->conn[3].id == id );
	ok ( sock->closed == 0 );
	ok ( fc->closed_n == 1 );
	ok ( fc->closed_id[0] == old );

	/* A CONNECT in a slot whose old socket is still there (the core reused a slot we did not hear about): the old socket
	 * is closed, the new one opened; the core is not told about the old id (the core freed it itself)
	 */
	fc->closed_n = 0;
	fc_push_connect4 ( fc_id ( 3, 3 ), addr_b, 3300, 1000 );
	rbd_conn_drain ( fix.table );
	sock2 = sock_of ( &fix, 3 );
	ok ( sock2 != NULL );
	ok ( sock2 != sock );
	ok ( sock->closed == 1 );
	ok ( fc->closed_n == 0 );
	ok ( fix.table->conn[3].id == fc_id ( 3, 3 ) );
	ok ( fix.table->conn[3].state == RBD_CONN_CONNECTING );
	ok ( rbd_conn_live ( fix.table ) == 1 );

	/* All slots at once, each with its own socket; closing one leaves the others */
	rbd_conn_shutdown ( fix.table );
	fixture_end ( &fix, heap );
	heap = heap_probe();
	if ( ! fixture_start ( &fix ) )
		return;
	for ( i = 0 ; i < RBD_CONN_SLOTS ; i++ )
		ok ( connect_up ( &fix, i, 1 ) != NULL );
	ok ( rbd_conn_live ( fix.table ) == RBD_CONN_SLOTS );
	ok ( socks_n == RBD_CONN_SLOTS );
	fc_push_close ( fc_id ( 5, 1 ) );
	rbd_conn_drain ( fix.table );
	ok ( rbd_conn_live ( fix.table ) == ( RBD_CONN_SLOTS - 1 ) );
	for ( i = 0 ; i < RBD_CONN_SLOTS ; i++ ) {
		ok ( ( fix.table->conn[i].state == RBD_CONN_FREE ) == ( i == 5 ) );
	}
 out:
	fixture_end ( &fix, heap );
}

/****************************************************************************
 *
 * Transmit
 *
 ****************************************************************************
 */

/**
 * Put bytes into the fake core's output for a connection
 *
 * @v id		Connection id
 * @v len		Length (a counting pattern: byte i is i + 1 mod 251)
 * @v piece		Size of the gather pieces
 */
static void fc_queue_tx ( wr_conn_id id, size_t len, size_t piece ) {
	struct fake_conn *conn = fc_conn ( id );
	size_t i;

	if ( ! conn )
		return;
	for ( i = 0 ; i < len ; i++ )
		conn->tx[ conn->tx_len + i ] = ( ( ( conn->tx_len + i ) % 251 ) + 1 );
	conn->tx_len += len;
	conn->tx_piece = piece;
}

/** Check that the socket received bytes i = 0 .. len - 1 of the counting pattern */
static int sock_got_pattern ( const struct fake_sock *sock, size_t len ) {
	size_t i;

	if ( sock->sent_len != len )
		return 0;
	for ( i = 0 ; i < len ; i++ ) {
		if ( sock->sent[i] != ( ( i % 251 ) + 1 ) )
			return 0;
	}
	return 1;
}

/**
 * Check transmit
 *
 */
static void rbd_conn_transmit_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	struct fake_conn *cc;
	size_t heap = heap_probe();
	wr_conn_id id = fc_id ( 0, 1 );
	unsigned int guard;
	size_t total;
	int work;

	if ( ! fixture_start ( &fix ) )
		return;
	sock = connect_up ( &fix, 0, 1 );
	if ( ! sock )
		goto out;
	cc = fc_conn ( id );

	/* Nothing to send: nothing happens, and the service says there is no work */
	ok ( rbd_conn_service ( fix.table ) == 0 );
	ok ( sock->deliveries == 0 );

	/* Pending bytes, a window of zero: nothing is sent, nothing is consumed, no work is claimed (the window-changed
	 * event will say when there is room)
	 */
	fc_queue_tx ( id, 100, 7 );
	sock->window = 0;
	ok ( rbd_conn_service ( fix.table ) == 0 );
	ok ( sock->deliveries == 0 );
	ok ( cc->tx_pos == 0 );

	/* A window smaller than the pending bytes: exactly the window goes, in one packet, across the gather pieces
	 * (7-byte pieces: 10 bytes is a piece and part of the next); the window is zero afterwards, as with TCP's one packet
	 * in flight; the core is told what went
	 */
	sock->window = 10;
	work = rbd_conn_service ( fix.table );
	ok ( work & RBD_CONN_PROGRESS );
	ok ( ! ( work & RBD_CONN_MORE ) );
	ok ( sock->deliveries == 1 );
	ok ( sock->packet[0] == 10 );
	ok ( cc->tx_pos == 10 );
	ok ( sock_got_pattern ( sock, 10 ) );

	/* Window still zero: the same call does nothing */
	ok ( rbd_conn_service ( fix.table ) == 0 );
	ok ( sock->deliveries == 1 );

	/* The ACK opens the window: the event wakes the session, the next call sends the next piece of the stream */
	fc->wakes = 0;
	sock->window = 25;
	xfer_window_changed ( &sock->intf );
	ok ( fc->wakes >= 1 );
	work = rbd_conn_service ( fix.table );
	ok ( work & RBD_CONN_PROGRESS );
	ok ( sock->packet[1] == 25 );
	ok ( cc->tx_pos == 35 );
	ok ( sock_got_pattern ( sock, 35 ) );

	/* A window that fell to zero (our own packet in flight) wakes nobody */
	fc->wakes = 0;
	sock->window = 0;
	xfer_window_changed ( &sock->intf );
	ok ( fc->wakes == 0 );

	/* A window larger than what is left: only what is left goes (65 bytes) */
	sock->window = 1460;
	xfer_window_changed ( &sock->intf );
	work = rbd_conn_service ( fix.table );
	ok ( work & RBD_CONN_PROGRESS );
	ok ( sock->packet[2] == 65 );
	ok ( cc->tx_pos == 100 );
	ok ( sock_got_pattern ( sock, 100 ) );
	sock->window = 1460;
	ok ( rbd_conn_service ( fix.table ) == 0 );
	ok ( sock->deliveries == 3 );

	/* A long stream through a window of 13 bytes, one packet per ACK, in pieces of 5 and then 1, 3, 1460: the stream that
	 * arrives is the stream that was queued, byte for byte
	 */
	sock->sent_len = 0;
	sock->deliveries = 0;
	cc->tx_len = 0;
	cc->tx_pos = 0;
	fc_queue_tx ( id, 1000, 5 );
	total = 0;
	for ( guard = 0 ; ( guard < 200 ) && ( cc->tx_pos < cc->tx_len ) ; guard++ ) {
		sock->window = 13;
		work = rbd_conn_service ( fix.table );
		total += ( work & RBD_CONN_PROGRESS ) ? 1 : 0;
	}
	ok ( cc->tx_pos == 1000 );
	ok ( sock_got_pattern ( sock, 1000 ) );
	ok ( sock->deliveries == 77 );
	ok ( total == 77 );
	sock->sent_len = 0;
	sock->deliveries = 0;
	cc->tx_len = 0;
	cc->tx_pos = 0;
	fc_queue_tx ( id, 500, 1 );
	for ( guard = 0 ; ( guard < 500 ) && ( cc->tx_pos < cc->tx_len ) ; guard++ ) {
		sock->window = 3;
		( void ) rbd_conn_service ( fix.table );
	}
	ok ( sock_got_pattern ( sock, 500 ) );
	ok ( sock->deliveries == 167 );
	/* a gather list of one-byte pieces is cut into RBD_CONN_IOV pieces at most per peek; the packet is still the window */
	ok ( sock->packet[0] == 3 );

	/* A window larger than the gather list can describe (16 one-byte pieces) is a short packet, and the rest follows on
	 * the same call if the socket stays open (a fast transport): the burst limit applies
	 */
	sock->sent_len = 0;
	sock->deliveries = 0;
	cc->tx_len = 0;
	cc->tx_pos = 0;
	sock->keep_open = 1;
	fc_queue_tx ( id, 300, 1 );
	sock->window = 4000;
	work = rbd_conn_service ( fix.table );
	ok ( work & RBD_CONN_PROGRESS );
	ok ( work & RBD_CONN_MORE );
	ok ( sock->deliveries == RBD_CONN_TX_BURST );
	ok ( sock->packet[0] == RBD_CONN_IOV );
	ok ( cc->tx_pos == ( RBD_CONN_TX_BURST * RBD_CONN_IOV ) );
	work = rbd_conn_service ( fix.table );
	ok ( cc->tx_pos == ( 2 * RBD_CONN_TX_BURST * RBD_CONN_IOV ) );
	for ( guard = 0 ; ( guard < 10 ) && ( cc->tx_pos < cc->tx_len ) ; guard++ )
		( void ) rbd_conn_service ( fix.table );
	ok ( sock_got_pattern ( sock, 300 ) );
	sock->keep_open = 0;

	/* No memory for a packet: nothing is consumed, nothing is lost, the service asks to be called again (no event will
	 * announce that memory is back), and the same bytes go when there is memory
	 */
	sock->sent_len = 0;
	sock->deliveries = 0;
	cc->tx_len = 0;
	cc->tx_pos = 0;
	fc_queue_tx ( id, 40, 40 );
	sock->no_alloc = 1;
	sock->window = 1460;
	work = rbd_conn_service ( fix.table );
	ok ( work & RBD_CONN_MORE );
	ok ( ! ( work & RBD_CONN_PROGRESS ) );
	ok ( cc->tx_pos == 0 );
	ok ( sock->deliveries == 0 );
	ok ( fix.table->conn[0].state == RBD_CONN_UP );
	sock->no_alloc = 0;
	work = rbd_conn_service ( fix.table );
	ok ( work & RBD_CONN_PROGRESS );
	ok ( sock_got_pattern ( sock, 40 ) );

	/* A send that fails (the socket took the buffer and says no): the connection is closed with that status, the core is
	 * told, the bytes are not reported as sent
	 */
	cc->tx_len = 0;
	cc->tx_pos = 0;
	sock->sent_len = 0;
	fc_queue_tx ( id, 40, 40 );
	sock->deliver_rc = -EPIPE;
	sock->window = 1460;
	fc->closed_n = 0;
	( void ) rbd_conn_service ( fix.table );
	ok ( fix.table->conn[0].state == RBD_CONN_FREE );
	ok ( sock->closed == 1 );
	ok ( fc->closed_n == 1 );
	ok ( fc->closed_id[0] == id );
	ok ( rbd_conn_error_kind ( fc->closed_errno[0] ) ==
	     rbd_conn_error_kind ( -EPIPE ) );
 out:
	fixture_end ( &fix, heap );
}

/**
 * Check a socket that closes inside a send
 *
 */
static void rbd_conn_transmit_close_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	struct fake_sock *sock1;
	size_t heap = heap_probe();
	wr_conn_id id = fc_id ( 0, 1 );
	int work;

	if ( ! fixture_start ( &fix ) )
		return;
	sock = connect_up ( &fix, 0, 1 );
	sock1 = connect_up ( &fix, 1, 1 );
	if ( ! ( sock && sock1 ) )
		goto out;
	fc_queue_tx ( id, 40, 40 );
	fc_queue_tx ( fc_id ( 1, 1 ), 20, 20 );

	/* TCP can close its consumer from inside a delivery (a reset noticed while building the packet). The table notices,
	 * does not report the bytes as sent, tells the core exactly once, and goes on to the next connection
	 */
	sock->deliver_closes = 1;
	sock->deliver_closes_rc = -ECONNRESET;
	sock->window = 1460;
	sock1->window = 1460;
	fc->closed_n = 0;
	work = rbd_conn_service ( fix.table );
	ok ( fix.table->conn[0].state == RBD_CONN_FREE );
	ok ( fc->closed_n == 1 );
	ok ( fc->closed_id[0] == id );
	ok ( rbd_conn_error_kind ( fc->closed_errno[0] ) ==
	     rbd_conn_error_kind ( -ECONNRESET ) );
	ok ( sock->deliveries == 1 );
	ok ( fc->conn[0].id == 0 );
	ok ( fix.table->conn[1].state == RBD_CONN_UP );
	ok ( sock1->sent_len == 20 );
	ok ( work & RBD_CONN_PROGRESS );
	/* ... and a second pass has nothing to do for the closed slot */
	ok ( rbd_conn_service ( fix.table ) == 0 );
	ok ( fc->closed_n == 1 );
 out:
	fixture_end ( &fix, heap );
}

/****************************************************************************
 *
 * Receive
 *
 ****************************************************************************
 */

/** Deliver bytes to the table the way the socket does */
static int sock_send ( struct fake_sock *sock, const void *data, size_t len ) {

	return xfer_deliver_raw ( &sock->intf, data, len );
}

/** A counting pattern for the receive tests (byte i is 0x80 + i mod 100) */
static void rx_pattern ( uint8_t *out, size_t from, size_t len ) {
	size_t i;

	for ( i = 0 ; i < len ; i++ )
		out[i] = ( 0x80 + ( ( from + i ) % 100 ) );
}

/** Check that the fake core's connection received bytes 0 .. len - 1 of the receive pattern */
static int core_got_pattern ( const struct fake_conn *conn, size_t len ) {
	uint8_t want[FAKE_BUF];

	if ( conn->rx_len != len )
		return 0;
	rx_pattern ( want, 0, len );
	return ( memcmp ( conn->rx, want, len ) == 0 );
}

/**
 * Check receive
 *
 */
static void rbd_conn_receive_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	struct fake_conn *cc;
	struct rbd_conn *conn;
	size_t heap = heap_probe();
	wr_conn_id id = fc_id ( 0, 1 );
	uint8_t data[512];
	int work;

	if ( ! fixture_start ( &fix ) )
		return;
	sock = connect_up ( &fix, 0, 1 );
	if ( ! sock )
		goto out;
	cc = fc_conn ( id );
	conn = &fix.table->conn[0];
	rx_pattern ( data, 0, sizeof ( data ) );

	/* The window TCP is told is the core's room */
	cc->rx_room = 100;
	ok ( xfer_window ( &sock->intf ) == 100 );
	ok ( conn->adv_max == 100 );

	/* A room larger than RBD_CONN_RX_WINDOW_MAX is announced as that limit and no more (iPXE's TCP queues out-of-order data up to
	 * the window it announced, in I/O buffers of its 4 MiB heap, and never announces less than the largest window it has seen), and
	 * the limit is what the backlog may grow to; a smaller room is announced as it is
	 */
	cc->rx_room = ( 4 * 1024 * 1024 );
	ok ( xfer_window ( &sock->intf ) == RBD_CONN_RX_WINDOW_MAX );
	ok ( conn->adv_max == RBD_CONN_RX_WINDOW_MAX );
	cc->rx_room = ( ( size_t ) RBD_CONN_RX_WINDOW_MAX + 1 );
	ok ( xfer_window ( &sock->intf ) == RBD_CONN_RX_WINDOW_MAX );
	cc->rx_room = RBD_CONN_RX_WINDOW_MAX;
	ok ( xfer_window ( &sock->intf ) == RBD_CONN_RX_WINDOW_MAX );
	conn->adv_max = 0;
	cc->rx_room = 100;
	ok ( xfer_window ( &sock->intf ) == 100 );
	ok ( conn->adv_max == 100 );

	/* Data the core can take goes straight into it, in order, with nothing parked; the session is woken, the core is
	 * not run (the table never calls it)
	 */
	fc->wakes = 0;
	ok ( sock_send ( sock, data, 40 ) == 0 );
	ok ( cc->rx_len == 40 );
	ok ( conn->backlog_len == 0 );
	ok ( list_empty ( &conn->backlog ) );
	ok ( fc->wakes >= 1 );
	ok ( xfer_window ( &sock->intf ) == 60 );

	/* An empty buffer is nothing */
	ok ( sock_send ( sock, data, 0 ) == 0 );
	ok ( cc->rx_len == 40 );

	/* The core's room shrinks after the window was announced (it is full of bytes it has not parsed yet): what it cannot
	 * take is parked, in order. The window reported is now the room less the backlog (zero)
	 */
	cc->rx_room = 30;
	fc->wakes = 0;
	ok ( sock_send ( sock, data + 40, 50 ) == 0 );
	ok ( fc->wakes >= 1 );		/* (parked data needs a pass of the session too) */
	ok ( cc->rx_len == 70 );
	ok ( conn->backlog_len == 20 );
	ok ( ! list_empty ( &conn->backlog ) );
	ok ( xfer_window ( &sock->intf ) == 0 );
	cc->rx_room = 15;
	ok ( xfer_window ( &sock->intf ) == 0 );
	cc->rx_room = 20;
	ok ( xfer_window ( &sock->intf ) == 0 );
	cc->rx_room = 21;
	ok ( xfer_window ( &sock->intf ) == 1 );
	cc->rx_room = 0;

	/* The service finds no room: nothing moves, and it says that work is waiting that no event will announce */
	work = rbd_conn_service ( fix.table );
	ok ( work & RBD_CONN_MORE );
	ok ( ! ( work & RBD_CONN_PROGRESS ) );
	ok ( conn->backlog_len == 20 );

	/* Data that arrives behind a backlog goes behind it, even when the core has room by then (it may not overtake) */
	cc->rx_room = 5;
	ok ( sock_send ( sock, data + 90, 10 ) == 0 );
	ok ( cc->rx_len == 70 );
	ok ( conn->backlog_len == 30 );

	/* The core makes room: the service hands the backlog over, in order, and the core gets exactly the stream */
	cc->rx_room = 12;
	work = rbd_conn_service ( fix.table );
	ok ( work & RBD_CONN_PROGRESS );
	ok ( work & RBD_CONN_MORE );
	ok ( cc->rx_len == 82 );
	ok ( conn->backlog_len == 18 );
	cc->rx_room = 1000;
	work = rbd_conn_service ( fix.table );
	ok ( work & RBD_CONN_PROGRESS );
	ok ( ! ( work & RBD_CONN_MORE ) );
	ok ( cc->rx_len == 100 );
	ok ( conn->backlog_len == 0 );
	ok ( list_empty ( &conn->backlog ) );
	ok ( core_got_pattern ( cc, 100 ) );
	ok ( rbd_conn_service ( fix.table ) == 0 );

	/* Back to direct delivery */
	ok ( sock_send ( sock, data + 100, 100 ) == 0 );
	ok ( cc->rx_len == 200 );
	ok ( conn->backlog_len == 0 );
	ok ( core_got_pattern ( cc, 200 ) );

	/* A peer that sends more than what was announced (TCP does not do that; a socket that is not TCP, or a window that was
	 * miscalculated, could): the connection is closed, the core is told, no byte is kept beyond the bound
	 */
	cc->rx_room = 10;
	ok ( xfer_window ( &sock->intf ) == 10 );
	cc->rx_room = 0;
	ok ( sock_send ( sock, data, 10 ) == 0 );
	ok ( conn->backlog_len == 10 );
	fc->closed_n = 0;
	ok ( sock_send ( sock, data, 1000 ) != 0 );
	ok ( conn->state == RBD_CONN_FREE );
	ok ( list_empty ( &conn->backlog ) );
	ok ( conn->backlog_len == 0 );
	ok ( sock->closed == 1 );
	ok ( fc->closed_n == 1 );
	ok ( fc->closed_id[0] == id );
	ok ( rbd_conn_error_kind ( fc->closed_errno[0] ) ==
	     rbd_conn_error_kind ( -ENOBUFS ) );
 out:
	fixture_end ( &fix, heap );
}

/**
 * Check the bound on the backlog
 *
 */
static void rbd_conn_backlog_bound_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	struct fake_conn *cc;
	struct rbd_conn *conn;
	size_t heap = heap_probe();
	wr_conn_id id = fc_id ( 0, 1 );
	uint8_t data[256];

	if ( ! fixture_start ( &fix ) )
		return;
	sock = connect_up ( &fix, 0, 1 );
	if ( ! sock )
		goto out;
	cc = fc_conn ( id );
	conn = &fix.table->conn[0];
	rx_pattern ( data, 0, sizeof ( data ) );

	/* The bound is the largest room the core has offered, not the window of the moment: the window announced when the
	 * backlog was already 50 was room - 50, and everything TCP lets through after that still fits within room
	 */
	cc->rx_room = 100;
	ok ( xfer_window ( &sock->intf ) == 100 );
	cc->rx_room = 0;
	ok ( sock_send ( sock, data, 50 ) == 0 );
	ok ( conn->backlog_len == 50 );
	cc->rx_room = 100;
	ok ( xfer_window ( &sock->intf ) == 50 );
	cc->rx_room = 0;
	ok ( sock_send ( sock, data + 50, 50 ) == 0 );
	ok ( conn->backlog_len == 100 );
	ok ( conn->state == RBD_CONN_UP );
	/* one byte more than ever was offered: closed */
	ok ( sock_send ( sock, data, 1 ) != 0 );
	ok ( conn->state == RBD_CONN_FREE );

	/* The first window announced while a backlog already exists is "room less backlog", and still the bound is the room:
	 * room 60 offered, 40 parked, room 100 offered (window 60), 60 more parked: 100 bytes, within what was ever offered
	 */
	sock = connect_up ( &fix, 4, 1 );
	if ( ! sock )
		goto out;
	cc = fc_conn ( fc_id ( 4, 1 ) );
	conn = &fix.table->conn[4];
	cc->rx_room = 60;
	ok ( xfer_window ( &sock->intf ) == 60 );
	cc->rx_room = 0;
	ok ( sock_send ( sock, data, 40 ) == 0 );
	ok ( conn->backlog_len == 40 );
	cc->rx_room = 100;
	ok ( xfer_window ( &sock->intf ) == 60 );
	ok ( conn->adv_max == 100 );
	cc->rx_room = 0;
	ok ( sock_send ( sock, data + 40, 60 ) == 0 );
	ok ( conn->backlog_len == 100 );
	ok ( conn->state == RBD_CONN_UP );
	ok ( sock_send ( sock, data, 1 ) != 0 );
	ok ( conn->state == RBD_CONN_FREE );

	/* A connection on which no window was ever announced has no bound: any byte the core cannot take closes it */
	sock = connect_up ( &fix, 1, 1 );
	if ( ! sock )
		goto out;
	cc = fc_conn ( fc_id ( 1, 1 ) );
	cc->rx_room = 4;
	ok ( sock_send ( sock, data, 4 ) == 0 );
	ok ( cc->rx_len == 4 );
	ok ( sock_send ( sock, data, 1 ) != 0 );
	ok ( fix.table->conn[1].state == RBD_CONN_FREE );

	/* Shutdown with a full backlog, a running timer and sockets in both states frees everything (fixture_end checks the
	 * heap and the timers) and does not tell the core
	 */
	sock = connect_up ( &fix, 2, 1 );
	if ( ! sock )
		goto out;
	cc = fc_conn ( fc_id ( 2, 1 ) );
	cc->rx_room = 100;
	( void ) xfer_window ( &sock->intf );
	cc->rx_room = 0;
	ok ( sock_send ( sock, data, 30 ) == 0 );
	ok ( sock_send ( sock, data, 30 ) == 0 );
	ok ( fix.table->conn[2].backlog_len == 60 );
	fc_push_connect4 ( fc_id ( 3, 1 ), addr_a, 3300, 60000 );
	rbd_conn_drain ( fix.table );
	ok ( timer_running ( &fix.table->conn[3].timer ) );
	fc->closed_n = 0;
	fc->wakes = 0;
	rbd_conn_shutdown ( fix.table );
	ok ( fc->closed_n == 0 );
	ok ( fc->wakes == 0 );
	ok ( rbd_conn_live ( fix.table ) == 0 );
	ok ( sock_of ( &fix, 2 ) == NULL );
	ok ( sock_of ( &fix, 3 ) == NULL );
	ok ( ! timer_running ( &fix.table->conn[3].timer ) );
	/* after shutdown the table does nothing for the core any more */
	fc_push_connect4 ( fc_id ( 4, 1 ), addr_a, 3300, 1000 );
	ok ( rbd_conn_drain ( fix.table ) == 0 );
	ok ( rbd_conn_service ( fix.table ) == 0 );
	ok ( socks_n == 5 );
 out:
	fixture_end ( &fix, heap );
}

/**
 * Check data that arrives before the "established" event
 *
 */
static void rbd_conn_early_data_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	struct fake_conn *cc;
	size_t heap = heap_probe();
	wr_conn_id id = fc_id ( 0, 1 );
	uint8_t data[64];

	if ( ! fixture_start ( &fix ) )
		return;
	rx_pattern ( data, 0, sizeof ( data ) );

	/* The socket's window stays at zero (a peer that opened with a zero window) but the peer speaks first, as msgr2 does:
	 * data proves that the connection is up. The core is told first, then given the bytes; they are not dropped
	 */
	fc_push_connect4 ( id, addr_a, 3300, 5000 );
	rbd_conn_drain ( fix.table );
	sock = sock_of ( &fix, 0 );
	ok ( sock != NULL );
	if ( ! sock )
		goto out;
	cc = fc_conn ( id );
	sock->window = 0;
	ok ( fix.table->conn[0].state == RBD_CONN_CONNECTING );
	ok ( sock_send ( sock, data, 20 ) == 0 );
	ok ( fix.table->conn[0].state == RBD_CONN_UP );
	ok ( fc->connected_n == 1 );
	ok ( ! timer_running ( &fix.table->conn[0].timer ) );
	ok ( cc->rx_len == 20 );
	ok ( core_got_pattern ( cc, 20 ) );

	/* Data for a connection that was closed (a late packet): the interface is not plugged any more, so it goes nowhere */
	fc_push_close ( id );
	rbd_conn_drain ( fix.table );
	ok ( fix.table->conn[0].state == RBD_CONN_FREE );
	ok ( sock_send ( sock, data, 20 ) != 0 );
	ok ( cc->rx_len == 20 );
 out:
	fixture_end ( &fix, heap );
}

/**
 * Check the window-changed event with the window at zero, and a socket with no window to report
 *
 */
static void rbd_conn_wake_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	size_t heap = heap_probe();

	if ( ! fixture_start ( &fix ) )
		return;
	sock = connect_up ( &fix, 0, 1 );
	if ( ! sock )
		goto out;

	/* Window changes: woken when a packet can go, not when the window closes */
	fc->wakes = 0;
	sock->window = 0;
	xfer_window_changed ( &sock->intf );
	ok ( fc->wakes == 0 );
	sock->window = 1;
	xfer_window_changed ( &sock->intf );
	ok ( fc->wakes == 1 );

	/* The table has no wake function (a test, or a session being torn down): events do not fail */
	fix.table->wake = NULL;
	xfer_window_changed ( &sock->intf );
	ok ( sock_send ( sock, "abc", 3 ) == 0 );
 out:
	fixture_end ( &fix, heap );
}

/****************************************************************************
 *
 * The real core
 *
 ****************************************************************************
 */

/** Wake counter of the real-core tests */
static unsigned int real_wakes;

static void real_wake ( void *ctx __unused ) {

	real_wakes++;
}

/** The ops of the real-core tests: the real core, the fake socket and a counting random source */
static struct rbd_conn_ops real_ops;

/** Bytes of the peer's banner delivered at a time in the next flight (0: the peer says nothing) */
static size_t real_rx_chunk;

/** The result of one flight of the real client */
struct real_flight {
	/** What the client sent (the first bytes) */
	uint8_t sent[2048];
	size_t sent_len;
	/** Packets */
	unsigned int packets;
	/** The monitor address the client dialled */
	struct sockaddr_tcpip peer;
	/** What the client sent after the peer's banner (the first bytes of the whole stream) */
	uint8_t sent2[2048];
	size_t sent2_len;
	/** The connection was still up after the peer's banner */
	int up_after_banner;
	/** The client asked for a connection at all, and the table made it established */
	int established;
	/** The table had a socket for it */
	int connected;
};

/**
 * Drive a real client through the table until it has nothing more to send
 *
 * @v window		Window of the fake socket for each packet (0: one big packet, whatever there is)
 * @v out		Result
 * @v garbage		Send a peer banner that is not one afterwards, and expect the client to close the connection
 * @ret ok		The flight went as it should
 */
static int real_flight_run ( size_t window, struct real_flight *out, int garbage ) {
	struct rbd_conn_table *table;
	struct wr_client *client = NULL;
	wr_config cfg;
	wr_mem_req req;
	wr_host_ops host;
	wr_cluster_spec *spec;
	wr_clock now;
	wr_mem_region arena;
	wr_mem_region bulk;
	void *arena_ptr;
	void *bulk_ptr;
	struct fake_sock *sock = NULL;
	unsigned int pass;
	unsigned int live_before;
	size_t room;
	int work;
	int good = 0;
	unsigned int i;
	int rc;

	memset ( out, 0, sizeof ( *out ) );
	arena_ptr = NULL;
	bulk_ptr = NULL;
	socks = zalloc ( FAKE_SOCKS * sizeof ( socks[0] ) );
	table = zalloc ( sizeof ( *table ) );
	spec = zalloc ( sizeof ( *spec ) );
	ok ( socks && table && spec );
	if ( ! ( socks && table && spec ) )
		goto out;
	socks_n = 0;
	fake_open_rc = 0;
	rbd_conn_pattern = 0;

	/* The real core's connection calls, the fake socket, a counting random source (the same bytes every run) */
	real_ops = rbd_conn_default_ops;
	real_ops.open = fake_open;
	real_ops.generate = rbd_conn_generate_pattern;
	rbd_conn_init ( table, NULL, real_wake, NULL );
	table->ops = &real_ops;
	rbd_conn_host_ops ( table, &host );

	/* A client for a made-up cluster (TEST-NET-1), with a made-up key */
	wr_config_profile_ipxe ( &cfg );
	rc = wr_client_mem_required ( &cfg, &req );
	ok ( rc == WR_OK );
	if ( rc != WR_OK )
		goto out;
	arena_ptr = umalloc ( req.arena + 16 );
	bulk_ptr = umalloc ( req.bulk + 16 );
	ok ( arena_ptr != NULL );
	ok ( bulk_ptr != NULL );
	if ( ( arena_ptr == NULL ) || ( bulk_ptr == NULL ) )
		goto out;
	/* the core wants 16-byte aligned regions; umalloc() promises a page, but the Linux one hands out the address after an
	 * 8-byte header on a 32-bit system, so the regions are aligned here (the 16 bytes of slack are in the allocation)
	 */
	arena.base = ( void * ) ( ( ( uintptr_t ) arena_ptr + 15 ) & ~( ( uintptr_t ) 15 ) );
	arena.size = req.arena;
	bulk.base = ( void * ) ( ( ( uintptr_t ) bulk_ptr + 15 ) & ~( ( uintptr_t ) 15 ) );
	bulk.size = req.bulk;
	memset ( arena.base, 0, arena.size );
	memset ( bulk.base, 0, bulk.size );
	strcpy ( spec->user, "test" );
	{
		uint8_t secret[16];

		for ( i = 0 ; i < sizeof ( secret ) ; i++ )
			secret[i] = ( 0x40 + i );
		rc = wr_key_from_raw ( &spec->key, WR_KEY_TYPE_AES, secret,
				       sizeof ( secret ) );
		ok ( rc == WR_OK );
		if ( rc != WR_OK )
			goto out;
	}
	spec->mons[0].family = WR_AF_IPV4;
	rbd_conn_test_copy ( spec->mons[0].ip, addr_a, 4 );
	spec->mons[0].port = 3300;
	spec->n_mons = 1;
	rc = wr_client_create ( &cfg, &host, spec, arena, bulk, &client );
	if ( rc != WR_OK )
		printf ( "rbd_conn_test: wr_client_create failed: %s (%s), arena %zd bulk %zd\n",
			 wr_strerror ( rc ), wr_status_name ( rc ), arena.size,
			 bulk.size );
	ok ( rc == WR_OK );
	if ( rc != WR_OK )
		goto out;
	rbd_conn_attach ( table, client );

	/* The first pass: the client wants a monitor, the table opens a socket, nothing is established yet */
	memset ( &now, 0, sizeof ( now ) );
	now.mono_ms = 1000;
	( void ) wr_client_run ( client, &now, 0 );
	ok ( rbd_conn_drain ( table ) >= 1 );
	ok ( socks_n == 1 );
	ok ( rbd_conn_live ( table ) == 1 );
	if ( socks_n != 1 )
		goto out;
	sock = &socks[0];
	out->peer = sock->peer;
	ok ( sock->peer.st_family == AF_INET );
	ok ( ( ( struct sockaddr_in * ) &sock->peer )->sin_port == htons ( 3300 ) );
	ok ( memcmp ( &( ( struct sockaddr_in * ) &sock->peer )->sin_addr,
		      addr_a, 4 ) == 0 );
	sock->window = 0;
	ok ( rbd_conn_service ( table ) == 0 );
	ok ( sock->deliveries == 0 );

	/* The window opens: the core is told the connection is up, and starts to send */
	sock->window = ( window ? window : 1460 );
	xfer_window_changed ( &sock->intf );
	out->established = ( table->conn[0].state == RBD_CONN_UP );
	ok ( out->established );
	ok ( real_wakes >= 1 );
	for ( pass = 0 ; pass < 400 ; pass++ ) {
		now.mono_ms += 1;
		( void ) wr_client_run ( client, &now, 0 );
		( void ) rbd_conn_drain ( table );
		sock->window = ( window ? window : 1460 );
		work = rbd_conn_service ( table );
		if ( ! ( work & ( RBD_CONN_PROGRESS | RBD_CONN_MORE ) ) ) {
			/* nothing moved: one more round to be sure the client has nothing queued */
			now.mono_ms += 1;
			( void ) wr_client_run ( client, &now, 0 );
			sock->window = ( window ? window : 1460 );
			work = rbd_conn_service ( table );
			if ( ! ( work & ( RBD_CONN_PROGRESS | RBD_CONN_MORE ) ) )
				break;
		}
	}
	out->sent_len = ( ( sock->sent_len < sizeof ( out->sent ) ) ?
			  sock->sent_len : sizeof ( out->sent ) );
	memcpy ( out->sent, sock->sent, out->sent_len );
	out->packets = sock->deliveries;
	if ( window && ( out->sent_len > 0 ) ) {
		/* with a small window no packet is larger than the window */
		for ( i = 0 ; ( i < out->packets ) &&
			      ( i < ( sizeof ( sock->packet ) /
				      sizeof ( sock->packet[0] ) ) ) ; i++ )
			ok ( sock->packet[i] <= window );
	}

	/* The receive window the socket reports is the core's */
	room = xfer_window ( &sock->intf );
	ok ( room > 0 );
	ok ( room < 0x100000 );

	/* A peer that sends something that is not a banner: the client refuses it and asks for the connection to be closed */
	if ( garbage ) {
		static const char junk[] = "this is not a msgr banner, not at all......";

		live_before = rbd_conn_live ( table );
		ok ( live_before == 1 );
		ok ( sock_send ( sock, junk, ( sizeof ( junk ) - 1 ) ) == 0 );
		for ( pass = 0 ; ( pass < 20 ) && ( ! sock->closed ) ; pass++ ) {
			now.mono_ms += 1;
			( void ) wr_client_run ( client, &now, 0 );
			( void ) rbd_conn_drain ( table );
			( void ) rbd_conn_service ( table );
		}
		ok ( sock->closed == 1 );
		ok ( sock->close_rc == 0 );
		ok ( table->conn[0].state == RBD_CONN_FREE );
	}

	/* A peer that answers with a real banner, in pieces of real_rx_chunk bytes, each no larger than the window the table
	 * reports (a peer obeys the window): the client accepts it and goes on with its HELLO. The pieces end up in the
	 * core through the window and the backlog of the table, and the stream the client sends does not depend on them.
	 */
	if ( real_rx_chunk && ( ! garbage ) ) {
		static const uint8_t banner[26] = {
			'c', 'e', 'p', 'h', ' ', 'v', '2', '\n', 16, 0,
			1, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0
		};
		size_t before = sock->sent_len;
		size_t off = 0;
		size_t piece;
		unsigned int stuck = 0;

		ok ( before >= 26 );
		while ( ( off < sizeof ( banner ) ) && ( stuck < 50 ) ) {
			room = xfer_window ( &sock->intf );
			piece = ( sizeof ( banner ) - off );
			if ( piece > real_rx_chunk )
				piece = real_rx_chunk;
			if ( piece > room )
				piece = room;
			if ( piece ) {
				ok ( sock_send ( sock, ( banner + off ), piece ) == 0 );
				off += piece;
				stuck = 0;
			} else {
				stuck++;
			}
			now.mono_ms += 1;
			( void ) wr_client_run ( client, &now, 0 );
			( void ) rbd_conn_drain ( table );
			sock->window = ( window ? window : 1460 );
			( void ) rbd_conn_service ( table );
		}
		ok ( off == sizeof ( banner ) );
		for ( pass = 0 ; pass < 400 ; pass++ ) {
			now.mono_ms += 1;
			( void ) wr_client_run ( client, &now, 0 );
			( void ) rbd_conn_drain ( table );
			sock->window = ( window ? window : 1460 );
			work = rbd_conn_service ( table );
			if ( ! ( work & ( RBD_CONN_PROGRESS | RBD_CONN_MORE ) ) )
				break;
		}
		out->up_after_banner = ( ( ! sock->closed ) &&
					 ( table->conn[0].state == RBD_CONN_UP ) );
		ok ( sock->sent_len > before );
		out->sent2_len = ( ( sock->sent_len < sizeof ( out->sent2 ) ) ?
				   sock->sent_len : sizeof ( out->sent2 ) );
		memcpy ( out->sent2, sock->sent, out->sent2_len );
		ok ( table->conn[0].backlog_len == 0 );
	}
	good = 1;
 out:
	if ( table ) {
		rbd_conn_shutdown ( table );
		ok ( rbd_conn_live ( table ) == 0 );
	}
	if ( client )
		wr_client_destroy ( client );
	ufree ( arena_ptr );
	ufree ( bulk_ptr );
	free ( spec );
	free ( table );
	free ( socks );
	socks = NULL;
	return good;
}

/**
 * Check the table against the real core
 *
 */
static void rbd_conn_real_core_ok ( void ) {
	static struct real_flight a;
	static struct real_flight b;
	static struct real_flight c;
	size_t heap = heap_probe();
	size_t i;

	real_wakes = 0;

	/* The whole first flight in one go, then the same with seven bytes per ACK, then with one byte: the same bytes */
	ok ( real_flight_run ( 0, &a, 0 ) );
	ok ( a.established );
	ok ( a.sent_len >= 8 );
	ok ( memcmp ( a.sent, "ceph v2\n", 8 ) == 0 );
	ok ( real_flight_run ( 7, &b, 0 ) );
	ok ( b.sent_len == a.sent_len );
	ok ( memcmp ( a.sent, b.sent, a.sent_len ) == 0 );
	ok ( b.packets > a.packets );
	ok ( real_flight_run ( 1, &c, 1 ) );
	ok ( c.sent_len == a.sent_len );
	ok ( memcmp ( a.sent, c.sent, a.sent_len ) == 0 );
	ok ( c.packets == c.sent_len );

	/* A peer with a proper banner, delivered whole, three bytes at a time and one byte at a time: the client carries on
	 * with its HELLO and what it sends does not depend on how the peer's bytes came
	 */
	real_rx_chunk = 64;
	ok ( real_flight_run ( 0, &a, 0 ) );
	real_rx_chunk = 3;
	ok ( real_flight_run ( 7, &b, 0 ) );
	real_rx_chunk = 1;
	ok ( real_flight_run ( 0, &c, 0 ) );
	real_rx_chunk = 0;
	ok ( a.up_after_banner );
	ok ( b.up_after_banner );
	ok ( c.up_after_banner );
	ok ( a.sent2_len > a.sent_len );
	ok ( b.sent2_len == a.sent2_len );
	ok ( c.sent2_len == a.sent2_len );
	ok ( memcmp ( a.sent2, b.sent2, a.sent2_len ) == 0 );
	ok ( memcmp ( a.sent2, c.sent2, a.sent2_len ) == 0 );
	ok ( memcmp ( a.sent2, a.sent, a.sent_len ) == 0 );

	/* The core dialled the monitor it was given, once per flight */
	ok ( a.peer.st_family == AF_INET );
	ok ( memcmp ( &a.peer, &b.peer, sizeof ( a.peer ) ) == 0 );

	/* The flight is not made of zeros or of one repeated byte (a banner and, if the core sends it at once, the hello) */
	for ( i = 1 ; i < a.sent_len ; i++ ) {
		if ( a.sent[i] != a.sent[0] )
			break;
	}
	ok ( i < a.sent_len );
	ok ( ( heap_probe() + 1 ) >= heap );
}

/****************************************************************************
 *
 * The owner's reference, a table that is not attached, a core that miscounts
 *
 ****************************************************************************
 */

/** What the free function of the owner leaves in the id of every slot, so that a slot released after the owner was freed is seen */
#define REFOBJ_POISON 0xdead0001U

/** The owner of a table: reference counted, like the session that holds it (the table is part of it) */
struct refobj {
	/** Reference counter (an interface plugged into the table or a running timer holds one reference) */
	struct refcnt refcnt;
	/** The table */
	struct rbd_conn_table table;
	/** Times the free function ran */
	unsigned int freed;
};

/**
 * Free the owner (the test frees the memory itself; this only marks the moment)
 *
 * @v refcnt		Reference counter
 *
 * Writes into the table the way freed memory would look to a function that goes on using the table: every slot looks
 * live (CONNECTING, with a poison id). A release that comes after this overwrites the id, which the test sees.
 */
static void refobj_free ( struct refcnt *refcnt ) {
	struct refobj *obj = container_of ( refcnt, struct refobj, refcnt );
	unsigned int i;

	obj->freed++;
	for ( i = 0 ; i < RBD_CONN_SLOTS ; i++ ) {
		obj->table.conn[i].id = REFOBJ_POISON;
		obj->table.conn[i].state = RBD_CONN_CONNECTING;
	}
}

/**
 * Start a test with a table that has a reference counted owner
 *
 * @v fix		Fixture (only its table pointer is set, to the owner's table)
 * @ret obj		The owner, or NULL (a failure has been counted)
 */
static struct refobj * refobj_start ( struct fixture *fix ) {
	struct refobj *obj;

	memset ( fix, 0, sizeof ( *fix ) );
	fc = zalloc ( sizeof ( *fc ) );
	socks = zalloc ( FAKE_SOCKS * sizeof ( socks[0] ) );
	obj = zalloc ( sizeof ( *obj ) );
	if ( ! ( fc && socks && obj ) ) {
		free ( fc );
		free ( socks );
		free ( obj );
		fc = NULL;
		socks = NULL;
		ok ( 0 );
		return NULL;
	}
	socks_n = 0;
	fake_open_rc = 0;
	ref_init ( &obj->refcnt, refobj_free );
	rbd_conn_init ( &obj->table, &obj->refcnt, fc_wake, NULL );
	obj->table.ops = &fake_conn_ops;
	rbd_conn_attach ( &obj->table, ( wr_client * ) fc );
	fix->table = &obj->table;
	return obj;
}

/**
 * Finish a test that used refobj_start()
 *
 * @v obj		Owner
 * @v heap_before	Free heap measured before the test
 */
static void refobj_end ( struct refobj *obj, size_t heap_before ) {
	size_t heap_after;

	ok ( fc->stale_calls == 0 );
	free ( obj );
	free ( socks );
	free ( fc );
	fc = NULL;
	socks = NULL;
	heap_after = heap_probe();
	ok ( ( heap_after + 1 ) >= heap_before );
}

/**
 * Check that no reference is leaked or dropped twice, and that the owner may go before the table is shut down
 *
 * The other tests give the table no owner (a NULL reference counter, as the fake socket has none), so a socket or a
 * timer that was left holding a reference, or a reference let go twice, was invisible to them.
 */
static void rbd_conn_refcnt_ok ( void ) {
	struct fixture fix;
	struct refobj *obj;
	struct fake_sock *sock;
	struct fake_sock *sock3;
	size_t heap = heap_probe();
	uint8_t data[40];
	unsigned int i;

	obj = refobj_start ( &fix );
	if ( ! obj )
		return;
	ok ( obj->refcnt.count == 0 );

	/* Connecting: the socket and the connect timer each hold one reference; established: only the socket */
	fc_push_connect4 ( fc_id ( 0, 1 ), addr_a, 3300, 5000 );
	rbd_conn_drain ( fix.table );
	ok ( obj->refcnt.count == 2 );
	sock = sock_of ( &fix, 0 );
	ok ( sock != NULL );
	if ( ! sock )
		goto out;
	sock->window = 1460;
	xfer_window_changed ( &sock->intf );
	ok ( fix.table->conn[0].state == RBD_CONN_UP );
	ok ( obj->refcnt.count == 1 );

	/* Closed by the peer: both references are back */
	sock->open = 0;
	intf_shutdown ( &sock->intf, -ECONNRESET );
	ok ( fix.table->conn[0].state == RBD_CONN_FREE );
	ok ( obj->refcnt.count == 0 );

	/* Closed by the core */
	sock = connect_up ( &fix, 1, 1 );
	ok ( obj->refcnt.count == 1 );
	fc_push_close ( fc_id ( 1, 1 ) );
	rbd_conn_drain ( fix.table );
	ok ( obj->refcnt.count == 0 );

	/* A timeout while connecting */
	fc_push_connect4 ( fc_id ( 2, 1 ), addr_a, 3300, 2500 );
	rbd_conn_drain ( fix.table );
	ok ( obj->refcnt.count == 2 );
	fix.table->conn[2].timer.expired ( &fix.table->conn[2].timer, 0 );
	ok ( obj->refcnt.count == 0 );

	/* A socket that cannot be opened holds nothing, and neither does a replaced one */
	fake_open_rc = -ENETUNREACH;
	fc_push_connect4 ( fc_id ( 3, 1 ), addr_a, 3300, 5000 );
	rbd_conn_drain ( fix.table );
	fake_open_rc = 0;
	ok ( obj->refcnt.count == 0 );
	fc_push_connect4 ( fc_id ( 3, 2 ), addr_a, 3300, 5000 );
	rbd_conn_drain ( fix.table );
	fc_push_connect4 ( fc_id ( 3, 3 ), addr_b, 3300, 5000 );
	rbd_conn_drain ( fix.table );
	ok ( obj->refcnt.count == 2 );
	ok ( socks_n == 5 );

	/* A socket that closes from inside a send, with data parked for the core: all references and the parked buffers go */
	sock = connect_up ( &fix, 4, 1 );
	if ( ! sock )
		goto out;
	fc->conn[4].rx_room = 100;
	ok ( xfer_window ( &sock->intf ) == 100 );
	fc->conn[4].rx_room = 0;
	for ( i = 0 ; i < sizeof ( data ) ; i++ )
		data[i] = i;
	ok ( sock_send ( sock, data, sizeof ( data ) ) == 0 );
	ok ( fix.table->conn[4].backlog_len == sizeof ( data ) );
	fc_queue_tx ( fc_id ( 4, 1 ), 10, 10 );
	sock->window = 1460;
	sock->deliver_closes = 1;
	sock->deliver_closes_rc = -ECONNRESET;
	rbd_conn_service ( fix.table );
	ok ( fix.table->conn[4].state == RBD_CONN_FREE );
	ok ( list_empty ( &fix.table->conn[4].backlog ) );
	ok ( fix.table->conn[4].backlog_len == 0 );

	/* Shut down with sockets open (slot 3 is still connecting: socket and timer): all references are given back */
	ok ( obj->refcnt.count == 2 );
	rbd_conn_shutdown ( fix.table );
	ok ( obj->refcnt.count == 0 );
	ok ( obj->freed == 0 );

	/* The owner lets go of its own reference while two sockets are still open: they keep it alive, and a shutdown that
	 * lets go of the last of them frees the owner at its very end, not in the middle of its loop over the slots
	 */
	rbd_conn_init ( fix.table, &obj->refcnt, fc_wake, NULL );
	fix.table->ops = &fake_conn_ops;
	rbd_conn_attach ( fix.table, ( wr_client * ) fc );
	sock = connect_up ( &fix, 0, 7 );
	sock3 = connect_up ( &fix, 3, 7 );
	if ( ! ( sock && sock3 ) )
		goto out;
	ok ( obj->refcnt.count == 2 );
	ref_put ( &obj->refcnt );
	ok ( obj->freed == 0 );
	ok ( obj->refcnt.count == 1 );
	rbd_conn_shutdown ( fix.table );
	ok ( sock->closed == 1 );
	ok ( sock3->closed == 1 );
	ok ( obj->freed == 1 );
	for ( i = 0 ; i < RBD_CONN_SLOTS ; i++ )
		ok ( obj->table.conn[i].id == REFOBJ_POISON );
 out:
	refobj_end ( obj, heap );
}

/**
 * Check that a table with no core opens no socket
 *
 * Before the client is attached and after the table has been shut down there is nobody to tell about a socket and nobody to
 * serve it: a CONNECT is refused, and nothing is opened that would outlive the session.
 */
static void rbd_conn_no_client_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	wr_action action;
	size_t heap = heap_probe();

	if ( ! fixture_start ( &fix ) )
		return;
	memset ( &action, 0, sizeof ( action ) );
	action.kind = WR_ACT_CONNECT;
	action.conn = fc_id ( 1, 1 );
	action.addr.family = WR_AF_IPV4;
	rbd_conn_test_copy ( action.addr.ip, addr_a, 4 );
	action.addr.port = 3300;
	action.timeout_ms = 1000;

	/* Never attached */
	fix.table->client = NULL;
	ok ( rbd_conn_error_kind ( rbd_conn_action ( fix.table, &action ) ) ==
	     rbd_conn_error_kind ( -ENOTCONN ) );
	ok ( socks_n == 0 );
	ok ( rbd_conn_live ( fix.table ) == 0 );
	ok ( ! timer_running ( &fix.table->conn[0].timer ) );
	ok ( fc->closed_n == 0 );

	/* Attached: it works */
	rbd_conn_attach ( fix.table, ( wr_client * ) fc );
	fc->conn[1].id = action.conn;
	ok ( rbd_conn_action ( fix.table, &action ) == 0 );
	ok ( socks_n == 1 );
	sock = sock_of ( &fix, 1 );
	ok ( sock != NULL );

	/* Data for a table whose core has gone is refused, and its buffer is freed (the heap check of the fixture sees a leak) */
	fix.table->client = NULL;
	ok ( rbd_conn_error_kind ( sock_send ( sock, "abc", 3 ) ) ==
	     rbd_conn_error_kind ( -ENOTCONN ) );
	rbd_conn_attach ( fix.table, ( wr_client * ) fc );

	/* Shut down: refused again, and nothing is left running */
	rbd_conn_shutdown ( fix.table );
	ok ( rbd_conn_live ( fix.table ) == 0 );
	ok ( sock && ( sock->closed == 1 ) );
	action.conn = fc_id ( 2, 1 );
	ok ( rbd_conn_action ( fix.table, &action ) != 0 );
	ok ( socks_n == 1 );
	ok ( rbd_conn_live ( fix.table ) == 0 );
	ok ( ! timer_running ( &fix.table->conn[1].timer ) );
	ok ( ! timer_running ( &fix.table->conn[2].timer ) );
	ok ( fc->closed_n == 0 );
	fixture_end ( &fix, heap );
}

/**
 * Check that a slot used again starts afresh
 *
 * What the previous connection of a slot learned about the core's room must not decide how much the next one may park.
 */
static void rbd_conn_slot_reuse_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	struct rbd_conn *conn;
	size_t heap = heap_probe();
	uint8_t data[64];

	if ( ! fixture_start ( &fix ) )
		return;
	conn = &fix.table->conn[2];
	memset ( data, 0x5a, sizeof ( data ) );

	/* The first connection saw a room of 100 */
	sock = connect_up ( &fix, 2, 1 );
	if ( ! sock )
		goto out;
	fc->conn[2].rx_room = 100;
	ok ( xfer_window ( &sock->intf ) == 100 );
	ok ( conn->adv_max == 100 );
	fc_push_close ( fc_id ( 2, 1 ) );
	rbd_conn_drain ( fix.table );
	ok ( conn->state == RBD_CONN_FREE );

	/* The next one starts with nothing announced, and learns its own room: with a room of 10 it may park 10 bytes, not 64 */
	sock = connect_up ( &fix, 2, 2 );
	if ( ! sock )
		goto out;
	ok ( conn->adv_max == 0 );
	ok ( conn->backlog_len == 0 );
	fc->conn[2].rx_room = 10;
	ok ( xfer_window ( &sock->intf ) == 10 );
	ok ( conn->adv_max == 10 );
	fc->conn[2].rx_room = 0;
	ok ( sock_send ( sock, data, sizeof ( data ) ) != 0 );
	ok ( conn->state == RBD_CONN_FREE );
	ok ( conn->backlog_len == 0 );
	ok ( list_empty ( &conn->backlog ) );
	ok ( fc->closed_n == 2 );
	ok ( fc->closed_id[1] == fc_id ( 2, 2 ) );
	ok ( rbd_conn_error_kind ( fc->closed_errno[1] ) ==
	     rbd_conn_error_kind ( -ENOBUFS ) );
 out:
	fixture_end ( &fix, heap );
}

/**
 * Check a transport that is ready the moment it is opened, a socket that closes while its window is asked, and the limit of
 * one drain
 */
static void rbd_conn_edges_ok ( void ) {
	struct fixture fix;
	struct fake_sock *sock;
	wr_action action;
	size_t heap = heap_probe();
	unsigned int i;

	if ( ! fixture_start ( &fix ) )
		return;

	/* A socket with a window as soon as it is opened is established at once, and its timer does not keep running */
	fake_open_window = 1460;
	fc_push_connect4 ( fc_id ( 0, 1 ), addr_a, 3300, 5000 );
	ok ( rbd_conn_drain ( fix.table ) == 1 );
	fake_open_window = 0;
	ok ( fix.table->conn[0].state == RBD_CONN_UP );
	ok ( fc->connected_n == 1 );
	ok ( ! timer_running ( &fix.table->conn[0].timer ) );

	/* A socket that closes while the table asks for its window: the table looks at the slot again and goes no further (it
	 * must not ask the core for bytes of a connection it has just told the core is gone)
	 */
	sock = sock_of ( &fix, 0 );
	ok ( sock != NULL );
	if ( ! sock )
		goto out;
	fc_queue_tx ( fc_id ( 0, 1 ), 30, 30 );
	sock->window = 1460;
	sock->window_closes = 1;
	fc->closed_n = 0;
	rbd_conn_service ( fix.table );
	ok ( fix.table->conn[0].state == RBD_CONN_FREE );
	ok ( fc->closed_n == 1 );
	ok ( sock->deliveries == 0 );
	ok ( fc->stale_calls == 0 );

	/* One drain takes at most RBD_CONN_ACTION_MAX actions and says so, so that the session calls again */
	memset ( &action, 0, sizeof ( action ) );
	action.kind = WR_ACT_TX_READY;
	for ( i = 0 ; i < ( RBD_CONN_ACTION_MAX + 36 ) ; i++ )
		fc_push ( &action );
	ok ( rbd_conn_drain ( fix.table ) == RBD_CONN_ACTION_MAX );
	ok ( rbd_conn_drain ( fix.table ) == 36 );
	ok ( rbd_conn_drain ( fix.table ) == 0 );
 out:
	fixture_end ( &fix, heap );
}

/** A core that reports more gather elements than it was given room for */
static size_t fc_tx_peek_over ( wr_client *c, wr_conn_id id, wr_iov *iov,
				size_t max_iov ) {

	return ( fc_tx_peek ( c, id, iov, max_iov ) + 5 );
}

/** A core that reports having taken more bytes than it was given */
static size_t fc_rx_push_over ( wr_client *c, wr_conn_id id,
				const uint8_t *data, size_t n ) {
	size_t taken = fc_rx_push ( c, id, data, n );

	return ( taken ? ( taken + 7 ) : 0 );
}

/**
 * Check that a core that miscounts does not make the table read or free past what it has
 *
 * The contract of wr_client.h says a core never does either; the table does not trust the count with memory it owns.
 */
static void rbd_conn_hostile_core_ok ( void ) {
	static struct rbd_conn_ops over_ops;
	struct fixture fix;
	struct fake_sock *sock;
	uint8_t data[10];
	size_t heap = heap_probe();
	size_t i;

	if ( ! fixture_start ( &fix ) )
		return;
	over_ops = fake_conn_ops;
	over_ops.tx_peek = fc_tx_peek_over;
	over_ops.rx_push = fc_rx_push_over;
	fix.table->ops = &over_ops;
	sock = connect_up ( &fix, 0, 1 );
	if ( ! sock )
		goto out;

	/* More elements than the table asked for: only the elements the gather list has are sent (one byte each here) */
	fc_queue_tx ( fc_id ( 0, 1 ), 40, 1 );
	sock->window = 1460;
	rbd_conn_service ( fix.table );
	ok ( sock->sent_len == RBD_CONN_IOV );
	ok ( sock_got_pattern ( sock, RBD_CONN_IOV ) );

	/* More bytes than were given: the buffer is not pulled past its end, the backlog does not go below zero */
	for ( i = 0 ; i < sizeof ( data ) ; i++ )
		data[i] = ( 0x80 + i );
	fc->conn[0].rx_room = 100;
	ok ( xfer_window ( &sock->intf ) == 100 );
	ok ( sock_send ( sock, data, sizeof ( data ) ) == 0 );
	ok ( fix.table->conn[0].backlog_len == 0 );
	ok ( list_empty ( &fix.table->conn[0].backlog ) );
	fc->conn[0].rx_room = 0;
	ok ( sock_send ( sock, data, sizeof ( data ) ) == 0 );
	ok ( fix.table->conn[0].backlog_len == sizeof ( data ) );
	fc->conn[0].rx_room = 100;
	rbd_conn_service ( fix.table );
	ok ( fix.table->conn[0].backlog_len == 0 );
	ok ( list_empty ( &fix.table->conn[0].backlog ) );
 out:
	fixture_end ( &fix, heap );
}

/**
 * Check a status that is not an iPXE error code
 *
 * An open that fails with the most negative int must not overflow when the status is made positive for the core.
 */
static void rbd_conn_extreme_status_ok ( void ) {
	struct fixture fix;
	size_t heap = heap_probe();

	if ( ! fixture_start ( &fix ) )
		return;
	fake_open_rc = ( -2147483647 - 1 );
	fc_push_connect4 ( fc_id ( 0, 1 ), addr_a, 3300, 5000 );
	rbd_conn_drain ( fix.table );
	fake_open_rc = 0;
	ok ( fc->closed_n == 1 );
	ok ( fc->closed_errno[0] == 2147483647 );
	ok ( rbd_conn_live ( fix.table ) == 0 );
	fixture_end ( &fix, heap );
}

/** Run all the tests */
static void rbd_conn_test_exec ( void ) {

	rbd_conn_convert_ok();
	rbd_conn_clock_ok();
	rbd_conn_wall_ok();
	rbd_conn_now_ok();
	rbd_conn_random_ok();
	rbd_conn_gather_ok();
	rbd_conn_connect_ok();
	rbd_conn_timeout_ok();
	rbd_conn_fail_ok();
	rbd_conn_close_ok();
	rbd_conn_transmit_ok();
	rbd_conn_transmit_close_ok();
	rbd_conn_receive_ok();
	rbd_conn_backlog_bound_ok();
	rbd_conn_early_data_ok();
	rbd_conn_wake_ok();
	rbd_conn_refcnt_ok();
	rbd_conn_no_client_ok();
	rbd_conn_slot_reuse_ok();
	rbd_conn_edges_ok();
	rbd_conn_hostile_core_ok();
	rbd_conn_extreme_status_ok();
	rbd_conn_real_core_ok();
}

/** The pump host self-test */
struct self_test rbd_conn_test __self_test = {
	.name = "rbd_conn_test",
	.exec = rbd_conn_test_exec,
};
