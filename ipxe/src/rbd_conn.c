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

/* Secure Boot: FORBIDDEN, like every file of the driver (docs/design/ipxe-driver.md, section 13). This file is the first
 * code to see the bytes that come from the network (the cluster's replies and anything in between) and it hands them to a
 * core that has not had the security review iPXE requires for PERMITTED; the login and the data of every request go through its
 * sockets.
 */
FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

/** @file
 *
 * RBD (Ceph) SAN protocol: the pump host
 *
 * The core never opens a socket: it asks (WR_ACT_CONNECT, WR_ACT_CLOSE), the host does it and reports back. This
 * file is that host for iPXE: one struct interface per connection slot of the core, opened with xfer_open_socket(),
 * a deliver handler that pushes received data into the core's receive window, a transmit step that offers the core's
 * pending bytes to the socket as far as xfer_window() allows (iPXE's TCP accepts one unacknowledged packet at a
 * time: partial acceptance is the normal case), a connect timer per slot, and the time, random and log callbacks of
 * the core's host table (docs/design/ipxe-driver.md, section 4). The declarations are in rbd_conn.h.
 *
 * Structure follows iscsi.c (the socket interface, the "resume on window change" pattern of iscsi_tx_resume()) and
 * the usage notes of wr_client.h; there is no protocol logic here.
 *
 * Rules this file keeps (the reason for each is in the function that applies it):
 *
 *   - Delivery from the network (xfer_deliver, xfer_window_changed, intf_close, the connect timer) only pushes into
 *     the core and calls wake(): it never calls wr_client_run(). iPXE may close an interface synchronously inside
 *     any call into TCP, so every function that calls into TCP re-checks the slot afterwards.
 *   - Every byte iPXE's TCP has acknowledged is either in the core or in the connection's backlog (TCP drops a
 *     segment whose delivery fails after acknowledging it), and the backlog is bounded by the window announced.
 *   - Large objects are not on the stack (the BIOS stack is 4 kB): the gather list is part of the table.
 *   - No 64-bit division (i386 has no division helper in this build): time conversion is a multiply and a shift.
 *   - Random bytes come from the DRBG or not at all.
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <byteswap.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/open.h>
#include <ipxe/interface.h>
#include <ipxe/socket.h>
#include <ipxe/in.h>
#include <ipxe/tcpip.h>
#include <ipxe/timer.h>
#include <ipxe/retry.h>
#include <ipxe/rbg.h>
#include <ipxe/list.h>
#include "rbd_conn.h"

#if ( TICKS_PER_SEC != 1024 )
#error "rbd_conn.c converts ticks to milliseconds as ticks * 125 / 128: it needs TICKS_PER_SEC == 1024"
#endif

/** The largest 64-bit value */
#define RBD_CONN_U64_MAX ( ~( uint64_t ) 0 )

/** Random bytes asked of the DRBG at a time (SP 800-90A limits one request; the core asks for a few dozen bytes) */
#define RBD_CONN_RANDOM_CHUNK 1024

/** A socket address of any family the core can dial */
union rbd_conn_sockaddr {
	struct sockaddr sa;
	struct sockaddr_tcpip st;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

/****************************************************************************
 *
 * Time
 *
 ****************************************************************************
 */

/**
 * Convert ticks to milliseconds
 *
 * @v ticks		Ticks of iPXE's clock (TICKS_PER_SEC is 1024)
 * @ret ms		Milliseconds
 *
 * ms = ticks * 1000 / 1024 = ticks * 125 / 128 exactly. Written as quotient and remainder of 128 so that the
 * multiplication cannot overflow for any 64-bit input (ticks >> 7 is below 2^57 and 125 < 2^7) and no division
 * is needed; the function is monotonic by construction.
 */
uint64_t rbd_conn_ticks_to_ms ( uint64_t ticks ) {

	return ( ( ( ticks >> 7 ) * 125 ) + ( ( ( ticks & 127 ) * 125 ) >> 7 ) );
}

/**
 * Convert milliseconds to ticks, rounding up
 *
 * @v ms		Milliseconds
 * @ret ticks		Ticks (at least one: a timer of zero ticks would fire before the connect could start)
 *
 * ceil ( ms * 128 / 125 ), in 32 bits: ms is clamped to a day, so every intermediate value fits.
 */
unsigned long rbd_conn_ms_to_ticks ( uint32_t ms ) {
	uint32_t whole;
	uint32_t rest;
	uint32_t ticks;

	if ( ms > RBD_CONN_TIMEOUT_MAX_MS )
		ms = RBD_CONN_TIMEOUT_MAX_MS;
	whole = ( ms / 125 );
	rest = ( ms % 125 );
	ticks = ( ( whole * 128 ) + ( ( ( rest * 128 ) + 124 ) / 125 ) );
	return ( ticks ? ticks : 1 );
}

/**
 * Advance the 64-bit tick count to a raw clock reading
 *
 * @v clock		Clock
 * @v raw		Raw value of currticks() (unsigned long: 32 bits on i386, 64 bits elsewhere)
 * @ret ticks		Ticks since the epoch of this clock; never decreases
 *
 * The difference to the last reading is taken modulo the width of unsigned long and read as signed, so a counter that
 * wraps counts on, and a reading that is behind the last one (a firmware clock that steps back, for example at the
 * BIOS midnight rollover) counts as no time rather than as nearly a full wrap.
 */
uint64_t rbd_clock_advance ( struct rbd_clock *clock, unsigned long raw ) {
	signed long delta;

	if ( ! clock->started ) {
		clock->started = 1;
		clock->ticks = ( ( uint64_t ) raw + RBD_CLOCK_EPOCH_TICKS );
	} else {
		delta = ( signed long ) ( raw - clock->last );
		if ( delta > 0 )
			clock->ticks += ( unsigned long ) delta;
	}
	clock->last = raw;
	return clock->ticks;
}

/**
 * Get the wall clock for a monotonic time, given what the platform says the time is
 *
 * @v clock		Clock
 * @v mono_ms		Monotonic milliseconds now
 * @v seconds		Seconds since the Unix epoch as the platform reports them (zero or negative: it has no clock)
 * @ret wall_ms		Milliseconds since the Unix epoch, or 0 when the platform has no wall clock
 *
 * The platform clock is read when it is due (every RBD_CLOCK_WALL_REFRESH_MS of monotonic time) and the time in
 * between is the monotonic clock plus the offset found at the last reading: the BIOS reads its RTC with a spin on the
 * update flag, which a pass of the session's process must not pay for. The caller passes the reading only when it
 * is due (see rbd_clock_wall()); this function is the pure part.
 */
uint64_t rbd_clock_wall_at ( struct rbd_clock *clock, uint64_t mono_ms,
			     int64_t seconds ) {

	if ( ( seconds > 0 ) &&
	     ( ( uint64_t ) seconds <= ( RBD_CONN_U64_MAX / 1000 ) ) ) {
		clock->wall_base_ms = ( ( ( uint64_t ) seconds * 1000 ) - mono_ms );
		clock->wall_valid = 1;
	}
	if ( mono_ms > ( RBD_CONN_U64_MAX - RBD_CLOCK_WALL_REFRESH_MS ) ) {
		clock->wall_next_ms = RBD_CONN_U64_MAX;
	} else {
		clock->wall_next_ms = ( mono_ms + RBD_CLOCK_WALL_REFRESH_MS );
	}
	return ( clock->wall_valid ? ( clock->wall_base_ms + mono_ms ) : 0 );
}

/**
 * Get the wall clock
 *
 * @v clock		Clock
 * @v mono_ms		Monotonic milliseconds now
 * @ret wall_ms		Milliseconds since the Unix epoch, or 0 when the platform has no wall clock
 */
static uint64_t rbd_clock_wall ( struct rbd_clock *clock, uint64_t mono_ms ) {

	/* Between readings, extrapolate from the last one (a platform with no clock is not asked again before it is due either) */
	if ( mono_ms < clock->wall_next_ms )
		return ( clock->wall_valid ? ( clock->wall_base_ms + mono_ms ) : 0 );

	/* Read the platform clock (time() is zero where there is none) */
	return rbd_clock_wall_at ( clock, mono_ms, ( int64_t ) time ( NULL ) );
}

/**
 * Get the time for the core
 *
 * @v table		Connection table
 * @v now		Clock to fill in
 */
void rbd_conn_now ( struct rbd_conn_table *table, wr_clock *now ) {

	now->mono_ms = rbd_conn_ticks_to_ms ( rbd_clock_advance ( &table->clock,
								  currticks() ) );
	now->wall_ms = rbd_clock_wall ( &table->clock, now->mono_ms );
}

/****************************************************************************
 *
 * Random and log
 *
 ****************************************************************************
 */

/**
 * Get random bytes from the DRBG
 *
 * @v out		Buffer
 * @v len		Length
 * @ret rc		Return status code
 */
static int rbd_conn_generate ( void *out, size_t len ) {
	size_t frag_len;
	int rc;

	while ( len ) {
		frag_len = ( ( len > RBD_CONN_RANDOM_CHUNK ) ?
			     RBD_CONN_RANDOM_CHUNK : len );
		if ( ( rc = rbg_generate ( NULL, 0, 0, out, frag_len ) ) != 0 )
			return rc;
		out += frag_len;
		len -= frag_len;
	}
	return 0;
}

/**
 * Get random bytes for the core
 *
 * @v ctx		The connection table, or NULL for the default source
 * @v out		Buffer to fill
 * @v len		Number of bytes
 * @ret st		WR_OK, or WR_E_HOST_RANDOM: the core fails the connection; there is no weak fallback
 */
wr_status rbd_conn_random ( void *ctx, uint8_t *out, size_t len ) {
	struct rbd_conn_table *table = ctx;
	const struct rbd_conn_ops *ops;

	ops = ( table ? table->ops : &rbd_conn_default_ops );
	if ( ops->generate ( out, len ) != 0 )
		return WR_E_HOST_RANDOM;
	return WR_OK;
}

/**
 * Log a record of the core
 *
 * @v ctx		Context (unused)
 * @v rec		Log record
 *
 * The record is a static message and four numbers; the core puts no key material, ticket or payload in it. It is
 * printed only in a build that has debugging enabled for this object (DEBUG=rbd_conn).
 */
void rbd_conn_log ( void *ctx __unused, const wr_log_rec *rec ) {
	static const char levels[] = "?EWIDT";

	if ( ! rec )
		return;
	DBGC ( rec, "RBD %c mod %d conn %#x st %d: %s %#llx %#llx %#llx %#llx\n",
	       ( ( rec->level < ( sizeof ( levels ) - 1 ) ) ?
		 levels[rec->level] : '?' ), rec->module, rec->conn,
	       rec->status, ( rec->msg ? rec->msg : "" ),
	       ( ( unsigned long long ) rec->a0 ),
	       ( ( unsigned long long ) rec->a1 ),
	       ( ( unsigned long long ) rec->a2 ),
	       ( ( unsigned long long ) rec->a3 ) );
}

/**
 * Fill in the core's host table
 *
 * @v table		Connection table
 * @v host		Host table to fill in
 */
void rbd_conn_host_ops ( struct rbd_conn_table *table, wr_host_ops *host ) {

	memset ( host, 0, sizeof ( *host ) );
	host->size = sizeof ( *host );
	host->ctx = table;
	host->random = rbd_conn_random;
	host->log = rbd_conn_log;
}

/****************************************************************************
 *
 * Sockets
 *
 ****************************************************************************
 */

/**
 * Open a TCP connection
 *
 * @v intf		Socket interface
 * @v peer		Peer socket address
 * @ret rc		Return status code
 */
static int rbd_conn_open_tcp ( struct interface *intf, struct sockaddr *peer ) {

	return xfer_open_socket ( intf, SOCK_STREAM, peer, NULL );
}

/** Production sockets, random and core calls */
const struct rbd_conn_ops rbd_conn_default_ops = {
	.open = rbd_conn_open_tcp,
	.generate = rbd_conn_generate,
	.next_action = wr_client_next_action,
	.connected = wr_conn_connected,
	.closed = wr_conn_closed,
	.rx_window = wr_conn_rx_window,
	.rx_push = wr_conn_rx_push,
	.tx_peek = wr_conn_tx_peek,
	.tx_consume = wr_conn_tx_consume,
};

/**
 * Wake the session's process
 *
 * @v table		Connection table
 */
static void rbd_conn_wake ( struct rbd_conn_table *table ) {

	if ( table->wake )
		table->wake ( table->wake_ctx );
}

/**
 * Convert an iPXE error code into what the core's diagnostics carry
 *
 * @v rc		Return status code
 * @ret host_errno	Zero for an orderly close, else the iPXE error code made positive (strerror() prints it)
 */
static int rbd_conn_errno ( int rc ) {

	/* (-INT_MIN does not exist; no iPXE error code is that, but a value from a callback is not trusted to be one) */
	if ( rc == ( -2147483647 - 1 ) )
		return 2147483647;
	return ( ( rc < 0 ) ? -rc : rc );
}

/**
 * Free the receive backlog of a connection
 *
 * @v conn		Connection
 */
static void rbd_conn_backlog_free ( struct rbd_conn *conn ) {
	struct io_buffer *iobuf;
	struct io_buffer *tmp;

	list_for_each_entry_safe ( iobuf, tmp, &conn->backlog, list ) {
		list_del ( &iobuf->list );
		free_iob ( iobuf );
	}
	conn->backlog_len = 0;
}

/**
 * Release a connection slot
 *
 * @v conn		Connection
 * @v rc		Reason for closing (zero: orderly)
 * @v report		Tell the core that the connection is gone
 *
 * Used for every end of a connection: a close from the peer, a close the core asked for, a timeout, an error of ours.
 * The state is changed first, so that a callback re-entering from the interface teardown finds a free slot.
 */
static void rbd_conn_release ( struct rbd_conn *conn, int rc, int report ) {
	struct rbd_conn_table *table = conn->table;
	wr_conn_id id = conn->id;

	if ( conn->state == RBD_CONN_FREE )
		return;
	conn->state = RBD_CONN_FREE;
	conn->id = WR_CONN_NONE;
	stop_timer ( &conn->timer );
	rbd_conn_backlog_free ( conn );
	intf_restart ( &conn->intf, rc );
	if ( report && table->client )
		table->ops->closed ( table->client, id, rbd_conn_errno ( rc ) );
	rbd_conn_wake ( table );
}

/**
 * Mark a connecting socket as established and tell the core
 *
 * @v conn		Connection (in state RBD_CONN_CONNECTING)
 */
static void rbd_conn_up ( struct rbd_conn *conn ) {
	struct rbd_conn_table *table = conn->table;

	conn->state = RBD_CONN_UP;
	stop_timer ( &conn->timer );
	if ( table->client )
		table->ops->connected ( table->client, conn->id );
	rbd_conn_wake ( table );
}

/**
 * Check whether a connecting socket has become established
 *
 * @v conn		Connection
 *
 * Established means that the socket will take data: xfer_window() is not zero (TCP: the connection can send and its
 * transmit queue is empty). This runs inline from the window-changed event, before TCP builds the ACK that completes
 * the handshake, so that the receive window TCP announces already is the core's (the core's window is zero until it
 * has been told the connection is up).
 */
static void rbd_conn_check_up ( struct rbd_conn *conn ) {

	if ( conn->state != RBD_CONN_CONNECTING )
		return;
	if ( ! xfer_window ( &conn->intf ) )
		return;
	rbd_conn_up ( conn );
}

/**
 * Handle the connect timeout
 *
 * @v timer		Connect timer
 * @v over		Failure indicator (unused: the timer is fixed, so any expiry is final)
 */
static void rbd_conn_expired ( struct retry_timer *timer, int over __unused ) {
	struct rbd_conn *conn = container_of ( timer, struct rbd_conn, timer );

	if ( conn->state != RBD_CONN_CONNECTING )
		return;
	DBGC ( conn->table, "RBD conn %#x connect timed out\n", conn->id );
	rbd_conn_release ( conn, -ETIMEDOUT, 1 );
}

/**
 * Close a connection socket (the peer or TCP closed it)
 *
 * @v conn		Connection
 * @v rc		Reason for close
 */
static void rbd_conn_close ( struct rbd_conn *conn, int rc ) {

	DBGC ( conn->table, "RBD conn %#x closed by the socket: %s\n", conn->id,
	       strerror ( rc ) );
	rbd_conn_release ( conn, rc, 1 );
}

/**
 * Handle a change of the socket's transmit window
 *
 * @v conn		Connection
 *
 * The pattern of iscsi_tx_resume(): the next packet can go once the previous one has been acknowledged.
 */
static void rbd_conn_window_changed ( struct rbd_conn *conn ) {

	/* A window that fell to zero (our own packet is in flight) has nothing for the session to do; the ACK that opens it
	 * again is the event that does
	 */
	rbd_conn_check_up ( conn );
	if ( ( conn->state == RBD_CONN_UP ) && xfer_window ( &conn->intf ) )
		rbd_conn_wake ( conn->table );
}

/**
 * Check the receive window of a connection
 *
 * @v conn		Connection
 * @ret len		Window length
 *
 * What the core can take, less what already waits in the backlog, and never more than RBD_CONN_RX_WINDOW_MAX: iPXE's TCP
 * announces this to the peer, so the peer is held back by the core's own buffer space (real backpressure), and the data TCP
 * may hold out of order (I/O buffers from the 4 MiB heap) is bounded. The room the core offers is remembered (adv_max):
 * whatever TCP lets through was announced as that room less the backlog of the moment, so room itself bounds the backlog.
 */
static size_t rbd_conn_rx_window ( struct rbd_conn *conn ) {
	struct rbd_conn_table *table = conn->table;
	uint8_t *ptr;
	size_t room;

	if ( ( conn->state == RBD_CONN_FREE ) || ( ! table->client ) )
		return 0;
	room = table->ops->rx_window ( table->client, conn->id, &ptr );
	if ( room > RBD_CONN_RX_WINDOW_MAX )
		room = RBD_CONN_RX_WINDOW_MAX;
	if ( room > conn->adv_max )
		conn->adv_max = room;
	if ( room <= conn->backlog_len )
		return 0;
	return ( room - conn->backlog_len );
}

/**
 * Receive data from a core connection's socket
 *
 * @v conn		Connection
 * @v iobuf		I/O buffer
 * @v meta		Data transfer metadata
 * @ret rc		Return status code
 *
 * Copies into the core's window and returns: the core is not run from here. What the window cannot take waits in
 * the backlog, which may not exceed what was announced (TCP sends nothing beyond its window, so this only trips on
 * a socket that is not TCP or on a broken window calculation: the connection is then closed, never grown).
 */
static int rbd_conn_deliver ( struct rbd_conn *conn, struct io_buffer *iobuf,
			      struct xfer_metadata *meta __unused ) {
	struct rbd_conn_table *table = conn->table;
	size_t len;
	size_t taken = 0;

	/* TCP delivers data only on an established connection, so data is proof that this one is up, even if the
	 * window-changed event that announces it was not seen (a peer that opened with a zero window)
	 */
	if ( conn->state == RBD_CONN_CONNECTING )
		rbd_conn_up ( conn );
	if ( ( conn->state != RBD_CONN_UP ) || ( ! table->client ) ) {
		free_iob ( iobuf );
		return -ENOTCONN;
	}

	/* Nothing to do for an empty buffer */
	len = iob_len ( iobuf );
	if ( ! len ) {
		free_iob ( iobuf );
		return 0;
	}

	/* Give the core what it can take; order is kept by never overtaking the backlog */
	if ( list_empty ( &conn->backlog ) ) {
		taken = table->ops->rx_push ( table->client, conn->id,
					      iobuf->data, len );
		if ( taken > len )	/* (the core never takes more than it is given; an I/O buffer is not pulled past its end) */
			taken = len;
		if ( taken == len ) {
			free_iob ( iobuf );
			rbd_conn_wake ( table );
			return 0;
		}
		iob_pull ( iobuf, taken );
		len -= taken;
	}

	/* Park the rest, within the announced window */
	if ( ( len > conn->adv_max ) ||
	     ( conn->backlog_len > ( conn->adv_max - len ) ) ) {
		DBGC ( table, "RBD conn %#x receive backlog %zd + %zd exceeds "
		       "the announced window %zd\n", conn->id,
		       conn->backlog_len, len, conn->adv_max );
		free_iob ( iobuf );
		rbd_conn_release ( conn, -ENOBUFS, 1 );
		return -ENOBUFS;
	}
	list_add_tail ( &iobuf->list, &conn->backlog );
	conn->backlog_len += len;
	rbd_conn_wake ( table );
	return 0;
}

/** Core connection socket interface operations */
static struct interface_operation rbd_conn_operations[] = {
	INTF_OP ( xfer_deliver, struct rbd_conn *, rbd_conn_deliver ),
	INTF_OP ( xfer_window, struct rbd_conn *, rbd_conn_rx_window ),
	INTF_OP ( xfer_window_changed, struct rbd_conn *,
		  rbd_conn_window_changed ),
	INTF_OP ( intf_close, struct rbd_conn *, rbd_conn_close ),
};

/** Core connection socket interface descriptor */
static struct interface_descriptor rbd_conn_desc =
	INTF_DESC ( struct rbd_conn, intf, rbd_conn_operations );

/****************************************************************************
 *
 * Receive backlog and transmit
 *
 ****************************************************************************
 */

/**
 * Pass the receive backlog of a connection to the core
 *
 * @v conn		Connection
 * @ret work		RBD_CONN_PROGRESS if the core took data, RBD_CONN_MORE if some is left
 */
static int rbd_conn_flush ( struct rbd_conn *conn ) {
	struct rbd_conn_table *table = conn->table;
	struct io_buffer *iobuf;
	size_t len;
	size_t taken;
	int work = 0;

	while ( ( iobuf = list_first_entry ( &conn->backlog, struct io_buffer,
					     list ) ) != NULL ) {
		len = iob_len ( iobuf );
		taken = table->ops->rx_push ( table->client, conn->id,
					      iobuf->data, len );
		if ( ! taken )
			break;
		if ( taken > len )
			taken = len;
		work |= RBD_CONN_PROGRESS;
		conn->backlog_len -= taken;
		if ( taken < len ) {
			iob_pull ( iobuf, taken );
			break;
		}
		list_del ( &iobuf->list );
		free_iob ( iobuf );
	}
	if ( ! list_empty ( &conn->backlog ) )
		work |= RBD_CONN_MORE;
	return work;
}

/**
 * Get the length of a gather list, limited
 *
 * @v iov		Gather list
 * @v count		Number of elements
 * @v max		Limit
 * @ret len		Total length, or max if the total is larger (no overflow for any lengths)
 */
size_t rbd_conn_gather_len ( const wr_iov *iov, size_t count, size_t max ) {
	size_t len = 0;
	size_t i;

	for ( i = 0 ; i < count ; i++ ) {
		if ( iov[i].len >= ( max - len ) )
			return max;
		len += iov[i].len;
	}
	return len;
}

/**
 * Copy the start of a gather list
 *
 * @v dest		Destination
 * @v iov		Gather list
 * @v count		Number of elements
 * @v len		Length to copy (not more than the list holds)
 */
void rbd_conn_gather_copy ( void *dest, const wr_iov *iov, size_t count,
			    size_t len ) {
	size_t frag_len;
	size_t i;

	for ( i = 0 ; ( i < count ) && len ; i++ ) {
		frag_len = ( ( iov[i].len < len ) ? iov[i].len : len );
		memcpy ( dest, iov[i].base, frag_len );
		dest += frag_len;
		len -= frag_len;
	}
}

/**
 * Send the core's pending bytes on a connection, as far as the socket's window allows
 *
 * @v conn		Connection
 * @ret work		RBD_CONN_PROGRESS if bytes were sent, RBD_CONN_MORE if the step must be repeated without an event
 *
 * Each packet is one I/O buffer holding min ( window, pending ) bytes of the core's gather list, copied (the core's
 * memory stays valid until consumed, so a send that fails leaves everything where it was). TCP takes one packet
 * at a time: the window is zero until it is acknowledged and xfer_window_changed() then wakes the session.
 * After each call into the socket the slot is checked again: the socket may have closed synchronously.
 */
static int rbd_conn_transmit ( struct rbd_conn *conn ) {
	struct rbd_conn_table *table = conn->table;
	wr_conn_id id = conn->id;
	struct io_buffer *iobuf;
	size_t window;
	size_t count;
	size_t len;
	unsigned int burst;
	int work = 0;
	int rc;

	for ( burst = 0 ; burst < RBD_CONN_TX_BURST ; burst++ ) {

		/* Stop if the socket will not take a packet now */
		window = xfer_window ( &conn->intf );
		if ( ( conn->state != RBD_CONN_UP ) || ( conn->id != id ) )
			return work;
		if ( ! window )
			return work;

		/* Stop if the core has nothing to send */
		count = table->ops->tx_peek ( table->client, id, table->iov,
					      RBD_CONN_IOV );
		if ( count > RBD_CONN_IOV )	/* (the core fills at most what it is given; the gather list is not read past its end) */
			count = RBD_CONN_IOV;
		len = rbd_conn_gather_len ( table->iov, count, window );
		if ( ! len )
			return work;

		/* Build one packet; try again later (without an event to say so) if there is no memory */
		iobuf = xfer_alloc_iob ( &conn->intf, len );
		if ( ! iobuf ) {
			DBGC ( table, "RBD conn %#x could not allocate %zd "
			       "bytes to send\n", id, len );
			return ( work | RBD_CONN_MORE );
		}
		rbd_conn_gather_copy ( iob_put ( iobuf, len ), table->iov,
				       count, len );

		/* Hand it over (the socket takes the buffer even if it fails) */
		rc = xfer_deliver_iob ( &conn->intf, iobuf );
		if ( ( conn->state != RBD_CONN_UP ) || ( conn->id != id ) )
			return work;
		if ( rc != 0 ) {
			DBGC ( table, "RBD conn %#x send failed: %s\n", id,
			       strerror ( rc ) );
			rbd_conn_release ( conn, rc, 1 );
			return work;
		}
		table->ops->tx_consume ( table->client, id, len );
		work |= RBD_CONN_PROGRESS;
	}
	return ( work | RBD_CONN_MORE );
}

/**
 * Serve all connections: receive backlog into the core, core output to the sockets
 *
 * @v table		Connection table
 * @ret work		RBD_CONN_* bits
 */
int rbd_conn_service ( struct rbd_conn_table *table ) {
	struct rbd_conn *conn;
	unsigned int i;
	int work = 0;

	if ( ! table->client )
		return 0;
	for ( i = 0 ; i < RBD_CONN_SLOTS ; i++ ) {
		conn = &table->conn[i];
		if ( conn->state != RBD_CONN_UP )
			continue;
		work |= rbd_conn_flush ( conn );
		work |= rbd_conn_transmit ( conn );
	}
	return work;
}

/****************************************************************************
 *
 * Actions of the core
 *
 ****************************************************************************
 */

/**
 * Find the slot of a connection id
 *
 * @v table		Connection table
 * @v id		Connection id (low 16 bits: slot index + 1; high 16 bits: generation)
 * @ret conn		Slot, or NULL if the id names no slot of this table
 */
static struct rbd_conn * rbd_conn_slot ( struct rbd_conn_table *table,
					 wr_conn_id id ) {
	unsigned int index = ( id & 0xffff );

	if ( ( index == 0 ) || ( index > RBD_CONN_SLOTS ) )
		return NULL;
	return &table->conn[ index - 1 ];
}

/**
 * Copy the bytes of an IP address
 *
 * @v dest		Destination (an address field of a socket address)
 * @v ip		Address bytes (the core's, at an odd offset of its structure)
 * @v len		Length (4 or 16)
 *
 * Not memcpy(): for constant lengths of 2, 4, 5, 6 and 8 bytes iPXE's x86 memcpy() is a load and a store through a
 * pointer to a wider type, which is a misaligned access for the core's address bytes (they follow a one-byte family
 * field). x86 does not mind, but the UBSan build of the self-tests ("build.sh test -u") does, rightly: the access is not
 * defined C. A byte loop is defined and costs nothing at these lengths.
 */
static void rbd_conn_copy_ip ( void *dest, const uint8_t *ip, size_t len ) {
	uint8_t *out = dest;
	size_t i;

	for ( i = 0 ; i < len ; i++ )
		out[i] = ip[i];
}

/**
 * Build a socket address from the core's address
 *
 * @v sa		Socket address to fill in
 * @v addr		The core's address (IP bytes in network order, port in host order)
 * @ret rc		Return status code
 */
static int rbd_conn_sockaddr ( union rbd_conn_sockaddr *sa,
			       const wr_addr *addr ) {

	memset ( sa, 0, sizeof ( *sa ) );
	if ( ! addr->port )
		return -EINVAL;
	switch ( addr->family ) {
	case WR_AF_IPV4:
		sa->sin.sin_family = AF_INET;
		sa->sin.sin_port = htons ( addr->port );
		rbd_conn_copy_ip ( &sa->sin.sin_addr, addr->ip,
				   sizeof ( sa->sin.sin_addr ) );
		return 0;
	case WR_AF_IPV6:
		sa->sin6.sin6_family = AF_INET6;
		sa->sin6.sin6_port = htons ( addr->port );
		rbd_conn_copy_ip ( &sa->sin6.sin6_addr, addr->ip,
				   sizeof ( sa->sin6.sin6_addr ) );
		return 0;
	default:
		return -EAFNOSUPPORT;
	}
}

/**
 * Open a connection for the core
 *
 * @v table		Connection table
 * @v action		WR_ACT_CONNECT action
 * @ret rc		Return status code (the core is told of a failure, unless there is no core: -ENOTCONN)
 */
static int rbd_conn_connect ( struct rbd_conn_table *table,
			      const wr_action *action ) {
	union rbd_conn_sockaddr peer;
	struct rbd_conn *conn;
	int rc;

	/* No core to tell and none to serve: a table that was never attached, or has been shut down, opens no socket (a socket
	 * opened now would outlive the session that is going away)
	 */
	if ( ! table->client )
		return -ENOTCONN;

	/* The id must name a slot of this table */
	conn = rbd_conn_slot ( table, action->conn );
	if ( ! conn ) {
		rc = -EINVAL;
		goto err_slot;
	}

	/* The core reuses a slot only after wr_conn_closed(): whatever this slot still holds is stale */
	if ( conn->state != RBD_CONN_FREE ) {
		DBGC ( table, "RBD conn %#x replaces a stale socket in slot "
		       "%d\n", action->conn, ( int ) ( conn - table->conn ) );
		rbd_conn_release ( conn, -ECANCELED, 0 );
	}

	/* Build the peer address */
	if ( ( rc = rbd_conn_sockaddr ( &peer, &action->addr ) ) != 0 )
		goto err_sockaddr;

	/* Start the connect timer (a timeout of zero is "no limit" for the core: TCP's own retry then decides) */
	conn->id = action->conn;
	conn->state = RBD_CONN_CONNECTING;
	conn->adv_max = 0;
	if ( action->timeout_ms )
		start_timer_fixed ( &conn->timer,
				    rbd_conn_ms_to_ticks ( action->timeout_ms ) );

	/* Open the socket; it may close again (or become established) before this call returns */
	if ( ( rc = table->ops->open ( &conn->intf, &peer.sa ) ) != 0 ) {
		DBGC ( table, "RBD conn %#x could not open a socket: %s\n",
		       action->conn, strerror ( rc ) );
		goto err_open;
	}
	rbd_conn_check_up ( conn );
	return 0;

 err_open:
	rbd_conn_release ( conn, rc, 1 );
	return rc;
 err_sockaddr:
 err_slot:
	if ( table->client )
		table->ops->closed ( table->client, action->conn,
				     rbd_conn_errno ( rc ) );
	return rc;
}

/**
 * Close a connection for the core
 *
 * @v table		Connection table
 * @v action		WR_ACT_CLOSE action
 */
static void rbd_conn_disconnect ( struct rbd_conn_table *table,
				  const wr_action *action ) {
	struct rbd_conn *conn;

	conn = rbd_conn_slot ( table, action->conn );
	if ( conn && ( conn->state != RBD_CONN_FREE ) &&
	     ( conn->id == action->conn ) ) {
		rbd_conn_release ( conn, 0, 1 );
		return;
	}

	/* Nothing is open under that id: say so anyway (a stale id is ignored by the core, a live one is freed) */
	if ( table->client )
		table->ops->closed ( table->client, action->conn, 0 );
}

/**
 * Carry out one action of the core
 *
 * @v table		Connection table
 * @v action		Action
 * @ret rc		Return status code (of a CONNECT; the core has been told of a failure)
 */
int rbd_conn_action ( struct rbd_conn_table *table, const wr_action *action ) {

	switch ( action->kind ) {
	case WR_ACT_CONNECT:
		return rbd_conn_connect ( table, action );
	case WR_ACT_CLOSE:
		rbd_conn_disconnect ( table, action );
		return 0;
	case WR_ACT_TX_READY:
		/* The transmit step of rbd_conn_service() looks at every connection anyway */
		return 0;
	default:
		return 0;
	}
}

/**
 * Carry out all pending actions of the core
 *
 * @v table		Connection table
 * @ret count		Number of actions taken
 */
unsigned int rbd_conn_drain ( struct rbd_conn_table *table ) {
	wr_action action;
	unsigned int count = 0;

	if ( ! table->client )
		return 0;
	while ( ( count < RBD_CONN_ACTION_MAX ) &&
		table->ops->next_action ( table->client, &action ) ) {
		rbd_conn_action ( table, &action );
		count++;
	}
	return count;
}

/****************************************************************************
 *
 * Table
 *
 ****************************************************************************
 */

/**
 * Initialise a connection table
 *
 * @v table		Connection table
 * @v refcnt		Reference counter of the owner (may be NULL)
 * @v wake		Function to call when a socket event needs a pass of the session's process
 * @v wake_ctx		Argument of wake()
 */
void rbd_conn_init ( struct rbd_conn_table *table, struct refcnt *refcnt,
		     void ( * wake ) ( void *ctx ), void *wake_ctx ) {
	struct rbd_conn *conn;
	unsigned int i;

	memset ( table, 0, sizeof ( *table ) );
	table->refcnt = refcnt;
	table->wake = wake;
	table->wake_ctx = wake_ctx;
	table->ops = &rbd_conn_default_ops;
	for ( i = 0 ; i < RBD_CONN_SLOTS ; i++ ) {
		conn = &table->conn[i];
		conn->table = table;
		INIT_LIST_HEAD ( &conn->backlog );
		intf_init ( &conn->intf, &rbd_conn_desc, refcnt );
		timer_init ( &conn->timer, rbd_conn_expired, refcnt );
	}
}

/**
 * Attach the core's client to the table
 *
 * @v table		Connection table
 * @v client		Client
 */
void rbd_conn_attach ( struct rbd_conn_table *table, wr_client *client ) {

	table->client = client;
}

/**
 * Shut the table down: close every socket, free every backlog, stop every timer
 *
 * @v table		Connection table
 *
 * Called before the client is destroyed. The core is not told (it is going away) and the session is not woken. The table
 * is finished after this: rbd_conn_action() refuses a CONNECT until a client is attached again, and the wake function is
 * gone (call rbd_conn_init() again for a table that is to be used afresh). If the owner has dropped its own reference,
 * the owner is freed by the last reference this function lets go, at its end.
 */
void rbd_conn_shutdown ( struct rbd_conn_table *table ) {
	struct refcnt *refcnt = table->refcnt;
	unsigned int i;

	/* Every plugged socket holds a reference to the owner: the last one is let go in the loop below. Hold one of our own
	 * until the loop has ended, so that an owner that has already dropped its own reference is not freed from under it
	 * (the table is part of the owner)
	 */
	ref_get ( refcnt );
	table->client = NULL;
	table->wake = NULL;
	for ( i = 0 ; i < RBD_CONN_SLOTS ; i++ )
		rbd_conn_release ( &table->conn[i], 0, 0 );
	ref_put ( refcnt );
}

/**
 * Count the open connections
 *
 * @v table		Connection table
 * @ret live		Number of slots in use
 */
unsigned int rbd_conn_live ( const struct rbd_conn_table *table ) {
	unsigned int live = 0;
	unsigned int i;

	for ( i = 0 ; i < RBD_CONN_SLOTS ; i++ ) {
		if ( table->conn[i].state != RBD_CONN_FREE )
			live++;
	}
	return live;
}
