#ifndef _RBD_CONN_H
#define _RBD_CONN_H
/* SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL */
/** @file
 *
 * RBD (Ceph) SAN protocol: the pump host (private declarations of rbd_conn.c)
 *
 * The core never opens a socket: it asks (WR_ACT_CONNECT, WR_ACT_CLOSE), the host does it and reports back
 * (docs/design/ipxe-driver.md, section 4). rbd_conn.c is that host for iPXE: a table with one struct interface per
 * connection slot of the core, plus the time and random sources and the log sink of the core's host table. It is the
 * only file of the driver that touches xfer_* on a socket.
 *
 * This header is private to the pump host and its users: rbd_priv.h (the contract between the glue files) is frozen in
 * this wave. The session (rbd_session.c, the only caller of wr_client_run) owns one struct rbd_conn_table and drives it:
 *
 *	rbd_conn_init ( table, &session->refcnt, wake, session );
 *	rbd_conn_host_ops ( table, &host );		the host table for wr_client_create()
 *	client created
 *	rbd_conn_attach ( table, client );
 *
 *	every pass of the session's process:
 *		rbd_conn_now ( table, &now );		the clock for wr_client_run()
 *		wr_client_run ( client, &now, budget );
 *		rbd_conn_drain ( table );		CONNECT and CLOSE actions
 *		work = rbd_conn_service ( table );	receive backlog into the core, core output to the sockets
 *		( run the core again while work & RBD_CONN_PROGRESS; stay scheduled while work & RBD_CONN_MORE )
 *
 *	before the client is destroyed:
 *		rbd_conn_shutdown ( table );		(the table is finished after this: rbd_conn_init() it again to use it afresh)
 *
 * The table calls wake() whenever a socket event needs a pass of the session's process (connected, closed, received
 * data, transmit window opened). Delivery from the network never calls into wr_client_run.
 *
 * Notes for the session:
 *
 *	- rbd_conn_drain() takes at most RBD_CONN_ACTION_MAX actions; a return value equal to it means "call again".
 *	- A CONNECT before rbd_conn_attach() or after rbd_conn_shutdown() opens nothing (-ENOTCONN): there is no core to tell.
 *	- A failed CONNECT, a close from either side and a timeout are all reported to the core from here
 *	  (wr_conn_closed), including from inside a socket callback: the session does not have to look at sockets.
 *	- iPXE's TCP learns the receive window only when it sends a packet (there is no way to tell it that the window grew).
 *	  A connection whose window fell to zero therefore resumes when the peer's next probe is answered. The window is
 *	  zero only while the core has no room for received bytes, which is a state the core leaves at its next run.
 *
 * Everything here is single threaded, like the core: iPXE runs it all from step() and from interface callbacks.
 *
 * The self-tests (ipxe/tests/rbd_conn_test.c) replace the sockets, the random source and the core's connection calls
 * through struct rbd_conn_ops; production code never sets table->ops (rbd_conn_init() installs rbd_conn_default_ops).
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( FORBIDDEN );

#include <stdint.h>
#include <stddef.h>
#include <ipxe/refcnt.h>
#include <ipxe/list.h>
#include <ipxe/interface.h>
#include <ipxe/retry.h>
#include <ipxe/socket.h>
#include "winrbd.h"

/** Connection slots of the table: the iPXE profile's max_conns (osd_sessions 6 + 2) */
#define RBD_CONN_SLOTS 8

/** Gather elements asked of the core per transmit step (one TCP packet never needs more than a few frame segments) */
#define RBD_CONN_IOV 16

/** Most packets sent on one connection per call of rbd_conn_service() (fairness between connections) */
#define RBD_CONN_TX_BURST 8

/** Most receive window announced on one connection (bytes). iPXE's TCP announces what xfer_window() says, up to 2 MiB, and queues the
 * out-of-order segments that arrive inside it, each in an I/O buffer from its 4 MiB heap (the in-order data goes straight to us). The
 * core's whole room (megabytes) as the window therefore lets a lossy connection (a segment lost with the rest of the window behind
 * it) hold the heap, and with it the NIC's receive buffers and the next transmit. 64 KiB per connection (8 connections: half a
 * megabyte of payload) is bounded, and at a round trip of 10 ms still 6 MB/s per connection. (A build can set it with
 * EXTRA_CFLAGS=-DRBD_CONN_RX_WINDOW_MAX=<bytes>: the experiments of docs/design/ipxe-driver.md section 18.2 (R-1) and
 * docs/design/ipxe-driver-measurements.md compare 64 KiB with 4 MiB.) */
#ifndef RBD_CONN_RX_WINDOW_MAX
#define RBD_CONN_RX_WINDOW_MAX 65536
#endif

/** Most actions taken from the core per call of rbd_conn_drain() (each slot yields at most two per pass, so this only bounds a bug) */
#define RBD_CONN_ACTION_MAX 64

/** Longest connect timeout honoured (ms): a day; the core's own values are seconds */
#define RBD_CONN_TIMEOUT_MAX_MS 86400000U

/** How often the wall clock is read again (ms of the monotonic clock): reading the RTC of a BIOS costs a spin on its update flag */
#define RBD_CLOCK_WALL_REFRESH_MS 60000U

/** The monotonic clock starts this many ticks after zero, so that no deadline computed from it is ever "0" (one second) */
#define RBD_CLOCK_EPOCH_TICKS 1024U

/** Result bits of rbd_conn_service() */
#define RBD_CONN_PROGRESS 0x01		/**< bytes moved: the core may have more to do, run it again */
#define RBD_CONN_MORE 0x02		/**< work is left that no event will announce: stay scheduled */

/** Connection state */
enum rbd_conn_state {
	RBD_CONN_FREE = 0,		/**< no socket, no id */
	RBD_CONN_CONNECTING,		/**< socket opened, not yet established */
	RBD_CONN_UP,			/**< established, the core has been told */
};

/** The monotonic and wall clock of one session */
struct rbd_clock {
	/** Last raw value of currticks() */
	unsigned long last;
	/** Ticks since the (shifted) epoch: 64 bits, never decreases */
	uint64_t ticks;
	/** Wall time (ms since the Unix epoch) minus the monotonic ms at the last read; modular arithmetic */
	uint64_t wall_base_ms;
	/** Monotonic ms at which the wall clock is read again */
	uint64_t wall_next_ms;
	/** The ticks have been started */
	uint8_t started;
	/** wall_base_ms holds a time the platform gave */
	uint8_t wall_valid;
};

struct rbd_conn_table;

/** One core connection slot */
struct rbd_conn {
	/** The socket interface (plugged into a TCP connection) */
	struct interface intf;
	/** The table */
	struct rbd_conn_table *table;
	/** Connect timer (the core's per-action timeout; iPXE's TCP would retry for much longer) */
	struct retry_timer timer;
	/** Received I/O buffers the core could not take yet, in order */
	struct list_head backlog;
	/** Bytes in the backlog */
	size_t backlog_len;
	/** Largest room (at most RBD_CONN_RX_WINDOW_MAX) offered for received bytes on this connection (the backlog never exceeds it: TCP sends
	 * no more than the window it announced, which was this room less the backlog of that moment) */
	size_t adv_max;
	/** The core's id of the connection (WR_CONN_NONE when free) */
	wr_conn_id id;
	/** State, enum rbd_conn_state */
	uint8_t state;
};

/**
 * The seams of the table
 *
 * Where it gets its sockets and its random bytes, and how it talks to the core's connection API. Production uses
 * rbd_conn_default_ops (iPXE's TCP, the DRBG, the wr_conn_* functions of wr_client.h); the self-tests replace them with
 * a fake socket, a fake random source and a fake core, so that the state machine can be driven into every corner (a
 * core window of three bytes, a socket window of one, a close from inside a call) without a network and without
 * depending on how large the real core's buffers happen to be. The contract of the core entries is the one in
 * wr_client.h.
 */
struct rbd_conn_ops {
	/**
	 * Open a TCP connection
	 *
	 * @v intf		Socket interface to plug
	 * @v peer		Peer socket address (a struct sockaddr_tcpip)
	 * @ret rc		Return status code
	 */
	int ( * open ) ( struct interface *intf, struct sockaddr *peer );
	/**
	 * Fill a buffer with random bytes
	 *
	 * @v out		Buffer
	 * @v len		Length
	 * @ret rc		Return status code (non-zero: no random bytes; the core never falls back to a weak source)
	 */
	int ( * generate ) ( void *out, size_t len );
	/** The core's connection API (wr_client.h) */
	int ( * next_action ) ( wr_client *c, wr_action *out );
	void ( * connected ) ( wr_client *c, wr_conn_id id );
	void ( * closed ) ( wr_client *c, wr_conn_id id, int host_errno );
	size_t ( * rx_window ) ( wr_client *c, wr_conn_id id, uint8_t **ptr );
	size_t ( * rx_push ) ( wr_client *c, wr_conn_id id, const uint8_t *data,
			       size_t n );
	size_t ( * tx_peek ) ( wr_client *c, wr_conn_id id, wr_iov *iov,
			       size_t max_iov );
	void ( * tx_consume ) ( wr_client *c, wr_conn_id id, size_t n );
};

/** The connection table of one session */
struct rbd_conn_table {
	/** Reference counter of the owner (the session); every interface and timer holds a reference while it is in use */
	struct refcnt *refcnt;
	/** The core's client, NULL before attach and after shutdown */
	wr_client *client;
	/** Called when a socket event needs a pass of the session's process */
	void ( * wake ) ( void *ctx );
	/** Argument of wake() */
	void *wake_ctx;
	/** Sockets, random and the core's connection API */
	const struct rbd_conn_ops *ops;
	/** Clock */
	struct rbd_clock clock;
	/** Scratch gather list of the transmit step (not on the 4 kB BIOS stack; the pump is not re-entrant) */
	wr_iov iov[RBD_CONN_IOV];
	/** The slots */
	struct rbd_conn conn[RBD_CONN_SLOTS];
};

/** The production sockets (iPXE's TCP), random (the DRBG) and core calls */
extern const struct rbd_conn_ops rbd_conn_default_ops;

/* Table */
extern void rbd_conn_init ( struct rbd_conn_table *table, struct refcnt *refcnt,
			    void ( * wake ) ( void *ctx ), void *wake_ctx );
extern void rbd_conn_attach ( struct rbd_conn_table *table, wr_client *client );
extern void rbd_conn_shutdown ( struct rbd_conn_table *table );
extern int rbd_conn_action ( struct rbd_conn_table *table,
			     const wr_action *action );
extern unsigned int rbd_conn_drain ( struct rbd_conn_table *table );
extern int rbd_conn_service ( struct rbd_conn_table *table );
extern unsigned int rbd_conn_live ( const struct rbd_conn_table *table );

/* Host table of the core */
extern void rbd_conn_host_ops ( struct rbd_conn_table *table, wr_host_ops *host );
extern wr_status rbd_conn_random ( void *ctx, uint8_t *out, size_t len );
extern void rbd_conn_log ( void *ctx, const wr_log_rec *rec );

/* Time */
extern void rbd_conn_now ( struct rbd_conn_table *table, wr_clock *now );
extern uint64_t rbd_clock_advance ( struct rbd_clock *clock, unsigned long raw );
extern uint64_t rbd_clock_wall_at ( struct rbd_clock *clock, uint64_t mono_ms,
				    int64_t seconds );
extern uint64_t rbd_conn_ticks_to_ms ( uint64_t ticks );
extern unsigned long rbd_conn_ms_to_ticks ( uint32_t ms );

/* Transmit helpers (pure: the self-tests call them directly) */
extern size_t rbd_conn_gather_len ( const wr_iov *iov, size_t count, size_t max );
extern void rbd_conn_gather_copy ( void *dest, const wr_iov *iov, size_t count, size_t len );

#endif /* _RBD_CONN_H */
