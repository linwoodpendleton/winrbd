/* SPDX-License-Identifier: MIT */
/*
 * wrl_loop.c - part 2 of the Linux host: the socket pump. It runs the reference loop of wr_client.h
 * on non-blocking TCP sockets and poll(2).
 *
 * One iteration (wrl_loop_step) is: sleep in poll(2) until a socket is ready, a timer is due or the
 * caller's limit passes (skipped when the previous iteration left work behind), then wr_client_run, drain
 * the actions (connect / close), and move bytes for every connection (send what tx_peek exposes, recv into
 * what rx_window names). That is the reference loop of wr_client.h turned by one step: the wait comes
 * first so that whatever run produced (events, map messages) is in the caller's hands the moment the step
 * returns, not after a sleep.
 *
 * Rules kept here:
 *   - one socket per wr_conn_id, looked up by id; a stale id is never mapped to a live socket;
 *   - no call blocks: every socket is O_NONBLOCK, partial sends / receives, EAGAIN and EINTR are normal;
 *   - SIGPIPE cannot be raised (MSG_NOSIGNAL); a broken connection is reported with its errno;
 *   - the connect timeout is the one the action carries; a requested close is always answered with
 *     wr_conn_closed;
 *   - the wait is the minimum of the caller's limit, the client's next deadline (from the previous run)
 *     and the nearest connect deadline, so an idle client sleeps and a busy one does not;
 *   - poll interest is recomputed from the engine at the start of the wait (receive window open, output
 *     pending), so a window the caller reopened by releasing a map message is noticed at once;
 *   - a connection with a zero receive window is left out of the poll set (backpressure); polling a
 *     hung-up socket with no interest would return at once and spin.
 * Key material never passes through here: the loop only sees opaque bytes.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "wrl_host.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifdef SOCK_CLOEXEC /* close-on-exec from the first instant, so a fork in another thread cannot inherit it */
#define WRL_SOCK_FLAGS SOCK_CLOEXEC
#else
#define WRL_SOCK_FLAGS 0
#endif

#define WRL_MAX_CONNS 64u            /* sockets held at once; the harness profile uses 16 */
#define WRL_TX_IOV 8u                /* gather elements per sendmsg */
#define WRL_IO_ROUNDS 8u             /* send / recv rounds per connection per step, so one busy socket cannot starve the rest */
#define WRL_RUN_BUDGET (256u * 1024u) /* bytes of work per wr_client_run, the figure of the reference loop */
#define WRL_CONNECT_DEFAULT_MS 5000u /* used when an action carries timeout 0 */
#define WRL_IDLE_CAP_MS 1000         /* longest sleep when no socket and no timer exist */

enum { WRL_FREE = 0, WRL_CONNECTING = 1, WRL_UP = 2 };

typedef struct wrl_conn {
	int fd;
	uint8_t state;
	wr_conn_id id;
	uint64_t deadline_ms;      /* CONNECTING: monotonic time at which the connect is given up */
} wrl_conn;

struct wrl_loop {
	wr_client *c;
	uint64_t next_deadline_ms; /* from the last wr_client_run */
	uint8_t skip_wait;         /* the last step left work behind: do not sleep before the next one */
	wrl_conn conns[WRL_MAX_CONNS];
};

/* ---- small helpers --------------------------------------------------------------------------- */

static wr_status wrl_fatal_status(const wr_client *c)
{
	const wr_errinfo *e = wr_client_last_error(c);

	return (e != NULL && e->status != WR_OK) ? e->status : WR_E_STATE;
}

/* A socket that stayed blocking would stall the whole pump on its first partial read, so a failure here is
 * a failure of the connection (the caller reports errno), never ignored. Returns 0 on success, -1 with errno. */
static int wrl_set_nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL, 0);

	if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0)
		return -1;
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0)
		return -1;
	return 0;
}

static wrl_conn *wrl_find(wrl_loop *l, wr_conn_id id)
{
	unsigned i;

	for (i = 0; i < WRL_MAX_CONNS; i++)
		if (l->conns[i].state != WRL_FREE && l->conns[i].id == id)
			return &l->conns[i];
	return NULL;
}

static wrl_conn *wrl_alloc(wrl_loop *l)
{
	unsigned i;

	for (i = 0; i < WRL_MAX_CONNS; i++)
		if (l->conns[i].state == WRL_FREE)
			return &l->conns[i];
	return NULL;
}

static void wrl_release(wrl_conn *c)
{
	if (c->fd >= 0)
		(void)close(c->fd); /* nothing useful to do with a close error, and a retry could close a reused fd */
	memset(c, 0, sizeof(*c));
	c->fd = -1;
}

/* The connection is over for any reason: free the socket, then tell the engine (which frees its slot). */
static void wrl_end(wrl_loop *l, wrl_conn *c, int err)
{
	wr_conn_id id = c->id;

	wrl_release(c);
	wr_conn_closed(l->c, id, err);
}

/* wr_addr to a socket address; returns its length, 0 if the address cannot be dialled. */
static socklen_t wrl_sockaddr(const wr_addr *a, struct sockaddr_storage *ss, int *family)
{
	memset(ss, 0, sizeof(*ss));
	if (a->port == 0)
		return 0;
	if (a->family == WR_AF_IPV4) {
		struct sockaddr_in sa;

		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(a->port);
		memcpy(&sa.sin_addr, a->ip, 4);
		memcpy(ss, &sa, sizeof(sa));
		*family = AF_INET;
		return (socklen_t)sizeof(sa);
	}
	if (a->family == WR_AF_IPV6) {
		struct sockaddr_in6 sa;

		memset(&sa, 0, sizeof(sa));
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(a->port);
		memcpy(&sa.sin6_addr, a->ip, 16);
		memcpy(ss, &sa, sizeof(sa));
		*family = AF_INET6;
		return (socklen_t)sizeof(sa);
	}
	return 0;
}

/* ---- actions --------------------------------------------------------------------------------- */

static void wrl_act_connect(wrl_loop *l, const wr_action *a, uint64_t now_ms)
{
	struct sockaddr_storage ss;
	socklen_t sl;
	int family = 0, fd, one = 1, rc;
	wrl_conn *c;
	uint32_t tmo = a->timeout_ms != 0 ? a->timeout_ms : WRL_CONNECT_DEFAULT_MS;

	c = wrl_find(l, a->conn);
	if (c != NULL) /* a second CONNECT for a live id cannot happen; do not leak the first socket if it does */
		wrl_release(c);
	c = wrl_alloc(l);
	if (c == NULL) {
		wr_conn_closed(l->c, a->conn, EMFILE);
		return;
	}
	sl = wrl_sockaddr(&a->addr, &ss, &family);
	if (sl == 0) {
		wr_conn_closed(l->c, a->conn, EINVAL);
		return;
	}
	fd = socket(family, SOCK_STREAM | WRL_SOCK_FLAGS, 0);
	if (fd < 0) {
		wr_conn_closed(l->c, a->conn, errno);
		return;
	}
	if (wrl_set_nonblock(fd) != 0) {
		int err = errno;

		(void)close(fd);
		wr_conn_closed(l->c, a->conn, err);
		return;
	}
	(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, (socklen_t)sizeof(one)); /* small frames: best effort */
	c->fd = fd;
	c->id = a->conn;
	c->deadline_ms = now_ms + tmo < now_ms ? UINT64_MAX : now_ms + tmo;
	rc = connect(fd, (const struct sockaddr *)&ss, sl);
	if (rc == 0) {
		c->state = WRL_UP;
		wr_conn_connected(l->c, c->id);
	} else if (errno == EINPROGRESS || errno == EINTR) {
		c->state = WRL_CONNECTING; /* an interrupted connect carries on in the background */
	} else {
		int err = errno;

		c->state = WRL_UP; /* wrl_end only needs a non-free entry */
		wrl_end(l, c, err);
	}
}

static void wrl_drain_actions(wrl_loop *l, uint64_t now_ms, unsigned *progress)
{
	wr_action a;

	while (wr_client_next_action(l->c, &a)) {
		wrl_conn *c;

		*progress = 1;
		switch (a.kind) {
		case WR_ACT_CONNECT:
			wrl_act_connect(l, &a, now_ms);
			break;
		case WR_ACT_CLOSE:
			c = wrl_find(l, a.conn);
			if (c != NULL)
				wrl_release(c);
			wr_conn_closed(l->c, a.conn, 0); /* answered even for an id we do not hold: stale ids are ignored */
			break;
		case WR_ACT_TX_READY: /* a hint only: every connection is polled for output on each step */
		case WR_ACT_NONE:
		default:
			break;
		}
	}
}

/* ---- moving bytes ---------------------------------------------------------------------------- */

static void wrl_check_connect(wrl_loop *l, wrl_conn *c, uint64_t now_ms, unsigned *progress)
{
	struct pollfd p;
	int rc;

	p.fd = c->fd;
	p.events = POLLOUT;
	p.revents = 0;
	do {
		rc = poll(&p, 1, 0);
	} while (rc < 0 && errno == EINTR);
	if (rc > 0 && p.revents != 0) {
		int err = 0;
		socklen_t el = (socklen_t)sizeof(err);

		if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0)
			err = errno;
		*progress = 1;
		if (err != 0) {
			wrl_end(l, c, err);
			return;
		}
		c->state = WRL_UP;
		wr_conn_connected(l->c, c->id);
		return;
	}
	if (now_ms >= c->deadline_ms) {
		*progress = 1;
		wrl_end(l, c, ETIMEDOUT);
	}
}

/* Send what the engine exposes. Returns 0 if the connection was ended. */
static int wrl_pump_tx(wrl_loop *l, wrl_conn *c, unsigned *progress)
{
	unsigned round;

	for (round = 0; round < WRL_IO_ROUNDS; round++) {
		wr_iov iov[WRL_TX_IOV];
		struct iovec sv[WRL_TX_IOV];
		struct msghdr mh;
		size_t n, i, total = 0;
		ssize_t s;

		n = wr_conn_tx_peek(l->c, c->id, iov, WRL_TX_IOV);
		if (n > WRL_TX_IOV) /* the engine never returns more than asked; a bad count must not index past sv[] */
			n = WRL_TX_IOV;
		for (i = 0; i < n; i++) {
			sv[i].iov_base = (void *)(uintptr_t)iov[i].base; /* sendmsg takes a non-const pointer; it does not write */
			sv[i].iov_len = iov[i].len;
			total += iov[i].len;
		}
		if (n == 0 || total == 0)
			return 1;
		memset(&mh, 0, sizeof(mh));
		mh.msg_iov = sv;
		mh.msg_iovlen = n;
		s = sendmsg(c->fd, &mh, MSG_NOSIGNAL);
		if (s > 0) {
			if ((size_t)s > total) /* cannot happen; never report more consumed than was offered */
				s = (ssize_t)total;
			wr_conn_tx_consume(l->c, c->id, (size_t)s);
			*progress = 1;
			if ((size_t)s < total) /* the kernel took part of it: the rest waits for room (POLLOUT) */
				return 1;
			continue;
		}
		if (s < 0 && errno == EINTR)
			continue;
		if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return 1;
		wrl_end(l, c, s < 0 ? errno : EPIPE);
		*progress = 1;
		return 0;
	}
	return 1; /* rounds used up with output still pending: progress is set, so the next step comes at once */
}

/* Receive into the window the engine names. Returns 0 if the connection was ended. */
static int wrl_pump_rx(wrl_loop *l, wrl_conn *c, unsigned *progress)
{
	unsigned round;

	for (round = 0; round < WRL_IO_ROUNDS; round++) {
		uint8_t *p = NULL;
		size_t room = wr_conn_rx_window(l->c, c->id, &p);
		ssize_t s;

		if (room == 0 || p == NULL)
			return 1; /* backpressure: not in the poll set until the engine opens the window */
		s = recv(c->fd, p, room, 0);
		if (s > 0) {
			if ((size_t)s > room) /* cannot happen; the commit must never exceed the window */
				s = (ssize_t)room;
			wr_conn_rx_commit(l->c, c->id, (size_t)s);
			*progress = 1;
			if ((size_t)s < room) /* the socket is drained for now */
				return 1;
			continue;
		}
		if (s == 0) { /* orderly EOF from the peer */
			wrl_end(l, c, 0);
			*progress = 1;
			return 0;
		}
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 1;
		wrl_end(l, c, errno);
		*progress = 1;
		return 0;
	}
	return 1;
}

static void wrl_pump_all(wrl_loop *l, uint64_t now_ms, unsigned *progress)
{
	unsigned i;

	for (i = 0; i < WRL_MAX_CONNS; i++) {
		wrl_conn *c = &l->conns[i];

		if (c->state == WRL_CONNECTING)
			wrl_check_connect(l, c, now_ms, progress);
		if (c->state != WRL_UP)
			continue;
		if (!wrl_pump_tx(l, c, progress))
			continue;
		(void)wrl_pump_rx(l, c, progress);
	}
}

/* ---- the wait -------------------------------------------------------------------------------- */

static int wrl_ms_until(uint64_t deadline, uint64_t now)
{
	uint64_t d;

	if (deadline == WR_DEADLINE_NONE)
		return -1;
	if (deadline <= now)
		return 0;
	d = deadline - now;
	return d > (uint64_t)INT_MAX ? INT_MAX : (int)d;
}

static int wrl_min_wait(int a, int b) /* -1 = no limit */
{
	if (a < 0)
		return b;
	if (b < 0)
		return a;
	return a < b ? a : b;
}

/* Poll interest of an established connection, asked of the engine now. */
static short wrl_interest(wrl_loop *l, const wrl_conn *c)
{
	wr_iov iov[1];
	uint8_t *p = NULL;
	short ev = 0;

	if (wr_conn_rx_window(l->c, c->id, &p) > 0)
		ev |= POLLIN;
	if (wr_conn_tx_peek(l->c, c->id, iov, 1) > 0)
		ev |= POLLOUT;
	return ev;
}

static void wrl_wait(wrl_loop *l, int max_wait_ms)
{
	struct pollfd pf[WRL_MAX_CONNS];
	nfds_t n = 0;
	unsigned i;
	wr_clock now;
	int t = max_wait_ms;

	wrl_clock(&now);
	t = wrl_min_wait(t, wrl_ms_until(l->next_deadline_ms, now.mono_ms));
	for (i = 0; i < WRL_MAX_CONNS; i++) {
		const wrl_conn *c = &l->conns[i];
		short ev = 0;

		if (c->state == WRL_CONNECTING) {
			ev = POLLOUT;
			t = wrl_min_wait(t, wrl_ms_until(c->deadline_ms, now.mono_ms));
		} else if (c->state == WRL_UP) {
			ev = wrl_interest(l, c);
		}
		if (ev == 0)
			continue;
		pf[n].fd = c->fd;
		pf[n].events = ev;
		pf[n].revents = 0;
		n++;
	}
	if (t < 0 && n == 0)
		t = WRL_IDLE_CAP_MS; /* nothing can ever wake us: do not sleep for ever */
	if (t == 0)
		return;
	/* The result is not used: readiness is rediscovered by the non-blocking calls of the step that follows.
	 * EINTR is a normal wake-up. */
	(void)poll(pf, n, t);
}

/* ---- public ---------------------------------------------------------------------------------- */

wr_status wrl_loop_create(wr_client *c, wrl_loop **out)
{
	wrl_loop *l;
	unsigned i;

	if (out != NULL)
		*out = NULL;
	if (c == NULL || out == NULL)
		return WR_E_INVAL;
	l = (wrl_loop *)calloc(1, sizeof(*l));
	if (l == NULL)
		return WR_E_BUDGET;
	l->c = c;
	l->next_deadline_ms = WR_DEADLINE_NONE;
	l->skip_wait = 1; /* the first step runs the engine at once */
	for (i = 0; i < WRL_MAX_CONNS; i++)
		l->conns[i].fd = -1;
	*out = l;
	return WR_OK;
}

void wrl_loop_destroy(wrl_loop *l)
{
	unsigned i;

	if (l == NULL)
		return;
	for (i = 0; i < WRL_MAX_CONNS; i++)
		if (l->conns[i].state != WRL_FREE)
			wrl_release(&l->conns[i]);
	free(l);
}

unsigned wrl_loop_open_sockets(const wrl_loop *l)
{
	unsigned i, n = 0;

	if (l == NULL)
		return 0;
	for (i = 0; i < WRL_MAX_CONNS; i++)
		n += l->conns[i].state != WRL_FREE;
	return n;
}

wr_status wrl_loop_step(wrl_loop *l, int max_wait_ms)
{
	wr_clock now;
	wr_run_result r;
	unsigned progress = 0;

	if (l == NULL)
		return WR_E_INVAL;
	if (!l->skip_wait && max_wait_ms != 0)
		wrl_wait(l, max_wait_ms);
	wrl_clock(&now);
	r = wr_client_run(l->c, &now, WRL_RUN_BUDGET);
	l->next_deadline_ms = r.next_deadline_ms;
	if (wr_client_get_state(l->c) == WR_CS_FAILED)
		return wrl_fatal_status(l->c);
	wrl_drain_actions(l, now.mono_ms, &progress);
	wrl_pump_all(l, now.mono_ms, &progress);
	if (wr_client_get_state(l->c) == WR_CS_FAILED)
		return wrl_fatal_status(l->c);
	l->skip_wait = (uint8_t)(progress || r.more_work);
	return WR_OK;
}

wr_status wrl_loop_run(wrl_loop *l, int (*stop)(void *arg), void *arg, int timeout_ms)
{
	wr_clock t0, t;
	wr_status st;

	if (l == NULL)
		return WR_E_INVAL;
	wrl_clock(&t0);
	for (;;) {
		uint64_t el;
		int wait = -1;

		if (stop != NULL && stop(arg))
			return WR_OK;
		wrl_clock(&t);
		el = t.mono_ms > t0.mono_ms ? t.mono_ms - t0.mono_ms : 0;
		if (timeout_ms >= 0) {
			if (el >= (uint64_t)timeout_ms)
				return WR_E_TIMEOUT;
			wait = (int)((uint64_t)timeout_ms - el);
		}
		st = wrl_loop_step(l, wait);
		if (st != WR_OK)
			return st;
	}
}
