/* SPDX-License-Identifier: MIT */
/*
 * test_host_loop.c - the Linux socket pump (harness/host/wrl_loop.c) against the simulated monitor over
 * REAL TCP sockets on 127.0.0.1. A pthread server owns a sim_mon (all sim calls happen under its mutex),
 * accepts connections and moves bytes between the sockets and the simulator; the test thread runs the
 * client engine with wrl_loop_run / wrl_loop_step exactly as a program would.
 *
 * The pump source is included, not linked (like test_host_sys.c), which allows a few deterministic
 * interventions before the include:
 *   sendmsg -> hk_sendmsg   short sends (a cap per call), EAGAIN, EINTR and hard errors on demand;
 *                           checks that every send asks for MSG_NOSIGNAL
 *   recv    -> hk_recv      one byte at a time, EAGAIN, EINTR, errors on demand
 *   connect -> hk_connect   counts and timestamps every dial; an immediate failure on demand
 *   poll    -> hk_poll      counts the waits and records the longest one (idle must sleep)
 *   wr_conn_closed / wr_conn_connected -> spies that log what the pump told the engine (errno included)
 *
 * Checked: a session to ACTIVE with both key types; delivery of the monitor's maps and of a pushed epoch
 * and monmap; the server cutting the session (EOF, reset) and the reconnect after it; a connect to a
 * closed port (errno, UNREACHABLE events, exponential back-off, no busy loop); a connect that never
 * completes (the action's timeout, ETIMEDOUT); the engine asking for a close (handshake timeout) and the
 * pump answering it; slow server writes and one byte reads; short sends, EAGAIN and EINTR on both
 * directions; hard send / recv errors; a zero receive window (backpressure) without spinning; an idle
 * client that sleeps; a failing random source (fatal status); the argument checks and the timeout of
 * wrl_loop_run; a wrong key (refusal events, back-off).
 * Driven by injected actions (the pump's own error paths, which a real engine does not produce on demand): a
 * dial of an unusable address (EINVAL), a CONNECT beyond the 64 sockets (EMFILE), a CONNECT for a live id, a
 * CLOSE of a live and of an unknown id, an IPv6 dial (accepted and refused), a socket that cannot be made
 * non-blocking (no leaked descriptor), an engine that reports more gather elements than it was asked for;
 * wrl_sockaddr itself; and the wr-monprobe tool end to end (exit codes, output, no key in the output).
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "wrt.h"
#include "sim_mon.h"

#include "../host/wrl_sys.c"

/* ---- interventions installed before the pump is included ------------------------------------------ */

static ssize_t hk_sendmsg(int fd, const struct msghdr *m, int flags);
static ssize_t hk_recv(int fd, void *buf, size_t n, int flags);
static int hk_connect(int fd, const struct sockaddr *sa, socklen_t sl);
static int hk_poll(struct pollfd *pf, nfds_t n, int timeout);
static void spy_closed(wr_client *c, wr_conn_id id, int err);
static void spy_connected(wr_client *c, wr_conn_id id);
static int hk_fcntl(int fd, int cmd, ...);
static int spy_next_action(wr_client *c, wr_action *a);
static size_t spy_tx_peek(wr_client *c, wr_conn_id id, wr_iov *iov, size_t max_iov);
static void spy_tx_consume(wr_client *c, wr_conn_id id, size_t n);
#define sendmsg hk_sendmsg
#define recv hk_recv
#define connect hk_connect
#define poll hk_poll
#define wr_conn_closed spy_closed
#define wr_conn_connected spy_connected
#define fcntl hk_fcntl
#define wr_client_next_action spy_next_action
#define wr_conn_tx_peek spy_tx_peek
#define wr_conn_tx_consume spy_tx_consume

#include "../host/wrl_loop.c"

#undef sendmsg
#undef recv
#undef connect
#undef poll
#undef wr_conn_closed
#undef wr_conn_connected
#undef fcntl
#undef wr_client_next_action
#undef wr_conn_tx_peek
#undef wr_conn_tx_consume

#define MAXCON 64u
#define MAXEV 512u
#define MAXMAP 64u

static uint64_t now_ms(void)
{
	wr_clock c;

	wrl_clock(&c);
	return c.mono_ms;
}

static struct hk {
	int send_max;                       /* > 0: at most this many bytes per sendmsg */
	int send_eagain, send_eintr;        /* the next N sends fail like this */
	int send_err;                       /* errno to fail the next send with (once) */
	int recv_max;                       /* > 0: at most this many bytes per recv */
	int recv_eagain, recv_eintr;
	int recv_err;
	int connect_err;                    /* errno to fail the next connect with (once) */
	int fcntl_err;                      /* errno to fail the next F_SETFL with (once) */
	long n_send, n_short, n_send_eagain, n_recv, n_recv_eagain, n_poll, n_connect;
	long bad_flags;
	int max_poll_ms;
	int last_fd;                        /* the socket of the last recv */
	uint64_t conn_at[MAXCON];
} hk;

static struct spy {
	struct {
		wr_conn_id id;
		int err;
		uint64_t at;
	} closed[MAXCON];
	unsigned n_closed, n_connected;
	wr_conn_id connected[MAXCON];
} sp;

/* Actions the test hands to the pump ahead of the engine's own, and a lying tx_peek for fake connections. */
#define FAKE_BASE 0xF0000000u
static struct inj {
	wr_action q[96];
	unsigned n, pos;
	unsigned tx_lie;                /* > 0: a fake connection's peek claims max + tx_lie elements */
	unsigned n_consume, max_consume;
	size_t consumed;
} inj;

static ssize_t hk_sendmsg(int fd, const struct msghdr *m, int flags)
{
	struct msghdr m2 = *m;
	struct iovec iv[16];
	size_t i, total = 0, left;

	hk.n_send++;
	if ((flags & MSG_NOSIGNAL) == 0)
		hk.bad_flags++;
	if (hk.send_err != 0) {
		errno = hk.send_err;
		hk.send_err = 0;
		return -1;
	}
	if (hk.send_eintr > 0) {
		hk.send_eintr--;
		errno = EINTR;
		return -1;
	}
	if (hk.send_eagain > 0) {
		hk.send_eagain--;
		hk.n_send_eagain++;
		errno = EAGAIN;
		return -1;
	}
	for (i = 0; i < m->msg_iovlen; i++)
		total += m->msg_iov[i].iov_len;
	if (hk.send_max > 0 && total > (size_t)hk.send_max && m->msg_iovlen <= 16) {
		left = (size_t)hk.send_max;
		for (i = 0; i < m->msg_iovlen && left > 0; i++) {
			iv[i] = m->msg_iov[i];
			if (iv[i].iov_len > left)
				iv[i].iov_len = left;
			left -= iv[i].iov_len;
		}
		m2.msg_iov = iv;
		m2.msg_iovlen = i;
		hk.n_short++;
	}
	return sendmsg(fd, &m2, flags);
}

static ssize_t hk_recv(int fd, void *buf, size_t n, int flags)
{
	hk.n_recv++;
	hk.last_fd = fd;
	if (hk.recv_err != 0) {
		errno = hk.recv_err;
		hk.recv_err = 0;
		return -1;
	}
	if (hk.recv_eintr > 0) {
		hk.recv_eintr--;
		errno = EINTR;
		return -1;
	}
	if (hk.recv_eagain > 0) {
		hk.recv_eagain--;
		hk.n_recv_eagain++;
		errno = EAGAIN;
		return -1;
	}
	if (hk.recv_max > 0 && n > (size_t)hk.recv_max)
		n = (size_t)hk.recv_max;
	return recv(fd, buf, n, flags);
}

static int hk_connect(int fd, const struct sockaddr *sa, socklen_t sl)
{
	if (hk.n_connect < (long)MAXCON)
		hk.conn_at[hk.n_connect] = now_ms();
	hk.n_connect++;
	if (hk.connect_err != 0) {
		errno = hk.connect_err;
		hk.connect_err = 0;
		return -1;
	}
	return connect(fd, sa, sl);
}

static int hk_poll(struct pollfd *pf, nfds_t n, int timeout)
{
	if (timeout != 0) {
		hk.n_poll++;
		if (timeout > hk.max_poll_ms)
			hk.max_poll_ms = timeout;
	}
	return poll(pf, n, timeout);
}

static void spy_closed(wr_client *c, wr_conn_id id, int err)
{
	if (sp.n_closed < MAXCON) {
		sp.closed[sp.n_closed].id = id;
		sp.closed[sp.n_closed].err = err;
		sp.closed[sp.n_closed].at = now_ms();
	}
	sp.n_closed++;
	wr_conn_closed(c, id, err);
}

static void spy_connected(wr_client *c, wr_conn_id id)
{
	if (sp.n_connected < MAXCON)
		sp.connected[sp.n_connected] = id;
	sp.n_connected++;
	wr_conn_connected(c, id);
}

static int hk_fcntl(int fd, int cmd, ...)
{
	va_list ap;
	int arg = 0;

	if (cmd != F_GETFL) {
		va_start(ap, cmd);
		arg = va_arg(ap, int);
		va_end(ap);
	}
	if (cmd == F_SETFL && hk.fcntl_err != 0) {
		errno = hk.fcntl_err;
		hk.fcntl_err = 0;
		return -1;
	}
	return cmd == F_GETFL ? fcntl(fd, cmd) : fcntl(fd, cmd, arg);
}

static int spy_next_action(wr_client *c, wr_action *a)
{
	if (inj.pos < inj.n) {
		*a = inj.q[inj.pos++];
		return 1;
	}
	return wr_client_next_action(c, a);
}

static size_t spy_tx_peek(wr_client *c, wr_conn_id id, wr_iov *iov, size_t max_iov)
{
	static const uint8_t junk[4] = {'j', 'u', 'n', 'k'};
	size_t i;

	if (id < FAKE_BASE)
		return wr_conn_tx_peek(c, id, iov, max_iov);
	if (inj.tx_lie == 0)
		return 0;
	for (i = 0; i < max_iov; i++) { /* every element it was asked for is valid; the count is a lie */
		iov[i].base = junk;
		iov[i].len = sizeof(junk);
	}
	return max_iov + inj.tx_lie;
}

static void spy_tx_consume(wr_client *c, wr_conn_id id, size_t n)
{
	if (id < FAKE_BASE) {
		wr_conn_tx_consume(c, id, n);
		return;
	}
	inj.n_consume++;
	inj.consumed += n;
	if (n > inj.max_consume)
		inj.max_consume = (unsigned)n;
}

/* ---- keys and the monitor ---------------------------------------------------------------------------- */

static void mkkey(wr_key *k, unsigned type, uint8_t salt)
{
	uint8_t raw[32];
	size_t i, len = type == WR_KEY_TYPE_AES ? 16u : 32u;

	for (i = 0; i < len; i++)
		raw[i] = (uint8_t)(salt + i * 7u);
	if (wr_key_from_raw(k, type, raw, len) != WR_OK)
		abort();
}

/* The committed MonMap vector with its one monitor address (10.77.0.10:3300) moved to 127.0.0.1:port, so that
 * the engine, which dials the monmap's addresses once it has one, keeps talking to this test's server. */
static uint8_t g_monmap[512];
static size_t g_monmap_len;

static void load_monmap(uint16_t port)
{
	static const uint8_t from[8] = {0x02, 0x00, 0x0c, 0xe4, 0x0a, 0x4d, 0x00, 0x0a};
	wrt_json j;
	uint8_t *b = NULL;
	size_t n = 0, i, hits = 0;

	if (wrt_json_load_vec(&j, "monclient/mmonmap-e3.json") != 0)
		abort();
	if (wrt_json_get_hex(&j, wrt_json_root(&j), "monmap_hex", &b, &n) != 0 || n > sizeof(g_monmap))
		abort();
	for (i = 0; i + 8u <= n; i++) {
		if (memcmp(b + i, from, 8) == 0) {
			b[i + 2] = (uint8_t)(port >> 8);
			b[i + 3] = (uint8_t)(port & 0xffu);
			b[i + 4] = 127, b[i + 5] = 0, b[i + 6] = 0, b[i + 7] = 1;
			hits++;
		}
	}
	WRT_CHECK_U64(hits, 1);
	memcpy(g_monmap, b, n);
	g_monmap_len = n;
	free(b);
	wrt_json_free(&j);
}

/* ---- the TCP server ------------------------------------------------------------------------------------ */

#define SMAX 8u
#define OUTCAP (256u * 1024u)

typedef struct sconn {
	int fd, silent;
	sim_mon_conn *sc;
	uint8_t *out;
	size_t out_len, out_off;
} sconn;

typedef struct srv {
	int lfd;
	uint16_t port;
	pthread_t th;
	pthread_mutex_t mu;
	volatile int stop;
	sim_mon *sim;
	sconn c[SMAX];
	/* knobs, set under the mutex */
	size_t wr_chunk, rd_chunk;
	unsigned silent_first;
	int cmd_rst;
	/* stats */
	unsigned n_accept, n_eof, n_rst;
} srv;

static srv S;

static void s_lock(void)
{
	pthread_mutex_lock(&S.mu);
}
static void s_unlock(void)
{
	pthread_mutex_unlock(&S.mu);
}

static void sconn_drop(sconn *c, int rst)
{
	if (rst) {
		struct linger lg;

		lg.l_onoff = 1;
		lg.l_linger = 0;
		(void)setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &lg, (socklen_t)sizeof(lg));
		S.n_rst++;
	}
	close(c->fd);
	if (c->sc != NULL)
		sim_mon_conn_free(c->sc);
	free(c->out);
	memset(c, 0, sizeof(*c));
	c->fd = -1;
}

static void s_accept(void)
{
	int fd = accept(S.lfd, NULL, NULL);
	unsigned i;
	int one = 1;

	if (fd < 0)
		return;
	for (i = 0; i < SMAX && S.c[i].fd >= 0; i++) {
	}
	if (i == SMAX) {
		close(fd);
		return;
	}
	(void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, (socklen_t)sizeof(one));
	memset(&S.c[i], 0, sizeof(S.c[i]));
	S.c[i].fd = fd;
	S.n_accept++;
	if (S.n_accept <= S.silent_first) {
		S.c[i].silent = 1;
		return;
	}
	S.c[i].sc = sim_mon_accept(S.sim);
	S.c[i].out = (uint8_t *)malloc(OUTCAP);
	if (S.c[i].sc == NULL || S.c[i].out == NULL)
		abort();
}

static void s_conn(sconn *c, short rev)
{
	uint8_t buf[4096];

	if (c->silent) {
		if (rev & (POLLIN | POLLHUP | POLLERR)) {
			ssize_t n = recv(c->fd, buf, sizeof(buf), 0);

			if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
				S.n_eof++;
				sconn_drop(c, 0);
			}
		}
		return;
	}
	if (rev & (POLLIN | POLLHUP | POLLERR)) {
		size_t want = S.rd_chunk != 0 ? S.rd_chunk : sizeof(buf);
		ssize_t n = recv(c->fd, buf, want < sizeof(buf) ? want : sizeof(buf), 0);

		if (n > 0) {
			(void)sim_mon_feed(c->sc, buf, (size_t)n);
		} else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
			S.n_eof++;
			sconn_drop(c, 0);
			return;
		}
	}
	if (c->out_off == c->out_len)
		c->out_off = c->out_len = 0;
	c->out_len += sim_mon_drain(c->sc, c->out + c->out_len, OUTCAP - c->out_len);
	if (c->out_len > c->out_off) {
		size_t left = c->out_len - c->out_off, k = S.wr_chunk != 0 && S.wr_chunk < left ? S.wr_chunk : left;
		ssize_t w = send(c->fd, c->out + c->out_off, k, MSG_NOSIGNAL | MSG_DONTWAIT);

		if (w > 0)
			c->out_off += (size_t)w;
		else if (w < 0 && errno != EAGAIN && errno != EINTR) {
			sconn_drop(c, 0);
			return;
		}
	}
	if (sim_mon_closed(c->sc) && c->out_off == c->out_len)
		sconn_drop(c, 0);
}

static void *srv_main(void *arg)
{
	(void)arg;
	while (!S.stop) {
		struct pollfd pf[1 + SMAX];
		unsigned i, n = 1;
		int idx[SMAX];

		pf[0].fd = S.lfd;
		pf[0].events = POLLIN;
		pf[0].revents = 0;
		s_lock();
		for (i = 0; i < SMAX; i++) {
			if (S.c[i].fd < 0)
				continue;
			pf[n].fd = S.c[i].fd;
			pf[n].events = POLLIN;
			if (S.c[i].out_len > S.c[i].out_off)
				pf[n].events |= POLLOUT;
			pf[n].revents = 0;
			idx[n - 1u] = (int)i;
			n++;
		}
		s_unlock();
		(void)poll(pf, n, 3);
		s_lock();
		if (S.cmd_rst) {
			for (i = 0; i < SMAX; i++)
				if (S.c[i].fd >= 0)
					sconn_drop(&S.c[i], 1);
			S.cmd_rst = 0;
		}
		if (pf[0].revents & POLLIN)
			s_accept();
		for (i = 1; i < n; i++) {
			sconn *c = &S.c[idx[i - 1u]];

			if (c->fd >= 0 && c->fd == pf[i].fd)
				s_conn(c, pf[i].revents);
		}
		/* the simulator may have output (a push, a released message) or a close with no socket event */
		for (i = 0; i < SMAX; i++)
			if (S.c[i].fd >= 0 && !S.c[i].silent)
				s_conn(&S.c[i], 0);
		s_unlock();
	}
	return NULL;
}

static int listen_on(uint16_t *port, int backlog)
{
	struct sockaddr_in sa;
	socklen_t sl = (socklen_t)sizeof(sa);
	int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;

	if (fd < 0)
		abort();
	(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof(one));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, backlog) != 0 ||
	    getsockname(fd, (struct sockaddr *)&sa, &sl) != 0)
		abort();
	*port = ntohs(sa.sin_port);
	return fd;
}

static void srv_start(unsigned key_type, void (*tweak)(sim_mon_cfg *))
{
	sim_mon_cfg sc;
	unsigned i;

	memset(&S, 0, sizeof(S));
	pthread_mutex_init(&S.mu, NULL);
	for (i = 0; i < SMAX; i++)
		S.c[i].fd = -1;
	S.lfd = listen_on(&S.port, 16);
	load_monmap(S.port);
	sim_mon_cfg_default(&sc);
	mkkey(&sc.key, key_type, 1);
	sc.m2.server_ip[0] = 127, sc.m2.server_ip[1] = 0, sc.m2.server_ip[2] = 0, sc.m2.server_ip[3] = 1;
	sc.m2.server_port = S.port;
	sc.monmap = g_monmap;
	sc.monmap_len = g_monmap_len;
	if (tweak != NULL)
		tweak(&sc);
	S.sim = sim_mon_new(&sc);
	if (S.sim == NULL)
		abort();
	if (pthread_create(&S.th, NULL, srv_main, NULL) != 0)
		abort();
}

static void srv_stop(void)
{
	unsigned i;

	S.stop = 1;
	pthread_join(S.th, NULL);
	for (i = 0; i < SMAX; i++)
		if (S.c[i].fd >= 0)
			sconn_drop(&S.c[i], 0);
	close(S.lfd);
	sim_mon_free(S.sim);
	pthread_mutex_destroy(&S.mu);
}

/* ---- the client side: engine, loop, collector -------------------------------------------------------- */

static struct rig {
	wr_config cfg;
	wr_host_ops ops;
	unsigned level;
	wr_cluster_spec spec;
	wr_mem_region arena, bulk;
	wr_client *c;
	wrl_loop *l;
} R;

static struct col {
	wr_event ev[MAXEV];
	uint64_t ev_at[MAXEV];
	unsigned n_ev, n_kind[8];
	struct {
		wr_mapmsg_kind kind;
		uint32_t epoch;
		size_t len;
	} maps[MAXMAP];
	unsigned n_maps, n_monmap, n_osdmap;
	uint32_t max_osd_epoch, max_mon_epoch;
	int hold_maps;
} C;

/* Random bytes that fail once the flag is set (the engine draws its first ones at create, so the failure is
 * armed after that). */
static int g_rng_fail;

static wr_status flaky_random(void *ctx, uint8_t *out, size_t n)
{
	if (g_rng_fail)
		return WR_E_HOST_RANDOM;
	return wrl_random(ctx, out, n);
}

static void rig_start(unsigned key_type, int wrong_key, uint16_t port, void (*tweak)(wr_config *), int fail_rng)
{
	wr_mem_req req;

	memset(&R, 0, sizeof(R));
	memset(&C, 0, sizeof(C));
	memset(&hk, 0, sizeof(hk));
	memset(&sp, 0, sizeof(sp));
	memset(&inj, 0, sizeof(inj));
	wr_config_profile_harness(&R.cfg);
	R.cfg.mon_msg_cap = 256u * 1024u;
	R.cfg.connect_timeout_ms = 1000;
	R.cfg.hunt_backoff_min_ms = 50;
	R.cfg.hunt_backoff_max_ms = 400;
	if (tweak != NULL)
		tweak(&R.cfg);
	R.level = getenv("WRL_TEST_LOG") != NULL ? (unsigned)atoi(getenv("WRL_TEST_LOG")) : WR_LOG_ERR;
	wrl_host_ops_init(&R.ops, &R.level);
	g_rng_fail = 0;
	if (fail_rng)
		R.ops.random = flaky_random;
	strcpy(R.spec.user, "client.winrbd");
	mkkey(&R.spec.key, key_type, wrong_key ? 99 : 1);
	R.spec.n_mons = 1;
	R.spec.mons[0].family = WR_AF_IPV4;
	R.spec.mons[0].ip[0] = 127, R.spec.mons[0].ip[3] = 1;
	R.spec.mons[0].port = port;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&R.cfg, &req));
	WRT_CHECK_STATUS(WR_OK, wrl_mem_alloc(&R.arena, req.arena));
	WRT_CHECK_STATUS(WR_OK, wrl_mem_alloc(&R.bulk, req.bulk));
	WRT_CHECK_STATUS(WR_OK, wr_client_create(&R.cfg, &R.ops, &R.spec, R.arena, R.bulk, &R.c));
	WRT_CHECK_STATUS(WR_OK, wrl_loop_create(R.c, &R.l));
}

static void rig_stop(void)
{
	wrl_loop_destroy(R.l);
	wr_client_destroy(R.c);
	wrl_mem_free(&R.arena);
	wrl_mem_free(&R.bulk);
}

static int collect(void *arg)
{
	wr_event e;
	wr_mapmsg m;

	(void)arg;
	while (wr_client_next_event(R.c, &e)) {
		if (C.n_ev < MAXEV) {
			C.ev[C.n_ev] = e;
			C.ev_at[C.n_ev++] = now_ms();
		}
		if ((unsigned)e.kind < 8u)
			C.n_kind[e.kind]++;
	}
	while (!C.hold_maps && wr_client_mapmsg_peek(R.c, &m)) {
		if (C.n_maps < MAXMAP) {
			C.maps[C.n_maps].kind = m.kind;
			C.maps[C.n_maps].epoch = m.newest_epoch;
			C.maps[C.n_maps].len = m.front_len;
			C.n_maps++;
		}
		if (m.kind == WR_MAPMSG_MONMAP) {
			C.n_monmap++;
			if (m.newest_epoch > C.max_mon_epoch)
				C.max_mon_epoch = m.newest_epoch;
		} else {
			C.n_osdmap++;
			if (m.newest_epoch > C.max_osd_epoch)
				C.max_osd_epoch = m.newest_epoch;
		}
		wr_client_mapmsg_release(R.c);
	}
	return 0;
}

static int stop_never(void *arg)
{
	return collect(arg);
}

static int stop_active_maps(void *arg)
{
	collect(arg);
	return wr_client_get_state(R.c) == WR_CS_ACTIVE && C.n_monmap > 0 && C.n_osdmap > 0;
}

typedef struct want_kind {
	wr_ev_kind k;
	unsigned n;
} want_kind;

static int stop_kind(void *arg)
{
	const want_kind *w = (const want_kind *)arg;

	collect(NULL);
	return C.n_kind[w->k] >= w->n;
}

static int stop_up_active(void *arg)
{
	unsigned n = *(const unsigned *)arg;

	collect(NULL);
	return C.n_kind[WR_EV_MON_SESSION_UP] >= n && wr_client_get_state(R.c) == WR_CS_ACTIVE;
}

static int stop_osd_epoch(void *arg)
{
	collect(NULL);
	return C.max_osd_epoch >= *(const uint32_t *)arg;
}

static int stop_mon_epoch(void *arg)
{
	collect(NULL);
	return C.max_mon_epoch >= *(const uint32_t *)arg;
}

static int stop_closed(void *arg)
{
	collect(NULL);
	return sp.n_closed >= *(const unsigned *)arg;
}

/* Run until stop or timeout; the checks name what was waited for. */
static wr_status run_until(int (*stop)(void *), void *arg, int ms)
{
	return wrl_loop_run(R.l, stop, arg, ms);
}

/* Steps for `ms` milliseconds; returns the number of steps taken. */
static unsigned steps_for(int ms)
{
	uint64_t end = now_ms() + (uint64_t)ms;
	unsigned n = 0;

	while (now_ms() < end) {
		int left = (int)(end - now_ms());

		collect(NULL);
		if (wrl_loop_step(R.l, left) != WR_OK)
			break;
		n++;
	}
	return n;
}

/* ---- tests ------------------------------------------------------------------------------------------- */

static void tweak_keepalive_fast(wr_config *c)
{
	c->keepalive_ms = 100;
}

static void test_session_and_maps(unsigned key_type)
{
	uint32_t e43 = 43, mon4 = 4;
	unsigned up = 1, i, mon_seen = 0, osd_seen = 0;

	srv_start(key_type, NULL);
	rig_start(key_type, 0, S.port, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, run_until(stop_active_maps, NULL, 8000));
	WRT_CHECK(wr_client_get_state(R.c) == WR_CS_ACTIVE);
	WRT_CHECK_U64(C.n_kind[WR_EV_MON_SESSION_UP], 1);
	WRT_CHECK_U64(C.n_kind[WR_EV_AUTH_FAILED], 0);
	WRT_CHECK_U64(C.n_kind[WR_EV_FATAL], 0);
	WRT_CHECK(C.n_monmap >= 1 && C.n_osdmap >= 1);
	WRT_CHECK_U64(C.max_mon_epoch, 3); /* the committed MonMap vector */
	WRT_CHECK_U64(C.max_osd_epoch, 42);
	for (i = 0; i < C.n_maps; i++) {
		WRT_CHECK(C.maps[i].len > 16u);
		mon_seen += C.maps[i].kind == WR_MAPMSG_MONMAP;
		osd_seen += C.maps[i].kind == WR_MAPMSG_OSDMAP;
	}
	WRT_CHECK(mon_seen >= 1 && osd_seen >= 1);
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), 1);
	WRT_CHECK_U64(sp.n_connected, 1);
	WRT_CHECK_U64(hk.bad_flags, 0);
	s_lock();
	WRT_CHECK_U64(S.n_accept, 1);
	WRT_CHECK_U64(S.sim->n_accepted, 1);
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(S.sim)); /* a new osdmap epoch, pushed to the subscriber */
	s_unlock();
	WRT_CHECK_STATUS(WR_OK, run_until(stop_osd_epoch, &e43, 3000));
	s_lock();
	WRT_CHECK_STATUS(WR_OK, sim_mon_bump_monmap(S.sim));
	s_unlock();
	WRT_CHECK_STATUS(WR_OK, run_until(stop_mon_epoch, &mon4, 3000));
	WRT_CHECK_U64(C.n_kind[WR_EV_MON_SESSION_UP], up);
	rig_stop();
	srv_stop();
}

/* The server cuts the session: EOF, then a reset. Each time the engine reports DOWN and reconnects. */
static void test_server_cuts(void)
{
	unsigned up = 2;
	unsigned i, eof_seen = 0;

	srv_start(WR_KEY_TYPE_AES256K, NULL);
	rig_start(WR_KEY_TYPE_AES256K, 0, S.port, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, run_until(stop_active_maps, NULL, 8000));

	s_lock();
	sim_mon_restart(S.sim); /* every session cut at once, the monmap epoch goes up */
	s_unlock();
	WRT_CHECK_STATUS(WR_OK, run_until(stop_up_active, &up, 8000));
	WRT_CHECK(C.n_kind[WR_EV_MON_SESSION_DOWN] >= 1);
	WRT_CHECK(sp.n_closed >= 1);
	WRT_CHECK(sp.closed[0].err == 0 || sp.closed[0].err == ECONNRESET); /* orderly EOF (0) is what a clean close gives */
	for (i = 0; i < sp.n_closed && i < MAXCON; i++)
		eof_seen += sp.closed[i].err == 0;
	WRT_CHECK(eof_seen >= 1);
	WRT_CHECK(sp.closed[0].id != 0);
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), 1);
	WRT_CHECK_U64(sp.n_connected, 2);
	s_lock();
	WRT_CHECK_U64(S.sim->n_accepted, 2);
	s_unlock();

	/* a reset (RST instead of FIN): ECONNRESET, then the engine hunts again */
	up = 3;
	sp.n_closed = 0;
	s_lock();
	S.cmd_rst = 1;
	s_unlock();
	WRT_CHECK_STATUS(WR_OK, run_until(stop_up_active, &up, 8000));
	WRT_CHECK(sp.n_closed >= 1);
	WRT_CHECK(sp.closed[0].err == ECONNRESET || sp.closed[0].err == EPIPE);
	WRT_CHECK(C.n_kind[WR_EV_MON_SESSION_DOWN] >= 2);
	WRT_CHECK(hk.bad_flags == 0);
	rig_stop();
	srv_stop();
}

static unsigned closed_port(void)
{
	uint16_t p;
	int fd = listen_on(&p, 1);

	close(fd);
	return p;
}

/* Nothing listens: ECONNREFUSED, hunting, UNREACHABLE after every round, a growing wait, no spinning. */
static void test_connect_refused(void)
{
	unsigned i, n;
	uint64_t first_gap, last_gap;

	rig_start(WR_KEY_TYPE_AES256K, 0, (uint16_t)closed_port(), NULL, 0);
	WRT_CHECK_STATUS(WR_E_TIMEOUT, run_until(stop_never, NULL, 1800));
	WRT_CHECK(wr_client_get_state(R.c) == WR_CS_HUNTING);
	WRT_CHECK(C.n_kind[WR_EV_CLUSTER_UNREACHABLE] >= 3);
	WRT_CHECK_U64(C.n_kind[WR_EV_MON_SESSION_UP], 0);
	n = hk.n_connect < (long)MAXCON ? (unsigned)hk.n_connect : MAXCON;
	WRT_CHECK(n >= 5 && n <= 20);
	WRT_CHECK(sp.n_closed >= n - 1u);
	for (i = 0; i < sp.n_closed && i < n - 1u; i++)
		WRT_CHECK_U64(sp.closed[i].err, ECONNREFUSED);
	for (i = 1; i < n; i++) {
		uint64_t gap = hk.conn_at[i] - hk.conn_at[i - 1u];

		WRT_CHECK(gap >= 45u);  /* never below the minimum wait */
		WRT_CHECK(gap <= 700u); /* never far above the maximum (400 ms) */
	}
	if (n >= 5) {
		first_gap = hk.conn_at[1] - hk.conn_at[0];
		last_gap = hk.conn_at[n - 1u] - hk.conn_at[n - 2u];
		WRT_CHECK(last_gap >= 2u * first_gap); /* exponential back-off */
	}
	WRT_CHECK(hk.n_poll < 60); /* it slept between attempts */
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), 0);
	WRT_CHECK(C.ev[0].kind != WR_EV_NONE);
	rig_stop();

	/* an immediate failure of connect(2) itself is reported the same way */
	rig_start(WR_KEY_TYPE_AES256K, 0, (uint16_t)closed_port(), NULL, 0);
	hk.connect_err = ENETUNREACH;
	WRT_CHECK_STATUS(WR_OK, run_until(stop_closed, &(unsigned){1}, 2000));
	WRT_CHECK_U64(sp.closed[0].err, ENETUNREACH);
	rig_stop();
}

static void tweak_connect_tmo(wr_config *c)
{
	c->connect_timeout_ms = 300;
}

/* A connect that never completes: a listener whose accept queue is full drops the SYN. */
static void test_connect_timeout(void)
{
	uint16_t port;
	int lfd = listen_on(&port, 0), fill[4], i, probe_done = 0;
	uint64_t t0, dt;

	for (i = 0; i < 4; i++) {
		struct sockaddr_in sa;
		struct pollfd pf;

		fill[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sa.sin_port = htons(port);
		(void)connect(fill[i], (struct sockaddr *)&sa, sizeof(sa));
		pf.fd = fill[i];
		pf.events = POLLOUT;
		pf.revents = 0;
		if (i == 3)
			probe_done = poll(&pf, 1, 120) > 0 && (pf.revents & POLLOUT) != 0;
	}
	if (probe_done) {
		fprintf(stderr, "note: this kernel completes connects to a full accept queue; connect timeout test skipped\n");
	} else {
		rig_start(WR_KEY_TYPE_AES256K, 0, port, tweak_connect_tmo, 0);
		WRT_CHECK_STATUS(WR_OK, run_until(stop_closed, &(unsigned){1}, 3000));
		t0 = hk.conn_at[0];
		WRT_CHECK(sp.n_closed >= 1);
		WRT_CHECK_U64(sp.closed[0].err, ETIMEDOUT);
		dt = sp.closed[0].at - t0;
		WRT_CHECK(dt >= 280u && dt <= 800u);
		WRT_CHECK_U64(wrl_loop_open_sockets(R.l), 0);
		rig_stop();
	}
	for (i = 0; i < 4; i++)
		close(fill[i]);
	close(lfd);
}

static void tweak_hs_timeout(wr_config *c)
{
	c->handshake_timeout_ms = 300;
}

/* The server accepts and says nothing: the engine gives up (handshake timeout), asks for a close, and the
 * pump closes the socket (the server sees EOF) and answers it; the next attempt reaches a normal server. */
static void test_close_action(void)
{
	unsigned up = 1;

	srv_start(WR_KEY_TYPE_AES256K, NULL);
	s_lock();
	S.silent_first = 1;
	s_unlock();
	rig_start(WR_KEY_TYPE_AES256K, 0, S.port, tweak_hs_timeout, 0);
	WRT_CHECK_STATUS(WR_OK, run_until(stop_up_active, &up, 8000));
	WRT_CHECK(sp.n_closed >= 1);
	WRT_CHECK_U64(sp.closed[0].err, 0); /* the answer to WR_ACT_CLOSE is an orderly close */
	WRT_CHECK(sp.closed[0].at - hk.conn_at[0] >= 250u);
	s_lock();
	WRT_CHECK_U64(S.n_accept, 2);
	WRT_CHECK(S.n_eof >= 1); /* the silent connection really was closed by us */
	s_unlock();
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), 1);
	rig_stop();
	srv_stop();
}

/* A slow server (one byte per write) and a slow reader (one byte per recv, one byte per server read). */
static void test_slow_peers(void)
{
	srv_start(WR_KEY_TYPE_AES256K, NULL);
	s_lock();
	S.wr_chunk = 1;
	S.rd_chunk = 1;
	s_unlock();
	rig_start(WR_KEY_TYPE_AES256K, 0, S.port, NULL, 0);
	hk.recv_max = 1;
	hk.send_max = 5;
	WRT_CHECK_STATUS(WR_OK, run_until(stop_active_maps, NULL, 20000));
	WRT_CHECK(wr_client_get_state(R.c) == WR_CS_ACTIVE);
	WRT_CHECK_U64(C.n_kind[WR_EV_MON_SESSION_UP], 1);
	WRT_CHECK_U64(C.n_kind[WR_EV_MON_SESSION_DOWN], 0);
	WRT_CHECK(hk.n_short > 0);
	WRT_CHECK(hk.n_recv > 1000);
	WRT_CHECK_U64(C.max_osd_epoch, 42);
	rig_stop();
	srv_stop();
}

/* Partial sends, EAGAIN and EINTR in both directions, then hard errors, on a session that talks every 100 ms. */
static void test_io_errors(void)
{
	unsigned up = 2, closed_before;
	uint64_t t;

	srv_start(WR_KEY_TYPE_AES256K, NULL);
	rig_start(WR_KEY_TYPE_AES256K, 0, S.port, tweak_keepalive_fast, 0);
	WRT_CHECK_STATUS(WR_OK, run_until(stop_active_maps, NULL, 8000));

	hk.send_max = 3;
	hk.send_eagain = 4;
	hk.send_eintr = 3;
	hk.recv_eagain = 4;
	hk.recv_eintr = 3;
	t = now_ms();
	while (now_ms() - t < 1500 && (hk.send_eagain > 0 || hk.recv_eagain > 0 || hk.send_eintr > 0 || hk.recv_eintr > 0))
		(void)steps_for(50);
	WRT_CHECK_U64(hk.send_eagain, 0);
	WRT_CHECK_U64(hk.recv_eagain, 0);
	WRT_CHECK_U64(hk.send_eintr, 0);
	WRT_CHECK_U64(hk.recv_eintr, 0);
	/* the last injected failure may have been the final send of the loop above: wait for a send that is cut short */
	t = now_ms();
	while (now_ms() - t < 3000 && hk.n_short == 0)
		(void)steps_for(50);
	WRT_CHECK(hk.n_short > 0);
	hk.send_max = 0;
	(void)steps_for(300);
	WRT_CHECK(wr_client_get_state(R.c) == WR_CS_ACTIVE); /* none of that cost the session */
	WRT_CHECK_U64(C.n_kind[WR_EV_MON_SESSION_DOWN], 0);
	WRT_CHECK_U64(sp.n_closed, 0);

	/* a hard send error ends the connection with its errno; the engine reconnects */
	closed_before = sp.n_closed;
	hk.send_err = EPIPE;
	WRT_CHECK_STATUS(WR_OK, run_until(stop_closed, &(unsigned){1}, 3000));
	WRT_CHECK(sp.n_closed == closed_before + 1u);
	WRT_CHECK_U64(sp.closed[0].err, EPIPE);
	WRT_CHECK_STATUS(WR_OK, run_until(stop_up_active, &up, 8000));

	/* a hard recv error likewise */
	up = 3;
	hk.recv_err = ECONNRESET;
	WRT_CHECK_STATUS(WR_OK, run_until(stop_closed, &(unsigned){2}, 3000));
	WRT_CHECK_U64(sp.closed[1].err, ECONNRESET);
	WRT_CHECK_STATUS(WR_OK, run_until(stop_up_active, &up, 8000));
	WRT_CHECK_U64(hk.bad_flags, 0); /* every send said MSG_NOSIGNAL */
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), 1);
	rig_stop();
	srv_stop();
}

static void tweak_one_slot(wr_config *c)
{
	c->mapmsg_queue = 1;
}

static void tweak_big_osdmap(sim_mon_cfg *c)
{
	c->osdmap_pad = 150u * 1024u; /* an MOSDMap front larger than the staging ring and the socket buffers' idle share */
}

/* The consumer sits on the only map slot: the receive window closes, the socket still has data, and the
 * pump must neither read nor spin. Releasing the slot lets the rest through. */
static void test_backpressure(void)
{
	unsigned steps, i, big = 0;
	long polls0, recv0;

	srv_start(WR_KEY_TYPE_AES256K, tweak_big_osdmap);
	rig_start(WR_KEY_TYPE_AES256K, 0, S.port, tweak_one_slot, 0);
	C.hold_maps = 1;
	WRT_CHECK_STATUS(WR_OK, run_until(stop_kind, &(want_kind){WR_EV_MAPMSG, 1}, 8000));
	(void)steps_for(200); /* settle: whatever fits is in the ring now */
	{ /* the precondition of this test: the socket really holds unread bytes while the window is closed */
		uint8_t b;

		WRT_CHECK(recv(hk.last_fd, &b, 1, MSG_PEEK | MSG_DONTWAIT) == 1);
	}
	polls0 = hk.n_poll;
	recv0 = hk.n_recv;
	steps = steps_for(500);
	/* The engine itself asks for a call every 10 ms while it holds output back (WRI_MON_RETRY_MS), so about 50
	 * steps fit in 500 ms. A pump that polled a socket with unread data and a closed window would do thousands. */
	WRT_CHECK(steps <= 60u);
	WRT_CHECK(hk.n_poll - polls0 <= 60);
	WRT_CHECK(hk.n_recv - recv0 <= 60); /* and it does not read into a closed window */
	C.hold_maps = 0; /* collect() now releases the held message, which opens the window */
	WRT_CHECK_STATUS(WR_OK, run_until(stop_active_maps, NULL, 8000));
	WRT_CHECK(C.n_monmap >= 1 && C.n_osdmap >= 1);
	WRT_CHECK_U64(C.max_osd_epoch, 42);
	for (i = 0; i < C.n_maps; i++)
		big += C.maps[i].kind == WR_MAPMSG_OSDMAP && C.maps[i].len > 150u * 1024u;
	WRT_CHECK(big >= 1); /* the large message did arrive whole once the slot was free */
	rig_stop();
	srv_stop();
}

/* An established, quiet session: the loop sleeps in poll(2) until its next timer, it does not spin. */
static void test_idle_sleeps(void)
{
	unsigned steps;
	long polls0;

	srv_start(WR_KEY_TYPE_AES256K, NULL);
	rig_start(WR_KEY_TYPE_AES256K, 0, S.port, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, run_until(stop_active_maps, NULL, 8000));
	(void)steps_for(150);
	polls0 = hk.n_poll;
	steps = steps_for(800);
	WRT_CHECK(steps >= 1u && steps <= 10u);
	WRT_CHECK(hk.n_poll - polls0 <= 10);
	WRT_CHECK(hk.max_poll_ms >= 300); /* at least one real sleep of a few hundred ms */
	rig_stop();
	srv_stop();
}

static int stop_after_n(void *arg)
{
	int *n = (int *)arg;

	return ++*n > 0;
}

static void test_api_and_fatal(void)
{
	wrl_loop *l = NULL;
	int calls = 0;
	wr_status st;
	uint64_t t;

	WRT_CHECK_STATUS(WR_E_INVAL, wrl_loop_create(NULL, &l));
	WRT_CHECK(l == NULL);
	rig_start(WR_KEY_TYPE_AES256K, 0, (uint16_t)closed_port(), NULL, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_loop_create(R.c, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_loop_step(NULL, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_loop_run(NULL, NULL, NULL, 10));
	wrl_loop_destroy(NULL);
	WRT_CHECK_U64(wrl_loop_open_sockets(NULL), 0);
	/* stop is asked before the first step */
	WRT_CHECK_STATUS(WR_OK, wrl_loop_run(R.l, stop_after_n, &calls, 1000));
	WRT_CHECK_U64(hk.n_connect, 0);
	/* the timeout is honoured and not by a long way overshot */
	t = now_ms();
	WRT_CHECK_STATUS(WR_E_TIMEOUT, wrl_loop_run(R.l, NULL, NULL, 200));
	t = now_ms() - t;
	WRT_CHECK(t >= 190u && t < 600u);
	WRT_CHECK_STATUS(WR_E_TIMEOUT, wrl_loop_run(R.l, NULL, NULL, 0));
	rig_stop();

	/* no random bytes: the client fails for good, the loop reports it */
	srv_start(WR_KEY_TYPE_AES256K, NULL);
	rig_start(WR_KEY_TYPE_AES256K, 0, S.port, NULL, 1);
	g_rng_fail = 1;
	R.level = 0; /* the failure is expected: keep stderr quiet */
	st = wrl_loop_run(R.l, NULL, NULL, 2000);
	WRT_CHECK(st != WR_OK && st != WR_E_TIMEOUT);
	WRT_CHECK(wr_client_get_state(R.c) == WR_CS_FAILED);
	WRT_CHECK_STATUS(st, wrl_loop_step(R.l, 0)); /* and keeps reporting it */
	rig_stop();
	srv_stop();
}

/* A key the monitor does not accept: AUTH_FAILED events, never ACTIVE, back-off between the attempts. */
static void test_wrong_key(void)
{
	srv_start(WR_KEY_TYPE_AES256K, NULL);
	rig_start(WR_KEY_TYPE_AES256K, 1, S.port, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, run_until(stop_kind, &(want_kind){WR_EV_AUTH_FAILED, 3}, 8000));
	WRT_CHECK(wr_client_get_state(R.c) != WR_CS_ACTIVE);
	WRT_CHECK_U64(C.n_kind[WR_EV_MON_SESSION_UP], 0);
	WRT_CHECK(C.n_kind[WR_EV_AUTH_FAILED] >= 3);
	WRT_CHECK(hk.n_connect >= 3);
	WRT_CHECK(hk.n_poll < 200);
	rig_stop();
	srv_stop();
}

/* ---- pump error paths, driven by injected actions ----------------------------------------------------- */

static int count_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	int n = 0;
	struct dirent *e;

	if (d == NULL)
		return -1;
	while ((e = readdir(d)) != NULL)
		if (e->d_name[0] != '.')
			n++;
	closedir(d);
	return n - 1; /* the descriptor of the directory stream itself */
}

/* The next free queue entry; the queue starts over once the pump has taken everything. */
static wr_action *inj_slot(void)
{
	if (inj.pos == inj.n)
		inj.pos = inj.n = 0;
	if (inj.n >= sizeof(inj.q) / sizeof(inj.q[0]))
		abort();
	return &inj.q[inj.n++];
}

static void inj_connect(uint32_t id, unsigned family, uint16_t port, const uint8_t *ip, size_t iplen)
{
	wr_action *a = inj_slot();

	memset(a, 0, sizeof(*a));
	a->kind = WR_ACT_CONNECT;
	a->conn = id;
	a->addr.family = (uint8_t)family;
	a->addr.port = port;
	memcpy(a->addr.ip, ip, iplen);
	a->timeout_ms = 2000;
}

static void inj_close(uint32_t id)
{
	wr_action *a = inj_slot();

	memset(a, 0, sizeof(*a));
	a->kind = WR_ACT_CLOSE;
	a->conn = id;
}

/* Last recorded close of an id: its errno, or -1 if it was never closed. */
static int closed_err_of(wr_conn_id id)
{
	unsigned i;

	for (i = 0; i < sp.n_closed && i < MAXCON; i++)
		if (sp.closed[i].id == id)
			return sp.closed[i].err;
	return -1;
}

static unsigned closed_count_err(int err)
{
	unsigned i, n = 0;

	for (i = 0; i < sp.n_closed && i < MAXCON; i++)
		n += sp.closed[i].err == err && sp.closed[i].id >= FAKE_BASE;
	return n;
}

static int connected_has(wr_conn_id id)
{
	unsigned i;

	for (i = 0; i < sp.n_connected && i < MAXCON; i++)
		if (sp.connected[i] == id)
			return 1;
	return 0;
}

static void tweak_hs_long(wr_config *c)
{
	c->handshake_timeout_ms = 30000; /* the engine's own socket stays up (silent peer) for the whole test */
}

static void test_sockaddr(void)
{
	struct sockaddr_storage ss;
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;
	wr_addr a;
	int fam = 0;
	static const uint8_t v6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34};

	memset(&a, 0, sizeof(a));
	a.family = WR_AF_IPV4;
	a.port = 0x1234;
	a.ip[0] = 10, a.ip[1] = 77, a.ip[2] = 0, a.ip[3] = 10;
	WRT_CHECK_U64(wrl_sockaddr(&a, &ss, &fam), sizeof(sa4));
	memcpy(&sa4, &ss, sizeof(sa4));
	WRT_CHECK_U64(fam, AF_INET);
	WRT_CHECK_U64(sa4.sin_family, AF_INET);
	WRT_CHECK_U64(ntohs(sa4.sin_port), 0x1234); /* host order in the wr_addr, network order in the sockaddr */
	WRT_CHECK_U64(ntohl(sa4.sin_addr.s_addr), 0x0a4d000au);

	memset(&a, 0, sizeof(a));
	a.family = WR_AF_IPV6;
	a.port = 3300;
	memcpy(a.ip, v6, 16);
	fam = 0;
	WRT_CHECK_U64(wrl_sockaddr(&a, &ss, &fam), sizeof(sa6));
	memcpy(&sa6, &ss, sizeof(sa6));
	WRT_CHECK_U64(fam, AF_INET6);
	WRT_CHECK_U64(sa6.sin6_family, AF_INET6);
	WRT_CHECK_U64(ntohs(sa6.sin6_port), 3300);
	WRT_CHECK_MEM(&sa6.sin6_addr, v6, 16);

	/* port 0, no family, an unknown family: not dialled, and the output is cleared, not left as garbage */
	a.port = 0;
	memset(&ss, 0xaa, sizeof(ss));
	WRT_CHECK_U64(wrl_sockaddr(&a, &ss, &fam), 0);
	WRT_CHECK(((uint8_t *)&ss)[0] == 0 && ((uint8_t *)&ss)[sizeof(ss) - 1u] == 0);
	a.port = 3300;
	a.family = 0;
	WRT_CHECK_U64(wrl_sockaddr(&a, &ss, &fam), 0);
	a.family = 5;
	WRT_CHECK_U64(wrl_sockaddr(&a, &ss, &fam), 0);
	a.family = 255;
	WRT_CHECK_U64(wrl_sockaddr(&a, &ss, &fam), 0);
}

/* Everything the engine would never ask for on demand: bad addresses, a full socket table, repeated and stale
 * ids, IPv6, a failing fcntl, a miscounting tx_peek. The engine's own connection (a listener that never
 * accepts and a long handshake timeout) keeps one slot occupied throughout. */
static void test_injected_actions(void)
{
	uint16_t port, port6 = 0;
	int lfd, l6 = -1, fds0, fds1, i;
	unsigned base, n_emfile, n_emfile0, steps;
	static const uint8_t lo4[4] = {127, 0, 0, 1};
	uint8_t lo6[16];
	uint32_t id;

	fds0 = count_fds();
	lfd = listen_on(&port, 128);
	rig_start(WR_KEY_TYPE_AES256K, 0, port, tweak_hs_long, 0);
	for (i = 0; i < 40 && wrl_loop_open_sockets(R.l) == 0; i++)
		(void)wrl_loop_step(R.l, 20);
	base = wrl_loop_open_sockets(R.l);
	WRT_CHECK_U64(base, 1);
	fds1 = count_fds();

	/* unusable addresses: answered with EINVAL, no socket */
	inj_connect(FAKE_BASE + 1, WR_AF_IPV4, 0, lo4, 4);       /* port 0 */
	inj_connect(FAKE_BASE + 2, 0, 3300, lo4, 4);              /* no family */
	inj_connect(FAKE_BASE + 3, 9, 3300, lo4, 4);              /* unknown family */
	WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	WRT_CHECK_U64(closed_err_of(FAKE_BASE + 1), EINVAL);
	WRT_CHECK_U64(closed_err_of(FAKE_BASE + 2), EINVAL);
	WRT_CHECK_U64(closed_err_of(FAKE_BASE + 3), EINVAL);
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), base);
	WRT_CHECK_U64(count_fds(), fds1);

	/* a socket that cannot be made non-blocking: the connection fails with that errno, the descriptor is closed */
	hk.fcntl_err = EMFILE;
	inj_connect(FAKE_BASE + 4, WR_AF_IPV4, port, lo4, 4);
	WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	WRT_CHECK_U64(closed_err_of(FAKE_BASE + 4), EMFILE);
	WRT_CHECK_U64(hk.fcntl_err, 0);
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), base);
	WRT_CHECK_U64(count_fds(), fds1);

	/* a full table: 70 dials, only the free slots get a socket, the rest are answered EMFILE */
	n_emfile0 = closed_count_err(EMFILE);
	for (i = 0; i < 70; i++)
		inj_connect(FAKE_BASE + 100u + (unsigned)i, WR_AF_IPV4, port, lo4, 4);
	WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	n_emfile = closed_count_err(EMFILE) - n_emfile0;
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), 64);
	WRT_CHECK_U64(n_emfile, 70u - (64u - base));
	WRT_CHECK(closed_err_of(FAKE_BASE + 100u + (64u - base)) == EMFILE); /* the first one that did not fit */
	WRT_CHECK(closed_err_of(FAKE_BASE + 100u) == -1);                    /* and the first one fitted */
	(void)steps_for(50); /* the connects complete (or already had) and are reported to the engine */
	WRT_CHECK(connected_has(FAKE_BASE + 100u));
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), 64);

	/* an engine that reports more gather elements than it was asked for must not make the pump read past its
	 * own array (AddressSanitizer sees that) nor send more than it holds */
	inj.tx_lie = 3;
	steps = steps_for(60);
	inj.tx_lie = 0;
	WRT_CHECK(steps > 0);
	WRT_CHECK(inj.n_consume > 0);
	WRT_CHECK(inj.max_consume <= WRL_TX_IOV * 4u); /* at most the 8 elements of 4 bytes it was given */
	WRT_CHECK_U64(closed_err_of(FAKE_BASE + 100u), -1); /* no EFAULT: the connection is intact */

	/* CLOSE of a live id closes the socket and is answered with 0; of an unknown id it is answered, nothing else */
	inj_close(FAKE_BASE + 100u);
	inj_close(FAKE_BASE + 9999u);
	WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	WRT_CHECK_U64(closed_err_of(FAKE_BASE + 100u), 0);
	WRT_CHECK_U64(closed_err_of(FAKE_BASE + 9999u), 0);
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), 63);

	/* a second CONNECT for a live id replaces the first: no second slot, no leaked descriptor */
	fds1 = count_fds();
	inj_connect(FAKE_BASE + 101u, WR_AF_IPV4, port, lo4, 4);
	WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), 63);
	WRT_CHECK_U64(count_fds(), fds1);

	/* free the table again, then IPv6: one dial that is accepted, one that is refused */
	for (id = 101; id < 100u + (64u - base); id++)
		inj_close(FAKE_BASE + id);
	WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), base);
	sp.n_closed = sp.n_connected = 0; /* the logs hold 64 entries; start them afresh for this part */
	{
		struct sockaddr_in6 sa;
		socklen_t sl = (socklen_t)sizeof(sa);
		int one = 1;

		memset(lo6, 0, sizeof(lo6));
		lo6[15] = 1;
		l6 = socket(AF_INET6, SOCK_STREAM, 0);
		memset(&sa, 0, sizeof(sa));
		sa.sin6_family = AF_INET6;
		sa.sin6_addr = in6addr_loopback;
		if (l6 >= 0)
			(void)setsockopt(l6, SOL_SOCKET, SO_REUSEADDR, &one, (socklen_t)sizeof(one));
		if (l6 < 0 || bind(l6, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(l6, 4) != 0 ||
		    getsockname(l6, (struct sockaddr *)&sa, &sl) != 0) {
			fprintf(stderr, "note: no IPv6 loopback here; IPv6 dial test skipped\n");
			if (l6 >= 0)
				close(l6);
			l6 = -1;
		} else {
			port6 = ntohs(sa.sin6_port);
		}
	}
	if (l6 >= 0) {
		inj_connect(FAKE_BASE + 300u, WR_AF_IPV6, port6, lo6, 16);
		WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
		(void)steps_for(50);
		WRT_CHECK(connected_has(FAKE_BASE + 300u));
		WRT_CHECK_U64(wrl_loop_open_sockets(R.l), base + 1u);
		inj_close(FAKE_BASE + 300u);
		close(l6); /* now nothing listens there */
		inj_connect(FAKE_BASE + 301u, WR_AF_IPV6, port6, lo6, 16);
		WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
		(void)steps_for(50);
		WRT_CHECK_U64(closed_err_of(FAKE_BASE + 301u), ECONNREFUSED);
		WRT_CHECK_U64(wrl_loop_open_sockets(R.l), base);
	}

	rig_stop();
	close(lfd);
	WRT_CHECK_U64(count_fds(), fds0); /* every socket the pump opened is closed again */
}

/* ---- wr-monprobe, run as a child process against the simulated monitor ------------------------------------ */

static void b64_put(char *out, size_t *o, const uint8_t *in, size_t n)
{
	static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i;

	for (i = 0; i < n; i += 3) {
		uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0u) | (i + 2 < n ? in[i + 2] : 0u);

		out[(*o)++] = t[(v >> 18) & 63u];
		out[(*o)++] = t[(v >> 12) & 63u];
		out[(*o)++] = i + 1 < n ? t[(v >> 6) & 63u] : '=';
		out[(*o)++] = i + 2 < n ? t[v & 63u] : '=';
	}
}

/* Write a keyring file for the key mkkey(salt) builds: base64 of {u16 type, u32 sec, u32 nsec, u16 len, secret}. */
static void write_keyring(const char *path, unsigned type, uint8_t salt, char *b64_out)
{
	uint8_t blob[2 + 8 + 2 + 32];
	size_t len = type == WR_KEY_TYPE_AES ? 16u : 32u, i, o = 0;
	char line[256];
	FILE *f;

	memset(blob, 0, sizeof(blob));
	blob[0] = (uint8_t)type;
	blob[10] = (uint8_t)len;
	for (i = 0; i < len; i++)
		blob[12 + i] = (uint8_t)(salt + i * 7u);
	b64_put(b64_out, &o, blob, 12u + len);
	b64_out[o] = '\0';
	snprintf(line, sizeof(line), "[client.winrbd]\n\tkey = %s\n", b64_out);
	f = fopen(path, "w");
	if (f == NULL)
		abort();
	(void)chmod(path, 0600);
	fputs(line, f);
	fclose(f);
}

/* Run the tool; fills out (NUL-terminated, capped) with stdout+stderr and returns its exit status, -1 if it did
 * not exit normally. */
static int run_probe(const char *exe, char *const *argv, char *out, size_t cap)
{
	int pfd[2], status = 0;
	size_t n = 0;
	pid_t pid;

	if (pipe(pfd) != 0)
		abort();
	pid = fork();
	if (pid < 0)
		abort();
	if (pid == 0) {
		(void)dup2(pfd[1], 1);
		(void)dup2(pfd[1], 2);
		close(pfd[0]);
		close(pfd[1]);
		execv(exe, argv);
		_exit(127);
	}
	close(pfd[1]);
	for (;;) {
		ssize_t r;

		if (n + 1u >= cap) { /* drain and drop the rest */
			char junk[256];

			r = read(pfd[0], junk, sizeof(junk));
		} else {
			r = read(pfd[0], out + n, cap - 1u - n);
			if (r > 0)
				n += (size_t)r;
		}
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			break;
	}
	out[n] = '\0';
	close(pfd[0]);
	(void)waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void test_monprobe(void)
{
	const char *exe = getenv("WR_MONPROBE");
	char dir[] = "/tmp/wrl-probe-XXXXXX", kr[160], kr_bad[160], b64[128], b64_bad[128], mon[64], out[8192];
	char *argv_ok[] = {(char *)"wr-monprobe", (char *)"--mon", mon, (char *)"--user", (char *)"winrbd", (char *)"--keyring", kr,
			   (char *)"--timeout", (char *)"8000", NULL};
	char *argv_fsid[] = {(char *)"wr-monprobe", (char *)"--mon", mon, (char *)"--user", (char *)"winrbd", (char *)"--keyring", kr,
			     (char *)"--timeout", (char *)"8000", (char *)"--fsid", (char *)"00000000-1111-2222-3333-444444444444", NULL};
	char *argv_bad[] = {(char *)"wr-monprobe", (char *)"--mon", mon, (char *)"--user", (char *)"winrbd", (char *)"--keyring", kr_bad,
			    (char *)"--timeout", (char *)"1500", NULL};
	int rc;

	if (exe == NULL || *exe == '\0') {
		fprintf(stderr, "note: WR_MONPROBE not set; wr-monprobe tests skipped\n");
		return;
	}
	if (mkdtemp(dir) == NULL)
		abort();
	snprintf(kr, sizeof(kr), "%s/good.keyring", dir);
	snprintf(kr_bad, sizeof(kr_bad), "%s/bad.keyring", dir);

	/* usage and argument errors: exit 2, a message, no crash */
	{
		char *a0[] = {(char *)"wr-monprobe", NULL};
		char *a1[] = {(char *)"wr-monprobe", (char *)"--mon", (char *)"127.0.0.1", (char *)"--user", (char *)"u", (char *)"--keyring",
			      (char *)"/nonexistent/keyring", NULL};
		char *a2[] = {(char *)"wr-monprobe", (char *)"--mon", (char *)"127.0.0.1", (char *)"--user", (char *)"u", (char *)"--keyring",
			      (char *)"/nonexistent/keyring", (char *)"--timeout", (char *)"abc", NULL};
		char *a3[] = {(char *)"wr-monprobe", (char *)"--mon", (char *)"127.0.0.1", (char *)"--user", (char *)"u", (char *)"--keyring",
			      (char *)"/nonexistent/keyring", (char *)"--timeout", (char *)"99999999999999999999", NULL};
		char *a4[] = {(char *)"wr-monprobe", (char *)"--mon", (char *)"127.0.0.1", (char *)"--user", (char *)"u", (char *)"--keyring",
			      (char *)"/nonexistent/keyring", (char *)"--fsid", (char *)"not-a-uuid", NULL};
		char *a5[] = {(char *)"wr-monprobe", (char *)"--mon", (char *)"not an address!", (char *)"--user", (char *)"u", (char *)"--keyring",
			      (char *)"/nonexistent/keyring", NULL};
		char *a6[] = {(char *)"wr-monprobe", (char *)"--bogus", NULL};
		char longuser[200];
		char *a7[] = {(char *)"wr-monprobe", (char *)"--mon", (char *)"127.0.0.1", (char *)"--user", longuser, (char *)"--keyring",
			      (char *)"/nonexistent/keyring", NULL};

		memset(longuser, 'u', sizeof(longuser) - 1u);
		longuser[sizeof(longuser) - 1u] = '\0';
		WRT_CHECK_U64(run_probe(exe, a0, out, sizeof(out)), 2);
		WRT_CHECK(strstr(out, "usage:") != NULL);
		WRT_CHECK_U64(run_probe(exe, a1, out, sizeof(out)), 2); /* keyring cannot be read */
		WRT_CHECK(strstr(out, "keyring") != NULL);
		WRT_CHECK_U64(run_probe(exe, a2, out, sizeof(out)), 2);
		WRT_CHECK(strstr(out, "--timeout") != NULL);
		WRT_CHECK_U64(run_probe(exe, a3, out, sizeof(out)), 2); /* out of range, not wrapped around */
		WRT_CHECK(strstr(out, "--timeout") != NULL);
		WRT_CHECK_U64(run_probe(exe, a4, out, sizeof(out)), 2);
		WRT_CHECK(strstr(out, "--fsid") != NULL);
		WRT_CHECK_U64(run_probe(exe, a5, out, sizeof(out)), 2);
		WRT_CHECK_U64(run_probe(exe, a6, out, sizeof(out)), 2);
		WRT_CHECK_U64(run_probe(exe, a7, out, sizeof(out)), 2);
		WRT_CHECK(strstr(out, "too long") != NULL);
	}

	srv_start(WR_KEY_TYPE_AES256K, NULL); /* the simulator's key is mkkey(type, salt 1) */
	snprintf(mon, sizeof(mon), "127.0.0.1:%u", (unsigned)S.port);
	write_keyring(kr, WR_KEY_TYPE_AES256K, 1, b64);
	write_keyring(kr_bad, WR_KEY_TYPE_AES256K, 99, b64_bad);

	/* the right key: active, both maps, the cluster id of the vector, and the key text nowhere in the output */
	rc = run_probe(exe, argv_ok, out, sizeof(out));
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(strstr(out, " result active=1 ") != NULL);
	WRT_CHECK(strstr(out, "maps=11") != NULL);
	WRT_CHECK(strstr(out, "monmap_epoch=3") != NULL);
	WRT_CHECK(strstr(out, "osdmap_newest_epoch=") != NULL);
	WRT_CHECK(strstr(out, "FSID_MISMATCH") == NULL);
	WRT_CHECK(strstr(out, "event MON_SESSION_UP") != NULL);
	WRT_CHECK(strstr(out, b64) == NULL);

	/* a cluster id that is not the monitor's: reported, exit 4 */
	rc = run_probe(exe, argv_fsid, out, sizeof(out));
	WRT_CHECK_U64(rc, 4);
	WRT_CHECK(strstr(out, "FSID_MISMATCH") != NULL);

	/* a wrong key: never active, exit 1, and neither key text is printed */
	rc = run_probe(exe, argv_bad, out, sizeof(out));
	WRT_CHECK_U64(rc, 1);
	WRT_CHECK(strstr(out, "active=0") != NULL);
	WRT_CHECK(strstr(out, "event AUTH_FAILED") != NULL);
	WRT_CHECK(strstr(out, b64_bad) == NULL);
	WRT_CHECK(strstr(out, b64) == NULL);

	srv_stop();
	(void)unlink(kr);
	(void)unlink(kr_bad);
	(void)rmdir(dir);
}

#define RUN(t)                                                                                    \
	do {                                                                                      \
		uint64_t t0_ = now_ms();                                                          \
		t;                                                                                \
		fprintf(stderr, "  %-40s %5llu ms\n", #t, (unsigned long long)(now_ms() - t0_)); \
	} while (0)

int main(void)
{
	/* A send on a reset connection must not kill the test: the pump uses MSG_NOSIGNAL. Leave SIGPIPE at its
	 * default on purpose, so a missing flag shows as a dead test. */
	RUN(test_session_and_maps(WR_KEY_TYPE_AES256K));
	RUN(test_session_and_maps(WR_KEY_TYPE_AES));
	RUN(test_server_cuts());
	RUN(test_connect_refused());
	RUN(test_connect_timeout());
	RUN(test_close_action());
	RUN(test_slow_peers());
	RUN(test_io_errors());
	RUN(test_backpressure());
	RUN(test_idle_sleeps());
	RUN(test_api_and_fatal());
	RUN(test_wrong_key());
	RUN(test_sockaddr());
	RUN(test_injected_actions());
	RUN(test_monprobe());
	return wrt_finish();
}
