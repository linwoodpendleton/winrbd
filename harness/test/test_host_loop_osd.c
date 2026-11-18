/* SPDX-License-Identifier: MIT */
/*
 * test_host_loop_osd.c - the Linux socket pump (harness/host/wrl_loop.c) with MANY connections: the whole client engine with the OSD client and the image
 * layer, against one simulated monitor and N simulated OSDs over REAL TCP sockets on 127.0.0.1 (docs/design/core-architecture.md section 28, module
 * host-osd-loop). Every simulator has its own pthread server (the technique of test_host_loop.c: a listener, a poll loop, the simulator's feed / drain
 * under one mutex, because the OSDs share the store and the monitor's tickets); the test thread is the host: it runs the engine with wrl_loop_step /
 * wrl_loop_run exactly as a program would and submits image requests through the public API only.
 *
 * The pump source is included, not linked (like test_host_loop.c), so that a few hooks can see what it does: socket / close (every descriptor the pump
 * creates must be closed again), connect, the actions it is given (the timeout each CONNECT carries) and wr_conn_closed (errno and time of every end).
 *
 * Checked:
 *   image I/O      an image opened, written (concurrent, cross-object), flushed, read, discarded and zeroed through real sockets with both key types; every
 *                  byte compared with a flat model AND with the simulator's object store; the flush completes after the writes it covers
 *   slow server    every server writes and reads one byte at a time (monitor and OSDs): handshakes, writes and reads still finish, data intact
 *   server cuts    an OSD that closes in the middle of a reply (orderly close and reset) and one that executes a write and cuts without answering: the
 *                  engine reconnects, resends, the data is right and the duplicate is recognised by the OSD
 *   unreachable    a monitor and an OSD whose connect never completes (accept queue full): each CONNECT carries its own timeout and the pump honours it
 *                  (ETIMEDOUT at the monitor's and at the OSD's own value); the requests of the OTHER OSDs complete long before the connect timeout;
 *                  the stalled ones finish after the OSD comes back. A silent OSD (accepts, never answers): the handshake timeout makes the engine ask for
 *                  the close and the pump answers it
 *   50 sockets     49 OSDs and the monitor at once (the harness profile, 50 live sockets within the pump's 64) with all of them in use
 *   no leak        every descriptor the pump opened is closed after wrl_loop_destroy (also in the middle of I/O); the process holds the same descriptors
 *                  after every test as before it
 *   submit         wr_client_run is called after a submit (a step with no wait), so a request does not wait for a timer
 *   overlap order  random overlapping reads / writes / discards / zeroes / flushes in flight (zero lengths and the end of the image included) on an image
 *                  whose size is not a multiple of the object size: every read equals the model as of its submission, overlapping requests complete in
 *                  submission order, a flush completes after the writes before it, no object grows past the image end
 *   range edges    an image whose last object holds 7 bytes; requests outside it (also with offset + length wrapping 2^64) are refused at submit, queue nothing
 *   64-bit offsets an 8 TiB sparse image: offsets around 2^31, 2^32, 2^33, 2^40 and the last bytes, checked object by object in the simulator's store
 *   error mapping  EIO / EPERM / ENOSPC of an OSD fail the request with their own status; ENOENT on a read is the one error that reads as zeros
 *   cancels        reads cancelled while their replies land in the caller's buffers (buffers freed at once: ASan watches), a 4 MiB write cancelled with
 *                  operations in the transmit queues, and a write abandoned with its answer lost (the OSDs restart): the resend comes from the core's
 *                  copy and a later overlapping write waits for it, also when the OSDs keep no duplicate log (the fence of C10, not the OSD, orders them)
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
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "client_osd_rig.h"

#include "../host/wrl_sys.c"

/* ---- interventions installed before the pump is included ------------------------------------------ */

static int hk_socket(int domain, int type, int proto);
static int hk_close(int fd);
static int hk_connect(int fd, const struct sockaddr *sa, socklen_t sl);
static void spy_closed(wr_client *c, wr_conn_id id, int err);
static int spy_next_action(wr_client *c, wr_action *a);
#define socket hk_socket
#define close hk_close
#define connect hk_connect
#define wr_conn_closed spy_closed
#define wr_client_next_action spy_next_action

#include "../host/wrl_loop.c"

#undef socket
#undef close
#undef connect
#undef wr_conn_closed
#undef wr_client_next_action

static uint64_t now_ms(void)
{
	wr_clock c;

	wrl_clock(&c);
	return c.mono_ms;
}

/* The descriptors the pump holds (socket() adds, close() removes): empty after wrl_loop_destroy. */
#define FDTAB 256u
static int g_fds[FDTAB];
static unsigned g_nfds;

static int hk_socket(int domain, int type, int proto)
{
	int fd = socket(domain, type, proto);

	if (fd >= 0 && g_nfds < FDTAB)
		g_fds[g_nfds++] = fd;
	return fd;
}

static int hk_close(int fd)
{
	unsigned i;

	for (i = 0; i < g_nfds; i++) {
		if (g_fds[i] == fd) {
			g_fds[i] = g_fds[--g_nfds];
			break;
		}
	}
	return close(fd);
}

/* One entry per CONNECT action: its timeout, when it was served and how it ended. */
typedef struct dial {
	wr_conn_id id;
	uint16_t port;
	uint32_t tmo;
	uint64_t t_act, t_closed;
	int closed, err;
} dial;
#define MAXDIAL 2048u
static dial D[MAXDIAL];
static unsigned nD;
static unsigned g_connects;

static int hk_connect(int fd, const struct sockaddr *sa, socklen_t sl)
{
	g_connects++;
	return connect(fd, sa, sl);
}

static void spy_closed(wr_client *c, wr_conn_id id, int err)
{
	unsigned i;

	for (i = nD; i > 0; i--) {
		if (D[i - 1u].id == id && !D[i - 1u].closed) {
			D[i - 1u].closed = 1;
			D[i - 1u].err = err;
			D[i - 1u].t_closed = now_ms();
			break;
		}
	}
	wr_conn_closed(c, id, err);
}

static int spy_next_action(wr_client *c, wr_action *a)
{
	int r = wr_client_next_action(c, a);

	if (r && a->kind == WR_ACT_CONNECT && nD < MAXDIAL) {
		D[nD].id = a->conn;
		D[nD].port = a->addr.port;
		D[nD].tmo = a->timeout_ms;
		D[nD].t_act = now_ms();
		D[nD].closed = 0;
		D[nD].err = 0;
		nD++;
	}
	return r;
}

static unsigned dials_to(uint16_t port)
{
	unsigned i, n = 0;

	for (i = 0; i < nD; i++)
		n += D[i].port == port;
	return n;
}

static int fd_count(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	int n = 0;

	if (d == NULL)
		return -1;
	while ((e = readdir(d)) != NULL)
		if (e->d_name[0] != '.')
			n++;
	closedir(d);
	return n;
}

/* ---- the TCP servers --------------------------------------------------------------------------------- */

#define MAXSRV 52u    /* the monitor and up to 51 OSDs */
#define SMAX 16u      /* connections one server holds */
#define OUTCAP (512u * 1024u)

enum { M_LIVE = 0, M_BLACKHOLE = 1, M_SILENT = 2 };
enum { CUT_NONE = 0, CUT_MID = 1, CUT_DROP = 2 };

typedef struct sconn {
	int fd, silent;
	void *sc;
	uint8_t *out;
	size_t out_len, out_off;
	int cutting, cut_rst;
	size_t cut_left;
} sconn;

typedef struct srv {
	unsigned idx;
	int is_mon;
	int lfd;
	uint16_t port;
	pthread_t th;
	int started;
	volatile int stop;
	sim_osd *osd;
	sconn c[SMAX];
	int dummy[24];
	unsigned n_dummy;
	/* knobs, set under the mutex */
	int mode, bh_acked;
	size_t wr_chunk, rd_chunk;
	int cut, cut_rst;
	uint32_t cut_base;
	/* stats */
	unsigned n_accept, n_eof, n_cut;
} srv;

static struct world {
	pthread_mutex_t mu;
	sim_mon *mon;
	sim_store *store;
	wrt_mg_map desc;
	unsigned n_osd, key_type;
	srv s[MAXSRV];
} G;

static void s_lock(void)
{
	pthread_mutex_lock(&G.mu);
}
static void s_unlock(void)
{
	pthread_mutex_unlock(&G.mu);
}

static size_t sc_feed(const srv *s, sconn *c, const uint8_t *b, size_t n)
{
	return s->is_mon ? sim_mon_feed((sim_mon_conn *)c->sc, b, n) : sim_osd_feed((sim_osd_conn *)c->sc, b, n);
}
static size_t sc_drain(const srv *s, sconn *c, uint8_t *b, size_t n)
{
	return s->is_mon ? sim_mon_drain((sim_mon_conn *)c->sc, b, n) : sim_osd_drain((sim_osd_conn *)c->sc, b, n);
}
static int sc_closed(const srv *s, sconn *c)
{
	return s->is_mon ? sim_mon_closed((sim_mon_conn *)c->sc) : sim_osd_closed((sim_osd_conn *)c->sc);
}

static void sconn_drop(srv *s, sconn *c, int rst)
{
	if (rst) {
		struct linger lg;

		lg.l_onoff = 1;
		lg.l_linger = 0;
		(void)setsockopt(c->fd, SOL_SOCKET, SO_LINGER, &lg, (socklen_t)sizeof(lg));
	}
	close(c->fd);
	if (c->sc != NULL) {
		if (s->is_mon)
			sim_mon_conn_free((sim_mon_conn *)c->sc);
		else
			sim_osd_conn_free((sim_osd_conn *)c->sc);
	}
	free(c->out);
	memset(c, 0, sizeof(*c));
	c->fd = -1;
}

static void s_accept(srv *s)
{
	for (;;) {
		int fd = accept(s->lfd, NULL, NULL), one = 1;
		unsigned i;
		sconn *c;

		if (fd < 0)
			return;
		for (i = 0; i < SMAX && s->c[i].fd >= 0; i++) {
		}
		if (i == SMAX) {
			close(fd);
			continue;
		}
		c = &s->c[i];
		(void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
		(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, (socklen_t)sizeof(one));
		memset(c, 0, sizeof(*c));
		c->fd = fd;
		s->n_accept++;
		if (s->mode == M_SILENT) {
			c->silent = 1;
			continue;
		}
		c->sc = s->is_mon ? (void *)sim_mon_accept(G.mon) : (void *)sim_osd_accept(s->osd);
		c->out = (uint8_t *)malloc(OUTCAP);
		if (c->out == NULL)
			abort();
		if (c->sc == NULL)
			sconn_drop(s, c, 0); /* the simulator has no room (a probe or dummy connection piled up): refuse like a full server */
	}
}

static void s_conn(srv *s, sconn *c, short rev)
{
	uint8_t buf[4096];

	if (c->silent) {
		if (rev & (POLLIN | POLLHUP | POLLERR)) {
			ssize_t n = recv(c->fd, buf, sizeof(buf), 0);

			if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
				s->n_eof++;
				sconn_drop(s, c, 0);
			}
		}
		return;
	}
	if (rev & (POLLIN | POLLHUP | POLLERR)) {
		size_t want = s->rd_chunk != 0 ? s->rd_chunk : sizeof(buf);
		ssize_t n = recv(c->fd, buf, want < sizeof(buf) ? want : sizeof(buf), 0);

		if (n > 0) {
			(void)sc_feed(s, c, buf, (size_t)n);
		} else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
			s->n_eof++;
			sconn_drop(s, c, 0);
			return;
		}
	}
	if (c->out_off == c->out_len)
		c->out_off = c->out_len = 0;
	c->out_len += sc_drain(s, c, c->out + c->out_len, OUTCAP - c->out_len);
	/* The fault plan: the first request this OSD sees after it was armed. */
	if (!s->is_mon && s->cut != CUT_NONE && !c->cutting && sim_osd_n_requests(s->osd) > s->cut_base) {
		if (s->cut == CUT_DROP) { /* executed, the answer is lost */
			s->cut = CUT_NONE;
			s->n_cut++;
			sconn_drop(s, c, s->cut_rst);
			return;
		}
		if (c->out_len - c->out_off >= 2u) { /* half of the reply goes out, then the connection ends */
			c->cutting = 1;
			c->cut_rst = s->cut_rst;
			c->cut_left = (c->out_len - c->out_off) / 2u;
			s->cut = CUT_NONE;
			s->n_cut++;
		}
	}
	if (c->out_len > c->out_off) {
		size_t left = c->out_len - c->out_off, k = s->wr_chunk != 0 && s->wr_chunk < left ? s->wr_chunk : left;
		ssize_t w;

		if (c->cutting && k > c->cut_left)
			k = c->cut_left;
		w = send(c->fd, c->out + c->out_off, k, MSG_NOSIGNAL | MSG_DONTWAIT);
		if (w > 0) {
			c->out_off += (size_t)w;
			if (c->cutting) {
				c->cut_left -= (size_t)w;
				if (c->cut_left == 0) {
					sconn_drop(s, c, c->cut_rst);
					return;
				}
			}
		} else if (w < 0 && errno != EAGAIN && errno != EINTR) {
			sconn_drop(s, c, 0);
			return;
		}
	}
	if (sc_closed(s, c) && c->out_off == c->out_len)
		sconn_drop(s, c, 0);
}

static void *srv_main(void *arg)
{
	srv *s = (srv *)arg;

	while (!s->stop) {
		struct pollfd pf[1 + SMAX];
		unsigned i, n = 1;
		int idx[SMAX];

		s_lock();
		if (s->mode == M_BLACKHOLE && !s->bh_acked) { /* what the host had open is cut; nothing is accepted from now on */
			for (i = 0; i < SMAX; i++)
				if (s->c[i].fd >= 0)
					sconn_drop(s, &s->c[i], 1);
			s->bh_acked = 1;
		}
		pf[0].fd = s->lfd;
		pf[0].events = s->mode == M_BLACKHOLE ? 0 : POLLIN;
		pf[0].revents = 0;
		for (i = 0; i < SMAX; i++) {
			if (s->c[i].fd < 0)
				continue;
			pf[n].fd = s->c[i].fd;
			pf[n].events = POLLIN;
			if (s->c[i].out_len > s->c[i].out_off)
				pf[n].events |= POLLOUT;
			pf[n].revents = 0;
			idx[n - 1u] = (int)i;
			n++;
		}
		s_unlock();
		(void)poll(pf, n, 4);
		s_lock();
		if (s->mode != M_BLACKHOLE && (pf[0].revents & POLLIN))
			s_accept(s);
		for (i = 1; i < n; i++) {
			sconn *c = &s->c[idx[i - 1u]];

			if (c->fd >= 0 && c->fd == pf[i].fd)
				s_conn(s, c, pf[i].revents);
		}
		/* the simulator may have output (a push, a released message) or a close with no socket event */
		for (i = 0; i < SMAX; i++)
			if (s->c[i].fd >= 0 && !s->c[i].silent)
				s_conn(s, &s->c[i], 0);
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
	(void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	return fd;
}

/* ---- the world: monitor, OSDs, store, image ------------------------------------------------------------ */

/* The committed MonMap vector with its one monitor address (10.77.0.10:3300) moved to 127.0.0.1:port. */
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

typedef struct wopts {
	unsigned n_osd, key_type, pg_num;
	uint64_t img_size;
	uint8_t order;
	uint8_t no_model; /* a sparse image too big for a flat model (64-bit offsets): the store and patterns are the oracle */
} wopts;

#define IMG_NAME "hl-img"
#define IMG_ID "hlid1"

static srv *S_MON(void) { return &G.s[0]; }
static srv *S_OSD(unsigned i) { return &G.s[1u + i]; }

static void world_start(const wopts *o)
{
	sim_mon_cfg mcf;
	wrt_mg_cluster_spec cs;
	wrt_mg_buf b;
	sim_rbd_image_cfg ic;
	unsigned i;

	memset(&G, 0, sizeof(G));
	memset(&b, 0, sizeof(b));
	pthread_mutex_init(&G.mu, NULL);
	G.n_osd = o->n_osd;
	G.key_type = o->key_type;
	for (i = 0; i <= o->n_osd; i++) {
		unsigned k;

		G.s[i].idx = i;
		G.s[i].is_mon = i == 0;
		G.s[i].lfd = listen_on(&G.s[i].port, 6);
		for (k = 0; k < SMAX; k++)
			G.s[i].c[k].fd = -1;
	}
	load_monmap(S_MON()->port);
	sim_mon_cfg_default(&mcf);
	mt_key(&mcf.key, o->key_type, 1);
	mcf.m2.server_ip[0] = 127, mcf.m2.server_ip[1] = 0, mcf.m2.server_ip[2] = 0, mcf.m2.server_ip[3] = 1;
	mcf.m2.server_port = S_MON()->port;
	mcf.monmap = g_monmap;
	mcf.monmap_len = g_monmap_len;
	mcf.no_default_osdmaps = 1;
	G.mon = sim_mon_new(&mcf);
	G.store = sim_store_new();
	if (G.mon == NULL || G.store == NULL)
		abort();
	wrt_mg_cluster_spec_init(&cs, o->n_osd);
	cs.osds_per_host = 1;
	cs.n_pools = 2;
	cs.pg_num = o->pg_num;
	cs.pool_size = o->n_osd < 3u ? o->n_osd : 3u;
	cs.epoch = 1;
	cs.seed = 77;
	if (wrt_mg_build_map(&G.desc, &cs) != 0)
		abort();
	for (i = 0; i < o->n_osd; i++)
		wrt_mg_av_v2(&WRT_MG_E(G.desc.client_addrs, wrt_mg_addrvec, i), 0x7f000001u, S_OSD(i)->port, 7000u + i);
	memcpy(G.desc.fsid, G.mon->fsid, 16);
	if (wrt_mg_map_encode(&G.desc, &b) != 0)
		abort();
	if (sim_mon_add_epoch(G.mon, G.desc.epoch, b.p, b.len, NULL, 0) != WR_OK || sim_mon_push_epoch(G.mon) != WR_OK)
		abort();
	wrt_mg_buf_free(&b);
	for (i = 0; i < o->n_osd; i++) {
		sim_osd_cfg oc;

		sim_osd_cfg_default(&oc);
		oc.mon = G.mon;
		oc.store = G.store;
		oc.id = (int32_t)i;
		oc.seed = 11u + i;
		oc.m2.server_ip[0] = 127, oc.m2.server_ip[1] = 0, oc.m2.server_ip[2] = 0, oc.m2.server_ip[3] = 1;
		oc.m2.server_port = S_OSD(i)->port;
		oc.m2.server_nonce = 7000u + i;
		oc.m2.check_target = 1;
		S_OSD(i)->osd = sim_osd_new(&oc);
		if (S_OSD(i)->osd == NULL)
			abort();
	}
	memset(&ic, 0, sizeof(ic));
	ic.pool = 1;
	ic.name = IMG_NAME;
	ic.id = IMG_ID;
	ic.size = o->img_size;
	ic.order = o->order;
	ic.data_pool = -1;
	if (sim_rbd_image_create(G.store, &ic) != WR_OK)
		abort();
	for (i = 0; i <= o->n_osd; i++) {
		if (pthread_create(&G.s[i].th, NULL, srv_main, &G.s[i]) != 0)
			abort();
		G.s[i].started = 1;
	}
}

static void world_stop(void)
{
	unsigned i, k;

	for (i = 0; i <= G.n_osd; i++)
		G.s[i].stop = 1;
	for (i = 0; i <= G.n_osd; i++)
		if (G.s[i].started)
			pthread_join(G.s[i].th, NULL);
	for (i = 0; i <= G.n_osd; i++) {
		for (k = 0; k < G.s[i].n_dummy; k++)
			close(G.s[i].dummy[k]);
		for (k = 0; k < SMAX; k++)
			if (G.s[i].c[k].fd >= 0)
				sconn_drop(&G.s[i], &G.s[i].c[k], 0);
		close(G.s[i].lfd);
		if (G.s[i].osd != NULL)
			sim_osd_free(G.s[i].osd);
	}
	sim_mon_free(G.mon);
	sim_store_free(G.store);
	wrt_mg_map_free(&G.desc);
	pthread_mutex_destroy(&G.mu);
}

static void world_check_sane(void)
{
	unsigned i, v = 0;

	s_lock();
	for (i = 0; i < G.n_osd; i++)
		v += sim_osd_n_violations(S_OSD(i)->osd);
	s_unlock();
	WRT_CHECK_U64(v, 0); /* no OSD saw a message it could not decode or a rule a stock client keeps broken */
}

/* ---- unreachable servers --------------------------------------------------------------------------------- */

static void nb_connect(int fd, uint16_t port)
{
	struct sockaddr_in sa;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons(port);
	(void)connect(fd, (struct sockaddr *)&sa, sizeof(sa));
}

/* Make the server unreachable: it drops what it holds and stops accepting, and its accept queue is filled with dummy connections, so the kernel drops
 * every further SYN (the connect hangs). Returns 0 when the kernel does it, -1 if it does not (the caller skips the timing checks). */
static int blackhole_on(srv *s)
{
	unsigned i;
	struct pollfd pf;
	int probe, done = 0, acked = 0;

	s_lock();
	s->mode = M_BLACKHOLE;
	s->bh_acked = 0;
	s_unlock();
	for (i = 0; i < 200 && !acked; i++) {
		s_lock();
		acked = s->bh_acked;
		s_unlock();
		if (!acked)
			usleep(5000);
	}
	WRT_CHECK(acked);
	for (i = 0; i < 12; i++) {
		int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

		nb_connect(fd, s->port);
		s->dummy[s->n_dummy++] = fd;
	}
	usleep(100000);
	probe = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	nb_connect(probe, s->port);
	pf.fd = probe;
	pf.events = POLLOUT;
	pf.revents = 0;
	done = poll(&pf, 1, 150) > 0 && (pf.revents & POLLOUT) != 0;
	s->dummy[s->n_dummy++] = probe;
	return done ? -1 : 0;
}

static void blackhole_off(srv *s)
{
	unsigned i;

	for (i = 0; i < s->n_dummy; i++)
		close(s->dummy[i]);
	s->n_dummy = 0;
	s_lock();
	s->mode = M_LIVE;
	s_unlock();
}

static void srv_set_mode(srv *s, int mode)
{
	s_lock();
	s->mode = mode;
	s_unlock();
}

/* ---- the client side: engine, loop, jobs --------------------------------------------------------------------- */

static struct rig {
	wr_config cfg;
	wr_host_ops ops;
	unsigned level;
	wr_cluster_spec spec;
	wr_mem_region arena, bulk;
	wr_client *c;
	wrl_loop *l;
	wr_image *img;
	wr_image_info info;
	unsigned peak_sockets;
	unsigned n_ev_kind[16];
	unsigned seq;
} R;

typedef struct job {
	wr_io_req r;
	uint8_t *buf;
	int done;
	wr_status st;
	uint64_t t_sub, t_done;
	unsigned seq;
	uint8_t *exp; /* READ: what the image must hold at the moment the request was submitted (see job_add_read_exp) */
} job;
#define MAXJOB 1100u
static job J[MAXJOB];
static unsigned nJ;

static uint8_t *M; /* the flat model of the image */
static uint64_t Msize;

static void jobs_reset(void)
{
	unsigned i;

	for (i = 0; i < nJ; i++) {
		free(J[i].buf);
		free(J[i].exp);
	}
	memset(J, 0, sizeof(J));
	nJ = 0;
}

static void collect(void)
{
	wr_event e;
	wr_io_req *r;
	unsigned o = wrl_loop_open_sockets(R.l);

	if (o > R.peak_sockets)
		R.peak_sockets = o;
	while (wr_client_next_event(R.c, &e))
		if ((unsigned)e.kind < 16u)
			R.n_ev_kind[e.kind]++;
	while ((r = wr_client_next_done(R.c)) != NULL) {
		job *j = (job *)r->user;

		j->done = 1;
		j->st = r->status;
		j->t_done = now_ms();
		j->seq = ++R.seq;
	}
}

typedef struct pw {
	int (*f)(void *);
	void *a;
} pw;

static int stop_wrap(void *p)
{
	pw *w = (pw *)p;

	collect();
	return w->f != NULL ? w->f(w->a) : 0;
}

/* Run the pump until f(a) holds or ms passed. */
static wr_status pump(int (*f)(void *), void *a, int ms)
{
	pw w;
	wr_status st;

	w.f = f;
	w.a = a;
	st = wrl_loop_run(R.l, stop_wrap, &w, ms);
	collect();
	return st;
}

static int stop_never(void *a)
{
	(void)a;
	return 0;
}

/* Run the pump for ms with nothing to wait for (collects events and completions). */
static void idle(int ms)
{
	WRT_CHECK_U64(pump(stop_never, NULL, ms), (uint64_t)(int64_t)WR_E_TIMEOUT);
}

typedef struct jr {
	unsigned first, n;
} jr;

static int jr_done(void *a)
{
	const jr *r = (const jr *)a;
	unsigned i;

	for (i = 0; i < r->n; i++)
		if (!J[r->first + i].done)
			return 0;
	return 1;
}

static int img_final(void *a)
{
	(void)a;
	return wr_image_get_state(R.img) == WR_IMG_OPEN || wr_image_get_state(R.img) == WR_IMG_FAILED;
}

/* A job: its buffer is filled (WRITE: the pattern, and the model takes it at once, since the engine orders overlapping writes in submit order; READ: junk). */
static job *job_add(wr_io_kind kind, uint64_t off, uint64_t len, uint32_t seed)
{
	job *j;

	if (nJ >= MAXJOB)
		abort();
	j = &J[nJ++];
	memset(j, 0, sizeof(*j));
	j->r.kind = kind;
	j->r.offset = off;
	j->r.length = len;
	j->r.user = j;
	if (kind == WR_IO_WRITE || kind == WR_IO_READ) {
		j->buf = (uint8_t *)malloc((size_t)len);
		if (j->buf == NULL)
			abort();
		j->r.buf = j->buf;
		if (kind == WR_IO_WRITE) {
			cw_fill(j->buf, seed, off, (size_t)len);
			if (M != NULL)
				memcpy(M + off, j->buf, (size_t)len);
		} else {
			memset(j->buf, 0xEE, (size_t)len);
		}
	} else if ((kind == WR_IO_DISCARD || kind == WR_IO_WRITE_ZEROES) && M != NULL) {
		memset(M + off, 0, (size_t)len); /* both read back as zeros */
	}
	return j;
}

/* A READ that is checked against the model AS OF ITS SUBMISSION: requests that overlap an earlier one wait for it and an earlier read is not
 * overtaken by a later write (design C14), so a read sees exactly the writes submitted before it. */
static job *job_add_read_exp(uint64_t off, uint64_t len)
{
	job *j = job_add(WR_IO_READ, off, len, 0);

	if (len != 0) {
		j->exp = (uint8_t *)malloc((size_t)len);
		if (j->exp == NULL)
			abort();
		memcpy(j->exp, M + off, (size_t)len);
	}
	return j;
}

/* Submit and run the engine once without waiting (the rule of design 28.2: a submit cannot wake the host, the next run encodes and queues the messages). */
static wr_status job_submit(job *j)
{
	wr_status st = wr_image_submit(R.img, &j->r);

	j->t_sub = now_ms();
	if (st == WR_OK)
		WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	return st;
}

static jr jobs_submit_range(unsigned first, unsigned n)
{
	unsigned i;
	jr r;

	for (i = 0; i < n; i++)
		WRT_CHECK_STATUS(WR_OK, job_submit(&J[first + i]));
	r.first = first;
	r.n = n;
	return r;
}

static void cfg_default(wr_config *cfg)
{
	wr_config_profile_harness(cfg);
	wr_config_enable_maps(cfg, WR_MAPS_HARNESS);
	wr_config_enable_osd(cfg, WR_MAPS_HARNESS);
	cfg->mon_msg_cap = 1024u * 1024u;
	cfg->connect_timeout_ms = 1000;
	cfg->hunt_backoff_min_ms = 50;
	cfg->hunt_backoff_max_ms = 400;
}

static void client_start(const wopts *o, void (*tweak)(wr_config *))
{
	wr_mem_req req;

	memset(&R, 0, sizeof(R));
	memset(D, 0, sizeof(D));
	nD = 0;
	g_connects = 0;
	g_nfds = 0;
	cfg_default(&R.cfg);
	if (tweak != NULL)
		tweak(&R.cfg);
	R.level = getenv("WRL_TEST_LOG") != NULL ? (unsigned)atoi(getenv("WRL_TEST_LOG")) : WR_LOG_ERR;
	wrl_host_ops_init(&R.ops, &R.level);
	strcpy(R.spec.user, "client.winrbd");
	mt_key(&R.spec.key, o->key_type, 1);
	R.spec.n_mons = 1;
	R.spec.mons[0].family = WR_AF_IPV4;
	R.spec.mons[0].ip[0] = 127, R.spec.mons[0].ip[3] = 1;
	R.spec.mons[0].port = S_MON()->port;
	WRT_CHECK(R.cfg.max_conns <= 64u); /* the pump's cap */
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&R.cfg, &req));
	WRT_CHECK_STATUS(WR_OK, wrl_mem_alloc(&R.arena, req.arena));
	WRT_CHECK_STATUS(WR_OK, wrl_mem_alloc(&R.bulk, req.bulk));
	WRT_CHECK_STATUS(WR_OK, wr_client_create(&R.cfg, &R.ops, &R.spec, R.arena, R.bulk, &R.c));
	WRT_CHECK_STATUS(WR_OK, wrl_loop_create(R.c, &R.l));
	Msize = o->img_size;
	free(M);
	M = NULL;
	if (!o->no_model) {
		M = (uint8_t *)calloc(1, (size_t)Msize);
		if (M == NULL)
			abort();
	}
}

/* The pump goes first (the engine may still be alive: it is destroyed after, as a host does); every descriptor it opened is closed. */
static void client_stop(void)
{
	wrl_loop_destroy(R.l);
	WRT_CHECK_U64(g_nfds, 0);
	wr_client_destroy(R.c);
	wrl_mem_free(&R.arena);
	wrl_mem_free(&R.bulk);
	jobs_reset();
	free(M);
	M = NULL;
}

static int open_image(void)
{
	wr_image_params p = cw_params(IMG_NAME, 1);

	R.img = NULL;
	WRT_CHECK_STATUS(WR_OK, wr_image_open(R.c, &p, &R.img));
	if (R.img == NULL)
		return -1;
	WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	WRT_CHECK_STATUS(WR_OK, pump(img_final, NULL, 30000));
	WRT_CHECK_U64(wr_image_get_state(R.img), WR_IMG_OPEN);
	if (wr_image_get_state(R.img) != WR_IMG_OPEN)
		return -1;
	WRT_CHECK_STATUS(WR_OK, wr_image_get_info(R.img, &R.info));
	return 0;
}

/* The object store holds exactly what the model says, object by object. */
static void check_store(void)
{
	uint8_t *tmp = (uint8_t *)malloc(R.info.object_size);
	uint64_t o, n = (Msize + R.info.object_size - 1u) / R.info.object_size;
	unsigned bad = 0;

	for (o = 0; o < n && tmp != NULL; o++) {
		char name[160];
		int exists = 0;
		uint64_t len = Msize - o * R.info.object_size < R.info.object_size ? Msize - o * R.info.object_size : R.info.object_size;
		wr_status st;

		snprintf(name, sizeof(name), "%s.%016" PRIx64, R.info.object_prefix, o);
		s_lock();
		st = sim_store_read(G.store, R.info.data_pool_id, name, 0, tmp, (size_t)len, &exists);
		s_unlock();
		if (st != WR_OK || memcmp(tmp, M + o * R.info.object_size, (size_t)len) != 0)
			bad++;
		if (exists) { /* nothing was written past the image end or past the object end: the last object of an odd-sized image is short */
			uint64_t sz = 0;

			s_lock();
			st = sim_store_size(G.store, R.info.data_pool_id, name, &sz);
			s_unlock();
			if (st != WR_OK || sz > len)
				bad++;
		}
	}
	WRT_CHECK_U64(bad, 0);
	free(tmp);
}

/* The whole image read back through the engine in `chunk` pieces, all in flight together, equals the model. */
static void check_image(uint64_t chunk)
{
	unsigned first = nJ, i, n = (unsigned)((Msize + chunk - 1u) / chunk), bad = 0;
	jr r;

	for (i = 0; i < n; i++) {
		uint64_t off = (uint64_t)i * chunk, len = Msize - off < chunk ? Msize - off : chunk;

		(void)job_add(WR_IO_READ, off, len, 0);
	}
	r = jobs_submit_range(first, n);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	for (i = 0; i < n; i++) {
		job *j = &J[first + i];

		if (!j->done || j->st != WR_OK || memcmp(j->buf, M + j->r.offset, (size_t)j->r.length) != 0)
			bad++;
	}
	WRT_CHECK_U64(bad, 0);
}

static uint64_t rng_state = 0x1234567890abcdefull;
static uint32_t rnd(void)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (uint32_t)((rng_state * 0x2545f4914f6cdd1dull) >> 32);
}

/* ---- tests --------------------------------------------------------------------------------------------- */

/* Image I/O with the model and the store as oracles. */
static void test_image_io(unsigned key_type)
{
	wopts o;
	unsigned round, i;
	wr_osd_stats st;

	memset(&o, 0, sizeof(o));
	o.n_osd = 6;
	o.key_type = key_type;
	o.pg_num = 64;
	o.img_size = 8u << 20;
	o.order = 16;
	world_start(&o);
	client_start(&o, NULL);
	WRT_CHECK(open_image() == 0);
	if (R.img == NULL || wr_image_get_state(R.img) != WR_IMG_OPEN)
		goto out;
	for (round = 0; round < 3; round++) {
		unsigned first = nJ, nw = 12, fl;
		uint64_t reg = Msize / nw;
		jr r;
		unsigned max_seq = 0;

		for (i = 0; i < nw; i++) { /* 12 writes in flight, one in each region of the image, so they never overlap */
			uint64_t start = (uint64_t)i * reg, off = start + rnd() % (reg / 2u), room = reg - (off - start);
			uint64_t len = 1u + rnd() % (room < 300000u ? room : 300000u);

			(void)job_add(WR_IO_WRITE, off, len, 100u + round * 16u + i);
		}
		fl = nJ;
		(void)job_add(WR_IO_FLUSH, 0, 0, 0);
		r = jobs_submit_range(first, nw + 1u);
		WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
		for (i = 0; i <= nw; i++)
			WRT_CHECK_STATUS(WR_OK, J[first + i].st);
		for (i = 0; i < nw; i++)
			if (J[first + i].seq > max_seq)
				max_seq = J[first + i].seq;
		WRT_CHECK(J[fl].seq > max_seq); /* the flush completed after every write it covers */
		check_image(300000u + round);   /* unaligned chunks: reads cross objects */
	}
	{ /* discard and write-zeroes over a model range, then everything again */
		unsigned first = nJ;
		jr r;

		(void)job_add(WR_IO_DISCARD, (1u << 20) + 5u, 700000u, 0);
		(void)job_add(WR_IO_WRITE_ZEROES, (4u << 20) + 77u, 123457u, 0);
		(void)job_add(WR_IO_DISCARD, 6u << 20, 3u << 16, 0); /* whole objects */
		r = jobs_submit_range(first, 3);
		WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
		for (i = 0; i < 3; i++)
			WRT_CHECK_STATUS(WR_OK, J[first + i].st);
		check_image(1u << 20);
	}
	check_store();
	wr_client_osd_stats(R.c, &st);
	WRT_CHECK(st.sessions_hiwater >= 2u);
	WRT_CHECK(st.ops_done > 20u);
	/* st.ops_failed is not asserted: it also counts the ENOENT answers of reads of objects that were never written (they read as zeros) */
	WRT_CHECK(R.peak_sockets >= 3u && R.peak_sockets <= 1u + o.n_osd);
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
	world_check_sane();
out:
	client_stop();
	world_stop();
}

static void set_slow(void)
{
	unsigned i;

	for (i = 0; i <= G.n_osd; i++) {
		G.s[i].wr_chunk = 1;
		G.s[i].rd_chunk = 1;
	}
}

/* Every server writes and reads one byte at a time. */
static void test_slow_server(void)
{
	wopts o;
	unsigned first, i;
	jr r;
	uint64_t t0;

	memset(&o, 0, sizeof(o));
	o.n_osd = 3;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 32;
	o.img_size = 2u << 20;
	o.order = 16;
	world_start(&o);
	s_lock();
	set_slow();
	s_unlock();
	client_start(&o, NULL);
	t0 = now_ms();
	if (open_image() != 0)
		goto out;
	first = nJ;
	(void)job_add(WR_IO_WRITE, 60u * 1024u, 20u * 1024u, 5); /* crosses the first object boundary */
	(void)job_add(WR_IO_WRITE, 300u * 1024u + 3u, 17u * 1024u, 6);
	(void)job_add(WR_IO_WRITE, 1000u * 1024u, 9000u, 7);
	(void)job_add(WR_IO_FLUSH, 0, 0, 0);
	r = jobs_submit_range(first, 4);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	for (i = 0; i < 4; i++)
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
	first = nJ;
	(void)job_add(WR_IO_READ, 50u * 1024u, 40u * 1024u, 0);
	(void)job_add(WR_IO_READ, 296u * 1024u, 30u * 1024u, 0);
	(void)job_add(WR_IO_READ, 999u * 1024u, 12000u, 0);
	r = jobs_submit_range(first, 3);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	for (i = 0; i < 3; i++) {
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
		WRT_CHECK(memcmp(J[first + i].buf, M + J[first + i].r.offset, (size_t)J[first + i].r.length) == 0);
	}
	check_store();
	fprintf(stderr, "  (slow server: %llu ms for open + 3 writes + 3 reads at one byte per call)\n", (unsigned long long)(now_ms() - t0));
	world_check_sane();
out:
	client_stop();
	world_stop();
}

static void tweak_cuts(wr_config *c)
{
	c->osd_connect_timeout_ms = 400; /* also the base of the engine's wait before it dials an OSD again */
}

static unsigned sum_cuts(void)
{
	unsigned i, n = 0;

	s_lock();
	for (i = 0; i < G.n_osd; i++)
		n += S_OSD(i)->n_cut;
	s_unlock();
	return n;
}

static void arm_cuts(int mode, int rst)
{
	unsigned i;

	s_lock();
	for (i = 0; i < G.n_osd; i++) {
		srv *s = S_OSD(i);

		s->cut = mode;
		s->cut_rst = rst;
		s->cut_base = sim_osd_n_requests(s->osd);
	}
	s_unlock();
}

static unsigned sum_dup_recs(void)
{
	unsigned i, k, n = 0;

	s_lock();
	for (i = 0; i < G.n_osd; i++) {
		uint32_t nr = 0;
		const sim_osd_rec *rec = sim_osd_recs(S_OSD(i)->osd, &nr);

		for (k = 0; k < nr; k++)
			n += rec[k].duplicate != 0;
	}
	s_unlock();
	return n;
}

static unsigned osd_dials(void)
{
	unsigned i, n = 0;

	for (i = 0; i < G.n_osd; i++)
		n += dials_to(S_OSD(i)->port);
	return n;
}

static unsigned osd_dials_closed_with(int err)
{
	unsigned i, k, n = 0;

	for (i = 0; i < G.n_osd; i++)
		for (k = 0; k < nD; k++)
			n += D[k].port == S_OSD(i)->port && D[k].closed && D[k].err == err;
	return n;
}

static void cut_round(int mode, int rst, int write, uint32_t seed)
{
	unsigned first = nJ, dials0 = osd_dials(), cuts0 = sum_cuts(), dup0 = sum_dup_recs(), i;
	wr_osd_stats st0, st1;
	jr r;
	job *j;

	uint64_t t_round = now_ms();

	wr_client_osd_stats(R.c, &st0);
	arm_cuts(mode, rst);
	/* five objects of 64 KiB: 100 KiB .. 356 KiB */
	j = job_add(write ? WR_IO_WRITE : WR_IO_READ, 100u * 1024u, 256u * 1024u, seed);
	WRT_CHECK(j != NULL);
	r = jobs_submit_range(first, 1);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	WRT_CHECK_STATUS(WR_OK, J[first].st);
	if (!write)
		WRT_CHECK(memcmp(J[first].buf, M + J[first].r.offset, (size_t)J[first].r.length) == 0);
	fprintf(stderr, "  (cut mode %d rst %d %s: request done after %llu ms)\n", mode, rst, write ? "write" : "read",
		(unsigned long long)(J[first].t_done - t_round));
	WRT_CHECK(sum_cuts() > cuts0);                 /* the plan fired */
	WRT_CHECK(osd_dials() > dials0);               /* the engine dialled again */
	wr_client_osd_stats(R.c, &st1);
	WRT_CHECK(st1.ops_resent > st0.ops_resent);    /* and resent what had no answer */
	if (mode == CUT_DROP)
		WRT_CHECK(sum_dup_recs() > dup0);      /* the OSD recognised the resent write */
	/* a second read after the dust settled: the engine works on the new sessions */
	first = nJ;
	for (i = 0; i < 4; i++)
		(void)job_add(WR_IO_READ, (uint64_t)i * 70000u, 65536u, 0);
	r = jobs_submit_range(first, 4);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	for (i = 0; i < 4; i++) {
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
		WRT_CHECK(memcmp(J[first + i].buf, M + J[first + i].r.offset, (size_t)J[first + i].r.length) == 0);
	}
}

/* A server that cuts in the middle of a reply (FIN and RST), and one that executes a write and cuts without answering. */
static void test_server_cuts(void)
{
	wopts o;
	unsigned first, i;
	jr r;

	memset(&o, 0, sizeof(o));
	o.n_osd = 4;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 64;
	o.img_size = 4u << 20;
	o.order = 16;
	world_start(&o);
	client_start(&o, tweak_cuts);
	if (open_image() != 0)
		goto out;
	first = nJ; /* content to read: the whole image in 1 MiB writes */
	for (i = 0; i < 4; i++)
		(void)job_add(WR_IO_WRITE, (uint64_t)i << 20, 1u << 20, 40u + i);
	r = jobs_submit_range(first, 4);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	for (i = 0; i < 4; i++)
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);

	cut_round(CUT_MID, 0, 0, 0); /* orderly close after half of a reply */
	WRT_CHECK(osd_dials_closed_with(0) >= 1u);
	cut_round(CUT_MID, 1, 0, 0); /* reset after half of a reply */
	WRT_CHECK(osd_dials_closed_with(ECONNRESET) >= 1u);
	cut_round(CUT_DROP, 0, 1, 90); /* the write is executed, the answer lost, the connection closed */
	cut_round(CUT_DROP, 1, 1, 91); /* the same with a reset */
	check_image(1u << 20);
	check_store();
	world_check_sane();
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
out:
	client_stop();
	world_stop();
}

static void tweak_unreachable(wr_config *c)
{
	c->connect_timeout_ms = 700;       /* the monitor's */
	c->osd_connect_timeout_ms = 1500;  /* the OSDs' */
	c->handshake_timeout_ms = 800;
	c->op_timeout_ms = 30000;
}

static int stop_dial_closed(void *a)
{
	return D[*(const unsigned *)a].closed != 0;
}

/* Which OSDs saw the data object `objno`, the header objects: from what the simulators recorded. */
static void map_owners(int owner[], unsigned n_obj, int is_hdr[])
{
	unsigned i, k, plen = (unsigned)strlen(R.info.object_prefix);

	for (i = 0; i < n_obj; i++)
		owner[i] = -1;
	s_lock();
	for (i = 0; i < G.n_osd; i++) {
		uint32_t nr = 0;
		const sim_osd_rec *rec = sim_osd_recs(S_OSD(i)->osd, &nr);

		is_hdr[i] = 0;
		for (k = 0; k < nr; k++) {
			if (strncmp(rec[k].oid, "rbd_header.", 11) == 0 || strncmp(rec[k].oid, "rbd_id.", 7) == 0)
				is_hdr[i] = 1;
			if (strncmp(rec[k].oid, R.info.object_prefix, plen) == 0 && rec[k].oid[plen] == '.') {
				unsigned long long no = strtoull(rec[k].oid + plen + 1, NULL, 16);

				if (no < n_obj)
					owner[no] = (int)i;
			}
		}
	}
	s_unlock();
}

#define NOBJ 64u

/* One OSD (`mode`: blackhole or silent) is unreachable while writes go to every object. */
static void scenario_unreachable_osd(int mode)
{
	wopts o;
	int owner[NOBJ], is_hdr[8], k = -1, i2;
	unsigned first, i, n_other = 0, dial_k0;
	uint64_t tbh;
	uint64_t t0;
	jr r;
	srv *sk;

	memset(&o, 0, sizeof(o));
	o.n_osd = 4;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 64;
	o.img_size = 4u << 20;
	o.order = 16;
	world_start(&o);
	client_start(&o, tweak_unreachable);
	if (open_image() != 0)
		goto out;
	/* phase A: one write into every object, so the simulators tell which OSD owns which */
	first = nJ;
	for (i = 0; i < NOBJ; i++)
		(void)job_add(WR_IO_WRITE, (uint64_t)i * R.info.object_size, 4096u, 200u);
	r = jobs_submit_range(first, NOBJ);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	map_owners(owner, NOBJ, is_hdr);
	for (i2 = 0; i2 < (int)o.n_osd && k < 0; i2++) {
		unsigned cnt = 0;

		for (i = 0; i < NOBJ; i++)
			cnt += owner[i] == i2;
		if (!is_hdr[i2] && cnt >= 3u)
			k = i2;
	}
	WRT_CHECK(k >= 0);
	if (k < 0)
		goto out;
	sk = S_OSD((unsigned)k);
	dial_k0 = dials_to(sk->port);
	tbh = now_ms();
	if (mode == M_BLACKHOLE) {
		if (blackhole_on(sk) != 0) {
			fprintf(stderr, "note: this kernel completes connects to a full accept queue; the unreachable-OSD test is skipped\n");
			blackhole_off(sk);
			goto out;
		}
	} else {
		srv_set_mode(sk, M_SILENT);
		s_lock(); /* what it holds is cut: the engine dials again and meets a server that accepts and says nothing */
		for (i = 0; i < SMAX; i++)
			if (sk->c[i].fd >= 0)
				sconn_drop(sk, &sk->c[i], 1);
		s_unlock();
	}
	/* phase B: writes to every object again */
	first = nJ;
	for (i = 0; i < NOBJ; i++)
		(void)job_add(WR_IO_WRITE, (uint64_t)i * R.info.object_size + 4096u, 4096u, 300u);
	t0 = now_ms();
	r = jobs_submit_range(first, NOBJ);
	for (i = 0; i < NOBJ; i++)
		if (owner[i] != k)
			n_other++;
	/* the requests of the other OSDs are not held back by the dead one */
	for (;;) {
		unsigned done_other = 0;

		idle(20);
		for (i = 0; i < NOBJ; i++)
			if (owner[i] != k && J[first + i].done)
				done_other++;
		if (done_other == n_other || now_ms() - t0 > 4000u)
			break;
	}
	for (i = 0; i < NOBJ; i++) {
		job *j = &J[first + i];

		if (owner[i] != k) {
			WRT_CHECK(j->done);
			WRT_CHECK_STATUS(WR_OK, j->st);
			WRT_CHECK(j->done && j->t_done - t0 < 1200u); /* well before the OSD connect timeout of 1500 ms */
		} else {
			WRT_CHECK(!j->done); /* nobody can answer these yet */
		}
	}
	/* the dead OSD's own dial ends the way the mode says, at the time the action carried */
	{
		unsigned di = 0, found = 0, w;

		for (w = 0; w < 200u && !found; w++) {
			for (di = 0; di < nD; di++)
				if (D[di].port == sk->port && D[di].t_act >= tbh && D[di].closed && (mode == M_SILENT || D[di].err != 0)) {
					found = 1;
					break;
				}
			if (!found)
				idle(50);
		}
		WRT_CHECK(found);
		if (found && mode == M_BLACKHOLE) {
			uint64_t dt = D[di].t_closed - D[di].t_act;

			WRT_CHECK_U64(D[di].tmo, 1500u);        /* the action carried the OSD value, not the monitor's 700 */
			WRT_CHECK_U64(D[di].err, ETIMEDOUT);
			WRT_CHECK(dt >= 1400u && dt <= 2300u);
		}
		if (found && mode == M_SILENT) {
			uint64_t dt = D[di].t_closed - D[di].t_act;

			WRT_CHECK_U64(D[di].err, 0);            /* the engine's CLOSE (handshake timeout), answered by the pump */
			WRT_CHECK(dt >= 700u && dt <= 1900u);
		}
	}
	/* the other OSDs' sockets were never disturbed */
	{
		unsigned bad = 0, d;

		for (d = 0; d < nD; d++)
			for (i = 0; i < o.n_osd; i++)
				if ((int)i != k && D[d].port == S_OSD(i)->port && D[d].closed && D[d].err != 0)
					bad++;
		WRT_CHECK_U64(bad, 0);
	}
	/* the OSD comes back: the stalled requests finish with the right data */
	if (mode == M_BLACKHOLE)
		blackhole_off(sk);
	else
		srv_set_mode(sk, M_LIVE);
	r.first = first;
	r.n = NOBJ;
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 40000));
	for (i = 0; i < NOBJ; i++)
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
	WRT_CHECK(dials_to(sk->port) > dial_k0);
	check_image(1u << 20);
	check_store();
	world_check_sane();
out:
	client_stop();
	world_stop();
}

/* The monitor is unreachable at the start: its CONNECT carries connect_timeout_ms, the pump gives up at that time; then it is reachable and everything runs. */
static void test_monitor_connect_timeout(void)
{
	wopts o;
	unsigned zero = 0, first, i;
	jr r;

	memset(&o, 0, sizeof(o));
	o.n_osd = 3;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 32;
	o.img_size = 2u << 20;
	o.order = 16;
	world_start(&o);
	if (blackhole_on(S_MON()) != 0) {
		fprintf(stderr, "note: this kernel completes connects to a full accept queue; the monitor connect timeout test is skipped\n");
		blackhole_off(S_MON());
		world_stop();
		return;
	}
	client_start(&o, tweak_unreachable);
	WRT_CHECK_STATUS(WR_OK, pump(stop_dial_closed, &zero, 4000));
	WRT_CHECK(nD >= 1u && D[0].closed);
	WRT_CHECK_U64(D[0].port, S_MON()->port);
	WRT_CHECK_U64(D[0].tmo, 700u);
	WRT_CHECK_U64(D[0].err, ETIMEDOUT);
	WRT_CHECK(D[0].t_closed - D[0].t_act >= 650u && D[0].t_closed - D[0].t_act <= 1400u);
	blackhole_off(S_MON());
	if (open_image() == 0) {
		first = nJ;
		for (i = 0; i < 3; i++)
			(void)job_add(WR_IO_WRITE, (uint64_t)i * 70000u, 65536u, 7u + i);
		r = jobs_submit_range(first, 3);
		WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
		for (i = 0; i < 3; i++)
			WRT_CHECK_STATUS(WR_OK, J[first + i].st);
		check_store();
	}
	client_stop();
	world_stop();
}

static void tweak_49(wr_config *c)
{
	c->osd_sessions = 49;
	c->max_conns = 51;
}

static int stop_after_ms_flag;
static int stop_flag(void *a)
{
	(void)a;
	return stop_after_ms_flag;
}

/* 49 OSDs and the monitor at once: 50 live sockets (49 sessions, 51 connections), all of them in use. */
static void test_fifty_sockets(void)
{
	wopts o;
	unsigned first, i, k, nobj = 1000, batch = 400, touched = 0;
	jr r;

	memset(&o, 0, sizeof(o));
	o.n_osd = 49;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 1024;
	o.img_size = 64u << 20;
	o.order = 16;
	world_start(&o);
	client_start(&o, tweak_49);
	if (open_image() != 0)
		goto out;
	/* one write into every object, in batches of 400 in flight: all primaries get work, so every session is open at the same time */
	for (k = 0; k < nobj; k += batch) {
		unsigned n = nobj - k < batch ? nobj - k : batch;

		jobs_reset();
		first = nJ;
		for (i = 0; i < n; i++)
			(void)job_add(WR_IO_WRITE, (uint64_t)(k + i) * R.info.object_size + ((k + i) % 7u) * 512u, 4096u, 500u);
		r = jobs_submit_range(first, n);
		WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 120000));
		for (i = 0; i < n; i++)
			WRT_CHECK_STATUS(WR_OK, J[first + i].st);
	}
	s_lock();
	for (i = 0; i < G.n_osd; i++)
		touched += sim_osd_n_requests(S_OSD(i)->osd) > 0u;
	s_unlock();
	WRT_CHECK_U64(touched, 49);
	WRT_CHECK_U64(R.peak_sockets, 50);              /* the monitor and every OSD at once, within the pump's 64 */
	WRT_CHECK(R.peak_sockets <= 64u);
	WRT_CHECK_U64(wrl_loop_open_sockets(R.l), 50);
	{
		wr_osd_stats st;

		wr_client_osd_stats(R.c, &st);
		WRT_CHECK_U64(st.sessions_hiwater, 49);
	}
	for (k = 0; k < nobj; k += batch) {
		unsigned n = nobj - k < batch ? nobj - k : batch;

		jobs_reset();
		first = nJ;
		for (i = 0; i < n; i++)
			(void)job_add(WR_IO_READ, (uint64_t)(k + i) * R.info.object_size, 8192u, 0);
		(void)job_add(WR_IO_FLUSH, 0, 0, 0);
		r = jobs_submit_range(first, n + 1u);
		WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 120000));
		for (i = 0; i < n; i++) {
			WRT_CHECK_STATUS(WR_OK, J[first + i].st);
			WRT_CHECK(memcmp(J[first + i].buf, M + J[first + i].r.offset, 8192u) == 0);
		}
	}
	check_store();
	world_check_sane();
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
	/* closing the image frees its slot; the pump keeps running */
	WRT_CHECK_STATUS(WR_OK, wr_image_close(R.img, WR_CLOSE_DRAIN));
	WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	stop_after_ms_flag = 0;
	WRT_CHECK_STATUS(WR_E_TIMEOUT, pump(stop_flag, NULL, 200));
out:
	client_stop();
	world_stop();
}

/* The pump is destroyed in the middle of I/O with sockets open: nothing it opened stays open. */
static void test_destroy_in_flight(void)
{
	wopts o;
	unsigned first, i, open_before;
	jr r;

	memset(&o, 0, sizeof(o));
	o.n_osd = 4;
	o.key_type = WR_KEY_TYPE_AES;
	o.pg_num = 32;
	o.img_size = 4u << 20;
	o.order = 16;
	world_start(&o);
	client_start(&o, NULL);
	if (open_image() == 0) {
		s_lock();
		for (i = 1; i <= G.n_osd; i++)
			G.s[i].rd_chunk = 64; /* the OSDs read slowly: the writes cannot have finished a moment later */
		s_unlock();
		first = nJ;
		for (i = 0; i < 32; i++)
			(void)job_add(WR_IO_WRITE, (uint64_t)i * 100000u, 100000u, 3u);
		r = jobs_submit_range(first, 32);
		WRT_CHECK_U64(pump(jr_done, &r, 100), (uint64_t)(int64_t)WR_E_TIMEOUT); /* a moment, not to the end */
		WRT_CHECK(!jr_done(&r));
		open_before = wrl_loop_open_sockets(R.l);
		WRT_CHECK(open_before >= 2u);
		WRT_CHECK(g_nfds == open_before);
	}
	client_stop(); /* checks g_nfds == 0 */
	world_stop();
}

/* A submit is followed by a run, so a request does not wait for a timer. */
static void test_submit_runs_now(void)
{
	wopts o;
	unsigned i;
	uint64_t worst = 0, t_wait = 0;

	memset(&o, 0, sizeof(o));
	o.n_osd = 3;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 32;
	o.img_size = 2u << 20;
	o.order = 16;
	world_start(&o);
	client_start(&o, NULL);
	if (open_image() != 0)
		goto out;
	idle(400); /* idle: the engine sleeps until its next timer */
	{
		wr_clock now;

		wrl_clock(&now);
		WRT_CHECK(R.l->next_deadline_ms == WR_DEADLINE_NONE || R.l->next_deadline_ms > now.mono_ms + 1500u); /* a timer wait would cost seconds */
	}
	for (i = 0; i < 40; i++) {
		unsigned first = nJ;
		jr r;
		uint64_t dt;

		(void)job_add(i % 2u ? WR_IO_READ : WR_IO_WRITE, (uint64_t)i * 40000u, 4096u, 9u);
		r = jobs_submit_range(first, 1);
		WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 5000));
		WRT_CHECK_STATUS(WR_OK, J[first].st);
		dt = J[first].t_done - J[first].t_sub;
		if (dt > worst)
			worst = dt;
	}
	WRT_CHECK(worst < 1000u);
	/* what happens without the run: the request waits for the loop's next wake-up (a note, not a rule of the pump) */
	{
		unsigned first = nJ;
		jr r;

		idle(300); /* the pump is idle again: the next step sleeps */
		(void)job_add(WR_IO_WRITE, 1500000u, 4096u, 9u);
		WRT_CHECK_STATUS(WR_OK, wr_image_submit(R.img, &J[first].r));
		J[first].t_sub = now_ms();
		r.first = first;
		r.n = 1;
		(void)pump(jr_done, &r, 2500); /* gives up after 2.5 s: the wait would be until the next timer (hdr_refresh_ms is 10 s) */
		t_wait = now_ms() - J[first].t_sub;
		WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0)); /* the run the host owed */
		WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 20000));
		WRT_CHECK_STATUS(WR_OK, J[first].st);
	}
	fprintf(stderr, "  (submit + run: worst %llu ms of 40; submit without the run: still waiting after %llu ms)\n", (unsigned long long)worst,
		(unsigned long long)t_wait);
	check_store();
out:
	client_stop();
	world_stop();
}

/* ---- review additions: ordering, odd sizes, 64-bit offsets, error mapping, cancels ---------------------------------------------- */

static int rng_pick(unsigned n)
{
	return (int)(rnd() % n);
}

static int overlaps(const job *a, const job *b)
{
	return a->r.length != 0 && b->r.length != 0 && a->r.offset < b->r.offset + b->r.length && b->r.offset < a->r.offset + a->r.length;
}

/* Overlapping requests of every kind in flight together, over real sockets and several OSDs, on an image whose size is not a multiple of the object
 * size. Reads are compared with the model as of their submission (C14: an overlapping request waits for the earlier one), and for every pair of
 * overlapping requests, unless both are reads, the earlier one completes first. */
static void test_overlap_order(void)
{
	wopts o;
	unsigned nb, i, j, ops = 0;

	memset(&o, 0, sizeof(o));
	o.n_osd = 5;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 64;
	o.img_size = (1u << 20) + 12345u;
	o.order = 16;
	world_start(&o);
	client_start(&o, NULL);
	if (open_image() != 0)
		goto out;
	for (nb = 0; nb < 24; nb++) {
		unsigned n = 20 + (unsigned)rng_pick(29), bad = 0;
		jr r;

		jobs_reset();
		for (i = 0; i < n; i++) {
			unsigned k = (unsigned)rng_pick(100);
			uint64_t off = rng_pick(4) == 0 ? Msize - 1u - (uint64_t)rng_pick(90000) : (uint64_t)rng_pick(5) * 100003u + (uint64_t)rng_pick(40000);
			uint64_t len = 1u + (uint64_t)rng_pick(130000);

			if (rng_pick(12) == 0)
				len = 0;
			if (off >= Msize)
				off = Msize - 1u;
			if (len > Msize - off)
				len = Msize - off;
			if (k < 38)
				(void)job_add(WR_IO_WRITE, off, len, 2000u + nb * 64u + i);
			else if (k < 72)
				(void)job_add_read_exp(off, len);
			else if (k < 80)
				(void)job_add(WR_IO_DISCARD, off, len, 0);
			else if (k < 90)
				(void)job_add(WR_IO_WRITE_ZEROES, off, len, 0);
			else
				(void)job_add(WR_IO_FLUSH, 0, 0, 0);
		}
		r = jobs_submit_range(0, n);
		WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
		for (i = 0; i < n; i++) {
			WRT_CHECK_STATUS(WR_OK, J[i].st);
			if (J[i].r.kind == WR_IO_READ && J[i].r.length != 0 && memcmp(J[i].buf, J[i].exp, (size_t)J[i].r.length) != 0)
				bad++;
			if (J[i].r.kind == WR_IO_FLUSH) {
				for (j = 0; j < i; j++)
					if (J[j].r.kind == WR_IO_WRITE && J[j].seq > J[i].seq)
						bad++; /* a flush that completed before a write it covers */
			}
			for (j = i + 1u; j < n; j++)
				if (overlaps(&J[i], &J[j]) && !(J[i].r.kind == WR_IO_READ && J[j].r.kind == WR_IO_READ) && J[i].seq > J[j].seq)
					bad++; /* overlapping requests completed out of submission order */
		}
		WRT_CHECK_U64(bad, 0);
		ops += n;
	}
	check_image(300007u);
	check_store();
	WRT_CHECK(ops > 400u);
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
	world_check_sane();
out:
	client_stop();
	world_stop();
}

/* An image whose last object holds seven bytes, and requests outside the image: each is refused when it is submitted and queues nothing. */
static void test_range_edges(void)
{
	wopts o;
	wr_io_req r;
	uint8_t buf[64];
	unsigned first, i;
	jr jj;
	wr_osd_stats st;
	struct {
		uint64_t off, len;
	} bad[] = {{3u * 65536u + 7u, 1}, {3u * 65536u + 6u, 2}, {UINT64_MAX - 3u, 8}, {UINT64_MAX, 1}, {1u << 20, 1}};

	memset(&o, 0, sizeof(o));
	o.n_osd = 3;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 32;
	o.img_size = 3u * 65536u + 7u;
	o.order = 16;
	world_start(&o);
	client_start(&o, NULL);
	if (open_image() != 0)
		goto out;
	WRT_CHECK_U64(R.info.size_bytes, o.img_size);
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		memset(&r, 0, sizeof(r));
		r.kind = WR_IO_WRITE;
		r.offset = bad[i].off;
		r.length = bad[i].len;
		r.buf = buf;
		WRT_CHECK_STATUS(WR_E_RANGE, wr_image_submit(R.img, &r));
		r.kind = WR_IO_READ;
		WRT_CHECK_STATUS(WR_E_RANGE, wr_image_submit(R.img, &r));
		r.kind = WR_IO_DISCARD;
		WRT_CHECK_STATUS(WR_E_RANGE, wr_image_submit(R.img, &r));
	}
	{ /* the long one: a whole-image read plus one byte */
		uint8_t *big = (uint8_t *)malloc((size_t)o.img_size + 1u);

		memset(&r, 0, sizeof(r));
		r.kind = WR_IO_READ;
		r.offset = 0;
		r.length = o.img_size + 1u;
		r.buf = big;
		WRT_CHECK_STATUS(WR_E_RANGE, wr_image_submit(R.img, &r));
		free(big);
	}
	WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	wr_client_osd_stats(R.c, &st);
	WRT_CHECK_U64(st.reqs_inflight, 0);
	first = nJ;
	(void)job_add(WR_IO_WRITE, 3u * 65536u, 7u, 31);                 /* the whole last object */
	(void)job_add(WR_IO_WRITE, 3u * 65536u - 5u, 12u, 32);           /* across the last boundary, to the end */
	(void)job_add(WR_IO_WRITE, o.img_size - 1u, 1u, 33);             /* the last byte */
	(void)job_add(WR_IO_WRITE, 2u * 65536u + 65535u, 1u, 34);        /* the last byte of the third object */
	jj = jobs_submit_range(first, nJ - first);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &jj, 30000));
	for (i = 0; i < jj.n; i++)
		WRT_CHECK_STATUS(WR_OK, J[jj.first + i].st);
	check_image(o.img_size);
	check_image(65536u);
	check_image(4093u);
	check_store();
	world_check_sane();
out:
	client_stop();
	world_stop();
}

/* Offsets above 2^31 and 2^32 on an 8 TiB sparse image (4 MiB objects): the object number, the offset inside it and the name are computed here
 * independently and the simulator's store is the oracle. */
static void test_big_offsets(void)
{
	wopts o;
	static const struct {
		uint64_t off, len;
	} W[] = {
	    {(8ull << 40) - 4097u, 4097u},                    /* the last bytes of the image */
	    {(1ull << 32) - 100u, 200u},                      /* across the 2^32 boundary (also an object boundary) */
	    {(1ull << 31) - 100u, 200u},                      /* across 2^31 */
	    {(1ull << 40) + 4194304u - 5000u, 10000u},        /* across an object boundary above 2^40 */
	    {(3ull << 32) + 1u, 300u},                        /* inside an object */
	    {(1ull << 33) + (1ull << 22) * 5u + 4194303u, 1u} /* the last byte of an object */
	};
	enum { NW = sizeof(W) / sizeof(W[0]) };
	unsigned i, first;
	uint64_t obj = 1ull << 22;
	jr r;

	memset(&o, 0, sizeof(o));
	o.n_osd = 4;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 32;
	o.img_size = 8ull << 40;
	o.order = 22;
	o.no_model = 1;
	world_start(&o);
	client_start(&o, NULL);
	if (open_image() != 0)
		goto out;
	WRT_CHECK_U64(R.info.size_bytes, o.img_size);
	WRT_CHECK_U64(R.info.object_size, obj);
	first = nJ;
	for (i = 0; i < NW; i++)
		(void)job_add(WR_IO_WRITE, W[i].off, W[i].len, 700u + i);
	r = jobs_submit_range(first, NW);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 30000));
	for (i = 0; i < NW; i++) {
		unsigned bad = 0;
		uint64_t pos = W[i].off, end = W[i].off + W[i].len;
		uint8_t *want = (uint8_t *)malloc((size_t)W[i].len), *got = (uint8_t *)malloc((size_t)W[i].len);

		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
		if (want == NULL || got == NULL)
			abort();
		cw_fill(want, 700u + i, W[i].off, (size_t)W[i].len);
		while (pos < end) { /* object by object, from the store */
			uint64_t objno = pos / obj, in = pos % obj, n = obj - in < end - pos ? obj - in : end - pos;
			char name[160];
			int exists = 0;
			wr_status st;

			snprintf(name, sizeof(name), "%s.%016" PRIx64, R.info.object_prefix, objno);
			s_lock();
			st = sim_store_read(G.store, R.info.data_pool_id, name, in, got + (pos - W[i].off), (size_t)n, &exists);
			s_unlock();
			if (st != WR_OK || !exists)
				bad++;
			pos += n;
		}
		if (memcmp(got, want, (size_t)W[i].len) != 0)
			bad++;
		WRT_CHECK_U64(bad, 0);
		free(want);
		free(got);
	}
	/* and back through the engine */
	first = nJ;
	for (i = 0; i < NW; i++)
		(void)job_add(WR_IO_READ, W[i].off, W[i].len, 0);
	r = jobs_submit_range(first, NW);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 30000));
	for (i = 0; i < NW; i++) {
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
		WRT_CHECK_U64(cw_diff(J[first + i].buf, 700u + i, W[i].off, (size_t)W[i].len), 0);
	}
	/* a read of an object nobody wrote, far out: zeros */
	first = nJ;
	(void)job_add(WR_IO_READ, (5ull << 40) + 17u, 5000u, 0);
	r = jobs_submit_range(first, 1);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 30000));
	WRT_CHECK_STATUS(WR_OK, J[first].st);
	for (i = 0; i < 5000u; i++)
		if (J[first].buf[i] != 0)
			break;
	WRT_CHECK_U64(i, 5000);
	world_check_sane();
out:
	client_stop();
	world_stop();
}

static void osd_fault_all(int32_t op, int32_t err)
{
	unsigned i;

	s_lock();
	for (i = 0; i < G.n_osd; i++) {
		sim_osd_faults(S_OSD(i)->osd)->force_errno_op = op;
		sim_osd_faults(S_OSD(i)->osd)->force_errno = err;
	}
	s_unlock();
}

/* The error of an OSD reaches the request that caused it; ENOENT on a data object is the one error that reads as zeros. */
static void test_error_mapping(void)
{
	wopts o;
	unsigned first, i;
	jr r;
	wr_osd_stats st;

	memset(&o, 0, sizeof(o));
	o.n_osd = 3;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 32;
	o.img_size = 1u << 20;
	o.order = 16;
	world_start(&o);
	client_start(&o, NULL);
	if (open_image() != 0)
		goto out;
	first = nJ;
	(void)job_add(WR_IO_WRITE, 0, 200000u, 61);
	r = jobs_submit_range(first, 1);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 30000));
	WRT_CHECK_STATUS(WR_OK, J[first].st);
	/* EIO on reads: the request fails with the OSD's error, it does not read as zeros */
	osd_fault_all((int32_t)WRI_OSD_OP_READ, -5);
	first = nJ;
	(void)job_add(WR_IO_READ, 1000u, 150000u, 0);
	r = jobs_submit_range(first, 1);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 30000));
	WRT_CHECK_STATUS(WR_E_OSD_IO, J[first].st);
	/* EIO on writes */
	osd_fault_all((int32_t)WRI_OSD_OP_WRITE, -5);
	first = nJ;
	(void)job_add(WR_IO_WRITE, 5000u, 70000u, 62);
	r = jobs_submit_range(first, 1);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 30000));
	WRT_CHECK_STATUS(WR_E_OSD_IO, J[first].st);
	/* EPERM, ENOSPC: their own statuses */
	osd_fault_all((int32_t)WRI_OSD_OP_READ, -1);
	first = nJ;
	(void)job_add(WR_IO_READ, 0, 4096u, 0);
	r = jobs_submit_range(first, 1);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 30000));
	WRT_CHECK_STATUS(WR_E_OSD_PERM, J[first].st);
	osd_fault_all((int32_t)WRI_OSD_OP_WRITE, -28);
	first = nJ;
	(void)job_add(WR_IO_WRITE, 5000u, 70000u, 62);
	r = jobs_submit_range(first, 1);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 30000));
	WRT_CHECK_STATUS(WR_E_OSD_NOSPC, J[first].st);
	/* ENOENT on a read: the object is "missing", it reads as zeros whatever the store holds */
	osd_fault_all((int32_t)WRI_OSD_OP_READ, -2);
	first = nJ;
	(void)job_add(WR_IO_READ, 1000u, 150000u, 0);
	r = jobs_submit_range(first, 1);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 30000));
	WRT_CHECK_STATUS(WR_OK, J[first].st);
	for (i = 0; i < 150000u; i++)
		if (J[first].buf[i] != 0)
			break;
	WRT_CHECK_U64(i, 150000);
	/* the fault ends: the same requests work, and the failed writes did not leave a stray state behind */
	osd_fault_all(0, 0);
	first = nJ;
	(void)job_add(WR_IO_WRITE, 5000u, 70000u, 62);
	r = jobs_submit_range(first, 1);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 30000));
	WRT_CHECK_STATUS(WR_OK, J[first].st);
	check_image(65537u);
	check_store();
	wr_client_osd_stats(R.c, &st);
	WRT_CHECK(st.ops_failed >= 4u);
	WRT_CHECK_U64(st.reqs_inflight, 0);
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
	world_check_sane();
out:
	client_stop();
	world_stop();
}

static void free_job_buf(job *j)
{
	if (j->buf != NULL) {
		memset(j->buf, 0xDD, (size_t)j->r.length); /* poison, then give it back: a late write or read by the engine is a use after free (ASan) */
		free(j->buf);
		j->buf = NULL;
	}
}

/* Reads are cancelled while their replies are landing in the caller's buffers (the window of rx_window points into them); a cancel that is
 * answered WR_OK hands the buffer back at once and the test frees it. The data is checked afterwards and the connection must recover. */
static void test_cancel_landing(void)
{
	wopts o;
	unsigned first, i, n_ok = 0, n_busy = 0, n_state = 0;
	jr r;

	memset(&o, 0, sizeof(o));
	o.n_osd = 4;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 32;
	o.img_size = 4u << 20;
	o.order = 16;
	world_start(&o);
	client_start(&o, tweak_cuts);
	if (open_image() != 0)
		goto out;
	first = nJ;
	for (i = 0; i < 4; i++)
		(void)job_add(WR_IO_WRITE, (uint64_t)i << 20, 1u << 20, 80u + i);
	r = jobs_submit_range(first, 4);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	for (i = 0; i < 4; i++)
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
	s_lock();
	for (i = 1; i <= G.n_osd; i++)
		G.s[i].wr_chunk = 16; /* the replies trickle in: 600 KB per OSD take far longer than the 60 ms below, however fast the machine */
	s_unlock();
	first = nJ;
	for (i = 0; i < 8; i++)
		(void)job_add(WR_IO_READ, (uint64_t)i * 400000u + 11u, 300000u, 0);
	r = jobs_submit_range(first, 8);
	idle(60); /* some of the data is in the buffers, none of the reads is complete */
	for (i = 0; i < 8; i++) {
		job *j = &J[first + i];
		wr_status st;

		if (j->done)
			continue;
		st = wr_image_cancel(R.img, &j->r);
		if (st == WR_OK) {
			n_ok++;
			free_job_buf(j);
		} else if (st == WR_E_BUSY) {
			n_busy++;
		} else {
			WRT_CHECK_STATUS(WR_E_STATE, st);
			n_state++;
		}
	}
	WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	WRT_CHECK(n_ok + n_busy > 0u);
	s_lock();
	for (i = 1; i <= G.n_osd; i++)
		G.s[i].wr_chunk = 0;
	s_unlock();
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	for (i = 0; i < 8; i++) {
		job *j = &J[first + i];

		WRT_CHECK(j->st == WR_OK || j->st == WR_E_CANCELLED);
		if (j->st == WR_OK && j->buf != NULL)
			WRT_CHECK(memcmp(j->buf, M + j->r.offset, (size_t)j->r.length) == 0);
	}
	fprintf(stderr, "  (cancel while landing: %u cancelled at once, %u busy, %u already done)\n", n_ok, n_busy, n_state);
	check_image(1u << 20); /* the sessions that were reset serve again */
	check_store();
	world_check_sane();
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
out:
	client_stop();
	world_stop();
}

/* A 4 MiB write is cancelled while the OSDs read slowly: some of its operations are queued, some are half in a transmit queue (the buffer is
 * referenced: WR_E_BUSY, the host keeps it), some are out and unanswered (a zombie with its own copy: WR_OK, the host frees the buffer and the
 * test poisons it first). A full overwrite follows at once; once every zombie is answered the image holds the overwrite, nothing of the old write. */
static void test_cancel_write_tx(void)
{
	wopts o;
	unsigned first, i;
	jr r;
	wr_status cst;
	wr_osd_stats st;

	memset(&o, 0, sizeof(o));
	o.n_osd = 4;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 64;
	o.img_size = 4u << 20;
	o.order = 16;
	world_start(&o);
	client_start(&o, tweak_cuts);
	if (open_image() != 0)
		goto out;
	s_lock();
	for (i = 1; i <= G.n_osd; i++)
		G.s[i].rd_chunk = 64;
	s_unlock();
	first = nJ;
	(void)job_add(WR_IO_WRITE, 0, 4u << 20, 301u);
	r = jobs_submit_range(first, 1);
	idle(80);
	WRT_CHECK(!J[first].done);
	cst = wr_image_cancel(R.img, &J[first].r);
	WRT_CHECK(cst == WR_OK || cst == WR_E_BUSY);
	if (cst == WR_OK)
		free_job_buf(&J[first]);
	fprintf(stderr, "  (cancel of a write with operations in the transmit queues: %s)\n", cst == WR_OK ? "answered WR_OK" : "answered WR_E_BUSY");
	s_lock();
	for (i = 1; i <= G.n_osd; i++)
		G.s[i].rd_chunk = 0;
	s_unlock();
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	WRT_CHECK_STATUS(WR_E_CANCELLED, J[first].st);
	first = nJ;
	for (i = 0; i < 4; i++)
		(void)job_add(WR_IO_WRITE, (uint64_t)i << 20, 1u << 20, 310u + i);
	r = jobs_submit_range(first, 4);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	for (i = 0; i < 4; i++)
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
	for (i = 0; i < 200u; i++) {
		wr_client_osd_stats(R.c, &st);
		if (st.zombie_bytes_used == 0u && st.reqs_inflight == 0u && st.ops_inflight == 0u)
			break;
		idle(50);
	}
	wr_client_osd_stats(R.c, &st);
	WRT_CHECK_U64(st.zombie_bytes_used, 0);
	WRT_CHECK_U64(st.ops_inflight, 0);
	check_image(1u << 20);
	check_store();
	world_check_sane();
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
out:
	client_stop();
	world_stop();
}

static unsigned sum_held(void)
{
	unsigned i, n = 0;

	s_lock();
	for (i = 0; i < G.n_osd; i++)
		n += sim_osd_n_held(S_OSD(i)->osd);
	s_unlock();
	return n;
}

/* A write is cancelled once every one of its operations is at an OSD, executed, with the answer held back; its buffer is freed; a later overlapping write
 * is submitted; then the OSDs "restart" (connections cut, the held answers are lost). The abandoned write is resent from the core's copy and the later
 * write waits for its answer (C10), so the overlap holds the LATER bytes and the rest of the first write holds the first write's. With no_dedup the OSD
 * cannot recognise the resend: the later write would be overwritten by it if it were sent before the resend was answered. */
static void zombie_round(int no_dedup, unsigned seedbase)
{
	wopts o;
	unsigned first, i, tries;
	uint64_t a_off = 100000u, a_len = 300000u, b_off = 250000u, b_len = 200000u, k, bad = 0;
	unsigned n_a_ops = (unsigned)((a_off + a_len - 1u) / 65536u - a_off / 65536u + 1u);
	jr r;
	wr_status cst;
	wr_osd_stats st;
	uint8_t *a, *b;

	memset(&o, 0, sizeof(o));
	o.n_osd = 4;
	o.key_type = WR_KEY_TYPE_AES256K;
	o.pg_num = 64;
	o.img_size = 2u << 20;
	o.order = 16;
	world_start(&o);
	client_start(&o, tweak_cuts);
	if (open_image() != 0)
		goto out;
	first = nJ; /* warm up: a write into every object, so every OSD session of the image is open */
	for (i = 0; i < 32u; i++)
		(void)job_add(WR_IO_WRITE, (uint64_t)i * 65536u, 512u, seedbase + 5u);
	r = jobs_submit_range(first, 32);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	for (i = 0; i < 32u; i++)
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
	s_lock();
	for (i = 0; i < G.n_osd; i++) {
		sim_osd_faults(S_OSD(i)->osd)->hold_replies = 1;
		sim_osd_faults(S_OSD(i)->osd)->no_dedup = (uint8_t)no_dedup;
	}
	s_unlock();
	first = nJ;
	(void)job_add(WR_IO_WRITE, a_off, a_len, seedbase);
	r = jobs_submit_range(first, 1);
	a = (uint8_t *)malloc((size_t)a_len); /* a copy for the check: the job's own buffer is freed below */
	if (a == NULL)
		abort();
	memcpy(a, J[first].buf, (size_t)a_len);
	for (tries = 0; tries < 400u && sum_held() < n_a_ops; tries++)
		idle(10);
	WRT_CHECK_U64(sum_held(), n_a_ops); /* every operation of the write executed and its answer is held */
	cst = wr_image_cancel(R.img, &J[first].r);
	WRT_CHECK_STATUS(WR_OK, cst); /* all operations are out and none is answered: the core keeps a copy and hands the buffer back */
	if (cst == WR_OK)
		free_job_buf(&J[first]);
	s_lock();
	for (i = 0; i < G.n_osd; i++)
		sim_osd_faults(S_OSD(i)->osd)->hold_replies = 0; /* what is held stays held; new answers flow */
	s_unlock();
	(void)job_add(WR_IO_WRITE, b_off, b_len, seedbase + 1u);
	b = (uint8_t *)malloc((size_t)b_len);
	if (b == NULL)
		abort();
	memcpy(b, J[first + 1u].buf, (size_t)b_len);
	WRT_CHECK_STATUS(WR_OK, job_submit(&J[first + 1u]));
	idle(100); /* the later write is held back by the fence: nothing of it may reach an OSD (and be answered) while the abandoned one is unanswered */
	WRT_CHECK(!J[first + 1u].done);
	wr_client_osd_stats(R.c, &st);
	WRT_CHECK(st.zombie_bytes_used >= a_len);
	s_lock();
	for (i = 0; i < G.n_osd; i++)
		sim_osd_restart(S_OSD(i)->osd); /* the connections are cut and the held answers are gone */
	s_unlock();
	r.first = first;
	r.n = 2;
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	WRT_CHECK_STATUS(WR_E_CANCELLED, J[first].st);
	WRT_CHECK_STATUS(WR_OK, J[first + 1u].st);
	for (i = 0; i < 200u; i++) {
		wr_client_osd_stats(R.c, &st);
		if (st.zombie_bytes_used == 0u && st.reqs_inflight == 0u && st.ops_inflight == 0u)
			break;
		idle(50);
	}
	wr_client_osd_stats(R.c, &st);
	WRT_CHECK_U64(st.zombie_bytes_used, 0);
	WRT_CHECK_U64(st.ops_inflight, 0);
	WRT_CHECK(st.ops_resent > 0u);
	/* what the image holds now, through the engine */
	first = nJ;
	(void)job_add(WR_IO_READ, 0, 600000u, 0);
	r = jobs_submit_range(first, 1);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	WRT_CHECK_STATUS(WR_OK, J[first].st);
	for (k = 0; k < 600000u; k++) {
		uint8_t g = J[first].buf[k];
		uint8_t want = 0;

		if (k >= b_off && k < b_off + b_len)
			want = b[k - b_off]; /* the overlap holds the later write, whatever the resends did */
		else if (k >= a_off && k < a_off + a_len)
			want = a[k - a_off]; /* its operations were all executed before the cancel */
		else if (k % 65536u < 512u)
			want = cw_pat(seedbase + 5u, k); /* the warm-up writes */
		if (g != want)
			bad++;
	}
	WRT_CHECK_U64(bad, 0);
	free(a);
	free(b);
	world_check_sane();
out:
	client_stop();
	world_stop();
}

#define RUN(t)                                                                                          \
	do {                                                                                            \
		uint64_t t0_ = now_ms();                                                                \
		int fd0_ = fd_count();                                                                  \
		t;                                                                                      \
		fprintf(stderr, "  %-44s %6llu ms\n", #t, (unsigned long long)(now_ms() - t0_));         \
		WRT_CHECK_U64(fd_count(), fd0_); /* no descriptor left over by the test as a whole */   \
	} while (0)

int main(void)
{
	/* A send on a reset connection must not kill the test: the pump uses MSG_NOSIGNAL. SIGPIPE stays at its default on purpose. */
	RUN(test_image_io(WR_KEY_TYPE_AES256K));
	RUN(test_image_io(WR_KEY_TYPE_AES));
	RUN(test_slow_server());
	RUN(test_server_cuts());
	RUN(test_monitor_connect_timeout());
	RUN(scenario_unreachable_osd(M_BLACKHOLE));
	RUN(scenario_unreachable_osd(M_SILENT));
	RUN(test_fifty_sockets());
	RUN(test_destroy_in_flight());
	RUN(test_submit_runs_now());
	RUN(test_overlap_order());
	RUN(test_range_edges());
	RUN(test_big_offsets());
	RUN(test_error_mapping());
	RUN(test_cancel_landing());
	RUN(test_cancel_write_tx());
	RUN(zombie_round(0, 900));
	RUN(zombie_round(1, 910)); /* 1 = the OSDs keep no duplicate log */
	return wrt_finish();
}
