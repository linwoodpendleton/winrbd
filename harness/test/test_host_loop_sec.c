/* SPDX-License-Identifier: MIT */
/*
 * test_host_loop_sec.c - the Linux socket pump (harness/host/wrl_loop.c) with msgr2 SECURE MODE: the whole client engine with the OSD client and the image
 * layer against one simulated monitor and N simulated OSDs over REAL TCP sockets on 127.0.0.1 (docs/design/core-architecture.md part D, module tool-modes,
 * ctest name host.loop.sec). The servers are the technique of test_host_loop_osd.c (one pthread per server, the simulator's feed / drain under one mutex,
 * the test thread is the host and drives the engine with wrl_loop_step / wrl_loop_run), with secure peers: after AUTH_DONE every byte in both directions
 * goes through the independent secure encoder / decoder of the simulators (sim_m2_sec.h, ref_gcm.h), which share no code with the core.
 *
 * The pump and the system services are included, not linked (like test_host_loop_osd.c), so that every socket the pump opens can be counted; the AES-NI hook
 * is included too, and a counting table in front of it (the same idea as the spy of wr-rbd) shows whether the hook really ran.
 *
 * Checked:
 *   image I/O      secure-only everywhere (monitor, 3 OSDs), both key types, with and without the accelerated hook: an image written (12 concurrent cross-
 *                  object writes, a flush that completes after them), read back, discarded and zeroed; every byte compared with a flat model AND with the
 *                  simulator's store; conns_secure counts the connections, conns_crc and sec_failures stay 0; every secret the servers issued is different;
 *                  no complete secret is in the engine's memory afterwards; with the hook, its key objects are used (two per connection) and its updates counted
 *   slow server    every server writes and reads one byte at a time (secure framing is cut at every byte), with and without the hook
 *   server cuts    an OSD that closes in the middle of a secure reply (orderly close and reset) and one that executes a write and cuts without answering: the
 *                  engine reconnects, the new connection has a NEW secret (the log of secrets grows, all distinct), resends, data right, duplicate recognised
 *   hostile frames one bit flipped in the next secure frame of every live OSD connection (tag failure: sec_failures counted, the connection redialled, the
 *                  request completes with the right data); a secure frame cut after 50 bytes followed by EOF (an end in the middle of part 1: no tag failure)
 *   policies       stock, secure-only + crc-only OSDs, crc-only + secure-only OSDs, secure-first against crc-only servers, crc-first against both and
 *                  against secure-only servers: the mode each role ends in is what the policy and the server's list say (the counters and the secrets the
 *                  servers issued agree with each other)
 *   refusals       a secure-only client against a crc-only monitor, a crc-only client against a secure-only monitor: AUTH_FAILED with M2_BAD_METHOD and the
 *                  allowed-modes mask of the server, no connection counted, the pump does not spin on it
 *   no leak        every descriptor the pump opened is closed again, after every test
 *   wr-monprobe    (when WR_MONPROBE names the tool) --mode secure / --require-mode / --accel against the secure monitor: exit status, the stats line, a
 *                  refused offer, bad option values; the connection secret nowhere in the output
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "client_sec_rig.h"

#include "../host/wrl_sys.c"
#include "../host/wrl_gcm_aesni.c"

/* ---- a counter on every socket the pump opens, and on every connect --------------------------------------- */

static int hk_socket(int domain, int type, int proto);
static int hk_close(int fd);
static int hk_connect(int fd, const struct sockaddr *sa, socklen_t sl);
#define socket hk_socket
#define close hk_close
#define connect hk_connect

#include "../host/wrl_loop.c"

#undef socket
#undef close
#undef connect

#define FDTAB 256u
static int g_fds[FDTAB];
static unsigned g_nfds, g_connects;

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

static int hk_connect(int fd, const struct sockaddr *sa, socklen_t sl)
{
	g_connects++;
	return connect(fd, sa, sl);
}

static uint64_t now_ms(void)
{
	wr_clock c;

	wrl_clock(&c);
	return c.mono_ms;
}

/* ---- the accelerated hook, with a count of what the core calls ---------------------------------------------- */

typedef struct gcm_spy {
	wr_prim_ops tab;  /* what the core is given */
	wr_prim_ops hook; /* the hook's own table */
	uint64_t setkeys, starts, updates, finals, wipes;
} gcm_spy;

static gcm_spy g_spy;

static wr_status spy_setkey(void *ctx, void *state, const uint8_t key[16])
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->setkeys++;
	return g->hook.gcm_setkey(g->hook.ctx, state, key);
}
static wr_status spy_start(void *ctx, void *state, const uint8_t iv[12], int decrypt)
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->starts++;
	return g->hook.gcm_start(g->hook.ctx, state, iv, decrypt);
}
static void spy_update(void *ctx, void *state, const uint8_t *in, uint8_t *out, size_t n)
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->updates++;
	g->hook.gcm_update(g->hook.ctx, state, in, out, n);
}
static void spy_final_enc(void *ctx, void *state, uint8_t tag[16])
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->finals++;
	g->hook.gcm_final_enc(g->hook.ctx, state, tag);
}
static wr_status spy_final_dec(void *ctx, void *state, const uint8_t tag[16])
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->finals++;
	return g->hook.gcm_final_dec(g->hook.ctx, state, tag);
}
static void spy_wipe(void *ctx, void *state)
{
	gcm_spy *g = (gcm_spy *)ctx;

	g->wipes++;
	g->hook.gcm_wipe(g->hook.ctx, state);
}

/* 0 when the hook is there (this CPU, this build). */
static int spy_init(void)
{
	memset(&g_spy, 0, sizeof(g_spy));
	if (!wrl_gcm_aesni_available() || wrl_gcm_aesni_ops(&g_spy.hook) != 0)
		return -1;
	g_spy.tab.size = (uint32_t)sizeof(g_spy.tab);
	g_spy.tab.ctx = &g_spy;
	g_spy.tab.gcm_state_bytes = g_spy.hook.gcm_state_bytes;
	g_spy.tab.gcm_setkey = spy_setkey;
	g_spy.tab.gcm_start = spy_start;
	g_spy.tab.gcm_update = spy_update;
	g_spy.tab.gcm_final_enc = spy_final_enc;
	g_spy.tab.gcm_final_dec = spy_final_dec;
	g_spy.tab.gcm_wipe = spy_wipe;
	return 0;
}

/* ---- the TCP servers --------------------------------------------------------------------------------- */

#define MAXSRV 8u  /* the monitor and up to 7 OSDs */
#define SMAX 16u   /* connections one server holds */
#define OUTCAP (512u * 1024u)

enum { CUT_NONE = 0, CUT_MID = 1, CUT_DROP = 2 };

typedef struct sconn {
	int fd;
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
	size_t wr_chunk, rd_chunk; /* 0 = no limit; set under the mutex */
	int cut, cut_rst;
	uint32_t cut_base;
	unsigned n_accept, n_cut;
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

static srv *S_MON(void) { return &G.s[0]; }
static srv *S_OSD(unsigned i) { return &G.s[1u + i]; }

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
		c->sc = s->is_mon ? (void *)sim_mon_accept(G.mon) : (void *)sim_osd_accept(s->osd);
		c->out = (uint8_t *)malloc(OUTCAP);
		if (c->out == NULL)
			abort();
		if (c->sc == NULL)
			sconn_drop(s, c, 0);
	}
}

static void s_conn(srv *s, sconn *c, short rev)
{
	uint8_t buf[4096];

	if (rev & (POLLIN | POLLHUP | POLLERR)) {
		size_t want = s->rd_chunk != 0 ? s->rd_chunk : sizeof(buf);
		ssize_t n = recv(c->fd, buf, want < sizeof(buf) ? want : sizeof(buf), 0);

		if (n > 0) {
			(void)sc_feed(s, c, buf, (size_t)n);
		} else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
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
		if (c->out_len - c->out_off >= 2u) { /* half of the (secure) reply goes out, then the connection ends */
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
		pf[0].fd = s->lfd;
		pf[0].events = POLLIN;
		pf[0].revents = 0;
		for (i = 0; i < SMAX; i++) {
			if (s->c[i].fd < 0)
				continue;
			pf[n].fd = s->c[i].fd;
			pf[n].events = (short)(POLLIN | (s->c[i].out_len > s->c[i].out_off ? POLLOUT : 0));
			pf[n].revents = 0;
			idx[n - 1u] = (int)i;
			n++;
		}
		s_unlock();
		(void)poll(pf, n, 4);
		s_lock();
		if (pf[0].revents & POLLIN)
			s_accept(s);
		for (i = 1; i < n; i++) {
			sconn *c = &s->c[idx[i - 1u]];

			if (c->fd >= 0 && c->fd == pf[i].fd)
				s_conn(s, c, pf[i].revents);
		}
		/* the simulator may have output (a push, a released message) or a close with no socket event */
		for (i = 0; i < SMAX; i++)
			if (s->c[i].fd >= 0)
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
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, backlog) != 0 || getsockname(fd, (struct sockaddr *)&sa, &sl) != 0)
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
	unsigned mon_allow, osd_allow; /* SC_ALLOW_* of the simulated servers (0 = crc and secure) */
	uint8_t policy, policy_osd;    /* the client's mode_policy / mode_policy_osd (0 policy = secure only) */
	int accel;                     /* the client gets the AES-NI hook (through the counting table) */
	uint32_t done_mode_mon, done_mode_osd; /* sim_m2_fault.done_mode of the servers: the mode AUTH_DONE claims (0 = the negotiated one) */
} wopts;

#define IMG_NAME "hs-img"
#define IMG_ID "hsid1"

static void world_start(const wopts *o)
{
	sim_mon_cfg mcf;
	wrt_mg_cluster_spec cs;
	wrt_mg_buf b;
	sim_rbd_image_cfg ic;
	unsigned i, mon_allow = o->mon_allow != 0u ? o->mon_allow : SC_ALLOW_CRC | SC_ALLOW_SECURE;
	unsigned osd_allow = o->osd_allow != 0u ? o->osd_allow : SC_ALLOW_CRC | SC_ALLOW_SECURE;

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
	sc_allow(&mcf.m2, mon_allow);
	mcf.m2.f.done_mode = o->done_mode_mon;
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
		sc_allow(&oc.m2, osd_allow);
		oc.m2.f.done_mode = o->done_mode_osd;
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

/* The secrets the servers issued: how many (monitor, all OSDs), and whether every one differs from every other one. */
static unsigned secrets_mon(void)
{
	unsigned n;

	s_lock();
	n = sim_mon_secrets(G.mon)->n;
	s_unlock();
	return n;
}

static unsigned secrets_osd(void)
{
	unsigned i, n = 0;

	s_lock();
	for (i = 0; i < G.n_osd; i++)
		n += sim_osd_secrets(S_OSD(i)->osd)->n;
	s_unlock();
	return n;
}

static int secrets_distinct(void)
{
	const sim_sec_log *logs[MAXSRV];
	unsigned n = 0, i, j, a, b;
	int ok = 1;

	s_lock();
	logs[n++] = sim_mon_secrets(G.mon);
	for (i = 0; i < G.n_osd; i++)
		logs[n++] = sim_osd_secrets(S_OSD(i)->osd);
	for (i = 0; i < n && ok; i++) {
		if (logs[i]->kept != logs[i]->n || !sim_sec_log_distinct(logs[i]))
			ok = 0;
		for (j = i + 1u; j < n && ok; j++)
			for (a = 0; a < logs[i]->kept && ok; a++)
				for (b = 0; b < logs[j]->kept && ok; b++)
					if (logs[i]->len[a] == logs[j]->len[b] && memcmp(logs[i]->secret[a], logs[j]->secret[b], logs[i]->len[a]) == 0)
						ok = 0;
	}
	s_unlock();
	return ok;
}

/* How many whole secrets (any server, any connection ever made) are in the engine's memory right now. */
static unsigned secrets_in_engine(const wr_mem_region *arena, const wr_mem_region *bulk)
{
	const sim_sec_log *logs[MAXSRV];
	unsigned n = 0, i, a, hits = 0;

	s_lock();
	logs[n++] = sim_mon_secrets(G.mon);
	for (i = 0; i < G.n_osd; i++)
		logs[n++] = sim_osd_secrets(S_OSD(i)->osd);
	for (i = 0; i < n; i++)
		for (a = 0; a < logs[i]->kept; a++)
			hits += sc_occurs((const uint8_t *)arena->base, arena->size, logs[i]->secret[a], logs[i]->len[a]) +
				sc_occurs((const uint8_t *)bulk->base, bulk->size, logs[i]->secret[a], logs[i]->len[a]);
	s_unlock();
	return hits;
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
	unsigned n_ev_kind[16];
	unsigned seq;
	wr_errinfo last_auth_err; /* the errinfo of the last AUTH_FAILED event */
	wr_status last_ev_status; /* the status of the last event that carried one (WR_OK: none yet) */
} R;

typedef struct job {
	wr_io_req r;
	uint8_t *buf;
	int done;
	wr_status st;
	unsigned seq;
} job;
#define MAXJOB 400u
static job J[MAXJOB];
static unsigned nJ;

static uint8_t *M; /* the flat model of the image */
static uint64_t Msize;

static void jobs_reset(void)
{
	unsigned i;

	for (i = 0; i < nJ; i++)
		free(J[i].buf);
	memset(J, 0, sizeof(J));
	nJ = 0;
}

static void collect(void)
{
	wr_event e;
	wr_io_req *r;

	while (wr_client_next_event(R.c, &e)) {
		if ((unsigned)e.kind < 16u)
			R.n_ev_kind[e.kind]++;
		if (e.kind == WR_EV_AUTH_FAILED)
			R.last_auth_err = e.err;
		if (e.err.status != WR_OK)
			R.last_ev_status = e.err.status;
	}
	while ((r = wr_client_next_done(R.c)) != NULL) {
		job *j = (job *)r->user;

		j->done = 1;
		j->st = r->status;
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

/* Run the pump until f(a) holds or ms passed. When the time is up, one more step without a wait runs first, as the next step of a host would. */
static wr_status pump(int (*f)(void *), void *a, int ms)
{
	pw w;
	wr_status st;

	w.f = f;
	w.a = a;
	st = wrl_loop_run(R.l, stop_wrap, &w, ms);
	if (st == WR_E_TIMEOUT && f != NULL) {
		st = wrl_loop_step(R.l, 0);
		collect();
		st = st != WR_OK ? st : f(a) ? WR_OK : WR_E_TIMEOUT;
	}
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
			memcpy(M + off, j->buf, (size_t)len);
		} else {
			memset(j->buf, 0xEE, (size_t)len);
		}
	} else if (kind == WR_IO_DISCARD || kind == WR_IO_WRITE_ZEROES) {
		memset(M + off, 0, (size_t)len); /* both read back as zeros */
	}
	return j;
}

/* Submit and run the engine once without waiting (the rule of design 28.2: a submit cannot wake the host, the next run encodes and queues the messages). */
static wr_status job_submit(job *j)
{
	wr_status st = wr_image_submit(R.img, &j->r);

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
	cfg->osd_connect_timeout_ms = 400; /* also the base of the engine's wait before it dials an OSD again */
	cfg->hunt_backoff_min_ms = 50;
	cfg->hunt_backoff_max_ms = 400;
}

static void client_start(const wopts *o)
{
	wr_mem_req req;

	memset(&R, 0, sizeof(R));
	g_nfds = 0;
	g_connects = 0;
	cfg_default(&R.cfg);
	wr_config_enable_secure(&R.cfg, WR_MAPS_HARNESS, o->policy != 0u ? o->policy : WR_MODE_SECURE_ONLY);
	R.cfg.mode_policy_osd = o->policy_osd;
	R.level = getenv("WRL_TEST_LOG") != NULL ? (unsigned)atoi(getenv("WRL_TEST_LOG")) : WR_LOG_ERR;
	wrl_host_ops_init(&R.ops, &R.level);
	if (o->accel) {
		WRT_CHECK_U64(spy_init(), 0);
		R.ops.prim = &g_spy.tab;
	}
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
	M = (uint8_t *)calloc(1, (size_t)Msize);
	if (M == NULL)
		abort();
}

/* The pump goes first (the engine may still be alive: it is destroyed after, as a host does); every descriptor it opened is closed. */
static void client_stop(void)
{
	wrl_loop_destroy(R.l);
	R.l = NULL;
	WRT_CHECK_U64(g_nfds, 0);
	wr_client_destroy(R.c);
	if (R.ops.prim == &g_spy.tab) /* every key object the hook was given was wiped again by the time the engine is gone (a key never outlives its connection) */
		WRT_CHECK_U64(g_spy.wipes >= g_spy.setkeys, 1);
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

static wr_stats cstats(void)
{
	wr_stats ws;

	memset(&ws, 0, sizeof(ws));
	wr_client_get_stats(R.c, &ws);
	return ws;
}

/* A little traffic that touches every OSD: 6 writes spread over the image, a flush, and the whole image read back. */
static void small_traffic(unsigned seed)
{
	unsigned first = nJ, i, nw = 6;
	uint64_t reg = Msize / nw;
	jr r;

	for (i = 0; i < nw; i++) {
		uint64_t start = (uint64_t)i * reg, off = start + rnd() % (reg / 2u), room = reg - (off - start);
		uint64_t len = 1u + rnd() % (room < 100000u ? room : 100000u);

		(void)job_add(WR_IO_WRITE, off, len, seed + i);
	}
	(void)job_add(WR_IO_FLUSH, 0, 0, 0);
	r = jobs_submit_range(first, nw + 1u);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
	for (i = 0; i <= nw; i++)
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
	check_image(300000u + seed);
}

/* ---- tests --------------------------------------------------------------------------------------------- */

#define IMG_SMALL (1u << 20)

static wopts base_opts(unsigned key_type)
{
	wopts o;

	memset(&o, 0, sizeof(o));
	o.n_osd = 3;
	o.key_type = key_type;
	o.pg_num = 32;
	o.img_size = IMG_SMALL;
	o.order = 16;
	o.mon_allow = o.osd_allow = SC_ALLOW_SECURE;
	o.policy = WR_MODE_SECURE_ONLY;
	return o;
}

/* Everything secure: the counters, the secrets, the memory, and the hook when it was installed. */
static void check_all_secure(const wopts *o)
{
	wr_stats ws = cstats();
	unsigned issued = secrets_mon() + secrets_osd();

	WRT_CHECK(ws.conns_secure >= 3u); /* the monitor and at least two OSD sessions */
	WRT_CHECK_U64(ws.conns_crc, 0);
	WRT_CHECK_U64(ws.sec_failures, 0);
	WRT_CHECK(issued >= ws.conns_secure);
	WRT_CHECK(secrets_distinct());
	WRT_CHECK_U64(secrets_in_engine(&R.arena, &R.bulk), 0); /* a secret is turned into key schedules and nonces: it exists nowhere whole */
	if (o->accel) {
		WRT_CHECK(g_spy.setkeys >= 2u * ws.conns_secure); /* two directions, one key object each */
		WRT_CHECK(g_spy.updates > 0u && g_spy.finals > 0u);
	}
}

/* Image I/O with the model and the store as oracles. */
static void test_image_io(unsigned key_type, int accel)
{
	wopts o = base_opts(key_type);
	unsigned round, i;
	wr_osd_stats st;

	o.accel = accel;
	if (accel && spy_init() != 0) {
		fprintf(stderr, "note: no AES-NI / PCLMULQDQ here: the accelerated pass is skipped\n");
		return;
	}
	world_start(&o);
	client_start(&o);
	WRT_CHECK(open_image() == 0);
	if (R.img == NULL || wr_image_get_state(R.img) != WR_IMG_OPEN)
		goto out;
	for (round = 0; round < 2; round++) {
		unsigned first = nJ, nw = 12, fl;
		uint64_t reg = Msize / nw;
		jr r;
		unsigned max_seq = 0;

		for (i = 0; i < nw; i++) { /* 12 writes in flight, one in each region of the image, so they never overlap */
			uint64_t start = (uint64_t)i * reg, off = start + rnd() % (reg / 2u), room = reg - (off - start);
			uint64_t len = 1u + rnd() % (room < 60000u ? room : 60000u);

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

		(void)job_add(WR_IO_DISCARD, 100005u, 200000u, 0);
		(void)job_add(WR_IO_WRITE_ZEROES, 600077u, 123457u, 0);
		(void)job_add(WR_IO_DISCARD, 12u << 16, 3u << 16, 0); /* whole objects */
		r = jobs_submit_range(first, 3);
		WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 60000));
		for (i = 0; i < 3; i++)
			WRT_CHECK_STATUS(WR_OK, J[first + i].st);
		check_image(1u << 18);
	}
	check_store();
	wr_client_osd_stats(R.c, &st);
	WRT_CHECK(st.sessions_hiwater >= 2u);
	WRT_CHECK(st.ops_done > 20u);
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
	check_all_secure(&o);
	world_check_sane();
	fprintf(stderr, "  (image io, key type %u, hook %s: %u secure connections, %u secrets)\n", key_type, accel ? "on" : "off",
		cstats().conns_secure, secrets_mon() + secrets_osd());
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

/* Every server writes and reads one byte at a time: the secure frames (96-byte first parts, tags, 16-byte blocks) are cut at every byte. */
static void test_slow_server(int accel)
{
	wopts o = base_opts(WR_KEY_TYPE_AES256K);
	unsigned first, i;
	jr r;
	uint64_t t0;

	o.accel = accel;
	if (accel && spy_init() != 0) {
		fprintf(stderr, "note: no AES-NI / PCLMULQDQ here: the accelerated pass is skipped\n");
		return;
	}
	o.img_size = 1u << 20;
	world_start(&o);
	s_lock();
	set_slow();
	s_unlock();
	client_start(&o);
	t0 = now_ms();
	if (open_image() != 0)
		goto out;
	first = nJ;
	(void)job_add(WR_IO_WRITE, 60u * 1024u, 20u * 1024u, 5); /* crosses the first object boundary */
	(void)job_add(WR_IO_WRITE, 300u * 1024u + 3u, 17u * 1024u, 6);
	(void)job_add(WR_IO_WRITE, 700u * 1024u, 9000u, 7);
	(void)job_add(WR_IO_FLUSH, 0, 0, 0);
	r = jobs_submit_range(first, 4);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 90000));
	for (i = 0; i < 4; i++)
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
	first = nJ;
	(void)job_add(WR_IO_READ, 50u * 1024u, 40u * 1024u, 0);
	(void)job_add(WR_IO_READ, 296u * 1024u, 30u * 1024u, 0);
	(void)job_add(WR_IO_READ, 699u * 1024u, 12000u, 0);
	r = jobs_submit_range(first, 3);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 90000));
	for (i = 0; i < 3; i++) {
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
		WRT_CHECK(memcmp(J[first + i].buf, M + J[first + i].r.offset, (size_t)J[first + i].r.length) == 0);
	}
	check_store();
	check_all_secure(&o);
	fprintf(stderr, "  (slow server, hook %s: %llu ms for open + 3 writes + 3 reads at one byte per call)\n", accel ? "on" : "off",
		(unsigned long long)(now_ms() - t0));
	world_check_sane();
out:
	client_stop();
	world_stop();
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

static void cut_round(int mode, int rst, int write, uint32_t seed)
{
	unsigned first = nJ, cuts0 = sum_cuts(), dup0 = sum_dup_recs(), conns0 = cstats().conns_secure, sec0 = secrets_osd(), i;
	wr_osd_stats st0, st1;
	jr r;
	job *j;

	wr_client_osd_stats(R.c, &st0);
	arm_cuts(mode, rst);
	/* three objects of 64 KiB: 100 KiB .. 292 KiB */
	j = job_add(write ? WR_IO_WRITE : WR_IO_READ, 100u * 1024u, 192u * 1024u, seed);
	WRT_CHECK(j != NULL);
	r = jobs_submit_range(first, 1);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 90000));
	WRT_CHECK_STATUS(WR_OK, J[first].st);
	if (!write)
		WRT_CHECK(memcmp(J[first].buf, M + J[first].r.offset, (size_t)J[first].r.length) == 0);
	WRT_CHECK(sum_cuts() > cuts0);                 /* the plan fired */
	wr_client_osd_stats(R.c, &st1);
	WRT_CHECK(st1.ops_resent > st0.ops_resent);    /* the engine dialled again and resent what had no answer */
	WRT_CHECK(cstats().conns_secure > conns0);     /* the new connection is a secure one ... */
	WRT_CHECK(secrets_osd() > sec0);               /* ... with a secret of its own (rekeying is reconnecting) */
	WRT_CHECK(secrets_distinct());
	if (mode == CUT_DROP)
		WRT_CHECK(sum_dup_recs() > dup0);      /* the OSD recognised the resent write */
	/* a second read after the dust settled: the engine works on the new sessions */
	first = nJ;
	for (i = 0; i < 4; i++)
		(void)job_add(WR_IO_READ, (uint64_t)i * 70000u, 65536u, 0);
	r = jobs_submit_range(first, 4);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 90000));
	for (i = 0; i < 4; i++) {
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
		WRT_CHECK(memcmp(J[first + i].buf, M + J[first + i].r.offset, (size_t)J[first + i].r.length) == 0);
	}
}

/* A server that cuts in the middle of a secure reply (FIN and RST), and one that executes a write and cuts without answering. */
static void test_server_cuts(void)
{
	wopts o = base_opts(WR_KEY_TYPE_AES256K);
	unsigned first, i;
	jr r;
	wr_stats ws;

	o.n_osd = 4;
	o.img_size = 512u << 10;
	world_start(&o);
	client_start(&o);
	if (open_image() != 0)
		goto out;
	first = nJ; /* content to read: the whole image in 128 KiB writes */
	for (i = 0; i < 4; i++)
		(void)job_add(WR_IO_WRITE, (uint64_t)i << 17, 1u << 17, 40u + i);
	r = jobs_submit_range(first, 4);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 90000));
	for (i = 0; i < 4; i++)
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);

	cut_round(CUT_MID, 0, 0, 0);   /* orderly close after half of a reply */
	cut_round(CUT_MID, 1, 0, 0);   /* reset after half of a reply */
	cut_round(CUT_DROP, 0, 1, 90); /* the write is executed, the answer lost, the connection closed */
	cut_round(CUT_DROP, 1, 1, 91); /* the same with a reset */
	check_image(1u << 17);
	check_store();
	world_check_sane();
	ws = cstats();
	WRT_CHECK_U64(ws.conns_crc, 0);
	WRT_CHECK_U64(ws.sec_failures, 0); /* a close or a reset is not a tag failure: nothing was forged */
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
	WRT_CHECK_U64(secrets_in_engine(&R.arena, &R.bulk), 0);
out:
	client_stop();
	world_stop();
}

/* The next secure frame of every live, secure OSD connection is damaged: kind 0 flips one bit of part 1's ciphertext (the tag no longer matches), kind 1
 * cuts the frame after 50 bytes and closes the connection. Returns the number of connections armed. */
static unsigned arm_frame_fault(int kind)
{
	unsigned i, k, n = 0;

	s_lock();
	for (i = 0; i < G.n_osd; i++) {
		for (k = 0; k < SMAX; k++) {
			sconn *c = &S_OSD(i)->c[k];
			sim_m2 *m;

			if (c->fd < 0 || c->sc == NULL)
				continue;
			m = ((sim_osd_conn *)c->sc)->m2;
			if (!sim_m2_is_secure(m))
				continue;
			memset(&m->cfg.f.sec, 0, sizeof(m->cfg.f.sec));
			m->cfg.f.sec.mut_frame = m->n_tx_frames + 1u;
			if (kind == 0) {
				m->cfg.f.sec.mut.mask = SIM_SEC_M_FLIP;
				m->cfg.f.sec.mut.flip_part = 1;
				m->cfg.f.sec.mut.flip_region = SIM_SEC_R_RAW;
				m->cfg.f.sec.mut.flip_byte = 3;
				m->cfg.f.sec.mut.flip_bit = 0;
			} else {
				m->cfg.f.sec.mut.mask = SIM_SEC_M_TRUNC;
				m->cfg.f.sec.mut.truncate_at = 50;
				m->cfg.f.sec.mut_close = 1;
			}
			n++;
		}
	}
	s_unlock();
	return n;
}

static void hostile_round(int kind)
{
	unsigned first = nJ, i, armed, conns0 = cstats().conns_secure;
	uint32_t fail0 = cstats().sec_failures;
	jr r;

	/* every object of the image is read, so every OSD session has a reply to send */
	armed = arm_frame_fault(kind);
	WRT_CHECK(armed >= 1u); /* at least one live secure OSD session: the reads below touch every object, so every primary has a reply to send */
	for (i = 0; i < 4; i++)
		(void)job_add(WR_IO_READ, (uint64_t)i << 17, 1u << 17, 0);
	r = jobs_submit_range(first, 4);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 90000));
	for (i = 0; i < 4; i++) {
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
		WRT_CHECK(memcmp(J[first + i].buf, M + J[first + i].r.offset, (size_t)J[first + i].r.length) == 0);
	}
	if (kind == 0)
		WRT_CHECK(cstats().sec_failures > fail0); /* a damaged tag is a secure-mode failure and is counted */
	else
		WRT_CHECK_U64(cstats().sec_failures, fail0); /* an end in the middle of part 1 forged nothing */
	WRT_CHECK(cstats().conns_secure > conns0);     /* the engine dialled again: new secure connections */
}

static void test_hostile_frames(int accel)
{
	wopts o = base_opts(WR_KEY_TYPE_AES);
	unsigned first, i;
	jr r;

	o.accel = accel;
	if (accel && spy_init() != 0) {
		fprintf(stderr, "note: no AES-NI / PCLMULQDQ here: the accelerated pass is skipped\n");
		return;
	}
	o.n_osd = 3;
	o.img_size = 512u << 10;
	world_start(&o);
	client_start(&o);
	if (open_image() != 0)
		goto out;
	first = nJ;
	for (i = 0; i < 4; i++)
		(void)job_add(WR_IO_WRITE, (uint64_t)i << 17, 1u << 17, 60u + i);
	r = jobs_submit_range(first, 4);
	WRT_CHECK_STATUS(WR_OK, pump(jr_done, &r, 90000));
	for (i = 0; i < 4; i++)
		WRT_CHECK_STATUS(WR_OK, J[first + i].st);
	idle(100); /* the sessions are idle and live */
	hostile_round(0);
	idle(100);
	hostile_round(1);
	idle(100);
	hostile_round(0);
	check_image(1u << 17);
	check_store();
	WRT_CHECK_U64(cstats().conns_crc, 0);
	WRT_CHECK(secrets_distinct());
	WRT_CHECK_U64(secrets_in_engine(&R.arena, &R.bulk), 0);
	world_check_sane();
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
out:
	client_stop();
	world_stop();
}

/* ---- policies and refusals ---------------------------------------------------------------------------------- */

static const char *mode_name(unsigned m)
{
	return m == WRI_CONN_MODE_SECURE ? "secure" : m == WRI_CONN_MODE_CRC ? "crc" : "refused";
}

/* One policy against servers with given lists: the mode each role must end in is what sc_expect_mode says (the first of OUR modes the server allows). */
static void policy_case(uint8_t policy, uint8_t policy_osd, unsigned mon_allow, unsigned osd_allow)
{
	wopts o = base_opts(WR_KEY_TYPE_AES256K);
	unsigned mon_mode = sc_expect_mode(policy, policy_osd, WRI_ENTITY_MON, mon_allow);
	unsigned osd_mode = sc_expect_mode(policy, policy_osd, WRI_ENTITY_OSD, osd_allow);
	wr_stats ws;

	WRT_CHECK(mon_mode != 0u && osd_mode != 0u); /* every case here has an answer */
	o.policy = policy;
	o.policy_osd = policy_osd;
	o.mon_allow = mon_allow;
	o.osd_allow = osd_allow;
	o.img_size = 1u << 20;
	world_start(&o);
	client_start(&o);
	if (open_image() != 0)
		goto out;
	small_traffic(9);
	check_store();
	ws = cstats();
	/* the servers say the same thing: a server issues a secret only for a connection it negotiated secure */
	if (mon_mode == WRI_CONN_MODE_SECURE)
		WRT_CHECK(secrets_mon() >= 1u);
	else
		WRT_CHECK_U64(secrets_mon(), 0);
	if (osd_mode == WRI_CONN_MODE_SECURE)
		WRT_CHECK(secrets_osd() >= 2u);
	else
		WRT_CHECK_U64(secrets_osd(), 0);
	if (mon_mode == WRI_CONN_MODE_SECURE && osd_mode == WRI_CONN_MODE_SECURE) {
		WRT_CHECK(ws.conns_secure >= 3u);
		WRT_CHECK_U64(ws.conns_crc, 0);
	} else if (mon_mode == WRI_CONN_MODE_CRC && osd_mode == WRI_CONN_MODE_CRC) {
		WRT_CHECK_U64(ws.conns_secure, 0);
		WRT_CHECK(ws.conns_crc >= 3u);
	} else if (mon_mode == WRI_CONN_MODE_SECURE) { /* the monitor secure, the OSDs crc */
		WRT_CHECK(ws.conns_secure >= 1u && ws.conns_secure <= secrets_mon()); /* every secure connection was given a secret by the monitor */
		WRT_CHECK(ws.conns_crc >= 2u);
	} else {                                       /* the monitor crc, the OSDs secure */
		WRT_CHECK(ws.conns_secure >= 2u);
		WRT_CHECK(ws.conns_crc >= 1u);
	}
	WRT_CHECK_U64(ws.sec_failures, 0);
	WRT_CHECK(secrets_distinct());
	WRT_CHECK_U64(secrets_in_engine(&R.arena, &R.bulk), 0);
	world_check_sane();
	fprintf(stderr, "  (policy %u/%u, servers %u/%u: monitor %s, OSDs %s: %u secure, %u crc connections)\n", (unsigned)policy, (unsigned)policy_osd,
		mon_allow, osd_allow, mode_name(mon_mode), mode_name(osd_mode), ws.conns_secure, ws.conns_crc);
out:
	client_stop();
	world_stop();
}

static void test_policies(void)
{
	const unsigned both = SC_ALLOW_CRC | SC_ALLOW_SECURE;

	policy_case(WR_MODE_STOCK, 0, both, both);                           /* the stock client: secure to the monitor, crc to the OSDs */
	policy_case(WR_MODE_SECURE_ONLY, WR_MODE_CRC_ONLY, both, both);      /* a per-role override: the OSDs get crc */
	policy_case(WR_MODE_CRC_ONLY, WR_MODE_SECURE_ONLY, both, both);      /* and the other way round */
	policy_case(WR_MODE_SECURE_FIRST, 0, SC_ALLOW_CRC, SC_ALLOW_CRC);    /* secure preferred, crc servers: crc */
	policy_case(WR_MODE_CRC_FIRST, 0, both, both);                       /* crc preferred, both allowed: crc */
	policy_case(WR_MODE_CRC_FIRST, 0, SC_ALLOW_SECURE, SC_ALLOW_SECURE); /* crc preferred, secure-only servers: secure */
}

static int mon_failed_seen(void *a)
{
	(void)a;
	return R.n_ev_kind[WR_EV_AUTH_FAILED] >= 1u || R.last_ev_status != WR_OK;
}

static int auth_failed_seen(void *a)
{
	(void)a;
	return R.n_ev_kind[WR_EV_AUTH_FAILED] >= 1u;
}

/* A server that allows none of the offered modes refuses the authentication: M2_BAD_METHOD with its allowed-modes mask, no connection is counted, and the
 * engine's retries are paced (it hunts with a back-off, it does not spin). */
static void refusal_case(uint8_t policy, unsigned mon_allow)
{
	wopts o = base_opts(WR_KEY_TYPE_AES256K);
	unsigned conns0;
	wr_stats ws;

	o.policy = policy;
	o.mon_allow = mon_allow;
	o.img_size = 1u << 20;
	world_start(&o);
	client_start(&o);
	WRT_CHECK_STATUS(WR_OK, pump(auth_failed_seen, NULL, 60000)); /* the refusal itself: no clock assumption on how soon it comes */
	idle(500);                                                    /* then a while longer, to see that nothing else happens */
	WRT_CHECK(R.n_ev_kind[WR_EV_AUTH_FAILED] >= 1u);
	WRT_CHECK_U64(R.last_auth_err.status, WR_E_M2_BAD_METHOD);
	WRT_CHECK_U64(R.last_auth_err.a1, sc_mode_mask(mon_allow)); /* what the server allows, as it said */
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_MON_SESSION_UP], 0);
	ws = cstats();
	WRT_CHECK_U64(ws.conns_secure, 0);
	WRT_CHECK_U64(ws.conns_crc, 0);
	WRT_CHECK_U64(secrets_mon(), 0); /* nothing was negotiated: no secret was issued */
	conns0 = g_connects;
	WRT_CHECK(conns0 >= 1u && conns0 <= 40u); /* paced: a 50..400 ms back-off makes a handful of dials in this time, not a storm (a slow machine dials less) */
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
	client_stop();
	world_stop();
}

static void test_refusals(void)
{
	refusal_case(WR_MODE_SECURE_ONLY, SC_ALLOW_CRC);  /* we insist on secure, the monitor allows crc only: allowed modes {crc} */
	refusal_case(WR_MODE_CRC_ONLY, SC_ALLOW_SECURE);  /* the default policy against a secure-only monitor: allowed modes {secure} */
}

/* ---- a server that lies about the mode (a downgrade) --------------------------------------------------------------- */

/* The monitor's AUTH_DONE names a mode the engine must not accept: crc for a secure-only offer (the plain downgrade; a secret was issued, but the server says
 * crc), crc for [secure, crc] with a secret in the payload (a server that sends a key it will not use), secure for a crc-only offer. The connection must fail
 * with the status of the rule, nothing may be counted as connected, and nothing may run in the mode the client did not ask for: an attacker that rewrites
 * the mode must never get a crc session out of a client that required secure. */
static void downgrade_mon_case(uint8_t policy, unsigned mon_allow, uint32_t done_mode, wr_status want)
{
	wopts o = base_opts(WR_KEY_TYPE_AES256K);
	wr_stats ws;

	o.policy = policy;
	o.mon_allow = mon_allow;
	o.done_mode_mon = done_mode;
	o.img_size = 1u << 20;
	world_start(&o);
	client_start(&o);
	WRT_CHECK_STATUS(WR_OK, pump(mon_failed_seen, NULL, 60000));
	idle(300);
	WRT_CHECK_U64(R.last_ev_status, want);
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_MON_SESSION_UP], 0);
	ws = cstats();
	WRT_CHECK_U64(ws.conns_secure, 0);
	WRT_CHECK_U64(ws.conns_crc, 0); /* no crc session came out of a client that wanted something else */
	WRT_CHECK_U64(R.n_ev_kind[WR_EV_FATAL], 0);
	WRT_CHECK_U64(secrets_in_engine(&R.arena, &R.bulk), 0); /* the refused connection's secret was wiped too */
	client_stop();
	world_stop();
}

/* The OSDs lie (AUTH_DONE says crc to a client that offers secure only): the monitor session is fine, but no OSD session may come up, so the image cannot
 * open, no request reaches an OSD, and the engine keeps trying. */
static int osd_redials_seen(void *a)
{
	unsigned i, n = 0;

	(void)a;
	s_lock();
	for (i = 0; i < G.n_osd; i++)
		n += S_OSD(i)->n_accept;
	s_unlock();
	return n >= 4u; /* more attempts than OSDs: it keeps trying */
}

static void downgrade_osd_case(void)
{
	wopts o = base_opts(WR_KEY_TYPE_AES256K);
	wr_image_params p;
	unsigned i, reqs = 0;
	wr_stats ws;

	o.done_mode_osd = 1;
	o.img_size = 1u << 20;
	world_start(&o);
	client_start(&o);
	p = cw_params(IMG_NAME, 1);
	R.img = NULL;
	WRT_CHECK_STATUS(WR_OK, wr_image_open(R.c, &p, &R.img));
	WRT_CHECK_STATUS(WR_OK, wrl_loop_step(R.l, 0));
	WRT_CHECK_STATUS(WR_OK, pump(osd_redials_seen, NULL, 60000));
	WRT_CHECK(wr_image_get_state(R.img) != WR_IMG_OPEN);
	ws = cstats();
	WRT_CHECK_U64(ws.conns_crc, 0);
	WRT_CHECK_U64(R.last_ev_status == WR_OK ? 0u : (unsigned)(R.last_ev_status == WR_E_M2_MODE), 1); /* the rule that refused them */
	s_lock();
	for (i = 0; i < G.n_osd; i++)
		reqs += sim_osd_n_requests(S_OSD(i)->osd);
	s_unlock();
	WRT_CHECK_U64(reqs, 0); /* not one operation went out in a mode nobody asked for */
	client_stop();
	world_stop();
}

static void test_downgrade(void)
{
	downgrade_mon_case(WR_MODE_SECURE_ONLY, SC_ALLOW_SECURE, 1, WR_E_M2_MODE);              /* [secure] offered, the answer says crc */
	downgrade_mon_case(WR_MODE_SECURE_FIRST, SC_ALLOW_SECURE, 1, WR_E_AUTH_PROTO);          /* crc was offered too, but the payload carries a secret */
	downgrade_mon_case(WR_MODE_CRC_ONLY, SC_ALLOW_CRC, 2, WR_E_M2_MODE);                    /* [crc] offered, the answer says secure */
	downgrade_osd_case();
}

/* ---- wr-monprobe ----------------------------------------------------------------------------------------- */

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

/* A keyring file for the key mt_key(type, salt) builds; b64_out gets the key text (to check it never shows up in output). */
static void write_keyring(const char *path, unsigned type, uint8_t salt, char *b64_out)
{
	uint8_t blob[2 + 8 + 2 + 32];
	size_t len = type == WR_KEY_TYPE_AES ? 16u : 32u, i, o = 0;
	FILE *f;

	memset(blob, 0, sizeof(blob));
	blob[0] = (uint8_t)type;
	blob[10] = (uint8_t)len;
	for (i = 0; i < len; i++)
		blob[12 + i] = (uint8_t)(salt + i * 7u);
	b64_put(b64_out, &o, blob, 12u + len);
	b64_out[o] = '\0';
	f = fopen(path, "w");
	if (f == NULL)
		abort();
	(void)chmod(path, 0600);
	fprintf(f, "[client.winrbd]\n\tkey = %s\n", b64_out);
	fclose(f);
}

/* Run exe with args (a NULL terminated list); out gets stdout + stderr. The exit status, -1 if it did not exit normally. */
static int run_child(const char *exe, char *const *args, char *out, size_t cap, unsigned secs)
{
	int pfd[2], status = 0;
	size_t n = 0;
	pid_t pid;
	uint64_t t_end = now_ms() + secs * 1000u;

	if (pipe(pfd) != 0)
		abort();
	pid = fork();
	if (pid < 0)
		abort();
	if (pid == 0) {
		int dn = open("/dev/null", O_RDONLY);

		(void)dup2(dn, 0);
		(void)dup2(pfd[1], 1);
		(void)dup2(pfd[1], 2);
		close(pfd[0]);
		close(pfd[1]);
		execv(exe, args);
		_exit(127);
	}
	close(pfd[1]);
	(void)fcntl(pfd[0], F_SETFL, fcntl(pfd[0], F_GETFL, 0) | O_NONBLOCK);
	for (;;) {
		struct pollfd pf;
		ssize_t r;
		char junk[256];

		pf.fd = pfd[0];
		pf.events = POLLIN;
		pf.revents = 0;
		if (now_ms() > t_end) {
			fprintf(stderr, "tool did not finish in %u s: killed\n", secs);
			kill(pid, SIGKILL);
			break;
		}
		if (poll(&pf, 1, 200) <= 0)
			continue;
		if (n + 1u >= cap)
			r = read(pfd[0], junk, sizeof(junk));
		else {
			r = read(pfd[0], out + n, cap - 1u - n);
			if (r > 0)
				n += (size_t)r;
		}
		if (r < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (r <= 0)
			break;
	}
	out[n] = '\0';
	close(pfd[0]);
	(void)waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* wr-monprobe against the monitor of the world with the given extra options (a space separated list). */
static int probe(const char *exe, const char *kr, const char *extra, char *out, size_t cap)
{
	char mon[64], copy[512];
	char *args[40];
	unsigned n = 0;
	char *tok;

	snprintf(mon, sizeof(mon), "127.0.0.1:%u", (unsigned)S_MON()->port);
	args[n++] = (char *)"wr-monprobe";
	args[n++] = (char *)"--mon";
	args[n++] = mon;
	args[n++] = (char *)"--user";
	args[n++] = (char *)"winrbd";
	args[n++] = (char *)"--keyring";
	args[n++] = (char *)kr;
	args[n++] = (char *)"--timeout";
	args[n++] = (char *)"4000";
	snprintf(copy, sizeof(copy), "%s", extra);
	for (tok = strtok(copy, " "); tok != NULL && n + 1u < 40u; tok = strtok(NULL, " "))
		args[n++] = tok;
	args[n] = NULL;
	return run_child(exe, args, out, cap, 60);
}

static unsigned long long field_u(const char *out, const char *key)
{
	const char *p = strstr(out, key);

	return p == NULL ? ~0ull : strtoull(p + strlen(key), NULL, 10);
}

static int has(const char *out, const char *s)
{
	return strstr(out, s) != NULL;
}

/* No hex text of any 8-byte window of any issued secret in the output (a printed secret would show as hex). */
static int no_secret_hex(const char *out)
{
	const sim_sec_log *log;
	unsigned a, k;
	int ok = 1;

	s_lock();
	log = sim_mon_secrets(G.mon);
	for (a = 0; a < log->kept && ok; a++) {
		for (k = 0; k + 8u <= log->len[a] && ok; k += 4u) {
			char hex[17];
			unsigned i;

			for (i = 0; i < 8u; i++)
				snprintf(hex + 2u * i, 3, "%02x", log->secret[a][k + i]);
			if (strstr(out, hex) != NULL)
				ok = 0;
		}
	}
	s_unlock();
	return ok;
}

static void test_monprobe(void)
{
	const char *exe = getenv("WR_MONPROBE");
	char dir[] = "/tmp/wrl-sec-probe-XXXXXX", kr[160], b64[128], out[16384];
	wopts o = base_opts(WR_KEY_TYPE_AES256K);
	int rc, accel_ok;

	if (exe == NULL || *exe == '\0') {
		fprintf(stderr, "note: WR_MONPROBE not set; wr-monprobe tests skipped\n");
		return;
	}
	accel_ok = spy_init() == 0;
	if (mkdtemp(dir) == NULL)
		abort();
	snprintf(kr, sizeof(kr), "%s/good.keyring", dir);

	/* option errors: exit 2 with a message, before anything connects */
	o.mon_allow = SC_ALLOW_CRC | SC_ALLOW_SECURE;
	world_start(&o);
	write_keyring(kr, WR_KEY_TYPE_AES256K, 1, b64);
	rc = probe(exe, kr, "--mode bogus", out, sizeof(out));
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has(out, "--mode"));
	rc = probe(exe, kr, "--mode secure --mode-osd bogus", out, sizeof(out));
	WRT_CHECK_U64(rc, 2);
	rc = probe(exe, kr, "--require-mode both", out, sizeof(out));
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has(out, "--require-mode"));

	/* the default is crc, as it always was: no secure memory, one crc connection, no stats of the hook */
	rc = probe(exe, kr, "", out, sizeof(out));
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK_U64(field_u(out, "conns_secure="), 0);
	WRT_CHECK_U64(field_u(out, "conns_crc="), 1);
	WRT_CHECK(has(out, "accel=0 gcm=portable gcm_ops=0"));
	WRT_CHECK_U64(secrets_mon(), 0);

	/* secure: one secure connection, a secret of its own, the assertion holds, the secret and the key text are nowhere in the output */
	rc = probe(exe, kr, "--mode secure --require-mode secure", out, sizeof(out));
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(out, " result active=1 "));
	WRT_CHECK(has(out, "maps=11"));
	WRT_CHECK_U64(field_u(out, "conns_secure="), 1);
	WRT_CHECK_U64(field_u(out, "conns_crc="), 0);
	WRT_CHECK_U64(field_u(out, "sec_failures="), 0);
	WRT_CHECK(has(out, "accel=0 gcm=portable gcm_ops=0"));
	WRT_CHECK(has(out, "result require_mode ok=1 wanted=secure"));
	WRT_CHECK_U64(secrets_mon(), 1);
	WRT_CHECK(no_secret_hex(out));
	WRT_CHECK(!has(out, b64));

	/* every policy word is understood; the stock policy offers the monitor secure first */
	rc = probe(exe, kr, "--mode stock --require-mode secure", out, sizeof(out));
	WRT_CHECK_U64(rc, 0);
	rc = probe(exe, kr, "--mode secure-first --mode-osd crc --require-mode secure", out, sizeof(out));
	WRT_CHECK_U64(rc, 0);
	rc = probe(exe, kr, "--mode crc-first --require-mode crc", out, sizeof(out)); /* crc first and the server allows crc: crc */
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK_U64(field_u(out, "conns_crc="), 1);

	/* the assertion fails when the connection ended in the other mode: exit 3, the line says what was counted */
	rc = probe(exe, kr, "--mode crc --require-mode secure", out, sizeof(out));
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(out, "result require_mode ok=0 wanted=secure conns_secure=0 conns_crc=1"));
	WRT_CHECK(has(out, " result active=1 ")); /* the probe itself worked: only the assertion failed */
	rc = probe(exe, kr, "--mode secure --require-mode crc", out, sizeof(out));
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(out, "result require_mode ok=0 wanted=crc conns_secure=1 conns_crc=0"));

	/* the accelerated hook: the same session, the hook's key objects used (two per connection) */
	if (accel_ok) {
		rc = probe(exe, kr, "--mode secure --accel --require-mode secure", out, sizeof(out));
		WRT_CHECK_U64(rc, 0);
		WRT_CHECK(has(out, "accel=1 gcm=host"));
		WRT_CHECK(field_u(out, "gcm_ops=") > 0u);
		WRT_CHECK(no_secret_hex(out));
		rc = probe(exe, kr, "--mode crc --accel", out, sizeof(out)); /* a hook that is installed and never used says so */
		WRT_CHECK_U64(rc, 0);
		WRT_CHECK(has(out, "accel=1 gcm=portable gcm_ops=0"));
	} else {
		fprintf(stderr, "note: no AES-NI / PCLMULQDQ here: --accel is refused (exit 2) and the hook runs are skipped\n");
		rc = probe(exe, kr, "--mode secure --accel", out, sizeof(out));
		WRT_CHECK_U64(rc, 2);
		WRT_CHECK(has(out, "--accel"));
	}
	world_stop();

	/* a monitor that allows secure only against the default (crc) offer: refused, the event names what the server allows; --mode secure works */
	o.mon_allow = SC_ALLOW_SECURE;
	world_start(&o);
	rc = probe(exe, kr, "--require-mode crc", out, sizeof(out));
	WRT_CHECK(rc != 0);
	WRT_CHECK(has(out, "event AUTH_FAILED status=WR_E_M2_BAD_METHOD"));
	if (!has(out, "allowed_modes=0x4"))
		fprintf(stderr, "probe output:\n%.3000s\n", out);
	WRT_CHECK(has(out, "allowed_modes=0x4")); /* bit 2 = secure */
	WRT_CHECK(has(out, "result require_mode ok=0 wanted=crc conns_secure=0 conns_crc=0"));
	rc = probe(exe, kr, "--mode secure --require-mode secure", out, sizeof(out));
	WRT_CHECK_U64(rc, 0);
	world_stop();

	/* the reverse: a crc-only monitor refuses a secure-only offer (allowed modes {crc} = bit 1 = 0x2); nothing connected, so "all secure" is not true either */
	o.mon_allow = SC_ALLOW_CRC;
	world_start(&o);
	rc = probe(exe, kr, "--mode secure --require-mode secure", out, sizeof(out));
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(out, "event AUTH_FAILED status=WR_E_M2_BAD_METHOD"));
	if (!has(out, "allowed_modes=0x2"))
		fprintf(stderr, "probe output:\n%.3000s\n", out);
	WRT_CHECK(has(out, "allowed_modes=0x2"));
	WRT_CHECK(has(out, "result require_mode ok=0 wanted=secure conns_secure=0 conns_crc=0"));
	WRT_CHECK(has(out, " result active=0 "));
	world_stop();
	{
		char path[256];

		snprintf(path, sizeof(path), "%s/good.keyring", dir);
		(void)unlink(path);
		(void)rmdir(dir);
	}
}

/* ---- main ------------------------------------------------------------------------------------------------ */

int main(void)
{
	uint64_t t0;

#define RUN(t)                                                                                    \
	do {                                                                                      \
		t0 = now_ms();                                                                    \
		t;                                                                                \
		fprintf(stderr, "  %-44s %6llu ms\n", #t, (unsigned long long)(now_ms() - t0));   \
	} while (0)
	RUN(test_image_io(WR_KEY_TYPE_AES256K, 0));
	RUN(test_image_io(WR_KEY_TYPE_AES, 0));
	RUN(test_image_io(WR_KEY_TYPE_AES256K, 1));
	RUN(test_image_io(WR_KEY_TYPE_AES, 1));
	RUN(test_slow_server(0));
	RUN(test_slow_server(1));
	RUN(test_server_cuts());
	RUN(test_hostile_frames(0));
	RUN(test_hostile_frames(1));
	RUN(test_policies());
	RUN(test_refusals());
	RUN(test_downgrade());
	RUN(test_monprobe());
#undef RUN
	return wrt_finish();
}
