/* SPDX-License-Identifier: MIT */
/*
 * test_host_tool_rbd.c - the wr-rbd tool (harness/host/tools/wr-rbd.c) run as a child process against a whole simulated
 * cluster over REAL TCP sockets on 127.0.0.1: one sim_mon and three sim_osd over one shared sim_store, each with its own
 * listening socket, served by one pthread (all simulator calls happen under its mutex). The map the monitor serves names
 * the OSDs by their 127.0.0.1 ports, so the engine dials them like any cluster. ctest name: host.tool_rbd.
 *
 * Checked, through the tool's output and exit status and, independently, through the simulator's store:
 *   - arguments and refusals: no command, unknown command, bad pattern, a write without --rw, a range outside the image,
 *     a missing image, an image the writer profile refuses, a wrong key; the key text never appears in any output;
 *   - info, fill / verify (a wrong pattern is a difference, exit 1, with its first offset), write of a pattern and of a
 *     file at unaligned offsets, read to a file and to a checksum, discard and zeroes, compare with an exported file (a
 *     flipped byte is found), bench read and write;
 *   - random: zero differences with queue depths 1 and 8 and several seeds, then the saved model equals the bytes the
 *     simulator's store holds; the same with every OSD restarted every few milliseconds (connections cut under I/O);
 *   - shell: commands on one open image, "done N rc=R" per command, the worst code is the exit status;
 *   - both key types.
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sim_osd.h"
#include "wrt.h"
#include "wrt_mapgen.h"

#define NOSD 3u
#define SMAX 24u
#define OUTCAP (1024u * 1024u)
#define POOL 1
#define IMG_ORDER 16u
#define IMG_SIZE (4u << 20)
#define IMG2_ORDER 20u
#define IMG2_SIZE (16u << 20)
#define IMG3_ORDER 14u /* 16 KiB objects, and a size that is not a whole number of them (nor of a sector): the last object is partial */
#define IMG3_SIZE (50u * 16384u + 1233u)

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ---- keys ---------------------------------------------------------------------------------------------------- */

static void mkkey(wr_key *k, unsigned type, uint8_t salt)
{
	uint8_t raw[32];
	size_t i, len = type == WR_KEY_TYPE_AES ? 16u : 32u;

	for (i = 0; i < len; i++)
		raw[i] = (uint8_t)(salt + i * 7u);
	if (wr_key_from_raw(k, type, raw, len) != WR_OK)
		abort();
}

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

/* A keyring file for the key mkkey(salt) builds; b64_out gets the key text (to check it never shows up in output). */
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

/* ---- the simulated cluster -------------------------------------------------------------------------------------- */

typedef struct sconn {
	int fd;
	int who; /* 0 = monitor, 1 + i = OSD i */
	sim_mon_conn *mc;
	sim_osd_conn *oc;
	uint8_t *out;
	size_t out_len, out_off;
} sconn;

typedef struct srv {
	int lfd[1u + NOSD];
	uint16_t port[1u + NOSD];
	pthread_t th;
	pthread_mutex_t mu;
	volatile int stop;
	sim_mon *mon;
	sim_store *store;
	sim_osd *osd[NOSD];
	sconn c[SMAX];
	wrt_mg_map desc;
	uint64_t restart_every_ms, next_restart; /* 0 = never */
	unsigned rr, n_restarts, n_accept, restart_budget; /* restarts left to do (the engine backs off a failing OSD, so a storm would only slow the run) */
	uint8_t monmap[512];
	size_t monmap_len;
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

static int listen_on(uint16_t *port)
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
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 32) != 0 || getsockname(fd, (struct sockaddr *)&sa, &sl) != 0)
		abort();
	*port = ntohs(sa.sin_port);
	(void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	return fd;
}

/* The committed MonMap vector with its one monitor address (10.77.0.10:3300) moved to 127.0.0.1:port. */
static void load_monmap(uint16_t port)
{
	static const uint8_t from[8] = {0x02, 0x00, 0x0c, 0xe4, 0x0a, 0x4d, 0x00, 0x0a};
	wrt_json j;
	uint8_t *b = NULL;
	size_t n = 0, i, hits = 0;

	if (wrt_json_load_vec(&j, "monclient/mmonmap-e3.json") != 0)
		abort();
	if (wrt_json_get_hex(&j, wrt_json_root(&j), "monmap_hex", &b, &n) != 0 || n > sizeof(S.monmap))
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
	memcpy(S.monmap, b, n);
	S.monmap_len = n;
	free(b);
	wrt_json_free(&j);
}

static void sconn_drop(sconn *c)
{
	close(c->fd);
	if (c->mc != NULL)
		sim_mon_conn_free(c->mc);
	if (c->oc != NULL)
		sim_osd_conn_free(c->oc);
	free(c->out);
	memset(c, 0, sizeof(*c));
	c->fd = -1;
}

static void s_accept(unsigned who)
{
	int fd = accept(S.lfd[who], NULL, NULL), one = 1;
	unsigned i;

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
	S.c[i].who = (int)who;
	S.c[i].out = (uint8_t *)malloc(OUTCAP);
	if (who == 0u)
		S.c[i].mc = sim_mon_accept(S.mon);
	else
		S.c[i].oc = sim_osd_accept(S.osd[who - 1u]);
	S.n_accept++;
	if (S.c[i].out == NULL || (S.c[i].mc == NULL && S.c[i].oc == NULL))
		sconn_drop(&S.c[i]);
}

static void s_conn(sconn *c, short rev)
{
	uint8_t buf[65536];
	int closed;

	if (rev & (POLLIN | POLLHUP | POLLERR)) {
		ssize_t n = recv(c->fd, buf, sizeof(buf), 0);

		if (n > 0) {
			if (c->mc != NULL)
				(void)sim_mon_feed(c->mc, buf, (size_t)n);
			else
				(void)sim_osd_feed(c->oc, buf, (size_t)n);
		} else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
			sconn_drop(c);
			return;
		}
	}
	if (c->out_off == c->out_len)
		c->out_off = c->out_len = 0;
	if (c->out_len < OUTCAP)
		c->out_len += c->mc != NULL ? sim_mon_drain(c->mc, c->out + c->out_len, OUTCAP - c->out_len)
					    : sim_osd_drain(c->oc, c->out + c->out_len, OUTCAP - c->out_len);
	if (c->out_len > c->out_off) {
		ssize_t w = send(c->fd, c->out + c->out_off, c->out_len - c->out_off, MSG_NOSIGNAL | MSG_DONTWAIT);

		if (w > 0)
			c->out_off += (size_t)w;
		else if (w < 0 && errno != EAGAIN && errno != EINTR) {
			sconn_drop(c);
			return;
		}
	}
	closed = c->mc != NULL ? sim_mon_closed(c->mc) : sim_osd_closed(c->oc);
	if (closed && c->out_off == c->out_len)
		sconn_drop(c);
}

static void *srv_main(void *arg)
{
	(void)arg;
	while (!S.stop) {
		struct pollfd pf[1u + NOSD + SMAX];
		unsigned i, n = 0, nl = 1u + NOSD;
		int idx[SMAX];

		for (i = 0; i < nl; i++) {
			pf[n].fd = S.lfd[i];
			pf[n].events = POLLIN;
			pf[n].revents = 0;
			n++;
		}
		s_lock();
		for (i = 0; i < SMAX; i++) {
			if (S.c[i].fd < 0)
				continue;
			pf[n].fd = S.c[i].fd;
			pf[n].events = POLLIN | (S.c[i].out_len > S.c[i].out_off ? POLLOUT : 0);
			pf[n].revents = 0;
			idx[n - nl] = (int)i;
			n++;
		}
		s_unlock();
		(void)poll(pf, n, 2);
		s_lock();
		if (S.restart_every_ms != 0u && S.restart_budget != 0u && now_ms() >= S.next_restart) {
			sim_osd_restart(S.osd[S.rr % NOSD]); /* every connection of that OSD is cut, held replies are lost */
			S.rr++;
			S.n_restarts++;
			S.restart_budget--;
			S.next_restart = now_ms() + S.restart_every_ms;
		}
		for (i = 0; i < nl; i++)
			if (pf[i].revents & POLLIN)
				s_accept(i);
		for (i = nl; i < n; i++) {
			sconn *c = &S.c[idx[i - nl]];

			if (c->fd >= 0 && c->fd == pf[i].fd)
				s_conn(c, pf[i].revents);
		}
		for (i = 0; i < SMAX; i++) /* output the simulator produced on its own (a restart's cut, a push) */
			if (S.c[i].fd >= 0)
				s_conn(&S.c[i], 0);
		s_unlock();
	}
	return NULL;
}

static int image_make(const char *name, const char *id, uint64_t size, uint8_t order, uint64_t features, int64_t data_pool)
{
	sim_rbd_image_cfg c;

	memset(&c, 0, sizeof(c));
	c.pool = POOL;
	c.name = name;
	c.id = id;
	c.size = size;
	c.order = order;
	c.features = features;
	c.data_pool = data_pool;
	return sim_rbd_image_create(S.store, &c) == WR_OK ? 0 : -1;
}

static void srv_start(unsigned key_type)
{
	sim_mon_cfg mc;
	wrt_mg_cluster_spec cs;
	wrt_mg_buf b;
	unsigned i;
	uint32_t epoch;

	memset(&S, 0, sizeof(S));
	memset(&b, 0, sizeof(b));
	pthread_mutex_init(&S.mu, NULL);
	for (i = 0; i < SMAX; i++)
		S.c[i].fd = -1;
	for (i = 0; i < 1u + NOSD; i++)
		S.lfd[i] = listen_on(&S.port[i]);
	load_monmap(S.port[0]);
	sim_mon_cfg_default(&mc);
	mkkey(&mc.key, key_type, 1);
	mc.m2.server_ip[0] = 127, mc.m2.server_ip[1] = 0, mc.m2.server_ip[2] = 0, mc.m2.server_ip[3] = 1;
	mc.m2.server_port = S.port[0];
	mc.monmap = S.monmap;
	mc.monmap_len = S.monmap_len;
	mc.no_default_osdmaps = 1;
	S.mon = sim_mon_new(&mc);
	S.store = sim_store_new();
	if (S.mon == NULL || S.store == NULL)
		abort();
	/* the map: three OSDs on three hosts, two pools ("pool1" = 1, "pool2" = 2), the OSDs at their loopback ports */
	wrt_mg_cluster_spec_init(&cs, NOSD);
	cs.osds_per_host = 1;
	cs.n_pools = 2;
	cs.pg_num = 16;
	cs.pool_size = 3;
	cs.epoch = 1;
	cs.seed = 77;
	if (wrt_mg_build_map(&S.desc, &cs) != 0)
		abort();
	for (i = 0; i < NOSD; i++)
		wrt_mg_av_v2(&WRT_MG_E(S.desc.client_addrs, wrt_mg_addrvec, i), 0x7f000001u, S.port[1u + i], 7000u + i);
	memcpy(S.desc.fsid, S.mon->fsid, 16);
	epoch = S.desc.epoch;
	if (wrt_mg_map_encode(&S.desc, &b) != 0 || sim_mon_add_epoch(S.mon, epoch, b.p, b.len, NULL, 0) != WR_OK ||
	    sim_mon_push_epoch(S.mon) != WR_OK)
		abort();
	wrt_mg_buf_free(&b);
	for (i = 0; i < NOSD; i++) {
		sim_osd_cfg oc;

		sim_osd_cfg_default(&oc);
		oc.mon = S.mon;
		oc.store = S.store;
		oc.id = (int32_t)i;
		oc.seed = 11u + i;
		oc.m2.server_ip[0] = 127, oc.m2.server_ip[1] = 0, oc.m2.server_ip[2] = 0, oc.m2.server_ip[3] = 1;
		oc.m2.server_port = S.port[1u + i];
		oc.m2.server_nonce = 7000u + i;
		oc.m2.check_target = 1;
		S.osd[i] = sim_osd_new(&oc);
		if (S.osd[i] == NULL)
			abort();
	}
	if (image_make("img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) != 0 || image_make("img2", "abc124", IMG2_SIZE, IMG2_ORDER, 0x1, -1) != 0 ||
	    image_make("imgfull", "abc125", IMG_SIZE, IMG_ORDER, 0x3d, -1) != 0 || image_make("img3", "abc126", IMG3_SIZE, IMG3_ORDER, 0x21, -1) != 0)
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
			sconn_drop(&S.c[i]);
	for (i = 0; i < 1u + NOSD; i++)
		close(S.lfd[i]);
	for (i = 0; i < NOSD; i++)
		sim_osd_free(S.osd[i]);
	sim_mon_free(S.mon);
	sim_store_free(S.store);
	wrt_mg_map_free(&S.desc);
	pthread_mutex_destroy(&S.mu);
}

/* The bytes of image `id` the store holds (object by object, holes and missing objects as zeros). */
static void store_image(const char *id, uint8_t order, uint64_t size, uint8_t *out)
{
	uint64_t obj = 1ull << order, i;

	s_lock();
	for (i = 0; i * obj < size; i++) {
		char oid[96];
		int exists = 0;

		snprintf(oid, sizeof(oid), "rbd_data.%s.%016llx", id, (unsigned long long)i);
		if (sim_store_read(S.store, POOL, oid, 0, out + i * obj, (size_t)obj, &exists) != WR_OK)
			memset(out + i * obj, 0xEE, (size_t)obj);
	}
	s_unlock();
}

/* ---- running the tool -------------------------------------------------------------------------------------------- */

static char g_tool[512];
static char g_dir[128];
static char g_kr[192], g_kr_bad[192], g_b64[128], g_b64_bad[128];

/* Run the tool with `args` (a NULL terminated list after the common ones); `input` is fed to its stdin (may be NULL).
 * out gets stdout + stderr. Returns the exit status, -1 if it did not exit normally. */
static int run_tool(char *const *args, const char *input, char *out, size_t cap, unsigned secs)
{
	int pfd[2], status = 0, in_fd = -1;
	size_t n = 0;
	pid_t pid;
	uint64_t t_end = now_ms() + secs * 1000u;
	char inpath[192];

	if (input != NULL) {
		FILE *f;

		snprintf(inpath, sizeof(inpath), "%s/stdin.txt", g_dir);
		f = fopen(inpath, "w");
		if (f == NULL)
			abort();
		fputs(input, f);
		fclose(f);
		in_fd = open(inpath, O_RDONLY);
	}
	if (pipe(pfd) != 0)
		abort();
	pid = fork();
	if (pid < 0)
		abort();
	if (pid == 0) {
		if (in_fd >= 0)
			(void)dup2(in_fd, 0);
		else {
			int dn = open("/dev/null", O_RDONLY);

			(void)dup2(dn, 0);
		}
		(void)dup2(pfd[1], 1);
		(void)dup2(pfd[1], 2);
		close(pfd[0]);
		close(pfd[1]);
		execv(g_tool, args);
		_exit(127);
	}
	close(pfd[1]);
	if (in_fd >= 0)
		close(in_fd);
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
	if (input != NULL)
		(void)unlink(inpath);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

#define MAXARGS 40
/* Common arguments for the simulated cluster + the given extras. */
static int tool(char *out, size_t cap, const char *keyring, const char *image, const char *input, const char *extra, unsigned secs)
{
	char mon[64], copy[1024];
	char *args[MAXARGS];
	unsigned n = 0;
	char *tok;

	snprintf(mon, sizeof(mon), "127.0.0.1:%u", (unsigned)S.port[0]);
	args[n++] = (char *)"wr-rbd";
	args[n++] = (char *)"--mon";
	args[n++] = mon;
	args[n++] = (char *)"--user";
	args[n++] = (char *)"winrbd";
	args[n++] = (char *)"--keyring";
	args[n++] = (char *)keyring;
	args[n++] = (char *)"--pool";
	args[n++] = (char *)"pool1";
	args[n++] = (char *)"--image";
	args[n++] = (char *)image;
	snprintf(copy, sizeof(copy), "%s", extra);
	for (tok = strtok(copy, " "); tok != NULL && n + 1u < MAXARGS; tok = strtok(NULL, " "))
		args[n++] = tok;
	args[n] = NULL;
	return run_tool(args, input, out, cap, secs);
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

static int tmp_file_write(const char *name, const uint8_t *p, size_t n, char *path_out, size_t cap)
{
	FILE *f;

	snprintf(path_out, cap, "%s/%s", g_dir, name);
	f = fopen(path_out, "wb");
	if (f == NULL)
		return -1;
	if (fwrite(p, 1, n, f) != n) {
		fclose(f);
		return -1;
	}
	return fclose(f);
}

static uint8_t *tmp_file_read(const char *path, size_t *n)
{
	uint8_t *b = NULL;

	if (wrt_read_file(path, &b, n) != 0)
		return NULL;
	return b;
}

static uint8_t pat_rand(uint64_t seed, uint64_t x)
{
	/* the same function as the tool's rand:SEED pattern, written out from its definition in the tool header comment */
	uint64_t z = seed * 0x2545f4914f6cdd1dull + (x >> 3);

	z += 0x9e3779b97f4a7c15ull;
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
	z ^= z >> 31;
	return (uint8_t)(z >> (8u * (unsigned)(x & 7u)));
}

/* ---- the tests ------------------------------------------------------------------------------------------------ */

static char OUT[1 << 17];

static void test_args_and_refusals(void)
{
	char *a0[] = {(char *)"wr-rbd", NULL};
	char *a1[] = {(char *)"wr-rbd", (char *)"--mon", (char *)"127.0.0.1", (char *)"--user", (char *)"u", (char *)"--keyring", (char *)"/nonexistent/k",
		      (char *)"--pool", (char *)"p", (char *)"--image", (char *)"i", (char *)"frobnicate", NULL};
	char *a2[] = {(char *)"wr-rbd", (char *)"--mon", (char *)"127.0.0.1", (char *)"--user", (char *)"u", (char *)"--keyring", (char *)"/nonexistent/k",
		      (char *)"--pool", (char *)"p", (char *)"--image", (char *)"i", (char *)"info", NULL};
	char *a3[] = {(char *)"wr-rbd", (char *)"--bogus", NULL};
	char *a4[] = {(char *)"wr-rbd", (char *)"--mon", (char *)"127.0.0.1", (char *)"--user", (char *)"u", (char *)"--keyring", g_kr,
		      (char *)"--pool", (char *)"p", (char *)"--image", (char *)"i", (char *)"--depth", (char *)"0", (char *)"info", NULL};
	char *a5[] = {(char *)"wr-rbd", (char *)"--mon", (char *)"not an address!", (char *)"--user", (char *)"u", (char *)"--keyring", g_kr,
		      (char *)"--pool", (char *)"p", (char *)"--image", (char *)"i", (char *)"info", NULL};
	int rc;

	WRT_CHECK_U64(run_tool(a0, NULL, OUT, sizeof(OUT), 20), 2);
	WRT_CHECK(has(OUT, "usage:"));
	WRT_CHECK_U64(run_tool(a1, NULL, OUT, sizeof(OUT), 20), 2);
	WRT_CHECK(has(OUT, "unknown command"));
	WRT_CHECK_U64(run_tool(a2, NULL, OUT, sizeof(OUT), 20), 2); /* the keyring cannot be read */
	WRT_CHECK(has(OUT, "keyring"));
	WRT_CHECK_U64(run_tool(a3, NULL, OUT, sizeof(OUT), 20), 2);
	WRT_CHECK_U64(run_tool(a4, NULL, OUT, sizeof(OUT), 20), 2);
	WRT_CHECK(has(OUT, "--depth"));
	WRT_CHECK_U64(run_tool(a5, NULL, OUT, sizeof(OUT), 20), 2);

	/* a command that needs --rw, a bad pattern, a range outside the image, arguments of a command */
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "write 0 4096 --pattern rand:1", 30);
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has(OUT, "need --rw"));
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--rw write 0 4096 --pattern nonsense", 30);
	WRT_CHECK_U64(rc, 2);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--rw write 4194000 4096 --pattern rand:1", 30);
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has(OUT, "status=range"));
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "read 0", 30);
	WRT_CHECK_U64(rc, 2);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "verify 0 4096", 30); /* no pattern */
	WRT_CHECK_U64(rc, 2);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "random 10", 30);
	WRT_CHECK_U64(rc, 2);

	/* a missing image, an image the writer profile refuses (default features 0x3d), a wrong key */
	rc = tool(OUT, sizeof(OUT), g_kr, "nosuchimage", NULL, "--timeout 8000 info", 30);
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(OUT, "result open ok=0"));
	WRT_CHECK(has(OUT, "WR_E_RBD_NOT_FOUND"));
	rc = tool(OUT, sizeof(OUT), g_kr, "imgfull", NULL, "--rw --timeout 8000 info", 30);
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(OUT, "WR_E_RBD_FEATURES"));
	rc = tool(OUT, sizeof(OUT), g_kr_bad, "img", NULL, "--timeout 1500 info", 30);
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(OUT, "result open ok=0"));
	WRT_CHECK(!has(OUT, g_b64_bad));
	WRT_CHECK(!has(OUT, g_b64));
}

static void test_basic_io(void)
{
	static uint8_t img[IMG_SIZE], exp[IMG_SIZE];
	char fpath[256], fpath2[256], cmd[640];
	uint8_t *got;
	size_t n = 0, i;
	int rc;

	/* info: the header's numbers, read only and writable */
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "info", 30);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " result info ok=1 state=OPEN"));
	WRT_CHECK_U64(field_u(OUT, " size="), IMG_SIZE);
	WRT_CHECK_U64(field_u(OUT, " order="), IMG_ORDER);
	WRT_CHECK(has(OUT, "features=0x21"));
	WRT_CHECK(has(OUT, "writable=0"));
	WRT_CHECK(has(OUT, "event MON_SESSION_UP"));
	WRT_CHECK(has(OUT, " stats ops_inflight=0"));
	WRT_CHECK(!has(OUT, g_b64));
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--rw info", 30);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, "writable=1"));

	/* an untouched image reads as zeros */
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "verify --pattern zero", 30);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " result verify ok=1"));

	/* fill and verify: the right pattern, a wrong one (exit 1, first difference at 0), a part of the image */
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--rw fill --pattern rand:5", 60);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " result fill ok=1 off=0 len=4194304 bytes=4194304 diffs=0 errors=0"));
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "verify --pattern rand:5", 60);
	WRT_CHECK_U64(rc, 0);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "verify --pattern rand:6", 60);
	WRT_CHECK_U64(rc, 1);
	{
		char want[48];
		uint64_t first = 0;

		while (first < IMG_SIZE && pat_rand(5, first) == pat_rand(6, first))
			first++;
		snprintf(want, sizeof(want), "first_diff=%llu ", (unsigned long long)first); /* the first byte where the two patterns differ */
		WRT_CHECK(has(OUT, want));
	}
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "verify 1000003 70001 --pattern rand:5", 60);
	WRT_CHECK_U64(rc, 0);
	store_image("abc123", IMG_ORDER, IMG_SIZE, img);
	for (i = 0; i < IMG_SIZE; i++)
		exp[i] = pat_rand(5, i);
	WRT_CHECK(memcmp(img, exp, IMG_SIZE) == 0); /* the simulator's own bytes, independently of the tool */

	/* write a pattern at an unaligned offset across several 64 KiB objects */
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--rw write 300001 250000 --pattern byte:0xab", 60);
	WRT_CHECK_U64(rc, 0);
	memset(exp + 300001, 0xab, 250000);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "verify 300001 250000 --pattern byte:0xab", 60);
	WRT_CHECK_U64(rc, 0);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "verify 300000 1 --pattern rand:5", 60);
	WRT_CHECK_U64(rc, 0);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "verify 550001 1 --pattern rand:5", 60);
	WRT_CHECK_U64(rc, 0);

	/* write a file, read a range into a file */
	for (i = 0; i < 100000u; i++)
		img[i] = (uint8_t)(i * 31u + 7u);
	WRT_CHECK(tmp_file_write("in.bin", img, 100000, fpath, sizeof(fpath)) == 0);
	snprintf(cmd, sizeof(cmd), "--rw write 777777 - --file %s", fpath);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, cmd, 60);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK_U64(field_u(OUT, " bytes="), 100000);
	memcpy(exp + 777777, img, 100000);
	snprintf(fpath2, sizeof(fpath2), "%s/out.bin", g_dir);
	snprintf(cmd, sizeof(cmd), "read 777777 100000 %s", fpath2);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, cmd, 60);
	WRT_CHECK_U64(rc, 0);
	got = tmp_file_read(fpath2, &n);
	WRT_CHECK(got != NULL && n == 100000u && memcmp(got, img, 100000) == 0);
	free(got);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "read 0 1000", 60); /* no file: a checksum line */
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " read-sum "));

	/* discard and zeroes: whole objects and ragged ends read back as zeros */
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--rw discard 65536 131072", 60);
	WRT_CHECK_U64(rc, 0);
	memset(exp + 65536, 0, 131072);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--rw zeroes 1000000 5000", 60);
	WRT_CHECK_U64(rc, 0);
	memset(exp + 1000000, 0, 5000);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--rw discard 2000000 70000", 60);
	WRT_CHECK_U64(rc, 0);
	memset(exp + 2000000, 0, 70000);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "verify 65536 131072 --pattern zero", 60);
	WRT_CHECK_U64(rc, 0);
	store_image("abc123", IMG_ORDER, IMG_SIZE, img);
	WRT_CHECK(memcmp(img, exp, IMG_SIZE) == 0);

	/* compare with an export: equal, then a flipped byte is found (exit 1, its offset) */
	WRT_CHECK(tmp_file_write("export.bin", exp, IMG_SIZE, fpath, sizeof(fpath)) == 0);
	snprintf(cmd, sizeof(cmd), "compare %s", fpath);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, cmd, 60);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " result compare ok=1"));
	exp[3333333] ^= 0x10;
	exp[IMG_SIZE - 1u] ^= 0x01;
	WRT_CHECK(tmp_file_write("export2.bin", exp, IMG_SIZE, fpath, sizeof(fpath)) == 0);
	snprintf(cmd, sizeof(cmd), "compare %s", fpath);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, cmd, 60);
	WRT_CHECK_U64(rc, 1);
	WRT_CHECK(has(OUT, "first_diff=3333333 "));
	WRT_CHECK_U64(field_u(OUT, " diffs="), 2);
	(void)unlink(fpath);
	/* a file of the wrong size is a difference too */
	WRT_CHECK(tmp_file_write("short.bin", exp, 1000, fpath, sizeof(fpath)) == 0);
	snprintf(cmd, sizeof(cmd), "compare %s", fpath);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, cmd, 60);
	WRT_CHECK_U64(rc, 1);
	WRT_CHECK(has(OUT, "size_mismatch"));

	/* bench */
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--rw --io-size 32768 --depth 4 bench write --total 1M", 60);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " result bench ok=1 kind=write"));
	WRT_CHECK_U64(field_u(OUT, " ops="), 32);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--io-size 32768 --depth 4 bench read --total 1M --random", 60);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " result bench ok=1 kind=read"));
	WRT_CHECK(has(OUT, "random=1"));
	WRT_CHECK(!has(OUT, g_b64));
}

/* random against the model; then the saved model is compared with what the simulator's store holds */
static void random_run(const char *extra, uint64_t seed, unsigned n_ops, const char *label)
{
	static uint8_t img[IMG_SIZE];
	char fpath[256], cmd[640];
	uint8_t *model;
	size_t n = 0;
	int rc;

	snprintf(fpath, sizeof(fpath), "%s/model.bin", g_dir);
	snprintf(cmd, sizeof(cmd), "--rw %s random %u %llu --save %s", extra, n_ops, (unsigned long long)seed, fpath);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, cmd, 180);
	if (rc != 0)
		fprintf(stderr, "random %s: exit %d, output follows\n%.3000s\n", label, rc, OUT);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " result random ok=1 "));
	WRT_CHECK_U64(field_u(OUT, "read_mismatches="), 0);
	WRT_CHECK_U64(field_u(OUT, "final_diff_bytes="), 0);
	WRT_CHECK_U64(field_u(OUT, " errors="), 0);
	WRT_CHECK_U64(field_u(OUT, " ops="), n_ops);
	WRT_CHECK(field_u(OUT, " writes=") > 0 && field_u(OUT, " reads=") > 0 && field_u(OUT, " discards=") > 0);
	WRT_CHECK_U64(field_u(OUT, " barrier_violations="), 0); /* no flush overtook a write, no request came back twice */
	WRT_CHECK_U64(field_u(OUT, " bad_completions="), 0);
	model = tmp_file_read(fpath, &n);
	WRT_CHECK(model != NULL && n > 0 && n <= IMG_SIZE);
	if (model != NULL && n > 0 && n <= IMG_SIZE) {
		store_image("abc123", IMG_ORDER, IMG_SIZE, img);
		WRT_CHECK(memcmp(img, model, n) == 0); /* the cluster holds what the model says (the model's region): zero differences */
	}
	free(model);
	(void)unlink(fpath);
}

static void test_random(void)
{
	random_run("--depth 1", 1, 150, "depth 1");
	random_run("--depth 8", 2, 300, "depth 8");
	random_run("--depth 4 --io-size 16384 --max-len 200000", 3, 200, "max-len");
	random_run("--depth 16 --model-bytes 1048576", 4, 300, "small model");
	/* a model that starts from non-zero content: the image keeps what the earlier runs left, the model reads it first */
	random_run("--depth 6", 5, 200, "on existing content");
	/* requests that overlap in flight: the core runs them in submission order (design C14), the model says what every read must see */
	random_run("--depth 16 --overlap --max-len 100000", 21, 400, "overlap");
	random_run("--depth 4 --overlap --model-bytes 262144 --max-len 70000", 22, 300, "overlap, small model");
	/* the engine knobs and the output switch: ORDERSNAP, a short header refresh, timeouts, no full-pool try, quiet events */
	random_run("--depth 4 --ordersnap --hdr-refresh 1500 --io-timeout 8000 --op-timeout 4000 --run-timeout 120000 --no-full-try --stats-only", 7, 120,
		   "engine knobs");
	WRT_CHECK(!has(OUT, " event "));
	WRT_CHECK(has(OUT, " stats "));
}

static void test_random_with_restarts(void)
{
	unsigned before;

	s_lock();
	S.restart_every_ms = 250;
	S.restart_budget = 9;
	S.next_restart = now_ms() + 250;
	before = S.n_restarts;
	s_unlock();
	random_run("--depth 8 --op-timeout 3000 --delay-ms 12", 6, 250, "restarts"); /* paced, so the run outlasts the restarts */
	s_lock();
	S.restart_budget = 6; /* the same with overlapping requests in flight: a resend must not overtake a later overlapping write */
	S.next_restart = now_ms() + 250;
	s_unlock();
	random_run("--depth 8 --overlap --op-timeout 3000 --delay-ms 12", 8, 250, "restarts, overlapping");
	s_lock();
	S.restart_every_ms = 0;
	fprintf(stderr, "  OSD restarts during the run: %u\n", S.n_restarts - before);
	WRT_CHECK(S.n_restarts - before >= 3u); /* the faults really happened (some or all of the budget) */
	s_unlock();
	WRT_CHECK(has(OUT, " stats ")); /* the counters of the run are printed */
	fprintf(stderr, "  %.400s\n", strstr(OUT, " stats ") != NULL ? strstr(OUT, " stats ") : "");
}

static void test_shell(void)
{
	int rc;
	const char *script = "echo hello world\n"
			     "# a comment\n"
			     "frobnicate 1 2\n"
			     "write 0 4096\n"
			     "quit\n"
			     "echo not reached\n";

	rc = tool(OUT, sizeof(OUT), g_kr, "img2", script, "--rw shell", 60);
	WRT_CHECK_U64(rc, 2); /* the worst command code: an unknown command and a write without a pattern are usage errors */
	WRT_CHECK(has(OUT, " shell ready"));
	WRT_CHECK(has(OUT, " echo hello world"));
	WRT_CHECK(has(OUT, " done 1 rc=0"));
	WRT_CHECK(has(OUT, " done 2 rc=2"));
	WRT_CHECK(has(OUT, " done 3 rc=2"));
	WRT_CHECK(!has(OUT, "not reached"));
	WRT_CHECK(has(OUT, " result shell ok=0 commands=4")); /* "quit" counts as a command, a comment does not */
	/* the proper form, on one open image */
	script = "write 0 4096 --pattern byte:7\n"
		 "sleep 30\n"
		 "verify 0 4096 --pattern byte:7\n"
		 "verify 0 4096 --pattern byte:8\n"
		 "zeroes 0 4096\n"
		 "verify 0 4096 --pattern zero\n"
		 "random 20 9 --model-bytes 262144\n"
		 "echo bye\n";
	rc = tool(OUT, sizeof(OUT), g_kr, "img2", script, "--rw shell", 90);
	WRT_CHECK_U64(rc, 1); /* the second verify differs */
	WRT_CHECK(has(OUT, " done 1 rc=0"));
	WRT_CHECK(has(OUT, " done 3 rc=0"));
	WRT_CHECK(has(OUT, " done 4 rc=1"));
	WRT_CHECK(has(OUT, " done 6 rc=0"));
	WRT_CHECK(has(OUT, " done 7 rc=0"));
	WRT_CHECK(has(OUT, " done 8 rc=0"));
	WRT_CHECK(has(OUT, " echo bye"));
	WRT_CHECK_U64(field_u(OUT, "stats ops_inflight="), 0);
}

/* An image that is not a whole number of objects (50 objects of 16 KiB and 1233 bytes more, not a multiple of a sector either): the last object
 * is partial, the last byte is writable, the first byte past the end is refused, and the model run covers the whole image. */
static void test_odd_image(void)
{
	static uint8_t st[51u * 16384u], exp[IMG3_SIZE];
	char fpath[256], cmd[640];
	const uint64_t last = 50u * 16384u, tail = IMG3_SIZE - last;
	uint8_t *model;
	size_t n = 0, i;
	int rc;

	rc = tool(OUT, sizeof(OUT), g_kr, "img3", NULL, "--rw info", 30);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK_U64(field_u(OUT, " size="), IMG3_SIZE);
	WRT_CHECK_U64(field_u(OUT, " object_size="), 16384);
	rc = tool(OUT, sizeof(OUT), g_kr, "img3", NULL, "--rw fill --pattern rand:3", 60);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK_U64(field_u(OUT, " bytes="), IMG3_SIZE);
	rc = tool(OUT, sizeof(OUT), g_kr, "img3", NULL, "verify --pattern rand:3", 60);
	WRT_CHECK_U64(rc, 0);
	for (i = 0; i < IMG3_SIZE; i++)
		exp[i] = pat_rand(3, i);
	store_image("abc126", IMG3_ORDER, 51u * 16384u, st);
	WRT_CHECK(memcmp(st, exp, IMG3_SIZE) == 0);
	for (i = IMG3_SIZE; i < sizeof(st); i++) /* nothing was written past the end of the image */
		if (st[i] != 0)
			break;
	WRT_CHECK(i == sizeof(st));

	/* the last partial object: discard it, write the last byte, discard across the boundary, zero across the last two objects */
	snprintf(cmd, sizeof(cmd), "--rw discard %llu %llu", (unsigned long long)last, (unsigned long long)tail);
	WRT_CHECK_U64(tool(OUT, sizeof(OUT), g_kr, "img3", NULL, cmd, 60), 0);
	memset(exp + last, 0, (size_t)tail);
	snprintf(cmd, sizeof(cmd), "--rw write %llu 1 --pattern byte:0x77", (unsigned long long)IMG3_SIZE - 1u);
	WRT_CHECK_U64(tool(OUT, sizeof(OUT), g_kr, "img3", NULL, cmd, 60), 0);
	exp[IMG3_SIZE - 1u] = 0x77;
	snprintf(cmd, sizeof(cmd), "--rw discard %llu 2", (unsigned long long)last - 1u);
	WRT_CHECK_U64(tool(OUT, sizeof(OUT), g_kr, "img3", NULL, cmd, 60), 0);
	exp[last - 1u] = exp[last] = 0;
	snprintf(cmd, sizeof(cmd), "--rw zeroes %llu %llu", (unsigned long long)last - 16000u, (unsigned long long)tail + 15999u); /* up to the byte before the last */
	WRT_CHECK_U64(tool(OUT, sizeof(OUT), g_kr, "img3", NULL, cmd, 60), 0);
	memset(exp + last - 16000u, 0, (size_t)tail + 15999u);
	store_image("abc126", IMG3_ORDER, 51u * 16384u, st);
	WRT_CHECK(memcmp(st, exp, IMG3_SIZE) == 0);

	/* the end: the last byte is readable, one byte more is a range error (nothing is sent), a write of no bytes at the end is fine */
	snprintf(cmd, sizeof(cmd), "read %llu 1", (unsigned long long)IMG3_SIZE - 1u);
	WRT_CHECK_U64(tool(OUT, sizeof(OUT), g_kr, "img3", NULL, cmd, 60), 0);
	WRT_CHECK(has(OUT, "nonzero=1"));
	snprintf(cmd, sizeof(cmd), "read %llu 2", (unsigned long long)IMG3_SIZE - 1u);
	WRT_CHECK_U64(tool(OUT, sizeof(OUT), g_kr, "img3", NULL, cmd, 60), 2);
	WRT_CHECK(has(OUT, "status=range"));
	snprintf(cmd, sizeof(cmd), "--rw write %llu 1 --pattern byte:1", (unsigned long long)IMG3_SIZE);
	WRT_CHECK_U64(tool(OUT, sizeof(OUT), g_kr, "img3", NULL, cmd, 60), 2);
	snprintf(cmd, sizeof(cmd), "--rw write %llu 0 --pattern byte:1", (unsigned long long)IMG3_SIZE);
	WRT_CHECK_U64(tool(OUT, sizeof(OUT), g_kr, "img3", NULL, cmd, 60), 0);
	snprintf(cmd, sizeof(cmd), "verify %llu 1 --pattern byte:0x77", (unsigned long long)IMG3_SIZE - 1u);
	WRT_CHECK_U64(tool(OUT, sizeof(OUT), g_kr, "img3", NULL, cmd, 60), 0);

	/* the model run over the whole image, overlapping requests in flight, then what the store holds equals the model */
	snprintf(fpath, sizeof(fpath), "%s/model.bin", g_dir);
	snprintf(cmd, sizeof(cmd), "--rw --depth 12 --overlap --model-bytes 1M --max-len 40000 random 500 11 --save %s", fpath);
	rc = tool(OUT, sizeof(OUT), g_kr, "img3", NULL, cmd, 180);
	if (rc != 0)
		fprintf(stderr, "odd image random: exit %d, output follows\n%.3000s\n", rc, OUT);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK_U64(field_u(OUT, " region="), IMG3_SIZE);
	WRT_CHECK_U64(field_u(OUT, " barrier_violations="), 0);
	model = tmp_file_read(fpath, &n);
	WRT_CHECK(model != NULL && n == IMG3_SIZE);
	store_image("abc126", IMG3_ORDER, 51u * 16384u, st);
	WRT_CHECK(model != NULL && n == IMG3_SIZE && memcmp(st, model, IMG3_SIZE) == 0);
	free(model);
	(void)unlink(fpath);
}

/* Errors of the OSD: a READ that fails is an error (never zeros), except ENOENT which is a hole; a WRITE that fails is an error whatever the errno. */
static void set_force(uint32_t op, int32_t err)
{
	unsigned i;

	s_lock();
	for (i = 0; i < NOSD; i++) {
		sim_osd_faults(S.osd[i])->force_errno_op = (int32_t)op;
		sim_osd_faults(S.osd[i])->force_errno = err;
	}
	s_unlock();
}

static void test_error_paths(void)
{
	int rc;

	set_force(0x1201u, -5); /* READ -> EIO */
	rc = tool(OUT, sizeof(OUT), g_kr, "imgfull", NULL, "--timeout 8000 verify 0 8192 --pattern zero", 60);
	WRT_CHECK_U64(rc, 4);
	WRT_CHECK(has(OUT, "WR_E_OSD_IO"));
	WRT_CHECK(!has(OUT, "ok=1"));
	rc = tool(OUT, sizeof(OUT), g_kr, "imgfull", NULL, "read 0 8192", 60);
	WRT_CHECK_U64(rc, 4);
	WRT_CHECK(!has(OUT, " read-sum ")); /* the checksum of a failed read would look like a result */
	set_force(0x1201u, -1); /* READ -> EPERM */
	rc = tool(OUT, sizeof(OUT), g_kr, "imgfull", NULL, "verify 0 8192 --pattern zero", 60);
	WRT_CHECK_U64(rc, 4);
	WRT_CHECK(has(OUT, "WR_E_OSD_PERM"));
	set_force(0x1201u, -2); /* READ -> ENOENT: a hole, zeros */
	rc = tool(OUT, sizeof(OUT), g_kr, "imgfull", NULL, "verify 0 8192 --pattern zero", 60);
	WRT_CHECK_U64(rc, 0);
	rc = tool(OUT, sizeof(OUT), g_kr, "img2", NULL, "verify 0 100000 --pattern zero", 60); /* img2 holds data from the shell test; the forced ENOENT */
	WRT_CHECK_U64(rc, 0);                                                                  /* is the answer for every object, so it reads as holes */
	set_force(0x2201u, -2); /* WRITE -> ENOENT is NOT a hole: the write failed */
	rc = tool(OUT, sizeof(OUT), g_kr, "img2", NULL, "--rw write 0 4096 --pattern byte:1", 60);
	WRT_CHECK_U64(rc, 4);
	WRT_CHECK(has(OUT, "status=WR_E_OSD"));
	WRT_CHECK(!has(OUT, "ok=1"));
	set_force(0x2201u, -28); /* WRITE -> ENOSPC */
	rc = tool(OUT, sizeof(OUT), g_kr, "img2", NULL, "--rw write 0 4096 --pattern byte:1", 60);
	WRT_CHECK_U64(rc, 4);
	WRT_CHECK(has(OUT, "WR_E_OSD_NOSPC"));
	set_force(0, 0);
	rc = tool(OUT, sizeof(OUT), g_kr, "img2", NULL, "--rw write 0 4096 --pattern byte:1", 60); /* healthy again */
	WRT_CHECK_U64(rc, 0);
}

/* Numbers and the shell: a leading zero is not octal, a sign or a hex garbage is refused, limits are refused (not truncated), a long line is not
 * run in pieces. */
static void test_numbers_and_shell(void)
{
	static char script[4096 + 256];
	int rc;
	size_t n;

	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "read 010 08", 30);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " result read ok=1 off=10 len=8 "));
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "read 0x10 1K", 30);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " result read ok=1 off=16 len=1024 "));
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "read +5 1", 30);
	WRT_CHECK_U64(rc, 2);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "read 0x 1", 30);
	WRT_CHECK_U64(rc, 2);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "read 1e3 1", 30);
	WRT_CHECK_U64(rc, 2);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "read 99999999999999999999 1", 30);
	WRT_CHECK_U64(rc, 2);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--io-timeout 4294967296 info", 30);
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has(OUT, "timeout"));
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--op-timeout 0 info", 30);
	WRT_CHECK_U64(rc, 2);

	/* limits on a shell line */
	rc = tool(OUT, sizeof(OUT), g_kr, "img", "read 0 1 --depth 0\nread 0 1 --depth 256\nread 0 1 --io-size 0\nread 0 1 --run-timeout 5000\nquit\n", "shell", 60);
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has(OUT, " done 1 rc=2"));
	WRT_CHECK(has(OUT, " done 2 rc=2"));
	WRT_CHECK(has(OUT, " done 3 rc=2"));
	WRT_CHECK(has(OUT, " done 4 rc=0"));

	/* a line that does not fit is refused whole: its tail never runs as a command. One longer than the buffer, with a command after it. */
	n = 0;
	n += (size_t)snprintf(script + n, sizeof(script) - n, "echo first\n");
	memset(script + n, 'x', 3000);
	n += 3000;
	n += (size_t)snprintf(script + n, sizeof(script) - n, " echo injected-long\n");
	n += (size_t)snprintf(script + n, sizeof(script) - n, "echo second\n");
	memset(script + n, 'y', 1100);
	n += 1100;
	n += (size_t)snprintf(script + n, sizeof(script) - n, " echo injected-short\n");
	n += (size_t)snprintf(script + n, sizeof(script) - n, "echo third\nquit\n");
	script[n] = '\0';
	rc = tool(OUT, sizeof(OUT), g_kr, "img", script, "shell", 60);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " echo first"));
	WRT_CHECK(has(OUT, " echo second"));
	WRT_CHECK(has(OUT, " echo third"));
	WRT_CHECK(!has(OUT, "injected"));
	WRT_CHECK(has(OUT, "shell line too long"));
}

static void test_key_types(unsigned type)
{
	int rc;

	srv_start(type);
	write_keyring(g_kr, type, 1, g_b64);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--rw fill 0 1M --pattern rand:9", 60);
	WRT_CHECK_U64(rc, 0);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "verify 0 1M --pattern rand:9", 60);
	WRT_CHECK_U64(rc, 0);
	rc = tool(OUT, sizeof(OUT), g_kr, "img", NULL, "--rw random 100 31", 120);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(!has(OUT, g_b64));
	srv_stop();
}

int main(void)
{
	const char *exe = getenv("WR_RBD");
	char dir[] = "/tmp/wr-rbd-test-XXXXXX";
	uint64_t t0;

	if (exe == NULL || *exe == '\0')
		WRT_SKIP("WR_RBD (the path of the wr-rbd tool) is not set");
	snprintf(g_tool, sizeof(g_tool), "%s", exe);
	if (mkdtemp(dir) == NULL)
		abort();
	snprintf(g_dir, sizeof(g_dir), "%s", dir);
	snprintf(g_kr, sizeof(g_kr), "%s/good.keyring", g_dir);
	snprintf(g_kr_bad, sizeof(g_kr_bad), "%s/bad.keyring", g_dir);

	srv_start(WR_KEY_TYPE_AES256K);
	write_keyring(g_kr, WR_KEY_TYPE_AES256K, 1, g_b64);
	write_keyring(g_kr_bad, WR_KEY_TYPE_AES256K, 99, g_b64_bad);
#define RUN(t)                                                                                    \
	do {                                                                                      \
		t0 = now_ms();                                                                    \
		t;                                                                                \
		fprintf(stderr, "  %-40s %6llu ms\n", #t, (unsigned long long)(now_ms() - t0));   \
	} while (0)
	RUN(test_args_and_refusals());
	RUN(test_basic_io());
	RUN(test_random());
	RUN(test_random_with_restarts());
	RUN(test_shell());
	RUN(test_odd_image());
	RUN(test_numbers_and_shell());
	RUN(test_error_paths());
	srv_stop();
	RUN(test_key_types(WR_KEY_TYPE_AES));
#undef RUN
	{
		char path[256];
		const char *names[] = {"good.keyring", "bad.keyring", "in.bin", "out.bin", "export.bin", "export2.bin", "short.bin", "model.bin", "stdin.txt"};
		unsigned i;

		for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
			snprintf(path, sizeof(path), "%s/%s", g_dir, names[i]);
			(void)unlink(path);
		}
		(void)rmdir(g_dir);
	}
	return wrt_finish();
}
