/* SPDX-License-Identifier: MIT */
/*
 * test_host_tool_rbd_sec.c - the wr-rbd tool (harness/host/tools/wr-rbd.c) in msgr2 SECURE MODE: run as a child process against a whole simulated cluster over REAL
 * TCP sockets on 127.0.0.1 (docs/design/core-architecture.md part D, module tool-modes; ctest name host.tool.rbd.sec). The cluster is the one of test_host_tool_rbd.c, one
 * sim_mon and three sim_osd over one shared sim_store, each with its own listening socket, served by one pthread (all simulator calls under its mutex), but its servers speak
 * secure mode: every byte after AUTH_DONE goes through the independent secure encoder and decoder of the simulators (sim_m2_sec.h), which share no code with the core.
 *
 * Checked, through the tool's output and exit status and, independently, through the simulator's store and the log of secrets the servers issued:
 *   options        --mode / --mode-osd / --require-mode with a bad value, --accel without the CPU feature, a shell command that carries a whole-run option: refused (exit 2 or rc=2), nothing runs
 *   random         `--mode secure --require-mode secure random N SEED` with queue depths 1 and 8 and on an image whose last object is partial: zero differences, the saved model equals
 *                  the bytes the simulator's store holds, conns_secure counts the connections, conns_crc and sec_failures are 0, gcm=portable; both key types
 *   accelerated    the same with --accel: gcm=host with a non-zero gcm_ops and the same result; data written with the hook is verified by a run without it and the other way round
 *   compare        the image compared with a file of its bytes (an `rbd export`): equal, and a flipped byte is a difference (exit 1) that --require-mode does not mask
 *   require-mode   the assertion over the policies: --mode crc / secure / stock / secure-first / crc-first / --mode-osd against servers that allow both: exit 0 when every connection ended
 *                  in the required mode, exit 3 (with the counts in "result require_mode ok=0") when one ended in the other, and when none connected at all
 *   server lists   servers that allow secure only against the default offer: the open is refused, the event names the allowed modes (0x4 = secure), exit 3; --mode secure works; a
 *                  secure-only OSD with a crc monitor works with --mode crc --mode-osd secure and is then neither "all secure" nor "all crc"
 *   shell          a shell on one open secure image: commands, the worst code as exit status, the stats line at the end
 *   restarts       OSDs restarted every few milliseconds during a secure `random`: every reconnect is a new secure connection with a new secret, the data still right
 *   output         no key text and no part of any connection secret (hex) anywhere in the output of any run
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sim_osd.h"
#include "sim_osd_int.h"
#include "wrt.h"
#include "wrt_mapgen.h"

#include "../host/wrl_gcm_aesni.c"

#define NOSD 3u
#define SMAX 24u
#define OUTCAP (1024u * 1024u)
#define POOL 1
#define IMG_ORDER 16u
#define IMG_SIZE (2u << 20)
#define IMG3_ORDER 14u /* 16 KiB objects, and a size that is not a whole number of them (nor of a sector): the last object is partial */
#define IMG3_SIZE (40u * 16384u + 1233u)

#define ALLOW_CRC 1u
#define ALLOW_SECURE 2u

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
	uint64_t flip_every_ms, flip_next;       /* 0 = never: every period the next secure frame of every secure OSD connection gets a bit flipped */
	unsigned flip_budget, n_flips;           /* flips left to do, flips that found a secure connection to damage */
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
			pf[n].events = (short)(POLLIN | (S.c[i].out_len > S.c[i].out_off ? POLLOUT : 0));
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
		if (S.flip_every_ms != 0u && S.flip_budget != 0u && now_ms() >= S.flip_next) {
			unsigned k, armed = 0;

			for (k = 0; k < SMAX; k++) {
				sim_m2 *m;

				if (S.c[k].fd < 0 || S.c[k].oc == NULL)
					continue;
				m = S.c[k].oc->m2;
				if (!sim_m2_is_secure(m))
					continue;
				memset(&m->cfg.f.sec, 0, sizeof(m->cfg.f.sec));
				m->cfg.f.sec.mut_frame = m->n_tx_frames + 1u; /* the next frame this server sends: one bit of part 1's ciphertext, so the tag cannot match */
				m->cfg.f.sec.mut.mask = SIM_SEC_M_FLIP;
				m->cfg.f.sec.mut.flip_part = 1;
				m->cfg.f.sec.mut.flip_region = SIM_SEC_R_RAW;
				m->cfg.f.sec.mut.flip_byte = 3;
				m->cfg.f.sec.mut.flip_bit = 0;
				armed++;
			}
			if (armed != 0u) {
				S.n_flips++;
				S.flip_budget--;
			}
			S.flip_next = now_ms() + S.flip_every_ms;
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

/* The allowed connection modes of a simulated server (a mask of ALLOW_*), in the order crc, secure. The simulators copy their list into every connection they accept, so a
 * list changed under the lock applies to the connections made afterwards. */
static void allow_set(sim_m2_cfg *m2, unsigned allow)
{
	unsigned n = 0;

	if (allow & ALLOW_CRC)
		m2->modes[n++] = SIM_M2_MODE_CRC;
	if (allow & ALLOW_SECURE)
		m2->modes[n++] = SIM_M2_MODE_SECURE;
	m2->n_modes = n;
}

static void servers_allow(unsigned mon_allow, unsigned osd_allow)
{
	unsigned i;

	s_lock();
	allow_set(&S.mon->cfg.m2, mon_allow);
	for (i = 0; i < NOSD; i++)
		allow_set(&S.osd[i]->cfg.m2, osd_allow);
	s_unlock();
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
	allow_set(&mc.m2, ALLOW_CRC | ALLOW_SECURE);
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
		allow_set(&oc.m2, ALLOW_CRC | ALLOW_SECURE); /* a stock OSD allows both */
		S.osd[i] = sim_osd_new(&oc);
		if (S.osd[i] == NULL)
			abort();
	}
	if (image_make("img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) != 0 || image_make("img3", "abc126", IMG3_SIZE, IMG3_ORDER, 0x21, -1) != 0)
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
		uint64_t len = size - i * obj < obj ? size - i * obj : obj;

		snprintf(oid, sizeof(oid), "rbd_data.%s.%016llx", id, (unsigned long long)i);
		if (sim_store_read(S.store, POOL, oid, 0, out + i * obj, (size_t)len, &exists) != WR_OK)
			memset(out + i * obj, 0xEE, (size_t)len);
	}
	s_unlock();
}

/* The secrets the servers issued so far: how many, and whether any two are equal. */
static unsigned secrets_issued(int *distinct)
{
	const sim_sec_log *logs[1u + NOSD];
	unsigned n = 0, i, j, a, b, total = 0;

	s_lock();
	logs[n++] = sim_mon_secrets(S.mon);
	for (i = 0; i < NOSD; i++)
		logs[n++] = sim_osd_secrets(S.osd[i]);
	*distinct = 1;
	for (i = 0; i < n; i++) {
		total += logs[i]->n;
		if (logs[i]->kept != logs[i]->n || !sim_sec_log_distinct(logs[i]))
			*distinct = 0;
		for (j = i + 1u; j < n; j++)
			for (a = 0; a < logs[i]->kept; a++)
				for (b = 0; b < logs[j]->kept; b++)
					if (logs[i]->len[a] == logs[j]->len[b] && memcmp(logs[i]->secret[a], logs[j]->secret[b], logs[i]->len[a]) == 0)
						*distinct = 0;
	}
	s_unlock();
	return total;
}

/* No hex text of any 8-byte window of any secret any server issued in the output (a printed secret would show as hex). */
static int no_secret_hex(const char *out)
{
	const sim_sec_log *logs[1u + NOSD];
	unsigned n = 0, i, a, k;
	int ok = 1;

	s_lock();
	logs[n++] = sim_mon_secrets(S.mon);
	for (i = 0; i < NOSD; i++)
		logs[n++] = sim_osd_secrets(S.osd[i]);
	for (i = 0; i < n && ok; i++) {
		for (a = 0; a < logs[i]->kept && ok; a++) {
			for (k = 0; k + 8u <= logs[i]->len[a] && ok; k += 4u) {
				char hex[17];
				unsigned q;

				for (q = 0; q < 8u; q++)
					snprintf(hex + 2u * q, 3, "%02x", logs[i]->secret[a][k + q]);
				if (strstr(out, hex) != NULL)
					ok = 0;
			}
		}
	}
	s_unlock();
	return ok;
}

/* ---- running the tool -------------------------------------------------------------------------------------------- */

static char g_tool[512];
static char g_dir[128];
static char g_kr[192], g_b64[128];

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

#define MAXARGS 48
/* Common arguments for the simulated cluster + the given extras. */
static int tool(char *out, size_t cap, const char *image, const char *input, const char *extra, unsigned secs)
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
	args[n++] = (char *)g_kr;
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

/* The key text and the secrets are nowhere in the output of any run. */
static void check_out_clean(const char *out)
{
	WRT_CHECK(!has(out, g_b64));
	WRT_CHECK(no_secret_hex(out));
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

static char OUT[1 << 17];
static int g_have_hook;

/* ---- the tests ------------------------------------------------------------------------------------------------ */

static void test_args_and_refusals(void)
{
	int rc;

	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode bogus info", 30);
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has(OUT, "--mode and --mode-osd take crc, crc-first, secure-first, secure or stock"));
	WRT_CHECK(!has(OUT, "event MON_SESSION_UP")); /* nothing connected */
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode secure --mode-osd 3 info", 30);
	WRT_CHECK_U64(rc, 2);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode-osd SECURE info", 30); /* the words are exact: no case folding, no abbreviation */
	WRT_CHECK_U64(rc, 2);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--require-mode both info", 30);
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has(OUT, "--require-mode takes secure or crc"));
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode", 30); /* a missing value */
	WRT_CHECK_U64(rc, 2);
	if (!g_have_hook) { /* no CPU feature: --accel is refused (exit 2), never silently the portable code */
		rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode secure --accel info", 30);
		WRT_CHECK_U64(rc, 2);
		WRT_CHECK(has(OUT, "--accel"));
		WRT_CHECK(!has(OUT, "event MON_SESSION_UP"));
	}
	/* the defaults of every earlier run are unchanged: crc, one monitor and its OSD connections, the new fields in the stats line */
	rc = tool(OUT, sizeof(OUT), "img", NULL, "info", 30);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK_U64(field_u(OUT, " conns_secure="), 0);
	WRT_CHECK(field_u(OUT, " conns_crc=") >= 2u);
	WRT_CHECK_U64(field_u(OUT, " sec_failures="), 0);
	WRT_CHECK(has(OUT, " accel=0 gcm=portable gcm_ops=0"));
	WRT_CHECK(!has(OUT, "result require_mode")); /* only with --require-mode */
	check_out_clean(OUT);
}

/* random against the model; then the saved model is compared with what the simulator's store holds */
static void random_run(const char *image, const char *id, uint8_t order, uint64_t size, const char *extra, uint64_t seed, unsigned n_ops, const char *label)
{
	static uint8_t img[IMG_SIZE > IMG3_SIZE ? IMG_SIZE : IMG3_SIZE];
	char fpath[256], cmd[640];
	uint8_t *model;
	size_t n = 0;
	int rc;

	snprintf(fpath, sizeof(fpath), "%s/model.bin", g_dir);
	snprintf(cmd, sizeof(cmd), "--rw %s random %u %llu --save %s", extra, n_ops, (unsigned long long)seed, fpath);
	rc = tool(OUT, sizeof(OUT), image, NULL, cmd, 240);
	if (rc != 0)
		fprintf(stderr, "random %s: exit %d, output follows\n%.3000s\n", label, rc, OUT);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " result random ok=1 "));
	WRT_CHECK_U64(field_u(OUT, "read_mismatches="), 0);
	WRT_CHECK_U64(field_u(OUT, "final_diff_bytes="), 0);
	WRT_CHECK_U64(field_u(OUT, " errors="), 0);
	WRT_CHECK_U64(field_u(OUT, " ops="), n_ops);
	WRT_CHECK_U64(field_u(OUT, " barrier_violations="), 0);
	WRT_CHECK_U64(field_u(OUT, " bad_completions="), 0);
	model = tmp_file_read(fpath, &n);
	WRT_CHECK(model != NULL && n > 0 && n <= size);
	if (model != NULL && n > 0 && n <= size) {
		store_image(id, order, size, img);
		WRT_CHECK(memcmp(img, model, n) == 0); /* the cluster holds what the model says (the model's region): zero differences */
	}
	free(model);
	(void)unlink(fpath);
	check_out_clean(OUT);
}

/* The stats line says: all connections of this run were secure (counted), none failed on a secret / nonce / tag. */
static void expect_all_secure(const char *hook)
{
	WRT_CHECK(field_u(OUT, " conns_secure=") >= 3u); /* the monitor and at least two OSD sessions */
	WRT_CHECK_U64(field_u(OUT, " conns_crc="), 0);
	WRT_CHECK_U64(field_u(OUT, " sec_failures="), 0);
	WRT_CHECK(has(OUT, "result require_mode ok=1 wanted=secure"));
	if (hook != NULL && strcmp(hook, "host") == 0) {
		WRT_CHECK(has(OUT, " accel=1 gcm=host gcm_ops="));
		WRT_CHECK(field_u(OUT, " gcm_ops=") > 0u);
	} else {
		WRT_CHECK(has(OUT, " accel=0 gcm=portable gcm_ops=0"));
	}
}

static void test_random_secure(void)
{
	int distinct = 0;
	unsigned issued;

	random_run("img", "abc123", IMG_ORDER, IMG_SIZE, "--mode secure --require-mode secure --depth 1 --model-bytes 524288 --max-len 90000", 1, 80, "depth 1");
	expect_all_secure(NULL);
	random_run("img", "abc123", IMG_ORDER, IMG_SIZE, "--mode secure --require-mode secure --depth 8 --model-bytes 1048576 --max-len 150000", 2, 120, "depth 8");
	expect_all_secure(NULL);
	/* an image whose last object is partial (the secure framing at odd lengths and pad16 edges), with an unusual I/O size */
	random_run("img3", "abc126", IMG3_ORDER, IMG3_SIZE, "--mode secure --require-mode secure --depth 4 --io-size 4096 --model-bytes 262144 --max-len 60000", 3, 100,
		   "odd image");
	expect_all_secure(NULL);
	/* the stock policy and the per-role override: the monitor secure, the OSDs crc (they are 'neither all secure nor all crc': no require) */
	random_run("img", "abc123", IMG_ORDER, IMG_SIZE, "--mode stock --depth 4 --model-bytes 262144 --max-len 60000", 4, 60, "stock");
	WRT_CHECK(field_u(OUT, " conns_secure=") >= 1u && field_u(OUT, " conns_crc=") >= 2u);
	random_run("img", "abc123", IMG_ORDER, IMG_SIZE, "--mode secure --mode-osd crc --depth 4 --model-bytes 262144 --max-len 60000", 5, 60, "secure monitor, crc OSDs");
	WRT_CHECK(field_u(OUT, " conns_secure=") >= 1u && field_u(OUT, " conns_crc=") >= 2u);
	issued = secrets_issued(&distinct);
	WRT_CHECK(issued >= 10u);
	WRT_CHECK(distinct); /* every connection of every run got its own secret */
}

static void test_accel(void)
{
	char cmd[512];
	int rc;

	if (!g_have_hook) {
		fprintf(stderr, "note: no AES-NI / PCLMULQDQ here: the accelerated runs are skipped\n");
		return;
	}
	random_run("img", "abc123", IMG_ORDER, IMG_SIZE, "--mode secure --accel --require-mode secure --depth 8 --model-bytes 1048576 --max-len 150000", 11, 120,
		   "accelerated");
	expect_all_secure("host");
	/* written with the hook, verified without it (and the other way round): the two implementations agree with each other, not only with the simulator */
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--rw --mode secure --accel --require-mode secure fill 0 524288 --pattern rand:21", 120);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " accel=1 gcm=host gcm_ops="));
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode secure --require-mode secure verify 0 524288 --pattern rand:21", 120);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " accel=0 gcm=portable gcm_ops=0"));
	snprintf(cmd, sizeof(cmd), "--rw --mode secure --require-mode secure fill 524288 262144 --pattern rand:22");
	rc = tool(OUT, sizeof(OUT), "img", NULL, cmd, 120);
	WRT_CHECK_U64(rc, 0);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode secure --accel --require-mode secure verify 524288 262144 --pattern rand:22", 120);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " accel=1 gcm=host gcm_ops="));
	/* a hook that is installed but never used (a crc run) says so */
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode crc --accel --require-mode crc info", 60);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " accel=1 gcm=portable gcm_ops=0"));
	check_out_clean(OUT);
}

static void test_compare(void)
{
	static uint8_t img[IMG_SIZE];
	char path[256];
	int rc;

	rc = tool(OUT, sizeof(OUT), "img", NULL, "--rw --mode secure --require-mode secure fill 0 2097152 --pattern rand:31", 120);
	WRT_CHECK_U64(rc, 0);
	store_image("abc123", IMG_ORDER, IMG_SIZE, img);
	WRT_CHECK(tmp_file_write("export.bin", img, IMG_SIZE, path, sizeof(path)) == 0);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode secure --require-mode secure compare " , 60); /* no file: a usage error, not a pass */
	WRT_CHECK(rc != 0);
	{
		char cmd[512];

		snprintf(cmd, sizeof(cmd), "--mode secure --require-mode secure compare %s", path);
		rc = tool(OUT, sizeof(OUT), "img", NULL, cmd, 120);
		WRT_CHECK_U64(rc, 0);
		WRT_CHECK(has(OUT, " result compare ok=1 "));
		WRT_CHECK_U64(field_u(OUT, " diffs="), 0);
		expect_all_secure(NULL);
		/* one byte of the export differs: a difference (exit 1) with its offset; the mode assertion held, and a failing one would not turn exit 1 into 3 */
		img[1234567] ^= 0x40;
		WRT_CHECK(tmp_file_write("export.bin", img, IMG_SIZE, path, sizeof(path)) == 0);
		rc = tool(OUT, sizeof(OUT), "img", NULL, cmd, 120);
		WRT_CHECK_U64(rc, 1);
		WRT_CHECK(has(OUT, " result compare ok=0 "));
		WRT_CHECK(has(OUT, "result require_mode ok=1 wanted=secure"));
		snprintf(cmd, sizeof(cmd), "--mode crc --require-mode secure compare %s", path); /* both findings: the data one wins the exit code, the line has both */
		rc = tool(OUT, sizeof(OUT), "img", NULL, cmd, 120);
		WRT_CHECK_U64(rc, 1);
		WRT_CHECK(has(OUT, "result require_mode ok=0 wanted=secure"));
	}
	check_out_clean(OUT);
	(void)unlink(path);
}

/* One run of the tool with options; the exit code and what the require line says about the counts. */
static void require_case(const char *opts, int want_rc, const char *want_line)
{
	char cmd[512];
	int rc;

	snprintf(cmd, sizeof(cmd), "%s info", opts);
	rc = tool(OUT, sizeof(OUT), "img", NULL, cmd, 60);
	if (rc != want_rc)
		fprintf(stderr, "require case '%s': exit %d, wanted %d; output follows\n%.2000s\n", opts, rc, want_rc, OUT);
	WRT_CHECK_U64(rc, want_rc);
	WRT_CHECK(has(OUT, want_line));
	if (want_rc == 3 && has(OUT, " result info ok=1")) /* the command worked: only the assertion failed */
		WRT_CHECK(has(OUT, "--require-mode"));
	check_out_clean(OUT);
}

static void test_require_mode(void)
{
	/* the servers allow both modes: the policy decides */
	require_case("--mode secure --require-mode secure", 0, "result require_mode ok=1 wanted=secure");
	require_case("--mode crc --require-mode crc", 0, "result require_mode ok=1 wanted=crc");
	require_case("--require-mode crc", 0, "result require_mode ok=1 wanted=crc"); /* the default policy is crc */
	require_case("--mode crc-first --require-mode crc", 0, "result require_mode ok=1 wanted=crc");
	require_case("--mode secure-first --require-mode secure", 0, "result require_mode ok=1 wanted=secure");
	require_case("--mode secure-first --mode-osd secure --require-mode secure", 0, "result require_mode ok=1 wanted=secure");
	require_case("--mode crc --require-mode secure", 3, "result require_mode ok=0 wanted=secure conns_secure=0 conns_crc=");
	require_case("--mode secure --require-mode crc", 3, "result require_mode ok=0 wanted=crc conns_secure=");
	require_case("--mode crc-first --require-mode secure", 3, "result require_mode ok=0 wanted=secure conns_secure=0");
	/* a mix: the monitor secure and the OSDs crc is neither: both assertions fail, each with the counts that broke it */
	require_case("--mode stock --require-mode secure", 3, "result require_mode ok=0 wanted=secure");
	WRT_CHECK(field_u(OUT, " conns_secure=") >= 1u && field_u(OUT, " conns_crc=") >= 1u); /* the monitor secure, the OSD that serves the header crc */
	require_case("--mode stock --require-mode crc", 3, "result require_mode ok=0 wanted=crc");
	require_case("--mode secure --mode-osd crc --require-mode secure", 3, "result require_mode ok=0 wanted=secure");
	require_case("--mode crc --mode-osd secure --require-mode crc", 3, "result require_mode ok=0 wanted=crc");
	/* the option stands before or after the command, like every flag; and the assertion holds for the whole run, not for one command */
	{
		int rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode secure info --require-mode secure", 60);

		WRT_CHECK_U64(rc, 0);
		WRT_CHECK(has(OUT, "result require_mode ok=1 wanted=secure"));
	}
}

static void test_server_lists(void)
{
	int rc;

	/* every server allows secure only: the default offer (crc) is refused, the event says what the servers allow */
	servers_allow(ALLOW_SECURE, ALLOW_SECURE);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--timeout 2500 info", 60);
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(OUT, "event AUTH_FAILED status=WR_E_M2_BAD_METHOD"));
	WRT_CHECK(has(OUT, "allowed_modes=0x4")); /* bit v = mode v: 2 = secure */
	WRT_CHECK(has(OUT, " result open ok=0 "));
	WRT_CHECK_U64(field_u(OUT, " conns_secure="), 0);
	WRT_CHECK_U64(field_u(OUT, " conns_crc="), 0);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--timeout 2500 --require-mode secure info", 60); /* nothing connected: the assertion does not pass vacuously */
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(OUT, "result require_mode ok=0 wanted=secure conns_secure=0 conns_crc=0"));
	check_out_clean(OUT);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode secure --require-mode secure info", 60);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(OUT, " result info ok=1 "));
	/* the other way round: crc only servers and a secure-only client: allowed modes {crc} = 0x2 */
	servers_allow(ALLOW_CRC, ALLOW_CRC);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode secure --timeout 2500 info", 60);
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(OUT, "event AUTH_FAILED status=WR_E_M2_BAD_METHOD"));
	WRT_CHECK(has(OUT, "allowed_modes=0x2"));
	/* a crc monitor with secure-only OSDs: --mode crc --mode-osd secure is the only offer that works */
	servers_allow(ALLOW_CRC, ALLOW_SECURE);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--rw --mode crc --mode-osd secure fill 0 262144 --pattern rand:41", 90);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(field_u(OUT, " conns_secure=") >= 2u && field_u(OUT, " conns_crc=") >= 1u);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode crc --mode-osd secure --require-mode secure verify 0 262144 --pattern rand:41", 90);
	WRT_CHECK_U64(rc, 3); /* the monitor was crc */
	WRT_CHECK(has(OUT, " result verify ok=1 "));
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode crc verify 0 262144 --pattern zero --timeout 2500", 60); /* crc to secure-only OSDs: the OSDs refuse */
	WRT_CHECK(rc != 0);
	servers_allow(ALLOW_CRC | ALLOW_SECURE, ALLOW_CRC | ALLOW_SECURE);
	check_out_clean(OUT);
}

static void test_shell(void)
{
	int rc;
	const char *script = "echo hello secure\n"
			     "fill 0 262144 --pattern rand:51\n"
			     "verify 0 262144 --pattern rand:51\n"
			     "verify 0 262144 --pattern rand:52\n"
			     "info --mode crc\n"
			     "info --accel\n"
			     "info --mode secure --require-mode secure\n"
			     "sleep 20\n"
			     "quit\n";

	rc = tool(OUT, sizeof(OUT), "img", script, "--rw --mode secure --require-mode secure shell", 120);
	WRT_CHECK_U64(rc, 2); /* the worst command: a whole-run option inside the shell */
	WRT_CHECK(has(OUT, " shell ready"));
	WRT_CHECK(has(OUT, "done 2 rc=0"));
	WRT_CHECK(has(OUT, "done 3 rc=0"));
	WRT_CHECK(has(OUT, "done 4 rc=1")); /* the wrong pattern */
	WRT_CHECK(has(OUT, "done 5 rc=2")); /* 'info --mode crc' on a shell line: refused, nothing ran */
	WRT_CHECK(has(OUT, "done 6 rc=2"));
	WRT_CHECK(has(OUT, "done 7 rc=0")); /* the same values as the command line said are no change: accepted */
	WRT_CHECK(has(OUT, "apply to the whole run"));
	WRT_CHECK(has(OUT, "result require_mode ok=1 wanted=secure")); /* the shell's run was secure all through */
	WRT_CHECK(field_u(OUT, " conns_secure=") >= 3u);
	WRT_CHECK_U64(field_u(OUT, " conns_crc="), 0);
	check_out_clean(OUT);
}

static void test_restarts(void)
{
	unsigned before, issued0, issued1;
	int distinct = 0;
	unsigned conns;

	issued0 = secrets_issued(&distinct);
	s_lock();
	S.restart_every_ms = 250;
	S.restart_budget = 8;
	S.next_restart = now_ms() + 250;
	before = S.n_restarts;
	s_unlock();
	random_run("img", "abc123", IMG_ORDER, IMG_SIZE, "--mode secure --require-mode secure --depth 8 --op-timeout 3000 --delay-ms 25 --model-bytes 524288 --max-len 60000", 6,
		   160, "restarts");
	s_lock();
	S.restart_every_ms = 0;
	fprintf(stderr, "  OSD restarts during the run: %u\n", S.n_restarts - before);
	WRT_CHECK(S.n_restarts - before >= 3u); /* the faults really happened */
	s_unlock();
	conns = (unsigned)field_u(OUT, " conns_secure=");
	WRT_CHECK(conns >= 3u + 3u);          /* every cut OSD connection was dialled again, and each new one is a secure connection */
	WRT_CHECK_U64(field_u(OUT, " conns_crc="), 0);
	issued1 = secrets_issued(&distinct);
	WRT_CHECK(issued1 >= issued0 + conns); /* a new secret for each of them (rekeying is reconnecting) ... */
	WRT_CHECK(distinct);                   /* ... and none repeated */
}

/* A frame whose tag does not verify (the server flips a bit) is a secure-mode failure the engine counts, redials after and survives with the right data; the tool
 * must not let `--require-mode secure` read it as a clean secure run: exit 3, ok=0, sec_failures in the line, while the data check itself still says ok=1. */
static void test_tag_failure(void)
{
	char fpath[256], cmd[640];
	unsigned before;
	int rc;

	s_lock();
	S.flip_every_ms = 150;
	S.flip_budget = 6;
	S.flip_next = now_ms() + 150;
	before = S.n_flips;
	s_unlock();
	snprintf(fpath, sizeof(fpath), "%s/model.bin", g_dir);
	snprintf(cmd, sizeof(cmd), "--rw --mode secure --require-mode secure --depth 8 --op-timeout 3000 --delay-ms 25 --model-bytes 524288 --max-len 60000 random 160 12 --save %s",
		 fpath);
	rc = tool(OUT, sizeof(OUT), "img", NULL, cmd, 240);
	s_lock();
	S.flip_every_ms = 0;
	WRT_CHECK(S.n_flips - before >= 1u); /* the damage really happened (the run takes at least 160 x 25 ms) */
	s_unlock();
	if (rc != 3)
		fprintf(stderr, "tag failure: exit %d, output follows\n%.3000s\n", rc, OUT);
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(OUT, " result random ok=1 ")); /* the engine redialled: no wrong byte, no failed request */
	WRT_CHECK_U64(field_u(OUT, "read_mismatches="), 0);
	WRT_CHECK_U64(field_u(OUT, "final_diff_bytes="), 0);
	WRT_CHECK(field_u(OUT, " sec_failures=") >= 1u);
	WRT_CHECK_U64(field_u(OUT, " conns_crc="), 0);
	WRT_CHECK(has(OUT, "result require_mode ok=0 wanted=secure"));
	check_out_clean(OUT);
	(void)unlink(fpath);
}

static void test_key_types(unsigned type)
{
	int rc, distinct = 0;

	srv_start(type);
	write_keyring(g_kr, type, 1, g_b64);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--rw --mode secure --require-mode secure fill 0 524288 --pattern rand:9", 120);
	WRT_CHECK_U64(rc, 0);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--mode secure --require-mode secure verify 0 524288 --pattern rand:9", 120);
	WRT_CHECK_U64(rc, 0);
	rc = tool(OUT, sizeof(OUT), "img", NULL, "--rw --mode secure --require-mode secure random 60 31 --model-bytes 262144 --max-len 60000", 120);
	WRT_CHECK_U64(rc, 0);
	expect_all_secure(NULL);
	check_out_clean(OUT);
	WRT_CHECK(secrets_issued(&distinct) >= 9u && distinct);
	srv_stop();
}

int main(void)
{
	const char *exe = getenv("WR_RBD");
	char dir[] = "/tmp/wr-rbd-sec-test-XXXXXX";
	uint64_t t0;

	if (exe == NULL || *exe == '\0')
		WRT_SKIP("WR_RBD (the path of the wr-rbd tool) is not set");
	snprintf(g_tool, sizeof(g_tool), "%s", exe);
	if (mkdtemp(dir) == NULL)
		abort();
	snprintf(g_dir, sizeof(g_dir), "%s", dir);
	snprintf(g_kr, sizeof(g_kr), "%s/good.keyring", g_dir);
	g_have_hook = wrl_gcm_aesni_available();

	srv_start(WR_KEY_TYPE_AES256K);
	write_keyring(g_kr, WR_KEY_TYPE_AES256K, 1, g_b64);
#define RUN(t)                                                                                    \
	do {                                                                                      \
		t0 = now_ms();                                                                    \
		t;                                                                                \
		fprintf(stderr, "  %-40s %6llu ms\n", #t, (unsigned long long)(now_ms() - t0));   \
	} while (0)
	RUN(test_args_and_refusals());
	RUN(test_random_secure());
	RUN(test_accel());
	RUN(test_compare());
	RUN(test_require_mode());
	RUN(test_server_lists());
	RUN(test_shell());
	RUN(test_restarts());
	RUN(test_tag_failure());
	srv_stop();
	RUN(test_key_types(WR_KEY_TYPE_AES));
#undef RUN
	{
		char path[256];
		const char *names[] = {"good.keyring", "export.bin", "model.bin", "stdin.txt"};
		unsigned i;

		for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
			snprintf(path, sizeof(path), "%s/%s", g_dir, names[i]);
			(void)unlink(path);
		}
		(void)rmdir(g_dir);
	}
	return wrt_finish();
}
