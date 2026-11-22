/* SPDX-License-Identifier: MIT */
/*
 * cmp_rig.h - what the tests of the krbd comparison (test_host_cmp.c, test_host_tool_krbdcmp.c) share: a whole simulated cluster over REAL TCP
 * sockets on 127.0.0.1 (one sim_mon, three sim_osd over one shared sim_store, one pthread serving all of them under one mutex, the technique of
 * test_host_tool_rbd.c), the images it holds, and an in-process "block device" for the engine: pread / pwrite / discard / write-zeroes / flush
 * implemented straight on the simulator's object store with the geometry the DEVICE believes (which a test may make different from the core's),
 * plus the knobs that make it misbehave (flip a byte, fail, answer short, be slow or hang).
 *
 * Written from the architecture note 33.6; it shares no code with wrl_cmp.c: the device decides for itself what a discard does and the checks of
 * the tests read the store directly.
 */
#ifndef CMP_RIG_H
#define CMP_RIG_H

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
#include "wrt.h"
#include "wrt_mapgen.h"

#define CR_NOSD 3u
#define CR_SMAX 24u
#define CR_OUTCAP (1024u * 1024u)
#define CR_POOL 1

static uint64_t cr_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ---- keys -------------------------------------------------------------------------------------------------------- */

static void cr_mkkey(wr_key *k, unsigned type, uint8_t salt)
{
	uint8_t raw[32];
	size_t i, len = type == WR_KEY_TYPE_AES ? 16u : 32u;

	for (i = 0; i < len; i++)
		raw[i] = (uint8_t)(salt + i * 7u);
	if (wr_key_from_raw(k, type, raw, len) != WR_OK)
		abort();
}

static void cr_b64_put(char *out, size_t *o, const uint8_t *in, size_t n)
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

/* A keyring file for the key cr_mkkey(salt) builds; b64_out gets the key text (so a test can check it never shows up in an output). */
WRT_UNUSED static void cr_write_keyring(const char *path, unsigned type, uint8_t salt, char *b64_out)
{
	uint8_t blob[2 + 8 + 2 + 32];
	size_t len = type == WR_KEY_TYPE_AES ? 16u : 32u, i, o = 0;
	FILE *f;

	memset(blob, 0, sizeof(blob));
	blob[0] = (uint8_t)type;
	blob[10] = (uint8_t)len;
	for (i = 0; i < len; i++)
		blob[12 + i] = (uint8_t)(salt + i * 7u);
	cr_b64_put(b64_out, &o, blob, 12u + len);
	b64_out[o] = '\0';
	f = fopen(path, "w");
	if (f == NULL)
		abort();
	(void)chmod(path, 0600);
	fprintf(f, "[client.winrbd]\n\tkey = %s\n", b64_out);
	fclose(f);
}

/* ---- the simulated cluster ---------------------------------------------------------------------------------------- */

typedef struct cr_conn {
	int fd;
	int who; /* 0 = monitor, 1 + i = OSD i */
	sim_mon_conn *mc;
	sim_osd_conn *oc;
	uint8_t *out;
	size_t out_len, out_off;
} cr_conn;

typedef struct cr_srv {
	int lfd[1u + CR_NOSD];
	uint16_t port[1u + CR_NOSD];
	pthread_t th;
	pthread_mutex_t mu;
	volatile int stop;
	sim_mon *mon;
	sim_store *store;
	sim_osd *osd[CR_NOSD];
	cr_conn c[CR_SMAX];
	wrt_mg_map desc;
	uint8_t monmap[512];
	size_t monmap_len;
} cr_srv;

static cr_srv CR;

static void cr_lock(void)
{
	pthread_mutex_lock(&CR.mu);
}
static void cr_unlock(void)
{
	pthread_mutex_unlock(&CR.mu);
}

static int cr_listen_on(uint16_t *port)
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
static void cr_load_monmap(uint16_t port)
{
	static const uint8_t from[8] = {0x02, 0x00, 0x0c, 0xe4, 0x0a, 0x4d, 0x00, 0x0a};
	wrt_json j;
	uint8_t *b = NULL;
	size_t n = 0, i, hits = 0;

	if (wrt_json_load_vec(&j, "monclient/mmonmap-e3.json") != 0)
		abort();
	if (wrt_json_get_hex(&j, wrt_json_root(&j), "monmap_hex", &b, &n) != 0 || n > sizeof(CR.monmap))
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
	memcpy(CR.monmap, b, n);
	CR.monmap_len = n;
	free(b);
	wrt_json_free(&j);
}

static void cr_conn_drop(cr_conn *c)
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

static void cr_accept(unsigned who)
{
	int fd = accept(CR.lfd[who], NULL, NULL), one = 1;
	unsigned i;

	if (fd < 0)
		return;
	for (i = 0; i < CR_SMAX && CR.c[i].fd >= 0; i++) {
	}
	if (i == CR_SMAX) {
		close(fd);
		return;
	}
	(void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, (socklen_t)sizeof(one));
	memset(&CR.c[i], 0, sizeof(CR.c[i]));
	CR.c[i].fd = fd;
	CR.c[i].who = (int)who;
	CR.c[i].out = (uint8_t *)malloc(CR_OUTCAP);
	if (who == 0u)
		CR.c[i].mc = sim_mon_accept(CR.mon);
	else
		CR.c[i].oc = sim_osd_accept(CR.osd[who - 1u]);
	if (CR.c[i].out == NULL || (CR.c[i].mc == NULL && CR.c[i].oc == NULL))
		cr_conn_drop(&CR.c[i]);
}

static void cr_serve(cr_conn *c, short rev)
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
			cr_conn_drop(c);
			return;
		}
	}
	if (c->out_off == c->out_len)
		c->out_off = c->out_len = 0;
	if (c->out_len < CR_OUTCAP)
		c->out_len += c->mc != NULL ? sim_mon_drain(c->mc, c->out + c->out_len, CR_OUTCAP - c->out_len)
					    : sim_osd_drain(c->oc, c->out + c->out_len, CR_OUTCAP - c->out_len);
	if (c->out_len > c->out_off) {
		ssize_t w = send(c->fd, c->out + c->out_off, c->out_len - c->out_off, MSG_NOSIGNAL | MSG_DONTWAIT);

		if (w > 0)
			c->out_off += (size_t)w;
		else if (w < 0 && errno != EAGAIN && errno != EINTR) {
			cr_conn_drop(c);
			return;
		}
	}
	closed = c->mc != NULL ? sim_mon_closed(c->mc) : sim_osd_closed(c->oc);
	if (closed && c->out_off == c->out_len)
		cr_conn_drop(c);
}

static void *cr_srv_main(void *arg)
{
	(void)arg;
	while (!CR.stop) {
		struct pollfd pf[1u + CR_NOSD + CR_SMAX];
		unsigned i, n = 0, nl = 1u + CR_NOSD;
		int idx[CR_SMAX];

		for (i = 0; i < nl; i++) {
			pf[n].fd = CR.lfd[i];
			pf[n].events = POLLIN;
			pf[n].revents = 0;
			n++;
		}
		cr_lock();
		for (i = 0; i < CR_SMAX; i++) {
			if (CR.c[i].fd < 0)
				continue;
			pf[n].fd = CR.c[i].fd;
			pf[n].events = POLLIN | (CR.c[i].out_len > CR.c[i].out_off ? POLLOUT : 0);
			pf[n].revents = 0;
			idx[n - nl] = (int)i;
			n++;
		}
		cr_unlock();
		(void)poll(pf, n, 2);
		cr_lock();
		for (i = 0; i < nl; i++)
			if (pf[i].revents & POLLIN)
				cr_accept(i);
		for (i = nl; i < n; i++) {
			cr_conn *c = &CR.c[idx[i - nl]];

			if (c->fd >= 0 && c->fd == pf[i].fd)
				cr_serve(c, pf[i].revents);
		}
		for (i = 0; i < CR_SMAX; i++) /* output the simulator produced on its own */
			if (CR.c[i].fd >= 0)
				cr_serve(&CR.c[i], 0);
		cr_unlock();
	}
	return NULL;
}

/* An image of pool 1 in the store. prefix NULL = rbd_data.<id>. */
static int cr_image_make(const char *name, const char *id, uint64_t size, uint8_t order, uint64_t features, const char *prefix)
{
	sim_rbd_image_cfg c;
	int rc;

	memset(&c, 0, sizeof(c));
	c.pool = CR_POOL;
	c.name = name;
	c.id = id;
	c.size = size;
	c.order = order;
	c.features = features;
	c.data_pool = -1;
	c.prefix = prefix;
	cr_lock();
	rc = sim_rbd_image_create(CR.store, &c) == WR_OK ? 0 : -1;
	cr_unlock();
	return rc;
}

static void cr_srv_start(unsigned key_type)
{
	sim_mon_cfg mc;
	wrt_mg_cluster_spec cs;
	wrt_mg_buf b;
	unsigned i;
	uint32_t epoch;

	memset(&CR, 0, sizeof(CR));
	memset(&b, 0, sizeof(b));
	pthread_mutex_init(&CR.mu, NULL);
	for (i = 0; i < CR_SMAX; i++)
		CR.c[i].fd = -1;
	for (i = 0; i < 1u + CR_NOSD; i++)
		CR.lfd[i] = cr_listen_on(&CR.port[i]);
	cr_load_monmap(CR.port[0]);
	sim_mon_cfg_default(&mc);
	cr_mkkey(&mc.key, key_type, 1);
	mc.m2.server_ip[0] = 127, mc.m2.server_ip[1] = 0, mc.m2.server_ip[2] = 0, mc.m2.server_ip[3] = 1;
	mc.m2.server_port = CR.port[0];
	mc.monmap = CR.monmap;
	mc.monmap_len = CR.monmap_len;
	mc.no_default_osdmaps = 1;
	CR.mon = sim_mon_new(&mc);
	CR.store = sim_store_new();
	if (CR.mon == NULL || CR.store == NULL)
		abort();
	wrt_mg_cluster_spec_init(&cs, CR_NOSD);
	cs.osds_per_host = 1;
	cs.n_pools = 2;
	cs.pg_num = 16;
	cs.pool_size = 3;
	cs.epoch = 1;
	cs.seed = 77;
	if (wrt_mg_build_map(&CR.desc, &cs) != 0)
		abort();
	for (i = 0; i < CR_NOSD; i++)
		wrt_mg_av_v2(&WRT_MG_E(CR.desc.client_addrs, wrt_mg_addrvec, i), 0x7f000001u, CR.port[1u + i], 7000u + i);
	memcpy(CR.desc.fsid, CR.mon->fsid, 16);
	epoch = CR.desc.epoch;
	if (wrt_mg_map_encode(&CR.desc, &b) != 0 || sim_mon_add_epoch(CR.mon, epoch, b.p, b.len, NULL, 0) != WR_OK ||
	    sim_mon_push_epoch(CR.mon) != WR_OK)
		abort();
	wrt_mg_buf_free(&b);
	for (i = 0; i < CR_NOSD; i++) {
		sim_osd_cfg oc;

		sim_osd_cfg_default(&oc);
		oc.mon = CR.mon;
		oc.store = CR.store;
		oc.id = (int32_t)i;
		oc.seed = 11u + i;
		oc.m2.server_ip[0] = 127, oc.m2.server_ip[1] = 0, oc.m2.server_ip[2] = 0, oc.m2.server_ip[3] = 1;
		oc.m2.server_port = CR.port[1u + i];
		oc.m2.server_nonce = 7000u + i;
		oc.m2.check_target = 1;
		CR.osd[i] = sim_osd_new(&oc);
		if (CR.osd[i] == NULL)
			abort();
	}
	if (pthread_create(&CR.th, NULL, cr_srv_main, NULL) != 0)
		abort();
}

static void cr_srv_stop(void)
{
	unsigned i;

	CR.stop = 1;
	pthread_join(CR.th, NULL);
	for (i = 0; i < CR_SMAX; i++)
		if (CR.c[i].fd >= 0)
			cr_conn_drop(&CR.c[i]);
	for (i = 0; i < 1u + CR_NOSD; i++)
		close(CR.lfd[i]);
	for (i = 0; i < CR_NOSD; i++)
		sim_osd_free(CR.osd[i]);
	sim_mon_free(CR.mon);
	sim_store_free(CR.store);
	wrt_mg_map_free(&CR.desc);
	pthread_mutex_destroy(&CR.mu);
}

/* ---- reading the store as the test's own oracle ------------------------------------------------------------------- */

/* The bytes of [off, off + n) of the image whose data objects are "<prefix>.<index>", straight from the store. */
static void cr_store_read(const char *prefix, uint8_t order, uint64_t off, uint8_t *out, size_t n)
{
	uint64_t obj = 1ull << order, done = 0;

	while (done < n) {
		uint64_t x = off + done, idx = x / obj, o = x % obj, m = obj - o;
		char name[128];
		int exists = 0;

		if (m > n - done)
			m = n - done;
		snprintf(name, sizeof(name), "%s.%016llx", prefix, (unsigned long long)idx);
		cr_lock();
		if (sim_store_read(CR.store, CR_POOL, name, o, out + done, (size_t)m, &exists) != WR_OK)
			memset(out + done, 0xEE, (size_t)m);
		cr_unlock();
		done += m;
	}
}

WRT_UNUSED static uint64_t cr_fnv(const uint8_t *p, size_t n)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	for (i = 0; i < n; i++)
		h = (h ^ p[i]) * 0x100000001b3ull;
	return h;
}

/* FNV-1a of the whole image as the store holds it. */
static uint64_t cr_store_digest(const char *prefix, uint8_t order, uint64_t size)
{
	uint8_t *buf = (uint8_t *)malloc(1u << 20);
	uint64_t h = 0xcbf29ce484222325ull, off = 0;

	if (buf == NULL)
		abort();
	while (off < size) {
		size_t n = size - off < (1u << 20) ? (size_t)(size - off) : (1u << 20);
		size_t i;

		cr_store_read(prefix, order, off, buf, n);
		for (i = 0; i < n; i++)
			h = (h ^ buf[i]) * 0x100000001b3ull;
		off += n;
	}
	free(buf);
	return h;
}

/* ---- the in-process block device ---------------------------------------------------------------------------------- */

typedef struct cr_dev {
	int64_t pool;
	char prefix[96];
	uint64_t size;
	uint8_t order;
	uint32_t sector, gran;
	/* misbehaviour, set before the run (all off in a zeroed structure) */
	uint64_t flip_off;
	uint8_t flip_xor;      /* a byte of every read that covers flip_off is xor-ed with this (0 = off) */
	int flip_once;         /* ... only the first read that covers it */
	int flip_fired;
	int eio_after;         /* > 0: every call after this many calls fails with -EIO */
	int short_reads;       /* every read of more than one sector comes back one sector short */
	int lax_end;           /* a read or a write at or past the end of the device is accepted (a device that does not check) */
	uint64_t scribble_off; /* after the first write, this byte of the store is changed behind everyone's back (a device that writes too much) */
	int scribble;
	int hang_after;        /* > 0: the call number hang_after blocks until cr_dev_release() */
	uint64_t slow_ticks;   /* the call number slow_nth waits until the virtual clock has advanced this much */
	int slow_nth;
	/* counters */
	int calls;
	uint64_t n_read, n_write, n_discard, n_zero, n_flush;
	volatile int released;
	pthread_mutex_t mu;
} cr_dev;

static uint64_t g_cr_vt, g_cr_vt_step;

/* A virtual clock that advances by a fixed step every time anybody reads it: a hang or a slow device is decided by counting engine iterations,
 * not by how fast the machine is. */
WRT_UNUSED static uint64_t cr_tick_now(void *ctx)
{
	(void)ctx;
	return __atomic_add_fetch(&g_cr_vt, g_cr_vt_step, __ATOMIC_RELAXED);
}

static void cr_dev_init(cr_dev *d, const char *prefix, uint64_t size, uint8_t order)
{
	memset(d, 0, sizeof(*d));
	d->pool = CR_POOL;
	snprintf(d->prefix, sizeof(d->prefix), "%s", prefix);
	d->size = size - size % 512u; /* the capacity of a block device is a whole number of sectors: the tail of an odd image is out of its reach */
	d->order = order;
	d->sector = 512;
	d->gran = 512;
	pthread_mutex_init(&d->mu, NULL);
}

WRT_UNUSED static void cr_dev_release(cr_dev *d)
{
	d->released = 1;
}

/* Behaviour common to every call; returns a negative errno to fail the call, 0 to go on. */
static int cr_dev_pre(cr_dev *d, int is_read)
{
	int n;

	pthread_mutex_lock(&d->mu);
	n = ++d->calls;
	pthread_mutex_unlock(&d->mu);
	(void)is_read;
	if (d->hang_after > 0 && n == d->hang_after) {
		while (!d->released)
			usleep(1000);
	}
	if (d->slow_nth > 0 && n == d->slow_nth) {
		uint64_t target = __atomic_load_n(&g_cr_vt, __ATOMIC_RELAXED) + d->slow_ticks;

		while (!d->released && __atomic_load_n(&g_cr_vt, __ATOMIC_RELAXED) < target)
			usleep(200);
	}
	if (d->eio_after > 0 && n > d->eio_after)
		return -EIO;
	return 0;
}

static void cr_dev_oid(const cr_dev *d, uint64_t idx, char *out, size_t cap)
{
	snprintf(out, cap, "%s.%016llx", d->prefix, (unsigned long long)idx);
}

WRT_UNUSED static long cr_dev_pread(void *ctx, void *buf, size_t n, uint64_t off)
{
	cr_dev *d = (cr_dev *)ctx;
	uint64_t obj = 1ull << d->order, done = 0;
	int rc = cr_dev_pre(d, 1);

	if (rc != 0)
		return rc;
	d->n_read++;
	if (off >= d->size) {
		if (d->lax_end) {
			memset(buf, 0, n);
			return (long)n;
		}
		return 0;
	}
	if (n > d->size - off)
		n = (size_t)(d->size - off);
	while (done < n) {
		uint64_t x = off + done, o = x % obj, m = obj - o;
		char oid[128];
		int exists = 0;

		if (m > n - done)
			m = n - done;
		cr_dev_oid(d, x / obj, oid, sizeof(oid));
		cr_lock();
		if (sim_store_read(CR.store, d->pool, oid, o, (uint8_t *)buf + done, (size_t)m, &exists) != WR_OK)
			memset((uint8_t *)buf + done, 0xEE, (size_t)m);
		cr_unlock();
		done += m;
	}
	if (d->flip_xor != 0u && d->flip_off >= off && d->flip_off < off + n && !(d->flip_once && d->flip_fired)) {
		((uint8_t *)buf)[d->flip_off - off] ^= d->flip_xor;
		d->flip_fired = 1;
	}
	if (d->short_reads && n > d->sector)
		return (long)(n - d->sector);
	return (long)n;
}

static void cr_dev_store_write(cr_dev *d, uint64_t off, const uint8_t *data, size_t n)
{
	uint64_t obj = 1ull << d->order, done = 0;

	while (done < n) {
		uint64_t x = off + done, o = x % obj, m = obj - o;
		char oid[128];

		if (m > n - done)
			m = n - done;
		cr_dev_oid(d, x / obj, oid, sizeof(oid));
		cr_lock();
		if (sim_store_write(CR.store, d->pool, oid, o, data + done, (size_t)m) != WR_OK)
			abort();
		cr_unlock();
		done += m;
	}
}

WRT_UNUSED static long cr_dev_pwrite(void *ctx, const void *buf, size_t n, uint64_t off)
{
	cr_dev *d = (cr_dev *)ctx;
	int rc = cr_dev_pre(d, 0);

	if (rc != 0)
		return rc;
	d->n_write++;
	if (off >= d->size || n > d->size - off)
		return d->lax_end ? (long)n : -ENOSPC;
	cr_dev_store_write(d, off, (const uint8_t *)buf, n);
	if (d->scribble && d->n_write == 1u) { /* a device bug that both readers will see and the model cannot know */
		uint8_t v = 0;
		uint8_t *tmp = &v;

		cr_store_read(d->prefix, d->order, d->scribble_off, tmp, 1);
		v ^= 0x40u;
		cr_dev_store_write(d, d->scribble_off, tmp, 1);
	}
	return (long)n;
}

static void cr_dev_zero(cr_dev *d, uint64_t off, uint64_t len)
{
	static const uint8_t zeros[4096] = {0};

	while (len > 0u) {
		size_t m = len < sizeof(zeros) ? (size_t)len : sizeof(zeros);

		cr_dev_store_write(d, off, zeros, m);
		off += m;
		len -= m;
	}
}

WRT_UNUSED static int cr_dev_discard(void *ctx, uint64_t off, uint64_t len)
{
	cr_dev *d = (cr_dev *)ctx;
	uint64_t obj = 1ull << d->order, end = off + len;
	int rc = cr_dev_pre(d, 0);

	if (rc != 0)
		return rc;
	d->n_discard++;
	if (off >= d->size || len > d->size - off)
		return -EINVAL;
	while (off < end) { /* honoured inward to the granularity, object by object (the kernel client's alloc_size rule) */
		uint64_t ob = off / obj * obj, oe = ob + obj, se = end < oe ? end : oe;
		uint64_t a = ob + ((off - ob + d->gran - 1u) / d->gran) * d->gran, b = ob + ((se - ob) / d->gran) * d->gran;

		if (a < b)
			cr_dev_zero(d, a, b - a);
		off = se;
	}
	return 0;
}

WRT_UNUSED static int cr_dev_zeroes(void *ctx, uint64_t off, uint64_t len)
{
	cr_dev *d = (cr_dev *)ctx;
	int rc = cr_dev_pre(d, 0);

	if (rc != 0)
		return rc;
	d->n_zero++;
	if (off >= d->size || len > d->size - off)
		return -EINVAL;
	cr_dev_zero(d, off, len);
	return 0;
}

WRT_UNUSED static int cr_dev_flush(void *ctx)
{
	cr_dev *d = (cr_dev *)ctx;
	int rc = cr_dev_pre(d, 0);

	if (rc != 0)
		return rc;
	d->n_flush++;
	return 0;
}

WRT_UNUSED static int cr_dev_size(void *ctx, uint64_t *bytes)
{
	cr_dev *d = (cr_dev *)ctx;

	*bytes = d->size - d->size % d->sector;
	return 0;
}

#endif /* CMP_RIG_H */
