/* SPDX-License-Identifier: MIT */
/*
 * wr-krbdcmp - compare the winrbd core with the Linux kernel client (krbd) on the same RBD image, byte for byte, against a third
 * witness: a flat model of what the image must hold (Phase 1 milestone 9, docs/design/core-architecture.md section 33).
 *
 *   wr-krbdcmp --mon <ip[:port]> --user NAME --keyring FILE --pool P --image I --dev /dev/rbdN
 *              [--mode crc|crc-first|secure-first|secure|stock] [--mode-osd MODE] [--require-mode secure|crc] [--accel]
 *              [--dir core-to-krbd|krbd-to-core|interleave|all] [--phase edges|random|scan|all]
 *              [--seed S] [--ops N] [--time SEC] [--max-len N] [--depth N] [--chunk N] [--checkpoint N] [--stall-ms MS] [-v]
 *
 * The core opens the image as a writer (profile P1) and the kernel's block device is opened O_DIRECT | O_DSYNC (no page cache between
 * this tool and the OSDs; BLKFLSBUF is issued whenever the writer changes). Discards go to the device as BLKDISCARD and write-zeroes as
 * BLKZEROOUT. krbd must have been mapped with ms_mode=prefer-crc (or secure) and, to honour every discard, -o alloc_size=512
 * (harness/lab/krbd-compare.sh does both); --discard-gran N tells the tool what granularity the device really honours (the model shrinks
 * a device discard inward to it, as krbd does).
 *
 * Phases: edges (deterministic object boundary, hole, last partial object, past the end and unaligned classes at the image's order),
 * random (seeded, boundary biased read / write / discard / write-zeroes / flush; --ops operations or --time seconds, split over the
 * directions when --dir all), scan (a full read by both clients in different chunk sizes against the model, at the end of every phase
 * and every --checkpoint operations, default 5000). Directions: core-to-krbd (the core writes, the device reads, the core reads back),
 * krbd-to-core (the device writes sector aligned, the core reads), interleave (the writer alternates, ranges overlap on purpose), all
 * (the three in turn). --depth N operations in flight (lanes; ranges of lanes in flight never overlap), default 8. --stall-ms MS: a
 * request without a completion for that long is a hang (default 180000).
 *
 * Output (stdout, "@<ms> <kind> <key=value ...>"): plan, image, device, phase, scan, progress, retry, diff, error, stall, stats, result.
 * A "diff" record has the direction, the operation number, the range, the first differing byte and the three digests (core, krbd, model)
 * with who is alone (verdict core | device | model | both). No key material is ever printed.
 * Exit status: 0 no difference; 1 a difference; 2 usage or setup error; 3 the image or the device could not be opened or a client failed;
 * 4 a request failed with no difference (an I/O error, a short transfer, a hang past --stall-ms); 5 the data agreed but --require-mode was not
 * met (see below).
 *
 * Connection modes (msgr2 secure mode, docs/design/core-architecture.md part D). --mode is the offer made to the monitor (and to the OSDs unless
 * --mode-osd says otherwise; default crc, the behaviour of every earlier run). The core counts the connections that reached READY in each mode;
 * the stats record ends with conns_secure= conns_crc= (connections of the core to the monitor and to every OSD in secure and in crc mode) and
 * sec_failures= (secure connections that ended on a secret, nonce or tag failure: the engine redials and carries on, which is not a clean run).
 * These three fields are appended to the stats record; every older field keeps its name, its place and its format.
 * --require-mode secure|crc turns the run into an assertion: it holds when every connection was in that mode, at least one connection was made (a
 * run in which nothing connected proves nothing) and sec_failures is 0. When it does not hold the run exits 5, prints one stderr line and a
 * "result require_mode ok=0 wanted=M conns_secure=N conns_crc=N sec_failures=N" record (printed with ok=1 when it holds), and the "result" record
 * of the comparison itself is printed with ok=0 exit=5. A difference (1), a client failure (3) or a request failure (4) is the more serious finding
 * and keeps its code; the require_mode record says what was counted either way. A --require-mode that no connection of the chosen offer can ever
 * meet (secure with a crc-only offer to the monitor or the OSDs, crc with a secure-only one) is refused at once with exit 2.
 * Without --require-mode nothing changes, except that a run that was given --mode secure and still counted a crc connection (a --mode-osd that lets
 * the OSDs use crc does it too) prints a warning line on stderr (the exit status stays as it was: pass --require-mode secure to make it a failure).
 *
 * --accel (the host's accelerated GCM) is refused: this host has none yet (exit 2).
 *
 * SAFETY: the tool writes random data over the whole image, so it refuses what it was not meant for: an image whose name does not start with
 * "wrtest-" (the lab's fixture rule: never img-default or img-v1), and, on Linux, a block device that is not /dev/rbd<N> mapped from exactly
 * --pool / --image (read from /sys/bus/rbd/devices/<N>/{pool,name}). --allow-any-target lifts both (the test-only mode needs it: the simulated
 * images have other names; a person has no use for it).
 *
 * TEST-ONLY options (ctest host.tool.krbdcmp, never used in the lab): --self-test-mirror makes a REGULAR FILE the "device" and keeps it
 * equal to the image by performing every write on both sides; --corrupt-at OFF[:core|device|model][:once] damages one byte of what that
 * witness reports (core and device: a byte of every read that covers OFF, or only the first with :once; model: one byte of the model)
 * so the exit codes and the record shapes of a difference can be checked without a faulty kernel.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/fs.h>
#include <sys/ioctl.h>
#endif

#include "wrl_cmp.h"
#include "wrl_host.h"

#define KEYRING_MAX 4096u

typedef struct opts {
	const char *mon, *user, *keyring, *pool, *image, *dev, *mode, *mode_osd, *dir, *phase, *label, *fsid, *corrupt, *require_mode;
	int accel, verbose, mirror, no_direct, any_target;
	uint64_t seed, ops, time_s, max_len, depth, chunk, checkpoint, stall_ms, open_timeout_ms, discard_gran, sector, mem_max;
	int have_seed, have_discard_gran;
} opts;

/* ---- small helpers -------------------------------------------------------------------------------------------- */

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0)
		*v++ = 0;
}

static uint64_t now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* A number: decimal or 0x hexadecimal, an optional K / M / G / T suffix (powers of 1024). No sign, no white space. */
static int parse_u64(const char *s, uint64_t *out)
{
	char *end = NULL;
	unsigned long long v;
	uint64_t mul = 1;
	int base = 10;

	if (s == NULL || *s < '0' || *s > '9')
		return -1;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		base = 16;
	errno = 0;
	v = strtoull(s, &end, base);
	if (errno != 0 || end == s)
		return -1;
	switch (*end) {
	case 'k': case 'K': mul = 1ull << 10; end++; break;
	case 'm': case 'M': mul = 1ull << 20; end++; break;
	case 'g': case 'G': mul = 1ull << 30; end++; break;
	case 't': case 'T': mul = 1ull << 40; end++; break;
	default: break;
	}
	if (mul != 1u && (*end == 'i' || *end == 'I'))
		end++;
	if (*end == 'b' || *end == 'B')
		end++;
	if (*end != '\0' || (mul != 1u && v > UINT64_MAX / mul))
		return -1;
	*out = (uint64_t)v * mul;
	return 0;
}

static int fsid_parse(const char *s, uint8_t *out)
{
	unsigned i, n = 0;

	for (i = 0; s[i] != '\0'; i++) {
		int v;
		char ch = s[i];

		if (ch == '-')
			continue;
		if (ch >= '0' && ch <= '9')
			v = ch - '0';
		else if (ch >= 'a' && ch <= 'f')
			v = ch - 'a' + 10;
		else if (ch >= 'A' && ch <= 'F')
			v = ch - 'A' + 10;
		else
			return -1;
		if (n >= 32u)
			return -1;
		if ((n & 1u) == 0)
			out[n / 2u] = (uint8_t)(v << 4);
		else
			out[n / 2u] = (uint8_t)(out[n / 2u] | v);
		n++;
	}
	return n == 32u ? 0 : -1;
}

/* ---- the device: an fd ----------------------------------------------------------------------------------------- */

typedef struct fdev {
	int fd;
	int blk;           /* a block device (else a regular file of the self test) */
	uint64_t size;     /* bytes (the file's length, or the device's capacity) */
	uint32_t sector;
} fdev;

static long fd_pread(void *ctx, void *buf, size_t n, uint64_t off)
{
	fdev *d = (fdev *)ctx;

	for (;;) {
		ssize_t r = pread(d->fd, buf, n, (off_t)off);

		if (r >= 0)
			return (long)r;
		if (errno != EINTR)
			return -(long)errno;
	}
}

static long fd_pwrite(void *ctx, const void *buf, size_t n, uint64_t off)
{
	fdev *d = (fdev *)ctx;
	size_t done = 0;

	if (!d->blk && (off > d->size || n > d->size - off)) /* a block device refuses a write at its end; a regular file would grow */
		return -(long)ENOSPC;
	while (done < n) {
		ssize_t r = pwrite(d->fd, (const uint8_t *)buf + done, n - done, (off_t)(off + done));

		if (r < 0) {
			if (errno == EINTR)
				continue;
			return done > 0u ? (long)done : -(long)errno;
		}
		if (r == 0)
			break;
		done += (size_t)r;
	}
	return (long)done;
}

static int fd_zero_write(fdev *d, uint64_t off, uint64_t len)
{
	static uint8_t zeros[1u << 16];

	while (len > 0u) {
		size_t n = len < sizeof(zeros) ? (size_t)len : sizeof(zeros);
		long r = fd_pwrite(d, zeros, n, off);

		if (r < 0)
			return (int)r;
		if ((size_t)r != n)
			return -EIO;
		off += n;
		len -= n;
	}
	return 0;
}

static int fd_discard(void *ctx, uint64_t off, uint64_t len)
{
	fdev *d = (fdev *)ctx;

#ifdef BLKDISCARD
	if (d->blk) {
		uint64_t range[2];

		range[0] = off;
		range[1] = len;
		return ioctl(d->fd, BLKDISCARD, range) == 0 ? 0 : -errno;
	}
#endif
	return fd_zero_write(d, off, len);
}

static int fd_zeroes(void *ctx, uint64_t off, uint64_t len)
{
	fdev *d = (fdev *)ctx;

#ifdef BLKZEROOUT
	if (d->blk) {
		uint64_t range[2];

		range[0] = off;
		range[1] = len;
		return ioctl(d->fd, BLKZEROOUT, range) == 0 ? 0 : -errno;
	}
#endif
	return fd_zero_write(d, off, len);
}

static int fd_flush(void *ctx)
{
	fdev *d = (fdev *)ctx;

	if (!d->blk)
		return 0; /* the file of the self test is not a durability witness: an fsync would only wait for whatever else the disk is doing */
#ifdef BLKFLSBUF
	if (ioctl(d->fd, BLKFLSBUF, 0) != 0)
		return -errno;
#endif
	return fsync(d->fd) == 0 || errno == EINVAL ? 0 : -errno;
}

static int fd_size(void *ctx, uint64_t *bytes)
{
	fdev *d = (fdev *)ctx;

	*bytes = d->size - d->size % d->sector;
	return 0;
}

/* The first line of a small text file (a sysfs attribute) without its newline; 0 ok, -1 unreadable. */
static int read_attr(const char *path, char *out, size_t cap)
{
	FILE *f = fopen(path, "r");
	size_t n;

	if (f == NULL)
		return -1;
	if (fgets(out, (int)cap, f) == NULL) {
		fclose(f);
		return -1;
	}
	fclose(f);
	n = strlen(out);
	while (n > 0u && (out[n - 1u] == '\n' || out[n - 1u] == '\r'))
		out[--n] = '\0';
	return 0;
}

/* The block device must be the krbd mapping of --pool/--image and nothing else: a typo in --dev would otherwise have the tool write random data
 * over another disk of the same size. 0 ok, -1 refused (reported on stderr). */
static int rbd_target_check(const opts *o)
{
	char real[PATH_MAX], path[160], pool[256], name[256];
	const char *base, *p;

	if (realpath(o->dev, real) == NULL) {
		fprintf(stderr, "wr-krbdcmp: cannot resolve %s: %s\n", o->dev, strerror(errno));
		return -1;
	}
	base = strrchr(real, '/');
	base = base != NULL ? base + 1 : real;
	if (strncmp(base, "rbd", 3) != 0 || base[3] == '\0') {
		fprintf(stderr, "wr-krbdcmp: %s is not a krbd device (/dev/rbd<N>): refusing to write to it\n", real);
		return -1;
	}
	for (p = base + 3; *p != '\0'; p++) {
		if (*p < '0' || *p > '9') {
			fprintf(stderr, "wr-krbdcmp: %s is not a krbd device (/dev/rbd<N>): refusing to write to it\n", real);
			return -1;
		}
	}
	snprintf(path, sizeof(path), "/sys/bus/rbd/devices/%s/pool", base + 3);
	if (read_attr(path, pool, sizeof(pool)) != 0) {
		fprintf(stderr, "wr-krbdcmp: cannot read %s: not sure what %s is mapped from: refusing to write to it\n", path, real);
		return -1;
	}
	snprintf(path, sizeof(path), "/sys/bus/rbd/devices/%s/name", base + 3);
	if (read_attr(path, name, sizeof(name)) != 0) {
		fprintf(stderr, "wr-krbdcmp: cannot read %s: not sure what %s is mapped from: refusing to write to it\n", path, real);
		return -1;
	}
	if (strcmp(pool, o->pool) != 0 || strcmp(name, o->image) != 0) {
		fprintf(stderr, "wr-krbdcmp: %s is mapped from %s/%s, not from %s/%s: refusing to write to it\n", real, pool, name, o->pool, o->image);
		return -1;
	}
	return 0;
}

/* Open the device. 0 ok, -1 it cannot be opened or read (exit 3), -2 it is the wrong kind of thing for these options (exit 2); reported on stderr.
 * A block device is opened O_DIRECT | O_DSYNC; a regular file only with the self test. */
static int fd_open(fdev *d, const opts *o)
{
	struct stat st;
	int flags = O_RDWR
#ifdef O_CLOEXEC
		    | O_CLOEXEC
#endif
		    ;

	memset(d, 0, sizeof(*d));
	d->fd = -1;
	if (stat(o->dev, &st) != 0) {
		fprintf(stderr, "wr-krbdcmp: cannot stat %s: %s\n", o->dev, strerror(errno));
		return -1;
	}
	d->blk = S_ISBLK(st.st_mode) ? 1 : 0;
	if (d->blk && !o->any_target && rbd_target_check(o) != 0)
		return -2;
	if (!d->blk && !S_ISREG(st.st_mode)) {
		fprintf(stderr, "wr-krbdcmp: %s is neither a block device nor a regular file\n", o->dev);
		return -2;
	}
	if (d->blk && o->mirror) {
		fprintf(stderr, "wr-krbdcmp: --self-test-mirror is for a regular file; refusing to use it on a block device\n");
		return -2;
	}
	if (!d->blk && !o->mirror) {
		fprintf(stderr, "wr-krbdcmp: %s is a regular file: it is not connected to the image, so nothing would be compared "
			"(--self-test-mirror is the test-only mode that keeps one in step)\n", o->dev);
		return -2;
	}
	if (d->blk) {
#ifdef O_DIRECT
		if (!o->no_direct)
			flags |= O_DIRECT;
#endif
#ifdef O_DSYNC
		flags |= O_DSYNC;
#endif
	}
	d->fd = open(o->dev, flags);
	if (d->fd < 0) {
		fprintf(stderr, "wr-krbdcmp: cannot open %s: %s\n", o->dev, strerror(errno));
		return -1;
	}
	d->sector = 512;
	if (d->blk) {
#ifdef BLKGETSIZE64
		uint64_t sz = 0;

		if (ioctl(d->fd, BLKGETSIZE64, &sz) != 0) {
			fprintf(stderr, "wr-krbdcmp: BLKGETSIZE64 on %s: %s\n", o->dev, strerror(errno));
			close(d->fd);
			return -1;
		}
		d->size = sz;
#endif
#ifdef BLKSSZGET
		{
			int ss = 0;

			if (ioctl(d->fd, BLKSSZGET, &ss) == 0 && ss >= 512 && ss <= 4096 && (ss & (ss - 1)) == 0)
				d->sector = (uint32_t)ss;
		}
#endif
	} else {
		d->size = (uint64_t)st.st_size;
	}
	if (o->sector != 0u)
		d->sector = (uint32_t)o->sector;
	return 0;
}

/* ---- command line ----------------------------------------------------------------------------------------------- */

static void usage(void)
{
	fprintf(stderr,
		"usage: wr-krbdcmp --mon <ip[:port]> --user NAME --keyring FILE --pool P --image I --dev /dev/rbdN\n"
		"                  [--mode crc|crc-first|secure-first|secure|stock] [--mode-osd MODE] [--accel]\n"
		"                  [--require-mode secure|crc]\n"
		"                  [--dir core-to-krbd|krbd-to-core|interleave|all] [--phase edges|random|scan|all]\n"
		"                  [--seed S] [--ops N] [--time SEC] [--max-len N] [--depth N] [--chunk N] [--checkpoint N] [--stall-ms MS]\n"
		"                  [--timeout MS] [--discard-gran N] [--sector N] [--mem-max N] [--label TEXT] [--fsid UUID] [-v]\n"
		"test only:        [--self-test-mirror] [--corrupt-at OFF[:core|device|model][:once]] [--no-direct] [--allow-any-target]\n");
}

static int num_opt(const char *name, const char *v, uint64_t *out)
{
	if (parse_u64(v, out) != 0) {
		fprintf(stderr, "wr-krbdcmp: bad value for %s\n", name);
		return -1;
	}
	return 0;
}

static int parse_args(opts *o, int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];
		int has_val = i + 1 < argc;

#define STROPT(flag, field) \
	if (strcmp(a, flag) == 0 && has_val) { o->field = argv[++i]; continue; }
#define NUMOPT(flag, field) \
	if (strcmp(a, flag) == 0 && has_val) { if (num_opt(flag, argv[++i], &o->field) != 0) return -1; continue; }
		STROPT("--mon", mon) STROPT("--user", user) STROPT("--keyring", keyring) STROPT("--pool", pool) STROPT("--image", image)
		STROPT("--dev", dev) STROPT("--mode", mode) STROPT("--mode-osd", mode_osd) STROPT("--dir", dir) STROPT("--phase", phase)
		STROPT("--label", label) STROPT("--fsid", fsid) STROPT("--corrupt-at", corrupt) STROPT("--require-mode", require_mode)
		NUMOPT("--ops", ops) NUMOPT("--time", time_s) NUMOPT("--max-len", max_len) NUMOPT("--depth", depth) NUMOPT("--chunk", chunk)
		NUMOPT("--checkpoint", checkpoint) NUMOPT("--stall-ms", stall_ms) NUMOPT("--timeout", open_timeout_ms) NUMOPT("--sector", sector)
		NUMOPT("--mem-max", mem_max)
#undef STROPT
#undef NUMOPT
		if (strcmp(a, "--seed") == 0 && has_val) {
			if (num_opt(a, argv[++i], &o->seed) != 0)
				return -1;
			o->have_seed = 1;
		} else if (strcmp(a, "--discard-gran") == 0 && has_val) {
			if (num_opt(a, argv[++i], &o->discard_gran) != 0)
				return -1;
			o->have_discard_gran = 1;
		} else if (strcmp(a, "--accel") == 0) {
			o->accel = 1;
		} else if (strcmp(a, "--self-test-mirror") == 0) {
			o->mirror = 1;
		} else if (strcmp(a, "--no-direct") == 0) {
			o->no_direct = 1;
		} else if (strcmp(a, "--allow-any-target") == 0) {
			o->any_target = 1;
		} else if (strcmp(a, "-v") == 0) {
			o->verbose = 1;
		} else {
			fprintf(stderr, "wr-krbdcmp: unknown or incomplete option %s\n", a);
			return -1;
		}
	}
	return 0;
}

static int mode_parse(const char *s, uint8_t *out)
{
	if (s == NULL || strcmp(s, "crc") == 0)
		*out = WR_MODE_CRC_ONLY;
	else if (strcmp(s, "crc-first") == 0)
		*out = WR_MODE_CRC_FIRST;
	else if (strcmp(s, "secure-first") == 0)
		*out = WR_MODE_SECURE_FIRST;
	else if (strcmp(s, "secure") == 0)
		*out = WR_MODE_SECURE_ONLY;
	else if (strcmp(s, "stock") == 0)
		*out = WR_MODE_STOCK;
	else
		return -1;
	return 0;
}

static int corrupt_parse(const char *s, wrl_cmp_cfg *c)
{
	char buf[96];
	char *p, *w, *once;

	if (s == NULL)
		return 0;
	if (strlen(s) >= sizeof(buf))
		return -1;
	snprintf(buf, sizeof(buf), "%s", s);
	p = strchr(buf, ':');
	if (p != NULL)
		*p++ = '\0';
	if (parse_u64(buf, &c->corrupt_off) != 0)
		return -1;
	c->corrupt = WRL_CMP_CORRUPT_DEV;
	if (p == NULL)
		return 0;
	once = strchr(p, ':');
	if (once != NULL)
		*once++ = '\0';
	w = p;
	if (strcmp(w, "core") == 0)
		c->corrupt = WRL_CMP_CORRUPT_CORE;
	else if (strcmp(w, "device") == 0)
		c->corrupt = WRL_CMP_CORRUPT_DEV;
	else if (strcmp(w, "model") == 0)
		c->corrupt = WRL_CMP_CORRUPT_MODEL;
	else
		return -1;
	if (once != NULL) {
		if (strcmp(once, "once") != 0)
			return -1;
		c->corrupt_once = 1;
	}
	return 0;
}

/* ---- the client ----------------------------------------------------------------------------------------------- */

typedef struct tool {
	wr_client *c;
	wrl_loop *loop;
	wr_image *img;
	wr_mem_region arena, bulk;
	uint64_t t0;
	wr_status fatal;
} tool;

static const char *img_state_name(wr_image_state s)
{
	switch (s) {
	case WR_IMG_OPENING: return "OPENING";
	case WR_IMG_OPEN: return "OPEN";
	case WR_IMG_FAILED: return "FAILED";
	case WR_IMG_CLOSING: return "CLOSING";
	case WR_IMG_FREE:
	default: return "FREE";
	}
}

static int tool_create(tool *t, const opts *o, const wr_cluster_spec *spec, unsigned *level, uint8_t pol, uint8_t pol_osd)
{
	wr_config cfg;
	wr_host_ops ops;
	wr_mem_req req;
	wr_status st;

	wr_config_profile_harness(&cfg);
	wr_config_enable_maps(&cfg, WR_MAPS_HARNESS);
	wr_config_enable_osd(&cfg, WR_MAPS_HARNESS);
	wr_config_enable_secure(&cfg, WR_MAPS_HARNESS, pol);
	if (pol_osd != 0u)
		cfg.mode_policy_osd = pol_osd;
	cfg.mon_msg_cap = 8u * 1024u * 1024u;
	cfg.max_images = 1;
	cfg.max_reqs = (uint16_t)(o->depth + 16u > 128u ? o->depth + 16u : 128u);
	wrl_host_ops_init(&ops, level);
	st = wr_client_mem_required(&cfg, &req);
	if (st == WR_OK)
		st = wrl_mem_alloc(&t->arena, req.arena);
	if (st == WR_OK) {
		st = wrl_mem_alloc(&t->bulk, req.bulk);
		if (st != WR_OK)
			wrl_mem_free(&t->arena);
	}
	if (st == WR_OK) {
		st = wr_client_create(&cfg, &ops, spec, t->arena, t->bulk, &t->c);
		if (st != WR_OK) {
			wrl_mem_free(&t->arena);
			wrl_mem_free(&t->bulk);
		}
	}
	if (st != WR_OK) {
		fprintf(stderr, "wr-krbdcmp: cannot create the client: %s (%s)\n", wr_strerror(st), wr_status_name(st));
		return -1;
	}
	st = wrl_loop_create(t->c, &t->loop);
	if (st != WR_OK) {
		fprintf(stderr, "wr-krbdcmp: cannot create the loop: %s\n", wr_strerror(st));
		wr_client_destroy(t->c);
		wrl_mem_free(&t->arena);
		wrl_mem_free(&t->bulk);
		t->c = NULL;
		return -1;
	}
	return 0;
}

static void drain_events(tool *t)
{
	wr_event e;
	wr_mapmsg m;

	while (wr_client_next_event(t->c, &e))
		;
	while (wr_client_mapmsg_peek(t->c, &m))
		wr_client_mapmsg_release(t->c);
}

/* 0 open, -1 failed (reported on stdout like wr-rbd). */
static int tool_open_image(tool *t, const opts *o, wr_image_info *info)
{
	wr_image_params p;
	wr_status st;
	uint64_t limit = now_ms() + o->open_timeout_ms + 10000u;

	memset(&p, 0, sizeof(p));
	p.size = (uint32_t)sizeof(p);
	p.pool = o->pool;
	p.name = o->image;
	p.snap_id = WR_SNAP_HEAD;
	p.open_timeout_ms = (uint32_t)o->open_timeout_ms;
	p.want_write = 1;
	st = wr_image_open(t->c, &p, &t->img);
	if (st != WR_OK) {
		printf("@%llu result open ok=0 status=%s (%s)\n", (unsigned long long)(now_ms() - t->t0), wr_status_name(st), wr_strerror(st));
		return -1;
	}
	while (t->fatal == WR_OK && wr_image_get_state(t->img) == WR_IMG_OPENING && now_ms() < limit) {
		t->fatal = wrl_loop_step(t->loop, 20);
		drain_events(t);
	}
	if (wr_image_get_state(t->img) != WR_IMG_OPEN) {
		const wr_errinfo *e = wr_image_error(t->img);
		wr_status why = t->fatal != WR_OK ? t->fatal : e->status;

		printf("@%llu result open ok=0 state=%s status=%s peer_result=%d what=\"%s\" (%s)\n", (unsigned long long)(now_ms() - t->t0),
		       img_state_name(wr_image_get_state(t->img)), wr_status_name(why), (int)e->peer_result, e->what != NULL ? e->what : "",
		       wr_strerror(why));
		return -1;
	}
	if (wr_image_get_info(t->img, info) != WR_OK) {
		printf("@%llu result open ok=0 status=get_info\n", (unsigned long long)(now_ms() - t->t0));
		return -1;
	}
	return 0;
}

/* ---- the records of the engine, with the connection counts of the core appended to the stats record --------------------------------------- */

/*
 * The engine (wrl_cmp.c) prints the stats record itself and does not know the connection counters of the client. The tool hands it a pipe as its
 * record stream and forwards every line to stdout from a thread of its own, unchanged, as it arrives (progress is still live), except two:
 *   - the "stats" record gets " conns_secure=N conns_crc=N sec_failures=N" appended at its end (new fields last: the old ones keep name, order and format);
 *   - when --require-mode was not met and nothing worse happened, the "result" record is printed with ok=0 exit=5 (what the process exits with).
 * Both need the counts, which exist once the run is over: the thread holds the stats record until the main thread has published them (the engine writes only
 * the result record after it, far less than a pipe holds). Without the thread (a pipe or thread that cannot be made) the records go to stdout as the engine
 * prints them and the tool prints a stats record of its own with the three fields afterwards.
 */
#define FWD_LINE_MAX 16384u

typedef struct fwd {
	int rfd;
	FILE *w;                 /* the engine's stream: the write end of the pipe */
	pthread_t th;
	pthread_mutex_t mu;
	pthread_cond_t cv;
	int started, published;
	int mode_bad;            /* the result record is rewritten to ok=0 exit=5 */
	char extra[96];          /* the text appended to the stats record */
} fwd;

static void fwd_wait_published(fwd *f)
{
	pthread_mutex_lock(&f->mu);
	while (!f->published)
		pthread_cond_wait(&f->cv, &f->mu);
	pthread_mutex_unlock(&f->mu);
}

/* Skip "@<digits> " and return the kind and what follows it, or NULL when the line is not a record. */
static const char *rec_kind(const char *line)
{
	const char *p = line;

	if (*p != '@')
		return NULL;
	p++;
	while (*p >= '0' && *p <= '9')
		p++;
	return *p == ' ' ? p + 1 : NULL;
}

static void fwd_line(fwd *f, const char *line)
{
	const char *k = rec_kind(line);

	if (k != NULL && strncmp(k, "stats ", 6) == 0) {
		fwd_wait_published(f);
		fputs(line, stdout);
		fputs(f->extra, stdout);
		fputc('\n', stdout);
	} else if (k != NULL && strncmp(k, "result ok=1 exit=0 ", 19) == 0) {
		int bad;

		fwd_wait_published(f);
		bad = f->mode_bad;
		if (bad) { /* the comparison itself found nothing; the process exits 5 */
			fwrite(line, 1, (size_t)(k - line) + 7u, stdout); /* up to and with "result " */
			fputs("ok=0 exit=5 ", stdout);
			fputs(k + 19, stdout);
		} else {
			fputs(line, stdout);
		}
		fputc('\n', stdout);
	} else {
		fputs(line, stdout);
		fputc('\n', stdout);
	}
	fflush(stdout);
}

static void *fwd_main(void *arg)
{
	fwd *f = (fwd *)arg;
	static char line[FWD_LINE_MAX + 1u];
	char buf[4096];
	size_t n = 0;

	for (;;) {
		ssize_t r = read(f->rfd, buf, sizeof(buf));
		ssize_t i;

		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (r == 0)
			break;
		for (i = 0; i < r; i++) {
			if (buf[i] == '\n') {
				line[n] = '\0';
				fwd_line(f, line);
				n = 0;
			} else if (n < FWD_LINE_MAX) {
				line[n++] = buf[i];
			} else { /* an overlong line (no record is): pass what there is, unmodified */
				fwrite(line, 1, n, stdout);
				n = 0;
				line[n++] = buf[i];
			}
		}
	}
	if (n > 0u) {
		fwrite(line, 1, n, stdout);
		fputc('\n', stdout);
	}
	fflush(stdout);
	return NULL;
}

/* 0 started: f->w is the stream for the engine; -1: not possible (the caller uses stdout). */
static int fwd_start(fwd *f)
{
	int fds[2];

	memset(f, 0, sizeof(*f));
	f->rfd = -1;
	if (pipe(fds) != 0)
		return -1;
	f->rfd = fds[0];
	f->w = fdopen(fds[1], "w");
	if (f->w == NULL) {
		close(fds[0]);
		close(fds[1]);
		return -1;
	}
	if (pthread_mutex_init(&f->mu, NULL) != 0)
		goto fail;
	if (pthread_cond_init(&f->cv, NULL) != 0) {
		pthread_mutex_destroy(&f->mu);
		goto fail;
	}
	if (pthread_create(&f->th, NULL, fwd_main, f) != 0) {
		pthread_cond_destroy(&f->cv);
		pthread_mutex_destroy(&f->mu);
		goto fail;
	}
	f->started = 1;
	return 0;
fail:
	fclose(f->w);
	close(f->rfd);
	f->w = NULL;
	return -1;
}

/* The run is over: hand the thread the counts, close the stream and wait until every line is out. */
static void fwd_finish(fwd *f, const char *extra, int mode_bad)
{
	pthread_mutex_lock(&f->mu);
	snprintf(f->extra, sizeof(f->extra), "%s", extra);
	f->mode_bad = mode_bad;
	f->published = 1;
	pthread_cond_broadcast(&f->cv);
	pthread_mutex_unlock(&f->mu);
	fflush(f->w);
	close(fileno(f->w)); /* not fclose: a device worker the engine abandoned must not find a freed stream (it never writes records, but the process is about to end) */
	(void)pthread_join(f->th, NULL);
	close(f->rfd);
	f->started = 0;
}

/* Does the run meet --require-mode (NULL: nothing is required)? Every connection in the mode, at least one connection, no secure-mode failure. */
static int mode_met(const char *req, const wr_stats *ws)
{
	int want_secure;

	if (req == NULL)
		return 1;
	want_secure = strcmp(req, "secure") == 0;
	return (want_secure ? ws->conns_crc == 0u && ws->conns_secure != 0u : ws->conns_secure == 0u && ws->conns_crc != 0u) && ws->sec_failures == 0u;
}

/* ---- main ------------------------------------------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	opts o;
	tool t;
	fdev fd;
	wrl_cmp_cfg cfg;
	wrl_cmp_result res;
	wr_image_info info;
	wr_cluster_spec spec;
	unsigned level = WR_LOG_WARN;
	static char kr[KEYRING_MAX];
	size_t krlen = 0, nmon = 0;
	uint8_t pol = WR_MODE_CRC_ONLY, pol_osd = 0;
	unsigned dirs = WRL_CMP_DIR_ALL, phases = WRL_CMP_PH_ALL;
	wr_status st;
	wr_stats ws;
	fwd fw;
	char extra[96];
	int rc = 0, fdrc, ran = 0, mode_ok = 1;

	memset(&o, 0, sizeof(o));
	memset(&fw, 0, sizeof(fw));
	memset(&ws, 0, sizeof(ws));
	memset(&t, 0, sizeof(t));
	memset(&cfg, 0, sizeof(cfg));
	o.depth = 8;
	o.open_timeout_ms = 30000;
	if (parse_args(&o, argc, argv) != 0) {
		usage();
		return 2;
	}
	if (o.mon == NULL || o.user == NULL || o.keyring == NULL || o.pool == NULL || o.image == NULL || o.dev == NULL) {
		usage();
		return 2;
	}
	if (!o.any_target && strncmp(o.image, "wrtest-", 7) != 0) {
		fprintf(stderr, "wr-krbdcmp: refusing image %s: the tool overwrites the image with random data and only works on lab fixtures named wrtest-* "
			"(never img-default or img-v1)\n", o.image);
		return 2;
	}
	if (o.depth == 0u || o.depth > 64u) {
		fprintf(stderr, "wr-krbdcmp: --depth must be 1 to 64\n");
		return 2;
	}
	if (o.open_timeout_ms > UINT32_MAX || o.stall_ms > (uint64_t)1 << 40 || o.time_s > (uint64_t)1 << 30) {
		fprintf(stderr, "wr-krbdcmp: a time value is out of range\n");
		return 2;
	}
	if (o.sector != 0u && (o.sector < 512u || o.sector > 4096u || (o.sector & (o.sector - 1u)) != 0u)) {
		fprintf(stderr, "wr-krbdcmp: --sector must be a power of two from 512 to 4096\n");
		return 2;
	}
	if (o.have_discard_gran && (o.discard_gran == 0u || o.discard_gran > (1u << 30) || (o.discard_gran & (o.discard_gran - 1u)) != 0u)) {
		fprintf(stderr, "wr-krbdcmp: --discard-gran must be a power of two\n");
		return 2;
	}
	if (mode_parse(o.mode, &pol) != 0 || (o.mode_osd != NULL && mode_parse(o.mode_osd, &pol_osd) != 0)) {
		fprintf(stderr, "wr-krbdcmp: --mode takes crc, crc-first, secure-first, secure or stock\n");
		return 2;
	}
	if (o.require_mode != NULL) {
		uint8_t eff_osd = pol_osd != 0u ? pol_osd : pol;

		if (strcmp(o.require_mode, "secure") != 0 && strcmp(o.require_mode, "crc") != 0) {
			fprintf(stderr, "wr-krbdcmp: --require-mode takes secure or crc\n");
			return 2;
		}
		/* an offer that cannot ever meet the assertion would only fail at the end of a long run */
		if ((strcmp(o.require_mode, "secure") == 0 && (pol == WR_MODE_CRC_ONLY || eff_osd == WR_MODE_CRC_ONLY)) ||
		    (strcmp(o.require_mode, "crc") == 0 && (pol == WR_MODE_SECURE_ONLY || eff_osd == WR_MODE_SECURE_ONLY))) {
			fprintf(stderr, "wr-krbdcmp: --require-mode %s can never be met with --mode %s%s%s: the offer excludes it\n", o.require_mode,
				o.mode != NULL ? o.mode : "crc", o.mode_osd != NULL ? " --mode-osd " : "", o.mode_osd != NULL ? o.mode_osd : "");
			return 2;
		}
	}
	if (o.accel) {
		fprintf(stderr, "wr-krbdcmp: --accel: this host has no accelerated primitives yet (the GCM hook is not wired): unsupported\n");
		return 2;
	}
	if (o.dir != NULL) {
		if (strcmp(o.dir, "core-to-krbd") == 0)
			dirs = WRL_CMP_DIR_C2K;
		else if (strcmp(o.dir, "krbd-to-core") == 0)
			dirs = WRL_CMP_DIR_K2C;
		else if (strcmp(o.dir, "interleave") == 0)
			dirs = WRL_CMP_DIR_INTER;
		else if (strcmp(o.dir, "all") == 0)
			dirs = WRL_CMP_DIR_ALL;
		else {
			fprintf(stderr, "wr-krbdcmp: --dir takes core-to-krbd, krbd-to-core, interleave or all\n");
			return 2;
		}
	}
	if (o.phase != NULL) {
		if (strcmp(o.phase, "edges") == 0)
			phases = WRL_CMP_PH_EDGES;
		else if (strcmp(o.phase, "random") == 0)
			phases = WRL_CMP_PH_RANDOM;
		else if (strcmp(o.phase, "scan") == 0)
			phases = WRL_CMP_PH_SCAN;
		else if (strcmp(o.phase, "all") == 0)
			phases = WRL_CMP_PH_ALL;
		else {
			fprintf(stderr, "wr-krbdcmp: --phase takes edges, random, scan or all\n");
			return 2;
		}
	}
	if (corrupt_parse(o.corrupt, &cfg) != 0) {
		fprintf(stderr, "wr-krbdcmp: bad --corrupt-at (OFF[:core|device|model][:once])\n");
		return 2;
	}
	if (o.verbose)
		level = WR_LOG_DEBUG;
	memset(&spec, 0, sizeof(spec));
	if (strlen(o.user) >= sizeof(spec.user)) {
		fprintf(stderr, "wr-krbdcmp: user name too long\n");
		return 2;
	}
	strcpy(spec.user, o.user);
	if (o.fsid != NULL) {
		if (fsid_parse(o.fsid, spec.fsid) != 0) {
			fprintf(stderr, "wr-krbdcmp: bad --fsid\n");
			return 2;
		}
		spec.fsid_known = 1;
	}
	st = wr_mon_parse_hosts(o.mon, strlen(o.mon), spec.mons, WR_MAX_MONS, &nmon);
	if (st != WR_OK) {
		fprintf(stderr, "wr-krbdcmp: --mon: %s\n", wr_strerror(st));
		return 2;
	}
	spec.n_mons = (uint8_t)nmon;
	st = wrl_read_text_file(o.keyring, kr, sizeof(kr), &krlen);
	if (st == WR_OK)
		st = wr_key_parse_keyring(&spec.key, kr, krlen);
	wipe(kr, sizeof(kr));
	if (st != WR_OK) {
		wr_key_wipe(&spec.key); /* a parse that stopped half way may have left part of a key */
		fprintf(stderr, "wr-krbdcmp: keyring %s: %s\n", o.keyring, wr_strerror(st));
		return 2;
	}
	fdrc = fd_open(&fd, &o);
	if (fdrc != 0) {
		wr_key_wipe(&spec.key);
		return fdrc == -2 ? 2 : 3;
	}
	t.t0 = now_ms();
	if (tool_create(&t, &o, &spec, &level, pol, pol_osd) != 0) {
		wr_key_wipe(&spec.key);
		close(fd.fd);
		return 2;
	}
	wr_key_wipe(&spec.key);
	if (tool_open_image(&t, &o, &info) != 0) {
		rc = 3;
		goto out;
	}
	printf("@%llu image id=%s prefix=%s size=%llu features=0x%llx order=%u object_size=%u pool_id=%lld writable=%u label=%s\n",
	       (unsigned long long)(now_ms() - t.t0), info.image_id, info.object_prefix, (unsigned long long)info.size_bytes,
	       (unsigned long long)info.features, (unsigned)info.order, (unsigned)info.object_size, (long long)info.pool_id, (unsigned)info.writable,
	       o.label != NULL ? o.label : "-");
	printf("@%llu device path=%s kind=%s bytes=%llu sector=%u\n", (unsigned long long)(now_ms() - t.t0), o.dev, fd.blk ? "block" : "file(self-test)",
	       (unsigned long long)(fd.size - fd.size % fd.sector), (unsigned)fd.sector);
	fflush(stdout);

	cfg.client = t.c;
	cfg.loop = t.loop;
	cfg.img = t.img;
	cfg.dev.ctx = &fd;
	cfg.dev.pread = fd_pread;
	cfg.dev.pwrite = fd_pwrite;
	cfg.dev.discard = fd_discard;
	cfg.dev.zeroes = fd_zeroes;
	cfg.dev.flush = fd_flush;
	cfg.dev.size = fd_size;
	cfg.dev.sector = fd.sector;
	cfg.dirs = dirs;
	cfg.phases = phases;
	if (o.have_seed) {
		cfg.seed = o.seed;
	} else {
		struct timespec ts;

		clock_gettime(CLOCK_REALTIME, &ts);
		cfg.seed = ((uint64_t)ts.tv_sec << 20) ^ (uint64_t)ts.tv_nsec ^ ((uint64_t)getpid() << 40);
	}
	cfg.ops = o.ops;
	cfg.time_ms = o.time_s * 1000u;
	cfg.max_len = o.max_len;
	cfg.chunk = o.chunk;
	cfg.checkpoint = o.checkpoint;
	cfg.stall_ms = o.stall_ms;
	cfg.mem_max = o.mem_max;
	cfg.depth = (uint32_t)o.depth;
	cfg.discard_gran = (uint32_t)o.discard_gran;
	cfg.out = stdout;
	if (fwd_start(&fw) == 0)
		cfg.out = fw.w;
	cfg.label = o.label;
	cfg.verbose = o.verbose;
	cfg.mirror = o.mirror;
	ran = 1;
	rc = wrl_cmp_run(&cfg, &res);
out:
	/* the connection counters of the core: the monitor's and every OSD's connection, by the mode it reached READY in */
	wr_client_get_stats(t.c, &ws);
	mode_ok = mode_met(o.require_mode, &ws);
	snprintf(extra, sizeof(extra), " conns_secure=%u conns_crc=%u sec_failures=%u", ws.conns_secure, ws.conns_crc, ws.sec_failures);
	if (fw.started)
		fwd_finish(&fw, extra, !mode_ok && rc == 0 && t.fatal == WR_OK);
	if (ran && fw.w == NULL) /* no stream thread (a pipe or thread that could not be made): the engine's stats record went out as it is, the fields follow on one of their own */
		printf("@%llu stats%s\n", (unsigned long long)(now_ms() - t.t0), extra);
	if (o.require_mode != NULL) {
		printf("@%llu result require_mode ok=%d wanted=%s conns_secure=%u conns_crc=%u sec_failures=%u\n", (unsigned long long)(now_ms() - t.t0), mode_ok,
		       o.require_mode, ws.conns_secure, ws.conns_crc, ws.sec_failures);
		if (!mode_ok)
			fprintf(stderr, "wr-krbdcmp: --require-mode %s: %u secure and %u crc connection(s) reached READY, %u secure-mode failure(s)\n", o.require_mode,
				ws.conns_secure, ws.conns_crc, ws.sec_failures);
	} else if (ran && ws.conns_crc != 0u && pol == WR_MODE_SECURE_ONLY) {
		fprintf(stderr, "wr-krbdcmp: warning: --mode secure was asked for but %u connection(s) reached READY in crc mode (%u in secure mode): pass "
			"--require-mode secure to make that a failure\n", ws.conns_crc, ws.conns_secure);
	}
	fflush(stdout);
	if (t.img != NULL && wr_image_get_state(t.img) != WR_IMG_FREE && t.fatal == WR_OK)
		st = wr_image_close(t.img, WR_CLOSE_ABANDON); /* the process ends next: a refusal changes nothing */
	wrl_loop_destroy(t.loop);
	wr_client_destroy(t.c);
	wrl_mem_free(&t.arena);
	wrl_mem_free(&t.bulk);
	(void)st;
	if (fd.fd >= 0)
		close(fd.fd);
	if (rc == 0 && t.fatal != WR_OK)
		rc = 3;
	if (rc == 0 && !mode_ok)
		rc = 5;
	return rc;
}
