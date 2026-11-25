/* SPDX-License-Identifier: MIT */
/*
 * rdbench - time sequential reads of a block device, the way the kernel client's side of the exit measurements does (design 14.4).
 *
 *   rdbench DEV direct|buffered BS BYTES SKIP RUNS [RA_KIB]
 *
 * Reads BYTES bytes from byte SKIP of DEV in blocks of BS bytes, RUNS times (after one untimed pass over the same range), and prints one line per pass:
 *   KRBD mode=direct bs=65536 run=1 bytes=134217728 secs=1.2345 mibs=103.7
 * direct uses O_DIRECT (no page cache, no client readahead); buffered reads through the page cache after the cache has been dropped
 * (/proc/sys/vm/drop_caches), with the device's readahead set to RA_KIB KiB when RA_KIB is given. Static, no library but libc; reads only.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void drop_caches(void)
{
	int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);

	if (fd >= 0) {
		if (write(fd, "1\n", 2) < 0)
			perror("drop_caches");
		close(fd);
	}
}

static int pass(int fd, char *buf, size_t bs, uint64_t bytes, uint64_t skip)
{
	uint64_t done = 0;

	while (done < bytes) {
		size_t want = bs;
		ssize_t n;

		if (bytes - done < want)
			want = (size_t)(bytes - done);
		n = pread(fd, buf, want, (off_t)(skip + done));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("pread");
			return -1;
		}
		if (n == 0) {
			fprintf(stderr, "rdbench: short device at %llu\n", (unsigned long long)(skip + done));
			return -1;
		}
		done += (uint64_t)n;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int direct, runs, fd, i;
	size_t bs;
	uint64_t bytes, skip;
	char *buf;
	double t0, t1;

	if (argc < 7) {
		fprintf(stderr, "usage: rdbench DEV direct|buffered BS BYTES SKIP RUNS [RA_KIB]\n");
		return 2;
	}
	direct = strcmp(argv[2], "direct") == 0;
	if (!direct && strcmp(argv[2], "buffered") != 0) {
		fprintf(stderr, "rdbench: mode must be direct or buffered\n");
		return 2;
	}
	bs = (size_t)strtoull(argv[3], NULL, 10);
	bytes = strtoull(argv[4], NULL, 10);
	skip = strtoull(argv[5], NULL, 10);
	runs = atoi(argv[6]);
	if (bs == 0 || bs > (64u << 20) || bytes == 0 || runs <= 0) {
		fprintf(stderr, "rdbench: bad numbers\n");
		return 2;
	}
	if (posix_memalign((void **)&buf, 4096, bs > (1u << 20) ? bs : (1u << 20)) != 0) {	/* the warm pass reads 1 MiB blocks */
		fprintf(stderr, "rdbench: no memory\n");
		return 1;
	}
	fd = open(argv[1], O_RDONLY | (direct ? O_DIRECT : 0));
	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (argc > 7 && !direct) {
		unsigned long ra_sectors = strtoul(argv[7], NULL, 10) * 2;

		if (ioctl(fd, BLKRASET, ra_sectors) < 0)
			perror("BLKRASET");
	}
	if (pass(fd, buf, 1u << 20, bytes, skip) != 0)	/* the warm pass: the servers have the range in cache, as in the iPXE runs */
		return 1;
	for (i = 1; i <= runs; i++) {
		if (!direct)
			drop_caches();
		t0 = now();
		if (pass(fd, buf, bs, bytes, skip) != 0)
			return 1;
		t1 = now();
		printf("KRBD mode=%s bs=%zu run=%d bytes=%llu secs=%.4f mibs=%.2f\n", direct ? "direct" : "ra", bs, i, (unsigned long long)bytes, t1 - t0,
		       (double)bytes / 1048576.0 / (t1 - t0));
		fflush(stdout);
	}
	close(fd);
	return 0;
}
