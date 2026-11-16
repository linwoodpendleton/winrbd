/* SPDX-License-Identifier: MIT */
/*
 * test_host_sys.c - unit tests of harness/host/wrl_sys.c: clocks, random bytes, the log sink, memory
 * regions and text files.
 *
 * The implementation file is included here (not linked) on purpose: it lets the test replace three
 * libc entry points with observable ones before the include, so that paths no real run reaches can be
 * driven and checked:
 *   getrandom -> wrlt_getrandom   (partial reads, EINTR, ENOSYS, errors, a zero return)
 *   read      -> wrlt_read        (EINTR, one byte at a time, EIO after N bytes; off by default)
 *   free      -> wrlt_free        (looks at the block just before it goes back to the allocator, which
 *                                  is how "wiped before free" is observed without touching freed memory)
 *   the entropy device path -> a variable (fallback and double failure)
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "wrt.h"

/* ---- hooks installed before the implementation is included ----------------------------------- */

static const char *wrlt_urandom_path = "/dev/urandom";

enum { GR_REAL, GR_ENOSYS, GR_EPERM, GR_EIO, GR_ZERO, GR_SLOW };
static int wrlt_gr_mode = GR_REAL;
static unsigned long wrlt_gr_calls;
static uint8_t wrlt_gr_counter;

static ssize_t wrlt_getrandom(void *buf, size_t n, unsigned flags);
#define getrandom wrlt_getrandom

static const void *wrlt_watch_ptr;
static size_t wrlt_watch_len;
static int wrlt_watch_seen;
static int wrlt_watch_all_zero;

enum { RD_REAL, RD_EINTR_SLOW, RD_EIO_AFTER };
static int wrlt_rd_mode = RD_REAL;
static unsigned long wrlt_rd_calls;
static size_t wrlt_rd_served;
static size_t wrlt_rd_limit;

static ssize_t wrlt_read(int fd, void *buf, size_t n);
#define read wrlt_read

static void wrlt_free(void *p);
#define free(p) wrlt_free(p)

#define WRL_URANDOM_PATH wrlt_urandom_path
#include "../host/wrl_sys.c"

#undef free
#undef getrandom
#undef read

static ssize_t wrlt_read(int fd, void *buf, size_t n)
{
	wrlt_rd_calls++;
	switch (wrlt_rd_mode) {
	case RD_EINTR_SLOW:
		/* every other call is interrupted; the others return a single byte at most */
		if (wrlt_rd_calls % 2u == 1u) {
			errno = EINTR;
			return -1;
		}
		return read(fd, buf, n > 1 ? 1 : n);
	case RD_EIO_AFTER:
		if (wrlt_rd_served >= wrlt_rd_limit) {
			errno = EIO;
			return -1;
		}
		if (n > wrlt_rd_limit - wrlt_rd_served)
			n = wrlt_rd_limit - wrlt_rd_served;
		{
			ssize_t r = read(fd, buf, n);

			if (r > 0)
				wrlt_rd_served += (size_t)r;
			return r;
		}
	default:
		return read(fd, buf, n);
	}
}

static ssize_t wrlt_getrandom(void *buf, size_t n, unsigned flags)
{
	uint8_t *p = (uint8_t *)buf;

	wrlt_gr_calls++;
	switch (wrlt_gr_mode) {
	case GR_ENOSYS:
		errno = ENOSYS;
		return -1;
	case GR_EPERM:
		errno = EPERM;
		return -1;
	case GR_EIO:
		errno = EIO;
		return -1;
	case GR_ZERO:
		return 0;
	case GR_SLOW:
		/* every other call is interrupted; the others give one byte of a counting pattern */
		if (wrlt_gr_calls % 2u == 1u) {
			errno = EINTR;
			return -1;
		}
		p[0] = wrlt_gr_counter++;
		return 1;
	default:
		return getrandom(buf, n, flags);
	}
}

static void wrlt_free(void *p)
{
	if (p != NULL && p == wrlt_watch_ptr) {
		const uint8_t *b = (const uint8_t *)p;
		size_t i;

		wrlt_watch_seen = 1;
		wrlt_watch_all_zero = 1;
		for (i = 0; i < wrlt_watch_len; i++)
			if (b[i] != 0)
				wrlt_watch_all_zero = 0;
	}
	(free)(p);
}

/* ---- helpers ---------------------------------------------------------------------------------- */

static int all_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != 0)
			return 0;
	return 1;
}

static uint64_t ms_of(const struct timespec *ts)
{
	return (uint64_t)ts->tv_sec * 1000u + (uint64_t)ts->tv_nsec / 1000000u;
}

/* Capture of fd 2 into a temp file: begin, run, end returns the bytes written (NUL-terminated). */
static int cap_saved = -1;
static int cap_fd = -1;
static char cap_path[] = "/tmp/wrl_sys_cap_XXXXXX";

static void cap_begin(void)
{
	fflush(stderr);
	cap_fd = mkstemp(cap_path);
	WRT_CHECK(cap_fd >= 0);
	cap_saved = dup(STDERR_FILENO);
	WRT_CHECK(cap_saved >= 0);
	WRT_CHECK(dup2(cap_fd, STDERR_FILENO) >= 0);
}

static size_t cap_end(char *out, size_t cap)
{
	off_t end;
	ssize_t r;
	size_t n = 0;

	fflush(stderr);
	WRT_CHECK(dup2(cap_saved, STDERR_FILENO) >= 0);
	(void)close(cap_saved);
	end = lseek(cap_fd, 0, SEEK_END);
	WRT_CHECK(end >= 0 && (size_t)end < cap);
	(void)lseek(cap_fd, 0, SEEK_SET);
	while (n < cap - 1u && (r = read(cap_fd, out + n, cap - 1u - n)) > 0)
		n += (size_t)r;
	out[n] = '\0';
	(void)close(cap_fd);
	(void)unlink(cap_path);
	cap_fd = cap_saved = -1;
	memcpy(cap_path + sizeof(cap_path) - 7, "XXXXXX", 6);
	return n;
}

static size_t count_char(const char *s, char c)
{
	size_t n = 0;

	for (; *s != '\0'; s++)
		if (*s == c)
			n++;
	return n;
}

/* ---- clocks ----------------------------------------------------------------------------------- */

static void test_clock(void)
{
	wr_clock prev, cur;
	struct timespec nap = {0, 20 * 1000 * 1000};
	struct timespec rt;
	int i, monotone = 1;
	uint64_t t0;

	wrl_clock(&prev);
	for (i = 0; i < 1000; i++) {
		wrl_clock(&cur);
		if (cur.mono_ms < prev.mono_ms)
			monotone = 0;
		prev = cur;
	}
	WRT_CHECK(monotone);
	WRT_CHECK(cur.mono_ms > 0);

	/* the clock really runs: a 20 ms sleep moves it by 20..2000 ms */
	wrl_clock(&prev);
	(void)nanosleep(&nap, NULL);
	wrl_clock(&cur);
	WRT_CHECK(cur.mono_ms >= prev.mono_ms + 20u);
	WRT_CHECK(cur.mono_ms <= prev.mono_ms + 2000u);

	/* wall clock within 2 s of time(), and consistent with CLOCK_REALTIME */
	t0 = (uint64_t)time(NULL);
	wrl_clock(&cur);
	WRT_CHECK(cur.wall_ms / 1000u + 2u >= t0 && cur.wall_ms / 1000u <= t0 + 2u);
	WRT_CHECK(clock_gettime(CLOCK_REALTIME, &rt) == 0);
	WRT_CHECK(ms_of(&rt) >= cur.wall_ms && ms_of(&rt) - cur.wall_ms < 2000u);

	wrl_clock(NULL); /* must not crash */
}

/* ---- random ----------------------------------------------------------------------------------- */

#define GUARD 16u

static void fill_check(size_t n)
{
	uint8_t *a = (uint8_t *)malloc(n + 2 * GUARD);
	uint8_t *b = (uint8_t *)malloc(n + 2 * GUARD);

	WRT_CHECK(a != NULL && b != NULL);
	if (a == NULL || b == NULL) {
		(free)(a);
		(free)(b);
		return;
	}
	memset(a, 0xC3, n + 2 * GUARD);
	memset(b, 0xC3, n + 2 * GUARD);
	WRT_CHECK_STATUS(WR_OK, wrl_random(NULL, a + GUARD, n));
	WRT_CHECK_STATUS(WR_OK, wrl_random(NULL, b + GUARD, n));
	/* the guards on both sides are untouched */
	WRT_CHECK(memcmp(a, b, GUARD) == 0 && a[0] == 0xC3 && a[GUARD - 1] == 0xC3);
	WRT_CHECK(a[GUARD + n] == 0xC3 && a[2 * GUARD + n - 1] == 0xC3);
	WRT_CHECK(b[GUARD + n] == 0xC3 && b[2 * GUARD + n - 1] == 0xC3);
	if (n >= 16) {
		/* two draws of 16+ bytes collide with probability 2^-128; all-zero is just as unlikely */
		WRT_CHECK(memcmp(a + GUARD, b + GUARD, n) != 0);
		WRT_CHECK(!all_zero(a + GUARD, n));
	}
	(free)(a);
	(free)(b);
}

static void test_random(void)
{
	static const size_t sizes[] = {1, 2, 7, 15, 16, 17, 31, 32, 255, 256, 257, 1000, 4096, 4097, 65535, 65536};
	size_t i;
	uint8_t buf[32];
	uint8_t one[1];
	int varied = 0;
	char tmp[] = "/tmp/wrl_sys_ur_XXXXXX";
	int fd;

	wrlt_gr_mode = GR_REAL;
	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
		fill_check(sizes[i]);

	/* a single byte varies across draws (256 draws all equal: 2^-2040) */
	WRT_CHECK_STATUS(WR_OK, wrl_random(NULL, one, 1));
	for (i = 0; i < 256; i++) {
		uint8_t first = one[0];

		WRT_CHECK_STATUS(WR_OK, wrl_random(NULL, one, 1));
		if (one[0] != first)
			varied = 1;
	}
	WRT_CHECK(varied);

	/* argument edge cases */
	WRT_CHECK_STATUS(WR_OK, wrl_random(NULL, NULL, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_random(NULL, NULL, 5));

	/* getrandom hands back one byte per call and is interrupted every other call: the loop must
	 * advance its offset, retry on EINTR, and fill exactly n bytes in order */
	wrlt_gr_mode = GR_SLOW;
	wrlt_gr_calls = 0;
	wrlt_gr_counter = 0;
	memset(buf, 0xFF, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wrl_random(NULL, buf, 20));
	for (i = 0; i < 20; i++)
		WRT_CHECK_U64(buf[i], i);
	WRT_CHECK_U64(buf[20], 0xFF);
	WRT_CHECK_U64(wrlt_gr_calls, 40);

	/* no getrandom (ENOSYS, or EPERM from a sandbox): fall back to the entropy device */
	wrlt_gr_mode = GR_ENOSYS;
	memset(buf, 0, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wrl_random(NULL, buf, sizeof(buf)));
	WRT_CHECK(!all_zero(buf, sizeof(buf)));
	wrlt_gr_mode = GR_EPERM;
	memset(buf, 0, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wrl_random(NULL, buf, sizeof(buf)));
	WRT_CHECK(!all_zero(buf, sizeof(buf)));

	/* fallback that cannot work: no weak substitute, the failure is reported */
	wrlt_urandom_path = "/nonexistent-dir/urandom";
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wrl_random(NULL, buf, sizeof(buf)));
	wrlt_urandom_path = "/dev/urandom";

	/* other getrandom failures are not retried through the device and are not hidden */
	wrlt_gr_mode = GR_EIO;
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wrl_random(NULL, buf, sizeof(buf)));
	wrlt_gr_mode = GR_ZERO;
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wrl_random(NULL, buf, sizeof(buf)));
	wrlt_gr_mode = GR_REAL;

	/* the device reader itself: missing file, short file (EOF before n bytes), full file */
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wrl_urandom_fill("/nonexistent-dir/urandom", buf, 4));
	fd = mkstemp(tmp);
	WRT_CHECK(fd >= 0);
	if (fd >= 0) {
		static const uint8_t pat[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

		WRT_CHECK(write(fd, pat, 3) == 3);
		(void)close(fd);
		WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wrl_urandom_fill(tmp, buf, 10));
		WRT_CHECK_STATUS(WR_OK, wrl_urandom_fill(tmp, buf, 3));
		WRT_CHECK_MEM(buf, pat, 3);
		(void)unlink(tmp);
	}
	memset(buf, 0, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wrl_urandom_fill("/dev/urandom", buf, sizeof(buf)));
	WRT_CHECK(!all_zero(buf, sizeof(buf)));
}

/* ---- log sink --------------------------------------------------------------------------------- */

static wr_log_rec mkrec(unsigned level, const char *msg)
{
	wr_log_rec r;

	memset(&r, 0, sizeof(r));
	r.level = (uint8_t)level;
	r.module = WR_MOD_CLIENT;
	r.status = WR_OK;
	r.msg = msg;
	return r;
}

static void test_log(void)
{
	static char out[8192];
	static char longmsg[3000];
	unsigned lvl;
	wr_log_rec r;
	wr_host_ops ops;
	size_t n;

	/* default filter (ctx NULL) = INFO: INFO passes, DEBUG does not */
	cap_begin();
	r = mkrec(WR_LOG_INFO, "hello");
	wrl_log_stderr(NULL, &r);
	r = mkrec(WR_LOG_DEBUG, "hidden");
	wrl_log_stderr(NULL, &r);
	n = cap_end(out, sizeof(out));
	WRT_CHECK(n > 0);
	WRT_CHECK(strstr(out, "hello") != NULL);
	WRT_CHECK(strstr(out, "hidden") == NULL);
	WRT_CHECK_U64(count_char(out, '\n'), 1);

	/* exact line format: level, module, status name, conn, message, four hex arguments */
	cap_begin();
	r = mkrec(WR_LOG_WARN, "frame bad");
	r.module = WR_MOD_M2;
	r.status = WR_E_M2_FRAME_CRC;
	r.conn = 0x00010002u;
	r.a0 = 1;
	r.a1 = UINT64_MAX;
	r.a2 = 0;
	r.a3 = 0xdeadbeefull;
	wrl_log_stderr(NULL, &r);
	n = cap_end(out, sizeof(out));
	WRT_CHECK(n > 0);
	WRT_CHECK(strcmp(out, "winrbd WARN msgr2 WR_E_M2_FRAME_CRC conn=0x00010002 frame bad "
			      "a0=0x1 a1=0xffffffffffffffff a2=0x0 a3=0xdeadbeef\n") == 0);

	/* no connection: no conn field; success status prints WR_OK; unknown module and level */
	cap_begin();
	r = mkrec(WR_LOG_ERR, "plain");
	r.module = 200;
	wrl_log_stderr(NULL, &r);
	n = cap_end(out, sizeof(out));
	WRT_CHECK(n > 0);
	WRT_CHECK(strcmp(out, "winrbd ERR mod? WR_OK plain a0=0x0 a1=0x0 a2=0x0 a3=0x0\n") == 0);

	/* the level filter, every threshold: lines printed = records with level <= max */
	for (lvl = 0; lvl <= 6; lvl++) {
		unsigned want = lvl > 5 ? 5 : lvl;
		unsigned l;

		cap_begin();
		for (l = 1; l <= 5; l++) {
			r = mkrec(l, "m");
			wrl_log_stderr(&lvl, &r);
		}
		n = cap_end(out, sizeof(out));
		WRT_CHECK_U64(count_char(out, '\n'), want);
		WRT_CHECK((strstr(out, "TRACE") != NULL) == (lvl >= WR_LOG_TRACE));
		WRT_CHECK((strstr(out, "ERR") != NULL) == (lvl >= WR_LOG_ERR));
	}

	/* a message cannot break the one-line rule, a missing one is tolerated, NULL record is ignored */
	cap_begin();
	r = mkrec(WR_LOG_ERR, "a\nb\r\tc\x01 d");
	wrl_log_stderr(NULL, &r);
	r = mkrec(WR_LOG_ERR, NULL);
	wrl_log_stderr(NULL, &r);
	wrl_log_stderr(NULL, NULL);
	n = cap_end(out, sizeof(out));
	WRT_CHECK(strstr(out, "a?b??c? d") != NULL);
	WRT_CHECK(strstr(out, "(no message)") != NULL);
	WRT_CHECK_U64(count_char(out, '\n'), 2);

	/* an over-long message is cut, the record is still one complete line */
	memset(longmsg, 'x', sizeof(longmsg) - 1);
	longmsg[sizeof(longmsg) - 1] = '\0';
	cap_begin();
	r = mkrec(WR_LOG_ERR, longmsg);
	r.conn = 0xffffffffu;
	r.a0 = r.a1 = r.a2 = r.a3 = UINT64_MAX;
	wrl_log_stderr(NULL, &r);
	n = cap_end(out, sizeof(out));
	WRT_CHECK(n > 100 && n <= WRL_LOG_LINE_MAX);
	WRT_CHECK(out[n - 1] == '\n');
	WRT_CHECK_U64(count_char(out, '\n'), 1);

	/* the ops table: filled, random and log work through it, the level is read through ctx */
	lvl = WR_LOG_ERR;
	memset(&ops, 0xEE, sizeof(ops));
	wrl_host_ops_init(&ops, &lvl);
	WRT_CHECK_U64(ops.size, sizeof(wr_host_ops));
	WRT_CHECK(ops.ctx == &lvl);
	WRT_CHECK(ops.random == wrl_random);
	WRT_CHECK(ops.log == wrl_log_stderr);
	WRT_CHECK(ops.prim == NULL);
	{
		uint8_t b[24];

		memset(b, 0, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, ops.random(ops.ctx, b, sizeof(b)));
		WRT_CHECK(!all_zero(b, sizeof(b)));
	}
	cap_begin();
	r = mkrec(WR_LOG_INFO, "filtered");
	ops.log(ops.ctx, &r);
	r = mkrec(WR_LOG_ERR, "kept");
	ops.log(ops.ctx, &r);
	n = cap_end(out, sizeof(out));
	WRT_CHECK(strstr(out, "filtered") == NULL && strstr(out, "kept") != NULL);
	lvl = WR_LOG_TRACE; /* the filter follows the variable, not a copy */
	cap_begin();
	r = mkrec(WR_LOG_TRACE, "now-shown");
	ops.log(ops.ctx, &r);
	n = cap_end(out, sizeof(out));
	WRT_CHECK(strstr(out, "now-shown") != NULL);

	wrl_host_ops_init(&ops, NULL); /* NULL = INFO */
	WRT_CHECK(ops.ctx == NULL);
	cap_begin();
	r = mkrec(WR_LOG_INFO, "info-ok");
	ops.log(ops.ctx, &r);
	r = mkrec(WR_LOG_DEBUG, "debug-no");
	ops.log(ops.ctx, &r);
	n = cap_end(out, sizeof(out));
	WRT_CHECK(strstr(out, "info-ok") != NULL && strstr(out, "debug-no") == NULL);
	wrl_host_ops_init(NULL, NULL); /* must not crash */
}

#if defined(__SANITIZE_ADDRESS__)
#define WRLT_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer)
#define WRLT_ASAN 1 /* MemorySanitizer's allocator aborts on an absurd request as well */
#endif
#endif
#ifndef WRLT_ASAN
#define WRLT_ASAN 0
#endif

/* ---- memory regions --------------------------------------------------------------------------- */

static void test_mem(void)
{
	static const size_t sizes[] = {1, 15, 63, 64, 65, 100, 4096, 4097, 1u << 20, (1u << 20) + 1};
	wr_mem_region r;
	size_t i;

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		size_t sz = sizes[i];
		size_t rounded = (sz + 63u) & ~(size_t)63u;

		memset(&r, 0xAB, sizeof(r));
		WRT_CHECK_STATUS(WR_OK, wrl_mem_alloc(&r, sz));
		WRT_CHECK(r.base != NULL);
		WRT_CHECK_U64(r.size, sz);
		WRT_CHECK_U64((uintptr_t)r.base % 64u, 0);
		WRT_CHECK(all_zero(r.base, sz));
		if (r.base != NULL) {
			/* dirty it, free it, and ask again: the new block is zero whatever malloc reuses */
			wr_mem_region r2;

			memset(r.base, 0xFF, sz);
			wrl_mem_free(&r);
			WRT_CHECK(r.base == NULL && r.size == 0);
			WRT_CHECK_STATUS(WR_OK, wrl_mem_alloc(&r2, sz));
			WRT_CHECK(r2.base != NULL && all_zero(r2.base, sz));
			WRT_CHECK_U64((uintptr_t)r2.base % 64u, 0);

			/* wipe-on-free: the allocator receives an all-zero block, padding included */
			memset(r2.base, 0x5A, sz);
			wrlt_watch_ptr = r2.base;
			wrlt_watch_len = rounded;
			wrlt_watch_seen = 0;
			wrlt_watch_all_zero = 0;
			wrl_mem_free(&r2);
			WRT_CHECK(wrlt_watch_seen);
			WRT_CHECK(wrlt_watch_all_zero);
			wrlt_watch_ptr = NULL;
			WRT_CHECK(r2.base == NULL && r2.size == 0);
		}
	}

	/* size 0 is {NULL, 0}; freeing that, a NULL pointer, or the same region twice is harmless */
	memset(&r, 0xAB, sizeof(r));
	WRT_CHECK_STATUS(WR_OK, wrl_mem_alloc(&r, 0));
	WRT_CHECK(r.base == NULL && r.size == 0);
	wrl_mem_free(&r);
	wrl_mem_free(&r);
	wrl_mem_free(NULL);

	/* failures leave an empty region */
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_mem_alloc(NULL, 10));
	memset(&r, 0xAB, sizeof(r));
	WRT_CHECK_STATUS(WR_E_TOOBIG, wrl_mem_alloc(&r, SIZE_MAX));
	WRT_CHECK(r.base == NULL && r.size == 0);
	/* an allocation the system cannot satisfy; skipped under ASan, whose allocator aborts on it */
	if (sizeof(size_t) == 8 && !WRLT_ASAN) {
		memset(&r, 0xAB, sizeof(r));
		WRT_CHECK_STATUS(WR_E_BUDGET, wrl_mem_alloc(&r, (size_t)1 << (sizeof(size_t) * 8 - 2)));
		WRT_CHECK(r.base == NULL && r.size == 0);
	}
}

/* ---- text files ------------------------------------------------------------------------------- */

static int make_file(char *path, const void *data, size_t n)
{
	int fd = mkstemp(path);

	if (fd < 0)
		return -1;
	if (n > 0 && write(fd, data, n) != (ssize_t)n) {
		(void)close(fd);
		return -1;
	}
	return close(fd);
}

static void test_text_file(void)
{
	char path[] = "/tmp/wrl_sys_txt_XXXXXX";
	char buf[128];
	char big[128];
	size_t len = 99;
	static const char keyring[] = "[client.winrbd]\n\tkey = AQBNW3Ro+0dWMBAAxJSkQiV2gXEyW8FlA1TVag==\n";

	WRT_CHECK(make_file(path, keyring, sizeof(keyring) - 1) == 0);
	memset(buf, 0xAA, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wrl_read_text_file(path, buf, sizeof(buf), &len));
	WRT_CHECK_U64(len, sizeof(keyring) - 1);
	WRT_CHECK(strcmp(buf, keyring) == 0);
	WRT_CHECK_U64(buf[len], 0);
	(void)unlink(path);

	/* empty file: success, empty string */
	memcpy(path, "/tmp/wrl_sys_txt_XXXXXX", sizeof("/tmp/wrl_sys_txt_XXXXXX"));
	WRT_CHECK(make_file(path, "", 0) == 0);
	memset(buf, 0xAA, sizeof(buf));
	len = 99;
	WRT_CHECK_STATUS(WR_OK, wrl_read_text_file(path, buf, sizeof(buf), &len));
	WRT_CHECK(len == 0 && buf[0] == '\0');
	/* cap 1 holds only the NUL: an empty file fits */
	WRT_CHECK_STATUS(WR_OK, wrl_read_text_file(path, buf, 1, &len));
	(void)unlink(path);

	/* exactly cap-1 bytes fits; one more byte is WR_E_RANGE and leaves nothing behind */
	memset(big, 'k', sizeof(big));
	memcpy(path, "/tmp/wrl_sys_txt_XXXXXX", sizeof("/tmp/wrl_sys_txt_XXXXXX"));
	WRT_CHECK(make_file(path, big, sizeof(buf) - 1) == 0);
	WRT_CHECK_STATUS(WR_OK, wrl_read_text_file(path, buf, sizeof(buf), &len));
	WRT_CHECK_U64(len, sizeof(buf) - 1);
	WRT_CHECK_U64(buf[sizeof(buf) - 1], 0);
	/* the same file into a buffer one byte smaller: too large */
	memset(buf, 0xAA, sizeof(buf));
	len = 99;
	WRT_CHECK_STATUS(WR_E_RANGE, wrl_read_text_file(path, buf, sizeof(buf) - 1, &len));
	WRT_CHECK_U64(len, 0);
	WRT_CHECK(buf[0] == '\0'); /* declared size known up front: refused before reading */
	/* a file that does not know its size (st_size 0) is read, found too big by the probe byte, and
	 * what was read is wiped, not left for the caller */
	memset(buf, 0xAA, sizeof(buf));
	len = 99;
	WRT_CHECK_STATUS(WR_E_RANGE, wrl_read_text_file("/proc/self/status", buf, 64, &len));
	WRT_CHECK_U64(len, 0);
	WRT_CHECK(all_zero(buf, 63) && buf[63] == (char)0xAA);
	WRT_CHECK_STATUS(WR_E_RANGE, wrl_read_text_file(path, buf, 1, &len));
	(void)unlink(path);

	/* a large file into a small buffer */
	{
		static char megabyte[1u << 20];

		memset(megabyte, 'z', sizeof(megabyte));
		memcpy(path, "/tmp/wrl_sys_txt_XXXXXX", sizeof("/tmp/wrl_sys_txt_XXXXXX"));
		WRT_CHECK(make_file(path, megabyte, sizeof(megabyte)) == 0);
		len = 99;
		WRT_CHECK_STATUS(WR_E_RANGE, wrl_read_text_file(path, buf, sizeof(buf), &len));
		WRT_CHECK_U64(len, 0);
		WRT_CHECK(buf[0] == '\0');
		(void)unlink(path);
	}

	/* a NUL byte inside is rejected and wiped */
	memcpy(path, "/tmp/wrl_sys_txt_XXXXXX", sizeof("/tmp/wrl_sys_txt_XXXXXX"));
	WRT_CHECK(make_file(path, "key=ab\0cd\n", 10) == 0);
	len = 99;
	WRT_CHECK_STATUS(WR_E_ENCODING, wrl_read_text_file(path, buf, sizeof(buf), &len));
	WRT_CHECK_U64(len, 0);
	WRT_CHECK(all_zero(buf, 10));
	(void)unlink(path);

	/* a keyring whose size is declared up front is refused without being read: the buffer keeps
	 * the empty string it was given, even when the buffer is far smaller than the file */
	memcpy(path, "/tmp/wrl_sys_txt_XXXXXX", sizeof("/tmp/wrl_sys_txt_XXXXXX"));
	WRT_CHECK(make_file(path, keyring, sizeof(keyring) - 1) == 0);
	memset(buf, 'S', sizeof(buf));
	len = 99;
	wrlt_rd_calls = 0;
	WRT_CHECK_STATUS(WR_E_RANGE, wrl_read_text_file(path, buf, 8, &len));
	WRT_CHECK(len == 0 && buf[0] == '\0' && buf[8] == 'S');
	WRT_CHECK_U64(wrlt_rd_calls, 0);

	/* interrupted and one-byte reads still give the whole file, in order */
	wrlt_rd_mode = RD_EINTR_SLOW;
	len = 0;
	memset(buf, 0xAA, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, wrl_read_text_file(path, buf, sizeof(buf), &len));
	WRT_CHECK_U64(len, sizeof(keyring) - 1);
	WRT_CHECK(strcmp(buf, keyring) == 0);

	/* the same with a buffer exactly one byte short for the probe (cap - 1 == file size) */
	len = 99;
	WRT_CHECK_STATUS(WR_OK, wrl_read_text_file(path, buf, sizeof(keyring), &len));
	WRT_CHECK_U64(len, sizeof(keyring) - 1);
	wrlt_rd_mode = RD_REAL;

	/* a read error half way: failure, and the part already read is wiped, not left in the buffer */
	wrlt_rd_mode = RD_EIO_AFTER;
	wrlt_rd_served = 0;
	wrlt_rd_limit = 20;
	memset(buf, 0xAA, sizeof(buf));
	len = 99;
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file(path, buf, sizeof(buf), &len));
	WRT_CHECK_U64(len, 0);
	WRT_CHECK(buf[0] == '\0' && all_zero(buf, 20));
	/* error on the probe read (file is exactly cap - 1 bytes and the next read fails) */
	wrlt_rd_served = 0;
	wrlt_rd_limit = sizeof(keyring) - 1;
	memset(buf, 0xAA, sizeof(buf));
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file(path, buf, sizeof(keyring), &len));
	WRT_CHECK(buf[0] == '\0' && all_zero(buf, sizeof(keyring) - 1));
	wrlt_rd_mode = RD_REAL;
	(void)unlink(path);

	/* a symlink to a regular file works; a FIFO (must not block) and a character device are refused */
	{
		char dir[] = "/tmp/wrl_sys_dir_XXXXXX";
		char fpath[64], lpath[64], ffifo[64];
		int fd;

		WRT_CHECK(mkdtemp(dir) != NULL);
		snprintf(fpath, sizeof(fpath), "%s/f", dir);
		snprintf(lpath, sizeof(lpath), "%s/l", dir);
		snprintf(ffifo, sizeof(ffifo), "%s/p", dir);
		fd = open(fpath, O_WRONLY | O_CREAT, 0600);
		WRT_CHECK(fd >= 0);
		if (fd >= 0) {
			WRT_CHECK(write(fd, "abc", 3) == 3);
			(void)close(fd);
		}
		WRT_CHECK(symlink(fpath, lpath) == 0);
		WRT_CHECK(mkfifo(ffifo, 0600) == 0);
		len = 0;
		WRT_CHECK_STATUS(WR_OK, wrl_read_text_file(lpath, buf, sizeof(buf), &len));
		WRT_CHECK(len == 3 && strcmp(buf, "abc") == 0);
		buf[0] = 'x';
		WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file(ffifo, buf, sizeof(buf), &len));
		WRT_CHECK(len == 0 && buf[0] == '\0');
		buf[0] = 'x';
		WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file("/dev/zero", buf, sizeof(buf), &len));
		WRT_CHECK(len == 0 && buf[0] == '\0');
		(void)unlink(fpath);
		(void)unlink(lpath);
		(void)unlink(ffifo);
		(void)rmdir(dir);
	}

	/* bad arguments still leave an empty string in a usable buffer */
	memset(buf, 'x', sizeof(buf));
	len = 99;
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file(NULL, buf, sizeof(buf), &len));
	WRT_CHECK(buf[0] == '\0' && len == 0);
	memset(buf, 'x', sizeof(buf));
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file("/etc/hostname", buf, sizeof(buf), NULL));
	WRT_CHECK(buf[0] == '\0');

	/* missing file, directory, bad arguments */
	buf[0] = 'x';
	len = 99;
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file("/nonexistent-dir/no-such-keyring", buf, sizeof(buf), &len));
	WRT_CHECK(len == 0 && buf[0] == '\0');
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file("/tmp", buf, sizeof(buf), &len));
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file(NULL, buf, sizeof(buf), &len));
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file("/etc/hostname", NULL, sizeof(buf), &len));
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file("/etc/hostname", buf, 0, &len));
	WRT_CHECK_STATUS(WR_E_INVAL, wrl_read_text_file("/etc/hostname", buf, sizeof(buf), NULL));
}

int main(void)
{
	test_clock();
	test_random();
	test_log();
	test_mem();
	test_text_file();
	return wrt_finish();
}
