/* SPDX-License-Identifier: MIT */
/*
 * wrl_sys.c - part 1 of the Linux host: the system services of the shim (clock, random bytes, log
 * sink, memory regions, small text files). Harness code: libc and POSIX are allowed here. The
 * socket pump is a different module (wrl_loop.c).
 *
 * Rules kept here, because the core depends on them:
 *   - random bytes come from the kernel only; a failure is reported, never papered over;
 *   - key material is never written anywhere by this file; regions that may hold keys are wiped
 *     before they are returned to the allocator; a keyring that could not be read in full is wiped
 *     from the caller's buffer before the error is returned.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "wrl_host.h"

/* The entropy device used when getrandom(2) is not available (old kernel, seccomp filter). Tests that
 * include this file may point it elsewhere before the include. */
#ifndef WRL_URANDOM_PATH
#define WRL_URANDOM_PATH "/dev/urandom"
#endif

#define WRL_MEM_ALIGN 64u
#define WRL_LOG_LINE_MAX 512u

/* ---- wiping ---------------------------------------------------------------------------------- */

/* memset that the optimiser cannot drop: the barrier makes the bytes look used. */
static void wrl_wipe(void *p, size_t n)
{
	if (p == NULL || n == 0)
		return;
	memset(p, 0, n);
#if defined(__GNUC__) || defined(__clang__)
	__asm__ __volatile__("" : : "r"(p) : "memory");
#endif
}

/* ---- clocks ---------------------------------------------------------------------------------- */

static uint64_t wrl_clock_ms(clockid_t id)
{
	struct timespec ts;

	if (clock_gettime(id, &ts) != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

void wrl_clock(wr_clock *out)
{
	if (out == NULL)
		return;
	out->mono_ms = wrl_clock_ms(CLOCK_MONOTONIC);
	out->wall_ms = wrl_clock_ms(CLOCK_REALTIME); /* 0 only if the realtime clock failed: "no wall clock" */
}

/* ---- random ---------------------------------------------------------------------------------- */

/* Fill from a device file, with a loop for short reads. EOF before n bytes is a failure. */
static wr_status wrl_urandom_fill(const char *path, uint8_t *out, size_t n)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	size_t got = 0;

	if (fd < 0)
		return WR_E_HOST_RANDOM;
	while (got < n) {
		ssize_t r = read(fd, out + got, n - got);

		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0) {
			(void)close(fd);
			return WR_E_HOST_RANDOM;
		}
		got += (size_t)r;
	}
	(void)close(fd);
	return WR_OK;
}

wr_status wrl_random(void *ctx, uint8_t *out, size_t n)
{
	size_t got = 0;

	(void)ctx;
	if (n == 0)
		return WR_OK;
	if (out == NULL)
		return WR_E_INVAL;
	while (got < n) {
		ssize_t r = getrandom(out + got, n - got, 0);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			/* Only "this kernel or sandbox has no getrandom" falls back to the entropy device (which
			 * is the same kernel pool); any other failure is reported as it is. */
			if (errno == ENOSYS || errno == EPERM)
				return wrl_urandom_fill(WRL_URANDOM_PATH, out + got, n - got);
			return WR_E_HOST_RANDOM;
		}
		if (r == 0)
			return WR_E_HOST_RANDOM; /* getrandom never returns 0 for n > 0: treat as broken */
		got += (size_t)r;
	}
	return WR_OK;
}

/* ---- log sink -------------------------------------------------------------------------------- */

static const char *wrl_level_name(unsigned level)
{
	switch (level) {
	case WR_LOG_ERR:
		return "ERR";
	case WR_LOG_WARN:
		return "WARN";
	case WR_LOG_INFO:
		return "INFO";
	case WR_LOG_DEBUG:
		return "DEBUG";
	case WR_LOG_TRACE:
		return "TRACE";
	default:
		return "L?";
	}
}

static const char *wrl_module_name(unsigned module)
{
	static const char *const names[] = {"none", "util", "crypto", "msgr2", "auth", "mon",
					    "client", "map", "crush", "osd", "rbd", "host"};

	if (module < sizeof(names) / sizeof(names[0]))
		return names[module];
	return "mod?";
}

/* The line is cut on purpose when it does not fit (the lengths below are clamped after every snprintf); gcc at -O2 cannot
 * see that the remaining room is never zero and warns about the cut itself. */
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
void wrl_log_stderr(void *ctx, const wr_log_rec *rec)
{
	char line[WRL_LOG_LINE_MAX];
	char msg[200];
	unsigned max_level = WR_LOG_INFO;
	size_t i, len;
	int n;

	if (rec == NULL)
		return;
	if (ctx != NULL)
		max_level = *(const unsigned *)ctx;
	if ((unsigned)rec->level > max_level)
		return;

	/* The message is a static literal from the core, but a line sink must stay one line whatever it is
	 * given: copy it with anything outside printable ASCII replaced. */
	if (rec->msg == NULL) {
		memcpy(msg, "(no message)", sizeof("(no message)"));
	} else {
		for (i = 0; i + 1 < sizeof(msg) && rec->msg[i] != '\0'; i++) {
			unsigned char ch = (unsigned char)rec->msg[i];

			msg[i] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
		}
		msg[i] = '\0';
	}

	n = snprintf(line, sizeof(line) - 1, "winrbd %s %s %s", wrl_level_name(rec->level),
		     wrl_module_name(rec->module), wr_status_name(rec->status));
	if (n < 0)
		return;
	len = (size_t)n < sizeof(line) - 1 ? (size_t)n : sizeof(line) - 2;
	if (rec->conn != WR_CONN_NONE && len < sizeof(line) - 1) {
		n = snprintf(line + len, sizeof(line) - 1 - len, " conn=0x%08x", (unsigned)rec->conn);
		if (n > 0)
			len += (size_t)n < sizeof(line) - 1 - len ? (size_t)n : sizeof(line) - 2 - len;
	}
	if (len < sizeof(line) - 1) {
		n = snprintf(line + len, sizeof(line) - 1 - len,
			     " %s a0=0x%llx a1=0x%llx a2=0x%llx a3=0x%llx", msg, (unsigned long long)rec->a0,
			     (unsigned long long)rec->a1, (unsigned long long)rec->a2,
			     (unsigned long long)rec->a3);
		if (n > 0)
			len += (size_t)n < sizeof(line) - 1 - len ? (size_t)n : sizeof(line) - 2 - len;
	}
	line[len++] = '\n'; /* always room: every length above is capped at sizeof(line) - 1 */

	/* One write(2) per record so lines from several threads or processes do not interleave. A short
	 * write or an error is dropped: logging must never stall or fail the caller. */
	{
		size_t off = 0;

		while (off < len) {
			ssize_t w = write(STDERR_FILENO, line + off, len - off);

			if (w < 0 && errno == EINTR)
				continue;
			if (w <= 0)
				break;
			off += (size_t)w;
		}
	}
}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

void wrl_host_ops_init(wr_host_ops *ops, unsigned *max_level)
{
	if (ops == NULL)
		return;
	memset(ops, 0, sizeof(*ops));
	ops->size = (uint32_t)sizeof(*ops);
	ops->ctx = max_level;
	ops->random = wrl_random;
	ops->log = wrl_log_stderr;
	ops->prim = NULL;
}

/* ---- memory regions -------------------------------------------------------------------------- */

wr_status wrl_mem_alloc(wr_mem_region *out, size_t size)
{
	void *p = NULL;
	size_t rounded;

	if (out == NULL)
		return WR_E_INVAL;
	out->base = NULL;
	out->size = 0;
	if (size == 0)
		return WR_OK;
	if (size > SIZE_MAX - (WRL_MEM_ALIGN - 1u))
		return WR_E_TOOBIG;
	/* Round the block up to a whole number of cache lines; the region reports the size asked for. */
	rounded = (size + (WRL_MEM_ALIGN - 1u)) & ~(size_t)(WRL_MEM_ALIGN - 1u);
	if (posix_memalign(&p, WRL_MEM_ALIGN, rounded) != 0 || p == NULL)
		return WR_E_BUDGET;
	memset(p, 0, rounded);
	out->base = p;
	out->size = size;
	return WR_OK;
}

void wrl_mem_free(wr_mem_region *r)
{
	size_t rounded;

	if (r == NULL)
		return;
	if (r->base != NULL) {
		/* The block was rounded up at allocation; wipe all of it (the rounding cannot overflow: it
		 * succeeded when the block was made). */
		rounded = (r->size + (WRL_MEM_ALIGN - 1u)) & ~(size_t)(WRL_MEM_ALIGN - 1u);
		wrl_wipe(r->base, rounded);
		free(r->base);
	}
	r->base = NULL;
	r->size = 0;
}

/* ---- text files ------------------------------------------------------------------------------ */

wr_status wrl_read_text_file(const char *path, char *buf, size_t cap, size_t *len)
{
	struct stat st;
	size_t got = 0;
	wr_status rc = WR_OK;
	char probe;
	int fd;

	if (len != NULL)
		*len = 0;
	if (buf != NULL && cap != 0)
		buf[0] = '\0'; /* every error leaves an empty string, including a bad argument */
	if (path == NULL || buf == NULL || cap == 0 || len == NULL)
		return WR_E_INVAL;

	/* O_NONBLOCK so that opening a FIFO cannot hang; regular files ignore it. O_NOCTTY so that a
	 * terminal device given by mistake cannot become our controlling terminal. */
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
	if (fd < 0)
		return WR_E_INVAL; /* missing, not readable, ...: there is no I/O status in the table */
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		(void)close(fd);
		return WR_E_INVAL;
	}
	/* A file that is plainly too large is refused without reading it (its bytes may be a secret that
	 * would otherwise sit in the caller's buffer). Files that lie about their size (st_size 0 in
	 * /proc, or growth after this check) are still bounded by the read loop and the probe below. */
	if (st.st_size > 0 && (uint64_t)st.st_size > (uint64_t)(cap - 1u)) {
		(void)close(fd);
		return WR_E_RANGE;
	}
	while (got < cap - 1u) {
		ssize_t r = read(fd, buf + got, cap - 1u - got);

		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			rc = WR_E_INVAL;
			break;
		}
		if (r == 0)
			break;
		got += (size_t)r;
	}
	if (rc == WR_OK && got == cap - 1u) {
		/* Buffer full: the file must end exactly here, otherwise it is too large. */
		ssize_t r;

		do {
			r = read(fd, &probe, 1);
		} while (r < 0 && errno == EINTR);
		if (r < 0)
			rc = WR_E_INVAL;
		else if (r > 0)
			rc = WR_E_RANGE;
		wrl_wipe(&probe, sizeof(probe));
	}
	(void)close(fd);
	/* A text file has no NUL: one inside would make *len disagree with strlen(buf). */
	if (rc == WR_OK && memchr(buf, '\0', got) != NULL)
		rc = WR_E_ENCODING;
	if (rc != WR_OK) {
		wrl_wipe(buf, got);
		buf[0] = '\0';
		return rc;
	}
	buf[got] = '\0';
	*len = got;
	return WR_OK;
}
