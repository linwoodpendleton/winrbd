/* SPDX-License-Identifier: MIT */
/*
 * test_lab_rbd.c - the wr-rbd tool against a REAL Ceph cluster (the lab), once per cephx key type. Label "lab": skipped (exit 77)
 * unless the environment names a cluster, a scratch image and the tool, so a plain ctest run on any machine stays green. Key
 * material comes from keyring files named in the environment, never from the repository, and is never printed. ctest name: lab.rbd.
 *
 *   WR_RBD                the wr-rbd executable (ctest sets it)
 *   WR_LAB_MON            monitor address, literal ip[:port] (the lab: 10.77.0.10:3300), reachable from the machine running the test
 *   WR_LAB_USER_K2        cephx user id for the aes256k key ("winrbd"); WR_LAB_KEYRING_K2 its keyring file
 *   WR_LAB_USER_K1        cephx user id for the legacy aes key ("winrbd-aes"); WR_LAB_KEYRING_K1 its file
 *   WR_LAB_POOL           pool of the scratch image (default winrbd)
 *   WR_LAB_RBD_IMAGE      a scratch image of the writer profile (features 0x1 or 0x21) of at least 8 MiB. Its first 8 MiB are
 *                         OVERWRITTEN: use an image made for the test (harness/lab/rbd-prepare.sh makes wrtest-lrt-*)
 *
 * For every configured key the test requires: info (the image opens, a writer when asked), a fill with a pattern and its verify
 * (and a wrong pattern as a difference), a write of a file at an unaligned offset read back by `read` to a file, discard and
 * zeroes, 300 random operations against the model with zero differences and the whole region read back, the same with overlapping
 * requests in flight, and the refusals (a write without --rw, a missing image). The stock tools are
 * the oracle in live-rbd.sh, not here.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "wrt.h"

static uint64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static const char *g_tool, *g_mon, *g_pool, *g_image;
static char g_dir[128];
static char OUT[1 << 16];

/* Run the tool on `image` with the common arguments plus the words of `extra`; out = stdout + stderr. Exit status, -1 if it did not exit. */
static int run_img(const char *image, const char *user, const char *keyring, const char *extra, unsigned secs)
{
	char *args[40], copy[768], *tok;
	unsigned n = 0;
	int pfd[2], status = 0;
	size_t len = 0;
	pid_t pid;
	uint64_t t_end = now_ms() + secs * 1000u;

	args[n++] = (char *)"wr-rbd";
	args[n++] = (char *)"--mon";
	args[n++] = (char *)g_mon;
	args[n++] = (char *)"--user";
	args[n++] = (char *)user;
	args[n++] = (char *)"--keyring";
	args[n++] = (char *)keyring;
	args[n++] = (char *)"--pool";
	args[n++] = (char *)g_pool;
	args[n++] = (char *)"--image";
	args[n++] = (char *)image;
	snprintf(copy, sizeof(copy), "%s", extra);
	for (tok = strtok(copy, " "); tok != NULL && n + 1u < 40u; tok = strtok(NULL, " "))
		args[n++] = tok;
	args[n] = NULL;
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
		execv(g_tool, args);
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
		if (len + 1u >= sizeof(OUT))
			r = read(pfd[0], junk, sizeof(junk));
		else {
			r = read(pfd[0], OUT + len, sizeof(OUT) - 1u - len);
			if (r > 0)
				len += (size_t)r;
		}
		if (r < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (r <= 0)
			break;
	}
	OUT[len] = '\0';
	close(pfd[0]);
	(void)waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run(const char *user, const char *keyring, const char *extra, unsigned secs)
{
	return run_img(g_image, user, keyring, extra, secs);
}

static int has(const char *s)
{
	return strstr(OUT, s) != NULL;
}

static void show(const char *what, int rc)
{
	fprintf(stderr, "lab rbd: %s: exit %d\n%.2500s\n", what, rc, OUT);
}

static void one_key(const char *label, const char *user, const char *keyring)
{
	char fpath[256], cmd[512];
	int rc;
	uint64_t t0 = now_ms();

	snprintf(fpath, sizeof(fpath), "%s/%s.out", g_dir, label);

	rc = run(user, keyring, "--rw info", 60);
	if (rc != 0)
		show("info", rc);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(" result info ok=1 state=OPEN"));
	WRT_CHECK(has("writable=1"));
	WRT_CHECK(has("event MON_SESSION_UP"));

	rc = run(user, keyring, "--rw fill 0 8M --pattern rand:41", 120);
	if (rc != 0)
		show("fill", rc);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(" result fill ok=1 "));
	rc = run(user, keyring, "verify 0 8M --pattern rand:41", 120);
	WRT_CHECK_U64(rc, 0);
	rc = run(user, keyring, "verify 0 8M --pattern rand:42", 120);
	WRT_CHECK_U64(rc, 1);
	WRT_CHECK(has("first_diff="));

	/* a file at an unaligned offset across an object boundary (the default object size is 4 MiB: 4194304 - 5000) */
	{
		uint8_t *buf = (uint8_t *)malloc(20000);
		FILE *f;
		size_t i;
		uint8_t *got = NULL;
		size_t gn = 0;
		char in[256];

		WRT_CHECK(buf != NULL);
		for (i = 0; buf != NULL && i < 20000u; i++)
			buf[i] = (uint8_t)(i * 131u + 17u);
		snprintf(in, sizeof(in), "%s/%s.in", g_dir, label);
		f = fopen(in, "wb");
		WRT_CHECK(f != NULL);
		if (f != NULL && buf != NULL) {
			WRT_CHECK(fwrite(buf, 1, 20000, f) == 20000u);
			fclose(f);
		}
		snprintf(cmd, sizeof(cmd), "--rw write 4189304 - --file %s", in);
		rc = run(user, keyring, cmd, 120);
		WRT_CHECK_U64(rc, 0);
		snprintf(cmd, sizeof(cmd), "read 4189304 20000 %s", fpath);
		rc = run(user, keyring, cmd, 120);
		WRT_CHECK_U64(rc, 0);
		if (wrt_read_file(fpath, &got, &gn) == 0) {
			WRT_CHECK(gn == 20000u && buf != NULL && memcmp(got, buf, 20000) == 0);
			free(got);
		} else {
			WRT_CHECK(0);
		}
		(void)unlink(in);
		free(buf);
	}

	rc = run(user, keyring, "--rw discard 4194304 1048576", 120);
	WRT_CHECK_U64(rc, 0);
	rc = run(user, keyring, "--rw zeroes 100000 50000", 120);
	WRT_CHECK_U64(rc, 0);
	rc = run(user, keyring, "verify 4194304 1048576 --pattern zero", 120);
	WRT_CHECK_U64(rc, 0);
	rc = run(user, keyring, "verify 100000 50000 --pattern zero", 120);
	WRT_CHECK_U64(rc, 0);

	rc = run(user, keyring, "--rw --depth 6 random 300 7", 300);
	if (rc != 0)
		show("random", rc);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(" result random ok=1 "));
	WRT_CHECK(has("read_mismatches=0 final_diff_bytes=0 errors=0"));
	/* overlapping requests in flight: the core runs them in submission order, every read must see exactly the writes submitted before it */
	rc = run(user, keyring, "--rw --depth 12 --overlap --model-bytes 8M --max-len 1M random 300 8", 300);
	if (rc != 0)
		show("random overlap", rc);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(has(" result random ok=1 "));
	WRT_CHECK(has("read_mismatches=0 final_diff_bytes=0 errors=0"));
	WRT_CHECK(has("barrier_violations=0 bad_completions=0"));

	/* the refusals of the tool and of the cluster, which are not zeros and not a success */
	rc = run(user, keyring, "write 0 4096 --pattern rand:1", 60); /* no --rw */
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has("need --rw"));
	rc = run_img("wrtest-no-such-image-lab-rbd", user, keyring, "--timeout 15000 info", 60);
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has("WR_E_RBD_NOT_FOUND"));
	WRT_CHECK(!has(" result info ok=1"));

	(void)unlink(fpath);
	fprintf(stderr, "lab rbd %s: user %s, %llu ms\n", label, user, (unsigned long long)(now_ms() - t0));
}

int main(void)
{
	const char *u2 = getenv("WR_LAB_USER_K2"), *k2 = getenv("WR_LAB_KEYRING_K2");
	const char *u1 = getenv("WR_LAB_USER_K1"), *k1 = getenv("WR_LAB_KEYRING_K1");
	char dir[] = "/tmp/wr-lab-rbd-XXXXXX";
	int have2 = u2 != NULL && k2 != NULL && *u2 != '\0' && *k2 != '\0';
	int have1 = u1 != NULL && k1 != NULL && *u1 != '\0' && *k1 != '\0';

	g_tool = getenv("WR_RBD");
	g_mon = getenv("WR_LAB_MON");
	g_pool = getenv("WR_LAB_POOL");
	g_image = getenv("WR_LAB_RBD_IMAGE");
	if (g_pool == NULL || *g_pool == '\0')
		g_pool = "winrbd";
	if (g_tool == NULL || *g_tool == '\0' || g_mon == NULL || *g_mon == '\0' || g_image == NULL || *g_image == '\0' || (!have1 && !have2))
		WRT_SKIP("WR_RBD, WR_LAB_MON, WR_LAB_RBD_IMAGE and WR_LAB_USER_K2 / WR_LAB_KEYRING_K2 (or the K1 pair) are not set");
	if (mkdtemp(dir) == NULL)
		abort();
	snprintf(g_dir, sizeof(g_dir), "%s", dir);
	if (have2)
		one_key("k2", u2, k2);
	if (have1)
		one_key("k1", u1, k1);
	(void)rmdir(g_dir);
	return wrt_finish();
}
