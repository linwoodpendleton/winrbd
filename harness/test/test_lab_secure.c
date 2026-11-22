/* SPDX-License-Identifier: MIT */
/*
 * test_lab_secure.c - the live secure-mode matrix (harness/lab/secure-live.sh, docs/design/core-architecture.md 39.2) against the REAL lab
 * cluster. Label "lab": skipped (exit 77) unless the environment names a cluster, the tools and the keyrings, so a plain ctest run on any
 * machine stays green. Key material comes from keyring files named in the environment, never from the repository, and is never printed.
 * ctest name: lab.secure; the timeout is set in the `module vectors-sec` block of harness/CMakeLists.txt.
 *
 *   WR_LAB_MON            monitor address, literal ip[:port] (the lab: 10.77.0.10:3300); reachable from the machine running the test, which for
 *                         the lab VM means running it inside the VM (with passwordless sudo: the script uses the stock rbd and ceph commands)
 *   WR_LAB_USER_K2        cephx user id for the aes256k key ("winrbd"); WR_LAB_KEYRING_K2 its keyring file
 *   WR_LAB_USER_K1        cephx user id for the legacy aes key ("winrbd-aes"); WR_LAB_KEYRING_K1 its file
 *   WR_LAB_POOL           pool of the scratch images (default winrbd)
 *   WR_RBD, WR_MONPROBE   the wr-rbd and wr-monprobe executables (default: next to this test's own executable: build the two targets)
 *
 * What it runs, by default, is the part of the matrix that changes nothing on the cluster: the client side secure runs against the default
 * cluster (both key types, every connection secure, the data checked against the stock `rbd export`, AES-NI hook when the CPU has it) and the
 * offer policies (the mode each connection got, next to the stock client with the same options). Two environment switches add what is slow or
 * disruptive, and both are off unless asked for:
 *
 *   WR_LAB_SECURE_FORCED=1   also the two sections that force the cluster to secure and then to crc (ms_mon_service_mode and ms_service_mode: the
 *                            monitor and every OSD are restarted one at a time, three rounds with the restore) and the refusals; about 15 to
 *                            25 minutes. The script puts the options and the daemons back in an EXIT trap; the lab rules allow exactly this
 *   WR_LAB_SECURE_KRBD=1     also wr-krbdcmp with krbd mapped ms_mode=secure (harness/lab/krbd-compare.sh --mode secure; needs `rbd map`)
 *   WR_LAB_SECURE_CAPTURE_DIR=DIR   keep the refusal captures of the forced run in DIR
 *   WR_LAB_SECURE_DEADLINE=SEC      the longest the script may run (default 5400, 0 = no limit): then it gets SIGTERM, which makes it put the lab back
 *                            (options, daemons, images) and finish, and the test fails. ctest's own timeout (harness/CMakeLists.txt, module vectors-sec,
 *                            7200 s) is only the backstop for a hang AFTER that: ctest ends a test with SIGKILL, which no restore can survive, so the
 *                            limit that matters is this one, and it leaves ctest 30 minutes for the restore. The same goes for a SIGINT / SIGTERM / SIGHUP
 *                            that reaches this test (Ctrl-C of ctest, a service stop): it is passed on to the script and the test waits for the restore
 *
 * The test passes when the script exits 0: every check passed, the lab matches the snapshot taken before the run (health, OSD tree, upmaps,
 * config database, the four mode options one by one, pools, daemons). The script's output is printed on failure and summarised on success.
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "wrt.h"

/* the script's pid, for the handler that passes a signal on (0 while there is none); only a pid is shared with the handler */
static volatile sig_atomic_t g_script_pid;
static volatile sig_atomic_t g_deadline_hit, g_signalled;

static void on_signal(int sig)
{
	pid_t pid = (pid_t)g_script_pid;

	if (sig == SIGALRM)
		g_deadline_hit = 1;
	else
		g_signalled = 1;
	/* SIGTERM, not the signal received: the script's own trap (restore, then exit) is what it understands */
	if (pid > 0)
		(void)kill(pid, SIGTERM);
}

static int file_exists(const char *p)
{
	struct stat st;

	return stat(p, &st) == 0;
}

static int is_exec(const char *p)
{
	return access(p, X_OK) == 0;
}

/* The directory of this executable (the tools are built next to it); "" when it cannot be told. */
static void exe_dir(char *out, size_t cap)
{
	ssize_t n;
	char *slash;

	out[0] = '\0';
	n = readlink("/proc/self/exe", out, cap - 1u);
	if (n <= 0) {
		out[0] = '\0'; /* (a failed readlink leaves the buffer alone) */
		return;
	}
	out[n] = '\0';
	slash = strrchr(out, '/');
	if (slash != NULL)
		*slash = '\0';
}

static const char *env_or(const char *name, const char *dflt)
{
	const char *v = getenv(name);

	return (v != NULL && *v != '\0') ? v : dflt;
}

/* Run argv with stdout and stderr in `outfile`; returns the exit status, -1 when it did not exit, -2 when it could not be run at all. A signal
 * that reaches this process, or `deadline` seconds (0: none), is passed on to the child as SIGTERM and the wait goes on: the script restores the
 * lab on SIGTERM, and a test that left before it was done would leave the cluster forced (the options and the daemons restarted under them). */
static int run_to_file(char *const argv[], const char *outfile, unsigned deadline)
{
	pid_t pid;
	int status = 0, norun[2];
	sigset_t all, old;
	struct sigaction sa;
	unsigned char code = 0;

	if (pipe(norun) != 0)
		return -2;
	(void)fcntl(norun[1], F_SETFD, FD_CLOEXEC);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	(void)sigaction(SIGINT, &sa, NULL);
	(void)sigaction(SIGTERM, &sa, NULL);
	(void)sigaction(SIGHUP, &sa, NULL);
	(void)sigaction(SIGALRM, &sa, NULL);
	sigfillset(&all);
	(void)sigprocmask(SIG_BLOCK, &all, &old);
	pid = fork();
	if (pid < 0) {
		(void)sigprocmask(SIG_SETMASK, &old, NULL);
		close(norun[0]);
		close(norun[1]);
		return -2;
	}
	if (pid == 0) {
		int fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		int dn = open("/dev/null", O_RDONLY);

		(void)sigprocmask(SIG_SETMASK, &old, NULL);
		if (fd < 0)
			_exit(126);
		(void)dup2(dn, 0);
		(void)dup2(fd, 1);
		(void)dup2(fd, 2);
		close(fd);
		close(norun[0]);
		execvp(argv[0], argv);
		code = 1;
		(void)!write(norun[1], &code, 1);
		_exit(127);
	}
	g_script_pid = (sig_atomic_t)pid;
	if (deadline != 0u)
		(void)alarm(deadline);
	(void)sigprocmask(SIG_SETMASK, &old, NULL);
	close(norun[1]);
	for (;;) {
		pid_t w = waitpid(pid, &status, 0);

		if (w == pid)
			break;
		if (w < 0 && errno != EINTR)
			break;
	}
	(void)alarm(0);
	g_script_pid = 0;
	/* exec failed (the child wrote a byte before it left): it is "could not be run", not a status of the script */
	if (read(norun[0], &code, 1) == 1)
		status = -2;
	close(norun[0]);
	if (status == -2)
		return -2;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int starts(const char *p, size_t len, const char *pre)
{
	size_t n = strlen(pre);

	return len >= n && memcmp(p, pre, n) == 0;
}

/* Print the last 80 lines of `buf` (tail != 0), or only its summary lines: the NOTE lines (captures, the policy table), the failures and the
 * script's own status lines. */
static void show(const char *buf, size_t n, int tail)
{
	const char *p = buf, *end = buf + n;
	size_t lines = 0, at = 0;

	for (const char *q = buf; q < end; q++)
		if (*q == '\n')
			lines++;
	while (p < end) {
		const char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t len = nl != NULL ? (size_t)(nl - p) : (size_t)(end - p);
		int keep = tail ? lines - at <= 80u : (starts(p, len, "NOTE ") || starts(p, len, "FAIL ") || starts(p, len, "secure-live: "));

		if (keep)
			fprintf(stderr, "%.*s\n", (int)(len > 400u ? 400u : len), p);
		p += len + (nl != NULL ? 1u : 0u);
		at++;
	}
}

int main(int argc, char **argv)
{
	const char *mon = getenv("WR_LAB_MON"), *u2 = getenv("WR_LAB_USER_K2"), *k2 = getenv("WR_LAB_KEYRING_K2");
	const char *u1 = getenv("WR_LAB_USER_K1"), *k1 = getenv("WR_LAB_KEYRING_K1");
	int have2 = u2 != NULL && k2 != NULL && *u2 != '\0' && *k2 != '\0';
	int have1 = u1 != NULL && k1 != NULL && *u1 != '\0' && *k1 != '\0';
	char dir[PATH_MAX], script[PATH_MAX + 64], wr[PATH_MAX + 32], mp[PATH_MAX + 32], outfile[] = "/tmp/wr-lab-secure-XXXXXX";
	char *args[16];
	unsigned n = 0;
	const char *rbd_exe, *mp_exe, *capdir;
	unsigned deadline;
	uint8_t *buf = NULL;
	size_t len = 0;
	int rc, fd;

	(void)argc;
	(void)argv;
	if (mon == NULL || *mon == '\0' || (!have1 && !have2))
		WRT_SKIP("WR_LAB_MON and WR_LAB_USER_K2 / WR_LAB_KEYRING_K2 (or the K1 pair) are not set");
	exe_dir(dir, sizeof(dir));
	snprintf(script, sizeof(script), "%s/../lab/secure-live.sh", WRT_VECTOR_DIR);
	snprintf(wr, sizeof(wr), "%s/wr-rbd", dir);
	snprintf(mp, sizeof(mp), "%s/wr-monprobe", dir);
	rbd_exe = env_or("WR_RBD", wr);
	mp_exe = env_or("WR_MONPROBE", mp);
	if (!file_exists(script))
		WRT_SKIP("harness/lab/secure-live.sh is not next to the vectors (an installed copy of the harness only)");
	if (!is_exec(rbd_exe) || !is_exec(mp_exe))
		WRT_SKIP("wr-rbd and wr-monprobe are not built next to this test (build the targets, or set WR_RBD and WR_MONPROBE)");
	if (!is_exec("/usr/bin/bash") && !is_exec("/bin/bash"))
		WRT_SKIP("bash is not available");
	if (!is_exec("/usr/bin/sudo") && !is_exec("/bin/sudo"))
		WRT_SKIP("sudo is not available: the script drives the stock ceph and rbd commands with it");

	/* the script reads its configuration from the environment: pass the names this test was given on */
	setenv("WR_RBD", rbd_exe, 1);
	setenv("WR_MONPROBE", mp_exe, 1);

	args[n++] = (char *)"bash";
	args[n++] = script;
	args[n++] = (char *)"--keys";
	args[n++] = (char *)(have2 && have1 ? "both" : have2 ? "k2" : "k1");
	args[n++] = (char *)"--quick";
	if (!(env_or("WR_LAB_SECURE_FORCED", "")[0] == '1'))
		args[n++] = (char *)"--skip-forced";
	if (!(env_or("WR_LAB_SECURE_KRBD", "")[0] == '1'))
		args[n++] = (char *)"--skip-krbd";
	capdir = getenv("WR_LAB_SECURE_CAPTURE_DIR");
	if (capdir != NULL && *capdir != '\0') {
		args[n++] = (char *)"--capture-dir";
		args[n++] = (char *)capdir;
	}
	args[n] = NULL;

	fd = mkstemp(outfile);
	if (fd < 0)
		abort();
	close(fd);
	{
		/* a value that is not a plain number of seconds must not turn into 0 (no limit): the limit is what lets the script restore the lab */
		const char *dl = env_or("WR_LAB_SECURE_DEADLINE", "5400");
		char *end = NULL;
		unsigned long v;

		errno = 0;
		v = strtoul(dl, &end, 10);
		if (errno != 0 || end == dl || *end != '\0' || *dl == '-' || v > 86400ul * 7u) {
			fprintf(stderr, "lab secure: WR_LAB_SECURE_DEADLINE=%s is not a number of seconds (0 to 604800)\n", dl);
			(void)unlink(outfile);
			WRT_CHECK(0);
			return wrt_finish();
		}
		deadline = (unsigned)v;
	}
	rc = run_to_file(args, outfile, deadline);
	if (rc == -2) {
		(void)unlink(outfile);
		WRT_SKIP("bash could not be started");
	}
	if (wrt_read_file(outfile, &buf, &len) != 0) {
		buf = NULL;
		len = 0;
	}
	if (rc != 0) {
		fprintf(stderr, "lab secure: secure-live.sh exited %d; its output:\n", rc);
		if (buf != NULL)
			show((const char *)buf, len, 1);
	} else if (buf != NULL) {
		show((const char *)buf, len, 0);
	}
	if (g_deadline_hit)
		fprintf(stderr, "lab secure: the script ran longer than WR_LAB_SECURE_DEADLINE (%u s) and was told to stop and restore the lab\n", deadline);
	if (g_signalled)
		fprintf(stderr, "lab secure: a signal reached the test; the script was told to stop and restore the lab\n");
	WRT_CHECK(!g_deadline_hit);
	WRT_CHECK(!g_signalled);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(buf != NULL && strstr((const char *)buf, "secure-live: finished with exit status 0") != NULL);
	if (buf != NULL && rc == 0) {
		WRT_CHECK(strstr((const char *)buf, "state: the lab matches the snapshot") != NULL);
		WRT_CHECK(strstr((const char *)buf, "\nFAIL ") == NULL);
		WRT_CHECK(strstr((const char *)buf, "PASS  k2 secure: every connection secure") != NULL || !have2);
		WRT_CHECK(strstr((const char *)buf, "PASS  k1 secure: every connection secure") != NULL || !have1);
		/* what each key type must have proved on the wire and with a wrong key (a section that silently did not run is not a pass) */
		WRT_CHECK(strstr((const char *)buf, "PASS  k2 wire: not one run of the pattern in the secure capture") != NULL ||
			  strstr((const char *)buf, "k2 wire: tcpdump is not installed") != NULL || !have2);
		WRT_CHECK(strstr((const char *)buf, "PASS  k1 wire: not one run of the pattern in the secure capture") != NULL ||
			  strstr((const char *)buf, "k1 wire: tcpdump is not installed") != NULL || !have1);
		WRT_CHECK(strstr((const char *)buf, "PASS  k2 wire: the crc capture shows the pattern") != NULL ||
			  strstr((const char *)buf, "k2 wire: tcpdump is not installed") != NULL || !have2);
		WRT_CHECK(strstr((const char *)buf, "PASS  k1 wire: the crc capture shows the pattern") != NULL ||
			  strstr((const char *)buf, "k1 wire: tcpdump is not installed") != NULL || !have1);
		WRT_CHECK(strstr((const char *)buf, "PASS  k2 wrong key, secure: wr-monprobe fails") != NULL || !have2);
		WRT_CHECK(strstr((const char *)buf, "PASS  k1 wrong key, secure: wr-monprobe fails") != NULL || !have1);
		WRT_CHECK(strstr((const char *)buf, "PASS  k2 policy stock:") != NULL || !have2);
		WRT_CHECK(strstr((const char *)buf, "PASS  k1 policy stock:") != NULL || !have1);
		if (env_or("WR_LAB_SECURE_FORCED", "")[0] == '1') {
			/* both forced sections, every refusal, and the lab working again under the original options */
			WRT_CHECK(strstr((const char *)buf, "PASS  forced-secure-monitor-crc-only: refused with WR_E_M2_BAD_METHOD") != NULL);
			WRT_CHECK(strstr((const char *)buf, "PASS  forced-crc-osd-secure-only: refused with WR_E_M2_BAD_METHOD") != NULL);
			WRT_CHECK(strstr((const char *)buf, "PASS  forced-secure-osd-crc-only: the monitor connection reached READY in secure") != NULL);
			WRT_CHECK(strstr((const char *)buf, "PASS  forced-crc-osd-secure-only: the monitor connection reached READY in crc") != NULL);
			WRT_CHECK(strstr((const char *)buf, "PASS  restored: a crc-only client works again") != NULL);
			WRT_CHECK(strstr((const char *)buf, "PASS  restored: a secure-only client works again") != NULL);
		}
		if (env_or("WR_LAB_SECURE_KRBD", "")[0] == '1')
			WRT_CHECK(strstr((const char *)buf, "PASS  krbd mapped with ms_mode=secure and the core with --mode secure") != NULL);
	}
	free(buf);
	(void)unlink(outfile);
	return wrt_finish();
}
