/* SPDX-License-Identifier: MIT */
/*
 * test_lab_exit.c - the Phase 1 exit run (harness/lab/exit-run.sh, docs/design/core-architecture.md 40) against the REAL lab cluster: the core and the
 * kernel client (krbd) compared byte for byte on the same images for hours while a fault injector kills and restarts OSDs and the monitor, marks an OSD
 * out and in and moves a primary. Label "lab": skipped (exit 77) unless the environment names a cluster, the tools and the keyrings, so a plain ctest
 * run on any machine stays green. Key material comes from keyring files named in the environment, never from the repository, and is never printed.
 * ctest name: lab.exit; the timeout is set in the `module exit-run` block of harness/CMakeLists.txt.
 *
 *   WR_LAB_MON            monitor address, literal ip[:port] (the lab: 10.77.0.10:3300); the test must run inside the lab VM (passwordless sudo, the stock
 *                         ceph and rbd commands, `rbd map`)
 *   WR_LAB_USER_K2        cephx user id for the aes256k key ("winrbd"); WR_LAB_KEYRING_K2 its keyring file, which must be named client.<user>.keyring
 *   WR_LAB_USER_K1        cephx user id for the legacy aes key ("winrbd-aes", the one krbd authenticates as); WR_LAB_KEYRING_K1 its file (the same naming rule).
 *                         Both pairs are needed: the script's runs use both key types, and krbd always needs the K1 keyring; both files must be in one directory
 *   WR_LAB_POOL           pool of the scratch images (default winrbd)
 *   WR_KRBDCMP, WR_RBD    the wr-krbdcmp and wr-rbd executables (default: next to this test's own executable: build the two targets)
 *
 * By default the test runs the QUICK form of the script (`exit-run.sh --quick --runs 1`: small images, a few minutes, a handful of faults of every kind;
 * it shows that the script, the injector and the restore work on this cluster, not that the exit criteria hold). Environment switches:
 *
 *   WR_LAB_EXIT_RUNS=1,3,5   which runs of the five (default 1)
 *   WR_LAB_EXIT_FULL=1       the real thing: no --quick, at least 2 hours and 500,000 operations per image per run, the full deck of faults (about 3 hours
 *                            per run); the deadline then defaults to none (WR_LAB_EXIT_DEADLINE=0) and ctest's own timeout is the backstop
 *   WR_LAB_EXIT_DEADLINE=SEC the longest the script may run (default 3600 for the quick form, 0 = no limit for the full one): then it gets SIGTERM, which
 *                            makes it stop the injector, unmap, remove the images, put the options back and compare the state, and the test fails. ctest ends
 *                            a test with SIGKILL, which no restore can survive, so this limit must be shorter than ctest's own timeout; the same goes for a
 *                            SIGINT / SIGTERM / SIGHUP that reaches this test: it is passed on to the script and the test waits for the restore
 *   WR_LAB_EXIT_ARGS="..."   more arguments for the script (words separated by blanks, no quoting), e.g. "--hours 0.2 --osd-kills 2"
 *   WR_LAB_EXIT_REPORT=FILE  keep the script's report table in FILE
 *
 * The test passes when the script exits 0 (every run passed: zero differences, no hang, enough operations and faults, the mode asked for, the lab as it
 * was) and its output says so: the finish line, a state match, "differences in all tools: 0" and a PASS status for every run requested. The script's
 * output is printed on failure and its report on success. When the environment names the cluster, the keyrings and the tools but something it names is
 * not usable (a tool not built, a keyring file not named client.<user>.keyring), that is a failure, not a skip: the person asked for a real run.
 *
 * What passes and what fails in the report: a "  WARN:" line (late recoveries of the injector, which healed) and a "  NOTE:" line (Ceph's own osd_mclock_max_capacity_iops_hdd /
 * _ssd lines that appeared in the config database while OSDs restarted) do NOT fail a run; an injector line with failed above 0, a FAIL line (including a state that
 * differs in any other way), a byte difference, a run that is not restored or a missing line of the list above do.
 *
 * ctest name lab.exit.selftest: the same executable with WR_LAB_EXIT_SELFTEST=1, no cluster needed. It checks the test's own machinery against stand-in
 * scripts: the verdict on synthetic outputs (every way a report can fail to show a pass), the child's exit status, a stderr line, a command that cannot
 * be run, a child killed by a signal, and the two ways the test stops the script (the deadline, a signal that reaches the test): each must pass SIGTERM
 * on and wait until the script has finished its restore.
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
	if (n <= 0)
		return;
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

/* The directory part of a path, into out ("." when there is none). */
static void dir_of(const char *path, char *out, size_t cap)
{
	const char *slash = strrchr(path, '/');
	size_t n;

	if (slash == NULL) {
		snprintf(out, cap, ".");
		return;
	}
	n = (size_t)(slash - path);
	if (n == 0u)
		n = 1u;
	if (n >= cap)
		n = cap - 1u;
	memcpy(out, path, n);
	out[n] = '\0';
}

/* Does the file name end in client.<user>.keyring for this user? */
static int keyring_named(const char *path, const char *user)
{
	char want[256];
	const char *base = strrchr(path, '/');
	size_t bl;

	base = base != NULL ? base + 1 : path;
	snprintf(want, sizeof(want), "client.%s.keyring", user);
	bl = strlen(base);
	return strlen(want) == bl && memcmp(base, want, bl) == 0;
}

/* Run argv with stdout and stderr in `outfile`; returns the exit status, -1 when it did not exit, -2 when it could not be run at all. A signal that
 * reaches this process, or `deadline` seconds (0: none), is passed on to the child as SIGTERM and the wait goes on: the script restores the lab on
 * SIGTERM, and a test that left before it was done would leave the cluster hurt (an OSD down, one marked out, the options changed). */
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
	/* the pid first: a signal that arrives now must not be sent to a pid that is gone (and may be another process's by the time kill() runs) */
	g_script_pid = 0;
	(void)alarm(0);
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

/* Print the last 120 lines of `buf` (tail != 0), or the report: everything after the "==== report ====" line, the failures, and the script's own
 * status lines. */
static void show(const char *buf, size_t n, int tail)
{
	const char *p = buf, *end = buf + n;
	size_t lines = 0, at = 0;
	int in_report = 0;

	for (const char *q = buf; q < end; q++)
		if (*q == '\n')
			lines++;
	while (p < end) {
		const char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t len = nl != NULL ? (size_t)(nl - p) : (size_t)(end - p);
		int keep;

		if (starts(p, len, "==== report ===="))
			in_report = 1;
		keep = tail ? lines - at <= 120u : (in_report || starts(p, len, "FAIL ") || starts(p, len, "exit-run: finished"));
		if (keep)
			fprintf(stderr, "%.*s\n", (int)(len > 400u ? 400u : len), p);
		p += len + (nl != NULL ? 1u : 0u);
		at++;
	}
}

/* Count the occurrences of `needle` in the first n bytes of buf. */
static unsigned count_of(const char *buf, size_t n, const char *needle)
{
	size_t ln = strlen(needle);
	unsigned c = 0;

	for (size_t i = 0; ln != 0u && i + ln <= n; i++)
		if (memcmp(buf + i, needle, ln) == 0)
			c++;
	return c;
}

/* The number of runs in a list like "1,3,5": every digit 1 to 5 once (a list that is not one is refused by the script, status 2, and fails the test). */
static unsigned runs_in(const char *list)
{
	unsigned c = 0;

	for (; *list != '\0'; list++)
		if (*list >= '1' && *list <= '5')
			c++;
	return c;
}

/* Does an injector line of the report ("  injector: seed=... failed=<n> ...") have a failed count above zero (a fault whose step did not work)? Late
 * recoveries ("late=") are not looked at: they are a WARN, not a failure. */
static int injector_failed(const char *b, size_t len)
{
	static const char key[] = " failed=";
	const char *p = b, *end = b + len;

	while (p < end) {
		const char *nl = memchr(p, '\n', (size_t)(end - p));
		size_t ll = nl != NULL ? (size_t)(nl - p) : (size_t)(end - p);

		if (starts(p, ll, "  injector: seed=")) {
			size_t found = 0;

			for (size_t i = 0; i + sizeof(key) <= ll; i++) {
				if (memcmp(p + i, key, sizeof(key) - 1u) == 0) {
					size_t j = i + sizeof(key) - 1u;

					if (j >= ll || p[j] != '0' || (j + 1u < ll && p[j + 1u] >= '0' && p[j + 1u] <= '9'))   /* not exactly 0 */
						return 1;
					found++;
				}
			}
			if (found != 1u)   /* no failed= count (or two of them): nothing shows that every fault worked */
				return 1;
		}
		p += ll + (nl != NULL ? 1u : 0u);
	}
	return 0;
}

/* Why the output of the script does not show a pass, or NULL when it does. Every condition of the test, in one place so that the self-test can show that
 * each of them can fail. nofaults: the run was asked to have no injector (the report then has no injector line). */
static const char *verdict(const char *b, size_t len, int rc, int nofaults, unsigned nruns, int deadline_hit, int signalled)
{
	if (deadline_hit)
		return "the script ran longer than WR_LAB_EXIT_DEADLINE and was told to stop and restore the lab";
	if (signalled)
		return "a signal reached the test and the script was told to stop and restore the lab";
	if (rc != 0)
		return "the script did not exit with status 0";
	if (b == NULL)
		return "the script's output could not be read";
	if (nruns == 0u)
		return "no run was asked for";
	if (strstr(b, "exit-run: finished with exit status 0") == NULL)
		return "no 'exit-run: finished with exit status 0' line";
	if (strstr(b, "state: the lab matches the snapshot taken before (after)") == NULL)
		return "no final 'the lab matches the snapshot' line";
	if (strstr(b, "\nFAIL ") != NULL || starts(b, len, "FAIL "))
		return "a FAIL line in the output";
	if (strstr(b, "differences in all tools: 0") == NULL)
		return "no 'differences in all tools: 0' line";
	/* every run asked for has its PASS line and none is missing a restore or a quiet dmesg (a run that silently did not happen is not a pass) */
	if (count_of(b, len, "status PASS") != nruns)
		return "the number of runs with status PASS is not the number asked for";
	if (count_of(b, len, "  lab restored: yes; dmesg: quiet") != nruns)
		return "a run without '  lab restored: yes; dmesg: quiet'";
	if (strstr(b, "status FAIL") != NULL)
		return "a run with status FAIL";
	if (!nofaults && count_of(b, len, "  injector: seed=") != nruns)
		return "a run without an injector line (the faults did not run)";
	/* a fault that failed is a failure; late recoveries (a "  WARN:" line) and Ceph's own mclock lines ("  NOTE:") are not */
	if (injector_failed(b, len))
		return "an injector line with failed above 0 (a fault whose step did not work)";
	return NULL;
}

/* The environment names a cluster, keyrings and tools, so a run was asked for: what stops it is a failure of the test, not a skip (a skip would read as a
 * pass in a summary, and nothing was shown). Only an environment that does not name them at all is a skip. */
#define NOTRUN(why)                                                                                                                                    \
	do {                                                                                                                                           \
		fprintf(stderr, "lab exit: the environment asks for a run but it cannot be made: %s\n", (why));                                          \
		return 1;                                                                                                                              \
	} while (0)

/* ---- the self-test (WR_LAB_EXIT_SELFTEST=1): the test's own machinery, no cluster -------------------------------------------------------------------- */

static const char st_good[] =
	"exit-run: finished with exit status 0 (cleanup: clean; modes: original; state: as-before; dmesg: quiet)\n"
	"state: the lab matches the snapshot taken before (after)\n"
	"==== report ====\n"
	"\n"
	"RUN 1  crc  core key k2  cluster as found  status PASS\n"
	"  injector: seed=11 osdkill=2 monkill=1 monclean=1 mon_restarts=2 outin=1 upmap=1 failed=0 late=0 max_recovery_s=9\n"
	"  lab restored: yes; dmesg: quiet\n"
	"\n"
	"RUN 3  secure  core key k2  cluster as found  status PASS\n"
	"  injector: seed=12 osdkill=2 monkill=1 monclean=1 mon_restarts=2 outin=1 upmap=1 failed=0 late=0 max_recovery_s=9\n"
	"  lab restored: yes; dmesg: quiet\n"
	"\n"
	"differences in all tools: 0\n";

/* st_good with the first `from` replaced by `to` (a malloc'd copy); the self-test fails when `from` is not there, so a case cannot silently test nothing */
static char *st_edit(const char *from, const char *to)
{
	const char *at = strstr(st_good, from);
	size_t head, tail;
	char *out;

	WRT_CHECK(at != NULL);
	if (at == NULL)
		return NULL;
	head = (size_t)(at - st_good);
	tail = strlen(at + strlen(from));
	out = malloc(head + strlen(to) + tail + 1u);
	if (out == NULL)
		abort();
	memcpy(out, st_good, head);
	memcpy(out + head, to, strlen(to));
	memcpy(out + head + strlen(to), at + strlen(from), tail + 1u);
	return out;
}

static void st_verdict(const char *what, const char *from, const char *to, int rc, int nofaults, unsigned nruns, int deadline_hit, int signalled, int want_pass)
{
	char *text = from != NULL ? st_edit(from, to) : NULL;
	const char *b = from != NULL ? text : st_good;
	const char *why;

	if (from != NULL && text == NULL)
		return;
	why = verdict(b, strlen(b), rc, nofaults, nruns, deadline_hit, signalled);
	if ((why == NULL) != (want_pass != 0))
		fprintf(stderr, "lab exit selftest: %s: verdict is '%s', wanted %s\n", what, why != NULL ? why : "a pass", want_pass ? "a pass" : "a refusal");
	WRT_CHECK((why == NULL) == (want_pass != 0));
	free(text);
}

static void st_write(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");

	WRT_CHECK(f != NULL);
	if (f == NULL)
		return;
	fputs(text, f);
	fclose(f);
}

static int st_exists(const char *path)
{
	return file_exists(path);
}

static void st_reset(void)
{
	g_deadline_hit = 0;
	g_signalled = 0;
	g_script_pid = 0;
}

static void selftest(void)
{
	char dir[] = "/tmp/wr-lab-exit-st-XXXXXX";
	char p_ok[PATH_MAX], p_fail[PATH_MAX], p_kill[PATH_MAX], p_dead[PATH_MAX], p_sig[PATH_MAX], p_out[PATH_MAX], p_mark1[PATH_MAX], p_mark2[PATH_MAX], p_bad[PATH_MAX];
	char *args[8];
	char outbuf[256];
	uint8_t *got = NULL;
	size_t n = 0;
	int rc;

	if (!is_exec("/usr/bin/bash") && !is_exec("/bin/bash"))
		WRT_SKIP("bash is not available");
	if (mkdtemp(dir) == NULL)
		WRT_SKIP("no temporary directory");
	snprintf(p_ok, sizeof(p_ok), "%s/ok.sh", dir);
	snprintf(p_fail, sizeof(p_fail), "%s/fail.sh", dir);
	snprintf(p_kill, sizeof(p_kill), "%s/kill.sh", dir);
	snprintf(p_dead, sizeof(p_dead), "%s/deadline.sh", dir);
	snprintf(p_sig, sizeof(p_sig), "%s/signal.sh", dir);
	snprintf(p_out, sizeof(p_out), "%s/out", dir);
	snprintf(p_mark1, sizeof(p_mark1), "%s/restored1", dir);
	snprintf(p_mark2, sizeof(p_mark2), "%s/restored2", dir);
	snprintf(p_bad, sizeof(p_bad), "%s/no/such/dir/out", dir);

	/* the small helpers */
	WRT_CHECK(keyring_named("/k/client.winrbd.keyring", "winrbd"));
	WRT_CHECK(keyring_named("client.winrbd-aes.keyring", "winrbd-aes"));
	WRT_CHECK(!keyring_named("/k/client.winrbd.keyring", "winrbd-aes"));
	WRT_CHECK(!keyring_named("/k/winrbd.keyring", "winrbd"));
	WRT_CHECK(!keyring_named("/k/client.winrbd.keyring.bak", "winrbd"));
	dir_of("/a/b/c", outbuf, sizeof(outbuf));
	WRT_CHECK(strcmp(outbuf, "/a/b") == 0);
	dir_of("c", outbuf, sizeof(outbuf));
	WRT_CHECK(strcmp(outbuf, ".") == 0);
	dir_of("/c", outbuf, sizeof(outbuf));
	WRT_CHECK(strcmp(outbuf, "/") == 0);
	dir_of("/abcdefghij/c", outbuf, 5u);   /* a small buffer: cut, still terminated */
	WRT_CHECK(strlen(outbuf) == 4u);
	WRT_CHECK_U64(runs_in("1,3,5"), 3);
	WRT_CHECK_U64(runs_in(""), 0);
	WRT_CHECK_U64(runs_in("1,6,x,0"), 1);
	WRT_CHECK_U64(count_of("aXaXa", 5u, "a"), 3);
	WRT_CHECK_U64(count_of("aXaXa", 3u, "a"), 2);   /* only the first n bytes are looked at */
	WRT_CHECK_U64(count_of("aaa", 3u, ""), 0);
	WRT_CHECK_U64(count_of("ab", 2u, "abc"), 0);

	/* the verdict: a report that shows a pass, and every way it can fail to */
	st_verdict("a good report", NULL, NULL, 0, 0, 2u, 0, 0, 1);
	st_verdict("a good report of a control run without faults", "  injector: seed=11", "  injector: none (no faults)", 0, 1, 2u, 0, 0, 1);
	st_verdict("a missing injector line", "  injector: seed=12", "  injector: none (no faults)", 0, 0, 2u, 0, 0, 0);
	st_verdict("the script's status", NULL, NULL, 1, 0, 2u, 0, 0, 0);
	st_verdict("the deadline", NULL, NULL, 0, 0, 2u, 1, 0, 0);
	st_verdict("a signal", NULL, NULL, 0, 0, 2u, 0, 1, 0);
	st_verdict("no run asked for", NULL, NULL, 0, 0, 0u, 0, 0, 0);
	st_verdict("one run asked for, two reported", NULL, NULL, 0, 0, 1u, 0, 0, 0);
	st_verdict("three runs asked for, two reported", NULL, NULL, 0, 0, 3u, 0, 0, 0);
	st_verdict("the finish line says 1", "finished with exit status 0", "finished with exit status 1", 0, 0, 2u, 0, 0, 0);
	st_verdict("no state match", "state: the lab matches the snapshot taken before (after)", "state: the lab differs", 0, 0, 2u, 0, 0, 0);
	st_verdict("differences", "differences in all tools: 0", "differences in all tools: 3", 0, 0, 2u, 0, 0, 0);
	st_verdict("a run that is FAIL", "RUN 3  secure  core key k2  cluster as found  status PASS", "RUN 3  secure  core key k2  cluster as found  status FAIL", 0, 0, 2u, 0, 0, 0);
	st_verdict("one more run than asked for, with a PASS", "differences in all tools: 0", "RUN 5  secure  core key k1  cluster as found  status PASS\ndifferences in all tools: 0", 0, 0, 2u, 0, 0, 0);
	st_verdict("one more run than asked for, with a FAIL", "differences in all tools: 0", "RUN 5  secure  core key k1  cluster as found  status FAIL\ndifferences in all tools: 0", 0, 0, 2u, 0, 0, 0);
	/* the two classes that are not failures: late recoveries (WARN, with the count and the lateness) and Ceph's own mclock capacity lines (NOTE) */
	st_verdict("late recoveries with failed=0 are a WARN, not a failure", "failed=0 late=0 max_recovery_s=9\n",
		   "failed=0 late=14 max_recovery_s=1789 late_max_over_s=1189 recovery_limit_s=600\n  WARN: 14 late recoveries (each took longer than the 600 s limit but the cluster healed), the slowest 1189 s past the limit\n",
		   0, 0, 2u, 0, 0, 1);
	st_verdict("an mclock capacity line is a NOTE, the state still matches", "  lab restored: yes; dmesg: quiet\n",
		   "  lab restored: yes; dmesg: quiet\n  NOTE: Ceph wrote osd.2//osd_mclock_max_capacity_iops_hdd: added, value 208.634136\n", 0, 0, 2u, 0, 0, 1);
	st_verdict("a WARN and a NOTE together", "  lab restored: yes; dmesg: quiet\n",
		   "  WARN: 3 late recoveries\n  lab restored: yes; dmesg: quiet\n  NOTE: Ceph wrote osd.0//osd_mclock_max_capacity_iops_ssd: added, value 5000\n", 0, 0, 2u, 0, 0, 1);
	st_verdict("failed above 0 fails", "failed=0 late=0 max_recovery_s=9\n", "failed=2 late=0 max_recovery_s=9\n", 0, 0, 2u, 0, 0, 0);
	st_verdict("an injector line without a failed= count fails", "failed=0 late=0 max_recovery_s=9\n", "late=0 max_recovery_s=9\n", 0, 0, 2u, 0, 0, 0);
	st_verdict("failed above 0 fails (two digits)", "failed=0 late=0 max_recovery_s=9\n", "failed=10 late=0 max_recovery_s=9\n", 0, 0, 2u, 0, 0, 0);
	st_verdict("failed above 0 fails even with late recoveries", "failed=0 late=0 max_recovery_s=9\n", "failed=1 late=14 max_recovery_s=1789\n  WARN: 14 late recoveries\n", 0, 0, 2u, 0, 0, 0);
	st_verdict("a state that differs by an mclock line and another line fails", "state: the lab matches the snapshot taken before (after)\n",
		   "FAIL  the cluster state differs from the snapshot taken before (after):\n      | +config osd.2//osd_mclock_max_capacity_iops_hdd=208.6\n      | +config osd//osd_memory_target=5\n", 0, 0, 2u, 0, 0, 0);
	st_verdict("a run that is not restored because of a state difference fails", "  lab restored: yes; dmesg: quiet\n\nRUN 3", "  lab restored: NO (the state differs from the snapshot)\n\nRUN 3", 0, 0, 2u, 0, 0, 0);
	st_verdict("a lab that was not restored", "  lab restored: yes; dmesg: quiet", "  lab restored: NO (the state differs)", 0, 0, 2u, 0, 0, 0);
	st_verdict("a dmesg with errors", "  lab restored: yes; dmesg: quiet", "  lab restored: yes; dmesg: NEW ERRORS", 0, 0, 2u, 0, 0, 0);
	st_verdict("a FAIL line", "==== report ====", "FAIL  something went wrong\n==== report ====", 0, 0, 2u, 0, 0, 0);
	st_verdict("a FAIL line right after the first line", "state: the lab matches", "FAIL  x\nstate: the lab matches", 0, 0, 2u, 0, 0, 0);
	{
		const char *b = "FAIL  at the very start\n";   /* a FAIL line that is the first one of the output */
		char *both = malloc(strlen(b) + sizeof(st_good));

		if (both == NULL)
			abort();
		strcpy(both, b);
		strcat(both, st_good);
		WRT_CHECK(verdict(both, strlen(both), 0, 0, 2u, 0, 0) != NULL);
		free(both);
	}
	WRT_CHECK(verdict(NULL, 0u, 0, 0, 2u, 0, 0) != NULL);
	WRT_CHECK(verdict("", 0u, 0, 0, 2u, 0, 0) != NULL);
	show(st_good, sizeof(st_good) - 1u, 0);   /* the two printers on a small output (the sanitizers look at them) */
	show(st_good, sizeof(st_good) - 1u, 1);
	show("", 0u, 0);

	/* the child: its status, what it printed on stdout and on stderr, a command that cannot be run, a child killed by a signal, a file that cannot be made */
	st_write(p_ok, "echo out-line; echo err-line >&2; exit 0\n");
	st_write(p_fail, "echo failing; exit 3\n");
	st_write(p_kill, "kill -KILL $$\n");
	args[0] = (char *)"bash"; args[1] = p_ok; args[2] = NULL;
	st_reset();
	rc = run_to_file(args, p_out, 0u);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(wrt_read_file(p_out, &got, &n) == 0 && strstr((const char *)got, "out-line\n") != NULL && strstr((const char *)got, "err-line\n") != NULL);
	free(got);
	got = NULL;
	args[1] = p_fail;
	rc = run_to_file(args, p_out, 0u);
	WRT_CHECK_U64(rc, 3);
	args[1] = p_kill;
	rc = run_to_file(args, p_out, 0u);
	WRT_CHECK(rc == -1);   /* killed by a signal: no exit status */
	args[0] = (char *)"/nonexistent/wr-lab-exit-selftest"; args[1] = NULL;
	rc = run_to_file(args, p_out, 0u);
	WRT_CHECK(rc == -2);   /* "could not be run" is not a status of the script */
	args[0] = (char *)"bash"; args[1] = p_ok; args[2] = NULL;
	rc = run_to_file(args, p_bad, 0u);
	WRT_CHECK_U64(rc, 126);
	WRT_CHECK(!g_deadline_hit && !g_signalled && g_script_pid == 0);

	/* the deadline: the script is told to stop (SIGTERM, not a kill), the test waits until it has restored, and records the deadline */
	st_write(p_dead, "trap 'echo restored > \"$1\"; exit 0' TERM\nfor i in $(seq 1 600); do sleep 0.1; done\nexit 9\n");
	args[0] = (char *)"bash"; args[1] = p_dead; args[2] = p_mark1; args[3] = NULL;
	st_reset();
	rc = run_to_file(args, p_out, 1u);
	WRT_CHECK_U64(rc, 0);                  /* its own exit status after the restore, not 9 (it ran on) and not a signal */
	WRT_CHECK(g_deadline_hit == 1 && g_signalled == 0);
	WRT_CHECK(st_exists(p_mark1));         /* the restore ran to its end before the test went on */
	WRT_CHECK(verdict(st_good, sizeof(st_good) - 1u, rc, 0, 2u, g_deadline_hit, g_signalled) != NULL);

	/* a signal that reaches the test (Ctrl-C in the terminal): passed on as SIGTERM, waited for, recorded; the script here sends it to the test itself */
	st_write(p_sig, "trap 'echo restored > \"$1\"; exit 0' TERM\nkill -INT $PPID\nfor i in $(seq 1 600); do sleep 0.1; done\nexit 9\n");
	args[1] = p_sig; args[2] = p_mark2;
	st_reset();
	rc = run_to_file(args, p_out, 0u);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(g_signalled == 1 && g_deadline_hit == 0);
	WRT_CHECK(st_exists(p_mark2));
	WRT_CHECK(verdict(st_good, sizeof(st_good) - 1u, rc, 0, 2u, g_deadline_hit, g_signalled) != NULL);
	st_reset();

	/* clean up what this made */
	(void)unlink(p_ok); (void)unlink(p_fail); (void)unlink(p_kill); (void)unlink(p_dead); (void)unlink(p_sig); (void)unlink(p_out); (void)unlink(p_mark1);
	(void)unlink(p_mark2);
	(void)rmdir(dir);
}

int main(int argc, char **argv)
{
	const char *mon = getenv("WR_LAB_MON"), *u2 = getenv("WR_LAB_USER_K2"), *k2 = getenv("WR_LAB_KEYRING_K2");
	const char *u1 = getenv("WR_LAB_USER_K1"), *k1 = getenv("WR_LAB_KEYRING_K1");
	int have2 = u2 != NULL && k2 != NULL && *u2 != '\0' && *k2 != '\0';
	int have1 = u1 != NULL && k1 != NULL && *u1 != '\0' && *k1 != '\0';
	char dir[PATH_MAX], script[PATH_MAX + 64], wk[PATH_MAX + 32], rb[PATH_MAX + 32], keydir[PATH_MAX], keydir1[PATH_MAX], outfile[] = "/tmp/wr-lab-exit-XXXXXX";
	char *args[48], *extra = NULL;
	unsigned n = 0, deadline, nruns, i;
	const char *krbdcmp_exe, *rbd_exe, *runs, *report;
	int full, rc, fd, nofaults = 0;
	uint8_t *buf = NULL;
	size_t len = 0;

	(void)argc;
	(void)argv;
	if (env_or("WR_LAB_EXIT_SELFTEST", "")[0] == '1') {
		selftest();
		return wrt_finish();
	}
	if (mon == NULL || *mon == '\0' || !have1 || !have2)
		WRT_SKIP("WR_LAB_MON and both WR_LAB_USER_K2 / WR_LAB_KEYRING_K2 and WR_LAB_USER_K1 / WR_LAB_KEYRING_K1 are needed (the runs use both key types)");
	exe_dir(dir, sizeof(dir));
	snprintf(script, sizeof(script), "%s/../lab/exit-run.sh", WRT_VECTOR_DIR);
	snprintf(wk, sizeof(wk), "%s/wr-krbdcmp", dir);
	snprintf(rb, sizeof(rb), "%s/wr-rbd", dir);
	krbdcmp_exe = env_or("WR_KRBDCMP", wk);
	rbd_exe = env_or("WR_RBD", rb);
	if (!file_exists(script))
		NOTRUN("harness/lab/exit-run.sh is not next to the vectors (an installed copy of the harness only)");
	if (!is_exec(krbdcmp_exe) || !is_exec(rbd_exe))
		NOTRUN("wr-krbdcmp and wr-rbd are not built next to this test (build the targets, or set WR_KRBDCMP and WR_RBD)");
	if (!is_exec("/usr/bin/bash") && !is_exec("/bin/bash"))
		NOTRUN("bash is not available");
	if (!is_exec("/usr/bin/sudo") && !is_exec("/bin/sudo"))
		NOTRUN("sudo is not available: the script drives the stock ceph and rbd commands, systemctl and the tools on /dev/rbdN with it");
	if (!keyring_named(k2, u2) || !keyring_named(k1, u1))
		NOTRUN("the keyring files must be named client.<user>.keyring (the script finds them by user name in one directory)");
	dir_of(k2, keydir, sizeof(keydir));
	dir_of(k1, keydir1, sizeof(keydir1));
	if (strcmp(keydir, keydir1) != 0)
		NOTRUN("both keyrings must be in one directory");

	/* the script reads its configuration from the environment: pass the names this test was given on */
	setenv("WR_KRBDCMP", krbdcmp_exe, 1);
	setenv("WR_RBD", rbd_exe, 1);
	setenv("WR_LAB_KEYRING_DIR", keydir, 1);
	setenv("WR_LAB_USER_K2", u2, 1);
	setenv("WR_LAB_USER_K1", u1, 1);

	full = env_or("WR_LAB_EXIT_FULL", "")[0] == '1';
	runs = env_or("WR_LAB_EXIT_RUNS", "1");
	report = getenv("WR_LAB_EXIT_REPORT");
	if (report != NULL && *report != '\0')
		setenv("EX_REPORT", report, 1);
	nruns = runs_in(runs);
	deadline = (unsigned)strtoul(env_or("WR_LAB_EXIT_DEADLINE", full ? "0" : "3600"), NULL, 10);

	args[n++] = (char *)"bash";
	args[n++] = script;
	args[n++] = (char *)"--runs";
	args[n++] = (char *)runs;
	if (!full)
		args[n++] = (char *)"--quick";
	if (getenv("WR_LAB_EXIT_ARGS") != NULL && *getenv("WR_LAB_EXIT_ARGS") != '\0') {
		char *w;

		extra = strdup(getenv("WR_LAB_EXIT_ARGS"));
		if (extra == NULL)
			abort();
		for (w = strtok(extra, " \t"); w != NULL && n + 1u < sizeof(args) / sizeof(args[0]); w = strtok(NULL, " \t"))
			args[n++] = w;
	}
	args[n] = NULL;
	/* a control run without the injector has no injector line to find; every other form (the full one too) must show that the faults ran */
	for (i = 0; i < n; i++)
		if (strcmp(args[i], "--no-faults") == 0)
			nofaults = 1;

	fd = mkstemp(outfile);
	if (fd < 0)
		abort();
	close(fd);
	rc = run_to_file(args, outfile, deadline);
	if (rc == -2) {
		(void)unlink(outfile);
		free(extra);
		NOTRUN("bash could not be started");
	}
	if (wrt_read_file(outfile, &buf, &len) != 0) {
		buf = NULL;
		len = 0;
	}
	if (rc != 0) {
		fprintf(stderr, "lab exit: exit-run.sh exited %d; its output:\n", rc);
		if (buf != NULL)
			show((const char *)buf, len, 1);
	} else if (buf != NULL) {
		show((const char *)buf, len, 0);
	}
	if (g_deadline_hit)
		fprintf(stderr, "lab exit: the script ran longer than WR_LAB_EXIT_DEADLINE (%u s) and was told to stop and restore the lab\n", deadline);
	if (g_signalled)
		fprintf(stderr, "lab exit: a signal reached the test; the script was told to stop and restore the lab\n");
	{
		const char *why = verdict((const char *)buf, len, rc, nofaults, nruns, g_deadline_hit, g_signalled);

		if (why != NULL)
			fprintf(stderr, "lab exit: NOT a pass: %s\n", why);
		WRT_CHECK(why == NULL);
	}
	free(buf);
	free(extra);
	(void)unlink(outfile);
	return wrt_finish();
}
