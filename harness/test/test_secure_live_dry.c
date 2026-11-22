/* SPDX-License-Identifier: MIT */
/*
 * test_secure_live_dry.c - the dry run of harness/lab/secure-live.sh (docs/design/core-architecture.md 39.2, module secure-live). No cluster needed:
 * the script runs against stand-ins for ceph, rbd, systemctl, wr-rbd, wr-monprobe, krbd-compare.sh and tcpdump that model a cluster whose monitor and
 * OSDs read the service modes when they are restarted (`secure-live.sh --selftest`). The self test proves, among other things:
 *
 *   - a full run passes and puts the cluster back exactly as it was (options, daemons restarted under them, no image or cephx user left);
 *   - a failure injected at each of thirteen steps (image creation, the stock export and import, the krbd comparison, both `config set` of each
 *     forced section, the restart of the monitor and of an OSD, the second export): the run fails AND the restore still ran;
 *   - a first `config set` that fails restarts nothing, a second one that fails restarts every daemon once;
 *   - a restore that cannot restart a daemon is not hidden (the run fails, "restore: FAILED"), and the next run refuses to start over it;
 *   - a drifted cluster (an upmap appears during the run) fails the run; a TERM while the cluster is forced is restored by the trap;
 *   - the wire check: the stand-in tcpdump writes a real capture in which the OSDs replicate the pattern among themselves in the clear (as on the
 *     stock cluster) and the check still passes; the pattern on a secure CLIENT connection fails it, and so does a capture blind to the client;
 *   - a run that sets no option (a client-only run) never reverts one: an option set by someone else during it is reported and left alone,
 *     and nothing is restarted.
 *
 * It also checks that the script names no cluster option other than the four of the lab rules (ms_mon_service_mode, ms_service_mode,
 * ms_mon_client_mode, ms_client_mode): every identifier that starts with ms_ in the file must be one of them. ctest name: secure.live.dry (skipped,
 * exit 77, on a machine without bash 4 and python3 on Linux: the script says so itself).
 */
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "wrt.h"

static int is_ident(int c)
{
	return isalnum((unsigned char)c) || c == '_';
}

/* every "ms_<word>" that is not inside a longer identifier must be one of the four allowed names */
static void check_option_names(const char *text, size_t n)
{
	static const char *const allowed[] = {"ms_mon_service_mode", "ms_service_mode", "ms_mon_client_mode", "ms_client_mode",
					      "ms_mode" /* krbd's own map option, not a cluster option */};
	size_t i, j;
	unsigned seen = 0;

	for (i = 0; i + 3u < n; i++) {
		char word[64];
		int ok = 0;
		size_t len = 0;

		if (memcmp(text + i, "ms_", 3) != 0 || (i > 0 && is_ident((unsigned char)text[i - 1u])))
			continue;
		while (i + len < n && is_ident((unsigned char)text[i + len]) && len + 1u < sizeof(word)) {
			word[len] = text[i + len];
			len++;
		}
		word[len] = '\0';
		if (len == 3u) /* "ms_*" in a sentence about the options in general */
			continue;
		for (j = 0; j < sizeof(allowed) / sizeof(allowed[0]); j++)
			if (strcmp(word, allowed[j]) == 0)
				ok = 1;
		if (!ok)
			fprintf(stderr, "secure-live.sh names the option '%s': only the four of the lab rules may appear\n", word);
		WRT_CHECK(ok);
		seen++;
		i += len;
	}
	WRT_CHECK(seen >= 4u); /* the scan found them: it did not silently match nothing */
}

int main(void)
{
	char script[PATH_MAX + 64], outfile[] = "/tmp/wr-secure-live-dry-XXXXXX";
	uint8_t *text = NULL, *out = NULL;
	size_t tlen = 0, olen = 0;
	pid_t pid;
	int status = 0, fd, rc;

	snprintf(script, sizeof(script), "%s/../lab/secure-live.sh", WRT_VECTOR_DIR);
	if (wrt_read_file(script, &text, &tlen) != 0)
		WRT_SKIP("harness/lab/secure-live.sh is not next to the vectors (an installed copy of the harness only)");
	check_option_names((const char *)text, tlen);
	WRT_CHECK(strstr((const char *)text, "trap on_exit EXIT") != NULL); /* the restore is in a trap, not at the end of the run */
	free(text);

	fd = mkstemp(outfile);
	if (fd < 0)
		abort();
	close(fd);
	pid = fork();
	if (pid < 0)
		abort();
	if (pid == 0) {
		int o = open(outfile, O_WRONLY | O_TRUNC, 0600), dn = open("/dev/null", O_RDONLY);

		(void)dup2(dn, 0);
		(void)dup2(o, 1);
		(void)dup2(o, 2);
		close(o);
		execlp("bash", "bash", script, "--selftest", (char *)NULL);
		_exit(127);
	}
	(void)waitpid(pid, &status, 0);
	rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	if (wrt_read_file(outfile, &out, &olen) != 0) {
		out = NULL;
		olen = 0;
	}
	(void)unlink(outfile);
	if (rc == 127)
		WRT_SKIP("bash is not available");
	if (rc == 77) {
		fprintf(stderr, "%s", out != NULL ? (const char *)out : "");
		free(out);
		WRT_SKIP("the self test of secure-live.sh needs bash 4+, Linux, python3 and timeout");
	}
	if (rc != 0 && out != NULL)
		fprintf(stderr, "%s", (const char *)out);
	WRT_CHECK_U64(rc, 0);
	WRT_CHECK(out != NULL && strstr((const char *)out, "selftest: all checks passed") != NULL);
	WRT_CHECK(out != NULL && strstr((const char *)out, "FAIL ") == NULL);
	free(out);
	return wrt_finish();
}
