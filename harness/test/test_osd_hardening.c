/* SPDX-License-Identifier: MIT */
/*
 * test_osd_hardening.c - the hardening of part C (OSD sessions, RBD open, image I/O) must stay wired into CI and the docs.
 *
 * The sibling of test_map_hardening.c for the milestones 6 to 8. Fuzz targets, seeds, static limits and the fault run
 * do their work only while something runs them; each check here is one way that could silently stop:
 *
 *   1. the seven part C fuzz targets (osd_reply, osd_backoff, rbd_cls, osd_sess, osd_req, rbd_open, client_osd) exist,
 *      each with committed seeds no larger than the 64 KiB input cap of the smoke job and of fuzz_long.sh, and the CI smoke
 *      job names them (a target dropped from the build turns the job red instead of shortening it);
 *   2. harness/tools/fuzz_long.sh knows the preset "partc" and its line lists exactly these seven;
 *   3. both READMEs mention every target and `osd.hardening`; every part C test group (osd.*, rbd.*, client.osd.*) is
 *      documented, and the README of the harness says what the fault run is;
 *   4. the call-graph budgets of part C are in the workflow: the OSD step, the engine's OSD stage, the image step, the request
 *      encode and the reply decode as `--entry NAME=BYTES` (those are also run by map.hardening, which runs every such token
 *      of the workflow), and the reply path through the msgr2 table as `--link` plus `--entry=` tokens, which this test reads
 *      out of the workflow and runs, so the workflow and the test cannot drift apart. The machinery is checked from the failing
 *      side too: a budget of 1 byte must fail with status 1, a link or an entry that is not in the graph must be a tool error
 *      (status 2). It compiles the core with gcc and needs python3; without them the part is skipped, with a message;
 *   5. the fault lab script exists, parses (`bash -n`), only ever creates and removes wrtest-ofl-* images, restores what it
 *      changed (daemons, `osd in`, the upmap entries it added), covers the faults the exit criteria name, refuses to start on a
 *      cluster that is not whole, and contains no command that destroys cluster state (purge, destroy, auth changes, pool
 *      deletion, the existing images); no text of the module names an address other than the lab defaults and the
 *      documentation ranges;
 *   6. the open items of the part C design (R-C1 to R-C12, Q12 to Q20) each have a line in section 31.3 of the design
 *      document, which also states what the finished code measured, and the roadmap shows milestones 6 to 8 as done.
 *
 * The test reads the source tree through WRT_VECTOR_DIR (<repo>/harness/vectors); without a source tree it skips.
 */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "wrt.h"

static const char *const targets[] = {"fuzz_osd_reply", "fuzz_osd_backoff", "fuzz_rbd_cls", "fuzz_osd_sess",
				      "fuzz_osd_req", "fuzz_rbd_open", "fuzz_client_osd"};
#define N_TARGETS (sizeof(targets) / sizeof(targets[0]))

/* the plain entry points whose own stack budget the workflow passes as `--entry NAME=BYTES` */
static const char *const entries[] = {"wri_osdc_step", "wri_client_osd_begin", "wri_rbd_step", "wri_mosdop_encode",
				      "wri_mosdopreply_decode"};
#define N_ENTRIES (sizeof(entries) / sizeof(entries[0]))

/* the reply path step of the workflow */
#define REPLY_STEP "- name: Measure the reply path through the msgr2 table"
#define REPLY_ENTRY "core/src/osd/wri_osd_sess_up.c:up_message"
#define REPLY_LINK "wri_m2c_ready_frame=" REPLY_ENTRY

#define FUZZ_MAX_LEN 65536u

static char root[1024];

static char *slurp(const char *rel)
{
	char path[1536];
	FILE *f;
	long n;
	char *buf;
	size_t got;

	if (snprintf(path, sizeof(path), "%s/%s", root, rel) >= (int)sizeof(path))
		return NULL;
	f = fopen(path, "rb");
	if (f == NULL)
		return NULL;
	if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
		fclose(f);
		return NULL;
	}
	buf = (char *)malloc((size_t)n + 1u);
	if (buf == NULL)
		abort();
	got = fread(buf, 1, (size_t)n, f);
	fclose(f);
	buf[got] = '\0';
	return buf;
}

static int file_exists(const char *rel)
{
	char path[1536];
	struct stat st;

	if (snprintf(path, sizeof(path), "%s/%s", root, rel) >= (int)sizeof(path))
		return 0;
	return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static unsigned count_files(const char *rel)
{
	char path[1536];
	DIR *d;
	struct dirent *e;
	unsigned n = 0;

	if (snprintf(path, sizeof(path), "%s/%s", root, rel) >= (int)sizeof(path))
		return 0;
	d = opendir(path);
	if (d == NULL)
		return 0;
	while ((e = readdir(d)) != NULL)
		if (e->d_name[0] != '.')
			n++;
	closedir(d);
	return n;
}

static unsigned long largest_file(const char *rel)
{
	char path[1536], f[2048];
	DIR *d;
	struct dirent *e;
	unsigned long big = 0;

	if (snprintf(path, sizeof(path), "%s/%s", root, rel) >= (int)sizeof(path))
		return 0;
	d = opendir(path);
	if (d == NULL)
		return 0;
	while ((e = readdir(d)) != NULL) {
		struct stat st;

		if (e->d_name[0] == '.' || snprintf(f, sizeof(f), "%s/%s", path, e->d_name) >= (int)sizeof(f))
			continue;
		if (stat(f, &st) == 0 && S_ISREG(st.st_mode) && (unsigned long)st.st_size > big)
			big = (unsigned long)st.st_size;
	}
	closedir(d);
	return big;
}

static void need(const char *doc, const char *docname, const char *what)
{
	if (strstr(doc, what) == NULL)
		fprintf(stderr, "%s has no '%s'\n", docname, what);
	WRT_CHECK(strstr(doc, what) != NULL);
}

static void forbid(const char *doc, const char *docname, const char *what)
{
	if (strstr(doc, what) != NULL)
		fprintf(stderr, "%s must not contain '%s'\n", docname, what);
	WRT_CHECK(strstr(doc, what) == NULL);
}

/* every dotted quad in a text of the module is the lab default (10.77.0.x), a documentation address (192.0.2.x) or loopback:
 * no other machine of any network is named in the repository */
static void check_addresses(const char *doc, const char *docname)
{
	const char *p;

	for (p = doc; *p != '\0'; p++) {
		unsigned parts = 0, k = 0;
		const char *q = p;
		int ok = 0;

		if (*p < '0' || *p > '9' || (p != doc && ((p[-1] >= '0' && p[-1] <= '9') || p[-1] == '.')))
			continue;
		while (parts < 4u) {
			k = 0;
			while (q[k] >= '0' && q[k] <= '9')
				k++;
			if (k == 0 || k > 3u)
				break;
			parts++;
			q += k;
			if (parts < 4u) {
				if (*q != '.')
					break;
				q++;
			}
		}
		if (parts == 4u && !(*q >= '0' && *q <= '9') && *q != '.') {
			ok = strncmp(p, "10.77.0.", 8) == 0 || strncmp(p, "192.0.2.", 8) == 0 || strncmp(p, "127.0.0.", 8) == 0;
			if (!ok)
				fprintf(stderr, "%s names an address that is neither the lab default nor a documentation address: %.*s\n",
					docname, (int)(q - p), p);
			WRT_CHECK(ok);
		}
		if (parts >= 1u && q > p)
			p = q - 1;
	}
}

/* ---- 1 to 3: targets, seeds, presets, documents --------------------------------------------------------------- */

/* the line of fuzz_long.sh that defines the preset: it must hold every target and nothing else that starts with fuzz_ */
static void check_preset_line(const char *lng)
{
	const char *p = strstr(lng, "\npartc=\"");
	const char *e;
	size_t i, n_words = 0;
	const char *q;

	WRT_CHECK(p != NULL);
	if (p == NULL)
		return;
	p += 8;
	e = strchr(p, '"');
	WRT_CHECK(e != NULL);
	if (e == NULL)
		return;
	for (q = p; q < e; q++)
		if (*q == 'f' && (q == p || q[-1] == ' '))
			n_words++;
	if (n_words != N_TARGETS)
		fprintf(stderr, "fuzz_long.sh: the partc preset lists %u targets, not %u\n", (unsigned)n_words, (unsigned)N_TARGETS);
	WRT_CHECK(n_words == N_TARGETS);
	for (i = 0; i < N_TARGETS; i++) {
		size_t len = strlen(targets[i]);
		const char *w = p;
		int found = 0;

		while ((w = strstr(w, targets[i])) != NULL && w < e) {
			if ((w == p || w[-1] == ' ') && (w[len] == ' ' || w + len == e))
				found = 1;
			w += len;
		}
		if (!found)
			fprintf(stderr, "the partc preset of fuzz_long.sh does not list %s\n", targets[i]);
		WRT_CHECK(found);
	}
}

static int has_prefix_test(const char *name, const char *prefix)
{
	return strncmp(name, prefix, strlen(prefix)) == 0;
}

/* every part C test group is named in one of the READMEs: its exact name, or its group wildcard (`osd.*`) */
#define MAX_TESTS 256u
static char tests[MAX_TESTS][64];
static unsigned n_tests;

static void collect_tests(void)
{
	char path[1536];
	DIR *d;
	struct dirent *e;

	snprintf(path, sizeof(path), "%s/harness/test", root);
	d = opendir(path);
	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		size_t len = strlen(e->d_name);
		char *p;

		if (strncmp(e->d_name, "test_", 5) != 0 || len < 8u || strcmp(e->d_name + len - 2u, ".c") != 0 ||
		    n_tests >= MAX_TESTS || len - 7u >= sizeof(tests[0]))
			continue;
		memcpy(tests[n_tests], e->d_name + 5, len - 7u);
		tests[n_tests][len - 7u] = '\0';
		for (p = tests[n_tests]; *p != '\0'; p++)
			if (*p == '_')
				*p = '.';
		n_tests++;
	}
	closedir(d);
}

static void check_test_docs(const char *hr, const char *cr)
{
	unsigned i, part_c = 0;

	collect_tests();
	for (i = 0; i < n_tests; i++) {
		const char *wild = NULL;
		char tick[96];

		if (has_prefix_test(tests[i], "osd.") && !has_prefix_test(tests[i], "osd.map"))
			wild = "`osd.*`";
		else if (has_prefix_test(tests[i], "rbd."))
			wild = "`rbd.*`";
		else if (has_prefix_test(tests[i], "client.osd."))
			wild = "`client.osd.*`";
		if (wild == NULL)
			continue;
		part_c++;
		snprintf(tick, sizeof(tick), "`%.60s`", tests[i]);
		if (strstr(hr, tick) == NULL && strstr(cr, tick) == NULL && strstr(hr, wild) == NULL && strstr(cr, wild) == NULL)
			fprintf(stderr, "no README names the part C test %s (nor its group %s)\n", tests[i], wild);
		WRT_CHECK(strstr(hr, tick) != NULL || strstr(cr, tick) != NULL || strstr(hr, wild) != NULL ||
			  strstr(cr, wild) != NULL);
	}
	WRT_CHECK(part_c >= 30u); /* the scan found the part C tests: it did not silently match nothing */
}

static char *step_text(const char *yml, const char *header);

#define SMOKE_STEP "- name: The part C targets exist and have seeds"

static void check_targets_and_docs(void)
{
	char *yml = slurp(".github/workflows/harness.yml");
	char *lng = slurp("harness/tools/fuzz_long.sh");
	char *hr = slurp("harness/README.md");
	char *cr = slurp("core/README.md");
	char *smoke;
	size_t i;
	char rel[256], tick[64], bare[64];

	WRT_CHECK(yml != NULL && lng != NULL && hr != NULL && cr != NULL);
	if (yml == NULL || lng == NULL || hr == NULL || cr == NULL)
		goto out;
	need(lng, "fuzz_long.sh", "partc");
	need(lng, "fuzz_long.sh", "-max_len=65536");
	check_preset_line(lng);
	need(yml, "harness.yml", "The part C targets exist and have seeds");
	need(yml, "harness.yml", "-max_len=65536");
	/* the existence step must loop over every target: a name that is only mentioned elsewhere in the file (a comment) would let
	 * a dropped target shorten the check without turning the job red */
	smoke = step_text(yml, SMOKE_STEP);
	WRT_CHECK(smoke != NULL);
	if (smoke != NULL) {
		need(smoke, "the part C smoke step", "for t in ");
		need(smoke, "the part C smoke step", "build/fuzz/$t");
		need(smoke, "the part C smoke step", "harness/fuzz/seeds/$t");
		for (i = 0; i < N_TARGETS; i++) {
			snprintf(tick, sizeof(tick), " %s", targets[i]);
			need(smoke, "the part C smoke step", tick);
		}
		free(smoke);
	}
	for (i = 0; i < N_TARGETS; i++) {
		snprintf(rel, sizeof(rel), "harness/fuzz/%s.c", targets[i]);
		if (!file_exists(rel))
			fprintf(stderr, "%s is missing\n", rel);
		WRT_CHECK(file_exists(rel));
		snprintf(rel, sizeof(rel), "harness/fuzz/seeds/%s", targets[i]);
		if (count_files(rel) == 0)
			fprintf(stderr, "%s has no committed seed\n", rel);
		WRT_CHECK(count_files(rel) > 0);
		if (largest_file(rel) > FUZZ_MAX_LEN)
			fprintf(stderr, "%s has a seed above the %u-byte input cap of the fuzz runs\n", rel, FUZZ_MAX_LEN);
		WRT_CHECK(largest_file(rel) <= FUZZ_MAX_LEN);
		need(yml, "harness.yml", targets[i]);
		need(lng, "fuzz_long.sh", targets[i]);
		snprintf(tick, sizeof(tick), "`%s`", targets[i]);
		need(hr, "harness/README.md", tick);
		need(cr, "core/README.md", tick);
		snprintf(bare, sizeof(bare), "`%s`", targets[i] + 5);
		need(hr, "harness/README.md", bare);
	}
	need(hr, "harness/README.md", "`osd.hardening`");
	need(cr, "core/README.md", "`osd.hardening`");
	need(hr, "harness/README.md", "osd_fault_lab.sh");
	need(hr, "harness/README.md", "-p partc");
	need(cr, "core/README.md", "osd_fault_lab.sh");
	check_test_docs(hr, cr);
	check_addresses(yml, "harness.yml");
	check_addresses(lng, "fuzz_long.sh");
	check_addresses(hr, "harness/README.md");
	check_addresses(cr, "core/README.md");
out:
	free(yml);
	free(lng);
	free(hr);
	free(cr);
}

/* ---- 4: the call-graph budgets of part C ------------------------------------------------------------------------ */

/* the text of one workflow step: from its "- name:" line to the next empty line */
static char *step_text(const char *yml, const char *header)
{
	const char *p = strstr(yml, header), *e;
	char *out;

	if (p == NULL)
		return NULL;
	e = strstr(p, "\n\n");
	if (e == NULL)
		e = p + strlen(p);
	out = (char *)malloc((size_t)(e - p) + 1u);
	if (out == NULL)
		abort();
	memcpy(out, p, (size_t)(e - p));
	out[e - p] = '\0';
	return out;
}

static int arg_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '=' || c == '.' || c == '/' || c == ':';
}

/* append " <opt> '<value>'" for every token of the step that starts with opt (a two-token option "--link X" or "--entry=X");
 * only plain characters go into a shell command; returns how many were added, -1 on a bad token */
static int append_tokens(const char *step, const char *opt, int two_tokens, char *cmd, size_t cap)
{
	const char *p = step;
	size_t optlen = strlen(opt), len = strlen(cmd);
	int n = 0;

	while ((p = strstr(p, opt)) != NULL) {
		const char *ls = p, *v;
		size_t k = 0, j;

		while (ls > step && ls[-1] != '\n')
			ls--;
		while (*ls == ' ' || *ls == '\t')
			ls++;
		v = p + optlen;
		if (*ls == '#' || (p != step && p[-1] != ' ')) { /* a comment, or the middle of a longer word */
			p = v;
			continue;
		}
		if (two_tokens) {
			if (*v != ' ') {
				p = v;
				continue;
			}
			v++;
		}
		while (v[k] != '\0' && v[k] != '\n' && v[k] != ' ' && v[k] != '\r')
			k++;
		if (k == 0 || k > 120u) {
			fprintf(stderr, "harness.yml: odd %s token\n", opt);
			return -1;
		}
		for (j = 0; j < k; j++)
			if (!arg_char(v[j])) {
				fprintf(stderr, "harness.yml: odd character in a %s token\n", opt);
				return -1;
			}
		if (len + k + 24u >= cap)
			return -1;
		if (two_tokens)
			len += (size_t)snprintf(cmd + len, cap - len, " %s '%.*s'", opt, (int)k, v);
		else
			len += (size_t)snprintf(cmd + len, cap - len, " %s'%.*s'", opt, (int)k, v);
		n++;
		p = v + k;
	}
	return n;
}

static int status_of(int rc)
{
	return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

static void check_callgraph(void)
{
	char *yml = slurp(".github/workflows/harness.yml");
	char *step = NULL;
	char cmd[4096], quoted[1100], path[1100];
	size_t i, q = 0;
	int rc, n_link, n_entry;

	WRT_CHECK(yml != NULL);
	if (yml == NULL)
		return;
	/* the workflow must carry the budgets, whatever gcc or python can do here */
	need(yml, "harness.yml", "check_callgraph.py --cc gcc --depth 14 --stack 3328");
	for (i = 0; i < N_ENTRIES; i++) {
		char tok[96];

		snprintf(tok, sizeof(tok), "--entry %s=", entries[i]); /* a budget, not just a report */
		need(yml, "harness.yml", tok);
	}
	need(yml, "harness.yml", REPLY_STEP);
	step = step_text(yml, REPLY_STEP);
	WRT_CHECK(step != NULL);
	if (step == NULL)
		goto out;
	need(step, "the reply path step", "--depth 14 --stack 3328");
	need(step, "the reply path step", "--link " REPLY_LINK);
	need(step, "the reply path step", "--entry=" REPLY_ENTRY "=");

	if (system("python3 --version >/dev/null 2>&1") != 0 || system("gcc --version >/dev/null 2>&1") != 0) {
		fprintf(stderr, "osd.hardening: python3 or gcc not found: the call-graph part is skipped\n");
		goto out;
	}
	if (!file_exists("harness/tests/ci-docs-hardening/check_callgraph.py")) {
		fprintf(stderr, "check_callgraph.py is missing\n");
		WRT_CHECK(0);
		goto out;
	}
	snprintf(path, sizeof(path), "%s/harness/tests/ci-docs-hardening/check_callgraph.py", root);
	/* the repository path goes into a shell command: single-quote it and refuse a quote inside it */
	for (i = 0; path[i] != '\0' && q + 2u < sizeof(quoted); i++) {
		if (path[i] == '\'') {
			fprintf(stderr, "osd.hardening: a quote in the path, call-graph part skipped\n");
			goto out;
		}
		quoted[q++] = path[i];
	}
	quoted[q] = '\0';

	/* the reply path, exactly as the workflow runs it */
	snprintf(cmd, sizeof(cmd), "python3 -I '%s' --cc gcc --depth 14 --stack 3328", quoted);
	n_link = append_tokens(step, "--link", 1, cmd, sizeof(cmd));
	n_entry = append_tokens(step, "--entry=", 0, cmd, sizeof(cmd));
	WRT_CHECK(n_link >= 2); /* the OSD session and the monitor client */
	WRT_CHECK(n_entry >= 2);
	if (n_link >= 2 && n_entry >= 2) {
		rc = system(cmd);
		if (rc != 0)
			fprintf(stderr, "osd.hardening: the call-graph check of the reply path failed (status %d): %s\n", rc, cmd);
		WRT_CHECK(rc == 0);
	}
	/* the failing side: a budget of 1 byte through the link fails with 1, a link or an entry that is not in the graph is 2 */
	snprintf(cmd, sizeof(cmd), "python3 -I '%s' --cc gcc --depth 14 --stack 3328 --link '%s' --entry='%s=1' >/dev/null 2>&1",
		 quoted, REPLY_LINK, REPLY_ENTRY);
	rc = system(cmd);
	if (status_of(rc) != 1)
		fprintf(stderr, "osd.hardening: a budget of 1 byte did not fail the call-graph check with status 1 (got %d)\n", rc);
	WRT_CHECK(status_of(rc) == 1);
	snprintf(cmd, sizeof(cmd), "python3 -I '%s' --cc gcc --depth 14 --stack 3328 --link 'wri_m2c_ready_frame=wri_no_such_handler'"
		 " >/dev/null 2>&1", quoted);
	rc = system(cmd);
	if (status_of(rc) != 2)
		fprintf(stderr, "osd.hardening: a link to a function that does not exist was not a tool error (status 2) (got %d)\n", rc);
	WRT_CHECK(status_of(rc) == 2);
	snprintf(cmd, sizeof(cmd), "python3 -I '%s' --cc gcc --depth 14 --stack 3328 --entry wri_no_such_entry=64 >/dev/null 2>&1",
		 quoted);
	rc = system(cmd);
	if (status_of(rc) != 2)
		fprintf(stderr, "osd.hardening: an unknown entry point was not a tool error (status 2) (got %d)\n", rc);
	WRT_CHECK(status_of(rc) == 2);
out:
	free(step);
	free(yml);
}

/* ---- 5: the fault lab script ---------------------------------------------------------------------------------- */

static void check_fault_lab(void)
{
	static const char *const must[] = {
		"wrtest-ofl-",           /* the only things it creates */
		"PFX=wrtest-ofl-",
		"restore_cluster",       /* daemons, osd in, upmap entries */
		"osd rm-pg-upmap",       /* what it added, it removes */
		"osd pg-upmap",          /* the map change without a daemon going down */
		"osd out",               /* mark out and in */
		"osd in",
		"pkill -9",              /* a daemon killed, not only stopped */
		"systemctl stop",
		"trap cleanup EXIT",     /* also after an interrupted run */
		"--overlap",             /* requests that overlap while the map changes */
		"--cycles",              /* the fault repeated while the run is going */
		"kill -0",               /* ... and the run must outlast the first fault */
		"rbd export",            /* the stock tool as the second reader */
		"final_diff_bytes=0",    /* zero differences */
		"BASE_STATE",            /* the cluster compared with where it started */
		"act_kill", "act_outin", "act_upmap", "act_both",
	};
	/* nothing in the script may destroy cluster state, touch an existing image or pool, or name a machine that is not ours */
	static const char *const never[] = {
		"osd purge", "osd destroy", "osd rm ", "osd crush remove", "osd crush rm", "auth del", "auth rm", "auth caps",
		"auth import", "pool delete", "pool rm", "osd pool set", "osd pool create", "img-default", "img-v1",
		"mon remove", "mon rm", "osd set noout", "rbd snap", "rbd trash", "--yes-i-really",
		"osd reweight", "osd crush reweight", "rm -rf /",
	};
	char *sh = slurp("harness/tools/osd_fault_lab.sh");
	char path[1536];
	size_t i;

	WRT_CHECK(sh != NULL);
	if (sh == NULL)
		return;
	for (i = 0; i < sizeof(must) / sizeof(must[0]); i++)
		need(sh, "osd_fault_lab.sh", must[i]);
	for (i = 0; i < sizeof(never) / sizeof(never[0]); i++)
		forbid(sh, "osd_fault_lab.sh", never[i]);
	check_addresses(sh, "osd_fault_lab.sh");
	/* it refuses to start on a cluster that is not whole: the restore puts every OSD back, which must be a restore */
	need(sh, "osd_fault_lab.sh", "not every OSD is up and in at the start");
	need(sh, "osd_fault_lab.sh", "PRE_UPMAP");
	need(sh, "osd_fault_lab.sh", "--only takes");
	/* every image it removes is guarded by the prefix */
	need(sh, "osd_fault_lab.sh", "case \"$i\" in \"$PFX\"*) RBD rm");
	{ /* ... and it is the only place an image is removed: a second `RBD rm` would be one nobody guarded */
		unsigned n_rm = 0;
		const char *q = sh;

		while ((q = strstr(q, "RBD rm")) != NULL) {
			n_rm++;
			q += 6;
		}
		if (n_rm != 1u)
			fprintf(stderr, "osd_fault_lab.sh removes images in %u places, not in the one guarded by the prefix\n", n_rm);
		WRT_CHECK(n_rm == 1u);
	}
	if (strncmp(sh, "#!/usr/bin/env bash\n# SPDX-License-Identifier: MIT", 50) != 0)
		fprintf(stderr, "osd_fault_lab.sh: the first two lines are not the interpreter and the SPDX tag\n");
	WRT_CHECK(strncmp(sh, "#!/usr/bin/env bash\n# SPDX-License-Identifier: MIT", 50) == 0);
	/* no key material: it never prints or copies a keyring */
	forbid(sh, "osd_fault_lab.sh", "cat \"$KR_");
	forbid(sh, "osd_fault_lab.sh", "cat \"$CUR_KR");
	free(sh);

	snprintf(path, sizeof(path), "bash -n '%s/harness/tools/osd_fault_lab.sh' 2>/dev/null", root);
	if (strchr(root, '\'') == NULL && system("bash --version >/dev/null 2>&1") == 0) {
		int rc = system(path);

		if (status_of(rc) != 0)
			fprintf(stderr, "osd_fault_lab.sh does not parse (bash -n, status %d)\n", rc);
		WRT_CHECK(status_of(rc) == 0);
	} else {
		fprintf(stderr, "osd.hardening: bash not found: the syntax check of osd_fault_lab.sh is skipped\n");
	}
	snprintf(path, sizeof(path), "sh -n '%s/harness/tools/fuzz_long.sh' 2>/dev/null", root);
	if (strchr(root, '\'') == NULL) {
		int rc = system(path);

		if (status_of(rc) != 0)
			fprintf(stderr, "fuzz_long.sh does not parse (sh -n, status %d)\n", rc);
		WRT_CHECK(status_of(rc) == 0);
	}
}

/* ---- 6: the design document and the roadmap ---------------------------------------------------------------------- */

static void check_design_and_roadmap(void)
{
	char *doc = slurp("docs/design/core-architecture.md");
	char *road = slurp("docs/ROADMAP.md");
	const char *s31, *end;
	char *sec;
	unsigned i;

	WRT_CHECK(doc != NULL && road != NULL);
	if (doc == NULL || road == NULL)
		goto out;
	check_addresses(doc, "core-architecture.md");
	check_addresses(road, "ROADMAP.md");
	/* the status line at the top of the design document must not still say that part C is only a skeleton */
	forbid(doc, "core-architecture.md", "implementation waves of section 29.2 have not started");
	s31 = strstr(doc, "\n### 31.3 ");
	WRT_CHECK(s31 != NULL);
	if (s31 == NULL) {
		fprintf(stderr, "the design document has no section 31.3 (what the finished code measured)\n");
		goto out;
	}
	s31++;
	end = strstr(s31, "\n## ");
	if (end == NULL)
		end = strstr(s31, "\n---");
	if (end == NULL)
		end = s31 + strlen(s31);
	sec = (char *)malloc((size_t)(end - s31) + 1u);
	if (sec == NULL)
		abort();
	memcpy(sec, s31, (size_t)(end - s31));
	sec[end - s31] = '\0';
	for (i = 1; i <= 12; i++) {
		char tok[32];

		snprintf(tok, sizeof(tok), "R-C%u ", i);
		need(sec, "section 31.3", tok);
	}
	for (i = 12; i <= 20; i++) {
		char tok[32];

		snprintf(tok, sizeof(tok), "Q%u ", i);
		need(sec, "section 31.3", tok);
	}
	need(sec, "section 31.3", "Footprint");
	need(sec, "section 31.3", "Call graph");
	need(sec, "section 31.3", "Fuzzing");
	need(sec, "section 31.3", "Fault run");
	free(sec);
	/* the roadmap's status table: the three milestones are no longer "not started" (English and Chinese rows) */
	forbid(road, "ROADMAP.md", "| 6 to 9 | OSD sessions, RBD open, image I/O, krbd comparison | not started |");
	forbid(road, "ROADMAP.md", "| 6 至 9 |");
	need(road, "ROADMAP.md", "| 6 | OSD sessions");
	need(road, "ROADMAP.md", "| 7 | RBD format 2 open");
	need(road, "ROADMAP.md", "| 8 | Image block I/O");
	need(road, "ROADMAP.md", "| 9 | Comparison with krbd");
out:
	free(doc);
	free(road);
}

int main(void)
{
	char probe[1536];
	struct stat st;

	snprintf(root, sizeof(root), "%s/../..", WRT_VECTOR_DIR);
	snprintf(probe, sizeof(probe), "%s/core/README.md", root);
	if (stat(probe, &st) != 0)
		WRT_SKIP("no source tree around the harness (core/README.md not found)");
	check_targets_and_docs();
	check_callgraph();
	check_fault_lab();
	check_design_and_roadmap();
	return wrt_finish();
}
