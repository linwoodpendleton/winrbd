/* SPDX-License-Identifier: MIT */
/*
 * test_secure_hardening.c - the hardening of part D (the krbd comparison and secure mode) must stay wired into CI and the docs.
 *
 * The sibling of test_map_hardening.c and test_osd_hardening.c for the milestones 9 and 11. Fuzz targets, seeds, static limits and
 * the Valgrind check do their work only while something runs them; each check here is one way that could silently stop:
 *
 *   1. the five new fuzz targets (gcm, m2_sec_tx, m2_sec_rx, m2_conn_sec, client_secure) exist, each with committed seeds no larger
 *      than the 64 KiB input cap of the smoke job and of fuzz_long.sh, and the secret-carrying seeds of fuzz_cx_reply are there; the
 *      CI smoke job has a step that loops over exactly these names (a target dropped from the build turns the job red instead of
 *      shortening it);
 *   2. harness/tools/fuzz_long.sh knows the preset "partd" (its line lists exactly the five) and the option -w; bad values of the
 *      options are refused with status 2 before anything is built;
 *   3. both READMEs mention every target and `secure.hardening`; every part D test group is documented; the README of the harness
 *      says what -p partd and -w are;
 *   4. the call-graph budgets of part D are in the workflow: the secure receive step, the secure transmit frame, the GCM update
 *      chain and the rest of the chains of design 36.4 as `--entry NAME=BYTES`; the test reads them out of the workflow step and
 *      runs them (so the workflow and the test cannot drift apart), and checks the machinery from the failing side too: a budget
 *      of 1 byte must fail with status 1 and an entry that is not in the graph must be a tool error (status 2). The global limits
 *      of the step must equal those of the first measuring step. It compiles the core with gcc and needs python3; without them
 *      this part is skipped, with a message;
 *   5. the Valgrind check of the constant-time properties is a required step of CI (valgrind installed, WRT_CT_REQUIRE=1, the
 *      crypto.ct tests selected, a ctest that finds nothing fails);
 *   6. every file of the part D modules is in core/sources.txt, and nothing in core/ names a crypto library or a kernel client, nor
 *      carries the AES substitution table (in any of its usual spellings) in the constant-time files; no text file of the repository
 *      (core, harness, docs, the workflows, the top-level documents) carries an authorship trailer or the name of a tool vendor (the
 *      licence and copying scan; the comparison against the Ceph tree is the offline part of it, recorded in section 41.3 of the
 *      design document);
 *   7. the open items of the part D design (R-D1 to R-D9, the seven open questions of 41.2) each have a line in section 41.3 of the
 *      design document, which also states what the finished code measured; the roadmap shows milestones 9 and 11 as done, with the
 *      numbers of the lab runs that showed it, and Phase 1 as not closed until the exit run with the faults has reported (English
 *      and Chinese); the secure-mode note has the answers of the lab to its questions 6.4 and 6.5.
 *
 * The test reads the source tree through WRT_VECTOR_DIR (<repo>/harness/vectors); without a source tree it skips.
 */
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "wrt.h"

static const char *const targets[] = {"fuzz_gcm", "fuzz_m2_sec_tx", "fuzz_m2_sec_rx", "fuzz_m2_conn_sec", "fuzz_client_secure"};
#define N_TARGETS (sizeof(targets) / sizeof(targets[0]))

/* the plain entry points whose own stack budget the workflow passes as `--entry NAME=BYTES` in the secure-mode step (design 36.4: the
 * secure receive step, the secure transmit frame and the GCM update chain, and the neighbours that complete the picture) */
static const char *const entries[] = {"wri_m2s_rx_step",     "wri_m2s_tx_frame",       "wri_m2s_tx_consume", "wri_pgcm_update",
				      "wri_pgcm_final_enc",  "wri_pgcm_final_dec",     "wri_pgcm_setkey",    "wri_m2_secure_on",
				      "wri_ghash_blocks",    "wri_aesct_encrypt_blocks", "wri_m2_rx_step",   "wri_m2c_send"};
#define N_ENTRIES (sizeof(entries) / sizeof(entries[0]))

#define SECURE_STEP "- name: Measure the secure-mode chains"
#define SMOKE_STEP "- name: The part D targets exist and have seeds"
#define VG_STEP "- name: Constant-time checks under Valgrind"
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

static unsigned count_prefixed(const char *rel, const char *prefix)
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
		if (e->d_name[0] != '.' && strncmp(e->d_name, prefix, strlen(prefix)) == 0)
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

static int status_of(int rc)
{
	return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

/* ---- 1 to 3: targets, seeds, presets, documents --------------------------------------------------------------- */

/* the line of fuzz_long.sh that defines the preset: it must hold every target and nothing else that starts with fuzz_ */
static void check_preset_line(const char *lng)
{
	const char *p = strstr(lng, "\npartd=\"");
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
		fprintf(stderr, "fuzz_long.sh: the partd preset lists %u targets, not %u\n", (unsigned)n_words, (unsigned)N_TARGETS);
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
			fprintf(stderr, "the partd preset of fuzz_long.sh does not list %s\n", targets[i]);
		WRT_CHECK(found);
	}
}

/* the part D test groups: a test whose name starts with one of these is documented in a README, by its exact name or by its group
 * wildcard (`m2.sec.*`) */
static const char *const groups[] = {"crypto.aesct", "crypto.ghash", "crypto.gcm", "crypto.pgcm", "crypto.ct.", "ref.gcm",
				     "m2.sec.", "m2.modes", "m2.conn.sec.", "client.sec.", "sim.sec.", "host.gcm.aesni",
				     "host.cmp", "host.tool.krbdcmp", "host.loop.sec", "host.tool.rbd.sec", "lab.secure", "secure.",
				     "auth.secret"};
#define N_GROUPS (sizeof(groups) / sizeof(groups[0]))

#define MAX_TESTS 320u
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

/* documented: the exact test name in backticks, or the wildcard of its group (`m2.sec.*`, `crypto.gcm.*`), or the group named whole
 * for a group that is one test (`m2.modes`, `host.cmp`) */
static int documented(const char *hr, const char *cr, const char *name, const char *group)
{
	char tick[96], wild[96];
	size_t g = strlen(group);

	snprintf(tick, sizeof(tick), "`%.60s`", name);
	if (strstr(hr, tick) != NULL || strstr(cr, tick) != NULL)
		return 1;
	snprintf(wild, sizeof(wild), "`%.60s%s*`", group, group[g - 1u] == '.' ? "" : ".");
	if (strstr(hr, wild) != NULL || strstr(cr, wild) != NULL)
		return 1;
	snprintf(wild, sizeof(wild), "`%.60s`", group);
	return strstr(hr, wild) != NULL || strstr(cr, wild) != NULL;
}

static void check_test_docs(const char *hr, const char *cr)
{
	unsigned i, g, part_d = 0;

	collect_tests();
	for (i = 0; i < n_tests; i++) {
		for (g = 0; g < N_GROUPS; g++) {
			if (strncmp(tests[i], groups[g], strlen(groups[g])) != 0)
				continue;
			part_d++;
			if (!documented(hr, cr, tests[i], groups[g]))
				fprintf(stderr, "no README names the part D test %s (nor its group %s)\n", tests[i], groups[g]);
			WRT_CHECK(documented(hr, cr, tests[i], groups[g]));
			break;
		}
	}
	WRT_CHECK(part_d >= 40u); /* the scan found the part D tests: it did not silently match nothing */
}

static void check_targets_and_docs(void)
{
	char *yml = slurp(".github/workflows/harness.yml");
	char *lng = slurp("harness/tools/fuzz_long.sh");
	char *hr = slurp("harness/README.md");
	char *cr = slurp("core/README.md");
	char *smoke;
	size_t i;
	char rel[256], tick[96], bare[96];

	WRT_CHECK(yml != NULL && lng != NULL && hr != NULL && cr != NULL);
	if (yml == NULL || lng == NULL || hr == NULL || cr == NULL)
		goto out;
	need(lng, "fuzz_long.sh", "partd");
	need(lng, "fuzz_long.sh", "-max_len=65536");
	need(lng, "fuzz_long.sh", "-fork=");
	need(lng, "fuzz_long.sh", "-w WORKERS");
	check_preset_line(lng);
	need(yml, "harness.yml", SMOKE_STEP);
	/* the existence step must loop over every target: a name that is only mentioned elsewhere in the file (a comment) would let
	 * a dropped target shorten the check without turning the job red */
	smoke = step_text(yml, SMOKE_STEP);
	WRT_CHECK(smoke != NULL);
	if (smoke != NULL) {
		need(smoke, "the part D smoke step", "for t in ");
		need(smoke, "the part D smoke step", "build/fuzz/$t");
		need(smoke, "the part D smoke step", "harness/fuzz/seeds/$t");
		for (i = 0; i < N_TARGETS; i++) {
			snprintf(tick, sizeof(tick), " %s", targets[i]);
			need(smoke, "the part D smoke step", tick);
		}
		need(smoke, "the part D smoke step", "seeds/fuzz_cx_reply/sec_"); /* the secret-carrying seeds of the older target */
		free(smoke);
	}
	for (i = 0; i < N_TARGETS; i++) {
		snprintf(rel, sizeof(rel), "harness/fuzz/%s.c", targets[i]);
		if (!file_exists(rel))
			fprintf(stderr, "%s is missing\n", rel);
		WRT_CHECK(file_exists(rel));
		snprintf(rel, sizeof(rel), "harness/fuzz/seeds/%s", targets[i]);
		if (count_prefixed(rel, "") == 0)
			fprintf(stderr, "%s has no committed seed\n", rel);
		WRT_CHECK(count_prefixed(rel, "") > 0);
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
	/* fuzz_cx_reply gained seeds that carry a connection secret (a monitor and an OSD reply, good and bad lengths, both versions) */
	WRT_CHECK(count_prefixed("harness/fuzz/seeds/fuzz_cx_reply", "sec_") >= 8u);
	need(hr, "harness/README.md", "`secure.hardening`");
	need(cr, "core/README.md", "`secure.hardening`");
	need(hr, "harness/README.md", "-p partd");
	need(hr, "harness/README.md", "-w ");
	need(cr, "core/README.md", "-p partd");
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

/* the options of fuzz_long.sh that are refused are refused before anything is built (exit 2); the script is parsed by sh -n too */
static void check_fuzz_long_options(void)
{
	static const char *const bad[] = {"-w 0", "-w x", "-w 999", "-w ''", "-p partx", "-t fuzz_gcm -p partd", "-j 0"};
	char cmd[1800];
	size_t i;

	if (strchr(root, '\'') != NULL)
		return;
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		int rc;

		snprintf(cmd, sizeof(cmd), "sh '%s/harness/tools/fuzz_long.sh' -o /nonexistent/never/made %s >/dev/null 2>&1", root, bad[i]);
		rc = system(cmd);
		if (status_of(rc) != 2)
			fprintf(stderr, "fuzz_long.sh %s: expected status 2, got %d\n", bad[i], status_of(rc));
		WRT_CHECK(status_of(rc) == 2);
	}
	snprintf(cmd, sizeof(cmd), "sh -n '%s/harness/tools/fuzz_long.sh' 2>/dev/null", root);
	WRT_CHECK(status_of(system(cmd)) == 0);
}

/* ---- 4: the call-graph budgets of part D ------------------------------------------------------------------------ */

static int arg_char(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '=' || c == '.' || c == '/' || c == ':';
}

/* append " --entry '<value>'" for every "--entry NAME=BYTES" token of the step that is not in a comment; returns how many were
 * added, -1 on a bad token */
static int append_entries(const char *step, char *cmd, size_t cap)
{
	const char *p = step;
	size_t len = strlen(cmd);
	int n = 0;

	while ((p = strstr(p, "--entry ")) != NULL) {
		const char *ls = p, *v = p + 8;
		size_t k = 0, j;

		while (ls > step && ls[-1] != '\n')
			ls--;
		while (*ls == ' ' || *ls == '\t')
			ls++;
		if (*ls == '#') {
			p = v;
			continue;
		}
		while (v[k] != '\0' && v[k] != '\n' && v[k] != ' ' && v[k] != '\r')
			k++;
		if (k == 0 || k > 120u) {
			fprintf(stderr, "harness.yml: odd --entry token\n");
			return -1;
		}
		for (j = 0; j < k; j++)
			if (!arg_char(v[j])) {
				fprintf(stderr, "harness.yml: odd character in an --entry token\n");
				return -1;
			}
		if (len + k + 24u >= cap)
			return -1;
		len += (size_t)snprintf(cmd + len, cap - len, " --entry '%.*s'", (int)k, v);
		n++;
		p = v + k;
	}
	return n;
}

/* "--depth N --stack M" of a text: both numbers, 0 when absent */
static int limits_of(const char *text, unsigned *depth, unsigned *stack)
{
	const char *p = strstr(text, "--depth ");

	*depth = *stack = 0;
	if (p == NULL)
		return 0;
	*depth = (unsigned)strtoul(p + 8, NULL, 10);
	p = strstr(p, "--stack ");
	if (p == NULL)
		return 0;
	*stack = (unsigned)strtoul(p + 8, NULL, 10);
	return *depth != 0u && *stack != 0u;
}

static void check_callgraph(void)
{
	char *yml = slurp(".github/workflows/harness.yml");
	char *step = NULL, *first = NULL;
	char cmd[4096], quoted[1100], path[1100], lim[64];
	size_t i, q = 0;
	int rc, n_entry;
	unsigned depth = 0, stack = 0, d0 = 0, s0 = 0;

	WRT_CHECK(yml != NULL);
	if (yml == NULL)
		return;
	need(yml, "harness.yml", SECURE_STEP);
	step = step_text(yml, SECURE_STEP);
	WRT_CHECK(step != NULL);
	if (step == NULL)
		goto out;
	need(step, "the secure-mode step", "check_callgraph.py --cc gcc");
	WRT_CHECK(limits_of(step, &depth, &stack));
	/* the global limits are those of the first measuring step: one pair of numbers for the whole core, written in both places */
	first = step_text(yml, "- name: Measure\n");
	WRT_CHECK(first != NULL);
	if (first != NULL) {
		WRT_CHECK(limits_of(first, &d0, &s0));
		if (d0 != depth || s0 != stack)
			fprintf(stderr, "the global limits of the two measuring steps differ: %u/%u and %u/%u\n", d0, s0, depth, stack);
		WRT_CHECK(d0 == depth && s0 == stack);
	}
	for (i = 0; i < N_ENTRIES; i++) {
		char tok[96];

		snprintf(tok, sizeof(tok), "--entry %s=", entries[i]); /* a budget, not just a report */
		need(step, "the secure-mode step", tok);
	}
	/* the budgets are numbers above zero */
	WRT_CHECK(strstr(step, "=0 ") == NULL && strstr(step, "=0\n") == NULL);

	if (system("python3 --version >/dev/null 2>&1") != 0 || system("gcc --version >/dev/null 2>&1") != 0) {
		fprintf(stderr, "secure.hardening: python3 or gcc not found: the call-graph part is skipped\n");
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
			fprintf(stderr, "secure.hardening: a quote in the path, call-graph part skipped\n");
			goto out;
		}
		quoted[q++] = path[i];
	}
	quoted[q] = '\0';
	snprintf(lim, sizeof(lim), "--depth %u --stack %u", depth, stack);

	/* the chains, exactly as the workflow runs them */
	snprintf(cmd, sizeof(cmd), "python3 -I '%s' --cc gcc %s", quoted, lim);
	n_entry = append_entries(step, cmd, sizeof(cmd));
	WRT_CHECK(n_entry >= (int)N_ENTRIES);
	/* every expected entry is one of the tokens that will run (a mention in a comment, or one entry written twice, is not a budget) */
	for (i = 0; i < N_ENTRIES; i++) {
		char tok[110];

		snprintf(tok, sizeof(tok), " --entry '%s=", entries[i]);
		if (strstr(cmd, tok) == NULL)
			fprintf(stderr, "the secure-mode step has no live '--entry %s=BYTES'\n", entries[i]);
		WRT_CHECK(strstr(cmd, tok) != NULL);
	}
	if (n_entry >= (int)N_ENTRIES) {
		rc = system(cmd);
		if (rc != 0)
			fprintf(stderr, "secure.hardening: the call-graph check of the secure-mode chains failed (status %d): %s\n", rc, cmd);
		WRT_CHECK(rc == 0);
	}
	/* the failing side: a budget of 1 byte fails with 1, an entry that is not in the graph is a tool error, 2 */
	snprintf(cmd, sizeof(cmd), "python3 -I '%s' --cc gcc %s --entry wri_m2s_rx_step=1 >/dev/null 2>&1", quoted, lim);
	rc = system(cmd);
	if (status_of(rc) != 1)
		fprintf(stderr, "secure.hardening: a budget of 1 byte did not fail the call-graph check with status 1 (got %d)\n", rc);
	WRT_CHECK(status_of(rc) == 1);
	snprintf(cmd, sizeof(cmd), "python3 -I '%s' --cc gcc %s --entry wri_no_such_entry=64 >/dev/null 2>&1", quoted, lim);
	rc = system(cmd);
	if (status_of(rc) != 2)
		fprintf(stderr, "secure.hardening: an unknown entry point was not a tool error (status 2) (got %d)\n", rc);
	WRT_CHECK(status_of(rc) == 2);
out:
	free(first);
	free(step);
	free(yml);
}

/* ---- 5: the Valgrind step ----------------------------------------------------------------------------------------- */

static void check_valgrind_step(void)
{
	char *yml = slurp(".github/workflows/harness.yml");
	char *step;

	WRT_CHECK(yml != NULL);
	if (yml == NULL)
		return;
	need(yml, "harness.yml", "ninja-build libssl-dev python3 valgrind "); /* installed with the build dependencies of build-test */
	need(yml, "harness.yml", VG_STEP);
	step = step_text(yml, VG_STEP);
	WRT_CHECK(step != NULL);
	if (step != NULL) {
		need(step, "the Valgrind step", "WRT_CT_REQUIRE: 1");          /* a missing Valgrind is a failure, not a skip */
		need(step, "the Valgrind step", "if: matrix.sanitize == ''"); /* the sanitizer runtimes do not run under Valgrind */
		need(step, "the Valgrind step", "ctest");
		need(step, "the Valgrind step", "crypto\\.ct\\.");
		need(step, "the Valgrind step", "--no-tests=error");
		forbid(step, "the Valgrind step", "continue-on-error");
	}
	free(step);
	free(yml);
}

/* ---- 6: files, names, constants ------------------------------------------------------------------------------- */

static const char *const part_d_files[] = {
	"src/crypto/wri_aesct.c",    "src/crypto/wri_ghash.c",  "src/crypto/wri_gcm.c",       "src/crypto/wri_pgcm.c",
	"src/msgr2/wri_m2_modes.c",  "src/msgr2/wri_m2_sec.c",  "src/msgr2/wri_m2_sec_tx.c",  "src/msgr2/wri_m2_sec_tx2.c",
	"src/msgr2/wri_m2_sec_rx.c", "src/msgr2/wri_m2_sec_rx2.c", "src/msgr2/wri_m2_conn_sec.c", "src/auth/wri_cx_secret.c",
	"src/client/wri_client_modes.c",
};

/* names a core file must not carry (a copied routine, or a comment that points at one). The list is for the crypto and the msgr2 code
 * only: the harness is allowed to name OpenSSL, which it uses as a differential oracle. */
static const char *const forbidden_names[] = {
	"openssl", "boringssl", "libressl", "mbedtls", "mbed tls", "wolfssl", "libgcrypt", "gnutls", "nettle", "cryptopp", "crypto++",
	"tiny-aes", "tinyaes", "bearssl", "rijndael", "libceph", "linux kernel",
};

/* names no text file of the repository may carry: an authorship trailer, or a tool vendor. They are spelled in two pieces so that this file
 * does not contain them itself (the scan below reads this file too). */
static const char *const forbidden_everywhere[] = {
	"cla" "ude", "anthr" "opic", "chat" "gpt", "open" "ai", "copi" "lot", "co-auth" "ored-by",
};

static int lower_find(const char *hay, const char *needle)
{
	size_t n = strlen(needle);

	for (; *hay != '\0'; hay++) {
		size_t i = 0;

		while (i < n && hay[i] != '\0' && (char)tolower((unsigned char)hay[i]) == needle[i])
			i++;
		if (i == n)
			return 1;
	}
	return 0;
}

/* a text file of the repository: the sources, the scripts, the documents, the build files, the workflows */
static int text_name(const char *name)
{
	static const char *const ext[] = {".c", ".h", ".md", ".sh", ".py", ".yml", ".yaml", ".txt", ".cmake", ".example", ".in"};
	size_t len = strlen(name), i;

	for (i = 0; i < sizeof(ext) / sizeof(ext[0]); i++) {
		size_t k = strlen(ext[i]);

		if (len > k && strcmp(name + len - k, ext[i]) == 0)
			return 1;
	}
	return 0;
}

static void scan_one(const char *rel, const char *const *names, size_t n_names)
{
	char *s = slurp(rel);
	size_t i;

	WRT_CHECK(s != NULL);
	if (s == NULL)
		return;
	for (i = 0; i < n_names; i++)
		if (lower_find(s, names[i])) {
			fprintf(stderr, "%s names '%s' (the licence and copying scan)\n", rel, names[i]);
			WRT_CHECK(0);
		}
	free(s);
}

/* every text file under rel (directories whose name has no dot, and ".github"), any depth */
static void scan_dir(const char *rel, const char *const *names, size_t n_names)
{
	char path[1536];
	DIR *d;
	struct dirent *e;

	if (snprintf(path, sizeof(path), "%s/%s", root, rel) >= (int)sizeof(path))
		return;
	d = opendir(path);
	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		char sub[1024];
		char full[1600];
		struct stat st;

		if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0 || strcmp(e->d_name, ".git") == 0 ||
		    snprintf(sub, sizeof(sub), "%s/%s", rel, e->d_name) >= (int)sizeof(sub) ||
		    snprintf(full, sizeof(full), "%s/%s", root, sub) >= (int)sizeof(full) || stat(full, &st) != 0)
			continue;
		if (S_ISDIR(st.st_mode)) {
			/* not the seeds (binary), and not what a build in the tree would add (its files carry the builder's own paths) */
			if (strchr(e->d_name + 1, '.') == NULL && strcmp(e->d_name, "third_party") != 0 && strcmp(e->d_name, "seeds") != 0 &&
			    strncmp(e->d_name, "build", 5) != 0 && strcmp(e->d_name, "CMakeFiles") != 0)
				scan_dir(sub, names, n_names);
		} else if (S_ISREG(st.st_mode) && text_name(e->d_name) && st.st_size <= (1 << 24)) {
			scan_one(sub, names, n_names);
		}
	}
	closedir(d);
}

static void check_files_and_scan(void)
{
	char *src = slurp("core/sources.txt");
	size_t i;
	char rel[256];
	static const char *const ct_files[] = {"wri_aesct.c", "wri_ghash.c", "wri_gcm.c", "wri_pgcm.c"};

	WRT_CHECK(src != NULL);
	if (src != NULL) {
		for (i = 0; i < sizeof(part_d_files) / sizeof(part_d_files[0]); i++) {
			char line[300];

			snprintf(line, sizeof(line), "%s\n", part_d_files[i]);
			if (strstr(src, line) == NULL)
				fprintf(stderr, "core/sources.txt does not list %s\n", part_d_files[i]);
			WRT_CHECK(strstr(src, line) != NULL);
			snprintf(rel, sizeof(rel), "core/%s", part_d_files[i]);
			WRT_CHECK(file_exists(rel));
		}
		free(src);
	}
	scan_dir("core/src", forbidden_names, sizeof(forbidden_names) / sizeof(forbidden_names[0]));
	scan_dir("core/include", forbidden_names, sizeof(forbidden_names) / sizeof(forbidden_names[0]));
	{
		static const char *const trees[] = {"core", "harness", "docs", ".github"};
		static const char *const top[] = {"README.md", "CONTRIBUTING.md"};

		for (i = 0; i < sizeof(trees) / sizeof(trees[0]); i++)
			scan_dir(trees[i], forbidden_everywhere, sizeof(forbidden_everywhere) / sizeof(forbidden_everywhere[0]));
		for (i = 0; i < sizeof(top) / sizeof(top[0]); i++)
			if (file_exists(top[i]))
				scan_one(top[i], forbidden_everywhere, sizeof(forbidden_everywhere) / sizeof(forbidden_everywhere[0]));
	}
	/* the constant-time files carry no AES substitution table: the first bytes of it, in the usual hex and decimal spellings, are not there */
	for (i = 0; i < sizeof(ct_files) / sizeof(ct_files[0]); i++) {
		char *s;
		int has;

		snprintf(rel, sizeof(rel), "core/src/crypto/%s", ct_files[i]);
		s = slurp(rel);
		WRT_CHECK(s != NULL);
		if (s == NULL)
			continue;
		has = lower_find(s, "0x63, 0x7c, 0x77, 0x7b") || lower_find(s, "0x637c777b") || lower_find(s, "0x63,0x7c,0x77,0x7b") ||
		      lower_find(s, "0x63u, 0x7cu, 0x77u, 0x7bu") || lower_find(s, "99, 124, 119, 123") || lower_find(s, "99,124,119,123") ||
		      lower_find(s, "0x7c777bf2") || lower_find(s, "0x7c, 0x77, 0x7b, 0xf2");
		if (has)
			fprintf(stderr, "%s holds the first bytes of the AES substitution table\n", rel);
		WRT_CHECK(!has);
		free(s);
	}
}

/* ---- 7: the design document, the roadmap and the secure-mode note ------------------------------------------------ */

static void check_design_and_roadmap(void)
{
	char *doc = slurp("docs/design/core-architecture.md");
	char *road = slurp("docs/ROADMAP.md");
	char *sec = slurp("docs/spec/msgr2-secure-mode.md");
	const char *s41, *end;
	char *part;
	unsigned i;

	WRT_CHECK(doc != NULL && road != NULL && sec != NULL);
	if (doc == NULL || road == NULL || sec == NULL)
		goto out;
	check_addresses(doc, "core-architecture.md");
	check_addresses(road, "ROADMAP.md");
	check_addresses(sec, "msgr2-secure-mode.md");
	s41 = strstr(doc, "\n### 41.3 ");
	WRT_CHECK(s41 != NULL);
	if (s41 == NULL) {
		fprintf(stderr, "the design document has no section 41.3 (what the finished code measured)\n");
		goto out;
	}
	s41++;
	end = strstr(s41, "\n## ");
	if (end == NULL)
		end = strstr(s41, "\n---");
	if (end == NULL)
		end = s41 + strlen(s41);
	part = (char *)malloc((size_t)(end - s41) + 1u);
	if (part == NULL)
		abort();
	memcpy(part, s41, (size_t)(end - s41));
	part[end - s41] = '\0';
	for (i = 1; i <= 9; i++) {
		char tok[32];

		snprintf(tok, sizeof(tok), "R-D%u ", i);
		need(part, "section 41.3", tok);
	}
	for (i = 1; i <= 7; i++) {
		char tok[32];

		snprintf(tok, sizeof(tok), "Q-D%u ", i);
		need(part, "section 41.3", tok);
	}
	need(part, "section 41.3", "Test suite");
	need(part, "section 41.3", "Footprint");
	need(part, "section 41.3", "Call graph");
	need(part, "section 41.3", "Compile matrix");
	need(part, "section 41.3", "Mechanical gates");
	need(part, "section 41.3", "Fuzzing");
	need(part, "section 41.3", "Constant time");
	need(part, "section 41.3", "Not shown yet");
	free(part);
	/* the roadmap: the two milestones are done and say what showed it (the numbers of the lab runs), in English and in Chinese; the
	 * exit criteria say that Phase 1 is not closed until the long run with the faults has reported. If the evidence is ever taken out
	 * of a row, or a row goes back to a state that the evidence does not support, this fails. */
	need(road, "ROADMAP.md", "| 9 | Comparison with krbd | done");
	need(road, "ROADMAP.md", "| 11 | secure mode | done");
	need(road, "ROADMAP.md", "| 9 | 与 krbd 比对 | 已完成");
	need(road, "ROADMAP.md", "| 11 | secure 模式 | 已完成");
	need(road, "ROADMAP.md", "40,641 operations");
	need(road, "ROADMAP.md", "83,917 operations");
	need(road, "ROADMAP.md", "40,641 次操作");
	need(road, "ROADMAP.md", "83,917 次操作");
	need(road, "ROADMAP.md", "**not closed yet**");
	need(road, "ROADMAP.md", "**尚未收尾**");
	forbid(road, "ROADMAP.md", "| 9 | Comparison with krbd | implemented");
	forbid(road, "ROADMAP.md", "| 11 | secure mode | implemented");
	forbid(road, "ROADMAP.md", "| 9 | 与 krbd 比对 | 已实现");
	forbid(road, "ROADMAP.md", "| 11 | secure 模式 | 已实现");
	forbid(road, "ROADMAP.md", "| 9 | Comparison with krbd | not started");
	forbid(road, "ROADMAP.md", "| 11 | secure mode | not started");
	forbid(road, "ROADMAP.md", "| 11 | secure 模式 | 未开始");
	forbid(road, "ROADMAP.md", "| 9 | 与 krbd 比对 | 未开始");
	/* the secure-mode note: the lab answered 6.4 (the result of a mode mismatch) and 6.5 (a client without compression) */
	need(sec, "msgr2-secure-mode.md", "-95");
	need(sec, "msgr2-secure-mode.md", "EOPNOTSUPP");
	need(sec, "msgr2-secure-mode.md", "harness/vectors/public/secure");
out:
	free(doc);
	free(road);
	free(sec);
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
	check_fuzz_long_options();
	check_callgraph();
	check_valgrind_step();
	check_files_and_scan();
	check_design_and_roadmap();
	return wrt_finish();
}
