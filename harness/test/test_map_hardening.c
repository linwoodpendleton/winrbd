/* SPDX-License-Identifier: MIT */
/*
 * test_map_hardening.c - the hardening of part B (OSD map, CRUSH, placement) must stay wired into CI and the docs.
 *
 * Fuzz targets, seeds and static limits do their work only while something runs them. Each check here is one way that
 * could silently stop:
 *
 *   1. the five part B fuzz targets (crush_dec, crush_map, osdmap_full, osdmap_inc, mapstore) exist, each with committed
 *      seeds (the seed replay would pass an empty directory without running anything), and the CI smoke job names them,
 *      so that a target dropped from the build turns the job red instead of shortening it;
 *   2. harness/tools/fuzz_long.sh knows the preset that runs exactly these five;
 *   3. harness/README.md and core/README.md mention every one of them (the long-run table of the hardening section);
 *      and no committed seed of them is larger than the input cap (-max_len=65536) of the smoke job and of
 *      fuzz_long.sh: libFuzzer cuts a bigger input, so the seed would be replayed by ctest but fuzzed damaged;
 *   4. the call-graph check of the CI job static-limits passes with the same budgets the workflow passes: the --entry
 *      arguments are read out of .github/workflows/harness.yml, so the workflow and this test cannot drift apart.
 *      The workflow must pass the global limits this test documents (14 frames, 3,328 bytes) and name every part B entry
 *      point; a workflow that loosened a limit or dropped a budget would otherwise leave this test green.
 *      The budget machinery itself is checked from the failing side too: a budget of 1 byte must fail the check with
 *      status 1 and an entry point that does not exist must be a tool error (status 2), so neither can turn into a pass.
 *      It compiles the core with gcc and needs python3; without them the part is skipped by name, not hidden.
 *
 * The test reads the source tree through WRT_VECTOR_DIR (<repo>/harness/vectors); without a source tree it skips.
 */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "wrt.h"

static const char *const targets[] = {"fuzz_crush_dec", "fuzz_crush_map", "fuzz_osdmap_full", "fuzz_osdmap_inc",
				      "fuzz_mapstore"};
#define N_TARGETS (sizeof(targets) / sizeof(targets[0]))

/* the entry points whose own stack budget the workflow must pass (core/README.md, "No recursion") */
static const char *const entries[] = {"wr_client_map_target", "wri_mapstore_step", "wri_osdmap_decode_full",
				      "wri_osdmap_apply_inc", "wri_crush_decode", "wri_crush_do_rule"};
#define N_ENTRIES (sizeof(entries) / sizeof(entries[0]))

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

/* number of regular files directly in a directory of the tree */
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

/* size of the largest regular file directly in a directory of the tree */
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

static void check_targets_and_docs(void)
{
	char *yml = slurp(".github/workflows/harness.yml");
	char *lng = slurp("harness/tools/fuzz_long.sh");
	char *hr = slurp("harness/README.md");
	char *cr = slurp("core/README.md");
	size_t i;
	char rel[256], tick[64];

	WRT_CHECK(yml != NULL && lng != NULL && hr != NULL && cr != NULL);
	if (yml == NULL || lng == NULL || hr == NULL || cr == NULL)
		goto out;
	need(lng, "fuzz_long.sh", "partb");
	need(yml, "harness.yml", "The part B targets exist and have seeds");
	need(yml, "harness.yml", "-max_len=65536");
	need(lng, "fuzz_long.sh", "-max_len=65536");
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
	}
out:
	free(yml);
	free(lng);
	free(hr);
	free(cr);
}

/* the "--entry name=bytes" arguments of the static-limits job, appended to cmd (at most cap bytes) */
static int entries_of(const char *yml, char *cmd, size_t cap)
{
	const char *p = yml;
	int n = 0;
	size_t len = strlen(cmd);

	while ((p = strstr(p, "--entry ")) != NULL) {
		size_t k = 0;
		const char *ls = p;

		while (ls > yml && ls[-1] != '\n')
			ls--;
		while (*ls == ' ' || *ls == '\t')
			ls++;
		p += 8;
		if (*ls == '#') /* a comment that talks about the option */
			continue;
		while (p[k] != '\0' && p[k] != '\n' && p[k] != ' ' && p[k] != '\r')
			k++;
		/* only plain name=digits tokens go into a shell command */
		{
			size_t j;
			int ok = k > 2u && k < 80u;

			for (j = 0; j < k && ok; j++)
				ok = (p[j] >= 'a' && p[j] <= 'z') || (p[j] >= '0' && p[j] <= '9') || p[j] == '_' || p[j] == '=';
			if (!ok) {
				fprintf(stderr, "harness.yml: odd --entry token\n");
				WRT_CHECK(ok);
				return -1;
			}
			if (len + k + 10u >= cap)
				return -1;
			len += (size_t)snprintf(cmd + len, cap - len, " --entry %.*s", (int)k, p);
			n++;
		}
		p += k;
	}
	return n;
}

static void check_callgraph(void)
{
	char *yml = slurp(".github/workflows/harness.yml");
	char cmd[2048], quoted[1100];
	int n, rc;
	size_t i, q = 0;
	char path[1100];

	WRT_CHECK(yml != NULL);
	if (yml == NULL)
		return;
	if (system("python3 --version >/dev/null 2>&1") != 0 || system("gcc --version >/dev/null 2>&1") != 0) {
		fprintf(stderr, "map.hardening: python3 or gcc not found: the call-graph part is skipped\n");
		free(yml);
		return;
	}
	if (!file_exists("harness/tests/ci-docs-hardening/check_callgraph.py")) {
		fprintf(stderr, "check_callgraph.py is missing\n");
		WRT_CHECK(0);
		free(yml);
		return;
	}
	snprintf(path, sizeof(path), "%s/harness/tests/ci-docs-hardening/check_callgraph.py", root);
	/* the repository path goes into a shell command: single-quote it and refuse a quote inside it */
	for (i = 0; path[i] != '\0' && q + 2u < sizeof(quoted); i++) {
		if (path[i] == '\'') {
			fprintf(stderr, "map.hardening: a quote in the path, call-graph part skipped\n");
			free(yml);
			return;
		}
		quoted[q++] = path[i];
	}
	quoted[q] = '\0';
	need(yml, "harness.yml", "check_callgraph.py --cc gcc --depth 14 --stack 3328");
	for (i = 0; i < N_ENTRIES; i++) {
		char tok[96];

		snprintf(tok, sizeof(tok), "--entry %s=", entries[i]); /* a budget, not just a report */
		need(yml, "harness.yml", tok);
	}
	snprintf(cmd, sizeof(cmd), "python3 -I '%s' --cc gcc --depth 14 --stack 3328", quoted);
	n = entries_of(yml, cmd, sizeof(cmd));
	WRT_CHECK(n >= (int)N_ENTRIES); /* the workflow carries the budgets of the part B entry points */
	if (n >= (int)N_ENTRIES) {
		rc = system(cmd);
		if (rc != 0)
			fprintf(stderr, "map.hardening: the call-graph check failed (status %d): %s\n", rc, cmd);
		WRT_CHECK(rc == 0);
	}
	/* the failing side: the global limits plus one hostile --entry each (the output is of no interest) */
	snprintf(cmd, sizeof(cmd), "python3 -I '%s' --cc gcc --depth 14 --stack 3328 --entry wri_crush_do_rule=1 >/dev/null 2>&1", quoted);
	rc = system(cmd);
	if (!(WIFEXITED(rc) && WEXITSTATUS(rc) == 1))
		fprintf(stderr, "map.hardening: a budget of 1 byte did not fail the call-graph check with status 1 (got %d)\n", rc);
	WRT_CHECK(WIFEXITED(rc) && WEXITSTATUS(rc) == 1);
	snprintf(cmd, sizeof(cmd), "python3 -I '%s' --cc gcc --depth 14 --stack 3328 --entry wri_no_such_entry=64 >/dev/null 2>&1", quoted);
	rc = system(cmd);
	if (!(WIFEXITED(rc) && WEXITSTATUS(rc) == 2))
		fprintf(stderr, "map.hardening: an unknown entry point was not a tool error (status 2) (got %d)\n", rc);
	WRT_CHECK(WIFEXITED(rc) && WEXITSTATUS(rc) == 2);
	free(yml);
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
	return wrt_finish();
}
