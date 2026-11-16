/* SPDX-License-Identifier: MIT */
/*
 * test_core_docs.c - the documents and the CI workflow must say what the tree does.
 *
 * Every check here is a claim that core/README.md, harness/README.md or .github/workflows/harness.yml makes and that
 * used to be checked by nobody:
 *
 *   1. the footprint table of core/README.md (and its Chinese summary line) equals what wr_client_mem_required returns
 *      for the three profiles, and the documented budgets in it are the ones of core_budgets.h;
 *   2. "files stay under about 500 lines": no source or header under core/src is longer than 500 lines;
 *   3. every fuzz target has at least one committed seed (a missing or empty seed directory is an empty corpus, which
 *      the seed-replay test passes without running anything) and is listed in harness/README.md;
 *   4. every ctest name written in backticks in the two READMEs (`util.mem`, `m2.conn.*`, ...) is a test that exists
 *      (test file harness/test/test_<module>_<what>.c is ctest <module>.<what>; CMake turns every underscore into a dot);
 *   5. every source, header, script and build file of the product starts with the MIT SPDX tag (first three lines);
 *   6. the CI workflow keeps its promises: warnings stay errors, the sanitizer, 32-bit, iPXE-flag, header and fuzz
 *      jobs are there, and nothing in it lets a failure pass (continue-on-error).
 *
 * The test reads the source tree through WRT_VECTOR_DIR (<repo>/harness/vectors); without a source tree around it
 * (an installed copy of the harness only) it skips.
 */
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <sys/stat.h>

#include "core_budgets.h"
#include "wr_config.h"
#include "wr_err.h"
#include "wr_client.h"
#include "wrt.h"

#define MAX_LINES 500u

static char root[1024]; /* <repo> */

static void path_of(char *out, size_t cap, const char *rel)
{
	int n = snprintf(out, cap, "%s/%s", root, rel);

	if (n < 0 || (size_t)n >= cap) {
		fprintf(stderr, "path too long: %s\n", rel);
		exit(2);
	}
}

/* the whole file, NUL terminated; NULL if it cannot be read */
static char *slurp(const char *rel, size_t *len_out)
{
	char path[1536];
	FILE *f;
	long n;
	char *buf;
	size_t got;

	path_of(path, sizeof(path), rel);
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
	if (len_out != NULL)
		*len_out = got;
	return buf;
}

static unsigned count_lines(const char *s, size_t n)
{
	unsigned lines = 0;
	size_t i;

	for (i = 0; i < n; i++)
		if (s[i] == '\n')
			lines++;
	if (n != 0 && s[n - 1u] != '\n')
		lines++;
	return lines;
}

static int has_ext(const char *name, const char *ext)
{
	size_t a = strlen(name), b = strlen(ext);

	return a > b && strcmp(name + a - b, ext) == 0;
}

static int is_dir(const char *rel)
{
	char path[1536];
	struct stat st;

	path_of(path, sizeof(path), rel);
	return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Call fn(relpath) for every regular file directly inside dir (relative to the repo root), names sorted out by the caller. */
typedef void (*file_fn)(const char *rel, const char *name, void *arg);

static void each_file(const char *dir, file_fn fn, void *arg)
{
	char path[1536], rel[1536];
	DIR *d;
	struct dirent *e;

	path_of(path, sizeof(path), dir);
	d = opendir(path);
	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		struct stat st;
		char full[2048];

		if (e->d_name[0] == '.')
			continue;
		if (snprintf(rel, sizeof(rel), "%s/%s", dir, e->d_name) >= (int)sizeof(rel))
			continue;
		if (snprintf(full, sizeof(full), "%s/%s", root, rel) >= (int)sizeof(full))
			continue;
		if (stat(full, &st) == 0 && S_ISREG(st.st_mode))
			fn(rel, e->d_name, arg);
	}
	closedir(d);
}

/* ---- 1. the footprint table ---------------------------------------------------------------------- */

static const char *row_of(const char *doc, const char *profile)
{
	char key[96];
	const char *p;

	snprintf(key, sizeof(key), "| `%s` |", profile);
	p = strstr(doc, key);
	return p;
}

static void bulk_budget_text(char *out, size_t cap, size_t bytes)
{
	size_t mib = bytes / (1024u * 1024u), kib = (bytes % (1024u * 1024u)) / 1024u;

	snprintf(out, cap, "%u MiB + %u KiB", (unsigned)mib, (unsigned)kib);
}

static void check_row(const char *doc, const char *profile, void (*fill)(wr_config *), size_t arena_budget,
		      size_t bulk_budget, int product)
{
	wr_config cfg;
	wr_mem_req req;
	char want[256], bb[64];
	const char *row = row_of(doc, profile);
	size_t len;

	fill(&cfg);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	if (product) {
		bulk_budget_text(bb, sizeof(bb), bulk_budget);
		snprintf(want, sizeof(want), "| `%s` | %.0f KiB | %.0f KiB | %u KiB / %s |", profile,
			 (double)req.arena / 1024.0, (double)req.bulk / 1024.0, (unsigned)(arena_budget / 1024u), bb);
	} else {
		snprintf(want, sizeof(want), "| `%s` | %.1f MiB | %.0f MiB | (sanity cap %u MiB / %u MiB) |", profile,
			 (double)req.arena / 1048576.0, (double)req.bulk / 1048576.0,
			 (unsigned)(arena_budget / 1048576u), (unsigned)(bulk_budget / 1048576u));
	}
	WRT_CHECK(row != NULL);
	if (row == NULL) {
		fprintf(stderr, "core/README.md has no footprint row for %s; it should read: %s\n", profile, want);
		return;
	}
	len = strlen(want);
	if (strncmp(row, want, len) != 0) {
		const char *eol = strchr(row, '\n');

		fprintf(stderr, "core/README.md footprint row of %s is stale\n  has:    %.*s\n  should: %s\n", profile,
			eol != NULL ? (int)(eol - row) : 80, row, want);
		WRT_CHECK(0);
	} else {
		WRT_CHECK(1);
	}
}

static void check_footprint(void)
{
	char want[128];
	wr_config cfg;
	wr_mem_req req;
	size_t n;
	char *doc = slurp("core/README.md", &n);

	WRT_CHECK(doc != NULL);
	if (doc == NULL)
		return;
	check_row(doc, "wr_config_profile_ipxe", wr_config_profile_ipxe, WRB_IPXE_ARENA, WRB_IPXE_BULK, 1);
	check_row(doc, "wr_config_profile_kernel", wr_config_profile_kernel, WRB_KERNEL_ARENA, WRB_KERNEL_BULK, 1);
	check_row(doc, "wr_config_profile_harness", wr_config_profile_harness, WRB_HARNESS_ARENA, WRB_HARNESS_BULK, 0);

	/* the one-line summary in the Chinese half */
	wr_config_profile_ipxe(&cfg);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	snprintf(want, sizeof(want), "arena %.0f KiB / bulk %.0f KiB", (double)req.arena / 1024.0, (double)req.bulk / 1024.0);
	WRT_CHECK(strstr(doc, want) != NULL);
	if (strstr(doc, want) == NULL)
		fprintf(stderr, "core/README.md (Chinese summary) should contain: %s\n", want);
	wr_config_profile_kernel(&cfg);
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	snprintf(want, sizeof(want), "%.0f KiB / %.0f KiB", (double)req.arena / 1024.0, (double)req.bulk / 1024.0);
	WRT_CHECK(strstr(doc, want) != NULL);
	if (strstr(doc, want) == NULL)
		fprintf(stderr, "core/README.md (Chinese summary) should contain the kernel numbers: %s\n", want);
	free(doc);
}

/* ---- 2. file sizes --------------------------------------------------------------------------------- */

static void size_one(const char *rel, const char *name, void *arg)
{
	size_t n = 0;
	char *s;
	unsigned lines;

	(void)arg;
	if (!has_ext(name, ".c") && !has_ext(name, ".h"))
		return;
	s = slurp(rel, &n);
	WRT_CHECK(s != NULL);
	if (s == NULL)
		return;
	lines = count_lines(s, n);
	if (lines > MAX_LINES)
		fprintf(stderr, "%s has %u lines; core files stay under about %u (split it)\n", rel, lines, MAX_LINES);
	WRT_CHECK(lines <= MAX_LINES);
	free(s);
}

static void check_sizes(void)
{
	char path[1536];
	DIR *d;
	struct dirent *e;

	path_of(path, sizeof(path), "core/src");
	d = opendir(path);
	WRT_CHECK(d != NULL);
	if (d == NULL)
		return;
	while ((e = readdir(d)) != NULL) {
		char rel[512];

		if (e->d_name[0] == '.')
			continue;
		snprintf(rel, sizeof(rel), "core/src/%s", e->d_name);
		if (is_dir(rel))
			each_file(rel, size_one, NULL);
	}
	closedir(d);
}

/* ---- 3. fuzz targets and their seeds --------------------------------------------------------------- */

static void count_seed(const char *rel, const char *name, void *arg)
{
	(void)rel;
	(void)name;
	(*(unsigned *)arg)++;
}

static void fuzz_one(const char *rel, const char *name, void *arg)
{
	char base[128], seeds[512], tok[160];
	unsigned n = 0;
	size_t len = strlen(name);
	const char *readme = (const char *)arg;

	(void)rel;
	if (strncmp(name, "fuzz_", 5) != 0 || !has_ext(name, ".c") || strcmp(name, "fuzz_replay_main.c") == 0)
		return;
	if (len - 2u >= sizeof(base))
		return;
	memcpy(base, name, len - 2u);
	base[len - 2u] = '\0'; /* fuzz_<target> */
	snprintf(seeds, sizeof(seeds), "harness/fuzz/seeds/%s", base);
	each_file(seeds, count_seed, &n);
	if (n == 0)
		fprintf(stderr, "fuzz target %s has no committed seed in %s\n", base, seeds);
	WRT_CHECK(n >= 1u);
	snprintf(tok, sizeof(tok), "`%s`", base + 5);
	if (strstr(readme, tok) == NULL)
		fprintf(stderr, "harness/README.md does not list the fuzz target %s\n", tok);
	WRT_CHECK(strstr(readme, tok) != NULL);
}

static void check_fuzz(void)
{
	char *readme = slurp("harness/README.md", NULL);

	WRT_CHECK(readme != NULL);
	if (readme == NULL)
		return;
	each_file("harness/fuzz", fuzz_one, readme);
	free(readme);
}

/* ---- 4. ctest names in the READMEs ------------------------------------------------------------------ */

#define MAX_TESTS 256u
static char tests[MAX_TESTS][64];
static unsigned n_tests;

static void test_one(const char *rel, const char *name, void *arg)
{
	char *p;
	size_t len = strlen(name);

	(void)rel;
	(void)arg;
	if (strncmp(name, "test_", 5) != 0 || !has_ext(name, ".c") || n_tests >= MAX_TESTS || len - 7u >= sizeof(tests[0]))
		return;
	memcpy(tests[n_tests], name + 5, len - 7u);
	tests[n_tests][len - 7u] = '\0';
	for (p = tests[n_tests]; *p != '\0'; p++)
		if (*p == '_')
			*p = '.';
	n_tests++;
}

static int test_exists(const char *tok)
{
	size_t len = strlen(tok);
	unsigned i;

	if (len >= 2u && tok[len - 1u] == '*' && tok[len - 2u] == '.') { /* "m2.conn.*": any test below the prefix */
		for (i = 0; i < n_tests; i++)
			if (strncmp(tests[i], tok, len - 1u) == 0)
				return 1;
		return 0;
	}
	for (i = 0; i < n_tests; i++)
		if (strcmp(tests[i], tok) == 0)
			return 1;
	return 0;
}

/* a first segment that names a test module: a token that starts with one is a claim about a test */
static int is_module(const char *tok)
{
	unsigned i;
	size_t seg = strcspn(tok, ".");

	for (i = 0; i < n_tests; i++)
		if (strncmp(tests[i], tok, seg) == 0 && tests[i][seg] == '.')
			return 1;
	return 0;
}

static void check_test_names_in(const char *rel)
{
	char *doc = slurp(rel, NULL);
	const char *p;
	unsigned checked = 0;

	WRT_CHECK(doc != NULL);
	if (doc == NULL)
		return;
	for (p = doc; (p = strchr(p, '`')) != NULL;) {
		const char *q = strchr(p + 1, '`');
		char tok[96];
		size_t len, i;
		int plain;

		if (q == NULL)
			break;
		len = (size_t)(q - p - 1);
		p = q + 1;
		if (len == 0 || len >= sizeof(tok))
			continue;
		memcpy(tok, q - len, len);
		tok[len] = '\0';
		plain = strchr(tok, '.') != NULL;
		for (i = 0; i < len && plain; i++)
			if (!((tok[i] >= 'a' && tok[i] <= 'z') || (tok[i] >= '0' && tok[i] <= '9') || tok[i] == '.' ||
			      (tok[i] == '*' && i + 1u == len)))
				plain = 0;
		if (!plain || !is_module(tok))
			continue;
		checked++;
		if (!test_exists(tok))
			fprintf(stderr, "%s names the test `%s`, which does not exist\n", rel, tok);
		WRT_CHECK(test_exists(tok));
	}
	WRT_CHECK(checked >= 5u); /* the scan found the tables: it did not silently match nothing */
	free(doc);
}

static void check_test_names(void)
{
	each_file("harness/test", test_one, NULL);
	WRT_CHECK(n_tests >= 20u);
	check_test_names_in("core/README.md");
	check_test_names_in("harness/README.md");
}

/* ---- 5. SPDX tags ---------------------------------------------------------------------------------- */

static void spdx_one(const char *rel, const char *name, void *arg)
{
	size_t n = 0, head, i, nl = 0;
	char *s;

	(void)arg;
	if (!has_ext(name, ".c") && !has_ext(name, ".h") && !has_ext(name, ".inc") && !has_ext(name, ".sh") &&
	    !has_ext(name, ".py") && !has_ext(name, ".cmake") && !has_ext(name, ".yml") && strcmp(name, "CMakeLists.txt") != 0)
		return;
	s = slurp(rel, &n);
	WRT_CHECK(s != NULL);
	if (s == NULL)
		return;
	for (head = 0; head < n && nl < 3u; head++)
		if (s[head] == '\n')
			nl++;
	for (i = 0; i + 28u <= head; i++)
		if (memcmp(s + i, "SPDX-License-Identifier: MIT", 28) == 0)
			break;
	if (i + 28u > head)
		fprintf(stderr, "%s has no 'SPDX-License-Identifier: MIT' in its first three lines\n", rel);
	WRT_CHECK(i + 28u <= head);
	free(s);
}

static void check_spdx(void)
{
	static const char *const dirs[] = {
		"core/src/auth", "core/src/client", "core/src/crypto", "core/src/denc", "core/src/mon",
		"core/src/msgr2", "core/src/util", "core/include/winrbd", "core/tools", "harness", "harness/cmake",
		"harness/test", "harness/test/support", "harness/fuzz", "harness/host", "harness/host/tools",
		"harness/tests/ci-docs-hardening", ".github/workflows",
	};
	size_t i;

	for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
		each_file(dirs[i], spdx_one, NULL);
}

/* ---- 6. the workflow ---------------------------------------------------------------------------------- */

static void must_have(const char *doc, const char *what)
{
	if (strstr(doc, what) == NULL)
		fprintf(stderr, ".github/workflows/harness.yml has no '%s'\n", what);
	WRT_CHECK(strstr(doc, what) != NULL);
}

static void must_not_have(const char *doc, const char *what)
{
	if (strstr(doc, what) != NULL)
		fprintf(stderr, ".github/workflows/harness.yml must not contain '%s'\n", what);
	WRT_CHECK(strstr(doc, what) == NULL);
}

static void check_workflow(void)
{
	char *doc = slurp(".github/workflows/harness.yml", NULL);

	WRT_CHECK(doc != NULL);
	if (doc == NULL)
		return;
	must_have(doc, "-DWR_SANITIZE=");           /* the sanitizer flavours */
	must_have(doc, "wr_core_m32");              /* 32-bit */
	must_have(doc, "wr_core_ipxe_flags");       /* the iPXE warning set */
	must_have(doc, "wr_header_check");
	must_have(doc, "-DWR_FUZZ=ON");
	must_have(doc, "harness/fuzz/seeds/");
	must_have(doc, "ctest --test-dir");
	must_have(doc, "permissions:");             /* least privilege */
	must_not_have(doc, "continue-on-error");    /* a red job must stay red */
	must_not_have(doc, "WR_WERROR=OFF");        /* warnings stay errors */
	must_not_have(doc, "--no-tests=ignore");    /* a ctest that finds nothing must fail */
	must_not_have(doc, "pull_request_target");  /* never run a fork's code with the repository's secrets */
	free(doc);
}

int main(void)
{
	char probe[1536];
	struct stat st;

	snprintf(root, sizeof(root), "%s/../..", WRT_VECTOR_DIR);
	snprintf(probe, sizeof(probe), "%s/core/README.md", root);
	if (stat(probe, &st) != 0)
		WRT_SKIP("no source tree around the harness (core/README.md not found)");

	check_footprint();
	check_sizes();
	check_fuzz();
	check_test_names();
	check_spdx();
	check_workflow();
	return wrt_finish();
}
