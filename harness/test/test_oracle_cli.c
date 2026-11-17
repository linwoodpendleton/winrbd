/* SPDX-License-Identifier: MIT */
/*
 * test_oracle_cli.c - the wr-maporacle tool (harness/oracle/) against the committed ground truth, byte for byte.
 *
 * The tool is run as a program (its path is in $WR_MAPORACLE, set by the build) and its standard output is compared with
 * what Ceph's own tools printed for the same input:
 *
 *   text captured from the lab, used as it is
 *     public/gt/crushtool-tests/rule*.txt   crushtool --test --show-mappings: 8 runs x 10,000 mappings (two with --pool-id)
 *     public/gt/osdmaptool-test-map-pgs-dump-all.pool{1,2}.txt   the PG lines of osdmaptool --test-map-pgs-dump-all
 *     public/gt/osd-map-text-*.txt      ceph osd map, one line per command (also a namespaced object)
 *   tables captured as JSON, rendered here into the same text and then compared
 *     public/mapb/names/names-e709.json the name oracle: 3,352 (pool, name, namespace) rows over 8 pools, at one epoch
 *     public/mapb/states/ (all files)  every state of architecture 18.3: raw / up / acting of every PG, reached both by
 *                                       applying the incrementals to the epoch-666 map and (where there is one) from the
 *                                       monitor's full map of that epoch
 *     public/mapb/offline/ (.pgs.json) eight osdmaptool-made maps with every bucket algorithm
 *     public/mapb/crush/ (.mappings.json) crushtool runs of the 18 offline CRUSH maps (weights 0 and 0.5)
 *
 * and the behaviour of the tool itself: --dump-state of an applied chain equals the dump of the monitor's full map of the
 * same epoch, --epoch stops where asked, the escaping of odd bytes, a locator key, usage and fatal errors with their exit
 * statuses, an unsupported pool as an ERROR line (exit 3), a damaged map named by its CRC. A pool or rule this client does
 * not serve (erasure, indep, tree) is counted as skipped, and the totals are asserted so a skip cannot hide a data set.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdarg.h>
#include <sys/wait.h>
#include <unistd.h>

#include "wrt.h"
#include "wri_place.h"

/* ---- a growing text buffer ---------------------------------------------------------------------------- */

typedef struct buf {
	char *p;
	size_t n, cap;
} buf;

static void buf_reserve(buf *b, size_t more)
{
	if (b->n + more + 1u > b->cap) {
		size_t nc = b->cap ? b->cap : 4096u;

		while (nc < b->n + more + 1u)
			nc *= 2u;
		b->p = (char *)realloc(b->p, nc);
		if (b->p == NULL) {
			fprintf(stderr, "out of memory\n");
			exit(2);
		}
		b->cap = nc;
	}
}

static void buf_add(buf *b, const char *s, size_t n)
{
	buf_reserve(b, n);
	memcpy(b->p + b->n, s, n);
	b->n += n;
	b->p[b->n] = '\0';
}

#if defined(__GNUC__) || defined(__clang__)
#define PRINTF_LIKE __attribute__((format(printf, 2, 3)))
#else
#define PRINTF_LIKE
#endif

static void bprintf(buf *b, const char *fmt, ...) PRINTF_LIKE;
static void bprintf(buf *b, const char *fmt, ...)
{
	char tmp[1024];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(tmp)) {
		fprintf(stderr, "bprintf: line too long\n");
		exit(2);
	}
	buf_add(b, tmp, (size_t)n);
}

static void buf_free(buf *b)
{
	free(b->p);
	memset(b, 0, sizeof(*b));
}

static void buf_clear(buf *b)
{
	b->n = 0;
	if (b->p != NULL)
		b->p[0] = '\0';
}

/* The escaping the tool uses for object names: printable ASCII as it is, backslash doubled, anything else \xHH. */
static void put_escaped(buf *b, const uint8_t *s, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (s[i] == '\\')
			buf_add(b, "\\\\", 2);
		else if (s[i] >= 0x20u && s[i] <= 0x7eu)
			buf_add(b, (const char *)&s[i], 1);
		else
			bprintf(b, "\\x%02x", (unsigned)s[i]);
	}
}

/* ---- running the tool ---------------------------------------------------------------------------------- */

static const char *g_tool;

static void quote_add(buf *cmd, const char *a)
{
	const char *c;

	buf_add(cmd, " '", 2);
	for (c = a; *c; c++) {
		if (*c == '\'')
			buf_add(cmd, "'\\''", 4);
		else
			buf_add(cmd, c, 1);
	}
	buf_add(cmd, "'", 1);
}

/*
 * Run the tool with NULL-terminated `args`: stdout goes to `out` (stderr too when merge_err, else it is discarded).
 * Returns the exit status of the tool, or -1 when it did not exit normally.
 */
static int run_tool(const char *const *args, int merge_err, buf *out)
{
	buf cmd;
	FILE *f;
	char chunk[65536];
	size_t got;
	int st, i;

	memset(&cmd, 0, sizeof(cmd));
	quote_add(&cmd, g_tool);
	for (i = 0; args[i] != NULL; i++)
		quote_add(&cmd, args[i]);
	buf_add(&cmd, merge_err ? " 2>&1" : " 2>/dev/null", merge_err ? 5u : 12u);
	buf_clear(out);
	buf_add(out, "", 0);
	f = popen(cmd.p, "r");
	buf_free(&cmd);
	if (f == NULL) {
		WRT_CHECK(0);
		return -1;
	}
	while ((got = fread(chunk, 1, sizeof(chunk), f)) > 0)
		buf_add(out, chunk, got);
	st = pclose(f);
	if (st == -1 || !WIFEXITED(st))
		return -1;
	return WEXITSTATUS(st);
}

/* Compare two texts line by line; on a difference print the first one and fail once. Returns 1 when equal. */
static int same_text(const char *what, const buf *got, const buf *want)
{
	size_t i = 0, line = 1, ls = 0;

	wrt_checks++;
	if (got->n == want->n && (got->n == 0 || memcmp(got->p, want->p, got->n) == 0))
		return 1;
	while (i < got->n && i < want->n && got->p[i] == want->p[i]) {
		if (got->p[i] == '\n') {
			line++;
			ls = i + 1u;
		}
		i++;
	}
	{
		size_t ge = ls, we = ls;

		while (ge < got->n && got->p[ge] != '\n')
			ge++;
		while (we < want->n && want->p[we] != '\n')
			we++;
		wrt_failures++;
		fprintf(stderr, "%s:%d: %s: output differs at line %zu (got %zu bytes, want %zu)\n  got : %.*s\n  want: %.*s\n", __FILE__, __LINE__, what, line,
			got->n, want->n, (int)(ge - ls > 400 ? 400 : ge - ls), got->p + ls, (int)(we - ls > 400 ? 400 : we - ls), want->p + ls);
	}
	return 0;
}

/* ---- reading JSON vectors --------------------------------------------------------------------------------- */

static int64_t jint(const wrt_json *j, wrt_tok t)
{
	int ok = 0;
	int64_t v = wrt_json_int(j, t, &ok);

	WRT_CHECK(ok);
	return v;
}

static void put_jlist(buf *b, const wrt_json *j, wrt_tok arr)
{
	size_t i, n = wrt_json_count(j, arr);

	buf_add(b, "[", 1);
	for (i = 0; i < n; i++)
		bprintf(b, "%s%d", i ? "," : "", (int)jint(j, wrt_json_at(j, arr, i)));
	buf_add(b, "]", 1);
}

static int64_t jlist_first(const wrt_json *j, wrt_tok arr)
{
	return wrt_json_count(j, arr) ? jint(j, wrt_json_at(j, arr, 0)) : -1;
}

/* "<pool>.<hex>" -> pool id and seed. */
static int parse_pgid(const char *s, int64_t *pool, uint32_t *seed)
{
	char *end = NULL;
	long long p = strtoll(s, &end, 10);
	unsigned long long x;

	if (end == s || *end != '.')
		return -1;
	x = strtoull(end + 1, &end, 16);
	if (*end != '\0')
		return -1;
	*pool = (int64_t)p;
	*seed = (uint32_t)x;
	return 0;
}

/* strdup is not ISO C99: a tiny copy */
static char *dup_str(const char *s)
{
	size_t n = strlen(s);
	char *p = (char *)malloc(n + 1u);

	if (p == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	memcpy(p, s, n + 1u);
	return p;
}

/* A path under harness/vectors, copied (wrt_vec_path has one static buffer). */
static char *vpath(const char *rel)
{
	return dup_str(wrt_vec_path(rel));
}

static char *vpath2(const char *dir, const char *rel)
{
	char tmp[512];

	snprintf(tmp, sizeof(tmp), "%s%s", dir, rel);
	return vpath(tmp);
}

/* ---- ground truth that is plain text ------------------------------------------------------------------------ */

static int read_text(const char *path, buf *out)
{
	uint8_t *p = NULL;
	size_t n = 0;

	if (wrt_read_file(path, &p, &n) != 0)
		return -1;
	buf_clear(out);
	buf_add(out, (const char *)p, n);
	free(p);
	return 0;
}

/* The lines of `in` that start like a PG line "<digits>.<hex> raw" (osdmaptool's headers and statistics are dropped). */
static void keep_pg_lines(const buf *in, buf *out)
{
	size_t i = 0;

	buf_clear(out);
	while (i < in->n) {
		size_t e = i, k = i;

		while (e < in->n && in->p[e] != '\n')
			e++;
		while (k < e && in->p[k] >= '0' && in->p[k] <= '9')
			k++;
		if (k > i && k < e && in->p[k] == '.') {
			size_t q = k + 1u;

			while (q < e && ((in->p[q] >= '0' && in->p[q] <= '9') || (in->p[q] >= 'a' && in->p[q] <= 'f')))
				q++;
			if (q > k + 1u && e - q >= 4u && memcmp(in->p + q, " raw", 4) == 0) {
				buf_add(out, in->p + i, e - i);
				buf_add(out, "\n", 1);
			}
		}
		i = e + 1u;
	}
}

static void test_gt_crushtool(void)
{
	static const struct {
		const char *file;
		const char *rule;
		const char *rep;
		const char *pool; /* NULL: none */
	} runs[] = {
		{"rule0.rep1.x0-9999.txt", "0", "1", NULL},          {"rule0.rep2.x0-9999.txt", "0", "2", NULL},
		{"rule0.rep3.x0-9999.txt", "0", "3", NULL},          {"rule0.rep2.x0-9999.pool1.txt", "0", "2", "1"},
		{"rule1.rep1.x0-9999.txt", "1", "1", NULL},          {"rule1.rep2.x0-9999.txt", "1", "2", NULL},
		{"rule1.rep3.x0-9999.txt", "1", "3", NULL},          {"rule1.rep3.x0-9999.pool2.txt", "1", "3", "2"},
	};
	char *crush = vpath("public/gt/crush.bin");
	size_t i;
	buf want, got;

	memset(&want, 0, sizeof(want));
	memset(&got, 0, sizeof(got));
	for (i = 0; i < sizeof(runs) / sizeof(runs[0]); i++) {
		char rel[256];
		char *f;
		const char *args[16];
		unsigned k = 0;
		int rc;

		snprintf(rel, sizeof(rel), "public/gt/crushtool-tests/%s", runs[i].file);
		f = vpath(rel);
		if (read_text(f, &want) != 0) {
			WRT_CHECK(0);
			free(f);
			continue;
		}
		args[k++] = "--crush";
		args[k++] = crush;
		args[k++] = "--rule";
		args[k++] = runs[i].rule;
		args[k++] = "--num-rep";
		args[k++] = runs[i].rep;
		args[k++] = "--min-x";
		args[k++] = "0";
		args[k++] = "--max-x";
		args[k++] = "9999";
		if (runs[i].pool != NULL) {
			args[k++] = "--pool-id";
			args[k++] = runs[i].pool;
		}
		args[k] = NULL;
		rc = run_tool(args, 0, &got);
		WRT_CHECK_U64(rc, 0);
		WRT_CHECK_U64(want.n > 100000u, 1);
		(void)same_text(runs[i].file, &got, &want);
		free(f);
	}
	free(crush);
	buf_free(&want);
	buf_free(&got);
}

static void test_gt_osdmaptool(void)
{
	static const struct {
		const char *file, *pool;
	} runs[] = {{"public/gt/osdmaptool-test-map-pgs-dump-all.pool1.txt", ".mgr"}, {"public/gt/osdmaptool-test-map-pgs-dump-all.pool2.txt", "winrbd"}};
	char *map = vpath("public/gt/osdmap.bin");
	size_t i;
	buf raw, want, got;

	memset(&raw, 0, sizeof(raw));
	memset(&want, 0, sizeof(want));
	memset(&got, 0, sizeof(got));
	for (i = 0; i < 2; i++) {
		char *f = vpath(runs[i].file);
		const char *args[] = {"--map", map, "--pool", runs[i].pool, "--dump-pgs", NULL};
		int rc;

		WRT_CHECK(read_text(f, &raw) == 0);
		keep_pg_lines(&raw, &want);
		WRT_CHECK(want.n > 20u);
		rc = run_tool(args, 0, &got);
		WRT_CHECK_U64(rc, 0);
		(void)same_text(runs[i].file, &got, &want);
		free(f);
	}
	free(map);
	buf_free(&raw);
	buf_free(&want);
	buf_free(&got);
}

/* "$ ceph osd map POOL OBJ [(nspace NS)]" followed by the answer line. */
static void test_gt_ceph_osd_map(void)
{
	static const char *const files[] = {"public/gt/osd-map-text-winrbd.txt", "public/gt/osd-map-text-mgr.txt"};
	char *map = vpath("public/gt/osdmap.bin");
	size_t fi;
	unsigned total = 0;
	buf txt, got, want;

	memset(&txt, 0, sizeof(txt));
	memset(&got, 0, sizeof(got));
	memset(&want, 0, sizeof(want));
	for (fi = 0; fi < 2; fi++) {
		char *f = vpath(files[fi]);
		size_t i = 0;

		WRT_CHECK(read_text(f, &txt) == 0);
		free(f);
		while (i < txt.n) {
			size_t e = i, q;
			char line[512];

			while (e < txt.n && txt.p[e] != '\n')
				e++;
			if (e - i > 8u && e - i < sizeof(line) && memcmp(txt.p + i, "$ ceph osd map ", 15) == 0) {
				char pool[128], obj[256], ns[128];
				size_t ne;
				int n;

				memcpy(line, txt.p + i + 15, e - i - 15u);
				line[e - i - 15u] = '\0';
				ns[0] = '\0';
				n = sscanf(line, "%127s %255s (nspace %127[^)])", pool, obj, ns);
				ne = e + 1u;
				q = ne;
				while (q < txt.n && txt.p[q] != '\n')
					q++;
				WRT_CHECK(n >= 2);
				if (n >= 2 && ne < txt.n) {
					const char *args[12];
					unsigned k = 0;

					args[k++] = "--map";
					args[k++] = map;
					args[k++] = "--pool";
					args[k++] = pool;
					args[k++] = "--object-str";
					args[k++] = obj;
					if (n == 3) {
						args[k++] = "--ns-str";
						args[k++] = ns;
					}
					args[k] = NULL;
					buf_clear(&want);
					buf_add(&want, txt.p + ne, q - ne + 1u);
					WRT_CHECK_U64(run_tool(args, 0, &got), 0);
					(void)same_text(line, &got, &want);
					total++;
					i = q + 1u;
					continue;
				}
			}
			i = e + 1u;
		}
	}
	WRT_CHECK_U64(total, 12); /* ten commands on winrbd (one namespaced) and two on .mgr */
	fprintf(stderr, "ceph osd map text: %u commands compared\n", total);
	free(map);
	buf_free(&txt);
	buf_free(&got);
	buf_free(&want);
}

/* ---- the name oracle ----------------------------------------------------------------------------------------- */

static void test_name_oracle(void)
{
	wrt_json j;
	wrt_tok pools, rows;
	size_t np, nr, i;
	char *names[8];
	int64_t ids[8];
	char tmpl[] = "/tmp/wr_oracle_cli_XXXXXX";
	int fd;
	FILE *bf;
	buf want, got;
	const char *args[40];
	unsigned k = 0, too_big = 0;
	char *base = vpath("public/mapb/base-e666.hex"), *incs = vpath("public/mapb/incrementals.hex"), *full = vpath("public/mapb/maps/e709.hex");

	memset(&want, 0, sizeof(want));
	memset(&got, 0, sizeof(got));
	WRT_CHECK(wrt_json_load_vec(&j, "public/mapb/names/names-e709.json") == 0);
	pools = wrt_json_get(&j, wrt_json_root(&j), "pools");
	rows = wrt_json_get(&j, wrt_json_root(&j), "entries");
	np = wrt_json_count(&j, pools);
	nr = wrt_json_count(&j, rows);
	WRT_CHECK_U64(np, 8);
	WRT_CHECK_U64(nr, 3352);
	if (np != 8u || nr != 3352u) {
		wrt_json_free(&j);
		return;
	}
	for (i = 0; i < np; i++) {
		wrt_tok v;
		const char *key = wrt_json_key_at(&j, pools, i, &v);

		ids[i] = (int64_t)atoll(key);
		names[i] = wrt_json_strdup(&j, wrt_json_get(&j, v, "name"));
	}
	fd = mkstemp(tmpl);
	WRT_CHECK(fd >= 0);
	if (fd < 0) {
		wrt_json_free(&j);
		return;
	}
	bf = fdopen(fd, "w");
	for (i = 0; i < nr; i++) {
		wrt_tok r = wrt_json_at(&j, rows, i);
		int64_t pid = jint(&j, wrt_json_at(&j, r, 0));
		char *oh = wrt_json_strdup(&j, wrt_json_at(&j, r, 1)), *nh = wrt_json_strdup(&j, wrt_json_at(&j, r, 2));
		uint8_t *ob = NULL, *nb = NULL;
		size_t on = 0, nn = 0, p;
		int64_t raw_ps = jint(&j, wrt_json_at(&j, r, 3));
		char *pgid = wrt_json_strdup(&j, wrt_json_at(&j, r, 4));
		const char *pname = NULL;

		for (p = 0; p < np; p++)
			if (ids[p] == pid)
				pname = names[p];
		WRT_CHECK(pname != NULL);
		WRT_CHECK(wrt_hex_decode(oh, strlen(oh), &ob, &on) == 0 && wrt_hex_decode(nh, strlen(nh), &nb, &nn) == 0);
		fprintf(bf, "%s %s %s\n", pname, on ? oh : "-", nn ? nh : "-");
		bprintf(&want, "osdmap e709 pool '%s' (%d) object '", pname, (int)pid);
		if (nn) {
			put_escaped(&want, nb, nn);
			buf_add(&want, "/", 1);
		}
		put_escaped(&want, ob, on);
		if (on + nn > WRI_PLACE_NAME_MAX) {
			/* Ceph hashes a name of 4,096 bytes plus a namespace; the core refuses more than 4,096 bytes in all (wri_place.h) */
			buf_add(&want, "' -> ERROR WR_E_TOOBIG\n", 23);
			too_big++;
		} else {
			bprintf(&want, "' -> pg %d.%x (%s) -> up (", (int)pid, (unsigned)raw_ps, pgid);
			put_jlist(&want, &j, wrt_json_at(&j, r, 5));
			bprintf(&want, ", p%d) acting (", (int)jint(&j, wrt_json_at(&j, r, 6)));
			put_jlist(&want, &j, wrt_json_at(&j, r, 7));
			bprintf(&want, ", p%d)\n", (int)jint(&j, wrt_json_at(&j, r, 8)));
		}
		free(oh);
		free(nh);
		free(ob);
		free(nb);
		free(pgid);
	}
	fclose(bf);
	/* from the monitor's full map of epoch 709 */
	args[k++] = "--map";
	args[k++] = full;
	args[k++] = "--names";
	args[k++] = tmpl;
	for (i = 0; i < np; i++) {
		args[k++] = "--pool";
		args[k++] = names[i];
	}
	args[k] = NULL;
	WRT_CHECK_U64(too_big > 0u, 1);
	WRT_CHECK_U64(run_tool(args, 1, &got), 3);
	(void)same_text("name oracle, full map e709", &got, &want);
	/* and from the epoch-666 map with the incrementals applied up to 709 */
	k = 0;
	args[k++] = "--map";
	args[k++] = base;
	args[k++] = "--apply-inc";
	args[k++] = incs;
	args[k++] = "--epoch";
	args[k++] = "709";
	args[k++] = "--names";
	args[k++] = tmpl;
	for (i = 0; i < np; i++) {
		args[k++] = "--pool";
		args[k++] = names[i];
	}
	args[k] = NULL;
	WRT_CHECK_U64(run_tool(args, 1, &got), 3);
	(void)same_text("name oracle, chain to e709", &got, &want);
	fprintf(stderr, "name oracle: %zu names over %zu pools compared twice (%u of them above the core's 4,096-byte limit: ERROR WR_E_TOOBIG)\n", nr, np, too_big);
	unlink(tmpl);
	for (i = 0; i < np; i++)
		free(names[i]);
	wrt_json_free(&j);
	buf_free(&want);
	buf_free(&got);
	free(base);
	free(incs);
	free(full);
}

/* ---- tables of PGs: the states, the offline maps ------------------------------------------------------------ */

typedef struct pgent {
	uint32_t seed;
	wrt_tok val;
} pgent;

static int pgent_cmp(const void *a, const void *b)
{
	const pgent *x = (const pgent *)a, *y = (const pgent *)b;

	return x->seed < y->seed ? -1 : (x->seed > y->seed ? 1 : 0);
}

/* The PG lines of pool `pool` of a table {"<pool>.<seed>": [raw, up, up_primary, acting, acting_primary]} in osdmaptool's format. */
static unsigned render_table(buf *out, const wrt_json *j, wrt_tok pgs, int64_t pool)
{
	size_t i, n = wrt_json_count(j, pgs), m = 0;
	pgent *v = (pgent *)malloc((n ? n : 1u) * sizeof(*v));
	unsigned lines = 0;

	buf_clear(out);
	for (i = 0; i < n; i++) {
		wrt_tok val;
		const char *key = wrt_json_key_at(j, pgs, i, &val);
		int64_t p;
		uint32_t s;

		if (parse_pgid(key, &p, &s) != 0) {
			WRT_CHECK(0);
			continue;
		}
		if (p == pool) {
			v[m].seed = s;
			v[m].val = val;
			m++;
		}
	}
	qsort(v, m, sizeof(*v), pgent_cmp);
	for (i = 0; i < m; i++) {
		wrt_tok raw = wrt_json_at(j, v[i].val, 0), up = wrt_json_at(j, v[i].val, 1), act = wrt_json_at(j, v[i].val, 3);

		bprintf(out, "%d.%x raw (", (int)pool, (unsigned)v[i].seed);
		put_jlist(out, j, raw);
		bprintf(out, ", p%d) up (", (int)jlist_first(j, raw));
		put_jlist(out, j, up);
		bprintf(out, ", p%d) acting (", (int)jint(j, wrt_json_at(j, v[i].val, 2)));
		put_jlist(out, j, act);
		bprintf(out, ", p%d)\n", (int)jint(j, wrt_json_at(j, v[i].val, 4)));
		lines++;
	}
	free(v);
	return lines;
}

typedef struct tally {
	unsigned runs, skipped_pools, resyncs, pgs;
} tally;

/* One tool run for one pool, compared with the rendered table. A pool the client cannot serve is a skip. */
static void compare_pool(tally *t, const char *label, const char *const *base_args, const char *pool_name, const buf *want, unsigned lines)
{
	const char *args[24];
	unsigned k = 0;
	buf got;
	int rc;

	memset(&got, 0, sizeof(got));
	while (base_args[k] != NULL) {
		args[k] = base_args[k];
		k++;
	}
	args[k++] = "--pool";
	args[k++] = pool_name;
	args[k++] = "--dump-pgs";
	args[k] = NULL;
	rc = run_tool(args, 1, &got);
	if (rc == 3 && got.n > 5u && memcmp(got.p, "pool ", 5) == 0 &&
	    (strstr(got.p, " ERROR WR_E_POOL_UNSUPPORTED") != NULL || strstr(got.p, " ERROR WR_E_CRUSH_UNSUPPORTED") != NULL ||
	     strstr(got.p, " ERROR WR_E_CRUSH_NO_RULE") != NULL)) {
		t->skipped_pools++;
		fprintf(stderr, "  skipped (a pool or rule this client does not serve): %s\n", label);
	} else if (rc == 1 && strstr(got.p, "WR_E_MAP_RESYNC") != NULL) {
		/* a pool renamed into a tracked name that the chain never tracked: a client asks for a full map; the
		 * state's own full-map run is the comparison */
		t->resyncs++;
		fprintf(stderr, "  resync (full map needed): %s\n", label);
	} else {
		WRT_CHECK_U64(rc, 0);
		(void)same_text(label, &got, want);
		t->runs++;
		t->pgs += lines;
	}
	buf_free(&got);
}

static const char *pool_name_in_dump(const wrt_json *j, wrt_tok dump, int64_t id, char *name, size_t cap)
{
	wrt_tok pools = wrt_json_get(j, dump, "pools");
	size_t i, n = wrt_json_count(j, pools);

	for (i = 0; i < n; i++) {
		wrt_tok p = wrt_json_at(j, pools, i);

		if (jint(j, wrt_json_get(j, p, "pool")) == id) {
			char *s = wrt_json_strdup(j, wrt_json_get(j, p, "pool_name"));

			if (s == NULL)
				return NULL;
			snprintf(name, cap, "%s", s);
			free(s);
			return name;
		}
	}
	return NULL;
}

static void test_states(void)
{
	wrt_json idx;
	wrt_tok states;
	size_t ns, si;
	tally t;
	char *base = vpath("public/mapb/base-e666.hex"), *incs = vpath("public/mapb/incrementals.hex");
	buf want;

	memset(&t, 0, sizeof(t));
	memset(&want, 0, sizeof(want));
	WRT_CHECK(wrt_json_load_vec(&idx, "public/mapb/INDEX.json") == 0);
	states = wrt_json_get(&idx, wrt_json_root(&idx), "states");
	ns = wrt_json_count(&idx, states);
	WRT_CHECK(ns >= 60u);
	for (si = 0; si < ns; si++) {
		wrt_tok s = wrt_json_at(&idx, states, si);
		char *file = wrt_json_strdup(&idx, wrt_json_get(&idx, s, "file"));
		char *label = wrt_json_strdup(&idx, wrt_json_get(&idx, s, "label"));
		char *fullrel = wrt_json_strdup(&idx, wrt_json_get(&idx, s, "full_map"));
		int64_t epoch = jint(&idx, wrt_json_get(&idx, s, "epoch"));
		char rel[256], ebuf[32], *spath, *fullp = NULL;
		wrt_json sj;
		wrt_tok pgs, dump;
		size_t n, i;
		int64_t seen[16];
		unsigned nseen = 0;

		snprintf(rel, sizeof(rel), "public/mapb/%s", file);
		spath = vpath(rel);
		if (fullrel != NULL) {
			snprintf(rel, sizeof(rel), "public/mapb/%s", fullrel);
			fullp = vpath(rel);
		}
		snprintf(ebuf, sizeof(ebuf), "%d", (int)epoch);
		if (wrt_json_load(&sj, spath) != 0) {
			WRT_CHECK(0);
			goto next;
		}
		pgs = wrt_json_get(&sj, wrt_json_root(&sj), "pgs");
		dump = wrt_json_get(&sj, wrt_json_root(&sj), "dump");
		n = wrt_json_count(&sj, pgs);
		for (i = 0; i < n; i++) {
			wrt_tok v;
			int64_t p;
			uint32_t sd;
			unsigned q, dup = 0;

			if (parse_pgid(wrt_json_key_at(&sj, pgs, i, &v), &p, &sd) != 0)
				continue;
			for (q = 0; q < nseen; q++)
				if (seen[q] == p)
					dup = 1;
			if (!dup && nseen < 16u)
				seen[nseen++] = p;
		}
		for (i = 0; i < nseen; i++) {
			char pname[160], lab[300];
			unsigned lines = render_table(&want, &sj, pgs, seen[i]);

			if (pool_name_in_dump(&sj, dump, seen[i], pname, sizeof(pname)) == NULL) {
				WRT_CHECK(0);
				continue;
			}
			{
				const char *chain[] = {"--map", base, "--apply-inc", incs, "--epoch", ebuf, NULL};

				snprintf(lab, sizeof(lab), "state %s pool %s (chain to e%s)", label, pname, ebuf);
				compare_pool(&t, lab, chain, pname, &want, lines);
			}
			if (fullp != NULL) {
				const char *fm[] = {"--map", fullp, NULL};

				snprintf(lab, sizeof(lab), "state %s pool %s (full map)", label, pname);
				compare_pool(&t, lab, fm, pname, &want, lines);
			}
		}
		wrt_json_free(&sj);
	next:
		free(spath);
		free(fullp);
		free(file);
		free(label);
		free(fullrel);
	}
	fprintf(stderr, "states: %zu states, %u tool runs compared (%u PG lines), %u pools skipped as unsupported, %u chains needing a full map\n", ns, t.runs, t.pgs,
		t.skipped_pools, t.resyncs);
	WRT_CHECK(t.runs >= 100u);
	WRT_CHECK(t.pgs >= 2000u);
	WRT_CHECK(t.skipped_pools >= 1u && t.skipped_pools <= 16u); /* the erasure pool of S12 (chain and full map of each state) */
	WRT_CHECK_U64(t.resyncs, 1); /* S11d: the renamed pool */
	wrt_json_free(&idx);
	buf_free(&want);
	free(base);
	free(incs);
}

static void test_offline_maps(void)
{
	wrt_json idx;
	wrt_tok oms;
	size_t no, i;
	tally t;
	buf want;

	memset(&t, 0, sizeof(t));
	memset(&want, 0, sizeof(want));
	WRT_CHECK(wrt_json_load_vec(&idx, "public/mapb/INDEX.json") == 0);
	oms = wrt_json_get(&idx, wrt_json_root(&idx), "osdmaps");
	no = wrt_json_count(&idx, oms);
	WRT_CHECK_U64(no, 8);
	for (i = 0; i < no; i++) {
		wrt_tok o = wrt_json_at(&idx, oms, i);
		char *mrel = wrt_json_strdup(&idx, wrt_json_get(&idx, o, "osdmap")), *prel = wrt_json_strdup(&idx, wrt_json_get(&idx, o, "pgs"));
		char *mp = vpath2("public/mapb/", mrel), *pp = vpath2("public/mapb/", prel);
		wrt_json pj;

		if (wrt_json_load(&pj, pp) != 0) {
			WRT_CHECK(0);
		} else {
			const char *args[] = {"--map", mp, NULL};
			unsigned lines = render_table(&want, &pj, wrt_json_get(&pj, wrt_json_root(&pj), "pgs"), 1);

			WRT_CHECK(lines > 0u);
			compare_pool(&t, mrel, args, "rbd", &want, lines);
			wrt_json_free(&pj);
		}
		free(mrel);
		free(prel);
		free(mp);
		free(pp);
	}
	fprintf(stderr, "offline maps: %u compared (%u PG lines), %u skipped as unsupported\n", t.runs, t.pgs, t.skipped_pools);
	WRT_CHECK(t.runs + t.skipped_pools == 8u);
	WRT_CHECK(t.runs >= 6u);
	wrt_json_free(&idx);
	buf_free(&want);
}

/* ---- the CRUSH runs of the offline maps --------------------------------------------------------------------- */

static void test_crush_runs(void)
{
	wrt_json idx;
	wrt_tok cms;
	size_t nc, ci;
	unsigned runs = 0, skipped = 0, fractional = 0, lines_total = 0, half = 0;
	buf want, got;

	memset(&want, 0, sizeof(want));
	memset(&got, 0, sizeof(got));
	WRT_CHECK(wrt_json_load_vec(&idx, "public/mapb/INDEX.json") == 0);
	cms = wrt_json_get(&idx, wrt_json_root(&idx), "crush");
	nc = wrt_json_count(&idx, cms);
	WRT_CHECK_U64(nc, 18);
	for (ci = 0; ci < nc; ci++) {
		wrt_tok c = wrt_json_at(&idx, cms, ci);
		char *crel = wrt_json_strdup(&idx, wrt_json_get(&idx, c, "crush")), *mrel = wrt_json_strdup(&idx, wrt_json_get(&idx, c, "mappings"));
		char *cp = vpath2("public/mapb/", crel), *mp = vpath2("public/mapb/", mrel);
		wrt_json mj;
		wrt_tok runs_t;
		size_t nr, ri;

		if (wrt_json_load(&mj, mp) != 0) {
			WRT_CHECK(0);
			goto next;
		}
		runs_t = wrt_json_get(&mj, wrt_json_root(&mj), "runs");
		nr = wrt_json_count(&mj, runs_t);
		for (ri = 0; ri < nr; ri++) {
			wrt_tok r, xs, ws;
			const char *rname = wrt_json_key_at(&mj, runs_t, ri, &r);
			char rule[16], rep[16], minx[16], maxx[16], poolid[24];
			const char *args[64];
			char wbuf[48][16];
			unsigned k = 0, nw = 0, w;
			size_t nx, x, nwt, wi;
			int64_t minv = jint(&mj, wrt_json_get(&mj, r, "min_x"));
			int frac = 0, rc;
			wrt_tok pid = wrt_json_get(&mj, r, "pool_id");

			xs = wrt_json_get(&mj, r, "x_to_result");
			nx = wrt_json_count(&mj, xs);
			ws = wrt_json_get(&mj, r, "weights");
			nwt = ws == WRT_NONE ? 0u : wrt_json_count(&mj, ws);
			snprintf(rule, sizeof(rule), "%d", (int)jint(&mj, wrt_json_get(&mj, r, "rule")));
			snprintf(rep, sizeof(rep), "%d", (int)jint(&mj, wrt_json_get(&mj, r, "num_rep")));
			snprintf(minx, sizeof(minx), "%d", (int)minv);
			snprintf(maxx, sizeof(maxx), "%d", (int)(minv + (int64_t)nx - 1));
			args[k++] = "--crush";
			args[k++] = cp;
			args[k++] = "--rule";
			args[k++] = rule;
			args[k++] = "--num-rep";
			args[k++] = rep;
			args[k++] = "--min-x";
			args[k++] = minx;
			args[k++] = "--max-x";
			args[k++] = maxx;
			if (pid != WRT_NONE) {
				int ok = 0;
				int64_t pv = wrt_json_int(&mj, pid, &ok);

				if (ok && pv != -1) {
					snprintf(poolid, sizeof(poolid), "%d", (int)pv);
					args[k++] = "--pool-id";
					args[k++] = poolid;
				}
			}
			for (wi = 0; wi < nwt && !frac; wi++) {
				wrt_tok wv;
				const char *dev = wrt_json_key_at(&mj, ws, wi, &wv);
				int ok = 0;
				int64_t wval = wrt_json_int(&mj, wv, &ok);

				if (nw >= 24u) {
					frac = 1; /* too many overrides for this test's buffers */
					break;
				}
				snprintf(wbuf[2u * nw], sizeof(wbuf[0]), "%s", dev);
				/* The JSON reader has integers only. The committed runs use exactly two values, 0 and 0.5 (the python check
				 * map_oracle_diff.py passes every value verbatim and would show a third one), so a non-integer is 0.5. */
				snprintf(wbuf[2u * nw + 1u], sizeof(wbuf[0]), "%s", ok ? (wval == 0 ? "0" : "1") : "0.5");
				if (ok && wval != 0 && wval != 1) {
					frac = 1;
					break;
				}
				if (!ok)
					half++;
				nw++;
			}
			if (frac) {
				fractional++;
				continue;
			}
			for (w = 0; w < nw; w++) {
				args[k++] = "--weight";
				args[k++] = wbuf[2u * w];
				args[k++] = wbuf[2u * w + 1u];
			}
			args[k] = NULL;
			buf_clear(&want);
			for (x = 0; x < nx; x++) {
				bprintf(&want, "CRUSH rule %s x %d ", rule, (int)(minv + (int64_t)x));
				put_jlist(&want, &mj, wrt_json_at(&mj, xs, x));
				buf_add(&want, "\n", 1);
			}
			rc = run_tool(args, 0, &got);
			if (rc == 3 && strstr(got.p, " ERROR WR_E_") != NULL) {
				skipped++;
				continue;
			}
			WRT_CHECK_U64(rc, 0);
			{
				char lab[300];

				snprintf(lab, sizeof(lab), "crush %s run %s", crel, rname);
				(void)same_text(lab, &got, &want);
			}
			runs++;
			lines_total += (unsigned)nx;
		}
		wrt_json_free(&mj);
	next:
		free(crel);
		free(mrel);
		free(cp);
		free(mp);
	}
	fprintf(stderr, "crush runs: %u compared (%u mappings, %u half weights), %u skipped as unsupported (tree, indep), %u not run\n", runs, lines_total, half,
		skipped, fractional);
	WRT_CHECK(runs >= 60u);
	WRT_CHECK(lines_total >= 2500u);
	WRT_CHECK(half >= 40u); /* runs with --weight 0.5 are in the comparison */
	WRT_CHECK_U64(fractional, 0);
	wrt_json_free(&idx);
	buf_free(&want);
	buf_free(&got);
}

/* ---- the state dump: an applied chain equals the monitor's full map ---------------------------------------------- */

/* The text of the block "== epoch N" of a dump (up to the next block), with the flags line masked to the bits a client reads. */
static int block_of(const buf *dump, unsigned epoch, buf *out)
{
	char head[48];
	const char *p = dump->p, *end;
	size_t hl;
	const char *q;

	snprintf(head, sizeof(head), "== epoch %u\n", epoch);
	hl = strlen(head);
	for (q = p; q != NULL && (q = strstr(q, head)) != NULL; q += hl)
		if (q == p || q[-1] == '\n')
			break;
	if (q == NULL)
		return 0;
	end = strstr(q + hl, "\n== epoch ");
	end = end ? end + 1 : p + dump->n;
	buf_clear(out);
	while (q < end) {
		const char *e = (const char *)memchr(q, '\n', (size_t)(end - q));
		size_t ln = e ? (size_t)(e - q) + 1u : (size_t)(end - q);

		if (ln > 8u && memcmp(q, "flags 0x", 8) == 0) {
			unsigned long f = strtoul(q + 8, NULL, 16);

			bprintf(out, "flags(client bits) 0x%lx\n", f & 0xeul);
		} else {
			buf_add(out, q, ln);
		}
		q += ln;
	}
	return 1;
}

static void test_dump_state(void)
{
	static const unsigned full_epochs[] = {667, 681, 693, 698, 709, 710, 720, 740, 747, 764, 773, 782, 789, 848, 849, 852, 861, 866, 872, 875, 925};
	char *base = vpath("public/mapb/base-e666.hex"), *incs = vpath("public/mapb/incrementals.hex");
	const char *pools[] = {"winrbd", "wrtest-mb-p16", "wrtest-mb-p12", "wrtest-mb-p7", "wrtest-mb-np", "wrtest-mb-leg", "wrtest-mb-s4", "wrtest-mb-host"};
	buf chain, one, a, b;
	const char *args[40];
	unsigned k = 0, i, blocks = 0, matched = 0;
	int rc;

	memset(&chain, 0, sizeof(chain));
	memset(&one, 0, sizeof(one));
	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	args[k++] = "--map";
	args[k++] = base;
	args[k++] = "--apply-inc";
	args[k++] = incs;
	args[k++] = "--dump-state";
	for (i = 0; i < 8u; i++) {
		args[k++] = "--pool";
		args[k++] = pools[i];
	}
	args[k] = NULL;
	rc = run_tool(args, 1, &chain);
	WRT_CHECK_U64(rc, 0);
	{
		const char *q = chain.p;

		while ((q = strstr(q, "== epoch ")) != NULL) {
			blocks++;
			q += 9;
		}
	}
	WRT_CHECK_U64(blocks, 1u + (925u - 666u)); /* the base map and every incremental: 667 .. 925 */
	for (i = 0; i < sizeof(full_epochs) / sizeof(full_epochs[0]); i++) {
		char rel[64], *fp;
		const char *fa[40];
		unsigned fk = 0, q;

		snprintf(rel, sizeof(rel), "public/mapb/maps/e%u.hex", full_epochs[i]);
		fp = vpath(rel);
		fa[fk++] = "--map";
		fa[fk++] = fp;
		fa[fk++] = "--dump-state";
		for (q = 0; q < 8u; q++) {
			fa[fk++] = "--pool";
			fa[fk++] = pools[q];
		}
		fa[fk] = NULL;
		WRT_CHECK_U64(run_tool(fa, 1, &one), 0);
		if (block_of(&chain, full_epochs[i], &a) && block_of(&one, full_epochs[i], &b)) {
			char lab[64];

			snprintf(lab, sizeof(lab), "state dump, chain vs full map e%u", full_epochs[i]);
			if (same_text(lab, &a, &b))
				matched++;
		} else {
			WRT_CHECK(0);
		}
		free(fp);
	}
	WRT_CHECK_U64(matched, sizeof(full_epochs) / sizeof(full_epochs[0]));
	/* --epoch stops the chain: three blocks, the base map and two incrementals */
	k = 0;
	args[k++] = "--map";
	args[k++] = base;
	args[k++] = "--apply-inc";
	args[k++] = incs;
	args[k++] = "--epoch";
	args[k++] = "668";
	args[k++] = "--dump-state";
	args[k++] = "--pool";
	args[k++] = "winrbd";
	args[k] = NULL;
	WRT_CHECK_U64(run_tool(args, 1, &one), 0);
	WRT_CHECK(strstr(one.p, "== epoch 666\n") != NULL && strstr(one.p, "== epoch 667\n") != NULL && strstr(one.p, "== epoch 668\n") != NULL);
	WRT_CHECK(strstr(one.p, "== epoch 669\n") == NULL);
	WRT_CHECK(strstr(one.p, "pool 2 'winrbd' present type 1 size 3") != NULL);
	WRT_CHECK(strstr(one.p, "osd.0 state 3 weight 65536 affinity 65536 addr v4 10.77.0.10:") != NULL);
	WRT_CHECK(strstr(one.p, "crush buckets ") != NULL);
	/* the 89 incrementals of the first lab set: epoch 42's full map, then 43 .. 89 */
	{
		char *f42 = vpath("osdmap/full-e42.hex"), *i89 = vpath("osdmap/incrementals.hex");
		const char *a2[] = {"--map", f42, "--apply-inc", i89, "--dump-state", "--pool", "winrbd", NULL};

		WRT_CHECK_U64(run_tool(a2, 1, &one), 0);
		blocks = 0;
		{
			const char *q = one.p;

			while ((q = strstr(q, "== epoch ")) != NULL) {
				blocks++;
				q += 9;
			}
		}
		WRT_CHECK_U64(blocks, 1u + (89u - 42u));
		free(f42);
		free(i89);
	}
	free(base);
	free(incs);
	buf_free(&chain);
	buf_free(&one);
	buf_free(&a);
	buf_free(&b);
}

/* ---- the tool's own behaviour -------------------------------------------------------------------------------- */

static void test_object_forms(void)
{
	char *map = vpath("public/gt/osdmap.bin");
	buf a, b;
	const char *p;

	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	/* odd bytes are escaped: a backslash, a NUL, 0xff and a newline in the name; the namespace shows with a slash */
	{
		const char *args[] = {"--map", map, "--pool", "winrbd", "--object", "5c00ff0a", "--ns-str", "q", NULL};

		WRT_CHECK_U64(run_tool(args, 0, &a), 0);
		WRT_CHECK(strncmp(a.p, "osdmap e141 pool 'winrbd' (2) object 'q/\\\\\\x00\\xff\\x0a' -> pg 2.", 62) == 0);
		WRT_CHECK(a.n > 0 && a.p[a.n - 1] == '\n' && memchr(a.p, '\n', a.n) == a.p + a.n - 1);
	}
	/* hex and text arguments name the same bytes; an empty name is allowed */
	{
		const char *h[] = {"--map", map, "--pool", "winrbd", "--object", "666f6f", NULL};
		const char *s[] = {"--map", map, "--pool", "winrbd", "--object-str", "foo", NULL};
		const char *e[] = {"--map", map, "--pool", "winrbd", "--object", "", NULL};

		WRT_CHECK_U64(run_tool(h, 0, &a), 0);
		WRT_CHECK_U64(run_tool(s, 0, &b), 0);
		(void)same_text("hex and text object", &a, &b);
		WRT_CHECK_U64(run_tool(e, 0, &a), 0);
		WRT_CHECK(strstr(a.p, "object ''") != NULL);
	}
	/* a locator key replaces the name in the hash (the name is still printed) */
	{
		const char *k1[] = {"--map", map, "--pool", "winrbd", "--object-str", "other", "--key-str", "abc", NULL};
		const char *k2[] = {"--map", map, "--pool", "winrbd", "--object-str", "abc", NULL};

		WRT_CHECK_U64(run_tool(k1, 0, &a), 0);
		WRT_CHECK_U64(run_tool(k2, 0, &b), 0);
		p = strstr(a.p, " -> pg ");
		WRT_CHECK(p != NULL && strstr(b.p, p) != NULL);
		WRT_CHECK(strstr(a.p, "object 'other'") != NULL);
	}
	free(map);
	buf_free(&a);
	buf_free(&b);
}

static void test_errors(void)
{
	char *map = vpath("public/gt/osdmap.bin");
	char *hexmap = vpath("public/mapb/base-e666.hex");
	buf o;
	int rc;

	memset(&o, 0, sizeof(o));
	{
		const char *args[] = {"--bogus", NULL};

		rc = run_tool(args, 1, &o);
		WRT_CHECK_U64(rc, 2);
		WRT_CHECK(strstr(o.p, "usage:") != NULL);
	}
	{
		const char *args[] = {"--map", map, "--dump-pgs", NULL}; /* no pool */

		WRT_CHECK_U64(run_tool(args, 1, &o), 2);
		WRT_CHECK(strstr(o.p, "--pool") != NULL);
	}
	{
		const char *args[] = {"--map", map, "--pool", "winrbd", "--dump-pgs", "--dump-state", NULL}; /* two modes */

		WRT_CHECK_U64(run_tool(args, 1, &o), 2);
	}
	{
		const char *args[] = {"--map", map, "--pool", "winrbd", "--object", "zz", NULL}; /* not hex */

		WRT_CHECK_U64(run_tool(args, 1, &o), 2);
		WRT_CHECK(strstr(o.p, "hex") != NULL);
	}
	{
		const char *args[] = {"--map", "/nonexistent/map.bin", "--pool", "winrbd", "--dump-pgs", NULL};

		WRT_CHECK_U64(run_tool(args, 1, &o), 1);
		WRT_CHECK(strstr(o.p, "cannot open") != NULL);
	}
	{
		const char *args[] = {"--map", map, "--pool", "no-such-pool", "--dump-pgs", NULL};

		WRT_CHECK_U64(run_tool(args, 1, &o), 1);
		WRT_CHECK(strstr(o.p, "no-such-pool") != NULL && strstr(o.p, "not in the map") != NULL);
	}
	{
		const char *args[] = {"--map", map, "--pool", "no-such-pool", "--object-str", "x", NULL}; /* an object of an absent pool: an ERROR line */

		WRT_CHECK_U64(run_tool(args, 0, &o), 3);
		WRT_CHECK(strstr(o.p, "ERROR WR_E_POOL_NOT_FOUND") != NULL);
	}
	/* a damaged map is refused with its reason: flip one byte of the map's own bytes (the CRC no longer fits) */
	{
		uint8_t *raw = NULL;
		size_t n = 0;
		char tmpl[] = "/tmp/wr_oracle_cli_XXXXXX";
		int fd;

		WRT_CHECK(wrt_read_file(map, &raw, &n) == 0);
		raw[n / 2] ^= 0x01u;
		fd = mkstemp(tmpl);
		WRT_CHECK(fd >= 0);
		if (fd >= 0) {
			const char *args[] = {"--map", tmpl, "--pool", "winrbd", "--dump-pgs", NULL};
			const char *relaxed[] = {"--map", tmpl, "--pool", "winrbd", "--dump-pgs", "--no-crc", NULL};

			WRT_CHECK(write(fd, raw, n) == (ssize_t)n);
			close(fd);
			rc = run_tool(args, 1, &o);
			WRT_CHECK(rc == 1 && (strstr(o.p, "WR_E_MAP_CRC") != NULL || strstr(o.p, "WR_E_MAP_CORRUPT") != NULL));
			rc = run_tool(relaxed, 1, &o);
			WRT_CHECK(rc == 0 || rc == 1); /* without the CRC check it may still decode; it must not crash */
			unlink(tmpl);
		}
		free(raw);
	}
	/* an incremental of the wrong epoch is named; the base map is not touched */
	{
		char *incs = vpath("public/mapb/incrementals.hex");
		char tmpl[] = "/tmp/wr_oracle_cli_XXXXXX";
		int fd = mkstemp(tmpl);
		buf txt;

		memset(&txt, 0, sizeof(txt));
		if (fd >= 0) {
			/* skip epoch 667: the file holds only 668 and later */
			WRT_CHECK(read_text(incs, &txt) == 0);
			{
				const char *l = strstr(txt.p, "\n668 ");

				WRT_CHECK(l != NULL);
				if (l != NULL) {
					const char *args[] = {"--map", hexmap, "--apply-inc", tmpl, "--pool", "winrbd", "--dump-pgs", NULL};

					WRT_CHECK(write(fd, l + 1, strlen(l + 1)) == (ssize_t)strlen(l + 1));
					close(fd);
					rc = run_tool(args, 1, &o);
					WRT_CHECK(rc == 1 && strstr(o.p, "incremental of epoch 668") != NULL && strstr(o.p, "WR_E_MAP_EPOCH") != NULL);
				}
			}
			unlink(tmpl);
		}
		buf_free(&txt);
		free(incs);
	}
	free(map);
	free(hexmap);
	buf_free(&o);
}

/* An erasure pool is an ERROR line for the pool and exit status 3; a batch file with a bad line is a fatal error. */
static void test_unsupported_and_batch(void)
{
	char *base = vpath("public/mapb/base-e666.hex"), *incs = vpath("public/mapb/incrementals.hex");
	char tmpl[] = "/tmp/wr_oracle_cli_XXXXXX";
	int fd;
	buf o;
	wrt_json sj;
	int rc;

	memset(&o, 0, sizeof(o));
	/* state S12b names the erasure pool (id 52) of the capture */
	if (wrt_json_load_vec(&sj, "public/mapb/states/s12b-ec-pool.json") == 0) {
		char name[160] = "", ebuf[16];
		wrt_tok root = wrt_json_root(&sj);

		WRT_CHECK(pool_name_in_dump(&sj, wrt_json_get(&sj, root, "dump"), 52, name, sizeof(name)) != NULL);
		snprintf(ebuf, sizeof(ebuf), "%d", (int)jint(&sj, wrt_json_get(&sj, root, "epoch")));
		if (name[0] != '\0') {
			const char *a3[] = {"--map", base, "--apply-inc", incs, "--epoch", ebuf, "--pool", name, "--dump-pgs", NULL};

			rc = run_tool(a3, 0, &o);
			WRT_CHECK_U64(rc, 3);
			WRT_CHECK(strcmp(o.p, "pool 52 ERROR WR_E_POOL_UNSUPPORTED\n") == 0);
		}
		wrt_json_free(&sj);
	} else {
		WRT_CHECK(0);
	}
	/* a batch file: comments, an empty line, a namespace and an empty name are handled */
	fd = mkstemp(tmpl);
	WRT_CHECK(fd >= 0);
	if (fd >= 0) {
		const char *text = "# comment\n\nwinrbd 666f6f\nwinrbd 666f6f 6e73 # trailing comment\nwinrbd - -\n";
		const char *bad = "winrbd 666f6f\nelsewhere 66\n";
		char *map = vpath("public/gt/osdmap.bin");
		const char *a1[] = {"--map", map, "--pool", "winrbd", "--names", tmpl, NULL};
		unsigned lines = 0;
		const char *q;
		FILE *bf;

		WRT_CHECK(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
		close(fd);
		rc = run_tool(a1, 0, &o);
		WRT_CHECK_U64(rc, 0);
		for (q = o.p; *q; q++)
			if (*q == '\n')
				lines++;
		WRT_CHECK_U64(lines, 3);
		WRT_CHECK(strstr(o.p, "object 'foo' -> pg 2.7fc1f406 (2.6)") != NULL);
		WRT_CHECK(strstr(o.p, "object 'ns/foo' -> pg 2.ac17f0b6 (2.16)") != NULL);
		WRT_CHECK(strstr(o.p, "object '' ->") != NULL);
		/* a line naming a pool that was not given with --pool stops the run */
		bf = fopen(tmpl, "w");
		WRT_CHECK(bf != NULL);
		if (bf != NULL) {
			fputs(bad, bf);
			fclose(bf);
			rc = run_tool(a1, 1, &o);
			WRT_CHECK(rc == 1 && strstr(o.p, "was not given with --pool") != NULL);
		}
		unlink(tmpl);
		free(map);
	}
	buf_free(&o);
	free(base);
	free(incs);
}

/* ---- review round: the error paths and the odd inputs of the tool ---------------------------------------------- */

/* A temporary file with these bytes; the path is copied into `path` (caller unlinks). Returns 0 on success. */
static int write_tmp(char *path, size_t path_cap, const void *data, size_t n)
{
	char tmpl[] = "/tmp/wr_oracle_cli_XXXXXX";
	int fd = mkstemp(tmpl);

	if (fd < 0 || strlen(tmpl) + 1u > path_cap) {
		if (fd >= 0) {
			close(fd);
			unlink(tmpl);
		}
		return -1;
	}
	if (n != 0 && write(fd, data, n) != (ssize_t)n) {
		close(fd);
		unlink(tmpl);
		return -1;
	}
	close(fd);
	memcpy(path, tmpl, strlen(tmpl) + 1u);
	return 0;
}

/* The line of an "<epoch> <hex>" list text that starts with "<epoch> " (without the newline), or NULL. */
static const char *list_line(const buf *txt, unsigned epoch, size_t *len)
{
	char key[32];
	const char *q;
	size_t i = 0;

	snprintf(key, sizeof(key), "%u ", epoch);
	while (i < txt->n) {
		size_t e = i;

		while (e < txt->n && txt->p[e] != '\n')
			e++;
		q = txt->p + i;
		if (e - i > strlen(key) && memcmp(q, key, strlen(key)) == 0) {
			*len = e - i;
			return q;
		}
		i = e + 1u;
	}
	return NULL;
}

static void test_crush_cli_errors(void)
{
	char *crush = vpath("public/gt/crush.bin"), *map = vpath("public/gt/osdmap.bin");
	uint8_t *raw = NULL;
	size_t n = 0, cut;
	char tmp[64];
	buf o;
	int rc;

	memset(&o, 0, sizeof(o));
	WRT_CHECK(wrt_read_file(crush, &raw, &n) == 0);
	/* --crush and --map are two modes: refused, not "the first one wins" */
	{
		const char *a[] = {"--crush", crush, "--map", map, "--rule", "0", "--num-rep", "1", "--min-x", "0", "--max-x", "1", NULL};

		WRT_CHECK_U64(run_tool(a, 1, &o), 2);
		WRT_CHECK(strstr(o.p, "different modes") != NULL);
	}
	/* a CRUSH map cut anywhere, empty, or not hex is refused with a message and exit 1, never a crash */
	for (cut = 0; cut < n; cut += (n / 29u) + 1u) {
		const char *a[] = {"--crush", tmp, "--rule", "0", "--num-rep", "1", "--min-x", "0", "--max-x", "3", NULL};

		WRT_CHECK(write_tmp(tmp, sizeof(tmp), raw, cut) == 0);
		rc = run_tool(a, 1, &o);
		WRT_CHECK_U64(rc, 1);
		WRT_CHECK(strstr(o.p, "crush decode failed") != NULL);
		unlink(tmp);
	}
	{
		const char *a[] = {"--crush", tmp, "--rule", "0", "--num-rep", "1", "--min-x", "0", "--max-x", "3", NULL};

		WRT_CHECK(write_tmp(tmp, sizeof(tmp), "zz not hex\n", 11) == 0);
		WRT_CHECK_U64(run_tool(a, 1, &o), 1);
		WRT_CHECK(strstr(o.p, "not hex") != NULL);
		unlink(tmp);
	}
	/* a bucket that names device 2^31 - 3 makes max_devices huge: the tool must refuse it, not size an 8 GiB weight array by it */
	{
		const char *a[] = {"--crush", tmp, "--rule", "0", "--num-rep", "1", "--min-x", "0", "--max-x", "3", NULL};
		static const uint8_t huge[4] = {0xfd, 0xff, 0xff, 0x7f};
		size_t pos, refused = 0;

		for (pos = 0; pos + 4u <= n; pos += 4u) {
			uint8_t *cp = (uint8_t *)malloc(n);

			WRT_CHECK(cp != NULL);
			if (cp == NULL)
				break;
			memcpy(cp, raw, n);
			memcpy(cp + pos, huge, 4);
			WRT_CHECK(write_tmp(tmp, sizeof(tmp), cp, n) == 0);
			rc = run_tool(a, 1, &o);
			WRT_CHECK(rc == 0 || rc == 1 || rc == 3); /* never a signal, whatever the field */
			WRT_CHECK(strstr(o.p, "Sanitizer") == NULL); /* a sanitizer build reports a bad access on stderr and exits 1 */
			if (strstr(o.p, "too many devices") != NULL) {
				refused++;
				WRT_CHECK_U64(rc, 1);
			}
			unlink(tmp);
			free(cp);
		}
		WRT_CHECK(refused > 0); /* some field of the map is a device id: the guard was reached */
	}
	free(raw);
	/* bad numbers and missing pieces */
	{
		const char *nr0[] = {"--crush", crush, "--rule", "0", "--num-rep", "0", "--min-x", "0", "--max-x", "3", NULL};
		const char *nr17[] = {"--crush", crush, "--rule", "0", "--num-rep", "17", "--min-x", "0", "--max-x", "3", NULL};
		const char *minmax[] = {"--crush", crush, "--rule", "0", "--num-rep", "1", "--min-x", "5", "--max-x", "3", NULL};
		const char *nomax[] = {"--crush", crush, "--rule", "0", "--num-rep", "1", "--min-x", "5", NULL};
		const char *big[] = {"--crush", crush, "--rule", "0", "--num-rep", "1", "--min-x", "4294967296", "--max-x", "5", NULL};
		const char *nanw[] = {"--crush", crush, "--rule", "0", "--num-rep", "1", "--min-x", "0", "--max-x", "5", "--weight", "0", "nan", NULL};
		const char *halfw[] = {"--crush", crush, "--rule", "0", "--num-rep", "1", "--min-x", "0", "--max-x", "5", "--weight", "0", NULL};
		const char *negdev[] = {"--crush", crush, "--rule", "0", "--num-rep", "1", "--min-x", "0", "--max-x", "5", "--weight", "-1", "1", NULL};

		WRT_CHECK_U64(run_tool(nr0, 1, &o), 1);
		WRT_CHECK_U64(run_tool(nr17, 1, &o), 1);
		WRT_CHECK_U64(run_tool(minmax, 1, &o), 1);
		WRT_CHECK_U64(run_tool(nomax, 1, &o), 2);
		WRT_CHECK_U64(run_tool(big, 1, &o), 2);
		WRT_CHECK_U64(run_tool(nanw, 1, &o), 2);
		WRT_CHECK_U64(run_tool(halfw, 1, &o), 2);
		WRT_CHECK_U64(run_tool(negdev, 1, &o), 2);
	}
	/* a rule the map does not have: an ERROR line per mapping and exit 3 */
	{
		const char *a[] = {"--crush", crush, "--rule", "99", "--num-rep", "2", "--min-x", "0", "--max-x", "2", NULL};

		WRT_CHECK_U64(run_tool(a, 0, &o), 3);
		WRT_CHECK(strncmp(o.p, "CRUSH rule 99 x 0 ERROR WR_E_CRUSH_NO_RULE", 42) == 0);
	}
	/* the work budget is the tool's own option: a budget of one draw cannot map anything */
	{
		const char *a[] = {"--crush", crush, "--rule", "0", "--num-rep", "3", "--min-x", "0", "--max-x", "2", "--work-max", "1", NULL};

		WRT_CHECK_U64(run_tool(a, 0, &o), 3);
		WRT_CHECK(strstr(o.p, "ERROR WR_E_CRUSH_WORK") != NULL);
	}
	/* a device given weight 0 is never chosen; the whole range still maps (the lines are not errors) */
	{
		const char *a[] = {"--crush", crush, "--rule", "0", "--num-rep", "3", "--min-x", "0", "--max-x", "199", "--weight", "0", "0", NULL};
		const char *q;
		unsigned lines = 0;

		WRT_CHECK_U64(run_tool(a, 0, &o), 0);
		for (q = o.p; *q; q++)
			if (*q == '\n')
				lines++;
		WRT_CHECK_U64(lines, 200);
		WRT_CHECK(strstr(o.p, "[0,") == NULL && strstr(o.p, ",0,") == NULL && strstr(o.p, ",0]") == NULL && strstr(o.p, "[0]") == NULL);
	}
	buf_free(&o);
	free(crush);
	free(map);
}

/* Damaged and odd map inputs: every cut and every flipped byte ends in a clean exit, never in a signal. */
static void test_map_cli_damage(void)
{
	char *map = vpath("public/gt/osdmap.bin"), *base = vpath("public/mapb/base-e666.hex"), *incs = vpath("public/mapb/incrementals.hex");
	uint8_t *raw = NULL;
	size_t n = 0, i;
	char tmp[64];
	buf o, txt;
	int rc;

	memset(&o, 0, sizeof(o));
	memset(&txt, 0, sizeof(txt));
	WRT_CHECK(wrt_read_file(map, &raw, &n) == 0);
	/* cut at 40 places (and at 0): with the CRC check on, a cut map is always refused with exit 1 */
	for (i = 0; i <= 40u; i++) {
		size_t cut = i == 40u ? n - 1u : (n / 40u) * i;
		const char *a[] = {"--map", tmp, "--pool", "winrbd", "--dump-pgs", NULL};

		WRT_CHECK(write_tmp(tmp, sizeof(tmp), raw, cut) == 0);
		rc = run_tool(a, 1, &o);
		WRT_CHECK_U64(rc, 1);
		unlink(tmp);
	}
	/* a flipped byte at 60 places, without the CRC check: whatever the core makes of it, the tool exits 0, 1 or 3 */
	for (i = 0; i < 60u; i++) {
		const char *a[] = {"--map", tmp, "--pool", "winrbd", "--no-crc", "--dump-state", NULL};
		uint8_t *cp = (uint8_t *)malloc(n);

		WRT_CHECK(cp != NULL);
		if (cp == NULL)
			break;
		memcpy(cp, raw, n);
		cp[(n / 60u) * i + (i % 7u)] ^= (uint8_t)(0x01u << (i % 8u));
		WRT_CHECK(write_tmp(tmp, sizeof(tmp), cp, n) == 0);
		rc = run_tool(a, 1, &o);
		WRT_CHECK(rc == 0 || rc == 1 || rc == 3);
		unlink(tmp);
		free(cp);
	}
	free(raw);
	/* empty map, text that is not hex */
	{
		const char *a[] = {"--map", tmp, "--pool", "winrbd", "--dump-pgs", NULL};

		WRT_CHECK(write_tmp(tmp, sizeof(tmp), "", 0) == 0);
		WRT_CHECK_U64(run_tool(a, 1, &o), 1);
		unlink(tmp);
		WRT_CHECK(write_tmp(tmp, sizeof(tmp), "not hex at all\n", 15) == 0);
		WRT_CHECK_U64(run_tool(a, 1, &o), 1);
		WRT_CHECK(strstr(o.p, "not hex") != NULL);
		unlink(tmp);
	}
	/* incrementals: a cut entry and a garbage line in the list are named, the held map stays as it was */
	WRT_CHECK(read_text(incs, &txt) == 0);
	{
		size_t l667 = 0;
		const char *line = list_line(&txt, 667, &l667);
		buf lst;

		memset(&lst, 0, sizeof(lst));
		WRT_CHECK(line != NULL);
		if (line != NULL) {
			const char *a[] = {"--map", base, "--apply-inc", tmp, "--pool", "winrbd", "--dump-pgs", NULL};

			buf_add(&lst, line, l667 - 12u); /* cut inside the hex: even digit count, wrong length */
			buf_add(&lst, "\n", 1);
			WRT_CHECK(write_tmp(tmp, sizeof(tmp), lst.p, lst.n) == 0);
			rc = run_tool(a, 1, &o);
			WRT_CHECK(rc == 1 && strstr(o.p, "incremental") != NULL);
			unlink(tmp);
			WRT_CHECK(write_tmp(tmp, sizeof(tmp), "667 zz\n", 7) == 0);
			rc = run_tool(a, 1, &o);
			WRT_CHECK(rc == 1 && strstr(o.p, "bad line in the incremental list") != NULL);
			unlink(tmp);
			/* the same incremental as a space separated hex dump (a blob, not a list: its first token has a leading zero) */
			{
				const char *hex = line + 4; /* "667 " */
				size_t hn = l667 - 4u, k;
				buf spaced, st_list, st_dump;
				char lf[64];
				const char *b2[] = {"--map", base, "--apply-inc", tmp, "--pool", "winrbd", "--dump-state", NULL};
				const char *b3[] = {"--map", base, "--apply-inc", lf, "--pool", "winrbd", "--dump-state", NULL};

				memset(&spaced, 0, sizeof(spaced));
				memset(&st_list, 0, sizeof(st_list));
				memset(&st_dump, 0, sizeof(st_dump));
				for (k = 0; k + 1u < hn; k += 2u) {
					buf_add(&spaced, hex + k, 2);
					buf_add(&spaced, (k / 2u) % 16u == 15u ? "\n" : " ", 1);
				}
				buf_add(&spaced, "\n", 1);
				WRT_CHECK(write_tmp(tmp, sizeof(tmp), spaced.p, spaced.n) == 0);
				WRT_CHECK(write_tmp(lf, sizeof(lf), line, l667) == 0);
				WRT_CHECK_U64(run_tool(b2, 1, &st_dump), 0);
				WRT_CHECK_U64(run_tool(b3, 1, &st_list), 0);
				(void)same_text("space separated hex dump and the list entry", &st_dump, &st_list);
				WRT_CHECK(strstr(st_dump.p, "== epoch 667\n") != NULL);
				unlink(tmp);
				unlink(lf);
				buf_free(&spaced);
				buf_free(&st_list);
				buf_free(&st_dump);
			}
		}
		buf_free(&lst);
	}
	/* --epoch stops the chain for good: a later file that holds an epoch which fits the held map is not applied either */
	{
		size_t l1 = 0, l2 = 0, l3 = 0;
		const char *e667 = list_line(&txt, 667, &l1), *e668 = list_line(&txt, 668, &l2), *e669 = list_line(&txt, 669, &l3);

		WRT_CHECK(e667 != NULL && e668 != NULL && e669 != NULL);
		if (e667 != NULL && e668 != NULL && e669 != NULL) {
			char fa[64], fb[64];
			buf la, lb;
			const char *a[] = {"--map", base, "--apply-inc", fa, "--apply-inc", fb, "--epoch", "668", "--pool", "winrbd", "--dump-state", NULL};

			memset(&la, 0, sizeof(la));
			memset(&lb, 0, sizeof(lb));
			buf_add(&la, e667, l1);
			buf_add(&la, "\n", 1);
			buf_add(&la, e669, l3);
			buf_add(&la, "\n", 1);
			buf_add(&lb, e668, l2);
			buf_add(&lb, "\n", 1);
			WRT_CHECK(write_tmp(fa, sizeof(fa), la.p, la.n) == 0);
			WRT_CHECK(write_tmp(fb, sizeof(fb), lb.p, lb.n) == 0);
			WRT_CHECK_U64(run_tool(a, 1, &o), 0);
			WRT_CHECK(strstr(o.p, "== epoch 667\n") != NULL);
			WRT_CHECK(strstr(o.p, "== epoch 668\n") == NULL);
			unlink(fa);
			unlink(fb);
			buf_free(&la);
			buf_free(&lb);
		}
	}
	buf_free(&txt);
	buf_free(&o);
	free(map);
	free(base);
	free(incs);
}

/* The odd arguments and batch files. */
static void test_args_and_batch_edges(void)
{
	char *map = vpath("public/gt/osdmap.bin");
	char tmp[64];
	char longname[8200];
	buf o, a, b;
	size_t i;

	memset(&o, 0, sizeof(o));
	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	/* an option given twice: the last wins (the earlier bytes are released, which the leak checker would notice) */
	{
		const char *twice[] = {"--map", map, "--pool", "winrbd", "--object", "6161", "--object", "666f6f", "--ns-str", "x", "--ns-str", "y", NULL};
		const char *once[] = {"--map", map, "--pool", "winrbd", "--object", "666f6f", "--ns-str", "y", NULL};

		WRT_CHECK_U64(run_tool(twice, 0, &a), 0);
		WRT_CHECK_U64(run_tool(once, 0, &b), 0);
		(void)same_text("an option given twice", &a, &b);
	}
	/* a namespace and a locator key: the key replaces the name in "<ns> 0x1f <key>" */
	{
		const char *k1[] = {"--map", map, "--pool", "winrbd", "--object-str", "other", "--ns-str", "n", "--key-str", "abc", NULL};
		const char *k2[] = {"--map", map, "--pool", "winrbd", "--object-str", "abc", "--ns-str", "n", NULL};
		const char *k3[] = {"--map", map, "--pool", "winrbd", "--object-str", "abc", NULL};
		const char *p;

		WRT_CHECK_U64(run_tool(k1, 0, &a), 0);
		WRT_CHECK_U64(run_tool(k2, 0, &b), 0);
		p = strstr(a.p, " -> pg ");
		WRT_CHECK(p != NULL && strstr(b.p, p) != NULL);
		WRT_CHECK(strstr(a.p, "object 'n/other'") != NULL);
		WRT_CHECK_U64(run_tool(k3, 0, &b), 0);
		WRT_CHECK(p != NULL && strstr(b.p, p) == NULL); /* the namespace is part of the hash */
	}
	/* names of 4,096 + 1 bytes are the core's limit: an ERROR line, exit 3 (the name is hex so the bytes are exact) */
	for (i = 0; i < 4097u; i++)
		memcpy(longname + 2u * i, "61", 2);
	longname[2u * 4097u] = '\0';
	{
		const char *big[] = {"--map", map, "--pool", "winrbd", "--object", longname, NULL};
		const char *ok[] = {"--map", map, "--pool", "winrbd", "--object", longname + 2, NULL};

		WRT_CHECK_U64(run_tool(big, 0, &a), 3);
		WRT_CHECK(strstr(a.p, "-> ERROR WR_E_TOOBIG") != NULL);
		WRT_CHECK_U64(run_tool(ok, 0, &a), 0); /* exactly 4,096 bytes is still served */
	}
	/* pool names: empty, too long, too many */
	{
		char name129[130];
		const char *empty[] = {"--map", map, "--pool", "", "--dump-pgs", NULL};
		const char *longp[] = {"--map", map, "--pool", name129, "--dump-pgs", NULL};
		const char *many[] = {"--map", map, "--pool", "a", "--pool", "b", "--pool", "c", "--pool", "d", "--pool", "e",
				      "--pool", "f", "--pool", "g", "--pool", "h", "--pool", "i", "--dump-pgs", NULL};

		memset(name129, 'p', 129);
		name129[129] = '\0';
		WRT_CHECK_U64(run_tool(empty, 1, &a), 2);
		WRT_CHECK_U64(run_tool(longp, 1, &a), 2);
		WRT_CHECK_U64(run_tool(many, 1, &a), 2);
	}
	/* numbers: not a number, negative, above 32 bits */
	{
		const char *e1[] = {"--map", map, "--pool", "winrbd", "--epoch", "-1", "--dump-state", NULL};
		const char *e2[] = {"--map", map, "--pool", "winrbd", "--epoch", "12x", "--dump-state", NULL};
		const char *s1[] = {"--map", map, "--pool", "winrbd", "--slot-bytes", "100", "--dump-state", NULL};
		const char *s2[] = {"--map", map, "--pool", "winrbd", "--max-osd", "0", "--dump-state", NULL};
		const char *s3[] = {"--map", map, "--pool", "winrbd", "--work-max", "4294967296", "--dump-state", NULL};
		const char *s4[] = {"--map", map, "--pool", "winrbd", "--dump-state", "--object", "00", NULL};

		WRT_CHECK_U64(run_tool(e1, 1, &a), 2);
		WRT_CHECK_U64(run_tool(e2, 1, &a), 2);
		WRT_CHECK_U64(run_tool(s1, 1, &a), 2);
		WRT_CHECK_U64(run_tool(s2, 1, &a), 2);
		WRT_CHECK_U64(run_tool(s3, 1, &a), 2);
		WRT_CHECK_U64(run_tool(s4, 1, &a), 2); /* two modes */
	}
	/* --dump-pgs refuses a pool above --max-pgs before printing a line */
	{
		const char *a2[] = {"--map", map, "--pool", "winrbd", "--max-pgs", "1", "--dump-pgs", NULL};

		WRT_CHECK_U64(run_tool(a2, 1, &a), 1);
		WRT_CHECK(strstr(a.p, "above --max-pgs 1") != NULL && strstr(a.p, " raw (") == NULL);
	}
	/* a map above the configured budget: a clean error naming the status and the limit */
	{
		const char *a1[] = {"--map", map, "--pool", "winrbd", "--max-osd", "1", "--dump-pgs", NULL};

		WRT_CHECK_U64(run_tool(a1, 1, &a), 1);
		WRT_CHECK(strstr(a.p, "WR_E_MAP_BUDGET") != NULL);
	}
	/* batch file: CRLF line ends, no newline after the last line, a first empty line, tabs; and the bad ones */
	{
		const char *names[] = {"--map", map, "--pool", "winrbd", "--names", tmp, NULL};
		const char *text = "\n\twinrbd\t666f6f\r\nwinrbd 666f6f 6e73\r\nwinrbd 666f6f - 616263";
		unsigned lines = 0;
		const char *q;

		WRT_CHECK(write_tmp(tmp, sizeof(tmp), text, strlen(text)) == 0);
		WRT_CHECK_U64(run_tool(names, 0, &a), 0);
		for (q = a.p; *q; q++)
			if (*q == '\n')
				lines++;
		WRT_CHECK_U64(lines, 3);
		WRT_CHECK(strstr(a.p, "object 'foo' -> pg 2.7fc1f406") != NULL && strstr(a.p, "object 'ns/foo' -> pg 2.ac17f0b6") != NULL);
		unlink(tmp);
		text = "winrbd 66 - 61 62\n"; /* five fields */
		WRT_CHECK(write_tmp(tmp, sizeof(tmp), text, strlen(text)) == 0);
		WRT_CHECK_U64(run_tool(names, 1, &a), 1);
		WRT_CHECK(strstr(a.p, ":1:") != NULL);
		unlink(tmp);
		text = "\n\nwinrbd 6x\n"; /* not hex, on line 3: the message names the line */
		WRT_CHECK(write_tmp(tmp, sizeof(tmp), text, strlen(text)) == 0);
		WRT_CHECK_U64(run_tool(names, 1, &a), 1);
		WRT_CHECK(strstr(a.p, ":3:") != NULL && strstr(a.p, "must be hex") != NULL);
		unlink(tmp);
		text = "winrbd\n"; /* one field */
		WRT_CHECK(write_tmp(tmp, sizeof(tmp), text, strlen(text)) == 0);
		WRT_CHECK_U64(run_tool(names, 1, &a), 1);
		unlink(tmp);
		WRT_CHECK(write_tmp(tmp, sizeof(tmp), "", 0) == 0); /* an empty batch file answers nothing and succeeds */
		WRT_CHECK_U64(run_tool(names, 0, &a), 0);
		WRT_CHECK_U64(a.n, 0);
		unlink(tmp);
	}
	buf_free(&o);
	buf_free(&a);
	buf_free(&b);
	free(map);
}

int main(void)
{
	g_tool = getenv("WR_MAPORACLE");
	if (g_tool == NULL || g_tool[0] == '\0')
		WRT_SKIP("WR_MAPORACLE (the path of wr-maporacle) is not set");
	test_gt_crushtool();
	test_gt_osdmaptool();
	test_gt_ceph_osd_map();
	test_name_oracle();
	test_states();
	test_offline_maps();
	test_crush_runs();
	test_dump_state();
	test_object_forms();
	test_errors();
	test_unsupported_and_batch();
	test_crush_cli_errors();
	test_map_cli_damage();
	test_args_and_batch_edges();
	return wrt_finish();
}
