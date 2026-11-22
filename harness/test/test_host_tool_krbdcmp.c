/* SPDX-License-Identifier: MIT */
/*
 * test_host_tool_krbdcmp.c - the wr-krbdcmp tool (harness/host/tools/wr-krbdcmp.c) run as a child process against a whole simulated cluster over
 * REAL TCP sockets on 127.0.0.1 (the rig of cmp_rig.h), with a REGULAR FILE as the device and the test-only flags (docs/design/core-architecture.md
 * 33.3 and 33.6; ctest host.tool.krbdcmp). A regular file has no connection to the image, so --self-test-mirror makes the tool perform every write on
 * both sides; what is tested is the tool around the engine: arguments, exit codes, the shape of the records.
 *
 * Checked:
 *   arguments     no arguments, an unknown option, a missing one, bad values (--dir, --phase, --mode, --depth, --discard-gran), a regular file without the
 *                 test flag (nothing would be compared), --accel and every secure mode (refused while the glue is absent; with it, only that the tool
 *                 still exits cleanly): exit 2, a usage or setup text on stderr; a missing keyring is 2
 *   open          a missing image, a wrong key, a file of another size: exit 3, the "result open ok=0" or "error" record; the key text never appears in
 *                 any output
 *   a clean run   every phase and direction, both key types, image orders 14 and 16 with an odd number of bytes past the last sector: exit 0, the records
 *                 plan / image / device / phase / scan / stats / result, and afterwards the file equals the bytes in the simulator's store (independently)
 *   replay        the same --seed gives the same bytes in the store
 *   a difference  --corrupt-at OFF:core|device|model: exit 1, a "diff" record with every field of its shape and the verdict that matches the table; ":once"
 *                 on the device is a transient (exit 0 and a "retry" record); a scan alone over an image somebody else wrote is a "core" difference
 *   exit 4        the OSDs stop answering after the image is open and --stall-ms is short: exit 4 and a "stall" record
 *   conn modes    the connection counters of the core (module krbd-conn-modes): the stats record ends with conns_secure= conns_crc= sec_failures= after the unchanged older
 *                 fields (a default run: crc connections only, no new record, no warning); --require-mode secure|crc over servers that allow both modes, one mode, or
 *                 different modes for the monitor and the OSDs: met = exit 0 and "result require_mode ok=1"; one connection in the other mode = exit 5, a stderr line,
 *                 "result require_mode ok=0", the comparison's own result printed ok=0 exit=5, the data still equal; a difference (1) keeps its code; an offer that
 *                 can never meet the assertion and a bad value are exit 2; --mode secure without it only warns; a tag failure in secure mode (a bit flipped in a server
 *                 frame) is counted in sec_failures and fails --require-mode secure while the data stay right
 */
#include "cmp_rig.h"
#include "sim_osd_int.h"

#define OUTCAP (1024u * 1024u)
#define IMG_ORDER 16u
#define IMG_SIZE (40u * 65536u + 21504u + 100u)

static char g_tool[512], g_dir[128], g_kr[192], g_kr_bad[192], g_b64[128], g_b64_bad[128];
static char OUT[OUTCAP];
static unsigned g_nimg;

static int has(const char *out, const char *s)
{
	return strstr(out, s) != NULL;
}

static unsigned long long field_u(const char *out, const char *key)
{
	const char *p = strstr(out, key);

	return p == NULL ? ~0ull : strtoull(p + strlen(key), NULL, 10);
}

/* Run the tool with `args` (NULL terminated). out gets stdout + stderr. `trigger` (may be NULL): the first time it shows up in the output, hook() is
 * called (from this thread). Returns the exit status, -1 if it did not exit normally. */
static int run_tool_ex(char *const *args, char *out, size_t cap, unsigned secs, const char *trigger, void (*hook)(void))
{
	int pfd[2], status = 0, fired = 0;
	size_t n = 0;
	pid_t pid;
	uint64_t t_end = cr_now_ms() + secs * 1000u;

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
		if (cr_now_ms() > t_end) {
			fprintf(stderr, "tool did not finish in %u s: killed\n", secs);
			kill(pid, SIGKILL);
			break;
		}
		if (poll(&pf, 1, 100) <= 0)
			continue;
		if (n + 1u >= cap)
			r = read(pfd[0], junk, sizeof(junk));
		else {
			r = read(pfd[0], out + n, cap - 1u - n);
			if (r > 0) {
				n += (size_t)r;
				out[n] = '\0';
			}
		}
		if (trigger != NULL && !fired && strstr(out, trigger) != NULL) {
			fired = 1;
			if (hook != NULL)
				hook();
		}
		if (r < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (r <= 0)
			break;
	}
	out[n] = '\0';
	close(pfd[0]);
	(void)waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_tool(char *const *args, char *out, size_t cap, unsigned secs)
{
	return run_tool_ex(args, out, cap, secs, NULL, NULL);
}

#define MAXARGS 60

/* The tool for the image `image` on the file `file`, as the user `winrbd` with the keyring `keyring`, plus the space separated extras. */
static int tool_ex(const char *keyring, const char *image, const char *file, const char *extra, unsigned secs, const char *trigger, void (*hook)(void))
{
	char mon[64], copy[1024];
	char *args[MAXARGS];
	unsigned n = 0;
	char *tok;

	snprintf(mon, sizeof(mon), "127.0.0.1:%u", (unsigned)CR.port[0]);
	args[n++] = (char *)"wr-krbdcmp";
	args[n++] = (char *)"--mon";
	args[n++] = mon;
	args[n++] = (char *)"--user";
	args[n++] = (char *)"winrbd";
	args[n++] = (char *)"--keyring";
	args[n++] = (char *)keyring;
	args[n++] = (char *)"--pool";
	args[n++] = (char *)"pool1";
	args[n++] = (char *)"--image";
	args[n++] = (char *)image;
	args[n++] = (char *)"--dev";
	args[n++] = (char *)file;
	args[n++] = (char *)"--allow-any-target"; /* the simulated images are not named wrtest-*; the refusals themselves are tested with the raw argument lists */
	snprintf(copy, sizeof(copy), "%s", extra);
	for (tok = strtok(copy, " "); tok != NULL && n + 1u < MAXARGS; tok = strtok(NULL, " "))
		args[n++] = tok;
	args[n] = NULL;
	return run_tool_ex(args, OUT, sizeof(OUT), secs, trigger, hook);
}

static int tool(const char *image, const char *file, const char *extra, unsigned secs)
{
	return tool_ex(g_kr, image, file, extra, secs, NULL, NULL);
}

/* A fresh image in the store and an empty file of its size: returns the image name and the file path. */
typedef struct fx {
	char name[32], id[32], prefix[64], file[192];
	uint64_t size;
	uint8_t order;
} fx;

static void fx_new(fx *f, uint8_t order, uint64_t size)
{
	int fd;

	memset(f, 0, sizeof(*f));
	g_nimg++;
	snprintf(f->name, sizeof(f->name), "ti%u", g_nimg);
	snprintf(f->id, sizeof(f->id), "t%04x", g_nimg);
	snprintf(f->prefix, sizeof(f->prefix), "rbd_data.%s", f->id);
	snprintf(f->file, sizeof(f->file), "%s/dev%u.img", g_dir, g_nimg);
	f->size = size;
	f->order = order;
	WRT_CHECK(cr_image_make(f->name, f->id, size, order, 0x21, NULL) == 0);
	fd = open(f->file, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || ftruncate(fd, (off_t)size) != 0)
		abort();
	close(fd);
}

static void fx_free(fx *f)
{
	(void)unlink(f->file);
}

/* The file and the store hold the same bytes (the mirror kept them so; the check reads both independently of the tool). */
static void fx_check_equal(const fx *f)
{
	uint8_t *a = (uint8_t *)malloc((size_t)f->size), *b = (uint8_t *)malloc((size_t)f->size);
	FILE *fp = fopen(f->file, "rb");

	if (a == NULL || b == NULL || fp == NULL)
		abort();
	WRT_CHECK(fread(a, 1, (size_t)f->size, fp) == (size_t)f->size);
	fclose(fp);
	cr_store_read(f->prefix, f->order, 0, b, (size_t)f->size);
	WRT_CHECK(memcmp(a, b, (size_t)f->size) == 0);
	free(a);
	free(b);
}

static int nonzero_anywhere(const fx *f)
{
	uint8_t *b = (uint8_t *)malloc((size_t)f->size);
	size_t i;
	int any = 0;

	if (b == NULL)
		abort();
	cr_store_read(f->prefix, f->order, 0, b, (size_t)f->size);
	for (i = 0; i < f->size && !any; i++)
		any = b[i] != 0u;
	free(b);
	return any;
}

/* ---- tests ----------------------------------------------------------------------------------------------------- */

static void test_arguments_and_refusals(void)
{
	fx f;
	char *a0[] = {(char *)"wr-krbdcmp", NULL};
	char *a1[] = {(char *)"wr-krbdcmp", (char *)"--bogus", NULL};
	int rc;

	fx_new(&f, IMG_ORDER, IMG_SIZE);
	WRT_CHECK_U64(run_tool(a0, OUT, sizeof(OUT), 20), 2);
	WRT_CHECK(has(OUT, "usage:"));
	WRT_CHECK_U64(run_tool(a1, OUT, sizeof(OUT), 20), 2);
	WRT_CHECK(has(OUT, "unknown or incomplete option"));
	rc = tool(f.name, f.file, "--dir sideways --self-test-mirror", 20);
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has(OUT, "--dir takes"));
	WRT_CHECK_U64(tool(f.name, f.file, "--phase everything --self-test-mirror", 20), 2);
	WRT_CHECK_U64(tool(f.name, f.file, "--mode turbo --self-test-mirror", 20), 2);
	WRT_CHECK(has(OUT, "--mode takes"));
	WRT_CHECK_U64(tool(f.name, f.file, "--depth 0 --self-test-mirror", 20), 2);
	WRT_CHECK_U64(tool(f.name, f.file, "--depth 65 --self-test-mirror", 20), 2);
	WRT_CHECK_U64(tool(f.name, f.file, "--discard-gran 3 --self-test-mirror", 20), 2);
	WRT_CHECK_U64(tool(f.name, f.file, "--sector 100 --self-test-mirror", 20), 2);
	WRT_CHECK_U64(tool(f.name, f.file, "--ops many --self-test-mirror", 20), 2);
	WRT_CHECK_U64(tool(f.name, f.file, "--corrupt-at 12:nobody --self-test-mirror", 20), 2);
	WRT_CHECK_U64(tool(f.name, f.file, "--corrupt-at x --self-test-mirror", 20), 2);
	rc = tool(f.name, f.file, "--accel --self-test-mirror", 20);
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has(OUT, "unsupported"));
	/* a regular file is not connected to the image: without the test flag nothing would be compared, so it is refused */
	rc = tool(f.name, f.file, "--phase edges", 20);
	WRT_CHECK_U64(rc, 2);
	WRT_CHECK(has(OUT, "regular file") && has(OUT, "--self-test-mirror"));
	/* a path that is neither a file nor a block device, and one that does not exist */
	WRT_CHECK_U64(tool(f.name, "/dev/null", "--self-test-mirror", 20), 2);
	WRT_CHECK_U64(tool(f.name, "/nonexistent/dev", "--self-test-mirror", 20), 3);
	/* a keyring that cannot be read */
	{
		char *a2[] = {(char *)"wr-krbdcmp", (char *)"--mon", (char *)"127.0.0.1", (char *)"--user", (char *)"u", (char *)"--keyring", (char *)"/nonexistent/k",
			      (char *)"--pool", (char *)"p", (char *)"--image", (char *)"i", (char *)"--dev", f.file, (char *)"--self-test-mirror",
			      (char *)"--allow-any-target", NULL};

		WRT_CHECK_U64(run_tool(a2, OUT, sizeof(OUT), 20), 2);
		WRT_CHECK(has(OUT, "keyring"));
	}
	/* the tool overwrites its image with random data: it only works on lab fixtures (wrtest-*), and on a block device only when that is the krbd
	 * mapping of the very image. Neither refusal may touch the image or the file. */
	{
		static const char *const blk[] = {"/dev/loop0", "/dev/sda", "/dev/vda", "/dev/nvme0n1", "/dev/xvda", "/dev/mmcblk0"};
		char mon[64];
		char *a3[24];
		unsigned n = 0, i;
		struct stat st;
		const char *bd = NULL;

		snprintf(mon, sizeof(mon), "127.0.0.1:%u", (unsigned)CR.port[0]);
		a3[n++] = (char *)"wr-krbdcmp";
		a3[n++] = (char *)"--mon";
		a3[n++] = mon;
		a3[n++] = (char *)"--user";
		a3[n++] = (char *)"winrbd";
		a3[n++] = (char *)"--keyring";
		a3[n++] = g_kr;
		a3[n++] = (char *)"--pool";
		a3[n++] = (char *)"pool1";
		a3[n++] = (char *)"--image";
		a3[n++] = (char *)"img-default";
		a3[n++] = (char *)"--dev";
		a3[n++] = f.file;
		a3[n++] = (char *)"--self-test-mirror";
		a3[n] = NULL;
		WRT_CHECK_U64(run_tool(a3, OUT, sizeof(OUT), 20), 2);
		WRT_CHECK(has(OUT, "refusing image img-default") && !has(OUT, " plan "));
		WRT_CHECK(!nonzero_anywhere(&f));
		for (i = 0; i < sizeof(blk) / sizeof(blk[0]) && bd == NULL; i++)
			if (stat(blk[i], &st) == 0 && S_ISBLK(st.st_mode))
				bd = blk[i];
		if (bd != NULL) { /* only stat()ed by the tool: nothing is opened before the refusal */
			a3[10] = (char *)"wrtest-x";
			a3[12] = (char *)bd;
			a3[13] = NULL;
			WRT_CHECK_U64(run_tool(a3, OUT, sizeof(OUT), 20), 2);
			WRT_CHECK(has(OUT, "is not a krbd device") && has(OUT, "refusing to write") && !has(OUT, " plan "));
		} else {
			fprintf(stderr, "  (no block device node to try the refusal of a foreign device on)\n");
		}
	}
	/* a secure mode: the core refuses it while the glue of part D is absent (WR_E_UNSUPPORTED from wr_config_enable_secure's policies); once the glue
	 * has landed the tool must at least end cleanly (the simulated server here offers crc only: a handshake that fails is exit 3, never a crash) */
	rc = tool(f.name, f.file, "--mode secure --self-test-mirror --timeout 4000 --phase edges", 40);
	if (rc == 2 && has(OUT, "cannot create the client")) {
		WRT_CHECK(has(OUT, "UNSUPPORTED") || has(OUT, "unsupported"));
	} else {
		fprintf(stderr, "  (secure mode is wired: exit %d; the refusal check does not apply)\n", rc);
		WRT_CHECK(rc == 0 || rc == 1 || rc == 3 || rc == 4);
	}
	WRT_CHECK(!has(OUT, g_b64));
	fx_free(&f);
}

static void test_open_failures(void)
{
	fx f, g;
	int rc;

	fx_new(&f, IMG_ORDER, IMG_SIZE);
	rc = tool("nosuchimage", f.file, "--self-test-mirror --timeout 8000", 60);
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(OUT, "result open ok=0") && has(OUT, "WR_E_RBD_NOT_FOUND"));
	rc = tool_ex(g_kr_bad, f.name, f.file, "--self-test-mirror --timeout 1500", 60, NULL, NULL);
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(OUT, "result open ok=0"));
	WRT_CHECK(!has(OUT, g_b64_bad) && !has(OUT, g_b64));
	/* a file that is shorter than the image: the device and the image disagree about the size */
	fx_new(&g, IMG_ORDER, IMG_SIZE);
	WRT_CHECK(truncate(g.file, (off_t)(IMG_SIZE - 4096u)) == 0);
	rc = tool(g.name, g.file, "--self-test-mirror --phase edges", 60);
	WRT_CHECK_U64(rc, 3);
	WRT_CHECK(has(OUT, " error the device holds "));
	WRT_CHECK(!nonzero_anywhere(&g)); /* nothing was written */
	fx_free(&f);
	fx_free(&g);
}

static void check_records_clean(const char *what)
{
	if (!has(OUT, " plan ") || !has(OUT, " image id=") || !has(OUT, " device path=") || !has(OUT, " stats ") || !has(OUT, " result ok=1 exit=0 diffs=0") ||
	    has(OUT, " diff ") || has(OUT, " error ") || has(OUT, g_b64)) {
		fprintf(stderr, "---- %s: records ----\n%s----\n", what, OUT);
		WRT_CHECK(0);
	}
}

static void test_clean_runs(void)
{
	static const struct {
		uint8_t order;
		uint64_t size;
		const char *args;
	} cases[] = {
		{16, IMG_SIZE, "--phase edges --dir all --depth 4"},
		{16, IMG_SIZE, "--phase random --dir all --ops 180 --seed 3 --depth 4 --checkpoint 40 --max-len 200K"},
		{14, 100u * 16384u + 9000u + 77u, "--phase all --dir interleave --ops 120 --seed 4 --depth 8 --checkpoint 50 --chunk 100K"},
		{16, IMG_SIZE, "--phase all --dir core-to-krbd --ops 80 --seed 5 --depth 2 --label case-c2k"},
		{14, 100u * 16384u + 9000u, "--phase all --dir krbd-to-core --ops 80 --seed 6 --depth 1"},
		{16, IMG_SIZE, "--phase scan"},
	};
	unsigned i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		fx f;
		char extra[512];
		int rc;

		fx_new(&f, cases[i].order, cases[i].size);
		snprintf(extra, sizeof(extra), "--self-test-mirror %s", cases[i].args);
		rc = tool(f.name, f.file, extra, 600);
		fprintf(stderr, "  clean run %u (%s): exit %d\n", i, cases[i].args, rc);
		WRT_CHECK_U64(rc, 0);
		check_records_clean(cases[i].args);
		if (i == 0u)
			WRT_CHECK(has(OUT, "phase name=edges") && has(OUT, " scan why=edges ") && has(OUT, "refusals=") && field_u(OUT, " refusals=") >= 9u);
		if (i == 1u)
			WRT_CHECK(has(OUT, "phase name=random") && field_u(OUT, " checkpoints=") >= 3u && field_u(OUT, " writes=") > 0u && has(OUT, "label=-"));
		if (i == 3u)
			WRT_CHECK(has(OUT, "label=case-c2k") && field_u(OUT, " krbd_writes=") == 0u && field_u(OUT, " core_writes=") > 0u);
		if (i == 4u)
			WRT_CHECK(field_u(OUT, " core_writes=") == 0u && field_u(OUT, " krbd_writes=") > 0u);
		if (i == 5u)
			WRT_CHECK(has(OUT, " scan why=scan ") && field_u(OUT, " scans=") == 1u);
		if (i < 5u) {
			WRT_CHECK(nonzero_anywhere(&f));
			fx_check_equal(&f); /* the file the tool kept in step and the store the core wrote */
		}
		fx_free(&f);
	}
}

static void test_verbose(void)
{
	fx f;

	fx_new(&f, IMG_ORDER, IMG_SIZE);
	WRT_CHECK_U64(tool(f.name, f.file, "--self-test-mirror --phase random --dir interleave --ops 40 --seed 9 -v", 300), 0);
	WRT_CHECK(has(OUT, " result ok=1 exit=0 diffs=0") && !has(OUT, g_b64));
	fx_free(&f);
}

static uint64_t seeded_digest(uint64_t seed)
{
	fx f;
	char extra[256];
	uint64_t d = 0;

	fx_new(&f, IMG_ORDER, IMG_SIZE);
	snprintf(extra, sizeof(extra), "--self-test-mirror --phase random --dir all --ops 120 --seed %llu --depth 3", (unsigned long long)seed);
	WRT_CHECK_U64(tool(f.name, f.file, extra, 300), 0);
	d = cr_store_digest(f.prefix, f.order, f.size);
	fx_free(&f);
	return d;
}

static void test_replay(void)
{
	uint64_t a = seeded_digest(21), b = seeded_digest(21), c = seeded_digest(22);

	WRT_CHECK(a != 0u && a == b && a != c);
}

static int diff_shape_ok(const char *out)
{
	static const char *keys[] = {" diff dir=", " op=", " kind=", " writer=", " cls=", " off=", " len=", " lo=", " hi=", " first_diff=", " window=", " core=",
				     " krbd=", " model=", " wcore=", " wkrbd=", " wmodel=", " verdict=", " alone=", " first_pass=", " tries=", " seed="};
	const char *ln = strstr(out, " diff dir=");
	unsigned i;

	if (ln == NULL)
		return 0;
	for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		const char *e = strchr(ln, '\n');
		const char *k = strstr(ln, keys[i]);

		if (k == NULL || (e != NULL && k > e))
			return 0;
	}
	return 1;
}

static void test_differences(void)
{
	static const struct {
		const char *args, *verdict, *alone;
		int rc;
	} cases[] = {
		{"--corrupt-at 5000:core", "core", "core", 1},
		{"--corrupt-at 5000:device", "device", "krbd", 1},
		{"--corrupt-at 5000:model", "model", "model", 1},
		{"--corrupt-at 5000", "device", "krbd", 1},          /* the default witness is the device */
		{"--corrupt-at 5000:device:once", NULL, NULL, 0},    /* a transient: counted, not a failure */
		{"--corrupt-at 5000:core:once", "core", "core", 1},  /* the core is never allowed one */
	};
	unsigned i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		fx f;
		char extra[256];
		int rc;

		fx_new(&f, IMG_ORDER, IMG_SIZE);
		snprintf(extra, sizeof(extra), "--self-test-mirror --phase edges --dir core-to-krbd --depth 3 %s", cases[i].args);
		rc = tool(f.name, f.file, extra, 300);
		fprintf(stderr, "  difference case %u (%s): exit %d\n", i, cases[i].args, rc);
		WRT_CHECK_U64(rc, cases[i].rc);
		if (cases[i].verdict != NULL) {
			char want[64];

			WRT_CHECK(diff_shape_ok(OUT));
			snprintf(want, sizeof(want), " verdict=%s alone=%s ", cases[i].verdict, cases[i].alone);
			WRT_CHECK(has(OUT, want));
			WRT_CHECK(has(OUT, " first_diff=5000 ") && has(OUT, "dir=core-to-krbd") && has(OUT, " result ok=0 exit=1 ") && has(OUT, " diffs=1 "));
			WRT_CHECK(!has(OUT, g_b64));
		} else {
			WRT_CHECK(has(OUT, " retry ") && has(OUT, "transient=1") && has(OUT, " transients=1 ") && has(OUT, " result ok=1 exit=0 diffs=0"));
		}
		fx_free(&f);
	}
	/* the three digests of a model difference: the two clients agree with each other and the model does not */
	{
		fx f;
		const char *ln;
		char dc[32] = "", dk[32] = "", dm[32] = "";
		const char *p;

		fx_new(&f, IMG_ORDER, IMG_SIZE);
		WRT_CHECK_U64(tool(f.name, f.file, "--self-test-mirror --phase edges --dir core-to-krbd --corrupt-at 5000:model", 300), 1);
		ln = strstr(OUT, " diff dir=");
		WRT_CHECK(ln != NULL);
		if (ln != NULL) {
			p = strstr(ln, " core=");
			if (p != NULL)
				sscanf(p, " core=%31s", dc);
			p = strstr(ln, " krbd=");
			if (p != NULL)
				sscanf(p, " krbd=%31s", dk);
			p = strstr(ln, " model=");
			if (p != NULL)
				sscanf(p, " model=%31s", dm);
			WRT_CHECK(strlen(dc) == 16u && strcmp(dc, dk) == 0 && strcmp(dc, dm) != 0);
		}
		fx_free(&f);
	}
	/* a scan alone over an image somebody else wrote: the model is blank, the file is blank (it mirrors the model), the core reads the other
	 * writer's bytes: the core is the odd one */
	{
		fx f;
		uint8_t one = 0x33;
		cr_dev d;

		fx_new(&f, IMG_ORDER, IMG_SIZE);
		cr_dev_init(&d, f.prefix, f.size, f.order);
		cr_dev_store_write(&d, 777, &one, 1);
		WRT_CHECK_U64(tool(f.name, f.file, "--self-test-mirror --phase scan", 300), 1);
		WRT_CHECK(has(OUT, "verdict=core alone=core") && has(OUT, " first_diff=777 "));
		pthread_mutex_destroy(&d.mu);
		fx_free(&f);
	}
}

static void silence_osds(void)
{
	unsigned i;

	cr_lock();
	for (i = 0; i < CR_NOSD; i++)
		sim_osd_faults(CR.osd[i])->silent = 1;
	cr_unlock();
}

static void test_hang(void)
{
	fx f;
	unsigned i;
	int rc;

	fx_new(&f, IMG_ORDER, IMG_SIZE);
	rc = tool_ex(g_kr, f.name, f.file, "--self-test-mirror --phase edges --dir core-to-krbd --stall-ms 1500", 120, " device path=", silence_osds);
	cr_lock();
	for (i = 0; i < CR_NOSD; i++)
		sim_osd_faults(CR.osd[i])->silent = 0;
	cr_unlock();
	WRT_CHECK_U64(rc, 4);
	WRT_CHECK(has(OUT, " stall ") && has(OUT, ": hang") && has(OUT, " result ok=0 exit=4 ") && !has(OUT, " diff "));
	fx_free(&f);
}

/* ---- connection modes ------------------------------------------------------------------------------------------- */

/* A small image for these runs: the portable constant-time GCM of the core is slow in a debug build and every byte of a secure run goes through it twice. */
#define CM_ORDER 14u
#define CM_SIZE (7u * 16384u + 5000u + 77u)

#define ALLOW_CRC 1u
#define ALLOW_SECURE 2u

static void allow_set(sim_m2_cfg *m2, unsigned allow)
{
	unsigned n = 0;

	if (allow & ALLOW_CRC)
		m2->modes[n++] = SIM_M2_MODE_CRC;
	if (allow & ALLOW_SECURE)
		m2->modes[n++] = SIM_M2_MODE_SECURE;
	m2->n_modes = n;
}

/* The connection modes the simulated servers allow from now on (the connections made afterwards): the monitor's mask and the OSDs'. */
static void servers_allow(unsigned mon_allow, unsigned osd_allow)
{
	unsigned i;

	cr_lock();
	allow_set(&CR.mon->cfg.m2, mon_allow);
	for (i = 0; i < CR_NOSD; i++)
		allow_set(&CR.osd[i]->cfg.m2, osd_allow);
	cr_unlock();
}

/* The first record of `kind` in the output (the text after "@<ms> kind "), as a pointer into OUT's copy, or NULL. */
static const char *rec_of(const char *out, const char *kind)
{
	char key[48];
	const char *p = out;

	snprintf(key, sizeof(key), " %s ", kind);
	while ((p = strstr(p, key)) != NULL) {
		const char *b = p;

		while (b > out && b[-1] != '\n')
			b--;
		if (*b == '@') {
			const char *q = b + 1;

			while (*q >= '0' && *q <= '9')
				q++;
			if (q == p)
				return p + strlen(key);
		}
		p += strlen(key);
	}
	return NULL;
}

/* The value of key= on the first stats record, ~0 when it is not there. */
static unsigned long long stat_u(const char *out, const char *key)
{
	const char *r = rec_of(out, "stats"), *e, *k;
	char pat[48];

	if (r == NULL)
		return ~0ull;
	e = strchr(r, '\n');
	snprintf(pat, sizeof(pat), "%s=", key);
	k = strstr(r, pat);
	if (k == NULL || (e != NULL && k > e) || (k != r && k[-1] != ' '))
		return ~0ull;
	return strtoull(k + strlen(pat), NULL, 10);
}

/* The keys of a record in order: every key of `keys` (a space separated list) is there, each after the one before, all on the record's own line. */
static int keys_in_order(const char *rec, const char *keys)
{
	char copy[512];
	const char *line_end = strchr(rec, '\n'), *at = rec;
	char *tok;

	snprintf(copy, sizeof(copy), "%s", keys);
	for (tok = strtok(copy, " "); tok != NULL; tok = strtok(NULL, " ")) {
		char pat[64];
		const char *k;

		snprintf(pat, sizeof(pat), "%s=", tok);
		k = strstr(at, pat);
		if (k == NULL || (line_end != NULL && k > line_end) || (k != rec && k[-1] != ' '))
			return 0;
		at = k + strlen(pat);
	}
	return 1;
}

static const char *const STATS_OLD_KEYS = "ops_done ops_resent ops_failed session_resets ops_hiwater reqs_hiwater io_stalls io_resumes max_gap_ms "
					  "barrier_violations bad_completions model_chunks";
static const char *const RESULT_KEYS = "ok exit diffs transients errors verdict ops reads writes discards zeroes flushes refusals edges core_writes krbd_writes "
				       "core_bytes_written krbd_bytes_written core_bytes_read krbd_bytes_read checkpoints scans scan_core_bytes scan_krbd_bytes seed";

/* A stats record: the older fields in their old order, then conns_secure conns_crc sec_failures, and the line ends right after the last one. */
static int stats_shape_ok(const char *out)
{
	const char *r = rec_of(out, "stats"), *k, *p;

	if (r == NULL || !keys_in_order(r, STATS_OLD_KEYS) || !keys_in_order(r, "model_chunks conns_secure conns_crc sec_failures"))
		return 0;
	k = strstr(r, " sec_failures=");
	if (k == NULL)
		return 0;
	p = k + strlen(" sec_failures=");
	while (*p >= '0' && *p <= '9')
		p++;
	return *p == '\n' || *p == '\0';
}

static const char *out_tail(size_t n)
{
	size_t len = strlen(OUT);

	return len > n ? OUT + (len - n) : OUT;
}

/* A check that shows the tool's output when it fails (these runs depend on the servers and the exit paths: the records are what explains a failure). */
#define CHECK_OUT(cond)                                                                           \
	do {                                                                                      \
		if (!(cond))                                                                      \
			fprintf(stderr, "---- the tool's output (its last 6000 bytes) ----\n%s\n----\n", out_tail(6000));          \
		WRT_CHECK(cond);                                                                  \
	} while (0)

static void test_conn_modes(void)
{
	char b1[16384];
	fx f;
	int rc;

	/* the servers of this rig allow crc only until told otherwise: a default run is all crc, with the three counters appended and nothing else new */
	servers_allow(ALLOW_CRC, ALLOW_CRC);
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool(f.name, f.file, "--self-test-mirror --phase all --dir all --ops 60 --seed 11 --depth 4 --checkpoint 30 --label cm0", 300);
	WRT_CHECK_U64(rc, 0);
	check_records_clean("conn modes: default");
	CHECK_OUT(stats_shape_ok(OUT));
	CHECK_OUT(keys_in_order(rec_of(OUT, "result"), RESULT_KEYS) && has(OUT, " result ok=1 exit=0 diffs=0 "));
	CHECK_OUT(stat_u(OUT, "conns_secure") == 0u && stat_u(OUT, "conns_crc") >= 2u && stat_u(OUT, "sec_failures") == 0u); /* the monitor and at least one OSD */
	CHECK_OUT(!has(OUT, "require_mode") && !has(OUT, "warning"));
	/* exactly one stats record: the fields are appended to the engine's, not printed on a second one */
	{
		const char *a = strstr(OUT, " stats ");

		WRT_CHECK(a != NULL && strstr(a + 1, " stats ") == NULL);
	}
	fx_check_equal(&f);
	fx_free(&f);

	/* --require-mode crc on the same servers is met */
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool(f.name, f.file, "--self-test-mirror --phase edges --dir core-to-krbd --require-mode crc", 300);
	WRT_CHECK_U64(rc, 0);
	CHECK_OUT(has(OUT, " result require_mode ok=1 wanted=crc conns_secure=0 conns_crc="));
	CHECK_OUT(has(OUT, " result ok=1 exit=0 "));
	fx_free(&f);

	/* every server allows both: --mode secure ends in secure on every connection, --require-mode secure is met */
	servers_allow(ALLOW_CRC | ALLOW_SECURE, ALLOW_CRC | ALLOW_SECURE);
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool(f.name, f.file, "--self-test-mirror --mode secure --require-mode secure --phase edges --dir core-to-krbd --depth 4", 300);
	if (rc != 0)
		fprintf(stderr, "---- secure run: exit %d ----\n%s\n", rc, out_tail(4000));
	WRT_CHECK_U64(rc, 0);
	check_records_clean("conn modes: all secure");
	CHECK_OUT(stats_shape_ok(OUT));
	CHECK_OUT(stat_u(OUT, "conns_secure") >= 2u && stat_u(OUT, "conns_crc") == 0u && stat_u(OUT, "sec_failures") == 0u);
	snprintf(b1, sizeof(b1), " result require_mode ok=1 wanted=secure conns_secure=%llu conns_crc=0 sec_failures=0\n", stat_u(OUT, "conns_secure"));
	CHECK_OUT(has(OUT, b1));
	CHECK_OUT(!has(OUT, "warning") && !has(OUT, "--require-mode secure:"));
	fx_check_equal(&f);
	fx_free(&f);

	/* --mode secure without --require-mode: the same counters, no assertion, no warning when nothing was crc */
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool(f.name, f.file, "--self-test-mirror --mode secure --phase scan", 300);
	WRT_CHECK_U64(rc, 0);
	CHECK_OUT(stat_u(OUT, "conns_secure") >= 2u && stat_u(OUT, "conns_crc") == 0u);
	CHECK_OUT(!has(OUT, "require_mode") && !has(OUT, "warning"));
	fx_free(&f);

	/* --require-mode crc when the connections were secure (the offer does not exclude it: secure-first against servers that allow both) */
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool(f.name, f.file, "--self-test-mirror --mode secure-first --require-mode crc --phase scan", 300);
	WRT_CHECK_U64(rc, 5);
	CHECK_OUT(has(OUT, " result require_mode ok=0 wanted=crc ") && has(OUT, "wr-krbdcmp: --require-mode crc: "));
	CHECK_OUT(has(OUT, " result ok=0 exit=5 diffs=0 "));
	fx_free(&f);

	/* A connection in crc mode (the monitor's, in this rig): the monitor allows crc only, the OSDs secure; the offer is secure-first for the monitor and secure for the OSDs. The run itself
	 * is fine (the data agree), --require-mode secure fails it with exit 5 and says why */
	servers_allow(ALLOW_CRC, ALLOW_SECURE);
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool(f.name, f.file, "--self-test-mirror --mode secure-first --mode-osd secure --phase scan", 300);
	WRT_CHECK_U64(rc, 0); /* without --require-mode: as before, exit 0 and no warning (secure-first accepts crc) */
	CHECK_OUT(stats_shape_ok(OUT) && stat_u(OUT, "conns_crc") >= 1u && stat_u(OUT, "conns_secure") >= 1u && !has(OUT, "warning") && !has(OUT, "require_mode"));
	fx_free(&f);
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool(f.name, f.file, "--self-test-mirror --mode secure-first --mode-osd secure --require-mode secure --phase edges --dir core-to-krbd --depth 4", 300);
	if (rc != 5)
		fprintf(stderr, "---- one crc connection: exit %d ----\n%s\n", rc, out_tail(4000));
	WRT_CHECK_U64(rc, 5);
	CHECK_OUT(stats_shape_ok(OUT) && stat_u(OUT, "conns_crc") >= 1u && stat_u(OUT, "conns_secure") >= 1u && stat_u(OUT, "sec_failures") == 0u);
	snprintf(b1, sizeof(b1), " result require_mode ok=0 wanted=secure conns_secure=%llu conns_crc=%llu sec_failures=0\n", stat_u(OUT, "conns_secure"), stat_u(OUT, "conns_crc"));
	CHECK_OUT(has(OUT, b1));
	snprintf(b1, sizeof(b1), "wr-krbdcmp: --require-mode secure: %llu secure and %llu crc connection(s) reached READY, 0 secure-mode failure(s)\n", stat_u(OUT, "conns_secure"),
		 stat_u(OUT, "conns_crc"));
	CHECK_OUT(has(OUT, b1));
	/* the comparison's own result record says what the process exits with, the rest of it is as it was */
	CHECK_OUT(has(OUT, " result ok=0 exit=5 diffs=0 ") && keys_in_order(rec_of(OUT, "result"), RESULT_KEYS) && !has(OUT, " diff ") && !has(OUT, " error "));
	CHECK_OUT(!has(OUT, g_b64));
	fx_check_equal(&f); /* the data were compared and agree: the failure is about the connections only */
	fx_free(&f);

	/* a difference outranks it: exit 1, the require_mode record still says what was counted, the result record is the engine's own */
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool(f.name, f.file, "--self-test-mirror --mode secure-first --mode-osd secure --require-mode secure --phase scan --corrupt-at 5000:core", 300);
	WRT_CHECK_U64(rc, 1);
	CHECK_OUT(has(OUT, " result ok=0 exit=1 ") && has(OUT, " result require_mode ok=0 wanted=secure "));
	fx_free(&f);

	/* an unreachable open: exit 3 whatever --require-mode says, and the record is there */
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool("nosuchimage", f.file, "--self-test-mirror --mode secure --require-mode secure --timeout 5000", 60);
	WRT_CHECK_U64(rc, 3);
	CHECK_OUT(has(OUT, " result open ok=0") && has(OUT, " result require_mode ")); /* the counters of the failed open; the exit status stays the open failure's */
	fx_free(&f);

	/* nothing connected at all (a wrong key: no connection reaches READY): zero connections is not "every connection was secure". The record must say ok=0 with both counters
	 * 0 (a check that only asks for "no crc connection" would pass it), and so for the crc assertion; the exit status stays the open failure's (3) */
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool_ex(g_kr_bad, f.name, f.file, "--self-test-mirror --mode secure --require-mode secure --timeout 3000", 60, NULL, NULL);
	WRT_CHECK_U64(rc, 3);
	CHECK_OUT(has(OUT, " result open ok=0"));
	CHECK_OUT(has(OUT, " result require_mode ok=0 wanted=secure conns_secure=0 conns_crc=0 "));
	CHECK_OUT(has(OUT, "wr-krbdcmp: --require-mode secure: 0 secure and 0 crc connection(s) reached READY"));
	CHECK_OUT(!has(OUT, " stats ") && !has(OUT, g_b64_bad) && !has(OUT, g_b64));
	rc = tool_ex(g_kr_bad, f.name, f.file, "--self-test-mirror --mode crc-first --require-mode crc --timeout 3000", 60, NULL, NULL);
	WRT_CHECK_U64(rc, 3);
	CHECK_OUT(has(OUT, " result require_mode ok=0 wanted=crc conns_secure=0 conns_crc=0 "));
	fx_free(&f);

	/* --mode secure and a crc connection, without --require-mode: a warning on stderr, exit status as before (0) */
	servers_allow(ALLOW_CRC | ALLOW_SECURE, ALLOW_CRC | ALLOW_SECURE);
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool(f.name, f.file, "--self-test-mirror --mode secure --mode-osd crc --phase scan", 300);
	WRT_CHECK_U64(rc, 0);
	CHECK_OUT(stat_u(OUT, "conns_secure") >= 1u && stat_u(OUT, "conns_crc") >= 1u);
	CHECK_OUT(has(OUT, "wr-krbdcmp: warning: --mode secure was asked for but ") && has(OUT, " connection(s) reached READY in crc mode "));
	CHECK_OUT(!has(OUT, "require_mode"));
	fx_check_equal(&f);
	fx_free(&f);

	/* arguments: a bad value, and offers that exclude the assertion, are refused before anything runs */
	fx_new(&f, CM_ORDER, CM_SIZE);
	WRT_CHECK_U64(tool(f.name, f.file, "--self-test-mirror --require-mode turbo", 20), 2);
	CHECK_OUT(has(OUT, "--require-mode takes secure or crc") && !has(OUT, " plan "));
	WRT_CHECK_U64(tool(f.name, f.file, "--self-test-mirror --require-mode secure", 20), 2); /* the default offer is crc */
	CHECK_OUT(has(OUT, "can never be met") && !has(OUT, " plan "));
	WRT_CHECK_U64(tool(f.name, f.file, "--self-test-mirror --mode secure --require-mode crc", 20), 2);
	WRT_CHECK_U64(tool(f.name, f.file, "--self-test-mirror --mode secure --mode-osd crc --require-mode secure", 20), 2);
	CHECK_OUT(has(OUT, "can never be met") && has(OUT, "--mode-osd crc"));
	WRT_CHECK_U64(tool(f.name, f.file, "--self-test-mirror --mode crc-first --mode-osd crc --require-mode secure", 20), 2);
	WRT_CHECK_U64(tool(f.name, f.file, "--self-test-mirror --require-mode", 20), 2); /* a value is missing */
	CHECK_OUT(!nonzero_anywhere(&f));
	fx_free(&f);

	servers_allow(ALLOW_CRC, ALLOW_CRC);
}

/* A frame of a secure connection whose tag does not verify (the server flips a bit of the next frame it sends) is a secure-mode failure the engine counts and redials
 * after: the data stay right, sec_failures says so, and --require-mode secure does not read it as a clean secure run. A thread of the test damages the next frame of
 * every secure OSD connection that exists, every 120 ms, three times (the technique of test_host_tool_rbd_sec.c: the connection's own copy of the fault is set under the
 * rig's lock), from the moment the tool has opened the image until it ends. */
static struct {
	volatile int run;
	unsigned budget, armed;
	pthread_t th;
	int started;
} FL;

static void *flip_main(void *arg)
{
	(void)arg;
	while (FL.run && FL.budget != 0u) {
		unsigned k, n = 0;

		usleep(120000);
		cr_lock();
		for (k = 0; k < CR_SMAX; k++) {
			sim_m2 *m;

			if (CR.c[k].fd < 0 || CR.c[k].oc == NULL)
				continue;
			m = CR.c[k].oc->m2;
			if (!sim_m2_is_secure(m))
				continue;
			memset(&m->cfg.f.sec, 0, sizeof(m->cfg.f.sec));
			m->cfg.f.sec.mut_frame = m->n_tx_frames + 1u; /* the next frame this server sends: one bit of part 1's ciphertext, so the tag cannot match */
			m->cfg.f.sec.mut.mask = SIM_SEC_M_FLIP;
			m->cfg.f.sec.mut.flip_part = 1;
			m->cfg.f.sec.mut.flip_region = SIM_SEC_R_RAW;
			m->cfg.f.sec.mut.flip_byte = 3;
			m->cfg.f.sec.mut.flip_bit = 0;
			n++;
		}
		cr_unlock();
		if (n != 0u) {
			FL.armed++;
			FL.budget--;
		}
	}
	return NULL;
}

static void flips_start(void)
{
	FL.run = 1;
	FL.budget = 3;
	FL.armed = 0;
	FL.started = pthread_create(&FL.th, NULL, flip_main, NULL) == 0;
	WRT_CHECK(FL.started);
}

static void test_tag_failure(void)
{
	fx f;
	int rc;

	servers_allow(ALLOW_CRC | ALLOW_SECURE, ALLOW_CRC | ALLOW_SECURE);
	fx_new(&f, CM_ORDER, CM_SIZE);
	rc = tool_ex(g_kr, f.name, f.file, "--self-test-mirror --mode secure --require-mode secure --phase edges --dir core-to-krbd --depth 4 --stall-ms 60000", 600,
		     " device path=", flips_start);
	FL.run = 0;
	if (FL.started)
		pthread_join(FL.th, NULL);
	FL.started = 0;
	if (rc != 5 || FL.armed == 0u)
		fprintf(stderr, "---- tag failure: exit %d, %u flips armed ----\n%s\n", rc, FL.armed, out_tail(6000));
	WRT_CHECK(FL.armed >= 1u); /* the damage really happened */
	WRT_CHECK_U64(rc, 5);
	CHECK_OUT(stat_u(OUT, "sec_failures") >= 1u && stat_u(OUT, "conns_crc") == 0u && stat_u(OUT, "conns_secure") >= 3u);
	CHECK_OUT(has(OUT, " result require_mode ok=0 wanted=secure ") && has(OUT, " result ok=0 exit=5 diffs=0 ") && !has(OUT, " diff "));
	fx_check_equal(&f); /* the engine redialled: no wrong byte */
	fx_free(&f);
	servers_allow(ALLOW_CRC, ALLOW_CRC);
}

int main(void)
{
	const char *exe = getenv("WR_KRBDCMP");
	char dir[] = "/tmp/wr-krbdcmp-test-XXXXXX";
	uint64_t t0;

	if (exe == NULL || *exe == '\0')
		WRT_SKIP("WR_KRBDCMP (the path of the wr-krbdcmp tool) is not set");
	snprintf(g_tool, sizeof(g_tool), "%s", exe);
	if (mkdtemp(dir) == NULL)
		abort();
	snprintf(g_dir, sizeof(g_dir), "%s", dir);
	snprintf(g_kr, sizeof(g_kr), "%s/good.keyring", g_dir);
	snprintf(g_kr_bad, sizeof(g_kr_bad), "%s/bad.keyring", g_dir);
	signal(SIGPIPE, SIG_IGN);
	cr_srv_start(WR_KEY_TYPE_AES256K);
	cr_write_keyring(g_kr, WR_KEY_TYPE_AES256K, 1, g_b64);
	cr_write_keyring(g_kr_bad, WR_KEY_TYPE_AES256K, 99, g_b64_bad);
#define RUN(t)                                                                                    \
	do {                                                                                      \
		t0 = cr_now_ms();                                                                 \
		t;                                                                                \
		fprintf(stderr, "  %-40s %6llu ms\n", #t, (unsigned long long)(cr_now_ms() - t0)); \
	} while (0)
	RUN(test_arguments_and_refusals());
	RUN(test_open_failures());
	RUN(test_clean_runs());
	RUN(test_verbose());
	RUN(test_replay());
	RUN(test_differences());
	RUN(test_hang());
	RUN(test_conn_modes());
	RUN(test_tag_failure());
	cr_srv_stop();
	/* the legacy key type: the server and the keyring change, the tool does not */
	cr_srv_start(WR_KEY_TYPE_AES);
	cr_write_keyring(g_kr, WR_KEY_TYPE_AES, 1, g_b64);
	{
		fx f;

		fx_new(&f, IMG_ORDER, IMG_SIZE);
		RUN(WRT_CHECK_U64(tool(f.name, f.file, "--self-test-mirror --phase all --dir all --ops 90 --seed 8 --depth 4 --checkpoint 40", 300), 0));
		check_records_clean("legacy key");
		fx_check_equal(&f);
		fx_free(&f);
	}
	cr_srv_stop();
#undef RUN
	{
		char path[256];
		static const char *names[] = {"good.keyring", "bad.keyring"};
		unsigned i;

		for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
			snprintf(path, sizeof(path), "%s/%s", g_dir, names[i]);
			(void)unlink(path);
		}
		(void)rmdir(g_dir);
	}
	return wrt_finish();
}
