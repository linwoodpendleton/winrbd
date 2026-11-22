/* SPDX-License-Identifier: MIT */
/*
 * test_host_cmp.c - the krbd comparison engine (harness/host/wrl_cmp.c, docs/design/core-architecture.md 33.6), ctest host.cmp.
 *
 * The core talks to a simulated monitor and three simulated OSDs over real TCP sockets (cmp_rig.h); the "kernel client" is an in-process device
 * implemented on the simulator's own object store, with the geometry the DEVICE believes (so a test can make it differ from the core's) and knobs
 * that make it misbehave. The engine, with all three witnesses, runs against them. Checked:
 *
 *   phases        every phase and direction at the orders of the lab matrix (12, 16, 18, 20, 22, 25), images with a partial last object and, in two of
 *                 them, an odd number of bytes past the last sector: exit 0, every kind of operation done, both writers used, refusals of every
 *                 past-the-end op by the core and by the device, scans at the checkpoints and at the end of the phases, both key types
 *   determinism   the same seed gives the same bytes in the store whatever the depth (1, 4, 16: operations in flight never overlap in range, so the end
 *                 state is a function of the operations alone); another seed gives other bytes
 *   attribution   a model that drifts is reported as "model" (the two readers agree with each other); a device that flips a byte on read as "device"
 *                 after the re-read; one flip that does not repeat is a counted transient, not a failure; a core made wrong by the simulator (the header it
 *                 is served makes it address other objects than the device does) as "core"; a core and a device that are both wrong, differently, as
 *                 "both"; a device that writes one byte too many as "model" with the writer named; the three digests in the record are the ones that
 *                 attribution needs (equal where the table says equal)
 *   past the end  a device that accepts a request at its end is a "device" difference
 *   exit 4        a device that fails with EIO, one that answers short, one that is slow past --stall-ms and one that hangs (a virtual clock decides: no
 *                 wall-clock speed is involved), OSDs that stop answering: exit 4 with the record that says what hung; a slow device within the limit is fine
 *   exit 3        a device whose size is not the image's, an image opened read-only
 *   knobs         --time (a wall clock bound, the only one used), a memory budget far below the size of one operation, depth 64
 */
#include "cmp_rig.h"
#include "wrl_cmp.h"

/* ---- the client of the engine ------------------------------------------------------------------------------------ */

typedef struct world {
	wr_client *c;
	wrl_loop *l;
	wr_image *img;
	wr_mem_region arena, bulk;
} world;

static unsigned g_level = WR_LOG_ERR;

static int world_open(world *w, const char *image, unsigned key_type, int want_write)
{
	wr_config cfg;
	wr_host_ops ops;
	wr_cluster_spec spec;
	wr_mem_req req;
	wr_image_params p;
	char mon[64];
	size_t nmon = 0;
	uint64_t limit = cr_now_ms() + 30000u;

	memset(w, 0, sizeof(*w));
	wr_config_profile_harness(&cfg);
	wr_config_enable_maps(&cfg, WR_MAPS_HARNESS);
	wr_config_enable_osd(&cfg, WR_MAPS_HARNESS);
	cfg.mon_msg_cap = 8u * 1024u * 1024u;
	cfg.max_images = 1;
	wrl_host_ops_init(&ops, &g_level);
	memset(&spec, 0, sizeof(spec));
	strcpy(spec.user, "winrbd");
	cr_mkkey(&spec.key, key_type, 1);
	snprintf(mon, sizeof(mon), "127.0.0.1:%u", (unsigned)CR.port[0]);
	WRT_CHECK_STATUS(WR_OK, wr_mon_parse_hosts(mon, strlen(mon), spec.mons, WR_MAX_MONS, &nmon));
	spec.n_mons = (uint8_t)nmon;
	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&cfg, &req));
	WRT_CHECK_STATUS(WR_OK, wrl_mem_alloc(&w->arena, req.arena));
	WRT_CHECK_STATUS(WR_OK, wrl_mem_alloc(&w->bulk, req.bulk));
	WRT_CHECK_STATUS(WR_OK, wr_client_create(&cfg, &ops, &spec, w->arena, w->bulk, &w->c));
	wr_key_wipe(&spec.key);
	WRT_CHECK_STATUS(WR_OK, wrl_loop_create(w->c, &w->l));
	memset(&p, 0, sizeof(p));
	p.size = (uint32_t)sizeof(p);
	p.pool = "pool1";
	p.name = image;
	p.snap_id = WR_SNAP_HEAD;
	p.open_timeout_ms = 20000;
	p.want_write = (uint8_t)want_write;
	WRT_CHECK_STATUS(WR_OK, wr_image_open(w->c, &p, &w->img));
	while (wr_image_get_state(w->img) == WR_IMG_OPENING && cr_now_ms() < limit) {
		wr_event ev;

		(void)wrl_loop_step(w->l, 20);
		while (wr_client_next_event(w->c, &ev))
			;
	}
	return wr_image_get_state(w->img) == WR_IMG_OPEN ? 0 : -1;
}

static void world_close(world *w)
{
	if (w->img != NULL && wr_image_close(w->img, WR_CLOSE_ABANDON) != WR_OK)
		fprintf(stderr, "  (the image was already closed)\n");
	wrl_loop_destroy(w->l);
	wr_client_destroy(w->c);
	wrl_mem_free(&w->arena);
	wrl_mem_free(&w->bulk);
	memset(w, 0, sizeof(*w));
}

/* ---- images, devices, a run ----------------------------------------------------------------------------------------- */

static cr_dev DEVS[48]; /* never freed or reused: a device call abandoned by a hang may still be running when its test is over */
static unsigned g_ndev, g_nimg;

typedef struct img {
	char name[32], id[32], prefix[64];
	uint64_t size;
	uint8_t order;
	cr_dev *dev;
} img;

static void img_new(img *im, uint8_t order, uint64_t size)
{
	memset(im, 0, sizeof(*im));
	g_nimg++;
	snprintf(im->name, sizeof(im->name), "ci%u", g_nimg);
	snprintf(im->id, sizeof(im->id), "c%04x", g_nimg);
	snprintf(im->prefix, sizeof(im->prefix), "rbd_data.%s", im->id);
	im->size = size;
	im->order = order;
	if (g_ndev >= sizeof(DEVS) / sizeof(DEVS[0]))
		abort();
	im->dev = &DEVS[g_ndev++];
	cr_dev_init(im->dev, im->prefix, size, order);
	WRT_CHECK(cr_image_make(im->name, im->id, size, order, 0x21, NULL) == 0);
}

typedef struct rr {
	wrl_cmp_cfg cfg;
	wrl_cmp_result res;
	int rc;
	char out[1u << 18];
} rr;

static void rr_defaults(rr *r)
{
	memset(r, 0, sizeof(*r));
	r->cfg.dirs = WRL_CMP_DIR_ALL;
	r->cfg.phases = WRL_CMP_PH_ALL;
	r->cfg.ops = 120;
	r->cfg.depth = 4;
	r->cfg.checkpoint = 50;
	r->cfg.seed = 1;
	r->cfg.chunk = 256u * 1024u;
	r->cfg.max_len = 256u * 1024u;
	r->cfg.stall_ms = 120000;
}

/* Open `core_image` as the core's view, run the engine with `dev` as the device, collect the records. */
static void run(rr *r, const char *core_image, cr_dev *dev, unsigned key_type)
{
	world w;
	FILE *f = tmpfile();
	size_t n;

	if (f == NULL)
		abort();
	if (world_open(&w, core_image, key_type, 1) != 0) {
		WRT_CHECK(0);
		world_close(&w);
		fclose(f);
		r->rc = -1;
		return;
	}
	r->cfg.client = w.c;
	r->cfg.loop = w.l;
	r->cfg.img = w.img;
	r->cfg.dev.ctx = dev;
	r->cfg.dev.pread = cr_dev_pread;
	r->cfg.dev.pwrite = cr_dev_pwrite;
	r->cfg.dev.discard = cr_dev_discard;
	r->cfg.dev.zeroes = cr_dev_zeroes;
	r->cfg.dev.flush = cr_dev_flush;
	r->cfg.dev.size = cr_dev_size;
	r->cfg.dev.sector = dev->sector;
	r->cfg.discard_gran = dev->gran;
	r->cfg.out = f;
	r->rc = wrl_cmp_run(&r->cfg, &r->res);
	rewind(f);
	n = fread(r->out, 1, sizeof(r->out) - 1u, f);
	r->out[n] = '\0';
	fclose(f);
	world_close(&w);
	WRT_CHECK_U64(r->res.exit_code, r->rc);
}

static const char *line_with(const char *out, const char *needle)
{
	const char *p = strstr(out, needle);

	while (p != NULL && p > out && p[-1] != '\n')
		p--;
	return p;
}

static int fld(const char *line, const char *key, char *dst, size_t cap)
{
	const char *p, *q;
	size_t n;

	if (line == NULL)
		return -1;
	for (p = line; (p = strstr(p, key)) != NULL; p++) {
		if (p == line || p[-1] == ' ')
			break;
	}
	if (p == NULL)
		return -1;
	p += strlen(key);
	for (q = p; *q != '\0' && *q != ' ' && *q != '\n'; q++)
		;
	n = (size_t)(q - p);
	if (n >= cap)
		n = cap - 1u;
	memcpy(dst, p, n);
	dst[n] = '\0';
	return 0;
}

static int has(const char *out, const char *s)
{
	return strstr(out, s) != NULL;
}

static void show(const char *what, const rr *r)
{
	fprintf(stderr, "  %-34s rc=%d ops=%llu/%llu/%llu/%llu/%llu wc=%llu wd=%llu scans=%llu ckpt=%llu transient=%llu\n", what, r->rc,
		(unsigned long long)r->res.ops[WRL_CMP_K_READ], (unsigned long long)r->res.ops[WRL_CMP_K_WRITE],
		(unsigned long long)r->res.ops[WRL_CMP_K_DISCARD], (unsigned long long)r->res.ops[WRL_CMP_K_ZEROES],
		(unsigned long long)r->res.ops[WRL_CMP_K_FLUSH], (unsigned long long)r->res.writes_core, (unsigned long long)r->res.writes_dev,
		(unsigned long long)r->res.scans, (unsigned long long)r->res.checkpoints, (unsigned long long)r->res.transients);
}

static void dump_on_failure(const rr *r, int expect_rc)
{
	if (r->rc != expect_rc) {
		fprintf(stderr, "---- records of the failed run (rc %d, wanted %d) ----\n%s----\n", r->rc, expect_rc, r->out);
	}
}

/* ---- tests -------------------------------------------------------------------------------------------------------- */

static uint32_t n_edges(const img *im, unsigned sector, unsigned *npast)
{
	static wrl_cmp_edge l[WRL_CMP_EDGES_MAX];
	wrl_cmp_geom g;
	uint32_t n, i;

	g.size = im->size;
	g.order = im->order;
	g.sector = sector;
	n = wrl_cmp_edges_build(&g, l, WRL_CMP_EDGES_MAX);
	*npast = 0;
	for (i = 0; i < n; i++)
		*npast += l[i].kind == WRL_CMP_K_PAST ? 1u : 0u;
	return n;
}

static void test_phases(uint8_t order, uint64_t size, unsigned key_type, uint64_t max_len, uint64_t ops, unsigned phases)
{
	static rr r;
	img im;
	unsigned npast = 0;
	uint32_t ne;
	char name[64];

	img_new(&im, order, size);
	ne = n_edges(&im, 512, &npast);
	rr_defaults(&r);
	r.cfg.phases = phases;
	r.cfg.ops = ops;
	r.cfg.checkpoint = ops / 6u;
	r.cfg.max_len = max_len;
	run(&r, im.name, im.dev, key_type);
	snprintf(name, sizeof(name), "phases order %u key %u", (unsigned)order, key_type);
	show(name, &r);
	dump_on_failure(&r, 0);
	WRT_CHECK_U64(r.rc, 0);
	WRT_CHECK_U64(r.res.diffs, 0);
	WRT_CHECK_U64(r.res.errors, 0);
	WRT_CHECK_U64(r.res.transients, 0);
	WRT_CHECK_U64(r.res.barrier_violations, 0);
	WRT_CHECK_U64(r.res.bad_completions, 0);
	WRT_CHECK(r.res.ops[WRL_CMP_K_READ] > 0u && r.res.ops[WRL_CMP_K_WRITE] > 0u && r.res.ops[WRL_CMP_K_DISCARD] > 0u);
	WRT_CHECK(r.res.writes_core > 0u && r.res.writes_dev > 0u && r.res.bytes_written_core > 0u && r.res.bytes_written_dev > 0u);
	if (phases & WRL_CMP_PH_EDGES) {
		WRT_CHECK_U64(r.res.edges_run, 3u * ne);
		WRT_CHECK_U64(r.res.refusals_ok, 3u * npast);
		WRT_CHECK(npast >= 3u);
		WRT_CHECK(r.res.ops[WRL_CMP_K_ZEROES] > 0u && r.res.ops[WRL_CMP_K_FLUSH] > 0u);
	}
	WRT_CHECK(r.res.scans >= 5u && r.res.checkpoints >= 3u); /* the end of edges, a checkpoint per direction, the end of random */
	WRT_CHECK(r.res.scan_bytes_core >= im.size && r.res.scan_bytes_dev >= im.size - im.size % 512u);
	WRT_CHECK(im.dev->n_read > 0u && im.dev->n_write > 0u);
	WRT_CHECK(has(r.out, " plan label=") && has(r.out, "phase name=random") && has(r.out, " scan why=random") && has(r.out, " result ok=1 exit=0 diffs=0"));
	if (phases & WRL_CMP_PH_EDGES)
		WRT_CHECK(has(r.out, "phase name=edges") && has(r.out, " scan why=edges") && im.dev->n_discard > 0u && im.dev->n_zero > 0u && im.dev->n_flush > 0u);
	WRT_CHECK(!has(r.out, " diff ") && !has(r.out, " error "));
}

static uint64_t run_digest(uint8_t order, uint64_t size, uint64_t seed, unsigned depth, uint64_t ops)
{
	static rr r;
	img im;

	img_new(&im, order, size);
	rr_defaults(&r);
	r.cfg.seed = seed;
	r.cfg.depth = depth;
	r.cfg.ops = ops;
	r.cfg.checkpoint = UINT64_MAX; /* a scan in the middle changes no bytes, but keeps the run short */
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	dump_on_failure(&r, 0);
	WRT_CHECK_U64(r.rc, 0);
	return cr_store_digest(im.prefix, order, size);
}

static void test_determinism(void)
{
	uint64_t a = run_digest(16, 40u * 65536u + 21504u + 100u, 5, 4, 150);
	uint64_t b = run_digest(16, 40u * 65536u + 21504u + 100u, 5, 4, 150);
	uint64_t c = run_digest(16, 40u * 65536u + 21504u + 100u, 5, 1, 150);
	uint64_t d = run_digest(16, 40u * 65536u + 21504u + 100u, 5, 16, 150);
	uint64_t e = run_digest(16, 40u * 65536u + 21504u + 100u, 6, 4, 150);

	WRT_CHECK(a != 0u);
	WRT_CHECK_U64(b, a); /* the same seed, the same bytes ... */
	WRT_CHECK_U64(c, a); /* ... whatever the number of operations in flight ... */
	WRT_CHECK_U64(d, a);
	WRT_CHECK(e != a);   /* ... and another seed gives other bytes */
	fprintf(stderr, "  determinism: digest %016llx at depth 1, 4, 16\n", (unsigned long long)a);
}

/* A run on a small image that is meant to find one difference: edges in one direction, random after it. */
static void small_run(rr *r, img *im, unsigned dir, unsigned phases)
{
	img_new(im, 16, 40u * 65536u + 21504u);
	rr_defaults(r);
	r->cfg.dirs = dir;
	r->cfg.phases = phases;
	r->cfg.ops = 90;
	r->cfg.depth = 3;
	r->cfg.seed = 11;
}

static void test_attribution(void)
{
	static rr r;
	img im, ia;
	char v[32], al[32], dc[32], dk[32], dm[32], tries[8];
	const char *ln;

	/* the model drifts: one byte of the model changes, both readers still agree with each other */
	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_EDGES);
	r.cfg.corrupt = WRL_CMP_CORRUPT_MODEL;
	r.cfg.corrupt_off = 5000;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("model drift", &r);
	WRT_CHECK_U64(r.rc, 1);
	ln = line_with(r.out, " diff ");
	WRT_CHECK(ln != NULL && fld(ln, "verdict=", v, sizeof(v)) == 0 && strcmp(v, "model") == 0);
	WRT_CHECK(fld(ln, "alone=", al, sizeof(al)) == 0 && strcmp(al, "model") == 0);
	WRT_CHECK(fld(ln, "core=", dc, sizeof(dc)) == 0 && fld(ln, "krbd=", dk, sizeof(dk)) == 0 && fld(ln, "model=", dm, sizeof(dm)) == 0);
	WRT_CHECK(strcmp(dc, dk) == 0 && strcmp(dc, dm) != 0); /* the two clients agree, the model is the odd one */
	WRT_CHECK(has(r.out, " first_diff=5000 ") && has(r.out, "dir=core-to-krbd") && has(r.out, " result ok=0 exit=1 ") && has(r.out, "verdict=model"));
	WRT_CHECK_U64(r.res.diffs, 1);
	WRT_CHECK_U64(r.res.diff_first, 5000);
	WRT_CHECK_U64(r.res.dig_core, r.res.dig_dev);
	WRT_CHECK(r.res.dig_core != r.res.dig_model);
	WRT_CHECK(strcmp(r.res.verdict, "model") == 0);

	/* a device that flips a byte of every read: "device" (the re-read does not help) */
	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_EDGES);
	im.dev->flip_off = 5000;
	im.dev->flip_xor = 0x10;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("device flips a byte", &r);
	WRT_CHECK_U64(r.rc, 1);
	ln = line_with(r.out, " diff ");
	WRT_CHECK(ln != NULL && fld(ln, "verdict=", v, sizeof(v)) == 0 && strcmp(v, "device") == 0);
	WRT_CHECK(fld(ln, "alone=", al, sizeof(al)) == 0 && strcmp(al, "krbd") == 0);
	WRT_CHECK(fld(ln, "core=", dc, sizeof(dc)) == 0 && fld(ln, "krbd=", dk, sizeof(dk)) == 0 && fld(ln, "model=", dm, sizeof(dm)) == 0);
	WRT_CHECK(strcmp(dc, dm) == 0 && strcmp(dk, dm) != 0); /* the core and the model agree, the device is the odd one */
	WRT_CHECK(fld(ln, "tries=", tries, sizeof(tries)) == 0 && strcmp(tries, "1") == 0); /* it was read again once */
	WRT_CHECK(has(r.out, " retry ") && has(r.out, " first_diff=5000 "));
	WRT_CHECK(strcmp(r.res.verdict, "device") == 0 && r.res.dig_core == r.res.dig_model && r.res.dig_dev != r.res.dig_model);

	/* the same flip, once: the second read agrees, a transient that is counted and does not fail the run */
	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_EDGES);
	im.dev->flip_off = 5000;
	im.dev->flip_xor = 0x10;
	im.dev->flip_once = 1;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("device flips once", &r);
	dump_on_failure(&r, 0);
	WRT_CHECK_U64(r.rc, 0);
	WRT_CHECK_U64(r.res.transients, 1);
	WRT_CHECK_U64(r.res.diffs, 0);
	WRT_CHECK(has(r.out, " retry ") && has(r.out, "transient=1") && has(r.out, " result ok=1 "));

	/* a core made wrong by the simulator: the header it is served (order 15, the same data prefix) makes it address other objects than the device
	 * does. krbd-to-core: the device writes and reads back its own bytes, the core reads other ones */
	img_new(&ia, 16, 40u * 65536u + 21504u);
	{
		char idb[32], nameb[32];

		snprintf(idb, sizeof(idb), "x%04x", g_nimg);
		snprintf(nameb, sizeof(nameb), "cx%u", g_nimg);
		WRT_CHECK(cr_image_make(nameb, idb, ia.size, 15, 0x21, ia.prefix) == 0);
		rr_defaults(&r);
		r.cfg.dirs = WRL_CMP_DIR_K2C;
		r.cfg.phases = WRL_CMP_PH_EDGES;
		run(&r, nameb, ia.dev, WR_KEY_TYPE_AES256K);
	}
	show("core addresses other objects", &r);
	WRT_CHECK_U64(r.rc, 1);
	ln = line_with(r.out, " diff ");
	WRT_CHECK(ln != NULL && fld(ln, "verdict=", v, sizeof(v)) == 0 && strcmp(v, "core") == 0);
	WRT_CHECK(fld(ln, "alone=", al, sizeof(al)) == 0 && strcmp(al, "core") == 0);
	WRT_CHECK(fld(ln, "core=", dc, sizeof(dc)) == 0 && fld(ln, "krbd=", dk, sizeof(dk)) == 0 && fld(ln, "model=", dm, sizeof(dm)) == 0);
	WRT_CHECK(strcmp(dk, dm) == 0 && strcmp(dc, dm) != 0); /* the device and the model agree, the core is the odd one */
	WRT_CHECK(has(r.out, "dir=krbd-to-core") && has(r.out, "writer=krbd"));
	WRT_CHECK(strcmp(r.res.verdict, "core") == 0 && r.res.dig_dev == r.res.dig_model && r.res.dig_core != r.res.dig_model);

	/* the core and the device both wrong, differently: nobody agrees with anybody */
	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_EDGES);
	r.cfg.corrupt = WRL_CMP_CORRUPT_CORE;
	r.cfg.corrupt_off = 5000;
	im.dev->flip_off = 5000;
	im.dev->flip_xor = 0x80;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("both wrong", &r);
	WRT_CHECK_U64(r.rc, 1);
	ln = line_with(r.out, " diff ");
	WRT_CHECK(ln != NULL && fld(ln, "verdict=", v, sizeof(v)) == 0 && strcmp(v, "both") == 0);
	WRT_CHECK(fld(ln, "core=", dc, sizeof(dc)) == 0 && fld(ln, "krbd=", dk, sizeof(dk)) == 0 && fld(ln, "model=", dm, sizeof(dm)) == 0);
	WRT_CHECK(strcmp(dc, dk) != 0 && strcmp(dc, dm) != 0 && strcmp(dk, dm) != 0);

	/* a core that is wrong on its own (the engine's read hook), found with the other readers right: "core", also when it does not repeat */
	small_run(&r, &im, WRL_CMP_DIR_INTER, WRL_CMP_PH_EDGES);
	r.cfg.corrupt = WRL_CMP_CORRUPT_CORE;
	r.cfg.corrupt_off = 5000;
	r.cfg.corrupt_once = 1;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("core wrong once", &r);
	WRT_CHECK_U64(r.rc, 1);
	WRT_CHECK(has(r.out, "verdict=core") && has(r.out, "transient_the_core_read_differed_once"));

	/* a device that writes one byte too many: both readers see it, the model does not know: "model", and the record names the writer (a scan or
	 * a verification finds it) */
	small_run(&r, &im, WRL_CMP_DIR_K2C, WRL_CMP_PH_EDGES);
	im.dev->scribble = 1;
	im.dev->scribble_off = 700; /* inside the margin the first write's verification reads around it */
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("device writes one byte too many", &r);
	WRT_CHECK_U64(r.rc, 1);
	ln = line_with(r.out, " diff ");
	WRT_CHECK(ln != NULL && fld(ln, "verdict=", v, sizeof(v)) == 0 && strcmp(v, "model") == 0);
	WRT_CHECK(has(r.out, "note=writer_krbd:"));
	WRT_CHECK(has(r.out, " first_diff=700 "));

	/* the device accepts a request at its end: a "device" difference, found by the refusal check */
	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_EDGES);
	im.dev->lax_end = 1;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("device accepts past the end", &r);
	WRT_CHECK_U64(r.rc, 1);
	WRT_CHECK(has(r.out, "kind=past") && has(r.out, "verdict=device") && has(r.out, "the_device_accepted_a_request_at_or_past_its_end"));
}

/* the virtual clock: a step per reading */
static void use_tick_clock(rr *r, uint64_t step)
{
	g_cr_vt = 0;
	g_cr_vt_step = step;
	r->cfg.now_ms = cr_tick_now;
}

static void test_failures_and_hangs(void)
{
	static rr r;
	img im;
	unsigned i;

	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_EDGES);
	im.dev->eio_after = 25;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("device EIO", &r);
	WRT_CHECK_U64(r.rc, 4);
	WRT_CHECK(has(r.out, " error ") && has(r.out, "dev_result=-5") && has(r.out, " result ok=0 exit=4 ") && !has(r.out, " diff "));
	WRT_CHECK(r.res.errors >= 1u);

	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_EDGES);
	im.dev->short_reads = 1;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("device answers short", &r);
	WRT_CHECK_U64(r.rc, 4);
	WRT_CHECK(has(r.out, "device read came back short") && !has(r.out, " diff "));

	/* a hang: the device call number 12 never returns. The virtual clock advances 10 ms per reading, the limit is 20 s of it: 2,000 readings */
	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_EDGES);
	im.dev->hang_after = 12;
	r.cfg.stall_ms = 20000;
	use_tick_clock(&r, 10);
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("device hangs", &r);
	WRT_CHECK_U64(r.rc, 4);
	WRT_CHECK(has(r.out, " stall ") && has(r.out, ": hang") && has(r.out, "device_inflight=") && !has(r.out, " diff "));
	WRT_CHECK(r.res.max_gap_ms >= 20000u);
	cr_dev_release(im.dev); /* let the abandoned worker finish; its memory was left behind on purpose */
	usleep(100000);

	/* a hang inside a scan (the device scanner's own job, not an operation's): the run ends with exit 4 and the abandoned job's memory must stay
	 * valid until the worker lets go of it (a build with the address sanitizer sees a freed engine here as a use after free) */
	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_SCAN);
	im.dev->hang_after = 2;
	r.cfg.stall_ms = 20000;
	use_tick_clock(&r, 10);
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("device hangs inside a scan", &r);
	WRT_CHECK_U64(r.rc, 4);
	WRT_CHECK(has(r.out, " stall ") && has(r.out, ": hang") && !has(r.out, " diff "));
	cr_dev_release(im.dev);
	usleep(100000);

	/* a device that is slow past the limit: the call waits 50 s of the virtual clock, the limit is 20 s */
	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_EDGES);
	im.dev->slow_nth = 12;
	im.dev->slow_ticks = 50000;
	r.cfg.stall_ms = 20000;
	use_tick_clock(&r, 10);
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("device slow past the limit", &r);
	WRT_CHECK_U64(r.rc, 4);
	WRT_CHECK(has(r.out, " stall ") && !has(r.out, " diff "));
	cr_dev_release(im.dev);
	usleep(100000);

	/* ... and one that is slow within it is fine (the same 12th call waits 5 s of the virtual clock, the limit is 20 s) */
	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_EDGES);
	im.dev->slow_nth = 12;
	im.dev->slow_ticks = 5000;
	r.cfg.stall_ms = 40000;
	use_tick_clock(&r, 10);
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("device slow within the limit", &r);
	dump_on_failure(&r, 0);
	WRT_CHECK_U64(r.rc, 0);
	WRT_CHECK(r.res.max_gap_ms < 40000u);

	/* the OSDs stop answering after the image is open: the core's requests hang */
	small_run(&r, &im, WRL_CMP_DIR_C2K, WRL_CMP_PH_EDGES);
	r.cfg.stall_ms = 6000;
	use_tick_clock(&r, 40);
	{
		world w;
		FILE *f = tmpfile();
		size_t n;

		WRT_CHECK(world_open(&w, im.name, WR_KEY_TYPE_AES256K, 1) == 0);
		cr_lock();
		for (i = 0; i < CR_NOSD; i++)
			sim_osd_faults(CR.osd[i])->silent = 1;
		cr_unlock();
		r.cfg.client = w.c;
		r.cfg.loop = w.l;
		r.cfg.img = w.img;
		r.cfg.dev.ctx = im.dev;
		r.cfg.dev.pread = cr_dev_pread;
		r.cfg.dev.pwrite = cr_dev_pwrite;
		r.cfg.dev.discard = cr_dev_discard;
		r.cfg.dev.zeroes = cr_dev_zeroes;
		r.cfg.dev.flush = cr_dev_flush;
		r.cfg.dev.size = cr_dev_size;
		r.cfg.dev.sector = 512;
		r.cfg.out = f;
		r.rc = wrl_cmp_run(&r.cfg, &r.res);
		cr_lock();
		for (i = 0; i < CR_NOSD; i++)
			sim_osd_faults(CR.osd[i])->silent = 0;
		cr_unlock();
		rewind(f);
		n = fread(r.out, 1, sizeof(r.out) - 1u, f);
		r.out[n] = '\0';
		fclose(f);
		world_close(&w);
	}
	show("OSDs stop answering", &r);
	WRT_CHECK_U64(r.rc, 4);
	WRT_CHECK(has(r.out, " stall ") && has(r.out, "core_inflight=") && !has(r.out, " diff "));
}

static void test_setup_errors_and_knobs(void)
{
	static rr r;
	img im;

	/* a device of another size */
	img_new(&im, 16, 40u * 65536u + 21504u);
	im.dev->size += 4096u;
	rr_defaults(&r);
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	WRT_CHECK_U64(r.rc, 3);
	WRT_CHECK(has(r.out, " error the device holds "));

	/* an image opened read-only: the comparison writes */
	img_new(&im, 16, 40u * 65536u);
	{
		world w;
		FILE *f = tmpfile();
		size_t n;

		WRT_CHECK(world_open(&w, im.name, WR_KEY_TYPE_AES256K, 0) == 0);
		rr_defaults(&r);
		r.cfg.client = w.c;
		r.cfg.loop = w.l;
		r.cfg.img = w.img;
		r.cfg.dev.ctx = im.dev;
		r.cfg.dev.pread = cr_dev_pread;
		r.cfg.dev.pwrite = cr_dev_pwrite;
		r.cfg.dev.size = cr_dev_size;
		r.cfg.dev.sector = 512;
		r.cfg.out = f;
		r.rc = wrl_cmp_run(&r.cfg, &r.res);
		rewind(f);
		n = fread(r.out, 1, sizeof(r.out) - 1u, f);
		r.out[n] = '\0';
		fclose(f);
		world_close(&w);
		WRT_CHECK_U64(r.rc, 3);
		WRT_CHECK(has(r.out, "opened read-only"));
	}

	/* --time: a bound by the clock of the run (the virtual one: 5 ms a reading, 3 s in all, a second of it for each direction), no operation count.
	 * The number of operations done depends on how fast the machine is, the fact that every direction ends and does work does not */
	img_new(&im, 18, 20u * 262144u + 100352u);
	rr_defaults(&r);
	r.cfg.phases = WRL_CMP_PH_RANDOM;
	r.cfg.ops = 0;
	r.cfg.time_ms = 3000;
	r.cfg.checkpoint = UINT64_MAX;
	use_tick_clock(&r, 5);
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("time bound", &r);
	dump_on_failure(&r, 0);
	WRT_CHECK_U64(r.rc, 0);
	WRT_CHECK(r.res.ops[WRL_CMP_K_WRITE] > 0u && has(r.out, "phase name=random ops=0 time_ms=3000"));
	WRT_CHECK(has(r.out, "phase name=random dir=core-to-krbd done") && has(r.out, "phase name=random dir=krbd-to-core done") &&
		  has(r.out, "phase name=random dir=interleave done"));

	/* a memory budget far below one operation: every operation runs alone, none is lost, nothing deadlocks */
	img_new(&im, 20, 9u * 1048576u + 300000u);
	rr_defaults(&r);
	r.cfg.phases = WRL_CMP_PH_RANDOM;
	r.cfg.ops = 60;
	r.cfg.mem_max = 4096;
	r.cfg.depth = 8;
	r.cfg.max_len = 512u * 1024u;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("memory budget", &r);
	dump_on_failure(&r, 0);
	WRT_CHECK_U64(r.rc, 0);
	WRT_CHECK(r.res.ops[WRL_CMP_K_WRITE] > 0u);

	/* the deepest queue */
	img_new(&im, 16, 40u * 65536u + 21504u);
	rr_defaults(&r);
	r.cfg.phases = WRL_CMP_PH_RANDOM;
	r.cfg.ops = 200;
	r.cfg.depth = 64;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	show("depth 64", &r);
	dump_on_failure(&r, 0);
	WRT_CHECK_U64(r.rc, 0);

	/* an absurd scan chunk (the largest number): the engine caps it (256 MiB) instead of overflowing the size of the device's 3/2 chunk, and the
	 * scan still covers the whole image in one piece */
	img_new(&im, 16, 40u * 65536u + 21504u);
	rr_defaults(&r);
	r.cfg.phases = WRL_CMP_PH_SCAN;
	r.cfg.chunk = UINT64_MAX;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	dump_on_failure(&r, 0);
	WRT_CHECK_U64(r.rc, 0);
	WRT_CHECK(has(r.out, " chunk=268435456 ") && has(r.out, "device_chunk=402653184 ") && r.res.scan_bytes_core == im.size);

	/* a scan alone, on an image written by a first run (its model starts empty: the first run must leave the image as the model of the second
	 * says, so the second run is only meaningful on a fresh image; on one with data a scan-only run must find a difference: the model is blank) */
	img_new(&im, 16, 40u * 65536u + 21504u);
	rr_defaults(&r);
	r.cfg.phases = WRL_CMP_PH_SCAN;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	dump_on_failure(&r, 0);
	WRT_CHECK_U64(r.rc, 0);
	WRT_CHECK_U64(r.res.scans, 1);
	/* not a zero any more: one byte written straight into the store, which is what a stale model would meet */
	{
		uint8_t one = 0x33;

		cr_dev_store_write(im.dev, 777, &one, 1);
	}
	rr_defaults(&r);
	r.cfg.phases = WRL_CMP_PH_SCAN;
	run(&r, im.name, im.dev, WR_KEY_TYPE_AES256K);
	WRT_CHECK_U64(r.rc, 1);
	WRT_CHECK(has(r.out, "verdict=model") && has(r.out, " first_diff=777 "));
}

int main(int argc, char **argv)
{
	uint64_t t0;
	const char *only = argc > 1 ? argv[1] : NULL; /* a substring of a test's call: run only those (a reproduction aid, ctest runs them all) */

	signal(SIGPIPE, SIG_IGN);
#define RUN(t)                                                                                    \
	do {                                                                                      \
		if (only != NULL && strstr(#t, only) == NULL)                                     \
			break;                                                                    \
		t0 = cr_now_ms();                                                                 \
		t;                                                                                \
		fprintf(stderr, "  %-60s %6llu ms\n", #t, (unsigned long long)(cr_now_ms() - t0)); \
	} while (0)
	cr_srv_start(WR_KEY_TYPE_AES256K);
	RUN(test_phases(12, 300u * 4096u + 1536u, WR_KEY_TYPE_AES256K, 65536u, 150, WRL_CMP_PH_ALL));
	RUN(test_phases(18, 20u * 262144u + 100352u, WR_KEY_TYPE_AES256K, 524288u, 120, WRL_CMP_PH_ALL));
	RUN(test_phases(22, 4ull * 4194304u + 1572864u, WR_KEY_TYPE_AES256K, 1048576u, 60, WRL_CMP_PH_ALL));
	/* objects of 32 MiB through the test server (64 KiB a turn) are slow: no whole-object edges here, the random phase works across the one boundary
	 * (the edge list itself is checked at order 25 by host.cmp.edges and in the lab) */
	RUN(test_phases(25, 33ull << 20, WR_KEY_TYPE_AES256K, 262144u, 90, WRL_CMP_PH_RANDOM | WRL_CMP_PH_SCAN));
	RUN(test_determinism());
	RUN(test_attribution());
	RUN(test_failures_and_hangs());
	RUN(test_setup_errors_and_knobs());
	cr_srv_stop();
	/* the legacy key type (a different monitor key: another server) */
	cr_srv_start(WR_KEY_TYPE_AES);
	RUN(test_phases(16, 40u * 65536u + 21504u + 100u, WR_KEY_TYPE_AES, 262144u, 150, WRL_CMP_PH_ALL));
	RUN(test_phases(20, 9u * 1048576u + 300000u, WR_KEY_TYPE_AES, 1048576u, 90, WRL_CMP_PH_ALL));
	cr_srv_stop();
#undef RUN
	return wrt_finish();
}
