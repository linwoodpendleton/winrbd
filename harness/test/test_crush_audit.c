/* SPDX-License-Identifier: MIT */
/*
 * test_crush_audit.c - wri_crush_audit_rule (core/src/crush/wri_crush_audit.c): one case per refusal of
 * docs/design/core-architecture.md 16.3.5, and the rules it must accept.
 *
 * Refusals: no rule / a rule of another type, indep and MSR opcodes, more than 64 steps, a take of a missing bucket
 * or of a device beyond max_devices, an item that names a missing bucket, a reachable tree bucket (and the same
 * bucket when nothing can reach it), list and uniform buckets while module crush-legacy is a skeleton, a uniform
 * bucket above 256 items, a bucket above 256 items when the local fallback needs the permutation chooser (tunable or
 * SET step), a hierarchy of more than 10 levels, a cycle, a hierarchy that fans out through shared buckets, vary_r
 * above 32 (tunable or step), a result_max outside 1..16, a region that is not one. Every refusal has the module
 * and a reason in the errinfo. A final loop checks the promise of the audit on generated maps: when it accepts, the
 * mapper never fails for a structural reason.
 */
#include "wrt.h"
#include "wrt_mapgen.h"
#include "wri_crush.h"
#include "wri_crush_buck.h"

/* ---- helpers --------------------------------------------------------------------------------------------- */

#define W_IN 0x10000u

typedef struct cmap {
	uint8_t *room;
	wri_crush *c;
} cmap;

static int cm_from_mg(cmap *m, const wrt_mg_crush *mg)
{
	wrt_mg_buf b;
	size_t cap, used = 0;
	wr_errinfo why;

	memset(&b, 0, sizeof(b));
	memset(&why, 0, sizeof(why));
	if (wrt_mg_crush_encode(mg, &b) != 0)
		return -1;
	cap = b.len * 4u + 65536u;
	m->room = (uint8_t *)malloc(cap);
	if (m->room == NULL)
		abort();
	if (wri_crush_decode(b.p, b.len, m->room, cap, &used, &why) != WR_OK) {
		fprintf(stderr, "decode failed: %s\n", why.what ? why.what : "?");
		free(m->room);
		m->room = NULL;
		wrt_mg_buf_free(&b);
		return -1;
	}
	wrt_mg_buf_free(&b);
	m->c = (wri_crush *)(void *)m->room;
	return 0;
}

static int cm_load(cmap *m, const uint8_t *blob, size_t n)
{
	size_t cap = n * 4u + 65536u, used = 0;
	wr_errinfo why;

	memset(&why, 0, sizeof(why));
	m->room = (uint8_t *)malloc(cap);
	if (m->room == NULL)
		abort();
	if (wri_crush_decode(blob, n, m->room, cap, &used, &why) != WR_OK) {
		free(m->room);
		m->room = NULL;
		return -1;
	}
	m->c = (wri_crush *)(void *)m->room;
	return 0;
}

static void cm_free(cmap *m)
{
	free(m->room);
	m->room = NULL;
}

static int legacy_list, legacy_uniform, legacy_perm;

static void probe_legacy(void)
{
	uint32_t buf[8];
	wri_cbucket b;
	uint16_t perm[WRI_CRUSH_PERM_MAX];
	int32_t item = 0;

	memset(buf, 0, sizeof(buf));
	memset(&b, 0, sizeof(b));
	b.id = -1;
	b.alg = (uint8_t)WRI_CRUSH_ALG_LIST;
	b.size = 1;
	memcpy(buf, &b, sizeof(b));
	buf[5] = W_IN;
	buf[6] = W_IN;
	legacy_list = wri_crush_choose_list((const wri_cbucket *)(const void *)buf, 0, 0, &item) != WR_E_CRUSH_UNSUPPORTED;
	legacy_uniform = wri_crush_choose_uniform((const wri_cbucket *)(const void *)buf, 0, 0, perm, &item) != WR_E_CRUSH_UNSUPPORTED;
	legacy_perm = wri_crush_choose_perm((const wri_cbucket *)(const void *)buf, 0, 0, perm, &item) != WR_E_CRUSH_UNSUPPORTED;
	printf("legacy choosers present: list %d uniform %d permutation %d\n", legacy_list, legacy_uniform, legacy_perm);
}

/* Audit with an errinfo and check the status, the module and (when `sub` is given) the reason text. */
static void audit(const char *name, const cmap *m, uint32_t rule, uint32_t rmax, wr_status want, const char *sub)
{
	wr_errinfo why;
	wr_status st;

	memset(&why, 0, sizeof(why));
	st = wri_crush_audit_rule(m->c, rule, rmax, &why);
	wrt_checks++;
	if (st != want) {
		wrt_failures++;
		fprintf(stderr, "%s: audit returned %d (%s), want %d (%s); reason: %s\n", name, (int)st, wrt_status_name_(st), (int)want,
			wrt_status_name_(want), why.what ? why.what : "-");
		return;
	}
	if (want == WR_OK) {
		WRT_CHECK(why.status == 0 && why.what == NULL); /* success leaves the errinfo alone */
		return;
	}
	if (want == WR_E_INVAL)
		return;
	if (why.status != want || why.module != WR_MOD_CRUSH || why.what == NULL) {
		wrt_failures++;
		fprintf(stderr, "%s: errinfo not filled (status %d module %d what %s)\n", name, (int)why.status, (int)why.module,
			why.what ? why.what : "NULL");
	}
	if (sub != NULL && (why.what == NULL || strstr(why.what, sub) == NULL)) {
		wrt_failures++;
		fprintf(stderr, "%s: reason \"%s\" does not mention \"%s\"\n", name, why.what ? why.what : "NULL", sub);
	}
	/* the same call without an errinfo gives the same status */
	WRT_CHECK_STATUS(want, wri_crush_audit_rule(m->c, rule, rmax, NULL));
}

static void add_rule(wrt_mg_crush *m, uint32_t slot, const wrt_mg_step *st, uint32_t n)
{
	WRT_CHECK(wrt_mg_crush_add_rule(m, slot, 1, st, n) == (int)slot);
}

/* racks x hosts per rack x devices per host, with the three algorithms given; type ids as the generator's: host 1, rack 3, root 11 */
static void mk_hier(wrt_mg_crush *m, int tun, uint8_t ah, uint8_t ar, uint8_t aroot, uint32_t racks, uint32_t hpr, uint32_t dph)
{
	uint32_t n_hosts = racks ? racks * hpr : hpr, h, r, i, root_n = 0;
	int32_t first_host = -2 - (int32_t)racks;
	int32_t items[64];

	wrt_mg_crush_init(m);
	wrt_mg_crush_tunables(m, tun);
	for (h = 0; h < n_hosts; h++) {
		for (i = 0; i < dph; i++)
			items[i] = (int32_t)(h * dph + i);
		WRT_CHECK(wrt_mg_crush_add_bucket(m, first_host - (int32_t)h, 1, ah, items, NULL, dph) >= 0);
	}
	if (racks) {
		for (r = 0; r < racks; r++) {
			for (i = 0; i < hpr; i++)
				items[i] = first_host - (int32_t)(r * hpr + i);
			WRT_CHECK(wrt_mg_crush_add_bucket(m, -2 - (int32_t)r, 3, ar, items, NULL, hpr) >= 0);
			items[root_n++] = -2 - (int32_t)r;
		}
	} else {
		for (h = 0; h < n_hosts; h++)
			items[root_n++] = first_host - (int32_t)h;
	}
	WRT_CHECK(wrt_mg_crush_add_bucket(m, -1, 11, aroot, items, NULL, root_n) >= 0);
}

static const wrt_mg_step S_LF_HOST[] = {{1, -1, 0}, {6, 0, 1}, {4, 0, 0}};
static const wrt_mg_step S_CH_OSD[] = {{1, -1, 0}, {2, 0, 0}, {4, 0, 0}};

/* ---- accepted rules ------------------------------------------------------------------------------------- */

static void check_accepted(void)
{
	wrt_mg_crush m;
	cmap cm;
	uint8_t *blob;
	size_t n;
	uint32_t rule;

	/* the two lab maps: rules 0 and 1 */
	if (wrt_mg_load_hex_file(wrt_vec_path("crush/crush-getcrushmap.hex"), &blob, &n) != 0) {
		WRT_CHECK(0);
	} else {
		WRT_CHECK(cm_load(&cm, blob, n) == 0);
		audit("lab rule 0", &cm, 0, 3, WR_OK, NULL);
		audit("lab rule 1", &cm, 1, 3, WR_OK, NULL);
		audit("lab rule 0 size 1", &cm, 0, 1, WR_OK, NULL);
		audit("lab rule 0 size 16", &cm, 0, 16, WR_OK, NULL);
		audit("lab rule 2", &cm, 2, 3, WR_E_CRUSH_NO_RULE, "missing");
		cm_free(&cm);
		free(blob);
	}

	/* straw2 and straw hierarchies with several rule shapes, every tunable profile */
	for (rule = 0; rule < 5; rule++) {
		uint8_t alg = (uint8_t)(rule % 2 ? WRT_MG_ALG_STRAW : WRT_MG_ALG_STRAW2);
		const wrt_mg_step rack_leaf[] = {{1, -1, 0}, {6, 0, 3}, {4, 0, 0}};
		const wrt_mg_step two[] = {{1, -1, 0}, {2, 2, 3}, {6, 2, 1}, {4, 0, 0}};
		const wrt_mg_step sets[] = {{1, -1, 0}, {8, 100, 0}, {9, 5, 0}, {10, 0, 0}, {11, 0, 0}, {12, 32, 0}, {13, 1, 0}, {6, -1, 1}, {4, 0, 0}};
		const wrt_mg_step devs[] = {{1, 2, 0}, {4, 0, 0}, {1, -2, 0}, {2, 1, 0}, {4, 0, 0}};
		const wrt_mg_step noop[] = {{1, -1, 0}, {0, 0, 0}, {99, 1, 1}, {5, 3, 3}, {6, 0, 1}, {4, 0, 0}};
		const wrt_mg_step none[] = {{4, 0, 0}};

		mk_hier(&m, (int)rule == 0 ? WRT_MG_TUN_JEWEL : (int)rule == 1 ? WRT_MG_TUN_HAMMER : WRT_MG_TUN_BOBTAIL, alg, alg, alg, 3, 3, 4);
		add_rule(&m, 0, S_LF_HOST, 3);
		add_rule(&m, 1, S_CH_OSD, 3);
		add_rule(&m, 2, rack_leaf, 3);
		add_rule(&m, 3, two, 4);
		add_rule(&m, 4, sets, 9);
		add_rule(&m, 5, devs, 5);
		add_rule(&m, 6, noop, 6);
		add_rule(&m, 7, none, 1);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		{
			uint32_t r;

			for (r = 0; r < 8; r++)
				audit("hierarchy rule", &cm, r, 3, WR_OK, NULL);
		}
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}

	/* a bucket that two parents share is a hierarchy, not a loop */
	{
		int32_t a[2] = {-3, -4}, b[1] = {-4}, c[2] = {0, 1};
		const wrt_mg_step st[] = {{1, -1, 0}, {6, 0, 1}, {4, 0, 0}};

		wrt_mg_crush_init(&m);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -1, 11, WRT_MG_ALG_STRAW2, a, NULL, 2) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -3, 3, WRT_MG_ALG_STRAW2, b, NULL, 1) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -4, 1, WRT_MG_ALG_STRAW2, c, NULL, 2) >= 0);
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("shared bucket", &cm, 0, 3, WR_OK, NULL);
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}
	/* a path of exactly ten buckets is accepted; empty buckets are accepted (the mapper treats them as rejections) */
	{
		int32_t it[1], dev[2] = {0, 1};
		int k;
		const wrt_mg_step st[] = {{1, -1, 0}, {2, 1, 0}, {4, 0, 0}};

		wrt_mg_crush_init(&m);
		for (k = 1; k <= 10; k++) {
			if (k < 10) {
				it[0] = -(k + 1);
				WRT_CHECK(wrt_mg_crush_add_bucket(&m, -k, 3, WRT_MG_ALG_STRAW2, it, NULL, 1) >= 0);
			} else {
				WRT_CHECK(wrt_mg_crush_add_bucket(&m, -k, 1, WRT_MG_ALG_STRAW2, dev, NULL, 2) >= 0);
			}
		}
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("ten levels", &cm, 0, 3, WR_OK, NULL);
		cm_free(&cm);
		wrt_mg_crush_free(&m);
		wrt_mg_crush_init(&m);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -1, 11, WRT_MG_ALG_STRAW2, dev, NULL, 0) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -2, 1, WRT_MG_ALG_STRAW2, dev, NULL, 2) >= 0);
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("empty bucket", &cm, 0, 3, WR_OK, NULL);
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}
}

/* ---- refusals ------------------------------------------------------------------------------------------- */

static void check_rule_refusals(void)
{
	wrt_mg_crush m;
	cmap cm;
	const wrt_mg_step indep[] = {{1, -1, 0}, {3, 0, 1}, {4, 0, 0}};
	const wrt_mg_step lindep[] = {{1, -1, 0}, {7, 0, 1}, {4, 0, 0}};
	const wrt_mg_step msr1[] = {{1, -1, 0}, {14, 0, 1}, {4, 0, 0}};
	const wrt_mg_step msr2[] = {{1, -1, 0}, {15, 0, 1}, {4, 0, 0}};
	const wrt_mg_step msr3[] = {{1, -1, 0}, {16, 0, 1}, {4, 0, 0}};
	const wrt_mg_step vary33[] = {{1, -1, 0}, {12, 33, 0}, {6, 0, 1}, {4, 0, 0}};
	const wrt_mg_step vary32[] = {{1, -1, 0}, {12, 32, 0}, {6, 0, 1}, {4, 0, 0}};
	const wrt_mg_step varyneg[] = {{1, -1, 0}, {12, -5, 0}, {6, 0, 1}, {4, 0, 0}};
	const wrt_mg_step tmiss[] = {{1, -99, 0}, {4, 0, 0}};
	const wrt_mg_step tdev[] = {{1, 999, 0}, {4, 0, 0}};
	const wrt_mg_step tdev_ok[] = {{1, 11, 0}, {4, 0, 0}};
	const wrt_mg_step tsecond[] = {{1, -1, 0}, {6, 0, 1}, {4, 0, 0}, {1, -77, 0}, {4, 0, 0}};
	const wrt_mg_step fb[] = {{1, -1, 0}, {11, 3, 0}, {6, 0, 1}, {4, 0, 0}};
	const wrt_mg_step fb0[] = {{1, -1, 0}, {11, 0, 0}, {6, 0, 1}, {4, 0, 0}};

	mk_hier(&m, WRT_MG_TUN_JEWEL, WRT_MG_ALG_STRAW2, WRT_MG_ALG_STRAW2, WRT_MG_ALG_STRAW2, 2, 2, 6); /* 24 devices: 0..23 */
	add_rule(&m, 0, S_LF_HOST, 3);
	add_rule(&m, 1, indep, 3);
	add_rule(&m, 2, lindep, 3);
	add_rule(&m, 3, msr1, 3);
	add_rule(&m, 4, msr2, 3);
	add_rule(&m, 5, msr3, 3);
	add_rule(&m, 6, vary33, 4);
	add_rule(&m, 7, vary32, 4);
	add_rule(&m, 8, tmiss, 2);
	add_rule(&m, 9, tdev, 2);
	add_rule(&m, 10, tdev_ok, 2);
	add_rule(&m, 11, tsecond, 5);
	add_rule(&m, 12, fb, 4);
	add_rule(&m, 13, fb0, 4);
	add_rule(&m, 14, varyneg, 4);
	WRT_CHECK(wrt_mg_crush_add_rule(&m, 20, 3, S_LF_HOST, 3) == 20); /* a rule of type 3 */
	WRT_CHECK(cm_from_mg(&cm, &m) == 0);

	audit("ok", &cm, 0, 3, WR_OK, NULL);
	audit("rule beyond max_rules", &cm, 200, 3, WR_E_CRUSH_NO_RULE, "missing");
	audit("rule beyond the table", &cm, 4000000000u, 3, WR_E_CRUSH_NO_RULE, "missing");
	audit("rule in an empty slot", &cm, 19, 3, WR_E_CRUSH_NO_RULE, "missing");
	audit("rule of another type", &cm, 20, 3, WR_E_CRUSH_NO_RULE, "not a replicated");
	audit("chooseleaf indep", &cm, 2, 3, WR_E_CRUSH_UNSUPPORTED, "indep");
	audit("choose indep", &cm, 1, 3, WR_E_CRUSH_UNSUPPORTED, "indep");
	audit("MSR 14", &cm, 3, 3, WR_E_CRUSH_UNSUPPORTED, "MSR");
	audit("MSR 15", &cm, 4, 3, WR_E_CRUSH_UNSUPPORTED, "MSR");
	audit("MSR 16", &cm, 5, 3, WR_E_CRUSH_UNSUPPORTED, "MSR");
	audit("vary_r step 33", &cm, 6, 3, WR_E_CRUSH_UNSUPPORTED, "VARY_R");
	audit("vary_r step 32", &cm, 7, 3, WR_OK, NULL);
	audit("vary_r step -5 is ignored", &cm, 14, 3, WR_OK, NULL);
	audit("take of a missing bucket", &cm, 8, 3, WR_E_CRUSH_UNSUPPORTED, "missing bucket");
	audit("take of a device beyond max_devices", &cm, 9, 3, WR_E_CRUSH_UNSUPPORTED, "max_devices");
	audit("take of a device", &cm, 10, 3, WR_OK, NULL);
	audit("second take missing", &cm, 11, 3, WR_E_CRUSH_UNSUPPORTED, "missing bucket");
	audit("result_max 0", &cm, 0, 0, WR_E_CRUSH_UNSUPPORTED, "pool size");
	audit("result_max 17", &cm, 0, 17, WR_E_CRUSH_UNSUPPORTED, "pool size");
	audit("result_max 16", &cm, 0, 16, WR_OK, NULL);
	/* local fallback on small buckets needs the permutation chooser */
	audit("SET fallback 3", &cm, 12, 3, legacy_perm ? WR_OK : WR_E_CRUSH_UNSUPPORTED, "permutation");
	audit("SET fallback 0", &cm, 13, 3, WR_OK, NULL);

	/* NULL and damaged regions */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_audit_rule(NULL, 0, 3, NULL));
	cm.c->magic ^= 1u;
	audit("bad magic", &cm, 0, 3, WR_E_CRUSH_ENCODING, "not a compact");
	cm.c->magic ^= 1u;
	{
		wri_crule *r = (wri_crule *)(void *)wri_crush_rule(cm.c, 0); /* more than 64 steps: the decoder never makes this, a damaged region could */

		r->nsteps = 65;
		audit("65 steps", &cm, 0, 3, WR_E_CRUSH_UNSUPPORTED, "too many steps");
		r->nsteps = 3;
	}
	cm.c->tun.chooseleaf_vary_r = 33;
	audit("tunable vary_r 33", &cm, 0, 3, WR_E_CRUSH_UNSUPPORTED, "vary_r");
	cm.c->tun.chooseleaf_vary_r = 32;
	audit("tunable vary_r 32", &cm, 0, 3, WR_OK, NULL);
	cm.c->tun.chooseleaf_vary_r = 1;
	audit("restored", &cm, 0, 3, WR_OK, NULL);
	cm.c->tun.choose_local_fallback_tries = 5; /* the tunable alone also needs the permutation chooser */
	audit("tunable fallback 5", &cm, 0, 3, legacy_perm ? WR_OK : WR_E_CRUSH_UNSUPPORTED, "permutation");
	cm_free(&cm);
	wrt_mg_crush_free(&m);
}

static void check_bucket_refusals(void)
{
	wrt_mg_crush m;
	cmap cm;
	unsigned alg;

	/* every algorithm, as the host buckets of a hierarchy: tree always refused, list and uniform while legacy is a skeleton */
	for (alg = 1; alg <= 5; alg++) {
		char nm[64];
		wr_status want = WR_OK;
		const char *sub = NULL;

		if (alg == WRT_MG_ALG_TREE) {
			want = WR_E_CRUSH_UNSUPPORTED;
			sub = "tree";
		} else if (alg == WRT_MG_ALG_LIST && !legacy_list) {
			want = WR_E_CRUSH_UNSUPPORTED;
			sub = "list";
		} else if (alg == WRT_MG_ALG_UNIFORM && !legacy_uniform) {
			want = WR_E_CRUSH_UNSUPPORTED;
			sub = "uniform";
		}
		mk_hier(&m, WRT_MG_TUN_JEWEL, (uint8_t)alg, WRT_MG_ALG_STRAW2, WRT_MG_ALG_STRAW2, 2, 2, 4);
		add_rule(&m, 0, S_LF_HOST, 3);
		{
			const wrt_mg_step devtake[] = {{1, 3, 0}, {4, 0, 0}}; /* a take of a device never looks at buckets */
			const wrt_mg_step racktake[] = {{1, -2, 0}, {2, 0, 0}, {4, 0, 0}};

			add_rule(&m, 1, devtake, 2);
			add_rule(&m, 2, racktake, 3);
		}
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		snprintf(nm, sizeof(nm), "alg %u hosts", alg);
		audit(nm, &cm, 0, 3, want, sub);
		audit(nm, &cm, 2, 3, want, sub); /* the rack holds the hosts */
		audit("device take", &cm, 1, 3, WR_OK, NULL);
		cm_free(&cm);
		wrt_mg_crush_free(&m);
		/* the same algorithm as the root: also refused, the walk starts there */
		mk_hier(&m, WRT_MG_TUN_JEWEL, WRT_MG_ALG_STRAW2, WRT_MG_ALG_STRAW2, (uint8_t)alg, 2, 2, 4);
		add_rule(&m, 0, S_LF_HOST, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		snprintf(nm, sizeof(nm), "alg %u root", alg);
		audit(nm, &cm, 0, 3, want, sub);
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}
	/* a tree bucket that no take can reach is not the audit's business */
	{
		int32_t it[1] = {-2}, d1[2] = {0, 1}, d2[2] = {2, 3};
		const wrt_mg_step st[] = {{1, -1, 0}, {6, 0, 1}, {4, 0, 0}};

		wrt_mg_crush_init(&m);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -1, 11, WRT_MG_ALG_STRAW2, it, NULL, 1) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -2, 1, WRT_MG_ALG_STRAW2, d1, NULL, 2) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -3, 1, WRT_MG_ALG_TREE, d2, NULL, 2) >= 0); /* nobody holds it */
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("unreachable tree", &cm, 0, 3, WR_OK, NULL);
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}
	/* uniform and straw2 buckets of 256 and 257 items; the local fallback needs the permutation chooser for any large bucket */
	{
		int32_t big[300];
		int k;
		const wrt_mg_step st[] = {{1, -1, 0}, {2, 0, 0}, {4, 0, 0}};
		const wrt_mg_step stfb[] = {{1, -1, 0}, {11, 2, 0}, {2, 0, 0}, {4, 0, 0}};

		for (k = 0; k < 300; k++)
			big[k] = k;
		wrt_mg_crush_init(&m);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -1, 11, WRT_MG_ALG_UNIFORM, big, NULL, 256) >= 0);
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("uniform 256", &cm, 0, 3, legacy_uniform ? WR_OK : WR_E_CRUSH_UNSUPPORTED, NULL);
		cm_free(&cm);
		wrt_mg_crush_free(&m);
		wrt_mg_crush_init(&m);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -1, 11, WRT_MG_ALG_UNIFORM, big, NULL, 257) >= 0);
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("uniform 257", &cm, 0, 3, WR_E_CRUSH_UNSUPPORTED, NULL);
		if (legacy_uniform)
			audit("uniform 257 reason", &cm, 0, 3, WR_E_CRUSH_UNSUPPORTED, "permutation");
		cm_free(&cm);
		wrt_mg_crush_free(&m);
		/* straw2 of 300: fine on its own, refused once a fallback can run */
		wrt_mg_crush_init(&m);
		wrt_mg_crush_tunables(&m, WRT_MG_TUN_JEWEL);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -1, 11, WRT_MG_ALG_STRAW2, big, NULL, 300) >= 0);
		add_rule(&m, 0, st, 3);
		add_rule(&m, 1, stfb, 4);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("straw2 300", &cm, 0, 3, WR_OK, NULL);
		audit("straw2 300 with a fallback step", &cm, 1, 3, WR_E_CRUSH_UNSUPPORTED, NULL);
		cm.c->tun.choose_local_fallback_tries = 1;
		audit("straw2 300 with the fallback tunable", &cm, 0, 3, WR_E_CRUSH_UNSUPPORTED, NULL);
		if (legacy_perm)
			audit("straw2 300 reason", &cm, 0, 3, WR_E_CRUSH_UNSUPPORTED, "larger than");
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}
}

static void check_hierarchy_refusals(void)
{
	wrt_mg_crush m;
	cmap cm;
	const wrt_mg_step st[] = {{1, -1, 0}, {2, 1, 0}, {4, 0, 0}};
	int k, depth;

	/* 11 buckets in a line: one level too many; 10 passed in check_accepted */
	for (depth = 10; depth <= 14; depth++) {
		int32_t it[1], dev[2] = {0, 1};
		char nm[64];

		wrt_mg_crush_init(&m);
		for (k = 1; k <= depth; k++) {
			if (k < depth) {
				it[0] = -(k + 1);
				WRT_CHECK(wrt_mg_crush_add_bucket(&m, -k, 3, WRT_MG_ALG_STRAW2, it, NULL, 1) >= 0);
			} else {
				WRT_CHECK(wrt_mg_crush_add_bucket(&m, -k, 1, WRT_MG_ALG_STRAW2, dev, NULL, 2) >= 0);
			}
		}
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		snprintf(nm, sizeof(nm), "%d levels", depth);
		if (depth == 10)
			audit(nm, &cm, 0, 3, WR_OK, NULL);
		else
			audit(nm, &cm, 0, 3, WR_E_CRUSH_LOOP, "deeper");
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}
	/* cycles: a self loop, a two-cycle, a cycle below a root, and a cycle that only a second take reaches */
	{
		int32_t self[2] = {-1, 0}, a[2] = {-2, 0}, b[2] = {-1, 1}, root[1] = {-2}, c1[1] = {-3}, c2[2] = {-2, 0};
		const wrt_mg_step second[] = {{1, -4, 0}, {2, 1, 0}, {4, 0, 0}, {1, -2, 0}, {2, 1, 0}, {4, 0, 0}};

		wrt_mg_crush_init(&m);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -1, 11, WRT_MG_ALG_STRAW2, self, NULL, 2) >= 0);
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("self loop", &cm, 0, 3, WR_E_CRUSH_LOOP, "cyclic");
		cm_free(&cm);
		wrt_mg_crush_free(&m);
		wrt_mg_crush_init(&m);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -1, 11, WRT_MG_ALG_STRAW2, a, NULL, 2) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -2, 3, WRT_MG_ALG_STRAW2, b, NULL, 2) >= 0);
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("two cycle", &cm, 0, 3, WR_E_CRUSH_LOOP, "cyclic");
		cm_free(&cm);
		wrt_mg_crush_free(&m);
		/* -4 is a clean root; -2 -> -3 -> -2 is a cycle that only the second take reaches */
		wrt_mg_crush_init(&m);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -2, 3, WRT_MG_ALG_STRAW2, c1, NULL, 1) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -3, 3, WRT_MG_ALG_STRAW2, c2, NULL, 2) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -4, 11, WRT_MG_ALG_STRAW2, c2 + 1, NULL, 1) >= 0);
		(void)root;
		add_rule(&m, 0, second, 6);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("cycle behind the second take", &cm, 0, 3, WR_E_CRUSH_LOOP, "cyclic");
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}
	/* a hierarchy that fans out through shared buckets: ten levels, every bucket holds the next one twice */
	{
		int32_t it[2], dev[2] = {0, 1};

		wrt_mg_crush_init(&m);
		for (k = 1; k <= 10; k++) {
			if (k < 10) {
				it[0] = it[1] = -(k + 1);
				WRT_CHECK(wrt_mg_crush_add_bucket(&m, -k, 3, WRT_MG_ALG_STRAW2, it, NULL, 2) >= 0);
			} else {
				WRT_CHECK(wrt_mg_crush_add_bucket(&m, -k, 1, WRT_MG_ALG_STRAW2, dev, NULL, 2) >= 0);
			}
		}
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("fan out", &cm, 0, 3, WR_E_CRUSH_LOOP, "revisits");
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}
	/* an item that names a missing bucket (a hole in the slot table) */
	{
		int32_t it[2] = {-3, 0}, d[1] = {1};

		wrt_mg_crush_init(&m);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -1, 11, WRT_MG_ALG_STRAW2, it, NULL, 2) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -4, 1, WRT_MG_ALG_STRAW2, d, NULL, 1) >= 0);
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		audit("hole", &cm, 0, 3, WR_E_CRUSH_UNSUPPORTED, "missing bucket");
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}
	/* a device item beyond max_devices cannot be decoded, but a damaged region can hold one */
	{
		int32_t it[2] = {0, 1};

		wrt_mg_crush_init(&m);
		WRT_CHECK(wrt_mg_crush_add_bucket(&m, -1, 11, WRT_MG_ALG_STRAW2, it, NULL, 2) >= 0);
		add_rule(&m, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		((int32_t *)(void *)wri_cbucket_items(wri_crush_bucket(cm.c, -1)))[1] = 9;
		audit("device beyond max_devices", &cm, 0, 3, WR_E_CRUSH_UNSUPPORTED, "max_devices");
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}
}

/* ---- the promise: accepted means mappable ------------------------------------------------------------------------ */

static void check_promise(void)
{
	static const uint8_t algs[] = {WRT_MG_ALG_STRAW2, WRT_MG_ALG_STRAW, WRT_MG_ALG_LIST, WRT_MG_ALG_UNIFORM, WRT_MG_ALG_TREE};
	const wrt_mg_step lf_rack[] = {{1, -1, 0}, {6, 0, 3}, {4, 0, 0}};
	const wrt_mg_step sets[] = {{1, -1, 0}, {10, 2, 0}, {11, 3, 0}, {6, 0, 1}, {4, 0, 0}};
	const wrt_mg_step take_rack[] = {{1, -2, 0}, {2, 0, 0}, {4, 0, 0}};
	unsigned a1, a2, a3, tun, accepted = 0, refused = 0;

	for (a1 = 0; a1 < 5; a1++)
		for (a2 = 0; a2 < 5; a2++)
			for (a3 = 0; a3 < 5; a3++)
				for (tun = 0; tun < 5; tun++) {
					wrt_mg_crush m;
					cmap cm;
					uint32_t rule, nd, x;
					uint32_t *w;

					/* every algorithm combination on the jewel profile, every profile for the combinations of straw2 and straw */
					if (tun != WRT_MG_TUN_JEWEL && (a1 > 1 || a2 > 1 || a3 > 1))
						continue;
					mk_hier(&m, (int)tun, algs[a1], algs[a2], algs[a3], 2, 3, 4);
					add_rule(&m, 0, S_LF_HOST, 3);
					add_rule(&m, 1, S_CH_OSD, 3);
					add_rule(&m, 2, lf_rack, 3);
					add_rule(&m, 3, sets, 5);
					add_rule(&m, 4, take_rack, 3);
					if (cm_from_mg(&cm, &m) != 0) {
						WRT_CHECK(0);
						wrt_mg_crush_free(&m);
						continue;
					}
					nd = (uint32_t)cm.c->max_devices;
					w = (uint32_t *)malloc(nd * sizeof(uint32_t));
					for (x = 0; x < nd; x++)
						w[x] = (x % 5u == 1u) ? 0u : ((x % 3u == 0u) ? 0x9000u : W_IN);
					for (rule = 0; rule < 5; rule++) {
						wr_status st = wri_crush_audit_rule(cm.c, rule, 3, NULL);

						if (st != WR_OK) {
							refused++;
							continue;
						}
						accepted++;
						for (x = 0; x < 24; x++) {
							wri_crush_ws ws;
							wri_crush_in in;
							int32_t res[WRI_CRUSH_RESULT_MAX];
							uint32_t n = 0;
							wr_status ms;

							memset(&ws, 0, sizeof(ws));
							ws.work = 1000000;
							in.rule = rule;
							in.x = x * 31u + rule;
							in.result_max = 3;
							in.osd_weight = w;
							in.weight_max = nd;
							in.args_pool = 0;
							ms = wri_crush_do_rule(cm.c, &in, &ws, res, &n, NULL);
							WRT_CHECK_STATUS(WR_OK, ms); /* never UNSUPPORTED, NO_RULE or LOOP after an accepted audit */
						}
					}
					free(w);
					cm_free(&cm);
					wrt_mg_crush_free(&m);
				}
	printf("audit promise: %u rules accepted and mapped, %u refused\n", accepted, refused);
	WRT_CHECK(accepted > 100 && refused > 50);
}

int main(void)
{
	probe_legacy();
	check_accepted();
	check_rule_refusals();
	check_bucket_refusals();
	check_hierarchy_refusals();
	check_promise();
	return wrt_finish();
}
