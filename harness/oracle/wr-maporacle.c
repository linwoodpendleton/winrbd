/* SPDX-License-Identifier: MIT */
/*
 * wr-maporacle - prints what the core's OSD map decoder, incremental applier, placement pipeline and CRUSH mapper answer, in
 * the line formats of Ceph's own tools, so a script can diff the two (harness/oracle/README.md; module oracle-cli of
 * docs/design/core-architecture.md 18.4). Harness code: reads files, writes stdout, opens no socket.
 *
 *   map modes    --map F [--apply-inc F]... [--epoch N] --pool NAME... one of
 *                  --object HEX | --object-str S [--ns HEX | --ns-str S] [--key HEX | --key-str S]   (ceph osd map)
 *                  --names FILE                       one object line per "<pool> <object hex|-> [<ns hex|->  [<key hex|->]]" line
 *                  --dump-pgs                         every PG of the pools (osdmaptool --test-map-pgs-dump-all)
 *                  --dump-state                       the compact state of the base map and after every applied incremental
 *   crush mode   --crush F --rule N --num-rep R --min-x A --max-x B [--pool-id P] [--weight OSD W]...  (crushtool --test --show-mappings)
 *
 * Exit status: 0 all answered, 1 a fatal problem (message on stderr, nothing partial is promised), 2 a usage error, 3 the run
 * finished but some line is an ERROR line (a pool or rule this client does not serve).
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wr_maporacle_fmt.h"
#include "wri_crush.h"
#include "wri_crush_hash.h"
#include "wri_osdmap_dec.h"
#include "wri_place.h"

#define DEFAULT_SLOT_BYTES (8u * 1024u * 1024u)
#define DEFAULT_MAX_OSD 65536u
#define DEFAULT_WORK_MAX 4000000u
#define DEFAULT_MAX_PGS (1u << 22)
#define MAX_ORACLE_DEVICES (1u << 24) /* CRUSH mode: devices a map may name (the weight array is 4 bytes each) */

typedef struct opts {
	const char *map;
	const char *incs[16];
	unsigned n_incs;
	int have_epoch;
	uint64_t epoch;
	const char *pools[WRI_MAP_POOLS_MAX];
	unsigned n_pools;
	int mode_object, mode_names, mode_pgs, mode_state;
	uint8_t *obj, *ns, *key;
	size_t obj_n, ns_n, key_n;
	const char *names_file;
	/* crush mode */
	const char *crush;
	int have_rule, have_rep, have_minx, have_maxx;
	uint64_t rule, num_rep, min_x, max_x;
	int have_pool_id;
	int64_t pool_id;
	uint32_t wdev[256];
	uint32_t wval[256];
	unsigned n_w;
	/* limits */
	uint64_t slot_bytes, max_osd, work_max, max_pgs;
	int verify_crc;
} opts;

static int usage(const char *why)
{
	if (why != NULL)
		fprintf(stderr, "wr-maporacle: %s\n", why);
	fputs("usage: wr-maporacle --map F [--apply-inc F]... [--epoch N] --pool NAME... (--object HEX|--object-str S [--ns HEX|--ns-str S]\n"
	      "                    [--key HEX|--key-str S] | --names FILE | --dump-pgs | --dump-state)\n"
	      "       wr-maporacle --crush F --rule N --num-rep R --min-x A --max-x B [--pool-id P] [--weight OSD W]...\n"
	      "       limits: --slot-bytes N  --max-osd N  --work-max N  --max-pgs N  --no-crc      (see harness/oracle/README.md)\n",
	      stderr);
	return 2;
}

static int fatal(const char *what, const char *detail)
{
	fprintf(stderr, "wr-maporacle: %s%s%s\n", what, detail ? ": " : "", detail ? detail : "");
	return 1;
}

/* A hex argument ("" is empty; "-" is empty too, so a batch line can leave a field out). */
static int hex_arg(const char *s, uint8_t **out, size_t *n)
{
	if (strcmp(s, "-") == 0)
		s = "";
	return wrm_hex_decode(s, strlen(s), out, n);
}

/* The same for an option given twice on the command line: the last one wins and the earlier bytes are released. */
static int hex_opt(const char *s, uint8_t **out, size_t *n)
{
	free(*out);
	*out = NULL;
	*n = 0;
	return hex_arg(s, out, n);
}

static int str_arg(const char *s, uint8_t **out, size_t *n)
{
	size_t l = strlen(s);

	free(*out);
	*out = (uint8_t *)malloc(l + 1u);
	if (*out == NULL)
		return -1;
	memcpy(*out, s, l);
	*n = l;
	return 0;
}

static int need(int argc, int i, int count)
{
	return i + count < argc;
}

/* Returns 0, or the exit status to stop with. */
static int parse_args(int argc, char **argv, opts *o)
{
	int i;

	memset(o, 0, sizeof(*o));
	o->slot_bytes = DEFAULT_SLOT_BYTES;
	o->max_osd = DEFAULT_MAX_OSD;
	o->work_max = DEFAULT_WORK_MAX;
	o->max_pgs = DEFAULT_MAX_PGS;
	o->verify_crc = 1;
	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
			(void)usage(NULL);
			return 2;
		} else if (strcmp(a, "--map") == 0 && need(argc, i, 1)) {
			o->map = argv[++i];
		} else if (strcmp(a, "--apply-inc") == 0 && need(argc, i, 1)) {
			if (o->n_incs == 16u)
				return usage("at most 16 --apply-inc files");
			o->incs[o->n_incs++] = argv[++i];
		} else if (strcmp(a, "--epoch") == 0 && need(argc, i, 1)) {
			if (wrm_parse_u64(argv[++i], &o->epoch) != 0)
				return usage("--epoch wants a number");
			o->have_epoch = 1;
		} else if (strcmp(a, "--pool") == 0 && need(argc, i, 1)) {
			if (o->n_pools == WRI_MAP_POOLS_MAX)
				return usage("at most 8 --pool names (the core tracks that many)");
			if (strlen(argv[i + 1]) == 0 || strlen(argv[i + 1]) > WRI_MAP_NAME_MAX)
				return usage("pool name empty or longer than 128 bytes");
			o->pools[o->n_pools++] = argv[++i];
		} else if (strcmp(a, "--object") == 0 && need(argc, i, 1)) {
			if (hex_opt(argv[++i], &o->obj, &o->obj_n) != 0)
				return usage("--object wants hex (use --object-str for text)");
			o->mode_object = 1;
		} else if (strcmp(a, "--object-str") == 0 && need(argc, i, 1)) {
			if (str_arg(argv[++i], &o->obj, &o->obj_n) != 0)
				return fatal("out of memory", NULL);
			o->mode_object = 1;
		} else if (strcmp(a, "--ns") == 0 && need(argc, i, 1)) {
			if (hex_opt(argv[++i], &o->ns, &o->ns_n) != 0)
				return usage("--ns wants hex (use --ns-str for text)");
		} else if (strcmp(a, "--ns-str") == 0 && need(argc, i, 1)) {
			if (str_arg(argv[++i], &o->ns, &o->ns_n) != 0)
				return fatal("out of memory", NULL);
		} else if (strcmp(a, "--key") == 0 && need(argc, i, 1)) {
			if (hex_opt(argv[++i], &o->key, &o->key_n) != 0)
				return usage("--key wants hex (use --key-str for text)");
		} else if (strcmp(a, "--key-str") == 0 && need(argc, i, 1)) {
			if (str_arg(argv[++i], &o->key, &o->key_n) != 0)
				return fatal("out of memory", NULL);
		} else if (strcmp(a, "--names") == 0 && need(argc, i, 1)) {
			o->names_file = argv[++i];
			o->mode_names = 1;
		} else if (strcmp(a, "--dump-pgs") == 0) {
			o->mode_pgs = 1;
		} else if (strcmp(a, "--dump-state") == 0) {
			o->mode_state = 1;
		} else if (strcmp(a, "--crush") == 0 && need(argc, i, 1)) {
			o->crush = argv[++i];
		} else if (strcmp(a, "--rule") == 0 && need(argc, i, 1)) {
			if (wrm_parse_u64(argv[++i], &o->rule) != 0)
				return usage("--rule wants a number");
			o->have_rule = 1;
		} else if (strcmp(a, "--num-rep") == 0 && need(argc, i, 1)) {
			if (wrm_parse_u64(argv[++i], &o->num_rep) != 0)
				return usage("--num-rep wants a number");
			o->have_rep = 1;
		} else if (strcmp(a, "--min-x") == 0 && need(argc, i, 1)) {
			if (wrm_parse_u64(argv[++i], &o->min_x) != 0 || o->min_x > 0xffffffffu)
				return usage("--min-x wants a 32-bit number");
			o->have_minx = 1;
		} else if (strcmp(a, "--max-x") == 0 && need(argc, i, 1)) {
			if (wrm_parse_u64(argv[++i], &o->max_x) != 0 || o->max_x > 0xffffffffu)
				return usage("--max-x wants a 32-bit number");
			o->have_maxx = 1;
		} else if (strcmp(a, "--pool-id") == 0 && need(argc, i, 1)) {
			if (wrm_parse_i64(argv[++i], &o->pool_id) != 0)
				return usage("--pool-id wants a number");
			o->have_pool_id = 1;
		} else if (strcmp(a, "--weight") == 0 && need(argc, i, 2)) {
			uint64_t dev;
			uint32_t w;

			if (wrm_parse_u64(argv[i + 1], &dev) != 0 || dev > 0x7fffffffu || wrm_parse_weight(argv[i + 2], &w) != 0)
				return usage("--weight wants a device number and a number");
			if (o->n_w == 256u)
				return usage("at most 256 --weight overrides");
			o->wdev[o->n_w] = (uint32_t)dev;
			o->wval[o->n_w++] = w;
			i += 2;
		} else if (strcmp(a, "--slot-bytes") == 0 && need(argc, i, 1)) {
			if (wrm_parse_u64(argv[++i], &o->slot_bytes) != 0 || o->slot_bytes < 4096u || o->slot_bytes > 0x7fffffffu)
				return usage("--slot-bytes wants 4096 .. 2147483647");
		} else if (strcmp(a, "--max-osd") == 0 && need(argc, i, 1)) {
			if (wrm_parse_u64(argv[++i], &o->max_osd) != 0 || o->max_osd == 0 || o->max_osd > WRI_MAP_OSD_HARD_MAX)
				return usage("--max-osd wants 1 .. 262144");
		} else if (strcmp(a, "--work-max") == 0 && need(argc, i, 1)) {
			if (wrm_parse_u64(argv[++i], &o->work_max) != 0 || o->work_max == 0 || o->work_max > 0xffffffffu)
				return usage("--work-max wants a positive 32-bit number");
		} else if (strcmp(a, "--max-pgs") == 0 && need(argc, i, 1)) {
			if (wrm_parse_u64(argv[++i], &o->max_pgs) != 0 || o->max_pgs == 0 || o->max_pgs > 0xffffffffu)
				return usage("--max-pgs wants a positive 32-bit number");
		} else if (strcmp(a, "--no-crc") == 0) {
			o->verify_crc = 0;
		} else {
			fprintf(stderr, "wr-maporacle: unknown or incomplete option '%s'\n", a);
			return usage(NULL);
		}
	}
	return 0;
}

/* ---- CRUSH mode ---------------------------------------------------------------------------------------- */

/* The device weights crushtool --test uses: the --weight value, else 1.0 for a device some bucket holds, else 0. */
static uint32_t *crush_weights(const wri_crush *c, const opts *o, uint32_t *n)
{
	uint32_t nd = c->max_devices > 0 ? (uint32_t)c->max_devices : 0u, i, k;
	uint32_t *w = NULL;
	uint8_t *present = NULL;

	/* a map may name a device id up to 2^31 - 2 in one bucket: do not size two arrays by an id an attacker chose */
	if (nd <= MAX_ORACLE_DEVICES) {
		w = (uint32_t *)calloc(nd + 1u, sizeof(*w));
		present = (uint8_t *)calloc(nd + 1u, 1);
	}
	if (w == NULL || present == NULL) {
		free(w);
		free(present);
		return NULL;
	}
	for (i = 0; i < c->max_buckets; i++) {
		const wri_cbucket *b = wri_crush_bucket_at(c, i);
		const int32_t *it;

		if (b == NULL)
			continue;
		it = wri_cbucket_items(b);
		for (k = 0; k < b->size; k++)
			if (it[k] >= 0 && (uint32_t)it[k] < nd)
				present[it[k]] = 1;
	}
	for (i = 0; i < nd; i++)
		w[i] = present[i] ? 0x10000u : 0u;
	for (k = 0; k < o->n_w; k++)
		if (o->wdev[k] < nd)
			w[o->wdev[k]] = o->wval[k];
	free(present);
	*n = nd;
	return w;
}

static int run_crush(const opts *o)
{
	uint8_t *blob = NULL, *mem = NULL, *region = NULL;
	size_t bn = 0, cap, used = 0;
	const char *err = NULL;
	wr_errinfo why;
	wr_status st = WR_E_MAP_BUDGET;
	const wri_crush *c;
	uint32_t *weights, nw = 0, errors = 0;
	wri_crush_ws *ws;
	uint64_t x;

	if (!o->have_rule || !o->have_rep || !o->have_minx || !o->have_maxx)
		return usage("--crush needs --rule, --num-rep, --min-x and --max-x");
	if (o->num_rep == 0 || o->num_rep > WRI_CRUSH_RESULT_MAX)
		return fatal("--num-rep must be 1 .. 16", NULL);
	if (o->min_x > o->max_x)
		return fatal("--min-x is above --max-x", NULL);
	if (wrm_load_blob(o->crush, &blob, &bn, &err) != 0)
		return fatal(o->crush, err);
	if (bn > ((size_t)1 << 25)) {
		free(blob);
		return fatal(o->crush, "CRUSH map file is larger than 32 MiB");
	}
	memset(&why, 0, sizeof(why));
	for (cap = bn * 8u + 65536u; cap <= ((size_t)1 << 29); cap *= 4u) {
		mem = (uint8_t *)malloc(cap + 16u);
		if (mem == NULL)
			break;
		region = (uint8_t *)(((uintptr_t)mem + 15u) & ~(uintptr_t)15u);
		memset(&why, 0, sizeof(why));
		st = wri_crush_decode(blob, bn, region, cap, &used, &why);
		if (st != WR_E_MAP_BUDGET)
			break;
		free(mem);
		mem = NULL;
	}
	free(blob);
	if (st != WR_OK || mem == NULL) {
		fprintf(stderr, "wr-maporacle: %s: crush decode failed: ", o->crush);
		wrm_put_status(stderr, st, &why);
		fputc('\n', stderr);
		free(mem);
		return 1;
	}
	c = (const wri_crush *)(const void *)region;
	weights = crush_weights(c, o, &nw);
	ws = (wri_crush_ws *)calloc(1, sizeof(*ws));
	if (weights == NULL || ws == NULL) {
		int too_many = c->max_devices > (int32_t)MAX_ORACLE_DEVICES; /* read before the region is released */

		free(weights);
		free(ws);
		free(mem);
		return fatal(too_many ? "the map names too many devices for this tool" : "out of memory", NULL);
	}
	for (x = o->min_x; x <= o->max_x; x++) {
		wri_crush_in in;
		int32_t res[WRI_CRUSH_RESULT_MAX];
		uint32_t n = 0, real_x = (uint32_t)x;

		if (o->have_pool_id && o->pool_id != -1)
			real_x = wri_crush_hash2((uint32_t)x, (uint32_t)o->pool_id);
		in.rule = (uint32_t)o->rule;
		in.x = real_x;
		in.result_max = (uint32_t)o->num_rep;
		in.osd_weight = weights;
		in.weight_max = nw;
		in.args_pool = 0; /* crushtool asks for choose_args key 0 and falls back to the default set */
		ws->work = (uint32_t)o->work_max;
		memset(&why, 0, sizeof(why));
		st = wri_crush_do_rule(c, &in, ws, res, &n, &why);
		if (st != WR_OK) {
			wrm_put_crush_error(stdout, (uint32_t)o->rule, (uint32_t)x, st, &why);
			errors++;
		} else {
			wrm_put_crush_line(stdout, (uint32_t)o->rule, (uint32_t)x, res, n);
		}
	}
	free(weights);
	free(ws);
	free(mem);
	return errors ? 3 : 0;
}

/* ---- map modes -------------------------------------------------------------------------------------------- */

typedef struct mapctx {
	wri_mapcfg cfg;
	uint8_t *raw[2];
	uint8_t *slot[2];
	size_t cap;
	int cur;
	wri_crush_ws *ws;
	uint32_t work_max;
} mapctx;

static const wri_osdmap *held(const mapctx *c)
{
	return (const wri_osdmap *)(const void *)c->slot[c->cur];
}

static void mapctx_free(mapctx *c)
{
	free(c->raw[0]);
	free(c->raw[1]);
	free(c->ws);
}

static int mapctx_init(mapctx *c, const opts *o)
{
	unsigned k, s;

	memset(c, 0, sizeof(*c));
	c->cfg.slot_bytes = (uint32_t)o->slot_bytes;
	c->cfg.max_osd = (uint32_t)o->max_osd;
	c->cfg.work_max = (uint32_t)o->work_max;
	c->cfg.verify_crc = (uint8_t)o->verify_crc;
	c->cfg.n_pools = (uint8_t)o->n_pools;
	for (k = 0; k < o->n_pools; k++) {
		c->cfg.name_len[k] = (uint8_t)strlen(o->pools[k]);
		memcpy(c->cfg.name[k], o->pools[k], c->cfg.name_len[k]);
	}
	c->cap = (size_t)o->slot_bytes;
	c->work_max = (uint32_t)o->work_max;
	c->ws = (wri_crush_ws *)calloc(1, sizeof(*c->ws));
	for (s = 0; s < 2u; s++) {
		c->raw[s] = (uint8_t *)malloc(c->cap + 16u);
		if (c->raw[s] == NULL || c->ws == NULL)
			return -1;
		c->slot[s] = (uint8_t *)(((uintptr_t)c->raw[s] + 15u) & ~(uintptr_t)15u);
	}
	return 0;
}

/* Load the base map into slot 0, then apply the incrementals; the state of every step goes to `state_out` when not NULL. */
static int load_maps(mapctx *c, const opts *o, FILE *state_out)
{
	uint8_t *blob = NULL;
	size_t bn = 0, i;
	const char *err = NULL;
	wr_errinfo why;
	wr_status st;
	unsigned f;
	int stop = 0; /* an incremental above --epoch was reached: nothing after it is applied, in this file or the next */

	if (wrm_load_blob(o->map, &blob, &bn, &err) != 0)
		return fatal(o->map, err);
	memset(&why, 0, sizeof(why));
	st = wri_osdmap_decode_full(&c->cfg, blob, bn, c->slot[0], c->cap, &why);
	free(blob);
	if (st != WR_OK) {
		fprintf(stderr, "wr-maporacle: %s: ", o->map);
		wrm_put_status(stderr, st, &why);
		fputc('\n', stderr);
		return 1;
	}
	c->cur = 0;
	if (state_out != NULL && !(o->have_epoch && held(c)->epoch > o->epoch))
		wrm_put_state(state_out, held(c), &c->cfg);
	for (f = 0; f < o->n_incs && !stop; f++) {
		wrm_item *items = NULL;
		size_t cnt = 0;

		if (wrm_load_items(o->incs[f], &items, &cnt, &err) != 0)
			return fatal(o->incs[f], err);
		for (i = 0; i < cnt; i++) {
			wri_map_blob_info info;

			memset(&why, 0, sizeof(why));
			st = wri_osdmap_inc_info(items[i].p, items[i].n, &info, &why);
			if (st != WR_OK) {
				fprintf(stderr, "wr-maporacle: %s entry %u: ", o->incs[f], (unsigned)(i + 1u));
				wrm_put_status(stderr, st, &why);
				fputc('\n', stderr);
				wrm_items_free(items, cnt);
				return 1;
			}
			if (o->have_epoch && info.epoch > o->epoch) {
				stop = 1;
				break;
			}
			if (info.epoch <= held(c)->epoch)
				continue; /* already part of the held map */
			memset(&why, 0, sizeof(why));
			st = wri_osdmap_apply_inc(&c->cfg, held(c), items[i].p, items[i].n, c->slot[1 - c->cur], c->cap, &why);
			if (st != WR_OK) {
				fprintf(stderr, "wr-maporacle: incremental of epoch %u: ", (unsigned)info.epoch);
				wrm_put_status(stderr, st, &why);
				fputc('\n', stderr);
				wrm_items_free(items, cnt);
				return 1;
			}
			c->cur = 1 - c->cur;
			if (state_out != NULL)
				wrm_put_state(state_out, held(c), &c->cfg);
		}
		wrm_items_free(items, cnt);
	}
	return 0;
}

static int64_t tracked_index(const mapctx *c, const uint8_t *name, size_t n)
{
	uint32_t k;

	for (k = 0; k < c->cfg.n_pools; k++)
		if (c->cfg.name_len[k] == n && memcmp(c->cfg.name[k], name, n) == 0)
			return (int64_t)k;
	return -1;
}

/* One object of tracked pool k: the line, or an error line. Returns 1 when it was an error line. */
static int one_object(const mapctx *c, unsigned k, const uint8_t *name, size_t nn, const uint8_t *ns, size_t nsn, const uint8_t *key,
		      size_t kn)
{
	const wri_osdmap *m = held(c);
	const wri_map_pool *p = &wri_map_pools(m)[k];
	wri_oid oid;
	wri_pg_result res;
	wr_errinfo why;
	wr_status st;
	uint32_t ps = 0, seed;

	memset(&why, 0, sizeof(why));
	if (!p->present) {
		wrm_put_object_error(stdout, m->epoch, c->cfg.name[k], c->cfg.name_len[k], -1, name, nn, ns, nsn, WR_E_POOL_NOT_FOUND, NULL);
		return 1;
	}
	if (p->status != WR_OK) {
		wrm_put_object_error(stdout, m->epoch, c->cfg.name[k], c->cfg.name_len[k], p->id, name, nn, ns, nsn, (wr_status)p->status, NULL);
		return 1;
	}
	oid.name = name;
	oid.name_len = (uint32_t)nn;
	oid.nspace = ns;
	oid.nspace_len = (uint32_t)nsn;
	oid.key = key;
	oid.key_len = (uint32_t)kn;
	st = wri_place_hash(p, &oid, &ps);
	if (st == WR_OK) {
		seed = wri_place_pg_seed(p, ps);
		st = wri_place_pg(m, k, seed, c->work_max, c->ws, &res, &why);
	} else {
		seed = 0;
	}
	if (st != WR_OK) {
		wrm_put_object_error(stdout, m->epoch, c->cfg.name[k], c->cfg.name_len[k], p->id, name, nn, ns, nsn, st, &why);
		return 1;
	}
	wrm_put_object_line(stdout, m->epoch, c->cfg.name[k], c->cfg.name_len[k], p->id, name, nn, ns, nsn, ps, seed, &res);
	return 0;
}

/* The batch file: one line per object. */
static int run_names(const mapctx *c, const opts *o)
{
	FILE *f = fopen(o->names_file, "r");
	char *line = NULL;
	size_t cap = 0, lineno = 0;
	int rc = 0;
	int ch;
	size_t len = 0;

	if (f == NULL)
		return fatal(o->names_file, "cannot open file");
	for (;;) {
		char *tok[4], *p, *hash;
		unsigned nt = 0;

		len = 0;
		while ((ch = fgetc(f)) != EOF && ch != '\n') {
			if (len + 2u > cap) {
				char *nl = (char *)realloc(line, cap ? cap * 2u : 1024u);

				if (nl == NULL) {
					free(line);
					fclose(f);
					return fatal("out of memory", NULL);
				}
				line = nl;
				cap = cap ? cap * 2u : 1024u;
			}
			line[len++] = (char)ch;
		}
		if (ch == EOF && len == 0)
			break;
		lineno++;
		if (line == NULL)
			continue;
		line[len] = '\0';
		hash = strchr(line, '#');
		if (hash != NULL)
			*hash = '\0';
		for (p = line; *p != '\0';) {
			while (*p == ' ' || *p == '\t' || *p == '\r')
				p++;
			if (*p == '\0')
				break;
			if (nt == 4u) {
				nt = 5u;
				break;
			}
			tok[nt++] = p;
			while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\r')
				p++;
			if (*p != '\0')
				*p++ = '\0';
		}
		if (nt == 0)
			continue;
		if (nt < 2u || nt > 4u) {
			fprintf(stderr, "wr-maporacle: %s:%u: want \"<pool> <object hex> [<ns hex> [<key hex>]]\"\n", o->names_file, (unsigned)lineno);
			rc = 1;
			break;
		}
		{
			uint8_t *name = NULL, *ns = NULL, *key = NULL;
			size_t nn = 0, nsn = 0, kn = 0;
			int64_t k = tracked_index(c, (const uint8_t *)tok[0], strlen(tok[0]));
			int bad = 0;

			if (k < 0) {
				fprintf(stderr, "wr-maporacle: %s:%u: pool '%s' was not given with --pool\n", o->names_file, (unsigned)lineno, tok[0]);
				rc = 1;
			} else if (hex_arg(tok[1], &name, &nn) != 0 || (nt > 2u && hex_arg(tok[2], &ns, &nsn) != 0) ||
				   (nt > 3u && hex_arg(tok[3], &key, &kn) != 0)) {
				fprintf(stderr, "wr-maporacle: %s:%u: object, namespace and key must be hex (or -)\n", o->names_file, (unsigned)lineno);
				bad = 1;
				rc = 1;
			} else if (one_object(c, (unsigned)k, name, nn, ns, nsn, key, kn) != 0 && rc == 0) {
				rc = 3;
			}
			free(name);
			free(ns);
			free(key);
			if (k < 0 || bad)
				break;
		}
		if (ch == EOF)
			break;
	}
	free(line);
	fclose(f);
	return rc;
}

static int run_pgs(const mapctx *c, const opts *o)
{
	const wri_osdmap *m = held(c);
	const wri_map_pool *pl = wri_map_pools(m);
	uint32_t done[WRI_MAP_POOLS_MAX];
	uint32_t n_done = 0, k, errors = 0;

	for (k = 0; k < c->cfg.n_pools; k++)
		if (!pl[k].present) {
			fprintf(stderr, "wr-maporacle: pool '%.*s' is not in the map (epoch %u)\n", (int)c->cfg.name_len[k], (const char *)c->cfg.name[k],
				(unsigned)m->epoch);
			return 1;
		}
	/* a damaged map can claim any pg_num: a pool above the limit stops the run before the first line is printed */
	for (k = 0; k < c->cfg.n_pools; k++)
		if (pl[k].status == WR_OK && pl[k].pg_num > o->max_pgs) {
			fprintf(stderr, "wr-maporacle: pool '%.*s' has pg_num %u, above --max-pgs %u\n", (int)c->cfg.name_len[k], (const char *)c->cfg.name[k],
				(unsigned)pl[k].pg_num, (unsigned)o->max_pgs);
			return 1;
		}
	/* pools in ascending id, as osdmaptool walks them */
	while (n_done < c->cfg.n_pools) {
		int64_t best = 0;
		int have = 0;
		uint32_t bi = 0, i;
		uint32_t seed;

		for (i = 0; i < c->cfg.n_pools; i++) {
			uint32_t j;
			int taken = 0;

			for (j = 0; j < n_done; j++)
				if (done[j] == i)
					taken = 1;
			if (!taken && (!have || pl[i].id < best)) {
				best = pl[i].id;
				bi = i;
				have = 1;
			}
		}
		done[n_done++] = bi;
		if (pl[bi].status != WR_OK) {
			wrm_put_pool_error(stdout, pl[bi].id, (wr_status)pl[bi].status);
			errors++;
			continue;
		}
		for (seed = 0; seed < pl[bi].pg_num; seed++) {
			wri_pg_result res;
			wr_errinfo why;
			wr_status st;

			memset(&why, 0, sizeof(why));
			st = wri_place_pg(m, bi, seed, c->work_max, c->ws, &res, &why);
			if (st != WR_OK) {
				wrm_put_pg_error(stdout, pl[bi].id, seed, st, &why);
				errors++;
			} else {
				wrm_put_pg_line(stdout, pl[bi].id, seed, &res);
			}
		}
	}
	return errors ? 3 : 0;
}

static int run_map(const opts *o)
{
	mapctx c;
	int rc, modes = o->mode_object + o->mode_names + o->mode_pgs + o->mode_state;

	if (o->map == NULL)
		return usage("need --map (or --crush)");
	if (modes != 1)
		return usage("exactly one of --object, --names, --dump-pgs and --dump-state");
	if (o->n_pools == 0)
		return usage("need at least one --pool NAME (the core only keeps the pools it is told to track)");
	if (o->mode_object && o->n_pools != 1u)
		return usage("--object takes exactly one --pool");
	if (mapctx_init(&c, o) != 0) {
		mapctx_free(&c);
		return fatal("out of memory", NULL);
	}
	rc = load_maps(&c, o, o->mode_state ? stdout : NULL);
	if (rc == 0) {
		if (o->mode_object) {
			rc = one_object(&c, 0, o->obj, o->obj_n, o->ns, o->ns_n, o->key, o->key_n) ? 3 : 0;
		} else if (o->mode_names) {
			rc = run_names(&c, o);
		} else if (o->mode_pgs) {
			rc = run_pgs(&c, o);
		}
	}
	mapctx_free(&c);
	return rc;
}

int main(int argc, char **argv)
{
	opts o;
	int rc = parse_args(argc, argv, &o);

	if (rc == 0 && o.crush != NULL && o.map != NULL)
		rc = usage("--crush and --map are two different modes");
	if (rc == 0)
		rc = o.crush != NULL ? run_crush(&o) : run_map(&o);
	/* a write that failed earlier (a full disk, a closed pipe) is remembered by the stream, not by the final flush */
	if ((fflush(stdout) != 0 || ferror(stdout)) && rc == 0)
		rc = fatal("write error", NULL);
	free(o.obj);
	free(o.ns);
	free(o.key);
	return rc;
}
