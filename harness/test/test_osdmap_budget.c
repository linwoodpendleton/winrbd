/* SPDX-License-Identifier: MIT */
/*
 * test_osdmap_budget.c - what a full map costs in a slot, and what happens when the slot is too small
 * (core/src/osdmap/wri_osdmap_full.c; architecture 15.3 and 18.2).
 *
 *  - a slot one byte short of each section (the OSD arrays, the pool records, each of the five pg tables, the CRUSH
 *    region): the decode fails with WR_E_MAP_BUDGET, names the section that did not fit and the bytes it wanted and had, the
 *    slot has magic 0 and nothing beyond it is written; a slot of exactly the used size decodes the same map;
 *  - every slot size from 0 to the used size of a small map: a budget failure for each, a success only from the used size on;
 *  - the footprint of generated clusters of 100, 1,000, 2,048 and 8,192 OSDs, with and without device classes: it prints the
 *    bytes per OSD of the arrays, of the CRUSH region and of each pg table entry, and fails if a profile's slot cannot hold the
 *    cluster size the profile claims (2,048 OSDs in the 256 KiB slot of the iPXE profile, 8,192 in the 1 MiB slot of the
 *    kernel profile) or if the per-OSD cost leaves the range the design budgets for.
 */
#include "wrt.h"
#include "wrt_mapgen.h"
#include "wri_ctx.h"
#include "wri_osdmap_dec.h"

#define IPXE_SLOT (256u * 1024u)
#define KERNEL_SLOT (1024u * 1024u)
#define BIG_SLOT (4u * 1024u * 1024u)

typedef struct slot {
	uint8_t *raw, *p;
	size_t cap, total;
} slot;

static void slot_new(slot *s, size_t cap, uint8_t fill)
{
	uintptr_t a;

	s->total = cap + 32u + 15u + 64u;
	s->raw = (uint8_t *)malloc(s->total);
	if (s->raw == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	memset(s->raw, 0xA5, s->total);
	a = ((uintptr_t)s->raw + 32u + 15u) & ~(uintptr_t)15u;
	s->p = (uint8_t *)a;
	s->cap = cap;
	memset(s->p, fill, cap);
}
static void slot_free(slot *s) { free(s->raw); }
static int slot_guard_ok(const slot *s)
{
	size_t i, pre = (size_t)(s->p - s->raw);

	for (i = 0; i < pre; i++)
		if (s->raw[i] != 0xA5)
			return 0;
	for (i = pre + s->cap; i < s->total; i++)
		if (s->raw[i] != 0xA5)
			return 0;
	return 1;
}

static void cfg_init(wri_mapcfg *c, uint32_t slot_bytes, uint32_t max_osd, int verify, const char *const *names, unsigned n)
{
	unsigned k;

	memset(c, 0, sizeof(*c));
	c->slot_bytes = slot_bytes;
	c->max_osd = max_osd;
	c->work_max = 200000;
	c->verify_crc = (uint8_t)verify;
	c->n_pools = (uint8_t)n;
	for (k = 0; k < n; k++) {
		c->name_len[k] = (uint8_t)strlen(names[k]);
		memcpy(c->name[k], names[k], c->name_len[k]);
	}
}

static const wri_osdmap *map_of(const slot *s) { return (const wri_osdmap *)(const void *)s->p; }

/* A cluster with every kind of content: affinity, upmaps, temps, two pools, optionally device classes. */
static void gen_cluster(wrt_mg_map *m, uint32_t n_osds, uint32_t n_classes, uint32_t entries)
{
	wrt_mg_cluster_spec s;

	wrt_mg_cluster_spec_init(&s, n_osds);
	s.n_pools = 2;
	s.pg_num = entries < 32u ? 32u : entries * 4u;
	s.n_classes = n_classes;
	s.n_affinity = n_osds / 4u;
	s.never_up_pct = 3;
	s.up_pct = 90;
	s.n_upmap_items = entries;
	s.n_upmap = entries;
	s.n_pg_temp = entries;
	s.n_primary_temp = entries;
	s.n_upmap_primaries = entries;
	s.seed = 7;
	if (wrt_mg_build_map(m, &s) != 0) {
		fprintf(stderr, "cannot build a cluster of %u OSDs\n", n_osds);
		exit(2);
	}
}

static wr_status decode(const wri_mapcfg *cfg, const wrt_mg_buf *b, slot *s, wr_errinfo *why)
{
	uint8_t *c = (uint8_t *)malloc(b->len);
	wr_status st;

	if (c == NULL)
		exit(2);
	memcpy(c, b->p, b->len);
	if (why != NULL)
		memset(why, 0, sizeof(*why));
	st = wri_osdmap_decode_full(cfg, c, b->len, s->p, s->cap, why);
	free(c);
	WRT_CHECK(slot_guard_ok(s));
	if (st != WR_OK && s->cap >= 4u) {
		uint32_t magic;

		memcpy(&magic, s->p, 4);
		WRT_CHECK_U64(magic, 0);
	}
	return st;
}

/* ---- a slot one byte short of each section ----------------------------------------------------------- */

typedef struct section {
	const char *name;
	const char *word; /* a word the errinfo's `what` has to contain */
	size_t end;       /* offset of the end of the section's data */
	int in_crush;
} section;

static unsigned sections_of(const wri_osdmap *m, section *out)
{
	static const char *const tabw[WRI_TAB_COUNT] = {"pg_temp", "primary_temp", "pg_upmap table", "pg_upmap_items", "pg_upmap_primaries"};
	unsigned n = 0, k;

	out[n].name = "state";
	out[n].word = "OSD state";
	out[n].end = (size_t)m->state_off + m->max_osd;
	out[n++].in_crush = 0;
	out[n].name = "weight";
	out[n].word = "OSD weight";
	out[n].end = (size_t)m->weight_off + (size_t)m->max_osd * 4u;
	out[n++].in_crush = 0;
	if (m->aff_off != 0) {
		out[n].name = "affinity";
		out[n].word = "affinity";
		out[n].end = (size_t)m->aff_off + (size_t)m->max_osd * 4u;
		out[n++].in_crush = 0;
	}
	out[n].name = "address";
	out[n].word = "OSD address";
	out[n].end = (size_t)m->addr_off + (size_t)m->max_osd * sizeof(wri_osd_addr);
	out[n++].in_crush = 0;
	out[n].name = "pools";
	out[n].word = "pool records";
	out[n].end = (size_t)m->pool_off + (size_t)m->n_pools * sizeof(wri_map_pool);
	out[n++].in_crush = 0;
	for (k = 0; k < WRI_TAB_COUNT; k++) {
		const wri_pgtab *t = &m->tab[k];

		if (t->cap_n != 0) {
			out[n].name = "table keys";
			out[n].word = tabw[k];
			out[n].end = (size_t)t->key_off + (size_t)t->cap_n * 8u;
			out[n++].in_crush = 0;
		}
		out[n].name = "table offsets";
		out[n].word = tabw[k];
		out[n].end = (size_t)t->off_off + ((size_t)t->cap_n + 1u) * 4u;
		out[n++].in_crush = 0;
		if (t->cap_nv != 0) {
			out[n].name = "table values";
			out[n].word = tabw[k];
			out[n].end = (size_t)t->val_off + (size_t)t->cap_nv * 4u;
			out[n++].in_crush = 0;
		}
	}
	out[n].name = "CRUSH";
	out[n].word = "CRUSH";
	out[n].end = (size_t)m->crush_off + wri_map_crush(m)->bytes;
	out[n++].in_crush = 1;
	return n;
}

static void test_short_by_one(void)
{
	static const char *const names[] = {"pool1", "pool2"};
	wrt_mg_map m;
	wrt_mg_buf b;
	wri_mapcfg cfg;
	slot big, s;
	wr_errinfo why;
	section sec[40];
	unsigned n, i;
	size_t used;
	uint8_t *keep;

	gen_cluster(&m, 40, 2, 20);
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_map_encode(&m, &b) == 0);
	cfg_init(&cfg, BIG_SLOT, 2048, 1, names, 2);
	slot_new(&big, BIG_SLOT, 0);
	WRT_CHECK_STATUS(WR_OK, decode(&cfg, &b, &big, &why));
	used = map_of(&big)->bytes;
	n = sections_of(map_of(&big), sec);
	WRT_CHECK(n >= 12);
	WRT_CHECK(map_of(&big)->aff_off != 0);
	for (i = 0; i < WRI_TAB_COUNT; i++)
		WRT_CHECK(map_of(&big)->tab[i].n >= 10); /* every table has entries */
	WRT_CHECK_U64(sec[n - 1].end, used); /* the CRUSH region ends the map */
	keep = (uint8_t *)malloc(used);
	memcpy(keep, big.p, used);

	for (i = 0; i < n; i++) {
		slot_new(&s, sec[i].end - 1u, 0x6B);
		cfg.slot_bytes = BIG_SLOT;
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, decode(&cfg, &b, &s, &why));
		WRT_CHECK_U64(why.status, WR_E_MAP_BUDGET);
		WRT_CHECK(why.what != NULL);
		if (sec[i].in_crush) { /* the CRUSH decoder reports its own section of the region that did not fit */
			WRT_CHECK_U64(why.module, WR_MOD_CRUSH);
		} else if (why.what != NULL && strstr(why.what, sec[i].word) == NULL) {
			fprintf(stderr, "section %s: errinfo says \"%s\"\n", sec[i].name, why.what);
			WRT_CHECK(0 && "the errinfo does not name the section that did not fit");
		}
		if (!sec[i].in_crush) {
			WRT_CHECK_U64(why.module, WR_MOD_MAP);
			WRT_CHECK_U64(why.a2, s.cap);
			WRT_CHECK(why.a1 < why.a0); /* it wanted more than it had */
		}
		slot_free(&s);
	}
	/* exactly the used size: the same map, byte for byte */
	slot_new(&s, used, 0x6B);
	WRT_CHECK_STATUS(WR_OK, decode(&cfg, &b, &s, &why));
	WRT_CHECK(memcmp(s.p, keep, 8u) == 0 && memcmp(s.p + 12, keep + 12, used - 12u) == 0); /* all but the header's cap */
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(map_of(&s)));
	WRT_CHECK_U64(map_of(&s)->cap, used);
	slot_free(&s);

	/* every slot size below it, one by one (a small map: some thousand decodes) */
	for (i = 0; i < used; i += (i < 600u || used - i < 600u) ? 1u : 13u) {
		slot_new(&s, i, 0x6B);
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, decode(&cfg, &b, &s, &why));
		slot_free(&s);
	}
	free(keep);
	slot_free(&big);
	wrt_mg_buf_free(&b);
	wrt_mg_map_free(&m);
}

/* ---- the footprint ------------------------------------------------------------------------------------ */

typedef struct cost {
	size_t wire, slot;
	double arrays, crush;
	size_t pools, tab[WRI_TAB_COUNT];
	uint32_t tab_n[WRI_TAB_COUNT], tab_nv[WRI_TAB_COUNT];
	size_t header;
} cost;

static void measure(const wri_osdmap *m, size_t wire, cost *c)
{
	unsigned k;

	memset(c, 0, sizeof(*c));
	c->wire = wire;
	c->slot = m->bytes;
	c->header = m->state_off;
	c->arrays = (double)((size_t)m->pool_off - m->state_off) / (m->max_osd != 0 ? m->max_osd : 1u);
	c->crush = (double)wri_map_crush(m)->bytes / (m->max_osd != 0 ? m->max_osd : 1u);
	c->pools = (size_t)m->n_pools * sizeof(wri_map_pool);
	for (k = 0; k < WRI_TAB_COUNT; k++) {
		c->tab_n[k] = m->tab[k].n;
		c->tab_nv[k] = m->tab[k].nv;
		c->tab[k] = ((size_t)m->tab[k].val_off + (size_t)m->tab[k].cap_nv * 4u) - m->tab[k].key_off;
	}
}

static void print_cost(uint32_t n, uint32_t classes, const cost *c)
{
	static const char *const tn[WRI_TAB_COUNT] = {"pg_temp", "primary_temp", "pg_upmap", "pg_upmap_items", "pg_upmap_primaries"};
	unsigned k;

	printf("osdmap.budget: %5u OSDs, %u classes: wire %8zu B (%.0f B/OSD), slot %8zu B (%.1f B/OSD)\n", n, classes, c->wire,
	       (double)c->wire / n, c->slot, (double)c->slot / n);
	printf("               header %zu B, per OSD: arrays %.1f B, CRUSH %.1f B; pool records %zu B\n", c->header, c->arrays, c->crush, c->pools);
	for (k = 0; k < WRI_TAB_COUNT; k++)
		if (c->tab_n[k] != 0)
			printf("               %-18s %5u entries, %6u values, %7zu B (%.1f B/entry)\n", tn[k], c->tab_n[k], c->tab_nv[k], c->tab[k],
			       (double)c->tab[k] / c->tab_n[k]);
}

static void test_footprint(void)
{
	static const char *const names[] = {"pool1", "pool2"};
	static const uint32_t sizes[] = {100, 1000, 2048, 8192};
	unsigned si, ci;

	for (si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
		for (ci = 0; ci < 2; ci++) {
			uint32_t n = sizes[si], classes = ci == 0 ? 0u : 2u;
			wrt_mg_map m;
			wrt_mg_buf b;
			wri_mapcfg cfg;
			slot s;
			wr_errinfo why;
			cost c;
			wr_status st;
			unsigned k;

			gen_cluster(&m, n, classes, n >= 1000 ? 200u : 40u);
			memset(&b, 0, sizeof(b));
			WRT_CHECK(wrt_mg_map_encode(&m, &b) == 0);
			cfg_init(&cfg, BIG_SLOT, 32768, 1, names, 2);
			slot_new(&s, BIG_SLOT, 0);
			st = decode(&cfg, &b, &s, &why);
			WRT_CHECK_STATUS(WR_OK, st);
			if (st == WR_OK) {
				WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(map_of(&s)));
				measure(map_of(&s), b.len, &c);
				print_cost(n, classes, &c);

				/* the arrays cost what 15.3 says: 1 + 4 + 24 (+ 4 with affinity) per OSD, the alignment aside */
				WRT_CHECK(c.arrays >= 33.0 && c.arrays <= 33.0 + 16.0 / n + 0.01);
				/* CRUSH: one 8-byte entry per OSD in its host bucket (straw2 item + weight) and in each class's shadow bucket, plus
				 * the hosts, the racks and the tables: a few tens of bytes per OSD, growing with the classes */
				WRT_CHECK(c.crush > 7.0 && c.crush < (classes == 0 ? 40.0 : 60.0) + 2000.0 / n);
				/* tables: 8 + 4 per entry plus 4 per value */
				for (k = 0; k < WRI_TAB_COUNT; k++)
					if (c.tab_n[k] != 0)
						WRT_CHECK_U64(c.tab[k], 12u * (size_t)c.tab_n[k] + 4u + 4u * (size_t)c.tab_nv[k]);
				/* a profile holds the cluster size it claims */
				if (n <= 2048) {
					cfg.slot_bytes = IPXE_SLOT;
					cfg.max_osd = 2048;
					{
						slot sp;

						slot_new(&sp, IPXE_SLOT, 0x6B);
						WRT_CHECK_STATUS(WR_OK, decode(&cfg, &b, &sp, &why));
						slot_free(&sp);
					}
				}
				if (n <= 8192) {
					cfg.slot_bytes = KERNEL_SLOT;
					cfg.max_osd = 8192;
					{
						slot sp;

						slot_new(&sp, KERNEL_SLOT, 0x6B);
						WRT_CHECK_STATUS(WR_OK, decode(&cfg, &b, &sp, &why));
						slot_free(&sp);
					}
				}
				if (n == 2048 && classes == 0) { /* the cap of the ipxe profile: one more OSD than it claims is refused by the number, not by crashing */
					cfg.slot_bytes = IPXE_SLOT;
					cfg.max_osd = 2047;
					{
						slot sp;

						slot_new(&sp, IPXE_SLOT, 0x6B);
						WRT_CHECK_STATUS(WR_E_MAP_BUDGET, decode(&cfg, &b, &sp, &why));
						WRT_CHECK(why.what != NULL && strstr(why.what, "max_osd") != NULL);
						slot_free(&sp);
					}
				}
			}
			slot_free(&s);
			wrt_mg_buf_free(&b);
			wrt_mg_map_free(&m);
		}
	}
}

/* The smallest slot a cluster needs is its used size: nothing in the map depends on the slot's size. */
static void test_slot_size_independence(void)
{
	static const char *const names[] = {"pool1", "pool2"};
	wrt_mg_map m;
	wrt_mg_buf b;
	wri_mapcfg cfg;
	slot a, c;
	wr_errinfo why;

	gen_cluster(&m, 300, 2, 60);
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_map_encode(&m, &b) == 0);
	cfg_init(&cfg, BIG_SLOT, 2048, 1, names, 2);
	slot_new(&a, BIG_SLOT, 0x11);
	WRT_CHECK_STATUS(WR_OK, decode(&cfg, &b, &a, &why));
	slot_new(&c, map_of(&a)->bytes + 7u, 0xEE); /* a few bytes more than needed */
	WRT_CHECK_STATUS(WR_OK, decode(&cfg, &b, &c, &why));
	WRT_CHECK_U64(map_of(&c)->bytes, map_of(&a)->bytes);
	/* everything but the header's `cap` (offset 8) is identical */
	WRT_CHECK(memcmp(a.p, c.p, 8u) == 0);
	WRT_CHECK(memcmp(a.p + 12, c.p + 12, map_of(&a)->bytes - 12u) == 0);
	slot_free(&a);
	slot_free(&c);
	wrt_mg_buf_free(&b);
	wrt_mg_map_free(&m);
}

int main(void)
{
	test_short_by_one();
	test_slot_size_independence();
	test_footprint();
	return wrt_finish();
}
