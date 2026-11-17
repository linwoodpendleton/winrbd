/* SPDX-License-Identifier: MIT */
/*
 * crush_dec_gen.h - a small CRUSH blob writer for the crush-dec tests and their fuzz seeds.
 *
 * It writes the wire form of docs/spec/crush-and-placement.md 2.2 byte by byte and shares no code with the decoder. On
 * top of the primitives, ks_build() writes the "kitchen sink" map (every bucket algorithm, a hole, rules of two types, the
 * three name maps with a legacy 64-bit-key entry and an empty name, every tunable group, classes, two choose_args sets
 * with weight rows and ids, the MSR pair) up to a chosen stage and records where each field sits, so a test can patch
 * one field and expect one refusal. All functions are static: the header is included by one test.
 */
#ifndef CRUSH_DEC_GEN_H
#define CRUSH_DEC_GEN_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct gb {
	uint8_t *p;
	size_t n, cap;
} gb;

static void gb_init(gb *g)
{
	g->cap = 4096;
	g->p = (uint8_t *)malloc(g->cap);
	g->n = 0;
}

static void gb_free(gb *g)
{
	free(g->p);
	g->p = NULL;
	g->n = g->cap = 0;
}

static void gb_u8(gb *g, uint8_t v)
{
	if (g->n == g->cap) {
		g->cap *= 2;
		g->p = (uint8_t *)realloc(g->p, g->cap);
	}
	g->p[g->n++] = v;
}

static void gb_u16(gb *g, uint16_t v)
{
	gb_u8(g, (uint8_t)(v & 0xffu));
	gb_u8(g, (uint8_t)(v >> 8));
}

static void gb_u32(gb *g, uint32_t v)
{
	gb_u16(g, (uint16_t)(v & 0xffffu));
	gb_u16(g, (uint16_t)(v >> 16));
}

static void gb_i32(gb *g, int32_t v)
{
	gb_u32(g, (uint32_t)v);
}

static void gb_u64(gb *g, uint64_t v)
{
	gb_u32(g, (uint32_t)(v & 0xffffffffu));
	gb_u32(g, (uint32_t)(v >> 32));
}

static void gb_bytes(gb *g, const void *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		gb_u8(g, ((const uint8_t *)p)[i]);
}

/* Overwrite bytes already written (little endian). */
static void gb_patch(gb *g, size_t at, uint32_t v, unsigned width)
{
	unsigned i;

	for (i = 0; i < width; i++)
		g->p[at + i] = (uint8_t)(v >> (8u * i));
}

static gb gb_copy(const gb *g)
{
	gb c;

	c.cap = g->n + 16;
	c.p = (uint8_t *)malloc(c.cap);
	memcpy(c.p, g->p, g->n);
	c.n = g->n;
	return c;
}

/* ---- groups ---------------------------------------------------------------------------------------------- */

static void gb_header(gb *g, uint32_t max_buckets, uint32_t max_rules, int32_t max_devices)
{
	gb_u32(g, 0x00010000u);
	gb_u32(g, max_buckets);
	gb_u32(g, max_rules);
	gb_i32(g, max_devices);
}

/* A bucket: `alg` 1..5. w = item weights (list/straw/straw2), x = list sums or straws; uniform writes w[0]; tree writes
 * `nodes` node weights taken from w (num_nodes as a u8). */
static void gb_bucket(gb *g, uint32_t alg, int32_t id, uint16_t type, uint32_t size, const int32_t *items, const uint32_t *w,
		      const uint32_t *x, unsigned nodes)
{
	uint32_t i, total = 0;

	gb_u32(g, alg);
	gb_i32(g, id);
	gb_u16(g, type);
	gb_u8(g, (uint8_t)alg);
	gb_u8(g, 0);
	for (i = 0; i < size && w != NULL; i++)
		total += w[i];
	gb_u32(g, total);
	gb_u32(g, size);
	for (i = 0; i < size; i++)
		gb_i32(g, items[i]);
	switch (alg) {
	case 1:
		gb_u32(g, w[0]);
		break;
	case 2:
	case 4:
		for (i = 0; i < size; i++) {
			gb_u32(g, w[i]);
			gb_u32(g, x[i]);
		}
		break;
	case 3:
		gb_u8(g, (uint8_t)nodes);
		for (i = 0; i < nodes; i++)
			gb_u32(g, w[i]);
		break;
	default:
		for (i = 0; i < size; i++)
			gb_u32(g, w[i]);
		break;
	}
}

static void gb_hole(gb *g)
{
	gb_u32(g, 0);
}

static void gb_rule(gb *g, uint8_t ruleset, uint8_t type, uint32_t nsteps, const int32_t (*steps)[3], uint8_t min, uint8_t max)
{
	uint32_t i;

	gb_u32(g, 1);
	gb_u32(g, nsteps);
	gb_u8(g, ruleset);
	gb_u8(g, type);
	gb_u8(g, min);
	gb_u8(g, max);
	for (i = 0; i < nsteps; i++) {
		gb_u32(g, (uint32_t)steps[i][0]);
		gb_i32(g, steps[i][1]);
		gb_i32(g, steps[i][2]);
	}
}

/* A name map entry: key, length, bytes; or the legacy form (a 64-bit key: the high half reads as a zero length). */
static void gb_name(gb *g, int32_t key, const char *s, int legacy64)
{
	size_t n = strlen(s);

	gb_i32(g, key);
	if (legacy64 || n == 0)
		gb_u32(g, 0);
	gb_u32(g, (uint32_t)n);
	gb_bytes(g, s, n);
}

/* ---- the kitchen sink map --------------------------------------------------------------------------------- */

#define KS_BUCKETS 7u
#define KS_RULES 3u
#define KS_STAGE_NAMES 0   /* ends after rule_name_map: every tunable group absent */
#define KS_STAGE_TUN_A 1   /* + choose_local_tries, choose_local_fallback_tries, choose_total_tries */
#define KS_STAGE_DESCEND 2 /* + chooseleaf_descend_once */
#define KS_STAGE_VARY_R 3
#define KS_STAGE_STRAW_CALC 4
#define KS_STAGE_ALLOWED 5
#define KS_STAGE_STABLE 6
#define KS_STAGE_CLASSES 7
#define KS_STAGE_ARGS 8
#define KS_STAGE_MSR 9     /* the whole blob, as getcrushmap returns it */

typedef struct ks_off {
	size_t max_dev;
	size_t bk[KS_BUCKETS];  /* start of each slot; fields: +0 marker, +4 id, +8 type, +10 alg, +11 hash, +12 weight, +16 size, +20 items */
	size_t ru[KS_RULES];    /* +0 present, +4 len, +8 ruleset, +9 type, +10 min, +11 max, +12 steps */
	size_t tmap, nmap, rmap; /* start of each name map (the u32 count) */
	size_t nmap_key12;      /* the key of the name_map entry 12 */
	size_t tun, cls, ca;    /* tunables A, class_map, choose_args count */
	size_t set_key[2], set_nb[2];
	size_t s0b0, s0b1, s1b0;  /* the listed buckets: +0 index, +4 n_pos, then rows (size, weights) and ids_size */
	size_t s0b1_row0_size;    /* the size field of the first weight row of the second bucket of set 0 */
	size_t s0b1_row0_w0;      /* its first weight */
	size_t s0b1_ids_size;
	size_t msr;
	size_t end;
} ks_off;

/* Expected facts of the map, for the verification of the decoded region. */
static const int32_t ks_b0_items[3] = {-2, -3, -5};
static const uint32_t ks_b0_w[3] = {0x30000, 0x20000, 0x10000};
static const int32_t ks_b1_items[3] = {0, 1, 2};
static const uint32_t ks_b1_w[3] = {0x10000, 0x8000, 0x10000};
static const int32_t ks_b2_items[2] = {3, 4};
static const uint32_t ks_b2_w[2] = {0x10000, 0x20000};
static const uint32_t ks_b2_sums[2] = {0x10000, 0x30000};
static const int32_t ks_b4_items[2] = {5, 6};
static const uint32_t ks_b4_w[2] = {0x10000, 0x8000};
static const uint32_t ks_b4_straws[2] = {0x11111, 0x22222};
static const int32_t ks_b5_items[3] = {7, 8, 9};
static const uint32_t ks_b5_w[3] = {0x10000, 0x10000, 0x10000};
static const int32_t ks_b6_items[2] = {10, 11};
static const uint32_t ks_b6_nodes[4] = {0x20000, 0x10000, 0x10000, 0};
static const int32_t ks_r0_steps[3][3] = {{1, -1, 0}, {6, 0, 1}, {4, 0, 0}};
static const int32_t ks_r1_steps[2][3] = {{1, -1, 0}, {3, 0, 1}};
static const uint32_t ks_a0b0_row[3] = {0x1000, 0x2000, 0x3000};
static const uint32_t ks_a0b1_rows[2][3] = {{0x4000, 0x5000, 0x6000}, {0x7000, 0x8000, 0x9000}};
static const int32_t ks_a0b1_ids[3] = {100, 101, 102};
static const int32_t ks_a1b0_ids[3] = {7, 8, -9};

static void ks_build(gb *g, int stage, ks_off *o)
{
	uint32_t i;
	ks_off z;

	if (o == NULL)
		o = &z;
	memset(o, 0, sizeof(*o));
	o->max_dev = 12;
	gb_header(g, KS_BUCKETS, KS_RULES, 999); /* the wire max_devices is not trusted */
	o->bk[0] = g->n;
	gb_bucket(g, 5, -1, 11, 3, ks_b0_items, ks_b0_w, NULL, 0);
	o->bk[1] = g->n;
	gb_bucket(g, 5, -2, 1, 3, ks_b1_items, ks_b1_w, NULL, 0);
	o->bk[2] = g->n;
	gb_bucket(g, 2, -3, 1, 2, ks_b2_items, ks_b2_w, ks_b2_sums, 0);
	o->bk[3] = g->n;
	gb_hole(g);
	o->bk[4] = g->n;
	gb_bucket(g, 4, -5, 1, 2, ks_b4_items, ks_b4_w, ks_b4_straws, 0);
	o->bk[5] = g->n;
	gb_bucket(g, 1, -6, 1, 3, ks_b5_items, ks_b5_w, NULL, 0);
	o->bk[6] = g->n;
	gb_bucket(g, 3, -7, 1, 2, ks_b6_items, ks_b6_nodes, NULL, 4);
	o->ru[0] = g->n;
	gb_rule(g, 0, 1, 3, ks_r0_steps, 1, 10);
	o->ru[1] = g->n;
	gb_rule(g, 1, 3, 2, ks_r1_steps, 3, 20);
	o->ru[2] = g->n;
	gb_u32(g, 0); /* a rule hole */

	o->tmap = g->n;
	gb_u32(g, 2);
	gb_name(g, 0, "osd", 0);
	gb_name(g, 1, "host", 1);
	o->nmap = g->n;
	gb_u32(g, 6);
	gb_name(g, -1, "default", 0);
	gb_name(g, 0, "osd.0", 1);
	gb_name(g, 3, "", 0); /* an empty name: key, 0, 0 */
	gb_name(g, -2, "host-a", 0);
	o->nmap_key12 = g->n;
	gb_name(g, 12, "osd.12", 0); /* beyond every bucket item: raises max_devices to 13 */
	gb_name(g, 7, "osd.7", 0);
	o->rmap = g->n;
	gb_u32(g, 1);
	gb_name(g, 0, "replicated_rule", 0);
	o->max_dev = 13;
	o->tun = g->n;
	if (stage >= KS_STAGE_TUN_A) {
		gb_u32(g, 0);
		gb_u32(g, 0);
		gb_u32(g, 50);
	}
	if (stage >= KS_STAGE_DESCEND)
		gb_u32(g, 1);
	if (stage >= KS_STAGE_VARY_R)
		gb_u8(g, 1);
	if (stage >= KS_STAGE_STRAW_CALC)
		gb_u8(g, 1);
	if (stage >= KS_STAGE_ALLOWED)
		gb_u32(g, 0x36);
	if (stage >= KS_STAGE_STABLE)
		gb_u8(g, 1);
	o->cls = g->n;
	if (stage >= KS_STAGE_CLASSES) {
		gb_u32(g, 2); /* class_map */
		gb_i32(g, 0);
		gb_i32(g, 0);
		gb_i32(g, 1);
		gb_i32(g, 0);
		gb_u32(g, 1); /* class_name */
		gb_i32(g, 0);
		gb_u32(g, 3);
		gb_bytes(g, "hdd", 3);
		gb_u32(g, 1); /* class_bucket */
		gb_i32(g, -1);
		gb_u32(g, 1);
		gb_i32(g, 0);
		gb_i32(g, -9);
	}
	o->ca = g->n;
	if (stage >= KS_STAGE_ARGS) {
		gb_u32(g, 2);
		o->set_key[0] = g->n;
		gb_u64(g, (uint64_t)-1); /* the default set */
		o->set_nb[0] = g->n;
		gb_u32(g, 2);
		o->s0b0 = g->n;
		gb_u32(g, 0); /* bucket slot 0: one row, no ids */
		gb_u32(g, 1);
		gb_u32(g, 3);
		for (i = 0; i < 3; i++)
			gb_u32(g, ks_a0b0_row[i]);
		gb_u32(g, 0);
		o->s0b1 = g->n;
		gb_u32(g, 1); /* bucket slot 1: two rows and ids */
		gb_u32(g, 2);
		o->s0b1_row0_size = g->n;
		gb_u32(g, 3);
		o->s0b1_row0_w0 = g->n;
		for (i = 0; i < 3; i++)
			gb_u32(g, ks_a0b1_rows[0][i]);
		gb_u32(g, 3);
		for (i = 0; i < 3; i++)
			gb_u32(g, ks_a0b1_rows[1][i]);
		o->s0b1_ids_size = g->n;
		gb_u32(g, 3);
		for (i = 0; i < 3; i++)
			gb_i32(g, ks_a0b1_ids[i]);
		o->set_key[1] = g->n;
		gb_u64(g, 5); /* the set of pool 5 */
		o->set_nb[1] = g->n;
		gb_u32(g, 1);
		o->s1b0 = g->n;
		gb_u32(g, 1); /* bucket slot 1: ids only */
		gb_u32(g, 0);
		gb_u32(g, 3);
		for (i = 0; i < 3; i++)
			gb_i32(g, ks_a1b0_ids[i]);
	}
	o->msr = g->n;
	if (stage >= KS_STAGE_MSR) {
		gb_u32(g, 100);
		gb_u32(g, 100);
	}
	o->end = g->n;
}

#endif /* CRUSH_DEC_GEN_H */
