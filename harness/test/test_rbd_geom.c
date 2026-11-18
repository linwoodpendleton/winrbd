/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_geom.c - unit tests of core/src/rbd/wri_rbd_geom.c, the pure part of image I/O (design 25.2, 25.6; rbd-format2.md
 * 2.1.1, 2.9 to 2.11, 3.7).
 *
 *  - wri_rbd_geom_init: every order 0..255 (12..25 accepted, the rest WR_E_RBD_ORDER), NULL, the output left cleared on failure;
 *    a geometry that init did not produce (order and object size disagree, not a power of two) gives empty answers;
 *  - the worked examples of rbd-format2.md 2.10 (the default layout through the real iterator; the two striped examples through a
 *    reference of the general formula kept here, which is then also run against the default instance as a second model) and the
 *    object names of 2.1.1;
 *  - object counts at every order (zero, one byte, exact multiples, one over, near 2^64);
 *  - the extent iterator against a per-byte model (objno = off / object_size by division, never by shift) on random ranges at every
 *    order 12..25 with random max_run: coverage without gaps, run bounds, maximality, exact in-object offsets; a handful of ranges
 *    checked byte by byte; ranges that end exactly at 2^64; the broken-call convention (empty extent);
 *  - names: object 0, 255, 2^63, 2^64 - 1 and random numbers against snprintf, the 95-byte limit of the prefix, buffer capacity edges
 *    (nothing written past `cap`), empty and unterminated inputs, "rbd_id." and "rbd_header." limits;
 *  - wri_rbd_overlap: exhaustive over a small universe at the bottom and at the top of the 64-bit range (byte-set model), symmetry,
 *    adjacency, empty ranges, ranges reaching 2^64, random ranges against a model with 65-bit ends;
 *  - wri_rbd_discard_op: the table of rbd-format2.md 3.7 at every order, an exhaustive sweep at order 12, invalid extents;
 *  - wri_rbd_op_status: every operation code against every result, the ENOENT rule, zero_fill.
 *
 * Output buffers handed to the functions are exact-size heap blocks so that ASan sees any write past the end.
 */
#include "wrt.h"

#include "wri_rbd_io.h"

/* ---- helpers ------------------------------------------------------------------------------------------------------ */

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;

static uint64_t rnd(void) /* xorshift64* */
{
	uint64_t x = rng_state;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	rng_state = x;
	return x * 0x2545f4914f6cdd1dull;
}

/* uniform-ish in [0, n), n > 0 */
static uint64_t rnd_below(uint64_t n)
{
	return rnd() % n;
}

static char *heap_buf(size_t n)
{
	char *p = (char *)malloc(n ? n : 1);

	if (p == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	memset(p, 0xA5, n);
	return p;
}

static wri_rbd_geom geom_of(unsigned order)
{
	wri_rbd_geom g;

	memset(&g, 0, sizeof(g));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_geom_init(&g, (uint8_t)order));
	return g;
}

#define KiB ((uint64_t)1 << 10)
#define MiB ((uint64_t)1 << 20)
#define GiB ((uint64_t)1 << 30)

/* ---- init --------------------------------------------------------------------------------------------------------- */

static void test_init(void)
{
	unsigned order;
	wri_rbd_geom g;

	for (order = 0; order < 256; order++) {
		memset(&g, 0xff, sizeof(g));
		if (order >= 12 && order <= 25) {
			WRT_CHECK_STATUS(WR_OK, wri_rbd_geom_init(&g, (uint8_t)order));
			WRT_CHECK_U64(g.order, order);
			WRT_CHECK_U64(g.object_size, (uint64_t)1 << order);
		} else {
			WRT_CHECK_STATUS(WR_E_RBD_ORDER, wri_rbd_geom_init(&g, (uint8_t)order));
			/* a failed init leaves nothing usable behind: a zero object size makes every later call an empty answer */
			WRT_CHECK_U64(g.object_size, 0);
			WRT_CHECK_U64(g.order, 0);
		}
	}
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_geom_init(NULL, 22));
	WRT_CHECK_U64(sizeof(wri_rbd_geom), 16);
	/* the default of the tool chain: 4 MiB */
	g = geom_of(22);
	WRT_CHECK_U64(g.object_size, 4 * MiB);
	/* the status text is the documented one */
	WRT_CHECK(strcmp(wr_status_name(WR_E_RBD_ORDER), "WR_E_RBD_ORDER") == 0);
}

/* A geometry that init did not produce (never initialised, hand built, damaged) gives empty answers, never a shift by 64 or more or a
 * mask of a size that is not a power of two. */
static void test_geom_validity(void)
{
	wri_rbd_geom g, ok = geom_of(22);
	uint64_t on, oo;
	uint32_t run;
	unsigned order;
	unsigned i;

	/* init clears every byte it does not set: the reserved bytes are zero and a second init gives the same bytes */
	memset(&g, 0xff, sizeof(g));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_geom_init(&g, 22));
	for (i = 0; i < sizeof(g.reserved8); i++)
		WRT_CHECK_U64(g.reserved8[i], 0);
	WRT_CHECK(memcmp(&g, &ok, sizeof(g)) == 0);

	/* order and object size must agree and lie in 12 .. 25; try every order byte with the size of 4 MiB, and every size with order 22 */
	for (order = 0; order < 256; order++) {
		g = ok;
		g.order = (uint8_t)order;
		on = oo = 77;
		run = 77;
		wri_rbd_geom_extent(&g, 12345, 100, 100, &on, &oo, &run);
		if (order == 22) {
			WRT_CHECK_U64(run, 100);
		} else {
			WRT_CHECK_U64(run, 0);
			WRT_CHECK_U64(on, 0);
			WRT_CHECK_U64(oo, 0);
			WRT_CHECK_U64(wri_rbd_geom_objects(&g, 1 << 30), 0);
			WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, (uint32_t)(4 * MiB)), WRI_OSD_OP_ZERO);
		}
	}
	for (order = 0; order < 64; order++) {
		g = ok;
		g.object_size = (uint64_t)1 << order;
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, 1 << 30), order == 22 ? 256u : 0u);
	}
	{
		static const uint64_t bad[] = {0, 1, 3, 4096 * 3, 4 * MiB - 1, 4 * MiB + 1, 8 * MiB, UINT64_MAX, (uint64_t)1 << 63};
		unsigned b;

		for (b = 0; b < sizeof(bad) / sizeof(bad[0]); b++) {
			g = ok;
			g.object_size = bad[b];
			WRT_CHECK_U64(wri_rbd_geom_objects(&g, 123456789), 0);
			run = 77;
			wri_rbd_geom_extent(&g, 5, 5, 5, &on, &oo, &run);
			WRT_CHECK_U64(run, 0);
			WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, 0), WRI_OSD_OP_ZERO);
			WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, (uint32_t)bad[b]), WRI_OSD_OP_ZERO);
		}
	}
	/* the unchanged geometry still works after all of that (the copies were separate) */
	run = 0;
	wri_rbd_geom_extent(&ok, 4 * MiB - 1, 2, 4096, &on, &oo, &run);
	WRT_CHECK_U64(on, 0);
	WRT_CHECK_U64(oo, 4 * MiB - 1);
	WRT_CHECK_U64(run, 1);
}

/* ---- object counts ------------------------------------------------------------------------------------------------ */

static void test_objects(void)
{
	unsigned order;
	wri_rbd_geom g;

	for (order = 12; order <= 25; order++) {
		uint64_t os = (uint64_t)1 << order;
		uint64_t k;

		g = geom_of(order);
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, 0), 0);
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, 1), 1);
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, os - 1), 1);
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, os), 1);
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, os + 1), 2);
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, 2 * os), 2);
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, 2 * os + 1), 3);
		for (k = 0; k < 64; k++) {
			uint64_t n = rnd_below((uint64_t)1 << 40);
			uint64_t want = n / os + (n % os != 0 ? 1u : 0u); /* by division */

			WRT_CHECK_U64(wri_rbd_geom_objects(&g, n), want);
		}
		/* near 2^64: no wrap in the rounding */
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, UINT64_MAX), (uint64_t)1 << (64 - order));
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, (uint64_t)0 - os + 1), (uint64_t)1 << (64 - order)); /* 2^64 - os + 1 rounds up */
		WRT_CHECK_U64(wri_rbd_geom_objects(&g, (uint64_t)0 - os), ((uint64_t)1 << (64 - order)) - 1); /* 2^64 - os: exact multiple */
	}
	/* the usual cases by name */
	g = geom_of(22);
	WRT_CHECK_U64(wri_rbd_geom_objects(&g, GiB), 256);
	WRT_CHECK_U64(wri_rbd_geom_objects(&g, 10 * GiB + 1), 2561);
	g = geom_of(12);
	WRT_CHECK_U64(wri_rbd_geom_objects(&g, 10 * KiB), 3);
	g = geom_of(25);
	WRT_CHECK_U64(wri_rbd_geom_objects(&g, 100 * MiB), 4);
	/* no geometry: nothing */
	WRT_CHECK_U64(wri_rbd_geom_objects(NULL, 12345), 0);
	memset(&g, 0, sizeof(g));
	WRT_CHECK_U64(wri_rbd_geom_objects(&g, 12345), 0);
}

/* ---- the general striping formula of rbd-format2.md 2.10 (reference, test only) --------------------------------- */

static void ref_stripe(uint64_t object_size, uint64_t su, uint64_t sc, uint64_t cur, uint64_t remaining, uint64_t *objno, uint64_t *in_off,
		       uint64_t *run)
{
	uint64_t spo = object_size / su;
	uint64_t block = cur / su;
	uint64_t stripe = block / sc;
	uint64_t pos = block % sc;
	uint64_t objectset = stripe / spo;
	uint64_t left = su - (cur % su);

	*objno = objectset * sc + pos;
	*in_off = (stripe % spo) * su + (cur % su);
	*run = remaining < left ? remaining : left;
}

/* ---- worked examples ---------------------------------------------------------------------------------------------- */

struct ext {
	uint64_t objno, off;
	uint32_t run;
};

static unsigned walk(const wri_rbd_geom *g, uint64_t off, uint64_t len, uint32_t max_run, struct ext *out, unsigned cap)
{
	unsigned n = 0;

	while (len > 0 && n < cap) {
		wri_rbd_geom_extent(g, off, len, max_run, &out[n].objno, &out[n].off, &out[n].run);
		if (out[n].run == 0)
			break;
		off += out[n].run;
		len -= out[n].run;
		n++;
	}
	return n;
}

static void test_worked_examples(void)
{
	wri_rbd_geom g = geom_of(22);
	struct ext e[8];
	uint64_t on, oo, run;
	char name[WRI_RBD_OBJNAME_MAX];

	/* 2.10, default layout, 4 MiB objects: offset 10 MiB, length 8 MiB */
	WRT_CHECK_U64(walk(&g, 10 * MiB, 8 * MiB, 0xffffffffu, e, 8), 3);
	WRT_CHECK_U64(e[0].objno, 2);
	WRT_CHECK_U64(e[0].off, 2 * MiB);
	WRT_CHECK_U64(e[0].run, 2 * MiB);
	WRT_CHECK_U64(e[1].objno, 3);
	WRT_CHECK_U64(e[1].off, 0);
	WRT_CHECK_U64(e[1].run, 4 * MiB);
	WRT_CHECK_U64(e[2].objno, 4);
	WRT_CHECK_U64(e[2].off, 0);
	WRT_CHECK_U64(e[2].run, 2 * MiB);

	/* the same range with a 1 MiB run cap: eight runs, still object-aligned */
	WRT_CHECK_U64(walk(&g, 10 * MiB, 8 * MiB, (uint32_t)MiB, e, 8), 8);
	WRT_CHECK_U64(e[0].objno, 2);
	WRT_CHECK_U64(e[0].off, 2 * MiB);
	WRT_CHECK_U64(e[1].off, 3 * MiB);
	WRT_CHECK_U64(e[2].objno, 3);
	WRT_CHECK_U64(e[2].off, 0);
	WRT_CHECK_U64(e[7].objno, 4);
	WRT_CHECK_U64(e[7].off, MiB);

	/* the reference formula, run on the default instance (su = object size, sc = 1), gives the same three extents */
	ref_stripe(4 * MiB, 4 * MiB, 1, 10 * MiB, 8 * MiB, &on, &oo, &run);
	WRT_CHECK_U64(on, 2);
	WRT_CHECK_U64(oo, 2 * MiB);
	WRT_CHECK_U64(run, 2 * MiB);

	/* 2.10, striped layout (su 64 KiB, sc 4, 4 MiB objects). The splitter is default-striping only; the reference checks that the
	 * documented results follow from the documented formula so the table stays pinned for the phase that implements it. */
	ref_stripe(4 * MiB, 64 * KiB, 4, 327680, 4096, &on, &oo, &run);
	WRT_CHECK_U64(on, 1);
	WRT_CHECK_U64(oo, 65536);
	WRT_CHECK_U64(run, 4096);
	ref_stripe(4 * MiB, 64 * KiB, 4, 16 * MiB, 4096, &on, &oo, &run);
	WRT_CHECK_U64(on, 4);
	WRT_CHECK_U64(oo, 0);
	WRT_CHECK_U64(run, 4096);

	/* 2.1.1 data object names */
	WRT_CHECK_U64(wri_rbd_obj_name(name, sizeof(name), "rbd_data.abc123", 2), 32);
	WRT_CHECK(strcmp(name, "rbd_data.abc123.0000000000000002") == 0);
	WRT_CHECK_U64(wri_rbd_obj_name(name, sizeof(name), "rbd_data.7.abc123", 255), 34);
	WRT_CHECK(strcmp(name, "rbd_data.7.abc123.00000000000000ff") == 0);
	WRT_CHECK_U64(wri_rbd_obj_name(name, sizeof(name), "rbd_data.2.600ecac4b85c", 0), 40);
	WRT_CHECK(strcmp(name, "rbd_data.2.600ecac4b85c.0000000000000000") == 0);
}

/* ---- the extent iterator against the per-byte model --------------------------------------------------------------- */

/* Check one whole walk of [off, off + len) at `max_run` against the per-byte model; `bytewise` checks every byte of every extent. */
static void check_walk(const wri_rbd_geom *g, uint64_t off, uint64_t len, uint32_t max_run, int bytewise)
{
	uint64_t os = g->object_size;
	uint64_t cur = off, left = len;
	unsigned long n = 0;

	while (left > 0) {
		uint64_t objno = ~(uint64_t)0, oo = ~(uint64_t)0, i, want;
		uint32_t run = 0xdeadbeefu;
		uint64_t room;

		wri_rbd_geom_extent(g, cur, left, max_run, &objno, &oo, &run);
		/* first byte: the model is a division and a remainder */
		if (objno != cur / os || oo != cur % os) {
			WRT_CHECK_U64(objno, cur / os);
			WRT_CHECK_U64(oo, cur % os);
			return;
		}
		/* the run is the largest the three bounds allow */
		room = os - cur % os;
		want = left;
		if (room < want)
			want = room;
		if (max_run < want)
			want = max_run;
		if (run != want) {
			WRT_CHECK_U64(run, want);
			return;
		}
		WRT_CHECK(run >= 1 && oo + run <= os && run <= max_run && run <= left);
		/* the last byte of the run is in the same object, the byte after it either is not or the run stopped for another reason */
		WRT_CHECK_U64((cur + run - 1) / os, objno);
		if (bytewise) {
			for (i = 0; i < run; i++) {
				if ((cur + i) / os != objno || (cur + i) % os != oo + i) {
					WRT_CHECK(0 && "byte of an extent maps elsewhere");
					return;
				}
			}
		}
		cur += run; /* may wrap to 0 at exactly 2^64: left is 0 then */
		left -= run;
		n++;
		if (n > 100000000ul) {
			WRT_CHECK(0 && "walk does not terminate");
			return;
		}
	}
}

static void test_extent_model(void)
{
	unsigned order;
	unsigned iter;

	for (order = 12; order <= 25; order++) {
		wri_rbd_geom g = geom_of(order);
		uint64_t os = g.object_size;

		for (iter = 0; iter < 400; iter++) {
			uint64_t off, len;
			uint32_t max_run;
			unsigned mode = (unsigned)rnd_below(8);

			/* offsets: anywhere, around object boundaries, around the sector size, big */
			switch (rnd_below(5)) {
			case 0: off = rnd_below(64 * os); break;
			case 1: off = rnd_below(64) * os + os - 1 - rnd_below(8); break;
			case 2: off = rnd_below(64) * os + rnd_below(3); break;
			case 3: off = rnd_below(1024) * 512; break;
			default: off = rnd() >> (12 + rnd_below(30)); break; /* below 2^52: off + len cannot wrap */
			}
			/* lengths: tiny, within an object, a few objects, many */
			switch (rnd_below(5)) {
			case 0: len = 1 + rnd_below(8); break;
			case 1: len = 1 + rnd_below(os); break;
			case 2: len = 1 + rnd_below(3 * os); break;
			case 3: len = os * (1 + rnd_below(6)); break;
			default: len = 1 + rnd_below(16 * os); break;
			}
			/* max_run: none, tiny, sector multiples, around the object size, unlimited */
			switch (mode) {
			case 0: max_run = 0xffffffffu; break;
			case 1: max_run = 1 + (uint32_t)rnd_below(7); break;
			case 2: max_run = 512u * (1 + (uint32_t)rnd_below(8)); break;
			case 3: max_run = (uint32_t)(os - 1); break;
			case 4: max_run = (uint32_t)os; break;
			case 5: max_run = (uint32_t)(os + 1); break;
			case 6: max_run = (uint32_t)(os / 2); break;
			default: max_run = 1 + (uint32_t)rnd_below(2 * os); break;
			}
			/* keep the walk short: at most about 50k extents */
			if (len / max_run > 50000u)
				max_run = (uint32_t)(len / 50000u + 1u);
			check_walk(&g, off, len, max_run, len <= 64 * KiB);
		}
		/* exhaustive-ish: every small offset window around the first boundary with a small run cap, byte by byte */
		{
			uint64_t o, l;

			for (o = os - 6; o < os + 6; o++)
				for (l = 1; l <= 14; l++)
					check_walk(&g, o, l, 5, 1);
		}
		/* a range that ends exactly at 2^64 and one that starts at the very last byte */
		check_walk(&g, (uint64_t)0 - 3 * os, 3 * os, 0xffffffffu, 0);
		check_walk(&g, (uint64_t)0 - 3 * os + 7, 3 * os - 7, (uint32_t)(os / 3), 0);
		check_walk(&g, UINT64_MAX, 1, 1, 1);
		check_walk(&g, UINT64_MAX - 100, 101, 0xffffffffu, 1);
		{
			uint64_t on = 0, oo = 0;
			uint32_t run = 0;

			wri_rbd_geom_extent(&g, UINT64_MAX, 1, 0xffffffffu, &on, &oo, &run);
			WRT_CHECK_U64(on, ((uint64_t)1 << (64 - order)) - 1);
			WRT_CHECK_U64(oo, os - 1);
			WRT_CHECK_U64(run, 1);
		}
		/* the second model: the general formula of 2.10 with su = object size and sc = 1 */
		for (iter = 0; iter < 200; iter++) {
			uint64_t off = rnd() >> rnd_below(30), len = 1 + rnd_below(3 * os), on, oo, run;
			uint64_t gon = 0, goo = 0;
			uint32_t grun = 0;

			ref_stripe(os, os, 1, off, len, &on, &oo, &run);
			wri_rbd_geom_extent(&g, off, len, 0xffffffffu, &gon, &goo, &grun);
			WRT_CHECK_U64(gon, on);
			WRT_CHECK_U64(goo, oo);
			WRT_CHECK_U64(grun, run);
		}
	}
	/* the whole 1 GiB of a 4 MiB image from offset 0, one run per object */
	{
		wri_rbd_geom g = geom_of(22);
		uint64_t cur = 0, k;

		for (k = 0; k < 256; k++) {
			uint64_t on = 0, oo = 0;
			uint32_t run = 0;

			wri_rbd_geom_extent(&g, cur, GiB - cur, 0xffffffffu, &on, &oo, &run);
			WRT_CHECK_U64(on, k);
			WRT_CHECK_U64(oo, 0);
			WRT_CHECK_U64(run, 4 * MiB);
			cur += run;
		}
		WRT_CHECK_U64(cur, GiB);
	}
}

static void test_extent_contract(void)
{
	wri_rbd_geom g = geom_of(22);
	uint64_t on, oo;
	uint32_t run;

	/* len or max_run zero: the caller broke the contract; the answer is an empty extent, never a run that fails to advance */
	on = oo = 77;
	run = 77;
	wri_rbd_geom_extent(&g, 12345, 0, 4096, &on, &oo, &run);
	WRT_CHECK_U64(run, 0);
	WRT_CHECK_U64(on, 0);
	WRT_CHECK_U64(oo, 0);
	on = oo = 77;
	run = 77;
	wri_rbd_geom_extent(&g, 12345, 4096, 0, &on, &oo, &run);
	WRT_CHECK_U64(run, 0);
	on = oo = 77;
	run = 77;
	wri_rbd_geom_extent(NULL, 12345, 4096, 4096, &on, &oo, &run);
	WRT_CHECK_U64(run, 0);
	memset(&g, 0, sizeof(g));
	run = 77;
	wri_rbd_geom_extent(&g, 12345, 4096, 4096, &on, &oo, &run);
	WRT_CHECK_U64(run, 0);

	/* max_run of 1: byte at a time */
	g = geom_of(12);
	wri_rbd_geom_extent(&g, 4095, 100, 1, &on, &oo, &run);
	WRT_CHECK_U64(on, 0);
	WRT_CHECK_U64(oo, 4095);
	WRT_CHECK_U64(run, 1);
	wri_rbd_geom_extent(&g, 4096, 100, 1, &on, &oo, &run);
	WRT_CHECK_U64(on, 1);
	WRT_CHECK_U64(oo, 0);
	WRT_CHECK_U64(run, 1);
	/* the largest object (32 MiB) with the largest run cap */
	g = geom_of(25);
	wri_rbd_geom_extent(&g, 0, UINT64_MAX, 0xffffffffu, &on, &oo, &run);
	WRT_CHECK_U64(run, (uint64_t)1 << 25);
}

/* ---- names -------------------------------------------------------------------------------------------------------- */

static void test_obj_names(void)
{
	char name[WRI_RBD_OBJNAME_MAX];
	char ref[160];
	char prefix[128];
	size_t n;
	unsigned i, plen;

	/* object numbers named in the task */
	n = wri_rbd_obj_name(name, sizeof(name), "rbd_data.p", 0);
	WRT_CHECK_U64(n, 27);
	WRT_CHECK(strcmp(name, "rbd_data.p.0000000000000000") == 0);
	n = wri_rbd_obj_name(name, sizeof(name), "rbd_data.p", 255);
	WRT_CHECK_U64(n, 27);
	WRT_CHECK(strcmp(name, "rbd_data.p.00000000000000ff") == 0);
	n = wri_rbd_obj_name(name, sizeof(name), "rbd_data.p", (uint64_t)1 << 63);
	WRT_CHECK_U64(n, 27);
	WRT_CHECK(strcmp(name, "rbd_data.p.8000000000000000") == 0);
	n = wri_rbd_obj_name(name, sizeof(name), "rbd_data.p", UINT64_MAX);
	WRT_CHECK_U64(n, 27);
	WRT_CHECK(strcmp(name, "rbd_data.p.ffffffffffffffff") == 0);
	/* lower-case digits, all sixteen, in order */
	n = wri_rbd_obj_name(name, sizeof(name), "x", 0x0123456789abcdefull);
	WRT_CHECK_U64(n, 18);
	WRT_CHECK(strcmp(name, "x.0123456789abcdef") == 0);
	n = wri_rbd_obj_name(name, sizeof(name), "x", 0xfedcba9876543210ull);
	WRT_CHECK(strcmp(name, "x.fedcba9876543210") == 0);

	/* random object numbers against snprintf */
	for (i = 0; i < 2000; i++) {
		uint64_t o = rnd() >> rnd_below(64);

		n = wri_rbd_obj_name(name, sizeof(name), "rbd_data.7.abc123", o);
		snprintf(ref, sizeof(ref), "rbd_data.7.abc123.%016" PRIx64, o);
		WRT_CHECK_U64(n, strlen(ref));
		WRT_CHECK(strcmp(name, ref) == 0);
	}

	/* the 95-byte limit: the prefix may be 78 bytes, 79 is refused */
	for (plen = 1; plen <= 100; plen++) {
		char *out = heap_buf(160); /* roomy: the 95-byte limit is the rule here, not the capacity */

		memset(prefix, 'p', plen);
		prefix[plen] = '\0';
		n = wri_rbd_obj_name(out, 160, prefix, 0x1234);
		if (plen + 17 <= 95) {
			WRT_CHECK_U64(n, plen + 17);
			WRT_CHECK_U64(strlen(out), plen + 17);
			WRT_CHECK_U64((unsigned char)out[plen], '.');
			WRT_CHECK(strcmp(out + plen + 1, "0000000000001234") == 0);
		} else {
			WRT_CHECK_U64(n, 0);
			WRT_CHECK_U64(out[0], 0); /* a refused name leaves an empty string, not stale bytes */
		}
		free(out);
	}
	/* the exact edge, written out */
	memset(prefix, 'q', 78);
	prefix[78] = '\0';
	WRT_CHECK_U64(wri_rbd_obj_name(name, sizeof(name), prefix, 1), 95);
	prefix[78] = 'q';
	prefix[79] = '\0';
	WRT_CHECK_U64(wri_rbd_obj_name(name, sizeof(name), prefix, 1), 0);

	/* an unterminated prefix is not read past the limit (a 4 KiB block of non-NUL bytes) */
	{
		char *big = heap_buf(4096);

		memset(big, 'z', 4096);
		WRT_CHECK_U64(wri_rbd_obj_name(name, sizeof(name), big, 1), 0);
		free(big);
		big = heap_buf(96); /* exactly 96 non-NUL bytes: too long, and the scan must stop inside the block */
		memset(big, 'z', 96);
		WRT_CHECK_U64(wri_rbd_obj_name(name, sizeof(name), big, 1), 0);
		free(big);
	}

	/* empty and NULL prefix, NULL / empty buffer */
	WRT_CHECK_U64(wri_rbd_obj_name(name, sizeof(name), "", 1), 0);
	WRT_CHECK_U64(name[0], 0);
	WRT_CHECK_U64(wri_rbd_obj_name(name, sizeof(name), NULL, 1), 0);
	WRT_CHECK_U64(wri_rbd_obj_name(NULL, 100, "p", 1), 0);
	WRT_CHECK_U64(wri_rbd_obj_name(name, 0, "p", 1), 0);

	/* capacity edges: needs length + 1 bytes, writes nothing beyond cap */
	for (i = 0; i <= 25; i++) {
		char *out = heap_buf(i ? i : 1);

		n = wri_rbd_obj_name(out, i, "rbd_data.p", 0xabcdef); /* needs 27 + 1 */
		WRT_CHECK_U64(n, 0);
		if (i > 0)
			WRT_CHECK_U64(out[0], 0);
		free(out);
	}
	{
		char *out = heap_buf(28);

		n = wri_rbd_obj_name(out, 28, "rbd_data.p", 0xabcdef);
		WRT_CHECK_U64(n, 27);
		WRT_CHECK(strcmp(out, "rbd_data.p.0000000000abcdef") == 0);
		free(out);
		out = heap_buf(27); /* one short */
		WRT_CHECK_U64(wri_rbd_obj_name(out, 27, "rbd_data.p", 0xabcdef), 0);
		WRT_CHECK_U64(out[0], 0);
		free(out);
	}
	/* the largest possible name fits a WRI_RBD_OBJNAME_MAX buffer exactly */
	memset(prefix, 'm', 78);
	prefix[78] = '\0';
	{
		char *out = heap_buf(WRI_RBD_OBJNAME_MAX);

		WRT_CHECK_U64(wri_rbd_obj_name(out, WRI_RBD_OBJNAME_MAX, prefix, UINT64_MAX), 95);
		WRT_CHECK_U64(out[95], 0);
		free(out);
	}
}

static void test_meta_names(void)
{
	char name[WRI_RBD_OBJNAME_MAX];
	char in[128];
	size_t n;
	unsigned len;

	WRT_CHECK_U64(wri_rbd_id_obj_name(name, sizeof(name), "disk1"), 12);
	WRT_CHECK(strcmp(name, "rbd_id.disk1") == 0);
	WRT_CHECK_U64(wri_rbd_header_obj_name(name, sizeof(name), "600ecac4b85c"), 23);
	WRT_CHECK(strcmp(name, "rbd_header.600ecac4b85c") == 0);
	/* names with dots and dashes pass through verbatim (the image name is the caller's) */
	WRT_CHECK_U64(wri_rbd_id_obj_name(name, sizeof(name), "a.b-c_d"), 14);
	WRT_CHECK(strcmp(name, "rbd_id.a.b-c_d") == 0);

	/* empty / NULL inputs */
	WRT_CHECK_U64(wri_rbd_id_obj_name(name, sizeof(name), ""), 0);
	WRT_CHECK_U64(name[0], 0);
	WRT_CHECK_U64(wri_rbd_header_obj_name(name, sizeof(name), ""), 0);
	WRT_CHECK_U64(wri_rbd_id_obj_name(name, sizeof(name), NULL), 0);
	WRT_CHECK_U64(wri_rbd_header_obj_name(name, sizeof(name), NULL), 0);
	WRT_CHECK_U64(wri_rbd_id_obj_name(NULL, 100, "x"), 0);
	WRT_CHECK_U64(wri_rbd_header_obj_name(name, 0, "x"), 0);

	/* 95-byte limit: "rbd_id." is 7 bytes (88 of name), "rbd_header." is 11 (84 of id) */
	for (len = 1; len <= 100; len++) {
		char *out = heap_buf(160); /* roomy: the 95-byte limit is the rule here, not the capacity */

		memset(in, 'n', len);
		in[len] = '\0';
		n = wri_rbd_id_obj_name(out, 160, in);
		if (len <= 88) {
			WRT_CHECK_U64(n, 7 + len);
			WRT_CHECK_U64(strlen(out), 7 + len);
		} else {
			WRT_CHECK_U64(n, 0);
			WRT_CHECK_U64(out[0], 0);
		}
		n = wri_rbd_header_obj_name(out, 160, in);
		if (len <= 84) {
			WRT_CHECK_U64(n, 11 + len);
			WRT_CHECK_U64(strlen(out), 11 + len);
		} else {
			WRT_CHECK_U64(n, 0);
			WRT_CHECK_U64(out[0], 0);
		}
		free(out);
	}
	WRT_CHECK_U64(WRI_RBD_NAME_MAX, 88); /* the image name limit of the open path matches the id-object limit */

	/* capacity: 7 + 5 = 12 bytes need 13 */
	{
		char *out = heap_buf(12);

		WRT_CHECK_U64(wri_rbd_id_obj_name(out, 12, "disk1"), 0);
		WRT_CHECK_U64(out[0], 0);
		free(out);
		out = heap_buf(13);
		WRT_CHECK_U64(wri_rbd_id_obj_name(out, 13, "disk1"), 12);
		WRT_CHECK(strcmp(out, "rbd_id.disk1") == 0);
		free(out);
	}
	/* an unterminated input is not read past the limit */
	{
		char *big = heap_buf(96);

		memset(big, 'z', 96);
		WRT_CHECK_U64(wri_rbd_id_obj_name(name, sizeof(name), big), 0);
		WRT_CHECK_U64(wri_rbd_header_obj_name(name, sizeof(name), big), 0);
		free(big);
	}
}

/* ---- overlap ------------------------------------------------------------------------------------------------------ */

/* Exhaustive over a 16-byte universe starting at `base`: the byte-set model. */
static void overlap_exhaustive(uint64_t base)
{
	unsigned ao, al, bo, bl;

	for (ao = 0; ao < 16; ao++)
		for (al = 0; ao + al <= 16; al++)
			for (bo = 0; bo < 16; bo++)
				for (bl = 0; bo + bl <= 16; bl++) {
					int want = 0, got;
					unsigned i;

					for (i = 0; i < 16; i++)
						if (i >= ao && i < ao + al && i >= bo && i < bo + bl)
							want = 1;
					got = wri_rbd_overlap(base + ao, al, base + bo, bl);
					if (got != want) {
						fprintf(stderr, "overlap(base+%u,%u, base+%u,%u) base=0x%" PRIx64 ": got %d want %d\n", ao, al, bo, bl,
							base, got, want);
						WRT_CHECK(got == want);
						return;
					}
					WRT_CHECK(got == 0 || got == 1);
				}
}

static void test_overlap(void)
{
	unsigned i;
	const uint64_t top = UINT64_MAX;

	overlap_exhaustive(0);
	overlap_exhaustive(top - 15); /* universe [2^64 - 16, 2^64): the ends touch 2^64 */
	overlap_exhaustive((uint64_t)1 << 63);
	overlap_exhaustive(0x7ffffffffffffff8ull); /* across 2^63 */

	/* the table of the doc comment */
	WRT_CHECK_U64(wri_rbd_overlap(0, 10, 5, 10), 1);
	WRT_CHECK_U64(wri_rbd_overlap(5, 10, 0, 10), 1);
	WRT_CHECK_U64(wri_rbd_overlap(0, 10, 10, 10), 0); /* adjacent */
	WRT_CHECK_U64(wri_rbd_overlap(10, 10, 0, 10), 0);
	WRT_CHECK_U64(wri_rbd_overlap(0, 10, 9, 1), 1);   /* last byte of a */
	WRT_CHECK_U64(wri_rbd_overlap(0, 10, 10, 1), 0);  /* one past */
	WRT_CHECK_U64(wri_rbd_overlap(0, 100, 40, 10), 1); /* containment */
	WRT_CHECK_U64(wri_rbd_overlap(40, 10, 0, 100), 1);
	WRT_CHECK_U64(wri_rbd_overlap(7, 3, 7, 3), 1);     /* identical */
	WRT_CHECK_U64(wri_rbd_overlap(7, 1, 7, 1), 1);     /* one byte, the same byte */
	WRT_CHECK_U64(wri_rbd_overlap(7, 1, 8, 1), 0);
	/* empty ranges intersect nothing, wherever they sit */
	WRT_CHECK_U64(wri_rbd_overlap(5, 0, 0, 100), 0);
	WRT_CHECK_U64(wri_rbd_overlap(0, 100, 5, 0), 0);
	WRT_CHECK_U64(wri_rbd_overlap(5, 0, 5, 0), 0);
	WRT_CHECK_U64(wri_rbd_overlap(0, 0, 0, 0), 0);
	WRT_CHECK_U64(wri_rbd_overlap(top, 0, 0, top), 0);
	WRT_CHECK_U64(wri_rbd_overlap(0, top, top, 0), 0);
	/* near 2^64 */
	WRT_CHECK_U64(wri_rbd_overlap(top - 9, 10, top, 1), 1);        /* [2^64-10, 2^64) holds the last byte */
	WRT_CHECK_U64(wri_rbd_overlap(top - 9, 5, top - 4, 5), 0);     /* adjacent at the top */
	WRT_CHECK_U64(wri_rbd_overlap(top - 9, 6, top - 4, 5), 1);
	WRT_CHECK_U64(wri_rbd_overlap(top, 1, top, 1), 1);
	WRT_CHECK_U64(wri_rbd_overlap(top, 1, top - 1, 1), 0);
	/* a range that runs past 2^64 does not wrap around to the start */
	WRT_CHECK_U64(wri_rbd_overlap(top, 100, 0, 1), 0);
	WRT_CHECK_U64(wri_rbd_overlap(0, 1, top, 100), 0);
	WRT_CHECK_U64(wri_rbd_overlap(top - 5, top, 0, 1), 0);
	WRT_CHECK_U64(wri_rbd_overlap(top - 5, top, 3, 3), 0);
	WRT_CHECK_U64(wri_rbd_overlap(top - 5, top, top, 1), 1);
	WRT_CHECK_U64(wri_rbd_overlap(top, top, top, top), 1);
	/* maximal lengths */
	WRT_CHECK_U64(wri_rbd_overlap(0, top, top - 1, 1), 1);  /* [0, 2^64-1) holds 2^64-2 */
	WRT_CHECK_U64(wri_rbd_overlap(0, top, top, 1), 0);      /* ... and not 2^64-1 */
	WRT_CHECK_U64(wri_rbd_overlap(1, top, 0, 1), 0);
	WRT_CHECK_U64(wri_rbd_overlap(1, top, 1, 1), 1);
	WRT_CHECK_U64(wri_rbd_overlap(0, top, 0, top), 1);

	/* properties on random ranges */
	for (i = 0; i < 200000; i++) {
		uint64_t ao, al, bo, bl;
		int ab, ba;

		switch (rnd_below(4)) {
		case 0: /* small */
			ao = rnd_below(1000); al = rnd_below(100); bo = rnd_below(1000); bl = rnd_below(100);
			break;
		case 1: /* around 2^64 */
			ao = top - rnd_below(1000); al = rnd_below(2000); bo = top - rnd_below(1000); bl = rnd_below(2000);
			break;
		case 2: /* anywhere */
			ao = rnd(); al = rnd() >> rnd_below(64); bo = rnd(); bl = rnd() >> rnd_below(64);
			break;
		default: /* a is built to touch b exactly: adjacency and one-byte overlap */
			bo = rnd() >> rnd_below(40); bl = 1 + (rnd() >> rnd_below(63));
			al = 1 + rnd_below(1000);
			ao = bo - al; /* a ends where b starts (wraps for bo < al: then a lies at the top, away from b) */
			break;
		}
		ab = wri_rbd_overlap(ao, al, bo, bl);
		ba = wri_rbd_overlap(bo, bl, ao, al);
		if (ab != ba) {
			WRT_CHECK(ab == ba); /* symmetry */
			return;
		}
		/* a range always intersects itself unless empty */
		WRT_CHECK_U64(wri_rbd_overlap(ao, al, ao, al), al != 0);
		/* a range does not intersect the empty range */
		WRT_CHECK_U64(wri_rbd_overlap(ao, al, bo, 0), 0);
		{
			/* the ends as 65-bit numbers (carry, low word), so no end can wrap */
			uint64_t a1 = ao + al, b1 = bo + bl;
			unsigned a1c = a1 < ao, b1c = b1 < bo;
			int a_before_b_end = b1c ? 1 : ao < b1; /* a0 < b1: a start below 2^64 is below an end at or past it */
			int b_before_a_end = a1c ? 1 : bo < a1; /* b0 < a1 */
			int want = (al != 0 && bl != 0 && a_before_b_end && b_before_a_end) ? 1 : 0;

			if (ab != want) {
				fprintf(stderr, "overlap(0x%" PRIx64 ",0x%" PRIx64 ", 0x%" PRIx64 ",0x%" PRIx64 "): got %d want %d\n", ao, al, bo, bl, ab,
					want);
				WRT_CHECK(ab == want);
				return;
			}
		}
	}
	/* adjacency at every order and at random positions: [x, x + n) and [x + n, x + n + m) */
	for (i = 0; i < 20000; i++) {
		uint64_t x = rnd() >> 2, n = 1 + rnd_below(1 << 20), m = 1 + rnd_below(1 << 20);

		WRT_CHECK_U64(wri_rbd_overlap(x, n, x + n, m), 0);
		WRT_CHECK_U64(wri_rbd_overlap(x + n, m, x, n), 0);
		WRT_CHECK_U64(wri_rbd_overlap(x, n + 1, x + n, m), 1); /* one byte more: they share x + n */
		WRT_CHECK_U64(wri_rbd_overlap(x + n, m, x, n + 1), 1);
	}
}

/* ---- discard ------------------------------------------------------------------------------------------------------ */

static uint16_t discard_ref(uint64_t os, uint64_t off, uint64_t run)
{
	/* the table of rbd-format2.md 3.7, written from the table: whole object, tail, anything else */
	if (off == 0 && run == os)
		return WRI_OSD_OP_DELETE;
	if (off > 0 && off < os && run > 0 && off + run == os)
		return WRI_OSD_OP_TRUNCATE;
	return WRI_OSD_OP_ZERO;
}

static void test_discard(void)
{
	unsigned order;
	uint64_t off, run;
	wri_rbd_geom g;

	for (order = 12; order <= 25; order++) {
		uint64_t os;

		g = geom_of(order);
		os = g.object_size;
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, (uint32_t)os), WRI_OSD_OP_DELETE);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 1, (uint32_t)(os - 1)), WRI_OSD_OP_TRUNCATE);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 512, (uint32_t)(os - 512)), WRI_OSD_OP_TRUNCATE);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, os / 2, (uint32_t)(os / 2)), WRI_OSD_OP_TRUNCATE);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, os - 1, 1), WRI_OSD_OP_TRUNCATE);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, (uint32_t)(os - 1)), WRI_OSD_OP_ZERO);  /* head, not the whole */
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, (uint32_t)(os / 2)), WRI_OSD_OP_ZERO);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, 1), WRI_OSD_OP_ZERO);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 512, 512), WRI_OSD_OP_ZERO);              /* the middle */
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 1, (uint32_t)(os - 2)), WRI_OSD_OP_ZERO); /* both ends inside */
		/* invalid extents get the harmless shape, never a DELETE or a TRUNCATE */
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, 0), WRI_OSD_OP_ZERO);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, os, 0), WRI_OSD_OP_ZERO);   /* empty at the end: not a truncate to os */
		WRT_CHECK_U64(wri_rbd_discard_op(&g, os, 1), WRI_OSD_OP_ZERO);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, os - 1, 2), WRI_OSD_OP_ZERO);   /* past the end */
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, (uint32_t)os + 1), WRI_OSD_OP_ZERO);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, 0xffffffffu), WRI_OSD_OP_ZERO);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, UINT64_MAX, 1), WRI_OSD_OP_ZERO);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, UINT64_MAX, 0xffffffffu), WRI_OSD_OP_ZERO);
	}
	/* the same extent length is a DELETE at one order and a ZERO at the next */
	g = geom_of(12);
	WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, 4096), WRI_OSD_OP_DELETE);
	g = geom_of(13);
	WRT_CHECK_U64(wri_rbd_discard_op(&g, 0, 4096), WRI_OSD_OP_ZERO);
	WRT_CHECK_U64(wri_rbd_discard_op(&g, 4096, 4096), WRI_OSD_OP_TRUNCATE);
	/* the op codes are the wire values of rbd-format2.md 2.11 */
	WRT_CHECK_U64(WRI_OSD_OP_DELETE, 0x2205);
	WRT_CHECK_U64(WRI_OSD_OP_TRUNCATE, 0x2203);
	WRT_CHECK_U64(WRI_OSD_OP_ZERO, 0x2204);

	/* exhaustive sweep at order 12 against the table, including every invalid pair */
	g = geom_of(12);
	for (off = 0; off <= 4098; off++)
		for (run = 0; run <= 4099; run++) {
			uint16_t got = wri_rbd_discard_op(&g, off, (uint32_t)run);
			uint16_t want = discard_ref(4096, off, run);

			if (got != want) {
				fprintf(stderr, "discard_op(off %" PRIu64 ", run %" PRIu64 ") = 0x%x, want 0x%x\n", off, run, got, want);
				WRT_CHECK(got == want);
				return;
			}
		}
	/* NULL geometry */
	WRT_CHECK_U64(wri_rbd_discard_op(NULL, 0, 4096), WRI_OSD_OP_ZERO);
	{
		wri_rbd_geom z;

		memset(&z, 0, sizeof(z));
		WRT_CHECK_U64(wri_rbd_discard_op(&z, 0, 4096), WRI_OSD_OP_ZERO);
	}
	/* every extent of a walk over a whole image classifies as the shape of the walk: head ZERO, middle DELETE, tail TRUNCATE */
	g = geom_of(22);
	{
		struct ext e[16];
		unsigned n = walk(&g, 3 * MiB, 14 * MiB, 0xffffffffu, e, 16); /* 3 MiB..17 MiB: tail of obj 0, objs 1-3, head of obj 4 */

		WRT_CHECK_U64(n, 5);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, e[0].off, e[0].run), WRI_OSD_OP_TRUNCATE);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, e[1].off, e[1].run), WRI_OSD_OP_DELETE);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, e[2].off, e[2].run), WRI_OSD_OP_DELETE);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, e[3].off, e[3].run), WRI_OSD_OP_DELETE);
		WRT_CHECK_U64(wri_rbd_discard_op(&g, e[4].off, e[4].run), WRI_OSD_OP_ZERO);
	}
}

/* ---- status ------------------------------------------------------------------------------------------------------- */

/* What wri_osd_errno_status documents (wri_osd_msg.h), written out as a table so a change of that mapping shows here. EAGAIN is not
 * among the inputs: the request layer resubmits it and it never reaches a caller. */
static wr_status errno_table(int32_t result)
{
	switch (result) {
	case 0: return WR_OK;
	case -WRI_ERRNO_ENOENT:
	case -WRI_ERRNO_EOPNOTSUPP: return WR_E_OSD_NOENT;
	case -WRI_ERRNO_EPERM: return WR_E_OSD_PERM;
	case -WRI_ERRNO_EIO: return WR_E_OSD_IO;
	case -WRI_ERRNO_ENOSPC:
	case -WRI_ERRNO_EDQUOT: return WR_E_OSD_NOSPC;
	case -WRI_ERRNO_EBLOCKLISTED: return WR_E_OSD_BLOCKLISTED;
	default: break;
	}
	return result > 0 ? WR_OK : WR_E_OSD_ERRNO;
}

static void test_status(void)
{
	static const uint16_t codes[] = {WRI_OSD_OP_READ,     WRI_OSD_OP_STAT,      WRI_OSD_OP_SPARSE_READ, WRI_OSD_OP_WRITE,
					 WRI_OSD_OP_WRITEFULL, WRI_OSD_OP_TRUNCATE,  WRI_OSD_OP_ZERO,        WRI_OSD_OP_DELETE,
					 WRI_OSD_OP_CREATE,    WRI_OSD_OP_SETALLOCHINT, WRI_OSD_OP_GETXATTR,   WRI_OSD_OP_CALL,
					 WRI_OSD_OP_OMAPGETVALS, WRI_OSD_OP_OMAPGETVALSBYKEYS, 0x0000, 0xffff};
	static const int32_t results[] = {0,
					  1,
					  4096,
					  0x7fffffff,
					  -WRI_ERRNO_EPERM,
					  -WRI_ERRNO_ENOENT,
					  -WRI_ERRNO_EIO,
					  -WRI_ERRNO_EEXIST,
					  -WRI_ERRNO_EINVAL,
					  -WRI_ERRNO_EFBIG,
					  -WRI_ERRNO_ENOSPC,
					  -WRI_ERRNO_EOPNOTSUPP,
					  -WRI_ERRNO_EBLOCKLISTED,
					  -WRI_ERRNO_EDQUOT,
					  -WRI_ERRNO_EOLDSNAPC,
					  -3,
					  -255,
					  (int32_t)(-0x7fffffff - 1)};
	unsigned c, r;
	int zf;

	for (c = 0; c < sizeof(codes) / sizeof(codes[0]); c++)
		for (r = 0; r < sizeof(results) / sizeof(results[0]); r++) {
			uint16_t code = codes[c];
			int32_t res = results[r];
			int enoent_ok = res == -WRI_ERRNO_ENOENT &&
					(code == WRI_OSD_OP_READ || code == WRI_OSD_OP_DELETE || code == WRI_OSD_OP_ZERO || code == WRI_OSD_OP_TRUNCATE);
			int want_zf = res == -WRI_ERRNO_ENOENT && code == WRI_OSD_OP_READ;
			wr_status want = enoent_ok ? WR_OK : errno_table(res);
			wr_status got;

			zf = 99; /* the function sets it in every case */
			got = wri_rbd_op_status(code, res, &zf);
			if (got != want || zf != want_zf) {
				fprintf(stderr, "op_status(code 0x%x, result %d) = %d zf %d, want %d zf %d\n", code, (int)res, (int)got, zf, (int)want, want_zf);
				WRT_CHECK(got == want && zf == want_zf);
			}
			WRT_CHECK(want_zf == 0 || want == WR_OK);
			/* everything that is not the ENOENT rule is exactly the OSD errno mapping */
			if (!enoent_ok)
				WRT_CHECK_STATUS(wri_osd_errno_status(res), got);
			/* a NULL zero_fill is accepted and changes nothing else */
			WRT_CHECK_STATUS(got, wri_rbd_op_status(code, res, NULL));
		}

	/* the rule by name */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_op_status(WRI_OSD_OP_READ, 0, &zf));
	WRT_CHECK_U64(zf, 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_op_status(WRI_OSD_OP_READ, 4096, &zf));
	WRT_CHECK_U64(zf, 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_op_status(WRI_OSD_OP_READ, -WRI_ERRNO_ENOENT, &zf));
	WRT_CHECK_U64(zf, 1);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_op_status(WRI_OSD_OP_DELETE, -WRI_ERRNO_ENOENT, &zf));
	WRT_CHECK_U64(zf, 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_op_status(WRI_OSD_OP_ZERO, -WRI_ERRNO_ENOENT, &zf));
	WRT_CHECK_U64(zf, 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_op_status(WRI_OSD_OP_TRUNCATE, -WRI_ERRNO_ENOENT, &zf));
	WRT_CHECK_U64(zf, 0);
	/* a write has no reason to meet ENOENT; if it does, it is an error, not a hole */
	WRT_CHECK_STATUS(WR_E_OSD_NOENT, wri_rbd_op_status(WRI_OSD_OP_WRITE, -WRI_ERRNO_ENOENT, &zf));
	WRT_CHECK_U64(zf, 0);
	WRT_CHECK_STATUS(WR_E_OSD_NOENT, wri_rbd_op_status(WRI_OSD_OP_WRITEFULL, -WRI_ERRNO_ENOENT, &zf));
	WRT_CHECK_STATUS(WR_E_OSD_NOENT, wri_rbd_op_status(WRI_OSD_OP_SPARSE_READ, -WRI_ERRNO_ENOENT, &zf));
	WRT_CHECK_U64(zf, 0);
	/* the other errors of a read stay errors and do not ask for a zero-fill */
	WRT_CHECK_STATUS(WR_E_OSD_IO, wri_rbd_op_status(WRI_OSD_OP_READ, -WRI_ERRNO_EIO, &zf));
	WRT_CHECK_U64(zf, 0);
	WRT_CHECK_STATUS(WR_E_OSD_BLOCKLISTED, wri_rbd_op_status(WRI_OSD_OP_WRITE, -WRI_ERRNO_EBLOCKLISTED, &zf));
	WRT_CHECK_STATUS(WR_E_OSD_BLOCKLISTED, wri_rbd_op_status(WRI_OSD_OP_DELETE, -WRI_ERRNO_EBLOCKLISTED, &zf));
	WRT_CHECK_STATUS(WR_E_OSD_NOSPC, wri_rbd_op_status(WRI_OSD_OP_WRITE, -WRI_ERRNO_ENOSPC, &zf));
	WRT_CHECK_STATUS(WR_E_OSD_NOSPC, wri_rbd_op_status(WRI_OSD_OP_ZERO, -WRI_ERRNO_EDQUOT, &zf));
	WRT_CHECK_STATUS(WR_E_OSD_PERM, wri_rbd_op_status(WRI_OSD_OP_READ, -WRI_ERRNO_EPERM, &zf));
	WRT_CHECK_STATUS(WR_E_OSD_ERRNO, wri_rbd_op_status(WRI_OSD_OP_WRITE, -WRI_ERRNO_EFBIG, &zf));
	WRT_CHECK_STATUS(WR_E_OSD_ERRNO, wri_rbd_op_status(WRI_OSD_OP_WRITE, -WRI_ERRNO_EINVAL, &zf));
	/* a stale zero_fill from an earlier call is cleared */
	zf = 1;
	WRT_CHECK_STATUS(WR_OK, wri_rbd_op_status(WRI_OSD_OP_READ, 512, &zf));
	WRT_CHECK_U64(zf, 0);
}

int main(void)
{
	test_init();
	test_geom_validity();
	test_objects();
	test_worked_examples();
	test_extent_model();
	test_extent_contract();
	test_obj_names();
	test_meta_names();
	test_overlap();
	test_discard();
	test_status();
	return wrt_finish();
}
