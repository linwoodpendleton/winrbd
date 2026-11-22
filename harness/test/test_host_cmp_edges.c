/* SPDX-License-Identifier: MIT */
/*
 * test_host_cmp_edges.c - the edge generator of the krbd comparison (harness/host/wrl_cmp_edges.c), no network (ctest host.cmp.edges).
 *
 * The list is a pure function of the geometry, so what is checked here is the list itself:
 *   determinism   the same geometry gives the same list twice, byte for byte, and a fixed digest of the list for fixed geometries (so a change of
 *                 the generator is a visible change of the test: the digest is updated on purpose);
 *   coverage      at every order of the lab matrix (12, 16, 18, 20, 22, 25) and at the sector sizes 512 and 4096, on an image with a partial last
 *                 object, with an odd number of bytes at its end and with exactly whole objects: every class of wrl_cmp.h is present;
 *   truth         the classes an op claims are the classes its numbers have (an op that says END_AFTER ends one byte after a boundary, ...): the
 *                 claim is recomputed here from first principles, independently of the generator;
 *   validity      every op that is not a past-the-end op lies inside the image, every past-the-end op begins at or crosses its end, nothing is empty
 *                 except a flush; the list fits WRL_CMP_EDGES_MAX;
 *   small images  one object, a partial one, sizes of 1 .. 4097 bytes: valid lists, never a crash, never a range outside the image;
 *   refusals      an unusable geometry (size 0, order outside 9 .. 30, a sector that is not a power of two) gives an empty list;
 *   cap           a cap smaller than the list writes that many entries and still returns the full count; NULL counts.
 */
#include "wrl_cmp.h"
#include "wrt.h"

#define ALL_CLASSES ((1ull << WRL_EC_COUNT) - 1u)

static uint64_t digest_list(const wrl_cmp_edge *l, uint32_t n)
{
	uint64_t h = 0xcbf29ce484222325ull;
	uint32_t i;
	unsigned k;

	for (i = 0; i < n; i++) {
		uint64_t f[4];

		f[0] = (uint64_t)l[i].kind << 8 | l[i].pat;
		f[1] = l[i].off;
		f[2] = l[i].len;
		f[3] = l[i].classes;
		for (k = 0; k < 4u; k++) {
			unsigned b;

			for (b = 0; b < 8u; b++)
				h = (h ^ ((f[k] >> (8u * b)) & 0xffu)) * 0x100000001b3ull;
		}
	}
	return h;
}

/* The classes an op has by its numbers, written again from the definitions in wrl_cmp.h (the generator derives them the same way; this is the second reading). */
static uint64_t claimed_ok(const wrl_cmp_geom *g, const wrl_cmp_edge *e, const char **why)
{
	uint64_t o = 1ull << g->order, nobj = (g->size + o - 1u) / o, last = (nobj - 1u) * o, end = e->off + e->len;
	uint64_t c = e->classes;

	*why = "";
	if (e->kind == WRL_CMP_K_FLUSH)
		return c == (1ull << WRL_EC_FLUSH);
	if (e->kind == WRL_CMP_K_PAST)
		return (c & (1ull << WRL_EC_PAST_END)) != 0u;
	if (((c >> WRL_EC_LEN_1) & 1u) != (e->len == 1u)) { *why = "len_1"; return 0; }
	if (((c >> WRL_EC_LEN_512) & 1u) != (e->len == 512u)) { *why = "len_512"; return 0; }
	if (((c >> WRL_EC_LEN_4095) & 1u) != (e->len == 4095u)) { *why = "len_4095"; return 0; }
	if (((c >> WRL_EC_LEN_4096) & 1u) != (e->len == 4096u)) { *why = "len_4096"; return 0; }
	if (((c >> WRL_EC_LEN_4097) & 1u) != (e->len == 4097u)) { *why = "len_4097"; return 0; }
	if (((c >> WRL_EC_LEN_OBJ1) & 1u) != (e->len == o)) { *why = "len_obj1"; return 0; }
	if (((c >> WRL_EC_LEN_OBJ2) & 1u) != (e->len == 2u * o)) { *why = "len_obj2"; return 0; }
	if (((c >> WRL_EC_LEN_OBJ3) & 1u) != (e->len == 3u * o)) { *why = "len_obj3"; return 0; }
	if (((c >> WRL_EC_END_AT) & 1u) != (end % o == 0u)) { *why = "end_at"; return 0; }
	if (((c >> WRL_EC_END_BEFORE) & 1u) != (end % o == o - 1u)) { *why = "end_before"; return 0; }
	if (((c >> WRL_EC_END_AFTER) & 1u) != (end % o == 1u)) { *why = "end_after"; return 0; }
	if (((c >> WRL_EC_START_AT) & 1u) != (e->off % o == 0u)) { *why = "start_at"; return 0; }
	if (((c >> WRL_EC_START_BEFORE) & 1u) != (e->off % o == o - 1u)) { *why = "start_before"; return 0; }
	if (((c >> WRL_EC_START_AFTER) & 1u) != (e->off % o == 1u)) { *why = "start_after"; return 0; }
	if (((c >> WRL_EC_UNALIGNED) & 1u) != (e->off % g->sector != 0u)) { *why = "unaligned"; return 0; }
	if (((c >> WRL_EC_OBJ_FIRST) & 1u) != (e->len == 1u && e->off % o == 0u)) { *why = "obj_first"; return 0; }
	if (((c >> WRL_EC_OBJ_LAST) & 1u) != (e->len == 1u && e->off % o == o - 1u)) { *why = "obj_last"; return 0; }
	if (((c >> WRL_EC_IMG_FIRST) & 1u) != (e->len == 1u && e->off == 0u)) { *why = "img_first"; return 0; }
	if (((c >> WRL_EC_IMG_LAST) & 1u) != (e->len == 1u && e->off == g->size - 1u)) { *why = "img_last"; return 0; }
	if (((c >> WRL_EC_LASTOBJ_FIRST) & 1u) != (e->len == 1u && e->off == last)) { *why = "lastobj_first"; return 0; }
	if (((c >> WRL_EC_LASTOBJ_LAST) & 1u) != (e->len == 1u && e->off == g->size - 1u)) { *why = "lastobj_last"; return 0; }
	if (((c >> WRL_EC_LASTOBJ_WHOLE) & 1u) != (e->off == last && e->len == g->size - last)) { *why = "lastobj_whole"; return 0; }
	if (((c >> WRL_EC_ZEROES) & 1u) != (e->kind == WRL_CMP_K_ZEROES)) { *why = "zeroes"; return 0; }
	if ((c & ((1ull << WRL_EC_DISCARD_OBJ) | (1ull << WRL_EC_DISCARD_PART))) != 0u && e->kind != WRL_CMP_K_DISCARD) { *why = "discard on a non-discard"; return 0; }
	if (e->kind == WRL_CMP_K_DISCARD && ((c >> WRL_EC_DISCARD_OBJ) & 1u) == ((c >> WRL_EC_DISCARD_PART) & 1u)) { *why = "a discard is whole xor partial"; return 0; }
	if (((c >> WRL_EC_ZERO_OBJ) & 1u) != 0u && !(e->kind == WRL_CMP_K_WRITE && e->pat == 1u && e->off % o == 0u)) { *why = "zero_obj"; return 0; }
	return 1;
}

static void check_geometry(const wrl_cmp_geom *g, int want_all)
{
	static wrl_cmp_edge a[WRL_CMP_EDGES_MAX], b[WRL_CMP_EDGES_MAX];
	uint32_t n = wrl_cmp_edges_build(g, NULL, 0), n2, i;
	uint64_t seen = 0, o = 1ull << g->order;

	WRT_CHECK(n > 0u && n <= WRL_CMP_EDGES_MAX);
	if (n == 0u || n > WRL_CMP_EDGES_MAX)
		return;
	n2 = wrl_cmp_edges_build(g, a, WRL_CMP_EDGES_MAX);
	WRT_CHECK_U64(n2, n);
	WRT_CHECK_U64(wrl_cmp_edges_build(g, b, WRL_CMP_EDGES_MAX), n);
	WRT_CHECK(memcmp(a, b, n * sizeof(a[0])) == 0); /* deterministic */
	for (i = 0; i < n; i++) {
		const char *why = "";
		const wrl_cmp_edge *e = &a[i];

		seen |= e->classes;
		WRT_CHECK(e->kind >= WRL_CMP_K_READ && e->kind <= WRL_CMP_K_PAST);
		WRT_CHECK(e->pat <= 2u);
		if (e->kind == WRL_CMP_K_FLUSH) {
			WRT_CHECK_U64(e->len, 0);
		} else if (e->kind == WRL_CMP_K_PAST) {
			WRT_CHECK(e->off >= g->size - 1u && e->len >= 1u);
			WRT_CHECK(e->off + e->len > g->size); /* it begins at or past the end, or crosses it */
		} else {
			WRT_CHECK(e->len >= 1u);
			WRT_CHECK(e->off < g->size && e->len <= g->size - e->off);
			if (e->kind == WRL_CMP_K_READ || e->kind == WRL_CMP_K_DISCARD || e->kind == WRL_CMP_K_ZEROES)
				WRT_CHECK_U64(e->pat, 0); /* only a write has a pattern */
		}
		if (!claimed_ok(g, e, &why)) {
			WRT_CHECK(0);
			fprintf(stderr, "  edge %u (kind %u off %llu len %llu classes 0x%llx): claim wrong at %s (order %u size %llu sector %u)\n", i, (unsigned)e->kind,
				(unsigned long long)e->off, (unsigned long long)e->len, (unsigned long long)e->classes, why, (unsigned)g->order,
				(unsigned long long)g->size, (unsigned)g->sector);
		}
	}
	(void)o;
	if (want_all && seen != ALL_CLASSES) {
		unsigned c;

		WRT_CHECK(0);
		for (c = 0; c < WRL_EC_COUNT; c++)
			if (!((seen >> c) & 1u))
				fprintf(stderr, "  class %s is missing at order %u size %llu sector %u\n", wrl_cmp_class_name(c), (unsigned)g->order,
					(unsigned long long)g->size, (unsigned)g->sector);
	}
	/* a cap smaller than the list */
	{
		wrl_cmp_edge small[3];

		memset(small, 0xAA, sizeof(small));
		WRT_CHECK_U64(wrl_cmp_edges_build(g, small, 3), n);
		WRT_CHECK(memcmp(small, a, sizeof(small)) == 0);
		WRT_CHECK_U64(wrl_cmp_edges_build(g, a, 0), n);
	}
}

static void test_coverage_every_order(void)
{
	static const unsigned orders[] = {12, 16, 18, 20, 22, 25};
	unsigned i, s;
	static const uint32_t sectors[] = {512, 4096};

	for (i = 0; i < sizeof(orders) / sizeof(orders[0]); i++) {
		uint64_t o = 1ull << orders[i];

		for (s = 0; s < 2u; s++) {
			wrl_cmp_geom g;

			g.order = (uint8_t)orders[i];
			g.sector = sectors[s];
			g.size = 24u * o + o / 3u + 512u * 5u; /* a partial last object, sector multiple */
			check_geometry(&g, 1);
			g.size = 24u * o + o / 3u + 77u;       /* ... with an odd number of bytes at the very end */
			check_geometry(&g, 1);
			g.size = 25u * o;                      /* a whole number of objects: the last object is a whole one */
			check_geometry(&g, 1);
		}
	}
}

static void test_small_and_odd_images(void)
{
	static const uint64_t sizes[] = {1, 2, 511, 512, 513, 4095, 4096, 4097, 8192, 1u << 16, (1u << 16) + 1u, 3u * 512u * 1024u + 5u};
	unsigned i, order;

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		for (order = 9; order <= 25u; order += 4u) {
			wrl_cmp_geom g;

			g.size = sizes[i];
			g.order = (uint8_t)order;
			g.sector = 512;
			check_geometry(&g, 0);
		}
	}
	/* one object, a partial one, many objects: the classes that need room are simply absent, the list stays valid */
	{
		wrl_cmp_geom g = {1u << 20, 20, 512};

		check_geometry(&g, 0);
		g.size = 1u << 19;
		check_geometry(&g, 0);
		g.size = (1ull << 20) * 3u;
		check_geometry(&g, 0);
	}
}

static void test_unusable_geometry(void)
{
	wrl_cmp_geom g = {1u << 20, 16, 512};
	wrl_cmp_edge e[4];

	WRT_CHECK_U64(wrl_cmp_edges_build(NULL, e, 4), 0);
	g.size = 0;
	WRT_CHECK_U64(wrl_cmp_edges_build(&g, e, 4), 0);
	g.size = 1u << 20;
	g.order = 8;
	WRT_CHECK_U64(wrl_cmp_edges_build(&g, e, 4), 0);
	g.order = 31;
	WRT_CHECK_U64(wrl_cmp_edges_build(&g, e, 4), 0);
	g.order = 16;
	g.sector = 0;
	WRT_CHECK_U64(wrl_cmp_edges_build(&g, e, 4), 0);
	g.sector = 513;
	WRT_CHECK_U64(wrl_cmp_edges_build(&g, e, 4), 0);
	g.sector = 256;
	WRT_CHECK_U64(wrl_cmp_edges_build(&g, e, 4), 0);
	g.sector = 512;
	WRT_CHECK(wrl_cmp_edges_build(&g, e, 4) > 0u);
}

static void golden(const wrl_cmp_geom *g, uint32_t want_n, uint64_t want_digest)
{
	static wrl_cmp_edge l[WRL_CMP_EDGES_MAX];
	uint32_t n = wrl_cmp_edges_build(g, l, WRL_CMP_EDGES_MAX);
	uint64_t d = digest_list(l, n);

	if (getenv("WRT_PRINT_GOLDEN") != NULL)
		fprintf(stderr, "  golden order %u size %llu sector %u: %u edges, digest 0x%016llxull\n", (unsigned)g->order, (unsigned long long)g->size,
			(unsigned)g->sector, (unsigned)n, (unsigned long long)d);
	WRT_CHECK_U64(n, want_n);
	WRT_CHECK_U64(d, want_digest);
}

static void test_names_and_golden(void)
{
	unsigned c, d;
	wrl_cmp_geom g16 = {40u * 65536u + 21504u + 100u, 16, 512};
	wrl_cmp_geom g12 = {300u * 4096u + 1536u, 12, 512};
	wrl_cmp_geom g25 = {40ull << 20, 25, 4096};

	for (c = 0; c < WRL_EC_COUNT; c++) {
		WRT_CHECK(wrl_cmp_class_name(c) != NULL && wrl_cmp_class_name(c)[0] != '\0' && wrl_cmp_class_name(c)[0] != '?');
		for (d = c + 1u; d < WRL_EC_COUNT; d++)
			WRT_CHECK(strcmp(wrl_cmp_class_name(c), wrl_cmp_class_name(d)) != 0);
	}
	WRT_CHECK(strcmp(wrl_cmp_class_name(WRL_EC_COUNT), "?") == 0);
	/* The list for fixed geometries has a fixed digest: a change of the generator shows up here, and is made on purpose
	 * (WRT_PRINT_GOLDEN=1 prints the new numbers). */
	golden(&g16, 186, 0xe227737254a69b40ull);
	golden(&g12, 174, 0x58a15d08e5ce0495ull);
	golden(&g25, 100, 0x35a08cdf80b89eb7ull);
}

int main(void)
{
	test_coverage_every_order();
	test_small_and_odd_images();
	test_unusable_geometry();
	test_names_and_golden();
	return wrt_finish();
}
