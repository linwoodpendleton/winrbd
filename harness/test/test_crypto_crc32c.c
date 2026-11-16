/* SPDX-License-Identifier: MIT */
/*
 * Unit test of wri_crc32c: committed vectors (msgr2/crc32c.json, the crc32c block of
 * secure/primitives.json), known answers, a bitwise reference over every length and alignment,
 * the chaining property, the table regeneration check, and all three slice variants.
 */
#include "wrt.h"

/* The three build variants are compiled into this test under private names, next to the library
 * build (default slice) which is tested through the public symbol. */
#undef WRI_CRC32C_H
#undef WRI_CRC32C_SLICE /* a build may pass -DWRI_CRC32C_SLICE=n for the library; the variants below set their own */
#define WRI_CRC32C_SLICE 1
#define wri_crc32c wrt_crc32c_s1
#define wri_crc32c_tab wrt_tab_s1
#include "wri_crc32c.c"
#undef wri_crc32c
#undef wri_crc32c_tab
#undef WRI_CRC32C_SLICE
#undef WRI_CRC32C_H
#undef WRI_CRC_LD32

#define WRI_CRC32C_SLICE 4
#define wri_crc32c wrt_crc32c_s4
#define wri_crc32c_tab wrt_tab_s4
#include "wri_crc32c.c"
#undef wri_crc32c
#undef wri_crc32c_tab
#undef WRI_CRC32C_SLICE
#undef WRI_CRC32C_H
#undef WRI_CRC_LD32

#define WRI_CRC32C_SLICE 8
#define wri_crc32c wrt_crc32c_s8
#define wri_crc32c_tab wrt_tab_s8
#include "wri_crc32c.c"
#undef wri_crc32c
#undef wri_crc32c_tab
#undef WRI_CRC32C_SLICE
#undef WRI_CRC32C_H
#undef WRI_CRC_LD32

/* The library function. WRI_CRC32C_SLICE is left undefined here; the library's own choice (default or a
 * build override) is exercised through the public symbol only. */
#include "wri_crc32c.h"

#define POLY 0x82F63B78u

typedef uint32_t (*crc_fn)(uint32_t, const uint8_t *, size_t);

static uint32_t crc_s1(uint32_t c, const uint8_t *p, size_t n) { return wrt_crc32c_s1(c, p, n); }
static uint32_t crc_s4(uint32_t c, const uint8_t *p, size_t n) { return wrt_crc32c_s4(c, p, n); }
static uint32_t crc_s8(uint32_t c, const uint8_t *p, size_t n) { return wrt_crc32c_s8(c, p, n); }
static uint32_t crc_lib(uint32_t c, const uint8_t *p, size_t n) { return wri_crc32c(c, p, n); }

static const crc_fn impls[] = {crc_lib, crc_s1, crc_s4, crc_s8};
static const char *const impl_names[] = {"library", "slice1", "slice4", "slice8"};
#define NIMPL (sizeof(impls) / sizeof(impls[0]))

/* Independent bit-at-a-time reference. */
static uint32_t ref_crc(uint32_t crc, const uint8_t *p, size_t n)
{
	size_t i;
	int b;

	for (i = 0; i < n; i++) {
		crc ^= p[i];
		for (b = 0; b < 8; b++)
			crc = (crc & 1u) ? (crc >> 1) ^ POLY : crc >> 1;
	}
	return crc;
}

/* ---- known answers --------------------------------------------------------------------------- */

static void test_known_answers(void)
{
	static const uint8_t s[] = "123456789";
	size_t i;

	for (i = 0; i < NIMPL; i++) {
		WRT_CHECK_U64(impls[i](0xFFFFFFFFu, s, 9), 0x1CF96D7Cu);
		WRT_CHECK_U64(impls[i](0, s, 9), 0x58E3FA20u);
		/* the textbook CRC-32C is the raw update with seed ~0 and a final inversion */
		WRT_CHECK_U64(impls[i](0xFFFFFFFFu, s, 9) ^ 0xFFFFFFFFu, 0xE3069283u);
		/* zero length returns the seed untouched, and never dereferences the pointer */
		WRT_CHECK_U64(impls[i](0x12345678u, NULL, 0), 0x12345678u);
		WRT_CHECK_U64(impls[i](0xFFFFFFFFu, s, 0), 0xFFFFFFFFu);
		WRT_CHECK_U64(impls[i](0, s, 0), 0);
	}
}

/* ---- committed vectors ----------------------------------------------------------------------- */

static void run_vector(const uint8_t *data, size_t n, uint32_t seed, uint32_t want)
{
	size_t i;

	for (i = 0; i < NIMPL; i++) {
		uint32_t got = impls[i](seed, data, n);

		if (got != want)
			fprintf(stderr, "vector (%s, n=%zu, seed=0x%08" PRIx32 ") got 0x%08" PRIx32 " want 0x%08" PRIx32 "\n",
				impl_names[i], n, seed, got, want);
		WRT_CHECK_U64(got, want);
	}
}

/* Run the vector entry `e` whose data lives under `ascii_key` / `hex_key`. Returns 0 if it ran. */
static int run_entry(const wrt_json *j, wrt_tok e, const char *ascii_key, const char *hex_key, const char *seed_key)
{
	uint8_t *data = NULL;
	size_t n = 0;
	int ok_seed = 0, ok_crc = 0;
	wrt_tok t;
	int64_t seed, crc;
	char *ascii;

	t = wrt_json_get(j, e, ascii_key);
	if (t != WRT_NONE) {
		ascii = wrt_json_strdup(j, t);
		WRT_CHECK(ascii != NULL);
		if (!ascii)
			return -1;
		n = strlen(ascii);
		data = (uint8_t *)ascii;
	} else {
		WRT_CHECK(wrt_json_get_hex(j, e, hex_key, &data, &n) == 0);
		if (!data && n != 0)
			return -1;
	}
	seed = wrt_json_int(j, wrt_json_get(j, e, seed_key), &ok_seed);
	crc = wrt_json_int(j, wrt_json_get(j, e, "crc"), &ok_crc);
	WRT_CHECK(ok_seed && ok_crc);
	if (ok_seed && ok_crc)
		run_vector(data, n, (uint32_t)seed, (uint32_t)crc);
	free(data);
	return 0;
}

static void test_msgr2_vectors(void)
{
	wrt_json j;
	wrt_tok vecs, te;
	size_t i, nv;

	if (wrt_json_load_vec(&j, "msgr2/crc32c.json") != 0) {
		WRT_CHECK(0 && "load msgr2/crc32c.json");
		return;
	}
	vecs = wrt_json_get(&j, wrt_json_root(&j), "vectors");
	nv = wrt_json_count(&j, vecs);
	WRT_CHECK(nv >= 6);
	for (i = 0; i < nv; i++)
		WRT_CHECK(run_entry(&j, wrt_json_at(&j, vecs, i), "input_ascii", "input_hex", "seed") == 0);

	/* table_entries: index -> T[0][index] */
	te = wrt_json_get(&j, wrt_json_root(&j), "table_entries");
	WRT_CHECK(te != WRT_NONE);
	nv = (te == WRT_NONE) ? 0 : wrt_json_count(&j, te);
	WRT_CHECK(nv >= 4);
	for (i = 0; i < nv; i++) {
		int ok_i = 0, ok_v = 0;
		wrt_tok val = WRT_NONE;
		const char *key = wrt_json_key_at(&j, te, i, &val);
		char *ks = NULL;
		int64_t idx = -1, want;

		WRT_CHECK(key != NULL);
		if (!key)
			continue;
		ks = (char *)malloc(strlen(key) + 1);
		WRT_CHECK(ks != NULL);
		if (!ks)
			continue;
		strcpy(ks, key);
		idx = (int64_t)strtol(ks, NULL, 10);
		free(ks);
		want = wrt_json_int(&j, val, &ok_v);
		ok_i = (idx >= 0 && idx < 256);
		WRT_CHECK(ok_i && ok_v);
		if (ok_i && ok_v) {
			/* with seed 0 the raw update of the single byte i is exactly T[0][i] */
			uint8_t b = (uint8_t)idx;
			size_t k;

			for (k = 0; k < NIMPL; k++)
				WRT_CHECK_U64(impls[k](0, &b, 1), (uint32_t)want);
		}
	}
	wrt_json_free(&j);
}

static void test_secure_vectors(void)
{
	wrt_json j;
	wrt_tok arr;
	size_t i, nv;

	if (wrt_json_load_vec(&j, "secure/primitives.json") != 0) {
		WRT_CHECK(0 && "load secure/primitives.json");
		return;
	}
	arr = wrt_json_get(&j, wrt_json_root(&j), "crc32c");
	nv = wrt_json_count(&j, arr);
	WRT_CHECK(nv >= 5);
	for (i = 0; i < nv; i++) {
		wrt_tok e = wrt_json_at(&j, arr, i);

		WRT_CHECK(run_entry(&j, e, "data_ascii", "data_hex", "seed") == 0);
	}
	wrt_json_free(&j);
}

/* ---- bitwise reference over lengths and alignments ------------------------------------------- */

#define BUFSZ 320
#define MAXOFF 8

static void fill(uint8_t *b, size_t n, uint32_t s)
{
	size_t i;

	for (i = 0; i < n; i++) {
		s = s * 1664525u + 1013904223u;
		b[i] = (uint8_t)(s >> 24);
	}
}

static void test_reference_sweep(void)
{
	static const uint32_t seeds[] = {0, 0xFFFFFFFFu, 1, 0x80000000u, 0xDEADBEEFu};
	uint8_t buf[BUFSZ + MAXOFF];
	size_t off, len, i, k;
	unsigned long bad = 0;

	fill(buf, sizeof(buf), 0xC0FFEEu);
	for (off = 0; off < MAXOFF; off++) {
		for (len = 0; len <= 300; len++) {
			for (i = 0; i < sizeof(seeds) / sizeof(seeds[0]); i++) {
				uint32_t want = ref_crc(seeds[i], buf + off, len);

				for (k = 0; k < NIMPL; k++) {
					uint32_t got = impls[k](seeds[i], buf + off, len);

					if (got != want) {
						if (bad++ < 5)
							fprintf(stderr, "sweep mismatch %s off=%zu len=%zu seed=0x%08" PRIx32
								" got 0x%08" PRIx32 " want 0x%08" PRIx32 "\n",
								impl_names[k], off, len, seeds[i], got, want);
					}
				}
			}
		}
	}
	/* one counted check for the whole sweep: 8 offsets x 301 lengths x 5 seeds x 4 impls */
	WRT_CHECK(bad == 0);
}

/* A buffer whose end is exactly the end of a heap block, so a read past the end trips ASan. Every start
 * offset 0..7 inside the block is used (the function is alignment-agnostic), and the length covers
 * every combination of 8-, 4- and 1-byte tails. */
static void test_exact_end_buffers(void)
{
	size_t len, off, k;

	for (off = 0; off < MAXOFF; off++) {
		for (len = 1; len <= 70; len++) {
			uint8_t *b = (uint8_t *)malloc(len + off);
			uint32_t want;

			WRT_CHECK(b != NULL);
			if (!b)
				return;
			fill(b, len + off, (uint32_t)(len * 31 + off));
			want = ref_crc(0xFFFFFFFFu, b + off, len);
			for (k = 0; k < NIMPL; k++)
				WRT_CHECK_U64(impls[k](0xFFFFFFFFu, b + off, len), want);
			free(b);
		}
	}
}

/* ---- large buffers --------------------------------------------------------------------------- */

/* msgr2 data segments are up to several MiB: one-shot and randomly chunked passes must both equal the
 * bitwise reference, for an odd length and an odd start offset. */
static void test_large_buffer(void)
{
	const size_t total = (size_t)4 * 1024 * 1024 + 7;
	uint8_t *raw = (uint8_t *)malloc(total + 3);
	uint8_t *b;
	uint32_t want, s = 0x1234567u;
	size_t k, pos;

	WRT_CHECK(raw != NULL);
	if (!raw)
		return;
	b = raw + 3;
	fill(b, total, 0xABCDEFu);
	want = ref_crc(0xFFFFFFFFu, b, total);
	for (k = 0; k < NIMPL; k++) {
		uint32_t c = 0xFFFFFFFFu;

		WRT_CHECK_U64(impls[k](0xFFFFFFFFu, b, total), want);
		pos = 0;
		while (pos < total) {
			size_t chunk;

			s = s * 1664525u + 1013904223u;
			chunk = (s >> 8) % 70001u; /* includes 0 */
			if (chunk > total - pos)
				chunk = total - pos;
			c = impls[k](c, b + pos, chunk);
			pos += chunk;
		}
		WRT_CHECK_U64(c, want);
	}
	/* constant patterns: all-ones and all-zero input of a length that is not a multiple of 8 */
	memset(b, 0xFF, 4099);
	want = ref_crc(0xFFFFFFFFu, b, 4099);
	for (k = 0; k < NIMPL; k++)
		WRT_CHECK_U64(impls[k](0xFFFFFFFFu, b, 4099), want);
	memset(b, 0x00, 4099);
	want = ref_crc(0, b, 4099);
	for (k = 0; k < NIMPL; k++)
		WRT_CHECK_U64(impls[k](0, b, 4099), want);
	free(raw);
}

/* ---- captured frames ------------------------------------------------------------------------- */

static uint32_t ld32(const uint8_t *q)
{
	return (uint32_t)q[0] | ((uint32_t)q[1] << 8) | ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24);
}

/* Every frame of msgr2/frames-crc.json (28 frames taken from real captures, scrubbed with CRCs
 * recomputed): the preamble CRC (seed 0, bytes 0..27, stored at 28), the inline segment-0 CRC (seed
 * 0xFFFFFFFF) and, for multi-segment frames, the epilogue slots (empty used segment = 0xFFFFFFFF,
 * unused = 0) must all equal what each implementation computes. */
static void test_frame_vectors(void)
{
	wrt_json j;
	wrt_tok frames;
	size_t i, nf, nchecked = 0;

	if (wrt_json_load_vec(&j, "msgr2/frames-crc.json") != 0) {
		WRT_CHECK(0 && "load msgr2/frames-crc.json");
		return;
	}
	frames = wrt_json_get(&j, wrt_json_root(&j), "frames");
	nf = wrt_json_count(&j, frames);
	WRT_CHECK(nf >= 20);
	for (i = 0; i < nf; i++) {
		wrt_tok e = wrt_json_at(&j, frames, i);
		uint8_t *f = NULL;
		size_t n = 0, k, seg, off, nseg;
		uint32_t len[4] = {0, 0, 0, 0};
		int ok = 0;
		int64_t pc, sc;
		wrt_tok lens = wrt_json_get(&j, e, "segment_lengths");

		if (wrt_json_get_hex(&j, e, "hex", &f, &n) != 0 || n < 33) {
			WRT_CHECK(0 && "frame hex");
			free(f);
			continue;
		}
		nseg = wrt_json_count(&j, lens);
		WRT_CHECK(nseg >= 1 && nseg <= 4 && nseg == f[1]);
		if (nseg < 1 || nseg > 4 || nseg != f[1]) {
			free(f);
			continue;
		}
		for (seg = 0; seg < nseg; seg++)
			len[seg] = (uint32_t)wrt_json_int(&j, wrt_json_at(&j, lens, seg), &ok);
		/* preamble: lengths in the JSON equal the preamble, total size follows the 2.6.1 formula */
		for (seg = 0; seg < nseg; seg++)
			WRT_CHECK_U64(ld32(f + 2 + 6 * seg), len[seg]);
		WRT_CHECK_U64(n, (uint64_t)32 + (len[0] ? len[0] + 4 : 0) + len[1] + len[2] + len[3] + (nseg > 1 ? 13 : 0));

		pc = wrt_json_int(&j, wrt_json_get(&j, e, "preamble_crc"), &ok);
		WRT_CHECK(ok);
		for (k = 0; k < NIMPL; k++) {
			WRT_CHECK_U64(impls[k](0, f, 28), ld32(f + 28));
			WRT_CHECK_U64(impls[k](0, f, 28), (uint32_t)pc);
		}
		off = 32;
		if (len[0]) {
			sc = wrt_json_int(&j, wrt_json_get(&j, e, "segment0_crc"), &ok);
			WRT_CHECK(ok);
			for (k = 0; k < NIMPL; k++) {
				WRT_CHECK_U64(impls[k](0xFFFFFFFFu, f + off, len[0]), ld32(f + off + len[0]));
				WRT_CHECK_U64(impls[k](0xFFFFFFFFu, f + off, len[0]), (uint32_t)sc);
			}
			off += (size_t)len[0] + 4;
		}
		if (nseg > 1) {
			const uint8_t *ep = f + n - 13; /* the epilogue is always the last 13 bytes */
			size_t slot;

			WRT_CHECK_U64(ep[0] & 0x0Fu, 0x0Eu);
			/* segments 1..3 follow segment 0 (+ its inline CRC) and end where the epilogue starts */
			WRT_CHECK(off + len[1] + len[2] + len[3] + 13 == n);
			for (slot = 0; slot < 3; slot++) {
				seg = slot + 1;
				if (seg < nseg) {
					/* an empty used segment leaves the seed: 0xFFFFFFFF */
					for (k = 0; k < NIMPL; k++)
						WRT_CHECK_U64(impls[k](0xFFFFFFFFu, f + off, len[seg]), ld32(ep + 1 + 4 * slot));
					off += len[seg];
				} else {
					WRT_CHECK_U64(ld32(ep + 1 + 4 * slot), 0);
				}
			}
		}
		nchecked++;
		free(f);
	}
	WRT_CHECK(nchecked == nf);
	wrt_json_free(&j);
}

/* ---- chaining -------------------------------------------------------------------------------- */

static void test_chaining(void)
{
	uint8_t buf[300];
	size_t cut, cut2, k;
	unsigned long bad = 0;

	fill(buf, sizeof(buf), 0x5EEDu);
	for (k = 0; k < NIMPL; k++) {
		uint32_t whole = impls[k](0xFFFFFFFFu, buf, sizeof(buf));

		for (cut = 0; cut <= sizeof(buf); cut++) {
			uint32_t a = impls[k](0xFFFFFFFFu, buf, cut);
			uint32_t ab = impls[k](a, buf + cut, sizeof(buf) - cut);

			if (ab != whole)
				bad++;
		}
		/* three pieces, including empty ones */
		for (cut = 0; cut <= sizeof(buf); cut += 7) {
			for (cut2 = cut; cut2 <= sizeof(buf); cut2 += 13) {
				uint32_t c = impls[k](0xFFFFFFFFu, buf, cut);

				c = impls[k](c, buf + cut, cut2 - cut);
				c = impls[k](c, buf + cut2, sizeof(buf) - cut2);
				if (c != whole)
					bad++;
			}
		}
		WRT_CHECK(bad == 0);
	}
	/* the msgr2 shape: the same bytes under seed 0 and seed ~0 differ, and the textbook form
	 * relates them to the raw update */
	WRT_CHECK(wri_crc32c(0, buf, sizeof(buf)) != wri_crc32c(0xFFFFFFFFu, buf, sizeof(buf)));
}

/* ---- tables ---------------------------------------------------------------------------------- */

static void test_tables(void)
{
	uint32_t t[8][256];
	unsigned r, i, b;
	size_t k;

	for (i = 0; i < 256; i++) {
		uint32_t c = i;

		for (b = 0; b < 8; b++)
			c = (c & 1u) ? (c >> 1) ^ POLY : c >> 1;
		t[0][i] = c;
	}
	for (r = 1; r < 8; r++)
		for (i = 0; i < 256; i++)
			t[r][i] = (t[r - 1][i] >> 8) ^ t[0][t[r - 1][i] & 0xFFu];

	/* the three compiled-in variants carry exactly the leading rows of the regenerated tables */
	WRT_CHECK(sizeof(wrt_tab_s1) == 1024 && sizeof(wrt_tab_s4) == 4096 && sizeof(wrt_tab_s8) == 8192);
	for (i = 0; i < 256; i++) {
		WRT_CHECK_U64(wrt_tab_s1[0][i], t[0][i]);
		for (r = 0; r < 4; r++)
			WRT_CHECK_U64(wrt_tab_s4[r][i], t[r][i]);
		for (r = 0; r < 8; r++)
			WRT_CHECK_U64(wrt_tab_s8[r][i], t[r][i]);
	}
	/* the library table footprint is the documented default unless the build overrides it */
	WRT_CHECK_U64(wri_crc32c(0, (const uint8_t *)"\x01", 1), t[0][1]);
	for (k = 0; k < 256; k++) {
		uint8_t byte = (uint8_t)k;

		WRT_CHECK_U64(wri_crc32c(0, &byte, 1), t[0][k]);
	}
	/* anchors from the spec note */
	WRT_CHECK_U64(t[0][0], 0x00000000u);
	WRT_CHECK_U64(t[0][1], 0xF26B8303u);
	WRT_CHECK_U64(t[0][2], 0xE13B70F7u);
	WRT_CHECK_U64(t[0][128], 0x82F63B78u);
	WRT_CHECK_U64(t[0][255], 0xAD7D5351u);
}

int main(void)
{
	test_known_answers();
	test_msgr2_vectors();
	test_secure_vectors();
	test_reference_sweep();
	test_exact_end_buffers();
	test_large_buffer();
	test_frame_vectors();
	test_chaining();
	test_tables();
	return wrt_finish();
}
