/* SPDX-License-Identifier: MIT */
/*
 * test_m2_sec_len - the wire arithmetic of a secure frame: wri_m2s_wire_len (core/src/msgr2/wri_m2_sec.c, design 34.4,
 * docs/spec/msgr2-secure-mode.md 2.8 and the frame size table of 5.1).
 *
 * What is checked:
 *   - the table of 5.1 row by row (bytes on the wire and GCM operations), and the rows of the design's examples;
 *   - the boundaries of the three parts: segment 0 of 0, 1, 47, 48, 49, 63, 64, 65 bytes (the 48-byte inline buffer and the 16-byte
 *     blocks), segments of 1, 15, 16, 17 bytes, the epilogue and tag that come with every frame of more than one segment;
 *   - every shape up to 130 bytes per segment against a second formula written here from the part sizes of 2.8 (division instead of
 *     masks, a different order of terms): all of 1, 2 and 3 segments exhaustively, 4 segments with every length of segment 0 and 3 and
 *     a representative set for the two in the middle (and a long random sweep of 4 segments over the whole range);
 *   - invalid shapes: 0 or more than 4 segments, an empty last segment when there is more than one, NULL lengths: 0 bytes, 0 operations;
 *     a NULL `nops` is accepted; slots past `nseg` are ignored whatever they hold; empty middle segments are fine;
 *   - 64-bit arithmetic: lengths up to 0xffffffff in all four segments, sums above 2^32 and above 2^34, the padding of 0xfffffff1 and
 *     0xffffffff (which does not wrap in 32 bits), and the invariants (never below 96, never less than the logical bytes).
 */
#include "wrt.h"

#include "wri_m2_sec.h"

/* The second formula: parts by name. */
static uint64_t blocks16(uint64_t x)
{
	return (x + 15u) / 16u; /* number of 16-byte blocks */
}

static uint64_t ref_wire(const uint32_t len[4], unsigned nseg, unsigned *ops)
{
	uint64_t total = 80u + 16u; /* part 1: preamble and 48 inline bytes, then its tag */
	unsigned o = 1, i;

	if (len[0] > 48u) {
		total += 16u * blocks16((uint64_t)len[0] - 48u) + 16u; /* the rest of segment 0 in blocks, plus the tag */
		o++;
	}
	if (nseg > 1u) {
		uint64_t body = 16u; /* the epilogue block */

		for (i = 1; i < nseg; i++)
			body += 16u * blocks16(len[i]);
		total += body + 16u; /* and the tag */
		o++;
	}
	*ops = o;
	return total;
}

static void one(uint32_t a, uint32_t b, uint32_t c, uint32_t d, unsigned nseg, uint64_t want_bytes, unsigned want_ops)
{
	uint32_t len[4];
	unsigned ops = 99;

	len[0] = a;
	len[1] = b;
	len[2] = c;
	len[3] = d;
	WRT_CHECK_U64(wri_m2s_wire_len(len, nseg, &ops), want_bytes);
	WRT_CHECK_U64(ops, want_ops);
	/* a NULL ops pointer gives the same length */
	WRT_CHECK_U64(wri_m2s_wire_len(len, nseg, NULL), want_bytes);
}

static void test_table_5_1(void)
{
	/* sec.md 5.1, in its own rows. nseg is what the row says: the number of segments up to the last non-empty one. */
	one(0, 0, 0, 0, 1, 96, 1);                      /* 0+0+0+0 */
	one(20, 0, 0, 0, 1, 96, 1);                     /* 20+0+0+0 */
	one(0, 70, 0, 0, 2, 96 + 80 + 32, 2);           /* 0+70+0+0 = 208 */
	one(20, 70, 0, 350, 4, 96 + 80 + 352 + 32, 2);  /* 20+70+0+350 = 560 */
	one(105, 0, 0, 0, 1, 96 + 80, 2);               /* 105+0+0+0 = 176 */
	one(105, 70, 0, 350, 4, 96 + 80 + 80 + 352 + 32, 3); /* 105+70+0+350 = 640 */
	/* the message-header row: 41 + front + middle + data, all non-empty */
	one(41, 100, 30, 4096, 4, 96 + 112 + 32 + 4096 + 32, 2);
	one(41, 1, 1, 1, 4, 96 + 16 + 16 + 16 + 32, 2);
	one(41, 5000, 0, 0, 2, 96 + 5008 + 32, 2);
	/* the examples of the design (frames A and B of 5.2: 96 and 144 bytes) and the file's AUTH_SIGNATURE / KEEPALIVE frames */
	one(32, 0, 0, 0, 1, 96, 1);
	one(20, 10, 0, 0, 2, 144, 2);
	one(8, 0, 0, 0, 1, 96, 1);
}

static void test_boundaries(void)
{
	static const uint32_t l0[] = {0, 1, 47, 48, 49, 63, 64, 65, 79, 80, 81, 95, 96, 97, 4095, 4096};
	static const uint32_t ls[] = {1, 15, 16, 17, 31, 32, 33};
	size_t i, k;

	/* segment 0 alone: 96 up to 48, then 96 + (pad16 - 48) + 16 */
	for (i = 0; i < sizeof(l0) / sizeof(l0[0]); i++) {
		uint32_t a = l0[i];
		uint64_t pad = ((uint64_t)a + 15u) / 16u * 16u;

		one(a, 0, 0, 0, 1, a <= 48u ? 96u : 96u + (pad - 48u) + 16u, a <= 48u ? 1u : 2u);
		/* with one more segment: + pad16 + 32, one more operation */
		for (k = 0; k < sizeof(ls) / sizeof(ls[0]); k++) {
			uint64_t p1 = ((uint64_t)ls[k] + 15u) / 16u * 16u;

			one(a, ls[k], 0, 0, 2, (a <= 48u ? 96u : 96u + (pad - 48u) + 16u) + p1 + 32u, a <= 48u ? 2u : 3u);
		}
	}
	/* the epilogue block comes with every multi-segment frame and is a whole block of its own */
	one(0, 1, 0, 0, 2, 96 + 16 + 32, 2);
	one(0, 16, 0, 0, 2, 96 + 16 + 32, 2);
	one(0, 17, 0, 0, 2, 96 + 32 + 32, 2);
	one(0, 0, 0, 17, 4, 96 + 32 + 32, 2);
	one(0, 0, 0, 16, 4, 96 + 16 + 32, 2);
	one(48, 0, 0, 1, 4, 96 + 16 + 32, 2); /* 48 still fits the first part */
	one(49, 0, 0, 1, 4, 96 + (64 - 48 + 16) + 16 + 32, 3);
}

static void test_exhaustive(void)
{
	uint32_t len[4];
	unsigned ops, rops;
	uint32_t a, b, c, d;
	uint64_t got, want, n = 0;
	static const uint32_t mid[] = {0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 95, 96, 97, 127, 128, 129};

	/* 1, 2, 3 segments: every combination 0..130 (the last of 2 or 3 non-empty) */
	for (a = 0; a <= 130u; a++) {
		len[0] = a;
		len[1] = len[2] = len[3] = 0xdeadbeefu; /* slots past nseg are never looked at */
		got = wri_m2s_wire_len(len, 1, &ops);
		want = ref_wire(len, 1, &rops);
		WRT_CHECK(got == want && ops == rops);
		n++;
		for (b = 0; b <= 130u; b++) {
			len[1] = b;
			len[2] = len[3] = 0xfeedfaceu;
			got = wri_m2s_wire_len(len, 2, &ops);
			if (b == 0u) {
				WRT_CHECK(got == 0u && ops == 0u); /* an empty last segment is not a shape */
			} else {
				want = ref_wire(len, 2, &rops);
				WRT_CHECK(got == want && ops == rops && got >= 96u);
			}
			n++;
			for (c = 0; c <= 130u; c++) {
				len[2] = c;
				len[3] = 7u;
				got = wri_m2s_wire_len(len, 3, &ops);
				if (c == 0u) {
					WRT_CHECK(got == 0u && ops == 0u);
				} else {
					want = ref_wire(len, 3, &rops);
					WRT_CHECK(got == want && ops == rops);
				}
				n++;
			}
		}
	}
	/* 4 segments: every length of segment 0 and of the data segment, a representative set for the two between */
	for (a = 0; a <= 130u; a++)
		for (b = 0; b < sizeof(mid) / sizeof(mid[0]); b++)
			for (c = 0; c < sizeof(mid) / sizeof(mid[0]); c++)
				for (d = 0; d <= 130u; d++) {
					len[0] = a;
					len[1] = mid[b];
					len[2] = mid[c];
					len[3] = d;
					got = wri_m2s_wire_len(len, 4, &ops);
					if (d == 0u) {
						WRT_CHECK(got == 0u && ops == 0u);
					} else {
						want = ref_wire(len, 4, &rops);
						WRT_CHECK(got == want && ops == rops);
					}
					n++;
				}
	WRT_CHECK(n > 2000000u);
}

static void test_random_wide(void)
{
	uint64_t x = 0x9e3779b97f4a7c15ull;
	int it;

	for (it = 0; it < 200000; it++) {
		uint32_t len[4];
		unsigned nseg, ops, rops, i;
		uint64_t got, want;

		x ^= x >> 12;
		x ^= x << 25;
		x ^= x >> 27;
		nseg = 1u + (unsigned)((x >> 7) & 3u);
		for (i = 0; i < 4u; i++) {
			x ^= x >> 12;
			x ^= x << 25;
			x ^= x >> 27;
			switch ((x >> 5) & 3u) {
			case 0:
				len[i] = (uint32_t)(x >> 32) & 0xffffu;
				break;
			case 1:
				len[i] = (uint32_t)(x >> 32);
				break;
			case 2:
				len[i] = (uint32_t)(x >> 40) & 0xffu;
				break;
			default:
				len[i] = (uint32_t)(0xffffffffu - ((x >> 33) & 0x1fu));
				break;
			}
		}
		got = wri_m2s_wire_len(len, nseg, &ops);
		if (nseg > 1u && len[nseg - 1u] == 0u) {
			WRT_CHECK(got == 0u && ops == 0u);
			continue;
		}
		want = ref_wire(len, nseg, &rops);
		WRT_CHECK(got == want && ops == rops);
		/* what goes over the wire is never less than what the segments hold, and a multiple of 16 once the first 96 are taken off */
		{
			uint64_t logical = 0;

			for (i = 0; i < nseg; i++)
				logical += len[i];
			WRT_CHECK(got >= 96u && got >= logical);
		}
	}
}

static void test_invalid(void)
{
	uint32_t len[4] = {10, 20, 30, 40};
	unsigned ops = 99;
	unsigned n;

	/* number of segments */
	WRT_CHECK_U64(wri_m2s_wire_len(len, 0, &ops), 0);
	WRT_CHECK_U64(ops, 0);
	ops = 99;
	WRT_CHECK_U64(wri_m2s_wire_len(len, 5, &ops), 0);
	WRT_CHECK_U64(ops, 0);
	ops = 99;
	WRT_CHECK_U64(wri_m2s_wire_len(len, 0xffffffffu, &ops), 0);
	WRT_CHECK_U64(ops, 0);
	WRT_CHECK_U64(wri_m2s_wire_len(len, 0, NULL), 0);
	WRT_CHECK_U64(wri_m2s_wire_len(len, 5, NULL), 0);
	/* NULL lengths */
	ops = 99;
	WRT_CHECK_U64(wri_m2s_wire_len(NULL, 1, &ops), 0);
	WRT_CHECK_U64(ops, 0);
	WRT_CHECK_U64(wri_m2s_wire_len(NULL, 3, NULL), 0);
	/* an empty last segment, for each nseg 2..4 (an empty last of nseg 1 is the empty frame: valid) */
	for (n = 2; n <= 4u; n++) {
		uint32_t l[4] = {5, 6, 7, 8};

		l[n - 1u] = 0;
		ops = 99;
		WRT_CHECK_U64(wri_m2s_wire_len(l, n, &ops), 0);
		WRT_CHECK_U64(ops, 0);
	}
	len[0] = 0;
	WRT_CHECK_U64(wri_m2s_wire_len(len, 1, &ops), 96);
	WRT_CHECK_U64(ops, 1);
	/* empty middle segments are fine, and cost nothing but the epilogue block */
	{
		uint32_t l[4] = {0, 0, 0, 1};

		WRT_CHECK_U64(wri_m2s_wire_len(l, 4, &ops), 96 + 16 + 32);
		WRT_CHECK_U64(ops, 2);
	}
	/* a segment length of 0 in the last used slot of a shorter frame does not matter for slots past nseg */
	{
		uint32_t l[4] = {1, 2, 0, 0};

		WRT_CHECK_U64(wri_m2s_wire_len(l, 2, &ops), 96 + 16 + 32);
	}
}

static void test_64bit(void)
{
	static const uint64_t pad_ff = (uint64_t)1 << 32; /* pad16(0xffffffff) = 2^32: does not fit in 32 bits */
	uint32_t len[4];
	unsigned ops;
	uint64_t want;

	/* one segment of 0xffffffff in each slot */
	len[0] = len[1] = len[2] = len[3] = 0xffffffffu;
	want = 96u + (pad_ff - 48u + 16u) + 3u * pad_ff + 32u;
	WRT_CHECK_U64(wri_m2s_wire_len(len, 4, &ops), want);
	WRT_CHECK_U64(want, 0x400000060ull);
	WRT_CHECK_U64(ops, 3);
	WRT_CHECK(want > ((uint64_t)1 << 34));
	/* the same without the first part's extra */
	len[0] = 48;
	WRT_CHECK_U64(wri_m2s_wire_len(len, 4, &ops), 96u + 3u * pad_ff + 32u);
	WRT_CHECK_U64(ops, 2);
	/* single segment: segment 0 alone */
	len[0] = 0xffffffffu;
	WRT_CHECK_U64(wri_m2s_wire_len(len, 1, &ops), 96u + (pad_ff - 48u) + 16u);
	WRT_CHECK_U64(ops, 2);
	/* the edge of padding: 0xfffffff0 is a whole number of blocks, 0xfffffff1 rounds up to 2^32 */
	len[0] = 0;
	len[1] = 0xfffffff0u;
	WRT_CHECK_U64(wri_m2s_wire_len(len, 2, &ops), 96u + 0xfffffff0ull + 32u);
	len[1] = 0xfffffff1u;
	WRT_CHECK_U64(wri_m2s_wire_len(len, 2, &ops), 96u + pad_ff + 32u);
	len[0] = 0xfffffff1u;
	len[1] = 0;
	WRT_CHECK_U64(wri_m2s_wire_len(len, 1, &ops), 96u + (pad_ff - 48u) + 16u);
	len[0] = 0xffffffffu;
	len[1] = 0xffffffffu;
	WRT_CHECK_U64(wri_m2s_wire_len(len, 2, &ops), 96u + (pad_ff - 48u) + 16u + pad_ff + 32u);
	WRT_CHECK_U64(ops, 3);
}

int main(void)
{
	test_table_5_1();
	test_boundaries();
	test_exhaustive();
	test_random_wide();
	test_invalid();
	test_64bit();
	return wrt_finish();
}
