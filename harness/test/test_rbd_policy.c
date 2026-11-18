/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_policy - the refusal rules of the open (core/src/rbd/wri_rbd_policy.c; design 24.3, docs/spec/rbd-format2.md 3.3 and 4.2).
 *
 * The table: all 12 feature bits (and the bits above them) alone and in every combination, reader and writer, with the exact status and
 * the offending mask in a0; then each of the other rules on its own (order 0 to 255, striping layouts at every order, parent evidence,
 * data pool, flags); then the order of the rules (every subset of the six rules failing at once: the first of the order wins, for both
 * profiles); the errinfo (first failure stays, module, `what`, untouched on success, NULL is fine); the images of the vectors by their
 * feature words; the two feature masks.
 */
#include "wrt.h"

#include "wri_rbd_cls.h"

/* The expected masks, written out here and not taken from the code under test. */
#define READER_MASK 0x1ffull
#define WRITER_MASK 0xa1ull
#define WRITER_COND 0x2ull /* striping: judged by its layout, for both profiles */

static wri_rbd_hdr base(void)
{
	wri_rbd_hdr h;

	memset(&h, 0, sizeof(h));
	h.order = 22;
	h.size = 4ull << 30;
	h.features = 1;
	h.data_pool_id = -1;
	memcpy(h.prefix, "rbd_data.37841afbd1d7", 21);
	return h;
}

/* A header whose context fields agree with its feature bits, so only the feature rule can fire. */
static wri_rbd_hdr with_features(uint64_t f)
{
	wri_rbd_hdr h = base();

	h.features = f;
	if ((f & 0x2) != 0) {
		h.stripe_unit = 1ull << 22;
		h.stripe_count = 1;
	}
	if ((f & 0x80) != 0)
		h.data_pool_id = 5;
	return h;
}

static wr_status judge(const wri_rbd_hdr *h, int w, wr_errinfo *why)
{
	memset(why, 0, sizeof(*why));
	return wri_rbd_check_profile(h, w, why);
}

/* ---- the feature table ---------------------------------------------------------------------- */

static void test_each_bit(void)
{
	int b, w;

	for (b = 0; b < 64; b++) {
		uint64_t bit = 1ull << b;

		for (w = 0; w < 2; w++) {
			wri_rbd_hdr h = with_features(bit);
			wr_errinfo why;
			uint64_t ok = w ? (WRITER_MASK | WRITER_COND) : READER_MASK;
			wr_status st = judge(&h, w, &why);

			if ((bit & ok) != 0) {
				WRT_CHECK_STATUS(WR_OK, st);
				WRT_CHECK(why.status == WR_OK);
			} else {
				WRT_CHECK_STATUS(WR_E_RBD_FEATURES, st);
				WRT_CHECK_STATUS(WR_E_RBD_FEATURES, why.status);
				WRT_CHECK_U64(why.a0, bit);
				WRT_CHECK_U64(why.a1, bit);
				WRT_CHECK_U64(why.a2, w);
				WRT_CHECK(why.module == WR_MOD_RBD);
				WRT_CHECK(why.what != NULL);
			}
		}
	}
	/* the twelve named bits, spelled out: reader 0..8 yes, 9..11 no; writer layering, striping (default form), deep-flatten, data-pool */
	{
		static const int reader_ok[12] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0};
		static const int writer_ok[12] = {1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0};

		for (b = 0; b < 12; b++) {
			wri_rbd_hdr h = with_features(1ull << b);
			wr_errinfo why;

			WRT_CHECK_STATUS(reader_ok[b] ? WR_OK : WR_E_RBD_FEATURES, judge(&h, 0, &why));
			WRT_CHECK_STATUS(writer_ok[b] ? WR_OK : WR_E_RBD_FEATURES, judge(&h, 1, &why));
		}
	}
}

static void test_all_combinations(void)
{
	uint64_t f;

	for (f = 0; f < 0x1000; f++) {
		int w;

		for (w = 0; w < 2; w++) {
			wri_rbd_hdr h = with_features(f);
			wr_errinfo why;
			uint64_t bad = f & ~(w ? (WRITER_MASK | WRITER_COND) : READER_MASK);
			wr_status st = judge(&h, w, &why);

			WRT_CHECK_STATUS(bad ? WR_E_RBD_FEATURES : WR_OK, st);
			if (bad != 0) {
				WRT_CHECK_U64(why.a0, bad);
				WRT_CHECK_U64(why.a1, f);
			}
		}
	}
	/* bits above 11 are always among the offenders, with the valid bits kept out of a0 */
	{
		static const uint64_t hi[] = {0x1000, 0x2000, 0x80000000ull, 0x100000000ull, 0x8000000000000000ull, 0xfffffffffffff000ull};
		size_t i;

		for (i = 0; i < sizeof(hi) / sizeof(hi[0]); i++) {
			wri_rbd_hdr h = with_features(0x21 | hi[i]);
			wr_errinfo why;

			WRT_CHECK_STATUS(WR_E_RBD_FEATURES, judge(&h, 0, &why));
			WRT_CHECK_U64(why.a0, hi[i]);
			WRT_CHECK_STATUS(WR_E_RBD_FEATURES, judge(&h, 1, &why));
			WRT_CHECK_U64(why.a0, hi[i]);
		}
		{
			wri_rbd_hdr h = with_features(0x3d | 0x40 | 0x400 | 0x1000);
			wr_errinfo why;

			WRT_CHECK_STATUS(WR_E_RBD_FEATURES, judge(&h, 1, &why));
			WRT_CHECK_U64(why.a0, 0x145c); /* exclusive-lock, object-map, fast-diff, journaling, non-primary, bit 12 */
			WRT_CHECK_STATUS(WR_E_RBD_FEATURES, judge(&h, 0, &why));
			WRT_CHECK_U64(why.a0, 0x400 | 0x1000);
		}
	}
}

/* ---- the other rules, one by one ----------------------------------------------------------------- */

static void test_order(void)
{
	unsigned o;
	int w;

	for (w = 0; w < 2; w++) {
		for (o = 0; o < 256; o++) {
			wri_rbd_hdr h = base();
			wr_errinfo why;
			int ok = o >= 12 && o <= 25;

			h.order = (uint8_t)o;
			WRT_CHECK_STATUS(ok ? WR_OK : WR_E_RBD_ORDER, judge(&h, w, &why));
			if (!ok) {
				WRT_CHECK_U64(why.a0, o);
				WRT_CHECK_U64(why.a1, 12);
				WRT_CHECK_U64(why.a2, 25);
			}
		}
	}
}

static void test_striping(void)
{
	unsigned o;
	int w;

	for (w = 0; w < 2; w++) {
		for (o = 12; o <= 25; o++) {
			uint64_t obj = 1ull << o;
			wri_rbd_hdr h = base();
			wr_errinfo why;

			h.order = (uint8_t)o;
			h.features = 0x3;
			/* the default form: accepted */
			h.stripe_unit = obj;
			h.stripe_count = 1;
			WRT_CHECK_STATUS(WR_OK, judge(&h, w, &why));
			/* a zero unit or count is what librbd also reads as default */
			h.stripe_unit = 0;
			h.stripe_count = 0;
			WRT_CHECK_STATUS(WR_OK, judge(&h, w, &why));
			h.stripe_unit = 0;
			h.stripe_count = 4;
			WRT_CHECK_STATUS(WR_OK, judge(&h, w, &why));
			h.stripe_unit = obj;
			h.stripe_count = 0;
			WRT_CHECK_STATUS(WR_OK, judge(&h, w, &why));
			/* everything else: refused, with the numbers */
			{
				static const uint64_t counts[] = {1, 2, 4, 16, 0xffffffffffffffffull};
				uint64_t units[6];
				size_t u, c;

				units[0] = obj;
				units[1] = obj / 2;
				units[2] = obj + 1;
				units[3] = obj * 2;
				units[4] = 512;
				units[5] = 0xffffffffffffffffull;
				for (u = 0; u < 6; u++)
					for (c = 0; c < 5; c++) {
						int def = units[u] == obj && counts[c] == 1;

						h.stripe_unit = units[u];
						h.stripe_count = counts[c];
						WRT_CHECK_STATUS(def ? WR_OK : WR_E_RBD_STRIPING, judge(&h, w, &why));
						if (!def) {
							WRT_CHECK_U64(why.a0, units[u]);
							WRT_CHECK_U64(why.a1, counts[c]);
							WRT_CHECK_U64(why.a2, obj);
						}
					}
			}
			/* the bit clear: the layout words are not read and not judged */
			h.features = 0x1;
			h.stripe_unit = 4096;
			h.stripe_count = 8;
			WRT_CHECK_STATUS(WR_OK, judge(&h, w, &why));
		}
	}
}

static void test_parent(void)
{
	int w;

	for (w = 0; w < 2; w++) {
		wri_rbd_hdr h = base();
		wr_errinfo why;

		/* parent_get found one */
		h.has_parent = 1;
		WRT_CHECK_STATUS(WR_E_RBD_PARENT, judge(&h, w, &why));
		WRT_CHECK_U64(why.a0, 1);
		/* the overlap alone (parent_get said no, parent_overlap_get answered): refused too, with its value */
		h.has_parent = 0;
		h.has_overlap = 1;
		h.overlap = 16777216;
		WRT_CHECK_STATUS(WR_E_RBD_PARENT, judge(&h, w, &why));
		WRT_CHECK_U64(why.a0, 2);
		WRT_CHECK_U64(why.a1, 16777216);
		h.overlap = 0; /* present with 0: a parent that no longer overlaps is still a clone */
		WRT_CHECK_STATUS(WR_E_RBD_PARENT, judge(&h, w, &why));
		/* both */
		h.has_parent = 1;
		WRT_CHECK_STATUS(WR_E_RBD_PARENT, judge(&h, w, &why));
		WRT_CHECK_U64(why.a0, 3);
		/* neither: fine; an overlap value without the present marker is not evidence */
		h.has_parent = 0;
		h.has_overlap = 0;
		h.overlap = 123;
		WRT_CHECK_STATUS(WR_OK, judge(&h, w, &why));
	}
	/* op_features: clone-child, only meaningful (and only read) with the operations bit; the writer never gets this far */
	{
		wri_rbd_hdr h = base();
		wr_errinfo why;
		uint64_t opf;

		h.features = 0x1 | 0x100;
		for (opf = 0; opf < 16; opf++) {
			h.op_features = opf;
			WRT_CHECK_STATUS((opf & 2) ? WR_E_RBD_PARENT : WR_OK, judge(&h, 0, &why));
			if (opf & 2) {
				WRT_CHECK_U64(why.a0, 4);
				WRT_CHECK_U64(why.a2, opf);
			}
			WRT_CHECK_STATUS(WR_E_RBD_FEATURES, judge(&h, 1, &why)); /* the operations bit is refused for a writer first */
			WRT_CHECK_U64(why.a0, 0x100);
		}
		h.features = 0x1; /* the bit clear: op_features was not read and is not looked at */
		h.op_features = 2;
		WRT_CHECK_STATUS(WR_OK, judge(&h, 0, &why));
		WRT_CHECK_STATUS(WR_OK, judge(&h, 1, &why));
	}
}

static void test_data_pool(void)
{
	static const int64_t ids[] = {-1, -2, INT64_MIN, 0, 1, 5, INT64_MAX};
	size_t i;
	int w;

	for (w = 0; w < 2; w++)
		for (i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
			wri_rbd_hdr h = base();
			wr_errinfo why;

			/* the bit set: the id must be a pool id */
			h.features = 0x81;
			h.data_pool_id = ids[i];
			WRT_CHECK_STATUS(ids[i] >= 0 ? WR_OK : WR_E_RBD_DATA_POOL, judge(&h, w, &why));
			if (ids[i] < 0)
				WRT_CHECK_U64(why.a0, (uint64_t)ids[i]);
			/* the bit clear: the id is not judged here (the open does not use it) */
			h.features = 0x1;
			WRT_CHECK_STATUS(WR_OK, judge(&h, w, &why));
		}
}

static void test_flags(void)
{
	static const uint64_t fl[] = {0, 1, 2, 3, 4, 0x8000000000000000ull, 0xffffffffffffffffull};
	size_t i;

	for (i = 0; i < sizeof(fl) / sizeof(fl[0]); i++) {
		wri_rbd_hdr h = base();
		wr_errinfo why;

		h.flags = fl[i];
		WRT_CHECK_STATUS(WR_OK, judge(&h, 0, &why)); /* a reader ignores flags */
		WRT_CHECK_STATUS(fl[i] != 0 ? WR_E_RBD_FLAGS : WR_OK, judge(&h, 1, &why));
		if (fl[i] != 0)
			WRT_CHECK_U64(why.a0, fl[i]);
	}
}

/* ---- the order of the rules --------------------------------------------------------------------- */

enum { R_FEAT, R_ORDER, R_STRIPE, R_PARENT, R_POOL, R_FLAGS, R_N };

static void test_rule_order(void)
{
	static const wr_status status_of[R_N] = {WR_E_RBD_FEATURES, WR_E_RBD_ORDER, WR_E_RBD_STRIPING, WR_E_RBD_PARENT, WR_E_RBD_DATA_POOL,
						 WR_E_RBD_FLAGS};
	unsigned set;
	int w;

	for (w = 0; w < 2; w++)
		for (set = 0; set < (1u << R_N); set++) {
			wri_rbd_hdr h = base();
			wr_errinfo why;
			wr_status want = WR_OK;
			int r;

			if (set & (1u << R_FEAT))
				h.features |= w ? 0x4 : 0x200;
			if (set & (1u << R_ORDER))
				h.order = 11;
			if (set & (1u << R_STRIPE)) {
				h.features |= 0x2;
				h.stripe_unit = 4096;
				h.stripe_count = 4;
			}
			if (set & (1u << R_PARENT))
				h.has_parent = 1;
			if (set & (1u << R_POOL)) {
				h.features |= 0x80;
				h.data_pool_id = -1;
			}
			if (set & (1u << R_FLAGS))
				h.flags = 2;
			/* the first rule of the order that is both set and applicable to the profile; a reader does not judge flags */
			for (r = 0; r < R_N; r++)
				if ((set & (1u << r)) != 0 && !(r == R_FLAGS && !w)) {
					want = status_of[r];
					break;
				}
			WRT_CHECK_STATUS(want, judge(&h, w, &why));
			WRT_CHECK_STATUS(want, why.status);
		}
}

/* ---- errinfo ---------------------------------------------------------------------------------------- */

static void test_errinfo(void)
{
	wri_rbd_hdr h = with_features(0x3d);
	wr_errinfo why;

	/* on success the errinfo is untouched */
	memset(&why, 0, sizeof(why));
	h = with_features(0x21);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_check_profile(&h, 1, &why));
	WRT_CHECK(why.status == WR_OK && why.what == NULL && why.a0 == 0 && why.module == 0);
	/* a refusal fills it */
	h = with_features(0x3d);
	WRT_CHECK_STATUS(WR_E_RBD_FEATURES, wri_rbd_check_profile(&h, 1, &why));
	WRT_CHECK(why.status == WR_E_RBD_FEATURES && why.module == WR_MOD_RBD && why.what != NULL && why.line != 0);
	WRT_CHECK_U64(why.a0, 0x1c);
	WRT_CHECK_U64(why.a1, 0x3d);
	WRT_CHECK_U64(why.a2, 1);
	/* first failure wins: a second judgement returns its own status and leaves the record alone */
	{
		wri_rbd_hdr bad = base();

		bad.order = 3;
		WRT_CHECK_STATUS(WR_E_RBD_ORDER, wri_rbd_check_profile(&bad, 1, &why));
		WRT_CHECK(why.status == WR_E_RBD_FEATURES && why.a0 == 0x1c);
	}
	/* NULL why is fine */
	WRT_CHECK_STATUS(WR_E_RBD_FEATURES, wri_rbd_check_profile(&h, 1, NULL));
	h = with_features(0x3d);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_check_profile(&h, 0, NULL));
	/* NULL header */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_check_profile(NULL, 0, &why));
	/* a writer flag value other than 0 / 1 is a writer */
	WRT_CHECK_STATUS(WR_E_RBD_FEATURES, wri_rbd_check_profile(&h, 7, NULL));
	/* the masks */
	WRT_CHECK_U64(wri_rbd_features_ok(0), 0x1ff);
	WRT_CHECK_U64(wri_rbd_features_ok(1), 0xa1);
	WRT_CHECK_U64(wri_rbd_features_ok(5), 0xa1);
}

/* ---- the images of the vectors, by feature word ----------------------------------------------- */

static void test_lab_images(void)
{
	static const struct {
		const char *what;
		uint64_t features;
		int64_t pool;
		int clone, striped, flags;
		wr_status reader, writer;
		uint64_t writer_a0;
	} t[] = {
		{"layering only (img-v1)", 0x01, -1, 0, 0, 0, WR_OK, WR_OK, 0},
		{"layering + deep-flatten (an image made shared)", 0x21, -1, 0, 0, 0, WR_OK, WR_OK, 0},
		{"default features (img-default)", 0x3d, -1, 0, 0, 0, WR_OK, WR_E_RBD_FEATURES, 0x1c},
		{"layering + exclusive-lock", 0x05, -1, 0, 0, 0, WR_OK, WR_E_RBD_FEATURES, 0x04},
		{"journaling", 0x45, -1, 0, 0, 0, WR_OK, WR_E_RBD_FEATURES, 0x44},
		{"striped 65536 x 4", 0x03, -1, 0, 1, 0, WR_E_RBD_STRIPING, WR_E_RBD_STRIPING, 0},
		{"a snapshotted layering image", 0x01, -1, 0, 0, 0, WR_OK, WR_OK, 0},
		{"a clone", 0x01, -1, 1, 0, 0, WR_E_RBD_PARENT, WR_E_RBD_PARENT, 0},
		{"data pool 5", 0x81, 5, 0, 0, 0, WR_OK, WR_OK, 0},
		{"migration target", 0x201, -1, 0, 0, 0, WR_E_RBD_FEATURES, WR_E_RBD_FEATURES, 0x200},
		{"object map marked invalid", 0x3d, -1, 0, 0, 1, WR_OK, WR_E_RBD_FEATURES, 0x1c},
		{"layering with object map invalid flag", 0x21, -1, 0, 0, 1, WR_OK, WR_E_RBD_FLAGS, 0},
	};
	size_t i;

	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		wri_rbd_hdr h = with_features(t[i].features);
		wr_errinfo why;
		wr_status st;

		h.data_pool_id = t[i].pool;
		h.has_parent = (uint8_t)t[i].clone;
		h.has_overlap = (uint8_t)t[i].clone;
		h.overlap = t[i].clone ? 16777216 : 0;
		h.flags = (uint64_t)t[i].flags;
		if (t[i].striped) {
			h.stripe_unit = 65536;
			h.stripe_count = 4;
		}
		st = judge(&h, 0, &why);
		if (st != t[i].reader)
			fprintf(stderr, "reader: %s\n", t[i].what);
		WRT_CHECK_STATUS(t[i].reader, st);
		st = judge(&h, 1, &why);
		if (st != t[i].writer)
			fprintf(stderr, "writer: %s\n", t[i].what);
		WRT_CHECK_STATUS(t[i].writer, st);
		if (t[i].writer_a0 != 0 && st == WR_E_RBD_FEATURES)
			WRT_CHECK_U64(why.a0, t[i].writer_a0);
	}
}

int main(void)
{
	test_each_bit();
	test_all_combinations();
	test_order();
	test_striping();
	test_parent();
	test_data_pool();
	test_flags();
	test_rule_order();
	test_errinfo();
	test_lab_images();
	return wrt_finish();
}
