/* SPDX-License-Identifier: MIT */
/*
 * test_m2_sec_nonce - the nonce stream of one direction of a secure connection (core/src/msgr2/wri_m2_sec.c, design 34.5,
 * docs/spec/msgr2-secure-mode.md 2.6).
 *
 * What is checked, against a model in this file that keeps the counter as a plain uint64 (so it shares no code with the core):
 *   - the first take returns the seed unchanged; every later one is the seed's fixed field (bytes 0..3, never touched) followed by the
 *     little-endian counter (bytes 4..11) stepped once per take, including the carries inside the counter;
 *   - the counter wraps modulo 2^64 without carrying into the fixed field (fixed = 0xffffffff, counter 2^64 - 3 .. 2);
 *   - after 2^64 takes the stream is back at its seed and refuses (white box: the state is set one step before the seed; 2^64 takes
 *     cannot be run), with the state and the output untouched; a stream that has not started may sit at its seed;
 *   - the operation limit: exactly `limit` takes succeed, then a refusal that changes nothing, forever; limit 0 means none (also at an
 *     operation count far above the default limit); the refusal wins over a pending wrap and vice versa;
 *   - two directions are independent (interleaved, different seeds, one refused while the other goes on);
 *   - a connection secret whose seed counter sits near 2^64 - 3 (read through wri_m2s_init, both views) gives the wrapping streams;
 *   - random seeds (counters from small to near the wrap) against the model for thousands of takes;
 *   - NULL arguments, an all-zero seed, a NULL seed.
 * The random source is a fixed-seed xorshift, so a failure reproduces.
 */
#include "wrt.h"

#include "wri_m2_sec.h"

/* ---- model ------------------------------------------------------------------------------------- */

static uint64_t rng_state = 0x9e3779b97f4a7c15ull;

static uint32_t rnd(void)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (uint32_t)((rng_state * 0x2545f4914f6cdd1dull) >> 32);
}

static uint64_t rnd64(void)
{
	return ((uint64_t)rnd() << 32) | rnd();
}

static uint64_t le64_get(const uint8_t *p)
{
	uint64_t v = 0;
	int i;

	for (i = 7; i >= 0; i--)
		v = (v << 8) | p[i];
	return v;
}

static void le64_put(uint8_t *p, uint64_t v)
{
	int i;

	for (i = 0; i < 8; i++)
		p[i] = (uint8_t)(v >> (8 * i));
}

/* The model of one stream: fixed field + counter, the nonce of the k-th take (k from 0) is fixed || LE64(c0 + k). */
typedef struct model {
	uint8_t fixed[4];
	uint64_t c0;
} model;

static void model_from_seed(model *m, const uint8_t seed[12])
{
	memcpy(m->fixed, seed, 4);
	m->c0 = le64_get(seed + 4);
}

static void model_nonce(const model *m, uint64_t k, uint8_t out[12])
{
	memcpy(out, m->fixed, 4);
	le64_put(out + 4, m->c0 + k); /* unsigned wrap is the point */
}

static void make_seed(uint8_t seed[12], uint32_t fixed, uint64_t ctr)
{
	seed[0] = (uint8_t)fixed;
	seed[1] = (uint8_t)(fixed >> 8);
	seed[2] = (uint8_t)(fixed >> 16);
	seed[3] = (uint8_t)(fixed >> 24);
	le64_put(seed + 4, ctr);
}

/* Take `count` nonces and compare each with the model; returns 0 when all agree and succeeded. */
static int run_against_model(wri_m2s_nonce *n, const model *m, uint64_t first_k, uint64_t count, uint64_t limit)
{
	uint64_t k;
	uint8_t got[12], want[12];

	for (k = 0; k < count; k++) {
		if (wri_m2s_nonce_take(n, limit, got) != WR_OK)
			return -1;
		model_nonce(m, first_k + k, want);
		if (memcmp(got, want, 12) != 0)
			return -2;
	}
	return 0;
}

/* ---- the table --------------------------------------------------------------------------------- */

static void test_first_is_seed_and_steps(void)
{
	static const uint8_t seed[12] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	wri_m2s_nonce n;
	uint8_t out[12], want[12];
	size_t i;

	wri_m2s_nonce_init(&n, seed);
	WRT_CHECK(memcmp(n.seed, seed, 12) == 0 && memcmp(n.cur, seed, 12) == 0);
	WRT_CHECK(n.started == 0u && n.ops == 0u);
	/* the first operation uses the seed itself */
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	WRT_CHECK_MEM(out, seed, 12);
	WRT_CHECK(n.started == 1u && n.ops == 1u);
	/* then the counter in bytes 4..11 steps by one, byte 0..3 stay */
	memcpy(want, seed, 12);
	want[4] = 1;
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	WRT_CHECK_MEM(out, want, 12);
	want[4] = 2;
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	WRT_CHECK_MEM(out, want, 12);
	WRT_CHECK(n.ops == 3u);
	WRT_CHECK(memcmp(n.seed, seed, 12) == 0); /* the seed itself never changes */
	/* the spec's worked example, 2.6 / 5.2: seed 1c1d1e1f 20 21 22 23 24 25 26 27, ops 1, 2, 3 -> counter byte 4: 20, 21, 22 */
	{
		static const uint8_t s2[12] = {0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27};
		wri_m2s_nonce m;

		wri_m2s_nonce_init(&m, s2);
		for (i = 0; i < 3; i++) {
			memcpy(want, s2, 12);
			want[4] = (uint8_t)(0x20u + i);
			WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&m, 0, out));
			/* only byte 4 moves (the low byte of the counter, no carry in these three steps) */
			WRT_CHECK(out[0] == 0x1c && out[1] == 0x1d && out[2] == 0x1e && out[3] == 0x1f);
			WRT_CHECK(out[4] == (uint8_t)(0x20u + i) && memcmp(out + 5, s2 + 5, 7) == 0);
		}
	}
}

static void test_carries_and_wrap(void)
{
	uint8_t seed[12], out[12];
	wri_m2s_nonce n;
	model m;
	uint64_t starts[] = {0, 1, 0xfe, 0xff, 0x100, 0xffff, 0xffffff, 0xffffffffull, 0xffffffffffull, 0xffffffffffffull,
			     0xffffffffffffffull, 0x7fffffffffffffffull, 0x8000000000000000ull, 0xfffffffffffffff0ull,
			     0xfffffffffffffffdull, 0xfffffffffffffffeull, 0xffffffffffffffffull};
	size_t i;

	for (i = 0; i < sizeof(starts) / sizeof(starts[0]); i++) {
		make_seed(seed, 0xffffffffu, starts[i]); /* fixed all ones: a carry into it would show at once */
		wri_m2s_nonce_init(&n, seed);
		model_from_seed(&m, seed);
		WRT_CHECK(run_against_model(&n, &m, 0, 600, 0) == 0);
		WRT_CHECK(n.ops == 600u);
		WRT_CHECK(memcmp(n.cur, seed, 4) == 0); /* the fixed field is still the seed's */
	}
	/* the exact wrap, the table of the task: counter 2^64 - 3 */
	make_seed(seed, 0x11223344u, 0xfffffffffffffffdull);
	wri_m2s_nonce_init(&n, seed);
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	WRT_CHECK(le64_get(out + 4) == 0xfffffffffffffffdull);
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	WRT_CHECK(le64_get(out + 4) == 0xfffffffffffffffeull);
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	WRT_CHECK(le64_get(out + 4) == 0xffffffffffffffffull);
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	WRT_CHECK(le64_get(out + 4) == 0u); /* wrapped to zero ... */
	WRT_CHECK(out[0] == 0x44 && out[1] == 0x33 && out[2] == 0x22 && out[3] == 0x11); /* ... without a carry into the fixed field */
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	WRT_CHECK(le64_get(out + 4) == 1u);
	WRT_CHECK(out[0] == 0x44 && out[3] == 0x11);
}

static void test_refusal_at_seed(void)
{
	uint8_t seed[12], out[12], keep[12], before[sizeof(wri_m2s_nonce)];
	wri_m2s_nonce n;
	uint64_t c0s[] = {0, 1, 0x1234567812345678ull, 0xffffffffffffffffull};
	size_t i;
	int k;

	for (i = 0; i < sizeof(c0s) / sizeof(c0s[0]); i++) {
		make_seed(seed, 0xa5a5a5a5u, c0s[i]);
		/* White box: the stream that has taken 2^64 - 1 nonces is one step before the seed (cur = seed - 1) ... */
		wri_m2s_nonce_init(&n, seed);
		le64_put(n.cur + 4, c0s[i] - 1u);
		n.started = 1u;
		n.ops = 0xffffffffffffffffull;
		WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out)); /* the 2^64-th operation */
		WRT_CHECK(le64_get(out + 4) == c0s[i] - 1u);
		WRT_CHECK(memcmp(n.cur, seed, 12) == 0 && n.started == 1u); /* ... and now back at the seed */
		/* ... the next take is refused with nothing changed, and every one after it */
		memcpy(before, &n, sizeof(n));
		memset(out, 0xee, sizeof(out));
		memset(keep, 0xee, sizeof(keep));
		for (k = 0; k < 3; k++) {
			WRT_CHECK_STATUS(WR_E_M2_NONCE, wri_m2s_nonce_take(&n, 0, out));
			WRT_CHECK_MEM(out, keep, 12);
			WRT_CHECK(memcmp(before, &n, sizeof(n)) == 0);
		}
		/* a limit does not unblock it */
		WRT_CHECK_STATUS(WR_E_M2_NONCE, wri_m2s_nonce_take(&n, 0xffffffffffffffffull, out));
		WRT_CHECK(memcmp(before, &n, sizeof(n)) == 0);
	}
	/* A stream that has not started may sit at its seed: that is the first use. */
	make_seed(seed, 7u, 5u);
	wri_m2s_nonce_init(&n, seed);
	WRT_CHECK(memcmp(n.cur, n.seed, 12) == 0 && n.started == 0u);
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	WRT_CHECK_MEM(out, seed, 12);
	/* ... and the refusal looks at the whole nonce: a different fixed field is no match */
	{
		uint8_t s1[12], s2[12];

		make_seed(s1, 1u, 9u);
		wri_m2s_nonce_init(&n, s1);
		memcpy(s2, s1, 12);
		s2[0] ^= 0x80u;
		memcpy(n.cur, s2, 12); /* cannot happen through the API; the check must still compare all 12 bytes */
		n.started = 1u;
		WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
		memcpy(n.cur, s1, 12);
		n.cur[11] ^= 1u;
		WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
		memcpy(n.cur, s1, 12);
		WRT_CHECK_STATUS(WR_E_M2_NONCE, wri_m2s_nonce_take(&n, 0, out));
	}
}

static void test_limit(void)
{
	uint8_t seed[12], out[12], keep[12], before[sizeof(wri_m2s_nonce)];
	wri_m2s_nonce n;
	model m;
	uint64_t limits[] = {1, 2, 3, 5, 64, 1000};
	size_t i;
	uint64_t k;

	make_seed(seed, 0x01020304u, 0x1000u);
	model_from_seed(&m, seed);
	for (i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
		wri_m2s_nonce_init(&n, seed);
		/* exactly `limit` takes succeed and are the right nonces */
		WRT_CHECK(run_against_model(&n, &m, 0, limits[i], limits[i]) == 0);
		WRT_CHECK(n.ops == limits[i]);
		/* then a refusal that changes nothing, on every later call */
		memcpy(before, &n, sizeof(n));
		memset(out, 0xee, 12);
		memset(keep, 0xee, 12);
		for (k = 0; k < 4; k++) {
			WRT_CHECK_STATUS(WR_E_M2_NONCE, wri_m2s_nonce_take(&n, limits[i], out));
			WRT_CHECK_MEM(out, keep, 12);
			WRT_CHECK(memcmp(before, &n, sizeof(n)) == 0);
		}
		/* the limit belongs to the call: raising it (a test hook, 34.5) lets the stream go on from where it stopped */
		WRT_CHECK(run_against_model(&n, &m, limits[i], 2, limits[i] + 2u) == 0);
		/* limit 0 = none */
		WRT_CHECK(run_against_model(&n, &m, limits[i] + 2u, 10, 0) == 0);
	}
	/* limit 0 well beyond the default limit of the connection (2^40): an operation count of 2^41 is no obstacle */
	wri_m2s_nonce_init(&n, seed);
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out)); /* off the seed */
	n.ops = (uint64_t)1 << 41;
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	WRT_CHECK_STATUS(WR_E_M2_NONCE, wri_m2s_nonce_take(&n, WRI_M2S_OPS_LIMIT_DEFAULT, out));
	/* the default limit: refused at the 2^40-th, accepted just below */
	n.ops = WRI_M2S_OPS_LIMIT_DEFAULT - 1u;
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, WRI_M2S_OPS_LIMIT_DEFAULT, out));
	WRT_CHECK_U64(n.ops, WRI_M2S_OPS_LIMIT_DEFAULT);
	WRT_CHECK_STATUS(WR_E_M2_NONCE, wri_m2s_nonce_take(&n, WRI_M2S_OPS_LIMIT_DEFAULT, out));
	/* a huge limit never trips before the wrap */
	n.ops = 5;
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0xffffffffffffffffull, out));
}

static void test_directions_independent(void)
{
	uint8_t sa[12], sb[12], oa[12], ob[12], keep[12];
	wri_m2s_nonce a, b;
	model ma, mb;
	uint64_t i;

	make_seed(sa, 0x11111111u, 0xfffffffffffffff0ull); /* crosses the wrap during the run */
	make_seed(sb, 0x22222222u, 77u);
	model_from_seed(&ma, sa);
	model_from_seed(&mb, sb);
	wri_m2s_nonce_init(&a, sa);
	wri_m2s_nonce_init(&b, sb);
	for (i = 0; i < 40; i++) {
		uint8_t want[12];

		WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&a, 0, oa));
		model_nonce(&ma, i, want);
		WRT_CHECK_MEM(oa, want, 12);
		if (i % 3u != 2u) { /* b runs at its own pace */
			WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&b, 0, ob));
			model_nonce(&mb, b.ops - 1u, want);
			WRT_CHECK_MEM(ob, want, 12);
		}
		WRT_CHECK(memcmp(oa, ob, 12) != 0);
	}
	WRT_CHECK(a.ops == 40u && b.ops == 27u);
	/* b hits its limit; a is not affected by that, and b's refusal does not move a */
	WRT_CHECK_STATUS(WR_E_M2_NONCE, wri_m2s_nonce_take(&b, b.ops, ob));
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&a, 0, oa));
	WRT_CHECK(a.ops == 41u && b.ops == 27u);
	/* a nonce stream does not look at any other object: two streams with the same seed give the same nonces independently */
	{
		wri_m2s_nonce c, d;

		wri_m2s_nonce_init(&c, sb);
		wri_m2s_nonce_init(&d, sb);
		WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&c, 0, oa));
		WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&c, 0, oa));
		WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&d, 0, ob));
		memcpy(keep, sb, 12);
		WRT_CHECK_MEM(ob, keep, 12);
		WRT_CHECK(c.ops == 2u && d.ops == 1u);
	}
}

static void test_random_seeds(void)
{
	size_t s;

	for (s = 0; s < 64u; s++) {
		uint8_t seed[12];
		wri_m2s_nonce n;
		model m;
		uint64_t c;

		switch (s % 4u) {
		case 0:
			c = rnd64();
			break;
		case 1:
			c = rnd() & 0xffffu;
			break;
		case 2:
			c = 0ull - (uint64_t)(rnd() % 5000u) - 1u; /* just below 2^64: wraps during the run */
			break;
		default:
			c = (uint64_t)(rnd() % 5000u) * 0x100000001ull; /* carries across bytes */
			break;
		}
		make_seed(seed, rnd(), c);
		wri_m2s_nonce_init(&n, seed);
		model_from_seed(&m, seed);
		WRT_CHECK(run_against_model(&n, &m, 0, 6000, 0) == 0);
		WRT_CHECK(n.ops == 6000u);
	}
}

static void test_args(void)
{
	uint8_t out[12], zero[12];
	wri_m2s_nonce n, snap;
	uint8_t seed[12];

	memset(zero, 0, sizeof(zero));
	/* NULL arguments: refused, nothing written, no crash */
	wri_m2s_nonce_init(NULL, NULL);
	memset(seed, 3, sizeof(seed));
	wri_m2s_nonce_init(&n, seed);
	snap = n;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2s_nonce_take(NULL, 0, out));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2s_nonce_take(&n, 0, NULL));
	WRT_CHECK(memcmp(&snap, &n, sizeof(n)) == 0);
	/* a NULL seed gives the all-zero stream (documented), an all-zero seed works like any other */
	wri_m2s_nonce_init(&n, NULL);
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	WRT_CHECK_MEM(out, zero, 12);
	WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&n, 0, out));
	zero[4] = 1;
	WRT_CHECK_MEM(out, zero, 12);
	/* init discards whatever the object held (a reused stream restarts) */
	memset(&n, 0xab, sizeof(n));
	wri_m2s_nonce_init(&n, seed);
	WRT_CHECK(n.started == 0u && n.ops == 0u && memcmp(n.cur, seed, 12) == 0 && memcmp(n.seed, seed, 12) == 0);
	WRT_CHECK(n.reserved[0] == 0 && n.reserved[1] == 0 && n.reserved[2] == 0);
}

/* ---- through the connection state ----------------------------------------------------------------- */

/* A secret whose two seeds have counters near 2^64 - 3: seed A = S[16..27], seed B = S[28..39]. */
static void test_secret_near_wrap(void)
{
	uint8_t secret[64], out[12];
	wri_m2s s;
	size_t i, k;
	int crossed;

	for (i = 0; i < sizeof(secret); i++)
		secret[i] = (uint8_t)(0xc0u + i);
	make_seed(secret + 16, 0xcafef00du, 0xfffffffffffffffdull); /* A: 2^64 - 3 */
	make_seed(secret + 28, 0x0badbeefu, 0xfffffffffffffffeull); /* B: 2^64 - 2 */
	for (crossed = 0; crossed < 2; crossed++) {
		const uint8_t *tx_seed = secret + (crossed ? 16 : 28), *rx_seed = secret + (crossed ? 28 : 16);
		model mt, mr;

		WRT_CHECK_STATUS(WR_OK, wri_m2s_init(&s, NULL, secret, sizeof(secret), crossed));
		WRT_CHECK_MEM(s.tx_n.seed, tx_seed, 12);
		WRT_CHECK_MEM(s.rx_n.seed, rx_seed, 12);
		model_from_seed(&mt, tx_seed);
		model_from_seed(&mr, rx_seed);
		for (k = 0; k < 8; k++) {
			uint8_t want[12];

			WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&s.tx_n, s.ops_limit, out));
			model_nonce(&mt, k, want);
			WRT_CHECK_MEM(out, want, 12);
			WRT_CHECK_STATUS(WR_OK, wri_m2s_nonce_take(&s.rx_n, s.ops_limit, out));
			model_nonce(&mr, k, want);
			WRT_CHECK_MEM(out, want, 12);
		}
		/* the wrap happened inside this run: the counters of both directions went through 0 and the fixed fields stayed */
		WRT_CHECK(le64_get(s.tx_n.cur + 4) == (crossed ? 5u : 6u) && le64_get(s.rx_n.cur + 4) == (crossed ? 6u : 5u));
		WRT_CHECK_MEM(s.tx_n.cur, tx_seed, 4);
		WRT_CHECK_MEM(s.rx_n.cur, rx_seed, 4);
		WRT_CHECK(s.tx_n.ops == 8u && s.rx_n.ops == 8u);
		wri_m2s_wipe(&s);
	}
}

int main(void)
{
	test_first_is_seed_and_steps();
	test_carries_and_wrap();
	test_refusal_at_seed();
	test_limit();
	test_directions_independent();
	test_random_seeds();
	test_args();
	test_secret_near_wrap();
	return wrt_finish();
}
