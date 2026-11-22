/* SPDX-License-Identifier: MIT */
/*
 * wrl_gcm_aesni.c - AES-128-GCM for msgr2 secure mode with AES-NI and PCLMULQDQ. See wrl_gcm_aesni.h for the contract.
 *
 * Written from FIPS 197 (AES), NIST SP 800-38D (GCM) and the instruction descriptions; no code of any library is used.
 *
 * How the hash works here. GCM numbers the bits of a block from the left of byte 0: the leftmost bit is the coefficient of x^0.
 * Reversing the 16 bytes of a block turns it into a 128-bit integer in which the coefficient of x^i sits at bit 127 - i (the
 * "reflected" form). The carry-less product of two such integers has the coefficient of x^k at bit 254 - k, which is a 256-bit
 * reflected value of x times the product. So the hash key is stored as H * x^-1 (a left shift by one with the reduction folded in:
 * the constant 0xc2000000 00000001 appears when the bit shifted out is set); then PCLMULQDQ yields the product with its bits
 * exactly where a reflected 256-bit value has them. The high half of that value holds x^0 .. x^127, the low half x^128 .. x^255,
 * and x^128 = x^7 + x^2 + x + 1 modulo the GCM polynomial, so the reduction is "high ^ F ^ F>>1 ^ F>>2 ^ F>>7" with F the low half
 * plus its own overflow (the bits the right shifts would lose, which come back as low powers of x). Two blocks are combined
 * with the squared key, (acc ^ c0) * H^2 ^ c1 * H, before one reduction.
 *
 * The block counter starts at 2 (J0 = IV || 1 is only used for the tag mask) and is the number of blocks done plus 2; the tag
 * mask is encrypted at the end from the stored IV, so no copy of it is kept.
 */
#include "wrl_gcm_aesni.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define WRL_AESNI 1
#include <cpuid.h>
#include <immintrin.h>
#endif

#ifdef WRL_AESNI

#define WRL_TGT __attribute__((target("aes,pclmul,sse4.1")))

/* Tests may replace the CPUID leaf 1 reader to see what the hook does on a CPU without a feature: the function returns 1 and
 * stores ECX, or returns 0 when the leaf is not there. */
#ifdef WRL_GCM_AESNI_CPUID1
#define WRL_CPUID1 WRL_GCM_AESNI_CPUID1
#else
static int wrl_cpuid1_default(unsigned *ecx)
{
	unsigned a = 0, b = 0, c = 0, d = 0;

	if (!__get_cpuid(1, &a, &b, &c, &d))
		return 0;
	*ecx = c;
	return 1;
}
#define WRL_CPUID1 wrl_cpuid1_default
#endif

/* The operation modes of the state. 0 must be "all zero": a wiped state is unkeyed. */
enum { M_NOKEY = 0, M_IDLE = 1, M_ENC = 2, M_DEC = 3, M_FAILED = 4 };

typedef struct wrl_gs {
	uint8_t rk[176];  /* AES-128 round keys, 11 * 16 */
	uint8_t hk[32];   /* H * x^-1 and H^2 * x^-1, reflected form, little-endian vector bytes */
	uint8_t acc[16];  /* running hash, reflected form */
	uint8_t iv[12];   /* IV of the running operation */
	uint32_t ctr;     /* next counter value (2 at the start of an operation) */
	uint32_t mode;
	uint32_t pad;
} wrl_gs;

typedef char wrl_gs_size_check[(sizeof(wrl_gs) == WRL_GCM_AESNI_STATE_BYTES && sizeof(wrl_gs) <= WR_GCM_HOST_STATE_MAX &&
				sizeof(wrl_gs) % 8u == 0u)
			       ? 1
			       : -1];

static const uint8_t k_bswap[16] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
/* x^127 + x^6 + x + 1 in reflected form: what dividing by x adds when the constant term was set */
static const uint8_t k_red[16] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc2};

/* ---- small helpers --------------------------------------------------------------------------- */

static WRL_TGT __m128i ld128(const void *p)
{
	return _mm_loadu_si128((const __m128i *)p);
}

static WRL_TGT void st128(void *p, __m128i v)
{
	_mm_storeu_si128((__m128i *)p, v);
}

static WRL_TGT __m128i bswap128(__m128i x)
{
	return _mm_shuffle_epi8(x, ld128(k_bswap));
}

/* x >> n and x << n as 128-bit integers, 0 < n < 64 */
static WRL_TGT __m128i shr128(__m128i x, int n)
{
	/* the shifted lanes, plus the bits of the high lane that cross into the low one */
	__m128i a = _mm_srli_epi64(x, n);
	__m128i b = _mm_slli_epi64(x, 64 - n);

	return _mm_or_si128(a, _mm_srli_si128(b, 8));
}

static WRL_TGT __m128i shl128_1(__m128i x)
{
	__m128i a = _mm_slli_epi64(x, 1);
	__m128i b = _mm_srli_epi64(x, 63);

	return _mm_or_si128(a, _mm_slli_si128(b, 8));
}

/* (low lane of x) << (64 + k) as a 128-bit integer: only the low lane survives, moved into the high one */
static WRL_TGT __m128i shl_lo_up(__m128i x, int k)
{
	return _mm_slli_si128(_mm_slli_epi64(x, k), 8);
}

/* ---- GHASH ----------------------------------------------------------------------------------- */

/* Add the carry-less product of a and b (unreduced) into the three accumulators. */
static WRL_TGT void clm_acc(__m128i a, __m128i b, __m128i *lo, __m128i *hi, __m128i *mid)
{
	*lo = _mm_xor_si128(*lo, _mm_clmulepi64_si128(a, b, 0x00));
	*hi = _mm_xor_si128(*hi, _mm_clmulepi64_si128(a, b, 0x11));
	*mid = _mm_xor_si128(*mid, _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x10), _mm_clmulepi64_si128(a, b, 0x01)));
}

/* Reduce the 256-bit value (hi:lo with the middle terms in mid) modulo the GCM polynomial, see the header comment. */
static WRL_TGT __m128i gh_reduce(__m128i lo, __m128i hi, __m128i mid)
{
	__m128i l = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
	__m128i h = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));
	/* the bits the right shifts below would lose come back as low powers of x */
	__m128i f = _mm_xor_si128(l, _mm_xor_si128(shl_lo_up(l, 63), _mm_xor_si128(shl_lo_up(l, 62), shl_lo_up(l, 57))));

	h = _mm_xor_si128(h, f);
	h = _mm_xor_si128(h, shr128(f, 1));
	h = _mm_xor_si128(h, shr128(f, 2));
	return _mm_xor_si128(h, shr128(f, 7));
}

/* a * b where bt is b * x^-1: the field product of the two blocks, reflected form */
static WRL_TGT __m128i gh_mul(__m128i a, __m128i bt)
{
	__m128i lo = _mm_setzero_si128(), hi = _mm_setzero_si128(), mid = _mm_setzero_si128();

	clm_acc(a, bt, &lo, &hi, &mid);
	return gh_reduce(lo, hi, mid);
}

/* v * x^-1 modulo the polynomial (reflected form: shift left by one, fold the carry in without a branch) */
static WRL_TGT __m128i gh_div_x(__m128i v)
{
	__m128i carry = _mm_shuffle_epi32(_mm_srai_epi32(v, 31), 0xff); /* all ones when bit 127 is set */

	return _mm_xor_si128(shl128_1(v), _mm_and_si128(carry, ld128(k_red)));
}

/* acc = (acc ^ c0) * H^2 ^ c1 * H, with the two products reduced once */
static WRL_TGT __m128i gh_pair(__m128i acc, __m128i c0, __m128i c1, __m128i h1, __m128i h2)
{
	__m128i lo = _mm_setzero_si128(), hi = _mm_setzero_si128(), mid = _mm_setzero_si128();

	clm_acc(_mm_xor_si128(acc, c0), h2, &lo, &hi, &mid);
	clm_acc(c1, h1, &lo, &hi, &mid);
	return gh_reduce(lo, hi, mid);
}

/* ---- AES-128, encrypt direction -------------------------------------------------------------- */

static WRL_TGT __m128i ks_step(__m128i key, __m128i assist)
{
	assist = _mm_shuffle_epi32(assist, 0xff);
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, assist);
}

#define WRL_KS(i, rcon)                                                                                                   \
	do {                                                                                                              \
		k = ks_step(k, _mm_aeskeygenassist_si128(k, rcon));                                                       \
		st128(rk + 16 * (i), k);                                                                                  \
	} while (0)

static WRL_TGT void aes128_expand(uint8_t rk[176], const uint8_t key[16])
{
	__m128i k = ld128(key);

	st128(rk, k);
	WRL_KS(1, 0x01);
	WRL_KS(2, 0x02);
	WRL_KS(3, 0x04);
	WRL_KS(4, 0x08);
	WRL_KS(5, 0x10);
	WRL_KS(6, 0x20);
	WRL_KS(7, 0x40);
	WRL_KS(8, 0x80);
	WRL_KS(9, 0x1b);
	WRL_KS(10, 0x36);
}

static WRL_TGT __m128i aes_enc1(const uint8_t *rk, __m128i b)
{
	int i;

	b = _mm_xor_si128(b, ld128(rk));
	for (i = 1; i < 10; i++)
		b = _mm_aesenc_si128(b, ld128(rk + 16 * i));
	return _mm_aesenclast_si128(b, ld128(rk + 160));
}

static WRL_TGT void aes_enc4(const uint8_t *rk, __m128i b[4])
{
	__m128i k = ld128(rk);
	int i;

	b[0] = _mm_xor_si128(b[0], k);
	b[1] = _mm_xor_si128(b[1], k);
	b[2] = _mm_xor_si128(b[2], k);
	b[3] = _mm_xor_si128(b[3], k);
	for (i = 1; i < 10; i++) {
		k = ld128(rk + 16 * i);
		b[0] = _mm_aesenc_si128(b[0], k);
		b[1] = _mm_aesenc_si128(b[1], k);
		b[2] = _mm_aesenc_si128(b[2], k);
		b[3] = _mm_aesenc_si128(b[3], k);
	}
	k = ld128(rk + 160);
	b[0] = _mm_aesenclast_si128(b[0], k);
	b[1] = _mm_aesenclast_si128(b[1], k);
	b[2] = _mm_aesenclast_si128(b[2], k);
	b[3] = _mm_aesenclast_si128(b[3], k);
}

/* IV || big-endian counter, as a block */
static WRL_TGT __m128i ctr_block(__m128i ivbase, uint32_t c)
{
	return _mm_insert_epi32(ivbase, (int)__builtin_bswap32(c), 3);
}

/* ---- helpers on the state -------------------------------------------------------------------- */

static void gs_zero(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0u)
		*v++ = 0;
}

/* The same for vectors, one store per 16 bytes (the byte loop above would cost more than a short operation does). */
static WRL_TGT void vec_zero(__m128i *v, size_t n)
{
	volatile __m128i *w = (volatile __m128i *)v;
	size_t i;

	for (i = 0; i < n; i++)
		w[i] = _mm_setzero_si128();
}

/* Leave the running operation: the key stays, everything of the operation goes. */
static void gs_end_op(wrl_gs *s)
{
	gs_zero(s->acc, sizeof(s->acc));
	gs_zero(s->iv, sizeof(s->iv));
	s->ctr = 0;
	if (s->mode != M_NOKEY)
		s->mode = M_IDLE;
}

static void gs_poison(wrl_gs *s)
{
	s->mode = M_FAILED;
}

/* Hash and crypt nblocks whole blocks of the running operation. in == out is fine (every load of a group precedes its stores). */
static WRL_TGT void gs_run(wrl_gs *s, const uint8_t *in, uint8_t *out, size_t nblocks, int dec)
{
	__m128i h1 = ld128(s->hk), h2 = ld128(s->hk + 16), acc = ld128(s->acc);
	uint8_t ivb[16];
	__m128i ivbase;
	__m128i p4[4], ks4[4], g4[4]; /* the data, keystream and hash input of a group: erased below, they hold plaintext and keystream */
	uint32_t c = s->ctr;

	memset(ivb, 0, sizeof(ivb));
	memcpy(ivb, s->iv, 12);
	ivbase = ld128(ivb);

	while (nblocks >= 4u) {
		__m128i *p = p4, *ks = ks4, *g = g4;
		int i;

		for (i = 0; i < 4; i++) {
			p[i] = ld128(in + 16 * i);
			ks[i] = ctr_block(ivbase, c + (uint32_t)i);
		}
		aes_enc4(s->rk, ks);
		for (i = 0; i < 4; i++) {
			__m128i x = _mm_xor_si128(p[i], ks[i]);

			g[i] = bswap128(dec ? p[i] : x);
			st128(out + 16 * i, x);
		}
		acc = gh_pair(acc, g[0], g[1], h1, h2);
		acc = gh_pair(acc, g[2], g[3], h1, h2);
		in += 64;
		out += 64;
		c += 4u;
		nblocks -= 4u;
	}
	while (nblocks > 0u) {
		__m128i p = ld128(in);
		__m128i x = _mm_xor_si128(p, aes_enc1(s->rk, ctr_block(ivbase, c)));

		st128(out, x);
		acc = gh_mul(_mm_xor_si128(acc, bswap128(dec ? p : x)), h1);
		in += 16;
		out += 16;
		c++;
		nblocks--;
	}
	st128(s->acc, acc);
	s->ctr = c;
	gs_zero(ivb, sizeof(ivb));
	vec_zero(p4, 4);
	vec_zero(ks4, 4);
	vec_zero(g4, 4);
}

/* The tag of the finished operation: hash of the length block xor E(K, IV || 1). Reflected hash out as wire bytes. */
static WRL_TGT void gs_tag(const wrl_gs *s, uint8_t tag[16])
{
	uint8_t lb[16], j0[16];
	uint64_t bits = (uint64_t)(uint32_t)(s->ctr - 2u) * 128u; /* blocks * 16 * 8 */
	__m128i h1 = ld128(s->hk), acc = ld128(s->acc), t;
	int i;

	memset(lb, 0, sizeof(lb)); /* no additional data: the first length is zero */
	for (i = 0; i < 8; i++)
		lb[15 - i] = (uint8_t)(bits >> (8 * i));
	acc = gh_mul(_mm_xor_si128(acc, bswap128(ld128(lb))), h1);
	memcpy(j0, s->iv, 12);
	j0[12] = 0;
	j0[13] = 0;
	j0[14] = 0;
	j0[15] = 1;
	t = _mm_xor_si128(bswap128(acc), aes_enc1(s->rk, ld128(j0)));
	st128(tag, t);
	gs_zero(lb, sizeof(lb));
	gs_zero(j0, sizeof(j0));
}

/* ---- the six members ------------------------------------------------------------------------- */

static WRL_TGT wr_status hook_setkey(void *ctx, void *state, const uint8_t key[16])
{
	wrl_gs *s = (wrl_gs *)state;
	uint8_t zero[16], hraw[16];
	__m128i h, hs, h2;

	(void)ctx;
	if (s == NULL)
		return WR_E_INVAL;
	gs_zero(s, sizeof(*s));
	if (key == NULL)
		return WR_E_INVAL;
	aes128_expand(s->rk, key);
	memset(zero, 0, sizeof(zero));
	st128(hraw, aes_enc1(s->rk, ld128(zero)));
	h = bswap128(ld128(hraw));
	hs = gh_div_x(h);
	h2 = gh_mul(h, hs); /* H * H, reflected */
	st128(s->hk, hs);
	st128(s->hk + 16, gh_div_x(h2));
	s->mode = M_IDLE;
	gs_zero(hraw, sizeof(hraw));
	return WR_OK;
}

static wr_status hook_start(void *ctx, void *state, const uint8_t iv[12], int decrypt)
{
	wrl_gs *s = (wrl_gs *)state;

	(void)ctx;
	if (s == NULL || s->mode == M_NOKEY)
		return WR_E_STATE;
	if (iv == NULL || (decrypt != 0 && decrypt != 1))
		return WR_E_INVAL;
	/* an operation still running is dropped */
	gs_zero(s->acc, sizeof(s->acc));
	memcpy(s->iv, iv, 12);
	s->ctr = 2u;
	s->mode = decrypt ? M_DEC : M_ENC;
	return WR_OK;
}

static void hook_update(void *ctx, void *state, const uint8_t *in, uint8_t *out, size_t n)
{
	wrl_gs *s = (wrl_gs *)state;
	uint64_t used, room;

	(void)ctx;
	if (s == NULL || (s->mode != M_ENC && s->mode != M_DEC))
		return; /* not in an operation (or already failed): nothing to do, nothing is written */
	if (n == 0u)
		return;
	if ((n & 15u) != 0u || in == NULL || out == NULL) {
		gs_poison(s);
		return;
	}
	if (in != out) {
		uintptr_t a = (uintptr_t)in, b = (uintptr_t)out;

		/* partial overlap; the distance form cannot wrap around the top of the address space the way a + n could */
		if ((a < b) ? ((b - a) < (uintptr_t)n) : ((a - b) < (uintptr_t)n)) {
			gs_poison(s);
			return;
		}
	}
	used = (uint32_t)(s->ctr - 2u);
	room = 0xfffffffeull - used; /* 2^32 - 2 blocks = 2^36 - 32 bytes at most per operation */
	if ((uint64_t)(n >> 4) > room) {
		gs_poison(s);
		return;
	}
	gs_run(s, in, out, n >> 4, s->mode == M_DEC);
}

static void hook_final_enc(void *ctx, void *state, uint8_t tag[16])
{
	wrl_gs *s = (wrl_gs *)state;

	(void)ctx;
	if (s == NULL)
		return;
	if (tag == NULL) { /* nowhere to put a tag: the operation is over, nothing is written */
		gs_end_op(s);
		return;
	}
	if (s->mode != M_ENC)
		memset(tag, 0, 16);
	else
		gs_tag(s, tag);
	gs_end_op(s);
}

static wr_status hook_final_dec(void *ctx, void *state, const uint8_t tag[16])
{
	wrl_gs *s = (wrl_gs *)state;
	uint8_t want[16];
	unsigned diff = 0;
	size_t i;
	wr_status r;

	(void)ctx;
	if (s == NULL)
		return WR_E_CRYPTO_MAC;
	if (tag == NULL || s->mode != M_DEC) { /* no tag to compare with is a refusal, and it ends the operation */
		gs_end_op(s);
		return WR_E_CRYPTO_MAC;
	}
	gs_tag(s, want);
	for (i = 0; i < 16u; i++) /* every byte, no early exit */
		diff |= (unsigned)(want[i] ^ tag[i]);
	/* an empty asm statement: the compiler may not see through the accumulated value and turn the loop into an early-exit compare */
	__asm__ volatile("" : "+r"(diff));
	r = (diff == 0u) ? WR_OK : WR_E_CRYPTO_MAC;
	gs_zero(want, sizeof(want));
	gs_end_op(s);
	return r;
}

static void hook_wipe(void *ctx, void *state)
{
	(void)ctx;
	if (state != NULL)
		gs_zero(state, sizeof(wrl_gs));
}

/* ---- public ---------------------------------------------------------------------------------- */

int wrl_gcm_aesni_available(void)
{
	unsigned ecx = 0;

	if (!WRL_CPUID1(&ecx))
		return 0;
	/* CPUID.1:ECX bit 1 PCLMULQDQ, 9 SSSE3, 19 SSE4.1, 25 AES */
	return ((ecx >> 1) & 1u) && ((ecx >> 9) & 1u) && ((ecx >> 19) & 1u) && ((ecx >> 25) & 1u);
}

int wrl_gcm_aesni_ops(wr_prim_ops *out)
{
	if (out == NULL || !wrl_gcm_aesni_available())
		return -1;
	memset(out, 0, sizeof(*out));
	out->size = (uint32_t)sizeof(*out);
	out->gcm_state_bytes = WRL_GCM_AESNI_STATE_BYTES;
	out->gcm_setkey = hook_setkey;
	out->gcm_start = hook_start;
	out->gcm_update = hook_update;
	out->gcm_final_enc = hook_final_enc;
	out->gcm_final_dec = hook_final_dec;
	out->gcm_wipe = hook_wipe;
	return 0;
}

#else /* not x86-64 with gcc or clang: the hook is not there */

int wrl_gcm_aesni_available(void)
{
	return 0;
}

int wrl_gcm_aesni_ops(wr_prim_ops *out)
{
	(void)out;
	return -1;
}

#endif
