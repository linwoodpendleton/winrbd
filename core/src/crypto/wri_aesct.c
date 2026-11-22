/* SPDX-License-Identifier: MIT */
/*
 * wri_aesct.c - constant-time bitsliced AES-128 / AES-256, encrypt direction (see wri_aesct.h for the contract and the
 * constant-time argument).
 *
 * State layout. Two blocks are processed at once. The state is eight 32-bit words, one per bit of a byte ("plane" k holds bit k of
 * every state byte). Bit position inside a plane word is 8 * row + 4 * blk + col, where the byte of block blk sits in column col and
 * row row of the FIPS 197 state matrix (so memory byte 16 * blk + 4 * col + row). One byte lane of a plane (8 bits) is therefore one
 * row of both blocks: the low nibble of the lane is block 0, the high nibble block 1, the bit inside a nibble is the column.
 *   - SubBytes   one Boolean circuit applied to the eight planes (all 32 bytes in parallel);
 *   - ShiftRows  rotates the four bits of each nibble of row r by r positions: masks and constant shifts;
 *   - MixColumns a row is a byte lane, so "the next row" is a rotation of the word by 8 bits and "two rows on" one by 16;
 *   - AddRoundKey an XOR with the round key in the same layout, both blocks alike (stored that way by setkey).
 * Loading is a transposition of an 8 x 8 bit matrix per byte lane (three rounds of delta swaps, no table). Fewer than two blocks
 * are padded with zeros and the padding is dropped on the way out.
 *
 * S-box. The 113-gate circuit of Boyar and Peralta (cited in wri_aesct.h) typed in from their paper: a top linear layer, a
 * non-linear middle that inverts in a tower field, a bottom linear layer that also adds the affine constant. Only XOR, AND and
 * NOT of whole words. It is checked against all 256 entries of the table in wri_aes.c by the tests (wri_aesct_sbox32 is the hook).
 *
 * Key schedule. FIPS 197 5.2 on 32-bit words; SubWord runs the same circuit (one word, transposed into four bit lanes). The words are first
 * expanded in place in ctx->rk, then every round key is converted into the plane layout, last round key first, so a converted key
 * never overwrites a word that is still to be read. Whatever the call does not need is wiped before it returns.
 *
 * No table, no secret-dependent branch, loop bound, shift amount or address, no division. No heap, no global. Stack of the block
 * function: its own frame (the eight state words and six loop values) plus the larger of the S-box and the round tail, which it calls
 * one after the other. Under 256 bytes on x86-64 (System V) with gcc 13 / 15 and clang 18 / 22 at -O1 to -O3 and -Os; the test paints
 * and measures the stack. The Windows x64 ABI has no red zone and gives every non-leaf call 32 bytes of shadow space, so the same code
 * measures about 290 bytes there (gcc 15, compile-time frame sizes): the Windows glue's budget has to say so.
 */
#include "wri_aesct.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/*
 * The block path is split into frames that are siblings, never nested: the caller holds the state, the S-box and the round tail are
 * called one after the other, so the deepest chain is the caller plus the larger of the two. A compiler that inlines them back gives
 * a larger frame, not a different result; the attribute only keeps the stack small where it is understood.
 */
#if defined(__GNUC__) || defined(__clang__)
#define WRI_AESCT_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define WRI_AESCT_NOINLINE __declspec(noinline)
#else
#define WRI_AESCT_NOINLINE
#endif

/* Little-endian load / store: the word order of the state is the memory order whatever the host. */
static uint32_t ld32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void st32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static uint32_t ror32(uint32_t x, unsigned n) /* n is a constant 1..31 at every call */
{
	return (x >> n) | (x << (32u - n));
}

/* Delta swap: exchange the bits of *hi selected by mask (shifted up by s) with the bits of *lo selected by mask. */
static void dswap(uint32_t *lo, uint32_t *hi, unsigned s, uint32_t mask)
{
	uint32_t t = ((*lo >> s) ^ *hi) & mask;

	*hi ^= t;
	*lo ^= t << s;
}

/*
 * Swap the bit s of the word index (s = 4, 2, 1) with the bit s of the position inside each byte lane: transposes, per lane, the
 * 8 x 8 bit matrix whose rows are the words. Words w[m] (bytes 4m .. 4m+3 of the 32 byte chunk) become the planes, plane k bit
 * 8 * i + m = bit k of byte 4m + i; applied to planes it gives the words back (the three swaps commute and each is its own inverse).
 */
static void ortho(uint32_t *w)
{
	dswap(&w[0], &w[4], 4, 0x0f0f0f0fu);
	dswap(&w[1], &w[5], 4, 0x0f0f0f0fu);
	dswap(&w[2], &w[6], 4, 0x0f0f0f0fu);
	dswap(&w[3], &w[7], 4, 0x0f0f0f0fu);
	dswap(&w[0], &w[2], 2, 0x33333333u);
	dswap(&w[1], &w[3], 2, 0x33333333u);
	dswap(&w[4], &w[6], 2, 0x33333333u);
	dswap(&w[5], &w[7], 2, 0x33333333u);
	dswap(&w[0], &w[1], 1, 0x55555555u);
	dswap(&w[2], &w[3], 1, 0x55555555u);
	dswap(&w[4], &w[5], 1, 0x55555555u);
	dswap(&w[6], &w[7], 1, 0x55555555u);
}

/*
 * The S-box on eight planes (q[k] = bit k), every bit position independently: the 113-gate circuit of Boyar and Peralta, typed in from
 * their paper with its gate names (inputs U0..U7 with U0 = most significant bit = q[7], outputs S0..S7 with S0 = most significant
 * bit; T = top linear layer, M = the non-linear middle with the products of the bottom, L = bottom linear layer). A gate that only one
 * other gate uses is written into that gate's expression (its name is in the comment), which leaves 64 names instead of 120: at -O0
 * every name is a stack slot, and -Wframe-larger-than=1024 applies to the sanitizer builds as well. The circuit is the same.
 */
WRI_AESCT_NOINLINE static void sbox_planes(uint32_t *q)
{
	uint32_t U0 = q[7], U1 = q[6], U2 = q[5], U3 = q[4], U4 = q[3], U5 = q[2], U6 = q[1], U7 = q[0];
	uint32_t T1 = U0 ^ U3;
	uint32_t T2 = U0 ^ U5;
	uint32_t T3 = U0 ^ U6;
	uint32_t T4 = U3 ^ U5;
	uint32_t T5 = U4 ^ U6;
	uint32_t T6 = T1 ^ T5;
	uint32_t T7 = U1 ^ U2;
	uint32_t T8 = U7 ^ T6;
	uint32_t T9 = U7 ^ T7;
	uint32_t T10 = T6 ^ T7;
	uint32_t T11 = U1 ^ U5;
	uint32_t T12 = U2 ^ U5;
	uint32_t T13 = T3 ^ T4;
	uint32_t T15 = T5 ^ T11;
	uint32_t T16 = T5 ^ T12;
	uint32_t T17 = T9 ^ T16;
	uint32_t T19 = T7 ^ (U3 ^ U7);  /* T19 with T18 */
	uint32_t T20 = T1 ^ T19;
	uint32_t T22 = T7 ^ (U6 ^ U7);  /* T22 with T21 */
	uint32_t T23 = T2 ^ T22;
	uint32_t T27 = T1 ^ T12;
	uint32_t M1 = T13 & T6;
	uint32_t M6 = T3 & T16;
	uint32_t M11 = T1 & T15;
	uint32_t M13 = (T4 & T27) ^ M11;  /* M13 with M12 */
	uint32_t M15 = (T2 & T10) ^ M11;  /* M15 with M14 */
	uint32_t M20 = (((T6 ^ T11) ^ M1) ^ (T23 & T8)) ^ M13;  /* M20 with M16, M3, T14, M2 */
	uint32_t M21 = (((T19 & U7) ^ M1) ^ (T2 ^ T10)) ^ M15;  /* M21 with M17, M5, M4, T24 */
	uint32_t M22 = (((T3 ^ T16) ^ M6) ^ (T22 & T9)) ^ M13;  /* M22 with M18, M8, T26, M7 */
	uint32_t M23 = (((T20 & T17) ^ M6) ^ M15) ^ (T20 ^ T17);  /* M23 with M19, M10, M9, T25 */
	uint32_t M24 = M22 ^ M23;
	uint32_t M25 = M22 & M20;
	uint32_t M27 = M20 ^ M21;
	uint32_t M37 = M21 ^ ((M23 ^ M25) & M27);  /* M37 with M29, M28 */
	uint32_t M38 = (M27 & (M20 & M23)) ^ (M27 ^ M25);  /* M38 with M32, M31, M33 */
	uint32_t M39 = M23 ^ ((M21 ^ M25) & M24);  /* M39 with M30, M26 */
	uint32_t M40 = (M24 & (M21 & M22)) ^ (M24 ^ M25);  /* M40 with M35, M34, M36 */
	uint32_t M41 = M38 ^ M40;
	uint32_t M42 = M37 ^ M39;
	uint32_t M43 = M37 ^ M38;
	uint32_t M44 = M39 ^ M40;
	uint32_t M45 = M42 ^ M41;
	uint32_t M46 = M44 & T6;
	uint32_t M48 = M39 & U7;
	uint32_t M50 = M38 & T9;
	uint32_t M51 = M37 & T17;
	uint32_t M52 = M42 & T15;
	uint32_t M53 = M45 & T27;
	uint32_t M55 = M44 & T13;
	uint32_t M56 = M40 & T23;
	uint32_t M58 = M43 & T3;
	uint32_t M61 = M42 & T1;
	uint32_t M62 = M45 & T4;
	uint32_t L0 = M61 ^ M62;
	uint32_t L1 = M50 ^ M56;
	uint32_t L2 = M46 ^ M48;
	uint32_t L3 = (M40 & T8) ^ M55;  /* L3 with M47 */
	uint32_t L4 = (M41 & T10) ^ M58;  /* L4 with M54 */
	uint32_t L6 = M62 ^ ((M43 & T16) ^ M61);  /* L6 with L5, M49 */
	uint32_t L7 = M46 ^ L3;
	uint32_t L8 = M51 ^ (M38 & T22);  /* L8 with M59 */
	uint32_t L9 = M52 ^ M53;
	uint32_t L10 = M53 ^ L4;
	uint32_t L11 = (M37 & T20) ^ L2;  /* L11 with M60 */

	q[7] = L6 ^ ((M55 ^ L1) ^ L9);  /* S0 */
	q[6] = ~((M56 ^ L0) ^ (L7 ^ L9));  /* S1 */
	q[5] = ~(((M41 & T2) ^ L4) ^ (L11 ^ (M52 ^ M61)));  /* S2 */
	q[4] = L6 ^ (L1 ^ L7);  /* S3 */
	q[3] = (L0 ^ L1) ^ (L3 ^ (M48 ^ M51));  /* S4 */
	q[2] = (L6 ^ L10) ^ (L11 ^ ((M39 & T19) ^ L1));  /* S5 */
	q[1] = ~((M50 ^ L0) ^ (L8 ^ L10));  /* S6 */
	q[0] = ~(L6 ^ ((M58 ^ L8) ^ L2));  /* S7 */
}

/* ShiftRows: row r (byte lane r) takes, in every nibble, bit c + r (mod 4) into bit c. */
static void shift_rows(uint32_t *q)
{
	unsigned k;

	for (k = 0; k < 8u; k++) {
		uint32_t x = q[k];

		q[k] = (x & 0x000000ffu)
		       | ((x >> 1) & 0x00007700u) | ((x << 3) & 0x00008800u)
		       | ((x >> 2) & 0x00330000u) | ((x << 2) & 0x00cc0000u)
		       | ((x >> 3) & 0x11000000u) | ((x << 1) & 0xee000000u);
	}
}

/*
 * MixColumns: out_r = 2 a_r + 3 a_(r+1) + a_(r+2) + a_(r+3) = xtime(t_r) + a_r + t_r + t_(r+2) with t_r = a_r + a_(r+1)
 * (so a_(r+1) = a_r + t_r and a_(r+2) + a_(r+3) = t_(r+2)). Per plane: t = q + (q one row on), and xtime(t) takes plane k - 1 of t
 * (plane 7 also feeds planes 1, 3 and 4: x^8 = x^4 + x^3 + x + 1, mask 0x1a). Planes are done in order with the previous t kept in a
 * scalar, so no second array is needed.
 */
static void mix_columns(uint32_t *q)
{
	uint32_t t7 = q[7] ^ ror32(q[7], 8), tp = t7, t;
	unsigned k;

	for (k = 0; k < 7u; k++) {
		t = q[k] ^ ror32(q[k], 8);
		q[k] ^= t ^ ror32(t, 16) ^ tp ^ (t7 & (0u - ((0x1au >> k) & 1u)));
		tp = t;
	}
	q[7] ^= t7 ^ ror32(t7, 16) ^ tp;
}

/* The rest of a round after SubBytes: ShiftRows, MixColumns (not in the last round; mix is public), AddRoundKey. */
WRI_AESCT_NOINLINE static void round_tail(uint32_t *q, const uint32_t *rk, unsigned mix)
{
	unsigned k;

	shift_rows(q);
	if (mix != 0u)
		mix_columns(q);
	for (k = 0; k < 8u; k++)
		q[k] ^= rk[k];
}

/* A usable context: keyed by a successful wri_aesct_setkey. rounds is public. */
static int ctx_ok(const wri_aesct_ctx *c)
{
	return c != NULL && (c->rounds == 10u || c->rounds == 14u);
}

/* SubWord: the circuit on the four bytes of a word. Word 0 of an all-zero chunk becomes the planes (lane i = byte i); the zeros around it are
 * transposed and substituted too, which costs nothing that matters here: the key schedule runs once per key. */
static uint32_t sub_word(uint32_t w)
{
	uint32_t q[8], r;
	unsigned k;

	q[0] = w;
	for (k = 1; k < 8u; k++)
		q[k] = 0;
	ortho(q);
	sbox_planes(q);
	ortho(q);
	r = q[0];
	wri_secure_zero(q, sizeof(q));
	return r;
}

wr_status wri_aesct_setkey(wri_aesct_ctx *c, const uint8_t *key, size_t klen)
{
	uint32_t nk, total, i, j, rcon, r, k;
	int len_ok = (klen == 16u || klen == 32u);

	if (c == NULL)
		return len_ok ? WR_E_INVAL : WR_E_CRYPTO_KEY;
	/* Fail closed: until the schedule is complete the context is unusable and holds no half-made schedule. */
	c->rounds = 0;
	WR_MEMSET(c->rk, 0, sizeof(c->rk));
	if (!len_ok)
		return WR_E_CRYPTO_KEY;
	if (key == NULL)
		return WR_E_INVAL;

	nk = (uint32_t)(klen / 4u);
	total = 4u * (nk + 6u + 1u);
	for (i = 0; i < nk; i++)
		c->rk[i] = ld32(key + 4u * i);
	rcon = 1;
	for (i = nk, j = 0; i < total; i++) { /* j = i mod nk, counted instead of divided: i, j, nk and rcon are all public */
		uint32_t t = c->rk[i - 1u];

		if (j == 0u) {
			t = sub_word(ror32(t, 8)) ^ rcon; /* RotWord: byte 0 of the word is the first byte, so rotate right by 8 */
			rcon = (rcon << 1) ^ (0x11bu & (0u - (rcon >> 7)));
		} else if (nk > 6u && j == 4u) {
			t = sub_word(t);
		}
		c->rk[i] = c->rk[i - nk] ^ t;
		j = (j + 1u == nk) ? 0u : j + 1u;
	}
	/* round keys to planes, last first: round r reads words 4r..4r+3 and writes words 8r..8r+7, never a word still to be read */
	for (r = total / 4u; r-- > 0;) {
		uint32_t w[8];

		for (k = 0; k < 4u; k++) {
			w[k] = c->rk[4u * r + k];
			w[4u + k] = w[k]; /* the second block sees the same key */
		}
		ortho(w);
		for (k = 0; k < 8u; k++)
			c->rk[8u * r + k] = w[k];
		wri_secure_zero(w, sizeof(w));
	}
	c->rounds = nk + 6u;
	return WR_OK;
}

void wri_aesct_sbox32(const uint8_t in[32], uint8_t out[32])
{
	uint32_t w[8];
	unsigned k;

	if (out == NULL)
		return;
	if (in == NULL) {
		WR_MEMSET(out, 0, 32);
		return;
	}
	for (k = 0; k < 8u; k++)
		w[k] = ld32(in + 4u * k);
	ortho(w);
	sbox_planes(w);
	ortho(w);
	for (k = 0; k < 8u; k++)
		st32(out + 4u * k, w[k]);
}

/* Up to two blocks (all of them when nblocks is 1; a missing second block is zeros) into the planes, with the first round key added. */
WRI_AESCT_NOINLINE static void load_planes(uint32_t *q, const uint8_t *in, size_t nblocks, const uint32_t *rk)
{
	unsigned k, lim = nblocks >= 2u ? 8u : 4u; /* state words of this pass: public */

	for (k = 0; k < 8u; k++)
		q[k] = k < lim ? ld32(in + 4u * k) : 0u;
	ortho(q);
	for (k = 0; k < 8u; k++)
		q[k] ^= rk[k];
}

/* The planes back to bytes, the zero block dropped; returns how many blocks (1 or 2) this pass held, so the caller needs no counter. */
WRI_AESCT_NOINLINE static size_t store_planes(uint8_t *out, uint32_t *q, size_t nblocks)
{
	unsigned k, nb = nblocks >= 2u ? 2u : 1u;

	ortho(q);
	for (k = 0; k < 4u * nb; k++)
		st32(out + 4u * k, q[k]);
	return nb;
}

/*
 * The cipher, two blocks per pass (a last odd block is padded with a zero block that is dropped on the way out). The caller holds only
 * the state and six loop values; the S-box, round tail and transposition calls follow one another (they are siblings), so the
 * deepest chain is this frame plus the larger of those: the eight state words and the circuit's temporaries.
 */
void wri_aesct_encrypt_blocks(const wri_aesct_ctx *c, const uint8_t *in, uint8_t *out, size_t nblocks)
{
	uint32_t q[8];
	const uint32_t *rk, *last;
	size_t nb;

	if (out == NULL || nblocks == 0u || nblocks > ((size_t)-1) / WRI_AESCT_BLOCK)
		return;
	if (!ctx_ok(c) || in == NULL) {
		WR_MEMSET(out, 0, nblocks * WRI_AESCT_BLOCK);
		return;
	}
	last = c->rk + 8u * c->rounds; /* the round key of the last round; the number of rounds is public */
	while (nblocks > 0u) {
		load_planes(q, in, nblocks, c->rk);
		for (rk = c->rk + 8; ; rk += 8) {
			sbox_planes(q);
			round_tail(q, rk, rk != last);
			if (rk == last)
				break;
		}
		nb = store_planes(out, q, nblocks);
		in += 16u * nb;
		out += 16u * nb;
		nblocks -= nb;
	}
	wri_secure_zero(q, sizeof(q));
}

/* Store the counter as its four big-endian bytes. */
static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

void wri_aesct_ctr32(const wri_aesct_ctx *c, uint8_t ctr[16], const uint8_t *in, uint8_t *out, size_t n)
{
	uint8_t cb[32]; /* two counter blocks, then the keystream in their place */
	uint32_t cnt;
	size_t take, i;

	if (out == NULL || n == 0u)
		return;
	if (ctr == NULL || !ctx_ok(c) || in == NULL) { /* fail closed: zeros, never the plain text (in place too), and the counter stays */
		WR_MEMSET(out, 0, n);
		return;
	}
	cnt = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16) | ((uint32_t)ctr[14] << 8) | (uint32_t)ctr[15];
	while (n > 0u) {
		WR_MEMCPY(cb, ctr, 12); /* the previous chunk's keystream replaced the blocks */
		WR_MEMCPY(cb + 16, ctr, 12);
		put_be32(cb + 12, cnt);
		put_be32(cb + 28, cnt + 1u); /* modulo 2^32: no carry into the nonce */
		take = n < 32u ? n : 32u; /* public */
		wri_aesct_encrypt_blocks(c, cb, cb, take > 16u ? 2u : 1u);
		for (i = 0; i < take; i++)
			out[i] = (uint8_t)(in[i] ^ cb[i]);
		cnt += (uint32_t)((take + 15u) / 16u);
		in += take;
		out += take;
		n -= take;
	}
	put_be32(ctr + 12, cnt);
	wri_secure_zero(cb, sizeof(cb));
}

void wri_aesct_wipe(wri_aesct_ctx *c)
{
	if (c != NULL)
		wri_secure_zero(c, sizeof(*c));
}
