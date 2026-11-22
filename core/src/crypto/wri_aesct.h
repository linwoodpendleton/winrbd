/* SPDX-License-Identifier: MIT */
/*
 * wri_aesct.h - AES-128 and AES-256, ENCRYPT direction only, constant time. Docs: docs/design/core-architecture.md 35.1.
 *
 * Constant-time argument. The cipher is a bitsliced Boolean circuit over 32-bit words: the 32 state bytes of two blocks are held as
 * eight bit planes, SubBytes is a fixed list of XOR / AND / NOT gates on those planes (the 113-gate S-box circuit of Boyar and
 * Peralta), ShiftRows and MixColumns are masks, constant shifts, constant rotations and XORs, AddRoundKey an XOR. The key schedule
 * uses the same S-box circuit. Consequently:
 *   - no memory access has an address that depends on a key or data byte: there is no S-box table, no round table, no lookup of
 *     any kind (the object code has no read-only data but the 16-byte mask constants that a compiler's vectoriser builds from
 *     the bit masks of the transposition and of ShiftRows: 0 to 144 bytes in total with gcc 13 and clang 18, -O0 to -O3 and -Os);
 *   - no branch, loop bound or shift amount depends on a key or data byte: every branch and loop depends on the key length, the
 *     round count, the number of blocks or bytes and the loop indices, which are public;
 *   - no variable-time instruction is used: the operations are word XOR, AND, NOT, constant shifts and constant rotations, and
 *     additions and shifts on public values (counters, lengths, Rcon).
 * Only the key length (16 or 32), the number of blocks or bytes and the addresses of the buffers are public. What the argument
 * cannot cover is a compiler that turns the circuit into something else; the Valgrind and object-code checks of design 35.6 are
 * the guard for that. The state words and the unpacked key material kept in arrays are wiped before the functions return. What
 * portable C cannot wipe is a scalar that the compiler keeps in a register or spills to the frame of the S-box or of the key
 * schedule (a round-state word, a schedule word): those frames are dead stack after the return and are not scrubbed. A host that
 * defends against reads of stale stack scrubs the stack of the thread that ran the cipher.
 *
 * Sources (the circuit is typed in from the papers, the rest written from FIPS 197; no code of any library):
 *   J. Boyar, R. Peralta, "A new combinational logic minimization technique with applications to cryptology", SEA 2010
 *     (the 113-gate, 32-AND S-box circuit used here), and "A small depth-16 circuit for the AES S-box", IFIP SEC 2012;
 *   FIPS 197 (the cipher and the key expansion); the bit layout of the planes is described at the top of wri_aesct.c.
 *
 * Why encrypt only: GCM and CTR use the forward cipher in both directions. The table-driven wri_aes.c (cephx CBC and CTS,
 * which also needs the inverse cipher) stays as it is; it is NOT constant time, see 35.5 of the design for what that leaves.
 *
 * The context holds a secret key schedule: the owner wipes it (wri_aesct_wipe) when done. No heap, no globals.
 */
#ifndef WRI_AESCT_H
#define WRI_AESCT_H

#include "wr_err.h"
#include "wr_port.h"

#define WRI_AESCT_BLOCK 16u

typedef struct wri_aesct_ctx {
	uint32_t rk[120];  /* the key schedule in bit-plane form: 8 words per round key (two identical blocks), 11 or 15 round keys */
	uint32_t rounds;   /* 10 (AES-128) or 14 (AES-256); 0 = no key */
} wri_aesct_ctx;

/* klen 16 or 32; WR_E_CRYPTO_KEY otherwise (24-byte keys are refused: nothing here needs them); a NULL key of a valid length is
 * WR_E_INVAL, as in wri_aes_setkey. A failed call leaves a context that encrypts to 16 zero bytes per block (and whose ctr32 output
 * is zeros), never garbage derived from an uninitialised schedule and never the plain text. */
WR_MUST_CHECK wr_status wri_aesct_setkey(wri_aesct_ctx *c, const uint8_t *key, size_t klen);

/* ECB over nblocks 16-byte blocks; in == out allowed, partial overlap is not. An unkeyed or failed context writes zeros. */
void wri_aesct_encrypt_blocks(const wri_aesct_ctx *c, const uint8_t *in, uint8_t *out, size_t nblocks);

/*
 * Counter mode as GCM uses it: ctr is the next counter block; the last four bytes are a big-endian 32-bit counter that wraps
 * modulo 2^32 without carrying into the other twelve. out = in XOR keystream over n bytes (n any value; a final partial block
 * uses the first n % 16 bytes of its keystream block and still consumes that counter value), and ctr is advanced by
 * ceil(n / 16). in == out allowed. The wrap is the GCM counter's: a call, or a series of calls with the same key and counter
 * prefix, that runs through more than 2^32 blocks repeats keystream, so the caller bounds the message (GCM: 2^36 - 32 bytes). The
 * number of keystream blocks (not their values) depends on n, which is public. An unkeyed or failed context, a NULL ctr or a NULL
 * in writes n zero bytes (never the plain text, in place or not) and leaves ctr alone.
 */
void wri_aesct_ctr32(const wri_aesct_ctx *c, uint8_t ctr[16], const uint8_t *in, uint8_t *out, size_t n);

/*
 * Test hook: the S-box circuit on 32 bytes (SubBytes of two blocks without the rest of the round), in[] -> out[], in place allowed.
 * The tests compare all 256 outputs with the table of wri_aes.c through it. Public data only; nothing else calls it.
 */
void wri_aesct_sbox32(const uint8_t in[32], uint8_t out[32]);

/* Erase the schedule (volatile-safe, wri_secure_zero). */
void wri_aesct_wipe(wri_aesct_ctx *c);

#endif /* WRI_AESCT_H */
