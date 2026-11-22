/* SPDX-License-Identifier: MIT */
/*
 * fuzz_gcm - random operation scripts against the streaming AES-GCM (wri_gcm) and its dispatcher (wri_pgcm, portable path), checked
 * step by step against a model that is built on the independent reference (harness/test/support/ref_gcm.c).
 *
 * Input: byte 0 bit 0 = AES-256 (wri_gcm only), bit 1 = drive the dispatcher instead of wri_gcm; 32 key bytes; then a script of
 * operations, each one an opcode byte (low 3 bits; bit 3 a flag) and its operand bytes:
 *   0 start       12 IV bytes; flag = decrypt
 *   1 aad         length byte, then that many bytes (wri_gcm only; the dispatcher has no additional data)
 *   2 update      two length bytes (n = value mod 1100, so 0 .. 1099) and the content seed; flag = in place
 *   3 final       one byte: bit 7 = the final of the other direction, bit 6 = which one when nothing runs, bits 0..3 and 4..6 pick the
 *                bit of the tag to damage when flag is set (a decrypt then must say WR_E_CRYPTO_MAC)
 *   4 setkey      one byte: key size choice (wri_gcm), new key from the seed bytes
 *   5 wipe        the object is wiped (unkeyed afterwards)
 *   6 bad start   a start with an IV length that is not 12 (wri_gcm) / a NULL iv (dispatcher)
 *   7 bad args    one byte picks: NULL input, NULL output, NULL tag, NULL additional data (each with a length above 0)
 * Whatever the script does, the model says what status each call returns (every refusal inside an operation ends the operation), the
 * bytes written are the keystream XOR, the tag the reference GHASH, and a decrypt with a damaged tag is WR_E_CRYPTO_MAC. The run
 * ends with a wipe and the check that the whole object is zero. Total data per run is capped so a run stays fast.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ref_gcm.h"
#include "wri_gcm.h"
#include "wri_pgcm.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAXDATA 6000u
#define MAXAAD 2000u

#define CHECK(c)                                                                                  \
	do {                                                                                      \
		if (!(c)) {                                                                       \
			fprintf(stderr, "fuzz_gcm: model mismatch at %s:%d: %s\n", __FILE__, __LINE__, #c); \
			__builtin_trap();                                                         \
		}                                                                                 \
	} while (0)

enum { M_NOKEY = 0, M_IDLE, M_AAD, M_DATA };

typedef struct model {
	int state;
	int dir;
	uint8_t iv[12];
	ref_gcm_key key;
	uint8_t aad[MAXAAD];
	size_t aadn;
	uint8_t ct[MAXDATA]; /* the ciphertext so far (the input of a decrypt, the output of an encrypt) */
	size_t ctn;
} model;

static void ks_block(const model *m, size_t blk, uint8_t out[16])
{
	uint8_t cb[16];
	uint32_t ctr = (uint32_t)blk + 2u;

	memcpy(cb, m->iv, 12);
	cb[12] = (uint8_t)(ctr >> 24);
	cb[13] = (uint8_t)(ctr >> 16);
	cb[14] = (uint8_t)(ctr >> 8);
	cb[15] = (uint8_t)ctr;
	ref_aes_encrypt_block(&m->key.aes, cb, out);
}

static void model_tag(const model *m, uint8_t tag[16])
{
	uint8_t j0[16], e[16], g[16];
	size_t i;

	memcpy(j0, m->iv, 12);
	j0[12] = 0;
	j0[13] = 0;
	j0[14] = 0;
	j0[15] = 1;
	ref_aes_encrypt_block(&m->key.aes, j0, e);
	ref_ghash(m->key.h, m->aad, m->aadn, m->ct, m->ctn, g);
	for (i = 0; i < 16u; i++)
		tag[i] = (uint8_t)(g[i] ^ e[i]);
}

typedef struct cursor {
	const uint8_t *p;
	size_t n;
	size_t pos;
} cursor;

static int cur_u8(cursor *c, uint8_t *v)
{
	if (c->pos >= c->n)
		return 0;
	*v = c->p[c->pos++];
	return 1;
}

static int cur_bytes(cursor *c, uint8_t *out, size_t n)
{
	if (c->n - c->pos < n)
		return 0;
	memcpy(out, c->p + c->pos, n);
	c->pos += n;
	return 1;
}

/* Content bytes from a seed: cheap, deterministic, not a security primitive. */
static void fill_seed(uint8_t *out, size_t n, uint32_t seed)
{
	size_t i;

	for (i = 0; i < n; i++) {
		seed = seed * 1664525u + 1013904223u;
		out[i] = (uint8_t)(seed >> 24);
	}
}

static int all_zero(const void *p, size_t n)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != 0)
			return 0;
	return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static model m;
	static uint8_t in[MAXDATA + 16], out[MAXDATA + 16], buf[MAXDATA + 16];
	wri_gcm g;
	wri_pgcm pg;
	cursor c;
	uint8_t flags, key[32], op, sel, tag[16], want[16];
	size_t klen, total = 0;
	const int use_pg = (size >= 1u) && ((data[0] & 2u) != 0u);

	if (size < 1u + 32u)
		return 0;
	flags = data[0];
	memcpy(key, data + 1, 32);
	c.p = data;
	c.n = size;
	c.pos = 33;
	klen = (use_pg || (flags & 1u) == 0u) ? 16u : 32u;

	memset(&m, 0, sizeof(m));
	memset(&g, 0, sizeof(g));
	memset(&pg, 0, sizeof(pg));
	if (use_pg)
		CHECK(wri_pgcm_setkey(&pg, NULL, key) == WR_OK);
	else
		CHECK(wri_gcm_setkey(&g, key, klen) == WR_OK);
	CHECK(ref_gcm_setkey(&m.key, key, klen) == 0);
	m.state = M_IDLE;

	while (cur_u8(&c, &op)) {
		const int flag = (op & 8u) != 0u;
		wr_status st;

		switch (op & 7u) {
		case 0: { /* start */
			uint8_t iv[12];

			if (!cur_bytes(&c, iv, 12))
				goto done;
			st = use_pg ? wri_pgcm_start(&pg, iv, flag) : wri_gcm_start(&g, iv, 12, flag);
			if (m.state == M_NOKEY) {
				CHECK(st == WR_E_STATE);
			} else {
				CHECK(st == WR_OK);
				memcpy(m.iv, iv, 12);
				m.dir = flag;
				m.aadn = 0;
				m.ctn = 0;
				m.state = M_AAD;
			}
			break;
		}
		case 1: { /* aad */
			uint8_t l;
			uint8_t a[255];

			if (use_pg)
				break;
			if (!cur_u8(&c, &l) || !cur_bytes(&c, a, (size_t)l))
				goto done;
			if (m.aadn + l > MAXAAD)
				break;
			st = wri_gcm_aad(&g, a, l);
			if (m.state != M_AAD) {
				CHECK(st == WR_E_STATE);
				if (m.state != M_NOKEY)
					m.state = M_IDLE;
			} else {
				CHECK(st == WR_OK);
				memcpy(m.aad + m.aadn, a, l);
				m.aadn += l;
			}
			break;
		}
		case 2: { /* update */
			uint8_t lo, hi, s0, s1;
			size_t n, i;

			if (!cur_u8(&c, &lo) || !cur_u8(&c, &hi) || !cur_u8(&c, &s0) || !cur_u8(&c, &s1))
				goto done;
			n = ((size_t)lo | ((size_t)hi << 8)) % 1100u;
			if (total + n > MAXDATA)
				break;
			fill_seed(in, n, (uint32_t)s0 | ((uint32_t)s1 << 8));
			memcpy(buf, in, n);
			memset(out, 0xee, sizeof(out));
			if (flag)
				st = use_pg ? wri_pgcm_update(&pg, buf, buf, n) : wri_gcm_update(&g, buf, buf, n);
			else
				st = use_pg ? wri_pgcm_update(&pg, in, out, n) : wri_gcm_update(&g, in, out, n);
			if (m.state != M_AAD && m.state != M_DATA) {
				CHECK(st == WR_E_STATE);
				if (m.state != M_NOKEY)
					m.state = M_IDLE;
			} else if (use_pg && (n & 15u) != 0u) {
				CHECK(st == WR_E_CRYPTO_LEN);
				CHECK(flag || out[0] == 0xee); /* nothing written */
				m.state = M_IDLE;
			} else {
				const uint8_t *o = flag ? buf : out;

				CHECK(st == WR_OK);
				if (n != 0u) {
					uint8_t k[16];
					size_t last = (size_t)-1;

					m.state = M_DATA;
					for (i = 0; i < n; i++) {
						size_t pos = m.ctn + i;

						if (pos / 16u != last) {
							ks_block(&m, pos / 16u, k);
							last = pos / 16u;
						}
						CHECK(o[i] == (uint8_t)(in[i] ^ k[pos % 16u]));
						m.ct[pos] = m.dir ? in[i] : o[i];
					}
					m.ctn += n;
					total += n;
				}
				if (!flag)
					CHECK(out[n] == 0xee); /* nothing past the end */
			}
			break;
		}
		case 3: { /* final */
			uint8_t pick, t2[16];
			const int running = (m.state == M_AAD || m.state == M_DATA);
			int call_dec;

			if (!cur_u8(&c, &pick))
				goto done;
			/* the final of the running operation's direction, or (bit 7) the other one; with nothing running, bit 6 picks */
			call_dec = running ? (m.dir ^ ((pick & 0x80u) != 0u)) : ((pick & 0x40u) != 0u);
			memset(tag, 0xee, sizeof(tag));
			memset(want, 0, sizeof(want));
			if (running)
				model_tag(&m, want);
			if (call_dec) {
				memcpy(t2, want, 16);
				if (flag)
					t2[pick & 15u] ^= (uint8_t)(1u << ((pick >> 4) & 7u));
				st = use_pg ? wri_pgcm_final_dec(&pg, t2) : wri_gcm_final_dec(&g, t2);
				if (running && m.dir == 1)
					CHECK(st == (flag ? WR_E_CRYPTO_MAC : WR_OK));
				else
					CHECK(st == WR_E_STATE);
			} else {
				st = use_pg ? wri_pgcm_final_enc(&pg, tag) : wri_gcm_final_enc(&g, tag);
				if (running && m.dir == 0) {
					CHECK(st == WR_OK);
					CHECK(memcmp(tag, want, 16) == 0);
				} else {
					CHECK(st == WR_E_STATE);
					CHECK(all_zero(tag, 16));
				}
			}
			if (m.state != M_NOKEY)
				m.state = M_IDLE;
			break;
		}
		case 4: { /* setkey */
			uint8_t kb, nk[32];

			if (!cur_u8(&c, &kb))
				goto done;
			fill_seed(nk, 32, kb);
			if (use_pg) {
				CHECK(wri_pgcm_setkey(&pg, NULL, nk) == WR_OK);
				klen = 16u;
			} else {
				klen = (kb & 1u) ? 32u : 16u;
				CHECK(wri_gcm_setkey(&g, nk, klen) == WR_OK);
			}
			CHECK(ref_gcm_setkey(&m.key, nk, klen) == 0);
			m.state = M_IDLE;
			break;
		}
		case 5: /* wipe */
			if (use_pg) {
				wri_pgcm_wipe(&pg);
				CHECK(all_zero(&pg, sizeof(pg)));
			} else {
				wri_gcm_wipe(&g);
				CHECK(all_zero(&g, sizeof(g)));
			}
			m.state = M_NOKEY;
			break;
		case 6: { /* a start that is refused for its arguments */
			uint8_t iv[16];

			memset(iv, 1, sizeof(iv));
			if (!cur_u8(&c, &sel))
				goto done;
			if (use_pg) {
				st = wri_pgcm_start(&pg, NULL, flag);
				CHECK(st == (m.state == M_NOKEY ? WR_E_STATE : WR_E_INVAL));
			} else {
				size_t ivlen = (size_t)sel;

				if (ivlen == 12u)
					ivlen = 13u;
				st = wri_gcm_start(&g, iv, ivlen, flag);
				CHECK(st == (m.state == M_NOKEY ? WR_E_STATE : WR_E_CRYPTO_LEN));
			}
			if (m.state != M_NOKEY)
				m.state = M_IDLE; /* a refused start also ends a running operation */
			break;
		}
		default: { /* 7: NULL arguments with a length above 0 */
			static const uint8_t one[16] = {0};
			uint8_t o16[16];

			if (!cur_u8(&c, &sel))
				goto done;
			memset(tag, 0xee, sizeof(tag));
			switch (sel & 3u) {
			case 0: /* NULL input */
				st = use_pg ? wri_pgcm_update(&pg, NULL, o16, 16) : wri_gcm_update(&g, NULL, o16, 16);
				if (m.state == M_AAD || m.state == M_DATA) {
					CHECK(st == WR_E_INVAL);
					m.state = M_IDLE;
				} else {
					CHECK(st == WR_E_STATE);
				}
				break;
			case 1: /* NULL output */
				st = use_pg ? wri_pgcm_update(&pg, one, NULL, 16) : wri_gcm_update(&g, one, NULL, 16);
				if (m.state == M_AAD || m.state == M_DATA) {
					CHECK(st == WR_E_INVAL);
					m.state = M_IDLE;
				} else {
					CHECK(st == WR_E_STATE);
				}
				break;
			case 2: /* NULL tag */
				if (m.dir == 0) {
					st = use_pg ? wri_pgcm_final_enc(&pg, NULL) : wri_gcm_final_enc(&g, NULL);
				} else {
					st = use_pg ? wri_pgcm_final_dec(&pg, NULL) : wri_gcm_final_dec(&g, NULL);
				}
				CHECK(st == WR_E_INVAL);
				if (m.state != M_NOKEY)
					m.state = M_IDLE;
				break;
			default: /* NULL additional data */
				if (use_pg)
					break;
				st = wri_gcm_aad(&g, NULL, 5);
				if (m.state == M_AAD) {
					CHECK(st == WR_E_INVAL);
					m.state = M_IDLE;
				} else {
					CHECK(st == WR_E_STATE);
					if (m.state != M_NOKEY)
						m.state = M_IDLE;
				}
				break;
			}
			break;
		}
		}
	}
done:
	if (use_pg) {
		wri_pgcm_wipe(&pg);
		CHECK(all_zero(&pg, sizeof(pg)));
	} else {
		wri_gcm_wipe(&g);
		CHECK(all_zero(&g, sizeof(g)));
	}
	return 0;
}
