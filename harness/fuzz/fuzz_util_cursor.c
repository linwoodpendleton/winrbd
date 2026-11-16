/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the cursors (core/src/util/wri_cursor.c).
 *
 * The input is a small program followed by a payload:
 *
 *   byte 0          length L of the program (clamped to the input size - 1)
 *   bytes 1 .. L    the program; its first byte is the writer capacity (0 .. 255)
 *   the rest        the payload, which the reader walks over
 *
 * Every program step (one op byte plus up to two argument bytes) is executed on the real cursor
 * and on a trivial model kept next to it; after each step the two must agree. The payload and the
 * output buffer are heap allocations of exactly the right size, so under ASan any read or write
 * outside them is reported; without ASan a canary behind the output buffer catches overruns.
 * A property violation traps.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_cursor.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define CANARY 16u
#define OUT_MAX 256u

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

/* Reader model: position and sticky error, over the same payload. */
struct rmodel {
	size_t len, pos;
	int err; /* 0 none, otherwise the expected wr_status */
};

static uint64_t model_le(const uint8_t *p, unsigned n)
{
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < n; i++)
		v |= (uint64_t)p[i] << (8 * i);
	return v;
}

/* Expected result of reading n bytes: returns 1 if it succeeds and advances the model. */
static int rmodel_take(struct rmodel *m, size_t n)
{
	if (m->err)
		return 0;
	if (n > m->len - m->pos) {
		m->err = WR_E_TRUNCATED;
		return 0;
	}
	m->pos += n;
	return 1;
}

static void check_reader(const wri_rd *r, const struct rmodel *m)
{
	check(r->pos == m->pos);
	check(r->err == (m->err ? m->err : WR_OK));
	check(r->pos <= r->len);
	check(wri_rd_left(r) == (m->err ? 0 : m->len - m->pos));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const uint8_t *prog, *payload_in;
	uint8_t *payload = NULL, *out = NULL;
	uint8_t shadow[OUT_MAX];
	size_t plen, proglen, ip, cap, pay_len;
	wri_rd r, sub;
	wri_wr w;
	struct rmodel rm, sm;
	size_t wpos = 0;
	int werr = 0;
	int have_sub = 0;
	unsigned steps = 0;
	size_t i;

	if (size < 2)
		return 0;
	proglen = data[0];
	if (proglen > size - 1)
		proglen = size - 1;
	prog = data + 1;
	payload_in = prog + proglen;
	pay_len = size - 1 - proglen;
	if (proglen == 0)
		return 0;

	cap = prog[0]; /* writer capacity 0 .. 255 */
	ip = 1;

	/* exact-size copies so out-of-bounds access is detectable */
	plen = pay_len;
	if (plen > 0) {
		payload = (uint8_t *)malloc(plen);
		if (!payload)
			return 0;
		memcpy(payload, payload_in, plen);
	}
	out = (uint8_t *)malloc(cap + CANARY);
	if (!out) {
		free(payload);
		return 0;
	}
	memset(out, 0xC5, cap + CANARY);
	memset(shadow, 0xC5, sizeof(shadow));

	wri_rd_init(&r, payload, plen);
	wri_wr_init(&w, cap ? out : NULL, cap);
	rm.len = plen;
	rm.pos = 0;
	rm.err = 0;
	sm.len = sm.pos = 0;
	sm.err = 0;
	check_reader(&r, &rm);

	while (ip < proglen && steps++ < 512) {
		uint8_t op = prog[ip++];
		unsigned a1 = ip < proglen ? prog[ip] : 0;
		unsigned a2 = ip + 1 < proglen ? prog[ip + 1] : 0;
		const uint8_t *base = payload;

		switch (op & 15u) {
		case 0: { /* reads of each width on the parent */
			unsigned width = 1u << (a1 & 3u);
			uint64_t got = 0, want = 0;
			size_t before = rm.pos;

			ip += 1;
			switch (width) {
			case 1: got = wri_rd_u8(&r); break;
			case 2: got = wri_rd_u16(&r); break;
			case 4: got = (a1 & 4u) ? (uint32_t)wri_rd_i32(&r) : wri_rd_u32(&r); break;
			default: got = (a1 & 4u) ? (uint64_t)wri_rd_i64(&r) : wri_rd_u64(&r); break;
			}
			if (rmodel_take(&rm, width))
				want = model_le(base + before, width);
			check(got == want);
			check_reader(&r, &rm);
			break;
		}
		case 1: { /* bytes / skip */
			size_t n = a1 * 3u + a2 % 3u;
			size_t before = rm.pos;
			const uint8_t *q;

			ip += 2;
			if (a2 & 1u) {
				q = wri_rd_bytes(&r, n);
				if (rmodel_take(&rm, n)) {
					check(n == 0 ? 1 : q == base + before);
				} else {
					check(q == NULL);
				}
			} else {
				wri_rd_skip(&r, n);
				(void)rmodel_take(&rm, n);
			}
			check_reader(&r, &rm);
			break;
		}
		case 2: { /* copy into a small stack buffer; on failure it must be zeroed */
			uint8_t dst[64];
			size_t n = a1 % 65u;
			size_t before = rm.pos;
			int ok;

			ip += 1;
			memset(dst, 0x77, sizeof(dst));
			wri_rd_copy(&r, dst, n);
			ok = rmodel_take(&rm, n);
			for (i = 0; i < n; i++)
				check(dst[i] == (ok ? base[before + i] : 0));
			for (i = n; i < sizeof(dst); i++)
				check(dst[i] == 0x77);
			check_reader(&r, &rm);
			break;
		}
		case 3: { /* open a sub-reader (replaces the previous one) */
			size_t n = a1 + (a2 & 1u ? 256u * a2 : 0u);
			size_t before = rm.pos;
			int ok;

			ip += 2;
			sub = wri_rd_sub(&r, n);
			ok = rmodel_take(&rm, n);
			check_reader(&r, &rm);
			if (ok) {
				check(sub.err == WR_OK && sub.len == n && sub.pos == 0);
				check(n == 0 || sub.p == base + before);
				sm.len = n;
				sm.pos = 0;
				sm.err = 0;
			} else {
				check(sub.err == r.err && sub.len == 0);
				sm.len = 0;
				sm.pos = 0;
				sm.err = rm.err;
			}
			have_sub = 1;
			check_reader(&sub, &sm);
			break;
		}
		case 4: { /* read from the sub-reader: it must never see past its window */
			uint32_t got;
			uint64_t want = 0;

			if (!have_sub)
				break;
			got = wri_rd_u32(&sub);
			if (rmodel_take(&sm, 4))
				want = model_le(sub.p + sm.pos - 4, 4);
			check(got == want);
			check_reader(&sub, &sm);
			check_reader(&r, &rm); /* the parent is not affected */
			break;
		}
		case 5: { /* count */
			uint32_t max = a1 * 17u;
			size_t emin = a2 % 5u;
			size_t before = rm.pos;
			uint32_t got = wri_rd_count(&r, max, emin);
			uint64_t want = 0;

			ip += 2;
			if (rmodel_take(&rm, 4)) {
				uint64_t c = model_le(base + before, 4);

				if (c > max || (emin != 0 && c > (rm.len - rm.pos) / emin)) {
					rm.err = WR_E_TOOBIG;
				} else {
					want = c;
				}
			}
			check(got == want);
			check_reader(&r, &rm);
			break;
		}
		case 6: { /* fail */
			ip += 1;
			wri_rd_fail(&r, a1 & 1u ? WR_E_ENCODING : WR_E_RANGE);
			if (!rm.err)
				rm.err = (a1 & 1u) ? WR_E_ENCODING : WR_E_RANGE;
			check_reader(&r, &rm);
			break;
		}
		case 7: { /* nested sub-reader of the sub-reader */
			wri_rd inner;
			size_t n = a1 % 33u;
			size_t before = sm.pos;
			int ok;

			if (!have_sub)
				break;
			ip += 1;
			inner = wri_rd_sub(&sub, n);
			ok = rmodel_take(&sm, n);
			check_reader(&sub, &sm);
			if (ok) {
				check(inner.err == WR_OK && inner.len == n);
				check(n == 0 || inner.p == sub.p + before);
			} else {
				check(inner.err != WR_OK && inner.len == 0);
			}
			break;
		}
		case 8: { /* writer: scalar of each width */
			unsigned width = 1u << (a1 & 3u);
			uint64_t v = (uint64_t)a2 * 0x0101010101010101ull + a1;

			ip += 2;
			switch (width) {
			case 1: wri_wr_u8(&w, (uint8_t)v); break;
			case 2: wri_wr_u16(&w, (uint16_t)v); break;
			case 4: wri_wr_u32(&w, (uint32_t)v); break;
			default: wri_wr_u64(&w, v); break;
			}
			if (!werr) {
				if (width > cap - wpos) {
					werr = WR_E_TOOBIG;
				} else {
					for (i = 0; i < width; i++)
						shadow[wpos + i] = (uint8_t)(v >> (8 * i));
					wpos += width;
				}
			}
			break;
		}
		case 9: { /* writer: bytes from the payload, possibly overlapping nothing */
			size_t n = a1 % 70u;
			size_t off = a2 % 8u;

			ip += 2;
			if (plen == 0)
				break;
			if (off + n > plen)
				n = plen > off ? plen - off : 0;
			wri_wr_bytes(&w, base + off, n);
			if (!werr && n != 0) {
				if (n > cap - wpos) {
					werr = WR_E_TOOBIG;
				} else {
					memcpy(shadow + wpos, base + off, n);
					wpos += n;
				}
			}
			break;
		}
		case 10: { /* writer: zero fill */
			size_t n = a1 % 70u;

			ip += 1;
			wri_wr_zero(&w, n);
			if (!werr && n != 0) {
				if (n > cap - wpos) {
					werr = WR_E_TOOBIG;
				} else {
					memset(shadow + wpos, 0, n);
					wpos += n;
				}
			}
			break;
		}
		case 11: { /* writer: reserve and fill */
			size_t n = a1 % 70u;
			uint8_t *q;

			ip += 1;
			q = wri_wr_reserve(&w, n);
			if (!werr) {
				if (n > cap - wpos) {
					werr = WR_E_TOOBIG;
					check(q == NULL);
				} else {
					if (n != 0)
						check(q == out + wpos);
					for (i = 0; i < n; i++) {
						q[i] = (uint8_t)(a2 + i);
						shadow[wpos + i] = (uint8_t)(a2 + i);
					}
					wpos += n;
				}
			} else {
				check(q == NULL);
			}
			break;
		}
		case 12: { /* writer: back-patch */
			size_t at = a1 % 40u;

			ip += 2;
			wri_wr_patch_u32(&w, at, 0x0A0B0C0Du + a2);
			if (!werr) {
				if (at > wpos || wpos - at < 4) {
					werr = WR_E_RANGE;
				} else {
					uint32_t v = 0x0A0B0C0Du + a2;

					for (i = 0; i < 4; i++)
						shadow[at + i] = (uint8_t)(v >> (8 * i));
				}
			}
			break;
		}
		case 13: { /* writer: a wild offset, near the wrap */
			size_t at = (size_t)0 - 1u - (a1 & 7u);

			ip += 1;
			wri_wr_patch_u32(&w, at, 1);
			if (!werr)
				werr = WR_E_RANGE;
			break;
		}
		case 14: { /* writer: a huge request must be refused, not wrapped */
			size_t n = (size_t)0 - 1u - (a1 & 7u);

			ip += 1;
			wri_wr_zero(&w, n);
			if (!werr)
				werr = WR_E_TOOBIG;
			break;
		}
		default:
			break;
		}

		/* writer invariants after every step */
		check(w.pos == wpos);
		check(w.pos <= cap);
		check(w.err == (werr ? werr : WR_OK));
		check(wri_wr_left(&w) == (werr ? 0 : cap - wpos));
		for (i = 0; i < CANARY; i++)
			check(out[cap + i] == 0xC5);
		for (i = wpos; i < cap; i++)
			check(out[i] == 0xC5); /* nothing written beyond pos */
	}

	/* the bytes written must be exactly what the model says */
	check(cap == 0 || memcmp(out, shadow, wpos) == 0);

	free(out);
	free(payload);
	return 0;
}
