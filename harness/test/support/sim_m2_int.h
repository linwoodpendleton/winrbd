/* SPDX-License-Identifier: MIT */
/*
 * sim_m2_int.h - internals shared by the files of the msgr2 test server (sim_m2.c: queue, frames,
 * pump and public API; sim_m2_hs.c: handshake handlers and the scripted auth callbacks;
 * sim_m2_sess.c: frame dispatch and the session handlers). Not for tests.
 */
#ifndef SIM_M2_INT_H
#define SIM_M2_INT_H

#include <stdlib.h>
#include <string.h>

#include "sim_m2.h"
#include "wri_le.h"

/* ---- readers and writers -------------------------------------------------------------------- */

typedef struct sr {
	const uint8_t *p;
	size_t n, pos;
	int bad;
} sr;

WR_INLINE const uint8_t *sr_take(sr *r, size_t k)
{
	const uint8_t *q;

	if (r->bad || k > r->n - r->pos) {
		r->bad = 1;
		return NULL;
	}
	q = r->p + r->pos;
	r->pos += k;
	return q;
}

WR_INLINE uint8_t sr_u8(sr *r)
{
	const uint8_t *q = sr_take(r, 1);
	return q != NULL ? q[0] : 0;
}

WR_INLINE uint32_t sr_u32(sr *r)
{
	const uint8_t *q = sr_take(r, 4);
	return q != NULL ? wri_le32_get(q) : 0;
}

WR_INLINE uint64_t sr_u64(sr *r)
{
	const uint8_t *q = sr_take(r, 8);
	return q != NULL ? wri_le64_get(q) : 0;
}

/* One entity_addr_t in the marker-1 form: returns its bytes (marker included) and length. */
WR_INLINE const uint8_t *sr_addr(sr *r, uint32_t *len)
{
	size_t start = r->pos;
	const uint8_t *q = sr_take(r, 7);
	uint32_t sl;

	if (q == NULL)
		return NULL;
	sl = wri_le32_get(q + 3);
	/* marker 1, struct_compat <= 1 (the decoder's limit), the struct holds type + nonce + elen (12 bytes)
	 * and then exactly elen sockaddr bytes, at most 28 */
	if (q[0] != 1 || q[2] > 1 || sl < 12 || sl > SIM_M2_ADDR_MAX - 7u || sr_take(r, sl) == NULL) {
		r->bad = 1;
		return NULL;
	}
	{
		uint32_t elen = wri_le32_get(r->p + start + 15);

		if (elen > 28u || elen != sl - 12u) {
			r->bad = 1;
			return NULL;
		}
	}
	*len = 7u + sl;
	return r->p + start;
}

typedef struct sw {
	uint8_t *p;
	size_t cap, n;
	int bad;
} sw;

WR_INLINE uint8_t *sw_take(sw *w, size_t k)
{
	uint8_t *q;

	if (w->bad || k > w->cap - w->n) {
		w->bad = 1;
		return NULL;
	}
	q = w->p + w->n;
	w->n += k;
	return q;
}

WR_INLINE void sw_bytes(sw *w, const void *src, size_t k)
{
	uint8_t *q = sw_take(w, k);

	if (q != NULL && k != 0)
		memcpy(q, src, k);
}

WR_INLINE void sw_u8(sw *w, uint8_t v) { sw_bytes(w, &v, 1); }

WR_INLINE void sw_u32(sw *w, uint32_t v)
{
	uint8_t *q = sw_take(w, 4);

	if (q != NULL)
		wri_le32_put(q, v);
}

WR_INLINE void sw_u64(sw *w, uint64_t v)
{
	uint8_t *q = sw_take(w, 8);

	if (q != NULL)
		wri_le64_put(q, v);
}

WR_INLINE void sw_blob(sw *w, const uint8_t *p, uint32_t n)
{
	sw_u32(w, n);
	sw_bytes(w, p, n);
}

WR_INLINE void sw_list(sw *w, const uint32_t *v, uint32_t n)
{
	uint32_t i;

	sw_u32(w, n);
	for (i = 0; i < n; i++)
		sw_u32(w, v[i]);
}

/* Move on unless the handler's own send already killed the connection. */
WR_INLINE void sim_m2_next_state(sim_m2 *s, uint8_t st)
{
	if (s->state != SIM_M2_ST_DEAD)
		s->state = st;
}

/* The connection ends: first failure wins; the server closes once its queued output is drained. */
void sim_m2_die(sim_m2 *s, wr_status st, const char *what, uint64_t a0, uint64_t a1);
/* A writer over the scratch buffer (ctl_cap bytes) and the send of what was built, as one segment 0. */
sw sim_m2_ctl_writer(sim_m2 *s);
void sim_m2_emit_ctl(sim_m2 *s, uint8_t tag, const sw *w);
/* Handshake states (HELLO .. IDENT): handle the frame, or return 0 if its tag is not valid now. */
int sim_m2_hs_frame(sim_m2 *s, uint8_t tag, const uint8_t *p, size_t n);
/* A complete, verified frame arrived: bookkeeping and dispatch by state. */
void sim_m2_on_frame(sim_m2 *s);

#endif /* SIM_M2_INT_H */
