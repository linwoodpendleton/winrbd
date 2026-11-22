/* SPDX-License-Identifier: MIT */
/*
 * sim_m2_sec.c - the secure-mode peer of the test servers: secret slicing, nonce streams, the frame encoder with its
 * deliberate defects, the frame decoder and the log of issued secrets. See sim_m2_sec.h. Written from
 * docs/spec/msgr2-secure-mode.md with ref_gcm; nothing from core/. Test code: libc allowed.
 */
#include <stdlib.h>
#include <string.h>

#include "sim_m2_sec.h"

/* ---- little endian helpers (own copies: nothing of the core is used here) ---------------------------------------------- */

static uint32_t ld32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t ld64(const uint8_t *p) { return (uint64_t)ld32(p) | (uint64_t)ld32(p + 4) << 32; }
static uint16_t ld16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }

static void st16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void st32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void st64(uint8_t *p, uint64_t v)
{
	st32(p, (uint32_t)v);
	st32(p + 4, (uint32_t)(v >> 32));
}

static uint64_t pad16(uint64_t x) { return (x + 15u) & ~(uint64_t)15u; }

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = (volatile uint8_t *)p;

	while (n-- > 0)
		*v++ = 0;
}

void sim_sec_wipe(void *p, size_t n)
{
	if (p != NULL)
		wipe(p, n);
}

/* ---- CRC-32C, bit by bit ---------------------------------------------------------------------------------------------- */

uint32_t sim_sec_crc32c(uint32_t crc, const uint8_t *p, size_t n)
{
	size_t i;
	int k;

	for (i = 0; i < n; i++) {
		crc ^= p[i];
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^ (0x82f63b78u & (0u - (crc & 1u)));
	}
	return crc;
}

/* ---- the secret and the streams ---------------------------------------------------------------------------------------- */

int sim_sec_slice(const uint8_t *secret, size_t n, uint8_t key[SIM_SEC_KEY], uint8_t seed_a[SIM_SEC_NONCE],
		  uint8_t seed_b[SIM_SEC_NONCE])
{
	if (secret == NULL || n < SIM_SEC_SECRET_MIN)
		return -1;
	if (key != NULL)
		memcpy(key, secret, SIM_SEC_KEY);
	if (seed_a != NULL)
		memcpy(seed_a, secret + 16, SIM_SEC_NONCE);
	if (seed_b != NULL)
		memcpy(seed_b, secret + 28, SIM_SEC_NONCE);
	return 0;
}

void sim_sec_nonce_step(uint8_t nonce[SIM_SEC_NONCE]) { st64(nonce + 4, ld64(nonce + 4) + 1u); }

void sim_sec_dir_init(sim_sec_dir *d, const uint8_t key[SIM_SEC_KEY], const uint8_t seed[SIM_SEC_NONCE])
{
	memset(d, 0, sizeof(*d));
	memcpy(d->key, key, SIM_SEC_KEY);
	memcpy(d->seed, seed, SIM_SEC_NONCE);
	memcpy(d->nonce, seed, SIM_SEC_NONCE);
	d->keyed = ref_gcm_setkey(&d->gk, key, SIM_SEC_KEY) == 0;
}

void sim_sec_dir_set_counter(sim_sec_dir *d, uint64_t ctr) { st64(d->nonce + 4, ctr); }
uint64_t sim_sec_dir_counter(const sim_sec_dir *d) { return ld64(d->nonce + 4); }

int sim_sec_ctx_init(sim_sec_ctx *c, const uint8_t *secret, size_t n, int server)
{
	uint8_t key[SIM_SEC_KEY], a[SIM_SEC_NONCE], b[SIM_SEC_NONCE];

	memset(c, 0, sizeof(*c));
	if (sim_sec_slice(secret, n, key, a, b) != 0)
		return -1;
	/* the client sends with seed B and reads with seed A; the server is the crossed side */
	sim_sec_dir_init(&c->tx, key, server ? a : b);
	sim_sec_dir_init(&c->rx, key, server ? b : a);
	wipe(key, sizeof(key));
	return 0;
}

void sim_sec_secret_set_counters(uint8_t *secret, size_t n, int set_a, uint64_t ctr_a, int set_b, uint64_t ctr_b)
{
	if (n < SIM_SEC_SECRET_MIN)
		return;
	if (set_a)
		st64(secret + 16 + 4, ctr_a);
	if (set_b)
		st64(secret + 28 + 4, ctr_b);
}

void sim_sec_ctx_wipe(sim_sec_ctx *c)
{
	ref_gcm_wipe(&c->tx.gk);
	ref_gcm_wipe(&c->rx.gk);
	wipe(c, sizeof(*c));
}

/* ---- the log of issued secrets ------------------------------------------------------------------------------------------ */

void sim_sec_log_add(sim_sec_log *l, const uint8_t *secret, size_t n)
{
	if (n > SIM_SEC_SECRET_MAX)
		n = SIM_SEC_SECRET_MAX;
	if (l->kept < SIM_SEC_LOG_MAX) {
		memcpy(l->secret[l->kept], secret, n);
		l->len[l->kept] = (uint32_t)n;
		l->kept++;
	}
	l->n++;
}

int sim_sec_log_distinct(const sim_sec_log *l)
{
	uint32_t i, j, k;

	for (i = 0; i < l->kept; i++) {
		int zero = 1;

		for (k = 0; k < l->len[i]; k++)
			if (l->secret[i][k] != 0)
				zero = 0;
		if (zero)
			return 0;
		for (j = i + 1; j < l->kept; j++)
			if (l->len[i] == l->len[j] && memcmp(l->secret[i], l->secret[j], l->len[i]) == 0)
				return 0;
	}
	return 1;
}

int sim_sec_log_has(const sim_sec_log *l, const uint8_t *secret, size_t n)
{
	uint32_t i;

	for (i = 0; i < l->kept; i++)
		if (l->len[i] == n && memcmp(l->secret[i], secret, n) == 0)
			return 1;
	return 0;
}

/* ---- the encoder --------------------------------------------------------------------------------------------------------- */

typedef struct shape {
	unsigned n, ops;
	uint32_t len[4];
	uint64_t pad[4];
	size_t part[3];
	size_t total;
} shape;

static const uint16_t k_align[4] = {8, 8, 8, 4096};

static int shape_of(const sim_sec_spec *f, int keep_tail, shape *s)
{
	unsigned i;
	uint64_t p3 = 0, total;

	memset(s, 0, sizeof(*s));
	if (f == NULL || f->nseg < 1u || f->nseg > SIM_SEC_MAX_SEG)
		return -1;
	s->n = f->nseg;
	for (i = 0; i < 4u; i++)
		s->len[i] = i < f->nseg ? f->len[i] : 0u;
	for (i = 0; i < s->n; i++)
		if (s->len[i] != 0 && f->seg[i] == NULL)
			return -1;
	while (!keep_tail && s->n > 1u && s->len[s->n - 1u] == 0)
		s->n--;
	for (i = 0; i < 4u; i++) {
		s->pad[i] = pad16(s->len[i]);
		if (s->pad[i] > (uint64_t)((size_t)-1) / 8u) /* the sums below are made in size_t: a segment near 4 GiB on a 32-bit host */
			return -1;
	}
	s->part[0] = SIM_SEC_P1_WIRE;
	s->ops = 1;
	if (s->len[0] > SIM_SEC_INLINE) {
		s->part[1] = (size_t)(s->pad[0] - SIM_SEC_INLINE) + SIM_SEC_TAG;
		s->ops++;
	}
	if (s->n > 1u) {
		for (i = 1; i < s->n; i++)
			p3 += s->pad[i];
		p3 += SIM_SEC_EPI + SIM_SEC_TAG;
		s->part[2] = (size_t)p3;
		s->ops++;
	}
	total = (uint64_t)s->part[0] + s->part[1] + s->part[2];
	if (total > (uint64_t)((size_t)-1) / 2u)
		return -1;
	s->total = (size_t)total;
	return 0;
}

size_t sim_sec_frame_len_m(const sim_sec_spec *f, const sim_sec_mut *m, unsigned *nops, size_t parts[3])
{
	shape s;

	if (shape_of(f, m != NULL && (m->mask & SIM_SEC_M_KEEP_TAIL) != 0, &s) != 0)
		return 0;
	if (nops != NULL)
		*nops = s.ops;
	if (parts != NULL)
		memcpy(parts, s.part, sizeof(s.part));
	return s.total;
}

size_t sim_sec_frame_len(const sim_sec_spec *f, unsigned *nops, size_t parts[3]) { return sim_sec_frame_len_m(f, NULL, nops, parts); }

/* The IV of operation `op` (0 based) of this frame: the stream's nonce, or counter + delta when the mutation asks for it. */
static void iv_of(const sim_sec_dir *tx, const sim_sec_mut *m, unsigned op, uint8_t iv[SIM_SEC_NONCE])
{
	unsigned want = m != NULL && m->nonce_part != 0 ? m->nonce_part : 1u;

	memcpy(iv, tx->nonce, SIM_SEC_NONCE);
	if (m != NULL && (m->mask & SIM_SEC_M_NONCE) != 0 && op + 1u == want)
		st64(iv + 4, ld64(iv + 4) + (uint64_t)(int64_t)m->nonce_delta);
}

static void build_preamble(const sim_sec_spec *f, const shape *s, const sim_sec_mut *m, uint8_t pre[SIM_SEC_PRE])
{
	unsigned i;
	uint32_t mask = m != NULL ? m->mask : 0u;

	memset(pre, 0, SIM_SEC_PRE);
	pre[0] = f->tag;
	pre[1] = (uint8_t)s->n;
	for (i = 0; i < s->n; i++) {
		st32(pre + 2 + 6u * i, s->len[i]);
		st16(pre + 6 + 6u * i, f->align[i] != 0 ? f->align[i] : k_align[i]);
	}
	if ((mask & SIM_SEC_M_PRE_LEN) != 0)
		for (i = 0; i < 4u; i++)
			if ((m->pre_len_mask >> i) & 1u)
				st32(pre + 2 + 6u * i, m->pre_len[i]);
	if ((mask & SIM_SEC_M_SLOT) != 0 && s->n < 4u)
		pre[2 + 6u * s->n] = m->slot_junk;
	if ((mask & SIM_SEC_M_PRE_TAG) != 0)
		pre[0] = m->pre_tag;
	if ((mask & SIM_SEC_M_PRE_NSEG) != 0)
		pre[1] = m->pre_nseg;
	if ((mask & SIM_SEC_M_FLAGS) != 0)
		pre[26] = m->pre_flags;
	if ((mask & SIM_SEC_M_RESERVED) != 0)
		pre[27] = m->pre_reserved;
	st32(pre + 28, sim_sec_crc32c(0, pre, 28));
	if ((mask & SIM_SEC_M_PRE_CRC) != 0)
		pre[28] ^= m->pre_crc_xor != 0 ? m->pre_crc_xor : 1u;
}

void sim_sec_preamble(const sim_sec_spec *f, const sim_sec_mut *m, uint8_t pre[SIM_SEC_PRE])
{
	shape s;

	if (shape_of(f, m != NULL && (m->mask & SIM_SEC_M_KEEP_TAIL) != 0, &s) != 0) {
		memset(pre, 0, SIM_SEC_PRE);
		return;
	}
	build_preamble(f, &s, m, pre);
}

int sim_sec_seal(sim_sec_dir *tx, const uint8_t *plain, size_t n, uint8_t *out)
{
	uint8_t iv[SIM_SEC_NONCE], tag[SIM_SEC_TAG];

	if (tx == NULL || !tx->keyed)
		return -1;
	memcpy(iv, tx->nonce, SIM_SEC_NONCE);
	if (out != plain && n != 0)
		memcpy(out, plain, n);
	if (ref_gcm_encrypt(&tx->gk, iv, SIM_SEC_NONCE, NULL, 0, out, n, out, tag) != 0)
		return -1;
	memcpy(out + n, tag, SIM_SEC_TAG);
	sim_sec_nonce_step(tx->nonce);
	tx->ops++;
	return 0;
}

/* Seal `n` plaintext bytes at buf in place; the tag goes right behind them. With `other_tag` set the tag is the one a
 * different plaintext (bit 0 of byte 0 flipped) would have under the same IV. */
static int seal_part(const ref_gcm_key *gk, const uint8_t iv[SIM_SEC_NONCE], uint8_t *buf, size_t n, int other_tag)
{
	uint8_t tag[SIM_SEC_TAG], tag2[SIM_SEC_TAG];

	if (other_tag) {
		uint8_t *tmp = (uint8_t *)malloc(n != 0 ? n : 1u);

		if (tmp == NULL)
			return -1;
		memcpy(tmp, buf, n);
		tmp[0] ^= 0x01;
		if (ref_gcm_encrypt(gk, iv, SIM_SEC_NONCE, NULL, 0, tmp, n, tmp, tag2) != 0) {
			free(tmp);
			return -1;
		}
		free(tmp);
	}
	if (ref_gcm_encrypt(gk, iv, SIM_SEC_NONCE, NULL, 0, buf, n, buf, tag) != 0)
		return -1;
	memcpy(buf + n, other_tag ? tag2 : tag, SIM_SEC_TAG);
	return 0;
}

int sim_sec_encode(sim_sec_dir *tx, const sim_sec_spec *f, const sim_sec_mut *m, uint8_t *out, size_t cap, size_t *n)
{
	shape s;
	uint32_t mask = m != NULL ? m->mask : 0u;
	uint8_t pre[SIM_SEC_PRE], iv[SIM_SEC_NONCE], fill = (mask & SIM_SEC_M_PAD) != 0 ? m->pad_fill : 0u;
	ref_gcm_key alt;
	const ref_gcm_key *gk;
	size_t off, k, i, produced;
	unsigned op = 0;
	int rc = -1, have_alt = 0;
	uint8_t late = (mask & SIM_SEC_M_LATE) != 0 ? m->late_status : SIM_SEC_LATE_COMPLETE;
	uint8_t *p3 = NULL;
	uint8_t nonce0[SIM_SEC_NONCE]; /* the stream as it was: restored when the frame cannot be finished */
	uint64_t ops0;

	if (tx == NULL || !tx->keyed || out == NULL || shape_of(f, (mask & SIM_SEC_M_KEEP_TAIL) != 0, &s) != 0 || cap < s.total)
		return -1;
	gk = &tx->gk;
	memcpy(nonce0, tx->nonce, sizeof(nonce0));
	ops0 = tx->ops;
	if ((mask & SIM_SEC_M_NONCE) != 0 && m->nonce_part > s.ops) /* names an operation the frame does not have */
		return -1;
	if ((mask & SIM_SEC_M_FLIP) != 0) {
		unsigned fp = m->flip_part;
		size_t pl;

		if (fp < 1u || fp > 3u || s.part[fp - 1u] == 0 || m->flip_bit > 7u)
			return -1;
		pl = s.part[fp - 1u];
		if (m->flip_region == SIM_SEC_R_TAG ? m->flip_byte >= SIM_SEC_TAG
		    : m->flip_region == SIM_SEC_R_EPILOGUE ? (fp != 3u || m->flip_byte >= SIM_SEC_EPI)
		    : m->flip_byte >= pl)
			return -1;
	}
	if ((mask & SIM_SEC_M_TAG) != 0 && (m->tag_part < 1u || m->tag_part > 3u || s.part[m->tag_part - 1u] == 0))
		return -1;
	if ((mask & SIM_SEC_M_KEY) != 0) {
		uint8_t k2[SIM_SEC_KEY];

		memcpy(k2, tx->key, sizeof(k2));
		k2[0] ^= 0x01;
		if (ref_gcm_setkey(&alt, k2, sizeof(k2)) != 0)
			return -1;
		wipe(k2, sizeof(k2));
		gk = &alt;
		have_alt = 1;
	}
	build_preamble(f, &s, m, pre);

	/* part 1: preamble, then the first 48 bytes of segment 0 (all of it and zero fill when it is shorter) */
	memcpy(out, pre, SIM_SEC_PRE);
	memset(out + SIM_SEC_PRE, (int)fill, SIM_SEC_INLINE);
	k = s.len[0] < SIM_SEC_INLINE ? s.len[0] : SIM_SEC_INLINE;
	if (k != 0)
		memcpy(out + SIM_SEC_PRE, f->seg[0], k);
	iv_of(tx, m, op, iv);
	if (seal_part(gk, iv, out, SIM_SEC_P1_PLAIN, m != NULL && (mask & SIM_SEC_M_TAG) != 0 && m->tag_part == 1u) != 0)
		goto done;
	sim_sec_nonce_step(tx->nonce);
	tx->ops++;
	op++;
	off = SIM_SEC_P1_WIRE;

	/* part 2: the rest of segment 0, padded to 16 */
	if (s.part[1] != 0) {
		size_t body = s.part[1] - SIM_SEC_TAG, rest = (size_t)s.len[0] - SIM_SEC_INLINE;

		memcpy(out + off, f->seg[0] + SIM_SEC_INLINE, rest);
		memset(out + off + rest, (int)fill, body - rest);
		iv_of(tx, m, op, iv);
		if (seal_part(gk, iv, out + off, body, m != NULL && (mask & SIM_SEC_M_TAG) != 0 && m->tag_part == 2u) != 0)
			goto done;
		sim_sec_nonce_step(tx->nonce);
		tx->ops++;
		op++;
		off += s.part[1];
	}

	/* part 3: segments 1.. each padded to 16, then the epilogue block */
	if (s.part[2] != 0) {
		size_t body = s.part[2] - SIM_SEC_TAG, at = 0;

		p3 = out + off;
		for (i = 1; i < s.n; i++) {
			if (s.len[i] != 0)
				memcpy(p3 + at, f->seg[i], s.len[i]);
			memset(p3 + at + s.len[i], (int)fill, (size_t)s.pad[i] - s.len[i]);
			at += (size_t)s.pad[i];
		}
		memset(p3 + at, (int)fill, SIM_SEC_EPI);
		p3[at] = late;
		iv_of(tx, m, op, iv);
		if (seal_part(gk, iv, p3, body, m != NULL && (mask & SIM_SEC_M_TAG) != 0 && m->tag_part == 3u) != 0)
			goto done;
		sim_sec_nonce_step(tx->nonce);
		tx->ops++;
		op++;
	}

	if ((mask & SIM_SEC_M_FLIP) != 0) {
		size_t base = m->flip_part == 1u ? 0 : m->flip_part == 2u ? s.part[0] : (size_t)s.part[0] + s.part[1];
		size_t at = m->flip_byte;

		if (m->flip_region == SIM_SEC_R_TAG)
			at = s.part[m->flip_part - 1u] - SIM_SEC_TAG + m->flip_byte;
		else if (m->flip_region == SIM_SEC_R_EPILOGUE)
			at = s.part[2] - SIM_SEC_TAG - SIM_SEC_EPI + m->flip_byte;
		out[base + at] ^= (uint8_t)(1u << m->flip_bit);
	}
	produced = s.total;
	if ((mask & SIM_SEC_M_TRUNC) != 0 && m->truncate_at < produced)
		produced = m->truncate_at;
	*n = produced;
	rc = 0;
done:
	if (have_alt)
		ref_gcm_wipe(&alt);
	if (rc != 0) { /* a failure inside the frame (out of memory): the stream is not stepped, as the header says */
		memcpy(tx->nonce, nonce0, sizeof(nonce0));
		tx->ops = ops0;
	}
	return rc;
}

/* ---- the decoder ---------------------------------------------------------------------------------------------------------- */

enum { DS_P1 = 0, DS_P2, DS_P3, DS_DEAD };

void sim_sec_dec_init(sim_sec_dec *d, sim_sec_dir *rx, uint32_t cap0, uint32_t capn)
{
	memset(d, 0, sizeof(*d));
	d->rx = rx;
	d->cap0 = cap0 != 0 ? cap0 : (1u << 30);
	d->capn = capn != 0 ? capn : (1u << 30);
	d->state = DS_P1;
}

void sim_sec_dec_free(sim_sec_dec *d)
{
	if (d->in != NULL)
		wipe(d->in, d->in_cap);
	if (d->out != NULL)
		wipe(d->out, d->out_cap);
	wipe(d->inline_, sizeof(d->inline_)); /* plaintext of the frame in progress */
	wipe(d->f.pre, sizeof(d->f.pre));
	free(d->in);
	free(d->out);
	d->in = d->out = NULL;
	d->in_cap = d->out_cap = d->in_head = d->in_len = 0;
}

int sim_sec_dec_feed(sim_sec_dec *d, const uint8_t *p, size_t n)
{
	if (n == 0)
		return 0;
	if (d->in_head + d->in_len + n > d->in_cap) {
		size_t need = d->in_len + n, nc;
		uint8_t *q;

		if (d->in_head != 0 && need <= d->in_cap) {
			memmove(d->in, d->in + d->in_head, d->in_len);
			d->in_head = 0;
		} else {
			nc = d->in_cap != 0 ? d->in_cap : 4096u;
			while (nc < need)
				nc *= 2u;
			q = (uint8_t *)malloc(nc);
			if (q == NULL)
				return -1;
			if (d->in_len != 0)
				memcpy(q, d->in + d->in_head, d->in_len);
			if (d->in != NULL) {
				wipe(d->in, d->in_cap);
				free(d->in);
			}
			d->in = q;
			d->in_cap = nc;
			d->in_head = 0;
		}
	}
	memcpy(d->in + d->in_head + d->in_len, p, n);
	d->in_len += n;
	return 0;
}

size_t sim_sec_dec_buffered(const sim_sec_dec *d) { return d->in_len; }

size_t sim_sec_dec_take(sim_sec_dec *d, uint8_t *out, size_t cap)
{
	size_t k = d->in_len < cap ? d->in_len : cap;

	if (k == 0)
		return 0; /* (d->in may be NULL: no bytes were ever fed) */
	memcpy(out, d->in + d->in_head, k);
	d->in_head += k;
	d->in_len -= k;
	return k;
}

static void consume(sim_sec_dec *d, size_t k)
{
	d->in_head += k;
	d->in_len -= k;
	d->consumed += k;
	if (d->in_len == 0)
		d->in_head = 0;
}

static int fail(sim_sec_dec *d, wr_status st, const char *why)
{
	d->err = st;
	d->why = why;
	d->state = DS_DEAD;
	return SIM_SEC_DEC_ERROR;
}

/* One operation on the next `n` ciphertext bytes (tag right behind them) of the input: the nonce is taken whatever the
 * verdict, the tag decides before any plaintext is looked at. */
static int open_part(sim_sec_dec *d, size_t n, uint8_t *plain)
{
	const uint8_t *in = d->in + d->in_head;
	uint8_t iv[SIM_SEC_NONCE];
	int rc;

	memcpy(iv, d->rx->nonce, SIM_SEC_NONCE);
	sim_sec_nonce_step(d->rx->nonce);
	d->rx->ops++;
	rc = ref_gcm_decrypt(&d->rx->gk, iv, SIM_SEC_NONCE, NULL, 0, in, n, in + n, plain);
	return rc;
}

static int parse_preamble(sim_sec_dec *d, const uint8_t *pre)
{
	sim_sec_frame *f = &d->f;
	unsigned i;

	memcpy(f->pre, pre, SIM_SEC_PRE);
	if (sim_sec_crc32c(0, pre, 28) != ld32(pre + 28))
		return fail(d, WR_E_M2_FRAME_CRC, "preamble CRC does not match");
	f->tag = pre[0];
	f->nseg = pre[1];
	f->flags = pre[26];
	f->reserved = pre[27];
	if (f->nseg < 1u || f->nseg > SIM_SEC_MAX_SEG)
		return fail(d, WR_E_M2_FRAME_FORM, "segment count outside 1..4");
	if (f->tag < 1u || f->tag > SIM_SEC_TAG_MAX)
		return fail(d, WR_E_M2_TAG, "unknown frame tag");
	if (f->flags != 0)
		return fail(d, WR_E_M2_FRAME_FORM, (f->flags & 1u) != 0 ? "compressed flag set" : "unknown preamble flags");
	if (f->reserved != 0)
		return fail(d, WR_E_M2_FRAME_FORM, "reserved preamble byte not zero");
	for (i = 0; i < SIM_SEC_MAX_SEG; i++) {
		f->len[i] = ld32(pre + 2 + 6u * i);
		f->align[i] = ld16(pre + 6 + 6u * i);
		if (i >= f->nseg && (f->len[i] != 0 || f->align[i] != 0))
			return fail(d, WR_E_M2_FRAME_FORM, "unused segment slot not zero");
	}
	if (f->nseg > 1u && f->len[f->nseg - 1u] == 0)
		return fail(d, WR_E_M2_FRAME_FORM, "empty last segment");
	if (f->len[0] > d->cap0)
		return fail(d, WR_E_M2_FRAME_TOOBIG, "segment 0 above its cap");
	for (i = 1; i < f->nseg; i++)
		if (f->len[i] > d->capn)
			return fail(d, WR_E_M2_FRAME_TOOBIG, "segment above its cap");
	{ /* the plaintext of the whole frame must be addressable (caps near 4 GiB on a 32-bit size_t would wrap the sums below) */
		uint64_t all = (uint64_t)pad16(f->len[0]) + SIM_SEC_EPI + SIM_SEC_TAG + 3u * SIM_SEC_BLOCK;

		for (i = 1; i < f->nseg; i++)
			all += pad16(f->len[i]);
		if (all > (uint64_t)((size_t)-1) / 2u)
			return fail(d, WR_E_M2_FRAME_TOOBIG, "frame too large for this host");
	}
	return 0;
}

static int ensure_out(sim_sec_dec *d, size_t n)
{
	uint8_t *q;

	if (n <= d->out_cap)
		return 0;
	q = (uint8_t *)malloc(n);
	if (q == NULL)
		return -1;
	if (d->out != NULL) {
		wipe(d->out, d->out_cap);
		free(d->out);
	}
	d->out = q;
	d->out_cap = n;
	return 0;
}

/* The layout of the plaintext of the frame: segment 0 (its logical length), then segments 1.. padded, then the epilogue
 * block; one byte more so a frame of zero length has an address. */
static int make_out(sim_sec_dec *d)
{
	const sim_sec_frame *f = &d->f;
	size_t at = f->len[0];
	unsigned i;

	for (i = 1; i < 4u; i++)
		if (i < f->nseg)
			at += (size_t)d->pad[i];
	if (ensure_out(d, at + SIM_SEC_EPI + 1u) != 0)
		return -1;
	at = f->len[0];
	d->seg_off[0] = 0;
	for (i = 1; i < 4u; i++) {
		d->seg_off[i] = at;
		at += i < f->nseg ? (size_t)d->pad[i] : 0u;
	}
	return 0;
}

int sim_sec_dec_next(sim_sec_dec *d, sim_sec_frame *out_f)
{
	for (;;) {
		sim_sec_frame *f = &d->f;
		uint64_t need;
		unsigned i;

		if (d->state == DS_DEAD)
			return SIM_SEC_DEC_ERROR;
		if (d->state == DS_P1) {
			uint8_t plain[SIM_SEC_P1_PLAIN];

			if (d->in_len < SIM_SEC_P1_WIRE)
				return SIM_SEC_DEC_NEED;
			memset(f, 0, sizeof(*f));
			d->consumed = 0;
			if (open_part(d, SIM_SEC_P1_PLAIN, plain) != 0) {
				wipe(plain, sizeof(plain));
				return fail(d, WR_E_M2_SEC_TAG, "part 1 failed authentication");
			}
			consume(d, SIM_SEC_P1_WIRE);
			f->ops = 1;
			if (parse_preamble(d, plain) != 0) {
				wipe(plain, sizeof(plain));
				return SIM_SEC_DEC_ERROR;
			}
			memcpy(d->inline_, plain + SIM_SEC_PRE, SIM_SEC_INLINE);
			wipe(plain, sizeof(plain));
			d->pad[0] = pad16(f->len[0]);
			for (i = 1; i < 4u; i++)
				d->pad[i] = pad16(f->len[i]);
			if (f->len[0] > SIM_SEC_INLINE) {
				d->state = DS_P2;
			} else {
				if (make_out(d) != 0)
					return fail(d, WR_E_BUDGET, "out of memory");
				memcpy(d->out, d->inline_, f->len[0]);
				d->state = f->nseg > 1u ? DS_P3 : DS_P1;
			}
			f->wire = SIM_SEC_P1_WIRE;
		}
		if (d->state == DS_P2) {
			size_t body = (size_t)(d->pad[0] - SIM_SEC_INLINE);
			uint8_t *rest;

			if (d->in_len < body + SIM_SEC_TAG)
				return SIM_SEC_DEC_NEED;
			rest = (uint8_t *)malloc(body);
			if (rest == NULL)
				return fail(d, WR_E_BUDGET, "out of memory");
			if (open_part(d, body, rest) != 0) {
				wipe(rest, body);
				free(rest);
				return fail(d, WR_E_M2_SEC_TAG, "part 2 failed authentication");
			}
			consume(d, body + SIM_SEC_TAG);
			if (make_out(d) != 0) {
				wipe(rest, body);
				free(rest);
				return fail(d, WR_E_BUDGET, "out of memory");
			}
			memcpy(d->out, d->inline_, SIM_SEC_INLINE);
			memcpy(d->out + SIM_SEC_INLINE, rest, (size_t)f->len[0] - SIM_SEC_INLINE);
			wipe(rest, body);
			free(rest);
			f->ops++;
			f->wire += body + SIM_SEC_TAG;
			d->state = f->nseg > 1u ? DS_P3 : DS_P1;
		}
		if (d->state == DS_P3) {
			size_t body = SIM_SEC_EPI;

			for (i = 1; i < f->nseg; i++)
				body += (size_t)d->pad[i];
			need = (uint64_t)body + SIM_SEC_TAG;
			if (d->in_len < need)
				return SIM_SEC_DEC_NEED;
			if (open_part(d, body, d->out + f->len[0]) != 0) {
				wipe(d->out + f->len[0], body); /* never looked at: the tag failed */
				return fail(d, WR_E_M2_SEC_TAG, "part 3 failed authentication");
			}
			consume(d, body + SIM_SEC_TAG);
			f->ops++;
			f->wire += body + SIM_SEC_TAG;
			f->late_status = d->out[f->len[0] + body - SIM_SEC_EPI];
			d->state = DS_P1;
			if ((f->late_status & 0x0fu) != SIM_SEC_LATE_ABORTED && (f->late_status & 0x0fu) != SIM_SEC_LATE_COMPLETE)
				return fail(d, WR_E_M2_FRAME_FORM, "epilogue late_status is neither complete nor aborted");
		}
		d->state = DS_P1;
		for (i = 0; i < 4u; i++)
			f->seg[i] = i < f->nseg ? d->out + d->seg_off[i] : NULL;
		d->n_frames++;
		*out_f = *f;
		return (f->late_status & 0x0fu) == SIM_SEC_LATE_ABORTED && f->nseg > 1u ? SIM_SEC_DEC_ABORTED : SIM_SEC_DEC_FRAME;
	}
}
