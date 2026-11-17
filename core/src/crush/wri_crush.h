/* SPDX-License-Identifier: MIT */
/*
 * wri_crush.h - the compact CRUSH map and the mapper that runs rules on it.
 *
 * What lives here (docs/design/core-architecture.md section 16):
 *   - the COMPACT FORMAT: what a CRUSH blob from an OSDMap (crush-and-placement.md 2.2) is turned into, kept
 *     inside a map slot. It holds only what mapping reads: buckets (items and the weights their algorithm
 *     uses), replicated rules, tunables and choose_args. Names, classes, type names, rule names and the
 *     rows that never influence a mapping are dropped. The layout is defined here, together with the inline
 *     accessors, so the decoder (wri_crush_dec.c) and the mapper (wri_crush_map.c, wri_crush_buck.c,
 *     wri_crush_legacy.c) can be written independently of each other.
 *   - the decoder, a structural checker, a rule audit and the rule interpreter (declared at the end).
 *
 * The compact region is OUR memory, never wire bytes: host byte order, 4-byte aligned words, addressed by
 * offsets from the start of the region (so it can be copied with memcpy and sits at a different address in
 * each of the two map slots). Structs may overlay it. The whole region is immutable once decoded.
 *
 * Supported: bucket algorithms straw2 (alg 5) and straw (4) fully; list (2) and uniform (1) in the legacy
 * module; tree (3) is decoded structurally (id, type, size, items) and refused when a mapping reaches it.
 * Rules of type 1 (replicated) made of take / choose firstn / chooseleaf firstn / emit / the SET_* steps.
 * Written from docs/spec/crush-and-placement.md; written independently of Ceph's code.
 */
#ifndef WRI_CRUSH_H
#define WRI_CRUSH_H

#include "wr_err.h"
#include "wr_port.h"
#include "wri_cursor.h"

/* ---- constants (crush-and-placement.md 2.2, 2.3) ----------------------------------------------- */

#define WRI_CRUSH_MAGIC_WIRE 0x00010000u /* first u32 of a CRUSH blob */
#define WRI_CRUSH_MAGIC 0x57435331u      /* "WCS1": first word of the compact region */

#define WRI_CRUSH_ITEM_NONE 0x7fffffff
#define WRI_CRUSH_ITEM_UNDEF 0x7ffffffe

#define WRI_CRUSH_MAX_BUCKETS 32768u     /* bucket slots in a map we accept */
#define WRI_CRUSH_MAX_RULES 256u
#define WRI_CRUSH_MAX_STEPS 64u          /* steps in one rule */
#define WRI_CRUSH_MAX_DEPTH 10u          /* hierarchy depth of the reference; a descent deeper than 16 is a loop */
#define WRI_CRUSH_DESCENT_MAX 16u
#define WRI_CRUSH_MAX_BUCKET_SIZE 65535u /* items in one bucket */
#define WRI_CRUSH_RESULT_MAX 16u         /* replicas a mapping returns at most (pool size above this is unsupported) */
#define WRI_CRUSH_PERM_MAX 256u          /* largest bucket the permutation chooser (uniform, local fallback) handles */
#define WRI_CRUSH_VARY_R_MAX 32u         /* chooseleaf_vary_r above this is refused (a shift by vary_r - 1) */

/* bucket algorithms */
#define WRI_CRUSH_ALG_UNIFORM 1u
#define WRI_CRUSH_ALG_LIST 2u
#define WRI_CRUSH_ALG_TREE 3u
#define WRI_CRUSH_ALG_STRAW 4u
#define WRI_CRUSH_ALG_STRAW2 5u

/* rule types and steps */
#define WRI_CRUSH_RULE_REPLICATED 1u
#define WRI_CRUSH_OP_NOOP 0u
#define WRI_CRUSH_OP_TAKE 1u
#define WRI_CRUSH_OP_CHOOSE_FIRSTN 2u
#define WRI_CRUSH_OP_CHOOSE_INDEP 3u
#define WRI_CRUSH_OP_EMIT 4u
#define WRI_CRUSH_OP_CHOOSELEAF_FIRSTN 6u
#define WRI_CRUSH_OP_CHOOSELEAF_INDEP 7u
#define WRI_CRUSH_OP_SET_CHOOSE_TRIES 8u
#define WRI_CRUSH_OP_SET_CHOOSELEAF_TRIES 9u
#define WRI_CRUSH_OP_SET_CHOOSE_LOCAL_TRIES 10u
#define WRI_CRUSH_OP_SET_CHOOSE_LOCAL_FALLBACK_TRIES 11u
#define WRI_CRUSH_OP_SET_CHOOSELEAF_VARY_R 12u
#define WRI_CRUSH_OP_SET_CHOOSELEAF_STABLE 13u
/* 14 .. 16 are the MSR steps: refused by the rule audit */

/* ---- the compact format ------------------------------------------------------------------------ */

/* Tunables as decoded (absent groups keep the legacy defaults of crush-and-placement.md 2.5). */
typedef struct wri_crush_tun {
	uint32_t choose_local_tries;
	uint32_t choose_local_fallback_tries;
	uint32_t choose_total_tries; /* the stored value: a number of retries, the interpreter allows one more attempt */
	uint32_t chooseleaf_descend_once;
	uint8_t chooseleaf_vary_r;
	uint8_t chooseleaf_stable;
	uint8_t reserved[2];
} wri_crush_tun;

/*
 * Header of a compact region. All offsets are in bytes from the first byte of this header and are
 * multiples of 4; 0 means "none". bucket_tab is u32[max_buckets] (slot i holds the bucket with id -1 - i),
 * rule_tab is u32[max_rules], set_tab is wri_cargs_set[n_sets].
 */
typedef struct wri_crush {
	uint32_t magic;       /* WRI_CRUSH_MAGIC */
	uint32_t bytes;       /* size of the whole region, this header included */
	uint32_t max_buckets;
	uint32_t max_rules;
	int32_t max_devices;  /* recomputed after decoding (crush-and-placement.md 2.4 item 1) */
	uint32_t bucket_tab;
	uint32_t rule_tab;
	uint32_t n_sets;
	uint32_t set_tab;
	wri_crush_tun tun;
} wri_crush;

#define WRI_CRUSH_HDR_BYTES 56u /* sizeof(wri_crush): the tables follow it */

/*
 * A bucket record: this 16-byte head, then items[size] (s32), then a tail that depends on the algorithm:
 *   straw2   weights[size]  (u32, 16.16)
 *   straw    straws[size]   (u32; the item weights are not stored, mapping never reads them)
 *   list     item_weights[size], then sum_weights[size]
 *   uniform  nothing
 *   tree     nothing (decoded for its items only; a mapping that reaches it fails with WR_E_CRUSH_UNSUPPORTED)
 */
typedef struct wri_cbucket {
	int32_t id;      /* negative, equal to -1 - slot */
	uint16_t type;
	uint8_t alg;     /* WRI_CRUSH_ALG_* */
	uint8_t hash;    /* always 0 (rjenkins1): the decoder refuses anything else */
	uint32_t size;   /* items, 0 .. WRI_CRUSH_MAX_BUCKET_SIZE (an empty bucket is kept; the mapper treats it as a rejection) */
	uint32_t reserved;
} wri_cbucket;

/* A rule record: the step count, then nsteps x wri_cstep. Only rules of type 1 are stored (see WRI_CRUSH_RULE_OTHER). */
typedef struct wri_crule {
	uint32_t nsteps;
} wri_crule;

typedef struct wri_cstep {
	uint32_t op;
	int32_t arg1;
	int32_t arg2;
} wri_cstep;

/*
 * choose_args (weight sets and substitute ids). One directory entry per set, key = pool id or -1 for the
 * default set (keys that do not fit an s32 can never match a pool and are dropped); index is the offset of
 * u32[max_buckets]: the offset of that bucket's wri_cargs, 0 = no override for it. A wri_cargs record is
 * this head, then n_pos rows of `size` u32 weights, then `size` s32 ids when has_ids.
 */
typedef struct wri_cargs_set {
	int32_t pool;
	uint32_t index;
} wri_cargs_set;

typedef struct wri_cargs {
	uint32_t n_pos;
	uint32_t has_ids;
} wri_cargs;

WR_STATIC_ASSERT(sizeof(wri_crush) == WRI_CRUSH_HDR_BYTES, wri_crush_size);
WR_STATIC_ASSERT(sizeof(wri_cbucket) == 16u, wri_cbucket_size);
WR_STATIC_ASSERT(sizeof(wri_cstep) == 12u, wri_cstep_size);
WR_STATIC_ASSERT(sizeof(wri_cargs_set) == 8u, wri_cargs_set_size);
WR_STATIC_ASSERT(sizeof(wri_cargs) == 8u, wri_cargs_size);

/* ---- accessors (all take a decoded region; bounds are the decoder's guarantee, checked by wri_crush_check) ---- */

WR_INLINE const uint32_t *wri_crush_words(const wri_crush *c, uint32_t off)
{
	return (const uint32_t *)(const void *)((const uint8_t *)c + off);
}

/* The bucket in slot i (id -1 - i), NULL for a hole or an out-of-range slot. */
WR_INLINE const wri_cbucket *wri_crush_bucket_at(const wri_crush *c, uint32_t slot)
{
	uint32_t off;

	if (slot >= c->max_buckets)
		return NULL;
	off = wri_crush_words(c, c->bucket_tab)[slot];
	return off == 0 ? NULL : (const wri_cbucket *)(const void *)((const uint8_t *)c + off);
}

/* The bucket with this (negative) id; NULL for a device id, a hole or an out-of-range id. */
WR_INLINE const wri_cbucket *wri_crush_bucket(const wri_crush *c, int32_t id)
{
	return id >= 0 ? NULL : wri_crush_bucket_at(c, (uint32_t)(-1 - id));
}

WR_INLINE const int32_t *wri_cbucket_items(const wri_cbucket *b)
{
	return (const int32_t *)(const void *)(b + 1);
}
/* straw2 weights, straw straws, list item weights: the first u32 array after the items. */
WR_INLINE const uint32_t *wri_cbucket_w(const wri_cbucket *b)
{
	return (const uint32_t *)(const void *)(wri_cbucket_items(b) + b->size);
}
/* list sum_weights: the second u32 array. */
WR_INLINE const uint32_t *wri_cbucket_sums(const wri_cbucket *b)
{
	return wri_cbucket_w(b) + b->size;
}

/*
 * rule_tab entries: 0 = no rule in that slot, WRI_CRUSH_RULE_OTHER = a rule of another type than replicated exists
 * (not stored: indep and MSR rules are refused), else the offset of the wri_crule record (a multiple of 4, so the
 * odd sentinel cannot be an offset).
 */
#define WRI_CRUSH_RULE_OTHER 1u

/* 0 no rule, 1 a rule we do not store (not replicated), 2 a replicated rule. */
WR_INLINE unsigned wri_crush_rule_kind(const wri_crush *c, uint32_t rule)
{
	uint32_t off;

	if (rule >= c->max_rules)
		return 0;
	off = wri_crush_words(c, c->rule_tab)[rule];
	return off == 0 ? 0u : (off == WRI_CRUSH_RULE_OTHER ? 1u : 2u);
}

/* Rule `rule` (its id is its slot), NULL when there is no replicated rule of that id. */
WR_INLINE const wri_crule *wri_crush_rule(const wri_crush *c, uint32_t rule)
{
	uint32_t off;

	if (rule >= c->max_rules)
		return NULL;
	off = wri_crush_words(c, c->rule_tab)[rule];
	return off <= WRI_CRUSH_RULE_OTHER ? NULL : (const wri_crule *)(const void *)((const uint8_t *)c + off);
}
WR_INLINE const wri_cstep *wri_crule_steps(const wri_crule *r)
{
	return (const wri_cstep *)(const void *)(r + 1);
}

/*
 * The choose_args index table (u32[max_buckets]) of the set that applies to `pool`: the set keyed by the pool
 * id, else the set keyed -1, else NULL (crush-and-placement.md 3.3).
 */
WR_INLINE const uint32_t *wri_crush_args_index(const wri_crush *c, int32_t pool)
{
	const wri_cargs_set *s = (const wri_cargs_set *)(const void *)((const uint8_t *)c + c->set_tab);
	uint32_t i, def = c->n_sets;

	for (i = 0; i < c->n_sets; i++) {
		if (s[i].pool == pool)
			return wri_crush_words(c, s[i].index);
		if (s[i].pool == -1)
			def = i;
	}
	return def < c->n_sets ? wri_crush_words(c, s[def].index) : NULL;
}
/* The override of bucket slot `slot` in a set's index table, or NULL. */
WR_INLINE const wri_cargs *wri_crush_args_of(const wri_crush *c, const uint32_t *index, uint32_t slot)
{
	return (index == NULL || index[slot] == 0) ? NULL : (const wri_cargs *)(const void *)((const uint8_t *)c + index[slot]);
}
/* Weight row for a draw position: row min(position, n_pos - 1); NULL if the override has no weight rows. */
WR_INLINE const uint32_t *wri_cargs_row(const wri_cargs *a, uint32_t size, uint32_t position)
{
	uint32_t row;

	if (a == NULL || a->n_pos == 0)
		return NULL;
	row = position < a->n_pos ? position : a->n_pos - 1u;
	return (const uint32_t *)(const void *)(a + 1) + (size_t)row * size;
}
/* Substitute ids (hash input only), NULL if the override has none. */
WR_INLINE const int32_t *wri_cargs_ids(const wri_cargs *a, uint32_t size)
{
	return (a == NULL || a->has_ids == 0) ? NULL
					      : (const int32_t *)(const void *)((const uint32_t *)(const void *)(a + 1) + (size_t)a->n_pos * size);
}

/* ---- decoder (module crush-dec, wri_crush_dec.c) ------------------------------------------------ */

/*
 * Decode a CRUSH blob (crush-and-placement.md 2.2) into the compact format at `out` (8-byte aligned, `cap`
 * bytes). *used gets the region size on success. The blob has no envelope: it ends where the buffer ends and
 * every group after the rules is optional (absent groups keep the legacy defaults). Accepts both forms of
 * 2.1 (with and without the MSR tunable pair, any stored rule min/max size). Applies the fix-ups of 2.4
 * (max_devices recomputed from the buckets and the name map keys). Rejects, with a reason in *why (may be
 * NULL): wrong magic, alg marker different from the bucket's alg byte, bucket id != -1 - slot, hash != 0,
 * ruleset != slot, a bucket reference beyond max_buckets, vary_r above WRI_CRUSH_VARY_R_MAX, choose_args whose
 * ids or weight rows do not match the bucket size, a straw2 weight or weight-set weight of 0x80000000 or more (the
 * reference would read it as a negative divisor; no real map has one, and refusing it makes the unsigned division
 * exact), and counts above the WRI_CRUSH_MAX_* limits (WR_E_CRUSH_ENCODING);
 * WR_E_MAP_BUDGET when the region does not fit `cap`. Never reads or writes outside blob[0..n) and out[0..cap).
 */
WR_MUST_CHECK wr_status wri_crush_decode(const uint8_t *blob, size_t n, uint8_t *out, size_t cap, size_t *used,
					 wr_errinfo *why);

/*
 * Structural self-check of a compact region of `bytes` bytes: magic, every offset inside the region and
 * 4-aligned, every bucket and rule record inside it, ids equal to their slot, sizes within limits. For tests,
 * fuzzing and a paranoid caller after a memcpy; returns WR_OK or WR_E_CRUSH_ENCODING.
 */
WR_MUST_CHECK wr_status wri_crush_check(const wri_crush *c, size_t bytes);

/* ---- decoder internals (shared by wri_crush_dec.c and wri_crush_dec2.c; no other module uses them) ---------- */

/* The state of one decode: the blob reader, the room being filled (a bump allocator: every record is a multiple of 4
 * bytes, so everything stays 4-aligned) and the facts the later groups need from the earlier ones. */
typedef struct wri_crush_dctx {
	wri_rd r;
	uint8_t *out;          /* the room, 8-byte aligned */
	size_t cap;            /* its size, at most 0xffffffff */
	size_t pos;            /* bytes handed out so far */
	wr_errinfo *why;       /* may be NULL */
	uint32_t max_buckets;
	uint32_t max_rules;
	int64_t max_dev;       /* one more than the largest device id seen in a bucket or a name_map key */
	uint32_t n_sets;       /* choose_args sets kept */
	uint32_t set_tab;      /* offset of wri_cargs_set[n_sets], 0 when n_sets == 0 */
	wri_crush_tun tun;
} wri_crush_dctx;

/* Record a CRUSH failure (module WR_MOD_CRUSH; errinfo what, a0 = offset in the blob, a1 and a2 = the numbers) and return `st`. */
wr_status wri_crush_dec_fail(wri_crush_dctx *c, wr_status st, const char *what, size_t off, uint64_t a1, uint64_t a2);
/* The reader failed (truncated, or a count larger than the bytes left): report `what` as WR_E_CRUSH_ENCODING. */
wr_status wri_crush_dec_rd_fail(wri_crush_dctx *c, const char *what);
/* Hand out n bytes of the room (n a multiple of 4), or NULL with WR_E_MAP_BUDGET recorded. The bytes are NOT cleared. */
uint8_t *wri_crush_dec_alloc(wri_crush_dctx *c, uint64_t n, const char *what);
/* Everything after the rules: names, tunables, classes, choose_args, the MSR pair, trailing bytes (wri_crush_dec2.c). */
WR_MUST_CHECK wr_status wri_crush_dec_tail(wri_crush_dctx *c);

/* Host-order word access to the room without alignment or aliasing assumptions. */
WR_INLINE void wri_crush_put32(uint8_t *p, uint32_t v)
{
	WR_MEMCPY(p, &v, 4);
}
WR_INLINE uint32_t wri_crush_get32(const uint8_t *p)
{
	uint32_t v;

	WR_MEMCPY(&v, p, 4);
	return v;
}

/* ---- mapper (modules crush-map, crush-legacy) -------------------------------------------------- */

/* Caller-owned workspace of one mapping (it lives in the map store, not on the stack). */
typedef struct wri_crush_ws {
	int32_t w[WRI_CRUSH_RESULT_MAX]; /* working set of the rule interpreter */
	int32_t o[WRI_CRUSH_RESULT_MAX]; /* output of the current choose step */
	int32_t leaf[WRI_CRUSH_RESULT_MAX]; /* chooseleaf results */
	uint16_t perm[WRI_CRUSH_PERM_MAX]; /* scratch of the permutation chooser */
	uint32_t work;                   /* bucket evaluations the next mapping may still spend; the caller sets it */
} wri_crush_ws;

/* The inputs of one mapping besides the map. */
typedef struct wri_crush_in {
	uint32_t rule;             /* pool crush_rule */
	uint32_t x;                /* placement seed (pps) */
	uint32_t result_max;       /* pool size, 1 .. WRI_CRUSH_RESULT_MAX */
	const uint32_t *osd_weight;/* OSD reweight array (16.16, 0x10000 = in) */
	uint32_t weight_max;       /* its length (max_osd): an id at or above it is out */
	int32_t args_pool;         /* pool id that selects the choose_args set */
} wri_crush_in;

/*
 * Run rule `in->rule`: fills result[0..*n_out) (at most in->result_max entries, firstn never pads) and returns
 * WR_OK. Failures: WR_E_CRUSH_NO_RULE (no replicated rule of that id), WR_E_CRUSH_UNSUPPORTED (an opcode, bucket
 * algorithm or tunable outside the supported set, reached by this mapping), WR_E_CRUSH_LOOP (descent deeper than
 * WRI_CRUSH_DESCENT_MAX), WR_E_CRUSH_WORK (ws->work bucket evaluations spent). Reason in *why (may be NULL).
 * No recursion, no allocation, frames under 1 KiB; the result is a pure function of (map, in, osd_weight).
 */
WR_MUST_CHECK wr_status wri_crush_do_rule(const wri_crush *c, const wri_crush_in *in, wri_crush_ws *ws, int32_t *result,
					  uint32_t *n_out, wr_errinfo *why);

/*
 * Walk the rule and everything reachable from its take roots and fail early, with a reason, for what
 * wri_crush_do_rule would fail on later: no replicated rule, an unsupported opcode (indep, MSR), a take of a
 * missing bucket, a reachable bucket of an unsupported algorithm or with an item beyond max_buckets, a
 * hierarchy deeper than WRI_CRUSH_MAX_DEPTH or cyclic, a bucket too large for the permutation chooser where one
 * is needed. Used once per tracked pool when a map is adopted: the answer becomes the pool's status.
 */
WR_MUST_CHECK wr_status wri_crush_audit_rule(const wri_crush *c, uint32_t rule, uint32_t result_max, wr_errinfo *why);

#endif /* WRI_CRUSH_H */
