/* SPDX-License-Identifier: MIT */
/*
 * wrt_mapgen.h - test support that WRITES the wire bytes of part B (CRUSH blobs, OSDMaps, incrementals, pools,
 * address vectors, MOSDMap fronts) from plain description structs, builds clusters of any size on demand, and
 * applies incrementals to a plain-array model so tests can compare the core with something that shares no code
 * and no compact format with it.
 *
 * Why it exists (docs/design/core-architecture.md, wave 1 "mapgen"): decoder tests must not depend on the
 * decoders, and the footprint numbers of 15.3 need maps of 100 to 8,192 OSDs that no lab can supply.
 *
 * Written from docs/spec/osdmap.md and docs/spec/crush-and-placement.md only; the few places where the notes
 * leave a byte open (types of the OSD-only block, which the core skips by length but Ceph's decoder reads) were
 * settled against the Ceph decoder in the lab (harness/tools/mapgen_dencoder_check.sh) and against the real
 * bytes in harness/vectors/osdmap/ (the self test re-encodes them byte for byte). No Ceph code is used.
 *
 * How it is built. One walker per wire structure serves four jobs (so the layout is written once and the four
 * can never disagree): encode (description -> bytes), decode (bytes -> description, the independent READER the
 * tests use as an oracle), and free. A description is an ordinary struct of fixed fields and wrt_mg_vec
 * vectors; zero-initialise it (or call the *_init function, which also sets realistic defaults), fill it, encode
 * it, then call the *_free function. Everything that is on the wire is a field; knobs that make hostile shapes
 * (raised struct_v, struct_compat, extra tail bytes, wrong CRC, unsorted tables, array lengths that disagree with
 * max_osd, a pool with size 17, ...) are plain fields too, so a test needs no byte surgery for the common cases.
 *
 * Conventions:
 *   - every function returns 0 on success and -1 on failure (decode errors, never an encode error); allocation
 *     failure aborts (this is test code);
 *   - vectors are wrt_mg_vec { void *v; uint32_t n, cap; }, element access with WRT_MG_E(vec, type, i), appends
 *     with WRT_MG_PUSH(vec, type, value) (a copy; the element's own vectors are then owned by the description);
 *   - tables that are std::map / std::set on the wire are written in the order of the vector, which the
 *     builders and the model keep ascending (the order of a real monitor); a test makes them unsorted by pushing
 *     out of order;
 *   - names are fixed-size NUL-terminated char arrays (the longest is 255 bytes);
 *   - floats are carried as their 32-bit patterns (no floating point in the support code).
 */
#ifndef WRT_MAPGEN_H
#define WRT_MAPGEN_H

#include <stddef.h>
#include <stdint.h>

/* ---- constants ------------------------------------------------------------------------------------------- */

#define WRT_MG_NONE 0x7fffffff /* CRUSH "no item" (crush note 2.3) */
#define WRT_MG_OSD_EXISTS 0x1u
#define WRT_MG_OSD_UP 0x2u
#define WRT_MG_OSD_AUTOOUT 0x4u
#define WRT_MG_OSD_NEW 0x8u
#define WRT_MG_OSD_STOP 0x1000u
#define WRT_MG_W_IN 0x10000u        /* reweight "in", and the default primary affinity */
#define WRT_MG_POOL_HASHPSPOOL 0x1u /* pool flag bit 0 */
#define WRT_MG_FEATURES_ALL 0x3f07fffffffdffffull /* what the stock client advertises (msgr2 note 4.4) */
#define WRT_MG_NAME_MAX 256
#define WRT_MG_AV_MAX 4 /* entries of one address vector */
#define WRT_MG_MAX_REPL 32 /* longest result list of the model */

/* ---- growable byte buffer, vectors, PRNG -------------------------------------------------------------------- */

typedef struct {
	uint8_t *p;
	size_t len, cap;
} wrt_mg_buf;

void wrt_mg_buf_free(wrt_mg_buf *b);
void wrt_mg_buf_put(wrt_mg_buf *b, const void *p, size_t n);

typedef struct {
	void *v;
	uint32_t n, cap;
} wrt_mg_vec;

#define WRT_MG_E(vec, T, i) (((T *)(vec).v)[i])
/* Append a copy of `val`. The element must be a value of type T (a compound literal or a variable). */
#define WRT_MG_PUSH(vec, T, val)                                                                             \
	do {                                                                                                 \
		T wrt_mg_pv_ = (val);                                                                        \
		wrt_mg_vec_grow_(&(vec), sizeof(T));                                                         \
		((T *)(vec).v)[(vec).n++] = wrt_mg_pv_;                                                      \
	} while (0)
void wrt_mg_vec_grow_(wrt_mg_vec *v, size_t esz);
/* Remove element i (shifts the tail down; the element's own vectors are NOT freed). */
void wrt_mg_vec_del(wrt_mg_vec *v, size_t esz, uint32_t i);
/* Make the vector exactly n elements long; new elements are zero, dropped ones are NOT freed. */
void wrt_mg_vec_resize0(wrt_mg_vec *v, size_t esz, uint32_t n);

/* splitmix64: deterministic and tiny. */
typedef struct {
	uint64_t s;
} wrt_mg_rng;
void wrt_mg_rng_seed(wrt_mg_rng *r, uint64_t seed);
uint64_t wrt_mg_rng_next(wrt_mg_rng *r);
uint32_t wrt_mg_rng_below(wrt_mg_rng *r, uint32_t n); /* 0 <= result < n (n > 0) */

/* ---- small shared types ------------------------------------------------------------------------------------- */

typedef struct {
	uint32_t sec, nsec;
} wrt_mg_utime;
typedef struct {
	uint64_t pool;
	uint32_t seed;
} wrt_mg_pg; /* pg_t; the "preferred" field is always -1 on the wire */
typedef struct {
	int32_t from, to;
} wrt_mg_pair;
typedef struct {
	uint64_t start, len;
} wrt_mg_iv; /* interval_set<snapid_t> element */

/* ---- addresses (osdmap.md 2.1.2, 2.1.3) -------------------------------------------------------------------- */

typedef struct {
	uint32_t type;  /* 0 none, 1 legacy (v1), 2 msgr2, 3 any, 4 cidr */
	uint32_t nonce;
	uint32_t elen;  /* length of the socket address that follows (0, or 2..28); the encoder never writes 0, a test may */
	uint16_t family; /* little-endian family (2 IPv4, 10 IPv6, 0 blank), present when elen >= 2 */
	uint8_t sa[26]; /* the elen - 2 bytes after the family: IPv4 = port(be16) ip(4) 8 zero; IPv6 = port flow(4) ip(16) scope(4) */
} wrt_mg_addr;

typedef struct {
	uint8_t marker; /* 2 normal (count + entries); 1 one entry without a count; 0 the legacy 136-byte form */
	uint32_t n;
	wrt_mg_addr a[WRT_MG_AV_MAX];
} wrt_mg_addrvec;

void wrt_mg_addr_v4(wrt_mg_addr *a, uint32_t type, uint32_t ip_host_order, uint16_t port, uint32_t nonce);
void wrt_mg_addr_v6(wrt_mg_addr *a, uint32_t type, const uint8_t ip[16], uint16_t port, uint32_t nonce);
void wrt_mg_addr_blank(wrt_mg_addr *a); /* family 0, elen 28, 26 zero bytes (an unset address) */
/* [v2 entry at port, v1 entry at port + 1], the usual shape of a booted OSD. */
void wrt_mg_av_v2v1(wrt_mg_addrvec *av, uint32_t ip_host_order, uint16_t port, uint32_t nonce);
void wrt_mg_av_v2(wrt_mg_addrvec *av, uint32_t ip_host_order, uint16_t port, uint32_t nonce);
void wrt_mg_av_v1(wrt_mg_addrvec *av, uint32_t ip_host_order, uint16_t port, uint32_t nonce);
void wrt_mg_av_v6(wrt_mg_addrvec *av, const uint8_t ip[16], uint16_t port, uint32_t nonce); /* v2 + v1 over IPv6 */
void wrt_mg_av_empty(wrt_mg_addrvec *av); /* marker 2, count 0: the 5-byte vector of an OSD that never booted */
void wrt_mg_av_blank(wrt_mg_addrvec *av); /* marker 2, one blank entry */
void wrt_mg_av_legacy(wrt_mg_addrvec *av, uint32_t ip_host_order, uint16_t port, uint32_t nonce); /* marker 0 */
/* "10.77.0.10:6802" (IPv4) or "[addr]:port" (IPv6, lower-case hex groups, no compression); "" for a blank one. */
void wrt_mg_addr_str(const wrt_mg_addr *a, char *out, size_t cap);

int wrt_mg_addrvec_encode(const wrt_mg_addrvec *av, wrt_mg_buf *out);
int wrt_mg_addrvec_parse(const uint8_t *p, size_t n, wrt_mg_addrvec *av);

/* ---- CRUSH blob (crush note 2.2) --------------------------------------------------------------------------- */

#define WRT_MG_ALG_UNIFORM 1
#define WRT_MG_ALG_LIST 2
#define WRT_MG_ALG_TREE 3
#define WRT_MG_ALG_STRAW 4
#define WRT_MG_ALG_STRAW2 5

typedef struct {
	int present;            /* 0: a hole (alg marker 0, nothing follows) */
	uint32_t alg_marker;    /* written before the bucket; 0 = same as alg (a test sets another value to break it) */
	int32_t id;             /* must be -1 - slot; the builder sets it, a test breaks it */
	uint16_t type;
	uint8_t alg, hash;
	uint32_t weight;        /* total, 16.16 */
	wrt_mg_vec items;       /* int32_t */
	wrt_mg_vec item_weights; /* uint32_t, one per item; uniform: element 0 is the single item_weight */
	wrt_mg_vec sum_weights;  /* uint32_t, list buckets: running sums as stored */
	wrt_mg_vec straws;       /* uint32_t, straw buckets (NOT Ceph's computed straws: see wrt_mg_crush_add_bucket) */
	wrt_mg_vec node_weights; /* uint32_t, tree buckets; the count is the u8 num_nodes */
} wrt_mg_bucket;

typedef struct {
	uint32_t op;
	int32_t a1, a2;
} wrt_mg_step;

typedef struct {
	int present; /* 0: a hole */
	uint8_t ruleset; /* must equal the slot; the builder sets it */
	uint8_t type, min_size, max_size;
	wrt_mg_vec steps; /* wrt_mg_step */
} wrt_mg_rule;

typedef struct {
	int32_t key;
	uint8_t legacy64; /* the key was written as 64 bits: after the key comes a zero u32, then the length (the empty-name quirk) */
	char name[WRT_MG_NAME_MAX]; /* a name of 255 bytes round-trips (item names in real maps can be long host names) */
} wrt_mg_name;

typedef struct {
	int32_t item, cls;
} wrt_mg_cls_map;
typedef struct {
	int32_t id;
	char name[48];
} wrt_mg_cls_name;
typedef struct {
	int32_t bucket;
	wrt_mg_vec shadows; /* wrt_mg_pair { from = class id, to = shadow bucket id } */
} wrt_mg_cls_bucket;

typedef struct {
	wrt_mg_vec w; /* uint32_t */
} wrt_mg_wrow;
typedef struct {
	uint32_t index;   /* bucket slot */
	wrt_mg_vec rows;  /* wrt_mg_wrow (weight_set_positions of them) */
	wrt_mg_vec ids;   /* int32_t, empty = none */
} wrt_mg_carg;
typedef struct {
	int64_t key;       /* pool id, or -1 for the default set */
	wrt_mg_vec bucks;  /* wrt_mg_carg */
} wrt_mg_cset;

/* How many of the trailing groups are present (crush note 2.2 rows 10 to 20); each stands for "the buffer ends
 * here" when absent, and an absent group means the legacy default for the decoder. */
#define WRT_MG_UPTO_NONE 0 /* header, buckets, rules, three name maps and nothing else */
#define WRT_MG_UPTO_A 1    /* + choose_local_tries, choose_local_fallback_tries, choose_total_tries */
#define WRT_MG_UPTO_B 2    /* + chooseleaf_descend_once */
#define WRT_MG_UPTO_C 3    /* + chooseleaf_vary_r */
#define WRT_MG_UPTO_D 4    /* + straw_calc_version */
#define WRT_MG_UPTO_E 5    /* + allowed_bucket_algs */
#define WRT_MG_UPTO_F 6    /* + chooseleaf_stable */
#define WRT_MG_UPTO_CLASSES 7 /* + class_map, class_name, class_bucket */
#define WRT_MG_UPTO_CARGS 8   /* + choose_args (the form inside a full OSDMap: no MSR pair) */
#define WRT_MG_UPTO_MSR 9     /* + msr_descents, msr_collision_tries (the form of an incremental / getcrushmap) */

typedef struct {
	uint32_t magic;       /* 0x00010000 */
	int32_t max_devices;  /* the wire value (the decoder recomputes it); the builder sets 1 + the largest item id */
	int hdr_override;     /* 1: write hdr_max_buckets / hdr_max_rules in the header instead of the vector lengths (a lie) */
	uint32_t hdr_max_buckets, hdr_max_rules;
	int upto;             /* WRT_MG_UPTO_* */
	wrt_mg_vec buckets;   /* wrt_mg_bucket, slot i holds id -1 - i */
	wrt_mg_vec rules;     /* wrt_mg_rule, slot i is rule i */
	wrt_mg_vec type_names, item_names, rule_names; /* wrt_mg_name */
	uint32_t choose_local_tries, choose_local_fallback_tries, choose_total_tries, chooseleaf_descend_once;
	uint8_t chooseleaf_vary_r, straw_calc_version;
	uint32_t allowed_bucket_algs;
	uint8_t chooseleaf_stable;
	wrt_mg_vec class_map;    /* wrt_mg_cls_map */
	wrt_mg_vec class_names;  /* wrt_mg_cls_name */
	wrt_mg_vec class_bucket; /* wrt_mg_cls_bucket */
	wrt_mg_vec choose_args;  /* wrt_mg_cset */
	uint32_t msr_descents, msr_collision_tries;
} wrt_mg_crush;

/* Tunable profiles (crush note 2.5). LEGACY is what a decoder assumes when the groups are absent. */
#define WRT_MG_TUN_LEGACY 0 /* 2 / 5 / 19, descend_once 0, vary_r 0, stable 0 */
#define WRT_MG_TUN_BOBTAIL 1
#define WRT_MG_TUN_FIREFLY 2
#define WRT_MG_TUN_HAMMER 3
#define WRT_MG_TUN_JEWEL 4 /* = optimal in v20.2.5 */

void wrt_mg_crush_init(wrt_mg_crush *c);          /* jewel tunables, upto CARGS, no buckets */
void wrt_mg_crush_free(wrt_mg_crush *c);
void wrt_mg_crush_tunables(wrt_mg_crush *c, int profile);
/*
 * Add a bucket at slot -1 - id (the slot vector grows with holes). weights: one 16.16 weight per item (NULL = all
 * 0x10000). The bucket total, the list sums, the uniform item_weight and a plausible tree are filled in. A straw
 * bucket gets straws that are simply a function of the weights (NOT the values Ceph's own builder computes), so a
 * map with straw buckets decodes and maps deterministically but is not what crushtool would have written; a test
 * that compares placements against crushtool for straw maps must take the blob from crushtool.
 * Returns the slot, or -1.
 */
int wrt_mg_crush_add_bucket(wrt_mg_crush *c, int32_t id, uint16_t type, uint8_t alg, const int32_t *items,
			    const uint32_t *weights, uint32_t n);
int wrt_mg_crush_add_rule(wrt_mg_crush *c, uint32_t slot, uint8_t type, const wrt_mg_step *steps, uint32_t nsteps);
void wrt_mg_crush_name(wrt_mg_crush *c, int which, int32_t key, const char *name); /* which: 0 type, 1 item, 2 rule */
void wrt_mg_crush_recount(wrt_mg_crush *c); /* recompute max_devices from the items and the item names */

int wrt_mg_crush_encode(const wrt_mg_crush *c, wrt_mg_buf *out);
int wrt_mg_crush_parse(const uint8_t *p, size_t n, wrt_mg_crush *c); /* c is initialised by the call */

/* Opcodes used by the rule builders. */
#define WRT_MG_OP_TAKE 1
#define WRT_MG_OP_CHOOSE_FIRSTN 2
#define WRT_MG_OP_EMIT 4
#define WRT_MG_OP_CHOOSELEAF_FIRSTN 6

/* ---- pools (osdmap.md 2.5) ---------------------------------------------------------------------------------- */

typedef struct {
	uint64_t id; /* snapid, written as the map key and again inside the entry */
	wrt_mg_utime stamp;
	char name[64];
} wrt_mg_snap;
typedef struct {
	char k[64], v[64];
} wrt_mg_kv;
typedef struct {
	char app[64];
	wrt_mg_vec kv; /* wrt_mg_kv */
} wrt_mg_app;
typedef struct {
	int32_t key;
	int64_t val; /* only INT options are written (type 1) */
} wrt_mg_opt;

typedef struct {
	uint8_t v, compat; /* struct_v (default 32), struct_compat (default 5) */
	uint32_t tail;     /* extra bytes after the known rows (zeros), to test skipping */
	uint8_t type, size, crush_rule, object_hash;
	uint32_t pg_num, pgp_num, lpg_num, lpgp_num, last_change;
	uint64_t snap_seq;
	uint32_t snap_epoch;
	wrt_mg_vec snaps;         /* wrt_mg_snap */
	wrt_mg_vec removed_snaps; /* wrt_mg_iv */
	uint64_t auid, flags;
	uint32_t crash_replay_interval;
	uint8_t min_size;
	uint64_t quota_max_bytes, quota_max_objects;
	wrt_mg_vec tiers; /* uint64_t */
	int64_t tier_of;
	uint8_t cache_mode;
	int64_t read_tier, write_tier;
	wrt_mg_vec properties; /* wrt_mg_kv */
	uint8_t hit_set_type;  /* the hit_set_params envelope holds this one byte (0 = none) */
	uint32_t hit_set_period, hit_set_count, stripe_width;
	uint64_t target_max_bytes, target_max_objects;
	uint32_t cache_target_dirty_ratio_micro, cache_target_full_ratio_micro, cache_min_flush_age, cache_min_evict_age;
	char erasure_code_profile[64];
	uint32_t last_force_op_resend_preluminous, min_read_recency_for_promote;
	uint64_t expected_num_objects;
	uint32_t cache_target_dirty_high_ratio_micro, min_write_recency_for_promote;
	uint8_t use_gmt_hitset, fast_read;
	uint32_t hit_set_grade_decay_rate, hit_set_search_last_n;
	wrt_mg_vec opts; /* wrt_mg_opt */
	uint32_t last_force_op_resend_prenautilus;
	wrt_mg_vec application_metadata; /* wrt_mg_app */
	wrt_mg_utime create_time;
	uint32_t pg_num_target, pgp_num_target, pg_num_pending, pg_num_dec_a, pg_num_dec_b, last_force_op_resend;
	uint8_t pg_autoscale_mode;
	uint8_t merge_meta[53]; /* last_pg_merge_meta body (v >= 29); all zero in a pool that never merged */
	uint32_t stretch_count, stretch_target, stretch_barrier; /* v == 30 only */
	int32_t stretch_mandatory;                              /* v == 30: default 0x7fffffff when unused */
	uint8_t peering_present;                                /* v >= 31: optional<tuple<4 x u32>> */
	uint32_t peering_count, peering_target, peering_barrier, peering_mandatory;
	uint64_t nonprimary_lo, nonprimary_hi; /* v >= 32: two varints, low word first */
} wrt_mg_pool;

typedef struct {
	int64_t id;
	wrt_mg_pool p;
} wrt_mg_pool_ent;

/* A replicated, HASHPSPOOL, size 3 / min_size 2 pool with `struct_v` v (29 to 32 are the supported ones). */
void wrt_mg_pool_init(wrt_mg_pool *p, uint8_t v);
void wrt_mg_pool_free(wrt_mg_pool *p);
/* Shapes the core must refuse (names are the cases of the architecture, wave 2 "osdmap-pool"). */
#define WRT_MG_SHAPE_STRETCH 1     /* v30 with a non-zero bucket count */
#define WRT_MG_SHAPE_STRETCH_V31 2 /* v31 with the optional tuple present */
#define WRT_MG_SHAPE_ERASURE 3     /* type 3, a profile name, stripe_width */
#define WRT_MG_SHAPE_TIER_OF 4
#define WRT_MG_SHAPE_TIERS 5
#define WRT_MG_SHAPE_READ_TIER 6
#define WRT_MG_SHAPE_WRITE_TIER 7
#define WRT_MG_SHAPE_EC_PROFILE 8 /* replicated type with a non-empty erasure_code_profile */
#define WRT_MG_SHAPE_HASH3 9
#define WRT_MG_SHAPE_SIZE0 10
#define WRT_MG_SHAPE_SIZE17 11
#define WRT_MG_SHAPE_PGNUM0 12
#define WRT_MG_SHAPE_PGPNUM0 13
#define WRT_MG_SHAPE_POOL_SNAPS 14 /* POOL_SNAPS flag */
#define WRT_MG_SHAPE_EIO 15       /* EIO flag */
#define WRT_MG_SHAPE_LINUX_HASH 16 /* object_hash 1 (supported, but not the default) */
#define WRT_MG_SHAPE_NO_HASHPSPOOL 17
void wrt_mg_pool_shape(wrt_mg_pool *p, int shape);

int wrt_mg_pool_encode(const wrt_mg_pool *p, wrt_mg_buf *out);
int wrt_mg_pool_parse(const uint8_t *b, size_t n, wrt_mg_pool *p);

/* ---- full OSDMap (osdmap.md 2.4) ------------------------------------------------------------------------- */

typedef struct {
	int32_t osd;
	uint32_t val;
} wrt_mg_osd_u32;
typedef struct {
	int32_t osd;
	uint32_t a, b;
} wrt_mg_osd_pair;
typedef struct {
	int32_t osd;
	uint8_t uuid[16];
} wrt_mg_osd_uuid;
typedef struct {
	int32_t osd;
	wrt_mg_addrvec av;
} wrt_mg_osd_av;
typedef struct {
	uint8_t v, compat; /* osd_xinfo_t envelope: 4 / 1 */
	wrt_mg_utime down_stamp;
	uint32_t laggy_probability, laggy_interval;
	uint64_t features;
	uint32_t old_weight;
	wrt_mg_utime last_purged_snaps_scrub; /* v >= 4 */
	uint32_t dead_epoch;                  /* v >= 4 */
} wrt_mg_xinfo;
typedef struct {
	int32_t osd;
	wrt_mg_xinfo x;
} wrt_mg_osd_xinfo;
typedef struct {
	uint32_t last_clean_begin, last_clean_end, up_from, up_thru, down_at, lost_at;
} wrt_mg_info;
typedef struct {
	wrt_mg_pg pg;
	wrt_mg_vec osds; /* int32_t */
} wrt_mg_pg_list;
typedef struct {
	wrt_mg_pg pg;
	wrt_mg_vec items; /* wrt_mg_pair */
} wrt_mg_pg_items;
typedef struct {
	wrt_mg_pg pg;
	int32_t osd;
} wrt_mg_pg_osd;
typedef struct {
	int64_t pool;
	wrt_mg_vec iv; /* wrt_mg_iv */
} wrt_mg_snapset;
typedef struct {
	wrt_mg_addr addr;
	wrt_mg_utime until;
} wrt_mg_blk;
typedef struct {
	char name[64];
	wrt_mg_vec kv; /* wrt_mg_kv */
} wrt_mg_ecprof;
typedef struct {
	int64_t id;
	char name[WRT_MG_NAME_MAX];
} wrt_mg_pname;
typedef struct {
	char s[64];
} wrt_mg_str;

typedef struct {
	/* wrapper and block versions (written / read as given) */
	uint8_t wrapper_v, wrapper_compat; /* 8 / 7 */
	uint8_t client_v, client_compat;   /* 10 / 1 (9 for a pre-reef map) */
	uint8_t osd_v, osd_compat;         /* 9 / 1 (10 to 12 add the stretch, range blocklist and crimson rows) */
	uint32_t wrapper_tail, client_tail, osd_tail; /* extra bytes (zeros) at the end of each envelope */
	uint32_t crc;      /* the value on the wire: computed by the encoder unless crc_override */
	int crc_override;  /* 1: write `crc` as given (a wrong one) */
	int crc_ok;        /* set by the parser: the stored CRC matches the bytes */

	/* client-usable block */
	uint8_t fsid[16];
	uint32_t epoch;
	wrt_mg_utime created, modified;
	wrt_mg_vec pools;      /* wrt_mg_pool_ent */
	wrt_mg_vec pool_names; /* wrt_mg_pname */
	int32_t pool_max;
	uint32_t flags;
	int32_t max_osd;
	wrt_mg_vec osd_state;  /* uint32_t */
	wrt_mg_vec osd_weight; /* uint32_t */
	wrt_mg_vec client_addrs; /* wrt_mg_addrvec */
	wrt_mg_vec pg_temp;      /* wrt_mg_pg_list */
	wrt_mg_vec primary_temp; /* wrt_mg_pg_osd */
	wrt_mg_vec osd_primary_affinity; /* uint32_t; empty = every OSD at the default */
	uint8_t *crush;    /* the CRUSH blob (owned); NULL / 0 = an empty blob */
	uint32_t crush_len;
	wrt_mg_vec erasure_code_profiles; /* wrt_mg_ecprof */
	wrt_mg_vec pg_upmap;        /* wrt_mg_pg_list */
	wrt_mg_vec pg_upmap_items;  /* wrt_mg_pg_items */
	uint32_t crush_version;     /* v >= 6 */
	wrt_mg_vec new_removed_snaps, new_purged_snaps; /* wrt_mg_snapset, v >= 7 */
	wrt_mg_utime last_up_change, last_in_change;    /* v >= 9 */
	wrt_mg_vec pg_upmap_primaries; /* wrt_mg_pg_osd, v >= 10 */

	/* OSD-only block (one entry per OSD in the realistic case; the sizes are the vectors' own) */
	wrt_mg_vec hb_back_addrs, cluster_addrs, hb_front_addrs; /* wrt_mg_addrvec */
	wrt_mg_vec osd_info;  /* wrt_mg_info */
	wrt_mg_vec blocklist; /* wrt_mg_blk */
	uint32_t cluster_snapshot_epoch;
	char cluster_snapshot[64];
	wrt_mg_vec osd_uuid; /* 16 bytes each: wrt_mg_osd_uuid with osd unused */
	wrt_mg_vec osd_xinfo; /* wrt_mg_osd_xinfo with osd unused */
	uint32_t nearfull_bits, full_bits, backfillfull_bits; /* float patterns */
	uint8_t require_min_compat_client, require_osd_release;
	wrt_mg_vec removed_snaps_queue; /* wrt_mg_snapset, v >= 6 */
	wrt_mg_vec crush_node_flags, device_class_flags; /* wrt_mg_osd_u32 (osd = id), v >= 8 / 9 */
	uint8_t stretch_mode_enabled; /* v >= 10 */
	uint32_t stretch_bucket_count, degraded_stretch_mode, recovering_stretch_mode;
	int32_t stretch_mode_bucket;
	wrt_mg_vec range_blocklist; /* wrt_mg_blk, v >= 11 */
	uint8_t allow_crimson;      /* v >= 12 */
} wrt_mg_map;

void wrt_mg_map_init(wrt_mg_map *m); /* epoch 1, empty, versions 8/7, 10/1, 9/1, the lab flags, fsid 00112233-... */
void wrt_mg_map_free(wrt_mg_map *m);
int wrt_mg_map_encode(const wrt_mg_map *m, wrt_mg_buf *out);
int wrt_mg_map_parse(const uint8_t *p, size_t n, wrt_mg_map *m); /* m is initialised by the call */
/* Deep copy through the wire form (so knobs that are not on the wire, such as crc_override, are lost). */
int wrt_mg_map_clone(const wrt_mg_map *src, wrt_mg_map *dst);

/*
 * Where the envelopes of an encoded full map or incremental lie (offsets from the start of the buffer), so a test can
 * patch a length, a version or a count without parsing: the wrapper header at 0, the client block's envelope, the
 * OSD-only block's envelope. `*_body` is the first byte after the 6-byte envelope header, `*_end` the end of the block.
 * The CRC field(s) start at osd_end. Returns -1 if the lengths do not nest (then nothing is filled).
 */
typedef struct {
	size_t wrapper_end;
	size_t client_off, client_body, client_end;
	size_t osd_off, osd_body, osd_end;
} wrt_mg_layout;
int wrt_mg_wrapper_layout(const uint8_t *p, size_t n, wrt_mg_layout *out);
/* After patching bytes of an encoded map (is_inc 0) or incremental (is_inc 1): recompute the CRC field (inc_crc for an
 * incremental; full_crc is left alone) so the patch is the only thing wrong with it. Needs wrapper struct_v >= 8. */
int wrt_mg_fix_crc(uint8_t *p, size_t n, int is_inc);

void wrt_mg_map_set_crush(wrt_mg_map *m, const wrt_mg_crush *c);
/* Table setters that keep the table sorted and replace an existing key. */
void wrt_mg_map_set_pg_temp(wrt_mg_map *m, wrt_mg_pg pg, const int32_t *osds, uint32_t n);
void wrt_mg_map_set_primary_temp(wrt_mg_map *m, wrt_mg_pg pg, int32_t osd);
void wrt_mg_map_set_pg_upmap(wrt_mg_map *m, wrt_mg_pg pg, const int32_t *osds, uint32_t n);
void wrt_mg_map_set_pg_upmap_items(wrt_mg_map *m, wrt_mg_pg pg, const wrt_mg_pair *items, uint32_t n);
void wrt_mg_map_set_upmap_primary(wrt_mg_map *m, wrt_mg_pg pg, int32_t osd);
/* Add (or replace) a pool and its name; keeps both tables sorted by id. */
void wrt_mg_map_add_pool(wrt_mg_map *m, int64_t id, const char *name, const wrt_mg_pool *p);
const wrt_mg_pool *wrt_mg_map_pool(const wrt_mg_map *m, int64_t id); /* NULL if absent */
/* Grow or shrink every per-OSD vector (client and OSD-only block) to n entries and set max_osd; new slots are state
 * 0, weight 0, empty addresses, default affinity (if the array exists), zeroed info / xinfo / uuid. */
void wrt_mg_map_resize(wrt_mg_map *m, int32_t n);

/* ---- Incremental (osdmap.md 2.6) ------------------------------------------------------------------------ */

typedef struct {
	uint8_t wrapper_v, wrapper_compat; /* 8 / 7 */
	uint8_t client_v, client_compat;   /* 9 / 1 */
	uint8_t osd_v, osd_compat;         /* 9 / 1 */
	uint32_t wrapper_tail, client_tail, osd_tail;
	uint32_t inc_crc, full_crc;
	int inc_crc_override; /* 1: write inc_crc as given */
	int inc_crc_ok;       /* set by the parser */

	/* client-usable block, rows 1 to 29 of osdmap.md 2.6.3 */
	uint8_t fsid[16];
	uint32_t epoch;
	wrt_mg_utime modified;
	int64_t new_pool_max; /* -1 = no change */
	int32_t new_flags;    /* -1 = no change */
	uint8_t *fullmap;     /* owned blob; non-empty means "this epoch is a complete map" */
	uint32_t fullmap_len;
	uint8_t *crush;       /* owned blob; empty = no change */
	uint32_t crush_len;
	int32_t new_max_osd;  /* -1 = no change */
	wrt_mg_vec new_pools;      /* wrt_mg_pool_ent */
	wrt_mg_vec new_pool_names; /* wrt_mg_pname */
	wrt_mg_vec old_pools;      /* int64_t */
	wrt_mg_vec new_up_client;  /* wrt_mg_osd_av */
	wrt_mg_vec new_state;      /* wrt_mg_osd_u32 (XOR masks) */
	wrt_mg_vec new_weight;     /* wrt_mg_osd_u32 */
	wrt_mg_vec new_pg_temp;    /* wrt_mg_pg_list (empty list removes) */
	wrt_mg_vec new_primary_temp; /* wrt_mg_pg_osd (-1 removes) */
	wrt_mg_vec new_primary_affinity; /* wrt_mg_osd_u32 */
	wrt_mg_vec new_erasure_code_profiles; /* wrt_mg_ecprof */
	wrt_mg_vec old_erasure_code_profiles; /* wrt_mg_str */
	wrt_mg_vec new_pg_upmap;        /* wrt_mg_pg_list */
	wrt_mg_vec old_pg_upmap;        /* wrt_mg_pg */
	wrt_mg_vec new_pg_upmap_items;  /* wrt_mg_pg_items */
	wrt_mg_vec old_pg_upmap_items;  /* wrt_mg_pg */
	wrt_mg_vec new_removed_snaps, new_purged_snaps; /* wrt_mg_snapset */
	wrt_mg_utime new_last_up_change, new_last_in_change;
	wrt_mg_vec new_pg_upmap_primary; /* wrt_mg_pg_osd */
	wrt_mg_vec old_pg_upmap_primary; /* wrt_mg_pg */

	/* OSD-only block */
	wrt_mg_vec new_hb_back_up, new_up_cluster, new_hb_front_up; /* wrt_mg_osd_av */
	wrt_mg_vec new_up_thru; /* wrt_mg_osd_u32 */
	wrt_mg_vec new_last_clean_interval; /* wrt_mg_osd_pair */
	wrt_mg_vec new_lost; /* wrt_mg_osd_u32 */
	wrt_mg_vec new_blocklist; /* wrt_mg_blk */
	wrt_mg_vec old_blocklist; /* wrt_mg_addr */
	char cluster_snapshot[64];
	wrt_mg_vec new_uuid;  /* wrt_mg_osd_uuid */
	wrt_mg_vec new_xinfo; /* wrt_mg_osd_xinfo */
	uint64_t features;    /* the feature set the incremental was encoded with */
	uint32_t new_nearfull_bits, new_full_bits, new_backfillfull_bits; /* float patterns; 0xbf800000 = -1.0f = unchanged */
	uint8_t new_require_min_compat_client, new_require_osd_release; /* 0xff = unchanged */
	wrt_mg_vec new_crush_node_flags, new_device_class_flags; /* wrt_mg_osd_u32 */
	uint8_t change_stretch_mode; /* v >= 10 */
	uint32_t new_stretch_bucket_count, new_degraded_stretch_mode, new_recovering_stretch_mode;
	int32_t new_stretch_mode_bucket;
	uint8_t stretch_mode_enabled;
	wrt_mg_vec new_range_blocklist; /* wrt_mg_blk, v >= 11 */
	wrt_mg_vec old_range_blocklist; /* wrt_mg_addr */
	uint8_t mutate_allow_crimson;   /* v >= 12 */
} wrt_mg_inc;

/* Epoch e, every "no change" marker set (-1, empty), versions 8/7, 9/1, 9/1. */
void wrt_mg_inc_init(wrt_mg_inc *inc, const uint8_t fsid[16], uint32_t epoch);
void wrt_mg_inc_free(wrt_mg_inc *inc);
int wrt_mg_inc_encode(const wrt_mg_inc *inc, wrt_mg_buf *out);
int wrt_mg_inc_parse(const uint8_t *p, size_t n, wrt_mg_inc *inc); /* inc is initialised by the call */
void wrt_mg_inc_set_fullmap(wrt_mg_inc *inc, const wrt_mg_map *m); /* embeds the encoded map and sets full_crc */
void wrt_mg_inc_set_crush(wrt_mg_inc *inc, const wrt_mg_crush *c);
/* Typical single edits (each appends to the right table, keeping it ascending). */
void wrt_mg_inc_mark_down(wrt_mg_inc *inc, int32_t osd);  /* new_state toggles UP */
void wrt_mg_inc_mark_up(wrt_mg_inc *inc, int32_t osd, const wrt_mg_addrvec *client); /* new_up_client (+ heartbeat / cluster copies) */
void wrt_mg_inc_set_weight(wrt_mg_inc *inc, int32_t osd, uint32_t w);
void wrt_mg_inc_set_affinity(wrt_mg_inc *inc, int32_t osd, uint32_t a);

/* ---- MOSDMap front (osdmap.md 2.3) ---------------------------------------------------------------------- */

typedef struct {
	int is_full;
	uint32_t epoch;
	const uint8_t *p; /* not copied */
	size_t n;
} wrt_mg_mitem;

/*
 * The payload front of one MOSDMap message of header version `hv` (1 to 4; 4 is what v20.2.5 sends): fsid, the
 * incrementals (items with is_full == 0, in the order given), the full maps (is_full == 1, in the order given),
 * and for hv >= 2 the trim lower bound and newest_map, for hv >= 4 `ngaps` removed-snaps gap entries (pool ids
 * 1.. each with one interval) after a count.
 */
int wrt_mg_mosdmap_front(wrt_mg_buf *out, const uint8_t fsid[16], const wrt_mg_mitem *items, uint32_t nitems,
			 uint32_t oldest, uint32_t newest, int hv, uint32_t ngaps);

/* ---- cluster builder ---------------------------------------------------------------------------------------- */

/* Use wrt_mg_cluster_spec_init: a zeroed spec means legacy tunables and the bare CRUSH header (no groups at all). */
typedef struct {
	uint32_t n_osds;
	uint32_t osds_per_host;  /* default 4 */
	uint32_t hosts_per_rack; /* 0: no rack level (root -> hosts) */
	uint32_t n_classes;      /* 0 none, 1 hdd, 2 hdd + ssd, 3 + nvme; OSD i is of class i % n_classes */
	uint8_t bucket_alg;      /* default straw2 */
	uint32_t dev_weight;     /* 16.16, default 0x10000; with weight_jitter the weight varies +-25 % */
	int weight_jitter;
	int tunables;            /* WRT_MG_TUN_*, default JEWEL */
	int crush_upto;          /* WRT_MG_UPTO_*, default CARGS */
	uint32_t choose_args_rows; /* 0 none; else one default (-1) set whose straw2 buckets carry this many weight rows */
	int choose_args_ids;       /* substitute ids in that set */
	int choose_args_pool_set;  /* a second set keyed by pool id 1 */
	uint32_t n_pools;        /* default 1 */
	uint32_t pg_num;         /* per pool, default 32 */
	uint32_t pool_size;      /* default 3 */
	uint32_t up_pct;         /* booted OSDs that are up, default 100 */
	uint32_t never_up_pct;   /* OSDs that never booted (state EXISTS|NEW, empty addresses), default 0 */
	uint32_t out_pct;        /* OSDs with weight 0, default 0 */
	uint32_t n_upmap_items, n_upmap, n_pg_temp, n_primary_temp, n_upmap_primaries; /* entries on pool 1 */
	uint32_t n_affinity;     /* OSDs with a primary affinity below the default */
	uint32_t epoch;          /* default 1 */
	uint64_t seed;
	int ipv6_every;          /* every n-th booted OSD gets IPv6 addresses (0 = none) */
	int v1_only_every;       /* every n-th booted OSD is v1 only */
} wrt_mg_cluster_spec;
/*
 * The CRUSH rules of a built cluster: rule 0 "replicated_rule" (take root, chooseleaf firstn 0 type host), rule 1
 * "replicated_osd" (take root, choose firstn 0 type osd), rule 2 "replicated_rack" (chooseleaf firstn 0 type rack)
 * only when there are racks, then one rule per device class (take the shadow root of the class, chooseleaf firstn 0
 * type host). Bucket ids: root -1, racks, hosts, then the shadow buckets of each class in class order.
 */

void wrt_mg_cluster_spec_init(wrt_mg_cluster_spec *s, uint32_t n_osds);
int wrt_mg_build_crush(wrt_mg_crush *c, const wrt_mg_cluster_spec *s);
/* A whole map (client and OSD-only blocks filled with realistic per-OSD content) including the CRUSH blob. */
int wrt_mg_build_map(wrt_mg_map *m, const wrt_mg_cluster_spec *s);

/* ---- the independent model (plain arrays) -------------------------------------------------------------------- */

#define WRT_MG_E_OK 0
#define WRT_MG_E_FSID (-1)
#define WRT_MG_E_EPOCH (-2)
#define WRT_MG_E_OSD_RANGE (-3)
#define WRT_MG_E_PARSE (-4) /* the embedded full map or the CRUSH blob did not parse */
#define WRT_MG_E_SHAPE (-5) /* the model itself is not a consistent map (a per-OSD vector shorter than max_osd), or new_max_osd is absurd */
#define WRT_MG_MAX_OSD_MODEL (1 << 22) /* the model refuses a new_max_osd above this (a hostile value would allocate gigabytes) */

/*
 * Apply an incremental to `m` in the order of osdmap.md 3.5 (the reference order, for the client rows and for
 * the per-OSD rows of the OSD-only block, so a model state can be re-encoded as a full map). On an error `m` is
 * left untouched. An empty map (epoch 0, max_osd 0) accepts epoch 1.
 */
int wrt_mg_model_apply(wrt_mg_map *m, const wrt_mg_inc *inc);
void wrt_mg_model_init(wrt_mg_map *m); /* the state before epoch 1: wrt_mg_map_init with epoch 0 */

/* Predicates of osdmap.md 2.7.1; bounds-checked against max_osd. */
int wrt_mg_exists(const wrt_mg_map *m, int32_t osd);
int wrt_mg_is_up(const wrt_mg_map *m, int32_t osd);
uint32_t wrt_mg_weight(const wrt_mg_map *m, int32_t osd);
uint32_t wrt_mg_affinity(const wrt_mg_map *m, int32_t osd);

/* The CRUSH hash of two inputs (crush note 3.2.1, written from the table of the note). */
uint32_t wrt_mg_hash32_2(uint32_t a, uint32_t b);
uint32_t wrt_mg_pg_mask(uint32_t n);                          /* (1 << bits(n - 1)) - 1; 0 for n <= 1 */
uint32_t wrt_mg_stable_mod(uint32_t x, uint32_t b, uint32_t bmask);
uint32_t wrt_mg_pg_seed(const wrt_mg_pool *p, uint32_t ps);     /* the masked PG seed */
uint32_t wrt_mg_pps(const wrt_mg_pool *p, int64_t pool_id, uint32_t ps); /* the CRUSH input x */

typedef struct {
	int32_t up[WRT_MG_MAX_REPL];
	uint32_t nup;
	int32_t up_primary; /* -1 if none */
	int32_t acting[WRT_MG_MAX_REPL];
	uint32_t nacting;
	int32_t acting_primary;
} wrt_mg_place;

/*
 * The stages after CRUSH for a replicated pool (osdmap.md 3.7 steps 6 second half to 10): drop non-existent OSDs from
 * the raw list, pg_upmap / pg_upmap_items / pg_upmap_primaries, the up set, primary affinity (hash of `pps`),
 * pg_temp / primary_temp, acting set and primaries. `pg_seed` is the masked PG seed (the table key); `raw` is what
 * CRUSH returned (it may hold WRT_MG_NONE and ids that do not exist). nraw <= WRT_MG_MAX_REPL.
 */
int wrt_mg_model_stages(const wrt_mg_map *m, int64_t pool_id, uint32_t pg_seed, uint32_t pps, const int32_t *raw,
			uint32_t nraw, wrt_mg_place *out);

/* ---- helpers for tests --------------------------------------------------------------------------------------- */

/* Read a vector file whose comment lines start with '#': hex text -> bytes (malloc'd). 0 / -1. */
int wrt_mg_load_hex_file(const char *path, uint8_t **out, size_t *n);
/* Epoch lines "<epoch> <hex>" of incrementals.hex: *out_n entries, each bytes malloc'd; free with wrt_mg_free_lines. */
typedef struct {
	uint32_t epoch;
	uint8_t *p;
	size_t n;
} wrt_mg_line;
int wrt_mg_load_epoch_lines(const char *path, wrt_mg_line **lines, size_t *nlines);
void wrt_mg_free_lines(wrt_mg_line *lines, size_t n);

/* ---- internal: the shared codec (used by wrt_mapgen.c and wrt_mapgen_crush.c; tests do not need it) -------- */

#define WRT_MG_ENC 1
#define WRT_MG_DEC 2
#define WRT_MG_FREE 3
#define WRT_MG_DEPTH 8

typedef struct {
	int mode;
	wrt_mg_buf *out;      /* ENC */
	const uint8_t *in;    /* DEC */
	size_t len, pos;
	size_t mark[WRT_MG_DEPTH]; /* ENC: offset of the length field; DEC: end of the envelope */
	int depth;
	int err;
} wrt_mg_cx;
typedef void (*wrt_mg_walk_fn)(wrt_mg_cx *cx, void *elem);

void wrt_mg_cx_u8(wrt_mg_cx *cx, uint8_t *v);
void wrt_mg_cx_u16(wrt_mg_cx *cx, uint16_t *v);
void wrt_mg_cx_u32(wrt_mg_cx *cx, uint32_t *v);
void wrt_mg_cx_s32(wrt_mg_cx *cx, int32_t *v);
void wrt_mg_cx_u64(wrt_mg_cx *cx, uint64_t *v);
void wrt_mg_cx_s64(wrt_mg_cx *cx, int64_t *v);
void wrt_mg_cx_bytes(wrt_mg_cx *cx, void *p, size_t n);
void wrt_mg_cx_blob(wrt_mg_cx *cx, uint8_t **p, uint32_t *n);
void wrt_mg_cx_str(wrt_mg_cx *cx, char *s, size_t cap);
void wrt_mg_cx_varint(wrt_mg_cx *cx, uint64_t *v);
void wrt_mg_cx_env_begin(wrt_mg_cx *cx, uint8_t *v, uint8_t *compat);
void wrt_mg_cx_env_end(wrt_mg_cx *cx, uint32_t *tail);
void wrt_mg_cx_vec(wrt_mg_cx *cx, wrt_mg_vec *v, size_t esz, wrt_mg_walk_fn fn);        /* u32 count + elements */
void wrt_mg_cx_vec_n(wrt_mg_cx *cx, wrt_mg_vec *v, uint32_t n, size_t esz, wrt_mg_walk_fn fn); /* count given */
int wrt_mg_cx_more(const wrt_mg_cx *cx);
void wrt_mg_cx_fail(wrt_mg_cx *cx);
void wrt_mg_walk_utime(wrt_mg_cx *cx, void *e);
void wrt_mg_walk_s32(wrt_mg_cx *cx, void *e);
void wrt_mg_walk_u32(wrt_mg_cx *cx, void *e);
void wrt_mg_walk_u64(wrt_mg_cx *cx, void *e);
void wrt_mg_walk_s64(wrt_mg_cx *cx, void *e);
void wrt_mg_walk_pg(wrt_mg_cx *cx, void *e);
void wrt_mg_walk_pair(wrt_mg_cx *cx, void *e);
void wrt_mg_walk_iv(wrt_mg_cx *cx, void *e);
void wrt_mg_walk_kv(wrt_mg_cx *cx, void *e);
void wrt_mg_walk_str(wrt_mg_cx *cx, void *e);
void wrt_mg_walk_crush(wrt_mg_cx *cx, wrt_mg_crush *c);

#endif /* WRT_MAPGEN_H */
