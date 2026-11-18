/* SPDX-License-Identifier: MIT */
/*
 * sim_osd_int.h - internals shared by the files of the fake OSD (sim_osd.c: lifecycle, connections, hooks, held replies, backoff and map
 * pushes, recorded ops; sim_osd_ops.c: the MOSDOp decoder, the execution of the operations and the MOSDOpReply encoder; sim_osd_cls.c: the
 * object classes and the RBD image fixtures; sim_osd_store.c: the shared object store and the duplicate log; sim_osd_auth.c: the cephx
 * server side of the OSD service). Not for tests. Test code: libc allowed.
 */
#ifndef SIM_OSD_INT_H
#define SIM_OSD_INT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sim_osd.h"
#include "wri_cursor.h"
#include "wri_ctx.h"
#include "wri_cx.h"
#include "wri_denc.h"
#include "wri_le.h"
#include "wri_m2_ctl.h"
#include "wri_misc.h"

/* ---- constants (osd-ops.md, rbd-format2.md; Linux errno values as they are on the wire) ---------------------------------- */

#define SO_EPERM 1
#define SO_ENOENT 2
#define SO_EIO 5
#define SO_ENOEXEC 8
#define SO_EAGAIN 11
#define SO_EBUSY 16
#define SO_EEXIST 17
#define SO_EINVAL 22
#define SO_EFBIG 27
#define SO_ENOSPC 28
#define SO_ENAMETOOLONG 36
#define SO_ENODATA 61
#define SO_EOLDSNAPC 85
#define SO_EMSGSIZE 90
#define SO_EOPNOTSUPP 95

#define SO_OP_READ 0x1201u
#define SO_OP_STAT 0x1202u
#define SO_OP_SPARSE_READ 0x1205u
#define SO_OP_OMAPGETKEYS 0x1211u
#define SO_OP_OMAPGETVALS 0x1212u
#define SO_OP_OMAPGETVALSBYKEYS 0x1214u
#define SO_OP_GETXATTR 0x1301u
#define SO_OP_CALL 0x1401u
#define SO_OP_WRITE 0x2201u
#define SO_OP_WRITEFULL 0x2202u
#define SO_OP_TRUNCATE 0x2203u
#define SO_OP_ZERO 0x2204u
#define SO_OP_DELETE 0x2205u
#define SO_OP_CREATE 0x220Du
#define SO_OP_SETALLOCHINT 0x2223u

#define SO_OPF_EXCL 0x1u
#define SO_OPF_FAILOK 0x2u

#define SO_F_ACK 0x1u
#define SO_F_ONDISK 0x4u
#define SO_F_ORDERSNAP 0x40u
#define SO_F_PARALLELEXEC 0x200u
#define SO_F_FULL_TRY 0x800000u
#define SO_F_FULL_FORCE 0x1000000u

#define SO_SNAP_NOSNAP 0xfffffffffffffffeull
#define SO_SNAP_MAX 0xfffffffffffffffdull

#define SO_OPREC 38u        /* ceph_osd_op */
#define SO_OPS_CAP 32u      /* operations of one message the simulator takes (the record keeps SIM_OSD_OPS_MAX) */
#define SO_SNAPS_CAP 1024u  /* snapshot ids of one context (a real image can carry hundreds; more is a decode failure here) */
#define SO_NAME_MAX 2048u   /* osd_max_object_name_len */
#define SO_NSPACE_MAX 256u
#define SO_NAME_DECODE_MAX 8192u /* longer names are a decode failure, not ENAMETOOLONG */
#define SO_OMAP_MAX_ENTRIES 1024u
#define SO_MAX_STORE_OBJECT (1ull << 30) /* hard cap of the page table */

#define SO_MSG_OSD_MAP 41u
#define SO_MSG_OSD_OP 42u
#define SO_MSG_OSD_OPREPLY 43u
#define SO_MSG_OSD_BACKOFF 61u

#define SO_PAGE 4096u

/* ---- the object store ---------------------------------------------------------------------------------------------- */

typedef struct so_page {
	uint32_t refs;
	uint8_t d[SO_PAGE];
} so_page;

typedef struct so_kv {
	uint8_t *k, *v;
	uint32_t kl, vl;
} so_kv;

typedef struct so_kvs {
	so_kv *a;
	uint32_t n, cap;
} so_kvs;

/* The state of one object (the head, or one clone): data pages (shared by reference count between a clone and the head, copied on
 * write), omap, xattrs, size, times. Invariant: the bytes of an allocated page beyond `size` are zero. */
typedef struct so_body {
	uint64_t size;
	so_page **pg;
	uint32_t npg;
	uint64_t *ex;                /* the byte ranges that hold data, sorted, disjoint, adjacent ones merged: pairs (start, end), what a SPARSE_READ reports (the
				      * lab's object store reports exact byte ranges, not blocks: a zeroed middle of a block is a hole of its own) */
	uint32_t nex, excap;
	so_kvs omap, xattr;
	uint32_t mtime_s, mtime_ns;
	uint64_t user_version;
} so_body;

typedef struct so_clone {
	uint64_t id;                 /* the snapshot context's seq at the time of the write that made it */
	uint64_t *snaps;             /* snapshots this clone is the object of, descending */
	uint32_t nsnaps;
	so_body b;
} so_clone;

typedef struct so_obj so_obj;
struct so_obj {
	so_obj *next;
	int64_t pool;
	uint8_t *key;                /* nspace 0x1f oid, or oid */
	uint32_t klen;
	uint8_t exists;              /* a live head */
	uint8_t whiteout;            /* no head, clones remain */
	uint64_t snapseq;            /* the newest snapshot context seq seen by a write */
	so_body head;
	so_clone *clones;            /* ascending id */
	uint32_t nclones, ccap;
};

#define SO_DEDUP_N 16384u        /* power of two */

typedef struct so_dedup {
	uint64_t gid, tid;
	uint32_t inc;
	int32_t result;
	uint64_t user_version, replay_ver;
	uint32_t replay_epoch;
	uint32_t next;               /* chain: entry index + 1 */
	uint8_t valid;
} so_dedup;

struct sim_store {
	so_obj **bucket;
	uint32_t nb, nobj;
	uint64_t now_s;
	uint64_t pg_version;         /* replay versions handed out */
	so_dedup *dd;                /* ring of SO_DEDUP_N */
	uint32_t *dd_head;           /* SO_DEDUP_N chain heads (entry index + 1) */
	uint32_t dd_pos, dd_count;
};

/* growable output buffer */
typedef struct so_buf {
	uint8_t *p;
	size_t len, cap;
	int oom;
} so_buf;
void so_buf_free(so_buf *b);
uint8_t *so_buf_grow(so_buf *b, size_t n);                  /* reserve n more bytes at the end, NULL on oom (sets oom) */
void so_buf_put(so_buf *b, const void *p, size_t n);
void so_buf_u8(so_buf *b, uint8_t v);
void so_buf_u32(so_buf *b, uint32_t v);
void so_buf_u64(so_buf *b, uint64_t v);
void so_buf_str(so_buf *b, const void *p, size_t n);        /* u32 length + bytes */

/* bodies */
void so_body_init(so_body *b);
void so_body_free(so_body *b);
int so_body_dup(so_body *d, const so_body *s);              /* 0 or -1 (oom); pages are shared */
int so_body_write(so_body *b, uint64_t off, const uint8_t *data, uint64_t n);   /* grows the size; 0 or -1 */
int so_body_zero(so_body *b, uint64_t off, uint64_t n);     /* inside the size: whole pages become holes */
int so_body_truncate(so_body *b, uint64_t size);
void so_body_read(const so_body *b, uint64_t off, uint8_t *out, uint64_t n);    /* holes and beyond the size are zeros */
/* extents of allocated pages clipped to [off, off + len) and the size, merged when adjacent; returns a malloc'd array of 2 * *n values */
uint64_t *so_body_extents(const so_body *b, uint64_t off, uint64_t len, uint32_t *n);
void so_body_clear_data(so_body *b);                        /* size 0, no pages (omap and xattrs stay) */

const so_kv *so_kv_get(const so_kvs *s, const void *k, uint32_t kl);
int so_kv_set(so_kvs *s, const void *k, uint32_t kl, const void *v, uint32_t vl);
int so_kv_del(so_kvs *s, const void *k, uint32_t kl);       /* 0 or -1 if absent */
uint32_t so_kv_lower(const so_kvs *s, const void *k, uint32_t kl, int *found);

/* objects */
so_obj *so_obj_find(const sim_store *s, int64_t pool, const uint8_t *key, uint32_t klen);
so_obj *so_obj_get(sim_store *s, int64_t pool, const uint8_t *key, uint32_t klen);   /* find or create an empty record */
void so_obj_purge(sim_store *s, so_obj *o);                  /* drop the record altogether */
void so_obj_wipe(so_obj *o);                                 /* free head and clones, keep the key, clear the flags and snapseq */
int so_obj_copy_state(so_obj *dst, const so_obj *src);       /* dst (wiped) gets a shallow copy of the state of src */
void so_obj_move_state(so_obj *dst, so_obj *src);            /* dst (wiped) takes the state of src, src is left empty */
int so_obj_add_clone(so_obj *o, uint64_t id, const uint64_t *snaps, uint32_t n, const so_body *from);
/* the body a read at `snapid` sees, NULL when the object was not there then */
const so_body *so_obj_at(const so_obj *o, uint64_t snapid);
void so_key_build(uint8_t *out, uint32_t *klen, const uint8_t *nspace, uint32_t nl, const uint8_t *oid, uint32_t ol); /* out holds nl + 1 + ol */

/* duplicate log */
const so_dedup *so_dedup_find(const sim_store *s, uint64_t gid, uint64_t tid, uint32_t inc);
void so_dedup_add(sim_store *s, const so_dedup *e);

/* ---- decoded request ----------------------------------------------------------------------------------------------- */

typedef struct so_opd {
	uint16_t code;
	uint32_t flags;
	uint8_t raw[SO_OPREC];       /* the record as received */
	uint32_t payload_len;
	const uint8_t *in;           /* points into the data segment */
} so_opd;

typedef struct so_req {
	uint8_t version;
	int64_t pool;
	uint32_t pg_seed, hash, epoch, flags, client_inc;
	uint64_t gid, tid;           /* the identity used for duplicate detection (client.<gid>, header tid) */
	uint32_t mtime_s, mtime_ns;
	const uint8_t *oid, *key, *nspace;
	uint32_t oid_len, key_len, nspace_len;
	uint64_t snapid, snap_seq;
	uint64_t snaps[SO_SNAPS_CAP];
	uint32_t n_snaps;
	int32_t retry_attempt;
	uint32_t n_ops;
	so_opd ops[SO_OPS_CAP];
	const uint8_t *data;         /* the data segment */
	uint32_t data_len;
} so_req;

/* the answer under construction */
typedef struct so_rep {
	int32_t result;
	uint8_t executed;            /* ACK | ONDISK recomputed */
	uint8_t do_redirect;
	int64_t redirect_pool;
	uint8_t rec[SO_OPS_CAP][SO_OPREC];
	int32_t rval[SO_OPS_CAP];
	uint32_t outlen[SO_OPS_CAP];
	so_buf out;                  /* the outputs back to back in op order */
	uint64_t replay_ver, user_version;
	uint32_t replay_epoch;
} so_rep;

/* ---- classes ------------------------------------------------------------------------------------------------------- */

/* what a method sees of the object it runs on */
typedef struct so_cctx {
	sim_store *store;
	so_body *body;
	uint8_t exists;
	uint8_t dirty;               /* set when the method changed the object */
	uint64_t gid;                /* the caller's global id (the locker identity) */
	uint8_t addr[35];            /* the caller's address as entity_addr_t, type forced to legacy */
	uint64_t now_s;
	const char *oid;             /* NUL terminated copy of the object name */
	uint32_t oid_len;
} so_cctx;

typedef int32_t (*so_cls_fn)(so_cctx *cx, const uint8_t *in, uint32_t inlen, so_buf *out);

/* 0 = known (fn, writes set), -1 = unknown class, -2 = unknown method of a known class */
int so_cls_lookup(const char *cls, uint32_t cl, const char *method, uint32_t ml, so_cls_fn *fn, uint8_t *writes);

/* ---- the OSD ------------------------------------------------------------------------------------------------------- */

#define SO_BACKOFFS 16u
#define SO_PAY 1024u

typedef struct so_backoff {
	uint8_t used, acked, begin_max, end_max;
	uint64_t id;
	int64_t pool;
	uint32_t pg_seed;
	char begin[SIM_OSD_NAME_MAX], end[SIM_OSD_NAME_MAX];
	uint32_t begin_hash, end_hash;
} so_backoff;

struct sim_osd_conn {
	sim_osd *osd;
	sim_m2 *m2;
	uint32_t index;
	uint8_t killed;
	/* cephx */
	uint8_t stage;               /* 0 none, 1 challenge sent, 2 authenticated */
	uint64_t gid, nonce, challenge;
	wr_key key;
	uint8_t tkt_blob[1100];      /* the ticket of the first authorizer: the second must carry the same */
	uint32_t tkt_len;
	uint8_t pay[SO_PAY];
	so_backoff bo[SO_BACKOFFS];
	uint32_t n_msgs;
	wr_status send_err;
};

typedef struct so_held {
	sim_osd_conn *c;
	uint64_t tid;
	uint8_t *front, *data;
	uint32_t flen, dlen;
	uint32_t rec;                /* index in the recorded ops, UINT32_MAX = none */
} so_held;

typedef struct so_parked {
	sim_osd_conn *c;
	uint8_t version;
	uint64_t tid;
	uint8_t *front, *data;
	uint32_t flen, dlen;
} so_parked;

struct sim_osd {
	sim_osd_cfg cfg;
	uint32_t epoch;
	wri_ctx *x;
	uint64_t rng;
	sim_osd_conn *conns[SIM_OSD_MAX_CONNS];
	uint32_t n_accepted;
	sim_osd_rec *recs;
	uint32_t n_recs;
	uint32_t n_requests, n_other, n_violations, n_acks, n_backoff_drops;
	so_held held[SIM_OSD_HELD_MAX];
	uint32_t n_held;
	so_parked parked[SIM_OSD_HELD_MAX];
	uint32_t n_parked;
	uint32_t cut_count;          /* requests handled while cut_after_ops was armed */
	int (*cls_hook)(void *ctx, sim_osd_cls_call *call, int run);
	void *cls_hook_ctx;
	uint8_t reentry;             /* handling a parked request: no nested parking release */
};

/* sim_osd.c */
uint64_t so_rand64(sim_osd *o);
void so_rand(sim_osd *o, uint8_t *out, size_t n);
const wri_ctx *so_ctx(const sim_osd *o);
wr_status so_send_msg(sim_osd_conn *c, uint16_t type, uint64_t tid, uint16_t version, uint16_t compat, const uint8_t *front, uint32_t flen,
		      const uint8_t *data, uint32_t dlen);
void so_violation(sim_osd_conn *c, const char *what, uint64_t a0, uint64_t a1);
void so_cut_all(sim_osd *o);

/* sim_osd_ops.c */
void so_on_message(void *ctx, sim_m2 *s, const sim_m2_msg *m);
/* handle one decoded-from-wire MOSDOp (also used to replay a parked one): front + data as received */
void so_handle_osdop(sim_osd_conn *c, uint8_t version, uint64_t msg_tid, const uint8_t *front, uint32_t flen, const uint8_t *data, uint32_t dlen,
		     int parked);
int so_backoff_covers(const sim_osd_conn *c, const so_req *rq);
void so_backoff_note(sim_osd_conn *c, const uint8_t *front, uint32_t flen);

/* sim_osd_auth.c */
int so_auth_request(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p, uint32_t n, sim_m2_auth_reply *rep);
int so_auth_more(void *ctx, const uint8_t *p, uint32_t n, sim_m2_auth_reply *rep);

/* sim_osd_cls.c: nothing beyond so_cls_lookup and the fixtures of the public header */

#endif /* SIM_OSD_INT_H */
