/* SPDX-License-Identifier: MIT */
/*
 * sim_osd.h - a fake OSD for tests (harness code, libc allowed, never part of the core), built on the msgr2 test server sim_m2 and the
 * fake monitor sim_mon, in the way sim_mon is. Module sim-osd (docs/design/core-architecture.md section 29, wave 1): the interface up to the
 * "additions" block at the end is the one the skeleton froze; the additions only add (store access, the class hook, epochs, counters). Files:
 * sim_osd.c (lifecycle, connections, hooks), sim_osd_ops.c (MOSDOp decoder, executor, reply encoder), sim_osd_cls.c (rbd / lock classes and the image
 * fixtures), sim_osd_store.c (the shared store and the dedup log), sim_osd_auth.c (cephx for the OSD service). Tests: test_sim_osd*.c with the
 * hand-driven client of harness/test/sim_osd_rig.h.
 *
 * What was checked against the lab's OSD (BlueStore, v20.2.5) and is modelled on purpose: SPARSE_READ reports EXACT byte ranges of the data that was written
 * (a zeroed middle of a block is a hole of its own, ranges that touch are one range, written zeros are data, a truncate cuts, an extension adds nothing); ZERO is
 * turned into a TRUNCATE when it reaches the end and then the TRUNCATE still checks the original length (off + len above the limit is -EFBIG), every other ZERO
 * checks the range before it looks at the object; a full pool refuses what makes an object appear or grow, found out by running the operations (an overwrite in
 * place, ZERO, TRUNCATE down and DELETE are served); the end of the last PG of a pool is the "max" hobject_t (SIM_OSD_BO_MAX). Not modelled: a DELETE that comes
 * after a recreate in the same message ([DELETE, CREATE, DELETE] leaves the old object in place on the lab), a sequence no stock client sends.
 *
 * Where the simulator pins a point the notes leave open or contradict: an unknown class is -EPERM and an unknown method of rbd / lock -EOPNOTSUPP
 * (the capture, rbd-format2.md 2.2; osd-ops.md 2.7 says -EOPNOTSUPP for both); the reply of a duplicate echoes the ops without output and rvals 0 and
 * the stored result; ZERO echoed as TRUNCATE keeps its length field; reads answer result 0 and rval 0 with the byte count in the record's extent
 * length (vector 03); the dedup log is cluster wide (a PG log is replicated), so a resend to another OSD of the same store is recognised too.
 *
 * Written from docs/spec/osd-ops.md and rbd-format2.md from the SERVER's point of view; it shares no code with the client modules it tests
 * (osd-msg, osd-sess, osd-req, rbd-*): it carries its own small MOSDOp decoder and MOSDOpReply encoder (so a misreading of the notes in the
 * client is not repeated here, R9), and from the core it uses only the m2 frame layer through sim_m2, the cephx cipher / envelope layer to verify an
 * authorizer (as sim_mon does) and, optionally, the placement module (sim_osd_cfg.check_primary, documented as sharing the core's placement).
 *
 * One sim_osd is one OSD daemon with a cluster-wide object store it shares with its siblings (sim_store): the tests create ONE store, N OSDs on
 * it, and let the test pump route each dialled address to an OSD. What it does, per connection (a sim_m2 server underneath, fed and drained by the
 * test as sim_mon is):
 *   - cephx server side for the OSD service: the authorizer (u8 1, global id, service, ticket blob, sealed CephXAuthorize) is verified against the
 *     tickets of the sim_mon it is told about (sim_mon_ticket_valid and the issued session key), a challenge round trip is answered
 *     (AUTH_REPLY_MORE with the server challenge, AUTH_DONE with nonce + 1), a ticket the monitor did not issue or an expired one is AUTH_BAD_METHOD -13;
 *   - MOSDOp v9 / v8 (type 42): decoded, checked (epoch parking, misdirected / stale-epoch silence, size and name limits, EINVAL cases, snapid, snapshot
 *     context validity), executed in operation order against the store with the semantics of osd-ops.md 2.7 (READ, SPARSE_READ, STAT, WRITE,
 *     WRITEFULL, ZERO -> TRUNCATE rewrite, TRUNCATE, DELETE, CREATE, SETALLOCHINT, GETXATTR, OMAPGETVALS, CALL), answered with MOSDOpReply v8;
 *   - duplicate detection by (global id, tid) for writes, like the PG log: a resent write is answered with the stored result and not applied twice;
 *   - the object classes `rbd` (the header methods of rbd-format2.md 2.3) and `lock` (get_info, lock, unlock, break_lock) over images created with
 *     sim_rbd_image_create, and a hook for any other class;
 *   - snapshot semantics for self-managed snapshots: a write whose context carries a snapshot newer than the object's last-seen one makes a clone, a
 *     read with a snapid reads the clone, a DELETE with live snapshots leaves a whiteout (rbd-format2.md 3.6): enough to check that a client's writes preserve
 *     snapshots;
 *   - MOSDBackoff (BLOCK, ACK_BLOCK, UNBLOCK) scripted by the test, MOSDMap pushes (type 41) scripted by the test.
 *
 * Fault hooks (sim_osd_fault): reply silence (the OSD drops: misdirected, stale epoch, full pool without FULL_TRY), N dropped replies, an abrupt cut after N
 * ops (the lossy-session loss), EAGAIN replies, forced errnos per op code, redirect replies, held replies released by the test, replies in reverse
 * order, a reply with a damaged length, a very slow reader (sim_m2's out_chunk), and a clock for "the OSD applied the write but the answer was lost".
 */
#ifndef SIM_OSD_H
#define SIM_OSD_H

#include "sim_m2.h"
#include "sim_mon.h"

#define SIM_OSD_MAX_CONNS 32u
#define SIM_OSD_REC_MAX 4096u     /* operations recorded per OSD (the test asserts on them) */
#define SIM_OSD_OPS_MAX 8u
#define SIM_OSD_HELD_MAX 64u
#define SIM_OSD_NAME_MAX 128u

/* ---- the shared object store ------------------------------------------------------------------------------------------- */

typedef struct sim_store sim_store;

sim_store *sim_store_new(void);
void sim_store_free(sim_store *s);

/* Direct access for the test (not through the wire): the oracle the client's reads and writes are compared with. */
wr_status sim_store_write(sim_store *s, int64_t pool, const char *oid, uint64_t off, const uint8_t *data, size_t n);
/* Reads [off, off + n) into out with holes and a missing object as zeros; *exists says whether the object exists. */
wr_status sim_store_read(sim_store *s, int64_t pool, const char *oid, uint64_t off, uint8_t *out, size_t n, int *exists);
wr_status sim_store_size(sim_store *s, int64_t pool, const char *oid, uint64_t *size); /* WR_E_RANGE if the object does not exist */
uint32_t sim_store_n_objects(const sim_store *s);

/* An RBD image as the store holds it (header state structured; the class methods answer from it): creates rbd_id.<name>, rbd_header.<id>, no data
 * objects. features and the optional parts exactly as rbd-format2.md describes them, so every refusal of the open can be provoked. */
typedef struct sim_rbd_image_cfg {
	int64_t pool;               /* metadata pool id */
	const char *name;
	const char *id;
	uint64_t size;
	uint8_t order;              /* default 22 */
	uint64_t features;
	uint64_t flags;
	int64_t data_pool;          /* -1 = none */
	uint64_t stripe_unit, stripe_count; /* both 0 = not set */
	uint64_t snap_seq;
	uint32_t n_snaps;
	uint64_t snaps[16];         /* descending */
	uint8_t has_parent;         /* parent_get reports one (pool 1, image "parent", snapshot 2), overlap = size */
	uint64_t op_features;
	const char *prefix;         /* NULL = "rbd_data.<id>" (or "rbd_data.<pool>.<id>" with a data pool) */
	uint8_t lock_held;          /* lock get_info reports a foreign exclusive locker */
} sim_rbd_image_cfg;
wr_status sim_rbd_image_create(sim_store *s, const sim_rbd_image_cfg *c);
/* The test changes the header after the open (a snapshot appears, the image shrinks, a feature is enabled): the next header read sees it. */
wr_status sim_rbd_image_set_snapc(sim_store *s, int64_t pool, const char *id, uint64_t seq, const uint64_t *snaps, uint32_t n);
wr_status sim_rbd_image_set_size(sim_store *s, int64_t pool, const char *id, uint64_t size);
wr_status sim_rbd_image_set_features(sim_store *s, int64_t pool, const char *id, uint64_t features);

/* ---- one OSD ------------------------------------------------------------------------------------------------------------ */

typedef struct sim_osd_fault {
	uint8_t silent;                  /* answer no request at all (a misdirected or stale-epoch drop, a full pool) */
	uint32_t drop_replies;           /* drop the next N replies (the op IS executed): "applied, answer lost" */
	uint32_t cut_after_ops;          /* != 0: cut every connection abruptly once this many requests were handled */
	uint32_t eagain_ops;             /* answer the next N requests -EAGAIN before executing them */
	uint8_t redirect;                /* answer requests with a redirect reply */
	int32_t force_errno_op;          /* != 0: ops with this code fail with force_errno (whole message, before execution) */
	int32_t force_errno;
	uint8_t hold_replies;            /* queue replies until sim_osd_release() */
	uint8_t reverse_release;         /* sim_osd_release() sends the held replies newest first */
	uint8_t bad_reply_len;           /* the reply's data segment is one byte shorter than the sum of its payload_lens */
	uint8_t no_dedup;                /* do not detect duplicate writes (to prove the client's fence does not rely on it) */
	uint8_t pool_full_drop;          /* the pool is full: a message that makes an object appear or grow is dropped without FULL_TRY, answered -ENOSPC with it,
					  * and goes through with FULL_FORCE; everything that does not grow (overwrite in place, ZERO, TRUNCATE down, DELETE, reads) is served */
	uint32_t min_epoch;              /* requests stamped with a lower epoch are dropped silently (the OSD is "ahead") */
	uint8_t refuse_auth;             /* complete the authorizer round trip, then AUTH_BAD_METHOD -13 (a key without OSD caps) */
} sim_osd_fault;

typedef struct sim_osd_cfg {
	sim_m2_cfg m2;                   /* base of every connection; entity type OSD (the defaults set it) */
	sim_mon *mon;                    /* the monitor whose OSD tickets this OSD accepts (required) */
	sim_store *store;                /* the object store of the cluster (required) */
	int32_t id;                      /* OSD id, also the ordinal in the recorded ops */
	uint64_t seed;
	uint32_t epoch;                  /* the map epoch this OSD claims in replies; 0 = no map of its own: nothing is parked and the
					  * reply carries the request's epoch. != 0: a request stamped with a LATER epoch is parked (no
					  * answer) until sim_osd_set_epoch() reaches it, and replies carry this epoch */
	uint8_t check_primary;           /* != 0: silently drop requests whose (pool, pg_seed, epoch) this OSD is not the acting primary of, per `is_primary` */
	int (*is_primary)(void *ctx, int32_t osd, int64_t pool, uint32_t pg_seed, uint32_t hash, uint32_t epoch);
	void *is_primary_ctx;
	uint8_t v8_only;                 /* advertise features without SERVER_SQUID: the client must fall back to MOSDOp v8 or refuse */
	uint32_t max_write_bytes;        /* osd_max_write_size, default 90 MiB */
	uint32_t max_object_bytes;       /* osd_max_object_size, default 128 MiB */
	sim_osd_fault fault;
} sim_osd_cfg;

void sim_osd_cfg_default(sim_osd_cfg *c);

/* What the OSD recorded of one request (the test asserts on tids, retry attempts, epochs, flags and the ops). */
typedef struct sim_osd_rec {
	uint32_t conn;                   /* connection index (accept order) */
	uint64_t tid, global_id;
	uint32_t epoch, flags, hash, pg_seed, retry_attempt;
	int64_t pool;
	char oid[SIM_OSD_NAME_MAX];
	uint64_t snapid, snap_seq;
	uint32_t n_snaps;
	uint8_t version;
	uint32_t n_ops;
	uint16_t op_code[SIM_OSD_OPS_MAX];
	uint64_t op_off[SIM_OSD_OPS_MAX], op_len[SIM_OSD_OPS_MAX];
	int32_t result;                  /* what was answered, 0 for a dropped reply, INT32_MIN when nothing was sent */
	uint8_t executed, duplicate, dropped_reply;
	uint8_t mutating;                /* what the OSD made of the message (any mutating op, a mutating class method included) */
	uint8_t parked;                  /* waited for a newer map epoch before it was handled */
	uint8_t backoff_drop;            /* dropped silently because it lay inside an acknowledged backoff */
	uint8_t held;                    /* the reply was queued by hold_replies */
	uint32_t data_len;               /* bytes of the data segment of the request */
	int32_t op_rval[SIM_OSD_OPS_MAX];
	uint32_t op_out[SIM_OSD_OPS_MAX]; /* bytes of output of each op as answered */
} sim_osd_rec;

typedef struct sim_osd sim_osd;
typedef struct sim_osd_conn sim_osd_conn;

/* NULL on a bad configuration or out of memory. */
sim_osd *sim_osd_new(const sim_osd_cfg *cfg);
void sim_osd_free(sim_osd *o);
sim_osd_fault *sim_osd_faults(sim_osd *o);            /* change the fault plan while running */

sim_osd_conn *sim_osd_accept(sim_osd *o);              /* server banner queued; NULL when SIM_OSD_MAX_CONNS are live */
void sim_osd_conn_free(sim_osd_conn *c);
size_t sim_osd_feed(sim_osd_conn *c, const uint8_t *p, size_t n);
size_t sim_osd_drain(sim_osd_conn *c, uint8_t *out, size_t cap);
int sim_osd_closed(const sim_osd_conn *c);
sim_m2 *sim_osd_conn_m2(sim_osd_conn *c);              /* the msgr2 server underneath: its fault hooks, recorded frames, errors */

/* The OSD "restarts": every connection is cut at once, held replies are lost, the dedup log is kept (a PG log survives). */
void sim_osd_restart(sim_osd *o);
/* Send up to n held replies (0 = all); returns how many. */
uint32_t sim_osd_release(sim_osd *o, uint32_t n);
/* As begin_oid / end_oid of sim_osd_send_backoff: the "max" hobject_t (max flag set), what the end of the last PG of a pool is on the wire. */
#define SIM_OSD_BO_MAX "\xff\xfe<hobject max>"
/* Server-initiated messages on a connection: a BLOCK / UNBLOCK of the given object range (hobject strings, hash, pg), an MOSDMap push (type 41). */
wr_status sim_osd_send_backoff(sim_osd_conn *c, uint8_t op, uint64_t id, int64_t pool, uint32_t pg_seed, uint32_t map_epoch,
			       const char *begin_oid, uint32_t begin_hash, const char *end_oid, uint32_t end_hash);
wr_status sim_osd_send_map_push(sim_osd_conn *c, const uint8_t *front, uint32_t n);

const sim_osd_rec *sim_osd_recs(const sim_osd *o, uint32_t *n);
void sim_osd_recs_clear(sim_osd *o);
uint32_t sim_osd_n_conns_accepted(const sim_osd *o);
uint32_t sim_osd_n_acks(const sim_osd *o);             /* ACK_BLOCK messages received from the client */


/* ---- additions of the sim-osd module (the frozen part above is unchanged) ---------------------------------------------- */

/* Store: more direct access for tests (not through the wire). A write through sim_store_write() bypasses the snapshot logic. */
int sim_store_exists(const sim_store *s, int64_t pool, const char *oid);          /* a live head (a whiteout does not count) */
int sim_store_is_whiteout(const sim_store *s, int64_t pool, const char *oid);
uint32_t sim_store_n_clones(const sim_store *s, int64_t pool, const char *oid);
/* Reads the object as of snapshot `snapid` (UINT64_MAX - 1 = the head); *exists = 0 when the object was not there then (out is zeros). */
wr_status sim_store_read_snap(sim_store *s, int64_t pool, const char *oid, uint64_t snapid, uint64_t off, uint8_t *out, size_t n,
			      int *exists);
wr_status sim_store_remove(sim_store *s, int64_t pool, const char *oid);          /* the head, its clones and everything: WR_E_RANGE if absent */
/* Omap and xattrs (the omap of an object that does not exist is created with the object). key / value are raw bytes. */
wr_status sim_store_omap_set(sim_store *s, int64_t pool, const char *oid, const char *key, const uint8_t *val, size_t n);
wr_status sim_store_omap_rm(sim_store *s, int64_t pool, const char *oid, const char *key);   /* WR_E_RANGE if absent */
wr_status sim_store_omap_get(sim_store *s, int64_t pool, const char *oid, const char *key, uint8_t *out, size_t cap, size_t *n);
wr_status sim_store_xattr_set(sim_store *s, int64_t pool, const char *oid, const char *name, const uint8_t *val, size_t n);
wr_status sim_store_xattr_get(sim_store *s, int64_t pool, const char *oid, const char *name, uint8_t *out, size_t cap, size_t *n);
uint64_t sim_store_version(const sim_store *s, int64_t pool, const char *oid);    /* the object's user version, 0 if absent */
/* The store's clock in seconds (class lock expirations): default 1700000000. */
void sim_store_set_time(sim_store *s, uint64_t sec);
/* The duplicate-detection log (the "PG log": cluster wide, so a resend to another OSD is recognised too). */
int sim_store_dedup_has(const sim_store *s, uint64_t global_id, uint64_t tid);
uint32_t sim_store_dedup_count(const sim_store *s);

/* A class other than rbd / lock: run = 0 classifies (return 1 when the method exists, set call->writes), run = 1 executes
 * (fill out / out_len / rval). An unknown class without a hook is -EPERM, an unknown method of rbd / lock -EOPNOTSUPP (the capture). */
typedef struct sim_osd_cls_call {
	const char *cls, *method;        /* NUL terminated */
	const uint8_t *in;
	uint32_t in_len;
	uint8_t *out;                    /* 64 KiB */
	uint32_t out_cap, out_len;
	int32_t rval;
	uint8_t writes;
} sim_osd_cls_call;
void sim_osd_set_class_hook(sim_osd *o, int (*fn)(void *ctx, sim_osd_cls_call *call, int run), void *ctx);

/* The OSD's own map epoch (cfg.epoch != 0): parked requests whose epoch is now reached are handled, in arrival order. */
void sim_osd_set_epoch(sim_osd *o, uint32_t epoch);
uint32_t sim_osd_n_parked(const sim_osd *o);
uint32_t sim_osd_n_held(const sim_osd *o);
uint32_t sim_osd_n_violations(const sim_osd *o);       /* requests the OSD could not decode or that broke a rule a stock client keeps (the connection was closed) */
uint32_t sim_osd_n_backoff_drops(const sim_osd *o);    /* requests dropped inside an acknowledged backoff */
uint32_t sim_osd_n_requests(const sim_osd *o);         /* every MOSDOp decoded, recorded or not */
uint32_t sim_osd_n_other(const sim_osd *o);            /* messages of other types received (counted, ignored) */
uint32_t sim_osd_epoch(const sim_osd *o);              /* the epoch the OSD holds now */

#endif /* SIM_OSD_H */
