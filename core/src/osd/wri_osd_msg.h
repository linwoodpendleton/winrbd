/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_msg.h - the OSD messages of the object client: MOSDOp (client to OSD), MOSDOpReply, MOSDBackoff, and the encodings
 * of the operation outputs the client reads. Pure functions over bytes and cursors: no state, no allocation, no connection.
 * Spec: docs/spec/osd-ops.md (cited as osd-ops.md 2.3 and so on); design: docs/design/core-architecture.md section 22.
 *
 * Conventions of the core apply: every wire value goes through the cursors, every count is capped before use, decoded
 * structures borrow from the input buffer (a pointer is valid as long as the buffer is), a decoder that fails leaves its output
 * cleared. The symbolic names below are ours (WRI_OSD_OP_*, WRI_OSDF_*); the numbers are protocol constants (osd-ops.md 2.4,
 * 2.6, 2.10, 2.11).
 *
 * One request message carries up to WRI_OSD_OPS_MAX operations against ONE object, runs them in order and stops at the first
 * failure (osd-ops.md 2.7). The data segment of the message is the concatenation of the operations' input bytes in operation
 * order; the data segment of the reply is the concatenation of their outputs. The owner of a request lays the input bytes out
 * itself (zero-copy for a write: its own buffer; for header calls: a small buffer) and the encoder only needs each operation's
 * length, so no scratch memory is needed here.
 *
 * Module osd-msg: wri_osd_msg.c (request encoder), wri_osd_rep.c (reply and output decoders), wri_osd_bo.c (backoff, hobject).
 */
#ifndef WRI_OSD_MSG_H
#define WRI_OSD_MSG_H

#include "wr_err.h"
#include "wr_types.h"
#include "wri_cursor.h"

/* ---- message types, versions, priority (osd-ops.md 2.1) ---------------------------------------------------------- */

#define WRI_MSG_OSD_MAP 41u      /* MOSDMap pushed by an OSD: discarded by the object client (design 21.4) */
#define WRI_MSG_OSD_OP 42u
#define WRI_MSG_OSD_OPREPLY 43u
#define WRI_MSG_OSD_BACKOFF 61u
#define WRI_MOSDOP_VERSION 9u        /* what a v20.2.5 OSD wants (SERVER_SQUID); 8 is the same without the otel field */
#define WRI_MOSDOP_VERSION_V8 8u
#define WRI_MOSDOP_COMPAT 3u
#define WRI_MOSDOPREPLY_VERSION 8u   /* the only reply version decoded; compat must be <= 8 */
#define WRI_MOSDBACKOFF_VERSION 1u
#define WRI_MSG_PRIO_CLIENT 63u      /* priority of every request and of the backoff ack */

/* ---- limits ------------------------------------------------------------------------------------------------------ */

#define WRI_OSD_OPS_MAX 8u       /* operations in one message: the open reads of an image are 8 calls (design 24.2) */
#define WRI_OSD_OID_MAX 96u      /* object name bytes the request table stores (an RBD name is at most 95) */
#define WRI_OSD_NAME_LIMIT 2048u /* the OSD refuses longer names or locator keys (osd-ops.md 2.11); a namespace is at most 256 */
#define WRI_OSD_SPARSE_EXT_MAX 64u /* extents of a sparse-read output the decoder keeps */

/* ---- operation codes (osd-ops.md 2.6) ---------------------------------------------------------------------------- */

#define WRI_OSD_OP_READ 0x1201u
#define WRI_OSD_OP_STAT 0x1202u
#define WRI_OSD_OP_SPARSE_READ 0x1205u
#define WRI_OSD_OP_WRITE 0x2201u
#define WRI_OSD_OP_WRITEFULL 0x2202u
#define WRI_OSD_OP_TRUNCATE 0x2203u
#define WRI_OSD_OP_ZERO 0x2204u
#define WRI_OSD_OP_DELETE 0x2205u
#define WRI_OSD_OP_CREATE 0x220Du
#define WRI_OSD_OP_SETALLOCHINT 0x2223u
#define WRI_OSD_OP_GETXATTR 0x1301u
#define WRI_OSD_OP_CALL 0x1401u
#define WRI_OSD_OP_OMAPGETVALS 0x1212u
#define WRI_OSD_OP_OMAPGETVALSBYKEYS 0x1214u
/* The v1 object client sends READ, WRITE, ZERO, TRUNCATE, DELETE and CALL; the others are encoded and decoded (tests, later
 * milestones) but never chosen by the request layers. */

/* ---- message flags (osd-ops.md 2.4) and per-operation flags (2.5) ------------------------------------------------- */

#define WRI_OSDF_ONDISK 0x00000004u        /* set on every request */
#define WRI_OSDF_RETRY 0x00000008u         /* set by the encoder exactly when retry_attempt != 0 */
#define WRI_OSDF_READ 0x00000010u
#define WRI_OSDF_WRITE 0x00000020u
#define WRI_OSDF_KNOWN_REDIR 0x00400000u   /* set on every request */
#define WRI_OSDF_ORDERSNAP 0x00000040u     /* writes, config switch: the OSD answers EOLDSNAPC when our snapshot context is older than the object's */
#define WRI_OSDF_FULL_TRY 0x00800000u      /* writes: a full pool answers ENOSPC / EDQUOT instead of dropping the write */
#define WRI_OSDF_SUPPORTSPOOLEIO 0x08000000u /* set on every request; then the CLIENT fails operations on a pool with the EIO flag */
#define WRI_OSDF_BASE_READ (WRI_OSDF_ONDISK | WRI_OSDF_READ | WRI_OSDF_KNOWN_REDIR | WRI_OSDF_SUPPORTSPOOLEIO)   /* 0x08400014 */
#define WRI_OSDF_BASE_WRITE (WRI_OSDF_ONDISK | WRI_OSDF_WRITE | WRI_OSDF_KNOWN_REDIR | WRI_OSDF_SUPPORTSPOOLEIO) /* 0x08400024 */
#define WRI_OSD_OPF_EXCL 0x1u
#define WRI_OSD_OPF_FAILOK 0x2u

#define WRI_SNAP_NOSNAP 0xfffffffffffffffeull /* snapid of the live object */
#define WRI_SNAP_MAX 0xfffffffffffffffdull    /* highest valid snapshot id (a snapshot context's seq is at most this) */

/* ---- errno values on the wire (Linux numbers, negative in result and rval) --------------------------------------- */

#define WRI_ERRNO_EPERM 1
#define WRI_ERRNO_ENOENT 2
#define WRI_ERRNO_EIO 5
#define WRI_ERRNO_EAGAIN 11
#define WRI_ERRNO_EEXIST 17
#define WRI_ERRNO_EINVAL 22
#define WRI_ERRNO_EFBIG 27
#define WRI_ERRNO_ENOSPC 28
#define WRI_ERRNO_EOPNOTSUPP 95
#define WRI_ERRNO_EDQUOT 122
#define WRI_ERRNO_EBLOCKLISTED 108
#define WRI_ERRNO_EOLDSNAPC 85

/*
 * The wr_status of an OSD errno (result or rval, as a negative number): 0 -> WR_OK, ENOENT and EOPNOTSUPP -> WR_E_OSD_NOENT,
 * EPERM -> WR_E_OSD_PERM, EIO -> WR_E_OSD_IO, ENOSPC and EDQUOT -> WR_E_OSD_NOSPC, EBLOCKLISTED -> WR_E_OSD_BLOCKLISTED,
 * anything else negative -> WR_E_OSD_ERRNO (the caller puts the number into errinfo.peer_result). EAGAIN never reaches a caller
 * (the request layer resubmits it). A positive result is success.
 */
wr_status wri_osd_errno_status(int32_t result);

/* ---- the request (osd-ops.md 2.3, version 9 / 8) ------------------------------------------------------------------ */

/* One operation of a message. The first block is the input of the encoder, the second the output of the reply decoder. */
typedef struct wri_osd_opd {
	uint16_t code;            /* WRI_OSD_OP_* */
	uint16_t flags;           /* per-operation flags: WRI_OSD_OPF_* */
	uint32_t in_len;          /* bytes this operation takes from the data segment (WRITE: length; CALL: class + method + argument) */
	uint64_t off;             /* extent operations: offset (TRUNCATE: the new size; SETALLOCHINT: expected object size) */
	uint64_t len;             /* extent operations: length (READ: bytes wanted; SETALLOCHINT: expected write size). GETXATTR (name_len = in_len)
	                           * and the omap reads (offset 0, length = in_len, as the stock client sends them) take no off / len: the
	                           * encoder derives their records from in_len and ignores both fields. */
	uint8_t cls_class_len;    /* CALL: the first bytes of its input are the class name, then the method name, then the argument */
	uint8_t cls_method_len;
	uint8_t reserved8[2];
	/* ---- filled by wri_mosdopreply_decode, read by the owner ---- */
	uint32_t out_len;         /* bytes this operation put into the reply's data segment */
	int32_t rval;             /* this operation's result: 0, or a negative errno; positive values are method specific (CALL) */
} wri_osd_opd;

/* Snapshot context of a write (osd-ops.md 3.9; rbd-format2.md 2.5). The owner (the image) keeps the array. */
typedef struct wri_snapc {
	uint64_t seq;             /* the image's snap_seq */
	uint32_t n;               /* snapshots that exist, strictly descending, each at most seq */
	uint32_t cap;             /* room of `snaps` */
	uint64_t *snaps;
} wri_snapc;
/* 1 if (seq, snaps) is a valid context: seq <= WRI_SNAP_MAX, snaps[0] <= seq, strictly descending, no 0 followed by another. NULL is the
 * empty context (valid), as in wri_mosdop_hdr.snapc. The array is read for n entries; `cap` is not looked at. */
int wri_snapc_valid(const wri_snapc *s);

/* Everything about a request message that is not an operation. */
typedef struct wri_mosdop_hdr {
	uint8_t version;          /* WRI_MOSDOP_VERSION (9) or WRI_MOSDOP_VERSION_V8 (8: no otel field) */
	uint8_t reserved8[3];
	int64_t pool;             /* data or metadata pool id */
	uint32_t pg_seed;         /* the PG seed of the target (after stable_mod): spg_t pgid = (pool, seed, shard -1) */
	uint32_t hash;            /* the full 32-bit placement hash of the object (wr_target.ps) */
	uint32_t map_epoch;       /* the epoch of the map the target was computed in */
	uint32_t flags;           /* WRI_OSDF_*; the encoder adds RETRY itself */
	uint32_t mtime_sec, mtime_nsec; /* wall clock for mutating operations, 0 for reads (design 22.3) */
	const uint8_t *oid;       /* object name */
	uint32_t oid_len;
	const uint8_t *nspace;    /* RADOS namespace, normally empty */
	uint32_t nspace_len;
	uint64_t snapid;          /* WRI_SNAP_NOSNAP; must be that for any message that may write */
	const wri_snapc *snapc;   /* write snapshot context, NULL = empty (seq 0, no snapshots); reads ignore it */
	int32_t retry_attempt;    /* 0 on the first transmission, +1 for every resend of the same tid */
	uint64_t features;        /* the connection's negotiated feature word (wri_m2_conn.features) */
} wri_mosdop_hdr;

/* Upper bound of the front segment of a request, for sizing buffers: the fixed part, the object name, the operations, the context. */
size_t wri_mosdop_front_max(uint32_t oid_len, uint32_t nspace_len, unsigned n_ops, uint32_t n_snaps);

/*
 * Encode the front segment of an MOSDOp into w (the data segment is the owner's: sum of ops[i].in_len bytes). Checks what the
 * OSD would answer EINVAL / ENAMETOOLONG for or crash on, so none of it is sent: version 8 or 9 (WR_E_UNSUPPORTED), n_ops 1 ..
 * WRI_OSD_OPS_MAX, empty name or a name above WRI_OSD_NAME_LIMIT / namespace above 256 (WR_E_RANGE), a write-capable
 * message whose snapid is not NOSNAP or whose context is invalid (WR_E_INVAL; the image layer judges contexts earlier, WR_E_RBD_SNAPC), a
 * CALL whose class + method lengths exceed in_len (WR_E_INVAL), a WRITE / WRITEFULL whose `len` differs from its in_len (the OSD answers
 * EINVAL: WR_E_INVAL), an operation code outside the table of design 22.2 (WR_E_UNSUPPORTED), a data segment above 4 GiB - 1 or a
 * negative pool (WR_E_RANGE), a retry_attempt below 0 (WR_E_INVAL). A message is write-capable when WRI_OSDF_WRITE is set in `flags` or
 * any operation code has the mutating mode bit (0x2000). A refusal writes nothing and leaves `w` untouched; RETRY in `flags` is
 * replaced by the one derived from retry_attempt; a read message always carries snap_seq 0 and no snapshots. reqid.inc and client_inc
 * are both 0. WR_E_TOOBIG if w is too small (w->err is set the usual way; the bytes already written are then incomplete).
 */
WR_MUST_CHECK wr_status wri_mosdop_encode(wri_wr *w, const wri_mosdop_hdr *h, const wri_osd_opd *ops, unsigned n_ops);

/* The 38-byte per-operation record (osd-ops.md 2.5); exposed for tests and for the reply decoder. */
#define WRI_OSD_OPREC_LEN 38u
void wri_osd_op_put(wri_wr *w, const wri_osd_opd *op);

/* ---- the reply (osd-ops.md 2.9, version 8) ----------------------------------------------------------------------- */

typedef struct wri_mosdopreply {
	const uint8_t *oid;       /* echo of the object name (borrowed from the input) */
	uint32_t oid_len;
	int64_t pool;             /* pgid of the PG that handled it */
	uint32_t pg_seed;
	int64_t flags;            /* 64 bit in the reply */
	int32_t result;           /* the message result: negative errno on failure */
	uint32_t map_epoch;       /* the OSD's epoch when it replied */
	uint32_t n_ops;           /* at most WRI_OSD_OPS_MAX */
	uint16_t op_code[WRI_OSD_OPS_MAX]; /* the echoed codes (a ZERO may come back as TRUNCATE) */
	uint32_t out_len[WRI_OSD_OPS_MAX]; /* payload_len of each echoed record: that op's output bytes */
	int32_t rval[WRI_OSD_OPS_MAX];
	int32_t retry_attempt;    /* echo of the request's */
	uint64_t user_version;
	uint8_t do_redirect;      /* the OSD redirected the request: the object client fails it (WR_E_OSD_REDIRECT) */
	uint64_t out_total;       /* sum of out_len: must equal the data segment length (checked by the decoder's caller) */
} wri_mosdopreply;

/*
 * Decode a reply front. msg_version / msg_compat come from the msgr2 header: a reply whose compat_version is above 8 or whose
 * version is not 8 is WR_E_OSD_VERSION. Every count capped (n_ops above WRI_OSD_OPS_MAX is WR_E_OSD_PROTO), the oid length
 * checked, the whole front consumed apart from the trailing 24-byte trace block, which must be there and is ignored (so a front cut
 * at any offset fails). Every malformed front (truncated, oversized, pg_t version byte not 1) is WR_E_OSD_PROTO; *out is cleared on
 * failure. A redirect is only detected (`do_redirect`), its body is skipped by its length. The echoed code and out_len of each
 * operation are kept; an `rval` is kept raw (the caller maps it with wri_osd_errno_status).
 */
WR_MUST_CHECK wr_status wri_mosdopreply_decode(const uint8_t *front, size_t n, uint16_t msg_version, uint16_t msg_compat,
					       wri_mosdopreply *out);

/* ---- operation outputs ------------------------------------------------------------------------------------------- */

typedef struct wri_osd_extent {
	uint64_t off, len;
} wri_osd_extent;

/*
 * SPARSE_READ output (osd-ops.md 2.7): u32 n, n x (u64 offset, u64 length), u32 data_len, the data. Validates that the extents are
 * strictly ascending, do not overlap, lie inside [req_off, req_off + req_len) and add up to data_len, and that the data really
 * is in the buffer. *data_off is where the data starts in `out` (the extent bytes follow back to back); the data must fill `out` to its
 * end. At most min(ext_max, WRI_OSD_SPARSE_EXT_MAX) extents are kept: a longer table is WR_E_TOOBIG, every other defect (truncated,
 * lying count, overlap, outside the request, lengths that do not add up) is WR_E_OSD_PROTO; on failure the three results are 0 and the
 * extent slots the table named are cleared. A zero-length extent is accepted (it adds nothing). `ext` may be NULL when ext_max is 0.
 * Not used by the v1 image layer (it reads with READ, design 22.2); decoded for tests and for a later bounce-buffer mode.
 */
WR_MUST_CHECK wr_status wri_osd_sparse_decode(const uint8_t *out, uint32_t n, uint64_t req_off, uint64_t req_len,
					      wri_osd_extent *ext, uint32_t ext_max, uint32_t *n_ext, uint32_t *data_off,
					      uint32_t *data_len);
/* STAT output: u64 size, utime mtime (u32 sec, u32 nsec): exactly 16 bytes, anything else is WR_E_OSD_PROTO (results then 0). */
WR_MUST_CHECK wr_status wri_osd_stat_decode(const uint8_t *out, uint32_t n, uint64_t *size, uint32_t *mtime_sec,
					    uint32_t *mtime_nsec);

/* ---- MOSDBackoff (osd-ops.md 2.10, 3.7) -------------------------------------------------------------------------- */

#define WRI_BACKOFF_BLOCK 1u
#define WRI_BACKOFF_ACK_BLOCK 2u
#define WRI_BACKOFF_UNBLOCK 3u

/* hobject_t as the backoff carries it (full encoding); strings borrow from the input. */
typedef struct wri_hobj {
	const uint8_t *key;
	const uint8_t *oid;
	const uint8_t *nspace;
	uint32_t key_len, oid_len, nspace_len;
	uint64_t snap;
	uint32_t hash;            /* the 32-bit hash, compared bit-reversed (osd-ops.md 2.10) */
	uint8_t max;              /* sorts above everything */
	uint8_t reserved8[3];
	int64_t pool;
} wri_hobj;

typedef struct wri_mbackoff {
	int64_t pool;
	uint32_t pg_seed;
	uint32_t map_epoch;
	uint8_t op;               /* WRI_BACKOFF_* */
	uint64_t id;              /* unique within the OSD session */
	wri_hobj begin, end;      /* begin == end: that one object; else the half-open range [begin, end) */
} wri_mbackoff;

/* Decode a backoff front. The message has no struct header of its own: msg_version must be at least 1 and msg_compat at most 1, else
 * WR_E_OSD_VERSION (a later minor version may append fields after the two positions, which are ignored; version 1 must end there).
 * Strings capped at WRI_OSD_NAME_LIMIT (key, oid) and 256 (namespace); op 1 .. 3; the shard of the pgid must be -1 (replicated pools
 * only); a position's struct header older than version 4 or with a compat above 4 is WR_E_OSD_VERSION. Any other defect is
 * WR_E_OSD_PROTO. The output is cleared on failure; the strings borrow from `front`. */
WR_MUST_CHECK wr_status wri_mbackoff_decode(const uint8_t *front, size_t n, uint16_t msg_version, uint16_t msg_compat,
					    wri_mbackoff *out);
/* The ACK_BLOCK answer: the same pgid, id, begin and end as the BLOCK it answers and the BLOCK's map_epoch. `block` must be a decoded
 * BLOCK (op WRI_BACKOFF_BLOCK, else WR_E_INVAL). Needs `w` big enough (WR_E_TOOBIG): exactly wri_mbackoff_ack_len(block) bytes, which
 * is WRI_MBACKOFF_FIXED_LEN + the lengths of the six strings (key, oid, namespace of begin and of end); the caller sizes its buffer
 * from the BLOCK it holds (at most WRI_MBACKOFF_FIXED_LEN + 2 * (2048 + 2048 + 256) bytes). */
WR_MUST_CHECK wr_status wri_mbackoff_encode_ack(wri_wr *w, const wri_mbackoff *block);
#define WRI_MBACKOFF_FIXED_LEN 115u /* spg_t 24 + epoch 4 + op 1 + id 8 + two positions of 39 bytes without their strings */
size_t wri_mbackoff_ack_len(const wri_mbackoff *block);
/* Total order of osd-ops.md 2.10: max flag, pool, bit-reversed hash, namespace, effective key (key, or the name when the key is empty),
 * name, snapshot id. <0, 0, >0. */
int wri_hobj_cmp(const wri_hobj *a, const wri_hobj *b);
/* The position of one of our own requests: pool, hash, namespace, key empty, name, snapshot NOSNAP. */
void wri_hobj_of_request(wri_hobj *h, int64_t pool, uint32_t hash, const uint8_t *nspace, uint32_t nspace_len,
			 const uint8_t *oid, uint32_t oid_len);
/* 1 if `pos` lies in the backoff: begin <= pos < end, or pos == begin when begin == end (the entry's own PG is the caller's check). */
int wri_mbackoff_covers(const wri_mbackoff *b, const wri_hobj *pos);

#endif /* WRI_OSD_MSG_H */
