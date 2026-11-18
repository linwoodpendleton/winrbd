/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_msg.c - the MOSDOp request encoder (osd-ops.md 2.3 to 2.6), the 38-byte operation record, the snapshot context rule,
 * the errno to status table and the front size bound. Pure functions over the cursors: no state, no allocation.
 * The reply and the operation outputs are in wri_osd_rep.c, the backoff and the hobject order in wri_osd_bo.c.
 */
#include "wri_osd_msg.h"

#include "wri_denc.h"

WR_FILE_LICENCE_MIT

/* Mode bit of an operation code that makes it a mutating operation (osd-ops.md 2.6: mode WR 0x2000). */
#define OPC_MODE_WR 0x2000u
#define NS_LIMIT 256u               /* longest RADOS namespace the OSD accepts */
#define FIXED_FRONT 178u            /* every byte of a v9 front that does not depend on name, namespace, operations or snapshots */

/* ---- errno to status (design 22.5) ---------------------------------------------------------------------------------------- */

wr_status wri_osd_errno_status(int32_t result)
{
	if (result >= 0)
		return WR_OK;
	switch (result) {
	case -WRI_ERRNO_ENOENT:
	case -WRI_ERRNO_EOPNOTSUPP:
		return WR_E_OSD_NOENT;
	case -WRI_ERRNO_EPERM:
		return WR_E_OSD_PERM;
	case -WRI_ERRNO_EIO:
		return WR_E_OSD_IO;
	case -WRI_ERRNO_ENOSPC:
	case -WRI_ERRNO_EDQUOT:
		return WR_E_OSD_NOSPC;
	case -WRI_ERRNO_EBLOCKLISTED:
		return WR_E_OSD_BLOCKLISTED;
	default:
		return WR_E_OSD_ERRNO;
	}
}

/* ---- snapshot context ------------------------------------------------------------------------------------------------------ */

int wri_snapc_valid(const wri_snapc *s)
{
	uint32_t i;

	if (s == NULL) /* no context at all is the empty context */
		return 1;
	if (s->seq > WRI_SNAP_MAX)
		return 0;
	if (s->n == 0)
		return 1;
	if (s->snaps == NULL || s->snaps[0] > s->seq)
		return 0;
	/* Strictly descending also covers "an id 0 is never followed by another": nothing sorts below 0. */
	for (i = 1; i < s->n; i++)
		if (s->snaps[i] >= s->snaps[i - 1u])
			return 0;
	return 1;
}

/* ---- sizes ------------------------------------------------------------------------------------------------------------------ */

size_t wri_mosdop_front_max(uint32_t oid_len, uint32_t nspace_len, unsigned n_ops, uint32_t n_snaps)
{
	/* 64-bit arithmetic: the largest inputs (2^32 + 2^32 + 8 * 2^32 + 38 * 2^32) stay far below 2^64. */
	uint64_t n = (uint64_t)FIXED_FRONT + (uint64_t)oid_len + (uint64_t)nspace_len + (uint64_t)WRI_OSD_OPREC_LEN * (uint64_t)n_ops +
		     8u * (uint64_t)n_snaps;

	if (n > (uint64_t)(size_t)-1) /* only on a 32-bit host, for absurd inputs the encoder refuses anyway */
		return (size_t)-1;
	return (size_t)n;
}

/* ---- the operation record (osd-ops.md 2.5) ------------------------------------------------------------------------------- */

void wri_osd_op_put(wri_wr *w, const wri_osd_opd *op)
{
	uint32_t in_len;
	uint32_t names;

	if (w == NULL)
		return;
	if (op == NULL) {
		wri_wr_fail(w, WR_E_INVAL);
		return;
	}
	in_len = op->in_len;
	wri_wr_u16(w, op->code);
	wri_wr_u32(w, op->flags);
	if (op->code == WRI_OSD_OP_CALL) {
		/* cls variant: u8 class_len, u8 method_len, u8 argc (unused), u32 indata_len, the rest of the 28 byte union zero */
		names = (uint32_t)op->cls_class_len + (uint32_t)op->cls_method_len;
		wri_wr_u8(w, op->cls_class_len);
		wri_wr_u8(w, op->cls_method_len);
		wri_wr_u8(w, 0);
		wri_wr_u32(w, in_len >= names ? in_len - names : 0u);
		wri_wr_zero(w, 21);
	} else if (op->code == WRI_OSD_OP_GETXATTR) {
		/* xattr variant: u32 name_len, u32 value_len (0), cmp_op, cmp_mode, the rest zero. The OSD cuts the attribute name out of the
		 * input by name_len, so an extent-shaped record (offset 0) would ask for the attribute named "" and always miss. */
		wri_wr_u32(w, in_len);
		wri_wr_zero(w, 24);
	} else if (op->code == WRI_OSD_OP_OMAPGETVALS || op->code == WRI_OSD_OP_OMAPGETVALSBYKEYS) {
		/* The OSD reads the arguments of the omap reads from the input only; the stock client puts offset 0 and length = input length
		 * into the extent fields (captured), so the same bytes go out whatever the owner left in off and len. */
		wri_wr_u64(w, 0);
		wri_wr_u64(w, in_len);
		wri_wr_u64(w, 0);
		wri_wr_u32(w, 0);
	} else {
		/* extent variant: offset, length, truncate_size 0, truncate_seq 0. SETALLOCHINT carries its two sizes in the first
		 * two fields, which sit at the same places. */
		wri_wr_u64(w, op->off);
		wri_wr_u64(w, op->len);
		wri_wr_u64(w, 0);
		wri_wr_u32(w, 0);
	}
	wri_wr_u32(w, in_len);
}

/* ---- the request ------------------------------------------------------------------------------------------------------------- */

/* 1 for an operation the encoder knows how to send (design 22.2; CMPEXT, WRITESAME, ASSERT_VER, watch and notify are refused). */
static int op_known(uint16_t code)
{
	switch (code) {
	case WRI_OSD_OP_READ:
	case WRI_OSD_OP_STAT:
	case WRI_OSD_OP_SPARSE_READ:
	case WRI_OSD_OP_WRITE:
	case WRI_OSD_OP_WRITEFULL:
	case WRI_OSD_OP_TRUNCATE:
	case WRI_OSD_OP_ZERO:
	case WRI_OSD_OP_DELETE:
	case WRI_OSD_OP_CREATE:
	case WRI_OSD_OP_SETALLOCHINT:
	case WRI_OSD_OP_GETXATTR:
	case WRI_OSD_OP_CALL:
	case WRI_OSD_OP_OMAPGETVALS:
	case WRI_OSD_OP_OMAPGETVALSBYKEYS:
		return 1;
	default:
		return 0;
	}
}

/* The operations: known codes, the length rules of WRITE / WRITEFULL (the OSD answers EINVAL when extent.length differs from the
 * input) and of CALL, a data segment that fits the u32 of the frame. *may_write is set when any operation can mutate. */
static wr_status check_ops(const wri_osd_opd *ops, unsigned n_ops, int *may_write)
{
	uint64_t total = 0;
	unsigned i;

	for (i = 0; i < n_ops; i++) {
		const wri_osd_opd *o = &ops[i];

		if (!op_known(o->code))
			return WR_E_UNSUPPORTED;
		if ((o->code & OPC_MODE_WR) != 0u)
			*may_write = 1;
		if ((o->code == WRI_OSD_OP_WRITE || o->code == WRI_OSD_OP_WRITEFULL) && o->len != (uint64_t)o->in_len)
			return WR_E_INVAL;
		if (o->code == WRI_OSD_OP_CALL &&
		    (uint32_t)o->cls_class_len + (uint32_t)o->cls_method_len > o->in_len)
			return WR_E_INVAL;
		total += o->in_len;
	}
	if (total > 0xFFFFFFFFull)
		return WR_E_RANGE;
	return WR_OK;
}

/* Everything the encoder refuses before writing a byte (design 22.3). */
static wr_status check_request(const wri_mosdop_hdr *h, const wri_osd_opd *ops, unsigned n_ops, int *may_write)
{
	wr_status st;

	if (h->version != WRI_MOSDOP_VERSION && h->version != WRI_MOSDOP_VERSION_V8)
		return WR_E_UNSUPPORTED;
	if (n_ops < 1u || n_ops > WRI_OSD_OPS_MAX)
		return WR_E_RANGE;
	if (h->oid_len == 0 || h->oid_len > WRI_OSD_NAME_LIMIT || h->nspace_len > NS_LIMIT || h->pool < 0)
		return WR_E_RANGE;
	if (h->oid == NULL || (h->nspace == NULL && h->nspace_len != 0))
		return WR_E_INVAL;
	if (h->retry_attempt < 0)
		return WR_E_INVAL;
	*may_write = (h->flags & WRI_OSDF_WRITE) != 0u;
	st = check_ops(ops, n_ops, may_write);
	if (st != WR_OK)
		return st;
	if (*may_write && (h->snapid != WRI_SNAP_NOSNAP || !wri_snapc_valid(h->snapc)))
		return WR_E_INVAL;
	return WR_OK;
}

/* spg_t of a replicated pool: struct v1 compat 1, then pg_t (version byte 1, pool, seed, retired -1) and shard -1 (24 bytes). */
static void put_spg(wri_wr *w, int64_t pool, uint32_t seed)
{
	size_t mark = wri_env_begin(w, 1, 1);

	wri_wr_u8(w, 1);
	wri_wr_u64(w, (uint64_t)pool);
	wri_wr_u32(w, seed);
	wri_wr_i32(w, -1);
	wri_wr_u8(w, 0xFFu);
	wri_env_end(w, mark);
}

/* object_locator_t: pool, retired -1, empty key, namespace, hash -1 (struct v6 compat 3: the hash is not used). */
static void put_oloc(wri_wr *w, int64_t pool, const uint8_t *nspace, uint32_t nspace_len)
{
	size_t mark = wri_env_begin(w, 6, 3);

	wri_wr_i64(w, pool);
	wri_wr_i32(w, -1);
	wri_wr_u32(w, 0);
	wri_denc_put_blob(w, nspace, nspace_len);
	wri_wr_i64(w, -1);
	wri_env_end(w, mark);
}

/* osd_reqid_t: struct v2 compat 2, entity name (type 0, num 0), tid 0, inc 0 (the OSD builds the real one; osd-ops.md 2.3). */
static void put_reqid(wri_wr *w)
{
	size_t mark = wri_env_begin(w, 2, 2);

	wri_wr_u8(w, 0);
	wri_wr_u64(w, 0);
	wri_wr_u64(w, 0);
	wri_wr_i32(w, 0);
	wri_env_end(w, mark);
}

wr_status wri_mosdop_encode(wri_wr *w, const wri_mosdop_hdr *h, const wri_osd_opd *ops, unsigned n_ops)
{
	int may_write = 0;
	uint32_t flags;
	uint32_t i;
	wr_status st;

	if (w == NULL || h == NULL || ops == NULL)
		return WR_E_INVAL;
	st = check_request(h, ops, n_ops, &may_write);
	if (st != WR_OK)
		return st;

	/* RETRY is derived, never taken from the caller. */
	flags = h->flags & ~WRI_OSDF_RETRY;
	if (h->retry_attempt != 0)
		flags |= WRI_OSDF_RETRY;

	put_spg(w, h->pool, h->pg_seed);
	wri_wr_u32(w, h->hash);
	wri_wr_u32(w, h->map_epoch);
	wri_wr_u32(w, flags);
	put_reqid(w);
	wri_wr_zero(w, 24);                     /* blkin trace */
	if (h->version == WRI_MOSDOP_VERSION) { /* otel trace: struct v1 compat 1 len 1, not valid */
		wri_wr_u8(w, 1);
		wri_wr_u8(w, 1);
		wri_wr_u32(w, 1);
		wri_wr_u8(w, 0);
	}
	wri_wr_u32(w, 0);                       /* client_inc, equal to reqid.inc */
	wri_denc_put_utime(w, h->mtime_sec, h->mtime_nsec);
	put_oloc(w, h->pool, h->nspace, h->nspace_len);
	wri_denc_put_blob(w, h->oid, h->oid_len);
	wri_wr_u16(w, (uint16_t)n_ops);
	for (i = 0; i < n_ops; i++)
		wri_osd_op_put(w, &ops[i]);
	wri_wr_u64(w, h->snapid);
	if (may_write && h->snapc != NULL) {
		wri_wr_u64(w, h->snapc->seq);
		wri_wr_u32(w, h->snapc->n);
		for (i = 0; i < h->snapc->n && wri_wr_ok(w); i++)
			wri_wr_u64(w, h->snapc->snaps[i]);
	} else { /* reads ignore the context on the OSD: seq 0 and no ids */
		wri_wr_u64(w, 0);
		wri_wr_u32(w, 0);
	}
	wri_wr_i32(w, h->retry_attempt);
	wri_wr_u64(w, h->features);
	return w->err;
}
