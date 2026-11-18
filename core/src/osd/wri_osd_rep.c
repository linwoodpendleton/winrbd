/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_rep.c - decoders of what an OSD sends back: the MOSDOpReply front (osd-ops.md 2.9, version 8) and the outputs of
 * SPARSE_READ and STAT (osd-ops.md 2.7). Network-facing parsers: every count is capped before use, every length is checked
 * against the bytes at hand, the output is cleared on failure, nothing is allocated. A malformed message is WR_E_OSD_PROTO
 * (truncated, oversized, inconsistent); a version the decoder does not implement is WR_E_OSD_VERSION.
 */
#include "wri_osd_msg.h"

#include "wri_denc.h"

WR_FILE_LICENCE_MIT

#define REPLY_TRACE_LEN 24u        /* the blkin trace block that ends a v8 reply front: required, ignored */
#define EVERSION_LEN 12u           /* u64 version + u32 epoch */
#define OPREC_PAYLOAD_AT 34u       /* offset of payload_len in the 38 byte record */

/* ---- MOSDOpReply v8 ---------------------------------------------------------------------------------------------------------- */

/* The echoed operation records: the code and the payload length of each, the rest of the 38 bytes (flags and the argument union)
 * is not needed by the client. */
static void read_op_records(wri_rd *r, wri_mosdopreply *out)
{
	uint32_t i;

	for (i = 0; i < out->n_ops; i++) {
		const uint8_t *rec = wri_rd_bytes(r, WRI_OSD_OPREC_LEN);

		if (rec == NULL)
			return;
		out->op_code[i] = (uint16_t)((uint16_t)rec[0] | (uint16_t)((uint16_t)rec[1] << 8));
		out->out_len[i] = (uint32_t)rec[OPREC_PAYLOAD_AT] | ((uint32_t)rec[OPREC_PAYLOAD_AT + 1u] << 8) |
				  ((uint32_t)rec[OPREC_PAYLOAD_AT + 2u] << 16) | ((uint32_t)rec[OPREC_PAYLOAD_AT + 3u] << 24);
		out->out_total += out->out_len[i];
	}
}

/* The fields after the operation records: retry_attempt, rval[], replay_version (skipped), user_version, do_redirect, the redirect
 * struct (skipped by its length: the client fails a redirected request, it never follows it) and the trace block. */
static void read_reply_tail(wri_rd *r, wri_mosdopreply *out)
{
	uint32_t i;

	out->retry_attempt = wri_rd_i32(r);
	for (i = 0; i < out->n_ops; i++)
		out->rval[i] = wri_rd_i32(r);
	wri_rd_skip(r, EVERSION_LEN);
	out->user_version = wri_rd_u64(r);
	out->do_redirect = wri_rd_u8(r) != 0u ? 1u : 0u;
	if (out->do_redirect != 0u) {
		wri_env e;

		if (wri_env_open(r, 1, &e) != WR_OK)
			wri_rd_fail(r, WR_E_OSD_PROTO);
	}
	/* The trace block always ends a v8 front (an OSD writes it even when tracing is off). A shorter front is not a v8 reply; extra
	 * bytes after it would belong to a later minor revision and are ignored. */
	if (wri_rd_left(r) < REPLY_TRACE_LEN)
		wri_rd_fail(r, WR_E_OSD_PROTO);
}

wr_status wri_mosdopreply_decode(const uint8_t *front, size_t n, uint16_t msg_version, uint16_t msg_compat, wri_mosdopreply *out)
{
	wri_rd r;
	uint32_t oid_len = 0;
	uint32_t count;
	uint8_t pg_ver;

	if (out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	if (front == NULL && n != 0)
		return WR_E_INVAL;
	if (msg_version != WRI_MOSDOPREPLY_VERSION || msg_compat > WRI_MOSDOPREPLY_VERSION)
		return WR_E_OSD_VERSION;

	wri_rd_init(&r, front, n);
	out->oid = wri_denc_blob(&r, &oid_len, WRI_OSD_NAME_LIMIT);
	out->oid_len = oid_len;
	pg_ver = wri_rd_u8(&r); /* pg_t: a version byte, not an envelope */
	out->pool = (int64_t)wri_rd_u64(&r);
	out->pg_seed = wri_rd_u32(&r);
	wri_rd_skip(&r, 4); /* the retired preferred-OSD field */
	out->flags = wri_rd_i64(&r);
	out->result = wri_rd_i32(&r);
	wri_rd_skip(&r, EVERSION_LEN); /* bad_replay_version: legacy */
	out->map_epoch = wri_rd_u32(&r);
	count = wri_rd_u32(&r);
	if (wri_rd_ok(&r) && (pg_ver != 1u || count > WRI_OSD_OPS_MAX))
		wri_rd_fail(&r, WR_E_OSD_PROTO);
	if (wri_rd_ok(&r)) {
		out->n_ops = count;
		read_op_records(&r, out);
	}
	if (wri_rd_ok(&r))
		read_reply_tail(&r, out);
	if (!wri_rd_ok(&r)) {
		WR_MEMSET(out, 0, sizeof(*out));
		return WR_E_OSD_PROTO;
	}
	return WR_OK;
}

/* ---- SPARSE_READ output -------------------------------------------------------------------------------------------------------- */

static void sparse_clear(wri_osd_extent *ext, uint32_t upto, uint32_t *n_ext, uint32_t *data_off, uint32_t *data_len)
{
	uint32_t i;

	for (i = 0; i < upto; i++) {
		ext[i].off = 0;
		ext[i].len = 0;
	}
	*n_ext = 0;
	*data_off = 0;
	*data_len = 0;
}

wr_status wri_osd_sparse_decode(const uint8_t *out, uint32_t n, uint64_t req_off, uint64_t req_len, wri_osd_extent *ext,
				uint32_t ext_max, uint32_t *n_ext, uint32_t *data_off, uint32_t *data_len)
{
	wri_rd r;
	uint32_t count;
	uint32_t i = 0;
	uint32_t cap = ext_max < WRI_OSD_SPARSE_EXT_MAX ? ext_max : WRI_OSD_SPARSE_EXT_MAX;
	uint64_t used = 0; /* bytes of the request range covered so far: the next extent starts at or after req_off + used */
	uint64_t sum = 0;
	uint32_t dlen;

	if (n_ext == NULL || data_off == NULL || data_len == NULL || (ext == NULL && ext_max != 0) || (out == NULL && n != 0))
		return WR_E_INVAL;
	sparse_clear(ext, 0, n_ext, data_off, data_len);

	wri_rd_init(&r, out, n);
	count = wri_rd_u32(&r);
	if (!wri_rd_ok(&r))
		return WR_E_OSD_PROTO;
	if ((size_t)count > wri_rd_left(&r) / 16u) /* more extents than the bytes can hold: a lie about the size */
		return WR_E_OSD_PROTO;
	if (count > cap) /* plausible, but more than the caller (or WRI_OSD_SPARSE_EXT_MAX) keeps */
		return WR_E_TOOBIG;
	for (; i < count; i++) {
		uint64_t eo = wri_rd_u64(&r);
		uint64_t el = wri_rd_u64(&r);
		uint64_t rel;

		/* Positions relative to the request, so req_off + req_len cannot overflow: ascending and disjoint means the extent
		 * starts at or after the end of the previous one, inside means it ends within req_len. */
		if (eo < req_off)
			break;
		rel = eo - req_off;
		if (rel < used || rel > req_len || el > req_len - rel)
			break;
		ext[i].off = eo;
		ext[i].len = el;
		used = rel + el;
		sum += el; /* <= req_len: the extents are disjoint and inside the range */
	}
	dlen = wri_rd_u32(&r);
	if (i != count || !wri_rd_ok(&r) || (uint64_t)dlen != sum || (size_t)dlen != wri_rd_left(&r)) {
		sparse_clear(ext, count, n_ext, data_off, data_len); /* every slot the table could have touched */
		return WR_E_OSD_PROTO;
	}
	*n_ext = count;
	*data_off = (uint32_t)r.pos;
	*data_len = dlen;
	return WR_OK;
}

/* ---- STAT output ------------------------------------------------------------------------------------------------------------- */

wr_status wri_osd_stat_decode(const uint8_t *out, uint32_t n, uint64_t *size, uint32_t *mtime_sec, uint32_t *mtime_nsec)
{
	wri_rd r;
	uint64_t sz;
	uint32_t sec, nsec;

	if (size == NULL || mtime_sec == NULL || mtime_nsec == NULL || (out == NULL && n != 0))
		return WR_E_INVAL;
	*size = 0;
	*mtime_sec = 0;
	*mtime_nsec = 0;
	wri_rd_init(&r, out, n);
	sz = wri_rd_u64(&r);
	sec = wri_rd_u32(&r);
	nsec = wri_rd_u32(&r);
	if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0)
		return WR_E_OSD_PROTO;
	*size = sz;
	*mtime_sec = sec;
	*mtime_nsec = nsec;
	return WR_OK;
}
