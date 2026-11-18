/* SPDX-License-Identifier: MIT */
/*
 * osd_msg_rig.h - shared by the osd-msg tests: loads the captured exchanges of harness/vectors/osdop/ (request and reply fronts with
 * their decoded summaries) and turns a request summary back into the encoder's inputs. Test-only (libc allowed).
 *
 * The summaries do not carry everything: the mtime of a write and the argument fields of SETALLOCHINT are read from the captured
 * front itself (fixed offsets of osd-ops.md 2.3 and 2.5); everything else comes from the summary.
 */
#ifndef OSD_MSG_RIG_H
#define OSD_MSG_RIG_H

#include "wrt.h"
#include "wri_osd_msg.h"

#define RIG_NVEC 19u

static const char *const rig_vec_name[RIG_NVEC] = {
	"01-rados-put-small.json",        "02-rados-stat.json",           "03-rados-read-whole.json",
	"04-rados-read-enoent.json",      "05-rados-delete.json",         "06-rados-put-big-chunk.json",
	"07-rbd-write-64k.json",          "08-rbd-sparse-read-64k.json",  "09-rbd-open-compound-5calls.json",
	"10-rbd-lock-get-info.json",      "11-rbd-mirror-image-get-enoent.json", "12-rbd-write-call-failing.json",
	"13-rbd-create-then-call.json",   "14-omap-getvals-byk.json",     "15-omap-getvals-page2.json",
	"16-eperm-write.json",            "17-k1-rbd-get-size.json",      "18-secure-mode-read.json",
	"19-note-5-1-example.json"};

/* Offsets inside a v9 request front (osd-ops.md 2.3): the fixed part up to the mtime. */
#define RIG_MTIME_AT 98u
#define RIG_OTEL_AT 87u
#define RIG_OTEL_LEN 7u

/* A number of a JSON document that may exceed int64 (snapid, features): the digits after the first `"key": `. */
static WRT_UNUSED uint64_t rig_u64_after(const wrt_json *j, const char *key, uint64_t dflt)
{
	char pat[64];
	const char *p;

	snprintf(pat, sizeof(pat), "\"%s\":", key);
	p = strstr(j->text, pat);
	if (p == NULL)
		return dflt;
	p += strlen(pat);
	while (*p == ' ')
		p++;
	return (uint64_t)strtoull(p, NULL, 10);
}

static WRT_UNUSED int64_t rig_int(const wrt_json *j, wrt_tok obj, const char *key, int64_t dflt)
{
	wrt_tok t = wrt_json_get(j, obj, key);
	int ok = 0;
	int64_t v;

	if (t == WRT_NONE)
		return dflt;
	v = wrt_json_int(j, t, &ok);
	return ok ? v : dflt;
}

static WRT_UNUSED int rig_has(const wrt_json *j, wrt_tok obj, const char *key)
{
	return wrt_json_get(j, obj, key) != WRT_NONE;
}

typedef struct rig_vec {
	wrt_json j;
	wrt_tok root, req, rep, req_sum, rep_sum;
	uint8_t *req_front, *rep_front;
	size_t req_len, rep_len;
	uint16_t req_version, req_compat, rep_version, rep_compat;
	uint64_t rep_data_len;    /* length of the reply's data segment (0 when the vector has no reply) */
} rig_vec;

/* Load one exchange; 0 on success. */
static WRT_UNUSED int rig_vec_load(rig_vec *v, const char *name)
{
	char rel[128];
	wrt_tok t;

	memset(v, 0, sizeof(*v));
	snprintf(rel, sizeof(rel), "osdop/%s", name);
	if (wrt_json_load_vec(&v->j, rel) != 0)
		return -1;
	v->root = wrt_json_root(&v->j);
	v->req = wrt_json_get(&v->j, v->root, "request");
	v->rep = wrt_json_get(&v->j, v->root, "reply");
	if (v->req == WRT_NONE)
		return -1;
	v->req_sum = wrt_json_get(&v->j, v->req, "summary");
	if (wrt_json_get_hex(&v->j, v->req, "front_hex", &v->req_front, &v->req_len) != 0)
		return -1;
	v->req_version = (uint16_t)rig_int(&v->j, v->req, "version", 9);
	v->req_compat = (uint16_t)rig_int(&v->j, v->req, "compat_version", 3);
	if (v->rep != WRT_NONE) {
		v->rep_sum = wrt_json_get(&v->j, v->rep, "summary");
		if (wrt_json_get_hex(&v->j, v->rep, "front_hex", &v->rep_front, &v->rep_len) != 0)
			return -1;
		v->rep_version = (uint16_t)rig_int(&v->j, v->rep, "version", 8);
		v->rep_compat = (uint16_t)rig_int(&v->j, v->rep, "compat_version", 2);
		t = wrt_json_get(&v->j, v->rep, "data");
		v->rep_data_len = t == WRT_NONE ? 0u : (uint64_t)rig_int(&v->j, t, "length", 0);
	}
	return 0;
}

static WRT_UNUSED void rig_vec_free(rig_vec *v)
{
	free(v->req_front);
	free(v->rep_front);
	wrt_json_free(&v->j);
	memset(v, 0, sizeof(*v));
}

/* The encoder's inputs rebuilt from a request summary. */
typedef struct rig_req {
	wri_mosdop_hdr h;
	wri_osd_opd ops[WRI_OSD_OPS_MAX];
	unsigned n_ops;
	wri_snapc snapc;
	uint64_t snaps[32];
	char *oid;
} rig_req;

static WRT_UNUSED uint32_t rig_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static WRT_UNUSED uint64_t rig_le64(const uint8_t *p)
{
	return (uint64_t)rig_le32(p) | ((uint64_t)rig_le32(p + 4) << 32);
}

/* Returns 0 on success; q->oid is malloc'd (rig_req_free). */
static WRT_UNUSED int rig_req_build(rig_req *q, const rig_vec *v)
{
	const wrt_json *j = &v->j;
	wrt_tok ops, snaps;
	size_t i, rec0;

	memset(q, 0, sizeof(*q));
	q->h.version = (uint8_t)v->req_version;
	q->h.pool = rig_int(j, v->req_sum, "pool", 0);
	q->h.pg_seed = (uint32_t)rig_int(j, v->req_sum, "seed", 0);
	q->h.hash = (uint32_t)rig_int(j, v->req_sum, "hash", 0);
	q->h.map_epoch = (uint32_t)rig_int(j, v->req_sum, "epoch", 0);
	q->h.flags = (uint32_t)rig_int(j, v->req_sum, "flags", 0);
	q->h.retry_attempt = (int32_t)rig_int(j, v->req_sum, "retry_attempt", 0);
	q->h.features = rig_u64_after(j, "features", 0);
	q->h.snapid = rig_u64_after(j, "snapid", WRI_SNAP_NOSNAP);
	q->oid = wrt_json_strdup(j, wrt_json_get(j, v->req_sum, "oid"));
	if (q->oid == NULL)
		return -1;
	q->h.oid = (const uint8_t *)q->oid;
	q->h.oid_len = (uint32_t)strlen(q->oid);
	/* the mtime is not in the summary: the captured front has it */
	if (v->req_len >= RIG_MTIME_AT + 8u) {
		q->h.mtime_sec = rig_le32(v->req_front + RIG_MTIME_AT);
		q->h.mtime_nsec = rig_le32(v->req_front + RIG_MTIME_AT + 4u);
	}
	q->snapc.seq = (uint64_t)rig_int(j, v->req_sum, "snap_seq", 0);
	snaps = wrt_json_get(j, v->req_sum, "snaps");
	for (i = 0; snaps != WRT_NONE && i < wrt_json_count(j, snaps) && i < 32; i++) {
		int ok = 0;

		q->snaps[i] = (uint64_t)wrt_json_int(j, wrt_json_at(j, snaps, i), &ok);
		q->snapc.n++;
	}
	q->snapc.cap = 32;
	q->snapc.snaps = q->snaps;
	q->h.snapc = &q->snapc;

	/* operation records start after: fixed part 106 (v9) + locator 34 + name length prefix 4 + name + count 2 */
	rec0 = 106u + 34u + 4u + q->h.oid_len + 2u;
	ops = wrt_json_get(j, v->req_sum, "ops");
	q->n_ops = (unsigned)wrt_json_count(j, ops);
	for (i = 0; i < q->n_ops && i < WRI_OSD_OPS_MAX; i++) {
		wrt_tok o = wrt_json_at(j, ops, i);
		wri_osd_opd *d = &q->ops[i];
		const uint8_t *rec = v->req_front + rec0 + i * WRI_OSD_OPREC_LEN;

		d->code = (uint16_t)rig_int(j, o, "code", 0);
		d->flags = (uint16_t)rig_int(j, o, "flags", 0);
		d->in_len = (uint32_t)rig_int(j, o, "payload_len", 0);
		d->cls_class_len = (uint8_t)rig_int(j, o, "class_len", 0);
		d->cls_method_len = (uint8_t)rig_int(j, o, "method_len", 0);
		if (rig_has(j, o, "offset"))
			d->off = (uint64_t)rig_int(j, o, "offset", 0);
		else
			d->off = d->code == WRI_OSD_OP_CALL ? 0 : rig_le64(rec + 6);        /* SETALLOCHINT: expected object size */
		if (rig_has(j, o, "length"))
			d->len = (uint64_t)rig_int(j, o, "length", 0);
		else
			d->len = d->code == WRI_OSD_OP_CALL ? 0 : rig_le64(rec + 14);       /* SETALLOCHINT: expected write size */
	}
	return 0;
}

static WRT_UNUSED void rig_req_free(rig_req *q)
{
	free(q->oid);
	q->oid = NULL;
}

#endif /* OSD_MSG_RIG_H */
