/* SPDX-License-Identifier: MIT */
/*
 * osdc_vec_rig.h - shared by the vector replays of module vectors-c (test_osd_vec_replay.c, test_rbd_vec_replay.c): loads the lab
 * captures of harness/vectors/public/osdc/ (sessions of OSD requests and replies as the stock client library sent and received them,
 * with the decoded summaries the independent checker wrote) and turns a request summary back into the encoder's inputs.
 * Test-only (libc allowed).
 *
 * Every u64 of the files that may pass 2^53 (snapshot ids, the feature word) is a "0x..." string; everything else is a number.
 */
#ifndef OSDC_VEC_RIG_H
#define OSDC_VEC_RIG_H

#include <errno.h>

#include "wrt.h"
#include "wri_osd_msg.h"

#define OV_DIR "public/osdc/"
#define OV_SNAPS_MAX 64u

/* 1 if the vectors are in the tree (a source archive without harness/vectors/public/osdc skips the replays with a reason). */
static WRT_UNUSED int ov_present(void)
{
	FILE *f = fopen(wrt_vec_path(OV_DIR "INDEX.json"), "rb");

	if (f == NULL)
		return 0;
	fclose(f);
	return 1;
}

static WRT_UNUSED int ov_load(wrt_json *j, const char *rel)
{
	char path[256];

	snprintf(path, sizeof(path), OV_DIR "%s", rel);
	return wrt_json_load_vec(j, path);
}

static WRT_UNUSED int64_t ov_int(const wrt_json *j, wrt_tok obj, const char *key, int64_t dflt)
{
	wrt_tok t = wrt_json_get(j, obj, key);
	int ok = 0;
	int64_t v;

	if (t == WRT_NONE)
		return dflt;
	v = wrt_json_int(j, t, &ok);
	return ok ? v : dflt;
}

/* A u64 that travels as a "0x..." string (or a plain number). */
static WRT_UNUSED uint64_t ov_u64_tok(const wrt_json *j, wrt_tok t)
{
	char *s = wrt_json_strdup(j, t);
	uint64_t v = 0;

	if (s != NULL) {
		v = (uint64_t)strtoull(s, NULL, 0);
		free(s);
	} else {
		int ok = 0;

		v = (uint64_t)wrt_json_int(j, t, &ok);
	}
	return v;
}

static WRT_UNUSED uint64_t ov_u64(const wrt_json *j, wrt_tok obj, const char *key)
{
	wrt_tok t = wrt_json_get(j, obj, key);

	return t == WRT_NONE ? 0 : ov_u64_tok(j, t);
}

/* One captured message: the front and the data segment (when the file holds it in full), the header words, the decoded summary. */
typedef struct ov_msg {
	wrt_tok tok;
	uint16_t type, version, compat;
	uint32_t priority;
	uint64_t tid;
	uint8_t *front;
	size_t front_len;
	uint8_t *data;        /* NULL when the file only holds a head and a hash */
	size_t data_len;      /* bytes in `data` */
	uint64_t data_total;  /* length of the data segment on the wire */
	wrt_tok summary;
} ov_msg;

static WRT_UNUSED int ov_msg_load(ov_msg *m, const wrt_json *j, wrt_tok t)
{
	wrt_tok d;

	memset(m, 0, sizeof(*m));
	m->tok = t;
	m->type = (uint16_t)ov_int(j, t, "type", 0);
	m->version = (uint16_t)ov_int(j, t, "version", 0);
	m->compat = (uint16_t)ov_int(j, t, "compat_version", 0);
	m->priority = (uint32_t)ov_int(j, t, "priority", 0);
	m->tid = (uint64_t)ov_int(j, t, "tid", 0);
	m->summary = wrt_json_get(j, t, "summary");
	if (wrt_json_get_hex(j, t, "front_hex", &m->front, &m->front_len) != 0)
		return -1;
	d = wrt_json_get(j, t, "data");
	if (d == WRT_NONE)
		return -1;
	m->data_total = (uint64_t)ov_int(j, d, "length", 0);
	if (wrt_json_get(j, d, "hex") != WRT_NONE) {
		if (wrt_json_get_hex(j, d, "hex", &m->data, &m->data_len) != 0)
			return -1;
		if (m->data_len != m->data_total)
			return -1;
	}
	return 0;
}

static WRT_UNUSED void ov_msg_free(ov_msg *m)
{
	free(m->front);
	free(m->data);
	memset(m, 0, sizeof(*m));
}

/* The encoder's inputs rebuilt from a request summary. */
typedef struct ov_req {
	wri_mosdop_hdr h;
	wri_osd_opd ops[WRI_OSD_OPS_MAX];
	unsigned n_ops;
	wri_snapc snapc;
	uint64_t snaps[OV_SNAPS_MAX];
	char *oid;
	char *nspace;
} ov_req;

/* 0 on success; q->oid is malloc'd (ov_req_free). `version` is the message version of the capture (9, or 8). */
static WRT_UNUSED int ov_req_build(ov_req *q, const wrt_json *j, wrt_tok sum, uint8_t version)
{
	wrt_tok ops, snaps, mt;
	size_t i;

	memset(q, 0, sizeof(*q));
	q->h.version = version;
	q->h.pool = ov_int(j, sum, "pool", -1);
	q->h.pg_seed = (uint32_t)ov_int(j, sum, "seed", 0);
	q->h.hash = (uint32_t)ov_int(j, sum, "hash", 0);
	q->h.map_epoch = (uint32_t)ov_int(j, sum, "epoch", 0);
	q->h.flags = (uint32_t)ov_int(j, sum, "flags", 0);
	q->h.retry_attempt = (int32_t)ov_int(j, sum, "retry_attempt", 0);
	q->h.features = ov_u64(j, sum, "features");
	q->h.snapid = ov_u64(j, sum, "snapid");
	q->oid = wrt_json_strdup(j, wrt_json_get(j, sum, "oid"));
	q->nspace = wrt_json_strdup(j, wrt_json_get(j, sum, "nspace"));
	if (q->oid == NULL || q->nspace == NULL)
		return -1;
	q->h.oid = (const uint8_t *)q->oid;
	q->h.oid_len = (uint32_t)strlen(q->oid);
	q->h.nspace = (const uint8_t *)q->nspace;
	q->h.nspace_len = (uint32_t)strlen(q->nspace);
	mt = wrt_json_get(j, sum, "mtime");
	if (mt == WRT_NONE || wrt_json_count(j, mt) != 2)
		return -1;
	{
		int ok = 0;

		q->h.mtime_sec = (uint32_t)wrt_json_int(j, wrt_json_at(j, mt, 0), &ok);
		q->h.mtime_nsec = (uint32_t)wrt_json_int(j, wrt_json_at(j, mt, 1), &ok);
	}
	q->snapc.seq = ov_u64(j, sum, "snap_seq");
	snaps = wrt_json_get(j, sum, "snaps");
	if (snaps == WRT_NONE || wrt_json_count(j, snaps) > OV_SNAPS_MAX)
		return -1;
	for (i = 0; i < wrt_json_count(j, snaps); i++)
		q->snaps[q->snapc.n++] = ov_u64_tok(j, wrt_json_at(j, snaps, i));
	q->snapc.cap = OV_SNAPS_MAX;
	q->snapc.snaps = q->snaps;
	q->h.snapc = &q->snapc;
	ops = wrt_json_get(j, sum, "ops");
	if (ops == WRT_NONE || wrt_json_count(j, ops) < 1 || wrt_json_count(j, ops) > WRI_OSD_OPS_MAX)
		return -1;
	q->n_ops = (unsigned)wrt_json_count(j, ops);
	for (i = 0; i < q->n_ops; i++) {
		wrt_tok o = wrt_json_at(j, ops, i);
		wri_osd_opd *d = &q->ops[i];

		d->code = (uint16_t)ov_int(j, o, "code", 0);
		d->flags = (uint16_t)ov_int(j, o, "flags", 0);
		d->in_len = (uint32_t)ov_int(j, o, "payload_len", 0);
		d->off = (uint64_t)ov_int(j, o, "off", 0);
		d->len = (uint64_t)ov_int(j, o, "len", 0);
		d->cls_class_len = (uint8_t)ov_int(j, o, "class_len", 0);
		d->cls_method_len = (uint8_t)ov_int(j, o, "method_len", 0);
	}
	return 0;
}

static WRT_UNUSED void ov_req_free(ov_req *q)
{
	free(q->oid);
	free(q->nspace);
	memset(q, 0, sizeof(*q));
}

/* Encode a rebuilt request and compare with the captured front. Returns 0 when identical; else prints what differs and returns -1. */
static WRT_UNUSED int ov_req_check(const ov_req *q, const ov_msg *m, const char *where)
{
	uint8_t buf[4096];
	wri_wr w;
	wr_status st;
	size_t i, n;

	wri_wr_init(&w, buf, sizeof(buf));
	st = wri_mosdop_encode(&w, &q->h, q->ops, q->n_ops);
	if (st != WR_OK || !wri_wr_ok(&w)) {
		fprintf(stderr, "%s: wri_mosdop_encode refused the captured request: %s\n", where, wrt_status_name_((int32_t)st));
		return -1;
	}
	n = wri_wr_len(&w);
	if (n != m->front_len) {
		fprintf(stderr, "%s: encoded front is %zu bytes, the capture's is %zu\n", where, n, m->front_len);
		return -1;
	}
	for (i = 0; i < n; i++)
		if (buf[i] != m->front[i]) {
			fprintf(stderr, "%s: encoded front differs from the capture at byte %zu (0x%02x, captured 0x%02x)\n", where, i, buf[i],
				m->front[i]);
			return -1;
		}
	if (wri_mosdop_front_max(q->h.oid_len, q->h.nspace_len, q->n_ops, q->snapc.n) < n) {
		fprintf(stderr, "%s: wri_mosdop_front_max is below the real front size\n", where);
		return -1;
	}
	return 0;
}

#endif /* OSDC_VEC_RIG_H */
