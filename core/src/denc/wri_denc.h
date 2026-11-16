/* SPDX-License-Identifier: MIT */
/*
 * wri_denc.h - Ceph's primitive encodings on top of the cursors: versioned envelopes,
 * length-prefixed strings and blobs, utime. Used by msgr2 control frames, cephx, the monitor
 * messages and (later) the maps. Own code, written from docs/spec/msgr2.md 2.1.
 */
#ifndef WRI_DENC_H
#define WRI_DENC_H

#include "wri_cursor.h"

/*
 * Versioned envelope: u8 struct_v, u8 struct_compat, u32 struct_len, then struct_len bytes.
 * A reader that knows versions up to `supported_compat` must refuse an envelope whose
 * struct_compat is larger (WR_E_UNSUPPORTED) and must skip unknown trailing bytes: wri_env_open
 * consumes the whole body from the parent reader and hands back a sub-reader over it, so
 * "skip to the end" is automatic. WR_E_TRUNCATED if struct_len exceeds the bytes left.
 */
typedef struct wri_env {
	uint8_t v;      /* struct_v */
	uint8_t compat; /* struct_compat */
	wri_rd body;    /* exactly struct_len bytes */
} wri_env;

WR_MUST_CHECK wr_status wri_env_open(wri_rd *r, uint8_t supported_compat, wri_env *e);

/* Writer side. Returns the offset of the length field; wri_env_end patches it. */
size_t wri_env_begin(wri_wr *w, uint8_t v, uint8_t compat);
void wri_env_end(wri_wr *w, size_t mark);

/* u32 length + bytes. The returned pointer points into the reader's buffer. Fails with
 * WR_E_TOOBIG if the length exceeds max. */
const uint8_t *wri_denc_blob(wri_rd *r, uint32_t *len, uint32_t max);
void wri_denc_put_blob(wri_wr *w, const uint8_t *p, size_t n);

/* A string is encoded exactly like a blob (no NUL). Same functions, separate names for clarity. */
#define wri_denc_str wri_denc_blob
#define wri_denc_put_str wri_denc_put_blob

/* utime_t: u32 seconds, u32 nanoseconds. */
void wri_denc_utime(wri_rd *r, uint32_t *sec, uint32_t *nsec);
void wri_denc_put_utime(wri_wr *w, uint32_t sec, uint32_t nsec);

#endif /* WRI_DENC_H */
