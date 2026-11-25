/* SPDX-License-Identifier: MIT */
/*
 * wri_rburl.h - internals shared by the two files of the rbd URL parser (wri_rburl.c: the URL parts,
 * wri_rburl_opt.c: the query and the options). Not part of the public API (wr_rburl.h).
 */
#ifndef WRI_RBURL_H
#define WRI_RBURL_H

#include "wr_rburl.h"

/* Decoded option name and value buffers (with the NUL): the longest option name is "readahead" (9) and the longest value a UUID
 * (36); anything longer cannot be legal, and is refused by length (an unknown name, a bad value) without being kept. */
#define WRI_RBURL_NAME_TOKEN_MAX 16u
#define WRI_RBURL_VALUE_TOKEN_MAX 40u

/* Results of wri_rburl_unescape(). */
#define WRI_RBURL_ESC_OK 0
#define WRI_RBURL_ESC_BAD 1       /* a "%" without two hex digits, a decoded NUL, or a raw byte outside 0x21 .. 0x7e */
#define WRI_RBURL_ESC_TOO_LONG 2  /* the decoded text does not fit (cap counts the NUL) */

/* Record a failure in *err (NULL = nothing to record) and return `st`; the line is the detection point. */
wr_status wri_rburl_fail(wr_errinfo *err, wr_status st, const char *what, uint64_t a0, uint64_t a1, uint64_t a2,
			 unsigned line);
#define WRI_RBURL_FAIL(err, st, what, a0, a1, a2) \
	wri_rburl_fail((err), (st), (what), (uint64_t)(a0), (uint64_t)(a1), (uint64_t)(a2), (unsigned)__LINE__)

/* Fill in the defaults of every option (the spec is zero when this is called). */
void wri_rburl_defaults(wr_rburl_spec *out);

/*
 * Percent-decode raw[0 .. n) into dst (NUL terminated, cap bytes including the NUL). "%XX" with two hex digits of
 * either case becomes that byte; "+" stays a plus. *len gets the decoded length (without the NUL); on failure
 * dst[0] is NUL and *len 0.
 */
int wri_rburl_unescape(const char *raw, size_t n, char *dst, size_t cap, size_t *len);

/* Walk the raw query q[0 .. n) ("a=b&c=d"), apply every option to *out, refuse unknown, repeated and malformed ones. */
wr_status wri_rburl_query(const char *q, size_t n, wr_rburl_spec *out, wr_errinfo *err);

/* Split a decoded path "/pool/image[@snap]" into *out's pool, image and snap (names validated). */
wr_status wri_rburl_path(const char *path, size_t n, wr_rburl_spec *out, wr_errinfo *err);

#endif /* WRI_RBURL_H */
