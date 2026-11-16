/* SPDX-License-Identifier: MIT */
/*
 * wrt.h - the tiny test framework of the harness (user space, libc allowed), plus the helpers every
 * test uses to read the committed vectors in harness/vectors/.
 *
 * A test is one executable with a main() that runs checks and ends with `return wrt_finish();`.
 * ctest treats exit code 0 as pass and 77 as skip (WRT_SKIP). Failures print file:line and keep
 * going, so one run shows every broken check.
 *
 *   int main(void) {
 *       WRT_CHECK(1 + 1 == 2);
 *       WRT_CHECK_U64(wri_crc32c(0, p, n), 0x58E3FA20u);
 *       WRT_CHECK_STATUS(WR_E_TRUNCATED, decode(...));
 *       return wrt_finish();
 *   }
 */
#ifndef WRT_H
#define WRT_H

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define WRT_UNUSED __attribute__((unused))
#else
#define WRT_UNUSED
#endif

/* ---- checks --------------------------------------------------------------------------------- */

extern unsigned long wrt_checks;
extern unsigned long wrt_failures;

#define WRT_CHECK(cond)                                                                           \
	do {                                                                                      \
		wrt_checks++;                                                                     \
		if (!(cond)) {                                                                    \
			wrt_failures++;                                                           \
			fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);   \
		}                                                                                 \
	} while (0)

/* Compare two integers (any width up to 64 bit), printing both on failure. */
#define WRT_CHECK_U64(got, want)                                                                  \
	do {                                                                                      \
		uint64_t wrt_g_ = (uint64_t)(got), wrt_w_ = (uint64_t)(want);                     \
		wrt_checks++;                                                                     \
		if (wrt_g_ != wrt_w_) {                                                           \
			wrt_failures++;                                                           \
			fprintf(stderr, "%s:%d: %s == 0x%" PRIx64 ", want 0x%" PRIx64 "\n", __FILE__, \
				__LINE__, #got, wrt_g_, wrt_w_);                                  \
		}                                                                                 \
	} while (0)

/* Compare a wr_status with an expected one, printing both symbolic names. */
#define WRT_CHECK_STATUS(want, expr)                                                              \
	do {                                                                                      \
		int32_t wrt_s_ = (int32_t)(expr), wrt_e_ = (int32_t)(want);                       \
		wrt_checks++;                                                                     \
		if (wrt_s_ != wrt_e_) {                                                           \
			wrt_failures++;                                                           \
			fprintf(stderr, "%s:%d: %s returned %d (%s), want %d (%s)\n", __FILE__,    \
				__LINE__, #expr, wrt_s_, wrt_status_name_(wrt_s_), wrt_e_,        \
				wrt_status_name_(wrt_e_));                                        \
		}                                                                                 \
	} while (0)

/* Compare two byte buffers; on mismatch prints the first differing offset. */
#define WRT_CHECK_MEM(got, want, n) wrt_check_mem_(__FILE__, __LINE__, #got, (got), (want), (n))

/* Mark the whole test skipped (exit 77) with a reason; never use it to hide a failure. */
#define WRT_SKIP(reason)                                                                          \
	do {                                                                                      \
		fprintf(stderr, "SKIP: %s\n", (reason));                                          \
		exit(77);                                                                         \
	} while (0)

/* Print a summary and return the process exit code. */
int wrt_finish(void);

/* Implementation details of the macros above. */
const char *wrt_status_name_(int32_t st);
void wrt_check_mem_(const char *file, int line, const char *what, const void *got, const void *want, size_t n);

/* ---- files and hex --------------------------------------------------------------------------- */

/* Read a whole file into a malloc'd buffer (NUL-terminated for convenience; *n excludes the NUL).
 * Returns 0, or -1 with a message on stderr. */
int wrt_read_file(const char *path, uint8_t **buf, size_t *n);

/* "<WRT_VECTOR_DIR>/<rel>" in a static buffer (valid until the next call). */
const char *wrt_vec_path(const char *rel);

/* Decode a hex string (case-insensitive, ASCII whitespace skipped) into a malloc'd buffer. Returns 0 or -1. */
int wrt_hex_decode(const char *hex, size_t len, uint8_t **out, size_t *n);
/* Lower-case hex of a buffer into out (needs 2n + 1 bytes). */
void wrt_hex_encode(const uint8_t *p, size_t n, char *out);

/* ---- minimal JSON reader --------------------------------------------------------------------- */

typedef int wrt_tok; /* token index; WRT_NONE = absent */
#define WRT_NONE (-1)

typedef struct wrt_json wrt_json;
struct wrt_json {
	char *text;      /* owned copy of the document */
	size_t text_len;
	void *tok;       /* internal token array */
	size_t ntok;
};

/* Parse a document held in memory / read from a file / read from harness/vectors/<rel>. 0 = ok. */
int wrt_json_parse(wrt_json *j, const char *text, size_t n);
int wrt_json_load(wrt_json *j, const char *path);
int wrt_json_load_vec(wrt_json *j, const char *rel);
void wrt_json_free(wrt_json *j);

wrt_tok wrt_json_root(const wrt_json *j);
wrt_tok wrt_json_get(const wrt_json *j, wrt_tok obj, const char *key);    /* member of an object */
wrt_tok wrt_json_at(const wrt_json *j, wrt_tok arr, size_t i);            /* element of an array */
size_t wrt_json_count(const wrt_json *j, wrt_tok t);                      /* members / elements */
int wrt_json_is_string(const wrt_json *j, wrt_tok t);
int wrt_json_is_number(const wrt_json *j, wrt_tok t);
int wrt_json_is_bool(const wrt_json *j, wrt_tok t);
/* Object member key at index i (so a test can iterate an object). */
const char *wrt_json_key_at(const wrt_json *j, wrt_tok obj, size_t i, wrt_tok *value);

/* String value as a malloc'd NUL-terminated UTF-8 string with escapes resolved; NULL if not a string. */
char *wrt_json_strdup(const wrt_json *j, wrt_tok t);
/* Integer value (decimal; a "0x..." string is accepted too); *ok = 0 if not a number. */
int64_t wrt_json_int(const wrt_json *j, wrt_tok t, int *ok);
/* A JSON string holding hex digits, decoded into a malloc'd buffer. 0 = ok. */
int wrt_json_hex(const wrt_json *j, wrt_tok t, uint8_t **out, size_t *n);
/* Convenience: member `key` of `obj` as hex. 0 = ok. */
int wrt_json_get_hex(const wrt_json *j, wrt_tok obj, const char *key, uint8_t **out, size_t *n);

#endif /* WRT_H */
