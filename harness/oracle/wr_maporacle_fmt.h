/* SPDX-License-Identifier: MIT */
/*
 * wr_maporacle_fmt.h - what wr-maporacle prints and how it reads its inputs (harness code: libc is fine).
 *
 * The line formats follow the tools the answers are compared with; every function writes one complete line (or block)
 * and nothing else, so the output of the tool is exactly the concatenation of these lines.
 *
 *   object line   osdmap e<epoch> pool '<name>' (<id>) object '<ns/>name' -> pg <id>.<ps hex> (<id>.<seed hex>) -> up ([..], p<n>) acting ([..], p<n>)
 *                 (ceph osd map: the namespace is shown as "<ns>/<name>"; the hashed bytes are namespace, 0x1f, name)
 *   pg line       <id>.<seed hex> raw ([..], p<n>) up ([..], p<n>) acting ([..], p<n>)
 *                 (osdmaptool --test-map-pgs-dump-all; the raw primary is the first raw member, as there)
 *   crush line    CRUSH rule <r> x <x> [..]               (crushtool --test --show-mappings)
 *
 * Bytes of an object name that are not printable ASCII (and the backslash) are written as \xHH (\\ for the backslash)
 * so a line is always one line of plain text. This is the one place where the output departs from Ceph's tools, which
 * print the raw bytes; names the lab compares are given as hex anyway and the comparison scripts read fields, not names.
 *
 * A request the core cannot answer prints the same line with "ERROR <status name>" in place of the sets (object line,
 * crush line) or one "pool <id> ERROR <status name>" line (a whole pool); the exit status of the tool says that some
 * line was an error. Statuses WR_E_POOL_UNSUPPORTED, WR_E_CRUSH_UNSUPPORTED and WR_E_CRUSH_NO_RULE mean "a kind of pool or
 * rule this client does not serve" (erasure pools, indep rules, tree buckets): scripts count those as skipped, not wrong.
 */
#ifndef WR_MAPORACLE_FMT_H
#define WR_MAPORACLE_FMT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "wri_osdmap_dec.h"
#include "wri_place.h"

/* ---- output ---------------------------------------------------------------------------------------------- */

/* "[1,0,2]"; with none_text a CRUSH_ITEM_NONE member is written NONE (pg_vector_string of the monitor), else as a number. */
void wrm_put_list(FILE *o, const int32_t *v, uint32_t n, int none_text);
/* The bytes with the escaping described above. */
void wrm_put_escaped(FILE *o, const uint8_t *s, size_t n);

/* The object line. `name` / `ns` are the object bytes as hashed. */
void wrm_put_object_line(FILE *o, uint32_t epoch, const uint8_t *pool_name, size_t pool_name_len, int64_t pool_id, const uint8_t *name,
			 size_t name_len, const uint8_t *ns, size_t ns_len, uint32_t ps, uint32_t seed, const wri_pg_result *r);
/* The same line with an error in place of the placement; `why` may be NULL. */
void wrm_put_object_error(FILE *o, uint32_t epoch, const uint8_t *pool_name, size_t pool_name_len, int64_t pool_id, const uint8_t *name,
			  size_t name_len, const uint8_t *ns, size_t ns_len, wr_status st, const wr_errinfo *why);

void wrm_put_pg_line(FILE *o, int64_t pool, uint32_t seed, const wri_pg_result *r);
void wrm_put_pg_error(FILE *o, int64_t pool, uint32_t seed, wr_status st, const wr_errinfo *why);
void wrm_put_pool_error(FILE *o, int64_t pool, wr_status st);

void wrm_put_crush_line(FILE *o, uint32_t rule, uint32_t x, const int32_t *v, uint32_t n);
void wrm_put_crush_error(FILE *o, uint32_t rule, uint32_t x, wr_status st, const wr_errinfo *why);

/* The compact state of one map as text: a "== epoch N" line, fsid, flags (raw), max_osd, one line per OSD, one per tracked
 * pool and the five pg tables of the tracked pools, then a summary line of the CRUSH region with its CRC-32C. */
void wrm_put_state(FILE *o, const wri_osdmap *m, const wri_mapcfg *cfg);

/* "status NAME (text; what; a0 a1 a2)" for a diagnostic on stderr. */
void wrm_put_status(FILE *o, wr_status st, const wr_errinfo *why);

/* ---- input ----------------------------------------------------------------------------------------------- */

/* Decode a hex string (ASCII whitespace skipped, an odd digit count or any other character is an error) into a malloc'd
 * buffer (*out is NULL and *n 0 for an empty string). 0 = ok, -1 = not hex. */
int wrm_hex_decode(const char *s, size_t len, uint8_t **out, size_t *n);
/* Unsigned / signed decimal of a whole argument; 0 = ok. */
int wrm_parse_u64(const char *s, uint64_t *v);
int wrm_parse_i64(const char *s, int64_t *v);
/* crushtool --weight: a decimal number, scaled by 0x10000 as a float and truncated, clamped to 0 .. 0x10000. 0 = ok. */
int wrm_parse_weight(const char *s, uint32_t *w16);

/* A file that holds either raw bytes or hex text (lines may carry # comments; ASCII whitespace is ignored). A file whose
 * bytes are all tab, newline, carriage return or printable ASCII is read as hex text. malloc'd; 0 = ok, -1 with *err set to
 * a static message. */
int wrm_load_blob(const char *path, uint8_t **buf, size_t *n, const char **err);

/* One blob of a list file. */
typedef struct wrm_item {
	uint8_t *p;
	size_t n;
} wrm_item;

/* A list of incrementals: a file of lines "<epoch> <hex>" (the layout of incrementals.hex; the epoch is only a label, the
 * blob names its own), or a single incremental (raw or hex text) which becomes a list of one. *items is malloc'd with *count
 * entries, each with a malloc'd blob; free with wrm_items_free. 0 = ok, -1 with *err. */
int wrm_load_items(const char *path, wrm_item **items, size_t *count, const char **err);
void wrm_items_free(wrm_item *items, size_t count);

#endif /* WR_MAPORACLE_FMT_H */
