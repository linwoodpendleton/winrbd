/* SPDX-License-Identifier: MIT */
/*
 * wri_mon_msgs.c - small monitor message bodies: MMonSubscribe, the MMonMap front, MAuth and
 * MAuthReply (docs/spec/mon-client.md 2.4 to 2.5, 3.8; docs/spec/cephx.md 2.11). Pure functions
 * over the cursors; the MonMap and MOSDMap codecs live in their own files.
 */
#include "wri_mon.h"

#include "wri_denc.h"

WR_FILE_LICENCE_MIT

#define SUB_ITEMS_MAX 32u         /* subscriptions written in one message (a client sends two to four) */
#define SUB_NAME_MAX 255u         /* longest subscription name or host name written */
#define MAUTH_BLOB_MAX 65536u     /* auth payload / result blob accepted, same cap as the msgr2 auth blobs */

/* Length of a C string, stopping one past cap so an unterminated or huge string cannot loop. */
static size_t str_len_capped(const char *s, size_t cap)
{
	size_t n = 0;

	while (n <= cap && s[n] != '\0')
		n++;
	return n;
}

/* Equal C strings, compared for at most SUB_NAME_MAX + 1 bytes (longer ones are refused by put_cstr). */
static int str_eq(const char *a, const char *b)
{
	size_t i;

	for (i = 0; i <= SUB_NAME_MAX; i++) {
		if (a[i] != b[i])
			return 0;
		if (a[i] == '\0')
			return 1;
	}
	return 1;
}

static void put_cstr(wri_wr *w, const char *s)
{
	size_t n;

	if (s == NULL) {
		wri_wr_fail(w, WR_E_INVAL);
		return;
	}
	n = str_len_capped(s, SUB_NAME_MAX);
	if (n > SUB_NAME_MAX) {
		wri_wr_fail(w, WR_E_TOOBIG);
		return;
	}
	wri_denc_put_str(w, (const uint8_t *)s, n);
}

/* ---- MMonSubscribe v3 ------------------------------------------------------------------------ */

void wri_mmonsubscribe_encode(wri_wr *w, const wri_sub_item *items, size_t n, const char *hostname)
{
	size_t i;

	if (w == NULL)
		return;
	if (n != 0 && items == NULL) {
		wri_wr_fail(w, WR_E_INVAL);
		return;
	}
	if (n > SUB_ITEMS_MAX) {
		wri_wr_fail(w, WR_E_TOOBIG);
		return;
	}
	/*
	 * The monitor decodes the items into a map keyed by name, so a repeated name would silently
	 * collapse two subscriptions into one (which start epoch wins is not ours to guess): refuse it.
	 * n is at most SUB_ITEMS_MAX, so the pairwise check is a few hundred compares at worst.
	 */
	for (i = 0; i < n; i++) {
		size_t k;

		if (items[i].what == NULL) {
			wri_wr_fail(w, WR_E_INVAL);
			return;
		}
		for (k = 0; k < i; k++) {
			if (str_eq(items[k].what, items[i].what)) {
				wri_wr_fail(w, WR_E_INVAL);
				return;
			}
		}
	}
	wri_wr_u32(w, (uint32_t)n);
	for (i = 0; i < n; i++) {
		put_cstr(w, items[i].what);
		wri_wr_u64(w, items[i].start);
		wri_wr_u8(w, items[i].flags);
	}
	/* The monitor stores the host name only when it is not empty, so NULL is written as "". */
	put_cstr(w, hostname != NULL ? hostname : "");
}

/* ---- MMonMap front ----------------------------------------------------------------------------- */

wr_status wri_mmonmap_front(const uint8_t *front, size_t n, const uint8_t **monmap, size_t *monmap_len)
{
	wri_rd r;
	uint32_t len = 0;
	const uint8_t *blob;

	if (monmap != NULL)
		*monmap = NULL;
	if (monmap_len != NULL)
		*monmap_len = 0;
	if (monmap == NULL || monmap_len == NULL || (front == NULL && n != 0))
		return WR_E_INVAL;
	wri_rd_init(&r, front, n);
	/* Any length that does not fit in the bytes at hand is a truncation, so the cap is "everything". */
	blob = wri_denc_blob(&r, &len, 0xFFFFFFFFu);
	if (blob == NULL)
		return r.err;
	*monmap = blob;
	*monmap_len = (size_t)len;
	return WR_OK;
}

/* ---- MAuth / MAuthReply ------------------------------------------------------------------------ */

void wri_mauth_encode(wri_wr *w, uint32_t protocol, const uint8_t *payload, size_t n, uint32_t monmap_epoch)
{
	if (w == NULL)
		return;
	/* PaxosServiceMessage prefix: version 0, session_mon -1 (i16), session_mon_tid 0. */
	wri_wr_u64(w, 0);
	wri_wr_u16(w, 0xFFFFu);
	wri_wr_u64(w, 0);
	wri_wr_u32(w, protocol);
	wri_denc_put_blob(w, payload, n);
	wri_wr_u32(w, monmap_epoch);
}

wr_status wri_mauth_reply_decode(const uint8_t *front, size_t n, wri_mauth_reply *out)
{
	wri_rd r;
	uint32_t len = 0, msg_len = 0;
	const uint8_t *blob;

	if (out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	if (front == NULL && n != 0)
		return WR_E_INVAL;
	wri_rd_init(&r, front, n);
	out->protocol = wri_rd_u32(&r);
	out->result = wri_rd_i32(&r);
	out->global_id = wri_rd_u64(&r);
	blob = wri_denc_blob(&r, &len, MAUTH_BLOB_MAX);
	/*
	 * result_msg is read for the bounds and dropped. It has no cap of its own (the front is already
	 * bounded and nothing is copied): a long human-readable reason must not hide the numeric result
	 * that says why the request was refused.
	 */
	(void)wri_denc_str(&r, &msg_len, 0xFFFFFFFFu);
	if (!wri_rd_ok(&r) || blob == NULL) {
		wr_status st = r.err != WR_OK ? r.err : WR_E_ENCODING;

		WR_MEMSET(out, 0, sizeof(*out));
		return st;
	}
	out->payload = blob;
	out->payload_len = len;
	return WR_OK;
}
