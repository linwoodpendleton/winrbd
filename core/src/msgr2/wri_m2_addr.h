/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_addr.h - entity_addr_t and entity_addrvec_t (msgr2.md 2.8, osdmap.md 2.1.2).
 *
 * The decoded form keeps the exact wire bytes of the marker-1 encoding because the server
 * compares addresses bytewise: target_addr in CLIENT_IDENT must be copied unchanged from the
 * map (msgr2.md 3.6).
 */
#ifndef WRI_M2_ADDR_H
#define WRI_M2_ADDR_H

#include "wr_err.h"
#include "wr_types.h"
#include "wri_cursor.h"

#define WRI_EADDR_TYPE_NONE 0u
#define WRI_EADDR_TYPE_LEGACY 1u
#define WRI_EADDR_TYPE_MSGR2 2u
#define WRI_EADDR_TYPE_ANY 3u

#define WRI_EADDR_MAX_WIRE 47u /* IPv6 marker-1 form: 3 + 4 + 40 */
#define WRI_EADDRVEC_MAX 8u    /* entries kept from a vector; more are skipped */
#define WRI_EADDRVEC_WIRE_MAX 16u /* largest count accepted on the wire (and written) */

typedef struct wri_eaddr {
	uint32_t type;      /* WRI_EADDR_TYPE_* */
	uint32_t nonce;
	uint8_t family;     /* 0 blank, WR_AF_IPV4, WR_AF_IPV6 (NOT the Linux 2 / 10 numbers) */
	uint8_t ip[16];
	uint16_t port;      /* host order */
	uint8_t raw[WRI_EADDR_MAX_WIRE]; /* canonical marker-1 encoding of the decoded object (see wri_m2_addr.c) */
	uint8_t raw_len;
} wri_eaddr;

/*
 * Decode one entity_addr_t. Accepts marker 1 (IPv4, IPv6, blank, elen 0 = blank); rejects marker
 * 0 (legacy sockaddr_storage form) with WR_E_UNSUPPORTED and struct_compat > 1 likewise. Larger
 * struct_v: extra bytes inside struct_len are skipped. elen larger than the sockaddr for the
 * family: WR_E_ENCODING; elen 1: WR_E_ENCODING; a family other than IPv4, IPv6 or blank (0):
 * WR_E_UNSUPPORTED. Also fills raw / raw_len. On any error *out is zeroed.
 */
WR_MUST_CHECK wr_status wri_eaddr_decode(wri_rd *r, wri_eaddr *out);

/* Encode in the canonical marker-1 form (IPv4: 35 bytes, IPv6: 47, blank: family 0, elen 28). */
void wri_eaddr_encode(wri_wr *w, const wri_eaddr *a);

/* entity_addrvec_t: marker 2, u32 count, count entities; marker 1 = a single entity follows
 * (marker shared), marker 0 or > 2 rejected. At most max entries are stored in out, *n_total gets
 * the count on the wire, *n_stored the number stored (<= max). Count is capped at 16. */
WR_MUST_CHECK wr_status wri_eaddrvec_decode(wri_rd *r, wri_eaddr *out, size_t max, size_t *n_stored, size_t *n_total);
void wri_eaddrvec_encode(wri_wr *w, const wri_eaddr *a, size_t n);

/* Equality as the server sees it: the canonical encodings (type, nonce, family, port, address and
 * the reserved sockaddr bytes) are identical. Follows the typed fields, so it stays right after a
 * field is edited and for addresses built without raw. NULL on either side: 0. */
int wri_eaddr_equal(const wri_eaddr *a, const wri_eaddr *b);

/* Conversions to and from the public address. from_wr builds the canonical raw bytes too.
 * A NULL out is ignored; a NULL source gives a blank result. */
void wri_eaddr_from_wr(wri_eaddr *out, const wr_addr *a, uint32_t type);
void wri_eaddr_to_wr(wr_addr *out, const wri_eaddr *a);

#endif /* WRI_M2_ADDR_H */
