/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_addr.c - entity_addr_t and entity_addrvec_t (wri_m2_addr.h, msgr2.md 2.8).
 *
 * Shape of the marker-1 form, all integers little-endian except the port and the address bytes:
 *
 *   marker(1) struct_v(1) struct_compat(1) struct_len(4)
 *   type(4) nonce(4) elen(4)
 *   [ family(2) sa_data(elen - 2) ]                  only when elen != 0
 *
 * sa_data is the rest of a Linux sockaddr: IPv4 = port(2) addr(4) zero(8); IPv6 = port(2)
 * flowinfo(4) addr(16) scope(4).
 *
 * The server compares the decoded in-memory object bytewise, so two encodings that decode to the
 * same object are the same address. `raw` therefore always holds the canonical-shape marker-1
 * encoding of that object: version 1 / compat 1, struct_len = 12 + elen, elen padded up to the
 * full sockaddr size of the family (16 IPv4, 28 IPv6 and blank), unused bytes zero. For every
 * encoding the stock encoder produces this is the wire bytes unchanged. Bytes the typed fields do
 * not model (IPv6 flowinfo and scope id, non-zero padding) are kept in raw only.
 */
#include "wri_m2_addr.h"

#include "wri_denc.h"
#include "wri_le.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define WIRE_AF_INET 2u
#define WIRE_AF_INET6 10u

#define SA_DATA_MAX 26u    /* sa_data bytes of the largest sockaddr (IPv6) */
#define SA_DATA_V4 14u     /* sa_data bytes of sockaddr_in */
#define ELEN_V4 16u        /* full sockaddr_in */
#define ELEN_FULL 28u      /* full sockaddr_in6, also the blank address */
#define EADDR_HDR 7u       /* marker, struct_v, struct_compat, struct_len */
#define EADDR_FIXED 12u    /* type, nonce, elen */
#define EADDR_BODY_OFF 19u /* offset of the family field in raw */

/* Smallest possible marker-1 entity_addr_t on the wire (elen == 0). */
#define EADDR_MIN_WIRE (EADDR_HDR + EADDR_FIXED)

WR_STATIC_ASSERT(EADDR_BODY_OFF + ELEN_FULL == WRI_EADDR_MAX_WIRE, eaddr_max_wire);

/* ---- sockaddr helpers -------------------------------------------------------------------- */

static uint16_t wire_family(uint8_t family)
{
	if (family == WR_AF_IPV4)
		return (uint16_t)WIRE_AF_INET;
	if (family == WR_AF_IPV6)
		return (uint16_t)WIRE_AF_INET6;
	return 0;
}

static uint8_t norm_family(uint8_t f)
{
	return (f == WR_AF_IPV4 || f == WR_AF_IPV6) ? f : 0;
}

/* Typed fields from the sa_data bytes (family already set in a). */
static void sa_to_fields(wri_eaddr *a, const uint8_t sa[SA_DATA_MAX])
{
	if (a->family == WR_AF_IPV4) {
		a->port = wri_be16_get(sa);
		WR_MEMCPY(a->ip, sa + 2, 4);
	} else if (a->family == WR_AF_IPV6) {
		a->port = wri_be16_get(sa);
		WR_MEMCPY(a->ip, sa + 6, 16);
	}
}

/* sa_data bytes from the typed fields: everything the fields do not name is zero. */
static void sa_from_fields(const wri_eaddr *a, uint8_t sa[SA_DATA_MAX])
{
	WR_MEMSET(sa, 0, SA_DATA_MAX);
	if (a->family == WR_AF_IPV4) {
		wri_be16_put(sa, a->port);
		WR_MEMCPY(sa + 2, a->ip, 4);
	} else if (a->family == WR_AF_IPV6) {
		wri_be16_put(sa, a->port);
		WR_MEMCPY(sa + 6, a->ip, 16);
	}
}

/* Write the canonical-shape marker-1 encoding; buf holds WRI_EADDR_MAX_WIRE bytes. */
static size_t eaddr_pack(uint8_t *buf, uint32_t type, uint32_t nonce, uint8_t family,
			 const uint8_t sa[SA_DATA_MAX])
{
	uint32_t elen = (family == WR_AF_IPV4) ? ELEN_V4 : ELEN_FULL;

	buf[0] = 1;
	buf[1] = 1;
	buf[2] = 1;
	wri_le32_put(buf + 3, EADDR_FIXED + elen);
	wri_le32_put(buf + 7, type);
	wri_le32_put(buf + 11, nonce);
	wri_le32_put(buf + 15, elen);
	wri_le16_put(buf + EADDR_BODY_OFF, wire_family(family));
	WR_MEMCPY(buf + EADDR_BODY_OFF + 2, sa, elen - 2u);
	return (size_t)(EADDR_BODY_OFF + elen);
}

/*
 * The sa_data bytes to emit for `a`: those kept in a->raw when raw still describes the same
 * family, port and address as the typed fields (so a copied target_addr keeps IPv6 flowinfo and
 * scope id), otherwise rebuilt from the fields.
 */
static void eaddr_sa(const wri_eaddr *a, uint8_t sa[SA_DATA_MAX])
{
	wri_eaddr t;
	uint8_t from_raw[SA_DATA_MAX];
	uint32_t elen;
	uint16_t wire_af;

	sa_from_fields(a, sa);
	if (a->raw_len < EADDR_BODY_OFF + ELEN_V4 || a->raw_len > WRI_EADDR_MAX_WIRE || a->raw[0] != 1)
		return;
	elen = wri_le32_get(a->raw + 15);
	if (elen < 2u || elen > ELEN_FULL || (size_t)EADDR_BODY_OFF + elen != a->raw_len)
		return;
	wire_af = wri_le16_get(a->raw + EADDR_BODY_OFF);
	if (wire_af != wire_family(a->family))
		return;
	WR_MEMSET(from_raw, 0, sizeof(from_raw));
	WR_MEMCPY(from_raw, a->raw + EADDR_BODY_OFF + 2, elen - 2u);
	WR_MEMSET(&t, 0, sizeof(t));
	t.family = a->family;
	sa_to_fields(&t, from_raw);
	if (t.port != a->port || !wri_ct_memeq(t.ip, a->ip, sizeof(t.ip)))
		return;
	WR_MEMCPY(sa, from_raw, SA_DATA_MAX);
}

/* ---- entity_addr_t decode ---------------------------------------------------------------- */

/* The versioned body, marker byte already consumed. */
static wr_status eaddr_body(wri_rd *r, wri_eaddr *out)
{
	wri_env e;
	uint8_t sa[SA_DATA_MAX];
	uint32_t type, nonce, elen;
	uint16_t wire_af = 0;

	WR_MEMSET(sa, 0, sizeof(sa));
	if (wri_env_open(r, 1, &e) != WR_OK)
		return r->err;
	type = wri_rd_u32(&e.body);
	nonce = wri_rd_u32(&e.body);
	elen = wri_rd_u32(&e.body);
	if (e.body.err != WR_OK) {
		wri_rd_fail(r, e.body.err);
		return r->err;
	}
	if (elen != 0) {
		uint32_t sa_n, sa_max;

		if (elen < 2u) {
			wri_rd_fail(r, WR_E_ENCODING); /* too short to hold the family */
			return r->err;
		}
		wire_af = wri_rd_u16(&e.body);
		sa_n = elen - 2u;
		sa_max = (wire_af == WIRE_AF_INET) ? SA_DATA_V4 : SA_DATA_MAX;
		if (sa_n > sa_max) {
			wri_rd_fail(r, WR_E_ENCODING);
			return r->err;
		}
		wri_rd_copy(&e.body, sa, sa_n);
		if (e.body.err != WR_OK) {
			wri_rd_fail(r, e.body.err);
			return r->err;
		}
	}

	if (wire_af != WIRE_AF_INET && wire_af != WIRE_AF_INET6 && wire_af != 0) {
		/* Ceph would carry any family in its sockaddr union; we only speak IP. */
		wri_rd_fail(r, WR_E_UNSUPPORTED);
		return r->err;
	}
	WR_MEMSET(out, 0, sizeof(*out));
	out->type = type;
	out->nonce = nonce;
	if (wire_af == WIRE_AF_INET)
		out->family = WR_AF_IPV4;
	else if (wire_af == WIRE_AF_INET6)
		out->family = WR_AF_IPV6;
	sa_to_fields(out, sa);
	out->raw_len = (uint8_t)eaddr_pack(out->raw, type, nonce, out->family, sa);
	return WR_OK;
}

wr_status wri_eaddr_decode(wri_rd *r, wri_eaddr *out)
{
	uint8_t marker;

	if (r == NULL)
		return WR_E_INVAL;
	if (out == NULL) {
		wri_rd_fail(r, WR_E_INVAL);
		return r->err;
	}
	WR_MEMSET(out, 0, sizeof(*out));
	marker = wri_rd_u8(r);
	if (r->err != WR_OK)
		return r->err;
	if (marker == 0)
		wri_rd_fail(r, WR_E_UNSUPPORTED); /* legacy sockaddr_storage form */
	else if (marker != 1)
		wri_rd_fail(r, WR_E_ENCODING);
	else
		(void)eaddr_body(r, out); /* an error is recorded in r */
	if (r->err != WR_OK)
		WR_MEMSET(out, 0, sizeof(*out));
	return r->err;
}

/* The canonical encoding of `a` as it would go on the wire now (typed fields win over a stale raw). */
static size_t eaddr_canon(const wri_eaddr *a, uint8_t buf[WRI_EADDR_MAX_WIRE])
{
	uint8_t sa[SA_DATA_MAX];

	eaddr_sa(a, sa);
	return eaddr_pack(buf, a->type, a->nonce, norm_family(a->family), sa);
}

void wri_eaddr_encode(wri_wr *w, const wri_eaddr *a)
{
	uint8_t buf[WRI_EADDR_MAX_WIRE];
	size_t n;

	if (a == NULL) {
		wri_wr_fail(w, WR_E_INVAL);
		return;
	}
	n = eaddr_canon(a, buf);
	wri_wr_bytes(w, buf, n);
}

/* ---- entity_addrvec_t -------------------------------------------------------------------- */

static void vec_clear(wri_eaddr *out, size_t stored, size_t *n_stored, size_t *n_total)
{
	size_t i;

	for (i = 0; out != NULL && i < stored; i++)
		WR_MEMSET(&out[i], 0, sizeof(out[i]));
	if (n_stored != NULL)
		*n_stored = 0;
	if (n_total != NULL)
		*n_total = 0;
}

wr_status wri_eaddrvec_decode(wri_rd *r, wri_eaddr *out, size_t max, size_t *n_stored, size_t *n_total)
{
	size_t stored = 0, total = 0;
	wri_eaddr scratch;
	uint8_t marker;

	if (n_stored != NULL)
		*n_stored = 0;
	if (n_total != NULL)
		*n_total = 0;
	if (r == NULL)
		return WR_E_INVAL;
	if (max > 0 && out == NULL) {
		wri_rd_fail(r, WR_E_INVAL);
		return r->err;
	}
	marker = wri_rd_u8(r);
	if (r->err != WR_OK)
		return r->err;

	if (marker == 0) {
		wri_rd_fail(r, WR_E_UNSUPPORTED);
	} else if (marker == 1) {
		/* the marker byte is shared: one entity_addr_t body follows */
		wri_eaddr *dst = (max > 0) ? &out[0] : &scratch;

		if (eaddr_body(r, dst) == WR_OK) {
			stored = (max > 0) ? 1 : 0;
			total = 1;
		}
	} else if (marker == 2) {
		uint32_t count = wri_rd_count(r, WRI_EADDRVEC_WIRE_MAX, EADDR_MIN_WIRE);
		uint32_t i;

		for (i = 0; i < count && r->err == WR_OK; i++) {
			wri_eaddr *dst = (stored < max) ? &out[stored] : &scratch;

			if (wri_eaddr_decode(r, dst) != WR_OK)
				break;
			if (stored < max)
				stored++;
			total++;
		}
	} else {
		wri_rd_fail(r, WR_E_ENCODING);
	}

	if (r->err != WR_OK) {
		vec_clear(out, stored, n_stored, n_total);
		return r->err;
	}
	if (n_stored != NULL)
		*n_stored = stored;
	if (n_total != NULL)
		*n_total = total;
	return WR_OK;
}

void wri_eaddrvec_encode(wri_wr *w, const wri_eaddr *a, size_t n)
{
	size_t i;

	if (n > WRI_EADDRVEC_WIRE_MAX) {
		wri_wr_fail(w, WR_E_TOOBIG);
		return;
	}
	if (n > 0 && a == NULL) {
		wri_wr_fail(w, WR_E_INVAL);
		return;
	}
	wri_wr_u8(w, 2);
	wri_wr_u32(w, (uint32_t)n);
	for (i = 0; i < n; i++)
		wri_eaddr_encode(w, &a[i]);
}

/* ---- comparison and conversion ----------------------------------------------------------- */

int wri_eaddr_equal(const wri_eaddr *a, const wri_eaddr *b)
{
	uint8_t ca[WRI_EADDR_MAX_WIRE], cb[WRI_EADDR_MAX_WIRE];
	size_t na, nb;

	if (a == NULL || b == NULL)
		return 0;
	/* Compare what would be sent, not the cached raw: an address whose typed fields were edited
	 * after decoding, or one built by hand (raw_len 0), must not compare equal to a different
	 * address just because its cache is stale or empty. For decoded addresses nothing changed:
	 * the canonical form is raw. (Addresses are not secrets, so a plain compare is fine.) */
	na = eaddr_canon(a, ca);
	nb = eaddr_canon(b, cb);
	return na == nb && wri_ct_memeq(ca, cb, na);
}

void wri_eaddr_from_wr(wri_eaddr *out, const wr_addr *a, uint32_t type)
{
	uint8_t sa[SA_DATA_MAX];

	if (out == NULL)
		return;
	WR_MEMSET(out, 0, sizeof(*out));
	out->type = type;
	if (a != NULL) {
		out->nonce = a->nonce;
		out->family = norm_family(a->family);
		if (out->family == WR_AF_IPV4) {
			WR_MEMCPY(out->ip, a->ip, 4); /* the other 12 bytes stay zero */
			out->port = a->port;
		} else if (out->family == WR_AF_IPV6) {
			WR_MEMCPY(out->ip, a->ip, 16);
			out->port = a->port;
		}
	}
	sa_from_fields(out, sa);
	out->raw_len = (uint8_t)eaddr_pack(out->raw, out->type, out->nonce, out->family, sa);
}

void wri_eaddr_to_wr(wr_addr *out, const wri_eaddr *a)
{
	if (out == NULL)
		return;
	WR_MEMSET(out, 0, sizeof(*out));
	if (a == NULL)
		return;
	out->family = norm_family(a->family);
	if (out->family == WR_AF_IPV4)
		WR_MEMCPY(out->ip, a->ip, 4);
	else if (out->family == WR_AF_IPV6)
		WR_MEMCPY(out->ip, a->ip, 16);
	if (out->family != 0)
		out->port = a->port;
	out->nonce = a->nonce;
}
