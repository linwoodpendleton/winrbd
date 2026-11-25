/* SPDX-License-Identifier: MIT */
/*
 * wri_handoff_enc.c - the rBFT handoff table, version 1: the field rules, the canonical layout and the
 * encoder (wr_handoff.h, docs/design/handoff-table.md).
 *
 * The encoder is a pure function of its input. It validates everything and computes the layout before it
 * writes a byte, so a refused table leaves the caller's buffer untouched (no half-written key).
 */
#include "wri_handoff.h"

#include "wri_cursor.h"
#include "wri_le.h"

WR_FILE_LICENCE_MIT

/* ---- small helpers ------------------------------------------------------------------------------ */

size_t wri_ho_slen(const char *s)
{
	size_t n = 0;

	if (s == NULL)
		return 0;
	while (n <= WR_HANDOFF_MAX_STR && s[n] != '\0')
		n++;
	return n;
}

/* 1 when p[0 .. n) is all zero. */
static int wri_ho_zero(const uint8_t *p, size_t n)
{
	uint8_t acc = 0;
	size_t i;

	for (i = 0; i < n; i++)
		acc = (uint8_t)(acc | p[i]);
	return acc == 0;
}

/* An address in a 16-byte field: an IPv4 address (family 4) leaves bytes 4 .. 15 zero. */
static int wri_ho_addr_ok(unsigned family, const uint8_t ip[16])
{
	if (family == 4u)
		return wri_ho_zero(ip + 4, 12);
	return family == 6u;
}

/* ---- the rules --------------------------------------------------------------------------------- */

static wr_status wri_ho_check_strings(const wr_handoff_info *i)
{
	if (wri_ho_slen(i->entity) > WR_HANDOFF_MAX_STR || wri_ho_slen(i->pool) > WR_HANDOFF_MAX_STR ||
	    wri_ho_slen(i->rbd_namespace) > WR_HANDOFF_MAX_STR || wri_ho_slen(i->image) > WR_HANDOFF_MAX_STR ||
	    wri_ho_slen(i->image_id) > WR_HANDOFF_MAX_STR || wri_ho_slen(i->snapshot) > WR_HANDOFF_MAX_STR)
		return WR_E_HO_FIELD;
	if (!wri_ho_present(i->pool) || !wri_ho_present(i->image))
		return WR_E_HO_FIELD;
	if (i->auth == WR_HANDOFF_AUTH_CEPHX && !wri_ho_present(i->entity))
		return WR_E_HO_FIELD;
	return WR_OK;
}

static wr_status wri_ho_check_key(const wr_handoff_info *i)
{
	if ((i->flags & WR_HANDOFF_F_KEY) == 0)
		return (i->key_type == 0 && i->key_len == 0) ? WR_OK : WR_E_HO_FIELD;
	if (i->auth != WR_HANDOFF_AUTH_CEPHX || i->key == NULL)
		return WR_E_HO_FIELD;
	if (i->key_type != WR_KEY_TYPE_AES && i->key_type != WR_KEY_TYPE_AES256K)
		return WR_E_HO_FIELD;
	if (i->key_len > WR_HANDOFF_KEY_MAX ||
	    i->key_len < (i->key_type == WR_KEY_TYPE_AES ? WR_HANDOFF_KEY_MIN_AES : WR_HANDOFF_KEY_MIN_AES256K))
		return WR_E_HO_FIELD;
	return WR_OK;
}

static wr_status wri_ho_check_mons(const wr_handoff_info *i)
{
	size_t k;

	if (i->mon_count == 0 || i->mon_count > WR_HANDOFF_MAX_MONS)
		return WR_E_HO_FIELD;
	for (k = 0; k < i->mon_count; k++) {
		const wr_addr *a = &i->mons[k];

		if ((a->family != WR_AF_IPV4 && a->family != WR_AF_IPV6) || a->port == 0 ||
		    !wri_ho_addr_ok(a->family, a->ip))
			return WR_E_HO_FIELD;
	}
	return WR_OK;
}

static wr_status wri_ho_check_nic(const wr_handoff_info *i)
{
	unsigned maxpfx;

	if (i->nic_family != 0 && i->nic_family != 4 && i->nic_family != 6)
		return WR_E_HO_FIELD;
	if (i->nic_family == 0) {
		if (i->nic_prefix != 0 || !wri_ho_zero(i->nic_ip, 16) || !wri_ho_zero(i->nic_gateway, 16) ||
		    !wri_ho_zero(i->nic_dns, 16) || (i->flags & WR_HANDOFF_F_NIC_STATIC) != 0)
			return WR_E_HO_FIELD;
	} else {
		maxpfx = i->nic_family == 4 ? 32u : 128u;
		if (i->nic_prefix > maxpfx || !wri_ho_addr_ok(i->nic_family, i->nic_ip) ||
		    !wri_ho_addr_ok(i->nic_family, i->nic_gateway) || !wri_ho_addr_ok(i->nic_family, i->nic_dns))
			return WR_E_HO_FIELD;
	}
	if ((i->flags & WR_HANDOFF_F_VLAN) != 0) {
		if (i->nic_vlan == 0 || i->nic_vlan > 4094u)
			return WR_E_HO_FIELD;
	} else if (i->nic_vlan != 0) {
		return WR_E_HO_FIELD;
	}
	return WR_OK;
}

wr_status wri_ho_check_info(const wr_handoff_info *i)
{
	wr_status st;

	if ((i->flags & ~(uint32_t)WR_HANDOFF_F_ALL) != 0)
		return WR_E_HO_FIELD;
	if (i->auth != WR_HANDOFF_AUTH_NONE && i->auth != WR_HANDOFF_AUTH_CEPHX)
		return WR_E_HO_FIELD;
	if (i->msgr_mode < WR_MODE_CRC_ONLY || i->msgr_mode > WR_MODE_SECURE_ONLY)
		return WR_E_HO_FIELD;
	if ((i->flags & WR_HANDOFF_F_SECURE_REQUIRED) != 0 && i->msgr_mode != WR_MODE_SECURE_ONLY)
		return WR_E_HO_FIELD;
	if ((i->flags & WR_HANDOFF_F_FSID) == 0 && !wri_ho_zero(i->fsid, sizeof(i->fsid)))
		return WR_E_HO_FIELD;
	st = wri_ho_check_key(i);
	if (st == WR_OK)
		st = wri_ho_check_mons(i);
	if (st == WR_OK)
		st = wri_ho_check_nic(i);
	if (st == WR_OK)
		st = wri_ho_check_strings(i);
	if (st == WR_OK && wri_ho_present(i->rbd_namespace))
		st = WR_E_UNSUPPORTED; /* the field exists in the layout; version 1 writers and readers leave it absent */
	return st;
}

/* ---- the layout --------------------------------------------------------------------------------- */

/* Give a string its slot at *pos (offset + length + NUL) or WRI_HO_ABSENT. */
static uint16_t wri_ho_slot(const char *s, size_t *pos)
{
	uint16_t off;

	if (!wri_ho_present(s))
		return WRI_HO_ABSENT;
	off = (uint16_t)*pos;
	*pos += wri_ho_slen(s) + 1u;
	return off;
}

void wri_ho_layout_of(const wr_handoff_info *i, wri_ho_layout *l)
{
	size_t pos = 0;

	l->off_entity = wri_ho_slot(i->entity, &pos);
	l->off_pool = wri_ho_slot(i->pool, &pos);
	l->off_ns = wri_ho_slot(i->rbd_namespace, &pos);
	l->off_image = wri_ho_slot(i->image, &pos);
	l->off_image_id = wri_ho_slot(i->image_id, &pos);
	l->off_snap = wri_ho_slot(i->snapshot, &pos);
	l->off_mons = (uint16_t)pos;
	pos += (size_t)i->mon_count * WR_HANDOFF_MON_REC_LEN;
	if ((i->flags & WR_HANDOFF_F_KEY) != 0) {
		l->off_key = (uint16_t)pos;
		pos += i->key_len;
	} else {
		l->off_key = WRI_HO_ABSENT;
	}
	l->area_len = pos;
	l->body_len = WR_HANDOFF_FIXED_LEN + pos;
}

/* ---- the encoder -------------------------------------------------------------------------------- */

static void wri_ho_put_str(wri_wr *w, const char *s)
{
	if (wri_ho_present(s))
		wri_wr_bytes(w, (const uint8_t *)s, wri_ho_slen(s) + 1u);
}

/* The fixed part, byte for byte as the design document lists it. */
static void wri_ho_write_fixed(wri_wr *w, const wr_handoff_info *i, const wri_ho_layout *l)
{
	wri_wr_bytes(w, (const uint8_t *)WR_HANDOFF_MAGIC, 4);
	wri_wr_u16(w, (uint16_t)WR_HANDOFF_VERSION);
	wri_wr_u16(w, (uint16_t)WR_HANDOFF_FIXED_LEN);
	wri_wr_u32(w, i->flags);
	wri_wr_u8(w, i->auth);
	wri_wr_u8(w, i->msgr_mode);
	wri_wr_u8(w, i->key_type);
	wri_wr_u8(w, i->key_len);
	wri_wr_u8(w, i->mon_count);
	wri_wr_u8(w, i->nic_family);
	wri_wr_u8(w, i->nic_prefix);
	wri_wr_u8(w, 0); /* reserved */
	wri_wr_bytes(w, i->fsid, sizeof(i->fsid));
	wri_wr_bytes(w, i->nic_mac, sizeof(i->nic_mac));
	wri_wr_u16(w, i->nic_vlan);
	wri_wr_u16(w, i->nic_mtu);
	wri_wr_u16(w, 0); /* reserved */
	wri_wr_bytes(w, i->nic_ip, sizeof(i->nic_ip));
	wri_wr_bytes(w, i->nic_gateway, sizeof(i->nic_gateway));
	wri_wr_bytes(w, i->nic_dns, sizeof(i->nic_dns));
	wri_wr_u16(w, l->off_entity);
	wri_wr_u16(w, l->off_pool);
	wri_wr_u16(w, l->off_ns);
	wri_wr_u16(w, l->off_image);
	wri_wr_u16(w, l->off_image_id);
	wri_wr_u16(w, l->off_snap);
	wri_wr_u16(w, l->off_mons);
	wri_wr_u16(w, l->off_key);
	wri_wr_u32(w, 0); /* reserved */
}

/* The variable area in its canonical order: strings, monitor records, key. */
static void wri_ho_write_area(wri_wr *w, const wr_handoff_info *i)
{
	size_t k;

	wri_ho_put_str(w, i->entity);
	wri_ho_put_str(w, i->pool);
	wri_ho_put_str(w, i->rbd_namespace);
	wri_ho_put_str(w, i->image);
	wri_ho_put_str(w, i->image_id);
	wri_ho_put_str(w, i->snapshot);
	for (k = 0; k < i->mon_count; k++) {
		wri_wr_u8(w, i->mons[k].family);
		wri_wr_u8(w, 0); /* reserved */
		wri_wr_u16(w, i->mons[k].port);
		wri_wr_bytes(w, i->mons[k].ip, sizeof(i->mons[k].ip));
	}
	if ((i->flags & WR_HANDOFF_F_KEY) != 0)
		wri_wr_bytes(w, i->key, i->key_len);
}

/* The body. The caller sized w and checked the info. */
static void wri_ho_write_body(wri_wr *w, const wr_handoff_info *i, const wri_ho_layout *l)
{
	wri_ho_write_fixed(w, i, l);
	wri_ho_write_area(w, i);
}

/*
 * Validate, lay out and size-check. On WR_OK *l is the layout and *len the size to write (hdr + body); on
 * WR_E_HO_TOO_BIG and WR_E_TOOBIG *len is the size that would be needed; on any other failure *len is untouched.
 */
static wr_status wri_ho_plan(const wr_handoff_info *info, size_t hdr, size_t cap, size_t *len, wri_ho_layout *l)
{
	wr_status st = wri_ho_check_info(info);

	if (st != WR_OK)
		return st;
	wri_ho_layout_of(info, l);
	*len = hdr + l->body_len;
	if (l->body_len > WR_HANDOFF_MAX_BODY) /* the design maximum is of the whole table, so the body alone is held to it too */
		return WR_E_HO_TOO_BIG;
	if (*len > cap)
		return WR_E_TOOBIG;
	return WR_OK;
}

wr_status wr_handoff_encode(const wr_handoff_info *info, uint8_t *buf, size_t cap, size_t *len)
{
	wri_ho_layout l;
	wri_wr w;
	wr_status st;

	if (len == NULL)
		return WR_E_INVAL;
	*len = 0;
	if (info == NULL || (buf == NULL && cap != 0))
		return WR_E_INVAL;
	st = wri_ho_plan(info, 0, cap, len, &l);
	if (st != WR_OK)
		return st;
	wri_wr_init(&w, buf, cap);
	wri_ho_write_body(&w, info, &l);
	if (!wri_wr_ok(&w) || wri_wr_len(&w) != l.body_len) {
		*len = 0;
		return WR_E_STATE; /* cannot happen: the size was checked; never report a short table as good */
	}
	return WR_OK;
}

wr_status wr_handoff_fix_checksum(uint8_t *table, size_t len)
{
	uint8_t sum = 0;
	size_t i;

	if (table == NULL)
		return WR_E_INVAL;
	if (len < WR_HANDOFF_ACPI_HDR_LEN)
		return WR_E_TRUNCATED;
	if ((size_t)wri_le32_get(table + WRI_HO_ACPI_LEN) != len) /* compared as size_t: no wrap of a 64-bit len into the field */
		return WR_E_HO_LENGTH;
	if (len > WR_HANDOFF_MAX_TABLE)
		return WR_E_HO_TOO_BIG;
	table[WRI_HO_ACPI_SUM] = 0;
	for (i = 0; i < len; i++)
		sum = (uint8_t)(sum + table[i]);
	table[WRI_HO_ACPI_SUM] = (uint8_t)(0u - sum);
	return WR_OK;
}

wr_status wr_handoff_encode_table(const wr_handoff_info *info, uint8_t *buf, size_t cap, size_t *len)
{
	wri_ho_layout l;
	wri_wr w;
	wr_status st;

	if (len == NULL)
		return WR_E_INVAL;
	*len = 0;
	if (info == NULL || (buf == NULL && cap != 0))
		return WR_E_INVAL;
	st = wri_ho_plan(info, WR_HANDOFF_ACPI_HDR_LEN, cap, len, &l);
	if (st != WR_OK)
		return st;
	wri_wr_init(&w, buf, cap);
	wri_wr_bytes(&w, (const uint8_t *)WR_HANDOFF_SIGNATURE, 4);
	wri_wr_u32(&w, (uint32_t)*len);
	wri_wr_u8(&w, (uint8_t)WR_HANDOFF_ACPI_REVISION);
	wri_wr_u8(&w, 0); /* checksum, fixed below */
	wri_wr_zero(&w, 26); /* OEM id, OEM table id, OEM revision, creator id, creator revision: the host's */
	wri_ho_write_body(&w, info, &l);
	if (!wri_wr_ok(&w) || wri_wr_len(&w) != *len) {
		*len = 0;
		return WR_E_STATE; /* cannot happen: see above */
	}
	return wr_handoff_fix_checksum(buf, *len);
}
