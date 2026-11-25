/* SPDX-License-Identifier: MIT */
/*
 * wri_handoff_dec.c - the decoder of the rBFT handoff table, version 1 (wr_handoff.h,
 * docs/design/handoff-table.md). Every byte is untrusted: lengths, counts and offsets are compared with the
 * buffer before they are used, a string must have its NUL inside the variable area, and the variable area
 * must be exactly the canonical one the encoder produces, so a table decodes one way only and
 * encode(decode(x)) == x.
 */
#include "wri_handoff.h"

#include "wri_cursor.h"
#include "wri_le.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/*
 * The string at area[off]: *out is NULL when the offset says absent. The NUL must lie inside the area and
 * within WR_HANDOFF_MAX_STR + 1 bytes of the start; a present string is not empty (absent is the way to say so).
 */
static wr_status wri_ho_str(const uint8_t *area, size_t area_len, uint16_t off, const char **out)
{
	size_t avail, lim, k;

	*out = NULL;
	if (off == WRI_HO_ABSENT)
		return WR_OK;
	if (off >= area_len)
		return WR_E_HO_OFFSET;
	avail = area_len - off;
	lim = avail < WR_HANDOFF_MAX_STR + 1u ? avail : WR_HANDOFF_MAX_STR + 1u;
	for (k = 0; k < lim; k++) {
		if (area[off + k] == 0) {
			if (k == 0)
				return WR_E_HO_FIELD;
			*out = (const char *)(area + off);
			return WR_OK;
		}
	}
	/* no NUL in the bytes looked at: the area ended first (unterminated) or the string is over 255 bytes */
	return avail < WR_HANDOFF_MAX_STR + 1u ? WR_E_HO_OFFSET : WR_E_HO_FIELD;
}

/* Offsets as read from the fixed part, in the order of wri_ho_layout. */
enum { HO_O_ENTITY, HO_O_POOL, HO_O_NS, HO_O_IMAGE, HO_O_IMAGE_ID, HO_O_SNAP, HO_O_MONS, HO_O_KEY, HO_O_COUNT };

/* The fixed part into *o and off[]; the reserved bytes and the counts the area parser relies on are checked here. */
static wr_status wri_ho_read_fixed(const uint8_t *b, wr_handoff_info *o, uint16_t off[HO_O_COUNT])
{
	wri_rd r;
	uint32_t rsv2;
	uint16_t rsv1;
	uint8_t rsv0;
	size_t k;

	wri_rd_init(&r, b, WR_HANDOFF_FIXED_LEN);
	wri_rd_skip(&r, WRI_HO_O_FLAGS); /* magic, version, header_len: checked by the caller */
	o->flags = wri_rd_u32(&r);
	o->auth = wri_rd_u8(&r);
	o->msgr_mode = wri_rd_u8(&r);
	o->key_type = wri_rd_u8(&r);
	o->key_len = wri_rd_u8(&r);
	o->mon_count = wri_rd_u8(&r);
	o->nic_family = wri_rd_u8(&r);
	o->nic_prefix = wri_rd_u8(&r);
	rsv0 = wri_rd_u8(&r);
	wri_rd_copy(&r, o->fsid, sizeof(o->fsid));
	wri_rd_copy(&r, o->nic_mac, sizeof(o->nic_mac));
	o->nic_vlan = wri_rd_u16(&r);
	o->nic_mtu = wri_rd_u16(&r);
	rsv1 = wri_rd_u16(&r);
	wri_rd_copy(&r, o->nic_ip, sizeof(o->nic_ip));
	wri_rd_copy(&r, o->nic_gateway, sizeof(o->nic_gateway));
	wri_rd_copy(&r, o->nic_dns, sizeof(o->nic_dns));
	for (k = 0; k < HO_O_COUNT; k++)
		off[k] = wri_rd_u16(&r);
	rsv2 = wri_rd_u32(&r);
	if (!wri_rd_ok(&r) || r.pos != WR_HANDOFF_FIXED_LEN)
		return WR_E_TRUNCATED; /* cannot happen: the caller checked the length */

	if (rsv0 != 0 || rsv1 != 0 || rsv2 != 0 || (o->flags & ~(uint32_t)WR_HANDOFF_F_ALL) != 0)
		return WR_E_HO_FIELD;
	if (o->mon_count == 0 || o->mon_count > WR_HANDOFF_MAX_MONS || o->key_len > WR_HANDOFF_KEY_MAX)
		return WR_E_HO_FIELD;
	/* key flag, key offset and key length must agree */
	if ((o->flags & WR_HANDOFF_F_KEY) != 0) {
		if (off[HO_O_KEY] == WRI_HO_ABSENT || o->key_len == 0)
			return WR_E_HO_FIELD;
	} else if (off[HO_O_KEY] != WRI_HO_ABSENT) {
		return WR_E_HO_FIELD;
	}
	return WR_OK;
}

static wr_status wri_ho_read_mons(const uint8_t *area, size_t area_len, uint16_t off, wr_handoff_info *o)
{
	wri_rd r;
	size_t k, need = (size_t)o->mon_count * WR_HANDOFF_MON_REC_LEN;

	if (off == WRI_HO_ABSENT || off > area_len || need > area_len - off)
		return WR_E_HO_OFFSET;
	wri_rd_init(&r, area + off, need);
	for (k = 0; k < o->mon_count; k++) {
		uint8_t rsv;

		o->mons[k].family = wri_rd_u8(&r);
		rsv = wri_rd_u8(&r);
		o->mons[k].port = wri_rd_u16(&r);
		wri_rd_copy(&r, o->mons[k].ip, sizeof(o->mons[k].ip));
		o->mons[k].nonce = 0;
		if (rsv != 0)
			return WR_E_HO_FIELD;
	}
	return wri_rd_ok(&r) ? WR_OK : WR_E_TRUNCATED;
}

static wr_status wri_ho_read_area(const uint8_t *area, size_t area_len, const uint16_t off[HO_O_COUNT],
				  wr_handoff_info *o)
{
	wr_status st;

	st = wri_ho_str(area, area_len, off[HO_O_ENTITY], &o->entity);
	if (st == WR_OK)
		st = wri_ho_str(area, area_len, off[HO_O_POOL], &o->pool);
	if (st == WR_OK)
		st = wri_ho_str(area, area_len, off[HO_O_NS], &o->rbd_namespace);
	if (st == WR_OK)
		st = wri_ho_str(area, area_len, off[HO_O_IMAGE], &o->image);
	if (st == WR_OK)
		st = wri_ho_str(area, area_len, off[HO_O_IMAGE_ID], &o->image_id);
	if (st == WR_OK)
		st = wri_ho_str(area, area_len, off[HO_O_SNAP], &o->snapshot);
	if (st == WR_OK)
		st = wri_ho_read_mons(area, area_len, off[HO_O_MONS], o);
	if (st == WR_OK && (o->flags & WR_HANDOFF_F_KEY) != 0) {
		if (off[HO_O_KEY] > area_len || (size_t)o->key_len > area_len - off[HO_O_KEY])
			return WR_E_HO_OFFSET;
		o->key = area + off[HO_O_KEY];
	}
	return st;
}

/* The offsets and the length read from the table must be the canonical ones of what it decoded to. */
static int wri_ho_is_canonical(const wri_ho_layout *l, const uint16_t off[HO_O_COUNT], size_t len)
{
	return l->off_entity == off[HO_O_ENTITY] && l->off_pool == off[HO_O_POOL] && l->off_ns == off[HO_O_NS] &&
	       l->off_image == off[HO_O_IMAGE] && l->off_image_id == off[HO_O_IMAGE_ID] &&
	       l->off_snap == off[HO_O_SNAP] && l->off_mons == off[HO_O_MONS] && l->off_key == off[HO_O_KEY] &&
	       l->body_len == len;
}

static wr_status wri_ho_parse(const uint8_t *b, size_t len, wr_handoff_info *o)
{
	static const uint8_t magic[4] = {'W', 'R', 'B', 'T'};
	uint16_t off[HO_O_COUNT];
	wri_ho_layout l;
	wr_status st;

	if (len < WRI_HO_O_FLAGS)
		return WR_E_TRUNCATED;
	if (!wri_ct_memeq(b + WRI_HO_O_MAGIC, magic, sizeof(magic)))
		return WR_E_HO_SIGNATURE;
	if (wri_le16_get(b + WRI_HO_O_VERSION) != WR_HANDOFF_VERSION)
		return WR_E_HO_VERSION;
	if (wri_le16_get(b + WRI_HO_O_HDRLEN) != WR_HANDOFF_FIXED_LEN)
		return WR_E_HO_LENGTH;
	if (len < WR_HANDOFF_FIXED_LEN)
		return WR_E_TRUNCATED;
	if (len > WR_HANDOFF_MAX_BODY)
		return WR_E_HO_TOO_BIG;

	st = wri_ho_read_fixed(b, o, off);
	if (st == WR_OK)
		st = wri_ho_read_area(b + WR_HANDOFF_FIXED_LEN, len - WR_HANDOFF_FIXED_LEN, off, o);
	if (st == WR_OK)
		st = wri_ho_check_info(o);
	if (st != WR_OK)
		return st;
	wri_ho_layout_of(o, &l);
	return wri_ho_is_canonical(&l, off, len) ? WR_OK : WR_E_HO_LAYOUT;
}

wr_status wr_handoff_decode(const uint8_t *body, size_t len, wr_handoff_info *out)
{
	wr_handoff_info tmp;
	wr_handoff_info *o = out != NULL ? out : &tmp;
	wr_status st;

	WR_MEMSET(o, 0, sizeof(*o));
	if (body == NULL)
		return WR_E_INVAL;
	st = wri_ho_parse(body, len, o);
	if (st != WR_OK)
		WR_MEMSET(o, 0, sizeof(*o)); /* nothing half-decoded, no pointer into a refused table */
	return st;
}

wr_status wr_handoff_decode_table(const uint8_t *table, size_t len, wr_handoff_info *out)
{
	static const uint8_t sig[4] = {'r', 'B', 'F', 'T'};
	uint32_t tlen;
	uint8_t sum = 0;
	size_t k;

	if (out != NULL)
		WR_MEMSET(out, 0, sizeof(*out));
	if (table == NULL)
		return WR_E_INVAL;
	if (len < WR_HANDOFF_ACPI_HDR_LEN)
		return WR_E_TRUNCATED;
	if (!wri_ct_memeq(table + WRI_HO_ACPI_SIG, sig, sizeof(sig)))
		return WR_E_HO_SIGNATURE;
	tlen = wri_le32_get(table + WRI_HO_ACPI_LEN);
	if (tlen < WR_HANDOFF_ACPI_HDR_LEN + WR_HANDOFF_FIXED_LEN)
		return WR_E_HO_LENGTH;
	if (tlen > WR_HANDOFF_MAX_TABLE)
		return WR_E_HO_TOO_BIG;
	if ((size_t)tlen > len)
		return WR_E_TRUNCATED;
	if (table[WRI_HO_ACPI_REV] != WR_HANDOFF_ACPI_REVISION)
		return WR_E_HO_VERSION;
	for (k = 0; k < tlen; k++)
		sum = (uint8_t)(sum + table[k]);
	if (sum != 0)
		return WR_E_HO_CHECKSUM;
	return wr_handoff_decode(table + WR_HANDOFF_ACPI_HDR_LEN, (size_t)tlen - WR_HANDOFF_ACPI_HDR_LEN, out);
}
