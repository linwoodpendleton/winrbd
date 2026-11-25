/* SPDX-License-Identifier: MIT */
/*
 * wri_handoff.h - internals of the rBFT handoff table codec (wr_handoff.h, docs/design/handoff-table.md):
 * the offsets of the fixed part, the canonical layout of the variable area, and the field rules the
 * encoder and the decoder share. Two files use it: wri_handoff_enc.c (rules, layout, encoder) and
 * wri_handoff_dec.c (decoder).
 */
#ifndef WRI_HANDOFF_H
#define WRI_HANDOFF_H

#include "wr_config.h"
#include "wr_err.h"
#include "wr_handoff.h"
#include "wr_port.h"

/* Offsets in the fixed part of the body (little-endian, packed; the table of the design document). */
#define WRI_HO_O_MAGIC 0u
#define WRI_HO_O_VERSION 4u
#define WRI_HO_O_HDRLEN 6u
#define WRI_HO_O_FLAGS 8u
#define WRI_HO_O_AUTH 12u
#define WRI_HO_O_MODE 13u
#define WRI_HO_O_KEYTYPE 14u
#define WRI_HO_O_KEYLEN 15u
#define WRI_HO_O_MONCNT 16u
#define WRI_HO_O_NICFAM 17u
#define WRI_HO_O_NICPFX 18u
#define WRI_HO_O_RSV0 19u
#define WRI_HO_O_FSID 20u
#define WRI_HO_O_MAC 36u
#define WRI_HO_O_VLAN 42u
#define WRI_HO_O_MTU 44u
#define WRI_HO_O_RSV1 46u
#define WRI_HO_O_IP 48u
#define WRI_HO_O_GW 64u
#define WRI_HO_O_DNS 80u
#define WRI_HO_O_OFF_ENTITY 96u
#define WRI_HO_O_OFF_POOL 98u
#define WRI_HO_O_OFF_NS 100u
#define WRI_HO_O_OFF_IMAGE 102u
#define WRI_HO_O_OFF_IMAGE_ID 104u
#define WRI_HO_O_OFF_SNAP 106u
#define WRI_HO_O_OFF_MONS 108u
#define WRI_HO_O_OFF_KEY 110u
#define WRI_HO_O_RSV2 112u /* 4 bytes, the end of the fixed part is at 116 */

#define WRI_HO_ABSENT 0xffffu /* an offset field with no data behind it */

/* ACPI header offsets (the table = header + body). */
#define WRI_HO_ACPI_SIG 0u
#define WRI_HO_ACPI_LEN 4u
#define WRI_HO_ACPI_REV 8u
#define WRI_HO_ACPI_SUM 9u

WR_STATIC_ASSERT(WRI_HO_O_RSV2 + 4u == WR_HANDOFF_FIXED_LEN, ho_fixed_len);

/*
 * Where each part of the variable area goes in the one canonical form (strings in the order entity,
 * pool, namespace, image, image id, snapshot, each followed by its NUL, then the monitor records, then
 * the key; no padding). Offsets are relative to the start of the variable area, WRI_HO_ABSENT if absent.
 */
typedef struct wri_ho_layout {
	uint16_t off_entity;
	uint16_t off_pool;
	uint16_t off_ns;
	uint16_t off_image;
	uint16_t off_image_id;
	uint16_t off_snap;
	uint16_t off_mons;
	uint16_t off_key;
	size_t area_len; /* bytes of the variable area */
	size_t body_len; /* fixed part + variable area */
} wri_ho_layout;

/* A string counts as present when it is non-NULL and not empty. */
WR_INLINE int wri_ho_present(const char *s) { return s != NULL && s[0] != '\0'; }

/* Length of s up to WR_HANDOFF_MAX_STR + 1: a result above WR_HANDOFF_MAX_STR means "too long". NULL is 0. */
size_t wri_ho_slen(const char *s);

/*
 * The rules of wr_handoff_info (see wr_handoff.h) applied to one description: WR_OK, WR_E_HO_FIELD or
 * WR_E_UNSUPPORTED (a namespace). Shared by the encoder (input) and the decoder (what it read).
 */
WR_MUST_CHECK wr_status wri_ho_check_info(const wr_handoff_info *info);

/* The canonical layout of an info that passed wri_ho_check_info. */
void wri_ho_layout_of(const wr_handoff_info *info, wri_ho_layout *l);

#endif /* WRI_HANDOFF_H */
