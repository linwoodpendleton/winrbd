/* SPDX-License-Identifier: MIT */
/*
 * wr_handoff.h - the "rBFT" handoff table, version 1: what a boot loader tells the operating system's
 * boot-start driver so it can open the same RBD image again (the role iBFT plays for iSCSI).
 *
 * The layout is specified in docs/design/handoff-table.md. This header is the codec's whole interface:
 * a plain description of the table (wr_handoff_info), an encoder that builds the body or the whole ACPI
 * table, and a decoder that validates untrusted bytes and hands the fields back.
 *
 * Rules of the codec:
 *   - Encoding is a pure function of its input: the same wr_handoff_info gives the same bytes every time
 *     (the iPXE describe pass rebuilds the table on every call). Nothing is allocated, nothing is kept.
 *   - A table that does not fit the design maximum (WR_HANDOFF_MAX_TABLE bytes) is refused, never
 *     truncated. A failed encode leaves the output buffer untouched.
 *   - The key travels only when WR_HANDOFF_F_KEY is set and is never produced in any other way. The table
 *     is readable by an administrator of the booted OS and by any kernel code (see the design document).
 *   - The decoder accepts exactly the canonical form the encoder produces (variable area in the fixed
 *     order, no gaps, no padding, absent optional strings really absent), so decode followed by encode
 *     returns the input byte for byte. It never reads outside the given buffer and never writes outside
 *     the output structure; on failure the output structure is zeroed.
 *   - The ACPI header's OEM fields are not part of the contract: iPXE overwrites them. The encoder leaves
 *     them zero; a host that sets them must call wr_handoff_fix_checksum() afterwards.
 *
 * Portable C99, freestanding, no allocation, no globals.
 */
#ifndef WR_HANDOFF_H
#define WR_HANDOFF_H

#include "wr_config.h" /* WR_MODE_* */
#include "wr_err.h"
#include "wr_key.h"
#include "wr_types.h"

/* ---- sizes and constants ---------------------------------------------------------------------- */

#define WR_HANDOFF_VERSION 1u          /* the layout version this codec reads and writes */
#define WR_HANDOFF_ACPI_REVISION 1u    /* ACPI header revision */
#define WR_HANDOFF_ACPI_HDR_LEN 36u    /* the standard ACPI table header */
#define WR_HANDOFF_FIXED_LEN 116u      /* fixed part of the body (header_len) */
#define WR_HANDOFF_MAX_TABLE 1024u     /* design maximum of the whole table, ACPI header included */
#define WR_HANDOFF_MAX_BODY (WR_HANDOFF_MAX_TABLE - WR_HANDOFF_ACPI_HDR_LEN)
#define WR_HANDOFF_MAX_STR 255u        /* longest string, bytes without the NUL */
#define WR_HANDOFF_MAX_MONS 8u
#define WR_HANDOFF_MON_REC_LEN 20u     /* {u8 family, u8 reserved, u16 port, u8 ip[16]} */
#define WR_HANDOFF_KEY_MAX 64u
#define WR_HANDOFF_KEY_MIN_AES 16u     /* shortest "aes" secret (the same floor as wr_key_from_raw) */
#define WR_HANDOFF_KEY_MIN_AES256K 32u /* shortest "aes256k" secret */

/* ACPI signature, in table byte order: 'r' 'B' 'F' 'T'. Body magic: 'W' 'R' 'B' 'T'. */
#define WR_HANDOFF_SIGNATURE "rBFT"
#define WR_HANDOFF_MAGIC "WRBT"

/* wr_handoff_info.flags */
#define WR_HANDOFF_F_READONLY 0x01u        /* the loader opened the image read-only */
#define WR_HANDOFF_F_KEY 0x02u             /* the key is in the table (key, key_len, key_type) */
#define WR_HANDOFF_F_NIC_STATIC 0x04u      /* the NIC address was configured statically, not by DHCP */
#define WR_HANDOFF_F_VLAN 0x08u            /* nic_vlan is a VLAN id (1 .. 4094) */
#define WR_HANDOFF_F_FSID 0x10u            /* fsid holds the cluster id */
#define WR_HANDOFF_F_SECURE_REQUIRED 0x20u /* connect in secure mode only; msgr_mode is then WR_MODE_SECURE_ONLY */
#define WR_HANDOFF_F_ALL 0x3fu

/* wr_handoff_info.auth */
#define WR_HANDOFF_AUTH_NONE 0u
#define WR_HANDOFF_AUTH_CEPHX 1u

/* ---- the description of a table ---------------------------------------------------------------- */

/*
 * One table. The same structure is the input of the encoder and the output of the decoder.
 *
 * Strings are NUL-terminated, at most WR_HANDOFF_MAX_STR bytes. NULL or "" means absent. They are bytes
 * to the codec: the design says UTF-8 and the writer supplies it, but the encoding is not checked (only
 * the framing is: length, terminator, place). After a decode the pointers (and `key`) point into the buffer
 * that was decoded and are valid as long as it is; the caller copies what it keeps and wipes the copy of
 * the key. Validation holds for the bytes as they were read: when other code can change the buffer
 * (firmware memory), decode a private copy of the table, not the original.
 *
 * Encoding writes to buf only; buf must not overlap the strings or the key of info (an in-place re-encode
 * of a table that was decoded from that same buffer would overwrite its own source).
 *
 * IP bytes are in network order; an IPv4 address uses ip[0..3] and the other bytes are zero. A monitor
 * is a wr_addr (family WR_AF_IPV4 or WR_AF_IPV6, a non-zero port): its nonce is not carried (0 after a
 * decode, ignored by the encoder). A wr_cluster_spec may leave a port 0 to mean the
 * default (3300); the table never does, so the host fills the default in before it encodes (a port 0 is
 * refused, not guessed).
 *
 * The rules the encoder enforces and the decoder checks (WR_E_HO_FIELD unless noted):
 *   flags: only WR_HANDOFF_F_* bits.
 *   auth: NONE or CEPHX. entity is required with CEPHX. pool and image are always required.
 *   rbd_namespace: must be absent in version 1 (WR_E_UNSUPPORTED).
 *   msgr_mode: WR_MODE_CRC_ONLY .. WR_MODE_SECURE_ONLY (1 .. 4). WR_HANDOFF_F_SECURE_REQUIRED needs 4.
 *   key: present exactly when WR_HANDOFF_F_KEY is set; then auth is CEPHX, key_type is WR_KEY_TYPE_AES or
 *        WR_KEY_TYPE_AES256K, key_len is WR_HANDOFF_KEY_MIN_AES .. WR_HANDOFF_KEY_MAX for "aes" and
 *        WR_HANDOFF_KEY_MIN_AES256K .. WR_HANDOFF_KEY_MAX for "aes256k" (what wr_key_from_raw accepts: a
 *        table that carries a key the core would refuse is refused here, where the error can be named),
 *        and key is not NULL. Otherwise key_type and key_len are 0 (a key that is not allowed in is
 *        refused, not dropped).
 *   mon_count: 1 .. WR_HANDOFF_MAX_MONS.
 *   nic_family: 0 (unknown), 4 or 6. With 0 the prefix and the three addresses are zero. nic_prefix is at
 *        most 32 (IPv4) or 128 (IPv6). WR_HANDOFF_F_NIC_STATIC needs a family.
 *   nic_vlan: 1 .. 4094 with WR_HANDOFF_F_VLAN, else 0.
 *   fsid: zero unless WR_HANDOFF_F_FSID.
 */
typedef struct wr_handoff_info {
	uint32_t flags;      /* WR_HANDOFF_F_* */
	uint8_t auth;        /* WR_HANDOFF_AUTH_* */
	uint8_t msgr_mode;   /* WR_MODE_* (1 .. 4) */
	uint8_t key_type;    /* WR_KEY_TYPE_*, 0 without a key */
	uint8_t key_len;     /* bytes at key, 0 without a key */
	uint8_t mon_count;   /* valid entries of mons */
	uint8_t nic_family;  /* 0, 4 or 6 */
	uint8_t nic_prefix;  /* prefix length of nic_ip */
	uint8_t fsid[16];
	uint8_t nic_mac[6];
	uint16_t nic_vlan;
	uint16_t nic_mtu;
	uint8_t nic_ip[16];
	uint8_t nic_gateway[16];
	uint8_t nic_dns[16];
	const char *entity;        /* cephx user id, for example "winrbd-boot" (no "client." prefix is added) */
	const char *pool;
	const char *rbd_namespace; /* absent in version 1 */
	const char *image;
	const char *image_id;      /* absent unless known */
	const char *snapshot;      /* absent for the head */
	wr_addr mons[WR_HANDOFF_MAX_MONS];
	const uint8_t *key;
} wr_handoff_info;

/* ---- encoding ---------------------------------------------------------------------------------- */

/*
 * Build the body (magic .. key) into buf. *len is set to the body size on success; when the table
 * would not fit it is set to the size it would need (WR_E_HO_TOO_BIG, WR_E_TOOBIG) so a caller can
 * size a buffer; on any other failure it is 0.
 *   WR_E_INVAL      NULL info or len, or buf NULL with cap != 0
 *   WR_E_UNSUPPORTED a namespace
 *   WR_E_HO_FIELD   a field breaks the rules above (string too long included)
 *   WR_E_HO_TOO_BIG the whole table (36 + body) would exceed WR_HANDOFF_MAX_TABLE
 *   WR_E_TOOBIG     cap is smaller than the body (buf may be NULL with cap 0 to just ask the size)
 * Nothing is written to buf unless the call succeeds.
 */
WR_MUST_CHECK wr_status wr_handoff_encode(const wr_handoff_info *info, uint8_t *buf, size_t cap, size_t *len);

/*
 * Build the whole ACPI table: the 36-byte header (signature "rBFT", length, revision 1, checksum, OEM and
 * creator fields zero) followed by the body. Same results and the same refusals as wr_handoff_encode;
 * *len is the table size, and cap is compared with the table size. The checksum makes all bytes of the
 * table sum to 0 modulo 256. A host that changes the OEM fields afterwards calls wr_handoff_fix_checksum.
 */
WR_MUST_CHECK wr_status wr_handoff_encode_table(const wr_handoff_info *info, uint8_t *buf, size_t cap, size_t *len);

/*
 * Recompute the checksum byte of an ACPI table held at table[0 .. len) so that the bytes sum to 0.
 * len is the length field of the header (checked against it: WR_E_HO_LENGTH when it differs, WR_E_TRUNCATED
 * when len < 36, WR_E_INVAL for NULL). For hosts that write the OEM fields. A table the host wrote into has
 * to be at most WR_HANDOFF_MAX_TABLE bytes like every other; a larger len is WR_E_HO_TOO_BIG.
 */
WR_MUST_CHECK wr_status wr_handoff_fix_checksum(uint8_t *table, size_t len);

/* ---- decoding ---------------------------------------------------------------------------------- */

/*
 * Validate the body at body[0 .. len) (len = the body size, ACPI header excluded) and fill *out (which
 * may be NULL when only the verdict is wanted). The structural checks come first, in this order:
 *   WR_E_INVAL      NULL body
 *   WR_E_TRUNCATED  fewer than 8 bytes, or fewer than the 116-byte fixed part
 *   WR_E_HO_SIGNATURE  magic is not "WRBT"
 *   WR_E_HO_VERSION    version is not 1
 *   WR_E_HO_LENGTH     header_len is not 116
 *   WR_E_HO_TOO_BIG    the body does not fit WR_HANDOFF_MAX_BODY
 * then the content, where a table with several defects gets the first one the decoder meets:
 *   WR_E_HO_FIELD      reserved bytes or unknown flag bits not zero, a count or a value out of range,
 *                      a string longer than 255 bytes, key flag and key offset or length disagree, an
 *                      optional string present but empty, any rule of wr_handoff_info
 *   WR_E_HO_OFFSET     an offset or record outside the variable area, or a string without its NUL
 *   WR_E_UNSUPPORTED   a namespace is present
 * and last, once everything else is fine:
 *   WR_E_HO_LAYOUT     the variable area is not the canonical one (gap, overlap, wrong order, trailing bytes)
 */
WR_MUST_CHECK wr_status wr_handoff_decode(const uint8_t *body, size_t len, wr_handoff_info *out);

/*
 * Validate a whole ACPI table held at table[0 .. len) (len may exceed the table: a BIOS scan hands over
 * the rest of its area; bytes after the header's length are ignored). The checks, in order:
 *   WR_E_INVAL      NULL table
 *   WR_E_TRUNCATED  fewer than 36 bytes
 *   WR_E_HO_SIGNATURE  signature is not "rBFT"
 *   WR_E_HO_LENGTH     the length field is smaller than the 36-byte header plus the 116-byte fixed part
 *   WR_E_HO_TOO_BIG    the length field is larger than WR_HANDOFF_MAX_TABLE
 *   WR_E_TRUNCATED     fewer bytes were given than the length field says
 *   WR_E_HO_VERSION    ACPI revision is not 1
 *   WR_E_HO_CHECKSUM   the bytes do not sum to 0 modulo 256
 * then the body checks of wr_handoff_decode on the bytes after the header. A single flipped bit anywhere
 * in the table is refused. The OEM and creator fields are not interpreted.
 */
WR_MUST_CHECK wr_status wr_handoff_decode_table(const uint8_t *table, size_t len, wr_handoff_info *out);

#endif /* WR_HANDOFF_H */
