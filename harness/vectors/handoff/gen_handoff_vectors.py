#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Writes the golden vectors of the rBFT handoff table, version 1 (docs/design/handoff-table.md), and the seed
corpus of the fuzz target.

This is a SECOND implementation of the layout, written from the table in the design document with struct.pack_into
at absolute offsets and no shared code with core/src/handoff/. The C tests encode the described tables and must
reproduce the bytes written here; the decoder must refuse every damaged table listed here for the stated reason.

    python3 -I harness/vectors/handoff/gen_handoff_vectors.py               rewrite handoff-v1.json
    python3 -I harness/vectors/handoff/gen_handoff_vectors.py --check       exit 1 when handoff-v1.json is stale
    python3 -I harness/vectors/handoff/gen_handoff_vectors.py --seeds DIR   also write the fuzz seeds into DIR

Everything is deterministic. The keys are fixed fake patterns, not keys of any cluster.
"""
import argparse
import ipaddress
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "handoff-v1.json")

FIXED = 116
ACPI = 36
MAX_TABLE = 1024
ABSENT = 0xFFFF

F_RO, F_KEY, F_STATIC, F_VLAN, F_FSID, F_SECREQ = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
MODE_CRC_ONLY, MODE_CRC_FIRST, MODE_SECURE_FIRST, MODE_SECURE_ONLY = 1, 2, 3, 4
KEY_AES, KEY_AES256K = 1, 2

# absolute offsets of the fixed part (the table of the design document, section "Layout")
O = dict(magic=0, version=4, header_len=6, flags=8, auth=12, msgr_mode=13, key_type=14, key_len=15, mon_count=16,
         nic_family=17, nic_prefix=18, rsv0=19, fsid=20, nic_mac=36, nic_vlan=42, nic_mtu=44, rsv1=46, nic_ip=48,
         nic_gateway=64, nic_dns=80, off_entity=96, off_pool=98, off_namespace=100, off_image=102, off_image_id=104,
         off_snapshot=106, off_mons=108, off_key=110, rsv2=112)
STRINGS = [("entity", "off_entity"), ("pool", "off_pool"), ("rbd_namespace", "off_namespace"), ("image", "off_image"),
           ("image_id", "off_image_id"), ("snapshot", "off_snapshot")]


def ip16(text):
    """An address as the 16 bytes of the table (IPv4: the four bytes, then zeros)."""
    a = ipaddress.ip_address(text)
    return a.packed + b"\0" * (16 - len(a.packed))


def mon(text, port=3300):
    return {"family": 4 if ":" not in text else 6, "port": port, "ip": ip16(text).hex(), "ip_text": text}


def key_pattern(n, seed):
    """A fixed fake key: not the key of anything."""
    return bytes(((i * 37 + seed) & 0xFF) for i in range(n))


def base_info(**kw):
    i = {
        "flags": 0, "auth": 1, "msgr_mode": MODE_CRC_ONLY, "key_type": 0, "key": "",
        "fsid": "00" * 16, "nic_mac": "525400123456", "nic_vlan": 0, "nic_mtu": 1500, "nic_family": 4,
        "nic_prefix": 24, "nic_ip": ip16("10.77.0.50").hex(), "nic_gateway": ip16("10.77.0.1").hex(),
        "nic_dns": ip16("10.77.0.2").hex(),
        "entity": "winrbd-boot", "pool": "winrbd", "rbd_namespace": "", "image": "boot-win11", "image_id": "",
        "snapshot": "",
        "mons": [mon("10.77.0.10"), mon("10.77.0.11"), mon("10.77.0.12")],
    }
    i.update(kw)
    return i


def build_body(i, area_override=None, fixed_patch=None):
    """The body of a described table, laid out in the canonical order. No validation: refusal vectors use it too."""
    fixed = bytearray(FIXED)
    area = bytearray()
    offs = {}
    for name, field in STRINGS:
        s = i.get(name) or ""
        if s:
            offs[field] = len(area)
            area += s.encode("utf-8") + b"\0"
        else:
            offs[field] = ABSENT
    mons = i["mons"]
    offs["off_mons"] = len(area)
    for m in mons:
        area += struct.pack("<BBH", m["family"], 0, m["port"]) + bytes.fromhex(m["ip"])
    key = bytes.fromhex(i.get("key", ""))
    offs["off_key"] = len(area) if (i["flags"] & F_KEY) else ABSENT
    if i["flags"] & F_KEY:
        area += key
    fixed[0:4] = b"WRBT"
    struct.pack_into("<H", fixed, O["version"], 1)
    struct.pack_into("<H", fixed, O["header_len"], FIXED)
    struct.pack_into("<I", fixed, O["flags"], i["flags"])
    fixed[O["auth"]] = i["auth"]
    fixed[O["msgr_mode"]] = i["msgr_mode"]
    fixed[O["key_type"]] = i["key_type"]
    fixed[O["key_len"]] = i.get("key_len", len(key))
    fixed[O["mon_count"]] = i.get("mon_count", len(mons))
    fixed[O["nic_family"]] = i["nic_family"]
    fixed[O["nic_prefix"]] = i["nic_prefix"]
    fixed[O["fsid"]:O["fsid"] + 16] = bytes.fromhex(i["fsid"])
    fixed[O["nic_mac"]:O["nic_mac"] + 6] = bytes.fromhex(i["nic_mac"])
    struct.pack_into("<H", fixed, O["nic_vlan"], i["nic_vlan"])
    struct.pack_into("<H", fixed, O["nic_mtu"], i["nic_mtu"])
    fixed[O["nic_ip"]:O["nic_ip"] + 16] = bytes.fromhex(i["nic_ip"])
    fixed[O["nic_gateway"]:O["nic_gateway"] + 16] = bytes.fromhex(i["nic_gateway"])
    fixed[O["nic_dns"]:O["nic_dns"] + 16] = bytes.fromhex(i["nic_dns"])
    for field, v in offs.items():
        struct.pack_into("<H", fixed, O[field], v)
    if fixed_patch:
        fixed_patch(fixed)
    return bytes(fixed) + bytes(area if area_override is None else area_override)


def wrap_table(body, fix=True, length=None, rev=1, sig=b"rBFT"):
    n = ACPI + len(body) if length is None else length
    t = bytearray(sig + struct.pack("<IBB", n, rev, 0) + b"\0" * 26 + body)
    if fix:
        t[9] = (-sum(t[:min(len(t), n)] if n <= len(t) else t)) & 0xFF
    return bytes(t)


def set_checksum(t):
    t = bytearray(t)
    t[9] = 0
    t[9] = (-sum(t)) & 0xFF
    return bytes(t)


# ---- the valid tables ---------------------------------------------------------------------------------------

def valid_cases():
    v6 = [mon("fd00:77::%x" % (0x10 + k), 3300 + (k % 2) * 3200) for k in range(8)]
    # the last monitor's bytes are not zero, so a string pointed at them is unterminated (used by a refusal vector)
    v6[7]["ip"] = bytes([0xFD, 0, 0x00, 0x77] + [0] * 8 + [0, 0, 0x0B, 0x0C]).hex()
    long_pool = "p" * 135
    cases = []

    def add(name, why, info):
        body = build_body(info)
        cases.append({"name": name, "why": why, "info": info, "body": body.hex(), "table": wrap_table(body).hex()})

    add("typical_ipv4_nokey", "three IPv4 monitors, no key, DHCP NIC, fsid known, crc mode",
        base_info(flags=F_FSID, fsid=key_pattern(16, 7).hex()))
    add("typical_ipv4_key_aes256k", "the same with the key in the table (aes256k, 32 bytes) and the image opened read-only",
        base_info(flags=F_FSID | F_KEY | F_RO, fsid=key_pattern(16, 7).hex(), key_type=KEY_AES256K,
                  key=key_pattern(32, 0x11).hex()))
    add("key_aes_legacy_16", "legacy aes key, 16 bytes, secure-first mode",
        base_info(flags=F_KEY, key_type=KEY_AES, key=key_pattern(16, 0x5A).hex(), msgr_mode=MODE_SECURE_FIRST))
    add("eight_ipv6_monitors", "eight IPv6 monitors, IPv6 NIC with a VLAN, secure required, snapshot and image id",
        base_info(flags=F_VLAN | F_SECREQ | F_STATIC, msgr_mode=MODE_SECURE_ONLY, nic_vlan=100, nic_family=6,
                  nic_prefix=64, nic_ip=ip16("fd00:77::50").hex(), nic_gateway=ip16("fd00:77::1").hex(),
                  nic_dns=ip16("fd00:77::2").hex(), mons=v6, image_id="10a3b7e2c91f", snapshot="before-update"))
    add("all_flags_key_64", "every flag, a 64-byte key, VLAN 4094, static IPv4, mode secure-only",
        base_info(flags=0x3F, msgr_mode=MODE_SECURE_ONLY, key_type=KEY_AES256K,
                  key=key_pattern(64, 0x21).hex(), fsid=key_pattern(16, 3).hex(), nic_vlan=4094,
                  nic_mtu=9000, nic_prefix=32, image_id="5f0e1d2c3b4a"))
    add("minimal_no_auth", "no authentication, no entity, one monitor, NIC unknown",
        base_info(auth=0, entity="", nic_family=0, nic_prefix=0, nic_mtu=0, nic_mac="000000000000",
                  nic_ip="00" * 16, nic_gateway="00" * 16, nic_dns="00" * 16, mons=[mon("10.77.0.10", 6789)]))
    add("utf8_names", "names are UTF-8: two-byte and three-byte sequences",
        base_info(entity="winrbd-boöt", pool="pûl", image="引导盘-é"))
    add("max_size_1024", "the whole table is exactly 1,024 bytes: 255-byte entity and image, 135-byte pool, 8 monitors, 64-byte key",
        base_info(flags=F_KEY, key_type=KEY_AES256K, key=key_pattern(64, 0x33).hex(), entity="e" * 255,
                  pool=long_pool, image="i" * 255, mons=[mon("10.77.0.%d" % (10 + k)) for k in range(8)]))
    return cases


# ---- refusals of the decoder -----------------------------------------------------------------------------------

def refusals(valid):
    by = {c["name"]: c for c in valid}
    typ = by["typical_ipv4_key_aes256k"]
    v6 = by["eight_ipv6_monitors"]
    out = []

    def body_of(c):
        return bytearray.fromhex(c["body"])

    def table_of(c):
        return bytearray.fromhex(c["table"])

    def rbody(name, why, status, body):
        out.append({"name": name, "why": why, "kind": "body", "hex": bytes(body).hex(), "status": status})

    def rtable(name, why, status, table):
        out.append({"name": name, "why": why, "kind": "table", "hex": bytes(table).hex(), "status": status})

    def fixed_field(c, name, value, size=1):
        b = body_of(c)
        b[O[name]:O[name] + size] = value.to_bytes(size, "little")
        return b

    def table_fix(body):
        return wrap_table(bytes(body))

    def shorten_key(c, n):
        # the key is the last thing in the body: drop its tail and say so in key_len, so the layout stays canonical
        b = body_of(c)
        klen = b[O["key_len"]]
        del b[len(b) - (klen - n):]
        b[O["key_len"]] = n
        return b

    # ACPI level
    t = table_of(typ)
    t2 = bytearray(t)
    t2[0:4] = b"rBFU"
    rtable("acpi_signature", "signature is rBFU (checksum fixed up)", "WR_E_HO_SIGNATURE", set_checksum(t2))
    t2 = bytearray(t)
    t2[9] ^= 0x01
    rtable("acpi_checksum", "checksum byte off by one", "WR_E_HO_CHECKSUM", t2)
    t2 = bytearray(t)
    t2[20] ^= 0x80
    rtable("acpi_checksum_oem_changed", "an OEM byte changed without fixing the checksum (what iPXE does before it fixes it)",
           "WR_E_HO_CHECKSUM", t2)
    rtable("acpi_revision_2", "ACPI revision 2 (checksum fixed up)", "WR_E_HO_VERSION", wrap_table(bytes.fromhex(typ["body"]), rev=2))
    rtable("acpi_length_too_small", "length field smaller than the header plus the fixed part", "WR_E_HO_LENGTH",
           wrap_table(bytes.fromhex(typ["body"]), length=ACPI + FIXED - 1))
    big = bytes.fromhex(typ["body"]) + b"\0" * (MAX_TABLE - ACPI - len(bytes.fromhex(typ["body"])) + 1)
    rtable("acpi_length_1025", "length field 1025", "WR_E_HO_TOO_BIG", wrap_table(big))
    rtable("acpi_length_beyond_buffer", "the buffer is one byte shorter than the length field says", "WR_E_TRUNCATED",
           t[:-1])
    rtable("acpi_shorter_than_header", "fewer than 36 bytes", "WR_E_TRUNCATED", t[:35])

    # body level (the table around them is valid, checksum fixed)
    b = body_of(typ)
    b[0:4] = b"WRBU"
    rtable("body_magic", "body magic is WRBU", "WR_E_HO_SIGNATURE", table_fix(b))
    rtable("body_version_2", "layout version 2", "WR_E_HO_VERSION", table_fix(fixed_field(typ, "version", 2, 2)))
    rtable("body_version_0", "layout version 0", "WR_E_HO_VERSION", table_fix(fixed_field(typ, "version", 0, 2)))
    rtable("body_header_len_120", "header_len 120 in a version 1 table", "WR_E_HO_LENGTH",
           table_fix(fixed_field(typ, "header_len", 120, 2)))
    rtable("body_header_len_100", "header_len 100", "WR_E_HO_LENGTH", table_fix(fixed_field(typ, "header_len", 100, 2)))
    rbody("body_shorter_than_fixed", "body of 115 bytes", "WR_E_TRUNCATED", body_of(typ)[:115])
    rbody("body_over_988", "body of 989 bytes", "WR_E_HO_TOO_BIG", body_of(typ) + b"\0" * (989 - len(body_of(typ))))
    rtable("flags_unknown_bit", "flag bit 6 set", "WR_E_HO_FIELD",
           table_fix(fixed_field(typ, "flags", 0x40 | 0x02 | 0x01 | 0x10, 4)))
    rtable("reserved_byte_19", "reserved byte at 19 not zero", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "rsv0", 1)))
    rtable("reserved_word_46", "reserved word at 46 not zero", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "rsv1", 1, 2)))
    rtable("reserved_dword_112", "reserved dword at 112 not zero", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "rsv2", 1, 4)))
    rtable("auth_2", "auth 2", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "auth", 2)))
    rtable("msgr_mode_0", "msgr_mode 0", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "msgr_mode", 0)))
    rtable("msgr_mode_5", "msgr_mode 5 (stock) is not a table value", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "msgr_mode", 5)))
    rtable("secure_required_with_crc", "secure-required flag with msgr_mode crc-only", "WR_E_HO_FIELD",
           table_fix(fixed_field(typ, "flags", 0x20 | 0x02 | 0x01 | 0x10, 4)))
    rtable("mon_count_0", "mon_count 0", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "mon_count", 0)))
    rtable("mon_count_9", "mon_count 9", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "mon_count", 9)))
    rtable("mon_count_beyond_area", "mon_count 8 but only 3 records are there", "WR_E_HO_OFFSET",
           table_fix(fixed_field(typ, "mon_count", 8)))
    rtable("key_len_65", "key_len 65", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "key_len", 65)))
    rtable("key_len_0_with_flag", "key flag set, key_len 0", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "key_len", 0)))
    rtable("key_len_beyond_area", "key_len 33 where 32 key bytes are left", "WR_E_HO_OFFSET",
           table_fix(fixed_field(typ, "key_len", 33)))
    rtable("key_len_31_aes256k", "aes256k key_len 31 (the core accepts 32 and more), key bytes shortened to match", "WR_E_HO_FIELD",
           table_fix(shorten_key(typ, 31)))
    aes = by["key_aes_legacy_16"]
    rtable("key_len_15_aes", "aes key_len 15 (the core accepts 16 and more), key bytes shortened to match", "WR_E_HO_FIELD",
           table_fix(shorten_key(aes, 15)))
    rtable("key_len_1_aes256k", "aes256k key_len 1", "WR_E_HO_FIELD", table_fix(shorten_key(typ, 1)))
    rtable("key_type_3", "key_type 3", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "key_type", 3)))
    rtable("key_type_0_with_flag", "key flag set, key_type 0", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "key_type", 0)))
    rtable("key_flag_without_offset", "key flag set, key offset absent", "WR_E_HO_FIELD",
           table_fix(fixed_field(typ, "off_key", ABSENT, 2)))
    nokey = by["typical_ipv4_nokey"]
    b = body_of(nokey)
    struct.pack_into("<H", b, O["off_key"], len(b) - FIXED - 4)
    rtable("key_offset_without_flag", "key offset present, key flag clear", "WR_E_HO_FIELD", table_fix(b))
    b = body_of(nokey)
    b[O["key_type"]] = 2
    b[O["key_len"]] = 32
    rtable("key_fields_without_flag", "key_type and key_len set, key flag clear", "WR_E_HO_FIELD", table_fix(b))
    b = body_of(typ)
    b[O["auth"]] = 0
    rtable("key_with_auth_none", "key flag set with auth none", "WR_E_HO_FIELD", table_fix(b))
    b = body_of(nokey)
    b[O["fsid"]] = 1
    b[O["flags"]] = 0
    rtable("fsid_without_flag", "fsid not zero, fsid flag clear", "WR_E_HO_FIELD", table_fix(b))
    rtable("nic_family_5", "nic_family 5", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "nic_family", 5)))
    rtable("nic_prefix_33", "IPv4 prefix 33", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "nic_prefix", 33)))
    rtable("vlan_without_flag", "nic_vlan 5, VLAN flag clear", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "nic_vlan", 5, 2)))
    b = body_of(v6)
    struct.pack_into("<H", b, O["nic_vlan"], 4095)
    rtable("vlan_4095", "VLAN id 4095", "WR_E_HO_FIELD", table_fix(b))
    b = body_of(v6)
    struct.pack_into("<H", b, O["nic_vlan"], 0)
    rtable("vlan_flag_with_0", "VLAN flag set, id 0", "WR_E_HO_FIELD", table_fix(b))
    b = body_of(typ)
    b[O["nic_ip"] + 9] = 7
    rtable("nic_ipv4_tail_not_zero", "IPv4 address with a non-zero byte beyond the fourth", "WR_E_HO_FIELD", table_fix(b))
    # monitor records: the area is strings (11 + 7 + 11 = 29 bytes) then the records
    area_off = FIXED
    mons_at = area_off + len("winrbd-boot") + 1 + len("winrbd") + 1 + len("boot-win11") + 1
    b = body_of(typ)
    b[mons_at] = 5
    rtable("mon_family_5", "first monitor family 5", "WR_E_HO_FIELD", table_fix(b))
    b = body_of(typ)
    b[mons_at + 1] = 1
    rtable("mon_reserved_not_zero", "reserved byte of a monitor record not zero", "WR_E_HO_FIELD", table_fix(b))
    b = body_of(typ)
    b[mons_at + 2:mons_at + 4] = b"\0\0"
    rtable("mon_port_0", "monitor port 0", "WR_E_HO_FIELD", table_fix(b))
    b = body_of(typ)
    b[mons_at + 4 + 8] = 9
    rtable("mon_ipv4_tail_not_zero", "IPv4 monitor with a non-zero byte beyond the fourth", "WR_E_HO_FIELD", table_fix(b))

    # offsets and strings
    for field, why in (("off_entity", "entity"), ("off_pool", "pool"), ("off_image", "image")):
        rtable("offset_%s_out_of_range" % why, "%s offset beyond the variable area" % why, "WR_E_HO_OFFSET",
               table_fix(fixed_field(typ, field, 0x0800, 2)))
    rtable("offset_mons_out_of_range", "monitor offset beyond the variable area", "WR_E_HO_OFFSET",
           table_fix(fixed_field(typ, "off_mons", 0x0800, 2)))
    rtable("offset_mons_absent", "monitor offset absent with mon_count 3", "WR_E_HO_OFFSET",
           table_fix(fixed_field(typ, "off_mons", ABSENT, 2)))
    rtable("offset_key_out_of_range", "key offset beyond the variable area", "WR_E_HO_OFFSET",
           table_fix(fixed_field(typ, "off_key", 0x0800, 2)))
    rtable("pool_absent", "pool offset absent", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "off_pool", ABSENT, 2)))
    rtable("image_absent", "image offset absent", "WR_E_HO_FIELD", table_fix(fixed_field(typ, "off_image", ABSENT, 2)))
    rtable("entity_absent_with_cephx", "entity offset absent with cephx", "WR_E_HO_FIELD",
           table_fix(fixed_field(typ, "off_entity", ABSENT, 2)))
    # the last two bytes of the last IPv6 monitor are 0x0b 0x0c: a string that starts there has no NUL in the area
    b = body_of(v6)
    struct.pack_into("<H", b, O["off_snapshot"], len(b) - FIXED - 2)
    rtable("string_unterminated", "snapshot offset points at the last two bytes of the area, which hold no NUL",
           "WR_E_HO_OFFSET", table_fix(b))
    # the pool grows to 256 bytes; the offsets of what follows move with it, so only the string length is wrong
    typ_body = bytes.fromhex(typ["body"])
    area = typ_body[FIXED:]
    pool_off = len("winrbd-boot") + 1
    long_s = b"p" * 256 + b"\0"
    area2 = area[:pool_off] + long_s + area[pool_off + len("winrbd") + 1:]
    shift = len(long_s) - (len("winrbd") + 1)
    b = bytearray(typ_body[:FIXED] + area2)
    for field in ("off_image", "off_mons", "off_key"):
        struct.pack_into("<H", b, O[field], struct.unpack_from("<H", typ_body, O[field])[0] + shift)
    rtable("string_256_bytes", "the pool is 256 bytes long (the maximum is 255)", "WR_E_HO_FIELD", table_fix(b))
    # an optional string that is present but empty
    b = body_of(typ)
    area = bytes(b[FIXED:])
    # insert one NUL after the image string, make image_id point at it, move everything after it by one
    img_end = area.index(b"boot-win11\0") + len(b"boot-win11\0")
    area2 = area[:img_end] + b"\0" + area[img_end:]
    b = bytearray(b[:FIXED] + area2)
    struct.pack_into("<H", b, O["off_image_id"], img_end)
    for field in ("off_mons", "off_key"):
        struct.pack_into("<H", b, O[field], struct.unpack_from("<H", b, O[field])[0] + 1)
    rtable("string_present_but_empty", "image id present as an empty string (absent is the way to say none)",
           "WR_E_HO_FIELD", table_fix(b))
    # a namespace
    area = bytes(body_of(typ)[FIXED:])
    img = area.index(b"boot-win11\0")
    area2 = area[:img] + b"ns1\0" + area[img:]
    b = bytearray(body_of(typ)[:FIXED] + area2)
    struct.pack_into("<H", b, O["off_namespace"], img)
    for field in ("off_image", "off_mons", "off_key"):
        struct.pack_into("<H", b, O[field], struct.unpack_from("<H", b, O[field])[0] + 4)
    rtable("namespace_present", "a namespace (not supported in version 1)", "WR_E_UNSUPPORTED", table_fix(b))

    # canonical layout
    area = bytes(body_of(typ)[FIXED:])
    b = bytearray(body_of(typ)[:FIXED] + area[:11 + 1] + b"\xaa" + area[12:])  # one stray byte after the entity
    for field in ("off_pool", "off_image", "off_mons", "off_key"):
        struct.pack_into("<H", b, O[field], struct.unpack_from("<H", b, O[field])[0] + 1)
    rtable("layout_gap_between_strings", "a stray byte between the entity and the pool, offsets adjusted", "WR_E_HO_LAYOUT",
           table_fix(b))
    rtable("layout_trailing_byte", "one byte after the key", "WR_E_HO_LAYOUT", table_fix(body_of(typ) + b"\0"))
    b = bytearray(body_of(typ))
    area = bytes(b[FIXED:])
    area2 = b"winrbd\0" + b"winrbd-boot\0" + area[len("winrbd-boot\0winrbd\0"):]
    b = bytearray(b[:FIXED] + area2)
    struct.pack_into("<H", b, O["off_pool"], 0)
    struct.pack_into("<H", b, O["off_entity"], len("winrbd\0"))
    rtable("layout_strings_swapped", "entity and pool in the wrong order (offsets consistent)", "WR_E_HO_LAYOUT", table_fix(b))
    b = bytearray(body_of(typ))
    struct.pack_into("<H", b, O["off_pool"], struct.unpack_from("<H", b, O["off_entity"])[0] + 1)  # pool inside the entity
    rtable("layout_overlap", "the pool offset points into the entity string", "WR_E_HO_LAYOUT", table_fix(b))
    b = bytearray(body_of(typ))
    struct.pack_into("<H", b, O["off_key"], struct.unpack_from("<H", b, O["off_mons"])[0] + 20)  # key over the records
    rtable("layout_key_overlaps_monitors", "the key offset points into the monitor records", "WR_E_HO_LAYOUT", table_fix(b))
    return out


# ---- refusals of the encoder ------------------------------------------------------------------------------------

def encode_refusals(valid):
    by = {c["name"]: c for c in valid}
    out = []

    def r(name, why, status, **kw):
        base = kw.pop("_base", None)
        info = json.loads(json.dumps(by[base]["info"] if base else base_info()))
        info.update(kw)
        out.append({"name": name, "why": why, "info": info, "status": status})

    mx = "max_size_1024"
    r("pool_136_over_1024", "the maximum table with a 136-byte pool: 1,025 bytes", "WR_E_HO_TOO_BIG", _base=mx, pool="p" * 136)
    r("image_256_bytes", "a 256-byte image name", "WR_E_HO_FIELD", image="i" * 256)
    r("entity_256_bytes", "a 256-byte entity", "WR_E_HO_FIELD", entity="e" * 256)
    r("pool_missing", "no pool", "WR_E_HO_FIELD", pool="")
    r("image_missing", "no image", "WR_E_HO_FIELD", image="")
    r("entity_missing_with_cephx", "cephx without an entity", "WR_E_HO_FIELD", entity="")
    r("namespace_given", "a namespace", "WR_E_UNSUPPORTED", rbd_namespace="ns1")
    r("flag_unknown_bit", "an unknown flag bit", "WR_E_HO_FIELD", flags=0x80)
    r("key_flag_without_key", "key flag, no key bytes", "WR_E_HO_FIELD", flags=F_KEY, key_type=KEY_AES256K, key="",
      key_len=0)
    r("key_not_allowed_without_flag", "key bytes given but the key flag clear: refused, not dropped", "WR_E_HO_FIELD",
      key_type=KEY_AES256K, key=key_pattern(32, 1).hex())
    r("key_65_bytes", "a 65-byte key", "WR_E_HO_FIELD", flags=F_KEY, key_type=KEY_AES256K, key=key_pattern(65, 1).hex())
    r("key_aes256k_31_bytes", "a 31-byte aes256k key", "WR_E_HO_FIELD", flags=F_KEY, key_type=KEY_AES256K,
      key=key_pattern(31, 1).hex())
    r("key_aes_15_bytes", "a 15-byte aes key", "WR_E_HO_FIELD", flags=F_KEY, key_type=KEY_AES, key=key_pattern(15, 1).hex())
    r("key_type_9", "key type 9", "WR_E_HO_FIELD", flags=F_KEY, key_type=9, key=key_pattern(32, 1).hex())
    r("key_with_auth_none", "key with auth none", "WR_E_HO_FIELD", flags=F_KEY, auth=0, key_type=KEY_AES256K,
      key=key_pattern(32, 1).hex())
    r("mon_count_0", "no monitors", "WR_E_HO_FIELD", mons=[])
    r("mon_count_9", "nine monitors", "WR_E_HO_FIELD", mon_count=9)
    r("mon_port_0", "monitor port 0", "WR_E_HO_FIELD", mons=[mon("10.77.0.10", 0)])
    r("mon_family_0", "monitor family 0", "WR_E_HO_FIELD", mons=[{"family": 0, "port": 3300, "ip": "00" * 16}])
    r("mode_5", "msgr_mode 5", "WR_E_HO_FIELD", msgr_mode=5)
    r("mode_0", "msgr_mode 0", "WR_E_HO_FIELD", msgr_mode=0)
    r("secure_required_needs_secure_only", "secure required with crc-first", "WR_E_HO_FIELD", flags=F_SECREQ,
      msgr_mode=MODE_CRC_FIRST)
    r("vlan_flag_without_id", "VLAN flag, id 0", "WR_E_HO_FIELD", flags=F_VLAN, nic_vlan=0)
    r("vlan_id_without_flag", "VLAN id without the flag", "WR_E_HO_FIELD", nic_vlan=7)
    r("static_without_family", "static NIC flag with an unknown family", "WR_E_HO_FIELD", flags=F_STATIC, nic_family=0,
      nic_prefix=0, nic_ip="00" * 16, nic_gateway="00" * 16, nic_dns="00" * 16)
    r("prefix_129", "IPv6 prefix 129", "WR_E_HO_FIELD", nic_family=6, nic_prefix=129)
    r("fsid_without_flag", "fsid given without the flag", "WR_E_HO_FIELD", fsid=key_pattern(16, 9).hex())
    return out


def self_check(valid):
    for c in valid:
        t = bytes.fromhex(c["table"])
        assert sum(t) & 0xFF == 0, c["name"]
        assert len(t) <= MAX_TABLE, c["name"]
    mx = next(c for c in valid if c["name"] == "max_size_1024")
    assert len(bytes.fromhex(mx["table"])) == MAX_TABLE, len(bytes.fromhex(mx["table"]))


def document():
    valid = valid_cases()
    self_check(valid)
    return {
        "_about": "Golden vectors of the rBFT handoff table, version 1 (docs/design/handoff-table.md). Written by "
                  "gen_handoff_vectors.py, an independent second implementation of the layout; read by "
                  "harness/test/test_handoff_vec.c. 'info' describes a table (hex fields are byte strings, ip_text is "
                  "for humans), 'body' and 'table' are the exact bytes (hex). Keys are fixed fake patterns.",
        "valid": valid,
        "refuse_decode": refusals(valid),
        "refuse_encode": encode_refusals(valid),
    }


def write_seeds(doc, d):
    os.makedirs(d, exist_ok=True)  # existing files are left alone: seeds added by fuzz runs stay
    n = 0

    def put(name, data):
        nonlocal n
        with open(os.path.join(d, name), "wb") as f:
            f.write(data)
        n += 1

    for c in doc["valid"]:
        put("%s.body" % c["name"], b"\x00" + bytes.fromhex(c["body"]))
        put("%s.table" % c["name"], b"\x01" + bytes.fromhex(c["table"]))
        put("%s.wrapped" % c["name"], b"\x02" + bytes.fromhex(c["body"]))
    for c in doc["refuse_decode"]:
        mode = b"\x00" if c["kind"] == "body" else b"\x01"
        put("refuse_%s" % c["name"], mode + bytes.fromhex(c["hex"]))
        if c["kind"] == "table" and len(c["hex"]) > 2 * ACPI:
            # the same body behind a header the fuzz target rebuilds (mode 2): reaches the body parser with a good checksum
            put("refuse_wrapped_%s" % c["name"], b"\x02" + bytes.fromhex(c["hex"])[ACPI:])
    # structured mode: a few byte strings the target turns into descriptions
    for k in range(8):
        put("struct_%d" % k, b"\x03" + bytes(((j * (k + 3) + 5 * k) & 0xFF) for j in range(80)))
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--seeds", metavar="DIR")
    a = ap.parse_args()
    doc = document()
    text = json.dumps(doc, indent=1, ensure_ascii=False) + "\n"
    if a.check:
        with open(OUT, encoding="utf-8") as f:
            if f.read() != text:
                sys.stderr.write("handoff-v1.json is stale: run gen_handoff_vectors.py\n")
                return 1
        return 0
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print("wrote %s: %d valid, %d decode refusals, %d encode refusals" %
          (OUT, len(doc["valid"]), len(doc["refuse_decode"]), len(doc["refuse_encode"])))
    if a.seeds:
        print("wrote %d seeds into %s" % (write_seeds(doc, a.seeds), a.seeds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
