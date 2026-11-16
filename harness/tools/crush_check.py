#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
crush_check.py - independent checker for docs/spec/crush-and-placement.md

Written from the spec NOTES only (crush-and-placement.md, plus osdmap.md / msgr2.md / osd-ops.md for the
containers that carry the CRUSH blob), not from Ceph source and not by calling any Ceph decoder.  Ceph's own
tools (ceph-dencoder, crushtool, osdmaptool, `ceph osd map`) appear only as ORACLE OUTPUT files in the capture
directory; they are never run.

Usage:
    python3 harness/tools/crush_check.py --captures <dir> [--ref <ceph-ref-tree>] [--quick] [--no-pcap]
                                         [--tree-x N] [--emit-vectors <dir>] [-v]

Exit status 0 when every check passes, 1 when any fails, 2 on usage / missing-input errors.

What is checked (details in harness/vectors/crush/README.md):
  A  arithmetic vectors of note section 5.1 (string hashes, CRUSH hashes, stable_mod, pps, crush_ln) and the
     table facts of section 3.4.2 (tables are read at run time from the reference tree, never embedded)
  B  CRUSH blob decoder (section 2.2 / 2.4) against the dencoder JSON, incl. the "embedded vs getcrushmap" claims
  C  OSDMap full-map and Incremental decoders (osdmap.md) against dencoder JSON for every stored epoch; the
     incremental apply rules of note 2.7 / osdmap.md 3.5 by replaying epochs 1..89 and comparing with the stored maps
  D  placement pipeline of sections 3.1 - 3.7 against `ceph osd map` (2194 names), crushtool and osdmaptool output
  E  (optional, needs the pcaps) msgr2 crc-mode frames, MOSDMap payloads, MOSDOp targets: does the stock client
     really send what the note predicts (ps in the hash field, masked pg, primary OSD connection)?
  F  (optional, needs --ref) in-tree known-answer crushtool tests: straw / chooseleaf / tunables paths

Standard library only.  No key material is read or printed.
"""
import argparse
import glob
import json
import os
import re
import struct
import sys
import time
from decimal import Decimal, getcontext

M32 = 0xFFFFFFFF
S64_MIN = -(1 << 63)

# --------------------------------------------------------------------------------------------------------------
# result bookkeeping
# --------------------------------------------------------------------------------------------------------------


class Results:
    def __init__(self, verbose=False):
        self.rows = []  # (group, name, status, detail)
        self.verbose = verbose
        self.units = 0  # individual comparisons (mappings, fields, frames ...) behind the checks

    def check(self, group, name, ok, detail="", units=0):
        self.units += units
        self.rows.append((group, name, "PASS" if ok else "FAIL", detail))
        if not ok or self.verbose:
            print(("  FAIL " if not ok else "  ok   ") + "[%s] %s %s" % (group, name, detail), flush=True)
        return ok

    def info(self, group, name, detail=""):
        self.rows.append((group, name, "INFO", detail))
        print("  info [%s] %s %s" % (group, name, detail), flush=True)

    def counts(self):
        p = sum(1 for r in self.rows if r[2] == "PASS")
        f = sum(1 for r in self.rows if r[2] == "FAIL")
        i = sum(1 for r in self.rows if r[2] == "INFO")
        return p, f, i


class CheckError(Exception):
    pass


# --------------------------------------------------------------------------------------------------------------
# byte reader (little endian)
# --------------------------------------------------------------------------------------------------------------


class R:
    __slots__ = ("b", "p", "end")

    def __init__(self, b, p=0, end=None):
        self.b = b
        self.p = p
        self.end = len(b) if end is None else end

    def left(self):
        return self.end - self.p

    def need(self, n):
        if n < 0 or self.p + n > self.end:
            raise CheckError("short read: need %d at %d, end %d" % (n, self.p, self.end))

    def u8(self):
        self.need(1)
        v = self.b[self.p]
        self.p += 1
        return v

    def s8(self):
        v = self.u8()
        return v - 256 if v & 0x80 else v

    def u16(self):
        self.need(2)
        v = struct.unpack_from("<H", self.b, self.p)[0]
        self.p += 2
        return v

    def u32(self):
        self.need(4)
        v = struct.unpack_from("<I", self.b, self.p)[0]
        self.p += 4
        return v

    def s32(self):
        self.need(4)
        v = struct.unpack_from("<i", self.b, self.p)[0]
        self.p += 4
        return v

    def u64(self):
        self.need(8)
        v = struct.unpack_from("<Q", self.b, self.p)[0]
        self.p += 8
        return v

    def s64(self):
        self.need(8)
        v = struct.unpack_from("<q", self.b, self.p)[0]
        self.p += 8
        return v

    def raw(self, n):
        self.need(n)
        v = bytes(self.b[self.p:self.p + n])
        self.p += n
        return v

    def blob(self):
        return self.raw(self.u32())

    def string(self):
        return self.blob()

    def skip(self, n):
        self.need(n)
        self.p += n


def env(r, legacy_at=None):
    """Versioned envelope (osdmap.md 2.2).  Returns (struct_v, struct_compat, end).  legacy_at: wrapper/pool
    threshold; below it the compat / length fields do not exist (not supported here, raises)."""
    v = r.u8()
    if legacy_at is not None and v < legacy_at:
        raise CheckError("legacy struct_v %d < %d" % (v, legacy_at))
    compat = r.u8()
    ln = r.u32()
    if r.p + ln > r.end:
        raise CheckError("envelope length %d exceeds enclosing struct (%d left)" % (ln, r.left()))
    return v, compat, r.p + ln


def finish(r, end, what=""):
    if r.p > end:
        raise CheckError("%s consumed past envelope end (%d > %d)" % (what, r.p, end))
    r.p = end


# --------------------------------------------------------------------------------------------------------------
# CRC-32C (msgr2.md 2.5): raw table-driven update, no inversion
# --------------------------------------------------------------------------------------------------------------

_CT = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CT.append(_c)


def crc32c(data, seed=0):
    c = seed
    t = _CT
    for b in data:
        c = t[(c ^ b) & 0xFF] ^ (c >> 8)
    return c


# --------------------------------------------------------------------------------------------------------------
# hashes (note 3.1.1, 3.1.2, 3.2.1)
# --------------------------------------------------------------------------------------------------------------


def str_hash_rjenkins(data):
    a = b = 0x9E3779B9
    c = 0
    n = len(data)
    k = data
    pos = 0
    left = n
    while left >= 12:
        a = (a + struct.unpack_from("<I", k, pos)[0]) & M32
        b = (b + struct.unpack_from("<I", k, pos + 4)[0]) & M32
        c = (c + struct.unpack_from("<I", k, pos + 8)[0]) & M32
        a, b, c = _mix(a, b, c)
        pos += 12
        left -= 12
    c = (c + n) & M32
    t = k[pos:]
    for i in range(left):
        if i < 4:
            a = (a + (t[i] << (8 * i))) & M32
        elif i < 8:
            b = (b + (t[i] << (8 * (i - 4)))) & M32
        else:
            c = (c + (t[i] << (8 * (i - 8) + 8))) & M32
    a, b, c = _mix(a, b, c)
    return c


def str_hash_linux(data):
    h = 0
    for c in data:
        h = ((h + (c << 4) + (c >> 4)) * 11) & M32
    return h


def _mix(a, b, c):
    a = (a - b - c) & M32; a ^= c >> 13
    b = (b - c - a) & M32; b ^= (a << 8) & M32
    c = (c - a - b) & M32; c ^= b >> 13
    a = (a - b - c) & M32; a ^= c >> 12
    b = (b - c - a) & M32; b ^= (a << 16) & M32
    c = (c - a - b) & M32; c ^= b >> 5
    a = (a - b - c) & M32; a ^= c >> 3
    b = (b - c - a) & M32; b ^= (a << 10) & M32
    c = (c - a - b) & M32; c ^= b >> 15
    return a, b, c


_SEED = 1315423911
_X0 = 231232
_Y0 = 1232


def _mix_src(a, b, c):
    """source text of one nine-round mix on the named variables (table of note 3.2.1); used to build the hash
    functions below with the mixes inlined (about 3x faster than calling _mix)"""
    return "\n".join("    %s = (%s - %s - %s) & 0xFFFFFFFF; %s ^= %s" % (t, t, u, v, t, sh) for t, u, v, sh in (
        (a, b, c, "%s >> 13" % c), (b, c, a, "(%s << 8) & 0xFFFFFFFF" % a), (c, a, b, "%s >> 13" % b),
        (a, b, c, "%s >> 12" % c), (b, c, a, "(%s << 16) & 0xFFFFFFFF" % a), (c, a, b, "%s >> 5" % b),
        (a, b, c, "%s >> 3" % c), (b, c, a, "(%s << 10) & 0xFFFFFFFF" % a), (c, a, b, "%s >> 15" % b))) + "\n"


def _build_hash(name, args, seq):
    src = "def %s(%s):\n" % (name, ", ".join(args))
    src += "".join("    %s &= 0xFFFFFFFF\n" % x for x in args)
    src += "    h = %d ^ %s\n    x = %d\n    y = %d\n" % (_SEED, " ^ ".join(args), _X0, _Y0)
    for tri in seq:
        src += _mix_src(*(("h" if t == "h" else t) for t in tri))
    src += "    return h\n"
    ns = {}
    exec(src, ns)
    return ns[name]


# the sequences of the table in 3.2.1 (h is the accumulator; X and Y are the local constants x and y)
hash2 = _build_hash("hash2", ["a", "b"], [("a", "b", "h"), ("x", "a", "h"), ("b", "y", "h")])
hash3 = _build_hash("hash3", ["a", "b", "c"], [("a", "b", "h"), ("c", "x", "h"), ("y", "a", "h"), ("b", "x", "h"), ("y", "c", "h")])
hash4 = _build_hash("hash4", ["a", "b", "c", "d"], [("a", "b", "h"), ("c", "d", "h"), ("a", "x", "h"), ("y", "b", "h"), ("c", "x", "h"), ("y", "d", "h")])


def hash1_reconstructed(a):
    """NOT specified in the note (3.2.1 only lists hash2..hash4).  Reconstructed from the pattern; used only to see
    whether the hash1 vectors of 5.1 are reproducible from what the note says."""
    a &= M32
    h = _SEED ^ a
    b = a
    x = _X0; y = _Y0
    b, x, h = _mix(b, x, h)
    y, a, h = _mix(y, a, h)
    return h


def cbits(v):
    return v.bit_length()


def stable_mod(x, b, bmask):
    if (x & bmask) < b:
        return x & bmask
    return x & (bmask >> 1)


def pool_masks(pg_num, pgp_num):
    return (1 << cbits(pg_num - 1)) - 1, (1 << cbits(pgp_num - 1)) - 1


# --------------------------------------------------------------------------------------------------------------
# crush_ln tables: loaded at run time from the reference tree (never embedded)
# --------------------------------------------------------------------------------------------------------------


class LnTables:
    def __init__(self, header_path):
        txt = open(header_path, "r", encoding="utf-8", errors="replace").read()
        i = txt.index("__RH_LH_tbl")
        j = txt.index("__LL_tbl")
        # only the array bodies (between the first '{' after the name and the closing '}')
        def body(s, start):
            a = s.index("{", start)
            b = s.index("}", a)
            return s[a + 1:b]
        rh = [int(m, 16) for m in re.findall(r"0x([0-9a-fA-F]+)(?:ll|ull)", body(txt, i))]
        ll = [int(m, 16) for m in re.findall(r"0x([0-9a-fA-F]+)(?:ll|ull)", body(txt, j))]
        if len(rh) != 258 or len(ll) != 256:
            raise CheckError("unexpected table sizes %d / %d" % (len(rh), len(ll)))
        self.rh_lh = rh
        self.ll = ll

    def ln(self, u, ll=None):
        ll = self.ll if ll is None else ll
        x = u + 1
        iexpon = 15
        if not (x & 0x18000):
            bits = 16 - x.bit_length()
            x <<= bits
            iexpon = 15 - bits
        index1 = (x >> 8) << 1
        RH = self.rh_lh[index1 - 256]
        LH = self.rh_lh[index1 + 1 - 256]
        xl = (x * RH) >> 48
        LL = ll[xl & 0xFF]
        return (iexpon << 44) + ((LH + LL) >> 4)


LN = None  # set by main (needs --ref)


_LNC = None


def crush_ln(u):
    """crush_ln over all 65536 inputs, computed once from the run-time tables"""
    global _LNC
    if _LNC is None:
        _LNC = [LN.ln(i) for i in range(65536)]
    return _LNC[u]


# --------------------------------------------------------------------------------------------------------------
# CRUSH blob decoder (note 2.2, 2.4)
# --------------------------------------------------------------------------------------------------------------


class Bucket:
    __slots__ = ("id", "type", "alg", "hash", "weight", "size", "items", "item_weight", "item_weights",
                 "sum_weights", "straws", "node_weights", "slot")


class Rule:
    __slots__ = ("ruleset", "type", "min_size", "max_size", "steps")


class CrushMap:
    pass


def _name_map(r):
    """rows 7-9 incl. the empty-name quirk of note 2.2."""
    n = r.u32()
    d = {}
    for _ in range(n):
        key = r.s32()
        ln = r.u32()
        if ln == 0:
            ln = r.u32()  # upper half of an old 64-bit key
        d[key] = r.raw(ln).decode("utf-8", "replace")
    return d


def decode_crush(blob):
    r = R(blob)
    cm = CrushMap()
    magic = r.u32()
    if magic != 0x00010000:
        raise CheckError("bad crush magic %#x" % magic)
    cm.max_buckets = r.s32()
    cm.max_rules = r.u32()
    cm.wire_max_devices = r.s32()
    cm.buckets = []
    for slot in range(cm.max_buckets):
        marker = r.u32()
        if marker == 0:
            cm.buckets.append(None)
            continue
        b = Bucket()
        b.slot = slot
        b.id = r.s32()
        b.type = r.u16()
        b.alg = r.u8()
        b.hash = r.u8()
        b.weight = r.u32()
        b.size = r.u32()
        if marker != b.alg:
            raise CheckError("alg marker %d != alg %d in slot %d" % (marker, b.alg, slot))
        if b.id != -1 - slot:
            raise CheckError("bucket id %d does not match slot %d" % (b.id, slot))
        if b.hash != 0:
            raise CheckError("bucket hash %d != 0" % b.hash)
        b.items = [r.s32() for _ in range(b.size)]
        b.item_weight = b.item_weights = b.sum_weights = b.straws = b.node_weights = None
        if b.alg == 1:
            b.item_weight = r.u32()
        elif b.alg == 2:
            b.item_weights = []
            b.sum_weights = []
            for _ in range(b.size):
                b.item_weights.append(r.u32())
                b.sum_weights.append(r.u32())
        elif b.alg == 3:
            nn = r.u8()
            b.node_weights = [r.u32() for _ in range(nn)]
        elif b.alg == 4:
            b.item_weights = []
            b.straws = []
            for _ in range(b.size):
                b.item_weights.append(r.u32())
                b.straws.append(r.u32())
        elif b.alg == 5:
            b.item_weights = [r.u32() for _ in range(b.size)]
        else:
            raise CheckError("unknown bucket alg %d" % b.alg)
        cm.buckets.append(b)
    cm.rules = []
    for slot in range(cm.max_rules):
        present = r.u32()
        if present == 0:
            cm.rules.append(None)
            continue
        ru = Rule()
        ln = r.u32()
        ru.ruleset = r.u8()
        ru.type = r.u8()
        ru.min_size = r.u8()
        ru.max_size = r.u8()
        if ru.ruleset != slot:
            raise CheckError("rule ruleset %d != slot %d" % (ru.ruleset, slot))
        ru.steps = [(r.u32(), r.s32(), r.s32()) for _ in range(ln)]
        cm.rules.append(ru)
    cm.type_map = _name_map(r)
    cm.name_map = _name_map(r)
    cm.rule_name_map = _name_map(r)
    # tunables, legacy defaults when the group is absent
    t = dict(choose_local_tries=2, choose_local_fallback_tries=5, choose_total_tries=19, chooseleaf_descend_once=0,
             chooseleaf_vary_r=0, straw_calc_version=0, allowed_bucket_algs=0x16, chooseleaf_stable=0,
             msr_descents=100, msr_collision_tries=100)
    cm.present = []  # which trailing groups were present
    if r.left() > 0:
        t["choose_local_tries"] = r.u32(); t["choose_local_fallback_tries"] = r.u32(); t["choose_total_tries"] = r.u32()
        cm.present.append("A")
    if r.left() > 0:
        t["chooseleaf_descend_once"] = r.u32(); cm.present.append("B")
    if r.left() > 0:
        t["chooseleaf_vary_r"] = r.u8(); cm.present.append("C")
    if r.left() > 0:
        t["straw_calc_version"] = r.u8(); cm.present.append("D")
    if r.left() > 0:
        t["allowed_bucket_algs"] = r.u32(); cm.present.append("E")
    if r.left() > 0:
        t["chooseleaf_stable"] = r.u8(); cm.present.append("F")
    cm.class_map = cm.class_name = cm.class_bucket = None
    if r.left() > 0:
        n = r.u32()
        cm.class_map = {}
        for _ in range(n):
            k = r.s32(); cm.class_map[k] = r.s32()
        n = r.u32()
        cm.class_name = {}
        for _ in range(n):
            k = r.s32(); cm.class_name[k] = r.string().decode()
        n = r.u32()
        cm.class_bucket = {}
        for _ in range(n):
            k = r.s32()
            m = r.u32()
            cm.class_bucket[k] = {}
            for _ in range(m):
                c = r.s32(); cm.class_bucket[k][c] = r.s32()
        cm.present.append("classes")
    cm.choose_args = {}
    if r.left() > 0:
        n = r.u32()
        for _ in range(n):
            key = r.s64()
            nb = r.u32()
            sets = {}
            for _ in range(nb):
                idx = r.u32()
                if idx >= cm.max_buckets:
                    raise CheckError("choose_args bucket index %d >= max_buckets" % idx)
                pos = r.u32()
                rows = []
                for _ in range(pos):
                    sz = r.u32()
                    rows.append([r.u32() for _ in range(sz)])
                ids_size = r.u32()
                ids = [r.s32() for _ in range(ids_size)]
                b = cm.buckets[idx]
                if b is None:
                    raise CheckError("choose_args on empty slot %d" % idx)
                if ids_size not in (0, b.size) or any(len(row) != b.size for row in rows):
                    raise CheckError("choose_args size mismatch on slot %d" % idx)
                sets[idx] = (rows, ids)
            cm.choose_args[key] = sets
        cm.present.append("choose_args")
    cm.has_msr_pair = False
    if r.left() > 0:
        t["msr_descents"] = r.u32()
        t["msr_collision_tries"] = r.u32()
        cm.has_msr_pair = True
        cm.present.append("msr")
    if r.left() != 0:
        raise CheckError("%d trailing bytes after CRUSH blob" % r.left())
    cm.tun = t
    # note 2.4: max_devices is recomputed
    md = 0
    for b in cm.buckets:
        if b is not None:
            for it in b.items:
                if it >= 0:
                    md = max(md, it + 1)
    for k in cm.name_map:
        if isinstance(k, int) and k >= 0:
            md = max(md, k + 1)
    cm.max_devices = md
    return cm


# --------------------------------------------------------------------------------------------------------------
# CRUSH mapper (note 3.3 - 3.6)
# --------------------------------------------------------------------------------------------------------------

ITEM_NONE = 0x7FFFFFFF


class Unsupported(Exception):
    pass


def _cdiv(a, b):
    """signed 64-bit division truncating toward zero"""
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q


def straw2_choose(b, x, r, position, ca):
    weights = b.item_weights
    ids = b.items
    if ca is not None:
        ent = ca.get(b.slot)
        if ent is not None:
            rows, aids = ent
            if rows:
                weights = rows[min(position, len(rows) - 1)]
            if aids:
                ids = aids
    best = None
    high = S64_MIN
    for i in range(b.size):
        w = weights[i]
        if w:
            u = hash3(x, ids[i], r) & 0xFFFF
            ln = crush_ln(u) - 0x1000000000000
            ws = w - (1 << 32) if w >= (1 << 31) else w
            draw = _cdiv(ln, ws)
        else:
            draw = S64_MIN
        if i == 0 or draw > high:
            best = i
            high = draw
    return b.items[best]


PERM_CALLS = [0]
RETRY_HITS = {"collide_local": 0, "fallback_local": 0, "restart_descent": 0}


def perm_choose(b, x, r):
    PERM_CALLS[0] += 1
    size = b.size
    pr = r % size
    perm = list(range(size))
    for p in range(pr + 1):
        if p < size - 1:
            j = p + (hash3(x, b.id, p) % (size - p))
            perm[p], perm[j] = perm[j], perm[p]
    return b.items[perm[pr]]


def bucket_choose(b, x, r, position, ca):
    if b.alg == 5:
        return straw2_choose(b, x, r, position, ca)
    if b.alg == 4:
        best = 0
        high = -1
        for i in range(b.size):
            d = (hash3(x, b.items[i], r) & 0xFFFF) * b.straws[i]
            if i == 0 or d > high:
                best = i
                high = d
        return b.items[best]
    if b.alg == 2:
        for i in range(b.size - 1, -1, -1):
            w = hash4(x, b.items[i], r, b.id) & 0xFFFF
            w = (w * b.sum_weights[i]) >> 16
            if w < b.item_weights[i]:
                return b.items[i]
        return b.items[0]
    if b.alg == 1:
        return perm_choose(b, x, r)
    raise Unsupported("bucket alg %d" % b.alg)


def is_out(weights, item, x):
    if item >= len(weights):
        return True
    w = weights[item]
    if w >= 0x10000:
        return False
    if w == 0:
        return True
    return not ((hash2(x, item) & 0xFFFF) < w)


def choose_firstn(cm, B, x, numrep, T, out, outpos, budget, tries, recurse_tries, lret, lfall, leaf, vary_r,
                  stable, out2, parent_r, weights, ca):
    rep = 0 if stable else outpos
    count = budget
    while rep < numrep and count > 0:
        fails_all = 0
        fails_here = 0
        cur = B
        skip = False
        item = None
        while True:
            r = rep + parent_r + fails_all
            reject = False
            collide = False
            if cur.size == 0:
                reject = True
            else:
                if lfall > 0 and fails_here >= cur.size // 2 and fails_here > lfall:
                    item = perm_choose(cur, x, r)
                else:
                    item = bucket_choose(cur, x, r, outpos, ca)
                if item >= cm.max_devices:
                    skip = True
                    break
                if item >= 0:
                    itype = 0
                else:
                    ib = -1 - item
                    if ib >= cm.max_buckets or cm.buckets[ib] is None:
                        skip = True
                        break
                    itype = cm.buckets[ib].type
                if itype != T:
                    if item >= 0:
                        skip = True
                        break
                    cur = cm.buckets[-1 - item]
                    continue
                collide = item in out[:outpos]
                if not collide and leaf:
                    if item < 0:
                        sub_r = (r >> (vary_r - 1)) if vary_r else 0
                        n = choose_firstn(cm, cm.buckets[-1 - item], x, 1 if stable else outpos + 1, 0, out2,
                                          outpos, count, recurse_tries, 0, lret, lfall, False, vary_r, stable,
                                          None, sub_r, weights, ca)
                        if n <= outpos:
                            reject = True
                    else:
                        out2[outpos] = item
                if not reject and not collide and itype == 0:
                    reject = is_out(weights, item, x)
            if reject or collide:
                fails_all += 1
                fails_here += 1
                if collide and fails_here <= lret:
                    RETRY_HITS["collide_local"] += 1
                    continue
                if lfall > 0 and fails_here <= cur.size + lfall:
                    RETRY_HITS["fallback_local"] += 1
                    continue
                if fails_all < tries:
                    RETRY_HITS["restart_descent"] += 1
                    cur = B
                    fails_here = 0
                    continue
                skip = True
                break
            break
        if not skip:
            out[outpos] = item
            outpos += 1
            count -= 1
        rep += 1
    return outpos


def do_rule(cm, ruleno, x, result_max, weights, ca=None, tun=None):
    """note 3.3.  ca: dict slot -> (rows, ids) of the selected choose_args set or None."""
    if ruleno >= cm.max_rules:
        return []
    rule = cm.rules[ruleno]
    if rule is None:
        raise CheckError("rule %d has no rule slot" % ruleno)
    if rule.type != 1:
        raise Unsupported("rule type %d" % rule.type)
    t = cm.tun if tun is None else tun
    choose_tries = t["choose_total_tries"] + 1
    choose_leaf_tries = 0
    lret = t["choose_local_tries"]
    lfall = t["choose_local_fallback_tries"]
    vary_r = t["chooseleaf_vary_r"]
    stable = t["chooseleaf_stable"]
    w = []
    result = []
    for op, a1, a2 in rule.steps:
        if op == 1:  # TAKE
            if (0 <= a1 < cm.max_devices) or (a1 < 0 and -1 - a1 < cm.max_buckets and cm.buckets[-1 - a1] is not None):
                w = [a1]
        elif op == 8:
            if a1 > 0: choose_tries = a1
        elif op == 9:
            if a1 > 0: choose_leaf_tries = a1
        elif op == 10:
            if a1 >= 0: lret = a1
        elif op == 11:
            if a1 >= 0: lfall = a1
        elif op == 12:
            if a1 >= 0: vary_r = a1
        elif op == 13:
            if a1 >= 0: stable = a1
        elif op in (2, 6):
            if not w:
                continue
            leaf = op == 6
            o = []
            c = []
            for wi in w:
                numrep = a1
                if numrep <= 0:
                    numrep += result_max
                    if numrep <= 0:
                        continue
                bno = -1 - wi
                if bno < 0 or bno >= cm.max_buckets or cm.buckets[bno] is None:
                    continue
                if choose_leaf_tries:
                    rtries = choose_leaf_tries
                elif t["chooseleaf_descend_once"]:
                    rtries = 1
                else:
                    rtries = choose_tries
                budget = result_max - len(o)
                if budget <= 0:
                    continue
                out = [0] * (numrep + 1)
                out2 = [0] * (numrep + 1)
                n = choose_firstn(cm, cm.buckets[bno], x, numrep, a2, out, 0, budget, choose_tries, rtries, lret,
                                  lfall, leaf, vary_r, stable, out2, 0, weights, ca)
                o.extend(out[:n])
                c.extend(out2[:n])
            if leaf:
                o = c[:len(o)]
            w = o
        elif op in (3, 7, 14, 15, 16):
            raise Unsupported("opcode %d" % op)
        elif op == 4:
            for it in w:
                if len(result) < result_max:
                    result.append(it)
            w = []
    return result


def select_choose_args(cm, pool_id):
    if pool_id in cm.choose_args:
        return cm.choose_args[pool_id]
    if -1 in cm.choose_args:
        return cm.choose_args[-1]
    return None


# --------------------------------------------------------------------------------------------------------------
# OSDMap / Incremental decoders (osdmap.md 2.x); only what placement needs, everything else skipped by length
# --------------------------------------------------------------------------------------------------------------


def read_pg(r):
    r.u8()  # version byte, ignored
    pool = r.u64()
    seed = r.u32()
    r.s32()  # preferred
    return (pool, seed)


def read_interval_set(r):
    n = r.u32()
    return [(r.u64(), r.u64()) for _ in range(n)]


def read_str_map_map(r):
    out = {}
    for _ in range(r.u32()):
        k = r.string()
        d = {}
        for _ in range(r.u32()):
            a = r.string()
            d[a] = r.string()
        out[k] = d
    return out


class Pool:
    pass


def decode_pool(r):
    v = r.u8()
    if v < 5:
        raise CheckError("pool struct_v %d < 5" % v)
    compat = r.u8()
    ln = r.u32()
    end = r.p + ln
    if end > r.end:
        raise CheckError("pool envelope overruns")
    p = Pool()
    p.v = v
    p.type = r.u8(); p.size = r.u8(); p.crush_rule = r.u8(); p.object_hash = r.u8()
    p.pg_num = r.u32(); p.pgp_num = r.u32(); r.u32(); r.u32()
    p.last_change = r.u32()
    p.snap_seq = r.u64(); p.snap_epoch = r.u32()
    if v >= 3:
        for _ in range(r.u32()):
            r.u64()
            _v, _c, e2 = env(r)
            r.p = e2
        p.removed_snaps = read_interval_set(r)
        r.u64()  # auid
    p.flags = 0
    if v >= 4:
        p.flags = r.u64()
        r.u32()
    p.min_size = r.u8() if v >= 7 else 0
    p.quota_max_bytes = p.quota_max_objects = 0
    if v >= 8:
        p.quota_max_bytes = r.u64(); p.quota_max_objects = r.u64()
    p.tiers = []; p.tier_of = -1; p.read_tier = -1; p.write_tier = -1
    if v >= 9:
        p.tiers = [r.u64() for _ in range(r.u32())]
        p.tier_of = r.s64()
        r.u8()
        p.read_tier = r.s64(); p.write_tier = r.s64()
    if v >= 10:
        for _ in range(r.u32()):
            r.string(); r.string()
    if v >= 11:
        _v, _c, e2 = env(r)
        r.p = e2
        r.u32(); r.u32()
    p.stripe_width = r.u32() if v >= 12 else 0
    if v >= 13:
        r.u64(); r.u64(); r.u32(); r.u32(); r.u32(); r.u32()
    p.erasure_code_profile = r.string() if v >= 14 else b""
    if v >= 15: r.u32()
    if v >= 16: r.u32()
    if v >= 17: r.u64()
    if v >= 19: r.u32()
    if v >= 20: r.u32()
    if v >= 21: r.u8()
    if v >= 22: r.u8()
    if v >= 23: r.u32(); r.u32()
    if v >= 24:
        _v, _c, e2 = env(r)
        r.p = e2
    if v >= 25: r.u32()
    if v >= 26: p.application_metadata = read_str_map_map(r)
    if v >= 27: r.raw(8)
    p.pg_num_target = p.pgp_num_target = p.pg_num_pending = 0
    p.last_force_op_resend = 0
    if v >= 28:
        p.pg_num_target = r.u32(); p.pgp_num_target = r.u32(); p.pg_num_pending = r.u32()
        r.u32(); r.u32()
        p.last_force_op_resend = r.u32()
        r.u8()
    if v >= 29:
        _v, _c, e2 = env(r)
        r.p = e2
    p.stretch = (0, 0, 0, 0x7FFFFFFF)
    if v == 30:
        p.stretch = (r.u32(), r.u32(), r.u32(), r.s32())
    if v >= 31:
        if r.u8():
            p.stretch = (r.u32(), r.u32(), r.u32(), r.u32())
    if v >= 32:
        # two varints (note 2.5 row 53)
        for _ in range(2):
            while r.u8() & 0x80:
                pass
    if r.p != end:
        raise CheckError("pool v%d: consumed %d of %d envelope bytes" % (v, r.p - (end - ln), ln))
    p.pg_num_mask, p.pgp_num_mask = pool_masks(p.pg_num, p.pgp_num) if p.pg_num and p.pgp_num else (0, 0)
    return p


def read_addrvec(r):
    marker = r.u8()
    if marker == 2:
        n = r.u32()
        out = []
        for _ in range(n):
            out.append(read_addr(r))
        return out
    if marker == 0 or marker == 1:
        raise CheckError("legacy addrvec marker %d" % marker)
    raise CheckError("bad addrvec marker %d" % marker)


def read_addr(r):
    m = r.u8()
    if m != 1:
        raise CheckError("entity_addr marker %d" % m)
    v = r.u8(); c = r.u8()
    ln = r.u32()
    end = r.p + ln
    typ = r.u32(); nonce = r.u32(); elen = r.u32()
    fam = port = ip = None
    if elen:
        fam = r.u16()
        body = r.raw(elen - 2)
        if fam == 2:
            port = struct.unpack(">H", body[:2])[0]
            ip = ".".join(str(b) for b in body[2:6])
    r.p = end
    return (typ, nonce, ip, port)


class OSDMap:
    pass


def read_pg_vec_map(r):
    d = {}
    for _ in range(r.u32()):
        pg = read_pg(r)
        d[pg] = [r.s32() for _ in range(r.u32())]
    return d


def read_pg_pairs_map(r):
    d = {}
    for _ in range(r.u32()):
        pg = read_pg(r)
        d[pg] = [(r.s32(), r.s32()) for _ in range(r.u32())]
    return d


def read_pg_s32_map(r):
    d = {}
    for _ in range(r.u32()):
        pg = read_pg(r)
        d[pg] = r.s32()
    return d


def decode_osdmap(buf, verify_crc=True):
    r = R(buf)
    m = OSDMap()
    wv = r.u8()
    if wv < 7:
        raise CheckError("old whole-struct OSDMap format %d" % wv)
    wcompat = r.u8()
    wlen = r.u32()
    wend = r.p + wlen
    if wend > len(buf):
        raise CheckError("wrapper length overruns buffer")
    m.wrapper_v = wv
    m.wrapper_compat = wcompat
    cv, cc, cend = env(r)
    m.client_v = cv
    m.client_compat = cc
    m.fsid = r.raw(16)
    m.epoch = r.u32()
    m.created = r.raw(8)
    m.modified = r.raw(8)
    m.pools = {}
    for _ in range(r.u32()):
        pid = r.s64()
        m.pools[pid] = decode_pool(r)
    m.pool_name = {}
    for _ in range(r.u32()):
        pid = r.s64()
        m.pool_name[pid] = r.string()
    m.pool_max = r.s32()
    m.flags = r.u32()
    m.max_osd = r.s32()
    nst = r.u32()
    m.osd_state = [r.u32() for _ in range(nst)]
    nw = r.u32()
    m.osd_weight = [r.u32() for _ in range(nw)]
    na = r.u32()
    m.client_addrs = [read_addrvec(r) for _ in range(na)]
    m.pg_temp = read_pg_vec_map(r)
    m.primary_temp = read_pg_s32_map(r)
    n = r.u32()
    m.affinity = [r.u32() for _ in range(n)] if n else None
    m.crush_blob = r.blob()
    m.ec_profiles = read_str_map_map(r) if cv >= 3 else {}
    m.pg_upmap = read_pg_vec_map(r) if cv >= 4 else {}
    m.pg_upmap_items = read_pg_pairs_map(r) if cv >= 4 else {}
    m.crush_version = r.u32() if cv >= 6 else 0
    if cv >= 7:
        for _ in range(2):
            for _ in range(r.u32()):
                r.s64()
                read_interval_set(r)
    if cv >= 9:
        r.raw(16)
    m.pg_upmap_primaries = read_pg_s32_map(r) if cv >= 10 else {}
    if r.p > cend:
        raise CheckError("client block overrun")
    finish(r, cend, "client block")
    # OSD-only block: skip by its length
    ov, oc, oend = env(r)
    m.osd_block_v = ov
    r.p = oend
    m.crc = None
    m.crc_ok = None
    if wv >= 8:
        crc_pos = r.p
        m.crc = r.u32()
        if verify_crc:
            c = crc32c(buf[:crc_pos], 0xFFFFFFFF)
            c = crc32c(buf[crc_pos + 4:wend], c)
            m.crc_ok = (c == m.crc)
    if r.p > wend:
        raise CheckError("wrapper overrun")
    m.wend = wend
    m._crush = None
    return m


def osdmap_crush(m):
    if m._crush is None:
        m._crush = decode_crush(m.crush_blob)
    return m._crush


class Incremental:
    pass


def decode_incremental(buf, verify_crc=True):
    r = R(buf)
    inc = Incremental()
    wv = r.u8()
    if wv < 7:
        raise CheckError("old incremental format")
    r.u8()
    wlen = r.u32()
    wend = r.p + wlen
    inc.wrapper_v = wv
    cv, cc, cend = env(r)
    inc.client_v = cv
    inc.fsid = r.raw(16)
    inc.epoch = r.u32()
    inc.modified = r.raw(8)
    inc.new_pool_max = r.s64()
    inc.new_flags = r.s32()
    inc.fullmap = r.blob()
    inc.crush = r.blob()
    inc.new_max_osd = r.s32()
    inc.new_pools = {}
    for _ in range(r.u32()):
        pid = r.s64()
        inc.new_pools[pid] = decode_pool(r)
    inc.new_pool_names = {}
    for _ in range(r.u32()):
        pid = r.s64()
        inc.new_pool_names[pid] = r.string()
    inc.old_pools = [r.s64() for _ in range(r.u32())]
    inc.new_up_client = {}
    for _ in range(r.u32()):
        o = r.s32()
        inc.new_up_client[o] = read_addrvec(r)
    inc.new_state = {}
    for _ in range(r.u32()):
        o = r.s32()
        inc.new_state[o] = r.u32()
    inc.new_weight = {}
    for _ in range(r.u32()):
        o = r.s32()
        inc.new_weight[o] = r.u32()
    inc.new_pg_temp = read_pg_vec_map(r)
    inc.new_primary_temp = read_pg_s32_map(r)
    inc.new_primary_affinity = {}
    if cv >= 2:
        for _ in range(r.u32()):
            o = r.s32()
            inc.new_primary_affinity[o] = r.u32()
    if cv >= 3:
        read_str_map_map(r)
        for _ in range(r.u32()):
            r.string()
    inc.new_pg_upmap = inc.new_pg_upmap_items = {}
    inc.old_pg_upmap = inc.old_pg_upmap_items = []
    if cv >= 4:
        inc.new_pg_upmap = read_pg_vec_map(r)
        inc.old_pg_upmap = [read_pg(r) for _ in range(r.u32())]
        inc.new_pg_upmap_items = read_pg_pairs_map(r)
        inc.old_pg_upmap_items = [read_pg(r) for _ in range(r.u32())]
    if cv >= 6:
        for _ in range(2):
            for _ in range(r.u32()):
                r.s64()
                read_interval_set(r)
    if cv >= 8:
        r.raw(16)
    inc.new_pg_upmap_primary = {}
    inc.old_pg_upmap_primary = []
    if cv >= 9:
        inc.new_pg_upmap_primary = read_pg_s32_map(r)
        inc.old_pg_upmap_primary = [read_pg(r) for _ in range(r.u32())]
    finish(r, cend, "incremental client block")
    ov, oc, oend = env(r)
    r.p = oend
    inc.inc_crc = inc.full_crc = None
    inc.inc_crc_ok = None
    if wv >= 8:
        pos = r.p
        inc.inc_crc = r.u32()
        inc.full_crc = r.u32()
        if verify_crc:
            c = crc32c(buf[:pos], 0xFFFFFFFF)
            c = crc32c(buf[pos + 4:wend], c)
            inc.inc_crc_ok = (c == inc.inc_crc)
    inc.wend = wend
    return inc


def clone_map(m):
    n = OSDMap()
    n.__dict__.update(m.__dict__)
    n.osd_state = list(m.osd_state)
    n.osd_weight = list(m.osd_weight)
    n.client_addrs = list(m.client_addrs)
    n.pg_temp = {k: list(v) for k, v in m.pg_temp.items()}
    n.primary_temp = dict(m.primary_temp)
    n.affinity = None if m.affinity is None else list(m.affinity)
    n.pg_upmap = {k: list(v) for k, v in m.pg_upmap.items()}
    n.pg_upmap_items = {k: list(v) for k, v in m.pg_upmap_items.items()}
    n.pg_upmap_primaries = dict(m.pg_upmap_primaries)
    n.pools = dict(m.pools)
    n.pool_name = dict(m.pool_name)
    n._crush = None
    return n


def apply_incremental(m, inc, tweak=None):
    """osdmap.md 3.5 / crush note 2.7.  Returns a new map; the input is not modified."""
    if inc.fullmap:
        full = decode_osdmap(inc.fullmap)
        return full
    if m is None:
        raise CheckError("no base map")
    if inc.fsid != m.fsid:
        raise CheckError("fsid mismatch")
    if inc.epoch != m.epoch + 1:
        raise CheckError("epoch %d not contiguous to %d" % (inc.epoch, m.epoch))
    n = clone_map(m)
    n.epoch = inc.epoch
    n.modified = inc.modified
    if inc.new_flags >= 0:
        n.flags = inc.new_flags
    if inc.new_max_osd >= 0:
        k = inc.new_max_osd
        n.max_osd = k
        n.osd_state = (n.osd_state + [0] * k)[:k]
        n.osd_weight = (n.osd_weight + [0] * k)[:k]
        n.client_addrs = (n.client_addrs + [[] for _ in range(k)])[:k]
        if n.affinity is not None:
            n.affinity = (n.affinity + [0x10000] * k)[:k]
    if inc.new_pool_max != -1:
        n.pool_max = inc.new_pool_max
    for pid, p in inc.new_pools.items():
        p.last_change = inc.epoch  # note: "set that record's last_change to the new epoch"
        n.pools[pid] = p
    for pid, nm in inc.new_pool_names.items():
        n.pool_name[pid] = nm
    for pid in inc.old_pools:
        n.pools.pop(pid, None)
        n.pool_name.pop(pid, None)
    for o, w in inc.new_weight.items():
        n.osd_weight[o] = w
        if w:
            n.osd_state[o] = (n.osd_state[o] | 1) & ~(0x4 | 0x8)
    for o, a in inc.new_primary_affinity.items():
        if n.affinity is None:
            n.affinity = [0x10000] * n.max_osd
        n.affinity[o] = a
    for o, mask in inc.new_state.items():
        eff = mask if mask else 0x2
        if (n.osd_state[o] & 1) and (eff & 1):
            n.osd_state[o] = 0
            n.client_addrs[o] = []
            if n.affinity is not None:
                n.affinity[o] = 0x10000
        else:
            n.osd_state[o] ^= eff
    for o, av in inc.new_up_client.items():
        n.osd_state[o] = (n.osd_state[o] | 0x3) & ~0x1000
        n.client_addrs[o] = av
    for pg, v in inc.new_pg_temp.items():
        if v:
            n.pg_temp[pg] = v
        else:
            n.pg_temp.pop(pg, None)
    for pg, o in inc.new_primary_temp.items():
        if o == -1:
            n.primary_temp.pop(pg, None)
        else:
            n.primary_temp[pg] = o
    for pg, v in inc.new_pg_upmap.items():
        n.pg_upmap[pg] = v
    for pg in inc.old_pg_upmap:
        n.pg_upmap.pop(pg, None)
    for pg, v in inc.new_pg_upmap_items.items():
        n.pg_upmap_items[pg] = v
    for pg in inc.old_pg_upmap_items:
        n.pg_upmap_items.pop(pg, None)
    for pg, v in inc.new_pg_upmap_primary.items():
        n.pg_upmap_primaries[pg] = v
    for pg in inc.old_pg_upmap_primary:
        n.pg_upmap_primaries.pop(pg, None)
    if inc.crush:
        n.crush_blob = inc.crush
    for p in n.pools.values():
        p.pg_num_mask, p.pgp_num_mask = pool_masks(p.pg_num, p.pgp_num)
    return n


# --------------------------------------------------------------------------------------------------------------
# placement pipeline (note 3.1 - 3.7)
# --------------------------------------------------------------------------------------------------------------

FLAG_HASHPSPOOL = 1


class Unmappable(Exception):
    pass


def object_ps(pool, name, nspace=b"", key=b""):
    subject = key if key else name
    s = (nspace + b"\x1f" + subject) if nspace else subject
    if pool.object_hash == 2:
        return str_hash_rjenkins(s)
    if pool.object_hash == 1:
        return str_hash_linux(s)
    raise Unsupported("object_hash %d" % pool.object_hash)


def pool_pps(pool, pool_id, ps):
    s = stable_mod(ps, pool.pgp_num, pool.pgp_num_mask)
    if pool.flags & FLAG_HASHPSPOOL:
        return hash2(s, pool_id & M32)
    return (s + pool_id) & M32


def _exists(m, o):
    return 0 <= o < m.max_osd and bool(m.osd_state[o] & 1)


def _up(m, o):
    return _exists(m, o) and bool(m.osd_state[o] & 2)


def _valid(m, o):
    return o != ITEM_NONE and 0 <= o < m.max_osd


def _first_non_none(lst):
    for o in lst:
        if o != ITEM_NONE:
            return o
    return -1


def pg_mapping(m, pool_id, seed, pps=None):
    """Returns dict(raw, up, up_primary, acting, acting_primary) for the masked pg (pool_id, seed)."""
    pool = m.pools.get(pool_id)
    if pool is None:
        raise Unmappable("no pool %d" % pool_id)
    if pool.type != 1:
        raise Unsupported("pool type %d" % pool.type)
    if pps is None:
        pps = pool_pps(pool, pool_id, seed)
    cm = osdmap_crush(m)
    ca = select_choose_args(cm, pool_id)
    raw = do_rule(cm, pool.crush_rule, pps, pool.size, m.osd_weight, ca)
    raw = [o for o in raw if _exists(m, o)]
    pg = (pool_id, seed)
    stage = {"raw_before_upmap": list(raw)}
    # upmap
    skip_rest = False
    if pg in m.pg_upmap:
        lst = m.pg_upmap[pg]
        if any(_valid(m, o) and m.osd_weight[o] == 0 for o in lst):
            skip_rest = True
        else:
            raw = list(lst)
    if not skip_rest:
        if pg in m.pg_upmap_items:
            for frm, to in m.pg_upmap_items[pg]:
                if to in raw:
                    continue
                pos = -1
                for i, o in enumerate(raw):
                    if o == frm and pos < 0:
                        if not (_valid(m, to) and m.osd_weight[to] == 0):
                            pos = i
                if pos >= 0:
                    raw[pos] = to
        if pg in m.pg_upmap_primaries:
            p = m.pg_upmap_primaries[pg]
            if _valid(m, p) and m.osd_weight[p] != 0:
                for k in range(1, len(raw)):
                    if raw[k] == p:
                        raw[0], raw[k] = raw[k], raw[0]
                        break
    stage["raw_after_upmap"] = list(raw)
    up = [o for o in raw if _up(m, o)]
    up_primary = _first_non_none(up)
    if m.affinity is not None and up:
        aff = m.affinity
        if any(_valid(m, o) and aff[o] != 0x10000 for o in up):
            pos = -1
            for i, o in enumerate(up):
                a = aff[o]
                if a < 0x10000 and (hash2(pps, o) >> 16) >= a:
                    if pos < 0:
                        pos = i
                else:
                    pos = i
                    break
            if pos >= 0:
                up_primary = up[pos]
                if pos > 0:
                    for i in range(pos, 0, -1):
                        up[i] = up[i - 1]
                    up[0] = up_primary
    temp = [o for o in m.pg_temp.get(pg, []) if _up(m, o)]
    if pg in m.primary_temp:
        tp = m.primary_temp[pg]
    elif temp:
        tp = _first_non_none(temp)
    else:
        tp = -1
    if not temp:
        acting = list(up)
        acting_primary = tp if tp != -1 else up_primary
    else:
        acting = temp
        acting_primary = tp
    return dict(raw=stage["raw_before_upmap"], raw_after_upmap=stage["raw_after_upmap"], up=up,
                up_primary=up_primary, acting=acting, acting_primary=acting_primary, pps=pps)


def map_object(m, pool_id, name, nspace=b"", key=b""):
    pool = m.pools[pool_id]
    ps = object_ps(pool, name, nspace, key)
    seed = stable_mod(ps, pool.pg_num, pool.pg_num_mask)
    d = pg_mapping(m, pool_id, seed)
    d["ps"] = ps
    d["seed"] = seed
    return d


# --------------------------------------------------------------------------------------------------------------
# pcap -> TCP streams -> msgr2 revision-1 crc-mode frames (msgr2.md 2.3, 2.6.1, 2.9) -> MOSDMap / MOSDOp
# --------------------------------------------------------------------------------------------------------------


def read_pcap(path):
    """yield (ts, src, sport, dst, dport, seq, flags, payload) for every IPv4/TCP packet"""
    data = open(path, "rb").read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        raise CheckError("%s: not a classic pcap file" % path)
    link = struct.unpack(e + "I", data[20:24])[0]
    p = 24
    n = len(data)
    while p + 16 <= n:
        ts_s, ts_f, incl, orig = struct.unpack(e + "IIII", data[p:p + 16])
        p += 16
        pkt = data[p:p + incl]
        p += incl
        if link == 1:
            if len(pkt) < 14:
                continue
            et = struct.unpack(">H", pkt[12:14])[0]
            off = 14
            if et == 0x8100:
                et = struct.unpack(">H", pkt[16:18])[0]
                off = 18
            if et != 0x0800:
                continue
        elif link == 113:
            if len(pkt) < 16 or struct.unpack(">H", pkt[14:16])[0] != 0x0800:
                continue
            off = 16
        elif link == 101:
            off = 0
        else:
            raise CheckError("unsupported link type %d" % link)
        ip = pkt[off:]
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 0xF) * 4
        tl = struct.unpack(">H", ip[2:4])[0]
        if tl == 0 or tl > len(ip):
            tl = len(ip)
        tcp = ip[ihl:tl]
        if len(tcp) < 20:
            continue
        sport, dport, seq, ack = struct.unpack(">HHII", tcp[:12])
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        yield (ts_s + ts_f * 1e-6, src, sport, dst, dport, seq, flags, tcp[doff:])


class _Stream:
    def __init__(self):
        self.nxt = None
        self.buf = bytearray()
        self.pending = {}
        self.retrans = 0
        self.first_ts = None

    def add(self, seq, data, flags, ts):
        if self.first_ts is None:
            self.first_ts = ts
        if flags & 0x02:  # SYN
            self.nxt = (seq + 1) & M32
            return
        if not data:
            return
        if self.nxt is None:
            self.nxt = seq
        d = ((seq - self.nxt + 0x80000000) & M32) - 0x80000000
        if d < 0:
            if -d >= len(data):
                self.retrans += 1
                return
            self.retrans += 1
            data = data[-d:]
            d = 0
        if d == 0:
            self.buf += data
            self.nxt = (self.nxt + len(data)) & M32
            self._drain()
        else:
            old = self.pending.get(seq)
            if old is None or len(old) < len(data):
                self.pending[seq] = data

    def _drain(self):
        progress = True
        while progress and self.pending:
            progress = False
            for seq in list(self.pending):
                d = ((seq - self.nxt + 0x80000000) & M32) - 0x80000000
                if d <= 0:
                    data = self.pending.pop(seq)
                    if -d < len(data):
                        data = data[-d:]
                        self.buf += data
                        self.nxt = (self.nxt + len(data)) & M32
                    progress = True


def _first_syn_sender(path):
    """The capture is one client talking to daemons: the client is whoever sends the first bare SYN."""
    for ts, src, sport, dst, dport, seq, flags, payload in read_pcap(path):
        if (flags & 0x12) == 0x02:
            return src
    return None


def pcap_connections(path, client_ip=None):
    """returns list of dict(client_port, server_ip, server_port, c2s=bytes, s2c=bytes, retrans, t0)"""
    conns = {}
    if client_ip is None:
        client_ip = _first_syn_sender(path)
    for ts, src, sport, dst, dport, seq, flags, payload in read_pcap(path):
        if src == client_ip:
            key = (sport, dst, dport)
            side = "c2s"
        elif dst == client_ip:
            key = (dport, src, sport)
            side = "s2c"
        else:
            continue
        c = conns.setdefault(key, {"c2s": _Stream(), "s2c": _Stream()})
        c[side].add(seq, payload, flags, ts)
    out = []
    for (cp, sip, sp), c in conns.items():
        t0 = min(x for x in (c["c2s"].first_ts, c["s2c"].first_ts) if x is not None)
        out.append(dict(client_port=cp, server_ip=sip, server_port=sp, c2s=bytes(c["c2s"].buf),
                        s2c=bytes(c["s2c"].buf), retrans=c["c2s"].retrans + c["s2c"].retrans, t0=t0,
                        gaps=len(c["c2s"].pending) + len(c["s2c"].pending),
                        gap_dir={"c2s": len(c["c2s"].pending), "s2c": len(c["s2c"].pending)}))
    out.sort(key=lambda d: d["t0"])
    return out


TAGS = {1: "HELLO", 2: "AUTH_REQUEST", 3: "AUTH_BAD_METHOD", 4: "AUTH_REPLY_MORE", 5: "AUTH_REQUEST_MORE",
        6: "AUTH_DONE", 7: "AUTH_SIGNATURE", 8: "CLIENT_IDENT", 9: "SERVER_IDENT", 10: "IDENT_MISSING_FEATURES",
        11: "SESSION_RECONNECT", 12: "SESSION_RESET", 13: "SESSION_RETRY", 14: "SESSION_RETRY_GLOBAL",
        15: "SESSION_RECONNECT_OK", 16: "WAIT", 17: "MESSAGE", 18: "KEEPALIVE2", 19: "KEEPALIVE2_ACK", 20: "ACK",
        21: "COMPRESSION_REQUEST", 22: "COMPRESSION_DONE"}


class FrameStats:
    def __init__(self):
        self.frames = 0
        self.crc_checked = 0
        self.crc_bad = 0
        self.len_bad = 0
        self.tag_bad = 0
        self.epi_bad = 0
        self.bytes_crc = 0
        self.secure_at = None  # frame index where the preamble CRC first failed (secure mode starts)
        self.banner_ok = True
        self.tail = 0  # unparsed bytes at the end
        self.messages = []  # (header2 dict, front, middle, data)


def parse_msgr2_stream(buf, quick=False):
    st = FrameStats()
    if len(buf) < 26 or buf[:8] != b"ceph v2\n" or struct.unpack("<H", buf[8:10])[0] != 16:
        st.banner_ok = False
        return st
    sup, req = struct.unpack("<QQ", buf[10:26])
    st.banner_features = (sup, req)
    p = 26
    n = len(buf)
    while p + 32 <= n:
        pre = buf[p:p + 32]
        if crc32c(pre[:28], 0) != struct.unpack("<I", pre[28:32])[0]:
            st.secure_at = st.frames
            break
        tag = pre[0]
        ns = pre[1]
        segs = []
        for i in range(4):
            ln, al = struct.unpack("<IH", pre[2 + 6 * i:8 + 6 * i])
            segs.append((ln, al))
        if tag not in TAGS or not (1 <= ns <= 4) or (ns > 1 and segs[ns - 1][0] == 0) or any(
                segs[i][0] or segs[i][1] for i in range(ns, 4)):
            st.tag_bad += 1
            break
        L0, L1, L2, L3 = (s[0] for s in segs)
        total = 32 + (L0 + 4 if L0 else 0) + L1 + L2 + L3 + (13 if ns > 1 else 0)
        if p + total > n:
            st.tail = n - p
            break
        q = p + 32
        payloads = []
        if L0:
            s0 = buf[q:q + L0]
            c = struct.unpack("<I", buf[q + L0:q + L0 + 4])[0]
            st.crc_checked += 1
            if crc32c(s0, M32) != c:
                st.crc_bad += 1
            q += L0 + 4
        else:
            s0 = b""
        payloads.append(s0)
        for i in range(1, ns):
            payloads.append(buf[q:q + segs[i][0]])
            q += segs[i][0]
        if ns > 1:
            epi = buf[q:q + 13]
            if epi[0] & 0x0F != 0x0E:
                st.epi_bad += 1
            for i in range(1, 4):
                slot = struct.unpack("<I", epi[1 + 4 * (i - 1):5 + 4 * (i - 1)])[0]
                if i < ns:
                    ln = segs[i][0]
                    if ln == 0:
                        want = M32
                    elif quick and ln > 65536:
                        continue
                    else:
                        want = crc32c(payloads[i], M32)
                        st.bytes_crc += ln
                    st.crc_checked += 1
                    if slot != want:
                        st.crc_bad += 1
                elif slot != 0:
                    st.crc_bad += 1
        st.frames += 1
        if tag == 17:
            if len(payloads[0]) != 41:
                st.len_bad += 1
            else:
                h = payloads[0]
                hd = dict(seq=struct.unpack("<Q", h[0:8])[0], tid=struct.unpack("<Q", h[8:16])[0],
                          type=struct.unpack("<H", h[16:18])[0], prio=struct.unpack("<H", h[18:20])[0],
                          version=struct.unpack("<H", h[20:22])[0], flags=h[36],
                          compat=struct.unpack("<H", h[37:39])[0])
                payloads += [b""] * (4 - len(payloads))
                st.messages.append((hd, payloads[1], payloads[2], payloads[3]))
        p += total
    else:
        st.tail = n - p
    if st.secure_at is None and st.tail == 0 and p == n:
        pass
    return st


def decode_mosdmap(front, version):
    r = R(front)
    fsid = r.raw(16)
    incs = {}
    for _ in range(r.u32()):
        e = r.u32()
        incs[e] = r.blob()
    maps = {}
    for _ in range(r.u32()):
        e = r.u32()
        maps[e] = r.blob()
    oldest = newest = None
    gaps = 0
    if version >= 2:
        oldest = r.u32()
        newest = r.u32()
    if version >= 4:
        gaps = r.u32()
        for _ in range(gaps):
            r.s64()
            read_interval_set(r)
    return dict(fsid=fsid, incs=incs, maps=maps, oldest=oldest, newest=newest, gaps=gaps, left=r.left())


def decode_mosdop(front, version):
    r = R(front)
    o = {}
    _v, _c, e = env(r)
    pgv = r.u8()
    o["pool"] = r.u64()
    o["seed"] = r.u32()
    r.s32()
    o["shard"] = r.s8()
    r.p = e
    o["hash"] = r.u32()
    o["epoch"] = r.u32()
    o["flags"] = r.u32()
    r.skip(27)  # reqid
    r.skip(24)  # blkin
    if version >= 9:
        r.skip(7)  # otel
    o["client_inc"] = r.u32()
    r.skip(8)  # mtime
    _v, _c, e = env(r)
    o["oloc_pool"] = r.s64()
    r.s32()
    o["key"] = r.string()
    o["nspace"] = r.string()
    o["oloc_hash"] = r.s64()
    r.p = e
    o["oid"] = r.string()
    nops = r.u16()
    o["ops"] = []
    for _ in range(nops):
        rec = r.raw(38)
        o["ops"].append(struct.unpack("<H", rec[:2])[0])
    o["snapid"] = r.u64()
    o["snap_seq"] = r.u64()
    r.skip(8 * r.u32())
    o["retry"] = r.s32()
    o["features"] = r.u64()
    o["left"] = r.left()
    return o


# --------------------------------------------------------------------------------------------------------------
# the checks
# --------------------------------------------------------------------------------------------------------------

STATE_BITS = {"exists": 0x1, "up": 0x2, "autoout": 0x4, "new": 0x8, "full": 0x10, "nearfull": 0x20,
              "backfillfull": 0x40, "destroyed": 0x80, "noup": 0x100, "nodown": 0x200, "noin": 0x400,
              "noout": 0x800, "stop": 0x1000}


def pgstr(pg):
    return "%d.%x" % pg


def parse_pgstr(s):
    a, b = s.split(".")
    return (int(a), int(b, 16))


def uuid_str(b):
    h = b.hex()
    return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:])


def oracle_bytes(s):
    """The monitor's JSON command parser turns a code point above U+FFFF into two 3-byte (CESU-8) halves; see the
    README of the vectors.  Everything else is plain UTF-8."""
    out = []
    for ch in s:
        o = ord(ch)
        if o > 0xFFFF:
            o -= 0x10000
            out.append(chr(0xD800 + (o >> 10)))
            out.append(chr(0xDC00 + (o & 0x3FF)))
        else:
            out.append(ch)
    return "".join(out).encode("utf-8", "surrogatepass")


def crush_struct(cm):
    """comparable summary of a decoded CRUSH map that ignores the two encoder-dependent places of note 2.1"""
    bs = []
    for b in cm.buckets:
        if b is None:
            bs.append(None)
        else:
            bs.append((b.id, b.type, b.alg, b.hash, b.weight, tuple(b.items), tuple(b.item_weights or ()),
                       tuple(b.sum_weights or ()), tuple(b.straws or ()), b.item_weight))
    rules = [None if r is None else (r.ruleset, r.type, tuple(r.steps)) for r in cm.rules]
    t = dict(cm.tun)
    t.pop("msr_descents"); t.pop("msr_collision_tries")
    return (bs, rules, sorted(t.items()), sorted(cm.type_map.items()), sorted(cm.name_map.items()),
            sorted(cm.rule_name_map.items()), cm.class_map, cm.class_name, cm.class_bucket,
            {k: v for k, v in cm.choose_args.items()})


def load_json(p):
    with open(p) as f:
        return json.load(f)


def read_bytes(p):
    with open(p, "rb") as f:
        return f.read()


# ---- A: arithmetic and table facts ------------------------------------------------------------------------------


def grp_arith(res):
    g = "A.arith"
    h = str_hash_rjenkins
    sv = [(b"", 0xbd49d10d, 0), (b"a", 0x29eec818, 0x42f2), (b"foo", 0x7fc1f406, 0x24db2a),
          (b"abcdefghijkl", 0x0b1b3ea5, 0xf281eff0), (b"abcdefghijklm", 0x3122b031, 0x6b959a82),
          (b"rbd_directory", 0x30a98c1c, 0x9569da2c), (b"rbd_id.myimage", 0xf8d9dc15, 0xca6e1713),
          (b"rbd_header.1234abcd5678", 0xdb3ea4d9, 0xc6227fd9),
          (b"rbd_data.1234abcd5678.0000000000000000", 0x89a0b515, 0xe9caf84f), (b"ns\x1ffoo", 0xac17f0b6, 0xccc913ee)]
    bad = [(x[0], hex(h(x[0])), hex(x[1])) for x in sv if h(x[0]) != x[1]]
    res.check(g, "5.1 rjenkins string hash, 10 vectors", not bad, str(bad), 10)
    bad = [(x[0], hex(str_hash_linux(x[0])), hex(x[2])) for x in sv if str_hash_linux(x[0]) != x[2]]
    res.check(g, "5.1 linux dcache string hash, 10 vectors", not bad, str(bad), 10)
    hv = [("hash2(0,0)", hash2(0, 0), 0x19ad4ce9), ("hash2(1,2)", hash2(1, 2), 0xb78dee9c),
          ("hash2(0x7fc1f406,1)", hash2(0x7fc1f406, 1), 0x8ddb71b1),
          ("hash2(ffffffff,ffffffff)", hash2(M32, M32), 0x9f3c11cc), ("hash3(0,0,0)", hash3(0, 0, 0), 0x7a3bf3b2),
          ("hash3(1,2,3)", hash3(1, 2, 3), 0x735ad42b), ("hash3(12345678,ffffffff,7)", hash3(0x12345678, M32, 7), 0x03097224),
          ("hash3(5,ffffffff,0)", hash3(5, M32, 0), 0x3e502f1c), ("hash4(0,0,0,0)", hash4(0, 0, 0, 0), 0x3fafb04d),
          ("hash4(1,2,3,4)", hash4(1, 2, 3, 4), 0x696d1f16)]
    bad = [(n, hex(a), hex(b)) for n, a, b in hv if a != b]
    res.check(g, "5.1 CRUSH hash2/3/4, 10 vectors (from the table of 3.2.1)", not bad, str(bad), 10)
    h1 = [(hash1_reconstructed(0), 0x17c4a80b), (hash1_reconstructed(1), 0xd5082851), (hash1_reconstructed(M32), 0x7f71bc2a)]
    res.info(g, "5.1 hash1 vectors", "3.2.1 defines hash2/3/4 only; a hash1 reconstructed from the same pattern "
             "(mix(b=a,X,h); mix(Y,a,h)) reproduces all 3 hash1 vectors: %s" % all(a == b for a, b in h1))
    sm = [(stable_mod(0x7fc1f406, 12, 15), 6), (stable_mod(0x7fc1f40e, 12, 15), 6), (stable_mod(0x7fc1f40e, 16, 15), 14),
          (stable_mod(M32, 100, 127), 63), (stable_mod(100, 100, 127), 36), (stable_mod(12345, 1, 0), 0)]
    res.check(g, "5.1 stable_mod vectors", all(a == b for a, b in sm), str(sm), len(sm))
    pv = [(hash2(6, 1), 0xd77484f9), (hash2(6, 2), 0x37f72ca0), (hash2(14, 1), 0xadee4b52)]
    legacy = [((stable_mod(6, 12, 15) + 1) & M32, 7), ((stable_mod(6, 12, 15) + 2) & M32, 8)]
    res.check(g, "5.1 HASHPSPOOL and legacy pps vectors", all(a == b for a, b in pv + legacy), "", 5)
    cv = [(0, 0x0), (1, 0x100000000000), (2, 0x195c01a39fbd), (255, 0x800000000000), (256, 0x80171e3b6d7a),
          (0x1234, 0xc2fb9e09ec18), (0x7fff, 0xf00000000000), (0x8000, 0xf0002e2a60a0), (0xfffe, 0xfffffd61ad10),
          (0xffff, 0xfffff0000000)]
    bad = [(hex(u), hex(crush_ln(u)), hex(e)) for u, e in cv if crush_ln(u) != e]
    res.check(g, "5.1 crush_ln, 10 vectors (tables read from the reference tree at run time)", not bad, str(bad), 10)
    # 3.4.2 table facts
    getcontext().prec = 80
    rh = LN.rh_lh
    ll = LN.ll
    ln2 = Decimal(2).ln()
    n_rh = sum(1 for k in range(129) if rh[2 * k] == -(-(1 << 55) // (128 + k)))
    n_lh = sum(1 for k in range(128) if rh[2 * k + 1] == int((Decimal(128 + k) / Decimal(128)).ln() / ln2 * Decimal(2 ** 48)))
    res.check(g, "3.4.2 RH_LH[2k] = ceil(2^48/(1+k/128)) for 129 entries", n_rh == 129, "%d/129" % n_rh, 129)
    res.check(g, "3.4.2 RH_LH[2k+1] = floor(2^48*log2(1+k/128)) for 128 entries", n_lh == 128, "%d/128" % n_lh, 128)
    res.check(g, "3.4.2 RH_LH[257] == 2^48-2^32", rh[257] == (1 << 48) - (1 << 32), hex(rh[257]), 1)
    exact = [int((Decimal(2 ** 15 + k) / Decimal(2 ** 15)).ln() / ln2 * Decimal(2 ** 48)) for k in range(256)]
    eq = near = oth = 0
    for k in range(256):
        d = ll[k] - exact[k]
        if d == 0:
            eq += 1
        elif abs(d - 5493489664) <= 1:
            near += 1
        else:
            oth += 1
    res.check(g, "3.4.2 LL_tbl split 21 exact / 212 near +5,493,489,664 / 23 other", (eq, near, oth) == (21, 212, 23),
              "%d/%d/%d" % (eq, near, oth), 256)
    nd = 0
    mx = 0
    for u in range(65536):
        a = LN.ln(u)
        b = LN.ln(u, exact)
        if a != b:
            nd += 1
            mx = max(mx, abs(a - b))
    res.check(g, "3.4.2 exact-formula LL changes crush_ln for 63,500 inputs, max diff 343,343,104", (nd, mx) == (63500, 343343104),
              "%d inputs, max diff %d" % (nd, mx), 65536)
    # monotonic sanity (not in the note): crush_ln is non-decreasing
    prev = -1
    mono = True
    for u in range(65536):
        v = LN.ln(u)
        if v < prev:
            mono = False
        prev = v
    res.info(g, "crush_ln monotonic over 0..65535 (extra)", str(mono))


# ---- B: CRUSH blob ----------------------------------------------------------------------------------------------


def grp_crush(res, C, ctx):
    g = "B.crush-blob"
    getblob = read_bytes(C + "/gt/crush.bin")
    full42 = ctx["full42"]
    jc = load_json(C + "/gt/dencoder-CrushWrapper.json")
    try:
        cm_get = decode_crush(getblob)
        cm_emb = decode_crush(full42.crush_blob)
    except CheckError as e:
        res.check(g, "decode both blobs", False, str(e))
        return
    res.check(g, "2.2 decode getcrushmap blob (723 B) and the blob embedded in the OSDMap (715 B)", True,
              "%d / %d bytes" % (len(getblob), len(full42.crush_blob)), 2)
    res.check(g, "2.2 blobs start with magic 0x00010000, no struct envelope", getblob[:4] == b"\x00\x00\x01\x00", "", 1)
    res.check(g, "2.4 recomputed max_devices == wire max_devices (3) in this map", cm_get.max_devices == cm_get.wire_max_devices == 3,
              "%d vs %d" % (cm_get.max_devices, cm_get.wire_max_devices), 1)
    # buckets
    name = cm_get.name_map
    tname = {t["type_id"]: t["name"] for t in jc["types"]}
    bad = []
    ids = set()
    for jb in jc["buckets"]:
        ids.add(jb["id"])
        b = cm_get.buckets[-1 - jb["id"]] if -1 - jb["id"] < len(cm_get.buckets) else None
        if b is None:
            bad.append(("missing", jb["id"]))
            continue
        mine = (b.id, b.type, {1: "uniform", 2: "list", 3: "tree", 4: "straw", 5: "straw2"}[b.alg], b.weight,
                [(it, w) for it, w in zip(b.items, b.item_weights)], name.get(b.id))
        exp = (jb["id"], jb["type_id"], jb["alg"], jb["weight"], [(i["id"], i["weight"]) for i in jb["items"]], jb["name"])
        if mine != exp:
            bad.append((mine, exp))
    extra = [b.id for b in cm_get.buckets if b is not None and b.id not in ids]
    res.check(g, "2.2 buckets (id, type, alg, weight, items+weights, name) equal ceph-dencoder JSON, shadow buckets included",
              not bad and not extra, str(bad[:2] + extra), len(jc["buckets"]))
    # rules
    opn = {"take": 1, "choose_firstn": 2, "choose_indep": 3, "emit": 4, "chooseleaf_firstn": 6, "chooseleaf_indep": 7}
    tid = {v: k for k, v in tname.items()}
    bad = []
    for jr in jc["rules"]:
        r = cm_get.rules[jr["rule_id"]]
        steps = []
        for s in jr["steps"]:
            op = opn[s["op"]]
            if op == 1:
                steps.append((1, s["item"], 0))
            elif op == 4:
                steps.append((4, 0, 0))
            else:
                steps.append((op, s["num"], tid[s["type"]]))
        if (r.type, steps, cm_get.rule_name_map[jr["rule_id"]]) != (jr["type"], steps, jr["rule_name"]) or list(r.steps) != steps:
            bad.append((jr["rule_id"], r.steps, steps))
    res.check(g, "2.2 rules (type, steps, names) equal dencoder JSON", not bad, str(bad[:1]), len(jc["rules"]))
    t = jc["tunables"]
    bad = [(k, cm_get.tun[k], t[k]) for k in ("choose_local_tries", "choose_local_fallback_tries", "choose_total_tries",
           "chooseleaf_descend_once", "chooseleaf_vary_r", "chooseleaf_stable", "straw_calc_version", "allowed_bucket_algs",
           "msr_descents", "msr_collision_tries") if cm_get.tun[k] != t[k]]
    res.check(g, "2.2/2.5 tunables incl. MSR pair equal dencoder JSON", not bad, str(bad), 10)
    bad = [(d["id"], name.get(d["id"]), d["name"], cm_get.class_name.get(cm_get.class_map.get(d["id"])), d["class"])
           for d in jc["devices"] if name.get(d["id"]) != d["name"] or cm_get.class_name.get(cm_get.class_map.get(d["id"])) != d.get("class")]
    res.check(g, "2.2 rows 8, 16, 17: device names and device classes", not bad, str(bad), len(jc["devices"]))
    res.check(g, "2.6 shadow buckets exist as ordinary buckets: class_bucket maps root/host to shadow ids",
              any(cm_get.class_bucket.values()) and all(-1 - s < cm_get.max_buckets and cm_get.buckets[-1 - s] is not None
                                                        for d in cm_get.class_bucket.values() for s in d.values()),
              str(cm_get.class_bucket), 1)
    res.check(g, "2.2 row 19: choose_args count is 0 on this cluster (so choose_args cannot be exercised here)",
              cm_get.choose_args == {} and cm_emb.choose_args == {}, "", 1)
    # embedded vs getcrushmap (2.1)
    only_msr = getblob[:-8] == full42.crush_blob and struct.unpack("<II", getblob[-8:]) == (100, 100)
    res.check(g, "2.1 [C1/C7/13] embedded blob has NO MSR pair, getcrushmap blob has it; otherwise byte-identical",
              only_msr and cm_get.has_msr_pair and not cm_emb.has_msr_pair, "diff = trailing 8 bytes (100,100)", 1)
    res.check(g, "2.1 the two forms decode to the same map except the MSR pair", crush_struct(cm_get) == crush_struct(cm_emb), "", 1)
    rm = [(r.min_size, r.max_size) for r in cm_emb.rules] + [(r.min_size, r.max_size) for r in cm_get.rules]
    res.info(g, "2.1 rule min/max bytes", "(1,100) in BOTH forms on this cluster (stored values are 1/100), so claim (b) "
             "'stored values instead of the constants' cannot be told apart here: %s" % sorted(set(rm)))
    # across all stored epochs
    nfull = ninc = nmsr_full = nmsr_inc = 0
    ok = True
    for e in sorted(ctx["fulls"]):
        cm = osdmap_crush(ctx["fulls"][e])
        nfull += 1
        nmsr_full += cm.has_msr_pair
    for e in sorted(ctx["incs"]):
        i = ctx["incs"][e]
        if i.crush:
            cm = decode_crush(i.crush)
            ninc += 1
            nmsr_inc += cm.has_msr_pair
    res.check(g, "2.1 all 89 stored full maps carry the no-MSR form; all %d stored incrementals with a crush field carry the MSR form" % ninc,
              nmsr_full == 0 and nmsr_inc == ninc and ninc > 0, "full with pair %d/%d, incremental with pair %d/%d" % (nmsr_full, nfull, nmsr_inc, ninc), nfull + ninc)
    ctx["crush_get"] = cm_get


# ---- C: OSDMap and incremental decoders, replay -------------------------------------------------------------------


def _norm_pgmap(lst, key):
    out = {}
    if lst and isinstance(lst[0], str):  # flat ["1.0", 0] quirk of the dumper
        lst = [lst[i:i + 2] for i in range(0, len(lst), 2)] if len(lst) % 2 == 0 else lst
    for e in lst:
        if isinstance(e, dict):
            if key == "mappings":
                out[parse_pgstr(e["pgid"])] = [(m["from"], m["to"]) for m in e["mappings"]]
            else:
                out[parse_pgstr(e["pgid"])] = e.get(key, e.get("osds"))
        else:
            out[parse_pgstr(e[0])] = e[1]
    return out


def compare_full_json(m, j):
    d = []
    if m.epoch != j["epoch"]: d.append("epoch")
    if uuid_str(m.fsid) != j["fsid"]: d.append("fsid")
    if m.max_osd != j["max_osd"]: d.append("max_osd")
    if m.pool_max != j["pool_max"]: d.append("pool_max")
    if m.flags != j["flags_num"]: d.append("flags")
    if m.crush_version != j["crush_version"]: d.append("crush_version")
    jp = {p["pool"]: p for p in j["pools"]}
    if set(jp) != set(m.pools):
        d.append("poolset")
    else:
        for pid, p in m.pools.items():
            q = jp[pid]
            exp = dict(type=q["type"], size=q["size"], min_size=q["min_size"], crush_rule=q["crush_rule"],
                       object_hash=q["object_hash"], pg_num=q["pg_num"], pgp_num=q["pg_placement_num"],
                       flags=q["flags"], snap_seq=q["snap_seq"], snap_epoch=q["snap_epoch"], tier_of=q["tier_of"],
                       read_tier=q["read_tier"], write_tier=q["write_tier"], tiers=q["tiers"],
                       pg_num_pending=q["pg_num_pending"], pg_num_target=q["pg_num_target"],
                       pgp_num_target=q["pg_placement_num_target"], last_force_op_resend=int(q["last_force_op_resend"]),
                       last_change=int(q["last_change"]), stripe_width=q["stripe_width"],
                       quota_max_bytes=q["quota_max_bytes"], quota_max_objects=q["quota_max_objects"],
                       erasure_code_profile=q["erasure_code_profile"].encode(),
                       stretch=(q["peering_crush_bucket_count"], q["peering_crush_bucket_target"],
                                q["peering_crush_bucket_barrier"], q["peering_crush_bucket_mandatory_member"]))
            for k, v in exp.items():
                if getattr(p, k) != v:
                    d.append("pool%d.%s %r!=%r" % (pid, k, getattr(p, k), v))
            if m.pool_name.get(pid) != q["pool_name"].encode():
                d.append("pool%d.name" % pid)
    for o in j["osds"]:
        i = o["osd"]
        if i >= m.max_osd:
            d.append("osd%d beyond max_osd" % i)
            continue
        st = m.osd_state[i]
        if bool(st & 2) != bool(o["up"]): d.append("osd%d.up" % i)
        if bool(m.osd_weight[i]) != bool(o["in"]): d.append("osd%d.in" % i)
        if abs(m.osd_weight[i] / 65536.0 - o["weight"]) > 1e-4: d.append("osd%d.weight" % i)
        aff = 0x10000 if m.affinity is None else m.affinity[i]
        if abs(aff / 65536.0 - o["primary_affinity"]) > 1e-4: d.append("osd%d.affinity" % i)
        # address of the first v2 entry
        v2 = [a for a in m.client_addrs[i] if a[0] == 2]
        ja = [a for a in o["public_addrs"]["addrvec"] if a["type"] == "v2"]
        if v2 and ja:
            if "%s:%d" % (v2[0][2], v2[0][3]) != ja[0]["addr"] or v2[0][1] != ja[0]["nonce"]:
                d.append("osd%d.addr" % i)
    for k, jk, key in (("pg_temp", "pg_temp", "osds"), ("pg_upmap", "pg_upmap", "osds"),
                       ("pg_upmap_items", "pg_upmap_items", "mappings"), ("primary_temp", "primary_temp", "osd")):
        try:
            jv = _norm_pgmap(j[jk], key)
        except Exception as ex:
            d.append("%s json shape %s" % (k, ex))
            continue
        if getattr(m, k) != jv:
            d.append("%s %r != %r" % (k, getattr(m, k), jv))
    if j["pg_upmap_primaries"] != [] or m.pg_upmap_primaries:
        if _norm_pgmap(j["pg_upmap_primaries"], "osd") != m.pg_upmap_primaries:
            d.append("pg_upmap_primaries")
    return d


def compare_inc_json(i, j):
    d = []
    if i.epoch != j["epoch"]: d.append("epoch")
    if i.new_max_osd != j["new_max_osd"]: d.append("new_max_osd")
    if i.new_flags != j["new_flags"]: d.append("new_flags")
    if i.new_pool_max != j["new_pool_max"]: d.append("new_pool_max")
    if i.new_weight != {e["osd"]: e["weight"] for e in j["new_weight"]}: d.append("new_weight")
    st = {}
    for e in j["osd_state_xor"]:
        mask = 0
        for nme in e["state_xor"]:
            mask |= STATE_BITS[nme]
        st[e["osd"]] = mask
    mine = {o: (m if m else 0x2) for o, m in i.new_state.items()}  # 0 = toggle UP
    exp = {o: (m if m else 0x2) for o, m in st.items()}
    if mine != exp: d.append("osd_state_xor %r != %r" % (i.new_state, st))
    if sorted(i.new_up_client) != sorted(e["osd"] for e in j["new_up_osds"]): d.append("new_up")
    if sorted(i.new_pools) != sorted(p["pool"] for p in j["new_pools"]): d.append("new_pools")
    if i.old_pools != [p if isinstance(p, int) else p for p in j["old_pools"]]: d.append("old_pools")
    if i.new_pg_temp != _norm_pgmap(j["new_pg_temp"], "osds"): d.append("new_pg_temp")
    if i.new_primary_temp != _norm_pgmap(j["primary_temp"], "osd"): d.append("new_primary_temp")
    if i.new_pg_upmap != _norm_pgmap(j["new_pg_upmap"], "osds"): d.append("new_pg_upmap")
    if i.new_pg_upmap_items != _norm_pgmap(j["new_pg_upmap_items"], "mappings"): d.append("new_pg_upmap_items")
    if sorted(i.old_pg_upmap) != sorted(parse_pgstr(x) for x in j["old_pg_upmap"]): d.append("old_pg_upmap")
    if sorted(i.old_pg_upmap_items) != sorted(parse_pgstr(x) for x in j["old_pg_upmap_items"]): d.append("old_pg_upmap_items")
    return d


def grp_osdmap(res, C, ctx):
    g = "C.osdmap"
    fulls = {}
    incs = {}
    for e in range(1, 90):
        fulls[e] = decode_osdmap(read_bytes(C + "/gt3/full/full.%05d.bin" % e))
        incs[e] = decode_incremental(read_bytes(C + "/gt3/inc/inc.%05d.bin" % e))
    ctx["fulls"] = fulls
    ctx["incs"] = incs
    res.check(g, "osdmap.md 2.4/2.5: decode 89 stored full maps (wrapper v8/compat 7, client block v10, OSD block v9, pool v32; "
              "every pool envelope consumed exactly)", True, "", 89)
    vs = {(f.wrapper_v, f.wrapper_compat, f.client_v, f.osd_block_v) for f in fulls.values()}
    res.check(g, "osdmap.md 2.4.2 versions written by v20.2.5 (wrapper 8 / compat 7, client 10, OSD-only 9)",
              vs == {(8, 7, 10, 9)}, str(vs), 89)
    pv = {p.v for f in fulls.values() for p in f.pools.values()}
    res.check(g, "osdmap.md 2.5 pool struct_v is 32 on this cluster", pv == {32}, str(pv), 1)
    nbad = [e for e, f in fulls.items() if not f.crc_ok]
    res.check(g, "osdmap.md 2.4.5 trailing CRC = raw CRC-32C (seed 0xFFFFFFFF, no final xor) over the wrapper without the CRC "
              "field, for all 89 full maps [confirm T8]", not nbad, str(nbad[:5]), 89)
    ibad = [e for e, i in incs.items() if i.inc_crc is not None and not i.inc_crc_ok]
    res.check(g, "osdmap.md 2.6.1 inc_crc (same recipe, continued over full_crc) for all 89 incrementals", not ibad, str(ibad[:5]), 89)
    fb = [e for e, i in incs.items() if i.full_crc is not None and not i.fullmap and i.full_crc != fulls[e].crc]
    res.check(g, "osdmap.md 2.6.1 incremental.full_crc == crc of the stored full map of that epoch (epochs 2..89)", not fb,
              str(fb[:5]), 88)
    # vs dencoder JSON
    n = 0
    bad = []
    for e in sorted(fulls):
        try:
            dj = compare_full_json(fulls[e], load_json(C + "/gt3/full-json/full.%05d.json" % e))
        except Exception as ex:
            dj = ["exception %s" % ex]
        n += 1
        if dj:
            bad.append((e, dj[:3]))
    res.check(g, "full-map decoder (epochs 1..89) equals ceph-dencoder JSON: pools, osd state/weight/affinity/address, pg_temp, "
              "primary_temp, pg_upmap(_items)", not bad, str(bad[:3]), n)
    jb = []
    for e in sorted(incs):
        dj = compare_inc_json(incs[e], load_json(C + "/gt3/inc-json/inc.%05d.json" % e))
        if dj:
            jb.append((e, dj[:3]))
    res.check(g, "incremental decoder (epochs 1..89) equals ceph-dencoder JSON (new_weight, state xor, pools, temps, upmaps)",
              not jb, str(jb[:3]), 89)
    mm = decode_osdmap(read_bytes(C + "/gt/osdmap.bin"))
    res.check(g, "gt/osdmap.bin (getmap, epoch 42) decodes, CRC ok, equals gt3 full map 42 byte for byte",
              mm.crc_ok and read_bytes(C + "/gt/osdmap.bin") == read_bytes(C + "/gt3/full/full.00042.bin"), "", 1)
    ctx["full42"] = mm
    # primary affinity incrementals (JSON omits them)
    aff = {e: i.new_primary_affinity for e, i in incs.items() if i.new_primary_affinity}
    ok = aff == {55: {1: 0x8000}, 57: {1: 0x10000}} or (sorted(aff) == [55, 57])
    res.check(g, "new_primary_affinity is present only in the raw bytes (epochs 55 and 57), and replay matches the full maps",
              sorted(aff) == [55, 57] and aff[55].get(1) is not None, str(aff), 2)
    res.info(g, "dencoder omits new_primary_affinity", "the Incremental JSON dump has no such field (INDEX shows epochs 55 and 57 as 'empty'); raw bytes decode to %s" % aff)
    ea = [(e, f.affinity) for e, f in fulls.items() if f.affinity is not None]
    res.info(g, "full-map affinity vector", "first epoch with non-empty vector: %s; epochs 1..54 carry an empty vector (decoded as 'absent'): %s"
             % (ea[0][0] if ea else None, all(fulls[e].affinity is None for e in range(1, 55))))
    # replay
    cur = None
    bad = []
    for e in range(1, 90):
        cur = apply_incremental(cur, incs[e])
        f = fulls[e]
        d = []
        for k in ("epoch", "flags", "max_osd", "osd_state", "osd_weight", "affinity", "pg_temp", "primary_temp",
                  "pg_upmap", "pg_upmap_items", "pg_upmap_primaries", "pool_max", "pool_name", "client_addrs"):
            if getattr(cur, k) != getattr(f, k):
                d.append(k)
        if set(cur.pools) != set(f.pools):
            d.append("poolset")
        else:
            for pid in cur.pools:
                for k, v in cur.pools[pid].__dict__.items():
                    if getattr(f.pools[pid], k, None) != v:
                        d.append("pool%d.%s" % (pid, k))
        if crush_struct(decode_crush(cur.crush_blob)) != crush_struct(osdmap_crush(f)):
            d.append("crush")
        if d:
            bad.append((e, d))
    res.check(g, "crush note 2.7 / osdmap.md 3.5: replaying incrementals 1..89 (steps 1-18) reproduces every stored full map: "
              "flags, max_osd resize, state XOR/destroy/new_up, weight side effect, affinity creation, pg_temp/primary_temp "
              "erase rules, upmap set-then-erase, new_pools last_change = epoch, crush replace",
              not bad, str(bad[:3]), 89)
    # what do the 89 epochs actually exercise?
    ex = dict(state_xor=sum(1 for i in incs.values() if i.new_state), pg_temp_set=sum(1 for i in incs.values() for v in i.new_pg_temp.values() if v),
              pg_temp_erase=sum(1 for i in incs.values() for v in i.new_pg_temp.values() if not v),
              primary_temp=sum(len(i.new_primary_temp) for i in incs.values()),
              upmap=sum(len(i.new_pg_upmap) + len(i.old_pg_upmap) for i in incs.values()),
              upmap_items=sum(len(i.new_pg_upmap_items) + len(i.old_pg_upmap_items) for i in incs.values()),
              affinity=sum(len(i.new_primary_affinity) for i in incs.values()), crush_replace=sum(1 for i in incs.values() if i.crush),
              new_pools=sum(len(i.new_pools) for i in incs.values()), weight=sum(len(i.new_weight) for i in incs.values()),
              primary_temp_minus1=sum(1 for i in incs.values() for v in i.new_primary_temp.values() if v == -1),
              upmap_primary=sum(len(i.new_pg_upmap_primary) for i in incs.values()),
              destroy_branch=0)
    res.info(g, "replay coverage", str(ex))


# ---- D: placement against the oracles ----------------------------------------------------------------------------


def parse_crushtool_file(path):
    out = []
    for line in open(path):
        m = re.match(r"CRUSH rule (\d+) x (\d+) \[(.*)\]\s*$", line)
        if m:
            out.append((int(m.group(1)), int(m.group(2)), [int(v) for v in m.group(3).split(",") if v != ""]))
    return out


def grp_place(res, C, ctx):
    g = "D.placement"
    m = ctx["full42"]
    cm = osdmap_crush(m)
    # 1 ceph osd map
    n = bad_up = bad_pg = bad_ps = 0
    firsts = []
    by_kind = {"winrbd": 0, ".mgr": 0, "ns": 0}
    cesu = 0
    ps_masked_equal = True
    lens = set()
    for line in open(C + "/gt/osd-map-all.jsonl"):
        d = json.loads(line)
        rs = d["result"]
        pid = rs["pool_id"]
        name = oracle_bytes(d["object"])
        ns = oracle_bytes(d["nspace"]) if d["nspace"] else b""
        if any(ord(ch) > 0xFFFF for ch in d["object"]):
            cesu += 1
        got = map_object(m, pid, name, ns)
        n += 1
        by_kind["ns" if ns else (".mgr" if pid == 1 else "winrbd")] += 1
        lens.add(len(name))
        if got["ps"] != int(rs["raw_pgid"].split(".")[1], 16):
            bad_ps += 1
            firsts.append(("ps", d["object"], hex(got["ps"]), rs["raw_pgid"]))
        if "%d.%x" % (pid, got["seed"]) != rs["pgid"]:
            bad_pg += 1
            firsts.append(("pg", d["object"], got["seed"], rs["pgid"]))
        if (got["up"], got["up_primary"], got["acting"], got["acting_primary"]) != (rs["up"], rs["up_primary"], rs["acting"], rs["acting_primary"]):
            bad_up += 1
            firsts.append(("up", d["object"], got["up"], rs["up"]))
        pool = m.pools[pid]
        if pool_pps(pool, pid, got["ps"]) != got["pps"]:
            ps_masked_equal = False
    res.check(g, "3.1/3.2 object -> ps (rjenkins, 0x1f namespace rule) equals `ceph osd map` raw pg for %d names (%s; lengths 1..%d; "
              "incl. non-ASCII and namespaces)" % (n, by_kind, max(lens)), bad_ps == 0, str(firsts[:3]), n)
    res.check(g, "3.2 step 1: stable_mod against pg_num gives the printed pgid for all names", bad_pg == 0, "", n)
    res.check(g, "3.3-3.7 whole pipeline: up, up_primary, acting, acting_primary equal `ceph osd map` for all names (CRUSH, straw2, "
              "choose firstn, is_out, up/acting)", bad_up == 0, str(firsts[:3]), n)
    res.check(g, "3.2 pps computed from the full 32-bit ps equals pps computed from the pg_num-masked seed (all names)", ps_masked_equal, "", n)
    res.info(g, "oracle quirk", "%d name(s) with a code point above U+FFFF: `ceph osd map` hashed the CESU-8 form (each surrogate half as "
             "3 UTF-8 bytes), not the UTF-8 bytes; our result matches only with that form. A real client hashes the bytes it sends." % cesu)
    # exhaustive-ish check of 'masking first gives the same pps'
    bad = 0
    tot = 0
    for pg_num in range(1, 141):
        pm = (1 << cbits(pg_num - 1)) - 1
        for pgp in range(1, pg_num + 1):
            qm = (1 << cbits(pgp - 1)) - 1
            for ps in list(range(0, 40)) + [0x7fffffff, 0x80000000, M32, 0x12345678, 0xdeadbeef]:
                a = stable_mod(ps, pgp, qm)
                b = stable_mod(stable_mod(ps, pg_num, pm), pgp, qm)
                tot += 1
                bad += a != b
    res.check(g, "3.2 step 2 claim: with pgp_num <= pg_num the order (mask by pg_num first or not) does not change the pgp stable_mod "
              "(pg_num 1..140, all pgp_num, 45 ps values)", bad == 0, "%d mismatches" % bad, tot)
    # 2 crushtool
    w = [0x10000] * cm.max_devices
    files = sorted(glob.glob(C + "/gt/crushtool-tests/rule*.x0-9999*.txt"))
    tot = bad = 0
    for f in files:
        base = os.path.basename(f)
        mm = re.match(r"rule(\d+)\.rep(\d+)\.x0-9999(?:\.pool(\d+))?\.txt", base)
        R, NR, P = int(mm.group(1)), int(mm.group(2)), mm.group(3)
        rows = parse_crushtool_file(f)
        fb = 0
        for rr, x, exp in rows:
            xin = hash2(x, int(P)) if P else x
            got = do_rule(cm, R, xin, NR, w)
            tot += 1
            if got != exp or rr != R:
                fb += 1
        bad += fb
        res.check(g, "C2 crushtool %s: %d mappings (x 0..9999, rule %d, num-rep %d%s)" % (base, len(rows), R, NR,
                  ", --pool-id %s: hash2(x,pool) applied by the tool" % P if P else ""), fb == 0 and len(rows) == 10000,
                  "%d mismatches" % fb, len(rows))
    res.info(g, "C2 total", "%d crushtool mappings compared, %d mismatches" % (tot, bad))
    # 3 osdmaptool dump-all
    for pool in (1, 2):
        f = C + "/gt/osdmaptool-test-map-pgs-dump-all.pool%d.txt" % pool
        rows = 0
        mism = []
        for line in open(f):
            mt = re.match(r"(\d+)\.([0-9a-f]+) raw \(\[(.*?)\], p(-?\d+)\) up \(\[(.*?)\], p(-?\d+)\) acting \(\[(.*?)\], p(-?\d+)\)", line)
            if not mt:
                continue
            rows += 1
            pg = (int(mt.group(1)), int(mt.group(2), 16))
            L = lambda s: [int(v) for v in s.split(",") if v != ""]
            exp = (L(mt.group(3)), int(mt.group(4)), L(mt.group(5)), int(mt.group(6)), L(mt.group(7)), int(mt.group(8)))
            r = pg_mapping(m, pg[0], pg[1])
            mine = (r["raw"], _first_non_none(r["raw"]), r["up"], r["up_primary"], r["acting"], r["acting_primary"])
            if mine != exp:
                mism.append((pg, mine, exp))
        res.check(g, "C3 osdmaptool --test-map-pgs-dump-all pool %d: %d PGs, raw/up/acting + primaries" % (pool, rows), rows > 0 and not mism,
                  str(mism[:2]), rows)
    # test-map-object
    txt = open(C + "/gt/osdmaptool-test-map-object.txt").read()
    cnt = 0
    mism = []
    for mt in re.finditer(r"--test-map-object (\S+) --pool (\d+)\n.*?\n object '.*?' -> (\d+)\.([0-9a-f]+) -> \[(.*?)\]", txt, re.S):
        o = map_object(m, int(mt.group(2)), mt.group(1).encode())
        cnt += 1
        if ("%d.%x" % (int(mt.group(3)), o["seed"]), o["acting"]) != ("%d.%s" % (int(mt.group(3)), mt.group(4)), [int(v) for v in mt.group(5).split(",") if v]):
            mism.append(mt.group(1))
    res.check(g, "C4 osdmaptool --test-map-object (%d objects incl. the note's `foo`, rbd_directory, rbd_header.<id>)" % cnt, cnt >= 4 and not mism, str(mism), cnt)
    # 4: invariants over all stored maps (no oracle)
    inv_bad = []
    tot = 0
    for e, f in sorted(ctx["fulls"].items()):
        if not f.pools or osdmap_crush(f) is None:
            continue
        for pid, p in f.pools.items():
            if p.type != 1 or p.pg_num == 0:
                continue
            for s in range(p.pg_num):
                try:
                    r = pg_mapping(f, pid, s)
                except Unmappable:
                    continue
                tot += 1
                ok = len(set(r["up"])) == len(r["up"]) and all(_up(f, o) for o in r["up"]) and len(r["raw"]) <= p.size
                ok = ok and all(f.osd_weight[o] != 0 for o in r["raw_after_upmap"] if (pid, s) not in f.pg_upmap and (pid, s) not in f.pg_upmap_items and _valid(f, o))
                ok = ok and (not r["up"] or r["up_primary"] in r["up"] or (pid, s) in f.primary_temp)
                if not ok:
                    inv_bad.append((e, pid, s, r))
    res.check(g, "3.7 invariants over every PG of every stored map (89 epochs): up has no duplicates and only up OSDs, no zero-weight OSD "
              "in raw without upmap, primary is a member (no oracle; sanity only)", not inv_bad, str(inv_bad[:1]), tot)


def grp_semantics(res, C, ctx):
    """3.7 steps 3,5,6,7 on states that exist in the stored maps; NO oracle output exists for these maps, so these are
    expectations derived from what the admin command did, reported as consistency checks (not as oracle matches)."""
    g = "D2.semantics (consistency only, no oracle)"
    F = ctx["fulls"]
    out = {}
    # find epochs by content
    e_items = [e for e, f in F.items() if f.pg_upmap_items]
    e_full = [e for e, f in F.items() if f.pg_upmap]
    e_ptemp = [e for e, f in F.items() if f.primary_temp]
    e_pgtemp = [e for e, f in F.items() if f.pg_temp]
    e_aff = [e for e, f in F.items() if f.affinity is not None and any(a != 0x10000 for a in f.affinity)]
    e_out = [e for e, f in F.items() if f.max_osd == 3 and f.osd_weight and f.osd_weight[2] == 0 and f.osd_state[2] & 1]
    e_down = [e for e, f in sorted(F.items(), reverse=True) if f.max_osd == 3 and f.osd_state[2] & 1 and not f.osd_state[2] & 2 and f.osd_weight[2]]
    out["epochs"] = dict(upmap_items=e_items, upmap=e_full, primary_temp=e_ptemp, pg_temp=e_pgtemp[:4], affinity=e_aff,
                         out=e_out, down=e_down[:4])
    res.info(g, "stored states available", str({k: (v if len(v) < 6 else v[:6] + ["..."]) for k, v in out["epochs"].items()}))
    base = F[42]
    cmb = osdmap_crush(base)
    # 2.6: a rule that takes the device-class shadow root maps like the plain root (same hash inputs); synthetic rule, consistency only
    shadow_root = cmb.class_bucket[-1][next(iter(cmb.class_bucket[-1]))]
    rr = Rule()
    rr.ruleset, rr.type, rr.min_size, rr.max_size, rr.steps = 2, 1, 1, 100, [(1, shadow_root, 0), (2, 0, 0), (4, 0, 0)]
    cms = decode_crush(base.crush_blob)
    cms.rules = list(cms.rules) + [rr]
    cms.max_rules = len(cms.rules)
    w3 = [0x10000] * 3
    diff = sum(1 for x in range(3000) for n in (1, 2, 3) if do_rule(cms, 2, x, n, w3) != do_rule(cms, 1, x, n, w3))
    res.check(g, "2.6 consistency: a (synthetic) rule 'take %d (default~hdd shadow root)' maps exactly like 'take -1' for 9000 (x, num-rep) pairs "
              "- the shadow tree reuses the device ids as hash inputs" % shadow_root, diff == 0, "%d differences" % diff, 9000)
    pre = pg_mapping(base, 1, 0)
    ok = pre["up"] == [1, 0]
    res.check(g, "baseline pg 1.0 up == [1,0] (matches 'pg 1.0 up before: [1,0]' in the capture log)", ok, str(pre["up"]), 1)
    if e_items:
        f = F[e_items[0]]
        r = pg_mapping(f, 1, 0)
        res.check(g, "3.7 step 3: pg_upmap_items 1.0 [0->2] on up [1,0] gives up [1,2]", r["up"] == [1, 2] and r["up_primary"] == 1, str(r["up"]), 1)
    if e_full:
        f = F[e_full[0]]
        r = pg_mapping(f, 1, 0)
        res.check(g, "3.7 step 3: pg_upmap 1.0 [0,2] gives up [0,2]", r["up"] == [0, 2] and r["up_primary"] == 0, str(r["up"]), 1)
    if e_ptemp:
        f = F[e_ptemp[0]]
        r = pg_mapping(f, 1, 0)
        res.check(g, "3.7 step 7: primary_temp 1.0 -> 0 with NO pg_temp: acting == up, acting_primary == 0 while up_primary stays %d"
                  % r["up_primary"], r["acting"] == r["up"] and r["acting_primary"] == 0 and r["up_primary"] != 0, str(r), 1)
    if e_pgtemp:
        ok = True
        det = []
        for e in e_pgtemp:
            f = F[e]
            for pg, lst in f.pg_temp.items():
                r = pg_mapping(f, pg[0], pg[1])
                want = [o for o in lst if _up(f, o)]
                good = r["acting"] == want and r["acting_primary"] == (want[0] if want else r["up_primary"])
                ok &= good
                if not good:
                    det.append((e, pg, r))
        res.check(g, "3.7 steps 6-7: pg_temp members (down/non-existent dropped) become acting, first one is acting primary, in %d stored maps" % len(e_pgtemp), ok, str(det[:1]), len(e_pgtemp))
    if e_out:
        f = F[e_out[0]]
        bad = 0
        for pid, p in f.pools.items():
            for s in range(p.pg_num):
                r = pg_mapping(f, pid, s)
                bad += 2 in r["raw"]
        res.check(g, "3.5/3.6: osd.2 with weight 0 never appears in any raw list (is_out, step 1-2) in epoch %d" % e_out[0], bad == 0, "%d" % bad, 1)
    if e_down:
        f = F[e_down[0]]
        bad = 0
        kept = 0
        for pid, p in f.pools.items():
            for s in range(p.pg_num):
                r = pg_mapping(f, pid, s)
                bad += 2 in r["up"] or 2 in r["acting"]
                kept += 2 in r["raw"]
        res.check(g, "3.7 step 2/4: down osd.2 stays in the raw list (%d PGs) but never in up/acting (epoch %d)" % (kept, e_down[0]), bad == 0 and kept > 0, "%d" % bad, 1)
    if e_aff:
        f = F[e_aff[0]]
        moved = 0
        tot = 0
        det = []
        for pid, p in f.pools.items():
            for s in range(p.pg_num):
                r = pg_mapping(f, pid, s)
                tot += 1
                # primary affinity must not change the SET of OSDs, only the order (replicated)
                f2 = clone_map(f)
                f2.affinity = None
                r2 = pg_mapping(f2, pid, s)
                if sorted(r["up"]) != sorted(r2["up"]):
                    det.append((pid, s))
                if r["up_primary"] != r2["up_primary"]:
                    moved += 1
        res.check(g, "3.7 step 5: affinity (osd.1 = 0.5) only reorders, never changes the member set; %d of %d PGs change primary" % (moved, tot),
                  not det, str(det[:2]), tot)
        res.info(g, "affinity", "no oracle for which PGs change primary: the captures hold no mapping taken at an epoch with a non-default affinity")


# ---- F: in-tree known-answer tests ---------------------------------------------------------------------------------


def parse_t_file(path, testdir):
    import shlex
    lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    cmdline = None
    exp = []
    nr = None
    lastx = None
    for ln in lines:
        if ln.startswith("  $ "):
            if cmdline is not None:
                break
            cmdline = ln[4:].replace("$TESTDIR", testdir)
            continue
        mt = re.match(r"  CRUSH rule (\d+) x (\d+) \[(.*)\]$", ln)
        if mt:
            x = int(mt.group(2))
            if lastx is None or x <= lastx:
                nr = 1 if nr is None else nr + 1
            lastx = x
            exp.append((nr, x, int(mt.group(1)), [int(v) for v in mt.group(3).split(",") if v != ""]))
    toks = shlex.split(cmdline)
    minrep = 1
    for k, t in enumerate(toks):
        if t in ("--min-rep", "--num-rep"):
            minrep = int(toks[k + 1])
    exp = [(nr + minrep - 1, x, rr, e) for nr, x, rr, e in exp]
    return toks, exp


def grp_tree(res, ref, maxx, ctx):
    g = "F.tree-known-answers"
    td = os.path.join(ref, "src/test/cli/crushtool")
    files = ["test-map-jewel-tunables.t", "test-map-hammer-tunables.t", "test-map-legacy-tunables.t",
             "test-map-bobtail-tunables.t", "test-map-firefly-tunables.t", "test-map-tries-vs-retries.t",
             "test-map-vary-r-0.t", "test-map-vary-r-1.t", "test-map-vary-r-2.t", "test-map-vary-r-3.t",
             "test-map-vary-r-4.t"]
    algs_seen = set()
    feats = set()
    grand = 0
    for fn in files:
        p = os.path.join(td, fn)
        if not os.path.exists(p):
            res.info(g, fn, "missing in reference tree")
            continue
        toks, exp = parse_t_file(p, td)
        opts = {"weights": {}}
        i = 1
        while i < len(toks):
            t = toks[i]
            if t == "-i":
                opts["map"] = toks[i + 1]; i += 2
            elif t == "--rule":
                opts["rule"] = int(toks[i + 1]); i += 2
            elif t == "--weight":
                opts["weights"][int(toks[i + 1])] = int(float(toks[i + 2]) * 0x10000); i += 3
            elif t == "--min-rep":
                opts["min"] = int(toks[i + 1]); i += 2
            elif t == "--max-rep":
                opts["max"] = int(toks[i + 1]); i += 2
            elif t.startswith("--set-"):
                opts[t] = int(toks[i + 1]); i += 2
            else:
                i += 1
        cm = decode_crush(read_bytes(opts["map"]))
        for b in cm.buckets:
            if b is not None:
                algs_seen.add(b.alg)
        tun = dict(cm.tun)
        for k, tk in (("--set-choose-local-tries", "choose_local_tries"), ("--set-choose-local-fallback-tries", "choose_local_fallback_tries"),
                      ("--set-choose-total-tries", "choose_total_tries"), ("--set-chooseleaf-descend-once", "chooseleaf_descend_once"),
                      ("--set-chooseleaf-vary-r", "chooseleaf_vary_r"), ("--set-chooseleaf-stable", "chooseleaf_stable")):
            if k in opts:
                tun[tk] = opts[k]
        inbucket = set()
        for b in cm.buckets:
            if b is not None:
                inbucket.update(it for it in b.items if it >= 0)
        weights = [0x10000 if d in inbucket else 0 for d in range(cm.max_devices)]
        for d, wv in opts["weights"].items():
            if d < len(weights):
                weights[d] = wv
        R = opts.get("rule", exp[0][2] if exp else 0)
        rule = cm.rules[R]
        for op, a1, a2 in rule.steps:
            if op == 6: feats.add("chooseleaf_firstn")
            if op == 2: feats.add("choose_firstn")
            if op in (8, 9, 10, 11, 12, 13): feats.add("rule SET_* step %d" % op)
        if tun["choose_local_tries"] or tun["choose_local_fallback_tries"]:
            feats.add("legacy local-retry tunables set")
        if tun["chooseleaf_vary_r"]: feats.add("vary_r=%d" % tun["chooseleaf_vary_r"])
        if tun["chooseleaf_stable"]: feats.add("stable")
        if tun["chooseleaf_descend_once"]: feats.add("descend_once")
        total = bad = 0
        first_bad = None
        for nr, x, rr, e in exp:
            if x >= maxx:
                continue
            try:
                got = do_rule(cm, R, x, nr, weights, None, tun)
            except Unsupported as ex:
                got = "unsupported %s" % ex
            total += 1
            if got != e:
                bad += 1
                if first_bad is None:
                    first_bad = (nr, x, got, e)
        grand += total
        algs = sorted({b.alg for b in cm.buckets if b is not None})
        res.check(g, "%s: map %s, rule %d, bucket algs %s, %d mappings (x < %d)" % (fn, os.path.basename(opts["map"]), R, algs, total, maxx),
                  bad == 0 and total > 0, "%d mismatches, first %s" % (bad, first_bad), total)
    # decode every binary map in the tree (legacy blobs without the trailing groups included)
    seen = {}
    fails = []
    shapes = {}
    for f in sorted(glob.glob(td + "/*.crushmap")):
        try:
            cm = decode_crush(read_bytes(f))
        except CheckError as ex:
            fails.append((os.path.basename(f), str(ex)))
            continue
        shapes[os.path.basename(f)] = "".join(x if len(x) == 1 else "+" for x in cm.present)
        for b in cm.buckets:
            if b is not None:
                seen[b.alg] = seen.get(b.alg, 0) + 1
    res.check(g, "2.2/2.4 the blob decoder accepts all %d binary maps shipped in the tree, including old ones that end before the "
              "tunable / class / choose_args groups (legacy defaults of 2.5 apply)" % len(shapes), not fails and len(shapes) > 0, str(fails), len(shapes))
    res.info(g, "bucket algorithms present in the tree's binary maps", str(seen) + "  (1 uniform, 2 list, 3 tree, 4 straw, 5 straw2); trailing groups present per map: " + str(shapes))
    jw = decode_crush(read_bytes(os.path.join(td, "test-map-jewel-tunables.crushmap")))
    ha = decode_crush(read_bytes(os.path.join(td, "test-map-hammer-tunables.crushmap")))
    res.check(g, "6 Q14: test-map-jewel-tunables.crushmap decodes with allowed_bucket_algs 0x1600 and chooseleaf_stable 1; the hammer map "
              "decodes with 0x16 (harmless oddity of the test file, not of the format)",
              (jw.tun["allowed_bucket_algs"], jw.tun["chooseleaf_stable"], ha.tun["allowed_bucket_algs"]) == (0x1600, 1, 0x16),
              str((hex(jw.tun["allowed_bucket_algs"]), jw.tun["chooseleaf_stable"], hex(ha.tun["allowed_bucket_algs"]))), 3)
    res.info(g, "coverage", "step 8 branches during the known-answer runs: %s; permutation fallback (3.4.5 / 3.6 step 4) used %d times; bucket algs decoded/exercised: %s (1 uniform, 2 list, 3 tree, 4 straw, 5 straw2); features: %s"
             % (RETRY_HITS, PERM_CALLS[0], sorted(algs_seen), sorted(feats)))


# ---- E: pcaps ------------------------------------------------------------------------------------------------------


def osd_ports(f):
    ports = {}
    for osd, av in enumerate(f.client_addrs):
        for a in av:
            if a[0] == 2:
                ports[a[3]] = osd
    return ports


def map_for_epoch(fulls, e):
    e = max(1, min(e, max(fulls)))
    return fulls[e], e


def grp_pcap(res, C, ctx, quick):
    g = "E.pcap"
    fulls = ctx["fulls"]
    pcs = sorted(glob.glob(C + "/pcap/*.pcap"))
    T = dict(pcaps=0, conns=0, streams=0, frames=0, crc=0, crc_bad=0, tag_bad=0, epi_bad=0, len_bad=0, secure_streams=0,
            tails=0, retrans=0, gaps=0, banner_bad=0, mosdmap=0, mosdop=0, mosdop_ok=0, mosdop_unknown_port=0,
            maps_full=0, maps_inc=0, bytes_crc=0, empty=0, holes=0)
    sec_expected = set()
    sec_seen = set()
    mosdmap_ver = set()
    mosdop_ver = set()
    bad_ops = []
    fm_bad = []
    crush_embedded_msr = []
    inc_msr = []
    map_equal = [0, 0]
    inc_equal = [0, 0]
    op_samples = []
    op_epochs = set()
    unknown_port_detail = []
    hole_streams = []
    op_seen = set()
    for pc in pcs:
        name = os.path.basename(pc)[:-5]
        T["pcaps"] += 1
        conns = pcap_connections(pc)
        for cn in conns:
            T["conns"] += 1
            T["retrans"] += cn["retrans"]
            for d in ("c2s", "s2c"):
                if not cn[d]:
                    T["empty"] += 1  # connection refused / reset before any payload
                    continue
                st = parse_msgr2_stream(cn[d], quick)
                T["streams"] += 1
                if cn["gap_dir"][d]:
                    T["holes"] += 1
                    hole_streams.append((name, cn["server_port"], d))
                    st.tail = 0  # parsing legitimately stops at the capture hole
                if not st.banner_ok:
                    T["banner_bad"] += 1
                    continue
                T["frames"] += st.frames
                T["crc"] += st.crc_checked
                T["crc_bad"] += st.crc_bad
                T["tag_bad"] += st.tag_bad
                T["epi_bad"] += st.epi_bad
                T["len_bad"] += st.len_bad
                T["tails"] += 1 if st.tail else 0
                T["bytes_crc"] += st.bytes_crc
                if st.secure_at is not None:
                    T["secure_streams"] += 1
                    sec_seen.add(name)
                if d == "s2c" and cn["server_port"] == 3300:
                    for hd, front, mid, data in st.messages:
                        if hd["type"] == 41:
                            T["mosdmap"] += 1
                            mosdmap_ver.add((hd["version"], hd["compat"]))
                            mm = decode_mosdmap(front, hd["version"])
                            if mm["left"]:
                                fm_bad.append((name, "trailing bytes in MOSDMap"))
                            for e, blob in mm["maps"].items():
                                T["maps_full"] += 1
                                fmap = decode_osdmap(blob)
                                if not fmap.crc_ok:
                                    fm_bad.append((name, e, "crc"))
                                crush_embedded_msr.append(osdmap_crush(fmap).has_msr_pair)
                                if e in fulls:
                                    map_equal[1] += 1
                                    map_equal[0] += blob == read_bytes(C + "/gt3/full/full.%05d.bin" % e)
                            for e, blob in mm["incs"].items():
                                T["maps_inc"] += 1
                                inc = decode_incremental(blob)
                                if inc.inc_crc_ok is False:
                                    fm_bad.append((name, e, "inc crc"))
                                if inc.crush:
                                    inc_msr.append(decode_crush(inc.crush).has_msr_pair)
                                if e in fulls:
                                    inc_equal[1] += 1
                                    inc_equal[0] += blob == read_bytes(C + "/gt3/inc/inc.%05d.bin" % e)
                if d == "c2s" and cn["server_port"] != 3300 and cn["server_port"] < 7000 and cn["server_port"] >= 6800:
                    for hd, front, mid, data in st.messages:
                        if hd["type"] == 42:
                            T["mosdop"] += 1
                            mosdop_ver.add((hd["version"], hd["compat"]))
                            try:
                                op = decode_mosdop(front, hd["version"])
                            except CheckError as ex:
                                bad_ops.append((name, "decode", str(ex)))
                                continue
                            if op["left"]:
                                bad_ops.append((name, "trailing", op["left"]))
                            if not op["oid"]:
                                continue
                            f, used = map_for_epoch(fulls, op["epoch"])
                            op_epochs.add(op["epoch"])
                            pool = f.pools.get(op["pool"])
                            if pool is None:
                                bad_ops.append((name, "pool", op["pool"]))
                                continue
                            ps = object_ps(pool, op["oid"], op["nspace"], op["key"])
                            seed = stable_mod(ps, pool.pg_num, pool.pg_num_mask)
                            r = pg_mapping(f, op["pool"], seed)
                            ports = osd_ports(f)
                            tgt = ports.get(cn["server_port"])
                            problems = []
                            if op["hash"] != ps: problems.append("hash %x != %x" % (op["hash"], ps))
                            if op["seed"] != seed: problems.append("pgid seed")
                            if op["oloc_pool"] != op["pool"] or op["oloc_hash"] != -1 or op["shard"] != -1: problems.append("oloc/shard")
                            if tgt is None:
                                T["mosdop_unknown_port"] += 1
                                unknown_port_detail.append((name, cn["server_port"], op["epoch"]))
                            elif tgt != r["acting_primary"]:
                                problems.append("target osd %s != acting primary %s" % (tgt, r["acting_primary"]))
                            if problems:
                                bad_ops.append((name, op["oid"], problems))
                            else:
                                T["mosdop_ok"] += 1
                                key = (op["oid"], op["nspace"], op["pool"], tgt)
                                if key not in op_seen and len(op_samples) < 400:
                                    op_seen.add(key)
                                    op_samples.append(dict(oid=op["oid"].decode("latin-1"), nspace=op["nspace"].decode("latin-1"),
                                                           pool=op["pool"], hash=op["hash"], seed=seed, epoch=op["epoch"],
                                                           osd=tgt, acting=r["acting"], pcap=name))
    ctx["op_samples"] = op_samples
    n_ok = T["frames"]
    res.check(g, "msgr2.md 2.2: %d pcaps, %d TCP connections reassembled by sequence number (%d retransmitted segments dropped); every "
              "non-empty stream starts with the 26-byte banner `ceph v2\\n`, payload length 16" % (T["pcaps"], T["conns"], T["retrans"]),
              T["banner_bad"] == 0, "banner problems %d" % T["banner_bad"], T["streams"])
    res.info(g, "capture quality", "%d empty streams (refused connections); %d streams contain a capture hole (packets the capture itself lost, "
             "parsing stops there): %s" % (T["empty"], T["holes"], hole_streams))
    res.check(g, "msgr2.md 2.3/2.6.1/2.5: every preamble CRC, inline segment-0 CRC, epilogue late_status and per-segment CRC slot "
              "(incl. 0xFFFFFFFF for empty used segments and 0 for unused ones) of all %d crc-mode frames verifies "
              "(%d CRC values checked, %.1f MB of segment data hashed%s)" % (T["frames"], T["crc"], T["bytes_crc"] / 1e6, ", segments >64 KiB skipped (--quick)" if quick else ""),
              T["crc_bad"] == 0 and T["tag_bad"] == 0 and T["epi_bad"] == 0 and T["len_bad"] == 0,
              "bad crc %d, bad tag/segment rules %d, bad late_status %d, bad header2 length %d" % (T["crc_bad"], T["tag_bad"], T["epi_bad"], T["len_bad"]), T["crc"])
    exp_sec = {n for n in (os.path.basename(p)[:-5] for p in pcs) if "-sec-" in n or "-def-" in n}
    res.check(g, "msgr2.md 2.6.3: preamble CRC fails (= secure framing starts) only in the sec/def sessions: %d pcaps with %d secure streams; "
              "every crc-mode pcap parses to the last byte" % (len(sec_seen), T["secure_streams"]),
              sec_seen == exp_sec and T["tails"] == 0, "seen %s, expected %s, streams with an unparsed tail %d" % (sorted(sec_seen), sorted(exp_sec), T["tails"]), T["streams"])
    res.check(g, "osdmap.md 2.3: %d MOSDMap messages (header version/compat %s) decode with no trailing bytes; %d full maps and %d incrementals inside"
              % (T["mosdmap"], sorted(mosdmap_ver), T["maps_full"], T["maps_inc"]), T["mosdmap"] > 0 and not fm_bad, str(fm_bad[:2]), T["mosdmap"])
    res.check(g, "osdmap.md 2.3/2.8: full maps delivered inside MOSDMap are byte-identical to the monitor's stored map of that epoch (%d/%d); "
              "embedded incrementals identical to the stored ones (%d/%d)" % (map_equal[0], map_equal[1], inc_equal[0], inc_equal[1]),
              map_equal[0] == map_equal[1] and inc_equal[0] == inc_equal[1], "", map_equal[1] + inc_equal[1])
    res.check(g, "crush 2.1 [C1/C7/13]: every CRUSH blob inside a full OSDMap received by the stock client has NO MSR pair (%d of %d)"
              % (sum(1 for x in crush_embedded_msr if not x), len(crush_embedded_msr)), crush_embedded_msr and not any(crush_embedded_msr), "", len(crush_embedded_msr))
    if inc_msr:
        res.check(g, "crush 2.1: CRUSH blobs inside incrementals received on the wire carry the MSR pair (%d of %d)" % (sum(inc_msr), len(inc_msr)),
                  all(inc_msr), "", len(inc_msr))
    res.check(g, "crush 3.1 step 5 / osd-ops 2.2-2.3: %d MOSDOp frames (header version/compat %s) from the stock client: hash field == full 32-bit "
              "rjenkins ps (key/namespace rules), pgid seed == stable_mod(ps, pg_num), shard -1, oloc hash -1, and the TCP connection "
              "goes to OSD acting_primary of our pipeline" % (T["mosdop"], sorted(mosdop_ver)),
              T["mosdop"] > 0 and not bad_ops, "%s" % (bad_ops[:2],), T["mosdop_ok"])
    if T["mosdop_unknown_port"]:
        res.info(g, "MOSDOp connections to a port not in the map used", "%d (e.g. %s): target comparison skipped for those" % (T["mosdop_unknown_port"], unknown_port_detail[:2]))
    res.info(g, "MOSDOp osdmap_epoch values seen", str(sorted(op_epochs)))
    res.info(g, "pcap totals", str(T))


# ---- vectors ---------------------------------------------------------------------------------------------------------


def grp_emit(res, C, ctx, outdir):
    os.makedirs(outdir, exist_ok=True)
    m = ctx["full42"]
    cm = ctx["crush_get"]

    def dump(name, obj):
        """one JSON member per line; list elements and sub-objects of a member on one line each (small, diff-friendly)"""
        cj = lambda v: json.dumps(v, separators=(", ", ": "))
        lines = []
        for k, v in obj.items():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                lines.append("  %s: [\n    %s\n  ]" % (cj(k), ",\n    ".join(cj(x) for x in v)))
            elif isinstance(v, dict) and v and all(isinstance(x, dict) for x in v.values()):
                lines.append("  %s: {\n    %s\n  }" % (cj(k), ",\n    ".join("%s: %s" % (cj(a), cj(b)) for a, b in v.items())))
            else:
                lines.append("  %s: %s" % (cj(k), cj(v)))
        with open(os.path.join(outdir, name), "w") as f:
            f.write("{\n" + ",\n".join(lines) + "\n}\n")

    def dumphex(name, b, width=64):
        with open(os.path.join(outdir, name), "w") as f:
            h = b.hex()
            for i in range(0, len(h), width * 2):
                f.write(h[i:i + width * 2] + "\n")

    # hashes
    names = [b"", b"a", b"foo", b"abcdefghijkl", b"abcdefghijklm", b"rbd_directory", b"rbd_id.myimage", b"rbd_header.1234abcd5678",
             b"rbd_data.1234abcd5678.0000000000000000", b"ns\x1ffoo"]
    dump("hash-vectors.json", {
        "provenance": "arithmetic of crush-and-placement.md 5.1, produced by harness/tools/crush_check.py (written from the note) and "
                      "agreeing with the reviewer's compile of the pinned C sources; the placement-expected.json file below is the live-cluster oracle",
        "rjenkins_str": [{"input_hex": n.hex(), "rjenkins": "%08x" % str_hash_rjenkins(n), "linux_dcache": "%08x" % str_hash_linux(n)} for n in names],
        "crush_hash": ([{"fn": "hash2", "args": list(a), "result": "%08x" % hash2(*a)} for a in ((0, 0), (1, 2), (0x7fc1f406, 1), (M32, M32))] +
                       [{"fn": "hash3", "args": list(a), "result": "%08x" % hash3(*a)} for a in ((0, 0, 0), (1, 2, 3), (0x12345678, M32, 7), (5, M32, 0))] +
                       [{"fn": "hash4", "args": list(a), "result": "%08x" % hash4(*a)} for a in ((0, 0, 0, 0), (1, 2, 3, 4))]),
        "stable_mod": [{"x": a, "b": b, "mask": c, "result": stable_mod(a, b, c)} for a, b, c in
                       ((0x7fc1f406, 12, 15), (0x7fc1f40e, 12, 15), (0x7fc1f40e, 16, 15), (M32, 100, 127), (100, 100, 127), (12345, 1, 0))],
        "pps_hashpspool": [{"pool": p, "seed": s, "pps": "%08x" % hash2(s, p)} for p, s in ((1, 6), (2, 6), (1, 14))],
        "crush_ln": [{"u": u, "result": "%012x" % crush_ln(u)} for u in (0, 1, 2, 255, 256, 0x1234, 0x7fff, 0x8000, 0xfffe, 0xffff)],
        "crush_ln_note": "crush_ln needs the two tables of crush_ln_table.h; this repository does not carry them (licensing question 7.1). "
                         "The harness loads them from the reference tree at run time."})
    # crush blobs
    dumphex("crush-getcrushmap.hex", read_bytes(C + "/gt/crush.bin"))
    dumphex("crush-embedded-in-osdmap.hex", m.crush_blob)
    dump("crush-blob.expected.json", {
        "provenance": "lab cluster, Ceph v20.2.5, epoch 42; both blobs decode to the same map except the trailing MSR pair "
                      "(msr_descents/msr_collision_tries = 100/100 present only in the getcrushmap form)",
        "max_buckets": cm.max_buckets, "max_rules": cm.max_rules, "max_devices_wire": cm.wire_max_devices, "max_devices_recomputed": cm.max_devices,
        "buckets": [{"slot": b.slot, "id": b.id, "type": b.type, "alg": b.alg, "hash": b.hash, "weight": b.weight, "items": b.items,
                     "item_weights": b.item_weights, "name": cm.name_map.get(b.id)} for b in cm.buckets if b],
        "rules": [{"slot": i, "type": r.type, "min_size": r.min_size, "max_size": r.max_size, "steps": [list(s) for s in r.steps]}
                  for i, r in enumerate(cm.rules) if r],
        "tunables": {k: v for k, v in cm.tun.items()}, "class_map": {str(k): v for k, v in cm.class_map.items()},
        "class_name": {str(k): v for k, v in cm.class_name.items()}, "class_bucket": {str(k): {str(a): b for a, b in v.items()} for k, v in cm.class_bucket.items()},
        "type_map": {str(k): v for k, v in cm.type_map.items()}, "choose_args": {}})
    # osdmap summary (no fsid, uuids, addresses, blocklist)
    dump("osdmap-e42.placement-input.json", {
        "provenance": "client-visible placement inputs of the lab OSDMap at epoch 42 (fsid, osd uuids, addresses and blocklist left out on purpose); "
                      "the CRUSH blob is crush-embedded-in-osdmap.hex",
        "epoch": m.epoch, "max_osd": m.max_osd, "osd_state": m.osd_state, "osd_weight": m.osd_weight, "osd_primary_affinity": m.affinity,
        "pg_temp": [], "primary_temp": [], "pg_upmap": [], "pg_upmap_items": [], "pg_upmap_primaries": [],
        "pools": [{"id": pid, "name": m.pool_name[pid].decode(), "type": p.type, "size": p.size, "min_size": p.min_size, "crush_rule": p.crush_rule,
                   "object_hash": p.object_hash, "pg_num": p.pg_num, "pgp_num": p.pgp_num, "flags": p.flags,
                   "pg_num_mask": p.pg_num_mask, "pgp_num_mask": p.pgp_num_mask} for pid, p in sorted(m.pools.items())]})
    # ceph osd map oracle samples
    rows = []
    allrows = [json.loads(l) for l in open(C + "/gt/osd-map-all.jsonl")]
    pick = []
    seen_len = set()
    for d in allrows:
        o = d["object"]
        ln = len(oracle_bytes(o))
        take = (d["nspace"] is not None) and sum(1 for x in pick if x["nspace"]) < 12
        take = take or (ln not in seen_len and d["result"]["pool_id"] == 2 and d["nspace"] is None)
        take = take or (d["result"]["pool_id"] == 1 and sum(1 for x in pick if x["result"]["pool_id"] == 1) < 6)
        take = take or any(ord(ch) > 127 for ch in o) and sum(1 for x in pick if any(ord(ch) > 127 for ch in x["object"])) < 8
        take = take or o.startswith("rbd_") and sum(1 for x in pick if x["object"].startswith("rbd_")) < 30
        if take:
            seen_len.add(ln)
            pick.append(d)
    for d in pick:
        rs = d["result"]
        rows.append({"pool_id": rs["pool_id"], "object_hex": oracle_bytes(d["object"]).hex(), "nspace_hex": oracle_bytes(d["nspace"]).hex() if d["nspace"] else "",
                                          "raw_pgid": rs["raw_pgid"], "pgid": rs["pgid"], "up": rs["up"], "up_primary": rs["up_primary"],
                     "acting": rs["acting"], "acting_primary": rs["acting_primary"]})
    dump("placement-expected.json", {"provenance": "`ceph osd map -f json` on the lab cluster at epoch 42 (the same pipeline input as osdmap-e42.placement-input.json); "
                                                   "%d of 2194 names, chosen to cover every name length present, namespaces, non-ASCII bytes and the .mgr pool" % len(rows),
                                     "name_form": "object_hex / nspace_hex are the bytes the monitor hashed; a code point above U+FFFF reached it in CESU-8 form "
                                                  "(two 3-byte halves), see README", "cases": rows})
    # crushtool
    ct = {}
    for f in sorted(glob.glob(C + "/gt/crushtool-tests/rule*.x0-9999*.txt")):
        mm = re.match(r"rule(\d+)\.rep(\d+)\.x0-9999(?:\.pool(\d+))?\.txt", os.path.basename(f))
        rows2 = parse_crushtool_file(f)[:64]
        ct["rule%s.rep%s%s" % (mm.group(1), mm.group(2), ".pool" + mm.group(3) if mm.group(3) else "")] = {
            "rule": int(mm.group(1)), "num_rep": int(mm.group(2)), "pool_id_hash2_applied_by_tool": int(mm.group(3)) if mm.group(3) else None,
            "device_weights": [0x10000] * 3, "x_to_result": [r[2] for r in rows2]}
    dump("crushtool-mappings.json", {"provenance": "`crushtool --test --show-mappings` on crush-getcrushmap.hex, x = 0..63 of the 0..9999 run (all weights 1.0). "
                                                   "With pool_id set the tool maps x through hash2(x, pool_id) first", "runs": ct})
    # incrementals: client block only, fsid zeroed
    pick = {55: "new_primary_affinity osd.1", 57: "new_primary_affinity osd.1 back", 61: "new_pg_upmap_items 1.0", 63: "old_pg_upmap_items",
            65: "new_pg_upmap 1.0", 67: "old_pg_upmap", 69: "new_primary_temp 1.0", 71: "new_pg_temp 2.0", 82: "osd_state_xor osd.2 up",
            4: "crush replace (MSR form)"}
    incs = ctx["incs"]
    out = []
    for e, why in sorted(pick.items()):
        raw = read_bytes(C + "/gt3/inc/inc.%05d.bin" % e)
        i = incs[e]
        r = R(raw)
        r.u8(); r.u8(); r.u32()
        cv, cc, cend = env(r)
        blk = bytearray(raw[r.p - 6:cend])
        blk[6:22] = b"\x00" * 16  # fsid
        out.append({"epoch": e, "why": why, "wrapper_v": i.wrapper_v, "client_block_v": i.client_v,
                    "client_block_hex_fsid_zeroed": bytes(blk).hex(),
                    "decoded": {"new_flags": i.new_flags, "new_max_osd": i.new_max_osd, "new_pool_max": i.new_pool_max,
                                "new_pools": sorted(i.new_pools), "new_weight": {str(k): v for k, v in i.new_weight.items()},
                                "new_state": {str(k): v for k, v in i.new_state.items()},
                                "new_primary_affinity": {str(k): v for k, v in i.new_primary_affinity.items()},
                                "new_pg_temp": {pgstr(k): v for k, v in i.new_pg_temp.items() if v} or None,
                                "new_pg_temp_erase_count": sum(1 for v in i.new_pg_temp.values() if not v),
                                "new_primary_temp": {pgstr(k): v for k, v in i.new_primary_temp.items()},
                                "new_pg_upmap": {pgstr(k): v for k, v in i.new_pg_upmap.items()},
                                "old_pg_upmap": [pgstr(k) for k in i.old_pg_upmap],
                                "new_pg_upmap_items": {pgstr(k): v for k, v in i.new_pg_upmap_items.items()},
                                "old_pg_upmap_items": [pgstr(k) for k in i.old_pg_upmap_items],
                                "crush_len": len(i.crush)}})
    dump("incremental-client-blocks.json", {
        "provenance": "client-usable block (osdmap.md 2.6.3) of stored Incrementals from the lab monitor; wrapper header, OSD-only block and CRCs "
                      "omitted, fsid replaced by 16 zero bytes. The `decoded` fields were compared with ceph-dencoder JSON, except "
                      "new_primary_affinity which that dump omits (raw bytes only)", "incrementals": out})
    # full map client block at epoch 42
    raw = read_bytes(C + "/gt/osdmap.bin")
    r = R(raw)
    r.u8(); r.u8(); r.u32()
    cv, cc, cend = env(r)
    blk = bytearray(raw[r.p - 6:cend])
    blk[6:22] = b"\x00" * 16
    dumphex("osdmap-e42.client-block.hex", bytes(blk))
    dump("osdmap-e42.client-block.json", {"provenance": "client-usable block v10 of the epoch-42 full map, fsid zeroed; wrapper, OSD-only block and CRC omitted. Contains daemon "
                                          "addresses (lab 10.77.0.x) and daemon nonces (random process ids, not secrets)",
                                          "length": len(blk), "epoch": m.epoch, "pools": sorted(m.pools), "max_osd": m.max_osd,
                                          "block_struct_v": m.client_v})
    # MOSDOp targets from real client frames
    dump("mosdop-targets.json", {"provenance": "MOSDOp frames (crc mode) sent by the stock Ceph 20.2.5 client in the lab captures: object, the hash and pg seed it put in the "
                                               "message, the OSD the TCP connection went to, and the acting set our pipeline computes for that epoch. No payload bytes.",
                                 "samples": ctx.get("op_samples", [])[:40]})


# ---- main ----------------------------------------------------------------------------------------------------------


def main(argv=None):
    ap = argparse.ArgumentParser(description="independent checker for docs/spec/crush-and-placement.md")
    ap.add_argument("--captures", required=True, help="capture directory (contains gt/ gt3/ pcap/ ...)")
    ap.add_argument("--ref", help="reference Ceph tree (default: <captures>/../ceph-v20.2.5); needed for crush_ln tables and group F")
    ap.add_argument("--quick", action="store_true", help="skip CRC of segments > 64 KiB and the in-tree crushtool group")
    ap.add_argument("--no-pcap", action="store_true", help="skip group E")
    ap.add_argument("--no-tree", action="store_true", help="skip group F")
    ap.add_argument("--tree-x", type=int, default=8, help="in-tree known-answer tests: compare x < N (default 128; 1024 = whole files)")
    ap.add_argument("--emit-vectors", metavar="DIR", help="write scrubbed test vectors to DIR")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    C = os.path.abspath(a.captures).rstrip("/")
    ref = os.path.abspath(a.ref) if a.ref else os.path.join(os.path.dirname(C), "ceph-v20.2.5")
    hdr = os.path.join(ref, "src/crush/crush_ln_table.h")
    if not os.path.isdir(C + "/gt3") or not os.path.exists(hdr):
        print("need <captures>/gt3 and %s (use --captures / --ref)" % hdr, file=sys.stderr)
        return 2
    global LN
    LN = LnTables(hdr)
    res = Results(a.verbose)
    ctx = {}
    t0 = time.time()
    steps = [("A arithmetic and table facts", lambda: grp_arith(res)),
             ("C OSDMap / Incremental decode and replay", lambda: grp_osdmap(res, C, ctx)),
             ("B CRUSH blob", lambda: grp_crush(res, C, ctx)),
             ("D placement vs oracles", lambda: grp_place(res, C, ctx)),
             ("D2 semantic consistency", lambda: grp_semantics(res, C, ctx))]
    if not a.no_pcap:
        steps.append(("E pcaps", lambda: grp_pcap(res, C, ctx, a.quick)))
    if not a.no_tree and not a.quick:
        steps.append(("F in-tree known answers", lambda: grp_tree(res, ref, a.tree_x, ctx)))
    if a.emit_vectors:
        steps.append(("emit vectors", lambda: grp_emit(res, C, ctx, a.emit_vectors)))
    for name, fn in steps:
        t = time.time()
        print("== %s" % name, flush=True)
        try:
            fn()
        except Exception as ex:  # a crashing group is a failure, not a pass
            import traceback
            traceback.print_exc()
            res.check(name, "group aborted", False, "%s: %s" % (type(ex).__name__, ex))
        print("   (%.1fs)" % (time.time() - t), flush=True)
    p, f, i = res.counts()
    print("\n==== crush_check summary: %d checks passed, %d failed, %d info; %d individual comparisons; %.0fs" % (p, f, i, res.units, time.time() - t0))
    for grp, name, st, detail in res.rows:
        if st == "FAIL":
            print("FAIL [%s] %s: %s" % (grp, name, detail))
    return 0 if f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
