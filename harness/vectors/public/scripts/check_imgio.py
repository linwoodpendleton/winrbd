#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
check_imgio.py - the image I/O capture set of module vectors-d (harness/vectors/public/imgio/): what the winrbd core itself sent to a real
Ceph v20.2.5 OSD for three scripted image sessions, with the OSD's replies and the stock export of every image before and after. An
independent checker written from docs/spec/osd-ops.md and rbd-format2.md (python3 standard library; the decoders and the pcap reader are
the ones of check_osdc.py, which is written from the notes too). No cluster needed.

    python3 -I check_imgio.py [check] [--dir DIR]        verify the committed vectors      (ctest: vectors_imgio_check)
    python3 -I check_imgio.py selftest [--dir DIR]       feed `check` damaged copies of them (ctest: vectors_imgio_selftest)
    python3 -I check_imgio.py extract --work W --out DIR build the vectors from a capture    (capture_imgio.sh, inside the lab VM)

check: everything check_osdc.py checks of a session (every message decoded again from its bytes and equal to its summary, request / reply
pairs by transaction id, the invariants of the notes), the file list against INDEX.json, no stray file, a size budget, no key-looking text
and no address outside the lab nets, and, beyond that, the image level:
  - the image block (id, prefix, size, order, features, snapshot ids) is what the header reads of the session say and what `rbd info` said;
  - every data request names an object of the image (prefix + 16 hex digits, inside the image), lies inside its object extent, and a writer's
    mutating request carries exactly the image's snapshot context (empty for an image without snapshots); a reader sends no mutation;
  - the tool reported no resend (the capture is of a quiet cluster) and every command of the script finished with status 0;
  - the data the core put in every WRITE is the pattern of the script command that covers it (by SHA-256 of the pattern bytes);
  - the requests are replayed against a model of the objects (WRITE, WRITEFULL, ZERO, TRUNCATE, DELETE, with the OSD's rewrite of a ZERO that
    reaches the end of an object), and every READ / SPARSE_READ reply equals the model at that moment (a missing object is -ENOENT);
  - the model after the last request equals the stock export taken after the session; and so does the script applied to the image as it was
    before (so the script, the wire and the export agree);
  - the coverage the module promises: a write inside one object, across objects, a whole-object write, ZERO, TRUNCATE, DELETE, a read of a
    hole (ENOENT), a short object, a write with a snapshot context, the reader's header read.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_osdc as co  # noqa: E402

DEFAULT_DIR = os.path.normpath(os.path.join(HERE, "..", "imgio"))
BUDGET = 1_500_000
M = (1 << 64) - 1
FEATURE_BITS = {"layering": 1, "striping": 2, "exclusive-lock": 4, "object-map": 8, "fast-diff": 16, "deep-flatten": 32,
                "journaling": 64, "data-pool": 128}
OP_READ, OP_SPARSE, OP_STAT, OP_WRITE, OP_WRITEFULL, OP_TRUNCATE, OP_ZERO, OP_DELETE = 0x1201, 0x1205, 0x1202, 0x2201, 0x2202, 0x2203, 0x2204, 0x2205
OP_CALL, OP_ALLOCHINT, OP_CREATE = 0x1401, 0x2223, 0x220D


# ---- the patterns of wr-rbd (documented in its header; written here independently of the C code) ----------------------------------------

def mix64(x):
    x = (x + 0x9e3779b97f4a7c15) & M
    x = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & M
    x = ((x ^ (x >> 27)) * 0x94d049bb133111eb) & M
    return x ^ (x >> 31)


def pattern(kind, arg, off, n):
    if kind == "zero":
        return bytes(n)
    if kind == "byte":
        return bytes([arg & 255]) * n
    if kind == "rand":
        out = bytearray()
        for w in range(off >> 3, (off + n + 7) >> 3):
            out += struct.pack("<Q", mix64((arg * 0x2545f4914f6cdd1d + w) & M))
        s = off & 7
        return bytes(out[s:s + n])
    raise ValueError("pattern " + kind)


def parse_script(lines):
    """The shell lines of the capture -> list of dicts {op, off, len, kind, arg}."""
    ops = []
    for ln in lines:
        w = ln.split()
        if not w or w[0].startswith("#"):
            continue
        d = dict(op=w[0], off=int(w[1]), len=int(w[2]))
        if "--pattern" in w:
            p = w[w.index("--pattern") + 1].split(":")
            d["kind"], d["arg"] = p[0], int(p[1], 0) if len(p) > 1 else 0
        if d["op"] not in ("write", "verify", "read", "discard", "zeroes"):
            raise ValueError("script command " + w[0])
        ops.append(d)
    return ops


def apply_script(img, ops):
    for o in ops:
        if o["op"] == "write":
            img[o["off"]:o["off"] + o["len"]] = pattern(o["kind"], o["arg"], o["off"], o["len"])
        elif o["op"] in ("discard", "zeroes"):
            img[o["off"]:o["off"] + o["len"]] = bytes(o["len"])


# ---- the object model --------------------------------------------------------------------------------------------------------------------

class Objects:
    """Objects as the OSD holds them: bytes of a known length, or absent."""

    def __init__(self, image_bytes, obj_size):
        self.o = {}
        self.size = obj_size
        for k in range((len(image_bytes) + obj_size - 1) // obj_size):
            chunk = bytes(image_bytes[k * obj_size:(k + 1) * obj_size])
            if any(chunk):
                self.o[k] = bytearray(chunk.rstrip(b"\0"))

    def write(self, k, off, data):
        b = self.o.setdefault(k, bytearray())
        if len(b) < off:
            b.extend(bytes(off - len(b)))
        b[off:off + len(data)] = data

    def zero(self, k, off, n, as_truncate):
        b = self.o.get(k)
        if b is None or off >= len(b) or n == 0:
            return
        if as_truncate or off + n >= len(b):
            del b[off:]
        else:
            b[off:off + n] = bytes(n)

    def truncate(self, k, size):
        b = self.o.get(k)
        if b is None:          # the OSD succeeds and does not make the object (a read of it is still -ENOENT: captured)
            return
        if len(b) > size:
            del b[size:]
        else:
            b.extend(bytes(size - len(b)))

    def delete(self, k):
        self.o.pop(k, None)

    def image(self, n_bytes):
        out = bytearray(n_bytes)
        for k, b in self.o.items():
            out[k * self.size:k * self.size + len(b)] = b
        return out


def num(v):
    """A u64 of the files: a number, or a "0x..." string when it can pass 2^53."""
    return int(v, 0) if isinstance(v, str) else v


def feature_word(names):
    w = 0
    for n in names:
        w |= FEATURE_BITS[n]
    return w


# ---- extract ----------------------------------------------------------------------------------------------------------------------------------

def jdump(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.write("\n")


def tool_report(path):
    done, stats = [], {}
    for ln in open(path):
        m = re.search(r" done (\d+) rc=(\d+)", ln)
        if m:
            done.append(int(m.group(2)))
        m = re.search(r" stats (.*)$", ln)
        if m:
            stats = {k: int(v) for k, v in (kv.split("=") for kv in m.group(1).split() if "=" in kv)}
    return done, stats


def cmd_extract(a):
    co.DATA_HEX_MAX = DATA_HEX_MAX
    work, out = os.path.abspath(a.work), os.path.abspath(a.out)
    plan = json.load(open(os.path.join(work, "plan.json")))
    os.makedirs(out, exist_ok=True)
    sessions = []
    for name in plan["sessions"]:
        meta = json.load(open(os.path.join(work, "meta", name + ".json")))
        pcap = os.path.join(work, "pcap", name + ".pcap")
        msgs = co.capture_messages(pcap)
        if not msgs:
            raise co.DecodeError("%s: no OSD message in the capture" % name)
        t0 = msgs[0]["ts"]
        info = json.load(open(os.path.join(work, "gt", name + ".info.json")))
        snaps = json.load(open(os.path.join(work, "gt", name + ".snaps.json")))
        lines = [ln.rstrip("\n") for ln in open(os.path.join(work, "run", name + ".script")) if ln.strip()]
        done, stats = tool_report(os.path.join(work, "run", name + ".out"))
        exs = co.pair_messages(msgs, single_client=True)
        for e in exs:
            e["t0"] = t0
        ids = sorted((s["id"] for s in snaps), reverse=True)
        sess = dict(session=name, about=meta["about"], mode="crc", writable=int(meta["writable"]), commands=lines, script_status=done,
                    tool_stats=dict(ops_resent=stats.get("ops_resent"), session_resets=stats.get("session_resets"), ops_done=stats.get("ops_done")),
                    osdmap_epoch=[meta["epoch0"], meta["epoch1"]], pcap_bytes=os.path.getsize(pcap),
                    pcap_sha256=hashlib.sha256(open(pcap, "rb").read()).hexdigest(), start=meta["start"], end=meta["end"],
                    tcpdump_dropped=meta["dropped"],
                    image=dict(name=info["name"], id=info["id"], prefix=info["block_name_prefix"], size=info["size"], order=info["order"],
                               features=feature_word(info["features"]), snap_ids=ids, snap_seq=max(ids) if ids else 0,
                               has_before=meta["bench"]),
                    exchanges=[co.exchange_json(e, i + 1) for i, e in enumerate(exs)], other_messages=sum(1 for m in msgs if m["h"]["type"] == 41))
        jdump(os.path.join(out, "sessions", name + ".json"), sess)
        os.makedirs(os.path.join(out, "images"), exist_ok=True)
        shutil.copyfile(os.path.join(work, "export", name + ".after.bin"), os.path.join(out, "images", name + ".after.bin"))
        if meta["bench"]:
            shutil.copyfile(os.path.join(work, "export", name + ".before.bin"), os.path.join(out, "images", name + ".before.bin"))
        sessions.append(name)
        print("session %-8s %3d exchanges, %d commands" % (name, len(sess["exchanges"]), len(lines)))
    index = dict(plan["index"], sessions=sessions)
    index["files"] = {}
    for root, _d, names in os.walk(out):
        for nm in names:
            rel = os.path.relpath(os.path.join(root, nm), out)
            if rel in ("INDEX.json", "README.md"):
                continue
            b = open(os.path.join(root, nm), "rb").read()
            index["files"][rel] = dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
    jdump(os.path.join(out, "INDEX.json"), index)
    print("wrote %d files, %d bytes" % (len(index["files"]), sum(f["bytes"] for f in index["files"].values())))
    return 0


# ---- check ------------------------------------------------------------------------------------------------------------------------------------

DATA_HEX_MAX = 20000     # as in check_osdc: what the extractor stores in full


def data_bytes(msg):
    d = msg["data"]
    return bytes.fromhex(d["hex"]) if "hex" in d else None


class Image:
    def __init__(self, c, s, d):
        self.c, self.s, self.d = c, s, d
        im = s["image"]
        self.im = im
        self.obj = 1 << im["order"]
        self.n_obj = (im["size"] + self.obj - 1) // self.obj
        self.name = s["session"]
        self.script = parse_script(s["commands"])
        self.cover = c.cover

    def err(self, msg):
        self.c.err("%s: %s" % (self.name, msg))

    def read_file(self, kind):
        p = os.path.join(self.d, "images", "%s.%s.bin" % (self.name, kind))
        try:
            return open(p, "rb").read()
        except OSError:
            return None

    def expected_write_data(self, abs_off, n):
        """The bytes of the script command that covers [abs_off, abs_off + n): the latest `write` of the script that contains the range
        and whose pattern slice has this SHA-256 is found by the caller; here every candidate is returned."""
        out = []
        for o in self.script:
            if o["op"] == "write" and o["off"] <= abs_off and abs_off + n <= o["off"] + o["len"]:
                out.append(pattern(o["kind"], o["arg"], abs_off, n))
        return out

    def check(self):
        s, im, c = self.s, self.im, self.c
        # the script ran to the end, nothing was resent
        if s["script_status"] != [0] * len(s["commands"]):
            self.err("a command of the script did not finish with status 0: %s" % s["script_status"])
        if s["tool_stats"]["ops_resent"] != 0 or s["tool_stats"]["session_resets"] != 0:
            self.err("the tool resent operations or reset a session (the capture must be of a quiet cluster)")
        if s["osdmap_epoch"][0] != s["osdmap_epoch"][1]:
            self.err("the OSD map changed during the session")
        if any("resends" in ex for ex in s["exchanges"]):
            self.err("an exchange has resends")
        exs = s["exchanges"]
        if len(exs) < 3:
            self.err("too few exchanges")
            return
        # the open: name -> id on rbd_id.<name>, then the header on rbd_header.<id>
        e0, e1 = exs[0]["request"]["summary"], exs[1]["request"]["summary"]
        if e0["oid"] != "rbd_id." + im["name"] or e1["oid"] != "rbd_header." + im["id"]:
            self.err("the first two requests are not the id lookup and the header read of the image")
        if im["prefix"] != "rbd_data." + im["id"]:
            self.err("the object prefix is not rbd_data.<id>")
        # the image block against the header reply
        self.check_header(exs)
        before = self.read_file("before")
        after = self.read_file("after")
        if after is None or len(after) != im["size"]:
            self.err("the export after the session is missing or of another size")
            return
        if bool(im["has_before"]) != (before is not None):
            self.err("before.bin and has_before disagree")
        if before is not None and len(before) != im["size"]:
            self.err("the export before the session is of another size")
            return
        start = bytearray(before) if before is not None else bytearray(im["size"])
        model = Objects(start, self.obj)
        n_mut = 0
        snapc = (im["snap_seq"], im["snap_ids"])
        for ex in exs:
            rq, rp = ex["request"], ex["reply"]
            rs, ps = rq["summary"], rp["summary"]
            where = "%s #%d" % (self.name, ex["n"])
            if rs["oid"] in ("rbd_id." + im["name"], "rbd_header." + im["id"]):
                continue   # the open: judged by check_header
            m = re.fullmatch(re.escape(im["prefix"]) + r"\.([0-9a-f]{16})", rs["oid"])
            if not m:
                self.err("%s: oid %s is not a data object of the image" % (where, rs["oid"]))
                continue
            k = int(m.group(1), 16)
            if k >= self.n_obj:
                self.err("%s: object %d is past the end of the image (%d objects)" % (where, k, self.n_obj))
                continue
            ext = min(self.obj, im["size"] - k * self.obj)    # the bytes of the image that this object holds
            mutating = any(o["code"] in co.MUTATING for o in rs["ops"])
            if mutating:
                n_mut += 1
                if not s["writable"]:
                    self.err("%s: a reader sent a mutating request" % where)
                if (num(rs["snap_seq"]), [num(x) for x in rs["snaps"]]) != snapc:
                    self.err("%s: snapshot context %s, the image has %s" % (where, (rs["snap_seq"], rs["snaps"]), snapc))
                elif snapc[1]:
                    self.cover["write with the image's snapshot context"] = True
            data = data_bytes(rq)
            doff = 0
            failed = ps["result"] < 0
            for i, op in enumerate(rs["ops"]):
                code = op["code"]
                if code == OP_ALLOCHINT or code == OP_CALL or code == OP_CREATE or code == OP_STAT:
                    continue
                if code in (OP_WRITE, OP_WRITEFULL):
                    n = op["len"]
                    off = op["off"] if code == OP_WRITE else 0
                    if off + n > ext:
                        self.err("%s: a write of %d bytes at %d lies outside the object's %d bytes of the image" % (where, n, off, ext))
                    abs_off = k * self.obj + off
                    chunk = data[doff:doff + n] if data is not None else None
                    sha = hashlib.sha256(chunk).hexdigest() if chunk is not None else None
                    doff += n
                    cands = self.expected_write_data(abs_off, n)
                    if data is None:
                        # the payload is stored as a hash only: find the script command whose pattern slice has it
                        if len(rs["ops"]) != 1 and not all(o["code"] in (OP_ALLOCHINT, OP_WRITE, OP_WRITEFULL) for o in rs["ops"]):
                            self.err("%s: a long payload in a message with other operations" % where)
                        want = rq["data"]["sha256"]
                        match = [x for x in cands if len([o for o in rs["ops"] if o["code"] in (OP_WRITE, OP_WRITEFULL)]) == 1
                                 and hashlib.sha256(x).hexdigest() == want]
                        if not match:
                            self.err("%s: no command of the script has a pattern with the SHA-256 of this write (%d bytes at image offset %d)" % (where, n, abs_off))
                            continue
                        chunk = match[0]
                    else:
                        if not any(x == chunk for x in cands):
                            self.err("%s: the bytes of this write are not the pattern of any script command (image offset %d, %d bytes)" % (where, abs_off, n))
                    if not failed:
                        model.write(k, off, chunk)
                    if off == 0 and n == self.obj:
                        self.cover["whole-object write"] = True
                    elif k == self.n_obj - 1 and off + n == ext:
                        self.cover["write to the end of the image"] = True
                    else:
                        self.cover["write inside an object"] = True
                    self.cover["WRITE"] = True
                elif code == OP_ZERO:
                    pcode = ps["ops"][i]["code"] if i < len(ps["ops"]) else code
                    if not failed:
                        model.zero(k, op["off"], op["len"], pcode == OP_TRUNCATE)
                    self.cover["ZERO"] = True
                elif code == OP_TRUNCATE:
                    if not failed:
                        model.truncate(k, op["off"])
                    self.cover["TRUNCATE"] = True
                elif code == OP_DELETE:
                    if not failed:
                        model.delete(k)
                    self.cover["DELETE"] = True
                elif code in (OP_READ, OP_SPARSE):
                    self.check_read(where, rq, rp, k, i, op, model)
                else:
                    self.err("%s: operation %#x is not one the image layer sends" % (where, code))
        if s["writable"] and n_mut == 0:
            self.err("a writer session without a mutating request")
        # the model after the last request, and the script on the image as it was, both against the stock export
        end = model.image(im["size"])
        if bytes(end) != after:
            self.err("the requests, replayed on the objects of the image as it was, do not give the stock export taken after the session (first difference at %d)" % first_diff(bytes(end), after))
        st2 = bytearray(start)
        apply_script(st2, self.script)
        if bytes(st2) != after:
            self.err("the script, applied to the image as it was, does not give the stock export (first difference at %d)" % first_diff(bytes(st2), after))
        self.cover["export equals the replayed requests"] = True

    def check_header(self, exs):
        im = self.im
        for ex in exs[:2]:
            if ex["reply"]["summary"]["result"] < 0 and ex["reply"]["summary"]["result"] != -2:
                self.err("a header request failed")
        # the header read of the session: sizes and features come back as the image block says
        calls = []
        ex = exs[1]
        rs, ps = ex["request"]["summary"], ex["reply"]["summary"]
        data = bytes.fromhex(ex["reply"]["data"]["hex"]) if "hex" in ex["reply"]["data"] else None
        if data is None:
            self.err("the header reply is not stored in full")
            return
        off = 0
        for o, po in zip(rs["ops"], ps["ops"]):
            out = data[off:off + po["out_len"]]
            off += po["out_len"]
            calls.append(out)
        # the calls are named by their class / method strings inside the request payload: decode with the checker's own decoder
        try:
            req_data = bytes.fromhex(ex["request"]["data"]["hex"])
            roff = 0
            meth = []
            for o in rs["ops"]:
                blob = req_data[roff:roff + o["payload_len"]]
                roff += o["payload_len"]
                cl, mt = blob[:o["class_len"]].decode(), blob[o["class_len"]:o["class_len"] + o["method_len"]].decode()
                meth.append((cl, mt))
        except (KeyError, ValueError) as e:
            self.err("the header request does not decode: %r" % e)
            return
        got = {}
        for (cl, mt), out in zip(meth, calls):
            try:
                got[mt] = co.dec_call_out(mt, out)
            except Exception as e:  # noqa: BLE001
                self.err("header call %s does not decode: %r" % (mt, e))
        gs = got.get("get_size")
        if gs is not None and (gs.get("size") != im["size"] or gs.get("order") != im["order"]):
            self.err("the header's size / order (%s) differ from the image block" % (gs,))
        gf = got.get("get_features")
        if gf is not None and gf.get("features") != im["features"]:
            self.err("the header's features (%#x) differ from the image block (%#x)" % (gf.get("features"), im["features"]))
        gp = got.get("get_snapcontext")
        if gp is not None and (gp.get("seq") != im["snap_seq"] or list(gp.get("snaps", [])) != im["snap_ids"]):
            self.err("the header's snapshot context differs from the image block")
        if any(mt == "get_features" for _c, mt in meth):
            self.cover["header read"] = True
        if "get_snapcontext" not in got or "get_size" not in got:
            self.err("the header read lacks get_size or get_snapcontext")

    def check_read(self, where, rq, rp, k, i, op, model):
        ps = rp["summary"]
        b = model.o.get(k)
        self.cover["READ"] = True
        if ps["result"] == -2:
            if b is not None:
                self.err("%s: the OSD says the object is missing, the model has it" % where)
            self.cover["read of a missing object (ENOENT)"] = True
            return
        if ps["result"] < 0:
            self.err("%s: a read failed with %d" % (where, ps["result"]))
            return
        raw = bytes.fromhex(rp["data"]["hex"]) if "hex" in rp["data"] else None
        outs = [po["out_len"] for po in ps["ops"]]
        o_start = sum(outs[:i])
        n_out = outs[i]
        have = bytes(b) if b is not None else b""
        want_len = op["len"]
        lo = op["off"]
        if op["code"] == OP_READ:
            want = have[lo:lo + want_len]
            if n_out != len(want):
                self.err("%s: a READ of %d bytes at %d returned %d bytes, the model says %d" % (where, want_len, lo, n_out, len(want)))
            if len(want) < want_len:
                self.cover["short read"] = True
            if raw is not None and raw[o_start:o_start + n_out] != want[:n_out]:
                self.err("%s: the bytes of a READ differ from the model" % where)
            elif raw is None:
                full = rp["data"]["sha256"]
                if len(outs) == 1 and hashlib.sha256(want).hexdigest() != full:
                    self.err("%s: the SHA-256 of a READ reply differs from the model" % where)
        else:
            if raw is None:
                if len(outs) == 1 and hashlib.sha256(b"").hexdigest():
                    pass
                return
            r = co.Rd(raw[o_start:o_start + n_out])
            n = r.u32()
            ext = [(r.u64(), r.u64()) for _ in range(n)]
            dl = r.u32()
            body = r.take(dl)
            pos = 0
            for eo, el in ext:
                if body[pos:pos + el] != have[eo:eo + el].ljust(el, b"\0"):
                    self.err("%s: sparse-read extent differs from the model" % where)
                pos += el
            self.cover["SPARSE_READ"] = True


def first_diff(a, b):
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n


def check_dir(d):
    co.DATA_HEX_MAX = DATA_HEX_MAX
    c = co.Checker(d)
    try:
        idx = json.load(open(os.path.join(d, "INDEX.json")))
    except (OSError, ValueError) as e:
        return ["no usable INDEX.json: %s" % e], "imgio vectors: unusable"
    files = idx["files"]
    on_disk, total = {}, 0
    for root, _dirs, names in os.walk(d, followlinks=False):
        for nm in names:
            p = os.path.join(root, nm)
            rel = os.path.relpath(p, d)
            if os.path.islink(p):
                c.err("symbolic link %s" % rel)
                continue
            if rel in ("INDEX.json", "README.md"):
                continue
            on_disk[rel] = p
    for rel in sorted(set(on_disk) - set(files)):
        c.err("stray file %s" % rel)
    for rel, meta in sorted(files.items()):
        p = on_disk.get(rel)
        if p is None:
            c.err("missing file %s" % rel)
            continue
        b = open(p, "rb").read()
        total += len(b)
        if len(b) != meta["bytes"] or hashlib.sha256(b).hexdigest() != meta["sha256"]:
            c.err("%s differs from INDEX.json" % rel)
        if rel.endswith((".json", ".txt", ".md", ".tsv")):
            txt = b.decode("utf-8", "replace")
            m = (co.KEY_RE_LOG if rel == "revert-proof.txt" else co.KEY_RE).search(txt)
            if m:
                c.err("%s: key-like text %r" % (rel, m.group(0)[:20]))
            m = co.PATH_RE.search(txt)
            if m:
                c.err("%s: a directory of the lab or of a developer machine (%r)" % (rel, txt[m.start():m.start() + 24]))
            for m in co.IP_RE.finditer(txt):
                q = tuple(int(x) for x in m.groups())
                if all(x < 256 for x in q) and q[:3] not in ((10, 77, 0), (192, 0, 2)) and not (q[0] == 127):
                    c.err("%s: address %s outside 10.77.0.x / 192.0.2.x" % (rel, m.group(0)))
                    break
    if total > BUDGET:
        c.err("total size %d above the budget of %d" % (total, BUDGET))
    if not isinstance(idx.get("user"), dict) or idx["user"].get("deleted") is not True or not idx["user"].get("verified_gone"):
        c.err("INDEX.json does not record the removal of the throwaway user")
    n_ex = 0
    for name in idx.get("sessions", []):
        rel = "sessions/%s.json" % name
        if rel not in files:
            c.err("session %s is not in the file list" % name)
            continue
        try:
            s = c.check_session(name)
            n_ex += len(s["exchanges"])
            Image(c, s, d).check()
        except (OSError, ValueError, KeyError, struct.error, co.DecodeError) as e:
            c.err("%s: %r" % (name, e))
    if len(idx.get("sessions", [])) < 3:
        c.err("fewer than three sessions")
    for r in ("WRITE", "whole-object write", "write inside an object", "write to the end of the image", "ZERO", "TRUNCATE", "DELETE", "READ",
              "read of a missing object (ENOENT)", "short read", "write with the image's snapshot context", "header read",
              "export equals the replayed requests", "CALL"):
        if not c.cover.get(r):
            c.err("coverage: nothing in the set shows `%s`" % r)
    st = c.stats
    line = "imgio vectors: %d files, %d bytes, %d sessions, %d exchanges, %d messages decoded: %s" % (
        len(files), total, st["sessions"], st["exchanges"], st["messages"], "OK" if not c.bad else "%d PROBLEMS" % len(c.bad))
    return c.bad, line


def cmd_check(a):
    d = os.path.abspath(a.dir)
    if not os.path.exists(os.path.join(d, "INDEX.json")):
        print("SKIP: %s has no INDEX.json (the lab captures of module vectors-d are not in this tree)" % d)
        return 77
    bad, line = check_dir(d)
    print(line)
    for b in bad[:25]:
        print("  " + b)
    return 0 if not bad else 1


# ---- the checker's own error paths --------------------------------------------------------------------------------------------------------

def _reindex(d):
    idx = json.load(open(os.path.join(d, "INDEX.json")))
    for rel in idx["files"]:
        b = open(os.path.join(d, rel), "rb").read()
        idx["files"][rel] = dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
    jdump(os.path.join(d, "INDEX.json"), idx)


def _edit_json(d, rel, fn):
    p = os.path.join(d, rel)
    doc = json.load(open(p))
    fn(doc)
    jdump(p, doc)
    _reindex(d)


def cmd_selftest(a):
    src = os.path.abspath(a.dir)
    if not os.path.exists(os.path.join(src, "INDEX.json")):
        print("SKIP: %s has no INDEX.json" % src)
        return 77
    bad0, line = check_dir(src)
    if bad0:
        print("the undamaged copy fails: %s" % bad0[:3])
        return 1

    def first_write(doc):
        for ex in doc["exchanges"]:
            if any(o["code"] == OP_WRITE for o in ex["request"]["summary"]["ops"]):
                return ex
        raise KeyError("no write")

    def flip_front(doc):
        ex = first_write(doc)
        h = ex["request"]["front_hex"]
        ex["request"]["front_hex"] = h[:60] + ("0" if h[60] != "0" else "1") + h[61:]

    def other_data(doc):
        # other payload bytes with a consistent length and hash: only the comparison with the script's patterns can see it
        ex = first_write(doc)
        h = ex["request"]["data"]["hex"]
        h = ("00" if h[:2] != "00" else "01") + h[2:]
        ex["request"]["data"]["hex"] = h
        ex["request"]["data"]["sha256"] = hashlib.sha256(bytes.fromhex(h)).hexdigest()

    def other_read(doc):
        # a read reply with other bytes (hex and hash consistent): only the replayed object model can see it
        for ex in doc["exchanges"]:
            ps = ex["reply"]["summary"]
            if ps["result"] == 0 and ex["request"]["summary"]["ops"][0]["name"] == "READ" and ex["reply"]["data"]["length"] > 8:
                h = ex["reply"]["data"]["hex"]
                h = ("00" if h[:2] != "00" else "01") + h[2:]
                ex["reply"]["data"]["hex"] = h
                ex["reply"]["data"]["sha256"] = hashlib.sha256(bytes.fromhex(h)).hexdigest()
                return
        raise KeyError("no read with data")

    def snapc_of_image(doc):
        doc["image"]["snap_seq"] += 1

    def wrong_prefix(doc):
        doc["image"]["prefix"] = "rbd_data.0000000000000"

    def resent(doc):
        doc["tool_stats"]["ops_resent"] = 1

    def bad_status(doc):
        doc["script_status"][0] = 1

    def no_user(doc):
        doc.pop("user", None)

    def flip_export(d):
        p = os.path.join(d, "images", "w4k.after.bin")
        b = bytearray(open(p, "rb").read())
        b[5] ^= 1
        open(p, "wb").write(bytes(b))
        _reindex(d)

    def stray(d):
        open(os.path.join(d, "images", "extra.bin"), "wb").write(b"x")

    def keylike(d):
        open(os.path.join(d, "revert-proof.txt"), "a").write("key = AQ" + "A" * 36 + "\n")
        _reindex(d)

    def foreign_ip(d):
        open(os.path.join(d, "revert-proof.txt"), "a").write("peer 203.0.113.7\n")
        _reindex(d)

    cases = [
        ("flipped byte in a request front", lambda d: _edit_json(d, "sessions/w4k.json", flip_front)),
        ("other payload bytes, hash consistent", lambda d: _edit_json(d, "sessions/w4k.json", other_data)),
        ("other read reply bytes, hash consistent", lambda d: _edit_json(d, "sessions/w4k.json", other_read)),
        ("snapshot context of the image block changed", lambda d: _edit_json(d, "sessions/snap64k.json", snapc_of_image)),
        ("an object prefix that is not the image's", lambda d: _edit_json(d, "sessions/w4k.json", wrong_prefix)),
        ("a resend reported by the tool", lambda d: _edit_json(d, "sessions/w4k.json", resent)),
        ("a script command with status 1", lambda d: _edit_json(d, "sessions/w4k.json", bad_status)),
        ("a changed byte in the stock export", flip_export),
        ("no record of the user's removal", lambda d: _edit_json(d, "INDEX.json", no_user)),
        ("a stray file", stray),
        ("key-like text", keylike),
        ("an address outside the lab nets", foreign_ip),
    ]
    fails = 0
    for label, fn in cases:
        tmp = tempfile.mkdtemp(prefix="imgio-selftest-")
        try:
            dst = os.path.join(tmp, "imgio")
            shutil.copytree(src, dst)
            fn(dst)
            bad, _ = check_dir(dst)
            if bad:
                print("ok    %-48s rejected: %s" % (label, bad[0][:90]))
            else:
                print("FAIL  %-48s was accepted" % label)
                fails += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print("selftest: %d damaged copies, %d accepted by mistake" % (len(cases), fails))
    return 0 if fails == 0 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("check")
    p.add_argument("--dir", default=DEFAULT_DIR)
    p = sub.add_parser("selftest")
    p.add_argument("--dir", default=DEFAULT_DIR)
    p = sub.add_parser("extract")
    p.add_argument("--work", required=True)
    p.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.cmd in (None, "check"):
        if a.cmd is None:
            a.dir = DEFAULT_DIR
        return cmd_check(a)
    if a.cmd == "selftest":
        return cmd_selftest(a)
    return cmd_extract(a)


if __name__ == "__main__":
    sys.exit(main())
