#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# labstate.sh - the state of the lab cluster as a stable text, for "restore the lab exactly as found" (qemu-robust).
#
#   labstate.sh snapshot FILE        write the state to FILE (made in the lab VM by ceph / rbd; no key, no secret in it)
#   labstate.sh diff A B             show what differs (exit 0 when the two are the same), after dropping the lines that are volatile by nature
#   labstate.sh health               one line: OSDs up / in, PG states, mon quorum, health check names
#
# What is in a snapshot: the cephx entities and their caps (never the keys), the pools (size, min_size, pg_num, flags), the RBD images of every pool with
# their sizes, the OSDs (up, in, reweight), the cluster flags, the pg-upmap entries, the configuration database, the names of the health checks and the monitors
# in quorum. What is not: epochs, timestamps, usage and counters (they move whatever the test does).
#
# How the lab VM is reached: P2_LAB_SSH (the words of an ssh command) or the lab directory of harness/lab/p2/cluster (P2_LAB_DIR / LAB_DIR: its key and
# port), as in images/import.sh. The lab user needs sudo without a password in the VM.
# shellcheck disable=SC2015  # "A && B || die" is a guard here, not an if-then-else
set -euo pipefail
LC_ALL=C
export LC_ALL
die() { echo "labstate.sh: $*" >&2; exit 2; }

lab() {
    if [ -n "${P2_LAB_SSH:-}" ]; then
        # shellcheck disable=SC2086  # the words of a command
        $P2_LAB_SSH "$@"
    else
        local d=${P2_LAB_DIR:-${LAB_DIR:-}}
        [ -n "$d" ] && [ -r "$d/ssh/id_ed25519" ] || die "no lab: set P2_LAB_SSH or P2_LAB_DIR"
        ssh -p "${LAB_SSH_PORT:-22232}" -i "$d/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=15 \
            -o "UserKnownHostsFile=$d/ssh/known_hosts" "${LAB_SSH_USER:-lab}@127.0.0.1" "$@"
    fi
}

snapshot_py() {
    cat <<'PY'
import json, subprocess, sys

def run(*a):
    r = subprocess.run(list(a), capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        print("COMMAND-FAILED %s: %s" % (" ".join(a), r.stderr.strip()[:200]))
        return None
    return r.stdout

def js(*a):
    o = run(*a)
    try:
        return json.loads(o) if o else None
    except ValueError:
        print("NOT-JSON %s" % " ".join(a))
        return None

out = []
auth = js("ceph", "auth", "ls", "--format", "json")
for e in sorted((auth or {}).get("auth_dump", []), key=lambda x: x["entity"]):
    caps = ";".join("%s=%s" % (k, e["caps"][k]) for k in sorted(e.get("caps", {})))
    out.append("auth %s %s" % (e["entity"], caps))
pools = js("ceph", "osd", "pool", "ls", "detail", "--format", "json") or []
for p in sorted(pools, key=lambda x: x["pool_name"]):
    out.append("pool %s size=%s min_size=%s pg_num=%s flags=%s app=%s" % (
        p["pool_name"], p.get("size"), p.get("min_size"), p.get("pg_num"), p.get("flags_names"), ",".join(sorted(p.get("application_metadata", {})))))
    if "rbd" in p.get("application_metadata", {}):
        imgs = js("rbd", "ls", "-l", "--format", "json", "-p", p["pool_name"]) or []
        for i in sorted(imgs, key=lambda x: (x["image"], x.get("snapshot", ""))):
            out.append("image %s/%s%s size=%s" % (p["pool_name"], i["image"], ("@" + i["snapshot"]) if i.get("snapshot") else "", i.get("size")))
tree = js("ceph", "osd", "tree", "--format", "json") or {}
for n in sorted((x for x in tree.get("nodes", []) if x.get("type") == "osd"), key=lambda x: x["id"]):
    out.append("osd %s status=%s reweight=%s" % (n["name"], n.get("status"), n.get("reweight")))
dump = js("ceph", "osd", "dump", "--format", "json") or {}
out.append("flags %s" % dump.get("flags_set"))
for k in ("pg_upmap", "pg_upmap_items", "pg_temp", "primary_temp", "blocklist"):
    v = dump.get(k)
    out.append("%s %s" % (k, len(v) if isinstance(v, (list, dict)) else v))
for c in sorted(js("ceph", "config", "dump", "--format", "json") or [], key=lambda x: (x["section"], x["name"])):
    out.append("config %s %s = %s" % (c["section"], c["name"], c["value"]))
h = js("ceph", "health", "detail", "--format", "json") or {}
for k in sorted(h.get("checks", {})):
    out.append("health %s muted=%s" % (k, h["checks"][k].get("muted")))
q = js("ceph", "quorum_status", "--format", "json") or {}
out.append("quorum %s" % ",".join(sorted(q.get("quorum_names", []))))
print("\n".join(out))
PY
}

cmd=${1:-}
case $cmd in
    snapshot)
        f=${2:?usage: labstate.sh snapshot FILE}
        snapshot_py | lab "sudo python3 -I -" > "$f.tmp" || { rm -f "$f.tmp"; die "the snapshot failed"; }
        grep -q -E '^(COMMAND-FAILED|NOT-JSON)' "$f.tmp" && { cat "$f.tmp" >&2; rm -f "$f.tmp"; die "a ceph command failed: the snapshot is not complete"; }
        if [ "$(grep -c '^osd ' "$f.tmp")" -lt 1 ] || ! grep -q '^quorum .' "$f.tmp"; then rm -f "$f.tmp"; die "the snapshot has no OSDs or no quorum"; fi
        mv -f "$f.tmp" "$f"
        echo "labstate: $(wc -l < "$f") lines in $f"
        ;;
    diff)
        a=${2:?usage: labstate.sh diff A B}; b=${3:?usage: labstate.sh diff A B}
        # (the blocklist is a count of entries that expire by themselves: it is in the snapshot for reading, not for comparing)
        diff -u <(grep -v '^blocklist ' "$a") <(grep -v '^blocklist ' "$b") && echo "labstate: no difference"
        ;;
    health)
        lab "sudo ceph osd stat; sudo ceph pg stat; sudo ceph health --format plain" | tr '\n' ' '; echo
        ;;
    *) die "usage: labstate.sh snapshot FILE | diff A B | health";;
esac
