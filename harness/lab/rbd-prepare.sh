#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# rbd-prepare.sh: make (and remove) the images, pools, users and reference files the live RBD matrix of
# harness/lab/live-rbd.sh runs on, with the STOCK tools (rbd, rados, ceph) as the oracle. Everything it creates is named
# wrtest-lrt-*  (images and the extra pool) or client.wrtest-lrt-* (cephx users), so `cleanup` can remove exactly that and nothing
# else. Run it inside the lab VM (it needs sudo for the stock CLI and the admin keyring there).
#
#   rbd-prepare.sh create     make the images, the data pool, the throwaway users and the reference files; print the manifest path
#   rbd-prepare.sh status     what exists now
#   rbd-prepare.sh cleanup    remove it all again (clones, snapshots, images, the pool, the users, the work directory contents)
#                             `create` exits 3 (and has made nothing) when an earlier run's images, pool or manifest are in the way
#   rbd-prepare.sh pylib      write the python helper (pattern files, expected images) and print its path
#
# Environment:
#   WR_LAB_POOL     pool of the images                          (default winrbd)
#   WR_LAB_WORK     work directory for reference files, keyrings and the manifest   (default ~/w/lrt-run; mode 0700)
#   WR_LAB_SUDO     command prefix for the stock CLI            (default "sudo")
#
# The images (8 at most, none above 128 MiB), all in the pool WR_LAB_POOL, and what each is for:
#   wrtest-lrt-p1a    features 0x1   (layering)                 reference content imported with `rbd import`: reads vs the stock export
#   wrtest-lrt-p1b    features 0x21  (layering, deep-flatten)   reference content written object by object with `rados put`
#   wrtest-lrt-dflt   default features 0x3d (exclusive-lock, object-map, fast-diff...)  refused as a writer, readable as a reader;
#                     a protected snapshot "bs" of it (the head keeps its content) is the parent of ...
#   wrtest-lrt-clone  ... a clone: refused (a parent)
#   wrtest-lrt-geo    features 0x21, 16 KiB objects, 10000001 bytes (not a multiple of the object size, nor of a sector): the last partial
#                     object, 64 bit arithmetic over 611 objects, odd offsets
#   wrtest-lrt-str    striped (stripe unit 64 KiB, count 4): refused
#   wrtest-lrt-dp     data pool wrtest-lrt-dp (feature 0x80): needs --data-pool, and a user with caps on both pools
#   wrtest-lrt-snap   features 0x21, empty, 128 MiB (32 objects): the snapshot, ORDERSNAP and mtime experiments
# The extra pool wrtest-lrt-dp is replicated with the CRUSH rule of the lab pool (failure domain osd), 8 PGs, autoscaler off.
# The throwaway cephx users (keyrings in $WR_LAB_WORK/keys, mode 0600, never printed):
#   client.wrtest-lrt-dp      profile rbd on both pools (the data-pool image)
#   client.wrtest-lrt-nocls   osd 'allow rw pool=<pool>': no class access, the image header calls are refused
#   client.wrtest-lrt-noosd   mon 'allow r' only: no OSD service at all, the authorizer is refused
#   client.wrtest-lrt-ro      profile rbd-read-only: opens, every write is refused
# Existing users, pools and images of the lab are never touched.
#
# Key material is written only into the work directory and is never printed.

set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
POOL=${WR_LAB_POOL:-winrbd}
WORK=${WR_LAB_WORK:-$HOME/w/lrt-run}
SUDO=${WR_LAB_SUDO:-sudo}
DP=wrtest-lrt-dp
PFX=wrtest-lrt-
MANIFEST=$WORK/manifest.env

die()  { echo "rbd-prepare: error: $*" >&2; exit 1; }
# a refusal before anything was made: exit 3, so a caller knows there is nothing of its own to clean up (and must not run `cleanup`,
# which would remove the images of the run that is in the way)
nothing() { echo "rbd-prepare: error: $*" >&2; exit 3; }
info() { echo "rbd-prepare: $*" >&2; }
RBD()   { $SUDO rbd "$@"; }
RADOS() { $SUDO rados "$@"; }
CEPH()  { $SUDO ceph "$@"; }

case "$WORK" in /*) ;; *) die "WR_LAB_WORK must be an absolute path";; esac
case "$WORK" in *' '*|*'*'*|*'?'*) die "WR_LAB_WORK must not contain spaces or glob characters";; esac

# ---- the python helper: pattern files and expected images (the oracle's expected side) ------------------------------------
write_pylib() {
    mkdir -p "$WORK"; chmod 700 "$WORK"
    cat > "$WORK/lrtpy.py" <<'PYEOF'
# SPDX-License-Identifier: MIT
# lrtpy.py: build files from pattern segments, the expected side of the live RBD matrix. The pattern functions are the ones
# wr-rbd documents (zero, byte:N, seq, offset, rand:SEED), written here independently of the C code.
#
#   lrtpy.py build OUT (zero:SIZE | INFILE) SEG...
#     SEG = OFF:LEN:KIND[:ARG]   KIND = zero | byte | seq | offset | rand | file (ARG = path; LEN may be - for the whole file)
#   lrtpy.py cmp A B            first differing offset or "same"  (exit 1 when different)
#   lrtpy.py id IMAGE_JSON       prints the image id from `rbd info --format json`
import json, struct, sys
M = (1 << 64) - 1

def mix64(x):
    x = (x + 0x9e3779b97f4a7c15) & M
    x = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & M
    x = ((x ^ (x >> 27)) * 0x94d049bb133111eb) & M
    return x ^ (x >> 31)

def words(fn, off, n):
    out = bytearray()
    for w in range(off >> 3, (off + n + 7) >> 3):
        out += struct.pack('<Q', fn(w))
    s = off & 7
    return bytes(out[s:s + n])

def pat(kind, arg, off, n):
    if kind == 'zero':
        return bytes(n)
    if kind == 'byte':
        return bytes([arg & 255]) * n
    if kind == 'seq':
        return bytes((off + i) & 255 for i in range(n))
    if kind == 'offset':
        return words(lambda w: (w * 8) & M, off, n)
    if kind == 'rand':
        return words(lambda w: mix64((arg * 0x2545f4914f6cdd1d + w) & M), off, n)
    raise SystemExit('bad pattern ' + kind)

def build(out, base, segs):
    if base.startswith('zero:'):
        buf = bytearray(int(base[5:], 0))
    else:
        buf = bytearray(open(base, 'rb').read())
    for s in segs:
        p = s.split(':', 3)
        off, kind = int(p[0], 0), p[2]
        if kind == 'file':
            data = open(p[3], 'rb').read()
            n = len(data) if p[1] == '-' else int(p[1], 0)
            data = data[:n]
        else:
            n = int(p[1], 0)
            data = pat(kind, int(p[3], 0) if len(p) > 3 else 0, off, n)
        if off + len(data) > len(buf):
            raise SystemExit('segment past the end: ' + s)
        buf[off:off + len(data)] = data
    open(out, 'wb').write(buf)

def main(a):
    if a[0] == 'build':
        build(a[1], a[2], a[3:])
    elif a[0] == 'cmp':
        x, y = open(a[1], 'rb').read(), open(a[2], 'rb').read()
        if x == y:
            print('same')
            return 0
        n = min(len(x), len(y))
        for i in range(n):
            if x[i] != y[i]:
                print('differ at %d (%#x vs %#x), sizes %d %d' % (i, x[i], y[i], len(x), len(y)))
                return 1
        print('sizes differ %d %d' % (len(x), len(y)))
        return 1
    elif a[0] == 'id':
        print(json.load(open(a[1]))['id'])
    else:
        raise SystemExit('unknown command')
    return 0

sys.exit(main(sys.argv[1:]))
PYEOF
}

py() { python3 -I "$WORK/lrtpy.py" "$@"; }

# ---- helpers ------------------------------------------------------------------------------------------------------------------
img_json()  { RBD info --format json "$POOL/$1"; }
img_exists(){ RBD info "$POOL/$1" >/dev/null 2>&1; }

mk_user() { # <suffix> <caps...>  : creates client.wrtest-lrt-<suffix>, keyring into $WORK/keys/<suffix>.keyring
    local suf=$1; shift
    mkdir -p "$WORK/keys"; chmod 700 "$WORK/keys"
    ( umask 077; CEPH auth get-or-create "client.${PFX}${suf}" "$@" > "$WORK/keys/${suf}.keyring" ) || die "cannot create client.${PFX}${suf}"
    chmod 600 "$WORK/keys/${suf}.keyring"
}

cmd_create() {
    mkdir -p "$WORK"; chmod 700 "$WORK"
    write_pylib
    [ -e "$MANIFEST" ] && nothing "$MANIFEST exists: an earlier create was not cleaned up (run cleanup first)"
    local n
    n=$(RBD ls "$POOL" | grep -c "^$PFX" || true)
    [ "$n" = 0 ] || nothing "images named $PFX* already exist in $POOL: run cleanup first"
    CEPH osd pool ls | grep -qx "$DP" && nothing "pool $DP exists: run cleanup first"

    info "reference files"
    # p1a: 64 MiB, imported. Data in ragged places: the first bytes, a stretch across the first object boundary, 4 MiB that start in the
    # middle of object 2 (so two partial objects), one whole object (5), a short object (100 bytes at the start of object 10), the last
    # bytes. Everything else is a hole.
    py build "$WORK/ref-p1a.bin" zero:67108864 \
        0:1000:rand:101  4191304:8000:rand:102  10485760:4194304:rand:103  20971520:4194304:rand:104 \
        41943040:100:rand:106  67108364:500:rand:105 || die "python helper failed"
    # p1b: written with rados put, object by object: object 0 whole, object 3 short (100 bytes), object 7 data only near its end
    # (so the object is zero-filled up to there), object 15 whole.
    py build "$WORK/ref-p1b.bin" zero:67108864 \
        0:4194304:rand:201  12582912:100:rand:202  29360128:4194304:zero 32503000:1000:rand:203  62914560:4194304:rand:204 || die "python helper failed"
    # dflt: 32 MiB with the default feature set
    py build "$WORK/ref-dflt.bin" zero:33554432 0:70000:rand:301  8388608:100000:offset  33554000:432:rand:302 || die "python helper failed"

    info "images"
    RBD import --image-format 2 --image-feature layering "$WORK/ref-p1a.bin" "$POOL/${PFX}p1a" >/dev/null 2>&1 || die "rbd import p1a failed"
    RBD create --size 64M --image-feature layering,deep-flatten "$POOL/${PFX}p1b" || die "rbd create p1b failed"
    RBD import --image-format 2 "$WORK/ref-dflt.bin" "$POOL/${PFX}dflt" >/dev/null 2>&1 || die "rbd import dflt failed"
    RBD snap create "$POOL/${PFX}dflt@bs" || die "snap create failed"
    RBD snap protect "$POOL/${PFX}dflt@bs" || die "snap protect failed"
    RBD clone --image-feature layering "$POOL/${PFX}dflt@bs" "$POOL/${PFX}clone" || die "rbd clone failed"
    RBD create --size 10000001B --object-size 16K --image-feature layering,deep-flatten "$POOL/${PFX}geo" || die "rbd create geo failed"
    RBD create --size 32M --image-feature layering,striping --stripe-unit 65536 --stripe-count 4 "$POOL/${PFX}str" || die "rbd create striped failed"
    RBD create --size 128M --image-feature layering,deep-flatten "$POOL/${PFX}snap" || die "rbd create snap failed"

    info "p1b content with rados put"
    local id prefix i
    id=$(img_json "${PFX}p1b" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])') || die "no id for p1b"
    prefix="rbd_data.$id"
    # object i = bytes [i*4M, (i+1)*4M) of the reference file; an object is put only up to its last non-zero byte
    for i in 0 3 7 15; do
        python3 -I - "$WORK/ref-p1b.bin" "$i" "$WORK/obj.tmp" <<'PYEOF' || die "cannot cut object $i"
import sys
data = open(sys.argv[1], 'rb').read()
i = int(sys.argv[2]); o = data[i * 4194304:(i + 1) * 4194304]
open(sys.argv[3], 'wb').write(o.rstrip(b'\0') if i != 15 else o)
PYEOF
        RADOS -p "$POOL" put "$(printf '%s.%016x' "$prefix" "$i")" "$WORK/obj.tmp" || die "rados put object $i failed"
    done
    rm -f "$WORK/obj.tmp"

    info "data pool image"
    local rule
    rule=$(CEPH osd pool get "$POOL" crush_rule 2>/dev/null | sed -n 's/^crush_rule: *//p')
    [ -n "$rule" ] || rule=replicated_rule
    CEPH osd pool create "$DP" 8 8 replicated "$rule" >/dev/null 2>&1 || die "cannot create pool $DP"
    CEPH osd pool set "$DP" pg_autoscale_mode off >/dev/null 2>&1
    CEPH osd pool application enable "$DP" rbd >/dev/null 2>&1
    RBD create --size 32M --image-feature layering --data-pool "$DP" "$POOL/${PFX}dp" || die "rbd create data-pool image failed"

    info "throwaway users"
    mk_user dp    mon 'profile rbd' osd "profile rbd pool=$POOL, profile rbd pool=$DP"
    mk_user nocls mon 'allow r' osd "allow rw pool=$POOL"
    mk_user noosd mon 'allow r'
    mk_user ro    mon 'profile rbd' osd "profile rbd-read-only pool=$POOL"

    {
        echo "# written by rbd-prepare.sh create; sourced by live-rbd.sh"
        echo "LRT_POOL=$POOL"
        echo "LRT_DP_POOL=$DP"
        echo "LRT_WORK=$WORK"
        for i in p1a p1b dflt clone str dp snap geo; do
            echo "LRT_IMG_$i=${PFX}$i"
            echo "LRT_ID_$i=$(img_json "${PFX}$i" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
        done
        for i in p1a p1b dflt; do echo "LRT_REF_$i=$WORK/ref-$i.bin"; done
        for i in dp nocls noosd ro; do
            echo "LRT_USER_$i=${PFX}$i"
            echo "LRT_KEYRING_$i=$WORK/keys/$i.keyring"
        done
    } > "$MANIFEST"
    chmod 600 "$MANIFEST"
    info "done; images:"
    RBD ls -l "$POOL" | grep "$PFX" >&2
    echo "$MANIFEST"
}

cmd_status() {
    echo "images in $POOL:"; RBD ls -l "$POOL" | grep -E "^NAME|$PFX" || true
    echo "pool $DP:"; CEPH osd pool ls | grep -x "$DP" || echo "  (none)"
    echo "users:"; CEPH auth ls 2>/dev/null | grep "^client\.${PFX}" || echo "  (none)"
    echo "work directory $WORK:"; ls -la "$WORK" 2>/dev/null | sed 's/^/  /' || echo "  (none)"
}

cmd_cleanup() {
    local img snap rc=0 orig
    # a clone is an image with a parent: remove those first, then the images that hold snapshots, then the rest
    for img in $(RBD ls "$POOL" 2>/dev/null | grep "^$PFX" || true); do
        if RBD info --format json "$POOL/$img" 2>/dev/null | python3 -I -c 'import json,sys; sys.exit(0 if "parent" in json.load(sys.stdin) else 1)'; then
            RBD rm "$POOL/$img" >/dev/null 2>&1 || { info "cannot remove clone $img"; rc=1; }
        fi
    done
    for img in $(RBD ls "$POOL" 2>/dev/null | grep "^$PFX" || true); do
        for snap in $(RBD snap ls --format json "$POOL/$img" 2>/dev/null | python3 -I -c 'import json,sys; print(" ".join(s["name"] for s in json.load(sys.stdin)))'); do
            RBD snap unprotect "$POOL/$img@$snap" >/dev/null 2>&1
        done
        RBD snap purge "$POOL/$img" >/dev/null 2>&1
        RBD rm "$POOL/$img" >/dev/null 2>&1 || { info "cannot remove image $img"; rc=1; }
    done
    if CEPH osd pool ls | grep -qx "$DP"; then
        # pool deletion is off in the lab: switch it on for this one removal and put the setting back exactly as it was (unset or set)
        local was_set
        was_set=$(CEPH config dump 2>/dev/null | grep -c '[[:space:]]mon_allow_pool_delete[[:space:]]')
        orig=$(CEPH config get mon mon_allow_pool_delete 2>/dev/null || echo false)
        CEPH config set mon mon_allow_pool_delete true >/dev/null 2>&1
        CEPH osd pool rm "$DP" "$DP" --yes-i-really-really-mean-it >/dev/null 2>&1 || { info "cannot remove pool $DP"; rc=1; }
        if [ "$was_set" -eq 0 ]; then CEPH config rm mon mon_allow_pool_delete >/dev/null 2>&1; else CEPH config set mon mon_allow_pool_delete "$orig" >/dev/null 2>&1; fi
    fi
    for u in $(CEPH auth ls 2>/dev/null | sed -n "s/^\(client\.${PFX}[a-z]*\)\$/\1/p"); do
        CEPH auth rm "$u" >/dev/null 2>&1 || { info "cannot remove $u"; rc=1; }
    done
    # the work directory: only the files this script makes
    if [ -d "$WORK" ]; then
        rm -f "$WORK"/ref-*.bin "$WORK"/obj.tmp "$WORK"/manifest.env "$WORK"/keys/*.keyring "$WORK"/lrtpy.py
        rmdir "$WORK/keys" 2>/dev/null
    fi
    info "cleanup done (rc=$rc); anything left named $PFX* in $POOL:"
    RBD ls "$POOL" | grep "^$PFX" >&2 || true
    return $rc
}

case "${1:-}" in
    create)  cmd_create ;;
    status)  cmd_status ;;
    cleanup) cmd_cleanup ;;
    pylib)   write_pylib; echo "$WORK/lrtpy.py" ;;
    -h|--help|"") sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown command: $1 (try --help)" ;;
esac
