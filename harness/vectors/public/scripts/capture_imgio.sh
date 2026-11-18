#!/bin/bash
# SPDX-License-Identifier: MIT
#
# capture_imgio.sh - the lab captures of module vectors-d (harness/vectors/public/imgio/): what the winrbd CORE itself puts on the wire when it
# does image I/O (its OSD requests, the real OSD's replies) for three small scripted sessions, and what the stock tools say the images hold
# afterwards (`rbd export`). The sessions are driven by the wr-rbd tool (harness/host/tools/wr-rbd.c, the core on the Linux host) in its
# `shell` mode, one request at a time (--depth 1), inside a network namespace under tcpdump, in crc mode.
#
# Runs INSIDE the disposable lab VM, as a user with passwordless sudo, with the stock tools (ceph, rbd, rados, tcpdump) and a built
# harness (wr-rbd). Everything it creates is named wrtest-imgio-* or client.vec-imgio and is removed again; the one thing it changes (a
# throwaway cephx user) is put back and the result is proven in revert-proof.txt. Usage:
#
#     WR=<path of wr-rbd> capture_imgio.sh run [OUTDIR]     the whole thing; the vector tree is written to OUTDIR (default $WORK/imgio)
#     capture_imgio.sh cleanup                              remove what an interrupted run left
#
# Environment: WORK (default $HOME/w/imgio-cap)  POOL (default winrbd)  WR (default <repo>/build/harness/wr-rbd)  SCRIPTS (default: the
# directory of this file, where check_imgio.py is).
#
# The cephx user is created with default key type (caps: mon 'profile rbd', osd 'profile rbd pool=<pool>'), used in crc mode only (the core
# speaks crc), and deleted at the end (`ceph auth get` must fail, which the script verifies before it writes the vectors). Its key is not part
# of the published set (crc-mode message bodies carry no secret); the script scans the finished tree for the key text and aborts on a hit.
# The cluster's admin key is used only for the setup and clean-up commands, never from inside the capture namespace.
set -u

WORK=${WORK:-$HOME/w/imgio-cap}
POOL=${POOL:-winrbd}
USERN=vec-imgio
SCRIPTS=${SCRIPTS:-$(cd "$(dirname "$0")" && pwd)}
REPO=$(cd "$SCRIPTS/../../../.." && pwd)
WR=${WR:-$REPO/build/harness/wr-rbd}
NSNAME=viins
VETH_H=vii0
VETH_C=vii1
NET_H=192.0.2.1   # the namespace's own point-to-point net (documentation addresses; the lab's 10.77.0.x is reached through the host)
NET_C=192.0.2.2
MON=${MON:-10.77.0.10:3300}
NS="sudo -n ip netns exec $NSNAME"
A="sudo -n ceph"
R="sudo -n rbd"
KEYRING=$WORK/keys/client.$USERN.keyring
PFXI=wrtest-imgio-

die() { echo "capture_imgio: $*" >&2; exit 1; }
say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }

net_setup() {
  sudo -n ip netns add $NSNAME || die "cannot create the namespace $NSNAME (left over from an earlier run? run: $0 cleanup)"
  sudo -n ip link add $VETH_H type veth peer name $VETH_C
  sudo -n ip link set $VETH_C netns $NSNAME
  sudo -n ip addr add $NET_H/24 dev $VETH_H
  sudo -n ip link set $VETH_H up
  $NS ip addr add $NET_C/24 dev $VETH_C
  $NS ip link set $VETH_C up
  $NS ip link set lo up
  $NS ip route add default via $NET_H
}
net_teardown() {
  sudo -n pkill -INT -f "tcpdump -i $VETH_H" 2>/dev/null
  sudo -n ip netns del $NSNAME 2>/dev/null
  sudo -n ip link del $VETH_H 2>/dev/null
  true
}

# ---- the sessions -----------------------------------------------------------------------------------------------------------------------
# name | image create arguments | writer? | snapshot taken before the session | stock writes before it (rbd bench) | the commands of the shell
# Each command is one request of the tool (the io size is 1 MiB, the depth 1): the core splits it into one operation per object.
SESSIONS="w4k snap64k rd64k"
declare -A S_ABOUT S_SIZE S_ORDER S_FEAT S_RW S_SNAP S_BENCH S_CMDS
S_ABOUT[w4k]="a writer on an empty image of 4 KiB objects (order 12, features 0x1), 40000 bytes: writes inside an object, across two and five, at the very end (the last partial object), reads of holes and of data, a discard of a whole object and of a part, write-zeroes inside and across objects, a discard that reaches the end of the image"
S_SIZE[w4k]=40000;  S_ORDER[w4k]=12; S_FEAT[w4k]=layering; S_RW[w4k]=1; S_SNAP[w4k]=0; S_BENCH[w4k]=0
S_CMDS[w4k]="verify 0 40000 --pattern zero
write 0 4096 --pattern rand:1
write 4000 300 --pattern rand:2
write 39990 10 --pattern rand:3
write 8192 20000 --pattern rand:4
verify 8192 20000 --pattern rand:4
verify 4000 300 --pattern rand:2
discard 4096 4096
discard 12388 100
zeroes 8190 8
zeroes 16384 4096
write 30000 1 --pattern byte:7
discard 36000 4000
read 0 40000"
S_ABOUT[snap64k]="a writer on an image of 64 KiB objects (order 16, features 0x21), 200000 bytes, that already has two snapshots when it is opened: every write, discard and write-zeroes carries the snapshot context (the OSD makes clones), including a discard of a whole object and of the last partial object"
S_SIZE[snap64k]=200000; S_ORDER[snap64k]=16; S_FEAT[snap64k]=layering,deep-flatten; S_RW[snap64k]=1; S_SNAP[snap64k]=2; S_BENCH[snap64k]=0
S_CMDS[snap64k]="write 0 70000 --pattern rand:11
write 65500 100 --pattern rand:12
write 199999 1 --pattern byte:9
write 131000 69000 --pattern rand:13
verify 131000 69000 --pattern rand:13
discard 65536 65536
zeroes 100000 5000
discard 196608 3392
read 0 200000"
S_ABOUT[rd64k]="a READER (profile R1, no --rw) on an image with the default feature set (0x3d: exclusive-lock, object-map, fast-diff) of 64 KiB objects, 131079 bytes, written by the stock tool before: header reads of the reader form, reads across objects, over holes and short objects, the last partial object"
S_SIZE[rd64k]=131079; S_ORDER[rd64k]=16; S_FEAT[rd64k]=default; S_RW[rd64k]=0; S_SNAP[rd64k]=0; S_BENCH[rd64k]=1
S_CMDS[rd64k]="read 0 131079
read 70000 1000
read 131070 9
read 65530 20"

iname() { echo "$PFXI$1"; }

make_user() {
  $A auth get client.$USERN >/dev/null 2>&1 && die "client.$USERN exists already (left over? run: $0 cleanup)"
  mkdir -p $WORK/keys; chmod 700 $WORK/keys
  $A auth get-or-create client.$USERN mon 'profile rbd' osd "profile rbd pool=$POOL" -o $KEYRING >/dev/null || die "cannot create client.$USERN"
  sudo -n chown $(id -u):$(id -g) $KEYRING; chmod 600 $KEYRING
  USER_CREATED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  say "created client.$USERN (key in $KEYRING, mode 600, never printed)"
}

state_snapshot() { # label
  local f=$WORK/state-$1.txt
  {
    echo "osd tree:"; $A osd tree -f json | python3 -c 'import sys,json;d=json.load(sys.stdin);print(sorted((n["name"],n.get("status"),n.get("reweight")) for n in d["nodes"] if n["type"]=="osd"))'
    echo "pools:"; $A osd pool ls detail -f json | python3 -c 'import sys,json;print(sorted((p["pool_name"],p["pg_num"],p["size"]) for p in json.load(sys.stdin)))'
    echo "upmap lines: $($A osd dump | grep -c 'pg_upmap')"
    echo "osd flags: $($A osd dump | grep '^flags')"
    $A health detail -f json | python3 -c 'import sys,json,hashlib;d=json.load(sys.stdin);c=sorted(d["checks"]);m=sorted(x["code"] for x in d.get("mutes",[]));print("health checks: %d, sha256 %s; mutes: %d, sha256 %s" % (len(c), hashlib.sha256(" ".join(c).encode()).hexdigest()[:16], len(m), hashlib.sha256(" ".join(m).encode()).hexdigest()[:16]))'
    echo "rbd images: $($R ls $POOL | sort | wc -l)"
    echo "rados objects: $(sudo -n rados -p $POOL ls | sort | wc -l), sha256 $(sudo -n rados -p $POOL ls | sort | sha256sum | cut -c1-16)"
    echo "auth entities: $($A auth ls 2>/dev/null | grep '^client\.\|^osd\.\|^mon\.\|^mgr\.' | sort | wc -l), sha256 $($A auth ls 2>/dev/null | grep '^client\.\|^osd\.\|^mon\.\|^mgr\.' | sort | sha256sum | cut -c1-16)"
    echo "config options set: $($A config dump -f json | python3 -c 'import sys,json,hashlib;d=json.load(sys.stdin);print("%d, sha256 %s" % (len(d), hashlib.sha256(json.dumps(sorted((x["section"],x["name"],x["value"]) for x in d)).encode()).hexdigest()[:16]))')"
  } > $f 2>&1
}

epoch_now() { $A osd stat -f json | python3 -c 'import sys,json;print(json.load(sys.stdin)["epoch"])'; }
# Creating and removing snapshots makes new OSD map epochs, some of them a moment after the command returns (the snapshot trimming of the
# image that was removed last): wait until the epoch has stood still for four seconds, so the session itself sees no map change.
settle_epoch() {
  local e last="" still=0 i
  for ((i = 0; i < 90; i++)); do
    e=$(epoch_now)
    if [ "$e" = "$last" ]; then still=$((still + 1)); else still=0; last=$e; fi
    [ $still -ge 4 ] && return 0
    sleep 1
  done
  die "the OSD map epoch does not settle"
}

# ---- one session --------------------------------------------------------------------------------------------------------------------------
run_session() { # name
  local n=$1 img; img=$(iname $n)
  local feat=${S_FEAT[$n]} cargs rw=""
  if [ "$feat" = default ]; then cargs=""; else cargs="--image-feature $feat"; fi
  $R create $POOL/$img --size ${S_SIZE[$n]}B --order ${S_ORDER[$n]} $cargs >/dev/null || die "cannot create $img"
  if [ "${S_BENCH[$n]}" = 1 ]; then
    $R bench --io-type write --io-size 4096 --io-threads 1 --io-total 49152 --io-pattern rand $POOL/$img >/dev/null 2>&1 || die "rbd bench failed"
  fi
  local k
  for ((k = 1; k <= ${S_SNAP[$n]}; k++)); do $R snap create $POOL/$img@s$k >/dev/null || die "snap create"; done
  rm -f $WORK/export/$n.before.bin $WORK/export/$n.after.bin
  mkdir -p $WORK/export $WORK/gt $WORK/pcap $WORK/run $WORK/meta
  $R export $POOL/$img $WORK/export/$n.before.bin >/dev/null 2>&1 || die "export (before) failed"
  $R info $POOL/$img --format json > $WORK/gt/$n.info.json
  $R snap ls $POOL/$img --format json > $WORK/gt/$n.snaps.json
  printf '%s\n' "${S_CMDS[$n]}" > $WORK/run/$n.script
  [ "${S_RW[$n]}" = 1 ] && rw="--rw"
  settle_epoch
  local ep0; ep0=$(epoch_now)
  local start; start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  sudo -n rm -f $WORK/pcap/$n.pcap
  $NS ping -c1 -W1 10.77.0.10 >/dev/null 2>&1; sudo -n ping -c1 -W1 -I $VETH_H $NET_C >/dev/null 2>&1
  sudo -n tcpdump -i $VETH_H -s 0 -U -B 16384 -w $WORK/pcap/$n.pcap host $NET_C >/dev/null 2>$WORK/pcap/$n.err &
  sleep 1.5
  $NS "$WR" --mon "$MON" --user $USERN --keyring $KEYRING --pool $POOL --image $img $rw --depth 1 --io-size 1M --hdr-refresh 0 shell \
        < $WORK/run/$n.script > $WORK/run/$n.out 2> $WORK/run/$n.err
  local rc=$?
  sleep 1.5
  sudo -n pkill -INT -f "tcpdump -i $VETH_H -s 0 -U -B 16384 -w $WORK/pcap/$n.pcap"; sleep 1.5
  sudo -n chown -R $(id -un):$(id -gn) $WORK/pcap 2>/dev/null
  local end ep1 dropped
  end=$(date -u +%Y-%m-%dT%H:%M:%SZ); ep1=$(epoch_now)
  dropped=$(grep -h 'packets dropped by kernel' $WORK/pcap/$n.err | awk '{print $1}')
  [ "$rc" = 0 ] || die "wr-rbd failed in session $n (exit $rc): $(tail -3 $WORK/run/$n.err)"
  [ "$ep0" = "$ep1" ] || die "the OSD map changed during session $n ($ep0 -> $ep1): the capture would hold a resend"
  $R export $POOL/$img $WORK/export/$n.after.bin >/dev/null 2>&1 || die "export (after) failed"
  $R info $POOL/$img --format json > $WORK/gt/$n.info_after.json
  S_START=$start S_END=$end S_EP0=$ep0 S_EP1=$ep1 S_DROP="${dropped:-0}" S_NAME=$n S_ABOUT_TXT="${S_ABOUT[$n]}" S_WRITABLE="${S_RW[$n]}" S_BENCH_ON="${S_BENCH[$n]}" python3 - <<'PY'
import json, os
w = os.environ["WORK"]; n = os.environ["S_NAME"]
json.dump(dict(start=os.environ["S_START"], end=os.environ["S_END"], epoch0=int(os.environ["S_EP0"]), epoch1=int(os.environ["S_EP1"]),
               dropped=int(os.environ["S_DROP"]), about=os.environ["S_ABOUT_TXT"], writable=os.environ["S_WRITABLE"] == "1",
               bench=os.environ["S_BENCH_ON"] == "1"), open("%s/meta/%s.json" % (w, n), "w"), indent=1)
PY
  say "session $n done: $(stat -c %s $WORK/pcap/$n.pcap) bytes of pcap, dropped by kernel: ${dropped:-0}, epoch $ep0"
  $R snap purge $POOL/$img >/dev/null 2>&1
  $R rm $POOL/$img >/dev/null 2>&1
}
export WORK

cleanup() {
  say "clean-up"
  net_teardown
  for n in $SESSIONS; do
    $R snap purge $POOL/$(iname $n) >/dev/null 2>&1
    $R rm $POOL/$(iname $n) >/dev/null 2>&1
  done
  $A auth del client.$USERN >/dev/null 2>&1
}

verify_gone() {
  USER_GONE=""
  if $A auth get client.$USERN >/dev/null 2>&1; then die "client.$USERN still exists after the clean-up"; fi
  $A auth ls 2>/dev/null | grep -q "client.$USERN" && die "client.$USERN is still in the auth list"
  USER_GONE="ceph auth get client.$USERN fails (ENOENT) and the entity is not in the auth list, checked $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  $R ls $POOL | grep -q wrtest-imgio && die "an image of the capture is left"
  ip netns list | grep -q $NSNAME && die "the namespace is left"
  pgrep -f "tcpdump -i $VETH_H" >/dev/null && die "a tcpdump is still running"
  return 0
}

write_plan() {
  USER_CREATED=$USER_CREATED USER_GONE="$USER_GONE" python3 - <<'PY'
import json, os
w = os.environ["WORK"]
plan = dict(sessions=["w4k", "snap64k", "rd64k"],
            index=dict(about="what the winrbd core puts on the wire for scripted image I/O, with the real OSD's replies and the stock export of the result",
                       made=os.popen("date -u +%Y-%m-%d").read().strip(), cluster="Ceph v20.2.5 lab cluster, one VM, 3 OSDs, replicated pool winrbd",
                       user=dict(name="client.vec-imgio", caps="mon 'profile rbd', osd 'profile rbd pool=winrbd'", created=os.environ["USER_CREATED"],
                                 deleted=True, verified_gone=os.environ["USER_GONE"], key_published=False)))
json.dump(plan, open(w + "/plan.json", "w"), indent=1)
PY
}

run_all() {
  local out=${1:-$WORK/imgio}
  [ -x "$WR" ] || die "wr-rbd not found at $WR (build the harness first, or set WR)"
  mkdir -p $WORK/pcap $WORK/meta $WORK/gt $WORK/run $WORK/export
  state_snapshot before
  $A osd stat | grep -Eq '^3 osds: 3 up.*, 3 in' || die "not every OSD is up and in before the start"
  trap 'cleanup' EXIT
  make_user
  net_setup
  for n in $SESSIONS; do run_session $n; done
  trap - EXIT
  cleanup
  state_snapshot after
  verify_gone
  write_plan
  mkdir -p "$out"
  {
    echo "# revert proof of capture_imgio.sh, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# the facts of the lab before the run and after the clean-up (osd tree, pools, upmap lines, flags, health checks, images, objects, auth entities,"
    echo "# every explicitly set configuration option), then the lines that differ"
    echo "--- before:"; cat $WORK/state-before.txt
    echo "--- after:"; cat $WORK/state-after.txt
    echo "--- diff:"
    diff $WORK/state-before.txt $WORK/state-after.txt && echo "(none)"
    echo "--- throwaway user: $USER_GONE"
  } > "$out/revert-proof.txt"
  python3 -I $SCRIPTS/check_imgio.py extract --work $WORK --out "$out" || die "the extraction failed"
  local key; key=$(awk '/key =/ {print $3}' $KEYRING 2>/dev/null)
  if [ -n "$key" ] && grep -rqF "$key" "$out"; then die "the user's key text is in the vector tree"; fi
  rm -f $KEYRING
  python3 -I $SCRIPTS/check_imgio.py check --dir "$out"
  say "done: $out"
}

case ${1:-help} in
  run) run_all "${2:-}";;
  cleanup) cleanup;;
  *) sed -n '2,25p' "$0";;
esac
