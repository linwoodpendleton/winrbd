#!/bin/bash
# SPDX-License-Identifier: MIT
#
# capture_secure.sh - the lab captures of module vectors-sec (harness/vectors/public/secure/): what the winrbd CORE itself puts on the wire in msgr2
# SECURE mode (AES-128-GCM framing) against a real Ceph v20.2.5 monitor and OSDs, and what the servers answer when they refuse the mode that was offered.
#
#   1. one session per cephx key type (aes256k = the cluster default, aes = the legacy 16-byte key): the wr-rbd tool (harness/host/tools/wr-rbd.c, the core on
#      the Linux host) in `shell` mode with --mode secure (monitor AND OSDs), inside a network namespace under tcpdump: open an image, write 1 MiB, read it back and
#      verify it, a small unaligned write, a partial discard, a whole-object discard. Every connection of the session (the monitor and the OSDs the image's
#      objects live on) is kept: the bytes of both directions;
#   2. the mode refusals (docs/spec/msgr2-secure-mode.md 6.4): a monitor that allows only `secure` against a client that offers only `crc`, a monitor that
#      allows only `crc` against a secure-only client, and the same for one OSD. Making the daemons refuse needs their service-mode options (they are read at
#      daemon start, sec.md 2.9) set and the daemon restarted; the script sets them for a few minutes, captures the refused attempts (the AUTH_BAD_METHOD frame
#      with its `result`), puts the options back and restarts the daemons again. Only the monitor and the one OSD the header object lives on are touched.
#
# Runs INSIDE the disposable lab VM, as a user with passwordless sudo, with the stock tools (ceph, rbd, tcpdump, systemctl) and a built harness (wr-rbd). Everything it
# creates is named wrtest-vsec-* or client.vec-sec-k* and is removed again. The two cephx users are THROWAWAY users created for the capture and deleted at the end
# (`ceph auth get` must fail, which the script verifies before it writes the vectors); their keys are published with the vectors because they authenticate
# nothing any more and the independent checker needs them to recompute the connection secrets. The lab's regular users (winrbd, winrbd-aes) and the admin key
# are never used from inside the capture namespace (the admin key only runs the stock setup, state and clean-up commands) and are never part of the output.
#
#     WR=<path of wr-rbd> capture_secure.sh run [OUTDIR]    the whole thing; the vector tree is written to OUTDIR (default $WORK/secure)
#     capture_secure.sh cleanup                              put back what an interrupted run left (options, daemons, users, images, namespace)
#
# Environment: WORK (default $HOME/w/vsec-cap)  POOL (default winrbd)  WR (default <repo>/build/harness/wr-rbd)  SCRIPTS (default: the directory of this file,
# where check_secure_core.py is)  MON (default 10.77.0.10:3300)  NO_REFUSALS=1 (skip part 2: no daemon is touched).
#
# Cluster rules kept: the only options changed are ms_mon_service_mode (monitor) and ms_service_mode (one OSD), each snapshotted first and put back exactly
# (removed when it was not set before); the script refuses to start when any ms_* option is set already (somebody else is working on them), checks that all
# OSDs are up and in before it starts and that the cluster is back to the same state after (HEALTH checks, mutes, OSD tree, pools, options, images, auth entities),
# and writes the proof to revert-proof.txt.
set -u

WORK=${WORK:-$HOME/w/vsec-cap}
POOL=${POOL:-winrbd}
SCRIPTS=${SCRIPTS:-$(cd "$(dirname "$0")" && pwd)}
REPO=$(cd "$SCRIPTS/../../../.." && pwd)
WR=${WR:-$REPO/build/harness/wr-rbd}
MON=${MON:-10.77.0.10:3300}
NSNAME=vscns
VETH_H=vsc0
VETH_C=vsc1
NET_H=192.0.2.201   # the namespace's own point-to-point net (documentation addresses; the lab's 10.77.0.x is reached through the host)
NET_C=192.0.2.202
NS="sudo -n ip netns exec $NSNAME"
A="sudo -n ceph"
R="sudo -n rbd"
PFXI=wrtest-vsec-
USERS="k2 k1"            # k2 = aes256k (the default), k1 = aes (legacy)
declare -A KTYPE=([k2]=aes256k [k1]=aes)
SESSION_SCRIPT="write 0 1M --pattern rand:21
verify 0 1M --pattern rand:21
write 2000000 100 --pattern rand:23
discard 262144 262144
discard 0 4M"

die() { echo "capture_secure: $*" >&2; exit 1; }
say() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
uname_of() { echo "vec-sec-$1"; }
keyring_of() { echo "$WORK/keys/client.$(uname_of $1).keyring"; }
image_of() { echo "$PFXI$1"; }

# ---- the namespace ----------------------------------------------------------------------------------------------------------------------
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

# ---- the cluster state --------------------------------------------------------------------------------------------------------------------
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
    echo "mode options in effect: mon service '$($A config get mon ms_mon_service_mode)', osd service '$($A config get osd ms_service_mode)', ms_* options set: $($A config dump | grep -c ' ms_')"
    echo "ceph units: $(systemctl list-units 'ceph-*' --no-legend | awk '{print $1, $3, $4}' | sort | sha256sum | cut -c1-16)"
  } > $f 2>&1
}

epoch_now() { $A osd stat -f json | python3 -c 'import sys,json;print(json.load(sys.stdin)["epoch"])'; }
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

wait_quorum() {
  local i
  for ((i = 0; i < 90; i++)); do
    timeout 10 sudo -n ceph quorum_status >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}
wait_clean() { # up to 180 s: every OSD up and in, every PG active+clean
  local i
  for ((i = 0; i < 90; i++)); do
    if timeout 15 sudo -n ceph -s -f json 2>/dev/null | python3 -c '
import sys, json
d = json.load(sys.stdin)
o = d["osdmap"]
p = d["pgmap"]
tot = p["num_pgs"]
ac = sum(s["count"] for s in p.get("pgs_by_state", []) if s["state_name"] == "active+clean")
sys.exit(0 if (o["num_osds"] == o["num_up_osds"] == o["num_in_osds"] and tot > 0 and ac == tot) else 1)' 2>/dev/null; then return 0; fi
    sleep 2
  done
  return 1
}

# ---- the mode options (the only thing this script changes on the cluster) ----------------------------------------------------------------------
# Each option is changed through opt_set, which remembers what was there (set or not, and its value) so that opt_restore_all puts back exactly that.
OPT_WHO=(); OPT_NAME=(); OPT_HAD=(); OPT_VAL=(); OPT_UNIT=()
opt_set() { # who name value unit
  local who=$1 name=$2 val=$3 unit=$4 had=0 old=""
  old=$($A config dump -f json | python3 -c '
import sys, json
for x in json.load(sys.stdin):
    if x["section"] == sys.argv[1] and x["name"] == sys.argv[2]:
        print(x["value"]); break
' "$who" "$name")
  [ -n "$old" ] && had=1
  OPT_WHO+=("$who"); OPT_NAME+=("$name"); OPT_HAD+=("$had"); OPT_VAL+=("$old"); OPT_UNIT+=("$unit")
  $A config set "$who" "$name" "$val" >/dev/null || die "cannot set $name for $who"
}
restart_unit() { # unit
  say "restarting $1"
  sudo -n systemctl restart "$1" || die "cannot restart $1"
}
opt_restore_all() {
  local i n=${#OPT_WHO[@]} unit restarted=" "
  for ((i = n - 1; i >= 0; i--)); do
    if [ "${OPT_HAD[$i]}" = 1 ]; then
      $A config set "${OPT_WHO[$i]}" "${OPT_NAME[$i]}" "${OPT_VAL[$i]}" >/dev/null
    else
      $A config rm "${OPT_WHO[$i]}" "${OPT_NAME[$i]}" >/dev/null
    fi
  done
  for ((i = n - 1; i >= 0; i--)); do
    unit=${OPT_UNIT[$i]}
    case "$restarted" in *" $unit "*) continue;; esac
    restarted="$restarted$unit "
    sudo -n systemctl restart "$unit"
    wait_quorum
  done
  OPT_WHO=(); OPT_NAME=(); OPT_HAD=(); OPT_VAL=(); OPT_UNIT=()
  [ $n -gt 0 ] && { wait_quorum; wait_clean || echo "WARNING: the cluster is not clean 180 s after the restore" >&2; }
  true
}

# ---- users and images -----------------------------------------------------------------------------------------------------------------
make_user() { # k
  local k=$1 kt=""
  $A auth get client.$(uname_of $k) >/dev/null 2>&1 && die "client.$(uname_of $k) exists already (left over? run: $0 cleanup)"
  mkdir -p $WORK/keys; chmod 700 $WORK/keys
  [ "${KTYPE[$k]}" = aes ] && kt="--key_type aes"
  $A auth get-or-create client.$(uname_of $k) mon 'profile rbd' osd "profile rbd pool=$POOL" $kt -o $(keyring_of $k) >/dev/null || die "cannot create client.$(uname_of $k)"
  sudo -n chown $(id -u):$(id -g) $(keyring_of $k); chmod 600 $(keyring_of $k)
  USER_CREATED[$k]=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  say "created client.$(uname_of $k) (${KTYPE[$k]}, key in $(keyring_of $k), mode 600, never printed)"
}
declare -A USER_CREATED

# ---- one secure session --------------------------------------------------------------------------------------------------------------------
run_session() { # k
  local k=$1 img; img=$(image_of $k)
  $R create $POOL/$img --size 4M --object-size 4M --image-feature layering >/dev/null 2>&1 || die "cannot create $img"
  mkdir -p $WORK/pcap $WORK/run $WORK/meta
  printf '%s\n' "$SESSION_SCRIPT" > $WORK/run/$k.script
  settle_epoch
  local ep0; ep0=$(epoch_now)
  local start; start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  sudo -n rm -f $WORK/pcap/$k.pcap
  $NS ping -c1 -W1 10.77.0.10 >/dev/null 2>&1; sudo -n ping -c1 -W1 -I $VETH_H $NET_C >/dev/null 2>&1
  sudo -n tcpdump -i $VETH_H -s 0 -U -B 16384 -w $WORK/pcap/$k.pcap host $NET_C >/dev/null 2>$WORK/pcap/$k.err &
  sleep 1.5
  $NS "$WR" --mon "$MON" --user "$(uname_of $k)" --keyring "$(keyring_of $k)" --pool $POOL --image $img --rw --depth 1 --io-size 1M --hdr-refresh 0 \
        --mode secure --require-mode secure shell < $WORK/run/$k.script > $WORK/run/$k.out 2> $WORK/run/$k.err
  local rc=$?
  sleep 1.5
  sudo -n pkill -INT -f "tcpdump -i $VETH_H -s 0 -U -B 16384 -w $WORK/pcap/$k.pcap"; sleep 1.5
  sudo -n chown -R $(id -un):$(id -gn) $WORK/pcap 2>/dev/null
  local end ep1 dropped
  end=$(date -u +%Y-%m-%dT%H:%M:%SZ); ep1=$(epoch_now)
  dropped=$(grep -h 'packets dropped by kernel' $WORK/pcap/$k.err | awk '{print $1}')
  [ "$rc" = 0 ] || die "wr-rbd failed in session $k (exit $rc): $(tail -3 $WORK/run/$k.err)"
  [ "$ep0" = "$ep1" ] || die "the OSD map changed during session $k ($ep0 -> $ep1): the capture would hold a resend"
  grep -q 'conns_crc=0 ' $WORK/run/$k.out || die "session $k had a crc connection"
  S_START=$start S_END=$end S_EP0=$ep0 S_EP1=$ep1 S_DROP="${dropped:-0}" S_NAME=$k S_KT=${KTYPE[$k]} S_USER=client.$(uname_of $k) S_IMAGE=$img \
    S_CREATED="${USER_CREATED[$k]}" python3 - <<'PY'
import json, os
w = os.environ["WORK"]; n = os.environ["S_NAME"]
json.dump(dict(start=os.environ["S_START"], end=os.environ["S_END"], epoch0=int(os.environ["S_EP0"]), epoch1=int(os.environ["S_EP1"]),
               dropped=int(os.environ["S_DROP"]), key_type=os.environ["S_KT"], entity=os.environ["S_USER"], image=os.environ["S_IMAGE"],
               user_created=os.environ["S_CREATED"]), open("%s/meta/%s.json" % (w, n), "w"), indent=1)
PY
  say "session $k done: $(stat -c %s $WORK/pcap/$k.pcap) bytes of pcap, dropped by kernel: ${dropped:-0}, epoch $ep0"
  $R rm $POOL/$img >/dev/null 2>&1
}
export WORK

# ---- the refusals --------------------------------------------------------------------------------------------------------------------------------
# One refused attempt: wr-rbd with the given offers against the cluster as configured right now, under tcpdump, bounded by --timeout.
# $1 = name, $2 = key id (k2 | k1), $3 = mon offer, $4 = osd offer, $5 = which daemon is expected to refuse (mon | osd)
refused_attempt() {
  local name=$1 k=$2 moff=$3 ooff=$4 who=$5 img; img=$(image_of ref)
  mkdir -p $WORK/pcap $WORK/run $WORK/meta
  sudo -n rm -f $WORK/pcap/$name.pcap
  $NS ping -c1 -W1 10.77.0.10 >/dev/null 2>&1
  sudo -n tcpdump -i $VETH_H -s 0 -U -B 16384 -w $WORK/pcap/$name.pcap host $NET_C >/dev/null 2>$WORK/pcap/$name.err &
  sleep 1.5
  echo "info" | $NS "$WR" --mon "$MON" --user "$(uname_of $k)" --keyring "$(keyring_of $k)" --pool $POOL --image $img --timeout 6000 --mode "$moff" --mode-osd "$ooff" shell \
        > $WORK/run/$name.out 2> $WORK/run/$name.err
  local rc=$?
  sleep 1
  sudo -n pkill -INT -f "tcpdump -i $VETH_H -s 0 -U -B 16384 -w $WORK/pcap/$name.pcap"; sleep 1.5
  sudo -n chown -R $(id -un):$(id -gn) $WORK/pcap 2>/dev/null
  grep -q 'M2_BAD_METHOD' $WORK/run/$name.out $WORK/run/$name.err || die "attempt $name was not refused with M2_BAD_METHOD (exit $rc): $(tail -3 $WORK/run/$name.out | tr '\n' ' ')"
  echo "$who" > $WORK/meta/$name.who
  say "attempt $name ($k, mon offer $moff, osd offer $ooff) refused by the $who, exit $rc"
}

LOCK=/tmp/winrbd-lab-mode-options.lock   # advisory: whoever changes the ms_* options and restarts daemons holds it (the live matrix script may use it too)
refusal_phase() {
  local img osd unit fsid host k
  mkdir $LOCK 2>/dev/null || die "$LOCK exists: somebody else is changing the mode options (or an earlier run died: remove it after checking the cluster)"
  echo "capture_secure.sh pid $$ $(date -u +%Y-%m-%dT%H:%M:%SZ)" > $LOCK/owner
  [ "$($A config dump | grep -c ' ms_')" = 0 ] || die "a ms_* option is set: somebody else is working on the mode options"
  img=$(image_of ref)
  $R create $POOL/$img --size 4M --object-size 4M --image-feature layering >/dev/null 2>&1 || die "cannot create $img"
  fsid=$($A fsid); host=$(hostname -s)
  # 1. the monitor allows only secure; the client offers only crc
  say "monitor: service mode secure only"
  opt_set mon ms_mon_service_mode secure ceph-$fsid@mon.$host.service
  restart_unit ceph-$fsid@mon.$host.service; wait_quorum || die "no quorum after the monitor restart"
  for k in $USERS; do refused_attempt mon-secure-only-$k $k crc crc mon; done
  # 2. the monitor allows only crc; the client offers only secure
  say "monitor: service mode crc only"
  $A config set mon ms_mon_service_mode crc >/dev/null
  restart_unit ceph-$fsid@mon.$host.service; wait_quorum || die "no quorum after the monitor restart"
  for k in $USERS; do refused_attempt mon-crc-only-$k $k secure secure mon; done
  # 3. back
  opt_restore_all
  # 4. one OSD (the primary of the image's id object, where the client's first OSD request goes)
  osd=$($A osd map $POOL rbd_id.$img -f json | python3 -c 'import sys,json;print(json.load(sys.stdin)["acting_primary"])')
  [ -n "$osd" ] || die "cannot find the OSD of rbd_id.$img"
  unit=ceph-$fsid@osd.$osd.service
  say "osd.$osd: service mode secure only"
  opt_set osd.$osd ms_service_mode secure $unit
  restart_unit $unit; wait_quorum; wait_clean || die "the cluster is not clean after the restart of osd.$osd"
  for k in $USERS; do refused_attempt osd-secure-only-$k $k crc crc osd; done
  say "osd.$osd: service mode crc only"
  $A config set osd.$osd ms_service_mode crc >/dev/null
  restart_unit $unit; wait_quorum; wait_clean || die "the cluster is not clean after the restart of osd.$osd"
  for k in $USERS; do refused_attempt osd-crc-only-$k $k secure secure osd; done
  opt_restore_all
  echo "$osd" > $WORK/meta/refusal-osd
  $R rm $POOL/$img >/dev/null 2>&1
  rm -rf $LOCK
}

# ---- clean-up and the proof --------------------------------------------------------------------------------------------------------------------
# A run that died hard (kill -9, a lost ssh session, a reboot of the VM) took its option bookkeeping (the OPT_* arrays) with it, so `cleanup` in a fresh process
# has nothing to restore from memory. The cluster itself tells: run_all refuses to start while any ms_* option is set, so before a run there was none, and
# the two options this script sets (ms_mon_service_mode of the monitor, ms_service_mode of an OSD) are removed when they are found, and the daemon that read
# them at its start is restarted. Only when the lock of a run exists and the run that owns it is not alive any more.
orphan_restore() {
  [ -f $LOCK/owner ] || return 0
  local pid fsid host who name u units=""
  pid=$(sed -n 's/^capture_secure.sh pid \([0-9][0-9]*\) .*/\1/p' $LOCK/owner)
  if [ -n "$pid" ] && [ "$pid" != "$$" ] && kill -0 "$pid" 2>/dev/null; then
    echo "capture_secure: the run of pid $pid is still going: its options are not touched" >&2
    return 0
  fi
  fsid=$($A fsid); host=$(hostname -s)
  while read -r who name; do
    case "$who/$name" in
      mon/ms_mon_service_mode) u=ceph-$fsid@mon.$host.service;;
      osd.*/ms_service_mode) u=ceph-$fsid@$who.service;;
      *) continue;;
    esac
    say "removing $name of $who (a run of this script died with it set)"
    $A config rm "$who" "$name" >/dev/null
    units="$units $u"
  done < <($A config dump -f json | python3 -c 'import sys,json
for x in json.load(sys.stdin):
    print(x["section"], x["name"])')
  for u in $units; do
    restart_unit "$u"
    wait_quorum
  done
  [ -n "$units" ] && { wait_clean || echo "WARNING: the cluster is not clean 180 s after the restore" >&2; }
  rm -rf $LOCK
}

cleanup() {
  say "clean-up"
  net_teardown
  opt_restore_all
  orphan_restore
  [ -f $LOCK/owner ] && grep -q "pid $$ " $LOCK/owner && rm -rf $LOCK
  local k
  for k in $USERS ref; do $R rm $POOL/$(image_of $k) >/dev/null 2>&1; done
  for k in $USERS; do $A auth del client.$(uname_of $k) >/dev/null 2>&1; done
  # the throwaway legacy-key user raised the count of the insecure-key warning, which drops its mute: put a mute back that was there before
  if [ -f $WORK/state-before.mutes ]; then
    local code
    for code in $(cat $WORK/state-before.mutes); do
      $A health detail -f json | python3 -c 'import sys,json;sys.exit(0 if any(m["code"]==sys.argv[1] for m in json.load(sys.stdin).get("mutes",[])) else 1)' $code || $A health mute $code >/dev/null 2>&1
    done
  fi
}

verify_gone() {
  USER_GONE=""
  local k
  for k in $USERS; do
    if $A auth get client.$(uname_of $k) >/dev/null 2>&1; then die "client.$(uname_of $k) still exists after the clean-up"; fi
    $A auth ls 2>/dev/null | grep -q "client.$(uname_of $k)" && die "client.$(uname_of $k) is still in the auth list"
  done
  USER_GONE="ceph auth get fails (ENOENT) for client.vec-sec-k2 and client.vec-sec-k1 and neither is in the auth list, checked $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  $R ls $POOL | grep -q wrtest-vsec && die "an image of the capture is left"
  ip netns list | grep -q $NSNAME && die "the namespace is left"
  pgrep -f "tcpdump -i $VETH_H" >/dev/null && die "a tcpdump is still running"
  [ "$($A config dump | grep -c ' ms_')" = 0 ] || die "a ms_* option is still set"
  return 0
}

write_plan() {
  USER_GONE="$USER_GONE" python3 - <<'PY'
import json, os
w = os.environ["WORK"]
def meta(n):
    return json.load(open("%s/meta/%s.json" % (w, n)))
plan = dict(about="what the winrbd core puts on the wire in msgr2 secure mode against a real Ceph v20.2.5 monitor and OSDs, and what the servers answer when they refuse a mode",
            made=os.popen("date -u +%Y-%m-%d").read().strip(), cluster="Ceph v20.2.5 lab cluster, one VM, 3 OSDs, replicated pool winrbd",
            users=dict((n, dict(meta(n), deleted=True)) for n in ("k2", "k1")), verified_gone=os.environ["USER_GONE"], key_published=True)
if os.path.exists(w + "/meta/refusal-osd"):
    plan["refusal_osd"] = int(open(w + "/meta/refusal-osd").read().strip())
json.dump(plan, open(w + "/plan.json", "w"), indent=1)
PY
}

run_all() {
  local out=${1:-$WORK/secure} k
  [ -x "$WR" ] || die "wr-rbd not found at $WR (build the harness first, or set WR)"
  mkdir -p $WORK/pcap $WORK/meta $WORK/run
  $A osd stat | grep -Eq '^3 osds: 3 up.*, 3 in' || die "not every OSD is up and in before the start"
  [ "$($A config dump | grep -c ' ms_')" = 0 ] || die "a ms_* option is set already: somebody else is working on the mode options, not starting"
  state_snapshot before
  $A health detail -f json | python3 -c 'import sys,json;print("\n".join(m["code"] for m in json.load(sys.stdin).get("mutes",[])))' > $WORK/state-before.mutes
  trap 'cleanup' EXIT
  net_setup
  for k in $USERS; do make_user $k; done
  for k in $USERS; do run_session $k; done
  if [ "${NO_REFUSALS:-0}" != 1 ]; then refusal_phase; fi
  trap - EXIT
  cleanup
  settle_epoch
  state_snapshot after
  verify_gone
  write_plan
  mkdir -p "$out"
  {
    echo "# revert proof of capture_secure.sh, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# the facts of the lab before the run and after the clean-up (osd tree, pools, upmap lines, flags, health checks and mutes, images, objects, auth"
    echo "# entities, every explicitly set configuration option, the mode options in effect, the state of the ceph units), then the lines that differ"
    echo "--- before:"; cat $WORK/state-before.txt
    echo "--- after:"; cat $WORK/state-after.txt
    echo "--- diff:"
    diff $WORK/state-before.txt $WORK/state-after.txt && echo "(none)"
    echo "--- throwaway users: $USER_GONE"
  } > "$out/revert-proof.txt"
  python3 -I $SCRIPTS/check_secure_core.py extract --work $WORK --out "$out" || die "the extraction failed"
  for k in $USERS; do rm -f $(keyring_of $k); done
  python3 -I $SCRIPTS/check_secure_core.py check --dir "$out"
  say "done: $out"
}

case ${1:-help} in
  run) run_all "${2:-}";;
  cleanup) cleanup;;
  *) sed -n '2,32p' "$0";;
esac
