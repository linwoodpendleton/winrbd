#!/bin/bash
# SPDX-License-Identifier: MIT
# Public vector capture driver. Runs inside the disposable lab VM as a user with passwordless sudo.
# Each client command runs in a network namespace (client address 10.78.0.2); tcpdump runs on the host
# side of the veth pair, one pcap per session. Usage: pubdriver.sh <mode>   (mode: setup | sessions | renew | teardown)
set -u
ROOT=${ROOT:-$HOME/capture-work}
BASE=$ROOT/out
PCAP=$BASE/pcap; LOGS=$BASE/logs; STD=$BASE/stdout; CMDS=$BASE/cmd; DATA=$BASE/data; KEYS=$ROOT/keys
mkdir -p $PCAP $LOGS $STD $CMDS $DATA $KEYS
NS="sudo -n ip netns exec t0c"
IMG1=winrbd/img-v1; IMGD=winrbd/img-default
A="sudo -n ceph"
epoch() { $A osd stat -f json | python3 -c 'import sys,json;print(json.load(sys.stdin)["epoch"])'; }

net_setup() {
  sudo -n ip netns add t0c
  sudo -n ip link add t0v0 type veth peer name t0v1
  sudo -n ip link set t0v1 netns t0c
  sudo -n ip addr add 10.78.0.1/24 dev t0v0
  sudo -n ip link set t0v0 up
  $NS ip addr add 10.78.0.2/24 dev t0v1
  $NS ip link set t0v1 up
  $NS ip link set lo up
  $NS ip route add default via 10.78.0.1
}
net_teardown() {
  sudo -n pkill -INT tcpdump 2>/dev/null
  sudo -n ip netns del t0c 2>/dev/null
  sudo -n ip link del t0v0 2>/dev/null
  true
}

mkopts() { # tool
  OPTS=(-n client.$USERN --keyring $KEYS/ceph.client.$USERN.keyring
        --debug_ms 5 --debug_auth $DAUTH --log_to_file=true --log_to_stderr=false
        --log_file=$LOGS/$SESS.$N.$1.log)
  case $MODE in
    crc) OPTS+=(--ms_client_mode crc --ms_mon_client_mode crc);;
    sec) OPTS+=(--ms_client_mode secure --ms_mon_client_mode secure);;
    def) ;;
  esac
}
begin() { # name user keytype mode dauth description
  SKIP=0
  if [ -n "${ONLY:-}" ] && ! echo " $ONLY " | grep -q " $1 "; then SKIP=1; return; fi
  # a re-run replaces the earlier record of the same session
  sed -i "/^$1\t/d" $BASE/sessions.tsv $BASE/epochs.tsv 2>/dev/null
  SESS=$1; USERN=$2; KT=$3; MODE=$4; DAUTH=$5; DESC=$6; N=0
  : > $STD/$SESS.out
  { echo "session: $SESS"; echo "description: $DESC"; echo "user: client.$USERN  key_type: $KT"
    echo "mode: $MODE (crc = --ms_client_mode crc --ms_mon_client_mode crc; sec = both secure; def = no mode options)"
    echo "debug: ms=5 auth=$DAUTH"; echo "netns client ip: 10.78.0.2; capture iface: t0v0 (host side of veth), filter 'host 10.78.0.2'"
    echo "commands (common options added to each: -n client.$USERN --keyring <keyring> --debug_ms 5 --debug_auth $DAUTH --log_file <per-command log> plus the mode options):"; } > $CMDS/$SESS.cmd
  START=$(date -u +%Y-%m-%dT%H:%M:%SZ); EP0=$(epoch)
  sudo -n rm -f $PCAP/$SESS.pcap
  # warm both ARP caches first so that no ARP frames land in the capture
  $NS ping -c1 -W1 10.77.0.10 >/dev/null 2>&1; sudo -n ping -c1 -W1 -I t0v0 10.78.0.2 >/dev/null 2>&1
  sudo -n tcpdump -i t0v0 -s 0 -U -B 16384 -w $PCAP/$SESS.pcap host 10.78.0.2 >/dev/null 2>$STD/$SESS.tcpdump.err &
  sleep 1.5
}
cl() { # tool args...
  [ "$SKIP" = 1 ] && return
  local tool=$1; shift
  N=$((N+1)); mkopts $tool
  echo "  [$N] $tool $*" >> $CMDS/$SESS.cmd
  echo "### [$N] $tool $*" >> $STD/$SESS.out
  $NS timeout 120 $tool "${OPTS[@]}" "$@" >> $STD/$SESS.out 2>&1
  echo "### rc=$?" >> $STD/$SESS.out
}
finish() {
  [ "$SKIP" = 1 ] && return
  sleep 1.5
  sudo -n pkill -INT -f "tcpdump -i t0v0 -s 0 -U -B 16384 -w $PCAP/$SESS.pcap"; sleep 1.5
  sudo -n chown -R $(id -un):$(id -gn) $PCAP $LOGS 2>/dev/null
  END=$(date -u +%Y-%m-%dT%H:%M:%SZ); EP1=$(epoch)
  local sz=$(stat -c %s $PCAP/$SESS.pcap)
  local pk=$(tcpdump -nr $PCAP/$SESS.pcap 2>/dev/null | wc -l)
  printf '%s\t%s\tclient.%s\t%s\t%s\tms=5,auth=%s\t%s\t%s\t%s\t%s\t%s\n' "$SESS" "$KT" "$USERN" "$MODE" "$N" "$DAUTH" "$START" "$END" "$sz" "$pk" "$DESC" >> $BASE/sessions.tsv
  printf '%s\t%s\t%s\n' "$SESS" "$EP0" "$EP1" >> $BASE/epochs.tsv
  echo "done $SESS pkts=$pk bytes=$sz epoch $EP0 -> $EP1; tcpdump: $(grep -h 'dropped by kernel' $STD/$SESS.tcpdump.err | tr '\n' ' ')"
}
pyidle() { # secs  (python rados client in the namespace)
  [ "$SKIP" = 1 ] && return
  N=$((N+1)); echo "  [$N] python3 pubidle.py $USERN <keyring> $MODE $1" >> $CMDS/$SESS.cmd
  $NS python3 $ROOT/pubidle.py $USERN $KEYS/ceph.client.$USERN.keyring $MODE $1 $LOGS/$SESS.$N.python.log >> $STD/$SESS.out 2>&1
}

mkdata() {
python3 - <<PY
def pat(n, mul, add): return bytes(((i*mul+add) % 251) for i in range(n))
open("$DATA/small.bin","wb").write(pat(100,7,3))
open("$DATA/big.bin","wb").write(pat(1024*1024+1234,7,3))
PY
}

one_set() { # tag user keytype
  local T=$1 U=$2 K=$3
  local BI=t0-bench-$T
  begin $T-rbd-info-v1 $U $K crc 10 "rbd info of the layering-only image (cls calls, header reads)"
  cl rbd info $IMG1; finish
  begin $T-rbd-info-default $U $K crc 10 "rbd info of the default-feature image (object-map, exclusive-lock, lock info)"
  cl rbd info $IMGD; cl rbd info --format json $IMGD; finish
  begin $T-rados-small $U $K crc 10 "rados put/stat/get/rm of a 100-byte object, plus read of a missing object (ENOENT)"
  cl rados -p winrbd put t0-small $DATA/small.bin
  cl rados -p winrbd stat t0-small
  cl rados -p winrbd get t0-small $DATA/small.$T.get
  cl rados -p winrbd get t0-missing-$T $DATA/missing.$T.get
  cl rados -p winrbd rm t0-small
  finish
  begin $T-rados-big $U $K crc 10 "rados put/stat/get/rm of a 1 MiB + 1234 byte object"
  cl rados -p winrbd put t0-big $DATA/big.bin
  cl rados -p winrbd stat t0-big
  cl rados -p winrbd get t0-big $DATA/big.$T.get
  cl rados -p winrbd rm t0-big
  finish
  begin $T-rbd-bench-v1 $U $K crc 10 "rbd create (layering only, 16 MiB), bench write 1 MiB then read 1 MiB (seq 64K), rm"
  cl rbd create --size 16M --image-feature layering winrbd/$BI
  cl rbd bench --io-type write --io-size 65536 --io-threads 4 --io-total 1M --io-pattern seq winrbd/$BI
  cl rbd bench --io-type read  --io-size 65536 --io-threads 4 --io-total 1M --io-pattern seq winrbd/$BI
  cl rbd rm winrbd/$BI
  finish
  begin $T-ceph-cli $U $K crc 10 "ceph CLI: mon dump, osd getmap (full map delivery), osd stat"
  cl ceph mon dump
  cl ceph osd getmap -o $DATA/getmap.$T.bin
  cl ceph osd stat
  finish
  begin $T-idle40 $U $K crc 10 "python rados: connect, stat, 40 s idle, stat (keepalive on mon and OSD sessions)"
  pyidle 40; finish
  begin $T-def-rbd-info $U $K def 10 "DEFAULT client options (mon connection secure, OSD crc): rbd info img-v1, rados put/get/rm of a 100-byte object"
  cl rbd info $IMG1
  cl rados -p winrbd put t0-small $DATA/small.bin
  cl rados -p winrbd get t0-small $DATA/small.$T.defget
  cl rados -p winrbd rm t0-small
  finish
  begin $T-sec-rbd-info $U $K sec 30 "BOTH forced secure (ms_client_mode=secure ms_mon_client_mode=secure): rbd info img-v1, rados put/get/rm of a 100-byte object"
  cl rbd info $IMG1
  cl rados -p winrbd put t0-small $DATA/small.bin
  cl rados -p winrbd get t0-small $DATA/small.$T.secget
  cl rados -p winrbd rm t0-small
  finish
}

wrongkey() { # tag user keytype
  local T=$1 U=$2 K=$3
  case " ${ONLY:-$T-wrongkey} " in *" $T-wrongkey "*) ;; *) return;; esac
  python3 - $KEYS/ceph.client.$U.keyring $KEYS/wrong.client.$U.keyring $U <<'PY'
import sys, base64, os, re
src, dst, user = sys.argv[1:4]
k = re.search(r'key\s*=\s*(\S+)', open(src).read()).group(1)
raw = base64.b64decode(k)
hdr, secret = raw[:12], raw[12:]          # type u16, created u32+u32, len u16 = 10 bytes; keep header, replace secret
import struct
t, sec, nsec, ln = struct.unpack('<HIIH', raw[:12])
assert 12 + ln == len(raw), (ln, len(raw))
new = raw[:12] + os.urandom(ln)
open(dst, 'w').write('[client.%s]\n\tkey = %s\n' % (user, base64.b64encode(new).decode()))
PY
  chmod 600 $KEYS/wrong.client.$U.keyring
  begin $T-wrongkey $U $K crc 10 "WRONG key (random secret of the right type) for client.$U: expect authentication failure"
  N=1; echo "  [1] rbd info winrbd/img-v1 (keyring = random key for client.$U)" >> $CMDS/$SESS.cmd
  $NS timeout 40 rbd -n client.$U --keyring $KEYS/wrong.client.$U.keyring --ms_client_mode crc --ms_mon_client_mode crc --debug_ms 5 --debug_auth 10 --log_to_file=true --log_to_stderr=false --log_file=$LOGS/$SESS.1.rbd.log --client_mount_timeout 15 info winrbd/img-v1 >> $STD/$SESS.out 2>&1; echo "### rc=$?" >> $STD/$SESS.out
  finish
}

renew() { # tag user keytype
  local T=$1 U=$2 K=$3
  begin $T-renew-ttl60 $U $K crc 10 "auth_service_ticket_ttl=60 on the mon: python rados client, op, 150 s idle, op (ticket renewal / re-auth)"
  pyidle 150; finish
}

case ${1:-} in
  setup) net_setup; mkdata;;
  sessions) one_set k2 vec-k2 aes256k; one_set k1 vec-k1 aes; wrongkey k2 vec-k2 aes256k; wrongkey k1 vec-k1 aes;;
  renew) renew k2 vec-k2 aes256k; renew k1 vec-k1 aes;;
  teardown) net_teardown;;
  *) echo "usage: $0 setup|sessions|renew|teardown"; exit 2;;
esac
