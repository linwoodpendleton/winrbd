#!/bin/bash
# SPDX-License-Identifier: MIT
#
# probe-capture.sh: run winrbd-probe against the lab monitor for both cephx key types and with a wrong
# key, record each run with tcpdump on the loopback interface (the lab monitor's address is local to the
# lab VM, so its traffic crosses lo), and check every capture with msgr2_check.py and cephx_check.py.
#
#   WR_KEYS=~/keys harness/lab/probe-capture.sh [--duration <s>]
#
# Environment:
#   WR_BUILD_DIR   harness build directory                       (default <repo>/build/harness)
#   WR_KEYS        directory with client.winrbd.keyring and client.winrbd-aes.keyring, mode 700, OUTSIDE the
#                  repository. The script adds wrong.<user>.keyring there: the same key type with a random
#                  secret that no cluster knows (the checkers recognise the "wrong." prefix).
#   WR_LAB_MON     monitor ip:port                                (default 10.77.0.10:3300)
#   WR_OUT         output directory                               (default <repo>/../probe-cap-<utc time>)
#
# Needs: sudo without password (tcpdump, ip netns), python3 with the "cryptography" package. Key material is never
# printed. Exit status: 0 when every run and every checker passed, non-zero otherwise.

set -u
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/../.." && pwd -P)
build=${WR_BUILD_DIR:-$repo/build/harness}
keys=${WR_KEYS:-$HOME/keys}
mon=${WR_LAB_MON:-10.77.0.10:3300}
out=${WR_OUT:-$repo/../probe-cap-$(date -u +%Y%m%dT%H%M%SZ)}
dur=60
[ "${1:-}" = "--duration" ] && dur=${2:?duration}

probe=$build/winrbd-probe
[ -x "$probe" ] || { echo "probe-capture: $probe not built" >&2; exit 2; }
[ -d "$keys" ] || { echo "probe-capture: key directory $keys missing" >&2; exit 2; }
mkdir -p "$out/pcap" "$out/stdout" || exit 2
chmod 700 "$out"
: > "$out/sessions.tsv"

# wrong.<user>.keyring: same entity and key type as the real one, random secret.
mkwrong() { # user
	python3 - "$keys/client.$1.keyring" "$keys/wrong.$1.keyring" "$1" <<'PY'
import base64, os, struct, sys
src, dst, user = sys.argv[1:4]
b64 = None
for line in open(src):
    if line.strip().startswith("key"):
        b64 = line.split("=", 1)[1].strip()
raw = base64.b64decode(b64)
typ, = struct.unpack_from("<H", raw, 0)
ln, = struct.unpack_from("<H", raw, 10)
new = struct.pack("<HIIH", typ, 0, 0, ln) + os.urandom(ln)
fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    f.write("[client.%s]\n\tkey = %s\n" % (user, base64.b64encode(new).decode()))
PY
}
mkwrong winrbd || exit 2
mkwrong winrbd-aes || exit 2

ns=wrprobe
netns_up() {
	sudo -n ip netns add $ns &&
	sudo -n ip link add wrpv0 type veth peer name wrpv1 &&
	sudo -n ip link set wrpv1 netns $ns &&
	sudo -n ip addr add 10.78.0.1/24 dev wrpv0 &&
	sudo -n ip link set wrpv0 up &&
	sudo -n ip netns exec $ns ip addr add 10.78.0.2/24 dev wrpv1 &&
	sudo -n ip netns exec $ns ip link set wrpv1 up &&
	sudo -n ip netns exec $ns ip link set lo up &&
	sudo -n ip netns exec $ns ip route add default via 10.78.0.1
}
netns_down() {
	sudo -n pkill -INT -x tcpdump 2>/dev/null
	sudo -n ip netns del $ns 2>/dev/null
	sudo -n ip link del wrpv0 2>/dev/null
	true
}
trap netns_down EXIT
netns_down
netns_up || { echo "probe-capture: cannot set up the network namespace" >&2; exit 2; }

fail=0
run() { # name user keyring keytype expect_rc
	local name=$1 user=$2 kr=$3 kt=$4 want=$5 pid rc start end
	sudo -n tcpdump -i wrpv0 -U -s 0 -n -w "$out/pcap/$name.pcap" "host 10.78.0.2 and port ${mon##*:}" >/dev/null 2>"$out/stdout/$name.tcpdump.err" &
	pid=$!
	sleep 1
	start=$(date -u +%FT%TZ)
	sudo -n ip netns exec $ns "$probe" --mon "$mon" --user "$user" --keyring "$kr" --duration "$dur" >"$out/stdout/$name.out" 2>"$out/stdout/$name.err"
	rc=$?
	end=$(date -u +%FT%TZ)
	sleep 1
	sudo -n pkill -INT -x tcpdump
	wait $pid 2>/dev/null
	sudo -n chown "$(id -u):$(id -g)" "$out/pcap/$name.pcap"
	printf '%s\t%s\tclient.%s\tcrc\t1\twinrbd-probe\t%s\t%s\t%s\t0\twinrbd-probe run, duration %ss\n' \
		"$name" "$kt" "$user" "$start" "$end" "$(stat -c %s "$out/pcap/$name.pcap")" "$dur" >> "$out/sessions.tsv"
	if [ "$rc" = "$want" ]; then echo "run $name: exit $rc (expected)"; else echo "run $name: exit $rc, EXPECTED $want"; fail=1; fi
}

run k2-probe winrbd "$keys/client.winrbd.keyring" aes256k 0
run k1-probe winrbd-aes "$keys/client.winrbd-aes.keyring" aes 0
run k2-wrongkey winrbd "$keys/wrong.winrbd.keyring" aes256k 5
run k1-wrongkey winrbd-aes "$keys/wrong.winrbd-aes.keyring" aes 5

export PYTHONDONTWRITEBYTECODE=1
for tool in msgr2_check cephx_check; do
	echo "== $tool"
	python3 "$repo/harness/tools/$tool.py" --captures "$out" --keys "$keys" > "$out/$tool.txt" 2>&1 || { echo "$tool: FAILED (see $out/$tool.txt)"; fail=1; }
	grep -E "WINRBD-(RESULT|SKIP)" "$out/$tool.txt"
done
echo "output in $out"
exit $fail
