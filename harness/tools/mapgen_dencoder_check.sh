#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Check the generator (harness/test/support/wrt_mapgen*.c) against Ceph's own decoder.
#
# Why: the generated maps, incrementals, pools and CRUSH blobs are the inputs of the core's decoder tests, and
# the generator and its reader share one description of the layout. The real lab bytes (harness/vectors/osdmap/)
# pin that description for what the lab can produce; this script pins the rest (IPv6 and v1-only OSDs, never
# booted OSDs, every bucket algorithm, choose_args, tunable profiles, absent trailing groups, pool versions 29 to
# 32 and the shapes the core refuses, the OSD-only block versions 10 to 12, clusters of 100 to 8,192 OSDs) by
# making `ceph-dencoder` of the lab cluster decode the bytes. The dencoder verifies the CRCs of maps and
# incrementals itself, so a wrong CRC is a failure here, and it must print the values that were described.
#
# Not part of ctest: it needs ceph-dencoder (the lab VM has it: Ubuntu 24.04, Ceph v20.2.5) and python3.
#
#   harness/tools/mapgen_dencoder_check.sh [<build dir with test_mapgen_self>]   (default: ./build/harness)
#
# On the lab VM, after building as in harness/lab/README.md:
#   cmake -S harness -B build/harness && cmake --build build/harness --target test_mapgen_self
#   sh harness/tools/mapgen_dencoder_check.sh build/harness
#
# The model's stages after CRUSH are checked against osdmaptool too when it is available (see the end of this script).
#
# Exit status: 0 all checks passed, 1 a check failed, 2 the tools are missing.
# It only reads the files it generates in a private temporary directory, which it removes at the end.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
build=${1:-$root/build/harness}
exe=$build/test_mapgen_self

if [ ! -x "$exe" ]; then
	echo "mapgen_dencoder_check: $exe not found; build it first (see the header of this script)" >&2
	exit 2
fi
if ! command -v ceph-dencoder >/dev/null 2>&1; then
	echo "mapgen_dencoder_check: ceph-dencoder not found (run this on the lab VM)" >&2
	exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
	echo "mapgen_dencoder_check: python3 not found" >&2
	exit 2
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/mapgen_dencoder.XXXXXX")
trap 'rm -rf "$work"' EXIT

echo "generating artifacts with $exe"
WRT_MAPGEN_DUMP_DIR=$work WRT_VECTOR_DIR=${WRT_VECTOR_DIR:-$root/harness/vectors} "$exe" >"$work/gen.log" 2>&1 || {
	cat "$work/gen.log" >&2
	echo "mapgen_dencoder_check: the generator test failed" >&2
	exit 1
}
tail -n 2 "$work/gen.log"

cat >"$work/compare.py" <<'PY'
import ipaddress
import json
import sys

work, name = sys.argv[1], sys.argv[2]


def norm(a):
    if a.startswith('['):
        host, _, port = a[1:].partition(']:')
        return '[%s]:%s' % (ipaddress.ip_address(host).compressed, port)
    return a


def ADDRS(lst):
    return [{'type': x['type'], 'addr': norm(x['addr']), 'nonce': x['nonce']} for x in lst]


def BUCKET(d, i):
    return next(b for b in d['buckets'] if b['id'] == i)


def RULE(d, i):
    return next(r for r in d['rules'] if r['rule_id'] == i)


def DEVCLASS(d, i):
    return next(x for x in d['devices'] if x['id'] == i).get('class')


def eq(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(a - b) < 1e-6
    return a == b


d = json.load(open('%s/%s.json' % (work, name)))
bad = 0
n = 0
for line in open('%s/%s.facts' % (work, name)):
    line = line.rstrip('\n')
    if not line:
        continue
    expr, _, want = line.partition('\t')
    n += 1
    try:
        got = eval(expr, {'d': d, 'ADDRS': ADDRS, 'BUCKET': BUCKET, 'RULE': RULE, 'DEVCLASS': DEVCLASS})
    except Exception as e:  # a missing key is a failed fact, not a crash
        print('  %s: %s -> %s: %r' % (name, expr, type(e).__name__, e))
        bad += 1
        continue
    exp = json.loads(want)
    if expr.startswith('ADDRS('):
        exp = ADDRS(exp)
    if not eq(got, exp):
        print('  %s: %s = %s, expected %s' % (name, expr, json.dumps(got)[:200], json.dumps(exp)[:200]))
        bad += 1
print('%d %d' % (n, bad))
sys.exit(1 if bad else 0)
PY

pass=0
fail=0
facts=0
while IFS='	' read -r name type mode; do
	[ -n "$name" ] || continue
	if [ "$mode" = decode ]; then # only the decode is checked (the CRCs are verified by it)
		if ceph-dencoder type "$type" import "$work/$name.bin" decode >/dev/null 2>"$work/$name.err"; then
			pass=$((pass + 1))
		else
			echo "FAIL $name ($type): ceph-dencoder refused the bytes: $(head -n 1 "$work/$name.err")"
			fail=$((fail + 1))
		fi
		continue
	fi
	if ! ceph-dencoder type "$type" import "$work/$name.bin" decode dump_json >"$work/$name.json" 2>"$work/$name.err"; then
		echo "FAIL $name ($type): ceph-dencoder refused the bytes: $(head -n 1 "$work/$name.err")"
		fail=$((fail + 1))
		continue
	fi
	if out=$(python3 -I "$work/compare.py" "$work" "$name"); then
		pass=$((pass + 1))
		facts=$((facts + $(echo "$out" | tail -n 1 | cut -d' ' -f1)))
	else
		echo "$out" | sed '$d'
		echo "FAIL $name ($type): the decoded values differ from the description"
		fail=$((fail + 1))
	fi
done <"$work/index.tsv"

# Negative controls: the dencoder must reject a map and an incremental with a flipped byte (it checks the CRCs), and
# truncated ones. If it did not, "accepted" above would prove little.
flip() { # <in> <out> <offset>
	python3 -I - "$1" "$2" "$3" <<'PY'
import sys
b = bytearray(open(sys.argv[1], 'rb').read())
b[int(sys.argv[3])] ^= 0x55
open(sys.argv[2], 'wb').write(b)
PY
}
for pair in "map_full_house:OSDMap:300" "inc_rows:OSDMap::Incremental:100" "map_osd_v12_facts:OSDMap:90"; do
	name=${pair%%:*}
	rest=${pair#*:}
	type=${rest%:*}
	off=${rest##*:}
	flip "$work/$name.bin" "$work/$name.flipped" "$off"
	if ceph-dencoder type "$type" import "$work/$name.flipped" decode dump_json >/dev/null 2>&1; then
		echo "FAIL negative control: ceph-dencoder accepted $name with byte $off flipped"
		fail=$((fail + 1))
	else
		pass=$((pass + 1))
	fi
	size=$(wc -c <"$work/$name.bin")
	head -c $((size - 9)) "$work/$name.bin" >"$work/$name.cut"
	if ceph-dencoder type "$type" import "$work/$name.cut" decode dump_json >/dev/null 2>&1; then
		echo "FAIL negative control: ceph-dencoder accepted a truncated $name"
		fail=$((fail + 1))
	else
		pass=$((pass + 1))
	fi
done

# The model's stages after CRUSH (upmap, up set, primary affinity, pg_temp, primary_temp: osdmaptool's own results are the
# oracle). Random clusters are generated, listed by `osdmaptool --test-map-pgs-dump-all`, decorated with tables that bite
# (using the raw sets of that listing), listed again, and every PG is compared with the model fed with the raw set.
# osdmaptool is found as $WRT_OSDMAPTOOL (a command prefix; the map file is appended), or on PATH, or run from the cluster's
# container image given as WRT_OSDMAPTOOL_IMAGE (podman, with sudo when not root); without any of them this part is skipped.
osdmaptool_cmd=${WRT_OSDMAPTOOL:-}
if [ -z "$osdmaptool_cmd" ]; then
	if command -v osdmaptool >/dev/null 2>&1; then
		osdmaptool_cmd=osdmaptool
	elif [ -n "${WRT_OSDMAPTOOL_IMAGE:-}" ] && command -v podman >/dev/null 2>&1; then
		sudo_prefix=
		[ "$(id -u)" -eq 0 ] || sudo_prefix="sudo"
		osdmaptool_cmd="$sudo_prefix podman run --rm -v $work:$work:Z --entrypoint osdmaptool $WRT_OSDMAPTOOL_IMAGE"
	fi
fi
if [ -z "$osdmaptool_cmd" ]; then
	echo "mapgen_dencoder_check: stages after CRUSH skipped (no osdmaptool; set WRT_OSDMAPTOOL or WRT_OSDMAPTOOL_IMAGE)"
else
	stdir=$work/stages
	mkdir "$stdir"
	list_all() { # run osdmaptool on every stg*.bin and keep the listing next to it
		for f in "$stdir"/stg*.bin; do
			if ! $osdmaptool_cmd "$f" --test-map-pgs-dump-all >"${f%.bin}.dump" 2>"${f%.bin}.err"; then
				echo "FAIL stages: osdmaptool refused $(basename "$f"): $(head -n 1 "${f%.bin}.err")"
				return 1
			fi
		done
	}
	stage() { WRT_MAPGEN_STAGES=$1 WRT_MAPGEN_DUMP_DIR=$stdir "$exe"; }
	if stage gen && list_all && stage check && stage craft && list_all && stage check; then
		pass=$((pass + 1))
	else
		echo "FAIL stages: the model disagrees with osdmaptool (or a step failed)"
		fail=$((fail + 1))
	fi
fi

echo "mapgen_dencoder_check: $pass passed, $fail failed ($facts described values compared)"
[ "$fail" -eq 0 ]
