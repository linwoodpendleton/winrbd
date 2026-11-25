#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# selftest.sh - offline test of harness/lab/p2/images: no VM, no root, no QEMU, no cluster, no network.
#
#   what it runs
#   - the table checker rbft-check (built with $CC $CFLAGS, -Werror) on tables made by expected-table.sh: every configuration passes
#     with every field checked (no SKIP); every deliberate difference fails exactly the line of its field; every defect (bad checksum,
#     length, signature, magic, version, revision, reserved bytes, trailing bytes, truncation) is named; iPXE's OEM fields are ignored;
#     the memory scan finds a table at every 16-byte position class and across the chunk edge, ignores decoys, refuses ambiguity;
#     the key never shows (output, dump), the secret for the kernel client is right, the values for the hook are safe
#   - the boot hook (initramfs/scripts/local-top/rbft) and the marker (system/wrboot-marker): the real files, run in a sandbox directory
#     with stand-ins for ip, modprobe, dmesg and the kernel's rbd interface (RBFT_ROOT): the NIC commands, the string handed to the
#     kernel client, what happens when the table is wrong, missing or unusable, and that no key is ever printed or left behind
#   - build-uefi.sh, build-bios.sh, import.sh: options, refusals, plans and dry runs; import.sh expect on a made-up disk (needs debugfs)
#   - the shell scripts parse with sh, dash (if present) and bash, and are shellcheck-clean (if shellcheck is present)
#
#   usage: selftest.sh        environment: CC (default cc), CFLAGS (extra, e.g. -fsanitize=address,undefined), KEEP=1 keeps the directory
#   exit status: 0 all passed, 1 a check failed, 77 a prerequisite is missing (nothing was tested)
# shellcheck disable=SC2015,SC2016  # "A && ok || bad" is how the checks are written (ok and bad cannot fail); stand-ins are written with single quotes
set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cc=${CC:-cc}
cflags=${CFLAGS:-}
npass=0 nfail=0 nskip=0

ok() { npass=$((npass + 1)); printf 'ok      %s\n' "$*"; }
bad() { nfail=$((nfail + 1)); printf 'FAILED  %s\n' "$*"; }
skip() { nskip=$((nskip + 1)); printf 'skipped %s\n' "$*"; }
check() { # LABEL COMMAND... : ok when the command succeeds
	local label=$1
	shift
	if "$@" > /dev/null 2>&1; then ok "$label"; else bad "$label"; fi
}
section() { printf '\n== %s\n' "$*"; }

for t in bash python3 sh; do
	command -v "$t" > /dev/null 2>&1 || { echo "selftest.sh: $t is needed"; exit 77; }
done
command -v "$cc" > /dev/null 2>&1 || { echo "selftest.sh: no C compiler ($cc)"; exit 77; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr-images-selftest.XXXXXX") || exit 77
cleanup() {
	if [ "${KEEP:-0}" = 1 ]; then echo "kept: $tmp"; return; fi
	# our own temporary directory only, made by mktemp above
	case $tmp in "${TMPDIR:-/tmp}"/wr-images-selftest.*) rm -rf "$tmp" ;; esac
}
trap cleanup EXIT

# ---------------------------------------------------------------------------------------------------------------------------
section "the checker builds"
# shellcheck disable=SC2086
if $cc -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 $cflags -o "$tmp/rbft-check" "$here/initramfs/rbft-check/rbft-check.c" 2> "$tmp/cc.log"; then
	ok "rbft-check.c compiles warning-free ($cc $cflags)"
else
	bad "rbft-check.c does not compile: $(head -n 5 "$tmp/cc.log")"
	echo "selftest.sh: $nfail failed"; exit 1
fi
rc=$tmp/rbft-check
et=$here/expected-table.sh

# throwaway keys (random, never printed): armoured cephx secrets as "ceph auth get-key" prints them
python3 -I - "$tmp" <<'PY'
import base64, os, struct, sys
d = sys.argv[1]
for name, n, typ in (("key-aes", 16, 1), ("key-aes256k", 32, 2)):
    secret = os.urandom(n)
    blob = struct.pack("<HIIH", typ if typ == 1 else 1, 0, 0, n) + secret
    open(os.path.join(d, name + ".b64"), "w").write(base64.b64encode(blob).decode() + "\n")
    open(os.path.join(d, name + ".hex"), "w").write(secret.hex() + "\n")
PY
chmod 600 "$tmp"/key-*.b64 "$tmp"/key-*.hex

# a table and its expectations: tbl NAME OPTIONS... ; the files are $tmp/NAME.bin and $tmp/NAME.params
tbl() {
	local n=$1
	shift
	"$et" table "$@" -o "$tmp/$n.bin" 2> /dev/null && "$et" params "$@" > "$tmp/$n.params" 2> /dev/null
}
# run the checker on a table: run NAME [extra args]; sets RC and $tmp/NAME.out
run() {
	local n=$1
	shift
	"$rc" --file "$tmp/$n.bin" --params "$tmp/$n.params" "$@" > "$tmp/$n.out" 2>&1
	RC=$?
}
fails() { sed -n 's/^RBFT FAIL \([^:]*\):.*/\1/p' "$1" | sort -u | tr '\n' ' '; }
nlines() { grep -c "$1" "$2" || true; }

# ---------------------------------------------------------------------------------------------------------------------------
section "expected-table.sh"
"$et" params > "$tmp/p.default" 2> /dev/null
check "params: the default configuration is the lab's (mon 10.77.0.10:3300, pool winrbd)" grep -q 'rbft.mons=10.77.0.10:3300 .*rbft.pool=winrbd ' "$tmp/p.default"
"$et" fwcfg > "$tmp/f.default" 2> /dev/null
if [ "$(wc -l < "$tmp/f.default")" -ge 18 ] && ! grep -q ' ' "$tmp/f.default"; then ok "fwcfg: one word per line, eighteen of them"; else bad "fwcfg output"; fi
tbl default
check "table: signature, length and OEM fields zero" python3 -I -c "
import sys
t = open(sys.argv[1], 'rb').read()
assert t[:4] == b'rBFT' and int.from_bytes(t[4:8], 'little') == len(t) and sum(t) % 256 == 0 and t[10:36] == bytes(26) and len(t) > 152
" "$tmp/default.bin"
"$et" body -o "$tmp/default.body" 2> /dev/null
check "body: the table without its ACPI header (QEMU -acpitable builds the header)" test "$(($(stat -c %s "$tmp/default.bin" 2> /dev/null || stat -f %z "$tmp/default.bin") - 36))" = "$(stat -c %s "$tmp/default.body" 2> /dev/null || stat -f %z "$tmp/default.body")"
for bad_args in "bogus" "table --nope" "table --mode weird -o $tmp/x" "table --keytype aes -o $tmp/x" "table --mons 10.0.0.1 -o $tmp/x" "table --set zzz=1 -o $tmp/x" "table --defect zzz -o $tmp/x" "params --pool a;b"; do
	# shellcheck disable=SC2086
	if "$et" $bad_args > /dev/null 2>&1; then bad "expected-table.sh accepted: $bad_args"; else ok "expected-table.sh refuses: $bad_args"; fi
done
# a defect needs the whole table; two defects would silently replace each other; bad numbers are a message, not a traceback
if "$et" body --defect magic -o "$tmp/x.body" > /dev/null 2>&1; then bad "body --defect was accepted (the defect would have been ignored)"; else ok "body --defect is refused (a body has no header to damage)"; fi
if "$et" table --defect checksum --defect length -o "$tmp/x.bin" > /dev/null 2>&1; then bad "two defects were accepted"; else ok "two --defect options are refused"; fi
for bad_args in "table --ip 10.0.0.1 -o $tmp/x" "table --gw nonsense -o $tmp/x" "table --mtu x -o $tmp/x" "table --set vlan=x -o $tmp/x"; do
	# shellcheck disable=SC2086
	if "$et" $bad_args > /dev/null 2> "$tmp/et.err"; then bad "expected-table.sh accepted: $bad_args"; elif grep -q Traceback "$tmp/et.err"; then bad "a traceback for: $bad_args"; else ok "expected-table.sh refuses with a message: $bad_args"; fi
done
if "$et" table -o "$tmp/nomons.bin" --mons "" > /dev/null 2>&1; then bad "an empty monitor list was accepted"; else ok "an empty monitor list is refused"; fi

# ---------------------------------------------------------------------------------------------------------------------------
section "every configuration passes, every field checked"
cfg_i=0
cfg() { # LABEL OPTIONS...
	local label=$1 n
	shift
	cfg_i=$((cfg_i + 1))
	n=cfg$cfg_i
	tbl "$n" "$@" || { bad "$label: no table"; return; }
	run "$n"
	local np nf ns
	np=$(sed -n 's/^RBFT-RESULT PASS pass=\([0-9]*\) fail=0 skip=\([0-9]*\)/\1/p' "$tmp/$n.out")
	ns=$(sed -n 's/^RBFT-RESULT PASS pass=\([0-9]*\) fail=0 skip=\([0-9]*\)/\2/p' "$tmp/$n.out")
	nf=$(nlines '^RBFT FAIL' "$tmp/$n.out")
	if [ "$RC" = 0 ] && [ "$nf" = 0 ] && [ "${ns:-x}" = 0 ] && [ "${np:-0}" -ge 30 ]; then ok "$label ($np lines PASS, none skipped)"; else bad "$label: rc=$RC pass=${np:-?} skip=${ns:-?} fail=$nf: $(fails "$tmp/$n.out")"; fi
}
cfg "defaults"
cfg "three monitors, one of them IPv6" --mons '10.77.0.10:3300,10.77.0.11:3300,[fd00::1]:6789'
cfg "IPv6 NIC with gateway and DNS" --ip fd00::20/64 --gw fd00::1 --dns fd00::2
cfg "VLAN, MTU, static flag, gateway and DNS" --vlan 100 --mtu 9000 --static --gw 10.77.0.1 --dns 10.77.0.2
cfg "read-only, fsid" --ro --fsid 0123abcd-4567-89ab-cdef-0123456789ab
cfg "secure only, secure required" --mode secure --secure-required
cfg "secure first, crc first" --mode secure-first
cfg "image id and snapshot" --image-id 1a2b3c4d --snap snap1
cfg "no authentication" --entity -
cfg "no NIC information" --ip -
cfg "key of type aes in the table" --keytype aes --key-b64-file "$tmp/key-aes.b64"
KEYCFG=cfg$cfg_i
cfg "key of type aes256k in the table" --keytype aes256k --key-b64-file "$tmp/key-aes256k.b64"
cfg "255-byte names" --pool "$(printf 'p%.0s' $(seq 1 120))" --image "$(printf 'i%.0s' $(seq 1 120))"
if [ -s "$tmp/$KEYCFG.out" ]; then
	if grep -qF "$(tr -d '\n' < "$tmp/key-aes.b64")" "$tmp/$KEYCFG.out" || grep -qF "$(tr -d '\n' < "$tmp/key-aes.hex")" "$tmp/$KEYCFG.out"; then bad "the aes key shows in the output"; else ok "the aes key is not in the output"; fi
fi
# the hexdump masks the key bytes
run "$KEYCFG" --hexdump
if [ "$RC" = 0 ] && grep -q '^RBFT DUMP' "$tmp/$KEYCFG.out" && grep -q '\.\. \.\. \.\.' "$tmp/$KEYCFG.out"; then ok "--hexdump masks the key bytes with .."; else bad "--hexdump"; fi
hexline=$(grep '^RBFT DUMP' "$tmp/$KEYCFG.out" | sed 's/^RBFT DUMP [0-9a-f]*: //' | tr -d ' \n')
if printf '%s' "$hexline" | grep -qF "$(tr -d '\n' < "$tmp/key-aes.hex")"; then bad "the key bytes are in the dump"; else ok "the key bytes are not in the dump"; fi
# no expectations at all: every field SKIPs (and --strict turns the skips into failures)
"$rc" --file "$tmp/cfg1.bin" > "$tmp/noexp.out" 2>&1
check "no expected values: structural checks pass, fields are SKIP" grep -q '^RBFT-RESULT PASS pass=[0-9]* fail=0 skip=[1-9]' "$tmp/noexp.out"
"$rc" --file "$tmp/cfg1.bin" --strict > "$tmp/strict.out" 2>&1
if [ $? = 1 ] && grep -q '^RBFT FAIL entity: no expected value' "$tmp/strict.out"; then ok "--strict: a field without an expected value fails"; else bad "--strict"; fi
# expectations from the kernel command line style words on the argument list, and "first source wins"
"$rc" --file "$tmp/cfg1.bin" --param rbft.pool=other --params "$tmp/cfg1.params" > "$tmp/first.out" 2>&1
check "the first source of a value wins (--param before --params)" grep -q "^RBFT FAIL pool: expected 'other'" "$tmp/first.out"

# ---------------------------------------------------------------------------------------------------------------------------
section "a deliberate difference fails exactly its field"
# expect_fail LABEL "allowed fields (the first one must fail)" OPTIONS...
expect_fail() {
	local label=$1 allowed=$2 first n f good=1
	shift 2
	first=${allowed%% *}
	cfg_i=$((cfg_i + 1))
	n=dev$cfg_i
	tbl "$n" "$@" || { bad "$label: no table"; return; }
	run "$n"
	f=$(fails "$tmp/$n.out")
	[ "$RC" = 1 ] || good=0
	case " $f " in *" $first "*) ;; *) good=0 ;; esac
	for x in $f; do case " $allowed " in *" $x "*) ;; *) good=0 ;; esac; done
	if [ "$good" = 1 ]; then ok "$label -> FAIL $f"; else bad "$label: rc=$RC failed fields: ${f:-none} (allowed: $allowed)"; fi
}
expect_fail "monitor"               "mon0"                           --set mons=10.77.0.11:3300
expect_fail "monitor port"          "mon0"                           --set mons=10.77.0.10:3301
expect_fail "entity"                "entity"                         --set entity=other
expect_fail "auth none in the table" "auth entity"                    --set auth=none
expect_fail "pool"                  "pool"                           --set pool=other
expect_fail "image"                 "image"                          --set image=other
expect_fail "snapshot"              "snapshot"                       --set snap=s1
expect_fail "message mode"          "msgr_mode"                      --set mode=secure
expect_fail "MAC"                   "nic_mac"                        --set mac=52:54:00:77:12:21
expect_fail "VLAN"                  "nic_vlan flags flag_vlan"       --set vlan=5
expect_fail "MTU"                   "nic_mtu"                        --set mtu=9000
expect_fail "address"               "nic_ip"                         --set ip=10.77.0.21/24
expect_fail "prefix"                "nic_prefix"                     --set ip=10.77.0.20/16
expect_fail "gateway"               "nic_gateway"                    --set gw=10.77.0.1
expect_fail "DNS"                   "nic_dns"                        --set dns=10.77.0.2
expect_fail "fsid"                  "fsid flags flag_fsid"           --set fsid=0123abcd-4567-89ab-cdef-0123456789ab
expect_fail "flags: static"         "flags flag_nic_static"          --set flags=0x4
expect_fail "flags: read-only"      "flags flag_readonly"            --set flags=0x1
expect_fail "IPv6 monitor for an IPv4 one" "mon0"                    --set mons='[fd00::1]:3300'
expect_fail "key type"              "key_type key_len flags flag_key" --set keytype=aes --key-b64-file "$tmp/key-aes.b64"

section "a damaged table is named"
# expect_defect LABEL "allowed fields" DEFECT
expect_defect() {
	local label=$1 allowed=$2 d=$3 first n f good=1
	first=${allowed%% *}
	cfg_i=$((cfg_i + 1))
	n=def$cfg_i
	tbl "$n" --defect "$d" || { bad "$label: no table"; return; }
	run "$n"
	f=$(fails "$tmp/$n.out")
	[ "$RC" = 1 ] || good=0
	case " $f " in *" $first "*) ;; *) good=0 ;; esac
	for x in $f; do case " $allowed " in *" $x "*) ;; *) good=0 ;; esac; done
	if [ "$good" = 1 ]; then ok "$label -> FAIL $f, exit 1"; else bad "$label: rc=$RC failed fields: ${f:-none} (allowed: $allowed)"; fi
}
expect_defect "bad checksum"       "checksum"        checksum
expect_defect "length too long"    "length"          length
expect_defect "wrong signature"    "signature"       signature
expect_defect "wrong magic"        "magic"           magic
expect_defect "unknown version"    "version"         version
expect_defect "ACPI revision 2"    "acpi_revision"   revision
expect_defect "reserved byte set"  "reserved"        reserved
expect_defect "bytes after the key" "layout"         trailing
expect_defect "truncated file"     "length"          truncate
tbl oem --defect oem
run oem
if [ "$RC" = 0 ] && [ -z "$(fails "$tmp/oem.out")" ] && grep -q "id 'FENSYS'" "$tmp/oem.out"; then ok "iPXE's OEM fields (FENSYS / iPXE) are ignored and printed as INFO"; else bad "OEM fields: rc=$RC $(fails "$tmp/oem.out")"; fi
# single byte flips: nothing may crash, and a damaged table never passes with every line PASS... except bytes the checker is
# not meant to read (the OEM fields 10..35)
python3 -I - "$tmp/default.bin" "$tmp" <<'PY'
import sys
t = bytearray(open(sys.argv[1], "rb").read())
d = sys.argv[2]
n = 0
for i in range(len(t)):
    u = bytearray(t); u[i] ^= 0x01
    open("%s/flip%d.bin" % (d, i), "wb").write(u); n += 1
open("%s/flips" % d, "w").write(str(n))
PY
nflip=$(cat "$tmp/flips")
silent=0 crash=0 i=0
while [ "$i" -lt "$nflip" ]; do
	"$rc" --file "$tmp/flip$i.bin" --params "$tmp/default.params" > "$tmp/flip$i.out" 2>&1
	r=$?
	case $r in 0 | 1 | 2) ;; *) crash=$((crash + 1)) ;; esac
	if [ "$r" = 0 ] && { [ "$i" -lt 10 ] || [ "$i" -ge 36 ]; }; then silent=$((silent + 1)); fi
	rm -f "$tmp/flip$i.bin" "$tmp/flip$i.out"
	i=$((i + 1))
done
if [ "$crash" = 0 ] && [ "$silent" = 0 ]; then ok "every one-bit change of the $nflip table bytes is caught (the OEM fields excepted), no crash"; else bad "bit flips: $crash crashes, $silent passed silently"; fi
# every truncation length
python3 -I - "$tmp/default.bin" "$tmp" <<'PY'
import sys
t = open(sys.argv[1], "rb").read()
for n in range(0, len(t)):
    open("%s/trunc%d.bin" % (sys.argv[2], n), "wb").write(t[:n])
PY
bad_trunc=0
for n in $(seq 0 4 "$(($(wc -c < "$tmp/default.bin") - 1))"); do
	"$rc" --file "$tmp/trunc$n.bin" > "$tmp/trunc.out" 2>&1
	r=$?
	if [ "$r" = 0 ] || [ "$r" -gt 2 ]; then bad_trunc=$((bad_trunc + 1)); fi
done
if [ "$bad_trunc" = 0 ]; then ok "a table cut short at any length is refused, no crash"; else bad "$bad_trunc truncated tables passed"; fi
rm -f "$tmp"/trunc*.bin "$tmp"/flip* "$tmp/flips"

# ---------------------------------------------------------------------------------------------------------------------------
section "the scan of physical memory"
mkscan() { # NAME TABLEFILE OFFSET [SIZE] : a memory image of SIZE bytes (1 MiB) with the table at OFFSET
	python3 -I - "$tmp/$1" "$2" "$3" "${4:-1048576}" <<'PY'
import sys
out, tab, off, size = sys.argv[1], sys.argv[2], int(sys.argv[3], 0), int(sys.argv[4])
img = bytearray(size)
t = open(tab, "rb").read()
img[off:off + len(t)] = t
open(out, "wb").write(img)
PY
}
scan_found() { # IMAGE... : run the scan, sets RC; the output is in $tmp/scan.out
	"$rc" --scan-file "$tmp/$1" "${@:2}" > "$tmp/scan.out" 2>&1
	RC=$?
}
for off in 0x0 0x10 0xFFF0 0x10000 0x9F000 0x9FC00 0xFFE00 0xFFF30; do
	mkscan mem "$tmp/default.bin" "$off"
	scan_found mem --params "$tmp/default.params"
	if [ "$RC" = 0 ] && grep -q "found at physical address $(printf '0x%x' "$off")" "$tmp/scan.out" && grep -q '^RBFT-RESULT PASS' "$tmp/scan.out"; then ok "table at $off found and checked"; else bad "table at $off: rc=$RC $(grep -E 'RESULT|source' "$tmp/scan.out" | head -n 2 | tr '\n' ' ')"; fi
done
mkscan mem "$tmp/default.bin" 0x9F008
scan_found mem
if [ "$RC" = 2 ]; then ok "a table not on a 16-byte boundary is not found (the loader aligns its tables)"; else bad "an unaligned table was found: rc=$RC"; fi
mkscan mem "$tmp/oem.bin" 0x9F000
scan_found mem --params "$tmp/oem.params"
if [ "$RC" = 0 ]; then ok "a table with iPXE's OEM fields is found by the scan"; else bad "OEM table in a scan: rc=$RC"; fi
# a decoy: the signature with a bad checksum before the real table
python3 -I - "$tmp/mem" "$tmp/default.bin" "$tmp/def.bin" <<'PY'
import sys
img = bytearray(1048576)
t = open(sys.argv[2], "rb").read()
bad = bytearray(t); bad[9] ^= 0x55
img[0x80000:0x80000 + len(t)] = bad
img[0x90000:0x90000 + len(t)] = t
img[0xA0010:0xA0014] = b"rBFT"          # a bare signature
open(sys.argv[1], "wb").write(img)
PY
scan_found mem --params "$tmp/default.params"
if [ "$RC" = 0 ] && grep -q 'found at physical address 0x90000' "$tmp/scan.out" && grep -q 'ignored' "$tmp/scan.out"; then ok "decoys (bad checksum, bare signature) are ignored and reported"; else bad "decoys: rc=$RC"; fi
# two different valid tables
tbl other --pool other
python3 -I - "$tmp/mem" "$tmp/default.bin" "$tmp/other.bin" <<'PY'
import sys
img = bytearray(1048576)
a = open(sys.argv[2], "rb").read(); b = open(sys.argv[3], "rb").read()
img[0x80000:0x80000 + len(a)] = a
img[0x90000:0x90000 + len(b)] = b
open(sys.argv[1], "wb").write(img)
PY
scan_found mem --params "$tmp/default.params"
if [ "$RC" = 1 ] && grep -q 'FAIL scan: .* differ' "$tmp/scan.out"; then ok "two different valid tables: ambiguous, FAIL"; else bad "ambiguity: rc=$RC"; fi
# the same table twice is one table
python3 -I - "$tmp/mem" "$tmp/default.bin" <<'PY'
import sys
img = bytearray(1048576)
a = open(sys.argv[2], "rb").read()
img[0x80000:0x80000 + len(a)] = a
img[0x90000:0x90000 + len(a)] = a
open(sys.argv[1], "wb").write(img)
PY
scan_found mem --params "$tmp/default.params"
if [ "$RC" = 0 ] && grep -q '2 valid copy' "$tmp/scan.out"; then ok "the same table twice (a re-described device) is accepted"; else bad "duplicates: rc=$RC"; fi
mkscan mem "$tmp/default.bin" 0x100000 2097152
scan_found mem --range 0x0-0x100000
if [ "$RC" = 2 ]; then ok "--range: a table above the range is not looked at"; else bad "--range: rc=$RC"; fi
scan_found mem --range 0x100000-0x200000 --params "$tmp/default.params"
if [ "$RC" = 0 ]; then ok "--range: a table inside it is found"; else bad "--range inside: rc=$RC"; fi
mkscan mem "$tmp/default.bin" 0x20 4096
scan_found mem --base 0xF0000 --range 0xF0000-0xF1000
if [ "$RC" = 0 ] && grep -q 'found at physical address 0xf0020' "$tmp/scan.out"; then ok "--base: addresses are those of the memory the file stands for"; else bad "--base: rc=$RC"; fi
# a table cut by the end of the range
python3 -I - "$tmp/mem" "$tmp/default.bin" <<'PY'
import sys
a = open(sys.argv[2], "rb").read()
open(sys.argv[1], "wb").write(bytes(4080) + a[:100])
PY
scan_found mem
if [ "$RC" = 2 ]; then ok "a table cut by the end of memory is not found"; else bad "cut table: rc=$RC"; fi
: > "$tmp/empty.img"
"$rc" --scan-file "$tmp/empty.img" > "$tmp/scan.out" 2>&1
if [ $? = 2 ]; then ok "an empty memory image: no table, exit 2"; else bad "empty image"; fi
"$rc" --file "$tmp/nonexistent" > "$tmp/scan.out" 2>&1
if [ $? = 2 ]; then ok "an unreadable file: exit 2"; else bad "unreadable file"; fi

# ---------------------------------------------------------------------------------------------------------------------------
section "values for the hook: environment and secret"
tbl env --keytype aes --key-b64-file "$tmp/key-aes.b64" --vlan 20 --mtu 1400 --gw 10.77.0.1 --ro --mons '10.77.0.10:3300,[fd00::10]:3300'
run env --emit-env "$tmp/env.sh" --emit-secret "$tmp/env.secret" --check-nic
check "emit-env writes a file (mode 600)" test -s "$tmp/env.sh"
perm=$(stat -c %a "$tmp/env.sh" 2> /dev/null || stat -f %Lp "$tmp/env.sh")
[ "$perm" = 600 ] && ok "emit-env file mode is 600" || bad "emit-env file mode is $perm"
# the second line of the check output says whether this machine has the NIC; only the values matter here
# shellcheck disable=SC1091,SC1090
( . "$tmp/env.sh" && [ "$RBFT_MONS" = '10.77.0.10:3300 [fd00::10]:3300' ] && [ "$RBFT_ENTITY" = winrbd-aes ] && [ "$RBFT_POOL" = winrbd ] \
	&& [ "$RBFT_IMAGE" = wrtest-p2-lin-uefi ] && [ "$RBFT_RO" = 1 ] && [ "$RBFT_VLAN" = 20 ] && [ "$RBFT_MTU" = 1400 ] && [ "$RBFT_IP" = 10.77.0.20 ] \
	&& [ "$RBFT_PREFIX" = 24 ] && [ "$RBFT_GW" = 10.77.0.1 ] && [ "$RBFT_MAC" = 52:54:00:77:12:20 ] && [ "$RBFT_MODE" = 1 ] && [ "$RBFT_KEYTYPE" = 1 ] \
	&& [ "$RBFT_KEY_IN_TABLE" = 1 ] && [ "$RBFT_SNAP" = - ] && [ "$RBFT_DNS" = "" ] ) && ok "the values in the environment file are right" || bad "environment file values"
if grep -qF "$(tr -d '\n' < "$tmp/key-aes.b64")" "$tmp/env.sh"; then bad "the key is in the environment file"; else ok "the environment file has no key"; fi
python3 -I - "$tmp/env.secret" "$tmp/key-aes.b64" <<'PY' && ok "emit-secret: the armoured secret the kernel client takes (type 1, the table's 16 key bytes)" || bad "emit-secret content"
import base64, sys
got = base64.b64decode(open(sys.argv[1]).read())
want = base64.b64decode(open(sys.argv[2]).read())
assert got[:2] == b"\x01\x00" and got[12:] == want[12:] and int.from_bytes(got[10:12], "little") == len(got) - 12 == 16
PY
perm=$(stat -c %a "$tmp/env.secret" 2> /dev/null || stat -f %Lp "$tmp/env.secret")
[ "$perm" = 600 ] && ok "the secret file is mode 600" || bad "secret file mode $perm"
if grep -qF "$(tr -d '\n' < "$tmp/key-aes.b64")" "$tmp/env.out"; then bad "the key is in the output with emit-secret"; else ok "emit-secret prints no key"; fi
run env --emit-secret "$tmp/env.secret"
check "emit-secret never overwrites a file (O_EXCL)" grep -q 'FAIL emit-secret' "$tmp/env.out"
rm -f "$tmp/env.secret"
tbl env2 --keytype aes256k --key-b64-file "$tmp/key-aes256k.b64"
run env2 --emit-secret "$tmp/env2.secret"
if [ ! -e "$tmp/env2.secret" ] && grep -q 'cannot be used by the kernel client' "$tmp/env2.out"; then ok "an aes256k key: no secret file (the kernel client cannot use it), said so"; else bad "aes256k secret"; fi
# a supplied key must equal the table's
run env --supplied-key "$tmp/key-aes.b64"
check "supplied key equals the table's key: PASS key_value" grep -q '^RBFT PASS key_value' "$tmp/env.out"
run env --supplied-key "$tmp/key-aes256k.b64"
check "supplied key differs from the table's: FAIL key_value" grep -q '^RBFT FAIL key_value' "$tmp/env.out"
tbl nokey
run nokey --supplied-key "$tmp/key-aes.b64"
if [ "$RC" = 0 ] && grep -q '^RBFT INFO key_value: the table carries no key' "$tmp/nokey.out"; then ok "no key in the table: the supplied one will be used (INFO)"; else bad "supplied key without table key: rc=$RC"; fi
# names that are not safe for a shell or the kernel client: no environment file
tbl unsafe --set "entity=a'b"
rm -f "$tmp/unsafe.env"
run unsafe --emit-env "$tmp/unsafe.env"
if [ ! -e "$tmp/unsafe.env" ]; then ok "a name with a quote: no environment file is written"; else bad "an unsafe name reached the environment file"; fi
tbl unsafe2 --set "image=a b"
rm -f "$tmp/unsafe2.env"
run unsafe2 --emit-env "$tmp/unsafe2.env"
if [ ! -e "$tmp/unsafe2.env" ]; then ok "a name with a blank: no environment file"; else bad "a blank in a name reached the environment file"; fi
# names outside the allow-list (shell metacharacters that a quote test would miss): no environment file either
for unsafe_name in 'a;b' 'a|b' 'a$(b)' 'a&b' 'a>b' 'a*b' 'a#b'; do
	tbl unsafe3 --set "image=$unsafe_name"
	rm -f "$tmp/unsafe3.env"
	run unsafe3 --emit-env "$tmp/unsafe3.env"
	if [ ! -e "$tmp/unsafe3.env" ]; then ok "the name '$unsafe_name': no environment file"; else bad "the name '$unsafe_name' reached the environment file"; fi
done
# a stale environment file from an earlier run is not left standing for a table that is not sound now
printf "RBFT_POOL='stale'\n" > "$tmp/stale.env"
tbl dmg0 --defect checksum
run dmg0 --emit-env "$tmp/stale.env"
[ ! -e "$tmp/stale.env" ] && ok "emit-env removes a file of an earlier run when this table is not sound" || bad "a stale environment file was left"
# a name from the table cannot forge a line of the check's own output (a line break in a name used to reach the console through the SKIP line)
tbl forge --set "entity=x
RBFT-RESULT PASS pass=99 fail=0 skip=0"
"$rc" --file "$tmp/forge.bin" > "$tmp/forge.out" 2>&1
nres=$(grep -c '^RBFT-RESULT' "$tmp/forge.out" || true)
if [ "$nres" = 1 ] && ! grep -q '^RBFT-RESULT PASS pass=99' "$tmp/forge.out"; then ok "a line break in a name cannot forge an RBFT-RESULT line (SKIP lines)"; else bad "a table name forged a result line ($nres RBFT-RESULT lines)"; fi
"$rc" --file "$tmp/forge.bin" --strict > "$tmp/forge.out" 2>&1
[ "$(grep -c '^RBFT-RESULT' "$tmp/forge.out" || true)" = 1 ] && ok "... and in the strict (FAIL) lines" || bad "forged line under --strict"
# an expectations file that does not fit the buffer is refused, not cut
python3 -I -c "print('rbft.pool=winrbd ' + 'rbft.x=' + 'a' * 5000)" > "$tmp/bigparams"
"$rc" --file "$tmp/default.bin" --params "$tmp/bigparams" > "$tmp/big.out" 2>&1
grep -q '^RBFT FAIL params: .* longer than 4095' "$tmp/big.out" && ok "an expectations file over 4095 bytes is refused (FAIL params), not silently cut" || bad "oversized params file: $(head -n 3 "$tmp/big.out" | tr '\n' ' ')"
# "rbft.flags=" with nothing after it is a syntax error, not "none"
tbl nf
"$rc" --file "$tmp/nf.bin" --params "$tmp/nf.params" --param rbft.flags= > "$tmp/nf.out" 2>&1
RC=$?
[ "$RC" = 1 ] && grep -q "^RBFT FAIL flags: the expected value '' does not parse" "$tmp/nf.out" && ok "an empty flags expectation does not parse (it is not 'none')" || bad "empty flags expectation: rc=$RC"
# the table's bytes are not left in the process: the supplied-key file is read and wiped (no key in any output was checked above)
# a damaged table: no environment file
tbl dmg --defect checksum
rm -f "$tmp/dmg.env"
run dmg --emit-env "$tmp/dmg.env"
if [ ! -e "$tmp/dmg.env" ]; then ok "a table with a bad checksum: no environment file"; else bad "a damaged table reached the environment file"; fi

# ---------------------------------------------------------------------------------------------------------------------------
section "the boot hook (the real local-top/rbft in a sandbox)"
hook=$here/initramfs/scripts/local-top/rbft
marker=$here/initramfs/system/wrboot-marker
SHELLS=(sh)
command -v dash > /dev/null 2>&1 && SHELLS=(sh dash)
KEYB64=$(tr -d '\n' < "$tmp/key-aes.b64")

sandbox() { # NAME CMDLINE TABLEFILE|- [PARAMSFILE|-] [KEYFILE|-] : a sandbox root; the table goes where $SRC_AT says
	local sb=$tmp/sb-$1
	case $sb in "$tmp"/sb-?*) rm -rf "$sb" ;; esac # a fresh sandbox every time (our own directory below $tmp)
	mkdir -p "$sb/proc" "$sb/sys/class/net/eth0" "$sb/sys/bus/rbd/devices" "$sb/sys/firmware/acpi/tables" "$sb/run" "$sb/conf" "$sb/dev" "$sb/bin" \
		"$sb/sys/firmware/qemu_fw_cfg/by_name/opt/winrbd/table" "$sb/sys/firmware/qemu_fw_cfg/by_name/opt/winrbd/params" "$sb/sys/firmware/qemu_fw_cfg/by_name/opt/winrbd/key"
	echo "52:54:00:77:12:20" > "$sb/sys/class/net/eth0/address"
	printf '%s\n' "$2" > "$sb/proc/cmdline"
	: > "$sb/sys/bus/rbd/add_single_major"
	[ "$3" = - ] || { cp "$tmp/$3" "$sb/sys/firmware/acpi/tables/rBFT"; cp "$tmp/$3" "$sb/sys/firmware/qemu_fw_cfg/by_name/opt/winrbd/table/raw"; }
	[ "${4:--}" = - ] || cp "$tmp/$4" "$sb/sys/firmware/qemu_fw_cfg/by_name/opt/winrbd/params/raw"
	[ "${5:--}" = - ] || cp "$5" "$sb/sys/firmware/qemu_fw_cfg/by_name/opt/winrbd/key/raw"
	# stand-ins: ip logs its arguments; the "kernel" makes the device when the hook waits after writing the add file
	cat > "$sb/bin/ip" <<'STUB'
#!/bin/sh
echo "ip $*" >> "$RBFT_ROOT/ip.log"
exit "${RBFT_IP_RC:-0}"
STUB
	printf '#!/bin/sh\nexit 0\n' > "$sb/bin/modprobe"
	printf '#!/bin/sh\necho "[    1.0] libceph: test line"\nexit 0\n' > "$sb/bin/dmesg"
	cat > "$sb/bin/fakesleep" <<'STUB'
#!/bin/sh
if [ -s "$RBFT_ROOT/sys/bus/rbd/add_single_major" ] && [ ! -e "$RBFT_ROOT/sys/bus/rbd/devices/0" ] && [ -z "$RBFT_NO_DEVICE" ]; then
	mkdir "$RBFT_ROOT/sys/bus/rbd/devices/0"
	[ -z "$RBFT_NO_PART" ] && : > "$RBFT_ROOT/dev/rbd0p2"
fi
exit 0
STUB
	chmod +x "$sb/bin/ip" "$sb/bin/modprobe" "$sb/bin/dmesg" "$sb/bin/fakesleep"
	printf '%s' "$sb"
}
runhook() { # SANDBOX [SHELL] : sets HRC, output in SANDBOX/out
	local sb=$1 sh=${2:-sh}
	RBFT_ROOT=$sb RBFT_CHECK=$rc RBFT_SLEEP=$sb/bin/fakesleep RBFT_BLOCKTEST=-e RBFT_NOPOWEROFF=1 PATH=$sb/bin:$PATH "$sh" "$hook" > "$sb/out" 2>&1
	HRC=$?
}
hasline() { grep -q -- "$2" "$1/out"; }

for shl in "${SHELLS[@]}"; do
	tbl hk --keytype none
	sb=$(sandbox a "console=ttyS0 root=LABEL=wrbroot rbft.hook=1 rbft.map=0 $(cat "$tmp/hk.params")" hk.bin -)
	runhook "$sb" "$shl"
	if [ "$HRC" = 0 ] && hasline "$sb" '^WRBOOT-TABLE PASS' && hasline "$sb" 'RBFT-RESULT PASS pass=[0-9]* fail=0 skip=0' && hasline "$sb" 'source sysfs\|table found by source sysfs'; then
		ok "[$shl] good table, expectations on the kernel command line: every field PASS, WRBOOT-TABLE PASS"
	else bad "[$shl] good table: rc=$HRC: $(grep -E 'WRBOOT|RESULT|FAIL' "$sb/out" | head -n 4 | tr '\n' ' ')"; fi
	if grep -q '^ip link set dev eth0 up' "$sb/ip.log" && grep -q '^ip addr add 10.77.0.20/24 dev eth0' "$sb/ip.log" && grep -q '^ip link set dev eth0 mtu 1500' "$sb/ip.log"; then
		ok "[$shl] the NIC with the table's MAC is brought up with its address and MTU"
	else bad "[$shl] NIC commands: $(tr '\n' ';' < "$sb/ip.log" 2> /dev/null)"; fi
	[ ! -s "$sb/sys/bus/rbd/add_single_major" ] && ok "[$shl] rbft.map=0: nothing is written to the kernel client" || bad "[$shl] map=0 wrote to rbd/add_single_major"
	grep -q '^TABLE=PASS' "$sb/run/rbft/result" && grep -q '^MAPPED=0' "$sb/run/rbft/result" && ok "[$shl] result file: TABLE=PASS MAPPED=0" || bad "[$shl] result file: $(tr '\n' ' ' < "$sb/run/rbft/result")"
	[ ! -s "$sb/conf/param.conf" ] && ok "[$shl] map=0 leaves root= alone (nothing in param.conf)" || bad "[$shl] param.conf written with map=0"

	# the same through fw_cfg expectations and the fw_cfg table source
	sb=$(sandbox b "console=ttyS0 rbft.hook=1 rbft.map=0 rbft.src=fwcfg" hk.bin hk.params -)
	runhook "$sb" "$shl"
	hasline "$sb" '^WRBOOT-TABLE PASS' && hasline "$sb" 'table found by source fwcfg' && ok "[$shl] table and expectations from QEMU fw_cfg files (rbft.src=fwcfg)" || bad "[$shl] fw_cfg source"

	# a map with the key from fw_cfg
	tbl hm
	printf '%s' "$KEYB64" > "$tmp/keyfile"
	sb=$(sandbox c "console=ttyS0 root=LABEL=wrbroot rbft.hook=1 $(cat "$tmp/hm.params")" hm.bin - "$tmp/keyfile")
	runhook "$sb" "$shl"
	want="10.77.0.10:3300 name=winrbd-aes,secret=$KEYB64,ms_mode=crc,noshare winrbd wrtest-p2-lin-uefi"
	if [ "$HRC" = 0 ] && [ "$(cat "$sb/sys/bus/rbd/add_single_major")" = "$want" ]; then ok "[$shl] map: the string handed to the kernel client is right (mons, user, key, ms_mode=crc, pool, image)"; else bad "[$shl] rbd/add: '$(sed "s|$KEYB64|KEY|" "$sb/sys/bus/rbd/add_single_major")'"; fi
	grep -q '^ROOT=/dev/rbd0p2$' "$sb/conf/param.conf" && ok "[$shl] ROOT=/dev/rbd0p2 is written for the initramfs" || bad "[$shl] param.conf: $(cat "$sb/conf/param.conf" 2> /dev/null)"
	hasline "$sb" 'WRBOOT-HOOK-DONE root=/dev/rbd0p2 table=PASS' && ok "[$shl] WRBOOT-HOOK-DONE root=/dev/rbd0p2 table=PASS" || bad "[$shl] no WRBOOT-HOOK-DONE"
	grep -q '^MAPPED=1' "$sb/run/rbft/result" && grep -q '^DEV=/dev/rbd0p2' "$sb/run/rbft/result" && ok "[$shl] result file: MAPPED=1 DEV=/dev/rbd0p2" || bad "[$shl] result file after a map"
	if grep -rqF "$KEYB64" "$sb/out" "$sb/ip.log" "$sb/run" "$sb/conf" 2> /dev/null; then bad "[$shl] the key shows in the output or was left behind"; else ok "[$shl] the key is neither printed nor left in /run"; fi
	if [ ! -e "$sb/run/rbft/secret" ] && [ ! -e "$sb/run/rbft/supplied" ]; then ok "[$shl] the key files are removed"; else bad "[$shl] a key file is left"; fi
	# a kernel without single_major has only "add"
	sb=$(sandbox c2 "console=ttyS0 root=LABEL=wrbroot rbft.hook=1 $(cat "$tmp/hm.params")" hm.bin - "$tmp/keyfile")
	rm -f "$sb/sys/bus/rbd/add_single_major"
	: > "$sb/sys/bus/rbd/add"
	sed -i.bak 's|rbd/add_single_major|rbd/add|' "$sb/bin/fakesleep" && rm -f "$sb/bin/fakesleep.bak"
	runhook "$sb" "$shl"
	if [ "$(cat "$sb/sys/bus/rbd/add")" = "$want" ] && grep -q '^ROOT=/dev/rbd0p2$' "$sb/conf/param.conf"; then ok "[$shl] a kernel without add_single_major: the plain add file is used"; else bad "[$shl] add fallback"; fi
	# the ro flag and the secure modes
	tbl hm2 --ro --mode secure --secure-required
	sb=$(sandbox d "rbft.hook=1 $(cat "$tmp/hm2.params")" hm2.bin - "$tmp/keyfile")
	runhook "$sb" "$shl"
	grep -q 'ms_mode=secure,noshare,read_only winrbd' "$sb/sys/bus/rbd/add_single_major" && ok "[$shl] read-only flag -> read_only, secure mode -> ms_mode=secure" || bad "[$shl] options: $(sed "s|$KEYB64|KEY|" "$sb/sys/bus/rbd/add_single_major")"
	tbl hm3 --mode crc-first --mons '10.77.0.10:3300,10.77.0.11:3300'
	sb=$(sandbox e "rbft.hook=1 $(cat "$tmp/hm3.params")" hm3.bin - "$tmp/keyfile")
	runhook "$sb" "$shl"
	grep -q '^10.77.0.10:3300,10.77.0.11:3300 name=winrbd-aes,secret=.*,ms_mode=prefer-crc,noshare ' "$sb/sys/bus/rbd/add_single_major" && ok "[$shl] two monitors are comma separated, crc-first -> prefer-crc" || bad "[$shl] monitors option"
	# VLAN, gateway
	tbl hv --vlan 100 --mtu 9000 --gw 10.77.0.1
	sb=$(sandbox f "rbft.hook=1 rbft.map=0 $(cat "$tmp/hv.params")" hv.bin -)
	runhook "$sb" "$shl"
	if grep -q '^ip link add link eth0 name eth0.100 type vlan id 100' "$sb/ip.log" && grep -q '^ip addr add 10.77.0.20/24 dev eth0.100' "$sb/ip.log" && grep -q '^ip route add default via 10.77.0.1 dev eth0.100' "$sb/ip.log" && grep -q '^ip link set dev eth0 mtu 9000' "$sb/ip.log"; then
		ok "[$shl] VLAN device, address on it, default route, MTU"
	else bad "[$shl] VLAN commands: $(tr '\n' ';' < "$sb/ip.log")"; fi
	# the key in the table (aes)
	tbl hk2 --keytype aes --key-b64-file "$tmp/key-aes.b64"
	sb=$(sandbox g "rbft.hook=1 $(cat "$tmp/hk2.params")" hk2.bin)
	runhook "$sb" "$shl"
	if [ "$(cat "$sb/sys/bus/rbd/add_single_major")" = "10.77.0.10:3300 name=winrbd-aes,secret=$KEYB64,ms_mode=crc,noshare winrbd wrtest-p2-lin-uefi" ]; then ok "[$shl] the key from the table (handoff=key) is used"; else bad "[$shl] table key mapping"; fi
	if grep -rqF "$KEYB64" "$sb/out" "$sb/run" 2> /dev/null; then bad "[$shl] the table's key shows or is left behind"; else ok "[$shl] the table's key is neither printed nor left behind"; fi
	grep -q '^RBFT DUMP' "$sb/out" && ! grep -rqF "$(tr -d '\n' < "$tmp/key-aes.hex")" "$sb/out" && ok "[$shl] the acpidump-style record is in the log, without the key" || bad "[$shl] dump / key hex"
	# table key and supplied key that differ
	sb=$(sandbox g2 "rbft.hook=1 $(cat "$tmp/hk2.params")" hk2.bin - "$tmp/key-aes256k.b64")
	runhook "$sb" "$shl"
	hasline "$sb" '^RBFT FAIL key_value' && hasline "$sb" '^WRBOOT-TABLE FAIL' && [ ! -s "$sb/sys/bus/rbd/add_single_major" ] && ok "[$shl] a supplied key that differs from the table's: FAIL, nothing mapped" || bad "[$shl] key mismatch"
	# aes256k in the table, nothing supplied
	tbl hk3 --keytype aes256k --key-b64-file "$tmp/key-aes256k.b64"
	sb=$(sandbox h "rbft.hook=1 $(cat "$tmp/hk3.params")" hk3.bin)
	runhook "$sb" "$shl"
	hasline "$sb" 'aes256k key, which the kernel client cannot use' && [ ! -s "$sb/sys/bus/rbd/add_single_major" ] && ok "[$shl] aes256k in the table and no legacy key: clear refusal, nothing mapped" || bad "[$shl] aes256k"
	# no key at all
	sb=$(sandbox i "rbft.hook=1 $(cat "$tmp/hm.params")" hm.bin)
	runhook "$sb" "$shl"
	hasline "$sb" 'carries no key and none was supplied' && [ ! -s "$sb/sys/bus/rbd/add_single_major" ] && ok "[$shl] no key anywhere: clear refusal" || bad "[$shl] no key"
	# wrong field: FAIL, no mapping, with and without require
	tbl hw --set pool=other
	sb=$(sandbox j "rbft.hook=1 $(cat "$tmp/hm.params")" hw.bin - "$tmp/keyfile")
	cp "$tmp/hw.bin" "$sb/sys/firmware/acpi/tables/rBFT"
	runhook "$sb" "$shl"
	if hasline "$sb" "^RBFT FAIL pool: expected 'winrbd', got 'other'" && hasline "$sb" '^WRBOOT-TABLE FAIL' && [ ! -s "$sb/sys/bus/rbd/add_single_major" ] && ! hasline "$sb" POWEROFF && grep -q '^TABLE=FAIL' "$sb/run/rbft/result"; then
		ok "[$shl] a wrong field: that FAIL line, WRBOOT-TABLE FAIL, nothing mapped, boot goes on"
	else bad "[$shl] wrong field: $(grep -E 'FAIL|WRBOOT' "$sb/out" | head -n 3 | tr '\n' ' ')"; fi
	sb=$(sandbox k "rbft.hook=1 rbft.require=1 $(cat "$tmp/hm.params")" hw.bin - "$tmp/keyfile")
	runhook "$sb" "$shl"
	hasline "$sb" '^WRBOOT-HOOK-POWEROFF' && ok "[$shl] rbft.require=1: a wrong table powers the guest off" || bad "[$shl] require + wrong field"
	# a name with shell metacharacters: the table is unusable, nothing is mapped, nothing is run
	tbl hx --set 'pool=a;b'
	sb=$(sandbox j2 "rbft.hook=1 $(cat "$tmp/hm.params")" hx.bin - "$tmp/keyfile")
	runhook "$sb" "$shl"
	if hasline "$sb" '^WRBOOT-TABLE UNUSABLE' && [ ! -s "$sb/sys/bus/rbd/add_single_major" ] && grep -q '^TABLE=UNUSABLE' "$sb/run/rbft/result"; then ok "[$shl] a name with ';': WRBOOT-TABLE UNUSABLE, nothing mapped"; else bad "[$shl] unsafe name: $(grep -E 'WRBOOT|FAIL' "$sb/out" | head -n 3 | tr '\n' ' ')"; fi
	# bad checksum through the fw_cfg table source
	tbl hc --defect checksum
	sb=$(sandbox l "rbft.hook=1 rbft.src=fwcfg rbft.map=0" hc.bin hc.params)
	runhook "$sb" "$shl"
	hasline "$sb" '^RBFT FAIL checksum' && hasline "$sb" '^WRBOOT-TABLE UNUSABLE' && grep -q '^TABLE=UNUSABLE' "$sb/run/rbft/result" && ok "[$shl] bad checksum: FAIL checksum, WRBOOT-TABLE UNUSABLE" || bad "[$shl] bad checksum: $(grep -E 'WRBOOT|FAIL' "$sb/out" | head -n 3 | tr '\n' ' ')"
	# no table
	sb=$(sandbox m "rbft.hook=1 rbft.src=sysfs root=LABEL=wrbroot" - )
	runhook "$sb" "$shl"
	hasline "$sb" '^WRBOOT-TABLE NONE' && [ "$HRC" = 0 ] && grep -q '^TABLE=NONE' "$sb/run/rbft/result" && ok "[$shl] no table: WRBOOT-TABLE NONE, the boot goes on with root= as given" || bad "[$shl] no table"
	sb=$(sandbox n "rbft.hook=1 rbft.src=sysfs rbft.require=1" - )
	runhook "$sb" "$shl"
	hasline "$sb" '^WRBOOT-HOOK-POWEROFF' && ok "[$shl] no table with rbft.require=1: powers off" || bad "[$shl] no table + require"
	# the kernel refuses; the partition does not appear; the device does not appear
	tbl hm4
	sb=$(sandbox o "rbft.hook=1 rbft.waitmap=2 $(cat "$tmp/hm4.params")" hm4.bin - "$tmp/keyfile")
	RBFT_NO_PART=1 runhook "$sb" "$shl"
	hasline "$sb" 'no partition 2 on /dev/rbd0' && [ ! -s "$sb/conf/param.conf" ] && ok "[$shl] the partition does not appear: clear message, ROOT not set" || bad "[$shl] no partition: $(grep -E 'FAIL|map' "$sb/out" | tail -n 2 | tr '\n' ' ')"
	sb=$(sandbox p "rbft.hook=1 rbft.waitmap=2 $(cat "$tmp/hm4.params")" hm4.bin - "$tmp/keyfile")
	RBFT_NO_DEVICE=1 runhook "$sb" "$shl"
	hasline "$sb" 'no rbd device showed up' && ok "[$shl] no device appears: clear message" || bad "[$shl] no device"
	# no NIC with the MAC
	rm "$tmp/sb-a/sys/class/net/eth0/address"
	echo "aa:bb:cc:dd:ee:ff" > "$tmp/sb-a/sys/class/net/eth0/address"
	sb=$tmp/sb-a
	rm -f "$sb/ip.log"
	RBFT_ROOT=$sb RBFT_CHECK=$rc RBFT_SLEEP=true RBFT_BLOCKTEST=-e RBFT_NOPOWEROFF=1 PATH=$sb/bin:$PATH "$shl" "$hook" > "$sb/out" 2>&1
	if grep -q 'no interface with MAC 52:54:00:77:12:20' "$sb/out" && grep -q '^RBFT FAIL nic_present' "$sb/out" && [ ! -e "$sb/ip.log" ]; then ok "[$shl] no NIC with the table's MAC: said so, FAIL nic_present, no ip command run"; else bad "[$shl] no NIC"; fi
	# options that are not valid
	sb=$(sandbox q "rbft.hook=1 rbft.map=x" - )
	runhook "$sb" "$shl"
	hasline "$sb" 'non-numeric' && ok "[$shl] a non-numeric option is refused with a message" || bad "[$shl] bad option"
	sb=$(sandbox r "rbft.hook=1 rbft.src=weird" - )
	runhook "$sb" "$shl"
	hasline "$sb" 'rbft.src=weird is not' && ok "[$shl] an unknown rbft.src is refused" || bad "[$shl] bad src"
	# the hook is silent when not asked
	sb=$(sandbox s "console=ttyS0 rbft.hook=0" hk.bin )
	runhook "$sb" "$shl"
	[ ! -s "$sb/out" ] && ok "[$shl] rbft.hook=0: no output, no action" || bad "[$shl] hook=0 spoke"
	sb=$(sandbox t "console=ttyS0 root=/dev/vda1" hk.bin )
	runhook "$sb" "$shl"
	if [ ! -s "$sb/out" ] && { [ ! -e "$sb/run/rbft" ] || [ ! -s "$sb/run/rbft/result" ]; }; then ok "[$shl] no rbft.hook: nothing happens"; else bad "[$shl] no hook option, but it ran"; fi
	# prereqs
	if "$shl" "$hook" prereqs > "$tmp/prereqs.out" 2>&1; then ok "[$shl] 'prereqs' is answered (initramfs-tools protocol)"; else bad "[$shl] prereqs"; fi
done
# the BIOS order: the scan first, then sysfs
sb=$(sandbox u "rbft.hook=1 rbft.map=0 $(cat "$tmp/hk.params")" hk.bin )
runhook "$sb"
hasline "$sb" 'table found by source' && ok "auto source without /sys/firmware/efi (BIOS): the scan is tried, then sysfs finds the table" || bad "BIOS auto order: $(head -n 5 "$sb/out" | tr '\n' ' ')"
mkdir "$sb/sys/firmware/efi"
sb2=$(sandbox v "rbft.hook=1 rbft.map=0 $(cat "$tmp/hk.params")" hk.bin )
mkdir "$sb2/sys/firmware/efi"
runhook "$sb2"
hasline "$sb2" 'table found by source sysfs' && ! hasline "$sb2" 'source scan' && ok "auto source with /sys/firmware/efi (UEFI): sysfs only" || bad "UEFI auto order"

# ---------------------------------------------------------------------------------------------------------------------------
section "the marker (the real wrboot-marker in a sandbox)"
mk() { # NAME CMDLINE RESULT-LINES MOUNTS : runs the marker; output in $tmp/mk-NAME/console
	local d=$tmp/mk-$1
	mkdir -p "$d/proc" "$d/run/rbft" "$d/sys/class/net" "$d/bin"
	printf '%s\n' "$2" > "$d/proc/cmdline"
	[ -z "$3" ] || printf '%b' "$3" > "$d/run/rbft/result"
	printf '%b' "$4" > "$d/proc/mounts"
	printf '#!/bin/sh\necho 6.8.0-test\n' > "$d/bin/uname"
	printf '#!/bin/sh\necho "systemctl $*" >> "$RBFT_ROOT/calls"\n' > "$d/bin/systemctl"
	printf '#!/bin/sh\necho "poweroff $*" >> "$RBFT_ROOT/calls"\n' > "$d/bin/poweroff"
	printf '#!/bin/sh\nexit 0\n' > "$d/bin/sleep"
	chmod +x "$d/bin/"*
	[ -z "${EFI:-}" ] || mkdir -p "$d/sys/firmware/efi"
	[ -z "${SYSTEMD:-}" ] || mkdir -p "$d/run/systemd/system"
	RBFT_ROOT=$d RBFT_CONSOLE=$d/console PATH=$d/bin:$PATH sh "$marker" > /dev/null 2>&1
}
RBDMOUNT='rootfs / rootfs rw 0 0\n/dev/rbd0p2 / ext4 ro,noatime 0 0\n'
LOCMOUNT='rootfs / rootfs rw 0 0\n/dev/vda2 / ext4 ro 0 0\n'
EFI=1 mk ok1 "rbft.hook=1" 'TABLE=PASS\nMAPPED=1\nDEV=/dev/rbd0p2\nSRC=sysfs\nREQUIRE=0\nIMAGE=wrtest-p2-lin-uefi\n' "$RBDMOUNT"
if grep -q '^WRBOOT-ROOT-OK fw=uefi root=/dev/rbd0p2 fstype=ext4 mapped=rbd0 table=PASS src=sysfs image=wrtest-p2-lin-uefi kernel=6.8.0-test$' "$tmp/mk-ok1/console"; then ok "marker: WRBOOT-ROOT-OK with / on the mapped image, table PASS, source, image, kernel"; else bad "marker ok1: $(cat "$tmp/mk-ok1/console")"; fi
# the result file is data: a value that looks like a command is printed, never run
PWN=$tmp/pwned
EFI=1 mk inj "rbft.hook=1" "TABLE=PASS\nMAPPED=0\nDEV=\nSRC=sysfs\nREQUIRE=0\nIMAGE=\$(touch $PWN);touch $PWN\n" "$LOCMOUNT"
if [ ! -e "$PWN" ] && grep -q '^WRBOOT-ROOT-OK ' "$tmp/mk-inj/console"; then ok "marker: a command-looking IMAGE in the result file is not executed"; else bad "marker executed a value of the result file"; fi
mk ok2 "rbft.hook=1 rbft.map=0" 'TABLE=PASS\nMAPPED=0\nDEV=\nSRC=sysfs\nREQUIRE=0\nIMAGE=x\n' "$LOCMOUNT"
grep -q '^WRBOOT-ROOT-OK fw=bios root=/dev/vda2 .* mapped=none table=PASS' "$tmp/mk-ok2/console" && ok "marker: a local root with a passing table is OK (plain QEMU run), fw=bios" || bad "marker ok2: $(cat "$tmp/mk-ok2/console")"
mk ok3 "root=/dev/vda2" "" "$LOCMOUNT"
grep -q '^WRBOOT-ROOT-OK .* table=off ' "$tmp/mk-ok3/console" && ok "marker: no hook, no table: table=off" || bad "marker ok3: $(cat "$tmp/mk-ok3/console")"
mk tf "rbft.hook=1" 'TABLE=FAIL\nMAPPED=0\nDEV=\nSRC=sysfs\nREQUIRE=0\nIMAGE=x\n' "$LOCMOUNT"
grep -q '^WRBOOT-ROOT-TABLE-FAIL ' "$tmp/mk-tf/console" && ! grep -q '^WRBOOT-ROOT-OK' "$tmp/mk-tf/console" && ok "marker: a failing table prints WRBOOT-ROOT-TABLE-FAIL and never WRBOOT-ROOT-OK" || bad "marker tf: $(cat "$tmp/mk-tf/console")"
mk tu "rbft.hook=1" 'TABLE=UNUSABLE\nMAPPED=0\nDEV=\nSRC=fwcfg\nREQUIRE=0\nIMAGE=\n' "$LOCMOUNT"
grep -q '^WRBOOT-ROOT-TABLE-FAIL ' "$tmp/mk-tu/console" && ok "marker: an unusable table is a failure too" || bad "marker tu"
mk wr "rbft.hook=1" 'TABLE=PASS\nMAPPED=1\nDEV=/dev/rbd0p2\nSRC=sysfs\nREQUIRE=0\nIMAGE=x\n' "$LOCMOUNT"
grep -q '^WRBOOT-ROOT-WRONG ' "$tmp/mk-wr/console" && ok "marker: the image was mapped but / is elsewhere: WRBOOT-ROOT-WRONG" || bad "marker wr"
mk nr "rbft.hook=1 rbft.require=1" 'TABLE=PASS\nMAPPED=0\nDEV=\nSRC=sysfs\nREQUIRE=1\nIMAGE=x\n' "$LOCMOUNT"
grep -q '^WRBOOT-ROOT-NOT-RBD ' "$tmp/mk-nr/console" && ok "marker: rbft.require=1 and a root that is not on the image: WRBOOT-ROOT-NOT-RBD" || bad "marker nr"
mk nt "rbft.hook=1" 'TABLE=NONE\nMAPPED=0\nDEV=\nSRC=none\nREQUIRE=0\nIMAGE=\n' "$LOCMOUNT"
grep -q '^WRBOOT-ROOT-OK .* table=NONE src=none' "$tmp/mk-nt/console" && ok "marker: no table and no requirement: OK with table=NONE" || bad "marker nt"
mk ini "rbft.hook=1 rbft.map=0" 'TABLE=PASS\nMAPPED=0\nDEV=\nSRC=scan\nREQUIRE=0\nIMAGE=\n' 'rootfs / rootfs rw 0 0\n'
grep -q '^WRBOOT-ROOT-OK fw=bios root=initramfs ' "$tmp/mk-ini/console" && ok "marker: the initramfs-only system (row B0) reports root=initramfs" || bad "marker ini: $(cat "$tmp/mk-ini/console")"
mkdir -p "$tmp/mk-edd/sys/firmware/edd/int13_dev80" "$tmp/mk-edd/sys/firmware/edd/int13_dev81"
echo 0x12345678 > "$tmp/mk-edd/sys/firmware/edd/int13_dev81/mbr_signature"
cp -R "$tmp/mk-ini/." "$tmp/mk-edd/" 2> /dev/null
RBFT_ROOT=$tmp/mk-edd RBFT_CONSOLE=$tmp/mk-edd/console PATH=$tmp/mk-edd/bin:$PATH sh "$marker" > /dev/null 2>&1
grep -q '^WRBOOT-EDD int13_dev80 ' "$tmp/mk-edd/console" && grep -q '^WRBOOT-EDD int13_dev81 mbr_signature=0x12345678' "$tmp/mk-edd/console" && ok "marker: the BIOS drives the kernel was told about are listed (EDD)" || bad "marker edd: $(cat "$tmp/mk-edd/console")"
SYSTEMD=1 mk po "rbft.hook=1 rbft.poweroff=1" 'TABLE=PASS\nMAPPED=0\nDEV=\nSRC=sysfs\nREQUIRE=0\nIMAGE=\n' "$LOCMOUNT"
grep -q 'systemctl --no-block poweroff' "$tmp/mk-po/calls" && ok "marker: rbft.poweroff=1 powers the guest off with systemd" || bad "marker poweroff"
mk po2 "rbft.hook=1 rbft.poweroff=1" 'TABLE=PASS\nMAPPED=0\nDEV=\nSRC=sysfs\nREQUIRE=0\nIMAGE=\n' 'rootfs / rootfs rw 0 0\n'
grep -q 'poweroff -f' "$tmp/mk-po2/calls" && ok "marker: ... and with poweroff -f where there is no systemd" || bad "marker poweroff -f"
mk np "rbft.hook=1" 'TABLE=PASS\nMAPPED=0\nDEV=\nSRC=sysfs\nREQUIRE=0\nIMAGE=\n' "$LOCMOUNT"
[ ! -e "$tmp/mk-np/calls" ] && ok "marker: without rbft.poweroff=1 the guest stays up" || bad "marker powered off unasked"

# ---------------------------------------------------------------------------------------------------------------------------
section "files of the initramfs and the build scripts"
check "the hook, the initramfs hook, the marker and the tiny init are executable" test -x "$hook" -a -x "$here/initramfs/hooks/rbft" -a -x "$marker" -a -x "$here/initramfs/tiny/init"
nreq=$(awk '$1 == "required"' "$here/initramfs/modules" | wc -l)
bogus=$(awk '$1 !~ /^#/ && NF && $1 != "required" && $1 != "optional"' "$here/initramfs/modules")
if [ "$nreq" -ge 8 ] && [ -z "$bogus" ]; then ok "modules list: $nreq required modules, every line is required/optional/comment"; else bad "modules list: $nreq required; bad lines: $bogus"; fi
for m in libceph rbd virtio_net; do
	grep -q "^required $m\$" "$here/initramfs/modules" && ok "modules list requires $m" || bad "modules list lacks $m"
done
check "the unit and the script agree on the path" grep -q 'ExecStart=/usr/local/sbin/wrboot-marker' "$here/initramfs/system/wrboot-marker.service"
for f in "$hook" "$marker" "$here/initramfs/hooks/rbft" "$here/initramfs/tiny/init"; do
	n=${f#"$here"/}
	if sh -n "$f" 2> /dev/null; then ok "sh -n $n"; else bad "sh -n $n"; fi
	if command -v dash > /dev/null 2>&1; then if dash -n "$f" 2> /dev/null; then ok "dash -n $n"; else bad "dash -n $n"; fi; fi
done
for f in build-uefi.sh build-bios.sh boot-test.sh import.sh expected-table.sh selftest.sh initramfs/lib/image-common.sh; do
	if bash -n "$here/$f" 2> /dev/null; then ok "bash -n $f"; else bad "bash -n $f"; fi
done
if command -v shellcheck > /dev/null 2>&1; then
	# from the directory of the scripts: shellcheck resolves the "source=" paths of build-*.sh from the current directory
	if (cd "$here" && shellcheck -x -s sh initramfs/scripts/local-top/rbft initramfs/system/wrboot-marker initramfs/hooks/rbft initramfs/tiny/init) > "$tmp/sc.out" 2>&1; then ok "shellcheck (sh): hook, marker, initramfs hook, tiny init"; else bad "shellcheck (sh): $(head -n 8 "$tmp/sc.out")"; fi
	if (cd "$here" && shellcheck -x build-uefi.sh build-bios.sh boot-test.sh import.sh expected-table.sh selftest.sh initramfs/lib/image-common.sh) > "$tmp/sc.out" 2>&1; then ok "shellcheck (bash): build scripts, import.sh, expected-table.sh, selftest.sh, the library"; else bad "shellcheck (bash): $(head -n 8 "$tmp/sc.out")"; fi
else
	skip "shellcheck is not installed"
fi

section "build-uefi.sh, build-bios.sh, boot-test.sh: options and plans (no root, nothing built)"
for s in build-uefi.sh build-bios.sh; do
	out=$(bash "$here/$s" -n --out "$tmp/img-$s.raw" 2>&1) && prc=0 || prc=$?
	if [ "$prc" = 0 ] && printf '%s' "$out" | grep -q 'plan' && [ ! -e "$tmp/img-$s.raw" ]; then ok "$s -n prints a plan and creates nothing"; else bad "$s -n: $out"; fi
	for badopt in "--size 4096" "--size 100" "--size abc" "--mirror ftp://x" "--release No_Good" "--nonsense" "--out"; do
		# shellcheck disable=SC2086
		if bash "$here/$s" -n $badopt > /dev/null 2>&1; then bad "$s accepted $badopt"; else ok "$s refuses $badopt"; fi
	done
	: > "$tmp/exists.raw"
	if bash "$here/$s" -n --out "$tmp/exists.raw" > /dev/null 2>&1; then bad "$s overwrites an existing image without --force"; else ok "$s refuses an existing image without --force"; fi
	bash "$here/$s" -n --force --out "$tmp/exists.raw" > /dev/null 2>&1 && ok "$s -n --force accepts it" || bad "$s --force"
	bash "$here/$s" --help 2> /dev/null | grep -q 'dry-run' && ok "$s --help documents -n" || bad "$s --help"
done
# the re-run as root: a user that is not root gets sudo, with the script's own arguments and the settings (a run once rebuilt the
# default image instead of "--tiny", and lost IMG_WORK / --mirror, because the option loop had shifted the arguments away and
# "sudo -E" is ignored by some sudo). The tools are stand-ins that exit 0; sudo is a stand-in that logs its arguments.
rr=$tmp/reroot
mkdir -p "$rr/bin" "$rr/grub/i386-pc" "$rr/grub/x86_64-efi"
for t in debootstrap sgdisk sfdisk losetup mkfs.ext4 mkfs.ext2 mkfs.vfat grub-install gcc tar zstd e2fsck fallocate truncate sha256sum mount umount chroot cpio gzip; do
	printf '#!/bin/sh\nexit 0\n' > "$rr/bin/$t"
	chmod +x "$rr/bin/$t"
done
printf '#!/bin/sh\nfor a in "$@"; do printf "%%s\\n" "$a"; done > "%s/sudo.args"\nexit 0\n' "$rr" > "$rr/bin/sudo"
chmod +x "$rr/bin/sudo"
rr_run() { # SCRIPT ARGS... : run a build script as a "user that is not root" with the stand-in tools; the arguments sudo got are in sudo.args
	local scr=$1
	shift
	rm -f "$rr/sudo.args"
	IMG_TEST_UID=1000 IMG_GRUB_DIR=$rr/grub IMG_WORK=$rr/work PATH=$rr/bin:$PATH bash "$here/$scr" "$@" > "$rr/out" 2>&1
}
if rr_run build-bios.sh --tiny --force --out "$rr/o.raw" --mirror http://m.example/ubuntu && [ -s "$rr/sudo.args" ] \
	&& grep -qx -- '--tiny' "$rr/sudo.args" && grep -qx -- '--force' "$rr/sudo.args" && grep -qx -- "$rr/o.raw" "$rr/sudo.args" \
	&& grep -qx -- 'http://m.example/ubuntu' "$rr/sudo.args" && grep -qx "IMG_WORK=$rr/work" "$rr/sudo.args" && grep -qx env "$rr/sudo.args"; then
	ok "build-bios.sh as a user: sudo gets the script's own arguments (--tiny --force --out --mirror) and IMG_WORK"
else
	bad "build-bios.sh re-run as root loses its arguments: $(tr '\n' ' ' < "$rr/sudo.args" 2> /dev/null) $(head -n 3 "$rr/out")"
fi
if rr_run build-uefi.sh --size 1024 --release jammy && grep -qx -- '--size' "$rr/sudo.args" && grep -qx -- '1024' "$rr/sudo.args" && grep -qx -- 'jammy' "$rr/sudo.args"; then
	ok "build-uefi.sh as a user: sudo gets --size and --release"
else
	bad "build-uefi.sh re-run as root loses its arguments: $(tr '\n' ' ' < "$rr/sudo.args" 2> /dev/null)"
fi
if rr_run build-uefi.sh && [ -s "$rr/sudo.args" ] && grep -qx "IMG_MIRROR=http://archive.ubuntu.com/ubuntu" "$rr/sudo.args"; then ok "build-uefi.sh with no arguments: the settings still go through env"; else bad "build-uefi.sh re-run with no arguments"; fi
bash "$here/boot-test.sh" --help > /dev/null 2>&1 && ok "boot-test.sh --help" || bad "boot-test.sh --help"
for badargs in "" "nonsense-case" "--cpus 9 uefi-good" "--mem 99999 uefi-good" "--timeout x uefi-good" "--accel hw uefi-good" "--nonsense uefi-good" "--qemu /nonexistent/qemu uefi-good"; do
	# shellcheck disable=SC2086
	bash "$here/boot-test.sh" $badargs > "$tmp/bt.out" 2>&1
	[ $? = 2 ] && ok "boot-test.sh refuses with exit 2: ${badargs:-no case}" || bad "boot-test.sh accepted: $badargs"
done
out=$(bash "$here/build-bios.sh" -n --tiny --out "$tmp/tiny.raw" 2>&1)
printf '%s' "$out" | grep -q 'tiny image of row B0' && ok "build-bios.sh --tiny -n plans the B0 disk" || bad "tiny plan: $out"
if command -v git > /dev/null 2>&1; then
	g=$tmp/repo
	mkdir -p "$g/ignored" && git -C "$g" init -q 2> /dev/null && printf 'ignored/\n' > "$g/.gitignore"
	if bash "$here/build-uefi.sh" -n --out "$g/tracked.raw" > /dev/null 2>&1; then bad "an image path git would track was accepted"; else ok "an image path inside a git work tree that is not ignored is refused"; fi
	bash "$here/build-uefi.sh" -n --out "$g/ignored/ok.raw" > /dev/null 2>&1 && ok "an ignored path inside a work tree is accepted" || bad "an ignored path was refused"
else
	skip "git is not installed"
fi
# the harness repository ignores the image kinds
if [ -d "$here/../../../../.git" ] || [ -f "$here/../../../../.git" ]; then
	repo=$(cd "$here/../../../.." && pwd)
	for f in images/x.raw images/x.img images/x.qcow2 images/out/x images/x.keyring images/x.secret; do
		git -C "$repo" check-ignore -q -- "harness/lab/p2/$f" 2> /dev/null && ok "git ignores harness/lab/p2/$f" || bad "git does not ignore harness/lab/p2/$f"
	done
fi

section "import.sh: validation and dry runs (no lab is contacted)"
imp=$here/import.sh
export P2_LAB_SSH='ssh LABHOST'
for bad_name in img-v1 img-default winrbd wrtest- 'wrtest-A' 'wrtest-a_b' 'wrtest-a b' 'wrtest-a;rm'; do
	if bash "$imp" -n user-create "$bad_name" > /dev/null 2>&1; then bad "user-create accepted the name '$bad_name'"; else ok "user-create refuses the name '$bad_name'"; fi
	if bash "$imp" -n delete "$bad_name" > /dev/null 2>&1; then bad "delete accepted the name '$bad_name'"; else ok "delete refuses the name '$bad_name'"; fi
done
for p in rbd .mgr 'winrbd2' 'a;b'; do
	if bash "$imp" -n user-create wrtest-x --pool "$p" > /dev/null 2>&1; then bad "a pool '$p' was accepted"; else ok "pool '$p' is refused"; fi
done
bash "$imp" -n user-create wrtest-p2-lin-uefi > "$tmp/imp.out" 2>&1 && grep -q 'ceph auth get-or-create' "$tmp/imp.out" && grep -q 'key_type aes' "$tmp/imp.out" && ok "user-create: legacy aes key, pool-limited caps (dry run shows the command)" || bad "user-create dry run"
head -c 40000000 /dev/zero > "$tmp/disk.raw" 2> /dev/null
bash "$imp" -n import --image "$tmp/disk.raw" --name wrtest-p2-lin-uefi > "$tmp/imp.out" 2>&1 && grep -q 'rbd import --no-progress --image-format 2 --image-feature layering --dest-pool winrbd' "$tmp/imp.out" && ok "import: format 2, feature layering only, pool winrbd" || bad "import dry run: $(cat "$tmp/imp.out")"
if bash "$imp" -n import --image "$tmp/nonexistent.raw" --name wrtest-x > /dev/null 2>&1; then bad "import of a missing file"; else ok "import refuses a missing file"; fi
head -c 1000 /dev/zero > "$tmp/small.raw"
if bash "$imp" -n import --image "$tmp/small.raw" --name wrtest-x > /dev/null 2>&1; then bad "import of a tiny file"; else ok "import refuses a file that is not a disk image"; fi
bash "$imp" -n check --name wrtest-p2-lin-uefi --sha256 "$(printf 'a%.0s' $(seq 1 64))" --rootpart 2 > "$tmp/imp.out" 2>&1 && ok "check: dry run" || bad "check dry run"
if bash "$imp" -n check --name wrtest-x --sha256 XYZ > /dev/null 2>&1; then bad "check accepted a non-hex digest"; else ok "check refuses a non-hex digest"; fi
if bash "$imp" -n check --name wrtest-x --rootpart x > /dev/null 2>&1; then bad "check accepted --rootpart x"; else ok "check refuses a non-numeric --rootpart"; fi
if grep -qi "secret\|key = " "$tmp/imp.out"; then bad "a dry run mentions a key"; else ok "dry runs print no key"; fi
if bash "$imp" bogus > /dev/null 2>&1; then bad "unknown command accepted"; else ok "import.sh refuses an unknown command"; fi
unset P2_LAB_SSH
if (unset LAB_DIR; bash "$imp" list > /dev/null 2>&1); then bad "import.sh ran without a lab"; else ok "import.sh says so when no lab is configured"; fi

section "import.sh against stand-ins for the lab VM (a fake ssh that runs the remote command here, fake sudo / rbd / ceph)"
if [ "$(uname -s)" = Linux ] && [ -d /dev/shm ] && [ -w /dev/shm ]; then
	fl=$tmp/fakelab
	mkdir -p "$fl/bin" "$fl/state"
	# ssh: run the remote command line with bash, in this machine, with the stand-ins first on the PATH
	printf '#!/bin/sh\nPATH=%s/bin:$PATH exec bash -c "$1"\n' "$fl" > "$fl/fakessh"
	printf '#!/bin/sh\nexec "$@"\n' > "$fl/bin/sudo"
	cat > "$fl/bin/rbd" <<'STUB'
#!/bin/sh
# state: $FL/state/image (the "image": its bytes), $FL/rbd.log
echo "rbd $*" >> "$FL/rbd.log"
case $1 in
info) [ -e "$FL/state/image" ] && case $* in *json*) echo "{\"name\": \"x\", \"size\": $(wc -c < "$FL/state/image")}" ;; esac ;;
rm) rm -f "$FL/state/image" ;;
export) cat "$FL/state/image" ;;
import) cat > "$FL/state/image"; [ -z "$FL_IMPORT_FAIL" ] ;;
*) exit 1 ;;
esac
STUB
	printf '#!/bin/sh\nexit 1\n' > "$fl/bin/ceph" # no cephx users: the krbd part of check is skipped
	chmod +x "$fl/fakessh" "$fl/bin/sudo" "$fl/bin/rbd" "$fl/bin/ceph"
	export FL=$fl
	flab() { P2_LAB_SSH="$fl/fakessh" bash "$imp" "$@"; }
	: > "$fl/rbd.log"
	# a transfer that fails leaves nothing behind
	FL_IMPORT_FAIL=1 flab import --image "$tmp/disk.raw" --name wrtest-fake > "$tmp/fl.out" 2>&1
	frc=$?
	if [ "$frc" != 0 ] && [ ! -e "$fl/state/image" ] && grep -q 'rbd rm' "$fl/rbd.log" && grep -q 'partial image was removed' "$tmp/fl.out"; then ok "import: a failed transfer removes the partial image and says so"; else bad "failed import: rc=$frc $(tail -n 2 "$tmp/fl.out" | tr '\n' ' ')"; fi
	# a transfer that works
	: > "$fl/rbd.log"
	if flab import --image "$tmp/disk.raw" --name wrtest-fake > "$tmp/fl.out" 2>&1 && [ "$(wc -c < "$fl/state/image")" = 40000000 ]; then ok "import: the bytes arrive (through the stand-in lab)"; else bad "import: $(tail -n 3 "$tmp/fl.out" | tr '\n' ' ')"; fi
	# check: the digest of the export; no user: PARTIAL, exit 3 (a skipped part is not a pass)
	want=$(sha256sum "$tmp/disk.raw" | cut -d' ' -f1)
	flab check --name wrtest-fake --sha256 "$want" > "$tmp/fl.out" 2>&1
	frc=$?
	if [ "$frc" = 3 ] && grep -q '^CHECK PASS rbd export has the SHA-256' "$tmp/fl.out" && grep -q '^CHECK SKIP no user' "$tmp/fl.out" && grep -q '^CHECK-RESULT PARTIAL' "$tmp/fl.out"; then ok "check: digest right, krbd part skipped (no user): CHECK-RESULT PARTIAL, exit 3, not a pass"; else bad "check partial: rc=$frc $(tail -n 3 "$tmp/fl.out" | tr '\n' ' ')"; fi
	flab check --name wrtest-fake --sha256 "$(printf 'b%.0s' $(seq 1 64))" > "$tmp/fl.out" 2>&1
	frc=$?
	if [ "$frc" = 1 ] && grep -q '^CHECK FAIL rbd export SHA-256' "$tmp/fl.out" && grep -q '^CHECK-RESULT FAIL' "$tmp/fl.out"; then ok "check: a wrong digest is CHECK-RESULT FAIL, exit 1 (the negative control)"; else bad "check wrong digest: rc=$frc"; fi
	flab check --name wrtest-fake > "$tmp/fl.out" 2>&1
	frc=$?
	[ "$frc" = 3 ] && grep -q '^CHECK SKIP no digest' "$tmp/fl.out" && ok "check: nothing to compare with is PARTIAL, not a pass" || bad "check without digest: rc=$frc"
	rm -f "$fl/state/image"
	flab check --name wrtest-fake --sha256 "$want" > "$tmp/fl.out" 2>&1
	frc=$?
	[ "$frc" != 0 ] && grep -q 'does not exist' "$tmp/fl.out" && ok "check: a missing image is a failure" || bad "check of a missing image"
	unset FL
else
	skip "the stand-in lab needs Linux with /dev/shm"
fi

section "import.sh expect: the expected values inside an image"
if command -v debugfs > /dev/null 2>&1 && command -v sfdisk > /dev/null 2>&1 && command -v mke2fs > /dev/null 2>&1 && [ "$(uname -s)" = Linux ]; then
	img=$tmp/exp.raw
	truncate -s 40M "$img"
	# an MBR with two partitions, written by hand (sfdisk syncs the disk, which can take minutes on a busy machine)
	python3 -I - "$img" <<'PY'
import struct, sys
f = open(sys.argv[1], "r+b")
ent = lambda boot, typ, start, size: struct.pack("<B3sB3sII", boot, b"\0\0\0", typ, b"\0\0\0", start, size)
f.seek(446)
f.write(ent(0, 0x0c, 2048, 16384) + ent(0x80, 0x83, 20480, 40960) + bytes(32))
f.write(b"\x55\xaa")
f.close()
PY
	if mke2fs -q -F -t ext4 -E offset=$((20480 * 512)) -L wrbroot "$img" 8M > /dev/null 2>&1; then
		debugfs -w -R "mkdir /boot" "$img?offset=$((20480 * 512))" > /dev/null 2>&1
		debugfs -w -R "mkdir /boot/grub" "$img?offset=$((20480 * 512))" > /dev/null 2>&1
		printf 'kind=uefi\nimage_sha256=%s\n' "$(printf '0%.0s' $(seq 1 64))" > "$img.manifest"
		if bash "$imp" expect --image "$img" --opts "--pool other --mons 10.1.2.3:3300" > "$tmp/exp.out" 2>&1; then
			if [ "$(sed -n 's/^image_sha256=//p' "$img.manifest")" = "$(sha256sum "$img" | cut -d' ' -f1)" ] && grep -q '^kind=uefi' "$img.manifest"; then ok "expect: the digest in the manifest follows the changed image (check --manifest stays right)"; else bad "expect left a stale digest in the manifest"; fi
			back=$(debugfs -R "cat /boot/grub/rbft-extra.cfg" "$img?offset=$((20480 * 512))" 2> /dev/null)
			case $back in
			'set rbft_extra="rbft.mons=10.1.2.3:3300 rbft.entity=winrbd-aes rbft.pool=other '*) ok "expect: /boot/grub/rbft-extra.cfg holds the expectations of the options, in the last partition" ;;
			*) bad "expect wrote: $back" ;;
			esac
			bash "$imp" expect --image "$img" --words "rbft.pool=again" > /dev/null 2>&1
			back=$(debugfs -R "cat /boot/grub/rbft-extra.cfg" "$img?offset=$((20480 * 512))" 2> /dev/null)
			[ "$back" = 'set rbft_extra="rbft.pool=again"' ] && ok "expect: a second call replaces the file" || bad "expect replace: $back"
			if bash "$imp" expect --image "$img" --words 'rbft.pool=a"b' > /dev/null 2>&1; then bad "expect accepted a quote"; else ok "expect refuses a quote in the words"; fi
			if bash "$imp" expect --image "$img" --words 'rbft.key=AAAA' > /dev/null 2>&1; then bad "expect accepted a key"; else ok "expect refuses a key (it does not belong in an image)"; fi
			if bash "$imp" expect --image "$img" > /dev/null 2>&1; then bad "expect without words"; else ok "expect needs --opts or --words"; fi
		else bad "expect failed: $(cat "$tmp/exp.out")"; fi
	else skip "mke2fs does not support -E offset here"; fi
else
	skip "expect needs Linux with debugfs, sfdisk and mke2fs"
fi

printf '\nselftest.sh: %d passed, %d failed, %d skipped\n' "$npass" "$nfail" "$nskip"
[ "$nfail" = 0 ]
