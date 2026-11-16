#!/bin/sh
# SPDX-License-Identifier: MIT
#
# fetch-ceph-ref.sh - download the few Ceph files the checkers read at run time.
#
# What it fetches: exactly the files listed in FILES below (the CRUSH log tables and the in-tree crushtool
# known-answer tests), from the pinned Ceph commit, over https from raw.githubusercontent.com:
#
#   https://raw.githubusercontent.com/ceph/ceph/<commit>/<path>   ->   <dest>/<path>
#
# Every file is checked against the sha256 kept in this script; a file that does not match is deleted and the
# script fails.  Files already present with the right hash are not downloaded again.
#
# Usage:   harness/tools/fetch-ceph-ref.sh [--dest DIR] [--quiet]
#   --dest DIR  where to put the files; default: $WINRBD_CEPH_SRC, else harness/.ceph-ref (git-ignored)
#   --quiet     no licence notice, no per-file lines
# Needs:   POSIX sh, curl, and one of sha256sum / shasum / openssl.
# Env:     CEPH_RAW_BASE   different base URL (a mirror); the hashes are still checked.
#
# Licence notice: the downloaded files belong to the Ceph project (https://github.com/ceph/ceph), mostly under
# LGPL-2.1 (see COPYING in the Ceph tree).  They are NOT part of winrbd, are not stored in this repository, and are
# not covered by its licence.  The checkers only read them at run time.

set -eu

COMMIT=ed27c686770872022f4c1de04f6b0ac5d5384ded
BASE=${CEPH_RAW_BASE:-https://raw.githubusercontent.com/ceph/ceph}

# sha256  path-in-the-ceph-tree          (computed from the tree at the commit above)
FILES='
9d0cdacacbb4a21da36f134368e41e835fca1d5d6058e6abebb85775339e1b1a  src/crush/crush_ln_table.h
268b70f78c0d6490a31c92a73545832f77f95cb16c44564d0c7a837dc038da0c  src/test/cli/crushtool/test-map-jewel-tunables.t
411c3fe95a514e7f3890879e40f8f1851a987cf57220574c453e3683728d22f0  src/test/cli/crushtool/test-map-hammer-tunables.t
9889916c3eace87448c043d6134b44347724e8207d7429dcb17950081336b3d3  src/test/cli/crushtool/test-map-legacy-tunables.t
49302596753ab66180af0c2e06761bd5e59763f01df60730a5b5e122bd8fbc86  src/test/cli/crushtool/test-map-bobtail-tunables.t
cc296abd018b76820566c6ae448108b945c00fb57892ed923b26d006628b3b94  src/test/cli/crushtool/test-map-firefly-tunables.t
fe39f33798696c16590154f2dbb7de4331873994fc1c2c41ca31642e103f9f5d  src/test/cli/crushtool/test-map-tries-vs-retries.t
30c80294d774f6a90e078a79eb8c7acffdfd20d3d7ae092d74fe981d9b4790f5  src/test/cli/crushtool/test-map-vary-r-0.t
f6fb2fed94167395b4efa80b7efb3b93c5fc14e93af183dcda19114723c2892b  src/test/cli/crushtool/test-map-vary-r-1.t
d6602de4e9601beec2dbcb394761a3068b5e9fc22b56482577ca62d98f18ceae  src/test/cli/crushtool/test-map-vary-r-2.t
294dbf3fe352e7a8c6ffda508832049ec1512841aad4dcd584d229ffb377e464  src/test/cli/crushtool/test-map-vary-r-3.t
27d83afe8c9927849c9b7aa655620fea3658a97f392a9f4d8b7306c444095e24  src/test/cli/crushtool/test-map-vary-r-4.t
3eacd04c60fa0143e298c49f6609a5b405fc01fc668f80386da28a8ea40781ca  src/test/cli/crushtool/test-map-a.crushmap
3c8979266fd148244ddd3dd05455f460c2fa411c5d40f4d7d788227716ae2b57  src/test/cli/crushtool/test-map-vary-r.crushmap
c1bf51b90ccdcc7dccef50a5d92384d444c44d75b7c3b4d915b8b30c03170b57  src/test/cli/crushtool/test-map-hammer-tunables.crushmap
4a54a318d1e9f33d1ed405edec87366add5e443433e4fcc40206f130fda46880  src/test/cli/crushtool/test-map-jewel-tunables.crushmap
df6669db23b0184704bb7b9b99d3d184f5d1ece01ef1607008365ac6df5c3d15  src/test/cli/crushtool/test-map-tries-vs-retries.crushmap
'

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
dest=${WINRBD_CEPH_SRC:-$repo/harness/.ceph-ref}
quiet=0

while [ $# -gt 0 ]; do
    case $1 in
        --dest) [ $# -ge 2 ] || { echo "fetch-ceph-ref: --dest needs a directory" >&2; exit 2; }
                dest=$2; shift 2 ;;
        --quiet) quiet=1; shift ;;
        -h|--help) sed -n '3,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "fetch-ceph-ref: unknown argument: $1" >&2; exit 2 ;;
    esac
done

say() { [ "$quiet" -eq 1 ] || echo "$@"; }

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum < "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 < "$1" | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 < "$1" | sed 's/^.*= *//'
    else
        echo "fetch-ceph-ref: need sha256sum, shasum or openssl" >&2
        return 1
    fi
}

command -v curl >/dev/null 2>&1 || { echo "fetch-ceph-ref: curl is required" >&2; exit 2; }

if [ "$quiet" -eq 0 ]; then
    cat <<EOF
NOTICE: the files fetched here belong to the Ceph project (https://github.com/ceph/ceph, commit $COMMIT).
They are licensed by Ceph (mostly LGPL-2.1, see COPYING in the Ceph tree), are not part of winrbd, are not
covered by winrbd's licence and are never committed to this repository; they go to a git-ignored directory
and the checkers read them at run time only.
EOF
fi

mkdir -p "$dest"
dest=$(cd "$dest" && pwd)
say "destination: $dest"

fail=0
n=0
got=0
# FILES is "sha256 path" pairs separated by whitespace (no spaces inside paths)
set -f
# shellcheck disable=SC2086
set -- $FILES
set +f
while [ $# -ge 2 ]; do
    want=$1
    path=$2
    shift 2
    n=$((n + 1))
    out=$dest/$path
    if [ -f "$out" ] && [ "$(sha256_of "$out")" = "$want" ]; then
        say "ok (cached)  $path"
        got=$((got + 1))
        continue
    fi
    mkdir -p "$(dirname "$out")"
    tmp=$out.part.$$
    url=$BASE/$COMMIT/$path
    if ! curl -fsSL --retry 3 --connect-timeout 20 --max-time 300 -o "$tmp" "$url"; then
        echo "fetch-ceph-ref: download failed: $url" >&2
        rm -f "$tmp"
        fail=1
        continue
    fi
    have=$(sha256_of "$tmp")
    if [ "$have" != "$want" ]; then
        echo "fetch-ceph-ref: sha256 mismatch for $path" >&2
        echo "  expected $want" >&2
        echo "  got      $have" >&2
        rm -f "$tmp"
        fail=1
        continue
    fi
    mv "$tmp" "$out"
    say "ok (fetched) $path"
    got=$((got + 1))
done

if [ "$fail" -ne 0 ]; then
    echo "fetch-ceph-ref: FAILED ($got of $n files are good)" >&2
    exit 1
fi
say "fetch-ceph-ref: $got of $n files present and verified"
