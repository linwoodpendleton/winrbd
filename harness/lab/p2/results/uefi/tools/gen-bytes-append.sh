#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# gen-bytes-append.sh MD5SUMS - the iPXE commands of the SAN-level byte check (run-script option --append): after the sanhook, every file of
# the byte-check disk (build-bytes-image.sh) is fetched through the SAN device by the firmware's FAT driver (file://WRBYTES/<name>, the
# volume found by its label) and digested in iPXE. Prints the commands on stdout; the result lines are
#   WRBYTES-FILE <name>   (then iPXE's md5sum line: "<md5>  <image name>")   or   WRBYTES-FAIL <name>
#   WRBYTES-DONE
# analyze.py (profile bytes) compares those digests with the list and with the files read out of rbd export.
set -euo pipefail
[ $# -eq 1 ] && [ -r "$1" ] || { echo "usage: gen-bytes-append.sh MD5SUMS" >&2; exit 2; }
echo 'echo WRINFO-BEGIN'
echo 'rbd-info'
echo 'echo WRINFO-END'
while read -r _ name; do
    [ -n "$name" ] || continue
    case $name in *[!A-Za-z0-9.+-]*) echo "gen-bytes-append.sh: odd file name $name" >&2; exit 2;; esac
    echo "echo WRBYTES-FILE $name"
    echo "imgfetch --name wrb file://WRBYTES/$name || goto fail-$name"
    echo "md5sum wrb"
    echo "imgfree wrb"
    echo "goto next-$name"
    echo ":fail-$name"
    echo "echo WRBYTES-FAIL $name"
    echo ":next-$name"
done < "$1"
echo 'echo WRINFO-BEGIN'
echo 'rbd-info'
echo 'echo WRINFO-END'
echo 'echo WRBYTES-DONE'
