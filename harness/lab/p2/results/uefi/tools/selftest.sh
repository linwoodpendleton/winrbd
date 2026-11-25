#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# selftest.sh - the offline test of the scripts that ran the UEFI rows of the live matrix (ctest uefi.selftest). Needs python3; the byte-check disk
# part also needs sfdisk, mkfs.vfat and mtools (it is skipped, with a line saying so, when one is missing).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
command -v python3 >/dev/null 2>&1 || { echo "uefi selftest: python3 is missing"; exit 77; }
exec python3 -I "$here/selftest.py"
