#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 matrix row B2 (design section 14.3): SeaBIOS, a USB stick (MBR + FAT + syslinux) that starts `ipxe.lkrn`.
#
#   The stick is built by make-usb.sh; syslinux hands the run script to iPXE as its initrd. A ready-made bin/ipxe.usb with an embedded
# script works with --media FILE --delivery embed.
#
# One run = one QEMU guest in a run directory of its own, with the serial console in a log; the script waits for the stage named by
# --expect (default: "san" when a target is given, else "ipxe") and prints one last line "RESULT row=... met=0|1 ...".
# Exit status: 0 the expected stage was reached, 1 it was not, 2 usage / environment, 4 something left behind or the key found in a log.
#
#   run-bios-usb.sh --help          every option (the list is the same for the six scripts; README.md has the matrix)
#   run-bios-usb.sh -n              print the QEMU command line and the iPXE script (key hidden), start nothing
#   run-bios-usb.sh --pool P --image I --user U --key-file K [--mon 10.77.0.10:3300] [--action sanhook|sanboot] [--expect san|os]
#
# Needs: the iPXE binary ipxe.lkrn in --ipxe-dir (default $P2Q_WORK/ipxe), qemu-system-x86_64 with KVM, python3, and for the UEFI
# rows OVMF (OVMF_CODE_4M.fd / OVMF_VARS_4M.fd). The library is common.sh; this file only says which row it is.
set -u -o pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$here/common.sh"
q_main bios-usb "$@"
exit $?
