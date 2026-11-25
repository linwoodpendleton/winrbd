#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# The rows of this module in the order they were run (matrix.sh, matrix2.sh and matrix3.sh; the first was stopped after four rows because the B2/B3 media need ipxe.lkrn, which had not been built yet).
# This file is a record: the scripts below were run one after the other (the paths are those of the build box and the builder guest), it is not meant to be run as one script.
# the BIOS rows of this module, one after the other; progress in $P2B_WORK/matrix.progress
. $BOX_BIOS2/env.sh
cd $BIN
P=$P2B_WORK/matrix.progress
printf 'rbd-xbft\nrbd-info\n' > $P2B_WORK/append-xbft.ipxe
row() { # label row variant [options]
  local label=$1; shift
  echo "$(date -u +%H:%M:%S) START $label $*" >> $P
  nice -n 19 bash runrow.sh $label "$@" >> $P2B_WORK/matrix.out 2>&1
  echo "$(date -u +%H:%M:%S) END   $label rc=$? $(grep -h '^VERDICT' $P2B_WORK/results/$label/result.txt 2>/dev/null | head -1)" >> $P
}
: > $P
# 1. the stack decision: no core stack (iPXE stack 16 KiB, measured), then as shipped with the monitor, then the interrupt-flag diagnostic
row B1-nt-1 b1 dbg
row B3-nt-1 b3 dbg
row B2-nt-1 b2 dbg
row B1-i386-sm-1 b1 i386-sm
row B2-i386-sm-1 b2 i386-sm
row B3-i386-sm-1 b3 i386-sm
row B1-if-1 b1 fix
row B3-if-1 b3 fix
# 2. B0 with the new commands: the tables as iPXE sees them, the exit warning (undionly), the control (native drivers)
row B0-i386-rel-1 b0 i386-rel --append $P2B_WORK/append-xbft.ipxe
row B0-rel-1 b0 rel --append $P2B_WORK/append-xbft.ipxe
row B0N-i386-rel-1 b0 i386-rel --bin ipxe.pxe --append $P2B_WORK/append-xbft.ipxe
# 3. the release builds, rows B1 to B3 and the negative control, both word sizes
row B1-i386-rel-1 b1 i386-rel
row B2-i386-rel-1 b2 i386-rel
row B3-i386-rel-1 b3 i386-rel
row B1-rel-1 b1 rel
row B2-rel-1 b2 rel
row B3-rel-1 b3 rel
row NEG-i386-rel-1 neg i386-rel
row B1-i386-rel-2 b1 i386-rel
row B3-i386-rel-2 b3 i386-rel
row B1-sm-1 b1 sm
echo "$(date -u +%H:%M:%S) MATRIX-DONE" >> $P
. $BOX_BIOS2/env.sh
cd $BIN
P=$P2B_WORK/matrix.progress
printf 'rbd-xbft\nrbd-info\n' > $P2B_WORK/append-xbft.ipxe
row() { # label row variant [options]
  local label=$1; shift
  echo "$(date -u +%H:%M:%S) START $label $*" >> $P
  nice -n 19 bash runrow.sh $label "$@" >> $P2B_WORK/matrix.out 2>&1
  echo "$(date -u +%H:%M:%S) END   $label rc=$? $(grep -h '^VERDICT' $P2B_WORK/results/$label/result.txt 2>/dev/null | head -1)" >> $P
}
echo "$(date -u +%H:%M:%S) MATRIX2-START" >> $P
row B3-nt-1 b3 dbg
row B2-nt-1 b2 dbg
row B2-i386-sm-1 b2 i386-sm
row B3-i386-sm-1 b3 i386-sm
row B1-if-1 b1 fix
row B3-if-1 b3 fix
row B0-i386-rel-1 b0 i386-rel --append $P2B_WORK/append-xbft.ipxe
row B0-i386-sm-1 b0 i386-sm --append $P2B_WORK/append-xbft.ipxe
row B0-rel-1 b0 rel --append $P2B_WORK/append-xbft.ipxe
row B0N-i386-rel-1 b0 i386-rel --bin ipxe.pxe --append $P2B_WORK/append-xbft.ipxe
row B1-i386-rel-1 b1 i386-rel
row B2-i386-rel-1 b2 i386-rel
row B3-i386-rel-1 b3 i386-rel
row B1-rel-1 b1 rel
row B2-rel-1 b2 rel
row B3-rel-1 b3 rel
row NEG-i386-rel-1 neg i386-rel
row B1-i386-rel-2 b1 i386-rel
row B3-i386-rel-2 b3 i386-rel
row B1-sm-1 b1 sm
echo "$(date -u +%H:%M:%S) MATRIX-DONE" >> $P
. $BOX_BIOS2/env.sh
cd $BIN
P=$P2B_WORK/matrix.progress
echo "$(date -u +%H:%M:%S) MATRIX3-START" >> $P
row() { local label=$1; shift
  echo "$(date -u +%H:%M:%S) START $label $*" >> $P
  nice -n 19 bash runrow.sh $label "$@" >> $P2B_WORK/matrix.out 2>&1
  echo "$(date -u +%H:%M:%S) END   $label rc=$? $(grep -h '^VERDICT' $P2B_WORK/results/$label/result.txt 2>/dev/null | head -1)" >> $P; }
wrow() { local label=$1; shift
  echo "$(date -u +%H:%M:%S) START $label $*" >> $P
  nice -n 19 bash runwinpe.sh $label "$@" >> $P2B_WORK/matrix.out 2>&1
  echo "$(date -u +%H:%M:%S) END   $label rc=$?" >> $P; }
row B1-x64fix-1 b1 dbg
row B3-x64fix-1 b3 dbg
export PATH=$BOX_BIOS2/mt/root/usr/bin:$PATH
wrow W3-i386-1 w3 i386-rel
wrow W4-i386-1 w4 i386-rel
wrow W3-x64-1 w3 rel
wrow W4-x64-1 w4 rel
echo "$(date -u +%H:%M:%S) MATRIX3-DONE" >> $P
