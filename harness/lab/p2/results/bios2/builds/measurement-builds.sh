#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# The builds of this module in the builder guest (Ubuntu 26.04, gcc 15.2): the release and monitor builds, the scratch measurement builds nt / if / x64, the extra ipxe.lkrn.
# This file is a record: the scripts below were run one after the other (the paths are those of the build box and the builder guest), it is not meant to be run as one script.
# ===== gbuild.sh
# guest-side: build the rel and sm variants of the BIOS images, both word sizes
set -u
cd ~/work/bios/repo
rm -rf build ipxe/build
mkdir -p ~/work/bios/out
T64="bin/undionly.kpxe bin/ipxe.pxe bin/ipxe.usb bin/ipxe.iso"
T32="bin-i386-pcbios/undionly.kpxe bin-i386-pcbios/ipxe.pxe bin-i386-pcbios/ipxe.usb bin-i386-pcbios/ipxe.iso"
build() { # name extra-cflags
  local name=$1; shift
  echo "=== $name: $*"
  nice -n 19 bash ipxe/tools/build.sh build -o ~/work/bios/tree-$name -j 8 -e ~/work/bios/stub.ipxe $T64 $T32 -- "EXTRA_CFLAGS=$*" > ~/work/bios/out/build-$name.log 2>&1
  echo "rc=$? warnings=$(grep -ci 'warning' ~/work/bios/out/build-$name.log)"
}
build rel -DCONSOLE_SERIAL
build sm -DCONSOLE_SERIAL -DRBD_STACK_MONITOR
echo GBUILD-DONE
# ===== gbuild2.sh
# guest-side: the measurement variants (scratch copies of the repository; nothing of them goes back into the repository)
set -u
cd ~/work/bios
T32="bin-i386-pcbios/undionly.kpxe bin-i386-pcbios/ipxe.pxe bin-i386-pcbios/ipxe.usb bin-i386-pcbios/ipxe.iso"
# ---- nt: no core stack (the core runs on iPXE's own stack), iPXE's stack 16 KiB so that the true peak is measured, stack monitor on
rm -rf repo-nt && cp -a repo repo-nt && rm -rf repo-nt/build repo-nt/ipxe/build
sed -i 's/^#define RBD_CORE_STACK_BYTES 16384$/#define RBD_CORE_STACK_BYTES 0/' repo-nt/ipxe/src/rbd_session.h
grep -n 'define RBD_CORE_STACK_BYTES' repo-nt/ipxe/src/rbd_session.h
cat > repo-nt/ipxe/patches/0009-scratch-stack16k.patch <<'EP'
Subject: scratch (measurement only, never committed): iPXE's i386 stack 16 KiB

---
--- a/src/arch/x86/core/stack.S
+++ b/src/arch/x86/core/stack.S
@@ -5,7 +5,7 @@
 #ifdef __x86_64__
 #define STACK_SIZE 8192
 #else
-#define STACK_SIZE 4096
+#define STACK_SIZE 16384
 #endif
 
 /****************************************************************************
EP
echo "=== nt"
nice -n 19 bash repo-nt/ipxe/tools/build.sh build -o ~/work/bios/tree-nt -j 8 -e ~/work/bios/stub.ipxe $T32 -- "EXTRA_CFLAGS=-DCONSOLE_SERIAL -DRBD_STACK_MONITOR" > ~/work/bios/out/build-nt.log 2>&1
echo "rc=$? warnings=$(grep -ci warning ~/work/bios/out/build-nt.log)"
# ---- if: the trampoline as it is, and a diagnostic that records the interrupt flag at every call of the core (scratch)
rm -rf repo-if && cp -a repo repo-if && rm -rf repo-if/build repo-if/ipxe/build
python3 - <<'EP'
p='repo-if/ipxe/src/rbd_stack.c'
s=open(p).read()
a='void rbd_call_on_stack ( void *top, void ( * fn ) ( void *arg ), void *arg ) {\n'
assert a in s
s=s.replace(a,'unsigned long rbd_if_calls, rbd_if_set;\nvoid rbd_call_on_stack ( void *top, void ( * fn ) ( void *arg ), void *arg ) {\n\tunsigned long fl;\n\t__asm__ __volatile__ ( "pushfl\\n\\tpopl %0" : "=r" ( fl ) );\n\trbd_if_calls++;\n\tif ( fl & 0x200 ) rbd_if_set++;\n')
b='	list_for_each_entry ( session, &rbd_sessions, list ) {\n		rbd_info_session ( session );'
assert b in s
s=s.replace(b,'	printf ( "rbd: DIAG-IF core calls %ld, with interrupts enabled %ld\\n", ( long ) rbd_if_calls, ( long ) rbd_if_set );\n'+b)
# also print it when the stack note prints
c='void rbd_stack_report ( void ) {\n'
assert c in s
s=s.replace(c,'extern unsigned long rbd_if_calls, rbd_if_set;\nvoid rbd_stack_report ( void ) {\n\tprintf ( "rbd: DIAG-IF core calls %ld, with interrupts enabled %ld\\n", ( long ) rbd_if_calls, ( long ) rbd_if_set );\n')
open(p,'w').write(s)
EP
echo "=== if"
nice -n 19 bash repo-if/ipxe/tools/build.sh build -o ~/work/bios/tree-if -j 8 -e ~/work/bios/stub.ipxe $T32 -- "EXTRA_CFLAGS=-DCONSOLE_SERIAL -DRBD_STACK_MONITOR" > ~/work/bios/out/build-if.log 2>&1
echo "rc=$? warnings=$(grep -ci warning ~/work/bios/out/build-if.log)"
echo GBUILD2-DONE
# ===== gbuild3.sh
set -u
cd ~/work/bios
T32="bin-i386-pcbios/ipxe.lkrn"
# the diagnostic: print immediately when interrupts are enabled at a call of the core, and every 512 calls the totals
python3 - <<'EP'
p='repo-if/ipxe/src/rbd_stack.c'
s=open(p).read()
a='\tif ( fl & 0x200 ) rbd_if_set++;\n'
assert a in s
s=s.replace(a,'\tif ( fl & 0x200 ) { rbd_if_set++; if ( rbd_if_set == 1 ) printf ( "rbd: DIAG-IF interrupts ENABLED at a core call\\n" ); }\n\tif ( ( rbd_if_calls % 512 ) == 0 ) printf ( "rbd: DIAG-IF core calls %ld, with interrupts enabled %ld\\n", ( long ) rbd_if_calls, ( long ) rbd_if_set );\n')
open(p,'w').write(s)
EP
echo "=== if (rebuild)"
nice -n 19 bash repo-if/ipxe/tools/build.sh build -o ~/work/bios/tree-if -j 8 -e ~/work/bios/stub.ipxe bin-i386-pcbios/undionly.kpxe bin-i386-pcbios/ipxe.pxe bin-i386-pcbios/ipxe.usb bin-i386-pcbios/ipxe.iso bin-i386-pcbios/ipxe.lkrn -- "EXTRA_CFLAGS=-DCONSOLE_SERIAL -DRBD_STACK_MONITOR" > ~/work/bios/out/build-if2.log 2>&1
echo "rc=$? warnings=$(grep -ci warning ~/work/bios/out/build-if2.log)"
for t in rel sm; do
  echo "=== lkrn $t"
  nice -n 19 bash repo/ipxe/tools/build.sh build -o ~/work/bios/tree-$t -j 8 -e ~/work/bios/stub.ipxe bin/ipxe.lkrn bin-i386-pcbios/ipxe.lkrn -- "EXTRA_CFLAGS=$( [ $t = sm ] && echo '-DCONSOLE_SERIAL -DRBD_STACK_MONITOR' || echo -DCONSOLE_SERIAL )" > ~/work/bios/out/build-lkrn-$t.log 2>&1
  echo "rc=$? warnings=$(grep -ci warning ~/work/bios/out/build-lkrn-$t.log)"
done
echo "=== lkrn nt"
nice -n 19 bash repo-nt/ipxe/tools/build.sh build -o ~/work/bios/tree-nt -j 8 -e ~/work/bios/stub.ipxe bin-i386-pcbios/ipxe.lkrn -- "EXTRA_CFLAGS=-DCONSOLE_SERIAL -DRBD_STACK_MONITOR" > ~/work/bios/out/build-lkrn-nt.log 2>&1
echo "rc=$? warnings=$(grep -ci warning ~/work/bios/out/build-lkrn-nt.log)"
S=stage-out2; rm -rf $S; mkdir -p $S
for d in rel:rel:bin rel:rel:bin-i386-pcbios; do :; done
mkdir -p $S/rel $S/sm $S/i386-rel $S/i386-sm $S/dbg $S/fix
cp tree-rel/src/bin/ipxe.lkrn $S/rel/; cp tree-sm/src/bin/ipxe.lkrn $S/sm/
cp tree-rel/src/bin-i386-pcbios/ipxe.lkrn $S/i386-rel/; cp tree-sm/src/bin-i386-pcbios/ipxe.lkrn $S/i386-sm/
cp tree-nt/src/bin-i386-pcbios/ipxe.lkrn $S/dbg/
for n in undionly.kpxe ipxe.pxe ipxe.usb ipxe.iso ipxe.lkrn; do cp tree-if/src/bin-i386-pcbios/$n $S/fix/; done
cp out/build-if2.log out/build-lkrn-*.log $S/
# size of the driver's BIOS object (what rbd_bios.c costs)
{ echo "== object sizes (i386 rel)"; size tree-rel/src/bin-i386-pcbios/rbd_bios.o tree-rel/src/bin-i386-pcbios/rbd_session.o tree-rel/src/bin-i386-pcbios/rbd_stack.o 2>&1; echo "== object sizes (x86_64 rel)"; size tree-rel/src/bin/rbd_bios.o 2>&1; } > $S/objsize.txt
echo GBUILD3-DONE
# ===== gbuild4.sh
set -u
cd ~/work/bios
rm -rf repo-x64 && cp -a repo repo-x64 && rm -rf repo-x64/build repo-x64/ipxe/build
( cd repo-x64 && patch -p1 < harness/lab/p2/results/bios/builds/stack-phys.diff )
echo "=== x64 fix (the stack monitor compares physical addresses; scratch)"
nice -n 19 bash repo-x64/ipxe/tools/build.sh build -o ~/work/bios/tree-x64 -j 8 -e ~/work/bios/stub.ipxe bin/undionly.kpxe bin/ipxe.pxe bin/ipxe.usb bin/ipxe.iso bin/ipxe.lkrn -- "EXTRA_CFLAGS=-DCONSOLE_SERIAL -DRBD_STACK_MONITOR" > ~/work/bios/out/build-x64.log 2>&1
echo "rc=$? warnings=$(grep -ci warning ~/work/bios/out/build-x64.log)"
S=stage-out3; rm -rf $S; mkdir -p $S/x64
for n in undionly.kpxe ipxe.pxe ipxe.usb ipxe.iso ipxe.lkrn; do cp tree-x64/src/bin/$n $S/x64/; done
cp out/build-x64.log $S/
echo GBUILD4-DONE
