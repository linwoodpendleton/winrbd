#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mkloop.sh - the iPXE script of the R10 test (design 16: the driver's memory over many hooks in one session of a long-lived iPXE).
#
#   mkloop.sh IMAGE COUNT GRACE_ROUNDS [OPTIONS]  > loop.ipxe
#
# After the run script's own sanhook, the script hooks IMAGE again COUNT times in a row (sanhook, sanunhook: the session lives on for 120 s after its
# last device, so these are re-opens of a cached session), then GRACE_ROUNDS times waits 125 s with nothing hooked (the session is destroyed: arena, bulk
# and cache are freed) and hooks again (a new session: a new umalloc block). Every hook prints WRLOOP-HOOK n ok; the end prints
# WRLOOP-END n=<hooks> ok=<hooks that worked> fail=<0 or 1>. A failed hook ends the loop. rbd-info is printed at the start and the end.
# OPTIONS are driver options for the URI ("readahead=0"), joined with "&".
set -euo pipefail
image=${1:?IMAGE}
count=${2:?COUNT}
grace=${3:?GRACE_ROUNDS}
shift 3
[[ $image =~ ^wrtest-p2-ms-[a-z0-9-]{1,30}$ ]] || { echo "mkloop.sh: image wrtest-p2-ms-<name>" >&2; exit 2; }
[[ $count =~ ^[0-9]+$ ]] && [[ $grace =~ ^[0-9]+$ ]] || { echo "mkloop.sh: numbers only" >&2; exit 2; }
q=""
[ $# -eq 0 ] || q="?$(IFS='&'; echo "$*")"
uri="rbd://$image@10.77.0.10:3300/winrbd/$image$q"
cat <<EOS
echo WRMS-INFO-BEGIN
rbd-info
echo WRMS-INFO-END
sanunhook --drive 0x80 || goto fail
set n:int32 0
:loop
isset \${n} || goto fail
iseq \${n} $count && goto grace || goto hook
:hook
sanhook --drive 0x80 $uri || goto fail
echo WRLOOP-HOOK \${n} ok
sanunhook --drive 0x80 || goto fail
inc n
goto loop
:grace
set g:int32 0
:graceloop
iseq \${g} $grace && goto end || goto graceround
:graceround
sleep 125
sanhook --drive 0x80 $uri || goto fail
echo WRLOOP-HOOK \${n} ok after-grace
sanunhook --drive 0x80 || goto fail
inc n
inc g
goto graceloop
:end
echo WRLOOP-END n=\${n} ok=\${n} fail=0
goto info
:fail
echo WRLOOP-HOOK \${n} fail 0x\${errno:hexraw}
echo WRLOOP-END n=\${n} ok=\${n} fail=1
:info
echo WRMS-INFO-BEGIN
rbd-info
echo WRMS-INFO-END
echo WRMS-END
EOS
