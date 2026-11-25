#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Mutation check of ipxe/src/rbd_bios.c: each sed breaks one line, the self-test program must then fail (or the build must break). mut.sh ran first; mut2.sh repeated the three that were not caught and added more.
# This file is a record: the scripts below were run one after the other (the paths are those of the build box and the builder guest), it is not meant to be run as one script.
# mutation check of rbd_bios.c: each mutation must make rbd_bios_test fail
B=$BOX_BIOS2
export IPXE_NICE="nice -n 19 choom -n 600 --"
run() { # name sed-expr
  rm -rf $B/mut && mkdir -p $B/mut && rsync -a --exclude build --exclude third_party $B/repo/ $B/mut/ && mkdir -p $B/mut/third_party && ln -s $B/repo/third_party/ipxe $B/mut/third_party/ipxe
  sed -i "$2" $B/mut/ipxe/src/rbd_bios.c
  if cmp -s $B/mut/ipxe/src/rbd_bios.c $B/repo/ipxe/src/rbd_bios.c; then echo "MUT $1: SED DID NOT CHANGE"; return; fi
  out=$(cd $B/mut && bash ipxe/tools/build.sh test -j 4 2>&1)
  if echo "$out" | grep -q 'FAILURE'; then echo "MUT $1: caught ($(echo "$out" | grep -c FAILURE) failure lines)"; else echo "MUT $1: NOT CAUGHT"; fi
}
run entry-align 's/return ( ( len + RBD_BIOS_XBFT_ALIGN - 1 ) \&/return ( ( len + RBD_BIOS_XBFT_ALIGN ) \&/'
run fit-gt 's/if ( lens\[i\] > ( area - pos ) )/if ( lens[i] >= ( area - pos ) )/'
run scan-nosum 's/if ( sum != 0 ) {/if ( 0 ) {/'
run scan-nocap 's/( tlen > RBD_BIOS_SCAN_TABLE_MAX ) ||/( 0 ) ||/'
run scan-nodecode 's/( wr_handoff_decode_table ( bytes + off, tlen,/( 0 \&\& wr_handoff_decode_table ( bytes + off, tlen,/'
run window-edge 's/phys >= RBD_BIOS_WINDOW_HI/phys > RBD_BIOS_WINDOW_HI/'
run warn-prefix 's/strcmp ( driver, "undionly" ) != 0/strncmp ( driver, "undi", 4 ) != 0/'
run warn-booting 's/if ( booting || ! drives || ! driver )/if ( ! drives || ! driver )/'
run scan-align 's/off += RBD_BIOS_XBFT_ALIGN )/off += 1 )/'
echo MUT-DONE
B=$BOX_BIOS2
export IPXE_NICE="nice -n 19 choom -n 600 --"
run() { # name sed-expr
  rm -rf $B/mut && mkdir -p $B/mut && rsync -a --exclude build --exclude third_party $B/repo/ $B/mut/ && mkdir -p $B/mut/third_party && ln -s $B/repo/third_party/ipxe $B/mut/third_party/ipxe
  sed -i "$2" $B/mut/ipxe/src/rbd_bios.c
  if cmp -s $B/mut/ipxe/src/rbd_bios.c $B/repo/ipxe/src/rbd_bios.c; then echo "MUT $1: SED DID NOT CHANGE"; return; fi
  out=$(cd $B/mut && bash ipxe/tools/build.sh test -j 4 2>&1)
  if echo "$out" | grep -q 'FAILURE'; then echo "MUT $1: caught by the tests ($(echo "$out" | grep -c FAILURE) failure lines)"; elif echo "$out" | grep -q 'rbd_bios_test" [0-9]* tests passed'; then echo "MUT $1: NOT CAUGHT (tests passed)"; else echo "MUT $1: build broke: $(echo "$out" | grep -m1 -i 'error')"; fi
}
run scan-nocap 's/( tlen > RBD_BIOS_SCAN_TABLE_MAX ) ||/( 0 ) ||/'
run window-edge 's/phys >= RBD_BIOS_WINDOW_HI/phys > RBD_BIOS_WINDOW_HI/'
run warn-booting 's/if ( booting || ! drives || ! driver )/if ( ! drives || ! driver )/'
run warn-drives 's/if ( booting || ! drives || ! driver )/if ( booting || ! driver )/'
run window-lo 's/phys < RBD_BIOS_WINDOW_LO/phys < ( RBD_BIOS_WINDOW_LO - 16 )/'
run fit-pos 's/pos = rbd_bios_xbft_entry ( pos + lens\[i\] );/pos = ( pos + lens[i] );/'
run scan-kind 's/if ( memcmp ( sig, "sBFT", 4 ) == 0 )/if ( memcmp ( sig, "sBFT", 3 ) == 0 )/'
echo MUT2-DONE

# ===== mut3.sh (the compile-safe forms of the two warning mutations, and the signature mutations that the first two rounds missed)
B=$BOX_BIOS2
export IPXE_NICE="nice -n 19 choom -n 600 --"
run() {
  rm -rf $B/mut && mkdir -p $B/mut && rsync -a --exclude build --exclude third_party $B/repo/ $B/mut/ && mkdir -p $B/mut/third_party && ln -s $B/repo/third_party/ipxe $B/mut/third_party/ipxe
  sed -i "$2" $B/mut/ipxe/src/rbd_bios.c
  if cmp -s $B/mut/ipxe/src/rbd_bios.c $B/repo/ipxe/src/rbd_bios.c; then echo "MUT $1: SED DID NOT CHANGE"; return; fi
  out=$(cd $B/mut && bash ipxe/tools/build.sh test -j 4 2>&1)
  if echo "$out" | grep -q 'FAILURE'; then echo "MUT $1: caught by the tests ($(echo "$out" | grep -c FAILURE) failure lines)"; elif echo "$out" | grep -q 'rbd_bios_test" [0-9]* tests passed'; then echo "MUT $1: NOT CAUGHT (tests passed)"; else echo "MUT $1: build broke: $(echo "$out" | grep -m1 -i 'error')"; fi
}
run warn-booting-compiles 's/if ( booting || ! drives || ! driver )/if ( ( booting \&\& 0 ) || ! drives || ! driver )/'
run warn-drives-compiles 's/if ( booting || ! drives || ! driver )/if ( booting || ( ! drives \&\& 0 ) || ! driver )/'
run warn-null-driver 's/if ( booting || ! drives || ! driver )/if ( booting || ! drives )/'
run scan-kind3 's/if ( memcmp ( sig, "sBFT", 4 ) == 0 )/if ( memcmp ( sig, "sBFT", 3 ) == 0 )/'
run scan-kind-r 's/memcmp ( sig, WR_HANDOFF_SIGNATURE, 4 )/memcmp ( sig, WR_HANDOFF_SIGNATURE, 3 )/'
echo MUT3-DONE
