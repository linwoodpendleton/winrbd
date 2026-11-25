<!-- SPDX-License-Identifier: MIT -->
# Phase 2, the BIOS-specific part (`ipxe-bios`): decisions, measurements, rows

What the module `ipxe-bios` decided from the live measurements of `harness/lab/p2/results/bios` (module `qemu-bios`, same lab, same scripts), what it added to the
driver, and the BIOS rows B0 to B3 (and the WinPE rows W3 and W4) run again with the result. Date of the runs: 2026-11-23/24. SeaBIOS 1.15.0 in QEMU 6.2.0/KVM, guests of
2 vCPU / 2 GiB, the dedicated lab VM of `harness/lab/p2/cluster` (real Ceph v20.2.5: one monitor, three OSDs), throwaway users `wrtest-p2-b0` to `b3` and
`wrtest-p2-winpe-mbr` (legacy `aes` key, deleted at the end). The box was loaded by other projects (load average 25 to 40): **times are indicative, the byte and
counter figures are not.** Every verdict is the output of `results/bios/bin/analyse.py --verdict` on the run's serial log (the scripts of `qemu-bios` ran unchanged).

## 1. Decisions

| Item | Decision | Evidence |
|---|---|---|
| 1. Stack on i386 BIOS (design 5.2) | **The own-stack trampoline stays** (it was already in `rbd_session.c` / `rbd_stack.c`; this module did not touch either). Measured without it, the core on iPXE's own stack takes **4,048 of the 4,096 bytes: 48 left**, under the 300-byte rule. With it: iPXE's stack peaks at **2,784** (1,312 left), the core's own stack at **1,696 of 16,384**. On x86_64 (8,192 bytes, no trampoline): 5,608 used, 2,584 left: none needed. | section 3 |
| 2. `edd_describe` | **Not implemented.** Linux (GRUB + kernel) and the owner's WinPE (boot manager and loader, PXE and USB stick, i386 and x86_64 images) reach their system without it. | section 4 |
| 3. Boot firmware table area | **2,048 bytes is enough, with no byte to spare** for the largest handoff table (1,024) next to the largest iBFT without CHAP (1,024); the stock 768 would not hold even a typical iBFT next to a typical handoff table. The table is inside the 0x80000-0xfffff window every time, at the address the guest's scan reports. A build now fails if `XBFTAB_SIZE` is lowered. | section 5 |
| 4. INT 13h findings of the live rows | F3 (**`sanhook` + `exit` over `undionly.kpxe`**: drive visible, unreadable): cause pinned down in iPXE's sources, a **warning** at exit added (`rbd_bios.c`). Re-run: unchanged behaviour, and the warning is on the console. | section 6 |

## 2. What was built and how it was tested

* **Files**: `ipxe/src/rbd_bios.c` and `rbd_bios.h` (new), `ipxe/patches/0004-winrbd-bios.patch`, `ipxe/tests/rbd_bios_test.c`; one line in `ipxe/patches/0003-winrbd-self-tests.patch` (`REQUIRE_OBJECT ( rbd_bios_test )`, the way
  `build.sh check` wants every test file wired).
* **Builds**, the pinned iPXE (9261ebe38) with patches 0001 to 0004, `ipxe/tools/build.sh build` with iPXE's own `-Werror`, `EXTRA_CFLAGS=-DCONSOLE_SERIAL` (and `-DRBD_STACK_MONITOR` for the `sm` builds), embedded constant stub script:
  * Ubuntu 26.04 guest, **gcc 15.2**: `bin/` (x86_64) and `bin-i386-pcbios/` (32-bit) `undionly.kpxe`, `ipxe.pxe`, `ipxe.usb`, `ipxe.iso`, `ipxe.lkrn`: 0 warning lines in every log, in the `rel`, `sm` and the two measurement variants (`builds/summary.txt`).
  * Build box, **gcc 11.4**: the same targets without the ISO (the box has no `xorriso` / `isolinux.bin`, and the ISO is a packaging step: the compiled objects are the ones of `ipxe.lkrn`, which it holds): 0 warning lines. The self-tests also ran there (below).
  * `build.sh licence` on the real builds of `bin/undionly.kpxe` and `bin-i386-pcbios/undionly.kpxe`: "GPL version 2 (or, at your option, any later version)" (`builds/licence-verify.txt`); `build.sh verify`: the driver is linked into all eight images and no self-test object is.
    (`licence` on `ipxe.pxe` with the full NIC driver set is refused by iPXE for files of its own that carry no `FILE_LICENCE`: the CI job checks `undionly.kpxe` and `snponly.efi`, as this run does.)
  * `build.sh check` and `check -n` (39 seeded mistakes): ok.
* **Self-tests** (`ipxe/tools/build.sh test`): `rbd_bios_test`: **15,459 checks** (the count printed by the run), passing in the 64-bit and the 32-bit program, plain and with UBSan in trap mode, with **gcc 11.4** (build box) and **gcc 15.2** (Ubuntu 26.04 guest); the whole programs: 84,639 tests (64-bit) and 84,714 (32-bit), all pass; `test -n` (the negative control) and `check -n` (39 seeded mistakes) also pass on the guest.
  They cover: the area arithmetic against a literal copy of `int13_install()` (5,000 random sequences), the iBFT size from iPXE's real structures against the steps of `ibft_install()`, the numbers of section 5, the scan against tables built by the core's encoder and rewritten the way
  `int13_install()` does (OEM fields, checksum), every way a candidate can be wrong, a flipped bit anywhere in the handoff table (every bit of a 233-byte table), a model of the BIOS machine, the window test at its edges, the exit warning's decision.
  Mutation check (`bin/mutation.sh`, logs `bin/mut*.log`): **15 deliberate breakages** of `rbd_bios.c` (the rounding, the fit comparison and its position update, the checksum, the length cap, the core's decoder, the alignment step, both edges of the window, the signature compare (the fourth character, the handoff signature), the warning's driver test and its two guards): each makes the self-test
  program fail or the build break. Three were first **not** caught, and tests for them were added: the length cap (only a table with a valid checksum over 4,097 bytes tells), the window's upper edge (only an empty table at 0x100000 tells) and the fourth character of a signature (`sBFX` is not an `sBFT`).
  Two (`warn-null-driver` and the first forms of the two guards) broke the build with `-Werror` (an unused parameter) instead of failing a test; the guards were redone in a form that compiles and are caught by the tests.
* **Rows**: `bin/matrix.sh` order, evidence in `rows/`. Section 7.

## 3. The stack decision (item 1)

The design's rule: *if the watermark leaves under 300 bytes of the 4,096 on i386, the core runs on its own stack*. The watermark (`RBD_STACK_MONITOR`, `rbd_stack.c`) was measured on a real boot (GRUB through INT 13h) in three builds of the same tree:

| Build | What | iPXE stack used (peak) | Left of 4,096 | Core's own stack |
|---|---|---|---|---|
| `nt` (scratch, **no trampoline**, iPXE's i386 stack enlarged to 16 KiB so that the true peak is measured instead of overflowing) | core runs on iPXE's stack | **4,048** (B1 PXE, B2 USB, B3 CD: identical in all three) | **48** | - |
| `i386-sm` (as shipped: trampoline) | core on its own 16 KiB stack | 2,784 (B1), 2,676 (B2, B3), 2,120 (B0) | 1,312 / 1,420 / 1,976 | 1,696 of 16,384 (every boot) |
| `x64` (scratch: the monitor of `rbd_stack.c` with the physical-address fix of `qemu-bios` F2; x86_64 BIOS) | core on iPXE's 8 KiB stack | **5,608** of 8,192 | 2,584 | - |

* The margin without the trampoline is **48 bytes** (the earlier estimate in the sources, 84, was taken in another boot): far under 300, and the three delivery paths agree to the byte, so it is deterministic, not noise. The decision is therefore the design's own: **the trampoline is needed on i386 and stays as written.** The stack monitor of the build
  `nt` repaints after each report (the report's own printing is not counted), as `rbd_stack.c` documents.
* **Interrupts on the switched stack** (design 5.2: "unverified"): a diagnostic build (`fix`, scratch) reads EFLAGS at every call of the core and prints `rbd: DIAG-IF interrupts ENABLED ...` the first time the interrupt flag is set. Result: **no such line in B1 (6,144+ calls) and B3 (12,288+ calls)**, and the running totals
  (`rbd: DIAG-IF core calls N, with interrupts enabled 0`) say 0 every time. Interrupts are disabled while the core runs in the INT 13h path of GRUB and of the rows' kernels, so no handler can fire on the core's stack.
* x86_64: the monitor of the tree as it is (`rel`/`sm` builds, row `B1-sm-1`) still says "the stack is not iPXE's own ... not painted" (finding F2 of `qemu-bios`: `rbd_stack.c` compares a physical frame address with link-time virtual symbols). That file is not this module's and was **not changed**; the figures above come from the scratch build with the fix.
  Rows `B1-x64fix-1`, `B3-x64fix-1`. Both pass.

## 4. `edd_describe` (item 2): skipped

INT 13h AH=48h returns the EDD drive parameters and, if the block interface has `edd_describe`, the device path information (interface type, host bus, ATA/SATA/SCSI device path). Without it iPXE returns the parameters without that part (`len = offsetof ( dpi )`: EDD 2.0). Skipped, because nothing needs it:

* Linux (GRUB, kernel, initramfs; PXE, USB stick, CD; i386 and x86_64 builds): rows B1 to B3, every one reaches `WRBOOT-ROOT-OK` with the root on the mapped image; the kernel lists the drive as `/sys/firmware/edd/int13_dev81` (row B0).
* WinPE (the owner's MBR image: bootmgr, the NT boot sector, `winload`, `boot.wim`): rows `W3-i386-1`, `W4-i386-1`, `W3-x64-1`, `W4-x64-1` below reach the WinPE shell from PXE and from the USB stick, on both word sizes, with the new build (and did so in `qemu-bios` before it).
* What a claimed ATA path would cost: the driver would invent a controller that does not exist; Windows' boot components resolve the disk by the signature in the MBR, not by the EDD path. This stays open for a *full Windows* boot (Phase 3, `GetSystemFirmwareTable`, the boot-start driver), which no row here tested.

## 5. The boot firmware table area (item 3)

All tables of all SAN devices share ONE area of data16 (`int13.c`: `xbftab`, `XBFTAB_SIZE`, entries 16-byte aligned, `-ENOSPC` when one does not fit and `sanhook` fails with it).

| Quantity | Value | Where from |
|---|---|---|
| Stock `XBFTAB_SIZE` / patched | 768 / **2,048** (link map, both word sizes: `xbftab` is `0x800` bytes in `.bss.data16` at `0x1a40`) | `builds/facts.txt` |
| Handoff table of the rows | 233 bytes (names of the rows), 248 (WinPE image names); the design maximum is 1,024 | rows, `RBFT PASS length` |
| iBFT, pinned iPXE, fixed part for one target | 512 bytes (control part 80, initiator 80, two NIC blocks 224, two target blocks 128: iPXE always makes at least two pairs) | `rbd_bios_test.c`, real structure sizes |
| iBFT strings of the reference | 512 (initiator and target IQN of the RFC 3720 maximum, 223 characters each, a 63-character host name, NULs); typical: 110 | |
| Reference iBFT / typical iBFT | 1,024 / 622 | |
| What the driver needs: largest handoff table + reference iBFT | 1,024 + 1,024 = **2,048: exactly the area** (`RBD_BIOS_XBFT_NEED`) | |
| Typical: iBFT (622) next to a typical handoff table (240) | 864 of 2,048; **stock 768 does not hold it** | `fit_test` |
| Does not fit | three tables of the largest size; the largest handoff table next to an iBFT that also has CHAP names and secrets | `fit_test` |

* `rbd_bios.c` (BIOS builds) has a compile-time check that `XBFTAB_SIZE` is at least `RBD_BIOS_XBFT_NEED` and equals the documented 2,048, and that the alignment is 16. Patch 0004 moves the two constants from `int13.c` to `int13.h`, values unchanged, so that the check can see them. Dropping or weakening patch 0002 is now a build error (checked: with `XBFTAB_SIZE` set to 1,024 in a prepared tree, `rbd_bios.c` fails to compile with `size of array 'rbd_bios_area_fits' is negative`, and with 2,048 it compiles).
* **Where a scan finds it.** The `rbd-xbft` command (new, BIOS builds) scans 0x80000-0xfffff in 16-byte steps like a guest does and prints what it finds, run after `sanhook` in the B0 rows:

  | Row | Binary | `rbd-xbft` (firmware's view) | The guest's scan (`RBFT INFO source`) |
  |---|---|---|---|
  | `B0-i386-rel-1` | `undionly.kpxe` i386 | `rBFT at 0x9a880, 233 bytes, inside the 0x80000-0xfffff window`; `1 table(s) use 240 of the 2048 bytes of the area (0 refused)` | `found at physical address 0x9a880`, 233 bytes, all 40 fields |
  | `B0-rel-1` | `undionly.kpxe` x86_64 | `rBFT at 0x9a840`, 233 bytes, inside | `0x9a840` |
  | `B0N-i386-rel-1` | `ipxe.pxe` i386 (native drivers) | `rBFT at 0x9e120`, 233 bytes, inside | `0x9e120` |

  Both views agree to the byte. The area is in data16 at the top of base memory (the two binaries put it at different places, 0x9a880 and 0x9e120): the table is inside the window an operating system scans as long as iPXE's resident BIOS part (text16 and data16: `_edata16` is 0x35c0 bytes in `undionly.kpxe`, about 14 KiB) stays below 128 KiB.
  The WinPE rows show the table at the same places early (8 s after the SAN opened) and at the shell.
* `rbd-xbft` adds nothing to the key's exposure: it prints signature, address, length, and never any table content (the handoff table can hold the key).

## 6. INT 13h findings of the live rows (item 4)

* **F3 (`sanhook` + `exit` over `undionly.kpxe`: the hooked drive is visible and unreadable, 130 s boot instead of 20 s).** Source reading, pinned iPXE: `int13_hook()` calls `devices_get()`, so iPXE does **not** remove its network devices when it exits; but with `undionly.kpxe` the NIC is
  driven through the PXE ROM's UNDI stack (`undinet.c`; `undionly_shutdown()` leaves `UNDI_FL_KEEP_ALL` set unless an OS is being booted), and the ROM stops that stack when iPXE returns to it. The same flow with native drivers (`ipxe.pxe`) leaves the NIC to iPXE: the drive is readable. That is an inference from the
  sources and the two rows (`B0-i386-rel-1` against `B0N-i386-rel-1`: 6 stall lines and `mbr_signature=-` against none and `0x7d1f0002`); iPXE itself was not changed and the cause was not observed inside the ROM.
  What the driver does about it: **one console line at exit** (`rbd_bios.c`, a shutdown hook, BIOS builds only): `rbd: net0: an RBD drive is hooked and iPXE is exiting over a UNDI network device: the PXE ROM stops its network stack when iPXE returns, and reads of the drive will then stall (boot with sanboot, or use ipxe.pxe with a native driver)`.
  Seen in `B0-i386-rel-1`, `B0-i386-sm-1` and `B0-rel-1` (undionly), **not** in `B0N-i386-rel-1` (native drivers) and not in `sanboot` rows. The behaviour of the drive is unchanged (the 6 stalls are still there): a driver cannot keep a NIC alive that the ROM stops.
* Nothing else INT 13h specific came out of the rows: the reads are those of `qemu-bios` section 4.1 (at most 64 sectors from GRUB, a few of 127), the stall/recovery behaviour is unchanged. The one recovery that did not complete in `qemu-bios` (F11, `W3-x64-1` there, under box load) was not seen again in the WinPE rows here (section 7).

## 7. Rows

All rows of this run, produced by `bin/summarize.py` over `rows/` (`B0-*`: sanhook and `exit`; `B1`: PXE `sanboot`; `B2`: USB stick; `B3`: CD; `NEG`: wrong key; `*-nt-*`: scratch build without the trampoline; `*-if-*`: scratch build with the interrupt-flag diagnostic; `*-x64fix-*`: scratch x86_64 build with the monitor's address fix; `dbg` and `fix` are
only the directory names that the run scripts accept for local diagnostic builds). **All verdicts are PASS** (B0: "drive unreadable" with `undionly.kpxe`, as in `qemu-bios`); the WinPE rows have no automatic verdict, the probe recognised the shell on the screen.

| label | build | verdict | net s | SAN s | GRUB s | read s | initramfs s | root OK s | table B | pass/fail/skip | stack used/total | core stack | arena B | bulk B | reads | sectors | of 127 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| B0-i386-rel-1 | i386-rel | PASS (drive unreadable) | 11.9 | 11.9 | 16.8 | - | - | 132.8 | 233 | 40/0/0 | - | 1696/16384 | 260128 | 2627584 | - | - | - |
| B0-i386-sm-1 | i386-sm | PASS (drive unreadable) | 11.3 | 11.3 | 16.3 | - | - | 131.2 | 233 | 40/0/0 | 2120/4096 | 1696/16384 | 260128 | 2627584 | - | - | - |
| B0-rel-1 | rel | PASS (drive unreadable) | 11.4 | 11.4 | 16.0 | - | - | 130.8 | 233 | 40/0/0 | - | - | 263392 | 2627584 | - | - | - |
| B0N-i386-rel-1 | i386-rel | PASS | 11.6 | 11.6 | 13.1 | - | - | 21.3 | 233 | 40/0/0 | - | 1696/16384 | 260128 | 2627584 | - | - | - |
| B1-i386-rel-1 | i386-rel | PASS | 11.1 | 11.1 | 13.5 | 8.3 | 24.1 | 58.8 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-i386-rel-2 | i386-rel | PASS | 11.5 | 11.5 | 14.5 | 8.4 | 25.1 | 62.4 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-i386-sm-1 | i386-sm | PASS | 11.1 | 11.2 | 14.2 | 9.7 | 26.2 | 61.2 | 234 | 40/0/0 | 2784/4096 | 1696/16384 | - | - | - | - | - |
| B1-if-1 | fix | PASS | 11.2 | 11.2 | 14.5 | 8.8 | 25.6 | 73.5 | 234 | 40/0/0 | 2784/4096 | 1696/16384 | - | - | - | - | - |
| B1-nt-1 | dbg | PASS | 11.5 | 11.5 | 14.4 | 68.2 | 84.8 | 120.2 | 234 | 40/0/0 | 4048/16384 | - | - | - | - | - | - |
| B1-rel-1 | rel | PASS | 11.9 | 11.9 | 16.6 | 30.5 | 49.5 | 98.9 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-sm-1 | sm | PASS | 11.2 | 11.3 | 14.4 | 10.3 | 27.0 | 62.4 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-x64fix-1 | dbg | PASS | 11.1 | 11.1 | 14.1 | 11.3 | 27.7 | 72.8 | 234 | 40/0/0 | 5608/8192 | - | - | - | - | - | - |
| B2-i386-rel-1 | i386-rel | PASS | 4.1 | 4.1 | 6.8 | 9.4 | 18.5 | 54.4 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B2-i386-sm-1 | i386-sm | PASS | 3.9 | 3.9 | 5.5 | 9.2 | 17.0 | 52.7 | 234 | 40/0/0 | 2676/4096 | 1696/16384 | - | - | - | - | - |
| B2-nt-1 | dbg | PASS | 3.9 | 3.9 | 5.4 | 8.9 | 16.5 | 52.0 | 234 | 40/0/0 | 4048/16384 | - | - | - | - | - | - |
| B2-rel-1 | rel | PASS | 4.1 | 4.1 | 5.8 | 10.0 | 18.2 | 58.0 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-i386-rel-1 | i386-rel | PASS | 3.4 | 3.4 | 5.3 | 4.5 | 12.1 | 47.4 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-i386-rel-2 | i386-rel | PASS | 3.5 | 3.5 | 5.2 | 6.1 | 13.6 | 50.1 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-i386-sm-1 | i386-sm | PASS | 3.4 | 3.4 | 5.1 | 4.8 | 12.2 | 48.4 | 234 | 40/0/0 | 2676/4096 | 1696/16384 | - | - | - | - | - |
| B3-if-1 | fix | PASS | 3.7 | 3.7 | 7.1 | 6.7 | 16.1 | 53.8 | 234 | 40/0/0 | 2676/4096 | 1696/16384 | - | - | - | - | - |
| B3-nt-1 | dbg | PASS | 3.4 | 3.4 | 5.8 | 4.3 | 12.3 | 52.6 | 234 | 40/0/0 | 4048/16384 | - | - | - | - | - | - |
| B3-rel-1 | rel | PASS | 3.4 | 3.4 | 5.8 | 6.0 | 14.2 | 51.9 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-x64fix-1 | dbg | PASS | 3.5 | 3.5 | 7.0 | 6.3 | 15.7 | 52.0 | 234 | 40/0/0 | 5608/8192 | - | - | - | - | - | - |
| NEG-i386-rel-1 | i386-rel | PASS | 11.3 | 11.3 | - | - | - | - | - | - | - | - | - | - | - | - | - |
| W3-i386-1 | i386-rel | WinPE shell | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| W3-x64-1 | rel | WinPE shell | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| W4-i386-1 | i386-rel | WinPE shell | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| W4-x64-1 | rel | WinPE shell | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |

WinPE rows (the owner's MBR image `winpe-mbr.vhd`, layout check PASS before the import, imported with the `layering` feature only and rolled back to its snapshot `pristine` before each row; only logs and the final screenshot are kept, never the image):

| Row | Delivery | Binary | Result | Table in guest memory (found by the evidence script) |
|---|---|---|---|---|
| `W3-i386-1` | PXE, one lab NIC (`undionly.kpxe`, 32-bit) | `i386-rel` | WinPE shell recognised, `X:\Windows\System32>` | rBFT at `0x9a880`, 248 bytes, key present (16 bytes), early (8 s after the SAN opened) and at the shell |
| `W4-i386-1` | USB stick (`ipxe.usb`, 32-bit) | `i386-rel` | WinPE shell recognised | `0x9e140`, 248 bytes |
| `W3-x64-1` | PXE (`undionly.kpxe`, x86_64) | `rel` | WinPE shell recognised | `0x9a840`, 248 bytes |
| `W4-x64-1` | USB stick (`ipxe.usb`, x86_64) | `rel` | WinPE shell recognised | `0x9e120`, 248 bytes |

None of the four logged a driver stall line (`closing the path`). The final screenshot of each row is `rows/<label>/shots/final.png`. WinPE's own marker on the serial port does not work in QEMU with these images (their `startnet.cmd` writes to a `COM1` that WinPE does not create, `qemu-bios` finding), so the shell is recognised by its screen.

## 8. Deviations, shared files, open issues

* **Shared file changes**: `ipxe/patches/0003-winrbd-self-tests.patch` (one `REQUIRE_OBJECT ( rbd_bios_test );` line and the hunk's new-line count, 12 to 13). Nothing else outside this module's files: not `rbd_session.c` (the trampoline was there and the measurement confirms it), not `rbd_stack.c`, no document of the design.
* **New file beyond the three named**: `ipxe/src/rbd_bios.h` (the declarations the test and the object share), and this directory.
* The measurement builds `nt`, `if` and `x64` are scratch copies of the tree with a sed or `patch` (`builds/measurement-builds.sh`): none of that is in the repository. Their runs use the variant names `dbg` (`nt`, later the `x64` build) and `fix` (`if`) because that is what `runrow.sh` accepts; the hash of the binary of each run is in its `hashes.txt`.
* Open: (a) `rbd_stack.c` x86_64 monitor (F2), not this module's file; (b) the CI job builds `bin/` (x86_64) only: the i386 images, where the trampoline and the 4 KiB stack are, are not built there (F1); (c) the design text still says the trampoline is "not written until the measurement asks for it" and that XBFTAB is a patch of 0002 only: section 5.2, 7 and 9.5 of
  `docs/design/ipxe-driver.md` need the numbers of this file; (d) a handoff table at the 1,024-byte maximum next to an iBFT with CHAP secrets does not fit and fails the SAN description with `-ENOSPC` (DBG line only); (e) `edd_describe` and Windows' use of the table (`GetSystemFirmwareTable`) are Phase 3 questions; (f) the cause of F3 is an inference.

## 9. Files

| Path | What |
|---|---|
| `rows/<label>/` | one run: `cmdline.txt`, `serial.txt`, `console.ts`, `result.txt`, `hashes.txt`, `metrics.json`, `params.txt`; WinPE rows: `evidence.txt`, `shots/final.png` |
| `builds/` | `SHA256SUMS` of every binary that ran, `facts.txt` (link-map facts, sizes), `summary.txt` (warnings per build log), `licence-verify.txt`, `objsize.txt`, `measurement-builds.sh` |
| `bin/` | `matrix.sh` (the rows in order), `mutation.sh` (the mutation check of `rbd_bios.c`) |

## 10. Reproduce

```
# builds (guest): ipxe/tools/build.sh build -o OUT -e stub.ipxe bin/undionly.kpxe bin/ipxe.pxe bin/ipxe.usb bin/ipxe.iso bin-i386-pcbios/... -- EXTRA_CFLAGS='-DCONSOLE_SERIAL [-DRBD_STACK_MONITOR]'
# self-tests:     ipxe/tools/build.sh test [-u] [bin-i386-linux/tests.linux]
# rows:           as results/bios/README.md section 8 (P2B_WORK, LAB_DIR, runrow.sh LABEL ROW VARIANT [--append FILE]); the B0 append file is: rbd-xbft, rbd-info
```
