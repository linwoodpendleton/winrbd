<!-- SPDX-License-Identifier: MIT -->
# Phase 2, the BIOS rows of the live matrix: what was run, what was seen

Rows B0 to B3 of `docs/design/ipxe-driver.md` section 14.3, the BIOS rows W3 and W4 (WinPE), the INT 13h measurements of section 14.4, and the findings. SeaBIOS in QEMU/KVM,
the iPXE `rbd://` driver of this tree against a real Ceph v20.2.5 cluster (the dedicated lab VM of `harness/lab/p2/cluster`), a Linux guest that keeps its root on the image after the
firmware is gone. **Every number below is computed from the evidence directories in `rows/` by `bin/report.py` and `bin/summarize.py`; every verdict is the output of
`bin/analyse.py --verdict` on the serial log of that run.**

* Date of the runs: 2026-11-23. Tree: `ipxe/` and `core/` digest and iPXE revision in `builds/*/BUILD-INFO.txt`. Builder: Ubuntu 26.04, gcc 15.2, iPXE's own `-Werror`: **zero warning lines in every build log** (`builds/map-facts.txt` ends with the line, warning and error counts of each log).
* Host: the shared KVM box (QEMU 6.2.0, SeaBIOS 1.15.0, KVM), guests of 2 vCPU / 2 GiB, `nice -n 19 choom -n 600`; the box was loaded by other projects during the runs (load average 25 to 67), so
  **times are indicative only**; ratios between runs taken minutes apart are what is meaningful (see "Readahead").

## 1. Result

`PASS` = every criterion of `analyse.py --verdict` held: the run reached its stage, the table was found by the low-memory scan and **all 40 fields of the rBFT table matched the expected values of the configuration**
(`RBFT-RESULT PASS pass=40 fail=0 skip=0`), the booted system printed `WRBOOT-ROOT-OK` with `root=/dev/rbd0p1 ... table=PASS src=scan` (so the firmware read grub, the kernel and the initramfs through our SAN device, and
the kernel client took over the same image afterwards).

**Important: there are two kinds of BIOS binaries, and the documented target names build the 64-bit one** (finding F1). `make bin/undionly.kpxe` of the pinned iPXE is an **x86_64** BIOS image (ELF64, 8 KiB stack,
no core-stack trampoline); the 32-bit images the design calls "i386 BIOS" (4 KiB stack, the core on its own 16 KiB stack) are `bin-i386-pcbios/...`. Both were built and run.

| Row | Firmware / delivery | iPXE binary | x86_64 (`bin/`) | i386 (`bin-i386-pcbios/`) |
|---|---|---|---|---|
| B0 | SeaBIOS, PXE, `sanhook --drive 0x81`, boot a small local disk | `undionly.kpxe` | PASS (`B0-rel-1`) with the finding F3 | PASS (`B0-i386-rel-1`) with the finding F3 |
| B0 (control) | the same with native NIC drivers | `ipxe.pxe` | PASS (`B0N-rel-1`): the hooked drive is readable | PASS (`B0N-i386-rel-1`) |
| B1 | SeaBIOS, PXE, `sanboot`, Linux MBR image, root on the image | `undionly.kpxe` | PASS (`B1-rel-1`) | PASS (`B1-i386-rel-1`, `B1-i386-rel-2`) |
| B1 (control) | the same with native NIC drivers | `ipxe.pxe` | - | PASS (`B1N-i386-rel-1`, `-2`) |
| B2 | SeaBIOS, USB stick | the real `bin/ipxe.usb` | PASS (`B2-rel-1`) | PASS (`B2-i386-rel-1`) |
| B3 | SeaBIOS, CD-ROM | the real `bin/ipxe.iso` | PASS (`B3-rel-1`) | PASS (`B3-i386-rel-1`) |
| negative control | B1 with a wrong key | `undionly.kpxe` | PASS (`NEG-rel-1`) | PASS (`NEG-i386-rel-1`) |
| W3 | SeaBIOS, PXE, **WinPE** (owner's MBR image) | `undionly.kpxe` | **reached the WinPE shell in 2 of 3 runs** (`W3-x64-2`, `W3-x64-3`); `W3-x64-1` did not (F11) | **reached the WinPE shell** (`W3-i386-1`) |
| W4 | SeaBIOS, USB stick, **WinPE** | the real `ipxe.usb` | **reached the WinPE shell** (`W4-x64-1`) | **reached the WinPE shell** (`W4-i386-1`) |

The release builds (`rel`) carry the constant stub script and no key; the key is read by the run script from a mode-600 file and reaches the guest through TFTP (`autoexec.ipxe`), is never in an argument, a log or a binary
(the run scripts scan every log for it: exit status 4 and the logs are discarded if it is found; none was).

What each row proves, from its log (`rows/<run>/serial.txt`, `console.ts`, `result.txt`):

* **B0**: the hooked RBD drive is a BIOS drive (`WRBOOT-EDD int13_dev81` in the guest, the kernel's `/sys/firmware/edd`), the rBFT table is found by the low-memory scan (address in `RBFT INFO source:`), all 40 fields match. `rbd-info` after
  the `sanhook` prints the session (below).
  The B0 criteria are "visible to the BIOS + the table + the local disk boots" and nothing about the drive being **readable**; the readability is a `NOTE` line of the verdict (the guest's EDD probe got an MBR signature or not), and the table of section 5
  says `PASS (drive unreadable)` for the `undionly.kpxe` rows, where it was not (F3).
* **B1, B2, B3**: as above, plus the root on `/dev/rbd0p1`, from the three delivery paths (PXE, USB, CD).
* **Negative control**: the same boot as B1 with a syntactically valid key that is not the user's. It fails with **one** driver console line and iPXE's own line, nothing boots, the SAN layer is never offered a device:
  `rbd: open failed: server refused the offered authentication method or mode (WR_E_M2_BAD_METHOD)` / `Could not open SAN device: Error 0x43766001` / `WRRUN-SAN-FAILED 0x43766001`, after the 20 s open timeout (finding F4).
* **W3, W4** (`rows/W3-i386-1`, `rows/W4-i386-1`, and the x86_64 runs `rows/W3-x64-*`, `rows/W4-x64-1`): the owner's BIOS WinPE image (`winpe-mbr.vhd`, layout check PASS before the import, imported with the `layering` feature only, rolled back to its snapshot `pristine` before each row)
  boots from the RBD image through `rbd://` to the WinPE shell (`X:\Windows\System32>` in a `cmd.exe` window; `evidence.sh probe`: "WinPE shell recognised"; `shots/final.png`), in both the PXE and the USB-stick delivery.
  The rBFT table is in guest memory **early** (8 s after the SAN opened) **and at the shell**: `rBFT at 0x9a880 length=248 flags=0x6 mode=1 mons=1 key=present (16 bytes) user=wrtest-p2-winpe-mbr image=winrbd/wrtest-p2-winpe-mbr`
  (i386, PXE) and at `0x9e140` (i386, USB; the x86_64 images: `0x9a840` and `0x9e120`), found by `harness/lab/p2/winpe/run-rows.md`'s scanner on a dump of the guest's memory. **Not tested**: that Windows can read that table (`GetSystemFirmwareTable`), and anything about a Windows
  that boots from the disk after WinPE (Phase 3). The serial marker of those images does not work in QEMU (their `startnet.cmd` writes to a `COM1` that WinPE does not create, see `winpe/run-rows.md`), so the shell is recognised by its screen.

## 2. How the runs were made, and why

* **Cluster.** The dedicated lab VM on the same box (design D11, option C): real mon and 3 OSDs, the guests on its private multicast layer 2 (`10.77.0.0/24`), no relay, no change to the box's network. **The main lab, its `~/w/lt2` and the
  Phase 1 exit run were not touched.** One throwaway cephx user (legacy `aes`) and one 2 GiB image per row (`wrtest-p2-b0` to `b3`, and `wrtest-p2-winpe-mbr`), all deleted at the end (section 6).
* **Guest images.** `build-bios.sh` and `build-bios.sh --tiny` of `harness/lab/p2/images` in the builder guest (`b0-tiny.raw` for B0, `linux-bios.raw` for the rest), imported with `import.sh` and verified against their manifests
  (`CHECK-RESULT PASS`: sha256 of `rbd export`, `e2fsck`, the files).
* **`undionly.kpxe` needs the lab NIC to be the PXE NIC** (it drives only the NIC the PXE ROM booted from). The stock `run-bios-pxe.sh` PXE-boots from a user-mode NIC and keeps the lab NIC second, where UNDI cannot see it
  (`WRRUN-NO-LAB-NIC`). `bin/run-undi.sh` therefore gives the guest **one** NIC, on the lab layer 2, which the PXE ROM boots from, and starts a `dnsmasq` in the lab VM for the length of the run: DHCP for this guest's MAC only
  (no router option, so the NIC has no gateway as in the other rows), TFTP of `undionly.kpxe` and `autoexec.ipxe`. It sources the stock library `harness/lab/p2/qemu/common.sh` **unchanged** and replaces three of its functions.
  `bin/run-media.sh` does the same for the real `bin/ipxe.usb` / `bin/ipxe.iso`: they carry the constant stub (no key inside), and the run script reaches them over QEMU's own TFTP server on the user-mode NIC.
* **Builds.** `ipxe/tools/build.sh` on the pinned submodule revision with the patch series, in the 26.04 guest: `rel` (`-DCONSOLE_SERIAL`, which the run scripts need to see anything), `sm` (`+ -DRBD_STACK_MONITOR`), `trace`
  (`sm` + `DEBUG=rbd_block:2,rbd_session` + `-DCONSOLE_DEBUGCON=0xf`; the directories `trace2` and `i386-trace2` of `builds/`), each as `bin/` (x86_64) and `bin-i386-pcbios/` (i386). Hashes of every binary that ran are in each run's `hashes.txt`, and in `builds/SHA256SUMS`.
* **Licence check.** `ipxe/tools/build.sh licence` (iPXE's `make bin/<target>.licence` on a real build) on `bin/undionly.kpxe` and `bin-i386-pcbios/undionly.kpxe` of the same tree: exit 0, overall licence "GPL version 2 (or, at your option, any later version)"
  (`builds/licence.txt`). The builds, the licence check and the Secure Boot refusal are CI's (`ipxe-ci`); this module only needed the binaries.
* **Expected values.** `bin/mkparams.sh` writes the expected table of the row (`expected-table.sh fwcfg`: monitor, entity, pool, image, **image id read from the cluster**, `crc` mode, MAC, address, static flag, key type and length), which
  the guest's checker compares field by field (`rbft.require=1`: a mismatch ends the run).
* **Time stamps.** `bin/tailts.py` stamps every serial line (and, for the trace builds, every line of QEMU's debug console) within 20 ms while the guest runs; the stages and times in the tables come from those.

## 3. Findings

Ordered by what a reader should act on first. "Evidence" names the run directories under `rows/`.

**F1. The documented BIOS targets are x86_64 images, not i386 (design premise, CI).** `Makefile.housekeeping` of the pinned iPXE has `DEFAULT_ARCH := x86_64`: `make bin/undionly.kpxe` (and `bin/ipxe.pxe`, `ipxe.usb`, `ipxe.iso`)
produce **64-bit** BIOS images (`file`: ELF 64-bit x86-64; the link map has `.stack` of 0x2000 bytes and 64-bit addresses), whose `RBD_CORE_STACK_BYTES` is 0 (the trampoline of design 5.2 is compiled out) and whose stack is 8 KiB.
The i386 images with the 4 KiB stack and the core's own 16 KiB stack are `bin-i386-pcbios/*`. `docs/design/ipxe-driver.md` (D6, 5.2, R2, 14.2), `ipxe/README.md` and the CI job `ipxe` say "i386" and build `bin/`:
**the i386-only path (the stack switch) is not built by CI and was never executed by a `bin/` build.** Both kinds pass every row here (the i386 trampoline is exercised: core stack mark 1,696 of 16,384 bytes in every i386 boot).
Evidence: `builds/map-facts.txt` (`file`, the `.stack` section, `xbftab` of both architectures), `hashes.txt` of any `*-i386-*` run against any other. Suggested: build and test both (`bin-i386-pcbios/` is what most BIOS machines need), say so in the design and the CI.

**F2. The stack monitor measures nothing on x86_64 BIOS (`ipxe/src/rbd_stack.c`).** `rbd_stack_paint()` compares the running frame (a physical address on x86_64) with the linker symbols `_stack` and `_estack`
(link-time virtual addresses `0xffffffffeb46...`): "the stack is not iPXE's own ... not painted", at every open. A diagnostic build (`rows/DIAG-x64-1`, `builds/diag-stack.txt`) prints `phys(frame) 7fe8edd8`
between `phys(_stack) 7fe8d660` and `phys(_estack) 7fe8f660`: the frame **is** on iPXE's stack. Comparing `virt_to_phys()` of all three fixes it (`builds/stack-phys.diff`, **not applied to the tree**: the file is not this module's);
with it the x86_64 boot reports 5,608 of 8,192 bytes used (`rows/B1-fix-1`, `B3-fix-1`). On i386 the monitor works as written.

**F3. `undionly.kpxe` + `sanhook` + `exit` (row B0): the hooked drive is visible but not usable.** After iPXE exits back to the PXE ROM the UNDI NIC stops working for the driver. The drive stays hooked
(`WRBOOT-EDD int13_dev81` is there, the table is there, all 40 fields match: **the roadmap's milestone 8 criteria hold**), but every INT 13h command on it waits for the driver's 30 s stall deadline and fails
(`rbd: the cluster has not answered for 30 seconds, closing the path: network connection could not be established (WR_E_NET_CONNECT)` x6), the kernel's EDD probe gets no MBR signature (`mbr_signature=-`), and the local disk's boot takes **130 s instead of 20 s**.
With native drivers (`ipxe.pxe`, same NIC, same flow) the drive works: `mbr_signature=0x7d1f0002`, 20 s. Evidence: `B0-rel-1`, `B0-i386-rel-1` (6 stall lines in each) against `B0N-rel-1`, `B0N-i386-rel-1`. It is a property of iPXE's UNDI shutdown rather than of the
driver (not investigated in iPXE's code), but a script that hooks a drive and leaves must not use UNDI, and a boot that probes the hooked drive pays 30 s per probe. `sanboot` (rows B1, W3) is not affected: iPXE does not exit.

**F4. A wrong key is reported as "server refused the offered authentication method or mode" (`WR_E_M2_BAD_METHOD`).** One line, correct errno class, but a user will read it as a mode/method problem; a key problem and an unknown user give the same text
(`rows/NEG-rel-1`, `NEG-i386-rel-1`; an unknown user gave the same text during bring-up, not kept). It also takes the 20 s open timeout to appear. Low.

**F5. Observability after a BIOS boot is the stack mark only.** During an INT 13h boot the driver prints nothing but the stack note (`rbd_stack_note`, only on stack growth of 128 bytes or more). `rbd-info` can run only before the hand-over, so the readahead
counters (hits, waits, misses), the arena and bulk high-water marks and the OSD counters **after** a real boot are not observable with this code (the figures below are at open, from `rbd-info` in row B0, and from the trace builds). Suggested: let the note print one summary line
(readahead hit rate, arena high-water) when it prints, or on a DEBUG level.

**F6. iPXE's DBG output reaches neither the serial console nor QEMU's debug console unless the console's usage mask says so.** `-DCONSOLE_SERIAL` (as the run scripts say) is the value `1` = standard output only: `DEBUG=` builds print on the VGA console only (and the VGA
text console makes a boot take 5 to 6 times longer). The trace builds therefore also use `-DCONSOLE_DEBUGCON=0xf` and QEMU's `-debugcon file:`. Timing taken from a `trace` run is not a measurement (the stack mark in them is 100 to 150 bytes higher for the same reason). Documentation point.

**F7. GRUB never issues the 127-sector reads the design expects.** The design (10, 14) assumes "bootloaders ask for 127 sectors (63.5 KiB)". GRUB 2.14 here reads in pieces of at most 64 sectors (32 KiB, its disk cache unit): 1,617 reads for 25.4 MiB, the sizes spread over 1 to 64
with only 4 reads of 127 sectors in the whole boot (section 4.1). 98 % of the reads continue the previous one exactly (sequential), which is what the readahead window needs. Windows' boot manager was **not** traced (a DEBUG boot of 340 MB would take hours on the VGA console), so the 127 for it stays an assumption.

**F8. The session asks for about 4.8 MiB, and the core's arena is almost exactly full at open.** `RBD ... needs 262144 + 2629632 + 2101248 + 16384 bytes` (arena + bulk + readahead cache + core stack = 5,009,408 bytes from `umalloc`); `rbd-info` after open:
arena 260,128 bytes used of 262,144 on i386 (2,016 bytes, 0.8 %, free) and 263,392 on x86_64, bulk 2,627,584 of 2,629,632. This is a fixed layout, not growth, but there is no margin to see in it.

**F9. The rBFT table is where the scan says, in different places per binary.** `0x9a840` / `0x9a880` (undionly), `0x9e120` / `0x9e140` (native drivers): the BIOS scan of the guest finds exactly one valid copy every time. Table length: 234 bytes with the key (`handoff=key`), **218 bytes without** (`rows/B1-i386-nokey-1`: key via QEMU file, `flags=static`),
248 bytes with the longer WinPE image name; the area `XBFTAB_SIZE` after patch 0002 is 2,048 bytes (`xbftab` in the link maps, both architectures): the table uses 10.6 to 12.1 % of it, and no iBFT competes for it here.

**F10. Odd but harmless.** (a) B1 through UNDI is about 2 times slower to read than through a native driver (section 4.2); (b) the NIC's gateway field is the DHCP router if the PXE server offers one (a first run recorded `nic_gateway: expected none, got 10.77.0.10` because dnsmasq's default offers itself: the field is
right, the expectation was wrong; the PXE server in these runs offers none); (c) the first run of a freshly created image with `winpe` default features (object-map, fast-diff, exclusive-lock) is refused by the writer profile with
`rbd: open failed: image uses features this client does not support (mask in a0) (WR_E_RBD_FEATURES)`: correct, but the line gives a hex mask, not the feature names.

**F11. One x86_64 WinPE run did not complete (`rows/W3-x64-1`): a 30 s cluster stall closed the path and the reopen did not finish for minutes.** The boot reached the Windows logo (boot manager running, `boot.wim` being read);
at 73 s the driver printed `rbd: the cluster has not answered for 30 seconds, closing the path: operation timed out (WR_E_TIMEOUT)`, and at 279 s `... connection handshake did not finish in time (WR_E_M2_HANDSHAKE_TIMEOUT)`; the screen stayed at the logo until the run's
timeout. The cluster itself showed no fault (no daemon restart, no health change), but the box was at its heaviest (load 52 to 67, several guests, 2 GiB memory dumps): within 13 s of its second complaint another x86_64 guest, a Linux boot, printed the same `WR_E_TIMEOUT` line (its path was closed once; one INT 13h read took 61.4 s from its first issue to its completion, the SAN layer cancelling it at its own 15 s command timeout and issuing it again four times:
`rows/B3-trace-1`, `debug.ts` at 369 to 431 s) and **recovered**. The same row repeated twice later on a quiet box reached the shell (`W3-x64-2`, `W3-x64-3`). So: not reproduced and the cause not proven; the 30 s stall itself is most likely the box's load (unproven), but it is the one recovery that did not recover, and why the reopen kept failing is the driver's to explain (robustness rows, module `qemu-robust`).

## 4. Measurements

### 4.1 INT 13h, from the trace builds

Three GRUB boots of the Linux image (PXE with UNDI and CD with a native NIC, i386; CD, x86_64): the commands the driver was handed through INT 13h, from the DBG output of the trace builds (the times in these runs are slowed by that output, see F6; the counts and sizes are not).
A command that the SAN layer cancels at its own 15 s command timeout (`SAN_COMMAND_TIMEOUT` of `core/sanboot.c`) and issues again (same kind, LBA and count, under the same address or, after the driver re-opened the path, a new one) is **one** read with a re-issue count; the latency is from its first issue to its completion
(`bin/analyse.py`; an earlier version counted each re-issue as a read and paired a completion with the next command that reused the address, which is why `B3-trace-1` once showed 1,621 reads and a 71.6 s maximum: 1,617 reads, four re-issues and 61.4 s are the real figures, and the same 1,617 reads / 52,008 sectors as the other CD boot):

### B1-i386-trace-1

- commands 1620 (reads 1619, capacity 1, writes 0), 52072 sectors = 25.43 MiB, largest 127 sectors, 4 reads of 127 sectors, 1587 reads continue the previous one
- first issue to done (20 ms resolution): median 64 ms, p90 236 ms, max 8256 ms over 1619 reads
- most frequent sizes (sectors: count): 1: 32, 11: 28, 53: 28, 16: 27, 20: 27, 22: 27, 31: 27, 33: 27
- reads over 64 sectors: 5

### B3-i386-trace-1

- commands 1618 (reads 1617, capacity 1, writes 0), 52008 sectors = 25.39 MiB, largest 127 sectors, 4 reads of 127 sectors, 1586 reads continue the previous one
- first issue to done (20 ms resolution): median 64 ms, p90 174 ms, max 8103 ms over 1617 reads
- most frequent sizes (sectors: count): 1: 31, 11: 28, 53: 28, 16: 27, 20: 27, 22: 27, 31: 27, 33: 27
- reads over 64 sectors: 5

### B3-trace-1

- commands 1618 (reads 1617, capacity 1, writes 0), 52008 sectors = 25.39 MiB, largest 127 sectors, 4 reads of 127 sectors, 1586 reads continue the previous one
- 4 re-issue(s) of a command that had not finished (the SAN layer's own timeout; counted once, not as new reads)
- first issue to done (20 ms resolution): median 87 ms, p90 332 ms, max 61387 ms over 1617 reads
- most frequent sizes (sectors: count): 1: 31, 11: 28, 53: 28, 16: 27, 20: 27, 22: 27, 31: 27, 33: 27
- reads over 64 sectors: 5

### 4.2 Readahead (`readahead=0` against the default 2,048 KiB)

Same image, same binary, three runs each, alternating, the read phase = GRUB's countdown ended -> the initramfs started (what the firmware spent serving the kernel and the initramfs, about 25 MiB):

| path | readahead | runs | read phase s (min / median / max) |
|---|---|---|---|
| PXE, undionly.kpxe (UNDI NIC) | 0 (off) | 3 | 33.5 / 35.5 / 122.5 |
| PXE, undionly.kpxe (UNDI NIC) | 2048 KiB (default) | 3 | 9.5 / 10.6 / 12.2 |
| CD, ipxe.iso (native NIC) | 0 (off) | 3 | 24.3 / 25.6 / 35.9 |
| CD, ipxe.iso (native NIC) | 2048 KiB (default) | 3 | 5.3 / 5.7 / 6.7 |

With the window the 1,600 sequential commands (4.1) are served from prefetched lines instead of costing one cluster round trip each: **3.3 times** (UNDI) and **4.5 times** (native NIC) shorter read phase at the median, on a loaded box (how many cluster operations that saved was not observable, F5). The spread of the `readahead=0` runs shows the load of the box, not the driver.
UNDI (undionly) is the slower path with the same driver and the same cluster: `B1N-i386-rel-*` (native NIC, PXE) are in the table of all runs.

### 4.3 Stack (RBD_STACK_MONITOR) and heap

**i386, a real boot** (GRUB reading through INT 13h, the stack mark printed by the driver when it grows):

| run | build | iPXE stack used / total (left) | core's own stack | arena B | bulk B |
|---|---|---|---|---|---|
| B0-i386-rel-1 | i386-rel | - | 1696 / 16384 | 260128 | 2627584 |
| B0-i386-sm-1 | i386-sm | 2120 / 4096 (1976) | 1696 / 16384 | 260128 | 2627584 |
| B0-rel-1 | rel | - | - | 263392 | 2627584 |
| B0-sm-1 | sm | - | - | 263392 | 2627584 |
| B0N-i386-rel-1 | i386-rel | - | 1696 / 16384 | 260128 | 2627584 |
| B0N-rel-1 | rel | - | - | 263392 | 2627584 |
| B0N-sm-1 | sm | - | - | 263392 | 2627584 |
| B1-fix-1 | fix | 5608 / 8192 (2584) | - | - | - |
| B1-i386-sm-1 | i386-sm | 2784 / 4096 (1312) | 1696 / 16384 | - | - |
| B1-i386-trace-1 | i386-trace2 | 2932 / 4096 (1164) | 1696 / 16384 | - | - |
| B2-i386-pause960-1 | i386-trace2 | 2812 / 4096 (1284) | 1696 / 16384 | - | - |
| B2-i386-sm-1 | i386-sm | 2676 / 4096 (1420) | 1696 / 16384 | - | - |
| B3-fix-1 | fix | 5608 / 8192 (2584) | - | - | - |
| B3-i386-pause60-1 | i386-trace2 | 2824 / 4096 (1272) | 1696 / 16384 | - | - |
| B3-i386-sm-1 | i386-sm | 2676 / 4096 (1420) | 1696 / 16384 | - | - |
| B3-i386-trace-1 | i386-trace2 | 2824 / 4096 (1272) | 1696 / 16384 | - | - |

* i386: **iPXE's 4,096-byte stack peaks at 2,784 bytes (1,312 left, 32 %)** in the worst release run (B1, PXE); 2,676 on USB and CD; 2,120 in B0. In the trace builds (more output on the stack) the largest was 2,932 (1,164 left).
  The core runs on its own stack: **1,696 of 16,384 bytes** in every i386 boot (the 2,632 bytes the call-graph tool predicts is the worst chain, not what GRUB's reads reach). So the margin the design feared (84 bytes without the trampoline) is 1,164 to 1,420 bytes with it.
* x86_64 (with the local fix of F2): 5,608 of 8,192 bytes (2,584 left, 32 %) at the end of both boots; there the core runs on iPXE's stack.
* Heap: the session asks `umalloc` for arena + bulk + readahead cache + core stack = 262,144 + 2,629,632 + 2,101,248 + 16,384 = **5,009,408 bytes** on i386 and 266,240 + 2,629,632 + 2,101,248 + 0 = 4,997,120 on x86_64 (the `needs` line of the trace builds, `rows/B3-i386-trace-1`, `rows/B3-trace-1`).
  At open (`rbd-info`, rows B0) the core has used 260,128 bytes of its arena on i386 and 263,392 on x86_64 (2,016 and 2,848 bytes free), and 2,627,584 of the bulk area. The marks after the boot are not observable (F5).

### 4.4 The table area

See F9: `xbftab` is 2,048 bytes after patch 0002 (map facts in `builds/`), the rBFT table 218 (no key) / 234 (key) / 248 bytes (WinPE names), found by the scan at the addresses above.

### 4.5 First command after a pause

The guest (i386 build, CD and USB, trace) was **stopped** with QMP `stop` while GRUB was reading the kernel (the first read at or above LBA 0x40000), and continued after 60 s and after 960 s (longer than Ceph's 900 s idle timeout of a connection). QEMU's `stop` freezes the guest's clock too, so iPXE's own timeouts do not run during the pause; what is measured is what the next commands cost.
**This is a frozen guest with one command in flight, not an idle connection**: the request was already sent and its reply could not be taken while the guest was stopped, so the cluster side saw a half-finished exchange, not a quiet one. What it shows is that a guest that comes back after 60 s or 960 s of stopped time carries on without a driver complaint; it does not measure an idle gap (a pause between two commands), which no row here did.

| run | guest stopped for | stopped at | the command in flight finished | the first command issued after | driver complaints after the resume |
|---|---|---|---|---|---|
| B2-i386-pause960-1 | 960 s | an INT 13h read at LBA 0x42a00 (20 sectors) | 2216 ms after the resume | 251 ms (LBA 0x42a14, 44 sectors) | none |
| B3-i386-pause60-1 | 60 s | an INT 13h read at LBA 0x42a00 (20 sectors) | 359 ms after the resume | 357 ms (LBA 0x42a14, 44 sectors) | none |

After 60 s the command that was in flight completes in 0.36 s, about the cost of any command in a trace build. After 960 s it costs **2.2 s**, about 1.9 s more: with no console line, no failure and no retry by the SAN layer. The cause is inferred, not observed (the trace builds print no connection events):
the connection had been closed on the cluster side (or its TCP state was gone after 16 minutes of unanswered segments) and the core reconnected and re-authenticated inside the command. The next command costs 0.25 s again. So a long freeze costs a couple of seconds once and the boot goes on; the design's "Idle gaps" statement (section 10) stays **untested** by this row. The robustness rows (an OSD killed, the NIC cut) belong to module `qemu-robust`.

## 5. All runs

One line per evidence directory (`bin/summarize.py`). `read s` = GRUB's countdown ended -> the initramfs started. The times of the `*-pause*` runs include the time the guest was stopped, those of the `trace` runs are slowed by the DBG output (F6), the W rows have no
automatic verdict: `WinPE shell` is the evidence script's probe of the screen (and `final.png`), `NO SHELL` the same probe at the deadline. `DIAG-x64-1` is a diagnostic build, not a row.

| label | build | verdict | net s | SAN s | GRUB s | read s | initramfs s | root OK s | table B | pass/fail/skip | stack used/total | core stack | arena B | bulk B | reads | sectors | of 127 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| B0-i386-rel-1 | i386-rel | PASS (drive unreadable) | 12.5 | 12.5 | 16.9 | - | - | 134.3 | 234 | 40/0/0 | - | 1696/16384 | 260128 | 2627584 | - | - | - |
| B0-i386-sm-1 | i386-sm | PASS (drive unreadable) | 13.9 | 13.9 | 18.2 | - | - | 133.7 | 234 | 40/0/0 | 2120/4096 | 1696/16384 | 260128 | 2627584 | - | - | - |
| B0-rel-1 | rel | PASS (drive unreadable) | 11.1 | 11.2 | 15.1 | - | - | 129.8 | 234 | 40/0/0 | - | - | 263392 | 2627584 | - | - | - |
| B0-sm-1 | sm | PASS (drive unreadable) | 11.1 | 11.2 | 15.3 | - | - | 130.7 | 234 | 40/0/0 | - | - | 263392 | 2627584 | - | - | - |
| B0N-i386-rel-1 | i386-rel | PASS | 11.8 | 11.8 | 12.8 | - | - | 20.9 | 234 | 40/0/0 | - | 1696/16384 | 260128 | 2627584 | - | - | - |
| B0N-rel-1 | rel | PASS | 11.7 | 11.9 | 13.0 | - | - | 17.8 | 234 | 40/0/0 | - | - | 263392 | 2627584 | - | - | - |
| B0N-sm-1 | sm | PASS | 11.8 | 12.1 | 13.4 | - | - | 18.7 | 234 | 40/0/0 | - | - | 263392 | 2627584 | - | - | - |
| B1-fix-1 | fix | PASS | 11.8 | 11.8 | 14.9 | 11.5 | 28.7 | 110.2 | 234 | 40/0/0 | 5608/8192 | - | - | - | - | - | - |
| B1-i386-nokey-1 | i386-rel | PASS | 11.1 | 11.1 | 13.5 | 9.4 | 25.2 | 60.2 | 218 | 40/0/0 | - | - | - | - | - | - | - |
| B1-i386-ra0-1 | i386-rel | PASS | 11.4 | 11.5 | 13.4 | 122.5 | 138.3 | 181.7 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-i386-ra0-2 | i386-rel | PASS | 11.3 | 11.4 | 13.2 | 33.5 | 49.0 | 84.8 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-i386-ra0-3 | i386-rel | PASS | 11.6 | 11.6 | 13.4 | 35.5 | 51.3 | 97.9 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-i386-rad-1 | i386-rel | PASS | 11.3 | 11.3 | 15.6 | 12.2 | 30.3 | 67.4 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-i386-rad-2 | i386-rel | PASS | 11.6 | 11.6 | 14.9 | 10.6 | 27.8 | 64.6 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-i386-rad-3 | i386-rel | PASS | 11.2 | 11.2 | 13.1 | 9.5 | 24.9 | 61.2 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-i386-rel-1 | i386-rel | PASS | 11.5 | 11.5 | 17.9 | 9.3 | 29.5 | 69.9 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-i386-rel-2 | i386-rel | PASS | 11.4 | 11.4 | 13.7 | 12.2 | 28.2 | 63.2 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-i386-sm-1 | i386-sm | PASS | 11.2 | 11.2 | 13.6 | 11.0 | 26.9 | 71.1 | 234 | 40/0/0 | 2784/4096 | 1696/16384 | - | - | - | - | - |
| B1-i386-trace-1 | i386-trace2 | PASS | 14.5 | 14.6 | 47.0 | 257.8 | 308.2 | 364.4 | 234 | 40/0/0 | 2932/4096 | 1696/16384 | - | - | 1619 | 52072 | 4 |
| B1-rel-1 | rel | PASS | 11.2 | 11.2 | 13.9 | 9.9 | 26.0 | 59.8 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1-sm-1 | sm | PASS | 11.4 | 11.4 | 15.2 | 20.0 | 37.6 | 75.1 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1N-i386-rel-1 | i386-rel | PASS | 11.8 | 11.8 | 13.4 | 5.6 | 21.3 | 57.6 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B1N-i386-rel-2 | i386-rel | PASS | 11.7 | 11.8 | 13.7 | 6.1 | 22.1 | 57.0 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B2-i386-pause960-1 | i386-trace2 | PASS | 4.8 | 4.8 | 980.0 | 171.2 | 1153.9 | 1192.8 | 234 | 40/0/0 | 2812/4096 | 1696/16384 | - | - | 1619 | 52072 | 4 |
| B2-i386-rel-1 | i386-rel | PASS | 5.6 | 5.6 | 8.6 | 18.5 | 29.6 | 68.1 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B2-i386-sm-1 | i386-sm | PASS | 4.1 | 4.1 | 7.7 | 11.6 | 21.7 | 59.4 | 234 | 40/0/0 | 2676/4096 | 1696/16384 | - | - | - | - | - |
| B2-rel-1 | rel | PASS | 3.8 | 3.8 | 5.0 | 10.1 | 17.5 | 53.6 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B2-sm-1 | sm | PASS | 4.1 | 4.1 | 6.0 | 12.7 | 20.9 | 57.3 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-fix-1 | fix | PASS | 3.9 | 3.9 | 6.2 | 7.6 | 16.1 | 52.4 | 234 | 40/0/0 | 5608/8192 | - | - | - | - | - | - |
| B3-i386-pause60-1 | i386-trace2 | PASS | 3.9 | 3.9 | 85.9 | 284.2 | 372.4 | 467.5 | 234 | 40/0/0 | 2824/4096 | 1696/16384 | - | - | 1637 | 52648 | 4 |
| B3-i386-ra0-1 | i386-rel | PASS | 3.5 | 3.5 | 5.2 | 25.6 | 33.2 | 72.7 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-i386-ra0-2 | i386-rel | PASS | 4.3 | 4.3 | 6.1 | 35.9 | 44.2 | 81.8 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-i386-ra0-3 | i386-rel | PASS | 3.5 | 3.5 | 5.4 | 24.3 | 32.4 | 68.5 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-i386-rad-1 | i386-rel | PASS | 3.7 | 3.7 | 6.5 | 6.7 | 15.5 | 97.0 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-i386-rad-2 | i386-rel | PASS | 3.4 | 3.4 | 5.6 | 5.7 | 13.6 | 49.8 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-i386-rad-3 | i386-rel | PASS | 3.5 | 3.5 | 5.5 | 5.3 | 13.3 | 107.5 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-i386-rel-1 | i386-rel | PASS | 3.6 | 3.6 | 5.3 | 5.3 | 12.9 | 48.4 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-i386-sm-1 | i386-sm | PASS | 3.4 | 3.4 | 5.6 | 8.0 | 16.1 | 53.2 | 234 | 40/0/0 | 2676/4096 | 1696/16384 | - | - | - | - | - |
| B3-i386-trace-1 | i386-trace2 | PASS | 4.3 | 4.3 | 21.4 | 223.5 | 248.3 | 297.6 | 234 | 40/0/0 | 2824/4096 | 1696/16384 | - | - | 1617 | 52008 | 4 |
| B3-rel-1 | rel | PASS | 3.4 | 3.4 | 5.6 | 6.0 | 13.8 | 50.3 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-sm-1 | sm | PASS | 3.4 | 3.4 | 4.9 | 4.1 | 11.3 | 46.3 | 234 | 40/0/0 | - | - | - | - | - | - | - |
| B3-trace-1 | trace2 | PASS | 4.2 | 4.2 | 13.0 | 453.9 | 469.2 | 508.9 | 234 | 40/0/0 | - | - | - | - | 1617 | 52008 | 4 |
| DIAG-x64-1 | dbg | diagnostic | 13.0 | 13.0 | - | - | - | - | - | - | - | - | - | - | - | - | - |
| NEG-i386-rel-1 | i386-rel | PASS | 11.2 | 11.3 | - | - | - | - | - | - | - | - | - | - | - | - | - |
| NEG-rel-1 | rel | PASS | 11.6 | 11.6 | - | - | - | - | - | - | - | - | - | - | - | - | - |
| W3-i386-1 | i386-rel | WinPE shell | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| W3-x64-1 | rel | NO SHELL | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| W3-x64-2 | rel | WinPE shell | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| W3-x64-3 | rel | WinPE shell | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| W4-i386-1 | i386-rel | WinPE shell | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |
| W4-x64-1 | rel | WinPE shell | - | - | - | - | - | - | - | - | - | - | - | - | - | - | - |

## 6. Cleaning up, deviations, open issues

**Left behind: nothing.** At the end of the work the lab had none of my users, images or the `dnsmasq` package; the builder guest and the box had none of my directories; no QEMU, tunnel or proxy of this module was running
(the exact commands and their output are in `cleanup.txt`).

**Deviations from the task.**

1. Cluster: the dedicated lab VM (design D11 option C), not the main lab: the task text's `~/w/lt2/DONE` rule applies to the main lab only.
2. `undionly.kpxe` rows use a single lab NIC booted by PXE from a `dnsmasq` in the lab VM (the lab VM got the package `dnsmasq-base`, removed at the end), because UNDI cannot see a second NIC. The stock `run-bios-pxe.sh` could not run these rows.
3. B2/B3 use the real `bin/ipxe.usb` / `bin/ipxe.iso` with the constant stub and QEMU's TFTP instead of an embedded script, to keep the key out of the binaries.
4. The box's own internet was 15 to 80 KB/s, so the guest image build fetched its Ubuntu packages through a caching proxy on the workstation that drives the runs, reached by `ssh -R` as `127.0.0.1:18081` on the box and as `10.0.2.2:18081` in the builder guest (apt verified the
   archive signatures; the proxy is untrusted). It is gone.
5. The workflow budget (24 cores / 32 GiB) is checked by the run scripts over every QEMU below one root; an old CI guest of the box (8 cores / 12 GiB, up for days, not part of Phase 2) is under the same root, so `P2Q_BUDGET_*` were raised by exactly its share (32 / 45,056 MiB). This module's guests together with the lab VM and the builder guest stayed within 22 cores / 30 GiB (up to five 2-core / 2 GiB guests at a time); guests of other modules count on top and were not mine to track.
6. W3 and W4 were run once on the i386 images, W4 once and W3 three times on the x86_64 images; the number of runs per row is small, and one of them failed (F11).
7. The key of a PXE row (`undionly.kpxe` / `ipxe.pxe`) is in `autoexec.ipxe`, which the lab VM's `dnsmasq` serves by TFTP on the lab's layer 2 (mode 600 on disk, but TFTP has no access control and the layer 2 is shared by every guest of every module): the key is a throwaway user's, deleted with the run, and
   a guest or a capture on that segment could have read it. The media rows (B2, B3) take it over QEMU's user-mode TFTP (`restrict=on`), which only the guest can reach. Not a leak into a log, which is what the run scripts scan for.
8. **Shared files**: only `harness/CMakeLists.txt` (one delimited block, ctest `bios.selftest`). Nothing under `ipxe/`, `core/` or any other module was edited; the stack experiments are local builds (`builds/stack-phys.diff`, `builds/diag-stack.txt`).

**Open issues** (for the owners of the files named): F1 (design and CI: i386 vs x86_64), F2 (`rbd_stack.c`), F3 (UNDI after exit: documentation, or a note in the driver), F4 (message), F5 (counters after a boot), F7 (the 127 assumption; Windows not traced),
the unmeasured: the Windows boot manager's command sizes, the x86_64 images with WinPE, `GetSystemFirmwareTable` in WinPE.

## 7. Files

| Path | What |
|---|---|
| `bin/run-undi.sh` | rows B0/B1 with `undionly.kpxe`: one lab NIC, `dnsmasq` in the lab VM |
| `bin/run-media.sh` | rows B2/B3: the real `ipxe.usb` / `ipxe.iso`, stub + QEMU TFTP |
| `bin/lib.sh`, `bin/tailts.py` | time-stamped serial and debug console, the pause (QMP stop / continue) |
| `bin/runrow.sh`, `bin/mkparams.sh`, `bin/labenv.sh` | one run with its evidence directory; the expected values of a row; the environment |
| `bin/runwinpe.sh` | rows W3/W4 (rollback of the image, run, evidence of `winpe/run-rows.md`) |
| `bin/analyse.py`, `bin/summarize.py`, `bin/report.py` | metrics and verdicts from a log; the table of runs; the numbers of this file |
| `bin/selftest.sh` | offline test of all of the above (ctest `bios.selftest`) |
| `rows/<label>/` | one run: `cmdline.txt` (the run script's plan, key hidden), `serial.txt` (the serial console; not `.log`: the repository's `.gitignore` skips `*.log`), `console.ts` / `console.chunks` (time-stamped), `debug.ts` (trace builds), `dnsmasq.txt` (PXE rows), `params.txt` (expected values), `hashes.txt` (binary, image, scripts), `metrics.json`, `result.txt` (RESULT line, verdict, lab health before and after) |
| (note) | the `CRITERION` / `NOTE` / `VERDICT` lines of every `result.txt` and every `metrics.json` were derived again with the final `analyse.py` after an adversarial review (stricter criteria: all 40 fields, the OK marker in B0, no verdict for an unknown row; re-issued commands counted once): no PASS/FAIL changed; the first four lines of `result.txt` (the run script's own RESULT line, exit status, lab health) are as the run left them. The `hashes.txt` of a run lists the scripts as they were when the run was made; the scripts in `bin/` are the final versions (later additions: the debug console and the pause source in `lib.sh` / `tailts.py`, `--oct`, the `dbg`/`fix`/`trace2` variants, the pinned control socket and the wait for the run directory in `runwinpe.sh`, the evidence-directory mode of `analyse.py`) |
| `cleanup.txt` | what was removed from the lab, the guest, the box and the workstation, and the state afterwards |
| `builds/` | `SHA256SUMS`, `*/BUILD-INFO.txt`, build logs, link-map facts, `stack-phys.diff`, `diag-stack.txt` |

## 8. Reproduce

```
export P2B_WORK=$HOME/winrbd-p2-bios LAB_DIR=$HOME/winrbd-p2-lab P2Q_WORK=$P2B_WORK/work         # the lab of harness/lab/p2/cluster is up
# builds:  ipxe/tools/build.sh build -o OUT -e stub.ipxe bin/undionly.kpxe bin/ipxe.usb bin/ipxe.iso -- EXTRA_CFLAGS=-DCONSOLE_SERIAL     (bin-i386-pcbios/... for the 32-bit images)
# images:  harness/lab/p2/images/build-bios.sh [--tiny]; users.sh create wrtest-p2-b1; import.sh import --image - --compressed --name wrtest-p2-b1
bin/runrow.sh B1-rel-1 b1 rel          # one row: b0 b1 b2 b3 neg; variants rel sm trace2 i386-rel i386-sm i386-trace2
bin/runrow.sh B1-i386-ra0-1 b1 i386-rel --opt readahead=0
bin/runwinpe.sh W3-i386-1 w3 i386-rel  # WinPE (the owner's image, imported with --features layering)
python3 -I bin/summarize.py $P2B_WORK/results --md; python3 -I bin/report.py $P2B_WORK/results
```
