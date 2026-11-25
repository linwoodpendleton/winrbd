<!-- SPDX-License-Identifier: MIT -->
# The UEFI rows of the live matrix: what was run, how, and what was seen

Rows U0 to U3 of `docs/design/ipxe-driver.md` section 14.3 (and, because the owner's WinPE images were available, W1 and W2), run on 2026-11-23 against the dedicated lab
(`harness/lab/p2/cluster`, a real Ceph v20.2.5: mon, three OSDs, one pool, in a VM on the build machine) with the iPXE build of `harness/lab/p2/builder/build-ipxe.sh`.
Every row is one QEMU/KVM guest (OVMF 4M, Secure Boot **off**, `-smp 2 -m 2048`, QEMU 6.2.0, user-mode networking plus the lab's private layer 2); every row is **one directory** in `rows/`.
`MATRIX.md` is the table of all of them (made by `tools/summarize.py`); the verdicts in it were made by `tools/analyze.py` from the logs, not typed in.

Nothing here is a claim that was not observed: a row that failed says FAIL and why. The findings (F1 to F8, T1 to T5, and what the review of this module found) are in the Findings section at the end of this file; the summary is at the end of this file.

## What is in this directory

| Path | What |
|---|---|
| `rows/NAME/` | one row: `cmdline.txt` (the exact command line; the key is only ever a file name), `binaries.sha256` (iPXE binary, OVMF code and variable store, image manifest, the build's SHA256SUMS, QEMU version), `serial.log`, `stamps.txt` (seconds to each stage; guest CPU wait), `result.txt` (the run script's `RESULT` line), `facts.txt` (what the analysis extracted: rbd console lines, `rbd-info` counters, the table check summary), `verdict.txt` (PASS / FAIL / BLOCKED, then one line per check), `shots/` (screenshots: U0 shell, WinPE), `stdout.txt` |
| `attempts/` | runs that did not count as the row but explain it: the first U0 tries (the hang at `exit`), the debug-build and layer-2-capture runs of finding F1, the `snponly.efi` runs, runs with a wrong address or marker (my mistakes, kept) |
| `expect/` | the expectation files and generated scripts of the rows (no key in any of them): the table expectations (`rbft.*`) the guest checked, the iPXE commands of U0 and of the byte check, the oracle's digests |
| `build/` | the iPXE build report (`results.txt`: 5 targets plus `snponly.efi` and the EFI ISO, zero warnings, licence, Secure Boot refusal, 69,180 + 69,255 self-tests, UBSan; **it has one FAIL line**, the builder's own count of FORBIDDEN objects, which is finding T1, a false alarm of the check and not of the sources: `secboot-recheck.txt` is the re-check with the repository's own tool) and the SHA-256 of every binary |
| `lab-after.txt` | what the lab holds after the run (the listing the task asks for; the box's own directory is shown as `<lab dir>`) |
| (the Findings section of this file) | the findings, with the rows that show each, what is and is not known, and what a rerun should and should not be |
| `MATRIX.md` | the table, one line per row |
| `tools/` | the scripts that ran it and judged it (below); `tools/selftest.sh` is ctest `uefi.selftest` |

## The result in one table

(`MATRIX.md` has every directory; this is the summary. "n" = runs of that row.)

| Row | What | n | Result |
|---|---|---|---|
| U0 `vendor`, `sata` | `ipxe.efi` by PXE, `sanhook` the Linux image, UEFI shell: `map -r` lists both block devices and their partitions, `ls` reads the ESP, the device path has the node of the flavour | 1 each | **PASS** |
| U0 `uri` | same, `devpath=uri` | 1 | **FAIL** (F2: the URI node can never be built) |
| U1 `vendor` | `sanboot` of the Linux GPT image to the login prompt: table check (40 of 40 fields PASS, none skipped), `/` on `/dev/rbd0p2`, login prompt | 33 (release build, default window: 32 in `rows/` and `attempts/U1-vendor-try1-killed`) | **28 PASS, 5 FAIL**: all five between 20:22 and 21:07 UTC; three (`r4`, `r11`, `r12`) were stopped by the operator with SIGTERM while the guest sat in GRUB (`qemu.out`: `terminating on signal 15 from pid ...`, so the run script says `guest-exited`; `r4` and `r11` name a `bash`), `r14` ended at once on the fail marker; the passing runs: GRUB at 12.5 to 25.7 s, table check at 20 to 44 s, root at 54 to 109 s, login at 59.6 to 112.7 s (quiet machine: 59.7 to 65.8 s). Of the 49 boot rows started after 21:19 UTC, 48 passed and the one FAIL is the deterministic `U1-uri` (F2); see F1 in the Findings section at the end of this file |
| U1 `vendor`, debug builds | the same with the debug builds of finding F1 (`ipxe-dbg.efi`, `ipxe-dbg2.efi`) | 8 | **4 PASS, 4 FAIL** (`r102` to `r104`, `r202`), all inside the same stretch |
| U1 `vendor` with `readahead=0` | the same, the readahead cache off (10 in a row, 10 interleaved with default runs, 7 under a build load) | 27 | **27 PASS**, login at 59.7 to 72.2 s (the window makes no difference to the boot time: the firmware reads 27 MiB) |
| U1 `sata` | same, SATA node | 1 | PASS (login 75.8 s) |
| U1 `uri` | same, URI node | 1 | **FAIL** (F2) |
| U1 handoff `nokey` / `key` | the key by QEMU's file channel (default) / the key inside the table (`handoff=key`: `key_type aes`, 16 bytes, not printed) | 16 / 1 | PASS (the `vendor` runs above) / **PASS** (`U1-handoff-key`, 40 of 40) |
| U2 | `ipxe.efi` as `EFI/BOOT/BOOTX64.EFI` on a USB stick image (GPT + FAT) | 1 | **PASS** (login 59.5 s) |
| U3 | the real `bin-x86_64-efi/ipxe.iso` with the script embedded (`EMBED=`), as a CD | 1 | **PASS** (login 55.2 s) |
| UB bytes | 18 files, 143.5 MB, read through the SAN device by the firmware's FAT driver, digested in iPXE; compared with the build list AND with the same files read out of `rbd export` of the imported image | 2 | **PASS 18 of 18 both times**; default window 18.6 s, `readahead=0` 53.7 s |
| N password / no key / wrong pool / wrong image / no monitor | each must fail with its console line and errno | 1 each | **PASS** (EINVAL, EINVAL, ENOENT, ENOENT, ENETUNREACH) |
| N wrong key | | 1 | **FAIL**: EPROTO instead of EACCES (F3) |
| W1 `vendor` / W2 `vendor` | the owner's WinPE (GPT) image from RBD: OVMF + PXE / + USB stick: boot manager, `boot.wim` through the SAN device, WinPE command prompt | 2 / 1 | **PASS**: the check is the screenshots' colour test (four corners in the WinPE desktop colour, stable to the last screenshot at second 360); that the `cmd.exe` window with `wpeinit` finished is what the screenshots show to the eye (`shots/shot-120.png`: the 120 s shot is the first with the desktop, the 60 s one has none) |
| W1 `sata` | same, SATA node | 2 | **FAIL** twice: nothing after `Booting from SAN device 0x80` (F8) |
| W1 `uri` | | 1 | **FAIL** (F2) |
| control: iPXE's stock HTTP SAN, same flow (kernel + initramfs loaded, hook ran) | 14 | 14 | PASS 14 (run on a quiet machine, so not a matched control of F1) |

WinPE rows W3 and W4 and every BIOS row are `results/bios`'s. The WinPE rows record the **boot manager and WinPE start** only: WinPE has no `rbd` driver in this phase, so the disk is not visible inside WinPE
and Windows' own view of the `rBFT` table was not tested (`docs/design/ipxe-winpe.md`).

## How a row is run (and repeated)

The machine that hosts the lab and the guests ("the box") runs everything; nothing is compiled on a workstation.

```sh
# one environment file on the box (an example: tools/box-env.example); the paths are the box's
export P2Q_WORK=...                # the QEMU scripts' work directory: ipxe/ (the build results + SHA256SUMS + Shell.efi), tools/usr (mtools, xorriso, syslinux)
export P2_LAB_DIR=... P2U_OUT=... P2U_IMAGES=...
tools/matrix.sh list               # the rows and what each proves
tools/matrix.sh -n U1-vendor       # look first: the command line, nothing started
tools/matrix.sh u0 bytes neg u1 u2 u3 w
tools/summarize.py rows > MATRIX.md
tools/cleanup.sh                   # the throwaway users, images and media, then the listing
```

* `tools/p2u.sh row NAME KIND ...` runs one row through `harness/lab/p2/qemu/run-uefi-{pxe,usb,iso}.sh` and writes the evidence directory; `tools/analyze.py` judges it (profiles `shell`, `boot`, `bytes`,
  `negative`, `winpe`, `control`); `p2u.sh rejudge` re-judges an existing directory when a rule changed (the run is not repeated). `tools/stamp.py` follows the serial line (stages, guest CPU wait),
  `tools/shot.py` takes screenshots through QMP (and tests the corners for the WinPE desktop colour), `tools/sniff.py` summarises the guest's frames on the lab's layer 2 (a diagnostic).
* One cephx user per image, made by `images/import.sh user-create`, legacy `aes` key (the Linux guest's kernel client cannot use the 32-byte keys), caps limited to the pool; the key goes to a mode-600 file
  (`p2u.sh key`), is read by `gen-script.sh` into the run script and nowhere else, and is never an argument, a log line or a file in this tree. The run scripts scan every console log for the key; this module scanned
  every evidence file again for the actual keys of the run and for anything that looks like one (`AQ...==`): none. The users and the images are deleted afterwards (`cleanup.sh`, `lab-after.txt`).
* **The images.** The Linux guest is `images/build-uefi.sh`'s `linux-uefi.raw` (Ubuntu 24.04, kernel 6.8.0-151, GPT: 128 MiB ESP + ext4 root, an initramfs hook that checks every field of the `rBFT` table, then
  maps the image with the kernel client and mounts `/` from it), imported with feature `layering` only. The byte-check disk is `tools/build-bytes-image.sh` (GPT + FAT32 labelled `WRBYTES`, 17 deterministic pseudo-random files
  of 1 B to 83.9 MB straddling every boundary that matters, plus the firmware's own `Shell.efi`); it is rebuilt byte for byte from its names. The WinPE image is the owner's `winpe-gpt.vhd` converted to raw
  (never committed or published; deleted from the lab and the box after the run).
* **The table check.** The expectations of a boot row (`expect/U1-vendor.params`) are the values the configuration must produce, generated by `images/expected-table.sh` from the options plus the image id and the lab NIC's
  MAC; the guest prints `RBFT PASS|FAIL|SKIP` per field, and `analyze.py` requires 40 PASS, 0 FAIL, 0 SKIP.

### Deviations from the design, and why

1. **Row U0 starts the shell from iPXE** (`imgexec`) instead of "leaving to the UEFI shell". When an EFI application returns, iPXE unloads and its SAN devices go with it (and with the rbd device hooked the guest hangs there:
   `attempts/U0-vendor-try1`, F4). The shell is OVMF's own, extracted from the firmware image by `tools/extract-shell.py` and read out of a second RBD image (the byte-check disk) through the SAN device, so
   both devices are visible to the shell (two sessions in one iPXE at the same time). `map -r` prints the device path as text (`VenMsg(9041FCE5-...)` is the shell's name for the vendor-defined messaging node, `Sata(...)`, `Uri(rbd:...)`), which is what `dh -d` would show for it; `dh -d` itself was not run.
2. **The byte check reads files, not raw sectors.** iPXE has no command that reads raw blocks. The firmware's FAT driver turns every file read into block reads at many offsets and lengths, iPXE's `imgfetch file://WRBYTES/NAME` + `md5sum`
   digest what arrived, and the oracle is `rbd export` of the same image read by the lab's own tools. A check that read raw ranges would need a command in the driver or a second boot.
3. **The boot rows have no "bytes read".** Nothing prints after `sanboot` (F6); the volume of the firmware phase is about 27 MiB (GRUB, kernel, initramfs: the manifest), the counters of 143.5 MB are in the `UB` rows. Time to the kernel is
   the table check (the initramfs hook runs at 20 s); the kernel prints no line of its own at `loglevel=4`.
4. **U3 uses an ISO with the key in it** (one throwaway user per image; the ISO is deleted with the user: `cleanup.sh`). The ISO is the real `bin-x86_64-efi/ipxe.iso` target built with `EMBED=`; `build/` has the hash of the un-embedded one.
5. **Shared files.** One: `harness/CMakeLists.txt` gets the block `module qemu-uefi` (ctest `uefi.selftest`, 148 checks, ~17 s (144 without the disk part, which skips itself, with a line saying so, when `sfdisk`, `mkfs.vfat` or mtools is missing: a machine without mtools runs the 144)). Nothing else outside `harness/lab/p2/results/`.
6. **Budget.** The 12 GiB `ci26` guest (Phase 1's CI, not part of this workflow) was excluded from the budget by raising `P2Q_BUDGET_CORES` / `P2Q_BUDGET_MEM_MB` by exactly its share, as the BIOS module did; this workflow's own guests (lab 4 vCPU / 8 GiB, builder 8 / 12 GiB, one test guest 2 / 2 GiB) stayed within 24 cores / 32 GiB.
7. **The verdicts were made again** on 2026-11-23, after a review of this module, with the stricter rules of `tools/analyze.py` (`p2u.sh rejudge-all rows expect`): no first line changed (103 rows: 89 PASS, 14 FAIL, none BLOCKED), the new lines are in each `verdict.txt` and `facts.txt` did not change. What the review tightened: the vendor node of the device path is decoded (version, fsid, `pool/image`) and must follow `PciRoot/Pci/MAC`; the ESP is the file system whose root holds `EFI` (not "FS2": with the SATA node the firmware numbers the ESP FS1, and FS2 is iPXE's own `Uri(file://WRBYTES/Shell.efi)` volume); the 40 table fields are 40 distinct names and agree with `RBFT-RESULT`; a boot that passed must not have printed a path closure, an out-of-memory line or a GRUB read error; the negative rows name the status (`WR_E_POOL_NOT_FOUND`, ...) and not just "failed"; a key-shaped string (`AQ...` and `Ag...`) in any file of a row, wrapped or not, is a FAIL that prints nothing of it. The HTTP control rows were first judged as `smoke` (their `cmdline.txt` still says so) and are judged as `control`. The expect files of the rows U0 and N-* were amended with the new expectations, `expect/MD5SUMS` is a copy of `expect/oracle.md5` (the original verdicts say all 18 files agreed three ways, so the build list and the oracle are the same list) so that the byte rows can be judged again from the evidence alone.
8. **The WinPE screenshots** (`rows/W*/shots`, `screen.png`) show a `cmd.exe` window of the owner's WinPE image; no Windows file is in this tree. Whether screenshots of a Windows window belong in a public repository is the owner's decision (the PNG files can be deleted and `probe.txt` kept: the verdict is made from the probe lines, not from the pictures).
9. **Operator stops.** `stop=guest-exited` in a row means the QEMU process ended, not that the guest powered off: in `U1-vendor-r4`, `-r11`, `-r12` it is the operator's SIGTERM (see `qemu.out`).

## Known problems these rows found (details with evidence in the Findings section at the end of this file)

F1 **a boot stalls after the GRUB menu in some runs** (5 of the first 16 default-window runs, then 0 of 17; 0 of 27 with `readahead=0`, but the first 10 of those ran after the bad stretch at a much lower load, so only the interleaved 10 + 10 compare like with like; all 8 failures of the release and debug builds lie between 20:22 and 21:19 UTC and 48 of 48 later boot rows passed except the deterministic F2; the failing runs' captures show the guest's transmit going silent while the cluster keeps sending, and iPXE's
virtio-net receive failing 17,582 times; the cause is not found and the readahead window is **not** shown to be the cause: the matched runs on a quiet machine pass with and without it) · F2 `devpath=uri` never works · F3 a wrong key is EPROTO, not EACCES ·
F4 U0 as designed cannot work and `exit` with a hooked device hangs · F5 a path that cannot be reopened prints `parse URI failed: out of memory` forever (the BIOS rows saw the same after a 30 s stall) · F6 no counters after `sanboot` ·
F7 `rbd-info` shows `1 failed` in a clean byte check · F8 the Windows boot manager takes the `vendor` node and not the `sata` one ·
T1 `build-ipxe.sh` has a flaky `grep -q` pipe in its Secure Boot object check · T2 `expected-table.sh`'s default MAC is not the run scripts' · T5 the budget and the global `sync()` stalls on the shared machine.

## Findings

What the rows in `rows/` showed, what is and is not known about it, and what a rerun is for. Row names are directories of `rows/`; times are UTC on 2026-11-23 (the start time of a row is the first line of its `cmdline.txt`).
A finding says what was **observed**; a cause is given only where the evidence has it, otherwise it says "not found".

### F1. Some boots fail after the GRUB menu (not understood)

| Observed | Where |
|---|---|
| 8 of the 23 boot rows started up to 21:19 failed: `r4`, `r11`, `r12`, `r14` (release build), `r102`, `r103`, `r104`, `r202` (debug builds); counting the release build only, 5 of 33 default-window runs (the fifth is `attempts/U1-vendor-try1-killed`). | `MATRIX.md`, family table |
| 48 of the 49 boot rows started after 21:19 passed; the one FAIL is `U1-uri` (F2, deterministic). Among them 27 `readahead=0` runs, 17 default runs (7 of them under a build load, load average 31 to 53) and the sata, handoff-key, USB and ISO rows. | same |
| All eight failing rows have `rbd: the cluster has not answered for 30 seconds, closing the path: <status>` (status `WR_E_TIMEOUT`, `WR_E_MON_UNREACHABLE` or `WR_E_NET_CONNECT`; 8 times in `r11`), and then, in six of them, `rbd: parse URI failed: out of memory` (36 times in `r4`, 18 in `r14`, 7 in `r11`, once in `r102` to `r104`) and, in `r4` and `r14`, GRUB's `error: failure reading sector ...` / `Failed to boot both default and fallback entries`. `r12` and `r202` have the closing line and nothing after it: the guest sat in the GRUB menu (`r12`: 256 s after it). | `rows/*/serial.log`, `rows/U1-vendor-r102/screen.png` |
| `r4`, `r11` and `r12` ended because the operator stopped QEMU (`qemu.out`: SIGTERM), not because the guest ended: the run script's `stop=guest-exited` is about the process. | `rows/*/qemu.out` |
| The guest's own CPU wait is small in every failing row (0.0 to 2.0 s in total, `stamps.txt`); the host's load average was 48 to 66 in the release failures and 27 in `r202`; but default runs at load 47 to 57 passed (`r9`, `r10`, `abdef-r10`, `ldef-r1`). Load alone does not separate them. | `stamps.txt` |
| The lab's OSD logs for 20:00 to 23:30 show BlueStore stalls at 20:08 (5 to 7 s commits on all three OSDs), a **51 s** read on `osd.2` at 20:12 (with a heartbeat timeout), 14 s at 21:28 and 5 s at 23:07; **nothing above BlueStore's 5 s logging threshold between 20:34 and 21:19**, and the cluster mutes `BLUESTORE_SLOW_OP_ALERT`. So the lab does stall for longer than the driver's 30 s watchdog now and then (the box has a global `sync()` problem: T5), but these logs do not show it inside the stretch with the failures. | the lab VM's `journalctl -u ceph-<fsid>@osd.N` (not kept in the repository) |

**Not known:** why the cluster, or the path to it, stopped answering the guest for 30 s in that stretch; whether the lab VM itself was starved (`stamp.py` did not record the lab VM's CPU wait then; it does now); why the 4 MiB iPXE `malloc` heap (design 5.1) cannot serve a small `zalloc`
(`rbd_parse_uri()`, `rbd_uri.c`) after a path closure: heap exhaustion is the common symptom (the debug captures' 17,582 failed virtio-net receives are the same thing seen from the NIC), the consumer was not identified.

**What the evidence does not support:** blaming `readahead` (the first `readahead=0` batch ran at 21:42, after the stretch, at load 21: it is confounded by time; the interleaved batch `abdef`/`abra0`, 10 + 10, is the matched one and did not fail either way) or blaming load (see above).

**Should the rows be run again?** Not the same rows as they are: a rerun of the unchanged matrix would most likely pass (48 of 49 boot rows since 21:19 passed) and would prove nothing about F1. What is worth running: (1) after F5 is fixed (an open that fails must not loop on an allocation failure), and with a heap-usage line printed when the path closes
(free bytes and largest free block of iPXE's heap), a **large interleaved default-vs-`readahead=0` series** (100 + 100; `stamps.txt` now records the lab VM's CPU wait next to the guest's), with the OSD slow-operation log of the same window kept next to each row; (2) after F2, F3 and F8 are fixed, the rows they failed
(`U0-uri`, `U1-uri`, `W1-uri`, `N-wrongkey`, `W1-sata`).

### F2. `devpath=uri` can never be built

`rbd: cannot build the EFI device path (devpath option, names or URI not usable)` then `Could not open SAN device: No such device` (0x2c222087, ENODEV) in `U0-uri`, `U1-uri`, `W1-uri`. The `vendor` and `sata` flavours work. The code is `ipxe/src/rbd_efi.c` (the `MSG_URI_DP` node); not fixed here.

### F3. A wrong key is EPROTO, not EACCES

`N-wrongkey`: `rbd: open failed: server refused the offered authentication method or mode (WR_E_M2_BAD_METHOD)`, error 0x43766098 = EPROTO. The design (section 12) wants EACCES for a key the cluster does not accept. The AUTH_BAD_METHOD frame of msgr2 carries a `result` (a negative errno) next to the method lists
(`src/msg/async/ProtocolV2.cc`, `handle_auth_bad_method`, which logs `cpp_strerror(bad_method.result())`), and Ceph's own client reports such an answer as `errno 13` (`ceph -s` without a keyring, run during the review, printed `handle_auth_bad_method ... allowed_methods [2] and I support [1]` and `RADOS permission denied`).
The row stays FAIL; the driver belongs to another module.

### F4. U0 "leave to the UEFI shell" cannot work; `exit` with a hooked device hangs

When an EFI application returns, iPXE unloads and its SAN devices go with it; with the rbd device hooked the guest hangs there (`attempts/U0-vendor-try1`). Row U0 therefore starts the shell from iPXE (deviation 1).

### F5. A path that cannot be reopened prints `parse URI failed: out of memory` forever

See F1. `rbd_parse_uri()` (`rbd_uri.c`) allocates its working area with `zalloc`; after the 30 s watchdog closed the path, every reopen attempt of the SAN layer fails there, forever (`r4`: 36 lines, `r14`: 18, `r11`: 7; the screen of `r102` ends with `SAN 0x80.0 could not (re)open URI: Not enough space`). The BIOS rows saw it too after a 30 s stall.

### F6. Nothing is printed after `sanboot`

No counters (bytes read, heap, stack watermark) can be taken from a boot row, which the design (14.3) asks of every row. The `UB` rows have the `rbd-info` counters (arena 263,392 B, bulk 2,627,584 B); a heap or stack watermark is in no row.

### F7. `rbd-info` shows `1 failed` operation in a byte check whose data are all right

`UB-bytes` (default window): `osd: 591 ops done, 0 resent, 1 failed`; `UB-bytes-ra0`: `0 failed`. All 18 digests agree three ways in both. Not explained (an operation cancelled by readahead and counted as failed, or a real failure that was retried above?). `analyze.py` now prints it in every row that has it.

### F8. The Windows boot manager does not start with the `sata` node

`W1-sata`, `W1-sata-a2`: the screen stays at `Booting from SAN device 0x80` for 400 s (`shots/shot-360.png`); `W1-vendor` and `W2-vendor` reach WinPE (a `cmd.exe` window after `wpeinit`). The cause is not found (the design says what `bootmgr` needs is unverified).

### Tooling findings

* **T1** `harness/lab/p2/builder/build-ipxe.sh`: its "every driver object is FORBIDDEN" check pipes `nm` into `grep -q` under `pipefail`; the early exit of `grep` can kill `nm` with SIGPIPE, and a large object (here `rbd_session.c`) then reads as "not forbidden". `build/results.txt` has that one FAIL; `build/secboot-recheck.txt` is the repository's own check
  (`ipxe/tools/build.sh secboot`) on the same sources: all 121 objects FORBIDDEN, the Secure Boot target refused. The builder's check should write `nm` to a file and `grep` the file. Not fixed here (another module's file).
* **T2** `images/expected-table.sh`'s default MAC is not the run scripts'. **T5** the box's global `sync()` stalls and the budget lock make a run wait or fail to start; a timing result is judged against `stamps.txt`.

### What the review of this module found, and what was done (2026-11-23)

| Severity | Issue | Fix |
|---|---|---|
| high | The UEFI-shell row (`shell` profile) judged "ls reads the ESP" with `<DIR> EFI` anywhere in the log plus "the command ran on FS2": with the SATA node the ESP is FS1 and FS2 is iPXE's own `Uri(file://WRBYTES/Shell.efi)` volume (empty), so `U0-sata` passed on a listing it was not looking at, and the deeper `EFI\BOOT` listing was never read in that row | the ESP is now the file system whose root listing holds `EFI`; `EFI\BOOT` must hold `BOOTX64.EFI` where it was listed, and is said (INFO) not to have been listed in `U0-sata` |
| high | The device path was judged only by the vendor GUID: the payload (version, fsid, `pool/image`) and the `PciRoot/Pci/MAC` prefix were never decoded | `decode_vendor()` checks version 1, reserved 0, NUL-terminated `pool/image` and the prefix; the U0 expect files name the two expected images |
| high | A key-shaped string was looked for only as legacy `AQ...` in the serial log, and the verdict printed the first 20 characters of the offending line | `AQ` and `Ag` (aes256k), per line and across wrapped lines, in `serial.log`, `stdout.txt`, `qemu.out`, `stamps.txt`, `cmdline.txt`, `result.txt`; only file names are printed; a BLOCKED run is scanned too; the new `tools/keyscan.py` looks for the run's own key (base64, hex, hex dump, `0x` forms) and `p2u.sh` deletes any file that holds it and makes the row FAIL |
| medium | `negative` rows accepted `rbd: .*failed`, which the out-of-memory line also matches; a negative row without an errno expectation passed anything | the matrix names the status (`WR_E_POOL_NOT_FOUND` ...); an errno and a console expectation are both required |
| medium | An expect-file key that is not known (a typo) was ignored: a check that never ran | unknown keys are FAIL |
| medium | `boot`: forty `RBFT PASS` lines counted as forty fields; `RBFT-RESULT` counts were not compared with the lines; a boot that printed a path closure, an out-of-memory line or a GRUB read error could still PASS; the `rbd-info` counters were not looked at | distinct fields; counts must agree; trouble lines are FAIL; a reopen or stall close in `rbd-info` is FAIL; a failed OSD operation is shown (F7) |
| medium | `winpe`: a screenshot colour seen once passed; a registered SAN device was not required | the colour must be in the last screenshot and in at least two; `Registered SAN device` and `Booting from SAN device` are required |
| medium | `bytes`: a file on the disk that is not in the list could not fail; `oracle-bytes.sh` could silently go on without the manifest of the image that was built | the oracle's file set must equal the list; no manifest is an error unless `P2U_ORACLE_NO_MANIFEST=1` |
| medium | This README said the findings were "in the module's return text" and gave "5 of the first 16 stalled" without saying that three of the failing rows were stopped by the operator, that four more failed with debug builds, that all failures lie in one stretch, that the first `readahead=0` batch is confounded, and that `build/results.txt` has a FAIL line | this section, the table above, deviations 7 to 9, the family table of `MATRIX.md` |
| medium | A key name for `p2u.sh key` went into a remote command with only a `wrtest-*` glob (`wrtest-x;id` passed) | `^wrtest-p2-[A-Za-z0-9-]{1,40}$` |
| low | `lab-after.txt` named the box's user and directory | replaced by `<lab dir>`; `cleanup.sh` does it for its own listing and also removes every `client.wrtest-p2-*.secret` |
| low | Rows carried "repository HEAD of the scripts: unknown" | `binaries.sha256` of new rows has `git rev-parse` or, without git metadata, a digest of `tools/` and `harness/lab/p2/qemu/` |
| low | `stamp.py` measured the guest's CPU wait only | with the lab VM's pid file it measures the cluster's as well (the number F1 lacks); `os.getloadavg()` instead of `/proc` |
| low | `MATRIX.md` had no count per family: the failed rows and the debug-build rows were easy to overlook | a family table in which every run counts |
| test | No test of the `winpe`, `control`, `san`, `smoke` profiles, of `exit=4`, the secret scan, `stamp.py`, `shot.py`'s colour probe, the `p2u.sh` key-name rule and key hook, the family table | 78 new checks (148 in all), each with its negative control |
| none | No licence or `FILE_SECBOOT` tag is wrong: all 16 glue files carry `FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )` and `FILE_SECBOOT ( FORBIDDEN )`; every script here is `SPDX-License-Identifier: MIT`; nothing in this module is copied from Linux or Ceph (`extract-shell.py` reads the firmware volume format from its public layout; the one Ceph reference above only settles a protocol question) | |

### Open gaps (not fixed)

* **No live row reads at byte offsets above 4 GiB or at LBAs above 2^32 (2 TiB).** The byte-check disk is 192 MiB, the Linux image about 2 GiB. `rbd_block.c` (`rbd_cmd_create`) checks `lba` and `count` against the capacity without overflow and computes `offset = lba * 512` in 64 bits, and the core's geometry tests go above 4 GiB,
  but the SAN layer, the firmware's GPT and FAT drivers and the driver have not been shown together at those offsets. A row needs a thin RBD image above 2 TiB (`rbd create`; `import.sh` refuses images over 2 GiB), a GPT whose FAT partition starts above 2 TiB, built in a sparse file and loaded with `rbd import-diff`
  (no 2 TiB of zeros read or written), the oracle from `rbd export-diff`, and `UB-bytes` on it.
* The `EFI\BOOT` listing of the ESP was not read in `U0-sata` (the run's shell commands list it on FS2 only; they should list it on every file system).
* The `dh -d` view of the device path was not run (the shell's `map -r` text is what the checks read).
* Windows' own view of the `rBFT` table was not tested (WinPE has no `rbd` driver in this phase).
