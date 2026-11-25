<!-- SPDX-License-Identifier: MIT -->
# WinPE preparation for the Phase 2 rows W1 to W4

Everything around a WinPE (or Windows setup) boot image that the iPXE `rbd://` driver is tested with: the exact image layouts, a script that
turns **your** media into a raw disk image and imports it into a lab RBD image, a script that checks the layout **before** a run and fails loudly, the
QEMU command lines and a results template for the four rows, and the design note on what is verified and what is not
([`docs/design/ipxe-winpe.md`](../../../../docs/design/ipxe-winpe.md)).

**This directory downloads nothing and contains no Windows file.** WinPE and the Windows installation media are the owner's property under their licences
(the Windows ADK and the media are not redistributable, and Microsoft's download pages are interactive); there is no legal, redistributable way to fetch them
from here, so you bring them. Every kind of file the scripts read or write is ignored by this directory's `.gitignore`, and the scripts **refuse to write inside a git
work tree at a path git would not ignore**. The rows are therefore marked **"needs a WinPE image from the owner"**; the owner has put images on the lab machine,
outside the repository, and the results of using them are in `run-rows.md` and `docs/design/ipxe-winpe.md`.

| File | What it is |
|---|---|
| `layout-uefi.md` | the UEFI image: GPT, FAT32 ESP with `EFI\BOOT\bootx64.efi`, `EFI\Microsoft\Boot\BCD`, `sources\boot.wim`, `boot\boot.sdi`; every rule and why |
| `layout-bios.md` | the BIOS image: MBR, active FAT32 partition, `bootmgr`, `boot\BCD`, `sources\boot.wim`, `boot\boot.sdi`, the Windows MBR and the NT 6 boot sector (and its second part in sector 12) |
| `check-layout.sh` | read-only check of an image against a layout, before a run; `PASS` / `WARN` / `FAIL` lines, exit 0 / 1 / 2 |
| `import-winpe.sh` | `build` (media directory or ISO to a raw image), `convert` (a VHD, VHDX or qcow2 of your own to raw), `import` (check, then `rbd import`, read-back by sha256, per-image cephx user, snapshot `pristine`), `all` |
| `run-rows.md` | the rows W0 (local-disk baseline) and W1 to W4: command lines, the evidence of each stage, the QMP tool and the rBFT scanner, the results template |
| `selftest.sh` | offline self-test of the scripts and of the tools in `run-rows.md` (no VM, no QEMU, no network, no root, no Windows file) |
| `.gitignore` | every Windows media file type and the work directories |

## What you must supply

A **WinPE** media (from the Windows ADK: `copype amd64 <dir>`, `MakeWinPEMedia`) or the **Windows installation media** (its `sources\boot.wim` is a WinPE with Setup), as an ISO or an
unpacked tree, **x86-64**. What `import-winpe.sh build` takes from it: `bootmgr`, `bootmgr.efi`, `boot\`, `EFI\`, `sources\boot.wim` and the language directories (the boot manager's messages);
it never takes `install.wim` / `install.esd`. An image you made on Windows yourself (`Disk2vhd`, DISM, the ADK's `MakeWinPEMedia /UFD`, a VHD) can be used as it is
(`convert`, then `check-layout.sh`). For the serial-line marker and the other points of the rows, see `run-rows.md`.

Reading an ISO needs 7-Zip (`7z` or `7zz`, it reads the UDF that Windows media use), `bsdtar` or `xorriso` (ISO 9660 only); or extract it yourself and pass the directory.

## Quick start

```
export WINPE_WORK=$HOME/winrbd-winpe                     # outside the repository
harness/lab/p2/winpe/import-winpe.sh build --layout uefi --media /path/to/winpe.iso --out "$WINPE_WORK/uefi.raw"     # build + check
harness/lab/p2/winpe/import-winpe.sh build --layout bios --media /path/to/winpe.iso --out "$WINPE_WORK/bios.raw"     # needs ms-sys for the boot code
harness/lab/p2/winpe/check-layout.sh --layout uefi "$WINPE_WORK/uefi.raw"                                           # any time, read-only
harness/lab/p2/winpe/import-winpe.sh -n import --layout uefi --image "$WINPE_WORK/uefi.raw" --name winpe-gpt       # -n: print, change nothing
harness/lab/p2/winpe/import-winpe.sh import    --layout uefi --image "$WINPE_WORK/uefi.raw" --name winpe-gpt
```

Then `run-rows.md`: W0 first (the image boots from a local disk), then W1 to W4.

## What the check covers, and what it cannot

`check-layout.sh --layout uefi|bios IMAGE` (there is no automatic detection: it must not pass an image for the wrong row):

* the size (a multiple of 512, 64 MiB to `--max-size`, default and maximum 2 GiB), a fixed VHD footer (stripped by `convert`), the partition table (GPT with a protective MBR, both GPT headers
  and their CRCs, an ESP; or MBR with exactly one active partition of type 0B / 0C, boot code in the MBR);
* the FAT32 boot sector (512-byte sectors, **FAT32 by cluster count**, which is what firmware uses), the file system size against the partition;
* BIOS: the hidden-sector count equals the partition start, the NT boot sector is not the stub `mkfs.fat` writes and names `BOOTMGR`, and its second part (sector 12) is there;
* the files, with a size floor and the magic number of each kind (`MZ` + `PE` + x86-64 + EFI application, `regf`, `MSWIM`, `$SDI0001`), and that every `.wim` / `.sdi` the BCD names is in the image.

It **cannot** parse the BCD (a registry hive; the check is a text scan for the paths it names), cannot run the boot code, and cannot say that firmware, `bootmgr` or `winload` will **accept** the
device iPXE presents: that is what the rows are for. Every failure line says what is wrong and what to do about it.

## The rules the scripts keep

* Nothing is downloaded. Nothing is written inside the repository (the git guard), and an existing output file is never overwritten.
* `import` runs the layout check first and imports nothing if it fails (and refuses a fixed VHD: `convert` it first); the image read back from the cluster must match by sha256; the per-image cephx user is limited to the one pool
  (`users.sh`); **no key is printed** by any script here; names must be `wrtest-*` (the rule of `users.sh`), and an existing image is replaced only with `--replace`.
* The lab limits of the Phase 2 workflow hold: an image is at most 2 GiB; the scripts need no root and no loop device.
* `-n` / `--dry-run` prints what would run and changes nothing.

## Needs

`bash`, `od`, `dd`, `tr`, `grep`, `sed`, `awk`, `sort`, `stat`, `sfdisk` (util-linux), `mtools` (`mdir`, `mcopy`, `mmd`); for `build` also `sgdisk` (gdisk), `mkfs.fat` with `--offset`
(dosfstools 4.2 or newer), `truncate`, and `ms-sys` for the BIOS boot code (or the Windows-side `bootsect /nt60`); for `import` the lab (`harness/lab/p2/cluster`) and `gzip`; for `convert` of
other formats `qemu-img`. `sgdisk` is used by `check-layout.sh` when present (it verifies the GPT CRCs). No root.

## Tests

```
bash harness/lab/p2/winpe/selftest.sh          # 25 cases; exit 0 pass, 1 fail, 77 this machine lacks a tool
ctest --test-dir <build> -R winpe              # the same, as winpe.selftest (label winpe)
```

The self-test builds **synthetic** media (the right names and magic numbers, no real content) and disk images from them with the scripts under test, and checks: a correct UEFI and BIOS layout passes (from a
directory and from an ISO, with and without a VHD footer); each of these fails with a clear message (missing `bootmgr`, `BCD`, `bootx64.efi`, `boot.wim`, `boot.sdi`; a BCD naming a missing file; a
boot.wim that is no WIM; an arm64 loader; an ESP that is FAT16, NTFS, empty or has 4096-byte sectors; no active flag; wrong partition type; no MBR boot code; the `mkfs.fat` stub boot sector; an empty sector 12;
a wrong hidden-sector count; a missing backup GPT; too big; not partitioned); `import` (the check comes first, the stream that reaches the VM is the image, a read-back that differs is refused, no
overwrite without `--replace`, names / pools / features validated, dry runs change nothing); the git guard; that this directory's `.gitignore` covers every media type and no media file is in it; the rBFT
scanner (also across a read boundary and with a string offset outside the table), the QMP tool and the evidence script of `run-rows.md` (against a stand-in QEMU: a screendump that is a valid PNG, a memory dump the scanner reads, a shell recognised, a deadline when there is none, no spinning on a dead run, dumps removed); that `check-layout.sh` leaves an image byte for byte unchanged; that a fixed VHD is not imported as it is; size arithmetic that cannot wrap; install images skipped in any letter case and no scratch tree left behind; a qcow2 overlay refused; `shellcheck` clean. The cluster, `users.sh` and the VM are
stand-ins. `ms-sys` is a stand-in too: **the real `ms-sys` was not available** where this was built (it is not in Ubuntu 26.04), so the writing of the boot code is tested for its plumbing only (open issue in
`docs/design/ipxe-winpe.md`).

Run on the Ubuntu 26.04 build guest (gcc 15.2 / clang 21.1.8 image of `harness/lab/p2/builder`, shellcheck 0.11, dosfstools 4.2, util-linux, 7-Zip 26.00): 25 passed, 0 failed (after the review of this module; the first 17 were the original set).

### Against real media (owner's images, 2026-11-23, nothing of it kept in the repository)

* `check-layout.sh` on the owner's UEFI and BIOS VHDs: both `RESULT: PASS`; the UEFI one has one `WARN` (`gpt-verify` skipped: the VHD footer means the end of the disk is not the end of the file).
* `import-winpe.sh build --layout uefi` from the owner's ISO (7-Zip reads it; 378 MiB payload; 512 MiB image; 7 seconds): `RESULT: PASS`. `--layout bios --ms-sys no`: fails exactly on the
  boot code, as designed.
* Boots: the owner's two VHDs, the UEFI image built from the ISO, and the BIOS image built from the ISO (with boot code written by a throw-away script from the owner's image) all reach the WinPE shell
  from a **local** disk in QEMU 6.2.0 with OVMF and with SeaBIOS (`run-rows.md`, row W0). A BIOS image with sector 0 of the boot record right and sector 12 empty hangs after `Booting from Hard Disk...`:
  that is why `check-layout.sh` has the `boot-sector-2` check.

When this module was written no W1 to W4 row had been run (it needed the lab cluster and the driver glue). They have since been run on the owner's images and passed; see the close-out in `run-rows.md` and `harness/lab/p2/results/final/`.
