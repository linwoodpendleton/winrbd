<!-- SPDX-License-Identifier: MIT -->
# WinPE image layout for BIOS (rows W3 and W4)

For a BIOS boot the iPXE driver shows the RBD image as an INT 13h drive (the first hard disk, `0x80`, when the guest has no
local disk). The BIOS then runs the **MBR boot code**, which runs the **boot sector of the active partition**, which loads
`\bootmgr`. Every link of that chain has to be on the image. `check-layout.sh --layout bios IMAGE` verifies each one before a
run. **No Windows file is part of this repository**; you bring the media (README.md).

## The disk

```
sector 0         MBR: 440 bytes of boot code (the Windows 7 and later MBR), 4-byte disk signature, 4 entries, 0x55AA
sectors 1..2047  empty (alignment; the partition starts at sector 2048 in the image import-winpe.sh builds)
partition 1      type 0x0C (or 0x0B), ACTIVE (0x80), FAT32, 512-byte sectors, runs to the end of the disk
                 sector 0 of it: the NT 6 FAT32 boot sector (3 sectors of boot code, backup at sector 6)
```

* **MBR, not GPT.** A GPT disk's protective MBR has no active partition and the Windows boot sector does not read GPT. The
  UEFI rows use a different image (layout-uefi.md); the two are never the same file.
* **Exactly one active partition.** SeaBIOS (and any BIOS) loads the first sector of the MBR and the MBR code looks for the single
  entry with 0x80. None, or two, and it stops with `Missing operating system` or picks the wrong one (`active-flag`).
  Set it with `sfdisk --activate IMAGE 1`.
* **Partition type 0x0B or 0x0C** (FAT32 CHS or LBA). `check-layout.sh` accepts both, `import-winpe.sh` writes 0x0C.
* **MBR boot code.** 440 zero bytes make SeaBIOS jump into nothing (`mbr-code`). The code the Windows 7 and later tools write
  contains the strings `Invalid partition table`, `Error loading operating system` and `Missing operating system`; the check looks for the
  first one and only *warns* if it is absent (any code that loads the active partition's boot sector works, and the check cannot know).
  Write it with `ms-sys --mbr7 IMAGE` (Linux), or on Windows `bootsect /nt60 X: /mbr` (the media's `boot\bootsect.exe`, or the ADK's).
* **The NT boot sector.** `mkfs.fat` writes a stub that prints `This is not a bootable disk`; it never loads `bootmgr`
  (`boot-sector` fails on it, with that message). The boot sector that loads `BOOTMGR` is the Windows Vista and later FAT32 one:
  `ms-sys --fat32pe` on Linux (the script checks that this ms-sys has the option, and the check that follows looks for the name
  `BOOTMGR` in the first three sectors), or `bootsect /nt60 X:` on Windows. The BPB inside it (sector size, cluster size, FAT
  size, root cluster, **hidden sectors**, **drive number 0x80**) is meant to stay as `mkfs.fat` wrote it, only the code is replaced; `hidden-sectors` checks it
  afterwards, so a writer that changes it is caught. (`ms-sys` documents `--mbr7` as leaving the disk signature alone; `--fat32pe` is its option for the boot record that loads BOOTMGR.)
* **Hidden sectors = the partition's start sector.** The boot code reads `bootmgr` at `hidden sectors + offset`. `import-winpe.sh`
  passes the start to `mkfs.fat -h`; a copied or re-partitioned image whose BPB still says another number is refused
  (`hidden-sectors`, with the fix). The BIOS rows have no other way to be right about this: no partition table repair happens
  between the BPB and the first read of `bootmgr`.
* **FAT32, 512-byte sectors, at least 65,525 clusters; at most 2 GiB** for the whole image: as in layout-uefi.md.
* **Disk signature.** Windows names an MBR disk by its 4-byte signature (offset 440); the media's BCD for BIOS is relative to the
  boot device, so any value is fine, but a zero one is warned about (`disk-signature`): give each image its own (`sfdisk --disk-id`).

## The files

| Path in the partition | At least | Is | Why | Check id |
|---|---|---|---|---|
| `\bootmgr` | 16 KiB | the Windows boot manager (no extension; the first file the boot sector loads) | the boot sector looks for exactly this name in the root | `bootmgr` |
| `\boot\BCD` | 4 KiB | registry hive (`regf`): the **BIOS** BCD (the UEFI one is in `\EFI\Microsoft\Boot\BCD`: different file) | the boot manager reads `\boot\BCD` | `bcd`, `bcd-references` |
| `\sources\boot.wim` | 1 MiB | a WIM (`MSWIM`): the WinPE image | the BCD's RAM-disk device element names it | `boot-wim` |
| `\boot\boot.sdi` | 64 KiB | System Deployment Image (`$SDI0001`) | the BCD loads `boot.wim` as a RAM disk using it | `boot-sdi` |

`import-winpe.sh build` also copies `\boot\fonts`, `\boot\*\bootmgr.exe.mui` and the media's language directories (the boot manager's
messages), and, for a media that has it, `\bootmgr.efi` and `\EFI`: harmless on a BIOS image, ignored by the check. `bcd-references`
is the same text scan as for UEFI (layout-uefi.md): it checks the files the BCD names, not the hive.

## Build one (Linux, no root)

```
import-winpe.sh build --layout bios --media /path/to/media-or.iso --out "$WINPE_WORK/bios.raw"      # also runs check-layout.sh
```

With `ms-sys` on the `PATH` (or `--ms-sys-bin PATH`) the script writes both pieces of boot code. Without it the image is built **without
boot code**, the script says so, and `check-layout.sh` fails on it with the two commands that fix it: on a machine that has `ms-sys` or
Windows (`bootsect`), write them and run the check again. Nothing is faked: a BIOS image that does not pass the check is not imported.

By hand: partition with `sfdisk` (`label: dos`, `start=2048, type=c, bootable`), `mkfs.fat -F 32 -S 512 -h 2048 -D 0x80 --offset 2048`,
copy the files with `mcopy` (as in layout-uefi.md), then `ms-sys --mbr7 IMAGE`. The boot sector has to be written to the partition, not
to the disk: with `ms-sys` that is the partition's device node (a loop device with `--partscan`, root) or, which needs no root, a scratch
copy of the partition's first sectors: `dd if=IMAGE of=pbr bs=512 skip=2048 count=16`, `ms-sys --fat32pe pbr`,
`dd if=pbr of=IMAGE bs=512 seek=2048 count=16 conv=notrunc` (this is what `import-winpe.sh` does).

## Geometry and INT 13h

iPXE answers the CHS calls (AH=02/08) with a geometry it guesses from the MBR (`int13_guess_geometry`), and the extended calls
(AH=41/42/48) with 64-bit LBAs. iPXE answers AH=41 with "extensions present", and the NT 6 boot sector and `bootmgr` are expected to use the extended calls then
(**unverified**: it is what row W3/W4 shows). The `drive number` in the BPB (offset 0x40) is 0x80 and the BIOS passes the real number in `DL`; for the
drive 0x80 these rows use both agree, so it does not matter here which of the two the boot code reads (it would for `sanhook --drive 0x81`; not tested).
Whether `bootmgr` also asks for the EDD device path (AH=48, `edd_describe`), which v1 of the driver does not provide, is **unverified**
and is one of the questions of row W3/W4 (`docs/design/ipxe-winpe.md`).

## What stays unverified by the check

That the BIOS **runs** this chain from an INT 13h drive that iPXE provides and that `bootmgr` then reads `boot.wim` through it. The check says
the chain is complete on the image; the rows (run-rows.md) say whether it works.
