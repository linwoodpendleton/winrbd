<!-- SPDX-License-Identifier: MIT -->
# WinPE image layout for UEFI (rows W1 and W2)

The disk the iPXE `rbd://` driver shows to OVMF is the RBD image, byte for byte. For a UEFI boot of WinPE (or of the Windows setup
media's boot part) that disk has to be what UEFI firmware expects of a boot disk. This page says exactly what, and what
`check-layout.sh --layout uefi IMAGE` verifies before a run. **No Windows file is part of this repository**: you bring the media
(README.md, "What you must supply").

## The disk

```
sector 0         protective MBR (one entry, type 0xEE, boot signature 0x55AA)
sector 1         GPT header (primary)
sectors 2..33    GPT partition entries
[optional]       MSR partition (type E3C9E316-...), 16 MiB; the Windows tools write one; not needed, harmless
ESP              partition of type C12A7328-F81F-11D2-BA4B-00A0C93EC93B, FAT32, 512-byte sectors, starts at a multiple of 1 MiB
                 (sector 2048 for the image import-winpe.sh builds), runs to the last usable sector
last 33 sectors  GPT partition entries (backup) and the BACKUP GPT header in the very last sector of the disk
```

* **GPT, not MBR.** The UEFI specification looks for boot files on the EFI system partition of a GPT disk, and the removable-media path
  `\EFI\BOOT\BOOTX64.EFI` is searched there. What the pieces in these rows actually do differs a little: the firmware's partition driver publishes the GPT
  partitions on the iPXE-made handle and its FAT driver mounts what it can, and iPXE's `efi_block_match` only asks that the file system is a *child* of the
  SAN device; neither looks at the type GUID. A firmware that follows the specification more strictly would, and the Windows tools always write the type, so the
  check insists on it (`esp`).
* **The backup header must be in the last sector of the *disk*.** The disk size is the image size, rounded down to a multiple of 512.
  An image that was grown or shrunk after the table was written has the backup header in the wrong place; firmware warns and may
  refuse (what Windows does with it is not verified here). `check-layout.sh` fails on it (`gpt-backup`) and names the fix (`sgdisk -e`).
* **Disk GUID.** Windows names a disk by it. A copy of the same media must get its own GUID (`sgdisk -G IMAGE`), or two test images
  look like the same disk to a BCD that names it. `import-winpe.sh build` makes a fresh one (`sgdisk -o`).
* **FAT32, 512-byte sectors.** The SAN device has 512-byte blocks. Firmware decides FAT12/16/32 by the **cluster count**, not by the
  label: a partition that is too small for FAT32 with the chosen cluster size reads as FAT16 whatever `mkfs.fat -F 32` said.
  `check-layout.sh` computes the count (`fat32`: at least 65,525 clusters) from the boot sector. The ESP is not NTFS: no firmware
  reads NTFS, and a Windows ESP is FAT32 for that reason.
* **At most 2 GiB** for the whole image (the lab's rule for test images; `--max-size` can lower it, `import-winpe.sh` refuses more).
  A WinPE `boot.wim` is 300 to 500 MB, so 1 GiB is plenty; install images (`install.wim`, `install.esd`) are **not** part of the
  image and `import-winpe.sh build` leaves them out. FAT32 cannot hold a file of 4 GiB or more anyway.

## The files

| Path in the ESP | At least | Is | Why | Check id |
|---|---|---|---|---|
| `\EFI\BOOT\bootx64.efi` | 64 KiB | PE32+ x86-64 EFI application: the **Windows boot manager** (the media's `efi\boot\bootx64.efi`, a copy of `bootmgfw.efi`) | the removable-media path every UEFI firmware (OVMF included) and iPXE's `sanboot` (`efi_block_boot`) loads | `efi-binary-file`, `efi-binary` |
| `\EFI\Microsoft\Boot\BCD` | 4 KiB | Windows registry hive (`regf`): the boot configuration data | the boot manager reads the BCD from beside itself on the ESP; it says which loader, which RAM disk | `bcd`, `bcd-references` |
| `\sources\boot.wim` | 1 MiB | a WIM (`MSWIM`): the WinPE image | the BCD's RAM-disk device element names it | `boot-wim` |
| `\boot\boot.sdi` | 64 KiB | System Deployment Image (`$SDI0001`) | the BCD loads `boot.wim` as a RAM disk using it | `boot-sdi` |

Also copied by `import-winpe.sh build` and **not** checked (the boot manager looks for them but does without): `\bootmgr.efi`,
`\EFI\Microsoft\Boot\*` (fonts, resources), `\boot\fonts`, `\boot\*\bootmgr.exe.mui`, and the language directories of the media
(`\en-us\bootmgr.efi.mui` and so on: the boot manager's messages; without the one for the BCD's locale the boot manager still works but
prints no text). Nothing else is needed for the boot.

`bcd-references` reads every `\path\name.wim` and `\path\name.sdi` that the BCD names (UTF-16 strings in the hive) and fails if one is
not in the image. It does **not** parse the hive: a BCD is a registry hive and this check is a text scan. What it cannot see: a BCD
whose device elements name a disk and partition by signature (a BCD taken from an installed system). The BCD of Windows setup
and WinPE media is relative (`[boot]`, the boot device), which is why a copy of the media onto any disk boots. If you start from
an installed system's BCD, rewrite it first (`bcdedit /store`, on Windows).

## Build one (Linux, no root)

```
import-winpe.sh build --layout uefi --media /path/to/media-or.iso --out "$WINPE_WORK/uefi.raw"      # also runs check-layout.sh
```

by hand, the same thing (what `build` runs), with `MEDIA` the root of the unpacked media and `IMG` a path that does not exist yet:

```
truncate -s 1G "$IMG"
sgdisk -o -n 1:2048:0 -t 1:EF00 -c "1:EFI system partition" "$IMG"            # one partition, from sector 2048 to the last usable one
read -r start size < <(sfdisk -d "$IMG" | sed -n 's/.*start= *\([0-9]*\), *size= *\([0-9]*\),.*/\1 \2/p')
mkfs.fat -F 32 -S 512 -n WINPE --offset "$start" "$IMG" $((size / 2))         # the size is in 1 KiB blocks; dosfstools 4.2 or newer
export MTOOLS_SKIP_CHECK=1; spec="$IMG@@$((start * 512))"
mmd -i "$spec" ::EFI ::sources ::boot
mcopy -s -n -i "$spec" "$MEDIA"/efi/* ::EFI/
mcopy -s -n -i "$spec" "$MEDIA"/boot/* ::boot/
mcopy -n -i "$spec" "$MEDIA/sources/boot.wim" ::sources/boot.wim
mcopy -n -i "$spec" "$MEDIA/bootmgr.efi" ::bootmgr.efi
check-layout.sh --layout uefi "$IMG"
```

(The media's directories are usually lower case on an ISO and the file names are matched without regard to case by FAT; `import-winpe.sh`
finds them in any case, which this short form does not.)

An image made on Windows (DISM / `MakeWinPEMedia /UFD`, then `Disk2vhd`-style export, or the owner's own VHD) is fine as it is
if the check passes: a **fixed** VHD (the raw disk followed by a 512-byte `conectix` footer) is read by `check-layout.sh` as it is,
and `import-winpe.sh convert` strips the footer (a dynamic VHD, a VHDX or a qcow2 needs `qemu-img`).

## What stays unverified by the check

That the firmware **runs** it. A passing check says the layout is the one the Windows media have; it does not say that
`bootx64.efi` accepts the iPXE-made handle's device path. That is the point of the rows (run-rows.md) and is listed in
`docs/design/ipxe-winpe.md`.
