# The iPXE driver and WinPE: what is verified, what is not

Companion to [ipxe-driver.md](ipxe-driver.md) (sections 6, 7, 9, 14.3 and 15, risk R3). It belongs to the module `winpe-prep`, whose files are in
`harness/lab/p2/winpe/`: the image layouts (`layout-uefi.md`, `layout-bios.md`), `import-winpe.sh`, `check-layout.sh`, and `run-rows.md` with the command lines and the
results template for the rows W1 to W4. This note says what those rows can and cannot show, and what has been established so far. Nothing in this repository is a Windows
file, and nothing is downloaded: **the rows need a WinPE image from the owner** (it is not redistributable; the Windows ADK and the installation media are licensed, and the
download pages are interactive).

**State at the end of this module (written 2026-11-23, before the rows ran).** Prepared and tested offline: the layouts, the import and check scripts, the run book and the tools. The owner's WinPE images (an ISO and two VHDs
built with the ADK, kept on the lab machine outside the repository) were used to test the scripts for real, and boot to the WinPE shell **from a local disk** in QEMU. At that time no W1 to W4 row had
been run: the lab cluster was in use by the Phase 1 exit run, and the driver glue did not yet boot anything. Sections 1 to 5 below are as written then; the close-out in section 6 says what the rows showed.

## 1. How a WinPE row boots through the driver

**UEFI (W1, W2).** `sanboot` on EFI (`efi_block_boot`, pinned iPXE `9261ebe38`) releases the SNP devices, finds the filesystem handle that the firmware's partition driver made on top of the
driver's `EFI_BLOCK_IO` handle, builds the device path `<filesystem path>\EFI\BOOT\BOOTX64.EFI` (`EFI_REMOVABLE_MEDIA_FILE_NAME`), and calls `LoadImage` and `StartImage` on it. So
the Windows boot manager (`bootx64.efi` on the ESP) runs with a loaded-image `DeviceHandle` whose device path is **the network prefix + our device-path node + `HD(...)`** (design section 6: one
vendor node, or a URI node, or a SATA node). The boot manager reads the BCD from beside itself, loads `boot.sdi` and `boot.wim` into a RAM disk through the same block device, and starts
`winload.efi` *from the RAM disk*.

**BIOS (W3, W4).** `sanboot` on BIOS (`int13_boot`) reads sector 0 of the hooked drive (`0x80` when the guest has no local disk) to `0000:7C00` and jumps to it with the drive in `DL`. The MBR code
runs the boot sector of the active partition (the NT 6 FAT32 boot record), which loads `\bootmgr`; the boot manager reads `\boot\BCD`, `boot.sdi` and `boot.wim` through INT 13h and starts
`winload.exe` from the RAM disk. iPXE answers the extended calls (AH=41h/42h/48h) and, in v1, gives no device-path information with AH=48h (`edd_describe` is not provided; design section 7).

**What follows from the RAM disk.** `boot.wim` is loaded **completely into memory by the boot manager**, and `winload` and WinPE run from it. After the boot manager has finished with the
disk, WinPE never touches the RBD image again: it has **no `rbd` driver** (that is Phase 3), so the RBD disk is not visible in WinPE and that is the expected outcome. A row that reaches the WinPE shell therefore proves exactly
one thing about the driver: *the boot manager read the whole of `boot.wim` (300 to 500 MB) and the other boot files correctly through the SAN device, on that firmware, with that device path*.
It proves nothing about Windows using the disk after `ExitBootServices` or after the BIOS is left.

## 2. Verified

| What | How | Where |
|---|---|---|
| The layouts are the ones Windows boot media have, and `check-layout.sh` accepts them | the owner's UEFI and BIOS VHDs pass `check-layout.sh` (UEFI: one `WARN`, the GPT CRC check is skipped because of the VHD footer) | README.md, "Against real media" |
| `import-winpe.sh build` produces a UEFI image from a real ISO that passes the check **and boots to the WinPE shell** | built from the owner's ISO (378 MiB payload, 512 MiB image, no `install.wim`), booted from a local AHCI disk with OVMF in QEMU 6.2.0 | `run-rows.md`, row W0 |
| The BIOS image it builds boots too, given the boot code | built from the same ISO; the Windows MBR and NT 6 boot record were written by a throw-away script from the owner's image (the real `ms-sys` was not available), booted from a local disk with SeaBIOS | `run-rows.md`, row W0 |
| The NT 6 FAT32 boot record needs **sector 12** (the rest of its code) as well as sector 0 | a BIOS image with sector 0 right and sector 12 empty hangs after `Booting from Hard Disk...`; with sector 12 it boots. `check-layout.sh` now fails on it (`boot-sector-2`) | `layout-bios.md` |
| The scripts pass all 25 offline cases (each negative case of the task and more; shellcheck clean) | `selftest.sh` on the Ubuntu 26.04 build guest | README.md, "Tests" |
| The rBFT scanner and the QMP tool work on a real guest | a 2 GiB `pmemsave` of the running WinPE guest (5.7 s) scanned in 6.4 s (no table: no iPXE in that run, as expected); `probe` recognised the WinPE shell | `run-rows.md` |
| What `sanboot` does on each firmware (previous section) | read from `efi_block.c` and `int13.c` of the pinned tree | |

## 3. Unverified (the rows exist to settle these)

**U1. Does the Windows boot manager (and then `winload`) accept the EFI device path the driver presents?** What is known: UEFI loads the boot manager through the partition handle's
`EFI_SIMPLE_FILE_SYSTEM`, which the firmware's partition driver builds on any valid parent path (design section 6), and the media's BCD is **relative** (`[boot]`), naming no disk. What is not known:
how `bootmgfw.efi` derives its boot device from the `DeviceHandle` (by device path, by block I/O handle, by reading the GPT signature) and whether an unknown vendor-defined messaging node, a URI node
or a SATA node in the parent path changes its behaviour. The three flavours (`devpath=vendor|uri|sata`) exist so that the first run can try them without a rebuild; **if they differ, that
is the answer to design question Q1**. Reading the outcome: S2 `no` (the boot manager did not start; iPXE got control back, `WRRUN-BOOT-RETURNED`) points at `LoadImage` or the path; S2 `yes`
and S3 `no` with a status code and file name on screen points at the boot manager's own reading of the device (`0xc000000f` names a file it could not find, so look at the BCD and at read errors in the driver).
No claim is made from Windows documentation; the behaviour is to be observed.

**U2. Windows on BIOS through INT 13h without `edd_describe`.** iPXE gives the extended drive parameters of EDD 2.0 and no device-path information (`int13_device_path_info`), which is valid. Whether the
NT 6 boot record and `bootmgr` need the path information is not known; both read through AH=42h, which iPXE provides, and the boot sector uses `DL`. For the WinPE rows this is a question about the boot
manager only. The larger question, which these rows do **not** answer, is the one a real Windows installation on the RBD disk raises later: `winload` matches the BIOS drive to a Windows disk by the MBR
signature and checksum it reads through INT 13h, and the Phase 3 driver must present the same disk. If bootmgr stops on BIOS without the path, the one-function fix of design section 7 (an ATA-style
`edd_describe`) is the next step; the rows say whether it is needed.

**U3. Reading an unknown ACPI signature early in boot (the `rBFT` table).** Two sub-questions, kept apart in the results.
(a) *Is it in guest memory when the OS starts?* The scanner answers it from the host, on UEFI and BIOS, with a dump taken just after `sanboot` hooks the device and one at the shell. (b) *Can Windows read it?*
On UEFI the table is in the XSDT and the question is whether the firmware-table interfaces of Windows return a table whose signature Windows has never heard of, to user mode in WinPE (the optional tool of
`run-rows.md` answers it) and, which is what the driver needs, to a boot-start driver before the OS has set up its own view of ACPI (**no run of this module can answer that: it is the Phase 3 driver's own test**).
Also unverified: that Windows tolerates the OEM ID and OEM table ID that iPXE forces onto the table (`FENSYS` / `iPXE`), and that no one reserves the signature.
On **BIOS the table is not in an RSDT** (design section 7), so `GetSystemFirmwareTable` cannot return it by design and (b) does not apply: a driver would scan the resident `xbftab` area itself, and whether
that area is where a Windows driver can reach it (and whether the memory is intact after bootmgr and `winload`) is also open.

**U4. Host-side limits of the evidence.** The WinPE stages are read from screenshots (S2, S3) and a pixel probe (S4), not from a log, because the owner's images cannot print on the serial port in QEMU
(section 4). A bootmgr screen that is neither an error nor the logo can be misjudged; every row files its screenshots with it for that reason.

## 4. Observations that changed the plan

* **The serial marker `WINRBD-WINPE-OK` is never printed by the owner's images in QEMU.** Their `startnet.cmd` writes it to `COM1`; in the guest Windows PE has the serial device (ACPI `PNP0501` is enumerated) but
  creates no `COM1` (`SERIALCOMM` is empty; `drvload msports.inf` answers `0x80070103`), so `echo ... > COM1` prints `The system cannot find the file specified.` This was seen on the owner's two VHDs and on the images
  built from the ISO, on both firmwares. Consequence: the rows cannot use `--expect os`; they run with `--expect none --stay` and the shell is recognised by screen (`run-rows.md`). A marker channel that works
  in WinPE is the owner's to choose (a network call to a listener, for example); the scripts do not depend on one.
* **Sector 12 of the NT 6 boot record** (section 2). It is the kind of defect the layout check exists for: the machine says `Booting from Hard Disk...` and does nothing.
* **Memory.** W0 ran with 2 GiB of guest RAM; the RAM disk the boot manager makes is the size of `boot.wim`.

## 5. Open issues

1. **The real `ms-sys` has not run.** It is not in Ubuntu 26.04 and nothing was downloaded; `import-winpe.sh` writes the boot code through a scratch copy of the first 16 sectors of the partition (so that
   sectors 0, 2, 6 to 8 and 12 are all covered) and the check that follows (`mbr-code`, `boot-sector`, `boot-sector-2`, `hidden-sectors`) fails loudly if it did not work. Tested with a stand-in and with boot code
   copied from the owner's image; **one run with the real tool, or with `bootsect /nt60` on Windows, is still to be done** by whoever has it.
2. W1 to W4 not run (above). Each needs: the lab cluster free (the Phase 1 exit run was still using it), the iPXE binaries with the driver working, the image imported
   (`import-winpe.sh import`) and W0 passed for it.
3. `ipxe-driver.md` sections 14.3 and 15 still say the WinPE rows are blocked on the owner's image; the images now exist, and those sections should say "prepared, images supplied, rows not yet run". That file is
   not owned by this module and was not changed.
4. `check-layout.sh` cannot verify the GPT CRCs of a fixed VHD in place (the footer moves the end of the disk); it warns. `import-winpe.sh convert` strips the footer and then the check is complete.
5. The probe's colours are those of the default WinPE theme (`#1273AA`); an image with another wallpaper needs `WINPE_BLUE` changed in the tool.

## 6. Close-out (Phase 2, 2026-11-24): the rows have run

W1 to W4 were run by the Phase 2 matrix on the **owner's current WinPE images** (built with the Windows ADK, kept outside the repository, rolled back to a snapshot before each run), on the final binaries, against the dedicated lab cluster. Evidence: `harness/lab/p2/results/final/` (`MATRIX.md`, `rows/runs-winpe-*`, `rows/rows-W1-*`), figures in `ipxe-driver-measurements.md`, summary in `ipxe-driver.md` section 18.3.

| Row | Firmware, delivery | Runs | Reached `WINRBD-WINPE-OK` on COM1 at |
|---|---|---|---|
| W1 | OVMF, PXE (`devpath=vendor`) | 2 | 61 s, 63 s; `uri` 70 s, `sata` 95 s (one run each) |
| W2 | OVMF, USB stick image | 2 | 77 s, 86 s |
| W3 | SeaBIOS, PXE (32-bit images) | 2 | 63 s, 81 s |
| W4 | SeaBIOS, USB stick image | 2 | 74 s, 84 s |

What this establishes is what section 1 said it would: the boot manager read `boot.wim` and the other boot files through the SAN device on that firmware, and WinPE started (`startnet.cmd` ran `wpeinit` and then wrote the marker). It does **not** show what Windows does with the disk afterwards (WinPE has no `rbd` driver: Phase 3).

How the open questions stand:

* **U1** (the device path): the default `vendor` node, and also `uri` and `sata`, let the stock boot manager load `boot.wim` on the owner's current images. The first matrix's `sata` row stuck on the earlier images; which of the two things that changed (the images, or nothing in the driver: the node builder did not change) made the difference is not shown. `winload` for an **installed** Windows system, as opposed to WinPE's RAM disk, is still **unverified**.
* **U2** (BIOS through INT 13h without `edd_describe`): the owner's MBR image boots from PXE and from a USB stick image, so the boot manager does not need the path information. The `winload`-matches-the-drive question for an installed system is still open (Phase 3).
* **U3** (the `rBFT` table): WinPE boots with iPXE's forced OEM fields on both firmwares; that a boot-start driver can read an unknown signature early, and that nobody reserves it, are still **unverified**.
* **U4**: the matrix judges these rows by the serial marker, not by screenshots (the owner's current images print it; the images of section 4 did not). The first matrix's screenshot judge passed `sata` and `uri` too.

Open issues 1, 4 and 5 of section 5 stand; 2 and 3 are done (the rows ran, and `ipxe-driver.md` sections 14.3 and 15 now say so).
