<!-- SPDX-License-Identifier: MIT -->
# Linux guest images for the Phase 2 live matrix

The live test matrix of the iPXE driver (`docs/design/ipxe-driver.md`, section 14.3) boots a Linux guest whose **disk is an RBD image
that the firmware reads through the driver's SAN device**. This directory makes those guests, puts them into the lab cluster, and
holds the guest-side proof that the handoff table (`docs/design/handoff-table.md`) is the one the design describes.

An image that boots to the marker below proved, step by step: firmware read the ESP / MBR, grub, the kernel and the initramfs through
our SAN device; the table is visible to the guest and **every one of its fields matches the expected values**; the NIC came up from the
table alone; the kernel client mapped the image from the table; the root file system is on `/dev/rbd<N>p<P>`, so the OS continues
after iPXE is gone.

| File | Purpose |
|---|---|
| `build-uefi.sh` | `linux-uefi.raw`: 2 GiB, GPT, p1 128 MiB FAT32 ESP (`EFI/BOOT/BOOTX64.EFI`, grub, the removable path), p2 ext4 root. The Linux guest of the UEFI rows (U0 to U3) |
| `build-bios.sh` | `linux-bios.raw`: 2 GiB, MBR, one ext4 partition, grub-pc in the MBR gap (the BIOS rows B1 to B3). With `--tiny`: `b0-tiny.raw`, 96 MiB, a disk whose whole system is an initramfs (row B0, no cluster needed) |
| `import.sh` | raw image into a lab RBD image (`rbd import` through the lab VM), throwaway cephx user, integrity check with krbd, expected values into an image, delete |
| `expected-table.sh` | the expected values of a test configuration as `rbft.*` words, and the matching hand-built rBFT table (also with deliberate differences and defects) |
| `boot-test.sh` | boots the images in plain QEMU from their own disks (no iPXE) and checks what the guest prints: good table, wrong field, bad checksum, no table, BIOS scan, row B0's disk, and (in the lab VM) the real krbd mapping |
| `selftest.sh` | the offline test (ctest `images.selftest`): the checker, the hook, the marker, the scripts. No VM, no root, no cluster |
| `initramfs/rbft-check/rbft-check.c` | the table checker (static C, no library): one PASS / FAIL / SKIP line per field |
| `initramfs/scripts/local-top/rbft` | the boot hook (initramfs-tools): find the table, check it, bring the NIC up, map the image |
| `initramfs/hooks/rbft`, `initramfs/modules` | what goes into the initramfs (checker, `ip`, the kernel modules of the client, NICs, disks, crypto) |
| `initramfs/system/wrboot-marker{,.service}` | prints the marker lines on the serial console in the booted system |
| `initramfs/tiny/init` | init of the initramfs-only disk of row B0 |
| `initramfs/lib/image-common.sh` | what the two build scripts share (the base system, loop devices, the guest files) |

Nothing here is committed that is an image: `.gitignore` has `*.raw`, `*.img`, `*.qcow2` and `out/`, and the build scripts refuse an
output path inside a git work tree that git would not ignore. No image holds a key, a real address or a password (root is locked; the
console shows a login prompt, the marker is the evidence).

## What is in an image

Ubuntu 24.04 (`noble`, minbase, kernel 6.8: the same family as the lab VM, whose krbd is the oracle of the project) with `systemd`,
`iproute2`, `initramfs-tools`, `busybox-static` and nothing else. The root is mounted **read-only** (`tmpfs` for `/tmp`, `/var/tmp`,
`/var/log`, `/var/cache`), so booting never changes the RBD image. grub is the host's, installed with `grub-install`
(`--target=x86_64-efi --removable`, or `i386-pc`), with a static `grub.cfg` (no disk probing): the first entry is the matrix entry
(`rbft.hook=1`), the second boots the local root only. Kernel command line:
`root=LABEL=wrbroot ro console=tty0 console=ttyS0,115200n8 net.ifnames=0 biosdevname=0 iomem=relaxed edd=on noresume loglevel=4 rbft.hook=1 rbft.rootpart=N $rbft_extra`
(`iomem=relaxed` lets the BIOS scan read RAM below 1 MiB through `/dev/mem`; `edd=on` makes the kernel keep the BIOS drive information, which
Ubuntu's kernel otherwise drops). The BIOS images use grub's `linux16` / `initrd16`: the plain `linux` command of grub-pc enters the kernel
in protected mode and skips the real-mode setup code that collects that information (`/sys/firmware/edd`, which row B0 reads).

The initramfs is made with `MODULES=list`, compressed with zstd: 10 MiB, next to a 15 MiB kernel (what the firmware reads through the SAN
device is those two and grub, about 27 MiB; everything after that is read by the guest's own kernel client).
`build-*.sh` checks the finished initramfs: the checker, `ip`, the hook and every module of `initramfs/modules` marked `required`
(`libceph rbd libcrc32c cbc aes_generic hmac virtio_net virtio_pci virtio_blk`; a module that Ubuntu builds into the kernel counts) must be
there, or the build fails.

## Build (in the builder guest)

The scripts need root, loop devices, `debootstrap`, `sgdisk` / `sfdisk`, `mkfs.ext4`, `mkfs.vfat`, `grub-install` for `x86_64-efi` and
`i386-pc`, `cpio`, and `gcc` with static glibc: the Ubuntu 26.04 guest of `harness/lab/p2/builder` has all of them (`up.sh` checks).
They re-run themselves with `sudo`. Nothing is built on a workstation.

```sh
# on the build machine (BUILDER_DIR as in harness/lab/p2/builder/README.md)
up.sh put harness/lab/p2/images work/images           # or rsync the repository's harness/lab/p2/images and harness/vectors/handoff
up.sh ssh 'cd work/images && IMG_MIRROR=http://mirror.example/ubuntu ./build-uefi.sh'    # ~4 min after the base is cached
up.sh ssh 'cd work/images && ./build-bios.sh && ./build-bios.sh --tiny'
up.sh get /var/tmp/winrbd-p2-images/out/ ./images-out/   # linux-uefi.raw linux-bios.raw b0-tiny.raw and their .manifest
```

`IMG_WORK` (default `/var/tmp/winrbd-p2-images`) holds `cache/` (the base system as a tar, made once: debootstrap and about 100 MB of
packages, 6 to 8 minutes on a good mirror), `out/` and `tmp/`. `IMG_MIRROR` is the Ubuntu archive (default `archive.ubuntu.com`; a nearby
mirror matters a lot on a slow link). Nothing in a script removes a directory tree: the system is built inside an ext4 image file that is
deleted as a file; mount points are empty directories made by `mktemp` and removed with `rmdir`. Every mount and loop device is undone
at exit, also on failure and on Ctrl-C.
`-n` prints the plan and checks the options and the tools; `--force` replaces an existing image; `--size` (1024 to 2048 MiB).

The kernel's `qemu_fw_cfg` driver is in the `linux-modules-extra` package, which the minimal image does not install. The base build
takes that one file out of the package (`apt-get download`, `dpkg-deb --fsys-tarfile | tar -x`, `depmod`) so that the hook can read the
QEMU file channel. `edd` (BIOS drive information) and `devmem` are built into the Ubuntu kernel.

A `.manifest` next to each image lists (not secret) the kernel, the label, the UUID, the SHA-256 of the kernel, initramfs, `grub.cfg`,
checker and marker inside the root, and the SHA-256 of the whole image. `import.sh check` compares an imported image with it. (`import.sh expect` changes the image, so it also rewrites the `image_sha256` line of
the manifest next to it; the manifest stays the digest of the file it sits beside.)

## The boot hook

`initramfs/scripts/local-top/rbft` runs before the root is mounted. It does nothing unless the kernel command line has `rbft.hook=1`.

1. **Find the table.** UEFI: `/sys/firmware/acpi/tables/rBFT` (the table is in the firmware's tables). BIOS: iPXE keeps its tables in its
   resident area, not in an RSDT, so `rbft-check --scan` reads physical memory 0 to 1 MiB through `/dev/mem` for the signature `rBFT` at
   a 16-byte boundary with a **valid length and checksum**; a bare signature or a bad checksum is ignored (and named); two different
   valid tables are an error; the same table twice is one table. With `rbft.src=auto` (default) BIOS tries the scan and then sysfs (QEMU's
   `-acpitable` puts a table into the RSDT; iPXE never does), UEFI uses sysfs. `rbft.src=scan|sysfs|fwcfg` forces one. `fwcfg` is a
   **test source**: the whole table from the QEMU file `opt/winrbd/table`, which lets a bad checksum through (QEMU repairs it in
   `-acpitable`). The checker works on a private copy of the bytes, never on live firmware memory.
2. **Check every field** against the expected values and print one line each, `RBFT PASS|FAIL|SKIP|INFO <field>: <detail>`, then
   `RBFT-RESULT PASS|FAIL pass=N fail=N skip=N`. Always checked (no expectation needed): signature, length, ACPI revision, checksum,
   body magic, version, header length, reserved bytes, flag bits, the canonical layout of the variable area (no gaps, no padding, nothing
   after the key), the namespace (absent in version 1) and every rule of the field table. Checked against the expected values: entity,
   pool, image, image id, snapshot, auth, message mode, flags (and each flag bit on its own line), key type and length, every monitor,
   fsid, MAC, VLAN, MTU, address family, address, prefix, gateway, DNS. The OEM and creator fields are **not** interpreted (iPXE writes its
   own): they are printed as INFO. The key is never printed (type and length only; `--hexdump` shows the table with the key bytes as `..`).
   A field without an expected value is `SKIP` (`rbft.strict=1`: `FAIL`), so a configuration cannot pass by leaving things out: the
   self-test configurations have no SKIP at all. The hook prints `WRBOOT-TABLE PASS|FAIL|UNUSABLE|NONE`.
3. **NIC from the table**: wait (`rbft.waitnic`, 20 s) for the interface with the table's MAC (`/sys/class/net`), MTU, VLAN device,
   address and prefix, default route.
4. **Map the image** with the kernel client: the string
   `<mon,mon> name=<entity>,secret=<key>,ms_mode=<mode>,noshare[,read_only] <pool> <image> [<snapshot>]` goes into
   `/sys/bus/rbd/add_single_major` (the module's default mode, the one that gives the device its partitions; the plain `add` answers
   EINVAL to everything then, which the first live run found; a kernel without `single_major` has only `add`, which the hook then uses)
   (monitors from the table, `crc` -> `ms_mode=crc`, `crc-first` -> `prefer-crc`, `secure-first` -> `prefer-secure`, `secure` -> `secure`,
   the read-only flag -> `read_only`); then it waits for `/dev/rbd<N>p<rbft.rootpart>` and writes `ROOT=` for the initramfs, so the
   normal `local` script mounts it. A table that fails its check (`FAIL` or `UNUSABLE`) is **not** mapped from.

**The key** comes from the table when the loader put it there (`handoff=key`, key type `aes`); otherwise from the kernel command line
(`rbft.key=<armoured base64>`, which is visible in the guest and in boot logs: lab use only) or, better, from the QEMU file
`opt/winrbd/key` (`-fw_cfg name=opt/winrbd/key,file=KEYFILE`; the key never touches the command line or the image). If both the table and
another channel give one, they must be equal (`RBFT PASS|FAIL key_value`). The kernel client cannot use the 32-byte `aes256k` keys
(`libceph: secret too big 32`): a table with such a key and no legacy key supplied stops with a clear message. The key is kept in a shell
variable only, handed to the kernel with a shell builtin (never in an argument list), and every file that held it is removed after the mapping.

**Options** (kernel command line, or one word per line in the QEMU file `opt/winrbd/params`; the command line wins; only the command
line can switch the hook on): `rbft.map=1|0` (0: check and bring the NIC up, but keep `root=` as given: a plain-QEMU run),
`rbft.src`, `rbft.rootpart` (UEFI image: 2, BIOS: 1), `rbft.require=1` (no table, an unusable table or a failed mapping is fatal and
powers the guest off; the default is to go on with `root=`), `rbft.onfail=continue|poweroff`, `rbft.waitnic`, `rbft.waitmap`,
`rbft.strict=1`, `rbft.poweroff=1` (the booted system powers off after the marker) and the expected values `rbft.mons rbft.entity rbft.pool
rbft.image rbft.imageid rbft.snap rbft.auth rbft.mode rbft.flags rbft.keytype rbft.keylen rbft.fsid rbft.mac rbft.vlan rbft.mtu rbft.ip
rbft.gw rbft.dns`. `expected-table.sh params|fwcfg [OPTIONS]` writes exactly these for a configuration (defaults: the dedicated lab, mon
`10.77.0.10:3300`, user `winrbd-aes`, pool `winrbd`, image `wrtest-p2-lin-uefi`, NIC `52:54:00:77:12:20` with `10.77.0.20/24`).

## The marker

The hook leaves its verdict for the booted system in `/run/rbft/result` as plain `KEY=VALUE` lines; the marker **reads** them (it never
sources the file, and the image name in it is limited to `A-Za-z0-9._+:-`), because one of the values comes out of the table, and a table is not trusted
with a shell. `rbft-check` hands names to the hook only if they are made of `A-Za-z0-9._+:-` (a table with a `;` in its image name is `UNUSABLE`).

The booted system's `wrboot-marker.service` prints on the serial console (and only one of the `WRBOOT-ROOT-*` lines):

```
WRBOOT-ROOT-OK fw=uefi root=/dev/rbd0p2 fstype=ext4 mapped=rbd0 table=PASS src=sysfs image=wrtest-p2-lin-uefi kernel=6.8.0-151-generic
WRBOOT-ROOT-TABLE-FAIL ...   the table did not match, or is unusable          (never together with -OK)
WRBOOT-ROOT-WRONG ...        the image was mapped but / is somewhere else
WRBOOT-ROOT-NOT-RBD ...      rbft.require=1 and the root is not on a mapped image
```

with `WRBOOT-NET <nic> mac=... <addresses>` and, on BIOS, `WRBOOT-EDD int13_dev80 ...` (the BIOS drives the kernel was told about) before
it. The qemu-scripts' default OS marker is `WRBOOT-ROOT-OK` (`--ok-marker`), so `--expect os` waits for exactly this line. The hook's own lines
are `RBFT-HOOK ...`, `WRBOOT-HOOK-DONE root=... table=...` and, when it gives up, `WRBOOT-HOOK-POWEROFF: <reason>`.
The table is also written to the log as an acpidump-style record, `RBFT DUMP <offset>: <16 bytes>`, key bytes masked.

## Plain QEMU, no iPXE: `boot-test.sh`

```sh
boot-test.sh [--uefi F] [--bios F] [--tiny F] all          # on a machine with qemu-system-x86_64 (KVM or TCG), OVMF
boot-test.sh uefi-good uefi-field bios-scan tiny-good
```

The images are opened with `snapshot=on` (never modified), user-mode networking only, `nice -n 19`. The table and the expected values
reach the guest as a loader would leave them: `-acpitable sig=rBFT,rev=1,data=<body>` (firmware tables), `-device loader,addr=0x9e000`
(low memory: the BIOS scan), or the fw_cfg test source; the expectations in `-fw_cfg name=opt/winrbd/params,file=...`. The cases and
what each must show are listed in the header of the script.

A table that QEMU puts into low memory is not protected the way iPXE's is (iPXE hides its resident area from the kernel with the INT 15h
memory map and the BIOS memory size): grub (pc) and the kernel overwrite or zero it. The scan cases (`bios-scan`, `bios-field`,
`bios-badsum`, `tiny-good`, `tiny-field`) therefore boot the image's **kernel and initramfs directly** (`-kernel`, `-initrd`, read out of the image
with `debugfs`) with the image's own command line plus `memmap=4K$0x9e000`, which reserves that page in the kernel's memory map the way iPXE's
hook does. The cases that boot through grub (`uefi-*`, `bios-good`, `tiny-boot`) use the firmware tables, or none. The end-to-end mapping cases
(`uefi-map`, `bios-map`) need a cluster the guest can reach: run as root in the lab VM they map the imported image there (read-only, with
the user's own key) as the guest's boot disk, give the key to the guest as an fw_cfg file, and boot with a table that names the lab's
monitor; the guest's kernel client then maps the same image and mounts the root from it:

```sh
sudo ./boot-test.sh uefi-map --map-image wrtest-p2-lin-uefi      # in the lab VM, after import.sh import / user-create
sudo ./boot-test.sh bios-map --map-image wrtest-p2-lin-bios
```

## Using the images in the matrix

```sh
# the raw image into the lab (the lab VM is reached by P2_LAB_SSH, see import.sh -h)
import.sh user-create wrtest-p2-lin-uefi                     # throwaway cephx user, legacy aes key, caps limited to the pool
import.sh import --image linux-uefi.raw --name wrtest-p2-lin-uefi
import.sh check  --name wrtest-p2-lin-uefi --manifest linux-uefi.raw.manifest
# optional: bake the expected values into the image first (they become kernel command line words through grub)
import.sh expect --image linux-uefi.raw --opts "--mons 10.77.0.10:3300 --image wrtest-p2-lin-uefi"
# ... run the rows with harness/lab/p2/qemu (pass the expected values and, if the table has no key, the key file as fw_cfg files).
# params.txt = the expectations of the row, plus rbft.require=1 so that a failure ends the run at once with WRBOOT-HOOK-POWEROFF and the kernel's
# reason instead of waiting for a root device that will never come:
expected-table.sh fwcfg --image wrtest-p2-lin-uefi > params.txt; echo rbft.require=1 >> params.txt
#   run-uefi-pxe.sh ... --qemu-arg -fw_cfg --qemu-arg name=opt/winrbd/params,file=$(pwd)/params.txt \
#                       --qemu-arg -fw_cfg --qemu-arg name=opt/winrbd/key,file=/path/to/keyfile --expect os
import.sh delete wrtest-p2-lin-uefi                          # the image and the user
```

`import.sh import` writes format 2 with **only the `layering` feature** (the writer profile of the driver; krbd takes it too; the default
feature set is opened read-only by the driver). It streams the image through `zstd` and `ssh` into `rbd import`, compares the size, and
`check` proves the import: the SHA-256 of `rbd export` equals the image's, and with the user's own key krbd maps it, `e2fsck -fn` is
clean, the root partition mounts read-only, the files named in the manifest have their recorded SHA-256 and (UEFI) the ESP holds
`EFI/BOOT/BOOTX64.EFI`; everything is unmapped and unmounted at the end, also on failure. The last line is `CHECK-RESULT PASS` (exit 0),
`FAIL` (exit 1) or `PARTIAL` (exit 3: a part could not run, for example no user `client.NAME` for the krbd part, or no digest to compare with; a
partly checked image is not a pass). A transfer that fails removes the half image it made. Only names that start with `wrtest-` are created,
imported over or deleted; pools: `winrbd` or `wrtest-*`; an image of at most 2 GiB. The key of the throwaway user stays in the cluster:
`import.sh` never copies, prints or passes it in an argument list.

**Row B0** (`undionly.kpxe`, `sanhook --drive 0x81`, boot a small local disk): `build-bios.sh --tiny` makes the disk
(`--disk b0-tiny.raw` of the qemu scripts). It prints the BIOS drives (`WRBOOT-EDD int13_dev80`, `int13_dev81` for the hooked drive),
finds the table by the low-memory scan, checks every field, prints the marker (`root=initramfs`) and powers off. Its `grub.cfg` has
`rbft.src=scan rbft.map=0`.

**Rows with a WinPE image** are not made here; see `harness/lab/p2/winpe`.

## Tests

* `selftest.sh` (ctest `images.selftest`, offline): the checker is built with `$CC $CFLAGS` and `-Werror` and run on 13 configurations that
  must pass with **no skipped field** (several monitors, IPv6, VLAN/MTU/static, read-only, fsid, secure mode, image id and snapshot, no
  auth, no NIC, both key types, 255-byte names); on 20 single deliberate differences (each must fail exactly its own line); on 9 defects
  (bad checksum, length, signature, magic, version, revision, reserved byte, trailing bytes, truncation) and iPXE's OEM fields (must
  pass); on every one-bit change of the table and on every truncation length (never a crash, never silently green); the memory scan at
  every position class, across the 64 KiB chunk edge, with decoys, ambiguity, ranges and an offset base; the key never in any output or
  dump, the secret for the kernel client (type, bytes, mode 0600), unsafe names (no environment file). The real boot hook runs in a
  sandbox (`RBFT_ROOT`) with stand-ins for `ip`, `modprobe` and the kernel's rbd interface, under `sh` and `dash`: the NIC commands, the
  exact string handed to the kernel client, key from fw_cfg and from the table, every refusal, a wrong field, a bad checksum, no table,
  `rbft.require`, a partition that does not appear, no NIC; the marker for every verdict. The build scripts' options, plans, refusals
  and the git-ignore check; `import.sh` name and pool validation and dry runs; `import.sh expect` on a made-up disk (needs `debugfs`),
  including the manifest digest it must keep right. Review round: a name with a line break cannot forge an `RBFT-RESULT` line, names with
  shell metacharacters give no environment file and an `UNUSABLE` table in the hook, a command-looking value in the result file is printed
  and never run by the marker, an oversized or empty expectation is refused, a stale environment file is removed; `import.sh` against a
  stand-in lab (a fake `ssh`/`sudo`/`rbd`/`ceph`: a failed transfer leaves no image, `check` is `PASS` / `FAIL` / `PARTIAL` with the exit
  status to match); `expected-table.sh` refuses a defect on a body, two defects and non-numbers with a message. Each of these was run
  against the code before the fix and failed there.
  Shell scripts parse with `sh`, `dash` and `bash` and are `shellcheck`-clean.
* `boot-test.sh` on a KVM machine: the real images, in QEMU, from their own disks: the 11 plain cases (38 checks) on any machine with QEMU and
  OVMF; the mapping cases (`uefi-map`, `bios-map` and their `-badkey` and `-noimage` variants) in the lab VM.
* `import.sh check` in the lab: the SHA-256 of `rbd export` equals the image's, krbd maps it with the user's own key, `e2fsck -fn` is clean,
  the files of the manifest are intact. A wrong digest makes `check` fail (the negative control).
* Found only by the live run, and now covered: the plain `/sys/bus/rbd/add` is refused with EINVAL by a kernel that has the default
  `single_major=Y` (the hook uses `add_single_major`); `ssh` reading the image from the shared standard input in `import.sh` (the helper
  calls now have `< /dev/null`; an import whose stream was damaged left an empty image, which `import.sh` now removes and reports).

## Limits

* The images are made from Ubuntu packages fetched during the build (`debootstrap`, signed by the Ubuntu archive key); the base is cached
  by release and package list, not pinned to a snapshot: two builds a month apart have different kernels. The manifest records which.
* Booting through the iPXE SAN device (rows U0 to B3) is exercised by the qemu scripts, not here; what this directory proves without
  iPXE is the guest side: the images boot, the checker and the hook behave, the import is intact and krbd reads the imported file system.
* The BIOS scan is proven on a table placed in low memory by QEMU; where iPXE's resident area really lies (and that the kernel's memory
  map leaves it readable through `/dev/mem`) is shown by row B0 and B1.
* The kernel client needs the legacy `aes` key; the hook says so for an `aes256k` key instead of failing in the kernel.
* The tiny disk's initramfs has no network driver: it cannot map anything, by design.
