# ipxe/

The iPXE `rbd://` SAN driver: opens an RBD image with `core/`, exposes it through iPXE's SAN layer (`EFI_BLOCK_IO` on UEFI, INT 13h on BIOS) and publishes the `rBFT` handoff ACPI table. Built **out of tree** against the iPXE revision pinned in `PINNED` (`third_party/ipxe`): nothing inside `third_party/ipxe` is ever modified.

Licence: the glue files in `src/` are GPL-2.0-or-later or UBDL (`FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )`), like iPXE's own SAN code; the patches are derived from iPXE files and carry the same licence; `tools/build.sh` is MIT. The MIT core is linked in unchanged (tagged `MIT` by the import, see below). **A binary that contains the driver is GPL-2.0-or-later only, not UBDL**: the core links the CRUSH log tables (`core/crush_ln/`, LGPL-2.1-only, tagged `GPL2_OR_LATER` for iPXE), and iPXE's own licence check (`make bin/<target>.licence`, run by `build.sh licence` and by CI) reports "GPL version 2 (or, at your option, any later version)" for every build of it. Every file is `FILE_SECBOOT ( FORBIDDEN )`: this driver is not part of UEFI Secure Boot signed builds, by design (`docs/design/ipxe-driver.md`, section 13).

## Status

**Phase 2: working in QEMU, against a real Ceph v20.2.5.** `sanboot rbd://...` boots a Linux image and the owner's WinPE image under OVMF (UEFI) and SeaBIOS (legacy BIOS, INT 13h), from PXE, from an iPXE USB stick image and from an iPXE CD, and the `rBFT` handoff table is visible in the guest and matches the design field by field. The evidence is `harness/lab/p2/results/`; the state per milestone is in `docs/ROADMAP.md`, the design and its notes in `docs/design/ipxe-driver.md`, the figures in `docs/design/ipxe-driver-measurements.md`. What has **not** been shown: a boot on real hardware, Windows' own view of the table (WinPE has no `rbd` driver in this phase), UEFI Secure Boot (refused by design), snapshots, and any network that loses packets for longer than the driver's 30 s watchdog tolerates.

| Piece | File | State |
|---|---|---|
| URI opener, settings (`rbd-key`, `rbd-user`), URI to spec | `src/rbd_uri.c` | done, unit tests |
| the shared cluster session: memory plan, core, image, the process that runs the core, reopen with cached maps | `src/rbd_session.c` | done |
| the pump host: connection table over iPXE TCP sockets, time, random | `src/rbd_conn.c` | done |
| the block device: read, write, capacity, commands, synchronous cancel, readahead hook | `src/rbd_block.c` | done |
| EFI device path (`vendor` default, `sata`, `uri`) | `src/rbd_efi.c` | done |
| the `rBFT` table as an `acpi_model` | `src/rbd_acpi.c` | done |
| BIOS: table scan, `rbd-xbft` command, exit warning for UNDI | `src/rbd_bios.c` | done |
| status mapping and console lines | `src/rbd_errors.c` | done |
| diagnostics: stack watermark, `rbd-info`, counters (test builds) | `src/rbd_stack.c` | done |
| patches to iPXE (hooks, error file ids, self-tests, BIOS table room) | `patches/0001` to `0004` | done |
| build and import script, licence and Secure Boot checks | `tools/build.sh` | done |
| self-tests that need no network (`ipxe/tests/`) | `tests/` | done: 72,520 tests of the driver in the 64-bit program (84,968 in iPXE's test program with its own 12,448; the 32-bit program runs 85,043), plain and with UBSan in trap mode |

## Layout

```
ipxe/
  PINNED                 iPXE revision the driver is built against (the build script refuses another)
  patches/               the whole change to iPXE's own files, applied in name order with patch -p1
  src/                   glue files: rbd_uri.c rbd_session.c rbd_conn.c rbd_block.c rbd_efi.c rbd_acpi.c rbd_bios.c rbd_errors.c rbd_stack.c and their headers, rbd_priv.h, rbd_core_cfg.h
  tests/                 iPXE self-tests of the glue (no network, no QEMU), wired in by patch 0003
  tools/build.sh         prepare | build | licence | verify | secboot | test | check | clean
```

## Building

Needs the iPXE build dependencies (gcc, make, perl, `liblzma-dev`; for `bin/ipxe.iso` also `mtools`, `xorriso`, `syslinux`/`isolinux`) and, on a 64-bit host, a compiler that can also produce 32-bit code (`gcc-multilib`) for the 32-bit BIOS targets.

```sh
git submodule update --init third_party/ipxe

# UEFI, and the 64-bit BIOS images ("bin/" is iPXE's DEFAULT_ARCH, x86_64)
ipxe/tools/build.sh build bin-x86_64-efi/ipxe.efi bin/undionly.kpxe bin/ipxe.pxe bin/ipxe.usb bin/ipxe.iso
# the 32-bit BIOS images (4 KiB stack, the core on a private 16 KiB stack): what most BIOS machines run
ipxe/tools/build.sh build bin-i386-pcbios/undionly.kpxe bin-i386-pcbios/ipxe.pxe bin-i386-pcbios/ipxe.usb bin-i386-pcbios/ipxe.iso

ipxe/tools/build.sh licence bin-x86_64-efi/snponly.efi bin/undionly.kpxe bin-i386-pcbios/undionly.kpxe  # iPXE's licence check on a real build
ipxe/tools/build.sh verify bin-x86_64-efi/ipxe.efi bin/undionly.kpxe          # the driver is linked in, no self-test is
ipxe/tools/build.sh secboot -j 8                                              # a Secure Boot build must be REFUSED; every driver object is FORBIDDEN
ipxe/tools/build.sh test ; ipxe/tools/build.sh test bin-i386-linux/tests.linux ; ipxe/tools/build.sh test -u    # the self-tests (tests/README.md)
ipxe/tools/build.sh build -e boot.ipxe bin-x86_64-efi/ipxe.efi                # with an embedded script (EMBED=)
```

A BIOS build for a serial console (the QEMU run scripts read the serial line) takes `-- EXTRA_CFLAGS=-DCONSOLE_SERIAL`; `-DRBD_STACK_MONITOR` adds the stack watermark on BIOS and a counters line with a heap probe every 5 s on every platform (for test builds, off in a release).

Everything goes to `build/ipxe/` (git-ignored); the result is `build/ipxe/src/<target>`. `build.sh prepare`:

1. exports the pinned tree with `git archive` (committed files only; a different revision stops the script);
2. applies `patches/*.patch`: `src/Makefile` (source directory `winrbd`), `config/general.h` (`SANBOOT_PROTO_RBD`), `config/config.c` (`REQUIRE_OBJECT ( rbd_uri )`, and `rbd_bios` on BIOS), `errfile.h` (error file ids), `tests.c` (the self-tests), and `int13.c` / `int13.h` (room for the handoff table in the BIOS boot firmware table area: 2,048 bytes instead of 768);
3. imports `src/*` and the core **flat** into `src/winrbd/` of the copy (`rbd_core_cfg.h` supplies what iPXE's `<stdint.h>` lacks and maps the core's memory primitives to iPXE's; one line in the imported `wr_port.h` selects it). The core is tagged for iPXE's textual licence check by a mechanical transform: the placeholder line `WR_FILE_LICENCE_MIT` of each `.c` file becomes `FILE_LICENCE ( MIT );` (`GPL2_OR_LATER` for `core/crush_ln/`) plus `FILE_SECBOOT ( FORBIDDEN );`, and every header and include file gets the same lines. The core in the repository stays free of iPXE macros.

`IPXE_HOST_LZMA_PREFIX` points the build at an `include/lzma.h` and `lib/liblzma.so` on a host without `liblzma-dev`; `IPXE_NICE` prefixes `make` (for example `nice -n 19`); `IPXE_JOBS` sets `-j`.

The licence check passes on `bin/undionly.kpxe`, `bin-i386-pcbios/undionly.kpxe` and `bin-x86_64-efi/snponly.efi` (the images with every NIC driver fail it on the pristine iPXE tree) and reports GPL-2.0-or-later. A Secure Boot build (`bin-x86_64-efi-sb/...`) is refused by design.

iPXE's own warning set and `-Werror` apply to the glue **and** the core inside the build. The harness builds the core with the same flags (`wr_core_ipxe_flags`, `wr_core_m32`), so a warning that would break the iPXE build is seen in `ctest` first.

## Using it

```
set rbd-key AQ...==                                       # the cephx key (never in the URI: a URI with a password is refused)
sanboot rbd://wruser@10.77.0.10:3300,10.77.0.11/winrbd/win10?mode=crc&readahead=2048
```

`rbd://[user@]mon[:port][,mon[:port]...]/pool/image[?option=value[&...]]`; monitors are IP literals. Options: `mode` (`crc` default, `crc-first`, `secure-first`, `secure`), `ro`, `timeout`, `readahead` (KiB, 0 = off), `fsid`, `devpath` (`vendor` default, `sata`, `uri`), `handoff` (`nokey` default, `key`, `none`); a snapshot (`@snap`) is refused. Settings: `rbd-key`, `rbd-user`. Commands: `rbd-info` (counters, stack), `rbd-xbft` (BIOS: where the boot firmware tables are). The full table and the reasons are in `docs/design/ipxe-driver.md`, section 8.

Running it in QEMU (what the live matrix does; the scripts are in `harness/lab/p2/`, each directory has its README): `builder/build-ipxe.sh` builds the targets in an Ubuntu 26.04 guest and runs the gates of CI, `cluster/up.sh` starts a dedicated single-host Ceph v20.2.5 lab VM (the guests join its private layer 2: monitor `10.77.0.10:3300`), `cluster/users.sh` makes a throwaway cephx user and a test image per row, and `qemu/run-uefi-pxe.sh` (and `run-uefi-usb.sh`, `run-uefi-iso.sh`, `run-bios-pxe.sh`, `run-bios-usb.sh`, `run-bios-iso.sh`) boot one guest per run, for example `qemu/run-uefi-pxe.sh --pool winrbd --image uefi-gpt --user wrp2 --key-file ~/wrp2.key --action sanboot --expect os --timeout 600` (`-n` prints what would run and starts nothing; the key is read from a mode-600 file and is never printed). `images/` builds the Linux guest images whose initramfs checks the `rBFT` table field by field. Windows images are not part of the repository: the WinPE rows need an image from the owner (`harness/lab/p2/winpe/README.md`).

A boot script or boot medium that carries the key holds a credential: keep it private, use one cephx user per image, and revoke a lost one with `ceph auth rm`. Where this is run: **QEMU only so far** (`harness/lab/p2/`: a dedicated Ceph lab VM, the run scripts, the evidence).

Things worth knowing before you use it:

- `bin/` builds 64-bit BIOS images; the 32-bit ones are `bin-i386-pcbios/`.
- `undionly.kpxe` drives only the NIC the PXE ROM booted from, and `sanhook` followed by `exit` leaves the drive hooked over a network stack the PXE ROM then stops (reads stall for 30 s each): boot with `sanboot`, or use `ipxe.pxe` (native drivers). The driver prints a warning at that exit.
- A path that the cluster does not answer for 30 s is closed and the SAN layer reopens it; a wrong key is `Permission denied`, an unreachable monitor `Network is unreachable`, each with one console line (`rbd: ...`) that says why.
- The driver announces at most 64 KiB of TCP receive window per connection (`RBD_CONN_RX_WINDOW_MAX`, a build option): iPXE's TCP queues out-of-order data inside the window in its 4 MiB heap, and larger windows made the default readahead 3 to 4 times slower for large commands in the measurements (`docs/design/ipxe-driver.md`, section 18, R-1).
- Writes are slow on a long round trip (iPXE's TCP sends one packet per round trip); reads are not affected. Boots are read-dominated.

## Rules

- A new glue file goes in `src/`, starts with `rbd_`, has `SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL` in its first five lines (`LicenseRef-UBDL` is iPXE's Unmodified Binary Distribution Licence, `third_party/ipxe/COPYING.UBDL`), and has `FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );` and `FILE_SECBOOT ( FORBIDDEN );` on lines of their own (`build.sh check` enforces all three). A file may not share a basename with a core file.
- No protocol logic in the glue: everything about Ceph is in `core/`. The glue opens sockets, moves bytes, keeps timers, and answers iPXE's interfaces.
- Large objects go on the heap, not the stack: the BIOS build runs on a **4 KiB** stack.
- Never print a URI, a key or a payload on the console; one line with the core's reason is printed where an open fails.
- Do not commit changes inside `third_party/ipxe`; changes to iPXE's own files are patches.
- Keys come from the `rbd-key` setting, never from the URI (a URI with a password is refused).
- Nothing is copied from Linux's libceph / rbd or from Ceph; structure that follows iPXE's `iscsi.c`, `aoe.c` and `ata.c` is credited in the file that does.

---

iPXE 的 `rbd://` SAN 驱动:用 `core/` 打开 RBD 镜像,经 iPXE 的 SAN 层提供给固件(UEFI 的 `EFI_BLOCK_IO`、BIOS 的 INT 13h),并发布 `rBFT` 交接 ACPI 表。**树外构建**,针对 `PINNED` 固定的 iPXE 版本(`third_party/ipxe`);`third_party/ipxe` 内部从不修改。

许可:`src/` 里的粘合文件为 GPL-2.0-or-later 或 UBDL(`GPL2_OR_LATER_OR_UBDL`),与 iPXE 自己的 SAN 代码一致;补丁由 iPXE 文件派生,许可相同;`tools/build.sh` 为 MIT;MIT 的核心原样链接(构建时标成 `MIT`)。**含有本驱动的二进制只能按 GPL-2.0-or-later 发布,不能按 UBDL**:核心链接了 CRUSH 对数表(`core/crush_ln/`,LGPL-2.1-only,对 iPXE 标成 `GPL2_OR_LATER`),iPXE 自己的许可检查(`make bin/<目标>.licence`,由 `build.sh licence` 和 CI 运行)对每个含驱动的构建都报告"GPL version 2 (or, at your option, any later version)"。每个文件都是 `FILE_SECBOOT ( FORBIDDEN )`:本驱动按设计不进入 UEFI 安全启动签名的构建(`docs/design/ipxe-driver.md` 第 13 节)。

**状态:第 2 阶段,已能在 QEMU 里对真实的 Ceph v20.2.5 工作。** `sanboot rbd://...` 能在 OVMF(UEFI)和 SeaBIOS(传统 BIOS,INT 13h)下启动 Linux 镜像和业主提供的 WinPE 镜像,经 PXE、iPXE U 盘镜像和 iPXE 光盘三种方式;`rBFT` 交接表在客户机里可见,逐字段与设计一致。证据在 `harness/lab/p2/results/`,各里程碑的状态见 `docs/ROADMAP.md`,设计与说明见 `docs/design/ipxe-driver.md`,数字见 `docs/design/ipxe-driver-measurements.md`。**尚未证明**:真机启动、Windows 自己看到的交接表(本阶段的 WinPE 没有 `rbd` 驱动)、UEFI 安全启动(按设计拒绝)、快照,以及网络丢包超过驱动 30 秒看门狗容忍度的情形。

构建:`ipxe/tools/build.sh build bin-x86_64-efi/ipxe.efi bin/undionly.kpxe`(`bin/` 是 x86_64 的 64 位 BIOS 镜像,32 位 BIOS 镜像在 `bin-i386-pcbios/`);许可检查:`ipxe/tools/build.sh licence <目标>`;自检:`ipxe/tools/build.sh test`(64 位、32 位、带 UBSan);结果在 `build/ipxe/src/<目标>`。补丁共四个(钩子与错误文件号、自检、BIOS 引导固件表空间与 BIOS 对象),核心以机械转换导入(只加许可与安全启动标记行)。用法:`set rbd-key <密钥>` 后 `sanboot rbd://用户@mon[:端口][,mon...]/池/镜像[?选项]`,详见 `docs/design/ipxe-driver.md` 第 8 节。规则:新粘合文件放 `src/`、以 `rbd_` 开头、带两行标记;粘合层不写协议逻辑;大对象放堆不放栈(BIOS 栈只有 4 KiB);控制台绝不打印 URI、密钥或数据;密钥只从 `rbd-key` 设置取,不放进 URI;不复制 Linux 的 libceph / rbd 或 Ceph 的代码。注意:`undionly.kpxe` 只驱动 PXE 启动用的那块网卡,`sanhook` 之后 `exit` 会让已挂接的驱动器因 PXE ROM 关闭网络栈而每次读取停顿 30 秒,请用 `sanboot` 或原生驱动的 `ipxe.pxe`。
