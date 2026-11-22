# winrbd

[English](#en) | [中文](#zh)

---

<a name="en"></a>

## English

**winrbd** is an open research project to boot and run Windows directly from a Ceph RBD image, with no iSCSI and no gateway in between. The client speaks Ceph's native protocol end to end.

**Status: Phase 1 (the portable core and its Linux harness) works against a live Ceph v20.2.5 cluster; Windows cannot boot from it yet.** The core logs in over msgr2 (crc and secure mode, AES-GCM) with cephx, follows the OSDMap, maps objects with CRUSH and reads and writes RBD format-2 images, byte for byte identical to the Linux kernel client (krbd) in the lab. The iPXE driver (Phase 2) and the Windows driver (later phases) are not written yet, so there is nothing to deploy. If you like hard systems problems and want to help build it in spare time, read on.

### Why

Today the usual way to give a Windows machine a Ceph-backed disk is an iSCSI gateway. That works, but:

- **An extra hop.** Every I/O goes client -> gateway -> OSDs. The gateway is a bottleneck and a failure domain you have to size, HA and monitor.
- **A weak last hop.** Ceph's own messenger (msgr2) can encrypt and authenticate traffic to the OSDs, but the iSCSI leg between client and gateway is typically not encrypted (CHAP authenticates; it does not encrypt) unless you add something else on top.
- **Windows cannot copy the Linux trick.** A Linux diskless client can load a kernel plus initramfs, let user space or the kernel RBD client (krbd) map the image, then `switch_root`. As far as we know Windows has no such stage: on the UEFI path `bootmgr` and `winload` read the system disk through firmware services, and only later does a boot-start storage driver inside Windows take over (to be verified against Microsoft's documentation on the Windows boot process and boot-start drivers; see Phase 4 in the roadmap). So the disk has to be visible to firmware first, and the OS driver has to find the *same* disk afterwards.

The idea is to put a native RBD client in both places that need one: in the boot loader (iPXE) and in the Windows kernel.

### How it is meant to work

```
  NIC PXE ROM / UEFI network boot
              |
              v
  +-----------------------------+
  | iPXE  (UEFI build)          |
  |   rbd://mons/pool/image     |   new SAN driver, speaks Ceph natively:
  |   - mon + cephx + msgr2     |   mon, cephx, msgr2, osdmap, CRUSH,
  |   - osdmap + CRUSH          |   OSD object I/O, RBD format 2
  |   - OSD object I/O          |
  +--------------+--------------+
                 | EFI_BLOCK_IO protocol  (the image looks like a local disk)
                 | + ACPI handoff table   (like iBFT: NIC, mons, image, ...)
                 v
  +-----------------------------+
  | stock bootmgr / winload     |   reads \Windows and boot-start drivers
  | (unmodified UEFI firmware)  |   through firmware block I/O
  +--------------+--------------+
                 | ExitBootServices: iPXE and its network are gone
                 v
  +-----------------------------+
  | Windows kernel              |
  |  boot-start NIC + TCP/IP    |
  |  winrbd.sys (storport       |   reads the handoff table, opens the SAME
  |  miniport, in-kernel RBD    |   image over WSK, becomes the system disk
  |  client over WSK)           |
  +--------------+--------------+
                 | Ceph native protocol (msgr2)
                 v
          Ceph mons + OSDs
```

UEFI firmware is never modified. After `ExitBootServices` iPXE's block device and network stack stop working, so the Windows driver must bring up the same image on its own; the handoff table is how it learns what to open.

### Components

| Directory | What | License intent |
|---|---|---|
| `core/` | One portable C core, no platform dependencies: mon client, cephx, msgr2, OSDMap, CRUSH, OSD object I/O, RBD format-2 image. A thin shim supplies sockets, allocation, time and crypto. | MIT |
| `harness/` | Linux user-space host for the core. Lets us develop without BSODs and compare bytes against Linux krbd as the oracle. | MIT |
| `ipxe/` | The `rbd://` SAN driver for iPXE; exposes EFI_BLOCK_IO and publishes the handoff ACPI table. | GPL-2.0-or-later or UBDL, like iPXE's own SAN code |
| `windows/` | Boot-start storport miniport forked from WNBD's `wnbd.sys`, with an in-kernel RBD client over WSK. | LGPL-2.1-or-later for new files; LGPL-2.1-only for WNBD-derived files |

The same core is hosted three ways: in the Linux harness, in iPXE, and in the Windows kernel. That is the main design bet: the hard protocol code is written and debugged once, in the easy environment.

### Status

Phase 1 works in the Linux harness: msgr2 (crc and secure mode), cephx, OSDMap and CRUSH, OSD object I/O and RBD format-2 image I/O, compared byte for byte with krbd on a lab cluster; the long exit run of Phase 1 is still being reported (see the roadmap). Booting is not possible yet: the iPXE `rbd://` driver and the Windows driver are later phases. See [docs/ROADMAP.md](docs/ROADMAP.md) for the phased plan, the per-milestone state and the evidence and [docs/design/handoff-table.md](docs/design/handoff-table.md) for the draft handoff table.

What we have checked so far, against the pinned source trees:

- iPXE has a generic SAN layer and an EFI_BLOCK_IO backend, and a generic ACPI table mechanism (used by iBFT and AoE's aBFT). It has no `rbd` or `ceph` URI scheme today.
- WNBD's current `wnbd.sys` is a storport virtual miniport with no network code; every disk is created at run time by a user-space process. It does not boot a system volume today. An older in-kernel NBD client over WSK existed in WNBD's history (removed in commit `59da53f`) and is a useful reference for structure.
- Some Ceph wire-level details are in the public docs (for example the msgr2 frame preamble, CRC-32C parameters and the secure-mode nonce layout, on [docs.ceph.com/en/latest/dev/msgr2/](https://docs.ceph.com/en/latest/dev/msgr2/)). Many others are not: numeric tags, the full message header layout, secure-mode key derivation, cephx cipher / IV / digest details, OSDMap and CRUSH encodings, and the RBD header method names for size, features and snap context. Those have to be established from Ceph's source and a live cluster, and are tracked as open questions in the roadmap, not assumed.

### Verify the notes yourself

The protocol notes in [docs/spec/](docs/spec/README.md) are checked against real bytes: a public set of packet captures of a stock Ceph 20.2.5 client, made with two throwaway cephx users that were deleted from the lab cluster right afterwards (their keys are published and authenticate nothing). Eight independent checkers read that set. From a fresh clone, with only Python 3, the `cryptography` package and `curl`, run one command:

```sh
harness/tools/run-all.sh
```

It downloads the few Ceph files the checkers need at run time (from the pinned Ceph commit, sha256-checked, into a git-ignored directory; they are never part of this repository), runs all eight checkers and prints a pass / fail / skip table. See [harness/tools/README.md](harness/tools/README.md) and [harness/vectors/README.md](harness/vectors/README.md).

### Scope

- Test networks and research. This is not a product.
- Spare-time project, best effort, **no timelines promised**.
- UEFI only. Legacy BIOS boot is out of scope for now.
- First target is a narrow, simple image profile (no clones, default striping, object-map / fast-diff / journaling off); the exact list is in the roadmap.

### Signing policy

- Development uses Windows test-signing with Secure Boot off.
- This project ships **no production-signed binaries**. Anyone who wants to deploy beyond a test network must obtain Microsoft attestation signing for their own build themselves.

### Licensing intent

- Portable core and Linux harness: **MIT**, so the same code can be linked into iPXE (GPL-2.0-or-later or UBDL), into the LGPL Windows driver, and into anything else without licence conversion.
- Windows driver: LGPL-2.1-or-later for new files. Most WNBD files say "Licensed under LGPL-2.1 (see LICENSE)", which does not say "or later"; `wnbd.rc` says `LGPL-2.1-only`. We treat WNBD-derived files as LGPL-2.1-only unless the copyright holders confirm otherwise.
- iPXE driver: the glue files in `ipxe/` are GPL-2.0-or-later or UBDL (`GPL2_OR_LATER_OR_UBDL`), like iPXE's own SAN code. The MIT core can be tagged `MIT` inside an iPXE build, so the UBDL option is kept.
- Independent implementation: the core is written from Ceph's public protocol documentation, with Ceph's user-space source as a reading reference. Code from the Linux kernel's libceph / rbd.c (GPL) is **not** copied.

Details and open licensing questions: [LICENSE](LICENSE).

### How to contribute

We would like people to join. Useful ways to help right now:

- **Open an issue** with questions, corrections or review of the plan. Design discussion is welcome, especially challenges to the architecture.
- **Wanted expertise:**
  - Windows kernel storage: storport, boot-start drivers, crash dump and hibernation paths, Driver Verifier.
  - iPXE internals: SAN layer, EFI block devices, ACPI table publishing.
  - Ceph protocol: msgr2, cephx, OSDMap and CRUSH encodings, librbd behavior.
  - Test infrastructure: small Ceph clusters, QEMU/OVMF setups, fault injection.
- See [CONTRIBUTING.md](CONTRIBUTING.md) for the rules (independent implementation, sign-off).

### Repository layout

```
winrbd/
  README.md             this file
  LICENSE               per-directory licensing policy
  COPYING.MIT           MIT licence text (core/, harness/)
  COPYING.LGPL-2.1      full LGPL-2.1 text
  COPYING.GPL-2.0       full GPL-2.0 text
  CONTRIBUTING.md
  docs/
    ROADMAP.md          phased plan, test environment
    design/
      handoff-table.md  DRAFT: ACPI handoff table
  core/                 planned: portable C core
  harness/              planned: Linux test harness
  ipxe/                 planned: iPXE rbd:// SAN driver
  windows/              planned: Windows boot-start driver
  third_party/
    ipxe/               git submodule, pinned reference
    wnbd/               git submodule, pinned reference
```

The submodules are references and build inputs. Clone with:

```
git clone --recursive https://github.com/linwoodpendleton/winrbd.git
```

or, in an existing clone, `git submodule update --init --recursive`.

### Prior art and credits

- **iPXE** (iPXE project): the boot loader we extend, and the iBFT / aBFT tables as the model for the handoff table.
- **WNBD** (Cloudbase Solutions; the sources carry "Copyright (c) 2019 SUSE LLC"): the Windows storport virtual miniport we fork. Its history also shows an earlier in-kernel NBD client over WSK (removed in `59da53f`, last present at `59da53f^`); the WSK library it used was a separate MIT-licensed project, ksocket_wsk (Petr Benes).
- **Ceph** and **Linux krbd**: the protocol, the reference implementations, and the byte-for-byte oracle for testing.
- **Citrix Provisioning Services** and other diskless-boot systems: as far as we know, prior art for a custom boot loader plus a custom boot-start disk driver plus a custom protocol on Windows. We have not yet checked this against public Citrix documentation, and we have no citation for the diskless systems reported to be used in internet cafes; treat both as unverified.

---

<a name="zh"></a>

## 中文

**winrbd** 是一个开源研究项目:让 Windows 直接从 Ceph RBD 镜像启动并运行,中间**没有 iSCSI、没有网关**,客户端从头到尾说 Ceph 原生协议。

**当前状态:第一阶段(可移植的 C 核心与 Linux 测试宿主)已能对接真实的 Ceph v20.2.5 集群;Windows 还不能从它启动。** 核心用 cephx 通过 msgr2(crc 与 secure 模式,AES-GCM)登录,跟随 OSDMap,用 CRUSH 定位对象,读写 RBD format 2 镜像,在实验集群上与 Linux 内核客户端(krbd)逐字节一致。iPXE 驱动(第二阶段)和 Windows 驱动(后续阶段)还没写,所以还没有能部署的东西。如果你喜欢啃硬骨头,愿意利用业余时间一起做,欢迎继续看。

### 为什么做

现在给 Windows 机器提供 Ceph 后端磁盘,通常的办法是 iSCSI 网关。能用,但有这些问题:

- **多一跳。** 每次 I/O 都是 客户端 -> 网关 -> OSD。网关是瓶颈,也是一个要自己评估容量、做高可用、做监控的故障域。
- **最后一跳较弱。** Ceph 自己的通信层(msgr2)可以对到 OSD 的流量做加密和认证,但客户端到网关这段 iSCSI 通常不加密(CHAP 只做认证,不做加密),除非另外再叠加方案。
- **Windows 没法照搬 Linux 的做法。** Linux 无盘客户端可以先加载内核和 initramfs,由用户态或内核里的 RBD 客户端(krbd)映射镜像,然后 `switch_root`。据我们所知 Windows 没有这个阶段:在 UEFI 路径上,`bootmgr` 和 `winload` 通过固件服务读系统盘,之后才由 Windows 内部的启动期(boot-start)存储驱动接手(有待对照 Microsoft 关于 Windows 启动过程和启动期驱动的文档核实,见路线图 Phase 4)。所以磁盘必须先对固件可见,随后操作系统里的驱动还要找到**同一块**盘。

思路是在两处都放一个原生 RBD 客户端:启动加载器(iPXE)里一个,Windows 内核里一个。

### 打算怎么工作

```
  NIC PXE ROM / UEFI network boot
              |
              v
  +-----------------------------+
  | iPXE (UEFI build)           |  [1]
  |   rbd://mons/pool/image     |
  |   - mon + cephx + msgr2     |
  |   - osdmap + CRUSH          |
  |   - OSD object I/O          |
  +--------------+--------------+
                 | EFI_BLOCK_IO protocol
                 | + ACPI handoff table
                 v
  +-----------------------------+
  | stock bootmgr / winload     |  [2]
  | (unmodified UEFI firmware)  |
  +--------------+--------------+
                 | ExitBootServices
                 v
  +-----------------------------+
  | Windows kernel              |  [3]
  |  boot-start NIC + TCP/IP    |
  |  winrbd.sys (storport       |
  |  miniport, RBD over WSK)    |
  +--------------+--------------+
                 | Ceph native protocol (msgr2)
                 v
          Ceph mons + OSDs
```

- [1] iPXE(UEFI 版):新的 SAN 驱动,直接说 Ceph 协议(mon、cephx、msgr2、osdmap、CRUSH、OSD 对象读写、RBD format 2)。镜像以 EFI_BLOCK_IO 呈现为一块本地盘,同时发布一张 ACPI 交接表(类似 iBFT:网卡、mon、镜像等)。
- [2] 原版 bootmgr / winload:通过固件块设备读取 `\Windows` 和启动期驱动;UEFI 固件不做任何修改。
- [3] Windows 内核:启动期网卡 + TCP/IP;winrbd.sys(storport miniport,内核内置 RBD 客户端,走 WSK)读取交接表,打开同一个镜像并接管为系统盘。`ExitBootServices` 之后 iPXE 和它的网络都消失了。

UEFI 固件不做任何修改。`ExitBootServices` 之后 iPXE 的块设备和网络栈都不再可用,所以 Windows 驱动必须自己重新连上同一个镜像;交接表就是告诉它该打开什么。

### 组成部分

| 目录 | 内容 | 许可意向 |
|---|---|---|
| `core/` | 一份与平台无关的 C 核心:mon 客户端、cephx、msgr2、OSDMap、CRUSH、OSD 对象读写、RBD format-2 镜像。套接字、内存、时间、加密由一层很薄的适配层提供。 | MIT |
| `harness/` | 在 Linux 用户态承载核心的测试台。开发时不会蓝屏,并能以 Linux krbd 为标准答案逐字节比对。 | MIT |
| `ipxe/` | iPXE 的 `rbd://` SAN 驱动;提供 EFI_BLOCK_IO,并发布交接用的 ACPI 表。 | GPL-2.0-or-later 或 UBDL,与 iPXE 自己的 SAN 代码一致 |
| `windows/` | 从 WNBD 的 `wnbd.sys` 分叉的启动期 storport miniport,内核内置 RBD 客户端,走 WSK。 | 新文件 LGPL-2.1-or-later;派生自 WNBD 的文件 LGPL-2.1-only |

同一份核心有三种承载方式:Linux 测试台、iPXE、Windows 内核。这是项目最主要的设计赌注:难的协议代码只写一次,并且在最容易调试的环境里调好。

### 状态

第一阶段在 Linux 测试宿主里已经能用:msgr2(crc 与 secure 模式)、cephx、OSDMap 与 CRUSH、OSD 对象读写、RBD format 2 镜像读写,在实验集群上与 krbd 逐字节对比;第一阶段的长时间退出测试结果还在出(见路线图)。目前还不能启动:iPXE `rbd://` 驱动和 Windows 驱动在后续阶段。分阶段计划、各里程碑状态和证据见 [docs/ROADMAP.md](docs/ROADMAP.md),交接表草案见 [docs/design/handoff-table.md](docs/design/handoff-table.md)。

目前对照固定版本的源码已经核实的内容:

- iPXE 有通用的 SAN 层和 EFI_BLOCK_IO 后端,也有通用的 ACPI 表机制(iBFT 和 AoE 的 aBFT 都在用)。目前没有 `rbd` 或 `ceph` 的 URI 方案。
- WNBD 当前的 `wnbd.sys` 是一个 storport 虚拟 miniport,驱动里没有网络代码;每块盘都由用户态进程在运行时创建。它现在不能启动系统卷。WNBD 的历史里曾有过走 WSK 的内核态 NBD 客户端(在提交 `59da53f` 中移除),结构上可作参考。
- Ceph 线上协议有一部分细节在公开文档里(例如 msgr2 的帧前导、CRC-32C 参数和 secure 模式的 nonce 布局,见 [docs.ceph.com/en/latest/dev/msgr2/](https://docs.ceph.com/en/latest/dev/msgr2/))。很多细节则没有:数字 tag、完整的消息头布局、secure 模式的密钥派生、cephx 的加密算法 / IV / 摘要细节、OSDMap 与 CRUSH 的编码,以及 RBD 头部中 size、features、snap context 对应的方法名。这些需要从 Ceph 源码和真实集群里确认,在路线图里作为未决问题列出,而不是想当然。

### 自己验证这些笔记

[docs/spec/](docs/spec/README.md) 里的协议笔记都对照真实字节检查过:一套公开的抓包,来自标准 Ceph 20.2.5 客户端,使用两个一次性的 cephx 用户,这两个用户在抓包结束后立刻从实验集群里删除了(密钥是公开的,已经不能认证任何东西)。八个相互独立的检查器读取这套抓包。从一份全新的克隆开始,只需要 Python 3、`cryptography` 包和 `curl`,运行一条命令:

```sh
harness/tools/run-all.sh
```

它会先下载检查器运行时需要的少量 Ceph 文件(取自固定的 Ceph 提交,做 sha256 校验,放进被 git 忽略的目录,绝不属于本仓库),然后运行全部八个检查器,并打印通过 / 失败 / 跳过的汇总表。详见 [harness/tools/README.md](harness/tools/README.md) 和 [harness/vectors/README.md](harness/vectors/README.md)。

### 范围

- 仅面向测试网络和研究,不是产品。
- 业余时间项目,尽力而为,**不承诺任何时间表**。
- 仅 UEFI;传统 BIOS 启动暂不考虑。
- 第一个目标是一个狭窄、简单的镜像配置(无克隆、默认条带、关闭 object-map / fast-diff / journaling);具体清单见路线图。

### 签名策略

- 开发阶段使用 Windows 测试签名,并关闭 Secure Boot。
- 本项目**不发布任何正式签名的二进制文件**。想在测试网络之外部署的人,需要自行为自己编译的版本取得 Microsoft 的 attestation 签名。

### 许可意向

- 可移植核心与 Linux 测试台:**MIT**。这样同一份代码可以直接链接进 iPXE(GPL-2.0-or-later 或 UBDL)、LGPL 的 Windows 驱动,以及其他任何项目,不需要转换许可。
- Windows 驱动:新文件使用 LGPL-2.1-or-later。WNBD 的大多数文件写的是 "Licensed under LGPL-2.1 (see LICENSE)",没有写 "or later";`wnbd.rc` 写的是 `LGPL-2.1-only`。除非版权持有人另行确认,我们把派生自 WNBD 的文件按 LGPL-2.1-only 处理。
- iPXE 驱动:`ipxe/` 里的粘合文件为 GPL-2.0-or-later 或 UBDL(`GPL2_OR_LATER_OR_UBDL`),与 iPXE 自己的 SAN 代码一致。MIT 的核心在 iPXE 构建里可以标成 `MIT`,所以 UBDL 选项得以保留。
- 独立实现:核心依据 Ceph 公开的协议文档编写,Ceph 用户态源码仅作阅读参考。Linux 内核 libceph / rbd.c(GPL)的代码**不会**被复制。

详情和尚未确认的许可问题见 [LICENSE](LICENSE)。

### 如何参与

欢迎加入。现阶段可以这样帮忙:

- **提 issue**:提问、纠错、评审计划。欢迎设计讨论,尤其欢迎对架构的质疑。
- **特别需要的经验:**
  - Windows 内核存储:storport、启动期驱动、崩溃转储与休眠路径、Driver Verifier。
  - iPXE 内部:SAN 层、EFI 块设备、ACPI 表发布。
  - Ceph 协议:msgr2、cephx、OSDMap 与 CRUSH 编码、librbd 行为。
  - 测试基础设施:小型 Ceph 集群、QEMU/OVMF 环境、故障注入。
- 规则(独立实现、签署)见 [CONTRIBUTING.md](CONTRIBUTING.md)。

### 仓库结构

```
winrbd/
  README.md             本文件
  LICENSE               各目录的许可策略
  COPYING.MIT           MIT 许可全文(core/、harness/)
  COPYING.LGPL-2.1      LGPL-2.1 全文
  COPYING.GPL-2.0       GPL-2.0 全文
  CONTRIBUTING.md
  docs/
    ROADMAP.md          分阶段计划、测试环境
    design/
      handoff-table.md  草案:ACPI 交接表
  core/                 计划中:可移植 C 核心
  harness/              计划中:Linux 测试台
  ipxe/                 计划中:iPXE rbd:// SAN 驱动
  windows/              计划中:Windows 启动期驱动
  third_party/
    ipxe/               git 子模块,固定版本的参考
    wnbd/               git 子模块,固定版本的参考
```

子模块是参考和构建输入。克隆方式:

```
git clone --recursive https://github.com/linwoodpendleton/winrbd.git
```

已经克隆过的,执行 `git submodule update --init --recursive`。

### 前人工作与致谢

- **iPXE**(iPXE 项目):我们要扩展的启动加载器;iBFT / aBFT 表是交接表的参照模型。
- **WNBD**(Cloudbase Solutions;源码里带有 "Copyright (c) 2019 SUSE LLC"):我们分叉的 Windows storport 虚拟 miniport。它的历史里还有早期走 WSK 的内核态 NBD 客户端(在 `59da53f` 中移除,最后存在于 `59da53f^`);当时用的 WSK 库是一个独立的 MIT 许可项目 ksocket_wsk(Petr Benes)。
- **Ceph** 和 **Linux krbd**:协议本身、参考实现,以及测试时逐字节比对的标准答案。
- **Citrix Provisioning Services** 及其他无盘启动系统:据我们所知,它们是"自带启动加载器 + 自带启动期磁盘驱动 + 自有协议"这条路线在 Windows 上的前人工作。我们还没有对照 Citrix 的公开文档核实,据说网吧使用的那类无盘系统也没有可引用的出处;两者都应视为未经核实。
