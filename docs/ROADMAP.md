# winrbd roadmap

[English](#en) | [中文](#zh)

No dates, on purpose. This is a spare-time project; phases are ordered by dependency, not by calendar. A phase is done when its exit criteria are met, not when time has passed.

---

<a name="en"></a>

## English

### Ground rules

- One portable C core, hosted three ways: Linux harness, iPXE, Windows kernel. Protocol bugs get fixed in the harness, where debugging is cheap.
- Linux krbd is the oracle: for any image, bytes read through our core must equal bytes read through krbd.
- Nothing is assumed about Ceph or Windows internals. Every claim is either checked against source / a live cluster / Microsoft documentation, or listed as an open question.
- First target is **one pinned Ceph release** and **one narrow image profile**. Widening comes later.

Proposed v1 image profile (to be confirmed in Phase 0): RBD format 2, default striping (stripe_count 1, stripe_unit = object size), replicated data pool, no parent (not a clone), journaling off, object-map and fast-diff off. exclusive-lock handling is an open question (see Phase 1).

### Starting point: what the pinned reference trees contain

Checked against the submodules in `third_party/` (iPXE `9261ebe38`, WNBD `20e029d04`, tag 0.7.0).

iPXE:

- `src/core/sanboot.c` is a generic SAN layer over a block interface; the EFI backend `src/interface/efi/efi_block.c` publishes a SAN device as EFI_BLOCK_IO, then connects firmware filesystem drivers to it.
- A new URI scheme is registered with a `struct uri_opener` (as `iscsi`, `aoe`, `usb` do). No `rbd` or `ceph` scheme exists.
- The ACPI mechanism (`struct acpi_descriptor`, `struct acpi_model`, `acpi_install`) is generic. `src/net/aoe.c` (aBFT) is the smallest complete example; `src/drivers/block/ibft.c` the larger one. On EFI the tables are installed through the firmware's ACPI table protocol, and iPXE overwrites the table header's OEM ID and OEM table ID, so our table must be identified by its 4-character signature or by body fields. Without the firmware's ACPI table protocol, `efi_block_describe` returns "not supported" and the whole `sanhook` / `sanboot` of the device fails, not just the table. Each description pass uninstalls and reinstalls all tables, so the table must be rebuilt idempotently every time.
- The SAN layer issues one command at a time (15 s timeout; 10 retries by default, configurable with the `san-retries` setting); parallelism across OSDs has to happen inside one command. The `malloc()` heap is a fixed 4 MiB (`HEAP_SIZE` in `src/core/malloc.c`), but large allocations can use `umalloc()`, which on EFI is backed by `AllocatePages` (`src/interface/efi/efi_umalloc.c`), so the heap limit only binds `malloc()`. There are no threads; everything runs from the main loop.
- AES (CBC, GCM), SHA-1/2, HMAC, HKDF and a DRBG exist; **CRC-32C does not** (only the IEEE CRC-32, in `src/crypto/crc32.c`), so it must be written new in the core, for example as a table-driven or slicing-by-8 routine.
- After `ExitBootServices`, iPXE's block devices and network are not usable.

WNBD:

- `wnbd.sys` is a storport virtual miniport. Disks are created at run time by a user-space IOCTL; I/O is forwarded to a user-space process through fetch/respond IOCTLs. The driver contains no network code today.
- It cannot boot a system volume as is: the adapter is root-enumerated, every disk depends on a user-space process, and there is no dump-mode or hibernate handling. The INF declares `SERVICE_BOOT_START`, but whether that alone yields a boot-critical adapter is unverified.
- WNBD's history contains an in-kernel NBD client over WSK, with per-device request and reply threads and no reconnect logic. The driver dropped it in commit `59da53f` ("driver: drop NBD implementation"); the last tree that has it is `59da53f^`. It used the ksocket_wsk library (MIT, Petr Benes). Useful as a structural reference.
- Block size is hard-limited to 512 bytes in the current driver. Build uses VS2019 / WDK 10.0.20348, x64 only.

### Phase 0: protocol study and spec notes

**Goal.** Know exactly what bytes go on the wire for one pinned Ceph release, before writing the core.

**Deliverables.**
- `docs/spec/` notes (own words, with sources) for: msgr2 banner, frames, handshake and tags; cephx exchanges and cipher details; mon subscribe and map delivery; OSDMap and Incremental encoding (the subset needed); CRUSH map encoding, hash and straw2; MOSDOp / MOSDOpReply encoding and op codes; RBD format-2 header access (cls_rbd methods or omap keys) and data object naming.
- A chosen supported Ceph release and the v1 image profile, written down.
- Packet captures from a live test cluster (secrets scrubbed) used as test vectors.

**Exit criteria.** Each wire structure the core needs is described in the notes with a source reference and has been confirmed against a capture or `ceph` / `rbd` / `crushtool` output from the test cluster.

**Open questions / risks.**
- Which Ceph release to pin (Quincy / Reef / Squid or later)? Encodings are versioned.
- msgr2 versions: the [msgr2 page](https://docs.ceph.com/en/latest/dev/msgr2/) says `CEPH_MSGR2_FEATURE_REVISION_1` lets 2.0 and 2.1 peers talk; which one the pinned release expects from a client still has to be confirmed on the test cluster.
- crc mode vs secure mode: the [msgr2 configuration page](https://docs.ceph.com/en/latest/rados/configuration/msgr2/) lists `ms_client_mode`, `ms_service_mode` and `ms_cluster_mode` as defaulting to "crc secure", so crc-only should be accepted by default, but fails on clusters configured secure-only; confirm with `ceph config help ms_service_mode` on the test cluster. Secure mode needs AES-128-GCM; the msgr2 page gives the nonce construction (seeded from the connection secret) but not the key derivation.
- What the public docs do not give: numeric tag values, the full `ceph_msg_header2` layout, secure-mode key derivation, cephx cipher / IV / digest details (the [cephx page](https://docs.ceph.com/en/latest/dev/cephx_protocol/) is high-level only), and the RBD header method names for size / features / snap context (the [rbd-layering page](https://docs.ceph.com/en/latest/dev/rbd-layering/) covers `rbd_header.$id`, `rbd_id.$name`, `rbd_directory` and some `cls_rbd` methods, not those). What the docs do give: the 32-byte frame preamble, CRC-32C parameters (polynomial 0x1EDC6F41, init values), the `ceph v2\n` banner and the nonce layout.
- Ceph user-space file licenses need confirming before we rely on them as a reference.

### Phase 1: portable C core and Linux harness

**Goal.** A C library that opens an RBD image and reads / writes it, driven from a Linux program, byte-identical to krbd.

**Milestones.**
1. Shim interface defined (sockets, allocation, time, random, crypto, logging); Linux implementation.
2. Connect to a mon over msgr2 (banner, hello, frames, CRC-32C).
3. cephx authentication; obtain tickets for mon and OSD services; renew them before expiry.
4. Subscribe to and receive the OSDMap; decode the needed subset; follow incrementals, or re-fetch the full map when one is missing.
5. CRUSH mapping: object name -> PG -> OSD list. **Matches `ceph osd map` for a large set of synthetic object names** across several pools, including upmap / pg_temp cases.
6. OSD sessions and object read / write with tid tracking, resend on map change or connection reset.
7. RBD format-2 open: resolve image name to id, read size / order / object prefix / features / snap context; reject unsupported profiles with a clear error.
8. Image-level read / write with correct sparse (missing object reads as zeros) semantics.
9. Byte-compare against krbd on the same image with random and patterned I/O, including unaligned and cross-object requests.
10. Unit tests and fuzzing of every decoder (frames, OSDMap, CRUSH, replies). Memory-bounded mode: fixed budgets and no unbounded allocation, because iPXE has a 4 MiB heap and Windows needs preallocated pools.
11. Optional stage: secure mode (AES-GCM) in addition to crc mode.

**Deliverables.** `core/`, `harness/`, test scripts that build a test image on the test cluster and run the comparison.

**Exit criteria.** Harness reads and writes an image written / read via krbd with zero byte differences over a long randomized run; survives killing and restarting an OSD and a mon mid-run without data loss or hang; decoders pass fuzzing without crashes for an agreed duration.

**Open questions / risks.**
- exclusive-lock: may a non-librbd writer ignore it when object-map, fast-diff and journaling are off, or must we take the lock (cls_lock plus watch / notify handling)? Read-only use does not need to resolve this; read-write does. Writers must carry the image's snap context or snapshot copy-on-write breaks.
- Watch / notify on the header (resize, snapshot events): skip for v1 by declaring the image immutable in size while attached?
- Memory budget for OSDMap + CRUSH on large clusters (matters most for iPXE).
- Erasure-coded data pools and cloned images: out of v1.

### Phase 2: iPXE `rbd://` SAN driver

**Goal.** `sanboot rbd://...` in iPXE under QEMU + OVMF boots a Linux or WinPE image straight from RBD with no gateway.

**Milestones.**
1. Build the core into iPXE with a new SAN protocol option (config define, object requirement, URI opener), following the iSCSI / AoE pattern.
2. Block interface: read, write, capacity; per-chunk splitting into object-sized sub-requests issued in parallel inside one SAN command.
3. EFI device path for the device; EFI_BLOCK_IO exposed through the existing EFI SAN backend.
4. `sanhook` of the image visible to OVMF; GPT and ESP readable by firmware.
5. `sanboot` of a Linux image, then a WinPE image.
6. Handoff ACPI table (see `docs/design/handoff-table.md`) installed and visible in a Linux guest (`/sys/firmware/acpi/tables`) and dumpable.
7. Boot-time robustness: reopen after a path failure, cached maps across reopen, sane behavior when a mon or OSD is down.

**Deliverables.** `ipxe/` patch / driver files, build instructions pinned to the submodule revision, QEMU run scripts, the handoff table spec promoted from DRAFT to v1.

**Exit criteria.** In QEMU with OVMF (Secure Boot off) the VM boots a Linux and a WinPE image over `rbd://`; the handoff table appears in the guest and matches the design.

**Open questions / risks.**
- Direct block ops (ATA / HTTP-block style) vs going through the SCSI layer (iSCSI / usbblk style): neither prototyped.
- Which EFI device path shape lets stock `bootmgr` / `winload` accept the device? Unverified.
- Choosing a table signature that does not collide with any registered ACPI signature; whether Windows tolerates iPXE's forced OEM ID fields.
- Boot throughput with a one-command-at-a-time SAN layer while loading the kernel and boot-start drivers; mitigation is intra-command parallelism and readahead. Not measured.
- 4 MiB `malloc()` heap versus map sizes; large buffers can come from `umalloc()` (EFI `AllocatePages`), which is not measured either.
- Upstream iPXE has its own contribution policy: follow its `CONTRIBUTING.md` in full before proposing anything there (each submission needs an accountable author who has reviewed and understands it). New iPXE files also need a `FILE_LICENCE` and a `FILE_SECBOOT` decision; files not marked `FILE_SECBOOT ( PERMITTED )` are not allowed in UEFI Secure Boot signed iPXE builds, and per `compiler.h` third-party contributions need an approved security review to be marked permitted.
- Licensing inside an iPXE build: tag core files `MIT` and glue files `GPL2_OR_LATER_OR_UBDL`, then run the iPXE licence check (`make bin/<target>.licence`) on a real build to confirm.

### Phase 3: Windows kernel driver as a data disk

**Goal.** A Windows VM attaches an RBD image as a normal (non-boot) data disk through our driver, matching the user-space reference client for correctness and in the same range for performance.

**Milestones.**
1. Fork `wnbd.sys`; strip the user-space request channel and the create / remove machinery that a boot disk does not need; keep storport registration, SCSI emulation, abort / reset handling.
2. WSK transport shim for the core (connect, send, receive, with timeouts); preallocated buffers; dedicated worker threads.
3. Attach by configuration (registry parameters or a small control tool), open image through the core, report size and identity from the image header.
4. Support 512 and 4096 byte logical blocks (WNBD currently rejects anything but 512; root cause not examined).
5. Correctness: `diskspd` / `fio` verify runs, NTFS volume with `chkdsk`, flush semantics, unmap.
6. Performance comparison against Ceph's Windows client (`rbd-wnbd`) on the same cluster and VM.
7. Driver Verifier and static analysis clean on the data-disk path.

**Deliverables.** `windows/` driver and INF, build instructions (VS and WDK versions confirmed against Microsoft documentation), test-signing instructions.

**Exit criteria.** Several hours of verify-mode I/O with Driver Verifier enabled, no corruption, no bugchecks; throughput and latency reported next to the reference client.

**Open questions / risks.**
- Toolchain: WNBD uses VS2019 and WDK 10.0.20348; confirm which current VS / WDK to use, and whether ARM64 matters.
- Per-I/O context: storport SRB extension or an own preallocated pool.
- Whether a storport virtual miniport can be the boot disk adapter at all (see Phase 4) should be tested early, even in this phase, to avoid a dead end.
- Licensing: keep WNBD-derived files LGPL-2.1-only; keep the MIT notice if any code from the old WSK wrapper is reused.

### Phase 4: boot-start system disk

**Goal.** A Windows installation lives on an RBD image and boots through iPXE with no iSCSI and no gateway; the Windows driver takes over the same image.

**Milestones.**
1. Prove the plain case first: install Windows to a disk image, then make the disk visible to iPXE and firmware; confirm `bootmgr` / `winload` start from it (read-only is enough here).
2. Find out how a boot-start storport driver reads our handoff table early in boot (statements about Windows boot-start drivers and the boot process in this plan are to be verified against Microsoft Learn before we rely on them), and what Windows requires for a boot-critical storage adapter (hardware-ID enumeration, boot-critical device database, driver service group and ordering).
3. Boot-start NIC and TCP/IP: make the NIC driver and tcpip load before the storage driver needs the network, or decide to run a minimal network path in the driver. Choose and document.
4. Driver takes the NIC identity and address from the handoff table, connects, opens the image, becomes the system disk with the right disk signature / identity so the boot volume is found.
5. Offline driver injection (DISM) of the boot-start driver and required service registry entries into the image; documented, scripted.
6. Full boot to desktop in QEMU / KVM, then on one physical machine with PXE.

**Deliverables.** Working boot path, `docs/` procedure for preparing an image, handoff table spec v1 final.

**Exit criteria.** Cold boot to login, repeated, with no gateway in the path; a short log from WinDbg showing the driver took over the disk from the firmware view.

**Open questions / risks.**
- Is WSK available to a boot-start storage driver at the point it needs it? Old WNBD only used WSK after full boot, so there is no evidence either way in the repo.
- Does a virtual miniport work as the boot disk adapter, and does Windows insist on a crash-dump / hibernate capable path?
- Key handling in the handoff table (see the design doc): the cephx key is readable by the OS administrator.
- Secure Boot is off in this phase; later work depends on signing options.

### Phase 5: hardening

**Goal.** Make it survivable: no deadlocks in the paging path, working crash dumps, graceful behavior when the cluster changes.

**Work items.**
- **Paging-path safety.** Everything the I/O path touches is preallocated and non-paged; no allocation, no waiting on something that itself may need paging. WSK / tcpip may allocate on their own; design around it (dedicated threads, reserves, bounded queues) and test under memory pressure.
- **Crash dump and hibernation.** Dump-mode I/O is polled and runs with no normal OS services. Decide the approach (own minimal polled network path vs a dump stack provided by the NIC driver), implement, and test with forced bugchecks and hibernate / resume.
- **OSD / map changes and reconnects.** Resend in-flight ops on map change, connection reset, mon failover, ticket expiry; idempotent retries; measured recovery time.
- **Fault injection.** Packet loss, delay, reordering, OSD kill, mon kill, full map churn (add / remove OSDs, change CRUSH), and cephx ticket rollover during I/O.
- **Driver Verifier** (all standard checks plus low resources simulation), static analysis, fuzzing the kernel build of the decoders.
- **Documentation** for deploying on a test network, with the signing policy repeated.

**Exit criteria.** A soak test (VM running a mixed workload while the cluster is disturbed) runs for an agreed duration without data loss or bugcheck; crash dump from a forced bugcheck is written and readable; hibernate / resume works or is documented as unsupported.

**Open questions / risks.**
- Whether crash dump and hibernation can be supported at all on a network system disk with this design; the answer may be "documented limitation".
- Signing: development uses test-signing; anyone deploying beyond a test network must obtain Microsoft attestation signing for their own build. This project ships no production-signed binaries.

### Test environment

- **Hypervisor:** QEMU / KVM with OVMF (UEFI), Secure Boot off; virtio or e1000e NIC depending on what the boot-start NIC driver story needs.
- **Windows:** test-signing enabled (`bcdedit /set testsigning on`); a debuggee VM with WinDbg attached over serial, or KDNET over a **separate** NIC (so debugging traffic does not share the NIC under test).
- **Ceph:** a small test cluster, for example single host deployed with cephadm, 3 OSDs on files or loop devices, with a replicated pool for RBD. Enough to test CRUSH and map changes; a second multi-host cluster later for failure testing. Dedicated cephx entity with caps limited to the test pool.
- **Oracle:** a Linux machine with krbd mapping the same images; `ceph osd map`, `crushtool --test`, `rbd info` for ground truth.
- **PXE side:** dnsmasq or similar providing DHCP and TFTP / HTTP for the iPXE binary and scripts.
- **Physical machine:** one spare UEFI PC on the same test LAN for Phase 4 and 5, with a serial or KDNET debug path.
- Never point experiments at a cluster that holds data you care about.

---

<a name="zh"></a>

## 中文

### 基本原则

- 一份可移植 C 核心,三种承载方式:Linux 测试台、iPXE、Windows 内核。协议层的 bug 在测试台里修,那里调试成本最低。
- Linux krbd 是标准答案:同一个镜像,经我们的核心读出的字节必须与经 krbd 读出的字节一致。
- 对 Ceph 和 Windows 内部实现不做任何假设。每一条结论要么对照源码 / 真实集群 / Microsoft 文档核实过,要么列为未决问题。
- 第一个目标是**固定的某一个 Ceph 版本**和**一个狭窄的镜像配置**,放宽留到以后。

v1 镜像配置(拟定,Phase 0 确认):RBD format 2、默认条带(stripe_count 1,stripe_unit 等于对象大小)、副本数据池、无父镜像(非克隆)、关闭 journaling、关闭 object-map 与 fast-diff。exclusive-lock 的处理仍是未决问题(见 Phase 1)。

### 起点:固定版本的参考源码里有什么

核对对象是 `third_party/` 下的子模块(iPXE `9261ebe38`,WNBD `20e029d04`,标签 0.7.0)。

iPXE:

- `src/core/sanboot.c` 是建立在块设备接口之上的通用 SAN 层;EFI 后端 `src/interface/efi/efi_block.c` 把 SAN 设备以 EFI_BLOCK_IO 发布出来,再让固件的文件系统驱动去绑定它。
- 新增 URI 方案要注册一个 `struct uri_opener`(`iscsi`、`aoe`、`usb` 都是这样)。目前没有 `rbd` 或 `ceph` 方案。
- ACPI 机制(`struct acpi_descriptor`、`struct acpi_model`、`acpi_install`)是通用的。`src/net/aoe.c`(aBFT)是最小的完整例子,`src/drivers/block/ibft.c` 是较大的例子。在 EFI 下表通过固件的 ACPI 表协议安装,iPXE 会改写表头的 OEM ID 和 OEM table ID,所以我们的表只能靠 4 字符签名或表体字段来识别。如果固件没有 ACPI 表协议,`efi_block_describe` 会返回"不支持",该设备的整个 `sanhook` / `sanboot` 都会失败,而不只是少一张表。每次描述都会卸载并重新安装所有表,所以这张表必须每次都能幂等地重建。
- SAN 层一次只发一条命令(超时 15 秒;默认重试 10 次,可用 `san-retries` 设置修改),跨 OSD 的并行只能在一条命令内部做。`malloc()` 堆是固定的 4 MiB(`src/core/malloc.c` 里的 `HEAP_SIZE`),但大块内存可以用 `umalloc()`,它在 EFI 下由 `AllocatePages` 支撑(`src/interface/efi/efi_umalloc.c`),所以堆上限只约束 `malloc()`。没有线程,一切都在主循环里跑。
- 已有 AES(CBC、GCM)、SHA-1/2、HMAC、HKDF 和 DRBG;**没有 CRC-32C**(只有 `src/crypto/crc32.c` 里的 IEEE CRC-32),所以要在核心里新写一份,例如查表法或 slicing-by-8。
- `ExitBootServices` 之后,iPXE 的块设备和网络不可用。

WNBD:

- `wnbd.sys` 是 storport 虚拟 miniport。磁盘由用户态 IOCTL 在运行时创建;I/O 通过 fetch / respond 两类 IOCTL 转给用户态进程。驱动里目前没有网络代码。
- 按现状它不能启动系统卷:适配器是 root 枚举的,每块盘都依赖用户态进程,也没有转储模式或休眠处理。INF 里声明了 `SERVICE_BOOT_START`,但仅凭这一点能否得到启动关键适配器,尚未核实。
- WNBD 的历史里有一个走 WSK 的内核态 NBD 客户端,每块盘有请求线程和应答线程,没有重连逻辑。驱动在提交 `59da53f`("driver: drop NBD implementation")中删掉了它;最后一个还带着它的树是 `59da53f^`。它用的是 ksocket_wsk 库(MIT,Petr Benes)。可作结构参考。
- 当前驱动把块大小硬性限制为 512 字节。构建环境为 VS2019 / WDK 10.0.20348,仅 x64。

### Phase 0:协议研究与规格笔记

**目标。** 在写核心之前,对固定的某个 Ceph 版本,弄清线上到底传哪些字节。

**交付物。**
- `docs/spec/` 笔记(用自己的话写,注明出处):msgr2 的 banner、帧、握手与 tag;cephx 的交互与加密细节;mon 订阅与 map 下发;OSDMap 与 Incremental 编码(只取需要的子集);CRUSH 的 map 编码、哈希与 straw2;MOSDOp / MOSDOpReply 编码与操作码;RBD format-2 头部读取方式(cls_rbd 方法或 omap 键)与数据对象命名。
- 确定下来并写明的受支持 Ceph 版本和 v1 镜像配置。
- 从真实测试集群抓取的报文(已清除密钥),作为测试向量。

**退出标准。** 核心需要的每个线上结构,笔记里都有来源引用,并已用测试集群的抓包或 `ceph` / `rbd` / `crushtool` 输出核对过。

**未决问题 / 风险。**
- 固定哪个 Ceph 版本(Quincy / Reef / Squid 或更新)?编码是带版本的。
- msgr2 版本:[msgr2 文档](https://docs.ceph.com/en/latest/dev/msgr2/)说 `CEPH_MSGR2_FEATURE_REVISION_1` 让 2.0 和 2.1 的对端可以通信;固定的那个版本对客户端期望哪一种,仍需在测试集群上确认。
- crc 模式与 secure 模式:[msgr2 配置文档](https://docs.ceph.com/en/latest/rados/configuration/msgr2/)里 `ms_client_mode`、`ms_service_mode`、`ms_cluster_mode` 的默认值是 "crc secure",所以只支持 crc 时默认设置应该能通过,但对只允许 secure 的集群会失败;在测试集群上用 `ceph config help ms_service_mode` 确认。secure 模式需要 AES-128-GCM;msgr2 文档给出了 nonce 的构造(由 connection secret 提供初始值),但没有给出密钥派生。
- 公开文档里没有的:数字 tag 值、完整的 `ceph_msg_header2` 布局、secure 模式的密钥派生、cephx 的加密算法 / IV / 摘要细节([cephx 文档](https://docs.ceph.com/en/latest/dev/cephx_protocol/)只有高层描述),以及 RBD 头部中 size / features / snap context 对应的方法名([rbd-layering 文档](https://docs.ceph.com/en/latest/dev/rbd-layering/)讲了 `rbd_header.$id`、`rbd_id.$name`、`rbd_directory` 和部分 `cls_rbd` 方法,但没有这些)。文档里有的:32 字节的帧前导、CRC-32C 参数(多项式 0x1EDC6F41、初始值)、`ceph v2\n` banner 和 nonce 布局。
- 在把 Ceph 用户态文件当作参考之前,需要确认它们各自的许可。

### Phase 1:可移植 C 核心与 Linux 测试台

**目标。** 一个 C 库,由 Linux 程序驱动,能打开 RBD 镜像并读写,结果与 krbd 逐字节一致。

**里程碑。**
1. 定义适配层接口(套接字、内存、时间、随机数、加密、日志);给出 Linux 实现。
2. 经 msgr2 连上 mon(banner、hello、帧、CRC-32C)。
3. cephx 认证;取得 mon 与 OSD 服务的 ticket;到期前续期。
4. 订阅并接收 OSDMap;解码所需子集;跟随增量,缺增量时重新拉取完整 map。
5. CRUSH 映射:对象名 -> PG -> OSD 列表。**对大量合成的对象名,结果与 `ceph osd map` 一致**,覆盖多个存储池,包括 upmap / pg_temp 的情况。
6. OSD 会话与对象读写,带 tid 跟踪,map 变化或连接重置时重发。
7. RBD format-2 打开:镜像名解析为 id,读取 size / order / object prefix / features / snap context;对不支持的配置给出清晰报错。
8. 镜像级读写,稀疏语义正确(缺失对象读出为零)。
9. 在同一镜像上与 krbd 逐字节比对,使用随机与规律模式的 I/O,包含不对齐和跨对象请求。
10. 对每个解码器(帧、OSDMap、CRUSH、应答)做单元测试和模糊测试。内存受限模式:固定预算、不无限分配,因为 iPXE 只有 4 MiB 堆,Windows 则需要预分配的内存池。
11. 可选阶段:在 crc 模式之外加入 secure 模式(AES-GCM)。

**交付物。** `core/`、`harness/`,以及在测试集群上建测试镜像并跑比对的测试脚本。

**退出标准。** 测试台读写的镜像与经 krbd 写入 / 读出的内容零字节差异,长时间随机运行;运行中杀掉并重启一个 OSD 和一个 mon,不丢数据、不挂死;解码器在约定时长的模糊测试中无崩溃。

**未决问题 / 风险。**
- exclusive-lock:在 object-map、fast-diff、journaling 都关闭时,非 librbd 的写入方能否无视它?还是必须取锁(cls_lock 加 watch / notify 处理)?只读使用不需要解决这个问题,读写需要。写入必须携带镜像的 snap context,否则快照的写时复制会被破坏。
- 头部对象上的 watch / notify(调整大小、快照事件):v1 是否通过"挂载期间镜像大小视为不变"来跳过?
- 大集群上 OSDMap + CRUSH 的内存预算(对 iPXE 影响最大)。
- 纠删码数据池和克隆镜像:不在 v1 范围内。

### Phase 2:iPXE `rbd://` SAN 驱动

**目标。** 在 QEMU + OVMF 下的 iPXE 里执行 `sanboot rbd://...`,不经任何网关,直接从 RBD 启动 Linux 或 WinPE 镜像。

**里程碑。**
1. 把核心编进 iPXE,新增一个 SAN 协议选项(配置宏、对象依赖、URI opener),照 iSCSI / AoE 的模式做。
2. 块接口:读、写、容量;每个分块拆成对象大小的子请求,在一条 SAN 命令内部并行发出。
3. 为该设备生成 EFI 设备路径;通过现有 EFI SAN 后端提供 EFI_BLOCK_IO。
4. `sanhook` 之后 OVMF 能看到该镜像;固件能读 GPT 和 ESP。
5. `sanboot` 启动 Linux 镜像,再启动 WinPE 镜像。
6. 交接 ACPI 表(见 `docs/design/handoff-table.md`)已安装,并能在 Linux 客户机里看到(`/sys/firmware/acpi/tables`)和导出。
7. 启动期健壮性:路径故障后重新打开,重新打开时复用已缓存的 map,mon 或 OSD 不可用时行为合理。

**交付物。** `ipxe/` 补丁 / 驱动文件、固定在子模块版本上的构建说明、QEMU 运行脚本、从草案升为 v1 的交接表规格。

**退出标准。** 在 QEMU + OVMF(Secure Boot 关闭)下,虚拟机通过 `rbd://` 启动 Linux 和 WinPE 镜像;交接表在客户机里可见且与设计一致。

**未决问题 / 风险。**
- 直接实现块操作(ATA / HTTP-block 风格)还是走 SCSI 层(iSCSI / usbblk 风格):两种都没做过原型。
- 什么形状的 EFI 设备路径,原版 `bootmgr` / `winload` 才会接受该设备?尚未验证。
- 选一个不与任何已注册 ACPI 签名冲突的表签名;Windows 是否容忍 iPXE 强制写入的 OEM 字段。
- SAN 层一次一条命令,加载内核和启动期驱动时的启动吞吐如何;缓解办法是命令内并行和预读。尚未测量。
- 4 MiB 的 `malloc()` 堆与 map 体积的矛盾;大缓冲区可以从 `umalloc()`(EFI `AllocatePages`)取,这一点同样没有测量过。
- iPXE 上游有自己的贡献政策:向它提交任何东西之前,必须完整遵守其 `CONTRIBUTING.md`(每份提交都要有对其负责、审阅过并理解的作者)。新的 iPXE 文件还需要决定 `FILE_LICENCE` 和 `FILE_SECBOOT`;没有标记 `FILE_SECBOOT ( PERMITTED )` 的文件不允许进入 UEFI Secure Boot 签名构建,而按 `compiler.h` 的说明,第三方贡献要通过认可的安全审查才能标记为 permitted。
- iPXE 构建里的许可:核心文件标 `MIT`,粘合文件标 `GPL2_OR_LATER_OR_UBDL`,再拿真实构建跑一次 iPXE 的许可检查(`make bin/<target>.licence`)确认。

### Phase 3:Windows 内核驱动,作数据盘

**目标。** Windows 虚拟机通过我们的驱动把 RBD 镜像挂成普通(非启动)数据盘,正确性与用户态参考客户端一致,性能处于同一量级。

**里程碑。**
1. 分叉 `wnbd.sys`;去掉用户态请求通道,以及启动盘用不到的创建 / 移除机制;保留 storport 注册、SCSI 模拟、abort / reset 处理。
2. 为核心做 WSK 传输适配层(连接、收发、超时);预分配缓冲区;专用工作线程。
3. 通过配置(注册表参数或一个小型控制工具)挂载,经核心打开镜像,从镜像头部报告大小和标识。
4. 支持 512 和 4096 字节逻辑块(WNBD 目前只接受 512,根因尚未研究)。
5. 正确性:`diskspd` / `fio` 校验运行、NTFS 卷加 `chkdsk`、flush 语义、unmap。
6. 在同一集群、同一虚拟机上与 Ceph 的 Windows 客户端(`rbd-wnbd`)做性能对比。
7. 数据盘路径通过 Driver Verifier 和静态分析。

**交付物。** `windows/` 驱动与 INF、构建说明(VS 与 WDK 版本对照 Microsoft 文档确认)、测试签名说明。

**退出标准。** 开启 Driver Verifier,连续数小时校验模式 I/O,无损坏、无 bugcheck;吞吐与延迟与参考客户端并列报告。

**未决问题 / 风险。**
- 工具链:WNBD 用 VS2019 和 WDK 10.0.20348;需确认现在该用哪个 VS / WDK,以及 ARM64 是否重要。
- 每个 I/O 的上下文:storport 的 SRB 扩展,还是自己预分配的池。
- storport 虚拟 miniport 究竟能不能充当启动盘适配器(见 Phase 4),应该尽早测,哪怕在这一阶段,以免走进死路。
- 许可:派生自 WNBD 的文件保持 LGPL-2.1-only;如果复用旧 WSK 封装的代码,要保留 MIT 声明。

### Phase 4:启动期系统盘

**目标。** Windows 安装在 RBD 镜像上,经 iPXE 启动,没有 iSCSI、没有网关;Windows 驱动接管同一个镜像。

**里程碑。**
1. 先证明最基本的情况:把 Windows 装到一个磁盘镜像上,让磁盘对 iPXE 和固件可见,确认 `bootmgr` / `winload` 能从它启动(这一步只读就够了)。
2. 搞清楚启动期 storport 驱动如何在启动早期读取我们的交接表(本计划中关于 Windows 启动期驱动和启动过程的说法,在依赖它们之前都要对照 Microsoft Learn 核实),以及 Windows 对启动关键存储适配器有哪些要求(硬件 ID 枚举、启动关键设备数据库、驱动服务组与加载顺序)。
3. 启动期网卡与 TCP/IP:让网卡驱动和 tcpip 先于存储驱动需要网络的时刻加载,或者决定在驱动里自带一条最小网络路径。选定并写下来。
4. 驱动从交接表取得网卡标识和地址,连接,打开镜像,以正确的磁盘签名 / 标识成为系统盘,让启动卷能被找到。
5. 离线把启动期驱动和所需服务注册表项注入镜像(DISM);写成文档并脚本化。
6. 先在 QEMU / KVM 里完整启动到桌面,再在一台物理机上用 PXE 做同样的事。

**交付物。** 能工作的启动路径、镜像准备流程的 `docs/` 文档、定稿的 v1 交接表规格。

**退出标准。** 冷启动到登录界面,可重复,路径中没有网关;一份简短的 WinDbg 日志,显示驱动从固件视角接管了磁盘。

**未决问题 / 风险。**
- 启动期存储驱动在需要的那一刻,WSK 是否可用?旧版 WNBD 只在系统完全启动后才用 WSK,仓库里两个方向都没有证据。
- 虚拟 miniport 能否作启动盘适配器?Windows 是否硬性要求具备崩溃转储 / 休眠能力的路径?
- 交接表中的密钥处理(见设计文档):cephx 密钥操作系统管理员可读。
- 这一阶段 Secure Boot 关闭;后续工作取决于签名方案。

### Phase 5:加固

**目标。** 让它经得起折腾:分页路径无死锁、崩溃转储可用、集群变化时行为得体。

**工作项。**
- **分页路径安全。** I/O 路径上用到的一切都预分配、非分页;不分配,不等待那些自己可能也需要分页的东西。WSK / tcpip 可能自行分配内存,需要绕开(专用线程、预留、有界队列),并在内存压力下测试。
- **崩溃转储与休眠。** 转储模式的 I/O 是轮询式的,没有常规操作系统服务。决定方案(自带最小轮询网络路径,还是借网卡驱动提供的转储栈),实现并用强制 bugcheck 和休眠 / 恢复来测试。
- **OSD / map 变化与重连。** map 变化、连接重置、mon 故障转移、ticket 过期时重发在途请求;幂等重试;测量恢复时间。
- **故障注入。** 丢包、延迟、乱序、杀 OSD、杀 mon、map 大幅变动(增删 OSD、改 CRUSH)、I/O 期间 cephx ticket 轮换。
- **Driver Verifier**(全部标准检查加低资源模拟)、静态分析、对内核版解码器做模糊测试。
- 面向测试网络的**部署文档**,并重申签名策略。

**退出标准。** 一次浸泡测试(虚拟机跑混合负载,同时扰动集群)在约定时长内无数据丢失、无 bugcheck;强制 bugcheck 能写出可读的崩溃转储;休眠 / 恢复可用,或明确记为不支持。

**未决问题 / 风险。**
- 按这个设计,网络系统盘上能否支持崩溃转储和休眠,答案可能是"文档注明的限制"。
- 签名:开发使用测试签名;想在测试网络之外部署的人,需要为自己编译的版本自行取得 Microsoft attestation 签名。本项目不发布任何正式签名的二进制文件。

### 测试环境

- **虚拟化:** QEMU / KVM 加 OVMF(UEFI),Secure Boot 关闭;网卡用 virtio 还是 e1000e,取决于启动期网卡驱动这条线需要什么。
- **Windows:** 开启测试签名(`bcdedit /set testsigning on`);被调试虚拟机通过串口接 WinDbg,或在**另一块**网卡上用 KDNET(调试流量不要和被测网卡混用)。
- **Ceph:** 小型测试集群,例如用 cephadm 部署的单机集群,3 个 OSD 放在文件或 loop 设备上,建一个副本存储池给 RBD。足够测试 CRUSH 和 map 变化;之后再用一个多机集群做故障测试。使用专用的 cephx 实体,权限限定在测试存储池。
- **标准答案:** 一台 Linux 机器用 krbd 映射同样的镜像;用 `ceph osd map`、`crushtool --test`、`rbd info` 作对照。
- **PXE 侧:** dnsmasq 或类似工具,提供 DHCP 以及 iPXE 二进制和脚本的 TFTP / HTTP。
- **物理机:** 同一测试局域网里一台闲置的 UEFI 电脑,用于 Phase 4 和 5,带串口或 KDNET 调试通道。
- 绝不要在存有重要数据的集群上做实验。
