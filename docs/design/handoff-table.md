# Handoff table (DRAFT)

[English](#en) | [中文](#zh)

**Status: DRAFT. Nothing here is implemented or frozen.** Field names, sizes and the signature are placeholders for discussion. The final spec is a Phase 2 deliverable.

---

<a name="en"></a>

## English

### Purpose

After iPXE exposes the RBD image as an EFI_BLOCK_IO disk and Windows starts, iPXE and its network stack are gone (after `ExitBootServices` they are not usable). The boot-start Windows driver has to find and open the same image on its own. The handoff table is how the loader tells it what to open. It plays the role iBFT plays for iSCSI boot.

### Mechanism (checked against the pinned iPXE tree)

- iPXE already has a generic mechanism for such tables: a driver embeds an ACPI descriptor, supplies a "complete" callback (returns "try again" until the data is known) and an "install" callback that builds an ACPI table. `src/net/aoe.c` (aBFT) is the smallest example; `src/drivers/block/ibft.c` the larger one.
- On EFI the table is installed through the firmware's ACPI table protocol. iPXE **overwrites the OEM ID and OEM table ID** in the table header, so our table cannot rely on those; it is identified by its **4-character signature** and by fields in the body.
- If the firmware lacks the ACPI table protocol, iPXE's EFI block hook (`efi_block_describe`) returns "not supported", which makes the whole `sanhook` / `sanboot` of the device fail, not just the table; such firmware cannot use this design as is.
- `efi_block_describe` uninstalls every ACPI table it installed earlier and installs them all again on each description pass (for example when a path is re-described), so the table must be rebuilt idempotently from current state each time.

### Open questions

- **Signature.** A 4-character value that collides with no registered ACPI signature and no existing boot-firmware table. Not chosen. (Placeholder below: `XXXX`.)
- How does a boot-start Windows driver read an unknown ACPI table early in boot? Not yet established; needs Microsoft documentation and an experiment.
- Does Windows tolerate the OEM fields iPXE forces?
- Does the boot-critical enumeration of the NIC need more than MAC and IP (PCI location, driver hints)?
- Read access control: Windows may expose firmware tables through its firmware-table APIs to user-mode processes. Whether an unprivileged process can read this table (and so the key) is not established.

### Proposed fields (all little-endian)

ACPI standard header first (signature, length, revision, checksum, OEM fields as set by iPXE), then:

| Field | Size | Meaning |
|---|---|---|
| version | u16 | Handoff layout version, starting at 1. Readers must refuse versions they do not know. |
| flags | u32 | See flags below. |
| header_length | u16 | Length of the fixed part, so later versions can append fields. |
| nic_mac | 6 bytes | MAC of the NIC iPXE used. |
| nic_flags | u16 | DHCP vs static, VLAN present, IPv4 / IPv6. |
| nic_vlan | u16 | VLAN id, if present. |
| nic_ip, prefix, gateway, dns | per family | IP configuration to bring up the same NIC, like the NIC block of iBFT. |
| nic_mtu | u16 | MTU in use. |
| mon_count | u8 | Number of monitor addresses. |
| mon_addrs | list | Monitor addresses with port (msgr2). Offsets into the strings area. |
| auth_mode | u8 | none / cephx. |
| entity | string offset | cephx entity name (for example `client.winrbd-boot`). |
| key_mode | u8 | How the key is provided; see the security note. |
| key | bytes | Key or ticket material, depending on `key_mode`. |
| fsid | 16 bytes | Cluster fsid (optional, lets the driver sanity-check what it connects to). |
| pool_name / pool_id | string / i64 | Pool of the image header. |
| namespace | string offset | RBD namespace (empty if none). |
| image_name | string offset | Image name. |
| image_id | string offset | Image id if known (optional). |
| snapshot | string offset | Snapshot name; empty for head. |
| msgr_mode | u8 | Preferred connection mode (crc / secure). |
| strings area | bytes | Variable-length strings referenced by offset. |

Flags (draft): bit 0 = image opened read-only by the loader; bit 1 = key present in table; bit 2 = NIC configuration is static, not DHCP.

Disk identity: the driver must present the disk so Windows finds the boot volume. Whether the table also needs to carry the disk signature / GPT disk GUID, or whether the driver reads it from the image itself, is open (reading it from the image is the likely answer).

### Security note: the key is readable by the OS administrator

ACPI tables are part of memory the operating system can read. Anything in this table, including a cephx key, **must be assumed readable by an administrator of the booted OS** and possibly by any code running in the kernel. Consequences and mitigations to be decided:

- Use a **dedicated cephx entity per boot image or per machine**, with capabilities limited to the one pool / namespace (and operations) it needs, so that leaking it exposes only that image.
- Consider handing over **short-lived ticket material** instead of the long-term secret, if the protocol allows it (open question).
- Alternatively keep the long-term key out of the table and obtain it another way (for example a second request from the driver to an enrolment service). Not designed.
- Do not log the key, ever. Do not commit keys to this repository; the `.gitignore` excludes common key file names, but that is a safety net, not a policy.
- Any code that runs after the loader in the same boot session (including a chain-loaded OS) can read the table. The boot script that carries the key into the loader needs protecting too, and a key sent in plain text during the DHCP / boot stage can be captured on the network.

This is a research project aimed at test networks; this design does not claim to protect a production secret.

---

<a name="zh"></a>

## 中文

**状态:草案。这里的内容没有实现,也没有定稿。** 字段名、大小和签名都只是供讨论的占位。正式规格是 Phase 2 的交付物。

### 用途

iPXE 把 RBD 镜像以 EFI_BLOCK_IO 磁盘的形式提供出来、Windows 开始启动之后,iPXE 和它的网络栈就不在了(`ExitBootServices` 之后不可用)。启动期的 Windows 驱动必须自己找到并打开同一个镜像。交接表就是启动加载器告诉它"该打开什么"的方式,作用相当于 iSCSI 启动里的 iBFT。

### 机制(已对照固定版本的 iPXE 源码核实)

- iPXE 已有生成这类表的通用机制:驱动内嵌一个 ACPI 描述符,提供一个 "complete" 回调(数据未就绪时返回"稍后再试")和一个构造 ACPI 表的 "install" 回调。`src/net/aoe.c`(aBFT)是最小的例子,`src/drivers/block/ibft.c` 是较大的例子。
- 在 EFI 下,表经固件的 ACPI 表协议安装。iPXE 会**改写表头里的 OEM ID 和 OEM table ID**,所以我们的表不能依赖这两个字段,只能靠 **4 字符签名**和表体里的字段来识别。
- 如果固件没有 ACPI 表协议,iPXE 的 EFI 块设备挂接(`efi_block_describe`)会返回"不支持",该设备的整个 `sanhook` / `sanboot` 都会失败,而不只是少一张表;这类固件无法照现在的设计使用。
- `efi_block_describe` 每次描述(例如重新描述某条路径)时,都会先卸载自己之前安装的所有 ACPI 表再全部重装,所以这张表必须每次都能根据当前状态幂等地重建。

### 未决问题

- **签名。** 要一个 4 字符值,不与任何已注册的 ACPI 签名和现有启动固件表冲突。尚未选定。(下表占位:`XXXX`。)
- 启动期 Windows 驱动如何在启动早期读取一个陌生的 ACPI 表?尚未搞清楚,需要查 Microsoft 文档并做实验。
- Windows 能否容忍 iPXE 强制写入的 OEM 字段?
- 启动关键的网卡枚举,除 MAC 和 IP 之外是否还需要更多信息(PCI 位置、驱动提示)?
- 读取权限:Windows 可能通过固件表 API 把固件表提供给用户态进程。无特权进程能否读到这张表(进而读到密钥),尚未确认。

### 拟定字段(均为小端)

先是 ACPI 标准头(签名、长度、版本、校验和,OEM 字段由 iPXE 设置),然后是:

| 字段 | 大小 | 含义 |
|---|---|---|
| version | u16 | 交接表布局版本,从 1 开始。读取方遇到不认识的版本必须拒绝。 |
| flags | u32 | 见下方标志位。 |
| header_length | u16 | 固定部分的长度,便于以后版本追加字段。 |
| nic_mac | 6 字节 | iPXE 使用的网卡 MAC。 |
| nic_flags | u16 | DHCP 还是静态、是否有 VLAN、IPv4 / IPv6。 |
| nic_vlan | u16 | VLAN id(若有)。 |
| nic_ip、prefix、gateway、dns | 按地址族 | 让同一块网卡重新起来所需的 IP 配置,类似 iBFT 的网卡块。 |
| nic_mtu | u16 | 使用中的 MTU。 |
| mon_count | u8 | mon 地址数量。 |
| mon_addrs | 列表 | mon 地址和端口(msgr2),为指向字符串区的偏移。 |
| auth_mode | u8 | 无 / cephx。 |
| entity | 字符串偏移 | cephx 实体名(例如 `client.winrbd-boot`)。 |
| key_mode | u8 | 密钥如何提供;见安全说明。 |
| key | 字节 | 密钥或 ticket 材料,取决于 `key_mode`。 |
| fsid | 16 字节 | 集群 fsid(可选,便于驱动核对连的是不是预期的集群)。 |
| pool_name / pool_id | 字符串 / i64 | 镜像头部所在的存储池。 |
| namespace | 字符串偏移 | RBD 命名空间(没有则为空)。 |
| image_name | 字符串偏移 | 镜像名。 |
| image_id | 字符串偏移 | 镜像 id(已知则填,可选)。 |
| snapshot | 字符串偏移 | 快照名;为空表示 head。 |
| msgr_mode | u8 | 首选连接模式(crc / secure)。 |
| 字符串区 | 字节 | 按偏移引用的变长字符串。 |

标志位(草案):bit 0 = 启动加载器以只读方式打开了镜像;bit 1 = 表中带有密钥;bit 2 = 网卡配置为静态而非 DHCP。

磁盘标识:驱动呈现磁盘的方式必须让 Windows 找得到启动卷。表里是否还要携带磁盘签名 / GPT 磁盘 GUID,还是由驱动直接从镜像里读,尚未决定(很可能是从镜像里读)。

### 安全说明:密钥操作系统管理员可读

ACPI 表属于操作系统可以读取的内存。放进这张表的任何东西,包括 cephx 密钥,**都必须假定已启动系统的管理员可读**,内核里运行的任何代码也可能读到。后果与待定的缓解办法:

- 为**每个启动镜像或每台机器使用专用的 cephx 实体**,权限限定在它需要的那一个存储池 / 命名空间(以及那几种操作),这样泄漏只暴露那一个镜像。
- 如果协议允许,考虑交接**短期有效的 ticket 材料**,而不是长期密钥(未决)。
- 或者不把长期密钥放进表里,改由别的途径获取(例如驱动再向一个登记服务发一次请求)。尚未设计。
- 任何情况下都不要记录密钥日志。不要把密钥提交进本仓库;`.gitignore` 排除了常见的密钥文件名,但那只是兜底,不是规则。
- 在加载器之后、同一次启动会话里运行的任何代码(包括被链式加载的操作系统)都能读到这张表。把密钥带进加载器的启动脚本也需要保护;在 DHCP / 启动阶段以明文发送的密钥可能在网络上被截获。

这是一个面向测试网络的研究项目;这个设计并不声称能保护生产环境的密钥。
