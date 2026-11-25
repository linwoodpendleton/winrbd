# Handoff table, version 1

[English](#en) | [中文](#zh)

**Status: version 1, implemented.** The layout below is the one the codec in `core/src/handoff/` reads and writes (public interface `core/include/winrbd/wr_handoff.h`), checked byte for byte against the golden vectors in `harness/vectors/handoff/`. The decisions behind it are in [ipxe-driver.md](ipxe-driver.md) section 9. What no test could establish (how a Windows boot-start driver reads the table, and Windows' behaviour towards the OEM fields) is marked **unverified** and is listed at the end.

---

<a name="en"></a>

## English

### Purpose

After iPXE exposes the RBD image as an EFI_BLOCK_IO disk (or an INT 13h drive) and the operating system starts, iPXE and its network stack are gone (after `ExitBootServices` they are not usable). The boot-start Windows driver has to find and open the same image on its own. The handoff table is how the loader tells it what to open. It plays the role iBFT plays for iSCSI boot (`aBFT` for AoE, `sBFT` for SRP).

### Mechanism (checked against the pinned iPXE tree)

- iPXE already has a generic mechanism for such tables: a driver embeds an ACPI descriptor, supplies a "complete" callback (returns "try again" until the data is known) and an "install" callback that builds an ACPI table. `src/net/aoe.c` (aBFT) is the smallest example; `src/drivers/block/ibft.c` the larger one.
- On EFI the table is installed through the firmware's ACPI table protocol; on BIOS it goes into the resident `xbftab` area. iPXE **overwrites the OEM ID and OEM table ID** of every table it installs (`efi_block_install`, `int13_install`) and fixes the checksum afterwards, so our table cannot rely on those fields; it is identified by its signature, its checksum and a magic at the start of its body.
- If the firmware lacks the ACPI table protocol, iPXE's EFI block hook (`efi_block_describe`) returns "not supported", which makes the whole `sanhook` / `sanboot` of the device fail, not just the table (the boot script then uses `sanboot --no-describe`, without a table).
- `efi_block_describe` uninstalls every ACPI table it installed earlier and installs them all again on each description pass, and `int13_describe` zeroes its area and installs again, so the table is **rebuilt from current state every time** (see "Rebuilt on every describe pass").

### Identity

- **ACPI signature `rBFT`** ("RBD boot firmware table"), in the family `iBFT` / `aBFT` / `sBFT` that iPXE installs. Checked, and recorded here:
  - no other `ACPI_SIGNATURE ( ... )` in the pinned iPXE tree (`9261ebe38`) uses it (it defines `AMAC MACA RTMA SPCR MCFG iBFT RSDT XSDT FACP DSDT SSDT sBFT aBFT _S5_`);
  - it is not among the 78 distinct `ACPI_SIG_*` signatures of the ACPICA headers of a Linux 5.15 tree (`include/acpi/actbl.h`, `actbl1.h` to `actbl3.h`), and the string `rBFT` occurs nowhere in `include/` or `drivers/acpi/` of that tree. (The ACPICA list is spelled `IBFT`, with a capital I; signatures are compared byte for byte.)
  - **Unverified:** that Microsoft does not reserve it privately (their list is not public), and what a Windows guest shows for it. What a Linux guest in QEMU shows for it is seen in the Phase 2 matrix (see "Where the consumer finds it" below).
- **Body magic `WRBT`** at the start of the body. A table is recognised by signature, checksum **and** magic.
- ACPI header `revision` = 1. The version of the *layout* is its own field, below.

### The OEM-field rule

Nothing depends on the OEM ID, OEM table ID, OEM revision, creator ID or creator revision (header bytes 10 to 35): iPXE writes its own. The encoder leaves them **zero**; a consumer **must not interpret them**; a decoder ignores them. A host that writes them (iPXE does, "FENSYS" / "iPXE") must recompute the checksum afterwards (`wr_handoff_fix_checksum`, in iPXE `acpi_fix_checksum`; it takes the length field as its length and refuses one over the 1,024-byte maximum). The checksum covers all bytes of the table, so a table whose OEM fields were changed without fixing it is refused.

### Layout (little-endian, packed)

The table is the **ACPI header (36 bytes)**, then the **body**: a fixed part of **116 bytes** (`header_len`), then the variable area.

ACPI header:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | signature | `r B F T` |
| 4 | 4 | length | the whole table, header included; at most 1,024 |
| 8 | 1 | revision | 1 |
| 9 | 1 | checksum | all bytes of the table sum to 0 modulo 256 |
| 10 | 6 | oem_id | zero from the encoder; the host's |
| 16 | 8 | oem_table_id | zero from the encoder; the host's |
| 24 | 4 | oem_revision | zero from the encoder; the host's |
| 28 | 4 | creator_id | zero from the encoder; the host's |
| 32 | 4 | creator_revision | zero from the encoder; the host's |

Body, fixed part (offsets from the start of the body). All offsets in it are relative to the start of the variable area (`header_len` after the body start); `0xffff` means absent.

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | magic | `W R B T` |
| 4 | 2 | version | 1. A reader refuses a version it does not know. |
| 6 | 2 | header_len | 116 in version 1. A later version appends fixed fields and says so here and in `version`; a reader of that version skips to `header_len`. |
| 8 | 4 | flags | bit0 read-only open; bit1 key present; bit2 NIC static (not DHCP); bit3 VLAN present; bit4 fsid valid; bit5 secure required; all other bits zero |
| 12 | 1 | auth | 0 none, 1 cephx |
| 13 | 1 | msgr_mode | `WR_MODE_CRC_ONLY` 1, `CRC_FIRST` 2, `SECURE_FIRST` 3, `SECURE_ONLY` 4 (not 5, "stock") |
| 14 | 1 | key_type | 0 none, 1 `aes` (`WR_KEY_TYPE_AES`), 2 `aes256k` (`WR_KEY_TYPE_AES256K`) |
| 15 | 1 | key_len | bytes of key: 0 without a key; with one 16 to 64 for `aes`, 32 to 64 for `aes256k` (the floor of `wr_key_from_raw`) |
| 16 | 1 | mon_count | 1 to 8 |
| 17 | 1 | nic_family | 4, 6, or 0 if unknown |
| 18 | 1 | nic_prefix | prefix length of nic_ip: at most 32 (4) or 128 (6); 0 if the family is 0 |
| 19 | 1 | reserved | 0 |
| 20 | 16 | fsid | zero unless the fsid-valid flag |
| 36 | 6 | nic_mac | MAC of the NIC iPXE used |
| 42 | 2 | nic_vlan | VLAN id 1 to 4094 with the VLAN flag, else 0 |
| 44 | 2 | nic_mtu | MTU in use, 0 if unknown |
| 46 | 2 | reserved | 0 |
| 48 | 16 | nic_ip | network order; an IPv4 address in the first four bytes, the rest zero |
| 64 | 16 | nic_gateway | same |
| 80 | 16 | nic_dns | same |
| 96 | 2 | off_entity | cephx user id (as in `wr_cluster_spec.user`, without `client.`), NUL-terminated string; required with cephx |
| 98 | 2 | off_pool | pool of the image; required |
| 100 | 2 | off_namespace | RBD namespace: **absent in version 1** (a writer never sets it, a reader refuses a table that does) |
| 102 | 2 | off_image | image name; required |
| 104 | 2 | off_image_id | absent unless known |
| 106 | 2 | off_snapshot | absent for the head |
| 108 | 2 | off_mons | `mon_count` records of 20 bytes: `{u8 family (4 or 6), u8 reserved 0, u16 port (not 0), u8 ip[16]}` |
| 110 | 2 | off_key | `key_len` bytes, or `0xffff` (exactly when the key flag is clear) |
| 112 | 4 | reserved | 0 |

Variable area, **canonical form** (the only form the encoder writes and the decoder accepts):

1. the strings, each followed by its NUL, in the order entity, pool, namespace, image, image id, snapshot; an absent string takes no space (an optional string is absent, never present-but-empty);
2. the `mon_count` monitor records;
3. the key bytes, if the key flag is set;

with **no padding, no gaps and nothing after the key**. Strings are meant to be UTF-8 and are at most 255 bytes plus the NUL; the codec checks the framing (length, terminator, place) and not the encoding, so a reader that needs valid UTF-8 checks it itself. The offsets in the fixed part are therefore a function of the contents; they exist so that a later version can reorder or add parts without breaking the readers of version 1, which check them rather than trust them.

### Field rules

Both the encoder (input) and the decoder (what it read) enforce these; a violation is `WR_E_HO_FIELD` unless stated:

- flags: only bits 0 to 5. Bit5 (secure required) needs `msgr_mode` 4, so that "required" and the offered mode cannot disagree. Bit2 (static) needs a NIC family. Bit3 (VLAN) needs `nic_vlan` 1 to 4094; without it `nic_vlan` is 0. Bit4 (fsid valid): without it the fsid is all zero.
- auth 0 or 1; entity is required with cephx. pool and image are always required and not empty.
- key: **present exactly when bit1 is set**. Then auth is cephx, `key_type` is 1 or 2, `key_len` is 16 to 64 (`aes`) or 32 to 64 (`aes256k`), the same floor `wr_key_from_raw` applies, so a table never carries a key the core would refuse later and the error is named here, and the bytes are there; the offset is set. Without the flag `key_type`, `key_len` and the offset are 0 / 0 / absent: a description that carries key bytes without the flag is **refused, not silently dropped** (and never written).
- mon_count 1 to 8; every record has family 4 or 6, a non-zero port, a reserved byte 0, and for IPv4 bytes 4 to 15 of the address zero. The table always carries the real port: a host whose monitor list leaves the port 0 ("default 3300" in `wr_cluster_spec`) fills the default in before it encodes, because the encoder refuses a port 0 rather than guess.
- nic_family 0, 4 or 6; with 0 the prefix and the three addresses are zero; IPv4 addresses have bytes 4 to 15 zero.
- namespace: `WR_E_UNSUPPORTED` if present.
- all reserved bytes zero (a decoder refuses a table with reserved bytes set: they belong to a later version).

### Content rules

- **Always**: identity (entity, monitors, pool, image, mode, flags) and the NIC of the first monitor's route: MAC, VLAN, MTU, address, prefix, gateway, DNS (from `tcpip_netdev()` of the first monitor and the settings of that device).
- **The key only on request.** `handoff=key` (or an equivalent explicit setting) sets bit1 and the key bytes; the default `nokey` carries everything else, so a leak of the table exposes an image *name*, not a credential. The codec enforces it: the key goes in only when bit1 is set, and bit1 without a key (or a key without bit1) is a refusal.
- `handoff=none` installs no table at all (the descriptor is not registered).
- Ticket material instead of the long-term key: not in version 1 (cephx tickets are bound to the session key; a driver cannot use them without the exchange).
- The monitors are literal addresses (the core does no name resolution); the NIC block is what the same NIC needs to come up again.

### Rebuilt on every describe pass, and byte-identical

`efi_block_describe()` uninstalls all tables it installed earlier and installs again, on every call (on hook, and whenever a path is re-described after a reopen); `int13_describe()` zeroes its area and installs again. The model's `install` callback therefore **builds each table from the device's current state and keeps nothing between calls**: monitors, user and names from the session's spec, the NIC from the route and the netdev's settings *at that moment*, the key from the spec.

The codec makes this a property it guarantees: **encoding is a pure function of the description**. The same `wr_handoff_info` gives the same bytes on every call and from any buffer content; no field of the output depends on anything else (no time, no counter, no padding left over from the buffer: every byte is written). A description with garbage in the parts the layout does not use (monitor slots beyond `mon_count`, the nonce of a monitor, bytes after a string's NUL) gives the same bytes. It builds the whole table before writing a byte, so a refused table leaves the caller's buffer untouched. Tested: two encodes, an encode into a dirty buffer, an encode after 50 other encodes (unit test, harness), golden vectors byte for byte, and the same bytes decoded and encoded again.

`complete()` returns `-EINPROGRESS` until the image is open and the NIC route is known, so `sandev_describe` waits (the DHCP-not-finished case of the iBFT).

### Size

With three monitors, short names and no key the whole table is about 240 bytes; with a 32-byte key about 270. The **design maximum is 1,024 bytes for the whole table, ACPI header included** (the body is at most 988): the encoder **refuses** a larger one with `WR_E_HO_TOO_BIG` (and the size it would have needed), never truncates, and the decoder refuses a table or body over the cap. The cap can be reached only with 255-byte names, eight monitors and a key together; there is a golden vector of exactly 1,024 bytes and one of 1,025. On BIOS `XBFTAB_SIZE` is 768 in stock iPXE and holds the typical table but not the maximum next to an iBFT; patch 0002 makes it 2,048.

### Where the consumer finds it, and what it checks

- **UEFI**: through the ACPI table protocol, in the XSDT: Linux `/sys/firmware/acpi/tables/rBFT` (and `acpidump`); Windows: firmware table APIs, **unverified** that a boot-start driver can read an unknown signature this early and that the OEM fields iPXE forces are tolerated. **Seen in a Linux guest** (OVMF, driver of the Phase 2 matrix): the table is at `/sys/firmware/acpi/tables/rBFT`, 218 bytes without the key, 234 with it, 237 to 248 with the longer image names of the test images; iPXE wrote `FENSYS` / `iPXE` into the OEM fields and a correct checksum, and the guest's decoder accepted it; all 40 fields of the check (signature, length, checksum, magic, version, every rule, the entity, pool, image, image id, monitor, mode, the NIC's MAC, address, prefix, gateway) agreed with the values the boot script was given.
- **BIOS**: not in an RSDT; in the resident `xbftab` area, found by scanning for the signature and a valid checksum. **Seen in a Linux guest** (SeaBIOS): the scan of the guest finds exactly one valid table, in the data16 area of iPXE (an address that differs per binary), and the same 40 fields agree; the area is 2,048 bytes (patch 0002), of which one table uses 11 to 12 %.
- **What a consumer does**: `wr_handoff_decode_table()` on the bytes it found (the buffer may be larger than the table: bytes after the header's `length` are ignored). It checks, in this order: at least 36 bytes, signature, `length` (at least 152, at most 1,024, at most what it was given), revision 1, checksum, then body magic, `version` 1, `header_len` 116, the field rules, the offsets, the NULs, and the canonical layout. Any failure leaves the output structure zeroed. After a success the strings and the key point into the buffer; the consumer copies what it keeps and wipes its copy of the key. The checks hold for the bytes as they were read: where other code can still change the buffer (firmware memory), the consumer decodes a private copy of the table, not the original.
- **Read access control**: whether an unprivileged Windows process can read the table through the firmware table APIs (and so see a key) is **unverified**; assume yes.

### Disk identity

The table does not carry the disk signature or GPT disk GUID: the driver reads them from the image itself.

### Versioning

`version` 1 is this document. A reader refuses a version it does not know (`WR_E_HO_VERSION`) and a `header_len` that is not the one of its version (`WR_E_HO_LENGTH`). Changing the meaning of a field, adding a flag or reordering the area needs a new version, because version 1 readers refuse unknown flag bits and reserved bytes that are not zero on purpose.

### The codec

`core/include/winrbd/wr_handoff.h`: `wr_handoff_encode` (the body), `wr_handoff_encode_table` (the whole ACPI table, OEM fields zero), `wr_handoff_fix_checksum`, `wr_handoff_decode` (body) and `wr_handoff_decode_table`; a `wr_handoff_info` describes a table in both directions. Portable C99, freestanding, MIT, no allocation, no globals. Statuses (`WR_E_HO_*`, 240 to 247): `SIGNATURE`, `VERSION`, `LENGTH`, `CHECKSUM`, `OFFSET`, `FIELD`, `TOO_BIG`, `LAYOUT`, plus the generic `WR_E_TRUNCATED`, `WR_E_TOOBIG` (buffer too small), `WR_E_UNSUPPORTED` (namespace) and `WR_E_INVAL`. Tests: `harness/test/test_handoff.c` (layout byte by byte, round trips of every field, pure-function and size-cap checks, every refusal, truncation at every length, every single-bit flip, random damage with a repaired checksum), `harness/test/test_handoff_vec.c` (the golden vectors of `harness/vectors/handoff/`, generated by an independent Python implementation), `harness/fuzz/fuzz_handoff.c` (libFuzzer; the seeds in `harness/fuzz/seeds/fuzz_handoff/` run as a ctest).

### Security note: the key is readable by the OS administrator

ACPI tables are part of memory the operating system can read. Anything in this table, including a cephx key, **must be assumed readable by an administrator of the booted OS** and possibly by any code running in the kernel. Consequences and mitigations:

- Use a **dedicated cephx entity per boot image or per machine**, with capabilities limited to the one pool / namespace (and operations) it needs, so that leaking it exposes only that image; rotate it (`ceph auth rm`) as for a key embedded on boot media.
- The default is `nokey`: the table then carries no credential. A boot-start driver that needs the key gets it from the table (`handoff=key`, explicit opt-in) or from another channel (**not designed**; an enrolment-service idea stays a note).
- Do not log the key, ever (the codec never formats it; the iPXE glue never prints it). Do not commit keys to this repository.
- `nokey` keeps the key out of the table, **not out of memory**: while the session lives, the core's arena holds the cephx key and the session keys, and the iPXE driver does not wipe the session when the loader takes over. On BIOS the INT 13h path keeps working after iPXE's shell is gone, and the block stays resident (hidden from the OS memory map) with the key in it; on UEFI the block is boot-services memory, which the OS reclaims at `ExitBootServices` as it finds it (what the firmware does with it is **unverified**). An administrator of the booted OS who can read physical memory, or a memory dump of the boot session, may find the key there even when the table has none. Nothing in the driver changes that today (the same mitigation applies: a dedicated cephx entity per image, revoked when the machine is lost or retired).
- Any code that runs after the loader in the same boot session (including a chain-loaded OS) can read the table. The boot script that carries the key into the loader needs protecting too, and a key sent in plain text during the DHCP / boot stage can be captured on the network.
- The checksum is for accident, not for authenticity: anyone who can write the table can fix it.

This is a research project aimed at test networks; this design does not claim to protect a production secret.

### Unverified

- How a Windows boot-start driver reads an unknown ACPI table this early, and whether Windows tolerates the OEM fields iPXE forces. (WinPE booted with the table installed, on UEFI and on BIOS, so the boot manager and WinPE start do not mind it; WinPE has no `rbd` driver in Phase 2, so nothing in Windows read the table.)
- Whether an unprivileged Windows process can read the table.
- Whether Microsoft reserves `rBFT` privately. (Resolved in part: Linux guests under QEMU show the table as described above, on UEFI and on BIOS.)
- Whether the boot-critical enumeration of the NIC needs more than MAC, VLAN, MTU and addresses (PCI location, driver hints): not in version 1.

---

<a name="zh"></a>

## 中文

**状态:第 1 版,已实现。** 下面的布局就是 `core/src/handoff/` 里的编解码器读写的布局(公开接口 `core/include/winrbd/wr_handoff.h`),并已逐字节对照 `harness/vectors/handoff/` 里的黄金向量。设计决定见 [ipxe-driver.md](ipxe-driver.md) 第 9 节。测试无法确认的内容(Windows 启动期驱动如何读取这张表、Windows 对 OEM 字段的态度)标为**未验证**,列在文末。

### 用途

iPXE 把 RBD 镜像以 EFI_BLOCK_IO 磁盘(或 INT 13h 驱动器)的形式提供出来、操作系统开始启动之后,iPXE 和它的网络栈就不在了(`ExitBootServices` 之后不可用)。启动期的 Windows 驱动必须自己找到并打开同一个镜像。交接表就是启动加载器告诉它"该打开什么"的方式,作用相当于 iSCSI 启动里的 iBFT(AoE 的 `aBFT`、SRP 的 `sBFT`)。

### 机制(已对照固定版本的 iPXE 源码核实)

- iPXE 已有生成这类表的通用机制:驱动内嵌一个 ACPI 描述符,提供 "complete" 回调(数据未就绪时返回"稍后再试")和构造 ACPI 表的 "install" 回调。`src/net/aoe.c`(aBFT)是最小的例子,`src/drivers/block/ibft.c` 是较大的例子。
- 在 EFI 下表经固件的 ACPI 表协议安装;在 BIOS 下放进驻留的 `xbftab` 区。iPXE 会**改写它安装的每张表的 OEM ID 和 OEM table ID**(`efi_block_install`、`int13_install`),然后重算校验和,所以我们的表不能依赖这些字段;表靠签名、校验和以及表体开头的魔数识别。
- 固件没有 ACPI 表协议时,iPXE 的 EFI 块设备挂接(`efi_block_describe`)返回"不支持",该设备的整个 `sanhook` / `sanboot` 都会失败,而不只是少一张表(此时启动脚本改用 `sanboot --no-describe`,没有交接表)。
- `efi_block_describe` 每次描述都会先卸载自己之前装的所有 ACPI 表再全部重装,`int13_describe` 会清零自己的区域再重装,所以这张表**每次都根据当前状态重建**(见"每次描述都重建")。

### 标识

- **ACPI 签名 `rBFT`**("RBD boot firmware table"),与 iPXE 已安装的 `iBFT` / `aBFT` / `sBFT` 同族。已核对并记录:
  - 固定版本 iPXE(`9261ebe38`)里没有其他 `ACPI_SIGNATURE ( ... )` 用它(iPXE 定义了 `AMAC MACA RTMA SPCR MCFG iBFT RSDT XSDT FACP DSDT SSDT sBFT aBFT _S5_`);
  - 它不在 Linux 5.15 内核树 ACPICA 头文件(`include/acpi/actbl.h`、`actbl1.h` 到 `actbl3.h`)的 78 个不同的 `ACPI_SIG_*` 签名里,字符串 `rBFT` 也不出现在该树的 `include/` 和 `drivers/acpi/` 中。(ACPICA 里写的是 `IBFT`,首字母大写;签名按字节比较。)
  - **未验证:** Microsoft 是否私下保留了它(其名单不公开),以及 Windows 客户机看到它时的表现。Linux 客户机在 QEMU 里的表现已在第二阶段矩阵里看到(见下面"使用方在哪里找到它")。
- **表体魔数 `WRBT`** 在表体开头。识别一张表要同时看签名、校验和**和**魔数。
- ACPI 头的 `revision` = 1。**布局**的版本是下面它自己的字段。

### OEM 字段规则

没有任何东西依赖 OEM ID、OEM table ID、OEM revision、creator ID 和 creator revision(头部第 10 到 35 字节):iPXE 会写自己的值。编码器把它们留为**零**;使用方**不得解释它们**;解码器忽略它们。写这些字段的宿主(iPXE 就会,"FENSYS" / "iPXE")事后**必须重算校验和**(`wr_handoff_fix_checksum`,iPXE 里是 `acpi_fix_checksum`;它以长度字段为长度,并拒绝超过 1,024 字节上限的长度)。校验和覆盖整张表的所有字节,所以改了 OEM 字段却没重算校验和的表会被拒绝。

### 布局(小端、紧凑排列)

整张表 = **ACPI 头(36 字节)** + **表体**:**116 字节**的固定部分(`header_len`),然后是变长区。

ACPI 头:

| 偏移 | 大小 | 字段 | 值 |
|---|---|---|---|
| 0 | 4 | signature | `r B F T` |
| 4 | 4 | length | 整张表的长度(含头),最大 1,024 |
| 8 | 1 | revision | 1 |
| 9 | 1 | checksum | 整张表所有字节之和模 256 为 0 |
| 10 | 6 | oem_id | 编码器写零;归宿主 |
| 16 | 8 | oem_table_id | 编码器写零;归宿主 |
| 24 | 4 | oem_revision | 编码器写零;归宿主 |
| 28 | 4 | creator_id | 编码器写零;归宿主 |
| 32 | 4 | creator_revision | 编码器写零;归宿主 |

表体固定部分(偏移从表体开头算)。其中所有偏移都相对变长区起点(表体开头之后 `header_len` 处),`0xffff` 表示没有。

| 偏移 | 大小 | 字段 | 含义 |
|---|---|---|---|
| 0 | 4 | magic | `W R B T` |
| 4 | 2 | version | 1。读取方遇到不认识的版本必须拒绝。 |
| 6 | 2 | header_len | 第 1 版为 116。以后的版本在固定部分追加字段,并在这里和 `version` 中体现;该版本的读取方跳到 `header_len`。 |
| 8 | 4 | flags | bit0 只读打开;bit1 带密钥;bit2 网卡为静态配置(非 DHCP);bit3 有 VLAN;bit4 fsid 有效;bit5 要求 secure;其余位为零 |
| 12 | 1 | auth | 0 无,1 cephx |
| 13 | 1 | msgr_mode | `WR_MODE_CRC_ONLY` 1、`CRC_FIRST` 2、`SECURE_FIRST` 3、`SECURE_ONLY` 4(没有 5,即 "stock") |
| 14 | 1 | key_type | 0 无,1 `aes`(`WR_KEY_TYPE_AES`),2 `aes256k`(`WR_KEY_TYPE_AES256K`) |
| 15 | 1 | key_len | 密钥字节数:没有密钥时为 0;有密钥时 `aes` 为 16 到 64,`aes256k` 为 32 到 64(与 `wr_key_from_raw` 的下限一致) |
| 16 | 1 | mon_count | 1 到 8 |
| 17 | 1 | nic_family | 4、6,未知为 0 |
| 18 | 1 | nic_prefix | nic_ip 的前缀长度:IPv4 最大 32、IPv6 最大 128;family 为 0 时为 0 |
| 19 | 1 | reserved | 0 |
| 20 | 16 | fsid | 没有 fsid 有效标志时为零 |
| 36 | 6 | nic_mac | iPXE 使用的网卡 MAC |
| 42 | 2 | nic_vlan | 有 VLAN 标志时为 1 到 4094,否则 0 |
| 44 | 2 | nic_mtu | 使用中的 MTU,未知为 0 |
| 46 | 2 | reserved | 0 |
| 48 | 16 | nic_ip | 网络字节序;IPv4 地址占前四字节,其余为零 |
| 64 | 16 | nic_gateway | 同上 |
| 80 | 16 | nic_dns | 同上 |
| 96 | 2 | off_entity | cephx 用户 id(同 `wr_cluster_spec.user`,不带 `client.`),以 NUL 结尾的字符串;用 cephx 时必须有 |
| 98 | 2 | off_pool | 镜像所在存储池;必须有 |
| 100 | 2 | off_namespace | RBD 命名空间:**第 1 版中不存在**(写入方从不设置,读取方遇到就拒绝) |
| 102 | 2 | off_image | 镜像名;必须有 |
| 104 | 2 | off_image_id | 已知才有 |
| 106 | 2 | off_snapshot | head 时没有 |
| 108 | 2 | off_mons | `mon_count` 条 20 字节记录:`{u8 family(4 或 6), u8 reserved 0, u16 port(不为 0), u8 ip[16]}` |
| 110 | 2 | off_key | `key_len` 字节,或 `0xffff`(当且仅当密钥标志未置位) |
| 112 | 4 | reserved | 0 |

变长区的**规范形式**(编码器只写这一种,解码器只接受这一种):

1. 各字符串,每个后面跟一个 NUL,顺序为 entity、pool、namespace、image、image id、snapshot;不存在的字符串不占空间(可选字符串要么不存在,要么非空,不能"存在但为空");
2. `mon_count` 条 mon 记录;
3. 密钥字节(密钥标志置位时);

**没有填充、没有空洞、密钥之后什么都没有。** 字符串应为 UTF-8,最多 255 字节外加 NUL;编解码器检查的是成帧(长度、结尾、位置)而不是编码,需要合法 UTF-8 的读取方要自己检查。因此固定部分里的偏移是内容的函数;保留它们是为了以后的版本能重排或增加部分而不破坏第 1 版的读取方,第 1 版的读取方会校验这些偏移,而不是信任它们。

### 字段规则

编码器(对输入)和解码器(对读到的内容)都执行这些规则,违反即返回 `WR_E_HO_FIELD`(另有说明的除外):

- flags:只允许 bit0 到 bit5。bit5(要求 secure)要求 `msgr_mode` 为 4,避免"要求"与提供的模式矛盾。bit2(静态)要求有网卡 family。bit3(VLAN)要求 `nic_vlan` 为 1 到 4094;没有该标志时 `nic_vlan` 为 0。bit4(fsid 有效):没有它时 fsid 全零。
- auth 为 0 或 1;用 cephx 时必须有 entity。pool 和 image 始终必须有且非空。
- 密钥:**当且仅当 bit1 置位时存在**。此时 auth 为 cephx,`key_type` 为 1 或 2,`key_len` 为 16 到 64(`aes`)或 32 到 64(`aes256k`),与 `wr_key_from_raw` 的下限相同,所以表里不会带着核心之后才会拒绝的密钥,错误在这里就能指明,字节在表里,偏移已设置。没有该标志时 `key_type`、`key_len` 和偏移分别为 0 / 0 / 不存在:描述里带了密钥字节却没有标志,会被**拒绝,而不是悄悄丢掉**(更不会写出去)。
- mon_count 为 1 到 8;每条记录的 family 为 4 或 6,port 非零,保留字节为 0,IPv4 地址的第 4 到 15 字节为零。表里始终写真实端口:监视器列表里端口为 0(`wr_cluster_spec` 中表示"默认 3300")的宿主要在编码之前自己填上默认值,因为编码器对端口 0 是拒绝而不是猜测。
- nic_family 为 0、4 或 6;为 0 时前缀和三个地址都是零;IPv4 地址的第 4 到 15 字节为零。
- namespace:出现则返回 `WR_E_UNSUPPORTED`。
- 所有保留字节为零(解码器拒绝保留字节非零的表:它们属于以后的版本)。

### 内容规则

- **始终携带**:身份(entity、mon、pool、image、模式、标志)以及第一个 mon 所走路由的网卡信息:MAC、VLAN、MTU、地址、前缀、网关、DNS(来自第一个 mon 的 `tcpip_netdev()` 和该设备的设置)。
- **密钥只在明确要求时才带。** `handoff=key`(或等价的明确设置)置位 bit1 并写入密钥字节;默认的 `nokey` 携带其余全部内容,所以表泄漏时暴露的是镜像*名字*,不是凭据。编解码器强制这一点:只有 bit1 置位才写入密钥,bit1 置位却没有密钥(或有密钥没有 bit1)都是拒绝。
- `handoff=none` 完全不安装表(描述符不注册)。
- 用 ticket 材料代替长期密钥:第 1 版不做(cephx ticket 绑定会话密钥,驱动不做密钥交换就用不了)。
- mon 是字面地址(核心不做名字解析);网卡部分是同一块网卡重新起来所需的信息。

### 每次描述都重建,且逐字节相同

`efi_block_describe()` 每次调用(挂接时,以及重新打开后重新描述某条路径时)都先卸载自己之前装的所有表再重装;`int13_describe()` 清零自己的区域再重装。因此模型的 `install` 回调**每次都根据设备当前状态构造表,两次调用之间不保留任何东西**:mon、用户和名字来自会话的规格,网卡来自*此刻*的路由和 netdev 设置,密钥来自规格。

编解码器把这一点作为它保证的性质:**编码是描述的纯函数**。同一个 `wr_handoff_info` 在每次调用、任何缓冲区初始内容下都得到相同的字节;输出的任何字段都不依赖别的东西(没有时间、没有计数器、没有缓冲区里遗留的填充:每个字节都被写入)。描述中布局不使用的部分带有垃圾(超过 `mon_count` 的 mon 槽、mon 的 nonce、字符串 NUL 之后的字节)也得到相同的字节。编码器在写任何字节之前先构建完整个表,所以被拒绝的表不会改动调用方的缓冲区。已测试:两次编码、向脏缓冲区编码、先做 50 次别的编码再编码(harness 单元测试)、逐字节对照黄金向量,以及解码后再编码得到相同字节。

`complete()` 在镜像打开且网卡路由已知之前返回 `-EINPROGRESS`,所以 `sandev_describe` 会等待(与 iBFT 里 DHCP 未完成的情形相同)。

### 大小

三个 mon、较短的名字、没有密钥时整张表约 240 字节;带 32 字节密钥约 270 字节。**设计上限是整张表 1,024 字节,含 ACPI 头**(表体最多 988 字节):编码器遇到更大的表以 `WR_E_HO_TOO_BIG` **拒绝**(并告知需要的大小),绝不截断;解码器拒绝超过上限的表或表体。只有 255 字节的名字、八个 mon 和密钥同时出现才会触顶;有一个恰为 1,024 字节的黄金向量和一个 1,025 字节的拒绝向量。BIOS 下原版 iPXE 的 `XBFTAB_SIZE` 是 768,放得下典型的表,但放不下上限大小的表加一张 iBFT;补丁 0002 把它改成 2,048。

### 使用方在哪里找到它、检查什么

- **UEFI**:通过 ACPI 表协议,在 XSDT 中:Linux 下是 `/sys/firmware/acpi/tables/rBFT`(以及 `acpidump`);Windows:固件表 API,**未验证**启动期驱动能否这么早读到陌生签名的表,以及 iPXE 强制写入的 OEM 字段是否被容忍。**已在 Linux 客户机里看到**(OVMF,第二阶段矩阵的驱动):表在 `/sys/firmware/acpi/tables/rBFT`,不带密钥 218 字节、带密钥 234 字节、测试镜像名字较长时 237 到 248 字节;iPXE 在 OEM 字段写入 `FENSYS` / `iPXE` 并写好校验和,客户机的解码器接受了它;检查的 40 个字段(签名、长度、校验和、魔数、版本、各条规则、用户、池、镜像、镜像 id、monitor、模式、网卡的 MAC、地址、前缀、网关)全部与启动脚本给的值一致。
- **BIOS**:不在 RSDT 里;在驻留的 `xbftab` 区,通过扫描签名和合法校验和找到。**已在 Linux 客户机里看到**(SeaBIOS):客户机的扫描正好找到一张合法的表,位于 iPXE 的 data16 区(地址因二进制而异),同样 40 个字段一致;该区 2,048 字节(补丁 0002),一张表只占 11% 到 12%。
- **使用方怎么做**:对找到的字节调用 `wr_handoff_decode_table()`(缓冲区可以比表大:头部 `length` 之后的字节被忽略)。检查顺序:至少 36 字节、签名、`length`(至少 152、至多 1,024、不超过给定的字节数)、revision 为 1、校验和,然后是表体魔数、`version` 为 1、`header_len` 为 116、字段规则、偏移、NUL、规范布局。任何失败都会把输出结构清零。成功之后字符串和密钥指向缓冲区;使用方复制自己要保留的内容,并擦除密钥的副本。检查只对读到的那些字节成立:如果别的代码还能改动这块缓冲区(固件内存),使用方应对表的私有副本解码,而不是对原件解码。
- **读取权限**:无特权的 Windows 进程能否通过固件表 API 读到这张表(进而读到密钥)**未验证**;按"能"来假定。

### 磁盘标识

表里不携带磁盘签名或 GPT 磁盘 GUID:驱动直接从镜像里读取。

### 版本策略

`version` 1 就是本文档。读取方拒绝不认识的版本(`WR_E_HO_VERSION`)和不是自己版本所用的 `header_len`(`WR_E_HO_LENGTH`)。改变字段含义、增加标志位或重排变长区都需要新版本,因为第 1 版的读取方会特意拒绝未知的标志位和非零的保留字节。

### 编解码器

`core/include/winrbd/wr_handoff.h`:`wr_handoff_encode`(表体)、`wr_handoff_encode_table`(整张 ACPI 表,OEM 字段为零)、`wr_handoff_fix_checksum`、`wr_handoff_decode`(表体)和 `wr_handoff_decode_table`;`wr_handoff_info` 在两个方向上描述一张表。可移植 C99、freestanding、MIT、不分配内存、没有全局变量。状态码(`WR_E_HO_*`,240 到 247):`SIGNATURE`、`VERSION`、`LENGTH`、`CHECKSUM`、`OFFSET`、`FIELD`、`TOO_BIG`、`LAYOUT`,另外用通用的 `WR_E_TRUNCATED`、`WR_E_TOOBIG`(缓冲区太小)、`WR_E_UNSUPPORTED`(namespace)和 `WR_E_INVAL`。测试:`harness/test/test_handoff.c`(逐字节的布局、每个字段的往返、纯函数与大小上限、每一种拒绝、任意长度的截断、每一个单比特翻转、校验和修复后的随机破坏)、`harness/test/test_handoff_vec.c`(`harness/vectors/handoff/` 的黄金向量,由独立的 Python 实现生成)、`harness/fuzz/fuzz_handoff.c`(libFuzzer;`harness/fuzz/seeds/fuzz_handoff/` 里的种子作为 ctest 回放)。

### 安全说明:密钥操作系统管理员可读

ACPI 表属于操作系统可以读取的内存。放进这张表的任何东西,包括 cephx 密钥,**都必须假定已启动系统的管理员可读**,内核里运行的任何代码也可能读到。后果与缓解办法:

- 为**每个启动镜像或每台机器使用专用的 cephx 实体**,权限限定在它需要的那一个存储池 / 命名空间(以及那几种操作),这样泄漏只暴露那一个镜像;与嵌入启动介质的密钥一样,需要时轮换(`ceph auth rm`)。
- 默认是 `nokey`:此时表里不带任何凭据。需要密钥的启动期驱动从表里取(`handoff=key`,明确选择加入),或经别的途径获取(**尚未设计**;登记服务的想法仅作备忘)。
- 任何情况下都不要记录密钥日志(编解码器从不格式化它;iPXE 粘合层从不打印它)。不要把密钥提交进本仓库。
- `nokey` 只是不把密钥放进表里,**并不是不留在内存里**:会话存活期间,核心的 arena 里有 cephx 密钥和会话密钥,而 iPXE 驱动在加载器接手时不会擦除会话。BIOS 下 INT 13h 通路在 iPXE 的命令行消失后仍然工作,这块内存继续驻留(对操作系统的内存图隐藏),密钥就在里面;UEFI 下这块内存是 boot services 内存,操作系统在 `ExitBootServices` 时原样回收(固件如何处理**未验证**)。能读物理内存的已启动系统管理员,或这次启动会话的内存转储,即使表里没有密钥也可能在那里找到。目前驱动里没有任何措施改变这一点(缓解办法相同:每个镜像一个专用的 cephx 实体,机器丢失或退役时吊销)。
- 在加载器之后、同一次启动会话里运行的任何代码(包括被链式加载的操作系统)都能读到这张表。把密钥带进加载器的启动脚本也需要保护;在 DHCP / 启动阶段以明文发送的密钥可能在网络上被截获。
- 校验和防的是意外,不是伪造:能写这张表的人也能重算校验和。

这是一个面向测试网络的研究项目;这个设计并不声称能保护生产环境的密钥。

### 未验证

- Windows 启动期驱动如何这么早读取陌生的 ACPI 表,以及 Windows 是否容忍 iPXE 强制写入的 OEM 字段。(装着这张表时 WinPE 在 UEFI 和 BIOS 下都能启动,所以启动管理器和 WinPE 的启动不受它影响;第二阶段的 WinPE 没有 `rbd` 驱动,没有 Windows 里的东西读过这张表。)
- 无特权的 Windows 进程能否读到这张表。
- Microsoft 是否私下保留了 `rBFT`。(部分已解决:QEMU 里的 Linux 客户机在 UEFI 和 BIOS 下都如上所述看到了这张表。)
- 启动关键的网卡枚举除 MAC、VLAN、MTU 和地址之外是否还需要更多信息(PCI 位置、驱动提示):第 1 版不含。
