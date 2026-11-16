# ipxe/ (planned)

The iPXE `rbd://` SAN driver: opens an RBD image using `core/`, exposes it as an EFI_BLOCK_IO disk through iPXE's SAN layer, and publishes the handoff ACPI table. Built against the iPXE tree pinned in `third_party/ipxe`.

License: GPL-2.0-or-later or UBDL (`GPL2_OR_LATER_OR_UBDL`), like iPXE's own SAN code. The MIT core links in without changing that. Nothing here yet.

---

iPXE 的 `rbd://` SAN 驱动(计划中):用 `core/` 打开 RBD 镜像,经 iPXE 的 SAN 层以 EFI_BLOCK_IO 磁盘的形式提供给固件,并发布交接用的 ACPI 表。基于 `third_party/ipxe` 固定的 iPXE 版本构建。

许可:GPL-2.0-or-later 或 UBDL(`GPL2_OR_LATER_OR_UBDL`),与 iPXE 自己的 SAN 代码一致;MIT 的核心链接进来不影响这一点。目前还没有代码。
