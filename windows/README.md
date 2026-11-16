# windows/ (planned)

The Windows boot-start storport miniport driver, forked from WNBD's `wnbd.sys`, with an in-kernel RBD client (using `core/` over WSK) that reads the handoff table and takes over the same image as the system disk.

License: new original files are LGPL-2.1-or-later. Most WNBD files say "Licensed under LGPL-2.1" without "or later" (`wnbd.rc` says LGPL-2.1-only), so files derived from WNBD are treated as LGPL-2.1-only. See `LICENSE`. Nothing here yet.

---

Windows 启动期(boot-start)storport miniport 驱动(计划中):从 WNBD 的 `wnbd.sys` 分叉,内核内置 RBD 客户端(`core/` 加 WSK 传输),读取交接表,把同一个镜像接管为系统盘。

许可:全新原创文件为 LGPL-2.1-or-later。WNBD 的大多数文件只写 "Licensed under LGPL-2.1" 而没有 "or later"(`wnbd.rc` 写的是 LGPL-2.1-only),所以派生自 WNBD 的文件按 LGPL-2.1-only 处理。详见 `LICENSE`。目前还没有代码。
