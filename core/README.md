# core/ (planned)

The portable C core: Ceph wire protocol (monitor client, cephx, msgr2, OSDMap, CRUSH, OSD object I/O) and RBD format-2 image access. No platform dependencies; sockets, allocation, time and crypto come in through a thin shim.

License: MIT (see `COPYING.MIT`). Nothing here yet.

---

核心层(计划中):与平台无关的 C 代码,实现 Ceph 通信协议(mon 客户端、cephx、msgr2、OSDMap、CRUSH、OSD 对象读写)与 RBD format-2 镜像访问。套接字、内存、时间、加密通过一层很薄的适配层接入。

许可:MIT(见 `COPYING.MIT`)。目前还没有代码。
