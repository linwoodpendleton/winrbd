# Contributing / 参与贡献

[English](#en) | [中文](#zh)

<a name="en"></a>

## English

winrbd is a spare-time research project; replies may be slow. Thoughtful issues and design discussion are as valuable as code at this stage.

### Ways to help

- Open an issue: questions, corrections, review of `docs/ROADMAP.md` and `docs/design/handoff-table.md`.
- Share expertise in Windows kernel storage (storport, boot-start drivers, dump / hibernate paths), iPXE internals, or the Ceph wire protocol.
- Help with test infrastructure (small Ceph clusters, QEMU + OVMF, fault injection).

### Rules

1. **Independent implementation for the core.** `core/` and `windows/` are written from Ceph's public protocol documentation, with Ceph's user-space source (mostly LGPL-2.1, to be confirmed per file) as a reading reference and a live cluster as the check. This is not a formal clean-room process. **Do not copy code from the Linux kernel's libceph / rbd (GPL) into this repository**, and do not paste code whose license you have not checked. Because `core/` is MIT, do not copy code from Ceph's user-space sources (mostly LGPL) into it either: use them to learn the protocol, then write your own. In a pull request, say which sources you read.
2. **License per directory.** See [LICENSE](LICENSE). New files carry an SPDX-License-Identifier matching their directory. Files derived from WNBD are treated as LGPL-2.1-only.
3. **Sign-off.** Add a `Signed-off-by:` line to each commit (Developer Certificate of Origin, see [developercertificate.org](https://developercertificate.org/); `git commit -s`). You keep your copyright; no assignment is required.
4. **No secrets.** Never commit cephx keys, keyrings, or captures that contain them. Scrub test vectors.
5. **Claims need evidence.** Statements about iPXE, WNBD, Ceph or Windows internals should cite the file and line, a document, or a test. If you are not sure, write it as an open question.
6. **Small, reviewable changes.** One topic per pull request. For anything large, open an issue first.
7. **Be kind.** Disagree with the design, not the person.
8. **Upstream iPXE has its own rules.** Anything proposed to the iPXE project must follow iPXE's own `CONTRIBUTING.md` in full, including its requirement that each submission has an accountable author who has reviewed and understands every line. New iPXE source files also need a `FILE_LICENCE` and a `FILE_SECBOOT` decision.

### Do not send

- Signed production binaries or signing keys.
- Anything intended for use against clusters you do not own.

<a name="zh"></a>

## 中文

winrbd 是业余时间的研究项目,回复可能较慢。现阶段,有思考的 issue 和设计讨论与代码一样有价值。

### 可以怎么帮忙

- 提 issue:提问、纠错、评审 `docs/ROADMAP.md` 与 `docs/design/handoff-table.md`。
- 分享 Windows 内核存储(storport、启动期驱动、转储 / 休眠路径)、iPXE 内部或 Ceph 线上协议方面的经验。
- 帮忙搭测试基础设施(小型 Ceph 集群、QEMU + OVMF、故障注入)。

### 规则

1. **核心部分为独立实现。** `core/` 和 `windows/` 依据 Ceph 公开的协议文档编写,Ceph 用户态源码(大多是 LGPL-2.1,需逐文件确认)仅作阅读参考,并以真实集群验证。这不是严格意义上的净室流程。**不要把 Linux 内核 libceph / rbd(GPL)的代码复制进本仓库**,也不要粘贴没有核对过许可的代码。由于 `core/` 是 MIT 许可,也不要把 Ceph 用户态源码(大多是 LGPL)复制进去:读它是为了弄懂协议,代码要自己写。提交 pull request 时请说明你读过哪些资料。
2. **按目录区分许可。** 见 [LICENSE](LICENSE)。新文件带上与所在目录相符的 SPDX-License-Identifier。派生自 WNBD 的文件按 LGPL-2.1-only 处理。
3. **签署。** 每个提交加一行 `Signed-off-by:`(开发者来源证书,见 [developercertificate.org](https://developercertificate.org/);`git commit -s`)。版权仍属于你,不需要转让。
4. **不要有密钥。** 永远不要提交 cephx 密钥、keyring,或包含它们的抓包。测试向量要先清洗。
5. **结论要有依据。** 关于 iPXE、WNBD、Ceph 或 Windows 内部实现的说法,请给出文件和行号、文档或测试。不确定就写成未决问题。
6. **小而易审。** 一个 pull request 一个主题。较大的改动请先开 issue。
7. **友善。** 可以反对设计,不要针对人。
8. **iPXE 上游有自己的规则。** 向 iPXE 项目提交任何东西,都必须完整遵守 iPXE 自己的 `CONTRIBUTING.md`,包括每份提交都要有对每一行负责、审阅过并理解的作者。新的 iPXE 源文件还需要决定 `FILE_LICENCE` 和 `FILE_SECBOOT`。

### 请不要提交

- 正式签名的二进制文件或签名密钥。
- 任何意图用于你不拥有的集群的东西。
