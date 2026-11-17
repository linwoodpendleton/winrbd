# harness/

The Linux user-space harness that hosts `core/`: the CMake build of the core as a static library, the unit tests and fuzz targets, the Linux host (sockets pump), and the tools and scripts around the lab cluster. It lets us develop and debug the protocol code without crashing a kernel, and (milestone 9) compare bytes read through the core against Linux krbd on the same image.

License: MIT (see `COPYING.MIT`).

## Status

**The build, the unit tests, the simulators, the fuzz targets and the CI workflow work for Phase 1 milestones 1 to 5, and the decoder half of milestone 10 covers the OSD map, CRUSH and placement too, proved against the live lab cluster.** 110 ctest tests (108 without the two lab ones, which skip): unit tests of every core module (the OSD map, CRUSH, placement and map store modules included), the capture replays, the vector tests of the lab's maps (`map.vec.*`, `vectors_mapb_check`), the oracle tool (`oracle.cli` and the self-test of its comparison script), the live placement vectors (`place.live`, `vectors_placement_check`), the mechanical gates (no libc, no globals, freestanding link), the footprint test, the documentation check, the hardening check of part B (`map.hardening`) and a seed replay of every fuzz target. The live lab tests (`harness/lab`, label `lab`: `lab.mon` and `lab.map`) need the lab cluster and are not part of the default run. The comparison with Ceph's own tools on the lab (`tools/map_oracle_lab.sh`) is a script run on the lab VM, not a ctest, and so is the live placement proof (`tools/map_placement_lab.py` drives the cluster while the whole client `winrbd-mapwatch` follows it; its vectors are replayed offline by `place.live`). Milestones 6 and later (OSD I/O, RBD) have no tests yet because they have no code yet.

## Build and test

Needs CMake 3.16+ and gcc or clang (C99). Optional: OpenSSL development files (differential crypto tests, skipped when absent), Python 3 (the pcap replay test, skipped when absent), `gcc-multilib` (the 32-bit compile check, skipped when absent).

```sh
cmake -S harness -B build/harness -DCMAKE_BUILD_TYPE=Debug
cmake --build build/harness -j
ctest --test-dir build/harness --output-on-failure
```

Options (see the header of [CMakeLists.txt](CMakeLists.txt)): `-DWR_SANITIZE=address,undefined`, `-DWR_FUZZ=ON` (clang, libFuzzer), `-DWR_WITH_OPENSSL=OFF`, `-DWR_BUILD_HOST=OFF`. Warnings are errors by default and must stay so.

Useful ctest selections: `ctest -L util` (one module's tests: the label is the first word of the name), `ctest -R core` (the mechanical gates and the footprint test), `ctest -L fuzz` (seed replays), `ctest -R client.pump -V` (one test, verbose).

### The four CI flavours

[.github/workflows/harness.yml](../.github/workflows/harness.yml) builds and tests:

| Flavour | Configure |
|---|---|
| gcc | `-DCMAKE_C_COMPILER=gcc` |
| clang | `-DCMAKE_C_COMPILER=clang` |
| clang + ASan + UBSan (gcc too) | `-DWR_SANITIZE=address,undefined`; the `core_no_libc` / `core_no_globals` checks are not registered here because the sanitizer runtime adds symbols |
| 32-bit and iPXE flags, compile only | `cmake --build build/harness --target wr_core_m32` (gcc and clang) and `--target wr_core_ipxe_flags` (gcc) |

Also in CI: `object-gates` (the no-libc and no-globals checks on optimised builds, Release and MinSizeRel with gcc and clang, because the Debug test builds never show what an optimiser turns a loop into), the same two checks on the 32-bit and iPXE-flag objects, `static-limits` (`tests/ci-docs-hardening/check_callgraph.py`: no recursion, no frame of unbounded size, at most 14 frames and 3,328 bytes of stack along any call chain of the core, and a budget of its own for each entry point of part B: map placement, store step, full-map decode, incremental apply, CRUSH decode, rule interpreter; the `--entry` arguments are read from the workflow by the ctest `map.hardening`, so the test and the job cannot drift apart), and the libFuzzer smoke run described below. The sanitizer runs set `ASAN_OPTIONS` / `UBSAN_OPTIONS` so a finding fails the test.

The core compares bytes with `wri_ct_memeq` and never calls `memcmp`, so clang at -O2 has no `memcmp(...) == 0` to turn into `bcmp`; no compiler flag is needed for `core_no_libc` on an optimised clang build (the CI jobs that pass `-DCMAKE_C_FLAGS=-fno-builtin-memcmp` still do, harmlessly).

## Tests

One executable per `test/test_<module>_<what>.c`, registered as ctest `<module>.<what>` with label `<module>` (`test_util_mem.c` is `util.mem`, `test_core_budgets.c` is `core.budgets`). A test that needs OpenSSL ends in `_ossl`. Exit code 77 is a skip with a printed reason; a skip never hides a failure.

- `test/support/`: the tiny framework (`wrt.h`: `WRT_CHECK`, `WRT_CHECK_U64`, `WRT_CHECK_STATUS`, `WRT_CHECK_MEM`), a JSON and hex reader so tests read `vectors/**/*.json` in place, and the **simulators**: `sim_m2` (a scriptable msgr2 server with fault hooks) and `sim_mon` (a fake monitor on top of it, with the cephx server side for both key types, `MMonMap`, `MOSDMap` from the committed vectors, renewal and restart). They are written from the spec notes, not from the client code.
- `core.budgets` (`test_core_budgets.c`) prints the footprint of the three profiles and the high-water mark of every pool and buffer after a full session (login, a map message of three quarters of the profile's cap, a pushed epoch, a monitor restart and recovery) and fails if a product profile exceeds its documented budget (`test/core_budgets.h`), an announced size is not what the engine took, or a buffer ever ran over its capacity. The engine gets regions of exactly the announced size, pre-filled with a byte pattern and surrounded by guard bands: a write outside them fails the test, and after destroy the whole arena must be zero. A second run per product profile sends a map message above `mon_msg_cap` and checks that it is dropped, the session survives and nothing outside the regions is touched. Run `ctest -R core.budgets -V` to see the table.
- `core.docs` (`test_core_docs.c`) checks the documents against the tree: the footprint table of `core/README.md` against `wr_client_mem_required`, the 500-line limit of the core files, a committed seed and a README entry for every fuzz target (an empty seed directory would pass the replay without running anything), every test name the READMEs mention, the SPDX tag of every product file, and that the CI workflow keeps warnings as errors and never ignores a failure.
- `client.mem` checks the exactness of `wr_client_mem_required` at every base alignment; `client.pump` drives the engine through the public pump API with a small in-test host.
- Part B (OSD map, CRUSH, placement): `map.vec.full` / `map.vec.pgs` / `map.vec.place` / `map.vec.err` run the committed lab vectors (`vectors/osdmap`, `vectors/crush`, `vectors/public/mapb`) through the real decoders and the real pipeline; `osdmap.budget` and `mapstore.mem` generate clusters of 100 to 8,192 OSDs and print the real per-OSD costs (see [core/README.md](../core/README.md), memory footprint); `oracle.cli` tests the comparison tool `oracle/wr-maporacle`, and a second ctest runs `tools/map_oracle_lab.sh --selftest` (every committed vector through the tool and the comparison code, plus negative tests), both without a cluster.
- `place.live` (`test_place_live.c`) replays `vectors/public/placement`: the full map and the 102 incrementals that the monitor sent to the client over a real session (CRCs verified), applied by the real incremental path, and at **every epoch** the PG tables of the tracked pools against the digest of `osdmaptool`'s table of that epoch; at each of the 23 states the whole PG table column by column, the held map against `ceph osd dump`, every one of 2,000 object names in every pool through hash, PG and CRUSH against the monitor's `ceph osd map` answers, and the monitor's own full maps and the full map the client was sent after a missed incremental against the chain. `vectors_placement_check` checks the files (hashes, contiguous chain, no stray file, no key-looking text). How the vectors were made and what they cover: [vectors/public/placement/README.md](vectors/public/placement/README.md).
- `map.hardening` (`test_map_hardening.c`) keeps the part B hardening wired in: the five fuzz targets exist and have seeds, the CI smoke job and `tools/fuzz_long.sh` name them, both READMEs list them, no committed seed of them is larger than the 64 KiB input cap of the fuzz runs (libFuzzer would cut it), the workflow still passes the global limits (14 frames, 3,328 bytes) and a budget for each of the six part B entry points, and the call-graph check passes with exactly the `--entry` budgets the workflow passes (it compiles the core with gcc and needs python3; without them that part is skipped, with a message).
- `lab.mon` and `lab.map` (label `lab`) run the client against the real lab monitor and are skipped without `WR_LAB_*` in the environment. `lab.map` is the map-enabled client: it logs in with each key type, tracks pools, takes the monitor's maps, optionally keeps following the cluster for `WR_LAB_FOLLOW_S` seconds while another shell changes it, checks that every placement is a consistent target and that not one map entry failed to decode, and can write the placements to `WR_LAB_OUT` for a script to compare with `ceph osd map` (the header of the test says how).

## Fuzzing

`fuzz/fuzz_<target>.c` defines `LLVMFuzzerTestOneInput`. Without `WR_FUZZ` each target is linked with `fuzz_replay_main.c` and ctest replays every file in `fuzz/seeds/<target>/` (`fuzzseed.<target>`), so the committed corpus is a regression test on every run. Targets: `util_cursor`, `denc_addr`, `m2_rx`, `m2_ctl`, `m2_conn`, `cx_envelope`, `cx_reply`, `mon_msgs`, `mon_session`, `client_session`, and `smoke`; and for part B (OSD map, CRUSH, placement, `docs/design/core-architecture.md` section 18) `crush_dec`, `crush_map`, `osdmap_full`, `osdmap_inc` and `mapstore`. `fuzz_crush_dec` decodes a CRUSH blob into a room between guard bands twice with different pre-fills (identical output, nothing written outside, a decoded region survives `wri_crush_check` and every accessor walk, a damaged region is judged without a crash); `fuzz_crush_map` runs the audit and the rule interpreter over a blob, a rule, an `x`, a weight array and a work budget (bounded work, results inside the map, a pure function of the inputs, an audited map never fails for a structural reason); `fuzz_osdmap_full` and `fuzz_osdmap_inc` decode a full map and apply an incremental to the lab's epoch-42 map (the same two pre-fills, the exact-size slot gives the same map and one byte less is `WR_E_MAP_BUDGET`, the held map is never written, an applied incremental does not apply twice); `fuzz_mapstore` feeds the map store the front of an `MOSDMap` message under a scripted clock (the epoch never goes down, an incremental is applied only to the epoch before it, every failure leaves a full-map request pending, nothing reads a front after its release, every placement answer is of the documented set). Every crasher is minimised and committed under `seeds/`.

`fuzz_client_session` is the whole-engine target. After a real handshake with the simulated monitor, the input script decides where the world misbehaves: bits flipped in the monitor's stream, connections cut, a monitor restart, a clock that steps back, a failing random source, calls that break the host contract, and two ways of playing the monitor itself: a well-framed `MESSAGE` with fuzzed type, header version and front (valid CRCs, so the message decoders are reached), and raw bytes that replace the stream. It asserts: no crash or undefined behaviour, the pump settles, pool accounting stays inside the configuration, the engine recovers when the world is good again, nothing is written outside the first `arena_used` / `bulk_used` bytes of the two pattern-filled regions (guard bands and a spare tail are checked), and the footprint equals what `wr_client_mem_required` announced. Every input is played twice with the two regions pre-filled with different byte patterns, and a digest of everything the host can observe (transmitted bytes, events, actions, map messages, the state after each pump) must be identical, so a decision taken on a byte the engine never wrote (an uninitialised read) shows up as a divergence.

To fuzz for real (clang, libFuzzer), instrument the core as well as the target. `WR_FUZZ=ON` alone instruments only the target file, so the fuzzer would see no coverage of the code under test; the global flag below fixes that:

```sh
CC=clang cmake -S harness -B build/fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_FLAGS=-fsanitize=fuzzer-no-link -DWR_FUZZ=ON -DWR_SANITIZE=address,undefined
cmake --build build/fuzz
mkdir -p /tmp/corpus && cp harness/fuzz/seeds/fuzz_client_session/* /tmp/corpus/
build/fuzz/fuzz_client_session -max_total_time=60 -max_len=4096 /tmp/corpus
```

`tools/fuzz_long.sh` does the same for every target at once (`sh harness/tools/fuzz_long.sh -s 900 -j 4`, optionally `-m` to minimise the corpora against the committed seeds afterwards and print how many inputs add coverage; `-t "fuzz_m2_rx fuzz_cx_reply"` picks targets, `-p partb` picks the five targets of part B (not together with `-t`), and a name that was not built, a failed build or an empty target list is an error, not a shorter run). The last long run of part A (15 minutes per target, then 10 to 15 minutes again after the last core change) did about 677 million executions with no crash and no sanitizer report. The long run of part B (16 minutes per target, the five targets side by side on the 8-core lab VM, ASan and UBSan, the core instrumented) did 18.6 million executions with no crash, no timeout, no out-of-memory and no sanitizer report; numbers per target are in the hardening section of [core/README.md](../core/README.md). The committed seeds are the vectors, the public captures cut into frames and payloads, the `mapgen` output and single-field mutations of the maps, and the coverage-adding inputs of those runs (1,478 inputs for the part B targets, 3.1 MB, from the minimised corpora; they derive from the scrubbed vectors only). CI runs every target for 30 s on a copy of its seeds, and fails if a part B target was not built or has no seeds. The duration for the Phase 1 exit criterion (60 s per target on every push, 1 h nightly, 8 CPU-hours per target before milestone 10 closes) is the maintainer's decision.

## Layout

| Path | What |
|---|---|
| `CMakeLists.txt`, `cmake/` | the build; globs `core/src/**/*.c`, `test/test_*.c`, `fuzz/fuzz_*.c`, `host/*.c`, `src/*.c`, so adding a module needs no edit here |
| `test/`, `test/support/` | unit tests, the framework and the simulators (`test_replay_public.c` replays the public captures through the cephx client, the monitor decoders and the signature code) |
| `fuzz/` | fuzz targets, the seed-replay driver and `seeds/<target>/` |
| `oracle/` | command-line tools that print the core's OSD map and placement answers in the format of Ceph's tools (part B, built from every `oracle/*.c`) |
| `src/` | end-to-end lab programs on the Linux host (globbed, linked with `wr_linux_host`): `winrbd-probe` connects to a monitor over msgr2 (crc), logs in with cephx, gets the monmap and the first osdmap, prints a summary and keeps the session alive with keepalives (`lab/probe-capture.sh` runs it for both key types and a wrong key under tcpdump and checks the captures with the Phase 0 checkers); `winrbd-mapwatch` is the map-enabled client: it lets the core's own store decode the monitor's maps and follow every incremental, and prints the placement (PG, up set, up primary, acting set, acting primary) of object names and PGs of tracked pools in the held epoch, at every adopted epoch if asked (`--trace`), saves the raw map messages it consumed (`--save-maps`), takes commands on standard input and can swallow a map message to force a gap (`drop`); see the header of `src/winrbd-mapwatch.c` |
| `host/` | the Linux host: `wrl_host.h` (interface), `wrl_sys.c` (clock, random, log, memory, file helpers), `wrl_loop.c` (the socket pump) and `tools/` (`wr-monprobe`: log in to a real monitor and print what the core learned) |
| `tests/ci-docs-hardening/` | scripts that CI runs outside ctest (`check_callgraph.py`: recursion, depth and stack of the core, with per-entry budgets for part B; `map.hardening` runs it too) |
| `tools/` | the Phase 0 protocol checkers (`run-all.sh`, run by the `vectors` workflow), `check_no_libc.sh`, `check_no_globals.sh`, `check_freestanding.sh` (freestanding compile and link smoke), `fuzz_long.sh` (long libFuzzer runs), `map_oracle_lab.sh` (the live comparison of the map, CRUSH and placement code with Ceph's own tools on the lab VM), `map_placement_lab.py` (the live proof with the whole client: `run` changes the lab cluster under `winrbd-mapwatch` and compares every answer with `ceph osd map`, `osdmaptool` and `ceph osd dump`, then restores the cluster and verifies it; `export` makes `vectors/public/placement`; `cleanup`, `reanalyze`), `pcap2stream.py` |
| `vectors/` | committed test vectors (scrubbed: no key material or tickets) and the public capture set |
| `lab/` | scripts that build and drive the lab Ceph cluster in a VM |

## Rules for test and harness code

Harness code may use libc; it never ships. It follows the same warning policy as the core minus the few warnings that fight with libc helpers. No secrets in the repository: lab keyrings are read from a path in the environment, copied to the VM only into a `0600` file outside the repository, and never printed. Tests never run destructive commands on a cluster.

---

Linux 用户态测试台,承载 `core/`:把核心编成静态库的 CMake 构建、单元测试与 fuzz 目标、Linux 宿主(套接字泵),以及围绕实验集群的工具和脚本。用来在不蓝屏的前提下开发调试协议代码,之后(里程碑 9)把核心层读到的字节与同一镜像经 Linux krbd 读到的字节做逐字节比对。

许可:MIT(见 `COPYING.MIT`)。

**状态:Phase 1 里程碑 1 到 5 的构建、单元测试、模拟器、fuzz 目标和 CI 工作流都可用,里程碑 10 的解码器部分也覆盖了 OSD map、CRUSH 和定位。** 110 个 ctest 用例(不含会跳过的两个 lab 用例共 108 个):各核心模块(含 OSD map、CRUSH、定位和 map 存储)的单元测试、抓包回放、实验集群 map 向量的测试(`map.vec.*`、`vectors_mapb_check`)、比对工具(`oracle.cli` 与比对脚本的自检)、实时定位证明的向量回放(`place.live`、`vectors_placement_check`)、机械检查(无 libc、无全局变量、freestanding 链接)、内存预算测试、文档核对、第二部分的加固检查(`map.hardening`),以及每个 fuzz 目标的种子回放。`tools/fuzz_long.sh` 可对全部目标做长时间 fuzz(`-p partb` 只跑 map 相关的五个目标);第一部分最近一轮约 6.8 亿次执行,第二部分(五个目标各 16 分钟,ASan + UBSan)约 1860 万次执行,均无崩溃、无 sanitizer 报告。`tools/map_oracle_lab.sh` 在实验集群的虚拟机里把核心的 map、CRUSH 和定位结果与 Ceph 自己的工具逐项比对(最近一轮 132,358 次比较,0 处差异)。`tools/map_placement_lab.py` 让完整客户端 `winrbd-mapwatch` 通过真实 monitor 会话跟随实验集群,同时用管理命令改动集群(upmap、upmap primary、pg_temp、primary_temp、亲和度、reweight、out、拆分、删池、漏掉一个增量、断开连接),逐项与 `ceph osd map`、`osdmaptool`、`ceph osd dump` 比对(212,000 个对象定位、103 个 epoch 的 28,510 行 PG,0 处差异,集群已还原);向量在 `vectors/public/placement`,由 `place.live` 离线回放。需要实验集群的 `lab` 测试(`lab.mon`、`lab.map`)不在默认运行中。

构建与测试命令见上(`cmake` + `ctest`)。CI(`.github/workflows/harness.yml`)跑四种组合:gcc、clang、带 ASan+UBSan 的构建、以及仅编译的 `-m32` 与 iPXE 编译选项,另加 clang + libFuzzer 每个目标 30 秒的冒烟。真正做 fuzz 时要同时给核心加覆盖率插桩(`-DCMAKE_C_FLAGS=-fsanitize=fuzzer-no-link`),否则 fuzzer 看不到核心代码的覆盖率,命令见上。`core.budgets` 测试打印三个配置档的内存占用与一次完整会话后各内存池的峰值,超出文档规定的预算就失败;区域按公布大小精确分配并带护栏,越界写会被发现。`core.docs` 测试核对文档与代码树是否一致(内存表、文件行数、fuzz 种子、测试名、SPDX、CI 工作流)。fuzz 整机目标把每个输入用两种不同的内存填充各跑一遍,可观察行为必须完全一致,以此发现读未初始化内存。CI 另有优化构建上的 no-libc / no-globals 检查和调用深度 / 栈用量检查。
