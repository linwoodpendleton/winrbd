# harness/

The Linux user-space harness that hosts `core/`: the CMake build of the core as a static library, the unit tests and fuzz targets, the Linux host (sockets pump), and the tools and scripts around the lab cluster. It lets us develop and debug the protocol code without crashing a kernel, and (milestone 9) compare bytes read through the core against Linux krbd on the same image.

License: MIT (see `COPYING.MIT`).

## Status

**The build, the unit tests, the simulators, the fuzz targets and the CI workflow work for Phase 1 milestones 1 to 3.** 69 ctest tests (68 without the lab one, which skips): unit tests of every core module, the capture replays, the mechanical gates (no libc, no globals, freestanding link), the footprint test, the documentation check and a seed replay of every fuzz target. The live lab tests (`harness/lab`, label `lab`) need the lab cluster and are not part of the default run. Milestones 5 and later (OSDMap decode, CRUSH, OSD I/O, RBD) have no tests yet because they have no code yet.

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

Also in CI: `object-gates` (the no-libc and no-globals checks on optimised builds, Release and MinSizeRel with gcc and clang, because the Debug test builds never show what an optimiser turns a loop into), the same two checks on the 32-bit and iPXE-flag objects, `static-limits` (`tests/ci-docs-hardening/check_callgraph.py`: no recursion, at most 14 frames and 2 KiB of stack along any call chain of the core), and the libFuzzer smoke run described below. The sanitizer runs set `ASAN_OPTIONS` / `UBSAN_OPTIONS` so a finding fails the test.

The core compares bytes with `wri_ct_memeq` and never calls `memcmp`, so clang at -O2 has no `memcmp(...) == 0` to turn into `bcmp`; no compiler flag is needed for `core_no_libc` on an optimised clang build (the CI jobs that pass `-DCMAKE_C_FLAGS=-fno-builtin-memcmp` still do, harmlessly).

## Tests

One executable per `test/test_<module>_<what>.c`, registered as ctest `<module>.<what>` with label `<module>` (`test_util_mem.c` is `util.mem`, `test_core_budgets.c` is `core.budgets`). A test that needs OpenSSL ends in `_ossl`. Exit code 77 is a skip with a printed reason; a skip never hides a failure.

- `test/support/`: the tiny framework (`wrt.h`: `WRT_CHECK`, `WRT_CHECK_U64`, `WRT_CHECK_STATUS`, `WRT_CHECK_MEM`), a JSON and hex reader so tests read `vectors/**/*.json` in place, and the **simulators**: `sim_m2` (a scriptable msgr2 server with fault hooks) and `sim_mon` (a fake monitor on top of it, with the cephx server side for both key types, `MMonMap`, `MOSDMap` from the committed vectors, renewal and restart). They are written from the spec notes, not from the client code.
- `core.budgets` (`test_core_budgets.c`) prints the footprint of the three profiles and the high-water mark of every pool and buffer after a full session (login, a map message of three quarters of the profile's cap, a pushed epoch, a monitor restart and recovery) and fails if a product profile exceeds its documented budget (`test/core_budgets.h`), an announced size is not what the engine took, or a buffer ever ran over its capacity. The engine gets regions of exactly the announced size, pre-filled with a byte pattern and surrounded by guard bands: a write outside them fails the test, and after destroy the whole arena must be zero. A second run per product profile sends a map message above `mon_msg_cap` and checks that it is dropped, the session survives and nothing outside the regions is touched. Run `ctest -R core.budgets -V` to see the table.
- `core.docs` (`test_core_docs.c`) checks the documents against the tree: the footprint table of `core/README.md` against `wr_client_mem_required`, the 500-line limit of the core files, a committed seed and a README entry for every fuzz target (an empty seed directory would pass the replay without running anything), every test name the READMEs mention, the SPDX tag of every product file, and that the CI workflow keeps warnings as errors and never ignores a failure.
- `client.mem` checks the exactness of `wr_client_mem_required` at every base alignment; `client.pump` drives the engine through the public pump API with a small in-test host.

## Fuzzing

`fuzz/fuzz_<target>.c` defines `LLVMFuzzerTestOneInput`. Without `WR_FUZZ` each target is linked with `fuzz_replay_main.c` and ctest replays every file in `fuzz/seeds/<target>/` (`fuzzseed.<target>`), so the committed corpus is a regression test on every run. Targets: `util_cursor`, `denc_addr`, `m2_rx`, `m2_ctl`, `m2_conn`, `cx_envelope`, `cx_reply`, `mon_msgs`, `mon_session`, `client_session`, and `smoke`. Every crasher is minimised and committed under `seeds/`.

`fuzz_client_session` is the whole-engine target. After a real handshake with the simulated monitor, the input script decides where the world misbehaves: bits flipped in the monitor's stream, connections cut, a monitor restart, a clock that steps back, a failing random source, calls that break the host contract, and two ways of playing the monitor itself: a well-framed `MESSAGE` with fuzzed type, header version and front (valid CRCs, so the message decoders are reached), and raw bytes that replace the stream. It asserts: no crash or undefined behaviour, the pump settles, pool accounting stays inside the configuration, the engine recovers when the world is good again, nothing is written outside the first `arena_used` / `bulk_used` bytes of the two pattern-filled regions (guard bands and a spare tail are checked), and the footprint equals what `wr_client_mem_required` announced. Every input is played twice with the two regions pre-filled with different byte patterns, and a digest of everything the host can observe (transmitted bytes, events, actions, map messages, the state after each pump) must be identical, so a decision taken on a byte the engine never wrote (an uninitialised read) shows up as a divergence.

To fuzz for real (clang, libFuzzer), instrument the core as well as the target. `WR_FUZZ=ON` alone instruments only the target file, so the fuzzer would see no coverage of the code under test; the global flag below fixes that:

```sh
CC=clang cmake -S harness -B build/fuzz -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_C_FLAGS=-fsanitize=fuzzer-no-link -DWR_FUZZ=ON -DWR_SANITIZE=address,undefined
cmake --build build/fuzz
mkdir -p /tmp/corpus && cp harness/fuzz/seeds/fuzz_client_session/* /tmp/corpus/
build/fuzz/fuzz_client_session -max_total_time=60 -max_len=4096 /tmp/corpus
```

`tools/fuzz_long.sh` does the same for every target at once (`sh harness/tools/fuzz_long.sh -s 900 -j 4`, optionally `-m` to minimise the corpora against the committed seeds afterwards). The last long run (15 minutes per target, then 10 to 15 minutes again after the last core change) did about 677 million executions with no crash and no sanitizer report; numbers per target are in the hardening section of [core/README.md](../core/README.md). The committed seeds are the vectors, the public captures cut into frames and payloads, and the coverage-adding inputs of those runs. CI runs every target for 30 s on a copy of its seeds. The duration for the Phase 1 exit criterion (60 s per target on every push, 1 h nightly, 8 CPU-hours per target before milestone 10 closes) is the maintainer's decision.

## Layout

| Path | What |
|---|---|
| `CMakeLists.txt`, `cmake/` | the build; globs `core/src/**/*.c`, `test/test_*.c`, `fuzz/fuzz_*.c`, `host/*.c`, `src/*.c`, so adding a module needs no edit here |
| `test/`, `test/support/` | unit tests, the framework and the simulators (`test_replay_public.c` replays the public captures through the cephx client, the monitor decoders and the signature code) |
| `fuzz/` | fuzz targets, the seed-replay driver and `seeds/<target>/` |
| `src/` | end-to-end lab programs on the Linux host (globbed, linked with `wr_linux_host`): `winrbd-probe` connects to a monitor over msgr2 (crc), logs in with cephx, gets the monmap and the first osdmap, prints a summary and keeps the session alive with keepalives (`lab/probe-capture.sh` runs it for both key types and a wrong key under tcpdump and checks the captures with the Phase 0 checkers) |
| `host/` | the Linux host: `wrl_host.h` (interface), `wrl_sys.c` (clock, random, log, memory, file helpers), `wrl_loop.c` (the socket pump) and `tools/` (`wr-monprobe`: log in to a real monitor and print what the core learned) |
| `tests/ci-docs-hardening/` | scripts that CI runs outside ctest (`check_callgraph.py`) |
| `tools/` | the Phase 0 protocol checkers (`run-all.sh`, run by the `vectors` workflow), `check_no_libc.sh`, `check_no_globals.sh`, `check_freestanding.sh` (freestanding compile and link smoke), `fuzz_long.sh` (long libFuzzer runs), `pcap2stream.py` |
| `vectors/` | committed test vectors (scrubbed: no key material or tickets) and the public capture set |
| `lab/` | scripts that build and drive the lab Ceph cluster in a VM |

## Rules for test and harness code

Harness code may use libc; it never ships. It follows the same warning policy as the core minus the few warnings that fight with libc helpers. No secrets in the repository: lab keyrings are read from a path in the environment, copied to the VM only into a `0600` file outside the repository, and never printed. Tests never run destructive commands on a cluster.

---

Linux 用户态测试台,承载 `core/`:把核心编成静态库的 CMake 构建、单元测试与 fuzz 目标、Linux 宿主(套接字泵),以及围绕实验集群的工具和脚本。用来在不蓝屏的前提下开发调试协议代码,之后(里程碑 9)把核心层读到的字节与同一镜像经 Linux krbd 读到的字节做逐字节比对。

许可:MIT(见 `COPYING.MIT`)。

**状态:Phase 1 里程碑 1 到 3 的构建、单元测试、模拟器、fuzz 目标和 CI 工作流都可用。** 69 个 ctest 用例(不含会跳过的 lab 用例共 68 个):各核心模块的单元测试、抓包回放、机械检查(无 libc、无全局变量、freestanding 链接)、内存预算测试,以及每个 fuzz 目标的种子回放。`tools/fuzz_long.sh` 可对全部目标做长时间 fuzz;最近一轮(每个目标 15 分钟,核心最后一次改动后再跑 10 至 15 分钟)约 6.8 亿次执行,无崩溃、无 sanitizer 报告。需要实验集群的 `lab` 测试不在默认运行中。

构建与测试命令见上(`cmake` + `ctest`)。CI(`.github/workflows/harness.yml`)跑四种组合:gcc、clang、带 ASan+UBSan 的构建、以及仅编译的 `-m32` 与 iPXE 编译选项,另加 clang + libFuzzer 每个目标 30 秒的冒烟。真正做 fuzz 时要同时给核心加覆盖率插桩(`-DCMAKE_C_FLAGS=-fsanitize=fuzzer-no-link`),否则 fuzzer 看不到核心代码的覆盖率,命令见上。`core.budgets` 测试打印三个配置档的内存占用与一次完整会话后各内存池的峰值,超出文档规定的预算就失败;区域按公布大小精确分配并带护栏,越界写会被发现。`core.docs` 测试核对文档与代码树是否一致(内存表、文件行数、fuzz 种子、测试名、SPDX、CI 工作流)。fuzz 整机目标把每个输入用两种不同的内存填充各跑一遍,可观察行为必须完全一致,以此发现读未初始化内存。CI 另有优化构建上的 no-libc / no-globals 检查和调用深度 / 栈用量检查。
