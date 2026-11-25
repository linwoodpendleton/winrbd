<!-- SPDX-License-Identifier: MIT -->
# Final hardening pass (third review, 2026-11-24): the whole change set read as one, and the gates run again

What is here: the logs of the runs that followed the third review (`docs/design/ipxe-driver.md`, section 18.5). Nothing here is a live boot; the live rows are in `../rows/` and were not repeated (section 18.5, R-20, says why and what the
code difference to the tree that ran them is).

| File | What |
|---|---|
| `ctest-ubuntu-26.04.txt` | the harness ctest matrix in the Ubuntu 26.04 guest (gcc 15.2, clang 21.1.8): Debug, Debug + ASan/UBSan, Release, MinSizeRel, both compilers, 8 of 8 flavours passed with no failed and no skipped test (one skip in each sanitizer flavour: `crypto.ct.valgrind`), then the 32-bit, iPXE-flag, header and object gates. One run, `-j 4`, on a box at a load average of 34 (maximum 52) |
| `ctest-ubuntu-24.04.txt` | the same in an Ubuntu 24.04 guest (gcc 13.3, clang 18.1.3), the image CI's `ubuntu-24.04` jobs use. gcc: 4 of 4 flavours passed. clang: Debug and MinSizeRel passed; **Debug + ASan/UBSan did not build** (the guest lacked the package `libclang-rt-18-dev`, an environment fault, not the code) and **Release failed one test**, `robust.selftest` (a timing-sensitive case, `osd-kill`, beside other tests on a loaded box; it passed twice alone on the same guest: R-18 of the design document, `RUN_SERIAL` since) |
| `ctest-ubuntu-24.04-clang-rerun.txt` | clang Debug + ASan/UBSan and Release again, in the same guest, after installing `libclang-rt-18-dev` and with `robust.selftest` serial: both passed |
| `gate-results.txt`, `gate-sha256.txt` | the build gate (`harness/lab/p2/builder/build-ipxe.sh`) on the tree of this review: 11 iPXE targets with iPXE's own `-Werror` and no warning, the licence verdicts, the Secure Boot refusal and its control, 122 objects `FORBIDDEN`, 84,968 / 85,043 self-tests (64 / 32 bit, plain and UBSan), the negative control; 0 checks failed. The hashes differ from `../BINARIES.txt` (the build gate of the earlier, smaller tree) and are the hashes of the current sources |

| `ctest-ubuntu-24.04-final-tree-gcc.txt`, `ctest-ubuntu-26.04-final-tree-release.txt` | the last short passes, on the tree as it is committed to the working copy (all edits of the review in): 24.04 gcc Release passed and gcc ASan/UBSan failed one test, `exitrun.selftest` ("signals", a timing case; load average about 45 from two other guests of the pass; three runs alone on the same guest passed); 26.04 Release with gcc and clang passed |

Machine paths are replaced by `<box>` and `<guest>`.
