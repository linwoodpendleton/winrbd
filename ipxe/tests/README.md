# ipxe/tests/

Self-tests of the `rbd://` driver's glue that need **no network, no QEMU and no cluster**. They are iPXE self-tests (`struct self_test`, `__self_test`, `ok()`), the same kind as iPXE's own `src/tests/*_test.c`, linked into iPXE's test program and run as an ordinary Linux process.

```sh
ipxe/tools/build.sh test                                   # bin-x86_64-linux/tests.linux: build, run, verify
ipxe/tools/build.sh test bin-i386-linux/tests.linux        # the 32-bit program (the word size of the BIOS images; needs gcc-multilib)
ipxe/tools/build.sh test -n                                # the negative control: a deliberate failure must be seen
ipxe/tools/build.sh test -u                                # the same run with UBSan (trap mode) in every glue, core and test object
ipxe/tools/build.sh check                                  # static checks of ipxe/ and of this directory (no iPXE tree needed)
```

`build.sh test` prepares the copy of the pinned iPXE tree (`build/ipxe`, git-ignored; prepared again when any input changed), builds the test program with iPXE's own warning set and `-Werror`, runs it, and accepts the run only if **all** of this holds:

- the program exits with status 0 and prints `OK: all N tests passed`;
- there is no `FAILURE` line;
- every file of this directory has its own `OK: "<name>" N tests passed` line (N > 0). A test file that was not wired in, or whose test set is empty, therefore fails instead of passing by not running.

On the pinned tree (9261ebe38) iPXE's own sets are 12,448 tests; the driver's eight files add 72,520 (64-bit program: 84,968 in all; the 32-bit program: 85,043); the total is printed on the last line.

## What is here

| File | Tests | Covers |
|---|---|---|
| `rbd_selftest.c` | 271 | what needs no session and no block device: a password in the URI is refused (7 spellings), the specification a parse produces (the design's defaults), `rbd_spec_wipe()`, `rbd_rc()` (the status table of `docs/design/ipxe-driver.md` section 12: every explicitly mapped status, `-EPROTO` for every other status of `WR_STATUS_LIST` and for numbers the core does not define, a failure is never success), `rbd_rc_peer()` (a refused login is permission denied, a refused connection mode is "not supported"), the SAN constants, the `rBFT` signature |
| `rbd_uri_test.c` | 4,639 | the opener and the parse: every option and its limits, monitor lists and the IPv6 forms, the user, the key (both key types, bad ones, the settings), refusals with their one console line, no key left in the heap after any outcome (a heap walk), the out-of-memory paths, `rbd_uri_text()` (the URI of the "uri" device path), a monitor list far beyond the limit never writes past the working area (guard bytes), and the opener's success path on the real core with fake sockets (`rbd_open_with()`: no window of the key in the free heap, the session's references and blocks all given back, eight rounds of each handoff mode) |
| `rbd_conn_test.c` | 9,231 | the connection table over a fake socket and a fake core: connect, timeout, established, receive window (never more than `RBD_CONN_RX_WINDOW_MAX`) and backlog, transmit with partial acceptance across gather pieces, close in every order, shutdown, the clock and the conversions, a real-core flight |
| `rbd_session_test.c` | 506 | the session over a fake core and fake sockets: create, find by identity, reopen, grace, the stall rules (none for a session no device is attached to), cancel and buffer ownership, destroy in every order, key wiping |
| `rbd_block_test.c` | 39,358 | the block device: commands, completion never from inside the starting call, every close order of a command / device / session, synchronous cancel, readahead hits, waits and misses, capacity, the 64-bit and i386 arithmetic, randomised interleavings |
| `rbd_efi_test.c` | 601 | the device path nodes (vendor, SATA, URI), redaction of the URI, name rules, prefix checks, composition, size limits |
| `rbd_acpi_test.c` | 2,431 | the handoff table over a faked descriptor: build, bounds, the NIC prefix, completion and install, key wiping |
| `rbd_bios_test.c` | 15,483 | the boot-firmware-table area arithmetic, the scan (every table kind, truncation, bad checksums), the window check, the exit warning |

`rbd_selftest.c` walks the core's own status list (`WR_STATUS_LIST`), so a status added to the core is covered the day it is added: it must map to `-EPROTO` unless the table in the test says otherwise. A deliberate new mapping means a new row in the test and in the design table.

## Adding a test file (every glue module ships one)

1. Write `ipxe/tests/rbd_<module>_test.c`. Start from the licence block (with its `SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL` line) and the two tag lines of `rbd_selftest.c`: `FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );` and `FILE_SECBOOT ( FORBIDDEN );`, each on a line of its own (`build.sh check` enforces it). `FILE_SECBOOT` is `FORBIDDEN` like every file of the driver; a test object is only linked into test programs, never into a bootable image.
2. The file name starts with `rbd_` (iPXE derives the object name from the base name; all test objects share `src/tests/` with iPXE's own, and the glue and core already own `src/winrbd/`), the base name is not that of a glue or core file, and the test set is registered with `.name` equal to the base name: `struct self_test rbd_<module>_test __self_test = { .name = "rbd_<module>_test", .exec = ... };` (`build.sh test` looks for `OK: "rbd_<module>_test"` in the run).
3. Wire it in: add `+REQUIRE_OBJECT ( rbd_<module>_test );` to the hunk of `ipxe/patches/0003-winrbd-self-tests.patch` and add one to the second number of the hunk header (`+97,6` becomes `+97,7`). `build.sh check` compares the patch with this directory in both directions, says what to add, and also checks that the line counts in the hunk headers match the hunks (a header that is too small would make `patch` apply the hunk without its last line, that is, without the new `REQUIRE_OBJECT`).
4. Run `build.sh check`, then `build.sh test`.

Things that are different from the glue and the core:

- **Error macros.** `-EINVAL` and the other POSIX names expand to a statement expression that carries the identifier of the *file* that uses them (`ERRFILE_<object>`), so `rbd_rc()` returns `-EINVAL` as seen from `rbd_errors.c` and the test's own `-EINVAL` differs in the file bits. They also cannot appear in a static initialiser. `rbd_selftest.c` defines `ERRFILE_rbd_selftest` locally (before it includes `<errno.h>`), uses `RBD_ERR ( EINVAL )` (a constant expression) and compares with `rbd_same_error()` (POSIX and platform part only). Copy those three bits.
- **Console output.** A refusal prints its one console line (`rbd: key material must not be part of the URI ...`), so the run shows it. That is expected. A test must never put a key or a URI in its own output either.
- **Heap, not stack, for big objects.** The Linux program has a large stack, but the code under test runs on a 4 KiB stack in the BIOS builds; allocate a `struct rbd_spec` with `zalloc()` as the opener does.
- **Same defines as the driver.** The test includes `"winrbd/rbd_priv.h"` (the imported glue header, which carries the core's headers); anything the test needs from the core goes through it.
- **Logic in a file of its own.** The test program is a Linux process: the EFI and BIOS side of the glue (`efi_describe`, device path nodes, the INT 13h hooks) is not linked into it, and what is not linked cannot be tested here. A module that has both pure logic (building a device path node into a buffer, encoding the handoff table body, range and overflow checks of a SAN command) and calls into the firmware keeps the logic in functions that take plain buffers and compile on every platform, so that its test file can call them.
- **No network, no time, no randomness.** A test that needs a socket uses a fake one (the connection table's state machine is tested with one when `ipxe-conn` lands); a test never waits on the clock.

## The negative control

`build.sh test -n` prepares a second copy next to the first (`<out>-negctl`), compiles `rbd_selftest.c` there with `-DRBD_SELFTEST_NEGATIVE_CONTROL` (iPXE's per-object flag variable `CFLAGS_rbd_selftest`), which adds one failing assertion, runs the **same** verification, and exits 0 only if the verification **failed for that reason**: the run must contain exactly the three `FAILURE` lines of one failed assertion in `rbd_selftest.c` (the assertion, the set summary `1 of N tests failed`, the overall summary). A build that dies, a crash, a timeout or a missing summary line also "fails the check" and proves nothing, so they are errors of their own. If a future change makes a failing test invisible (an exit status that is lost, a summary line that is not looked at), this step fails. The copy is deleted afterwards. CI runs it (`.github/workflows/ipxe.yml`, job `self-tests`).

`build.sh test -u` additionally counts the UBSan traps (`ud2`) in the glue and core objects of the test program (the plain build has none) and fails if there are none: the per-object flags go through iPXE's make, which does not say whether they were used.

## What this does not cover

- The firmware and the network: the EFI side (`efi_netdev_path()`, the route lookup, `efi_describe` installing the device path), the BIOS side (the `rbd-xbft` command, the exit hook, INT 13h itself), real TCP sockets, a real cluster and a real boot loader. The session, the block device, the connection table and the tables are tested here against fakes that the tests control (a scripted core, a fake socket, a faked descriptor); what runs on a firmware is the QEMU matrix of `docs/design/ipxe-driver.md` section 14.3 (`harness/lab/p2/results/`).
- AddressSanitizer is not used: the test program is iPXE's own two-stage link (every iPXE symbol gets a prefix, the iPXE objects are joined before the host libc is linked), and the ASan runtime's symbols would have to survive that. UBSan needs no runtime in trap mode: `build.sh test -u` compiles every glue, core and test object with `-fsanitize=undefined -fno-sanitize=alignment -fsanitize-undefined-trap-on-error` into its own copy (`<out>-ubsan`) and runs the same verification; a finding ends the program with SIGILL. The alignment check is off on purpose: iPXE's inline `memset()` clears small constant-size regions with a store of the widest type through a union pointer (fine on x86, which iPXE relies on everywhere), so a `uint8_t[4]` cleared with `WR_MEMSET` traps although nothing is wrong. The core itself is covered by the harness under ASan and UBSan with the full runtimes.
