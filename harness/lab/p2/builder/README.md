<!-- SPDX-License-Identifier: MIT -->
# Phase 2 builder: the Ubuntu 26.04 guest for everything that needs root or the CI compilers

One disposable QEMU/KVM guest on a shared Linux build box (no root on the box), with the toolchain of the CI runner (**gcc 15.2, clang 21.1.8**), the iPXE build dependencies, and the tools to build disk images (loop devices, `qemu-img`, partitioning, FAT/ext4, `debootstrap`, grub). It is a thin layer over [`harness/tools/ci26_vm.sh`](../../../tools/ci26_vm.sh) and keeps every rule of that script.

| Script | Purpose |
|---|---|
| `up.sh` | create (or boot) the guest, install the extra packages, check the toolchain; also `status`, `ssh CMD`, `put`, `get`, `start`, `stop`, `provision`, `env` (print and check the settings, no guest needed) |
| `build-ipxe.sh` | build the iPXE targets with the driver from a clean pinned tree, and check what the CI job `ipxe` checks, with gcc 15: zero warnings, driver in / self-tests out of the images, licence, Secure Boot refusal (with a control build of the pristine tree), the self-tests (64 and 32 bit, UBSan, negative control) |
| `build-harness.sh` | the CI ctest matrix of the harness (gcc and clang; Debug, Debug + ASan/UBSan, Release, MinSizeRel) plus the object and compile gates |
| `down.sh` | destroy the guest and everything of it; checks that no process is left |
| `selftest.sh` | offline self-test of the four scripts above (no VM, no ssh): `bash selftest.sh`, also ctest `builder.selftest` |

`up.sh` is also a library: the other scripts `source` it for the shared functions.

## The rules (all enforced by the scripts)

- The guest has **at most 8 cores and 12 GiB** (`BUILDER_CPUS`, `BUILDER_RAM_MB`; larger values are refused). Disk: 60 GiB, sparse.
- Every process the scripts start on the box runs as `nice -n 19 choom -n 600 --`.
- Before a guest is started the box must have **MemAvailable >= 64 GiB** (`ci26_vm.sh`); otherwise nothing starts.
- Networking is QEMU **user-mode** only: the one way in is an ssh port forwarded on the box's `127.0.0.1`. No bridge, no tap, no change to the host's network.
- Everything lives under **one state directory** (`BUILDER_DIR`), marked by a file. A directory that is not empty and has no marker is refused; `down.sh` deletes only known sub-directories of a marked one.
- Only one job at a time per guest (the lock of `ci26_vm.sh run`), so the timing-sensitive ctest checks never run beside a build.
- The key to the guest lives in the state directory (mode 600), never in the repository, and `down.sh` deletes it. The guest's `ci` user has passwordless sudo **inside the guest only**.
- **No secret travels.** The copy of the repository that goes to the box and into the guest leaves out `lab.conf`, `*.key`, `*.keyring`, `keyring`, `*.secret`, `*.pem`, `*.p12`, `id_ed25519*`, `id_rsa*`, `id_ecdsa*`, `ceph.conf.local` and `lab-secrets` (a working-tree copy can hold files that `.gitignore` keeps out of commits, so `.gitignore` alone would not do). The six keyrings of the public test vectors (throwaway cephx users, committed on purpose, read by the vector tests) and the pinned iPXE tree are let through. Nothing here embeds a cephx key into an image, and no script prints one.
- **A script runs from a file, never from the ssh pipe.** Guest scripts are written to `~/.builder/NAME.sh` and run with stdin on `/dev/null`. (`bash -s` reads its script as it goes: any program in it that reads stdin, `apt` or a package prompt for example, would eat the following lines and the run would end half-done with status 0.)

## Two ways to run it

**From your machine** (nothing is compiled there). The script copies the repository, plus a *clean shallow clone of the pinned iPXE revision* made from your `third_party/ipxe` (committed files only, 11 MB), to the box, and runs the same script there; logs (and, with `BUILDER_LOCAL_OUT`, the results) are copied back.

```sh
export BUILDER_HOST=user@box
export BUILDER_SSH_OPTS="-J user@jump -o HostKeyAlias=box"      # optional
export BUILDER_DIR=/home/user/somewhere/builder26                # absolute, on the box; required with BUILDER_HOST
export BUILDER_IMAGE_CACHE=/home/user/somewhere/ci26/dl         # optional: a directory that already has the cloud image + SHA256SUMS

harness/lab/p2/builder/up.sh                 # create + provision (a few minutes), idempotent
harness/lab/p2/builder/build-ipxe.sh         # five targets + licence + Secure Boot refusal
harness/lab/p2/builder/build-harness.sh      # the ctest matrix
harness/lab/p2/builder/down.sh               # destroy
```

A snapshot instead of the working tree: `BUILDER_TREE=/path/to/snapshot` ships that directory (for example `git archive HEAD` plus the files you want to test; it must contain `harness/lab/p2/builder`) while the pinned iPXE clone still comes from this repository's `third_party/ipxe`. Useful when the working tree is in the middle of an edit (for instance a stale `core/sources.txt`: the build stops with `core/sources.txt is stale`).

**On the box**: the same commands with `BUILDER_HOST` unset, from a copy of the repository whose `third_party/ipxe` is a git checkout at the revision of `ipxe/PINNED` (the "from your machine" mode produces exactly that under `$BUILDER_DIR/stage/repo`, which is also where a script of another module finds the tree: `bash $BUILDER_DIR/stage/repo/harness/lab/p2/builder/up.sh ssh 'uname -r'`). **Long jobs** (the harness matrix takes about 2.5 hours): do not run them in a foreground ssh session. A dropped connection (or a tool timeout) breaks the pipe the script prints into and the job dies at its next line of output. From your machine set `BUILDER_DETACH=1`: the job is started on the box detached from the session, the call returns in seconds and prints `BUILDER_DETACHED_LOG=<path on the box>`; follow it with `ssh <box> tail -f <path>`; it is finished when the last line is `BUILDER-EXIT <status>`. On the box use `nohup ... > log 2>&1 &` yourself.

State directory layout (`BUILDER_DIR`):

```
.winrbd-builder-dir      marker
ci26/                    ci26_vm.sh state: dl/ (cloud image, copied from the cache), vm/ (disk.qcow2, id_ci26, port, qemu.pid), logs/
stage/repo/              the repository copy (from your machine) - where the scripts run from
out/ipxe/                build-ipxe.sh results: ipxe.efi, undionly.kpxe, ipxe.pxe, ipxe.usb, ipxe.iso, snponly.efi, efi-ipxe.iso, results.txt, logs, SHA256SUMS
logs/                    short logs of every run, builder-versions.txt
ready                    extras-list revision installed in the guest
```

### The cloud image

The download of the Ubuntu 26.04 cloud image (860 MB) is slow on the lab box, so `up.sh` first looks for a copy: `BUILDER_IMAGE_CACHE`, then `$BUILDER_DIR/../ci26/dl`, then `$HOME/winrbd-ci26/dl`; it checks the copy against that directory's `SHA256SUMS` and puts it into `ci26/dl` (**the marker file of `ci26_vm.sh` is created first**, so that `create` accepts a directory that already holds a file). `ci26_vm.sh create` then compares the file with the current upstream `SHA256SUMS` and downloads only when they differ.

## `up.sh`: what is in the guest

From `ci26_vm.sh create` (the CI packages): `build-essential gcc cmake ninja-build libssl-dev python3 gcc-multilib clang valgrind git curl rsync`.
Added by `up.sh` (`extras-2`):

- iPXE: `liblzma-dev` (iPXE's `zbin`), `gcc-multilib` (the BIOS targets are 32-bit), `mtools xorriso syslinux syslinux-common isolinux` (`util/genfsimg` for `bin/ipxe.iso` looks for `isolinux.bin` and `ldlinux.c32` in fixed system directories), `patch git perl make binutils`.
- Sanitizers: `libclang-rt-N-dev` (the compiler-rt runtimes of clang; the ci26 package list does not pull them in, and without them every `-fsanitize=address,undefined` link of the clang matrix fails with `cannot find libclang_rt.asan.a`).
- Image building (for the `linux-images` module): `qemu-utils` (`qemu-img`), `parted gdisk dosfstools e2fsprogs kpartx fdisk util-linux xz-utils zstd cpio`, and, when the release has them, `debootstrap mmdebstrap grub-pc-bin grub-efi-amd64-bin grub-common squashfs-tools`. Loop devices work with `sudo losetup` inside the guest.

After installing, `up.sh` **verifies** every tool and file the scripts rely on (`gcc -m32` builds an object, a loop device attaches, `qemu-img create` works, `isolinux.bin`, `ldlinux.c32`, `lzma.h`, a program links and runs with `-fsanitize=address,undefined` under both compilers) and fails with the list of what is missing. The verification output and the compiler versions are saved in `logs/builder-versions.txt`.

For the image role, use the guest like this (all on the box):

```sh
up.sh put ./my-build-dir work/images/            # rsync into /home/ci/work/images/
up.sh ssh 'cd work/images && sudo ./make-image.sh'   # sudo, loop devices, qemu-img inside the guest
up.sh get work/images/out/ ./images-out/         # copy results back to the box
```

Images are staged under the guest's `/home/ci`; the guest disk is sparse and 60 GiB. Do not leave images in the guest when you are done: `down.sh` deletes the whole guest, so copy what you need out first.

## `build-ipxe.sh`: what it proves

It copies the repository and the pinned iPXE clone into the guest and runs, in the guest, with the compilers of the CI runner:

| # | Check | Pass when |
|---|---|---|
| 0 | `ipxe/tools/build.sh check`, pinned revision | the glue files carry `FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )` and `FILE_SECBOOT ( FORBIDDEN )`, no name collides with the core; `third_party/ipxe` is at `ipxe/PINNED` |
| 1 | `build.sh build` of `bin-x86_64-efi/ipxe.efi`, `bin/undionly.kpxe`, `bin/ipxe.pxe`, `bin/ipxe.usb`, `bin/ipxe.iso`, `bin-x86_64-efi/snponly.efi`, `bin-x86_64-efi/ipxe.iso`, from a clean prepared tree | exit 0 with iPXE's own `-Werror`, **zero** lines containing `warning`, no `error:`; every target exists |
| 2 | the driver is linked, the self-tests are not | in the link maps of `ipxe.efi`, `undionly.kpxe`, `ipxe.pxe`, `ipxe.lkrn`: `rbd_uri.o` is there, no `rbd_selftest` / `tests.o`; the console line of the URI check is in `ipxe.efi` and `rbd_selftest` is not |
| 3 | `build.sh licence bin/undionly.kpxe bin-x86_64-efi/snponly.efi` | the line right after `The overall licence for this file is:` is exactly **GPL version 2 (or, at your option, any later version)** for both. (The `subsumes` lines above the verdict contain that text too, so a search over the whole output would also pass a GPL-2-only or a mixed result.) |
| 4 | `build.sh build bin-x86_64-efi-sb/snponly.efi` | **fails** with `not permitted to be signed for UEFI Secure Boot` and leaves no binary; and every compiled glue and core object (more than 50) carries the symbol `__secboot__forbidden__<object>` (the refusal is one verdict for the whole image: a single file marked `PERMITTED` would not change it) |
| 5 | control: the same `-sb` target from the **pristine** pinned export (no patch, no driver) | **succeeds**, so that 4 fails because of the driver |
| 6 | `build.sh test` (64-bit program, `bin-i386-linux/tests.linux`), `test -u` (both, UBSan in trap mode), `test -n` (negative control) | each accepted by `build.sh` itself: exit 0, `OK: all N tests passed`, no `FAILURE`, an `OK` line for every file of `ipxe/tests`; the negative control must fail for exactly the deliberate reason |

The all-driver images (`ipxe.efi`, `ipxe.pxe`) fail iPXE's own licence check on the pristine tree too (InfiniBand NIC headers without `FILE_LICENCE`), which is why check 3 uses the two targets without NIC drivers (`docs/design/ipxe-driver.md`, section 3). Sizes are printed next to the skeleton table of the design document for information (that table was measured with gcc 11.4; sizes differ with the compiler and are not asserted).

Options: `-j N`, `-k` (keep the build trees in the guest), `-C` (skip check 5), `-T` (skip check 6), `-S` (power off afterwards). Exit status: 0 every check passed; 1 a check failed; 2 no verdict (ssh or rsync failed, a signal: a status other than 0 or 1 from the guest is never reported as a failed check). Each build step has a 50-minute `timeout`, so a hung build cannot hold the guest. `results.txt` starts with the tool versions and a digest of the tree that was built (the box's copy of the repository can be replaced by another driver between two runs). Results go to `$BUILDER_DIR/out/ipxe/` (`results.txt` has the check lines, tool versions and what failed; the build trees in the guest are deleted unless `-k`). The binaries are what a QEMU row of the matrix boots: they are plain files in `out/ipxe/` on the box (`ipxe.efi`, `undionly.kpxe`, `ipxe.pxe`, `ipxe.usb`, `ipxe.iso`, `snponly.efi`, `efi-ipxe.iso` = `bin-x86_64-efi/ipxe.iso`), with `SHA256SUMS`.

## `build-harness.sh`: the CI matrix

`build-harness.sh [-c "gcc clang"] [-f "debug san release minsizerel"] [-s "matrix gates"] [-l LABEL] [-j CTEST_JOBS] [-S]` first checks its words (an empty stage list, an unknown flavour or compiler, a label that is not a plain word are refused with exit 2: such a run would test nothing and read as green), then runs `ci26_vm.sh run` on the repository: for every compiler and flavour a `cmake -G Ninja` configure with `-DWR_WERROR=ON`, a build (any `warning:` line fails the flavour), `ctest -j 4 --timeout 600 -LE lab --no-tests=error`, and the named checks (`core.docs`, `core_sources_in_sync`, `core_freestanding*`, `core_no_libc`, `core_no_globals`) which must have **passed**, not skipped; then the compile and object gates of `harness.yml`. Flavours: `debug` = Debug, `san` = Debug + ASan/UBSan, `release`, `minsizerel`, `relsan`, `minsan` (`-f all` = all six). While it runs, a load log is written next to the short log (`harness-<label>-<time>.log.load`: the box's and the guest's load average every 30 s, and a summary line at the end), so that a timing flake can be judged against what the shared box was doing; `-j N` lowers ctest's parallelism (default 4, as CI). The script adds two checks on top: the guest's compilers must be gcc 15.2 and clang 21.1.8 (otherwise it refuses, `BUILDER_ALLOW_OTHER_TOOLCHAIN=1` overrides and marks the result), and the log must have a `PASS` line, found by exact name, for every requested compiler/flavour of the matrix and for every gate of the gates stage (`<cc>/wr_core_m32`, `wr_header_check`, `gates-Release`, `gates-MinSizeRel`, and `gcc/wr_core_ipxe_flags`): a skipped or empty stage is not green. The load sampler is stopped when the script ends, also on Ctrl-C. Exit status 0 / 1 / 2 = passed / failed / nothing tested.

## `down.sh`

`down.sh [--keep-image] [--keep-out] [--keep-logs]` powers the guest off, deletes its disk, key, staged trees, the repository copy, `out/`, `logs/` (and `ci26/logs`) and the cached image, removes `BUILDER_DIR`, and then looks for processes whose command line names `BUILDER_DIR` (this script and its ancestors excluded): any left is an error (exit 1). It refuses while a `build-*.sh` run holds the guest. The `--keep-*` flags are independent and leave the named part in place (and keep the directory; `--keep-logs` keeps both `logs/` and the `ci26_vm.sh` logs under `ci26/logs`); a second `down.sh` without them removes the rest.

## Limits and notes

- `up.sh` stops with a message when it finds a guest disk whose `create` never finished (no `versions.txt`): run `down.sh`, then `up.sh` again; booting such a disk would fail in confusing ways. A submodule checkout (`.git` is a file) cannot be copied into the guest as it is: the "from your machine" mode stages a real clone, on the box a plain clone is needed.
- **One driver at a time.** Every run from your machine re-stages the repository on the box (`stage/repo`) before it waits for the guest lock, so two drivers started at once can replace the tree a waiting job is going to copy. The jobs themselves are serialised (one lock), and every log records a digest of the tree it ran on; start a second job only after the first has copied its tree (the first lines of its log), or use `BUILDER_TREE` snapshots in separate state directories.
- The guest runs under KVM (`/dev/kvm` must be usable by the calling user); a build in emulation would be too slow to be a test.
- Timing tests are affected by load spikes of the box (other people's work): judge a flake against the load, never by weakening a test.
- `build-harness.sh` is the CI matrix; the libFuzzer smoke run and the call-graph stack budgets stay with CI and `fuzz_long.sh`, as in `ci26_vm.sh`.
- The guest reaches the internet through QEMU's user-mode NAT (for `apt`) and nothing can reach it except through the one forwarded ssh port on the box's loopback. It is a build and image machine only: it does not run the QEMU rows of the matrix and has no path to the Ceph lab.
- WinPE images cannot be built here (no legal, redistributable way on Linux): the guest does not try.
