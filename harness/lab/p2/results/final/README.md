<!-- SPDX-License-Identifier: MIT -->
# The final matrix: every row run again on the final binaries (close-out review, 2026-11-24)

The rows of `docs/design/ipxe-driver.md` section 14.3 that the close-out review (module `p2-review`, section 18 of the design document) ran **again after its fixes**, with the binaries built from the sources as they are in
the repository: the 32-bit and 64-bit BIOS images, `ipxe.efi`, the USB and CD media, each from `ipxe/tools/build.sh` / `harness/lab/p2/results/measure/tools/build-variants.sh` in the Ubuntu 26.04 builder guest (gcc 15.2, iPXE's own
`-Werror`, no warning). The lab is the dedicated one of `harness/lab/p2/cluster` (a real Ceph v20.2.5: monitor, three OSDs, in a VM on the build machine, its own layer 2). Guests: QEMU 6.2 / KVM, OVMF 4M (Secure Boot **off**)
or SeaBIOS, `-smp 2 -m 2048`.

What is here is the **small evidence** of each row, one directory per row under `rows/`: the command line (a key is only ever a file name), the hashes of the binaries, the run script's `RESULT` line, the stage times with the load of the
machine and the guest's CPU wait, the verdict of the analysis, and an **excerpt** of the guest's console (`serial.excerpt.txt`: the first 60 lines, every line the verdicts look at, the last 30). The full consoles were
scanned for the cephx key by the run scripts and by the analysis and stay on the build machine; the verdicts were made from them. (They are not copied here, for size. The `.gitignore` of this repository has an exception for `*.log` below `harness/lab/p2/results/`, so the
full consoles of the other families are kept: see section 18.4 of the design document.) `MATRIX.md` is the table of all rows; `BINARIES.txt` has the SHA-256 of every binary that ran; `gate-results.txt` is the build gate (`harness/lab/p2/builder/build-ipxe.sh`) on the same sources: 11 targets, the licence verdict, the Secure Boot refusal, the self-tests.

| Directory | What |
|---|---|
| `rows/runs-*` | one boot of a guest image through the driver, with the stage timer of the UEFI rows (`mboot.sh`): the login rows U1 to U3 and B1 to B3, the WinPE rows W1 to W4, the 64-bit BIOS rows, the loss rows (`loss2pct-*`, `loss8pct-*`: 4 MiB receive window against 64 KiB with loss on the lab's replies), the read bench with four windows (`rd-*`) |
| `rows/rows-*` | the UEFI rows of `results/uefi/tools/matrix.sh`: U0 (the firmware shell shows the device path of each flavour), the byte check, the negative rows, the `uri`, `sata` and `handoff=key` boots |
| `rows/robust-*` | the robustness rows of `results/robust/tools/matrix.sh` (one fault each) and the negative rows of both families |
| `rows/attempts-*` | rows that did not count and why (the first WinPE import had the image's default features, which the writer profile refuses; the first UEFI-shell rows used a build with iPXE's own serial console, so every character of its output was doubled; two rows named an option twice; one did not start) |

Rules these rows were run under are those of `results/README.md`: one throwaway cephx user per image (legacy `aes` key, deleted with the image), no key in any file, argument or log, a failure is counted and never retried away, binaries
and images that are not this project's (the firmware's shell, the owner's WinPE images) are never committed.

`BINARIES.txt` names the builds: `rel/` (the release builds the login rows use: `ipxe.efi`, and the 32-bit BIOS `ipxe-stub.pxe`, a build with the constant PXE stub), `media/` (`ipxe.efi`, `ipxe.lkrn`, the media rows), `inst/`
(stack monitor and `DEBUG=malloc`), `ab-old/` and `ab-new/` (the same UEFI build with `RBD_CONN_RX_WINDOW_MAX` of 4 MiB and of the default 64 KiB, with the stack monitor: the counters line and the heap probe), `x64/` and
`x64inst/` (the 64-bit BIOS build, plain and with the stack monitor).
