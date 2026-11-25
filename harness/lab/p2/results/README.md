<!-- SPDX-License-Identifier: MIT -->
# Results of the Phase 2 live matrix

The rows of `docs/design/ipxe-driver.md` section 14.3 that were run against the dedicated lab (`harness/lab/p2/cluster`), one directory per firmware family. Everything here is evidence, not
expectation: a row says what was observed, and a row that failed says FAIL.

| Directory | Rows | Written by |
|---|---|---|
| `uefi/` | U0, U1, U2, U3 (OVMF), the SAN-level byte check, the negative rows, and W1/W2 (the owner's WinPE image, UEFI) | module `qemu-uefi`; start at `uefi/README.md` |
| `bios/` | B0 to B3 (SeaBIOS) and W3/W4 | module `qemu-bios`; start at `bios/README.md` |
| `bios2/` | the BIOS rows B0 to B3 and W3/W4 run again after the BIOS-specific work (the boot firmware table area, the 32-bit images, the stack) | module `ipxe-bios`; start at `bios2/README.md` |
| `robust/` | milestone 7: U1 and B1 with one fault injected while the guest reads (monitor or OSD killed, link cut, all OSDs stopped, a stalled guest), and the negative rows | module `qemu-robust`; start at `robust/README.md` and `robust/MATRIX.md` |
| `measure/` | the exit measurements of design 14.4 (boot time, read throughput against readahead and receive window, heap and stack watermarks, the loss rows): the commands, the evidence of every run and the tools; the numbers are in `docs/design/ipxe-driver-measurements.md` | module `measure`; start at `measure/README.md` and `measure/RESULTS.md` |
| `final/` | the rows run again on the final binaries after the close-out review (both families, WinPE, device paths, robustness, negatives, the receive-window A/B), the build gate and the ctest matrices | module `p2-review`; start at `final/README.md` and `final/MATRIX.md` |

## The shape of one row (both families)

A row is a directory with the command line that ran it (`cmdline.txt`; a key is only ever a file name), the exact hashes of the binaries it used (`binaries.sha256`), the guest's serial console
(`serial.log`, scanned for the cephx key by the run script and again by the module), the stages with their times (`stamps.txt`), the run script's `RESULT` line (`result.txt`), what the analysis counted
(`facts.txt`) and the verdict (`verdict.txt`). **PASS** means every check of the row's profile held; **FAIL** means one did not (the line says which, with what was seen); **BLOCKED** means the guest did not run at all (no room
on the machine, QEMU did not start) and says nothing about the driver. A row is judged by `analyze.py` from the logs; `p2u.sh rejudge` judges a directory again when a rule changes, without running it again.

## Rules these results were made under

* One throwaway cephx user per image (legacy `aes` key, caps limited to the pool), created for the run and deleted afterwards with the image; no key in any file of this tree, in any argument or in any log (the run scripts
  discard a log with the key in it; the evidence was scanned again for the keys of the run and for the shape of a key).
* The lab is a real Ceph v20.2.5 cluster in a VM on the build machine, reached over a private layer 2 that QEMU makes itself; nothing on the machine's network is touched, and the lab holds only what a row needs while it runs
  (the listing after the run is in each family's `lab-after.txt`).
* A timing-sensitive result is judged against what the machine was doing: `stamps.txt` records the host's load and how long the guest's threads waited for a CPU, and a failure is counted, never retried away; repeats are separate rows.
* Binaries and images that are not this project's (the firmware's shell, the owner's WinPE image) are never committed or published.
