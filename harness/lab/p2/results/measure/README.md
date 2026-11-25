<!-- SPDX-License-Identifier: MIT -->
# Exit measurements of the iPXE `rbd://` driver (design section 14.4)

Everything here is evidence or the tools that made it. **The numbers, the method, the verdict per risk and the list of what changed in the design are in
[`docs/design/ipxe-driver-measurements.md`](../../../../../docs/design/ipxe-driver-measurements.md)**; this directory has the commands, the
evidence of every run and the scripts, so that a figure can be taken apart and made again.

| Path | What |
|---|---|
| `tools/bench.S` | the **bench program**: a BIOS boot sector that times INT 13h commands through the SAN layer (reads and copies of any command size up to 4 MiB, latency series, an idle gap), with the TSC, and checks the data it reads against sums of the image. The caller of the measurements, since after `sanboot` iPXE has no shell and no command reads raw sectors |
| `tools/mkbench.py` | assembles `bench.S`, patches the plan into it, writes the disk (a deterministic pseudo-random data area and a scratch area) and `plan.json` (the records, the expected sums, the digests of every copy's source). `verify` checks a copy run against `rbd export` (`--strict`: and that nothing else of the image changed) |
| `tools/analyze.py` | the console of one run -> `facts.json` + `verdict.txt` (TSC calibration, MiB/s per step, latencies, `rbd-info` counters, stack and heap marks, the data check, every step against the plan's sectors and number of commands; boot rows: stage seconds) |
| `tools/summarize.py` | the tables (median, minimum, maximum, n) from the evidence directories. Only runs whose verdict is PASS are summed; the others are listed |
| `tools/captan.py` | reads a `tcpdump` of the guest's connections: segments, the largest segment, bytes in flight, the time between segments, the time to the acknowledgement (risk R6) |
| `tools/mrun.sh` | one bench run in a SeaBIOS guest through the driver: lab snapshots before and after, host and lab load and CPU wait, optional `tc netem` delay, optional idle timeout of the daemons, optional capture, key scan, analysis |
| `tools/mboot.sh` | one boot of a Linux or WinPE guest image through the driver, timed to the login prompt with `stamp.py` of the UEFI rows (rows U1 to U3, B1 to B3, W1 to W4) |
| `tools/mguest.sh`, `guest/` | the **kernel client on the same path**: a Linux guest (the lab VM's own kernel, a static busybox, `rdbench.c`) on the same layer 2 with the same virtual NIC, mapping the same image with the same key, reading it with `rdbench` |
| `tools/krbd.sh` | the kernel client inside the lab VM (loopback path) on the same image |
| `tools/mimages.sh` | makes the bench disks, puts them into the lab (image + throwaway cephx user + key file), takes them out again |
| `tools/mheapbase.sh`, `tools/mheapefi.sh` | iPXE's heap maximum with nothing hooked (BIOS), and on UEFI with the image hooked and one file read from the ESP (the `HEAP maximum usage` line of a `DEBUG=malloc` build) |
| `tools/mkloop.sh` | the iPXE script of the R10 test: hundreds of hooks in one iPXE session, and hooks after the 120 s grace of the session cache |
| `tools/build-variants.sh` | the iPXE builds (release, instrumented, media, sizes with and without the driver) made in the builder guest with iPXE's own `-Werror` |
| `tools/campaign.sh` | the series of runs, in the order they were made |
| `tools/selftest.sh` | ctest `measure.selftest`: the analysers on synthetic data with negative controls, the assembled bench in QEMU (software emulation) on a plain disk, the option refusals |
| `tools/box-env.example` | the environment of the scripts on the build machine |
| `runs/NAME/` | the evidence of one counted or listed run (below); `attempts/` holds runs that never got going or were stopped by hand, with the reason in the directory name |
| `RESULTS.md` | the tables, as `summarize.py all runs/` printed them |
| `BUILD-INFO.txt`, `builds/` | the builds the runs used: hashes, flags, the digest of the sources; sizes of the images with and without the driver (`builds/sizes/*/sizes.txt`) |
| `logs/` | the series logs (`chain-*.log`, `campaign-*.log`) and the ctest logs of the builder guest (gcc and clang, Debug, Release, ASan and UBSan configurations) |
| `lab-base.txt`, `lab-final.txt` | the lab's state before this module put anything in it and after it took everything out again (they differ in one line: the OSD blocklist, 5 entries then and 12 now; see the document, section 12) |

## The bench program in one paragraph

`bench.S` is the first sector of an RBD disk that iPXE hooks as drive 0x80 and boots (`sanboot`). A plan of up to 64 records is patched into its second stage. A
read step issues INT 13h AH=42h commands of the step's size back to back; commands up to 127 sectors use the classic packet (segment:offset, a buffer at
0x10000, what a boot loader does), larger ones the EDD 3.0/4.0 packet (count 0xff, a 32-bit count, a 64-bit buffer address at 8 MiB). The time of every command is
`RDTSC` before and after the call; the TSC rate is measured against the BIOS tick (91 ticks of 18.2065 Hz, about 5 s) at the start and at the end (the two agree to
better than 0.05 % in every run). After a step the first and the last 64 KiB of the last command's buffer are summed (through INT 15h AH=87h for extended memory) and the
sums must equal those of the same bytes of the image: a buffer the driver did not fill would not have the sum. A copy step reads a command's worth and writes it to a
scratch area; its digest is checked from outside (`rbd export` of the image against the source's). A latency series reads far-apart blocks (no sequential
pattern, so no readahead window) and can wait first (`HLT` until the BIOS tick counter has moved): the idle gap. The program prints one line per step on COM1.

## A run

`runs/NAME/` (made by `mrun.sh`): `cmdline.txt` (the command; the key is only a file name), `binaries.sha256` (the iPXE binary, the run script, `bench.S`, the plan,
QEMU, the image's id), `plan.json`, `serial.txt` (the guest's console), `result.txt` (the run script's RESULT line), `load.txt` (host and lab VM load, and how long the
guest's and the lab VM's threads waited for a CPU, every 5 s), `lab-before.txt` / `lab-after.txt` / `lab-diff.txt` (the lab's state before and after: the diff must be
empty), `facts.json`, `verdict.txt`. Boot runs (`mboot.sh`) have `stamps.txt` instead of the plan. Kernel-client runs have `krbd.txt` (one `KRBD ...` line per pass).

A run that fails stays in the tree and is counted: `summarize.py` lists it and does not average over it.

## Rules these runs were made under

* The cluster is the dedicated lab of `harness/lab/p2/cluster` (a real Ceph v20.2.5: one monitor, three OSDs on one host, size 3, in a VM on the build machine); the main
  lab and its Phase 1 run were not used. One throwaway cephx user (legacy `aes` key, caps limited to the pool) per image; images and users are deleted at the end
  (`mimages.sh delete-all`), the lab's state before and after is compared by `labstate.sh` (`lab-base.txt`, `lab-final.txt`).
* The build machine is shared and was busy with other people's jobs (load average 25 to 70 on 100 cores) during the runs: a figure is the median of three or more runs,
  the spread is shown, and every run records the load and the CPU wait of the guest and of the lab VM. Nothing was retried away.
* No key in any file of this tree, in an argument or in a log; every evidence directory was scanned for the run's own key.
* Binaries that are not this project's (the owner's WinPE image, the firmware) are never committed.

## Known limits of the tools (found by the review of this module)

* **The data check is a spot check.** `bench.S` sums the first and the last 64 KiB of a step's *last* command, not every command; the rest of a step is covered by the plan check of `analyze.py` (the console must report the planned sectors in the planned number of commands, no error line), which cannot see a buffer that was filled with wrong bytes by a command that reported success.
* **`bench.S` waits on the BIOS tick counter without handling its midnight wrap** (the counter restarts at 0 after 0x1800B0 ticks, and SeaBIOS starts it from the guest's clock, which is the host's UTC): a calibration (5 s) or a gap (up to 960 s) that spans midnight UTC in the guest never ends. None of the counted runs did (they all finished), and the file is **not** changed here on purpose: `binaries.sha256` of every run records the hash of this very `bench.S`, and that provenance is worth more than the fix. A new campaign should not start within 20 minutes before 00:00 UTC, or the three places (`do_cal`, the gap loop in `do_lat`, the step's tick delta) should use a wrap-aware difference first.
* **The TSC calibration prints `ticks=91` as a constant** and does not read the tick counter again after the second edge; if the guest had missed a tick the rate would be 1.1 % off. The two calibrations of every run agree to 0.001 to 0.05 %, which a missed tick would have shown.
* **`mrun.sh --capture` kills every `tcpdump` on the lab VM** (`pkill -x tcpdump`), which is fine on the dedicated lab and would also stop someone else's capture on a shared one.
* **Captures taken before the review have no `-S`**: for a connection that was open when tcpdump began, one packet is printed in absolute numbers and the bytes in flight came out as 0 (`captan.py` now reports "not measured"; see the document, section 7).
