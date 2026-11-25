<!-- SPDX-License-Identifier: MIT -->
# Milestone 7: the robustness rows (kill, pause, cut, stall) of the iPXE `rbd://` driver

Rows U1 (OVMF, `ipxe.efi` over PXE) and B1 (SeaBIOS, i386 `ipxe.pxe` over PXE) of `docs/design/ipxe-driver.md` section 14.3 with **one fault injected into the lab or the guest while the
guest reads through the driver**, on 2026-11-23/24. Everything here is evidence: a row says what was seen, and a row that failed says FAIL.

* The cluster is the dedicated lab of `harness/lab/p2/cluster` (a real Ceph v20.2.5: one monitor, three OSDs on one host, size 3, in a VM on the build machine), the guests are QEMU/KVM
  guests on its private layer 2 (`10.77.0.0/24`), driven by `harness/lab/p2/qemu` with the fault driver `harness/lab/p2/qemu/robust.sh` (new, this module). Nothing on the
  build machine's network was touched; the main lab (`~/w/lt2`, the Phase 1 exit run) was not used at all.
* The iPXE binaries are the ones of `builds/BUILD-INFO.txt` (current tree, pinned iPXE 9261ebe38, gcc 15.2, zero warnings under iPXE's own `-Werror`).
* Findings are in section 4; the table of every row is `MATRIX.md` (made by `tools/summarize.py`); each row is one directory of `rows/`.

## 1. What is in this directory

| Path | What |
|---|---|
| `../../qemu/robust.sh` | the fault driver: `run-uefi-pxe.sh` / `run-bios-pxe.sh` (same library `common.sh`, same limits and clean-up) with a different waiting loop that stamps every console line, waits for a trigger line, injects **one** fault in the background, and puts everything back before it returns (also after a signal, also when the guest ends first). Faults: `mon-kill`, `mon-osd`, `osd-kill`, `pause`, `link-down`, `stall`, `outage`, `none`; options `--on`, `--delay`, `--down`, `--osd`, `--press`, `--idle-timeout`, `--capture` |
| `tools/rr.sh` | one row: makes the guest's iPXE script, runs `robust.sh`, snapshots the lab before and after, keeps the logs, scans every file for the run's own key, judges the row |
| `tools/matrix.sh` | the table of rows (name, family, workload, fault, trigger, timing, what it shows), `run`, `oracle`, `cleanup`, `rejudge`, `summarize` |
| `tools/analyze.py` | the verdict of a row from its files (profiles `bytes`, `reader`, `boot`, `bootgive`, `negative`) and `facts.txt` |
| `tools/labstate.sh` | the lab's state as stable text (cephx entities and caps, pools, images, OSDs, flags, upmaps, configuration database, health check names, quorum), and the diff that must be empty |
| `tools/reader.S`, `tools/mkreader.py` | the INT 13h reader (a boot sector, section 2) and the program that makes its disk and the oracle's side of its hash |
| `tools/summarize.py` | `MATRIX.md` |
| `tools/selftest.sh` | ctest `robust.selftest` (155 checks): option refusals, every fault and its undo against a QEMU stand-in and a lab stub, the verdicts on synthetic evidence with their negative controls, the reader's assembly |
| `expect/` | `bytes.md5` (the md5 list the byte-check disk was built from), `reader.prefix` (the oracle's hash after every progress point of the reader and at the end) |
| `builds/BUILD-INFO.txt` | the two iPXE builds and the four guest images |
| `rows/NAME/` | one row (below); `attempts/` runs that did not count and why |
| `review/` | the live smoke rows of the review of section 7 (the same row scripts, the fixed driver, a fresh lab image; same files as a row directory, paths replaced by `<...>`) and the self-test logs of that review |
| `oracle-start.txt`, `oracle-end.txt` | SHA-256 of `rbd export` of every image before the first row and after the last, against what was imported (they must be equal: the guests never write) |
| `lab-base.txt`, `lab-final.txt`, `lab-restore-diff.txt` | the lab's state before anything of this module existed, after it was all deleted again, and their difference |

A row directory has `cmdline.txt` (the exact command; the key is only a file name), `binaries.sha256`, `serial.txt` (the guest's console), `ts.txt` (the same, every line with the epoch second
it was first seen, resolution 0.25 s), `fault.txt` (what the driver did, with times), `syn.txt` (the lab VM's capture, see 2), `stdout.txt`, `result.txt`, `lab-before.txt`, `lab-after.txt`,
`lab-diff.txt`, `lab-health.txt`, `facts.txt` (what the analysis extracted), `verdict.txt` (PASS / FAIL / BLOCKED, then one line per check).

## 2. How a row is made

**Workloads.** Two ways of reading, because the two firmwares offer different tools, and a Linux boot for each family:

| Workload | Family | What the guest does | How the bytes are checked |
|---|---|---|---|
| `bytes` | U1 | `sanhook` the byte-check disk (GPT + FAT32, 17 files from 1 byte to 80 MB, 143.5 MB, built by `results/uefi/tools/build-bytes-image.sh`); the script reads every file through the firmware's file system driver (`imgfetch file://WRBYTES/<name>`) and prints its md5; `rbd-info` before and after | the md5 of every file equals the list the disk was built from (`expect/bytes.md5`); `rbd export` of the image has the SHA-256 of the image that was built (`oracle-*.txt`) |
| `reader` | B1 | `sanhook --drive 0x80` a disk whose boot sector is `tools/reader.S`, `sanboot` it. The reader is the loader: it reads 128 MiB with INT 13h AH=42h in commands of 127, 64, 33, 8, 1, 100, 17, 127 sectors (repeating), hashes every dword, prints a progress line every 4096 sectors and a verdict, and returns to iPXE with INT 18h, so that `rbd-info` can be printed afterwards | its hash after every progress point and at the end equals the oracle's (`expect/reader.prefix`, computed from the same seed by `mkreader.py --prefix`; the oracle of the image itself is `rbd export`) |
| `boot` | both | the Linux guest of `harness/lab/p2/images` (GRUB, kernel and initramfs read through the SAN device, then the guest's own kernel client takes over); Enter is pressed at GRUB's menu so that the kernel load starts at a known moment | `WRBOOT-ROOT-OK` with the root on `/dev/rbd0pN`, the 40 fields of the rBFT table checked in the guest, no failure marker |
| `boot-outage` | both | the same boot with every OSD stopped for 5.5 minutes from the kernel load on (the real loaders' reaction when the SAN layer gives up) | `bootgive`: the loader reaches an outcome (it boots after the cluster is back, or reports a read error and stops), never a damaged boot; if it boots, the table check passes |
| `neg-*` | both | wrong key, a pool and an image that do not exist, a monitor address nobody answers on | one driver console line with the right text, iPXE's own failure line, the right errno, nothing registered or booted |

**The canary** (design 14.3: "no byte lands in a released buffer"). The reader rotates three 64 KiB buffers. After a read it hashes the new one and remembers its dword sum; of the other two a buffer that
holds data must still have its sum (then it is overwritten with `0xA5A5A5A5`), and a buffer that holds the canary must still be all canary. A mismatch is a `WRRB-STALE` line. When a read **fails**
(the SAN layer gave up and handed the buffer back) the reader overwrites that buffer with the canary at once and retries the command in the next buffer, so a byte that still arrives later from a command the
driver did not really cancel breaks the canary and is reported. After the last read it waits a second and checks again. Only the BIOS family has this: on UEFI the firmware's file system driver owns the buffers,
and the proof there is the md5 of every file.

**Faults** (all of them undone after `--down` seconds or when the run ends, whichever is first; `fault.txt` says which):

| Fault | What it does in the lab VM or the guest | What it stands for |
|---|---|---|
| `mon-kill` | `systemctl kill -s KILL` of the monitor's unit, then `stop` (no automatic restart), `start` after `--down` s, wait for quorum | a crashed monitor |
| `osd-kill` | the same for `osd.1` | a crashed OSD (**the process dies, so its peers get a refused connection at once**: see finding 3) |
| `mon-osd` | the monitor is killed, one second later `osd.1`; the monitor is started after `--down` s, the OSD 10 s after that | an OSD that dies while nobody can mark it down or publish a map |
| `stall` / `outage` | `SIGSTOP` to every `ceph-osd` (nothing is refused, nothing answers, nobody is marked down), `SIGCONT` after `--down` s | a cluster that hangs: `stall` 20 s lies between the SAN layer's 15 s command timeout and the driver's 30 s watchdog, 40 s crosses both; `outage` (7 minutes) is long enough for the SAN layer to give up |
| `pause` | QMP `stop` of the guest, `cont` after 60 s | the idle gap: nothing in the guest runs, the cluster goes on |
| `pause` with `--idle-timeout 20` | the same, with `ms_connection_idle_timeout` of the monitor and the OSDs set to 20 s (`ceph config set`, removed afterwards) | an idle gap after which the daemons have closed the connections: the first command afterwards has to reconnect and authenticate again (design 11, "Idle gaps") |
| `link-down` | QMP `set_link` of the lab NIC, down 40 s, up | the cable pulled |

The fault is triggered by a console line (`--on`, `--delay`): for the byte check the start of the 17 MB file, for the reader its start line, for the Linux boot GRUB's menu (Enter is pressed one second later, the fault
comes 0.2 s after that, so the kernel and initramfs, 25 MB, are being read) or `Booting from SAN device` (the firmware reads GRUB from the ESP). `--capture` runs `tcpdump` in the lab VM on every SYN of the guest and every
packet to or from the monitor's ports (headers only), which is how new connections and the monitor's traffic are counted (`facts.txt`).

**Restoring the lab.** `labstate.sh snapshot` before and after every row (`lab-diff.txt` must say `no difference`), including the configuration database and the names of the health checks.
After a daemon is killed `robust.sh` asks cephadm for a refresh and waits until the set of health checks is the one the run started with (cephadm raises `CEPHADM_FAILED_DAEMON` for a killed unit and
keeps it until its next refresh, which once left a check behind that the next row saw as a difference: `attempts/`).

## 3. Results

Every directory of `rows/` is one run, the only one that counts for that row (a failed row is counted, not retried away); the runs that did not count are in `attempts/` with the reason (section 5). `MATRIX.md` has all of them with their counters.
Baselines (no fault): byte check 15.4 s (`U1-bytes-ctl`), INT 13h reader 11.5 s (`B1-reader-ctl`), the firmware's part of the Linux boot (SAN open to the first line the initramfs
prints, Enter pressed at GRUB's menu) 8.0 s on U1 and 8.6 s on B1. "slowest read" is the reader's own measure of its slowest INT 13h command (BIOS ticks of 55 ms); "new connections"
are TCP connections the lab VM saw the guest start after the fault began (for the boot rows the capture also holds the guest's kernel client after the firmware phase).

| Fault (design 14.3) | U1 byte check | B1 INT 13h reader | U1 / B1 Linux boot |
|---|---|---|---|
| **a** monitor killed, 20 s down | 10.6 s; nothing resent or cancelled; 4 reconnect attempts to the monitor in 7 s (gaps 0.9, 2.3, 3.8 s) | 12.8 s, slowest read 0.4 s | firmware phase 9.4 s / 7.8 s (the Linux kernel's own client then waited 19 s for the monitor on both: it is not the driver) |
| **a** monitor killed, back 2 s later (inside the read) | 14.9 s; the monitor is reconnected after its restart | 13.4 s, slowest 0.7 s | 10.8 s / 6.3 s |
| **a+b** monitor killed, then osd.1, monitor back after 15 s, OSD 10 s later | 38.1 s, 1 SAN cancel, 5 session resets, no path closed | 41.7 s, slowest read 27.7 s, 1 cancel | 35.1 s / 15.9 s (the kernel load waited for the monitor to publish a map; on B1 the Linux client then waited another 24 s for the monitor) |
| **b** osd.1 killed, 8 s / 45 s down | 12.5 s / 13.6 s (7 operations resent in the 45 s row) | slowest read 1.9 s / 1.5 s | ESP read: 12.2 s / 7.7 s; kernel load: 10.8 s / 20.2 s |
| **c** guest stopped for 60 s in the middle of a command stream | 72.4 s (= 60 + 12), no new connection, nothing resent | 73.6 s; the guest's CMOS clock jumped by 60 s, its BIOS tick count did not | 69.4 s / 67.1 s |
| **c** the same with the daemons closing idle connections after 20 s | 114.6 s; 1 monitor + 4 OSD connections started after the gap, 8 operations resent, 3 session resets | 80.3 s, slowest read 2.3 s, 1 monitor + 3 OSD connections, 7 resent | 69.4 s / 69.8 s |
| **d** lab NIC cut for 40 s | 57.3 s; path closed at 30 s (the console line), 3 cancels, 10 session resets | 56.9 s, slowest read 40.5 s, 3 cancels, 1 stall close, no error reached the loader | 51.7 s / 47.5 s |
| **f** every OSD stopped for 20 s (15 s timeout fires, 30 s watchdog not) | 33.6 s, 1 cancel | 34.1 s, slowest read 20.8 s, 1 cancel, canary clean | 27.7 s / 28.6 s |
| **f** every OSD stopped for 40 s (both fire) | 55.9 s, 3 cancels, 1 stall close | 54.9 s, slowest read 42.4 s, 2 cancels, canary clean | not run |
| **e** the cluster gone for minutes (SAN gives up) | `U1-bytes-outage`: the file being read when the cluster stopped answering failed after 155 s (11 cancels, 4 stall closes), the next file failed at once; every digest that was printed is right | `B1-reader-outage`: the first read error (`ah=04`) reached the reader 163 s after the cluster stopped answering, the second 166 s later; the third attempt completed 2 s after the cluster was resumed (421.7 s); 28 cancels, 13 stall closes; the final hash equals the oracle's, canary clean | `U1-boot-outage` (5.5 min): GRUB printed `error: failure reading sector 0xfce00 from hd0` 334 s after the stop (1.2 s after the cluster was resumed) and stopped; `B1-boot-outage`: GRUB printed nothing and went on waiting, the kernel started 6 s after the cluster was resumed and the system booted 40 s after it (root on `/dev/rbd0p1`, 40 table fields passed) |
| **e** wrong key | **FAIL**: `WR_E_M2_BAD_METHOD`, EPROTO instead of EACCES, after 20 s | **FAIL**: the same | |
| **e** no such pool / no such image | PASS: one line each (`pool not found`, `image not found`), ENOENT, 0.3 s | PASS | |
| **e** no monitor answers | PASS: `no monitor could be reached`, ENETUNREACH, after the driver's 20 s | PASS | |

Data: **every digest of every byte-check row is equal to the list (17 of 17 files; in the outage row two files failed to read and no digest that was printed is wrong), every progress hash and the final hash of every reader row equals the oracle's (`08ff74c1`), no read error
reached the reader in any row except the outage, no `WRRB-STALE` line anywhere, every Linux boot but the UEFI outage row reached `WRBOOT-ROOT-OK` with its 40 table fields passing (in that row GRUB stopped with a read error).** The two FAIL rows are the wrong-key rows (finding 1).
The cluster after the rows: every OSD up and in, the same health checks, no extra user, image, pool, upmap or configuration entry (section 6).

## 4. Findings

Ordered by what to act on first. "Evidence" names rows of `rows/`.

**1. A wrong key is still EPROTO, not EACCES (`WR_E_M2_BAD_METHOD`), and it takes the 20 s open timeout to appear.** `U1-neg-key`, `B1-neg-key`: one driver line,
`rbd: open failed: server refused the offered authentication method or mode (WR_E_M2_BAD_METHOD)`, then `Could not open SAN device: Error 0x4376...`. The design (section 12) wants EACCES for a key the cluster
does not accept; the cluster's AUTH_BAD_METHOD reply carries a result (a negative errno), which the driver does not use. It is the finding F3 of the UEFI rows and F4 of the BIOS rows, reproduced on the current build.
The unknown pool and image rows (ENOENT, 0.3 s, one line) and the unreachable monitor (ENETUNREACH after 20 s, one line) are right.

**2. A killed OSD is almost invisible to the guest here; a hung cluster is not, and the driver survives that.** `osd-kill` on this cluster costs the guest 1.5 to 1.9 s on its slowest read (`B1-reader-osd-*`) and a
handful of resent operations (`U1-bytes-osd-long`: 7). The reason is the cluster's, as far as the lab's configuration shows: a killed process refuses connections, its peers report it at once (`osd_fast_fail_on_connection_refused` is true here), the monitor
publishes a map within about a second and the client resends to the new primary (the monitor's traffic to the guest during the fault, 1.6 KB, is consistent with that map; the OSD logs were not read). A host that dies, or a network that drops, gives no refusal; the
`stall` and `link-down` rows are that case, and there the guest waited the whole time (slowest INT 13h read 20.8 s, 42.4 s, 40.5 s for 20, 40 and 40 s) and **nothing was lost**: the SAN layer cancelled the command at its
15 s timeout and issued it again (1 to 3 cancels), the driver closed the path once after 30 s without an answer (`rbd: the cluster has not answered for 30 seconds, closing the path: ...`: once in `U1-bytes-stall40`, `U1-bytes-link`, `B1-reader-link`; none in the 20 s rows, and none in `B1-reader-stall40`, where the SAN layer's two cancels came first), the SAN layer reopened it against the cached session (`reopens 0`: the image itself was never reopened; the 30 s line is the only trace of the close), and every command completed with the right bytes.

**3. Cancel is synchronous and no byte landed in a released buffer (BIOS family, canary).** `B1-reader-stall20`, `-stall40`, `-link`, `-mon-osd` and `-outage` have 1, 2, 3, 1 and 28 SAN cancels and `stale=0`:
no write into a buffer the loader had moved on from, also not in the buffers that the SAN layer had given back with an error (`B1-reader-outage`: two failed reads, each buffer filled with the canary at once, all
three buffers checked again a second after the end). On UEFI the firmware's file system driver owns the buffers, so the proof there is the md5 of every file (all equal in every row with cancels).

**4. The monitor going away does not touch the data path; the driver hunts for it with a growing delay and finds it again.** `U1-bytes-mon`, `B1-reader-mon`: with the monitor down for 20 s the reads run at their normal speed; the guest's
connection attempts to the monitor go out at +0.9, +2.3, +3.8 s after the kill (`U1-bytes-mon`); with the monitor down longer the gaps keep growing (`B1-reader-mon-osd`: attempts at +14.1, +14.9, +16.9, +20.3, +26.9, +38.6 s, gaps 0.8 to 11.7 s), and after the monitor is back the guest reconnects (a new monitor connection and about 1.3 KB of traffic, against
4.9 to 5.0 KB at the first open). **The one combination that stops the data path is a monitor and an OSD gone together** (`mon-osd`): nobody can mark the OSD down or publish a map, so reads to its placement groups wait for the monitor
(slowest read 27.7 s, byte check 38 s instead of 15 s, one SAN cancel, no path closed); they resume when the monitor is back, with the right bytes. The Linux guest's own kernel client waits for the monitor too (`U1-boot-mon`: the image is
mapped at +41 s instead of +21 s): that is Linux, not the driver, and `boot_phase_seconds` in `facts.txt` is measured at the first initramfs line to keep the two apart.

**5. The idle-gap case works, with the daemons' idle timeout lowered; with the default it never arises in 60 s.** A 60 s stop of the guest leaves every connection standing at Ceph's default (`ms_connection_idle_timeout` 900 s): no new connection,
nothing resent (`U1-bytes-pause`, `B1-reader-pause`, both boot rows). With the timeout at 20 s the daemons close the connections the stopped guest leaves idle, and the first commands after the gap reconnect and authenticate inside the command: 1 monitor
and 3 OSD connections within 6 s of the resume, 7 to 8 operations resent, slowest read 2.3 s, correct bytes (`B1-reader-idle`, `U1-bytes-idle`, `*-boot-idle`). **Not understood:** after the gap the rest of the UEFI byte check was slow (the 17 MB file took 83 s
including the 60 s gap, then the 80 MB file 17 s instead of 5 s, with two more OSD connections started 18 and 20 s after the resume); the lowered timeout also closes connections that idle during normal operation, so this is an upper bound of the cost,
and the cluster of the lab is small and busy, but a reader of these rows should not take "reconnect inside the command" for free. The guest could not tell that time had passed: its CMOS clock jumped by 60 s (`reader_rtc_largest_step_seconds`), its BIOS tick count did not.

**6. Maps were not fetched again after the link came back (indirect).** `rbd-info` has no counter of map fetches, so the check is the lab VM's view: after `U1-bytes-link` and `B1-reader-link` the guest started one monitor connection and two or three OSD connections and the monitor sent
1,337 bytes in 13 to 15 packets, against 4,937 / 5,006 bytes at the first open; `U1-bytes-stall40` and `B1-reader-stall40` (no monitor traffic at all after the stall: 44 bytes) show the same for a cluster that hung. That is consistent with a renewed subscription and
no full map; it does not prove it.

**7. Giving up works, and the loaders see an error, not garbage.** After the cluster stopped answering the SAN layer gave up on a command after 155 to 168 s (10 or 11 attempts of 15 s, a path close every 30 s: 4 to 6 stall-close lines per failed command) and returned an error
to the caller: INT 13h `ah=04` to the reader (twice, with the same sector), the file system driver's read error to `imgfetch`, and GRUB's `error: failure reading sector 0xfce00 from hd0` in `U1-boot-outage`. Nothing was booted from damaged data, the guest did not hang, and when the cluster came back
the next attempt succeeded (`B1-reader-outage`: the third try, which had started 94 s before, completed 2 s after the cluster was resumed; final hash right). The two GRUBs differ: UEFI GRUB gave up and stopped (the error came 334 s after the stop, 1.2 s after the cluster was back, not after the 165 s of one SAN give-up: why was not examined, one possibility is a retry inside the loader), BIOS GRUB (which retries through INT 13h) never saw an error in 330 s and booted 40 s after the cluster was back (`B1-boot-outage`). On UEFI the second read after an error failed at once without waiting (`U1-bytes-outage`: `z-fill-80m` right after `f-33m`);
whether that is the firmware's file system driver remembering the error or the SAN layer not retrying was not examined.

**8. The two failures of the earlier rows (F1/F5/F11: a path that cannot be reopened prints `parse URI failed: out of memory` for ever) did not occur.** No row of this module has an allocation failure or a reopen loop on its console (the check is in every verdict), including
`B1-reader-outage` with 13 path closes and `U1-bytes-link`, `*-stall40` with one. This says nothing about the cause that module did not find; it says that these faults, on this build, do not reproduce it.

**9. Observability.** (a) After a Linux boot `rbd-info` cannot be run (no iPXE shell), so the boot rows have no counters; the reader's INT 18h return and the byte check's script are what make the counters available in the other rows. (b) The 30 s line is printed
after iPXE's progress text on the same console line (`file://WRBYTES/f-33m...rbd: the cluster has not answered ...`), which makes a naive `^rbd:` search miss it; `analyze.py` looks for it anywhere in the line. (c) `rbd-info` after a stall close says `reopens 0`: that counter is the image reopen, not the SAN layer's reopen of the path. (d) The stack monitor of the BIOS build shows the recovery paths a little deeper than a normal boot: iPXE's own stack peaks at 2,920 of 4,096 bytes in the rows with a monitor fault or an OSD kill (`B1-reader-mon*`, `B1-boot-osd-*`; 2,772 in the control) and the core's own stack at 1,888 of 16,384 (`B1-reader-osd-*`, `B1-reader-mon-osd`; 1,696 in the control): 1,176 bytes left on iPXE's stack in the worst case.

## 5. Deviations, shared files, tests

* **Shared file:** `harness/CMakeLists.txt` gets one block, `module qemu-robust` (ctest `robust.selftest`). Nothing else outside `harness/lab/p2/results/robust/` and `harness/lab/p2/qemu/robust.sh`. `harness/lab/p2/qemu/README.md` does not list `robust.sh`
  (not this module's file): add one row to its table.
* **The lab:** these rows ran on the dedicated Phase 2 lab (`harness/lab/p2/cluster`, design 14.1 option C), not on the main lab; the rule about the Phase 1 exit run (`~/w/lt2/DONE`) therefore did not apply and the main lab was not touched.
* **Reader disk replaced once:** `reader.S` got the "poison the buffer of a failed read" path after the first batch of reader rows had started; the image `wrtest-p2-rb-reader` was imported again (`import.sh --force`, data sectors unchanged, hash unchanged; the code sectors differ: `oracle-notes.txt`). The reader rows
  that count (`B1-reader-*`) were all run with the final reader. A first batch of byte-check rows with a late trigger and no capture is kept in `attempts/batch1-late-trigger-no-capture/`: all PASS, but the faults landed late in the read (the last file takes 5 s and the trigger was its start plus 1 to 1.5 s, plus the time the ssh command took),
  so the rows were repeated with the trigger at the start of the 17 MB file (delay 0 to 0.5 s). Those first rows had no capture either (a `\&` in the `tcpdump` filter made it fail silently).
* **Rows that did not count (`attempts/`):** `U1-bytes-mon-short` once (my import of the reader image changed the list of images between its two snapshots) and once more, and `U1-bytes-outage` once (cephadm's `CEPHADM_FAILED_DAEMON` check, raised by the previous row's killed monitor, was gone by the end of the row: the lab
  diff was not empty). The cause was the driver's, not the cluster's: it did not wait for the check to clear; `robust.sh` now does (`r_wait_health`), and all the rows after that carry its line in `fault.txt`. The first `U1-bytes-mon` is also there: its fault was cut short by the end of the run and the verdict then did not know that case.
* **Budget:** `P2Q_BUDGET_ROOT` was the box's `winrbd` directory with 32 cores / 45056 MiB (24 / 32768 raised by the share of the 12 GiB `ci26` guest of Phase 1's CI, which is not part of this workflow, as the other modules did); this workflow's own guests were the lab (4 vCPU / 8 GiB), the builder (8 / 12 GiB) and one test guest (2 / 2 GiB).
* **Tests:** `robust.selftest` (155 checks after the review of section 7, `tools/selftest.sh`; 130 when the rows were made): ctest on the 26.04 builder guest with gcc 15.2 Debug and Release, clang 21 Debug, Release and Debug with `-DWR_SANITIZE=address,undefined` (each `Passed`, 137 to 149 s, for the first 130 checks); there is no C code in this module, so the sanitizer flavour only proves the test does not depend on the build type. `shellcheck` is clean on every script.
  The iPXE targets were built with iPXE's own `-Werror` and `grep -ci warning` of both logs is 0 (`builds/BUILD-INFO.txt`).
* **The BIOS binary is not the one of the design table.** Section 14.3 lists `undionly.kpxe` for B1; the rows ran `ipxe.pxe` (iPXE's own NIC drivers, a constant stub script built in, `-DCONSOLE_SERIAL`) because the lab NIC is the guest's second NIC (`builds/BUILD-INFO.txt`). Both guests ran builds with `-DRBD_STACK_MONITOR` (the stack watermark notes), not the shipping configuration; the driver's behaviour in these rows is the same code, the watermark lines are extra.
* **The rows ran with five revisions of `robust.sh`.** The SHA-256 of the fault driver is in each row's `binaries.sha256`: `cafc6271...` (19 rows), `12e44c29...` (15), `2a6de7c9...` (17, the file as it was when the module was handed over), `959542fc...` (2) and `e5592660...` (1). They differ in what the driver records (the health wait, the key presses, the capture), not in what it injects; the rows were not repeated for the fixes of section 7, which change the driver again. The review re-ran seven byte-check rows with the final driver (`review/`), and their numbers agree with the rows of section 3 (same counters, same verdict); all 54 rows stand on the earlier revisions.

## 6. Restoring the lab, and what is not covered

* `lab-base.txt` is the state of the lab (`labstate.sh snapshot`: cephx entities and caps, pools, images, OSDs, flags, upmaps, configuration database, health check names, quorum) before this module made anything; `lab-final.txt` is the state after the four throwaway users and images
  were deleted, the key files removed and every row was done; `lab-restore-diff.txt` is their difference (empty: `labstate: no difference`). Every row has its own before and after (`lab-diff.txt`). `oracle-end.txt` shows all four images equal to what was imported, so the guests never changed them; `oracle-start.txt` was taken before the reader image was imported again (see `oracle-notes.txt`), so its reader line is the hash of the first reader image.
* The key: one throwaway user per image (legacy `aes` key, caps limited to the pool), the key only in a mode-600 file, read by `gen-script.sh` into the run script and nowhere else. Every row's files were scanned for the run's own key (`keyscan.py`: base64, hex, hex dumps) and for the shape of a key
  (`AQ...` / `Ag...`): none. The negative rows used a random key that opens nothing.
* **Not covered:** a cluster with more than one monitor (the monitor hunt was only tested against a single monitor that comes back); an idle gap of the real 900 s; a host-level OSD failure as a real network partition (`stall` is its stand-in); the Windows boot manager (WinPE rows are other modules'); the loaders' behaviour when the SAN
  layer gives up, other than GRUB on both firmwares and the reader; the heap watermark during recovery (`rbd-info` does not print it); secure mode (crc only, as in the other rows).

## 7. Review of 2026-11-24 (adversarial, after the rows)

A second reader went through `qemu/robust.sh`, `tools/*`, the evidence and the design (sections 11, 12 and 14.3), then fixed what was wrong and ran the tests again. Severity is about what the problem could hide or break, not how much code it took.

| # | Severity | Problem found | Fix |
|---|---|---|---|
| 1 | high (test) | 28 checks of the delivered `tools/selftest.sh` (and ten of the ones written during this review, in the same style) were written `check "..." A && B`: `check` returns 0 whatever it saw, so only `A` was a check; `B` (and for several lines the main assertion) ran outside it and could not fail the run. Made real, two of them were wrong: the "events in the right order" check compared against strings that could never match, and the key-leak check looked at the console of another run | `check` takes a list (`A '&&' B ...`), all converted, the two checks written correctly, three negative controls for the helper itself; a mutation run with the fixes 3 to 7 taken out of `robust.sh` together fails exactly the five tests written for them (and `shellcheck` on the mutant); the first mutation run, made while the broken `check` was still in place, failed four of the five mutations and passed the fifth for the wrong reason, which is how the helper's defect was found |
| 2 | medium (test) | the header of `robust.sh` promises that the lab is put back after a signal; nothing tested it | a test sends SIGTERM in the middle of a monitor kill and checks exit 143, the monitor started again, no guest and no run directory left |
| 3 | medium | `--idle-timeout` undoes itself with `ceph config rm`: a lab that already had that setting would lose it. The flag that says "the setting is ours" was also cleared before the removal had worked | the driver refuses a lab that has the setting (or whose configuration it cannot read); the flag stays up until the removal worked. The first version of this check broke on the live lab (ceph starts its JSON with an empty line); the stub of the test now does the same |
| 4 | medium | the wait for the health checks to settle could not tell "no checks" from "no answer", so a cluster with fewer checks than at the start (or none) waited 120 s and failed the row | it asks `r_health_names` for its own status; only extra checks (or no answer) keep it waiting |
| 5 | medium | `--capture` with no `tcpdump` / `sudo` / `timeout` in the lab VM produced an empty `.syn`, which reads as "the guest made no connection"; the `tcpdump` could outlive the run | checked before the guest starts (the run stops); `tcpdump` runs under `timeout` (run time + 2 min) |
| 6 | low | the time-stamping loop cut the whole buffer once per line (quadratic): a burst of kernel messages could hold up the loop that decides when the fault starts and when the run ends. A last line with no newline (a prompt) was never written | one pass with `read`; the partial last line is written at the end of the run |
| 7 | low | the copy of the waiting loop lacked the stock early exit for a lab NIC with no link: such a guest was held to the timeout (up to 900 s) | the same branch as the stock loop |
| 8 | low | `--on` with an invalid regular expression never fired: no fault, the guest ran to the timeout | refused at parse time |
| 9 | low | a run whose guest never started (lab not reachable, QEMU refused) said "NO FAULT WAS INJECTED" and exited 3, pointing at the lab | only when the guest did run |
| 10 | low (evidence) | `analyze.py` measured "+x s after the start of the guest" from the first line of `fault.txt`, which is written before the guest exists (the health query, the idle timeout being set): 0.4 to 2 s too much in 24 rows | from the `guest started` line; all rows judged again (`matrix.sh rejudge`): the 54 verdicts are the same, `facts.txt`, `verdict.txt` lines and `MATRIX.md` carry the new times |
| 11 | low | `matrix.sh rejudge` overwrote a `FAIL secret scan` verdict (the files that held the key are deleted, so the analysis could not see it) and wrote a verdict for a row with no directory | the secret-scan failure is kept; a missing directory is refused |
| 12 | low | `rr.sh` left its scratch directory (the iPXE append script, the fw_cfg parameters) when it stopped early | removed on exit |
| 13 | low (doc) | the counts disagreed (135 and 130 checks); the B1 binary and the stack-monitor build were not in the deviations; nothing said the rows ran with five revisions of the driver | section 5 |

**Live check of the fixes** (`review/`): the lab VM of `harness/lab/p2/cluster` (it was running), a byte-check image rebuilt (the same 17 digests as `expect/bytes.md5`; the image's GPT and FAT ids differ, so its SHA-256 does too) and `ipxe.efi` of the 2026-11-23 build run (`1,423,360` bytes, the size of the builds of the rows), seven rows with `--capture`: no fault, monitor killed 20 s (cut short by the end of the run), osd.1 killed 8 s, every OSD stopped 20 s, monitor then osd.1, the guest stopped 60 s with `--idle-timeout 20`, the lab NIC cut 40 s. All PASS, the lab's state after every row equals the state before, and the counters agree with the rows of section 3 (for example the monitor-and-OSD row: 1 cancel, 5 session resets; the NIC row: 3 cancels, 1 stall close; the idle row: the daemons' idle timeout set and removed again, 3 session resets, a monitor and three OSD connections after the resume). The first attempt of the idle row was refused by the new configuration check (finding 3, its JSON bug) and is not kept. The throwaway user, image and key file of these rows were deleted again.
**Tests after the review:** `robust.selftest` 155 passed, 0 failed, 0 skipped on the box (Ubuntu 22.04, bash 5.1, python 3.10, GNU as/ld 2.38, shellcheck 0.8.0) and on the 26.04 builder guest (bash 5.3, python 3.14, shellcheck 0.11.0): `review/selftest-box.txt`, `review/selftest-ubuntu26.txt`.

**Checked and found right:** the errno table of `analyze.py` against the pinned tree's `errno.h` (all 15, and the `<< 24` layout of the code); the md5 list and the progress points of the reader (`mkreader.py` reproduces `expect/`); the reader's buffer arithmetic (127 sectors = 65,024 bytes in a 64 KiB slot, 16-bit counts of at most 16,256 dwords, the DAP, the slot segments, the retry-in-the-next-buffer logic); the key never appears in a `cmdline.txt`, a lab snapshot (caps only) or the capture (headers and lengths, `-q`); no internal address, host or user name in the module; every row's iPXE hash is one of the two builds of `BUILD-INFO.txt`; the numbers of section 3 against the `facts.txt` of the rows (22 spot checks, all equal).

**Not fixed, on purpose:** (a) `reader.S` waits one second with a compare of two BIOS tick counts; the count is reset at midnight, so a run that crosses midnight inside that second would wait until the next day (the run's timeout then ends it as a failed row; the same wrap makes the `maxticks` figure meaningless once). Changing the reader would change the binary every `B1-reader-*` row ran with, for a risk of about one run in 86,000. (b) The Linux boot rows prove that a kernel and an initramfs that were read through the driver start; they cannot show one wrong byte in a file that is not executed, and the screenshots (`screen.ppm`) cannot be scanned for the key by `keyscan.py`. (c) `robust.sh --capture` stops the capture with `pkill -x tcpdump` in the lab VM, which also ends a capture of someone else there: the lab is dedicated, and the `timeout` of finding 5 bounds the damage of a forgotten one. (d) The two `FAIL` rows (wrong key: EPROTO, not EACCES) are findings against the driver (section 4, finding 1), unchanged.

