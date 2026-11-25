# Exit measurements of the iPXE `rbd://` driver

Companion to [ipxe-driver.md](ipxe-driver.md) (section 14.4 and the risks of section 16). It belongs to the module `measure`; the tools, the evidence of every run and the commands are
in `harness/lab/p2/results/measure/` (`README.md` there). English only, like the design.

**Rule of this document.** Every figure below is computed from an evidence directory by `summarize.py` (or read from its `facts.json`); nothing is typed from memory. A figure is
**reported, not asserted**, except the budgets of section 5 of the design (arena, bulk, stack, heap), which have a pass or fail line in section 5. Every figure that comes from runs
says how many runs it rests on (`n`), the smallest and the largest value, and under what load of the machine it was taken. A run that did not pass its own checks is listed and is
not summed.

## 1. What was measured, on what

| | |
|---|---|
| Cluster | the dedicated lab of `harness/lab/p2/cluster`: Ceph v20.2.5, one monitor, three OSDs on one host (BlueStore on sparse files), pool `winrbd` with size 3, in a VM of 4 vCPUs / 8 GiB on the build machine. The main lab and its Phase 1 run were not used. Mode crc (msgr2) on both sides. |
| Guests | QEMU 6.2.0 / KVM, machine q35, `-cpu host`, 2 vCPUs, 1 GiB (2 GiB for the boot rows), `nice -n 19`; the cluster is reached over QEMU's own multicast layer 2 with a `virtio-net` NIC (the second NIC; the first is QEMU's user-mode NIC that carries the PXE bootfile) |
| Host | the shared build machine: AMD EPYC 7601, 100 cores, **busy with other people's jobs: load average 25 to 70 during the runs**. Every run records the load before, during and after, and how long the threads of its guest and of the lab VM waited for a CPU. The guest's threads waited 0.1 to 0.2 % of the time and the lab VM's about 0.5 %: the noise below is not vCPU starvation. |
| The caller | `bench.S`, a BIOS boot sector that is the "loader": it issues INT 13h commands of a chosen size through the SAN layer and times each with the TSC (calibrated against the BIOS tick at the start and the end of every run: the two rates agree within 0.05 %, 2.196 GHz). After a step it sums the first and the last 64 KiB of the last command's buffer and compares them with the same bytes of the image it was built from: **in every read step of every counted run those bytes were the right ones** (`sums_ok`). That is a spot check of one command per step, not of all 128 MiB; what covers the rest is that the console reports, for every step, exactly the sectors and the number of commands the plan has and no error line (`analyze.py`, from the review on: checked against the plan; the same check was run on every counted run without rewriting its evidence, and none changed its verdict). |
| iPXE | pinned `9261ebe38`, gcc 15.2.0 in the Ubuntu 26.04 builder guest, iPXE's own `-Werror`, **zero warning lines in every build log**. The 32-bit BIOS image (`bin-i386-pcbios/ipxe.pxe`, 4,096-byte stack, the core on its own 16 KiB stack) with a serial console and the constant PXE stub; `ipxe.efi` for UEFI. Source digest of `ipxe/` and `core/`: `5b8c14632092c5df` (`BUILD-INFO.txt`). |
| Binaries | `rel` (throughput, idle, writes): `ipxe-stub.pxe` sha256 `2629bc93...ed4142`, `ipxe.efi` `3eb7de2a...fb85`. `inst` (stack and heap marks: `-DRBD_STACK_MONITOR`, `DEBUG=malloc`): `ipxe-stub.pxe` `ddd8c539...4d2a`, `ipxe.efi` `333cd69f...c298`. `media` (the stick and the CD): `ipxe.lkrn` `1e7b8b9f...da77`, `ipxe.efi` `d94b813d...2c3b`. Full hashes: every run's `binaries.sha256`. |
| Cluster state | `HEALTH_OK` apart from the muted checks of the lab (`AUTH_INSECURE_*`, `BLUESTORE_SLOW_OP_ALERT`) and one old `RECENT_CRASH`; 3 OSDs up and in, 33 PGs `active+clean`; checked before every run (`lab-before.txt`), compared after (`lab-diff.txt`). Two runs overlapped events of the lab VM (section 10, F5) and are not counted. |
| Repeats | three runs per figure at least (a "run" is a fresh guest boot); each read run has two passes per command size, so a read figure has n = 6. |

Commands (all in `harness/lab/p2/results/measure/tools/`): `campaign.sh read 3`, `krbd 3`, `inst 3`, `redo`, `heap 3`, `write 3`, `netem 1 3 10 3` (stopped by hand after the first +10 ms run: it had shown the failure),
`ra 2`, `idle 3`, `r10 150`, `r10mem`, `r10leak 20`, `efi 3`, `efiheap 3`, `login 3`, `winpe 3`; each calls `mrun.sh`, `mboot.sh`, `mguest.sh`, `krbd.sh`, `mheapbase.sh` or
`mheapefi.sh`, which write one evidence directory per run (`runs/NAME/`, with `cmdline.txt`).

**The comparison with the kernel client** is made twice, on the same image and the same cluster:

* `krbd.sh`: the kernel client **inside the lab VM** (the cluster's own host), `rbd map` with the throwaway user's own key, `dd`-style reads. Loopback path: the upper bound of what a kernel
  client gets from this cluster on this machine, not the path the guests take.
* `mguest.sh`: the kernel client **in a Linux guest on the same layer 2** with the same virtual NIC, the same 2 vCPUs, the same image and key (the lab VM's own 6.8 kernel, a static
  busybox, `rdbench.c`; msgr2 crc). This is the same path as the iPXE guest, so the numbers can be set side by side.

Reading is done after one untimed pass over the same 128 MiB, so the OSDs have the range in cache for every client (the image was freshly written, and the lab VM has 8 GiB).

## 2. Image sizes with and without the driver

Same pinned iPXE revision, same compiler (gcc 15.2), same make, default configuration, no embedded script, no serial console (`build-variants.sh sizes`). "Without" is the pristine tree
(`git archive` of the submodule, no patch, no glue); "with" is `ipxe/tools/build.sh` (patches 0001 to 0004, the glue, the core). The `bin/` targets of this iPXE are **x86_64** BIOS images
(finding F1 of `results/bios/README.md`); `bin-i386-pcbios/` are the 32-bit images with the 4 KiB stack that the stack budget is about.

| image | without the driver (bytes) | with the driver (bytes) | added (bytes) | added |
|---|---|---|---|---|
| `x86_64-efi/ipxe.efi` | 1,179,648 | 1,423,360 | 243,712 | 20.7 % |
| `x86_64-pcbios/undionly.kpxe` | 81,058 | 201,955 | 120,897 | 149.1 % |
| `x86_64-pcbios/ipxe.pxe` | 429,766 | 546,230 | 116,464 | 27.1 % |
| `x86_64-pcbios/ipxe.usb` | 475,136 | 573,440 | 98,304 | 20.7 % |
| `x86_64-pcbios/ipxe.iso` | 966,656 | 1,083,392 | 116,736 | 12.1 % |
| `i386-pcbios/undionly.kpxe` | 72,470 | 191,195 | 118,725 | 163.8 % |
| `i386-pcbios/ipxe.pxe` | 398,100 | 513,052 | 114,952 | 28.9 % |
| `i386-pcbios/ipxe.usb` | 442,368 | 540,672 | 98,304 | 22.2 % |
| `i386-pcbios/ipxe.iso` | 933,888 | 1,048,576 | 114,688 | 12.3 % |

The driver adds **115 to 120 KB to a BIOS image and 244 KB to `ipxe.efi`** (the design's skeleton table, which linked only the core, had +95 KB for `ipxe.efi` and +52 KB for `undionly.kpxe`; the glue,
the readahead cache, the handoff codec and the URL parser are the rest). `undionly.kpxe` goes from 72 KB to 191 KB (32-bit) or from 81 KB to 202 KB (x86_64): still far below what PXE loads over TFTP.
`ipxe.usb` and `ipxe.iso` grow in 4 KiB / 2 KiB steps, so their delta is a rounded value.

## 3. Sequential read throughput through the SAN layer

The caller is `bench.S`: INT 13h AH=42h reads in commands of 127 sectors (63.5 KiB: the classic form, what a BIOS boot loader issues), 2,048 sectors (1 MiB) and 8,192 sectors (4 MiB, the
SAN layer's `max_count`: the EDD 3.0/4.0 form with a 64-bit buffer address), 128 MiB per pass over the same range, two passes per size per run, after an untimed warm pass. "Default" is the
driver's default readahead (a 2,048 KiB window over a cache of eight 256 KiB lines); `readahead=N` is the URI option. MiB/s = 1,048,576 bytes per second of wall time of the pass.

### 3.1 The driver against the kernel client on the same path

| group | runs (passed) | 127 sectors (63.5 KiB) MiB/s | 2,048 sectors (1 MiB) MiB/s | 8,192 sectors (4 MiB) MiB/s |
|---|---|---|---|---|
| inst | 3 (3) | 10.8 (9.9 - 11.5), n=6 | 4.1 (3.9 - 5.5), n=6 | 8.4 (7.7 - 9.1), n=6 |
| rd-def | 4 (3) | 11.0 (5.3 - 14.7), n=6 | 3.6 (2.7 - 6.1), n=6 | 6.7 (3.9 - 11.7), n=6 |
| rd-def-3: NOT counted | | the cluster did not disturb the run (resent 1, session resets 11, cancels 1, stall closes 0, failed 0) | | |
| rd-ra0 | 3 (3) | 9.2 (8.4 - 9.7), n=6 | 25.9 (25.0 - 28.0), n=6 | 32.1 (24.7 - 33.6), n=6 |

| series | mode | 64 KiB MiB/s | 1 MiB MiB/s | 4 MiB MiB/s |
|---|---|---|---|---|
| kernel client in the lab VM (loopback) | direct | 12.5 (3.0 - 20.2), n=9 | 121.5 (49.5 - 141.8), n=9 | 176.7 (51.2 - 241.6), n=9 |
| kernel client in the lab VM (loopback) | ra128k | 26.0 (21.7 - 60.3), n=9 | 114.6 (86.5 - 194.6), n=9 | 138.5 (87.4 - 278.8), n=9 |
| kernel client in the lab VM (loopback) | ra2048k | 128.5 (60.1 - 231.5), n=9 | 137.7 (103.4 - 232.1), n=9 | 164.3 (121.1 - 253.5), n=9 |
| kernel client in a guest on the layer 2 (same path as the iPXE guest) | direct | 6.7 (2.9 - 9.2), n=9 | 21.9 (18.6 - 30.2), n=9 | 25.1 (19.2 - 31.5), n=9 |
| kernel client in a guest on the layer 2 (same path as the iPXE guest) | ra128k | 16.3 (7.1 - 17.7), n=9 | 18.6 (13.0 - 26.7), n=9 | 22.3 (2.6 - 36.7), n=9 |
| kernel client in a guest on the layer 2 (same path as the iPXE guest) | ra2048k | 16.1 (6.5 - 18.2), n=9 | 31.3 (11.5 - 38.4), n=9 | 37.5 (12.0 - 38.1), n=9 |

What the numbers say, and what they do not:

* **With `readahead=0` the driver is at least level with the kernel client on the same path.** Direct reads (no client cache at all) by the kernel client in the Linux guest: 6.7 / 21.9 / 25.1 MiB/s
  for 64 KiB / 1 MiB / 4 MiB commands; the driver with no readahead: 9.2 / 25.9 / 32.1. The path is the limit: the same image read by the kernel client inside the lab VM, with no NIC between, runs
  at 12 / 122 / 177 MiB/s. In this lab the ceiling for a guest is about 25 to 38 MiB/s whoever the client is (the virtual NIC of a user-space multicast socket, 2 vCPUs, an OSD pool on
  sparse files of a busy disk).
* **The driver's default readahead is not a gain here; it is a loss for any command of 1 MiB or more.** Median 11.0 MiB/s for 63.5 KiB commands (against 9.2 without: **1.2 times**, spread
  5.3 to 14.7), but **3.6 MiB/s for 1 MiB commands (against 25.9: 7 times slower)** and 6.7 MiB/s for 4 MiB commands (against 32.1: 4.8 times slower). The kernel client's own readahead helps small commands
  (16 MiB/s against 6.7 for 64 KiB blocks) and costs large ones at most the noise of the lab (1 MiB blocks: 18.6 MiB/s with 128 KiB of readahead, 31.3 with 2 MiB, against 21.9 direct).
* **The estimate of design section 10 ("one round trip per window") was too optimistic for the INT 13h case and wrong for large commands.** A boot loader's 127-sector commands gain at best
  1.2 times here; the gain a real boot showed (3.3 to 4.5 times shorter read phase, `results/bios/README.md` section 4.2) is for GRUB's reads of at most 64 sectors (1 to 64, almost all sequential), which are smaller than 127, on a box under heavy load with a NIC (UNDI) that made every round trip slower.

### 3.2 The readahead window, swept

Same plan, the `readahead=` option set to 256, 512, 1,024 and 4,096 KiB (two runs each; the default and 0 are the rows above).

| group | runs (passed) | 127 sectors (63.5 KiB) MiB/s | 2,048 sectors (1 MiB) MiB/s | 8,192 sectors (4 MiB) MiB/s |
|---|---|---|---|---|
| rd-def | 4 (3) | 11.0 (5.3 - 14.7), n=6 | 3.6 (2.7 - 6.1), n=6 | 6.7 (3.9 - 11.7), n=6 |
| rd-def-3: NOT counted | | the cluster did not disturb the run (resent 1, session resets 11, cancels 1, stall closes 0, failed 0) | | |
| rd-ra0 | 3 (3) | 9.2 (8.4 - 9.7), n=6 | 25.9 (25.0 - 28.0), n=6 | 32.1 (24.7 - 33.6), n=6 |
| rd-ra1024 | 2 (2) | 14.7 (12.3 - 16.3), n=4 | 9.8 (8.1 - 13.0), n=4 | 11.9 (10.9 - 13.1), n=4 |
| rd-ra256 | 2 (2) | 15.4 (14.8 - 16.3), n=4 | 25.7 (23.5 - 26.9), n=4 | 29.6 (25.2 - 30.6), n=4 |
| rd-ra4096 | 2 (2) | 14.8 (14.0 - 15.3), n=4 | 16.3 (14.1 - 17.8), n=4 | 11.3 (10.9 - 11.7), n=4 |
| rd-ra512 | 2 (2) | 20.7 (16.6 - 21.9), n=4 | 18.5 (12.9 - 20.3), n=4 | 27.3 (21.0 - 31.0), n=4 |

The window is not monotonic, and the default (2,048 KiB, the size of the whole cache) is among the worst (two runs per size, so this is a direction and not a ranking): **a 256 KiB window (one line) gives 15.4 / 25.7 / 29.6 MiB/s**: better than no readahead for
63.5 KiB commands (1.7 times) and level with it for 1 MiB and 4 MiB commands; 512 KiB is about as good for small and large commands (20.7 / 18.5 / 27.3). With a window of 1 MiB to 4 MiB the 1 MiB
and 4 MiB commands slow down to 10 to 16 MiB/s. `rbd-info` after a default run shows why it is worth looking at (4,488 hits, **2,491 waits**, 110 misses, 2,972 prefetches for 7,089 reads; with a
256 KiB window: 3,110 hits, 1,022 waits, 1,488 misses): most reads of the default run park on a line that is still in flight, and a 1 MiB command needs four lines. The mechanism was **not**
investigated (this module only measures); it is finding F1 (section 10).

### 3.3 One command, far from the last (latency)

The latency series reads 127 sectors at addresses 24 MiB apart, so that no window opens: what one command costs.

| group | runs | reads | median ms | p90 ms | min - max ms |
|---|---|---|---|---|---|
| idle-def | 3 | 48 | 7.7 | 17.2 | 3.3 - 214.4 |
| idle-t10 | 3 | 48 | 5.0 | 19.1 | 2.9 - 247.3 |
| inst | 3 | 48 | 10.6 | 14.9 | 5.0 - 223.2 |
| rd-def | 3 | 48 | 10.6 | 18.9 | 3.9 - 220.7 |
| rd-ra0 | 3 | 48 | 4.8 | 6.7 | 3.4 - 9.7 |
| rd-ra1024 | 2 | 32 | 6.0 | 11.0 | 3.8 - 214.0 |
| rd-ra256 | 2 | 32 | 5.0 | 6.7 | 3.1 - 18.7 |
| rd-ra4096 | 2 | 32 | 4.8 | 6.9 | 3.3 - 16.7 |
| rd-ra512 | 2 | 32 | 5.8 | 8.2 | 3.0 - 32.0 |

Without readahead one command costs a median of 4.8 ms (p90 6.7). With the default window it costs 10.6 ms (p90 18.9), and one read in each of `rd-def-2` and `inst-2` took 220 ms: a command that does not continue a stream should not
pay for a window, and it did. With a 256 KiB or 4,096 KiB window the median is 5.0 and 4.8 ms, level with no readahead: the cost belongs to the default configuration (window = cache = 2 MiB), not to having a cache.

## 4. Time to login, per row

The Linux guest of `harness/lab/p2/images` (Ubuntu 24.04, kernel 6.8, GRUB; the firmware reads GRUB, the kernel and the initramfs, about 27 MiB, through the SAN device; the guest's own
kernel client then takes over the same image, and the root file system is on `/dev/rbd0pN`) is booted by the stock run scripts of `harness/lab/p2/qemu` and timed by `stamp.py`, which records
the second at which each stage of the guest's console is first seen (resolution 0.5 s; zero is the start of the run script, within a second or two of the start of the guest). Every
counted run printed the table check `RBFT-RESULT PASS pass=40 fail=0 skip=0` (the rBFT table matches the design), `WRBOOT-ROOT-OK` with the root on the image, and a login prompt. Rows: U1 OVMF + `ipxe.efi`
over PXE, U2 the same on a USB stick, U3 on a CD, B1 SeaBIOS + the 32-bit `ipxe.pxe` over PXE, B2 and B3 the 32-bit `ipxe.lkrn` on a stick and on a CD (isolinux; the run script is the initrd).
The WinPE rows W1 to W4 use the owner's WinPE images (UEFI/GPT and BIOS/MBR; never committed) rolled back to their snapshot before each run; the figure is the second at which `WINRBD-WINPE-OK`
appeared on COM1 (written by `startnet.cmd` after `wpeinit`).

| group | runs (passed) | GRUB s | kernel s | table checked s | root on the image s | login prompt / WinPE marker s |
|---|---|---|---|---|---|---|
| heap-efi | 3 (3) | 14.1 (13.1 - 14.1), n=3 | 20.7 (20.7 - 21.2), n=3 | 20.7 (20.7 - 21.2), n=3 | 54.5 (54.0 - 58.0), n=3 | 60.5 (60.0 - 64.0), n=3 |
| login-bios-iso | 3 (3) | 3.0 (2.5 - 3.5), n=3 | 10.1 (9.6 - 11.6), n=3 | 10.6 (10.1 - 12.1), n=3 | 43.9 (43.4 - 46.4), n=3 | 45.4 (44.9 - 47.9), n=3 |
| login-bios-pxe | 3 (3) | 12.6 (12.6 - 12.6), n=3 | 19.7 (19.1 - 20.1), n=3 | 20.2 (20.2 - 20.7), n=3 | 53.9 (53.9 - 54.4), n=3 | 55.0 (54.9 - 55.9), n=3 |
| login-bios-usb | 3 (3) | 3.0 (3.0 - 4.0), n=3 | 15.1 (15.1 - 17.1), n=3 | 16.2 (15.6 - 17.6), n=3 | 49.4 (48.9 - 50.9), n=3 | 51.0 (49.9 - 52.4), n=3 |
| login-uefi-iso | 3 (3) | 10.1 (10.1 - 11.6), n=3 | 16.6 (16.1 - 23.7), n=3 | 16.6 (16.1 - 23.7), n=3 | 50.0 (49.4 - 57.5), n=3 | 55.5 (55.5 - 63.6), n=3 |
| login-uefi-pxe | 3 (3) | 13.6 (13.1 - 15.1), n=3 | 20.2 (19.7 - 24.2), n=3 | 20.2 (20.2 - 24.2), n=3 | 54.0 (53.4 - 57.5), n=3 | 60.0 (59.5 - 63.5), n=3 |
| login-uefi-usb | 3 (3) | 10.1 (10.1 - 10.6), n=3 | 17.1 (16.6 - 17.6), n=3 | 17.1 (16.6 - 17.6), n=3 | 51.4 (49.9 - 59.0), n=3 | 57.0 (56.0 - 65.1), n=3 |
| winpe-W1 | 4 (3) | - | - | - | - | 84.0 (83.0 - 84.0), n=3 |
| winpe-W1-1: NOT counted | | the run script reached its expectation (met=0, stop=guest-exited) | | | | |
| winpe-W2 | 4 (3) | - | - | - | - | 87.0 (86.0 - 93.0), n=3 |
| winpe-W2-1: NOT counted | | the run script reached its expectation (met=0, stop=guest-exited) | | | | |
| winpe-W3 | 4 (3) | - | - | - | - | 61.0 (60.0 - 61.0), n=3 |
| winpe-W3-1: NOT counted | | the run script reached its expectation (met=0, stop=guest-exited) | | | | |
| winpe-W4 | 4 (4) | - | - | - | - | 68.0 (66.0 - 70.0), n=4 |

* **Every row of the matrix that has a Linux guest reaches its login prompt through the driver, three runs of three**, 45 to 65 s after the start of the run script; GRUB, the kernel and the initramfs (about 27 MiB)
  are read through the SAN device. The time **from GRUB's menu to the first line of the initramfs** (the part of the boot that the driver serves) is 6.6 s (U1), 7.0 s (U2), 6.5 s (U3), 7.1 s (B1),
  12.1 s (B2) and 7.1 s (B3) by the medians above (GRUB reads in commands of 1 to 64 sectors, finding F7 of `results/bios/README.md`); the remaining 30 to 40 s are the guest's own kernel client mapping the image and systemd,
  which are not the driver's. A PXE row starts later than a stick or a CD because the iPXE binary itself is downloaded first (GRUB at 12.6 to 13.6 s against 3.0 to 10.1 s).
* **The WinPE rows reach the WinPE marker in 61 to 87 s** (W1 UEFI PXE 84.0 s, W2 UEFI stick 87.0 s, W3 BIOS PXE 61.0 s, W4 BIOS stick 68.0 s, medians of three or four runs): the boot manager reads the 347 MB
  `boot.wim` through the driver (the default readahead, with the throughput of section 3), then WinPE starts from RAM. 61 to 87 s for 347 MB is an average of 4 to 6 MB/s over the whole boot, which is
  what the default window gives for large commands (an inference: the commands of the boot manager were not traced). UEFI is slower than BIOS here by 20 s; why was not examined. Three first-cycle runs (W1-1, W2-1,
  W3-1) failed because the imported images carried the features `exclusive-lock`, `object-map`, `fast-diff` and `deep-flatten`, which the driver refuses (`rbd: open failed: image uses features this client
  does not support`, correct and as designed; finding F10c of the BIOS README): the features were switched off with `rbd feature disable` and the rows were run again (`winpe-W1-4` to `winpe-W4-4` and the second and
  third cycle). They are listed above and not counted.
* `heap-efi` is row U1 with the instrumented `ipxe.efi` (section 5); it is a fourth set of U1 boots and agrees with `login-uefi-pxe` (60.5 s against 60.0 s).
* The rBFT table was found and checked in every Linux run (**40 of 40 fields**); the guest's table check is the "matches the design" clause of the exit criteria.


## 5. Stack and heap marks, and the budgets of design section 5

**Stack (BIOS, i386).** The instrumented build paints the free part of iPXE's own stack at every open and prints the high-water mark when it has grown by 128 bytes or at the end (`rbd: stack high-water`);
the core's own 16 KiB stack (design 5.2, layer 3) is painted the same way. Six runs (the 4 MiB read plan three times with all three command sizes, the probe plan three times): identical in all six.

| mark | measured | budget | line |
|---|---|---|---|
| iPXE's stack, high-water | **2,772 of 4,096 bytes, 1,324 left** (2,120 at open, 2,692 and then 2,772 while reading) | margin of at least 300 bytes (design 5.2, layer 3) | **PASS** |
| the core's own stack | **1,696 of 16,384 bytes** (it grew 512, 760, 1,304, 1,588, 1,696 during the first steps of every read run, and was 1,696 in all six) | 16,384 | **PASS** |
| the core's worst static chain (call-graph tool, i386 `-Os`) | 2,632 bytes; the 1,696 bytes seen is what the bench's reads (up to 4 MiB commands), copies and hook loops reach | | information |
| the stack without the own-stack switch | iPXE's 2,772 bytes plus the core's 1,696 would be 4,468 bytes of 4,096: **the trampoline is needed**, not a precaution | | R2 |

The 1,324 bytes left are 32 % of the stack. The design's guess for the margin without the trampoline (about 1,460 bytes minus the glue) was not enough: iPXE's frames plus the glue alone use 2,772 bytes.
**x86_64 BIOS** (the `bin/` targets of this iPXE, 8 KiB stack, the core on iPXE's stack) was **not measured**: the stack monitor compares the running frame with link-time addresses and prints
"the stack is not iPXE's own" there (finding F2 of `results/bios/README.md`, a fix is in that README's `builds/stack-phys.diff` and is not applied to the tree); the figure of that README with the local fix
is 5,608 of 8,192 bytes.

**Memory the session takes (`rbd-info` at open, every run, i386 BIOS).**

| piece | used | budget (design 5.1) | line |
|---|---|---|---|
| core arena | 260,128 bytes of 262,144 (2,016 free) | 262,144 (the request on i386; 263,392 measured on x86_64) | **PASS** |
| core bulk (two 256 KiB map slots, one 1 MiB monitor message slot, tables, 1 MiB zombie area) | 2,627,584 of 2,629,632 (2,048 free) | 2,629,632 | **PASS** |
| the one `umalloc()` block (arena + bulk + readahead cache 2,101,248 + core stack 16,384) | **5,013,508 bytes** requested (page aligned; `HEAP attempting to grow for 0x4c8004`), 4.78 MiB | about 4.8 MiB (4,871 KiB) | **PASS** |

The arena has **2 KiB to spare out of 256**: it is a fixed layout, and the lab's cluster (3 OSDs, one image) does not grow it, but there is no margin to see in the number (as `results/bios/README.md` F8 said).

**iPXE's `malloc()` heap (4 MiB).** `DEBUG=malloc` makes iPXE print `HEAP maximum usage NkB` at shutdown. BIOS: the run script exits iPXE after the bench returns, so the figure covers the
session and the reads. UEFI: iPXE shuts down when the boot loader calls `ExitBootServices`, so the figure covers the whole firmware phase of a boot, and the line comes out twice per character on the
serial line (the firmware console and the debug console; `analyze.py` reads it). Baseline: the same instrumented iPXE with nothing hooked.

| group | what | runs (passed) | heap maximum kB, per run | stack high-water (iPXE / core) bytes |
|---|---|---|---|---|
| heap-base | BIOS, nothing hooked (iPXE alone) | 3 (3) | 128, 103, 103 | - |
| heap-probe | BIOS, the probe image hooked, a few small reads | 3 (3) | 153, 132, 132 | 1696 of 16384; 2772 of 4096 |
| inst | BIOS, 128 MiB read in 127-sector, 1 MiB and 4 MiB commands, twice (the read plan) | 3 (3) | 403, 601, 301 | 1696 of 16384; 2772 of 4096 |
| r10-loop | BIOS, 153 hooks, 4 sessions created (the R10 loop) | 1 (1) | 131 | 1588 of 16384; 2120 of 4096 |
| heap-efix | UEFI, hook and one file read from the ESP | 3 (3) | 85, 85, 85 | - |
| heap-efi | UEFI, a whole boot to the hand-over to GRUB's kernel | 3 (3) | 248, 374, 315 | - |

The heap maximum is **at most 601 kB (14.7 % of 4,096 KiB)** in the worst of three runs that read 128 MiB in 1 MiB and 4 MiB commands on BIOS (the three runs gave 403, 601 and 301 kB: the
transient packet buffers of fast reads), 132 to 153 kB after a hook and a few small reads, and 248 to 374 kB for a UEFI boot (GRUB, kernel and initramfs read through the SAN device, three runs; 85 kB
for a hook and one file). iPXE alone, with the network up and its script loaded, uses 103 to 128 kB. The driver's own objects (the device, the session record, the connection table, the command objects: about
2 KiB per device) are not visible in these numbers: **the heap is not where the driver's memory goes** (the `umalloc` block is). The headroom for iPXE's other users is at least 3.4 MiB.
No `HEAP failed to allocate` line in any counted run.

## 6. The first command after a long idle (risk R8)

After `sanboot` hands over, nothing services the sockets between two INT 13h commands (design section 11). The bench waits (`HLT` until the BIOS tick counter has moved, the guest otherwise
running) and then reads 127 sectors at six far-apart addresses (24 MiB apart, so that each goes to another object and mostly another OSD); the first read of the six is the cost of the gap, the
others show what a second and third connection cost. The control is the same series with no gap, before and after. Gaps of 5, 40, 120 and 960 s (**960 s is longer than Ceph's default
`ms_connection_idle_timeout` of 900 s**: the daemons close the connection). Three guests of each configuration ran side by side, asleep for most of their time; the cluster is otherwise idle.

| group | runs (passed) | control (no gap) ms | gap s | first read after the gap ms | the reads after it ms |
|---|---|---|---|---|---|
| idle-def | 3 (3) | 7.7 (3.3 - 214.4), n=48 | 5 | 5.0 (4.2 - 5.3), n=3 | 4.0 (3.5 - 5.9), n=15 |
|  |  |  | 40 | 5.2 (5.1 - 5.5), n=3 | 4.9 (3.8 - 6.1), n=15 |
|  |  |  | 120 | 6.2 (5.1 - 6.7), n=3 | 4.5 (3.7 - 5.8), n=15 |
|  |  |  | 960 | 8.2 (8.0 - 1061.8), n=3 | 7.7 (5.7 - 2088.4), n=15 |
| idle-t10 | 3 (3) | 5.0 (2.9 - 247.3), n=48 | 5 | 11.6 (8.4 - 19.3), n=3 | 7.0 (5.9 - 19.9), n=15 |
|  |  |  | 40 | 2133.1 (2129.2 - 2133.1), n=3 | 11.3 (4.1 - 2090.7), n=15 |
|  |  |  | 120 | 2131.7 (2130.7 - 2131.7), n=3 | 6.7 (5.3 - 2084.6), n=15 |
|  |  |  | 960 | 2123.1 (2122.4 - 2123.2), n=3 | 4.1 (3.2 - 987.5), n=15 |

* **With the daemons' default idle timeout** (`idle-def`): gaps of 5, 40 and 120 s cost nothing measurable (first read 5.0, 5.2 and 6.2 ms, the control is 5 to 8 ms): the connections are still
  there and iPXE needs no running socket for the next command to go through. After **960 s** the first read cost 8.0 ms, 8.2 ms and **1,061.8 ms** in the three runs, and a later read of one run **2,088.4 ms**
  and of another 1,059.7 ms: when a daemon has closed the connection, the command that finds it dead **reconnects and authenticates inside the command**, and that costs about **1.06 s per
  connection** (the 2.09 s read is two of them in a row). No error reached the caller, nothing was resent (`ops_resent` 0 in these three runs), no path was closed, no SAN retry.
* **With the daemons closing idle connections after 10 s** (`idle-t10`, the case that a loader that spends a minute decompressing meets with a short idle timeout): **every** first read after a gap of
  40 s or more cost **2.13 s** (2,122 to 2,133 ms in all nine), and in each of the three gaps at least one of the later reads cost another 1.0 to 2.1 s (maxima 2,090.7, 2,084.6 and 987.5 ms). The first command after
  a long idle therefore costs **a few seconds once**, in steps of about 1.06 s per dead connection, and the boot goes on; it is not a failure. A loader whose own timeout is shorter than that
  (a boot manager that waits 5 s for a read) would see it.
* `rbd-info` after the runs: **default timeout (`idle-def`)**: `ops_resent` 0, `stall_closes` 0, `cancels` 0, and a session reset in two of the three runs. **10 s timeout (`idle-t10`)**: `ops_resent` 9, 9 and 8 and 9 session resets in each run (every dead connection's command is sent again on the new connection), `stall_closes` 0, `cancels` 0, no failed operation.

Why a reconnect costs about one second was not examined; the figures are the measurement: 1,059.7 and 1,061.8 ms for one dead connection in the default runs, 2,122 to 2,133 ms for the first command
(two connections) in nine of nine lowered-timeout gaps.

## 7. Writes and the one-packet-per-round-trip TCP (risk R6)

iPXE's `tcp_xfer_window()` is 0 while its transmit queue is not empty (design section 2): a connection has one unacknowledged segment in flight. The design estimated "MTU / RTT, about 1.4 MB/s at 1 ms".
The bench's copy step reads a command's worth and writes it to a scratch area (the digest of every destination is checked from outside with `rbd export`: **every write that completed is in the image**);
the write rate is the bytes divided by the sum of the TSC time of the write calls only. A `tcpdump` on the lab VM's lab NIC (headers only) was read by `captan.py`. The delay is added with
`tc netem` on the lab VM's NIC (egress: the OSDs' replies and acknowledgements to the guest): `d0` is the lab as it is, `d1`, `d3`, `d10` add 1, 3 and 10 ms.

| group | runs (passed) | 127 sectors MiB/s | 1 MiB MiB/s | 4 MiB MiB/s | time per 127-sector write ms | operations resent / session resets (per run) |
|---|---|---|---|---|---|---|
| wr-d0 | 3 (3) | 0.565 (0.562 - 0.620), n=3 | 1.318 (1.209 - 1.499), n=3 | 1.516 (1.508 - 1.610), n=3 | 108.9 (99.3 - 109.5), n=3 | 0/0/0 ; 0/0/0 |
| wr-d1 | 3 (3) | 0.372 (0.340 - 0.392), n=3 | 0.476 (0.457 - 0.502), n=3 | 0.371 (0.325 - 0.455), n=3 | 165.3 (157.0 - 181.0), n=3 | 2/5/4 ; 2/2/2 |
| wr-d10 | 1 (0) | - | - | - | - |  ;  |
| wr-d3 | 3 (0) | - | - | - | - |  ;  |

| group | runs | MSS seen (bytes) | most bytes in flight (flows measured) | median time between segments ms | median time to the ACK ms | ACKs at 30 ms or more (worst flow) % | MSS / gap MiB/s | commands that failed (127 / 1 MiB / 4 MiB sectors) |
|---|---|---|---|---|---|---|---|---|
| wr-d0 | 3 | 1208 | 1208 (2 of 4) | 0.55 (0.54 - 0.59), n=4 | 0.11 (0.11 - 0.11), n=4 | 0.9 | 2.09 (1.96 - 2.12), n=4 | 0 of 3 / 0 of 3 / 0 of 3 |
| wr-d1 | 3 | 1208 | 1208 (5 of 6) | 1.80 (1.73 - 1.82), n=6 | 1.27 (1.24 - 1.27), n=6 | 1.9 | 0.64 (0.63 - 0.67), n=6 | 0 of 3 / 0 of 3 / 0 of 3 |
| wr-d3 | 3 | 1208 | 1208 (3 of 5) | 3.88 (3.77 - 3.97), n=5 | 3.31 (3.28 - 3.34), n=5 | 1.4 | 0.30 (0.29 - 0.31), n=5 | 0 of 3 / 0 of 3 / 3 of 3 |
| wr-d10 | 1 | 1208 | 1208 (1 of 2) | 10.91 (10.89 - 10.92), n=2 | 10.32 (10.31 - 10.34), n=2 | 0.8 | 0.11 (0.11 - 0.11), n=2 | 0 of 1 / 1 of 1 / 1 of 1 |

* **It is stop-and-wait, and the measured cycle explains the rate.** The largest data segment the guest sent was 1,208 bytes and **never more than one segment was in flight** on any connection whose bytes in flight could be measured (`most bytes in
  flight` 1,208: one segment; the figure in brackets in the table is how many of the OSD connections it rests on: **11 of 17**). In the other six the capture had begun after the connection was open, tcpdump printed the first packet of the connection with
  absolute numbers and the rest relative to it, and `captan.py` (before the review) reported 0 bytes in flight for them: not a measurement, and now reported as not measured. For those six the other figures (gap, time to the ACK, segment size) are still read, and
  they have the stop-and-wait shape too; the bytes in flight themselves are not shown for them. In the samples kept (`capture-head.txt`) every packet the lab VM sent is in the capture twice, about 0.3 ms apart, and the guest's own packets once (not explained; the layer 2 echoing the lab VM's own frames back to it would do it); that changes no figure of the guest's segments, and the first copy of an acknowledgement is the one counted. New captures are taken with `tcpdump -S`.
  At d0 the median time between two segments is 0.55 ms and the receiving Linux acknowledges after 0.11 ms (no delayed-ACK stall: 0.8 to 1.9 % of acknowledgements, worst flow, took 30 ms or
  more); MSS / gap is 2.1 MiB/s, and the copy of 1 MiB and 4 MiB commands ran at **1.3 and 1.5 MiB/s**. With 63.5 KiB commands the rate is **0.57 MiB/s** (109 ms per command): the per-command
  round trip to the OSDs (all replicas committed) is added to a transfer of only 53 segments.
* **The rate falls with the round trip as the model says.** MSS / gap: 2.09 (d0), 0.64 (d1), 0.30 (d3), 0.11 MiB/s (d10); measured for the large commands: 1.3 to 1.5 (d0), 0.37 to 0.48 (d1), 0.22 to 0.28 for 1 MiB at d3 (the 4 MiB command failed), and at d10 only the 63.5 KiB command completed (0.095 MiB/s).
* **A write command that takes longer than the driver's operation timeout fails to complete.** At +1 ms (RTT about 1.8 ms) all commands completed, but the driver **resent 2, 5 and 4 operations and reset
  2 OSD sessions per run** (`op_timeout_ms` is 5,000 ms in the iPXE profile, `osd_ipxe()` of `wr_config.c`: an operation unanswered that long after its transmission gets its session reset and is sent again, and the core counts
  from the moment it hands the operation to the connection, not from the moment its last byte has left a stop-and-wait TCP). At +3 ms **the 4 MiB write command failed in 3 of 3 runs** (the SAN layer gave up: INT 13h `ah=04`, "a cancelled request did not finish; closing the
  cluster session"); at +10 ms the 63.5 KiB command still completed (0.095 MiB/s) and the **1 MiB and the 4 MiB commands failed**. Everything the driver wrote before a failure is correct (the digest of
  each completed command matches); what is lost is the command that failed.
* Reads are not affected (the receive window is the core's, section 2 of the design): the read rows above ran with the same TCP.

So R6 is real and measured: **a guest boot that writes a lot, or any write path with a round trip of a few milliseconds (a routed cluster), is bounded by about 1.2 KB per round trip**, and a large
write command fails when the transfer outlasts the operation timeout. Boot is read-dominated and the lab's round trip is 0.5 ms, so the Phase 2 exit criteria are not touched; a routed cluster with a
10 ms round trip is not usable for writes through this driver (about 0.1 MiB/s, and commands of 1 MiB and more fail).

## 8. A BIOS machine with little memory, and many hooks (risk R10)

`umalloc()` on BIOS is the external heap at the top of the largest block of the system memory map; the session asks it for **5,013,508 bytes** in one piece. Two tests with the probe image and the
instrumented build, in guests whose memory is set below the library's 512 MiB with a later `-m`:

* **How little memory opens the image?** One hook in a guest of 24, 16, 12, 10, 8 and 6 MiB.
* **Does a long-lived iPXE leak?** `mkloop.sh` hooks and unhooks the image 150 times in a row (the session lives on for 120 s after its last device, so these are re-opens of the cached session) and then
  three times after a wait of 125 s with nothing hooked (a new session each time: a new `umalloc` block each time, the old one freed), in a guest with 64 MiB; and a second run with 5 sessions created and
  destroyed in a guest too small for more than a few leaked blocks.

| guest memory | result |
|---|---|
| 24, 16, 12 MiB | the image opens, one hook ok (`r10-mem24-1`, `-mem16-1`, `-mem12-1`) |
| 10 MiB | **`rbd: open failed: out of memory (5013504 bytes of extended memory wanted)`**, then iPXE's own `Could not open SAN device: Not enough space`; `WRLOOP-HOOK fail 0x31716006` (`r10-mem10-1`) |
| 8 MiB | the same line and the same status (`r10-mem8-1`) |
| 6 MiB | the guest did not reach iPXE's script and exited after 10 s with no console output (`r10-mem6-1`): not the driver (the script never ran); not investigated |

* **The failure the design promised is the failure that happens**: with too little extended memory the open fails with `-ENOMEM`, one console line that says how many bytes were wanted, and nothing else is
  left registered. **A BIOS machine needs between 10 and 12 MiB of RAM** (12 MiB opens, 10 MiB does not, 11 MiB was not tried; the session block is 4.78 MiB; iPXE, the image, and the firmware's own areas take the rest).
* **150 hooks in one iPXE session, then 3 after the session cache's grace** (`r10-loop-1`, 64 MiB guest): 153 of 153 hooks succeeded; iPXE's heap maximum was 131 kB, the same as after a single hook (132 to 153 kB), so
  nothing accumulates on the 4 MiB heap; `umalloc` was asked for the 5,013,508-byte block four times (the first session and the three created after a grace), once per session and not once per hook.
* **5 sessions created and destroyed in a 20 MiB guest** (`r10-leak-1`: 20 hooks, then 4 hooks after a grace each, 540 s): 24 of 24 hooks succeeded and the block was granted 5 times (25 MB in all in a guest that can hold
  two at a time): **every session's block was returned**. Small leaks inside the block's own bookkeeping are not excluded; a leaked block per session is.


## 9. Verdicts

| Risk | What was measured | Verdict |
|---|---|---|
| R1 heap headroom | iPXE's `malloc()` heap maximum: 301 to 601 kB (BIOS, reading 128 MiB), 248 to 374 kB (UEFI boot), against 103 to 128 kB for iPXE alone, of 4,096 KiB | **Not a risk in this configuration**: the heap is not where the driver's memory goes; at least 3.4 MiB are left. The 4.78 MiB `umalloc` block is the cost (section 5). |
| R2 i386 BIOS stack | 2,772 of 4,096 bytes high-water for iPXE and the glue, 1,696 of 16,384 for the core on its own stack | **Budget met (1,324 bytes, 32 %, against 300); the own-stack switch is necessary**, not optional (2,772 + 1,696 > 4,096). x86_64 BIOS stack not measured (the monitor does not work there: F2 of the BIOS README). |
| R6 one packet per round trip | one 1,208-byte segment in flight (11 of 17 OSD connections measured); 1.3 to 1.5 MiB/s for large writes at 0.55 ms, 0.64 / 0.30 / 0.11 MiB/s MSS/gap at +1 / +3 / +10 ms; operations resent from +1 ms; write commands of 4 MiB fail from +3 ms and of 1 MiB at +10 ms | **Real, as designed, and worse than "slow": the transfer of one write command outlasts the 5 s operation timeout at a few milliseconds of round trip.** Irrelevant to boot (reads), relevant to any write path over a routed cluster. |
| R8 idle gaps | gaps of 5, 40, 120 s: no cost; after 960 s (daemons' 900 s idle timeout): 8 ms to 1.06 s for the first command, 2.09 s for a second connection; with a 10 s timeout 2.13 s for the first command after 40 s or more | **Works, as designed: reconnect inside the command, no error reaches the caller; the operation is sent again on the new connection (0 resent in the default-timeout runs, 8 or 9 per run with the 10 s timeout, which closes many connections). The price is about 1.06 s per dead connection**, once. |
| R9 readahead | 127-sector commands 1.2 times faster with the default window; 1 MiB and 4 MiB commands 7 and 4.8 times **slower**; window of 256 KiB the best compromise of the sizes tried (512 KiB better for 127-sector commands; n=2 each) | **The estimate does not hold: the default (2 MiB) window is a loss for large commands and a small gain for small ones; 256 KiB is the best of the sizes tried.** |
| R10 `umalloc`, long-lived iPXE | 12 MiB opens, 10 MiB fails with the designed line; 153 hooks and 5 sessions in a small guest with no failure, heap maximum 131 kB after 150 hooks | **Works as designed**: the failure is `-ENOMEM` with the byte count; nothing leaks across hooks or sessions at the granularity of a session block. |

The exit criteria of the roadmap are untouched by these figures: every counted boot reached its login prompt through the driver, the table check passed in every one, in no counted read run did a step read other than the planned sectors in the planned commands or return other bytes than the image's in the 128 KiB of its last command that is compared, and every copy that completed is in the image with the digest of its source. (The runs did not check that nothing *else* in the image changed: that is `mkbench.py verify --strict`, which `mrun.sh` uses from now on.) What the figures change is the **default of the readahead** and what can be promised about writes.

## 10. Findings

Ordered by what to act on first. "Evidence" names run directories of `results/measure/runs/`.

**F1. The default readahead window is a loss for 1 MiB and 4 MiB commands (and a small gain for 127-sector ones).** 3.6 MiB/s against 25.9 for 1 MiB commands, 6.7 against 32.1 for 4 MiB, 11.0 against 9.2 for 127 sectors
(`rd-def-*`, `rd-ra0-*`, `inst-*`); the sweep (`rd-ra*-*`) shows 256 KiB as the best compromise of the sizes tried (512 KiB is better for 127-sector commands: 20.7 against 15.4 MiB/s; two runs each) and a non-monotonic curve. A single far-away command also pays: median 10.6 ms against 4.8 ms with no readahead. The
default should be reviewed with the sweep and a window smaller than the cache; the mechanism (2,491 waits in 7,089 reads) was not examined, this module measures.

**F2. A write command that takes longer than `op_timeout_ms` (5 s on the iPXE profile) is resent and finally fails; stop-and-wait TCP gets there at +1 ms (resends) and +3 ms (failure of the 4 MiB command).** Evidence: `wr-d1-*`
(2 to 5 operations resent, 2 session resets per run), `wr-d3-*` (the 4 MiB command failed in 3 of 3: INT 13h `ah=04`, "a cancelled request did not finish; closing the cluster session"), `wr-d10-1` (the 1 MiB and 4 MiB commands failed).
The data written before a failure is correct (the digests of the commands that completed). The core's deadline of an operation runs from its transmission (`wri_osd_req_send.c`), and an operation queued behind a megabyte on a stop-and-wait connection waits
for the whole megabyte (this is the reading of the code and of the counters; the timeout itself was not traced). A write path that must work over a routed cluster needs either a deadline that follows the transfer (progress, not age), smaller write operations, or a better TCP; not this module.

**F3. Reconnecting inside a command costs about 1.06 s per dead connection.** `idle-def-*` after 960 s: 1,061.8 and 1,059.7 ms and 2,088.4 ms; `idle-t10-*`: 2,122 to 2,133 ms for the first command after every gap of 40 s or more, in nine of nine. It
looks like a fixed one-second wait in the reconnect (a back-off slot?) plus the handshake; not examined. A loader with a timeout under about 3 s for one read would fail on a machine whose cluster closes idle connections.

**F4. The kernel client on the same path is no faster than the driver without readahead.** 6.7 / 21.9 / 25.1 MiB/s direct (64 KiB / 1 MiB / 4 MiB) against the driver's 9.2 / 25.9 / 32.1; the lab VM's own kernel client reaches 12 / 122 / 177 MiB/s with no NIC in the way. The path (user-space
multicast socket NIC, 2 vCPUs, sparse-file OSDs on a loaded disk) is the ceiling for any guest in this lab, and every throughput figure here is bound to it; they say how the driver compares, not what a physical NIC would give.

**F5. The lab VM restarts its own daemons.** `unattended-upgrade` (apt-daily-upgrade, 06:24 to 06:35 UTC) restarted the monitor, the manager and the OSDs inside `rd-def-3`: 11 session resets, 1 resend, 1 cancel in its
`rbd-info` (the run's data was still right, and the driver recovered). The run is kept and is **not counted** (replaced by `rd-def-4`). One run (`inst-1`) started into a stalled lab VM and its SAN open failed at 35 s (kept in `attempts/`, replaced by
`inst-4`). The apt timers of the lab VM were stopped for the rest of the work and started again at the end. A lab that is measured must not upgrade itself.

**F6. The images are larger than the skeleton's table said.** +244 KB for `ipxe.efi` (the skeleton: +95 KB), +115 to 120 KB for BIOS images (+52 KB for `undionly.kpxe`). No limit is crossed (`undionly.kpxe` is 191 KB).

**F7. A UEFI console with `-DCONSOLE_SERIAL=` prints every character twice** (the firmware's console and iPXE's debug console both reach the serial line): a test that waits for a line must wait for the doubled text. Not a driver
problem; `analyze.py` and `mheapefi.sh` handle it.

**F8. `import-winpe.sh` leaves the features `exclusive-lock`, `object-map`, `fast-diff` and `deep-flatten` on the image it imports, and the driver (correctly) refuses such an image.** The first WinPE cycle (`winpe-W1-1`, `-W2-1`, `-W3-1`) failed with
`rbd: open failed: image uses features this client does not support (mask in a0)`; `rbd feature disable` fixed it. The importer's default for `--features` should be `layering` (the BIOS README already imported with that);
and the console line gives a hex mask where the feature names would help (F10c of that README).

## 11. What changed in `ipxe-driver.md`

Every "not measured" / "estimated" note of the design now points here and carries the figure (section numbers of `ipxe-driver.md` in brackets):

| where in `ipxe-driver.md` | was | is |
|---|---|---|
| section 2, "TCP in iPXE" (R6) | "about 1.4 MB/s at 1 ms" (an estimate) | the measured cycle, rates at +0, +1, +3, +10 ms, the failures: section 7 here |
| section 3, after the size table | "131 KiB, well inside what PXE loads" (the skeleton) | the sizes of the finished driver: section 2 here |
| section 5.1, "Not measured yet" | the heap headroom, the real `wr_client_mem_required` and the little-memory behaviour not measured | all three measured: section 5 and section 8 here |
| section 5.2, the stack frames | "A static sum of those frames was not made" | the measured high-water mark, and the finding that the own-stack switch is necessary: section 5 here |
| section 10, readahead | "estimated, **not measured**" | measured against `readahead=0`, with the window sweep: section 3 here |
| section 11, "Idle gaps" | "Tested in section 14.3 by pausing the guest" | measured with a real idle gap: section 6 here |
| section 14.4 | "Reported in the document, not asserted" | names this document and says which budgets are asserted |
| section 16, rows R1, R2, R6, R8, R9, R10 | "not measured" / "unmeasured" / "an estimate" / "accepted" | the measurement and a pointer to the section here (R3 to R5, R7, R11 to R14 are not touched) |

The edits are in place in `docs/design/ipxe-driver.md`; nothing was added to or removed from its decision table. The row text of R3 ("unverified") was changed by the review to "partly verified": all four WinPE rows reached the WinPE marker
with the default (`vendor`) device-path shape, which is evidence for it, not a verification of what Windows does after the boot manager or of the other two path shapes.


Nothing else of that document was edited: the decisions D1 to D11 and the text of sections 6, 7, 8, 9 and 12 stand. Three statements of the design are **contradicted** by the measurements and are the reason for
findings F1, F2 and F6: the readahead estimate (section 10), "write throughput about 1.4 MB/s at 1 ms" (section 2) as a harmless limit, and the size of the images (section 3).

## 12. Reproduce, and what this module left behind

Everything is in `harness/lab/p2/results/measure/` (its `README.md` lists the files). On the build machine, with `tools/box-env.example` sourced: `mimages.sh make`, `mimages.sh create probe read write idle lin-uefi lin-bios`,
then the series of `campaign.sh` in the order of section 1; `summarize.py all runs/` prints the tables of this document. The offline test is ctest `measure.selftest` (analysers with negative controls, the assembled
bench in QEMU with software emulation, the option refusals): it passed with gcc and clang, Debug / Release and ASan+UBSan configurations of the harness in the Ubuntu 26.04 builder guest (`logs/ctest-guest.log`),
and `core.docs` passed there (`logs/docs-ctest.log`); `shellcheck -S warning` is clean on every script. After the review of section 13 the self-test was run again on the build machine (`logs/review-selftest.log`: 54 checks, PASS).

Restored: the lab holds none of this module's images, users or key files (`mimages.sh delete-all`, the WinPE images and their snapshots); `lab-final.txt` against `lab-base.txt` differs in **one line: the OSD blocklist has 12 entries
where it had 5** (blocklist entries expire by themselves, after an hour by default; which runs added them, and whether the forced stops of guests or the kernel-client guests did, was not examined). The apt timers of the lab VM, stopped for the
runs, are started again; `ms_connection_idle_timeout` and the `netem` qdisc were removed after every run that set them (`lab-diff.txt` says "no difference" in 86 of the 89 runs that took one (the heap runs of `mheapbase.sh` and `mheapefi.sh` do not); the three that differ are `krbd-1` and `rd-def-3`, where the muted check `BLUESTORE_SLOW_OP_ALERT` appeared or cleared, and `heap-efi-1`, during which the WinPE users
were created, which this module did itself). The guests are gone, and the work directories and the builder guest's copies on the build machine were deleted at the end; only the small logs are kept here.

**Outside its own files this module changed:** `core/sources.txt` (regenerated by `core/tools/gen_sources.sh` by accident while looking at its usage; the list now names `handoff`, `ra` and `rburl`, which the orchestrator
regenerates after the wave anyway), `harness/CMakeLists.txt` (one block, `module measure`: the test `measure.selftest`), and this section's edits of `docs/design/ipxe-driver.md`.

## 13. What the review of this module changed

An adversarial review (the tools, the evidence and this document against the design) found the points below. The counted figures did not change; what changed is what the text claims for them, the tools, and
the tests. No run was repeated and no evidence file was rewritten.

| | finding | change |
|---|---|---|
| medium | The R6 "never more than one segment in flight" rested on `captan.py`'s bytes in flight, which came out as 0 for every connection that was already open when `tcpdump` began (6 of 17 OSD connections), and the table showed the maximum over all of them | `captan.py` drops the one packet printed in a different numbering and reports "not measured" when it cannot; `summarize.py` counts the flows the figure rests on (11 of 17, table and text); `mrun.sh` captures with `tcpdump -S`; self-test cases for a mid-connection capture and for the lab VM's packets twice |
| medium | Section 6 and the R8 verdict said "no resend" and "`ops_resent` 0 in every run"; the three `idle-t10` runs resent 9, 9 and 8 operations (9 session resets each) | text corrected in section 6, in the verdict and in design R8 |
| medium | "Every read step returned the right data" and "no run damaged a byte": the sum covers 128 KiB of the last command of a step, and the copies' check covers only the destination ranges | the text says what is checked; `analyze.py` now also checks every step against the plan (sectors, number of commands, writes, the latency series' reads, the calibrations; all counted runs pass it, run without rewriting evidence); `mkbench.py verify --strict` (data area, program, rest of the scratch area) is used by `mrun.sh` for copy runs |
| low | `lab-final.txt` differs from `lab-base.txt` (OSD blocklist 5 against 12) while the README said "no difference"; the README named a file that does not exist | both corrected; the cause of the blocklist entries was not examined |
| low | "A BIOS machine needs a little under 12 MiB" (12 opens, 10 does not, 11 not tried); "256 KiB is the best window" (two runs per size; 512 KiB is better for 127-sector commands); design R3 still said "unverified" after four WinPE rows booted | corrected in the text and in design R3, R9 |
| low, **not fixed** | `bench.S` has no wrap-aware tick arithmetic (a wait that spans midnight UTC in the guest never ends); the calibration prints a constant 91 ticks | listed in the README of the module under "Known limits"; the file is left as it is because every run's `binaries.sha256` records its hash |
| low | `mrun.sh --capture` stops every `tcpdump` on the lab VM | listed in the README |

Checked and found right: the build sizes and their percentages; every table of this document against `RESULTS.md` (generated, equal line for line); the stack, arena, heap and umalloc figures against the consoles of the runs; the
`rbd-info` counters quoted for the default and the 256 KiB window; the R10 refusals; the 86 of 89 `lab-diff.txt` count; the table check and the root marker in every login run; the WinPE marker in every counted WinPE run; no key,
no internal address other than the lab's 10.77.0.x, no host or user name in any file of the module (a scan for base64 keys and for the key file names of the runs found none); the licence line of every file (MIT, as the rest of `harness/`).
