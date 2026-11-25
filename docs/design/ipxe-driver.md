# Phase 2 design: the iPXE `rbd://` SAN driver

Status: **implemented and exercised in QEMU** against a real Ceph v20.2.5 (OVMF and SeaBIOS; PXE, USB stick, CD; Linux and the owner's WinPE image), with the notes of the close-out review in section 18. Sections 1 to 17 are the design as it was decided and the plan that was run; where the live runs or the review changed a decision or measured a figure, the section says so in a **Note (close-out)**. Pinned reference: iPXE `9261ebe38af0c0b38ac332adeec125a518845013` (`third_party/ipxe`, `ipxe/PINNED`). Inputs: `docs/ROADMAP.md` (Phase 2), `docs/design/core-architecture.md` (the pump, the iPXE profile, the memory model), `docs/design/handoff-table.md` (promoted to v1 by this design, section 9). Every claim about iPXE below was checked against the pinned tree and carries the file; a claim about firmware, Windows or hardware that was not checked is marked **unverified**.

English only, like `core-architecture.md`.

---

## 1. Decisions at a glance

| # | Question (ROADMAP, Phase 2) | Decision | Where |
|---|---|---|---|
| D1 | Direct block ops or the SCSI layer | **Direct block interface** (`block_read`, `block_write`, `block_read_capacity`), as the HTTP SAN protocol does. No SCSI emulation. | 2 |
| D2 | One SAN command at a time | One block command in flight, any size up to **4 MiB** (`max_count` = 8,192 blocks of 512 B); the core cuts it into object operations and issues them in parallel; **readahead** into a private cache hides the 127-sector reads of INT 13h. | 10 |
| D3 | EFI device path | Network device path (PCI parent, MAC, VLAN: `efi_netdev_path`) + **one vendor-defined messaging node** carrying the fsid and `pool/image`. Two escape hatches (`devpath=uri`, `devpath=sata`). What `bootmgr` / `winload` need: **unverified**. | 6 |
| D4 | Handoff ACPI table | Signature **`rBFT`**, body magic `WRBT`, layout version 1, rebuilt from current state on every describe pass, never relies on the OEM fields. Spec promoted from DRAFT to v1. | 9 |
| D5 | Memory | **One `umalloc()` block** (EFI `AllocatePages`, BIOS the external heap) for the core's arena, bulk, zombie area and readahead cache: about **4.8 MiB** (4,871 KiB) with the default readahead. The 4 MiB `malloc()` heap holds only the small glue objects (about 2 KiB per device). | 5 |
| D6 | INT 13h | 512-byte sectors, commands up to 4 MiB through the SAN layer, EDD only (no CHS-only path beyond what iPXE's generic code does), no `edd_describe` in v1 (iPXE falls back to parameters without the device path info). Stack is the real risk: **4,096 bytes** on i386 BIOS. | 7 |
| D7 | Reopen after a path failure | The cluster **session** (client, maps, tickets, open image) outlives the block device: a reopen finds it by identity and costs one image check, not a cold start. Kept 120 s after the last device. | 11 |
| D8 | URI and credentials | `rbd://[user@]mon[:port][,mon[:port]...]/pool/image[@snap][?options]`. The cephx key comes from the **`rbd-key` setting**; a URI with a password is refused. | 8 |
| D9 | `FILE_SECBOOT` | **`FORBIDDEN` for every file** (glue and imported core); declared explicitly so a Secure Boot build fails with the reason, not with "missing declaration". | 13 |
| D10 | Licence check | Glue `GPL2_OR_LATER_OR_UBDL`, core `MIT` (tags added by the import transform), `core/crush_ln/` `GPL2_OR_LATER`. `make bin/<target>.licence` is part of the build script and of CI. | 3, 13 |
| D11 | Live test path | A **dedicated single-host Ceph v20.2.5 lab VM on the shared KVM build box**, built with the repository's own `harness/lab` scripts, with the QEMU test guests joined to its private multicast layer 2 (guest NIC 2 = `10.77.0.0/24`). No relay, no dependency on the main lab; the main lab is a cross-check once the Phase 1 exit run has finished. | 14.1 |

The driver adds **no protocol logic**. The glue opens sockets, moves bytes, keeps timers and answers iPXE's interfaces; everything about Ceph stays in `core/`, where it is tested in the harness. Two pieces that are portable and testable without iPXE are new **core** modules (MIT): the handoff table codec and the URL and option parser (section 17).

---

## 2. What iPXE's SAN layer gives us, and what it takes away

All of it read in the pinned tree.

**The SAN layer** (`src/core/sanboot.c`, `src/include/ipxe/sanboot.h`):

- It is generic over a *block interface*: `sandev_rw()` splits a request into fragments of `capacity.max_count` blocks and runs each as one command through `sandev_command()`.
- **One command at a time**, with an overall timeout of 15 s (`SAN_COMMAND_TIMEOUT`) and up to 10 retries (`SAN_DEFAULT_RETRIES`, the `san-retries` setting). The caller blocks, calling `step()` in a loop; there are no threads. So parallelism across OSDs must happen *inside* one command, and nothing can be left running for a later command except work the glue starts on its own (readahead, section 10).
- A *path* is "active" when `xfer_window()` of the block interface is non-zero (`sanpath_step`). `sandev_reopen()` closes every path and opens the URI again; it waits **for ever** until a path is active or all have failed. The open therefore needs its own timeout (D8, `RBD_DEFAULT_OPEN_TIMEOUT_MS` = 20 s).
- When a path's block interface is closed with any status, the path is closed and the next command reopens (`sanpath_block_close` -> `sanpath_close` -> `sandev->active = NULL` -> `sandev_needs_reopen`). That is the reopen of milestone 7 (section 11). A command that times out is only closed and retried; the path stays.
- `register_sandev()` opens the device, **describes** it (`sandev_describe`: waits until every ACPI descriptor says complete), reads the capacity, and checks for an ISO 9660 primary descriptor at LBA 16 of 2048-byte blocks: an RBD image that holds an ISO is exposed as a CD-ROM with 2048-byte blocks (`blksize_shift`), which is what UEFI and BIOS want for a CD.
- `uriboot()` (`src/usr/autoboot.c`) hooks, describes (unless `--no-describe`), boots, unhooks (unless `keep-san` is set).

**Direct block ops against the SCSI layer.** The block interface is three operations (`src/include/ipxe/blockdev.h`): `block_read`, `block_write`, `block_read_capacity`; completion is `intf_close(rc)` on the *data* interface that came with the call, and the capacity is reported with `block_capacity()` before closing. ATA (`drivers/block/ata.c`, behind AoE) and SCSI (`drivers/block/scsi.c`, behind iSCSI, SRP, FCP, USB mass storage) implement it on top of a command set. The HTTP SAN protocol (`src/net/tcp/httpblock.c`) implements it **directly**, with `max_count = -1U` and a 512-byte block, and answers `efi_describe` with `efi_uri_path()` (`httpcore.c`): there is a working precedent for a block provider with no command set underneath, with an EFI device path.

Decision **D1: direct**. A SCSI emulation would add INQUIRY, TEST UNIT READY, READ CAPACITY(10 and 16), REPORT LUNS and sense data handling (`scsi.c` alone is about 1,000 lines) for no behaviour that RBD has: no unit attention, no reservations, no LUNs. A direct provider keeps the whole driver at one object with one interface and one completion path. The cost is only that the device must itself answer the three side operations iPXE asks of any SAN device: `xfer_window` (active), `acpi_describe`, and (EFI) `efi_describe`. The optional BIOS `edd_describe` is not provided in v1 (section 7).

**Block size.** RBD has none. The device presents **512 bytes**: BIOS INT 13h non-extended calls require it (`int13_rw_sectors` checks `sandev_blksize == INT13_BLKSIZE`), UEFI's `EFI_BLOCK_IO` accepts any, and the ISO 9660 detection above handles 2048-byte media by itself. A 4096-byte presentation for 4Kn guests is a later option (`?blksize=4096`), not v1.

**TCP in iPXE** (`src/net/tcp.c`): `tcp_xfer_window()` returns 0 while the transmit queue is non-empty, so **one unacknowledged packet is in flight per connection** and the window never exceeds the path MTU (`TCP_PATH_MTU`). Consequence for writes: a write is sent one segment at a time, each waiting for an ACK: throughput is roughly one segment (1,208 bytes seen) per round trip per connection. **Measured** ([ipxe-driver-measurements.md](ipxe-driver-measurements.md), section 7): 2.1 MiB/s from the segment cycle at the lab's 0.55 ms round trip and 1.3 to 1.5 MiB/s for large write commands; 0.64, 0.30 and 0.11 MiB/s at +1, +3 and +10 ms; with 1 ms added the driver's 5 s operation timeout already resends operations of a 4 MiB command, and at +3 ms (4 MiB commands) or +10 ms (1 MiB commands) the write command fails. Reads are not affected: the receive window is `min(xfer_window of the consumer, TCP_MAX_WINDOW_SIZE = 2 MiB)` and **the consumer is us**: the window we report is the core's receive window (`wr_conn_rx_window`), which is real backpressure. **Note (close-out):** that window was at first the core's whole room, and iPXE's TCP announces it as it is (up to 2 MiB per connection) and queues the out-of-order segments that arrive inside it as I/O buffers of the **4 MiB heap** (`tcp_rx_enqueue`): a connection that loses one segment with a window of megabytes behind it can hold the heap, and with it the NIC's receive buffers and the next transmit. The glue now never announces more than `RBD_CONN_RX_WINDOW_MAX` = 64 KiB per connection (section 18, finding R-1). Boot is read-dominated; writes (the OS writing its first log) are not a milestone concern. Recorded as risk R6; the fix, if ever needed, is in iPXE's TCP, not in this driver, and is out of scope.

---

## 3. Tree layout, patches, and how iPXE is built

```
ipxe/
  PINNED                     the iPXE revision this driver is built against (checked by the build script)
  patches/                   the WHOLE change to iPXE's own files (4 patches: hooks, BIOS table room, self-tests, the BIOS object)
  src/                       the glue files (rbd_*.c, rbd_priv.h), GPL2_OR_LATER_OR_UBDL
  tools/build.sh             prepare | build | licence | check | clean
```

`ipxe/tools/build.sh prepare` exports the pinned tree with `git archive` (committed files only: a dirty submodule cannot leak into a build; a mismatch with `PINNED` stops it), applies `ipxe/patches/*.patch`, and imports `ipxe/src/*` and the core, **flat**, into `src/winrbd/` of the copy. Nothing inside `third_party/ipxe` is ever modified, and nothing generated is committed.

The patches:

1. `0001-winrbd-hooks-for-the-rbd-sanboot-protocol.patch` (4 files): `src/Makefile` gets `SRCDIRS += winrbd`; `config/general.h` gets `#define SANBOOT_PROTO_RBD` next to the other SAN protocols; `config/config.c` gets `REQUIRE_OBJECT ( rbd_uri )` under that option (the pattern of `iscsi` and `httpblock`; everything else is pulled by symbol references); `include/ipxe/errfile.h` registers the glue objects (iPXE derives the file part of an error code from `ERRFILE_<object>`; an unregistered object that uses `ENOMEM` and friends fails to link).
2. `0002-int13-room-for-the-handoff-table.patch`: `XBFTAB_SIZE` 768 -> 2048 (section 9.5).
3. `0003-winrbd-self-tests.patch`: `src/tests/tests.c` requires the driver's self-test objects (`ipxe/tests/`), so that they are linked into iPXE's own test program (`bin-x86_64-linux/tests.linux`) and never into a bootable image.
4. `0004-winrbd-bios.patch`: `config/config.c` requires the BIOS-only object `rbd_bios` (the `rbd-xbft` command, the exit warning for UNDI) on the pcbios platform, `errfile.h` registers it, and `XBFTAB_SIZE` / `XBFTAB_ALIGN` move from `int13.c` to `int13.h` (values unchanged) so that the object can refuse to compile if the area is ever made smaller.

Why the core is imported **flat and with a transform**: iPXE derives object names from file basenames (the core already guarantees unique basenames; the build script checks that the glue's do not collide), and its licence check, `make bin/<target>.licence`, *greps the sources of every object and header* for `FILE_LICENCE (` and, in a Secure Boot build, `FILE_SECBOOT (`. The core must not contain iPXE macros, so the import replaces the one placeholder line `WR_FILE_LICENCE_MIT` of each `.c` file (the core's own hook for exactly this) by `FILE_LICENCE ( MIT );` (`GPL2_OR_LATER` for `core/crush_ln/`: iPXE has no LGPL tag; LGPL-2.1 section 3 allows the GPL) plus `FILE_SECBOOT ( FORBIDDEN );`, and adds the same two lines after the include guard of every header. The script stops if a core file has no placeholder or no guard. The transform is mechanical and reviewed in one place (`import_core_file`); the repository's core stays free of iPXE.

**What the skeleton showed about iPXE's C environment** (found by building it, not by reading it):

1. iPXE's `<stdint.h>` is not C99's: it has the fixed-width types but **no `uintptr_t` and none of the limit macros** (`UINT32_MAX`, `INT64_MIN`, `SIZE_MAX`, ...), which the core uses (the harness's `core_freestanding*` gates and `wr_core_ipxe_flags` use the compiler's own `<stdint.h>`, so they could not see this). The core already has the hook for a host that needs it: `WR_HOST_CONFIG_HEADER`, included first by `wr_port.h`. The glue provides `ipxe/src/rbd_core_cfg.h`, which supplies `uintptr_t` and the limits from the compiler's predefined macros (so they cannot disagree with iPXE's own types), and the import step inserts one line, `#define WR_HOST_CONFIG_HEADER "rbd_core_cfg.h"`, into the imported copy of `wr_port.h` (no compiler flag to remember, so a `make` run by hand in the copy behaves like the script).
2. On x86 iPXE's `memmove()` is an inline wrapper around `__memmove()`; there is **no out-of-line `memmove` symbol**, so the compiler's `__builtin_memmove` (the core's default for `WR_MEMMOVE`) ended in an undefined reference at link time. The same header maps `WR_MEMCPY`, `WR_MEMMOVE`, `WR_MEMSET` and `WR_MEMCMP` to iPXE's own functions. The core still references nothing but those three (the `core_no_libc` gate is unaffected: it is about the harness build).
3. The core has one non-C file, `core/src/crypto/wri_crc32c_tab.inc` (a table initialiser), which `wri_crc32c.c` includes. iPXE's make treats an include it cannot find as a generated file and loops; the import copies `.inc` files too, and for the licence check puts the two tag lines in a comment at the top (the check only greps for the text).

`build.sh build [-e SCRIPT] TARGET...` runs `make` in the copy with iPXE's own `-Werror` (never `NO_WERROR`), supports `EMBED=` and `DEBUG=`, and works on a host without `liblzma-dev` through `IPXE_HOST_LZMA_PREFIX` (iPXE's `zbin` host tool needs `lzma.h`; CI installs `liblzma-dev`). `bin/ipxe.iso` also needs `mtools`, `xorriso` and `syslinux` (`util/genfsimg`).

**Measured with the skeleton** (pinned iPXE, gcc 11.4 on the build box, `-Os`, iPXE's own `-Werror`, no warning; the skeleton links the **whole core** (its self-check really creates a client, section 5.1), so this is the real code size of the core in iPXE, without the glue that is still to be written):

| Target | Without the driver | With the skeleton | Delta |
|---|---|---|---|
| `bin-x86_64-efi/ipxe.efi` | 1,193,472 | 1,288,704 | +95,232 (+8 %) |
| `bin/undionly.kpxe` | 81,736 | 133,909 | +52,173 (+64 %) |
| `bin/ipxe.pxe` | 431,937 | 480,617 | +48,680 (+11 %) |
| `bin/ipxe.usb` | 475,136 | 507,904 | +32,768 (+7 %; padded) |

`undionly.kpxe` grows the most in proportion because it has no NIC drivers; it is still well inside what PXE loads over TFTP. **With the finished driver** (not the skeleton) the images are larger ([ipxe-driver-measurements.md](ipxe-driver-measurements.md), section 2): `ipxe.efi` +244 KB (the skeleton's +95 KB was the core alone), BIOS images +115 to 120 KB, `undionly.kpxe` 191 KB (32-bit) and 202 KB (x86_64). i386 links with no help from outside (iPXE's `libgcc` directory covers the core's 64-bit arithmetic); the BIOS data16 segment still fits with `XBFTAB_SIZE` 2,048.

`bin/ipxe.iso` was produced on the build box too: `bin/ipxe.lkrn` builds with no warning (1.0 MB ISO from 480,113 bytes of `ipxe.lkrn`), and the image step is iPXE's `util/genfsimg`, which looks for `isolinux.bin` and `ldlinux.c32` in **fixed system directories** (`/usr/lib/ISOLINUX`, `/usr/lib/syslinux/...`) and has no override. On a box without root the packages were unpacked into a private prefix and a copy of `genfsimg` with the two paths rewritten was run on the same `ipxe.lkrn`; CI and the builder VM install `isolinux` and `syslinux-common` normally.

**Run in firmware.** The skeleton's `ipxe.efi` with an embedded script was booted in QEMU (OVMF, Secure Boot off, delivered by OVMF's own PXE from a user-mode `tftp=` directory): `sanhook rbd://u:pw@...` is refused with the console line "rbd: key material must not be part of the URI (use the rbd-key setting)" and `Could not open SAN device: Invalid argument`; a well-formed `rbd://` URI ends in `Operation not supported` (fail closed; the error number carries the glue's own error file id, so the patch to `errfile.h` works); an unknown scheme gives the stock error. The same flow is the smoke test the `qemu-scripts` module keeps.

**The licence check on a real build** (`make bin/<target>.licence`): `bin/undionly.kpxe` and `bin-x86_64-efi/snponly.efi` pass and report **"GPL version 2 (or, at your option, any later version)"**, with the MIT files listed as subsumed. The default `bin-x86_64-efi/ipxe.efi` and `bin/ipxe.pxe` (every NIC driver) **fail the check on the pristine pinned iPXE as well**, because of unrelated InfiniBand NIC headers without a `FILE_LICENCE` (`drivers/infiniband/mlx_nodnic/...`): the check is run on the two targets without those drivers, and the two others only need to build.

**Upstream.** iPXE has its own contribution policy (`CONTRIBUTING.md` in the pinned tree: a large feature has very little chance of being merged without funding for review, every submission needs an accountable author who has read and understood it, and externally developed code is not eligible to be signed for UEFI Secure Boot). This driver is **out of tree by design**, shipped as patches plus files against a pinned revision; proposing any part upstream is a decision for the maintainers of this project.

---

## 4. The host shim: modules and flows

The shim is the set of glue files in `ipxe/src/`, with the structures of `rbd_priv.h` as the contract between them:

| File | Concern | Notes |
|---|---|---|
| `rbd_uri.c` | `rbd` URI opener (`__uri_opener`), the settings, URI -> `struct rbd_spec` | no network, no core calls except `wr_key_*`; owns the whole untrusted-text parsing surface of the glue (and calls the core's parser, section 17) |
| `rbd_session.c` | the shared session: memory plan, `wr_client`, `wr_image`, the one `struct process` that runs the core, timers, events, reopen cache | the only file that calls `wr_client_run` |
| `rbd_conn.c` | the pump host: connection table over iPXE sockets, time, random, log | the only file that touches `xfer_*` on sockets |
| `rbd_block.c` | the block interface of one device: commands, cancel, readahead hook, window, close | no socket, no core internals |
| `rbd_efi.c` | `efi_describe` | built in every target, returns data only on EFI |
| `rbd_acpi.c` | the handoff table as an `acpi_model` | builds the table through the core's codec |
| `rbd_errors.c` | `wr_status` -> iPXE rc, the one console line of a failed open | a refused login (`WR_E_M2_BAD_METHOD`) is told apart by what the peer answered: permission denied, or "mode not supported" |
| `rbd_bios.c` | BIOS only: the boot-firmware-table scan, the `rbd-xbft` command, the warning when iPXE exits with a drive hooked over UNDI | pure functions are tested on every platform |
| `rbd_stack.c` | the stack watermark (test builds), the core's private stack trampoline (i386 BIOS), the `rbd-info` command, the counters line (test builds) | |
| `rbd_core_cfg.h` | the core's host configuration header (section 3) | no logic |

**Open** (`sanhook rbd://...`): `rbd_open` (the URI opener) allocates a `struct rbd_spec` on the **heap** (it holds the key; the BIOS stack is 4 KiB), parses the URI and the settings, asks `rbd_session_open` for a session (found by identity or created), attaches a new `struct rbd_device` to the SAN path's interface (`rbd_device_open`), wipes the spec. The device's `xfer_window` is non-zero once the image is open (state `WR_IMG_OPEN`); until then the SAN layer waits. A failed open closes the block interface with an iPXE error code and prints one line (`rbd: open failed: <core text> (<WR_E_NAME>)`) with the reason: no URI, no key, no payload in it.

**The run loop.** One `struct process` per session (`PROC_DESC`, runs from iPXE's `step()`): calls `wr_client_run(c, &now, budget)` with the current time, drains `wr_client_next_action()` (CONNECT: open a socket; CLOSE: close it and report `wr_conn_closed`), services each live connection (transmit, below), pulls `wr_client_next_event()`, and completes finished block commands with `wr_client_next_done()`. A retry timer is armed from `next_deadline_ms`. Delivery from the network (`xfer_deliver`) **only pushes into the core and schedules the process**; it never calls `wr_client_run` (the pump contract, `core-architecture.md` 3.1: iPXE can close an interface synchronously inside a delivery).

**Connections.** One `struct interface` per core connection slot (8 on the iPXE profile). CONNECT: `xfer_open_socket(SOCK_STREAM, peer)` with a `struct sockaddr_tcpip` built from the `wr_addr` (IPv4 or IPv6, port); a **connect timer** of `timeout_ms` per slot (iPXE's TCP would retry for much longer than `osd_connect_timeout_ms`); established is `xfer_window != 0` after `xfer_window_changed`. Receive: `xfer_deliver` copies the I/O buffer into the core with `wr_conn_rx_push`, and returns the window (`xfer_window` = `wr_conn_rx_window`) so that TCP does not deliver more than the core can take; data the core could not take stays in a per-connection list of I/O buffers bounded by the advertised window. Transmit: `wr_conn_tx_peek` offers a gather list, the step sends `min(window, len)` with `xfer_alloc_iob` + `xfer_deliver_raw`, `wr_conn_tx_consume(n)`; the window is 0 until the ACK of the previous packet, and `xfer_window_changed` resumes the step (the pattern of `iscsi_tx_resume`). Close from iPXE (`intf_close`): `wr_conn_closed(id, errno)`.

**Time.** `mono_ms` from `currticks()`; `TICKS_PER_SEC` is 1024 (`ipxe/timer.h`), so `ms = ticks * 1000 / 1024` is computed in 64 bits with a multiply and a shift (no division helper on i386). `wall_ms` = `time(NULL) * 1000` when the platform has a clock, else 0 (core-architecture 3.4: whether OSDs accept an mtime of 0 on writes is an open item, Q4 there; the lab answers it in the first write test).

**Random.** `rbg_generate()` (`src/crypto/rbg.c`, an SP 800-90A DRBG over the entropy sources of the build: RTC and RDRAND on BIOS; EFI tick, EFI RNG protocol and RDRAND on EFI). A failure is `WR_E_HOST_RANDOM`: the open fails with the console line; **no weak fallback** (core-architecture 4.1). The object is pulled in by a symbol reference from `rbd_conn.c`.

**Log.** The core's `log` callback prints nothing by default; with `DEBUG=rbd` (or `rbd_conn`, ...) it maps `wr_log_rec` to `DBGC`. Compile-time ceiling `WR_LOG_MAX_LEVEL` stays at its default (the runtime filter is the build's `DEBUG`).

**Block commands.** `block_read(control, data, lba, count, buffer, len)`: allocate a refcounted command object, `intf_plug_plug(&cmd->block, data)` (the pattern of `ata.c`), build a `wr_io_req` with `buf = buffer` (**the SAN layer's buffer, used directly, zero copy**), submit it, `wr_client_run` once (a submit does no I/O: core-architecture 28 rule 2). Completion in the process step: `intf_shutdown(&cmd->block, rc)` (this is `intf_close(rc)` on the SAN's data interface). Capacity: `block_capacity(data, {blocks = size / 512, blksize = 512, max_count = 8192})` then close; a size that is not a multiple of 512 is truncated down and the tail is unreachable.

**Cancel** (the SAN layer closes the command interface on its 15 s timeout, or the whole path on reopen). The core's contract (`wr_image.h`): `wr_image_cancel` returns `WR_OK` (finished, the buffer is ours) or `WR_E_BUSY` (a reply may still land in the buffer: the session is being reset). The danger is a caller that then reuses the buffer. The glue therefore cancels **synchronously**: on `WR_E_BUSY` it runs `wr_client_run` and the action drain in a bounded loop (the reset needs no network: it closes sockets and frees slots) until the request comes back from `wr_client_next_done`; only then does `intf_close` of the command return to the SAN layer. Because data reaches a caller buffer only through `wr_conn_rx_push` calls made by the glue itself, and the glue stops delivering for a revoked request, **nothing can write into a released buffer**. A write whose data was sent stays alive in the core (zombie, `zombie_bytes`) exactly as the core says.

---

## 5. Memory and stack budgets

### 5.1 Memory

The arena and bulk figures were **measured in firmware** by the skeleton's self-check (it calls `wr_client_mem_required` for the iPXE profile with the OSD client on and crc policy, takes the memory from `umalloc()`, creates a `wr_client` and destroys it: QEMU with OVMF printed `RBD session needs 263392 + 2627584 bytes` and `client created and destroyed`); they agree with `core-architecture.md` 26 (the bulk figure there is 2,566 KiB *including* the 1 MiB zombie area) and with the 264 KiB arena budget of 36.3.

| Piece | Size | Where | Why there |
|---|---|---|---|
| core arena (engine, 8 connections, handshake slot, op table, sessions, image, request table) | **263,392 bytes** (257 KiB; measured by the skeleton in firmware); more with a policy that may end in secure | `umalloc` | one block, no fragmentation of the 4 MiB heap (below) |
| core bulk (two 256 KiB map slots, one 1 MiB monitor message slot, tables, and the 1 MiB zombie area: copies of cancelled writes) | **2,627,584 bytes** (2,566 KiB; measured) | `umalloc` | the core asks for it |
| readahead cache (`readahead=` option, default 2,048 KiB) | 2 MiB | `umalloc` | section 10 |
| **total** | **about 4.8 MiB** (4,871 KiB) | | |
| glue objects (device, session, command objects, spec during open) | about 2 KiB per device + 700 bytes during an open | `malloc` | small, short lived |

**Decision D5 against the roadmap's open question ("4 MiB `malloc()` heap versus map sizes").** `malloc()` is a fixed `char heap_area[4 MiB]` (`src/core/malloc.c`, `HEAP_SIZE`) shared with every iobuf, NIC ring, URI, interface object and image of the running iPXE: putting a 254 KiB arena there (6 %) fragments the one resource whose exhaustion breaks the network stack, for no benefit: the arena has no alignment or locality need that `umalloc` does not meet. `umalloc()` is `AllocatePages(EfiBootServicesData)` on EFI (`src/interface/efi/efi_umalloc.c`: page aligned, one extra page of header) and, on BIOS, the external heap of `src/core/uheap.c`, which grows **downwards from the top of the largest contiguous block of the system memory map** (page aligned; the memory is marked used so the OS memory map hides it while iPXE is resident). Both satisfy the core's 16-byte alignment. One allocation at session creation, one free at session destruction. The cost is that the cached maps live as long as the session (section 11).

**Measured** ([ipxe-driver-measurements.md](ipxe-driver-measurements.md), sections 5 and 8): iPXE's own `malloc()` heap peaks at **601 kB** during a BIOS run that reads 128 MiB in 4 MiB commands (**374 kB** on UEFI to the hand-over to the boot loader), against **103 to 128 kB** for the same iPXE with nothing hooked: the driver's share of the 4 MiB heap is under 0.55 MiB at its worst and the headroom (risk R1) is at least 3.4 MiB. The session's one `umalloc()` block is 5,013,508 bytes on i386 BIOS (`HEAP attempting to grow for 0x4c8004`), of which the arena is 260,128 of 262,144 and the bulk 2,627,584 of 2,629,632 bytes used at open: within the budget, with 2,016 and 2,048 bytes to spare. A BIOS guest with **12 MiB** of RAM opens the image; with **10 MiB** the open fails with the one console line `rbd: open failed: out of memory (5013504 bytes of extended memory wanted)` (the design's promise).

**Larger clusters.** The iPXE profile accepts clusters up to 2,048 OSDs with the default `mon_msg_cap` of 1 MiB (core README, Phase 1). A cluster that is too big for the profile fails the open with `WR_E_MAP_BUDGET` and the console line says so; the options `mapmem=` (KiB per map slot) and `monmsg=` (KiB) raise the budgets and are the only knobs, because more memory is the only fix (core-architecture 15.3).

### 5.2 Stack

iPXE's own stack (`src/arch/x86/core/stack.S`): **4,096 bytes on i386** (BIOS builds: `undionly.kpxe`, `ipxe.pxe`, `ipxe.usb`, `ipxe.iso`) and 8,192 bytes on x86_64; EFI builds run on the firmware's stack (hundreds of KiB). Measured on the build box (gcc 11.4) with the core's own call-graph tool (`harness/tests/ci-docs-hardening/check_callgraph.py`, `-Os`, which is what iPXE builds with; for i386 through a wrapper that adds `-m32`):

| Build | Worst static stack of the core | Entry | Chain |
|---|---|---|---|
| i386 (`-m32 -Os`) | **2,632 bytes** | `wr_client_run` | map store apply an incremental, decode the full map embedded in it, audit a CRUSH rule |
| x86_64 (`-Os`) | 2,944 bytes | `wr_client_run` | same |

On i386 BIOS the core alone takes 64 % of the stack, leaving about **1,460 bytes** for everything iPXE has on the stack when the core runs: the INT 13h entry, `sandev_read`, `sandev_rw`, `sandev_command`, `step()`, the process dispatch, the session step, and (if a command is cancelled from `intf_close` inside `step()`) the cancel path on top of those. **Measured** (the stack monitor, 3 runs of the 4 MiB read plan and 3 of the probe, i386 BIOS, `RBD_STACK_MONITOR`): iPXE's own 4,096-byte stack peaks at **2,772 bytes** (1,324 left) in every run, with the core running on its **own** stack (1,696 of 16,384 bytes used). The 1,324 bytes that are left are **less than the 1,696 the core uses**: without the own-stack trampoline the margin would be negative (see [ipxe-driver-measurements.md](ipxe-driver-measurements.md), section 5). The risk is real and is handled in three layers:

1. **A stack watermark** (module `ipxe-stack`, a build-time option of the glue, **off in release builds**): the session paints the free part of the stack with a pattern at open and reports the high-water mark at close (`DBG` and `rbd-info`). It makes the measurement part of every BIOS test run, in the INT 13h path of a real boot.
2. **Budgets in the gate**: the harness gets call-graph entries for the glue-facing entry points (`wr_client_run`, `wr_image_submit`, `wr_image_cancel`, `wr_conn_*`) with the i386 numbers above plus 8 %, so that a core change that deepens the worst chain is seen in review, exactly like parts B to D.
3. **If the watermark says the margin is under 300 bytes on i386**: run the core on its **own stack** (a 16 KiB region of the session block, switched by a ten-line trampoline in `rbd_session.c`, the only place that calls into the core). iPXE has no stack-walking code (no unwinding, no `__stack_chk` on BIOS in this build), and the glue calls the core from one place, so the switch is local; interrupts: the BIOS INT 13h path and iPXE's timer run with interrupts disabled in protected mode (**unverified**: the watermark run in QEMU settles whether any handler can fire on the switched stack). The decision rule is the measurement, not a guess; the trampoline is **not** written until the measurement asks for it (the project rule: default = original behaviour, a switch only when it is needed).

The glue itself keeps every large object off the stack: the `rbd_spec` (about 700 bytes with the key), the wr_config (about 220 bytes), the ACPI table under construction (up to 1 KiB) are all heap objects.

---

## 6. EFI device path and `EFI_BLOCK_IO`

`efi_block_hook()` (`src/interface/efi/efi_block.c`) calls `efi_describe(&sandev->active->block)` after the registration succeeded, installs `EFI_BLOCK_IO_PROTOCOL` (revision 3, `MediaPresent` 1, `LogicalBlocksPerPhysicalBlock` 1, `ReadOnly` **not** set, flush a no-op) and the path on a new handle, and connects every driver to it (`efi_connect`) so that the firmware's partition driver publishes the GPT partitions and its FAT driver the ESP. A device with no path fails the **whole hook** (`-ENODEV`), so the op is mandatory in the EFI build.

**Shape (D3).** `efi_netdev_path(netdev)` (parent PCI path, MAC node, VLAN node) as the prefix, followed by one **vendor-defined messaging node** (`MESSAGING_DEVICE_PATH`, `MSG_VENDOR_DP`), data = `{u8 version = 1, u8 reserved, u8 fsid[16] (zero if unknown), "pool/image[@snap]" NUL-terminated}`, with a fixed GUID of this project (`9041fce5-0402-4eae-b3c1-bd75adf50455`), then the end node. Reasons: (1) it names the image, so two RBD disks have two different paths, which firmware needs to tell handles apart; (2) it claims no existing node type (an iSCSI node would make Windows look for an iBFT and a SATA node would claim a controller that does not exist); (3) it is what the UEFI specification provides for a device class with no standard node; (4) iPXE builds the paths of AoE (`MSG_SATA_DP`) and iSCSI (`MSG_ISCSI_DP`) the same way (network prefix + one node: `efi_aoe_path`, `efi_iscsi_path`), and the HTTP protocol uses a URI node alone (`efi_uri_path`).

**Escape hatches.** `devpath=uri` uses a `MSG_URI_DP` node carrying the redacted URI (what the HTTP SAN protocol does); `devpath=sata` uses a SATA node (what AoE does) for firmware or loaders that only accept known classes. Default stays `vendor`; the others exist because the answer to the next question is not known.

**What do stock `bootmgr` / `winload` need? Unverified.** What is checked: UEFI loads the boot manager from the ESP through the partition handle's `EFI_SIMPLE_FILE_SYSTEM` (the partition driver builds the child path as `<parent path>/HD(...)`, so any valid parent path works), and the Windows boot manager and loader locate their volumes through block I/O handles and BCD device elements that name **disk and partition signatures (GPT GUIDs)**, not device paths. What is **not** checked, and needs a real WinPE image (section 15): whether `bootmgfw.efi` and `winload.efi` accept a parent path ending in an unknown vendor node, and what Windows does after `ExitBootServices` (that is the Phase 3 driver's problem, not the loader's; the loader's side is the table of section 9). The three path shapes exist so that the first Windows run can try them without a rebuild.

**Without the ACPI table protocol** (`acpi` is NULL in `efi_block.c`), `efi_block_describe()` returns `-ENOTSUP` and the whole `sanhook` fails; the boot script uses `sanboot --no-describe` to boot such firmware at the price of no handoff table. OVMF has the protocol.

**`ReadOnly`.** iPXE does not set `Media.ReadOnly`. A read-only image (`?ro=1`) answers `EFI_WRITE_PROTECTED` only after the first write fails with `WR_E_RBD_READONLY` (-> `-EROFS`); a loader that checks `ReadOnly` first would see a writable disk. This is a known gap of the SAN layer, not of the driver, listed in R7.

---

## 7. BIOS and INT 13h

`int13.c` (`src/arch/x86/interface/pcbios/int13.c`) turns the SAN device into a BIOS disk. What matters here:

- **Transfers.** Non-extended calls (AH=02/03) carry up to 255 sectors in AL (CHS with a guessed geometry from the MBR, `int13_guess_geometry`); extended calls (AH=42/43) take a count of up to 127 in the 16-bit form (`addr.count <= 0x7f`) or a 32-bit `long_count` when the count byte is 0xff (EDD 3.0). Bootloaders in practice ask for 127 sectors (63.5 KiB) or less; GRUB and the Windows boot manager both do. The buffer is addressed by a real-mode segment:offset or, with 0xffffffff, a 64-bit physical address; iPXE's flat protected mode turns both into a pointer (`real_to_virt`, `phys_to_virt`), so the core receives **directly into the caller's buffer** with no bounce.
- **Consequence for throughput**: one INT 13h call is one SAN command is one OSD operation (63.5 KiB, or two across an object boundary): no intra-command parallelism is possible. The latency of each is one network round trip plus the OSD's service time (about 1 to 2 ms on a LAN). That bounds sequential reads at roughly 30 MB/s, which is why D2 adds **readahead** (section 10): the next window is requested while the current command is being answered.
- **Capacity.** Sector counts are 64-bit in the extended calls; `int13_capacity32` clips the 32-bit value used by AH=08/15/CHS (images over 2 TiB are reachable only with EDD, which every current loader uses).
- **Device path info.** `INT 13h AH=48h` asks the block interface for `edd_describe` and `identify_device` (`int13_device_path_info`). Without them iPXE returns the extended parameters without the device path information (`len = offsetof(params, dpi)`), which is valid EDD 2.0. **v1 does not provide `edd_describe`**; if a Windows boot on BIOS turns out to need it (**unverified**), the one-function addition is an ATA-style path (`interface_type "ATA"`, master) behind the same module.
- **Boot firmware tables** are copied into one 768-byte area (`XBFTAB_SIZE`) of data16 with 16-byte alignment; `int13_install` fails with `-ENOSPC` when a table does not fit. Patch 0002 raises it to 2,048 bytes (section 9.5). On BIOS the tables are not in an RSDT: a consumer finds them by scanning the resident area for the signature and checksum, like the iBFT (Linux's iBFT driver scans 512 KiB to 1 MiB). The guest-side visibility test of milestone 8 does that scan (a small test tool reads physical memory, `iomem=relaxed` or `/dev/mem`); whether the table sits in the range a Windows driver would scan is **unverified**.
- **Stack**: section 5.2. **Memory**: section 5.1; `umalloc` on BIOS is the extended-memory heap, so a BIOS machine needs about 5 MiB of free extended memory (QEMU's default 128 MiB is plenty).
- **BIOS boot of Windows (MBR, `bootmgr` / `winload.exe` through INT 13h)**: **Note (close-out):** the owner's MBR WinPE image boots through INT 13h (rows W3 and W4, section 18.3), so `bootmgr` reads `boot.wim` through the driver; `winload` for an installed system (matching the BIOS drive by its MBR signature) is not tested.

---

## 8. The URI, the settings, the options

```
rbd://[user@]mon[:port][,mon[:port]...]/pool/image[@snap][?option=value[&option=value...]]
```

- **Authority.** `parse_uri` (`src/core/uri.c`) splits the authority at `@` into `user[:password]` and `host[:port]`, and splits `host[:port]` at the **last** colon unless the string ends in `]`. A list `10.0.0.1:3300,10.0.0.2:3300` therefore arrives as `host = "10.0.0.1:3300,10.0.0.2"`, `port = "3300"`. The glue rebuilds the authority as `host + ":" + port` (exactly the original string) and hands **that** to the core's parser (`wr_mon_parse_hosts`, which accepts `ip`, `ip:port`, `[v6]:port`, comma separated, default port 3300). Monitor addresses are **literals**: the core does no name resolution (`wr_key.h`), and v1 does not add iPXE's resolver; a host name fails with `WR_E_MON_HOSTS_SYNTAX` and the console line says "monitor addresses must be IP literals".
- **User.** `user@` in the URI, else the `rbd-user` setting. Both are the cephx id without `client.`; a leading `client.` is accepted and stripped (`wr_cluster_spec`).
- **Key.** Only the **`rbd-key` setting** (`set rbd-key AQ...==`): the base64 key as printed by `ceph auth get-key`, or the whole `key = ...` line of a keyring (`wr_key_parse_base64`, `wr_key_parse_keyring`). Both settings are `SETTING_AUTH_EXTRA`, like the iSCSI CHAP credentials. A URI with a **password** component is refused with a console line that says why: the URI is printed by errors, by `uri_dump` in debug builds and by menu code, and a key in it would leak. Settings are not hidden by iPXE (`show`, the config UI): the owner of the boot script is responsible, as for iSCSI CHAP; the design note on media in the roadmap (one cephx user per image, revoke with `ceph auth rm`) is the mitigation.
- **Path.** `/pool/image` (exactly two components; RBD namespaces are not in the core's image parameters yet, and the table has the field for later). `@snap` parses and is refused with `WR_E_UNSUPPORTED` until the core can open a snapshot (`wr_image_params.snap_id`).
- **Options** (all optional, unknown names are an error: fail closed):

| Option | Values | Default | Meaning |
|---|---|---|---|
| `mode` | `crc`, `crc-first`, `secure-first`, `secure` | `crc` | the offer policy (`WR_MODE_*`); `secure` needs a server that allows it, and costs 46 KiB more arena |
| `ro` | `0`, `1` | `0` | open read-only (profile R1) instead of as a writer (P1) |
| `timeout` | seconds, 1 to 600 | 20 | wait for the image to open |
| `readahead` | KiB, 0 to 16,384 | 2,048 | readahead window, 0 = off |
| `fsid` | UUID | none | refuse a cluster with another id |
| `devpath` | `vendor`, `uri`, `sata` | `vendor` | section 6 |
| `handoff` | `nokey`, `key`, `none` | `nokey` | section 9 |
| `mapmem`, `monmsg` | KiB | profile | section 5.1 |

- **Printing.** The console line of a failure never prints the URI; `DBG` output (build-time `DEBUG=`) prints what iPXE itself prints (`URI parsed ...`), which is why the key is not in it.

---

## 9. The handoff table, version 1

Promotes `docs/design/handoff-table.md` from DRAFT to v1 (module `core-handoff` writes the final text, the codec and the vectors; the decisions are here).

### 9.1 Signature and identity

- **Signature `rBFT`** ("RBD boot firmware table"), following the family `iBFT` (iSCSI), `aBFT` (AoE), `sBFT` (SRP) that iPXE already installs (`ibft.h`, `aoe.h`, `srp.h`). Checked: no other `ACPI_SIGNATURE` in the iPXE tree uses it; it is not one of the signatures the ACPI specification defines or reserves *to the best of this project's knowledge* (**unverified against Microsoft's private list**; the module records the check it did against the ACPICA signature list and the tables of a Linux and a Windows guest in QEMU).
- iPXE overwrites `oem_id` ("FENSYS") and `oem_table_id` ("iPXE") of every table it installs on EFI (`efi_block_install`) and on BIOS (`int13_install`), so **nothing depends on them**. The table is identified by the signature, the checksum **and a 4-byte magic `WRBT` at the start of the body**.
- ACPI header `revision` = 1; the version of the *layout* is its own field (below).

### 9.2 Layout (little-endian, packed)

After the 36-byte ACPI header, a **fixed part of 116 bytes** (`header_len`), then the variable area; all offsets in the fixed part are relative to the start of the variable area (`header_len` after the body start) and `0xffff` means absent.

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | magic | `W R B T` |
| 4 | 2 | version | 1. A reader refuses a version it does not know. |
| 6 | 2 | header_len | 116; later versions append fixed fields, readers skip to the variable area |
| 8 | 4 | flags | bit0 read-only open; bit1 key present; bit2 NIC static (not DHCP); bit3 VLAN present; bit4 fsid valid; bit5 secure required; others zero |
| 12 | 1 | auth | 0 none, 1 cephx |
| 13 | 1 | msgr_mode | `WR_MODE_CRC_ONLY` .. `WR_MODE_SECURE_ONLY` (1 to 4) |
| 14 | 1 | key_type | 0 none, 1 `aes`, 2 `aes256k` (the `wr_key` types) |
| 15 | 1 | key_len | bytes of key, 0 to 64 |
| 16 | 1 | mon_count | 1 to 8 |
| 17 | 1 | nic_family | 4, 6, or 0 if unknown |
| 18 | 1 | nic_prefix | prefix length |
| 19 | 1 | reserved | 0 |
| 20 | 16 | fsid | zero unless the fsid-valid flag |
| 36 | 6 | nic_mac | |
| 42 | 2 | nic_vlan | 0 if none |
| 44 | 2 | nic_mtu | |
| 46 | 2 | reserved | 0 |
| 48 | 16 | nic_ip | |
| 64 | 16 | nic_gateway | |
| 80 | 16 | nic_dns | |
| 96 | 2 | off_entity | cephx user id, NUL-terminated string |
| 98 | 2 | off_pool | |
| 100 | 2 | off_namespace | empty in v1 (absent) |
| 102 | 2 | off_image | |
| 104 | 2 | off_image_id | absent unless known |
| 106 | 2 | off_snapshot | absent for head |
| 108 | 2 | off_mons | `mon_count` records of 20 bytes: `{u8 family, u8 reserved, u16 port, u8 ip[16]}` |
| 110 | 2 | off_key | `key_len` bytes, or `0xffff` |
| 112 | 4 | reserved | 0 |

Then: strings (UTF-8, each at most 255 bytes plus the NUL), the monitor records, the key bytes. With three monitors, short names and a 32-byte key, the whole table is about 330 bytes; the **design maximum is 1,024 bytes** and the builder refuses (with a console line) anything larger instead of truncating.

### 9.3 Content rules

- **Always**: identity (entity, monitors, pool, image, mode, flags), the NIC of the first monitor's route: MAC, VLAN, MTU, address, prefix, gateway, DNS (from `tcpip_netdev()` of the first monitor and the settings of that device).
- **The key only on request.** `handoff=key` (or an equivalent explicit setting) sets flag bit1 and the key bytes; the default `nokey` carries everything else, so a leak of the table exposes an image *name*, not a credential. A boot-start driver that needs the key gets it from the table (`handoff=key`) or from another channel (**not designed**; the draft's enrolment-service idea stays a note). The table is readable by **an administrator of the booted OS and by any kernel code**, as the DRAFT said: the mitigation is one cephx user per image with the capabilities of that pool and nothing else, and rotation (`ceph auth rm`), as for a key embedded on boot media (roadmap, milestone 9).
- `handoff=none` installs no table at all (the descriptor is not registered).
- Ticket material instead of the long-term key: not in v1 (cephx tickets are bound to the session key; a driver cannot use them without the exchange).

### 9.4 Rebuilt on every describe pass

`efi_block_describe()` uninstalls all tables it installed earlier and installs again, on every call (`sandev_describe` on hook, and whenever a path is re-described after a reopen); `int13_describe()` zeroes its area and installs again. The model's `install` callback therefore **builds each table from the device's current state and keeps nothing between calls**: monitors, user and names from the session's spec, the NIC from the route and the netdev's settings *at that moment*, the key from the spec. Tested: two consecutive installs produce **byte-identical** tables (a harness unit test of the codec with fixed inputs, and an iPXE self-test over a faked descriptor); after a reopen the table is the same plus whatever changed in the world.

`complete()` returns `-EINPROGRESS` until the image is open and the NIC route is known, so `sandev_describe` waits (the DHCP-not-finished case of the iBFT).

### 9.5 Where the consumer finds it

- **UEFI**: through the ACPI table protocol, in the XSDT: Linux `/sys/firmware/acpi/tables/rBFT` (and `ACPI_SIG` tools such as `acpidump`); Windows: firmware table APIs, **unverified** that a boot-start driver can read an unknown signature this early and that the OEM fields iPXE forces are tolerated.
- **BIOS**: not in an RSDT; in the resident `xbftab` area, found by scanning for the signature and a valid checksum. `XBFTAB_SIZE` 768 would hold the 330-byte typical table but not the 1,024-byte maximum next to an iBFT; patch 0002 makes it 2,048.
- **Read access control**: whether an unprivileged Windows process can read the table through the firmware table APIs (and so see a key) is **unverified**; assume yes (the DRAFT's note stands).

### 9.6 Disk identity

The table does not carry the disk signature or GPT disk GUID: the driver reads them from the image itself (the likely answer of the DRAFT).

---

## 10. Parallelism and readahead

**What the core already does inside one command.** `wr_image_submit` cuts a request at object boundaries and admits up to `max_ops` (16, 14 for data) object operations in parallel, `op_bytes_max` 1 MiB each, `inflight_bytes_max` 4 MiB all together, spread over the OSDs by CRUSH. A 4 MiB SAN command (`max_count` 8,192 blocks, which EFI callers that read big pieces get) therefore runs up to four 1 MiB operations at once, on up to as many OSD connections (the profile has 6). The glue adds nothing there.

**What it cannot do**: BIOS calls are small (section 7), and every caller waits for each command before issuing the next. Hence a **readahead cache** (module `core-readahead`, MIT, pure state machine, tested in the harness against the real engine's simulator):

- A cache of `readahead` KiB in the session block, divided into **lines of 256 KiB** (one object operation each up to the profile's 1 MiB; the line size is a field), tracked by `(offset, state)` where state is EMPTY, PENDING (a `wr_io_req` is in flight into the line), VALID.
- **Sequential detector**: a read that starts where the previous one ended (within one line) twice in a row opens a window; the cache then keeps the next `W` bytes requested: as a demand read is answered, any line of the window that is EMPTY is submitted (up to the profile's in-flight limit, 4 MiB minus the demand request).
- **Hit** (the whole command inside VALID lines): copy and complete in the same step, no network. **Partial / pending**: wait for the pending line (the command's completion is the line's) and copy. **Miss**: the demand read goes **directly into the caller's buffer** (zero copy) and the window logic runs beside it.
- **Writes** invalidate every overlapping line (and the pending ones, whose data is dropped when it lands); a write is never delayed by the cache. `FLUSH`/DISCARD are not exposed by the SAN layer.
- **Failure of a prefetch is silent**: the line goes back to EMPTY; only demand reads report errors.
- Reopen drops the data (the maps stay, section 11). Memory: a window larger than the cache never grows it: it is a ring.
- **Note (close-out):** the measured benefit of this cache depends on the receive window the glue announces to iPXE's TCP. With the core's whole room as the window the cache cost 1 MiB and 4 MiB commands 5 to 7 times; with a window of 64 KiB per connection (`RBD_CONN_RX_WINDOW_MAX`, section 18, R-1) it gains 1.9 times for 127-sector commands, is level at 1 MiB and 0.7 times at 4 MiB (the figures are in 18.3).

What it buys was estimated; it is now **measured** ([ipxe-driver-measurements.md](ipxe-driver-measurements.md), section 3), against `readahead=0` as the baseline: with the default window (2,048 KiB, the whole cache) sequential 127-sector commands are **1.2 times** faster (11.0 against 9.2 MiB/s), 1 MiB commands are **7 times slower** (3.6 against 25.9 MiB/s) and 4 MiB commands 4.8 times slower (6.7 against 32.1). A window of **256 KiB** gives 15.4 / 25.7 / 29.6 MiB/s for 127-sector / 1 MiB / 4 MiB commands, and 512 KiB 20.7 / 18.5 / 27.3: better than none for small commands and level with it for large ones. The default of 2 MiB is therefore **not** supported by the measurements; `readahead=0` stays available, and a smaller default is the finding for the review (the mechanism was not examined: `rbd-info` shows 2,491 waits for 7,089 reads in a default run).

**Not done**: speculative reads of the next *file* (no filesystem knowledge in the driver), and write-back caching (writes are synchronous: the OSD answers after all replicas committed, which is what the OS above assumes of a disk with no write cache).

---

## 11. Reopen after a path failure; cached maps; when a monitor or an OSD is down

**The session outlives the device.** A `struct rbd_session` holds the `wr_client` (maps, tickets, the monitor session), the open `wr_image` and the connection table, reference counted by the devices attached. `sandev_reopen()` closes the block interface (the device drops its reference) and opens the URI again; `rbd_open` finds the session by **identity** (monitor list, user, pool, image, mode) and attaches a new device to it. If the session is healthy the reopen costs one check of the image state and no handshake. A session with no device is kept for **120 s** (a retry timer, `RBD_SESSION_GRACE_MS`), then destroyed with `wr_client_destroy` (keys wiped, arena freed). Two URIs with the same identity share one session; two images in one cluster are two sessions in v1 (one `wr_client` has one monitor session; sharing it across images is a later optimisation, see R5).

**When the glue closes the path itself.** Only on a real failure: the image state is `WR_IMG_FAILED` (blocklisted, header refresh failed, a feature appeared), `WR_EV_FATAL`, or the engine reports the cluster unreachable for longer than `RBD_STALL_CLOSE_MS` (default 30 s) with a command waiting. The close status carries the reason (`-EACCES` for auth and blocklist, `-ENOTCONN` for unreachable...). The SAN layer then reopens (with its 5 s delay) against the cached session, which first reopens the image (`wr_image_close(ABANDON)` + `wr_image_open`) if it failed, or waits for the monitor hunt if it is down.

**Idle gaps.** After `sanboot` hands over, iPXE's main loop runs only inside block commands (EFI: from `EFI_BLOCK_IO` calls; BIOS: from INT 13h). Between commands nothing services the sockets: TCP ACKs and msgr2 keepalives wait for the next command. The Ceph side may close an idle connection; the next command finds it dead and the core reconnects and re-authenticates (tickets are cached; the maps are held) inside that command. The first command after a long idle (a Windows loader that spends seconds decompressing) costs a few round trips, not a failure. **Measured** ([ipxe-driver-measurements.md](ipxe-driver-measurements.md), section 6; an idle gap in the guest, not a paused guest): nothing for gaps up to 120 s; after the daemons closed the connections the first command cost 8 ms to 1.06 s, and about **1.06 s per dead connection** (2.13 s with a 10 s idle timeout), with no error, no resend and no SAN retry.

**A monitor or an OSD down.** All of it is the core's (Phase 1, shown on the lab with a killed OSD, a restarted monitor and `pg-upmap` moves under I/O): operations resend under the same tid after a lost connection or a new map, the engine hunts across monitors with back-off, `WR_EV_IO_STALL` / `RESUME` are informational. The glue's part: a command that has waited longer than the SAN layer's 15 s is cancelled and retried by the SAN layer (up to `san-retries`), and `rbd-info` (a small command of the glue) prints the engine's counters (`wr_client_osd_stats`, `wr_stats`) for the test logs.

---

## 12. Status and error mapping

`rbd_rc()` (`rbd_errors.c`) maps a `wr_status` to an iPXE error code. The mapping is many to one: the SAN layer decides only success or failure, iPXE prints the errno text, and the useful detail travels on the **console line** printed once where an open fails (`rbd: <what> failed: <core text> (<WR_E_NAME>)`), never from a hot path, never with the URI or key.

| iPXE code | Core statuses |
|---|---|
| `-EINVAL` | `WR_E_INVAL`, `ENCODING`, `RANGE`, `TOOBIG`, `RBD_BAD_ID` |
| `-ENOMEM` | `WR_E_BUDGET`, `MAP_BUDGET` |
| `-ENOTSUP` | `WR_E_UNSUPPORTED`, map / monitor / OSD version, pool and CRUSH unsupported, `OSD_REDIRECT`, `RBD_FEATURES`, `STRIPING`, `PARENT`, `ORDER` |
| `-ETIMEDOUT` | `WR_E_TIMEOUT`, `M2_HANDSHAKE_TIMEOUT` |
| `-ENETUNREACH` / `-ECONNRESET` | `NET_CONNECT`, `MON_UNREACHABLE` / `NET_CLOSED` |
| `-EACCES` | `AUTH_DENIED`, `AUTH_DECRYPT`, `AUTH_KEY_TYPE`, `AUTH_RESULT`, `OSD_PERM`, `OSD_BLOCKLISTED` |
| `-ENOENT` | `POOL_NOT_FOUND`, `RBD_NOT_FOUND`, `OSD_NOENT` |
| `-ENOSPC` / `-EROFS` / `-EBUSY` | `OSD_NOSPC` / `RBD_READONLY` / `BUSY`, `RBD_LOCKED` |
| `-ECANCELED` | `WR_E_CANCELLED` |
| `-ENODEV` | `WR_E_HOST_RANDOM` |
| `-EPROTO` | every protocol or integrity failure (msgr2, cephx, OSD, RBD replies, `OSD_IO`) |

No iPXE-specific `EINFO` codes are defined in v1 (they need `ERRFILE_` entries and bring nothing the console line does not).

---

## 13. `FILE_SECBOOT`, licences, and the licence check

**`FILE_SECBOOT` (D9).** `compiler.h` says files not marked `FILE_SECBOOT ( PERMITTED )` are excluded from UEFI Secure Boot signed builds, and that a third-party contribution may only be marked permitted after an approved security review. The driver parses data from the network (Ceph servers, and anything in between) before any operating system exists and before any later stage can distrust it; the core is about 30 kLOC the iPXE maintainers have not reviewed. **Every file is `FILE_SECBOOT ( FORBIDDEN )`**: the glue by hand, the core by the import transform. There is no file whose status is a candidate for `PERMITTED`: a file that is logically harmless (`rbd_errors.c`, a header) is still linked only into builds that contain the rest. Consequence, intended: `bin-x86_64-efi-sb/ipxe.efi` (the Secure Boot build target of iPXE: `make SECUREBOOT=1` or the `-sb` directory) **fails with "not permitted to be signed for UEFI Secure Boot"** when the option `SANBOOT_PROTO_RBD` is on; a Secure Boot deployment signs its own build and is outside this project's scope. The explicit declaration means the failure names the cause instead of "missing FILE_SECBOOT declaration". CI builds one `-sb` target (`bin-x86_64-efi-sb/snponly.efi`) and asserts that exact failure, so a file that someone marks `PERMITTED` without review is seen.

**Licences (D10).** Glue: `FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )`, text of the iPXE files. Core files: `FILE_LICENCE ( MIT )` by the transform. `core/crush_ln/` (LGPL-2.1-only, the CRUSH log tables copied from Ceph): `FILE_LICENCE ( GPL2_OR_LATER )`, since iPXE has no LGPL tag and LGPL-2.1 section 3 lets the files be used under the GPL. `util/licence.pl` combines the licences of every linked object into the licence of the binary: a build that contains `crush_ln` **can only be distributed under the GPL (version 2 or later), not under the UBDL**, because the UBDL requires every file to allow it and an LGPL-only file does not. `README.md` used to say "so the UBDL option is kept": that holds for the glue and the rest of the core, **not for a binary that links the CRUSH tables, which the driver always does**. **Note (close-out):** README.md and `ipxe/README.md` now say so (a binary with the driver is GPL-2.0-or-later only); the real run of `make bin/<target>.licence` is the arbiter. It was run on real builds of `bin/undionly.kpxe`, `bin-i386-pcbios/undionly.kpxe` and `bin-x86_64-efi/snponly.efi` (the all-driver images fail the check on the pristine tree too, section 3) and reports "GPL version 2 (or, at your option, any later version)" with the MIT files listed as subsumed; no file of the driver or the core is missing a tag, and every driver object carries `__secboot__forbidden__` (122 objects; the build-box check counts them, and the Secure Boot target is refused with "not permitted to be signed for UEFI Secure Boot"). The harness and CI treat the licence run's output as a test expectation (`GPL (version 2 or later)`), so a change in it is a visible event.

---

## 14. Test plan

### 14.1 The live path: how QEMU guests reach a cluster (D11)

Constraints: the main lab cluster's monitor is `10.77.0.10:3300` **inside** the lab VM, which is not routable from the build box; the OSD addresses are *learned from the OSD map* (the guest must be able to reach every address the map advertises); until the completion marker of the Phase 1 exit run exists, that run (8 hours) owns the main lab (no cluster changes, no daemon restarts, no heavy CPU or I/O); on the build box only user-mode networking and 127.0.0.1 forwards are allowed, no bridge, tap or host network change.

Options weighed:

| Option | Reaches all OSD addresses | Speed | Independent of the Phase 1 run | Honest proof |
|---|---|---|---|---|
| A. QEMU (TCG) **inside the main lab VM**, user-mode NAT | yes: the guest's connections to `10.77.0.x` are made by QEMU from the VM itself | slow (no KVM: minutes per boot; a Windows boot much more) | **no**: needs the exit run to be finished, and apt installs and CPU in the lab VM | yes, but heavy and slow |
| B. Userspace relay from the build box through the jump hosts + `guestfwd` for the monitor and every OSD address | only if every address in the map is enumerated; breaks when the map changes (OSD restart = new address nonce / port) | KVM | no: boots read hundreds of MB through ssh | partly (the relay changes timing and hides connection resets) |
| **C. A dedicated Ceph lab VM on the build box + the guests on its private layer 2** | **yes: same L2, same addresses, no NAT** | KVM everywhere | **yes** | **yes**: real mon, real OSDs, real v20.2.5, real firmware |

**Decision: C.** `harness/lab/make-vm.sh`, `guest-packages.sh`, `bootstrap-ceph.sh` and `krbd-compat.sh` already build the lab on any KVM host, with a second NIC on a **private multicast layer 2 made by QEMU itself** (`-netdev socket,mcast=<group>,localaddr=127.0.0.1`): no bridge, no tap, no route, no firewall rule, nothing on the host network. Run it on the build box under one directory of its own (`LAB_DIR`, nothing else of the box is touched) with its own SSH port, SSH port, multicast group and MAC addresses (8 GiB, 4 vCPU, three sparse 12 GiB OSD disks). Every test guest gets **two NICs**: NIC 1 user-mode (slirp) for the PXE bootfile (`tftp=`, `bootfile=`) and DHCP; NIC 2 on the lab's multicast group with a static address in `10.77.0.0/24` (set by the embedded script; iPXE routes `10.77.0.10` by subnet to the right device). The ssh forward and QEMU's mcast socket live on 127.0.0.1 only. CPU budget (24 cores in total for the workflow at any time): the lab 4, a build VM 8, one test guest 2 to 4.

Two more reasons for C: the tests of milestone 7 kill and restart monitors and OSDs, which the main lab's rules allow only after the exit run and only with a restore; on a throwaway cluster nobody has to restore anything. And a single-image boot reads on the order of a gigabyte, which is not "no heavy I/O" for the main cluster while the exit run owns it.

**Cross-check on the main lab** (after the exit run, optional, its run directory left alone): the same binary, the same scripts, QEMU TCG inside the lab VM (Option A) for one Linux boot per firmware, and the digest of the image as read through the SAN layer compared with `rbd export`. It proves nothing new about the driver; it proves the driver against the cluster that Phase 1 was proved on.

**Keys.** One throwaway cephx user per test image, created for the run and deleted afterwards. Because the Linux guest's kernel client (krbd, used by the initramfs to keep the root on the image after the firmware is gone, section 14.3) cannot use the 32-byte `aes256k` keys (`libceph: secret too big 32`), the boot tests use a legacy-`aes` user on the lab VM prepared by `krbd-compat.sh`; the iPXE side takes either. No key is ever printed or committed; the boot script is generated per run into a scratch directory.

### 14.2 What is tested where

| Layer | Where | What |
|---|---|---|
| Core additions (handoff codec, URL parser, readahead) | harness, ctest: gcc and clang, plain and ASan/UBSan, Debug / Release / MinSizeRel; warning-free on the 26.04 guest (gcc 15.2, clang 21); libFuzzer targets with replayed seeds | golden vectors, round trips, truncation and bit-flip rejection, byte-identical rebuild, readahead against the simulated cluster and the model |
| Core gates | existing ctest gates | `core_no_libc`, `core_no_globals`, `core_freestanding*`, call-graph stack budgets (i386 entries added), footprint (`core.budgets`) |
| Glue builds | `ipxe/tools/build.sh` on the build box (gcc 11.4) and in the 26.04 guest (gcc 15), CI job `ipxe` | `bin-x86_64-efi/ipxe.efi`, `bin/undionly.kpxe`, `bin/ipxe.pxe`, `bin/ipxe.usb`, `bin/ipxe.iso` (these BIOS images are **64-bit**: `bin/` is iPXE's `DEFAULT_ARCH`) and the same four in `bin-i386-pcbios/` (the 32-bit BIOS images: 4 KiB stack, the core on its own stack; **added by the close-out review**, R-6), each with iPXE's own `-Werror` and **no warnings**; `make bin/<target>.licence` on `bin/undionly.kpxe`, `bin-i386-pcbios/undionly.kpxe` and `bin-x86_64-efi/snponly.efi` (the all-driver images fail upstream's own check, section 3); one `-sb` target must fail with the SECBOOT message and every driver object must carry `__secboot__forbidden__`; link-map check that the driver is linked and no self-test is (and, for `ipxe.efi`, the `rbd` scheme and the console line in its bytes) |
| Glue logic without a network | iPXE self-tests (`src/tests/*_test.c`, `__self_test`, wired by patch 0003) built into `bin-x86_64-linux/tests.linux` and `bin-i386-linux/tests.linux` (run as Linux programs, no QEMU), plain and with UBSan in trap mode (`build.sh test -u`) and with a negative control (`test -n`): iPXE's own 12,448 tests plus 72,520 of the driver's eight files (`ipxe/tests/README.md`) | URI + settings -> spec, the handoff table over a faked descriptor, status mapping, the connection table's state machine with a fake socket |
| The whole driver | QEMU on the build box against the dedicated lab VM | the matrix of 14.3 |

### 14.3 The QEMU matrix (the live tests)

Guest images live on RBD images of the lab VM (2 GiB, disposable). **Linux guests** are Ubuntu-based, built in a throwaway builder VM (sudo, loop devices): UEFI = GPT with an ESP (grub removable path) and an ext4 root; BIOS = MBR with grub-pc. Their initramfs has a hook that (1) reads the `rBFT` table (UEFI: `/sys/firmware/acpi/tables/rBFT`; BIOS: a scan helper over low memory), (2) **checks every field against the expected values** of the test's configuration (this *is* "the table matches the design"), (3) brings the NIC up from the table, (4) maps the image with krbd and mounts the root from it. A boot that reaches a login prompt with `/` on `/dev/rbd0p<N>` proved: firmware reads the image through our SAN device (ESP, grub, kernel, initramfs), the table is visible and right, and the OS can continue after iPXE is gone.

| Row | Firmware | iPXE binary | Delivered by | OS image | Needs |
|---|---|---|---|---|---|
| U0 | OVMF | `ipxe.efi` | PXE; the script runs `sanhook` and leaves to the UEFI shell | Linux GPT | lab VM; roadmap milestone 4: `map -r` lists the block device and its partitions, `ls` reads the ESP |
| U1 | OVMF (Secure Boot off) | `ipxe.efi` | PXE (OVMF's network stack, slirp `tftp=` + `bootfile=`) | Linux GPT | lab VM |
| U2 | OVMF | `ipxe.efi` as `EFI/BOOT/BOOTX64.EFI` | USB stick image (GPT + FAT) | Linux GPT | lab VM |
| B0 | SeaBIOS | `undionly.kpxe` | PXE; the script runs `sanhook --drive 0x81` and boots a small local disk | local Linux (any) | lab VM; roadmap milestone 8: the hooked drive is visible to the BIOS (`/sys/firmware/edd/int13_dev81` in the guest) and the handoff table is found by the scan |
| B1 | SeaBIOS | `undionly.kpxe` | PXE (QEMU's PXE option ROM, `tftp=`) | Linux MBR | lab VM |
| B2 | SeaBIOS | `ipxe.usb` | USB stick (`dd`) | Linux MBR | lab VM |
| B3 | SeaBIOS | `ipxe.iso` | CD-ROM | Linux MBR | lab VM, `mtools` + `xorriso` + `syslinux` |
| U3 | OVMF | `ipxe.iso` (EFI El Torito if the build has it) | CD-ROM | Linux GPT | as above |
| W1 to W4 | OVMF / SeaBIOS | as U1/U2, B1/B2 | PXE / USB | **WinPE** (GPT / MBR) | **a WinPE image from the owner** |

Each row also records: bytes read, time to the kernel, time to login, the iPXE stack and heap watermarks, `rbd-info` counters. Robustness rows (milestone 7), run on U1 and B1: (a) kill and restart the monitor during the kernel load; (b) kill one OSD during the ESP read; (c) pause the guest 60 s between two commands and resume (the idle-gap case); (d) block the guest's NIC 2 for 40 s (QEMU `set_link`) so the SAN layer's reopen runs against the cached session; (e) wrong key, wrong pool, wrong image, unreachable monitor: each fails with its one console line and the right errno, with the SAN layer retrying and then giving up. The byte-level proof: after a boot, the image is read **through the SAN layer in the guest firmware shell** (`dd`-like read loop in the iPXE script over `sanhook` + `md5` of fixed ranges, no OS) and compared with `rbd export` of the same ranges.

**WinPE rows W1 to W4 run on the owner's images.** WinPE cannot be built on Linux here, and there is no legal, redistributable way to obtain one: it ships in the Windows ADK and in Windows installation media, whose licences do not allow this project to redistribute them, and the official download pages are interactive. This project does **not** fetch Windows media from anywhere. The owner built images with the ADK on a Windows test machine (a UEFI / GPT disk, a BIOS / MBR disk and an ISO) and put them on the build machine, outside the repository; they are never committed or published. Their `startnet.cmd` runs `wpeinit`, makes `serial.sys` name the port COM1 and writes `WINRBD-WINPE-OK` there, so **a serial log that contains that line is a WinPE that booted** (the first matrix, which ran on earlier images that never reached the serial port, judged the rows by screenshots). What is prepared (module `winpe-prep`): the layouts for UEFI (GPT, FAT32 ESP with `EFI/BOOT/bootx64.efi`, `EFI/Microsoft/Boot/BCD`, `sources/boot.wim`) and BIOS (MBR, active FAT32 partition, `bootmgr`, `boot/BCD`, `sources/boot.wim`), a script that converts the owner's disk to a raw image, **checks the layout before the run** and imports it into an RBD image with the `layering` feature only (the writer profile refuses the default features, and says which, R-5) and a snapshot `pristine`, which every row rolls back to. The rows boot that image with the default `vendor` device path.

### 14.4 Exit measurements

Throughput against the kernel client on the same image and cluster (sequential 1 MiB reads, 64 KiB reads as INT 13h issues them, with `readahead=0` and the default), time-to-login per row, stack watermark on BIOS, heap watermark on both, the footprint of `ipxe.efi` and `undionly.kpxe` with and without the driver. Reported in [ipxe-driver-measurements.md](ipxe-driver-measurements.md), not asserted, except the budgets of section 5 (which have a pass or fail line there).

---

## 15. The exit criteria, clause by clause

The criteria (`docs/ROADMAP.md`, Phase 2): *"In QEMU with OVMF (Secure Boot off) and in QEMU with SeaBIOS, the VM boots a Linux and a WinPE image over `rbd://`, both via PXE and from an iPXE USB image; the handoff table appears in the guest and matches the design."*

| Clause | Shown by | State at the end of Phase 2 |
|---|---|---|
| "QEMU with OVMF (Secure Boot off)" | rows U0, U1, U2 (Linux), W1, W2 (WinPE) | **shown**: Linux rows U0 to U3 on the final binaries; WinPE rows W1 and W2 on the owner's images (section 18.3) |
| "QEMU with SeaBIOS" | rows B0, B1, B2 (Linux), W3, W4 (WinPE) | **shown**: B0 to B3 (32-bit images, and B1 with the 64-bit image), W3 and W4 on the owner's images |
| "boots a Linux ... image over `rbd://`" | the four Linux rows, root on the image through the table | **shown**, root on `/dev/rbd0p2` (GPT) and `/dev/rbd0p1` (MBR) |
| "... and a WinPE image" | the four WinPE rows | **shown on the owner's images** (two or three runs per row, no failed run): the boot manager loads `boot.wim` through the driver and WinPE writes its marker; what Windows does with the disk afterwards is not shown (Phase 3) |
| "both via PXE" | U1, B1, W1, W3 | |
| "and from an iPXE USB image" | U2, B2, W2, W4 (`ipxe.usb` for BIOS, `BOOTX64.EFI` on a USB stick for UEFI) | |
| "the handoff table appears in the guest" | the initramfs hook reads `/sys/firmware/acpi/tables/rBFT` (UEFI) or finds it by scan (BIOS), and the guest's `acpidump`-style output is stored with the run | |
| "and matches the design" | the hook compares **every field** with the expected values of the test configuration; the harness codec round-trips the same bytes against the golden vectors; `docs/design/handoff-table.md` is v1 | |

The milestones of the roadmap map to modules (section 17): 1 to `ipxe-uri` + `ipxe-driver-core` + `ipxe-conn` (and `tools/build.sh`, done in the skeleton), 2 to `ipxe-driver-core` + `core-readahead`, 3 to `ipxe-efi`, 4 to `qemu-uefi` (row U0), 5 to `linux-images` + `qemu-uefi` + `qemu-bios` (the WinPE part ran on the owner's image; `winpe-prep` prepared it), 6 to `core-handoff` + `ipxe-acpi`, 7 to `ipxe-driver-core` + `qemu-robust`, 8 to `ipxe-bios` + `qemu-bios` (row B0), 9 to `qemu-scripts` (the media) + the rows U2, B2, B3. The deliverables: `ipxe/` files and patches (this skeleton and its modules), build instructions pinned to the submodule revision (`ipxe/PINNED`, `ipxe/README.md`), QEMU run scripts (`qemu-scripts`), the handoff spec promoted to v1 (`core-handoff`).

---

## 16. Risks and open questions

| # | Risk or question | Status |
|---|---|---|
| R1 | Heap headroom next to iPXE's own users (the core architecture's R1) | **measured**: `malloc()` heap maximum 601 kB (BIOS, reading 128 MiB) and 374 kB (UEFI boot) of 4,096 KiB, against 103 to 128 kB with nothing hooked: headroom at least 3.4 MiB ([ipxe-driver-measurements.md](ipxe-driver-measurements.md), sections 5 and 9) |
| R2 | **i386 BIOS stack** (4,096 bytes; the core alone needs 2,632) | **measured**: iPXE's stack 2,772 bytes high-water (1,324 left) with the core on its own stack (1,696 of 16,384); the margin without the trampoline would be negative, so the trampoline is needed; the budget (margin of at least 300 bytes) holds ([ipxe-driver-measurements.md](ipxe-driver-measurements.md), section 5) |
| R3 | `bootmgr` / `winload` and the EFI device path shape; Windows on BIOS through INT 13h with no `edd_describe` | **partly verified**: the owner's WinPE images (UEFI/GPT and BIOS/MBR) booted to the `wpeinit` marker through the driver in all four rows (PXE and USB stick, two or three runs each, [ipxe-driver-measurements.md](ipxe-driver-measurements.md), section 4) with the default `vendor` path shape on UEFI and no `edd_describe` on BIOS, and W1 also with the `uri` and `sata` shapes on the current images (section 18.4); **unverified**: an installed Windows (WinPE runs from a RAM disk that the boot manager loaded: what Windows does with the SAN disk after the boot manager is not exercised) |
| R4 | The `rBFT` signature against Microsoft's reserved list; whether a boot-start driver can read an unknown ACPI signature and tolerates iPXE's forced OEM fields; whether an unprivileged process can read it | **unverified**; the signature was checked against the iPXE tree and ACPICA's list only |
| R5 | One session per image (two images of one cluster = two monitor sessions) | accepted in v1; sharing the client is a later change in the core's image layer, not in the glue |
| R6 | iPXE's TCP sends one packet per RTT: write throughput about MTU / RTT | **measured**: one 1,208-byte segment in flight, 1.3 to 1.5 MiB/s for large writes at 0.55 ms, 0.11 MiB/s at +10 ms; operations are resent from +1 ms and write commands fail from +3 ms (4 MiB) / +10 ms (1 MiB) because the transfer outlasts the 5 s operation timeout; boot is read-dominated; not fixable in this driver ([ipxe-driver-measurements.md](ipxe-driver-measurements.md), section 7) |
| R7 | The SAN layer does not set `Media.ReadOnly` and exposes no flush or discard | accepted; documented |
| R8 | Idle gaps: nothing services the sockets between commands | handled by reconnect-in-command; **measured**: no cost for gaps up to 120 s; after 960 s (past the daemons' 900 s idle timeout) the first command cost 8 ms to 1.06 s, and with a 10 s idle timeout 2.13 s once, about 1.06 s per dead connection; no error reaches the caller, the operation is sent again on the new connection (0 resent with the default timeout, 8 or 9 per run with a 10 s timeout) ([ipxe-driver-measurements.md](ipxe-driver-measurements.md), section 6) |
| R9 | Readahead's benefit is an estimate | **measured**: 1.2 times for 127-sector commands, a loss of 4.8 to 7 times for 1 MiB and 4 MiB commands at the default window; 256 KiB is the best compromise of the windows tried (two runs per size; 512 KiB is better for 127-sector commands) ([ipxe-driver-measurements.md](ipxe-driver-measurements.md), section 3) **Note (close-out):** re-measured after the receive window was capped (R-1): the default window now gains 1.9 times for 127-sector commands, is level at 1 MiB and 0.7 times at 4 MiB; the earlier loss was the window, not readahead. |
| R10 | `umalloc` on a BIOS machine with little extended memory; the heap's behaviour after hundreds of boots in one session of a long-lived iPXE | **measured**: 12 MiB of guest RAM opens the image, 10 MiB fails with `-ENOMEM` and the line that says how many bytes were wanted (5,013,504); 153 hooks in one session and 5 sessions created and destroyed in a 20 MiB guest all succeed, and the heap maximum does not grow (131 kB after 150 hooks) ([ipxe-driver-measurements.md](ipxe-driver-measurements.md), section 8) |
| R11 | The licence of a binary that includes the CRUSH tables is GPL2+ only (13) | **resolved**: README.md, `ipxe/README.md` and section 13 say so; `build.sh licence` and CI make a change of the verdict a visible event |
| R12 | `wall_ms = 0` on writes (mtime): whether the OSDs accept it | **resolved**: the write rows of the measurements ran with the clock the platform has (a BIOS RTC read every 60 s, extrapolated from the monotonic clock in between) and every written byte was verified; the glue passes `time(NULL)` when the platform has a clock |
| R13 | UEFI USB-stick and ISO media for `ipxe.efi` need `mtools`, `xorriso`, `syslinux` on the build host | CI installs them; the build box builds the ISO in a 26.04 guest |
| R14 | gcc 15 defaults to C23 (`-std=gnu23`) and iPXE sets no `-std`, so the core is compiled as C23 inside the iPXE build, not as C99 | the 107 core files compile clean with `-std=gnu2x -Wall -Wextra -Werror` on gcc 11 (checked); the real check is the build in the 26.04 guest (module `build-vm`) |
| R15 | **iPXE's TCP queues out-of-order data inside the window it announced, in I/O buffers of the 4 MiB heap; the core's receive window is a whole data segment (up to 4 MiB)** | **found by the close-out review (R-1, section 18), fixed**: at most 64 KiB announced per connection (`RBD_CONN_RX_WINDOW_MAX`); with it the default readahead is no longer a loss for large commands (R9); the heap exhaustion itself was not reproduced under 2 % and 8 % loss |
| R16 | `bin/` is iPXE's `DEFAULT_ARCH` (x86_64): the documented BIOS targets are 64-bit images, the 32-bit ones (4 KiB stack, the core on its own stack) are `bin-i386-pcbios/` | **found by the BIOS rows (finding F1 of `results/bios`), closed by the review (R-6)**: both are built by CI and the builder gate and both were booted in QEMU |
| R17 | `undionly.kpxe` followed by `exit` with a drive hooked: the PXE ROM stops the network stack the hooked drive still uses | **known, documented, warned at exit**; use `sanboot` or `ipxe.pxe`; not a driver defect |
| R18 | The default readahead window (2 MiB) loses for large commands (section 3 of the measurements) | **resolved by R-1**: re-measured with the capped receive window, the default is 16.4 / 18.4 / 18.5 MiB/s (127 sectors / 1 MiB / 4 MiB) against 8.8 / 18.3 / 25.7 without readahead; the default stays; 4 MiB commands remain 0.7 times slower than without readahead (two runs), which no boot loader measured so far issues |
| Q1 | Should `devpath` default to `vendor`? | **answered for WinPE**: `vendor` boots it (61 and 63 s), so does `uri` (70 s) and `sata` (95 s) on the owner's current images; the default stays `vendor`; an installed Windows (`winload`) is unverified |
| Q2 | Should hostnames be accepted (iPXE's resolver)? | no in v1; literals only; a module can add it without touching the core |

---

## 17. Implementation plan: waves of modules

**Note (close-out):** all eight waves were run (and the interrupted ones re-run); this section is kept as the record of the plan. Section 18 is wave 8.

Modules in a wave touch **disjoint files**; a wave may start when the modules it depends on are finished and reviewed. Rules for every module: implement, unit test (harness for core modules; the build and the live matrix for glue modules), adversarial review, fix. Shared files have one owner per wave: `ipxe/src/rbd_priv.h` is frozen in waves 1 and 2 (changes go through the orchestrator) and belongs to `ipxe-driver-core` in wave 3 (other modules put their private declarations in their own `rbd_<module>.h` and ask for changes to the shared header); `core/sources.txt` is **regenerated by the orchestrator after a wave** (`core/tools/gen_sources.sh`; a module runs it only in its own scratch copy); `harness/CMakeLists.txt` is not edited by a module whose tests the existing globs pick up. The gates stay green: `core_no_libc`, `core_no_globals`, `core_freestanding*`, the call-graph budgets, the iPXE-flag and 32-bit compiles, and the build of `ipxe/` (a core change must not break the iPXE build, which has its own `-Werror` and its own `<stdint.h>`).

| Wave | Modules | Needs |
|---|---|---|
| 1 | `core-handoff`, `core-rburl`, `core-readahead`, `ipxe-testbed`, `lab-cluster`, `build-vm` | nothing (the two lab modules are the long lead: a VM and a Ceph bootstrap) |
| 2 | `ipxe-conn`, `ipxe-efi`, `ipxe-uri`, `ipxe-acpi`, `linux-images`, `qemu-scripts`, `winpe-prep` | `ipxe-testbed` (self-tests), `core-rburl`, `core-handoff`, `lab-cluster`, `build-vm` as each names them |
| 3 | `ipxe-driver-core` (session, block, stack watermark), `ipxe-ci`, `harness-gates` | the glue of wave 2, `core-readahead` |
| 4 | `qemu-uefi`, `qemu-bios` | everything above; separate images, so they may run side by side |
| 5 | `ipxe-bios` | the BIOS measurements of wave 4 (stack, tables, `edd_describe` if needed) |
| 6 | `qemu-robust` | wave 5 (it kills monitors and OSDs: nothing else may run on that lab) |
| 7 | `measure` | wave 6 (a quiet cluster) |
| 8 | `p2-review` | all: whole-driver adversarial review, fixes, documentation close-out |

The module list with files, dependencies, tasks and tests is returned with this design (the plan the orchestrator runs); the one-line summary of each:

- **Wave 1.** `core-handoff` (MIT): the v1 codec of section 9 in `core/` with golden vectors, byte-identical rebuild, a fuzz target, and the promoted `docs/design/handoff-table.md`. `core-rburl` (MIT): the URL and option parser of section 8 over plain strings. `core-readahead` (MIT): the cache state machine of section 10 over host memory, tested against the simulated cluster. `ipxe-testbed`: the iPXE self-test wiring (a patch that requires the test objects, `ipxe/tests/`, `bin-x86_64-linux/tests.linux` in `build.sh` and CI) so every later glue module ships a test that runs without QEMU. `lab-cluster`: the dedicated lab VM of section 14.1. `build-vm`: the 26.04 builder (gcc 15, clang 21, ISO tools).
- **Wave 2.** `ipxe-conn` (the pump host of section 4), `ipxe-efi` (the three device-path shapes of section 6), `ipxe-uri` (opener, settings, spec), `ipxe-acpi` (the model and the idempotent install), `linux-images` (UEFI and BIOS Linux guests with the table-checking, krbd-root initramfs), `qemu-scripts` (command lines, boot script generator, USB and ISO media), `winpe-prep` (layout, import and check scripts for the owner's WinPE image).
- **Wave 3.** `ipxe-driver-core` (the session and the block device together, because they are one state machine: memory, process, image, reopen cache, commands, synchronous cancel, readahead hookup, watermarks, `rbd-info`), `ipxe-ci` (the CI job completed: ISO, licence, Secure Boot refusal, self-tests), `harness-gates` (i386 call-graph entries, documentation checks for the new core modules).
- **Waves 4 to 7.** The live matrix of 14.3, the BIOS findings (stack, tables, `edd_describe`), the robustness rows, the measurements of 14.4.
- **Wave 8.** The review and the close-out: ROADMAP, READMEs, this document's "not measured" notes replaced by the measurements.

---

## 18. Close-out: the whole-driver review, what the live matrix showed, what is open

Written when Phase 2 was closed out (module `p2-review`). Sections 1 to 17 are the design and the plan; this one is what was found when the finished driver was read adversarially, built, run in QEMU against a real cluster and run again after the fixes. Every number below was read from a log on the build machine; the evidence of the final matrix is in `harness/lab/p2/results/final/`.

### 18.1 What was reviewed, and what held

The glue (`ipxe/src`, about 6,600 lines) was read against iPXE's interfaces in the pinned tree (`tcp.c`, `xfer.c`, `interface.c`, `sanboot.c`, `int13.c`, `efi_block.c`, `iscsi.c`, `aoe.c`, `malloc.c`) and against the core's contracts. The questions, and the answers:

| Question | Answer |
|---|---|
| Every parser of untrusted text (URI, settings, the monitor list, option values, device path nodes, the BIOS table scan, the handoff table) | Bounded, length-checked, fail closed; the opener never prints the URI or a key. The core's parser (`core/src/rburl`) owns the grammar, the glue owns only the translation of iPXE's `struct uri` (authority rebuilt from host and port, which iPXE splits at the last colon). One defect: the text of the URI for the `uri` device path was never handed over (R-2) |
| Receive: `xfer_deliver`, window accounting, backlog | The backlog is bounded by the window announced, a buffer the core cannot take is parked in order, a deliver on a dead slot frees the buffer and returns an error. One defect: the window announced was the core's whole room (R-1) |
| Transmit with partial acceptance | One packet at a time of `min(window, pending)`, copied out of the core's gather list, consumed only after the socket took it; a failed allocation retries without an event; the slot is checked again after every call into the socket (it may have closed synchronously). No defect |
| Command lifetime and reference counts on every close order | A command is held by the SAN layer's interface, the session's list and its creator; completion never happens inside the call that started it; the SAN layer closing it, the device closing, the session failing and the session being destroyed each stop it exactly once. 90 randomised interleavings plus targeted tests of every order. No defect |
| Synchronous cancel and ownership of the SAN layer's buffer | `intf_close` of a command returns only when the core has handed the request back (a bounded loop of core runs with no network service); when it never does the session is destroyed first (the core is gone before the buffer is released). No defect |
| Session grace, reopen, identity | A session outlives its device for 120 s; the identity includes a fingerprint of the key; a device found by identity gets the cached maps; the stall rule (30 s) only acts while a command waits. No defect |
| ACPI table builder bounds | The codec refuses over 1,024 bytes and never truncates; the glue's copy of the monitors is bounded by a compile-time assertion; the table is rebuilt from current state on every describe pass; the work object is wiped. No defect |
| EFI device path node lengths | Names use the opener's character set; every length is checked before a byte is written; a buffer one byte too small writes nothing. No defect (a latent one was fixed by the `ipxe-efi` review) |
| `lba * blksize`, `count * blksize` on i386 | `lba < blocks` and `count <= 8,192` are checked before the multiplication, which is in 64 bits (`uint64_t`) for the offset and `count * 512` at most 4 MiB in `size_t`. No defect |
| 64-bit division on i386 | None in the glue except by the constant 512 (a shift) and the millisecond conversion, which is written in 32-bit quotient and remainder. The core's 64-bit arithmetic links through iPXE's own `libgcc`. All seven i386 and x86_64 BIOS targets link |
| `malloc` / `umalloc` failure paths | Every allocation of the open path (spec, work area, URI text, identity, session, devices, commands, I/O buffers, the ACPI work object) has a tested failure path that leaves nothing behind (heap walks in `rbd_uri_test`, `rbd_session_test`, `rbd_block_test`); an `umalloc` failure prints how many bytes it wanted |
| Key wiping on every exit | The spec and the parse work area are wiped on every path of the opener, the creation scratch right after the core copied the key, the session's copy when the last device that asked for `handoff=key` lets go and at destroy, the ACPI work object after the install, the core's private stack at destroy; heap walks after every outcome find no byte of the decoded key |
| Stack at every call chain | The call-graph gates (`callgraph_ipxe.sh`: every core entry point the glue calls, with its worst chain, on i386 and x86_64) and the measurement: i386 BIOS 2,784 of 4,096 bytes for iPXE and the glue with the core on its own 16 KiB stack (1,696 used), x86_64 BIOS 5,608 of 8,192 (2,584 left; the monitor works there since R-4) |
| Hidden global state | Only: the list of sessions (`rbd_sessions`, the registry), the model of the handoff table (`rbd_model`, iPXE's pattern), the `rbd-info` scratch, and the stack watermark of the test builds. None of them holds a secret |
| Copied code | None found: no Linux libceph / rbd and no Ceph code in `ipxe/` (the structures follow iPXE's `iscsi.c`, `aoe.c` and `ata.c`, credited in the files that do). The patches are derived from iPXE files and carry their licence |
| Licence run, `FILE_SECBOOT` | `make bin/<target>.licence` on real builds of the three images without NIC drivers: GPL version 2 or later, MIT files subsumed; a Secure Boot build is refused with the expected sentence; 122 driver objects carry `__secboot__forbidden__`; no file claims `PERMITTED` |
| Secrets in logs | Every `printf` and `DBGC` of the glue read: none prints a URI, a user's key, a monitor or a payload; the run scripts scan every console for the key (exit status 4 and the log discarded) and none was found in any row |

### 18.2 Findings of the review, with the fix and the test

| ID | Severity | Finding | Fix | Test |
|---|---|---|---|---|
| R-1 | high | **The receive window announced to iPXE's TCP was the core's whole room**: the remaining bytes of a data reply, up to 4 MiB, which iPXE's TCP announces up to its own 2 MiB maximum and in which it queues every out-of-order segment as an I/O buffer of its **4 MiB heap** (`tcp_rx_enqueue`). **Measured effect** (the 32-bit BIOS read bench of `results/measure`, the four windows run one after the other on the same day and cluster, `results/final`): with the default readahead, commands of 1 MiB and 4 MiB ran at 4.4 and 8.6 MiB/s with a window of 4 MiB, 4.3 and 9.9 with 256 KiB, 4.5 and 10.0 with 128 KiB, and **18.4 and 18.5 with 64 KiB**; the one disturbed run of the 4 MiB window had 3 session resets and a SAN-layer cancel (the first measurements' `rd-def-3` had 11). The "readahead loses 5 to 7 times for large commands" that the measurements reported as a property of readahead **was this window**. The price: without readahead the cap lowers large-command throughput (1 MiB / 4 MiB commands 29 / 33 MiB/s at 128 KiB, 23 / 28 at 4 MiB, 18 / 26 at 64 KiB; two runs each, the spread is large); a boot loader's small commands gain (127 sectors: 16.4 MiB/s with readahead against 8.8 without). **What was not shown:** the heap exhaustion the source allows was not reproduced: with 2 % and 8 % loss on the replies the old window booted as often and as fast as the new one (login at 76 to 88 s against 75 to 97 s at 2 %; 137 s against 133 s at 8 %) and the heap probe found 2 MiB free throughout, so the failed boots of the first matrix (findings F1 and F5 of `results/uefi`) are **not** explained by this finding | `RBD_CONN_RX_WINDOW_MAX` = 64 KiB per connection (a build option, so each window can be built again for an A/B) | `rbd_conn_test`: a room of 4 MiB, 64 KiB + 1 and 64 KiB is announced as 64 KiB, a smaller room as it is, the backlog is bounded by the cap. Live: the read bench and the loss rows above |
| R-2 | high | `devpath=uri` could never work: the opener never put the URI in the specification, so the device path node had nothing to carry and the SAN hook failed with "cannot build the EFI device path" (finding F2 of `results/uefi`) | `rbd_uri_text()`: the opener formats the URI (it has no password: that is refused earlier) when, and only when, the specification asks for `devpath=uri`, and frees it after the session took what it needs | `rbd_uri_test`: the text, no key in it, the node is buildable from it and was not without it, the out-of-memory path. Live: row U0-uri (the firmware's shell shows `Uri(rbd://...?devpath=uri)` on 10 map entries, the ESP is read) and row U1-uri (Linux boots to the login prompt) |
| R-3 | medium | A wrong key or an unknown user was reported as `Protocol error` (`WR_E_M2_BAD_METHOD` is "refused the login" and "refused the connection mode" in one frame), and the console line did not say which (findings F3 of `results/uefi`, F4 of `results/bios`) | the answer the cluster put in the frame decides: "not supported" is the mode, anything else is permission denied; the console line prints the answer and what to check | `rbd_selftest` (the mapping), `rbd_uri_test` (the lines). Live: row N-wrongkey: `EACCES`, the line `rbd: open failed: server refused the offered authentication method or mode (WR_E_M2_BAD_METHOD; the cluster answered -13): check the key (rbd-key), the user and its capabilities` |
| R-4 | medium | The stack watermark of the test builds measured nothing on 64-bit BIOS images: it compared a physical stack pointer with the linker's virtual addresses (finding F2 of `results/bios`) | compare physical addresses (`virt_to_phys` of the frame and of both linker symbols) | live: a 64-bit BIOS boot with the monitor (row `x64inst-b1`): 5,608 of 8,192 bytes high-water, 2,584 left |
| R-5 | medium | An image made with the default features is refused with "mask in a0" (finding F10c of `results/bios`); the first WinPE import of this review hit it too | the console line names the features and says what to do | `rbd_uri_test` (the line). Live: the failed WinPE rows of the first attempt, kept in `results/final/rows/attempts-*` |
| R-6 | medium | Neither the CI workflow nor the builder gate built the 32-bit BIOS images (`bin-i386-pcbios/`): `bin/` is iPXE's `DEFAULT_ARCH`, x86_64, so the path of the design that matters most for BIOS machines (4 KiB stack, the core on its own stack) was never built by a gate (finding F1 of `results/bios`) | the four 32-bit targets are in the CI matrix, in the builder gate, in the link-map check and in the licence check; `build.sh check` insists on two of them | CI and the builder gate: 11 targets build with no warning |
| R-7 | medium | The builder gate's "every driver object is FORBIDDEN" check failed on a good tree one time in three: `nm \| grep -q` under `pipefail` (finding T1 of `results/uefi`; `build.sh` had the same pattern fixed already) | `grep -c` | the gate: 122 objects, 0 not forbidden |
| R-8 | low | Nothing could be learned from a boot after the fact: `rbd-info` cannot run once the boot loader has the machine (finding F6 of `results/uefi`, F5 of `results/bios`), and a heap exhausted by something other than the driver left no trace | test builds (`-DRBD_STACK_MONITOR`) print one line of counters and a heap probe (the largest block `malloc` still gives) every 5 s while the cluster works and when the 30 s rule closes a path | live: the lines are in the consoles of the loss rows |
| R-9 | low | Documentation: README line 108, `ipxe/README.md`, the status line of this document, `ipxe/tests/README.md`, the ROADMAP rows and `handoff-table.md` still described the skeleton | rewritten from the evidence | `build.sh check` (static), the harness `core.docs` test |

### 18.3 The live matrix on the final binaries

All rows below ran against the dedicated lab (a real Ceph v20.2.5), on the binaries listed in `results/final/BINARIES.txt`, built from the sources as they are in the repository by a gate that passed with no failed check (`results/final/gate-results.txt`: 11 iPXE targets with iPXE's own `-Werror` and no warning, the licence verdict, the Secure Boot refusal, 122 objects `FORBIDDEN`, 84,727 / 84,802 self-tests in the 64 and 32-bit programs, plain and with UBSan, the negative control). `results/final/MATRIX.md` is the table of every row; a row that failed or did not count is in it with its reason.

| Rows | What | Result |
|---|---|---|
| U1, U2, U3 (OVMF: PXE, USB stick, CD) | the Linux GPT image to the login prompt, the table check (40 fields), `/` on `/dev/rbd0p2` | **PASS**, login at 60.5, 58.5 and 57.0 s |
| B1, B2, B3 (SeaBIOS, 32-bit images: PXE, USB stick, CD) | the Linux MBR image, the table found by the scan, `/` on `/dev/rbd0p1` | **PASS**, login at 55.5, 51.0 and 44.9 s |
| B1 with the 64-bit BIOS image | the same through `bin/ipxe.pxe` | **PASS**, login at 56.0 s; the stack monitor reports 5,608 of 8,192 bytes high-water (R-4) |
| U0 `vendor`, `uri`, `sata` | `sanhook`, the UEFI shell: `map -r` lists the device and its partitions, `ls` reads the ESP, the device path carries the node of the flavour | **PASS** (the `uri` node reads `Uri(rbd://...?devpath=uri)`: R-2) |
| U1 `uri`, `sata`, `handoff=key` | the same boot with the other device path flavours, and with the key in the table | **PASS**, 61, 59 and 61 s, 40 of 40 fields |
| UB bytes | 18 files (143.5 MB) read through the SAN device by the firmware's FAT driver, digested in iPXE, against the build list and `rbd export` | **PASS** 18 of 18, with and without readahead |
| N password, no key, wrong key, wrong pool, wrong image, no monitor | each fails with one console line and its errno | **PASS**; the wrong key is `EACCES` with "the cluster answered -13: check the key" (R-3) |
| W1, W2, W3, W4 (WinPE of the owner: UEFI PXE, UEFI USB, BIOS PXE, BIOS USB) | the boot manager loads `boot.wim` through the driver; `startnet.cmd` writes `WINRBD-WINPE-OK` to COM1 | **PASS**, two or three runs each (W1 61 and 63 s, W2 77 and 86 s, W3 63 and 81 s, W4 74 and 84 s); W1 with `sata` 95 s and `uri` 70 s |
| robustness: U1 and B1, control, monitor killed 20 s, OSD killed 45 s, link down 40 s, every OSD stopped 20 s | a Linux boot with one fault injected during the kernel load; the lab is put back (no diff) | **PASS** 10 of 10; 5 negative rows (wrong key, pool, image, monitor) **PASS** |
| the read bench, four receive windows (section 18.2, R-1) | INT 13h reads of 127 sectors, 1 MiB and 4 MiB, with and without readahead | the default readahead: 11.5 / 4.4 / 8.6 MiB/s with a 4 MiB window, 12.8 / 4.3 / 9.9 with 256 KiB, 13.3 / 4.5 / 10.0 with 128 KiB, **16.4 / 18.4 / 18.5 with 64 KiB**; without readahead 6.4 / 23.1 / 27.5, 8.1 / 22.6 / 26.0, 10.2 / 28.9 / 33.1 and 8.8 / 18.3 / 25.7 |
| the Linux boot with loss on the lab's replies, 4 MiB window against 64 KiB | 2 % (three each) and 8 % (two each) | all booted; login at 76 to 88 s (old) and 75 to 97 s (new) at 2 %, 137 and 133 s at 8 % (two 8 % rows booted and mapped their root but are judged FAIL by the marker patterns); the heap probe saw 2 MiB free throughout |

The rows that did not count are kept: the first WinPE import had the image's default features (R-5: the writer profile refused it, with a console line that now names the features), the first UEFI-shell rows used a build with iPXE's own serial console (every character doubled), two rows named an option twice, one did not start while the lab was busy.

**The tests.** (1) The harness's own matrix in the 26.04 guest (gcc 15.2, clang 21.1.8; Debug, Debug + ASan/UBSan, Release, MinSizeRel; 253 and 248 tests, `-LE lab`; `results/final/ctest-guest.txt`) ran once, with this review's builds and the QEMU matrix running beside it on a machine at a load average of 25 to 60: `gcc/san`, `clang/san` and `clang/release` passed, every gate (objects, 32-bit, iPXE flags, headers, no libc, no globals) passed in both compilers, and the other five flavours each failed one or two of three timing-sensitive self-tests (`faultinject.selftest`, `exitrun.selftest`, `winpe.selftest`: recovery limits of a few seconds); each of those passed when run again **alone on the idle guest** (65 to 67 s, 169 s and 83 s; `ctest -R`), so it is load, not a defect, and a clean pass of all flavours at once was not obtained in this run. (2) On the build machine itself (gcc 11.4, `results/final/ctest-box.txt`): Debug passed completely, Release passed except `faultinject.selftest` under load, which passed alone. (3) The driver's own 72,279 self-tests (section 14.2) in the build gate: 64 and 32 bit, plain and with UBSan, and the negative control. (4) Fuzzing of the two new core decoders, `fuzz_handoff` and `fuzz_rburl`: 7,200 s each in libFuzzer's fork mode with 4 workers (8 CPU-hours per target, the Phase 1 duration), ASan and UBSan, started from the committed seeds, in the builder guest: `fuzz_handoff` 644.5 million executions, coverage 460 edges, 1,158 features, a corpus of 333; `fuzz_rburl` 699.8 million executions, 860 edges, 2,488 features, a corpus of 1,126; **no crash, no leak, no timeout, no out-of-memory**. The minimised corpora hold 227 and 941 inputs beyond the committed seeds; they are fuzzer output, not committed here (`harness/tools/fuzz_long.sh -m` prints them for the owner to read first). The third new core module, the readahead state machine, has no decoder and no fuzz target; it is covered by its simulated-cluster tests.

### 18.3a Second review (module `p2-review`, run again on the finished tree)

A second reader went through the glue again (the same interfaces, the pinned tree, the patches, the build script, the CI workflow, the design and the claims in the READMEs) and then tested the **tests**: 104 hand-made mutants of the glue (a check removed, a wipe taken out, a comparison loosened, a reference left unreleased) were each built into the 64-bit self-test program and run; a mutant that the tests do not fail is a gap in the tests. Of the 93 that compiled (the other 11 only failed to build because the removed code left an unused function, and were redone in a form that builds), 69 were caught by the tests as they were. The 24 that were not were read one by one:

| Finding | Severity | What | Fix |
|---|---|---|---|
| R-10 | medium (test gap on a security check) | the copy of the monitor list into the parse's working area (`rbd_uri_authority()`) was only tested one byte past its limit, a byte that lands in the next field and is overwritten; with the length check removed every test stayed green, and a host of a few kilobytes in a URI served by a menu or a script would have overflowed the heap | `rbd_test_authority_overflow`: hosts of 1 limit + 1, 2 limits, 8 KiB and 20 KB with guard bytes behind the working area; the guard must be untouched and the parse must refuse. Caught: the mutant that removes the check |
| R-11 | medium (test gap on a secret) | **no test ran the opener's success path.** Every opener test stops at a refusal, before a session is asked for, so the `rbd_spec_wipe()` of the specification (which holds the decoded cephx key) after a successful open could be deleted with every test green, although the design says "heap walks after every outcome find no byte of the decoded key" | `rbd_open_with()` (the opener with a session environment; `rbd_open()` is it with NULL, nothing else of production changed) and `rbd_test_open_success`: the real parse, the real core, fake sockets, a device on a stand-in for the SAN path, then close and destroy, 16 rounds (`handoff=nokey` and `handoff=key`): no window of the key in the free heap, the session's key wiped when its device lets go, every session reference and block given back (the heap is exactly where it was). Caught: the mutants that drop the wipe, the session reference, or the free of the specification |
| R-12 | low (test gap) | a session with no device (the grace period between two opens of the SAN layer) must not run the stall rule: the "closing the path" line would print every 30 s for 120 s for nobody; no test said so | `ses_test_stall`, last block. Caught: the mutant that arms the rule for a session without devices |
| R-13 | low (doc) | the closing-the-path rule has a documented exception that the review confirmed in the code: a trouble that began before a long idle gap makes the first command after the gap close the path at once (the SAN layer then reopens, at no great cost; `ses_test_stall` pins it: "as it always did"). The comment on `RBD_STALL_CLOSE_MS` says "has waited this long" | not changed (a deliberate, tested behaviour); noted here |
| R-14 | low (doc, security) | the key stays in the session's memory after the hand-over: see section 18.4 and the security note of `handoff-table.md` | documented, not changed |
| R-15 | low (doc) | the patches' subject lines said 1/2, 2/2, 3/3 and 4/4; the design duplicated one sentence (R12) and the test counts changed with this review | corrected |

The survivors that remain, with the reason each is not a gap in the tests:

- **Double guards** over a promise the module below already keeps, which no input of a test (or of the field) reaches: the `-EIO` for an empty span in the copy of a readahead hit, the `n_pf` bound on a prefetch line, the second `attached` test of `rbd_cmd_create()` and of `rbd_block_window()`, the length check inside the URI node builder, the monitor count of the parser's answer.
- **Equivalent mutants**: the comparison in `rbd_conn_gather_len()` (`>=` against `>` gives the same length), the window test of `rbd_conn_transmit()` (a zero window gives a zero length, which returns anyway), the `-ENOSPC` branch of the table builder (the codec's status maps to the same error; only the console line differs), a monitor's nonce in the table (the parser never sets one), the clearing of `pending` of the requests at the destruction of a session (every reader copes with a destroyed session), the done function of a command that is closing (it is already off the list), the reset of the readahead cache at a reopen (the open does it again before any command can run), the guard against an image resized to under one block, the clamp of the length of a setting (the parser looks at the length first and refuses it).
- **Layers**: the wipe of the session's key at its destruction, at the free of its structure and at the detach of its last device. Any one of them is enough; the tests fail if the detach wipe goes (mutants `s6b`, `s6c`).
- **Platform**: the wipe of the core's private stack at destruction passes the 64-bit program (which has no such stack) and is caught by the 32-bit one.

**Counts after this review.** Driver tests: 72,520 (64-bit program 84,968 in all; 32-bit program 85,043; plain and with UBSan in trap mode; the negative control), the 11 iPXE targets build with iPXE's own `-Werror` and no warning with gcc 15.2, the licence verdict and the Secure Boot refusal as before, 122 objects `FORBIDDEN` (`build-ipxe.sh`, no check failed).

### 18.4 What is open

- **The failed boots of the first matrix are unexplained.** Findings F1 and F5 of `results/uefi` (eight of the UEFI boots started in one stretch of one afternoon, the guest's transmit going silent, `parse URI failed: out of memory` on every reopen afterwards) were not reproduced: the final matrix has no such run among its boot rows (6 login, 2 on 64-bit BIOS, 10 WinPE, 3 of the UEFI matrix, 10 with a fault injected, 12 with loss on the replies; the two 8 % rows that booted and were judged FAIL by their marker pattern are not stalls), and the loss rows (2 % and 8 % of the replies lost) did not exhaust the heap. R-1 was the best explanation found by reading iPXE's TCP and it is a real defect, but its measured effect is the readahead loss, not those stalls. What is known: the lab VM and the build machine do stall for longer than 30 s now and then (the machine has a global `sync()` problem); a 30 s stall closes the path and the SAN layer reopens it against the cached session. What the driver still lacks is a bound on how long a reopen may fail before the boot loader gives up (the boot loader decides).
- **Readahead default.** Kept at 2 MiB. After R-1 the default is a gain for the commands boot loaders issue (127 sectors: 16.4 against 8.8 MiB/s without readahead; GRUB issues at most 64 sectors; what the Windows boot manager issues is **unmeasured**) and level at 1 MiB; at 4 MiB it is 0.7 times slower than without (two runs each). `readahead=0` is the option for a workload of large commands. The default is tied to the core's parser (`WR_RBURL_READAHEAD_DEFAULT_KIB`, a core file); a different window needs the Windows loader's command sizes first.
- **`undionly.kpxe` and `exit`.** After `sanhook` and `exit`, an RBD drive stays hooked over a network stack the PXE ROM then stops: every read stalls for 30 s (row B0 of `results/bios`). Boot with `sanboot`, or use `ipxe.pxe` (native drivers). The driver prints a warning at that exit. Not a driver defect; iPXE's UNDI shutdown.
- **`devpath=sata` and Windows.** The first matrix's W1-sata stuck at "Booting from SAN device" on the owner's earlier images (finding F8 of `results/uefi`). On the owner's current images all three flavours reach WinPE: `vendor` (the default) at 61 and 63 s, `uri` at 70 s and `sata` at 95 s to the `WINRBD-WINPE-OK` marker on the serial port, and the first matrix's screenshot judge passes `sata` and `uri` too. The node builder did not change between the two runs; the images did, and which of the two made the difference is not shown. `vendor` stays the default (Q1).
- **An EFI application that returns while a device is hooked.** iPXE unloads when an EFI application it started returns, and its SAN devices go with it: with an RBD device hooked the guest hangs there (finding F4 of `results/uefi`; row U0 therefore starts the firmware's shell from iPXE). iPXE's own behaviour for any SAN device; documented, not changed.
- **The key stays in the session's memory after the hand-over (found by the second review).** `handoff=nokey` keeps the cephx key out of the `rBFT` table, not out of memory: the core's arena (key and session keys) is part of the session block, which is wiped only when the session is destroyed (section 11: 120 s after the last device lets go, or when the path fails for good). A session whose device is still hooked when the operating system starts is never destroyed: on BIOS the block stays resident and hidden from the OS memory map, on UEFI it is boot-services memory that the OS reclaims at `ExitBootServices` without clearing (**unverified** on real firmware). An administrator of the booted system with access to physical memory, or a dump, may read it. Not changed: the owner has to decide whether a wipe at hand-over is wanted (on UEFI nothing reads the device after `ExitBootServices`, so a wipe there is safe in principle; it needs a live boot of an OS to show that, which this review did not have); `docs/design/handoff-table.md` (security note) now says it. The mitigation is the one already given: one cephx entity per image.
- **The one WinPE run that did not complete** (finding F11 of `results/bios`: a 30 s stall closed the path and the reopen did not finish for minutes, on a box at load 52 to 67) is consistent with R-1 (a full heap makes every reopen fail), and it was not reproduced on a quiet machine; the final matrix has no such run, which is not proof.
- **`ops_failed` counts holes.** `rbd-info` showed "1 failed" in a byte check whose data were right (finding F7 of `results/uefi`). The core counts an object operation that returned `-ENOENT` as failed before the image layer turns it into zeros (`wri_or_complete`, `core/src/osd/wri_osd_req.c`), so a read of an object that was never written counts; consistent with the evidence, not proven by a row.
- **Not shown:** real hardware; Windows reading the table (WinPE has no `rbd` driver in this phase; nothing in Windows has read it); an image above 2 TiB (no row reads at LBAs above 2^32; the arithmetic is checked in unit tests); snapshots (refused); namespaces; `mapmem` and `monmsg` (parsed, refused with `-ENOTSUP` until the specification has fields for them).
- **Evidence hygiene.** The repository's `.gitignore` has `*.log`, which matches the `serial.log` of every row under `harness/lab/p2/results/uefi/rows/` and of the other families, and `build/`, which matches the build records. `.gitignore` now carries an exception for exactly these two (`!/harness/lab/p2/results/**/*.log`, `!/harness/lab/p2/results/**/build/`); `git status --ignored` shows no file below `harness/lab/p2/` as ignored. Every other ignore rule (keys, keyrings, `*.efi`, `*.img`, `*.qcow2`, ...) still applies there. The final rows keep an excerpt of the console (`serial.excerpt.txt`), not the full log.
- **The build machine's rows are timing-sensitive.** The matrix runs on a shared 100-core machine at a load average of 25 to 60; every row records the load and the guest's CPU wait (`stamps.txt`), and a failure is counted, never retried away.


### 18.5 Final hardening pass (third review: the whole change set read as one, the gates run again)

The whole Phase 2 change set (14 modified files, about 5,600 new ones, of which 5,283 are evidence under `results/`) was read against the design, the licence rules and the CI workflows, the patch series was applied to a fresh `git archive` of the pinned iPXE (`patch -p1 --fuzz=0`: all four apply, no offset), every new file was compared with Ceph v20.2.5 (windows of four consecutive non-trivial lines, 1.3 million windows of 6,656 files, with a positive control on `core/crush_ln/`: no match; the two windows that match iPXE's own files, a netmask default and a socket-address union, are from files under the same licence and the first is credited in `rbd_acpi.c`), the new files were searched for the names of Linux's libceph / rbd (none), for keys, internal addresses and user names (none), and the test matrix was run again. Evidence: `results/final/review3/`.

| ID | Severity | Finding | Fix |
|---|---|---|---|
| R-16 | low (licence hygiene) | `CONTRIBUTING.md` rule 2 and `LICENSE` say every new file carries an SPDX line matching its directory; the 26 glue and test files of `ipxe/` carried only iPXE's `FILE_LICENCE` and the licence text | `SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL` in the first five lines of each (on a line that was blank, so no line number moves); `build.sh check` now requires it, with a negative control (`check -n`: 40 seeded cases and stand-in inputs); `LICENSE`, `ipxe/README.md` and `ipxe/tests/README.md` say so |
| R-17 | low (gate coverage) | the SPDX gate of `core.docs` (`check_spdx`) listed the Phase 1 directories only: the three new core modules (`core/src/handoff`, `ra`, `rburl`) and the scripts of the live matrix were not looked at (they all carry the tag; nothing would have said so when one lost it) | the directories are in the list (`harness/tools`, `harness/lab`, the five `harness/lab/p2` script directories, `harness/vectors/handoff`, `ipxe/tools` too) |
| R-18 | low (flaky test) | `robust.selftest` (case `osd-kill`: a stand-in daemon killed and restarted at fixed instants, the order of the lab commands judged) failed once beside other tests of `ctest -j 4` in the 24.04 guest (clang Release) and passed twice alone, like `faultinject.selftest`, `exitrun.selftest` and `winpe.selftest` before it | `RUN_SERIAL` (no limit and no assertion changed). With it, the 26.04 guest passed all 8 flavours in one run, which the earlier close-out run did not (section 18.3). **One more timing case remains**: `exitrun.selftest` (already serial; its "signals" case sends SIGTERM, SIGINT and SIGHUP at fixed instants while the lab is put back) failed once, in the 24.04 guest's gcc ASan/UBSan flavour, while two other guests of the same pass were building on the machine (load average about 45), and passed three times in a row when run alone on that guest (168 to 244 s: its duration follows the load). Not changed: the instants are the test; no limit may be weakened |
| R-19 | info | `rbd_bios_test.c` was the one test file without its `FILE_SECBOOT` rationale | the same paragraph the other seven carry |
| R-20 | info (evidence) | `results/final/gate-results.txt` and the hashes of `BINARIES.txt` are of the tree before the second review (84,727 / 84,802 self-tests, where the sources now give 84,968 / 85,043: the 241 tests of R-10 to R-12), and the live rows ran on binaries built before it. The second review changed production code in one place (`rbd_open()` became `rbd_open_with()`, R-11). A copy of the tree that the final matrix's last check ran from (`p2-final-check` on the build machine) differs from the repository only in comments (the `FILE_SECBOOT` paragraphs, one comment in `rbd_acpi.c`, one in `rbd_conn.h`, the wording of patch 0002) and in the SPDX lines of R-16: same code, same tests. **The live rows were not run again**: the images would have to be rebuilt, imported and the rows driven for hours on a machine that was already carrying two build guests and the lab, to confirm a refactor that the 84,968 tests (the whole opener, the real parse, the real core, fake sockets) already cover | gate run again on the current tree (`results/final/review3/gate-results.txt`); this note |
| R-21 | info | the Ubuntu 24.04 guest of this review had no `libclang-rt-18-dev`, so clang's ASan/UBSan flavour could not link (the builder script provisions 26.04, where the runtime ships with clang) | package installed in the guest; the flavour passed |

**Open, for the owner (not changed).** (1) `core/crush_ln/crush_ln_table.h` is copied unchanged from Ceph under LGPL-2.1 and the build of the driver tags it `GPL2_OR_LATER` for iPXE, which LGPL-2.1 section 3 allows for a copy; section 3 also asks that the notices of that copy are altered to refer to the GPL, and the imported copy keeps Ceph's LGPL notice. Whether a distributed binary needs more than the statement in `README.md` and `LICENSE` is a legal question that this review cannot settle. (2) The questions of 18.4 (the key in session memory after the hand-over, the first matrix's unexplained stalls, real hardware, Windows' own view of the table) are as they were.

**Final matrix of this pass.** Ubuntu 26.04 guest (gcc 15.2, clang 21.1.8): Debug, Debug + ASan/UBSan, Release, MinSizeRel with both compilers, 8 of 8 passed in one run (253 / 246 / 253 / 253 tests with gcc, 248 / 246 / 248 / 248 with clang, no failed test, none skipped except `crypto.ct.valgrind` under the sanitizers) and every gate. Ubuntu 24.04 guest (gcc 13.3, clang 18.1.3): 8 of 8 after the two repairs above (R-18, R-21) (the last, shorter pass on the final tree, gcc Release and ASan/UBSan, had the `exitrun.selftest` failure described in R-18 once; `results/final/review3/ctest-ubuntu-24.04-final-tree-gcc.txt`). The 26.04 guest ran Release again with both compilers on the final tree: passed (`ctest-ubuntu-26.04-final-tree-release.txt`). The iPXE gate: 11 targets, licence, Secure Boot, 122 objects, 84,968 / 85,043 tests, negative control, 0 checks failed. The CI jobs' own commands (`ipxe-gates` of `harness.yml`: the header, language-standard and call-depth gates and their self-test, with `WRT_IPXE_REQUIRE=1`) passed in the 26.04 guest.
