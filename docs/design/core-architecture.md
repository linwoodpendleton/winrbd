# winrbd core architecture (Phase 1)

<!-- SPDX-License-Identifier: MIT -->

Status: **part A, Phase 1 milestones 1 to 3, plus delivery of the monitor's map messages as raw bytes (sections 1 to 14); part B, milestones 4 and 5 (OSD map, CRUSH, object placement) and the decoder half of milestone 10, in sections 15 to 19.** Part A is implemented (the waves of section 9). Part B is implemented too (the seven waves of section 17), reviewed module by module and hardened as a whole: its measured results (fuzzing, the comparison with Ceph's own tools on the lab, footprint, call depth and stack) are in section 18.6. Everything here is our own design, written from `docs/spec/`; Ceph, iPXE, WNBD and Linux kernel code is not copied (see [CONTRIBUTING.md](../../CONTRIBUTING.md), rule 1). Spec notes are cited as `msgr2.md 2.3`, `cephx.md 3.2`, and so on.

Scope of this run (ROADMAP Phase 1):

| Milestone | In scope |
|---|---|
| 1. Shim interface, Linux implementation | yes: `wr_host.h`, the pump API, `harness/host/` |
| 2. Monitor over msgr2 (banner, hello, frames, CRC-32C) | yes |
| 3. cephx, tickets for mon and OSD services, renewal | yes (both key types, mon handshake, OSD authorizer, in-session renewal) |
| 4. OSDMap | part A: receiving `MMonMap` and `MOSDMap` from the monitor, raw. Part B: decoding, incrementals, re-fetch (sections 15 and 17) |
| 5. CRUSH, object to PG to OSD | part B (sections 16 and 17) |
| 6 to 11 (OSD sessions, RBD, krbd compare, secure mode; milestone 10 for the part B decoders is in section 18) | later; section 10 records the hooks that keep them cheap |

Contents: 1 decisions at a glance, 2 language and portability rules, 3 hosting model (the pump), 4 shim and crypto, 5 memory model, 6 source layout, 7 module interfaces, 8 state machines, 9 implementation waves, 10 later milestones, 11 error model and logging, 12 build, tests, fuzzing, 13 where the alternatives disagreed, 14 risks and open questions. Part B: 15 OSD map (decoding, memory, following epochs, API), 16 CRUSH and placement, 17 implementation plan, 18 verification, 19 risks and open questions.

---

## 1. Decisions at a glance

Three independent design studies were compared: (a) strict sans-IO, (b) iPXE-first, (c) Windows-kernel-first. They agreed on most points; section 13 lists where they did not and what was chosen (the letters there refer to these studies).

| # | Topic | Decision |
|---|---|---|
| D1 | Language | **C99**, freestanding-friendly. Headers allowed: `<stddef.h>`, `<stdint.h>`. No VLAs, no floating point, no recursion, no atomics, no writable globals, no wire-struct overlays. |
| D2 | I/O model | **Sans-IO pump.** The core never opens a socket, reads a clock, allocates, blocks or calls the host. The host feeds bytes and time in and pulls bytes and actions out. Receive and transmit are window-based and zero-copy capable. |
| D3 | Completions | **Pulled, never called back.** Events, map messages (and later I/O completions) are fetched by the host. The only calls from core to host are the two leaf callbacks `random` and `log`. |
| D4 | Threads and re-entrancy | One owner per client; not thread-safe, not re-entrant. A host with many threads serialises itself. |
| D5 | Crypto | The core carries its **own portable MIT crypto** (CRC-32C, SHA-256/384, HMAC, AES, CBC, CTS-CS3, RFC 8009 KDF) behind an **optional override table** the host may fill. CTS, KDF and the cephx envelope are never overridable. |
| D6 | Memory | **No allocation, ever.** The host hands over two regions (`arena`, `bulk`); `wr_client_mem_required()` says how large. Run-time state lives in fixed pools addressed by `u32` index. |
| D7 | Time | The host passes a monotonic millisecond clock into `wr_client_run()`; deadlines are fields; there are no timer callbacks. A wall clock is optional (needed later for OSD op mtime). |
| D8 | Framing seam | A **codec seam** below the connection (crc now, secure later) guarantees the layers above only ever see verified segment bytes. |
| D9 | Errors and logs | Stable negative status codes grouped by module, a structured first-failure-wins `wr_errinfo`, English static strings, numeric log records. No `printf` in core, no `errno`. |
| D10 | Source layout | `core/include/winrbd/` public headers; `core/src/<module>/` internals; **unique C basenames** (iPXE names objects by basename); `core/sources.txt` generated; `core/crush_ln/` holds the LGPL tables (part B, 16.2). |
| D11 | Verification | Every module has unit tests on the committed vectors; mechanical checks forbid libc and globals in core; fuzz targets per decoder; a deterministic in-memory simulator of the monitor drives the whole engine. |

---

## 2. Language, toolchain and portability rules

### 2.1 Language level

**ISO C99, restricted.** C11 buys nothing we need and kernel-mode C11 support in the WDK toolchain is partial (WNBD builds with VS2019 and WDK 10.0.20348, ROADMAP Phase 3). C99 is a subset of what the iPXE build accepts (its Makefile sets no `-std`).

Allowed: `<stddef.h>`, `<stdint.h>` (both freestanding), designated initialisers, mixed declarations, `static inline` (spelled `WR_INLINE`). Forbidden in `core/`: VLAs, `alloca`, `<stdatomic.h>`, `<threads.h>`, `<stdbool.h>` (use `uint8_t` flags: iPXE and the WDK define their own `bool`), `<limits.h>`, any other libc header, floating point (CRUSH needs none, `crush-and-placement.md` 4.4), recursion (every walk is iterative with an explicit depth cap of 8 for envelopes), `long` for sizes, bitfields, packed structs, `enum` types on the wire (use `#define` of fixed-width constants), casts of wire bytes to structs.

**Wire access rule.** Structs never overlay buffers. Every multi-byte field goes through `wri_le16/32/64_get/put` (`wri_le.h`) or the bounds-checked cursors (`wri_cursor.h`). This removes endianness, alignment and strict-aliasing questions on i386 iPXE, x64 and ARM64 in one stroke.

**Static assert** is `WR_STATIC_ASSERT(cond, name)` (a typedef of a negative-size array), not `_Static_assert`.

**Integer discipline.** Lengths from the wire are `u32` or `u64` first, checked against a configured cap, then narrowed. `size_t` arithmetic on untrusted values goes through `wri_add_sz` / `wri_mul_sz` / `wri_align_up`. No reliance on signed overflow (UBSan enforces it in CI). 64-bit division goes through `wri_div_s64_u32` so a 32-bit host never needs `__divdi3` (CRUSH straw2, later).

**Stack.** No function frame above 1 KiB (`-Wframe-larger-than=1024`); call depth of any entry point at most 12 frames (reviewed, not yet enforced mechanically); large scratch lives in the arena. Windows kernel stacks and the iPXE firmware stack are small.

### 2.2 `wr_port.h`

The only header that touches the toolchain. It provides `WR_MEMCPY/MEMMOVE/MEMSET/MEMCMP` (default: compiler builtins; a host redefines them through `-DWR_HOST_CONFIG_HEADER="my_cfg.h"`, for example to `RtlCopyMemory`), `WR_INLINE`, `WR_MUST_CHECK`, `WR_STATIC_ASSERT`, `WR_LOG_MAX_LEVEL` (compile-time log ceiling) and `WR_FILE_LICENCE_MIT` (empty by default; the iPXE glue defines it as `FILE_LICENCE ( MIT );` so the iPXE licence check sees MIT).

### 2.3 Names and files

- Public API: `wr_` / `WR_`. Internal: `wri_` / `WRI_`. Test and harness code: `wrt_`, `wrl_`.
- **Every `.c` file under `core/` has a unique basename.** The iPXE build derives the object name from the file basename (`OBJECT = $(firstword $(subst ., ,$(@F)))`, `third_party/ipxe/src/Makefile.housekeeping:558`), so two `util.c` in different directories would collide. Files are `wri_<module>_<thing>.c` or `wr_<thing>.c`; `core/tools/gen_sources.sh` refuses duplicates.
- First line of every core file: `/* SPDX-License-Identifier: MIT */`; after the includes, a line `WR_FILE_LICENCE_MIT` (no semicolon).
- Files stay under about 500 lines; split by concern.
- `core/crush_ln/` holds the LGPL-licensed CRUSH log tables, copied unchanged, and nothing else (part B). Part A planned a single `wri_crush_ln` symbol across the boundary; part B refines it: only the table data crosses, through two accessors, and the arithmetic stays MIT (section 16.2).

### 2.4 Warning policy (all errors)

| Toolchain | Flags |
|---|---|
| gcc / clang (harness) | `-std=c99 -pedantic-errors -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion -Wcast-qual -Wcast-align -Wstrict-prototypes -Wmissing-prototypes -Wredundant-decls -Wundef -Wvla -Wwrite-strings -Wformat=2 -Wdouble-promotion -Wswitch-enum -Wframe-larger-than=1024 -fno-common -Werror` |
| iPXE flags (CI target `wr_core_ipxe_flags`, gcc) | `-std=gnu99 -ffreestanding -Os -Wall -W -Wformat-nonliteral -Wshift-overflow=2 -Wno-array-bounds -Werror` (taken from `Makefile.housekeeping`), so the core is clean without our extra flags |
| 32-bit (CI target `wr_core_m32`) | the harness flags plus `-m32`: `size_t` and pointers are 32 bits on iPXE i386 |
| sanitizers | ASan and UBSan with `-fno-sanitize-recover` (`-DWR_SANITIZE=address,undefined`) |
| MSVC / WDK (later) | `/W4 /WX`, C mode, `/kernel`, no CRT |

Mechanical gates (ctest, section 12): `core_no_libc` (the static library may reference only `memcpy/memmove/memset` and compiler arithmetic helpers; equality is `wri_ct_memeq`, so there is no `memcmp` or `bcmp`) plus `core_freestanding*` (every core file compiled as ISO C99 with `-ffreestanding` and no system headers, linked with `-nostdlib` next to those three functions) and `core_no_globals` (no `.data`, `.bss`, COMMON or TLS in any object).

---

## 3. Hosting model: the pump

### 3.1 Why sans-IO

The three hosts look nothing alike. Windows (WSK) completes asynchronous IRPs at DISPATCH_LEVEL, where protocol code must not run. iPXE pushes bytes at us from its main loop in iobufs of any size, and its TCP reports a transmit window of zero whenever its queue is non-empty (`third_party/ipxe/src/net/tcp.c:457`), so partial acceptance is the normal case. The Linux harness uses `poll(2)`. A core that calls `send()` or `connect()` through callbacks would re-enter itself on all three (iPXE's `xfer_deliver_raw` can close the interface synchronously; a WSK completion routine cannot run protocol code) and could not be tested deterministically.

So: **data in, data out, run to quiescence.** The host owns the sockets; the core exposes what it wants done and what it wants sent, and the host reports what happened.

### 3.2 The surface

All of it is in `wr_client.h`. In one table:

| Call | Direction | Meaning |
|---|---|---|
| `wr_client_run(c, &clock, budget)` | host -> core | advance everything; returns `next_deadline_ms` and `more_work`. `budget` bounds the bytes of CRC/crypto/copy work per call (0 = 256 KiB) so a kernel worker or the iPXE main loop never stalls. |
| `wr_client_next_action()` | core -> host | `WR_ACT_CONNECT{addr, timeout}`, `WR_ACT_CLOSE`, `WR_ACT_TX_READY`. Derived from per-connection flags, not from a queue, so it cannot overflow. |
| `wr_conn_connected(id)`, `wr_conn_closed(id, errno)` | host -> core | the TCP connection is up / gone (connect failed, reset, EOF, or the host finished a requested close). Stale ids are ignored (ids carry a generation). |
| `wr_conn_rx_window(id, &ptr)` + `wr_conn_rx_commit(id, n)` | core <-> host | where the next received bytes go (a staging ring, or later directly a caller's buffer); `commit` is O(1), all parsing happens in `run`. Window 0 = backpressure. |
| `wr_conn_rx_push(id, data, n)` | host -> core | convenience for push-style hosts (iPXE): copies through the window. |
| `wr_conn_tx_peek(id, iov, max)` + `wr_conn_tx_consume(id, n)` | core <-> host | pending output as a gather list; the host sends what its transport takes and reports it. |
| `wr_client_next_event()`, `wr_client_mapmsg_peek/release()` | core -> host | lifecycle events; raw monitor map messages (front bytes in the bulk region, valid until released). |

Reference loop (the Linux host implements it in about thirty lines, `wrl_loop_step`):

```c
for (;;) {
    wr_clock now = host_clock();
    wr_run_result r = wr_client_run(c, &now, 256 * 1024);
    wr_action a;
    while (wr_client_next_action(c, &a)) host_do_action(&a);          /* connect / close */
    for each live connection id {
        n = wr_conn_tx_peek(c, id, iov, 8);  sent = send(...);  wr_conn_tx_consume(c, id, sent);
        room = wr_conn_rx_window(c, id, &p); got = recv(fd, p, room);  wr_conn_rx_commit(c, id, got);
    }
    wait_until(r.more_work ? now : r.next_deadline_ms, socket events);
}
```

`WR_ACT_TX_READY` is a hint for event-driven hosts: it is emitted on the idle-to-busy edge of a connection's transmit queue. A simple host may call `tx_peek` for every connection after each `run` instead.

### 3.3 Contract details

1. **One owner.** A `wr_client` is not thread-safe and not re-entrant: no `wr_*` call may be made from inside another call on the same client. Nothing in the core takes a lock.
2. **No callbacks into the host** except `random` and `log` (leaf, synchronous, non-blocking, must not call the core). Completions are pulled.
3. **Lifetime of pointers.** An rx window is valid until the next `rx_commit` or `run` of that client. Tx iovecs are valid until `tx_consume` covers them or the connection closes. A raw map message `front` is valid until `wr_client_mapmsg_release`.
4. **Partial everything.** `tx_consume(n)` with `n` less than offered is normal; `rx_commit(n)` with `n` less than the window is normal.
5. **Backpressure is visible.** A zero rx window means "do not read now"; a pool that runs dry defers work (`WR_E_BUSY` internally), it never grows.
6. **Zero-copy contract** (applies once the OSD client lands, noted now because it shapes the window API): a read destination is written *before* its checksum is verified. On any error the content of the destination is undefined, and the request is re-issued or failed; hosts must not expose a failed read. Write data is referenced from the caller's buffer and must stay unchanged until the request completes.
7. **No cancel of an in-flight write.** A lossy client that loses a connection after sending a write does not know whether the OSD applied it. The object client (later) must therefore keep such a write alive (resend with the same tid) and fence later ops on the same object until it completes, rather than abandon it; storport abort/reset completes the SRB toward Windows but not the core request. Reads can be abandoned (zombie slot swallows the reply). This is recorded here because it constrains the pump API (`wr_io_cancel` will be read-only) and is the first item of the risk list in section 14.

### 3.4 Time

`wr_client_run` takes `wr_clock {mono_ms, wall_ms}`. Everything the core needs is relative: cephx tickets carry a validity duration and the core converts it to the local monotonic clock at receipt (`cephx.md 3.5`), handshakes and keepalives are timeouts. `wall_ms` is optional (0 = the host has none): the only later user is the mtime field of mutating OSD ops (`osd-ops.md` 2.3); whether OSDs accept mtime 0 is an open item (section 14, Q4). The core never reads a clock itself; a test drives time with a number.

### 3.5 How each host maps onto the pump

| Host | Mapping |
|---|---|
| **Linux harness** | `poll(2)` loop (`wrl_loop`), non-blocking sockets, `getrandom`, `clock_gettime`. Allocates both regions with `aligned_alloc`. |
| **iPXE** | One `struct process` step calls `wr_client_run` and drains actions. `xfer_deliver` copies the iobuf through `wr_conn_rx_push` and schedules the process (it does not call `run` inside the delivery). `xfer_window()` bounds each `tx_peek`/`consume`. A `retry_timer` is armed from `next_deadline_ms`. `arena` from `malloc()`, `bulk` from `umalloc()` (EFI `AllocatePages`), so the 4 MiB heap is not the limit. `random` from the iPXE DRBG. Time from `currticks()`. To verify on a build, not assumed: heap headroom (iobufs and NIC rings share the heap). |
| **Windows kernel** | One worker thread per client at PASSIVE_LEVEL owns the engine. `HwStartIo` only fills a preallocated per-tag record and pushes it on a non-paged `SLIST`; WSK completion routines record status and push to another list; the worker drains both, calls `run`, and issues `WskConnect/Send/Receive/Close` on preallocated IRPs. Both regions are non-paged, allocated once at adapter start. Windows claims here are marked to be verified against Microsoft documentation in Phase 3 and 4. |

---

## 4. The shim and crypto

### 4.1 `wr_host_ops` (`wr_host.h`)

```c
typedef struct wr_host_ops {
    uint32_t size;  void *ctx;
    wr_status (*random)(void *ctx, uint8_t *out, size_t n);   /* required; WR_E_HOST_RANDOM on failure */
    void (*log)(void *ctx, const wr_log_rec *rec);            /* optional */
    const wr_prim_ops *prim;                                  /* optional primitive overrides */
} wr_host_ops;
```

Not in the shim, on purpose: sockets and DNS (the pump; mon addresses are literals, resolved by the host), threads and locks, allocation (regions, section 5), the clock (an argument), files (keys are passed in memory), `fatal` hooks (the core never aborts on untrusted input).

`random` is used for the cephx client challenge, the type-2 confounder, authorizer nonces, the entity nonce and back-off jitter. If it fails the connection fails; there is never a weak fallback.

### 4.2 Crypto: carry our own, let the host override

**Decision.** The core always builds a portable reference implementation of everything it needs. A host may replace any primitive by filling members of `wr_prim_ops`; a NULL member (or a member beyond `size`) means "use the portable code". Dispatch is one pointer test per call (`wri_p_*` in `wri_prim.h`); every protocol call site uses the dispatchers, never the reference functions.

Why not "host crypto only" (the ROADMAP's first wording):

1. **iPXE gaps.** iPXE has AES (CBC, GCM), SHA-2 and HMAC under `src/crypto/` but no CRC-32C and no CTS mode, and they are reached through objects whose inclusion depends on build configuration. cephx type 2 needs HMAC-SHA384 and AES-256 CTS (CS3); that alone must be written.
2. **Windows kernel.** CNG in kernel mode is PASSIVE_LEVEL oriented and may not be available early in boot (Phase 4); the storage I/O path can run at DISPATCH_LEVEL and a later crash-dump mode (Phase 5) has no OS services at all. Our own code has none of those constraints.
3. **One implementation to verify.** The committed vectors (`cephx/*`, `msgr2/crc32c.json`, RFC 8009) test one code path on all hosts; a host primitive that disagrees shows up as a vector difference. The harness runs an OpenSSL differential test where libcrypto exists (never a core dependency).
4. **Licensing.** iPXE's crypto is GPL-or-later or UBDL; ours is MIT, so the core stays one clean MIT body linked into iPXE (GPL2_OR_LATER_OR_UBDL glue), the LGPL driver and the harness.

Costs accepted: about 2.5 kLOC of C; table-based AES is **not constant time against cache attacks** (documented; the threat model of the project is test networks, and the override exists for hosts with AES-NI, ARMv8 CE or CNG); software GCM will be slow (secure mode is milestone 11).

The override table is **stateless, one-shot calls** (`crc32c`, `hmac_sha256`, `hmac_sha384`, `aes_cbc_enc`, `aes_cbc_dec`, key passed on every call), because cephx messages are small and stateless calls keep the core allocation free and the host adapter trivial. A key schedule is rebuilt per call. Streaming GCM for secure mode will be added as new members guarded by `size` (no ABI break). CTS-CS3, the RFC 8009 KDF, PKCS#7 padding and the cephx envelope are built **by the core on top of CBC and HMAC**, never delegated, so no host override can change protocol semantics.

CRC-32C tables are const arrays generated by `core/tools/gen_crc32c_tab.py` and committed, so there is no run-time table build and no writable global.

### 4.3 Keys

`wr_key {type, len, secret[64]}` is parsed from the keyring's `key = <base64>` form (`cephx.md 2.3`) by `wr_key_parse_keyring`, or built from raw bytes. Type 1 (`aes`) and type 2 (`aes256k`) are both supported from day one and dispatched **by the type field of the key being used**, never globally (a ticket can carry a session key of a different type than the key that wrapped it, `cephx.md 3.4`). `wr_client_create` copies the key into the arena; the caller may wipe its copy; `wr_client_destroy` wipes the arena. Secrets are never logged (a canary test enforces it).

---

## 5. Memory model

### 5.1 Principles

1. **No allocation inside the core**, not at init and not at run time. The host passes memory in.
2. **Everything is sized from `wr_config`.** `wr_client_mem_required(cfg)` returns the exact byte counts of the two regions; `wr_client_create` fails with `WR_E_BUDGET` if a region is too small and then initialises nothing.
3. **Two regions.** `arena`: small and hot (engine state, connection slots, handshake transcripts, keys, tickets); non-paged on Windows, `malloc()` on iPXE. `bulk`: large and cold (monitor message buffers now, OSDMap and CRUSH slots later); `umalloc()` on iPXE so the 4 MiB heap is not the limit. The two regions may be one allocation split by the host. Both must be 16-byte aligned.
4. **Init-time bump allocation, run-time fixed pools.** `wri_arena` carves regions once at create; at run time everything is a `wri_pool` (fixed-size objects, intrusive free list) or a `wri_ring`. A pool that runs dry returns "busy" (backpressure), it does not grow.
5. **Index handles, not pointers,** between pool objects (`u32`, `WRI_NIL` = none): halves memory on 64-bit hosts, same layout on i386 and x64, relocatable arenas (keeps the crash-dump option of Phase 5 open), dangling pointers become bounds-checked index errors.
6. **Every wire-sourced length is compared with a budget before use.** Budgets are config fields.

### 5.2 `wr_config`

The fields (`wr_config.h`) are the budgets and policy of this milestone; `reserved[24]` words leave room for the OSD client, image and secure-mode fields without an ABI change.

| Field | Meaning | ipxe | kernel | harness |
|---|---|---|---|---|
| `max_conns` | live connections (monitor session + OSD sessions later); at least 2 so a renewal can open the new session before closing the old | 4 | 8 | 16 |
| `max_handshakes` | connections in handshake at once (each holds two pre-auth transcripts) | 1 | 2 | 4 |
| `rx_buf_bytes` | per connection staging ring | 4 KiB | 16 KiB | 64 KiB |
| `ctl_buf_bytes` | largest control-frame segment accepted (AUTH_DONE carries tickets) | 8 KiB | 16 KiB | 16 KiB |
| `tx_buf_bytes` | per connection encode buffer | 8 KiB | 16 KiB | 64 KiB |
| `preauth_cap` | per direction transcript bytes | 8 KiB | 16 KiB | 16 KiB |
| `ticket_cap` | largest service ticket blob kept | 1 KiB | 1 KiB | 2 KiB |
| `mon_msg_cap` | largest monitor message front accepted (an MOSDMap can carry about 40 maps) | 1 MiB | 4 MiB | 16 MiB |
| `mapmsg_queue` | raw map messages held for the consumer | 1 | 2 | 2 |
| timers | connect 5 s, handshake 8 s (server drops at 10 s), keepalive 10 s / 30 s timeout, hunt back-off 0.5 to 15 s | same | same | same |

These numbers are **first estimates** (the map module's budgets are in 15.3). The footprint test (`test_client_mem`, `test_core_budgets`) prints the real byte counts and asserts the budgets once the engine exists; the profile numbers in `core/src/client/wr_config.c` are then tuned. Rough shape of the iPXE arena: 4 connections x (4 KiB ring + 8 KiB control + 8 KiB encode) is about 80 KiB, one handshake slot 16 KiB, tickets and keys a few KiB; the bulk region is one 1 MiB message slot. The iPXE heap headroom next to iPXE's own users is unmeasured (risk R1).

### 5.3 Ownership

| Object | Owner | Lifetime |
|---|---|---|
| client, pools, connection buffers | arena | until `wr_client_destroy` |
| pre-auth transcripts | handshake pool (arena) | a connection borrows a slot until AUTH_SIGNATURE is verified or it fails, then it is wiped and returned |
| raw map message | bulk slot | from receipt until `wr_client_mapmsg_release` |
| keys, tickets | arena | wiped on forget, failure and destroy |
| caller I/O buffers (later) | caller | from submit to completion; the core never keeps a pointer past completion |

---

## 6. Source layout

### 6.1 What is in the tree now (the skeleton)

```
core/
  README.md
  sources.txt                       generated by core/tools/gen_sources.sh; consumed by iPXE make and msbuild
  tools/gen_sources.sh              regenerate / --check the list; refuses duplicate basenames
  include/winrbd/                   PUBLIC headers: the only thing a host includes
    winrbd.h                        umbrella
    wr_types.h  wr_port.h  wr_err.h  wr_host.h  wr_config.h  wr_key.h  wr_client.h
  src/
    util/      wri_le.h wri_cursor.h wri_mem.h wri_misc.h wri_ctx.h  + wri_err.c (done)
    crypto/    wri_crc32c.h wri_hash.h wri_aes.h wri_prim.h
    denc/      wri_denc.h
    msgr2/     wri_m2_addr.h wri_m2_frame.h wri_m2_ctl.h wri_m2_conn.h
    auth/      wri_cx.h  + wr_key.c (stub)
    mon/       wri_mon.h + wri_mon_hosts.c (stub)
    client/    wri_client.h  + wr_client.c (stub), wr_config.c (profiles, done)
harness/
  CMakeLists.txt  cmake/WrWarnings.cmake
  tools/         check_no_libc.sh check_no_globals.sh
  test/          test_<module>_<what>.c   (globbed)      test/support/  wrt.h wrt_util.c wrt_json.c (+ sim peers later)
  fuzz/          fuzz_<target>.c (globbed), fuzz_replay_main.c, seeds/<target>/
  host/          wrl_host.h (Linux host interface); wrl_sys.c, wrl_loop.c, tools/ come with the modules
  vectors/       (existing) committed vectors and the public capture set
```

The **headers are the frozen interfaces** between modules. The `.c` stubs return `WR_E_UNSUPPORTED` so the public API links and tests can assert the contract; each implementation wave replaces its stubs and adds its files. Header functions without a definition yet are declarations only; a module owner may add helpers to the headers it owns but must not change a signature another module uses without the integrator's say.

### 6.2 The planned core tree (end of this run)

```
core/src/
  util/     wri_cursor.c wri_mem.c wri_misc.c wri_ctx.c wri_err.c
  crypto/   wri_crc32c.c wri_crc32c_tab.inc wri_sha256.c wri_sha512.c wri_hmac.c wri_aes.c wri_aes_cbc.c wri_cts.c wri_prim.c
  denc/     wri_denc.c
  msgr2/    wri_m2_addr.c wri_m2_banner.c wri_m2_preamble.c wri_m2_rx.c wri_m2_tx.c wri_m2_ctl.c wri_m2_hdr2.c wri_m2_preauth.c
            wri_m2_conn.c wri_m2_conn_hs.c wri_m2_conn_msg.c
  auth/     wri_cx_cipher.c wri_cx_envelope.c wr_key.c wri_cx_ticket.c wri_cx_client.c wri_cx_renew.c
  mon/      wri_mon_msgs.c wri_monmap.c wri_mosdmap_hdr.c wri_mon_hosts.c wri_mon.c wri_mon_hunt.c wri_mon_maps.c
  client/   wr_client.c wri_client_conn.c wri_client_mem.c wr_config.c
```

Part B adds `crush/`, `osdmap/` and `core/crush_ln/` next to these (section 17.1); `osd/` and `rbd/` come with later milestones.

### 6.3 Dependency order

`util < crypto < denc < { msgr2, auth } < mon < client`. `msgr2` reaches `auth` only through the `wri_auth_ops` interface and `mon` reaches `msgr2` only through `wri_m2_upper` and `wri_mon_link`, so each layer is testable with a stub of the one above and below. Nothing in `core/src/` includes a host header. A later include-lint can enforce the order.

### 6.4 One source list, three build systems

- **CMake (harness):** globs `core/src/**/*.c`; no edit is needed to add a module.
- **iPXE make:** the glue (later, `ipxe/`) reads `core/sources.txt`, defines `WR_HOST_CONFIG_HEADER` for `FILE_LICENCE`, and links `core/crush_ln/` as a separate object. No generated sources, no autoconf.
- **msbuild / WDK:** a `.vcxitems` generated from `core/sources.txt` by a small script, checked for drift in CI; compiled as C with `/kernel`.

The ctest `core_sources_in_sync` fails if the committed list is stale; the integrator regenerates it after each wave.

---

## 7. Module interfaces

The authoritative text is the header of each module (listed in 6.1); this section records the rules that cross module boundaries and are easy to get wrong.

### 7.1 util (`wri_le.h`, `wri_cursor.h`, `wri_mem.h`, `wri_misc.h`, `wri_ctx.h`)

- **Cursors.** `wri_rd` / `wri_wr` carry a sticky first-failure-wins `err`. A reader past the end returns zeros and records `WR_E_TRUNCATED`; a decoder reads a whole structure and checks `wri_rd_ok` once. `wri_rd_sub(r, n)` consumes `n` bytes from the parent and returns a bounded reader over them, which is how versioned envelopes skip unknown trailing bytes. `wri_rd_count(r, max, elem_min)` is the only way to read a list count: it rejects counts above `max` and counts that cannot fit in the bytes left, so a hostile `0xFFFFFFFF` cannot cause a long loop. Writers never write past `cap` and set `WR_E_TOOBIG`.
- **Memory.** `wri_arena` (init only), `wri_pool` (u32-indexed, zeroed on get, `WRI_NIL` when empty, high-water mark), `wri_ring` (receive staging with contiguous write and read spans).
- **`wri_ctx`** is the environment every stateful module receives: a copy of the host ops and the config, plus `now` which only `wr_client_run` writes. `wri_random` fails with `WR_E_HOST_RANDOM`; `WRI_LOG` compiles away above `WR_LOG_MAX_LEVEL`; `WRI_ERRINFO` records the first failure with module, source line and a static string.

### 7.2 crypto (`wri_crc32c.h`, `wri_hash.h`, `wri_aes.h`, `wri_prim.h`)

Reference functions are `wri_crc32c`, `wri_sha256_*`, `wri_sha384_*`, `wri_hmac_sha256/384`, `wri_aes_*`, `wri_cts3_enc/dec`. Protocol code calls only the `wri_p_*` dispatchers. CRC-32C is the **raw** update (`msgr2.md 2.5`): seed 0 for the preamble, `0xFFFFFFFF` for every segment. Known answers over `123456789`: `0x1CF96D7C` (seed `0xFFFFFFFF`), `0x58E3FA20` (seed 0); the textbook CRC-32C `0xE3069283` is the first one XOR `0xFFFFFFFF`. CTS is built on `wri_p_aes_cbc_*` only.

### 7.3 denc and addresses (`wri_denc.h`, `wri_m2_addr.h`)

Envelope open returns the body as a sub-reader (so unknown trailing bytes are skipped automatically) and refuses `struct_compat` above what the caller supports. `wri_eaddr` keeps the exact marker-1 wire bytes of an address because the server compares addresses **bytewise** and `target_addr` in CLIENT_IDENT must be copied unchanged from the map, nonce included (`msgr2.md 3.6`). Decoded families are `WR_AF_IPV4/IPV6`; the Linux numbers 2 and 10 exist only on the wire. Marker-0 (legacy sockaddr) addresses are refused.

### 7.4 msgr2 framing (`wri_m2_frame.h`)

- **Receive parser** `wri_m2_rx`: states banner head, banner payload, preamble, segment 0 (+ inline CRC), segments 1..3, epilogue. The owner feeds it through `window` / `commit` (same shape as the public pump) and drives it with `step(budget)`, which returns an event: `BANNER`, `SEG0`, `FRAME`, `ABORTED`, `ERROR`. The parser never advances past an event by itself. After `SEG0` the owner reads the verified descriptor and segment 0 and may choose **sinks** for segments 1..3 (`wri_m2_rx_sink`), which is how a MESSAGE's front lands in a monitor slot and, later, how read data lands in a caller buffer. No sink = discard. CRC is computed as bytes land; on any error the content of a sink is undefined (zero-copy contract, 3.3 item 6).
- **Ring and direct windows.** Small elements are staged through a `wri_ring`; a large segment with a sink and an empty ring is received straight into the sink. This avoids both a copy of data and a `recv` per 32-byte preamble.
- **Transcript tap.** `step` reports every raw consumed byte, in wire order, to an optional `log_fn`; the builder reports every raw byte it appends. That is how the pre-auth transcripts are collected with no knowledge of the handshake.
- **Validation** on every frame: preamble CRC (seed 0), `nseg` 1..4, last segment non-empty when `nseg > 1`, tag 1..22, flags and reserved zero, per-segment length within its sink cap, inline segment-0 CRC, epilogue `late_status` low nibble `0xE` (complete) or `0x1` (aborted, drop silently), epilogue CRCs. Any failure is fatal for the connection; there is no resynchronisation.
- **Builder** `wri_m2_tx_frame`: segments 0 to 2 are copied into the connection's encode buffer, segment 3 (and any segment marked `ref`) is referenced from caller memory; the queue holds at most 8 iovecs and returns `WR_E_BUSY` when full.
- **Secure mode later** adds a second codec behind the same window/commit/step and builder interface (preamble 96 bytes on the wire, AES-128-GCM per part, `msgr2-secure-mode.md`); nothing above this file changes.

### 7.5 msgr2 control payloads and pre-auth (`wri_m2_ctl.h`)

Pure encoders and decoders for HELLO, AUTH_*, CLIENT_IDENT, SERVER_IDENT, KEEPALIVE2, and the 41-byte `ceph_msg_header2` (length checked, which the stock code does not do). Decoded structs borrow from the input buffer. `wri_m2_preauth` keeps two capped, independent logs (received bytes, sent bytes) from the first banner byte; `stop` freezes them before our AUTH_SIGNATURE is built; `wri_m2_sig_ours` is HMAC-SHA256 of the **received** log, `wri_m2_sig_expected` of the **sent** log, both under the raw session-key bytes (`msgr2.md 3.3`).

### 7.6 msgr2 connection (`wri_m2_conn.h`)

One lossy client connection from "TCP connected" to READY and the message flow after. It owns no memory (the client binds a ring, a control buffer, an encode buffer and a pre-auth slot). Authentication goes through `wri_auth_ops` (`begin`, `more`, `done`, `session_key`); delivery goes through `wri_m2_upper` (`plan`, `message`, `ready`, `closed`). Callbacks are synchronous inside `wri_m2_conn_step`, may call `wri_m2_conn_send_message`, and must never call `step`. The first failure is kept in `c->err` and `closed` fires once. Details of the machine are in 8.1.

### 7.7 cephx (`wri_cx.h`)

Four layers: ciphers (`wri_cx_encrypt/decrypt`, type 1 and 2, MAC verified in constant time before decrypting for type 2), the envelope (`u8 1 | u64 magic | item`, usage numbers 0x03 to 0x12), the ticket store (times converted to the local monotonic clock at receipt: `valid_until = now + validity`, `renew_at = valid_until - validity_seconds/4`), and the client machine behind `wri_cx_ops()` that serves both a monitor peer (GET_AUTH_SESSION_KEY handshake) and an OSD peer (authorizer with challenge round trip), plus in-session renewal (`wri_cx_renew_build/handle`, GET_PRINCIPAL_SESSION_KEY). The machine asks for ticket mask `0x24` (AUTH and OSD). Rules that matter: reject `global_id` 0, reject validity 0, treat any decrypt/magic/MAC failure as an authentication failure (never retried in a tight loop), and keep each key's own type.

### 7.8 monitor client (`wri_mon.h`)

Pure codecs first (`wri_monmap_decode`, `wri_mmonsubscribe_encode`, `wri_mosdmap_info_decode`, MAuth/MAuthReply), then the session machine that talks to its connection only through `wri_mon_link` (open, close, send, event) so it is testable with a fake link. Behaviour is in 8.3. The map messages it delivers are **raw**: `wr_mapmsg.front` is the msgr2 front segment exactly as received, already checksum-verified. For `MOSDMAP` the core extracts only the header facts it needs (fsid, epoch bounds, `newest_map`) without decoding maps.

### 7.9 client engine (`wri_client.h`, `wr_client.h`)

Owns the connection table (`max_conns` slots, ids carry slot+generation), the handshake pool, the cephx client, the monitor client, the event ring and the scheduler. Actions are **derived** from per-slot flags (`WANT_CONNECT`, `WANT_CLOSE`, `TX_NOTIFIED`), not queued, so the output side cannot overflow; events are a small ring that drops the oldest informational event on overflow (counted, never for `WR_EV_FATAL`). `wr_client_mem_required` is the sum of the modules' own size functions and must equal what `create` consumes (tested).

---

## 8. State machines

Convention for every machine: an enum of states in a struct together with counters and deadlines; one `step` function whose only inputs are values (bytes, events, the clock) and whose outputs go to bounded queues; **no loop waits for anything**; deadlines are fields read by the scheduler; a machine that fails records one `wr_errinfo`, asks its owner to close, and retries only through a deadline with back-off.

### 8.1 msgr2 connection (client, lossy, crc mode, revision 1)

Scope from `msgr2.md 4`: banner `ceph v2\n`, supported mask `0x1`, required `0x0`, revision-1 framing, lossy session (CLIENT_IDENT flag bit 0, cookie 0), no compression stage, no reconnect frames; a new TCP connection and full authentication after every fault.

| State | Entered when | Does | Leaves on |
|---|---|---|---|
| CONNECTING | `wri_m2_conn_open` | the client queues `WR_ACT_CONNECT` | `on_connected` |
| BANNER | connected | queue banner (26 bytes); wait for the peer's | banner head + payload verified (prefix, payload 16..64, REVISION_1 present, required mask subset of ours; `ceph v027` is `WR_E_M2_PEER_V1`) |
| HELLO | peer banner ok | send HELLO{type 0x08, peer_addr = dialled address}; wait for peer HELLO | peer type equals the dialled type (MON 0x01 / OSD 0x04), else `WR_E_M2_HELLO`; keep the address the server sees us as |
| AUTH | HELLO ok | send AUTH_REQUEST{method 2, modes [1], payload from `auth->begin`}; REPLY_MORE -> `auth->more` -> REQUEST_MORE (at most 4 rounds) | AUTH_DONE; AUTH_BAD_METHOD is terminal and carries `result` and the allowed lists in the errinfo (no silent downgrade) |
| SIG | AUTH_DONE | check the mode is one we offered (`WR_E_M2_MODE`), `auth->done`, stop the transcripts, send AUTH_SIGNATURE, compare the peer's in constant time | signature ok: wipe transcripts, return the handshake slot |
| IDENT | signature ok | send CLIENT_IDENT (addrs = one ANY-type address with the IP the server saw, port 0, our nonce; `target_addr` byte-exact; gid and `global_seq`; supported `0x3f07fffffffdffff`; required `0x0800000000000000`; flags 1; cookie 0) | SERVER_IDENT whose `addrs` contain the target byte-exact (`WR_E_M2_ADDR`); IDENT_MISSING_FEATURES and WAIT map to their errors |
| READY | SERVER_IDENT | MESSAGE and KEEPALIVE2 flow; `up->ready` | any fault |
| FAILED / CLOSING | first error | keep the first errinfo, call `up->closed` once, wait for `wr_conn_closed` | host closes |

Rules enforced in READY: MESSAGE `seq` counts from 1 and is never repeated or lowered (the stock server silently stops reading a connection that sees a repeated seq, `msgr2.md 2.9`); received messages with `seq <= in_seq` are dropped, gaps are accepted; KEEPALIVE2 is answered with the same stamp; ACK is ignored; other tags are `WR_E_M2_STATE`; nothing but handshake frames is sent before SERVER_IDENT is processed. The **handshake timeout** (config, 8 s) runs from connect to READY because the server drops unfinished connections at 10 s (`msgr2.md 3.7`).

`gid` in CLIENT_IDENT comes from the auth layer (`wri_auth_ops.ident_gid`): monitor connection with global id 0 in AUTH_REQUEST: -1; reclaiming a global id: that id; OSD connections: the monitor-assigned global id (`cephx.md 3.3`).

### 8.2 cephx client

`IDLE -> MON_SENT_REQ -> MON_SENT_AUTH -> DONE` for the monitor handshake (auth payload mode byte 10; AUTH_REPLY_MORE carries the server challenge; the answer is request header 0x0100 plus CephXAuthenticate with the challenge proof, the old ticket if reclaiming, and the want mask; AUTH_DONE carries the ticket reply, the connection secret blob and `extra` with the OSD ticket). `IDLE -> OSD_SENT_AUTHORIZER -> OSD_SENT_CHALLENGE -> DONE` for an OSD peer (authorizer, AUTHORIZE_CHALLENGE, authorizer again with `plus_one`, AUTHORIZE_REPLY with `nonce + 1`). Errors: decrypt, magic, MAC or nonce failure is `WR_E_AUTH_DECRYPT`; `-13` from the server (`WR_E_M2_BAD_METHOD` with result) is `WR_E_AUTH_DENIED`; the engine retries only after back-off and, for an OSD, once after a fresh ticket request.

Time: tickets store `valid_until` and `renew_at` in the local monotonic clock; an expired ticket is never used. Renewal first choice is in-session MAuth/MAuthReply (`cephx.md 3.6 B`); fallback is a fresh monitor session (`3.6 A`).

### 8.3 Monitor client

`IDLE -> HUNT_WAIT -> CONNECTING -> SYNC -> ACTIVE (-> RENEW) -> HUNT_WAIT ...`

- **Hunting.** Literal v2 addresses from the cluster spec, replaced by the monmap's msgr2 addresses once received. One session at a time; ranks tried in order; exponential back-off between `hunt_backoff_min_ms` and `_max_ms` with jitter from the host RNG; after a full round without success raise `WR_EV_CLUSTER_UNREACHABLE` and keep trying. Authentication failure raises `WR_EV_AUTH_FAILED` and backs off; never a tight loop.
- **On READY (state SYNC).** Send `MMonGetMap`, then `MMonSubscribe` v3 with `monmap` and a **continuous** `osdmap` subscription (start 0 on the first session, then held epoch + 1; flags 0), so no one-time re-request loop is needed (`mon-client.md 4`); expect two `MMonMap` messages and apply idempotently (ignore epoch not above the held one); ignore every other message type.
- **Delivery.** The upper-layer `plan` routes `MMonMap` and `MOSDMap` fronts into bulk slots (`mapmsg_queue` slots of `mon_msg_cap` bytes). All slots held by the consumer means `plan` offers no sink and the monitor connection stalls (backpressure) rather than dropping a map. A front above `mon_msg_cap` is discarded with `WR_E_MON_MSG_TOOBIG` recorded; the session continues (open question R2).
- **Keepalive.** KEEPALIVE2 every `keepalive_ms` (10 s) on the monitor connection; no ACK within `keepalive_timeout_ms` (30 s) means the session is dead (`msgr2.md 3.7`, `mon-client.md 3.6`).
- **Session loss.** Reset, hunt, resubscribe from `held + 1`. The consumer can ask for a different start with `wri_mon_want_osdmap` (gap handling, later).
- **Renewal.** At `wri_cx_next_renew_ms` send MAuth (type 17) with the renewal payload; handle MAuthReply (type 18) including the "again" loop; on failure open a fresh session before closing the old one (`max_conns >= 2`).
- fsid mismatch between monmap and MOSDMap drops the message; persistent mismatch is `WR_E_MON_FSID`.

### 8.4 Scheduler: `wr_client_run`

One call, fixed order, each stage bounded by the remaining work budget:

1. set `x.now`; expire deadlines (connect and handshake timeouts, hunt wait, keepalive, ticket due);
2. for each connection with committed rx bytes: `wri_m2_conn_step` (parse, CRC, dispatch to the monitor client and cephx);
3. `wri_mon_step`: hunting, subscriptions, renewal, map slots;
4. derive actions (connect, close, tx-ready) from slot flags;
5. return the earliest deadline over connections, monitor client and tickets; `more_work` if any stage ran out of budget or produced input for an earlier stage.

There is no re-entrancy: stages communicate through queues and indices inside the one engine object.

---

## 9. Implementation waves

Seven waves, 19 modules (part A; part B has its own waves in section 17). Modules of one wave touch disjoint files and can be implemented in parallel by different people; a wave depends only on earlier waves. The critical path is `util-core -> denc-addr -> m2-ctl -> m2-conn -> mon-client -> client-engine -> linux-host-loop`.

```
wave 1   util-core   crc32c   hash   aes   host-sys
wave 2   denc-addr   m2-frame   crypto-facade
wave 3   cephx-cipher   m2-ctl   mon-msgs   sim-peer-m2
wave 4   cephx-client   m2-conn   sim-peer-mon
wave 5   mon-client
wave 6   client-engine
wave 7   linux-host-loop   ci-docs-hardening
```

Ownership rules: a module owns exactly the files it lists. Headers under `core/src/` are owned by the module that implements them (the skeleton wrote their first version); an owner may add to its headers but must not change a signature another module uses without the integrator. `harness/CMakeLists.txt` needs no edit (globs). `core/sources.txt` is regenerated by the integrator after each wave with `core/tools/gen_sources.sh`. The test file naming `test_<module>_<what>.c` gives the ctest name `<module>.<what>` and the label `<module>`; the module part of the file name is the leading token (`test_m2_conn_hs.c` is ctest `m2.conn_hs`).

Test vectors are in `harness/vectors/` (see its README); the public capture set is `harness/vectors/public/`. Where a task says "skip", the test exits 77 with a reason; a skip is never used to hide a failure.

Common rules (docs/design/core-architecture.md sections 2, 6, 9): SPDX MIT + WR_FILE_LICENCE_MIT per core file, unique C basename, files <= ~500 lines, no libc/globals/recursion, cap every wire length, write from docs/spec in your own words, touch only the listed files (never harness/CMakeLists.txt or core/sources.txt), -Werror clean on gcc and clang and under -DWR_SANITIZE=address,undefined, own ctest tests pass.

### Wave 1

**util-core**

- Depends: none (skeleton only)
- Files: `core/src/util/wri_cursor.c`, `core/src/util/wri_mem.c`, `core/src/util/wri_misc.c`, `core/src/util/wri_ctx.c`, `core/src/util/wri_cursor.h`, `core/src/util/wri_mem.h`, `core/src/util/wri_misc.h`, `core/src/util/wri_ctx.h`, `harness/test/test_util_cursor.c`, `harness/test/test_util_mem.c`, `harness/test/test_util_misc.c`, `harness/test/test_util_ctx.c`, `harness/fuzz/fuzz_util_cursor.c`, `harness/fuzz/seeds/fuzz_util_cursor/`
- Task: Implement everything declared in the four util headers. Cursors (wri_rd / wri_wr): sticky first-failure-wins errors, reads past the end return 0 and set WR_E_TRUNCATED, wri_rd_sub consumes n bytes from the parent and returns a bounded sub-reader, wri_rd_count rejects count > max or count*elem_min > bytes left (overflow-safe) with WR_E_TOOBIG, writers set WR_E_TOOBIG and never write past cap, wri_wr_patch_u32 range-checked. Memory: bump arena (zeroed, align up to 64, overflow-safe, wri_arena_plan mirrors take), index pool with intrusive free list (get returns zeroed object or WRI_NIL, put ignores out-of-range, hiwater tracking), byte ring with wrap-aware write/read spans. Misc: wri_secure_zero (volatile stores), wri_ct_memeq, wri_add_sz / wri_mul_sz / wri_align_up with WR_E_OVERFLOW, wri_div_s64_u32 (native when WR_NATIVE_DIV64, else shift-subtract; also export wri_div_s64_u32_slow so tests can compare both), strict base64 decoder (RFC 4648, whitespace skipped, bad padding rejected, cap check). Ctx: wri_random (WR_E_HOST_RANDOM when the host has no source or it fails), wri_log_emit (null sink and level filter), wri_errinfo_set (first failure wins, never overwrites). You may add helpers to these headers but must not change an existing signature.
- Tests: test_util_cursor: every truncation point of a sample structure, sticky error, sub-reader boundaries, count caps with 0xFFFFFFFF, writer overflow and patch; test_util_mem: arena alignment/exhaustion/overflow, pool exhaustion/reuse/hiwater, ring wrap checked against a byte-array model over 100k random ops; test_util_misc: slow div vs __int128 on 1M random pairs incl. negatives and INT64_MIN, ct_memeq, overflow helpers at SIZE_MAX, base64 RFC 4648 vectors plus the keyring strings in harness/vectors/public/keys/*.keyring and malformed cases; test_util_ctx: failing/NULL random, level filtering, first-wins errinfo; fuzz_util_cursor: random read/write op programs must never crash or write out of bounds. Seeds committed under harness/fuzz/seeds/fuzz_util_cursor/.

**crc32c**

- Depends: none (skeleton only)
- Files: `core/src/crypto/wri_crc32c.c`, `core/src/crypto/wri_crc32c_tab.inc`, `core/tools/gen_crc32c_tab.py`, `harness/test/test_crypto_crc32c.c`
- Task: Raw CRC-32C update (no inversion; polynomial 0x82F63B78 reflected) per docs/spec/msgr2.md 2.5. Slice-by-4 with a 4 KiB const table by default, selectable byte-wise (1 KiB) or slice-by-8 through WRI_CRC32C_SLICE; unaligned-safe (byte loads, no casts of the input pointer), zero-length returns the seed. The table lives in wri_crc32c_tab.inc, generated by core/tools/gen_crc32c_tab.py (python3 standard library only, deterministic, --check mode exits 1 if the committed file differs) and committed; no run-time table build. Hosts may later override through wr_prim_ops.crc32c (dispatch is the crypto-facade module's job, not yours).
- Tests: test_crypto_crc32c: harness/vectors/msgr2/crc32c.json (all vectors and table_entries) and the crc32c block of secure/primitives.json; known answers over '123456789': seed 0xFFFFFFFF -> 0x1CF96D7C, seed 0 -> 0x58E3FA20; bitwise reference compared for every length 0..300 at start offsets 0..7 and several seeds; chaining property crc(crc(a),b) == crc(a||b); the test regenerates the tables with a bitwise loop and compares them with the included .inc.

**hash**

- Depends: none (skeleton only)
- Files: `core/src/crypto/wri_sha256.c`, `core/src/crypto/wri_sha512.c`, `core/src/crypto/wri_hmac.c`, `harness/test/test_crypto_hash.c`
- Task: SHA-256, SHA-512-core SHA-384 (init/update/final, 64-bit length counters, no recursion, context wiped in final) and HMAC-SHA256/384 over gather lists (RFC 2104; keys longer than the block are hashed first; stack contexts only, no heap, key pads wiped). The functions are in wri_hash.h; they have no failure paths. Portable table-free-ish code is fine; correctness over speed (secure mode later may plug host primitives).
- Tests: test_crypto_hash: FIPS 180-4 known answers for SHA-256 and SHA-384 (empty, 'abc', 448-bit and 896-bit messages, one million 'a'); incremental update split at every offset 0..200 equals one-shot; RFC 4231 test cases 1-7 for HMAC-SHA256 and HMAC-SHA384 (including keys and data longer than a block); iovec splitting at random cut points equals the concatenated input; empty iov list; the context is zero after final.

**aes**

- Depends: none (skeleton only)
- Files: `core/src/crypto/wri_aes.c`, `core/src/crypto/wri_aes_cbc.c`, `harness/test/test_crypto_aes.c`
- Task: AES-128/192/256 key schedule, single-block encrypt/decrypt and CBC over whole blocks (wri_aes_setkey, wri_aes_enc_block, wri_aes_dec_block, wri_aes_cbc_enc, wri_aes_cbc_dec in wri_aes.h; in == out allowed for CBC, iv never modified). Table based, no heap; document in the file header that it is not constant-time against cache attacks (architecture doc 4.3). Round keys live in wri_aes_ctx on the caller's stack or arena; setkey fails with WR_E_CRYPTO_KEY for other key lengths. Do NOT implement CTS here (crypto-facade owns wri_cts.c).
- Tests: test_crypto_aes: FIPS-197 appendix C.1-C.3 single-block vectors for all three key sizes, NIST SP 800-38A F.2.1/F.2.2 and F.2.5/F.2.6 CBC vectors, in-place vs out-of-place equality, random round trips, key-length rejection, and the CBC part of harness/vectors/cephx/cipher-type1.json (key_secret first 16 bytes, iv field, PKCS#7 padding applied by the test).

**host-sys**

- Depends: none (skeleton only)
- Files: `harness/host/wrl_host.h`, `harness/host/wrl_sys.c`, `harness/test/test_host_sys.c`
- Task: The Linux implementation of the shim and of the host-side system helpers declared in harness/host/wrl_host.h: wrl_clock (CLOCK_MONOTONIC and CLOCK_REALTIME in ms), wrl_random (getrandom(2) in a loop, /dev/urandom fallback, returns WR_E_HOST_RANDOM on failure, never a weak fallback), wrl_log_stderr (one line per record: level, module name, status name via wr_status_name, message, a0..a3 in hex; level filter from the ctx), wrl_host_ops_init (fills a wr_host_ops with random and log), wrl_mem_alloc / wrl_mem_free (64-byte aligned region for arena or bulk, zero on allocation, wiped before free), wrl_read_text_file (reads a keyring or config text file into a caller buffer, caller wipes it). Read the loop part of wrl_host.h but do not implement it (linux-host-loop module). Keys are never logged.
- Tests: test_host_sys: monotonic clock never decreases over 1000 reads, wall clock within 2 s of time(), random fills 1..64 KiB and two draws differ, injected failure path of the log filter, alignment and zeroing of wrl_mem_alloc, wipe-on-free observable through a custom hook, text file read of a temp file including a missing file error.

### Wave 2

**denc-addr**

- Depends: util-core
- Files: `core/src/denc/wri_denc.c`, `core/src/denc/wri_denc.h`, `core/src/msgr2/wri_m2_addr.c`, `core/src/msgr2/wri_m2_addr.h`, `harness/test/test_denc_envelope.c`, `harness/test/test_denc_addr.c`, `harness/fuzz/fuzz_denc_addr.c`, `harness/fuzz/seeds/fuzz_denc_addr/`
- Task: Ceph primitive encodings on the cursors (wri_denc.h): versioned envelope open (struct_v, struct_compat, struct_len; compat above supported -> WR_E_UNSUPPORTED, len above bytes left -> WR_E_TRUNCATED, body returned as a sub-reader so unknown trailing bytes are skipped), envelope begin/end writer with length back-patch, u32-length blobs/strings with a max, utime. Then entity_addr_t / entity_addrvec_t exactly per docs/spec/msgr2.md 2.8: marker 1 decode for IPv4, IPv6 and blank (elen 0 = blank), reject marker 0 (WR_E_UNSUPPORTED), struct_compat > 1, elen larger than the sockaddr for the family (WR_E_ENCODING); keep the exact marker-1 wire bytes in raw/raw_len; canonical encoder (IPv4 35 bytes, IPv6 47, blank = family 0 + elen 28); addrvec marker 2 and the marker-1 shared form, count capped at 16, at most max entries stored; equality = bytewise raw compare; Linux AF numbers 2/10 on the wire mapped to WR_AF_IPV4/IPV6; port big-endian on the wire. No allocation, every count capped.
- Tests: test_denc_envelope: every truncation, compat check, nested envelopes, skip-to-end, writer patch round trip. test_denc_addr: addresses decoded from harness/vectors/monclient/mmonmap-e3.json (monmap_hex contains v2 and v1 entries) and from the HELLO / CLIENT_IDENT / SERVER_IDENT frames in msgr2/frames-crc.json (fields give the expected values), canonical re-encode equals the original bytes, blank and IPv6 round trips, marker-0 and over-long elen rejection, addrvec with more than max entries. fuzz_denc_addr: decode then re-encode must succeed and, for canonical input, equal the input.

**m2-frame**

- Depends: util-core, crc32c
- Files: `core/src/msgr2/wri_m2_banner.c`, `core/src/msgr2/wri_m2_preamble.c`, `core/src/msgr2/wri_m2_rx.c`, `core/src/msgr2/wri_m2_tx.c`, `core/src/msgr2/wri_m2_frame.h`, `harness/tools/pcap2stream.py`, `harness/test/test_m2_frame.c`, `harness/test/test_m2_rx.c`, `harness/test/test_m2_replay.c`, `harness/fuzz/fuzz_m2_rx.c`, `harness/fuzz/seeds/fuzz_m2_rx/`
- Task: msgr2.1 crc-mode revision-1 framing exactly as declared in wri_m2_frame.h and specified in docs/spec/msgr2.md 2.2-2.6.1 and 4: banner build (26 bytes, supported 0x1, required 0x0) and head/payload validation (v1 prefix -> WR_E_M2_PEER_V1, payload cap 64, REVISION_1 required, required-mask check); preamble parse/build (CRC seed 0, nseg 1..4, last segment non-empty when nseg > 1, tag 1..22, reserved byte and flags must be 0, unused segments zero, alignments 8/8/8/4096 on send); the incremental receive parser (states banner, preamble, seg0 + inline CRC, segments 1..3, epilogue; window/commit/step shape; ring-fed with direct-to-sink windows for large segments; CRC computed as bytes land and budget-bounded; events BANNER, SEG0, FRAME, ABORTED, ERROR; late_status low nibble 0xE complete, 0x1 aborted, else fatal; per-segment caps -> WR_E_M2_FRAME_TOOBIG; transcript log callback receives every raw consumed byte in wire order; parser never advances past an event by itself; sinks 1..3 chosen between SEG0 and the next step, default discard); the transmit queue and frame builder (encode buffer plus <= 8 iovecs, segments 0..2 copied, segment 3 or any ref=1 segment referenced zero-copy, epilogue slot rules from 2.5/2.6.1, partial consume, WR_E_BUSY when full, builder reports exact appended bytes to the log callback). harness/tools/pcap2stream.py (python3 standard library only) extracts per-connection, per-direction TCP payload streams from harness/vectors/public/pcap/*.pcap (pcap and pcapng, Ethernet/IPv4/TCP, reassembly by sequence number) into files for the replay test.
- Tests: test_m2_frame: all 28 frames in harness/vectors/msgr2/frames-crc.json parse to the documented descriptor, CRCs and segment bytes, and the builder reproduces the hex byte for byte; banner vectors from handshake-skeletons.json; negative table (bad preamble CRC, nseg 0 and 5, empty last segment, tag 0 and 23, flags/reserved set, late_status 0x1 vs 0x3, bad epilogue CRC, bad inline CRC, segment above cap, v1 banner, short banner payload). test_m2_rx: feeding byte-at-a-time, in random splits and in one piece gives identical events; direct-sink mode lands data in place; budget exhaustion resumes correctly; sinks default to discard; log callback bytes equal the input stream; txq peek/consume/partial/reset semantics. test_m2_replay: run pcap2stream.py on the public captures (skip with WRT_SKIP when python3 or the pcaps are missing) and feed every server-to-client and client-to-server stream through the parser: frame boundaries, CRCs and tag sequence must match; secure-mode captures are expected to fail framing and are excluded by name. fuzz_m2_rx: arbitrary bytes into a parser started in each state; no crash, no write outside sinks, CRC-valid frames round-trip.

**crypto-facade**

- Depends: crc32c, hash, aes
- Files: `core/src/crypto/wri_prim.c`, `core/src/crypto/wri_cts.c`, `harness/test/test_crypto_prim.c`, `harness/test/test_crypto_cts.c`, `harness/test/test_crypto_diff_ossl.c`
- Task: Two things. (1) wri_prim.c: the dispatch layer of wri_prim.h: each wri_p_* call uses the host override from wr_prim_ops when the table is non-NULL, its size covers the member and the member is non-NULL, else the portable reference (wri_crc32c, wri_hmac_*, wri_aes_*). Validate key lengths before calling an override (16/32 for CBC). (2) wri_cts.c: CBC ciphertext stealing variant CS3 per docs/spec/cephx.md 2.5 built ONLY on wri_p_aes_cbc_enc/dec (so an overridden CBC gives CTS for free): n == 16 is one block; n > 16: zero-pad to a multiple of 16, CBC with the given IV, swap the last two blocks, truncate to n; decryption is the inverse (the stolen block is recovered by a one-block CBC decrypt with zero IV); n < 16 -> WR_E_CRYPTO_LEN; in == out allowed; stack scratch only (<= 64 bytes plus the key schedule).
- Tests: test_crypto_cts: harness/vectors/cephx/rfc8009-aes256-cts-hmac-sha384-192.json (all four vectors: confounder||plaintext encrypted with ke, zero IV gives aes_output) and the CTS part of cipher-type2.json, lengths 16..80 round trip, in-place, n < 16 rejected. test_crypto_prim: a fake override table counts calls; NULL table, NULL members and a short `size` fall back to the reference with identical results; bad key length rejected before the override. test_crypto_diff_ossl.c (built only when OpenSSL is found, name ends in _ossl): random-input differential tests of HMAC-SHA256/384, AES-CBC (128/256) and CTS-CS3 (EVP aes-256-cbc-cts) against OpenSSL, 10k cases each, plus CRC-32C against the bitwise reference.

### Wave 3

**cephx-cipher**

- Depends: crypto-facade, util-core
- Files: `core/src/auth/wri_cx_cipher.c`, `core/src/auth/wri_cx_envelope.c`, `core/src/auth/wr_key.c`, `harness/test/test_auth_cipher.c`, `harness/test/test_auth_key.c`, `harness/fuzz/fuzz_cx_envelope.c`, `harness/fuzz/seeds/fuzz_cx_envelope/`
- Task: Sections 1 and 2 of wri_cx.h plus the public key API (replace the stub wr_key.c): wri_cx_cipher_len, wri_cx_encrypt, wri_cx_decrypt, wri_cx_kdf, wri_cx_challenge_proof, wri_cx_seal, wri_cx_open, wr_key_from_raw / wr_key_parse_base64 / wr_key_parse_keyring / wr_key_wipe. Type 1 (docs/spec/cephx.md 2.4): AES-128-CBC with the fixed 16-byte IV 'cephsageyudagreg', PKCS#7 with a full extra block when aligned, decrypt rejects non-multiples of 16 and pad bytes outside 1..16 (WR_E_AUTH_DECRYPT). Type 2 (2.5): RFC 8009 KDF with empty context (Ke 0xAA/32 bytes, Ki 0x55/24 bytes, key = whole stored secret), 16-byte random confounder from the host RNG, CTS-CS3 with zero IV, MAC = first 24 bytes of HMAC-SHA384(Ki, 16 zero bytes || ciphertext); decrypt needs >= 40 bytes and verifies the MAC in constant time BEFORE decrypting. Envelope (2.6): u8 1 | u64 magic 0xff009cad8826aa55 | item; open requires the magic. Challenge proof (2.8): type 1 = XOR of the four full u64 LE words of the 36-byte length-prefixed ciphertext of (server||client challenge); other types = XOR of the four u64 words of HMAC-SHA256(secret, blob). Keys: base64 of {u16 type, utime, u16 len, secret}; type 1 needs len >= 16, type 2 >= 32, anything else WR_E_AUTH_KEY_TYPE / WR_E_CRYPTO_KEY; parse_keyring finds the first 'key = <base64>' line (spaces around '=' optional, CRLF tolerated). Use wri_p_* dispatch for every primitive. Wipe every temporary secret (derived keys, schedules) with wri_secure_zero; never log key material.
- Tests: test_auth_cipher: harness/vectors/cephx/cipher-type1.json and cipher-type2.json (decrypt known ciphertexts; encrypt with the vector's confounder injected through a fake host random and compare bytes; derived keys table; sealed envelopes), rfc8009 KDF outputs ke/ki, challenge-proof.json for both key types, tamper tests (flip every byte of a type-2 ciphertext: MAC failure, nothing decrypted), out_cap too small, in == out refused. test_auth_key: the throw-away keyrings in harness/vectors/public/keys/ (type 1 and type 2) parse to the expected type/len, malformed base64, wrong type, short secret, whitespace/CRLF variants, no key line, two key lines (first wins). fuzz_cx_envelope: arbitrary ciphertext into open/decrypt for both key types with fixed keys.

**m2-ctl**

- Depends: denc-addr, util-core, crypto-facade
- Files: `core/src/msgr2/wri_m2_ctl.c`, `core/src/msgr2/wri_m2_hdr2.c`, `core/src/msgr2/wri_m2_preauth.c`, `core/src/msgr2/wri_m2_ctl.h`, `harness/test/test_m2_ctl.c`, `harness/test/test_m2_preauth.c`, `harness/fuzz/fuzz_m2_ctl.c`, `harness/fuzz/seeds/fuzz_m2_ctl/`
- Task: Control-frame payload codecs and the pre-auth machinery of wri_m2_ctl.h, docs/spec/msgr2.md 2.7, 2.9, 3.3, 3.4: HELLO, AUTH_REQUEST encode, AUTH_BAD_METHOD / AUTH_REPLY_MORE / AUTH_REQUEST_MORE / AUTH_DONE / AUTH_SIGNATURE decode (and the matching encoders declared), CLIENT_IDENT encode, SERVER_IDENT decode (addrs capped at WRI_EADDRVEC_MAX stored), single-u64 and KEEPALIVE2 payloads, the 41-byte ceph_msg_header2 (length checked >= 41, extra ignored). Every vector count capped (WRI_M2_MODES_MAX stored, total capped at 16), every blob <= WRI_M2_AUTH_BLOB_MAX, trailing garbage in a fixed-field payload tolerated only where the spec says so. Pre-auth logs: two capped independent buffers, enabled from the start, append functions matching wri_m2_log_fn, overflow sets WR_E_M2_PREAUTH_TOOBIG sticky, stop() disables appending without wiping, wipe() zeroes; AUTH_SIGNATURE = HMAC-SHA256(session key, received bytes) for ours and over sent bytes for the expected server value (32 zero bytes when there is no key), via wri_p_hmac_sha256.
- Tests: test_m2_ctl: segment-0 payloads extracted from harness/vectors/msgr2/frames-crc.json (HELLO, AUTH_REQUEST, AUTH_REPLY_MORE, AUTH_DONE, CLIENT_IDENT, SERVER_IDENT, KEEPALIVE2 ...) decode to the documented fields and the encoders reproduce the bytes; header2_hex fields of harness/vectors/monclient/*.json; every truncation point; count and blob caps; AUTH_BAD_METHOD with more entries than stored. test_m2_preauth: harness/vectors/msgr2/preauth-hmac.json (both signatures verify; the two must_not_verify cases do not), overflow behaviour, stop/wipe semantics, zero-key signature. fuzz_m2_ctl: one payload per tag selected by the first byte.

**mon-msgs**

- Depends: denc-addr, util-core
- Files: `core/src/mon/wri_mon_msgs.c`, `core/src/mon/wri_monmap.c`, `core/src/mon/wri_mosdmap_hdr.c`, `core/src/mon/wri_mon_hosts.c`, `harness/test/test_mon_msgs.c`, `harness/test/test_mon_hosts.c`, `harness/fuzz/fuzz_mon_msgs.c`, `harness/fuzz/seeds/fuzz_mon_msgs/`
- Task: The pure message codecs of wri_mon.h (docs/spec/mon-client.md 2.3-2.6, 2.11, 3.1, 4) and the public mon_host parser (replace the stub wri_mon_hosts.c): wri_monmap_decode (struct_v 6..10, skip trailing by struct_len, refuse compat > 10 and v < 6 with WR_E_MON_MAP_VERSION, keep the first msgr2 address per monitor in rank order, WR_E_MON_NO_V2_ADDR when none), wri_mmonmap_front, wri_mmonsubscribe_encode (v3 body: map of name -> {start u64, flags u8} then hostname string; items encoded in the order given), wri_mosdmap_info_decode (MOSDMap v4 front header only: fsid, incremental and full epoch lists with blob lengths skipped by length, bounds, newest_map; reject header version < 2 and a non-empty removed-snaps block with WR_E_MON_PROTO; counts capped; never decode the maps), wri_mauth_encode / wri_mauth_reply_decode (cephx.md 2.11; paxos prefix version 0, session_mon -1, tid 0), and wr_mon_parse_hosts (forms of mon-client.md 3.1: bare IP, IP:port, bracketed IPv6, '[v2:ip:port,v1:ip:port]', separators comma/space/semicolon/newline, v1-only entries dropped, port defaults 3300, WR_E_MON_HOSTS_SYNTAX / WR_E_MON_NO_V2_ADDR). The MonMap and MOSDMap bodies stay opaque beyond what is listed.
- Tests: test_mon_msgs: harness/vectors/monclient/ mmonsubscribe-* (byte-exact fronts incl. hostname), mmongetmap, mmonmap-e3 (monmap_hex decodes to the documented fields), mosdmap-v4-full-e42 and the synthetic incremental vector (epochs, bounds, blob lengths), mauth-renewal-scrubbed and mauthreply-renewal-scrubbed structure, truncation at every offset, version refusals. test_mon_hosts: every accepted form and every rejection. fuzz_mon_msgs: monmap, mosdmap info and mauth reply decoders on arbitrary bytes.

**sim-peer-m2**

- Depends: m2-frame, hash, util-core
- Files: `harness/test/support/sim_m2.h`, `harness/test/support/sim_m2.c`, `harness/test/test_sim_m2.c`
- Task: A test-only scriptable msgr2 SERVER (written from docs/spec/msgr2.md 3, server behaviour as observed in the notes; not derived from the client code) used by every later connection-level test. In-memory duplex API: sim_m2_feed(server, bytes, n) / sim_m2_drain(server, out, cap); it uses the m2-frame parser/builder and wri_hmac_sha256 only (NOT m2-ctl, which is built in the same wave: it carries its own small server-side control-payload encoders/decoders). Behaviour: banner exchange (configurable supported/required masks, v1 prefix), HELLO, AUTH_REQUEST handled by a pluggable sim_auth callback table (return REPLY_MORE / DONE / BAD_METHOD with chosen payloads and a chosen session key; entity type MON or OSD), AUTH_SIGNATURE both ways over its own pre-auth transcripts, CLIENT_IDENT -> SERVER_IDENT (echoes target_addr as the first address, adds a legacy-type second address, configurable flags/features), then MESSAGE receive (records header2 and segments, enforces seq rules 1,2,3...) and send (server-initiated messages with its own seq), KEEPALIVE2 / ACK. Fault hooks: close or truncate after N bytes, corrupt the CRC of frame K, split output into 1-byte chunks, wrong AUTH_SIGNATURE, IDENT_MISSING_FEATURES, WAIT, mode 2 in AUTH_DONE, oversized frame.
- Tests: test_sim_m2: drive the sim server by hand with frames built by the m2-frame builder (a raw handshake following harness/vectors/msgr2/handshake-skeletons.json), check each fault hook, seq enforcement and keepalive echo; the self-test must not depend on any module that is built after wave 2.

### Wave 4

**cephx-client**

- Depends: cephx-cipher, denc-addr, util-core
- Files: `core/src/auth/wri_cx_ticket.c`, `core/src/auth/wri_cx_client.c`, `core/src/auth/wri_cx_renew.c`, `core/src/auth/wri_cx.h`, `harness/test/test_auth_client.c`, `harness/test/test_auth_renew.c`, `harness/fuzz/fuzz_cx_reply.c`, `harness/fuzz/seeds/fuzz_cx_reply/`
- Task: Sections 3 and 4 of wri_cx.h: the ticket store, the client machine behind wri_cx_ops(), and in-session renewal (docs/spec/cephx.md 3.1-3.8, 2.7, 2.11). Machine: begin() for a MON peer builds auth_payload = u8 10 | entity (u32 8, string id) | u64 global_id; more() handles AUTH_REPLY_MORE: CephXServerChallenge (v1, server_challenge non-zero) -> AUTH_REQUEST_MORE payload = request header 0x0100 | CephXAuthenticate{v 3, client challenge from the host RNG, proof via wri_cx_challenge_proof, old ticket blob (empty on first contact, the held AUTH ticket when reclaiming), other_keys mask 0x24}; done() decodes the mon reply: response header (request_type 0x0100, status must be 0 -> else WR_E_AUTH_RESULT), ticket reply for the AUTH ticket (msg_a under the principal key usage 0x04, ticket_enc 0 or 1 with the previous AUTH session key usage 0x05), then cbl (connection secret, empty in crc mode; secure mode not supported -> WR_E_M2_MODE) and extra (second ticket reply under the AUTH session key; a zero-length extra is legal when only AUTH was requested). Reject global_id 0 (WR_E_AUTH_GID0), validity 0, ticket larger than ticket_cap (WR_E_AUTH_TICKET_TOOBIG), any decrypt/magic/MAC failure (WR_E_AUTH_DECRYPT, no retry loop here). Tickets: times converted to the local monotonic clock at receipt (valid_until = now + validity, renew_at = valid_until - validity_seconds/4), session key keeps its own type (cephx.md 3.4). OSD peer: begin() builds the authorizer (u8 1 | global_id | service 4 | ticket blob | proof = envelope CephXAuthorize{v 2, nonce, have_challenge 0, 0} under the OSD session key usage 0x10), more() decrypts the AUTHORIZE_CHALLENGE (usage 0x11, raw ciphertext) and re-sends with plus_one, done() opens the AUTHORIZE_REPLY (usage 0x12) and requires nonce+1; session_key() exposes the key for AUTH_SIGNATURE (AUTH session key for MON, OSD ticket key for OSD). ident_gid(): -1 on a MON connection whose AUTH_REQUEST carried global_id 0, the reclaimed id when it carried one, the monitor-assigned id for an OSD connection. wri_cx_renew_build / wri_cx_renew_handle for CEPHX_GET_PRINCIPAL_SESSION_KEY (0x0200). Wipe on init failure, forget and wipe. Never log secrets.
- Tests: test_auth_client: replay the three connections of each of harness/vectors/cephx/session-type1-crc.json and session-type2-crc.json (client_stream / server_stream / expect) with the RNG injected so the client bytes equal the vector; both key types; tickets and session keys match `expect`; error table (wrong key, global_id 0, validity 0, oversize ticket, truncated reply, bad magic, status != 0); extra empty blob; ticket_enc 1 path; OSD authorizer byte layout and challenge round trip against cephx/captured-scrubbed-frames.json and captured-structure.json sizes; renew_at arithmetic with a fake clock; wipe leaves zeros. test_auth_renew: renewal request structure vs harness/vectors/monclient/mauth-renewal-scrubbed.json and reply handling vs mauthreply-renewal-scrubbed.json. fuzz_cx_reply: AUTH_DONE and AUTH_REPLY_MORE payloads against a machine with fixed keys.

**m2-conn**

- Depends: m2-frame, m2-ctl, denc-addr, sim-peer-m2, util-core, crypto-facade
- Files: `core/src/msgr2/wri_m2_conn.c`, `core/src/msgr2/wri_m2_conn_hs.c`, `core/src/msgr2/wri_m2_conn_msg.c`, `core/src/msgr2/wri_m2_conn.h`, `harness/test/test_m2_conn_hs.c`, `harness/test/test_m2_conn_msg.c`, `harness/fuzz/fuzz_m2_conn.c`, `harness/fuzz/seeds/fuzz_m2_conn/`
- Task: The connection state machine of wri_m2_conn.h, docs/spec/msgr2.md 3 and 4, with the cephx layer behind wri_auth_ops (the machine never sees cephx). Flow: open -> CONNECTING; on_connected: queue banner (counts into the sent pre-auth log) -> BANNER; peer banner verified -> send HELLO (entity type 0x08, peer_addr = dialled address) -> HELLO; peer HELLO type must be MON/OSD as dialled (WR_E_M2_HELLO), remember the address the server saw -> send AUTH_REQUEST (method 2, preferred modes [1], payload from auth->begin) -> AUTH; AUTH_REPLY_MORE -> auth->more -> AUTH_REQUEST_MORE (bounded to 4 rounds); AUTH_BAD_METHOD -> WR_E_M2_BAD_METHOD with result and the allowed lists in errinfo, no silent downgrade; AUTH_DONE: mode must be one we offered (else WR_E_M2_MODE), auth->done, stop transcripts, send AUTH_SIGNATURE, -> SIG; peer signature compared in constant time (WR_E_M2_SIGNATURE), transcripts wiped and the handshake slot released (c->pa = NULL) -> send CLIENT_IDENT (addrs: one ANY-type address with the IP the server saw, port 0, our nonce; target_addr = byte-exact dialled address; gid from auth->ident_gid(); global_seq; supported 0x3f07fffffffdffff; required 0x0800000000000000; flags 1; cookie 0) -> IDENT; SERVER_IDENT: addrs must contain target byte-exact (WR_E_M2_ADDR), keep gid, IDENT_MISSING_FEATURES and WAIT map to their errors -> READY, call up->ready. READY: MESSAGE frames (header2 >= 41 bytes, seq rules: drop <= in_seq, accept gaps, we count from 1 and never repeat/lower; the upper layer's plan() picks sinks for front/middle/data, discarding when it says so; message() fires after the frame verified), KEEPALIVE2 answered with the same stamp, ACK ignored, other tags fatal (WR_E_M2_STATE). Deadlines: handshake timeout from config, keepalive send is the monitor client's job. wri_m2_conn_send_message builds header2 (flags 3, seq, ack_seq = in_seq) + front copied + data referenced. Failure: first error kept in c->err, state FAILED, up->closed called once. Any frame in the wrong state is fatal. Never send MESSAGE or KEEPALIVE2 before SERVER_IDENT was processed.
- Tests: test_m2_conn_hs: against the sim-peer-m2 server with a test-defined wri_auth_ops (fixed session key): full happy path with the exact byte sequence checked (banner, HELLO, AUTH_REQUEST, AUTH_REQUEST_MORE, AUTH_SIGNATURE, CLIENT_IDENT fields), the transcripts match harness/vectors/msgr2/preauth-hmac.json scenario, byte-at-a-time and split delivery, handshake timeout with a fake clock, and a rejection table: v1 banner, banner without REVISION_1, bad frame CRC, wrong tag for the state, HELLO type mismatch, AUTH_BAD_METHOD with lists, AUTH_DONE mode 2, bad signature, IDENT_MISSING_FEATURES, WAIT, SERVER_IDENT without the target address, pre-auth overflow, every case asserting the status code and that nothing is sent afterwards. test_m2_conn_msg: seq numbering from 1, ack_seq, send_message only in READY (WR_E_STATE otherwise) and WR_E_BUSY when the queue is full, zero-copy data iovec, partial tx consume, keepalive answered with the echoed stamp, unknown message types discarded through plan(), oversized segment fatal, many messages in one feed. fuzz_m2_conn: random bytes into a connection placed in each state.

**sim-peer-mon**

- Depends: sim-peer-m2, cephx-cipher, mon-msgs, m2-frame, m2-ctl, util-core
- Files: `harness/test/support/sim_mon.h`, `harness/test/support/sim_mon.c`, `harness/test/test_sim_mon.c`
- Task: A test-only fake MONITOR on top of sim-peer-m2 (written from docs/spec/cephx.md 3.2, 3.6 and mon-client.md 3, from the server's point of view). cephx server side: AUTH_REQUEST (mode byte 10, entity, global_id) -> AUTH_REPLY_MORE with a server challenge -> AUTH_REQUEST_MORE: verify the proof for the configured principal key (type 1 or 2) -> AUTH_DONE with a chosen global_id (or the reclaimed one), the AUTH ticket reply (msg_a under the principal key usage 0x04), empty cbl, and `extra` with the OSD ticket (or an empty blob when only AUTH is requested), session keys/validity/blob contents configurable (short TTLs for renewal tests); wrong key -> AUTH_BAD_METHOD -13 after the challenge; -EBUSY style silent close. Monitor behaviour: MMonGetMap -> MMonMap with a configurable monmap blob (default: the one in harness/vectors/monclient/mmonmap-e3.json), a second MMonMap as the real monitor sends two; MMonSubscribe recorded and answered with MOSDMap v4 messages built from the vectors (mosdmap-v4-full-e42 for start 0, the synthetic incremental vector for later starts), continuous vs ONETIME flags honoured, a way to push a new epoch later; MAuth renewal (CEPHX_GET_PRINCIPAL_SESSION_KEY) -> MAuthReply; KEEPALIVE2 answered. Fault hooks: restart (drop all sessions and bump the monmap epoch), delayed or fragmented maps, an oversized MOSDMap front, ticket expiry, per-connection script.
- Tests: test_sim_mon: a scripted client built from the cephx-cipher and m2-frame/m2-ctl pieces (NOT the cephx machine or m2-conn, which arrive in the same wave) completes the monitor handshake with both key types, gets the documented tickets, subscribes and receives the vector maps; wrong key, renewal and restart hooks behave as documented.

### Wave 5

**mon-client**

- Depends: mon-msgs, cephx-client, m2-conn, sim-peer-mon, util-core
- Files: `core/src/mon/wri_mon.c`, `core/src/mon/wri_mon_hunt.c`, `core/src/mon/wri_mon_maps.c`, `core/src/mon/wri_mon.h`, `harness/test/test_mon_client.c`, `harness/test/test_mon_session.c`, `harness/fuzz/fuzz_mon_session.c`, `harness/fuzz/seeds/fuzz_mon_session/`
- Task: Sections 'session state machine' of wri_mon.h, docs/spec/mon-client.md 3 and 4. Hunting: literal v2 addresses from the cluster spec, replaced by the monmap once received; ONE monitor session at a time, ranks tried in order with exponential back-off between min and max config values plus jitter from the host RNG; a full round without success raises WR_EV_CLUSTER_UNREACHABLE (and keeps trying); AUTH failures (WR_E_M2_BAD_METHOD / WR_E_AUTH_*) raise WR_EV_AUTH_FAILED and back off, never a tight loop. On READY: send MMonGetMap, then MMonSubscribe v3 with {monmap start 0 (or epoch+1)} and a CONTINUOUS {osdmap start = 0 on the first session, held+1 afterwards, flags 0} (the sub_osdmap_start field, wri_mon_want_osdmap overrides), hostname empty; expect two MMonMap messages and apply idempotently (ignore epoch <= held); tolerate and ignore every other message type; the upper-layer plan() routes MMonMap/MOSDMap fronts into bulk slots (mapmsg_queue of mon_msg_cap bytes) and discards anything else, a front above mon_msg_cap is discarded with WR_E_MON_MSG_TOOBIG logged and counted (and the session keeps running: open question R2); with all slots held by the consumer the connection stalls (plan returns no sink; backpressure) instead of dropping. Each delivered slot records kind, header version/compat and newest epoch (wri_mosdmap_info_decode / MonMap epoch). Keepalive: send KEEPALIVE2 every keepalive_ms on the monitor connection, session dead if no ACK within keepalive_timeout_ms. Ticket renewal: at wri_cx_next_renew_ms use in-session MAuth (wri_cx_renew_build, WRI_MSG_AUTH) and handle MAuthReply with the 'again' loop; on failure fall back to a fresh session; events WR_EV_MON_SESSION_UP / DOWN / TICKETS_RENEWED through the link. fsid mismatch between monmap and MOSDMap: drop the message, repeated -> WR_E_MON_FSID. The machine talks to its connection only through wri_mon_link.
- Tests: test_mon_client (fake link, fake connection callbacks, virtual clock, fake RNG): hunting order and back-off sequence, first-message order and exact MMonGetMap / MMonSubscribe bytes matching harness/vectors/monclient scenario-fresh-session.json, reconnect resubscribes with held+1 and the monmap epoch (scenario-monitor-restart.json), duplicate/older MonMap ignored, slot exhaustion backpressure and release, oversize message handling, keepalive and ACK-timeout timing, renewal scheduling, unreachable and auth-failed events, no tight retry loop (count link.open calls per simulated minute). test_mon_session: the REAL m2-conn + cephx-client + sim-peer-mon wired by a small in-test byte pump (no client engine): both key types reach ACTIVE, receive the MonMap and the vector MOSDMap, survive a sim restart, renew tickets with a short TTL. fuzz_mon_session: arbitrary monitor message fronts delivered through the upper-layer callbacks of an ACTIVE session.

### Wave 6

**client-engine**

- Depends: mon-client, m2-conn, cephx-client, sim-peer-mon, util-core
- Files: `core/src/client/wr_client.c`, `core/src/client/wri_client_conn.c`, `core/src/client/wri_client_mem.c`, `core/src/client/wr_config.c`, `core/src/client/wri_client.h`, `harness/test/test_client_mem.c`, `harness/test/test_client_pump.c`, `harness/test/test_client_secrets.c`, `harness/test/test_client_api.c`
- Task: Replace the stub wr_client.c with the real engine behind wr_client.h (architecture doc 3 and 8.4). wr_client_mem_required = pure overflow-checked sum over the modules' own sizes (connection slots with ring + ctl + tx buffers, handshake pool of two preauth_cap transcripts per slot, wri_cx_client_mem, wri_mon_bulk_mem, engine struct) and must equal the bytes create actually consumes; create validates abi/size of cfg and host ops, WR_E_BUDGET if a region is too small (nothing partly initialised), copies cfg/spec/key, draws the entity nonce from the host RNG at create (WR_E_HOST_RANDOM fails create), starts in WR_CS_CREATED; destroy wipes arena secrets. wr_client_run: sets x.now, expires deadlines, steps every connection (budgeted), runs the monitor client, derives actions, returns the earliest deadline over connections, monitor client and cx. Actions are DERIVED from per-slot flags (CONNECT once, CLOSE once, TX_READY on the idle->busy edge of the transmit queue), scanned round-robin, so the output side cannot overflow; conn ids carry slot+generation and stale ids are ignored by every wr_conn_* call; wr_conn_closed releases the slot and the handshake slot, informs the connection and the monitor client; wr_conn_rx_window/commit/push and tx_peek/consume forward to the connection (rx_push loops window/copy/commit); events ring of WRI_EVENT_RING with drop-oldest-informational accounting (never drops WR_EV_FATAL); wr_client_mapmsg_peek/release forward to the monitor client; wr_client_get_state, last_error (first failure since the last success), stats with high-water marks. The monitor link hooks (open/close/send/event) are implemented here. wr_config.c: tune the three profiles from the measured footprint. Entity names: strip a leading 'client.'. Never call the host except random/log.
- Tests: test_client_mem: mem_required equals consumed bytes for all three profiles and random configs; create with arena-1 and bulk-1 fails with WR_E_BUDGET and leaves the regions untouched; the profile footprints stay inside the budgets written in the architecture doc (assert, and print the real numbers). test_client_pump: a pure in-test pump connects the engine to sim-peer-mon: full session to WR_CS_ACTIVE for both key types, action semantics (CONNECT/CLOSE/TX_READY once, stale id ignored, close then reconnect), rx window sizes and backpressure, rx_push, partial tx consume, map message peek/release and EV_MAPMSG ordering, connection reset mid-handshake leads to hunting and recovery, destroy mid-session. test_client_api: argument validation of every public entry point (NULLs, wrong abi/size, zero-sized regions). test_client_secrets: a canary key is never present in any log record (log sink scans args and message) and the arena contains no key bytes after wr_client_destroy.

### Wave 7

**linux-host-loop**

- Depends: client-engine, sim-peer-mon, host-sys
- Files: `harness/host/wrl_loop.c`, `harness/host/wrl_host.h`, `harness/host/tools/wr-monprobe.c`, `harness/test/test_host_loop.c`, `harness/test/test_lab_mon.c`, `harness/lab/live-mon.sh`
- Task: The socket pump of the Linux host (wrl_loop_* in harness/host/wrl_host.h): non-blocking sockets and poll(2), connect with the action's timeout, partial send/recv, EAGAIN and EINTR, SIGPIPE-safe, one connection per wr_conn_id, WR_ACT_CLOSE honoured then wr_conn_closed, host_errno reported, the wr_client_run / actions / tx_peek / rx_window cycle exactly as the reference loop in wr_client.h, wake-up computed from next_deadline_ms, no busy loop when idle. Tool harness/host/tools/wr-monprobe.c: connects to a monitor given on the command line (--mon ip:port --user NAME --keyring FILE [--timeout ms]), waits for WR_CS_ACTIVE, prints one line per event, the MonMap epoch and fsid (via the raw message), the newest MOSDMap epoch received, then exits 0; never prints key material. harness/lab/live-mon.sh runs it against the lab cluster with both key types (keyrings are read from a path in the environment, never from the repository).
- Tests: test_host_loop: a pthread TCP server on 127.0.0.1 backed by sim-peer-mon (real sockets): session reaches ACTIVE, map delivery, server closing mid-session leads to reconnect, connect to a closed port raises hunting/unreachable events with back-off, slow reader (1-byte server writes) and partial writes. test_lab_mon (label lab): skipped (exit 77) unless WR_LAB_MON, WR_LAB_USER_K2/WR_LAB_KEYRING_K2 (and the K1 pair) are set; with them it connects to the lab cluster for each key type, requires ACTIVE within 10 s, MonMap fsid equal to the cluster's, an MOSDMap with newest epoch >= 1, and no event of kind AUTH_FAILED.

**ci-docs-hardening**

- Depends: client-engine
- Files: `.github/workflows/harness.yml`, `core/README.md`, `harness/README.md`, `harness/fuzz/fuzz_client_session.c`, `harness/fuzz/seeds/fuzz_client_session/`, `harness/test/test_core_budgets.c`, `core/sources.txt`
- Task: Close the milestone 1-3 work: (a) .github/workflows/harness.yml building the harness with gcc and clang, with and without -DWR_SANITIZE=address,undefined, running ctest, the libFuzzer smoke (30 s per target on clang), and uploading nothing secret; (b) regenerate core/sources.txt with core/tools/gen_sources.sh and make sure ctest core_sources_in_sync passes; (c) replace the 'nothing here yet' text of core/README.md and harness/README.md with the real status (what builds, how to run tests, the module map, licence note, the hosts); (d) fuzz_client_session.c: a whole-engine target that runs a client against a byte stream produced by the fuzzer playing the monitor after a real sim-peer-mon handshake prefix, asserting no crash, no leak outside the arena and arena high-water <= budget; (e) test_core_budgets.c: a test that prints the footprint of the three profiles and the per-pool high-water marks after a full session and fails if a profile exceeds its documented budget; (f) a run of the compile matrix (gcc, clang, -m32, iPXE flags, no-libc, no-globals) and a list of any warning or budget overrun found, fixed in the owning module only after telling its owner. Do not change a module's behaviour here.
- Tests: The CI workflow itself must pass on a clean clone; test_core_budgets and the fuzz smoke runs pass; ctest total is green in all four build flavours (gcc, clang, clang+ASan+UBSan, gcc -m32 compile-only).


---

## 10. Later milestones: what is decided now so they stay cheap

These are not built in this run; they are recorded because they shape the headers that are.

**Object client (milestone 6).** One op slot pool (`max_ops`), each slot with an explicit state: `WAIT_MAP`, `WAIT_AUTH`, `HOMELESS`, `QUEUED`, `SENT`, `DONE`. Ops are encoded **at send time** from the slot (so a resend after a map change re-encodes with the new epoch and target at no extra memory) and sent in ascending tid order. Resend rules per `osd-ops.md 3.4, 3.5`: connection reset keeps the tid and bumps the attempt; a map change that moves the primary or the PG, or a skipped epoch, resends; `-EAGAIN` and redirects take a new tid; MOSDBackoff blocks and unblocks per PG range in a small bounded table. OSD sessions use the same connection table (`max_conns`), an `OSD` role and the same `wri_auth_ops` with the OSD ticket. Reserve a few op slots for control-plane ops (image open) so data ops cannot starve them. **No cancel of an in-flight write** (3.3 item 7): a write lives until a reply arrives, later ops on the same object are fenced behind it, and `IMAGE_FAILED` is the only other exit; reads may be abandoned.

**Image and I/O API (milestones 7 and 8), `wr_image.h`.**

```c
typedef struct wr_image wr_image;
typedef struct wr_image_info { uint64_t size_bytes; uint32_t object_size; uint8_t order; uint64_t features;
                               uint8_t writable; char object_prefix[48]; int64_t data_pool; } wr_image_info;
wr_status wr_image_open(wr_client *c, const char *pool, const char *name, int want_write, wr_image **out); /* async */
typedef struct wr_io_req {                    /* caller-embedded: submission never allocates */
    wr_io_kind kind; uint64_t offset; uint32_t length; void *buf; void *user;
    wr_status status;  uint32_t priv[12];     /* private, zero-initialised by the caller */
} wr_io_req;
wr_status wr_image_submit(wr_image *img, wr_io_req *req);   /* never blocks; WR_E_BUSY if the queue is full */
wr_io_req *wr_client_next_done(wr_client *c);               /* pulled completion, like every other output */
```

The open sequence and refusals follow `rbd-format2.md` 2.6 and 4.6 byte for byte; requests are cut into object extents with the default striping; missing objects read as zeros; flush is a barrier over earlier writes.

**OSDMap and CRUSH (milestones 4 and 5).** Designed in part B, sections 15 to 19, and refined from what was sketched here: decoders are pure functions over cursors; an incremental is applied by **building the next epoch in a second slot and swapping on success** (instead of validate-then-apply on one slot); the CRUSH blob is **decoded once into a compact region** (instead of kept as received with an offset index); two map slots in the bulk region (always two, the one-slot variant was rejected, 15.1); the LGPL seam is two table accessors, not one function (16.2). The raw messages part A delivers are exactly the input of those decoders.

**Secure mode (milestone 11).** `m2_codec_secure` behind the codec seam: AES-128-GCM, 16-byte key and two 12-byte nonces from the 64-byte connection secret, up to three AEAD operations per frame, secure data transmitted through a per-connection bounce buffer (the caller's write buffer must not be modified). New primitive members are added to `wr_prim_ops` behind `size`.

**Crash dump and hibernation (Phase 5).** Index-based, relocatable state keeps the option of serialising the minimum a dump-mode engine needs; nothing is built for it.

---

## 11. Error model and logging

### 11.1 Status codes

`wr_status` is `int32_t`: 0 success, `-(code)` failure. The code list is one X-macro (`WR_STATUS_LIST` in `wr_err.h`) with names and English texts, in ranges per module: 1 to 19 generic, 20 to 39 host and crypto, 40 to 79 msgr2, 80 to 99 cephx, 100 to 119 monitor client, 120 to 139 OSD map, 140 to 159 pools, 160 to 179 CRUSH, 180 to 199 placement (part B, 16.5), 200 to 239 reserved for the OSD client and RBD. `wr_strerror` and `wr_status_name` render them (static strings, no formatting, hosts localise by code). No `errno`, no exceptions, no assert that can fire on untrusted input; a decoder returns a status and never trusts a length.

### 11.2 Structured detail

```c
typedef struct wr_errinfo {
    wr_status status;  uint8_t module;  uint8_t reserved8;  uint16_t line;
    int32_t peer_result;  uint32_t conn;  uint64_t a0, a1, a2;  const char *what;
} wr_errinfo;
```

**First failure wins:** a machine stores one `wr_errinfo` and ignores later errors until reset, so a cascade (connection reset, then every op failing) does not overwrite the root cause. `a0..a2` carry context (expected and received value, offending mask); `peer_result` carries what the peer sent (for example `-13`). AUTH_BAD_METHOD puts the server's allowed method and mode lists into the errinfo so the operator is told which cluster setting to change. Messages are static English text plus numbers; the project rule that errors carry their cause is met by code, module, line, `what` and numbers.

### 11.3 Logging

`wr_log_rec {level, module, conn, status, msg (static literal), a0..a3}` goes to the host's `log` callback if any. `WRI_LOG` compiles to nothing above `WR_LOG_MAX_LEVEL` (iPXE and kernel builds keep errors and warnings only). **Never logged:** key bytes, session keys, tickets, authorizers, challenges, connection secrets, payload bytes. Frame logging is limited to tag, lengths, sequence numbers, tid and epochs. A canary test (`test_client_secrets`) fails if a known secret appears in any log record or in the arena after destroy.

---

## 12. Build, tests, fuzzing

### 12.1 Build

```sh
cmake -S harness -B build/harness -DCMAKE_BUILD_TYPE=Debug
cmake --build build/harness -j
ctest --test-dir build/harness --output-on-failure
```

Options: `-DWR_SANITIZE=address,undefined`, `-DWR_FUZZ=ON` (clang, libFuzzer), `-DWR_WERROR=OFF` (never in CI), `-DWR_WITH_OPENSSL=AUTO|ON|OFF`, `-DWR_BUILD_HOST=AUTO|ON|OFF`. Targets: `wr_core` (static library), `wr_core_internal` (include path for white-box tests), `wr_header_check` (every header compiles as the first include of a C99 translation unit), `wr_core_ipxe_flags` (gcc, iPXE-style flags), `wr_core_m32` (compile-only 32-bit, needs `gcc-multilib`), `wrt_support` (test framework), `wr_linux_host` (when `harness/host/*.c` exist).

### 12.2 Tests

- One executable per `harness/test/test_<module>_<what>.c`, registered automatically as ctest `<module>.<what>` with label `<module>` (a test using OpenSSL ends in `_ossl` and is built only when libcrypto is found; a lab test is labelled `lab` and exits 77 unless its environment is set).
- `wrt.h` is a tiny framework (`WRT_CHECK`, `WRT_CHECK_U64`, `WRT_CHECK_STATUS`, `WRT_CHECK_MEM`, `WRT_SKIP`) plus a small JSON reader and hex helpers so tests read `harness/vectors/**/*.json` in place (`WRT_VECTOR_DIR`); no Python is needed at build or test time except by the one test that replays pcaps, which skips without it.
- Mechanical gates registered by the skeleton: `core_sources_in_sync`, `core_no_libc`, `core_no_globals` (the last two are skipped in sanitizer builds, whose runtime adds symbols).
- Per module the vectors are named in section 9. Cross-module, test-only **simulators** matter most:
  - `sim-peer-m2`: a scriptable msgr2 server with fault hooks (close or truncate at byte N, bad CRC at frame K, one-byte chunks, wrong signature, v1 banner, missing features, WAIT).
  - `sim-peer-mon`: a fake monitor on top of it (cephx server side for both key types, MMonMap, MMonSubscribe -> MOSDMap from the committed vectors, renewal, restart).
  They are written from the spec notes, not from the client code, and cross-checked with the committed handshake vectors and the capture replay; milestone 9 (byte comparison against krbd on a live cluster) remains the real oracle. A simulator written by the author of the client can share the client's misunderstandings; the vectors and captures are the independent check.
- **Capture replay.** `harness/tools/pcap2stream.py` extracts per-connection TCP payload streams from the public pcaps; `test_m2_replay` feeds crc-mode streams (both directions) through the receive parser and checks frame boundaries, CRCs and tag order against the structure the Python checkers report. Secure-mode captures are excluded. Auth-dependent payloads are covered by the cephx vectors, not replay (client randoms differ).
- **Live lab** (`harness/lab/`, label `lab`, never in the default run): the lab cluster runs inside the VM `winrbd-ceph1` (monitor `10.77.0.10`, v2 port 3300, pool `winrbd`, users `client.winrbd` with an `aes256k` key and `client.winrbd-aes` with a legacy `aes` key). Keyrings are read from a path in the environment, copied to the VM only into a `0600` file outside the repository, never printed, never committed. Tests never run destructive commands on the cluster.

### 12.3 Fuzzing

`harness/fuzz/fuzz_<target>.c` defines `LLVMFuzzerTestOneInput`. With `-DWR_FUZZ=ON` (clang) it is a libFuzzer binary with ASan and UBSan; otherwise it is linked with `fuzz_replay_main.c` and ctest replays `harness/fuzz/seeds/<target>/` as `fuzzseed.<target>`, so the committed corpus is a regression test on every run. (The directory is `seeds/`, not `corpus/`, because `.gitignore` excludes `corpus/`.) Targets, one per decoder boundary: `util_cursor`, `denc_addr`, `m2_rx`, `m2_ctl`, `m2_conn`, `cx_envelope`, `cx_reply`, `mon_msgs`, `mon_session`, and the whole-engine `client_session`; part B adds `crush_dec`, `crush_map`, `osdmap_full`, `osdmap_inc` and `mapstore` (18.1). Properties asserted in every target: no crash or undefined behaviour, no read or write outside the input and sinks, memory inside the arena, and a decoder that succeeds consumed exactly what its envelope said. Proposed duration for the Phase 1 exit criterion ("agreed duration"): 60 s per target on every push, 1 h nightly, 8 CPU-hours per target before milestone 10 closes; the maintainer decides. Every crasher is minimised and committed under `seeds/`.

### 12.4 Where to run what

Developers build on the Mac or any Linux with gcc or clang and CMake 3.16+. The CI matrix is gcc, clang, clang with ASan+UBSan, and gcc `-m32` compile-only. The lab VM is for the live tests only; the source of truth is the repository, which is synced into a per-person directory on the VM for building.

---

## 13. Where the alternatives disagreed, and what was chosen

| Topic | Alternatives | Chosen, and why |
|---|---|---|
| I/O surface | (a) `rx_window/rx_commit` + `tx_peek/consume` + action queue; (b) push `net_rx(conn, bytes)` + `poll()` pulling one action; (c) explicit I/O effects (`CONNECT`, `SEND`, `RECV` with `min_bytes`, completions with ids) | **(a) plus the TX_READY hint and an `rx_push` helper from (b).** The window shape lets large segments land in place and fits WSK (post a receive into the window) and iPXE (copy from an iobuf) equally. (c) needs a descriptor per I/O, one-outstanding-per-direction rules and a `recv` per small element; its main benefit, explicit per-I/O completion for WSK, is available to a host that wraps the window in its own IRP. |
| Output queue | ring of actions vs derived from flags | **Derived from flags** (b): cannot overflow, no sizing. |
| Completions | callbacks from `run` vs pulled | **Pulled** (b, c): no re-entrancy at all; the core calls the host only for `random` and `log`. |
| Memory | one arena vs two regions | **Two regions** (a, b): iPXE needs the small hot part in `malloc()` and the large part in `umalloc()`; Windows may pass two halves of one allocation. |
| Crypto override | stateful contexts (init/update/final, host reports context size) vs stateless one-shot with the key each call | **Stateless one-shot** (a): cephx messages are small; no context sizes to negotiate; GCM streaming joins later behind `size`. HMAC is overridable (a, b) but CTS/KDF/envelope never are. |
| Time | monotonic only vs monotonic + optional wall | **Monotonic + optional wall** (a): mtime of OSD ops may need it later. |
| Errors | module-coded numbers + errinfo vs small flat codes + site ids | **Module-ranged codes + errinfo with module, line, `what`** (a and b merged). |
| Logging | static message + 4 numbers vs event id + 4 numbers | **Static literal + 4 numbers**: self-describing in a host log, still no formatting in core. |
| File names | per-module directories with short names vs globally unique `wr_*.c` | **Directories for readability, globally unique basenames** (b): iPXE's object naming. |
| Stack rule | 512 B vs 1 KiB frames | **1 KiB** (c), call depth <= 12. |
| Source list | checked-in list vs glob | **Generated list, CMake globs**, drift checked in ctest. |
| Test location | `core/tests/` vs `harness/test/` | **`harness/test/`**: `core/` stays product code only. |
| Writes after a lost connection | resend with same tid and fence vs fail the write | **Resend + fence, no cancel** (c): the only safe behaviour for a boot disk without exclusive-lock or blocklisting; recorded as a constraint on the later object client. |
| Crash-dump readiness | relocatable state vs ignore | **Index handles everywhere** (a, c) at no cost now. |
| Image/open API | image owned by the engine vs separate layer | **Engine owns the cluster session (survives image reopen); the image is a layer on top** (b): iPXE's SAN layer reopens a path after errors and the roadmap wants cached maps across a reopen. |

---

## 14. Risks and open questions

| # | Risk / question | Plan |
|---|---|---|
| R1 | **iPXE heap headroom** is unmeasured: iobufs and NIC rings share the 4 MiB heap with our arena. | Measure on a running EFI build in Phase 2; the profile numbers are estimates until the footprint test and that measurement exist. |
| R2 | **One MOSDMap can be larger than `mon_msg_cap`** (up to about 40 maps; a large cluster on iPXE). The fallback "ask for a narrow range with MMonGetOSDMap" is unverified (`mon-client.md` Q8). | v1 requires a contiguous message that fits in a bulk slot and reports `WR_E_MON_MSG_TOOBIG`; the cure is a bigger bulk budget. A streaming decoder over the ring is the escape hatch (the cursors make it local). Measure real sizes on the lab cluster early. |
| R3 | **Zero-copy lands data before the checksum is verified.** | Documented contract (3.3 item 6); completion only after verification; hosts must not expose a failed read. |
| R4 | **Reference AES is not constant time; software GCM is slow.** | Documented; override table; secure mode is milestone 11. |
| R5 | **Our own crypto must be correct.** | Known-answer tests from FIPS, RFC 4231 and RFC 8009; the committed cephx vectors; optional OpenSSL differential tests; the independent Python checkers remain the oracle for the notes. |
| R6 | **The exclusive-lock policy of a writer** (`rbd-format2.md` 4.5). | Not in this milestone. v1 writer on P1 without the lock; P1-L writes refused until confirmed on a capture. Requires watch/notify (a lingering op) in the object client later. |
| R7 | **Write ordering after a lost connection** (3.3 item 7). | Resend with the same tid, fence per object, no cancel; fault-injection test (kill the connection after the OSD received the write, send a conflicting write, check final bytes) before milestone 6 closes. |
| R8 | **Single-owner engine vs Windows I/O concurrency.** | The host worker owns the engine and queues requests to it (SLIST); decide the queue shape in Phase 3. |
| R9 | **The simulators share their author's misunderstandings.** | Written from the notes, cross-checked with vectors, captures and the lab cluster. |
| R10 | **Pool exhaustion shows as backpressure.** | Visible in the API (window 0, `WR_E_BUSY`); the simulator runs with tiny budgets. |
| R11 | **ABI churn.** | `size` and `abi` fields, `reserved[24]` in the config, `size`-gated primitive table. |
| R12 | **Spec items still marked unverified** (secure-mode details, `data_pre_padding_len` and `data_off` on OSD writes, mtime 0). | A conformance table in `core/README.md` links each to a test; lab checks when the client can write. |

Part B's risks (R-B1 to R-B11) and questions (Q7 to Q11) are in section 19.

Open questions for the maintainers (defaults stand unless answered):

- **Q1.** Ratify **C99** and **own crypto with host override** (sections 2.1, 4.2).
- **Q2.** Ratify the **two-region memory model** and the profile budgets after the first footprint run.
- **Q3.** Entity naming convention: `wr_cluster_spec.user` is the id without the type (`winrbd` for `client.winrbd`); a leading `client.` is stripped.
- **Q4.** Whether OSDs accept `mtime` 0 from a host without a wall clock (needs a lab check when writes exist).
- **Q5.** Hostname resolution stays outside the core (literal addresses): resolved by iPXE before the call, by user space on Windows and passed through the handoff table.
- **Q6.** Fuzzing duration for the exit criterion (proposal in 12.3).

---

# Part B: OSD map, CRUSH and placement (Phase 1, milestones 4 and 5)

Everything above (sections 1 to 14) is part A: the wire half. Part B is the map half. It is designed in sections 15 to 19; the skeleton of section 17.1 was filled in by the waves of section 17, and section 18.6 records what the finished code measured. The conventions of part A are unchanged: C99, no allocation, no writable globals, no recursion, `wri_` prefixes, unique C basenames, files under about 500 lines, `-Werror` clean on gcc and clang, ASan and UBSan, every decoder bounds-checked against untrusted input, every count and length compared with a budget before use. Spec notes are cited as `osdmap.md 2.5` and `crush note 3.6` (`docs/spec/osdmap.md`, `docs/spec/crush-and-placement.md`). Everything is our own code written from those notes; the one exception is the pair of CRUSH log tables of section 16.2.

| Milestone | Part B |
|---|---|
| 4. OSDMap: receive, decode the needed subset, follow incrementals or re-fetch the full map | sections 15.2 to 15.6 |
| 5. CRUSH: object name to PG to OSD set, matching `ceph osd map`, including upmap, `pg_temp`, `primary_temp`, primary affinity, reweight and out | sections 16.1 to 16.4 |
| 10 (the decoders of 4 and 5): unit tests, fuzzing, bounded memory | sections 15.3 and 18 |
| 6 and later | the object client consumes `wr_map.h` (15.7); nothing else here |

Out of scope, and how each is refused: erasure-coded pools, `indep` and MSR rules, cache tiers and stretch pools (a per-pool status, 15.2.4); the blocklist, snapshot lists and OSD-only fields (skipped by length); read-from-replica balancing (the acting primary is always used); device classes beyond what the rules already name (shadow trees are ordinary buckets, crush note 2.6).

---

## 15. OSD map: what is kept, how it is held, how it follows the cluster

### 15.1 Decisions at a glance

| # | Topic | Decision |
|---|---|---|
| B1 | Representation | Decode the subset a client needs into a **compact map slot**: one flat block of bulk memory, offset-addressed, host byte order, never a mirror of Ceph's structures. Two slots: the held map and the one being built. |
| B2 | What is kept | Per OSD: the EXISTS and UP bits, the reweight, the primary affinity and the first msgr2 address. For the pools the client **tracks by name**: the pool record and their entries in `pg_temp`, `primary_temp`, `pg_upmap`, `pg_upmap_items` and `pg_upmap_primaries`. The CRUSH map in compact form. Everything else on the wire is skipped by length. |
| B3 | Epochs | The next map is the held map plus one incremental, built in the other slot and swapped in on success. A failure keeps the held map. A gap or a failure makes the engine ask for a full map. The unit of work is one epoch per step. |
| B4 | Versions | Floors from `osdmap.md 4.1`: wrapper 7, full-map client block 9, incremental client block 8, `pg_pool_t` 29. Newer `struct_v` is accepted while `struct_compat` is within what we know, and the tail is skipped by length. |
| B5 | Memory | Every budget is a `wr_config` field. A map that does not fit fails with `WR_E_MAP_BUDGET` and the numbers. Design targets: 2,048 OSDs (iPXE), 8,192 (kernel), 32,768 (harness). |
| B6 | CRUSH data | The CRUSH blob is decoded once, when a map is built, into a compact region inside the slot (buckets, replicated rules, tunables, `choose_args`; names and classes dropped). The mapper reads that region directly; nothing is allocated per mapping. |
| B7 | Bucket algorithms | `straw2` and `straw` fully; `list` and `uniform` (with the permutation chooser) in a separate module; `tree` decoded for its items and refused where a mapping reaches it. |
| B8 | Rules | Replicated rules built from take, choose firstn, chooseleaf firstn, emit and the SET steps. `indep`, MSR and erasure rules are refused per pool by a rule audit when a map is adopted. |
| B9 | Arithmetic | Integers only. The straw2 draw uses `wri_div_s64_u32`; hashes are u32; no recursion; frames under 1 KiB; a work budget bounds every mapping. |
| B10 | `crush_ln` | The two LGPL log tables stay unchanged in `core/crush_ln/` behind two accessors. The arithmetic that uses them is MIT. |
| B11 | Hand-off | The engine owns the map store and consumes the monitor's raw map messages itself. Opt-in: `wr_config_enable_maps()`. With maps off, part A behaviour (raw delivery) is unchanged. |
| B12 | Pipeline | Exactly `crush note 3.7` / `osdmap.md 3.7`, with the reference client's choice of masking to `pg_num` first. Results per PG are cached per epoch. |
| B13 | Integrity | CRC verification of maps and incrementals is a config switch (on in the kernel and harness profiles). The transport CRC already covers the bytes in crc mode. |
| B14 | Failure reporting | A bad map keeps the held map and is reported with an errinfo. A pool the client cannot use is a **per-pool status**, not a map failure, so a cluster with one erasure pool next to the RBD pool still works. |
| B15 | Oracle | The harness gets a CLI that prints mappings in the format of Ceph's own tools; the independent Python checkers stay the second opinion. |

Rejected alternatives, once, so they are not rediscovered: (a) **mirror Ceph's structures** (pointer-rich maps and sets): needs an allocator, doubles memory, tempts line-by-line translation; (b) **one slot, mutate in place**: cannot be atomic when an incremental fails half way and stalls I/O during a full-map swap; (c) **keep the CRUSH blob as received and parse on demand**: the names, classes and the legacy name-map quirk sit between the buckets and the tunables, so the walk is not O(1) per bucket and the slot would carry about half of dead bytes; (d) **reachability pruning of buckets** (keep only what the tracked pools' rules can reach): the saving is small (shadow trees cost about 8 bytes per OSD) and a later `new_pools` change could need a bucket that was pruned, which would force a full-map fetch; (e) **keep all pools**: thousands of pool records on a large cluster for the sake of one; (f) **stream-decode the full map from the receive ring**: needs the CRUSH blob and the pool names in order of arrival and gives up the CRC; kept as the escape hatch of R-B1.

### 15.2 What is decoded and what is skipped

Legend: **K** kept in the slot; **T** kept only for tracked pools (other pools' entries are walked and dropped); **C** read to decide something, then dropped; **S** skipped by length or by walking.

#### 15.2.1 The `MOSDMap` message

The monitor client already checks the message header version (2 to 4) and the fsid, and hands the front over untouched (7.8, 8.3). The store reads it again with a cursor: `fsid` (16), `incremental_maps` (`u32` count, then per entry `u32` epoch, `u32` length, bytes), `maps` (the same shape, each blob a full map), then `cluster_osdmap_trim_lower_bound` and `newest_map` (`u32` each) and, in header version 4, the removed-snaps gap count (the monitor client has refused a non-zero one). Counts go through `wri_rd_count`; an entry whose length passes the front is `WR_E_MAP_CORRUPT`. Only `newest_map` and the two entry lists matter; the trim bound is not used (15.5 always recovers with a full map).

#### 15.2.2 Full map (`osdmap.md 2.4`)

Wrapper: legacy envelope (`struct_v` 7 or 8, compat at most 8). Inside it, in order: the **client-usable block** (own envelope), the **OSD-only block** (envelope read only for its length: whatever `struct_v` and `struct_compat` it has, it is jumped over), and for wrapper `struct_v` 8 the `u32` CRC. The client block, by row:

| Row | Field | Action | Note |
|---|---|---|---|
| 1 | fsid | K | 16 bytes |
| 2 | epoch | K | |
| 3, 4 | created, modified | S | |
| 5 | pools | T | each value is a `pg_pool_t` with its own envelope; untracked ones are jumped over (needs `struct_v` >= 5, else `WR_E_MAP_VERSION`) |
| 6 | pool_name | C | matched against the tracked names, never stored. Pools come first on the wire, so the decoder takes two passes over rows 5 and 6 (15.4) |
| 7 | pool_max | S | |
| 8 | flags | K | map flags, raw (pause and full bits) |
| 9 | max_osd | K | validated: `0 <= max_osd <= min(cfg.map_max_osd, WRI_MAP_OSD_HARD_MAX)` |
| 10 | osd_state | K | only EXISTS and UP are kept; exactly `max_osd` entries |
| 11 | osd_weight | K | exactly `max_osd` entries |
| 12 | client_addrs | K | first msgr2 entry of each vector (15.2.5); exactly `max_osd` vectors |
| 13 | pg_temp | T | |
| 14 | primary_temp | T | |
| 15 | osd_primary_affinity | K | empty = absent (all default), otherwise exactly `max_osd` entries |
| 16 | crush | K | decoded into the compact CRUSH region (16.1) |
| 17 | erasure_code_profiles | S | |
| 18 | pg_upmap | T | |
| 19 | pg_upmap_items | T | |
| 20 | crush_version | S | |
| 21, 22 | new_removed_snaps, new_purged_snaps | S | `osdmap.md 2.9`: a minimal client may ignore them |
| 23, 24 | last_up_change, last_in_change | S | |
| 25 | pg_upmap_primaries | T | block v10 only; absent below v10 |
| > 25 | newer rows | S | skipped by the block's `struct_len` |

#### 15.2.3 Incremental (`osdmap.md 2.6`)

Wrapper (legacy, 7 or 8), client block (v8 or v9), OSD-only block skipped by length, then `inc_crc` (verified when `verify_crc`) and `full_crc` (ignored: checking it needs a byte-exact re-encode of the whole map, `osdmap.md` Q4). Rows of the client block:

| Row | Field | Action | Row | Field | Action |
|---|---|---|---|---|---|
| 1 | fsid | C (checked) | 16 | new_primary_temp | T |
| 2 | epoch | K | 17 | new_primary_affinity | K |
| 3 | modified | S | 18, 19 | erasure profile changes | S |
| 4 | new_pool_max | S | 20 | new_pg_upmap | T |
| 5 | new_flags | K | 21 | old_pg_upmap | T |
| 6 | fullmap | K (decoded as a full map) | 22 | new_pg_upmap_items | T |
| 7 | crush | K (replaces the CRUSH region) | 23 | old_pg_upmap_items | T |
| 8 | new_max_osd | K | 24, 25 | removed / purged snaps | S |
| 9 | new_pools | T | 26, 27 | last up / in change | S |
| 10 | new_pool_names | C | 28 | new_pg_upmap_primary | T (v9) |
| 11 | old_pools | K | 29 | old_pg_upmap_primary | T (v9) |
| 12 | new_up_client | K (first msgr2 address) | | | |
| 13 | new_state | K (XOR on the two kept bits) | | | |
| 14 | new_weight | K | | | |
| 15 | new_pg_temp | T | | | |

XOR on the two kept bits is the same as XOR on the whole `u32` for those two bits, and the "destroy" test (EXISTS set and EXISTS in the mask) looks only at EXISTS, so dropping the other bits changes nothing (`osdmap.md 3.5` step 13).

#### 15.2.4 `pg_pool_t` (`osdmap.md 2.5`)

Legacy envelope (5, 5). Rows 1 to 52 are walked in order as far as the pool's `struct_v` has them, then the reader jumps to the envelope end (row 53 and anything newer are never read). Kept (**K**): type, size, min_size, crush_rule, object_hash, pg_num, pgp_num, flags, pg_num_pending, last_force_op_resend; the masks are computed. Read for a decision (**C**): `tiers`, `tier_of`, `read_tier`, `write_tier`, `erasure_code_profile`, the stretch fields of rows 51 and 52. Walked over (**S**): lpg numbers, last_change, snap_seq and snap_epoch, `snaps` (a map of envelopes), `removed_snaps` (an interval set), auid, crash replay interval, quotas, cache mode, `properties`, `hit_set_params` (envelope), hit-set period and count, stripe width, cache targets and ratios, old resend epochs, recency, expected objects, `use_gmt_hitset`, `fast_read`, hit-set decay, `opts` (envelope), `application_metadata`, create time, the target and merge fields of row 28, `last_pg_merge_meta` (envelope). A pool is marked **unsupported** (status `WR_E_POOL_UNSUPPORTED`, with a reason in the errinfo of the map that carried it) when: type is not 1; `tier_of` >= 0, `tiers` non-empty, or `read_tier` or `write_tier` >= 0; `erasure_code_profile` is non-empty; the stretch bucket count is non-zero; `object_hash` is not 1 or 2; `size` is 0 or above 16; `pg_num` or `pgp_num` is 0; its `struct_v` is below 29; its id does not fit 31 bits. Pool flags `POOL_SNAPS` and `EIO` are **not** reasons to refuse the pool: the flags are returned in `wr_pool_info` and the object client decides (`osdmap.md 4.3`: reads of a pool with `POOL_SNAPS` are fine, a writer must not use it).

#### 15.2.5 Addresses

Each `client_addrs` / `new_up_client` value is an `entity_addrvec_t` decoded with the part A decoder (`wri_eaddrvec_decode`, up to 8 entries stored). We keep **the first entry of type 2 (msgr2) with a usable family**: its nonce, port, family and the 16 address bytes, 24 bytes in all. The canonical marker-1 bytes that `CLIENT_IDENT.target_addr` must repeat (`msgr2.md 3.6`) are rebuilt from these fields by `wri_eaddr_from_wr`; the decoder normalises the reserved sockaddr bytes the same way, so a round trip is exact. An OSD without such an entry (never up, or v1 only) keeps family 0: the map is fine, that OSD simply cannot be contacted (`osdmap.md 4.3`).

#### 15.2.6 Versions we accept

| Structure | Accepted `struct_v` | `struct_compat` limit | What v20.2.5 writes | Outside the range |
|---|---|---|---|---|
| OSDMap wrapper and incremental wrapper | 7 and 8 (higher: skip the tail) | 8 | 8 / compat 7 | below 7: `WR_E_MAP_VERSION`; compat above 8: `WR_E_MAP_VERSION` |
| Full-map client block | 9 and 10 | 10 | 10 / compat 1 | below 9 or compat above 10: `WR_E_MAP_VERSION` |
| Incremental client block | 8 and 9 | 9 | 9 / compat 1 | below 8 or compat above 9: `WR_E_MAP_VERSION` |
| OSD-only blocks | not examined | none | 9 / compat 1 | never rejected |
| `pg_pool_t` | 29 to 32 (30 only for stretch pools, which are unsupported) | 32 | 32 / compat 5 | a **tracked** pool below 29: status `WR_E_POOL_UNSUPPORTED`; compat above 32: `WR_E_MAP_VERSION`; an untracked pool is skipped whatever its version (needs >= 5) |
| entity_addr_t | marker 1 entries in a marker 2 vector, compat 1 | 1 | as listed | marker 0: `WR_E_MAP_VERSION` |
| CRUSH blob | magic `0x00010000`, every group after the rules optional | | with or without the MSR pair | any other magic: `WR_E_CRUSH_ENCODING` |

The floors mean a cluster below `require_osd_release` reef is out (the v20 daemons refuse it anyway, `osdmap.md 2.4.2`); a client that advertises the full feature mask (`msgr2.md 4.4`) receives the canonical encodings listed in the "what v20.2.5 writes" column. The lower rows of the "since" columns are in the notes if a wider floor is ever wanted.

### 15.3 Memory model for maps

**Where.** Everything of this section lives in the **bulk region** (architecture 5.1): two map slots, `map_slot_bytes` each, carved at create time next to the monitor message slots. The only arena cost is the placement cache and the store struct (about 2 KiB). On iPXE that keeps the 4 MiB heap out of it: the bulk is `umalloc()` memory (risk R1 of part A is unchanged).

**Layout of a slot** (`wri_osdmap.h`; offsets from the slot start, all sections 4-aligned, the slot 16-aligned):

```
wri_osdmap header (236 bytes) | state u8[max_osd] | weight u32[max_osd] | affinity u32[max_osd] (only if some OSD has a non-default affinity)
| addr wri_osd_addr[max_osd] (24 bytes each) | pools wri_map_pool[n_tracked] (56 bytes each)
| pg_temp, primary_temp, pg_upmap, pg_upmap_items, pg_upmap_primaries (each: keys u64[n], offsets u32[n+1], values s32[nv])
| CRUSH region (wri_crush header, bucket table, rule table, bucket records, rules, choose_args)
```

A builder (`wri_mapbuild`) bump-carves the sections in this order and range-checks every carve against the slot; a section that does not fit fails the whole build with `WR_E_MAP_BUDGET` (errinfo: which section, bytes wanted, bytes left). Tables are sized by **counting first**: a pass over the wire rows counts the entries that belong to tracked pools, then the room is carved exactly (full map), or as held entries plus changed entries (incremental). The slot is never read before it has been zeroed or written.

**Costs.**

| Item | Bytes |
|---|---|
| per OSD, arrays | 1 state + 4 weight + 24 address = 29, plus 4 for affinity when present (33) |
| per OSD, CRUSH | about 20 to 45: the device appears in its host bucket and in one shadow bucket per device class in use (8 bytes each: item + weight); `straw` buckets cost the same; weight sets add 4 bytes per item per row |
| per `pg_temp` entry | 8 key + 4 offset + 4 per OSD = about 24 |
| per `pg_upmap_items` entry | 8 + 4 + 8 per pair = 20 for one pair, 36 for three |
| per `pg_upmap` entry | 8 + 4 + 4 per OSD = about 24 |
| per `primary_temp` / `pg_upmap_primaries` entry | 8 + 4 + 4 = 16 |
| tracked pools | 56 each |

The wire size of the same information is larger: for a booted OSD a full map carries about 0.43 KiB (derived: a client address vector 75 bytes with its v2 and v1 entries, three more address vectors for the heartbeat and cluster addresses, the OSD info, extended info and uuid in the OSD-only block, about 310 bytes there; 87 in the client block; about 40 of CRUSH names and items), so **0.45 KiB per OSD** is the planning figure. What we measured on the lab: a full map of 3 booted OSDs and 2 pools is 3,156 bytes (client block 1,921 of which CRUSH 715; OSD-only block 1,213), and `osdmaptool --createsimple` maps (OSDs that never booted, so without the address vectors) are 139 bytes per OSD at 1,000 OSDs (138,981 bytes) and 1.39 MB at 10,000. **Measured** by the footprint test (18.2) on generated clusters (`wrt_mapgen`: both blocks with realistic content, a few hundred upmap items), run on the finished code: the raw message costs **429 to 436 bytes per OSD** at 2,048 to 8,192 OSDs without device classes and **478 to 485** with two classes in use (451 and 501 at 1,000 OSDs; 487 and 539 at 100, where the fixed part of the map weighs more), against the 461 bytes of the planning figure: within 7 % below and 5 % above it at the design sizes. The compact slot costs 50 to 57 bytes per OSD without classes and 72 to 80 with two (the 78 of the table above, with classes). The profile numbers below did not move: the measurement is inside the 10 % band at the design sizes, so `wr_config_enable_maps()`, `core_budgets.h` and this table stand as designed (`core.budgets` prints the footprint rows: ipxe 112.8 KiB arena and 1,542 KiB bulk, kernel 501.7 KiB and 10,246 KiB, harness 3,065.9 KiB and 40,968 KiB).

**Budgets per profile** (`wr_config_enable_maps()`; bulk region unless stated):

| Field | ipxe | kernel | harness |
|---|---|---|---|
| `mon_msg_cap` (part A) | 1 MiB | 4 MiB | 16 MiB |
| `map_slot_bytes` (two slots) | 256 KiB | 1 MiB | 4 MiB |
| `map_max_osd` | 2,048 | 8,192 | 32,768 |
| `map_pools` (tracked pools) | 2 | 4 | 8 |
| `map_pg_cache` (arena, 152 bytes each) | 32 | 256 | 4,096 |
| `crush_work_max` (item draws per mapping) | 200,000 | 1,000,000 | 4,000,000 |
| `map_verify_crc` | 0 | 1 | 1 |
| `map_refetch_ms` | 1,000 | 1,000 | 1,000 |
| **bulk, with maps** | 1,542 KiB (was 1,030) | 10,246 KiB (was 8,198) | 40 MiB (was 32) |
| **arena, with maps** | about 113 KiB (was 106) | about 502 KiB (was 462) | about 3.0 MiB (was 2.4) |

**The largest cluster each profile supports.** Two limits apply, and the first one to fail is reported by name:

| | ipxe | kernel | harness |
|---|---|---|---|
| bound by the raw full-map message (`mon_msg_cap` / 0.45 KiB per booted OSD) | about 2,300 OSDs (measured 2,160 with two device classes, 2,400 without) | about 9,100 (8,770 to 9,780) | about 36,000 (35,100 to 39,100) |
| bound by the compact slot (75 % of the slot / about 78 bytes per OSD with CRUSH, the rest for tables) | about 2,500 | about 10,000 | about 40,000 |
| design target = `map_max_osd` | **2,048** | **8,192** | **32,768** |

So an iPXE client boots from clusters of up to about two thousand OSDs and tracks two pools; beyond that, the first failure is `WR_E_MON_MSG_TOOBIG` (the message) and, past it, `WR_E_MAP_BUDGET`. A larger iPXE cluster needs a larger `mon_msg_cap` (1 MiB more bulk per 2,300 OSDs) or the escape hatch of R-B1 (decode the prefix of an oversize full map, which moves the limit to the slot: 512 KiB slots would take about 5,000 OSDs for 0.5 MiB more bulk instead of 3 MiB). Everything else in the ipxe row fits the part A budgets with the exception of the bulk ceiling, which `core_budgets.h` raises to 1.5 MiB + 64 KiB when the glue lands; the kernel arena stays under its 512 KiB budget and the harness bulk cap moves from 40 to 48 MiB. Measured on the generator: 2,048 OSDs with two device classes are a 994,077-byte message (94.8 % of the 1 MiB cap) and a 162,748-byte slot (62 % of 256 KiB); 8,192 OSDs with two classes are 3,918,397 bytes (93.4 % of the kernel cap) and 592,956 bytes (57 % of its 1 MiB slot). The margin at the design size is the message cap, about 5 %: an iPXE deployment near 2,000 OSDs with many device classes should raise `mon_msg_cap`.

When a map does not fit, the failure is `WR_E_MAP_BUDGET` with the section and the byte counts in the errinfo. With no map yet that is fatal (`WR_EV_FATAL`, nothing a retry changes); with a held map the held map keeps serving, the failure is counted and reported with `WR_EV_MAP_RESYNC`, and the store keeps retrying with back-off (15.5): the object client must not send I/O for long on a map it knows is stale (R-B5).

**Stack and scratch.** No decoder or mapper frame exceeds 1 KiB. Working sets that would be large (the mapper's three arrays of 16 results, the permutation scratch of 256 entries) are in `wri_crush_ws` inside the store (708 bytes), not on the stack. The decoders need no scratch: they read the wire and write the slot directly, so the largest transient is the incremental index (29 offsets, under 128 bytes).

### 15.4 Decoders

All decoders are pure functions of (`wri_mapcfg`, input bytes, source map, destination slot) and live in `wri_osdmap_dec.h`: no store, no clock, no allocation. On any failure the destination is left with `magic` 0 and the source map is untouched, which is all that "atomic" needs (15.5). Errors carry an errinfo (`what`, the offset of the failure in `a0`, expected and got in `a1` and `a2`).

**Full map (`wri_osdmap_decode_full`).**

1. Wrapper envelope (legacy, 7 and 8); client block envelope (v >= 9, compat <= 10); remember the OSD-only block's length.
2. Rows 1 and 2. If `verify_crc`, run the CRC (`osdmap.md 2.4.5`: raw CRC-32C, start `0xFFFFFFFF`, no final inversion, over the whole wrapper except the CRC field) before building anything.
3. Rows 5 and 6 in two passes over copies of the reader: pass one walks the pools map skipping every record by its envelope and reads `pool_name`, matching each name against `cfg` to learn the ids of the tracked pools; pass two decodes only those records (`wri_pool_decode`), into `pools[k]`. A tracked name that is not in the map gives `present = 0`.
4. Rows 8 to 12 and 15: flags, `max_osd`, then the per-OSD arrays with their length checks (`osdmap.md 3.6`), carved and filled in one go. Rows 13, 14, 18, 19, 25: count the tracked entries, carve, fill; keys must be strictly ascending.
5. Row 16: `wri_crush_decode` straight from the wire into the CRUSH room of the slot.
6. Jump over the rest of the client block and the OSD-only block; read the CRC; check the wrapper's end.
7. For each present tracked pool: run `wri_crush_audit_rule` on its rule, and set the pool's status (16.3.5). `wri_mapbuild_finish`.

**Incremental (`wri_osdmap_apply_inc`).** A first walk of the client block records the start offset of each of its 29 rows in a small array (every row is a counted or length-prefixed value, so a walk finds the next one) and validates the structure, counts and sizes. The second walk applies the rows in the order of `osdmap.md 3.5`, which differs from the wire order (weights before state before up). Steps, with what each does to the new slot:

| Step | Rows | Effect on the new slot |
|---|---|---|
| 1 identity | 1, 2 | fsid must equal the source's (`WR_E_MAP_FSID`); epoch must be `src.epoch + 1` (`WR_E_MAP_EPOCH`) unless the incremental embeds a full map |
| 2 embedded map | 6 | non-empty: `wri_osdmap_decode_full` into the slot, then stop (nothing else is applied) |
| 3 header | 5 | epoch, flags (`new_flags >= 0` replaces) |
| 4 resize | 8 | arrays sized to `new_max_osd` (or kept), the common prefix copied; new OSDs get state 0, weight 0, affinity default, no address; shrinking drops the tail. Every OSD id of rows 12 to 14 and 17 must be below the new `max_osd`, else `WR_E_MAP_CORRUPT` |
| 5 pools | 9, 10, 11 | the tracked pool ids are re-resolved from `new_pool_names` first (a tracked name may now belong to another id, or its id may carry another name: then the pool is absent), then matching `new_pools` records replace the held ones, then `old_pools` removes (removal wins). A tracked name that gains an id whose record neither this incremental nor the held map has: `WR_E_MAP_RESYNC` (the store asks for a full map) |
| 6 weights | 14 | store; a non-zero weight also sets EXISTS (`osdmap.md 3.5` step 11: this is how a new OSD comes into being) |
| 7 affinity | 17 | create the array filled with the default on first use, then store |
| 8 state | 13 | XOR on the two kept bits, mask 0 meaning "toggle UP"; EXISTS toggled on an existing OSD is a destroy: state 0, address cleared, affinity default |
| 9 up | 12 | set EXISTS and UP, store the first msgr2 address |
| 10 temps | 15, 16 | `pg_temp` (empty vector removes) and `primary_temp` (-1 removes) merged into the sorted tables |
| 11 upmaps | 20 to 23, 28, 29 | for each of `pg_upmap`, `pg_upmap_items`, `pg_upmap_primaries`: upserts first, removals second |
| 12 CRUSH | 7 | non-empty: decode into the slot; empty: copy the held region |
| 13 audit | | recompute every tracked pool's status (a pool or the CRUSH map may have changed) |

The sorted tables are **merged**, not edited: the held table (sorted) and the incremental's list (sorted on the wire) are walked together and the result is appended to the new slot's table. An incremental whose list is not strictly ascending is `WR_E_MAP_CORRUPT`: the notes confirm that every container is written in key order (`osdmap.md 2.1`), and a client that does not rely on it would need a sort buffer.

### 15.5 Following the cluster: the map store

The store (`wri_mapstore.h`, `core/src/osdmap/wri_mapstore*.c`) owns the two slots and the policy. It knows nothing of connections: it reads monitor map messages through a small `wri_map_io` (peek, release, `want_osdmap`, `event`) that the engine glue implements over the monitor client, so a scripted fake can drive it in tests.

**State.** `have_map`, `cur` (which slot is held), `epoch`, `newest_seen`, a cursor into the open message (offsets of the next incremental and the next full map and how many of each remain), `want_full`, `refetch_at_ms`, `backoff_ms`, `fail_streak`, counters, the first errinfo since the last applied epoch.

**One step** (`wri_mapstore_step`, called by `wr_client_run` after the monitor step, 15.6):

1. No message open: peek the oldest monitor map message. An MMonMap is released unread (the monitor client has adopted it). For an MOSDMap: the fsid must equal the held map's (else count and drop it, `n_fsid_drop`); set the cursor.
2. Pick the next entry in epoch order from the two lists (incrementals and full maps interleave by epoch). Skip entries with epoch <= `epoch` (counted). Then:
   - **full map**: `wri_osdmap_decode_full` into the free slot; on success swap;
   - **incremental** with epoch `epoch + 1`: `wri_osdmap_apply_inc(held, inc)` into the free slot; on success swap;
   - **incremental** with a larger epoch (a gap), or any incremental with no map held: set `want_full`, drop the rest of the message;
   - on any failure: record the errinfo, count it, set `want_full`, drop the rest of the message (the held map stays).
3. After a swap: `epoch` advances, the placement cache needs no flush (its entries carry the epoch), and `WR_EV_MAP` is raised (coalesced: at most one event per step, carrying the newest epoch). `fail_streak` and `backoff_ms` reset.
4. When the cursor is exhausted (or the rest was dropped): release the message.
5. If `want_full` and `now >= refetch_at_ms`: `want_osdmap(0)`, count `n_resync`, raise `WR_EV_MAP_RESYNC` with the cause, `refetch_at_ms = now + backoff_ms`, `backoff_ms` doubles up to 32 s (starting at `map_refetch_ms`).
6. Return whether more is ready (an open message or a waiting one), so the scheduler runs again at once; at most one epoch of work is done per call, bounded by the work budget.

**Why a full map is the only recovery.** `osdmap.md 3.2` also allows asking for the missing epochs, but the monitor silently raises a too-low start to "last sent + 1" (`osdmap.md 2.3`), so a request for epochs that were sent but not applied returns nothing. A request with start 0 is always answered with a full map of the newest epoch. The full map costs at most `mon_msg_cap` bytes once per failure, and failures are rate-limited.

**Atomicity.** A step either swaps `cur` or leaves everything as it was: the held map is never written; the next map is built in the other slot, and the slot is only visible once `magic` is set and `cur` flips. Queries return plain structs (nothing points into a slot), so the swap cannot invalidate what a caller holds. Pointers into the held map (`wri_mapstore_map`) are valid until the next step.

**The first map.** With no map held only full maps are used, and an incremental is ignored. If the first full map fails with a status no retry can change (`WR_E_MAP_BUDGET`, `WR_E_MAP_VERSION`) the store raises `WR_EV_FATAL` once and stops asking; for a transient one (`WR_E_MAP_CORRUPT`, `WR_E_MAP_CRC`) it keeps retrying under the back-off.

**Tracked pools after the first map.** `wr_client_pool_track` for a name that the held map has not been decoded with sets `want_full`: the next full map resolves it (a map built without that name has no record to apply an incremental to).

**The monitor's own bookkeeping** (`wri_mon.osdmap_have`, `sub_osdmap_start`) counts epochs *received*, not applied; `wri_mon_want_osdmap(0)` resets both, which is exactly what a full re-fetch needs. A reconnect after a session loss resubscribes from received + 1 as before; the held slot of an unconsumed message stays held, so no epoch is lost.

### 15.6 Handing the monitor's messages to the map module

Today (part A) the monitor client fills a bulk slot with each `MMonMap` / `MOSDMap` front, raises `WR_EV_MAPMSG`, and the host peeks and releases. With maps enabled the engine itself is the consumer:

- `wri_client` embeds a `wri_mapstore`; `wr_client_mem_required` adds the store's arena (cache) and bulk (two slots) to the sums (the sizes come from `wri_mapstore_mem`, the same layout routine as create, so the exactness test of part A keeps holding).
- The monitor link's `event` hook swallows `WR_EV_MAPMSG` when maps are on (the store polls the slots itself), and `wr_client_mapmsg_peek` then returns 0 so that there is one consumer, not two.
- `wr_client_run` gets one more stage between the monitor step and the derived actions: `wri_mapstore_step`; its `more_work` result joins the others, and `wri_mapstore_deadline` joins the earliest-deadline computation (a rate-limited re-request).
- The store's `io` adapter is five lines each: `peek` = `wri_mon_mapmsg_peek`, `release` = `wri_mon_mapmsg_release`, `want_osdmap` = `wri_mon_want_osdmap`, `event` = the client's event ring (`WR_EV_MAP` is coalescible: a pending one is updated in place, never dropped as "oldest informational").
- The front stays valid until `release`, the store holds no pointer into it past the step that decodes from it, and while a message is held the monitor connection stalls (backpressure, part A 8.3), so a slow decode slows the stream instead of losing a map.
- Maps keep serving while the monitor session is down: the held slot is independent of the session; `wr_client_map_target` works through a hunt.

### 15.7 Public API

`wr_map.h` (included by `winrbd.h`) is the whole surface; nothing points into the map, every answer is a plain struct stamped with its epoch.

| Call | Meaning |
|---|---|
| `wr_client_pool_track(c, name, &h)` | track a pool by name (at most `map_pools`); returns a small handle; may be called before the first map |
| `wr_client_map_info(c, &info)` | epoch, flags (pause, full), `max_osd`, number of OSDs up, fsid; `WR_E_MAP_NONE` before the first map |
| `wr_client_pool_info(c, h, &info)` | id, flags, size, min_size, `pg_num`, `pgp_num`, `last_force_op_resend`, and the status (`WR_OK`, or why the pool cannot be used); `WR_E_POOL_NOT_FOUND` |
| `wr_client_osd_addr(c, osd, &addr, &up)` | first msgr2 address and the UP bit of an OSD |
| `wr_client_map_target(c, h, &oid, &target)` | object to PG to `wr_target`: epoch, pool id, full hash `ps`, `pg_seed`, up and acting sets, both primaries, the acting primary's address |
| `wr_client_map_target_pg(c, h, pg_seed, &target)` | the same for a PG |
| `wr_client_map_stats(c, &stats)` | counters: epochs held and seen, full maps and incrementals applied, re-requests, failures, slot use and high-water, cache hits |
| events | `WR_EV_MAP` (epoch adopted; the object client re-targets its outstanding ops) and `WR_EV_MAP_RESYNC` (a full map was requested; `err` says why) |

Statuses an object client handles: `WR_E_MAP_NONE` (wait), `WR_E_POOL_NOT_FOUND` and a non-OK pool status (fail the image open with the reason), `WR_E_PLACE_UNMAPPABLE` (hold the op until a newer map, `crush note 3.7` step 8). The pool flags and the map flags are returned raw; **enforcing** pause, full and EIO is the object client's job (`osdmap.md 4.4`).

---

## 16. CRUSH and placement

### 16.1 The compact CRUSH map

The blob inside an OSDMap (`crush note 2.2`) is decoded once, when a map is built, into a **compact region** at the end of the slot. The format is defined in `core/src/crush/wri_crush.h` with its inline accessors, so the decoder and the mapper can be written independently. It is our own memory (host byte order, 4-byte aligned words, addressed by byte offsets from the start of the region), so structs may overlay it and the region can be `memcpy`d between slots.

```
wri_crush header (56 bytes): magic, bytes, max_buckets, max_rules, max_devices, offsets of the three tables, tunables
bucket_tab  u32[max_buckets]   offset of the bucket record of slot i (id -1 - i), 0 = hole
rule_tab    u32[max_rules]     offset of the rule record, 0 = no rule, 1 = a rule of another type (not stored)
set_tab     {s32 pool, u32 index}[n_sets]    choose_args sets; index = offset of u32[max_buckets] -> override record
bucket record  16-byte head {id, type, alg, hash, size} | items s32[size] | tail by algorithm
   straw2: weights u32[size]      straw: straws u32[size]      list: item weights u32[size], sums u32[size]
   uniform, tree: no tail
rule record    nsteps | nsteps x {op, arg1, arg2}
choose_args record   {n_pos, has_ids} | n_pos rows of size u32 weights | size s32 ids (if has_ids)
```

**What the decoder (`wri_crush_decode`) does**, one forward pass over the blob, written into the room the builder gave it:

1. Magic `0x00010000`, then `max_buckets` (at most 32,768), `max_rules` (at most 256); carve the header and the two tables, zeroed.
2. Buckets: for each slot, the algorithm marker (0 = hole); otherwise the id (must equal `-1 - slot`: the reference does not check it, we do), type, algorithm byte (must equal the marker, 1 to 5), hash byte (must be 0, rjenkins1), weight (dropped), size, items, and the algorithm tail decoded to host order, keeping only what mapping reads. Sizes above 65,535 and straw2 weights of 0x80000000 or more are refused (the reference would divide by a negative `int`; no real map has one, and refusing makes the unsigned division exact). The largest device id is tracked.
3. Rules: for each slot the present flag; `ruleset` must equal the slot (the reference calls anything else "encoding too old"); type 1 rules are stored, others leave the sentinel; steps are capped at 64 per rule. Step opcodes are *not* judged here: the audit (16.3.5) judges them against the pool that uses the rule.
4. The three name maps are walked, not stored, with the **empty-name quirk** of `crush note 2.2` (a zero length is followed by the real length) and their keys feed `max_devices`; then the tunable groups, each present only if bytes remain (absent: the legacy defaults of `crush note 2.5`); `vary_r` above 32 is refused; the three class maps are walked and dropped.
5. `choose_args`: per set the key (an `s64` pool id or -1; keys that do not fit an `s32` can never match a pool and the set is dropped), then per listed bucket the weight rows and the substitute ids. The reference silently repairs a wrong row length and asserts on a wrong `ids` size; we **reject** both (`crush note 4.3`): the slot index must be below `max_buckets`, the bucket must be straw2, the rows and ids must have the bucket's size.
6. The MSR tunable pair, if present, is skipped.
7. `max_devices` = one more than the largest item id found in the buckets, raised to one more than the largest `name_map` key (`crush note 2.4`).
8. Every bucket item either is a device id or names a slot below `max_buckets`; the region's byte count is stored in the header.

Both forms of the blob decode (`crush note 2.1`): the one inside a full map (no MSR pair) and the one from `getcrushmap` or an incremental (with the pair). Bytes left after the last known group are refused (`WR_E_CRUSH_ENCODING`, errinfo "trailing bytes"): the blob has no envelope, so a group that a newer release appends would change placement and cannot be skipped safely; refusing is better than placing objects wrongly. A `wri_crush_check` structural self-check exists for tests and fuzzing.

**Cost.** About 8 bytes per bucket item (item plus weight), 16 per bucket, 12 per rule step; names and classes, which are typically half the blob, are dropped. The flat 1,000-OSD map of `osdmaptool --createsimple` (one host, one rack, one root; measured on the lab) has a 23,332-byte blob, of which 1,000 items and weights are 8,000 bytes, and is expected to decode to about 8,200 bytes.

### 16.2 The licence seam: `crush_ln`

straw2's draw is `crush_ln(hash & 0xffff) - 2^48` divided by the weight. `crush_ln` is a fixed-point approximation of `2^44 * log2(x + 1)` driven by two tables; `RH_LH` has closed forms but `LL_tbl` has none (`crush note 3.4.2`, 63,500 of the 65,536 outputs change if it is replaced by the formula), so bit-exactness needs Ceph's table. `LICENSE` settles how: both tables stay together in `core/crush_ln/crush_ln_table.h`, **copied byte for byte** from Ceph v20.2.5 with its copyright and LGPL-2.1 notice (SHA-256 `9d0cdaca...1b1a`, in `core/crush_ln/README.md`), and nothing else of CRUSH goes there.

The directory holds exactly four files plus a README, and a test (`core.docs`) enforces it:

| File | Role |
|---|---|
| `crush_ln_table.h` | the unchanged Ceph header; declares `static __s64` tables and includes `crush_compat.h` |
| `crush_ln_table.h.license` | a REUSE-style sidecar carrying `SPDX-License-Identifier: LGPL-2.1-only`, so the copied file stays byte-identical |
| `crush_compat.h` | our own tiny stand-in for Ceph's header of that name: `#define __s64 const int64_t`, which puts the tables in read-only data (`check_no_globals.sh` forbids `.data`) without editing the table file |
| `wri_crush_lntab.c` | `wri_crush_ln_rh_lh()` and `wri_crush_ln_ll()`, two accessors returning the tables; the whole interface |

The seam differs from the one part A sketched (a single `wri_crush_ln` symbol in the LGPL directory): the arithmetic of the seven steps (`crush note 3.4.2`: normalise `x`, index the high table, multiply, index the low table, add) is **our own MIT code** in `core/src/crush/wri_crush_ln.c`, written from the note; only data crosses the boundary, and the LGPL directory stays "the tables and nothing else". `wri_crush_ln.h` declares both sides. Consequences per host: the Linux harness links the LGPL object like any other object of the core (the usual LGPL obligations apply to that file only); the Windows driver is LGPL already; iPXE tags that object `GPL2_OR_LATER` through `WR_FILE_LICENCE_LGPL21` (`wr_port.h`, defined by the glue the way `WR_FILE_LICENCE_MIT` is), as `LICENSE` describes; `core/sources.txt` lists `crush_ln/wri_crush_lntab.c`, `gen_sources.sh` and the CMake glob include the directory, `check_freestanding.sh` compiles it. The skeleton's own test `map.skel` pins the header's SHA-256 and the ends of both tables, and `core.docs` the file list; the test `crush.ln` (module crush-prim) checks the table facts of `crush note 3.4.2` (129 + 128 exact `RH_LH` entries from the closed forms, the special last entry, the 21 / 212 / 23 split of `LL_tbl`), the ten `crush_ln` known answers, and a golden digest of all 65,536 outputs computed once with Ceph's own `mapper.c` in a scratch directory outside the repository.

### 16.3 The mapper

`wri_crush_do_rule(map, in, ws, result, &n, why)` runs one replicated rule. It is a pure function of the compact map and the inputs, uses no recursion and no allocation, and keeps every frame under 1 KiB (the workspace of 708 bytes is the caller's).

#### 16.3.1 Hashes and `x`

`hash2` and `hash3` (and `hash1`, `hash4` for tests and list buckets) are the rjenkins1 mixes of `crush note 3.2.1`, `wri_str_hash_rjenkins` and the Linux dcache hash are `3.1.1` and `3.1.2`, `wri_stable_mod` and `wri_pg_mask` `3.2`. All are u32 arithmetic on the bit patterns (a negative bucket id is hashed as its two's complement). The `is_out` test, the placement seed and primary affinity always use the rjenkins `hash2`, whatever a bucket's hash byte says.

#### 16.3.2 Buckets (`wri_crush_buck.h`)

| Algorithm | Status | Where | Rule |
|---|---|---|---|
| straw2 (5) | **supported**, verified by crushtool and capture vectors | module crush-map, `wri_crush_buck.c` | draw = `(crush_ln(hash3(x, id, r) & 0xffff) - 2^48) / weight` in signed 64-bit, truncating; the first item wins ties; weight 0 never draws; choose_args weight row `min(position, rows - 1)` replaces the weight and substitute ids replace the hash input only |
| straw (4) | **supported**, verified by the in-tree known-answer files | crush-map | draw = `(hash3(x, id, r) & 0xffff) * straw`, largest wins, first wins ties |
| list (2) | **supported** after module crush-legacy; unverified by any run until then | `wri_crush_legacy.c` | walk from the last item down, `hash4(x, item, r, bucket id)`, `(h * sum) >> 16 < weight` |
| uniform (1) | **supported** after crush-legacy, buckets up to 256 items | `wri_crush_legacy.c` | the permutation chooser |
| tree (3) | decoded (items only), **refused where reached**: `WR_E_CRUSH_UNSUPPORTED` with the bucket id | audit and mapper | legacy and described as buggy in the source (`crush note 3.4.6`) |

The division goes through `wri_div_s64_u32` so a 32-bit host never needs `__divdi3` (the weight is below 2^31 by decode). The permutation chooser is also the **local-fallback** path of choose_firstn for any algorithm (it runs only when the map's `choose_local_fallback_tries` is non-zero, an Argonaut-era tunable); it is the only user of `ws->perm`, which is why buckets above 256 items are refused there rather than overflowing a stack buffer.

#### 16.3.3 The interpreter

Per run the tunables start from the map: `choose_tries = choose_total_tries + 1` (the stored number counts retries), `choose_leaf_tries = 0`, local retries, fallback retries, `vary_r` and `stable` from the map; the SET steps change these copies for the rest of the run. Steps: TAKE (a device below `max_devices` or an existing bucket, else the working set is unchanged), the six SET steps, CHOOSE_FIRSTN and CHOOSELEAF_FIRSTN (below), EMIT (append to the result up to `result_max`, empty the working set), NOOP. CHOOSE_INDEP, CHOOSELEAF_INDEP and the MSR opcodes are `WR_E_CRUSH_UNSUPPORTED`. For each working-set item a fresh `choose_firstn` call starts at output position 0, so choose_args positions restart per item (`crush note 3.6`, last notes).

`choose_firstn` follows `crush note 3.6` step by step: the rejection and collision counters (`fails_all`, `fails_here`) and the draw number `r = rep + parent_r + fails_all`; moving into a child bucket of the wrong type keeps `r`; collisions are checked against the output of this call only; chooseleaf recurses once with type 0 and `numrep = 1` when `stable` else `outpos + 1`, `parent_r = r >> (vary_r - 1)` when `vary_r` is non-zero, `tries = recurse_tries`; `is_out` applies to devices only.

**No recursion.** The "recursive" chooseleaf call is the same procedure with different parameters and exactly one level of nesting, so the interpreter implements it as **two explicit frames** (a small struct array of depth 2 and a loop) rather than a self-call; the call graph stays acyclic as `check_callgraph.py` demands, and the stack bound does not depend on the map.

**Bounds that protect against a hostile map.** (a) the descent depth counter: more than `WRI_CRUSH_DESCENT_MAX` (16) bucket steps in one descent is `WR_E_CRUSH_LOOP` (the reference loops forever on a cyclic hierarchy); (b) `ws->work`, the **work budget**, counts item draws (one per candidate item examined, whatever the algorithm); it is set from `crush_work_max` before each mapping and running out is `WR_E_CRUSH_WORK`, so `choose_total_tries` of four billion cannot stall a boot loop; the defaults are orders of magnitude above what a normal map needs (a 3-replica chooseleaf over 10 racks of 10 hosts costs a few hundred draws; all-OSDs-out costs `51 tries x 3 x 2 levels x 30` = about 9,000); (c) all index arithmetic is checked: item ids against `max_buckets` and `max_devices`, `weight_max` for `is_out`; (d) `result_max` is at most 16.

#### 16.3.4 `choose_args` (weight sets and ids)

The set is chosen **by pool id** (the set keyed by the pool id, else the set keyed -1, else none; `wri_crush_args_index`), looked up per bucket by slot. A straw2 bucket with an override uses weight row `min(position, rows - 1)` where `position` is the current output position of the choose call, and the override's ids as hash input. Because a tracked pool's id is known when a map is built, the choice costs a short loop per mapping. Unverified by any run against a real cluster (the lab map has none): vector C5 of `crush note 5.3` is in the plan (18.3).

#### 16.3.5 The rule audit and the pool status

`wri_crush_audit_rule(crush, rule, size)` walks the pool's rule and the hierarchy under every `take`, and reports, with a reason, what the mapper would fail on later: no replicated rule of that id (`WR_E_CRUSH_NO_RULE`; the errinfo says "missing" or "not replicated"), an `indep` or MSR opcode or more than 64 steps, a `take` of a missing bucket, a reachable bucket of an unsupported algorithm (tree; list or uniform before crush-legacy), a hierarchy deeper than 10 or cyclic, a uniform bucket over 256 items where the permutation is needed, tunables that need the permutation chooser while it is unsupported, `vary_r` out of range. Every time a map is built, the audit runs for each present tracked pool and the result becomes that pool's `status` (`WR_OK` or the reason), next to the pool decoder's own unsupported checks. The audit is O(buckets reachable) and runs once per map, never per I/O.

#### 16.3.6 What is refused where

| What | Refused at | Status |
|---|---|---|
| bad magic, wrong alg marker, wrong bucket id, hash byte != 0, ruleset != slot, bad `choose_args` sizes, over-limit counts, `vary_r` > 32, straw2 weight >= 2^31 | decode (the whole map is refused: the blob is corrupt) | `WR_E_CRUSH_ENCODING` |
| tree buckets, `indep` / MSR rules, rules of another type, unsupported tunables | the audit (that **pool** is unusable; other pools and the map are fine) | `WR_E_CRUSH_UNSUPPORTED` / `WR_E_CRUSH_NO_RULE` |
| a cycle, a runaway descent, an over-large work count | the mapper, per mapping | `WR_E_CRUSH_LOOP` / `WR_E_CRUSH_WORK` |

### 16.4 The placement pipeline

`wri_place.h` implements, in this order and no other (`crush note 3.7`, `osdmap.md 3.7`):

| Step | Function | Rule |
|---|---|---|
| 1 hash | `wri_place_hash` | `ps` = the pool's `object_hash` over `ns` + `0x1f` + subject (the byte `0x1f` only when `ns` is non-empty), subject = the locator key if non-empty else the name. Names are arbitrary bytes (an embedded NUL is a byte), at most 4,096 in all (`WR_E_TOOBIG`). `object_hash` 2 = rjenkins, 1 = Linux dcache, anything else is an unsupported pool |
| 2 PG | `wri_place_pg_seed` | `pg_seed = stable_mod(ps, pg_num, pg_num_mask)`; the PG key is `(pool, pg_seed)` |
| 3 seed | `wri_place_pps` | HASHPSPOOL: `hash2(stable_mod(pg_seed, pgp_num, pgp_num_mask), pool)`; legacy pool: the stable mod plus the pool id (u32 wrap) |
| 4 raw | `wri_crush_do_rule` | rule `crush_rule`, `x = pps`, `result_max = size`, weights = `osd_weight`, `weight_max = max_osd`, choose_args by pool id; then drop OSDs that do not exist (compact) |
| 5 upmap | `wri_place_upmap` | `pg_upmap`: if any listed id is a valid OSD with weight 0, **abandon the whole upmap step** (items and primaries too), else replace the list; `pg_upmap_items`: pairs in order, skip a pair if `to` is already in the list or `to` is a valid id with weight 0, else replace the first `from`; `pg_upmap_primaries`: if the OSD is valid, non-zero weight and at index >= 1, swap it to index 0 |
| 6 up | `wri_place_up_set` | drop OSDs that do not exist or are down (compact); `up_primary` = first member |
| 7 affinity | `wri_place_affinity` | only if the map has an affinity array and some up member has a non-default affinity: walk in order, reject a member as primary when `hash2(pps, osd) >> 16 >= affinity` (affinity < 0x10000), first accepted wins, else the first rejected one; rotate the chosen primary to the front (entries before it shift back one place) |
| 8 temp | `wri_place_temp` | `pg_temp` members that do not exist or are down are dropped (compact); `primary_temp` if present (no validity check), else the first temp member, else none |
| 9 acting | `wri_place_pg` | temp list non-empty: acting = temp, acting primary = temp primary; else acting = up (after affinity) and acting primary = the temp primary if a `primary_temp` exists, else the up primary |

Edge cases the tests pin: `primary_temp` with no `pg_temp` (acting = up, acting primary = the temp value, which need not be in the set); a `pg_temp` whose members are all down behaves as absent; `0x7fffffff` (NONE) in `pg_temp` and `pg_upmap` vectors and every "valid id" test bound-checked against `max_osd`, not only against 0; an OSD that exists, is down and is out; a destroyed OSD; `pg_num` not a power of two; `pgp_num != pg_num`; a pool without HASHPSPOOL; names of length 0, 11, 12, 13, 23, 24, 25 and 255; non-ASCII and namespaced names. A PG with an empty acting set is not an error for the pipeline; `wr_client_map_target` reports it as `WR_E_PLACE_UNMAPPABLE`. The reference client masks to `pg_num` before it maps and so do we; `crush note 3.2` shows both orders agree while `pgp_num <= pg_num`, which the monitor enforces.

**Cache (`wri_pgcache`, module place-cache).** A direct-mapped table of `map_pg_cache` entries in the arena, keyed by `(epoch, pool, pg_seed)`; each entry stores the up and acting sets and the primaries (152 bytes). A lookup misses whenever the epoch differs, so nothing is ever invalidated and a stale result cannot be returned; `n == 0` disables it. Objects of one image spread over all PGs, so the cache only needs to be as large as the working set of PGs, not of objects.

### 16.5 Error model for part B

Status codes (`wr_err.h`, 11.1): 120 to 139 OSD map (`WR_E_MAP_NONE`, `_FSID`, `_VERSION`, `_CORRUPT`, `_EPOCH`, `_BUDGET`, `_CRC`, `_RESYNC`), 140 to 159 pools (`WR_E_POOL_NOT_FOUND`, `WR_E_POOL_UNSUPPORTED`), 160 to 179 CRUSH (`WR_E_CRUSH_ENCODING`, `_UNSUPPORTED`, `_NO_RULE`, `_LOOP`, `_WORK`), 180 to 199 placement (`WR_E_PLACE_UNMAPPABLE`); modules `WR_MOD_MAP` (7) and `WR_MOD_CRUSH` (8) in errinfo. Texts are static English. The errinfo of a decoder failure carries `what` (the check that failed, for example "bucket id does not match its slot"), the offset in `a0`, and the numbers in `a1`, `a2`. Never logged: nothing secret exists in a map, but object names are not logged either (they can name users' data); log records carry epochs, counts and statuses only.

---

## 17. Part B implementation plan

### 17.1 The skeleton that is in the tree

Written first, so the modules below can be implemented in parallel against frozen interfaces. It builds with gcc and clang, plain and with `-DWR_SANITIZE=address,undefined`, and the existing 69 ctest tests pass unchanged (plus `map.skel`).

```
core/include/winrbd/
  wr_map.h               NEW   public API of 15.7 (included by winrbd.h)
  wr_err.h               +codes 120 to 127, 140, 141, 160 to 164, 180; wr_config.h +map fields from the reserved words,
                               wr_config_enable_maps(); wr_client.h +WR_EV_MAP, WR_EV_MAP_RESYNC; wr_port.h +WR_FILE_LICENCE_LGPL21
core/src/denc/wri_denc_map.h        legacy envelope, pg_t, varint, skip helpers                       (declarations)
core/src/crush/
  wri_crush.h            the compact format with inline accessors, decoder / audit / mapper API         (declarations + accessors)
  wri_crush_hash.h  wri_crush_ln.h  wri_crush_buck.h                                                    (declarations)
  wri_crush_legacy.c     list / uniform / permutation choosers: stubs returning WR_E_CRUSH_UNSUPPORTED
core/src/osdmap/
  wri_osdmap.h           the compact map, accessors, builder, pg tables                                 (declarations + accessors)
  wri_osdmap_dec.h       pool / full / incremental decoders and shared helpers                          (declarations)
  wri_place.h            placement pipeline, stages, cache                                              (declarations)
  wri_mapstore.h         the store and its io vtable                                                    (declarations)
core/src/client/wr_map.c  the public API: stubs returning WR_E_UNSUPPORTED
core/src/client/wr_config.c  wr_config_enable_maps() (real)
core/crush_ln/           crush_ln_table.h (unchanged), .license, crush_compat.h, wri_crush_lntab.c (real), README.md
harness/CMakeLists.txt   globs core/crush_ln/*.c into wr_core, and harness/oracle/*.c into tools
harness/oracle/README.md the planned tool; core/tools/gen_sources.sh and harness/tools/check_freestanding.sh include core/crush_ln
harness/test/test_core_docs.c  covers the new directories and enforces the crush_ln boundary
harness/test/test_map_skel.c   the skeleton's own checks (ctest map.skel): status codes, layouts, accessors, config, stubs, crush_ln tables
core/sources.txt         regenerated
```

Functions that are only declared have no definition yet: a module owner replaces nothing, writes the file named in the plan. The two stub files (`wri_crush_legacy.c`, `wr_map.c`) are replaced by their modules, as part A's stubs were. Headers are owned by the module that implements them and are **frozen** for the others: an owner may add to a header but not change a signature or a layout another module uses without the integrator (the compact CRUSH format and the compact map layout above all).

### 17.2 Waves

Seven waves, 18 modules. Modules of one wave touch disjoint files and can be implemented in parallel; a wave depends only on earlier waves. The critical path is `denc-map -> osdmap-pool -> osdmap-full -> osdmap-inc -> mapstore -> client-glue -> map-hardening`.

```
wave 1   denc-map   crush-prim   crush-dec   osdmap-core   mapgen   vectors-b
wave 2   crush-map   osdmap-pool
wave 3   osdmap-full   crush-legacy   place
wave 4   osdmap-inc   place-cache
wave 5   mapstore   map-vectors   oracle-cli
wave 6   client-glue
wave 7   map-hardening
```

Rules as in part A section 9: a module owns exactly the files it lists; SPDX MIT plus `WR_FILE_LICENCE_MIT` per core file; unique C basenames; files at most about 500 lines (split with a numeric suffix or by concern); no libc, no globals, no recursion; every wire length capped; own code from the notes, never copied; `-Werror` clean with gcc and clang and under the sanitizers; ctest naming `test_<module>_<what>.c`; `core/sources.txt` regenerated by the integrator after each wave (`core/tools/gen_sources.sh`); `harness/CMakeLists.txt` needs no edit (globs). A skip is `exit 77` with a reason and never hides a failure. Where a task says "lab", the VM is `winrbd-ceph1` with the rules of the task header (extra pools named `wrtest-*`, every changed state restored).

### Wave 1

**denc-map**

- Depends: none (skeleton only)
- Files: `core/src/denc/wri_denc_map.c`, `core/src/denc/wri_denc_map.h`, `harness/test/test_denc_map.c`
- Task: everything declared in `wri_denc_map.h`: the legacy envelope (`struct_v`; compat only from `compat_at`; length only from `len_at`; below `min_v` or length absent or compat above the supported maximum is `WR_E_MAP_VERSION`; length past the parent is `WR_E_TRUNCATED`; returns the body as a sub-reader and leaves the parent past it, like `wri_env_open`), `wri_denc_pg` (17 bytes, version ignored, preferred skipped, the 64-bit pool returned as read), `wri_denc_varint` (at most 10 bytes, `WR_E_ENCODING` on overflow or no end), and the skip helpers (string, `map<string,string>`, `map<string,map<string,string>>`, interval set, modern envelope, `vector<s32>`): every count goes through `wri_denc_count` / `wri_rd_count` with the smallest element size, so a hostile `0xFFFFFFFF` cannot loop; nested skippers use the sub-reader of the enclosing value.
- Tests: `test_denc_map`: every truncation point of each helper; the threshold table of the legacy envelope for (7,7) and (5,5) with `struct_v` 1 to 40; compat limit; hostile counts at every nesting level; varint known answers, the 10-byte maximum and the 11-byte overflow; the two pools of `harness/vectors/osdmap/full-e42.hex` (v32, with `application_metadata`, `opts`, `hit_set_params` envelopes) walked with the skip helpers only must end exactly on their envelope ends; `pg_t` round trip with a writer; skipped bytes equal the bytes a reference walk consumes.

**crush-prim**

- Depends: none (skeleton only; the table accessors in `core/crush_ln/` are already real)
- Files: `core/src/crush/wri_crush_hash.c`, `core/src/crush/wri_crush_ln.c`, `harness/test/test_crush_hash.c`, `harness/test/test_crush_ln.c`
- Task: `wri_crush_hash1..4`, `wri_str_hash_rjenkins` (12-byte blocks, the tail rules with the length folded into `c`, the final mix always), `wri_str_hash_linux`, `wri_str_hash` (dispatch on the pool's object_hash id, `*ok = 0` for others), `wri_cbits`, `wri_pg_mask` (0 for 0, never shifts by 32), `wri_stable_mod`, all per `crush note 3.1` and `3.2`; and `wri_crush_ln` in `wri_crush_ln.c` from `crush note 3.4.2` (normalise `x = u + 1`, `RH_LH` pair by `(x >> 8) << 1`, `xl = (x * RH) >> 48` in u64, `LL` by `xl & 0xff`, result `(iexpon << 44) + ((LH + LL) >> 4)`), reading the tables only through `wri_crush_ln_rh_lh()` and `wri_crush_ln_ll()`. Do not touch `core/crush_ln/`.
- Tests: `test_crush_hash`: every row of `harness/vectors/crush/hash-vectors.json` (ten string hashes in both flavours including the namespace case, `hash1` to `hash4`, `stable_mod`, `pps`); string lengths 0 to 40 against a bitwise re-implementation written in the test from the note; `stable_mod(stable_mod(x, pg_num, m1), pgp_num, m2) == stable_mod(x, pgp_num, m2)` for `pg_num` 1 to 299, every `pgp_num <= pg_num`, 600 values of `x` (the reviewer's check of `crush note 3.2`); `wri_pg_mask` at 0, 1, 2, 3, 100, 128 and 2^31. `test_crush_ln`: the ten known answers of `crush note 5.1` (the digest of the table header is already pinned by the skeleton's `map.skel`); the table facts of `crush note 3.4.2` (the 129 `RH_LH[2k]` entries equal `ceil(2^55 / (128 + k))`, the special last entry `0x0000ffff00000000`, the table lengths); and a golden digest of all 65,536 outputs, generated once by compiling Ceph's `mapper.c` for `crush_ln` in a scratch directory outside the repository (the procedure is in the test's header comment; the tree is not needed at test time).

**crush-dec**

- Depends: none (skeleton only)
- Files: `core/src/crush/wri_crush_dec.c`, `core/src/crush/wri_crush_dec2.c` (choose_args and the name-map walkers if one file would pass 500 lines), `core/src/crush/wri_crush.h`, `harness/test/test_crush_dec.c`, `harness/fuzz/fuzz_crush_dec.c`, `harness/fuzz/seeds/fuzz_crush_dec/`
- Task: `wri_crush_decode` and `wri_crush_check` exactly as 16.1: one forward pass into the compact format already defined in `wri_crush.h` (do not change its layout); every limit and refusal of 16.1 and `crush note 4.3`; both blob forms; absent groups keep the legacy defaults; the empty-name quirk in the three name maps; `max_devices` from items and name keys; `choose_args` strictness; trailing bytes refused; `WR_E_MAP_BUDGET` when the room is too small, with nothing written past `cap`; reasons in the errinfo (`what`, offset, numbers).
- Tests: `test_crush_dec`: the two lab blobs (`crush-embedded-in-osdmap.hex`, `crush-getcrushmap.hex`) against `crush-blob.expected.json` (buckets, items, weights, rules, tunables, `max_devices` 3), the two compact regions identical; blobs built by `wrt_mapgen` (every algorithm, holes, a zero-length name entry, no trailing groups, MSR pair present and absent, classes, `choose_args` with weight sets and ids, a legacy-tunables map); a negative table (bad magic, alg marker different from the alg byte, bucket id different from its slot, hash 1, ruleset different from slot, counts above the limits, `vary_r` 33, ids size different from the bucket size, weight row of the wrong length, straw2 weight `0x80000000`, trailing byte); every truncation point of the lab blob; `cap` smaller by one byte at each section with guard bytes proving nothing is written past it; `wri_crush_check` passes on every success. `fuzz_crush_dec`: blob in, decode into a guarded 64 KiB room; on success `wri_crush_check` must pass and a second decode with a differently pre-filled room must give identical bytes; seeds are the lab blobs, mapgen blobs and their truncations.

**osdmap-core**

- Depends: none (skeleton only)
- Files: `core/src/osdmap/wri_osdmap.c`, `core/src/osdmap/wri_osdmap_tab.c`, `core/src/osdmap/wri_osdmap.h`, `harness/test/test_osdmap_core.c`, `harness/test/test_osdmap_tab.c`
- Task: the builder and the tables of `wri_osdmap.h`: `wri_mapbuild_begin/osds/pools/tab/crush_room/left/finish`, `wri_pgtab_push` (ascending keys, capacity), `wri_mapbuild_copy_tab`, `wri_pgtab_find` (binary search over the u64 keys), `wri_osdmap_check`. Every carve is range-checked against the slot and fails with `WR_E_MAP_BUDGET` and an errinfo naming the section and the byte counts; carved sections are zeroed (affinity filled with `WRI_OSD_IN_FULL`); sections are 4-aligned and the slot 16-aligned; `finish` sets `magic`, `bytes` and the derived counts. Not in scope: decoding anything.
- Tests: `test_osdmap_core`: build random maps with random section sizes and compare every accessor with a plain-array model; slot too small by one byte at each section (nothing written past the slot, guard band); `max_osd` 0, 1, the hard cap, cap + 1; `wri_osdmap_check` accepts every build and rejects a copy with each header field corrupted. `test_osdmap_tab`: tables of 0, 1, 2, 1,000 entries; keys at 0 and `UINT64_MAX`; out-of-order, duplicate and over-capacity pushes; `find` against a model for every key and for absent keys; `copy_tab` round trip; offsets and values consistent after interleaved pushes of different vector lengths.

**mapgen**

- Depends: none (skeleton only; uses the existing cursors and `wri_crc32c`)
- Files: `harness/test/support/wrt_mapgen.h`, `harness/test/support/wrt_mapgen.c`, `harness/test/support/wrt_mapgen_crush.c`, `harness/test/test_mapgen_self.c`, `harness/tools/mapgen_dencoder_check.sh`
- Task: test support that **writes** wire bytes from a plain description struct, so decoder tests do not depend on the decoders and big clusters can be made on demand: a CRUSH blob encoder (every algorithm, holes, names and classes with the empty-name quirk, tunable profiles, `choose_args`, MSR pair on or off, absent trailing groups), an OSDMap encoder (wrapper v8, client block v10 or v9, OSD-only block v9 filled with per-OSD content of realistic size so wire sizes are honest, CRC), an Incremental encoder covering all 29 rows including an embedded full map, a `pg_pool_t` encoder for v29 to v32 and for the unsupported shapes (stretch v30, erasure, tiers, hash 3, size 0 or 17, pg_num 0), address vectors (v2 plus v1, IPv6, blank, v1 only), an `MOSDMap` v4 front builder with any mix of full maps and incrementals, cluster builders (N OSDs in racks and hosts with device classes, pools, upmaps, temps, affinities) with a deterministic PRNG, and an **independent model** (plain arrays, no compact format) that applies an incremental as in `osdmap.md 3.5` and computes the stages after CRUSH, for the tests to compare with.
- Tests: `test_mapgen_self`: the generated bytes are well-formed by a small reader written in the test (envelope lengths add up, CRC verifies with `wri_crc32c`, counts match the description); the model applies the lab's real incrementals (`incrementals.hex`) to epoch 1 and reproduces `expected.json` per epoch; size figures printed for 100, 1,000, 2,048 and 8,192 OSDs (the footprint numbers of 15.3 are measured here). `mapgen_dencoder_check.sh` (lab, not part of ctest): feeds generated maps, incrementals and CRUSH blobs to the lab's `ceph-dencoder` (`OSDMap`, `OSDMap::Incremental`, `CrushWrapper`), which must accept them and print the described values, so the generator is checked by Ceph's decoder and not only by ours.

**vectors-b**

- Depends: none
- Files: `harness/vectors/public/mapb/` (new directory: binary maps, incrementals, crushmaps, ground-truth text), `harness/vectors/public/scripts/capture_mapb.sh`, `harness/vectors/public/MANIFEST.md` (a new section)
- Task: capture the states the existing vectors lack (list in 18.3) with the admin CLI on the lab cluster, plus offline maps built with `crushtool --build`, `crushtool -c` and `osdmaptool` on files. Extra pools are named `wrtest-*` with small PG counts; every state set on the cluster (upmaps, temps, affinity, reweight, out, noup, a primary-affinity change, pool create, rename and delete) is **restored at the end**; never touch `winrbd`, OSDs, mons or keys. For each state: `ceph osd getmap`, the incrementals around it, `ceph osd dump -f json`, `osdmaptool --test-map-pgs-dump-all` for every pool, and `crushtool --test --show-mappings` for the CRUSH maps. Names for `ceph osd map -f json`: at least 3,000 across at least four pools (a power-of-two `pg_num`, 12, 7 with `pgp_num` below `pg_num`, a legacy pool without HASHPSPOOL if the CLI allows it, `winrbd`), bytes carried as hex (the monitor hashes characters above U+FFFF in CESU-8). Keep it small (about 2 MB in all), nothing secret (scrub the fsid and OSD uuids as `harness/vectors/osdmap/README.md` does and recompute the CRCs), and note provenance in the public `MANIFEST.md`.
- Tests: `harness/vectors/public/scripts/capture_mapb.sh --check` verifies sizes, hashes and the scrub; the content is exercised by `map-vectors` in wave 5.

### Wave 2

**crush-map**

- Depends: crush-prim, crush-dec, mapgen
- Files: `core/src/crush/wri_crush_map.c`, `core/src/crush/wri_crush_buck.c`, `core/src/crush/wri_crush_audit.c`, `core/src/crush/wri_crush_buck.h`, `harness/test/test_crush_map.c`, `harness/test/test_crush_audit.c`, `harness/fuzz/fuzz_crush_map.c`, `harness/fuzz/seeds/fuzz_crush_map/`
- Task: `wri_crush_do_rule` as 16.3.3 (TAKE, the SET steps, CHOOSE_FIRSTN, CHOOSELEAF_FIRSTN with the two-frame realisation of the recursion, EMIT, `numrep <= 0`, collisions, rejections, `fails_all` / `fails_here`, local retries and fallback via `wri_crush_choose_perm`, `vary_r`, `stable`, `descend_once`, `is_out` with `hash2`, choose_args by pool and position), `wri_crush_choose_straw2` (signed 64-bit draw through `wri_div_s64_u32`, first wins ties, weight 0 never draws, weight rows and substitute ids) and `wri_crush_choose_straw`, the dispatch to the legacy choosers, the work budget (`ws->work`, one per item draw) and the descent depth counter, and `wri_crush_audit_rule` as 16.3.5. No recursion, frames under 1 KiB, nothing allocated.
- Tests: `test_crush_map`: `crush-mappings.json` (4 sets of 300) and `crushtool-mappings.json` (x 0 to 63) through the lab blobs; the placement and draw arithmetic against `hash-vectors.json`; maps built by `wrt_mapgen` for the tunable profiles (argonaut, bobtail, firefly, hammer, jewel), straw and straw2, chooseleaf over racks and hosts, device-class shadow roots, `SET_*` steps, `numrep` 0 and negative, take of a device and of a missing bucket, all-out, fractional reweights, `choose_args` with one and several weight rows and ids, every collision and retry path; **optional** (skips without `WINRBD_CEPH_SRC`): the in-tree `crushtool` known-answer files named in `crush note 1.3`, read from the pinned Ceph tree at test time and never copied into the repository; work budget exhaustion with `choose_total_tries` 4,000,000,000; a cyclic hierarchy gives `WR_E_CRUSH_LOOP`. `test_crush_audit`: one case per refusal of 16.3.5 and a table of accepted rules. `fuzz_crush_map`: blob, rule, `x`, replica count and weights from the input; every returned item is a device that appears in the map or `-1 - n` of a bucket where applicable, `n <= result_max`, no crash, the work counter never exceeds the budget.

**osdmap-pool**

- Depends: denc-map, osdmap-core, mapgen
- Files: `core/src/osdmap/wri_osdmap_pool.c`, `harness/test/test_osdmap_pool.c`
- Task: `wri_pool_decode` and `wri_pool_skip` as 15.2.4: the legacy envelope (5, 5), rows 1 to 52 as the pool's `struct_v` has them (every row walked with the skip helpers or read), the jump to the envelope end, masks computed with `wri_pg_mask`, `present = 1`, and the unsupported rules that set `status = WR_E_POOL_UNSUPPORTED` with a reason in the errinfo; failures only for malformed input and for `struct_compat` above 32.
- Tests: `test_osdmap_pool`: the two pools of `full-e42.hex` (ids 1 and 2, sizes, `pg_num`, flags, `crush_rule`) against `expected.json`; every row combination `wrt_mapgen` can write for v29, v30 (stretch), v31 and v32; erasure, each tier field, non-empty erasure profile, hash 3, size 0 and 17, `pg_num` 0, pool id above 2^31, `struct_v` 28 on a tracked pool; compat 33 rejected; `struct_v` 33 with extra rows accepted and the tail skipped; every truncation point; `wri_pool_skip` and `wri_pool_decode` end on the same offset; masks for `pg_num` 1, 2, 3, 12, 100, 128 and 2^31.

### Wave 3

**osdmap-full**

- Depends: denc-map, crush-dec, crush-map, osdmap-core, osdmap-pool, mapgen
- Files: `core/src/osdmap/wri_osdmap_full.c`, `core/src/osdmap/wri_osdmap_full2.c` (tables, info, addresses), `core/src/osdmap/wri_osdmap_dec.h`, `harness/test/test_osdmap_full.c`, `harness/test/test_osdmap_budget.c`, `harness/fuzz/fuzz_osdmap_full.c`, `harness/fuzz/seeds/fuzz_osdmap_full/`
- Task: `wri_osdmap_full_info`, `wri_osdmap_inc_info` (rows 1 and 2 only), `wri_osdmap_read_addr` and `wri_osdmap_decode_full` as 15.4: the version floors of 15.2.6, the two passes over pools and pool names, per-OSD arrays with their length checks, the five tables counted then carved then filled (strictly ascending keys, tracked pools only, vector length caps), the CRUSH decode into the slot, the OSD-only block jumped over, the CRC when `verify_crc`, the rule audit and pool statuses, `max_osd` and slot budgets with errinfo, and the validation list of `osdmap.md 3.6`. On failure the slot has `magic` 0.
- Tests: `test_osdmap_full`: `full-e42.hex` against `expected.json` (epoch, flags, `max_osd`, per-OSD state, weight, address, both pools, CRUSH), the embedded full map of incremental 1, the lab's other stored epochs if present in the vectors; `wrt_mapgen` maps with tracked and untracked pools in every mix (a tracked name absent, present, renamed), entries of untracked pools filtered out of all five tables, address vectors (v2 only, v1 plus v2, IPv6, blank, v1 only), `max_osd` at 0, the cap and cap + 1, an array one entry short or long, a hostile count, raised `struct_v` with a tail accepted and raised `struct_compat` rejected, block v8 rejected, an OSD-only block with a huge `struct_len`, CRC good, one flipped byte (`WR_E_MAP_CRC` when verifying, accepted when not), a tracked erasure pool giving a per-pool status while the map is accepted. `test_osdmap_budget`: the slot smaller by one byte at each section; the per-OSD, per-table and CRUSH byte costs of 15.3 measured on generated clusters of 100, 1,000, 2,048 and 8,192 OSDs and printed. `fuzz_osdmap_full`: bytes in, a pattern-filled slot with guards; success implies `wri_osdmap_check`; two runs with different pre-fills give identical slot bytes; seeds are `full-e42.hex`, mapgen maps, their truncations and single-field mutations.

**crush-legacy**

- Depends: crush-map, crush-prim, mapgen
- Files: `core/src/crush/wri_crush_legacy.c` (replaces the stub), `harness/test/test_crush_legacy.c`
- Task: `wri_crush_choose_list`, `wri_crush_choose_uniform`, `wri_crush_choose_perm` per `crush note 3.4.4` and `3.4.5`: list walks from the last item down with `hash4(x, item, r, bucket id)`; the permutation is the partial Fisher-Yates of `r mod size` steps with `hash3(x, bucket id, p) mod (size - p)`, computed in `ws->perm` (a bucket above 256 items is `WR_E_CRUSH_UNSUPPORTED`); the local-fallback path of `choose_firstn` reaches `wri_crush_choose_perm` for any algorithm. Update the rule audit's answer for these algorithms (they pass when this module is present).
- Tests: `test_crush_legacy`: known answers from the lab ground truth of vectors-b (`crushtool --build` maps with list and uniform buckets and with legacy tunables that use `choose_local_fallback_tries`), the in-tree legacy-tunable files when `WINRBD_CEPH_SRC` is set; the permutation is a permutation for every `r` and size up to 256; determinism; 257 items refused; a rule over a mixed map (straw2 root, list racks, uniform hosts).

**place**

- Depends: osdmap-core, crush-map, crush-dec, crush-prim, mapgen
- Files: `core/src/osdmap/wri_place.c`, `core/src/osdmap/wri_place_stage.c`, `core/src/osdmap/wri_place.h`, `harness/test/test_place_pipe.c`, `harness/test/test_place_stage.c`
- Task: everything of `wri_place.h` except the cache: `wri_place_hash` (namespace separator, locator key, length cap, object_hash dispatch), `wri_place_pg_seed`, `wri_place_pps`, the five stage functions and `wri_place_pg` in the order of 16.4, with the statuses of the header comment (pool absent, pool status, no CRUSH, mapper errors; an empty acting set is a successful result).
- Tests: `test_place_stage`: one table per stage with hand-built compact maps (the builder API plus a CRUSH region decoded from a `wrt_mapgen` blob): every edge case of 16.4 (`pg_upmap` with a weight-0 member abandoning items and primaries, items applied in order and skipping a present `to`, upmap primary swap, NONE and out-of-range ids, down members dropped, affinity rejection and rotation, `primary_temp` without `pg_temp`, a `pg_temp` of only down OSDs); randomised comparison with the model of `wrt_mapgen` over 100,000 random states and PGs. `test_place_pipe`: `ps` for the names of `hash-vectors.json` including a namespace and a locator key; `stable_mod` and `pps` for non-power-of-two `pg_num`, `pgp_num` below `pg_num` and a pool without HASHPSPOOL; result invariants (members exist and are up, primaries belong to their set or are -1, no duplicates in `up`); an unmappable PG; absent, unsupported and no-rule pools.

### Wave 4

**osdmap-inc**

- Depends: osdmap-full, osdmap-core, osdmap-pool, crush-dec, crush-map, mapgen
- Files: `core/src/osdmap/wri_osdmap_inc.c`, `core/src/osdmap/wri_osdmap_inc2.c` (table merges, rows), `harness/test/test_osdmap_inc.c`, `harness/test/test_osdmap_seq.c`, `harness/fuzz/fuzz_osdmap_inc.c`, `harness/fuzz/seeds/fuzz_osdmap_inc/`
- Task: `wri_osdmap_apply_inc` as 15.4: the index walk of the 29 rows, the 13 steps in their order, the embedded full map, the resize, pool re-resolution with `WR_E_MAP_RESYNC`, XOR state with destroy, the first-use affinity array, the merge of the five sorted tables with strict ordering, the CRUSH replacement or copy, the audit, `inc_crc`, the budgets. The held map is never written; on failure the new slot has `magic` 0.
- Tests: `test_osdmap_seq`: apply all 89 stored incrementals to epoch 1 and compare the state after each epoch with `expected.json` (pools, weights, state, affinity, every table, CRUSH); the same replay checked against the `wrt_mapgen` model. `test_osdmap_inc`: what the lab lacks, from `wrt_mapgen`: `old_pools`, a pool in both lists, a rename of a tracked and of an untracked pool (`WR_E_MAP_RESYNC`), a tracked pool appearing, OSD destroy and re-add in one epoch, `new_state` mask 0, `max_osd` growing and shrinking, `pg_upmap_primary`, every table merge case (same key set and removed, empty `pg_temp` vector, `primary_temp` -1, new key in the middle, key beyond the end), unsorted lists, an OSD id at `max_osd`, wrong fsid, epoch gap and repeat, an embedded full map, `inc_crc` good and bad. **Atomicity property**: after every failure the source slot is byte-identical to before and the new slot has `magic` 0; budget exceeded at each section. `fuzz_osdmap_inc`: a fixed base map (lab epoch 42) and a mutated incremental; the same properties plus two runs with different pre-fills identical; seeds are the 89 incrementals and mutated forms.

**place-cache**

- Depends: place
- Files: `core/src/osdmap/wri_place_cache.c`, `harness/test/test_place_cache.c`
- Task: `wri_pgcache_bytes`, `wri_pgcache_init`, `wri_pgcache_get`, `wri_pgcache_put` per 16.4: direct-mapped on a mix of the key, entries stamped with the epoch (0 = empty), `n == 0` never hits, counters.
- Tests: hit and miss, an epoch change misses every entry, conflict replacement, `n` of 0, 1 and a non-power-of-two, a long random sequence whose results equal uncached `wri_place_pg`, counters add up.

### Wave 5

**mapstore**

- Depends: osdmap-full, osdmap-inc, place, place-cache, mapgen
- Files: `core/src/osdmap/wri_mapstore.c`, `core/src/osdmap/wri_mapstore_msg.c`, `core/src/osdmap/wri_mapstore.h`, `harness/test/test_mapstore_epoch.c`, `harness/test/test_mapstore_mem.c`, `harness/fuzz/fuzz_mapstore.c`, `harness/fuzz/seeds/fuzz_mapstore/`
- Task: `wri_mapstore_mem`, `wri_mapstore_init`, `wri_mapstore_track`, `wri_mapstore_step` and its deadline, the queries and targets, the counters, as 15.5: the cursor over a message, epoch order across the two lists, fsid check, the swap, `want_full` and the rate-limited, backed-off request through `io->want_osdmap`, the events through `io->event`, the first-map fatal rule, `want_full` on a late `track`, one epoch of work per step. `wri_mapstore_target*` fill the public `wr_target` through the cache and map an empty acting set to `WR_E_PLACE_UNMAPPABLE`.
- Tests: `test_mapstore_epoch`: a scripted fake `wri_map_io` and `wrt_mapgen` messages: a full map; a full map and then incrementals; one message with forty epochs and interleaved lists; a gap (one request with start 0, none while rate-limited, a second after the back-off, the back-off doubling to 32 s and resetting on success); another fsid dropped; a decode failure keeping the held map (byte compare) and requesting a full map; budget and version failures as fatal only for the first map; a monitor message with only `MMonMap`; `track` after a map; one epoch per step and `more_work`; `WR_EV_MAP` coalescing; the message is not released before its last entry; queries before the first map and with an absent or unsupported pool; targets for the 219 names of `placement-names-e42.json` through the store. `test_mapstore_mem`: `wri_mapstore_mem` equals what `init` consumes at three base alignments; budget errors name the section. `fuzz_mapstore`: a fixed base map and a fuzzed `MOSDMap` front; the epoch never decreases, an incremental is never applied across a gap, every failure sets `want_full`, the held map stays valid (`wri_osdmap_check`), no write outside the slots.

**map-vectors**

- Depends: osdmap-full, osdmap-inc, place, crush-map, vectors-b
- Files: `harness/test/test_map_vec_full.c`, `harness/test/test_map_vec_place.c`, `harness/test/test_map_vec_pgs.c`
- Task: put every committed vector through the real code: `placement-names-e42.json` (219 names), `crush/placement-expected.json` (137 results), `crush/mosdop-targets.json` (40 frames: hash field, masked pg, OSD), `placement-states.json` (24 states of pools 1 and 2, rebuilt by applying `incrementals.hex`; raw, up, up primary, acting and acting primary for every PG), `crush-mappings.json`, and the new sets of `public/mapb/` (at least 3,000 names across four pools; each state of 18.3; the offline CRUSH maps with every bucket algorithm); names are bytes (hex), including the CESU-8 case.
- Tests: the three test files are the deliverable; they fail on the first mismatch with the name, pool, state and both answers printed.

**oracle-cli**

- Depends: osdmap-full, osdmap-inc, place, crush-map
- Files: `harness/oracle/wr-maporacle.c`, `harness/oracle/wr_maporacle_fmt.c`, `harness/oracle/README.md`, `harness/tools/map_oracle_lab.sh`, `harness/tools/map_oracle_diff.py`, `harness/test/test_oracle_cli.c`
- Task: `wr-maporacle` with the four modes of `harness/oracle/README.md`, printing in the exact format of `ceph osd map`, `osdmaptool --test-map-pgs-dump-all` and `crushtool --test --show-mappings` (object names and namespaces given as hex so exact bytes reach the hash). `map_oracle_lab.sh` (runs on the lab VM through `cephadm shell`): creates the `wrtest-*` pools, drives each state of 18.3 with the admin CLI, saves the map after each change, asks `ceph osd map -f json` for the large name set once per pool geometry and `osdmaptool` for every PG of every pool in every state, runs the CLI on the same maps and diffs with `map_oracle_diff.py`, then **restores the cluster** to its starting state; it prints the number of comparisons and the first mismatches.
- Tests: `test_oracle_cli` runs the built tool on the committed vectors and compares its output byte for byte with the committed ground-truth files; `map_oracle_lab.sh --selftest` does the same without a cluster. The live comparison is run by hand in wave 7.

### Wave 6

**client-glue**

- Depends: mapstore, place-cache, osdmap-inc
- Files: `core/src/client/wr_map.c` (replaces the stub), `core/src/client/wri_client_map.c`, `core/src/client/wri_client.h`, `core/src/client/wr_client.c`, `core/src/client/wri_client_conn.c`, `core/src/client/wri_client_mem.c`, `core/src/client/wr_config.c` (validation of the map fields), `core/include/winrbd/wr_map.h` (additive only), `harness/test/test_client_map.c`, `harness/test/test_client_mem.c`, `harness/test/test_core_budgets.c`, `harness/test/core_budgets.h`, `harness/test/support/sim_mon_maps.c`, `harness/fuzz/fuzz_client_session.c`, `core/README.md` (footprint rows)
- Task: 15.6: embed the store in `struct wr_client`, add its memory to `wr_client_mem_required` and to create (exactness at every base alignment), the `wri_map_io` adapter over the monitor client, the run stage and its deadline and `more_work`, the event hook that swallows `WR_EV_MAPMSG` when maps are on and makes `wr_client_mapmsg_peek` return 0, `WR_EV_MAP` and `WR_EV_MAP_RESYNC` in the event ring (coalescible), config validation (`map_pools` 1 to 8, slot size at least 16 KiB, `map_max_osd` within the hard cap, work budget non-zero), and the public functions of `wr_map.h` as thin calls into the store. Extend the simulated monitor to serve incrementals and mixed messages from the vectors. Raise the documented budgets (`core_budgets.h`, README rows) for the map-enabled profiles; plain profiles and every existing test are unchanged.
- Tests: `test_client_map`: a client with maps on against the simulated monitor: the first message holds the full epoch-42 map and `wr_client_map_target` for the names of `placement-names-e42.json` matches; incrementals follow (`WR_EV_MAP` once per batch); a gap produces an `MMonSubscribe` with start 0; a budget failure on the first map is `WR_EV_FATAL`; the monitor session drops and queries keep answering; maps off keeps raw delivery. `test_client_mem` / `test_core_budgets`: the exactness test for the three map-enabled profiles and their footprint rows. `fuzz_client_session` runs half its inputs with maps on.

### Wave 7

**map-hardening**

- Depends: client-glue
- Files: `.github/workflows/harness.yml`, `harness/tools/fuzz_long.sh`, `harness/tests/ci-docs-hardening/check_callgraph.py`, `harness/README.md`, `core/README.md`, `docs/ROADMAP.md`, `docs/spec/osdmap.md` and `docs/spec/crush-and-placement.md` ("Corrections after capture" and the marks), `docs/design/core-architecture.md` (the budget tables once measured)
- Task: add the five new fuzz targets to the CI smoke and `fuzz_long.sh`; run each for at least 15 minutes with ASan and UBSan and commit the coverage-adding seeds; run `map_oracle_lab.sh` against the lab for every state of 18.3 and record the comparison counts; run the call-graph check on the new chains (no recursion, depth within 14, stack within 2 KiB; raise the ratchet only if a measured chain needs it and say why); re-measure the footprint with the generator and, if a profile number moves, change `wr_config_enable_maps()`, `core_budgets.h` and the tables of 15.3 together; update the ROADMAP table (milestones 4 and 5 done, 10 for the new decoders) and mark each `[unverified]` item of the two notes that the vectors now settle.
- Tests: the whole ctest suite and the CI workflow green; `core.docs` passes with the new READMEs.

---

## 18. Part B verification

### 18.1 Layers

1. **Unit tests per module** (section 17): every decoder at every truncation point, every refusal, every budget at its edge, hostile counts, raised and lowered versions.
2. **Vector tests** (`map-vectors`): the committed vectors (`harness/vectors/osdmap`, `crush`, `public`) through the real decoders and the real pipeline; a mismatch prints name, pool, state and both answers.
3. **Model tests** (`mapgen`): a plain-array model, written in the test support from `osdmap.md 3.5` and `crush note 3.7` without sharing code with the core, compared on random states. Its limit is the one of part A (R9): an author can misread a note twice. The vectors and the Python checkers (`harness/tools/osdmap_check.py`, `crush_check.py`, written from the notes alone) are the independent opinion; the lab comparison is the oracle.
4. **Properties**, asserted in the fuzz targets and the unit tests: success implies the structural checks pass; on failure the source map is byte-identical and the destination is unusable (atomicity); the same input with differently pre-filled slots gives identical output (no read of uninitialised bytes, the trick of `fuzz_client_session`); no write outside a slot or a room (guard bands); every mapping returns at most `result_max` valid items and never spends more than its work budget; the store never lowers the epoch, never applies an incremental across a gap, and sets `want_full` on every failure.
5. **Fuzzing** (milestone 10 for these decoders): targets `crush_dec`, `crush_map`, `osdmap_full`, `osdmap_inc`, `mapstore`, following the part A layout (12.3): `harness/fuzz/fuzz_<target>.c`, seeds in `harness/fuzz/seeds/fuzz_<target>/`, replayed by ctest as `fuzzseed.fuzz_<target>`, libFuzzer with ASan and UBSan for real runs. Seeds: the committed vectors and their truncations, `wrt_mapgen` output, single-field mutations. Durations as in 12.3.
6. **Lab comparison** (18.4): the core's answers against `ceph osd map`, `osdmaptool` and `crushtool` on the lab cluster, by script, not by hand.

### 18.2 Footprint and budgets

`test_mapstore_mem` and `test_osdmap_budget` generate clusters of 100, 1,000, 2,048 and 8,192 OSDs with `wrt_mapgen` (realistic per-OSD content in both blocks, a few hundred upmap items) and assert, per map-enabled profile: the map decodes inside its slot up to `map_max_osd` and the slot high-water is printed; a cluster of `map_max_osd + 1` OSDs fails with `WR_E_MAP_BUDGET` (the section named) rather than corrupting anything; the raw message size per OSD is measured and compared with the 0.45 KiB figure of 15.3, and the profile numbers are corrected with the measurement when they differ by more than 10 %. `core.budgets` and `client.mem` gain the map-enabled rows. Memory beyond the slots is the 2 KiB store and the cache; no decoder allocates.

### 18.3 Vectors: what exists, what is missing, how to get it

Existing and used as they are: `osdmap/full-e42.hex`, `incrementals.hex` (89 epochs, `expected.json` holds the monitor's state of each), `placement-names-e42.json`, `placement-states.json` (24 states), `crush/*` (lab blobs, 80,000 `crushtool` mappings in 4 sets of 300 committed, `placement-expected.json`, `mosdop-targets.json`, `hash-vectors.json`), the public capture set. These cover a replicated HASHPSPOOL cluster with straw2, no `choose_args`, power-of-two `pg_num` and consistency-only upmap, temps and affinity states (`crush note 1.3`, `osdmap.md` section 6 list the gaps). The missing states, all captured since (module vectors-b: `harness/vectors/public/mapb/`, 70 states, 18 offline CRUSH maps, 8 offline OSDMaps, 3,352 name answers; made again live by `map_oracle_lab.sh` on 2026-11-17, results in 18.6; `cephadm shell -- ...` for `osdmaptool` and `crushtool`):

| # | State | How | Ground truth |
|---|---|---|---|
| S1 | `pg_num` not a power of two (12 and 7) and `pgp_num` below `pg_num` | `ceph osd pool create wrtest-np 12 8` and friends | `ceph osd map`, `osdmaptool` |
| S2 | a split in progress (`pg_num` raised, `pgp_num` lagging), saved at each epoch | `ceph osd pool set wrtest-np pg_num 14` then `pgp_num` | `osdmaptool` per epoch |
| S3 | `pg_upmap_items` with one and several pairs, one invalid | `ceph osd pg-upmap-items` | `osdmaptool`, `ceph osd map` |
| S4 | `pg_upmap`, including a member with weight 0 | `ceph osd pg-upmap`, `reweight` | the same |
| S5 | `pg_upmap_primary` | `ceph osd pg-upmap-primary` (needs `require_min_compat_client` reef: check `ceph osd dump`, `ceph features` first; restore the old value if it was changed) | the same |
| S6 | `pg_temp` and `primary_temp`, one without the other | `ceph osd pg-temp`, `primary-temp` | the same |
| S7 | primary affinity 0, 0.25, 0.5 on one, two, three OSDs | `ceph osd primary-affinity` | `osdmaptool` (the primary column) |
| S8 | reweight 0.5, 0.1, 0; out and in | `ceph osd reweight`, `out`, `in` | the same |
| S9 | an OSD down and not marked out (`noup` plus `ceph osd down`) | restore with `unset noup` | the same |
| S10 | a legacy pool without HASHPSPOOL | `ceph osd pool set wrtest-leg hashpspool false --yes-i-really-mean-it` if the cluster allows it | `ceph osd map` |
| S11 | a pool deleted (`old_pools`), a pool renamed (`new_pool_names`), a pool created | `wrtest-*` only; `mon_allow_pool_delete` set for the pool and restored | the incrementals themselves |
| S12 | an erasure-coded pool and a cache tier (must be refused with a clear status) | `ceph osd pool create ... erasure`, `ceph osd tier add` | `ceph osd dump` |
| S13 | `choose_args`: a positional weight set and a compat set | offline: write the CRUSH text with `choose_args`, `crushtool -c`, `osdmaptool --import-crush`; on the lab only for a `wrtest-*` pool and removed afterwards | `crushtool --test`, `osdmaptool` |
| S14 | bucket algorithms straw, list, uniform, tree; legacy tunables with fallback tries; `chooseleaf` rules over hosts and racks; device-class shadow roots | offline: `crushtool --build --num_osds 24 host straw 4 rack list 3 root uniform 0` and variants, `osdmaptool --createsimple` | `crushtool --test`, `osdmaptool` |

Not producible on the lab (rules: no OSD destroy or removal, one monitor, IPv4 only): OSD destroy, `max_osd` shrinking, IPv6 addresses, stretch pools, the Linux dcache object hash. They are covered by `wrt_mapgen` and checked against `ceph-dencoder` (`mapgen_dencoder_check.sh`), and their marks in the notes stay "[unverified by a run]". Public vectors contain no keyrings or auth data; the fsid and OSD uuids are scrubbed as in `harness/vectors/osdmap/README.md`; sizes are kept small and everything is listed in the public `MANIFEST.md`.

### 18.4 The oracle tooling

`harness/oracle/wr-maporacle` (module oracle-cli) prints what the core answers in the format of Ceph's tools (see `harness/oracle/README.md`): the placement of one object like `ceph osd map`, every PG of a pool like `osdmaptool --test-map-pgs-dump-all` (raw, up, acting with primaries), CRUSH mappings like `crushtool --test --show-mappings`, and the compact state after each incremental. `harness/tools/map_oracle_lab.sh` drives the lab: the large name set (at least 5,000 names over at least six pools, bytes as hex, covering every length 0 to 25 and 255, non-ASCII and namespaced names) is compared with `ceph osd map -f json` **once per pool geometry**, because name to PG depends only on the pool (`pg_num`, `pgp_num`, hash, namespace) and each `ceph osd map` call costs a round trip; every state of 18.3 is compared **per PG** with `osdmaptool` on the saved map, which is cheap and covers every override. At the end the script restores the cluster (upmaps, temps, affinity, reweights, noup, test pools, `require_min_compat_client`) and prints the number of comparisons. The result goes into the "Corrections after capture" sections of the two notes in wave 7.

### 18.5 Mechanical gates

`core_no_libc` and `core_freestanding*` now cover `crush_ln/`; `core_no_globals` holds because the tables are `const` (the compat header); `core.docs` enforces the 500-line limit, SPDX tags and the `crush_ln` boundary for the new directories; `wr_header_check` compiles every new header alone; `wr_core_m32` and `wr_core_ipxe_flags` build the new files (the 64-bit division is the one place a 32-bit build could need a helper: `wri_div_s64_u32` avoids it); the call-graph check (no recursion, depth within 14, stack within 3,328 bytes per chain) runs on the new entry points, the placement chain being `wr_client_map_target -> wri_mapstore_target -> wri_place_pg -> wri_crush_do_rule -> choose -> bucket choose -> hash` with a design budget of 1.5 KiB of static frames; measured: 10 frames and 1,528 bytes (8 bytes under the design budget), and `check_callgraph.py --entry` holds each entry point of part B to a budget of its own (18.6).

### 18.6 What the finished code measured (map-hardening, 2026-11-17)

Everything below was run on the lab VM (Ubuntu 24.04, gcc 13 and clang, 8 cores) from one source tree (the core files hash to the same value before and after the runs; the committed seeds
below were added after the fuzz run and change no core file).

**Test suite.** 108 ctest tests, 106 of which run anywhere (`lab.mon` and `lab.map` skip without a cluster), all passing with gcc and with clang, each plain and under ASan and UBSan (the two sanitizer builds register 106: `core_no_libc` and `core_no_globals` look at object code and exist in plain builds only). Also green: the object gates (`core_*`) on Release and MinSizeRel builds with both compilers, the no-libc and no-globals gates on the 32-bit objects (gcc, clang) and on the iPXE-flag objects, `wr_core_m32`, `wr_core_ipxe_flags` and `wr_header_check`, the call-graph check, and a 30-second libFuzzer smoke run of each part B target on a copy of its seeds with the CI loop (`-max_len=65536` for them).

**Fuzzing** (milestone 10 for the part B decoders). `fuzz_long.sh -p partb -s 960 -j 5 -m`: libFuzzer on clang, ASan and UBSan, the core instrumented for coverage, 16 minutes per target, the five targets side by side, the
committed seeds as the starting corpus.

| Target | Executions | Edges / features at the end | Committed seeds before / added | Result |
|---|---|---|---|---|
| `fuzz_crush_dec` | 13.54 M | 385 / 1,633 | 172 / 271 | no crash |
| `fuzz_crush_map` | 0.78 M | 565 / 1,792 | 151 / 239 | no crash |
| `fuzz_osdmap_full` | 1.66 M | 823 / 2,490 | 77 / 269 | no crash |
| `fuzz_osdmap_inc` | 0.99 M | 1,195 / 3,263 | 409 / 260 | no crash |
| `fuzz_mapstore` | 1.61 M | 1,416 / 4,325 | 34 / 439 | no crash |

18.6 million executions, no crash, no timeout, no out-of-memory, no sanitizer report. The grown corpora were minimised against the committed seeds (`-merge=1`) and the inputs that add coverage were
committed under `harness/fuzz/seeds/fuzz_<target>/` (1,478 inputs, 3.1 MB; they derive from the scrubbed vectors only, checked for the lab's real fsid), so `ctest` replays them in every flavour.

**MemorySanitizer and the integer sanitizers** (clang; the unit tests, the vector tests and every committed seed, 96 and 94 tests; the mechanical gates, the lab tests, the documentation checks and the oracle self-test left out). Under `-fsanitize=memory` with origin tracking: no report in the core. It reported
four places where a test or a fuzz target passes an uninitialised `wr_errinfo` (`test_map_vec_err.c`, `test_osdmap_tab.c`, `test_osdmap_inc.c`, `fuzz_osdmap_inc.c`; the decoders read `status` to keep the first failure, so the caller must zero it, `wr_err.h`); with every
`wr_errinfo` local of the tests and targets zero-initialised in a scratch copy, all 96 tests pass. The reports are harmless under ASan and are listed as open issues for the owners of those files. Under `-fsanitize=unsigned-integer-overflow,implicit-conversion,local-bounds` in recover mode: every report in
`core/` is intended modular arithmetic (the Jenkins mixes of `wri_crush_hash.c` and `wri_place.c`, the multiplicative hash of the placement cache, base64 digit ranges, SHA and HMAC); none in a decoder, the rule interpreter, a bucket chooser, the map store or the map glue; the only implicit-conversion reports are in three tests of part A.

**Live placement proof** (`harness/tools/map_placement_lab.py`, the client `harness/src/winrbd-mapwatch`, vectors `harness/vectors/public/placement/`, replayed by the ctest `place.live`; the numbers are in `core/README.md`): the whole client, not a model, follows the lab cluster over a monitor session while the script changes the cluster; the client's own map store decodes and applies every incremental, and its answers are compared with `ceph osd map` (same epoch only), `osdmaptool` over the monitor's map of every adopted epoch, and `ceph osd dump`. It adds to 18.3 and 18.4 what a table of saved maps cannot show: placement at every epoch of a moving cluster (the transient `pg_temp` epochs, splits in progress), a missed incremental recovered by a full map, a killed connection, two key types, and the exact bytes the monitor sends to a client.

**Comparison with Ceph's own tools on the lab** (`harness/tools/map_oracle_lab.sh run`, every state of 18.3; the lab was restored and the restore verified):

| Phase | Compared | Differences | Not compared |
|---|---|---|---|
| names against `ceph osd map -f json` (once per pool geometry: 8 pools, 2 pools, 2 pools) | 5,600 + 350 + 350 = 6,300 | 0 | 0 |
| every PG of every pool of 53 saved states against `osdmaptool --test-map-pgs-dump-all` (raw, up, up primary, acting, acting primary) | 5,104 | 0 | 80 (pools or rules the core does not serve: erasure, cache tier) |
| the compact state after every state against `ceph osd dump` (OSD up / in / weight / affinity, pool geometry, five tables) | 901 | 0 | 0 |
| 82 `crushtool --test --show-mappings` runs | 120,000 | 0 | 44,000 (22 runs whose rules reach a `tree` bucket or are `indep`) |
| a chain of 149 incrementals, epoch 2152 to 2301, applied by the core and compared with the monitor's maps at 53 points | 53 | 0 | 0 |
| **total** | **132,358** | **0** | **44,080** |

The 53 states cover S1 to S15 of 18.3 (S10 shares the state `s01-pools`). One state, `s13b` (positional weights changed), did not meet its predicate in this run (`crush_version` beyond the creation of the weight
set): the state was still saved and compared, and the script reports it and exits 1, so the run as a whole exits 1 although nothing differed. The predicate depends on how the monitor batches the weight-set changes: a partial rerun restricted to
S13 and S14 reached it. That rerun was cut off by a command timeout and the cluster was put back with the script's own `cleanup` command (restore verified): a predicate that tolerates the merge is a fix for the script (open issue).

**The client against the real monitor** (`harness/test/test_lab_map.c`, label `lab`, run inside the VM, both key types): the engine logs in, takes the full map of the epoch the monitor holds, tracks `winrbd` and `.mgr`, places names;
with a pool tracked after the first map the engine asks again with start 0 and the monitor answers with a full map of the epoch it already sent (2 full maps, 1 re-request, epoch 2555 both times). Followed while the cluster was changed
from another shell (upmap items on four PGs, reweight, primary affinity, one OSD out and in, a pool created, split and deleted): the client took the first full map and then 38, 36 and 66 incrementals in three runs (the autoscaler of the test pool off in the first, on in the second), none undecodable, none skipped, no full map re-requested; its 400 placements per run at its final epoch (2540 and 2599) equal `osdmaptool` on the monitor's map of that epoch (44 and 64 distinct PGs), 0 differences. The third run's comparison was made at a later epoch than the client's and is not counted (`docs/spec/osdmap.md`, corrections after round 2).

**Footprint** (the generator, 18.2): the profile numbers did not move (15.3). Per-OSD costs: wire 429 to 436 bytes (478 to 485 with two device classes), slot 50 to 57 bytes (72 to 80); the design sizes fit with the message cap as the tighter limit.

**Call graph** (`check_callgraph.py --cc gcc`, gcc 13, 67 files, 441 functions): no recursion; deepest chain 13 frames (the renewal chain, unchanged); largest stack 3,064 bytes (the incremental apply chain of the map store: `wr_client_run` 144, `wri_client_map_step` 128, `wri_mapstore_step` 304, `wri_osdmap_apply_inc` 768, the decoder of the full map embedded in an incremental 608, `wri_crush_audit_rule` 304, `probe_legacy` of the rule audit 640, then the bucket chooser and the hash, 168 in all); the placement chain `wr_client_map_target` is 10 frames and 1,528 bytes against its 1.5 KiB design budget. The depth limit (14 frames) was not raised. **The stack limit was raised from 2 KiB to 3,328 bytes** (about 8 % above the measurement): the first
measurement of this pass said 1,632 bytes, which was wrong. `check_callgraph.py` read the per-function sizes of the .ci files in directory order, and a function that one file only calls (a node without a size) could overwrite the size of its definition in another file; with the largest size kept, whatever the order, the real figures are those above (the wire half of part A, through the monitor client, is 2,096 bytes: it was over the old limit too). Open item for the owners of the map modules: the three biggest frames of the worst chain (`wri_osdmap_apply_inc`, `probe_legacy`, `wri_osdmap_decode_full`) are the place to win the stack back before the iPXE stack is measured in Phase 2 (R-B7). Budgets per entry point
(`--entry`, in the CI job and in the ctest `map.hardening`): placement 1,664, store step 3,072, full-map decode 1,920, incremental apply 2,752, CRUSH decode 640, rule interpreter 768 bytes (measured 1,528, 2,792, 1,720, 2,488, 568 and 696), each about 8 % above its measured stack.

**Provenance.** A 4-line-window comparison of every file under `core/src`, `core/include` and `harness/` (252 files, whitespace-normalised, windows of at least 80 characters) against all 7,648 C, C++ and Python files of the Ceph v20.2.5 tree and the iPXE and WNBD
submodules (2.0 million windows): the only match is the base64 digit ranges of `wri_misc.c` (as in part A).

---

## 19. Part B risks and open questions

| # | Risk or question | Plan |
|---|---|---|
| R-B1 | **A full map larger than `mon_msg_cap`** (about 2,300 booted OSDs per MiB). The monitor client discards the message (`WR_E_MON_MSG_TOOBIG`); an iPXE client on a bigger cluster has no map. | Raise `mon_msg_cap` (1 MiB of bulk per 2,300 OSDs) for now. The escape hatch, not in this run: give the monitor client a **prefix sink** for an oversize `MOSDMap`: the first `mon_msg_cap` bytes land in the slot, the rest is discarded while the CRC still runs over all of it; the client block (everything a client keeps, about a fifth of the bytes) lies in the prefix, so a single-map message can be decoded from it; the trim bound, `newest_map` and the CRC after the OSD-only block are lost, and the store takes them from the map. It needs a change in `wri_m2_rx` (a sink smaller than its segment) and in `wri_mon`; decide after measuring real maps. |
| R-B2 | **Sorted wire order is assumed** (strictly ascending keys) for the five pg tables and the incremental lists (`osdmap.md` Q8: confirmed for the containers in the lab maps, not for every `old_*` list). A violation is `WR_E_MAP_CORRUPT`, which leads to a full-map fetch and, if the full map is also unsorted, to a client that never gets a map. | Fall back to a counting sort in a scratch region only if a real cluster shows it; the lab and the C++ containers (ordered) say it will not. **Measured (18.6):** the core, which refuses unsorted keys, applied 259 incrementals from the monitor store, a chain of 149 and 104 taken over the wire (epochs 2150 to 2600) without one `WR_E_MAP_CORRUPT`; the longest `old_*` list in any of them has one entry, so a multi-entry `old_*` list is still unexercised. |
| R-B3 | **Unverified parts of the algorithms**: list, uniform, tree, the permutation fallback, `choose_args`, upmap primaries, primary affinity, split pools, legacy pools (`crush note 6`, `osdmap.md` section 6). | The states of 18.3 give ground truth from Ceph's own tools for every one except those the lab cannot produce; the marks change only after a run. **Done (18.6):** list, uniform, straw, the permutation fallback, `choose_args`, upmap primaries, primary affinity, split and merge, legacy pools, device classes: 132,358 comparisons, 0 differences; the marks of both notes were changed and say what settled each. Not producible and so still unrun: reduced-feature clients, the Linux dcache hash, OSD destroy. |
| R-B4 | **`crush_ln` provenance.** One table has no formula; the core carries Ceph's. | Settled by `LICENSE` and 16.2: unchanged file, one directory, checksum test. If the copyright holder later permits MIT, the directory can be removed. |
| R-B5 | **A client that cannot follow the map** (budget exceeded after the cluster grows, repeated decode failure) keeps serving on a stale epoch. Ops sent to the wrong OSD are answered by the OSD, but nothing guarantees progress. | `WR_EV_MAP_RESYNC` carries the status and the stale age; the object client must fail new I/O with that status once the map has been stale and failing for a bounded time (decided with milestone 6, default 30 s). |
| R-B6 | **CRC verification default.** Off for iPXE (the transport CRC covers the bytes, the cost is a megabyte of CRC at boot), on elsewhere. The CRC does not protect against a bug of our own decoder. | Keep the switch; decoder correctness is the vectors' and the lab comparison's job. |
| R-B7 | **Stack and time on iPXE.** The mapper's work is bounded by `crush_work_max` draws (about 0.1 s worst case on a slow CPU); a full-map decode of a megabyte is milliseconds. Neither has been measured on iPXE. | Measure in Phase 2 with the part A heap measurement (R1). |
| R-B8 | **The monitor restored from an old backup** serves a lower epoch than the one held. The store ignores epochs not above the held one, so the client would stay on the stale map. | Open: treat `newest_map` below the held epoch in three consecutive messages as a reset and re-fetch with start 0. Not needed for the lab; decide with milestone 9. |
| R-B9 | **A tracked pool added after the first map** costs a full-map fetch. | Acceptable: pools are tracked at image-open time, before I/O. **Measured live (18.6):** the monitor answers the second start-0 request with a full map of the epoch already sent; a host that only wakes on sockets and timers waits up to `keepalive_ms` for the request to go out unless it calls `wr_client_run` after tracking (documented in `wr_map.h`). |
| R-B10 | **Pool ids above 2^31** are unsupported by construction (the packed key, the 31-bit rule). Real ids are small counters. | Documented; a status, not a crash. |
| R-B11 | **Per-pool failure isolation.** One bad pool record must not take the map down. | A malformed record is a map error; an unsupported one is only that pool's status. |

Open questions for the maintainers (defaults stand unless answered):

- **Q7.** Ratify the opt-in design (`wr_config_enable_maps`, raw delivery unchanged when off) and the per-profile numbers of 15.3 after the footprint measurement.
- **Q8.** Ratify the licence seam of 16.2: the arithmetic of `crush_ln` stays MIT in `core/src/crush/`, only the table data and its two accessors are LGPL.
- **Q9.** CRC verification on by default everywhere (cost on iPXE), or as designed?
- **Q10.** Build the prefix-capture escape hatch (R-B1) in Phase 1, or leave it to the first customer with a cluster above 2,000 OSDs?
- **Q11.** How long the object client may run on a map known to be stale (R-B5).
